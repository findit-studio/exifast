// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! TIFF/Exif primitive type decoders — the faithful port of ExifTool's
//! `ReadValue` (`ExifTool.pm:6275-6321`) plus the `@formatSize` / `@formatName`
//! tables (`Exif.pm:82-94`) and the byte-order-aware `Get*` accessors
//! (`ExifTool.pm:6071-6115`).
//!
//! An Exif IFD entry's value is decoded with one of the 13 standard TIFF
//! format codes (plus the BigTIFF + Exif-3.0 extensions). Every decoder here
//! takes the raw byte slice + a [`ByteOrder`] and yields a [`RawValue`] — the
//! post-decode `$val` that flows into ExifTool's `HandleTag`. PrintConv /
//! ValueConv conversions happen LATER, at serialize time, in
//! [`crate::exif::tables`].

// Golden-v2 Contract 3c (Phase C, slice w2d): panic-safety by construction —
// every raw index/slice below is converted to a checked `.get()` form. Each
// `read_value` window read is dominated by the preceding `count`/`size`
// shorten guards, so the `.get()` fallback is the unreachable no-panic value.
#![deny(clippy::indexing_slicing)]

use core::convert::TryInto;
use std::vec::Vec;

use crate::value::Rational;

// ===========================================================================
// Byte order — `SetByteOrder`/`GetByteOrder` (ExifTool.pm:6143-6175)
// ===========================================================================

/// TIFF byte order — `II` (Intel, little-endian) or `MM` (Motorola,
/// big-endian). The TIFF header's first two bytes encode it
/// (`ExifTool.pm:8628` `my $byteOrder = substr($$dataPt,0,2)`).
///
/// D8: enum predicates + `as_str` (Display source) + a lossless decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ByteOrder {
  /// `II` — little-endian (Intel).
  Little,
  /// `MM` — big-endian (Motorola).
  Big,
}

impl ByteOrder {
  /// Decode the 2-byte TIFF byte-order marker (`b"II"` / `b"MM"`).
  /// `None` for any other marker — faithful to `SetByteOrder`
  /// (`ExifTool.pm:6149-6160`) returning false for an unrecognized order.
  #[must_use]
  #[inline]
  pub const fn from_marker(marker: &[u8]) -> Option<Self> {
    // A leading-two-byte slice pattern is the checked equivalent of the
    // `marker.len() < 2` guard + `(marker[0], marker[1])` index pair: it
    // matches only when ≥ 2 bytes are present, so a short marker falls to the
    // `_` arm (`None`) exactly as the explicit length guard did. `const`-fn
    // compatible (no `<[u8]>::get`, which is not yet const).
    match marker {
      [b'I', b'I', ..] => Some(ByteOrder::Little),
      [b'M', b'M', ..] => Some(ByteOrder::Big),
      _ => None,
    }
  }

  /// The raw 2-letter marker (`"II"` / `"MM"`) — the value of ExifTool's
  /// `File:ExifByteOrder` tag in `-n` mode (`ExifTool.pm:8691`).
  #[must_use]
  #[inline(always)]
  pub const fn as_str(self) -> &'static str {
    match self {
      ByteOrder::Little => "II",
      ByteOrder::Big => "MM",
    }
  }

  /// The `File:ExifByteOrder` PrintConv string (`-j` mode, `ExifTool.pm:
  /// 1833-1836`).
  #[must_use]
  #[inline(always)]
  pub const fn print_conv(self) -> &'static str {
    match self {
      ByteOrder::Little => "Little-endian (Intel, II)",
      ByteOrder::Big => "Big-endian (Motorola, MM)",
    }
  }

  /// `true` for the little-endian (`II`) order.
  #[must_use]
  #[inline(always)]
  pub const fn is_little(self) -> bool {
    matches!(self, ByteOrder::Little)
  }

  /// `true` for the big-endian (`MM`) order.
  #[must_use]
  #[inline(always)]
  pub const fn is_big(self) -> bool {
    matches!(self, ByteOrder::Big)
  }
}

// ---------------------------------------------------------------------------
// Byte-order-aware integer reads — `Get8u`..`Get64s` (ExifTool.pm:6071-6115).
// Each returns `None` when the slice is too short (Perl's unpack would warn
// and yield a zero/undef; we surface the truncation explicitly).
//
// The end of each read is `pos.checked_add(N)`: an attacker-controlled `pos`
// (e.g. a wrapped IFD offset on a 32-bit/wasm target) near `usize::MAX` must
// not overflow the `pos..pos+N` range bound — a debug-build `pos + N` would
// PANIC before `<[u8]>::get` is reached, and a release-build wrap would form
// an inverted range. `checked_add` turns either into a clean `None` (the same
// "too short" outcome a normal out-of-range read produces).
// ---------------------------------------------------------------------------

/// Read an unsigned 8-bit integer at `pos` (`Get8u`).
#[must_use]
#[inline]
pub fn get_u8(data: &[u8], pos: usize) -> Option<u8> {
  data.get(pos).copied()
}

/// Read a signed 8-bit integer at `pos` (`Get8s`).
#[must_use]
#[inline]
pub fn get_i8(data: &[u8], pos: usize) -> Option<i8> {
  data.get(pos).map(|&b| b as i8)
}

/// Read an unsigned 16-bit integer at `pos` in `order` (`Get16u`).
#[must_use]
#[inline]
pub fn get_u16(data: &[u8], pos: usize, order: ByteOrder) -> Option<u16> {
  let b: [u8; 2] = data.get(pos..pos.checked_add(2)?)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u16::from_le_bytes(b),
    ByteOrder::Big => u16::from_be_bytes(b),
  })
}

/// Read a signed 16-bit integer at `pos` in `order` (`Get16s`).
#[must_use]
#[inline]
pub fn get_i16(data: &[u8], pos: usize, order: ByteOrder) -> Option<i16> {
  #[allow(clippy::cast_possible_wrap)]
  get_u16(data, pos, order).map(|v| v as i16)
}

/// Read an unsigned 32-bit integer at `pos` in `order` (`Get32u`).
#[must_use]
#[inline]
pub fn get_u32(data: &[u8], pos: usize, order: ByteOrder) -> Option<u32> {
  let b: [u8; 4] = data.get(pos..pos.checked_add(4)?)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u32::from_le_bytes(b),
    ByteOrder::Big => u32::from_be_bytes(b),
  })
}

/// Read a signed 32-bit integer at `pos` in `order` (`Get32s`).
#[must_use]
#[inline]
pub fn get_i32(data: &[u8], pos: usize, order: ByteOrder) -> Option<i32> {
  #[allow(clippy::cast_possible_wrap)]
  get_u32(data, pos, order).map(|v| v as i32)
}

/// Read an unsigned 64-bit integer at `pos` in `order` (`Get64u` — BigTIFF).
#[must_use]
#[inline]
pub fn get_u64(data: &[u8], pos: usize, order: ByteOrder) -> Option<u64> {
  let b: [u8; 8] = data.get(pos..pos.checked_add(8)?)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u64::from_le_bytes(b),
    ByteOrder::Big => u64::from_be_bytes(b),
  })
}

/// Read a signed 64-bit integer at `pos` in `order` (`Get64s` — BigTIFF).
#[must_use]
#[inline]
pub fn get_i64(data: &[u8], pos: usize, order: ByteOrder) -> Option<i64> {
  #[allow(clippy::cast_possible_wrap)]
  get_u64(data, pos, order).map(|v| v as i64)
}

/// Read an IEEE-754 single at `pos` in `order` (`GetFloat`, `ExifTool.pm:6074`).
#[must_use]
#[inline]
pub fn get_f32(data: &[u8], pos: usize, order: ByteOrder) -> Option<f32> {
  let b: [u8; 4] = data.get(pos..pos.checked_add(4)?)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => f32::from_le_bytes(b),
    ByteOrder::Big => f32::from_be_bytes(b),
  })
}

/// Read an IEEE-754 double at `pos` in `order` (`GetDouble`, `ExifTool.pm:6075`).
#[must_use]
#[inline]
pub fn get_f64(data: &[u8], pos: usize, order: ByteOrder) -> Option<f64> {
  let b: [u8; 8] = data.get(pos..pos.checked_add(8)?)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => f64::from_le_bytes(b),
    ByteOrder::Big => f64::from_be_bytes(b),
  })
}

// ===========================================================================
// TIFF format codes — `%formatNumber` / `@formatName` / `@formatSize`
// (Exif.pm:82-122)
// ===========================================================================

/// One of the TIFF/Exif value formats. The discriminant IS the on-disk
/// format code (`Exif.pm:96-119` `%formatNumber`): the 13 standard TIFF
/// types (1-13), the three BigTIFF additions (16-18), and the Exif-3.0 UTF-8
/// type (129).
///
/// `Unicode` and `Complex` (codes 14, 15) carry a byte SIZE mapping
/// (`byte_size`) but ExifTool does not "properly support" them
/// (`Exif.pm:118-122`). They are NOT reachable on the IFD-walk decode path:
/// the walker's format gate admits only `1..=13 | 129` (`mod.rs`, the
/// `recognized` test before `read_value`), so a code-14/15 entry is rejected
/// as `Bad format` and never decoded. The `read_value` arm that maps them to
/// raw bytes is thus dead on this path, kept only for an exhaustive match.
///
/// D8: lossless `Unknown(n)` keeps an unrecognized format code rather than
/// discarding it — the Exif IFD walker uses it to faithfully emit the
/// `Bad format` warning (`Exif.pm:6464-6477`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Format {
  /// Code 1 — `int8u` (BYTE).
  Int8u,
  /// Code 2 — `string` (ASCII, NUL-terminated).
  Ascii,
  /// Code 3 — `int16u` (SHORT).
  Int16u,
  /// Code 4 — `int32u` (LONG).
  Int32u,
  /// Code 5 — `rational64u` (RATIONAL — two int32u).
  Rational64u,
  /// Code 6 — `int8s` (SBYTE).
  Int8s,
  /// Code 7 — `undef` (UNDEFINED — raw bytes).
  Undef,
  /// Code 8 — `int16s` (SSHORT).
  Int16s,
  /// Code 9 — `int32s` (SLONG).
  Int32s,
  /// Code 10 — `rational64s` (SRATIONAL — two int32s).
  Rational64s,
  /// Code 11 — `float` (FLOAT — IEEE-754 single).
  Float,
  /// Code 12 — `double` (DOUBLE — IEEE-754 double).
  Double,
  /// Code 13 — `ifd` (IFD pointer, decoded as int32u).
  Ifd,
  /// Code 14 — `unicode`. Byte-size known, but unreachable on the IFD path
  /// (the walker rejects format codes 14/15 before `read_value`).
  Unicode,
  /// Code 15 — `complex`. Byte-size known, but unreachable on the IFD path
  /// (the walker rejects format codes 14/15 before `read_value`).
  Complex,
  /// Code 16 — `int64u` (LONG8 — BigTIFF).
  Int64u,
  /// Code 17 — `int64s` (SLONG8 — BigTIFF).
  Int64s,
  /// Code 18 — `ifd64` (IFD8 — BigTIFF, decoded as int64u).
  Ifd64,
  /// Code 129 — `utf8` (Exif 3.0).
  Utf8,
  /// An unrecognized on-disk format code — kept losslessly so the IFD
  /// walker can emit the faithful `Bad format` warning.
  Unknown(u16),
}

impl Format {
  /// Decode an on-disk format code (`Exif.pm:6464` `Get16u($dataPt,$entry+2)`).
  #[must_use]
  pub const fn from_code(code: u16) -> Self {
    match code {
      1 => Format::Int8u,
      2 => Format::Ascii,
      3 => Format::Int16u,
      4 => Format::Int32u,
      5 => Format::Rational64u,
      6 => Format::Int8s,
      7 => Format::Undef,
      8 => Format::Int16s,
      9 => Format::Int32s,
      10 => Format::Rational64s,
      11 => Format::Float,
      12 => Format::Double,
      13 => Format::Ifd,
      14 => Format::Unicode,
      15 => Format::Complex,
      16 => Format::Int64u,
      17 => Format::Int64s,
      18 => Format::Ifd64,
      129 => Format::Utf8,
      other => Format::Unknown(other),
    }
  }

  /// Byte size of one element of this format (`@formatSize`, `Exif.pm:82-83`).
  /// `Unknown` formats report `0` (Perl's `@formatSize` index is `undef` for
  /// an out-of-range code; `ReadValue` then warns `Unknown format` and uses
  /// a length of 1 — the IFD walker handles `Unknown` before reaching here).
  #[must_use]
  pub const fn byte_size(self) -> usize {
    match self {
      Format::Int8u | Format::Ascii | Format::Int8s | Format::Undef | Format::Utf8 => 1,
      Format::Int16u | Format::Int16s | Format::Unicode => 2,
      Format::Int32u | Format::Int32s | Format::Float | Format::Ifd => 4,
      Format::Rational64u
      | Format::Rational64s
      | Format::Double
      | Format::Int64u
      | Format::Int64s
      | Format::Ifd64
      | Format::Complex => 8,
      Format::Unknown(_) => 0,
    }
  }

  /// The ExifTool format NAME (`@formatName`, `Exif.pm:86-93`) — used in
  /// warning messages.
  #[must_use]
  pub const fn name(self) -> &'static str {
    match self {
      Format::Int8u => "int8u",
      Format::Ascii => "string",
      Format::Int16u => "int16u",
      Format::Int32u => "int32u",
      Format::Rational64u => "rational64u",
      Format::Int8s => "int8s",
      Format::Undef => "undef",
      Format::Int16s => "int16s",
      Format::Int32s => "int32s",
      Format::Rational64s => "rational64s",
      Format::Float => "float",
      Format::Double => "double",
      Format::Ifd => "ifd",
      Format::Unicode => "unicode",
      Format::Complex => "complex",
      Format::Int64u => "int64u",
      Format::Int64s => "int64s",
      Format::Ifd64 => "ifd64",
      Format::Utf8 => "utf8",
      Format::Unknown(_) => "unknown",
    }
  }

  /// `true` for an on-disk format code that `ProcessExif` accepts in a standard
  /// TIFF/Exif IFD entry: the 13 standard TIFF types (`1..=13`) plus the
  /// Exif-3.0 UTF-8 type (`129`) (`Exif.pm:6463-6464` `if (($format < 1 or
  /// $format > 13) and $format != 129 …)`). Codes `14`/`15` (`unicode`/
  /// `complex`) and the BigTIFF additions `16`/`17`/`18` (`int64u`/`int64s`/
  /// `ifd64`) are NOT accepted on the IFD-walk decode path — a standard IFD
  /// entry carrying one is `Bad format` (warned, then entry-0-abort vs
  /// later-skip), never decoded.
  ///
  /// This is the SINGLE source of truth for the per-entry format-validity gate,
  /// shared by the standalone-TIFF walker (`mod.rs`), the Canon MakerNote
  /// classifier ([`crate::exif::makernotes::vendors::canon`]) and the Nikon
  /// MakerNote walker — each `ProcessExif`-equivalent reuses it so the
  /// `recognized` test cannot drift between vendors.
  #[must_use]
  pub const fn is_valid_ifd_code(code: u16) -> bool {
    matches!(code, 1..=13 | 129)
  }

  /// `true` for an integer format that may legitimately hold an IFD pointer
  /// (`%intFormat`, `Exif.pm:124-135`). The Exif IFD walker uses this to
  /// faithfully warn `Wrong format` when a SubIFD pointer has a non-integer
  /// type (`Exif.pm:6743-6745`).
  #[must_use]
  pub const fn is_int(self) -> bool {
    matches!(
      self,
      Format::Int8u
        | Format::Int16u
        | Format::Int32u
        | Format::Int8s
        | Format::Int16s
        | Format::Int32s
        | Format::Ifd
        | Format::Int64u
        | Format::Int64s
        | Format::Ifd64
    )
  }
}

// ===========================================================================
// RawValue — the decoded `$val` (post-format-decode, pre-conversion)
// ===========================================================================

/// One decoded IFD value — the faithful equivalent of the scalar/array `$val`
/// ExifTool's `ReadValue` returns (`ExifTool.pm:6318-6320` joins a
/// multi-element array with spaces; a single element is the bare scalar).
///
/// The conversion layer ([`crate::exif::tables`]) consumes this; PrintConv /
/// ValueConv have NOT been applied. `#[non_exhaustive]` so future Exif
/// formats can grow a new shape.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum RawValue {
  /// One or more unsigned integers (`int8u`/`int16u`/`int32u`/`int64u`/IFD
  /// pointers). Widened to `u64` so a BigTIFF `int64u` is exact.
  U64(Vec<u64>),
  /// One or more signed integers (`int8s`/`int16s`/`int32s`/`int64s`).
  I64(Vec<i64>),
  /// One or more floats (`float`/`double`).
  F64(Vec<f64>),
  /// One or more rationals (`rational64u`/`rational64s`). The [`Rational`]
  /// carries the `sig` width ExifTool's `RoundFloat` uses (32-bit ⇒ 7,
  /// 64-bit ⇒ 10 — `value.rs`).
  Rational(Vec<Rational>),
  /// A `string` (ASCII / Exif-3.0 UTF-8). NUL-terminator trimmed
  /// (`ExifTool.pm:6301` `$vals[0] =~ s/\0.*//s`).
  ///
  /// Carries BOTH the FixUTF8 display text (`text`) AND the pre-FixUTF8,
  /// NUL-trimmed original bytes (`raw`). A normal text conv reads `text`; a
  /// byte-walking `RawConv` (`CompositeImageExposureTimes`, `UserComment`)
  /// reads `raw` — ExifTool's post-`ReadValue` `$val` bytes, not a lossy
  /// re-encoding (see [`RawValue::val_bytes`]).
  Text {
    /// The FixUTF8 display string (`lossy_string` of `raw`).
    text: std::string::String,
    /// The pre-FixUTF8, NUL-trimmed original bytes — `$val`'s bytes.
    raw: Box<[u8]>,
  },
  /// `undef`/`binary`/`unicode`/`complex` — raw bytes, not NUL-trimmed.
  Bytes(Vec<u8>),
}

impl RawValue {
  /// The number of decoded elements (1 for `Text` — a string is one value).
  #[must_use]
  pub fn count(&self) -> usize {
    match self {
      RawValue::U64(v) => v.len(),
      RawValue::I64(v) => v.len(),
      RawValue::F64(v) => v.len(),
      RawValue::Rational(v) => v.len(),
      RawValue::Text { .. } => 1,
      RawValue::Bytes(v) => v.len(),
    }
  }

  /// Perl boolean truthiness of this value's post-`ReadValue` `$val` — the
  /// test an `if ($val)` (or `if ($$self{Member})` after a `RawConv` storing
  /// `$val`) applies. Perl treats a scalar as FALSE only when it is the empty
  /// string `""` or the one-character string `"0"`; every other value
  /// (including `"0.0"`, `"0 0 0 0"`, or a multi-element join) is TRUE. The
  /// `$val` form is taken from [`Self::val_bytes`] (numeric shapes → the
  /// space-joined `join(' ', @vals)` string `ReadValue` returns; `Text`/`Bytes`
  /// → the original bytes), so this matches ExifTool's truthiness for any
  /// shape. A count-0 numeric value yields the empty `$val` (`""`), hence false.
  ///
  /// Used by the `DNGVersion` (0xc612) `RawConv` DataMember tap to gate
  /// `OverrideFileType('DNG')` (`ExifTool.pm:8763` `if ($$self{DNGVersion} …`):
  /// `int8u[4]` `1 1 0 0`/`0 0 0 0` are TRUE → DNG, while a count-0 (empty) or a
  /// scalar `0` `DNGVersion` is FALSE → the file stays its non-DNG type.
  #[must_use]
  pub fn is_perl_truthy(&self) -> bool {
    let val = self.val_bytes();
    !val.is_empty() && &*val != b"0"
  }

  /// The first integer of a SubIFD pointer, as a SIGNED `i64`, accepting BOTH
  /// `U64` and `I64` shapes. `%intFormat` (Exif.pm:125-136) treats the signed
  /// formats (`int8s`/`int16s`/`int32s`/`int64s`) as valid integer offsets, so
  /// a GPSInfo/ExifOffset/InteropOffset mis-encoded as e.g. `int32s` passes the
  /// `Wrong format` gate (Exif.pm:6747) and is then used as `Start => '$val'`.
  /// ExifTool's `IsInt` (ExifTool.pm:5943, `/^[+-]?\d+$/`) accepts a NEGATIVE
  /// `$val` too; the sign is handled downstream by the
  /// `$subdirStart < 0 → Bad SubDirectory start` check (Exif.pm:7017). So
  /// return the value verbatim (negative allowed) and let the caller route it.
  #[must_use]
  pub fn first_subdir_offset(&self) -> Option<i64> {
    match self {
      RawValue::U64(v) => v.first().and_then(|&n| i64::try_from(n).ok()),
      RawValue::I64(v) => v.first().copied(),
      _ => None,
    }
  }

  /// EVERY SubIFD offset in a `ProcessBigIFD` `$$tagInfo{SubIFD}` pointer —
  /// the faithful port of `my @offsets = split ' ', $val` (`BigTIFF.pm:184`).
  ///
  /// `ProcessBigIFD` does NOT gate the pointer on an integer on-disk format
  /// (there is no `%intFormat` `Wrong format` check, unlike `ProcessExif` at
  /// `Exif.pm:6747`): it `ReadValue`s the pointer with whatever format the
  /// entry declares, takes the resulting `$val` STRING, `split ' '`s it, and
  /// recurses each token as an IFD start. So this iterates the SAME string
  /// form `ReadValue` produces ([`Self::raw_conv_val_string`] — `join(' ',
  /// @vals)` for the numeric shapes, the decoded text for `string`/`undef`),
  /// splits on whitespace runs exactly as Perl's `split ' '` does (leading
  /// whitespace stripped, no empty leading field), and coerces each token to
  /// an integer offset the way Perl numifies a string used as
  /// `Start => $offsets[$i]` (see [`perl_int_prefix`] for the IV/UV-vs-NV
  /// boundary): a WHOLLY-integer token (`^[+-]?[0-9]+$`) that fits `u64` is
  /// parsed on an EXACT checked `u64` path (byte-exact across BigTIFF's full
  /// 64-bit surface — an offset above `2^53` does NOT round-trip through `f64`);
  /// EVERY other token (trailing junk after a digit run, a fraction/exponent, a
  /// clean digit run `> u64::MAX`, or a non-finite spelling) goes through the
  /// `f64` grammar (`"1e3"` -> 1000, `"12abc"` -> 12, `"abc"` -> `Some(0)` — the
  /// degenerate offset-0 recursion bundled also takes). A NEGATIVE, `> u64::MAX`,
  /// or non-finite token -> [`None`] (skip — the `Bad SubDirectory start` /
  /// failed-`Seek` analogue). This subsumes the
  /// single-`int64u`/`ifd64` camera shape (`U64(vec![off])` -> one token -> one
  /// offset, byte-identical to [`Self::first_subdir_offset`]) AND the count>1
  /// (multiple offsets) / signed / ASCII-numeric shapes the first-only,
  /// `U64`/`I64`-only `first_subdir_offset` dropped.
  ///
  /// The offsets are positional: index `i` -> the `$i`-suffixed family-1
  /// group `$$tagInfo{Name}` + `$i` (`BigTIFF.pm:187-188`); a `None` entry is a
  /// skipped offset that STILL consumes its `$i` slot (so the next offset keeps
  /// the correct `$i+1` suffix — the Perl `for ($i...)` index advances
  /// regardless).
  #[must_use]
  pub fn subdir_offsets(&self) -> std::vec::Vec<Option<u64>> {
    self
      .raw_conv_val_string()
      .split_whitespace()
      .map(perl_int_prefix)
      .collect()
  }

  /// The first scalar integer (signed) — works for `U64`/`I64`. The dominant
  /// Apple maker-note shape (most tags are scalar int32s); the Apple PrintConv
  /// and typed-population paths read it directly from the decoded `$val`.
  #[must_use]
  pub fn first_i64(&self) -> Option<i64> {
    match self {
      RawValue::I64(v) => v.first().copied(),
      RawValue::U64(v) => v.first().and_then(|&n| i64::try_from(n).ok()),
      _ => None,
    }
  }

  /// The first two scalar integers (for Apple `AFPerformance`, `int32s[2]`).
  #[must_use]
  pub fn first_two_i64(&self) -> Option<(i64, i64)> {
    // `[a, b, ..]` matches len ≥ 2 and binds the first two — byte-identical to
    // the `if v.len() >= 2 => (v[0], v[1])` index pair, without raw indexing.
    match self {
      RawValue::I64(v) if let [a, b, ..] = v.as_slice() => Some((*a, *b)),
      RawValue::U64(v) if let [a, b, ..] = v.as_slice() => {
        let a = i64::try_from(*a).ok()?;
        let b = i64::try_from(*b).ok()?;
        Some((a, b))
      }
      _ => None,
    }
  }

  /// The first two rational64 values as f64 — for Apple `FocusDistanceRange`.
  #[must_use]
  pub fn rational_pair(&self) -> Option<(f64, f64)> {
    // `[r0, r1, ..]` matches len ≥ 2 and binds the first two — byte-identical to
    // the `rs.len() >= 2` guard + `rs[0]`/`rs[1]`, without raw indexing.
    match self {
      RawValue::Rational(rs) if let [r0, r1, ..] = rs.as_slice() => {
        let a = ratio_f64(r0.numerator(), r0.denominator())?;
        let b = ratio_f64(r1.numerator(), r1.denominator())?;
        Some((a, b))
      }
      _ => None,
    }
  }

  /// Convert this raw value to a default [`TagValue`] (no PrintConv — used by
  /// [`ApplePrintConv::None`](crate::exif::makernotes::vendors::apple::printconv::ApplePrintConv)
  /// and the PLIST-deferred branches).
  ///
  /// Delegates to the shared [`render_value`](crate::exif::render::render_value)
  /// — the single faithful `ReadValue` renderer (`ExifTool.pm:6275-6321`) the
  /// EXIF emitters and this Apple default path both use: integers → `I64`/`U64`,
  /// floats → `F64`, a single rational → `Rational` (its serializer renders the
  /// rounded decimal), a multi-rational → space-joined DECIMAL scalars
  /// (`Rational::exiftool_val_str`, NOT `n/d` fractions — e.g.
  /// AccelerationVector, `Apple.pm:62`), text → `Str`, bytes → `Bytes`. The
  /// no-conv default is mode-agnostic, so the active
  /// [`ConvMode`](crate::emit::ConvMode) is irrelevant here.
  #[must_use]
  pub fn to_default_tag_value(&self) -> crate::value::TagValue {
    crate::exif::render::render_value(self, crate::emit::ConvMode::PrintConv)
  }

  /// ExifTool's post-`ReadValue` `$val` AS BYTES — what a byte-walking
  /// `RawConv` consumes. Defined for EVERY shape so a conv never has to gate on
  /// `Format`: `Text` → the pre-FixUTF8 `raw` (the original on-disk bytes);
  /// `Bytes` → the bytes verbatim; numeric → the space-joined ExifTool `$val`
  /// rendering (`ReadValue`'s `join(' ', @vals)`, [`Self::numeric_val_string`]).
  ///
  /// Borrows for `Text`/`Bytes` (zero-copy); allocates only for the numeric
  /// shapes, which have no stored byte form.
  #[must_use]
  pub fn val_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
    use std::borrow::Cow;
    match self {
      RawValue::Text { raw, .. } => Cow::Borrowed(raw),
      RawValue::Bytes(b) => Cow::Borrowed(b),
      _ => Cow::Owned(self.numeric_val_string().into_bytes()),
    }
  }

  /// The numeric shapes as the single space-joined string ExifTool's
  /// `ReadValue` produces for `$val` (`join(' ', @vals)`): each element via the
  /// SAME per-element token form [`emit_raw`](crate::exif)/`value_space_joined`
  /// render — `U64`/`I64` decimal, `F64` via `%.15g` ([`crate::value::format_g`]
  /// `(_, 15)`), `Rational` via [`Rational::exiftool_val_str`]. A non-numeric
  /// shape (`Text`/`Bytes`) returns the empty string (callers reach those via
  /// [`Self::val_bytes`]'s borrowing arms, never here).
  #[must_use]
  fn numeric_val_string(&self) -> std::string::String {
    use std::fmt::Write as _;
    let mut s = std::string::String::new();
    match self {
      RawValue::U64(v) => join_display(&mut s, v),
      RawValue::I64(v) => join_display(&mut s, v),
      RawValue::F64(v) => {
        for (i, val) in v.iter().enumerate() {
          if i > 0 {
            s.push(' ');
          }
          s.push_str(&crate::value::format_g(*val, 15));
        }
      }
      RawValue::Rational(rs) => {
        for (i, r) in rs.iter().enumerate() {
          if i > 0 {
            s.push(' ');
          }
          let _ = write!(s, "{}", r.exiftool_val_str());
        }
      }
      RawValue::Text { .. } | RawValue::Bytes(_) => {}
    }
    s
  }

  /// ExifTool's post-`ReadValue` `$val` AS A DISPLAY STRING — the value a
  /// `RawConv` that stores `$$self{X} = $val` keeps in object state for ANY
  /// readable shape, the way that scalar later stringifies in an `eq`
  /// comparison. This is the string form of the IFD0 `Make`/`Model` the
  /// MakerNotes dispatcher and the JPEG DJI gate read (`$$self{Make} eq 'DJI'`,
  /// `Exif.pm:585`): the `RawConv` `$$self{Make} = $val` runs whenever the
  /// `Make` TAG is seen, NOT only when its on-disk format is ASCII — so a
  /// `Make` encoded `int16u`/`undef`/etc. still assigns `$$self{Make}` its
  /// stringified `$val` and must be captured.
  ///
  /// Per shape, mirroring how Perl stringifies the post-`ReadValue` `$val`:
  /// - `Text` → the FixUTF8 display string (`text`) — the SAME string the
  ///   EMITTED `Make`/`Model` tag renders (so an ASCII `Make` is captured
  ///   exactly as before this method existed: byte-for-byte the prior
  ///   `RawValue::Text`-only path);
  /// - numeric (`U64`/`I64`/`F64`/`Rational`) → the space-joined `$val`
  ///   ([`Self::numeric_val_string`] — `ReadValue`'s `join(' ', @vals)`), e.g.
  ///   an `int16u[2]` `Make` stringifies to `"1 2"`;
  /// - `Bytes` (`undef`/`binary`) → the lenient UTF-8 view of the bytes
  ///   (`from_utf8_lossy`) — the binary `$val`'s string form.
  ///
  /// The caller applies the `Make`/`Model` `RawConv`'s trailing-`\s+` trim on
  /// top (`s/\s+$//`); this method returns the untrimmed `$val` string.
  /// Borrows for `Text` (zero-copy); allocates only the numeric/`Bytes` forms,
  /// which have no stored display string.
  #[must_use]
  pub fn raw_conv_val_string(&self) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    match self {
      RawValue::Text { text, .. } => Cow::Borrowed(text.as_str()),
      RawValue::Bytes(b) => std::string::String::from_utf8_lossy(b),
      _ => Cow::Owned(self.numeric_val_string()),
    }
  }
}

/// Space-join `Display` elements into `s` (the `ReadValue` integer-array join).
fn join_display<T: core::fmt::Display>(s: &mut std::string::String, vals: &[T]) {
  use std::fmt::Write as _;
  for (i, v) in vals.iter().enumerate() {
    if i > 0 {
      s.push(' ');
    }
    let _ = write!(s, "{v}");
  }
}

/// Perl numeric coercion of one whitespace-stripped `split ' '` token to an
/// integer offset (`Start => $offsets[$i]`, `BigTIFF.pm:192`).
///
/// `ProcessBigIFD` uses the token in Perl numeric context (`$$dirInfo{DirStart}
/// = $offsets[$i]` then `Seek`), so the coercion is Perl's FULL string→number
/// grammar, NOT just a leading decimal-digit run: an optional sign, the leading
/// numeric run including a fraction AND an exponent, the rest ignored. Verified
/// against bundled Perl 5 / ExifTool 13.59 (`0 + $val`): `"1e3"` → 1000,
/// `"1.9e2"` → 190, `"12abc"` → 12, `"abc"` → 0, `"-1e2"` → -100. A crafted
/// BigTIFF whose GPSInfo (0x8825) SubIFD pointer is the ASCII string `"1e3"`
/// makes bundled recurse the child IFD at byte **1000** (emitting the child's
/// `GPSInfo:InteropIndex`/`InteropVersion`), NOT byte 1 — so a digit-prefix-only
/// reader would drop the child tags. [`crate::convert::perl_str_to_f64`] (the
/// `#133` Composite-engine port of that same grammar) supplies the coercion;
/// this truncates the `f64` toward zero (`int()` / the offset cast: `1000.0` →
/// 1000, `190.0` → 190, `-1.9e2` = `-190.0` → -190).
///
/// A non-finite coercion (`"inf"`/`"nan"` → `±Inf`/`NaN`) describes no seekable
/// directory — `ProcessBigIFD`'s `ReadValue`/`Seek` would yield no valid start —
/// so it is mapped to [`None`] (skip), exactly as a negative or oversized finite
/// offset is skipped. A token with no leading numeric run yields 0 (Perl's `0 +
/// "abc"`): bundled then recurses at byte 0 (the header) — a degenerate but real
/// recursion (ground-truthed: it reads the header as a directory count, hence a
/// content-dependent `Huge directory counts` warning, NOT a skip), so `"abc"` →
/// `Some(0)`. The caller has already split on whitespace, so `tok` carries no
/// surrounding spaces.
///
/// # IV/UV-vs-NV dispatch (the precision-faithful core)
///
/// BigTIFF is the 64-bit-offset format, so a pointer token can span the FULL
/// `u64` surface, and an `f64` round-trip loses precision above `2^53`
/// (`int(0 + '9007199254740993')` is `9007199254740993` on a 64-bit Perl, but
/// the `f64` path yields `9007199254740992` — off by one, recursing the wrong
/// byte). Perl's `grok_number`/`my_atof` does NOT go through `NV` for a scalar
/// whose WHOLE spelling is a clean 64-bit-fitting integer; it keeps the exact
/// `IV`/`UV`. So this mirrors that one boundary PER TOKEN, with no second
/// approximation of where integer ends and float begins:
///   - the EXACT checked-`u64` path is taken **iff the WHOLE token is a clean
///     Perl integer spelling** — `^[+-]?[0-9]+$`, an optional single sign then
///     one-or-more digits then END-OF-TOKEN — AND the magnitude fits `u64`. A
///     non-negative magnitude is the seek offset; a NEGATIVE one (Perl
///     `0 + "-5" == -5`, then ExifTool's `$subdirStart < 0 → Bad SubDirectory
///     start`, `Exif.pm:7017`) skips → [`None`];
///   - EVERY other token routes through [`crate::convert::perl_str_to_f64`] (the
///     `#133` Composite-engine port of Perl `my_atof`) → truncate toward zero
///     (`int()`) → range-check `[0, 2^64)` (out-of-range or non-finite → skip).
///     This is exactly the set Perl's integer fast-path does NOT accept wholly,
///     so Perl falls to `NV`: trailing junk after a digit run (`"9007199254740993abc"`
///     → `0 + …` is `9.0072e15` → `int` `…992`, NOT the exact `u64` of the
///     `…993` digit run; `"12abc"` → 12); a fraction/exponent (`"1.9e2"` → 190,
///     `"1e3"` → 1000); an MSVCRT non-finite spelling (`"1#INF"`/`"1#IND"`/
///     `"1#QNAN"` → ±Inf/NaN → skip) or a malformed one (`"1#IN"` → 1); a clean
///     all-digit magnitude `> u64::MAX` (`"18446744073709551616"` → an `NV`
///     `1.84e19` → out of range → skip); and an empty / sign-only token.
///
/// Verified against bundled Perl 5 / ExifTool 13.59 (`0 + $val`, `int(0 + $val)`):
/// `"9007199254740993"` → 9007199254740993 (EXACT, not `…992`);
/// `"9007199254740993abc"` → `…992` (NV path); `"18446744073709551615"`
/// (`u64::MAX`) → exact; `"18446744073709551616"` / `"99999999999999999999"`
/// (> `u64::MAX`) → an `NV` float → skip; `"1e3"` → 1000; `"1.9e2"` → 190;
/// `"12abc"` → 12; `"abc"` → 0; `"1#INF"` / `"1#IND"` / `"1#QNAN"` → skip;
/// `"1#IN"` → 1; `"-1e2"` → -100 (negative → skip); `"-5"` → skip. A crafted
/// BigTIFF whose GPSInfo (0x8825) SubIFD pointer is the ASCII string `"1e3"`
/// makes bundled recurse the child IFD at byte **1000** (emitting the child's
/// `GPSInfo:InteropIndex`/`InteropVersion`), NOT byte 1.
///
/// The returned [`u64`] is the byte offset to seek; the walker's EOF bound then
/// rejects an in-`u64`-but-past-end offset (the seek-fails-→-no-directory skip).
fn perl_int_prefix(tok: &str) -> Option<u64> {
  if let Some(parsed) = perl_integer_offset(tok) {
    // Wholly-integer (`^[+-]?[0-9]+$`) fast path: exact, no `f64`. `Some(off)` =
    // a non-negative `≤ u64::MAX` offset; `None` = a negative magnitude (skip).
    return parsed;
  }
  // EVERY not-wholly-integer token (trailing junk, fraction/exponent, non-finite
  // spelling, or a clean digit run `> u64::MAX`) goes through the one faithful
  // `f64` grammar — the single boundary, no second approximation.
  let f = crate::convert::perl_str_to_f64(tok);
  if !f.is_finite() {
    return None; // `±Inf` / `NaN`: no in-range directory.
  }
  let t = f.trunc(); // `int()` — truncate toward zero.
  // Range-check `[0, u64::MAX]` BEFORE recursing (do NOT saturate-then-seek): a
  // negative or `> u64::MAX` truncated `f64` resolves to no physical offset.
  // `u64::MAX as f64` rounds UP to `2^64`, so the strict `< 2^64` upper bound.
  if !(0.0..TWO_POW_64).contains(&t) {
    return None;
  }
  Some(t as u64)
}

/// `2^64` as an `f64` — the strict upper bound for a truncated-`f64` offset.
/// `u64::MAX` (`2^64 - 1`) is not exactly representable in `f64` (it rounds to
/// `2^64`), so a `≤ u64::MAX` test must compare `< 2^64`.
const TWO_POW_64: f64 = 18_446_744_073_709_551_616.0;

/// Perl's integer fast-path for a SubIFD-offset token: `Some(Some(off))` when the
/// token is INTEGER-shaped (Perl dual-sign + a leading decimal-digit run, no
/// fraction/exponent/`#` joining the numeric prefix) AND parses to a non-negative
/// `u64`; `Some(None)` when the token is a clean integer spelling but NEGATIVE
/// (skip, `$subdirStart < 0`); [`None`] when the token is NOT a clean integer —
/// trailing junk after a digit run, a fraction/exponent/non-finite spelling, OR
/// a clean all-digit magnitude that EXCEEDS `u64::MAX` (Perl spills it to an
/// `NV`) — all of which defer to [`crate::convert::perl_str_to_f64`].
///
/// This is the IV/UV-vs-NV boundary of Perl's `grok_number`/`my_atof`, mirrored
/// EXACTLY: the exact-integer fast path is taken **iff the WHOLE token is a clean
/// Perl integer spelling** — an optional single sign then one-or-more ASCII
/// digits then END-OF-TOKEN, i.e. the regex `^[+-]?[0-9]+$` with nothing
/// trailing — AND the magnitude fits `u64`. A scalar of that shape stays an exact
/// 64-bit `IV`/`UV` in Perl (no `NV` round-trip), so an offset above `2^53` is
/// byte-exact. Anything else is what Perl's integer fast-path does NOT accept
/// wholly, so Perl falls to `my_atof`/`NV`:
///   - trailing junk after the digits (`"9007199254740993abc"`, `"12abc"`) —
///     Perl numifies the leading run as a float (`0 + "9007199254740993abc"` is
///     `9.0072e15`, `int` → `…992`, NOT `…993`);
///   - a fraction or exponent (`"1.9e2"`, `"1e3"`);
///   - an MSVCRT non-finite spelling (`"1#INF"`/`"1#IND"`/`"1#QNAN"`) or a
///     malformed one (`"1#IN"` → Perl reads the integer `1`);
///   - a clean all-digit magnitude `> u64::MAX` (`"18446744073709551616"`): Perl
///     can't hold it in a `UV`, so it becomes an `NV` (`1.84e19`) — the `f64` arm
///     then range-checks it out (`> 2^64`) and skips;
///   - an empty or sign-only token (`""`, `"-"`).
///
/// Routing every not-wholly-integer token through the one faithful
/// [`crate::convert::perl_str_to_f64`] (the `#133` Composite-engine port of Perl
/// `my_atof`, which already mirrors the leading-numeric run, the dual-sign /
/// inter-sign-whitespace grammar, and the MSVCRT non-finite recognition) leaves
/// NO second approximation of the integer/float boundary to diverge.
fn perl_integer_offset(tok: &str) -> Option<Option<u64>> {
  let bytes = tok.as_bytes();
  // Optional SINGLE leading sign, then the token must be ALL ASCII digits to its
  // end (the `^[+-]?[0-9]+$` clean-integer spelling). A dual sign, inter-sign
  // whitespace, trailing junk, a `.`/`e`/`#`, or an empty digit run all fail this
  // and return `None` → the `f64` arm (Perl's `my_atof`/`NV`).
  let (negative, mag_bytes) = match bytes.split_first() {
    Some((&b'-', rest)) => (true, rest),
    Some((&b'+', rest)) => (false, rest),
    _ => (false, bytes),
  };
  if mag_bytes.is_empty() || !mag_bytes.iter().all(u8::is_ascii_digit) {
    return None; // not a clean integer spelling → defer to the `f64` arm.
  }
  // A clean `^[+-]?[0-9]+$` token: parse the EXACT magnitude as `u64` (no `f64`).
  // A magnitude `> u64::MAX` overflows the `parse` — Perl makes such a scalar an
  // `NV`, so defer to the `f64` arm (`None`), which range-checks it out. The
  // suffix slice is always in bounds (`mag_bytes` is the tail of `bytes`); the
  // `?` is a total formality.
  let mag_str = tok.get(tok.len() - mag_bytes.len()..)?;
  let Ok(mag) = mag_str.parse::<u64>() else {
    return None; // `> u64::MAX` magnitude → an `NV` → the `f64` arm.
  };
  if negative {
    // Perl `0 + "-5" == -5`; ExifTool's `$subdirStart < 0` skips it. A `-0`
    // (`mag == 0`) is `0`, a valid non-negative offset.
    if mag == 0 {
      return Some(Some(0));
    }
    return Some(None);
  }
  Some(Some(mag))
}

/// `numerator / denominator` as f64, `None` for a zero denominator — the
/// rational→float coercion [`RawValue::rational_pair`] uses.
fn ratio_f64(n: i64, d: i64) -> Option<f64> {
  if d == 0 {
    return None;
  }
  Some(n as f64 / d as f64)
}

// ===========================================================================
// ReadValue — the faithful port of ExifTool.pm:6275-6321
// ===========================================================================

/// The NUMBER OF ELEMENTS [`read_value`] will decode for these inputs — equal to
/// the count of `split ' '` tokens its `$val` yields — computed WITHOUT
/// materializing the values, sharing `read_value`'s exact count-clamping
/// (`ExifTool.pm:6285-6293` + the window re-shorten) so the two can never diverge.
///
/// Returns:
///  - `None` — the `read_value` `return undef` cases (`$count < 1` after the
///    `$len*$count > $size` re-clamp, or nothing fits the window);
///  - `Some(0)` — ONLY the `count == 0 && size < len` empty-value path
///    (`read_value` returns `Some(empty_value)`, whose `$val` is the empty string
///    ⇒ zero `split ' '` tokens);
///  - `Some(n)` (n >= 1) — the final clamped element count.
///
/// The DoS-bounded `0x014a SubIFD` parser ([`Walker::dispatch_classic_subifd`])
/// reads this to derive the `MaxSubdirs` overage (`@values - 10`,
/// `Exif.pm:6932`) from the integer count WITHOUT building the full
/// `RawValue`/`Vec`/`$val` string a hostile, huge-but-in-bounds count would
/// materialize.
#[must_use]
pub fn read_value_count(
  data: &[u8],
  offset: usize,
  format: Format,
  mut count: usize,
  size: usize,
) -> Option<usize> {
  let len = format.byte_size();
  if len == 0 {
    return None; // Unknown format — `read_value` returns `None` likewise.
  }
  // `unless ($count) { ... $count = int($size / $len) }` (ExifTool.pm:6285-6288).
  if count == 0 {
    if size < len {
      return Some(0); // `read_value` -> `Some(empty_value)`: an empty `$val`.
    }
    count = size / len;
  }
  // `if ($len * $count > $size) { $count = int($size / $len); ... }`
  // (ExifTool.pm:6290-6293).
  if len.saturating_mul(count) > size {
    count = size / len;
    if count < 1 {
      return None; // `$count < 1 and return undef`.
    }
  }
  // The window re-shorten (`read_value`'s `avail = window.len() / len`): bound the
  // count by the bytes actually present from `offset`. `window.len() = min(len*count,
  // data.len() - offset)` (for `offset <= data.len()`).
  let window_end = offset.saturating_add(len.saturating_mul(count));
  let window_len = window_end.min(data.len()).saturating_sub(offset);
  let count = count.min(window_len / len);
  if count == 0 {
    return None; // `read_value`'s final `if count == 0 { return None }`.
  }
  Some(count)
}

/// Decode `count` values of `format` from `data` starting at `offset` — the
/// faithful port of `ReadValue` (`ExifTool.pm:6275-6321`).
///
/// `size` is the valid byte length relative to `offset` (the IFD entry's
/// `$size`). If `format * count` exceeds `size`, the count is shortened
/// (`ExifTool.pm:6290-6293`); if NOTHING fits, returns `None` (Perl
/// `return undef`).
///
/// `Unknown` / zero-size formats return `None` — the IFD walker rejects an
/// `Unknown` format BEFORE calling this (`Exif.pm:6464-6477`), so the only
/// way to reach here with one would be a programming error.
#[must_use]
pub fn read_value(
  data: &[u8],
  offset: usize,
  format: Format,
  count: usize,
  size: usize,
  order: ByteOrder,
) -> Option<RawValue> {
  let len = format.byte_size();
  if len == 0 {
    return None; // Unknown format — `ReadValue` warns + len=1; walker pre-rejects.
  }
  let count = match read_value_count(data, offset, format, count, size) {
    // `read_value_count` returns `None` for the `read_value` `return undef` cases,
    // `Some(0)` ONLY for the `count == 0 && size < len` empty-value path, and
    // `Some(n)` (n>=1) for the clamped element count.
    None => return None,
    Some(0) => return Some(empty_value(format)),
    Some(n) => n,
  };
  // The byte window the values are read from. The IFD walker guarantees
  // `offset + len*count <= data.len()` for the inline (≤4-byte) case and the
  // out-of-line case alike; defend anyway (Perl's unpack would just stop). The
  // count is already clamped to the window by `read_value_count`, so the slice
  // never truncates here.
  let window_end = offset.saturating_add(len.saturating_mul(count));
  let window = data.get(offset..window_end.min(data.len()))?;

  // `count` is now `count.min(window.len() / len)` with `count >= 1`, so
  // `count * len <= window.len()`: every `window` access below is dominated by
  // this shorten and the checked `.get(..)?` recovers the same slice (its
  // `None` arm is unreachable). For the 1-byte string/undef formats `len == 1`,
  // so `count <= window.len()`.
  Some(match format {
    // ---- string types (no readValueProc — ExifTool.pm:6296-6302) ----------
    Format::Ascii => {
      // `substr` then `s/\0.*//s` — trim at the FIRST NUL.
      let raw = window.get(..count)?;
      let trimmed = match raw.iter().position(|&b| b == 0) {
        Some(nul) => raw.get(..nul).unwrap_or(raw),
        None => raw,
      };
      // ExifTool's `string` is Latin-1-ish bytes; for byte-equivalence with
      // the JSON oracle we keep valid UTF-8 verbatim and lossy-replace the
      // rare non-UTF-8 byte (the bundled camera fixtures are all ASCII). The
      // pre-FixUTF8 `trimmed` bytes are retained as `raw` so a byte-walking
      // RawConv reads `$val`'s ORIGINAL bytes, not the lossy re-encoding.
      RawValue::Text {
        text: lossy_string(trimmed),
        raw: trimmed.into(),
      }
    }
    Format::Utf8 => {
      // Exif 3.0 `utf8` — decoded as UTF-8 (`Exif.pm:6786` `Decode(.., 'UTF8')`).
      let raw = window.get(..count)?;
      let trimmed = match raw.iter().position(|&b| b == 0) {
        Some(nul) => raw.get(..nul).unwrap_or(raw),
        None => raw,
      };
      RawValue::Text {
        text: lossy_string(trimmed),
        raw: trimmed.into(),
      }
    }
    Format::Undef | Format::Unicode | Format::Complex => {
      // `undef`/`binary` — raw bytes, NOT NUL-trimmed. (`Unicode`/`Complex`
      // are unreachable here: the IFD walker rejects codes 14/15 as `Bad
      // format` before `read_value`; the arm is folded in only for the match.)
      RawValue::Bytes(window.get(..count * len)?.to_vec())
    }
    // ---- integer types ----------------------------------------------------
    Format::Int8u => RawValue::U64(
      (0..count)
        .map(|i| u64::from(window.get(i).copied().unwrap_or(0)))
        .collect(),
    ),
    Format::Int8s => RawValue::I64(
      (0..count)
        .map(|i| i64::from(window.get(i).copied().unwrap_or(0) as i8))
        .collect(),
    ),
    Format::Int16u => RawValue::U64(
      (0..count)
        .map(|i| u64::from(get_u16(window, i * 2, order).unwrap_or(0)))
        .collect(),
    ),
    Format::Int16s => RawValue::I64(
      (0..count)
        .map(|i| i64::from(get_i16(window, i * 2, order).unwrap_or(0)))
        .collect(),
    ),
    Format::Int32u | Format::Ifd => RawValue::U64(
      (0..count)
        .map(|i| u64::from(get_u32(window, i * 4, order).unwrap_or(0)))
        .collect(),
    ),
    Format::Int32s => RawValue::I64(
      (0..count)
        .map(|i| i64::from(get_i32(window, i * 4, order).unwrap_or(0)))
        .collect(),
    ),
    Format::Int64u | Format::Ifd64 => RawValue::U64(
      (0..count)
        .map(|i| get_u64(window, i * 8, order).unwrap_or(0))
        .collect(),
    ),
    Format::Int64s => RawValue::I64(
      (0..count)
        .map(|i| get_i64(window, i * 8, order).unwrap_or(0))
        .collect(),
    ),
    // ---- float types ------------------------------------------------------
    Format::Float => RawValue::F64(
      (0..count)
        .map(|i| f64::from(get_f32(window, i * 4, order).unwrap_or(0.0)))
        .collect(),
    ),
    Format::Double => RawValue::F64(
      (0..count)
        .map(|i| get_f64(window, i * 8, order).unwrap_or(0.0))
        .collect(),
    ),
    // ---- rational types (ExifTool.pm:6303-6314 — stored as Rational) ------
    Format::Rational64u => RawValue::Rational(
      (0..count)
        .map(|i| {
          let n = get_u32(window, i * 8, order).unwrap_or(0);
          let d = get_u32(window, i * 8 + 4, order).unwrap_or(0);
          // `GetRational64u`: numerator/denominator as int32u → 10-sig
          // RoundFloat (ExifTool.pm:6103-6109). The `Rational` carries
          // both components so `exiftool_val_str` can render inf/undef.
          Rational::rational64(i64::from(n), i64::from(d))
        })
        .collect(),
    ),
    Format::Rational64s => RawValue::Rational(
      (0..count)
        .map(|i| {
          let n = get_i32(window, i * 8, order).unwrap_or(0);
          let d = get_i32(window, i * 8 + 4, order).unwrap_or(0);
          Rational::rational64(i64::from(n), i64::from(d))
        })
        .collect(),
    ),
    // The IFD walker rejects `Unknown` before reaching `read_value`; the
    // `len == 0` guard above already returned `None`. Arm kept for the
    // exhaustive match.
    Format::Unknown(_) => return None,
  })
}

/// The "empty value" `ReadValue` returns when `defined $count` and the data
/// is too short (`ExifTool.pm:6286` `return ''`). For a string format that
/// is the empty string; for the others an empty list.
fn empty_value(format: Format) -> RawValue {
  match format {
    Format::Ascii | Format::Utf8 => RawValue::Text {
      text: std::string::String::new(),
      raw: Box::default(),
    },
    Format::Undef | Format::Unicode | Format::Complex => RawValue::Bytes(Vec::new()),
    Format::Int8s | Format::Int16s | Format::Int32s | Format::Int64s => RawValue::I64(Vec::new()),
    Format::Float | Format::Double => RawValue::F64(Vec::new()),
    Format::Rational64u | Format::Rational64s => RawValue::Rational(Vec::new()),
    _ => RawValue::U64(Vec::new()),
  }
}

/// Decode a TIFF `string`-format byte slice to a Rust `String`. ExifTool
/// treats `string` as bytes under the `CharsetEXIF` charset (default UTF-8 —
/// `ExifTool.pm:6296-6300`); for byte-equivalence with the JSON oracle we
/// keep valid UTF-8 verbatim and `from_utf8_lossy`-replace the rare invalid
/// byte (no bundled camera fixture exercises a non-UTF-8 EXIF string).
fn lossy_string(raw: &[u8]) -> std::string::String {
  match core::str::from_utf8(raw) {
    Ok(s) => s.to_string(),
    Err(_) => std::string::String::from_utf8_lossy(raw).into_owned(),
  }
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2d); the test fixtures index fixed-layout buffers freely
// (an out-of-range index is a test-assertion failure, not a shipped panic), so
// the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  #[test]
  fn byte_order_decode() {
    assert_eq!(ByteOrder::from_marker(b"II*\0"), Some(ByteOrder::Little));
    assert_eq!(ByteOrder::from_marker(b"MM\0*"), Some(ByteOrder::Big));
    assert_eq!(ByteOrder::from_marker(b"XX"), None);
    assert_eq!(ByteOrder::from_marker(b"I"), None);
    assert_eq!(ByteOrder::Little.as_str(), "II");
    assert_eq!(ByteOrder::Big.print_conv(), "Big-endian (Motorola, MM)");
  }

  #[test]
  fn get_integers_both_orders() {
    let data = [0x12, 0x34, 0x56, 0x78];
    assert_eq!(get_u16(&data, 0, ByteOrder::Big), Some(0x1234));
    assert_eq!(get_u16(&data, 0, ByteOrder::Little), Some(0x3412));
    assert_eq!(get_u32(&data, 0, ByteOrder::Big), Some(0x1234_5678));
    assert_eq!(get_u32(&data, 0, ByteOrder::Little), Some(0x7856_3412));
    // Out-of-bounds is None, not a panic.
    assert_eq!(get_u32(&data, 2, ByteOrder::Big), None);
  }

  #[test]
  fn format_code_round_trip() {
    assert_eq!(Format::from_code(1), Format::Int8u);
    assert_eq!(Format::from_code(5), Format::Rational64u);
    assert_eq!(Format::from_code(13), Format::Ifd);
    assert_eq!(Format::from_code(129), Format::Utf8);
    assert_eq!(Format::from_code(99), Format::Unknown(99));
    assert_eq!(Format::Rational64u.byte_size(), 8);
    assert_eq!(Format::Int16u.byte_size(), 2);
    assert!(Format::Int32u.is_int());
    assert!(!Format::Rational64u.is_int());
    assert!(Format::Ifd.is_int());
  }

  #[test]
  fn read_value_ascii_trims_at_first_nul() {
    // "Canon\0..." — string trims at the first NUL (ExifTool.pm:6301).
    let data = b"Canon\0junk";
    let v = read_value(data, 0, Format::Ascii, 10, 10, ByteOrder::Big).unwrap();
    assert_eq!(
      v,
      RawValue::Text {
        text: "Canon".to_string(),
        raw: b"Canon"[..].into(),
      }
    );
  }

  #[test]
  fn val_bytes_returns_original_for_every_shape() {
    use std::borrow::Cow;
    // Text → the pre-FixUTF8 raw bytes (NOT the lossy text).
    let t = RawValue::Text {
      text: "A\u{fffd}".into(),
      raw: b"A\xff"[..].into(),
    };
    assert_eq!(&*t.val_bytes(), b"A\xff");
    assert!(matches!(t.val_bytes(), Cow::Borrowed(_)));
    // Bytes → the bytes verbatim.
    let b = RawValue::Bytes(vec![1, 2, 3]);
    assert_eq!(&*b.val_bytes(), &[1, 2, 3]);
    assert!(matches!(b.val_bytes(), Cow::Borrowed(_)));
    // numeric → ExifTool's space-joined `$val` rendering, as bytes.
    let n = RawValue::U64(vec![16706, 17220]);
    assert_eq!(&*n.val_bytes(), b"16706 17220");
    assert!(matches!(n.val_bytes(), Cow::Owned(_)));
    // signed + float + rational shapes render via the same token form
    // `value_space_joined`/`emit_raw` use.
    assert_eq!(&*RawValue::I64(vec![-5, 7]).val_bytes(), b"-5 7");
    assert_eq!(&*RawValue::F64(vec![1.5, -0.25]).val_bytes(), b"1.5 -0.25");
    assert_eq!(
      &*RawValue::Rational(vec![Rational::new(1, 2, 7), Rational::new(3, 1, 7)]).val_bytes(),
      b"0.5 3"
    );
  }

  /// #240 round 2 — `subdir_offsets` is the faithful `my @offsets = split ' ',
  /// $val` (`BigTIFF.pm:184`) over the `$val` STRING form for EVERY shape, with
  /// Perl numeric coercion per token. It must:
  ///   - return EVERY offset of a count>1 numeric pointer (not just the first);
  ///   - numify an ASCII-numeric `string`/`undef` pointer (the case
  ///     `first_subdir_offset` dropped as a non-`U64`/`I64` shape);
  ///   - match `first_subdir_offset` for the single-offset camera shape.
  #[test]
  fn subdir_offsets_splits_every_token_and_ascii() {
    // count>1 LONG8 → both offsets, in order.
    assert_eq!(
      RawValue::U64(vec![88, 124]).subdir_offsets(),
      vec![Some(88), Some(124)]
    );
    assert_eq!(
      RawValue::U64(vec![96, 132, 168]).subdir_offsets(),
      vec![Some(96), Some(132), Some(168)]
    );
    // signed shape → a negative offset is SKIPPED (`None`), the `Bad SubDirectory
    // start` analogue (`$subdirStart < 0`); the positive sibling keeps its slot.
    assert_eq!(
      RawValue::I64(vec![-5, 7]).subdir_offsets(),
      vec![None, Some(7)]
    );
    // ASCII single "72" → one offset 72 (the `RawValue::Text` case
    // `first_subdir_offset` returned `None` for).
    let ascii = RawValue::Text {
      text: "72".into(),
      raw: b"72"[..].into(),
    };
    assert_eq!(ascii.subdir_offsets(), vec![Some(72)]);
    assert!(
      ascii.first_subdir_offset().is_none(),
      "the old extractor drops an ASCII pointer"
    );
    // ASCII multi-token "88 124" → split on whitespace → two offsets.
    let ascii_multi = RawValue::Text {
      text: "88 124".into(),
      raw: b"88 124"[..].into(),
    };
    assert_eq!(ascii_multi.subdir_offsets(), vec![Some(88), Some(124)]);
    // Perl numeric coercion of degenerate tokens: leading-numeric prefix
    // (`"72abc"` → 72), leading whitespace stripped (`" 72"` → 72), no leading
    // digits → 0 (`"abc"` → 0, the degenerate offset-0 recursion bundled takes).
    let junk = RawValue::Text {
      text: "72abc".into(),
      raw: b"72abc"[..].into(),
    };
    assert_eq!(junk.subdir_offsets(), vec![Some(72)]);
    let lead_space = RawValue::Text {
      text: " 72".into(),
      raw: b" 72"[..].into(),
    };
    assert_eq!(lead_space.subdir_offsets(), vec![Some(72)]);
    let nonnum = RawValue::Text {
      text: "abc".into(),
      raw: b"abc"[..].into(),
    };
    assert_eq!(nonnum.subdir_offsets(), vec![Some(0)]);
    // ASCII exponent/fraction token — the Perl numeric grammar (`0 + "1e3" ==
    // 1000`), the class the digit-prefix-only reader mis-coerced to 1. Ground-
    // truthed: bundled recurses the child IFD at byte 1000 (not byte 1).
    let exp = RawValue::Text {
      text: "1e3".into(),
      raw: b"1e3"[..].into(),
    };
    assert_eq!(exp.subdir_offsets(), vec![Some(1000)]);
    let exp_multi = RawValue::Text {
      text: "1e3 1.9e2".into(),
      raw: b"1e3 1.9e2"[..].into(),
    };
    assert_eq!(exp_multi.subdir_offsets(), vec![Some(1000), Some(190)]);
    // #240 R4 boundary, end-to-end: a trailing-junk token whose digit run
    // exceeds `2^53` numifies via the `f64`/NV path (`…992`), NOT the exact `u64`
    // of the leading digits (`…993`). Paired with a clean integer token (which
    // stays exact) and a `1#INF` non-finite (skipped) in one `split ' '` value.
    let boundary = RawValue::Text {
      text: "9007199254740993abc 9007199254740993 1#INF".into(),
      raw: b"9007199254740993abc 9007199254740993 1#INF"[..].into(),
    };
    assert_eq!(
      boundary.subdir_offsets(),
      vec![
        Some(9_007_199_254_740_992),
        Some(9_007_199_254_740_993),
        None
      ],
      "trailing junk → f64 (…992); clean integer → exact (…993); 1#INF → skip"
    );
    // Single-offset numeric → identical to `first_subdir_offset` (modulo the
    // `Some`-wrap; `first_subdir_offset` is `i64`, `subdir_offsets` a `u64`
    // offset).
    let single = RawValue::U64(vec![112]);
    assert_eq!(single.subdir_offsets(), vec![Some(112)]);
    assert_eq!(single.first_subdir_offset(), Some(112));
  }

  /// `perl_int_prefix` coerces one `split ' '` token to an offset the way Perl
  /// numifies a string used as `Start => $offsets[$i]`, mirroring Perl
  /// `grok_number`'s IV/UV-vs-NV boundary EXACTLY: the exact checked-`u64` path
  /// is taken IFF the WHOLE token is a clean Perl integer spelling
  /// (`^[+-]?[0-9]+$`) that fits `u64` (byte-exact across the full 64-bit
  /// surface, NO `f64` above `2^53`); a non-negative magnitude is the offset, a
  /// negative one skips. EVERY other token — trailing junk after a digit run, a
  /// fraction/exponent, an MSVCRT non-finite spelling, OR a clean digit run that
  /// exceeds `u64::MAX` (Perl spills it to an `NV`) — routes through the one
  /// faithful `perl_str_to_f64` (truncate toward zero, range-check `[0, 2^64)`,
  /// non-finite → skip). Every value is ground-truthed against bundled Perl 5 /
  /// ExifTool 13.59 (`0 + $val` and `int(0 + $val)`).
  #[test]
  fn perl_int_prefix_numifies_like_perl() {
    assert_eq!(perl_int_prefix("72"), Some(72)); // clean integer → exact path
    assert_eq!(perl_int_prefix("72abc"), Some(72)); // trailing junk → f64 → 72.0
    assert_eq!(perl_int_prefix("abc"), Some(0)); // no leading numeric run → f64 → 0
    assert_eq!(perl_int_prefix(""), Some(0)); // empty → f64 → 0
    // A negative offset is SKIPPED (`$subdirStart < 0 → Bad SubDirectory start`),
    // not carried as a signed value.
    assert_eq!(perl_int_prefix("-5"), None);
    assert_eq!(perl_int_prefix("+5"), Some(5)); // clean signed integer → exact path
    assert_eq!(perl_int_prefix("0"), Some(0));
    assert_eq!(perl_int_prefix("-0"), Some(0)); // `0 + "-0" == 0` → a valid offset
    assert_eq!(perl_int_prefix("007"), Some(7)); // leading zeros
    // Exponent / fraction forms — Perl numeric context, the class #240 R1/R2
    // fixed (`0 + "1e3" == 1000`, NOT the digit-prefix-only `1`). These are NOT
    // clean integer spellings, so they route through the `f64` arm; truncated
    // toward zero, then range-checked `[0, u64::MAX]`.
    assert_eq!(perl_int_prefix("1e3"), Some(1000)); // 0 + "1e3" == 1000
    assert_eq!(perl_int_prefix("1.9e2"), Some(190)); // 1.9e2 == 190.0 → 190
    assert_eq!(perl_int_prefix("1.5e2"), Some(150)); // 150.0 → 150
    assert_eq!(perl_int_prefix("-1e2"), None); // -100.0 < 0 → skip
    assert_eq!(perl_int_prefix("12abc"), Some(12)); // trailing junk → f64 → 12.0
    assert_eq!(perl_int_prefix("3.9"), Some(3)); // truncate toward zero, not round
    assert_eq!(perl_int_prefix("-3.9"), None); // -3.9 < 0 → skip
    // `"12e"` / `"12e+"` — an `e` with no power digit is NOT an exponent; the
    // token is not a clean integer either (the `e`), so it routes through the
    // `f64` arm, where `perl_str_to_f64` reads the `12` mantissa → 12.0.
    assert_eq!(perl_int_prefix("12e"), Some(12));
    assert_eq!(perl_int_prefix("12e+"), Some(12));
    // A non-finite coercion (no seekable directory) → skip.
    assert_eq!(perl_int_prefix("inf"), None);
    assert_eq!(perl_int_prefix("nan"), None);
    assert_eq!(perl_int_prefix("-inf"), None);

    // ---- THE PRECISION CASE (#240 R3 finding) ----------------------------
    // A CLEAN integer offset ABOVE `2^53` must be EXACT via the wholly-integer
    // path — it must NOT round-trip through `f64` (which would yield `…992`, off
    // by one, recursing the wrong byte). Ground-truthed: bundled
    // `0 + "9007199254740993"` == 9007199254740993 (the exact 64-bit IV/UV), NOT
    // 9007199254740992.
    assert_eq!(
      perl_int_prefix("9007199254740993"),
      Some(9_007_199_254_740_993),
      "a clean integer offset above 2^53 must be exact (not the f64-rounded …992)"
    );
    assert_ne!(
      perl_int_prefix("9007199254740993"),
      Some(9_007_199_254_740_992),
      "the wholly-integer path must not collapse to the 2^53-rounded value"
    );
    // The boundary itself and one above are also exact.
    assert_eq!(perl_int_prefix("9007199254740992"), Some(1u64 << 53)); // 2^53
    assert_eq!(perl_int_prefix("9007199254740994"), Some((1u64 << 53) + 2));
    // `i64::MAX` and the range above it up to `u64::MAX` are exact (the old `i64`
    // path could not represent above `i64::MAX`).
    assert_eq!(
      perl_int_prefix("9223372036854775807"),
      Some(i64::MAX as u64)
    ); // i64::MAX
    assert_eq!(perl_int_prefix("9223372036854775808"), Some(1u64 << 63)); // i64::MAX+1
    assert_eq!(perl_int_prefix("18446744073709551615"), Some(u64::MAX)); // u64::MAX (UV)

    // ---- THE BOUNDARY CASE (#240 R4 finding): trailing junk after a digit run
    // that exceeds `2^53` must take the `f64` (NV) path, NOT the exact path.
    // Ground-truthed: bundled `0 + "9007199254740993abc"` == 9.0072e15 (an `NV`,
    // the trailing junk forcing `my_atof`), `int` → 9007199254740992 — NOT the
    // exact-`u64`-of-the-leading-digits 9007199254740993, and NOT a stop-at-993
    // truncation either. The structural boundary: a clean integer spelling is
    // exact; ANY trailing junk routes through the single faithful `f64` path.
    assert_eq!(
      perl_int_prefix("9007199254740993abc"),
      Some(9_007_199_254_740_992),
      "trailing junk above 2^53 must numify via the f64/NV path (…992), not the exact u64 of 993"
    );
    assert_ne!(
      perl_int_prefix("9007199254740993abc"),
      Some(9_007_199_254_740_993),
      "trailing junk must NOT take the exact-u64 path of the leading digit run"
    );

    // ---- MSVCRT non-finite spellings (#240 R4): `1#INF`/`1#IND`/`1#QNAN` are
    // recognised by `perl_str_to_f64` as ±Inf / NaN → non-finite → skip (no
    // seekable directory). Ground-truthed: `0 + "1#INF"` == Inf, `0 + "1#IND"`
    // and `0 + "1#QNAN"` == NaN. They are NOT clean integers, so they route
    // through the `f64` arm and are rejected there.
    assert_eq!(perl_int_prefix("1#INF"), None);
    assert_eq!(perl_int_prefix("1#IND"), None);
    assert_eq!(perl_int_prefix("1#QNAN"), None);
    // A MALFORMED MSVCRT spelling (`1#IN`) is NOT a recognised non-finite form;
    // `perl_str_to_f64` reads the `1` mantissa (`#` terminates the prefix) →
    // 1.0. Ground-truthed: bundled `int(0 + "1#IN")` == 1.
    assert_eq!(perl_int_prefix("1#IN"), Some(1));

    // ---- RANGE REJECTION (above u64::MAX / Perl spills to NV) ------------
    // A CLEAN all-digit token that exceeds `u64::MAX` is NOT held in a Perl `UV`;
    // it becomes an `NV` (`0 + "18446744073709551616"` == 1.84467440737096e+19),
    // a non-physical offset no `Seek` resolves → the wholly-integer path falls
    // through to the `f64` arm, which range-checks it out → skip. NOT a
    // saturate-then-seek.
    assert_eq!(perl_int_prefix("18446744073709551616"), None); // u64::MAX + 1 (clean >u64)
    assert_eq!(perl_int_prefix("99999999999999999999"), None); // ~1e20 > 2^64
    assert_eq!(perl_int_prefix("99999999999999999999999"), None); // far above
    assert_eq!(perl_int_prefix("-99999999999999999999999"), None); // negative
  }

  /// LOCKS the Perl-faithful handling of a NEGATIVE *fractional* SubIFD-offset
  /// token (the `f64` arm). The SubIFD start is `int(0 + $token)` and ExifTool
  /// skips the directory IFF that integer is `< 0` (`Exif.pm:7017`
  /// `$subdirStart < 0`, computed from the `Start => $val[0]` eval at
  /// `Exif.pm:6956` then `IsInt` at `:5954`). Perl `int()` truncates TOWARD
  /// ZERO, so a magnitude-`< 1` negative numifies to `0` (a VALID offset →
  /// recurse at byte 0), and ONLY a magnitude-`>= 1` negative gives a negative
  /// `int` (→ skip). The `f64` arm mirrors this BY CONSTRUCTION:
  /// `(-0.5).trunc()` is `-0.0`, which `(0.0..2^64).contains` accepts (`-0.0 ==
  /// 0.0`) → `Some(0)`; `(-1.5).trunc()` is `-1.0`, out of range → `None`. So
  /// the trunc-then-`[0, 2^64)` range-check is faithful WITHOUT a separate
  /// pre-truncation sign test.
  ///
  /// Anti-regression: a reviewer "fix" that skips when the *raw* token is `< 0`
  /// BEFORE truncating (e.g. an early `if f < 0.0 { return None }`) would WRONGLY
  /// skip `-0.5` / `-0.9` (Perl `int` → `0`, recurse@0). The faithful invariant
  /// is `int(token) < 0` (POST-truncation), NOT `token < 0`. All values
  /// ground-truthed against bundled Perl 5 / ExifTool 13.59
  /// (`int(0 + "-0.5")` == 0, `int(0 + "-1.5")` == -1).
  #[test]
  fn perl_int_prefix_negative_fraction_truncates_toward_zero() {
    // Magnitude-`< 1` negatives: `int()` truncates to `0` → recurse at byte 0
    // (NOT a skip). These all route through the `f64` arm (a `.`/`e` makes them
    // non-clean-integer); `trunc()` yields `-0.0`, which is `>= 0.0`.
    assert_eq!(
      perl_int_prefix("-0.5"),
      Some(0),
      "int(-0.5) == 0 → recurse@0; the raw token being negative must NOT skip"
    );
    assert_eq!(perl_int_prefix("-.5"), Some(0)); // int(-0.5) == 0
    assert_eq!(perl_int_prefix("-1e-1"), Some(0)); // -0.1 → int 0
    assert_eq!(perl_int_prefix("-0.0"), Some(0)); // int(-0.0) == 0
    assert_eq!(perl_int_prefix("-0.9"), Some(0)); // int(-0.9) == 0 (truncate, not round)

    // Magnitude-`>= 1` negatives: `int()` is a NEGATIVE integer → no seekable
    // directory → skip. The fractional forms route through the `f64` arm
    // (`trunc()` is `<= -1.0`, out of `[0, 2^64)`); the clean-integer forms
    // (`-5`, `-100`) are caught earlier by `perl_integer_offset` as `Some(None)`.
    assert_eq!(perl_int_prefix("-1.5"), None, "int(-1.5) == -1 < 0 → skip");
    assert_eq!(perl_int_prefix("-2.9"), None); // int(-2.9) == -2 < 0 → skip
    assert_eq!(perl_int_prefix("-100.5"), None); // int(-100.5) == -100 < 0 → skip
    assert_eq!(perl_int_prefix("-5"), None); // clean integer, int -5 < 0 → skip
    assert_eq!(perl_int_prefix("-100"), None); // clean integer, int -100 < 0 → skip
  }

  #[test]
  fn read_value_u16_array() {
    // BitsPerSample "8 8 8" — three int16u (MM order).
    let data = [0x00, 0x08, 0x00, 0x08, 0x00, 0x08];
    let v = read_value(&data, 0, Format::Int16u, 3, 6, ByteOrder::Big).unwrap();
    assert_eq!(v, RawValue::U64(vec![8, 8, 8]));
    assert_eq!(v.count(), 3);
  }

  #[test]
  fn read_value_rational64u() {
    // 180/1 (XResolution) — MM order.
    let data = [0x00, 0x00, 0x00, 0xb4, 0x00, 0x00, 0x00, 0x01];
    let v = read_value(&data, 0, Format::Rational64u, 1, 8, ByteOrder::Big).unwrap();
    match v {
      RawValue::Rational(rs) => {
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].numerator(), 180);
        assert_eq!(rs[0].denominator(), 1);
        assert_eq!(rs[0].sig(), 10);
      }
      other => panic!("expected Rational, got {other:?}"),
    }
  }

  #[test]
  fn read_value_shortens_count_when_size_too_small() {
    // Ask for 4 int32u but only 8 bytes available ⇒ count shortened to 2.
    let data = [0u8; 8];
    let v = read_value(&data, 0, Format::Int32u, 4, 8, ByteOrder::Big).unwrap();
    assert_eq!(v.count(), 2);
  }

  #[test]
  fn read_value_returns_none_when_nothing_fits() {
    let data = [0u8; 2];
    // 4-byte int32u, count 1, only 2 bytes ⇒ None.
    assert!(read_value(&data, 0, Format::Int32u, 1, 2, ByteOrder::Big).is_none());
  }

  /// `read_value_count` (the DoS-bound element-count probe, #331-P2 Finding 1)
  /// must report EXACTLY what `read_value` decodes — the count of `split ' '`
  /// tokens its `$val` yields — across every clamp branch, WITHOUT materializing
  /// the values. Sweep representative shapes (incl. a large in-bounds count: the
  /// DoS case) and assert the two never diverge.
  #[test]
  fn read_value_count_matches_read_value_element_count() {
    let data = [0u8; 4096];
    let order = ByteOrder::Little;
    // (format, count, size) cases: exact-fit, count==0 derive, len*count>size
    // re-clamp, window truncation, a HUGE in-bounds count (DoS), and a
    // nothing-fits None.
    let cases: &[(Format, usize, usize)] = &[
      (Format::Int32u, 3, 12),     // exact: 3 elements.
      (Format::Int16u, 0, 10),     // count==0 ⇒ 10/2 = 5.
      (Format::Int8u, 0, 0),       // count==0, size<len ⇒ empty (0 tokens).
      (Format::Int32u, 100, 12),   // len*count>size ⇒ re-clamp to 3.
      (Format::Int8u, 4096, 4096), // HUGE in-bounds count: the DoS shape ⇒ 4096.
      (Format::Int8u, 1000, 50),   // re-clamp to 50.
      (Format::Int32u, 1, 2),      // nothing fits ⇒ None / 0.
    ];
    for &(format, count, size) in cases {
      let probed = read_value_count(&data, 0, format, count, size);
      let actual = read_value(&data, 0, format, count, size, order);
      let actual_tokens = match &actual {
        // The empty-value case (`count==0 && size<len`) ⇒ an empty `$val` ⇒ 0
        // split tokens; `read_value_count` reports `Some(0)`.
        Some(v) if v.count() == 0 => Some(0usize),
        Some(v) => Some(v.count()),
        None => None,
      };
      assert_eq!(
        probed, actual_tokens,
        "read_value_count != read_value element count for {format:?} count={count} size={size}"
      );
    }
  }
}
