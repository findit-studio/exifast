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
  mut count: usize,
  size: usize,
  order: ByteOrder,
) -> Option<RawValue> {
  let len = format.byte_size();
  if len == 0 {
    return None; // Unknown format — `ReadValue` warns + len=1; walker pre-rejects.
  }
  // `unless ($count) { ... $count = int($size / $len) }` (ExifTool.pm:6285-6288)
  if count == 0 {
    if size < len {
      return Some(empty_value(format));
    }
    count = size / len;
  }
  // `if ($len * $count > $size) { $count = int($size / $len); ... }`
  // (ExifTool.pm:6290-6293)
  if len.saturating_mul(count) > size {
    count = size / len;
    if count < 1 {
      return None; // `$count < 1 and return undef`
    }
  }
  // The byte window the values are read from. The IFD walker guarantees
  // `offset + len*count <= data.len()` for the inline (≤4-byte) case and the
  // out-of-line case alike; defend anyway (Perl's unpack would just stop).
  let window_end = offset.saturating_add(len.saturating_mul(count));
  let window = data.get(offset..window_end.min(data.len()))?;
  // Re-shorten if the slice truncated the window (mirrors Perl's `unpack`
  // simply yielding fewer items for a short buffer).
  let avail = window.len() / len;
  let count = count.min(avail);
  if count == 0 {
    return None;
  }

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
}
