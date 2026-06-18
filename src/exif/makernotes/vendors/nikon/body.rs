// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Nikon MakerNote IFD body helpers — the decrypt-key pre-scan, the
//! embedded-TIFF header resolver, and the decoded-value wrapper for the
//! `%Image::ExifTool::Nikon::Main` (`Nikon.pm:1778`) walk.
//!
//! Single-walker invariant (#243 phase 5): the Main-IFD extraction is the
//! shared `Walker` (`crate::exif::nikon_makernote_isolated`); the per-vendor
//! `walk_nikon_ifd` oracle + the `parse` / `parse_in_tiff` entry points were
//! deleted (do not reintroduce a second Nikon walker). What survives here is
//! shared with that isolated path: [`prescan_decrypt_keys`] (the separate
//! `PrescanExif` key scan), [`parse_embedded_tiff`] (the type-3 header
//! resolver), and the [`ParsedValue`] decode wrapper.
//!
//! ## Header layouts (`MakerNotes.pm:48-554`)
//!
//! Nikon writes three MakerNote layouts; the dispatcher
//! ([`crate::exif::makernotes::dispatch`]) classifies them and supplies the
//! `Start`/`Base`/`ByteOrder` directives:
//!
//! - **Type 3 (`MakerNoteNikon`, `MakerNotes.pm:51-58`)** — the modern DSLR
//!   layout: 6-byte `"Nikon\0"` + a 2-byte version (`\x02\x10`/`\x02\x00`) +
//!   2 pad bytes, then an EMBEDDED TIFF header at blob offset 10
//!   (`MM`/`II` + `0x002a` magic + the 4-byte IFD0 offset). `Start =>
//!   '$valuePtr + 18'` points at the IFD itself (`10 + 8`); the `Base =>
//!   '$start - 8'` directive makes out-of-line value offsets relative to the
//!   EMBEDDED TIFF header (blob offset 10), so the IFD is self-contained.
//! - **Type 2 (`MakerNoteNikon2`, `MakerNotes.pm:539-545`)** — `"Nikon\0\x01"`
//!   header; `Start => '$valuePtr + 8'`, no `Base` override (offsets
//!   blob-relative), explicit `LittleEndian`.
//! - **Type 1 / headerless (`MakerNoteNikon3`, `MakerNotes.pm:549-554`)** —
//!   no `"Nikon"` prefix; `Make =~ /^NIKON/i`; the blob IS the IFD (`Start`
//!   defaults to `$valuePtr`), `ByteOrder => 'Unknown'`.
//!
//! These layouts decide the `(ifd_offset, byte order, value_base)` the shared
//! `Walker` and [`prescan_decrypt_keys`] are handed: Type-3 sets
//! `value_base = 10`; the headerless / type-2 layouts set `value_base = 0`
//! (blob-relative). [`parse_embedded_tiff`] resolves the Type-3 embedded-TIFF
//! header. Every read here is a checked `.get()` (panic-free, bounded).

#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::{ByteOrder, Format, RawValue, read_value};
use crate::value::TagValue;
use std::vec::Vec;

/// One decoded IFD value (the post-Format-decode `$val`), wrapping
/// [`RawValue`] with the Nikon conversion helpers.
#[derive(Debug, Clone)]
pub struct ParsedValue {
  raw: RawValue,
}

impl ParsedValue {
  /// Wrap a decoded [`RawValue`].
  #[must_use]
  #[inline(always)]
  pub const fn new(raw: RawValue) -> Self {
    Self { raw }
  }

  /// Borrow the underlying raw value.
  #[must_use]
  #[inline(always)]
  pub const fn raw(&self) -> &RawValue {
    &self.raw
  }

  /// The first scalar integer (signed), accepting `U64`/`I64`.
  #[must_use]
  pub fn first_i64(&self) -> Option<i64> {
    match &self.raw {
      RawValue::I64(v) => v.first().copied(),
      RawValue::U64(v) => v.first().and_then(|&n| i64::try_from(n).ok()),
      _ => None,
    }
  }

  /// The post-`ReadValue` `$val` as a SINGLE all-digit count key — the faithful,
  /// FORMAT-AGNOSTIC port of ExifTool's `$count =~ /^\d+$/` test applied to the
  /// prescan-captured `$val` (`ProcessNikonEncrypted`, `Nikon.pm:13948`; the
  /// `$val` is `PrescanExif`'s `ReadValue` result, `Nikon.pm:14122`).
  ///
  /// `/^\d+$/` matches the WHOLE rendered scalar against one-or-more ASCII
  /// digits, so it is independent of the TIFF storage format: an `int32u 100`
  /// renders `"100"` (matches), an ASCII `"100"` (`string`/`undef` `0x00a7`)
  /// also renders `"100"` (matches), while a multi-element value renders
  /// space-joined (`int32u[2]` ⇒ `"100 0"`, the space fails), a negative
  /// renders with a leading `-` (fails), and a non-digit string fails. The
  /// rendering is [`RawValue::val_bytes`] — ExifTool's exact `$val` bytes for
  /// every shape. Used for the `ShutterCount` (0x00a7) count key, so a malformed
  /// `int32u[2]`/`int32s` 0x00a7 must NOT unlock decryption, while an integer OR
  /// ASCII-digit 0x00a7 does.
  ///
  /// The returned value is the count's LOW 32 BITS: ExifTool keeps the count as a
  /// numeric scalar and the cipher consumes only its four low bytes
  /// (`$key ^= ($count >> $i*8) & 0xff foreach 0..3`, `Nikon.pm:13620-13621`), so
  /// an all-digit string exceeding `u32` — which ExifTool still accepts via
  /// `/^\d+$/` and decrypts — is KEYED (not REJECTED for not fitting `u32`). The
  /// coercion uses the shared 64-bit-saturating [`super::decrypt::digit_key_u64`],
  /// faithfully modeling Perl's 64-bit numeric model: exact across the whole
  /// `u64` range, saturating beyond it (a `> u64` decimal is a crafted value Perl
  /// itself resolves via platform-defined NV→UV — no portable oracle).
  #[must_use]
  pub fn single_digit_count(&self) -> Option<u32> {
    let rendered = self.raw.val_bytes();
    // `/^\d+$/`: non-empty AND every byte an ASCII digit (no sign, space, NUL,
    // or non-digit). A space-joined multi-element render fails here.
    if rendered.is_empty() || !rendered.iter().all(u8::is_ascii_digit) {
      return None;
    }
    // The cipher's four-byte XOR fold consumes the count's low 32 bits; coerce via
    // the shared 64-bit-saturating helper and keep the low 32 bits.
    Some(super::decrypt::digit_key_u64(&rendered) as u32)
  }

  /// The first two unsigned integers (for `int16u[2]` ISO/ISOSetting).
  #[must_use]
  pub fn first_two_u64(&self) -> Option<(u64, u64)> {
    match &self.raw {
      RawValue::U64(v) if let [a, b, ..] = v.as_slice() => Some((*a, *b)),
      RawValue::I64(v) if let [a, b, ..] = v.as_slice() => {
        let a = u64::try_from(*a).ok()?;
        let b = u64::try_from(*b).ok()?;
        Some((a, b))
      }
      _ => None,
    }
  }

  /// The display string of a `Text` value, or `None` for a non-text shape.
  #[must_use]
  pub fn as_text(&self) -> Option<&str> {
    match &self.raw {
      RawValue::Text { text, .. } => Some(text.as_str()),
      _ => None,
    }
  }

  /// The bytes of an `undef`/`string` value — for the `MakerNoteVersion`
  /// ValueConv (`unpack("CCCC", $val)`), which inspects the raw on-disk
  /// bytes. `Bytes` → verbatim; `Text` → the pre-FixUTF8 NUL-trimmed bytes.
  #[must_use]
  pub fn undef_or_text_bytes(&self) -> Vec<u8> {
    match &self.raw {
      RawValue::Bytes(b) => b.clone(),
      RawValue::Text { raw, .. } => raw.to_vec(),
      _ => Vec::new(),
    }
  }

  /// The integer-array `$val` rendered as the space-joined decimal string
  /// `ReadValue` produces (`join(' ', @vals)`, `ExifTool.pm:6319`) — for the
  /// multi-`int16u` tags (`CropHiSpeed`/`RetouchHistory`/`NEFBitDepth`) whose
  /// ValueConv/PrintConv operate on the whole space-joined record. Returns
  /// `None` for a non-integer shape.
  #[must_use]
  pub fn int_list_val_string(&self) -> Option<std::string::String> {
    let mut s = std::string::String::new();
    match &self.raw {
      RawValue::U64(v) => {
        for (i, n) in v.iter().enumerate() {
          if i > 0 {
            s.push(' ');
          }
          s.push_str(&n.to_string());
        }
      }
      RawValue::I64(v) => {
        for (i, n) in v.iter().enumerate() {
          if i > 0 {
            s.push(' ');
          }
          s.push_str(&n.to_string());
        }
      }
      _ => return None,
    }
    Some(s)
  }

  /// The shared Nikon `c3` signed-fraction ValueConv
  /// (`my ($a,$b,$c)=unpack("c3",$val); $c ? $a*($b/$c) : 0`,
  /// `Nikon.pm:1846` etc.). The value is a 4-byte `undef`; the first three
  /// bytes are SIGNED (`c` = int8s).
  #[must_use]
  pub fn signed_fraction_c3(&self) -> Option<f64> {
    let bytes = self.undef_or_text_bytes();
    let a = *bytes.first()? as i8 as f64;
    let b = *bytes.get(1)? as i8 as f64;
    let c = *bytes.get(2)? as i8 as f64;
    if c != 0.0 {
      Some(a * (b / c))
    } else {
      Some(0.0)
    }
  }

  /// A `rational64u`/`rational64s` array joined as space-separated DECIMAL
  /// scalars (`ReadValue`'s `join(' ', @vals)` with `Rational::exiftool_val_str`)
  /// — the `$val` `Exif::PrintLensInfo` splits on. `None` for a non-rational.
  #[must_use]
  pub fn rational_join_decimal(&self) -> Option<std::string::String> {
    let RawValue::Rational(rs) = &self.raw else {
      return None;
    };
    let mut s = std::string::String::new();
    for (i, r) in rs.iter().enumerate() {
      if i > 0 {
        s.push(' ');
      }
      s.push_str(&r.exiftool_val_str());
    }
    Some(s)
  }

  /// Convert to the default [`TagValue`] (no PrintConv) via the shared
  /// faithful `ReadValue` renderer (integers → `I64`/`U64`, floats → `F64`,
  /// rationals → joined decimals, text → `Str`, bytes → `Bytes`).
  #[must_use]
  pub fn to_default_tag_value(&self) -> TagValue {
    crate::exif::render::render_value(&self.raw, crate::emit::ConvMode::PrintConv)
  }
}

/// Faithful port of the Nikon `PrescanExif` decryption-key pre-scan
/// (`Nikon.pm:14067-14125`, invoked at `:14199-14203`): a SEPARATE pass over the
/// raw MakerNote IFD that captures ONLY the `SerialNumber` (0x001d) and
/// `ShutterCount` (0x00a7) DataMembers used to key the encrypted sub-tables,
/// BEFORE — and INDEPENDENT of — the main MakerNote extraction (the shared
/// `Walker`, `crate::exif::nikon_makernote_isolated`).
///
/// ## Why a separate scan and not the walked entries
///
/// ExifTool runs `PrescanExif` with DIFFERENT, simpler entry gates than the main
/// `ProcessExif` walk: a `needTags` filter (only 0x001d / 0x00a7,
/// `Nikon.pm:14102`), a `format 1..=13` check (`:14104` — note this DROPS code
/// 129, which the main walk accepts), a 16 MB out-of-line size cap (`:14110`),
/// and an in-bounds check (`:14115`). It has NO suspicious-offset gate, NO
/// excessive-count (`> 100000`) skip, NO invalid-size (`> 0x7fffffff`) gate, and
/// NO `warnCount > 10` directory abort. So a 0x001d / 0x00a7 that the main walk
/// would DROP — at a suspicious offset, with an over-100000 count, or sitting
/// after ten earlier malformed entries tripped the abort — is STILL captured
/// here for the key, exactly as ExifTool. Sourcing the keys from the walked
/// entries (which have already passed the stricter gates) would suppress
/// decryption on those crafted layouts where ExifTool still decrypts.
///
/// Offsets resolve EXACTLY as the walk (inline at `entry + 8` for size ≤ 4, else
/// `offset + value_base`), so the captured value bytes are identical for any
/// well-formed file — the 0x001d / 0x00a7 of every real Nikon body passes both
/// scans, keeping decryption byte-identical. Returns the decoded 0x001d / 0x00a7
/// `ReadValue` results (`None` when absent, unreadable, or gated out); the caller
/// derives the serial/count keys ([`super::scan_decrypt_keys`]). Duplicate tags
/// keep the LAST occurrence (`$$tagHash{$tagID} = …` overwrites).
#[must_use]
pub fn prescan_decrypt_keys(
  blob: &[u8],
  ifd_offset: usize,
  order: ByteOrder,
  value_base: usize,
) -> (Option<RawValue>, Option<RawValue>) {
  let mut serial = None;
  let mut count = None;
  // numEntries (`Nikon.pm:14079-14082`): the 2-byte count plus the full 12-byte
  // entry table must fit the buffer; ExifTool otherwise falls back to the RAF,
  // and with no RAF (the in-memory MakerNote) captures nothing.
  let Some(num_entries) = read_u16(blob, ifd_offset, order) else {
    return (serial, count);
  };
  let num_entries = num_entries as usize;
  let Some(table_end) = ifd_offset.checked_add(2).and_then(|n| {
    12usize
      .checked_mul(num_entries)
      .and_then(|m| n.checked_add(m))
  }) else {
    return (serial, count);
  };
  if table_end > blob.len() {
    return (serial, count);
  }
  for index in 0..num_entries {
    // `$entry = $dirStart + 2 + 12 * $index` (`Nikon.pm:14094`): the entry byte
    // offset. Bounded `< table_end <= blob.len()` (framing-checked above), so this
    // never overflows on 64-bit; the explicit `checked_*` chain (deny-overflow
    // class) `break`s on the unreachable overflow, mirroring `walk_nikon_ifd`.
    let Some(entry_off) = index
      .checked_mul(12)
      .and_then(|o| o.checked_add(2))
      .and_then(|o| ifd_offset.checked_add(o))
    else {
      break;
    };
    let Some(tag_id) = read_u16(blob, entry_off, order) else {
      continue;
    };
    // `next unless exists $$tagHash{$tagID}` (`:14102`) — only the two needTags.
    let slot = match tag_id {
      0x001d => &mut serial,
      0x00a7 => &mut count,
      _ => continue,
    };
    let Some(fmt_pos) = entry_off.checked_add(2) else {
      continue;
    };
    let Some(format_code) = read_u16(blob, fmt_pos, order) else {
      continue;
    };
    // `next if $format < 1 or $format > 13` (`:14104`) — drops code 129, which
    // the main walk accepts; the prescan is format 1..=13 only.
    if !(1..=13).contains(&format_code) {
      continue;
    }
    let format = Format::from_code(format_code);
    let Some(count_pos) = entry_off.checked_add(4) else {
      continue;
    };
    let Some(count_n) = read_u32(blob, count_pos, order) else {
      continue;
    };
    let count_n = count_n as usize;
    let size = format.byte_size().saturating_mul(count_n);
    let value_off = if size <= 4 {
      // inline value (`$valuePtr = $entry + 8`)
      let Some(inline) = entry_off.checked_add(8) else {
        continue;
      };
      inline
    } else {
      if size > 0x0100_0000 {
        continue; // `next if $size > 0x1000000` — the 16 MB cap (`:14110`).
      }
      let Some(value_field) = entry_off.checked_add(8) else {
        continue;
      };
      let Some(off) = read_u32(blob, value_field, order) else {
        continue;
      };
      let Some(abs) = (off as usize).checked_add(value_base) else {
        continue;
      };
      // `next … if $valuePtr+$size > $dataLen` with no RAF (`:14115`) — the same
      // in-bounds rule the walk applies (`value_end > blob.len()`).
      match abs.checked_add(size) {
        Some(end) if end <= blob.len() => abs,
        _ => continue,
      }
    };
    // `ReadValue($dataPt, $valuePtr, $formatStr, $count, $size)` (`:14122`).
    if let Some(raw) = read_value(blob, value_off, format, count_n, size, order) {
      *slot = Some(raw);
    }
  }
  (serial, count)
}

/// Resolve the embedded-TIFF header for the type-3 layout. `blob` is the whole
/// MakerNote blob; the embedded TIFF starts at `tiff_at` (blob offset 10 for
/// the modern layout). Returns `(byte_order, ifd_offset_in_blob)`.
///
/// ## The IFD start is FIXED at `tiff_at + 8`, NOT the embedded IFD0-offset field
///
/// `MakerNotes.pm:51-57` gives the type-3 SubDirectory as `Start =>
/// '$valuePtr + 18'`, `Base => '$start - 8'`, `ByteOrder => 'Unknown'`.
/// With the embedded TIFF at blob offset 10 (`valuePtr + 10`), `$valuePtr + 18`
/// is `tiff_at + 8` — a FIXED offset. ExifTool reads the embedded `MM`/`II`
/// marker to resolve endianness (that is the entire effect of `ByteOrder =>
/// 'Unknown'`), but it does NOT consult the embedded TIFF header's 4-byte IFD0
/// offset field to locate the Main IFD: the IFD is ALWAYS walked at the fixed
/// `$valuePtr + 18`. Every real Nikon fixture happens to store `8` in that
/// field (so `tiff_at + field == tiff_at + 8`), but a crafted blob whose field
/// is some other in-bounds value must STILL be walked at `tiff_at + 8` — the
/// field is ignored. (`Base => '$start - 8'` = `tiff_at` sets the out-of-line
/// value base, which the caller passes as `value_base = 10`.)
///
/// `None` only when the marker is unreadable (no `MM`/`II`) or the fixed IFD
/// start (plus its 2-byte entry count) does not fit the blob.
#[must_use]
pub fn parse_embedded_tiff(blob: &[u8], tiff_at: usize) -> Option<(ByteOrder, usize)> {
  let header = blob.get(tiff_at..)?;
  // Bytes 0-1 are the `MM`/`II` byte-order marker — the only thing ExifTool
  // reads from the embedded header (`ByteOrder => 'Unknown'`). Bytes 2-3 are
  // the `0x002a` magic and bytes 4-7 the embedded IFD0 offset, both of which
  // ExifTool IGNORES for the type-3 layout (the IFD start is fixed below).
  let order = ByteOrder::from_marker(header)?;
  // The Main IFD always begins at the FIXED `$valuePtr + 18 == tiff_at + 8`
  // (`MakerNotes.pm:54`), regardless of the embedded IFD0-offset field.
  let ifd_offset = tiff_at.checked_add(8)?;
  // Bounds-check the fixed IFD start: its 2-byte entry count must fit the blob
  // (the walker re-checks the full entry table). A blob too short for even the
  // entry count has no Main IFD — return `None` (no panic / OOB).
  if ifd_offset.checked_add(2)? > blob.len() {
    return None;
  }
  Some((order, ifd_offset))
}

fn read_u16(data: &[u8], pos: usize, order: ByteOrder) -> Option<u16> {
  // `pos + 2` via `checked_add` (deny-overflow class) — byte-identical to
  // `ifd::get_u16`'s bounds check: an out-of-range `pos` yields `None`, exactly
  // as the slice `get` does for an in-range `pos`.
  let end = pos.checked_add(2)?;
  let arr: [u8; 2] = data.get(pos..end)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u16::from_le_bytes(arr),
    ByteOrder::Big => u16::from_be_bytes(arr),
  })
}

fn read_u32(data: &[u8], pos: usize, order: ByteOrder) -> Option<u32> {
  // `pos + 4` via `checked_add` (deny-overflow class) — byte-identical to
  // `ifd::get_u32`'s bounds check (see [`read_u16`]).
  let end = pos.checked_add(4)?;
  let arr: [u8; 4] = data.get(pos..end)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u32::from_le_bytes(arr),
    ByteOrder::Big => u32::from_be_bytes(arr),
  })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  /// Build a minimal type-3 Nikon blob: `"Nikon\0\x02\x10\0\0"` + an embedded
  /// big-endian TIFF (`MM\0\x2a` + IFD0-offset 8) with one IFD entry.
  fn type3_blob_one_entry(tag: u16, format: u16, count: u32, value: [u8; 4]) -> Vec<u8> {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"Nikon\x00\x02\x10\x00\x00"); // 10-byte header
    // Embedded TIFF at offset 10.
    b.extend_from_slice(b"MM"); // big-endian
    b.extend_from_slice(&[0x00, 0x2a]); // magic 0x002a
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x08]); // IFD0 at embedded-offset 8
    // IFD0 is at blob offset 10 + 8 = 18 = right here (entry count).
    b.extend_from_slice(&[0x00, 0x01]); // 1 entry
    b.extend_from_slice(&tag.to_be_bytes());
    b.extend_from_slice(&format.to_be_bytes());
    b.extend_from_slice(&count.to_be_bytes());
    b.extend_from_slice(&value);
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD = 0
    b
  }

  /// The embedded-TIFF header parser resolves the order + IFD offset.
  #[test]
  fn parse_embedded_tiff_resolves_big_endian() {
    let blob = type3_blob_one_entry(0x0004, 0x0002, 4, *b"FINE");
    let (order, ifd_off) = parse_embedded_tiff(&blob, 10).expect("embedded TIFF");
    assert!(order.is_big());
    assert_eq!(ifd_off, 18); // 10 + 8
  }

  /// The embedded IFD0-offset field is IGNORED: the Main IFD is ALWAYS resolved
  /// at the FIXED `tiff_at + 8` (`$valuePtr + 18`, `MakerNotes.pm:54`), NOT at
  /// `tiff_at + field`. A non-8 in-bounds field that points at a DIFFERENT
  /// valid-looking IFD must NOT move the walk — `parse_embedded_tiff` still
  /// returns `tiff_at + 8`, so only that IFD is read and the decoy IFD the
  /// field points to is never reached. (`ByteOrder => 'Unknown'` means ONLY
  /// the `MM`/`II` marker is read from the embedded header; the offset field is
  /// not consulted.)
  #[test]
  fn type3_embedded_ifd0_offset_field_is_ignored_fixed_start() {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"Nikon\x00\x02\x10\x00\x00"); // 10-byte header
    b.extend_from_slice(b"MM"); // big-endian embedded TIFF
    b.extend_from_slice(&[0x00, 0x2a]); // magic 0x002a
    // Embedded IFD0-offset field = 64 (NOT 8) — a value that, if (wrongly)
    // followed, would walk the Main IFD at tiff_at(10) + 64 = blob 74.
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x40]);
    // Pad out so a 64-byte-offset target would be in bounds (proving rejection
    // is by the FIXED-start contract, not by the field running out of bounds).
    while b.len() < 100 {
      b.push(0);
    }
    let (order, ifd_off) = parse_embedded_tiff(&b, 10).expect("embedded TIFF");
    assert!(order.is_big(), "byte order read from the MM marker");
    assert_eq!(
      ifd_off, 18,
      "IFD start is the FIXED tiff_at + 8 (=18), ignoring the embedded field (64)"
    );

    // A blob too short to even hold the 2-byte entry count at the fixed start
    // is rejected (`None`) — no panic, no OOB.
    let short = b"Nikon\x00\x02\x10\x00\x00MM\x00\x2a\x00\x00\x00\x40"; // 18 bytes, IFD start = 18 == len
    assert!(
      parse_embedded_tiff(short, 10).is_none(),
      "a blob too short for the entry count at the fixed IFD start yields None"
    );
  }

  /// The `signed_fraction_c3` ValueConv: `a*(b/c)` over the first 3 SIGNED
  /// bytes; `c == 0` → 0.
  #[test]
  fn signed_fraction_c3_value_conv() {
    // (-3, 1, 6) → -3*(1/6) = -0.5.
    let v = ParsedValue::new(RawValue::Bytes(vec![0xfd, 0x01, 0x06, 0x00]));
    assert!((v.signed_fraction_c3().unwrap() - (-0.5)).abs() < 1e-9);
    // c == 0 → 0.
    let v0 = ParsedValue::new(RawValue::Bytes(vec![0x05, 0x01, 0x00, 0x00]));
    assert_eq!(v0.signed_fraction_c3(), Some(0.0));
  }

  /// `single_digit_count` keys the count's LOW 32 BITS via the shared
  /// 64-bit-saturating coercion (the cipher's four-byte XOR fold), so an all-digit
  /// `ShutterCount` EXCEEDING `u32` — which ExifTool still accepts via `/^\d+$/`
  /// and decrypts — is keyed, NOT rejected for not fitting `u32`. Exact across the
  /// whole `u64` range; a `> u64` decimal saturates (Perl's NV→UV is platform
  /// UB — no portable oracle). (R9/R10 finding: the prior `parse::<u32>()`
  /// suppressed decryption, then an arbitrary-precision fold diverged from Perl's
  /// 64-bit model above `u64`.)
  #[test]
  fn single_digit_count_keys_low_32_bits() {
    let c = |s: &[u8]| ParsedValue::new(RawValue::Bytes(s.to_vec())).single_digit_count();
    assert_eq!(c(b"100"), Some(100)); // in range
    assert_eq!(c(b"4294967296"), Some(0)); // 2^32 ⇒ low 32 bits 0 (was rejected)
    assert_eq!(c(b"4294967297"), Some(1)); // 2^32 + 1 ⇒ low 32 bits 1
    // u64 boundary: u64::MAX = 0xffff_ffff_ffff_ffff ⇒ low 32 bits 0xffff_ffff;
    // u64::MAX + 1 / + 2 SATURATE to u64::MAX ⇒ same low 32 bits (Perl 64-bit
    // model; the cipher's XOR fold of 0xffff_ffff is key 0, matching 64-bit Perl).
    assert_eq!(c(b"18446744073709551615"), Some(0xffff_ffff)); // u64::MAX
    assert_eq!(c(b"18446744073709551616"), Some(0xffff_ffff)); // u64::MAX + 1
    assert_eq!(c(b"18446744073709551617"), Some(0xffff_ffff)); // u64::MAX + 2
    assert_eq!(c(b"100 0"), None); // space-joined multi-element render fails
    assert_eq!(c(b"-5"), None); // a sign fails
    assert_eq!(c(b""), None); // empty fails
  }

  /// `prescan_decrypt_keys` (ExifTool's `PrescanExif`) captures the decryption
  /// key with LOOSER gates than the main walk: it has NO `warnCount > 10` abort,
  /// so a trailing `ShutterCount` (0x00a7) the walk never reaches — because 11
  /// earlier bad-offset entries tripped the abort — is STILL keyed, exactly as
  /// ExifTool. (R9 finding: sourcing keys from the post-walk entries suppressed
  /// decryption on such crafted layouts.)
  #[test]
  fn prescan_captures_key_past_walk_warn_abort() {
    // 11 out-of-line entries whose value runs past EOF (each `++warnCount`).
    let mut entries: Vec<Vec<u8>> = (0..11u16)
      .map(|i| entry_offset(0x9000 + i, 2, 8, 0xffff)) // ascii[8] past EOF
      .collect();
    // A trailing ShutterCount (int32u 100, inline) after the 11 bad entries.
    // The main walk would ABORT (warnCount > 10) before reaching 0x00a7, but the
    // prescan has no abort, so it still captures the ShutterCount key (100).
    entries.push(entry_inline(0x00a7, 4, 1, [0x00, 0x00, 0x00, 0x64])); // big-endian 100
    let b = headerless_ifd(&entries);
    let (_serial, count) = prescan_decrypt_keys(&b, 0, ByteOrder::Big, 0);
    let count = count.expect("PrescanExif captures the count key past the walk abort");
    assert_eq!(ParsedValue::new(count).single_digit_count(), Some(100));
  }

  /// `prescan_decrypt_keys` captures ONLY the two needTags (0x001d / 0x00a7) and
  /// reads them format-agnostically, matching `PrescanExif`'s `needTags` filter +
  /// `ReadValue`. An unrelated tag is ignored; a present SerialNumber + a present
  /// ShutterCount are both returned.
  #[test]
  fn prescan_captures_only_needtags() {
    let serial = entry_inline(0x001d, 2, 4, [b'9', b'9', b'9', 0]); // ascii "999"
    let other = entry_inline(0x0005, 4, 1, [0x00, 0x00, 0x00, 0x07]); // ignored
    let shutter = entry_inline(0x00a7, 4, 1, [0x00, 0x00, 0x00, 0x2a]); // int32u 42
    let b = headerless_ifd(&[serial, other, shutter]);
    let (serial_val, count_val) = prescan_decrypt_keys(&b, 0, ByteOrder::Big, 0);
    let s = serial_val.expect("0x001d captured");
    assert_eq!(std::string::String::from_utf8_lossy(&s.val_bytes()), "999");
    let count = count_val.expect("0x00a7 captured");
    assert_eq!(ParsedValue::new(count).single_digit_count(), Some(42));
  }

  /// A 12-byte IFD entry with an inline 4-byte value (helper for the
  /// bad-format tests).
  fn entry_inline(tag: u16, format: u16, count: u32, value: [u8; 4]) -> Vec<u8> {
    let mut e: Vec<u8> = Vec::new();
    e.extend_from_slice(&tag.to_be_bytes());
    e.extend_from_slice(&format.to_be_bytes());
    e.extend_from_slice(&count.to_be_bytes());
    e.extend_from_slice(&value);
    e
  }

  /// A headerless big-endian Nikon IFD: `numEntries` + the 12-byte entries +
  /// a `0` next-IFD pointer.
  fn headerless_ifd(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    for e in entries {
      b.extend_from_slice(e);
    }
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD = 0
    b
  }

  /// A 12-byte IFD entry with an OUT-OF-LINE value (a 4-byte stored offset) —
  /// helper for the suspicious-offset / warnCount tests.
  fn entry_offset(tag: u16, format: u16, count: u32, offset: u32) -> Vec<u8> {
    let mut e: Vec<u8> = Vec::new();
    e.extend_from_slice(&tag.to_be_bytes());
    e.extend_from_slice(&format.to_be_bytes());
    e.extend_from_slice(&count.to_be_bytes());
    e.extend_from_slice(&offset.to_be_bytes());
    e
  }
}
