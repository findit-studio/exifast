// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Apple iOS MakerNote IFD body walker — Phase-2 port.
//!
//! After the dispatcher captures the raw blob and strips the 14-byte
//! `Apple iOS\0\0\x01MM` header (the `Start => '$valuePtr + 14'`
//! directive at `MakerNotes.pm:42`), this module walks the body as a
//! standard TIFF IFD.
//!
//! The body itself starts with another byte-order marker — `MM` for
//! big-endian (every Apple iPhone we've seen so far) — and the IFD entry
//! count immediately follows that marker (NOT a TIFF header — no
//! `0x002a` magic + IFD0 offset). The MakerNote `Base` directive
//! `'$start - 14'` (`MakerNotes.pm:43`) tells the walker that
//! out-of-line value offsets are RELATIVE to the start of the BLOB
//! (i.e. `body_offset - 14` from the body), so we resolve every
//! out-of-line offset against the BLOB (not just the body).

#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::{ByteOrder, Format, RawValue, read_value};
use crate::exif::makernotes::detected::ChildByteOrder;
use crate::value::TagValue;

/// One decoded Apple MakerNote IFD entry — the raw value plus the
/// post-PrintConv `TagValue` so the MakerNote struct can store both the
/// raw shape and the rendered string.
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

  /// Borrow the underlying raw value (the post-Format-decode `$val`).
  #[must_use]
  #[inline(always)]
  pub const fn raw(&self) -> &RawValue {
    &self.raw
  }

  /// The first scalar integer (signed) — works for `U64`/`I64`.
  #[must_use]
  pub fn first_i64(&self) -> Option<i64> {
    match &self.raw {
      RawValue::I64(v) => v.first().copied(),
      RawValue::U64(v) => v.first().and_then(|&n| i64::try_from(n).ok()),
      _ => None,
    }
  }

  /// The first two scalar integers (for `AFPerformance` which is
  /// `int32s[2]`).
  #[must_use]
  pub fn first_two_i64(&self) -> Option<(i64, i64)> {
    // `[a, b, ..]` matches len ≥ 2 and binds the first two — byte-identical to
    // the `if v.len() >= 2 => (v[0], v[1])` index pair, without raw indexing.
    match &self.raw {
      RawValue::I64(v) if let [a, b, ..] = v.as_slice() => Some((*a, *b)),
      RawValue::U64(v) if let [a, b, ..] = v.as_slice() => {
        let a = i64::try_from(*a).ok()?;
        let b = i64::try_from(*b).ok()?;
        Some((a, b))
      }
      _ => None,
    }
  }

  /// The first two rational64 values as f64 — for `FocusDistanceRange`.
  #[must_use]
  pub fn rational_pair(&self) -> Option<(f64, f64)> {
    // `[r0, r1, ..]` matches len ≥ 2 and binds the first two — byte-identical to
    // the `rs.len() >= 2` guard + `rs[0]`/`rs[1]`, without raw indexing.
    match &self.raw {
      RawValue::Rational(rs) if let [r0, r1, ..] = rs.as_slice() => {
        let a = ratio_f64(r0.numerator(), r0.denominator())?;
        let b = ratio_f64(r1.numerator(), r1.denominator())?;
        Some((a, b))
      }
      _ => None,
    }
  }

  /// Convert this raw value to a default [`TagValue`] (no PrintConv —
  /// used by [`ApplePrintConv::None`](super::printconv::ApplePrintConv) and
  /// the PLIST-deferred branches).
  ///
  /// Delegates to the shared [`render_value`](crate::exif::render::render_value)
  /// — the single faithful `ReadValue` renderer (`ExifTool.pm:6275-6321`)
  /// the EXIF emitters and this Apple default path now both use: integers →
  /// `I64`/`U64`, floats → `F64`, a single rational → `Rational` (its
  /// serializer renders the rounded decimal), a multi-rational →
  /// space-joined DECIMAL scalars (`Rational::exiftool_val_str`, NOT `n/d`
  /// fractions — e.g. AccelerationVector, `Apple.pm:62`), text → `Str`,
  /// bytes → `Bytes`. The no-conv default is mode-agnostic, so the active
  /// [`ConvMode`](crate::emit::ConvMode) is irrelevant here.
  #[must_use]
  pub fn to_default_tag_value(&self) -> TagValue {
    crate::exif::render::render_value(&self.raw, crate::emit::ConvMode::PrintConv)
  }
}

fn ratio_f64(n: i64, d: i64) -> Option<f64> {
  if d == 0 {
    return None;
  }
  Some(n as f64 / d as f64)
}

/// One IFD entry parsed from the Apple body — `(tag_id, value)`.
#[derive(Debug, Clone)]
pub struct AppleEntry {
  /// Apple tag ID (`Apple.pm:24-320` hash key).
  pub tag_id: u16,
  /// The decoded raw value.
  pub value: ParsedValue,
}

/// Walk the Apple MakerNote body and emit one [`AppleEntry`] per IFD
/// entry. The body starts with a 2-byte `II`/`MM` marker followed by
/// the 2-byte IFD entry count; the rest is a standard TIFF IFD.
///
/// `blob` is the WHOLE MakerNote blob (the raw bytes captured at
/// 0x927C). `body_offset` is the dispatcher's `Start => '$valuePtr +
/// 14'` directive (so `body = &blob[14..]`).
///
/// Out-of-line value offsets are RELATIVE to the start of the BLOB
/// (`Base => '$start - 14'` ⇒ rebased so `value_offset` indexes the
/// blob slice starting at the body offset — `MakerNotes.pm:43`).
///
/// Returns the entries in IFD walk order; malformed entries are silently
/// skipped (faithful to ExifTool's `Warn` + `next` on a malformed entry).
#[must_use]
pub fn walk_apple_body(
  blob: &[u8],
  body_offset: usize,
  parent_order: ByteOrder,
) -> Vec<AppleEntry> {
  let mut out = Vec::new();
  if body_offset >= blob.len() {
    return out;
  }
  // The guard above ⇒ `body_offset < blob.len()`, so `.get(body_offset..)` is
  // `Some`; the checked slice is byte-identical to `&blob[body_offset..]`.
  let Some(body) = blob.get(body_offset..) else {
    return out;
  };
  // Resolve byte order. `MakerNotes.pm:44` is `ByteOrder => 'Unknown'`,
  // so the body marker (II/MM at offset 0-1) decides; fall back to the
  // parent walk's order if the body has no marker (degenerate — every
  // real-iPhone fixture starts with `MM`).
  let (order, header_size) = match ByteOrder::from_marker(body) {
    Some(o) => (o, 2),
    None => (parent_order, 0),
  };
  // Entry count starts at `header_size` (right after the marker if
  // present, otherwise at the start of the body). For Apple's
  // `MM\0\x0e...` shape this is offset 2; the bytes 0..1 are `MM` and
  // 2..3 are the count (BE).
  let count_offset = header_size;
  let Some(num_entries) = read_u16(body, count_offset, order) else {
    return out;
  };
  let num_entries = num_entries as usize;
  let entries_start = count_offset + 2;
  // Bounds-check: the directory body must fit in `body`.
  let dir_end = entries_start.saturating_add(12usize.saturating_mul(num_entries));
  if dir_end > body.len() {
    // Truncated IFD; emit nothing (matches ExifTool's `Bad … directory` abort).
    return out;
  }
  // Walk each 12-byte entry.
  for i in 0..num_entries {
    let entry_off = entries_start + 12 * i;
    let Some(tag_id) = read_u16(body, entry_off, order) else {
      continue;
    };
    let Some(format_code) = read_u16(body, entry_off + 2, order) else {
      continue;
    };
    let Some(count) = read_u32(body, entry_off + 4, order) else {
      continue;
    };
    let count = count as usize;
    let format = Format::from_code(format_code);
    let elem_size = format.byte_size();
    if elem_size == 0 {
      continue; // Unknown format; skip (ExifTool warns + continues).
    }
    let total_size = elem_size.saturating_mul(count);
    // Value is inline if it fits in 4 bytes; otherwise it's an offset.
    let value_data_offset = if total_size <= 4 {
      entry_off + 8
    } else {
      let Some(off) = read_u32(body, entry_off + 8, order) else {
        continue;
      };
      // The `Base => '$start - 14'` rebase: an out-of-line offset is
      // counted from the start of the BLOB (the captured 0x927C value).
      // `$start` in MakerNotes.pm is the MakerNote body's value-pointer
      // in the parent's data buffer; the body offset (14) is added
      // back here so the offset indexes the SAME body slice we are
      // walking.
      let blob_off = off as usize;
      if blob_off >= blob.len() {
        continue;
      }
      // `blob_off` is the position in the WHOLE blob; subtract
      // `body_offset` to translate to the `body` slice we're working
      // with.
      if blob_off < body_offset {
        continue; // out-of-range — skip.
      }
      let body_off = blob_off - body_offset;
      if body_off.saturating_add(total_size) > body.len() {
        continue;
      }
      body_off
    };
    // Decode.
    if value_data_offset >= body.len() {
      continue;
    }
    let avail = body.len() - value_data_offset;
    let Some(raw) = read_value(body, value_data_offset, format, count, avail, order) else {
      continue;
    };
    out.push(AppleEntry {
      tag_id,
      value: ParsedValue::new(raw),
    });
  }
  let _ = ChildByteOrder::Unknown; // keep import used; safe no-op.
  out
}

fn read_u16(data: &[u8], pos: usize, order: ByteOrder) -> Option<u16> {
  // The `.get(pos..pos+2)?` slice has length 2, so `try_into::<[u8;2]>` always
  // succeeds; this is byte-identical to `[b[0], b[1]]` without raw indexing.
  let arr: [u8; 2] = data.get(pos..pos + 2)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u16::from_le_bytes(arr),
    ByteOrder::Big => u16::from_be_bytes(arr),
  })
}

fn read_u32(data: &[u8], pos: usize, order: ByteOrder) -> Option<u32> {
  // The `.get(pos..pos+4)?` slice has length 4, so `try_into::<[u8;4]>` always
  // succeeds; this is byte-identical to `[b[0]..b[3]]` without raw indexing.
  let arr: [u8; 4] = data.get(pos..pos + 4)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u32::from_le_bytes(arr),
    ByteOrder::Big => u32::from_be_bytes(arr),
  })
}

use std::vec::Vec;

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C S2); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  /// Synthetic Apple MakerNote — `Apple iOS\0\0\x01MM` header + 1 IFD
  /// entry for `MakerNoteVersion` (tag 0x0001, int32s, count 1, inline
  /// value = 4).
  #[test]
  fn synthetic_apple_body_emits_makernoteversion() {
    let mut blob: Vec<u8> = Vec::new();
    // 14-byte Apple header.
    blob.extend_from_slice(b"Apple iOS\x00\x00\x01MM");
    // Body: `MM` marker + 1 entry.
    blob.extend_from_slice(b"MM");
    blob.extend_from_slice(&[0x00, 0x01]); // num_entries=1
    // Entry: tag 0x0001, format 0x0009 (int32s), count 1, value 4.
    blob.extend_from_slice(&[0x00, 0x01]); // tag
    blob.extend_from_slice(&[0x00, 0x09]); // int32s
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // count
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // value 4

    let entries = walk_apple_body(&blob, 14, ByteOrder::Big);
    assert_eq!(entries.len(), 1, "one IFD entry parsed");
    let e = &entries[0];
    assert_eq!(e.tag_id, 0x0001);
    assert_eq!(e.value.first_i64(), Some(4));
  }

  /// Header is malformed (too short) → no entries.
  #[test]
  fn truncated_body_emits_no_entries() {
    let blob = b"Apple iOS\x00\x00\x01M";
    assert!(walk_apple_body(blob, 14, ByteOrder::Big).is_empty());
  }

  /// Empty body → no entries.
  #[test]
  fn empty_body_emits_no_entries() {
    let blob = b"Apple iOS\x00\x00\x01MM";
    let entries = walk_apple_body(blob, 14, ByteOrder::Big);
    assert!(entries.is_empty());
  }

  /// Three int32s + 1 rational value with an out-of-line offset.
  #[test]
  fn synthetic_body_with_offset_value() {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"Apple iOS\x00\x00\x01MM");
    blob.extend_from_slice(b"MM");
    blob.extend_from_slice(&[0x00, 0x01]); // 1 entry
    // Entry: tag 0x0008 (AccelerationVector), rational64s, count 3.
    blob.extend_from_slice(&[0x00, 0x08]);
    blob.extend_from_slice(&[0x00, 0x0a]); // rational64s = 10
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x03]); // count 3
    // Out-of-line offset: 14 (Apple header) + 2 (MM) + 2 (count) + 12 = 30.
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x1e]); // 30
    // Append 3 rationals (24 bytes total).
    for n in [(-1i32, 100i32), (2i32, 100i32), (-7i32, 10i32)] {
      blob.extend_from_slice(&n.0.to_be_bytes());
      blob.extend_from_slice(&n.1.to_be_bytes());
    }
    let entries = walk_apple_body(&blob, 14, ByteOrder::Big);
    assert_eq!(entries.len(), 1);
    let e = &entries[0];
    assert_eq!(e.tag_id, 0x0008);
    let raw = e.value.raw();
    if let RawValue::Rational(rs) = raw {
      assert_eq!(rs.len(), 3);
      assert_eq!(rs[0].numerator(), -1);
      assert_eq!(rs[1].numerator(), 2);
      assert_eq!(rs[2].numerator(), -7);
    } else {
      panic!("expected Rational, got {raw:?}");
    }

    // FIX 2: a no-PrintConv multi-rational renders as space-joined DECIMAL
    // scalars (`Rational::exiftool_val_str`), NOT `n/d` fractions. ExifTool
    // emits AccelerationVector (rational64s, no PrintConv) this way.
    match e.value.to_default_tag_value() {
      TagValue::Str(s) => {
        assert_eq!(s.as_str(), "-0.01 0.02 -0.7", "decimal, not fractions");
        assert!(!s.as_str().contains('/'), "no n/d fractions: {s}");
      }
      other => panic!("expected joined-decimal Str, got {other:?}"),
    }
  }
}
