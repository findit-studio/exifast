// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! DJI MakerNote IFD body walker — Phase-4 port.
//!
//! DJI's MakerNote (`MakerNoteDJI`, `MakerNotes.pm:99-106`) is identified
//! by `$$self{Make} eq "DJI"` (with a negative lookahead for the
//! Ambarella `...\@AMBA` and bare `DJI` signatures that DJI shares with
//! action-cam relatives). `Start => '$valuePtr'` (no header to strip);
//! `ByteOrder => 'Unknown'` (the byte order falls back to the parent
//! IFD's order since the body has no MM/II marker).
//!
//! Out-of-line value offsets in DJI entries are TIFF-relative (DJI
//! inherits the parent `Base` — there's no `Base =>` override on
//! `MakerNoteDJI`). The Phase-4 walker resolves out-of-line offsets
//! against the parent TIFF block when given parent-TIFF context, or
//! against the blob itself when the caller has only the captured BLOB.

#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::{ByteOrder, Format, RawValue, read_value};
use std::vec::Vec;

/// One decoded DJI MakerNote IFD entry — the tag + format + the
/// post-Format-decode `RawValue`.
#[derive(Debug, Clone)]
pub struct DjiEntry {
  /// Tag ID (`DJI.pm` Main hash key).
  pub tag_id: u16,
  /// On-disk format code.
  pub format: Format,
  /// Element count.
  pub count: usize,
  /// The decoded raw value (post-Format-decode, pre-PrintConv).
  pub value: RawValue,
}

/// Walk the DJI MakerNote body in the parent TIFF context, so
/// out-of-line value offsets resolve against the parent TIFF block.
///
/// `tiff_data` is the parent TIFF block; `mn_offset` is the start of the
/// captured MakerNote within `tiff_data`; `mn_len` is its byte length;
/// `parent_order` is the parent IFD walk's byte order (DJI's body has no
/// MM/II marker so the byte order falls back to the parent).
///
/// DJI inherits the parent `Base` (no `Base =>` override on
/// `MakerNoteDJI`), so out-of-line offsets in entries are TIFF-relative.
#[must_use]
pub fn walk_dji_in_tiff(
  tiff_data: &[u8],
  mn_offset: usize,
  mn_len: usize,
  parent_order: ByteOrder,
) -> Vec<DjiEntry> {
  let mut out = Vec::new();
  if mn_len < 2 {
    return out;
  }
  if mn_offset.saturating_add(2) > tiff_data.len() {
    return out;
  }
  let body_start = mn_offset;
  let order = parent_order;
  let num_entries = read_u16(tiff_data, body_start, order).unwrap_or(0) as usize;
  if num_entries == 0 || num_entries > 1024 {
    return out;
  }
  let entries_start = body_start + 2;
  let dir_end = entries_start.saturating_add(12usize.saturating_mul(num_entries));
  let mn_end = mn_offset + mn_len;
  if dir_end > mn_end.min(tiff_data.len()) {
    return out;
  }
  for i in 0..num_entries {
    let entry_off = entries_start + 12 * i;
    let Some(tag_id) = read_u16(tiff_data, entry_off, order) else {
      continue;
    };
    let Some(format_code) = read_u16(tiff_data, entry_off + 2, order) else {
      continue;
    };
    let Some(count) = read_u32(tiff_data, entry_off + 4, order) else {
      continue;
    };
    let count = count as usize;
    let format = Format::from_code(format_code);
    let elem_size = format.byte_size();
    if elem_size == 0 {
      continue;
    }
    let total_size = elem_size.saturating_mul(count);
    let value_data_offset = if total_size <= 4 {
      entry_off + 8
    } else {
      let Some(off) = read_u32(tiff_data, entry_off + 8, order) else {
        continue;
      };
      let abs_off = off as usize;
      if abs_off >= tiff_data.len() {
        continue;
      }
      if abs_off.saturating_add(total_size) > tiff_data.len() {
        continue;
      }
      abs_off
    };
    let avail = tiff_data.len() - value_data_offset;
    let Some(raw) = read_value(tiff_data, value_data_offset, format, count, avail, order) else {
      continue;
    };
    out.push(DjiEntry {
      tag_id,
      format,
      count,
      value: raw,
    });
  }
  out
}

/// Compatibility wrapper — walk DJI body when only the captured BLOB is
/// available (no parent TIFF context). Out-of-line offsets resolve
/// against the blob itself; only correct when the blob is
/// self-contained (synthetic test fixtures).
#[must_use]
pub fn walk_dji_body(blob: &[u8], parent_order: ByteOrder) -> Vec<DjiEntry> {
  walk_dji_in_tiff(blob, 0, blob.len(), parent_order)
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

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C S2); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  /// Synthetic DJI body — 1 entry — `Pitch` (tag 0x06, float, count 1,
  /// value 12.5), little-endian, headerless.
  #[test]
  fn synthetic_dji_pitch_inline() {
    let mut blob: Vec<u8> = Vec::new();
    // 1 entry LE
    blob.extend_from_slice(&[0x01, 0x00]);
    // Entry: tag 0x06, float (11), count 1, value=12.5 (LE) inline.
    blob.extend_from_slice(&[0x06, 0x00]); // tag 0x06
    blob.extend_from_slice(&[0x0b, 0x00]); // format 11 = float
    blob.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // count 1
    blob.extend_from_slice(&12.5f32.to_le_bytes()); // 12.5 inline
    let entries = walk_dji_body(&blob, ByteOrder::Little);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tag_id, 0x06);
    match &entries[0].value {
      RawValue::F64(v) => assert!((v[0] - 12.5).abs() < 1e-6, "got {:?}", v),
      other => panic!("expected F64, got {other:?}"),
    }
  }

  /// String value (the `Make` tag 0x01).
  #[test]
  fn synthetic_dji_make_string() {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(&[0x01, 0x00]); // 1 entry LE
    blob.extend_from_slice(&[0x01, 0x00]); // tag 0x01 (Make)
    blob.extend_from_slice(&[0x02, 0x00]); // format 2 = string
    blob.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]); // count 4 = "DJI\0"
    blob.extend_from_slice(b"DJI\x00"); // inline (4 bytes)
    let entries = walk_dji_body(&blob, ByteOrder::Little);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tag_id, 0x01);
    match &entries[0].value {
      RawValue::Text(s) => assert_eq!(s.trim_end_matches('\0'), "DJI"),
      other => panic!("expected Text, got {other:?}"),
    }
  }

  #[test]
  fn empty_blob_yields_no_entries() {
    let blob: Vec<u8> = Vec::new();
    assert!(walk_dji_body(&blob, ByteOrder::Little).is_empty());
  }

  #[test]
  fn implausible_count_short_circuits() {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(&[0x0f, 0x27]); // 9999 LE
    assert!(walk_dji_body(&blob, ByteOrder::Little).is_empty());
  }
}
