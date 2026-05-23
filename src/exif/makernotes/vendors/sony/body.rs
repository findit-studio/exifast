// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Sony MakerNote IFD body walker — Phase-3 port.
//!
//! Sony has SEVERAL signature variants (`MakerNotes.pm:1031-1099`):
//!
//! - `MakerNoteSony` — `SONY (DSC|CAM|MOBILE)`/`\0\0SONY PIC\0`/`VHAB     \0`
//!   prefix; body at `$valuePtr + 12`. No `Base` override (inherit parent).
//!   Routes to `Image::ExifTool::Sony::Main`.
//! - `MakerNoteSony5` — headerless body (`Start => '$valuePtr'`); no
//!   `Base` override. Routes to `Image::ExifTool::Sony::Main`.
//! - `MakerNoteSonyEricsson` — `SEMC MS\0` prefix; body at
//!   `$valuePtr + 20`, `Base => '$start - 8'`. Routes to `Sony::Ericsson`
//!   (Phase 3 ports the Sony Main table only — Ericsson decoding is a
//!   deferred long-tail item).
//!
//! Phase 3 walks the BODY for both `MakerNoteSony` and `MakerNoteSony5`
//! by accepting a body-offset argument from the dispatcher. Out-of-line
//! offsets in entries are TIFF-relative (since Sony inherits the parent
//! `Base`); the walker treats the BLOB as self-contained and resolves
//! offsets against the blob — the same convention Canon uses for
//! standalone-blob walks.

use super::tags;
use crate::exif::ifd::{ByteOrder, Format, RawValue, read_value};
use crate::exif::makernotes::vendors::resolve_read_format;
use std::vec::Vec;

/// One decoded Sony MakerNote IFD entry — the tag + format + the
/// post-Format-decode `RawValue`.
#[derive(Debug, Clone)]
pub struct SonyEntry {
  /// Tag ID (`Sony.pm` Main hash key).
  pub tag_id: u16,
  /// On-disk format code.
  pub format: Format,
  /// Element count.
  pub count: usize,
  /// The decoded raw value (post-Format-decode, pre-PrintConv).
  pub value: RawValue,
}

/// Walk the Sony MakerNote body in the parent TIFF context. `tiff_data`
/// is the parent TIFF block; `mn_offset` is the start of the captured
/// MakerNote within `tiff_data`; `mn_len` is its byte length;
/// `body_offset` is the BODY start offset within the captured MakerNote
/// (12 for the `SONY DSC ` prefix variant, 0 for `MakerNoteSony5`).
/// `parent_order` is the parent IFD walk's byte order — Sony's bodies
/// have no MM/II marker so the byte order falls back to the parent
/// (`ChildByteOrder::Unknown` resolves to parent here).
///
/// Out-of-line value offsets in entries are TIFF-relative.
#[must_use]
pub fn walk_sony_in_tiff(
  tiff_data: &[u8],
  mn_offset: usize,
  mn_len: usize,
  body_offset: usize,
  parent_order: ByteOrder,
) -> Vec<SonyEntry> {
  let mut out = Vec::new();
  if mn_offset.saturating_add(body_offset) + 2 > tiff_data.len() || mn_len < body_offset + 2 {
    return out;
  }
  let body_start = mn_offset + body_offset;
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
    // On-disk byte size + inline-vs-out-of-line pointer decision use the
    // ON-DISK format/count (Exif.pm:6502-6510) — BEFORE any Format override.
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
    // Apply the tag's `Format` directive (Exif.pm:6735-6744): re-interpret the
    // SAME value bytes with the override format + recomputed count. The on-disk
    // `format`/`count` are preserved on the entry for the `$format`-based
    // `Condition` gate; only the VALUE READ uses the override.
    let table_override = tags::lookup(tag_id).and_then(|t| t.format);
    let (read_format, read_count) = resolve_read_format(format, count, table_override);
    // `$readSize` is the on-disk byte size (Exif.pm:6503), clamped to the
    // available buffer — the override re-reads within these same bytes.
    let avail = tiff_data.len() - value_data_offset;
    let read_size = total_size.min(avail);
    let Some(raw) = read_value(
      tiff_data,
      value_data_offset,
      read_format,
      read_count,
      read_size,
      order,
    ) else {
      continue;
    };
    out.push(SonyEntry {
      tag_id,
      format,
      count: read_count,
      value: raw,
    });
  }
  out
}

/// Compatibility wrapper — walk Sony body when only the captured BLOB is
/// available (no parent TIFF context). Out-of-line offsets resolve
/// against the blob itself; only correct when the blob is self-contained.
#[must_use]
pub fn walk_sony_body(blob: &[u8], body_offset: usize, parent_order: ByteOrder) -> Vec<SonyEntry> {
  walk_sony_in_tiff(blob, 0, blob.len(), body_offset, parent_order)
}

fn read_u16(data: &[u8], pos: usize, order: ByteOrder) -> Option<u16> {
  let b = data.get(pos..pos + 2)?;
  let arr: [u8; 2] = [b[0], b[1]];
  Some(match order {
    ByteOrder::Little => u16::from_le_bytes(arr),
    ByteOrder::Big => u16::from_be_bytes(arr),
  })
}

fn read_u32(data: &[u8], pos: usize, order: ByteOrder) -> Option<u32> {
  let b = data.get(pos..pos + 4)?;
  let arr: [u8; 4] = [b[0], b[1], b[2], b[3]];
  Some(match order {
    ByteOrder::Little => u32::from_le_bytes(arr),
    ByteOrder::Big => u32::from_be_bytes(arr),
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Synthetic Sony body — 1 entry — `Quality` (tag 0x0102, int32u, count
  /// 1, value 2 = "Fine"), little-endian, headerless (Sony5).
  #[test]
  fn synthetic_sony_quality_headerless() {
    let mut blob: Vec<u8> = Vec::new();
    // 1 entry LE
    blob.extend_from_slice(&[0x01, 0x00]);
    // Entry: tag 0x0102, int32u (4), count 1, value=2 inline.
    blob.extend_from_slice(&[0x02, 0x01]); // tag 0x0102 LE
    blob.extend_from_slice(&[0x04, 0x00]); // format 4 = int32u
    blob.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // count 1
    blob.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // value 2 inline
    let entries = walk_sony_body(&blob, 0, ByteOrder::Little);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tag_id, 0x0102);
    match &entries[0].value {
      RawValue::U64(v) => assert_eq!(v, &[2]),
      other => panic!("expected U64, got {other:?}"),
    }
  }

  /// Sony body with the 12-byte `SONY DSC \0` header.
  #[test]
  fn synthetic_sony_with_dsc_header() {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"SONY DSC \x00\x00\x00");
    blob.extend_from_slice(&[0x01, 0x00]); // 1 entry LE
    blob.extend_from_slice(&[0x02, 0x01]); // tag 0x0102
    blob.extend_from_slice(&[0x04, 0x00]); // int32u
    blob.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // count 1
    blob.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]); // value 3 inline
    let entries = walk_sony_body(&blob, 12, ByteOrder::Little);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tag_id, 0x0102);
  }

  #[test]
  fn empty_blob_yields_no_entries() {
    let blob: Vec<u8> = Vec::new();
    assert!(walk_sony_body(&blob, 0, ByteOrder::Little).is_empty());
  }

  #[test]
  fn implausible_count_short_circuits() {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(&[0x0f, 0x27]); // 9999 entries LE
    assert!(walk_sony_body(&blob, 0, ByteOrder::Little).is_empty());
  }
}
