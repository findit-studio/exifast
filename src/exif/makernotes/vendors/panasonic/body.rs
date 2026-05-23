// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Panasonic MakerNote IFD body walker — Phase-3 port.
//!
//! Panasonic's MakerNote (`MakerNotePanasonic`, `MakerNotes.pm:732-740`)
//! starts with the 12-byte header `Panasonic\0\0\0` and is followed by a
//! standard IFD body (`count`, `entries[]`). `Start => '$valuePtr + 12'`,
//! `ByteOrder => 'Unknown'` (the byte order falls back to the parent IFD's
//! order since the body has no MM/II marker).
//!
//! ## Out-of-line value offsets and the `Base` directive
//!
//! There are TWO variants of `%Panasonic::Main`, distinguished only by
//! `Base` (`MakerNotes.pm:732-761`):
//!
//! - `MakerNotePanasonic` (`:733`) — NO `Base =>` line, so the child IFD
//!   INHERITS the parent walk's base. Out-of-line offsets are
//!   TIFF-relative (i.e. straight indices into the parent buffer).
//! - `MakerNotePanasonic3` (`:752`, the DC-FT7) — `Base => 12` (`:758`,
//!   the bundled comment literally reads `# crazy!`). The child IFD's
//!   `$$dirInfo{Base}` becomes `eval(12) + $base` (`Exif.pm:7003`); the
//!   value-offset resolver then reads `$valuePtr -= $dataPos`
//!   (`Exif.pm:6546`) where `$subdirDataPos += $base - $subdirBase`
//!   (`Exif.pm:7040`) has shifted `$dataPos` DOWN by 12. Net effect in
//!   the port's buffer coordinates (parent `base == 0`, `dataPos == 0`):
//!   a child out-of-line offset `off` resolves to buffer position
//!   `off + 12`. Reading it at `off` (base 0) lands 12 bytes EARLY ⇒ the
//!   value is corrupted/dropped — the bug this walker's `base_offset`
//!   parameter fixes.
//!
//! The walker takes the resolved `base_offset` (the buffer addend, = the
//! literal `Base` integer; 0 for the inherit variant) from the
//! [dispatcher](crate::exif::makernotes::dispatcher) and applies it to
//! every OUT-OF-LINE offset. Inline values (≤ 4 bytes, stored in the
//! entry) carry no offset and are unaffected (`Exif.pm:6504` only the
//! `$size > 4` branch reads/rebases a pointer).

use super::tags;
use crate::exif::ifd::{ByteOrder, Format, RawValue, read_value};
use crate::exif::makernotes::vendors::resolve_read_format;
use std::vec::Vec;

/// Header byte length for `MakerNotePanasonic` and `MakerNotePanasonic3`
/// (the 12-byte `Panasonic\0\0\0` prefix) — bundled `Start => '$valuePtr +
/// 12'` (`MakerNotes.pm:738`/`:757`). It is the DEFAULT `body_offset`; the
/// cross-table `MakerNoteLeica10` (`:724-730`) instead routes a
/// `LEICA CAMERA AG\0` blob to `%Panasonic::Main` with `Start => '$valuePtr
/// + 18'` (`:728`), so the walker takes the `body_offset` as a PARAMETER
/// rather than hard-coding 12 (mirrors the Sony walker's `body_offset`).
pub const HEADER_LEN: usize = 12;

/// One decoded Panasonic MakerNote IFD entry.
#[derive(Debug, Clone)]
pub struct PanasonicEntry {
  /// Tag ID (`Panasonic.pm` Main hash key).
  pub tag_id: u16,
  /// On-disk format code.
  pub format: Format,
  /// Element count.
  pub count: usize,
  /// The decoded raw value (post-Format-decode, pre-PrintConv).
  pub value: RawValue,
}

/// Walk the Panasonic MakerNote body in the parent TIFF context, so
/// out-of-line value offsets resolve against the parent TIFF block.
///
/// `tiff_data` is the parent TIFF block; `mn_offset` is the start of the
/// captured MakerNote within `tiff_data`; `mn_len` is its byte length;
/// `parent_order` is the parent IFD walk's byte order (Panasonic's body
/// has no MM/II marker so the byte order falls back to the parent).
///
/// `body_offset` is the BODY start offset within the captured MakerNote —
/// bundled `Start => '$valuePtr + N'`. It is [`HEADER_LEN`] (12) for
/// `MakerNotePanasonic`/`MakerNotePanasonic3` (the `Panasonic\0\0\0`
/// prefix, `MakerNotes.pm:738`/`:757`) and `18` for the cross-table
/// `MakerNoteLeica10` (`LEICA CAMERA AG\0` → `%Panasonic::Main`,
/// `:728`). Mirrors the Sony walker's `body_offset` parameter.
///
/// `base_offset` is the buffer addend applied to every OUT-OF-LINE value
/// offset — the bundled `SubDirectory{Base}` directive expressed in the
/// port's buffer coordinates (`Exif.pm:6546`/`:7003`/`:7040`; see the
/// module docs). It is `0` for `MakerNotePanasonic` (no `Base` ⇒ inherit
/// the parent base), `12` for `MakerNotePanasonic3` (`Base => 12`,
/// `MakerNotes.pm:758`), and `0` for `MakerNoteLeica10` (no `Base` line,
/// `:726-730` ⇒ inherit). Inline values are never rebased.
#[must_use]
pub fn walk_panasonic_in_tiff(
  tiff_data: &[u8],
  mn_offset: usize,
  mn_len: usize,
  body_offset: usize,
  parent_order: ByteOrder,
  base_offset: usize,
) -> Vec<PanasonicEntry> {
  let mut out = Vec::new();
  if mn_len < body_offset + 2 {
    return out;
  }
  if mn_offset.saturating_add(body_offset) >= tiff_data.len() {
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
      // `$valuePtr -= $dataPos` (`Exif.pm:6546`) where the maker-note
      // SubDirectory shifted `$dataPos` by `$base - $subdirBase`
      // (`Exif.pm:7040`); in the port's buffer coordinates that reduces to
      // ADDING the resolved `base_offset` (the `Base` integer) to the raw
      // out-of-line offset. `base_offset` is 0 for the inherit variant, so
      // the existing self-contained / Panasonic1 walks are byte-identical.
      let abs_off = (off as usize).saturating_add(base_offset);
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
    out.push(PanasonicEntry {
      tag_id,
      format,
      count: read_count,
      value: raw,
    });
  }
  out
}

/// Compatibility wrapper — walk Panasonic body when only the captured
/// BLOB is available (no parent TIFF context). Out-of-line offsets
/// resolve against the blob; correct only when the blob is
/// self-contained (synthetic test fixtures). Uses `base_offset == 0` —
/// the inherit variant (`MakerNotePanasonic`); the `Base => 12` DC-FT7
/// variant must go through [`walk_panasonic_in_tiff`] with `base_offset
/// = 12`.
#[must_use]
pub fn walk_panasonic_body(blob: &[u8], parent_order: ByteOrder) -> Vec<PanasonicEntry> {
  walk_panasonic_in_tiff(blob, 0, blob.len(), HEADER_LEN, parent_order, 0)
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

  /// Synthetic Panasonic body: 1 entry — `ImageQuality` (tag 0x01, int16u,
  /// count 1, value 2 = "High"), little-endian.
  #[test]
  fn synthetic_panasonic_image_quality_inline() {
    let mut blob: Vec<u8> = Vec::new();
    // 12-byte header "Panasonic\0\0\0"
    blob.extend_from_slice(b"Panasonic\x00\x00\x00");
    // 1 entry LE
    blob.extend_from_slice(&[0x01, 0x00]);
    // Entry: tag 0x01, int16u (3), count 1, value=2 in the 4-byte inline slot.
    blob.extend_from_slice(&[0x01, 0x00]); // tag
    blob.extend_from_slice(&[0x03, 0x00]); // format 3 = int16u
    blob.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // count 1
    blob.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // value 2 inline
    let entries = walk_panasonic_body(&blob, ByteOrder::Little);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tag_id, 0x01);
    match &entries[0].value {
      RawValue::U64(v) => assert_eq!(v, &[2]),
      other => panic!("expected U64, got {other:?}"),
    }
  }

  #[test]
  fn empty_blob_yields_no_entries() {
    let blob: Vec<u8> = Vec::new();
    assert!(walk_panasonic_body(&blob, ByteOrder::Little).is_empty());
  }

  #[test]
  fn header_too_short_yields_empty() {
    let blob = b"Panasonic\x00\x00\x00\x01".to_vec(); // 13 bytes — but only the header + 1 byte
    let entries = walk_panasonic_body(&blob, ByteOrder::Little);
    assert!(entries.is_empty());
  }

  #[test]
  fn implausible_count_short_circuits() {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"Panasonic\x00\x00\x00");
    blob.extend_from_slice(&[0x0f, 0x27]); // 9999 LE
    assert!(walk_panasonic_body(&blob, ByteOrder::Little).is_empty());
  }

  /// `MakerNotePanasonic3` (`Base => 12`, `MakerNotes.pm:758`): an
  /// OUT-OF-LINE string tag's stored offset is interpreted as `off + 12`
  /// in buffer coordinates. Build a blob whose 0x51 LensType (string,
  /// out-of-line) stores an offset 12 LESS than the real string position;
  /// `base_offset = 12` reads it correctly, `base_offset = 0` reads 12
  /// bytes early ⇒ wrong bytes.
  #[test]
  fn panasonic3_base12_out_of_line_offset() {
    // Layout (blob-relative, == buffer-relative since mn_offset = 0):
    //   [0..12)  "Panasonic\0\0\0"
    //   [12..14) count = 1
    //   [14..26) entry: tag 0x51, string(2), count 6, value-offset field
    //   [26..30) next-IFD ptr = 0
    //   [30..36) "ABCDE\0"  (the real string, 6 bytes, > 4 ⇒ out-of-line)
    let lens = b"ABCDE\x00";
    let str_pos = 30usize;
    // DC-FT7 stores the offset relative to base+12, so stored = real - 12.
    let stored = (str_pos - 12) as u32;
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"Panasonic\x00\x00\x00");
    blob.extend_from_slice(&1u16.to_le_bytes()); // 1 entry
    blob.extend_from_slice(&0x51u16.to_le_bytes()); // tag
    blob.extend_from_slice(&2u16.to_le_bytes()); // format 2 = string
    blob.extend_from_slice(&(lens.len() as u32).to_le_bytes()); // count 6
    blob.extend_from_slice(&stored.to_le_bytes()); // out-of-line offset (base-12)
    blob.extend_from_slice(&0u32.to_le_bytes()); // next IFD
    assert_eq!(blob.len(), str_pos);
    blob.extend_from_slice(lens);

    // base_offset = 12 ⇒ reads the real string bytes. body_offset = 12
    // (the `Panasonic\0\0\0` header).
    let entries = walk_panasonic_in_tiff(&blob, 0, blob.len(), HEADER_LEN, ByteOrder::Little, 12);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tag_id, 0x51);
    match &entries[0].value {
      RawValue::Text(s) => assert_eq!(s.as_str(), "ABCDE"),
      other => panic!("expected Text(\"ABCDE\"), got {other:?}"),
    }

    // base_offset = 0 (the OLD behaviour) reads 12 bytes early — the
    // entry's own value-offset field bytes, NOT "ABCDE": proves the fix
    // is load-bearing.
    let bad = walk_panasonic_in_tiff(&blob, 0, blob.len(), HEADER_LEN, ByteOrder::Little, 0);
    assert_eq!(bad.len(), 1);
    // A non-Text decode is also acceptable evidence of corruption; only a
    // Text("ABCDE") would mean the base-0 read wrongly recovered the string.
    if let RawValue::Text(s) = &bad[0].value {
      assert_ne!(
        s.as_str(),
        "ABCDE",
        "base_offset=0 must NOT land on the real string (it reads 12 bytes early)"
      );
    }
  }

  /// `MakerNotePanasonic` (no `Base` ⇒ inherit, `base_offset == 0`): an
  /// out-of-line string resolves against the buffer directly. Pins that
  /// the inherit variant is unchanged by the `base_offset` plumbing.
  #[test]
  fn panasonic1_inherit_out_of_line_offset() {
    let lens = b"ABCDE\x00";
    let str_pos = 30usize;
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"Panasonic\x00\x00\x00");
    blob.extend_from_slice(&1u16.to_le_bytes());
    blob.extend_from_slice(&0x51u16.to_le_bytes());
    blob.extend_from_slice(&2u16.to_le_bytes());
    blob.extend_from_slice(&(lens.len() as u32).to_le_bytes());
    blob.extend_from_slice(&(str_pos as u32).to_le_bytes()); // base-0 offset
    blob.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(blob.len(), str_pos);
    blob.extend_from_slice(lens);

    let entries = walk_panasonic_in_tiff(&blob, 0, blob.len(), HEADER_LEN, ByteOrder::Little, 0);
    assert_eq!(entries.len(), 1);
    match &entries[0].value {
      RawValue::Text(s) => assert_eq!(s.as_str(), "ABCDE"),
      other => panic!("expected Text(\"ABCDE\"), got {other:?}"),
    }
  }

  /// `MakerNoteLeica10` (`MakerNotes.pm:724-730`): a `LEICA CAMERA AG\0`
  /// blob routes to `%Panasonic::Main` with `Start => '$valuePtr + 18'`.
  /// The walker must read the IFD at `body_offset = 18` (NOT the
  /// `Panasonic\0\0\0` default of 12). Build a self-contained blob and pin
  /// that body_offset=18 finds the inline ImageQuality entry.
  #[test]
  fn leica10_body_offset_18_inline() {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"LEICA CAMERA AG\x00"); // 16-byte signature
    blob.extend_from_slice(&[0x00, 0x00]); // 2 pad ⇒ body starts at 18
    blob.extend_from_slice(&1u16.to_le_bytes()); // 1 entry
    blob.extend_from_slice(&0x01u16.to_le_bytes()); // tag 0x01 ImageQuality
    blob.extend_from_slice(&3u16.to_le_bytes()); // int16u
    blob.extend_from_slice(&1u32.to_le_bytes()); // count 1
    blob.extend_from_slice(&2u32.to_le_bytes()); // value 2 inline
    blob.extend_from_slice(&0u32.to_le_bytes()); // next IFD

    // body_offset = 18 reads the entry; the inherit base ⇒ base_offset = 0.
    let entries = walk_panasonic_in_tiff(&blob, 0, blob.len(), 18, ByteOrder::Little, 0);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tag_id, 0x01);
    match &entries[0].value {
      RawValue::U64(v) => assert_eq!(v, &[2]),
      other => panic!("expected U64([2]), got {other:?}"),
    }

    // body_offset = 12 (the Panasonic default) reads garbage from inside
    // the 16-byte signature ⇒ NOT a valid 1-entry ImageQuality IFD: proves
    // the 18 is load-bearing for the cross-table Leica10 route.
    let wrong = walk_panasonic_in_tiff(&blob, 0, blob.len(), 12, ByteOrder::Little, 0);
    assert!(
      wrong.first().is_none_or(|e| e.tag_id != 0x01),
      "body_offset=12 must NOT decode the ImageQuality entry (header is 18 for Leica10)"
    );
  }
}
