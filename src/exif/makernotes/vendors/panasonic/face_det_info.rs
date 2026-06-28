// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Panasonic::FaceDetInfo` (`Panasonic.pm:2279-2329`).
//!
//! Face-detection position information, reached via the `%Panasonic::Main` tag
//! `0x4e` SubDirectory (`Panasonic.pm:936-942`). A `ProcessBinaryData` table:
//! `FORMAT => 'int16u'` (so each numeric key is multiplied by the int16u size 2
//! to get the BYTE offset — `ExifTool.pm:9893,9957` `$entry = int($index) *
//! $increment`), `FIRST_ENTRY => 0`, `DATAMEMBER => [ 0 ]`. The emitted tags
//! carry the family-1 group `Panasonic` (the module default the source table
//! inherits — verified via `GetTagTable`).
//!
//! Positions (`Panasonic.pm:2289-2328`):
//!
//! - key 0 (byte 0) `NumFacePositions`, `int16u` — the `DataMember`; gates the
//!   five face positions below (`RawConv => '$$self{NumFacePositions} = $val'`).
//! - key 1/5/9/13/17 (bytes 2/10/18/26/34) `Face1..5Position`, `int16u[4]` —
//!   four numbers `X Y W H` (face center + width/height), each `RawConv =>
//!   '$$self{NumFacePositions} < N ? undef : $val'`: emitted only when
//!   `NumFacePositions >= N`.
//!
//! No `PrintConv`/`ValueConv` on any position, so `-j` and `-n` are identical
//! (the bare integer / space-joined integer list).
//!
//! D8: a pure decoder (no public fields); returns the `(Name, TagValue)`
//! emission pairs the dispatch site wraps in the `Panasonic` family-1 group.

// Golden-v2 Contract 3c: panic-safety by construction — every read is a checked
// `get_u16`/`.get()` dominated by a length guard (re-asserts the parent `exif`
// deny over the makernotes subtree's slice shim).
#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::{ByteOrder, get_u16};
use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

/// The five `FaceNPosition` names, indexed by `N - 1`.
const FACE_NAMES: [&str; 5] = [
  "Face1Position",
  "Face2Position",
  "Face3Position",
  "Face4Position",
  "Face5Position",
];

/// Decode the `Panasonic::FaceDetInfo` binary block (`Panasonic.pm:2279-2329`)
/// into the `(Name, TagValue)` emission pairs.
///
/// `data` is the raw `$$valPt` block (the verbatim `0x4e` value bytes); `order`
/// the parent Panasonic byte order (the SubDirectory has no `ByteOrder`
/// override, so it inherits, `Panasonic.pm:939-941`). Per-field availability:
/// each position is emitted only when its bytes are in range AND the
/// `NumFacePositions` `RawConv` gate passes — a truncated block yields the
/// fields that fit, never an all-or-nothing drop.
#[must_use]
pub fn parse(data: &[u8], order: ByteOrder) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  // key 0 (byte 0) NumFacePositions — the DataMember. Absent ⇒ the whole block
  // has no usable count word, so nothing is emitted.
  let Some(num) = get_u16(data, 0, order) else {
    return out;
  };
  out.push((
    SmolStr::new_static("NumFacePositions"),
    TagValue::I64(i64::from(num)),
  ));
  // FaceNPosition int16u[4] at byte 2 + (N-1)*8 (key 1/5/9/13/17 × increment 2),
  // gated `NumFacePositions >= N`.
  for (i, name) in FACE_NAMES.iter().enumerate() {
    // `RawConv => '$$self{NumFacePositions} < N ? undef : $val'` (N = i + 1).
    if u32::from(num) < (i as u32 + 1) {
      continue;
    }
    let byte = 2 + i * 8;
    if let Some(v) = read_u16x4(data, byte, order) {
      out.push((SmolStr::new_static(name), v));
    }
  }
  out
}

/// Read four `int16u` values at `byte` and render them as the space-joined
/// integer string ExifTool's default array rendering produces (`"160 120 50
/// 50"`). `None` when any of the four are out of range (per-field availability).
fn read_u16x4(data: &[u8], byte: usize, order: ByteOrder) -> Option<TagValue> {
  use std::fmt::Write;
  let mut s = String::new();
  for k in 0..4 {
    let v = get_u16(data, byte.checked_add(k * 2)?, order)?;
    if k != 0 {
      s.push(' ');
    }
    let _ = write!(s, "{v}");
  }
  Some(TagValue::Str(SmolStr::from(s)))
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract; the test builders index fixed-layout buffers freely (an out-of-range
// index is a test-assertion failure, not a shipped panic), so it is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  fn find(em: &[(SmolStr, TagValue)], name: &str) -> Option<TagValue> {
    em.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
  }

  /// Build a little-endian FaceDetInfo block: NumFacePositions then `faces`
  /// quadruples.
  fn build(num: u16, faces: &[[u16; 4]]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&num.to_le_bytes());
    for f in faces {
      for v in f {
        b.extend_from_slice(&v.to_le_bytes());
      }
    }
    b
  }

  /// Two faces present + declared. Oracle (`ProcessBinaryData` over the crafted
  /// block): `NumFacePositions = 2`, `Face1Position = "160 120 50 50"`,
  /// `Face2Position = "40 30 20 20"`; no `Face3..5Position` (count gate).
  #[test]
  fn two_faces() {
    let blob = build(2, &[[160, 120, 50, 50], [40, 30, 20, 20]]);
    let em = parse(&blob, ByteOrder::Little);
    assert_eq!(find(&em, "NumFacePositions"), Some(TagValue::I64(2)));
    assert_eq!(
      find(&em, "Face1Position"),
      Some(TagValue::Str("160 120 50 50".into()))
    );
    assert_eq!(
      find(&em, "Face2Position"),
      Some(TagValue::Str("40 30 20 20".into()))
    );
    assert_eq!(find(&em, "Face3Position"), None);
    assert_eq!(em.len(), 3);
  }

  /// The `NumFacePositions` `RawConv` gate drops a face whose index exceeds the
  /// declared count even when its BYTES are present (`NumFacePositions < N ?
  /// undef`).
  #[test]
  fn count_gate_drops_present_bytes() {
    // Declare 1 but supply 2 quadruples of bytes.
    let blob = build(1, &[[1, 2, 3, 4], [5, 6, 7, 8]]);
    let em = parse(&blob, ByteOrder::Little);
    assert_eq!(find(&em, "NumFacePositions"), Some(TagValue::I64(1)));
    assert_eq!(
      find(&em, "Face1Position"),
      Some(TagValue::Str("1 2 3 4".into()))
    );
    assert_eq!(
      find(&em, "Face2Position"),
      None,
      "Face2 must be gated off by NumFacePositions = 1"
    );
  }

  /// Per-field availability: a declared face whose bytes are entirely absent
  /// (its byte offset is at/past the block end, ExifTool's `next if $entry >=
  /// $size`) is simply omitted; the count word + the in-range faces still emit.
  #[test]
  fn absent_face_bytes_omitted() {
    // Declare 3 but supply only 2 full quadruples ⇒ Face3 starts at byte 18 of
    // an 18-byte block (start == size) ⇒ omitted.
    let blob = build(3, &[[9, 8, 7, 6], [5, 4, 3, 2]]);
    assert_eq!(blob.len(), 18);
    let em = parse(&blob, ByteOrder::Little);
    assert_eq!(find(&em, "NumFacePositions"), Some(TagValue::I64(3)));
    assert_eq!(
      find(&em, "Face1Position"),
      Some(TagValue::Str("9 8 7 6".into()))
    );
    assert_eq!(
      find(&em, "Face2Position"),
      Some(TagValue::Str("5 4 3 2".into()))
    );
    assert_eq!(find(&em, "Face3Position"), None);
  }

  /// An empty / sub-2-byte block has no count word ⇒ nothing is emitted.
  #[test]
  fn empty_block_emits_nothing() {
    assert!(parse(&[], ByteOrder::Little).is_empty());
    assert!(parse(&[0x01], ByteOrder::Little).is_empty());
  }

  /// Big-endian decode reads the count + positions MSB-first.
  #[test]
  fn big_endian() {
    let mut blob = Vec::new();
    blob.extend_from_slice(&1u16.to_be_bytes());
    for v in [100u16, 200, 25, 25] {
      blob.extend_from_slice(&v.to_be_bytes());
    }
    let em = parse(&blob, ByteOrder::Big);
    assert_eq!(find(&em, "NumFacePositions"), Some(TagValue::I64(1)));
    assert_eq!(
      find(&em, "Face1Position"),
      Some(TagValue::Str("100 200 25 25".into()))
    );
  }
}
