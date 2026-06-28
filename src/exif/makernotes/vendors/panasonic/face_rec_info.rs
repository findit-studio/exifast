// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Panasonic::FaceRecInfo` (`Panasonic.pm:2332-2397`).
//!
//! Face-RECOGNITION information (named/known faces), reached via the
//! `%Panasonic::Main` tag `0x61` SubDirectory (`Panasonic.pm:1007-1012`), first
//! seen on the DMC-TZ7. A `ProcessBinaryData` table with the DEFAULT
//! `FORMAT => 'int8u'` (so each numeric key IS the byte offset — increment 1),
//! `FIRST_ENTRY => 0`, `DATAMEMBER => [ 0 ]`. The emitted tags carry the
//! family-1 group `Panasonic` (the module default — verified via `GetTagTable`).
//!
//! Positions (`Panasonic.pm:2345-2396`), one block per recognized face:
//!
//! - byte 0 `FacesRecognized`, `int16u` — the `DataMember`; gates the per-face
//!   fields (`RawConv => '$$self{FacesRecognized} = $val'`).
//! - face N (N = 1..3), each gated `RawConv => '$$self{FacesRecognized} < N ?
//!   undef : $val'`:
//!   - `RecognizedFaceNName`, `string[20]`;
//!   - `RecognizedFaceNPosition`, `int16u[4]` (same `X Y W H` form as the face
//!     DETECTION tags);
//!   - `RecognizedFaceNAge`, `string[20]`.
//!
//! No `PrintConv`/`ValueConv`, so `-j` and `-n` are identical. Strings are
//! NUL-truncated (`ReadValue`'s `s/\0.*//s`) then run through ExifTool's
//! `FixUTF8` (`crate::convert::fix_utf8`), exactly like the Canon `SerialInfo`
//! port.
//!
//! D8: a pure decoder (no public fields); returns the `(Name, TagValue)`
//! emission pairs the dispatch site wraps in the `Panasonic` family-1 group.

// Golden-v2 Contract 3c: panic-safety by construction — every read is checked.
#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::{ByteOrder, get_u16};
use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

/// `(NameTag, name byte, PositionTag, position byte, AgeTag, age byte)` for the
/// three recognized-face blocks (`Panasonic.pm:2351-2396`).
const FACE_FIELDS: [(&str, usize, &str, usize, &str, usize); 3] = [
  (
    "RecognizedFace1Name",
    4,
    "RecognizedFace1Position",
    24,
    "RecognizedFace1Age",
    32,
  ),
  (
    "RecognizedFace2Name",
    52,
    "RecognizedFace2Position",
    72,
    "RecognizedFace2Age",
    80,
  ),
  (
    "RecognizedFace3Name",
    100,
    "RecognizedFace3Position",
    120,
    "RecognizedFace3Age",
    128,
  ),
];

/// Decode the `Panasonic::FaceRecInfo` binary block (`Panasonic.pm:2332-2397`)
/// into the `(Name, TagValue)` emission pairs.
///
/// `data` is the raw `$$valPt` block (the verbatim `0x61` value bytes); `order`
/// the inherited parent Panasonic byte order. Each face's three fields are
/// emitted only when `FacesRecognized >= N` (the `RawConv` gate) AND the bytes
/// are in range (per-field availability).
#[must_use]
pub fn parse(data: &[u8], order: ByteOrder) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  // byte 0 FacesRecognized — the DataMember. Absent ⇒ nothing emitted.
  let Some(faces) = get_u16(data, 0, order) else {
    return out;
  };
  out.push((
    SmolStr::new_static("FacesRecognized"),
    TagValue::I64(i64::from(faces)),
  ));
  for (i, (name_tag, name_off, pos_tag, pos_off, age_tag, age_off)) in
    FACE_FIELDS.iter().enumerate()
  {
    // `RawConv => '$$self{FacesRecognized} < N ? undef : $val'` (N = i + 1).
    if u32::from(faces) < (i as u32 + 1) {
      continue;
    }
    if let Some(v) = read_string(data, *name_off, 20) {
      out.push((SmolStr::new_static(name_tag), v));
    }
    if let Some(v) = read_u16x4(data, *pos_off, order) {
      out.push((SmolStr::new_static(pos_tag), v));
    }
    if let Some(v) = read_string(data, *age_off, 20) {
      out.push((SmolStr::new_static(age_tag), v));
    }
  }
  out
}

/// Read a `string[len]` at `off`: `None` when the start is at/past the block end
/// (ExifTool's `next if $entry >= $size`), else the NUL-truncated, `FixUTF8`'d
/// text over the bytes that fit (`ReadValue` clamps the count to what is
/// available, so a truncated trailing field reads fewer bytes — the Canon
/// `SerialInfo` convention).
fn read_string(data: &[u8], off: usize, len: usize) -> Option<TagValue> {
  if off >= data.len() {
    return None;
  }
  let end = off.saturating_add(len).min(data.len());
  let window = data.get(off..end).unwrap_or(&[]);
  // `s/\0.*//s` — truncate at the first NUL byte.
  let trimmed = match window.iter().position(|&b| b == 0) {
    Some(nul) => window.get(..nul).unwrap_or(window),
    None => window,
  };
  Some(TagValue::Str(SmolStr::from(crate::convert::fix_utf8(
    trimmed,
  ))))
}

/// Read four `int16u` values at `off` as the space-joined integer string; `None`
/// when any of the four are out of range (per-field availability).
fn read_u16x4(data: &[u8], off: usize, order: ByteOrder) -> Option<TagValue> {
  use std::fmt::Write;
  let mut s = String::new();
  for k in 0..4 {
    let v = get_u16(data, off.checked_add(k * 2)?, order)?;
    if k != 0 {
      s.push(' ');
    }
    let _ = write!(s, "{v}");
  }
  Some(TagValue::Str(SmolStr::from(s)))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  fn find(em: &[(SmolStr, TagValue)], name: &str) -> Option<TagValue> {
    em.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
  }

  /// Build a little-endian FaceRecInfo block holding `faces` declared and one
  /// fully-populated face block (Name@4, Position@24, Age@32) — 52 bytes.
  fn build_one(faces: u16, name: &[u8], pos: [u16; 4], age: &[u8]) -> Vec<u8> {
    let mut b = std::vec![0u8; 52];
    b[0..2].copy_from_slice(&faces.to_le_bytes());
    b[4..4 + name.len().min(20)].copy_from_slice(&name[..name.len().min(20)]);
    for (k, v) in pos.iter().enumerate() {
      b[24 + k * 2..26 + k * 2].copy_from_slice(&v.to_le_bytes());
    }
    b[32..32 + age.len().min(20)].copy_from_slice(&age[..age.len().min(20)]);
    b
  }

  /// One recognized face. Oracle: `FacesRecognized = 1`,
  /// `RecognizedFace1Name = "Alice"`, `RecognizedFace1Position = "10 20 30 40"`,
  /// `RecognizedFace1Age = "25"`; no Face2/Face3 (count gate).
  #[test]
  fn one_recognized_face() {
    let blob = build_one(1, b"Alice", [10, 20, 30, 40], b"25");
    let em = parse(&blob, ByteOrder::Little);
    assert_eq!(find(&em, "FacesRecognized"), Some(TagValue::I64(1)));
    assert_eq!(
      find(&em, "RecognizedFace1Name"),
      Some(TagValue::Str("Alice".into()))
    );
    assert_eq!(
      find(&em, "RecognizedFace1Position"),
      Some(TagValue::Str("10 20 30 40".into()))
    );
    assert_eq!(
      find(&em, "RecognizedFace1Age"),
      Some(TagValue::Str("25".into()))
    );
    assert_eq!(find(&em, "RecognizedFace2Name"), None);
    assert_eq!(em.len(), 4);
    // No PrintConv ⇒ `-n` identical.
    assert_eq!(parse(&blob, ByteOrder::Little), em);
  }

  /// The count gate drops a face whose Name/Position/Age bytes ARE present but
  /// whose index exceeds `FacesRecognized`.
  #[test]
  fn count_gate_drops_present_face2() {
    // Declare 1 but supply a 100-byte block (room for Face2's fields).
    let mut blob = build_one(1, b"Bob", [1, 2, 3, 4], b"30");
    blob.resize(120, 0);
    blob[52..55].copy_from_slice(b"Eve"); // Face2 name bytes present
    let em = parse(&blob, ByteOrder::Little);
    assert_eq!(
      find(&em, "RecognizedFace1Name"),
      Some(TagValue::Str("Bob".into()))
    );
    assert_eq!(
      find(&em, "RecognizedFace2Name"),
      None,
      "Face2 gated off by FacesRecognized = 1"
    );
  }

  /// Strings NUL-truncate (a 20-byte field with a NUL terminator).
  #[test]
  fn name_nul_truncates() {
    let blob = build_one(1, b"Carol\x00ignored", [0, 0, 0, 0], b"40");
    assert_eq!(
      find(&parse(&blob, ByteOrder::Little), "RecognizedFace1Name"),
      Some(TagValue::Str("Carol".into()))
    );
  }

  /// An empty / sub-2-byte block has no count word ⇒ nothing emitted.
  #[test]
  fn empty_block_emits_nothing() {
    assert!(parse(&[], ByteOrder::Little).is_empty());
    assert!(parse(&[0x01], ByteOrder::Little).is_empty());
  }
}
