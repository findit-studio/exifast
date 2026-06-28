// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Panasonic::ShotInfo` (`Panasonic.pm:2069-2081`).
//!
//! Leica type-5 ShotInfo (X2), reached via the `%Panasonic::Leica5` tag `0x0410`
//! SubDirectory (`Panasonic.pm:2039-2042`). A `ProcessBinaryData` table with the
//! DEFAULT `FORMAT => 'int8u'` (numeric keys are byte offsets), `TAG_PREFIX =>
//! 'Leica_ShotInfo'`, `FIRST_ENTRY => 0`. The emitted tag carries the family-1
//! group `Leica`.
//!
//! One position (`Panasonic.pm:2077-2080`):
//!
//! - byte 0 `FileIndex`, `int16u` — no `PrintConv`/`ValueConv`, so `-j` and `-n`
//!   are identical (the bare integer).
//!
//! D8: a pure decoder (no public fields); returns the `(Name, TagValue)`
//! emission pairs the dispatch site wraps in the `Leica` family-1 group.

#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::{ByteOrder, get_u16};
use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

/// Decode the `Panasonic::ShotInfo` binary block (`Panasonic.pm:2069-2081`) into
/// the `(Name, TagValue)` emission pairs. `print_conv` is accepted for a uniform
/// sub-table signature; there is no `PrintConv` here.
#[must_use]
pub fn parse(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let _ = print_conv;
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  // byte 0 FileIndex int16u.
  if let Some(n) = get_u16(data, 0, order) {
    out.push((
      SmolStr::new_static("FileIndex"),
      TagValue::I64(i64::from(n)),
    ));
  }
  out
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  fn find(em: &[(SmolStr, TagValue)], name: &str) -> Option<TagValue> {
    em.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
  }

  /// `FileIndex` is an `int16u` at byte 0. Oracle: bytes `D2 04` (LE) ⇒
  /// `Leica:FileIndex = 1234`.
  #[test]
  fn file_index_at_offset_0() {
    let em = parse(&1234u16.to_le_bytes(), ByteOrder::Little, true);
    assert_eq!(find(&em, "FileIndex"), Some(TagValue::I64(1234)));
    assert_eq!(em.len(), 1);
    // No PrintConv ⇒ `-n` identical.
    assert_eq!(parse(&1234u16.to_le_bytes(), ByteOrder::Little, false), em);
  }

  /// Big-endian decode reads MSB-first.
  #[test]
  fn big_endian() {
    let em = parse(&1234u16.to_be_bytes(), ByteOrder::Big, true);
    assert_eq!(find(&em, "FileIndex"), Some(TagValue::I64(1234)));
  }

  /// A sub-2-byte block omits the field.
  #[test]
  fn short_block_omits() {
    assert!(parse(&[0x01], ByteOrder::Little, true).is_empty());
  }
}
