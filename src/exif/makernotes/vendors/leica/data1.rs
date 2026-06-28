// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Panasonic::Data1` (`Panasonic.pm:1970-1987`).
//!
//! Leica M9 `Data1` binary block, reached via the `%Panasonic::Subdir` tag
//! `0x3901` SubDirectory (`Panasonic.pm:1927-1930`). A `ProcessBinaryData` table
//! with the DEFAULT `FORMAT => 'int8u'` (numeric keys are byte offsets),
//! `TAG_PREFIX => 'Leica_Data1'`, `FIRST_ENTRY => 0`. The emitted tag carries
//! the family-1 group `Leica`.
//!
//! One position (`Panasonic.pm:1978-1986`):
//!
//! - byte 0x16 (22) `LensType`, `int32u`, `Priority => 0` —
//!   `ValueConv => '(($val >> 2) & 0xffff) . " " . ($val & 0x3)'` (note the
//!   `& 0xffff` mask the IFD-level `LensType` lacks), then the `%leicaLensTypes`
//!   lookup (the full `"id bits"` key, then the leading-integer `OTHER`
//!   fallback). `-n` keeps the `"id bits"` ValueConv string.
//!
//! `Priority => 0` makes this LensType NOT override a higher-priority sibling
//! (e.g. the Subdir `0x3405 LensType`) in ExifTool's de-dup; exifast emits the
//! faithful VALUE and leaves de-dup ordering to the emission engine.
//!
//! D8: a pure decoder (no public fields); returns the `(Name, TagValue)`
//! emission pairs the dispatch site wraps in the `Leica` family-1 group.

#![deny(clippy::indexing_slicing)]

use super::lens_types;
use crate::exif::ifd::{ByteOrder, get_u32};
use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

/// Decode the `Panasonic::Data1` binary block (`Panasonic.pm:1970-1987`) into
/// the `(Name, TagValue)` emission pairs.
///
/// `data` is the raw `$$valPt` block; `order` the inherited Subdir byte order
/// (consumed by the int32u read). Per-field availability: `LensType` is emitted
/// only when its int32u (bytes 22..26) is in range.
#[must_use]
pub fn parse(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  // byte 22 LensType int32u.
  if let Some(raw) = get_u32(data, 22, order) {
    out.push((SmolStr::new_static("LensType"), lens_type(raw, print_conv)));
  }
  out
}

/// Data1 `LensType` (`Panasonic.pm:1983`): `ValueConv => '(($val >> 2) & 0xffff)
/// . " " . ($val & 0x3)'` then the `%leicaLensTypes` lookup (full `"id bits"`
/// key, then the leading-integer `OTHER` fallback). `-n` keeps the ValueConv
/// string.
fn lens_type(raw: u32, print_conv: bool) -> TagValue {
  let id = (raw >> 2) & 0xffff;
  let bits = raw & 0x3;
  let value_conv = std::format!("{id} {bits}");
  if !print_conv {
    return TagValue::Str(SmolStr::from(value_conv));
  }
  if let Some(name) = lens_types::lookup_name(&value_conv) {
    return TagValue::Str(name);
  }
  let id_key = std::format!("{id}");
  if let Some(name) = lens_types::lookup_name(&id_key) {
    return TagValue::Str(name);
  }
  // No match ⇒ ExifTool keeps the ValueConv string.
  TagValue::Str(SmolStr::from(value_conv))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  fn find(em: &[(SmolStr, TagValue)], name: &str) -> Option<TagValue> {
    em.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
  }

  /// `LensType` at byte 22. Oracle: int32u `(5 << 2) = 20` ⇒ id 5 bits 0 ⇒
  /// `"5"` ⇒ "Summilux-M 50mm f/1.4 (II)" (`-j`) / `"5 0"` (`-n`).
  #[test]
  fn lens_type_at_offset_22() {
    let mut blob = std::vec![0u8; 26];
    blob[22..26].copy_from_slice(&20u32.to_le_bytes());
    assert_eq!(
      find(&parse(&blob, ByteOrder::Little, true), "LensType"),
      Some(TagValue::Str("Summilux-M 50mm f/1.4 (II)".into()))
    );
    assert_eq!(
      find(&parse(&blob, ByteOrder::Little, false), "LensType"),
      Some(TagValue::Str("5 0".into()))
    );
  }

  /// The `& 0xffff` mask: an id whose pre-mask `>> 2` exceeds 16 bits wraps.
  /// `raw = ((0x10005) << 2) | 0` ⇒ `>> 2 = 0x10005`, `& 0xffff = 5` ⇒ id 5.
  #[test]
  fn lens_type_masks_id_to_16_bits() {
    let raw: u32 = 0x10005u32 << 2;
    let mut blob = std::vec![0u8; 26];
    blob[22..26].copy_from_slice(&raw.to_le_bytes());
    // id = (raw >> 2) & 0xffff = 5 ⇒ "5 0" ⇒ resolves like id 5.
    assert_eq!(
      find(&parse(&blob, ByteOrder::Little, false), "LensType"),
      Some(TagValue::Str("5 0".into()))
    );
  }

  /// A block too short to reach byte 22 omits LensType.
  #[test]
  fn short_block_omits() {
    assert!(parse(&[0u8; 10], ByteOrder::Little, true).is_empty());
  }
}
