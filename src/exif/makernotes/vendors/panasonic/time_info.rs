// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Panasonic::TimeInfo` (`Panasonic.pm:1939-1968`).
//!
//! Timestamp information, reached via the `%Panasonic::Main` tag `0x2003`
//! SubDirectory (`Panasonic.pm:1524-1527`). A `ProcessBinaryData` table with the
//! DEFAULT `FORMAT => 'int8u'` (numeric keys are byte offsets), `FIRST_ENTRY =>
//! 0`. The emitted tags carry the family-1 group `Panasonic`.
//!
//! Positions (`Panasonic.pm:1946-1967`):
//!
//! - byte 0 `PanasonicDateTime`, `undef[8]`:
//!   - `RawConv => '$val =~ /^\0/ ? undef : $val'` — drop when the first byte is
//!     NUL;
//!   - `ValueConv => 'sprintf("%s:%s:%s %s:%s:%s.%s", unpack "H4H2H2H2H2H2H2",
//!     $val)'` — the 8 bytes are nibble-hex-encoded into `YYYY:MM:DD
//!     HH:MM:SS.ff` (Perl `unpack "H"` is high-nibble-first lowercase hex; the
//!     leading `H4` consumes the first TWO bytes as the four-digit year);
//!   - `PrintConv => '$self->ConvertDateTime($val)'` — identity under the
//!     default options exifast models (no `-dateFormat`), so `-j` and `-n` agree.
//! - byte 16 `TimeLapseShotNumber`, `int32u`.
//!
//! D8: a pure decoder (no public fields); returns the `(Name, TagValue)`
//! emission pairs the dispatch site wraps in the `Panasonic` family-1 group.

// Golden-v2 Contract 3c: panic-safety by construction — array destructuring +
// checked reads, no raw indexing.
#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::{ByteOrder, get_u32};
use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

/// Decode the `Panasonic::TimeInfo` binary block (`Panasonic.pm:1939-1968`) into
/// the `(Name, TagValue)` emission pairs.
///
/// `data` is the raw `$$valPt` block (the verbatim `0x2003` value bytes);
/// `order` the inherited parent Panasonic byte order (consumed by the
/// `TimeLapseShotNumber` int32u read). `print_conv` is accepted for a uniform
/// sub-table signature; `PanasonicDateTime`'s only `PrintConv` is the identity
/// `ConvertDateTime`, so the result is the same in both modes.
#[must_use]
pub fn parse(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let _ = print_conv; // ConvertDateTime is identity here
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  // byte 0 PanasonicDateTime undef[8] — RawConv NUL-drop + the nibble-hex ValueConv.
  if let Some(dt) = format_datetime(data) {
    out.push((
      SmolStr::new_static("PanasonicDateTime"),
      TagValue::Str(SmolStr::from(dt)),
    ));
  }
  // byte 16 TimeLapseShotNumber int32u.
  if let Some(n) = get_u32(data, 16, order) {
    out.push((
      SmolStr::new_static("TimeLapseShotNumber"),
      TagValue::I64(i64::from(n)),
    ));
  }
  out
}

/// `unpack "H4H2H2H2H2H2H2"` + the `sprintf` date format (`Panasonic.pm:1952`),
/// gated by the `RawConv => '$val =~ /^\0/ ? undef : $val'` NUL-drop
/// (`Panasonic.pm:1951`). `None` when fewer than 8 bytes are present (the `undef`
/// field cannot be fully read) or the first byte is NUL.
fn format_datetime(data: &[u8]) -> Option<String> {
  let win: [u8; 8] = data.get(0..8)?.try_into().ok()?;
  let [b0, b1, b2, b3, b4, b5, b6, b7] = win;
  // `RawConv => '$val =~ /^\0/ ? undef : $val'` — drop a leading-NUL value.
  if b0 == 0 {
    return None;
  }
  // `unpack "H"` is high-nibble-first LOWERCASE hex; the `H4` leading field
  // consumes the first two bytes ⇒ the four-digit year.
  Some(std::format!(
    "{b0:02x}{b1:02x}:{b2:02x}:{b3:02x} {b4:02x}:{b5:02x}:{b6:02x}.{b7:02x}"
  ))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  fn find(em: &[(SmolStr, TagValue)], name: &str) -> Option<TagValue> {
    em.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
  }

  /// A normal BCD-style datetime + a TimeLapseShotNumber. Oracle (`unpack
  /// "H4H2H2H2H2H2H2"` then the sprintf): bytes `20 21 06 28 14 30 00 55` ⇒
  /// `"2021:06:28 14:30:00.55"`; int32u at byte 16 ⇒ the shot number.
  #[test]
  fn datetime_and_shot_number() {
    let mut blob = std::vec![0u8; 20];
    blob[0..8].copy_from_slice(&[0x20, 0x21, 0x06, 0x28, 0x14, 0x30, 0x00, 0x55]);
    blob[16..20].copy_from_slice(&7u32.to_le_bytes());
    let em = parse(&blob, ByteOrder::Little, true);
    assert_eq!(
      find(&em, "PanasonicDateTime"),
      Some(TagValue::Str("2021:06:28 14:30:00.55".into()))
    );
    assert_eq!(find(&em, "TimeLapseShotNumber"), Some(TagValue::I64(7)));
    // ConvertDateTime is identity ⇒ `-n` matches `-j`.
    assert_eq!(parse(&blob, ByteOrder::Little, false), em);
  }

  /// `RawConv => '$val =~ /^\0/ ? undef'` drops a leading-NUL datetime; the
  /// TimeLapseShotNumber (if present) still emits.
  #[test]
  fn leading_nul_datetime_dropped() {
    let mut blob = std::vec![0u8; 20];
    // First byte NUL ⇒ PanasonicDateTime dropped.
    blob[0..8].copy_from_slice(&[0x00, 0x21, 0x06, 0x28, 0x14, 0x30, 0x00, 0x55]);
    blob[16..20].copy_from_slice(&3u32.to_le_bytes());
    let em = parse(&blob, ByteOrder::Little, true);
    assert_eq!(find(&em, "PanasonicDateTime"), None);
    assert_eq!(find(&em, "TimeLapseShotNumber"), Some(TagValue::I64(3)));
  }

  /// Lowercase nibble-hex: a byte with an a-f nibble renders lowercase (Perl
  /// `unpack "H"`).
  #[test]
  fn nibble_hex_is_lowercase() {
    let blob = [0x20, 0x1a, 0x0b, 0x1c, 0x0a, 0x0f, 0x00, 0x00];
    assert_eq!(
      find(&parse(&blob, ByteOrder::Little, true), "PanasonicDateTime"),
      Some(TagValue::Str("201a:0b:1c 0a:0f:00.00".into()))
    );
  }

  /// A block shorter than 8 bytes has no full datetime field; an absent
  /// TimeLapseShotNumber (block < 20 bytes) is omitted.
  #[test]
  fn short_block() {
    assert!(parse(&[0x20, 0x21], ByteOrder::Little, true).is_empty());
    // 8-byte block: datetime present, shot number absent.
    let blob = [0x20, 0x21, 0x06, 0x28, 0x14, 0x30, 0x00, 0x55];
    let em = parse(&blob, ByteOrder::Little, true);
    assert_eq!(
      find(&em, "PanasonicDateTime"),
      Some(TagValue::Str("2021:06:28 14:30:00.55".into()))
    );
    assert_eq!(find(&em, "TimeLapseShotNumber"), None);
  }
}
