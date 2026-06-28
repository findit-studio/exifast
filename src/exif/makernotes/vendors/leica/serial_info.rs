// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Panasonic::SerialInfo` (`Panasonic.pm:1724-1733`).
//!
//! Leica serial-number info, reached via the `%Panasonic::Leica3` tag `0x0b`
//! SubDirectory (`Panasonic.pm:1712-1715`, the R8/R9 digital backs). A
//! `ProcessBinaryData` table with the DEFAULT `FORMAT => 'int8u'` (numeric keys
//! are byte offsets), `TAG_PREFIX => 'Leica_SerialInfo'`, `FIRST_ENTRY => 0`.
//! The emitted tag carries the family-1 group `Leica`.
//!
//! One position (`Panasonic.pm:1729-1732`):
//!
//! - byte 4 `SerialNumber`, `string[8]` — NUL-truncated (`ReadValue`'s
//!   `s/\0.*//s`) then run through `FixUTF8`. No `PrintConv`/`ValueConv`, so
//!   `-j` and `-n` are identical.
//!
//! D8: a pure decoder (no public fields); returns the `(Name, TagValue)`
//! emission pairs the dispatch site wraps in the `Leica` family-1 group.

#![deny(clippy::indexing_slicing)]

use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

/// Decode the `Panasonic::SerialInfo` binary block (`Panasonic.pm:1724-1733`)
/// into the `(Name, TagValue)` emission pairs. `print_conv` is accepted for a
/// uniform sub-table signature; there is no `PrintConv` here.
#[must_use]
pub fn parse(data: &[u8], print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let _ = print_conv;
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  // byte 4 SerialNumber string[8].
  if let Some(v) = read_string(data, 4, 8) {
    out.push((SmolStr::new_static("SerialNumber"), v));
  }
  out
}

/// Read a `string[len]` at `off`: `None` when the start is at/past the block end
/// (ExifTool's `next if $entry >= $size`), else the NUL-truncated, `FixUTF8`'d
/// text over the bytes that fit.
fn read_string(data: &[u8], off: usize, len: usize) -> Option<TagValue> {
  if off >= data.len() {
    return None;
  }
  let end = off.saturating_add(len).min(data.len());
  let window = data.get(off..end).unwrap_or(&[]);
  let trimmed = match window.iter().position(|&b| b == 0) {
    Some(nul) => window.get(..nul).unwrap_or(window),
    None => window,
  };
  Some(TagValue::Str(SmolStr::from(crate::convert::fix_utf8(
    trimmed,
  ))))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  fn find(em: &[(SmolStr, TagValue)], name: &str) -> Option<TagValue> {
    em.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
  }

  /// `SerialNumber` is a `string[8]` at byte 4. Oracle: a block whose bytes 4..12
  /// hold `"1234567\0"` ⇒ `Leica:SerialNumber = "1234567"`.
  #[test]
  fn serial_number_at_offset_4() {
    let mut blob = std::vec![0u8; 12];
    blob[4..12].copy_from_slice(b"1234567\x00");
    let em = parse(&blob, true);
    assert_eq!(
      find(&em, "SerialNumber"),
      Some(TagValue::Str("1234567".into()))
    );
    assert_eq!(em.len(), 1);
    // No PrintConv ⇒ `-n` identical.
    assert_eq!(parse(&blob, false), em);
  }

  /// A block too short to reach byte 4 omits the field.
  #[test]
  fn short_block_omits_serial() {
    assert!(parse(&[0, 1, 2], true).is_empty());
  }
}
