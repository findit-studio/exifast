// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Canon::MeasuredColor` (`Canon.pm:7295-7307`).
//!
//! Binary-data sub-table — `FORMAT => 'int16u'`, `FIRST_ENTRY => 1`,
//! `GROUPS => { 0 => 'MakerNotes', 2 => 'Camera' }`. Reached via the
//! `Canon::Main` tag `0xaa` SubDirectory (`Canon.pm:1913-1919`).
//!
//! The single named position 1 (`MeasuredRGGB`, `Format => 'int16u[4]'`,
//! byte offset `2 * 1 = 2`) is rendered as ExifTool's default space-joined
//! string (e.g. `"461 1024 1024 769"`). There is NO `PrintConv`, so the `-j`
//! and `-n` views are identical.
//!
//! D8: pure decoder (no public struct fields); returns the `(Name, TagValue)`
//! emission pairs the dispatch site wraps in the `Canon` family-1 group.

#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::ByteOrder;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::string::String;
use std::vec::Vec;

/// Decode the `Canon::MeasuredColor` binary block (`Canon.pm:7295-7307`).
/// `print_conv` is accepted for the uniform sub-table signature; there is no
/// `PrintConv`, so the result is identical in `-j` and `-n`. The block is
/// skipped if it is too short to hold the four `int16u` words at offset 2.
#[must_use]
pub fn parse(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let _ = print_conv; // no PrintConv in this table
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  // Position 1, `int16u[4]`: byte offset `2 * 1 = 2`.
  if let Some(quad) = read_u16x4(data, 1, order) {
    out.push((
      SmolStr::new_static("MeasuredRGGB"),
      TagValue::Str(SmolStr::from(join_u16(&quad))),
    ));
  }
  out
}

/// Read four consecutive unsigned 16-bit words starting at word `position`
/// (`Format => 'int16u[4]'`, byte offset `2*position`). Returns `None` if any
/// of the four words is past the end of `data`.
fn read_u16x4(data: &[u8], position: usize, order: ByteOrder) -> Option<[u16; 4]> {
  let mut quad = [0u16; 4];
  for (i, slot) in quad.iter_mut().enumerate() {
    let off = 2 * (position + i);
    let arr: [u8; 2] = data.get(off..off + 2)?.try_into().ok()?;
    *slot = match order {
      ByteOrder::Little => u16::from_le_bytes(arr),
      ByteOrder::Big => u16::from_be_bytes(arr),
    };
  }
  Some(quad)
}

/// Render an `int16u[4]` quad as ExifTool's default space-joined string.
fn join_u16(words: &[u16]) -> String {
  use std::fmt::Write;
  let mut s = String::new();
  for (i, w) in words.iter().enumerate() {
    if i != 0 {
      s.push(' ');
    }
    let _ = write!(s, "{w}");
  }
  s
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  fn build_u16(words: &[u16]) -> Vec<u8> {
    let mut v = Vec::new();
    for w in words {
      v.extend_from_slice(&w.to_le_bytes());
    }
    v
  }

  #[test]
  fn decodes_measured_rggb() {
    // word[0]=length, word[1..5]=MeasuredRGGB (the real EOS 5D block).
    let data = build_u16(&[10, 461, 1024, 1024, 769]);
    let em = parse(&data, ByteOrder::Little, true);
    assert_eq!(em.len(), 1);
    assert_eq!(em[0].0, "MeasuredRGGB");
    assert_eq!(em[0].1, TagValue::Str("461 1024 1024 769".into()));
    // `-n` is identical (no PrintConv).
    assert_eq!(parse(&data, ByteOrder::Little, false), em);
  }

  #[test]
  fn truncated_block_emits_nothing() {
    // Only 3 words present — the int16u[4] quad at offset 2 needs words 1..4.
    let data = build_u16(&[10, 461, 1024]);
    assert!(parse(&data, ByteOrder::Little, true).is_empty());
  }
}
