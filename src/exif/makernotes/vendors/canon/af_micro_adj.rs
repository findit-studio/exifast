// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Canon::AFMicroAdj` (`Canon.pm:8978-8997`).
//!
//! Binary-data sub-table — `FORMAT => 'int32s'`, `FIRST_ENTRY => 1`,
//! `GROUPS => { 0 => 'MakerNotes', 2 => 'Camera' }`. Reached via the
//! `Canon::Main` tag `0x4013` SubDirectory (`Canon.pm:2088-2096`).
//!
//! Two named positions (`int32s` ⇒ byte offset `4 * position`):
//! - position 1 `AFMicroAdjMode` (`int32s`, byte 4) — `PrintConv` `0 =>
//!   'Disable'`, `1 => 'Adjust all by the same amount'`, `2 => 'Adjust by
//!   lens'`;
//! - position 2 `AFMicroAdjValue` (`Format => 'rational64s'`, byte 8) — two
//!   `int32s` words (numerator at byte 8, denominator at byte 12) rendered as
//!   the decimal `num/denom`.
//!
//! D8: pure decoder (no public struct fields); returns the `(Name, TagValue)`
//! emission pairs the dispatch site wraps in the `Canon` family-1 group.

#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::ByteOrder;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

/// Decode the `Canon::AFMicroAdj` binary block (`Canon.pm:8978-8997`).
/// Each named position whose bytes are in range is emitted; a position past
/// the end of `data` is skipped (bundled's `ReadValue` returns undef).
#[must_use]
pub fn parse(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();

  // Position 1 — AFMicroAdjMode (`int32s`, byte offset 4).
  if let Some(mode) = read_i32(data, 1, order) {
    let value = if print_conv {
      match mode {
        0 => TagValue::Str(SmolStr::new_static("Disable")),
        1 => TagValue::Str(SmolStr::new_static("Adjust all by the same amount")),
        2 => TagValue::Str(SmolStr::new_static("Adjust by lens")),
        n => TagValue::Str(SmolStr::from(std::format!("Unknown ({n})"))),
      }
    } else {
      TagValue::I64(mode)
    };
    out.push((SmolStr::new_static("AFMicroAdjMode"), value));
  }

  // Position 2 — AFMicroAdjValue (`rational64s`: numerator at byte 8,
  // denominator at byte 12). The decimal `num/denom` value (no PrintConv ⇒
  // identical in `-j` and `-n`).
  if let (Some(num), Some(denom)) = (read_i32(data, 2, order), read_i32(data, 3, order)) {
    out.push((SmolStr::new_static("AFMicroAdjValue"), rational(num, denom)));
  }

  out
}

/// Read one signed 32-bit word at word `position` (byte offset `4*position`).
fn read_i32(data: &[u8], position: usize, order: ByteOrder) -> Option<i64> {
  let off = 4 * position;
  let arr: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => i32::from_le_bytes(arr),
    ByteOrder::Big => i32::from_be_bytes(arr),
  } as i64)
}

/// Render a `rational64s` as ExifTool's default decimal value (`num/denom`),
/// matching its whole-vs-fractional number formatting (`num_value`).
fn rational(num: i64, denom: i64) -> TagValue {
  if denom == 0 {
    // ExifTool surfaces a zero-denominator rational as its raw "num/denom"
    // string; this never occurs in the real fixtures (denom is 10 here).
    return TagValue::Str(SmolStr::from(std::format!("{num}/{denom}")));
  }
  let v = num as f64 / denom as f64;
  if v.fract() == 0.0 && v.is_finite() {
    TagValue::I64(v as i64)
  } else {
    TagValue::F64(v)
  }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  /// The real EOS 7D AFMicroAdj block (`Canon.pm:8978`): word0 = 44 (length),
  /// AFMicroAdjMode = 0, AFMicroAdjValue = 0/10.
  fn build() -> Vec<u8> {
    let mut v = Vec::new();
    for w in [44i32, 0 /*mode*/, 0 /*num*/, 10 /*denom*/] {
      v.extend_from_slice(&w.to_le_bytes());
    }
    v
  }

  #[test]
  fn decodes_7d_block_print() {
    let data = build();
    let em = parse(&data, ByteOrder::Little, true);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(
      find("AFMicroAdjMode"),
      Some(TagValue::Str("Disable".into()))
    );
    assert_eq!(find("AFMicroAdjValue"), Some(TagValue::I64(0)));
    assert_eq!(em.len(), 2);
  }

  #[test]
  fn numeric_mode_and_fractional_value() {
    let mut v = Vec::new();
    for w in [44i32, 2, 3, 10] {
      v.extend_from_slice(&w.to_le_bytes());
    }
    let em = parse(&v, ByteOrder::Little, false);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    // `-n` mode keeps the numeric mode.
    assert_eq!(find("AFMicroAdjMode"), Some(TagValue::I64(2)));
    // 3/10 = 0.3 (fractional ⇒ F64).
    assert_eq!(find("AFMicroAdjValue"), Some(TagValue::F64(0.3)));
  }
}
