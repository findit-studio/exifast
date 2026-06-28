// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Panasonic::FocusInfo` (`Panasonic.pm:2084-2109`).
//!
//! Leica type-5 FocusInfo, reached via the `%Panasonic::Leica5` tag `0x040a`
//! SubDirectory (`Panasonic.pm:2021-2024`). A `ProcessBinaryData` table with
//! `FORMAT => 'int16u'` (so each numeric key is multiplied by the int16u size 2
//! to get the byte offset), `TAG_PREFIX => 'Leica_FocusInfo'`, `FIRST_ENTRY =>
//! 0`. The emitted tags carry the family-1 group `Leica`.
//!
//! Positions (`Panasonic.pm:2093-2108`):
//!
//! - key 0 (byte 0) `FocusDistance`, `int16u` — `ValueConv => '$val / 1000'`,
//!   `PrintConv => '$val < 65535 ? "$val m" : "inf"'`. (The field is `int16u`,
//!   so `$val/1000 <= 65.535 < 65535`: the `inf` branch is unreachable, but it
//!   is kept faithfully.)
//! - key 1 (byte 2) `FocalLength`, `int16u` — `RawConv => '$val ? $val : undef'`
//!   (drop a zero raw), `ValueConv => '$val / 1000'`, `PrintConv =>
//!   'sprintf("%.1f mm",$val)'`.
//!
//! `-n` carries the ValueConv number (`$val / 1000`); `-j` the PrintConv string.
//!
//! D8: a pure decoder (no public fields); returns the `(Name, TagValue)`
//! emission pairs the dispatch site wraps in the `Leica` family-1 group.

#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::{ByteOrder, get_u16};
use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

/// Decode the `Panasonic::FocusInfo` binary block (`Panasonic.pm:2084-2109`)
/// into the `(Name, TagValue)` emission pairs.
///
/// `data` is the raw `$$valPt` block; `order` the inherited parent Leica byte
/// order. Per-field availability: each position is emitted only when its int16u
/// is in range (FocalLength additionally drops a zero raw via its `RawConv`).
#[must_use]
pub fn parse(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  // key 0 (byte 0) FocusDistance int16u.
  if let Some(raw) = get_u16(data, 0, order) {
    let v = f64::from(raw) / 1000.0;
    let value = if print_conv {
      // PrintConv: `$val < 65535 ? "$val m" : "inf"`.
      if v < 65535.0 {
        TagValue::Str(SmolStr::from(std::format!("{} m", fmt_milli(v))))
      } else {
        TagValue::Str(SmolStr::new_static("inf"))
      }
    } else {
      TagValue::F64(v)
    };
    out.push((SmolStr::new_static("FocusDistance"), value));
  }
  // key 1 (byte 2) FocalLength int16u — RawConv drops a zero raw.
  if let Some(raw) = get_u16(data, 2, order) {
    // `RawConv => '$val ? $val : undef'`.
    if raw != 0 {
      let v = f64::from(raw) / 1000.0;
      let value = if print_conv {
        TagValue::Str(SmolStr::from(std::format!("{v:.1} mm")))
      } else {
        TagValue::F64(v)
      };
      out.push((SmolStr::new_static("FocalLength"), value));
    }
  }
  out
}

/// Format `value / 1000` the way Perl stringifies it for the `"$val m"`
/// interpolation — up to three fractional digits (a `k/1000` value is exact to
/// three decimals) with trailing zeros (and a bare dot) stripped (`%g`-style).
fn fmt_milli(v: f64) -> String {
  let s = std::format!("{v:.3}");
  if s.contains('.') {
    s.trim_end_matches('0').trim_end_matches('.').to_string()
  } else {
    s
  }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  fn find(em: &[(SmolStr, TagValue)], name: &str) -> Option<TagValue> {
    em.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
  }

  /// FocusDistance + FocalLength. Oracle: FocusDistance raw 5500 ⇒ ValueConv 5.5
  /// ⇒ `"5.5 m"` (`-j`) / `5.5` (`-n`); FocalLength raw 50000 ⇒ 50 ⇒ `"50.0 mm"`
  /// (`-j`, fixed 1 decimal) / `50` (`-n`).
  #[test]
  fn distance_and_length() {
    let mut blob = Vec::new();
    blob.extend_from_slice(&5500u16.to_le_bytes());
    blob.extend_from_slice(&50000u16.to_le_bytes());
    let j = parse(&blob, ByteOrder::Little, true);
    assert_eq!(
      find(&j, "FocusDistance"),
      Some(TagValue::Str("5.5 m".into()))
    );
    assert_eq!(
      find(&j, "FocalLength"),
      Some(TagValue::Str("50.0 mm".into()))
    );
    let n = parse(&blob, ByteOrder::Little, false);
    assert_eq!(find(&n, "FocusDistance"), Some(TagValue::F64(5.5)));
    assert_eq!(find(&n, "FocalLength"), Some(TagValue::F64(50.0)));
  }

  /// A whole-metre FocusDistance strips trailing zeros in the `"$val m"` form
  /// (Perl `%g`): raw 5000 ⇒ 5 ⇒ `"5 m"` (not `"5.000 m"`).
  #[test]
  fn focus_distance_strips_trailing_zeros() {
    let blob = 5000u16.to_le_bytes();
    assert_eq!(
      find(&parse(&blob, ByteOrder::Little, true), "FocusDistance"),
      Some(TagValue::Str("5 m".into()))
    );
  }

  /// FocalLength `RawConv => '$val ? $val : undef'` drops a zero raw (FocusDistance,
  /// which has no such RawConv, still emits `"0 m"`).
  #[test]
  fn focal_length_zero_dropped() {
    let mut blob = Vec::new();
    blob.extend_from_slice(&0u16.to_le_bytes()); // FocusDistance 0
    blob.extend_from_slice(&0u16.to_le_bytes()); // FocalLength 0 ⇒ dropped
    let em = parse(&blob, ByteOrder::Little, true);
    assert_eq!(
      find(&em, "FocusDistance"),
      Some(TagValue::Str("0 m".into()))
    );
    assert_eq!(find(&em, "FocalLength"), None);
  }

  /// Per-field availability: a block holding only FocusDistance omits FocalLength.
  #[test]
  fn only_focus_distance_present() {
    let em = parse(&1500u16.to_le_bytes(), ByteOrder::Little, true);
    assert_eq!(
      find(&em, "FocusDistance"),
      Some(TagValue::Str("1.5 m".into()))
    );
    assert_eq!(find(&em, "FocalLength"), None);
    assert!(parse(&[], ByteOrder::Little, true).is_empty());
  }
}
