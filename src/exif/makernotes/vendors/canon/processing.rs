// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Canon::Processing` (`Canon.pm:7203-7265`).
//!
//! Binary-data sub-table — `FORMAT => 'int16s'`, `FIRST_ENTRY => 1`,
//! `GROUPS => { 0 => 'MakerNotes', 2 => 'Image' }`. Reached via the
//! `Canon::Main` tag `0xa0` SubDirectory (`Canon.pm:1895-1901`).
//!
//! Named positions (`int16s` ⇒ byte offset `2 * position`):
//! 1 `ToneCurve` (PrintConv), 2 `Sharpness` (Condition: Model not 20D/350D),
//! 3 `SharpnessFrequency` (PrintConv), 4 `SensorRedLevel`, 5 `SensorBlueLevel`,
//! 6 `WhiteBalanceRed`, 7 `WhiteBalanceBlue`, 8 `WhiteBalance`
//! (RawConv drops a negative, `%canonWhiteBalance`), 9 `ColorTemperature`,
//! 10 `PictureStyle` (PrintHex, `%pictureStyles`), 11 `DigitalGain`
//! (ValueConv `$val/10`), 12 `WBShiftAB`, 13 `WBShiftGM`,
//! 14 `UnsharpMaskFineness`, 15 `UnsharpMaskThreshold`.
//!
//! D8: pure decoder (no public struct fields); returns the `(Name, TagValue)`
//! emission pairs the dispatch site wraps in the `Canon` family-1 group.

#![deny(clippy::indexing_slicing)]

use super::printconv::picture_style_label;
use super::shot_info::white_balance_label;
use crate::exif::ifd::ByteOrder;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

/// Decode the `Canon::Processing` binary block (`Canon.pm:7203-7265`). `model`
/// keys the position-2 `Sharpness` Condition; `print_conv` selects the PrintConv
/// vs ValueConv view. A position past the end of `data` is skipped.
#[must_use]
pub fn parse(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let read = |pos: usize| read_i16(data, pos, order);

  // 1 — ToneCurve (PrintConv 0/1/2).
  if let Some(v) = read(1) {
    out.push((
      "ToneCurve".into(),
      enum_value(v, print_conv, tone_curve_label),
    ));
  }
  // 2 — Sharpness (`Condition`: Model is NOT a 20D/350D, `Canon.pm:7219`). Plain.
  if !model_is_20d_350d(model)
    && let Some(v) = read(2)
  {
    out.push(("Sharpness".into(), TagValue::I64(v)));
  }
  // 3 — SharpnessFrequency (PrintConv 0..5).
  if let Some(v) = read(3) {
    out.push((
      "SharpnessFrequency".into(),
      enum_value(v, print_conv, sharpness_freq_label),
    ));
  }
  // 4/5/6/7 — plain levels.
  for (pos, name) in [
    (4usize, "SensorRedLevel"),
    (5, "SensorBlueLevel"),
    (6, "WhiteBalanceRed"),
    (7, "WhiteBalanceBlue"),
  ] {
    if let Some(v) = read(pos) {
      out.push((SmolStr::new_static(name), TagValue::I64(v)));
    }
  }
  // 8 — WhiteBalance (`RawConv => '$val < 0 ? undef : $val'`, `%canonWhiteBalance`).
  if let Some(v) = read(8)
    && v >= 0
  {
    out.push((
      "WhiteBalance".into(),
      if print_conv {
        hash_value(v, white_balance_label(v))
      } else {
        TagValue::I64(v)
      },
    ));
  }
  // 9 — ColorTemperature (plain).
  if let Some(v) = read(9) {
    out.push(("ColorTemperature".into(), TagValue::I64(v)));
  }
  // 10 — PictureStyle (PrintHex, `%pictureStyles`).
  if let Some(v) = read(10) {
    out.push((
      "PictureStyle".into(),
      if print_conv {
        match picture_style_label(v) {
          Some(l) => TagValue::Str(SmolStr::new_static(l)),
          None => TagValue::Str(SmolStr::from(std::format!("Unknown (0x{v:x})"))),
        }
      } else {
        TagValue::I64(v)
      },
    ));
  }
  // 11 — DigitalGain (`ValueConv => '$val / 10'`; no PrintConv ⇒ `-j` == `-n`).
  if let Some(v) = read(11) {
    out.push(("DigitalGain".into(), num_value(v as f64 / 10.0)));
  }
  // 12/13/14/15 — plain.
  for (pos, name) in [
    (12usize, "WBShiftAB"),
    (13, "WBShiftGM"),
    (14, "UnsharpMaskFineness"),
    (15, "UnsharpMaskThreshold"),
  ] {
    if let Some(v) = read(pos) {
      out.push((SmolStr::new_static(name), TagValue::I64(v)));
    }
  }
  out
}

/// `ToneCurve` PrintConv (`Canon.pm:7210-7214`).
fn tone_curve_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Standard",
    1 => "Manual",
    2 => "Custom",
    _ => return None,
  })
}

/// `SharpnessFrequency` PrintConv (`Canon.pm:7225-7232`).
fn sharpness_freq_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "n/a",
    1 => "Lowest",
    2 => "Low",
    3 => "Standard",
    4 => "High",
    5 => "Highest",
    _ => return None,
  })
}

/// Render an enum PrintConv (label or `Unknown (N)`), or the raw int under `-n`.
fn enum_value(v: i64, print_conv: bool, label: fn(i64) -> Option<&'static str>) -> TagValue {
  if print_conv {
    hash_value(v, label(v))
  } else {
    TagValue::I64(v)
  }
}

/// A hash PrintConv result: the label, or the `Unknown (N)` fallback.
fn hash_value(v: i64, label: Option<&'static str>) -> TagValue {
  match label {
    Some(l) => TagValue::Str(SmolStr::new_static(l)),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
  }
}

/// ExifTool's whole-vs-fractional number formatting for a ValueConv float.
fn num_value(v: f64) -> TagValue {
  if v.fract() == 0.0 && v.is_finite() {
    TagValue::I64(v as i64)
  } else {
    TagValue::F64(v)
  }
}

/// Read one signed 16-bit word at word `position` (`FORMAT => 'int16s'`,
/// byte offset `2 * position`). `None` if past the end of `data`.
fn read_i16(data: &[u8], position: usize, order: ByteOrder) -> Option<i64> {
  let off = 2 * position;
  let arr: [u8; 2] = data.get(off..off + 2)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => i16::from_le_bytes(arr),
    ByteOrder::Big => i16::from_be_bytes(arr),
  } as i64)
}

/// `true` when `model` matches the position-2 `Sharpness` exclusion regex
/// `/\b(20D|350D|REBEL XT|Kiss Digital N)\b/` (`Canon.pm:7219`).
fn model_is_20d_350d(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  ["20D", "350D", "REBEL XT", "Kiss Digital N"]
    .iter()
    .any(|needle| word_bounded_contains(m, needle))
}

/// `true` when `needle` occurs in `hay` at `\b…\b` word boundaries (ASCII).
fn word_bounded_contains(hay: &str, needle: &str) -> bool {
  let hb = hay.as_bytes();
  let nb = needle.as_bytes();
  if nb.is_empty() || nb.len() > hb.len() {
    return false;
  }
  let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
  let mut i = 0;
  while i + nb.len() <= hb.len() {
    if hb.get(i..i + nb.len()) == Some(nb) {
      let before_ok = i == 0 || hb.get(i - 1).is_none_or(|&c| !is_word(c));
      let after_ok = hb.get(i + nb.len()).is_none_or(|&c| !is_word(c));
      // `\b` requires a word char on the needle's edge AND a non-word neighbour.
      let n_starts_word = nb.first().is_some_and(|&c| is_word(c));
      let n_ends_word = nb.last().is_some_and(|&c| is_word(c));
      if (!n_starts_word || before_ok) && (!n_ends_word || after_ok) {
        return true;
      }
    }
    i += 1;
  }
  false
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  /// The real EOS 5D Processing block (`int16s`, word0 = unused length slot):
  /// ToneCurve 0, Sharpness 3, SharpnessFrequency 0, SensorRed/Blue 0,
  /// WhiteBalanceRed/Blue 0, WhiteBalance -1 (RawConv ⇒ dropped),
  /// ColorTemperature 5200, PictureStyle 0x81, DigitalGain 0, WBShift 0/0.
  fn build(words: &[i16]) -> Vec<u8> {
    let mut v = Vec::new();
    for w in words {
      v.extend_from_slice(&w.to_le_bytes());
    }
    v
  }

  #[test]
  fn decodes_5d_processing_print() {
    let words = [0i16, 0, 3, 0, 0, 0, 0, 0, -1, 5200, 0x81, 0, 0, 0];
    let data = build(&words);
    let em = parse(&data, ByteOrder::Little, true, Some("Canon EOS 5D"));
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ToneCurve"), Some(TagValue::Str("Standard".into())));
    assert_eq!(find("Sharpness"), Some(TagValue::I64(3)));
    assert_eq!(
      find("SharpnessFrequency"),
      Some(TagValue::Str("n/a".into()))
    );
    assert_eq!(find("SensorRedLevel"), Some(TagValue::I64(0)));
    // WhiteBalance = -1 ⇒ RawConv drops it.
    assert!(find("WhiteBalance").is_none());
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("PictureStyle"), Some(TagValue::Str("Standard".into())));
    assert_eq!(find("DigitalGain"), Some(TagValue::I64(0)));
    assert_eq!(find("WBShiftAB"), Some(TagValue::I64(0)));
  }

  #[test]
  fn sharpness_dropped_for_350d() {
    let words = [0i16, 0, 7, 0];
    let data = build(&words);
    let em = parse(&data, ByteOrder::Little, true, Some("Canon EOS 350D"));
    assert!(em.iter().all(|(k, _)| k != "Sharpness"));
    // 120D would NOT match \b350D\b style boundaries — sanity on the matcher.
    assert!(!model_is_20d_350d(Some("Canon EOS 1350D")));
    assert!(model_is_20d_350d(Some("Canon EOS 20D")));
    assert!(!model_is_20d_350d(Some("Canon EOS 5D")));
  }
}
