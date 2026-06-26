// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! The Canon image-correction sub-tables (`Canon::Main` tags `0x4015`-`0x4019`):
//! `%Canon::VignettingCorr` (`Canon.pm:8999-9034`), `%Canon::VignettingCorr2`
//! (`:9050-9071`), `%Canon::LightingOpt` (`:9074-9129`) and `%Canon::LensInfo`
//! (`:9132-9148`).
//!
//! All emit only the in-range leaves (per-field availability). `VignettingCorr`
//! (0x4015) is a conditional SubDirectory list — only the first arm
//! (`$$valPt =~ /^\0/` and not all-zero / not the `\x00\x40\xdc\x05` Powershot
//! prefix) is the real table; both it and `VignettingCorr2` (0x4016) carry a
//! `Canon::Validate` size-word gate.
//!
//! D8: pure decoders — return the `(Name, TagValue)` emission pairs the dispatch
//! site wraps in the `Canon` family-1 group.

#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::ByteOrder;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::string::String;
use std::vec::Vec;

/// Decode `%Canon::VignettingCorr` (0x4015, arm 1) from the `undef[N]` blob
/// (`FORMAT => 'int16s'`). Gated by the conditional-list arm-1 condition and the
/// `Validate($dirData, $start+2, $size)` size-word check; a miss emits nothing.
#[must_use]
pub fn parse_vignetting(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
) -> Vec<(SmolStr, TagValue)> {
  if !vignetting_corr_condition(data) || !validate(data, 2, order) {
    return Vec::new();
  }
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  // 0 VignettingCorrVersion (Format int8u override) @ byte 0.
  if let Some(&b) = data.first() {
    out.push((
      SmolStr::new_static("VignettingCorrVersion"),
      TagValue::I64(i64::from(b)),
    ));
  }
  // int16s leaves at byte offset = index * 2.
  for &(idx, name, off_on) in &[
    (2usize, "PeripheralLighting", true),
    (3, "DistortionCorrection", true),
    (4, "ChromaticAberrationCorr", true),
    (5, "ChromaticAberrationCorr", true),
    (6, "PeripheralLightingValue", false),
    (9, "DistortionCorrectionValue", false),
    (11, "OriginalImageWidth", false),
    (12, "OriginalImageHeight", false),
  ] {
    if let Some(v) = i16s(data, idx * 2, order) {
      out.push((
        SmolStr::new_static(name),
        scalar_or_off_on(v, print_conv, off_on),
      ));
    }
  }
  out
}

/// Decode `%Canon::VignettingCorr2` (0x4016) from the int32s blob. Gated by
/// `Validate($dirData, $start, $size)`.
#[must_use]
pub fn parse_vignetting2(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
) -> Vec<(SmolStr, TagValue)> {
  if !validate(data, 0, order) {
    return Vec::new();
  }
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  // int32s leaves at byte offset = index * 4.
  for &(idx, name) in &[
    (5usize, "PeripheralLightingSetting"),
    (6, "ChromaticAberrationSetting"),
    (7, "DistortionCorrectionSetting"),
    (9, "DigitalLensOptimizerSetting"),
  ] {
    if let Some(v) = i32s(data, idx * 4, order) {
      out.push((SmolStr::new_static(name), off_on_value(v, print_conv)));
    }
  }
  out
}

/// Decode `%Canon::LightingOpt` (0x4018) from the int32s blob.
#[must_use]
pub fn parse_lighting_opt(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  // 1 PeripheralIlluminationCorr @ 4 (%offOn).
  if let Some(v) = i32s(data, 4, order) {
    out.push((
      SmolStr::new_static("PeripheralIlluminationCorr"),
      off_on_value(v, print_conv),
    ));
  }
  // 2 AutoLightingOptimizer @ 8.
  if let Some(v) = i32s(data, 8, order) {
    out.push((
      SmolStr::new_static("AutoLightingOptimizer"),
      hash(v, print_conv, auto_lighting_optimizer_label),
    ));
  }
  // 3 HighlightTonePriority @ 12 ({%offOn, 2 => 'Enhanced'}).
  if let Some(v) = i32s(data, 12, order) {
    out.push((
      SmolStr::new_static("HighlightTonePriority"),
      hash(v, print_conv, highlight_tone_priority_label),
    ));
  }
  // 4 LongExposureNoiseReduction @ 16.
  if let Some(v) = i32s(data, 16, order) {
    out.push((
      SmolStr::new_static("LongExposureNoiseReduction"),
      hash(v, print_conv, long_exposure_nr_label),
    ));
  }
  // 5 HighISONoiseReduction @ 20.
  if let Some(v) = i32s(data, 20, order) {
    out.push((
      SmolStr::new_static("HighISONoiseReduction"),
      hash(v, print_conv, high_iso_nr_label),
    ));
  }
  // 10 DigitalLensOptimizer @ 40 (`Canon.pm:9117-9123`, forum14286).
  if let Some(v) = i32s(data, 40, order) {
    out.push((
      SmolStr::new_static("DigitalLensOptimizer"),
      hash(v, print_conv, digital_lens_optimizer_label),
    ));
  }
  // 11 DualPixelRaw @ 44 (`Canon.pm:9125-9128`, forum15445, `%offOn`).
  if let Some(v) = i32s(data, 44, order) {
    out.push((
      SmolStr::new_static("DualPixelRaw"),
      hash(v, print_conv, off_on_label),
    ));
  }
  out
}

/// `DigitalLensOptimizer` PrintConv (`Canon.pm:9119-9122`).
fn digital_lens_optimizer_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    1 => "Standard",
    2 => "High",
    _ => return None,
  })
}

/// Decode `%Canon::LensInfo` (0x4019) from the `undef[N]` blob.
#[must_use]
pub fn parse_lens_info(
  data: &[u8],
  _order: ByteOrder,
  _print_conv: bool,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  // 0 LensSerialNumber (Format undef[5], Priority 0): RawConv drops a value
  // starting with four NUL bytes; ValueConv `unpack("H*", $val)` ⇒ lowercase hex.
  if let Some(bytes) = data.get(0..5)
    && bytes.get(0..4) != Some(&[0, 0, 0, 0])
  {
    let hex: String = bytes.iter().map(|b| std::format!("{b:02x}")).collect();
    out.push((
      SmolStr::new_static("LensSerialNumber"),
      TagValue::Str(SmolStr::from(hex)),
    ));
  }
  out
}

/// `%Canon::VignettingCorr` 0x4015 conditional-list arm-1 condition
/// (`Canon.pm:9001`): first byte `\0`, and not all-zero / not the
/// `\x00\x40\xdc\x05` (60D-style) prefix.
fn vignetting_corr_condition(b: &[u8]) -> bool {
  b.first() == Some(&0)
    && b.get(0..4) != Some(&[0, 0, 0, 0])
    && b.get(0..4) != Some(&[0x00, 0x40, 0xdc, 0x05])
}

/// `Image::ExifTool::Canon::Validate($dataPt, $offset, $size)`
/// (`Canon.pm:Validate`): the 16-bit word at `off` must equal the blob length.
fn validate(data: &[u8], off: usize, order: ByteOrder) -> bool {
  matches!(u16(data, off, order), Some(v) if v == data.len() as i64)
}

/// `%offOn` (`Canon.pm:1218`).
fn off_on_value(v: i64, print_conv: bool) -> TagValue {
  hash(v, print_conv, off_on_label)
}

/// A plain int16s leaf, OR a `%offOn` leaf when `off_on`.
fn scalar_or_off_on(v: i64, print_conv: bool, off_on: bool) -> TagValue {
  if off_on {
    off_on_value(v, print_conv)
  } else {
    TagValue::I64(v)
  }
}

fn off_on_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    1 => "On",
    _ => return None,
  })
}

/// `AutoLightingOptimizer` PrintConv (`Canon.pm:9086-9091`).
fn auto_lighting_optimizer_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Standard",
    1 => "Low",
    2 => "Strong",
    3 => "Off",
    _ => return None,
  })
}

/// `HighlightTonePriority` PrintConv (`Canon.pm:9095`, `{%offOn, 2 => 'Enhanced'}`).
fn highlight_tone_priority_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    1 => "On",
    2 => "Enhanced",
    _ => return None,
  })
}

/// `LongExposureNoiseReduction` PrintConv (`Canon.pm:9099-9103`).
fn long_exposure_nr_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    1 => "Auto",
    2 => "On",
    _ => return None,
  })
}

/// `HighISONoiseReduction` PrintConv (`Canon.pm:9107-9112`).
fn high_iso_nr_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Standard",
    1 => "Low",
    2 => "Strong",
    3 => "Off",
    _ => return None,
  })
}

/// Render a hash PrintConv: the label, or `Unknown (N)`; raw int under `-n`.
fn hash(v: i64, print_conv: bool, label: fn(i64) -> Option<&'static str>) -> TagValue {
  if !print_conv {
    return TagValue::I64(v);
  }
  match label(v) {
    Some(l) => TagValue::Str(SmolStr::new_static(l)),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
  }
}

/// Read one signed 16-bit word at byte `off`.
fn i16s(data: &[u8], off: usize, order: ByteOrder) -> Option<i64> {
  let arr: [u8; 2] = data.get(off..off + 2)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => i16::from_le_bytes(arr),
    ByteOrder::Big => i16::from_be_bytes(arr),
  } as i64)
}

/// Read one unsigned 16-bit word at byte `off`.
fn u16(data: &[u8], off: usize, order: ByteOrder) -> Option<i64> {
  let arr: [u8; 2] = data.get(off..off + 2)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u16::from_le_bytes(arr),
    ByteOrder::Big => u16::from_be_bytes(arr),
  } as i64)
}

/// Read one signed 32-bit word at byte `off`.
fn i32s(data: &[u8], off: usize, order: ByteOrder) -> Option<i64> {
  let arr: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => i32::from_le_bytes(arr),
    ByteOrder::Big => i32::from_be_bytes(arr),
  } as i64)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  #[test]
  fn vignetting_corr_7d() {
    let mut b = vec![0u8; 116];
    b[2] = 116; // size word (LE) == len ⇒ Validate passes
    b[22] = 0x40; // OriginalImageWidth int16s LE 0x1440 = 5184
    b[23] = 0x14;
    b[24] = 0x80; // OriginalImageHeight 0x0d80 = 3456
    b[25] = 0x0d;
    let em = parse_vignetting(&b, ByteOrder::Little, true);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("VignettingCorrVersion"), Some(TagValue::I64(0)));
    assert_eq!(
      find("PeripheralLighting"),
      Some(TagValue::Str("Off".into()))
    );
    assert_eq!(find("OriginalImageWidth"), Some(TagValue::I64(5184)));
    assert_eq!(find("OriginalImageHeight"), Some(TagValue::I64(3456)));
  }

  #[test]
  fn vignetting_corr_validate_fails() {
    let b = vec![0u8; 116]; // size word == 0 != 116 ⇒ Validate fails (also first4 all-zero)
    assert!(parse_vignetting(&b, ByteOrder::Little, true).is_empty());
  }

  #[test]
  fn vignetting2_per_field() {
    let mut b = vec![0u8; 28];
    b[0] = 28; // size word == len
    let em = parse_vignetting2(&b, ByteOrder::Little, true);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    // entries 5/6 in range; 7 (@28) and 9 (@36) out of the 28-byte block.
    assert_eq!(
      find("PeripheralLightingSetting"),
      Some(TagValue::Str("Off".into()))
    );
    assert_eq!(
      find("ChromaticAberrationSetting"),
      Some(TagValue::Str("Off".into()))
    );
    assert!(find("DistortionCorrectionSetting").is_none());
    assert!(find("DigitalLensOptimizerSetting").is_none());
  }

  #[test]
  fn lighting_opt_7d() {
    let mut b = vec![0u8; 28];
    b[4] = 1; // PeripheralIlluminationCorr = On
    b[8] = 3; // AutoLightingOptimizer = Off
    let em = parse_lighting_opt(&b, ByteOrder::Little, true);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(
      find("PeripheralIlluminationCorr"),
      Some(TagValue::Str("On".into()))
    );
    assert_eq!(
      find("AutoLightingOptimizer"),
      Some(TagValue::Str("Off".into()))
    );
    assert_eq!(
      find("HighISONoiseReduction"),
      Some(TagValue::Str("Standard".into()))
    );
  }

  #[test]
  fn lens_info_hex_serial() {
    let b = [0x00, 0x00, 0x14, 0x69, 0xa3, 0, 0, 0];
    let em = parse_lens_info(&b, ByteOrder::Little, true);
    assert_eq!(
      em.first().map(|(_, v)| v.clone()),
      Some(TagValue::Str("00001469a3".into()))
    );
  }

  #[test]
  fn lens_info_all_zero_dropped() {
    let b = [0u8; 8];
    assert!(parse_lens_info(&b, ByteOrder::Little, true).is_empty());
  }
}
