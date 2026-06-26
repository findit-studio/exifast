// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::CameraSettings` (`Sony.pm:4221-4716`) — the `0x0114`
//! Main-table SubDirectory dispatched when `$count == 280 || 364`
//! (`Sony.pm:805-811`), camera settings for the A200/A300/A350/A700/A850/A900.
//!
//! `FORMAT => 'int16u'`, `ByteOrder => 'BigEndian'`, `PRIORITY => 0`. UNLIKE the
//! `int8u`/LittleEndian `CameraSettings3`, every tag index here is a BIG-ENDIAN
//! `int16u` at byte `index * 2`, so reads use [`read_u16_be`]. Every leaf is a
//! `Priority => 0` duplicate: a higher-priority Main-IFD leaf of the same name
//! (`0x0102 Quality`, `0x0115 WhiteBalance`) is NOT overridden, and a settings
//! leaf shared with the earlier `FocusInfo` (`0x0020`) block keeps the
//! FocusInfo copy (priority-0 first-wins).
//!
//! Per the `ProcessBinaryData` per-field-availability contract a leaf is emitted
//! IFF its `int16u` byte range is in the block
//! ([[exifast-processbinarydata-per-field]]) — so the 280-byte A200/A300/A350
//! block omits `0x9a`/`0x9b` `FolderNumber`/`ImageNumber` (byte 308+, only in
//! the 364-byte A850/A900 block).

use crate::exif::tables::{print_exposure_time, print_fnumber};
use crate::value::TagValue;
use smol_str::SmolStr;

use super::subtables::{
  SubEmission, creative_style, drive_mode_a200, dro_mode, exposure_program, hash_hex_value,
};

/// Read a BIG-endian `int16u` at field index `idx` (byte `idx * 2`); `None` when
/// out of range (the per-field availability contract).
fn read_u16_be(buf: &[u8], idx: usize) -> Option<u16> {
  let off = idx.checked_mul(2)?;
  match buf.get(off..off + 2) {
    Some(&[a, b]) => Some(u16::from_be_bytes([a, b])),
    _ => None,
  }
}

/// Push a simple `int16u` hash-PrintConv leaf at field `idx`.
fn push_hash(
  buf: &[u8],
  idx: usize,
  name: &'static str,
  hit: impl Fn(u16) -> Option<&'static str>,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  if let Some(raw) = read_u16_be(buf, idx) {
    out.push(SubEmission::new(name, hash_u16(raw, hit(raw), print_conv)));
  }
}

/// Render an `int16u` hash-PrintConv leaf (`-j` label / `Unknown ($val)`, `-n`
/// raw int) — the `int16u` analogue of [`super::hash_print_value`].
fn hash_u16(raw: u16, hit: Option<&'static str>, print_conv: bool) -> TagValue {
  match (print_conv, hit) {
    (true, Some(s)) => TagValue::Str(SmolStr::new(s)),
    (true, None) => TagValue::Str(SmolStr::new(std::format!("Unknown ({raw})"))),
    (false, _) => TagValue::I64(i64::from(raw)),
  }
}

/// `$val ? 2**(6 - $val/8) : 0` shutter-time form (`ExposureTime` 0x00 /
/// `ShutterSpeedSetting` 0x2f): `-j` `PrintExposureTime`/`"Bulb"`, `-n` the bare
/// seconds float.
fn shutter_time(raw: u16, print_conv: bool, name: &'static str, out: &mut Vec<SubEmission>) {
  let secs = if raw != 0 {
    2f64.powf(6.0 - f64::from(raw) / 8.0)
  } else {
    0.0
  };
  let value = if print_conv {
    if raw != 0 {
      TagValue::Str(print_exposure_time(secs).into())
    } else {
      TagValue::Str("Bulb".into())
    }
  } else {
    crate::value::whole_f64_to_tag_value(secs)
  };
  out.push(SubEmission::new(name, value));
}

/// `2**(($val/8 - 1)/2)` aperture form (`FNumber` 0x01 / `ApertureSetting`
/// 0x30): `-j` `PrintFNumber`, `-n` the bare f-number float.
fn fnumber(raw: u16, print_conv: bool, name: &'static str, out: &mut Vec<SubEmission>) {
  let fnum = 2f64.powf((f64::from(raw) / 8.0 - 1.0) / 2.0);
  let value = if print_conv {
    TagValue::Str(print_fnumber(fnum).into())
  } else {
    crate::value::whole_f64_to_tag_value(fnum)
  };
  out.push(SubEmission::new(name, value));
}

/// `($val - 128) / 24` exposure-comp form (`ExposureCompensationSet` 0x03 /
/// `FlashExposureCompSet` 0x14): `-j` `$val ? sprintf("%+.1f") : 0`, `-n` the
/// bare float (a zero renders as the integer `0`).
fn exposure_comp(raw: u16, print_conv: bool, name: &'static str, out: &mut Vec<SubEmission>) {
  let val = (f64::from(raw) - 128.0) / 24.0;
  let value = if print_conv {
    if val == 0.0 {
      TagValue::I64(0)
    } else {
      TagValue::Str(SmolStr::new(std::format!("{val:+.1}")))
    }
  } else {
    crate::value::whole_f64_to_tag_value(val)
  };
  out.push(SubEmission::new(name, value));
}

/// `$val * 100`, `"$val K"` colour-temperature form (`ColorTemperatureSet` 0x07 /
/// `ColorTemperatureCustom` 0x0c).
fn color_temp(raw: u16, print_conv: bool, name: &'static str, out: &mut Vec<SubEmission>) {
  let k = u32::from(raw) * 100;
  let value = if print_conv {
    TagValue::Str(SmolStr::new(std::format!("{k} K")))
  } else {
    TagValue::I64(i64::from(k))
  };
  out.push(SubEmission::new(name, value));
}

/// `$val > 128 ? $val - 256 : $val` signed wrap (`WhiteBalanceFineTune` 0x06,
/// NO PrintConv — both modes emit the signed integer).
fn wb_fine_tune(raw: u16, out: &mut Vec<SubEmission>) {
  let v = if raw > 128 {
    i64::from(raw) - 256
  } else {
    i64::from(raw)
  };
  out.push(SubEmission::new("WhiteBalanceFineTune", TagValue::I64(v)));
}

/// `$val > 128 ? $val - 256 : $val`, `$val > 0 ? "+$val" : $val`
/// (`ColorCompensationFilterSet` 0x08 / `ColorCompensationFilterCustom` 0x0d):
/// `-n` the signed integer, `-j` the `+`-prefixed string for a positive value.
fn color_comp_filter(raw: u16, print_conv: bool, name: &'static str, out: &mut Vec<SubEmission>) {
  let v = if raw > 128 {
    i64::from(raw) - 256
  } else {
    i64::from(raw)
  };
  out.push(SubEmission::new(name, signed_plus(v, print_conv)));
}

/// `$val - 10`, `$val > 0 ? "+$val" : $val` setting form (`Sharpness` 0x1c /
/// `Contrast` 0x1d / `Saturation` 0x1e / `ZoneMatchingValue` 0x1f / `Brightness`
/// 0x22): `-n` the signed integer, `-j` the `+`-prefixed string for positive.
fn setting_minus10(raw: u16, print_conv: bool, name: &'static str, out: &mut Vec<SubEmission>) {
  let v = i64::from(raw) - 10;
  out.push(SubEmission::new(name, signed_plus(v, print_conv)));
}

/// Render `$val > 0 ? "+$val" : $val`: `-n` the signed integer, `-j` the
/// `+`-prefixed string for a positive value (else the integer).
fn signed_plus(v: i64, print_conv: bool) -> TagValue {
  if print_conv && v > 0 {
    TagValue::Str(SmolStr::new(std::format!("+{v}")))
  } else {
    TagValue::I64(v)
  }
}

/// `FocusStatus` (0x53) value (`Sony.pm:4694-4708`): literals `0 => 'Not
/// confirmed'`, `4 => 'Not confirmed, Tracking'`, else a `DecodeBits` over
/// `{0 => Confirmed, 1 => Failed, 2 => Tracking}`. `-n` is the raw integer.
fn focus_status(raw: u16, print_conv: bool) -> TagValue {
  if !print_conv {
    return TagValue::I64(i64::from(raw));
  }
  let s = match raw {
    0 => "Not confirmed".to_string(),
    4 => "Not confirmed, Tracking".to_string(),
    _ => decode_focus_bits(raw),
  };
  TagValue::Str(SmolStr::new(s))
}

/// `DecodeBits($val, {0 => Confirmed, 1 => Failed, 2 => Tracking})`
/// (`ExifTool.pm` DecodeBits): each set bit renders its label (or `[n]`),
/// joined `", "`; no set bit ⇒ `"(none)"`.
fn decode_focus_bits(raw: u16) -> String {
  let mut parts: Vec<String> = std::vec::Vec::new();
  for bit in 0..16u32 {
    if raw & (1 << bit) != 0 {
      let label = match bit {
        0 => "Confirmed".to_string(),
        1 => "Failed".to_string(),
        2 => "Tracking".to_string(),
        n => std::format!("[{n}]"),
      };
      parts.push(label);
    }
  }
  if parts.is_empty() {
    "(none)".to_string()
  } else {
    parts.join(", ")
  }
}

/// A masked count (`FolderNumber` mask 0x03ff / `ImageNumber` mask 0x3fff):
/// `sprintf("%.Nd", $val)` in `-j`; the raw masked integer in `-n`.
fn masked_count(
  raw: u16,
  mask: u16,
  width: usize,
  print_conv: bool,
  name: &'static str,
  out: &mut Vec<SubEmission>,
) {
  let v = u32::from(raw & mask);
  let value = if print_conv {
    TagValue::Str(SmolStr::new(std::format!("{v:0width$}")))
  } else {
    TagValue::I64(i64::from(v))
  };
  out.push(SubEmission::new(name, value));
}

/// `HighSpeedSync` (0x02) / `AFIlluminator` (0x29) / etc. — simple `int16u`
/// hashes inlined as PrintConv closures below.
#[must_use]
pub fn parse_camera_settings(buf: &[u8], print_conv: bool) -> Vec<SubEmission> {
  let mut out = std::vec::Vec::new();

  if let Some(raw) = read_u16_be(buf, 0x00) {
    shutter_time(raw, print_conv, "ExposureTime", &mut out);
  }
  if let Some(raw) = read_u16_be(buf, 0x01) {
    fnumber(raw, print_conv, "FNumber", &mut out);
  }
  push_hash(buf, 0x02, "HighSpeedSync", off_on, print_conv, &mut out);
  if let Some(raw) = read_u16_be(buf, 0x03) {
    exposure_comp(raw, print_conv, "ExposureCompensationSet", &mut out);
  }
  // 0x04 DriveMode — Mask 0xff, PrintHex (Sony.pm:4256-4274).
  if let Some(raw) = read_u16_be(buf, 0x04) {
    let masked = u32::from(raw & 0xff);
    out.push(SubEmission::new(
      "DriveMode",
      hash_hex_value(masked, drive_mode_a200(masked), print_conv),
    ));
  }
  push_hash(
    buf,
    0x05,
    "WhiteBalanceSetting",
    white_balance_setting,
    print_conv,
    &mut out,
  );
  if let Some(raw) = read_u16_be(buf, 0x06) {
    wb_fine_tune(raw, &mut out);
  }
  if let Some(raw) = read_u16_be(buf, 0x07) {
    color_temp(raw, print_conv, "ColorTemperatureSet", &mut out);
  }
  if let Some(raw) = read_u16_be(buf, 0x08) {
    color_comp_filter(raw, print_conv, "ColorCompensationFilterSet", &mut out);
  }
  if let Some(raw) = read_u16_be(buf, 0x0c) {
    color_temp(raw, print_conv, "ColorTemperatureCustom", &mut out);
  }
  if let Some(raw) = read_u16_be(buf, 0x0d) {
    color_comp_filter(raw, print_conv, "ColorCompensationFilterCustom", &mut out);
  }
  push_hash(
    buf,
    0x0f,
    "WhiteBalance",
    white_balance,
    print_conv,
    &mut out,
  );
  push_hash(
    buf,
    0x10,
    "FocusModeSetting",
    focus_mode_setting,
    print_conv,
    &mut out,
  );
  push_hash(buf, 0x11, "AFAreaMode", af_area_mode, print_conv, &mut out);
  push_hash(
    buf,
    0x12,
    "AFPointSetting",
    af_point_setting,
    print_conv,
    &mut out,
  );
  push_hash(buf, 0x13, "FlashMode", flash_mode, print_conv, &mut out);
  if let Some(raw) = read_u16_be(buf, 0x14) {
    exposure_comp(raw, print_conv, "FlashExposureCompSet", &mut out);
  }
  push_hash(
    buf,
    0x15,
    "MeteringMode",
    metering_mode,
    print_conv,
    &mut out,
  );
  if let Some(raw) = read_u16_be(buf, 0x16) {
    out.push(SubEmission::new("ISOSetting", iso_value(raw, print_conv)));
  }
  push_hash(
    buf,
    0x18,
    "DynamicRangeOptimizerMode",
    dro_mode_u16,
    print_conv,
    &mut out,
  );
  if let Some(raw) = read_u16_be(buf, 0x19) {
    out.push(SubEmission::new(
      "DynamicRangeOptimizerLevel",
      TagValue::I64(i64::from(raw)),
    ));
  }
  push_hash(
    buf,
    0x1a,
    "CreativeStyle",
    creative_style_u16,
    print_conv,
    &mut out,
  );
  push_hash(buf, 0x1b, "ColorSpace", color_space, print_conv, &mut out);
  for (idx, name) in [
    (0x1c, "Sharpness"),
    (0x1d, "Contrast"),
    (0x1e, "Saturation"),
    (0x1f, "ZoneMatchingValue"),
    (0x22, "Brightness"),
  ] {
    if let Some(raw) = read_u16_be(buf, idx) {
      setting_minus10(raw, print_conv, name, &mut out);
    }
  }
  push_hash(
    buf,
    0x23,
    "FlashControl",
    flash_control,
    print_conv,
    &mut out,
  );
  push_hash(
    buf,
    0x28,
    "PrioritySetupShutterRelease",
    priority_setup,
    print_conv,
    &mut out,
  );
  push_hash(
    buf,
    0x29,
    "AFIlluminator",
    af_illuminator,
    print_conv,
    &mut out,
  );
  push_hash(buf, 0x2a, "AFWithShutter", on_off, print_conv, &mut out);
  push_hash(
    buf,
    0x2b,
    "LongExposureNoiseReduction",
    off_on,
    print_conv,
    &mut out,
  );
  push_hash(
    buf,
    0x2c,
    "HighISONoiseReduction",
    high_iso_nr,
    print_conv,
    &mut out,
  );
  push_hash(buf, 0x2d, "ImageStyle", image_style, print_conv, &mut out);
  push_hash(
    buf,
    0x2e,
    "FocusModeSwitch",
    af_manual,
    print_conv,
    &mut out,
  );
  if let Some(raw) = read_u16_be(buf, 0x2f) {
    shutter_time(raw, print_conv, "ShutterSpeedSetting", &mut out);
  }
  if let Some(raw) = read_u16_be(buf, 0x30) {
    fnumber(raw, print_conv, "ApertureSetting", &mut out);
  }
  push_hash(
    buf,
    0x3c,
    "ExposureProgram",
    exposure_program_u16,
    print_conv,
    &mut out,
  );
  push_hash(
    buf,
    0x3d,
    "ImageStabilizationSetting",
    off_on,
    print_conv,
    &mut out,
  );
  push_hash(buf, 0x3e, "FlashAction", flash_action, print_conv, &mut out);
  push_hash(buf, 0x3f, "Rotation", rotation, print_conv, &mut out);
  push_hash(buf, 0x40, "AELock", ae_lock, print_conv, &mut out);
  push_hash(
    buf,
    0x4c,
    "FlashAction2",
    flash_action2,
    print_conv,
    &mut out,
  );
  push_hash(buf, 0x4d, "FocusMode", focus_mode, print_conv, &mut out);
  push_hash(
    buf,
    0x50,
    "BatteryState",
    battery_state,
    print_conv,
    &mut out,
  );
  // 0x51 BatteryLevel — `"$val%"` (Sony.pm:4640).
  if let Some(raw) = read_u16_be(buf, 0x51) {
    let value = if print_conv {
      TagValue::Str(SmolStr::new(std::format!("{raw}%")))
    } else {
      TagValue::I64(i64::from(raw))
    };
    out.push(SubEmission::new("BatteryLevel", value));
  }
  if let Some(raw) = read_u16_be(buf, 0x53) {
    out.push(SubEmission::new(
      "FocusStatus",
      focus_status(raw, print_conv),
    ));
  }
  push_hash(
    buf,
    0x54,
    "SonyImageSize",
    sony_image_size,
    print_conv,
    &mut out,
  );
  push_hash(buf, 0x55, "AspectRatio", aspect_ratio, print_conv, &mut out);
  push_hash(buf, 0x56, "Quality", quality, print_conv, &mut out);
  push_hash(
    buf,
    0x58,
    "ExposureLevelIncrements",
    exposure_level_increments,
    print_conv,
    &mut out,
  );
  push_hash(buf, 0x6a, "RedEyeReduction", off_on, print_conv, &mut out);
  // 0x9a FolderNumber (mask 0x03ff) / 0x9b ImageNumber (mask 0x3fff) — only
  // in-range for the 364-byte A850/A900 block (Sony.pm:4711-4724).
  if let Some(raw) = read_u16_be(buf, 0x9a) {
    masked_count(raw, 0x03ff, 3, print_conv, "FolderNumber", &mut out);
  }
  if let Some(raw) = read_u16_be(buf, 0x9b) {
    masked_count(raw, 0x3fff, 4, print_conv, "ImageNumber", &mut out);
  }

  // `PRIORITY => 0` — every leaf here NEVER overrides an earlier same-name
  // duplicate (the Main-IFD `Quality`/`WhiteBalance`, the `FocusInfo` settings).
  for e in &mut out {
    e.priority = 0;
  }
  out
}

/// `ISOSetting` (0x16) value — exp ValueConv + `%.0f`/`"Auto"` (Sony.pm:4409).
fn iso_value(raw: u16, print_conv: bool) -> TagValue {
  if raw == 0 {
    return if print_conv {
      TagValue::Str("Auto".into())
    } else {
      TagValue::I64(0)
    };
  }
  let vc = ((f64::from(raw) / 8.0 - 6.0) * core::f64::consts::LN_2).exp() * 100.0;
  if print_conv {
    TagValue::I64((vc + 0.5) as i64)
  } else {
    crate::value::whole_f64_to_tag_value(vc)
  }
}

fn dro_mode_u16(v: u16) -> Option<&'static str> {
  u8::try_from(v).ok().and_then(dro_mode)
}
fn creative_style_u16(v: u16) -> Option<&'static str> {
  u8::try_from(v).ok().and_then(creative_style)
}
fn exposure_program_u16(v: u16) -> Option<&'static str> {
  u8::try_from(v).ok().and_then(exposure_program)
}

/// `0 => Off`, `1 => On`.
fn off_on(v: u16) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    1 => "On",
    _ => return None,
  })
}

/// `0 => On`, `1 => Off` (`AFWithShutter`).
fn on_off(v: u16) -> Option<&'static str> {
  Some(match v {
    0 => "On",
    1 => "Off",
    _ => return None,
  })
}

/// `WhiteBalanceSetting` (0x05) PrintConv (`Sony.pm:4278-4291`).
fn white_balance_setting(v: u16) -> Option<&'static str> {
  Some(match v {
    2 => "Auto",
    4 => "Daylight",
    5 => "Fluorescent",
    6 => "Tungsten",
    7 => "Flash",
    16 => "Cloudy",
    17 => "Shade",
    18 => "Color Temperature/Color Filter",
    32 => "Custom 1",
    33 => "Custom 2",
    34 => "Custom 3",
    _ => return None,
  })
}

/// `WhiteBalance` (0x0f) PrintConv (`Sony.pm:4334-4347`).
fn white_balance(v: u16) -> Option<&'static str> {
  Some(match v {
    2 => "Auto",
    4 => "Daylight",
    5 => "Fluorescent",
    6 => "Tungsten",
    7 => "Flash",
    12 => "Color Temperature",
    13 => "Color Filter",
    14 => "Custom",
    16 => "Cloudy",
    17 => "Shade",
    _ => return None,
  })
}

/// `FocusModeSetting` (0x10) / `FocusMode` (0x4d) PrintConv (`Sony.pm:4350`).
fn focus_mode_setting(v: u16) -> Option<&'static str> {
  Some(match v {
    0 => "Manual",
    1 => "AF-S",
    2 => "AF-C",
    3 => "AF-A",
    4 => "DMF",
    _ => return None,
  })
}
fn focus_mode(v: u16) -> Option<&'static str> {
  focus_mode_setting(v)
}

/// `AFAreaMode` (0x11) PrintConv (`Sony.pm:4360-4365`).
fn af_area_mode(v: u16) -> Option<&'static str> {
  Some(match v {
    0 => "Wide",
    1 => "Local",
    2 => "Spot",
    _ => return None,
  })
}

/// `AFPointSetting` (0x12) PrintConv (`Sony.pm:4377-4388`).
fn af_point_setting(v: u16) -> Option<&'static str> {
  Some(match v {
    1 => "Center",
    2 => "Top",
    3 => "Upper-right",
    4 => "Right",
    5 => "Lower-right",
    6 => "Bottom",
    7 => "Lower-left",
    8 => "Left",
    9 => "Upper-left",
    10 => "Far Right",
    11 => "Far Left",
    _ => return None,
  })
}

/// `FlashMode` (0x13) PrintConv (`Sony.pm:4392-4400`).
fn flash_mode(v: u16) -> Option<&'static str> {
  Some(match v {
    0 => "Autoflash",
    2 => "Rear Sync",
    3 => "Wireless",
    4 => "Fill-flash",
    5 => "Flash Off",
    6 => "Slow Sync",
    _ => return None,
  })
}

/// `MeteringMode` (0x15) PrintConv (`Sony.pm:4404-4407`) — note `4 => Spot`
/// (vs `CameraSettings3`'s `3 => Spot`).
fn metering_mode(v: u16) -> Option<&'static str> {
  Some(match v {
    1 => "Multi-segment",
    2 => "Center-weighted average",
    4 => "Spot",
    _ => return None,
  })
}

/// `ColorSpace` (0x1b) PrintConv (`Sony.pm:4485-4489`).
fn color_space(v: u16) -> Option<&'static str> {
  Some(match v {
    0 => "sRGB",
    1 => "Adobe RGB",
    5 => "Adobe RGB (A700)",
    _ => return None,
  })
}

/// `FlashControl` (0x23) PrintConv (`Sony.pm:4516-4519`).
fn flash_control(v: u16) -> Option<&'static str> {
  Some(match v {
    0 => "ADI",
    1 => "Pre-flash TTL",
    2 => "Manual",
    _ => return None,
  })
}

/// `PrioritySetupShutterRelease` (0x28) PrintConv (`Sony.pm:4524-4527`).
fn priority_setup(v: u16) -> Option<&'static str> {
  Some(match v {
    0 => "AF",
    1 => "Release",
    _ => return None,
  })
}

/// `AFIlluminator` (0x29) PrintConv (`Sony.pm:4531-4534`).
fn af_illuminator(v: u16) -> Option<&'static str> {
  Some(match v {
    0 => "Auto",
    1 => "Off",
    _ => return None,
  })
}

/// `HighISONoiseReduction` (0x2c) PrintConv (`Sony.pm:4543-4548`).
fn high_iso_nr(v: u16) -> Option<&'static str> {
  Some(match v {
    0 => "Normal",
    1 => "Low",
    2 => "High",
    3 => "Off",
    _ => return None,
  })
}

/// `ImageStyle` (0x2d) PrintConv (`Sony.pm:4552-4570`).
fn image_style(v: u16) -> Option<&'static str> {
  Some(match v {
    1 => "Standard",
    2 => "Vivid",
    3 => "Portrait",
    4 => "Landscape",
    5 => "Sunset",
    7 => "Night View/Portrait",
    8 => "B&W",
    9 => "Adobe RGB",
    11 => "Neutral",
    129 => "StyleBox1",
    130 => "StyleBox2",
    131 => "StyleBox3",
    132 => "StyleBox4",
    133 => "StyleBox5",
    134 => "StyleBox6",
    _ => return None,
  })
}

/// `FocusModeSwitch` (0x2e) PrintConv (`0 => AF`, `1 => Manual`).
fn af_manual(v: u16) -> Option<&'static str> {
  Some(match v {
    0 => "AF",
    1 => "Manual",
    _ => return None,
  })
}

/// `FlashAction` (0x3e) PrintConv (`Sony.pm:4584-4589`).
fn flash_action(v: u16) -> Option<&'static str> {
  Some(match v {
    0 => "Did not fire",
    1 => "Fired",
    2 => "External Flash, Did not fire",
    3 => "External Flash, Fired",
    _ => return None,
  })
}

/// `Rotation` (0x3f) PrintConv (`Sony.pm:4593-4598`) — note `1`/`2` are NOT
/// inverted here (vs the `FocusInfo` 0x10 `Rotation`).
fn rotation(v: u16) -> Option<&'static str> {
  Some(match v {
    0 => "Horizontal (normal)",
    1 => "Rotate 90 CW",
    2 => "Rotate 270 CW",
    _ => return None,
  })
}

/// `AELock` (0x40) PrintConv (`1 => Off`, `2 => On`).
fn ae_lock(v: u16) -> Option<&'static str> {
  Some(match v {
    1 => "Off",
    2 => "On",
    _ => return None,
  })
}

/// `FlashAction2` (0x4c) PrintConv (`Sony.pm:4612-4623`).
fn flash_action2(v: u16) -> Option<&'static str> {
  Some(match v {
    1 => "Fired, Autoflash",
    2 => "Fired, Fill-flash",
    3 => "Fired, Rear Sync",
    4 => "Fired, Wireless",
    5 => "Did not fire",
    6 => "Fired, Slow Sync",
    17 => "Fired, Autoflash, Red-eye reduction",
    18 => "Fired, Fill-flash, Red-eye reduction",
    34 => "Fired, Fill-flash, HSS",
    _ => return None,
  })
}

/// `BatteryState` (0x50) PrintConv (`Sony.pm:4627-4633`).
fn battery_state(v: u16) -> Option<&'static str> {
  Some(match v {
    2 => "Empty",
    3 => "Very Low",
    4 => "Low",
    5 => "Sufficient",
    6 => "Full",
    _ => return None,
  })
}

/// `SonyImageSize` (0x54) PrintConv (`1 => Large`, `2 => Medium`, `3 => Small`).
fn sony_image_size(v: u16) -> Option<&'static str> {
  Some(match v {
    1 => "Large",
    2 => "Medium",
    3 => "Small",
    _ => return None,
  })
}

/// `AspectRatio` (0x55) PrintConv (`1 => 3:2`, `2 => 16:9`).
fn aspect_ratio(v: u16) -> Option<&'static str> {
  Some(match v {
    1 => "3:2",
    2 => "16:9",
    _ => return None,
  })
}

/// `Quality` (0x56) PrintConv (`Sony.pm:4666-4674`).
fn quality(v: u16) -> Option<&'static str> {
  Some(match v {
    0 => "RAW",
    2 => "CRAW",
    16 => "Extra Fine",
    32 => "Fine",
    34 => "RAW + JPEG",
    35 => "CRAW + JPEG",
    48 => "Standard",
    _ => return None,
  })
}

/// `ExposureLevelIncrements` (0x58) PrintConv (`33 => 1/3 EV`, `50 => 1/2 EV`).
fn exposure_level_increments(v: u16) -> Option<&'static str> {
  Some(match v {
    33 => "1/3 EV",
    50 => "1/2 EV",
    _ => return None,
  })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
#[path = "camerasettings_tests.rs"]
mod tests;
