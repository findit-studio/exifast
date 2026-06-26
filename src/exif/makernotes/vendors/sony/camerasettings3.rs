// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::CameraSettings3` (`Sony.pm:5134-5760`) — the
//! `0x0114` Main-table SubDirectory dispatched when `$count == 1536 || 2048`
//! (`Sony.pm:803-835`), an `int8u`-format `ProcessBinaryData` block of camera
//! settings for the A33/A35/A55, A450/A500/A550, A560/A580 and NEX-3/5/C3/VG10E.
//!
//! `FORMAT => 'int8u'`, `PRIORITY => 0`, `DATAMEMBER => [ 0x99 ]` (LensMount).
//! Per the `ProcessBinaryData` contract each tag is emitted IFF its byte range
//! is in the block AND its model `Condition` holds
//! ([[exifast-processbinarydata-per-field]]). The masked `0x0114`/`276.1`
//! `FolderNumber`/`ImageNumber` and `0x200` `ShotNumberSincePowerUp2` read
//! `int32u` from their offsets.

use crate::exif::tables::{print_exposure_time, print_fnumber};
use crate::value::TagValue;
use smol_str::SmolStr;

use super::subtables::{
  SubEmission, drive_mode, exposure_comp_value, exposure_program2, hash_hex_value,
  model_is_a4xx_9pt, model_is_nex, read_u32, signed_setting_value, white_balance_setting,
};

/// Render a plain (non-hex) hash-PrintConv leaf (`-j` label/`Unknown (N)`, `-n`
/// raw int) from a `u8` value.
fn hash_leaf(raw: u8, hit: Option<&'static str>, print_conv: bool) -> TagValue {
  super::hash_print_value(raw, hit, print_conv)
}

/// Push a simple `int8u` hash-PrintConv leaf at `off`.
fn push_hash(
  buf: &[u8],
  off: usize,
  name: &'static str,
  hit: impl Fn(u8) -> Option<&'static str>,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  if let Some(&raw) = buf.get(off) {
    out.push(SubEmission {
      priority: 1,
      name,
      value: hash_leaf(raw, hit(raw), print_conv),
    });
  }
}

/// `MeteringMode` PrintConv (`1 => Multi-segment`, `2 => Center-weighted
/// average`, `3 => Spot`) — shared by 0x07 here and `MoreSettings` 0x03.
fn metering_mode(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "Multi-segment",
    2 => "Center-weighted average",
    3 => "Spot",
    _ => return None,
  })
}

/// `FocusModeSetting` PrintConv (`Sony.pm:5214-5223`).
fn focus_mode_setting(v: u8) -> Option<&'static str> {
  Some(match v {
    17 => "AF-S",
    18 => "AF-C",
    19 => "AF-A",
    32 => "Manual",
    48 => "DMF",
    _ => return None,
  })
}

/// `DynamicRangeOptimizerSetting` PrintConv (`1 => Off`, `16 => On (Auto)`,
/// `17 => On (Manual)`).
fn dro_setting(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "Off",
    16 => "On (Auto)",
    17 => "On (Manual)",
    _ => return None,
  })
}

/// `ColorSpace` PrintConv (`1 => sRGB`, `2 => Adobe RGB`).
fn color_space(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "sRGB",
    2 => "Adobe RGB",
    _ => return None,
  })
}

/// `CreativeStyleSetting` PrintConv (`Sony.pm:5283-5292`).
fn creative_style_setting(v: u8) -> Option<&'static str> {
  Some(match v {
    16 => "Standard",
    32 => "Vivid",
    64 => "Portrait",
    80 => "Landscape",
    96 => "B&W",
    160 => "Sunset",
    _ => return None,
  })
}

/// `FlashMode` PrintConv (`Sony.pm` — shared 0x20 / `MoreSettings` 0x10).
fn flash_mode(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "Flash Off",
    16 => "Autoflash",
    17 => "Fill-flash",
    18 => "Slow Sync",
    19 => "Rear Sync",
    20 => "Wireless",
    _ => return None,
  })
}

/// `LongExposureNoiseReduction` PrintConv (`1 => Off`, `16 => On`).
fn long_exposure_nr(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "Off",
    16 => "On",
    _ => return None,
  })
}

/// `HighISONoiseReduction` PrintConv (`16 => Low`, `17 => High`, `19 => Auto`).
fn high_iso_nr(v: u8) -> Option<&'static str> {
  Some(match v {
    16 => "Low",
    17 => "High",
    19 => "Auto",
    _ => return None,
  })
}

/// `HDRSetting` PrintConv (`1 => Off`, `16 => On (Auto)`, `17 => On (Manual)`).
fn hdr_setting(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "Off",
    16 => "On (Auto)",
    17 => "On (Manual)",
    _ => return None,
  })
}

/// `HDRLevel` PrintConv (`Sony.pm` — shared 0x2e / `MoreSettings` 0x17).
fn hdr_level(v: u8) -> Option<&'static str> {
  Some(match v {
    33 => "1 EV",
    34 => "1.5 EV",
    35 => "2 EV",
    36 => "2.5 EV",
    37 => "3 EV",
    38 => "3.5 EV",
    39 => "4 EV",
    40 => "5 EV",
    41 => "6 EV",
    _ => return None,
  })
}

/// `ViewingMode` PrintConv (`16 => ViewFinder`, `33 => Focus Check Live View`,
/// `34 => Quick AF Live View`) — 0x2f.
fn viewing_mode(v: u8) -> Option<&'static str> {
  Some(match v {
    16 => "ViewFinder",
    33 => "Focus Check Live View",
    34 => "Quick AF Live View",
    _ => return None,
  })
}

/// `FaceDetection` PrintConv (`1 => Off`, `16 => On`).
fn face_detection(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "Off",
    16 => "On",
    _ => return None,
  })
}

/// Walk the `CameraSettings3` block and emit the settings leaves for the model.
///
/// `buf` is the verbatim (un-enciphered) `0x0114` block; `model` is
/// `$$self{Model}`; `print_conv` selects `-j` vs `-n`. The 9-point DSLR-A4xx
/// bodies use a different masked-tag layout (0x283.. / 0x30c..) — this port
/// targets the "other models" (SLT / A560 / A580 / NEX) branches the A33 needs
/// plus the shared leaves; the A4xx-only conditional leaves stay deferred.
#[must_use]
pub fn parse_camera_settings3(
  buf: &[u8],
  model: Option<&str>,
  print_conv: bool,
) -> Vec<SubEmission> {
  let mut out = std::vec::Vec::new();
  let nex = model_is_nex(model);
  let a4xx = model_is_a4xx_9pt(model);
  let other = !a4xx; // the `!~ /^DSLR-(A450|A500|A550)$/` class

  // 0x00 ShutterSpeedSetting — `$val ? 2**(6 - $val/8) : 0`,
  // `$val ? PrintExposureTime($val) : "Bulb"` (Sony.pm:5144-5150).
  if let Some(&raw) = buf.first() {
    let secs = if raw != 0 {
      2f64.powf(6.0 - f64::from(raw) / 8.0)
    } else {
      0.0
    };
    out.push(SubEmission {
      priority: 1,
      name: "ShutterSpeedSetting",
      value: if print_conv {
        if raw != 0 {
          TagValue::Str(print_exposure_time(secs).into())
        } else {
          TagValue::Str("Bulb".into())
        }
      } else {
        TagValue::F64(secs)
      },
    });
  }

  // 0x01 ApertureSetting — `2**(($val/8 - 1)/2)`, PrintFNumber (Sony.pm:5152).
  push_fnumber_leaf(buf, 0x01, "ApertureSetting", print_conv, &mut out);

  // 0x02 ISOSetting — special hash + `int($val+0.5)` OTHER (Sony.pm:5160-5172).
  if let Some(&raw) = buf.get(0x02) {
    out.push(SubEmission {
      priority: 1,
      name: "ISOSetting",
      value: iso_setting_value(raw, print_conv),
    });
  }

  // 0x03 ExposureCompensationSet — `($val-128)/24`, `%+.1f`|0 (Sony.pm:5174).
  if let Some(&raw) = buf.get(0x03) {
    out.push(SubEmission {
      priority: 1,
      name: "ExposureCompensationSet",
      value: exposure_comp_value(raw, print_conv),
    });
  }

  // 0x04 DriveModeSetting — `PrintHex`, %sonyDriveMode (Sony.pm:5181).
  push_drive_mode(buf, 0x04, "DriveModeSetting", false, print_conv, &mut out);

  // 0x05 ExposureProgram — %sonyExposureProgram2 (Sony.pm:5206).
  push_hash(
    buf,
    0x05,
    "ExposureProgram",
    exposure_program2_u8,
    print_conv,
    &mut out,
  );

  push_hash(
    buf,
    0x06,
    "FocusModeSetting",
    focus_mode_setting,
    print_conv,
    &mut out,
  );
  push_hash(
    buf,
    0x07,
    "MeteringMode",
    metering_mode,
    print_conv,
    &mut out,
  );
  push_hash(
    buf,
    0x09,
    "SonyImageSize",
    sony_image_size,
    print_conv,
    &mut out,
  );
  push_hash(buf, 0x0a, "AspectRatio", aspect_ratio, print_conv, &mut out);
  push_hash(buf, 0x0b, "Quality", quality, print_conv, &mut out);
  push_hash(
    buf,
    0x0c,
    "DynamicRangeOptimizerSetting",
    dro_setting,
    print_conv,
    &mut out,
  );

  // 0x0d DynamicRangeOptimizerLevel — plain int8u (no PrintConv).
  push_plain(
    buf,
    0x0d,
    "DynamicRangeOptimizerLevel",
    print_conv,
    &mut out,
  );

  push_hash(buf, 0x0e, "ColorSpace", color_space, print_conv, &mut out);
  push_hash(
    buf,
    0x0f,
    "CreativeStyleSetting",
    creative_style_setting,
    print_conv,
    &mut out,
  );
  push_signed(buf, 0x10, "ContrastSetting", print_conv, &mut out);
  push_signed(buf, 0x11, "SaturationSetting", print_conv, &mut out);
  push_signed(buf, 0x12, "SharpnessSetting", print_conv, &mut out);

  // 0x16 WhiteBalanceSetting — `PrintHex`, %whiteBalanceSetting (Sony.pm:5306).
  push_hash_hex(
    buf,
    0x16,
    "WhiteBalanceSetting",
    white_balance_setting,
    print_conv,
    &mut out,
  );

  // 0x17 ColorTemperatureSetting — `$val*100`, "$val K" (Sony.pm:5314).
  push_color_temp(buf, 0x17, print_conv, &mut out);

  // 0x18 ColorCompensationFilterSet — int8s `+$val`|$val (Sony.pm:5322).
  push_signed(
    buf,
    0x18,
    "ColorCompensationFilterSet",
    print_conv,
    &mut out,
  );

  // 0x19 CustomWB_RGBLevels — int16uRev[3] (Sony.pm:5332).
  push_custom_wb_rgb(buf, 0x19, print_conv, &mut out);

  push_hash(buf, 0x20, "FlashMode", flash_mode, print_conv, &mut out);
  push_hash(
    buf,
    0x21,
    "FlashControl",
    flash_control,
    print_conv,
    &mut out,
  );

  // 0x23 FlashExposureCompSet — `($val-128)/24` (Sony.pm:5402).
  if let Some(&raw) = buf.get(0x23) {
    out.push(SubEmission {
      priority: 1,
      name: "FlashExposureCompSet",
      value: exposure_comp_value(raw, print_conv),
    });
  }

  push_hash(buf, 0x24, "AFAreaMode", af_area_mode, print_conv, &mut out);
  push_hash(
    buf,
    0x25,
    "LongExposureNoiseReduction",
    long_exposure_nr,
    print_conv,
    &mut out,
  );
  push_hash(
    buf,
    0x26,
    "HighISONoiseReduction",
    high_iso_nr,
    print_conv,
    &mut out,
  );
  push_hash(
    buf,
    0x27,
    "SmileShutterMode",
    smile_shutter_mode,
    print_conv,
    &mut out,
  );
  push_hash(
    buf,
    0x28,
    "RedEyeReduction",
    red_eye_reduction,
    print_conv,
    &mut out,
  );
  push_hash(buf, 0x2d, "HDRSetting", hdr_setting, print_conv, &mut out);
  push_hash(buf, 0x2e, "HDRLevel", hdr_level, print_conv, &mut out);
  push_hash(buf, 0x2f, "ViewingMode", viewing_mode, print_conv, &mut out);
  push_hash(
    buf,
    0x30,
    "FaceDetection",
    face_detection,
    print_conv,
    &mut out,
  );
  push_hash(
    buf,
    0x31,
    "SmileShutter",
    smile_shutter,
    print_conv,
    &mut out,
  );

  // 0x32/0x33/0x34/0x35/0x36/0x38 — `Condition => '$$self{Model} !~
  // /^DSLR-(A450|A500|A550)$/'` (Sony.pm:5491-5615).
  if other {
    push_hash(
      buf,
      0x32,
      "SweepPanoramaSize",
      sweep_panorama_size,
      print_conv,
      &mut out,
    );
    push_hash(
      buf,
      0x33,
      "SweepPanoramaDirection",
      sweep_panorama_dir,
      print_conv,
      &mut out,
    );
    push_drive_mode(buf, 0x34, "DriveMode", true, print_conv, &mut out);
    push_hash(
      buf,
      0x35,
      "MultiFrameNoiseReduction",
      multi_frame_nr,
      print_conv,
      &mut out,
    );
  }
  // 0x36 LiveViewAFSetting / 0x38 PanoramaSize3D — `!~ /^(NEX-|DSLR-A4xx)/`.
  if other && !nex {
    push_hash(
      buf,
      0x36,
      "LiveViewAFSetting",
      live_view_af,
      print_conv,
      &mut out,
    );
    push_hash(
      buf,
      0x38,
      "PanoramaSize3D",
      panorama_size_3d,
      print_conv,
      &mut out,
    );
  }

  // 0x83..0x99 — the `!~ /^(NEX-|DSLR-A4xx)/` SLT/DSLR live-view block
  // (Sony.pm:5524-5614).
  if other && !nex {
    push_hash(
      buf,
      0x83,
      "AFButtonPressed",
      af_button_pressed,
      print_conv,
      &mut out,
    );
    push_hash(
      buf,
      0x84,
      "LiveViewMetering",
      live_view_metering,
      print_conv,
      &mut out,
    );
    push_hash(
      buf,
      0x85,
      "ViewingMode2",
      viewing_mode2,
      print_conv,
      &mut out,
    );
    push_hash(buf, 0x86, "AELock", ae_lock, print_conv, &mut out);
    push_hash(
      buf,
      0x8b,
      "LiveViewFocusMode",
      live_view_focus_mode,
      print_conv,
      &mut out,
    );
  }
  // 0x87/0x88 FlashStatus — `!~ /^DSLR-(A450|A500|A550)/` (Sony.pm:5564-5580).
  if other {
    push_hash(
      buf,
      0x87,
      "FlashStatusBuilt-in",
      flash_status_builtin,
      print_conv,
      &mut out,
    );
    push_hash(
      buf,
      0x88,
      "FlashStatusExternal",
      flash_status_external,
      print_conv,
      &mut out,
    );
  }
  // 0x99 LensMount — `!~ /^DSLR-A4xx$/`, DataMember (Sony.pm:5604).
  if other {
    push_hash(buf, 0x99, "LensMount", lens_mount, print_conv, &mut out);
  }

  // 0x10c SequenceNumber — OTHER-passthrough (Sony.pm:5638).
  if other && let Some(&raw) = buf.get(0x10c) {
    out.push(SubEmission {
      priority: 1,
      name: "SequenceNumber",
      value: sequence_number_value(raw, print_conv),
    });
  }

  // 0x0114 FolderNumber (mask 0x00ffc000) + 276.1 ImageNumber (mask
  // 0x00003fff) — int32u (Sony.pm:5650-5666).
  if other && let Some(v) = read_u32(buf, 0x0114) {
    let folder = (v & 0x00ff_c000) >> 14;
    out.push(SubEmission {
      priority: 1,
      name: "FolderNumber",
      value: masked_count_value(folder, 3, print_conv),
    });
    let image = v & 0x0000_3fff;
    out.push(SubEmission {
      priority: 1,
      name: "ImageNumber",
      value: masked_count_value(image, 4, print_conv),
    });
  }

  // 0x200 ShotNumberSincePowerUp2 — int32u (Sony.pm:5675).
  if other && let Some(v) = read_u32(buf, 0x200) {
    out.push(SubEmission {
      priority: 1,
      name: "ShotNumberSincePowerUp2",
      value: TagValue::I64(i64::from(v)),
    });
  }

  // `%CameraSettings3` is `PRIORITY => 0` (Sony.pm:5139): every leaf here is a
  // `Priority => 0` duplicate, so a higher-priority Main-IFD leaf of the same
  // name (e.g. the `0x0102` `Quality` = `RAW + JPEG/HEIF`) is NOT overridden.
  for e in &mut out {
    e.priority = 0;
  }
  out
}

/// `ExposureProgram` adaptor — `%sonyExposureProgram2` keyed by a `u8`.
fn exposure_program2_u8(v: u8) -> Option<&'static str> {
  exposure_program2(u32::from(v))
}

/// Push a `2**(($val/8 - 1)/2)` + PrintFNumber leaf at `off`.
fn push_fnumber_leaf(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  if let Some(&raw) = buf.get(off) {
    let fnum = 2f64.powf((f64::from(raw) / 8.0 - 1.0) / 2.0);
    out.push(SubEmission {
      priority: 1,
      name,
      value: if print_conv {
        TagValue::Str(print_fnumber(fnum).into())
      } else {
        TagValue::F64(fnum)
      },
    });
  }
}

/// Push a plain `int8u` leaf (no conversion) at `off`.
fn push_plain(
  buf: &[u8],
  off: usize,
  name: &'static str,
  _print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  if let Some(&raw) = buf.get(off) {
    out.push(SubEmission {
      priority: 1,
      name,
      value: TagValue::I64(i64::from(raw)),
    });
  }
}

/// Push an `int8s` `+$val`/$val signed-setting leaf at `off`.
fn push_signed(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  if let Some(&raw) = buf.get(off) {
    out.push(SubEmission {
      priority: 1,
      name,
      value: signed_setting_value(raw as i8, print_conv),
    });
  }
}

/// Push a `PrintHex` hash leaf honouring the `Unknown (0x%x)` miss.
fn push_hash_hex(
  buf: &[u8],
  off: usize,
  name: &'static str,
  hit: impl Fn(u32) -> Option<&'static str>,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  if let Some(&raw) = buf.get(off) {
    out.push(SubEmission {
      priority: 1,
      name,
      value: hash_hex_value(u32::from(raw), hit(u32::from(raw)), print_conv),
    });
  }
}

/// Push the `DriveMode`-family `PrintHex` hash leaf.
fn push_drive_mode(
  buf: &[u8],
  off: usize,
  name: &'static str,
  extended: bool,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  if let Some(&raw) = buf.get(off) {
    out.push(SubEmission {
      priority: 1,
      name,
      value: hash_hex_value(
        u32::from(raw),
        drive_mode(u32::from(raw), extended),
        print_conv,
      ),
    });
  }
}

/// Push the `ColorTemperatureSetting` (`$val*100`, `"$val K"`) leaf.
fn push_color_temp(buf: &[u8], off: usize, print_conv: bool, out: &mut Vec<SubEmission>) {
  if let Some(&raw) = buf.get(off) {
    let k = u32::from(raw) * 100;
    out.push(SubEmission {
      priority: 1,
      name: "ColorTemperatureSetting",
      value: if print_conv {
        TagValue::Str(SmolStr::new(std::format!("{k} K")))
      } else {
        TagValue::I64(i64::from(k))
      },
    });
  }
}

/// Push `CustomWB_RGBLevels` — `int16uRev[3]` (big-endian `int16u` triple,
/// space-joined). `-n` is the same space-joined string (no ValueConv).
fn push_custom_wb_rgb(buf: &[u8], off: usize, _print_conv: bool, out: &mut Vec<SubEmission>) {
  if let Some(&[a0, a1, b0, b1, c0, c1]) = buf.get(off..off + 6) {
    let a = u16::from_be_bytes([a0, a1]);
    let b = u16::from_be_bytes([b0, b1]);
    let c = u16::from_be_bytes([c0, c1]);
    out.push(SubEmission {
      priority: 1,
      name: "CustomWB_RGBLevels",
      value: TagValue::Str(SmolStr::new(std::format!("{a} {b} {c}"))),
    });
  }
}

/// `ISOSetting` value (`Sony.pm:5160-5172`): `ValueConv` `($val and $val<254) ?
/// exp(...)*100 : $val`, PrintConv hash with `0 => Auto`, `254 => n/a`, OTHER
/// `int($val+0.5)`.
fn iso_setting_value(raw: u8, print_conv: bool) -> TagValue {
  let vc = if raw != 0 && raw < 254 {
    (((f64::from(raw) / 8.0 - 6.0) * core::f64::consts::LN_2).exp()) * 100.0
  } else {
    f64::from(raw)
  };
  if !print_conv {
    // `-n`: the ValueConv result. For 0 / 254 it is the raw integer.
    return if raw != 0 && raw < 254 {
      TagValue::F64(vc)
    } else {
      TagValue::I64(i64::from(raw))
    };
  }
  match raw {
    0 => TagValue::Str("Auto".into()),
    254 => TagValue::Str("n/a".into()),
    _ => TagValue::I64((vc + 0.5) as i64),
  }
}

/// `SonyImageSize` PrintConv (`Sony.pm:5235-5244`).
fn sony_image_size(v: u8) -> Option<&'static str> {
  Some(match v {
    21 => "Large (3:2)",
    22 => "Medium (3:2)",
    23 => "Small (3:2)",
    25 => "Large (16:9)",
    26 => "Medium (16:9)",
    27 => "Small (16:9)",
    _ => return None,
  })
}

/// `AspectRatio` PrintConv (`4 => 3:2`, `8 => 16:9`).
fn aspect_ratio(v: u8) -> Option<&'static str> {
  Some(match v {
    4 => "3:2",
    8 => "16:9",
    _ => return None,
  })
}

/// `Quality` PrintConv (`2 => RAW`, `4 => RAW + JPEG`, `6 => Fine`,
/// `7 => Standard`).
fn quality(v: u8) -> Option<&'static str> {
  Some(match v {
    2 => "RAW",
    4 => "RAW + JPEG",
    6 => "Fine",
    7 => "Standard",
    _ => return None,
  })
}

/// `FlashControl` PrintConv (`1 => ADI Flash`, `2 => Pre-flash TTL`).
fn flash_control(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "ADI Flash",
    2 => "Pre-flash TTL",
    _ => return None,
  })
}

/// `AFAreaMode` PrintConv (`Sony.pm:5413-5420`).
fn af_area_mode(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "Wide",
    2 => "Spot",
    3 => "Local",
    4 => "Flexible",
    _ => return None,
  })
}

/// `SmileShutterMode` PrintConv (`17 => Slight Smile`, `18 => Normal Smile`,
/// `19 => Big Smile`).
fn smile_shutter_mode(v: u8) -> Option<&'static str> {
  Some(match v {
    17 => "Slight Smile",
    18 => "Normal Smile",
    19 => "Big Smile",
    _ => return None,
  })
}

/// `RedEyeReduction` PrintConv (`1 => Off`, `16 => On`).
fn red_eye_reduction(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "Off",
    16 => "On",
    _ => return None,
  })
}

/// `SmileShutter` PrintConv (`1 => Off`, `16 => On`).
fn smile_shutter(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "Off",
    16 => "On",
    _ => return None,
  })
}

/// `SweepPanoramaSize` PrintConv (`1 => Standard`, `2 => Wide`).
fn sweep_panorama_size(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "Standard",
    2 => "Wide",
    _ => return None,
  })
}

/// `SweepPanoramaDirection` PrintConv (`1 => Right`, `2 => Left`, `3 => Up`,
/// `4 => Down`).
fn sweep_panorama_dir(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "Right",
    2 => "Left",
    3 => "Up",
    4 => "Down",
    _ => return None,
  })
}

/// `MultiFrameNoiseReduction` PrintConv (`Sony.pm:5481-5489`).
fn multi_frame_nr(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "n/a",
    1 => "Off",
    16 => "On",
    255 => "None",
    _ => return None,
  })
}

/// `LiveViewAFSetting` PrintConv (`0 => n/a`, `1 => Phase-detect AF`,
/// `2 => Contrast AF`).
fn live_view_af(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "n/a",
    1 => "Phase-detect AF",
    2 => "Contrast AF",
    _ => return None,
  })
}

/// `PanoramaSize3D` PrintConv (`Sony.pm:5512-5519`).
fn panorama_size_3d(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "n/a",
    1 => "Standard",
    2 => "Wide",
    3 => "16:9",
    _ => return None,
  })
}

/// `AFButtonPressed` PrintConv (`1 => No`, `16 => Yes`).
fn af_button_pressed(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "No",
    16 => "Yes",
    _ => return None,
  })
}

/// `LiveViewMetering` PrintConv (`0 => n/a`, `16 => 40 Segment`,
/// `32 => 1200-zone Evaluative`).
fn live_view_metering(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "n/a",
    16 => "40 Segment",
    32 => "1200-zone Evaluative",
    _ => return None,
  })
}

/// `ViewingMode2` PrintConv (`Sony.pm:5547-5553`).
fn viewing_mode2(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "n/a",
    16 => "Viewfinder",
    33 => "Focus Check Live View",
    34 => "Quick AF Live View",
    _ => return None,
  })
}

/// `AELock` PrintConv (`1 => On`, `2 => Off`).
fn ae_lock(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "On",
    2 => "Off",
    _ => return None,
  })
}

/// `FlashStatusBuilt-in` PrintConv (`1 => Off`, `2 => On`).
fn flash_status_builtin(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "Off",
    2 => "On",
    _ => return None,
  })
}

/// `FlashStatusExternal` PrintConv (`1 => None`, `2 => Off`, `3 => On`).
fn flash_status_external(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "None",
    2 => "Off",
    3 => "On",
    _ => return None,
  })
}

/// `LiveViewFocusMode` PrintConv (`0 => n/a`, `1 => AF`, `16 => Manual`).
fn live_view_focus_mode(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "n/a",
    1 => "AF",
    16 => "Manual",
    _ => return None,
  })
}

/// `LensMount` PrintConv (`1 => Unknown`, `16 => A-mount`, `17 => E-mount`).
fn lens_mount(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "Unknown",
    16 => "A-mount",
    17 => "E-mount",
    _ => return None,
  })
}

/// `SequenceNumber` value (`Sony.pm:5621-5644`): `0 => Single`, `255 => n/a`,
/// OTHER passthrough. `-n` is the raw integer.
fn sequence_number_value(raw: u8, print_conv: bool) -> TagValue {
  if !print_conv {
    return TagValue::I64(i64::from(raw));
  }
  match raw {
    0 => TagValue::Str("Single".into()),
    255 => TagValue::Str("n/a".into()),
    n => TagValue::I64(i64::from(n)),
  }
}

/// A masked count (`FolderNumber`/`ImageNumber`): `sprintf("%.Nd", $val)` in
/// `-j`; the raw masked integer in `-n`.
fn masked_count_value(val: u32, width: usize, print_conv: bool) -> TagValue {
  if !print_conv {
    return TagValue::I64(i64::from(val));
  }
  TagValue::Str(SmolStr::new(std::format!("{val:0width$}")))
}
