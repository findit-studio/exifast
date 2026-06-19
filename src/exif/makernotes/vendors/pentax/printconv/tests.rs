// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

use super::*;
use crate::exif::ifd::RawValue;

fn u(vals: &[u64]) -> RawValue {
  RawValue::U64(vals.to_vec())
}

#[test]
fn fnumber_renders_one_decimal() {
  // 0x0013 FNumber — ValueConv `$val / 10`; PrintConv `sprintf("%.1f")`.
  // Pentax.jpg: raw 130 => "13.0".
  let conv = PentaxPrintConv::FNumber;
  assert_eq!(conv.apply(&u(&[130]), true), TagValue::Str("13.0".into()));
  // `-n`: post-ValueConv float.
  assert_eq!(conv.apply(&u(&[130]), false), TagValue::F64(13.0));
}

#[test]
fn hash_known_and_unknown() {
  let table: &[(i64, &str)] = &[(0, "Off"), (1, "On")];
  let conv = PentaxPrintConv::Hash(table);
  assert_eq!(conv.apply(&u(&[1]), true), TagValue::Str("On".into()));
  // Decimal Unknown (N) fallback.
  assert_eq!(
    conv.apply(&u(&[9]), true),
    TagValue::Str("Unknown (9)".into())
  );
  // `-n`: raw integer.
  assert_eq!(conv.apply(&u(&[1]), false), TagValue::I64(1));
}

#[test]
fn model_id_resolves_k10d() {
  // 0x0005 PentaxModelID — \%pentaxModelID. 76830 => "K10D".
  let conv = PentaxPrintConv::ModelId;
  assert_eq!(conv.apply(&u(&[76830]), true), TagValue::Str("K10D".into()));
  // Missing key ⇒ PrintHex bare hex.
  assert_eq!(
    conv.apply(&u(&[0x999999]), true),
    TagValue::Str("0x999999".into())
  );
}

#[test]
fn camera_temperature_suffixes_c() {
  // 0x0047 CameraTemperature — int8s; PrintConv `"$val C"`.
  let conv = PentaxPrintConv::CameraTemperature;
  assert_eq!(
    conv.apply(&RawValue::I64(std::vec![21]), true),
    TagValue::Str("21 C".into())
  );
}

#[test]
fn focal_length_173() {
  // 0x001d FocalLength (default variant) — ValueConv `$val / 100`; PrintConv
  // `sprintf("%.1f mm")`. Pentax.jpg: raw 1000 => "10.0 mm" / 10.0.
  let conv = PentaxPrintConv::FocalLength;
  assert_eq!(
    conv.apply(&u(&[1000]), true),
    TagValue::Str("10.0 mm".into())
  );
  assert_eq!(conv.apply(&u(&[1000]), false), TagValue::F64(10.0));
}

#[test]
fn effective_lv_173() {
  // 0x002d EffectiveLV (int16s) — `$val / 1024`; `sprintf("%.1f")`.
  // Pentax.jpg: 0x3b00 as int16s = 15104 => 14.75 => "14.8".
  let conv = PentaxPrintConv::EffectiveLv;
  let raw = RawValue::I64(std::vec![15104]);
  assert_eq!(conv.apply(&raw, true), TagValue::Str("14.8".into()));
  assert_eq!(conv.apply(&raw, false), TagValue::F64(14.75));
}

#[test]
fn exposure_compensation_and_flash_exposure_comp_173() {
  // 0x0016 ExposureCompensation — `($val-50)/10`; `$val ? %+.1f : 0`.
  // Pentax.jpg: raw 57 => 0.7 => "+0.7".
  let ec = PentaxPrintConv::ExposureCompensation;
  assert_eq!(ec.apply(&u(&[57]), true), TagValue::Str("+0.7".into()));
  assert_eq!(ec.apply(&u(&[57]), false), TagValue::F64(0.7));
  // Exactly zero ⇒ the integer 0.
  assert_eq!(ec.apply(&u(&[50]), true), TagValue::I64(0));
  // 0x004d FlashExposureComp — `$val/256`; same PrintConv. raw 0 => 0.
  let fc = PentaxPrintConv::FlashExposureComp;
  assert_eq!(
    fc.apply(&RawValue::I64(std::vec![0]), true),
    TagValue::I64(0)
  );
}

#[test]
fn flash_mode_array_173() {
  // 0x000c FlashMode — 2-element ARRAY PrintConv joined "; ".
  // Pentax.jpg: [1, 63] => "Off, Did not fire; Internal".
  let conv = PentaxPrintConv::FlashMode;
  assert_eq!(
    conv.apply(&u(&[1, 63]), true),
    TagValue::Str("Off, Did not fire; Internal".into())
  );
  // `-n`: space-joined raw run.
  assert_eq!(
    conv.apply(&u(&[1, 63]), false),
    TagValue::Str("1 63".into())
  );
}

#[test]
fn auto_bracketing_173() {
  // 0x0018 AutoBracketing — ValueConv per element then the bracket sub.
  // Pentax.jpg: [0, 0] => "0 EV, No Extended Bracket"; `-n` => "0 0".
  let conv = PentaxPrintConv::AutoBracketing;
  assert_eq!(
    conv.apply(&u(&[0, 0]), true),
    TagValue::Str("0 EV, No Extended Bracket".into())
  );
  assert_eq!(conv.apply(&u(&[0, 0]), false), TagValue::Str("0 0".into()));
}

#[test]
fn picture_mode_relist_173() {
  // 0x0033 PictureMode — Relist [[0,1],2] then 2-element ARRAY PrintConv.
  // Pentax.jpg: [5,0,1] => "Aperture Priority; 1/3 EV steps"; `-n` => "5 0 1".
  let conv = PentaxPrintConv::PictureMode;
  assert_eq!(
    conv.apply(&u(&[5, 0, 1]), true),
    TagValue::Str("Aperture Priority; 1/3 EV steps".into())
  );
  assert_eq!(
    conv.apply(&u(&[5, 0, 1]), false),
    TagValue::Str("5 0 1".into())
  );
  // K-x AVI: [255,4,1] => "Video (4); 1/3 EV steps".
  assert_eq!(
    conv.apply(&u(&[255, 4, 1]), true),
    TagValue::Str("Video (4); 1/3 EV steps".into())
  );
}

#[test]
fn drive_mode_array_173() {
  // 0x0034 DriveMode — 4-element ARRAY PrintConv joined "; ".
  // Pentax.jpg: [0,0,0,0] => "Single-frame; No Timer; Shutter Button; Single Exposure".
  let conv = PentaxPrintConv::DriveMode;
  assert_eq!(
    conv.apply(&u(&[0, 0, 0, 0]), true),
    TagValue::Str("Single-frame; No Timer; Shutter Button; Single Exposure".into())
  );
  // K-x AVI: [255,255,0,255] => "Video; n/a; Shutter Button; Video".
  assert_eq!(
    conv.apply(&u(&[255, 255, 0, 255]), true),
    TagValue::Str("Video; n/a; Shutter Button; Video".into())
  );
}

#[test]
fn image_editing_string_keyed_173() {
  // 0x0032 ImageEditing — HASH keyed on the space-joined run.
  // Pentax.jpg: [0,0,0,0] => "None"; `-n` => "0 0 0 0".
  let conv = PentaxPrintConv::StringKeyedHash(IMAGE_EDITING);
  assert_eq!(
    conv.apply(&u(&[0, 0, 0, 0]), true),
    TagValue::Str("None".into())
  );
  assert_eq!(
    conv.apply(&u(&[0, 0, 0, 0]), false),
    TagValue::Str("0 0 0 0".into())
  );
}
