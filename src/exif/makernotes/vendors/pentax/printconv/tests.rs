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
