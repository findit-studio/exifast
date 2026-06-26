// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Sony::CameraSettings` (`0x0114`, A200/A300/A350/A700/A850/A900): the
//! BigEndian `int16u` reads (byte = index * 2), the exposure/aperture
//! ValueConvs, the masked-`int16u` `DriveMode`, the `FocusStatus` BITMASK, and
//! the per-field availability of `FolderNumber`/`ImageNumber` (out of range for
//! the 280-byte block, in range for 364).

use super::*;

fn put(buf: &mut [u8], idx: usize, v: u16) {
  let off = idx * 2;
  buf[off..off + 2].copy_from_slice(&v.to_be_bytes());
}

fn find(ems: &[SubEmission], name: &str) -> Option<TagValue> {
  ems.iter().find(|e| e.name == name).map(|e| e.value.clone())
}

#[test]
fn exposure_aperture_and_temp_big_endian() {
  let mut buf = vec![0u8; 280];
  put(&mut buf, 0x00, 85); // ExposureTime -> 2**(6-85/8) ~= 1/25
  put(&mut buf, 0x01, 43); // FNumber -> 2**((43/8-1)/2) ~= 4.6
  put(&mut buf, 0x07, 55); // ColorTemperatureSet -> 5500 K
  put(&mut buf, 0x51, 70); // BatteryLevel -> 70%

  let j = parse_camera_settings(&buf, true);
  assert_eq!(find(&j, "ExposureTime"), Some(TagValue::Str("1/25".into())));
  assert_eq!(find(&j, "FNumber"), Some(TagValue::Str("4.6".into())));
  assert_eq!(
    find(&j, "ColorTemperatureSet"),
    Some(TagValue::Str("5500 K".into()))
  );
  assert_eq!(find(&j, "BatteryLevel"), Some(TagValue::Str("70%".into())));

  let n = parse_camera_settings(&buf, false);
  assert_eq!(find(&n, "ColorTemperatureSet"), Some(TagValue::I64(5500)));
  assert_eq!(find(&n, "BatteryLevel"), Some(TagValue::I64(70)));
}

#[test]
fn drive_mode_masked_and_focus_status_bitmask() {
  let mut buf = vec![0u8; 280];
  put(&mut buf, 0x04, 0x1107); // DriveMode masked 0xff -> 0x07 Continuous Bracketing
  put(&mut buf, 0x53, 0); // FocusStatus -> Not confirmed (literal)

  let j = parse_camera_settings(&buf, true);
  assert_eq!(
    find(&j, "DriveMode"),
    Some(TagValue::Str("Continuous Bracketing".into()))
  );
  assert_eq!(
    find(&j, "FocusStatus"),
    Some(TagValue::Str("Not confirmed".into()))
  );

  let n = parse_camera_settings(&buf, false);
  assert_eq!(find(&n, "DriveMode"), Some(TagValue::I64(0x07)));

  // A set-bit value decodes via DecodeBits (bit 0 = Confirmed, bit 1 = Failed).
  put(&mut buf, 0x53, 0b11);
  let j2 = parse_camera_settings(&buf, true);
  assert_eq!(
    find(&j2, "FocusStatus"),
    Some(TagValue::Str("Confirmed, Failed".into()))
  );
}

#[test]
fn priority_is_zero_and_folder_number_range_gated() {
  let buf280 = vec![0u8; 280];
  let ems = parse_camera_settings(&buf280, true);
  assert!(
    ems.iter().all(|e| e.priority == 0),
    "CameraSettings is PRIORITY => 0"
  );
  // 0x9a FolderNumber is at byte 308 — out of range for the 280-byte block.
  assert!(find(&ems, "FolderNumber").is_none());

  // The 364-byte A850/A900 block brings FolderNumber/ImageNumber in range.
  let mut buf364 = vec![0u8; 364];
  put(&mut buf364, 0x9a, 100);
  put(&mut buf364, 0x9b, 1867);
  let ems2 = parse_camera_settings(&buf364, true);
  assert_eq!(
    find(&ems2, "FolderNumber"),
    Some(TagValue::Str("100".into()))
  );
  assert_eq!(
    find(&ems2, "ImageNumber"),
    Some(TagValue::Str("1867".into()))
  );
}

/// TOKEN-LEVEL (the conformance comparator masks `0.0 == 0` and `800.0 == 800`):
/// the `-n` exposure-comp ValueConv `($val-128)/24` at a WHOLE result and the
/// `-n` `ISOSetting` exp ValueConv SERIALIZE to BARE integer tokens (`0`,
/// `800`), byte-identical to the bundled `.n` golden — NOT serde's `0.0`/`800.0`.
/// Asserts the raw serialized JSON string, not the value-equal comparator.
#[cfg(feature = "json")]
#[test]
fn n_whole_valueconvs_serialize_bare_integer_tokens() {
  let mut buf = vec![0u8; 280];
  put(&mut buf, 0x03, 128); // ExposureCompensationSet -> (128-128)/24 = 0
  put(&mut buf, 0x16, 72); // ISOSetting -> exp((72/8-6)*ln2)*100 = 799.9999999999998
  let n = parse_camera_settings(&buf, false);

  let ec = serde_json::to_string(&find(&n, "ExposureCompensationSet").unwrap()).unwrap();
  assert_eq!(
    ec, "0",
    "ExposureCompensationSet -n must be bare 0, not 0.0"
  );
  let iso = serde_json::to_string(&find(&n, "ISOSetting").unwrap()).unwrap();
  assert_eq!(iso, "800", "ISOSetting -n must be bare 800, not 800.0");
  assert!(!ec.contains('.') && !iso.contains('.'), "no trailing .0");

  // Regression guard: a genuinely FRACTIONAL exposure-comp keeps its float token
  // (the helper must NOT integer-ize a non-whole value).
  put(&mut buf, 0x03, 140); // (140-128)/24 = 0.5
  let n2 = parse_camera_settings(&buf, false);
  assert_eq!(
    serde_json::to_string(&find(&n2, "ExposureCompensationSet").unwrap()).unwrap(),
    "0.5"
  );
}
