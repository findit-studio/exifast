// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Sony::FocusInfo` (`0x0020`, A200-A900): the `DriveMode2` model-variant
//! selection, the `FocusPosition` model `Condition`, the `ISO`/`ISOSetting` exp
//! ValueConv, and the `TiffMeteringImage` length-gated placeholder.

use super::*;
use crate::value::TagValue;

fn find(ems: &[SubEmission], name: &str) -> Option<TagValue> {
  ems.iter().find(|e| e.name == name).map(|e| e.value.clone())
}

#[test]
fn drive_mode2_variant_and_iso() {
  let mut buf = vec![0u8; 0x80];
  buf[0x0e] = 0x01; // DriveMode2 -> Single Frame
  buf[0x10] = 0; // Rotation -> Horizontal (normal)
  buf[0x6d] = 72; // ISOSetting -> exp((72/8-6)*ln2)*100 = 800
  buf[0x6f] = 72; // ISO -> 800

  let j = parse_focus_info(&buf, Some("DSLR-A200"), true);
  assert_eq!(
    find(&j, "DriveMode2"),
    Some(TagValue::Str("Single Frame".into()))
  );
  assert_eq!(
    find(&j, "Rotation"),
    Some(TagValue::Str("Horizontal (normal)".into()))
  );
  assert_eq!(find(&j, "ISOSetting"), Some(TagValue::I64(800)));
  assert_eq!(find(&j, "ISO"), Some(TagValue::I64(800)));

  // `-n`: the bare exp ValueConv float (`exp(3*ln2)*100` is ~800 modulo the
  // compounded float rounding — its `%.15g` token re-parses to the golden's
  // `800`, value-equal under the conformance comparator).
  let n = parse_focus_info(&buf, Some("DSLR-A200"), false);
  match find(&n, "ISOSetting") {
    Some(TagValue::F64(v)) => assert!((v - 800.0).abs() < 1e-9, "ISOSetting -n ~= 800, got {v}"),
    other => panic!("expected F64 ISOSetting, got {other:?}"),
  }
  assert_eq!(find(&n, "DriveMode2"), Some(TagValue::I64(1)));
}

#[test]
fn focus_position_is_model_gated() {
  let mut buf = vec![0u8; 0x0a00];
  buf[0x09bb] = 128; // FocusPosition

  // A200 is in the FocusPosition Condition set.
  let a200 = parse_focus_info(&buf, Some("DSLR-A200"), true);
  assert_eq!(find(&a200, "FocusPosition"), Some(TagValue::I64(128)));

  // A560 is NOT in the set (uses FocusPosition2 instead).
  let a560 = parse_focus_info(&buf, Some("DSLR-A560"), true);
  assert!(find(&a560, "FocusPosition").is_none());
}

#[test]
fn tiff_metering_image_length_gated() {
  // Below the 0x1110 + 9600 threshold: no placeholder.
  let small = vec![0u8; 0x1110 + 9599];
  assert!(
    find(
      &parse_focus_info(&small, Some("DSLR-A200"), true),
      "TiffMeteringImage"
    )
    .is_none()
  );

  // At/above threshold: the fixed binary placeholder, in BOTH modes.
  let big = vec![0u8; 0x1110 + 9600];
  let want = TagValue::Str("(Binary data 7404 bytes, use -b option to extract)".into());
  assert_eq!(
    find(
      &parse_focus_info(&big, Some("DSLR-A200"), true),
      "TiffMeteringImage"
    ),
    Some(want.clone())
  );
  assert_eq!(
    find(
      &parse_focus_info(&big, Some("DSLR-A200"), false),
      "TiffMeteringImage"
    ),
    Some(want)
  );
}
