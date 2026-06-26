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

  // `-n`: the exp ValueConv float `exp(3*ln2)*100` = `799.9999999999998`, whose
  // `%.15g` token is `"800"`, so it is emitted as the BARE integer `800` (NOT
  // serde's `800.0`), byte-identical to the bundled `.n` golden. (Pre-fix it was
  // an `F64` rendering `"800.0"` — value-equal under the lenient comparator but
  // the WRONG token, masked.)
  let n = parse_focus_info(&buf, Some("DSLR-A200"), false);
  assert_eq!(find(&n, "ISOSetting"), Some(TagValue::I64(800)));
  assert_eq!(find(&n, "ISO"), Some(TagValue::I64(800)));
  assert_eq!(find(&n, "DriveMode2"), Some(TagValue::I64(1)));
}

/// TOKEN-LEVEL (the conformance comparator masks `800.0 == 800`): the A200
/// `ISOSetting`/`ISO` `-n` value SERIALIZES to the BARE JSON token `800`, NOT
/// serde's `800.0` — asserts the raw serialized string, not the value-equal
/// `json_equivalent_strict`.
#[cfg(feature = "json")]
#[test]
fn iso_n_serializes_bare_integer_token() {
  let mut buf = vec![0u8; 0x80];
  buf[0x6d] = 72; // ISOSetting -> exp((72/8-6)*ln2)*100 = 799.9999999999998
  buf[0x6f] = 72; // ISO
  let n = parse_focus_info(&buf, Some("DSLR-A200"), false);
  for name in ["ISOSetting", "ISO"] {
    let v = find(&n, name).expect("present");
    let token = serde_json::to_string(&v).expect("serialize");
    assert_eq!(
      token, "800",
      "{name} -n must be the bare token 800, not 800.0"
    );
    assert!(!token.contains('.'), "{name}: no trailing .0 ({token})");
  }
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

/// `%FocusInfo` is `PRIORITY => 0` (`Sony.pm:3198`): EVERY emitted leaf must
/// carry `priority == 0` (the table has no per-leaf `Priority` override), so a
/// later FocusInfo duplicate NEVER overrides an earlier same-name value — e.g.
/// an `ISOSetting` from the Main IFD / an earlier-walked table SURVIVES a
/// differing FocusInfo `ISOSetting`.
#[test]
fn focus_info_leaves_are_priority_zero_and_do_not_override() {
  let mut buf = vec![0u8; 0x80];
  buf[0x0e] = 0x01; // DriveMode2
  buf[0x15] = 1; // DynamicRangeOptimizerMode
  buf[0x3f] = 2; // ExposureProgram
  buf[0x41] = 1; // CreativeStyle
  buf[0x6d] = 72; // ISOSetting
  buf[0x6f] = 72; // ISO
  let ems = parse_focus_info(&buf, Some("DSLR-A200"), true);
  assert!(!ems.is_empty(), "FocusInfo emitted leaves");
  for e in &ems {
    assert_eq!(e.priority, 0, "{} must be PRIORITY 0", e.name);
  }

  // Consequence under the shared duplicate rule: a FocusInfo `ISOSetting`
  // (priority 0) does NOT override a stored priority-1 `ISOSetting`, so the
  // earlier (Main / earlier-walked) value wins even when the values DIFFER.
  let focus_iso_priority = ems
    .iter()
    .find(|e| e.name == "ISOSetting")
    .expect("ISOSetting emitted")
    .priority;
  assert!(
    !crate::tagmap::dedup_override(focus_iso_priority, 1),
    "a PRIORITY=>0 FocusInfo duplicate must NOT override a stored priority-1 value"
  );
  // Contrast: an ordinary priority-1 duplicate WOULD override (faithful last-wins).
  assert!(
    crate::tagmap::dedup_override(1, 1),
    "an ordinary priority-1 duplicate overrides (last-wins)"
  );
}
