// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `ExtraInfo3` 0x0014 conditional-array routing (`Sony.pm:5989-6035`):
//! `BatteryState` (SLT), `ExposureProgram` (A450/A500/A550, `Priority => 0`),
//! `ModeDialPosition` (the other DSLR bodies).

use super::*;

/// A minimal `ExtraInfo3` block (`int8u` default format ⇒ key = byte offset)
/// with the 0x0014 byte set to `v`; everything else zero.
fn block_with_0x14(v: u8) -> Vec<u8> {
  let mut buf = vec![0u8; 0x20];
  buf[0x14] = v;
  buf
}

fn find<'a>(out: &'a [SubEmission], name: &str) -> Option<&'a SubEmission> {
  out.iter().find(|e| e.name == name)
}

/// The A4xx (DSLR-A500) routes 0x0014 to `ExposureProgram` (NOT
/// `ModeDialPosition`): 247 => 'Program AE', carried at `Priority => 0`.
#[test]
fn a4xx_routes_0x14_to_exposure_program() {
  let buf = block_with_0x14(247);
  let out = parse_extra_info3(&buf, Some("DSLR-A500"), true);
  let ep = find(&out, "ExposureProgram").expect("ExposureProgram emitted");
  assert_eq!(ep.value, TagValue::Str("Program AE".into()));
  assert_eq!(ep.priority, 0, "Sony.pm Priority => 0");
  assert!(
    find(&out, "ModeDialPosition").is_none(),
    "A4xx must NOT fabricate a ModeDialPosition"
  );
  assert!(find(&out, "BatteryState").is_none());
}

/// `-n` keeps the raw byte for the A4xx ExposureProgram.
#[test]
fn a4xx_exposure_program_numeric() {
  let buf = block_with_0x14(247);
  let out = parse_extra_info3(&buf, Some("DSLR-A500"), false);
  assert_eq!(
    find(&out, "ExposureProgram").map(|e| &e.value),
    Some(&TagValue::I64(247))
  );
}

/// An A4xx ExposureProgram value not in the table renders the hash-miss
/// `"Unknown (N)"` (decimal; no `PrintHex`).
#[test]
fn a4xx_exposure_program_unknown_value() {
  let buf = block_with_0x14(242);
  let out = parse_extra_info3(&buf, Some("DSLR-A550"), true);
  assert_eq!(
    find(&out, "ExposureProgram").map(|e| &e.value),
    Some(&TagValue::Str("Unknown (242)".into()))
  );
}

/// Each A4xx body (A450/A500/A550, with the `\b` boundary) takes the
/// ExposureProgram branch.
#[test]
fn all_a4xx_bodies_route_to_exposure_program() {
  for model in ["DSLR-A450", "DSLR-A500", "DSLR-A550"] {
    let buf = block_with_0x14(255); // 255 => 'Manual'
    let out = parse_extra_info3(&buf, Some(model), true);
    assert_eq!(
      find(&out, "ExposureProgram").map(|e| &e.value),
      Some(&TagValue::Str("Manual".into())),
      "model={model}"
    );
    assert!(find(&out, "ModeDialPosition").is_none(), "model={model}");
  }
}

/// The SLT body (A33) still routes 0x0014 to `BatteryState` — the activation
/// golden's path, unchanged.
#[test]
fn slt_routes_0x14_to_battery_state() {
  let buf = block_with_0x14(5); // 5 => 'Full'
  let out = parse_extra_info3(&buf, Some("SLT-A33"), true);
  let bs = find(&out, "BatteryState").expect("BatteryState emitted");
  assert_eq!(bs.value, TagValue::Str("Full".into()));
  assert_eq!(bs.priority, 1);
  assert!(find(&out, "ExposureProgram").is_none());
  assert!(find(&out, "ModeDialPosition").is_none());
}

/// A non-A4xx DSLR (A580) routes 0x0014 to `ModeDialPosition`.
#[test]
fn other_dslr_routes_0x14_to_mode_dial_position() {
  let buf = block_with_0x14(252); // 252 => 'Auto'
  let out = parse_extra_info3(&buf, Some("DSLR-A580"), true);
  let md = find(&out, "ModeDialPosition").expect("ModeDialPosition emitted");
  assert_eq!(md.value, TagValue::Str("Auto".into()));
  assert_eq!(md.priority, 1);
  assert!(find(&out, "ExposureProgram").is_none());
  assert!(find(&out, "BatteryState").is_none());
}
