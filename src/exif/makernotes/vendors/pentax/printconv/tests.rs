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

#[test]
fn hue_p1_311() {
  // 0x0067 Hue — Pentax.avi: raw 1 => "Normal" (text label); `-n` => 1.
  let conv = PentaxPrintConv::Hash(super::super::tags::HUE);
  assert_eq!(conv.apply(&u(&[1]), true), TagValue::Str("Normal".into()));
  assert_eq!(conv.apply(&u(&[1]), false), TagValue::I64(1));
  // An INTEGER label (`0 => -2`) is stored as decimal text; the JSON number gate
  // renders it as the bare number -2 (not a quoted string).
  let v = conv.apply(&u(&[0]), true);
  assert_eq!(v, TagValue::Str("-2".into()));
  assert!(
    crate::value::escape_json_is_number(match &v {
      TagValue::Str(s) => s,
      _ => unreachable!(),
    }),
    "Hue integer label renders as a bare JSON number"
  );
  // 65535 => "None".
  assert_eq!(conv.apply(&u(&[65535]), true), TagValue::Str("None".into()));
}

#[test]
fn monochrome_filter_effect_and_toning_p1_311() {
  // 0x0073 / 0x0074 — Pentax.avi: raw 65535 => "None"; `-n` => 65535.
  let mfe = PentaxPrintConv::Hash(super::super::tags::MONOCHROME_FILTER_EFFECT);
  assert_eq!(mfe.apply(&u(&[65535]), true), TagValue::Str("None".into()));
  assert_eq!(mfe.apply(&u(&[65535]), false), TagValue::I64(65535));
  assert_eq!(mfe.apply(&u(&[1]), true), TagValue::Str("Green".into()));
  let mt = PentaxPrintConv::Hash(super::super::tags::MONOCHROME_TONING);
  assert_eq!(mt.apply(&u(&[65535]), true), TagValue::Str("None".into()));
  // Integer label `4 => 0` renders as the bare number 0.
  assert_eq!(mt.apply(&u(&[4]), true), TagValue::Str("0".into()));
  assert_eq!(mt.apply(&u(&[0]), true), TagValue::Str("-4".into()));
}

#[test]
fn cross_process_p1_311() {
  // 0x007b CrossProcess — Pentax.avi: raw 0 => "Off"; `-n` => 0.
  let conv = PentaxPrintConv::Hash(super::super::tags::CROSS_PROCESS);
  assert_eq!(conv.apply(&u(&[0]), true), TagValue::Str("Off".into()));
  assert_eq!(conv.apply(&u(&[0]), false), TagValue::I64(0));
  assert_eq!(
    conv.apply(&u(&[33]), true),
    TagValue::Str("Favorite 1".into())
  );
}

#[test]
fn high_low_key_adj_p1_311() {
  // 0x006c HighLowKeyAdj — int16s Count 2, StringKeyedHash on the joined pair.
  // Pentax.avi: [0,0] => "0" (bare number); `-n` => "0 0".
  let conv = PentaxPrintConv::StringKeyedHash(HIGH_LOW_KEY_ADJ);
  let raw = RawValue::I64(std::vec![0, 0]);
  assert_eq!(conv.apply(&raw, true), TagValue::Str("0".into()));
  assert_eq!(conv.apply(&raw, false), TagValue::Str("0 0".into()));
  // A negative pair maps to its signed integer label.
  assert_eq!(
    conv.apply(&RawValue::I64(std::vec![-4, 0]), true),
    TagValue::Str("-4".into())
  );
}

#[test]
fn string_leaves_preserve_trailing_spaces_p1_311() {
  // 0x0230 FirmwareVersion — plain `string` via `None`: the trailing spaces the
  // K-x writes survive (only the on-disk NUL terminator is trimmed by the
  // Walker). The empty 0x022e/0x022f Artist/Copyright render as "".
  let conv = PentaxPrintConv::None;
  let fw = RawValue::Text {
    text: "K-x Ver 1.00           ".into(),
    raw: b"K-x Ver 1.00           ".to_vec().into_boxed_slice(),
  };
  assert_eq!(
    conv.apply(&fw, true),
    TagValue::Str("K-x Ver 1.00           ".into())
  );
  let empty = RawValue::Text {
    text: std::string::String::new(),
    raw: std::boxed::Box::default(),
  };
  assert_eq!(conv.apply(&empty, true), TagValue::Str("".into()));
}

#[test]
fn interval_shooting_off_and_shot_count() {
  // 0x0092 IntervalShooting — int16u Count 2. `'0 0' => 'Off'`; the K-S2 golden
  // value (default state). The added branches do NOT change this output.
  let conv = PentaxPrintConv::IntervalShooting;
  assert_eq!(conv.apply(&u(&[0, 0]), true), TagValue::Str("Off".into()));
  // `-n`: the raw space-joined run (no ValueConv) — unchanged from the old
  // StringKeyedHash behaviour, so the K-S2 `-n` golden is byte-identical.
  assert_eq!(conv.apply(&u(&[0, 0]), false), TagValue::Str("0 0".into()));
  // The OTHER => sub forward branch `s/(\d+) (\d+)/Shot $1 of $2/`: a non-'0 0'
  // pair renders "Shot <shot> of <total>" (previously rendered "Unknown (3 10)").
  assert_eq!(
    conv.apply(&u(&[3, 10]), true),
    TagValue::Str("Shot 3 of 10".into())
  );
  assert_eq!(
    conv.apply(&u(&[1, 5]), true),
    TagValue::Str("Shot 1 of 5".into())
  );
  // `-n` still the raw run for a non-default value.
  assert_eq!(
    conv.apply(&u(&[3, 10]), false),
    TagValue::Str("3 10".into())
  );
  // A single-element value has no `\d+ \d+` pair ⇒ Perl's substitution is a
  // no-op and the value passes through unchanged.
  assert_eq!(conv.apply(&u(&[7]), true), TagValue::Str("7".into()));
}

#[test]
fn clarity_control_off_signed_and_unknown() {
  // 0x0096 ClarityControl — int8s Count 2. `'0 0' => 'Off'`; the K-S2 golden
  // value (default state). The added branches do NOT change this output.
  let conv = PentaxPrintConv::ClarityControl;
  let off = RawValue::I64(std::vec![0, 0]);
  assert_eq!(conv.apply(&off, true), TagValue::Str("Off".into()));
  // `-n`: the raw space-joined run (no ValueConv) — byte-identical to the old
  // StringKeyedHash behaviour, so the K-S2 `-n` golden is unchanged.
  assert_eq!(conv.apply(&off, false), TagValue::Str("0 0".into()));
  // The OTHER => sub forward branch `^1 (-?\d+)$ → $1 ? sprintf('%+d') : 0`:
  // a negative offset renders the signed integer string.
  assert_eq!(
    conv.apply(&RawValue::I64(std::vec![1, -2]), true),
    TagValue::Str("-2".into())
  );
  // A positive offset renders with the explicit `+` sign.
  assert_eq!(
    conv.apply(&RawValue::I64(std::vec![1, 3]), true),
    TagValue::Str("+3".into())
  );
  // `$1 ? ... : 0` — a zero offset yields the bare integer `0` (a JSON number),
  // NOT "+0" and NOT "Off".
  assert_eq!(
    conv.apply(&RawValue::I64(std::vec![1, 0]), true),
    TagValue::I64(0)
  );
  // A value not of the `1 N` shape falls to the else arm ⇒ "Unknown (...)".
  assert_eq!(
    conv.apply(&RawValue::I64(std::vec![2, 5]), true),
    TagValue::Str("Unknown (2 5)".into())
  );
  // `-n` for a non-default value is still the raw run.
  assert_eq!(
    conv.apply(&RawValue::I64(std::vec![1, -2]), false),
    TagValue::Str("1 -2".into())
  );
}

#[test]
fn af_points_in_focus_ks2_bottom_row_bits() {
  // 0x000f AFPointsInFocus (K-3/K-S1/K-S2 variant) — int32u, PrintHex, a
  // `{0 => '(none)', BITMASK => {0..26}}` DecodeBits PrintConv.
  let conv = PentaxPrintConv::AfPointsInFocus;
  // Zero ⇒ the explicit '(none)' key.
  assert_eq!(conv.apply(&u(&[0]), true), TagValue::Str("(none)".into()));
  // The K-S2 golden value: bit 13 = "Center" (0x2000). The full table does NOT
  // change this — the golden stays byte-identical.
  assert_eq!(
    conv.apply(&u(&[0x2000]), true),
    TagValue::Str("Center".into())
  );
  // Bit 24 ("Bottom") was previously MISSING from the table (it only had bits
  // 0..21) and rendered "[24]"; the appended bits 22..26 now resolve it.
  assert_eq!(
    conv.apply(&u(&[1 << 24]), true),
    TagValue::Str("Bottom".into())
  );
  // The two endpoints of the previously-missing run: bit 22 "Bottom-left",
  // bit 26 "Bottom-right" (DecodeBits joins set bits with ", ").
  assert_eq!(
    conv.apply(&u(&[(1 << 22) | (1 << 26)]), true),
    TagValue::Str("Bottom-left, Bottom-right".into())
  );
  // `-n`: the raw int.
  assert_eq!(conv.apply(&u(&[1 << 24]), false), TagValue::I64(1 << 24));
}

#[test]
fn af_point_selected_model_special_high_values() {
  // 0x000e AFPointSelected — the model-keyed element-0 hashes carry the
  // `0xfffb`-`0xffff` SPECIAL selections (Pentax.pm:1225-1230 K-1, 1302-1306
  // K-3/KP, 1382-1387 "other models"). The 6 body fixtures only ever exercise a
  // normal point (the K-3/KP fixture is raw 14 = "Center"), so these specials are
  // unexercised by the goldens — assert them directly via the model dispatcher.
  // Same defect class as `af_points_in_focus_ks2_bottom_row_bits` (a PrintConv
  // table missing the high values the fixtures don't hit).

  // K-3 / KP variant (AF_POINT_SELECTED_K3): the five specials previously MISSING
  // from the table rendered "Unknown (6553x)"; they now resolve.
  let kp = Some("PENTAX KP");
  assert_eq!(
    af_point_selected_for_model(&u(&[0xffff]), true, kp),
    TagValue::Str("Auto".into())
  );
  assert_eq!(
    af_point_selected_for_model(&u(&[0xfffe]), true, kp),
    TagValue::Str("Fixed Center".into())
  );
  assert_eq!(
    af_point_selected_for_model(&u(&[0xfffc]), true, Some("PENTAX K-3 Mark III")),
    TagValue::Str("Face Detect AF".into())
  );
  assert_eq!(
    af_point_selected_for_model(&u(&[0xfffb]), true, Some("PENTAX K-3")),
    TagValue::Str("AF Select".into())
  );
  // The K-3/KP fixture value (raw 14 = the normal "Center" point) is UNCHANGED by
  // the appended specials — the golden stays byte-identical.
  assert_eq!(
    af_point_selected_for_model(&u(&[14]), true, kp),
    TagValue::Str("Center".into())
  );
  // The K-3/KP hash has NO `0xfffa` (that is the "other models" 'Auto 2' only) ⇒
  // a K-3 raw 0xfffa misses ⇒ decimal "Unknown (N)" (no PrintHex on this leaf).
  assert_eq!(
    af_point_selected_for_model(&u(&[0xfffa]), true, kp),
    TagValue::Str("Unknown (65530)".into())
  );

  // K-1 / 645Z variant (AF_POINT_SELECTED_K1): the same five specials, plus its
  // own 33-point geometry (raw 17 = "Center" here, NOT 14).
  let k1 = Some("PENTAX K-1");
  assert_eq!(
    af_point_selected_for_model(&u(&[0xffff]), true, k1),
    TagValue::Str("Auto".into())
  );
  assert_eq!(
    af_point_selected_for_model(&u(&[0xfffd]), true, Some("PENTAX 645Z")),
    TagValue::Str("Automatic Tracking AF".into())
  );
  assert_eq!(
    af_point_selected_for_model(&u(&[17]), true, k1),
    TagValue::Str("Center".into())
  );

  // "other models" variant (AF_POINT_SELECTED): already had all six specials,
  // INCLUDING `0xfffa` 'Auto 2'. The K10D fixture is the single-element record.
  let k10d = Some("PENTAX K10D");
  assert_eq!(
    af_point_selected_for_model(&u(&[0xfffa]), true, k10d),
    TagValue::Str("Auto 2".into())
  );
  assert_eq!(
    af_point_selected_for_model(&u(&[0xffff]), true, k10d),
    TagValue::Str("Auto".into())
  );

  // The count-2 record threads the element-1 AREA hash (a special in element 0,
  // an Expanded-Area size in element 1, joined "; "). K-3/KP element 1 = the
  // 27-point ladder; K-1 element 1 = the 33-point ladder.
  assert_eq!(
    af_point_selected_for_model(&u(&[0xffff, 5]), true, kp),
    TagValue::Str("Auto; Expanded Area 27-point (L)".into())
  );
  assert_eq!(
    af_point_selected_for_model(&u(&[0xfffe, 5]), true, k1),
    TagValue::Str("Fixed Center; Expanded Area 33-point (L)".into())
  );

  // `-n` (print_conv = false) is the space-joined raw run for every model, so a
  // special value is NOT label-decoded.
  assert_eq!(
    af_point_selected_for_model(&u(&[0xffff]), false, kp),
    TagValue::Str("65535".into())
  );
}
