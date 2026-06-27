// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

use super::*;

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
  buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_i16(buf: &mut [u8], off: usize, v: i16) {
  buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
  buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// The parsers take the ALREADY-DECIPHERED block (the dispatcher deciphers
/// centrally), so the unit tests pass plaintext buffers directly.
fn find<'a>(em: &'a [Tag2010Emission], name: &str) -> Option<&'a TagValue> {
  em.iter().rev().find(|e| e.name == name).map(|e| &e.value)
}

/// First (walk-order) occurrence — used to target the `int32u` `ReleaseMode2`
/// row (`0x0008`/`0x0004`), which precedes the later `int8u` `ReleaseMode2`
/// (`0x112c`/`0x1018`) the sink keeps last-wins.
fn find_first<'a>(em: &'a [Tag2010Emission], name: &str) -> Option<&'a TagValue> {
  em.iter().find(|e| e.name == name).map(|e| &e.value)
}

fn as_str(tv: &TagValue) -> &str {
  match tv {
    TagValue::Str(s) => s.as_str(),
    other => panic!("expected Str, got {other:?}"),
  }
}

fn count(em: &[Tag2010Emission], name: &str) -> usize {
  em.iter().filter(|e| e.name == name).count()
}

// --- dispatch model gates ($-anchored exact match) ---------------------------

#[test]
fn variant_gates_are_exact() {
  // Tag2010a: ONLY exactly "NEX-5N".
  assert!(selects_tag2010a(Some("NEX-5N")));
  assert!(!selects_tag2010a(Some("NEX-5NX"))); // $-anchor: no trailing chars
  assert!(!selects_tag2010a(Some("NEX-5")));
  assert!(!selects_tag2010a(Some("XNEX-5N"))); // ^-anchor
  assert!(!selects_tag2010a(None));

  // Tag2010b: the SLT-A65/A77 (optional V), NEX-7/VG20E, Lunar set.
  for m in [
    "SLT-A65",
    "SLT-A65V",
    "SLT-A77",
    "SLT-A77V",
    "NEX-7",
    "NEX-VG20E",
    "Lunar",
  ] {
    assert!(selects_tag2010b(Some(m)), "{m} should select b");
  }
  assert!(!selects_tag2010b(Some("SLT-A65VX"))); // exact
  assert!(!selects_tag2010b(Some("NEX-70")));
  assert!(!selects_tag2010b(Some("NEX-5N")));

  // Tag2010c.
  for m in ["SLT-A37", "SLT-A57", "NEX-F3"] {
    assert!(selects_tag2010c(Some(m)), "{m} should select c");
  }
  assert!(!selects_tag2010c(Some("SLT-A37V")));

  // Tag2010f.
  for m in ["DSC-RX100M2", "DSC-QX10", "DSC-QX100"] {
    assert!(selects_tag2010f(Some(m)), "{m} should select f");
  }
  assert!(!selects_tag2010f(Some("DSC-RX100M3"))); // a g-variant model, not f

  // Cross-exclusion: each model selects exactly one variant.
  assert!(!selects_tag2010b(Some("NEX-5N")) && !selects_tag2010c(Some("NEX-5N")));
  assert!(!selects_tag2010f(Some("SLT-A65")));
}

/// `Tag2010d` requires the model AND `not $$self{Panorama}`.
#[test]
fn tag2010d_gate_honors_panorama() {
  for m in [
    "DSC-HX10V",
    "DSC-HX20V",
    "DSC-HX30V",
    "DSC-HX200V",
    "DSC-TX66",
    "DSC-TX200V",
    "DSC-TX300V",
    "DSC-WX50",
    "DSC-WX70",
    "DSC-WX100",
    "DSC-WX150",
  ] {
    assert!(
      selects_tag2010d(Some(m), false),
      "{m} should select d (no panorama)"
    );
    assert!(!selects_tag2010d(Some(m), true), "{m} panorama → NOT d");
  }
  assert!(!selects_tag2010d(Some("DSC-HX300"), false)); // an e-variant model
  assert!(!selects_tag2010d(None, false));
}

/// `$$self{Panorama} = ($$valPt =~ /^(\0\0)?\x01\x01/)`.
#[test]
fn detects_panorama_le_and_be() {
  assert!(detects_panorama(&[0x01, 0x01, 0x00, 0x00])); // little-endian 257
  assert!(detects_panorama(&[0x00, 0x00, 0x01, 0x01])); // big-endian 257
  assert!(!detects_panorama(&[0x00, 0x00, 0x00, 0x00]));
  assert!(!detects_panorama(&[0x01, 0x00])); // 1, not 257
  assert!(!detects_panorama(&[0x00, 0x00, 0x01])); // truncated
  assert!(!detects_panorama(&[]));
}

// --- Tag2010a ----------------------------------------------------------------

fn tag2010a_block() -> Vec<u8> {
  let mut p = vec![0u8; 0x1190];
  p[0x1128] = 1; // ReleaseMode3 → Continuous
  p[0x112c] = 2; // ReleaseMode2 → Continuous - Exposure Bracketing
  p[0x1134] = 2; // SelfTimer → Self-timer 2 s
  p[0x1138] = 1; // FlashMode → Fill-flash
  put_u16(&mut p, 0x113e, 512); // StopsAboveBaseISO → 14.0
  put_u16(&mut p, 0x1140, 15000); // BrightnessValue
  p[0x1144] = 5; // DynamicRangeOptimizer → Lv3
  p[0x1148] = 1; // HDRSetting → HDR Auto
  put_i16(&mut p, 0x114c, -256); // ExposureCompensation → +1.0
  p[0x115e] = 8; // PictureProfile (first)
  p[0x115f] = 10; // PictureProfile (second, wins)
  p[0x1163] = 1; // PictureEffect2 → Toy Camera
  p[0x1170] = 2; // Quality2 → RAW + JPEG
  p[0x1174] = 3; // MeteringMode → Spot
  p[0x1175] = 2; // ExposureProgram (%sonyExposureProgram3)
  put_u16(&mut p, 0x117c, 7000); // WB_RGBLevels[0]
  put_u16(&mut p, 0x117c + 2, 4096); // WB_RGBLevels[1]
  put_u16(&mut p, 0x117c + 4, 6500); // WB_RGBLevels[2]
  p
}

#[test]
fn tag2010a_print() {
  let p = tag2010a_block();
  let em = parse_tag2010a(&p, true);
  assert_eq!(
    find(&em, "ReleaseMode3"),
    Some(&TagValue::Str("Continuous".into()))
  );
  assert_eq!(
    find(&em, "ReleaseMode2"),
    Some(&TagValue::Str("Continuous - Exposure Bracketing".into()))
  );
  assert_eq!(
    find(&em, "SelfTimer"),
    Some(&TagValue::Str("Self-timer 2 s".into()))
  );
  assert_eq!(
    find(&em, "FlashMode"),
    Some(&TagValue::Str("Fill-flash".into()))
  );
  assert_eq!(
    find(&em, "StopsAboveBaseISO"),
    Some(&TagValue::Str("14.0".into()))
  );
  assert_eq!(
    find(&em, "BrightnessValue"),
    Some(&whole_f64_to_tag_value(15000.0 / 256.0 - 56.6))
  );
  assert_eq!(
    find(&em, "DynamicRangeOptimizer"),
    Some(&TagValue::Str("Lv3".into()))
  );
  assert_eq!(
    find(&em, "HDRSetting"),
    Some(&TagValue::Str("HDR Auto".into()))
  );
  assert_eq!(
    find(&em, "ExposureCompensation"),
    Some(&TagValue::Str("+1.0".into()))
  );
  // Two PictureProfile rows (0x115e, 0x115f); both emitted, 0x115f wins last.
  assert_eq!(count(&em, "PictureProfile"), 2);
  assert_eq!(
    find(&em, "PictureProfile"),
    Some(&TagValue::Str("Gamma Movie (PP1)".into()))
  );
  assert_eq!(
    find(&em, "PictureEffect2"),
    Some(&TagValue::Str("Toy Camera".into()))
  );
  assert_eq!(
    find(&em, "Quality2"),
    Some(&TagValue::Str("RAW + JPEG".into()))
  );
  assert_eq!(
    find(&em, "MeteringMode"),
    Some(&TagValue::Str("Spot".into()))
  );
  assert!(find(&em, "ExposureProgram").is_some());
  assert_eq!(
    find(&em, "WB_RGBLevels"),
    Some(&TagValue::Str("7000 4096 6500".into()))
  );
}

#[test]
fn tag2010a_raw() {
  let p = tag2010a_block();
  let em = parse_tag2010a(&p, false);
  assert_eq!(find(&em, "ReleaseMode3"), Some(&TagValue::I64(1)));
  assert_eq!(find(&em, "ReleaseMode2"), Some(&TagValue::I64(2)));
  assert_eq!(find(&em, "StopsAboveBaseISO"), Some(&TagValue::I64(14)));
  assert_eq!(find(&em, "ExposureCompensation"), Some(&TagValue::I64(1)));
  assert_eq!(find(&em, "PictureProfile"), Some(&TagValue::I64(10)));
  // Array rows render the same space-joined string in -n.
  assert_eq!(
    find(&em, "WB_RGBLevels"),
    Some(&TagValue::Str("7000 4096 6500".into()))
  );
}

// --- Tag2010b (sequence / date / int32u ReleaseMode2 / SonyISO / distortion) --

#[test]
fn tag2010b_scalars() {
  let mut p = vec![0u8; 0x1a50];
  put_u32(&mut p, 0x0000, 4); // SequenceImageNumber → 5
  put_u32(&mut p, 0x0004, 0); // SequenceFileNumber → 1
  put_u32(&mut p, 0x0008, 3); // ReleaseMode2 (int32u) → DRO or White Balance Bracketing
  // SonyDateTime undef[7]: year=2013, 08:15 12:34:56.
  put_u16(&mut p, 0x01b6, 2013);
  p[0x01b6 + 2] = 8;
  p[0x01b6 + 3] = 15;
  p[0x01b6 + 4] = 12;
  p[0x01b6 + 5] = 34;
  p[0x01b6 + 6] = 56;
  put_u16(&mut p, 0x1218, 2048); // SonyISO → 25600
  put_i16(&mut p, 0x1a23, 6); // DistortionCorrParams[0]
  put_i16(&mut p, 0x1a23 + 2, -7); // DistortionCorrParams[1]

  let em = parse_tag2010b(&p, true);
  assert_eq!(find(&em, "SequenceImageNumber"), Some(&TagValue::I64(5)));
  assert_eq!(find(&em, "SequenceFileNumber"), Some(&TagValue::I64(1)));
  // The int32u ReleaseMode2 (0x0008) is the FIRST of two same-named rows (the
  // int8u 0x112c follows; the sink keeps it last-wins).
  assert_eq!(
    find_first(&em, "ReleaseMode2"),
    Some(&TagValue::Str("DRO or White Balance Bracketing".into()))
  );
  assert_eq!(
    find(&em, "SonyDateTime"),
    Some(&TagValue::Str("2013:08:15 12:34:56".into()))
  );
  assert_eq!(find(&em, "SonyISO"), Some(&TagValue::Str("25600".into())));
  let dcp = as_str(find(&em, "DistortionCorrParams").unwrap());
  assert_eq!(dcp.split(' ').count(), 16);
  assert!(dcp.starts_with("6 -7 "));
}

/// `ReleaseMode2` with `Format => 'int32u'`: a value `> 255` is a hash miss →
/// `"Unknown ($val)"` carrying the FULL int32u; `-n` keeps the raw int.
#[test]
fn tag2010b_release_mode2_int32u_miss() {
  let mut p = vec![0u8; 0x10];
  put_u32(&mut p, 0x0008, 300);
  let em = parse_tag2010b(&p, true);
  assert_eq!(
    find(&em, "ReleaseMode2"),
    Some(&TagValue::Str("Unknown (300)".into()))
  );
  let em_n = parse_tag2010b(&p, false);
  assert_eq!(find(&em_n, "ReleaseMode2"), Some(&TagValue::I64(300)));
}

// --- Tag2010c (DigitalZoomRatio) ---------------------------------------------

#[test]
fn tag2010c_digital_zoom_and_iso() {
  let mut p = vec![0u8; 0x1200];
  p[0x0200] = 24; // DigitalZoomRatio → 24/16 = 1.5 (no PrintConv → both modes)
  put_u16(&mut p, 0x11f4, 1792); // SonyISO → 100*2^(16-7) = 51200
  p[0x1143] = 0; // PictureEffect2 → Off
  let em = parse_tag2010c(&p, true);
  assert_eq!(find(&em, "DigitalZoomRatio"), Some(&TagValue::F64(1.5)));
  assert_eq!(find(&em, "SonyISO"), Some(&TagValue::Str("51200".into())));
  assert_eq!(
    find(&em, "PictureEffect2"),
    Some(&TagValue::Str("Off".into()))
  );
  // -n keeps DigitalZoomRatio identical (no PrintConv).
  let em_n = parse_tag2010c(&p, false);
  assert_eq!(find(&em_n, "DigitalZoomRatio"), Some(&TagValue::F64(1.5)));
}

// --- Tag2010d (no ExposureCompensation / Quality2) ---------------------------

#[test]
fn tag2010d_offsets_and_absent_rows() {
  let mut p = vec![0u8; 0x1280];
  p[0x1180] = 1; // ReleaseMode3 → Continuous
  put_u16(&mut p, 0x1196, 512); // StopsAboveBaseISO → 14.0
  p[0x11d0] = 0; // MeteringMode → Multi-segment
  p[0x11d1] = 2; // ExposureProgram
  put_u16(&mut p, 0x1270, 2048); // SonyISO → 25600
  let em = parse_tag2010d(&p, true);
  assert_eq!(
    find(&em, "ReleaseMode3"),
    Some(&TagValue::Str("Continuous".into()))
  );
  assert_eq!(
    find(&em, "StopsAboveBaseISO"),
    Some(&TagValue::Str("14.0".into()))
  );
  assert_eq!(
    find(&em, "MeteringMode"),
    Some(&TagValue::Str("Multi-segment".into()))
  );
  assert_eq!(find(&em, "SonyISO"), Some(&TagValue::Str("25600".into())));
  // Tag2010d has NO ExposureCompensation / Quality2 rows.
  assert!(find(&em, "ExposureCompensation").is_none());
  assert!(find(&em, "Quality2").is_none());
}

// --- Tag2010f (ReleaseMode2 @0x0004, focal lengths, aspect ratio) ------------

#[test]
fn tag2010f_focal_and_aspect() {
  let mut p = vec![0u8; 0x1940];
  put_u32(&mut p, 0x0004, 1); // ReleaseMode2 (int32u, NOT at 0x08) → Continuous
  put_u16(&mut p, 0x1134, 240); // FocalLength → 24.0 mm
  put_u16(&mut p, 0x1136, 100); // MinFocalLength → 10.0 mm
  put_u16(&mut p, 0x1138, 0); // MaxFocalLength → 0.0 mm (no RawConv drop in f)
  put_u16(&mut p, 0x113c, 2048); // SonyISO → 25600
  p[0x192c] = 2; // AspectRatio → 3:2
  let em = parse_tag2010f(&p, true);
  // The int32u ReleaseMode2 (0x0004) is the FIRST of two same-named rows (the
  // int8u 0x1018 follows; the sink keeps it last-wins).
  assert_eq!(
    find_first(&em, "ReleaseMode2"),
    Some(&TagValue::Str("Continuous".into()))
  );
  assert_eq!(
    find(&em, "FocalLength"),
    Some(&TagValue::Str("24.0 mm".into()))
  );
  assert_eq!(
    find(&em, "MinFocalLength"),
    Some(&TagValue::Str("10.0 mm".into()))
  );
  assert_eq!(
    find(&em, "MaxFocalLength"),
    Some(&TagValue::Str("0.0 mm".into()))
  );
  assert_eq!(find(&em, "SonyISO"), Some(&TagValue::Str("25600".into())));
  assert_eq!(find(&em, "AspectRatio"), Some(&TagValue::Str("3:2".into())));

  let em_n = parse_tag2010f(&p, false);
  assert_eq!(find(&em_n, "FocalLength"), Some(&TagValue::I64(24)));
  assert_eq!(find(&em_n, "MaxFocalLength"), Some(&TagValue::I64(0)));
}

// --- shared-conversion edges -------------------------------------------------

/// `StopsAboveBaseISO` ValueConv of exactly 0 prints the bare integer `0`;
/// `ExposureCompensation` of 0 prints `0`, a negative `int16s` prints `-X.X`.
#[test]
fn gain_zero_and_exposure_comp_signs() {
  let mut p = vec![0u8; 0x1190];
  put_u16(&mut p, 0x113e, 4096); // StopsAboveBaseISO = 16 - 16 = 0 → bare 0
  put_i16(&mut p, 0x114c, 256); // ExposureCompensation = -256/256 = -1.0
  let em = parse_tag2010a(&p, true);
  assert_eq!(find(&em, "StopsAboveBaseISO"), Some(&TagValue::I64(0)));
  assert_eq!(
    find(&em, "ExposureCompensation"),
    Some(&TagValue::Str("-1.0".into()))
  );

  // ExposureCompensation = 0 → bare integer 0 (both modes).
  let zero = vec![0u8; 0x1190];
  let em0 = parse_tag2010a(&zero, true);
  assert_eq!(find(&em0, "ExposureCompensation"), Some(&TagValue::I64(0)));
}

/// `%pictureProfile2010` is the FULL hash — value 37 → "FL" (which `Tag9416`'s
/// truncated copy lacks); value 2 has no label → a miss.
#[test]
fn picture_profile_full_hash() {
  let mut p = vec![0u8; 0x1190];
  p[0x115f] = 37; // FL
  let em = parse_tag2010a(&p, true);
  assert_eq!(
    find(&em, "PictureProfile"),
    Some(&TagValue::Str("FL".into()))
  );

  let mut p2 = vec![0u8; 0x1190];
  p2[0x115e] = 2; // no label
  p2[0x115f] = 2;
  let em2 = parse_tag2010a(&p2, true);
  assert_eq!(
    find(&em2, "PictureProfile"),
    Some(&TagValue::Str("Unknown (2)".into()))
  );
}

/// Per-field availability: a buffer ending before an offset emits the earlier
/// leaves only; an empty buffer emits nothing.
#[test]
fn per_field_truncation() {
  let mut p = vec![0u8; 0x1140]; // ends just before BrightnessValue (0x1140)
  p[0x1128] = 1; // ReleaseMode3
  put_u16(&mut p, 0x113e, 512); // StopsAboveBaseISO
  let em = parse_tag2010a(&p, true);
  assert!(find(&em, "ReleaseMode3").is_some());
  assert!(find(&em, "StopsAboveBaseISO").is_some());
  assert!(find(&em, "BrightnessValue").is_none()); // 0x1140 out of range
  assert!(find(&em, "WB_RGBLevels").is_none());

  assert!(parse_tag2010a(&[], true).is_empty());
  assert!(parse_tag2010b(&[], true).is_empty());
  assert!(parse_tag2010c(&[], true).is_empty());
  assert!(parse_tag2010d(&[], true).is_empty());
  assert!(parse_tag2010f(&[], true).is_empty());
}
