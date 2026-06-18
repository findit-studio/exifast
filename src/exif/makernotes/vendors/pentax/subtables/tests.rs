// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

use super::*;
use crate::value::TagValue;

/// The verbatim K10D `CameraSettings` (0x0205) block from the `Pentax.jpg`
/// fixture (`exiftool -v3`: 23 bytes, `undef[23]`, BigEndian).
const CAMERA_SETTINGS_K10D: &[u8] = &[
  0x05, 0xa0, 0x50, 0x11, 0x00, 0x20, 0x20, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x25, 0x01, 0x9c,
  0x50, 0xe0, 0x81, 0x7f, 0x20, 0x3b, 0x00,
];

/// The verbatim K10D `AEInfo` (0x0206) block (16 bytes, `undef[16]`).
const AEINFO_K10D: &[u8] = &[
  0x7a, 0x7f, 0x20, 0x3b, 0x00, 0xa4, 0x01, 0x00, 0x1c, 0x64, 0x64, 0x8c, 0x00, 0x40, 0x00, 0x9d,
];

/// The verbatim K-x AVI `AEInfo` (0x0206) block (24 bytes, `undef[24]`) — the
/// `$size > 20` Hook shifts offsets 8+ by one.
const AEINFO_KX: &[u8] = &[
  0x73, 0x63, 0x33, 0x40, 0x00, 0xa8, 0x23, 0x00, 0xa1, 0x00, 0x64, 0x63, 0x90, 0x00, 0x40, 0xf8,
  0x6f, 0x63, 0x11, 0x11, 0x01, 0x04, 0x5a, 0x01,
];

/// The verbatim K10D `FlashInfo` (0x0208) block (27 bytes, `undef[27]`).
const FLASHINFO_K10D: &[u8] = &[
  0x00, 0xf5, 0x3f, 0x12, 0x00, 0x00, 0x00, 0x00, 0x96, 0x14, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// The verbatim K10D `LensInfo2` (0x0207) record from the `Pentax.jpg` fixture
/// (`exiftool -v3`: 69 bytes, `undef[69]`, BigEndian). Offset 0-3 = `LensType`
/// (`83 00 00 2c`); offset 4-20 = the nested `LensData` `undef[17]`
/// (`00 28 94 33 5b 53 86 ea 41 40 88 50 38 01 40 6c 03`); the trailing bytes are
/// the rest of the record (unused by the five ported leaves).
const LENSINFO2_K10D: &[u8] = &[
  0x83, 0x00, 0x00, 0x2c, 0x00, 0x28, 0x94, 0x33, 0x5b, 0x53, 0x86, 0xea, 0x41, 0x40, 0x88, 0x50,
  0x38, 0x01, 0x40, 0x6c, 0x03, 0xff, 0xff, 0xff, 0x00, 0x00, 0x53, 0x86, 0xea, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0xbf, 0xea, 0x00, 0x00, 0x00, 0x86, 0x16, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00,
];

fn find<'a>(em: &'a [VendorEmission], name: &str) -> Option<&'a TagValue> {
  em.iter()
    .find(|e| e.name() == name)
    .map(VendorEmission::value)
}

fn s(v: &str) -> TagValue {
  TagValue::Str(v.into())
}

#[test]
fn pentax_ev_matches_perl_oracle() {
  // PentaxEv(0) = 0; PentaxEv(64-59=5) -> frac 5 -> 5 + (16/3-5) = 16/3 -> /8 = 2/3.
  assert!((pentax_ev(0) - 0.0).abs() < 1e-12);
  assert!((pentax_ev(5) - (2.0 / 3.0)).abs() < 1e-12);
  // PentaxEv(3): frac 3 -> 3 + (8/3-3) = 8/3 -> /8 = 1/3.
  assert!((pentax_ev(3) - (1.0 / 3.0)).abs() < 1e-12);
  // Even value: straight /8.
  assert!((pentax_ev(8) - 1.0).abs() < 1e-12);
}

#[test]
fn camera_settings_k10d_print_conv_byte_exact() {
  // -j (PrintConv) — the K10D model gate is active. Values verified against
  // `exiftool -G1 -j Pentax.jpg`.
  let mut em = Vec::new();
  emit_camera_settings(CAMERA_SETTINGS_K10D, 23, Some("PENTAX K10D"), true, &mut em);

  assert_eq!(find(&em, "PictureMode2"), Some(&s("Aperture Priority")));
  assert_eq!(find(&em, "ProgramLine"), Some(&s("Normal")));
  assert_eq!(find(&em, "EVSteps"), Some(&s("1/3 EV Steps")));
  assert_eq!(find(&em, "E-DialInProgram"), Some(&s("Tv or Av")));
  assert_eq!(find(&em, "ApertureRingUse"), Some(&s("Permitted")));
  assert_eq!(find(&em, "FlashOptions"), Some(&s("Wireless (Master)")));
  assert_eq!(find(&em, "MeteringMode2"), Some(&s("Multi-segment")));
  assert_eq!(find(&em, "AFPointMode"), Some(&s("Select")));
  assert_eq!(find(&em, "FocusMode2"), Some(&s("AF-S")));
  assert_eq!(find(&em, "AFPointSelected2"), Some(&s("Center")));
  assert_eq!(find(&em, "ISOFloor"), Some(&TagValue::I64(100)));
  assert_eq!(find(&em, "DriveMode2"), Some(&s("Single-frame")));
  assert_eq!(find(&em, "ExposureBracketStepSize"), Some(&s("0.3")));
  assert_eq!(find(&em, "BracketShotNumber"), Some(&s("n/a")));
  assert_eq!(find(&em, "WhiteBalanceSet"), Some(&s("Auto")));
  assert_eq!(find(&em, "MultipleExposureSet"), Some(&s("Off")));
  // K10D-only (offset 13+).
  assert_eq!(
    find(&em, "RawAndJpgRecording"),
    Some(&s("RAW+JPEG (PEF, Better)"))
  );
  assert_eq!(find(&em, "JpgRecordedPixels"), Some(&s("6 MP")));
  assert_eq!(find(&em, "FlashOptions2"), Some(&s("Wireless (Master)")));
  assert_eq!(find(&em, "MeteringMode3"), Some(&s("Multi-segment")));
  assert_eq!(find(&em, "SRActive"), Some(&s("Yes")));
  assert_eq!(find(&em, "Rotation"), Some(&s("Rotate 270 CW")));
  assert_eq!(find(&em, "ISOSetting"), Some(&s("Manual")));
  assert_eq!(find(&em, "SensitivitySteps"), Some(&s("1 EV Steps")));
  assert_eq!(find(&em, "TvExposureTimeSetting"), Some(&s("1/203")));
  assert_eq!(find(&em, "AvApertureSetting"), Some(&s("12.7")));
  assert_eq!(find(&em, "SvISOSetting"), Some(&TagValue::I64(100)));
  assert_eq!(find(&em, "BaseExposureCompensation"), Some(&s("+0.7")));
  // 28 leaves total for the K10D variant.
  assert_eq!(em.len(), 28, "K10D CameraSettings emits 28 leaves");
}

#[test]
fn camera_settings_k10d_value_conv_floats() {
  // -n (ValueConv) — the exp/log leaves are raw f64s.
  let mut em = Vec::new();
  emit_camera_settings(
    CAMERA_SETTINGS_K10D,
    23,
    Some("PENTAX K10D"),
    false,
    &mut em,
  );
  // ISOFloor / SvISOSetting are integer (int(... + 0.5)).
  assert_eq!(find(&em, "ISOFloor"), Some(&TagValue::I64(100)));
  assert_eq!(find(&em, "SvISOSetting"), Some(&TagValue::I64(100)));
  // The enum/bitfield leaves are raw ints under -n.
  assert_eq!(find(&em, "PictureMode2"), Some(&TagValue::I64(5)));
  assert_eq!(find(&em, "ApertureRingUse"), Some(&TagValue::I64(1)));
  assert_eq!(find(&em, "AFPointSelected2"), Some(&TagValue::I64(32)));
  // The float ValueConv leaves.
  let approx = |name: &str, want: f64| {
    let TagValue::F64(g) = find(&em, name).expect(name) else {
      panic!("{name} is not F64");
    };
    assert!((g - want).abs() < 1e-9, "{name} = {g}, want {want}");
  };
  approx("TvExposureTimeSetting", 0.004_921_566_601_151_85);
  approx("AvApertureSetting", 12.699_208_415_745_6);
  approx("BaseExposureCompensation", 0.666_666_666_666_667);
}

#[test]
fn camera_settings_non_k10d_count_does_not_misdecode() {
  // The K-01 variant has `$count == 25` ⇒ `Condition => '$count < 25'` FAILS,
  // so the K10D layout MUST NOT decode (the scope-fence): ZERO emissions.
  let mut em = Vec::new();
  emit_camera_settings(CAMERA_SETTINGS_K10D, 25, Some("PENTAX K-01"), true, &mut em);
  assert!(
    em.is_empty(),
    "a $count >= 25 record must not decode the K10D layout"
  );

  // A larger count too.
  let mut em2 = Vec::new();
  emit_camera_settings(
    CAMERA_SETTINGS_K10D,
    64,
    Some("PENTAX K10D"),
    true,
    &mut em2,
  );
  assert!(em2.is_empty());
}

#[test]
fn camera_settings_non_k10d_model_skips_offset13_leaves() {
  // A different body with `$count < 25` (e.g. *istD, count 16): the BASE leaves
  // emit, but the offset-13+ `$$self{Model} =~ /(K10D|GX10)\b/` leaves do NOT.
  let mut em = Vec::new();
  emit_camera_settings(
    CAMERA_SETTINGS_K10D,
    16,
    Some("PENTAX *ist D"),
    true,
    &mut em,
  );
  // Base leaf present.
  assert_eq!(find(&em, "PictureMode2"), Some(&s("Aperture Priority")));
  assert_eq!(find(&em, "ISOFloor"), Some(&TagValue::I64(100)));
  // K10D-only leaves ABSENT.
  assert!(
    find(&em, "RawAndJpgRecording").is_none(),
    "offset-13+ is K10D-only"
  );
  assert!(find(&em, "SRActive").is_none());
  assert!(find(&em, "AvApertureSetting").is_none());
  assert!(find(&em, "BaseExposureCompensation").is_none());
  // GX10 matches the gate too.
  let mut em_gx = Vec::new();
  emit_camera_settings(
    CAMERA_SETTINGS_K10D,
    16,
    Some("PENTAX GX10"),
    true,
    &mut em_gx,
  );
  assert_eq!(find(&em_gx, "SRActive"), Some(&s("Yes")));
}

#[test]
fn aeinfo_k10d_print_conv_byte_exact() {
  let mut em = Vec::new();
  emit_aeinfo(AEINFO_K10D, 16, true, &mut em);
  assert_eq!(find(&em, "AEExposureTime"), Some(&s("1/101")));
  assert_eq!(find(&em, "AEAperture"), Some(&s("12.9")));
  assert_eq!(find(&em, "AE_ISO"), Some(&TagValue::I64(100)));
  assert_eq!(find(&em, "AEXv"), Some(&TagValue::F64(-0.625)));
  assert_eq!(find(&em, "AEBXv"), Some(&TagValue::F64(0.0)));
  assert_eq!(find(&em, "AEMinExposureTime"), Some(&s("1/3862")));
  assert_eq!(find(&em, "AEProgramMode"), Some(&s("Av, B or X")));
  assert_eq!(find(&em, "AEApertureSteps"), Some(&TagValue::I64(28)));
  assert_eq!(find(&em, "AEMaxAperture"), Some(&s("4.0")));
  assert_eq!(find(&em, "AEMaxAperture2"), Some(&s("4.0")));
  assert_eq!(find(&em, "AEMinAperture"), Some(&s("23")));
  assert_eq!(find(&em, "AEMeteringMode"), Some(&s("Multi-segment")));
  assert_eq!(find(&em, "FlashExposureCompSet"), Some(&TagValue::I64(0)));
  // AEFlags (offset 7) is NEVER emitted (RawConv drops it without -U).
  assert!(find(&em, "AEFlags").is_none());
  assert_eq!(em.len(), 13, "K10D AEInfo emits 13 leaves");
}

#[test]
fn aeinfo_non_k10d_count_does_not_misdecode() {
  // K-01 (AEInfo2) has `$count == 21` ⇒ `$count != 21` FAILS ⇒ no decode.
  let mut em = Vec::new();
  emit_aeinfo(AEINFO_K10D, 21, true, &mut em);
  assert!(
    em.is_empty(),
    "a $count == 21 record must not decode through AEInfo"
  );
  // AEInfo3 (K-30) has count 48/64 ⇒ `$count <= 25` FAILS ⇒ no decode.
  let mut em2 = Vec::new();
  emit_aeinfo(AEINFO_K10D, 48, true, &mut em2);
  assert!(em2.is_empty());
}

#[test]
fn flashinfo_k10d_print_conv_byte_exact() {
  let mut em = Vec::new();
  emit_flashinfo(FLASHINFO_K10D, 27, true, &mut em);
  assert_eq!(find(&em, "FlashStatus"), Some(&s("Off")));
  assert_eq!(
    find(&em, "InternalFlashMode"),
    Some(&s("Did not fire, Wireless (Master)"))
  );
  assert_eq!(find(&em, "ExternalFlashMode"), Some(&s("Off")));
  assert_eq!(find(&em, "InternalFlashStrength"), Some(&TagValue::I64(18)));
  assert_eq!(find(&em, "TTL_DA_AUp"), Some(&TagValue::I64(0)));
  assert_eq!(find(&em, "TTL_DA_ADown"), Some(&TagValue::I64(0)));
  assert_eq!(find(&em, "TTL_DA_BUp"), Some(&TagValue::I64(0)));
  assert_eq!(find(&em, "TTL_DA_BDown"), Some(&TagValue::I64(0)));
  assert_eq!(find(&em, "ExternalFlashGuideNumber"), Some(&s("n/a")));
  assert_eq!(find(&em, "ExternalFlashExposureComp"), Some(&s("n/a")));
  assert_eq!(find(&em, "ExternalFlashBounce"), Some(&s("n/a")));
  assert_eq!(em.len(), 11, "K10D FlashInfo emits 11 leaves");
}

#[test]
fn flashinfo_non_k10d_count_does_not_misdecode() {
  // The Q/Q10 FlashInfoUnknown variant (or any count != 27) ⇒ no decode.
  let mut em = Vec::new();
  emit_flashinfo(FLASHINFO_K10D, 32, true, &mut em);
  assert!(
    em.is_empty(),
    "a $count != 27 record must not decode through FlashInfo"
  );
}

#[test]
fn external_flash_guide_number_oracle() {
  // val 0 -> 0.0 (renders "n/a"); val 29 -> -3 -> 2**(-3/16+4) ~ 14.5; val 6 -> 2**(6/16+4) ~ 20.7.
  assert_eq!(external_flash_guide_number(0), 0.0);
  assert!((external_flash_guide_number(29) - 2.0_f64.powf(-3.0 / 16.0 + 4.0)).abs() < 1e-9);
  assert!((external_flash_guide_number(6) - 2.0_f64.powf(6.0 / 16.0 + 4.0)).abs() < 1e-9);
}

#[test]
fn truncated_block_skips_out_of_range_leaves() {
  // A short CameraSettings block (only 3 bytes) with a K10D count gate: the
  // in-range leaves decode, the rest are skipped (no panic, no OOB).
  let mut em = Vec::new();
  emit_camera_settings(
    &CAMERA_SETTINGS_K10D[..3],
    23,
    Some("PENTAX K10D"),
    true,
    &mut em,
  );
  // Offsets 0-2 decode (PictureMode2, the byte-1 + byte-2 bitfields).
  assert_eq!(find(&em, "PictureMode2"), Some(&s("Aperture Priority")));
  assert_eq!(find(&em, "FlashOptions"), Some(&s("Wireless (Master)")));
  // Offset 3+ skipped.
  assert!(find(&em, "FocusMode2").is_none());
  assert!(find(&em, "ISOFloor").is_none());
}

#[test]
fn aeinfo_size_over_20_shifts_offsets() {
  // The K-x AVI AEInfo is 24 bytes ⇒ the AEFlags Hook (`$size > 20`) shifts
  // offsets 8+ by one. AEApertureSteps reads byte 9 (= 0x00 = 0), NOT byte 8
  // (= 0xa1 = 161). Verified against `exiftool -v3 Pentax.avi`.
  let mut em = Vec::new();
  emit_aeinfo(AEINFO_KX, 24, true, &mut em);
  // Offsets 0-7 are unshifted.
  assert_eq!(find(&em, "AEProgramMode"), Some(&s("Standard"))); // byte 6 = 0x23 = 35
  // Offset 8+ shifted: AEApertureSteps reads byte 9 = 0.
  assert_eq!(find(&em, "AEApertureSteps"), Some(&TagValue::I64(0)));
  // FlashExposureCompSet reads byte 15 (= 0xf8 = -8 int8s) ⇒ PentaxEv(-8) = -1.
  assert_eq!(find(&em, "FlashExposureCompSet"), Some(&s("-1.0")));
  // The size-24-only AEWhiteBalance / AEMeteringMode2 / LevelIndicator are NOT
  // emitted by this Phase-2a port (deferred).
  assert!(find(&em, "AEWhiteBalance").is_none());
  assert!(find(&em, "LevelIndicator").is_none());
}

#[test]
fn aeinfo_aeflags_shift_follows_byte_size_not_count() {
  // The AEFlags Hook keys on ExifTool's `$size` (the SubDirectory data-block
  // BYTE size = the re-sliced `block.len()`), NOT `$count`. They COINCIDE for an
  // `undef` record (count == size, as in the K-x test above), but DIVERGE when a
  // wider-than-`int8u` on-disk format coerces a record through the implicit-`undef`
  // SubDirectory path: here the 24-byte K-x block is fed with a format-skewed
  // `count == 12` (as if int16u: value_size 24 / byte_size 2). `count == 12` still
  // passes the variant gate (`<= 25 and != 21`), but the shift MUST follow the
  // 24-byte block (24 > 20 ⇒ shift == 1), reading offsets 8+ one byte LATER. With
  // the old count-based shift (count 12 ⇒ shift 0) AEApertureSteps would read byte
  // 8 (= 0xa1 = 161) — a BOGUS Pentax tag one byte early.
  let mut em = Vec::new();
  emit_aeinfo(AEINFO_KX, 12, true, &mut em);
  // Unshifted leaves (offsets 0-7) decode the same as any in-gate record.
  assert_eq!(find(&em, "AEProgramMode"), Some(&s("Standard"))); // byte 6 = 0x23 = 35
  // The shift follows byte size: AEApertureSteps reads byte 9 (= 0x00 = 0), NOT
  // byte 8 (= 0xa1 = 161) — i.e. NOT one byte early.
  assert_eq!(find(&em, "AEApertureSteps"), Some(&TagValue::I64(0)));
  assert_ne!(find(&em, "AEApertureSteps"), Some(&TagValue::I64(161)));
  // The remaining shifted offsets land on the SAME bytes as the undef-24 K-x
  // record (`aeinfo_size_over_20_shifts_offsets`), proving size-keyed parity: e.g.
  // FlashExposureCompSet reads byte 15 (= 0xf8 = -8 int8s) ⇒ PentaxEv(-8) = -1.
  assert_eq!(find(&em, "FlashExposureCompSet"), Some(&s("-1.0")));
  // A control: with a SMALL byte size (<= 20) the same small count yields NO shift
  // — AEApertureSteps then reads byte 8. The first 20 bytes of the K-x block keep
  // count 12 in-gate but drop the block to 20 bytes (20 > 20 is false ⇒ shift 0),
  // so AEApertureSteps reads byte 8 (= 0xa1 = 161), confirming the shift tracks
  // `block.len()` and not the (unchanged) count.
  let mut em20 = Vec::new();
  emit_aeinfo(&AEINFO_KX[..20], 12, true, &mut em20);
  assert_eq!(find(&em20, "AEApertureSteps"), Some(&TagValue::I64(161)));
}

#[test]
fn lens_info2_k10d_print_conv_byte_exact() {
  // -j (PrintConv) — the K10D `LensInfo2` ($count == 69, not in the deferred
  // set). Values verified against `exiftool -G1 -j Pentax.jpg`.
  let mut em = Vec::new();
  emit_lens_info(LENSINFO2_K10D, 69, Some("PENTAX K10D"), true, &mut em);
  assert_eq!(find(&em, "LensFStops"), Some(&TagValue::F64(8.5)));
  assert_eq!(find(&em, "MinFocusDistance"), Some(&s("0.49-0.50 m")));
  assert_eq!(find(&em, "LensFocalLength"), Some(&s("10.0 mm")));
  assert_eq!(find(&em, "NominalMaxAperture"), Some(&s("4.0")));
  assert_eq!(find(&em, "NominalMinAperture"), Some(&s("23")));
  // ONLY the five LensData leaves — LensType (offset 0-3) is NOT re-emitted here
  // (Phase 1's 0x003f LensRec owns it), and the deferred LensData leaves
  // (AutoAperture, MinAperture, FocusRangeIndex, MaxAperture) are NOT emitted.
  assert!(
    find(&em, "LensType").is_none(),
    "LensType is owned by 0x003f, not 0x0207"
  );
  assert!(find(&em, "AutoAperture").is_none());
  assert!(find(&em, "MinAperture").is_none());
  assert!(find(&em, "FocusRangeIndex").is_none());
  assert!(find(&em, "MaxAperture").is_none());
  assert_eq!(
    em.len(),
    5,
    "LensInfo2 emits exactly the 5 ported LensData leaves"
  );
}

#[test]
fn lens_info2_k10d_value_conv_floats() {
  // -n (ValueConv) — the raw f64 / hash-key values (verified against
  // `exiftool -G1 -n Pentax.jpg`: LensFStops 8.5, MinFocusDistance 6,
  // LensFocalLength 10, NominalMaxAperture 4, NominalMinAperture 22.6274…).
  let mut em = Vec::new();
  emit_lens_info(LENSINFO2_K10D, 69, Some("PENTAX K10D"), false, &mut em);
  assert_eq!(find(&em, "LensFStops"), Some(&TagValue::F64(8.5)));
  // MinFocusDistance under -n is the raw masked value (no PrintConv hash).
  assert_eq!(find(&em, "MinFocusDistance"), Some(&TagValue::I64(6)));
  assert_eq!(find(&em, "LensFocalLength"), Some(&TagValue::F64(10.0)));
  assert_eq!(find(&em, "NominalMaxAperture"), Some(&TagValue::F64(4.0)));
  let approx = |name: &str, want: f64| {
    let TagValue::F64(g) = find(&em, name).expect(name) else {
      panic!("{name} is not F64");
    };
    assert!((g - want).abs() < 1e-9, "{name} = {g}, want {want}");
  };
  approx("NominalMinAperture", 2.0_f64.powf((8.0 + 10.0) / 4.0)); // 22.627416997969522
}

#[test]
fn lens_info2_deferred_variant_count_does_not_misdecode() {
  // The deferred LensInfo3 (645D, $count == 90), LensInfo4 (K-r/K-5, 91),
  // LensInfo5 (K-01/…, 80 or 128) and Ricoh GR III (168) layouts MUST NOT decode
  // through the K10D LensData offsets (the scope-fence): ZERO emissions.
  for count in [90usize, 91, 80, 128, 168] {
    let mut em = Vec::new();
    emit_lens_info(LENSINFO2_K10D, count, Some("PENTAX 645D"), true, &mut em);
    assert!(
      em.is_empty(),
      "a deferred-variant $count ({count}) must not decode the K10D LensData"
    );
  }
}

#[test]
fn lens_info2_focal_length_645z_gate() {
  // LensFocalLength carries `Condition => '$$self{Model} !~ /645Z/'`
  // (`Pentax.pm:4475`) — a 645Z body must NOT emit it, but the other four leaves
  // still do.
  let mut em = Vec::new();
  emit_lens_info(LENSINFO2_K10D, 69, Some("PENTAX 645Z"), true, &mut em);
  assert!(
    find(&em, "LensFocalLength").is_none(),
    "645Z must not emit LensFocalLength"
  );
  // The other leaves are unaffected.
  assert_eq!(find(&em, "LensFStops"), Some(&TagValue::F64(8.5)));
  assert_eq!(find(&em, "NominalMaxAperture"), Some(&s("4.0")));
  assert_eq!(em.len(), 4, "645Z drops only LensFocalLength");
}

#[test]
fn lens_info2_truncated_block_no_panic() {
  // A record shorter than LensInfo2 offset 4 itself: the LensData slice is empty
  // ⇒ no leaf emits, no panic / OOB.
  let mut em0 = Vec::new();
  emit_lens_info(
    &LENSINFO2_K10D[..3],
    69,
    Some("PENTAX K10D"),
    true,
    &mut em0,
  );
  assert!(
    em0.is_empty(),
    "a record shorter than offset 4 emits nothing"
  );

  // A record holding only LensData offsets 0-5 (block[4..10], a 6-byte tail): the
  // in-range leaves (offset 0 LensFStops, offset 3 MinFocusDistance) decode; the
  // offset-9 LensFocalLength and offset-10 NominalMax/Min leaves are skipped (no
  // panic), matching ProcessBinaryData's `last if $entry >= $size`.
  let mut em1 = Vec::new();
  emit_lens_info(
    &LENSINFO2_K10D[..10],
    69,
    Some("PENTAX K10D"),
    true,
    &mut em1,
  );
  assert_eq!(find(&em1, "LensFStops"), Some(&TagValue::F64(8.5)));
  assert_eq!(find(&em1, "MinFocusDistance"), Some(&s("0.49-0.50 m")));
  assert!(
    find(&em1, "LensFocalLength").is_none(),
    "offset-9 leaf skipped when truncated"
  );
  assert!(find(&em1, "NominalMaxAperture").is_none());

  // A record holding LensData offsets 0-9 but not 10 (block[4..14]): offset-10
  // NominalMax/Min are skipped, offset-9 LensFocalLength decodes.
  let mut em2 = Vec::new();
  emit_lens_info(
    &LENSINFO2_K10D[..14],
    69,
    Some("PENTAX K10D"),
    true,
    &mut em2,
  );
  assert_eq!(find(&em2, "LensFStops"), Some(&TagValue::F64(8.5)));
  assert_eq!(find(&em2, "LensFocalLength"), Some(&s("10.0 mm")));
  assert!(
    find(&em2, "NominalMaxAperture").is_none(),
    "offset-10 leaf skipped when truncated"
  );
  assert!(find(&em2, "NominalMinAperture").is_none());
}

#[test]
fn lens_info_old_format_ist_emits_nothing() {
  // ExifTool tests the old `%Pentax::LensInfo` variant FIRST, before the
  // `LensInfo2` `$count` condition (`Pentax.pm:2825-2833`): the *ist series ALWAYS
  // uses the deferred old format (`/(\*ist|GX-1[LS])/`). Even with an otherwise
  // valid (K10D) block at an in-gate count (69, not in {90,91,80,128,168}), an
  // *ist body must emit NOTHING — never misdecode through the offset-4 LensInfo2
  // `LensData`. (`LENSINFO2_K10D` byte 20 == 0x03, so this is the Model-regex
  // branch, independent of the byte-20 marker.)
  let mut em = Vec::new();
  emit_lens_info(LENSINFO2_K10D, 69, Some("PENTAX *ist DS"), true, &mut em);
  assert!(
    em.is_empty(),
    "an *ist body uses the deferred old LensInfo ⇒ zero emissions"
  );
}

#[test]
fn lens_info_old_format_gx1l_emits_nothing() {
  // The Samsung `GX-1[LS]` also always uses the old format (`/GX-1[LS]/`).
  let mut em = Vec::new();
  emit_lens_info(LENSINFO2_K10D, 69, Some("PENTAX GX-1L"), true, &mut em);
  assert!(
    em.is_empty(),
    "a GX-1L body uses the deferred old LensInfo ⇒ zero emissions"
  );
}

#[test]
fn lens_info_old_format_k100d_byte20_ff_emits_nothing() {
  // The K100D/K110D use the old format only when byte 20 of the record is `0xff`
  // (`$$valPt=~/^.{20}(\xff|\0\0)/s`). Craft a block whose byte 20 == 0xff: the
  // old-format marker matches ⇒ zero emissions (the deferred old LensInfo), NOT a
  // decode through LensInfo2.
  let mut block = LENSINFO2_K10D.to_vec();
  block[20] = 0xff;
  let mut em = Vec::new();
  emit_lens_info(&block, 69, Some("PENTAX K100D"), true, &mut em);
  assert!(
    em.is_empty(),
    "a K100D with byte 20 == 0xff uses the deferred old LensInfo ⇒ zero emissions"
  );
}

#[test]
fn lens_info_old_format_k100d_bytes20_21_zero_emits_nothing() {
  // The other old-format marker: bytes 20..22 == `00 00`.
  let mut block = LENSINFO2_K10D.to_vec();
  block[20] = 0x00;
  block[21] = 0x00;
  let mut em = Vec::new();
  emit_lens_info(&block, 69, Some("PENTAX K100D"), true, &mut em);
  assert!(
    em.is_empty(),
    "a K100D with bytes 20..22 == 00 00 uses the deferred old LensInfo ⇒ zero emissions"
  );
}

#[test]
fn lens_info_k100d_not_old_format_falls_through_to_lensinfo2() {
  // The byte-20 gate is SPECIFIC to the old-format marker: a K100D whose byte 20 is
  // NEITHER 0xff NOR (0x00 with byte 21 == 0x00) is the NEWER format and MUST fall
  // through to the LensInfo2 `$count` test and decode, matching ExifTool (only the
  // K100D/K110D with the marker take the old path). `LENSINFO2_K10D` byte 20 ==
  // 0x03 already; set byte 20 = 0x01 to be explicit it is non-old.
  let mut block = LENSINFO2_K10D.to_vec();
  block[20] = 0x01;
  let mut em = Vec::new();
  emit_lens_info(&block, 69, Some("PENTAX K100D"), true, &mut em);
  // Decodes through LensInfo2 — the same five leaves as the K10D path. Byte 20 is
  // not read by any of the five ported leaves (they live at LensData offsets
  // 0/3/9/10 = block 4/7/13/14), so the values match the K10D fixture exactly.
  assert_eq!(find(&em, "LensFStops"), Some(&TagValue::F64(8.5)));
  assert_eq!(find(&em, "MinFocusDistance"), Some(&s("0.49-0.50 m")));
  assert_eq!(find(&em, "LensFocalLength"), Some(&s("10.0 mm")));
  assert_eq!(find(&em, "NominalMaxAperture"), Some(&s("4.0")));
  assert_eq!(find(&em, "NominalMinAperture"), Some(&s("23")));
  assert_eq!(
    em.len(),
    5,
    "a non-old-format K100D decodes through LensInfo2 (5 leaves)"
  );
}

#[test]
fn lens_info_old_format_short_block_falls_through() {
  // The byte-20/21 reads are bounds-checked: a K100D record shorter than 21 bytes
  // can't carry the old-format marker (ExifTool's `/^.{20}.../s` simply fails to
  // match a short value) ⇒ NOT-old, fall through to the `$count` test. With a
  // 14-byte block the in-range leaves (offsets 0/3/9) decode; offset-10 is skipped.
  let mut em = Vec::new();
  emit_lens_info(
    &LENSINFO2_K10D[..14],
    69,
    Some("PENTAX K100D"),
    true,
    &mut em,
  );
  assert_eq!(find(&em, "LensFStops"), Some(&TagValue::F64(8.5)));
  assert_eq!(find(&em, "LensFocalLength"), Some(&s("10.0 mm")));
  assert!(
    find(&em, "NominalMaxAperture").is_none(),
    "short block: offset-10 leaf skipped, but the record still decodes (not old)"
  );
}
