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

/// The verbatim K10D `CameraInfo` (0x0215) block from the `Pentax.jpg` fixture
/// (`exiftool -v3`: 20 bytes, `int32u[5]` read as `undef[20]`, BigEndian).
/// offset 0 = PentaxModelID `00 01 2c 1e` (=0x12c1e=76830, K10D); offset 1 =
/// ManufactureDate `01 32 42 01` (=20070913); offset 2 = ProductionCode int32u[2]
/// `00 00 00 02` + `00 00 00 01` (=2, 1); offset 4 = InternalSerialNumber
/// `00 02 05 00` (=132352).
const CAMERAINFO_K10D: &[u8] = &[
  0x00, 0x01, 0x2c, 0x1e, 0x01, 0x32, 0x42, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
  0x00, 0x02, 0x05, 0x00,
];

fn find(em: &[VendorEmission<'_>], name: &str) -> Option<TagValue> {
  em.iter()
    .find(|e| e.name() == name)
    .map(|e| e.value().into_owned())
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

  assert_eq!(find(&em, "PictureMode2"), Some(s("Aperture Priority")));
  assert_eq!(find(&em, "ProgramLine"), Some(s("Normal")));
  assert_eq!(find(&em, "EVSteps"), Some(s("1/3 EV Steps")));
  assert_eq!(find(&em, "E-DialInProgram"), Some(s("Tv or Av")));
  assert_eq!(find(&em, "ApertureRingUse"), Some(s("Permitted")));
  assert_eq!(find(&em, "FlashOptions"), Some(s("Wireless (Master)")));
  assert_eq!(find(&em, "MeteringMode2"), Some(s("Multi-segment")));
  assert_eq!(find(&em, "AFPointMode"), Some(s("Select")));
  assert_eq!(find(&em, "FocusMode2"), Some(s("AF-S")));
  assert_eq!(find(&em, "AFPointSelected2"), Some(s("Center")));
  assert_eq!(find(&em, "ISOFloor"), Some(TagValue::I64(100)));
  assert_eq!(find(&em, "DriveMode2"), Some(s("Single-frame")));
  assert_eq!(find(&em, "ExposureBracketStepSize"), Some(s("0.3")));
  assert_eq!(find(&em, "BracketShotNumber"), Some(s("n/a")));
  assert_eq!(find(&em, "WhiteBalanceSet"), Some(s("Auto")));
  assert_eq!(find(&em, "MultipleExposureSet"), Some(s("Off")));
  // K10D-only (offset 13+).
  assert_eq!(
    find(&em, "RawAndJpgRecording"),
    Some(s("RAW+JPEG (PEF, Better)"))
  );
  assert_eq!(find(&em, "JpgRecordedPixels"), Some(s("6 MP")));
  assert_eq!(find(&em, "FlashOptions2"), Some(s("Wireless (Master)")));
  assert_eq!(find(&em, "MeteringMode3"), Some(s("Multi-segment")));
  assert_eq!(find(&em, "SRActive"), Some(s("Yes")));
  assert_eq!(find(&em, "Rotation"), Some(s("Rotate 270 CW")));
  assert_eq!(find(&em, "ISOSetting"), Some(s("Manual")));
  assert_eq!(find(&em, "SensitivitySteps"), Some(s("1 EV Steps")));
  assert_eq!(find(&em, "TvExposureTimeSetting"), Some(s("1/203")));
  assert_eq!(find(&em, "AvApertureSetting"), Some(s("12.7")));
  assert_eq!(find(&em, "SvISOSetting"), Some(TagValue::I64(100)));
  assert_eq!(find(&em, "BaseExposureCompensation"), Some(s("+0.7")));
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
  assert_eq!(find(&em, "ISOFloor"), Some(TagValue::I64(100)));
  assert_eq!(find(&em, "SvISOSetting"), Some(TagValue::I64(100)));
  // The enum/bitfield leaves are raw ints under -n.
  assert_eq!(find(&em, "PictureMode2"), Some(TagValue::I64(5)));
  assert_eq!(find(&em, "ApertureRingUse"), Some(TagValue::I64(1)));
  assert_eq!(find(&em, "AFPointSelected2"), Some(TagValue::I64(32)));
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
  assert_eq!(find(&em, "PictureMode2"), Some(s("Aperture Priority")));
  assert_eq!(find(&em, "ISOFloor"), Some(TagValue::I64(100)));
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
  assert_eq!(find(&em_gx, "SRActive"), Some(s("Yes")));
}

#[test]
fn aeinfo_k10d_print_conv_byte_exact() {
  let mut em = Vec::new();
  emit_aeinfo(AEINFO_K10D, 16, true, &mut em);
  assert_eq!(find(&em, "AEExposureTime"), Some(s("1/101")));
  assert_eq!(find(&em, "AEAperture"), Some(s("12.9")));
  assert_eq!(find(&em, "AE_ISO"), Some(TagValue::I64(100)));
  assert_eq!(find(&em, "AEXv"), Some(TagValue::F64(-0.625)));
  assert_eq!(find(&em, "AEBXv"), Some(TagValue::F64(0.0)));
  assert_eq!(find(&em, "AEMinExposureTime"), Some(s("1/3862")));
  assert_eq!(find(&em, "AEProgramMode"), Some(s("Av, B or X")));
  assert_eq!(find(&em, "AEApertureSteps"), Some(TagValue::I64(28)));
  assert_eq!(find(&em, "AEMaxAperture"), Some(s("4.0")));
  assert_eq!(find(&em, "AEMaxAperture2"), Some(s("4.0")));
  assert_eq!(find(&em, "AEMinAperture"), Some(s("23")));
  assert_eq!(find(&em, "AEMeteringMode"), Some(s("Multi-segment")));
  assert_eq!(find(&em, "FlashExposureCompSet"), Some(TagValue::I64(0)));
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
  assert_eq!(find(&em, "FlashStatus"), Some(s("Off")));
  assert_eq!(
    find(&em, "InternalFlashMode"),
    Some(s("Did not fire, Wireless (Master)"))
  );
  assert_eq!(find(&em, "ExternalFlashMode"), Some(s("Off")));
  assert_eq!(find(&em, "InternalFlashStrength"), Some(TagValue::I64(18)));
  assert_eq!(find(&em, "TTL_DA_AUp"), Some(TagValue::I64(0)));
  assert_eq!(find(&em, "TTL_DA_ADown"), Some(TagValue::I64(0)));
  assert_eq!(find(&em, "TTL_DA_BUp"), Some(TagValue::I64(0)));
  assert_eq!(find(&em, "TTL_DA_BDown"), Some(TagValue::I64(0)));
  assert_eq!(find(&em, "ExternalFlashGuideNumber"), Some(s("n/a")));
  assert_eq!(find(&em, "ExternalFlashExposureComp"), Some(s("n/a")));
  assert_eq!(find(&em, "ExternalFlashBounce"), Some(s("n/a")));
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
  assert_eq!(find(&em, "PictureMode2"), Some(s("Aperture Priority")));
  assert_eq!(find(&em, "FlashOptions"), Some(s("Wireless (Master)")));
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
  assert_eq!(find(&em, "AEProgramMode"), Some(s("Standard"))); // byte 6 = 0x23 = 35
  // Offset 8+ shifted: AEApertureSteps reads byte 9 = 0.
  assert_eq!(find(&em, "AEApertureSteps"), Some(TagValue::I64(0)));
  // FlashExposureCompSet reads byte 15 (= 0xf8 = -8 int8s) ⇒ PentaxEv(-8) = -1.
  assert_eq!(find(&em, "FlashExposureCompSet"), Some(s("-1.0")));
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
  assert_eq!(find(&em, "AEProgramMode"), Some(s("Standard"))); // byte 6 = 0x23 = 35
  // The shift follows byte size: AEApertureSteps reads byte 9 (= 0x00 = 0), NOT
  // byte 8 (= 0xa1 = 161) — i.e. NOT one byte early.
  assert_eq!(find(&em, "AEApertureSteps"), Some(TagValue::I64(0)));
  assert_ne!(find(&em, "AEApertureSteps"), Some(TagValue::I64(161)));
  // The remaining shifted offsets land on the SAME bytes as the undef-24 K-x
  // record (`aeinfo_size_over_20_shifts_offsets`), proving size-keyed parity: e.g.
  // FlashExposureCompSet reads byte 15 (= 0xf8 = -8 int8s) ⇒ PentaxEv(-8) = -1.
  assert_eq!(find(&em, "FlashExposureCompSet"), Some(s("-1.0")));
  // A control: with a SMALL byte size (<= 20) the same small count yields NO shift
  // — AEApertureSteps then reads byte 8. The first 20 bytes of the K-x block keep
  // count 12 in-gate but drop the block to 20 bytes (20 > 20 is false ⇒ shift 0),
  // so AEApertureSteps reads byte 8 (= 0xa1 = 161), confirming the shift tracks
  // `block.len()` and not the (unchanged) count.
  let mut em20 = Vec::new();
  emit_aeinfo(&AEINFO_KX[..20], 12, true, &mut em20);
  assert_eq!(find(&em20, "AEApertureSteps"), Some(TagValue::I64(161)));
}

#[test]
fn lens_info2_k10d_print_conv_byte_exact() {
  // -j (PrintConv) — the K10D `LensInfo2` ($count == 69, not in the deferred
  // set). Values verified against `exiftool -G1 -j Pentax.jpg`.
  let mut em = Vec::new();
  emit_lens_info(LENSINFO2_K10D, 69, Some("PENTAX K10D"), true, &mut em);
  assert_eq!(find(&em, "LensFStops"), Some(TagValue::F64(8.5)));
  assert_eq!(find(&em, "MinFocusDistance"), Some(s("0.49-0.50 m")));
  assert_eq!(find(&em, "LensFocalLength"), Some(s("10.0 mm")));
  assert_eq!(find(&em, "NominalMaxAperture"), Some(s("4.0")));
  assert_eq!(find(&em, "NominalMinAperture"), Some(s("23")));
  // The four #173 LensData leaves now emit (verified against `exiftool -G1 -j
  // Pentax.jpg`).
  assert_eq!(find(&em, "AutoAperture"), Some(s("On")));
  assert_eq!(find(&em, "MinAperture"), Some(s("22")));
  assert_eq!(find(&em, "FocusRangeIndex"), Some(s("7 (very far)")));
  assert_eq!(find(&em, "MaxAperture"), Some(s("3.9")));
  // LensType (offset 0-3) is NOT re-emitted here (Phase 1's 0x003f LensRec owns it).
  assert!(
    find(&em, "LensType").is_none(),
    "LensType is owned by 0x003f, not 0x0207"
  );
  assert_eq!(
    em.len(),
    9,
    "LensInfo2 emits the nine ported LensData leaves"
  );
}

#[test]
fn lens_info2_k10d_value_conv_floats() {
  // -n (ValueConv) — the raw f64 / hash-key values (verified against
  // `exiftool -G1 -n Pentax.jpg`: LensFStops 8.5, MinFocusDistance 6,
  // LensFocalLength 10, NominalMaxAperture 4, NominalMinAperture 22.6274…).
  let mut em = Vec::new();
  emit_lens_info(LENSINFO2_K10D, 69, Some("PENTAX K10D"), false, &mut em);
  assert_eq!(find(&em, "LensFStops"), Some(TagValue::F64(8.5)));
  // MinFocusDistance under -n is the raw masked value (no PrintConv hash).
  assert_eq!(find(&em, "MinFocusDistance"), Some(TagValue::I64(6)));
  assert_eq!(find(&em, "LensFocalLength"), Some(TagValue::F64(10.0)));
  assert_eq!(find(&em, "NominalMaxAperture"), Some(TagValue::F64(4.0)));
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
  assert_eq!(find(&em, "LensFStops"), Some(TagValue::F64(8.5)));
  assert_eq!(find(&em, "NominalMaxAperture"), Some(s("4.0")));
  assert_eq!(find(&em, "AutoAperture"), Some(s("On")));
  assert_eq!(find(&em, "MaxAperture"), Some(s("3.9")));
  assert_eq!(em.len(), 8, "645Z drops only LensFocalLength");
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
  assert_eq!(find(&em1, "LensFStops"), Some(TagValue::F64(8.5)));
  assert_eq!(find(&em1, "MinFocusDistance"), Some(s("0.49-0.50 m")));
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
  assert_eq!(find(&em2, "LensFStops"), Some(TagValue::F64(8.5)));
  assert_eq!(find(&em2, "LensFocalLength"), Some(s("10.0 mm")));
  assert!(
    find(&em2, "NominalMaxAperture").is_none(),
    "offset-10 leaf skipped when truncated"
  );
  assert!(find(&em2, "NominalMinAperture").is_none());
}

/// A crafted OLD-format `%Pentax::LensInfo` record (`Pentax.pm:4218-4237`):
/// `LensType` `int8u[2]` at offset 0-1, an unused byte at offset 2, then the
/// nested `LensData` `undef[17]` at offset 3 — here the SAME 17 LensData bytes as
/// the K10D `LensInfo2` fixture, so the decoded leaves match the K10D path exactly.
/// (The *ist series / GX-1[LS] use this layout; the K10D-LensData reuse keeps the
/// expected values identical to the byte-exact `LensInfo2` test.)
const LENSINFO_OLD: &[u8] = &[
  0x02, 0x00, // LensType (series 2, model 0)
  0x00, // offset 2 (unused)
  // offset 3: the K10D LensData `undef[17]`.
  0x00, 0x28, 0x94, 0x33, 0x5b, 0x53, 0x86, 0xea, 0x41, 0x40, 0x88, 0x50, 0x38, 0x01, 0x40, 0x6c,
  0x03,
];

/// Assert the nine OLD-format LensData leaves (identical to the K10D `LensInfo2`
/// values) — the old `%LensInfo` decodes `LensData` from offset 3.
fn assert_old_lens_info_leaves(em: &[VendorEmission<'_>]) {
  assert_eq!(find(em, "LensFStops"), Some(TagValue::F64(8.5)));
  assert_eq!(find(em, "MinFocusDistance"), Some(s("0.49-0.50 m")));
  assert_eq!(find(em, "LensFocalLength"), Some(s("10.0 mm")));
  assert_eq!(find(em, "NominalMaxAperture"), Some(s("4.0")));
  assert_eq!(find(em, "NominalMinAperture"), Some(s("23")));
  assert_eq!(find(em, "AutoAperture"), Some(s("On")));
  assert_eq!(find(em, "FocusRangeIndex"), Some(s("7 (very far)")));
}

#[test]
fn lens_info_old_format_ist_decodes_offset3() {
  // ExifTool tests the old `%Pentax::LensInfo` variant FIRST, before the
  // `LensInfo2` `$count` condition (`Pentax.pm:2825-2833`): the *ist series ALWAYS
  // uses the old format (`/(\*ist|GX-1[LS])/`), whose `LensData` lives at offset 3
  // (`IS_SUBDIR => [3]`). An *ist body decodes the SAME nested LensData leaves as
  // the K10D — never the offset-4 `LensInfo2` layout.
  let mut em = Vec::new();
  emit_lens_info(LENSINFO_OLD, 36, Some("PENTAX *ist DS"), true, &mut em);
  assert_old_lens_info_leaves(&em);
}

#[test]
fn lens_info_old_format_gx1l_decodes_offset3() {
  // The Samsung `GX-1[LS]` also always uses the old format (`/GX-1[LS]/`).
  let mut em = Vec::new();
  emit_lens_info(LENSINFO_OLD, 36, Some("PENTAX GX-1L"), true, &mut em);
  assert_old_lens_info_leaves(&em);
}

#[test]
fn lens_info_old_format_k100d_byte20_ff_decodes_offset3() {
  // The K100D/K110D use the old format only when byte 20 of the record is `0xff`
  // (`$$valPt=~/^.{20}(\xff|\0\0)/s`). Pad `LENSINFO_OLD` to 21 bytes with byte 20
  // == 0xff: the old-format marker matches ⇒ decode the offset-3 `LensData`, NOT a
  // decode through LensInfo2.
  let mut block = LENSINFO_OLD.to_vec();
  block.resize(20, 0x00);
  block.push(0xff); // byte 20
  let mut em = Vec::new();
  emit_lens_info(&block, 36, Some("PENTAX K100D"), true, &mut em);
  assert_old_lens_info_leaves(&em);
}

#[test]
fn lens_info_old_format_k100d_bytes20_21_zero_decodes_offset3() {
  // The other old-format marker: bytes 20..22 == `00 00`.
  let mut block = LENSINFO_OLD.to_vec();
  block.resize(22, 0x00); // bytes 20,21 == 00 00
  let mut em = Vec::new();
  emit_lens_info(&block, 36, Some("PENTAX K100D"), true, &mut em);
  assert_old_lens_info_leaves(&em);
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
  // Decodes through LensInfo2 — the same nine leaves as the K10D path. Byte 20
  // (LensData offset 16) is not read by any ported leaf (they live at LensData
  // offsets 0/3/9/10/14), so the values match the K10D fixture exactly.
  assert_eq!(find(&em, "LensFStops"), Some(TagValue::F64(8.5)));
  assert_eq!(find(&em, "MinFocusDistance"), Some(s("0.49-0.50 m")));
  assert_eq!(find(&em, "LensFocalLength"), Some(s("10.0 mm")));
  assert_eq!(find(&em, "NominalMaxAperture"), Some(s("4.0")));
  assert_eq!(find(&em, "NominalMinAperture"), Some(s("23")));
  assert_eq!(find(&em, "AutoAperture"), Some(s("On")));
  assert_eq!(find(&em, "FocusRangeIndex"), Some(s("7 (very far)")));
  assert_eq!(
    em.len(),
    9,
    "a non-old-format K100D decodes through LensInfo2 (9 leaves)"
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
  assert_eq!(find(&em, "LensFStops"), Some(TagValue::F64(8.5)));
  assert_eq!(find(&em, "LensFocalLength"), Some(s("10.0 mm")));
  assert!(
    find(&em, "NominalMaxAperture").is_none(),
    "short block: offset-10 leaf skipped, but the record still decodes (not old)"
  );
}

#[test]
fn camera_info_k10d_print_conv_byte_exact() {
  // -j (PrintConv) — the K10D `CameraInfo` (0x0215). Values verified against
  // `exiftool -G1 -j Pentax.jpg`: ManufactureDate "2007:09:13",
  // ProductionCode 2.1, InternalSerialNumber 132352.
  let mut em = Vec::new();
  emit_camera_info(CAMERAINFO_K10D, ByteOrder::Big, true, &mut em);
  assert_eq!(find(&em, "ManufactureDate"), Some(s("2007:09:13")));
  // ProductionCode is the dotted ValueConv string "2.1" (renders as a JSON number);
  // the "(camera has been serviced)" suffix applies only to an 8.x value.
  assert_eq!(find(&em, "ProductionCode"), Some(s("2.1")));
  assert_eq!(
    find(&em, "InternalSerialNumber"),
    Some(TagValue::I64(132352))
  );
  // PentaxModelID (offset 0) is NOT re-emitted from this path — Phase 1's 0x0005
  // leaf owns it (the guardrail).
  assert!(
    find(&em, "PentaxModelID").is_none(),
    "CameraInfo must not re-emit PentaxModelID (0x0005 owns it)"
  );
  assert_eq!(em.len(), 3, "CameraInfo emits exactly the 3 ported scalars");
}

#[test]
fn camera_info_k10d_value_conv() {
  // -n (ValueConv) — ManufactureDate has no PrintConv (same string), ProductionCode
  // is the bare dotted string, InternalSerialNumber the raw int.
  let mut em = Vec::new();
  emit_camera_info(CAMERAINFO_K10D, ByteOrder::Big, false, &mut em);
  assert_eq!(find(&em, "ManufactureDate"), Some(s("2007:09:13")));
  assert_eq!(find(&em, "ProductionCode"), Some(s("2.1")));
  assert_eq!(
    find(&em, "InternalSerialNumber"),
    Some(TagValue::I64(132352))
  );
  assert!(find(&em, "PentaxModelID").is_none());
}

#[test]
fn camera_info_kx_avi_byte_exact() {
  // The K-x `Pentax.avi` CameraInfo (also BigEndian, `exiftool -v3`): offset 1 =
  // ManufactureDate `01 32 90 18` (=20090904), offset 2 = ProductionCode
  // `00 00 00 02` + `00 00 00 03` (=2, 3), offset 4 = InternalSerialNumber
  // `00 7a 30 2d` (=8007725). Verified against `exiftool -G1 -j Pentax.avi`.
  const CAMERAINFO_KX: &[u8] = &[
    0x00, 0x01, 0x2d, 0xfe, 0x01, 0x32, 0x90, 0x18, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03,
    0x00, 0x7a, 0x30, 0x2d,
  ];
  let mut em = Vec::new();
  emit_camera_info(CAMERAINFO_KX, ByteOrder::Big, true, &mut em);
  assert_eq!(find(&em, "ManufactureDate"), Some(s("2009:09:04")));
  assert_eq!(find(&em, "ProductionCode"), Some(s("2.3")));
  assert_eq!(
    find(&em, "InternalSerialNumber"),
    Some(TagValue::I64(8007725))
  );
  assert!(find(&em, "PentaxModelID").is_none());
}

#[test]
fn camera_info_production_code_serviced_suffix() {
  // A crafted 8.x ProductionCode triggers the PrintConv service-check suffix
  // (`$val=~/^8\./ ? "$val (camera has been serviced)"`, `Pentax.pm:4750`); under
  // -n it stays the bare dotted string. Block: offset 2 = int32u[2] (8, 1).
  let block: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, // offset 0 PentaxModelID (ignored)
    0x01, 0x32, 0x42, 0x01, // offset 1 ManufactureDate = 20070913
    0x00, 0x00, 0x00, 0x08, // offset 2a = 8
    0x00, 0x00, 0x00, 0x01, // offset 2b = 1
    0x00, 0x00, 0x00, 0x05, // offset 4 InternalSerialNumber = 5
  ];
  let mut em = Vec::new();
  emit_camera_info(block, ByteOrder::Big, true, &mut em);
  assert_eq!(
    find(&em, "ProductionCode"),
    Some(s("8.1 (camera has been serviced)"))
  );
  // -n: the bare dotted string, no suffix.
  let mut emn = Vec::new();
  emit_camera_info(block, ByteOrder::Big, false, &mut emn);
  assert_eq!(find(&emn, "ProductionCode"), Some(s("8.1")));
}

#[test]
fn camera_info_manufacture_date_optio_and_unknown() {
  // The 5-digit Optio A10/A20 branch (`/^(\d)(\d{2})(\d{2})$/` ⇒ "200Y:MM:DD"):
  // raw 70913 ⇒ "2007:09:13". A value matching NEITHER regex ⇒ "Unknown ($val)".
  assert_eq!(manufacture_date(70913), SmolStr::from("2007:09:13"));
  // 8 digits ⇒ the primary branch.
  assert_eq!(manufacture_date(20070913), SmolStr::from("2007:09:13"));
  // 7 digits (neither 8 nor 5) ⇒ Unknown.
  assert_eq!(
    manufacture_date(2007091),
    SmolStr::from("Unknown (2007091)")
  );
  // 0 (1 digit) ⇒ Unknown.
  assert_eq!(manufacture_date(0), SmolStr::from("Unknown (0)"));
}

#[test]
fn camera_info_truncated_block_partial_emit_no_panic() {
  // CameraInfo is UNCONDITIONAL (no $count gate), so a short/truncated block emits
  // only the in-range scalars — bounds-checked, no panic. The 3 ported scalars
  // live at byte 4 (ManufactureDate), bytes 8-15 (ProductionCode int32u[2]) and
  // byte 16 (InternalSerialNumber).

  // 8 bytes: only ManufactureDate (byte 4) is fully in range; ProductionCode needs
  // bytes 8-15, InternalSerialNumber needs byte 16 — both skipped.
  let mut em8 = Vec::new();
  emit_camera_info(&CAMERAINFO_K10D[..8], ByteOrder::Big, true, &mut em8);
  assert_eq!(find(&em8, "ManufactureDate"), Some(s("2007:09:13")));
  assert!(
    find(&em8, "ProductionCode").is_none(),
    "int32u[2] ProductionCode needs bytes 8-15"
  );
  assert!(find(&em8, "InternalSerialNumber").is_none());
  assert_eq!(em8.len(), 1);

  // 12 bytes: ManufactureDate in range, but ProductionCode's SECOND int32u (byte
  // 12-15) is out of range ⇒ ProductionCode skipped (both elements required).
  let mut em12 = Vec::new();
  emit_camera_info(&CAMERAINFO_K10D[..12], ByteOrder::Big, true, &mut em12);
  assert_eq!(find(&em12, "ManufactureDate"), Some(s("2007:09:13")));
  assert!(
    find(&em12, "ProductionCode").is_none(),
    "the second int32u element (byte 12-15) is out of range"
  );
  assert!(find(&em12, "InternalSerialNumber").is_none());

  // 16 bytes: ManufactureDate + ProductionCode in range; InternalSerialNumber
  // (byte 16) skipped.
  let mut em16 = Vec::new();
  emit_camera_info(&CAMERAINFO_K10D[..16], ByteOrder::Big, true, &mut em16);
  assert_eq!(find(&em16, "ManufactureDate"), Some(s("2007:09:13")));
  assert_eq!(find(&em16, "ProductionCode"), Some(s("2.1")));
  assert!(find(&em16, "InternalSerialNumber").is_none());
  assert_eq!(em16.len(), 2);

  // 3 bytes: nothing in range (byte 4 absent) ⇒ zero emissions, no panic.
  let mut em3 = Vec::new();
  emit_camera_info(&CAMERAINFO_K10D[..3], ByteOrder::Big, true, &mut em3);
  assert!(em3.is_empty(), "a block shorter than byte 4 emits nothing");

  // Empty block ⇒ zero emissions, no panic.
  let mut em0 = Vec::new();
  emit_camera_info(&[], ByteOrder::Big, true, &mut em0);
  assert!(em0.is_empty());
}

/// #284: `%Pentax::LensData` `LensFocalLength` (offset 9) is `Priority => 0`
/// (`Pentax.pm:4506`) — the marking is carried on the emission so a duplicate
/// never overrides a higher-priority same-name tag. A sibling LensData leaf
/// (`LensFStops`) keeps the default priority 1.
#[test]
fn lens_data_focal_length_is_priority_zero() {
  let mut em = Vec::new();
  emit_lens_info(LENSINFO2_K10D, 69, Some("PENTAX K10D"), true, &mut em);
  let prio = |n: &str| {
    em.iter()
      .find(|e| e.name() == n)
      .map(VendorEmission::priority)
  };
  assert_eq!(
    prio("LensFocalLength"),
    Some(0),
    "LensData LensFocalLength Priority=>0"
  );
  assert_eq!(prio("LensFStops"), Some(1));
}

/// The verbatim K10D `SRInfo` (0x005c) block (`exiftool -v3`: 4 bytes).
const SRINFO_K10D: &[u8] = &[0x01, 0x01, 0x5c, 0x14];

/// The verbatim K10D `BatteryInfo` (0x0216) block (6 bytes, BigEndian).
const BATTERYINFO_K10D: &[u8] = &[0x02, 0x41, 0xad, 0xa8, 0x05, 0x01];

/// The verbatim K10D `AFInfo` (0x021f) block (12 bytes, BigEndian).
const AFINFO_K10D: &[u8] = &[
  0x00, 0x20, 0x60, 0x20, 0x00, 0x04, 0x02, 0x00, 0x1f, 0x1f, 0x0d, 0x05,
];

/// The verbatim K10D `ColorInfo` (0x0222) block (18 bytes, `FORMAT => 'int8s'`).
const COLORINFO_K10D: &[u8] = &[
  0x20, 0x83, 0x1f, 0x64, 0x1f, 0x7d, 0x20, 0x9c, 0x21, 0x48, 0x20, 0xf6, 0x1f, 0x33, 0x1f, 0x0a,
  0x00, 0x00,
];

#[test]
fn sr_info_k10d_byte_exact() {
  // -j — verified against `exiftool -G1 -j Pentax.jpg`.
  let mut em = Vec::new();
  emit_sr_info(SRINFO_K10D, 4, true, &mut em);
  assert_eq!(find(&em, "SRResult"), Some(s("Stabilized")));
  assert_eq!(find(&em, "ShakeReduction"), Some(s("On")));
  assert_eq!(find(&em, "SRHalfPressTime"), Some(s("1.53 s")));
  assert_eq!(find(&em, "SRFocalLength"), Some(s("10 mm")));
  assert_eq!(em.len(), 4);
  // -n — the post-ValueConv values.
  let mut emn = Vec::new();
  emit_sr_info(SRINFO_K10D, 4, false, &mut emn);
  assert_eq!(find(&emn, "SRResult"), Some(TagValue::I64(1)));
  assert_eq!(find(&emn, "ShakeReduction"), Some(TagValue::I64(1)));
  assert_eq!(find(&emn, "SRFocalLength"), Some(TagValue::F64(10.0)));
}

#[test]
fn sr_info_count_not_4_is_scope_fenced() {
  // A `$count != 4` record (the 2-byte K-3 SRInfo2 variant) emits nothing.
  let mut em = Vec::new();
  emit_sr_info(SRINFO_K10D, 2, true, &mut em);
  assert!(em.is_empty());
}

#[test]
fn battery_info_k10d_byte_exact() {
  // -j — verified against `exiftool -G1 -j Pentax.jpg`.
  let mut em = Vec::new();
  emit_battery_info(BATTERYINFO_K10D, Some("PENTAX K10D"), true, &mut em);
  assert_eq!(find(&em, "PowerSource"), Some(s("Body Battery")));
  assert_eq!(find(&em, "BodyBatteryState"), Some(s("Full")));
  assert_eq!(find(&em, "GripBatteryState"), Some(s("Empty or Missing")));
  assert_eq!(find(&em, "BodyBatteryADNoLoad"), Some(s("173 (7.6V, 51%)")));
  assert_eq!(find(&em, "BodyBatteryADLoad"), Some(s("168 (7.4V, 47%)")));
  assert_eq!(find(&em, "GripBatteryADNoLoad"), Some(TagValue::I64(5)));
  assert_eq!(find(&em, "GripBatteryADLoad"), Some(TagValue::I64(1)));
  assert_eq!(em.len(), 7);
}

#[test]
fn af_info_k10d_byte_exact() {
  // -j — BigEndian; verified against `exiftool -G1 -j Pentax.jpg`. The two
  // `Unknown => 1` AFPointsUnknown1/2 are suppressed.
  let mut em = Vec::new();
  emit_af_info(AFINFO_K10D, Some("PENTAX K10D"), true, &mut em);
  assert_eq!(find(&em, "AFPredictor"), Some(TagValue::I64(4)));
  assert_eq!(find(&em, "AFDefocus"), Some(TagValue::I64(2)));
  assert_eq!(find(&em, "AFIntegrationTime"), Some(s("0 ms")));
  assert_eq!(find(&em, "AFPointsInFocus"), Some(s("Center (horizontal)")));
  assert!(find(&em, "AFPointsUnknown1").is_none());
  assert!(find(&em, "AFPointsUnknown2").is_none());
  assert_eq!(em.len(), 4);
}

#[test]
fn color_info_k10d_byte_exact() {
  // -j — `FORMAT => 'int8s'`; both WB shifts are 0 in Pentax.jpg.
  let mut em = Vec::new();
  emit_color_info(COLORINFO_K10D, true, &mut em);
  assert_eq!(find(&em, "WBShiftAB"), Some(TagValue::I64(0)));
  assert_eq!(find(&em, "WBShiftGM"), Some(TagValue::I64(0)));
  assert_eq!(em.len(), 2);
  // A signed value reads as int8s (e.g. byte 0xff => -1).
  let mut signed = COLORINFO_K10D.to_vec();
  signed[16] = 0xff;
  let mut em2 = Vec::new();
  emit_color_info(&signed, true, &mut em2);
  assert_eq!(find(&em2, "WBShiftAB"), Some(TagValue::I64(-1)));
}

// ---------------------------------------------------------------------------
// #173 branch-selection regression tests: a non-K10D model must NEVER receive
// the K10D BatteryInfo byte-layout / the model-excluded AFPointsInFocus hash.
// The invariant: a leaf emits ONLY for the exact `$$self{Model}` its ExifTool
// variant carries; any other model emits nothing at that offset (the
// scope-fence), never a wrong value.
// ---------------------------------------------------------------------------

#[test]
fn battery_info_kx_does_not_emit_k10d_ad_layout() {
  // The K-x is NOT in any BatteryInfo `BodyBatteryAD*`/`GripBatteryAD*` model
  // regex (offsets 2/3/4 are the int16u `BodyBatteryVoltage1`/`2` for the K-x —
  // a DIFFERENT tag/format the port defers). With the SAME bytes a non-gated
  // decoder WOULD invent `BodyBatteryADNoLoad = 173 (...)`; the gate suppresses
  // every K10D-only AD leaf so none of them appears.
  let mut em = Vec::new();
  emit_battery_info(BATTERYINFO_K10D, Some("PENTAX K-x"), true, &mut em);
  for wrong in [
    "BodyBatteryADNoLoad",
    "BodyBatteryADLoad",
    "GripBatteryADNoLoad",
    "GripBatteryADLoad",
    "GripBatteryState",
  ] {
    assert!(
      find(&em, wrong).is_none(),
      "K-x must not emit the K10D leaf {wrong}"
    );
  }
  // PowerSource IS emitted for the K-x (its `Model !~ /K-3 Mark III/` gate
  // holds). The K-x fails BodyBatteryState variant A but matches variant B (the
  // 5-entry "Close to Full" hash, `!~ /(K110D|K2000|K-m|K-3 Mark III)/`), so it
  // emits BodyBatteryState (#311) — byte 1 mask 0xf0 = 4 → 'Close to Full'.
  assert!(find(&em, "PowerSource").is_some());
  assert_eq!(
    find(&em, "BodyBatteryState"),
    Some(TagValue::Str("Close to Full".into()))
  );
}

/// The verbatim K-3 Mark III `BatteryInfo` (0x0216) record from the
/// `PEF_pentax_k3_mark_iii.pef` fixture (`exiftool -v3`: 23 bytes, BigEndian).
/// Byte 0 = PowerSource/PowerAvailable; byte 2 = BodyBatteryState; byte 3 =
/// BodyBatteryPercent; bytes 4-7 = BodyBatteryVoltage (int32u); byte 16 =
/// GripBatteryState; byte 17 = GripBatteryPercent; bytes 18-21 = GripBatteryVoltage.
const BATTERYINFO_K3III: &[u8] = &[
  0x11, 0x4c, 0x05, 0x64, 0x0a, 0xbd, 0x0a, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x08, 0x5e, 0x00, 0x2c, 0x00,
];

#[test]
fn battery_info_k3iii_relayout_byte_exact() {
  // The K-3 Mark III re-lays the whole `%BatteryInfo` record (#393): PowerSource
  // (byte 0, mask 0x0f, the K-3III 3-entry hash) + PowerAvailable (byte 0, mask
  // 0xf0, BITMASK) + BodyBatteryState (byte 2) + BodyBatteryPercent (byte 3) +
  // BodyBatteryVoltage (int32u BE `$val*4e-8+0.27219`) + GripBatteryState (byte 16)
  // + GripBatteryPercent (byte 17) + GripBatteryVoltage (int32u BE). Values verified
  // against `exiftool -G1 -j PEF_pentax_k3_mark_iii.pef`.
  let mut em = Vec::new();
  emit_battery_info(
    BATTERYINFO_K3III,
    Some("PENTAX K-3 Mark III"),
    true,
    &mut em,
  );
  assert_eq!(find(&em, "PowerSource"), Some(s("Body Battery")));
  assert_eq!(find(&em, "PowerAvailable"), Some(s("Body Battery")));
  assert_eq!(find(&em, "BodyBatteryState"), Some(s("Full")));
  assert_eq!(find(&em, "BodyBatteryPercent"), Some(TagValue::I64(100)));
  assert_eq!(find(&em, "BodyBatteryVoltage"), Some(s("7.48 V")));
  assert_eq!(find(&em, "GripBatteryState"), Some(s("Empty or Missing")));
  assert_eq!(find(&em, "GripBatteryPercent"), Some(TagValue::I64(0)));
  assert_eq!(find(&em, "GripBatteryVoltage"), Some(s("5.89 V")));
  // The non-K-3III K10D AD layout must NOT appear (the K-3III branch is the sole
  // emitter — never a wrong-hash PowerSource or a K10D byte mis-read).
  for wrong in [
    "BodyBatteryADNoLoad",
    "BodyBatteryADLoad",
    "GripBatteryADNoLoad",
    "GripBatteryADLoad",
  ] {
    assert!(find(&em, wrong).is_none(), "K-3III must not emit {wrong}");
  }
}

#[test]
fn battery_info_k3iii_n_mode_raw_values() {
  // `-n`: PowerSource/PowerAvailable masked ints, BodyBatteryState/Percent raw, the
  // two voltages the post-ValueConv f64. Verified against the `.n.json` golden.
  let mut em = Vec::new();
  emit_battery_info(
    BATTERYINFO_K3III,
    Some("PENTAX K-3 Mark III"),
    false,
    &mut em,
  );
  assert_eq!(find(&em, "PowerSource"), Some(TagValue::I64(1)));
  assert_eq!(find(&em, "PowerAvailable"), Some(TagValue::I64(1)));
  assert_eq!(find(&em, "BodyBatteryState"), Some(TagValue::I64(5)));
  // The raw ValueConv f64 (`$val*4e-8+0.27219`). The serializer's `format_g`
  // renders these to the golden's `7.47863424` / `5.88731624` (10-sig-fig); the
  // stored f64 carries the full IEEE-754 precision.
  assert_eq!(
    find(&em, "BodyBatteryVoltage"),
    Some(TagValue::F64(f64::from(180161106u32) * 4e-8 + 0.27219))
  );
  assert_eq!(
    find(&em, "GripBatteryVoltage"),
    Some(TagValue::F64(f64::from(140378156u32) * 4e-8 + 0.27219))
  );
}

#[test]
fn battery_info_istd_uses_raw_ad_variant() {
  // The *istD takes the raw-int `BodyBatteryAD*` variant (B) — NO `%d (%.1fV..)`
  // PrintConv — and the *ist `GripBatteryADNoLoad`/`ADLoad` raw leaves, but NOT
  // the K10D/K20D-only `GripBatteryState`. This proves a DIFFERENT-but-faithful
  // variant is selected (not the K10D PrintConv form).
  let mut em = Vec::new();
  emit_battery_info(BATTERYINFO_K10D, Some("PENTAX *ist D"), true, &mut em);
  assert_eq!(find(&em, "BodyBatteryADNoLoad"), Some(TagValue::I64(173)));
  assert_eq!(find(&em, "BodyBatteryADLoad"), Some(TagValue::I64(168)));
  assert_eq!(find(&em, "GripBatteryADNoLoad"), Some(TagValue::I64(5)));
  assert_eq!(find(&em, "GripBatteryADLoad"), Some(TagValue::I64(1)));
  assert!(find(&em, "GripBatteryState").is_none());
  // A `None` model (defensive — production always threads IFD0's Model) matches
  // ExifTool's `$$self{Model} !~ /K-3 Mark III/` on an undef Model = TRUE, so
  // the model-INDEPENDENT non-K-3III PowerSource hash emits; but every leaf
  // GATED on a positive model regex (the K10D-byte `BodyBatteryAD*` etc.)
  // stays suppressed — never a wrong value.
  let mut emn = Vec::new();
  emit_battery_info(BATTERYINFO_K10D, None, true, &mut emn);
  assert!(find(&emn, "PowerSource").is_some());
  assert!(find(&emn, "BodyBatteryADNoLoad").is_none());
  assert!(find(&emn, "BodyBatteryADLoad").is_none());
  assert!(find(&emn, "GripBatteryADNoLoad").is_none());
  assert!(find(&emn, "GripBatteryADLoad").is_none());
  assert!(find(&emn, "GripBatteryState").is_none());
  // A `None` model fails variant A (`=~` on undef = false) but matches variant
  // B's NEGATIVE gate (`!~ /(K110D|K2000|K-m|K-3 Mark III)/` on undef = TRUE), so
  // BodyBatteryState emits — exactly as ExifTool would for an undef Model.
  assert_eq!(
    find(&emn, "BodyBatteryState"),
    Some(TagValue::Str("Close to Full".into()))
  );
}

#[test]
fn af_info_excluded_models_drop_af_points_in_focus() {
  // The K-3 (and K-1/K-70/KP/K-S1/K-S2) are EXCLUDED from `0x0b AFPointsInFocus`
  // — those records have no such tag, so the gate must emit nothing there even
  // though the same byte yields "Center (horizontal)" for the K10D.
  for excluded in [
    "PENTAX K-1",
    "PENTAX K-3",
    "PENTAX K-3 Mark III",
    "PENTAX K-70",
    "PENTAX KP",
    "RICOH K-S1",
    "PENTAX K-S2",
  ] {
    let mut em = Vec::new();
    emit_af_info(AFINFO_K10D, Some(excluded), true, &mut em);
    assert!(
      find(&em, "AFPointsInFocus").is_none(),
      "{excluded} must not emit AFPointsInFocus"
    );
    // The unconditional AF leaves still emit (only 0x0b is gated).
    assert_eq!(find(&em, "AFPredictor"), Some(TagValue::I64(4)));
  }
  // A non-excluded model (e.g. the K-5) keeps AFPointsInFocus.
  let mut em = Vec::new();
  emit_af_info(AFINFO_K10D, Some("PENTAX K-5"), true, &mut em);
  assert_eq!(find(&em, "AFPointsInFocus"), Some(s("Center (horizontal)")));
}

// ---------------------------------------------------------------------------
// #173 ROUND-5 STRUCTURAL GATE-SUPPRESSION TESTS.
//
// Each #173 LensData leaf and each sub-table leaf carries an ExifTool
// `Condition`. The invariant: every gate must be ACTUALLY CHECKED IN CODE (not
// comment-only) — a leaf emits ONLY for the faithfully-decoded context its
// `Condition` selects, and SUPPRESSES (emits nothing) otherwise. These tests
// feed each gate a NON-verified context and assert zero emission for that leaf,
// so a comment-only gate (one that documents the `Condition` but never branches)
// would FAIL here. (Verified to fail if the MaxAperture `model != Some("K-5")`
// check is reverted.)
// ---------------------------------------------------------------------------

#[test]
fn lens_data_max_aperture_k5_gate_suppresses() {
  // `Pentax.pm:4559`: MaxAperture `Condition => '$$self{Model} ne "K-5"'` — an
  // EXACT-string compare against the BARE literal `"K-5"` (NOT a `=~ /K-5/`
  // regex). A model that is exactly `"K-5"` MUST suppress MaxAperture; the four
  // other LensData leaves (AutoAperture/MinAperture/FocusRangeIndex + the
  // unconditional ones) still emit.
  let mut em = Vec::new();
  emit_lens_info(LENSINFO2_K10D, 69, Some("K-5"), true, &mut em);
  assert!(
    find(&em, "MaxAperture").is_none(),
    "an exactly-\"K-5\" model must suppress MaxAperture (ne \"K-5\")"
  );
  // The gate is leaf-local: the sibling LensData leaves are unaffected.
  assert_eq!(find(&em, "AutoAperture"), Some(s("On")));
  assert_eq!(find(&em, "MinAperture"), Some(s("22")));
  assert_eq!(find(&em, "FocusRangeIndex"), Some(s("7 (very far)")));
  assert_eq!(find(&em, "LensFStops"), Some(TagValue::F64(8.5)));
  assert_eq!(find(&em, "NominalMaxAperture"), Some(s("4.0")));
  // The K10D fixture-equivalent count emits the OTHER eight leaves (all but
  // MaxAperture).
  assert_eq!(
    em.len(),
    8,
    "an exactly-\"K-5\" model drops only MaxAperture (8 of 9 leaves)"
  );
}

#[test]
fn lens_data_max_aperture_emits_for_full_pentax_k5_string() {
  // The faithful-quirk control: `$$self{Model}` is the FULL IFD0 Model, so a
  // REAL PENTAX K-5 body is `"PENTAX K-5"`, which is NOT exactly `"K-5"` ⇒ it
  // STILL passes `ne "K-5"` and emits MaxAperture (matching ExifTool, which
  // compares the full model against the bare literal — see `Pentax.pm:5148`
  // keying on the full `"PENTAX K-3 II"`). A substring/regex gate would wrongly
  // suppress this; the exact-equality gate must not.
  let mut em = Vec::new();
  emit_lens_info(LENSINFO2_K10D, 69, Some("PENTAX K-5"), true, &mut em);
  assert_eq!(
    find(&em, "MaxAperture"),
    Some(s("3.9")),
    "a full \"PENTAX K-5\" model is not exactly \"K-5\" ⇒ MaxAperture still emits"
  );
  assert_eq!(em.len(), 9, "\"PENTAX K-5\" emits all nine LensData leaves");
}

#[test]
fn lens_data_max_aperture_emits_for_k10d_fixture() {
  // The K10D fixture (`"PENTAX K10D"`, the byte-exact path) is not `"K-5"` ⇒
  // MaxAperture emits `3.9` (the `Pentax.jpg` golden value). This pins that the
  // gate does NOT over-suppress the fixture body.
  let mut em = Vec::new();
  emit_lens_info(LENSINFO2_K10D, 69, Some("PENTAX K10D"), true, &mut em);
  assert_eq!(find(&em, "MaxAperture"), Some(s("3.9")));
}

#[test]
fn af_info_af_points_in_focus_excluded_model_suppresses() {
  // `Pentax.pm:5070`: `0x0b AFPointsInFocus` `Condition => '$$self{Model} !~
  // /(K-(1|3|70|S1|S2)|KP)\b/'`. An EXCLUDED model (here the K-3, which `\b`
  // also matches inside `K-3 Mark III`) MUST suppress AFPointsInFocus, even
  // though the same byte yields "Center (horizontal)" for the K10D. The three
  // unconditional AF leaves (AFPredictor/AFDefocus/AFIntegrationTime) still
  // emit — proving the gate is leaf-local and actually branches.
  let mut em = Vec::new();
  emit_af_info(AFINFO_K10D, Some("PENTAX K-3"), true, &mut em);
  assert!(
    find(&em, "AFPointsInFocus").is_none(),
    "a K-3 (excluded) must suppress AFPointsInFocus"
  );
  assert_eq!(find(&em, "AFPredictor"), Some(TagValue::I64(4)));
  assert_eq!(find(&em, "AFDefocus"), Some(TagValue::I64(2)));
  assert_eq!(find(&em, "AFIntegrationTime"), Some(s("0 ms")));
  assert_eq!(em.len(), 3, "an excluded model drops only AFPointsInFocus");
}

#[test]
fn battery_info_non_k10d_model_suppresses_ad_layout() {
  // `Pentax.pm:4848`…: the K10D-byte `BodyBatteryADNoLoad`/`ADLoad` (PrintConv
  // variant A `/(K10D|GX10|K20D|GX20)\b/`) and `GripBatteryAD*`/`GripBatteryState`
  // are all `$$self{Model}`-gated. A K-5 (whose offsets 2/3/4 are the DIFFERENT
  // int16u `BodyBatteryVoltage*` tags the port defers) MUST suppress every
  // K10D-byte AD leaf — never re-read the K10D byte as the wrong tag.
  let mut em = Vec::new();
  emit_battery_info(BATTERYINFO_K10D, Some("PENTAX K-5"), true, &mut em);
  for wrong in [
    "BodyBatteryADNoLoad",
    "BodyBatteryADLoad",
    "GripBatteryADNoLoad",
    "GripBatteryADLoad",
    "GripBatteryState",
  ] {
    assert!(
      find(&em, wrong).is_none(),
      "a K-5 must suppress the K10D BatteryInfo leaf {wrong}"
    );
  }
  // BodyBatteryState is NOT a K10D-byte AD leaf — the K-5 matches variant B (the
  // 5-entry hash), so it emits (byte 1 mask 0xf0 = 4 → 'Close to Full', #311).
  assert_eq!(
    find(&em, "BodyBatteryState"),
    Some(TagValue::Str("Close to Full".into()))
  );
}

#[test]
fn lens_data_no_comment_only_gate_for_unconditional_leaves() {
  // The UNCONDITIONAL LensData leaves (MinFocusDistance @3, FocusRangeIndex @3.1,
  // NominalMax/MinAperture @10/10.1) carry NO ExifTool `Condition`, so they MUST
  // emit for every in-gate model — including an exactly-"K-5" model (only
  // MaxAperture is K-5-gated). This pins that the K-5 gate did not accidentally
  // over-suppress its neighbours.
  let mut em = Vec::new();
  emit_lens_info(LENSINFO2_K10D, 69, Some("K-5"), true, &mut em);
  assert_eq!(find(&em, "MinFocusDistance"), Some(s("0.49-0.50 m")));
  assert_eq!(find(&em, "FocusRangeIndex"), Some(s("7 (very far)")));
  assert_eq!(find(&em, "NominalMaxAperture"), Some(s("4.0")));
  assert_eq!(find(&em, "NominalMinAperture"), Some(s("23")));
}

/// A crafted `%Pentax::FilterInfo` (`0x022a`) block with NON-ZERO
/// SourceDirectoryIndex / SourceFileIndex. `%FilterInfo` is `FORMAT => 'int8u'`
/// (`Pentax.pm:5663`), so the row keys are BYTE offsets: SourceDirectoryIndex (key
/// 0) is the `int16u` at bytes 0-1 and SourceFileIndex (key 2) the `int16u` at
/// bytes 2-3 — NOT element index 2 (which would be byte 4). Bytes
/// `12 34 56 78 ab cd ..`: BigEndian → SourceDirectoryIndex `0x1234`,
/// SourceFileIndex `0x5678`; LittleEndian → `0x3412` / `0x7856`. The two
/// interpretations are DISTINCT, so the byte order is observable (unlike every
/// real fixture, where both leaves are 0 and a wrong order is invisible).
///
/// Bytes 4-5 (`ab cd`) are a DECOY at the WRONG `int16u`-element-index offset the
/// pre-fix code read SourceFileIndex from: they must NEVER appear in any emitted
/// value, guarding against the element-index layout creeping back.
const FILTERINFO_NONZERO: &[u8] = &[0x12, 0x34, 0x56, 0x78, 0xab, 0xcd, 0x00, 0x00];

#[test]
fn filter_info_non_ricoh_body_reads_big_endian() {
  // `0x022a` is `$$self{Make}`-VARIANT-SELECTED (`Pentax.pm:3030-3043`): a
  // non-RICOH body (here `Make => "PENTAX"`, the K-5 II) reads `%FilterInfo`
  // BigEndian — NOT the parent IFD order. With a non-zero block, BE yields the
  // raw values; this is the case the all-zero K-S2 record cannot exercise (the
  // byte-order bug it would otherwise mask).
  let mut em = Vec::new();
  emit_filter_info(FILTERINFO_NONZERO, Some("PENTAX"), &mut em);
  assert_eq!(
    find(&em, "SourceDirectoryIndex"),
    Some(TagValue::I64(0x1234)),
    "a non-RICOH body must read FilterInfo BigEndian"
  );
  // SourceFileIndex (key 2) is the int16u at BYTE 2 (FORMAT int8u ⇒ key = byte
  // offset), so BE bytes 2-3 (`56 78`) ⇒ 0x5678 — NOT bytes 4-5 (`ab cd`).
  assert_eq!(
    find(&em, "SourceFileIndex"),
    Some(TagValue::I64(0x5678)),
    "SourceFileIndex must read byte offset 2 (int8u-FORMAT key), not element index 2 (byte 4)"
  );
  // Regression: the pre-fix code read SourceFileIndex from bytes 4-5 (the decoy
  // `ab cd`). No emitted value may equal that BE/LE decoy.
  for e in &em {
    assert_ne!(
      e.value().as_ref(),
      &TagValue::I64(0xabcd),
      "{}: bytes 4-5 (the element-index offset) must be IGNORED",
      e.name()
    );
    assert_ne!(
      e.value().as_ref(),
      &TagValue::I64(0xcdab),
      "{}: bytes 4-5 (the element-index offset) must be IGNORED",
      e.name()
    );
  }
}

#[test]
fn filter_info_ricoh_body_reads_little_endian() {
  // The RICOH arm (`Make =~ /^RICOH/`) reads `%FilterInfo` LittleEndian
  // (`Pentax.pm:3032-3036`). The K-S2 / K-1 / K-3 / KP / K-70 fixtures all report
  // `Make => "RICOH IMAGING COMPANY, LTD."` ⇒ this arm. With the same non-zero
  // block the byte-swapped values prove the LE selection — distinct from the BE
  // values above.
  let mut em = Vec::new();
  emit_filter_info(
    FILTERINFO_NONZERO,
    Some("RICOH IMAGING COMPANY, LTD."),
    &mut em,
  );
  assert_eq!(
    find(&em, "SourceDirectoryIndex"),
    Some(TagValue::I64(0x3412)),
    "a RICOH body must read FilterInfo LittleEndian"
  );
  // SourceFileIndex at byte 2, LittleEndian ⇒ LE bytes 2-3 (`56 78`) → 0x7856.
  assert_eq!(
    find(&em, "SourceFileIndex"),
    Some(TagValue::I64(0x7856)),
    "a RICOH body must read FilterInfo LittleEndian at byte offset 2"
  );
}

#[test]
fn filter_info_byte_order_is_make_forced_not_parent_order() {
  // The bug the reviewer flagged: the old replay threaded the (LittleEndian) K-S2
  // PARENT order. A PENTAX body whose parent IFD is LittleEndian must STILL read
  // BigEndian — the order is forced by `$$self{Make}`, never inherited. Proven by
  // the BE result for `Make => "PENTAX"` differing from the LE-parent value.
  let mut be = Vec::new();
  emit_filter_info(FILTERINFO_NONZERO, Some("PENTAX"), &mut be);
  let mut le = Vec::new();
  emit_filter_info(
    FILTERINFO_NONZERO,
    Some("RICOH IMAGING COMPANY, LTD."),
    &mut le,
  );
  assert_ne!(
    find(&be, "SourceDirectoryIndex"),
    find(&le, "SourceDirectoryIndex"),
    "RICOH and non-RICOH must decode the same bytes differently"
  );
  // A missing Make defaults to the non-RICOH (BigEndian) arm (`/^RICOH/` fails).
  let mut none = Vec::new();
  emit_filter_info(FILTERINFO_NONZERO, None, &mut none);
  assert_eq!(
    find(&none, "SourceDirectoryIndex"),
    Some(TagValue::I64(0x1234)),
    "absent Make falls to the non-RICOH BigEndian arm"
  );
}

/// A crafted `%Pentax::LevelInfoK3III` (`0x022b`) block (`int8s`): byte 1 =
/// CameraOrientation; bytes 3-4 / 5-6 = RollAngle / PitchAngle (`int16s`,
/// parent-order). `.. 03 .. 00 10 ff f0`: CameraOrientation raw 3 ("Rotate 90
/// CW"); BigEndian RollAngle `0x0010`=16 → -8.0; PitchAngle `0xfff0`=-16 → +8.0.
const LEVELINFO_K3III: &[u8] = &[0x00, 0x03, 0x00, 0x00, 0x10, 0xff, 0xf0, 0x00];

#[test]
fn level_info_k3iii_decodes_orientation_and_int16s_angles() {
  // `%LevelInfoK3III` (`Pentax.pm:5771-5801`) — the K-3-III re-layout. The int16s
  // RollAngle/PitchAngle honour the threaded parent order (here BigEndian). No
  // PrintConv on the angles ⇒ the value is identical for `-j`/`-n`.
  let mut em = Vec::new();
  emit_level_info_k3iii(LEVELINFO_K3III, ByteOrder::Big, true, &mut em);
  assert_eq!(find(&em, "CameraOrientation"), Some(s("Rotate 90 CW")));
  assert_eq!(find(&em, "RollAngle"), Some(TagValue::F64(-8.0)));
  assert_eq!(find(&em, "PitchAngle"), Some(TagValue::F64(8.0)));
  // The K3III table has NO LevelOrientation / CompositionAdjust* leaves — they are
  // the K-5-style `%LevelInfo`'s, and must NOT appear here.
  assert!(find(&em, "LevelOrientation").is_none());
  assert!(find(&em, "CompositionAdjustX").is_none());
}

#[test]
fn level_info_k3iii_int16s_angles_follow_parent_order() {
  // The int16s angles carry no per-table ByteOrder ⇒ inherit the parent order. A
  // LittleEndian parent reads the SAME bytes byte-swapped (RollAngle `0x1000` =
  // 4096 → -2048.0), proving the order is actually threaded (not hard-coded BE).
  let mut em = Vec::new();
  emit_level_info_k3iii(LEVELINFO_K3III, ByteOrder::Little, true, &mut em);
  assert_eq!(find(&em, "RollAngle"), Some(TagValue::F64(-2048.0)));
  // PitchAngle bytes `ff f0` LE = `0xf0ff` = -3841 → -(-3841)/2 = 1920.5.
  assert_eq!(find(&em, "PitchAngle"), Some(TagValue::F64(1920.5)));
}

#[test]
fn level_info_k3iii_model_gate_selects_variant() {
  // The `0x022b` selector (`Pentax.pm:3044-3051`): only `/K-3 Mark III/` routes to
  // `%LevelInfoK3III`. `is_k3_mark_iii` is the dispatcher's gate — a bare "PENTAX
  // K-3" (the active fixture) must NOT match (no "Mark III"), so it stays on the
  // K-5-style `%LevelInfo`.
  assert!(is_k3_mark_iii(Some("PENTAX K-3 Mark III")));
  assert!(!is_k3_mark_iii(Some("PENTAX K-3")));
  assert!(!is_k3_mark_iii(Some("PENTAX K-S2")));
  assert!(!is_k3_mark_iii(None));
}

#[test]
fn face_info_decodes_faces_detected_and_position() {
  // `%Pentax::FaceInfo` (0x0060, `Pentax.pm:3264-3280`): FacesDetected @0 (int8u),
  // FacePosition @2 (int8u[2], space-joined "x y"). No PrintConv ⇒ identical for
  // `-j`/`-n`.
  let block: &[u8] = &[0x02, 0x00, 0x32, 0x28, 0x00];
  let mut em = Vec::new();
  emit_face_info(block, &mut em);
  assert_eq!(find(&em, "FacesDetected"), Some(TagValue::I64(2)));
  assert_eq!(find(&em, "FacePosition"), Some(s("50 40")));
}

#[test]
fn face_info_0x0060_is_unconditional_not_k3iii_gated() {
  // REGRESSION: the Main `0x0060` row (`Pentax.pm:2293-2297`) is a single `{...}`
  // with NO `Condition` — UNLIKE the `0x022b` LevelInfo variant ARRAY. So 0x0060
  // is decoded through `%FaceInfo` for EVERY body, the K-3 Mark III included; the
  // K-3III's `%FaceInfoK3III` is a SEPARATE tag id (0x040b), not a 0x0060 model
  // variant. `emit_face_info` therefore takes NO model argument: a K-3III's 0x0060
  // must still emit FacesDetected/FacePosition (it is NOT suppressed, and is never
  // re-decoded through the K3III int32u layout). Adding an `is_k3_mark_iii` gate to
  // the 0x0060 dispatch arm would be a DIVERGENCE from ExifTool and would wrongly
  // drop FaceInfo for a K-3III body — this test guards against that.
  let block: &[u8] = &[0x01, 0x00, 0x10, 0x20, 0x00];
  // The K3III gate that DOES apply to LevelInfo (0x022b) must NOT be consulted for
  // FaceInfo: there is no code path that suppresses 0x0060 for a K-3III, so the
  // emission is byte-identical whatever the body would be. We assert the K-5-style
  // `%FaceInfo` decode is produced (FacesDetected present).
  let mut em = Vec::new();
  emit_face_info(block, &mut em);
  assert_eq!(find(&em, "FacesDetected"), Some(TagValue::I64(1)));
  assert_eq!(find(&em, "FacePosition"), Some(s("16 32")));
  // Sanity: a body that WOULD match the LevelInfo K3III gate is still a normal
  // FaceInfo producer at 0x0060 — the gate is unrelated to this table.
  assert!(is_k3_mark_iii(Some("PENTAX K-3 Mark III")));
}

/// A complete `%AFInfoK3III` (`0x040c`) record for NumAFPoints=1, int16u BigEndian
/// (28 bytes = elements 0..=13). element 0 AFMode=0 (Phase Detect); element 1
/// AFSelectionMode=0x1 (Spot); element 2 MaxNumAFPoints=101; element 3
/// NumAFPoints=1; elements 4..=6 filler; the single AF-area 7-tuple at elements
/// 7..=13 = (frameW=600, frameH=400, X=300, Y=200, areaW=0, areaH=0, flags=0x14).
/// areaW/areaH=0 ⇒ bytes 22..26 are all-zero ⇒ AFAreaSize (the contrast-detect
/// leaf) is correctly suppressed.
const AFINFO_K3III_COMPLETE: &[u8] = &[
  0x00, 0x00, // 0  AFMode = 0
  0x00, 0x01, // 1  AFSelectionMode = 0x1
  0x00, 0x65, // 2  MaxNumAFPoints = 101
  0x00, 0x01, // 3  NumAFPoints = 1
  0x00, 0x00, // 4
  0x00, 0x00, // 5
  0x00, 0x00, // 6
  0x02, 0x58, // 7  frameW = 600 (AFFrameSize width)
  0x01, 0x90, // 8  frameH = 400 (AFFrameSize height)
  0x01, 0x2c, // 9  X = 300
  0x00, 0xc8, // 10 Y = 200
  0x00, 0x00, // 11 areaW = 0 (AFAreaSize suppressed)
  0x00, 0x00, // 12 areaH = 0
  0x00, 0x14, // 13 flags = 0x14 (central + peripheral + in-focus)
];

/// `AFINFO_K3III_COMPLETE` truncated to 14 bytes (elements 0..=6 only): the
/// AFAreas run's first int16u (element 7 = bytes 14..16) is ABSENT. Declared as
/// its own literal rather than a runtime slice so the test stays index-free.
const AFINFO_K3III_TRUNCATED_BEFORE_AREA: &[u8] = &[
  0x00, 0x00, // 0  AFMode = 0
  0x00, 0x01, // 1  AFSelectionMode = 0x1
  0x00, 0x65, // 2  MaxNumAFPoints = 101
  0x00, 0x01, // 3  NumAFPoints = 1
  0x00, 0x00, // 4
  0x00, 0x00, // 5
  0x00, 0x00, // 6 (record ends here — element 7 absent)
];

/// `AFINFO_K3III_COMPLETE` truncated to 20 bytes (elements 0..=9): element 7 IS
/// present but the 7-value AF-area tuple overruns the record — only 3 whole int16u
/// (elements 7,8,9 = 600,400,300) fit, element 10's bytes 20..22 are absent.
const AFINFO_K3III_PARTIAL_AREA: &[u8] = &[
  0x00, 0x00, // 0  AFMode = 0
  0x00, 0x01, // 1  AFSelectionMode = 0x1
  0x00, 0x65, // 2  MaxNumAFPoints = 101
  0x00, 0x01, // 3  NumAFPoints = 1
  0x00, 0x00, // 4
  0x00, 0x00, // 5
  0x00, 0x00, // 6
  0x02, 0x58, // 7  frameW = 600
  0x01, 0x90, // 8  frameH = 400
  0x01, 0x2c, // 9  X = 300 (record ends here — element 10 absent)
];

#[test]
fn af_info_k3iii_complete_record_emits_areas() {
  // The full 28-byte record (NumAFPoints=1): the scalars decode and the AFAreas
  // run is present (element 7 = byte 14 IS within the record), so AFAreas emits
  // the single `"X,Y(flags)"` tuple. flags 0x14 → 0x10 'central', 0x08-unset
  // 'peripheral', 0x04 'in-focus'. AFFrameSize = 600x400. areaW/areaH=0 ⇒
  // AFAreaSize suppressed (phase-detect). This pins the byte-exact K-3III PEF
  // path the truncation guard must NOT regress.
  let mut em = Vec::new();
  emit_af_info_k3iii(AFINFO_K3III_COMPLETE, ByteOrder::Big, true, &mut em);
  assert_eq!(find(&em, "AFMode"), Some(s("Phase Detect")));
  assert_eq!(find(&em, "AFSelectionMode"), Some(s("Spot")));
  assert_eq!(find(&em, "MaxNumAFPoints"), Some(TagValue::I64(101)));
  assert_eq!(find(&em, "NumAFPoints"), Some(TagValue::I64(1)));
  assert_eq!(find(&em, "AFFrameSize"), Some(s("600x400")));
  assert_eq!(
    find(&em, "AFAreas"),
    Some(TagValue::List(vec![s(
      "300,200(central,peripheral,in-focus)"
    )]))
  );
  // areaW/areaH = 0 ⇒ the first 4 bytes of the AFAreaSize leaf (bytes 22..26) are
  // zero ⇒ the contrast-detect-only AFAreaSize is suppressed.
  assert!(find(&em, "AFAreaSize").is_none());
}

#[test]
fn af_info_k3iii_complete_record_value_conv_run() {
  // `-n` (print_conv=false): AFAreas is the WHOLE space-joined int16u run (no
  // PrintConv); AFFrameSize is the space-joined pair. The complete record emits
  // the full 7-value run for the single point.
  let mut em = Vec::new();
  emit_af_info_k3iii(AFINFO_K3III_COMPLETE, ByteOrder::Big, false, &mut em);
  assert_eq!(find(&em, "AFFrameSize"), Some(s("600 400")));
  // The single 7-tuple: 600 400 300 200 0 0 20.
  assert_eq!(find(&em, "AFAreas"), Some(s("600 400 300 200 0 0 20")));
}

#[test]
fn af_info_k3iii_truncated_before_area_skips_afareas() {
  // ProcessBinaryData skips a row whose start offset is outside the record: the
  // AFAreas run starts at element 7 = byte 14. A record that carries NumAFPoints
  // (>0) but stops BEFORE byte 14 (here 14 bytes, indices 0..13, so element 7's
  // first int16u at bytes 14..16 is absent) reaches `last`/`undef` in ExifTool —
  // it emits NO AFAreas tag. The port must SKIP AFAreas, not emit the empty-run
  // `(none)`/`[]`. The scalars (elements 0..=3) still decode.
  let mut em = Vec::new();
  emit_af_info_k3iii(
    AFINFO_K3III_TRUNCATED_BEFORE_AREA,
    ByteOrder::Big,
    true,
    &mut em,
  );
  assert_eq!(find(&em, "NumAFPoints"), Some(TagValue::I64(1)));
  // AFFrameSize (element 7..=8) and AFAreas (element 7+) are both absent — NOT an
  // empty list, NOT `(none)`.
  assert!(find(&em, "AFFrameSize").is_none());
  assert!(find(&em, "AFAreas").is_none());
  assert!(find(&em, "AFAreaSize").is_none());
}

#[test]
fn af_info_k3iii_truncated_before_area_value_conv_also_skips() {
  // Same truncation under `-n`: ExifTool emits no AFAreas value at all, so the
  // port must NOT fall into the empty-`(none)` branch of the AFAreasK3III
  // PrintConv — that branch models an empty *value*, not an absent *row*.
  let mut em = Vec::new();
  emit_af_info_k3iii(
    AFINFO_K3III_TRUNCATED_BEFORE_AREA,
    ByteOrder::Big,
    false,
    &mut em,
  );
  assert_eq!(find(&em, "NumAFPoints"), Some(TagValue::I64(1)));
  assert!(find(&em, "AFAreas").is_none());
}

#[test]
fn af_info_k3iii_partial_area_tuple_keeps_whole_int16u() {
  // Element 7 IS present but the full `int16u[7*NumAFPoints]` overruns the record:
  // ExifTool's ReadValue shortens the count to as many WHOLE int16u as fit. Here
  // the record stops mid-run (20 bytes ⇒ elements 7,8,9 readable = 3 whole int16u
  // of the 7-value tuple; element 10's bytes 20..22 are absent). The collect loop
  // keeps the 3 readable int16u and renders the PrintConv from what is present
  // (one incomplete tuple < 7 values ⇒ NO `"X,Y(flags)"` string for `-j`; the
  // space-joined partial run for `-n`).
  //
  // `-j`: fewer than 7 area values ⇒ the `while i+7 <= len` loop produces NO
  // tuple, so AFAreas is the empty LIST (an emitted tag, since element 7 IS
  // present — the row is NOT skipped, only its single tuple is incomplete).
  let mut em = Vec::new();
  emit_af_info_k3iii(AFINFO_K3III_PARTIAL_AREA, ByteOrder::Big, true, &mut em);
  assert_eq!(find(&em, "NumAFPoints"), Some(TagValue::I64(1)));
  assert_eq!(find(&em, "AFFrameSize"), Some(s("600x400"))); // elements 7,8 present
  assert_eq!(find(&em, "AFAreas"), Some(TagValue::List(vec![])));
  // `-n`: the space-joined run of the 3 readable int16u (600 400 300).
  let mut em_n = Vec::new();
  emit_af_info_k3iii(AFINFO_K3III_PARTIAL_AREA, ByteOrder::Big, false, &mut em_n);
  assert_eq!(find(&em_n, "AFAreas"), Some(s("600 400 300")));
}

#[test]
fn af_info_k3iii_partial_frame_size_keeps_single_int16u() {
  // AFFrameSize is a FIXED `int16u[2]` at element 7 (byte 14). When the record ends
  // mid-pair (element 7 readable, element 8 = bytes 16..18 absent) ExifTool's
  // ReadValue shortens the count to the one WHOLE int16u that fits and returns it.
  // The PrintConv `s/ /x/` has no space to rewrite, so the single value passes
  // through. Oracle (bundled, 16-byte record, NumAFPoints=1): AFFrameSize='600'
  // (`-n` likewise '600'); AFAreas='600' raw ⇒ empty list for `-j`. The whole-pair
  // both-present guard would have dropped this — the field must emit the partial.
  let block = &AFINFO_K3III_COMPLETE[..16]; // elements 0..=7 (element 7 = 600)
  let mut em = Vec::new();
  emit_af_info_k3iii(block, ByteOrder::Big, true, &mut em);
  assert_eq!(find(&em, "NumAFPoints"), Some(TagValue::I64(1)));
  assert_eq!(find(&em, "AFFrameSize"), Some(s("600")));
  assert_eq!(find(&em, "AFAreas"), Some(TagValue::List(vec![]))); // raw "600" < 7-tuple
  let mut em_n = Vec::new();
  emit_af_info_k3iii(block, ByteOrder::Big, false, &mut em_n);
  assert_eq!(find(&em_n, "AFFrameSize"), Some(s("600")));
  assert_eq!(find(&em_n, "AFAreas"), Some(s("600")));
}

/// A 24-byte contrast-detect record (elements 0..=11): NumAFPoints=1, areaW (element
/// 11, bytes 22..24) = 64 ≠ 0 ⇒ contrast-detect, but element 12 (bytes 24..26, areaH)
/// is ABSENT — AFAreaSize's `int16u[2]` ends mid-pair.
const AFINFO_K3III_PARTIAL_AREASIZE: &[u8] = &[
  0x00, 0x00, // 0  AFMode = 0
  0x00, 0x01, // 1  AFSelectionMode = 0x1
  0x00, 0x65, // 2  MaxNumAFPoints = 101
  0x00, 0x01, // 3  NumAFPoints = 1
  0x00, 0x00, // 4
  0x00, 0x00, // 5
  0x00, 0x00, // 6
  0x02, 0x58, // 7  frameW = 600
  0x01, 0x90, // 8  frameH = 400
  0x01, 0x2c, // 9  X = 300
  0x00, 0xc8, // 10 Y = 200
  0x00, 0x40, // 11 areaW = 64 (contrast-detect; record ends here — element 12 absent)
];

#[test]
fn af_info_k3iii_partial_area_size_keeps_single_int16u() {
  // AFAreaSize is a FIXED `int16u[2]` at element 11 (byte 22), gated on
  // NumAFPoints>0 AND `$$valPt !~ /^\0\0\0\0/`. `$$valPt` is the AVAILABLE leaf
  // bytes (here 2: 0x00 0x40), which cannot match the 4-NUL regex ⇒ Condition
  // passes; ReadValue then shortens the pair to the single readable int16u (64).
  // Oracle (bundled, 24-byte record): AFAreaSize='64' (`-n` '64'). A 4-byte-fixed
  // `$$valPt` slice or a both-present guard would have wrongly suppressed it.
  let mut em = Vec::new();
  emit_af_info_k3iii(AFINFO_K3III_PARTIAL_AREASIZE, ByteOrder::Big, true, &mut em);
  assert_eq!(find(&em, "AFFrameSize"), Some(s("600x400")));
  assert_eq!(find(&em, "AFAreaSize"), Some(s("64")));
  let mut em_n = Vec::new();
  emit_af_info_k3iii(
    AFINFO_K3III_PARTIAL_AREASIZE,
    ByteOrder::Big,
    false,
    &mut em_n,
  );
  assert_eq!(find(&em_n, "AFAreaSize"), Some(s("64")));
}

/// A FULL `%AFInfoK3III` record (28 bytes, element 7 = byte 14 readable) with
/// NumAFPoints=0. Differs from `AFINFO_K3III_COMPLETE` only at element 3.
const AFINFO_K3III_NUM_ZERO_PRESENT: &[u8] = &[
  0x00, 0x00, // 0  AFMode = 0
  0x00, 0x01, // 1  AFSelectionMode = 0x1
  0x00, 0x65, // 2  MaxNumAFPoints = 101
  0x00, 0x00, // 3  NumAFPoints = 0
  0x00, 0x00, // 4
  0x00, 0x00, // 5
  0x00, 0x00, // 6
  0x02, 0x58, // 7
  0x01, 0x90, // 8
  0x01, 0x2c, // 9
  0x00, 0xc8, // 10
  0x00, 0x00, // 11
  0x00, 0x00, // 12
  0x00, 0x14, // 13
];

#[test]
fn af_info_k3iii_num_af_points_zero_present_record_emits_empty_afareas() {
  // %AFInfoK3III gives AFAreas (7.1) NO Condition — only AFFrameSize (7) and
  // AFAreaSize (11) gate on `$$self{NumAFPoints} > 0`. For a PRESENT record
  // (element 7 = byte 14 within the data) with NumAFPoints==0, ExifTool evaluates
  // AFAreas's `int16u[7 * $val{3}]` = int16u[0]: ReadValue's `unless($count){return ''
  // if defined $count ...}` returns the DEFINED empty value, so the AFAreas tag IS
  // handled. Its PrintConv `AFAreasK3III('')` then hits `return '(none)' unless $val`.
  //
  // Oracle (bundled ExifTool 13.59, ProcessBinaryData on this record): PrintConv ⇒
  // `AFAreas = (none)`; `-n` ⇒ `AFAreas = ''` (empty). AFFrameSize/AFAreaSize are
  // both suppressed by the NumAFPoints>0 Condition. (Contrast the truncated-record
  // case below, where element 7 is ABSENT and AFAreas is skipped entirely.)
  let mut em = Vec::new();
  emit_af_info_k3iii(AFINFO_K3III_NUM_ZERO_PRESENT, ByteOrder::Big, true, &mut em);
  assert_eq!(find(&em, "NumAFPoints"), Some(TagValue::I64(0)));
  assert_eq!(find(&em, "AFAreas"), Some(s("(none)")));
  assert!(find(&em, "AFFrameSize").is_none());
  assert!(find(&em, "AFAreaSize").is_none());

  // `-n`: AFAreas is the raw empty value (no PrintConv ⇒ not `(none)`).
  let mut em_n = Vec::new();
  emit_af_info_k3iii(
    AFINFO_K3III_NUM_ZERO_PRESENT,
    ByteOrder::Big,
    false,
    &mut em_n,
  );
  assert_eq!(find(&em_n, "AFAreas"), Some(s("")));
  assert!(find(&em_n, "AFFrameSize").is_none());
  assert!(find(&em_n, "AFAreaSize").is_none());
}

#[test]
fn af_info_k3iii_num_af_points_zero_truncated_before_area_skips_afareas() {
  // The other half of the NumAFPoints==0 case: when the record stops BEFORE element
  // 7 (byte 14), `$more = $size - 14 <= 0` ⇒ ProcessBinaryData reaches `last` and
  // emits NO AFAreas tag (the row start is outside the data). This is the row-bound
  // skip, distinct from the present-zero-count empty value above. The first 7
  // elements of `AFINFO_K3III_NUM_ZERO_PRESENT` truncated to 14 bytes.
  let block = &AFINFO_K3III_NUM_ZERO_PRESENT[..14];
  let mut em = Vec::new();
  emit_af_info_k3iii(block, ByteOrder::Big, true, &mut em);
  assert_eq!(find(&em, "NumAFPoints"), Some(TagValue::I64(0)));
  assert!(find(&em, "AFAreas").is_none());
  assert!(find(&em, "AFFrameSize").is_none());
  assert!(find(&em, "AFAreaSize").is_none());
}

/// A 15-byte `%AFInfoK3III` record (elements 0..=6 whole, plus the lone byte 14 =
/// the AFAreas row START) with NumAFPoints=0. Byte 14 is present but byte 15 is
/// ABSENT — element 7 is NOT a complete int16u. This is the exact one-byte boundary
/// where the row IS dispatched (`$more = 15 - 14 = 1 > 0`) but no full int16u exists.
const AFINFO_K3III_ROW_START_ONLY_NUM_ZERO: &[u8] = &[
  0x00, 0x00, // 0  AFMode = 0
  0x00, 0x01, // 1  AFSelectionMode = 0x1
  0x00, 0x65, // 2  MaxNumAFPoints = 101
  0x00, 0x00, // 3  NumAFPoints = 0
  0x00, 0x00, // 4
  0x00, 0x00, // 5
  0x00, 0x00, // 6
  0x02, //       byte 14 = the AFAreas row start (byte 15 absent — element 7 incomplete)
];

#[test]
fn af_info_k3iii_row_start_only_num_zero_emits_empty_afareas() {
  // The one-byte boundary the #393 fix targets: a 15-byte record exposes byte 14
  // (the AFAreas row start) but NOT byte 15, so `u16_at(7)` would be None — yet
  // ProcessBinaryData dispatches the row on `$more = $size - 14 = 1 > 0`, and for
  // NumAFPoints==0 ReadValue's `unless($count){ return '' if defined $count }`
  // returns the DEFINED empty value BEFORE checking that a full int16u fits. So
  // AFAreas MUST emit empty here (`(none)` PrintConv / `""` -n), NOT be skipped.
  // Ground-truthed against bundled ExifTool 13.59: ReadValue(count=0, size=1) ⇒ ''.
  let mut em = Vec::new();
  emit_af_info_k3iii(
    AFINFO_K3III_ROW_START_ONLY_NUM_ZERO,
    ByteOrder::Big,
    true,
    &mut em,
  );
  assert_eq!(find(&em, "NumAFPoints"), Some(TagValue::I64(0)));
  assert_eq!(find(&em, "AFAreas"), Some(s("(none)")));
  // AFFrameSize/AFAreaSize stay suppressed by the NumAFPoints>0 Condition.
  assert!(find(&em, "AFFrameSize").is_none());
  assert!(find(&em, "AFAreaSize").is_none());

  // `-n`: AFAreas is the raw empty value (no PrintConv ⇒ not `(none)`).
  let mut em_n = Vec::new();
  emit_af_info_k3iii(
    AFINFO_K3III_ROW_START_ONLY_NUM_ZERO,
    ByteOrder::Big,
    false,
    &mut em_n,
  );
  assert_eq!(find(&em_n, "AFAreas"), Some(s("")));
}

/// Same 15-byte row-start-only record but with NumAFPoints=1 (count = 7*1 = 7).
const AFINFO_K3III_ROW_START_ONLY_NUM_ONE: &[u8] = &[
  0x00, 0x00, // 0  AFMode = 0
  0x00, 0x01, // 1  AFSelectionMode = 0x1
  0x00, 0x65, // 2  MaxNumAFPoints = 101
  0x00, 0x01, // 3  NumAFPoints = 1
  0x00, 0x00, // 4
  0x00, 0x00, // 5
  0x00, 0x00, // 6
  0x02, //       byte 14 = row start only
];

#[test]
fn af_info_k3iii_row_start_only_num_one_skips_afareas() {
  // The complementary half of the byte-14 boundary: with NumAFPoints>0 the count is
  // 7 (>0), so ReadValue shortens it to `int($more/2) = int(1/2) = 0` whole int16u
  // and `$count < 1 and return undef` — ProcessBinaryData's `next unless defined
  // $val` then SKIPS the tag. So byte 14 ALONE with NumAFPoints>0 emits no AFAreas
  // (distinct from the NumAFPoints==0 defined-empty case above). Ground-truthed:
  // ReadValue(count=7, size=1) ⇒ undef.
  let mut em = Vec::new();
  emit_af_info_k3iii(
    AFINFO_K3III_ROW_START_ONLY_NUM_ONE,
    ByteOrder::Big,
    true,
    &mut em,
  );
  assert_eq!(find(&em, "NumAFPoints"), Some(TagValue::I64(1)));
  assert!(find(&em, "AFAreas").is_none());
  // AFFrameSize (fixed int16u[2] at element 7) also shortens to 0 whole int16u here
  // (only byte 14) ⇒ ReadValue undef ⇒ skipped.
  assert!(find(&em, "AFFrameSize").is_none());
  assert!(find(&em, "AFAreaSize").is_none());

  let mut em_n = Vec::new();
  emit_af_info_k3iii(
    AFINFO_K3III_ROW_START_ONLY_NUM_ONE,
    ByteOrder::Big,
    false,
    &mut em_n,
  );
  assert!(find(&em_n, "AFAreas").is_none());
}

#[test]
fn af_info_k3iii_contrast_detect_emits_afareasize() {
  // areaW/areaH non-zero (bytes 22..26 not all zero) ⇒ contrast-detect ⇒ the
  // `$$valPt !~ /^\0\0\0\0/` half of the AFAreaSize Condition passes and
  // AFAreaSize emits (elements 11,12, `s/ /x/`). Confirms the truncation guard
  // leaves the contrast-detect path intact. Element 11 (areaW, bytes 22..24) = 64
  // and element 12 (areaH, bytes 24..26) = 48; the rest matches the complete
  // record, so bytes 22..26 are no longer all-zero ⇒ contrast-detect.
  let block: &[u8] = &[
    0x00, 0x00, // 0  AFMode = 0
    0x00, 0x01, // 1  AFSelectionMode = 0x1
    0x00, 0x65, // 2  MaxNumAFPoints = 101
    0x00, 0x01, // 3  NumAFPoints = 1
    0x00, 0x00, // 4
    0x00, 0x00, // 5
    0x00, 0x00, // 6
    0x02, 0x58, // 7  frameW = 600
    0x01, 0x90, // 8  frameH = 400
    0x01, 0x2c, // 9  X = 300
    0x00, 0xc8, // 10 Y = 200
    0x00, 0x40, // 11 areaW = 64
    0x00, 0x30, // 12 areaH = 48
    0x00, 0x14, // 13 flags = 0x14
  ];
  let mut em = Vec::new();
  emit_af_info_k3iii(block, ByteOrder::Big, true, &mut em);
  assert_eq!(find(&em, "AFAreaSize"), Some(s("64x48")));
}

#[test]
fn push_af_areas_k3iii_empty_value_render() {
  // The AFAreasK3III PrintConv `return '(none)' unless $val` keys off the RAW value,
  // and runs ONLY in PrintConv mode. The faithful renderings of a zero-count run:
  //   PrintConv (`-j`): the empty raw value ⇒ `(none)` SCALAR.
  //   `-n`:             no PrintConv ⇒ the raw value itself, the empty string `""`.
  // (Bundled ExifTool on a NumAFPoints==0 record: `AFAreas=(none)` vs `AFAreas=''`.)
  let mut em_j = Vec::new();
  push_af_areas_k3iii(&[], true, &mut em_j);
  assert_eq!(find(&em_j, "AFAreas"), Some(s("(none)")));
  let mut em_n = Vec::new();
  push_af_areas_k3iii(&[], false, &mut em_n);
  assert_eq!(find(&em_n, "AFAreas"), Some(s("")));
}

#[test]
fn push_af_areas_k3iii_short_nonempty_run_is_empty_list_not_none() {
  // A NON-empty raw value shorter than one 7-tuple passes `unless $val` (it is
  // truthy) and falls through to the loop, which produces no `"X,Y(flags)"` string
  // ⇒ the empty ARRAYREF `[]` (NOT `(none)`, which is only for an empty value).
  // Under `-n` it is the space-joined raw run. Pins the `(none)`-vs-`[]` boundary.
  let mut em_j = Vec::new();
  push_af_areas_k3iii(&[600, 400, 300], true, &mut em_j);
  assert_eq!(find(&em_j, "AFAreas"), Some(TagValue::List(vec![])));
  let mut em_n = Vec::new();
  push_af_areas_k3iii(&[600, 400, 300], false, &mut em_n);
  assert_eq!(find(&em_n, "AFAreas"), Some(s("600 400 300")));
}
