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
