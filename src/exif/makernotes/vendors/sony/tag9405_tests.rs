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

/// `parse_tag9405a`/`parse_tag9405b` take the ALREADY-DECIPHERED block (the
/// dispatcher deciphers centrally), so the unit tests pass plaintext buffers
/// directly — the cipher round-trip is exercised by `decipher_tests.rs`.
fn find<'a>(em: &'a [Tag9405Emission], name: &str) -> Option<&'a TagValue> {
  em.iter().rev().find(|e| e.name == name).map(|e| &e.value)
}

fn as_str(tv: &TagValue) -> &str {
  match tv {
    TagValue::Str(s) => s.as_str(),
    other => panic!("expected Str, got {other:?}"),
  }
}

// --- variant gates -----------------------------------------------------------

/// The variant gate tests the RAW (enciphered) FIRST byte (`Sony.pm:2027`/`2032`).
#[test]
fn variant_gates() {
  // Tag9405a: first byte ∈ {0x1b, 0x40, 0x7d}.
  for b in [0x1b_u8, 0x40, 0x7d] {
    assert!(selects_tag9405a(&[b, 0xaa, 0xbb]));
    assert!(!selects_tag9405b(&[b]));
  }
  // Tag9405b: first byte ∈ {0x3a, 0xb3, 0x7e, 0x9a, 0x25, 0xe1, 0x76, 0x8b}.
  for b in [0x3a_u8, 0xb3, 0x7e, 0x9a, 0x25, 0xe1, 0x76, 0x8b] {
    assert!(selects_tag9405b(&[b, 0x00]));
    assert!(!selects_tag9405a(&[b]));
  }
  // Neither variant + short buffers.
  assert!(!selects_tag9405a(&[0x00]));
  assert!(!selects_tag9405b(&[0xff]));
  assert!(!selects_tag9405a(&[]));
  assert!(!selects_tag9405b(&[]));
}

// --- Tag9405a ----------------------------------------------------------------

#[test]
fn tag9405a_print() {
  let mut p = vec![0u8; 0x6f0];
  p[0x0600] = 1; // DistortionCorrParamsPresent = Yes
  p[0x0601] = 1; // DistortionCorrection = Applied
  p[0x0603] = 2; // LensFormat = Full-frame
  p[0x0604] = 2; // LensMount = E-mount (DataMember = 2)
  put_u16(&mut p, 0x0605, 2); // LensType2 = id 2 (E-mount)
  put_i16(&mut p, 0x064a, 16); // VignettingCorrParams[0]
  put_i16(&mut p, 0x064a + 2, -5); // VignettingCorrParams[1]
  put_i16(&mut p, 0x066a, 32); // ChromaticAberrationCorrParams[0]
  put_i16(&mut p, 0x06ca, 8); // DistortionCorrParams[0]

  let em = parse_tag9405a(&p, Some("NEX-5N"), true);
  assert_eq!(
    find(&em, "DistortionCorrParamsPresent"),
    Some(&TagValue::Str("Yes".into()))
  );
  assert_eq!(
    find(&em, "DistortionCorrection"),
    Some(&TagValue::Str("Applied".into()))
  );
  assert_eq!(
    find(&em, "LensFormat"),
    Some(&TagValue::Str("Full-frame".into()))
  );
  assert_eq!(
    find(&em, "LensMount"),
    Some(&TagValue::Str("E-mount".into()))
  );
  assert_eq!(
    find(&em, "LensType2"),
    Some(&TagValue::Str("Sony LA-EA2 Adapter".into()))
  );
  assert!(find(&em, "LensType").is_none()); // A-mount gate (LensMount != 1)

  let vcp = as_str(find(&em, "VignettingCorrParams").unwrap());
  assert_eq!(vcp.split(' ').count(), 16);
  assert!(vcp.starts_with("16 "));
  assert!(vcp.contains("-5")); // int16s signedness
  let cacp = as_str(find(&em, "ChromaticAberrationCorrParams").unwrap());
  assert_eq!(cacp.split(' ').count(), 32);
  assert!(cacp.starts_with("32 "));
  let dcp = as_str(find(&em, "DistortionCorrParams").unwrap());
  assert_eq!(dcp.split(' ').count(), 16);
  assert!(dcp.starts_with("8 "));
}

#[test]
fn tag9405a_raw() {
  let mut p = vec![0u8; 0x60c];
  p[0x0603] = 2;
  p[0x0604] = 2;
  put_u16(&mut p, 0x0605, 2);
  let em = parse_tag9405a(&p, Some("NEX-5N"), false);
  assert_eq!(find(&em, "LensFormat"), Some(&TagValue::I64(2)));
  assert_eq!(find(&em, "LensMount"), Some(&TagValue::I64(2)));
  assert_eq!(find(&em, "LensType2"), Some(&TagValue::I64(2)));
}

/// `LensMount` `RawConv` latches the DataMember UNCONDITIONALLY but suppresses
/// the TAG for a DSC body (`$$self{Model} =~ /^(DSC-|Stellar)/ ? undef : $val`).
/// So a DSC body emits no `LensMount`/conditional leaves, yet `LensType2` still
/// fires off the latched DataMember.
#[test]
fn tag9405a_dsc_latches_datamember_but_suppresses_tag() {
  let mut p = vec![0u8; 0x60c];
  p[0x0600] = 1; // DistortionCorrParamsPresent (suppressed for DSC)
  p[0x0604] = 2; // LensMount byte (DataMember latched, tag suppressed)
  put_u16(&mut p, 0x0605, 2); // LensType2 (gate only LensMount == 2)
  let em = parse_tag9405a(&p, Some("DSC-RX1"), true);
  assert!(find(&em, "LensMount").is_none());
  assert!(find(&em, "DistortionCorrParamsPresent").is_none());
  // 0x0601 DistortionCorrection has NO model Condition ⇒ still emitted (0 → None).
  assert_eq!(
    find(&em, "DistortionCorrection"),
    Some(&TagValue::Str("None".into()))
  );
  // DataMember latched ⇒ LensType2 still resolves.
  assert_eq!(
    find(&em, "LensType2"),
    Some(&TagValue::Str("Sony LA-EA2 Adapter".into()))
  );
}

/// `LensMount == 1` selects the A-mount `LensType` (`%sonyLensTypes`); `LensType2`
/// (gate `== 2`) does not fire.
#[test]
fn tag9405a_amount_lenstype() {
  let mut p = vec![0u8; 0x60c];
  p[0x0604] = 1; // LensMount = A-mount
  put_u16(&mut p, 0x0608, 2); // LensType = A-mount id 2
  let em = parse_tag9405a(&p, Some("SLT-A99V"), true);
  assert_eq!(
    find(&em, "LensMount"),
    Some(&TagValue::Str("A-mount".into()))
  );
  assert_eq!(
    find(&em, "LensType"),
    Some(&TagValue::Str("Minolta AF 28-70mm F2.8 G".into()))
  );
  assert!(find(&em, "LensType2").is_none());
}

/// A hash-PrintConv miss renders `"Unknown ($val)"`.
#[test]
fn tag9405a_lens_format_unknown() {
  let mut p = vec![0u8; 0x60c];
  p[0x0603] = 9; // not in {0,1,2}
  let em = parse_tag9405a(&p, Some("NEX-5N"), true);
  assert_eq!(
    find(&em, "LensFormat"),
    Some(&TagValue::Str("Unknown (9)".into()))
  );
}

// --- Tag9405b ----------------------------------------------------------------

/// Build the `Tag9405b` scalar region (offsets ≤ 0x0064) for an `ILCE-7M2` body.
fn b_scalar_block() -> Vec<u8> {
  let mut p = vec![0u8; 0x84];
  put_u16(&mut p, 0x0004, 2048); // SonyISO → 25600
  put_u16(&mut p, 0x0006, 2304); // BaseISO → 12800
  put_u16(&mut p, 0x000a, 512); // StopsAboveBaseISO → 14.0
  put_u16(&mut p, 0x000e, 5888); // SonyExposureTime2 → 1/128
  put_u16(&mut p, 0x0010, 1); // ExposureTime num
  put_u16(&mut p, 0x0012, 128); // ExposureTime den → 1/128
  put_u16(&mut p, 0x0014, 5120); // SonyFNumber → 4.0
  put_u16(&mut p, 0x0016, 4608); // SonyMaxApertureValue → 2.0
  put_u32(&mut p, 0x0024, 4); // SequenceImageNumber → 5
  p[0x0034] = 0; // ReleaseMode2 → Normal
  put_u16(&mut p, 0x003e, 6000); // SonyImageWidthMax
  put_u16(&mut p, 0x0040, 4000); // SonyImageHeightMax
  p[0x0042] = 2; // HighISONoiseReduction → Normal
  p[0x0044] = 1; // LongExposureNoiseReduction → On
  p[0x0046] = 0; // PictureEffect2 → Off
  p[0x0048] = 3; // ExposureProgram → Manual
  p[0x004a] = 5; // CreativeStyle → B&W
  p[0x0052] = 3; // Sharpness → +3
  p[0x005a] = 1; // DistortionCorrParamsPresent → Yes
  p[0x005b] = 1; // DistortionCorrection → Applied
  p[0x005d] = 1; // LensFormat → APS-C
  p[0x005e] = 2; // LensMount → E-mount (DataMember)
  put_u16(&mut p, 0x0060, 2); // LensType2 → id 2
  put_i16(&mut p, 0x0064, 6); // DistortionCorrParams[0]
  p
}

#[test]
fn tag9405b_scalars_print() {
  let em = parse_tag9405b(&b_scalar_block(), Some("ILCE-7M2"), true);
  assert_eq!(find(&em, "SonyISO"), Some(&TagValue::Str("25600".into())));
  assert_eq!(find(&em, "BaseISO"), Some(&TagValue::Str("12800".into())));
  assert_eq!(
    find(&em, "StopsAboveBaseISO"),
    Some(&TagValue::Str("14.0".into()))
  );
  assert_eq!(
    find(&em, "SonyExposureTime2"),
    Some(&TagValue::Str("1/128".into()))
  );
  assert_eq!(
    find(&em, "ExposureTime"),
    Some(&TagValue::Str("1/128".into()))
  );
  assert_eq!(find(&em, "SonyFNumber"), Some(&TagValue::Str("4.0".into())));
  assert_eq!(
    find(&em, "SonyMaxApertureValue"),
    Some(&TagValue::Str("2.0".into()))
  );
  assert_eq!(find(&em, "SequenceImageNumber"), Some(&TagValue::I64(5)));
  assert_eq!(
    find(&em, "ReleaseMode2"),
    Some(&TagValue::Str("Normal".into()))
  );
  assert_eq!(find(&em, "SonyImageWidthMax"), Some(&TagValue::I64(6000)));
  assert_eq!(find(&em, "SonyImageHeightMax"), Some(&TagValue::I64(4000)));
  assert_eq!(
    find(&em, "HighISONoiseReduction"),
    Some(&TagValue::Str("Normal".into()))
  );
  assert_eq!(
    find(&em, "LongExposureNoiseReduction"),
    Some(&TagValue::Str("On".into()))
  );
  assert_eq!(
    find(&em, "PictureEffect2"),
    Some(&TagValue::Str("Off".into()))
  );
  assert_eq!(
    find(&em, "ExposureProgram"),
    Some(&TagValue::Str("Manual".into()))
  );
  assert_eq!(
    find(&em, "CreativeStyle"),
    Some(&TagValue::Str("B&W".into()))
  );
  assert_eq!(find(&em, "Sharpness"), Some(&TagValue::Str("+3".into())));
  assert_eq!(
    find(&em, "DistortionCorrParamsPresent"),
    Some(&TagValue::Str("Yes".into()))
  );
  assert_eq!(
    find(&em, "LensFormat"),
    Some(&TagValue::Str("APS-C".into()))
  );
  assert_eq!(
    find(&em, "LensMount"),
    Some(&TagValue::Str("E-mount".into()))
  );
  assert_eq!(
    find(&em, "LensType2"),
    Some(&TagValue::Str("Sony LA-EA2 Adapter".into()))
  );
  let dcp = as_str(find(&em, "DistortionCorrParams").unwrap());
  assert_eq!(dcp.split(' ').count(), 16);
  assert!(dcp.starts_with("6 "));
}

#[test]
fn tag9405b_scalars_raw() {
  let em = parse_tag9405b(&b_scalar_block(), Some("ILCE-7M2"), false);
  assert_eq!(find(&em, "SonyISO"), Some(&TagValue::I64(25600)));
  assert_eq!(find(&em, "BaseISO"), Some(&TagValue::I64(12800)));
  assert_eq!(find(&em, "StopsAboveBaseISO"), Some(&TagValue::I64(14)));
  assert_eq!(find(&em, "SonyFNumber"), Some(&TagValue::I64(4)));
  assert_eq!(find(&em, "SonyMaxApertureValue"), Some(&TagValue::I64(2)));
  assert_eq!(find(&em, "SequenceImageNumber"), Some(&TagValue::I64(5)));
  assert_eq!(find(&em, "ReleaseMode2"), Some(&TagValue::I64(0)));
  assert_eq!(find(&em, "ExposureProgram"), Some(&TagValue::I64(3)));
  assert_eq!(find(&em, "CreativeStyle"), Some(&TagValue::I64(5)));
  assert_eq!(find(&em, "Sharpness"), Some(&TagValue::I64(3)));
  assert_eq!(find(&em, "LensMount"), Some(&TagValue::I64(2)));
  assert_eq!(find(&em, "LensType2"), Some(&TagValue::I64(2)));
}

/// `StopsAboveBaseISO` ValueConv of exactly 0 prints the bare integer `0`
/// (`$val ? "%.1f" : $val`); a negative `int8s` `Sharpness` prints unprefixed.
#[test]
fn tag9405b_zero_stops_and_negative_sharpness() {
  let mut p = vec![0u8; 0x84];
  put_u16(&mut p, 0x000a, 4096); // StopsAboveBaseISO = 16 - 16 = 0
  p[0x0052] = 0xfe; // Sharpness int8s = -2
  let em = parse_tag9405b(&p, Some("ILCE-7M2"), true);
  assert_eq!(find(&em, "StopsAboveBaseISO"), Some(&TagValue::I64(0)));
  assert_eq!(find(&em, "Sharpness"), Some(&TagValue::I64(-2)));
}

/// `ExposureTime` `rational32u`: a 0 denominator yields the literal `'inf'`
/// (num != 0) or `'undef'` (num == 0) — never dropped (`GetRational32u`); both
/// non-numeric strings pass through `PrintExposureTime` and the raw `-n` path.
#[test]
fn tag9405b_exposure_time_rational_edges() {
  let mut inf = vec![0u8; 0x14];
  put_u16(&mut inf, 0x0010, 5); // num
  put_u16(&mut inf, 0x0012, 0); // den = 0
  let em = parse_tag9405b(&inf, Some("ILCE-7M2"), true);
  assert_eq!(
    find(&em, "ExposureTime"),
    Some(&TagValue::Str("inf".into()))
  );

  // 0/0 ⇒ literal 'undef', NOT dropped; identical for -j (print_conv) and -n.
  let zero = vec![0u8; 0x14];
  let em2 = parse_tag9405b(&zero, Some("ILCE-7M2"), true);
  assert_eq!(
    find(&em2, "ExposureTime"),
    Some(&TagValue::Str("undef".into()))
  );
  let em2n = parse_tag9405b(&zero, Some("ILCE-7M2"), false);
  assert_eq!(
    find(&em2n, "ExposureTime"),
    Some(&TagValue::Str("undef".into()))
  );
}

/// `ILCE-7RM2` selects `LensZoomPosition` @0x035a, `VignettingCorrParams` @0x0368,
/// `ChromaticAberrationCorrParams` @0x039c (the other model-conditional offsets
/// stay silent).
#[test]
fn tag9405b_model_arrays_ilce7rm2() {
  let mut p = vec![0u8; 0x3e0];
  put_u16(&mut p, 0x035a, 1024); // LensZoomPosition → 100%
  put_i16(&mut p, 0x0368, 7); // VignettingCorrParams[0]
  put_i16(&mut p, 0x039c, -3); // ChromaticAberrationCorrParams[0]
  let em = parse_tag9405b(&p, Some("ILCE-7RM2"), true);
  assert_eq!(
    find(&em, "LensZoomPosition"),
    Some(&TagValue::Str("100%".into()))
  );
  let vcp = as_str(find(&em, "VignettingCorrParams").unwrap());
  assert_eq!(vcp.split(' ').count(), 16);
  assert!(vcp.starts_with("7 "));
  let cacp = as_str(find(&em, "ChromaticAberrationCorrParams").unwrap());
  assert_eq!(cacp.split(' ').count(), 32);
  assert!(cacp.starts_with("-3 "));
}

/// The `\b` word boundary distinguishes a bare `ILCE-7` (VignettingCorrParams
/// @0x034a, the `…\b`-anchored A-mount/early-E set) from `ILCE-7M2`
/// (VignettingCorrParams @0x0350, the plain-prefix `ILCE-7M2` row).
#[test]
fn tag9405b_word_boundary_ilce7_vs_7m2() {
  let mut p = vec![0u8; 0x370];
  put_i16(&mut p, 0x034a, 11); // 0x034a array[0]
  put_i16(&mut p, 0x0350, 22); // 0x0350 array[0]

  let bare = parse_tag9405b(&p, Some("ILCE-7"), true);
  assert!(as_str(find(&bare, "VignettingCorrParams").unwrap()).starts_with("11 "));

  let m2 = parse_tag9405b(&p, Some("ILCE-7M2"), true);
  assert!(as_str(find(&m2, "VignettingCorrParams").unwrap()).starts_with("22 "));
}

/// A DSC body: the `/^DSC-/` conditional leaves (`SonyFNumber`,
/// `DistortionCorrParamsPresent`, `LensMount`, …) are suppressed, the
/// non-conditional ones still emit, and the latched `LensMount` DataMember still
/// drives `LensType2`.
#[test]
fn tag9405b_dsc_exclusions() {
  let mut p = vec![0u8; 0x84];
  put_u16(&mut p, 0x0004, 2048); // SonyISO (non-conditional)
  put_u16(&mut p, 0x0014, 5120); // SonyFNumber (DSC/ZV excluded)
  p[0x005a] = 1; // DistortionCorrParamsPresent (DSC excluded)
  p[0x005b] = 1; // DistortionCorrection (non-conditional)
  p[0x005e] = 2; // LensMount byte (DataMember latched, tag suppressed)
  put_u16(&mut p, 0x0060, 2); // LensType2

  let em = parse_tag9405b(&p, Some("DSC-RX100M4"), true);
  assert!(find(&em, "SonyFNumber").is_none());
  assert!(find(&em, "DistortionCorrParamsPresent").is_none());
  assert!(find(&em, "LensMount").is_none());
  assert_eq!(find(&em, "SonyISO"), Some(&TagValue::Str("25600".into())));
  assert_eq!(
    find(&em, "DistortionCorrection"),
    Some(&TagValue::Str("Applied".into()))
  );
  assert_eq!(
    find(&em, "LensType2"),
    Some(&TagValue::Str("Sony LA-EA2 Adapter".into()))
  );
}

/// Per-field availability: a buffer ending before an offset emits the earlier
/// leaves only; an empty buffer emits nothing.
#[test]
fn per_field_truncation() {
  let mut p = vec![0u8; 0x10];
  put_u16(&mut p, 0x0004, 2048);
  put_u16(&mut p, 0x000e, 5888);
  let em = parse_tag9405b(&p, Some("ILCE-7M2"), true);
  assert!(find(&em, "SonyISO").is_some());
  assert!(find(&em, "SonyExposureTime2").is_some());
  assert!(find(&em, "ExposureTime").is_none()); // 0x0010 out of range
  assert!(find(&em, "SonyFNumber").is_none());

  assert!(parse_tag9405b(&[], None, true).is_empty());
  assert!(parse_tag9405a(&[], None, true).is_empty());
}
