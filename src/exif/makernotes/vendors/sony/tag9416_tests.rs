// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

use super::*;

/// Forward Sony cipher `c = (b·b·b) mod 249` (`Sony.pm:11521`).
fn encipher_byte(b: u8) -> u8 {
  if b <= 248 {
    (((u32::from(b) * u32::from(b)) % 249 * u32::from(b)) % 249) as u8
  } else {
    b
  }
}

fn encipher(plain: &[u8]) -> Vec<u8> {
  plain.iter().map(|&b| encipher_byte(b)).collect()
}

/// The dispatcher's central decipher (`process_enciphered`) — single pass, or two
/// passes when `double_cipher` is set — reproducing the production path that hands
/// `parse_tag9416` ALREADY-DECIPHERED bytes.
fn process_enciphered(enc: &[u8], double_cipher: bool) -> Vec<u8> {
  super::super::decipher::process_enciphered(enc, double_cipher)
}

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
  buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_i16(buf: &mut [u8], off: usize, v: i16) {
  buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

/// A plaintext `Tag9416` block carrying the real ILME-FX3 + Tamron 28-75mm field
/// values (from the bundled `exiftool -v4` deciphered dump + the `-G1 -j`
/// golden), enciphered for input to `parse_tag9416`. The FX3-class array
/// offsets (0x088f/0x08b5/0x0914) push the buffer past 0x0934.
fn fx3_enciphered_block() -> Vec<u8> {
  let mut p = vec![0u8; 0x0a00];
  put_u16(&mut p, 0x04, 2218); // SonyISO ValueConv → 16156.126
  put_u16(&mut p, 0x06, 2133); // StopsAboveBaseISO → 7.668
  put_u16(&mut p, 0x0a, 5888); // SonyExposureTime2 → 0.0078125 → "1/128"
  // ExposureTime: rational32u = num int16u @0x0c + den int16u @0x0e (4 bytes).
  put_u16(&mut p, 0x0c, 1); // num = 1
  put_u16(&mut p, 0x0e, 125); // den = 125 → 1/125 = 0.008
  put_u16(&mut p, 0x10, 4882); // SonyFNumber2 → 2.898 → "2.9"
  put_u16(&mut p, 0x12, 4882); // SonyMaxApertureValue → 2.9
  p[0x1d..0x21].copy_from_slice(&0u32.to_le_bytes()); // SequenceImageNumber → 1
  p[0x2b] = 0; // ReleaseMode2 → Normal
  p[0x35] = 3; // ExposureProgram → Manual
  p[0x37] = 255; // CreativeStyle → Off
  p[0x48] = 2; // LensMount → E-mount
  p[0x49] = 2; // LensFormat → Full-frame
  p[0x4a] = 2; // LensMount (DataMember) → E-mount
  put_u16(&mut p, 0x4b, 49470); // LensType2 → Tamron 28-75mm
  for (i, v) in DISTORTION.iter().enumerate() {
    put_i16(&mut p, 0x4f + i * 2, *v);
  }
  p[0x70] = 36; // PictureProfile → Off
  put_u16(&mut p, 0x71, 280); // FocalLength → 28.0 mm
  put_u16(&mut p, 0x73, 280); // MinFocalLength → 28.0 mm
  put_u16(&mut p, 0x75, 750); // MaxFocalLength → 75.0 mm
  for (i, v) in VIGNETTING.iter().enumerate() {
    put_i16(&mut p, 0x088f + i * 2, *v);
  }
  p[0x08b5] = 0; // APS-CSizeCapture → Off
  for (i, v) in CHROMATIC.iter().enumerate() {
    put_i16(&mut p, 0x0914 + i * 2, *v);
  }
  encipher(&p)
}

const DISTORTION: [i16; 16] = [
  6, -1, -17, -38, -67, -102, -144, -190, -241, -293, -349, -403, -458, -508, -554, -589,
];
const VIGNETTING: [i16; 16] = [
  0, 0, 96, 256, 480, 704, 1088, 1792, 2688, 3744, 4960, 6432, 8064, 9728, 11392, 13056,
];
const CHROMATIC: [i16; 32] = [
  -48, -52, -68, -90, -126, -168, -222, -292, -358, -380, -382, -356, -330, -306, -308, -322, 964,
  1300, 1564, 1752, 1868, 1916, 1876, 1704, 1508, 1400, 1340, 1324, 1336, 1364, 1396, 1424,
];

fn find<'a>(em: &'a [Tag9416Emission], name: &str) -> Option<&'a TagValue> {
  // Last-wins (LensMount appears at 0x48 and 0x4a).
  em.iter().rev().find(|e| e.name == name).map(|e| &e.value)
}

#[test]
fn fx3_print_conv_matches_golden() {
  let blk = fx3_enciphered_block();
  let em = parse_tag9416(&process_enciphered(&blk, false), Some("ILME-FX3"), true);
  assert_eq!(find(&em, "SonyISO"), Some(&TagValue::Str("16156".into())));
  assert_eq!(
    find(&em, "StopsAboveBaseISO"),
    Some(&TagValue::Str("7.7".into()))
  );
  assert_eq!(
    find(&em, "SonyExposureTime2"),
    Some(&TagValue::Str("1/128".into()))
  );
  assert_eq!(
    find(&em, "ExposureTime"),
    Some(&TagValue::Str("1/125".into()))
  );
  assert_eq!(
    find(&em, "SonyFNumber2"),
    Some(&TagValue::Str("2.9".into()))
  );
  assert_eq!(
    find(&em, "SonyMaxApertureValue"),
    Some(&TagValue::Str("2.9".into()))
  );
  assert_eq!(find(&em, "SequenceImageNumber"), Some(&TagValue::I64(1)));
  assert_eq!(
    find(&em, "ReleaseMode2"),
    Some(&TagValue::Str("Normal".into()))
  );
  assert_eq!(
    find(&em, "ExposureProgram"),
    Some(&TagValue::Str("Manual".into()))
  );
  assert_eq!(
    find(&em, "CreativeStyle"),
    Some(&TagValue::Str("Off".into()))
  );
  assert_eq!(
    find(&em, "LensMount"),
    Some(&TagValue::Str("E-mount".into()))
  );
  assert_eq!(
    find(&em, "LensFormat"),
    Some(&TagValue::Str("Full-frame".into()))
  );
  assert_eq!(
    find(&em, "LensType2"),
    Some(&TagValue::Str("Tamron 28-75mm F2.8 Di III VXD G2".into()))
  );
  assert_eq!(
    find(&em, "DistortionCorrParams"),
    Some(&TagValue::Str(
      "6 -1 -17 -38 -67 -102 -144 -190 -241 -293 -349 -403 -458 -508 -554 -589".into()
    ))
  );
  assert_eq!(
    find(&em, "PictureProfile"),
    Some(&TagValue::Str("Off".into()))
  );
  assert_eq!(
    find(&em, "FocalLength"),
    Some(&TagValue::Str("28.0 mm".into()))
  );
  assert_eq!(
    find(&em, "MaxFocalLength"),
    Some(&TagValue::Str("75.0 mm".into()))
  );
  assert_eq!(
    find(&em, "VignettingCorrParams"),
    Some(&TagValue::Str(
      "0 0 96 256 480 704 1088 1792 2688 3744 4960 6432 8064 9728 11392 13056".into()
    ))
  );
  assert_eq!(
    find(&em, "APS-CSizeCapture"),
    Some(&TagValue::Str("Off".into()))
  );
  assert_eq!(
    find(&em, "ChromaticAberrationCorrParams"),
    Some(&TagValue::Str(
      "-48 -52 -68 -90 -126 -168 -222 -292 -358 -380 -382 -356 -330 -306 -308 -322 964 1300 1564 1752 1868 1916 1876 1704 1508 1400 1340 1324 1336 1364 1396 1424".into()
    ))
  );
}

#[test]
fn fx3_raw_values_match_golden() {
  let blk = fx3_enciphered_block();
  let em = parse_tag9416(&process_enciphered(&blk, false), Some("ILME-FX3"), false);
  // SonyISO -n is the full-precision ValueConv float; assert it renders to the
  // golden `%.15g` token `16156.1260850464` (the `-n` JSON value).
  let iso = find(&em, "SonyISO").expect("SonyISO present");
  let TagValue::F64(iso) = iso else {
    panic!("SonyISO not F64")
  };
  assert_eq!(crate::value::format_g(*iso, 15), "16156.1260850464");
  assert_eq!(
    find(&em, "StopsAboveBaseISO"),
    Some(&TagValue::F64(7.66796875))
  );
  assert_eq!(
    find(&em, "SonyExposureTime2"),
    Some(&TagValue::F64(0.0078125))
  );
  // ExposureTime -n is the rational RoundFloat(1/125, 7) = 0.008.
  assert_eq!(find(&em, "ExposureTime"), Some(&TagValue::F64(0.008)));
  assert_eq!(find(&em, "ExposureProgram"), Some(&TagValue::I64(3)));
  assert_eq!(find(&em, "CreativeStyle"), Some(&TagValue::I64(255)));
  assert_eq!(find(&em, "LensMount"), Some(&TagValue::I64(2)));
  assert_eq!(find(&em, "LensType2"), Some(&TagValue::I64(49470)));
  assert_eq!(find(&em, "PictureProfile"), Some(&TagValue::I64(36)));
  // FocalLength ValueConv $val/10 = 28.0 (serializes BARE-equal to golden 28).
  assert_eq!(find(&em, "FocalLength"), Some(&TagValue::F64(28.0)));
  assert_eq!(find(&em, "MaxFocalLength"), Some(&TagValue::F64(75.0)));
  assert_eq!(find(&em, "APS-CSizeCapture"), Some(&TagValue::I64(0)));
}

/// LensType2 (0x4b) is gated on the 0x4a `LensMount` DataMember being 2.
#[test]
fn lens_type2_gated_on_lensmount() {
  let mut p = vec![0u8; 0x0a00];
  p[0x4a] = 1; // A-mount, not 2
  put_u16(&mut p, 0x4b, 49470);
  let em = parse_tag9416(
    &process_enciphered(&encipher(&p), false),
    Some("ILME-FX3"),
    true,
  );
  assert!(find(&em, "LensType2").is_none());
}

/// MaxFocalLength (0x75) has `RawConv => '$val || undef'` — a 0 drops it.
#[test]
fn max_focal_length_zero_dropped() {
  let mut p = vec![0u8; 0x0a00];
  put_u16(&mut p, 0x75, 0);
  let em = parse_tag9416(
    &process_enciphered(&encipher(&p), false),
    Some("ILME-FX3"),
    true,
  );
  assert!(find(&em, "MaxFocalLength").is_none());
}

/// The FX3-class array offsets (0x088f/0x08b5/0x0914) fire only for the
/// ILCE-(1|7SM3)/ILME-FX3A? bodies; another body skips them.
#[test]
fn fx3_class_array_offsets_gated() {
  let blk = fx3_enciphered_block();
  // A non-FX3-class body (e.g. ILCE-7M4) reads the array tags at DIFFERENT
  // offsets, so the FX3 offsets must NOT fire.
  let em = parse_tag9416(&process_enciphered(&blk, false), Some("ILCE-7M4"), true);
  assert!(find(&em, "VignettingCorrParams").is_none());
  assert!(find(&em, "ChromaticAberrationCorrParams").is_none());
  // But the non-conditional leaves still emit.
  assert!(find(&em, "SonyISO").is_some());
  assert!(find(&em, "FocalLength").is_some());
}

/// Per-field availability: a truncated block emits only the in-range leaves.
#[test]
fn truncated_block_per_field() {
  let full = fx3_enciphered_block();
  // Keep through 0x80 — the early leaves fit, the 0x088f+ array tags do not.
  let em = parse_tag9416(
    &process_enciphered(&full[..0x80], false),
    Some("ILME-FX3"),
    true,
  );
  assert!(find(&em, "SonyISO").is_some());
  assert!(find(&em, "FocalLength").is_some());
  assert!(find(&em, "VignettingCorrParams").is_none());
  assert!(parse_tag9416(&[], Some("ILME-FX3"), true).is_empty());
}

/// Double-encipher regression (`Sony.pm:11553-11556`): when `$$self{DoubleCipher}`
/// is latched, the dispatcher's `process_enciphered` deciphers the 0x9416 block
/// TWICE before parse_tag9416 reads SonyISO/LensType2. A double-enciphered FX3
/// block recovers the real CameraSettings/lens fields with the second pass; a
/// single pass yields garbage, NOT the true values.
#[test]
fn double_cipher_recovers_tag9416_fields() {
  let plain = {
    let mut blk = process_enciphered(&fx3_enciphered_block(), false);
    blk.truncate(0x0a00);
    blk
  };
  let double = encipher(&encipher(&plain));

  let ok = parse_tag9416(&process_enciphered(&double, true), Some("ILME-FX3"), true);
  assert_eq!(find(&ok, "SonyISO"), Some(&TagValue::Str("16156".into())));
  assert_eq!(
    find(&ok, "LensType2"),
    Some(&TagValue::Str("Tamron 28-75mm F2.8 Di III VXD G2".into()))
  );

  let bad = parse_tag9416(&process_enciphered(&double, false), Some("ILME-FX3"), true);
  assert_ne!(
    find(&bad, "SonyISO"),
    Some(&TagValue::Str("16156".into())),
    "single decipher of a double-enciphered 0x9416 block must NOT yield the true value"
  );
}
