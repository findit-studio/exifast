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

fn process_enciphered(enc: &[u8], double_cipher: bool) -> Vec<u8> {
  super::super::decipher::process_enciphered(enc, double_cipher)
}

fn find<'a>(em: &'a [Tag9404Emission], name: &str) -> Option<&'a TagValue> {
  em.iter().rev().find(|e| e.name == name).map(|e| &e.value)
}

/// The variant gates test the RAW (enciphered) first + fourth bytes
/// (`Sony.pm:1993`/`1998`/`2003`).
#[test]
fn variant_gates() {
  // Tag9404a: first byte 0x40/0x7d, fourth byte 0x01.
  assert!(selects_tag9404a(&[0x40, 0, 0, 0x01]));
  assert!(selects_tag9404a(&[0x7d, 0xaa, 0xbb, 0x01]));
  assert!(!selects_tag9404a(&[0x40, 0, 0, 0x02])); // wrong fourth byte
  assert!(!selects_tag9404a(&[0x41, 0, 0, 0x01])); // wrong first byte
  // Tag9404b: first byte in {0xe7,0xea,0xcd,0x8a,0x70}, fourth byte 0x08.
  assert!(selects_tag9404b(&[0xe7, 0, 0, 0x08]));
  assert!(selects_tag9404b(&[0x70, 0, 0, 0x08]));
  assert!(!selects_tag9404b(&[0xe7, 0, 0, 0x01]));
  // Tag9404c: first byte 0xb6, fourth byte 0x01.
  assert!(selects_tag9404c(&[0xb6, 0, 0, 0x01]));
  assert!(!selects_tag9404c(&[0xb6, 0, 0, 0x08]));
  // Mutual exclusivity (a's 0x40 is not c's 0xb6) + short buffers.
  assert!(!selects_tag9404c(&[0x40, 0, 0, 0x01]));
  assert!(!selects_tag9404a(&[0x40]));
  assert!(!selects_tag9404a(&[]));
}

/// The two `.` wildcards at value bytes 1 and 2 are Perl `.` WITHOUT `/s`
/// (`Sony.pm:1993`/`1998`/`2003` have no `/s`), so a `0x0a` newline there fails
/// the regex and the variant is NOT selected — ExifTool falls through to the
/// unknown `Sony_0x9404` (emits nothing).
#[test]
fn variant_gates_reject_newline_in_wildcard() {
  // Tag9404a — byte 0 ∈ {0x40,0x7d}, byte 3 == 0x01; bytes 1,2 must be non-0x0a.
  assert!(selects_tag9404a(&[0x40, 0x55, 0x55, 0x01]));
  assert!(!selects_tag9404a(&[0x40, 0x0a, 0x55, 0x01])); // \n at byte 1
  assert!(!selects_tag9404a(&[0x40, 0x55, 0x0a, 0x01])); // \n at byte 2
  // Tag9404b — byte 0 ∈ {0xe7,0xea,0xcd,0x8a,0x70}, byte 3 == 0x08.
  assert!(selects_tag9404b(&[0xe7, 0x55, 0x55, 0x08]));
  assert!(!selects_tag9404b(&[0xe7, 0x0a, 0x55, 0x08])); // \n at byte 1
  assert!(!selects_tag9404b(&[0xe7, 0x55, 0x0a, 0x08])); // \n at byte 2
  // Tag9404c — byte 0 == 0xb6, byte 3 == 0x01.
  assert!(selects_tag9404c(&[0xb6, 0x55, 0x55, 0x01]));
  assert!(!selects_tag9404c(&[0xb6, 0x0a, 0x55, 0x01])); // \n at byte 1
  assert!(!selects_tag9404c(&[0xb6, 0x55, 0x0a, 0x01])); // \n at byte 2
}

#[test]
fn tag9404a_print_conv() {
  let mut plain = vec![0u8; 0x20];
  plain[0x0b] = 3; // ExposureProgram = Manual
  plain[0x0d] = 1; // IntelligentAuto = On
  plain[0x19] = 0x00; // LensZoomPosition int16u LE = 1024 ⇒ 100%
  plain[0x1a] = 0x04;
  let em = parse_tag9404a(
    &process_enciphered(&encipher(&plain), false),
    Some("ILCE-7M2"),
    true,
  );
  assert_eq!(
    find(&em, "ExposureProgram"),
    Some(&TagValue::Str("Manual".into()))
  );
  assert_eq!(
    find(&em, "IntelligentAuto"),
    Some(&TagValue::Str("On".into()))
  );
  assert_eq!(
    find(&em, "LensZoomPosition"),
    Some(&TagValue::Str("100%".into()))
  );
}

#[test]
fn tag9404a_raw() {
  let mut plain = vec![0u8; 0x20];
  plain[0x0b] = 3;
  plain[0x0d] = 1;
  plain[0x19] = 0x00;
  plain[0x1a] = 0x04; // 1024
  let em = parse_tag9404a(
    &process_enciphered(&encipher(&plain), false),
    Some("ILCE-7M2"),
    false,
  );
  assert_eq!(find(&em, "ExposureProgram"), Some(&TagValue::I64(3)));
  assert_eq!(find(&em, "IntelligentAuto"), Some(&TagValue::I64(1)));
  assert_eq!(find(&em, "LensZoomPosition"), Some(&TagValue::I64(1024)));
}

/// `Tag9404a` 0x19 `LensZoomPosition` `Condition => '$$self{Model} !~ /^SLT-/'`.
#[test]
fn tag9404a_lens_zoom_excluded_for_slt() {
  let mut plain = vec![0u8; 0x20];
  plain[0x19] = 0x00;
  plain[0x1a] = 0x04;
  let em = parse_tag9404a(
    &process_enciphered(&encipher(&plain), false),
    Some("SLT-A99V"),
    true,
  );
  assert!(find(&em, "LensZoomPosition").is_none());
}

/// `%sonyExposureProgram3` miss ⇒ `"Unknown ($val)"` (decimal; no `PrintHex`).
#[test]
fn tag9404a_exposure_program_unknown() {
  let mut plain = vec![0u8; 0x10];
  plain[0x0b] = 99;
  let em = parse_tag9404a(
    &process_enciphered(&encipher(&plain), false),
    Some("ILCE-7M2"),
    true,
  );
  assert_eq!(
    find(&em, "ExposureProgram"),
    Some(&TagValue::Str("Unknown (99)".into()))
  );
}

/// `Tag9404b` 0x1e `LensZoomPosition` (non-SLT/HV/ILCA) vs 0x20 `FocusPosition2`
/// (SLT/HV/ILCA) are mutually-exclusive by model.
#[test]
fn tag9404b_lens_zoom_vs_focus_position() {
  let mut plain = vec![0u8; 0x24];
  plain[0x0c] = 1; // ExposureProgram = Aperture-priority AE
  plain[0x0e] = 0; // IntelligentAuto = Off
  plain[0x1e] = 0x00; // LensZoomPosition int16u LE = 512 ⇒ 50%
  plain[0x1f] = 0x02;
  plain[0x20] = 182; // FocusPosition2 (only valid for SLT/HV/ILCA)

  let em = parse_tag9404b(
    &process_enciphered(&encipher(&plain), false),
    Some("ILCE-7M2"),
    true,
  );
  assert_eq!(
    find(&em, "ExposureProgram"),
    Some(&TagValue::Str("Aperture-priority AE".into()))
  );
  assert_eq!(
    find(&em, "IntelligentAuto"),
    Some(&TagValue::Str("Off".into()))
  );
  assert_eq!(
    find(&em, "LensZoomPosition"),
    Some(&TagValue::Str("50%".into()))
  );
  assert!(find(&em, "FocusPosition2").is_none());

  let em2 = parse_tag9404b(
    &process_enciphered(&encipher(&plain), false),
    Some("ILCA-77M2"),
    true,
  );
  assert_eq!(find(&em2, "FocusPosition2"), Some(&TagValue::I64(182)));
  assert!(find(&em2, "LensZoomPosition").is_none());
}

#[test]
fn tag9404c_fields() {
  let mut plain = vec![0u8; 0x10];
  plain[0x0b] = 4; // ExposureProgram = Auto
  plain[0x0d] = 1; // IntelligentAuto = On
  let em = parse_tag9404c(&process_enciphered(&encipher(&plain), false), true);
  assert_eq!(
    find(&em, "ExposureProgram"),
    Some(&TagValue::Str("Auto".into()))
  );
  assert_eq!(
    find(&em, "IntelligentAuto"),
    Some(&TagValue::Str("On".into()))
  );
}

/// Per-field availability: a block ending before 0x19 emits the early leaves but
/// not `LensZoomPosition`.
#[test]
fn per_field_truncation() {
  let mut plain = vec![0u8; 0x0e];
  plain[0x0b] = 3;
  plain[0x0d] = 1;
  let em = parse_tag9404a(
    &process_enciphered(&encipher(&plain), false),
    Some("ILCE-7M2"),
    true,
  );
  assert!(find(&em, "ExposureProgram").is_some());
  assert!(find(&em, "IntelligentAuto").is_some());
  assert!(find(&em, "LensZoomPosition").is_none());
  assert!(parse_tag9404a(&[], None, true).is_empty());
}
