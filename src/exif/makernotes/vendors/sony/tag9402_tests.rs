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
/// `parse_tag9402` ALREADY-DECIPHERED bytes.
fn process_enciphered(enc: &[u8], double_cipher: bool) -> Vec<u8> {
  super::super::decipher::process_enciphered(enc, double_cipher)
}

/// A 400-byte plaintext `Tag9402` block carrying the real ILME-FX3 field values
/// (from the bundled `exiftool -v4` deciphered dump), enciphered for input to
/// `parse_tag9402`. Deciphered: 0x00=0x22, 0x02=0xff (TempTest1), 0x04=0x00
/// (AmbientTemperature), 0x16=0x84 (FocusMode masked → 4), 0x17=0x03
/// (AFAreaMode), 0x2d=0x94 (FocusPosition2 = 148).
fn fx3_enciphered_block() -> Vec<u8> {
  let mut plain = vec![0u8; 400];
  plain[0x00] = 0x22;
  plain[0x02] = 0xff;
  plain[0x04] = 0x00;
  plain[0x16] = 0x84;
  plain[0x17] = 0x03;
  plain[0x2d] = 0x94;
  encipher(&plain)
}

fn find<'a>(em: &'a [Tag9402Emission], name: &str) -> Option<&'a TagValue> {
  em.iter().rev().find(|e| e.name == name).map(|e| &e.value)
}

#[test]
fn fx3_variant_gate() {
  let blk = fx3_enciphered_block();
  // Non-SLT/HV/ILCA body + enciphered first byte ∉ {0x05,0xff} ⇒ selected.
  assert!(selects_tag9402(&blk, Some("ILME-FX3")));
  // SLT/HV/ILCA bodies are excluded regardless of bytes.
  assert!(!selects_tag9402(&blk, Some("SLT-A99V")));
  assert!(!selects_tag9402(&blk, Some("ILCA-77M2")));
  // Enciphered first byte 0x05 or 0xff ⇒ not selected.
  assert!(!selects_tag9402(&[0x05, 0x00], Some("ILME-FX3")));
  assert!(!selects_tag9402(&[0xff, 0x00], Some("ILME-FX3")));
  assert!(!selects_tag9402(&[], None));
}

#[test]
fn fx3_print_conv_matches_golden() {
  let blk = fx3_enciphered_block();
  let em = parse_tag9402(&process_enciphered(&blk, false), true);
  assert_eq!(
    find(&em, "AmbientTemperature"),
    Some(&TagValue::Str("0 C".into()))
  );
  assert_eq!(find(&em, "FocusMode"), Some(&TagValue::Str("AF-A".into())));
  assert_eq!(
    find(&em, "AFAreaMode"),
    Some(&TagValue::Str("Flexible Spot".into()))
  );
  assert_eq!(find(&em, "FocusPosition2"), Some(&TagValue::I64(148)));
}

#[test]
fn fx3_raw_values_match_golden() {
  let blk = fx3_enciphered_block();
  let em = parse_tag9402(&process_enciphered(&blk, false), false);
  assert_eq!(find(&em, "AmbientTemperature"), Some(&TagValue::I64(0)));
  assert_eq!(find(&em, "FocusMode"), Some(&TagValue::I64(4)));
  assert_eq!(find(&em, "AFAreaMode"), Some(&TagValue::I64(3)));
  assert_eq!(find(&em, "FocusPosition2"), Some(&TagValue::I64(148)));
}

/// AmbientTemperature is dropped unless TempTest1 (0x02) deciphers to 255.
#[test]
fn ambient_temperature_gated_on_temptest1() {
  let mut plain = vec![0u8; 400];
  plain[0x02] = 0x10; // not 255
  plain[0x04] = 0x05;
  let em = parse_tag9402(&process_enciphered(&encipher(&plain), false), true);
  assert!(find(&em, "AmbientTemperature").is_none());
}

/// AmbientTemperature is int8s — a high byte renders as a negative temperature.
#[test]
fn ambient_temperature_signed() {
  let mut plain = vec![0u8; 400];
  plain[0x02] = 0xff;
  plain[0x04] = 0xee; // -18 as int8s
  let em = parse_tag9402(&process_enciphered(&encipher(&plain), false), true);
  assert_eq!(
    find(&em, "AmbientTemperature"),
    Some(&TagValue::Str("-18 C".into()))
  );
}

/// Per-field availability: a truncated block emits only the in-range leaves.
#[test]
fn truncated_block_per_field() {
  let full = fx3_enciphered_block();
  // Keep through 0x18 — AmbientTemperature/FocusMode/AFAreaMode fit, the 0x2d
  // FocusPosition2 does not.
  let em = parse_tag9402(&process_enciphered(&full[..0x18], false), true);
  assert!(find(&em, "AFAreaMode").is_some());
  assert!(find(&em, "FocusPosition2").is_none());
  assert!(parse_tag9402(&[], true).is_empty());
}

/// `$$self{DoubleCipher}`: a DOUBLE-enciphered block (the ExifTool 9.04-9.10
/// write-bug form) needs a SECOND `Decipher` pass (`Sony.pm:11553-11556`), now
/// applied CENTRALLY by `process_enciphered`. With `double_cipher=true` the
/// recovered block yields the correct FX3 fields; with `false` (a single pass)
/// the once-deciphered block is GARBAGE, NOT the right fields.
#[test]
fn double_cipher_second_pass() {
  let mut plain = vec![0u8; 400];
  plain[0x00] = 0x22;
  plain[0x02] = 0xff;
  plain[0x04] = 0x00;
  plain[0x16] = 0x84; // FocusMode masked → 4 (AF-A)
  plain[0x17] = 0x03; // AFAreaMode → Flexible Spot
  plain[0x2d] = 0x94; // FocusPosition2 = 148
  // On-disk DOUBLE-enciphered bytes = encipher(encipher(plain)).
  let double = encipher(&encipher(&plain));

  // double_cipher=true ⇒ process_enciphered runs two Decipher passes, recovering
  // `plain` exactly before parse_tag9402 reads it.
  let ok = parse_tag9402(&process_enciphered(&double, true), true);
  assert_eq!(find(&ok, "FocusMode"), Some(&TagValue::Str("AF-A".into())));
  assert_eq!(
    find(&ok, "AFAreaMode"),
    Some(&TagValue::Str("Flexible Spot".into()))
  );
  assert_eq!(find(&ok, "FocusPosition2"), Some(&TagValue::I64(148)));

  // double_cipher=false ⇒ only one pass ⇒ the leaves do NOT match the truth
  // (the bug this fix closes: once-deciphered garbage, not the real fields).
  let bad = parse_tag9402(&process_enciphered(&double, false), true);
  assert_ne!(
    find(&bad, "FocusPosition2"),
    Some(&TagValue::I64(148)),
    "single decipher of a double-enciphered block must NOT yield the true value"
  );
}
