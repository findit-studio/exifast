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

/// The dispatcher's central decipher (`process_enciphered`) — single pass —
/// reproducing the production path that hands `parse_tag9403` ALREADY-DECIPHERED
/// bytes.
fn process_enciphered(enc: &[u8], double_cipher: bool) -> Vec<u8> {
  super::super::decipher::process_enciphered(enc, double_cipher)
}

fn find<'a>(em: &'a [Tag9403Emission], name: &str) -> Option<&'a TagValue> {
  em.iter().rev().find(|e| e.name == name).map(|e| &e.value)
}

/// The real ILME-FX3 writes a 4-byte `0x9403` block (offsets `0..3`): neither
/// `0x04` (`TempTest2`) nor `0x05` (`CameraTemperature`) is in range, so the
/// table emits nothing — matching ExifTool's empty `Tag9403` directory.
#[test]
fn fx3_four_byte_block_emits_nothing() {
  let plain = vec![0u8; 4];
  let em = parse_tag9403(&process_enciphered(&encipher(&plain), false), true);
  assert!(em.is_empty());
}

#[test]
fn camera_temperature_emitted_in_range() {
  let mut plain = vec![0u8; 8];
  plain[0x04] = 20; // TempTest2 non-zero AND < 100 ⇒ Condition holds
  plain[0x05] = 25; // CameraTemperature int8s
  let em = parse_tag9403(&process_enciphered(&encipher(&plain), false), true);
  assert_eq!(
    find(&em, "CameraTemperature"),
    Some(&TagValue::Str("25 C".into()))
  );
  // -n keeps the raw signed integer.
  let em_n = parse_tag9403(&process_enciphered(&encipher(&plain), false), false);
  assert_eq!(find(&em_n, "CameraTemperature"), Some(&TagValue::I64(25)));
}

/// `CameraTemperature` is `int8s` (`Sony.pm:8812`): a high byte reads negative.
#[test]
fn camera_temperature_int8s_negative() {
  let mut plain = vec![0u8; 8];
  plain[0x04] = 20;
  plain[0x05] = 0xff; // -1 as int8s
  let em = parse_tag9403(&process_enciphered(&encipher(&plain), false), true);
  assert_eq!(
    find(&em, "CameraTemperature"),
    Some(&TagValue::Str("-1 C".into()))
  );
}

/// `Condition => '$$self{TempTest2} and …'`: a zero `TempTest2` is falsey ⇒
/// `CameraTemperature` is suppressed.
#[test]
fn temp_test2_zero_suppresses() {
  let mut plain = vec![0u8; 8];
  plain[0x04] = 0;
  plain[0x05] = 25;
  let em = parse_tag9403(&process_enciphered(&encipher(&plain), false), true);
  assert!(find(&em, "CameraTemperature").is_none());
}

/// `Condition => '… and $$self{TempTest2} < 100'`: a `TempTest2 >= 100` ⇒
/// `CameraTemperature` is suppressed.
#[test]
fn temp_test2_ge_100_suppresses() {
  let mut plain = vec![0u8; 8];
  plain[0x04] = 130;
  plain[0x05] = 25;
  let em = parse_tag9403(&process_enciphered(&encipher(&plain), false), true);
  assert!(find(&em, "CameraTemperature").is_none());
}

/// `TempTest2` is `Hidden => 1` with an `Unknown < 2` RawConv ⇒ never emitted.
#[test]
fn temp_test2_is_never_emitted() {
  let mut plain = vec![0u8; 8];
  plain[0x04] = 20;
  plain[0x05] = 25;
  let em = parse_tag9403(&process_enciphered(&encipher(&plain), false), true);
  assert!(find(&em, "TempTest2").is_none());
}

/// Per-field availability: a 5-byte block has `0x04` (gates) but not `0x05`.
#[test]
fn per_field_truncation() {
  let mut plain = vec![0u8; 5];
  plain[0x04] = 20;
  let em = parse_tag9403(&process_enciphered(&encipher(&plain), false), true);
  assert!(em.is_empty());
  assert!(parse_tag9403(&[], true).is_empty());
}
