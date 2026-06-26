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
/// `parse_tag9406` ALREADY-DECIPHERED bytes.
fn process_enciphered(enc: &[u8], double_cipher: bool) -> Vec<u8> {
  super::super::decipher::process_enciphered(enc, double_cipher)
}

/// A 64-byte plaintext `Tag9406` block carrying the real ILME-FX3 deciphered
/// field values (`exiftool -v4`): 0x00=0x03 (Ver, → enciphered 0x1b — the gate
/// first byte), 0x02=0x02 (→ enciphered 0x08 — the gate third byte), 0x05=95
/// (BatteryTemperature → 35.0 C), 0x06=0 (grip1, dropped), 0x07=97
/// (BatteryLevel), 0x08=0 (grip2, dropped). Enciphered for input to
/// `parse_tag9406`.
fn fx3_enciphered_block() -> Vec<u8> {
  let mut plain = vec![0u8; 64];
  plain[0x00] = 0x03;
  plain[0x02] = 0x02;
  plain[0x05] = 95;
  plain[0x06] = 0;
  plain[0x07] = 97;
  plain[0x08] = 0;
  encipher(&plain)
}

fn find<'a>(em: &'a [Tag9406Emission], name: &str) -> Option<&'a TagValue> {
  em.iter().rev().find(|e| e.name == name).map(|e| &e.value)
}

#[test]
fn fx3_variant_gate() {
  let blk = fx3_enciphered_block();
  // Enciphered first byte 0x1b + third byte 0x08 ⇒ Tag9406 (not 9406b).
  assert_eq!(blk[0], 0x1b);
  assert_eq!(blk[2], 0x08);
  assert!(selects_tag9406(&blk));
  // 0x40 first byte is the Tag9406b variant ⇒ not selected here.
  assert!(!selects_tag9406(&[0x40, 0x00, 0x08]));
  // First byte ok but third byte not 0x08/0x1b ⇒ not selected.
  assert!(!selects_tag9406(&[0x01, 0x00, 0x00]));
  assert!(!selects_tag9406(&[]));
}

#[test]
fn fx3_print_conv_matches_golden() {
  let blk = fx3_enciphered_block();
  let em = parse_tag9406(&process_enciphered(&blk, false), true);
  // BatteryTemperature: (95-32)/1.8 = 35.0 → "35.0 C".
  assert_eq!(
    find(&em, "BatteryTemperature"),
    Some(&TagValue::Str("35.0 C".into()))
  );
  // BatteryLevel: "$val%" → "97%".
  assert_eq!(
    find(&em, "BatteryLevel"),
    Some(&TagValue::Str("97%".into()))
  );
  // Grip1/Grip2 are 0 ⇒ dropped by their RawConv undef-guards.
  assert!(find(&em, "BatteryLevelGrip1").is_none());
  assert!(find(&em, "BatteryLevelGrip2").is_none());
}

#[test]
fn fx3_raw_values_match_golden() {
  let blk = fx3_enciphered_block();
  let em = parse_tag9406(&process_enciphered(&blk, false), false);
  // BatteryTemperature: the ValueConv result 35.0 → `%.15g` token "35" → the
  // BARE integer `35`, byte-identical to the golden (NOT serde's `35.0`).
  assert_eq!(find(&em, "BatteryTemperature"), Some(&TagValue::I64(35)));
  assert_eq!(find(&em, "BatteryLevel"), Some(&TagValue::I64(97)));
}

/// The grip leaves emit when non-zero (Grip1) / not 0|255 (Grip2).
#[test]
fn grip_leaves_emit_when_present() {
  let mut plain = vec![0u8; 64];
  plain[0x06] = 42; // grip1 non-zero
  plain[0x08] = 88; // grip2 not 0/255
  let em = parse_tag9406(&process_enciphered(&encipher(&plain), false), true);
  assert_eq!(
    find(&em, "BatteryLevelGrip1"),
    Some(&TagValue::Str("42%".into()))
  );
  assert_eq!(
    find(&em, "BatteryLevelGrip2"),
    Some(&TagValue::Str("88%".into()))
  );
  // Grip2 == 255 is dropped.
  let mut plain2 = vec![0u8; 64];
  plain2[0x08] = 255;
  let em2 = parse_tag9406(&process_enciphered(&encipher(&plain2), false), true);
  assert!(find(&em2, "BatteryLevelGrip2").is_none());
}

/// Per-field availability: a truncated block emits only the in-range leaves.
#[test]
fn truncated_block_per_field() {
  let full = fx3_enciphered_block();
  // Keep through 0x06 — BatteryTemperature fits, BatteryLevel (0x07) does not.
  let em = parse_tag9406(&process_enciphered(&full[..0x07], false), true);
  assert!(find(&em, "BatteryTemperature").is_some());
  assert!(find(&em, "BatteryLevel").is_none());
  assert!(parse_tag9406(&[], true).is_empty());
}

/// Double-encipher regression (`Sony.pm:11553-11556`): when `$$self{DoubleCipher}`
/// is latched, the dispatcher's `process_enciphered` deciphers the 0x9406 block
/// TWICE. A double-enciphered FX3 block recovers BatteryTemperature/BatteryLevel
/// with the second pass; a single pass yields garbage, NOT the true values.
#[test]
fn double_cipher_recovers_tag9406_fields() {
  let mut plain = vec![0u8; 64];
  plain[0x05] = 95; // BatteryTemperature → 35.0 C
  plain[0x07] = 97; // BatteryLevel → 97%
  let double = encipher(&encipher(&plain));

  let ok = parse_tag9406(&process_enciphered(&double, true), true);
  assert_eq!(
    find(&ok, "BatteryTemperature"),
    Some(&TagValue::Str("35.0 C".into()))
  );
  assert_eq!(
    find(&ok, "BatteryLevel"),
    Some(&TagValue::Str("97%".into()))
  );

  let bad = parse_tag9406(&process_enciphered(&double, false), true);
  assert_ne!(
    find(&bad, "BatteryLevel"),
    Some(&TagValue::Str("97%".into())),
    "single decipher of a double-enciphered 0x9406 block must NOT yield the true value"
  );
}
