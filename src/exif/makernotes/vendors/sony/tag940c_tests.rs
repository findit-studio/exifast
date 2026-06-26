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
/// `parse_tag940c` ALREADY-DECIPHERED bytes.
fn process_enciphered(enc: &[u8], double_cipher: bool) -> Vec<u8> {
  super::super::decipher::process_enciphered(enc, double_cipher)
}

/// A 64-byte plaintext `Tag940c` block carrying the real ILME-FX3 + Tamron
/// 28-75mm field values (from the bundled `exiftool -v4` deciphered dump),
/// enciphered for input to `parse_tag940c`. Deciphered:
/// `686e: 00 14 ff ff ff ff 00 00 04 3e c1 80 01 70 01 0f`
/// `687e: 00 00 00 00 01 02 …` ⇒ 0x08=0x04 (LensMount2=E-mount), 0x09=int16u
/// 0xc13e=49470 (LensType3), 0x0b=int16u 0x0180=384 (CameraE-mountVersion),
/// 0x0d=int16u 0x0170=368 (LensE-mountVersion), 0x14=int16u 0x0201=513
/// (LensFirmwareVersion).
fn fx3_enciphered_block() -> Vec<u8> {
  let mut plain = vec![0u8; 64];
  plain[0x00] = 0x00;
  plain[0x01] = 0x14;
  plain[0x02] = 0xff;
  plain[0x03] = 0xff;
  plain[0x04] = 0xff;
  plain[0x05] = 0xff;
  plain[0x08] = 0x04;
  plain[0x09] = 0x3e;
  plain[0x0a] = 0xc1;
  plain[0x0b] = 0x80;
  plain[0x0c] = 0x01;
  plain[0x0d] = 0x70;
  plain[0x0e] = 0x01;
  plain[0x14] = 0x01;
  plain[0x15] = 0x02;
  encipher(&plain)
}

fn find<'a>(em: &'a [Tag940cEmission], name: &str) -> Option<&'a TagValue> {
  em.iter().rev().find(|e| e.name == name).map(|e| &e.value)
}

#[test]
fn fx3_model_gate() {
  assert!(selects_tag940c(Some("ILME-FX3")));
  assert!(selects_tag940c(Some("ILCE-7M3")));
  assert!(selects_tag940c(Some("NEX-7")));
  assert!(selects_tag940c(Some("ZV-E1")));
  assert!(selects_tag940c(Some("ZV-E10")));
  // A DSC body has no Tag940c.
  assert!(!selects_tag940c(Some("DSC-RX100")));
  assert!(!selects_tag940c(None));
}

#[test]
fn fx3_print_conv_matches_golden() {
  let blk = fx3_enciphered_block();
  let em = parse_tag940c(&process_enciphered(&blk, false), true);
  assert_eq!(
    find(&em, "LensMount2"),
    Some(&TagValue::Str("E-mount".into()))
  );
  assert_eq!(
    find(&em, "LensType3"),
    Some(&TagValue::Str("Tamron 28-75mm F2.8 Di III VXD G2".into()))
  );
  // `sprintf("%x.%.2x", 384>>8, 384&0xff)` = "1.80" (the number-gate later emits
  // it BARE in JSON).
  assert_eq!(
    find(&em, "CameraE-mountVersion"),
    Some(&TagValue::Str("1.80".into()))
  );
  assert_eq!(
    find(&em, "LensE-mountVersion"),
    Some(&TagValue::Str("1.70".into()))
  );
  assert_eq!(
    find(&em, "LensFirmwareVersion"),
    Some(&TagValue::Str("Ver.02.001".into()))
  );
}

#[test]
fn fx3_raw_values_match_golden() {
  let blk = fx3_enciphered_block();
  let em = parse_tag940c(&process_enciphered(&blk, false), false);
  assert_eq!(find(&em, "LensMount2"), Some(&TagValue::I64(4)));
  assert_eq!(find(&em, "LensType3"), Some(&TagValue::I64(49470)));
  assert_eq!(find(&em, "CameraE-mountVersion"), Some(&TagValue::I64(384)));
  assert_eq!(find(&em, "LensE-mountVersion"), Some(&TagValue::I64(368)));
  assert_eq!(find(&em, "LensFirmwareVersion"), Some(&TagValue::I64(513)));
}

/// LensE-mountVersion / LensFirmwareVersion are dropped when LensMount (0x08)
/// deciphers to 0 (`Condition => '$$self{LensMount} != 0'`).
#[test]
fn emount_rows_gated_on_lensmount() {
  let mut plain = vec![0u8; 64];
  plain[0x08] = 0x00; // LensMount = 0
  plain[0x0d] = 0x70;
  plain[0x0e] = 0x01;
  plain[0x14] = 0x01;
  plain[0x15] = 0x02;
  let em = parse_tag940c(&process_enciphered(&encipher(&plain), false), true);
  // CameraE-mountVersion (0x0b) is NOT gated on LensMount, but LensE-mountVersion
  // and LensFirmwareVersion ARE.
  assert!(find(&em, "LensE-mountVersion").is_none());
  assert!(find(&em, "LensFirmwareVersion").is_none());
  // LensType3 RawConv: LensMount==0 ⇒ only kept if 0 < val < 32784.
  assert!(find(&em, "LensType3").is_none()); // val 0 here
}

/// Per-field availability: a truncated block emits only the in-range leaves.
#[test]
fn truncated_block_per_field() {
  let full = fx3_enciphered_block();
  // Keep through 0x0b (exclusive) — LensMount2 (0x08) + LensType3 (0x09..0x0b)
  // fit; CameraE-mountVersion (0x0b..0x0d) does not.
  let em = parse_tag940c(&process_enciphered(&full[..0x0b], false), true);
  assert!(find(&em, "LensMount2").is_some());
  assert!(find(&em, "LensType3").is_some());
  assert!(find(&em, "CameraE-mountVersion").is_none());
  assert!(parse_tag940c(&[], true).is_empty());
}

/// Double-encipher regression (`Sony.pm:11553-11556`): when `$$self{DoubleCipher}`
/// is latched, the dispatcher's `process_enciphered` deciphers the 0x940c block
/// TWICE before parse_tag940c reads LensMount2/LensType3. A double-enciphered FX3
/// block recovers the real lens fields with the second pass; a single pass yields
/// garbage, NOT the true values.
#[test]
fn double_cipher_recovers_tag940c_fields() {
  let plain = {
    let mut blk = process_enciphered(&fx3_enciphered_block(), false);
    blk.truncate(64);
    blk
  };
  let double = encipher(&encipher(&plain));

  let ok = parse_tag940c(&process_enciphered(&double, true), true);
  assert_eq!(
    find(&ok, "LensMount2"),
    Some(&TagValue::Str("E-mount".into()))
  );
  assert_eq!(
    find(&ok, "LensType3"),
    Some(&TagValue::Str("Tamron 28-75mm F2.8 Di III VXD G2".into()))
  );

  let bad = parse_tag940c(&process_enciphered(&double, false), true);
  assert_ne!(
    find(&bad, "LensType3"),
    Some(&TagValue::Str("Tamron 28-75mm F2.8 Di III VXD G2".into())),
    "single decipher of a double-enciphered 0x940c block must NOT yield the true lens"
  );
}
