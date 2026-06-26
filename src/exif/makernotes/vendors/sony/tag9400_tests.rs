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

/// A 456-byte plaintext `Tag9400c` block carrying the real ILME-FX3 field
/// values (from the bundled `exiftool -v4` deciphered dump), enciphered for
/// input to `parse_tag9400c`. The first plaintext byte is `0x6a` (which the
/// activation fixture carries); its enciphered form must be a `Tag9400c`
/// selector for the dispatch.
fn fx3_enciphered_block() -> Vec<u8> {
  let mut plain = vec![0u8; 456];
  // The dumped block begins `6a 01 01 01 …`.
  plain[0] = 0x6a;
  plain[1] = 0x01;
  plain[2] = 0x01;
  plain[3] = 0x01;
  // 0x0009 ReleaseMode2 = 0 (already 0).
  // 0x0012 SequenceImageNumber int32u = 0.
  plain[0x12..0x16].copy_from_slice(&0u32.to_le_bytes());
  // 0x0016 SequenceLength = 1.
  plain[0x16] = 1;
  // 0x001a SequenceFileNumber int32u = 0.
  plain[0x1a..0x1e].copy_from_slice(&0u32.to_le_bytes());
  // 0x001e SequenceLength = 1.
  plain[0x1e] = 1;
  // 0x0029 CameraOrientation = 1.
  plain[0x29] = 1;
  // 0x002a Quality2 = 2.
  plain[0x2a] = 2;
  encipher(&plain)
}

fn find<'a>(em: &'a [Tag9400Emission], name: &str) -> Option<&'a TagValue> {
  // Last-wins (the duplicate SequenceLength rows).
  em.iter().rev().find(|e| e.name == name).map(|e| &e.value)
}

/// The enciphered FX3 first byte selects the `Tag9400c` variant (`Sony.pm:1856`).
#[test]
fn fx3_first_byte_selects_tag9400c() {
  let blk = fx3_enciphered_block();
  assert!(selects_tag9400c(&blk));
  // 0x6a enciphers to 0x31 — one of the documented Tag9400c first bytes.
  assert_eq!(blk.first(), Some(&0x31));
  // An unrelated first byte does not select Tag9400c.
  assert!(!selects_tag9400c(&[0x0c, 0x00]));
  assert!(!selects_tag9400c(&[]));
}

#[test]
fn fx3_tag9400c_print_conv_matches_golden() {
  let blk = fx3_enciphered_block();
  let em = parse_tag9400c(&blk, Some("ILME-FX3"), true);
  assert_eq!(
    find(&em, "ReleaseMode2"),
    Some(&TagValue::Str("Normal".into()))
  );
  assert_eq!(find(&em, "SequenceImageNumber"), Some(&TagValue::I64(1)));
  assert_eq!(find(&em, "SequenceFileNumber"), Some(&TagValue::I64(1)));
  // 0x001e wins last → the "N files" form.
  assert_eq!(
    find(&em, "SequenceLength"),
    Some(&TagValue::Str("1 file".into()))
  );
  assert_eq!(
    find(&em, "CameraOrientation"),
    Some(&TagValue::Str("Horizontal (normal)".into()))
  );
  assert_eq!(find(&em, "Quality2"), Some(&TagValue::Str("RAW".into())));
}

#[test]
fn fx3_tag9400c_raw_values_match_golden() {
  let blk = fx3_enciphered_block();
  let em = parse_tag9400c(&blk, Some("ILME-FX3"), false);
  assert_eq!(find(&em, "ReleaseMode2"), Some(&TagValue::I64(0)));
  assert_eq!(find(&em, "SequenceImageNumber"), Some(&TagValue::I64(1)));
  assert_eq!(find(&em, "SequenceFileNumber"), Some(&TagValue::I64(1)));
  assert_eq!(find(&em, "SequenceLength"), Some(&TagValue::I64(1)));
  assert_eq!(find(&em, "CameraOrientation"), Some(&TagValue::I64(1)));
  assert_eq!(find(&em, "Quality2"), Some(&TagValue::I64(2)));
}

/// The FX3 (`ILME-FX3`) is excluded from the FIRST `Quality2` variant's
/// `Condition` (`Sony.pm:8587`), so it must use the modern (HEIF-aware) hash.
#[test]
fn quality2_variant_selection() {
  assert!(quality2_uses_modern_variant(Some("ILME-FX3")));
  assert!(quality2_uses_modern_variant(Some("ILCE-1")));
  assert!(quality2_uses_modern_variant(Some("ILCE-7SM3")));
  assert!(quality2_uses_modern_variant(Some("ILME-FX30")));
  // An older body uses the FIRST variant (so NOT the modern one).
  assert!(!quality2_uses_modern_variant(Some("ILCE-7M3")));
  assert!(!quality2_uses_modern_variant(Some("ILCE-6000")));
  assert!(!quality2_uses_modern_variant(Some("DSC-RX100M5")));
  assert!(!quality2_uses_modern_variant(None));
}

/// Per-field availability: a truncated block emits only the in-range leaves.
#[test]
fn truncated_block_per_field() {
  let full = fx3_enciphered_block();
  // Keep through 0x001a (ReleaseMode2 + SequenceImageNumber + 0x16 fit; the
  // 0x1e SequenceLength / 0x29 CameraOrientation / 0x2a Quality2 do not).
  let em = parse_tag9400c(&full[..0x1a], Some("ILME-FX3"), true);
  assert!(find(&em, "ReleaseMode2").is_some());
  assert!(find(&em, "SequenceImageNumber").is_some());
  assert!(find(&em, "CameraOrientation").is_none());
  assert!(find(&em, "Quality2").is_none());
  // The only SequenceLength present is the 0x16 "shots" form.
  assert_eq!(
    find(&em, "SequenceLength"),
    Some(&TagValue::Str("1 shot".into()))
  );
  assert!(parse_tag9400c(&[], Some("ILME-FX3"), true).is_empty());
}
