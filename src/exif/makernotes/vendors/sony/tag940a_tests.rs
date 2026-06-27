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

fn find<'a>(em: &'a [Tag940aEmission], name: &str) -> Option<&'a TagValue> {
  em.iter().rev().find(|e| e.name == name).map(|e| &e.value)
}

/// `Tag940a` is the SLT/HV variant only (`Sony.pm:2069`).
#[test]
fn selects_only_slt_hv() {
  assert!(selects_tag940a(Some("SLT-A77V")));
  assert!(selects_tag940a(Some("HV")));
  assert!(!selects_tag940a(Some("ILME-FX3")));
  assert!(!selects_tag940a(Some("ILCE-7M2")));
  assert!(!selects_tag940a(None));
}

/// A literal-hash key wins over the BITMASK (`ExifTool.pm:3616`).
#[test]
fn af_points_literal_keys() {
  let mut plain = vec![0u8; 0x10];
  plain[0x04] = 0x01; // int32u LE = 0x00007801 ⇒ "Center Zone"
  plain[0x05] = 0x78;
  let em = parse_tag940a(&process_enciphered(&encipher(&plain), false), true);
  assert_eq!(
    find(&em, "AFPointsSelected"),
    Some(&TagValue::Str("Center Zone".into()))
  );

  // 0 ⇒ literal "(none)".
  let zero = parse_tag940a(&process_enciphered(&encipher(&[0u8; 0x10]), false), true);
  assert_eq!(
    find(&zero, "AFPointsSelected"),
    Some(&TagValue::Str("(none)".into()))
  );

  // 0xffffffff ⇒ literal "n/a".
  let mut p2 = vec![0u8; 0x10];
  p2[0x04] = 0xff;
  p2[0x05] = 0xff;
  p2[0x06] = 0xff;
  p2[0x07] = 0xff;
  let em2 = parse_tag940a(&process_enciphered(&encipher(&p2), false), true);
  assert_eq!(
    find(&em2, "AFPointsSelected"),
    Some(&TagValue::Str("n/a".into()))
  );
}

/// A non-literal value decodes via DecodeBits (`ExifTool.pm:3617-3618`): bits 0
/// (Center) and 7 (Left) set ⇒ value 0x81 ⇒ "Center, Left".
#[test]
fn af_points_bitmask_decode() {
  let mut plain = vec![0u8; 0x10];
  plain[0x04] = 0x81;
  let em = parse_tag940a(&process_enciphered(&encipher(&plain), false), true);
  assert_eq!(
    find(&em, "AFPointsSelected"),
    Some(&TagValue::Str("Center, Left".into()))
  );
}

/// An unlabelled set bit renders `"[n]"` (`ExifTool.pm:6400`): bit 20 ⇒ "[20]".
#[test]
fn af_points_bitmask_unlabelled_bit() {
  let mut plain = vec![0u8; 0x10];
  plain[0x06] = 0x10; // int32u LE: 1 << 20 = 0x0010_0000
  let em = parse_tag940a(&process_enciphered(&encipher(&plain), false), true);
  assert_eq!(
    find(&em, "AFPointsSelected"),
    Some(&TagValue::Str("[20]".into()))
  );
}

/// `-n` keeps the raw `int32u` (no ValueConv), even for a literal-hash value.
#[test]
fn af_points_raw_n() {
  let mut plain = vec![0u8; 0x10];
  plain[0x04] = 0x01;
  plain[0x05] = 0x78; // 0x7801 = 30721 (a literal key in -j)
  let em = parse_tag940a(&process_enciphered(&encipher(&plain), false), false);
  assert_eq!(find(&em, "AFPointsSelected"), Some(&TagValue::I64(0x7801)));
}

/// Per-field availability: a 4-byte block has no int32u at 0x04.
#[test]
fn per_field_truncation() {
  let plain = vec![0u8; 4];
  let em = parse_tag940a(&process_enciphered(&encipher(&plain), false), true);
  assert!(em.is_empty());
  assert!(parse_tag940a(&[], true).is_empty());
}
