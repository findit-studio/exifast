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

/// A plaintext `Tag9401` block carrying the real ILME-FX3 deciphered values:
/// 0x0000=160 (Ver9401), and the ISOInfo 5-byte sub-block at 0x04a1 =
/// `ff 22 00 0b 00` (ISOSetting=255 → "Unknown (255)", ISOAutoMin=0 → "Auto",
/// ISOAutoMax=0 → "Auto"). Enciphered for input to `parse_tag9401`.
fn fx3_enciphered_block() -> Vec<u8> {
  let mut plain = vec![0u8; 0x04a1 + 5];
  plain[0x0000] = 160;
  plain[0x04a1] = 0xff;
  plain[0x04a2] = 0x22;
  plain[0x04a3] = 0x00;
  plain[0x04a4] = 0x0b;
  plain[0x04a5] = 0x00;
  encipher(&plain)
}

fn find<'a>(em: &'a [Tag9401Emission], name: &str) -> Option<&'a TagValue> {
  em.iter().rev().find(|e| e.name == name).map(|e| &e.value)
}

#[test]
fn fx3_iso_info_matches_golden() {
  let blk = fx3_enciphered_block();
  let em = parse_tag9401(&blk, Some("ILME-FX3"), Some("ILME-FX3 v4.00"));
  // ValueConv hash applies identically in -j and -n (no separate PrintConv).
  assert_eq!(
    find(&em, "ISOSetting"),
    Some(&TagValue::Str("Unknown (255)".into()))
  );
  assert_eq!(find(&em, "ISOAutoMin"), Some(&TagValue::Str("Auto".into())));
  assert_eq!(find(&em, "ISOAutoMax"), Some(&TagValue::Str("Auto".into())));
}

/// The `%isoSetting2010` ValueConv: 0 → "Auto", a mapped key → its ISO number,
/// a miss → "Unknown (N)".
#[test]
fn iso_setting_hash_values() {
  assert_eq!(iso_setting_2010(0), TagValue::Str("Auto".into()));
  assert_eq!(iso_setting_2010(11), TagValue::I64(100));
  assert_eq!(iso_setting_2010(23), TagValue::I64(1600));
  assert_eq!(iso_setting_2010(47), TagValue::I64(409600));
  assert_eq!(iso_setting_2010(255), TagValue::Str("Unknown (255)".into()));
  // Keys 1/2/3/4/6 are NOT in the hash ⇒ "Unknown (N)".
  assert_eq!(iso_setting_2010(6), TagValue::Str("Unknown (6)".into()));
}

/// The `IS_SUBDIR` offset selection: `Ver9401` (+ Software/Model) → ISOInfo
/// byte-offset, table-order first-match (`Sony.pm:8654-8672`).
#[test]
fn iso_info_offset_selection() {
  // FX3: Ver=160 (prefix), Software not "ILCE-1 v2" ⇒ 0x04a1.
  assert_eq!(
    iso_info_offset(160, Some("ILME-FX3"), Some("ILME-FX3 v4.00")),
    Some(0x04a1)
  );
  // Numeric-equality rows.
  assert_eq!(iso_info_offset(181, None, None), Some(0x03e2));
  assert_eq!(iso_info_offset(198, None, None), Some(0x0453));
  assert_eq!(iso_info_offset(68, None, None), Some(0x0634));
  // Prefix-alternation rows.
  assert_eq!(iso_info_offset(186, None, None), Some(0x03f4));
  assert_eq!(iso_info_offset(201, None, None), Some(0x044e));
  // Ver=167 splits on Software (ILCE-7M4 v2/v3 → 0x049e, else 0x049d).
  assert_eq!(
    iso_info_offset(167, None, Some("ILCE-7M4 v1.00")),
    Some(0x049d)
  );
  assert_eq!(
    iso_info_offset(167, None, Some("ILCE-7M4 v2.00")),
    Some(0x049e)
  );
  // Ver=164 with "ILCE-1 v2" software → 0x04a2 (NOT 0x04a1).
  assert_eq!(
    iso_info_offset(164, Some("ILCE-1"), Some("ILCE-1 v2.00")),
    Some(0x04a2)
  );
  assert_eq!(
    iso_info_offset(164, Some("ILCE-1"), Some("ILCE-1 v1.00")),
    Some(0x04a1)
  );
  // Ver=155 splits on Model (ZV-1M2 → 0x04ba, else 0x04a2).
  assert_eq!(iso_info_offset(155, Some("ZV-1M2"), None), Some(0x04ba));
  assert_eq!(iso_info_offset(155, Some("DSC-RX0M2"), None), Some(0x04a2));
  // No candidate ⇒ None.
  assert_eq!(iso_info_offset(5, None, None), None);
}

/// Per-field availability: a block too short for the selected ISOInfo offset
/// emits nothing (no panic).
#[test]
fn truncated_block_per_field() {
  // Ver9401=160 selects 0x04a1, but the block is far too short.
  let plain = {
    let mut p = vec![0u8; 16];
    p[0] = 160;
    p
  };
  assert!(parse_tag9401(&encipher(&plain), Some("ILME-FX3"), Some("ILME-FX3 v4.00")).is_empty());
  // Empty block ⇒ no Ver9401 ⇒ nothing.
  assert!(parse_tag9401(&[], None, None).is_empty());
}
