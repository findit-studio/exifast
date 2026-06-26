// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

use super::*;

/// Build a deciphered-then-RE-ENCIPHERED `Tag9050c` block so `parse_tag9050c`
/// (which deciphers internally) sees the documented plaintext at each offset.
/// The forward map is `c = (b·b·b) mod 249` (`Sony.pm:11521`).
fn encipher(plain: &[u8]) -> Vec<u8> {
  plain
    .iter()
    .map(|&b| {
      if b <= 248 {
        (((u32::from(b) * u32::from(b)) % 249 * u32::from(b)) % 249) as u8
      } else {
        b
      }
    })
    .collect()
}

/// A 256-byte plaintext `Tag9050c` block carrying the real ILME-FX3 field
/// values, enciphered for input to `parse_tag9050c`. Offsets/values are the
/// bundled `exiftool -v4` deciphered dump of the activation fixture.
fn fx3_enciphered_block() -> Vec<u8> {
  let mut plain = vec![0u8; 256];
  // 0x0026 Shutter int16u[3] = 2738 5168 6484.
  plain[0x26..0x2c].copy_from_slice(&[0xb2, 0x0a, 0x30, 0x14, 0x54, 0x19]);
  // 0x0039 FlashStatus = 0 (already 0).
  // 0x003a ShutterCount int32u = 2.
  plain[0x3a..0x3e].copy_from_slice(&2u32.to_le_bytes());
  // 0x0046 SonyExposureTime int16u = 5888.
  plain[0x46..0x48].copy_from_slice(&5888u16.to_le_bytes());
  // 0x0048 SonyFNumber int16u = 4882.
  plain[0x48..0x4a].copy_from_slice(&4882u16.to_le_bytes());
  // 0x004b ReleaseMode2 = 0.
  // 0x0050 ShutterCount2 int32u = 2.
  plain[0x50..0x54].copy_from_slice(&2u32.to_le_bytes());
  // 0x0066 SonyExposureTime int16u = 5888.
  plain[0x66..0x68].copy_from_slice(&5888u16.to_le_bytes());
  // 0x0068 SonyFNumber int16u = 4882.
  plain[0x68..0x6a].copy_from_slice(&4882u16.to_le_bytes());
  // 0x006b ReleaseMode2 = 0.
  // 0x0088 InternalSerialNumber int8u[6] = 71 255 0 0 167 8.
  plain[0x88..0x8e].copy_from_slice(&[71, 255, 0, 0, 167, 8]);
  encipher(&plain)
}

fn find<'a>(em: &'a [Tag9050Emission], name: &str) -> Option<&'a TagValue> {
  // Last-wins (the duplicate SonyExposureTime/SonyFNumber/ReleaseMode2 rows).
  em.iter().rev().find(|e| e.name == name).map(|e| &e.value)
}

#[test]
fn fx3_tag9050c_print_conv_matches_golden() {
  let blk = fx3_enciphered_block();
  let em = parse_tag9050c(&blk, Some("ILME-FX3"), true);
  assert_eq!(
    find(&em, "Shutter"),
    Some(&TagValue::Str("Mechanical (2738 5168 6484)".into()))
  );
  assert_eq!(
    find(&em, "FlashStatus"),
    Some(&TagValue::Str("No Flash present".into()))
  );
  assert_eq!(find(&em, "ShutterCount"), Some(&TagValue::I64(2)));
  assert_eq!(find(&em, "ShutterCount2"), Some(&TagValue::I64(2)));
  assert_eq!(
    find(&em, "SonyExposureTime"),
    Some(&TagValue::Str("1/128".into()))
  );
  assert_eq!(find(&em, "SonyFNumber"), Some(&TagValue::Str("2.9".into())));
  assert_eq!(
    find(&em, "ReleaseMode2"),
    Some(&TagValue::Str("Normal".into()))
  );
  assert_eq!(
    find(&em, "InternalSerialNumber"),
    Some(&TagValue::Str("47ff0000a708".into()))
  );
}

#[test]
fn fx3_tag9050c_raw_values_match_golden() {
  let blk = fx3_enciphered_block();
  let em = parse_tag9050c(&blk, Some("ILME-FX3"), false);
  assert_eq!(
    find(&em, "Shutter"),
    Some(&TagValue::Str("2738 5168 6484".into()))
  );
  assert_eq!(find(&em, "FlashStatus"), Some(&TagValue::I64(0)));
  assert_eq!(
    find(&em, "SonyExposureTime"),
    Some(&TagValue::F64(0.0078125))
  );
  assert_eq!(
    find(&em, "SonyFNumber"),
    Some(&TagValue::F64(2.898_198_179_284_07))
  );
  assert_eq!(find(&em, "ReleaseMode2"), Some(&TagValue::I64(0)));
  assert_eq!(
    find(&em, "InternalSerialNumber"),
    Some(&TagValue::Str("71 255 0 0 167 8".into()))
  );
}

/// `InternalSerialNumber` (0x0088) is model-gated: a non-FX3-class body must NOT
/// emit it (`Condition`, `Sony.pm:8297`).
#[test]
fn internal_serial_number_model_gated() {
  let blk = fx3_enciphered_block();
  let em = parse_tag9050c(&blk, Some("ILCE-9"), true);
  assert!(find(&em, "InternalSerialNumber").is_none());
}

/// Per-field availability: a TRUNCATED block emits only the leaves whose byte
/// range fits — no panic, no all-or-nothing.
#[test]
fn truncated_block_emits_only_in_range_fields() {
  let full = fx3_enciphered_block();
  // Keep through 0x003e (so Shutter + FlashStatus + ShutterCount fit, but the
  // SonyExposureTime/FNumber/serial at >= 0x46 do not).
  let em = parse_tag9050c(&full[..0x3e], Some("ILME-FX3"), true);
  assert!(find(&em, "Shutter").is_some());
  assert!(find(&em, "ShutterCount").is_some());
  assert!(find(&em, "SonyExposureTime").is_none());
  assert!(find(&em, "InternalSerialNumber").is_none());
  // An empty block emits nothing and does not panic.
  assert!(parse_tag9050c(&[], Some("ILME-FX3"), true).is_empty());
}
