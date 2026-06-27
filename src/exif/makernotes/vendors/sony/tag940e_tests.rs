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

fn find<'a>(em: &'a [Tag940eEmission], name: &str) -> Option<&'a TagValue> {
  em.iter().rev().find(|e| e.name == name).map(|e| &e.value)
}

/// `Tag940e` is the NEX/ILCE/Lunar variant (`Sony.pm:2100`); the SLT/HV/ILCA
/// bodies route to the (deferred) `%Sony::AFInfo` table instead.
#[test]
fn selects_only_emount() {
  assert!(selects_tag940e(Some("NEX-5N")));
  assert!(selects_tag940e(Some("ILCE-7M3")));
  assert!(selects_tag940e(Some("Lunar")));
  assert!(!selects_tag940e(Some("ILME-FX3"))); // ILME-, not ILCE-
  assert!(!selects_tag940e(Some("SLT-A77V")));
  assert!(!selects_tag940e(None));
}

/// The full block emits Width/Height (raw int8u) + the binary `TiffMeteringImage`
/// placeholder; the `\b` boundary excludes a suffixed body (`ILCE-9M2`).
#[test]
fn metering_model_word_boundary() {
  let mut plain = vec![0u8; 0x1a08 + 2640];
  plain[0x1a06] = 44; // width
  plain[0x1a07] = 30; // height
  let em = parse_tag940e(
    &process_enciphered(&encipher(&plain), false),
    Some("ILCE-9"),
    None,
  );
  assert_eq!(
    find(&em, "TiffMeteringImageWidth"),
    Some(&TagValue::I64(44))
  );
  assert_eq!(
    find(&em, "TiffMeteringImageHeight"),
    Some(&TagValue::I64(30))
  );
  assert_eq!(
    find(&em, "TiffMeteringImage"),
    Some(&TagValue::Str(
      "(Binary data 2640 bytes, use -b option to extract)".into()
    ))
  );

  // `ILCE-9M2` ⇒ `\b` after "ILCE-9" fails ⇒ no leaves.
  let em2 = parse_tag940e(
    &process_enciphered(&encipher(&plain), false),
    Some("ILCE-9M2"),
    None,
  );
  assert!(em2.is_empty());
}

/// `7RM3A?` — both `ILCE-7RM3` and `ILCE-7RM3A` match.
#[test]
fn metering_7rm3_optional_a() {
  let mut plain = vec![0u8; 0x1a08];
  plain[0x1a06] = 10;
  plain[0x1a07] = 12;
  for model in ["ILCE-7RM3", "ILCE-7RM3A"] {
    let em = parse_tag940e(
      &process_enciphered(&encipher(&plain), false),
      Some(model),
      None,
    );
    assert_eq!(
      find(&em, "TiffMeteringImageWidth"),
      Some(&TagValue::I64(10)),
      "model {model}"
    );
  }
}

/// `Software !~ /^ILCE-9 (v5.0|v6.0)/` — an excluded firmware drops the leaves.
#[test]
fn software_exclusion() {
  let mut plain = vec![0u8; 0x1a08];
  plain[0x1a06] = 10;
  let excluded = parse_tag940e(
    &process_enciphered(&encipher(&plain), false),
    Some("ILCE-9"),
    Some("ILCE-9 v5.00"),
  );
  assert!(excluded.is_empty());

  let ok = parse_tag940e(
    &process_enciphered(&encipher(&plain), false),
    Some("ILCE-9"),
    Some("ILCE-9 v4.00"),
  );
  assert_eq!(
    find(&ok, "TiffMeteringImageWidth"),
    Some(&TagValue::I64(10))
  );
}

/// Per-field availability: a block too short for the 2640-byte image still emits
/// Width/Height; a wrong model emits nothing.
#[test]
fn per_field_availability() {
  let mut plain = vec![0u8; 0x1a08 + 100];
  plain[0x1a06] = 44;
  plain[0x1a07] = 30;
  let em = parse_tag940e(
    &process_enciphered(&encipher(&plain), false),
    Some("ILCE-7M3"),
    None,
  );
  assert!(find(&em, "TiffMeteringImageWidth").is_some());
  assert!(find(&em, "TiffMeteringImageHeight").is_some());
  assert!(find(&em, "TiffMeteringImage").is_none());

  assert!(parse_tag940e(&[], Some("ILME-FX3"), None).is_empty());
}
