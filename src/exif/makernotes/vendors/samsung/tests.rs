// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Unit tests for the Samsung typed surface + PictureWizard binary sub-table.

use super::*;
use crate::value::TagValue;

#[test]
fn populate_typed_camera_identity() {
  let mut t = MakerNotesSamsung::new();
  populate_typed(&mut t, 0x0002, &RawValue::U64(std::vec![0x2000]));
  populate_typed(&mut t, 0x0003, &RawValue::U64(std::vec![0x5001038]));
  populate_typed(&mut t, 0xa003, &RawValue::U64(std::vec![10]));
  populate_typed(
    &mut t,
    0xa001,
    &RawValue::Text {
      text: std::string::String::from("1.10"),
      raw: Box::from(&b"1.10"[..]),
    },
  );
  assert_eq!(t.device_type(), Some(0x2000));
  assert_eq!(t.model_id(), Some(0x5001038));
  assert_eq!(t.model_name(), Some("Various Models (0x5001038)"));
  assert_eq!(t.lens_type(), Some(10));
  assert_eq!(t.lens_name(), Some("Samsung NX 45mm F1.8"));
  assert_eq!(t.firmware_name(), Some("1.10"));
}

/// The NX500 PictureWizard decoded array (the Walker decodes the int16u[5]
/// `00 00 ff ff 00 00 00 00 00 00` big-endian as `[0, 65535, 0, 0, 0]`) ⇒
/// Mode=0("Standard"), Color=65535, Saturation/Sharpness/Contrast = 0-4 = -4.
#[test]
fn emit_picture_wizard_nx500_members() {
  let members = [0u64, 65535, 0, 0, 0];
  let mut out = Vec::new();
  emit_picture_wizard(&members, true, &mut out);
  let pairs: Vec<(&str, &TagValue)> = out.iter().map(|e| (e.name(), e.value())).collect();
  assert_eq!(
    pairs,
    std::vec![
      ("PictureWizardMode", &TagValue::Str("Standard".into())),
      ("PictureWizardColor", &TagValue::I64(65535)),
      ("PictureWizardSaturation", &TagValue::I64(-4)),
      ("PictureWizardSharpness", &TagValue::I64(-4)),
      ("PictureWizardContrast", &TagValue::I64(-4)),
    ]
  );
}

/// A short member array stops emitting once an index runs past the data.
#[test]
fn emit_picture_wizard_short_array_stops() {
  // Only 2 members ⇒ indices 0,1 emit (index 2 is past the end).
  let members = [0u64, 65535];
  let mut out = Vec::new();
  emit_picture_wizard(&members, false, &mut out);
  let names: Vec<&str> = out.iter().map(|e| e.name()).collect();
  assert_eq!(names, std::vec!["PictureWizardMode", "PictureWizardColor"]);
}

// ===========================================================================
// Crypt wrong-format robustness (#242 Codex R1) — Samsung.pm operates on
// `split(" ",$val)` (the RENDERED value), TIFF-type-agnostic. The key capture
// and the Crypt value path therefore handle ANY integer encoding (int32u →
// `U64`, a parseable wrong-format int32s → `I64`), and a shape that does NOT
// render to integers emits NOTHING (Crypt returns undef → no tag), never `""`.
// ===========================================================================

/// The NX500 `0xa020 EncryptionKey` int32u[11] (the real-input key from the
/// crypt unit tests), reused here to prove the wrong-format paths still decrypt
/// to the byte-exact NX500 plaintext.
const NX500_KEY: [i64; 11] = [305, 72, 737, 456, 282, 307, 519, 724, 13, 505, 193];

/// Bug 1: a `0xa020` encoded as SIGNED integers (`RawValue::I64`) — a parseable
/// wrong-format key the old `U64`-only capture silently dropped — IS captured.
/// ExifTool's `[ split(" ",$val) ]` does not inspect the TIFF type.
#[test]
fn encryption_key_from_raw_captures_signed_key() {
  let signed = RawValue::I64(NX500_KEY.to_vec());
  assert_eq!(
    encryption_key_from_raw(&signed),
    NX500_KEY.to_vec(),
    "a signed-encoded 0xa020 must capture the key (not the empty Vec the old U64-only match left)"
  );
  // A non-integer shape still yields the empty key (⇒ later Crypt tags drop).
  assert!(
    encryption_key_from_raw(&RawValue::Bytes(std::vec![1, 2, 3])).is_empty(),
    "a non-integer 0xa020 shape renders to no key"
  );
}

/// Bug 1, end to end: with the key captured from a SIGNED-encoded `0xa020`, an
/// encrypted `0xa021` decrypts to the SAME byte-exact NX500 plaintext as the
/// happy (unsigned) path — proving the capture is format-agnostic, not that the
/// signed encoding changes the cipher input.
#[test]
fn emit_crypt_decrypts_under_signed_encoded_key() {
  // 0xa020 arrives SIGNED; the key must still come out as the NX500 int32u[11].
  let key = encryption_key_from_raw(&RawValue::I64(NX500_KEY.to_vec()));
  assert_eq!(key, NX500_KEY.to_vec());

  let crypt_tag = lookup(0xa021)
    .and_then(SamsungTag::crypt)
    .expect("0xa021 WB_RGGBLevelsUncorrected is a Crypt row");
  // The 0xa021 on-disk raw (int32u[4]) → bundled plaintext "6576 4096 4096 8608".
  let raw = RawValue::U64(std::vec![6881, 4168, 4833, 9064]);
  let mut out = Vec::new();
  emit_crypt(
    "WB_RGGBLevelsUncorrected",
    crypt_tag,
    &raw,
    &key,
    false,
    &mut out,
  );
  // Collect (name, value) without indexing (the module `#![deny]`s
  // indexing_slicing) — the same iterate-then-assert pattern the PictureWizard
  // tests use.
  let pairs: Vec<(&str, &TagValue)> = out.iter().map(|e| (e.name(), e.value())).collect();
  assert_eq!(
    pairs,
    std::vec![(
      "WB_RGGBLevelsUncorrected",
      &TagValue::Str("6576 4096 4096 8608".into())
    )],
    "byte-exact NX500 plaintext regardless of the key's TIFF encoding"
  );
}

/// Bug 1, both axes signed: BOTH the key AND the encrypted value arrive as
/// `RawValue::I64` (the shared `split(" ",$val)` splitter renders either shape
/// to the same integer tokens) — still the byte-exact NX500 plaintext.
#[test]
fn emit_crypt_signed_encoded_key_and_value() {
  let key = encryption_key_from_raw(&RawValue::I64(NX500_KEY.to_vec()));
  let crypt_tag = lookup(0xa021).and_then(SamsungTag::crypt).unwrap();
  // Same magnitudes as the int32u happy path, but encoded signed.
  let raw = RawValue::I64(std::vec![6881, 4168, 4833, 9064]);
  let mut out = Vec::new();
  emit_crypt(
    "WB_RGGBLevelsUncorrected",
    crypt_tag,
    &raw,
    &key,
    false,
    &mut out,
  );
  let values: Vec<&TagValue> = out.iter().map(super::VendorEmission::value).collect();
  assert_eq!(
    values,
    std::vec![&TagValue::Str("6576 4096 4096 8608".into())]
  );
}

/// Bug 2: an encrypted `0xa021` whose raw is a shape that does NOT render to
/// integers (`RawValue::Bytes`), with a NONEMPTY key, emits NOTHING — NOT a
/// `Some("")` from decrypting an artificial empty vector. Faithful to Crypt
/// returning undef.
#[test]
fn emit_crypt_non_integer_raw_emits_nothing() {
  let crypt_tag = lookup(0xa021).and_then(SamsungTag::crypt).unwrap();
  let raw = RawValue::Bytes(std::vec![0xde, 0xad, 0xbe, 0xef]);
  let mut out = Vec::new();
  // Key is present + nonempty — so the ONLY reason to drop is the un-renderable
  // raw shape (the old `Vec::new()` path would have decrypted [] to `Some("")`).
  emit_crypt(
    "WB_RGGBLevelsUncorrected",
    crypt_tag,
    &raw,
    &NX500_KEY,
    false,
    &mut out,
  );
  assert!(
    out.is_empty(),
    "an un-renderable Crypt raw shape emits NOTHING (not an empty-string tag)"
  );
}
