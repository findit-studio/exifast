// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

use super::*;
use crate::exif::ifd::RawValue;

#[test]
fn populate_typed_resolves_model() {
  // 0x0005 PentaxModelID 76830 => "K10D".
  let mut t = MakerNotesPentax::new();
  populate_typed_value(&mut t, 0x0005, &RawValue::U64(std::vec![76830]));
  assert_eq!(t.model_id(), Some(76830));
  assert_eq!(t.model_name(), Some("K10D"));
}

#[test]
fn emit_lens_rec_pentax_jpg_pair() {
  // Pentax.jpg LensRec position 0 = int8u[2] (3, 44).
  let block = [3u8, 44, 0, 0];
  // -j: the %pentaxLensTypes name.
  let mut em = std::vec::Vec::new();
  emit_lens_rec(&block, true, &mut em);
  assert_eq!(em.len(), 1);
  assert_eq!(em[0].name(), "LensType");
  // #284: `%Pentax::LensRec` `LensType` is `Priority => 0` (`Pentax.pm:4202`).
  assert_eq!(em[0].priority(), 0, "LensRec LensType Priority=>0");
  assert_eq!(
    em[0].value(),
    &crate::value::TagValue::Str("Sigma or Tamron Lens (3 44)".into())
  );
  // -n: the raw "series model" pair.
  let mut em_n = std::vec::Vec::new();
  emit_lens_rec(&block, false, &mut em_n);
  assert_eq!(em_n[0].value(), &crate::value::TagValue::Str("3 44".into()));
}

#[test]
fn emit_lens_rec_short_block_emits_nothing() {
  let mut em = std::vec::Vec::new();
  emit_lens_rec(&[3u8], true, &mut em);
  assert!(
    em.is_empty(),
    "a block too short for int8u[2] emits nothing"
  );
}

#[test]
fn populate_lens_type_packs_pair() {
  let mut t = MakerNotesPentax::new();
  populate_lens_type(&mut t, &[3u8, 44]);
  assert_eq!(t.lens_type(), Some((3 << 8) | 44));
  assert_eq!(t.lens_name(), Some("Sigma or Tamron Lens (3 44)"));
}
