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
