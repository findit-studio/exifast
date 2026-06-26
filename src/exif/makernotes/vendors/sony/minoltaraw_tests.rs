use super::*;
use crate::exif::ifd::RawValue;

/// The A200's real MRW block (from `exiftool -v4`): `\0MRI` header + total length
/// 0xb0, then `\0PRD` (24) / `\0WBG` (12) / `\0RIF` (116) segments.
fn a200_mrw() -> std::vec::Vec<u8> {
  let mut b = std::vec::Vec::new();
  b.extend_from_slice(&[0x00, b'M', b'R', b'I']);
  b.extend_from_slice(&0xb0u32.to_le_bytes());
  // \0PRD len=24
  b.extend_from_slice(&[0x00, b'P', b'R', b'D']);
  b.extend_from_slice(&24u32.to_le_bytes());
  b.extend_from_slice(&[
    0x32, 0x31, 0x38, 0x37, 0x30, 0x30, 0x30, 0x32, // FirmwareID "21870002"
    0x30, 0x0a, // SensorHeight 2608
    0x28, 0x0f, // SensorWidth 3880
    0x20, 0x0a, // ImageHeight 2592
    0x20, 0x0f, // ImageWidth 3872
    0x10, // RawDepth 16
    0x0c, // BitDepth 12
    0x52, // StorageMethod 82
    0x01, 0x01, 0x00, 0x00, // offsets 19-22 (unused)
    0x00, // offset 23: BayerPattern 0
  ]);
  // \0WBG len=12
  b.extend_from_slice(&[0x00, b'W', b'B', b'G']);
  b.extend_from_slice(&12u32.to_le_bytes());
  b.extend_from_slice(&[
    0x02, 0x02, 0x02, 0x02, // WBScale
    0x59, 0x01, 0x00, 0x01, 0x00, 0x01, 0x20, 0x03, // WB_RGGBLevels 345 256 256 800
  ]);
  // \0RIF len=116
  b.extend_from_slice(&[0x00, b'R', b'I', b'F']);
  b.extend_from_slice(&116u32.to_le_bytes());
  let mut rif = [0u8; 116];
  rif[5] = 0x80; // ProgramMode 128
  rif[6] = 0x04; // ISOSetting 4
  rif[0x3b] = 0xff; // Hue -1
  b.extend_from_slice(&rif);
  b
}

fn find<'a>(leaves: &'a [MrwLeaf], name: &str) -> Option<&'a RawValue> {
  leaves
    .iter()
    .find(|l| l.tag.name() == name)
    .map(|l| &l.value)
}

#[test]
fn process_mrw_emits_a200_prd_wbg_rif() {
  let mrw = a200_mrw();
  let leaves = process_mrw(&mrw, Some("SONY"), Some("DSLR-A200"));
  // 9 PRD + 2 WBG + 11 RIF = 22.
  assert_eq!(leaves.len(), 22, "A200 MRW emits 22 leaves");
  assert!(
    matches!(find(&leaves, "FirmwareID"), Some(RawValue::Text { text, .. }) if text == "21870002")
  );
  assert!(matches!(find(&leaves, "SensorHeight"), Some(RawValue::U64(v)) if v == &[2608]));
  assert!(matches!(find(&leaves, "ImageWidth"), Some(RawValue::U64(v)) if v == &[3872]));
  assert!(matches!(find(&leaves, "ImageHeight"), Some(RawValue::U64(v)) if v == &[2592]));
  assert!(matches!(find(&leaves, "StorageMethod"), Some(RawValue::U64(v)) if v == &[82]));
  assert!(matches!(find(&leaves, "BayerPattern"), Some(RawValue::U64(v)) if v == &[0]));
  assert!(
    matches!(find(&leaves, "WB_RGGBLevels"), Some(RawValue::U64(v)) if v == &[345, 256, 256, 800])
  );
  assert!(find(&leaves, "WB_GBRGLevels").is_none());
  assert!(matches!(find(&leaves, "ProgramMode"), Some(RawValue::U64(v)) if v == &[128]));
  assert!(matches!(find(&leaves, "ISOSetting"), Some(RawValue::U64(v)) if v == &[4]));
  assert!(matches!(find(&leaves, "Hue"), Some(RawValue::I64(v)) if v == &[-1]));
  // SONY make + DSLR-A200 model gating: ZoneMatching@74 + ColorTemperature@78 +
  // ColorFilter@79 emit; the Minolta/A100 leaves do not.
  assert!(find(&leaves, "ZoneMatching").is_some());
  assert!(find(&leaves, "ColorTemperature").is_some());
  assert!(find(&leaves, "ColorFilter").is_some());
  assert!(find(&leaves, "ColorMode").is_none());
}

#[test]
fn process_mrw_rejects_non_mrw_header() {
  // The FX3's non-MRW 0x7250 payload (encrypted) — no `\0MR[MI]` header.
  assert!(
    process_mrw(
      &[0x5c, 0xc6, 0x54, 0xc6, 0, 0, 0, 0],
      Some("SONY"),
      Some("ILME-FX3")
    )
    .is_empty()
  );
  // A zero block.
  assert!(process_mrw(&[0u8; 64], Some("SONY"), None).is_empty());
}

#[test]
fn iso_setting_print_other_branch() {
  // A200: raw 4 → int(2 ** ((4-48)/8) * 100 + 0.5) = 2.
  assert!(matches!(iso_setting_print(4), IsoPrint::Int(2)));
  assert!(matches!(iso_setting_print(0), IsoPrint::Str("Auto")));
  assert!(matches!(iso_setting_print(48), IsoPrint::Int(100)));
  assert!(matches!(
    iso_setting_print(174),
    IsoPrint::Str("80 (Zone Matching Low)")
  ));
}

#[test]
fn convert_wb_mode_auto() {
  assert_eq!(convert_wb_mode(0), "Auto");
  assert_eq!(convert_wb_mode(1), "Daylight");
  // high nibble in 6..=12 appends ` (hi-8)`.
  assert_eq!(convert_wb_mode(0x60), "Auto (-2)");
  assert_eq!(convert_wb_mode(0x0f), "Unknown (15)");
}

#[test]
fn dimage_a200_word_boundary() {
  assert!(model_is_dimage_a200("DiMAGE A200"));
  assert!(!model_is_dimage_a200("DSLR-A200"));
  assert!(!model_is_dimage_a200("DiMAGE A2000"));
}
