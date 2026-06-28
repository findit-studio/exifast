// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Unit tests for the Leica typed surface, the per-variant tag tables, and the
//! `LeicaPrintConv` conversions (`%Panasonic::Leica2`..`Leica9`).

use super::*;
use crate::exif::ifd::RawValue;
use crate::value::TagValue;

/// Leica2 0x310 LensType: stored int32u splits into `"<id> <bits>"` then
/// `%leicaLensTypes`. `5 << 2 = 20` ⇒ id 5, bits 0 ⇒ `"5"` ⇒
/// "Summilux-M 50mm f/1.4 (II)".
#[test]
fn lens_type_leica2_resolves_name() {
  let raw = RawValue::U64(std::vec![20]);
  let v = LeicaPrintConv::LensType.apply(&raw, true);
  assert_eq!(v, TagValue::Str("Summilux-M 50mm f/1.4 (II)".into()));
  // -n keeps the ValueConv "id bits" string.
  let n = LeicaPrintConv::LensType.apply(&raw, false);
  assert_eq!(n, TagValue::Str("5 0".into()));
}

/// LensType `"id bits"` key wins over the bare-`id` fallback: `6 << 2 | 0 = 24`
/// ⇒ `"6 0"` => "Summilux-M 35mm f/1.4" (NOT the `"6"` => "Summicron-M 35mm").
#[test]
fn lens_type_id_bits_key_preferred() {
  let raw = RawValue::U64(std::vec![24]); // id 6, bits 0
  let v = LeicaPrintConv::LensType.apply(&raw, true);
  assert_eq!(v, TagValue::Str("Summilux-M 35mm f/1.4".into()));
  // id 6 bits 2 ⇒ "6 2" absent ⇒ falls back to "6" => "Summicron-M 35mm f/2 (IV)".
  let raw2 = RawValue::U64(std::vec![(6 << 2) | 2]);
  let v2 = LeicaPrintConv::LensType.apply(&raw2, true);
  assert_eq!(v2, TagValue::Str("Summicron-M 35mm f/2 (IV)".into()));
}

/// An entirely unmatched LensType keeps the ValueConv `"id bits"` string.
#[test]
fn lens_type_unmatched_keeps_value_conv() {
  let raw = RawValue::U64(std::vec![(999 << 2) | 1]);
  let v = LeicaPrintConv::LensType.apply(&raw, true);
  assert_eq!(v, TagValue::Str("999 1".into()));
}

/// Leica2 0x303 SerialNumber: `sprintf("%.7d", $val)`.
#[test]
fn serial_number_7_zero_pads() {
  let raw = RawValue::U64(std::vec![1234]);
  assert_eq!(
    LeicaPrintConv::SerialNumber7.apply(&raw, true),
    TagValue::Str("0001234".into())
  );
  assert_eq!(
    LeicaPrintConv::SerialNumber7.apply(&raw, false),
    TagValue::I64(1234)
  );
}

/// Leica2 0x304 WhiteBalance: the hash, then the `> 0x8000` Kelvin OTHER.
#[test]
fn white_balance_2_hash_and_kelvin() {
  assert_eq!(
    LeicaPrintConv::WhiteBalance2.apply(&RawValue::U64(std::vec![1]), true),
    TagValue::Str("Daylight".into())
  );
  // 0x8000 + 5500 = 38268 ⇒ "5500 Kelvin".
  assert_eq!(
    LeicaPrintConv::WhiteBalance2.apply(&RawValue::U64(std::vec![0x8000 + 5500]), true),
    TagValue::Str("5500 Kelvin".into())
  );
  // An unmatched value below 0x8000 ⇒ raw passthrough (WhiteBalanceConv undef).
  assert_eq!(
    LeicaPrintConv::WhiteBalance2.apply(&RawValue::U64(std::vec![99]), true),
    TagValue::I64(99)
  );
}

/// The `rational64s` brightness rows: `sprintf("%.2f", $val)`.
#[test]
fn sprintf_2f_on_rational() {
  use crate::value::Rational;
  let raw = RawValue::Rational(std::vec![Rational::new(-325, 100, 7)]);
  assert_eq!(
    LeicaPrintConv::Sprintf2f.apply(&raw, true),
    TagValue::Str("-3.25".into())
  );
}

/// Leica6 0x303 LensType trims trailing spaces (ValueConv `$val=~s/ +$//`).
#[test]
fn lens_type_trim_strips_trailing_spaces() {
  let raw = RawValue::Text {
    text: std::string::String::from("APO-Summicron   "),
    raw: Box::from(&b"APO-Summicron   "[..]),
  };
  let v = LeicaPrintConv::LensTypeTrim.apply(&raw, true);
  assert_eq!(v, TagValue::Str("APO-Summicron".into()));
}

/// Leica6 0x320 FirmwareVersion: int8u[4] `$val=~tr/ /./`.
#[test]
fn firmware_version_dots() {
  let raw = RawValue::U64(std::vec![1, 2, 3, 4]);
  assert_eq!(
    LeicaPrintConv::FirmwareVersionDots.apply(&raw, true),
    TagValue::Str("1.2.3.4".into())
  );
  // -n keeps the space-joined value.
  assert_eq!(
    LeicaPrintConv::FirmwareVersionDots.apply(&raw, false),
    TagValue::Str("1 2 3 4".into())
  );
}

/// Leica9 0x35a FNumber: int32s ValueConv `/1000`, PrintConv `%.1f`.
#[test]
fn fnumber_div1000() {
  let raw = RawValue::I64(std::vec![2800]);
  assert_eq!(
    LeicaPrintConv::Div1000Sprintf1f.apply(&raw, true),
    TagValue::Str("2.8".into())
  );
  assert_eq!(
    LeicaPrintConv::Div1000Sprintf1f.apply(&raw, false),
    TagValue::F64(2.8)
  );
}

/// Leica9 0x359 ISOSelected: 0 => Auto, else identity.
#[test]
fn iso_selected_auto_and_identity() {
  assert_eq!(
    LeicaPrintConv::IsoSelected.apply(&RawValue::I64(std::vec![0]), true),
    TagValue::Str("Auto".into())
  );
  assert_eq!(
    LeicaPrintConv::IsoSelected.apply(&RawValue::I64(std::vec![3200]), true),
    TagValue::I64(3200)
  );
}

/// Leica5 0x040d ExposureMode: int8u[4] string hash.
#[test]
fn exposure_mode_5_hash() {
  let raw = RawValue::U64(std::vec![1, 1, 0, 0]);
  assert_eq!(
    LeicaPrintConv::ExposureMode5.apply(&raw, true),
    TagValue::Str("Aperture-priority AE (1)".into())
  );
  assert_eq!(
    LeicaPrintConv::ExposureMode5.apply(&raw, false),
    TagValue::Str("1 1 0 0".into())
  );
}

/// Leica5 0x0500 InternalSerialNumber: the date-decoding PrintConv.
/// "ABC" + "1903150042" ⇒ year 19→2019, "(ABC) 2019:03:15 no. 0042".
#[test]
fn internal_serial_number_decodes_date() {
  let bytes = b"ABC1903150042".to_vec();
  let raw = RawValue::Bytes(bytes);
  let v = LeicaPrintConv::InternalSerialNumber.apply(&raw, true);
  assert_eq!(v, TagValue::Str("(ABC) 2019:03:15 no. 0042".into()));
  // A non-matching value passes through unchanged (the bundled `return $val`).
  let raw2 = RawValue::Bytes(b"not-a-serial".to_vec());
  let v2 = LeicaPrintConv::InternalSerialNumber.apply(&raw2, true);
  assert_eq!(v2, TagValue::Bytes(b"not-a-serial".to_vec()));
}

/// The dispatcher signature-variant → table mapping: Leica7 reuses the Leica6
/// table, Leica8 reuses the Leica5 table (we model that as the dispatcher
/// resolving Leica7/8 to the table-bearing variant; here we assert the tables
/// themselves carry the right tags).
#[test]
fn variant_tables_carry_expected_leaves() {
  // Leica2 has 0x310 LensType.
  assert!(lookup(LeicaVariant::Leica2, 0x310).is_some());
  // Leica4 is all-SubDirectory ⇒ no plain leaf.
  assert!(lookup(LeicaVariant::Leica4, 0x3000).is_none());
  assert_eq!(LEICA4_TAGS.len(), 0);
  // Leica5 has the Condition-gated 0x0303 LensType + 0x040d ExposureMode.
  assert!(lookup(LeicaVariant::Leica5, 0x0303).is_some());
  assert!(lookup(LeicaVariant::Leica5, 0x040d).is_some());
  // Leica6 has the trimmed 0x303 LensType + the Typ-006 0x321.
  assert_eq!(
    lookup(LeicaVariant::Leica6, 0x303).map(LeicaTag::name),
    Some("LensType")
  );
  assert_eq!(
    lookup(LeicaVariant::Leica6, 0x321).and_then(LeicaTag::condition),
    Some(LeicaCondition::ModelTyp006)
  );
  // Leica9 has 0x35a FNumber.
  assert!(lookup(LeicaVariant::Leica9, 0x35a).is_some());
}

/// The `rational64s` Format override is present on the brightness rows.
#[test]
fn brightness_rows_have_rational64s_override() {
  use crate::exif::ifd::Format;
  assert_eq!(
    format_override(LeicaVariant::Leica2, 0x311),
    Some(Format::Rational64s)
  );
  assert_eq!(
    format_override(LeicaVariant::Leica9, 0x312),
    Some(Format::Rational64s)
  );
}

/// The typed surface captures the lens name + serial.
#[test]
fn populate_typed_lens_and_serial() {
  let mut t = MakerNotesLeica::new();
  populate_typed(
    &mut t,
    LeicaVariant::Leica2,
    0x310,
    &TagValue::Str("Summicron-M 50mm f/2 (IV, V)".into()),
    &RawValue::U64(std::vec![132]),
  );
  populate_typed(
    &mut t,
    LeicaVariant::Leica2,
    0x303,
    &TagValue::Str("0001234".into()),
    &RawValue::U64(std::vec![1234]),
  );
  assert_eq!(t.lens_name(), Some("Summicron-M 50mm f/2 (IV, V)"));
  assert_eq!(t.serial_number(), Some("0001234"));
}

/// The #105 binary `ProcessBinaryData` SubDirectory rows resolve with their
/// `sub_table` marker (so the capture loop descends them), the extended tables
/// stay sorted (the binary-search invariant), and `decode_leica_subdir` routes
/// each marker to its decoder.
#[test]
fn binary_subdir_rows_present_and_routed() {
  // The SubDirectory pointers carry the right marker.
  assert_eq!(
    lookup(LeicaVariant::Leica3, 0x0b).and_then(LeicaTag::sub_table),
    Some(LeicaSubTable::SerialInfo)
  );
  assert_eq!(
    lookup(LeicaVariant::Leica5, 0x040a).and_then(LeicaTag::sub_table),
    Some(LeicaSubTable::FocusInfo)
  );
  assert_eq!(
    lookup(LeicaVariant::Leica5, 0x0410).and_then(LeicaTag::sub_table),
    Some(LeicaSubTable::ShotInfo)
  );
  // The extended tables stay strictly sorted (binary-search-ready).
  for tags in [LEICA3_TAGS, LEICA5_TAGS] {
    let mut prev: i64 = -1;
    for t in tags {
      assert!(
        i64::from(t.id) > prev,
        "LEICA table unsorted at {:#x}",
        t.id
      );
      prev = i64::from(t.id);
    }
  }
  // The dispatcher routes each marker to its decoder.
  let shot = decode_leica_subdir(
    LeicaSubTable::ShotInfo,
    &1234u16.to_le_bytes(),
    crate::exif::ifd::ByteOrder::Little,
    true,
  );
  assert_eq!(shot.first().map(|(k, _)| k.as_str()), Some("FileIndex"));
  assert_eq!(
    shot.first().map(|(_, v)| v.clone()),
    Some(TagValue::I64(1234))
  );
}
