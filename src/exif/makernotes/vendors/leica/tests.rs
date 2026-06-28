// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Unit tests for the Leica typed surface, the per-variant tag tables, and the
//! `LeicaPrintConv` conversions (`%Panasonic::Leica2`..`Leica9`).

// Crafted-byte fixtures index into fixed-size scratch buffers (e.g. the Data1
// block's `data1[22..26]`); the parent module's `#![deny(clippy::indexing_slicing)]`
// is not meant for this test code, matching the sibling inline test modules.
#![allow(clippy::indexing_slicing)]

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
  assert_eq!(shot.first().map(|(k, ..)| k.as_str()), Some("FileIndex"));
  assert_eq!(
    shot.first().map(|(_, v, _)| v.clone()),
    Some(TagValue::I64(1234))
  );
  // The default `Priority => 1` (ShotInfo `FileIndex` has no `Priority` directive).
  assert_eq!(shot.first().map(|(.., p)| *p), Some(1u8));
}

/// The `%Panasonic::Subdir` table (#105, the Leica M9 sub-IFD): the plain leaves
/// resolve, the `0x3901`/`0x3902` rows carry the `Data1`/`Data2` markers, and the
/// table is strictly sorted (binary-search-ready).
#[test]
fn subdir_table_leaves_and_markers() {
  assert_eq!(
    lookup(LeicaVariant::Subdir, 0x300a).map(LeicaTag::name),
    Some("Contrast")
  );
  assert_eq!(
    lookup(LeicaVariant::Subdir, 0x3405).map(LeicaTag::name),
    Some("LensType")
  );
  assert_eq!(
    lookup(LeicaVariant::Subdir, 0x3901).and_then(LeicaTag::sub_table),
    Some(LeicaSubTable::Data1)
  );
  assert_eq!(
    lookup(LeicaVariant::Subdir, 0x3902).and_then(LeicaTag::sub_table),
    Some(LeicaSubTable::Data2)
  );
  let mut prev: i64 = -1;
  for t in SUBDIR_TAGS {
    assert!(
      i64::from(t.id) > prev,
      "SUBDIR_TAGS unsorted at {:#x}",
      t.id
    );
    prev = i64::from(t.id);
  }
  // Data2 is an empty table ⇒ descends but emits nothing.
  assert!(
    decode_leica_subdir(
      LeicaSubTable::Data2,
      &[1, 2, 3, 4],
      crate::exif::ifd::ByteOrder::Little,
      true
    )
    .is_empty()
  );
}

/// END-TO-END: a crafted Leica4 (M9) MakerNote descends Leica4 → `%Subdir` →
/// `%Data1`. The four Leica4 `0x3000`/… rows are IFD SubDirectories into
/// `%Panasonic::Subdir` (`ByteOrder => Unknown`); a Subdir `0x3901` row descends
/// into the `%Panasonic::Data1` binary block. Proves the in-walk descent emits
/// the Subdir LEAVES (Contrast, LensType) AND the Data1 LensType, with the parent
/// pointers never emitted.
#[test]
fn leica4_descends_into_subdir_and_data1() {
  use crate::exif::ifd::ByteOrder;
  use crate::exif::makernotes::vendors::VendorEmission;
  use crate::exif::makernotes::{BaseRule, ChildByteOrder, DetectedMakerNote, Vendor};

  fn push_entry(buf: &mut std::vec::Vec<u8>, tag: u16, format: u16, count: u32, value: u32) {
    buf.extend_from_slice(&tag.to_le_bytes());
    buf.extend_from_slice(&format.to_le_bytes());
    buf.extend_from_slice(&count.to_le_bytes());
    buf.extend_from_slice(&value.to_le_bytes());
  }

  // mn_offset 0 + Leica4 `Base => $start - 8` (RelativeToStart(-8)) ⇒
  // value_offset_base = (0 + 8) - 8 = 0, so every offset below is buffer-relative.
  let mut buf = std::vec::Vec::new();
  buf.extend_from_slice(b"LEICA0\x03\x00"); // 8-byte Leica4 signature
  // Leica4 IFD @ 8: one entry 0x3000 -> Subdir IFD @ 26.
  buf.extend_from_slice(&1u16.to_le_bytes());
  push_entry(&mut buf, 0x3000, 4, 1, 26); // LONG, value = Subdir IFD offset
  buf.extend_from_slice(&0u32.to_le_bytes()); // next-IFD
  assert_eq!(buf.len(), 26);
  // Subdir IFD @ 26: Contrast=2 ("Normal"), LensType=20 (id 5), Data1 @ 68.
  buf.extend_from_slice(&3u16.to_le_bytes());
  push_entry(&mut buf, 0x300a, 4, 1, 2); // Contrast int32u inline
  push_entry(&mut buf, 0x3405, 4, 1, 20); // LensType int32u inline (id 5)
  push_entry(&mut buf, 0x3901, 7, 26, 68); // Data1 undef[26] out-of-line @ 68
  buf.extend_from_slice(&0u32.to_le_bytes()); // next-IFD
  assert_eq!(buf.len(), 68);
  // Data1 block @ 68: LensType int32u @ byte 22 = 24 (id 6).
  let mut data1 = std::vec![0u8; 26];
  data1[22..26].copy_from_slice(&24u32.to_le_bytes());
  buf.extend_from_slice(&data1);

  let detected = DetectedMakerNote::new(
    Vendor::Leica,
    8,
    BaseRule::RelativeToStart(-8),
    ChildByteOrder::Unknown,
    false,
  );
  let (em, _typed) = crate::exif::leica_makernote_isolated(
    &buf,
    0,
    buf.len(),
    LeicaVariant::Leica4,
    detected,
    ByteOrder::Little,
    0,
    None,
    true,
  )
  .expect("Leica4 walk");
  let has = |name: &str, val: &str| {
    em.iter()
      .any(|e: &VendorEmission| e.name() == name && e.value() == &TagValue::Str(val.into()))
  };
  let names: std::vec::Vec<&str> = em.iter().map(VendorEmission::name).collect();
  // Subdir leaves (descended Leica4 -> Subdir).
  assert!(has("Contrast", "Normal"), "Subdir Contrast; got {names:?}");
  assert!(
    has("LensType", "Summilux-M 50mm f/1.4 (II)"),
    "Subdir 0x3405 LensType; got {names:?}"
  );
  // Data1 descent (Subdir 0x3901 -> Data1 LensType, the &0xffff variant, id 6).
  assert!(
    has("LensType", "Summilux-M 35mm f/1.4"),
    "Data1 LensType; got {names:?}"
  );
  // The parent SubDirectory pointers are never emitted as values.
  assert!(
    !names.contains(&"Subdir3000") && !names.contains(&"Data1"),
    "parent pointers must not emit; got {names:?}"
  );
  // #105 Codex [high]: BOTH LensType leaves are emitted, but the Subdir `0x3405`
  // leaf keeps its default `Priority => 1` while the Data1 leaf carries
  // `Priority => 0` (`Panasonic.pm:1981`) — so the shared de-dup keeps the
  // higher-priority `0x3405` value and the later Data1 value never overrides it.
  let prio = |name: &str, val: &str| -> Option<u8> {
    em.iter()
      .find(|e: &&VendorEmission| e.name() == name && e.value() == &TagValue::Str(val.into()))
      .map(VendorEmission::priority)
  };
  assert_eq!(
    prio("LensType", "Summilux-M 50mm f/1.4 (II)"),
    Some(1),
    "Subdir 0x3405 LensType default Priority => 1; got {names:?}"
  );
  assert_eq!(
    prio("LensType", "Summilux-M 35mm f/1.4"),
    Some(0),
    "Data1 LensType Priority => 0 (Panasonic.pm:1981); got {names:?}"
  );
}

/// MIXED-ENDIAN (#105): a crafted Leica4 (M9) whose OUTER IFD is little-endian
/// but whose `%Subdir` child IFD (`ByteOrder => Unknown`) probes to BIG-endian.
/// The Subdir `0x3901` `Data1` block carries an int32u `LensType` written
/// BIG-endian; it MUST decode under the CHILD IFD's resolved order (BIG), not the
/// outer MakerNote IFD's (LITTLE). Under the outer order the bytes byte-swap to a
/// different lens id — the regression this guards. The plain Subdir leaves
/// (Contrast / `0x3405` LensType), decoded inline during the child walk, already
/// used the child order; this proves the binary sub-table re-slice now does too
/// (each block decodes under [`ExifEntry::ifd_order`](crate::exif)).
#[test]
fn leica4_subdir_child_decodes_under_its_own_byte_order() {
  use crate::exif::ifd::ByteOrder;
  use crate::exif::makernotes::vendors::VendorEmission;
  use crate::exif::makernotes::{BaseRule, ChildByteOrder, DetectedMakerNote, Vendor};

  fn push_entry_le(buf: &mut std::vec::Vec<u8>, tag: u16, format: u16, count: u32, value: u32) {
    buf.extend_from_slice(&tag.to_le_bytes());
    buf.extend_from_slice(&format.to_le_bytes());
    buf.extend_from_slice(&count.to_le_bytes());
    buf.extend_from_slice(&value.to_le_bytes());
  }
  fn push_entry_be(buf: &mut std::vec::Vec<u8>, tag: u16, format: u16, count: u32, value: u32) {
    buf.extend_from_slice(&tag.to_be_bytes());
    buf.extend_from_slice(&format.to_be_bytes());
    buf.extend_from_slice(&count.to_be_bytes());
    buf.extend_from_slice(&value.to_be_bytes());
  }

  // mn_offset 0 + Leica4 `Base => $start - 8` (RelativeToStart(-8)) ⇒
  // value_offset_base = (0 + 8) - 8 = 0, so every offset below is buffer-relative.
  let mut buf = std::vec::Vec::new();
  buf.extend_from_slice(b"LEICA0\x03\x00"); // 8-byte Leica4 signature
  // OUTER Leica4 IFD @ 8 (LITTLE): the count word [0x01,0x00] read under the
  // parent order (Little) = 1 ⇒ no toggle ⇒ the outer IFD stays LITTLE. One entry
  // 0x3000 -> Subdir IFD @ 26.
  buf.extend_from_slice(&1u16.to_le_bytes());
  push_entry_le(&mut buf, 0x3000, 4, 1, 26); // LONG, value = Subdir IFD offset
  buf.extend_from_slice(&0u32.to_le_bytes()); // next-IFD
  assert_eq!(buf.len(), 26);
  // CHILD Subdir IFD @ 26 (BIG): the count word [0x00,0x03] read under the parent
  // order (Little) = 0x0300 ⇒ (num>>8)=3 > (num&0xff)=0 ⇒ TOGGLE ⇒ the child walks
  // BIG. Three BIG-endian entries: Contrast=2 ("Normal"), LensType=20 (id 5),
  // Data1 @ 68.
  buf.extend_from_slice(&3u16.to_be_bytes());
  push_entry_be(&mut buf, 0x300a, 4, 1, 2); // Contrast int32u inline
  push_entry_be(&mut buf, 0x3405, 4, 1, 20); // LensType int32u inline (id 5)
  push_entry_be(&mut buf, 0x3901, 7, 26, 68); // Data1 undef[26] out-of-line @ 68
  buf.extend_from_slice(&0u32.to_be_bytes()); // next-IFD
  assert_eq!(buf.len(), 68);
  // Data1 block @ 68: LensType int32u @ byte 22 = 24 (id 6), written BIG-endian.
  // Decoded under the child order (BIG) ⇒ 24 ⇒ id 6 "Summilux-M 35mm f/1.4";
  // under the outer order (LITTLE) the bytes [00,00,00,18] byte-swap to
  // 0x18000000 ⇒ id 0 "Uncoded lens" — the bug.
  let mut data1 = std::vec![0u8; 26];
  data1[22..26].copy_from_slice(&24u32.to_be_bytes());
  buf.extend_from_slice(&data1);

  let detected = DetectedMakerNote::new(
    Vendor::Leica,
    8,
    BaseRule::RelativeToStart(-8),
    ChildByteOrder::Unknown,
    false,
  );
  let (em, _typed) = crate::exif::leica_makernote_isolated(
    &buf,
    0,
    buf.len(),
    LeicaVariant::Leica4,
    detected,
    ByteOrder::Little, // the OUTER/parent order
    0,
    None,
    true,
  )
  .expect("Leica4 walk");
  let has = |name: &str, val: &str| {
    em.iter()
      .any(|e: &VendorEmission| e.name() == name && e.value() == &TagValue::Str(val.into()))
  };
  let names: std::vec::Vec<&str> = em.iter().map(VendorEmission::name).collect();
  // The BIG-endian child IFD's plain leaves decode under the child order.
  assert!(
    has("Contrast", "Normal"),
    "Subdir Contrast (child BIG); got {names:?}"
  );
  assert!(
    has("LensType", "Summilux-M 50mm f/1.4 (II)"),
    "Subdir 0x3405 LensType (child BIG); got {names:?}"
  );
  // THE FIX: the Data1 binary sub-table decodes under the CHILD IFD's order (BIG)
  // ⇒ id 6, not the byte-swapped outer-order value.
  assert!(
    has("LensType", "Summilux-M 35mm f/1.4"),
    "Data1 LensType must decode under the child IFD order (BIG); got {names:?}"
  );
  // The byte-swapped (buggy outer-order) decode would be id 0 "Uncoded lens" —
  // assert it is ABSENT so a regression to the outer order is unambiguous.
  assert!(
    !has("LensType", "Uncoded lens"),
    "Data1 must NOT decode under the outer order (byte-swapped to id 0); got {names:?}"
  );
  // The byte-order fix leaves the `Priority => 0` (`Panasonic.pm:1981`) ride
  // intact for the Data1 LensType.
  let prio = |name: &str, val: &str| -> Option<u8> {
    em.iter()
      .find(|e: &&VendorEmission| e.name() == name && e.value() == &TagValue::Str(val.into()))
      .map(VendorEmission::priority)
  };
  assert_eq!(
    prio("LensType", "Summilux-M 35mm f/1.4"),
    Some(0),
    "Data1 LensType Priority => 0; got {names:?}"
  );
}
