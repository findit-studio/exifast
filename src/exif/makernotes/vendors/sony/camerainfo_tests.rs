// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Base `%Sony::CameraInfo` (`0x0010`, A700/A850/A900): the BIG-endian
//! `%afStatusInfo` grid, the 23-point `AFPoint` list, the `Far Right`/`Far Left`
//! `AFPointSelected` values, and the A850/A900-only `AFMicroAdj*` `Mask` trio
//! render byte-exact vs `Sony.pm:2746-2896`.

use super::*;
use crate::value::TagValue;

fn put_i16_be(buf: &mut [u8], off: usize, v: i16) {
  buf[off..off + 2].copy_from_slice(&v.to_be_bytes());
}

fn find(ems: &[SubEmission], name: &str) -> Option<TagValue> {
  ems.iter().find(|e| e.name == name).map(|e| e.value.clone())
}

#[test]
fn focus_af_point_hashes() {
  let mut buf = vec![0u8; 0x50];
  buf[0x14] = 4; // FocusModeSetting -> DMF
  buf[0x15] = 10; // AFPointSelected -> Far Right (A700-only value)
  buf[0x19] = 22; // AFPoint -> Center F2.8 (top of the 23-point list)

  let j = parse_camera_info(&buf, Some("DSLR-A700"), true);
  assert_eq!(
    find(&j, "FocusModeSetting"),
    Some(TagValue::Str("DMF".into()))
  );
  assert_eq!(
    find(&j, "AFPointSelected"),
    Some(TagValue::Str("Far Right".into()))
  );
  assert_eq!(
    find(&j, "AFPoint"),
    Some(TagValue::Str("Center F2.8".into()))
  );

  // -n keeps the raw integers.
  let n = parse_camera_info(&buf, Some("DSLR-A700"), false);
  assert_eq!(find(&n, "AFPoint"), Some(TagValue::I64(22)));
}

#[test]
fn af_point_hash_miss_renders_unknown() {
  let mut buf = vec![0u8; 0x50];
  buf[0x15] = 99; // unmapped AFPointSelected
  let j = parse_camera_info(&buf, None, true);
  assert_eq!(
    find(&j, "AFPointSelected"),
    Some(TagValue::Str("Unknown (99)".into()))
  );
}

#[test]
fn af_status_grid_int16s_big_endian() {
  let mut buf = vec![0u8; 0x50];
  put_i16_be(&mut buf, 0x1e, 35); // AFStatusActiveSensor -> Back Focus (+35)
  put_i16_be(&mut buf, 0x20, -93); // AFStatusUpper-left -> Front Focus (-93)
  put_i16_be(&mut buf, 0x4c, 0); // AFStatusCenterF2-8 -> In Focus

  let j = parse_camera_info(&buf, None, true);
  assert_eq!(
    find(&j, "AFStatusActiveSensor"),
    Some(TagValue::Str("Back Focus (+35)".into()))
  );
  assert_eq!(
    find(&j, "AFStatusUpper-left"),
    Some(TagValue::Str("Front Focus (-93)".into()))
  );
  assert_eq!(
    find(&j, "AFStatusCenterF2-8"),
    Some(TagValue::Str("In Focus".into()))
  );
  // -n keeps the raw signed integer (big-endian decode).
  let n = parse_camera_info(&buf, None, false);
  assert_eq!(find(&n, "AFStatusUpper-left"), Some(TagValue::I64(-93)));
}

#[test]
fn af_micro_adj_trio_a850_a900_only() {
  let mut buf = vec![0u8; 0x132];
  buf[0x130] = 30; // AFMicroAdjValue -> 30 - 20 = 10
  buf[0x131] = 0x83; // Mask 0x80 -> 1 -> On; Mask 0x7f -> 3

  // A900 -> the trio is emitted.
  let j = parse_camera_info(&buf, Some("DSLR-A900"), true);
  assert_eq!(find(&j, "AFMicroAdjValue"), Some(TagValue::I64(10)));
  assert_eq!(find(&j, "AFMicroAdjMode"), Some(TagValue::Str("On".into())));
  assert_eq!(
    find(&j, "AFMicroAdjRegisteredLenses"),
    Some(TagValue::I64(3))
  );

  // A700 (same bytes) -> the A850/A900-only trio is suppressed by `Condition`.
  let a700 = parse_camera_info(&buf, Some("DSLR-A700"), true);
  assert!(find(&a700, "AFMicroAdjValue").is_none());
  assert!(find(&a700, "AFMicroAdjMode").is_none());
  assert!(find(&a700, "AFMicroAdjRegisteredLenses").is_none());
}

#[test]
fn af_micro_adj_mode_off() {
  let mut buf = vec![0u8; 0x132];
  buf[0x131] = 0x00; // Mask 0x80 -> 0 -> Off
  let j = parse_camera_info(&buf, Some("DSLR-A850"), true);
  assert_eq!(
    find(&j, "AFMicroAdjMode"),
    Some(TagValue::Str("Off".into()))
  );
}

#[test]
fn lens_spec_offset0_emitted_with_int16_byteswap() {
  // The A700/A850/A900 store LensSpec (0x00, undef[8]) with a per-int16 byte
  // swap (`ConvLensSpec(pack('v*', unpack('n*', $val)))`, Sony.pm:2749-2755).
  // The on-disk bytes below reorder to `40 00 18 00 55 35 56 40`, which the
  // SHARED ConvLensSpec/PrintLensSpec chain decodes to "PZ 18-55mm F3.5-5.6
  // Reflex" (verified vs bundled ExifTool 13.59). Emitted even when NO Main
  // 0xb02a leaf accompanies the block.
  let buf = [0x00u8, 0x40, 0x00, 0x18, 0x35, 0x55, 0x40, 0x56];

  let j = parse_camera_info(&buf, Some("DSLR-A900"), true);
  assert_eq!(
    find(&j, "LensSpec"),
    Some(TagValue::Str("PZ 18-55mm F3.5-5.6 Reflex".into()))
  );
  // -n is the ConvLensSpec value string (post-byteswap).
  let n = parse_camera_info(&buf, Some("DSLR-A900"), false);
  assert_eq!(
    find(&n, "LensSpec"),
    Some(TagValue::Str("40 18 55 3.5 5.6 40".into()))
  );
}

#[test]
fn lens_spec_offset0_bounded_under_8_bytes() {
  // Per-field availability: a block shorter than the undef[8] LensSpec emits no
  // LensSpec leaf (no out-of-bounds read).
  let buf = [0x00u8, 0x40, 0x00, 0x18, 0x35, 0x55, 0x40]; // 7 bytes
  let j = parse_camera_info(&buf, Some("DSLR-A900"), true);
  assert!(find(&j, "LensSpec").is_none());
}

#[test]
fn out_of_range_leaves_are_skipped() {
  // A truncated block emits only the in-range leaves (per-field availability).
  let buf = vec![0u8; 0x20];
  let j = parse_camera_info(&buf, Some("DSLR-A900"), true);
  assert!(find(&j, "FocusModeSetting").is_some()); // 0x14 in range
  assert!(find(&j, "AFStatusActiveSensor").is_some()); // 0x1e..0x20 in range
  assert!(find(&j, "AFStatusLeft").is_none()); // 0x22 out of range
  assert!(find(&j, "AFMicroAdjValue").is_none()); // 0x130 out of range
}
