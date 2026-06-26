// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Sony::CameraInfo2` (`0x0010`, A200-A390): the 9-point AF leaves +
//! `%afStatusInfo` grid render byte-exact, and `FocusModeSetting` carries the
//! extra `4 => DMF` value distinguishing it from `CameraInfo3`'s `FocusMode`.

use super::*;
use crate::value::TagValue;

fn put_i16(buf: &mut [u8], off: usize, v: i16) {
  buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn find(ems: &[SubEmission], name: &str) -> Option<TagValue> {
  ems.iter().find(|e| e.name == name).map(|e| e.value.clone())
}

#[test]
fn af_point_and_focus_mode_setting() {
  let mut buf = vec![0u8; 0x40];
  buf[0x14] = 0; // AFPointSelected -> Auto
  buf[0x15] = 4; // FocusModeSetting -> DMF (CameraInfo2-only value)
  buf[0x18] = 4; // AFPoint -> Center Vertical

  let j = parse_camera_info2(&buf, true);
  assert_eq!(
    find(&j, "AFPointSelected"),
    Some(TagValue::Str("Auto".into()))
  );
  assert_eq!(
    find(&j, "FocusModeSetting"),
    Some(TagValue::Str("DMF".into()))
  );
  assert_eq!(
    find(&j, "AFPoint"),
    Some(TagValue::Str("Center Vertical".into()))
  );

  let n = parse_camera_info2(&buf, false);
  assert_eq!(find(&n, "FocusModeSetting"), Some(TagValue::I64(4)));
}

#[test]
fn af_status_grid_int16s_little_endian() {
  let mut buf = vec![0u8; 0x40];
  put_i16(&mut buf, 0x1b, -346); // AFStatusActiveSensor
  put_i16(&mut buf, 0x1d, -32768); // AFStatusTop-right -> Out of Focus
  put_i16(&mut buf, 0x31, -362); // AFStatusRight

  let j = parse_camera_info2(&buf, true);
  assert_eq!(
    find(&j, "AFStatusActiveSensor"),
    Some(TagValue::Str("Front Focus (-346)".into()))
  );
  assert_eq!(
    find(&j, "AFStatusTop-right"),
    Some(TagValue::Str("Out of Focus".into()))
  );
  let n = parse_camera_info2(&buf, false);
  assert_eq!(find(&n, "AFStatusRight"), Some(TagValue::I64(-362)));
}

#[test]
fn out_of_range_leaves_are_skipped() {
  // A truncated block emits only the in-range leaves (per-field availability).
  let buf = vec![0u8; 0x16];
  let j = parse_camera_info2(&buf, true);
  assert!(find(&j, "AFPointSelected").is_some()); // 0x14 in range
  assert!(find(&j, "AFPoint").is_none()); // 0x18 out of range
  assert!(find(&j, "AFStatusRight").is_none()); // 0x31 out of range
}
