// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Sony::ShotInfo` (`0x3000`): the scalar DataMembers / image dims / date /
//! version render byte-exact, and the `FaceInfo1`/`FaceInfo2` SubDirectories
//! descend only when their `FaceInfoOffset`/`FaceInfoLength`/`FacesDetected`
//! `Condition` holds — emitting `Face<N>Position` for `N <= FacesDetected`
//! (`Sony.pm:6113-6177`, `:10246`, `:10295`).

use super::*;
use crate::value::TagValue;

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
  buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_str(buf: &mut [u8], off: usize, s: &str) {
  buf[off..off + s.len()].copy_from_slice(s.as_bytes());
}

fn find(ems: &[SubEmission], name: &str) -> Option<TagValue> {
  ems.iter().find(|e| e.name == name).map(|e| e.value.clone())
}

/// A 0x80-byte block wired for `FaceInfo1` (offset 0x48, length 0x20) with two
/// detected faces.
fn faceinfo1_block() -> Vec<u8> {
  let mut buf = vec![0u8; 0x80];
  put_u16(&mut buf, 0x02, 0x48); // FaceInfoOffset
  put_str(&mut buf, 0x06, "2010:08:15 12:34:56"); // SonyDateTime (19 chars + NUL)
  put_u16(&mut buf, 0x1a, 1080); // SonyImageHeight
  put_u16(&mut buf, 0x1c, 1920); // SonyImageWidth
  put_u16(&mut buf, 0x30, 2); // FacesDetected
  put_u16(&mut buf, 0x32, 0x20); // FaceInfoLength
  put_str(&mut buf, 0x34, "DC7303320222000"); // MetaVersion (15 chars + NUL)
  // Face1Position @0x48, Face2Position @0x68 (stride 0x20), int16u[4].
  for (i, v) in [100u16, 200, 50, 50].iter().enumerate() {
    put_u16(&mut buf, 0x48 + i * 2, *v);
  }
  for (i, v) in [10u16, 20, 30, 40].iter().enumerate() {
    put_u16(&mut buf, 0x68 + i * 2, *v);
  }
  buf
}

#[test]
fn scalar_leaves_and_datamembers() {
  let buf = faceinfo1_block();
  let j = parse_shot_info(&buf, true);
  assert_eq!(find(&j, "FaceInfoOffset"), Some(TagValue::I64(0x48)));
  assert_eq!(
    find(&j, "SonyDateTime"),
    Some(TagValue::Str("2010:08:15 12:34:56".into()))
  );
  assert_eq!(find(&j, "SonyImageHeight"), Some(TagValue::I64(1080)));
  assert_eq!(find(&j, "SonyImageWidth"), Some(TagValue::I64(1920)));
  assert_eq!(find(&j, "FacesDetected"), Some(TagValue::I64(2)));
  assert_eq!(find(&j, "FaceInfoLength"), Some(TagValue::I64(0x20)));
  assert_eq!(
    find(&j, "MetaVersion"),
    Some(TagValue::Str("DC7303320222000".into()))
  );
}

#[test]
fn faceinfo1_descends_and_honours_faces_detected() {
  let buf = faceinfo1_block();
  let j = parse_shot_info(&buf, true);
  // 2 faces detected -> Face1/Face2 only (int16u[4], space-joined).
  assert_eq!(
    find(&j, "Face1Position"),
    Some(TagValue::Str("100 200 50 50".into()))
  );
  assert_eq!(
    find(&j, "Face2Position"),
    Some(TagValue::Str("10 20 30 40".into()))
  );
  assert!(find(&j, "Face3Position").is_none()); // FacesDetected(2) < 3
}

#[test]
fn faceinfo2_descends_with_stride_0x25() {
  let mut buf = vec![0u8; 0x90];
  put_u16(&mut buf, 0x02, 0x5e); // FaceInfoOffset
  put_u16(&mut buf, 0x30, 1); // FacesDetected
  put_u16(&mut buf, 0x32, 0x25); // FaceInfoLength
  for (i, v) in [11u16, 22, 33, 44].iter().enumerate() {
    put_u16(&mut buf, 0x5e + i * 2, *v); // Face1Position @0x5e
  }
  let j = parse_shot_info(&buf, true);
  assert_eq!(
    find(&j, "Face1Position"),
    Some(TagValue::Str("11 22 33 44".into()))
  );
  assert!(find(&j, "Face2Position").is_none()); // FacesDetected(1) < 2
}

#[test]
fn faceinfo_not_descended_when_condition_fails() {
  // FaceInfoOffset 0x48 but FaceInfoLength 0x25 (FaceInfo1 wants 0x20) -> no
  // FaceInfo1; FaceInfo2 wants offset 0x5e -> no FaceInfo2 either.
  let mut buf = faceinfo1_block();
  put_u16(&mut buf, 0x32, 0x25);
  let j = parse_shot_info(&buf, true);
  assert!(find(&j, "Face1Position").is_none());
  // The scalar leaves are unaffected.
  assert_eq!(find(&j, "FacesDetected"), Some(TagValue::I64(2)));
}

#[test]
fn zero_faces_detected_suppresses_face_subdir() {
  let mut buf = faceinfo1_block();
  put_u16(&mut buf, 0x30, 0); // FacesDetected = 0
  let j = parse_shot_info(&buf, true);
  assert!(find(&j, "Face1Position").is_none());
}

#[test]
fn out_of_range_leaves_are_skipped() {
  // A short block (0x1c bytes) emits only the in-range scalar leaves.
  let mut buf = vec![0u8; 0x1c];
  put_u16(&mut buf, 0x02, 5);
  put_u16(&mut buf, 0x1a, 720);
  let j = parse_shot_info(&buf, true);
  assert_eq!(find(&j, "FaceInfoOffset"), Some(TagValue::I64(5)));
  assert_eq!(find(&j, "SonyImageHeight"), Some(TagValue::I64(720))); // 0x1a..0x1c in range
  assert!(find(&j, "SonyImageWidth").is_none()); // 0x1c..0x1e out of range
  assert!(find(&j, "FacesDetected").is_none()); // 0x30 out of range
}
