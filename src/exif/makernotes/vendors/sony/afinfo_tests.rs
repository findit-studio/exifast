// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Sony::AFInfo` (`0x940e`, SLT/HV/ILCA): the `AFType` DataMember selects the
//! SLT (`%afPoint15`/`%afPoint19` + `AFStatus15`/`AFStatus19`) vs ILCA
//! (`%afPoints79_940e` + `%afPoints79` bitmask + `AFStatus79`) decoding paths;
//! every leaf is `Priority => 0`. Crafted (already-deciphered) buffers exercise
//! both paths byte-exact vs `Sony.pm:9453-9748`.

use super::*;
use crate::value::TagValue;

fn put_i16(buf: &mut [u8], off: usize, v: i16) {
  buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
  buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn get<'a>(ems: &'a [SubEmission], name: &str) -> Option<&'a SubEmission> {
  ems.iter().find(|e| e.name == name)
}

fn find(ems: &[SubEmission], name: &str) -> Option<TagValue> {
  get(ems, name).map(|e| e.value.clone())
}

#[test]
fn af_type_hash() {
  let mut buf = vec![0u8; 0x10];
  for (raw, want) in [(1u8, "15-point"), (2, "19-point"), (3, "79-point")] {
    buf[0x02] = raw;
    let j = parse_af_info(&buf, Some("SLT-A77V"), true);
    assert_eq!(find(&j, "AFType"), Some(TagValue::Str(want.into())));
  }
  // Unmapped (0 = n.a.) -> "Unknown (0)".
  buf[0x02] = 0;
  let j = parse_af_info(&buf, Some("SLT-A77V"), true);
  assert_eq!(
    find(&j, "AFType"),
    Some(TagValue::Str("Unknown (0)".into()))
  );
}

#[test]
fn slt_aftype1_15point_path() {
  let mut buf = vec![0u8; 0x190];
  buf[0x02] = 1; // AFType -> 15-point
  put_i16(&mut buf, 0x04, 35); // AFStatusActiveSensor -> Back Focus (+35)
  buf[0x07] = 6; // AFPoint -> Center (horizontal)
  buf[0x08] = 255; // AFPointInFocus -> (none)
  buf[0x09] = 30; // AFPointAtShutterRelease -> (out of focus)
  buf[0x0a] = 2; // AFAreaMode -> Local
  buf[0x0b] = 4; // FocusMode -> AF-A
  put_i16(&mut buf, 0x11, -32768); // AFStatus15[0] AFStatusUpper-left -> Out of Focus
  put_u32(&mut buf, 0x16e, 0x0000_0001); // AFPointsUsed bit 0 -> Center
  buf[0x17d] = 0xfb; // AFMicroAdj int8s -> -5
  buf[0x17e] = 3; // ExposureProgram -> Manual

  let j = parse_af_info(&buf, Some("SLT-A77V"), true);
  assert_eq!(
    find(&j, "AFStatusActiveSensor"),
    Some(TagValue::Str("Back Focus (+35)".into()))
  );
  assert_eq!(
    find(&j, "AFPoint"),
    Some(TagValue::Str("Center (horizontal)".into()))
  );
  assert_eq!(
    find(&j, "AFPointInFocus"),
    Some(TagValue::Str("(none)".into()))
  );
  assert_eq!(
    find(&j, "AFPointAtShutterRelease"),
    Some(TagValue::Str("(out of focus)".into()))
  );
  assert_eq!(find(&j, "AFAreaMode"), Some(TagValue::Str("Local".into())));
  assert_eq!(find(&j, "FocusMode"), Some(TagValue::Str("AF-A".into())));
  assert_eq!(
    find(&j, "AFStatusUpper-left"),
    Some(TagValue::Str("Out of Focus".into()))
  );
  assert_eq!(
    find(&j, "AFPointsUsed"),
    Some(TagValue::Str("Center".into()))
  );
  assert_eq!(find(&j, "AFMicroAdj"), Some(TagValue::I64(-5)));
  assert_eq!(
    find(&j, "ExposureProgram"),
    Some(TagValue::Str("Manual".into()))
  );
  // 19-point-only leaves never appear on a 15-point body.
  assert!(find(&j, "AFStatusUpperFarLeft").is_none());
  // Every AFInfo leaf is Priority => 0.
  assert!(j.iter().all(|e| e.priority == 0));

  // -n keeps raw ints (AFPointsUsed int32u, AFMicroAdj int8s).
  let n = parse_af_info(&buf, Some("SLT-A77V"), false);
  assert_eq!(find(&n, "AFPointsUsed"), Some(TagValue::I64(1)));
  assert_eq!(find(&n, "AFMicroAdj"), Some(TagValue::I64(-5)));
  assert_eq!(find(&n, "AFPoint"), Some(TagValue::I64(6)));
}

#[test]
fn slt_aftype2_19point_path() {
  let mut buf = vec![0u8; 0x60];
  buf[0x02] = 2; // AFType -> 19-point
  buf[0x07] = 0; // AFPoint -> Upper Far Left (%afPoint19)
  put_i16(&mut buf, 0x11, -32768); // AFStatus19[0] AFStatusUpperFarLeft -> Out of Focus
  put_i16(&mut buf, 0x11 + 29 * 2, 0); // AFStatus19[29] AFStatusLower-rightVertical -> In Focus

  let j = parse_af_info(&buf, Some("SLT-A99V"), true);
  assert_eq!(
    find(&j, "AFPoint"),
    Some(TagValue::Str("Upper Far Left".into()))
  );
  assert_eq!(
    find(&j, "AFStatusUpperFarLeft"),
    Some(TagValue::Str("Out of Focus".into()))
  );
  assert_eq!(
    find(&j, "AFStatusLower-rightVertical"),
    Some(TagValue::Str("In Focus".into()))
  );
  // 15-point-only AFStatus names do not appear.
  assert!(find(&j, "AFStatusUpper-middle").is_some()); // 19-point also has this (index 16)
  assert!(find(&j, "AFStatusLower-left").is_none()); // 15-point-only name
}

#[test]
fn ilca_aftype3_79point_path() {
  let mut buf = vec![0u8; 0x140];
  buf[0x02] = 3; // AFType -> 79-point
  buf[0x05] = 3; // FocusMode -> AF-C (ILCA hash)
  buf[0x10] = 0x01; // AFPointsUsed int8u[10] bit 0 -> A5 (%afPoints79)
  buf[0x37] = 54; // AFPoint -> E6 Center (%afPoints79_940e)
  buf[0x38] = 255; // AFPointInFocus -> (none)
  buf[0x39] = 95; // AFPointAtShutterRelease -> (none)
  buf[0x3a] = 2; // AFAreaMode -> Flexible Spot (ILCA hash)
  put_i16(&mut buf, 0x3b, -50); // AFStatusActiveSensor -> Front Focus (-50)
  buf[0x43] = 4; // ExposureProgram -> Auto
  buf[0x50] = 3; // AFMicroAdj int8s -> 3
  put_i16(&mut buf, 0x7d, -32768); // AFStatus79[0] AFStatus_00_B4 -> Out of Focus

  let j = parse_af_info(&buf, Some("ILCA-77M2"), true);
  assert_eq!(find(&j, "AFType"), Some(TagValue::Str("79-point".into())));
  assert_eq!(find(&j, "FocusMode"), Some(TagValue::Str("AF-C".into())));
  assert_eq!(find(&j, "AFPointsUsed"), Some(TagValue::Str("A5".into())));
  assert_eq!(find(&j, "AFPoint"), Some(TagValue::Str("E6 Center".into())));
  assert_eq!(
    find(&j, "AFPointInFocus"),
    Some(TagValue::Str("(none)".into()))
  );
  assert_eq!(
    find(&j, "AFPointAtShutterRelease"),
    Some(TagValue::Str("(none)".into()))
  );
  assert_eq!(
    find(&j, "AFAreaMode"),
    Some(TagValue::Str("Flexible Spot".into()))
  );
  assert_eq!(
    find(&j, "AFStatusActiveSensor"),
    Some(TagValue::Str("Front Focus (-50)".into()))
  );
  assert_eq!(
    find(&j, "ExposureProgram"),
    Some(TagValue::Str("Auto".into()))
  );
  assert_eq!(find(&j, "AFMicroAdj"), Some(TagValue::I64(3)));
  assert_eq!(
    find(&j, "AFStatus_00_B4"),
    Some(TagValue::Str("Out of Focus".into()))
  );
  assert_eq!(
    find(&j, "AFStatus_94_E6_Center_F2-8"),
    Some(TagValue::Str("In Focus".into())) // default 0 -> In Focus
  );
  assert!(j.iter().all(|e| e.priority == 0));

  // -n: AFPointsUsed renders the space-joined int8u[10] list.
  let n = parse_af_info(&buf, Some("ILCA-77M2"), false);
  assert_eq!(
    find(&n, "AFPointsUsed"),
    Some(TagValue::Str("1 0 0 0 0 0 0 0 0 0".into()))
  );
}

#[test]
fn slt_and_ilca_paths_are_mutually_exclusive() {
  // An ILCA buffer wired with SLT-style bytes: the SLT-only leaves must NOT
  // appear (model =~ /^ILCA-/ takes the ILCA path), and vice-versa.
  let mut buf = vec![0u8; 0x140];
  buf[0x02] = 3;
  let ilca = parse_af_info(&buf, Some("ILCA-99M2"), true);
  // SLT-only AFAreaMode value "Local" / FocusMode 0x0b path absent.
  assert!(get(&ilca, "AFStatusUpper-left").is_none()); // SLT AFStatus15 name

  let mut buf2 = vec![0u8; 0x140];
  buf2[0x02] = 3; // AFType 3 but a NON-ILCA model -> SLT path (no 79-point branch)
  let slt = parse_af_info(&buf2, Some("SLT-A77V"), true);
  // AFType 3 on the SLT path: no AFPoint trio (needs AFType 1/2), no AFStatus79.
  assert!(find(&slt, "AFStatus_00_B4").is_none());
  assert!(find(&slt, "AFPoint").is_none());
  // AFType itself is still emitted.
  assert_eq!(find(&slt, "AFType"), Some(TagValue::Str("79-point".into())));
}

#[test]
fn af_points_used_none_when_no_bits_set() {
  let mut buf = vec![0u8; 0x190];
  buf[0x02] = 1;
  put_u32(&mut buf, 0x16e, 0); // no bits -> (none)
  let j = parse_af_info(&buf, Some("SLT-A77V"), true);
  assert_eq!(
    find(&j, "AFPointsUsed"),
    Some(TagValue::Str("(none)".into()))
  );
}

#[test]
fn out_of_range_leaves_are_skipped() {
  // A short block emits only the in-range leaves (per-field availability).
  let mut buf = vec![0u8; 0x08];
  buf[0x02] = 1; // AFType
  buf[0x07] = 6; // AFPoint (in range)
  let j = parse_af_info(&buf, Some("SLT-A77V"), true);
  assert!(find(&j, "AFType").is_some());
  assert!(find(&j, "AFPoint").is_some());
  assert!(find(&j, "AFPointsUsed").is_none()); // 0x16e out of range
  assert!(find(&j, "AFStatusUpper-left").is_none()); // 0x11 out of range
}
