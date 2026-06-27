// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::ShotInfo` (`Sony.pm:6113-6177`) — the `0x3000`
//! Main-table SubDirectory (DSC / Xperia bodies), a plain (un-enciphered)
//! `ProcessBinaryData` block. `ByteOrder` is little-endian (`# 0x00 - byte order
//! 'II'`), default `int8u` format, so the table keys are byte offsets.
//!
//! The block opens with three `DataMember`s — `FaceInfoOffset` (0x02),
//! `FacesDetected` (0x30) and `FaceInfoLength` (0x32) — plus `MetaVersion`
//! (0x34). Those gate the two `IS_SUBDIR` rows: `FaceInfo1` (`Sony.pm:10246`,
//! face stride 0x20) at byte 0x48 and `FaceInfo2` (`Sony.pm:10295`, face stride
//! 0x25) at byte 0x5e — each emitting `Face<N>Position` (`int16u[4]`: top, left,
//! height, width) IFF `$$self{FacesDetected} >= N` (the per-face `RawConv`).
//!
//! Per the `ProcessBinaryData` per-field-availability contract a leaf is emitted
//! IFF its byte range is in the block ([[exifast-processbinarydata-per-field]]).

use crate::value::TagValue;
use smol_str::SmolStr;

use super::subtables::{SubEmission, read_u16};

/// Read a little-endian `string[n]` at byte `off`: the bytes up to (not
/// including) the first NUL, decoded lossily (`$val =~ s/\0.*//s`,
/// `ExifTool.pm` string handling). `None` if the full `n`-byte field is out of
/// range (per-field availability).
fn read_string(buf: &[u8], off: usize, n: usize) -> Option<SmolStr> {
  let field = buf.get(off..off.checked_add(n)?)?;
  let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
  // `end <= field.len()`, so `get` is always `Some`; using it (not a slice
  // index) keeps the module's `#![deny(clippy::indexing_slicing)]` satisfied.
  let text = field.get(..end)?;
  Some(SmolStr::new(String::from_utf8_lossy(text)))
}

/// `int16u[4]` `Face<N>Position` value (`top, left, height, width`): the four
/// little-endian `int16u` rendered as ExifTool's default space-joined integer
/// list. `None` if the 8-byte field is out of range.
fn read_face_position(buf: &[u8], off: usize) -> Option<TagValue> {
  let a = read_u16(buf, off)?;
  let b = read_u16(buf, off.checked_add(2)?)?;
  let c = read_u16(buf, off.checked_add(4)?)?;
  let d = read_u16(buf, off.checked_add(6)?)?;
  Some(TagValue::Str(SmolStr::new(std::format!("{a} {b} {c} {d}"))))
}

/// Push the `Face1Position..Face8Position` leaves of a `FaceInfo` SubDirectory
/// whose block starts at byte `start` with per-face byte `stride`. `Face<N>` is
/// emitted IFF `faces_detected >= N` (the per-face `RawConv`) AND its 8-byte
/// field is in range.
fn push_face_info(
  buf: &[u8],
  start: usize,
  stride: usize,
  faces_detected: u16,
  out: &mut Vec<SubEmission>,
) {
  const NAMES: [&str; 8] = [
    "Face1Position",
    "Face2Position",
    "Face3Position",
    "Face4Position",
    "Face5Position",
    "Face6Position",
    "Face7Position",
    "Face8Position",
  ];
  for (i, name) in NAMES.iter().enumerate() {
    // `RawConv => '$$self{FacesDetected} < N ? undef : $val'` (N = i + 1).
    if u32::from(faces_detected) < (i as u32 + 1) {
      continue;
    }
    let Some(off) = start.checked_add(i * stride) else {
      break;
    };
    if let Some(v) = read_face_position(buf, off) {
      out.push(SubEmission::new(name, v));
    }
  }
}

/// Walk the `ShotInfo` block and emit its leaves (`Priority => 1`, the table
/// default).
///
/// `buf` is the verbatim (un-enciphered) `0x3000` block; `print_conv` selects
/// `-j` vs `-n` (the only PrintConv here, `SonyDateTime`'s `ConvertDateTime`, is
/// identity under default options, so the two render identically).
#[must_use]
pub fn parse_shot_info(buf: &[u8], _print_conv: bool) -> Vec<SubEmission> {
  let mut out = std::vec::Vec::new();

  // DataMembers (read first; gate the FaceInfo SubDirectories below).
  let face_info_offset = read_u16(buf, 0x02);
  let faces_detected = read_u16(buf, 0x30);
  let face_info_length = read_u16(buf, 0x32);

  // 0x02 FaceInfoOffset — int16u DataMember, emitted as a plain leaf.
  if let Some(v) = face_info_offset {
    out.push(SubEmission::new(
      "FaceInfoOffset",
      TagValue::I64(i64::from(v)),
    ));
  }
  // 0x06 SonyDateTime — string[20], PrintConv ConvertDateTime (identity).
  if let Some(s) = read_string(buf, 0x06, 20) {
    out.push(SubEmission::new("SonyDateTime", TagValue::Str(s)));
  }
  // 0x1a SonyImageHeight / 0x1c SonyImageWidth — int16u.
  if let Some(v) = read_u16(buf, 0x1a) {
    out.push(SubEmission::new(
      "SonyImageHeight",
      TagValue::I64(i64::from(v)),
    ));
  }
  if let Some(v) = read_u16(buf, 0x1c) {
    out.push(SubEmission::new(
      "SonyImageWidth",
      TagValue::I64(i64::from(v)),
    ));
  }
  // 0x30 FacesDetected / 0x32 FaceInfoLength — int16u DataMembers, emitted.
  if let Some(v) = faces_detected {
    out.push(SubEmission::new(
      "FacesDetected",
      TagValue::I64(i64::from(v)),
    ));
  }
  if let Some(v) = face_info_length {
    out.push(SubEmission::new(
      "FaceInfoLength",
      TagValue::I64(i64::from(v)),
    ));
  }
  // 0x34 MetaVersion — string[16] DataMember.
  if let Some(s) = read_string(buf, 0x34, 16) {
    out.push(SubEmission::new("MetaVersion", TagValue::Str(s)));
  }

  // 0x48 FaceInfo1 — `FacesDetected and FaceInfoOffset == 0x48 and
  // FaceInfoLength == 0x20` (Sony.pm:6159-6166), face stride 0x20.
  if faces_detected.is_some_and(|f| f != 0)
    && face_info_offset == Some(0x48)
    && face_info_length == Some(0x20)
  {
    push_face_info(buf, 0x48, 0x20, faces_detected.unwrap_or(0), &mut out);
  }
  // 0x5e FaceInfo2 — `FacesDetected and FaceInfoOffset == 0x5e and
  // FaceInfoLength == 0x25` (Sony.pm:6168-6175), face stride 0x25.
  if faces_detected.is_some_and(|f| f != 0)
    && face_info_offset == Some(0x5e)
    && face_info_length == Some(0x25)
  {
    push_face_info(buf, 0x5e, 0x25, faces_detected.unwrap_or(0), &mut out);
  }

  out
}

#[cfg(test)]
// The module-level `#![deny(clippy::indexing_slicing)]` is relaxed for the test
// module, which indexes fixed-layout byte buffers directly (an out-of-range
// index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
#[path = "shotinfo_tests.rs"]
mod tests;
