// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::CameraInfo2` (`Sony.pm:2899-2986`) — the `0x0010`
//! Main-table SubDirectory dispatched when `$count == 5506 || 6118`
//! (`Sony.pm:728-734`), a plain (un-enciphered) `ProcessBinaryData` block of
//! camera info for the DSLR-A200/A230/A290/A300/A330/A350/A380/A390.
//!
//! `ByteOrder => 'LittleEndian'`, default `int8u` format. The 9-point AF system
//! is shared with the A200-A390 generation: the `0x1b..0x31` `%afStatusInfo`
//! grid is at OFFSETS + NAMES identical to the `CameraInfo3` 9-point branch, but
//! this is a DISTINCT table (0x15 is `FocusModeSetting` here, with the extra
//! `4 => DMF` value, vs `CameraInfo3`'s `FocusMode`).
//!
//! Per the `ProcessBinaryData` per-field-availability contract each tag is
//! emitted IFF its byte range is in the block
//! ([[exifast-processbinarydata-per-field]]). `0x00 LensSpec` is the SAME
//! `LensSpec` name + value as the Main-IFD `0xb02a` leaf exifast already emits
//! (last-wins dedup keeps that byte-identical value), so it is intentionally NOT
//! re-emitted here.

use super::subtables::{SubEmission, af_status_value, read_i16};

/// `AFPointSelected` (0x14) PrintConv (`Sony.pm:2917-2929`) — the 9-point list.
fn af_point_selected(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Auto",
    1 => "Center",
    2 => "Top",
    3 => "Upper-right",
    4 => "Right",
    5 => "Lower-right",
    6 => "Bottom",
    7 => "Lower-left",
    8 => "Left",
    9 => "Upper-left",
    _ => return None,
  })
}

/// `FocusModeSetting` (0x15) PrintConv (`Sony.pm:2931-2941`) — note the extra
/// `4 => DMF` over `CameraInfo3`'s `FocusMode`.
fn focus_mode_setting(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Manual",
    1 => "AF-S",
    2 => "AF-C",
    3 => "AF-A",
    4 => "DMF",
    _ => return None,
  })
}

/// `AFPoint` (0x18) PrintConv (`Sony.pm:2953-2963`) — the A100-derived 9-point
/// sensor list.
fn af_point(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Top-right",
    1 => "Bottom-right",
    2 => "Bottom",
    3 => "Middle Horizontal",
    4 => "Center Vertical",
    5 => "Top",
    6 => "Top-left",
    7 => "Bottom-left",
    _ => return None,
  })
}

/// Push a simple `int8u` hash-PrintConv leaf at `off`.
fn push_hash(
  buf: &[u8],
  off: usize,
  name: &'static str,
  hit: impl Fn(u8) -> Option<&'static str>,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  if let Some(&raw) = buf.get(off) {
    out.push(SubEmission::new(
      name,
      super::hash_print_value(raw, hit(raw), print_conv),
    ));
  }
}

/// Push a `%afStatusInfo` `int16s` (little-endian) leaf at `off`.
fn push_af_status(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  if let Some(v) = read_i16(buf, off) {
    out.push(SubEmission::new(name, af_status_value(v, print_conv)));
  }
}

/// Walk the `CameraInfo2` block and emit the AF/focus leaves (`Priority => 1`,
/// the table default).
///
/// `buf` is the verbatim (un-enciphered) `0x0010` block; `print_conv` selects
/// `-j` vs `-n`. The table is model-unconditional for the DSLR-A2xx/A3xx bodies
/// (no per-leaf `Condition`), so each leaf is emitted purely on byte
/// availability.
#[must_use]
pub fn parse_camera_info2(buf: &[u8], print_conv: bool) -> Vec<SubEmission> {
  let mut out = std::vec::Vec::new();

  push_hash(
    buf,
    0x14,
    "AFPointSelected",
    af_point_selected,
    print_conv,
    &mut out,
  );
  push_hash(
    buf,
    0x15,
    "FocusModeSetting",
    focus_mode_setting,
    print_conv,
    &mut out,
  );
  push_hash(buf, 0x18, "AFPoint", af_point, print_conv, &mut out);

  // 0x1b..0x31 `%afStatusInfo` grid (Sony.pm:2966-2980) — `int16s`, identical
  // offsets/names to the `CameraInfo3` 9-point branch.
  push_af_status(buf, 0x1b, "AFStatusActiveSensor", print_conv, &mut out);
  push_af_status(buf, 0x1d, "AFStatusTop-right", print_conv, &mut out);
  push_af_status(buf, 0x1f, "AFStatusBottom-right", print_conv, &mut out);
  push_af_status(buf, 0x21, "AFStatusBottom", print_conv, &mut out);
  push_af_status(buf, 0x23, "AFStatusMiddleHorizontal", print_conv, &mut out);
  push_af_status(buf, 0x25, "AFStatusCenterVertical", print_conv, &mut out);
  push_af_status(buf, 0x27, "AFStatusTop", print_conv, &mut out);
  push_af_status(buf, 0x29, "AFStatusTop-left", print_conv, &mut out);
  push_af_status(buf, 0x2b, "AFStatusBottom-left", print_conv, &mut out);
  push_af_status(buf, 0x2d, "AFStatusLeft", print_conv, &mut out);
  push_af_status(buf, 0x2f, "AFStatusCenterHorizontal", print_conv, &mut out);
  push_af_status(buf, 0x31, "AFStatusRight", print_conv, &mut out);

  out
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
#[path = "camerainfo2_tests.rs"]
mod tests;
