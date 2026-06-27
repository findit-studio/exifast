// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::CameraInfo` (`Sony.pm:2746-2896`) — the BASE `0x0010`
//! Main-table SubDirectory dispatched when `$count == 368 || 5478`
//! (`Sony.pm:720-726`), a plain (un-enciphered) `ProcessBinaryData` block of
//! camera info for the DSLR-A700 (368) and A850/A900 (5478).
//!
//! `ByteOrder => 'BigEndian'`, default `int8u` format — so UNLIKE the
//! little-endian `CameraInfo2`/`CameraInfo3` the inline `%afStatusInfo` `int16s`
//! grid reads BIG-endian (via [`super::subtables::read_i16_be`]). The A700/A850/
//! A900 have a 23-sensor + F2.8 AF layout, so this is a DISTINCT table from the
//! 9-point `CameraInfo2` (different `AFPointSelected`/`AFPoint` lists, 24
//! `AFStatus*` leaves vs 12).
//!
//! Per the `ProcessBinaryData` per-field-availability contract each tag is
//! emitted IFF its byte range is in the block
//! ([[exifast-processbinarydata-per-field]]) AND its model `Condition` holds
//! (the `AFMicroAdj*` trio is A850/A900-only). `0x00 LensSpec` is decoded by the
//! SAME `ConvLensSpec`/`PrintLensSpec` chain as the Main-IFD `0xb02a` leaf, but
//! the A700/A850/A900 use a DIFFERENT int16 byte ordering: the ValueConv is
//! `ConvLensSpec(pack('v*', unpack('n*', $val)))` (`Sony.pm:2749-2755`) — each
//! of the 4 `undef[8]` int16 words is read big-endian and re-packed
//! little-endian (a per-pair byte swap) before the shared chain. It IS emitted
//! here: the canonical value usually matches the Main `0xb02a` leaf (which wins
//! the last-wins dedup when present), but a body may carry this CameraInfo copy
//! WITHOUT a Main `0xb02a` leaf, where ExifTool still surfaces LensSpec.

use crate::exif::ifd::RawValue;
use crate::value::TagValue;

use super::subtables::{SubEmission, af_status_value, read_i16_be};

/// `FocusModeSetting` (0x14) PrintConv (`Sony.pm:2768-2774`) — note the extra
/// `4 => DMF` (shared shape with `CameraInfo2`'s 0x15).
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

/// `AFPointSelected` (0x15) PrintConv (`Sony.pm:2779-2792`) — the A700/A850/A900
/// 9-direction list PLUS `10 => Far Right` / `11 => Far Left` (A700 only).
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
    10 => "Far Right",
    11 => "Far Left",
    _ => return None,
  })
}

/// `AFPoint` (0x19) PrintConv (`Sony.pm:2821-2846`) — the active AF sensor for
/// the A700/A850/A900 23-point + F2.8 layout.
fn af_point(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Upper-left",
    1 => "Left",
    2 => "Lower-left",
    3 => "Far Left",
    4 => "Bottom Assist-left",
    5 => "Bottom",
    6 => "Bottom Assist-right",
    7 => "Center (7)",
    8 => "Center (horizontal)",
    9 => "Center (9)",
    10 => "Center (10)",
    11 => "Center (11)",
    12 => "Center (12)",
    13 => "Center (vertical)",
    14 => "Center (14)",
    15 => "Top Assist-left",
    16 => "Top",
    17 => "Top Assist-right",
    18 => "Far Right",
    19 => "Upper-right",
    20 => "Right",
    21 => "Lower-right",
    22 => "Center F2.8",
    _ => return None,
  })
}

/// The 24 `%afStatusInfo` `int16s` leaves at OFFSETS `0x1e..=0x4c` (step 2),
/// in table order (`Sony.pm:2850-2873`).
const AF_STATUS_NAMES: [&str; 24] = [
  "AFStatusActiveSensor",       // 0x1e
  "AFStatusUpper-left",         // 0x20
  "AFStatusLeft",               // 0x22
  "AFStatusLower-left",         // 0x24
  "AFStatusFarLeft",            // 0x26
  "AFStatusBottomAssist-left",  // 0x28
  "AFStatusBottom",             // 0x2a
  "AFStatusBottomAssist-right", // 0x2c
  "AFStatusCenter-7",           // 0x2e
  "AFStatusCenter-horizontal",  // 0x30
  "AFStatusCenter-9",           // 0x32
  "AFStatusCenter-10",          // 0x34
  "AFStatusCenter-11",          // 0x36
  "AFStatusCenter-12",          // 0x38
  "AFStatusCenter-vertical",    // 0x3a
  "AFStatusCenter-14",          // 0x3c
  "AFStatusTopAssist-left",     // 0x3e
  "AFStatusTop",                // 0x40
  "AFStatusTopAssist-right",    // 0x42
  "AFStatusFarRight",           // 0x44
  "AFStatusUpper-right",        // 0x46
  "AFStatusRight",              // 0x48
  "AFStatusLower-right",        // 0x4a
  "AFStatusCenterF2-8",         // 0x4c
];

/// `$$self{Model} =~ /^DSLR-A(850|900)\b/` — the `AFMicroAdj*` trio condition
/// (`Sony.pm:2876`/`:2882`/`:2892`); the A700 (368-byte block) never matches.
fn model_is_a850_900(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  for tail in ["DSLR-A850", "DSLR-A900"] {
    if let Some(rest) = m.strip_prefix(tail) {
      // The prefix ends in a digit (word char), so `\b` requires the NEXT char
      // to be a non-word char (or end-of-string).
      if rest
        .chars()
        .next()
        .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'))
      {
        return true;
      }
    }
  }
  false
}

/// Push a simple `int8u` hash-PrintConv leaf at byte `off`.
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

/// Walk the base `CameraInfo` block and emit the AF/focus leaves (`Priority => 1`,
/// the table default).
///
/// `buf` is the verbatim (un-enciphered) `0x0010` block; `model` is
/// `$$self{Model}` (gates the A850/A900-only `AFMicroAdj*` trio); `print_conv`
/// selects `-j` vs `-n`.
#[must_use]
pub fn parse_camera_info(buf: &[u8], model: Option<&str>, print_conv: bool) -> Vec<SubEmission> {
  let mut out = std::vec::Vec::new();

  // 0x00 LensSpec (`Sony.pm:2749-2755`) — `Format => 'undef[8]'`. The
  // A700/A850/A900 store the LensSpec with a DIFFERENT int16 byte ordering than
  // the Main `0xb02a` leaf: the ValueConv is
  // `ConvLensSpec(pack('v*', unpack('n*', $val)))`, i.e. each of the 4 int16
  // words is read big-endian and re-packed little-endian (a per-pair byte swap
  // `b0b1b2b3b4b5b6b7` -> `b1b0b3b2b5b4b7b6`) before the SAME
  // `ConvLensSpec`/`PrintLensSpec` chain the Main `0xb02a` leaf uses. Emitted
  // IFF the 8-byte range is in the block (per-field availability).
  if let Some(&[b0, b1, b2, b3, b4, b5, b6, b7]) = buf.get(0x00..0x08) {
    let reordered = RawValue::Bytes(std::vec![b1, b0, b3, b2, b5, b4, b7, b6]);
    out.push(SubEmission::new(
      "LensSpec",
      super::SonyPrintConv::LensSpec.apply(&reordered, print_conv),
    ));
  }

  push_hash(
    buf,
    0x14,
    "FocusModeSetting",
    focus_mode_setting,
    print_conv,
    &mut out,
  );
  push_hash(
    buf,
    0x15,
    "AFPointSelected",
    af_point_selected,
    print_conv,
    &mut out,
  );
  push_hash(buf, 0x19, "AFPoint", af_point, print_conv, &mut out);

  // 0x1e..=0x4c `%afStatusInfo` grid (Sony.pm:2850-2873) — `int16s`, BIG-endian.
  for (i, name) in AF_STATUS_NAMES.iter().enumerate() {
    let off = 0x1e + i * 2;
    if let Some(v) = read_i16_be(buf, off) {
      out.push(SubEmission::new(name, af_status_value(v, print_conv)));
    }
  }

  // The A850/A900-only `AFMicroAdj*` trio (Sony.pm:2874-2894).
  if model_is_a850_900(model) {
    // 0x130 AFMicroAdjValue — int8u, `ValueConv => '$val - 20'` (no PrintConv),
    // so `-j` and `-n` both render the signed integer `$val - 20`.
    if let Some(&raw) = buf.get(0x130) {
      out.push(SubEmission::new(
        "AFMicroAdjValue",
        TagValue::I64(i64::from(raw) - 20),
      ));
    }
    // 0x131 AFMicroAdjMode — `Mask => 0x80` ⇒ `($val & 0x80) >> 7`, PrintConv
    // `{0 => Off, 1 => On}`.
    if let Some(&raw) = buf.get(0x131) {
      let masked = (raw & 0x80) >> 7;
      let hit = match masked {
        0 => Some("Off"),
        1 => Some("On"),
        _ => None,
      };
      out.push(SubEmission::new(
        "AFMicroAdjMode",
        super::hash_print_value(masked, hit, print_conv),
      ));
    }
    // 0x131.1 AFMicroAdjRegisteredLenses — `Mask => 0x7f` ⇒ `$val & 0x7f` (no
    // PrintConv) ⇒ the integer.
    if let Some(&raw) = buf.get(0x131) {
      out.push(SubEmission::new(
        "AFMicroAdjRegisteredLenses",
        TagValue::I64(i64::from(raw & 0x7f)),
      ));
    }
  }

  out
}

#[cfg(test)]
// The module-level `#![deny(clippy::indexing_slicing)]` is relaxed for the test
// module, which indexes fixed-layout byte buffers directly (an out-of-range
// index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
#[path = "camerainfo_tests.rs"]
mod tests;
