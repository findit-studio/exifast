// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::CameraInfo3` (`Sony.pm:2986-3170`) — the
//! `0x0010` Main-table SubDirectory dispatched when `$count == 15360`
//! (`Sony.pm:2280-2300`), a plain (un-enciphered) `ProcessBinaryData` block
//! holding camera info for the A33/A35/A55, A450/A500/A550, A560/A580,
//! NEX-3/5/5C/C3 and VG10E.
//!
//! The table covers TWO different AF systems at OVERLAPPING offsets, selected
//! by `$$self{Model}`:
//!  1. `DSLR-A(450|500|550)` — a 9-point AF system (offsets identical to the
//!     A200-A390 `CameraInfo` table).
//!  2. `SLT-` / `DSLR-A(560|580)` — a 15-point three-cross AF system (more
//!     info at different offsets), whose `0x23` `AFStatus15` SubDirectory holds
//!     an 18-element `int16s` AF-status grid (`%Sony::AFStatus15`,
//!     `Sony.pm:9798-9821`).
//!
//! Per the `ProcessBinaryData` contract each tag is emitted IFF its byte range
//! is in the block AND its model `Condition` holds
//! ([[exifast-processbinarydata-per-field]]). `LensSpec` (0x00) renders via the
//! shared [`super::printconv`] lens-spec conversion (same name as the Main-IFD
//! `0x0029` leaf — last-wins dedup keeps this byte-identical value).

use crate::value::TagValue;

use super::subtables::{
  SubEmission, af_status_value, model_is_a4xx_9pt, model_is_slt_15pt, read_i16, read_u16,
};

/// `%afPoint15` PrintConv (`Sony.pm:557-575`) — the 15-point AF sensor used.
fn af_point15(v: u16) -> Option<&'static str> {
  Some(match v {
    0 => "Upper-left",
    1 => "Left",
    2 => "Lower-left",
    3 => "Far Left",
    4 => "Top (horizontal)",
    5 => "Near Right",
    6 => "Center (horizontal)",
    7 => "Near Left",
    8 => "Bottom (horizontal)",
    9 => "Top (vertical)",
    10 => "Center (vertical)",
    11 => "Bottom (vertical)",
    12 => "Far Right",
    13 => "Upper-right",
    14 => "Right",
    15 => "Lower-right",
    16 => "Upper-middle",
    17 => "Lower-middle",
    255 => "(none)",
    _ => return None,
  })
}

/// `FocusStatus` (0x19) PrintConv (`Sony.pm:3082-3091`) — SLT / A560 / A580.
fn focus_status(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Manual - Not confirmed (0)",
    4 => "Manual - Not confirmed (4)",
    16 => "AF-C - Confirmed",
    24 => "AF-C - Not Confirmed",
    64 => "AF-S - Confirmed",
    _ => return None,
  })
}

/// `AFPointSelected` (0x1c, 15-point) PrintConv (`Sony.pm:3094-3118`).
fn af_point_selected15(v: u8) -> Option<&'static str> {
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
    12 => "Upper-middle",
    13 => "Near Right",
    14 => "Lower-middle",
    15 => "Near Left",
    _ => return None,
  })
}

/// `AFPointSelected` (0x14, 9-point) PrintConv (`Sony.pm:3030-3046`).
fn af_point_selected9(v: u8) -> Option<&'static str> {
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

/// `AFPoint` (0x18, 9-point) PrintConv (`Sony.pm:3058-3074`).
fn af_point9(v: u8) -> Option<&'static str> {
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

/// `FocusMode` (0x15 9-pt / 0x1d 15-pt) PrintConv (`Sony.pm:3050-3056`).
fn focus_mode(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Manual",
    1 => "AF-S",
    2 => "AF-C",
    3 => "AF-A",
    _ => return None,
  })
}

/// Render a hash-PrintConv leaf (`-j` label/`Unknown (N)`, `-n` raw int).
fn hash_leaf(raw: u8, hit: Option<&'static str>, print_conv: bool) -> TagValue {
  super::hash_print_value(raw, hit, print_conv)
}

/// Push a `%afStatusInfo` `int16s` leaf at `off` (the 9-point inline AF-status
/// fields).
fn push_af_status(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  if let Some(v) = read_i16(buf, off) {
    out.push(SubEmission {
      priority: 1,
      name,
      value: af_status_value(v, print_conv),
    });
  }
}

/// Walk the `CameraInfo3` block and emit the camera-info + AF leaves for the
/// model's AF system.
///
/// `buf` is the verbatim (un-enciphered) `0x0010` block. `model` is
/// `$$self{Model}`; `print_conv` selects `-j` vs `-n`.
#[must_use]
pub fn parse_camera_info3(buf: &[u8], model: Option<&str>, print_conv: bool) -> Vec<SubEmission> {
  let mut out = std::vec::Vec::new();
  let slt = model_is_slt_15pt(model);
  let a4xx = model_is_a4xx_9pt(model);

  // 0x00 LensSpec (`Condition !~ NEX-5C`, undef[8]; Sony.pm:2994-3002) is the
  // SAME `LensSpec` name + value as the Main-IFD `0x0029` leaf, which exifast
  // already emits byte-identically; since `0x0010` precedes `0x0029` in
  // tag-order the Main leaf wins the last-wins dedup either way, so this
  // duplicate is intentionally NOT re-emitted here (it would be dropped).

  // 0x0e FocalLength — int16u, `Condition !~ A450/A500/A550`, `$val/10`,
  // `Priority => 0`, `sprintf("%.1f mm",$val)` (Sony.pm:3006-3014).
  if !a4xx && let Some(raw) = read_u16(buf, 0x0e) {
    let mm = f64::from(raw) / 10.0;
    out.push(SubEmission {
      // `Priority => 0` (Sony.pm:3011) — this Sony `FocalLength` never overrides
      // an earlier same-name duplicate.
      priority: 0,
      name: "FocalLength",
      value: if print_conv {
        TagValue::Str(std::format!("{mm:.1} mm").into())
      } else {
        TagValue::F64(mm)
      },
    });
  }

  // 0x10 FocalLengthTeleZoom — int16u, `Condition !~ A450/A500/A550`,
  // `$val*2/3`, `sprintf("%.1f mm",$val)` (Sony.pm:3015-3023).
  if !a4xx && let Some(raw) = read_u16(buf, 0x10) {
    let mm = f64::from(raw) * 2.0 / 3.0;
    out.push(SubEmission {
      priority: 1,
      name: "FocalLengthTeleZoom",
      value: if print_conv {
        TagValue::Str(std::format!("{mm:.1} mm").into())
      } else {
        TagValue::F64(mm)
      },
    });
  }

  if a4xx {
    // 9-point AF system (DSLR-A450/A500/A550).
    if let Some(&raw) = buf.get(0x14) {
      out.push(SubEmission {
        priority: 1,
        name: "AFPointSelected",
        value: hash_leaf(raw, af_point_selected9(raw), print_conv),
      });
    }
    if let Some(&raw) = buf.get(0x15) {
      out.push(SubEmission {
        priority: 1,
        name: "FocusMode",
        value: hash_leaf(raw, focus_mode(raw), print_conv),
      });
    }
    if let Some(&raw) = buf.get(0x18) {
      out.push(SubEmission {
        priority: 1,
        name: "AFPoint",
        value: hash_leaf(raw, af_point9(raw), print_conv),
      });
    }
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
  } else if slt {
    // 15-point three-cross AF system (SLT- / DSLR-A560/A580).
    // 0x19 FocusStatus (Sony.pm:3076-3092).
    if let Some(&raw) = buf.get(0x19) {
      out.push(SubEmission {
        priority: 1,
        name: "FocusStatus",
        value: hash_leaf(raw, focus_status(raw), print_conv),
      });
    }
    // 0x1c AFPointSelected (Sony.pm:3094-3118).
    if let Some(&raw) = buf.get(0x1c) {
      out.push(SubEmission {
        priority: 1,
        name: "AFPointSelected",
        value: hash_leaf(raw, af_point_selected15(raw), print_conv),
      });
    }
    // 0x1d FocusMode (Sony.pm:3122-3130).
    if let Some(&raw) = buf.get(0x1d) {
      out.push(SubEmission {
        priority: 1,
        name: "FocusMode",
        value: hash_leaf(raw, focus_mode(raw), print_conv),
      });
    }
    // 0x20 AFPoint — `%afPoint15` (int8u; Sony.pm:3143-3151).
    if let Some(&raw) = buf.get(0x20) {
      out.push(SubEmission {
        priority: 1,
        name: "AFPoint",
        value: hash_leaf(raw, af_point15(u16::from(raw)), print_conv),
      });
    }
    // 0x21 AFStatusActiveSensor — int16s afStatusInfo (Sony.pm:3153-3158).
    push_af_status(buf, 0x21, "AFStatusActiveSensor", print_conv, &mut out);
    // 0x23 AFStatus15 — int16s[18] SubDirectory (Sony.pm:3166-3170).
    push_af_status15(buf, 0x23, print_conv, &mut out);
  }

  out
}

/// Emit the 18-element `int16s` `%Sony::AFStatus15` grid starting at `off`
/// (CameraInfo3 0x23). Each element is a `%afStatusInfo` leaf
/// (`Sony.pm:9798-9821`).
fn push_af_status15(buf: &[u8], off: usize, print_conv: bool, out: &mut Vec<SubEmission>) {
  const NAMES: [&str; 18] = [
    "AFStatusUpper-left",
    "AFStatusLeft",
    "AFStatusLower-left",
    "AFStatusFarLeft",
    "AFStatusTopHorizontal",
    "AFStatusNearRight",
    "AFStatusCenterHorizontal",
    "AFStatusNearLeft",
    "AFStatusBottomHorizontal",
    "AFStatusTopVertical",
    "AFStatusCenterVertical",
    "AFStatusBottomVertical",
    "AFStatusFarRight",
    "AFStatusUpper-right",
    "AFStatusRight",
    "AFStatusLower-right",
    "AFStatusUpper-middle",
    "AFStatusLower-middle",
  ];
  for (i, name) in NAMES.iter().enumerate() {
    push_af_status(buf, off + i * 2, name, print_conv, out);
  }
}
