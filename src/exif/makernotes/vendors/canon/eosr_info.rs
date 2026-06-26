// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! The EOS-R-era Canon `ProcessBinaryData` feature sub-tables: `%Canon::Ambience`
//! (`Canon.pm:9136-9151`, 0x4020), `%Canon::MultiExp` (`:9153-9183`, 0x4021),
//! `%Canon::HDRInfo` (`:9185-9211`, 0x4025) and `%Canon::AFConfig`
//! (`:9318-9520`, 0x4028). All are `FORMAT => 'int32s'`, `FIRST_ENTRY => 1` —
//! leaf index `N` is at byte offset `N*4`. Each emits only the in-range leaves
//! (per-field availability) under the parent `Canon` family-1 group.
//!
//! D8: pure decoders — return the `(Name, TagValue)` emission pairs the dispatch
//! site wraps in the group.

#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::ByteOrder;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

/// Read one signed 32-bit word at byte `off`.
fn i32s(data: &[u8], off: usize, order: ByteOrder) -> Option<i64> {
  let arr: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => i32::from_le_bytes(arr),
    ByteOrder::Big => i32::from_be_bytes(arr),
  } as i64)
}

/// Render a closed-hash PrintConv: the label, or `Unknown (N)`; raw int at `-n`.
fn hash(v: i64, print_conv: bool, label: fn(i64) -> Option<&'static str>) -> TagValue {
  if !print_conv {
    return TagValue::I64(v);
  }
  match label(v) {
    Some(l) => TagValue::Str(SmolStr::new_static(l)),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
  }
}

/// Decode `%Canon::Ambience` (0x4020). One leaf: AmbienceSelection @ 4.
#[must_use]
pub fn parse_ambience(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  if let Some(v) = i32s(data, 4, order) {
    out.push((
      SmolStr::new_static("AmbienceSelection"),
      hash(v, print_conv, |n| {
        Some(match n {
          0 => "Standard",
          1 => "Vivid",
          2 => "Warm",
          3 => "Soft",
          4 => "Cool",
          5 => "Intense",
          6 => "Brighter",
          7 => "Darker",
          8 => "Monochrome",
          _ => return None,
        })
      }),
    ));
  }
  out
}

/// Decode `%Canon::MultiExp` (0x4021): MultiExposure @ 4, MultiExposureControl
/// @ 8, MultiExposureShots @ 12 (plain int).
#[must_use]
pub fn parse_multi_exp(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  if let Some(v) = i32s(data, 4, order) {
    out.push((
      SmolStr::new_static("MultiExposure"),
      hash(v, print_conv, |n| {
        Some(match n {
          0 => "Off",
          1 => "On",
          2 => "On (RAW)",
          _ => return None,
        })
      }),
    ));
  }
  if let Some(v) = i32s(data, 8, order) {
    out.push((
      SmolStr::new_static("MultiExposureControl"),
      hash(v, print_conv, |n| {
        Some(match n {
          0 => "Additive",
          1 => "Average",
          2 => "Bright (comparative)",
          3 => "Dark (comparative)",
          _ => return None,
        })
      }),
    ));
  }
  // `3 => 'MultiExposureShots'` — no PrintConv (plain int in both modes).
  if let Some(v) = i32s(data, 12, order) {
    out.push((SmolStr::new_static("MultiExposureShots"), TagValue::I64(v)));
  }
  out
}

/// Decode `%Canon::HDRInfo` (0x4025): HDR @ 4, HDREffect @ 8.
#[must_use]
pub fn parse_hdr_info(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  if let Some(v) = i32s(data, 4, order) {
    out.push((
      SmolStr::new_static("HDR"),
      hash(v, print_conv, |n| {
        Some(match n {
          0 => "Off",
          1 => "Auto",
          2 => "On",
          _ => return None,
        })
      }),
    ));
  }
  if let Some(v) = i32s(data, 8, order) {
    out.push((
      SmolStr::new_static("HDREffect"),
      hash(v, print_conv, |n| {
        Some(match n {
          0 => "Natural",
          1 => "Art (standard)",
          2 => "Art (vivid)",
          3 => "Art (bold)",
          4 => "Art (embossed)",
          _ => return None,
        })
      }),
    ));
  }
  out
}

// ── %Canon::AFConfig (0x4028) ───────────────────────────────────────────────

/// `$$self{Model} =~ /EOS R\d/` — "EOS R" immediately followed by an ASCII
/// digit (the EOS R-NUMBER bodies, e.g. "EOS R5"; NOT the original "EOS R").
fn model_is_eos_r_numbered(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  let bytes = m.as_bytes();
  let needle = b"EOS R";
  bytes
    .windows(needle.len())
    .enumerate()
    .any(|(i, w)| w == needle && bytes.get(i + needle.len()).is_some_and(u8::is_ascii_digit))
}

/// `$$self{Model} =~ /EOS-1D X|EOS R/` (the 1D X + every EOS R-line body).
fn model_is_1dx_or_r(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.contains("EOS-1D X") || m.contains("EOS R"))
}

/// The "Auto"/"n/a" + `OTHER => $val` passthrough PrintConv shared by
/// AFTrackingSensitivity / AFAccelDecelTracking / AFPointSwitching: a matched
/// special key renders its label, every other value passes through as the bare
/// integer (in BOTH `-j` and `-n`).
fn passthrough(v: i64, print_conv: bool, special: &[(i64, &'static str)]) -> TagValue {
  if print_conv && let Some((_, label)) = special.iter().find(|(k, _)| *k == v) {
    return TagValue::Str(SmolStr::new_static(label));
  }
  TagValue::I64(v)
}

/// Decode `%Canon::AFConfig` (0x4028), threading the parent `$$self{Model}` for
/// the model-conditional indices 7 / 10 / 18 / 19.
#[must_use]
pub fn parse_af_config(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));

  // 1 AFConfigTool @ 4 — ValueConv `$val + 1`, PrintConv {11=>'Case A',
  // 0x80000000=>'n/a', OTHER=>'Case '.$val}.
  if let Some(raw) = i32s(data, 4, order) {
    let v = raw + 1;
    let value = if !print_conv {
      TagValue::I64(v)
    } else if v == 11 {
      TagValue::Str(SmolStr::new_static("Case A"))
    } else if v == 0x8000_0000 {
      TagValue::Str(SmolStr::new_static("n/a"))
    } else {
      TagValue::Str(SmolStr::from(std::format!("Case {v}")))
    };
    push("AFConfigTool", value);
  }
  // 2 AFTrackingSensitivity @ 8 — {127=>'Auto', 0x7fffffff=>'n/a', OTHER=>$val}.
  if let Some(v) = i32s(data, 8, order) {
    push(
      "AFTrackingSensitivity",
      passthrough(v, print_conv, &[(127, "Auto"), (0x7fff_ffff, "n/a")]),
    );
  }
  // 3 AFAccelDecelTracking @ 12 — {127=>'Auto', 0x7fffffff=>'n/a', OTHER=>$val}.
  if let Some(v) = i32s(data, 12, order) {
    push(
      "AFAccelDecelTracking",
      passthrough(v, print_conv, &[(127, "Auto"), (0x7fff_ffff, "n/a")]),
    );
  }
  // 4 AFPointSwitching @ 16 — {0x7fffffff=>'n/a', OTHER=>$val}.
  if let Some(v) = i32s(data, 16, order) {
    push(
      "AFPointSwitching",
      passthrough(v, print_conv, &[(0x7fff_ffff, "n/a")]),
    );
  }
  // 5 AIServoFirstImage @ 20.
  if let Some(v) = i32s(data, 20, order) {
    push(
      "AIServoFirstImage",
      hash(v, print_conv, |n| {
        Some(match n {
          0 => "Equal Priority",
          1 => "Release Priority",
          2 => "Focus Priority",
          _ => return None,
        })
      }),
    );
  }
  // 6 AIServoSecondImage @ 24.
  if let Some(v) = i32s(data, 24, order) {
    push(
      "AIServoSecondImage",
      hash(v, print_conv, |n| {
        Some(match n {
          0 => "Equal Priority",
          1 => "Release Priority",
          2 => "Focus Priority",
          3 => "Release High Priority",
          4 => "Focus High Priority",
          _ => return None,
        })
      }),
    );
  }
  // 7 USMLensElectronicMF @ 28 — model-conditional arms.
  if let Some(v) = i32s(data, 28, order) {
    let value = if model_is_eos_r_numbered(model) {
      hash(v, print_conv, |n| {
        Some(match n {
          0 => "Disable After One-Shot",
          1 => "One-Shot -> Enabled",
          2 => "One-Shot -> Enabled (magnify)",
          3 => "Disable in AF Mode",
          _ => return None,
        })
      })
    } else {
      hash(v, print_conv, |n| {
        Some(match n {
          0 => "Enable After AF",
          1 => "Disable After AF",
          2 => "Disable in AF Mode",
          _ => return None,
        })
      })
    };
    push("USMLensElectronicMF", value);
  }
  // 8 AFAssistBeam @ 32.
  if let Some(v) = i32s(data, 32, order) {
    push(
      "AFAssistBeam",
      hash(v, print_conv, |n| {
        Some(match n {
          0 => "Enable",
          1 => "Disable",
          2 => "IR AF Assist Beam Only",
          3 => "LED AF Assist Beam Only",
          _ => return None,
        })
      }),
    );
  }
  // 9 OneShotAFRelease @ 36.
  if let Some(v) = i32s(data, 36, order) {
    push(
      "OneShotAFRelease",
      hash(v, print_conv, |n| {
        Some(match n {
          0 => "Focus Priority",
          1 => "Release Priority",
          _ => return None,
        })
      }),
    );
  }
  // 10 AutoAFPointSelEOSiTRAF @ 40 — Condition `Model !~ /5D /`.
  if let Some(v) = i32s(data, 40, order)
    && !model.is_some_and(|m| m.contains("5D "))
  {
    push(
      "AutoAFPointSelEOSiTRAF",
      hash(v, print_conv, |n| {
        Some(match n {
          0 => "Enable",
          1 => "Disable",
          _ => return None,
        })
      }),
    );
  }
  // 11 LensDriveWhenAFImpossible @ 44.
  if let Some(v) = i32s(data, 44, order) {
    push(
      "LensDriveWhenAFImpossible",
      hash(v, print_conv, |n| {
        Some(match n {
          0 => "Continue Focus Search",
          1 => "Stop Focus Search",
          _ => return None,
        })
      }),
    );
  }
  // 12 SelectAFAreaSelectionMode @ 48 — BITMASK (DecodeBits, 32-bit).
  if let Some(v) = i32s(data, 48, order) {
    let value = if print_conv {
      TagValue::Str(SmolStr::from(crate::convert::decode_bits(
        &v.to_string(),
        Some(&[
          (0, "Single-point AF"),
          (1, "Auto"),
          (2, "Zone AF"),
          (3, "AF Point Expansion (4 point)"),
          (4, "Spot AF"),
          (5, "AF Point Expansion (8 point)"),
        ]),
        0,
      )))
    } else {
      TagValue::I64(v)
    };
    push("SelectAFAreaSelectionMode", value);
  }
  // 13 AFAreaSelectionMethod @ 52.
  if let Some(v) = i32s(data, 52, order) {
    push(
      "AFAreaSelectionMethod",
      hash(v, print_conv, |n| {
        Some(match n {
          0 => "M-Fn Button",
          1 => "Main Dial",
          _ => return None,
        })
      }),
    );
  }
  // 14 OrientationLinkedAF @ 56.
  if let Some(v) = i32s(data, 56, order) {
    push(
      "OrientationLinkedAF",
      hash(v, print_conv, |n| {
        Some(match n {
          0 => "Same for Vert/Horiz Points",
          1 => "Separate Vert/Horiz Points",
          2 => "Separate Area+Points",
          _ => return None,
        })
      }),
    );
  }
  // 15 ManualAFPointSelPattern @ 60.
  if let Some(v) = i32s(data, 60, order) {
    push(
      "ManualAFPointSelPattern",
      hash(v, print_conv, |n| {
        Some(match n {
          0 => "Stops at AF Area Edges",
          1 => "Continuous",
          _ => return None,
        })
      }),
    );
  }
  // 16 AFPointDisplayDuringFocus @ 64.
  if let Some(v) = i32s(data, 64, order) {
    push(
      "AFPointDisplayDuringFocus",
      hash(v, print_conv, |n| {
        Some(match n {
          0 => "Selected (constant)",
          1 => "All (constant)",
          2 => "Selected (pre-AF, focused)",
          3 => "Selected (focused)",
          4 => "Disabled",
          _ => return None,
        })
      }),
    );
  }
  // 17 VFDisplayIllumination @ 68.
  if let Some(v) = i32s(data, 68, order) {
    push(
      "VFDisplayIllumination",
      hash(v, print_conv, |n| {
        Some(match n {
          0 => "Auto",
          1 => "Enable",
          2 => "Disable",
          _ => return None,
        })
      }),
    );
  }
  // 18 AFStatusViewfinder @ 72 — Condition `Model =~ /EOS-1D X|EOS R/`.
  if let Some(v) = i32s(data, 72, order)
    && model_is_1dx_or_r(model)
  {
    push(
      "AFStatusViewfinder",
      hash(v, print_conv, |n| {
        Some(match n {
          0 => "Show in Field of View",
          1 => "Show Outside View",
          _ => return None,
        })
      }),
    );
  }
  // 19 InitialAFPointInServo @ 76 — Condition `Model =~ /EOS-1D X|EOS R/`.
  if let Some(v) = i32s(data, 76, order)
    && model_is_1dx_or_r(model)
  {
    push(
      "InitialAFPointInServo",
      hash(v, print_conv, |n| {
        Some(match n {
          0 => "Initial AF Point Selected",
          1 => "Manual AF Point",
          2 => "Auto",
          _ => return None,
        })
      }),
    );
  }
  // 20 SubjectToDetect @ 80 — beyond an 80-byte EOS R blob (per-field gated).
  if let Some(v) = i32s(data, 80, order) {
    push(
      "SubjectToDetect",
      hash(v, print_conv, |n| {
        Some(match n {
          0 => "None",
          1 => "People",
          2 => "Animals",
          3 => "Vehicles",
          4 => "Auto",
          _ => return None,
        })
      }),
    );
  }
  out
}
