// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::ExtraInfo3` (`Sony.pm:5919-6090`) — the `0x0116`
//! Main-table SubDirectory holding extra hardware (battery) info for the
//! A33/A35/A55, A450/A500/A550, A560/A580 and NEX-3/5/C3/VG10.
//!
//! Per the `ProcessBinaryData` contract each tag is emitted IFF its byte range
//! is in the block AND its model `Condition` holds
//! ([[exifast-processbinarydata-per-field]]). The `BatteryUnknown` (0x0000) leaf
//! carries `Unknown => 1`, so it is suppressed at default verbosity (matching
//! the golden, which omits it).

use crate::value::TagValue;
use smol_str::SmolStr;

use super::subtables::{
  SubEmission, model_is_a4xx_9pt, model_is_dslr, model_is_nex_battery_excl, model_is_slt, read_u16,
};

/// Walk the `ExtraInfo3` block and emit the battery/orientation leaves.
///
/// `buf` is the verbatim (un-enciphered) `0x0116` block; `model` is
/// `$$self{Model}`; `print_conv` selects `-j` vs `-n`.
#[must_use]
pub fn parse_extra_info3(buf: &[u8], model: Option<&str>, print_conv: bool) -> Vec<SubEmission> {
  let mut out = std::vec::Vec::new();
  let nex_excl = model_is_nex_battery_excl(model);

  // 0x0002 BatteryTemperature — int8u (no Format ⇒ the `%binaryDataAttrs`
  // default), `($val-32)/1.8`, `%.1f C` (Sony.pm:5932-5938).
  if let Some(&raw) = buf.get(0x0002) {
    let celsius = (f64::from(raw) - 32.0) / 1.8;
    out.push(SubEmission {
      priority: 1,
      name: "BatteryTemperature",
      value: if print_conv {
        TagValue::Str(SmolStr::new(std::format!("{celsius:.1} C")))
      } else {
        TagValue::F64(celsius)
      },
    });
  }

  // 0x0004 BatteryLevel — int8u (no Format), `"$val%"` (Sony.pm:5940).
  if let Some(&raw) = buf.get(0x0004) {
    out.push(SubEmission {
      priority: 1,
      name: "BatteryLevel",
      value: if print_conv {
        TagValue::Str(SmolStr::new(std::format!("{raw}%")))
      } else {
        TagValue::I64(i64::from(raw))
      },
    });
  }

  // 0x0006 BatteryVoltage1 / 0x0008 BatteryVoltage2 — int16u, `$val/128`,
  // `%.2f V`; `Condition !~ NEX-(3|5|5C|C3|VG10|VG10E)` (Sony.pm:5954-5970).
  if !nex_excl {
    push_voltage(buf, 0x0006, "BatteryVoltage1", print_conv, &mut out);
    push_voltage(buf, 0x0008, "BatteryVoltage2", print_conv, &mut out);
  }

  // 0x0011 ImageStabilization — int8u, `0 => Off`, `64 => On`;
  // `Condition !~ NEX-...` (Sony.pm:5982-5990).
  if !nex_excl && let Some(&raw) = buf.get(0x0011) {
    out.push(SubEmission {
      priority: 1,
      name: "ImageStabilization",
      value: super::hash_print_value(raw, image_stabilization(raw), print_conv),
    });
  }

  // 0x0014 — conditional ARRAY (`Sony.pm:5989-6035`), evaluated in table order
  // (first match wins):
  //   BatteryState     — `Model =~ /^SLT-/`
  //   ExposureProgram  — `Model =~ /^DSLR-(A450|A500|A550)\b/` (`Priority => 0`)
  //   ModeDialPosition — `Model =~ /^DSLR-/` (the other DSLR bodies)
  // The A4xx branch must precede the generic DSLR branch: ExifTool reads this
  // byte as ExposureProgram for the A450/A500/A550, NOT ModeDialPosition.
  if let Some(&raw) = buf.get(0x0014) {
    if model_is_slt(model) {
      out.push(SubEmission {
        priority: 1,
        name: "BatteryState",
        value: super::hash_print_value(raw, battery_state(raw), print_conv),
      });
    } else if model_is_a4xx_9pt(model) {
      // `Priority => 0` (`Sony.pm:6006` — "some unknown values").
      out.push(SubEmission {
        priority: 0,
        name: "ExposureProgram",
        value: super::hash_print_value(raw, exposure_program_a4xx(raw), print_conv),
      });
    } else if model_is_dslr(model) {
      out.push(SubEmission {
        priority: 1,
        name: "ModeDialPosition",
        value: super::hash_print_value(raw, mode_dial_position(raw), print_conv),
      });
    }
  }

  // 0x0018 CameraOrientation — int8u, Mask 0x30 (>> 4), plain hash, `!~ NEX-...`
  // (Sony.pm:6079-6090). `-n` emits the masked integer.
  if !nex_excl && let Some(&raw) = buf.get(0x0018) {
    let masked = (raw & 0x30) >> 4;
    out.push(SubEmission {
      priority: 1,
      name: "CameraOrientation",
      value: super::hash_print_value(masked, camera_orientation(u32::from(masked)), print_conv),
    });
  }

  out
}

/// Push a `$val/128` → `%.2f V` int16u battery-voltage leaf at `off`.
fn push_voltage(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  if let Some(raw) = read_u16(buf, off) {
    let v = f64::from(raw) / 128.0;
    out.push(SubEmission {
      priority: 1,
      name,
      value: if print_conv {
        TagValue::Str(SmolStr::new(std::format!("{v:.2} V")))
      } else {
        TagValue::F64(v)
      },
    });
  }
}

/// `ImageStabilization` PrintConv (`0 => Off`, `64 => On`).
fn image_stabilization(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    64 => "On",
    _ => return None,
  })
}

/// `BatteryState` PrintConv (SLT models; `Sony.pm:6001-6007`).
fn battery_state(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "Empty",
    2 => "Low",
    3 => "Half full",
    4 => "Almost full",
    5 => "Full",
    _ => return None,
  })
}

/// `ExposureProgram` PrintConv (A450/A500/A550 only; `Sony.pm:6007-6018`). The
/// `Priority => 0` 0x0014 branch for the 9-point DSLR bodies — a DISTINCT table
/// from `%sonyExposureProgram2` (the `MoreSettings`/`CameraSettings3`
/// `ExposureProgram`).
fn exposure_program_a4xx(v: u8) -> Option<&'static str> {
  Some(match v {
    241 => "Landscape",
    243 => "Aperture-priority AE",
    245 => "Portrait",
    246 => "Auto",
    247 => "Program AE",
    249 => "Macro",
    252 => "Sunset",
    253 => "Sports",
    255 => "Manual",
    _ => return None,
  })
}

/// `ModeDialPosition` PrintConv (other DSLR models; `Sony.pm:6024-6034`).
fn mode_dial_position(v: u8) -> Option<&'static str> {
  Some(match v {
    248 => "No Flash",
    249 => "Aperture-priority AE",
    250 => "SCN",
    251 => "Shutter speed priority AE",
    252 => "Auto",
    253 => "Program AE",
    254 => "Panorama",
    255 => "Manual",
    _ => return None,
  })
}

/// `CameraOrientation` PrintConv (`Sony.pm:6083-6088`).
fn camera_orientation(v: u32) -> Option<&'static str> {
  Some(match v {
    0 => "Horizontal (normal)",
    1 => "Rotate 90 CW",
    2 => "Rotate 270 CW",
    3 => "Rotate 180",
    _ => return None,
  })
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is relaxed for the test
// module, which indexes fixed-layout byte buffers directly (an out-of-range
// index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
#[path = "extrainfo3_tests.rs"]
mod tests;
