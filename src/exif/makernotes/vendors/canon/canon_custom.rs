// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Canon Custom Functions — `Image::ExifTool::CanonCustom` (`CanonCustom.pm`).
//!
//! The `%Canon::Main` tag `0x0f` (`Canon.pm:1501-1583`) is a model-conditional
//! list of `CanonCustom::Functions<Model>` SubDirectories, each processed by
//! `ProcessCanonCustom` (`CanonCustom.pm:2772-2801`): a length word at offset 0,
//! then `int16u` records from offset 2 where the HIGH byte is the record tag and
//! the LOW byte is the `int8u` value. Every record routes through the per-model
//! table's PrintConv.
//!
//! This module ports the EOS 5D table (`%CanonCustom::Functions5D`,
//! `CanonCustom.pm:228-383`, selected by `$$self{Model} =~ /EOS 5D/`) and the
//! consistent `%CanonCustom::Functions2` (`CanonCustom.pm:1198-2640`) used from
//! the EOS 1D Mark III onward — the `Canon::Main` tag `0x99` `CustomFunctions2`,
//! processed by a DIFFERENT walker, `ProcessCanonCustom2`
//! (`CanonCustom.pm:2642-2745`): a `int16u` size word, a `int32u` group count,
//! then per-group `(recNum, recLen, recCount)` headers each followed by
//! `(tag, num, int32s × num)` records. The emitted leaves land in the
//! `CanonCustom` family-1 group (the `Image::ExifTool::CanonCustom::*` package
//! group), NOT `Canon`.
//!
//! D8: pure decoder (no public struct fields); returns the `(Name, TagValue)`
//! emission pairs the dispatch site wraps in the `CanonCustom` family-1 group.

#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::ByteOrder;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::string::String;
use std::string::ToString;
use std::vec::Vec;

/// `true` when `model` selects `%CanonCustom::Functions5D` via the `0x0f`
/// conditional list (`Canon.pm:1511-1512`, `$$self{Model} =~ /EOS 5D/`). The
/// earlier `/EOS-1D/` arm (`Canon.pm:1503-1504`) is excluded so a 1D body never
/// mis-dispatches here.
#[must_use]
pub fn model_is_functions_5d(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  m.contains("EOS 5D") && !m.contains("EOS-1D")
}

/// Decode a `ProcessCanonCustom` block (`CanonCustom.pm:2772-2801`) against the
/// EOS 5D table. The leading length word is skipped; each subsequent `int16u`
/// record yields `tag = val >> 8`, `value = val & 0xff` (an `int8u`). A record
/// whose `tag` is not a named `Functions5D` entry is `Unknown` and dropped
/// (bundled gates it behind `-u`). `print_conv` selects the PrintConv label vs
/// the raw `int8u`.
#[must_use]
pub fn parse_functions_5d(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let size = data.len();
  let mut pos = 2usize;
  while pos + 2 <= size {
    let Some(arr) = data.get(pos..pos + 2) else {
      break;
    };
    let arr: [u8; 2] = match arr.try_into() {
      Ok(a) => a,
      Err(_) => break,
    };
    let word = match order {
      ByteOrder::Little => u16::from_le_bytes(arr),
      ByteOrder::Big => u16::from_be_bytes(arr),
    };
    let tag = (word >> 8) as u8;
    let val = (word & 0xff) as i64;
    if let Some((name, label)) = functions_5d_entry(tag) {
      let value = if print_conv {
        match label(val) {
          Some(l) => TagValue::Str(SmolStr::new_static(l)),
          None => TagValue::Str(SmolStr::from(std::format!("Unknown ({val})"))),
        }
      } else {
        TagValue::I64(val)
      };
      out.push((SmolStr::new_static(name), value));
    }
    pos += 2;
  }
  out
}

/// A record's `int8u`-value → PrintConv-label lookup (`None` ⇒ the `Unknown (N)`
/// fallback at the call site).
type LabelFn = fn(i64) -> Option<&'static str>;

/// One `%CanonCustom::Functions5D` record → its `Name` and PrintConv
/// (`CanonCustom.pm:234-382`). Tags 0..=20 are named; any other tag is
/// `Unknown` (returns `None`, dropped).
fn functions_5d_entry(tag: u8) -> Option<(&'static str, LabelFn)> {
  Some(match tag {
    0 => ("FocusingScreen", |v| {
      Some(match v {
        0 => "Ee-A",
        1 => "Ee-D",
        2 => "Ee-S",
        _ => return None,
      })
    }),
    1 => ("SetFunctionWhenShooting", |v| {
      Some(match v {
        0 => "Default (no function)",
        1 => "Change quality",
        2 => "Change Parameters",
        3 => "Menu display",
        4 => "Image replay",
        _ => return None,
      })
    }),
    2 => ("LongExposureNoiseReduction", |v| {
      Some(match v {
        0 => "Off",
        1 => "Auto",
        2 => "On",
        _ => return None,
      })
    }),
    3 => ("FlashSyncSpeedAv", |v| {
      Some(match v {
        0 => "Auto",
        1 => "1/200 Fixed",
        _ => return None,
      })
    }),
    4 => ("Shutter-AELock", |v| {
      Some(match v {
        0 => "AF/AE lock",
        1 => "AE lock/AF",
        2 => "AF/AF lock, No AE lock",
        3 => "AE/AF, No AE lock",
        _ => return None,
      })
    }),
    5 => ("AFAssistBeam", |v| {
      Some(match v {
        0 => "Emits",
        1 => "Does not emit",
        _ => return None,
      })
    }),
    6 => ("ExposureLevelIncrements", |v| {
      Some(match v {
        0 => "1/3 Stop",
        1 => "1/2 Stop",
        _ => return None,
      })
    }),
    7 => ("FlashFiring", |v| {
      Some(match v {
        0 => "Fires",
        1 => "Does not fire",
        _ => return None,
      })
    }),
    8 => ("ISOExpansion", off_on),
    9 => ("AEBSequenceAutoCancel", |v| {
      Some(match v {
        0 => "0,-,+/Enabled",
        1 => "0,-,+/Disabled",
        2 => "-,0,+/Enabled",
        3 => "-,0,+/Disabled",
        _ => return None,
      })
    }),
    10 => ("SuperimposedDisplay", on_off),
    11 => ("MenuButtonDisplayPosition", |v| {
      Some(match v {
        0 => "Previous (top if power off)",
        1 => "Previous",
        2 => "Top",
        _ => return None,
      })
    }),
    12 => ("MirrorLockup", disable_enable),
    13 => ("AFPointSelectionMethod", |v| {
      Some(match v {
        0 => "Normal",
        1 => "Multi-controller direct",
        2 => "Quick Control Dial direct",
        _ => return None,
      })
    }),
    14 => ("ETTLII", |v| {
      Some(match v {
        0 => "Evaluative",
        1 => "Average",
        _ => return None,
      })
    }),
    15 => ("ShutterCurtainSync", |v| {
      Some(match v {
        0 => "1st-curtain sync",
        1 => "2nd-curtain sync",
        _ => return None,
      })
    }),
    16 => ("SafetyShiftInAvOrTv", disable_enable),
    17 => ("AFPointActivationArea", |v| {
      Some(match v {
        0 => "Standard",
        1 => "Expanded",
        _ => return None,
      })
    }),
    18 => ("LCDDisplayReturnToShoot", |v| {
      Some(match v {
        0 => "With Shutter Button only",
        1 => "Also with * etc.",
        _ => return None,
      })
    }),
    19 => ("LensAFStopButton", |v| {
      Some(match v {
        0 => "AF stop",
        1 => "AF start",
        2 => "AE lock while metering",
        3 => "AF point: M -> Auto / Auto -> Ctr.",
        4 => "ONE SHOT <-> AI SERVO",
        5 => "IS start",
        _ => return None,
      })
    }),
    20 => ("AddOriginalDecisionData", off_on),
    _ => return None,
  })
}

/// `%offOn` (`CanonCustom.pm:33`).
fn off_on(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    1 => "On",
    _ => return None,
  })
}

/// `%onOff` (`CanonCustom.pm:32`).
fn on_off(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "On",
    1 => "Off",
    _ => return None,
  })
}

/// `%disableEnable` (`CanonCustom.pm:34`).
fn disable_enable(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Disable",
    1 => "Enable",
    _ => return None,
  })
}

/// `%enableDisable` (`CanonCustom.pm:35`).
fn enable_disable(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Enable",
    1 => "Disable",
    _ => return None,
  })
}

// ─── ProcessCanonCustom2 (`Canon::Main` 0x99) ────────────────────────────────

/// Decode a `ProcessCanonCustom2` block (`CanonCustom.pm:2642-2745`) against
/// `%CanonCustom::Functions2`. Structure: an `int16u` size word equal to the
/// block length (and at least 8 bytes), an `int32u` group count, then per-group
/// `(recNum, recLen, recCount)` `int32u` headers each followed by `recCount`
/// records of `(tag:int32u, num:int32u, int32s × num)`. Each record routes
/// through the model-keyed `Functions2` PrintConv; an unknown `tag` is dropped.
/// A malformed block stops the walk and keeps the records found so far
/// (ExifTool's `HandleTag` stores them before the `return 0`).
#[must_use]
pub fn parse_functions2(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let size = data.len();
  if size < 2 {
    return out;
  }
  // First 16-bit value is the block length; must equal the size and be >= 8.
  let Some(len) = u16_at(data, 0, order) else {
    return out;
  };
  if len != size || len < 8 {
    return out;
  }
  // (group count at offset 4 is verbose-only; the walk is bounded by `size`.)
  let mut pos = 8usize;
  while pos < size {
    let Some(next) = pos.checked_add(12) else {
      break;
    };
    if next > size {
      break;
    }
    // (recNum at `pos` is verbose-only.)
    let Some(rec_len) = u32_at(data, pos + 4, order) else {
      break;
    };
    if rec_len < 8 {
      break;
    }
    pos += 12;
    let mut rec_pos = pos;
    // recEnd = pos + recLen - 8; a recEnd past the block end is corruption →
    // stop (ExifTool `return 0`, keeping records already extracted).
    let Some(rec_end) = pos.checked_add(rec_len - 8) else {
      break;
    };
    if rec_end > size {
      break;
    }
    while rec_pos + 8 < rec_end {
      let (Some(tag), Some(num)) = (
        u32_at(data, rec_pos, order),
        u32_at(data, rec_pos + 4, order),
      ) else {
        break;
      };
      let Some(next_rec) = rec_pos
        .checked_add(8)
        .and_then(|p| num.checked_mul(4).and_then(|n| p.checked_add(n)))
      else {
        break;
      };
      if next_rec > rec_end {
        break;
      }
      rec_pos += 8;
      let mut vals: Vec<i64> = Vec::with_capacity(num);
      let mut ok = true;
      for i in 0..num {
        match i32s_at(data, rec_pos + i * 4, order) {
          Some(v) => vals.push(v),
          None => {
            ok = false;
            break;
          }
        }
      }
      if !ok {
        break;
      }
      if let Some((name, value)) = functions2_render(tag, num, &vals, print_conv, model) {
        out.push((SmolStr::new_static(name), value));
      }
      rec_pos = next_rec;
    }
    pos = rec_end;
  }
  out
}

/// Render one `%CanonCustom::Functions2` record. `None` ⇒ an unknown `tag`
/// (dropped, gated behind `-u` in bundled). `num`/`vals` are the `int32s` array.
fn functions2_render(
  tag: usize,
  num: usize,
  vals: &[i64],
  print_conv: bool,
  model: Option<&str>,
) -> Option<(&'static str, TagValue)> {
  let v0 = vals.first().copied().unwrap_or(0);
  // The three multi-value specials.
  match tag {
    // 0x507 AFMicroadjustment (Count 5, list PrintConv `[hash]`).
    0x507 => {
      let value = if print_conv {
        TagValue::Str(SmolStr::from(list_print(vals, af_microadjustment_label)))
      } else {
        joined(num, vals)
      };
      return Some(("AFMicroadjustment", value));
    }
    // 0x512 SelectAFAreaSelectMode (list PrintConv `[hash, 'Flags 0x%x']`).
    0x512 => {
      let value = if print_conv {
        TagValue::Str(SmolStr::from(list_print_flags(vals, select_af_area_label)))
      } else {
        joined(num, vals)
      };
      return Some(("SelectAFAreaSelectMode", value));
    }
    // 0x70c CustomControls (no PrintConv — passthrough).
    0x70c => return Some(("CustomControls", joined(num, vals))),
    _ => {}
  }
  // Single-value hash tags.
  let (name, label): (&'static str, fn(i64) -> Option<&'static str>) = match tag {
    0x101 if model_has(model, "1D") => ("ExposureLevelIncrements", exposure_level_1d_label),
    0x101 => ("ExposureLevelIncrements", exposure_level_label),
    0x102 => ("ISOSpeedIncrements", iso_speed_increments_label),
    0x103 => ("ISOExpansion", off_on),
    0x104 => ("AEBAutoCancel", on_off),
    0x105 => ("AEBSequence", aeb_sequence_label),
    0x108 => ("SafetyShift", safety_shift_label),
    0x10f => ("FlashSyncSpeedAv", flash_sync_speed_av_label),
    0x201 => ("LongExposureNoiseReduction", long_exposure_nr_label),
    0x202 => ("HighISONoiseReduction", high_iso_nr_label),
    0x203 => ("HighlightTonePriority", disable_enable),
    0x502 => (
      "AIServoTrackingSensitivity",
      ai_servo_tracking_sensitivity_label,
    ),
    0x503 => ("AIServoImagePriority", ai_servo_image_priority_label),
    0x504 => ("AIServoTrackingMethod", ai_servo_tracking_method_label),
    0x505 => ("LensDriveNoAF", lens_drive_no_af_label),
    0x50e => ("AFAssistBeam", af_assist_beam_label),
    0x510 if model_has(model, "7D") => ("VFDisplayIllumination", vf_display_illumination_label),
    0x510 => ("SuperimposedDisplay", on_off),
    0x513 => (
      "ManualAFPointSelectPattern",
      manual_af_point_select_pattern_label,
    ),
    0x514 => ("DisplayAllAFPoints", enable_disable),
    0x515 => ("FocusDisplayAIServoAndMF", enable_disable),
    0x516 => (
      "OrientationLinkedAFPoint",
      orientation_linked_af_point_label,
    ),
    0x60f => ("MirrorLockup", mirror_lockup_label),
    0x706 => ("DialDirectionTvAv", dial_direction_tv_av_label),
    0x80e => ("AddAspectRatioInfo", add_aspect_ratio_info_label),
    0x80f => ("AddOriginalDecisionData", off_on),
    _ => return None,
  };
  let value = if num != 1 {
    joined(num, vals)
  } else if print_conv {
    match label(v0) {
      Some(l) => TagValue::Str(SmolStr::new_static(l)),
      None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v0})"))),
    }
  } else {
    TagValue::I64(v0)
  };
  Some((name, value))
}

/// `joined(num, vals)`: a single value as `I64`; a multi-value as the
/// space-joined raw int32s string (matching ExifTool `ReadValue` for `num > 1`).
fn joined(num: usize, vals: &[i64]) -> TagValue {
  if num == 1 {
    TagValue::I64(vals.first().copied().unwrap_or(0))
  } else {
    TagValue::Str(SmolStr::from(space_joined(vals)))
  }
}

/// `vals` joined with a single space.
fn space_joined(vals: &[i64]) -> String {
  vals
    .iter()
    .map(ToString::to_string)
    .collect::<Vec<_>>()
    .join(" ")
}

/// A list PrintConv `[hash]`: element 0 via `label` (Unknown ⇒ `Unknown (N)`),
/// the rest passthrough; joined with "; ".
fn list_print(vals: &[i64], label: fn(i64) -> Option<&'static str>) -> String {
  vals
    .iter()
    .enumerate()
    .map(|(i, &v)| {
      if i == 0 {
        match label(v) {
          Some(l) => l.to_string(),
          None => std::format!("Unknown ({v})"),
        }
      } else {
        v.to_string()
      }
    })
    .collect::<Vec<_>>()
    .join("; ")
}

/// A list PrintConv `[hash, 'Flags 0x%x']`: element 0 via `label`, element 1 as
/// `Flags 0x%x`, the rest passthrough; joined with "; ".
fn list_print_flags(vals: &[i64], label: fn(i64) -> Option<&'static str>) -> String {
  vals
    .iter()
    .enumerate()
    .map(|(i, &v)| match i {
      0 => match label(v) {
        Some(l) => l.to_string(),
        None => std::format!("Unknown ({v})"),
      },
      1 => std::format!("Flags 0x{v:x}"),
      _ => v.to_string(),
    })
    .collect::<Vec<_>>()
    .join("; ")
}

/// `$$self{Model} =~ /…/` — a substring model match (the Canon model strings use
/// space/`-` word boundaries, so a plain `contains` is faithful here).
fn model_has(model: Option<&str>, needle: &str) -> bool {
  model.is_some_and(|m| m.contains(needle))
}

/// 0x101 `ExposureLevelIncrements`, non-1D arm (`CanonCustom.pm:1230-1233`).
fn exposure_level_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "1/3 Stop",
    1 => "1/2 Stop",
    _ => return None,
  })
}

/// 0x101 `ExposureLevelIncrements`, 1D arm (`CanonCustom.pm:1221-1225`).
fn exposure_level_1d_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "1/3-stop set, 1/3-stop comp.",
    1 => "1-stop set, 1/3-stop comp.",
    2 => "1/2-stop set, 1/2-stop comp.",
    _ => return None,
  })
}

/// 0x102 `ISOSpeedIncrements` (`CanonCustom.pm:1238-1241`).
fn iso_speed_increments_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "1/3 Stop",
    1 => "1 Stop",
    _ => return None,
  })
}

/// 0x105 `AEBSequence` (`CanonCustom.pm:1286-1290`).
fn aeb_sequence_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "0,-,+",
    1 => "-,0,+",
    2 => "+,0,-",
    _ => return None,
  })
}

/// 0x108 `SafetyShift` (`CanonCustom.pm:1333-1337`).
fn safety_shift_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Disable",
    1 => "Enable (Tv/Av)",
    2 => "Enable (ISO speed)",
    _ => return None,
  })
}

/// 0x10f `FlashSyncSpeedAv`, 50D/60D/7D arm (`CanonCustom.pm:1510-1514`).
fn flash_sync_speed_av_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Auto",
    1 => "1/250-1/60 Auto",
    2 => "1/250 Fixed",
    _ => return None,
  })
}

/// 0x201 `LongExposureNoiseReduction` (`CanonCustom.pm:1598-1602`).
fn long_exposure_nr_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    1 => "Auto",
    2 => "On",
    _ => return None,
  })
}

/// 0x202 `HighISONoiseReduction`, 50D/.../7D arm (`CanonCustom.pm:1612-1617`).
fn high_iso_nr_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Standard",
    1 => "Low",
    2 => "Strong",
    3 => "Off",
    _ => return None,
  })
}

/// 0x502 `AIServoTrackingSensitivity` (`CanonCustom.pm:1739-1743`).
fn ai_servo_tracking_sensitivity_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Standard",
    1 => "Medium Fast",
    2 => "Fast",
    _ => return None,
  })
}

/// 0x503 `AIServoImagePriority` (`CanonCustom.pm:1747-1752`).
fn ai_servo_image_priority_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "1: AF, 2: Tracking",
    1 => "1: AF, 2: Drive speed",
    2 => "1: Release, 2: Drive speed",
    3 => "1: Release, 2: Tracking",
    _ => return None,
  })
}

/// 0x504 `AIServoTrackingMethod` (`CanonCustom.pm:1756-1759`).
fn ai_servo_tracking_method_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Main focus point priority",
    1 => "Continuous AF track priority",
    _ => return None,
  })
}

/// 0x505 `LensDriveNoAF` (`CanonCustom.pm:1763-1766`).
fn lens_drive_no_af_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Focus search on",
    1 => "Focus search off",
    _ => return None,
  })
}

/// 0x507 `AFMicroadjustment` element-0 hash (`CanonCustom.pm:1786-1790`).
fn af_microadjustment_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Disable",
    1 => "Adjust all by same amount",
    2 => "Adjust by lens",
    _ => return None,
  })
}

/// 0x50e `AFAssistBeam`, non-(1DmkIV/6D) arm (`CanonCustom.pm:1920-1925`).
fn af_assist_beam_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Emits",
    1 => "Does not emit",
    2 => "Only ext. flash emits",
    3 => "IR AF assist beam only",
    _ => return None,
  })
}

/// 0x510 `VFDisplayIllumination`, 7D arm (`CanonCustom.pm:1954-1958`).
fn vf_display_illumination_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Auto",
    1 => "Enable",
    2 => "Disable",
    _ => return None,
  })
}

/// 0x512 `SelectAFAreaSelectMode` element-0 hash (`CanonCustom.pm:1986-1992`).
fn select_af_area_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Disable",
    1 => "Enable",
    2 => "Register",
    3 => "Select AF-modes",
    _ => return None,
  })
}

/// 0x513 `ManualAFPointSelectPattern` (`CanonCustom.pm:2002-2005`).
fn manual_af_point_select_pattern_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Stops at AF area edges",
    1 => "Continuous",
    _ => return None,
  })
}

/// 0x516 `OrientationLinkedAFPoint` (`CanonCustom.pm:2017-2020`).
fn orientation_linked_af_point_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Same for vertical and horizontal",
    1 => "Select different AF points",
    _ => return None,
  })
}

/// 0x60f `MirrorLockup` (`CanonCustom.pm:2085-2089`).
fn mirror_lockup_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Disable",
    1 => "Enable",
    2 => "Enable: Down with Set",
    _ => return None,
  })
}

/// 0x706 `DialDirectionTvAv` (`CanonCustom.pm:2349-2352`).
fn dial_direction_tv_av_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Normal",
    1 => "Reversed",
    _ => return None,
  })
}

/// 0x80e `AddAspectRatioInfo` (`CanonCustom.pm:2563-2570`).
fn add_aspect_ratio_info_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    1 => "6:6",
    2 => "3:4",
    3 => "4:5",
    4 => "6:7",
    5 => "10:12",
    6 => "5:7",
    _ => return None,
  })
}

/// Read an unsigned 16-bit word at byte `off`.
fn u16_at(data: &[u8], off: usize, order: ByteOrder) -> Option<usize> {
  let arr: [u8; 2] = data.get(off..off + 2)?.try_into().ok()?;
  Some(usize::from(match order {
    ByteOrder::Little => u16::from_le_bytes(arr),
    ByteOrder::Big => u16::from_be_bytes(arr),
  }))
}

/// Read an unsigned 32-bit word at byte `off` as a `usize` (offsets/counts).
fn u32_at(data: &[u8], off: usize, order: ByteOrder) -> Option<usize> {
  let arr: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
  let v = match order {
    ByteOrder::Little => u32::from_le_bytes(arr),
    ByteOrder::Big => u32::from_be_bytes(arr),
  };
  usize::try_from(v).ok()
}

/// Read a signed 32-bit word at byte `off`.
fn i32s_at(data: &[u8], off: usize, order: ByteOrder) -> Option<i64> {
  let arr: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
  Some(i64::from(match order {
    ByteOrder::Little => i32::from_le_bytes(arr),
    ByteOrder::Big => i32::from_be_bytes(arr),
  }))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  /// The real EOS 5D CustomFunctions block (`CanonCustom.pm:2780`): length word
  /// 0x002e, then 22 `int16u` records (high byte = tag, low byte = value). The
  /// last record (tag 0x15) is `Unknown` and dropped.
  fn build() -> Vec<u8> {
    let words: &[u16] = &[
      0x002e, 0x0002, 0x0100, 0x0200, 0x0300, 0x0403, 0x0500, 0x0600, 0x0701, 0x0801, 0x0900,
      0x0a00, 0x0b00, 0x0c00, 0x0d01, 0x0e00, 0x0f00, 0x1000, 0x1101, 0x1200, 0x1301, 0x1401,
      0x1500,
    ];
    let mut v = Vec::new();
    for w in words {
      v.extend_from_slice(&w.to_le_bytes());
    }
    v
  }

  #[test]
  fn decodes_5d_custom_functions_print() {
    let data = build();
    let em = parse_functions_5d(&data, ByteOrder::Little, true);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("FocusingScreen"), Some(TagValue::Str("Ee-S".into())));
    assert_eq!(
      find("Shutter-AELock"),
      Some(TagValue::Str("AE/AF, No AE lock".into()))
    );
    assert_eq!(
      find("FlashFiring"),
      Some(TagValue::Str("Does not fire".into()))
    );
    assert_eq!(find("ISOExpansion"), Some(TagValue::Str("On".into())));
    assert_eq!(
      find("AFPointSelectionMethod"),
      Some(TagValue::Str("Multi-controller direct".into()))
    );
    assert_eq!(
      find("AFPointActivationArea"),
      Some(TagValue::Str("Expanded".into()))
    );
    assert_eq!(
      find("LensAFStopButton"),
      Some(TagValue::Str("AF start".into()))
    );
    assert_eq!(
      find("AddOriginalDecisionData"),
      Some(TagValue::Str("On".into()))
    );
    // 21 named records (tags 0..=20); the tag-0x15 record is Unknown → dropped.
    assert_eq!(em.len(), 21);
    assert!(
      em.iter()
        .all(|(k, _)| k != "CanonCustom_Functions5D_0x0015")
    );
  }

  #[test]
  fn numeric_mode_keeps_raw_int8u() {
    let data = build();
    let em = parse_functions_5d(&data, ByteOrder::Little, false);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("FocusingScreen"), Some(TagValue::I64(2)));
    assert_eq!(find("Shutter-AELock"), Some(TagValue::I64(3)));
    assert_eq!(find("AddOriginalDecisionData"), Some(TagValue::I64(1)));
  }

  #[test]
  fn model_dispatch() {
    assert!(model_is_functions_5d(Some("Canon EOS 5D")));
    assert!(!model_is_functions_5d(Some("Canon EOS 7D")));
    assert!(!model_is_functions_5d(Some("Canon EOS-1D Mark III")));
    assert!(!model_is_functions_5d(None));
  }

  /// A single-group `ProcessCanonCustom2` block (`int32u` words): size, group
  /// count 1, one group (recNum 1, recLen 96, recCount 5), then five records
  /// exercising a scalar hash (0x101), `%offOn` (0x103), the multi-value
  /// `AFMicroadjustment` (0x507) and `SelectAFAreaSelectMode` (0x512) list
  /// PrintConvs, and the no-PrintConv `CustomControls` (0x70c).
  fn build_custom2() -> Vec<u8> {
    let words: &[u32] = &[
      108, 1, // size, group count
      1, 96, 5, // recNum, recLen, recCount
      0x101, 1, 0, // ExposureLevelIncrements = 0
      0x103, 1, 1, // ISOExpansion = 1
      0x507, 5, 0, 0, 0, 0, 0, // AFMicroadjustment = 0 0 0 0 0
      0x512, 2, 1, 31, // SelectAFAreaSelectMode = 1 31
      0x70c, 3, 0, 3, 5, // CustomControls = 0 3 5
    ];
    let mut v = Vec::new();
    for w in words {
      v.extend_from_slice(&w.to_le_bytes());
    }
    v
  }

  #[test]
  fn custom2_print_values() {
    let data = build_custom2();
    let em = parse_functions2(&data, ByteOrder::Little, true, Some("Canon EOS 7D"));
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(
      find("ExposureLevelIncrements"),
      Some(TagValue::Str("1/3 Stop".into()))
    );
    assert_eq!(find("ISOExpansion"), Some(TagValue::Str("On".into())));
    assert_eq!(
      find("AFMicroadjustment"),
      Some(TagValue::Str("Disable; 0; 0; 0; 0".into()))
    );
    assert_eq!(
      find("SelectAFAreaSelectMode"),
      Some(TagValue::Str("Enable; Flags 0x1f".into()))
    );
    assert_eq!(find("CustomControls"), Some(TagValue::Str("0 3 5".into())));
    assert_eq!(em.len(), 5);
  }

  #[test]
  fn custom2_numeric_values() {
    let data = build_custom2();
    let em = parse_functions2(&data, ByteOrder::Little, false, Some("Canon EOS 7D"));
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ExposureLevelIncrements"), Some(TagValue::I64(0)));
    assert_eq!(find("ISOExpansion"), Some(TagValue::I64(1)));
    assert_eq!(
      find("AFMicroadjustment"),
      Some(TagValue::Str("0 0 0 0 0".into()))
    );
    assert_eq!(
      find("SelectAFAreaSelectMode"),
      Some(TagValue::Str("1 31".into()))
    );
  }

  #[test]
  fn custom2_bad_size_rejected() {
    let mut data = build_custom2();
    // Corrupt the size word ⇒ `len != size` ⇒ nothing emitted.
    data[0] = 0xff;
    assert!(parse_functions2(&data, ByteOrder::Little, true, Some("Canon EOS 7D")).is_empty());
  }
}
