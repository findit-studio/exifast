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
//! This module ports the per-body `ProcessCanonCustom` tables the `0x0f`
//! conditional list selects by Model (`%CanonCustom::Functions{D30,10D,20D,30D,
//! 350D,400D,1D,5D}`, `CanonCustom.pm:41-1084`) — `Functions1D` is also the
//! `Canon::Main` 0x90 `CustomFunctions1D` tag (1D/1Ds). It also ports the
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

/// Select the `%CanonCustom::Functions<Model>` table for the `Canon::Main` 0x0f
/// `CustomFunctions` conditional list (`Canon.pm:1501-1583`), evaluated in the
/// SAME order as bundled (the FIRST matching `Condition` wins). `None` is the
/// `CustomFunctionsUnknown` fallback (`%CanonCustom::FuncsUnknown`,
/// `CanonCustom.pm:1085-1090`) — a tagless table that emits nothing.
fn select_custom_table(model: Option<&str>) -> Option<EntryFn> {
  let m = model?;
  Some(if m.contains("EOS-1D") {
    // 1DmkII / 1DSmkII / 1DmkIIN (`Canon.pm:1502-1509`).
    functions_1d_entry
  } else if m.contains("EOS 5D") {
    functions_5d_entry
  } else if m.contains("EOS 10D") {
    functions_10d_entry
  } else if m.contains("EOS 20D") {
    functions_20d_entry
  } else if m.contains("EOS 30D") {
    functions_30d_entry
  } else if word_bounded(m, "350D")
    || word_bounded(m, "REBEL XT")
    || word_bounded(m, "Kiss Digital N")
  {
    functions_350d_entry
  } else if word_bounded(m, "400D")
    || word_bounded(m, "REBEL XTi")
    || word_bounded(m, "Kiss Digital X")
    || word_bounded(m, "K236")
  {
    functions_400d_entry
  } else if trailing_bounded(m, "EOS D30") || trailing_bounded(m, "EOS D60") {
    // D30 + D60 share `%CanonCustom::FunctionsD30` (`Canon.pm:1560-1574`).
    functions_d30_entry
  } else {
    return None;
  })
}

/// Decode the `Canon::Main` 0x0f `CustomFunctions` SubDirectory: select the
/// per-body `%CanonCustom::Functions<Model>` table (`Canon.pm:1501-1583`) and
/// run the shared `ProcessCanonCustom` record walk. A model matching no arm
/// (`CustomFunctionsUnknown`) emits nothing.
#[must_use]
pub fn parse_custom_functions(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
) -> Vec<(SmolStr, TagValue)> {
  match select_custom_table(model) {
    Some(entry) => walk_canon_custom(data, order, print_conv, model, entry),
    None => Vec::new(),
  }
}

/// `\bNEEDLE\b` — `needle` appears in `hay` bounded by a non-word byte (or the
/// string edge) on each side (Perl `\w` = `[0-9A-Za-z_]`). The 350D/400D arms
/// use word-anchored alternations (`\b(350D|REBEL XT|…)\b`, `Canon.pm:1543`/
/// `:1551`), so a plain substring test would mis-route "REBEL XTi" (a 400D) to
/// the 350D `REBEL XT` arm.
pub(super) fn word_bounded(hay: &str, needle: &str) -> bool {
  if needle.is_empty() {
    return false;
  }
  let hb = hay.as_bytes();
  let nlen = needle.len();
  let mut start = 0usize;
  while let Some(rel) = hay.get(start..).and_then(|s| s.find(needle)) {
    let i = start + rel;
    let before_ok = i == 0 || hb.get(i - 1).is_none_or(|&b| !is_word_byte(b));
    let after_ok = hb.get(i + nlen).is_none_or(|&b| !is_word_byte(b));
    if before_ok && after_ok {
      return true;
    }
    start = i + 1;
  }
  false
}

/// `NEEDLE\b` — `needle` appears in `hay` followed by a non-word byte (or the
/// string edge); the leading edge is unanchored. The D30/D60 arms are
/// `/EOS D30\b/` / `/EOS D60\b/` (`Canon.pm:1561`/`:1569`), so a model
/// "EOS D3000" must NOT match.
fn trailing_bounded(hay: &str, needle: &str) -> bool {
  if needle.is_empty() {
    return false;
  }
  let hb = hay.as_bytes();
  let nlen = needle.len();
  let mut start = 0usize;
  while let Some(rel) = hay.get(start..).and_then(|s| s.find(needle)) {
    let i = start + rel;
    if hb.get(i + nlen).is_none_or(|&b| !is_word_byte(b)) {
      return true;
    }
    start = i + 1;
  }
  false
}

/// Perl `\w` byte — `[0-9A-Za-z_]`.
fn is_word_byte(b: u8) -> bool {
  b.is_ascii_alphanumeric() || b == b'_'
}

/// Decode a `ProcessCanonCustom` block (`CanonCustom.pm:2772-2801`) against the
/// EOS 5D table (`%CanonCustom::Functions5D`). See [`walk_canon_custom`].
#[must_use]
pub fn parse_functions_5d(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
) -> Vec<(SmolStr, TagValue)> {
  // The 0x0f EOS 5D arm — never a D60, so the length gate needs no model.
  walk_canon_custom(data, order, print_conv, None, functions_5d_entry)
}

/// Decode a `ProcessCanonCustom` block against the 1D table
/// (`%CanonCustom::Functions1D`, `CanonCustom.pm:41-227`) — the `Canon::Main`
/// 0x90 `CustomFunctions1D` SubDirectory (`Canon.pm:1796-1802`, the 1D/1Ds
/// path) and the 0x0f `EOS-1D` arm. See [`walk_canon_custom`].
#[must_use]
pub fn parse_functions_1d(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
) -> Vec<(SmolStr, TagValue)> {
  // The 0x90 CustomFunctions1D tag / 0x0f EOS-1D arm — never a D60.
  walk_canon_custom(data, order, print_conv, None, functions_1d_entry)
}

/// The shared `ProcessCanonCustom` record walk (`CanonCustom.pm:2772-2801`): the
/// leading `int16u` length word at offset 0 must equal the block size, else the
/// whole block is rejected (`CanonCustom.pm:2782-2785`, "Invalid CanonCustom
/// data", `return 0`) and emits nothing — it is NOT clamped to the declared
/// length. The lone tolerance is the EOS D60, which declares a length 2 bytes
/// short of its block (`$$et{Model} =~ /\bD60\b/ and $len+2 == $size`). Each
/// subsequent `int16u` record yields `tag = val >> 8`, `value = val & 0xff` (an
/// `int8u`); once the gate passes, the walk always covers the full buffer. A
/// record whose `tag` is not a named `entry` is `Unknown` and dropped (bundled
/// gates it behind `-u`). `print_conv` selects the PrintConv label vs the raw
/// `int8u`.
fn walk_canon_custom(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
  entry: EntryFn,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let size = data.len();
  // The "Invalid CanonCustom data" gate (`CanonCustom.pm:2782-2785`).
  let Some(len_bytes) = data.get(0..2) else {
    return out;
  };
  let len_arr: [u8; 2] = match len_bytes.try_into() {
    Ok(a) => a,
    Err(_) => return out,
  };
  let len = usize::from(match order {
    ByteOrder::Little => u16::from_le_bytes(len_arr),
    ByteOrder::Big => u16::from_be_bytes(len_arr),
  });
  let d60 = model.is_some_and(|m| word_bounded(m, "D60"));
  if !(len == size || (d60 && len + 2 == size)) {
    return out;
  }
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
    if let Some((name, label)) = entry(tag) {
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

/// One `%CanonCustom::Functions<Model>` record-table lookup: a custom-function
/// number → its `Name` and PrintConv (`None` for an `Unknown` record, dropped).
/// Every `ProcessCanonCustom` per-body table shares this shape.
type EntryFn = fn(u8) -> Option<(&'static str, LabelFn)>;

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

/// One `%CanonCustom::Functions1D` record (`CanonCustom.pm:41-227`) — all 1D
/// models up to (not including) the Mark III. Tags 0..=21 are named.
fn functions_1d_entry(tag: u8) -> Option<(&'static str, LabelFn)> {
  Some(match tag {
    0 => ("FocusingScreen", |v| {
      Some(match v {
        0 => "Ec-N, R",
        1 => "Ec-A,B,C,CII,CIII,D,H,I,L",
        _ => return None,
      })
    }),
    1 => ("FinderDisplayDuringExposure", off_on),
    2 => ("ShutterReleaseNoCFCard", yes_no),
    3 => ("ISOSpeedExpansion", |v| {
      Some(match v {
        0 => "No",
        1 => "Yes",
        _ => return None,
      })
    }),
    4 => ("ShutterAELButton", |v| {
      Some(match v {
        0 => "AF/AE lock stop",
        1 => "AE lock/AF",
        2 => "AF/AF lock, No AE lock",
        3 => "AE/AF, No AE lock",
        _ => return None,
      })
    }),
    5 => ("ManualTv", |v| {
      Some(match v {
        0 => "Tv=Main/Av=Control",
        1 => "Tv=Control/Av=Main",
        2 => "Tv=Main/Av=Main w/o lens",
        3 => "Tv=Control/Av=Main w/o lens",
        _ => return None,
      })
    }),
    6 => ("ExposureLevelIncrements", |v| {
      Some(match v {
        0 => "1/3-stop set, 1/3-stop comp.",
        1 => "1-stop set, 1/3-stop comp.",
        2 => "1/2-stop set, 1/2-stop comp.",
        _ => return None,
      })
    }),
    7 => ("USMLensElectronicMF", |v| {
      Some(match v {
        0 => "Turns on after one-shot AF",
        1 => "Turns off after one-shot AF",
        2 => "Always turned off",
        _ => return None,
      })
    }),
    8 => ("LCDPanels", |v| {
      Some(match v {
        0 => "Remain. shots/File no.",
        1 => "ISO/Remain. shots",
        2 => "ISO/File no.",
        3 => "Shots in folder/Remain. shots",
        _ => return None,
      })
    }),
    9 => ("AEBSequenceAutoCancel", aeb_sequence_auto_cancel),
    10 => ("AFPointIllumination", |v| {
      Some(match v {
        0 => "On",
        1 => "Off",
        2 => "On without dimming",
        3 => "Brighter",
        _ => return None,
      })
    }),
    11 => ("AFPointSelection", |v| {
      Some(match v {
        0 => "H=AF+Main/V=AF+Command",
        1 => "H=Comp+Main/V=Comp+Command",
        2 => "H=Command only/V=Assist+Main",
        3 => "H=FEL+Main/V=FEL+Command",
        _ => return None,
      })
    }),
    12 => ("MirrorLockup", disable_enable),
    13 => ("AFPointSpotMetering", |v| {
      Some(match v {
        0 => "45/Center AF point",
        1 => "11/Active AF point",
        2 => "11/Center AF point",
        3 => "9/Active AF point",
        _ => return None,
      })
    }),
    14 => ("FillFlashAutoReduction", enable_disable),
    15 => ("ShutterCurtainSync", curtain_sync),
    16 => ("SafetyShiftInAvOrTv", disable_enable),
    17 => ("AFPointActivationArea", |v| {
      Some(match v {
        0 => "Single AF point",
        1 => "Expanded (TTL. of 7 AF points)",
        2 => "Automatic expanded (max. 13)",
        _ => return None,
      })
    }),
    18 => ("SwitchToRegisteredAFPoint", |v| {
      Some(match v {
        0 => "Assist + AF",
        1 => "Assist",
        2 => "Only while pressing assist",
        _ => return None,
      })
    }),
    19 => ("LensAFStopButton", |v| {
      Some(match v {
        0 => "AF stop",
        1 => "AF start",
        2 => "AE lock while metering",
        3 => "AF point: M -> Auto / Auto -> Ctr.",
        4 => "AF mode: ONE SHOT <-> AI SERVO",
        5 => "IS start",
        _ => return None,
      })
    }),
    20 => ("AIServoTrackingSensitivity", |v| {
      Some(match v {
        0 => "Standard",
        1 => "Slow",
        2 => "Moderately slow",
        3 => "Moderately fast",
        4 => "Fast",
        _ => return None,
      })
    }),
    21 => ("AIServoContinuousShooting", |v| {
      Some(match v {
        0 => "Shooting not possible without focus",
        1 => "Shooting possible without focus",
        _ => return None,
      })
    }),
    _ => return None,
  })
}

/// One `%CanonCustom::Functions10D` record (`CanonCustom.pm:386-531`). Tags
/// 1..=17 are named.
fn functions_10d_entry(tag: u8) -> Option<(&'static str, LabelFn)> {
  Some(match tag {
    1 => ("SetButtonWhenShooting", |v| {
      Some(match v {
        0 => "Normal (disabled)",
        1 => "Image quality",
        2 => "Change parameters",
        3 => "Menu display",
        4 => "Image playback",
        _ => return None,
      })
    }),
    2 => ("ShutterReleaseNoCFCard", yes_no),
    3 => ("FlashSyncSpeedAv", flash_sync_200),
    4 => ("Shutter-AELock", shutter_ae_lock),
    5 => ("AFAssist", |v| {
      Some(match v {
        0 => "Emits/Fires",
        1 => "Does not emit/Fires",
        2 => "Only ext. flash emits/Fires",
        3 => "Emits/Does not fire",
        _ => return None,
      })
    }),
    6 => ("ExposureLevelIncrements", |v| {
      Some(match v {
        0 => "1/2 Stop",
        1 => "1/3 Stop",
        _ => return None,
      })
    }),
    7 => ("AFPointRegistration", |v| {
      Some(match v {
        0 => "Center",
        1 => "Bottom",
        2 => "Right",
        3 => "Extreme Right",
        4 => "Automatic",
        5 => "Extreme Left",
        6 => "Left",
        7 => "Top",
        _ => return None,
      })
    }),
    8 => ("RawAndJpgRecording", |v| {
      Some(match v {
        0 => "RAW+Small/Normal",
        1 => "RAW+Small/Fine",
        2 => "RAW+Medium/Normal",
        3 => "RAW+Medium/Fine",
        4 => "RAW+Large/Normal",
        5 => "RAW+Large/Fine",
        _ => return None,
      })
    }),
    9 => ("AEBSequenceAutoCancel", aeb_sequence_auto_cancel),
    10 => ("SuperimposedDisplay", on_off),
    11 => ("MenuButtonDisplayPosition", menu_button_display_position),
    12 => ("MirrorLockup", disable_enable),
    13 => ("AssistButtonFunction", |v| {
      Some(match v {
        0 => "Normal",
        1 => "Select Home Position",
        2 => "Select HP (while pressing)",
        3 => "Av+/- (AF point by QCD)",
        4 => "FE lock",
        _ => return None,
      })
    }),
    14 => ("FillFlashAutoReduction", enable_disable),
    15 => ("ShutterCurtainSync", curtain_sync),
    16 => ("SafetyShiftInAvOrTv", disable_enable),
    17 => ("LensAFStopButton", |v| {
      Some(match v {
        0 => "AF stop",
        1 => "AF start",
        2 => "AE lock while metering",
        3 => "AF point: M->Auto/Auto->ctr",
        4 => "One Shot <-> AI servo",
        5 => "IS start",
        _ => return None,
      })
    }),
    _ => return None,
  })
}

/// One `%CanonCustom::Functions20D` record (`CanonCustom.pm:532-664`). Tags
/// 0..=17 are named.
fn functions_20d_entry(tag: u8) -> Option<(&'static str, LabelFn)> {
  Some(match tag {
    0 => ("SetFunctionWhenShooting", set_function_when_shooting),
    1 => ("LongExposureNoiseReduction", off_on),
    2 => ("FlashSyncSpeedAv", flash_sync_250),
    3 => ("Shutter-AELock", shutter_ae_lock),
    4 => ("AFAssistBeam", af_assist_beam_3),
    5 => ("ExposureLevelIncrements", exposure_level_third_half),
    6 => ("FlashFiring", |v| {
      Some(match v {
        0 => "Fires",
        1 => "Does not fire",
        _ => return None,
      })
    }),
    7 => ("ISOExpansion", off_on),
    8 => ("AEBSequenceAutoCancel", aeb_sequence_auto_cancel),
    9 => ("SuperimposedDisplay", on_off),
    10 => ("MenuButtonDisplayPosition", menu_button_display_position),
    11 => ("MirrorLockup", disable_enable),
    12 => ("AFPointSelectionMethod", af_point_selection_method),
    13 => ("ETTLII", ettl_ii),
    14 => ("ShutterCurtainSync", curtain_sync),
    15 => ("SafetyShiftInAvOrTv", disable_enable),
    16 => ("LensAFStopButton", lens_af_stop_button),
    17 => ("AddOriginalDecisionData", off_on),
    _ => return None,
  })
}

/// One `%CanonCustom::Functions30D` record (`CanonCustom.pm:665-808`). Tags
/// 1..=19 are named.
fn functions_30d_entry(tag: u8) -> Option<(&'static str, LabelFn)> {
  Some(match tag {
    1 => ("SetFunctionWhenShooting", |v| {
      Some(match v {
        0 => "Default (no function)",
        1 => "Change quality",
        2 => "Change Picture Style",
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
    3 => ("FlashSyncSpeedAv", flash_sync_250),
    4 => ("Shutter-AELock", shutter_ae_lock),
    5 => ("AFAssistBeam", af_assist_beam_3),
    6 => ("ExposureLevelIncrements", exposure_level_third_half),
    7 => ("FlashFiring", |v| {
      Some(match v {
        0 => "Fires",
        1 => "Does not fire",
        _ => return None,
      })
    }),
    8 => ("ISOExpansion", off_on),
    9 => ("AEBSequenceAutoCancel", aeb_sequence_auto_cancel),
    10 => ("SuperimposedDisplay", on_off),
    11 => ("MenuButtonDisplayPosition", menu_button_display_position),
    12 => ("MirrorLockup", disable_enable),
    13 => ("AFPointSelectionMethod", af_point_selection_method),
    14 => ("ETTLII", ettl_ii),
    15 => ("ShutterCurtainSync", curtain_sync),
    16 => ("SafetyShiftInAvOrTv", disable_enable),
    17 => ("MagnifiedView", magnified_view),
    18 => ("LensAFStopButton", lens_af_stop_button),
    19 => ("AddOriginalDecisionData", off_on),
    _ => return None,
  })
}

/// One `%CanonCustom::Functions350D` record (`CanonCustom.pm:809-881`). Tags
/// 0..=8 are named.
fn functions_350d_entry(tag: u8) -> Option<(&'static str, LabelFn)> {
  Some(match tag {
    0 => ("SetButtonCrossKeysFunc", |v| {
      Some(match v {
        0 => "Normal",
        1 => "Set: Quality",
        2 => "Set: Parameter",
        3 => "Set: Playback",
        4 => "Cross keys: AF point select",
        _ => return None,
      })
    }),
    1 => ("LongExposureNoiseReduction", off_on),
    2 => ("FlashSyncSpeedAv", flash_sync_200),
    3 => ("Shutter-AELock", shutter_ae_lock),
    4 => ("AFAssistBeam", af_assist_beam_3),
    5 => ("ExposureLevelIncrements", exposure_level_third_half),
    6 => ("MirrorLockup", disable_enable),
    7 => ("ETTLII", ettl_ii),
    8 => ("ShutterCurtainSync", curtain_sync),
    _ => return None,
  })
}

/// One `%CanonCustom::Functions400D` record (`CanonCustom.pm:882-972`). Tags
/// 0..=10 are named.
fn functions_400d_entry(tag: u8) -> Option<(&'static str, LabelFn)> {
  Some(match tag {
    0 => ("SetButtonCrossKeysFunc", |v| {
      Some(match v {
        0 => "Set: Picture Style",
        1 => "Set: Quality",
        2 => "Set: Flash Exposure Comp",
        3 => "Set: Playback",
        4 => "Cross keys: AF point select",
        _ => return None,
      })
    }),
    1 => ("LongExposureNoiseReduction", |v| {
      Some(match v {
        0 => "Off",
        1 => "Auto",
        2 => "On",
        _ => return None,
      })
    }),
    2 => ("FlashSyncSpeedAv", flash_sync_200),
    3 => ("Shutter-AELock", shutter_ae_lock),
    4 => ("AFAssistBeam", af_assist_beam_3),
    5 => ("ExposureLevelIncrements", exposure_level_third_half),
    6 => ("MirrorLockup", disable_enable),
    7 => ("ETTLII", ettl_ii),
    8 => ("ShutterCurtainSync", curtain_sync),
    9 => ("MagnifiedView", magnified_view),
    10 => ("LCDDisplayAtPowerOn", |v| {
      Some(match v {
        0 => "Display",
        1 => "Retain power off status",
        _ => return None,
      })
    }),
    _ => return None,
  })
}

/// One `%CanonCustom::FunctionsD30` record (`CanonCustom.pm:973-1084`) — the
/// shared EOS D30/D60 table. Tags 1..=15 are named.
fn functions_d30_entry(tag: u8) -> Option<(&'static str, LabelFn)> {
  Some(match tag {
    1 => ("LongExposureNoiseReduction", off_on),
    2 => ("Shutter-AELock", |v| {
      Some(match v {
        0 => "AF/AE lock",
        1 => "AE lock/AF",
        2 => "AF/AF lock",
        3 => "AE+release/AE+AF",
        _ => return None,
      })
    }),
    3 => ("MirrorLockup", disable_enable),
    4 => ("ExposureLevelIncrements", |v| {
      Some(match v {
        0 => "1/2 Stop",
        1 => "1/3 Stop",
        _ => return None,
      })
    }),
    5 => ("AFAssist", |v| {
      Some(match v {
        0 => "Emits/Fires",
        1 => "Does not emit/Fires",
        2 => "Only ext. flash emits/Fires",
        3 => "Emits/Does not fire",
        _ => return None,
      })
    }),
    6 => ("FlashSyncSpeedAv", flash_sync_200),
    7 => ("AEBSequenceAutoCancel", aeb_sequence_auto_cancel),
    8 => ("ShutterCurtainSync", curtain_sync),
    9 => ("LensAFStopButton", |v| {
      Some(match v {
        0 => "AF Stop",
        1 => "Operate AF",
        2 => "Lock AE and start timer",
        _ => return None,
      })
    }),
    10 => ("FillFlashAutoReduction", enable_disable),
    11 => ("MenuButtonReturn", |v| {
      Some(match v {
        0 => "Top",
        1 => "Previous (volatile)",
        2 => "Previous",
        _ => return None,
      })
    }),
    12 => ("SetButtonWhenShooting", |v| {
      Some(match v {
        0 => "Default (no function)",
        1 => "Image quality",
        2 => "Change ISO speed",
        3 => "Change parameters",
        _ => return None,
      })
    }),
    13 => ("SensorCleaning", disable_enable),
    14 => ("SuperimposedDisplay", on_off),
    15 => ("ShutterReleaseNoCFCard", yes_no),
    _ => return None,
  })
}

/// `{ 0 => 'Yes', 1 => 'No' }` — `ShutterReleaseNoCFCard` (1D/10D/D30).
fn yes_no(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Yes",
    1 => "No",
    _ => return None,
  })
}

/// `{ 0 => '1st-curtain sync', 1 => '2nd-curtain sync' }` — `ShutterCurtainSync`
/// (every pre-Mark-III body table).
fn curtain_sync(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "1st-curtain sync",
    1 => "2nd-curtain sync",
    _ => return None,
  })
}

/// `AEBSequenceAutoCancel` (1D/10D/20D/30D/D30) — `{ 0,-,+/Enabled; …}`.
fn aeb_sequence_auto_cancel(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "0,-,+/Enabled",
    1 => "0,-,+/Disabled",
    2 => "-,0,+/Enabled",
    3 => "-,0,+/Disabled",
    _ => return None,
  })
}

/// `Shutter-AELock` 4-value form (10D/20D/30D/350D/400D).
fn shutter_ae_lock(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "AF/AE lock",
    1 => "AE lock/AF",
    2 => "AF/AF lock, No AE lock",
    3 => "AE/AF, No AE lock",
    _ => return None,
  })
}

/// `ETTLII` (20D/30D/350D/400D) — `{ 0 => 'Evaluative', 1 => 'Average' }`.
fn ettl_ii(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Evaluative",
    1 => "Average",
    _ => return None,
  })
}

/// `AFAssistBeam` 3-value form (20D/30D/350D/400D).
fn af_assist_beam_3(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Emits",
    1 => "Does not emit",
    2 => "Only ext. flash emits",
    _ => return None,
  })
}

/// `MagnifiedView` (30D/400D).
fn magnified_view(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Image playback only",
    1 => "Image review and playback",
    _ => return None,
  })
}

/// `MenuButtonDisplayPosition` (10D/20D/30D).
fn menu_button_display_position(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Previous (top if power off)",
    1 => "Previous",
    2 => "Top",
    _ => return None,
  })
}

/// `AFPointSelectionMethod` (20D/30D).
fn af_point_selection_method(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Normal",
    1 => "Multi-controller direct",
    2 => "Quick Control Dial direct",
    _ => return None,
  })
}

/// `LensAFStopButton` 6-value form (20D/30D — same labels as the 5D table).
fn lens_af_stop_button(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "AF stop",
    1 => "AF start",
    2 => "AE lock while metering",
    3 => "AF point: M -> Auto / Auto -> Ctr.",
    4 => "ONE SHOT <-> AI SERVO",
    5 => "IS start",
    _ => return None,
  })
}

/// `SetFunctionWhenShooting` (20D) — `{ 0 => 'Default (no function)', … }`.
fn set_function_when_shooting(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Default (no function)",
    1 => "Change quality",
    2 => "Change Parameters",
    3 => "Menu display",
    4 => "Image replay",
    _ => return None,
  })
}

/// `ExposureLevelIncrements` `{ 0 => '1/3 Stop', 1 => '1/2 Stop' }`
/// (20D/30D/350D/400D).
fn exposure_level_third_half(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "1/3 Stop",
    1 => "1/2 Stop",
    _ => return None,
  })
}

/// `FlashSyncSpeedAv` `{ 0 => 'Auto', 1 => '1/200 Fixed' }` (10D/350D/400D/D30).
fn flash_sync_200(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Auto",
    1 => "1/200 Fixed",
    _ => return None,
  })
}

/// `FlashSyncSpeedAv` `{ 0 => 'Auto', 1 => '1/250 Fixed' }` (20D/30D).
fn flash_sync_250(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Auto",
    1 => "1/250 Fixed",
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

/// `{0=>'Normal',1=>'Reversed'}` (ControlRingRotation / FocusRingRotation).
fn normal_reversed(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Normal",
    1 => "Reversed",
    _ => return None,
  })
}

/// `RFLensMFFocusRingSensitivity` PrintConv (`CanonCustom.pm:1259-1264`).
fn rf_lens_mf_sensitivity_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Varies With Rotation Speed",
    1 => "Linked To Rotation Angle",
    _ => return None,
  })
}

/// `SameExposureForNewAperture` PrintConv (`CanonCustom.pm:367-374`, 5DS arm).
fn same_exposure_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Disable",
    1 => "ISO Speed",
    2 => "Shutter Speed",
    _ => return None,
  })
}

/// `DefaultEraseOption` PrintConv (`CanonCustom.pm:1401-1409`).
fn default_erase_option_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Cancel selected",
    1 => "Erase selected",
    2 => "Erase RAW selected",
    3 => "Erase non-RAW selected",
    _ => return None,
  })
}

/// `AEBShotCount` single-value PrintConv render: the label, or `Unknown (N)`.
fn aeb_shots_hash(v: i64, label: fn(i64) -> Option<&'static str>) -> TagValue {
  match label(v) {
    Some(l) => TagValue::Str(SmolStr::new_static(l)),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
  }
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
    // 0x715 CustomizeDials (no PrintConv — passthrough; `CanonCustom.pm:1265`).
    0x715 => return Some(("CustomizeDials", joined(num, vals))),
    // 0x106 AEBShotCount — model + count conditional list (`CanonCustom.pm:95`).
    0x106 => {
      let value = if !print_conv {
        joined(num, vals)
      } else if model_has(model, "90D") {
        // Arm 1 (EOS 90D): the shot count keys directly.
        aeb_shots_hash(v0, |n| match n {
          2 => Some("2 shots"),
          3 => Some("3 shots"),
          5 => Some("5 shots"),
          7 => Some("7 shots"),
          _ => None,
        })
      } else if num == 1 {
        // Arm 2 (other models, single value): the EOS R path.
        aeb_shots_hash(v0, |n| match n {
          0 => Some("3 shots"),
          1 => Some("2 shots"),
          2 => Some("5 shots"),
          3 => Some("7 shots"),
          _ => None,
        })
      } else {
        // Arm 3 (Count 2): the space-joined pair keys the label.
        let key = space_joined(vals);
        match key.as_str() {
          "3 0" => TagValue::Str(SmolStr::new_static("3 shots")),
          "2 1" => TagValue::Str(SmolStr::new_static("2 shots")),
          "5 2" => TagValue::Str(SmolStr::new_static("5 shots")),
          "7 3" => TagValue::Str(SmolStr::new_static("7 shots")),
          _ => TagValue::Str(SmolStr::from(std::format!("Unknown ({key})"))),
        }
      };
      return Some(("AEBShotCount", value));
    }
    // 0x10c ShutterSpeedRange (EOS R, Count 4 — `CanonCustom.pm:1410-1436`).
    // Per-element ValueConv `exp(-$val/(1600*log(2)))`; positional PrintConv
    // "Manual: Hi"/"Lo"/"Auto: Hi"/"Lo" + `PrintExposureTime`, joined "; ". `-n`
    // is the space-joined ValueConv values (Perl `%.15g`).
    0x10c if num == 4 => {
      let vc = |r: i64| (-(r as f64) / (1600.0 * core::f64::consts::LN_2)).exp();
      let value = if print_conv {
        const PFX: [&str; 4] = ["Manual: Hi ", "Lo ", "Auto: Hi ", "Lo "];
        let s = vals
          .iter()
          .zip(PFX)
          .map(|(&r, p)| {
            std::format!(
              "{p}{}",
              crate::composite::convs::exif::print_exposure_time(vc(r))
            )
          })
          .collect::<Vec<_>>()
          .join("; ");
        TagValue::Str(SmolStr::from(s))
      } else {
        let s = vals
          .iter()
          .map(|&r| crate::value::format_g(vc(r), 15))
          .collect::<Vec<_>>()
          .join(" ");
        TagValue::Str(SmolStr::from(s))
      };
      return Some(("ShutterSpeedRange", value));
    }
    // 0x10d ApertureRange (EOS R, Count 4 — `CanonCustom.pm:1463-1490`).
    // Per-element ValueConv `exp($val/2400)`; positional PrintConv "Manual:
    // Closed"/"Open"/"Auto: Closed"/"Open" + `%.2g`, joined "; ". `-n` is the
    // space-joined ValueConv values (Perl `%.15g`).
    0x10d if num == 4 => {
      let vc = |r: i64| ((r as f64) / 2400.0).exp();
      let value = if print_conv {
        const PFX: [&str; 4] = ["Manual: Closed ", "Open ", "Auto: Closed ", "Open "];
        let s = vals
          .iter()
          .zip(PFX)
          .map(|(&r, p)| std::format!("{p}{}", crate::value::format_g(vc(r), 2)))
          .collect::<Vec<_>>()
          .join("; ");
        TagValue::Str(SmolStr::from(s))
      } else {
        let s = vals
          .iter()
          .map(|&r| crate::value::format_g(vc(r), 15))
          .collect::<Vec<_>>()
          .join(" ");
        TagValue::Str(SmolStr::from(s))
      };
      return Some(("ApertureRange", value));
    }
    // 0x114 AELockMeterModeAfterFocus — `BITMASK` (DecodeBits, `CanonCustom.pm:388`).
    0x114 => {
      let value = if print_conv {
        TagValue::Str(SmolStr::from(crate::convert::decode_bits(
          &v0.to_string(),
          Some(&[
            (0, "Evaluative"),
            (1, "Partial"),
            (2, "Spot"),
            (3, "Center-weighted"),
          ]),
          0,
        )))
      } else {
        TagValue::I64(v0)
      };
      return Some(("AELockMeterModeAfterFocus", value));
    }
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
    // EOS-R-era CustomFunctions2 leaves (`CanonCustom.pm`).
    0x112 => ("SameExposureForNewAperture", same_exposure_label),
    0x711 => ("ShutterReleaseWithoutLens", disable_enable),
    0x712 => ("ControlRingRotation", normal_reversed),
    0x713 => ("FocusRingRotation", normal_reversed),
    0x714 => ("RFLensMFFocusRingSensitivity", rf_lens_mf_sensitivity_label),
    0x813 => ("DefaultEraseOption", default_erase_option_label),
    0x814 => ("RetractLensOnPowerOff", enable_disable),
    0x815 => ("AddIPTCInformation", disable_enable),
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

// ─── PersonalFuncs (`Canon::Main` 0x91) ──────────────────────────────────────

/// Decode `%CanonCustom::PersonalFuncs` (`CanonCustom.pm:1091-1133`) — the
/// EOS-1D personal-function on/off flags. `ProcessBinaryData`, `FORMAT =>
/// 'int16u'`, `FIRST_ENTRY => 1`: a named position `index` reads the `int16u` at
/// byte offset `index * 2` (the size word at offset 0 is index 0, unread). Each
/// flag renders via [`convert_pfn`] (`%convPFn`). A position past the block end
/// is dropped (per-field availability — bundled `next unless defined $val`).
#[must_use]
pub fn parse_personal_funcs(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  for &(index, name) in PERSONAL_FUNCS {
    let Some(v) = u16_at(data, usize::from(index) * 2, order) else {
      continue;
    };
    let v = v as i64;
    let value = if print_conv {
      TagValue::Str(convert_pfn(v))
    } else {
      TagValue::I64(v)
    };
    out.push((SmolStr::new_static(name), value));
  }
  out
}

/// `%convPFn` PrintConv (`CanonCustom.pm:2622-2627`, `sub ConvertPfn`):
/// `0 => 'Off'`, `1 => 'On'`, otherwise `'On (N)'`.
fn convert_pfn(v: i64) -> SmolStr {
  match v {
    0 => SmolStr::new_static("Off"),
    1 => SmolStr::new_static("On"),
    n => SmolStr::from(std::format!("On ({n})")),
  }
}

/// `(index, Name)` for `%CanonCustom::PersonalFuncs` (`CanonCustom.pm:1100-1132`).
/// Indices 12/13 (`PF11`/`PF12`) and 23 (`PF22`) are commented out in bundled
/// (unused) and are absent here.
const PERSONAL_FUNCS: &[(u16, &str)] = &[
  (1, "PF0CustomFuncRegistration"),
  (2, "PF1DisableShootingModes"),
  (3, "PF2DisableMeteringModes"),
  (4, "PF3ManualExposureMetering"),
  (5, "PF4ExposureTimeLimits"),
  (6, "PF5ApertureLimits"),
  (7, "PF6PresetShootingModes"),
  (8, "PF7BracketContinuousShoot"),
  (9, "PF8SetBracketShots"),
  (10, "PF9ChangeBracketSequence"),
  (11, "PF10RetainProgramShift"),
  (14, "PF13DrivePriority"),
  (15, "PF14DisableFocusSearch"),
  (16, "PF15DisableAFAssistBeam"),
  (17, "PF16AutoFocusPointShoot"),
  (18, "PF17DisableAFPointSel"),
  (19, "PF18EnableAutoAFPointSel"),
  (20, "PF19ContinuousShootSpeed"),
  (21, "PF20LimitContinousShots"),
  (22, "PF21EnableQuietOperation"),
  (24, "PF23SetTimerLengths"),
  (25, "PF24LightLCDDuringBulb"),
  (26, "PF25DefaultClearSettings"),
  (27, "PF26ShortenReleaseLag"),
  (28, "PF27ReverseDialRotation"),
  (29, "PF28NoQuickDialExpComp"),
  (30, "PF29QuickDialSwitchOff"),
  (31, "PF30EnlargementMode"),
  (32, "PF31OriginalDecisionData"),
];

// ─── PersonalFuncValues (`Canon::Main` 0x92) ─────────────────────────────────

/// The per-position conversion for `%CanonCustom::PersonalFuncValues`.
#[derive(Clone, Copy)]
enum PfvConv {
  /// No `ValueConv`/`PrintConv` — the raw `int16u` in both `-j` and `-n`.
  Plain,
  /// `PF4ExposureTimeMin`/`Max` (`CanonCustom.pm:1155-1170`): `ValueConv =>
  /// 'exp(-CanonEv($val*4)*log(2))*1000/8'`, `PrintConv => PrintExposureTime`.
  ExposureTime,
  /// `PF5ApertureMin`/`Max` (`CanonCustom.pm:1171-1186`): `ValueConv =>
  /// 'exp(CanonEv($val*4-32)*log(2)/2)'`, `PrintConv => 'sprintf("%.2g",$val)'`.
  Aperture,
}

/// Decode `%CanonCustom::PersonalFuncValues` (`CanonCustom.pm:1135-1197`) — the
/// EOS-1D personal-function values reached via the `Canon::Main` 0x92
/// SubDirectory (`Canon.pm:1810-1816`). `ProcessBinaryData`, `FORMAT =>
/// 'int16u'`, `FIRST_ENTRY => 1`: position `index` reads the `int16u` at byte
/// offset `index * 2`. Most positions are passthrough; the four exposure-time /
/// aperture positions carry a `CanonEv`-based `ValueConv` (emitted as the
/// converted float in `-n`) and a `PrintExposureTime` / `%.2g` `PrintConv`.
/// A position past the block end is dropped (per-field availability). The
/// `RawConv => '$val > 0 ? $val : 0'` is an identity for the `int16u` read here.
#[must_use]
pub fn parse_personal_func_values(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
) -> Vec<(SmolStr, TagValue)> {
  use super::camera_settings::canon_ev;
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  for &(index, name, conv) in PERSONAL_FUNC_VALUES {
    let Some(raw) = u16_at(data, usize::from(index) * 2, order) else {
      continue;
    };
    let raw = raw as i64;
    let value = match conv {
      PfvConv::Plain => TagValue::I64(raw),
      PfvConv::ExposureTime => {
        let vc = (-canon_ev(raw * 4) * core::f64::consts::LN_2).exp() * 1000.0 / 8.0;
        if print_conv {
          TagValue::Str(SmolStr::from(
            crate::composite::convs::exif::print_exposure_time(vc),
          ))
        } else {
          TagValue::F64(vc)
        }
      }
      PfvConv::Aperture => {
        let vc = (canon_ev(raw * 4 - 32) * core::f64::consts::LN_2 / 2.0).exp();
        if print_conv {
          TagValue::Str(SmolStr::from(crate::value::format_g(vc, 2)))
        } else {
          TagValue::F64(vc)
        }
      }
    };
    out.push((SmolStr::new_static(name), value));
  }
  out
}

/// `(index, Name, conv)` for `%CanonCustom::PersonalFuncValues`
/// (`CanonCustom.pm:1144-1196`).
const PERSONAL_FUNC_VALUES: &[(u16, &str, PfvConv)] = &[
  (1, "PF1Value", PfvConv::Plain),
  (2, "PF2Value", PfvConv::Plain),
  (3, "PF3Value", PfvConv::Plain),
  (4, "PF4ExposureTimeMin", PfvConv::ExposureTime),
  (5, "PF4ExposureTimeMax", PfvConv::ExposureTime),
  (6, "PF5ApertureMin", PfvConv::Aperture),
  (7, "PF5ApertureMax", PfvConv::Aperture),
  (8, "PF8BracketShots", PfvConv::Plain),
  (9, "PF19ShootingSpeedLow", PfvConv::Plain),
  (10, "PF19ShootingSpeedHigh", PfvConv::Plain),
  (11, "PF20MaxContinousShots", PfvConv::Plain),
  (12, "PF23ShutterButtonTime", PfvConv::Plain),
  (13, "PF23FELockTime", PfvConv::Plain),
  (14, "PF23PostReleaseTime", PfvConv::Plain),
  (15, "PF25AEMode", PfvConv::Plain),
  (16, "PF25MeteringMode", PfvConv::Plain),
  (17, "PF25DriveMode", PfvConv::Plain),
  (18, "PF25AFMode", PfvConv::Plain),
  (19, "PF25AFPointSel", PfvConv::Plain),
  (20, "PF25ImageSize", PfvConv::Plain),
  (21, "PF25WBMode", PfvConv::Plain),
  (22, "PF25Parameters", PfvConv::Plain),
  (23, "PF25ColorMatrix", PfvConv::Plain),
  (24, "PF27Value", PfvConv::Plain),
];

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

  /// Build a `ProcessCanonCustom` block from `(tag, int8u)` pairs: the leading
  /// `int16u` length word (the byte size) then one `int16u` record per pair
  /// (`tag << 8 | value`), little-endian.
  fn build_custom(pairs: &[(u8, u8)]) -> Vec<u8> {
    let size = (pairs.len() + 1) * 2;
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&(size as u16).to_le_bytes());
    for &(t, v) in pairs {
      out.extend_from_slice(&((u16::from(t) << 8) | u16::from(v)).to_le_bytes());
    }
    out
  }

  fn find(em: &[(SmolStr, TagValue)], n: &str) -> Option<TagValue> {
    em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone())
  }

  fn want_str(em: &[(SmolStr, TagValue)], n: &str, label: &str) {
    assert_eq!(find(em, n), Some(TagValue::Str(label.into())), "{n}");
  }

  /// The `0x0f` conditional list selects the per-body table by Model in the
  /// SAME order as bundled — the `EOS-1D` arm precedes `EOS 5D` (`Canon.pm:1502`
  /// before `:1510`), and an unmatched model falls to the tagless `FuncsUnknown`.
  #[test]
  fn custom_functions_model_select() {
    // tag 0 distinguishes the 1D table ("Ec-N, R") from the 5D table ("Ee-A").
    let blk = build_custom(&[(0, 0)]);
    let sel = |m: Option<&str>| parse_custom_functions(&blk, ByteOrder::Little, true, m);
    want_str(
      &sel(Some("Canon EOS-1D Mark II")),
      "FocusingScreen",
      "Ec-N, R",
    );
    want_str(&sel(Some("Canon EOS 5D")), "FocusingScreen", "Ee-A");
    // FuncsUnknown / no model → nothing.
    assert!(sel(Some("Canon EOS 1100D")).is_empty());
    assert!(sel(None).is_empty());
  }

  /// `\b(350D|REBEL XT|…)\b` vs `\b(400D|REBEL XTi|…)\b` (`Canon.pm:1543`/`:1551`)
  /// — the word boundary keeps "REBEL XTi" (a 400D) off the 350D `REBEL XT` arm.
  #[test]
  fn rebel_xt_vs_xti_word_boundary() {
    let blk = build_custom(&[(0, 0)]);
    let sel = |m: &str| parse_custom_functions(&blk, ByteOrder::Little, true, Some(m));
    // 350D tag-0 label is "Normal"; the 400D tag-0 label is "Set: Picture Style".
    want_str(
      &sel("Canon EOS REBEL XT"),
      "SetButtonCrossKeysFunc",
      "Normal",
    );
    want_str(
      &sel("Canon EOS REBEL XTi"),
      "SetButtonCrossKeysFunc",
      "Set: Picture Style",
    );
    want_str(
      &sel("Canon EOS Kiss Digital N"),
      "SetButtonCrossKeysFunc",
      "Normal",
    );
    want_str(
      &sel("Canon EOS Kiss Digital X"),
      "SetButtonCrossKeysFunc",
      "Set: Picture Style",
    );
  }

  /// D30 and D60 share `%FunctionsD30`; the `/EOS D30\b/` trailing boundary keeps
  /// a hypothetical "EOS D3000" off the arm.
  #[test]
  fn d30_d60_share_table_and_boundary() {
    let blk = build_custom(&[(11, 1)]); // MenuButtonReturn = "Previous (volatile)"
    for model in ["Canon EOS D30", "Canon EOS D60"] {
      want_str(
        &parse_custom_functions(&blk, ByteOrder::Little, true, Some(model)),
        "MenuButtonReturn",
        "Previous (volatile)",
      );
    }
    assert!(
      parse_custom_functions(&blk, ByteOrder::Little, true, Some("Canon EOS D3000")).is_empty()
    );
  }

  /// `%CanonCustom::Functions1D` (`CanonCustom.pm:41-227`) — the 0x90 direct tag.
  #[test]
  fn functions_1d_decodes() {
    let data = build_custom(&[(0, 0), (5, 2), (19, 4), (21, 1)]);
    let em = parse_functions_1d(&data, ByteOrder::Little, true);
    want_str(&em, "FocusingScreen", "Ec-N, R");
    want_str(&em, "ManualTv", "Tv=Main/Av=Main w/o lens");
    want_str(&em, "LensAFStopButton", "AF mode: ONE SHOT <-> AI SERVO");
    want_str(
      &em,
      "AIServoContinuousShooting",
      "Shooting possible without focus",
    );
    assert_eq!(em.len(), 4);
  }

  /// Spot-check each per-body table's distinctive tags + shared PrintConv helpers.
  #[test]
  fn per_body_tables_decode() {
    let pc = |model: &str, pairs: &[(u8, u8)]| {
      parse_custom_functions(&build_custom(pairs), ByteOrder::Little, true, Some(model))
    };
    let em = pc("Canon EOS 10D", &[(1, 2), (5, 2), (17, 3)]);
    want_str(&em, "SetButtonWhenShooting", "Change parameters");
    want_str(&em, "AFAssist", "Only ext. flash emits/Fires");
    want_str(&em, "LensAFStopButton", "AF point: M->Auto/Auto->ctr");

    let em = pc("Canon EOS 20D", &[(0, 1), (13, 1), (16, 4)]);
    want_str(&em, "SetFunctionWhenShooting", "Change quality");
    want_str(&em, "ETTLII", "Average");
    want_str(&em, "LensAFStopButton", "ONE SHOT <-> AI SERVO");

    let em = pc("Canon EOS 30D", &[(1, 2), (17, 1), (2, 1)]);
    want_str(&em, "SetFunctionWhenShooting", "Change Picture Style");
    want_str(&em, "MagnifiedView", "Image review and playback");
    want_str(&em, "LongExposureNoiseReduction", "Auto");

    let em = pc("Canon EOS 350D", &[(0, 4), (5, 1)]);
    want_str(&em, "SetButtonCrossKeysFunc", "Cross keys: AF point select");
    want_str(&em, "ExposureLevelIncrements", "1/2 Stop");

    let em = pc("Canon EOS 400D", &[(2, 1), (10, 1)]);
    want_str(&em, "FlashSyncSpeedAv", "1/200 Fixed");
    want_str(&em, "LCDDisplayAtPowerOn", "Retain power off status");

    let em = pc("Canon EOS D30", &[(13, 1), (5, 3)]);
    want_str(&em, "SensorCleaning", "Enable");
    want_str(&em, "AFAssist", "Emits/Does not fire");
  }

  /// Numeric mode keeps the raw `int8u`; an unnamed tag is dropped; an
  /// out-of-range value renders `Unknown (N)`.
  #[test]
  fn custom_functions_numeric_and_unknown() {
    let data = build_custom(&[(0, 1), (99, 7), (21, 1)]);
    let em = parse_functions_1d(&data, ByteOrder::Little, false);
    assert_eq!(find(&em, "FocusingScreen"), Some(TagValue::I64(1)));
    assert_eq!(
      find(&em, "AIServoContinuousShooting"),
      Some(TagValue::I64(1))
    );
    assert_eq!(em.len(), 2); // the unnamed tag 99 is dropped
    let em2 = parse_functions_1d(&build_custom(&[(0, 9)]), ByteOrder::Little, true);
    want_str(&em2, "FocusingScreen", "Unknown (9)");
  }

  /// `ProcessCanonCustom` (`CanonCustom.pm:2782-2785`) REJECTS the whole block
  /// when the offset-0 `int16u` length word does not equal the block size — it
  /// is NOT clamped to the declared length. A length shorter than the buffer
  /// (trailing record-shaped padding) and a length longer than the buffer both
  /// emit nothing; only an exact `len == size` decodes.
  #[test]
  fn rejects_length_word_mismatch() {
    // Sanity: an exact `len == size` block decodes its four 1D records.
    let exact = build_custom(&[(0, 0), (5, 2), (19, 4), (21, 1)]);
    assert_eq!(parse_functions_1d(&exact, ByteOrder::Little, true).len(), 4);

    // SHORTER: declared len = 4, but three record-shaped words follow (size = 8)
    // — a full walk would decode them; ExifTool rejects (len != size) → nothing.
    let shorter = build_u16(&[4, 0x0000, 0x0500, 0x1304]);
    assert_eq!(shorter.len(), 8);
    assert!(parse_functions_1d(&shorter, ByteOrder::Little, true).is_empty());
    assert!(
      parse_custom_functions(&shorter, ByteOrder::Little, true, Some("Canon EOS 5D")).is_empty()
    );

    // LONGER: declared len = 0xffff overruns the 8-byte buffer → rejected, no OOB.
    let longer = build_u16(&[0xffff, 0x0000, 0x0500, 0x1304]);
    assert!(parse_functions_1d(&longer, ByteOrder::Little, true).is_empty());
    assert!(parse_functions_5d(&longer, ByteOrder::Little, true).is_empty());
  }

  /// The lone `ProcessCanonCustom` length tolerance (`CanonCustom.pm:2782`): an
  /// EOS D60 whose declared length is 2 bytes short of the block
  /// (`$$et{Model} =~ /\bD60\b/ and $len+2 == $size`) still decodes; the same
  /// 2-short block on any other body is rejected.
  #[test]
  fn d60_length_word_two_short() {
    // len = 4, then two FunctionsD30 records → size = 6 (= len + 2).
    let blk = build_u16(&[4, 0x0101, 0x0300]);
    assert_eq!(blk.len(), 6);
    let em = parse_custom_functions(&blk, ByteOrder::Little, true, Some("Canon EOS D60"));
    want_str(&em, "LongExposureNoiseReduction", "On");
    want_str(&em, "MirrorLockup", "Disable");
    assert_eq!(em.len(), 2);
    // A non-D60 body (D30, which shares the table) with the same 2-short length
    // falls to the gate.
    assert!(
      parse_custom_functions(&blk, ByteOrder::Little, true, Some("Canon EOS D30")).is_empty()
    );
  }

  /// Build a `%CanonCustom::PersonalFuncs`/`PersonalFuncValues` `int16u` block
  /// from `words` (word 0 is the unread size; named positions start at index 1).
  fn build_u16(words: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 2);
    for w in words {
      out.extend_from_slice(&w.to_le_bytes());
    }
    out
  }

  /// `%CanonCustom::PersonalFuncs` (`CanonCustom.pm:1091-1133`) — `int16u`,
  /// `FIRST_ENTRY 1`; each flag renders via `ConvertPfn`.
  #[test]
  fn personal_funcs_decode() {
    let mut words = [0u16; 33]; // indices 0..=32
    words[1] = 0; // PF0CustomFuncRegistration = Off
    words[2] = 1; // PF1DisableShootingModes = On
    words[8] = 5; // PF7BracketContinuousShoot = On (5)
    words[32] = 1; // PF31OriginalDecisionData = On
    let em = parse_personal_funcs(&build_u16(&words), ByteOrder::Little, true);
    want_str(&em, "PF0CustomFuncRegistration", "Off");
    want_str(&em, "PF1DisableShootingModes", "On");
    want_str(&em, "PF7BracketContinuousShoot", "On (5)");
    want_str(&em, "PF31OriginalDecisionData", "On");
    // 29 named indices (1..=32 minus the unused 12/13/23).
    assert_eq!(em.len(), 29);
  }

  /// Per-field availability: a position past the block end is dropped; numeric
  /// mode keeps the raw `int16u`.
  #[test]
  fn personal_funcs_per_field_and_numeric() {
    // 6 words = 12 bytes ⇒ indices 0..=5 present; index 6 (offset 12) is past.
    let em = parse_personal_funcs(&build_u16(&[0, 9, 0, 0, 0, 2]), ByteOrder::Little, false);
    assert_eq!(
      find(&em, "PF0CustomFuncRegistration"),
      Some(TagValue::I64(9))
    );
    assert_eq!(find(&em, "PF4ExposureTimeLimits"), Some(TagValue::I64(2)));
    assert_eq!(find(&em, "PF5ApertureLimits"), None); // index 6, dropped
    assert_eq!(em.len(), 5);
  }

  /// `%CanonCustom::PersonalFuncValues` (`CanonCustom.pm:1135-1197`) — `-j`:
  /// plain positions pass through; the exposure-time / aperture positions render
  /// their `CanonEv` `ValueConv` via `PrintExposureTime` / `%.2g`. The expected
  /// labels are ground-truthed against the bundled Perl.
  #[test]
  fn personal_func_values_print() {
    let mut words = [0u16; 25]; // indices 0..=24
    words[1] = 100; // PF1Value (plain)
    words[4] = 32; // PF4ExposureTimeMin -> 7.8125 -> "7.8"
    words[5] = 64; // PF4ExposureTimeMax -> 0.48828125 -> "0.5"
    words[6] = 8; // PF5ApertureMin -> f/1.0 -> "1"
    words[7] = 40; // PF5ApertureMax -> f/4.0 -> "4"
    words[8] = 3; // PF8BracketShots (plain)
    words[24] = 7; // PF27Value (plain)
    let em = parse_personal_func_values(&build_u16(&words), ByteOrder::Little, true);
    assert_eq!(find(&em, "PF1Value"), Some(TagValue::I64(100)));
    want_str(&em, "PF4ExposureTimeMin", "7.8");
    want_str(&em, "PF4ExposureTimeMax", "0.5");
    want_str(&em, "PF5ApertureMin", "1");
    want_str(&em, "PF5ApertureMax", "4");
    assert_eq!(find(&em, "PF8BracketShots"), Some(TagValue::I64(3)));
    assert_eq!(find(&em, "PF27Value"), Some(TagValue::I64(7)));
    assert_eq!(em.len(), 24); // indices 1..=24 all present
  }

  /// `-n`: the converted `ValueConv` float for the exposure-time / aperture
  /// positions, raw `int16u` for plain; a position past the block end is dropped.
  #[test]
  fn personal_func_values_numeric_and_per_field() {
    let mut words = [0u16; 8]; // indices 0..=7 (16 bytes)
    words[1] = 100;
    words[4] = 0; // PF4ExposureTimeMin raw 0 -> ValueConv 125.0
    words[6] = 8; // PF5ApertureMin raw 8 -> ValueConv f/1.0
    let em = parse_personal_func_values(&build_u16(&words), ByteOrder::Little, false);
    assert_eq!(find(&em, "PF1Value"), Some(TagValue::I64(100)));
    assert_eq!(find(&em, "PF4ExposureTimeMin"), Some(TagValue::F64(125.0)));
    assert_eq!(find(&em, "PF5ApertureMin"), Some(TagValue::F64(1.0)));
    // index 8 (PF8BracketShots, offset 16) is past the 16-byte block.
    assert_eq!(find(&em, "PF8BracketShots"), None);
    assert_eq!(em.len(), 7); // indices 1..=7
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
