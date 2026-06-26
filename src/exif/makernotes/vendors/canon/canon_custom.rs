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
//! `CanonCustom.pm:228-383`, selected by `$$self{Model} =~ /EOS 5D/`). The
//! emitted leaves land in the `CanonCustom` family-1 group (the
//! `Image::ExifTool::CanonCustom::*` package group), NOT `Canon`.
//!
//! D8: pure decoder (no public struct fields); returns the `(Name, TagValue)`
//! emission pairs the dispatch site wraps in the `CanonCustom` family-1 group.

#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::ByteOrder;
use crate::value::TagValue;
use smol_str::SmolStr;
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
}
