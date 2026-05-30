// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Canon::FileInfo` (`Canon.pm:6842-7140`).
//!
//! Binary-data sub-table — `FORMAT => 'int16s'`, `FIRST_ENTRY => 1`.
//!
//! Phase-2 scope: ports the model-agnostic tags (BracketMode=3,
//! BracketValue=4, BracketShotNumber=5, RawJpgQuality=6, RawJpgSize=7,
//! LongExposureNoiseReduction2=8, WBBracketMode=9, WBBracketValueAB=12,
//! WBBracketValueGM=13, FilterEffect=14, ToningEffect=15,
//! MacroMagnification=16, LiveViewShooting=19, FocusDistanceUpper=20,
//! FocusDistanceLower=21, ShutterMode=23, FlashExposureLock=25,
//! AntiFlicker=32, RFLensType=0x3d). FocusDistanceUpper (20) sets the
//! cross-position `FocusDistanceUpper2` DataMember (`Canon.pm:7023`) that
//! gates FocusDistanceLower (21, `Condition =>
//! '$$self{FocusDistanceUpper2}'`, `Canon.pm:7033`) — see [`parse`].
//!
//! MacroMagnification (16, `Canon.pm:6998-7005`, shared
//! `%ciMacroMagnification` at `Canon.pm:3124-3133`) is gated on TWO
//! cross-table inputs: the CameraSettings `$$self{LensType}` DataMember
//! (must equal 124, the MP-E 65mm) AND the body `$$self{Model}` (must NOT
//! be a 40D/450D/REBEL XSi/Kiss X2, which report a bogus value). Both are
//! threaded into [`parse`] by the Canon body walker (`super`).
//!
//! The model-conditional FileNumber/ShutterCount at position 1 is the
//! ONLY position still DEFERRED (to PR #164): each model has its own
//! bit-pattern interpretation; `Canon.pm:6848-6927` has six conditional
//! `$$self{Model} =~ /…/` variants.
//!
//! The table `FORMAT => 'int16s'` applies to every position EXCEPT
//! RFLensType (`0x3d`, `Canon.pm:7062`) and FocusDistanceUpper/Lower
//! (20/21, `Canon.pm:7024`/`:7034`), each `Format => 'int16u'` — see
//! [`FiFormat`].

use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

/// One FileInfo position.
#[derive(Debug, Clone, Copy)]
pub struct FileInfoTag {
  /// Word position.
  pub position: usize,
  /// Tag name.
  pub name: &'static str,
  /// On-disk word format. The table default is `int16s`
  /// (`Canon.pm:6845`); RFLensType (`0x3d`) and FocusDistanceUpper/Lower
  /// (20/21) override to `int16u` (`Canon.pm:7062`/`:7024`/`:7034`).
  pub format: FiFormat,
  /// PrintConv strategy.
  pub conv: FiPrintConv,
}

/// Per-position word format for a FileInfo entry. The `%Canon::FileInfo`
/// table default is `int16s` (`FORMAT => 'int16s'`, `Canon.pm:6845`);
/// RFLensType (`0x3d`, `Canon.pm:7062`) and FocusDistanceUpper/Lower
/// (20/21, `Canon.pm:7024`/`:7034`) override it with `Format => 'int16u'`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FiFormat {
  /// `int16s` — the table default.
  Int16s,
  /// `int16u` — RFLensType (`0x3d`) and FocusDistanceUpper/Lower (20/21).
  Int16u,
}

/// FileInfo per-tag PrintConv.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FiPrintConv {
  /// No PrintConv.
  None,
  /// `RawJpgQuality` (`Canon.pm:6941-6945`) — `%canonQuality`
  /// (`Canon.pm:1051-1061`); `RawConv => '$val<=0 ? undef : $val'`.
  RawJpgQuality,
  /// `RawJpgSize` (`Canon.pm:6946-6950`) — `%canonImageSize`
  /// (`Canon.pm:1062-1082`); `RawConv => '$val<0 ? undef : $val'`.
  RawJpgSize,
  /// `BracketMode` (`Canon.pm:6928-6937`).
  BracketMode,
  /// `WBBracketMode` (`Canon.pm:6965-6972`).
  WbBracketMode,
  /// `FilterEffect` (`Canon.pm:6975-6985`).
  FilterEffect,
  /// `ToningEffect` (`Canon.pm:6986-6996`).
  ToningEffect,
  /// `MacroMagnification` (pos 16, `Canon.pm:6998-7005`; shared
  /// `%ciMacroMagnification` at `Canon.pm:3124-3133`) — `int16s`,
  /// `ValueConv => 'exp((75-$val) * log(2) * 3 / 40)'`,
  /// `PrintConv => 'sprintf("%.1fx",$val)'`. Has BOTH a ValueConv and a
  /// PrintConv: `-n` emits the ValueConv `f64`, `-j` the `"%.1fx"` string.
  /// The position-16 `Condition` (`Canon.pm:7002-7005`,
  /// `$$self{LensType} == 124` AND `$$self{Model}` not an excluded body)
  /// is evaluated in [`parse`], not here.
  MacroMagnification,
  /// `LongExposureNoiseReduction2` (`Canon.pm:6950-6964`).
  LongExposureNR,
  /// `LiveViewShooting` (`Canon.pm:7012-7019`) — `%offOn`.
  LiveViewShooting,
  /// `FocusDistanceUpper` (pos 20, `Canon.pm:7021-7030`) /
  /// `FocusDistanceLower` (pos 21, `Canon.pm:7031-7039`) — `int16u`,
  /// `ValueConv => '$val / 100'`, `PrintConv => '$val > 655.345 ? "inf"
  /// : "$val m"'`. Position 20 additionally has `RawConv =>
  /// '($$self{FocusDistanceUpper2} = $val) || undef'` (sets the
  /// DataMember; drops the tag when raw is 0) and position 21 is gated by
  /// `Condition => '$$self{FocusDistanceUpper2}'`; both handled in
  /// [`parse`], not here.
  FocusDistance,
  /// `ShutterMode` (`Canon.pm:7041-7050`) — `{0=>'Mechanical',
  /// 1=>'Electronic First Curtain', 2=>'Electronic'}`.
  ShutterMode,
  /// `FlashExposureLock` (`Canon.pm:7052-7054`) — `%offOn`.
  FlashExposureLock,
  /// `AntiFlicker` (`Canon.pm:7056-7058`) — `%offOn`.
  AntiFlicker,
  /// `RFLensType` (`Canon.pm:7060-7142`) — `int16u`, lookup against the
  /// inline 76-entry RF-lens map (`Canon.pm:7063-7141`).
  RfLensType,
}

/// `%Canon::FileInfo` — sorted by position. Every entry is `int16s`
/// except RFLensType (`0x3d` = 61) and FocusDistanceUpper/Lower (20/21),
/// which are `int16u` (`Canon.pm:7062`/`:7024`/`:7034`).
///
/// Position DEFERRED (not in this table): 1 (FileNumber/ShutterCount —
/// six model-conditional bit-pattern variants, `Canon.pm:6848-6927`;
/// belongs to PR #164). Positions with no bundled entry at all: 2, 10,
/// 11, 17, 18, 22, 24, 26-31, 33-60 (commented-out / unallocated in
/// `%Canon::FileInfo`).
pub const FILE_INFO: &[FileInfoTag] = &[
  FileInfoTag {
    position: 3,
    name: "BracketMode",
    format: FiFormat::Int16s,
    conv: FiPrintConv::BracketMode,
  },
  FileInfoTag {
    position: 4,
    name: "BracketValue",
    format: FiFormat::Int16s,
    conv: FiPrintConv::None,
  },
  FileInfoTag {
    position: 5,
    name: "BracketShotNumber",
    format: FiFormat::Int16s,
    conv: FiPrintConv::None,
  },
  FileInfoTag {
    position: 6,
    name: "RawJpgQuality",
    format: FiFormat::Int16s,
    conv: FiPrintConv::RawJpgQuality,
  },
  FileInfoTag {
    position: 7,
    name: "RawJpgSize",
    format: FiFormat::Int16s,
    conv: FiPrintConv::RawJpgSize,
  },
  FileInfoTag {
    position: 8,
    name: "LongExposureNoiseReduction2",
    format: FiFormat::Int16s,
    conv: FiPrintConv::LongExposureNR,
  },
  FileInfoTag {
    position: 9,
    name: "WBBracketMode",
    format: FiFormat::Int16s,
    conv: FiPrintConv::WbBracketMode,
  },
  FileInfoTag {
    position: 12,
    name: "WBBracketValueAB",
    format: FiFormat::Int16s,
    conv: FiPrintConv::None,
  },
  FileInfoTag {
    position: 13,
    name: "WBBracketValueGM",
    format: FiFormat::Int16s,
    conv: FiPrintConv::None,
  },
  FileInfoTag {
    position: 14,
    name: "FilterEffect",
    format: FiFormat::Int16s,
    conv: FiPrintConv::FilterEffect,
  },
  FileInfoTag {
    position: 15,
    name: "ToningEffect",
    format: FiFormat::Int16s,
    conv: FiPrintConv::ToningEffect,
  },
  // `16 => MacroMagnification` (`Canon.pm:6998-7005`) — `int16s` (table
  // default). Gated by the position-16 `Condition` (`$$self{LensType} ==
  // 124` AND `$$self{Model}` not an excluded body), evaluated in [`parse`].
  FileInfoTag {
    position: 16,
    name: "MacroMagnification",
    format: FiFormat::Int16s,
    conv: FiPrintConv::MacroMagnification,
  },
  FileInfoTag {
    position: 19,
    name: "LiveViewShooting",
    format: FiFormat::Int16s,
    conv: FiPrintConv::LiveViewShooting,
  },
  // `20 => FocusDistanceUpper` (`Canon.pm:7021-7030`) — `Format =>
  // 'int16u'`. Sets the `FocusDistanceUpper2` DataMember; dropped when 0.
  FileInfoTag {
    position: 20,
    name: "FocusDistanceUpper",
    format: FiFormat::Int16u,
    conv: FiPrintConv::FocusDistance,
  },
  // `21 => FocusDistanceLower` (`Canon.pm:7031-7039`) — `Format =>
  // 'int16u'`, `Condition => '$$self{FocusDistanceUpper2}'`.
  FileInfoTag {
    position: 21,
    name: "FocusDistanceLower",
    format: FiFormat::Int16u,
    conv: FiPrintConv::FocusDistance,
  },
  // `23 => ShutterMode` (`Canon.pm:7041-7050`).
  FileInfoTag {
    position: 23,
    name: "ShutterMode",
    format: FiFormat::Int16s,
    conv: FiPrintConv::ShutterMode,
  },
  // `25 => FlashExposureLock` (`Canon.pm:7052-7054`) — `\%offOn`.
  FileInfoTag {
    position: 25,
    name: "FlashExposureLock",
    format: FiFormat::Int16s,
    conv: FiPrintConv::FlashExposureLock,
  },
  // `32 => AntiFlicker` (`Canon.pm:7056-7058`) — `\%offOn`.
  FileInfoTag {
    position: 32,
    name: "AntiFlicker",
    format: FiFormat::Int16s,
    conv: FiPrintConv::AntiFlicker,
  },
  // `0x3d => RFLensType` (`Canon.pm:7060-7142`) — `Format => 'int16u'`.
  FileInfoTag {
    position: 0x3d,
    name: "RFLensType",
    format: FiFormat::Int16u,
    conv: FiPrintConv::RfLensType,
  },
];

/// One `%Canon::FileInfo` RFLensType map entry (`Canon.pm:7063-7141`).
#[derive(Debug, Clone, Copy)]
struct RfLens {
  /// `int16u` RFLensType value (the hash key).
  key: u16,
  /// Human-readable RF-lens name (`Canon.pm` RHS).
  name: &'static str,
}

/// `RFLensType` PrintConv (`Canon.pm:7063-7141`), 76 entries, sorted by
/// `key`. Ported byte-for-byte; note the bundled hash has NO `322` key
/// (it jumps 321 → 323, `Canon.pm:7129-7130`).
const RF_LENS_TYPES: &[RfLens] = &[
  RfLens {
    key: 0,
    name: "n/a",
  },
  RfLens {
    key: 257,
    name: "Canon RF 50mm F1.2L USM",
  },
  RfLens {
    key: 258,
    name: "Canon RF 24-105mm F4L IS USM",
  },
  RfLens {
    key: 259,
    name: "Canon RF 28-70mm F2L USM",
  },
  RfLens {
    key: 260,
    name: "Canon RF 35mm F1.8 MACRO IS STM",
  },
  RfLens {
    key: 261,
    name: "Canon RF 85mm F1.2L USM",
  },
  RfLens {
    key: 262,
    name: "Canon RF 85mm F1.2L USM DS",
  },
  RfLens {
    key: 263,
    name: "Canon RF 24-70mm F2.8L IS USM",
  },
  RfLens {
    key: 264,
    name: "Canon RF 15-35mm F2.8L IS USM",
  },
  RfLens {
    key: 265,
    name: "Canon RF 24-240mm F4-6.3 IS USM",
  },
  RfLens {
    key: 266,
    name: "Canon RF 70-200mm F2.8L IS USM",
  },
  RfLens {
    key: 267,
    name: "Canon RF 85mm F2 MACRO IS STM",
  },
  RfLens {
    key: 268,
    name: "Canon RF 600mm F11 IS STM",
  },
  RfLens {
    key: 269,
    name: "Canon RF 600mm F11 IS STM + RF1.4x",
  },
  RfLens {
    key: 270,
    name: "Canon RF 600mm F11 IS STM + RF2x",
  },
  RfLens {
    key: 271,
    name: "Canon RF 800mm F11 IS STM",
  },
  RfLens {
    key: 272,
    name: "Canon RF 800mm F11 IS STM + RF1.4x",
  },
  RfLens {
    key: 273,
    name: "Canon RF 800mm F11 IS STM + RF2x",
  },
  RfLens {
    key: 274,
    name: "Canon RF 24-105mm F4-7.1 IS STM",
  },
  RfLens {
    key: 275,
    name: "Canon RF 100-500mm F4.5-7.1L IS USM",
  },
  RfLens {
    key: 276,
    name: "Canon RF 100-500mm F4.5-7.1L IS USM + RF1.4x",
  },
  RfLens {
    key: 277,
    name: "Canon RF 100-500mm F4.5-7.1L IS USM + RF2x",
  },
  RfLens {
    key: 278,
    name: "Canon RF 70-200mm F4L IS USM",
  },
  RfLens {
    key: 279,
    name: "Canon RF 100mm F2.8L MACRO IS USM",
  },
  RfLens {
    key: 280,
    name: "Canon RF 50mm F1.8 STM",
  },
  RfLens {
    key: 281,
    name: "Canon RF 14-35mm F4L IS USM",
  },
  RfLens {
    key: 282,
    name: "Canon RF-S 18-45mm F4.5-6.3 IS STM",
  },
  RfLens {
    key: 283,
    name: "Canon RF 100-400mm F5.6-8 IS USM",
  },
  RfLens {
    key: 284,
    name: "Canon RF 100-400mm F5.6-8 IS USM + RF1.4x",
  },
  RfLens {
    key: 285,
    name: "Canon RF 100-400mm F5.6-8 IS USM + RF2x",
  },
  RfLens {
    key: 286,
    name: "Canon RF-S 18-150mm F3.5-6.3 IS STM",
  },
  RfLens {
    key: 287,
    name: "Canon RF 24mm F1.8 MACRO IS STM",
  },
  RfLens {
    key: 288,
    name: "Canon RF 16mm F2.8 STM",
  },
  RfLens {
    key: 289,
    name: "Canon RF 400mm F2.8L IS USM",
  },
  RfLens {
    key: 290,
    name: "Canon RF 400mm F2.8L IS USM + RF1.4x",
  },
  RfLens {
    key: 291,
    name: "Canon RF 400mm F2.8L IS USM + RF2x",
  },
  RfLens {
    key: 292,
    name: "Canon RF 600mm F4L IS USM",
  },
  RfLens {
    key: 293,
    name: "Canon RF 600mm F4L IS USM + RF1.4x",
  },
  RfLens {
    key: 294,
    name: "Canon RF 600mm F4L IS USM + RF2x",
  },
  RfLens {
    key: 295,
    name: "Canon RF 800mm F5.6L IS USM",
  },
  RfLens {
    key: 296,
    name: "Canon RF 800mm F5.6L IS USM + RF1.4x",
  },
  RfLens {
    key: 297,
    name: "Canon RF 800mm F5.6L IS USM + RF2x",
  },
  RfLens {
    key: 298,
    name: "Canon RF 1200mm F8L IS USM",
  },
  RfLens {
    key: 299,
    name: "Canon RF 1200mm F8L IS USM + RF1.4x",
  },
  RfLens {
    key: 300,
    name: "Canon RF 1200mm F8L IS USM + RF2x",
  },
  RfLens {
    key: 301,
    name: "Canon RF 5.2mm F2.8L Dual Fisheye 3D VR",
  },
  RfLens {
    key: 302,
    name: "Canon RF 15-30mm F4.5-6.3 IS STM",
  },
  RfLens {
    key: 303,
    name: "Canon RF 135mm F1.8 L IS USM",
  },
  RfLens {
    key: 304,
    name: "Canon RF 24-50mm F4.5-6.3 IS STM",
  },
  RfLens {
    key: 305,
    name: "Canon RF-S 55-210mm F5-7.1 IS STM",
  },
  RfLens {
    key: 306,
    name: "Canon RF 100-300mm F2.8L IS USM",
  },
  RfLens {
    key: 307,
    name: "Canon RF 100-300mm F2.8L IS USM + RF1.4x",
  },
  RfLens {
    key: 308,
    name: "Canon RF 100-300mm F2.8L IS USM + RF2x",
  },
  RfLens {
    key: 309,
    name: "Canon RF 200-800mm F6.3-9 IS USM",
  },
  RfLens {
    key: 310,
    name: "Canon RF 200-800mm F6.3-9 IS USM + RF1.4x",
  },
  RfLens {
    key: 311,
    name: "Canon RF 200-800mm F6.3-9 IS USM + RF2x",
  },
  RfLens {
    key: 312,
    name: "Canon RF 10-20mm F4 L IS STM",
  },
  RfLens {
    key: 313,
    name: "Canon RF 28mm F2.8 STM",
  },
  RfLens {
    key: 314,
    name: "Canon RF 24-105mm F2.8 L IS USM Z",
  },
  RfLens {
    key: 315,
    name: "Canon RF-S 10-18mm F4.5-6.3 IS STM",
  },
  RfLens {
    key: 316,
    name: "Canon RF 35mm F1.4 L VCM",
  },
  RfLens {
    key: 317,
    name: "Canon RF-S 3.9mm F3.5 STM DUAL FISHEYE",
  },
  RfLens {
    key: 318,
    name: "Canon RF 28-70mm F2.8 IS STM",
  },
  RfLens {
    key: 319,
    name: "Canon RF 70-200mm F2.8 L IS USM Z",
  },
  RfLens {
    key: 320,
    name: "Canon RF 70-200mm F2.8 L IS USM Z + RF1.4x",
  },
  RfLens {
    key: 321,
    name: "Canon RF 70-200mm F2.8 L IS USM Z + RF2x",
  },
  RfLens {
    key: 323,
    name: "Canon RF 16-28mm F2.8 IS STM",
  },
  RfLens {
    key: 324,
    name: "Canon RF-S 14-30mm F4-6.3 IS STM PZ",
  },
  RfLens {
    key: 325,
    name: "Canon RF 50mm F1.4 L VCM",
  },
  RfLens {
    key: 326,
    name: "Canon RF 24mm F1.4 L VCM",
  },
  RfLens {
    key: 327,
    name: "Canon RF 20mm F1.4 L VCM",
  },
  RfLens {
    key: 328,
    name: "Canon RF 85mm F1.4 L VCM",
  },
  RfLens {
    key: 329,
    name: "Canon RF 20-50mm F4 L IS USM PZ",
  },
  RfLens {
    key: 330,
    name: "Canon RF 45mm F1.2 STM",
  },
  RfLens {
    key: 331,
    name: "Canon RF 7-14mm F2.8-3.5 L FISHEYE STM",
  },
  RfLens {
    key: 332,
    name: "Canon RF 14mm F1.4 L VCM",
  },
];

/// Look up an RFLensType name by its `int16u` key (`Canon.pm:7063-7141`).
fn rf_lens_name(key: u16) -> Option<&'static str> {
  RF_LENS_TYPES
    .binary_search_by(|e| e.key.cmp(&key))
    .ok()
    .map(|i| RF_LENS_TYPES[i].name)
}

/// Parse a FileInfo blob.
///
/// `lens_type` is the CameraSettings `$$self{LensType}` DataMember
/// (`Canon.pm:2503`) and `model` is the body `$$self{Model}`; both gate
/// position 16 (`MacroMagnification`, `Canon.pm:7002-7005`). They are
/// captured/threaded by the Canon body walker (`super`).
#[must_use]
pub fn parse(
  data: &[u8],
  parent_order: crate::exif::ifd::ByteOrder,
  print_conv: bool,
  lens_type: Option<u16>,
  model: Option<&str>,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  if data.len() < 4 {
    return out;
  }
  let order = parent_order;
  // `FocusDistanceUpper2` DataMember (`Canon.pm:7023`): set by position 20's
  // RawConv (`$$self{FocusDistanceUpper2} = $val`), then read by position
  // 21's `Condition => '$$self{FocusDistanceUpper2}'` (`Canon.pm:7033`).
  // `None` = never set (position 20 absent); `Some(0)` = set-but-falsy.
  let mut focus_distance_upper2: Option<i64> = None;
  for t in FILE_INFO {
    let byte_off = 2 * t.position;
    if byte_off + 2 > data.len() {
      break;
    }
    let arr: [u8; 2] = [data[byte_off], data[byte_off + 1]];
    // Read with the per-position format: the table default `int16s`
    // (`Canon.pm:6845`), or `int16u` for RFLensType (`Canon.pm:7062`) and
    // FocusDistanceUpper/Lower (`Canon.pm:7024`/`:7034`).
    let val: i64 = match t.format {
      FiFormat::Int16s => match order {
        crate::exif::ifd::ByteOrder::Little => i64::from(i16::from_le_bytes(arr)),
        crate::exif::ifd::ByteOrder::Big => i64::from(i16::from_be_bytes(arr)),
      },
      FiFormat::Int16u => match order {
        crate::exif::ifd::ByteOrder::Little => i64::from(u16::from_le_bytes(arr)),
        crate::exif::ifd::ByteOrder::Big => i64::from(u16::from_be_bytes(arr)),
      },
    };
    // Position 20 `FocusDistanceUpper` RawConv (`Canon.pm:7025`):
    // `($$self{FocusDistanceUpper2} = $val) || undef` — set the DataMember
    // (even when 0), and drop the tag when raw is 0 (`|| undef`).
    if t.position == 20 {
      focus_distance_upper2 = Some(val);
    }
    // Position 21 `FocusDistanceLower` Condition (`Canon.pm:7033`):
    // `$$self{FocusDistanceUpper2}` — emit only when that DataMember is
    // truthy (set AND nonzero). An unset (`None`) or zero member skips it.
    if t.position == 21 && !matches!(focus_distance_upper2, Some(v) if v != 0) {
      continue;
    }
    // Position 16 `MacroMagnification` Condition (`Canon.pm:7002-7005`):
    // `$$self{LensType} and $$self{LensType} == 124 and $$self{Model} !~
    // /\b(40D|450D|REBEL XSi|Kiss X2)\b/` — emit ONLY for the MP-E 65mm
    // (LensType 124), and NOT on the four bodies that report a bogus value.
    // (`LensType and LensType == 124` collapses to `== Some(124)`: a 0 or
    // unset LensType is never captured as `Some(124)`.)
    if t.position == 16 {
      let macro_mag_ok = lens_type == Some(124) && !model_excludes_macro_mag(model);
      if !macro_mag_ok {
        continue;
      }
    }
    // Per-position `RawConv` guards (`Canon.pm` `%Canon::FileInfo`).
    // BracketMode (3) has NO RawConv, so it is NEVER skipped here; the
    // new positions 23/25/32/0x3d likewise have no RawConv
    // (`Canon.pm:7041-7142`), so they are never skipped either.
    let skip = match t.position {
      6 => val <= 0,        // RawJpgQuality: `$val<=0 ? undef` (Canon.pm:6943)
      7 | 8 => val < 0,     // RawJpgSize / LongExposureNR2: `$val<0 ? undef` (:6948/:6958)
      14 | 15 => val == -1, // FilterEffect / ToningEffect: `$val==-1 ? undef` (:6978/:6989)
      20 => val == 0,       // FocusDistanceUpper: RawConv `… || undef` (Canon.pm:7025)
      _ => false,
    };
    if skip {
      continue;
    }
    let tag_value = apply_fi_print_conv(t.conv, val, print_conv);
    out.push((t.name.into(), tag_value));
  }
  out
}

/// `FocusDistanceUpper`/`FocusDistanceLower` Value/PrintConv
/// (`Canon.pm:7026-7028` / `:7035-7037`): `ValueConv => '$val / 100'`,
/// `PrintConv => '$val > 655.345 ? "inf" : "$val m"'`. The PrintConv
/// operates on the *ValueConv* result (`raw/100`); Perl interpolates the
/// scalar with its default NV stringification (`%.15g`, matched by
/// [`crate::value::format_g`]).
fn focus_distance_value(raw: i64, print_conv: bool) -> TagValue {
  let meters = raw as f64 / 100.0;
  if !print_conv {
    // `-n` (ValueConv) mode: the raw/100 float.
    return TagValue::F64(meters);
  }
  if meters > 655.345 {
    TagValue::Str(SmolStr::new_static("inf"))
  } else {
    let m = crate::value::format_g(meters, 15);
    TagValue::Str(SmolStr::from(std::format!("{m} m")))
  }
}

fn apply_fi_print_conv(conv: FiPrintConv, val: i64, print_conv: bool) -> TagValue {
  // FocusDistanceUpper/Lower have a `ValueConv => '$val / 100'`
  // (`Canon.pm:7026`/`:7035`) that applies in BOTH `-n` and `-j` modes, so
  // it is handled before the no-PrintConv early-return below (which assumes
  // no ValueConv runs in `-n` mode).
  if conv == FiPrintConv::FocusDistance {
    return focus_distance_value(val, print_conv);
  }
  // MacroMagnification likewise has a `ValueConv` (`Canon.pm:7129`) that
  // applies in BOTH modes; handle it before the no-PrintConv early-return.
  if conv == FiPrintConv::MacroMagnification {
    return macro_magnification_value(val, print_conv);
  }
  if !print_conv {
    return TagValue::I64(val);
  }
  let label_or_default = |label: Option<&'static str>| -> TagValue {
    match label {
      Some(l) => TagValue::Str(l.into()),
      None => TagValue::Str(SmolStr::from(std::format!("Unknown ({val})"))),
    }
  };
  match conv {
    FiPrintConv::None => TagValue::I64(val),
    FiPrintConv::RawJpgQuality => label_or_default(match val {
      // `%canonQuality` (`Canon.pm:1051-1061`).
      -1 => Some("n/a"),
      1 => Some("Economy"),
      2 => Some("Normal"),
      3 => Some("Fine"),
      4 => Some("RAW"),
      5 => Some("Superfine"),
      7 => Some("CRAW"),
      130 => Some("Light (RAW)"),
      131 => Some("Standard (RAW)"),
      _ => None,
    }),
    FiPrintConv::RawJpgSize => label_or_default(match val {
      // `%canonImageSize` (`Canon.pm:1062-1082`).
      -1 => Some("n/a"),
      0 => Some("Large"),
      1 => Some("Medium"),
      2 => Some("Small"),
      5 => Some("Medium 1"),
      6 => Some("Medium 2"),
      7 => Some("Medium 3"),
      8 => Some("Postcard"),
      9 => Some("Widescreen"),
      10 => Some("Medium Widescreen"),
      14 => Some("Small 1"),
      15 => Some("Small 2"),
      16 => Some("Small 3"),
      128 => Some("640x480 Movie"),
      129 => Some("Medium Movie"),
      130 => Some("Small Movie"),
      137 => Some("1280x720 Movie"),
      142 => Some("1920x1080 Movie"),
      143 => Some("4096x2160 Movie"),
      _ => None,
    }),
    FiPrintConv::BracketMode => label_or_default(match val {
      0 => Some("Off"),
      1 => Some("AEB"),
      2 => Some("FEB"),
      3 => Some("ISO"),
      4 => Some("WB"),
      _ => None,
    }),
    FiPrintConv::WbBracketMode => label_or_default(match val {
      0 => Some("Off"),
      1 => Some("On (shift AB)"),
      2 => Some("On (shift GM)"),
      _ => None,
    }),
    FiPrintConv::FilterEffect => label_or_default(match val {
      0 => Some("None"),
      1 => Some("Yellow"),
      2 => Some("Orange"),
      3 => Some("Red"),
      4 => Some("Green"),
      _ => None,
    }),
    FiPrintConv::ToningEffect => label_or_default(match val {
      0 => Some("None"),
      1 => Some("Sepia"),
      2 => Some("Blue"),
      3 => Some("Purple"),
      4 => Some("Green"),
      _ => None,
    }),
    FiPrintConv::LongExposureNR => label_or_default(match val {
      0 => Some("Off"),
      1 => Some("On (1D)"),
      3 => Some("On"),
      4 => Some("Auto"),
      _ => None,
    }),
    FiPrintConv::LiveViewShooting => label_or_default(match val {
      0 => Some("Off"),
      1 => Some("On"),
      _ => None,
    }),
    // `ShutterMode` (`Canon.pm:7043-7046`).
    FiPrintConv::ShutterMode => label_or_default(match val {
      0 => Some("Mechanical"),
      1 => Some("Electronic First Curtain"),
      2 => Some("Electronic"),
      _ => None,
    }),
    // `FlashExposureLock` / `AntiFlicker` — `\%offOn`
    // (`Canon.pm:1218` `%offOn = ( 0 => 'Off', 1 => 'On' )`).
    FiPrintConv::FlashExposureLock | FiPrintConv::AntiFlicker => label_or_default(match val {
      0 => Some("Off"),
      1 => Some("On"),
      _ => None,
    }),
    // `RFLensType` (`Canon.pm:7063-7141`). The bundled hash is a plain
    // value map (no OTHER/BITMASK), so unknown keys fall through to
    // ExifTool's default `Unknown (N)` PrintConv.
    FiPrintConv::RfLensType => label_or_default(u16::try_from(val).ok().and_then(rf_lens_name)),
    // Handled by the early-return above (it has a ValueConv that applies
    // in `-n` mode); routed here too for exhaustiveness.
    FiPrintConv::FocusDistance => focus_distance_value(val, print_conv),
    FiPrintConv::MacroMagnification => macro_magnification_value(val, print_conv),
  }
}

/// `MacroMagnification` Value/PrintConv (shared `%ciMacroMagnification`,
/// `Canon.pm:3129`/`:3131`): `ValueConv => 'exp((75-$val) * log(2) * 3 /
/// 40)'`, `PrintConv => 'sprintf("%.1fx",$val)'`. The PrintConv operates
/// on the *ValueConv* result. `-n` (ValueConv) mode emits the `f64`; `-j`
/// (PrintConv) mode emits the `"%.1fx"` string.
fn macro_magnification_value(raw: i64, print_conv: bool) -> TagValue {
  // `log(2)` is Perl's natural log of 2 (`ln 2`).
  let mag = ((75 - raw) as f64 * std::f64::consts::LN_2 * 3.0 / 40.0).exp();
  if !print_conv {
    return TagValue::F64(mag);
  }
  // `sprintf("%.1fx",$val)` — one decimal place, then a literal `x`.
  TagValue::Str(SmolStr::from(std::format!("{mag:.1}x")))
}

/// FileInfo position 16 `Condition` model exclusion (`Canon.pm:7004`):
/// `$$self{Model} !~ /\b(40D|450D|REBEL XSi|Kiss X2)\b/`. Returns `true`
/// when `model` matches one of those four bodies (so position 16 is
/// suppressed). Mirrors Perl's `\b` word boundaries: each token must be
/// flanked by a non-word/word transition (`\w` = `[A-Za-z0-9_]`). An
/// absent (`None`) Model — like the standalone-blob path — does NOT match
/// (Perl `undef !~ /…/` is true, i.e. NOT excluded).
fn model_excludes_macro_mag(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  ["40D", "450D", "REBEL XSi", "Kiss X2"]
    .iter()
    .any(|tok| contains_word(m, tok))
}

/// Perl `\bTOKEN\b` test: `TOKEN` appears in `haystack` flanked by word
/// boundaries, where a word char is `[A-Za-z0-9_]` (Perl `\w`). The
/// bundled tokens (`40D`, `450D`, `REBEL XSi`, `Kiss X2`) begin and end
/// with word chars, so a boundary requires the neighbouring char (if any)
/// to be a NON-word char.
fn contains_word(haystack: &str, token: &str) -> bool {
  let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
  let tb = token.as_bytes();
  let hb = haystack.as_bytes();
  if tb.is_empty() || tb.len() > hb.len() {
    return false;
  }
  // The bundled tokens are pure ASCII, so byte-indexed scanning is sound
  // (no UTF-8 multibyte char can match an ASCII token, and the boundary
  // chars we inspect are single ASCII bytes when present).
  let mut i = 0;
  while i + tb.len() <= hb.len() {
    if &hb[i..i + tb.len()] == tb {
      let before_ok = i == 0 || !is_word(hb[i - 1] as char);
      let after_idx = i + tb.len();
      let after_ok = after_idx == hb.len() || !is_word(hb[after_idx] as char);
      if before_ok && after_ok {
        return true;
      }
    }
    i += 1;
  }
  false
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::exif::ifd::ByteOrder;

  /// Synthetic FileInfo: position 3 (BracketMode) = 1 (AEB), position 4
  /// (BracketValue) = -2.
  #[test]
  fn parse_bracket_mode_and_value() {
    let mut data = std::vec![0u8; 12];
    let order = ByteOrder::Little;
    data[2 * 3..2 * 3 + 2].copy_from_slice(&(1i16).to_le_bytes());
    data[2 * 4..2 * 4 + 2].copy_from_slice(&(-2i16).to_le_bytes());
    let emissions = parse(&data, order, true, None, None);
    assert!(
      emissions
        .iter()
        .any(|(n, v)| n == "BracketMode" && *v == TagValue::Str("AEB".into()))
    );
    assert!(
      emissions
        .iter()
        .any(|(n, v)| n == "BracketValue" && *v == TagValue::I64(-2))
    );
  }

  #[test]
  fn parse_print_conv_off_keeps_int() {
    let mut data = std::vec![0u8; 12];
    data[2 * 3..2 * 3 + 2].copy_from_slice(&(1i16).to_le_bytes());
    let emissions = parse(&data, ByteOrder::Little, false, None, None);
    assert!(
      emissions
        .iter()
        .any(|(n, v)| n == "BracketMode" && *v == TagValue::I64(1))
    );
  }

  #[test]
  fn filter_effect_red_label() {
    let mut data = std::vec![0u8; 32];
    data[2 * 14..2 * 14 + 2].copy_from_slice(&(3i16).to_le_bytes());
    let emissions = parse(&data, ByteOrder::Little, true, None, None);
    assert!(
      emissions
        .iter()
        .any(|(n, v)| n == "FilterEffect" && *v == TagValue::Str("Red".into()))
    );
  }

  #[test]
  fn live_view_shooting_on_off() {
    let mut data = std::vec![0u8; 42];
    data[2 * 19..2 * 19 + 2].copy_from_slice(&(1i16).to_le_bytes());
    let emissions = parse(&data, ByteOrder::Little, true, None, None);
    assert!(
      emissions
        .iter()
        .any(|(n, v)| n == "LiveViewShooting" && *v == TagValue::Str("On".into()))
    );
  }

  /// RawJpgQuality (pos 6) ⇒ `%canonQuality`; `$val<=0` ⇒ undef.
  #[test]
  fn raw_jpg_quality_and_size() {
    let mut data = std::vec![0u8; 20];
    data[2 * 6..2 * 6 + 2].copy_from_slice(&(4i16).to_le_bytes()); // RAW
    data[2 * 7..2 * 7 + 2].copy_from_slice(&(1i16).to_le_bytes()); // Medium
    let v = parse(&data, ByteOrder::Little, true, None, None);
    assert!(
      v.iter()
        .any(|(n, val)| n == "RawJpgQuality" && *val == TagValue::Str("RAW".into()))
    );
    assert!(
      v.iter()
        .any(|(n, val)| n == "RawJpgSize" && *val == TagValue::Str("Medium".into()))
    );
  }

  /// RawJpgQuality `$val<=0 ? undef` (Canon.pm:6943): 0 is dropped (this
  /// differs from RawJpgSize, which only drops `<0`).
  #[test]
  fn raw_jpg_quality_zero_skipped_but_size_zero_kept() {
    let mut data = std::vec![0u8; 20];
    // pos 6 = 0 ⇒ undef; pos 7 = 0 ⇒ "Large" (kept).
    let v = parse(&data, ByteOrder::Little, true, None, None);
    assert!(!v.iter().any(|(n, _)| n == "RawJpgQuality"));
    assert!(
      v.iter()
        .any(|(n, val)| n == "RawJpgSize" && *val == TagValue::Str("Large".into()))
    );
    // Negative size ⇒ undef: the `$val<0 ? undef` RawConv (Canon.pm:6948)
    // drops the tag BEFORE the `-1 => 'n/a'` PrintConv arm can fire, so
    // RawJpgSize is NOT emitted (the `-1` map entry is unreachable here).
    data[2 * 7..2 * 7 + 2].copy_from_slice(&(-1i16).to_le_bytes());
    let v2 = parse(&data, ByteOrder::Little, true, None, None);
    assert!(!v2.iter().any(|(n, _)| n == "RawJpgSize"));
  }

  /// BracketMode (pos 3) has NO RawConv in bundled — a negative value
  /// must NOT be skipped (the old port wrongly dropped negatives).
  #[test]
  fn bracket_mode_negative_not_skipped() {
    let mut data = std::vec![0u8; 12];
    data[2 * 3..2 * 3 + 2].copy_from_slice(&(-5i16).to_le_bytes());
    let v = parse(&data, ByteOrder::Little, true, None, None);
    // -5 has no label ⇒ "Unknown (-5)", but it IS emitted.
    assert!(
      v.iter()
        .any(|(n, val)| n == "BracketMode" && *val == TagValue::Str("Unknown (-5)".into()))
    );
  }

  /// Build a FileInfo blob big enough to hold position `pos` (`int16s`).
  fn blob_with(pos: usize, raw: i16) -> std::vec::Vec<u8> {
    let mut data = std::vec![0u8; 2 * (pos + 1)];
    data[2 * pos..2 * pos + 2].copy_from_slice(&raw.to_le_bytes());
    data
  }

  /// `ShutterMode` (pos 23, `Canon.pm:7043-7046`): 0/1/2.
  #[test]
  fn shutter_mode_labels() {
    for (raw, label) in [
      (0i16, "Mechanical"),
      (1, "Electronic First Curtain"),
      (2, "Electronic"),
    ] {
      let v = parse(&blob_with(23, raw), ByteOrder::Little, true, None, None);
      assert!(
        v.iter()
          .any(|(n, val)| n == "ShutterMode" && *val == TagValue::Str(label.into())),
        "ShutterMode {raw} ⇒ {label}; got {v:?}"
      );
    }
    // -n keeps the integer.
    let vn = parse(&blob_with(23, 2), ByteOrder::Little, false, None, None);
    assert!(
      vn.iter()
        .any(|(n, val)| n == "ShutterMode" && *val == TagValue::I64(2))
    );
  }

  /// `FlashExposureLock` (pos 25) + `AntiFlicker` (pos 32) — `%offOn`.
  #[test]
  fn flash_exposure_lock_and_anti_flicker_off_on() {
    // FlashExposureLock = 1 (On), AntiFlicker = 0 (Off).
    let mut data = std::vec![0u8; 2 * 33];
    data[2 * 25..2 * 25 + 2].copy_from_slice(&(1i16).to_le_bytes());
    data[2 * 32..2 * 32 + 2].copy_from_slice(&(0i16).to_le_bytes());
    let v = parse(&data, ByteOrder::Little, true, None, None);
    assert!(
      v.iter()
        .any(|(n, val)| n == "FlashExposureLock" && *val == TagValue::Str("On".into())),
      "got {v:?}"
    );
    assert!(
      v.iter()
        .any(|(n, val)| n == "AntiFlicker" && *val == TagValue::Str("Off".into()))
    );
  }

  /// `RFLensType` (pos 0x3d=61) is `int16u` (`Canon.pm:7062`): 280 ⇒
  /// "Canon RF 50mm F1.8 STM" (print); 280 with `-n`; an unknown value ⇒
  /// `Unknown (N)` fallback.
  #[test]
  fn rf_lens_type_print_and_value_and_fallback() {
    // value-conv 280.
    let v280 = parse(&blob_with(61, 280), ByteOrder::Little, true, None, None);
    assert!(
      v280.iter().any(
        |(n, val)| n == "RFLensType" && *val == TagValue::Str("Canon RF 50mm F1.8 STM".into())
      ),
      "got {v280:?}"
    );
    // -n keeps the raw integer.
    let v280n = parse(&blob_with(61, 280), ByteOrder::Little, false, None, None);
    assert!(
      v280n
        .iter()
        .any(|(n, val)| n == "RFLensType" && *val == TagValue::I64(280))
    );
    // Unknown value ⇒ `Unknown (N)` (plain hash, no OTHER/BITMASK).
    let vunk = parse(
      &blob_with(61, 9999u16 as i16),
      ByteOrder::Little,
      true,
      None,
      None,
    );
    assert!(
      vunk
        .iter()
        .any(|(n, val)| n == "RFLensType" && *val == TagValue::Str("Unknown (9999)".into())),
      "got {vunk:?}"
    );
  }

  /// RFLensType is `int16u`: a value with the high bit set (e.g. 0x8000)
  /// must NOT be read as a negative `int16s`. 332 is the top known key.
  #[test]
  fn rf_lens_type_reads_unsigned() {
    let v = parse(&blob_with(61, 332), ByteOrder::Little, true, None, None);
    assert!(v.iter().any(
      |(n, val)| n == "RFLensType" && *val == TagValue::Str("Canon RF 14mm F1.4 L VCM".into())
    ));
    // 0x8000 = 32768 as int16u; would be -32768 as int16s. The unsigned
    // read keeps it positive ⇒ `Unknown (32768)`, NOT `Unknown (-32768)`.
    let vhi = parse(
      &blob_with(61, 0x8000u16 as i16),
      ByteOrder::Little,
      true,
      None,
      None,
    );
    assert!(
      vhi
        .iter()
        .any(|(n, val)| n == "RFLensType" && *val == TagValue::Str("Unknown (32768)".into())),
      "got {vhi:?}"
    );
  }

  /// The RFLensType map is sorted by key (binary_search invariant) and
  /// has the faithful 76-entry count with no `322` key.
  #[test]
  fn rf_lens_table_sorted_and_complete() {
    assert_eq!(RF_LENS_TYPES.len(), 76);
    let mut prev: Option<u16> = None;
    for e in RF_LENS_TYPES {
      if let Some(p) = prev {
        assert!(e.key > p, "RF lens table out of order at {}", e.key);
      }
      prev = Some(e.key);
    }
    // 322 is absent in bundled (`Canon.pm:7129-7130`: 321 → 323).
    assert!(rf_lens_name(322).is_none());
    assert!(rf_lens_name(321).is_some());
    assert!(rf_lens_name(323).is_some());
  }

  /// Build a FileInfo blob holding `int16u` words at the given positions
  /// (little-endian), sized for the highest position.
  fn blob_u16(words: &[(usize, u16)]) -> std::vec::Vec<u8> {
    let max_pos = words.iter().map(|&(p, _)| p).max().unwrap_or(0);
    let mut data = std::vec![0u8; 2 * (max_pos + 1)];
    for &(pos, raw) in words {
      data[2 * pos..2 * pos + 2].copy_from_slice(&raw.to_le_bytes());
    }
    data
  }

  /// FocusDistanceUpper (pos 20, `Canon.pm:7021-7030`) — `int16u`,
  /// `ValueConv => '$val / 100'`, `PrintConv => '$val > 655.345 ? "inf" :
  /// "$val m"'`. raw 12345 ⇒ value 123.45 ⇒ `"123.45 m"` (print);
  /// 123.45 (value-conv). Position 21 is gated by the DataMember.
  #[test]
  fn focus_distance_upper_value_and_print() {
    // raw 12345 ⇒ 123.45 m (print).
    let v = parse(
      &blob_u16(&[(20, 12345)]),
      ByteOrder::Little,
      true,
      None,
      None,
    );
    assert!(
      v.iter()
        .any(|(n, val)| n == "FocusDistanceUpper" && *val == TagValue::Str("123.45 m".into())),
      "got {v:?}"
    );
    // `-n` (ValueConv): the raw/100 float.
    let vn = parse(
      &blob_u16(&[(20, 12345)]),
      ByteOrder::Little,
      false,
      None,
      None,
    );
    assert!(
      vn.iter()
        .any(|(n, val)| n == "FocusDistanceUpper" && *val == TagValue::F64(123.45)),
      "got {vn:?}"
    );
  }

  /// FocusDistanceUpper `int16u`: a value with the high bit set must read
  /// unsigned. raw 65535 ⇒ 655.35 > 655.345 ⇒ `"inf"` (`Canon.pm:7028`).
  #[test]
  fn focus_distance_upper_inf_and_unsigned() {
    let v = parse(
      &blob_u16(&[(20, 65535)]),
      ByteOrder::Little,
      true,
      None,
      None,
    );
    assert!(
      v.iter()
        .any(|(n, val)| n == "FocusDistanceUpper" && *val == TagValue::Str("inf".into())),
      "got {v:?}"
    );
    // value-conv: 655.35 (unsigned read, NOT a negative int16s).
    let vn = parse(
      &blob_u16(&[(20, 65535)]),
      ByteOrder::Little,
      false,
      None,
      None,
    );
    assert!(
      vn.iter()
        .any(|(n, val)| n == "FocusDistanceUpper" && *val == TagValue::F64(655.35)),
      "got {vn:?}"
    );
  }

  /// FocusDistanceUpper RawConv `($$self{FocusDistanceUpper2}=$val)||undef`
  /// (`Canon.pm:7025`): raw 0 ⇒ tag DROPPED, and the now-zero DataMember
  /// gates OUT FocusDistanceLower (pos 21, `Condition`, `Canon.pm:7033`).
  #[test]
  fn focus_distance_upper_zero_drops_both() {
    // pos 20 = 0, pos 21 = 5000 (would be 50 m if emitted).
    let v = parse(
      &blob_u16(&[(20, 0), (21, 5000)]),
      ByteOrder::Little,
      true,
      None,
      None,
    );
    assert!(
      !v.iter().any(|(n, _)| n == "FocusDistanceUpper"),
      "pos-20 raw 0 must be dropped; got {v:?}"
    );
    assert!(
      !v.iter().any(|(n, _)| n == "FocusDistanceLower"),
      "pos-21 must be gated out when FocusDistanceUpper2 is 0; got {v:?}"
    );
  }

  /// FocusDistanceLower (pos 21) is emitted ONLY when FocusDistanceUpper2
  /// (set from pos 20) is truthy. With pos 20 nonzero ⇒ BOTH emit.
  #[test]
  fn focus_distance_lower_emitted_when_upper_nonzero() {
    // pos 20 = 30000 (300 m), pos 21 = 5000 (50 m).
    let v = parse(
      &blob_u16(&[(20, 30000), (21, 5000)]),
      ByteOrder::Little,
      true,
      None,
      None,
    );
    assert!(
      v.iter()
        .any(|(n, val)| n == "FocusDistanceUpper" && *val == TagValue::Str("300 m".into())),
      "got {v:?}"
    );
    assert!(
      v.iter()
        .any(|(n, val)| n == "FocusDistanceLower" && *val == TagValue::Str("50 m".into())),
      "FocusDistanceLower must emit when FocusDistanceUpper2 nonzero; got {v:?}"
    );
  }

  /// FocusDistanceLower is gated OUT when position 20 is entirely absent
  /// from the blob (DataMember never set ⇒ Condition falsy).
  #[test]
  fn focus_distance_lower_skipped_when_upper_absent() {
    // Blob long enough for pos 21 but pos 20 word is 0 (so DataMember=0).
    // Distinguish "absent" by checking the gate: pos 20 = 0 ⇒ lower out.
    let v = parse(
      &blob_u16(&[(21, 5000)]),
      ByteOrder::Little,
      true,
      None,
      None,
    );
    assert!(
      !v.iter().any(|(n, _)| n == "FocusDistanceLower"),
      "FocusDistanceLower must be gated out; got {v:?}"
    );
  }

  /// MacroMagnification (pos 16, `Canon.pm:6998-7005`): emitted ONLY when
  /// `$$self{LensType} == 124` (the MP-E 65mm) AND `$$self{Model}` is not
  /// an excluded body. `-j` (PrintConv) ⇒ `sprintf("%.1fx",$val)`; raw 75
  /// ⇒ exp(0) = 1.0 ⇒ `"1.0x"` (the bundled "75=1x" sample, `Canon.pm:7000`).
  #[test]
  fn macro_magnification_present_with_lens_124_print() {
    // pos 16 = 75 ⇒ ValueConv exp((75-75)*ln2*3/40)=1.0 ⇒ "1.0x".
    let v = parse(
      &blob_with(16, 75),
      ByteOrder::Little,
      true,
      Some(124),
      Some("Canon EOS 5D Mark II"),
    );
    assert!(
      v.iter()
        .any(|(n, val)| n == "MacroMagnification" && *val == TagValue::Str("1.0x".into())),
      "got {v:?}"
    );
  }

  /// MacroMagnification ValueConv: raw 44 ⇒ exp((75-44)*ln2*3/40) ≈ 5.0
  /// (the bundled "44=5x" sample, `Canon.pm:7000`) ⇒ `"5.0x"` (`-j`); the
  /// `f64` in `-n` mode (which carries the full ValueConv, no rounding).
  #[test]
  fn macro_magnification_value_conv_n_and_j() {
    // -j: raw 44 ⇒ "5.0x".
    let vj = parse(
      &blob_with(16, 44),
      ByteOrder::Little,
      true,
      Some(124),
      Some("Canon EOS 5D Mark II"),
    );
    assert!(
      vj.iter()
        .any(|(n, val)| n == "MacroMagnification" && *val == TagValue::Str("5.0x".into())),
      "got {vj:?}"
    );
    // -n: the raw ValueConv f64 = exp((75-44)*ln2*3/40).
    let expected = ((75 - 44) as f64 * std::f64::consts::LN_2 * 3.0 / 40.0).exp();
    let vn = parse(
      &blob_with(16, 44),
      ByteOrder::Little,
      false,
      Some(124),
      Some("Canon EOS 5D Mark II"),
    );
    assert!(
      vn.iter()
        .any(|(n, val)| n == "MacroMagnification" && *val == TagValue::F64(expected)),
      "got {vn:?}"
    );
    // Sanity: the ValueConv rounds to 5.0x but the raw f64 is ~5.01, NOT
    // exactly 5 — `-n` must carry the unrounded value.
    assert!((expected - 5.0).abs() < 0.05 && expected != 5.0);
  }

  /// MacroMagnification is ABSENT when LensType is not 124 (e.g. None, or
  /// a different lens) — the `$$self{LensType} == 124` arm of the Condition
  /// (`Canon.pm:7003`) fails.
  #[test]
  fn macro_magnification_absent_when_lens_not_124() {
    // LensType = None ⇒ absent.
    let v_none = parse(
      &blob_with(16, 75),
      ByteOrder::Little,
      true,
      None,
      Some("Canon EOS 5D Mark II"),
    );
    assert!(
      !v_none.iter().any(|(n, _)| n == "MacroMagnification"),
      "LensType None must suppress MacroMagnification; got {v_none:?}"
    );
    // LensType = 123 (not the MP-E 65mm) ⇒ absent.
    let v_other = parse(
      &blob_with(16, 75),
      ByteOrder::Little,
      true,
      Some(123),
      Some("Canon EOS 5D Mark II"),
    );
    assert!(
      !v_other.iter().any(|(n, _)| n == "MacroMagnification"),
      "LensType 123 must suppress MacroMagnification; got {v_other:?}"
    );
  }

  /// MacroMagnification is ABSENT on the four excluded bodies
  /// (`$$self{Model} !~ /\b(40D|450D|REBEL XSi|Kiss X2)\b/`,
  /// `Canon.pm:7004`) even with LensType 124 — these report a bogus value.
  #[test]
  fn macro_magnification_absent_on_excluded_models() {
    for model in [
      "Canon EOS 40D",
      "Canon EOS 450D",
      "Canon EOS REBEL XSi",
      "Canon EOS Kiss X2",
    ] {
      let v = parse(
        &blob_with(16, 75),
        ByteOrder::Little,
        true,
        Some(124),
        Some(model),
      );
      assert!(
        !v.iter().any(|(n, _)| n == "MacroMagnification"),
        "excluded model {model:?} must suppress MacroMagnification; got {v:?}"
      );
    }
  }

  /// The `\b` word boundaries in the exclusion regex (`Canon.pm:7004`)
  /// must be honoured: a Model where the token appears only as part of a
  /// LARGER word (no boundary) is NOT excluded, and an absent (`None`)
  /// Model is NOT excluded (Perl `undef !~ /…/` is true). A bare token at
  /// a boundary (e.g. trailing "40D") IS excluded.
  #[test]
  fn macro_magnification_model_word_boundary() {
    // "1240DX" embeds "40D" with word chars on both sides ⇒ NO boundary ⇒
    // NOT excluded ⇒ MacroMagnification present.
    let v_embedded = parse(
      &blob_with(16, 75),
      ByteOrder::Little,
      true,
      Some(124),
      Some("Canon EOS 1240DX"),
    );
    assert!(
      v_embedded.iter().any(|(n, _)| n == "MacroMagnification"),
      "embedded '40D' (no word boundary) must NOT exclude; got {v_embedded:?}"
    );
    // None Model ⇒ not excluded (standalone-blob path) ⇒ present.
    let v_no_model = parse(&blob_with(16, 75), ByteOrder::Little, true, Some(124), None);
    assert!(
      v_no_model.iter().any(|(n, _)| n == "MacroMagnification"),
      "None Model must NOT exclude; got {v_no_model:?}"
    );
    // Trailing "40D" at a boundary (end of string) IS excluded.
    let v_trailing = parse(
      &blob_with(16, 75),
      ByteOrder::Little,
      true,
      Some(124),
      Some("Canon EOS 40D"),
    );
    assert!(
      !v_trailing.iter().any(|(n, _)| n == "MacroMagnification"),
      "trailing '40D' at a boundary must exclude; got {v_trailing:?}"
    );
  }

  /// `contains_word` honours Perl `\b`: token must be flanked by non-word
  /// chars (or string edges). `\w` = `[A-Za-z0-9_]`.
  #[test]
  fn contains_word_boundaries() {
    assert!(contains_word("Canon EOS 40D", "40D")); // trailing edge
    assert!(contains_word("40D body", "40D")); // leading edge
    assert!(contains_word("EOS 40D body", "40D")); // both spaces
    assert!(!contains_word("1240DX", "40D")); // embedded — no boundary
    assert!(!contains_word("40DD", "40D")); // trailing word char
    assert!(!contains_word("A40D", "40D")); // leading word char
    assert!(!contains_word("40D_", "40D")); // '_' is a word char
    assert!(contains_word("REBEL XSi", "REBEL XSi")); // multi-word token
    assert!(!contains_word("REBEL XSiX", "REBEL XSi")); // trailing word char
  }
}
