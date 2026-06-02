// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::Main` IFD tag table (`Sony.pm:707-2711`).
//!
//! Faithful 1:1 port against bundled ExifTool 13.59 (Sony.pm `$VERSION`
//! 3.87). Every numeric key of the Main hash gets exactly one row here.
//! The bundled `%Sony::Main` has **114 numeric tag IDs** (the loaded-module
//! key count — verified by the `tests/sony_main_table.rs` perl-dump oracle).
//!
//! - LEAF tags carry their `name`, `unknown` flag, and a [`SonyPrintConv`]
//!   strategy. The `Unknown => 1` tags are the encrypted-cipher-data rows
//!   that pull in `%unknownCipherData` (`Sony.pm:675-681`, which sets
//!   `Unknown => 1`): the single-HASH `Sony_0x9407/8/9`, `Sony_0x940b/d/f`,
//!   `Sony_0x9411` (`Sony.pm:2055-2114`), plus the conditional-ARRAY tags
//!   whose final fallback branch is a `Sony_0x…` cipher entry (so the dump's
//!   OR-across-branches flag is set): `Tag2010a` 0x2010, `Tag9050a` 0x9050,
//!   `Tag9400a` 0x9400, `Tag9402` 0x9402, `Tag9404a` 0x9404, `Tag9405a`
//!   0x9405, `Tag9406` 0x9406, `Tag940a` 0x940a, `Tag940c` 0x940c, `AFInfo`
//!   0x940e.
//! - SubDirectory pointers (`PrintIM` 0x0e00, `Panorama` 0x1003, `Tag202a`
//!   0x202a, `HiddenInfo` 0x2044, `ShotInfo` 0x3000, `Tag900b` 0x900b,
//!   `Tag9401` 0x9401, `Tag9403` 0x9403, `Sony_0x9416` 0x9416,
//!   `MinoltaMakerNote` 0xb028) and the conditional-ARRAY SubDirectory
//!   dispatchers (`CameraInfo` 0x0010, `FocusInfo` 0x0020, `CameraSettings`
//!   0x0114, `ExtraInfo` 0x0116, and the `Tag2010a`/`Tag9xxx`/`AFInfo`
//!   series above) are recorded as [`SubTable`] so the dispatcher can
//!   surface the raw blob; the dedicated per-model walkers are deferred to a
//!   follow-up issue (Sony has 60+ such sub-tables, each model-specific —
//!   see "Deferred" in [`super`]).
//! - The `0xb001 SonyModelID` PrintConv hash is split into
//!   [`super::model_ids::SONY_MODEL_IDS`]; the `LensType` lookup
//!   (`%sonyLensTypes2`) is in [`super::lens_types::SONY_LENS_TYPES`].
//!
//! Conditional-ARRAY rows (`0xNN => [ {Condition=>…,Name=>…}, … ]`) carry
//! the FIRST branch's `Name` here, matching the `tests/sony_main_table.rs`
//! oracle (which records `$info->[0]{Name}` as the representative). The
//! per-branch model dispatch is deferred with the sub-table walker.

#![deny(clippy::indexing_slicing)]

use super::printconv::SonyPrintConv;
use crate::exif::ifd::Format;
use crate::exif::makernotes::vendors::FormatOverride;

/// One Sony Main IFD tag.
#[derive(Debug, Clone, Copy)]
pub struct SonyTag {
  /// Tag ID (`Sony.pm` Main hash key).
  pub id: u16,
  /// `Name => '…'` from bundled (first branch for conditional ARRAYs).
  pub name: &'static str,
  /// PrintConv strategy.
  pub conv: SonyPrintConv,
  /// `Some(SubTable::…)` when the tag is a SubDirectory pointer (or a
  /// conditional-ARRAY SubDirectory dispatcher).
  pub sub_table: Option<SubTable>,
  /// `Unknown => 1` in bundled (`ExifTool.pm:9179-9185` suppresses such
  /// tags from the default `-j` output). Set for the `%unknownCipherData`
  /// rows (`Sony.pm:675-681`). Mirrors the Apple/Canon/Panasonic flag.
  pub unknown: bool,
  /// `Some(FormatOverride)` when bundled carries a `Format => '…'` directive
  /// that RE-INTERPRETS the entry's on-disk value bytes with a different
  /// format (`Exif.pm:6728-6745`); `None` ⇒ read with the on-disk format.
  /// See [`FormatOverride`] for the read-count rule. The bundled rows with a
  /// directive are 0x0112/0x1000/0x200a/0x2037/0xb022/0xb02a (`Sony.pm`,
  /// cited at each row below); pinned by `tests/sony_main_format.rs`.
  pub format: Option<FormatOverride>,
}

impl SonyTag {
  /// `true` when bundled marks this tag `Unknown => 1` — suppressed in the
  /// default (`-j`, no `-u`) output (`ExifTool.pm:9179-9185`). Mirrors the
  /// Apple/Canon/Panasonic `is_unknown()` accessor.
  #[must_use]
  #[inline(always)]
  pub const fn is_unknown(&self) -> bool {
    self.unknown
  }
}

/// Sony Main SubDirectory targets — Phase 3 doesn't walk any of these
/// natively; each is surfaced as a raw blob/value so downstream sees the
/// presence + size.
///
/// Per [`exifast-camera-metadata-rescope`] memory, the most valuable
/// indexing data is already in the LEAF tags (Quality, ModelID, FocusMode/
/// AFAreaMode, lens, etc.); the sub-tables here mostly carry per-body
/// fine-grained AF/exposure state which is deferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubTable {
  /// `%Sony::CameraInfo`/`CameraInfo2`/`CameraInfo3`/`CameraInfoUnknown`
  /// dispatcher at 0x0010 (`Sony.pm:716-747`). Per-`count` conditional;
  /// deferred.
  CameraInfo,
  /// `%Sony::FocusInfo`/`MoreInfo` dispatcher at 0x0020 (`Sony.pm:750-769`).
  /// Deferred.
  FocusInfo,
  /// `%Sony::CameraSettings`/`CameraSettings2`/`CameraSettings3`/
  /// `CameraSettingsUnknown` dispatcher at 0x0114 (`Sony.pm:803-835`).
  /// Per-`count`; deferred.
  CameraSettings,
  /// `%Sony::ExtraInfo`/`ExtraInfo2`/`ExtraInfo3` dispatcher at 0x0116
  /// (`Sony.pm:856-873`). Deferred.
  ExtraInfo,
  /// `%Sony::ShotInfo` at 0x3000 (`Sony.pm:1768-1771`). Deferred.
  ShotInfo,
  /// `%Sony::Tag2010a`..`Tag2010i` dispatcher at 0x2010 (`Sony.pm:1100-1173`)
  /// — model-specific. Deferred.
  Tag2010,
  /// The encrypted `Tag9050x`/`Tag9400x`/`Tag9401`/`Tag9402`/`Tag9403`/
  /// `Tag9404x`/`Tag9405x`/`Tag9406x`/`Tag940a`/`Tag940c`/`Sony_0x9416`/
  /// `Tag900b`/`Tag202a` series (`Sony.pm:1573-2118`) — model-specific
  /// deciphered shot/AF/lens info. Deferred.
  Tag9xxx,
  /// `%Sony::AFInfo`/`Tag940e` dispatcher at 0x940e (`Sony.pm:2094-2105`).
  /// Deferred.
  AfInfo,
  /// `%Sony::Panorama` at 0x1003 (`Sony.pm:898-904`). Deferred.
  Panorama,
  /// `%Sony::HiddenInfo` at 0x2044 (`Sony.pm:1745-1748`). Deferred.
  HiddenInfo,
  /// `%Minolta::Main` SubIFD at 0xb028 (`Sony.pm:2373-2384`) — A100
  /// MinoltaMakerNote. Deferred.
  MinoltaMakerNote,
  /// `PrintIM::Main` at 0x0e00 (`Sony.pm:874-878`) — handled by a separate
  /// module. Surfaced raw.
  PrintIm,
}

/// `%Sony::Main` (`Sony.pm:707-2711`). Sorted by tag ID.
///
/// 114 rows — one per numeric key of the bundled hash.
pub const SONY_TAGS: &[SonyTag] = &[
  // 0x0010 CameraInfo (Sony.pm:716-747) — conditional ARRAY dispatcher.
  SonyTag {
    id: 0x0010,
    name: "CameraInfo",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::CameraInfo),
    unknown: false,
    format: None,
  },
  // 0x0020 FocusInfo (Sony.pm:750-769) — conditional ARRAY dispatcher.
  SonyTag {
    id: 0x0020,
    name: "FocusInfo",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::FocusInfo),
    unknown: false,
    format: None,
  },
  // 0x0102 Quality (Sony.pm:770-786) — int32u PrintConv.
  SonyTag {
    id: 0x0102,
    name: "Quality",
    conv: SonyPrintConv::Quality,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x0104 FlashExposureComp (Sony.pm:787-791) — rational64s.
  SonyTag {
    id: 0x0104,
    name: "FlashExposureComp",
    conv: SonyPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x0105 Teleconverter (Sony.pm:792-797) — Minolta teleconverters.
  SonyTag {
    id: 0x0105,
    name: "Teleconverter",
    conv: SonyPrintConv::Teleconverter,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x0112 WhiteBalanceFineTune (Sony.pm:798-802) — `Format => 'int32s'`
  // (`Writable => 'int32u'`): on-disk int32u, re-read as int32s.
  SonyTag {
    id: 0x0112,
    name: "WhiteBalanceFineTune",
    conv: SonyPrintConv::None,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int32s, None)),
  },
  // 0x0114 CameraSettings (Sony.pm:803-835) — conditional ARRAY dispatcher.
  SonyTag {
    id: 0x0114,
    name: "CameraSettings",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::CameraSettings),
    unknown: false,
    format: None,
  },
  // 0x0115 WhiteBalance (Sony.pm:836-853) — int32u PrintHex.
  SonyTag {
    id: 0x0115,
    name: "WhiteBalance",
    conv: SonyPrintConv::WhiteBalance,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x0116 ExtraInfo (Sony.pm:856-873) — conditional ARRAY dispatcher.
  SonyTag {
    id: 0x0116,
    name: "ExtraInfo",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::ExtraInfo),
    unknown: false,
    format: None,
  },
  // 0x0e00 PrintIM (Sony.pm:874-878) — SubDirectory.
  SonyTag {
    id: 0x0e00,
    name: "PrintIM",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::PrintIm),
    unknown: false,
    format: None,
  },
  // 0x1000 MultiBurstMode (Sony.pm:880-887) — 0=>Off,1=>On. `Format =>
  // 'int8u'` (`Writable => 'undef'`); the `Condition => '$format eq "undef"'`
  // (Sony.pm:882) is the ON-DISK format gate (kept separate from this
  // value-read override): on-disk `undef`, first byte re-read as int8u.
  SonyTag {
    id: 0x1000,
    name: "MultiBurstMode",
    conv: SonyPrintConv::OnOff,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int8u, None)),
  },
  // 0x1001 MultiBurstImageWidth (Sony.pm:888-892) — int16u.
  SonyTag {
    id: 0x1001,
    name: "MultiBurstImageWidth",
    conv: SonyPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x1002 MultiBurstImageHeight (Sony.pm:893-897) — int16u.
  SonyTag {
    id: 0x1002,
    name: "MultiBurstImageHeight",
    conv: SonyPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x1003 Panorama (Sony.pm:898-904) — SubDirectory.
  SonyTag {
    id: 0x1003,
    name: "Panorama",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::Panorama),
    unknown: false,
    format: None,
  },
  // 0x2001 PreviewImage (Sony.pm:906-948) — Binary, kept raw.
  SonyTag {
    id: 0x2001,
    name: "PreviewImage",
    conv: SonyPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2002 Rating (Sony.pm:949-952) — int32u (0-5 stars or 4294967295).
  SonyTag {
    id: 0x2002,
    name: "Rating",
    conv: SonyPrintConv::Rating,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2004 Contrast (Sony.pm:954-959) — int32s, $val>0?"+$val":$val.
  SonyTag {
    id: 0x2004,
    name: "Contrast",
    conv: SonyPrintConv::PlusOrInt,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2005 Saturation (Sony.pm:960-965) — int32s.
  SonyTag {
    id: 0x2005,
    name: "Saturation",
    conv: SonyPrintConv::PlusOrInt,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2006 Sharpness (Sony.pm:966-971) — int32s.
  SonyTag {
    id: 0x2006,
    name: "Sharpness",
    conv: SonyPrintConv::PlusOrInt,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2007 Brightness (Sony.pm:972-977) — int32s.
  SonyTag {
    id: 0x2007,
    name: "Brightness",
    conv: SonyPrintConv::PlusOrInt,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2008 LongExposureNoiseReduction (Sony.pm:978-990) — int32u PrintHex.
  SonyTag {
    id: 0x2008,
    name: "LongExposureNoiseReduction",
    conv: SonyPrintConv::LongExposureNr,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2009 HighISONoiseReduction (Sony.pm:991-1003) — int16u.
  SonyTag {
    id: 0x2009,
    name: "HighISONoiseReduction",
    conv: SonyPrintConv::HighIsoNr,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x200a HDR (Sony.pm:1004-1031) — `Format => 'int16u', Count => 2`
  // (`Writable => 'int32u'`, "stored as a 32-bit integer, but read as two
  // 16-bit integers"): on-disk int32u (4 bytes) re-read as two int16u.
  // Positional PrintConv [{A550-setting},{A580-result}], PrintHex, "; "-join.
  SonyTag {
    id: 0x200a,
    name: "HDR",
    conv: SonyPrintConv::Hdr,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16u, Some(2))),
  },
  // 0x200b MultiFrameNoiseReduction (Sony.pm:1032-1041) — int32u.
  SonyTag {
    id: 0x200b,
    name: "MultiFrameNoiseReduction",
    conv: SonyPrintConv::MultiFrameNr,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x200e PictureEffect (Sony.pm:1044-1085) — int16u.
  SonyTag {
    id: 0x200e,
    name: "PictureEffect",
    conv: SonyPrintConv::PictureEffect,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x200f SoftSkinEffect (Sony.pm:1086-1099) — int32u.
  SonyTag {
    id: 0x200f,
    name: "SoftSkinEffect",
    conv: SonyPrintConv::SoftSkinEffect,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2010 Tag2010a (Sony.pm:1100-1173) — conditional ARRAY dispatcher;
  // final branch is %unknownCipherData ⇒ Unknown=1.
  SonyTag {
    id: 0x2010,
    name: "Tag2010a",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::Tag2010),
    unknown: true,
    format: None,
  },
  // 0x2011 VignettingCorrection (Sony.pm:1174-1182) — int32u.
  SonyTag {
    id: 0x2011,
    name: "VignettingCorrection",
    conv: SonyPrintConv::OffAutoNa,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2012 LateralChromaticAberration (Sony.pm:1183-1191) — int32u.
  SonyTag {
    id: 0x2012,
    name: "LateralChromaticAberration",
    conv: SonyPrintConv::OffAutoNa,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2013 DistortionCorrectionSetting (Sony.pm:1192-1200) — int32u.
  SonyTag {
    id: 0x2013,
    name: "DistortionCorrectionSetting",
    conv: SonyPrintConv::OffAutoNa,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2014 WBShiftAB_GM (Sony.pm:1201-1209) — int32s[2].
  SonyTag {
    id: 0x2014,
    name: "WBShiftAB_GM",
    conv: SonyPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2016 AutoPortraitFramed (Sony.pm:1211-1216) — 0=>No,1=>Yes.
  SonyTag {
    id: 0x2016,
    name: "AutoPortraitFramed",
    conv: SonyPrintConv::NoYes,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2017 FlashAction (Sony.pm:1218-1228) — int32u.
  SonyTag {
    id: 0x2017,
    name: "FlashAction",
    conv: SonyPrintConv::FlashAction,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x201a ElectronicFrontCurtainShutter (Sony.pm:1232-1239) — int32u.
  SonyTag {
    id: 0x201a,
    name: "ElectronicFrontCurtainShutter",
    conv: SonyPrintConv::OffOn,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x201b FocusMode (Sony.pm:1240-1255) — int8u (SLT/ILCE newer mapping).
  SonyTag {
    id: 0x201b,
    name: "FocusMode",
    conv: SonyPrintConv::FocusMode2,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x201c AFAreaModeSetting (Sony.pm:1256-1306) — conditional ARRAY; the
  // per-`$$self{Model}` PrintConv branch is selected at parse time (the row
  // also sets the AFAreaILCx DataMember 0x201e reads).
  SonyTag {
    id: 0x201c,
    name: "AFAreaModeSetting",
    conv: SonyPrintConv::AfAreaModeSetting,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x201d FlexibleSpotPosition (Sony.pm:1307-1320) — int16u[2].
  SonyTag {
    id: 0x201d,
    name: "FlexibleSpotPosition",
    conv: SonyPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x201e AFPointSelected (Sony.pm:1321-1421) — conditional ARRAY; the
  // per-`$$self{Model}`/`AFAreaILCx`-DataMember PrintConv branch is selected
  // at parse time.
  SonyTag {
    id: 0x201e,
    name: "AFPointSelected",
    conv: SonyPrintConv::AfPointSelected,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2020 AFPointsUsed (Sony.pm:1426-1468) — conditional ARRAY; per-Model
  // BITMASK (DecodeBits), selected at parse time.
  SonyTag {
    id: 0x2020,
    name: "AFPointsUsed",
    conv: SonyPrintConv::AfPointsUsed,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2021 AFTracking (Sony.pm:1471-1480) — int8u.
  SonyTag {
    id: 0x2021,
    name: "AFTracking",
    conv: SonyPrintConv::AfTracking,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2022 FocalPlaneAFPointsUsed (Sony.pm:1487-1507) — conditional ARRAY;
  // per-Model BITMASK (empty lookup ⇒ `[n]` per set bit), selected at parse
  // time.
  SonyTag {
    id: 0x2022,
    name: "FocalPlaneAFPointsUsed",
    conv: SonyPrintConv::FocalPlaneAfPointsUsed,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2023 MultiFrameNREffect (Sony.pm:1508-1515) — int32u.
  SonyTag {
    id: 0x2023,
    name: "MultiFrameNREffect",
    conv: SonyPrintConv::MultiFrameNrEffect,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2026 WBShiftAB_GM_Precise (Sony.pm:1521-1530) — int32s[2]/1000,
  // sprintf("%.2f %.2f").
  SonyTag {
    id: 0x2026,
    name: "WBShiftAB_GM_Precise",
    conv: SonyPrintConv::WbShiftAbGmPrecise,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2027 FocusLocation (Sony.pm:1534-1543) — int16u[4].
  SonyTag {
    id: 0x2027,
    name: "FocusLocation",
    conv: SonyPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2028 VariableLowPassFilter (Sony.pm:1545-1556) — int16u[2].
  SonyTag {
    id: 0x2028,
    name: "VariableLowPassFilter",
    conv: SonyPrintConv::VariableLowPassFilter,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2029 RAWFileType (Sony.pm:1557-1567) — int16u.
  SonyTag {
    id: 0x2029,
    name: "RAWFileType",
    conv: SonyPrintConv::RawFileType,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x202a Tag202a (Sony.pm:1573-1577) — SubDirectory.
  SonyTag {
    id: 0x202a,
    name: "Tag202a",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::Tag9xxx),
    unknown: false,
    format: None,
  },
  // 0x202b PrioritySetInAWB (Sony.pm:1578-1586) — int8u.
  SonyTag {
    id: 0x202b,
    name: "PrioritySetInAWB",
    conv: SonyPrintConv::PrioritySetInAwb,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x202c MeteringMode2 (Sony.pm:1587-1599) — int16u PrintHex.
  SonyTag {
    id: 0x202c,
    name: "MeteringMode2",
    conv: SonyPrintConv::MeteringMode2,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x202d ExposureStandardAdjustment (Sony.pm:1600-1605) — rational64s.
  SonyTag {
    id: 0x202d,
    name: "ExposureStandardAdjustment",
    conv: SonyPrintConv::ExposureStandardAdjustment,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x202e Quality (Sony.pm:1606-1642) — int16u[2].
  SonyTag {
    id: 0x202e,
    name: "Quality",
    conv: SonyPrintConv::Quality2,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x202f PixelShiftInfo (Sony.pm:1643-1677) — undef[6], RawConv decode +
  // PrintConv hash with OTHER sub.
  SonyTag {
    id: 0x202f,
    name: "PixelShiftInfo",
    conv: SonyPrintConv::PixelShiftInfo,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2031 SerialNumber (Sony.pm:1678-1685) — string, ValueConv reorder.
  SonyTag {
    id: 0x2031,
    name: "SerialNumber",
    conv: SonyPrintConv::SerialNumber2031,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2032 Shadows (Sony.pm:1687-1692) — int32s.
  SonyTag {
    id: 0x2032,
    name: "Shadows",
    conv: SonyPrintConv::PlusOrInt,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2033 Highlights (Sony.pm:1693-1698) — int32s.
  SonyTag {
    id: 0x2033,
    name: "Highlights",
    conv: SonyPrintConv::PlusOrInt,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2034 Fade (Sony.pm:1699-1704) — int32s.
  SonyTag {
    id: 0x2034,
    name: "Fade",
    conv: SonyPrintConv::PlusOrInt,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2035 SharpnessRange (Sony.pm:1705-1710) — int32s.
  SonyTag {
    id: 0x2035,
    name: "SharpnessRange",
    conv: SonyPrintConv::PlusOrInt,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2036 Clarity (Sony.pm:1711-1716) — int32s.
  SonyTag {
    id: 0x2036,
    name: "Clarity",
    conv: SonyPrintConv::PlusOrInt,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2037 FocusFrameSize (Sony.pm:1717-1727) — `Format => 'int16u', Count =>
  // '3'`: re-read as three int16u; sprintf PrintConv ("%3dx%3d" or "n/a" when
  // the 3rd value is 0).
  SonyTag {
    id: 0x2037,
    name: "FocusFrameSize",
    conv: SonyPrintConv::FocusFrameSize,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16u, Some(3))),
  },
  // 0x2039 JPEG-HEIFSwitch (Sony.pm:1728-1736) — int16u.
  SonyTag {
    id: 0x2039,
    name: "JPEG-HEIFSwitch",
    conv: SonyPrintConv::JpegHeifSwitch,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2044 HiddenInfo (Sony.pm:1745-1748) — SubDirectory.
  SonyTag {
    id: 0x2044,
    name: "HiddenInfo",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::HiddenInfo),
    unknown: false,
    format: None,
  },
  // 0x204a FocusLocation2 (Sony.pm:1752-1757) — int16u[4].
  SonyTag {
    id: 0x204a,
    name: "FocusLocation2",
    conv: SonyPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x205c StepCropShooting (Sony.pm:1758-1767) — int8u (DSC-RX1RM3).
  SonyTag {
    id: 0x205c,
    name: "StepCropShooting",
    conv: SonyPrintConv::StepCropShooting,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x3000 ShotInfo (Sony.pm:1768-1771) — SubDirectory.
  SonyTag {
    id: 0x3000,
    name: "ShotInfo",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::ShotInfo),
    unknown: false,
    format: None,
  },
  // 0x900b Tag900b (Sony.pm:1784-1788) — SubDirectory.
  SonyTag {
    id: 0x900b,
    name: "Tag900b",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::Tag9xxx),
    unknown: false,
    format: None,
  },
  // 0x9050 Tag9050a (Sony.pm:1789-1825) — conditional ARRAY; final branch
  // %unknownCipherData ⇒ Unknown=1.
  SonyTag {
    id: 0x9050,
    name: "Tag9050a",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::Tag9xxx),
    unknown: true,
    format: None,
  },
  // 0x9400 Tag9400a (Sony.pm:1826-1861) — conditional ARRAY; final branch
  // %unknownCipherData ⇒ Unknown=1.
  SonyTag {
    id: 0x9400,
    name: "Tag9400a",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::Tag9xxx),
    unknown: true,
    format: None,
  },
  // 0x9401 Tag9401 (Sony.pm:1862-1934) — SubDirectory.
  SonyTag {
    id: 0x9401,
    name: "Tag9401",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::Tag9xxx),
    unknown: false,
    format: None,
  },
  // 0x9402 Tag9402 (Sony.pm:1935-1974) — conditional ARRAY; final branch
  // %unknownCipherData ⇒ Unknown=1.
  SonyTag {
    id: 0x9402,
    name: "Tag9402",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::Tag9xxx),
    unknown: true,
    format: None,
  },
  // 0x9403 Tag9403 (Sony.pm:1975-1978) — SubDirectory.
  SonyTag {
    id: 0x9403,
    name: "Tag9403",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::Tag9xxx),
    unknown: false,
    format: None,
  },
  // 0x9404 Tag9404a (Sony.pm:1990-2008) — conditional ARRAY; final branch
  // %unknownCipherData ⇒ Unknown=1.
  SonyTag {
    id: 0x9404,
    name: "Tag9404a",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::Tag9xxx),
    unknown: true,
    format: None,
  },
  // 0x9405 Tag9405a (Sony.pm:2024-2037) — conditional ARRAY; final branch
  // %unknownCipherData ⇒ Unknown=1.
  SonyTag {
    id: 0x9405,
    name: "Tag9405a",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::Tag9xxx),
    unknown: true,
    format: None,
  },
  // 0x9406 Tag9406 (Sony.pm:2038-2054) — conditional ARRAY; final branch
  // %unknownCipherData ⇒ Unknown=1.
  SonyTag {
    id: 0x9406,
    name: "Tag9406",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::Tag9xxx),
    unknown: true,
    format: None,
  },
  // 0x9407 Sony_0x9407 (Sony.pm:2055-2058) — %unknownCipherData ⇒ Unknown=1.
  SonyTag {
    id: 0x9407,
    name: "Sony_0x9407",
    conv: SonyPrintConv::None,
    sub_table: None,
    unknown: true,
    format: None,
  },
  // 0x9408 Sony_0x9408 (Sony.pm:2059-2062) — %unknownCipherData ⇒ Unknown=1.
  SonyTag {
    id: 0x9408,
    name: "Sony_0x9408",
    conv: SonyPrintConv::None,
    sub_table: None,
    unknown: true,
    format: None,
  },
  // 0x9409 Sony_0x9409 (Sony.pm:2063-2066) — %unknownCipherData ⇒ Unknown=1.
  SonyTag {
    id: 0x9409,
    name: "Sony_0x9409",
    conv: SonyPrintConv::None,
    sub_table: None,
    unknown: true,
    format: None,
  },
  // 0x940a Tag940a (Sony.pm:2067-2074) — conditional ARRAY; final branch
  // %unknownCipherData ⇒ Unknown=1.
  SonyTag {
    id: 0x940a,
    name: "Tag940a",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::Tag9xxx),
    unknown: true,
    format: None,
  },
  // 0x940b Sony_0x940b (Sony.pm:2075-2078) — %unknownCipherData ⇒ Unknown=1.
  SonyTag {
    id: 0x940b,
    name: "Sony_0x940b",
    conv: SonyPrintConv::None,
    sub_table: None,
    unknown: true,
    format: None,
  },
  // 0x940c Tag940c (Sony.pm:2079-2086) — conditional ARRAY; final branch
  // %unknownCipherData ⇒ Unknown=1.
  SonyTag {
    id: 0x940c,
    name: "Tag940c",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::Tag9xxx),
    unknown: true,
    format: None,
  },
  // 0x940d Sony_0x940d (Sony.pm:2087-2090) — %unknownCipherData ⇒ Unknown=1.
  SonyTag {
    id: 0x940d,
    name: "Sony_0x940d",
    conv: SonyPrintConv::None,
    sub_table: None,
    unknown: true,
    format: None,
  },
  // 0x940e AFInfo (Sony.pm:2094-2105) — conditional ARRAY; final branch
  // %unknownCipherData ⇒ Unknown=1.
  SonyTag {
    id: 0x940e,
    name: "AFInfo",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::AfInfo),
    unknown: true,
    format: None,
  },
  // 0x940f Sony_0x940f (Sony.pm:2106-2109) — %unknownCipherData ⇒ Unknown=1.
  SonyTag {
    id: 0x940f,
    name: "Sony_0x940f",
    conv: SonyPrintConv::None,
    sub_table: None,
    unknown: true,
    format: None,
  },
  // 0x9411 Sony_0x9411 (Sony.pm:2110-2114) — %unknownCipherData ⇒ Unknown=1.
  SonyTag {
    id: 0x9411,
    name: "Sony_0x9411",
    conv: SonyPrintConv::None,
    sub_table: None,
    unknown: true,
    format: None,
  },
  // 0x9416 Sony_0x9416 (Sony.pm:2115-2118) — SubDirectory (replaces 0x9405
  // for ILCE-7SM3+). Unknown=0 (plain SubDirectory, NOT cipher-data).
  SonyTag {
    id: 0x9416,
    name: "Sony_0x9416",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::Tag9xxx),
    unknown: false,
    format: None,
  },
  // 0xb000 FileFormat (Sony.pm:2119-2148) — int8u[4].
  SonyTag {
    id: 0xb000,
    name: "FileFormat",
    conv: SonyPrintConv::FileFormat,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb001 SonyModelID (Sony.pm:2149-2270) — int16u (%sonyModelID lookup).
  SonyTag {
    id: 0xb001,
    name: "SonyModelID",
    conv: SonyPrintConv::ModelId,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb020 CreativeStyle (Sony.pm:2271-2303) — string (label map + OTHER).
  SonyTag {
    id: 0xb020,
    name: "CreativeStyle",
    conv: SonyPrintConv::CreativeStyle,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb021 ColorTemperature (Sony.pm:2304-2309) — int32u.
  SonyTag {
    id: 0xb021,
    name: "ColorTemperature",
    conv: SonyPrintConv::ColorTemperature,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb022 ColorCompensationFilter (Sony.pm:2310-2315) — `Format => 'int32s'`
  // (`Writable => 'int32u'`, "written incorrectly as unsigned by Sony"):
  // on-disk int32u re-read as int32s (negative is green, positive magenta).
  SonyTag {
    id: 0xb022,
    name: "ColorCompensationFilter",
    conv: SonyPrintConv::None,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int32s, None)),
  },
  // 0xb023 SceneMode (Sony.pm:2316-2321) — %minoltaSceneMode lookup.
  SonyTag {
    id: 0xb023,
    name: "SceneMode",
    conv: SonyPrintConv::SceneMode,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb024 ZoneMatching (Sony.pm:2322-2330) — int32u.
  SonyTag {
    id: 0xb024,
    name: "ZoneMatching",
    conv: SonyPrintConv::ZoneMatching,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb025 DynamicRangeOptimizer (Sony.pm:2331-2354) — int32u.
  SonyTag {
    id: 0xb025,
    name: "DynamicRangeOptimizer",
    conv: SonyPrintConv::DynamicRangeOptimizer,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb026 ImageStabilization (Sony.pm:2355-2363) — int32u.
  SonyTag {
    id: 0xb026,
    name: "ImageStabilization",
    conv: SonyPrintConv::ImageStabilizationNa,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb027 LensType (Sony.pm:2364-2372) — int32u (%sonyLensTypes lookup,
  // A-mount; E-mount IDs resolve via %sonyLensTypes2 in lens_types).
  SonyTag {
    id: 0xb027,
    name: "LensType",
    conv: SonyPrintConv::LensType,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb028 MinoltaMakerNote (Sony.pm:2373-2384) — SubIFD → Minolta::Main.
  SonyTag {
    id: 0xb028,
    name: "MinoltaMakerNote",
    conv: SonyPrintConv::None,
    sub_table: Some(SubTable::MinoltaMakerNote),
    unknown: false,
    format: None,
  },
  // 0xb029 ColorMode (Sony.pm:2385-2390) — int32u, %Minolta::sonyColorMode.
  SonyTag {
    id: 0xb029,
    name: "ColorMode",
    conv: SonyPrintConv::ColorMode,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb02a LensSpec (Sony.pm:2391-2404) — `Format => 'undef', Count => 8`
  // (`Writable => 'int8u'`): on-disk int8u[8] re-read as 8 raw bytes;
  // ConvLensSpec ValueConv + PrintLensSpec PrintConv.
  SonyTag {
    id: 0xb02a,
    name: "LensSpec",
    conv: SonyPrintConv::LensSpec,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Undef, Some(8))),
  },
  // 0xb02b FullImageSize (Sony.pm:2405-2414) — int32u[2], "H x V".
  SonyTag {
    id: 0xb02b,
    name: "FullImageSize",
    conv: SonyPrintConv::ImageSizeHxV,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb02c PreviewImageSize (Sony.pm:2415-2423) — int32u[2], "H x V".
  SonyTag {
    id: 0xb02c,
    name: "PreviewImageSize",
    conv: SonyPrintConv::ImageSizeHxV,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb040 Macro (Sony.pm:2424-2434) — int16u.
  SonyTag {
    id: 0xb040,
    name: "Macro",
    conv: SonyPrintConv::Macro,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb041 ExposureMode (Sony.pm:2435-2475) — int16u.
  SonyTag {
    id: 0xb041,
    name: "ExposureMode",
    conv: SonyPrintConv::ExposureMode,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb042 FocusMode (Sony.pm:2476-2495) — int16u (older DSC).
  SonyTag {
    id: 0xb042,
    name: "FocusMode",
    conv: SonyPrintConv::FocusMode,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb043 AFAreaMode (Sony.pm:2496-2532) — conditional ARRAY; first branch
  // (older models).
  SonyTag {
    id: 0xb043,
    name: "AFAreaMode",
    conv: SonyPrintConv::AfAreaMode,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb044 AFIlluminator (Sony.pm:2533-2542) — int16u.
  SonyTag {
    id: 0xb044,
    name: "AFIlluminator",
    conv: SonyPrintConv::AfIlluminator,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb047 JPEGQuality (Sony.pm:2545-2555) — int16u.
  SonyTag {
    id: 0xb047,
    name: "JPEGQuality",
    conv: SonyPrintConv::JpegQuality,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb048 FlashLevel (Sony.pm:2556-2582) — int16s.
  SonyTag {
    id: 0xb048,
    name: "FlashLevel",
    conv: SonyPrintConv::FlashLevel,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb049 ReleaseMode (Sony.pm:2583-2595) — int16u.
  SonyTag {
    id: 0xb049,
    name: "ReleaseMode",
    conv: SonyPrintConv::ReleaseMode,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb04a SequenceNumber (Sony.pm:2596-2606) — int16u (0=>Single, OTHER).
  SonyTag {
    id: 0xb04a,
    name: "SequenceNumber",
    conv: SonyPrintConv::SequenceNumber,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb04b Anti-Blur (Sony.pm:2607-2617) — int16u.
  SonyTag {
    id: 0xb04b,
    name: "Anti-Blur",
    conv: SonyPrintConv::AntiBlur,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb04e FocusMode (Sony.pm:2634-2648) — int16u (HX9V generation+).
  SonyTag {
    id: 0xb04e,
    name: "FocusMode",
    conv: SonyPrintConv::FocusMode3,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb04f DynamicRangeOptimizer (Sony.pm:2649-2659) — int16u.
  SonyTag {
    id: 0xb04f,
    name: "DynamicRangeOptimizer",
    conv: SonyPrintConv::DynamicRangeOptimizer2,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb050 HighISONoiseReduction2 (Sony.pm:2660-2673) — int16u (DSC only).
  SonyTag {
    id: 0xb050,
    name: "HighISONoiseReduction2",
    conv: SonyPrintConv::HighIsoNr2,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb052 IntelligentAuto (Sony.pm:2675-2683) — int16u.
  SonyTag {
    id: 0xb052,
    name: "IntelligentAuto",
    conv: SonyPrintConv::IntelligentAuto,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb054 WhiteBalance (Sony.pm:2685-2710) — int16u.
  SonyTag {
    id: 0xb054,
    name: "WhiteBalance",
    conv: SonyPrintConv::WhiteBalance2,
    sub_table: None,
    unknown: false,
    format: None,
  },
];

/// Binary-search the table by tag ID.
#[must_use]
pub fn lookup(tag_id: u16) -> Option<&'static SonyTag> {
  match SONY_TAGS.binary_search_by_key(&tag_id, |t| t.id) {
    // `binary_search_by_key` returns the found index, so `i` is in-bounds;
    // `.get(i)` is the checked form (always `Some` here) — byte-identical.
    Ok(i) => SONY_TAGS.get(i),
    Err(_) => None,
  }
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C S2); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  #[test]
  fn table_sorted_for_binary_search() {
    let mut prev: i64 = -1;
    for t in SONY_TAGS {
      assert!(
        i64::from(t.id) > prev,
        "SONY_TAGS not strictly sorted: 0x{:04x} after {prev:#x}",
        t.id
      );
      prev = i64::from(t.id);
    }
  }

  #[test]
  fn lookup_quality() {
    let t = lookup(0x0102).expect("Quality present");
    assert_eq!(t.name, "Quality");
    assert_eq!(t.conv, SonyPrintConv::Quality);
    assert!(!t.is_unknown());
  }

  #[test]
  fn lookup_model_id() {
    let t = lookup(0xb001).expect("SonyModelID present");
    assert_eq!(t.name, "SonyModelID");
    assert_eq!(t.conv, SonyPrintConv::ModelId);
  }

  #[test]
  fn lookup_lens_type() {
    let t = lookup(0xb027).expect("LensType present");
    assert_eq!(t.name, "LensType");
    assert_eq!(t.conv, SonyPrintConv::LensType);
  }

  #[test]
  fn lookup_unknown_tag() {
    assert!(lookup(0xFFFF).is_none());
  }

  /// Bundled `%Sony::Main` has 114 numeric keys.
  #[test]
  fn table_has_114_rows() {
    assert_eq!(SONY_TAGS.len(), 114);
  }

  /// The confirmed-wrong leaf rows from the prior (wrong-version) table are
  /// now corrected to bundled 13.59 (`Sony.pm`).
  #[test]
  fn corrected_leaf_mappings() {
    assert_eq!(lookup(0x2028).unwrap().name, "VariableLowPassFilter"); // was Variance
    assert_eq!(lookup(0x202b).unwrap().name, "PrioritySetInAWB"); // was PictureProfile
    assert_eq!(lookup(0x202c).unwrap().name, "MeteringMode2"); // was PictureProfile2
    assert_eq!(lookup(0x202d).unwrap().name, "ExposureStandardAdjustment"); // was CreativeStyle2
    assert_eq!(lookup(0x202e).unwrap().name, "Quality"); // was UTC
    assert_eq!(lookup(0x202f).unwrap().name, "PixelShiftInfo"); // was DateTimeMode
    assert_eq!(lookup(0x2031).unwrap().name, "SerialNumber"); // was VariableLowPassFilter
    assert_eq!(lookup(0x2032).unwrap().name, "Shadows"); // was RAWFileType
    assert_eq!(lookup(0x2033).unwrap().name, "Highlights"); // was RAWBufferUsed
    assert_eq!(lookup(0x2034).unwrap().name, "Fade"); // was RAWFileLossless
    assert_eq!(lookup(0x2035).unwrap().name, "SharpnessRange"); // was PrioritySetInAWB
    assert_eq!(lookup(0x2036).unwrap().name, "Clarity"); // was MeteringMode3
    assert_eq!(lookup(0x2037).unwrap().name, "FocusFrameSize"); // was APS-CSizeCapture
    assert_eq!(lookup(0x2044).unwrap().name, "HiddenInfo"); // was RAWFileFormat
    assert_eq!(lookup(0x204a).unwrap().name, "FocusLocation2"); // was AspectRatio
    assert_eq!(lookup(0x205c).unwrap().name, "StepCropShooting"); // was Rx1Rm3Tag
    assert_eq!(lookup(0x2013).unwrap().name, "DistortionCorrectionSetting");
  }

  /// 0x202a is a SubDirectory (`Tag202a`), not the old leaf `MeteringMode2`.
  #[test]
  fn tag_202a_is_subdirectory() {
    let t = lookup(0x202a).unwrap();
    assert_eq!(t.name, "Tag202a");
    assert_eq!(t.sub_table, Some(SubTable::Tag9xxx));
  }

  /// The `%unknownCipherData` rows carry `Unknown => 1` (`Sony.pm:676`).
  #[test]
  fn cipher_data_tags_are_unknown() {
    for id in [
      0x2010u16, 0x9050, 0x9400, 0x9402, 0x9404, 0x9405, 0x9406, 0x9407, 0x9408, 0x9409, 0x940a,
      0x940b, 0x940c, 0x940d, 0x940e, 0x940f, 0x9411,
    ] {
      assert!(
        lookup(id).unwrap().is_unknown(),
        "0x{id:04x} should be Unknown"
      );
    }
    // Plain SubDirectory rows are NOT unknown.
    assert!(!lookup(0x9401).unwrap().is_unknown());
    assert!(!lookup(0x9403).unwrap().is_unknown());
    assert!(!lookup(0x9416).unwrap().is_unknown());
    assert!(!lookup(0x900b).unwrap().is_unknown());
  }

  /// Exactly 17 bundled Main tags are `Unknown => 1`.
  #[test]
  fn unknown_count_is_17() {
    assert_eq!(SONY_TAGS.iter().filter(|t| t.unknown).count(), 17);
  }
}
