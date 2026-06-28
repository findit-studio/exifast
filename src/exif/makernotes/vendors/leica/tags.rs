// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! The Leica MakerNote variant IFD tag tables —
//! `%Image::ExifTool::Panasonic::Leica2`..`Leica9` (`Panasonic.pm:1604-2256`).
//!
//! Faithful 1:1 port against bundled ExifTool 13.59 (`Panasonic.pm` `$VERSION`).
//! The dispatcher (`MakerNotes.pm:611-721`) detects EIGHT signature variants
//! (`MakerNoteLeica2`..`Leica9`), but two REUSE another variant's table:
//!
//! - **Leica7** (`MakerNotes.pm:690-701`, M Monochrom Typ 246) → `%Leica6`.
//! - **Leica8** (`MakerNotes.pm:703-712`, Q/SL/CL) → `%Leica5`.
//!
//! so there are SIX distinct tables: [`LeicaVariant::Leica2`]/`Leica3`/`Leica4`/
//! `Leica5`/`Leica6`/`Leica9`. The variant is threaded through the shared
//! `Walker` as the payload of
//! [`TableRef::Leica`](crate::exif::makernotes::subdir::TableRef::Leica).
//!
//! ## Scope (plain leaves + the binary sub-tables)
//!
//! This ports the PLAIN scalar/enum/string/lookup LEAVES of each table PLUS the
//! `ProcessBinaryData` SubDirectory pointers (a [`LeicaTag::sub_table`] marker,
//! decoded at capture time via [`super::decode_leica_subdir`], #105):
//!
//! - **Leica3** `0x0b SerialInfo` (`%Panasonic::SerialInfo`) descends to its
//!   binary block; `0x0d WB_RGBLevels` is the plain leaf.
//! - **Leica4** — every row is a SubDirectory into `%Panasonic::Subdir` (which
//!   chains into `Data1`/`Data2`); deferred. Leica4 carries no plain leaf.
//! - **Leica5** `0x040a FocusInfo` / `0x0410 ShotInfo` descend into their binary
//!   sub-tables; the `0x05ff CameraIFD` nested TIFF (`PanasonicRaw::CameraIFD`,
//!   raw-only) is out of scope.
//! - **Leica6** `0x300 PreviewImage` (a `RawConv` preview blob) + `0x301
//!   UnknownBlock` (`Unknown`+`Binary`+`Drop`) — deferred.

#![deny(clippy::indexing_slicing)]

use super::printconv::LeicaPrintConv;
use crate::exif::{ifd::Format, makernotes::vendors::FormatOverride};

/// Which Leica variant table a (sub-)directory walk resolves against. The
/// payload of [`TableRef::Leica`](crate::exif::makernotes::subdir::TableRef::Leica),
/// set by the dispatched MakerNote variant.
///
/// Six distinct tables; the eight dispatched signatures map here with Leica7 →
/// [`Leica6`](Self::Leica6) and Leica8 → [`Leica5`](Self::Leica5)
/// (`MakerNotes.pm:696`/`708`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LeicaVariant {
  /// `%Panasonic::Leica2` (`Panasonic.pm:1604`) — the M8.
  Leica2,
  /// `%Panasonic::Leica3` (`Panasonic.pm:1706`) — the R8/R9 backs.
  Leica3,
  /// `%Panasonic::Leica4` (`Panasonic.pm:1736`) — the M9/M-Monochrom (all rows
  /// are deferred SubDirectories ⇒ emits nothing).
  Leica4,
  /// `%Panasonic::Leica5` (`Panasonic.pm:1997`) — the X1/X2/X-VARIO/T/X-U AND
  /// (via Leica8) the Q/SL/CL.
  Leica5,
  /// `%Panasonic::Leica6` (`Panasonic.pm:2112`) — the S2/M-Typ240/S-Typ006 AND
  /// (via Leica7) the M Monochrom Typ 246.
  Leica6,
  /// `%Panasonic::Leica9` (`Panasonic.pm:2193`) — the S-Typ007/M10.
  Leica9,
  /// `%Panasonic::Subdir` (`Panasonic.pm:1773`) — the Leica M9 sub-IFD the four
  /// Leica4 `0x3000`/`0x3100`/`0x3400`/`0x3900` rows descend into (#105). Not a
  /// dispatched top-level variant; reached only via the in-walk Leica4 descent,
  /// walked under `ByteOrder => Unknown`.
  Subdir,
}

impl LeicaVariant {
  /// The family-1 group the variant emits under — always `"Leica"`
  /// (`Panasonic.pm` Leica tables declare `GROUPS => { 1 => 'Leica' }`).
  #[must_use]
  #[inline(always)]
  pub const fn group1(self) -> &'static str {
    "Leica"
  }
}

/// A Leica `ProcessBinaryData` SubDirectory target reached from a Leica variant
/// IFD row (#105). The binary block is decoded at capture time (the verbatim
/// `$$valPt` span) and its positions emit under the `Leica` family-1 group via
/// [`super::decode_leica_subdir`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeicaSubTable {
  /// `%Panasonic::SerialInfo` — Leica3 0x0b (`Panasonic.pm:1724`).
  SerialInfo,
  /// `%Panasonic::FocusInfo` — Leica5 0x040a (`Panasonic.pm:2084`).
  FocusInfo,
  /// `%Panasonic::ShotInfo` — Leica5 0x0410 (`Panasonic.pm:2069`).
  ShotInfo,
  /// `%Panasonic::Data1` — Subdir 0x3901 (`Panasonic.pm:1970`); one `LensType`
  /// at byte 22.
  Data1,
  /// `%Panasonic::Data2` — Subdir 0x3902 (`Panasonic.pm:1989`); an EMPTY table
  /// (no named positions), so it descends but emits nothing.
  Data2,
}

/// One Leica variant-table IFD tag — a plain LEAF, or (when [`sub_table`] is
/// `Some`) a `ProcessBinaryData` SubDirectory pointer descended at capture time.
///
/// [`sub_table`]: LeicaTag::sub_table
#[derive(Debug, Clone, Copy)]
pub struct LeicaTag {
  /// Tag ID (the `Panasonic.pm` Leica hash key).
  pub id: u16,
  /// `Name => '…'` from bundled.
  pub name: &'static str,
  /// Conversion strategy.
  pub conv: LeicaPrintConv,
  /// `Some(FormatOverride)` when bundled carries a `Format => '…'` directive
  /// that RE-INTERPRETS the entry's on-disk bytes (`Exif.pm:6728-6745`) — the
  /// `rational64s` brightness rows.
  pub format: Option<FormatOverride>,
  /// `Some(condition)` when the row carries a `Condition` that gates emission
  /// (the Leica5 0x0303 `$format eq "string"`, the Leica6 Typ-006 rows).
  pub condition: Option<LeicaCondition>,
  /// `Some(sub)` when the row is a `ProcessBinaryData` SubDirectory pointer
  /// descended at capture time (#105); `None` for a plain leaf.
  pub sub_table: Option<LeicaSubTable>,
}

impl LeicaTag {
  /// The resolved tag name (`Name => '…'`).
  #[must_use]
  #[inline(always)]
  pub const fn name(&self) -> &'static str {
    self.name
  }

  /// The tag's optional `Format =>` directive (`Exif.pm:6728-6745`).
  #[must_use]
  #[inline(always)]
  pub const fn format_override(&self) -> Option<FormatOverride> {
    self.format
  }

  /// The tag's emission `Condition`, if any.
  #[must_use]
  #[inline(always)]
  pub const fn condition(&self) -> Option<LeicaCondition> {
    self.condition
  }

  /// The row's `ProcessBinaryData` SubDirectory target, if any (#105).
  #[must_use]
  #[inline(always)]
  pub const fn sub_table(&self) -> Option<LeicaSubTable> {
    self.sub_table
  }
}

/// A row-level `Condition` that gates whether the tag is emitted (the faithful
/// port of ExifTool's `GetTagInfo` returning no tag when the `Condition` fails).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeicaCondition {
  /// `$format eq "string"` (Leica5 0x0303 `LensType`, `Panasonic.pm:2007`) —
  /// emit only when the entry's ON-DISK format is `string` (ASCII). The T body
  /// writes a string here; other bodies write a non-string `LensType` (a binary
  /// id) that this row must NOT claim.
  FormatIsString,
  /// `$$self{Model} =~ /Typ 006/` (Leica6 0x311/0x312/0x320/0x321,
  /// `Panasonic.pm:2160`+) — emit only for the Leica S (Typ 006).
  ModelTyp006,
}

/// `%Panasonic::Leica2` (`Panasonic.pm:1604-1703`) — the M8. 19 plain leaves.
pub const LEICA2_TAGS: &[LeicaTag] = &[
  // 0x300 Quality (Panasonic.pm:1610) — int16u, 1=>Fine 2=>Basic.
  LeicaTag {
    id: 0x300,
    name: "Quality",
    conv: LeicaPrintConv::Quality,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x302 UserProfile (Panasonic.pm:1617) — int32u label hash.
  LeicaTag {
    id: 0x302,
    name: "UserProfile",
    conv: LeicaPrintConv::UserProfile2,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x303 SerialNumber (Panasonic.pm:1628) — int32u, sprintf("%.7d",$val).
  LeicaTag {
    id: 0x303,
    name: "SerialNumber",
    conv: LeicaPrintConv::SerialNumber7,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x304 WhiteBalance (Panasonic.pm:1631) — int16u label hash + Kelvin OTHER.
  LeicaTag {
    id: 0x304,
    name: "WhiteBalance",
    conv: LeicaPrintConv::WhiteBalance2,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x310 LensType (Panasonic.pm:1649) — int32u, %leicaLensTypes.
  LeicaTag {
    id: 0x310,
    name: "LensType",
    conv: LeicaPrintConv::LensType,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x311 ExternalSensorBrightnessValue (Panasonic.pm:1657) — Format rational64s, sprintf("%.2f").
  LeicaTag {
    id: 0x311,
    name: "ExternalSensorBrightnessValue",
    conv: LeicaPrintConv::Sprintf2f,
    format: Some(FormatOverride::new(Format::Rational64s, None)),
    condition: None,
    sub_table: None,
  },
  // 0x312 MeasuredLV (Panasonic.pm:1663) — Format rational64s, sprintf("%.2f").
  LeicaTag {
    id: 0x312,
    name: "MeasuredLV",
    conv: LeicaPrintConv::Sprintf2f,
    format: Some(FormatOverride::new(Format::Rational64s, None)),
    condition: None,
    sub_table: None,
  },
  // 0x313 ApproximateFNumber (Panasonic.pm:1669) — rational64u, sprintf("%.1f").
  LeicaTag {
    id: 0x313,
    name: "ApproximateFNumber",
    conv: LeicaPrintConv::Sprintf1f,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x320 CameraTemperature (Panasonic.pm:1679) — int32s, "$val C".
  LeicaTag {
    id: 0x320,
    name: "CameraTemperature",
    conv: LeicaPrintConv::CameraTemperatureC,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x321 ColorTemperature (Panasonic.pm:1658) — int32u, raw.
  LeicaTag {
    id: 0x321,
    name: "ColorTemperature",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x322 WBRedLevel (Panasonic.pm:1659) — rational64u, raw.
  LeicaTag {
    id: 0x322,
    name: "WBRedLevel",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x323 WBGreenLevel (Panasonic.pm:1660) — rational64u, raw.
  LeicaTag {
    id: 0x323,
    name: "WBGreenLevel",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x324 WBBlueLevel (Panasonic.pm:1661) — rational64u, raw.
  LeicaTag {
    id: 0x324,
    name: "WBBlueLevel",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x325 UV-IRFilterCorrection (Panasonic.pm:1689) — int32u, 0=>Not Active 1=>Active.
  LeicaTag {
    id: 0x325,
    name: "UV-IRFilterCorrection",
    conv: LeicaPrintConv::UvIrFilterCorrection,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x330 CCDVersion (Panasonic.pm:1671) — int32u, raw.
  LeicaTag {
    id: 0x330,
    name: "CCDVersion",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x331 CCDBoardVersion (Panasonic.pm:1672) — int32u, raw.
  LeicaTag {
    id: 0x331,
    name: "CCDBoardVersion",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x332 ControllerBoardVersion (Panasonic.pm:1673) — int32u, raw.
  LeicaTag {
    id: 0x332,
    name: "ControllerBoardVersion",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x333 M16CVersion (Panasonic.pm:1674) — int32u, raw.
  LeicaTag {
    id: 0x333,
    name: "M16CVersion",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x340 ImageIDNumber (Panasonic.pm:1702) — int32u, raw.
  LeicaTag {
    id: 0x340,
    name: "ImageIDNumber",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
];

/// `%Panasonic::Leica3` (`Panasonic.pm:1706-1721`) — the R8/R9 backs. `0x0b`
/// descends into the `%Panasonic::SerialInfo` binary sub-table (#105); `0x0d
/// WB_RGBLevels` is the plain leaf.
pub const LEICA3_TAGS: &[LeicaTag] = &[
  // 0x0b SerialInfo (Panasonic.pm:1712) — ProcessBinaryData SubDirectory.
  LeicaTag {
    id: 0x0b,
    name: "SerialInfo",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: Some(LeicaSubTable::SerialInfo),
  },
  // 0x0d WB_RGBLevels (Panasonic.pm:1719) — int16u Count 3, space-joined.
  LeicaTag {
    id: 0x0d,
    name: "WB_RGBLevels",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
];

/// `%Panasonic::Leica4` (`Panasonic.pm:1736-1770`) — the M9. EVERY row
/// (`0x3000`/`0x3100`/`0x3400`/`0x3900`) is an IFD SubDirectory into
/// `%Panasonic::Subdir` walked under `ByteOrder => Unknown` (#105); the descent
/// is handled IN-WALK (keyed on `active_table == Leica(Leica4)`), so this table
/// carries NO plain leaf and `lookup` returns `None` for every Leica4 id.
pub const LEICA4_TAGS: &[LeicaTag] = &[];

/// `%Panasonic::Subdir` (`Panasonic.pm:1773-1936`) — the Leica M9 sub-IFD tags
/// (#105). Reached via the Leica4 `0x3000`/… descent. The plain leaves use the
/// pre-built M9 conversions; `0x3901`/`0x3902` descend into the `Data1`/`Data2`
/// binary sub-tables. Sorted by tag ID (binary-search-ready).
pub const SUBDIR_TAGS: &[LeicaTag] = &[
  // 0x300a Contrast (Panasonic.pm:1781) — int32u label hash.
  LeicaTag {
    id: 0x300a,
    name: "Contrast",
    conv: LeicaPrintConv::ContrastLevel,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x300b Sharpening (Panasonic.pm:1792) — int32u label hash.
  LeicaTag {
    id: 0x300b,
    name: "Sharpening",
    conv: LeicaPrintConv::Sharpening,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x300d Saturation (Panasonic.pm:1803) — Contrast hash + B&W extras.
  LeicaTag {
    id: 0x300d,
    name: "Saturation",
    conv: LeicaPrintConv::SaturationLevel,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x3033 WhiteBalance (Panasonic.pm:1817) — M9 white-balance hash.
  LeicaTag {
    id: 0x3033,
    name: "WhiteBalance",
    conv: LeicaPrintConv::WhiteBalanceM9,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x3034 JPEGQuality (Panasonic.pm:1833) — 94=>Basic, 97=>Fine.
  LeicaTag {
    id: 0x3034,
    name: "JPEGQuality",
    conv: LeicaPrintConv::JpegQuality,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x3036 WB_RGBLevels (Panasonic.pm:1842) — rational64u Count 3, space-joined.
  LeicaTag {
    id: 0x3036,
    name: "WB_RGBLevels",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x3038 UserProfile (Panasonic.pm:1847) — string.
  LeicaTag {
    id: 0x3038,
    name: "UserProfile",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x303a JPEGSize (Panasonic.pm:1851) — M9 resolution hash.
  LeicaTag {
    id: 0x303a,
    name: "JPEGSize",
    conv: LeicaPrintConv::JpegSize,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x3103 SerialNumber (Panasonic.pm:1862) — string.
  LeicaTag {
    id: 0x3103,
    name: "SerialNumber",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x3109 FirmwareVersion (Panasonic.pm:1869) — string.
  LeicaTag {
    id: 0x3109,
    name: "FirmwareVersion",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x312a BaseISO (Panasonic.pm:1873) — int32u, raw.
  LeicaTag {
    id: 0x312a,
    name: "BaseISO",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x312b SensorWidth (Panasonic.pm:1877) — int32u, raw.
  LeicaTag {
    id: 0x312b,
    name: "SensorWidth",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x312c SensorHeight (Panasonic.pm:1881) — int32u, raw.
  LeicaTag {
    id: 0x312c,
    name: "SensorHeight",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x312d SensorBitDepth (Panasonic.pm:1885) — int32u, raw.
  LeicaTag {
    id: 0x312d,
    name: "SensorBitDepth",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x3402 CameraTemperature (Panasonic.pm:1889) — int32s, "$val C".
  LeicaTag {
    id: 0x3402,
    name: "CameraTemperature",
    conv: LeicaPrintConv::CameraTemperatureC,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x3405 LensType (Panasonic.pm:1895) — int32u, %leicaLensTypes.
  LeicaTag {
    id: 0x3405,
    name: "LensType",
    conv: LeicaPrintConv::LensType,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x3406 ApproximateFNumber (Panasonic.pm:1903) — rational64u, sprintf("%.1f").
  LeicaTag {
    id: 0x3406,
    name: "ApproximateFNumber",
    conv: LeicaPrintConv::Sprintf1f,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x3407 MeasuredLV (Panasonic.pm:1909) — int32s, /1e5, sprintf("%.2f").
  LeicaTag {
    id: 0x3407,
    name: "MeasuredLV",
    conv: LeicaPrintConv::Div1e5Sprintf2f,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x3408 ExternalSensorBrightnessValue (Panasonic.pm:1918) — int32s, /1e5, "%.2f".
  LeicaTag {
    id: 0x3408,
    name: "ExternalSensorBrightnessValue",
    conv: LeicaPrintConv::Div1e5Sprintf2f,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x3901 Data1 (Panasonic.pm:1927) — ProcessBinaryData SubDirectory.
  LeicaTag {
    id: 0x3901,
    name: "Data1",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: Some(LeicaSubTable::Data1),
  },
  // 0x3902 Data2 (Panasonic.pm:1931) — ProcessBinaryData SubDirectory (empty).
  LeicaTag {
    id: 0x3902,
    name: "Data2",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: Some(LeicaSubTable::Data2),
  },
];

/// `%Panasonic::Leica5` (`Panasonic.pm:1997-2066`) — X1/X2/X-VARIO/T/X-U +
/// (via Leica8) Q/SL/CL. `PRIORITY => 0` at the table level. `0x040a FocusInfo`
/// / `0x0410 ShotInfo` descend into their binary sub-tables (#105); the `0x05ff
/// CameraIFD` nested TIFF (a `PanasonicRaw::CameraIFD` / raw-only directory) is
/// out of scope.
pub const LEICA5_TAGS: &[LeicaTag] = &[
  // 0x0303 LensType (Panasonic.pm:2004) — string, Condition $format eq "string" (Leica T only).
  LeicaTag {
    id: 0x0303,
    name: "LensType",
    conv: LeicaPrintConv::None,
    format: None,
    condition: Some(LeicaCondition::FormatIsString),
    sub_table: None,
  },
  // 0x0305 SerialNumber (Panasonic.pm:2014) — int32u, raw.
  LeicaTag {
    id: 0x0305,
    name: "SerialNumber",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x0407 OriginalFileName (Panasonic.pm:2023) — string.
  LeicaTag {
    id: 0x0407,
    name: "OriginalFileName",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x0408 OriginalDirectory (Panasonic.pm:2024) — string.
  LeicaTag {
    id: 0x0408,
    name: "OriginalDirectory",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x040a FocusInfo (Panasonic.pm:2021) — ProcessBinaryData SubDirectory.
  LeicaTag {
    id: 0x040a,
    name: "FocusInfo",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: Some(LeicaSubTable::FocusInfo),
  },
  // 0x040d ExposureMode (Panasonic.pm:2047) — Format int8u[4], PrintConv hash.
  LeicaTag {
    id: 0x040d,
    name: "ExposureMode",
    conv: LeicaPrintConv::ExposureMode5,
    format: Some(FormatOverride::new(Format::Int8u, Some(4))),
    condition: None,
    sub_table: None,
  },
  // 0x0410 ShotInfo (Panasonic.pm:2039) — ProcessBinaryData SubDirectory.
  LeicaTag {
    id: 0x0410,
    name: "ShotInfo",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: Some(LeicaSubTable::ShotInfo),
  },
  // 0x0412 FilmMode (Panasonic.pm:2065) — string.
  LeicaTag {
    id: 0x0412,
    name: "FilmMode",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x0413 WB_RGBLevels (Panasonic.pm:2066) — rational64u Count 3, space-joined.
  LeicaTag {
    id: 0x0413,
    name: "WB_RGBLevels",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x0500 InternalSerialNumber (Panasonic.pm:2047) — undef, date-encoded PrintConv.
  LeicaTag {
    id: 0x0500,
    name: "InternalSerialNumber",
    conv: LeicaPrintConv::InternalSerialNumber,
    format: None,
    condition: None,
    sub_table: None,
  },
];

/// `%Panasonic::Leica6` (`Panasonic.pm:2112-2190`) — S2/M-Typ240/S-Typ006 +
/// (via Leica7) M Monochrom Typ 246. The `0x300 PreviewImage` /
/// `0x301 UnknownBlock` binary rows are deferred. The Typ-006-only rows
/// (0x311/0x312/0x320/0x321) carry a Model `Condition`.
pub const LEICA6_TAGS: &[LeicaTag] = &[
  // 0x303 LensType (Panasonic.pm:2142) — string, ValueConv trailing-space trim, no PrintConv.
  LeicaTag {
    id: 0x303,
    name: "LensType",
    conv: LeicaPrintConv::LensTypeTrim,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x304 FocusDistance (Panasonic.pm:2154) — int32u, raw.
  LeicaTag {
    id: 0x304,
    name: "FocusDistance",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x311 ExternalSensorBrightnessValue (Panasonic.pm:2153) — Format rational64s, Condition Typ 006, sprintf("%.2f").
  LeicaTag {
    id: 0x311,
    name: "ExternalSensorBrightnessValue",
    conv: LeicaPrintConv::Sprintf2f,
    format: Some(FormatOverride::new(Format::Rational64s, None)),
    condition: Some(LeicaCondition::ModelTyp006),
    sub_table: None,
  },
  // 0x312 MeasuredLV (Panasonic.pm:2160) — Format rational64s, Condition Typ 006, sprintf("%.2f").
  LeicaTag {
    id: 0x312,
    name: "MeasuredLV",
    conv: LeicaPrintConv::Sprintf2f,
    format: Some(FormatOverride::new(Format::Rational64s, None)),
    condition: Some(LeicaCondition::ModelTyp006),
    sub_table: None,
  },
  // 0x320 FirmwareVersion (Panasonic.pm:2171) — int8u Count 4, Condition Typ 006, $val=~tr/ /./.
  LeicaTag {
    id: 0x320,
    name: "FirmwareVersion",
    conv: LeicaPrintConv::FirmwareVersionDots,
    format: None,
    condition: Some(LeicaCondition::ModelTyp006),
    sub_table: None,
  },
  // 0x321 LensSerialNumber (Panasonic.pm:2179) — int32u, Condition Typ 006, sprintf("%.10d").
  LeicaTag {
    id: 0x321,
    name: "LensSerialNumber",
    conv: LeicaPrintConv::Sprintf10d,
    format: None,
    condition: Some(LeicaCondition::ModelTyp006),
    sub_table: None,
  },
];

/// `%Panasonic::Leica9` (`Panasonic.pm:2193-2256`) — S-Typ007/M10. 10 plain
/// leaves.
pub const LEICA9_TAGS: &[LeicaTag] = &[
  // 0x304 FocusDistance (Panasonic.pm:2197) — int32u, raw.
  LeicaTag {
    id: 0x304,
    name: "FocusDistance",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x311 ExternalSensorBrightnessValue (Panasonic.pm:2203) — Format rational64s, sprintf("%.2f").
  LeicaTag {
    id: 0x311,
    name: "ExternalSensorBrightnessValue",
    conv: LeicaPrintConv::Sprintf2f,
    format: Some(FormatOverride::new(Format::Rational64s, None)),
    condition: None,
    sub_table: None,
  },
  // 0x312 MeasuredLV (Panasonic.pm:2208) — Format rational64s, sprintf("%.2f").
  LeicaTag {
    id: 0x312,
    name: "MeasuredLV",
    conv: LeicaPrintConv::Sprintf2f,
    format: Some(FormatOverride::new(Format::Rational64s, None)),
    condition: None,
    sub_table: None,
  },
  // 0x34c UserProfile (Panasonic.pm:2218) — string.
  LeicaTag {
    id: 0x34c,
    name: "UserProfile",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x359 ISOSelected (Panasonic.pm:2223) — int32s, 0=>Auto + identity OTHER.
  LeicaTag {
    id: 0x359,
    name: "ISOSelected",
    conv: LeicaPrintConv::IsoSelected,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x35a FNumber (Panasonic.pm:2231) — int32s, ValueConv /1000, sprintf("%.1f").
  LeicaTag {
    id: 0x35a,
    name: "FNumber",
    conv: LeicaPrintConv::Div1000Sprintf1f,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x35b CorrelatedColorTemp (Panasonic.pm:2233) — int16u, raw.
  LeicaTag {
    id: 0x35b,
    name: "CorrelatedColorTemp",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x35c ColorTint (Panasonic.pm:2234) — int16s, raw.
  LeicaTag {
    id: 0x35c,
    name: "ColorTint",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x35d WhitePoint (Panasonic.pm:2235) — rational64u Count 2, space-joined.
  LeicaTag {
    id: 0x35d,
    name: "WhitePoint",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
  // 0x370 LensProfileName (Panasonic.pm:2238) — string.
  LeicaTag {
    id: 0x370,
    name: "LensProfileName",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
    sub_table: None,
  },
];

/// The tag slice for a variant. Leica7 → Leica6, Leica8 → Leica5
/// (handled by the dispatcher mapping the signatures to the table-bearing
/// [`LeicaVariant`]).
#[must_use]
const fn table_for(variant: LeicaVariant) -> &'static [LeicaTag] {
  match variant {
    LeicaVariant::Leica2 => LEICA2_TAGS,
    LeicaVariant::Leica3 => LEICA3_TAGS,
    LeicaVariant::Leica4 => LEICA4_TAGS,
    LeicaVariant::Leica5 => LEICA5_TAGS,
    LeicaVariant::Leica6 => LEICA6_TAGS,
    LeicaVariant::Leica9 => LEICA9_TAGS,
    LeicaVariant::Subdir => SUBDIR_TAGS,
  }
}

/// Resolve a Leica tag by ID within `variant`'s table. `None` ⇒ not a ported
/// leaf (the shared `Walker` then drops it, the unknown-tag skip). Every table
/// is sorted by tag ID (binary-search-ready).
#[must_use]
pub fn lookup(variant: LeicaVariant, tag_id: u16) -> Option<&'static LeicaTag> {
  let tags = table_for(variant);
  match tags.binary_search_by_key(&tag_id, |t| t.id) {
    Ok(i) => tags.get(i),
    Err(_) => None,
  }
}

/// The `Format =>` directive's FORMAT for tag `id` under `variant`'s table, if
/// any — the per-table override the shared `Walker` resolves
/// (`Exif.pm:6729`). `None` for an unknown tag or a tag with no directive.
#[must_use]
pub fn format_override(variant: LeicaVariant, id: u16) -> Option<Format> {
  lookup(variant, id)
    .and_then(LeicaTag::format_override)
    .map(FormatOverride::format)
}
