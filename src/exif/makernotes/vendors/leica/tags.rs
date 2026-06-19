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
//! ## Phase scope (the plain camera-indexing leaves)
//!
//! Mirroring the Samsung/Pentax ports, this ports the PLAIN scalar/enum/string/
//! lookup LEAVES of each table. The binary `ProcessBinaryData` sub-tables and
//! the chained IFD SubDirectories are DEFERRED — their tag IDs are simply ABSENT
//! from the tables, so the shared `Walker` drops them (unknown-tag skip):
//!
//! - **Leica3** `0x0b SerialInfo` (`%Panasonic::SerialInfo` binary) — deferred;
//!   only `0x0d WB_RGBLevels` is a plain leaf.
//! - **Leica4** — every row is a SubDirectory into `%Panasonic::Subdir` (which
//!   chains into `Data1`/`Data2`); deferred. Leica4 therefore emits no plain
//!   leaf of its own (it routes correctly + emits nothing, not spurious tags).
//! - **Leica5** `0x040a FocusInfo` / `0x0410 ShotInfo` (binary) + `0x05ff
//!   CameraIFD` (a nested TIFF) — deferred.
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

/// One Leica variant-table IFD tag (a plain LEAF — the deferred SubDirectory /
/// binary rows are absent from the tables).
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
  },
  // 0x302 UserProfile (Panasonic.pm:1617) — int32u label hash.
  LeicaTag {
    id: 0x302,
    name: "UserProfile",
    conv: LeicaPrintConv::UserProfile2,
    format: None,
    condition: None,
  },
  // 0x303 SerialNumber (Panasonic.pm:1628) — int32u, sprintf("%.7d",$val).
  LeicaTag {
    id: 0x303,
    name: "SerialNumber",
    conv: LeicaPrintConv::SerialNumber7,
    format: None,
    condition: None,
  },
  // 0x304 WhiteBalance (Panasonic.pm:1631) — int16u label hash + Kelvin OTHER.
  LeicaTag {
    id: 0x304,
    name: "WhiteBalance",
    conv: LeicaPrintConv::WhiteBalance2,
    format: None,
    condition: None,
  },
  // 0x310 LensType (Panasonic.pm:1649) — int32u, %leicaLensTypes.
  LeicaTag {
    id: 0x310,
    name: "LensType",
    conv: LeicaPrintConv::LensType,
    format: None,
    condition: None,
  },
  // 0x311 ExternalSensorBrightnessValue (Panasonic.pm:1657) — Format rational64s, sprintf("%.2f").
  LeicaTag {
    id: 0x311,
    name: "ExternalSensorBrightnessValue",
    conv: LeicaPrintConv::Sprintf2f,
    format: Some(FormatOverride::new(Format::Rational64s, None)),
    condition: None,
  },
  // 0x312 MeasuredLV (Panasonic.pm:1663) — Format rational64s, sprintf("%.2f").
  LeicaTag {
    id: 0x312,
    name: "MeasuredLV",
    conv: LeicaPrintConv::Sprintf2f,
    format: Some(FormatOverride::new(Format::Rational64s, None)),
    condition: None,
  },
  // 0x313 ApproximateFNumber (Panasonic.pm:1669) — rational64u, sprintf("%.1f").
  LeicaTag {
    id: 0x313,
    name: "ApproximateFNumber",
    conv: LeicaPrintConv::Sprintf1f,
    format: None,
    condition: None,
  },
  // 0x320 CameraTemperature (Panasonic.pm:1679) — int32s, "$val C".
  LeicaTag {
    id: 0x320,
    name: "CameraTemperature",
    conv: LeicaPrintConv::CameraTemperatureC,
    format: None,
    condition: None,
  },
  // 0x321 ColorTemperature (Panasonic.pm:1658) — int32u, raw.
  LeicaTag {
    id: 0x321,
    name: "ColorTemperature",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
  },
  // 0x322 WBRedLevel (Panasonic.pm:1659) — rational64u, raw.
  LeicaTag {
    id: 0x322,
    name: "WBRedLevel",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
  },
  // 0x323 WBGreenLevel (Panasonic.pm:1660) — rational64u, raw.
  LeicaTag {
    id: 0x323,
    name: "WBGreenLevel",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
  },
  // 0x324 WBBlueLevel (Panasonic.pm:1661) — rational64u, raw.
  LeicaTag {
    id: 0x324,
    name: "WBBlueLevel",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
  },
  // 0x325 UV-IRFilterCorrection (Panasonic.pm:1689) — int32u, 0=>Not Active 1=>Active.
  LeicaTag {
    id: 0x325,
    name: "UV-IRFilterCorrection",
    conv: LeicaPrintConv::UvIrFilterCorrection,
    format: None,
    condition: None,
  },
  // 0x330 CCDVersion (Panasonic.pm:1671) — int32u, raw.
  LeicaTag {
    id: 0x330,
    name: "CCDVersion",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
  },
  // 0x331 CCDBoardVersion (Panasonic.pm:1672) — int32u, raw.
  LeicaTag {
    id: 0x331,
    name: "CCDBoardVersion",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
  },
  // 0x332 ControllerBoardVersion (Panasonic.pm:1673) — int32u, raw.
  LeicaTag {
    id: 0x332,
    name: "ControllerBoardVersion",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
  },
  // 0x333 M16CVersion (Panasonic.pm:1674) — int32u, raw.
  LeicaTag {
    id: 0x333,
    name: "M16CVersion",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
  },
  // 0x340 ImageIDNumber (Panasonic.pm:1702) — int32u, raw.
  LeicaTag {
    id: 0x340,
    name: "ImageIDNumber",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
  },
];

/// `%Panasonic::Leica3` (`Panasonic.pm:1706-1721`) — the R8/R9 backs. The
/// `0x0b SerialInfo` binary SubDirectory is deferred; `0x0d WB_RGBLevels` is the
/// only plain leaf.
pub const LEICA3_TAGS: &[LeicaTag] = &[
  // 0x0d WB_RGBLevels (Panasonic.pm:1719) — int16u Count 3, space-joined.
  LeicaTag {
    id: 0x0d,
    name: "WB_RGBLevels",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
  },
];

/// `%Panasonic::Leica4` (`Panasonic.pm:1736-1770`) — the M9. EVERY row is a
/// SubDirectory into `%Panasonic::Subdir` (deferred), so this table carries NO
/// plain leaf (the walk routes correctly + emits nothing).
pub const LEICA4_TAGS: &[LeicaTag] = &[];

/// `%Panasonic::Leica5` (`Panasonic.pm:1997-2066`) — X1/X2/X-VARIO/T/X-U +
/// (via Leica8) Q/SL/CL. `PRIORITY => 0` at the table level. The `0x040a
/// FocusInfo` / `0x0410 ShotInfo` binary SubDirectories + `0x05ff CameraIFD`
/// nested TIFF are deferred.
pub const LEICA5_TAGS: &[LeicaTag] = &[
  // 0x0303 LensType (Panasonic.pm:2004) — string, Condition $format eq "string" (Leica T only).
  LeicaTag {
    id: 0x0303,
    name: "LensType",
    conv: LeicaPrintConv::None,
    format: None,
    condition: Some(LeicaCondition::FormatIsString),
  },
  // 0x0305 SerialNumber (Panasonic.pm:2014) — int32u, raw.
  LeicaTag {
    id: 0x0305,
    name: "SerialNumber",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
  },
  // 0x0407 OriginalFileName (Panasonic.pm:2023) — string.
  LeicaTag {
    id: 0x0407,
    name: "OriginalFileName",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
  },
  // 0x0408 OriginalDirectory (Panasonic.pm:2024) — string.
  LeicaTag {
    id: 0x0408,
    name: "OriginalDirectory",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
  },
  // 0x040d ExposureMode (Panasonic.pm:2047) — Format int8u[4], PrintConv hash.
  LeicaTag {
    id: 0x040d,
    name: "ExposureMode",
    conv: LeicaPrintConv::ExposureMode5,
    format: Some(FormatOverride::new(Format::Int8u, Some(4))),
    condition: None,
  },
  // 0x0412 FilmMode (Panasonic.pm:2065) — string.
  LeicaTag {
    id: 0x0412,
    name: "FilmMode",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
  },
  // 0x0413 WB_RGBLevels (Panasonic.pm:2066) — rational64u Count 3, space-joined.
  LeicaTag {
    id: 0x0413,
    name: "WB_RGBLevels",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
  },
  // 0x0500 InternalSerialNumber (Panasonic.pm:2047) — undef, date-encoded PrintConv.
  LeicaTag {
    id: 0x0500,
    name: "InternalSerialNumber",
    conv: LeicaPrintConv::InternalSerialNumber,
    format: None,
    condition: None,
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
  },
  // 0x304 FocusDistance (Panasonic.pm:2154) — int32u, raw.
  LeicaTag {
    id: 0x304,
    name: "FocusDistance",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
  },
  // 0x311 ExternalSensorBrightnessValue (Panasonic.pm:2153) — Format rational64s, Condition Typ 006, sprintf("%.2f").
  LeicaTag {
    id: 0x311,
    name: "ExternalSensorBrightnessValue",
    conv: LeicaPrintConv::Sprintf2f,
    format: Some(FormatOverride::new(Format::Rational64s, None)),
    condition: Some(LeicaCondition::ModelTyp006),
  },
  // 0x312 MeasuredLV (Panasonic.pm:2160) — Format rational64s, Condition Typ 006, sprintf("%.2f").
  LeicaTag {
    id: 0x312,
    name: "MeasuredLV",
    conv: LeicaPrintConv::Sprintf2f,
    format: Some(FormatOverride::new(Format::Rational64s, None)),
    condition: Some(LeicaCondition::ModelTyp006),
  },
  // 0x320 FirmwareVersion (Panasonic.pm:2171) — int8u Count 4, Condition Typ 006, $val=~tr/ /./.
  LeicaTag {
    id: 0x320,
    name: "FirmwareVersion",
    conv: LeicaPrintConv::FirmwareVersionDots,
    format: None,
    condition: Some(LeicaCondition::ModelTyp006),
  },
  // 0x321 LensSerialNumber (Panasonic.pm:2179) — int32u, Condition Typ 006, sprintf("%.10d").
  LeicaTag {
    id: 0x321,
    name: "LensSerialNumber",
    conv: LeicaPrintConv::Sprintf10d,
    format: None,
    condition: Some(LeicaCondition::ModelTyp006),
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
  },
  // 0x311 ExternalSensorBrightnessValue (Panasonic.pm:2203) — Format rational64s, sprintf("%.2f").
  LeicaTag {
    id: 0x311,
    name: "ExternalSensorBrightnessValue",
    conv: LeicaPrintConv::Sprintf2f,
    format: Some(FormatOverride::new(Format::Rational64s, None)),
    condition: None,
  },
  // 0x312 MeasuredLV (Panasonic.pm:2208) — Format rational64s, sprintf("%.2f").
  LeicaTag {
    id: 0x312,
    name: "MeasuredLV",
    conv: LeicaPrintConv::Sprintf2f,
    format: Some(FormatOverride::new(Format::Rational64s, None)),
    condition: None,
  },
  // 0x34c UserProfile (Panasonic.pm:2218) — string.
  LeicaTag {
    id: 0x34c,
    name: "UserProfile",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
  },
  // 0x359 ISOSelected (Panasonic.pm:2223) — int32s, 0=>Auto + identity OTHER.
  LeicaTag {
    id: 0x359,
    name: "ISOSelected",
    conv: LeicaPrintConv::IsoSelected,
    format: None,
    condition: None,
  },
  // 0x35a FNumber (Panasonic.pm:2231) — int32s, ValueConv /1000, sprintf("%.1f").
  LeicaTag {
    id: 0x35a,
    name: "FNumber",
    conv: LeicaPrintConv::Div1000Sprintf1f,
    format: None,
    condition: None,
  },
  // 0x35b CorrelatedColorTemp (Panasonic.pm:2233) — int16u, raw.
  LeicaTag {
    id: 0x35b,
    name: "CorrelatedColorTemp",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
  },
  // 0x35c ColorTint (Panasonic.pm:2234) — int16s, raw.
  LeicaTag {
    id: 0x35c,
    name: "ColorTint",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
  },
  // 0x35d WhitePoint (Panasonic.pm:2235) — rational64u Count 2, space-joined.
  LeicaTag {
    id: 0x35d,
    name: "WhitePoint",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
  },
  // 0x370 LensProfileName (Panasonic.pm:2238) — string.
  LeicaTag {
    id: 0x370,
    name: "LensProfileName",
    conv: LeicaPrintConv::None,
    format: None,
    condition: None,
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
