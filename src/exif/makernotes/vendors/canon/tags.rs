// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Canon::Main` IFD tag table (`Canon.pm:1221-2209`).
//!
//! Phase-2 scope:
//!
//! - Every named LEAF tag (string/numeric/array) is ported. The
//!   `SubDirectory` arms (CameraSettings 0x01, FocalLength 0x02, ShotInfo
//!   0x04, Panorama 0x05, AFInfo 0x12, AFInfo2 0x26, FileInfo 0x93,
//!   ProcessingInfo 0x10/etc.) trigger a SECONDARY sub-table parse — the
//!   port handles CameraSettings + FileInfo natively (see
//!   [`super::camera_settings`] / [`super::file_info`]); the rest are
//!   captured as raw bytes (Phase-2 deferred — see follow-up issue
//!   linked from #62 umbrella).
//! - Model-specific `CanonCameraInfoXXX` conditional sub-directories at
//!   tag 0x0d (`Canon.pm:1307-1494`) are DEFERRED — each model has its
//!   own micro-table.
//! - `CustomFunctionsXXX` at tag 0x0f (`Canon.pm:1500-1582`) are
//!   DEFERRED — each model has its own micro-table.
//! - `ColorData1..12` (`Canon.pm:7435-8941`) are DEFERRED.

// Golden-v2 Contract 3c (Phase C, slice w2d): panic-safety by construction —
// this is the Canon Main tag table + dispatch; any raw index/slice is
// dominated by a length/count guard and becomes a checked `.get()` form
// (re-asserts the parent `exif` deny over the makernotes `#![allow]` shim).
#![deny(clippy::indexing_slicing)]

use super::printconv::CanonPrintConv;

/// One Canon Main IFD tag.
///
/// D8: no public fields — accessors only.
#[derive(Debug, Clone, Copy)]
pub struct CanonTag {
  /// Tag ID.
  id: u16,
  /// `Name => '…'` from bundled.
  name: &'static str,
  /// PrintConv strategy.
  conv: CanonPrintConv,
  /// Sub-table dispatch — `Some(SubTable::CameraSettings)` etc. — when
  /// the tag is a SubDirectory pointer (the data must be re-parsed as
  /// binary).
  sub_table: Option<SubTable>,
  /// `Unknown => 1` in bundled. ExifTool (`ExifTool.pm:9179-9185`)
  /// suppresses such tags in default output (no `-u`/Verbose/HTML/Validate),
  /// so the `-j -G1` golden OMITS them; the emission builder skips them.
  unknown: bool,
}

impl CanonTag {
  /// Tag ID (`Canon.pm` Main hash key).
  #[must_use]
  #[inline(always)]
  pub const fn id(&self) -> u16 {
    self.id
  }

  /// Tag `Name` (`Canon.pm` `Name => '…'`).
  #[must_use]
  #[inline(always)]
  pub const fn name(&self) -> &'static str {
    self.name
  }

  /// PrintConv strategy.
  #[must_use]
  #[inline(always)]
  pub const fn conv(&self) -> CanonPrintConv {
    self.conv
  }

  /// SubDirectory dispatch target, if this tag is a sub-table pointer.
  #[must_use]
  #[inline(always)]
  pub const fn sub_table(&self) -> Option<SubTable> {
    self.sub_table
  }

  /// `true` when bundled marks this tag `Unknown => 1` — suppressed in
  /// the default (`-j`, no `-u`) output (`ExifTool.pm:9179-9185`).
  #[must_use]
  #[inline(always)]
  pub const fn is_unknown(&self) -> bool {
    self.unknown
  }
}

/// Canon Main IFD SubDirectory targets — the Phase-2 ones the port
/// actually walks; everything else surfaces as raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubTable {
  /// `%Canon::CameraSettings` (`Canon.pm:2214-2690`). FORMAT int16s,
  /// FIRST_ENTRY 1. Decodes the LensType + focal length + aperture +
  /// drive + focus + macro + flash + image-size metadata.
  CameraSettings,
  /// `%Canon::FocalLength` (`Canon.pm:2693-2770`). FORMAT int16u,
  /// FIRST_ENTRY 0. Five entries: FocalType / FocalLength /
  /// FocalPlaneXSize / FocalPlaneYSize.
  FocalLength,
  /// `%Canon::FileInfo` (`Canon.pm:6842-7140`). FORMAT int16s,
  /// FIRST_ENTRY 1. Bracket + RawJpgQuality + file-number-related.
  FileInfo,
  /// `%Canon::ShotInfo` (`Canon.pm:2772-3052`). FORMAT int16s,
  /// FIRST_ENTRY 1. ISO setting, sequence number, AF-info, etc.
  ShotInfo,
  /// `%Canon::Panorama` (`Canon.pm:3054-3076`).
  Panorama,
  /// `%Canon::MyColors` (`Canon.pm:6704-6730`).
  MyColors,
  /// `%Canon::ContrastInfo` (`Canon.pm:6606-6632`).
  ContrastInfo,
  /// `%Canon::FaceDetect1` (`Canon.pm:6732-6800`).
  FaceDetect1,
  /// `%Canon::FaceDetect2` (`Canon.pm:6800-6810`).
  FaceDetect2,
  /// `%Canon::AFInfo` (`Canon.pm:6432-6500`).
  AfInfo,
  /// `%Canon::AFInfo2` (`Canon.pm:6503-6604`) — Main tag 0x26.
  AfInfo2,
  /// `Canon::Main` tag 0x3c `AFInfo3` (`Canon.pm:1764-1770`): processed
  /// with the SAME `%Canon::AFInfo2` table but with `$$self{AFInfo3} = 1`
  /// set (which suppresses the index-14 PrimaryAFPoint).
  AfInfo3,
  /// `%Canon::Processing` (`Canon.pm:7201-7264`).
  Processing,
  /// `%Canon::MovieInfo` (`Canon.pm:6358-6432`).
  MovieInfo,
  /// `%Canon::WBInfo` (`Canon.pm:6810-6829`).
  WbInfo,
  /// `%Canon::LensInfo` (`Canon.pm:9130-9148`).
  LensInfo,
  /// `%Canon::SensorInfo` (`Canon.pm:7411-7434`) — Main tag 0xe0. FORMAT
  /// int16s, FIRST_ENTRY 1. Sensor + black-mask border coordinates.
  SensorInfo,
  /// `%Canon::ColorBalance` (`Canon.pm:7268-7293`) — Main tag 0xa9. FORMAT
  /// int16s, FIRST_ENTRY 0. The `WB_RGGBLevels{Auto,Daylight,…}` quads.
  ColorBalance,
}

impl SubTable {
  /// `true` when the port walks this sub-table natively. Covers the
  /// Phase-2 set (CameraSettings / FileInfo / FocalLength) plus the deep
  /// sub-tables added for issues #86/#88 (ShotInfo / AFInfo / AFInfo2) and
  /// the SensorInfo / ColorBalance border + WB-levels tables (the CRW port).
  /// `false` when it stays a raw-bytes blob for now (deferred).
  #[must_use]
  #[inline(always)]
  pub const fn is_walked(self) -> bool {
    matches!(
      self,
      SubTable::CameraSettings
        | SubTable::FileInfo
        | SubTable::FocalLength
        | SubTable::ShotInfo
        | SubTable::AfInfo
        | SubTable::AfInfo2
        | SubTable::AfInfo3
        | SubTable::SensorInfo
        | SubTable::ColorBalance
    )
  }
}

/// `%Canon::Main` (`Canon.pm:1221-2209`). Sorted by tag ID.
///
/// Tags marked `(conditional list)` — bundled has multiple Conditions on
/// the same ID resolving by Model regex. The port surfaces a single
/// `Name` per ID (the most common / model-agnostic) and stores the raw
/// value; per-model decoding is deferred.
pub const CANON_TAGS: &[CanonTag] = &[
  // 0x01 — CanonCameraSettings (`Canon.pm:1225-1231`)
  CanonTag {
    id: 0x01,
    name: "CanonCameraSettings",
    conv: CanonPrintConv::None,
    sub_table: Some(SubTable::CameraSettings),
    unknown: false,
  },
  // 0x02 — CanonFocalLength (`Canon.pm:1232-1235`)
  CanonTag {
    id: 0x02,
    name: "CanonFocalLength",
    conv: CanonPrintConv::None,
    sub_table: Some(SubTable::FocalLength),
    unknown: false,
  },
  // 0x03 — CanonFlashInfo (`Canon.pm:1237-1239`). `Unknown => 1`, so
  // SUPPRESSED in default output (`ExifTool.pm:9179-9185`); `-u` reveals it.
  CanonTag {
    id: 0x03,
    name: "CanonFlashInfo",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: true, // Canon.pm:1239 `Unknown => 1`
  },
  // 0x04 — CanonShotInfo (`Canon.pm:1240-1246`) — sub-table, deferred-walk.
  CanonTag {
    id: 0x04,
    name: "CanonShotInfo",
    conv: CanonPrintConv::None,
    sub_table: Some(SubTable::ShotInfo),
    unknown: false,
  },
  // 0x05 — CanonPanorama (`Canon.pm:1247-1250`).
  CanonTag {
    id: 0x05,
    name: "CanonPanorama",
    conv: CanonPrintConv::None,
    sub_table: Some(SubTable::Panorama),
    unknown: false,
  },
  // 0x06 — CanonImageType (`Canon.pm:1251-1255`)
  CanonTag {
    id: 0x06,
    name: "CanonImageType",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x07 — CanonFirmwareVersion (`Canon.pm:1256-1259`)
  CanonTag {
    id: 0x07,
    name: "CanonFirmwareVersion",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x08 — FileNumber (`Canon.pm:1260-1266`) — int32u with N-NNNN format.
  CanonTag {
    id: 0x08,
    name: "FileNumber",
    conv: CanonPrintConv::FileNumberDash,
    sub_table: None,
    unknown: false,
  },
  // 0x09 — OwnerName (`Canon.pm:1267-1273`)
  CanonTag {
    id: 0x09,
    name: "OwnerName",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x0a — UnknownD30 (`Canon.pm:1274-1280`) — sub-table, raw.
  CanonTag {
    id: 0x0a,
    name: "UnknownD30",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x0c — SerialNumber (`Canon.pm:1281-1306`) — conditional Print format.
  CanonTag {
    id: 0x0c,
    name: "SerialNumber",
    conv: CanonPrintConv::SerialNumber,
    sub_table: None,
    unknown: false,
  },
  // 0x0d — CanonCameraInfo (`Canon.pm:1307-1494`) — conditional model-specific.
  CanonTag {
    id: 0x0d,
    name: "CanonCameraInfo",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x0e — CanonFileLength (`Canon.pm:1495-1499`) — int32u
  CanonTag {
    id: 0x0e,
    name: "CanonFileLength",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x0f — CustomFunctions (`Canon.pm:1500-1582`) — model-specific.
  CanonTag {
    id: 0x0f,
    name: "CustomFunctions",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x10 — CanonModelID (`Canon.pm:1583-1589`) — int32u, printConv via canonModelID.
  CanonTag {
    id: 0x10,
    name: "CanonModelID",
    conv: CanonPrintConv::ModelId,
    sub_table: None,
    unknown: false,
  },
  // 0x11 — MovieInfo (`Canon.pm:1590-1596`) — sub-table, deferred.
  CanonTag {
    id: 0x11,
    name: "MovieInfo",
    conv: CanonPrintConv::None,
    sub_table: Some(SubTable::MovieInfo),
    unknown: false,
  },
  // 0x12 — CanonAFInfo (`Canon.pm:1597-1607`)
  CanonTag {
    id: 0x12,
    name: "CanonAFInfo",
    conv: CanonPrintConv::None,
    sub_table: Some(SubTable::AfInfo),
    unknown: false,
  },
  // 0x13 — ThumbnailImageValidArea (`Canon.pm:1608-1614`) — int16u[4]
  CanonTag {
    id: 0x13,
    name: "ThumbnailImageValidArea",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x15 — SerialNumberFormat (`Canon.pm:1615-1624`) — int32u, PrintHex
  CanonTag {
    id: 0x15,
    name: "SerialNumberFormat",
    conv: CanonPrintConv::SerialNumberFormat,
    sub_table: None,
    unknown: false,
  },
  // 0x1a — SuperMacro (`Canon.pm:1625-1633`) — int16u, PrintConv 0/1/2
  CanonTag {
    id: 0x1a,
    name: "SuperMacro",
    conv: CanonPrintConv::SuperMacro,
    sub_table: None,
    unknown: false,
  },
  // 0x1c — DateStampMode (`Canon.pm:1634-1643`) — int16u
  CanonTag {
    id: 0x1c,
    name: "DateStampMode",
    conv: CanonPrintConv::DateStampMode,
    sub_table: None,
    unknown: false,
  },
  // 0x1d — MyColors (`Canon.pm:1644-1650`) — sub-table
  CanonTag {
    id: 0x1d,
    name: "MyColors",
    conv: CanonPrintConv::None,
    sub_table: Some(SubTable::MyColors),
    unknown: false,
  },
  // 0x1e — FirmwareRevision (`Canon.pm:1651-1670`) — int32u (Hex/PrintConv complex)
  CanonTag {
    id: 0x1e,
    name: "FirmwareRevision",
    conv: CanonPrintConv::FirmwareRevision,
    sub_table: None,
    unknown: false,
  },
  // 0x23 — Categories (`Canon.pm:1673-1695`) — int32u[2]
  CanonTag {
    id: 0x23,
    name: "Categories",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x24 — FaceDetect1 (`Canon.pm:1696-1702`)
  CanonTag {
    id: 0x24,
    name: "FaceDetect1",
    conv: CanonPrintConv::None,
    sub_table: Some(SubTable::FaceDetect1),
    unknown: false,
  },
  // 0x25 — FaceDetect2 (`Canon.pm:1703-1709`)
  CanonTag {
    id: 0x25,
    name: "FaceDetect2",
    conv: CanonPrintConv::None,
    sub_table: Some(SubTable::FaceDetect2),
    unknown: false,
  },
  // 0x26 — CanonAFInfo2 (`Canon.pm:1710-1717`)
  CanonTag {
    id: 0x26,
    name: "CanonAFInfo2",
    conv: CanonPrintConv::None,
    sub_table: Some(SubTable::AfInfo2),
    unknown: false,
  },
  // 0x27 — ContrastInfo (`Canon.pm:1718-1722`)
  CanonTag {
    id: 0x27,
    name: "ContrastInfo",
    conv: CanonPrintConv::None,
    sub_table: Some(SubTable::ContrastInfo),
    unknown: false,
  },
  // 0x28 — ImageUniqueID (`Canon.pm:1725-1734`) — 16-byte hex
  CanonTag {
    id: 0x28,
    name: "ImageUniqueID",
    conv: CanonPrintConv::HexEncoded,
    sub_table: None,
    unknown: false,
  },
  // 0x29 — WBInfo (`Canon.pm:1735-1738`)
  CanonTag {
    id: 0x29,
    name: "WBInfo",
    conv: CanonPrintConv::None,
    sub_table: Some(SubTable::WbInfo),
    unknown: false,
  },
  // 0x2f — FaceDetect3 (`Canon.pm:1740-1745`)
  CanonTag {
    id: 0x2f,
    name: "FaceDetect3",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x35 — TimeInfo (`Canon.pm:1748-1754`)
  CanonTag {
    id: 0x35,
    name: "TimeInfo",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x38 — BatteryType (`Canon.pm:1757-1764`) — string
  CanonTag {
    id: 0x38,
    name: "BatteryType",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x3c — AFInfo3 (`Canon.pm:1764-1770`). `Condition => '$$self{AFInfo3}
  // = 1'` (always-true assignment that sets the DataMember); SubDirectory
  // `TagTable => Canon::AFInfo2`, i.e. processed with the SAME AFInfo2
  // walker but with the AFInfo3 flag set.
  CanonTag {
    id: 0x3c,
    name: "AFInfo3",
    conv: CanonPrintConv::None,
    sub_table: Some(SubTable::AfInfo3),
    unknown: false,
  },
  // 0x81 — RawDataOffset (`Canon.pm:1774-1779`)
  CanonTag {
    id: 0x81,
    name: "RawDataOffset",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x82 — RawDataLength (`Canon.pm:1782-1785`)
  CanonTag {
    id: 0x82,
    name: "RawDataLength",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x83 — OriginalDecisionDataOffset (`Canon.pm:1788-1797`)
  CanonTag {
    id: 0x83,
    name: "OriginalDecisionDataOffset",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x90 — CustomFunctions1D (`Canon.pm:1796-1801`) — SubDirectory
  // (CanonCustom::Functions1D), deferred → emit raw.
  CanonTag {
    id: 0x90,
    name: "CustomFunctions1D",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x91 — PersonalFunctions (`Canon.pm:1804-1808`)
  CanonTag {
    id: 0x91,
    name: "PersonalFunctions",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x92 — PersonalFunctionValues (`Canon.pm:1811-1815`)
  CanonTag {
    id: 0x92,
    name: "PersonalFunctionValues",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x93 — CanonFileInfo (`Canon.pm:1816-1822`)
  CanonTag {
    id: 0x93,
    name: "CanonFileInfo",
    conv: CanonPrintConv::None,
    sub_table: Some(SubTable::FileInfo),
    unknown: false,
  },
  // 0x94 — AFPointsInFocus1D (`Canon.pm:1824-1828`)
  CanonTag {
    id: 0x94,
    name: "AFPointsInFocus1D",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x95 — LensModel (`Canon.pm:1830-1834`) — string
  CanonTag {
    id: 0x95,
    name: "LensModel",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x96 — MODEL-CONDITIONAL LIST (`Canon.pm:1834-1846`):
  //   [ { SerialInfo, Condition '$$self{Model} =~ /EOS 5D/',
  //       SubDirectory => Canon::SerialInfo },
  //     { InternalSerialNumber, string, ValueConv s/\xff+$// } ]
  // This static entry is the SECOND arm (`InternalSerialNumber`, the
  // model-agnostic fallback). The FIRST arm (`SerialInfo` SubDirectory)
  // is dispatched at the emit layer in `super::parse_in_tiff` where the
  // parent `$$self{Model}` is available (the SerialInfo sub-table decode
  // is a deferred follow-up — surfaced as a raw blob like ShotInfo).
  CanonTag {
    id: 0x96,
    name: "InternalSerialNumber",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x97 — DustRemovalData (`Canon.pm:1848-1865`)
  CanonTag {
    id: 0x97,
    name: "DustRemovalData",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x98 — CropInfo (`Canon.pm:1880-1882`)
  CanonTag {
    id: 0x98,
    name: "CropInfo",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x99 — CustomFunctions2 (`Canon.pm:1884-1888`)
  CanonTag {
    id: 0x99,
    name: "CustomFunctions2",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x9a — AspectInfo (`Canon.pm:1891-1893`)
  CanonTag {
    id: 0x9a,
    name: "AspectInfo",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0xa0 — ProcessingInfo (`Canon.pm:1897-1901`)
  CanonTag {
    id: 0xa0,
    name: "ProcessingInfo",
    conv: CanonPrintConv::None,
    sub_table: Some(SubTable::Processing),
    unknown: false,
  },
  // 0xa1 — ToneCurveTable (`Canon.pm:1902`)
  CanonTag {
    id: 0xa1,
    name: "ToneCurveTable",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0xa2 — SharpnessTable (`Canon.pm:1903`)
  CanonTag {
    id: 0xa2,
    name: "SharpnessTable",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0xa3 — SharpnessFreqTable (`Canon.pm:1904`)
  CanonTag {
    id: 0xa3,
    name: "SharpnessFreqTable",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0xa4 — WhiteBalanceTable (`Canon.pm:1905`)
  CanonTag {
    id: 0xa4,
    name: "WhiteBalanceTable",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0xa9 — ColorBalance (`Canon.pm:1907-1912`) — SubDirectory to
  // `Canon::ColorBalance` (the WB_RGGBLevels quads).
  CanonTag {
    id: 0xa9,
    name: "ColorBalance",
    conv: CanonPrintConv::None,
    sub_table: Some(SubTable::ColorBalance),
    unknown: false,
  },
  // 0xaa — MeasuredColor (`Canon.pm:1914-1919`)
  CanonTag {
    id: 0xaa,
    name: "MeasuredColor",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0xae — ColorTemperature (`Canon.pm:1921-1924`)
  CanonTag {
    id: 0xae,
    name: "ColorTemperature",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0xb0 — CanonFlags (`Canon.pm:1925-1933`)
  CanonTag {
    id: 0xb0,
    name: "CanonFlags",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0xb1 — ModifiedInfo (`Canon.pm:1932-1939`)
  CanonTag {
    id: 0xb1,
    name: "ModifiedInfo",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0xb2 — ToneCurveMatching (`Canon.pm:1940`)
  CanonTag {
    id: 0xb2,
    name: "ToneCurveMatching",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0xb3 — WhiteBalanceMatching (`Canon.pm:1941`)
  CanonTag {
    id: 0xb3,
    name: "WhiteBalanceMatching",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0xb4 — ColorSpace (`Canon.pm:1942-1950`) — int16u
  CanonTag {
    id: 0xb4,
    name: "ColorSpace",
    conv: CanonPrintConv::ColorSpace,
    sub_table: None,
    unknown: false,
  },
  // 0xb6 — PreviewImageInfo (`Canon.pm:1951-1958`)
  CanonTag {
    id: 0xb6,
    name: "PreviewImageInfo",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0xd0 — VRDOffset (`Canon.pm:1959-1966`) — int32u
  CanonTag {
    id: 0xd0,
    name: "VRDOffset",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0xe0 — SensorInfo (`Canon.pm:1967-1973`) — SubDirectory to
  // `Canon::SensorInfo` (sensor + black-mask border coordinates).
  CanonTag {
    id: 0xe0,
    name: "SensorInfo",
    conv: CanonPrintConv::None,
    sub_table: Some(SubTable::SensorInfo),
    unknown: false,
  },
  // 0x4001 — ColorData (`Canon.pm:1974-2046`) — model-specific ColorDataN.
  CanonTag {
    id: 0x4001,
    name: "ColorData",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x4002 — CRWParam (`Canon.pm:2048-2053`)
  CanonTag {
    id: 0x4002,
    name: "CRWParam",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x4003 — ColorInfo (`Canon.pm:2055-2057`)
  CanonTag {
    id: 0x4003,
    name: "ColorInfo",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x4005 — Flavor (`Canon.pm:2059-2063`)
  CanonTag {
    id: 0x4005,
    name: "Flavor",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x4008 — PictureStyleUserDef (`Canon.pm:2066-2073`) — int16u Count=3,
  // PrintHex, array PrintConv [\%pictureStyles x3].
  CanonTag {
    id: 0x4008,
    name: "PictureStyleUserDef",
    conv: CanonPrintConv::PictureStyle,
    sub_table: None,
    unknown: false,
  },
  // 0x4009 — PictureStylePC (`Canon.pm:2074-2081`) — int16u Count=3,
  // PrintHex, array PrintConv [\%pictureStyles x3].
  CanonTag {
    id: 0x4009,
    name: "PictureStylePC",
    conv: CanonPrintConv::PictureStyle,
    sub_table: None,
    unknown: false,
  },
  // 0x4010 — CustomPictureStyleFileName (`Canon.pm:2081-2086`) — string
  CanonTag {
    id: 0x4010,
    name: "CustomPictureStyleFileName",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x4013 — AFMicroAdj (`Canon.pm:2087-2095`)
  CanonTag {
    id: 0x4013,
    name: "AFMicroAdj",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x4015 — VignettingCorr (`Canon.pm:2097-2120`) — conditional
  CanonTag {
    id: 0x4015,
    name: "VignettingCorr",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x4016 — VignettingCorr2 (`Canon.pm:2121-2128`)
  CanonTag {
    id: 0x4016,
    name: "VignettingCorr2",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x4018 — LightingOpt (`Canon.pm:2130-2136`)
  CanonTag {
    id: 0x4018,
    name: "LightingOpt",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x4019 — LensInfo (`Canon.pm:2137-2142`) — Phase-2: emit raw.
  CanonTag {
    id: 0x4019,
    name: "LensInfo",
    conv: CanonPrintConv::None,
    sub_table: Some(SubTable::LensInfo),
    unknown: false,
  },
  // 0x4020 — AmbienceInfo (`Canon.pm:2144-2151`) — SubDirectory, deferred.
  CanonTag {
    id: 0x4020,
    name: "AmbienceInfo",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x4021 — MultiExp (`Canon.pm:2150-2156`)
  CanonTag {
    id: 0x4021,
    name: "MultiExp",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x4024 — FilterInfo (`Canon.pm:2158-2163`)
  CanonTag {
    id: 0x4024,
    name: "FilterInfo",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x4025 — HDRInfo (`Canon.pm:2164-2170`)
  CanonTag {
    id: 0x4025,
    name: "HDRInfo",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x4026 — LogInfo (`Canon.pm:2171-2178`)
  CanonTag {
    id: 0x4026,
    name: "LogInfo",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x4028 — AFConfig (`Canon.pm:2179-2184`)
  CanonTag {
    id: 0x4028,
    name: "AFConfig",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x403f — RawBurstModeRoll (`Canon.pm:2186-2189`)
  CanonTag {
    id: 0x403f,
    name: "RawBurstModeRoll",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x4053 — FocusBracketingInfo (`Canon.pm:2196-2202`)
  CanonTag {
    id: 0x4053,
    name: "FocusBracketingInfo",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
  // 0x4059 — LevelInfo (`Canon.pm:2203-2209`)
  CanonTag {
    id: 0x4059,
    name: "LevelInfo",
    conv: CanonPrintConv::None,
    sub_table: None,
    unknown: false,
  },
];

/// Look up a Canon Main tag by ID via binary search over the ID-sorted
/// 78-entry table (`canon_tags_sorted_by_id` guards the invariant).
#[must_use]
pub fn lookup(id: u16) -> Option<&'static CanonTag> {
  match CANON_TAGS.binary_search_by_key(&id, |t| t.id) {
    // `binary_search_by_key` returns the found index, so `i` is in-bounds;
    // `.get(i)` is the checked form (always `Some` here) — byte-identical.
    Ok(i) => CANON_TAGS.get(i),
    Err(_) => None,
  }
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2d); the test fixtures index fixed-layout buffers freely
// (an out-of-range index is a test-assertion failure, not a shipped panic), so
// the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  #[test]
  fn canon_tags_sorted_by_id() {
    let mut prev = 0u16;
    for t in CANON_TAGS {
      assert!(
        t.id > prev,
        "Canon tag table out of order: 0x{:04x} after 0x{:04x}",
        t.id,
        prev
      );
      prev = t.id;
    }
  }

  #[test]
  fn lookup_finds_canon_camera_identity_tags() {
    assert_eq!(lookup(0x07).unwrap().name, "CanonFirmwareVersion");
    assert_eq!(lookup(0x0c).unwrap().name, "SerialNumber");
    assert_eq!(lookup(0x10).unwrap().name, "CanonModelID");
    assert_eq!(lookup(0x95).unwrap().name, "LensModel");
    assert_eq!(lookup(0x96).unwrap().name, "InternalSerialNumber");
  }

  #[test]
  fn lookup_finds_canon_subdirectories() {
    let s = lookup(0x01).unwrap();
    assert_eq!(s.name, "CanonCameraSettings");
    assert_eq!(s.sub_table, Some(SubTable::CameraSettings));
    let f = lookup(0x93).unwrap();
    assert_eq!(f.name, "CanonFileInfo");
    assert_eq!(f.sub_table, Some(SubTable::FileInfo));
  }

  #[test]
  fn picture_style_tags_use_array_printconv() {
    // 0x4008/0x4009 wired to the array PrintConv (`Canon.pm:2066-2081`).
    assert_eq!(lookup(0x4008).unwrap().name, "PictureStyleUserDef");
    assert_eq!(lookup(0x4008).unwrap().conv, CanonPrintConv::PictureStyle);
    assert_eq!(lookup(0x4009).unwrap().name, "PictureStylePC");
    assert_eq!(lookup(0x4009).unwrap().conv, CanonPrintConv::PictureStyle);
  }

  #[test]
  fn swept_tag_names_match_canon_pm() {
    // 0xb4 ColorSpace dedicated conv (`Canon.pm:1941`).
    assert_eq!(lookup(0xb4).unwrap().name, "ColorSpace");
    assert_eq!(lookup(0xb4).unwrap().conv, CanonPrintConv::ColorSpace);
    // Sweep name fixes vs Canon.pm.
    assert_eq!(lookup(0x90).unwrap().name, "CustomFunctions1D"); // Canon.pm:1797
    assert_eq!(lookup(0x4020).unwrap().name, "AmbienceInfo"); // Canon.pm:2145
  }

  /// `0x4053`/`0x4059` were previously SWAPPED. Bundled:
  /// `Canon.pm:2196-2197` `0x4053 => FocusBracketingInfo`,
  /// `Canon.pm:2203-2204` `0x4059 => LevelInfo`.
  #[test]
  fn focus_bracketing_and_level_info_not_swapped() {
    assert_eq!(lookup(0x4053).unwrap().name, "FocusBracketingInfo");
    assert_eq!(lookup(0x4059).unwrap().name, "LevelInfo");
  }

  #[test]
  fn walked_subtables_are_marked() {
    assert!(SubTable::CameraSettings.is_walked());
    assert!(SubTable::FileInfo.is_walked());
    assert!(SubTable::FocalLength.is_walked());
    // Deep sub-tables (issues #86/#88) are now walked too.
    assert!(SubTable::ShotInfo.is_walked());
    assert!(SubTable::AfInfo.is_walked());
    assert!(SubTable::AfInfo2.is_walked());
    assert!(SubTable::AfInfo3.is_walked());
    // 0x3c (AFInfo3) dispatches to the AFInfo2 walker (`Canon.pm:1764-1770`).
    assert_eq!(
      lookup(0x3c).and_then(CanonTag::sub_table),
      Some(SubTable::AfInfo3)
    );
    // Still-deferred sub-tables remain raw.
    assert!(!SubTable::Panorama.is_walked());
    assert!(!SubTable::MyColors.is_walked());
    assert!(!SubTable::Processing.is_walked());
  }
}
