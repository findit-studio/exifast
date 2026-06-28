// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! MISB (Motion Imagery Standards Board) STANAG-4609 KLV metadata — a faithful
//! port of `Image::ExifTool::MISB` (MISB.pm). This is the timed-metadata stream
//! carried in an M2TS `0x15` ("packetized metadata") elementary stream and
//! dispatched from [`crate::formats::m2ts`] (M2TS.pm:355-364 →
//! `MISB::ParseMISB`).
//!
//! ## Structure
//!
//! A MISB PES packet is `[5-byte service header][KLV…]` (MISB.pm:401-405). Each
//! KLV is a 16-byte SMPTE Universal Key + a BER length + the value
//! ([`parse_misb`], `MISB::ParseMISB`). The universal key selects a sub-table
//! (the Main dispatch): the ST 0601.11 UAS Datalink local set
//! ([`UAS_DATALINK`]), the ST 0102.11 Security local set ([`SECURITY`], reached
//! ONLY via UAS tag 48 — see the key-case quirk below), the ChurchillNav
//! proprietary set ([`CHURCHILL_NAV`], little-endian doubles, all `Unknown`), or
//! the `Unknown` fallback. Each local set is then a flat `[1-byte tag][BER
//! length][value]` walk ([`process_klv`], `MISB::ProcessKLV`).
//!
//! ## `-ee` / `Doc<N>` and default mode
//!
//! Unlike a moov-level GPS source, MISB is NOT decode-gated on `-ee`: ExifTool
//! runs `ParseMISB` whenever the M2TS walk reaches a `0x15` PES whose payload
//! carries the MISB code (M2TS.pm:357); `-ee` only governs whether the walk
//! reaches LATER packets (M2TS.pm:359-363). So MISB tags surface in default
//! mode too when the walk reaches the first packet (e.g. an in-flight PES
//! flushed at end-of-scan). Each `ParseMISB` packet that yields ≥1 tag opens one
//! global `Doc<N>` (MISB.pm:398 `$$et{DOC_NUM} = ++$$et{DOC_COUNT}`; the count
//! is given back when the packet yielded nothing, MISB.pm:448).
//!
//! ## Faithful quirk: the Security universal key never matches
//!
//! MISB.pm writes the Security universal key in UPPERCASE
//! (`060E2B34030101010E01030302000000`) while `ParseMISB` looks it up via
//! `unpack('H*', …)` which is LOWERCASE (MISB.pm:407,417). The string compare is
//! case-sensitive, so the standalone Security key NEVER matches and falls
//! through to the `Unknown` fallback. The ST 0102 Security tags are therefore
//! reachable ONLY through UAS tag 48 (`SecurityLocalMetadataSet`, MISB.pm:143),
//! whose `SubDirectory` references the Security table directly. This port
//! replicates the quirk by comparing the lowercase key hex against the table
//! keys verbatim ([`MAIN_KEYS`]).

#![cfg(feature = "m2ts")]

use crate::convert::ByteOrder;
use crate::emit::{ConvMode, EmitOptions, EmittedTag};
use crate::value::{Group, TagValue};
use smol_str::SmolStr;

/// ExifTool number/format string for the [`Fmt`] (the `Format =>` value handed
/// to `ReadValue`, MISB.pm).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fmt {
  U8,
  U16,
  U32,
  I16,
  I32,
  U64,
  Str,
  Undef,
  Double,
}

impl Fmt {
  /// The ExifTool `Format` string this maps to (the argument [`crate::convert::read_value`] dispatches on).
  const fn as_str(self) -> &'static str {
    match self {
      Fmt::U8 => "int8u",
      Fmt::U16 => "int16u",
      Fmt::U32 => "int32u",
      Fmt::I16 => "int16s",
      Fmt::I32 => "int32s",
      Fmt::U64 => "int64u",
      Fmt::Str => "string",
      Fmt::Undef => "undef",
      Fmt::Double => "double",
    }
  }

  /// ExifTool `%formatSize` width in bytes (`ExifTool.pm:6199-6231`).
  const fn size(self) -> usize {
    match self {
      Fmt::U8 | Fmt::Str | Fmt::Undef => 1,
      Fmt::U16 | Fmt::I16 => 2,
      Fmt::U32 | Fmt::I32 => 4,
      Fmt::U64 | Fmt::Double => 8,
    }
  }
}

/// A MISB tag's value/print conversion (the `Format`/`ValueConv`/`PrintConv`
/// triple in MISB.pm collapsed into the cases the module actually uses).
#[derive(Clone, Copy)]
enum Conv {
  /// Value passthrough — the raw `ReadValue` result, both modes (`int*` raw,
  /// `string` raw). MISB.pm tags with no `ValueConv`/`PrintConv`.
  Raw(Fmt),
  /// `ValueConv => '$val * mul / div + off'` (no `PrintConv`) — emitted as the
  /// post-ValueConv `f64` in BOTH modes (MISB.pm `GPSTrack`/`PitchAngle`/…).
  /// `off` is non-zero only for `DensityAltitude` (MISB.pm:123).
  Scale {
    fmt: Fmt,
    mul: f64,
    div: f64,
    off: f64,
  },
  /// `%latInfo` (MISB.pm:29) — `int32s`, VC `$val*90/0x7fffffff`, PC `ToDMS(…,"N")`.
  Lat,
  /// `%lonInfo` (MISB.pm:34) — `int32s`, VC `$val*180/0x7fffffff`, PC `ToDMS(…,"E")`.
  Lon,
  /// `%altInfo` (MISB.pm:39) — `int16u`, VC `$val*19900/0xffff-900`, PC `"%.2f m"`.
  Alt,
  /// `%timeInfo` (MISB.pm:23) — `int64u`, VC `ConvertUnixTime($val/1e6,0,6)."Z"`,
  /// PC `ConvertDateTime` (identity under default options).
  Time,
  /// `int8u`, `PrintConv => '"$val <suffix>"'` (MISB.pm `TrueAirspeed`/…).
  Suffix(Fmt, &'static str),
  /// `int16u`, `PrintConv => 'sprintf("0x%.4x",$val)'` (`WeaponLoad`).
  Hex4(Fmt),
  /// `int8u`, `PrintConv => 'sprintf("0x%.2x",$val)'` (`WeaponFired`).
  Hex2(Fmt),
  /// hash `PrintConv` — raw at `-n`, label at `-j` (`IcingDetected`/…).
  Hash(Fmt, &'static [(i64, &'static str)]),
  /// `int8u`, `PrintConv => { BITMASK => {…} }` — raw at `-n`, `DecodeBits` at
  /// `-j` (`GenericFlagData01`).
  Bitmask(&'static [(u8, &'static str)]),
  /// `string`, `PrintConv => '$val =~ s(^//)(); $val'` — raw at `-n`, leading
  /// `//` stripped at `-j` (`ClassifyingCountry`/`ObjectCountryCodes`).
  StripSlashesPc,
  /// `string`, `ValueConv => '$val=~tr/-/:/'` — applied in BOTH modes
  /// (`ClassifyingCountryCodingMethodDate`/`ObjectCountryCodingMethodDate`).
  DashColonVc,
  /// `string`, `ValueConv => '$val =~ s/(\d{4})(\d{2})(\d{2})/$1:$2:$3/'` —
  /// applied in BOTH modes (`DeclassificationDate`).
  DeclassDateVc,
  /// `int16u`, `PrintConv => '"0102.$val"'` (`SecurityVersion`).
  SecVersion,
  /// `SubDirectory => { TagTable => … }` — recurse into a nested local set.
  Sub(Table),
}

/// A nested-local-set table id (the `SubDirectory` target / Main-key target).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Table {
  Uas,
  Security,
  ChurchillNav,
  Unknown,
}

impl Table {
  /// The table's tag entries.
  const fn entries(self) -> &'static [TagEntry] {
    match self {
      Table::Uas => UAS_DATALINK,
      Table::Security => SECURITY,
      Table::ChurchillNav => CHURCHILL_NAV,
      Table::Unknown => &[],
    }
  }

  /// The byte order a sub-table is processed under (MISB.pm:435 — only
  /// ChurchillNav is `ByteOrder => 'LittleEndian'`; every other table inherits
  /// the `SetByteOrder('MM')` default, MISB.pm:443).
  const fn byte_order(self) -> ByteOrder {
    match self {
      Table::ChurchillNav => ByteOrder::Ii,
      _ => ByteOrder::Mm,
    }
  }
}

/// One row of a MISB local-set table.
struct TagEntry {
  /// The 1-byte local-set tag id (MISB uses decimal ids).
  id: u8,
  /// The ExifTool tag name (the `-G1` JSON key tail).
  name: &'static str,
  /// `Unknown => 1` (suppressed from default output, MISB.pm ChurchillNav).
  unknown: bool,
  /// The value/print conversion.
  conv: Conv,
}

/// Shorthand for a non-`Unknown` entry.
const fn e(id: u8, name: &'static str, conv: Conv) -> TagEntry {
  TagEntry {
    id,
    name,
    unknown: false,
    conv,
  }
}

/// The Main-table universal keys (MISB.pm:60-78). The lookup compares the
/// LOWERCASE hex of the 16-byte key (`unpack('H*')`, MISB.pm:407) against these
/// verbatim, so the UPPERCASE Security key (MISB.pm:71) never matches — see the
/// module-level quirk note. The `<other>` / unmatched case routes to
/// [`Table::Unknown`] (MISB.pm:418-423).
const MAIN_KEYS: &[(&str, Table)] = &[
  ("060e2b34020b01010e01030101000000", Table::Uas), // MISB.pm:60 UASDataLink
  ("060e2b3402030101434e415644494147", Table::ChurchillNav), // MISB.pm:64 (LE)
  // MISB.pm:71 Security key is UPPERCASE in the source ⇒ never matches the
  // lowercase lookup; intentionally stored as-written so the compare fails.
  ("060E2B34030101010E01030302000000", Table::Security),
];

// ── %latInfo / %lonInfo / %altInfo / %timeInfo scaling constants ────────────
const LAT_DIV: f64 = 0x7fff_ffff as f64; // 0x7fffffff
const LON_DIV: f64 = 0x7fff_ffff as f64;
const U16_MAX_F: f64 = 0xffff as f64; // 0xffff
const U32_MAX_F: f64 = 0xffff_ffff_u32 as f64; // 0xffffffff
const I16_MAX_F: f64 = 0x7fff as f64; // 0x7fff
const U8_MAX_F: f64 = 0xff as f64; // 0xff

/// ST 0601.11 UAS Datalink local set (MISB.pm:82-220).
#[rustfmt::skip]
const UAS_DATALINK: &[TagEntry] = &[
  e(1, "Checksum", Conv::Raw(Fmt::U16)),
  e(2, "GPSDateTime", Conv::Time),
  e(3, "MissionID", Conv::Raw(Fmt::Str)),
  e(4, "TailNumber", Conv::Raw(Fmt::Str)),
  e(5, "GPSTrack", Conv::Scale { fmt: Fmt::U16, mul: 360.0, div: U16_MAX_F, off: 0.0 }),
  e(6, "PitchAngle", Conv::Scale { fmt: Fmt::I16, mul: 20.0, div: I16_MAX_F, off: 0.0 }),
  e(7, "RollAngle", Conv::Scale { fmt: Fmt::I16, mul: 50.0, div: I16_MAX_F, off: 0.0 }),
  e(8, "TrueAirspeed", Conv::Suffix(Fmt::U8, " m/s")),
  e(9, "IndicatedAirspeed", Conv::Suffix(Fmt::U8, " m/s")),
  e(10, "ProjectIDCode", Conv::Raw(Fmt::Str)),
  e(11, "SensorName", Conv::Raw(Fmt::Str)),
  e(12, "ImageCoordinateSystem", Conv::Raw(Fmt::Str)),
  e(13, "GPSLatitude", Conv::Lat),
  e(14, "GPSLongitude", Conv::Lon),
  e(15, "GPSAltitude", Conv::Alt),
  e(16, "HorizontalFieldOfView", Conv::Scale { fmt: Fmt::U16, mul: 180.0, div: U16_MAX_F, off: 0.0 }),
  e(17, "VerticalFieldOfView", Conv::Scale { fmt: Fmt::U16, mul: 180.0, div: U16_MAX_F, off: 0.0 }),
  e(18, "SensorRelativeAzimuthAngle", Conv::Scale { fmt: Fmt::U32, mul: 360.0, div: U32_MAX_F, off: 0.0 }),
  e(19, "SensorRelativeElevationAngle", Conv::Scale { fmt: Fmt::I32, mul: 180.0, div: LAT_DIV, off: 0.0 }),
  e(20, "SensorRelativeRollAngle", Conv::Scale { fmt: Fmt::U32, mul: 360.0, div: U32_MAX_F, off: 0.0 }),
  e(21, "SlantRange", Conv::Scale { fmt: Fmt::U32, mul: 5_000_000.0, div: U32_MAX_F, off: 0.0 }),
  e(22, "TargetWidth", Conv::Scale { fmt: Fmt::U16, mul: 10_000.0, div: U16_MAX_F, off: 0.0 }),
  e(23, "FrameCenterLatitude", Conv::Lat),
  e(24, "FrameCenterLongitude", Conv::Lon),
  e(25, "FrameCenterElevation", Conv::Alt),
  e(26, "OffsetCornerLatitude1", Conv::Scale { fmt: Fmt::I16, mul: 0.075, div: I16_MAX_F, off: 0.0 }),
  e(27, "OffsetCornerLongitude1", Conv::Scale { fmt: Fmt::I16, mul: 0.075, div: I16_MAX_F, off: 0.0 }),
  e(28, "OffsetCornerLatitude2", Conv::Scale { fmt: Fmt::I16, mul: 0.075, div: I16_MAX_F, off: 0.0 }),
  e(29, "OffsetCornerLongitude2", Conv::Scale { fmt: Fmt::I16, mul: 0.075, div: I16_MAX_F, off: 0.0 }),
  e(30, "OffsetCornerLatitude3", Conv::Scale { fmt: Fmt::I16, mul: 0.075, div: I16_MAX_F, off: 0.0 }),
  e(31, "OffsetCornerLongitude3", Conv::Scale { fmt: Fmt::I16, mul: 0.075, div: I16_MAX_F, off: 0.0 }),
  e(32, "OffsetCornerLatitude4", Conv::Scale { fmt: Fmt::I16, mul: 0.075, div: I16_MAX_F, off: 0.0 }),
  e(33, "OffsetCornerLongitude4", Conv::Scale { fmt: Fmt::I16, mul: 0.075, div: I16_MAX_F, off: 0.0 }),
  e(34, "IcingDetected", Conv::Hash(Fmt::U8, &[(0, "n/a"), (1, "No"), (2, "Yes")])),
  e(35, "WindDirection", Conv::Scale { fmt: Fmt::U16, mul: 360.0, div: U16_MAX_F, off: 0.0 }),
  e(36, "WindSpeed", Conv::Scale { fmt: Fmt::U8, mul: 100.0, div: U8_MAX_F, off: 0.0 }),
  e(37, "StaticPressure", Conv::Scale { fmt: Fmt::U16, mul: 5_000.0, div: U16_MAX_F, off: 0.0 }),
  e(38, "DensityAltitude", Conv::Scale { fmt: Fmt::U16, mul: 19_900.0, div: U16_MAX_F, off: -900.0 }),
  e(39, "AirTemperature", Conv::Raw(Fmt::U8)), // int8s — see decode note
  e(40, "TargetLocationLatitude", Conv::Lat),
  e(41, "TargetLocationLongitude", Conv::Lon),
  e(42, "TargetLocationElevation", Conv::Alt),
  e(43, "TargetTrackGateWidth", Conv::Raw(Fmt::U8)),
  e(44, "TargetTrackGateHeight", Conv::Raw(Fmt::U8)),
  e(45, "TargetErrorEstimateCE90", Conv::Raw(Fmt::U16)),
  e(46, "TargetErrorEstimateLE90", Conv::Raw(Fmt::U16)),
  e(47, "GenericFlagData01", Conv::Bitmask(&[
    (0, "Laser range"), (1, "Auto-track"), (2, "IR polarity black"),
    (3, "Icing detected"), (4, "Slant range measured"), (5, "Image invalid"),
  ])),
  e(48, "SecurityLocalMetadataSet", Conv::Sub(Table::Security)),
  e(49, "DifferentialPressure", Conv::Scale { fmt: Fmt::U16, mul: 5_000.0, div: U16_MAX_F, off: 0.0 }),
  e(50, "AngleOfAttack", Conv::Scale { fmt: Fmt::I16, mul: 20.0, div: I16_MAX_F, off: 0.0 }),
  e(51, "VerticalSpeed", Conv::Scale { fmt: Fmt::I16, mul: 180.0, div: I16_MAX_F, off: 0.0 }),
  e(52, "SideslipAngle", Conv::Scale { fmt: Fmt::I16, mul: 20.0, div: I16_MAX_F, off: 0.0 }),
  e(53, "AirfieldBarometricPressure", Conv::Scale { fmt: Fmt::U16, mul: 5_000.0, div: U16_MAX_F, off: 0.0 }),
  e(54, "AirfieldElevation", Conv::Alt),
  e(55, "RelativeHumidity", Conv::Scale { fmt: Fmt::U8, mul: 100.0, div: U8_MAX_F, off: 0.0 }),
  e(56, "GPSSpeed", Conv::Raw(Fmt::U8)),
  e(57, "GroundRange", Conv::Scale { fmt: Fmt::U32, mul: 5_000_000.0, div: U32_MAX_F, off: 0.0 }),
  e(58, "FuelRemaining", Conv::Scale { fmt: Fmt::U16, mul: 10_000.0, div: U16_MAX_F, off: 0.0 }),
  e(59, "CallSign", Conv::Raw(Fmt::Str)),
  e(60, "WeaponLoad", Conv::Hex4(Fmt::U16)),
  e(61, "WeaponFired", Conv::Hex2(Fmt::U8)),
  e(62, "LaserPRFCode", Conv::Raw(Fmt::U16)),
  e(63, "SensorFieldOfViewName", Conv::Hash(Fmt::U8, &[
    (0, "Ultranarrow"), (1, "Narrow"), (2, "Medium"), (3, "Wide"), (4, "Ultrawide"),
    (5, "Narrow Medium"), (6, "2x Ultranarrow"), (7, "4x Ultranarrow"),
  ])),
  e(64, "MagneticHeading", Conv::Scale { fmt: Fmt::U16, mul: 360.0, div: U16_MAX_F, off: 0.0 }),
  e(65, "UAS_LSVersionNumber", Conv::Raw(Fmt::U8)),
  e(66, "TargetLocationCovarianceMatrix", Conv::Raw(Fmt::Undef)),
  e(67, "AlternateLatitude", Conv::Lat),
  e(68, "AlternateLongitude", Conv::Lon),
  e(69, "AlternateAltitude", Conv::Alt),
  e(70, "AlternateName", Conv::Raw(Fmt::Str)),
  e(71, "AlternateHeading", Conv::Scale { fmt: Fmt::U16, mul: 360.0, div: U16_MAX_F, off: 0.0 }),
  e(72, "EventStartTime", Conv::Time),
  e(73, "RVTLocalSet", Conv::Sub(Table::Unknown)),
  e(74, "VMTIDataSet", Conv::Sub(Table::Unknown)),
  e(75, "SensorEllipsoidHeight", Conv::Alt),
  e(76, "AlternateEllipsoidHeight", Conv::Alt),
  e(77, "OperationalMode", Conv::Hash(Fmt::U8, &[
    (0, "Other"), (1, "Operational"), (2, "Training"), (3, "Exercise"), (4, "Maintenance"),
  ])),
  e(78, "FrameCenterHeightAboveEllipsoid", Conv::Alt),
  e(79, "SensorVelocityNorth", Conv::Scale { fmt: Fmt::I16, mul: 327.0, div: I16_MAX_F, off: 0.0 }),
  e(80, "SensorVelocityEast", Conv::Scale { fmt: Fmt::I16, mul: 327.0, div: I16_MAX_F, off: 0.0 }),
  e(81, "ImageHorizonPixelPack", Conv::Raw(Fmt::Undef)),
  e(82, "CornerLatitude1", Conv::Lat),
  e(83, "CornerLongitude1", Conv::Lon),
  e(84, "CornerLatitude2", Conv::Lat),
  e(85, "CornerLongitude2", Conv::Lon),
  e(86, "CornerLatitude3", Conv::Lat),
  e(87, "CornerLongitude3", Conv::Lon),
  e(88, "CornerLatitude4", Conv::Lat),
  e(89, "CornerLongitude4", Conv::Lon),
  e(90, "FullPitchAngle", Conv::Scale { fmt: Fmt::I32, mul: 90.0, div: LAT_DIV, off: 0.0 }),
  e(91, "FullRollAngle", Conv::Scale { fmt: Fmt::I32, mul: 90.0, div: LAT_DIV, off: 0.0 }),
  e(92, "FullAngleOfAttack", Conv::Scale { fmt: Fmt::I32, mul: 90.0, div: LAT_DIV, off: 0.0 }),
  e(93, "FullSideslipAngle", Conv::Scale { fmt: Fmt::I32, mul: 90.0, div: LAT_DIV, off: 0.0 }),
  e(94, "MIISCoreIdentifier", Conv::Raw(Fmt::Undef)),
  e(95, "SARMotionImageryData", Conv::Sub(Table::Unknown)),
  e(96, "TargetWidthExtended", Conv::Raw(Fmt::Undef)),
  e(97, "RangeImageLocalSet", Conv::Sub(Table::Unknown)),
  e(98, "GeoregistrationLocalSet", Conv::Sub(Table::Unknown)),
  e(99, "CompositeImagingLocalSet", Conv::Sub(Table::Unknown)),
  e(100, "SegmentLocalSet", Conv::Sub(Table::Unknown)),
  e(101, "AmendLocalSet", Conv::Sub(Table::Unknown)),
  e(102, "SDCC-FLP", Conv::Raw(Fmt::Undef)),
  e(103, "DensityAltitudeExtended", Conv::Raw(Fmt::Undef)),
  e(104, "SensorEllipsoidHeightExtended", Conv::Raw(Fmt::Undef)),
  e(105, "AlternateEllipsoidHeightExtended", Conv::Raw(Fmt::Undef)),
];

/// ST 0102.11 Security Metadata local set (MISB.pm:222-296).
#[rustfmt::skip]
const SECURITY: &[TagEntry] = &[
  e(1, "SecurityClassification", Conv::Hash(Fmt::U8, &[
    (1, "Unclassified"), (2, "Restricted"), (3, "Confidential"), (4, "Secret"), (5, "Top Secret"),
  ])),
  e(2, "ClassifyingCountryCodeMethod", Conv::Hash(Fmt::U8, &[
    (0x01, "ISO-3166 Two Letter"), (0x02, "ISO-3166 Three Letter"),
    (0x03, "FIPS 10-4 Two Letter"), (0x04, "FIPS 10-4 Four Letter"),
    (0x05, "ISO-3166 Numeric"), (0x06, "1059 Two Letter"), (0x07, "1059 Three Letter"),
    (0x0a, "FIPS 10-4 Mixed"), (0x0b, "ISO 3166 Mixed"), (0x0c, "STANAG 1059 Mixed"),
    (0x0d, "GENC Two Letter"), (0x0e, "GENC Three Letter"), (0x0f, "GENC Numeric"),
    (0x10, "GENC Mixed"),
  ])),
  e(3, "ClassifyingCountry", Conv::StripSlashesPc),
  e(4, "SecuritySCI-SHIInformation", Conv::Raw(Fmt::Str)),
  e(5, "Caveats", Conv::Raw(Fmt::Str)),
  e(6, "ReleasingInstructions", Conv::Raw(Fmt::Str)),
  e(7, "ClassifiedBy", Conv::Raw(Fmt::Str)),
  e(8, "DerivedFrom", Conv::Raw(Fmt::Str)),
  e(9, "ClassificationReason", Conv::Raw(Fmt::Str)),
  e(10, "DeclassificationDate", Conv::DeclassDateVc),
  e(11, "ClassificationAndMarkingSystem", Conv::Raw(Fmt::Str)),
  e(12, "ObjectCountryCodingMethod", Conv::Hash(Fmt::U8, &[
    (0x01, "ISO-3166 Two Letter"), (0x02, "ISO-3166 Three Letter"), (0x03, "ISO-3166 Numeric"),
    (0x04, "FIPS 10-4 Two Letter"), (0x05, "FIPS 10-4 Four Letter"),
    (0x06, "1059 Two Letter"), (0x07, "1059 Three Letter"),
    (0x0d, "GENC Two Letter"), (0x0e, "GENC Three Letter"), (0x0f, "GENC Numeric"),
    (0x40, "GENC AdminSub"),
  ])),
  e(13, "ObjectCountryCodes", Conv::StripSlashesPc),
  e(14, "ClassificationComments", Conv::Raw(Fmt::Str)),
  e(15, "UMID", Conv::Raw(Fmt::Str)),
  e(16, "StreamID", Conv::Raw(Fmt::Str)),
  e(17, "TransportStreamID", Conv::Raw(Fmt::Str)),
  e(21, "ItemDesignatorID", Conv::Raw(Fmt::Str)),
  e(22, "SecurityVersion", Conv::SecVersion),
  e(23, "ClassifyingCountryCodingMethodDate", Conv::DashColonVc),
  e(24, "ObjectCountryCodingMethodDate", Conv::DashColonVc),
];

/// ChurchillNav proprietary set (MISB.pm:300-325) — little-endian doubles, all
/// `Unknown => 1` (suppressed from default output) + `Hidden => 1`.
#[rustfmt::skip]
const CHURCHILL_NAV: &[TagEntry] = &[
  ch(1, "ChurchillNav_0x0001", Conv::Raw(Fmt::Double)),
  ch(2, "ChurchillNav_0x0002", Conv::Raw(Fmt::Double)),
  ch(3, "ChurchillNav_0x0003", Conv::Raw(Fmt::Double)),
  ch(4, "ChurchillNav_0x0004", Conv::Raw(Fmt::Double)),
  ch(5, "ChurchillNav_0x0005", Conv::Raw(Fmt::Double)),
  ch(6, "ChurchillNav_0x0006", Conv::Raw(Fmt::Double)),
  ch(9, "ChurchillNav_0x0009", Conv::Raw(Fmt::Double)),
  ch(10, "ChurchillNav_0x000a", Conv::Raw(Fmt::Double)),
  ch(11, "ChurchillNav_0x000b", Conv::Raw(Fmt::Str)),
  ch(12, "ChurchillNav_0x000c", Conv::Raw(Fmt::Double)),
  ch(13, "ChurchillNav_0x000d", Conv::Raw(Fmt::Double)),
  ch(14, "ChurchillNav_0x000e", Conv::Raw(Fmt::Double)),
  ch(16, "ChurchillNav_0x0010", Conv::Raw(Fmt::Double)),
  ch(17, "ChurchillNav_0x0011", Conv::Raw(Fmt::Double)),
  ch(18, "ChurchillNav_0x0012", Conv::Raw(Fmt::Double)),
  ch(20, "ChurchillNav_0x0014", Conv::Raw(Fmt::Double)),
];

/// Shorthand for a ChurchillNav (`Unknown => 1`) entry.
const fn ch(id: u8, name: &'static str, conv: Conv) -> TagEntry {
  TagEntry {
    id,
    name,
    unknown: true,
    conv,
  }
}

/// Look up a tag entry in a table by its 1-byte id.
fn lookup(table: Table, id: u8) -> Option<&'static TagEntry> {
  table.entries().iter().find(|t| t.id == id)
}

/// A decoded MISB leaf — one extracted tag, with both conversion views rendered
/// up front (the `-n`/`-j` toggle picks one at emit) and its `Doc<N>` stamp.
#[derive(Debug, Clone)]
struct MisbLeaf {
  /// `Doc<N>` document index (MISB.pm:398; `0` until [`MisbMeta::stamp_doc`]).
  doc: u32,
  /// The ExifTool tag name (`-G1` key tail).
  name: SmolStr,
  /// The `-n` (ValueConv) value.
  value_n: TagValue,
  /// The `-j` (PrintConv) value.
  value_print: TagValue,
  /// `Unknown => 1` — suppressed from default output.
  unknown: bool,
}

/// Accumulated MISB metadata for an M2TS file — the decoded leaves across every
/// `0x15` PES packet, in walk order, each stamped with its `Doc<N>`.
#[derive(Debug, Clone)]
pub struct MisbMeta {
  leaves: Vec<MisbLeaf>,
}

impl Default for MisbMeta {
  fn default() -> Self {
    Self::new()
  }
}

impl MisbMeta {
  /// A fresh, empty accumulator.
  #[must_use]
  pub fn new() -> Self {
    Self { leaves: Vec::new() }
  }

  /// `true` when no MISB tag has been decoded.
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.leaves.is_empty()
  }

  /// `true` when `payload` (a `0x15` PES payload, after the PES header) carries
  /// the MISB code: the 4-byte SMPTE prefix `06 0e 2b 34` AFTER the 5-byte
  /// service header (M2TS.pm:357 `/^.{5}\x06\x0e\x2b\x34/s`).
  #[must_use]
  pub fn has_misb_code(payload: &[u8]) -> bool {
    payload.get(5..9) == Some(&[0x06, 0x0e, 0x2b, 0x34])
  }

  /// Decode ONE MISB PES packet (`MISB::ParseMISB`, MISB.pm:388-450). `payload`
  /// is the PES payload (after the PES header); `doc_counter` is the running
  /// global `Doc<N>` count. Returns the (possibly incremented) counter: a
  /// packet that yielded ≥1 tag consumes one `Doc<N>` (MISB.pm:398), otherwise
  /// the count is given back (MISB.pm:448).
  pub fn parse_packet(&mut self, payload: &[u8], doc_counter: u32) -> u32 {
    let before = self.leaves.len();
    let doc = doc_counter + 1;
    parse_misb(payload, doc, &mut self.leaves);
    if self.leaves.len() > before {
      doc // a leaf was extracted ⇒ this packet keeps the Doc<N>
    } else {
      doc_counter // nothing extracted ⇒ give the count back (MISB.pm:448)
    }
  }

  /// Emit the decoded MISB leaves as [`EmittedTag`]s under the family-1 `MISB`
  /// group with each leaf's `Doc<N>` (collapsed at `-G1`, prefixed at `-G3`).
  /// Mirrors the M2TS LIGOGPS emission shape.
  pub fn emit(&self, opts: EmitOptions, out: &mut Vec<EmittedTag>) {
    let print_conv = matches!(opts.mode, ConvMode::PrintConv);
    for leaf in &self.leaves {
      let value = if print_conv {
        leaf.value_print.clone()
      } else {
        leaf.value_n.clone()
      };
      out.push(EmittedTag::new(
        Group::with_doc("MISB", "MISB", leaf.doc),
        leaf.name.clone(),
        value,
        leaf.unknown,
      ));
    }
  }
}

/// `MISB::ParseMISB` (MISB.pm:388-450) — skip the 5-byte service header, then
/// walk `[16-byte universal key][BER length][value]` records, dispatching each
/// to its Main-key sub-table. Bounds-checked (no panic on a truncated/crafted
/// packet); appends every decoded leaf (stamped `doc`) to `out`.
fn parse_misb(data: &[u8], doc: u32, out: &mut Vec<MisbLeaf>) {
  let end = data.len();
  // MISB.pm:406 `for ($pos = 5; $pos + 16 < $end; )` — skip the 5-byte header.
  // The guard is written subtraction-first so a `pos` at (or, defensively, past)
  // `end` can never overflow the `pos + 16` add on a crafted record.
  let mut pos = 5usize;
  while end.saturating_sub(pos) > 16 {
    // MISB.pm:407 `$key = unpack('H*', substr($$dataPt, $pos, 16))` (lowercase).
    // The loop guard keeps this in-bounds; `.get` keeps it panic-free regardless.
    let Some(key_bytes) = data.get(pos..pos.saturating_add(16)) else {
      return;
    };
    let key_hex = hex_lower(key_bytes);
    pos = pos.saturating_add(16);
    // MISB.pm:409-416 — BER length (short form, or long form when bit 0x80 set).
    let Some((len, next)) = read_ber(data, pos, end) else {
      return; // MISB.pm:414 `return if $pos + $n > $end`
    };
    pos = next;
    // MISB.pm:417 — Main-key lookup. The Security key never matches (quirk).
    let table = MAIN_KEYS
      .iter()
      .find(|(k, _)| *k == key_hex.as_str())
      .map(|(_, t)| *t);
    // MISB.pm:418-428 — unrecognized key ⇒ the Unknown table (the tags it yields
    // are all `Unknown`, suppressed from default output, matching the
    // `$verbose or $unknown` gate).
    let table = table.unwrap_or(Table::Unknown);
    // MISB.pm:430-433 — a record that runs past the buffer is clamped to the
    // bytes actually available (`$len = $end - $pos`), then the walk advances by
    // that SAME clamped length (`$pos += $len`, MISB.pm:444) ⇒ `pos` lands on
    // `end` and the loop terminates. A declared `len` larger than `avail` (e.g.
    // a saturated long-form BER length) therefore must NOT advance `pos` by the
    // untrusted `len` — that would set `pos` to a huge value and overflow the
    // next loop guard. Advance by the clamped `rec_len` instead.
    let avail = end.saturating_sub(pos);
    let rec_len = len.min(avail);
    // MISB.pm:434-442 — process the sub-table local set under its byte order.
    process_klv(data, pos, rec_len, table, table.byte_order(), doc, out);
    pos = pos.saturating_add(rec_len); // MISB.pm:444 `$pos += $len` (clamped)
    // A clamped (truncated) record consumes the rest of the buffer; ExifTool's
    // `$pos + 16 < $end` guard then ends the walk. Make that explicit so a future
    // change to the guard can never re-enter on a degenerate record.
    if rec_len < len {
      break;
    }
  }
}

/// `MISB::ProcessKLV` (MISB.pm:337-382) — walk a local set's `[1-byte tag][BER
/// length][value]` records over `data[start..start+dir_len]`, decoding each via
/// its table entry (or the default-format/binary fallback). Bounds-checked.
#[allow(clippy::too_many_arguments)]
fn process_klv(
  data: &[u8],
  start: usize,
  dir_len: usize,
  table: Table,
  byte_order: ByteOrder,
  doc: u32,
  out: &mut Vec<MisbLeaf>,
) {
  let dir_end = start.saturating_add(dir_len).min(data.len());
  // MISB.pm:349 `for ($pos=$dirStart; $pos<$dirEnd-1; )` — need a tag + len byte.
  // Subtraction-first guard so a `pos` at/over `dir_end` can't overflow `pos + 1`.
  let mut pos = start;
  while dir_end.saturating_sub(pos) > 1 {
    // The loop guard keeps `pos` in-bounds; `.get` keeps it panic-free regardless.
    let Some(&tag) = data.get(pos) else {
      return;
    };
    pos = pos.saturating_add(1);
    // MISB.pm:351-357 — BER length.
    let Some((len, next)) = read_ber(data, pos, dir_end) else {
      return; // MISB.pm:354 `last if $pos + $n > $dirEnd`
    };
    pos = next;
    // MISB.pm:358 `last if $pos + $len > $dirEnd` — a record (incl. a saturated
    // long-form BER length) declaring more than the bytes left in this local set
    // ENDS the walk (no partial decode). Compare via subtraction so the untrusted
    // `len` can never overflow a `pos + len` add.
    if len > dir_end.saturating_sub(pos) {
      return;
    }
    // `len <= dir_end - pos <= data.len() - pos` ⇒ `pos + len` is in-bounds; the
    // `decode_tag` value slices below cannot panic or read OOB.
    decode_tag(data, pos, len, tag, table, byte_order, doc, out);
    pos = pos.saturating_add(len); // MISB.pm:379 `$pos += $len`
  }
}

/// Decode ONE local-set record (`MISB::ProcessKLV` body, MISB.pm:360-378) and
/// push its leaf. Unrecognized tags / no-format values follow the
/// default-format-by-length then string/binary fallback (MISB.pm:362-372),
/// flagged `Unknown` so default output suppresses them.
#[allow(clippy::too_many_arguments)]
fn decode_tag(
  data: &[u8],
  pos: usize,
  len: usize,
  tag: u8,
  table: Table,
  byte_order: ByteOrder,
  doc: u32,
  out: &mut Vec<MisbLeaf>,
) {
  if let Some(entry) = lookup(table, tag) {
    if let Conv::Sub(sub) = entry.conv {
      // MISB.pm:434-442 — nested SubDirectory: recurse with the sub-table's
      // byte order. (The recognized container tag itself yields no scalar.)
      process_klv(data, pos, len, sub, sub.byte_order(), doc, out);
      return;
    }
    if let Some((value_n, value_print)) = convert(data, pos, len, entry.conv, byte_order) {
      out.push(MisbLeaf {
        doc,
        name: SmolStr::new(entry.name),
        value_n,
        value_print,
        unknown: entry.unknown,
      });
    }
    return;
  }
  // MISB.pm:361-372 — unrecognized tag: default format by length, else
  // string/binary. These are `Unknown`-gated (MISB.pm:418-428 spirit), so flag
  // them so default output drops them.
  let (value_n, value_print) = unknown_value(data, pos, len, byte_order);
  out.push(MisbLeaf {
    doc,
    name: unknown_name(tag),
    value_n,
    value_print,
    unknown: true,
  });
}

/// Apply a [`Conv`] to the record at `data[pos..pos+len]`, returning the
/// `(value_n, value_print)` pair. `None` ⇒ the value could not be read (drop
/// the tag).
fn convert(
  data: &[u8],
  pos: usize,
  len: usize,
  conv: Conv,
  byte_order: ByteOrder,
) -> Option<(TagValue, TagValue)> {
  // MISB.pm:360-364 `ReadValue($dataPt, $pos, $format, undef, $len)` — every
  // value decode is bounded to the DECLARED KLV length `$len`. Take that
  // `data[pos..pos+len]` slice ONCE (the bound is guaranteed in-range by the
  // `process_klv` BER guard, `len <= dir_end - pos <= data.len() - pos`;
  // `.get(..).unwrap_or(&[])` keeps it panic-free regardless) and decode EVERY
  // tag's value from it, so a too-short record can never read past `$len` into
  // the next local tag / next top-level KLV record.
  let value = pos
    .checked_add(len)
    .and_then(|end| data.get(pos..end))
    .unwrap_or(&[]);
  match conv {
    Conv::Sub(_) => None, // handled by the caller
    Conv::Raw(fmt) => {
      let v = read_fmt(value, fmt, byte_order)?;
      Some((v.clone(), v))
    }
    Conv::Scale { fmt, mul, div, off } => {
      let n = read_num(value, fmt, byte_order)?;
      // Faithful operation order: `$val * mul / div + off` (multiply THEN
      // divide), matching ExifTool's Perl double-precision evaluation.
      let scaled = TagValue::F64(n * mul / div + off);
      Some((scaled.clone(), scaled))
    }
    Conv::Lat => {
      let n = read_num(value, Fmt::I32, byte_order)?;
      let deg = n * 90.0 / LAT_DIV;
      Some((
        TagValue::F64(deg),
        TagValue::Str(crate::composite::convs::gps::to_dms(deg, 'N').into()),
      ))
    }
    Conv::Lon => {
      let n = read_num(value, Fmt::I32, byte_order)?;
      let deg = n * 180.0 / LON_DIV;
      Some((
        TagValue::F64(deg),
        TagValue::Str(crate::composite::convs::gps::to_dms(deg, 'E').into()),
      ))
    }
    Conv::Alt => {
      let n = read_num(value, Fmt::U16, byte_order)?;
      let m = n * 19_900.0 / U16_MAX_F - 900.0;
      Some((
        TagValue::F64(m),
        // MISB.pm:42 `sprintf("%.2f m", $val)`.
        TagValue::Str(std::format!("{m:.2} m").into()),
      ))
    }
    Conv::Time => {
      let n = read_num(value, Fmt::U64, byte_order)?;
      // MISB.pm:26 `ConvertUnixTime($val/1e6, 0, 6) . "Z"` (VC), then
      // `ConvertDateTime` (PC, identity under default options).
      let s = std::format!(
        "{}Z",
        crate::datetime::convert_unix_time_frac_f64(n / 1e6, 6)
      );
      let v = TagValue::Str(crate::datetime::convert_datetime(&s).into());
      Some((TagValue::Str(s.into()), v))
    }
    Conv::Suffix(fmt, suffix) => {
      let v = read_fmt(value, fmt, byte_order)?;
      let print = TagValue::Str(std::format!("{}{suffix}", scalar_text(&v)).into());
      Some((v, print))
    }
    Conv::Hex4(fmt) => {
      let n = read_num(value, fmt, byte_order)?;
      let raw = read_fmt(value, fmt, byte_order)?;
      Some((
        raw,
        TagValue::Str(std::format!("0x{:04x}", n as u64).into()),
      ))
    }
    Conv::Hex2(fmt) => {
      let n = read_num(value, fmt, byte_order)?;
      let raw = read_fmt(value, fmt, byte_order)?;
      Some((
        raw,
        TagValue::Str(std::format!("0x{:02x}", n as u64).into()),
      ))
    }
    Conv::Hash(fmt, table) => {
      let raw = read_fmt(value, fmt, byte_order)?;
      // MISB.pm hash `PrintConv => { k => label }` is a Perl hash lookup on the
      // RAW scalar `$val`, NOT an arithmetic conversion. Derive the integer key
      // from the extracted scalar (`I64`/`U64` for a real read); a too-short
      // value is `''` (empty `read_fmt` scalar) ⇒ `scalar_key` is `None`, the
      // lookup misses, and ExifTool returns `$val` unchanged (`$h{''}` miss,
      // verified vs bundled 13.59) — never the `read_num` empty→0 coercion that
      // would fabricate the key-0 label.
      let key = scalar_key(&raw);
      let print = match key.and_then(|k| table.iter().find(|(tk, _)| *tk == k)) {
        // Hash hit ⇒ the label.
        Some((_, label)) => TagValue::Str(SmolStr::new(*label)),
        // Hash miss (incl. an empty too-short scalar) ⇒ the raw value unchanged.
        None => raw.clone(),
      };
      Some((raw, print))
    }
    Conv::Bitmask(table) => {
      let raw = read_fmt(value, Fmt::U8, byte_order)?;
      let n = read_num(value, Fmt::U8, byte_order)? as i64;
      // MISB.pm BITMASK ⇒ `DecodeBits($val, …, BitsPerWord)`; no `BitsPerWord`
      // ⇒ the 32-bit default (memory: BITMASK = DecodeBits, not raw).
      let print = crate::convert::decode_bits(&std::format!("{n}"), Some(table), 32);
      Some((raw, TagValue::Str(print.into())))
    }
    Conv::StripSlashesPc => {
      let v = read_fmt(value, Fmt::Str, byte_order)?;
      let s = scalar_text(&v);
      // MISB.pm:250 `$val =~ s(^//)()` (PrintConv) — strip a single leading `//`.
      let stripped = s.strip_prefix("//").unwrap_or(&s);
      Some((v.clone(), TagValue::Str(SmolStr::new(stripped))))
    }
    Conv::DashColonVc => {
      let v = read_fmt(value, Fmt::Str, byte_order)?;
      // MISB.pm:288 `$val=~tr/-/:/` (ValueConv) — applied in BOTH modes.
      let s = scalar_text(&v).replace('-', ":");
      let out = TagValue::Str(s.into());
      Some((out.clone(), out))
    }
    Conv::DeclassDateVc => {
      let v = read_fmt(value, Fmt::Str, byte_order)?;
      // MISB.pm:261 `s/(\d{4})(\d{2})(\d{2})/$1:$2:$3/` (ValueConv) — both modes.
      let out = TagValue::Str(declassify_date(&scalar_text(&v)).into());
      Some((out.clone(), out))
    }
    Conv::SecVersion => {
      let raw = read_fmt(value, Fmt::U16, byte_order)?;
      // MISB.pm:283 `PrintConv => '"0102.$val"'` — string interpolation of the
      // RAW scalar, NOT an arithmetic conversion: a too-short `int16u` makes
      // `ReadValue` return `''` (empty `read_fmt` scalar) and ExifTool emits
      // `"0102."` (verified vs bundled 13.59 MISB.pm). Derive from the scalar so
      // the empty stays empty — never the `read_num` empty→0 numeric coercion
      // (which would fabricate `"0102.0"`).
      let print = std::format!("0102.{}", scalar_text(&raw));
      Some((raw, TagValue::Str(print.into())))
    }
  }
}

/// Read a value via the faithful `ReadValue` semantics for `fmt` over the
/// `len`-bounded record `value` (count = `int(len / format_size)`,
/// MISB.pm:360-364 `ReadValue($dataPt, $pos, $format, undef, $len)`). `value` is
/// the declared-KLV-length slice (`data[pos..pos+len]`), so passing offset `0`
/// makes `read_value`'s implicit `$size = length($value)` equal to the KLV
/// `$len` — the read CANNOT spill past the record into the next local tag / next
/// top-level KLV (the explicit-`$len` bound ExifTool's `ReadValue` enforces). A
/// recognized tag whose `len < fmt` width yields ExifTool's `''` (count
/// shortened to 0 ⇒ the empty-string scalar), NOT bytes from the following
/// record. For `string`/`undef` the whole slice is one scalar.
fn read_fmt(value: &[u8], fmt: Fmt, byte_order: ByteOrder) -> Option<TagValue> {
  let count = match fmt {
    Fmt::Str | Fmt::Undef => value.len(),
    _ => value.len() / fmt.size(),
  };
  crate::convert::read_value(value, 0, fmt.as_str(), count, byte_order)
}

/// Read the FIRST element of `fmt` as an `f64` — the numeric a
/// ValueConv/PrintConv operates on (MISB scale/hash/etc. tags are single-element
/// in practice). Bounded to the declared-KLV-length slice `value`, so a too-short
/// record can never read `fmt`-width bytes past `len` into the next record.
///
/// When `len < fmt` width, ExifTool's `ReadValue($dataPt, $pos, $format, undef,
/// $len)` returns the empty string `''` (ExifTool.pm:6294-6295 `return '' …
/// $size < $len`); a numeric ValueConv/PrintConv then evaluates it in numeric
/// context, where Perl coerces `''` to `0` (verified: an `int32s` `SensorLatitude`
/// with `len=1` emits GPS Latitude `0`, a `int64u` `UNIXTimeStamp` with `len=2`
/// emits `0000:00:00 00:00:00Z`, a `int16u` `WeaponLoad` with `len=1` emits
/// `0x0000`). Mirror that with `Some(0.0)` so the tag is emitted with the faithful
/// degenerate value rather than dropped — and, crucially, the following record
/// still decodes from its own bytes.
fn read_num(value: &[u8], fmt: Fmt, byte_order: ByteOrder) -> Option<f64> {
  match crate::convert::read_value(value, 0, fmt.as_str(), 1, byte_order) {
    Some(TagValue::I64(i)) => Some(i as f64),
    Some(TagValue::U64(u)) => Some(u as f64),
    Some(TagValue::F64(f)) => Some(f),
    // `len < fmt` width ⇒ `read_value` shortens the count to 0 and returns
    // `None`; ExifTool's `''` numeric-coerces to `0`.
    None => Some(0.0),
    Some(_) => None,
  }
}

/// MISB.pm:361-372 — an unrecognized tag's value: default format by length
/// (`%defaultFormat` 1/2/4/8 ⇒ int8u/16u/32u/64u, MISB.pm:46-51), else a
/// printable-ASCII string or raw binary.
fn unknown_value(
  data: &[u8],
  pos: usize,
  len: usize,
  byte_order: ByteOrder,
) -> (TagValue, TagValue) {
  // The declared-KLV-length slice (MISB.pm:367 `substr($$dataPt, $pos, $len)`),
  // shared by the default-format read and the string/binary fallback so neither
  // path can read past `$len`. `checked_add`/`unwrap_or(&[])` keep it panic-free
  // even on an untrusted `len`.
  let bytes = pos
    .checked_add(len)
    .and_then(|end| data.get(pos..end))
    .unwrap_or(&[]);
  let fmt = match len {
    1 => Some(Fmt::U8),
    2 => Some(Fmt::U16),
    4 => Some(Fmt::U32),
    8 => Some(Fmt::U64),
    _ => None,
  };
  if let Some(fmt) = fmt
    && let Some(v) = read_fmt(bytes, fmt, byte_order)
  {
    return (v.clone(), v);
  }
  // No default format ⇒ string if printable, else binary (MISB.pm:367-371).
  if bytes
    .iter()
    .all(|&b| matches!(b, b'\t' | b'\n' | b'\r' | 0x20..=0x7e))
  {
    let s = TagValue::Str(String::from_utf8_lossy(bytes).into_owned().into());
    (s.clone(), s)
  } else {
    let b = TagValue::Bytes(bytes.to_vec());
    (b.clone(), b)
  }
}

/// `MISB_$key`-style placeholder name for an unrecognized local-set tag id.
fn unknown_name(tag: u8) -> SmolStr {
  std::format!("MISB_Unknown_0x{tag:04x}").into()
}

/// Read a BER length at `pos` (MISB.pm:351-357 / :409-416). Short form: a single
/// byte `< 0x80`. Long form: `0x80 | n` then `n` big-endian length bytes.
/// Returns `(length, position_after_the_length_field)`, or `None` if the long
/// form runs past `end`.
fn read_ber(data: &[u8], pos: usize, end: usize) -> Option<(usize, usize)> {
  let first = *data.get(pos)?;
  // `data.get(pos)` succeeded ⇒ `pos < data.len()` ⇒ `pos + 1` cannot overflow.
  if first & 0x80 == 0 {
    return Some((first as usize, pos + 1));
  }
  let n = (first & 0x7f) as usize;
  let mut p = pos + 1;
  // MISB.pm:354/414 — `last`/`return` if the `n` length bytes run past `end`.
  // Subtraction-first so the bounded `n` (≤ 127) can never overflow a `p + n` add.
  if n > end.saturating_sub(p) {
    return None;
  }
  // The accumulated length is `saturating_*` so a long-form BER field declaring a
  // huge length saturates to `usize::MAX` rather than wrapping; the callers clamp
  // it to the bytes actually available (`parse_misb`) or terminate the walk
  // (`process_klv`), matching ExifTool's truncated-record handling.
  let mut len = 0usize;
  for _ in 0..n {
    len = len
      .saturating_mul(256)
      .saturating_add(*data.get(p)? as usize);
    p = p.saturating_add(1);
  }
  Some((len, p))
}

/// `s/(\d{4})(\d{2})(\d{2})/$1:$2:$3/` (MISB.pm:261) — insert `:` into the FIRST
/// 8-consecutive-ASCII-digit run. Non-matching input is returned unchanged.
fn declassify_date(s: &str) -> String {
  let b = s.as_bytes();
  // Find the FIRST index where 8 consecutive ASCII digits start. `i + 8 <=
  // b.len()` holds for every candidate, so each `.get` below is `Some`.
  let found = (0..=b.len().saturating_sub(8)).find(|&i| {
    b.get(i..i + 8)
      .is_some_and(|w| w.iter().all(u8::is_ascii_digit))
  });
  let Some(i) = found else {
    return s.to_string();
  };
  // The match guarantees `s` is ASCII over `[i, i+8)`, so these byte offsets are
  // all valid `str` boundaries; `.get(..).unwrap_or("")` keeps it panic-free.
  let g = |a: usize, z: usize| s.get(a..z).unwrap_or("");
  let mut out = String::with_capacity(s.len() + 2);
  out.push_str(g(0, i));
  out.push_str(g(i, i + 4));
  out.push(':');
  out.push_str(g(i + 4, i + 6));
  out.push(':');
  out.push_str(g(i + 6, i + 8));
  out.push_str(s.get(i + 8..).unwrap_or(""));
  out
}

/// Lowercase hex of `bytes` (`unpack('H*', …)`, MISB.pm:407).
fn hex_lower(bytes: &[u8]) -> String {
  use core::fmt::Write;
  let mut s = String::with_capacity(bytes.len() * 2);
  for b in bytes {
    let _ = write!(s, "{b:02x}");
  }
  s
}

/// The integer hash-lookup key a [`Conv::Hash`] `PrintConv` matches `$val`
/// against, derived from the EXTRACTED raw scalar. A real numeric read yields
/// `Some(n)`; a too-short value (the empty-string `read_fmt` scalar, ExifTool's
/// `''`) yields `None` so the hash lookup misses (`$h{''}` is absent) and the
/// caller returns the raw value unchanged — separating extraction from the
/// per-conversion interpretation so the empty→0 numeric coercion never applies
/// to this string-keyed lookup.
fn scalar_key(v: &TagValue) -> Option<i64> {
  match v {
    TagValue::I64(i) => Some(*i),
    TagValue::U64(u) => i64::try_from(*u).ok(),
    _ => None,
  }
}

/// Scalar text of a [`TagValue`] for the suffix/strip/hash string conversions
/// (Perl scalar stringification of the raw value).
fn scalar_text(v: &TagValue) -> String {
  match v {
    TagValue::I64(i) => i.to_string(),
    TagValue::U64(u) => u.to_string(),
    TagValue::F64(f) => crate::value::format_g(*f, 15),
    TagValue::Str(s) => s.to_string(),
    other => std::format!("{other:?}"),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// The 16-byte ST 0601.11 UAS Datalink universal key ([`MAIN_KEYS`]) — a
  /// crafted top-level KLV with this key dispatches to [`UAS_DATALINK`].
  const UAS_KEY: [u8; 16] = [
    0x06, 0x0e, 0x2b, 0x34, 0x02, 0x0b, 0x01, 0x01, 0x0e, 0x01, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00,
  ];

  /// Build a MISB PES payload: a 5-byte service header (skipped by
  /// [`parse_misb`]) followed by `body`.
  fn payload(body: &[u8]) -> Vec<u8> {
    let mut v = vec![0x00, 0x01, 0x0f, 0x00, 0x00];
    v.extend_from_slice(body);
    v
  }

  /// A valid UAS local-set record for tag 65 `UAS_LSVersionNumber` (int8u): the
  /// 1-byte tag id, a short-form BER length of 1, and the value `11`.
  fn uas_ls_version_record() -> [u8; 3] {
    [65, 0x01, 0x0b]
  }

  /// Decode one crafted packet and return the extracted leaves.
  fn decode(payload: &[u8]) -> Vec<MisbLeaf> {
    let mut out = Vec::new();
    parse_misb(payload, 1, &mut out);
    out
  }

  /// Assert the decode yielded exactly the one valid `UAS_LSVersionNumber = 11`
  /// leaf (the prefix surviving a malformed record). `.first()` keeps the helper
  /// panic-free / index-free.
  fn assert_single_uas_version(leaves: &[MisbLeaf]) {
    assert_eq!(leaves.len(), 1);
    let leaf = leaves.first().expect("exactly one leaf");
    assert_eq!(leaf.name.as_str(), "UAS_LSVersionNumber");
    assert_eq!(leaf.value_n, TagValue::I64(11));
  }

  /// A top-level long-form BER length that declares far more bytes than the
  /// packet actually carries must NOT advance `pos` by the untrusted length
  /// (which would overflow the next loop guard): the record is clamped to the
  /// bytes available, the valid local-set tags inside are still decoded, and the
  /// walk then terminates. Run under debug overflow-checks ⇒ proves no panic.
  #[test]
  fn top_level_oversized_ber_length_terminates_bounded_and_emits_prefix() {
    // [UAS key][BER 0x81 0xff = "255 bytes"][only a 3-byte valid record follows]
    let mut body = Vec::new();
    body.extend_from_slice(&UAS_KEY);
    body.extend_from_slice(&[0x81, 0xff]); // long-form BER: declares 255 bytes
    body.extend_from_slice(&uas_ls_version_record()); // 3 bytes actually present
    let leaves = decode(&payload(&body));
    // The clamped record is walked: the valid UAS_LSVersionNumber leaf surfaces.
    assert_single_uas_version(&leaves);
  }

  /// A long-form BER length whose magnitude saturates `usize` (eight `0xff`
  /// length bytes) must saturate (not wrap) and be clamped to the available
  /// bytes — no panic, no OOB, the valid prefix still decodes.
  #[test]
  fn top_level_saturating_ber_length_is_clamped_no_panic() {
    let mut body = Vec::new();
    body.extend_from_slice(&UAS_KEY);
    // 0x88 ⇒ 8 length bytes; all 0xff ⇒ accumulates to a saturated usize::MAX.
    body.push(0x88);
    body.extend_from_slice(&[0xff; 8]);
    body.extend_from_slice(&uas_ls_version_record());
    let leaves = decode(&payload(&body));
    assert_single_uas_version(&leaves);
  }

  /// A nested/local-set record whose BER length runs past the local set ends the
  /// inner walk (ExifTool `last if $pos + $len > $dirEnd`): tags before it are
  /// decoded, the oversized one is dropped, and there is no panic/OOB.
  #[test]
  fn nested_oversized_ber_length_terminates_inner_walk_no_panic() {
    // Inner local set: [valid tag 65 = 11][tag 1 with an oversized inner BER len].
    let mut inner = Vec::new();
    inner.extend_from_slice(&uas_ls_version_record()); // valid prefix tag
    inner.push(1); // tag 1 (Checksum)
    inner.extend_from_slice(&[0x81, 0xff]); // inner long-form BER: 255 bytes
    inner.push(0x00); // only 1 byte actually present (< 255)
    // Wrap it in a top-level record whose own length exactly spans `inner`.
    let mut body = Vec::new();
    body.extend_from_slice(&UAS_KEY);
    body.push(u8::try_from(inner.len()).expect("inner fits a short-form BER"));
    body.extend_from_slice(&inner);
    let leaves = decode(&payload(&body));
    // Only the valid prefix tag survives; the oversized inner record is dropped.
    assert_single_uas_version(&leaves);
  }

  /// A nested long-form BER length that saturates `usize` is likewise bounded —
  /// the inner walk terminates without panic or wrap.
  #[test]
  fn nested_saturating_ber_length_terminates_inner_walk_no_panic() {
    let mut inner = Vec::new();
    inner.extend_from_slice(&uas_ls_version_record());
    inner.push(1); // tag 1
    inner.push(0x88); // 8 length bytes
    inner.extend_from_slice(&[0xff; 8]); // saturates to usize::MAX
    let mut body = Vec::new();
    body.extend_from_slice(&UAS_KEY);
    body.push(u8::try_from(inner.len()).expect("inner fits a short-form BER"));
    body.extend_from_slice(&inner);
    let leaves = decode(&payload(&body));
    assert_single_uas_version(&leaves);
  }

  /// The precise #130 scenario: a MISB prefix whose top-level long-form
  /// BER length saturates and is followed by NO further bytes. The buggy code
  /// advanced `pos` to `usize::MAX` and overflowed `pos + 16` on the next guard;
  /// the fix clamps the advance to the available bytes and terminates. No panic.
  #[test]
  fn oversized_ber_with_no_value_bytes_does_not_overflow_loop_guard() {
    let mut body = Vec::new();
    body.extend_from_slice(&UAS_KEY);
    body.push(0x88); // 8 length bytes …
    body.extend_from_slice(&[0xff; 8]); // … saturating to usize::MAX, no value
    let leaves = decode(&payload(&body));
    // Nothing decodable, but crucially: no panic and a bounded, empty result.
    assert!(leaves.is_empty());
  }

  /// `read_ber` saturates a long-form length rather than wrapping, and a
  /// truncated long-form field (the declared count of length bytes runs past
  /// `end`) returns `None`.
  #[test]
  fn read_ber_saturates_and_rejects_truncated_long_form() {
    // 8 length bytes of 0xff ⇒ usize::MAX (saturated, not wrapped).
    let buf = [0x88u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert_eq!(read_ber(&buf, 0, buf.len()), Some((usize::MAX, buf.len())));
    // Declares 4 length bytes but only 2 are present ⇒ rejected.
    let trunc = [0x84u8, 0x00, 0x00];
    assert_eq!(read_ber(&trunc, 0, trunc.len()), None);
    // Short form passes through unchanged.
    assert_eq!(read_ber(&[0x05u8], 0, 1), Some((5, 1)));
  }

  /// The valid happy-path still decodes: a well-formed UAS record yields its
  /// leaf (guards the malformed-BER fixes against over-rejecting good input).
  #[test]
  fn valid_record_still_decodes() {
    let mut body = Vec::new();
    body.extend_from_slice(&UAS_KEY);
    body.push(u8::try_from(uas_ls_version_record().len()).expect("fits"));
    body.extend_from_slice(&uas_ls_version_record());
    let leaves = decode(&payload(&body));
    assert_single_uas_version(&leaves);
  }

  /// Wrap a UAS local-set `inner` body in one top-level KLV ([`UAS_KEY`] + a
  /// short-form BER length spanning exactly `inner`) and decode it.
  fn decode_uas_local_set(inner: &[u8]) -> Vec<MisbLeaf> {
    let mut body = Vec::new();
    body.extend_from_slice(&UAS_KEY);
    body.push(u8::try_from(inner.len()).expect("inner fits a short-form BER"));
    body.extend_from_slice(inner);
    decode(&payload(&body))
  }

  /// Find the decoded leaf named `name`.
  fn leaf<'a>(leaves: &'a [MisbLeaf], name: &str) -> &'a MisbLeaf {
    leaves
      .iter()
      .find(|l| l.name.as_str() == name)
      .unwrap_or_else(|| panic!("missing leaf {name}; got {:?}", names(leaves)))
  }

  /// The decoded leaf names, for assertion messages.
  fn names(leaves: &[MisbLeaf]) -> Vec<&str> {
    leaves.iter().map(|l| l.name.as_str()).collect()
  }

  /// A recognized NUMERIC tag whose declared BER length is SHORTER than its
  /// format width must NOT read `fmt`-width bytes from the following local tag
  /// (the #130 cross-boundary over-read). ExifTool's `ReadValue($dataPt, $pos,
  /// $format, undef, $len)` stays inside `data[pos..pos+len]`: a too-short read
  /// yields the empty string (numeric-coerced to `0` by any ValueConv), never
  /// the next record's bytes. Here `GPSLatitude` (int32s, `%latInfo`) declares
  /// `len=1` but is immediately followed by a valid `UAS_LSVersionNumber=11`;
  /// the latter MUST still decode from its own bytes.
  #[test]
  fn short_numeric_tag_does_not_over_read_into_next_record() {
    // [tag 13 GPSLatitude][BER len 1][0x7f]  [tag 65 = 11]
    let mut inner = vec![13, 0x01, 0x7f];
    inner.extend_from_slice(&uas_ls_version_record());
    let leaves = decode_uas_local_set(&inner);
    // The following record was NOT consumed by an int32s over-read — it decodes.
    assert_eq!(
      leaf(&leaves, "UAS_LSVersionNumber").value_n,
      TagValue::I64(11)
    );
    // The short latitude is the faithful degenerate value (`'' * 90/0x7fffffff`
    // = 0, ExifTool `-n` GPS Latitude `0`), NOT a value fabricated from the
    // next record's `[65, 0x01, 0x0b]` bytes.
    assert_eq!(leaf(&leaves, "GPSLatitude").value_n, TagValue::F64(0.0));
    // Exactly the two records were decoded — the short one consumed exactly its
    // declared 1 byte (a fabricated cross-boundary read would shift the walk and
    // change the leaf set).
    assert_eq!(leaves.len(), 2, "leaves: {:?}", names(&leaves));
  }

  /// The same bound on a `Raw` numeric (no ValueConv): a `Checksum` (int16u)
  /// with `len=1` must yield ExifTool's empty-string `ReadValue` result (`''`),
  /// not an `int16u` read that pulls the high byte from the next tag.
  #[test]
  fn short_raw_numeric_tag_yields_empty_not_over_read() {
    // [tag 1 Checksum int16u][BER len 1][0x7f]  [tag 65 = 11]
    let mut inner = vec![1, 0x01, 0x7f];
    inner.extend_from_slice(&uas_ls_version_record());
    let leaves = decode_uas_local_set(&inner);
    assert_eq!(
      leaf(&leaves, "UAS_LSVersionNumber").value_n,
      TagValue::I64(11)
    );
    // `ReadValue(.., undef, 1)` over a 2-byte format ⇒ `''` (ExifTool `-n`
    // Checksum `[]`), in BOTH modes (no ValueConv/PrintConv).
    let chk = leaf(&leaves, "Checksum");
    assert_eq!(chk.value_n, TagValue::Str("".into()));
    assert_eq!(chk.value_print, TagValue::Str("".into()));
    assert_eq!(leaves.len(), 2, "leaves: {:?}", names(&leaves));
  }

  /// A `Hex4` numeric (separate raw + `sprintf("0x%.4x")` print): a `WeaponLoad`
  /// (int16u) with `len=1` must print `0x0000` (ExifTool) and carry the
  /// empty-string raw — without over-reading the following record.
  #[test]
  fn short_hex4_tag_prints_zero_and_does_not_over_read() {
    // [tag 60 WeaponLoad int16u][BER len 1][0x05]  [tag 65 = 11]
    let mut inner = vec![60, 0x01, 0x05];
    inner.extend_from_slice(&uas_ls_version_record());
    let leaves = decode_uas_local_set(&inner);
    assert_eq!(
      leaf(&leaves, "UAS_LSVersionNumber").value_n,
      TagValue::I64(11)
    );
    let wl = leaf(&leaves, "WeaponLoad");
    // ExifTool: `sprintf("0x%.4x", '')` ⇒ `0x0000`; raw `-n` ⇒ `''`.
    assert_eq!(wl.value_print, TagValue::Str("0x0000".into()));
    assert_eq!(wl.value_n, TagValue::Str("".into()));
    assert_eq!(leaves.len(), 2, "leaves: {:?}", names(&leaves));
  }

  /// A string-valued tag is likewise bounded to its declared length and never
  /// reads into the next record. A `TailNumber` (string) with `len=2` over a
  /// 4-byte payload must decode EXACTLY its 2 bytes, leaving the trailing
  /// `UAS_LSVersionNumber` record intact.
  #[test]
  fn short_string_tag_is_length_bounded() {
    // [tag 4 TailNumber string][BER len 2]["AB"]  [tag 65 = 11]
    let mut inner = vec![4, 0x02, b'A', b'B'];
    inner.extend_from_slice(&uas_ls_version_record());
    let leaves = decode_uas_local_set(&inner);
    assert_eq!(
      leaf(&leaves, "UAS_LSVersionNumber").value_n,
      TagValue::I64(11)
    );
    // Exactly the two declared bytes — NOT "AB" plus the next record's tag byte.
    assert_eq!(
      leaf(&leaves, "TailNumber").value_n,
      TagValue::Str("AB".into())
    );
    assert_eq!(leaves.len(), 2, "leaves: {:?}", names(&leaves));
  }

  /// Wrap a Security local-set `inner` body in the UAS `SecurityLocalMetadataSet`
  /// container (UAS tag 48 `Conv::Sub(Table::Security)`) and decode it: the only
  /// route to the Security table in `process_klv` is through that SubDirectory.
  fn decode_security_local_set(inner: &[u8]) -> Vec<MisbLeaf> {
    // [tag 48][BER len = inner.len()][inner Security local set]
    let mut uas = vec![48, u8::try_from(inner.len()).expect("inner fits BER")];
    uas.extend_from_slice(inner);
    decode_uas_local_set(&uas)
  }

  /// A `SecVersion` string-interpolation `PrintConv` (`"0102.$val"`) over a
  /// too-short `int16u` (Security tag 22, declared `len=1`) must yield `"0102."`
  /// — the EMPTY `$val` (ExifTool `ReadValue` returns `''` for a `len < fmt`
  /// read), NOT `"0102.0"`. The #130 short-value class: the empty→0 numeric
  /// coercion is correct for ARITHMETIC convs but WRONG for a scalar-PrintConv
  /// string interpolation, which must derive from the raw scalar. The record is
  /// followed by a valid `SecurityVersion=11` to also prove no cross-boundary
  /// over-read of the second record.
  #[test]
  fn short_sec_version_interpolates_empty_not_zero() {
    // [tag 22 SecurityVersion int16u][BER len 1][0x05]  [tag 22][BER len 2][=11]
    let mut inner = vec![22, 0x01, 0x05];
    inner.extend_from_slice(&[22, 0x02, 0x00, 0x0b]); // a valid SecurityVersion=11
    let leaves = decode_security_local_set(&inner);
    let versions: Vec<&MisbLeaf> = leaves
      .iter()
      .filter(|l| l.name.as_str() == "SecurityVersion")
      .collect();
    assert_eq!(versions.len(), 2, "leaves: {:?}", names(&leaves));
    // First (short, len=1): `"0102.$val"` with empty `$val` ⇒ `"0102."` (NOT
    // `"0102.0"`); the raw `-n` value is the empty-string `ReadValue` result.
    let short = versions.first().expect("first SecurityVersion");
    assert_eq!(short.value_print, TagValue::Str("0102.".into()));
    assert_eq!(short.value_n, TagValue::Str("".into()));
    // Second (valid, len=2 = 11): still decodes from its OWN bytes ⇒ `"0102.11"`.
    let valid = versions.get(1).expect("second SecurityVersion");
    assert_eq!(valid.value_print, TagValue::Str("0102.11".into()));
    assert_eq!(valid.value_n, TagValue::I64(11));
  }

  /// A zero-length `Hash` tag whose table DEFINES key `0` (`IcingDetected`,
  /// int8u, `{ 0 => 'n/a', 1 => 'No', 2 => 'Yes' }`) must NOT fabricate the
  /// key-0 `"n/a"` label: ExifTool's `ReadValue(.., undef, 0)` is the empty
  /// string `''`, and the hash lookup `$h{''}` MISSES ⇒ `$val` is returned
  /// unchanged (empty). The empty→0 numeric coercion (correct for arithmetic
  /// convs) must NOT apply to this string-keyed PrintConv lookup.
  #[test]
  fn zero_length_hash_tag_does_not_fabricate_key_zero_label() {
    // [tag 34 IcingDetected int8u][BER len 0]  [tag 65 = 11]
    let mut inner = vec![34, 0x00];
    inner.extend_from_slice(&uas_ls_version_record());
    let leaves = decode_uas_local_set(&inner);
    let icing = leaf(&leaves, "IcingDetected");
    // Hash MISS on the empty `''` key ⇒ raw value unchanged, NOT the key-0 label.
    assert_eq!(icing.value_print, TagValue::Str("".into()));
    assert_eq!(icing.value_n, TagValue::Str("".into()));
    // The following record decodes from its own bytes (no boundary corruption).
    assert_eq!(
      leaf(&leaves, "UAS_LSVersionNumber").value_n,
      TagValue::I64(11)
    );
    assert_eq!(leaves.len(), 2, "leaves: {:?}", names(&leaves));
  }

  /// The valid `Hash` lens is unaffected: a full-width `IcingDetected = 2`
  /// resolves the table label `"Yes"` (`-j`) and the raw int (`-n`). Guards the
  /// scalar-key derivation against breaking the happy path.
  #[test]
  fn valid_hash_tag_resolves_label() {
    // [tag 34 IcingDetected int8u][BER len 1][value 2]
    let inner = vec![34, 0x01, 0x02];
    let leaves = decode_uas_local_set(&inner);
    let icing = leaf(&leaves, "IcingDetected");
    assert_eq!(icing.value_print, TagValue::Str("Yes".into()));
    assert_eq!(icing.value_n, TagValue::I64(2));
  }
}
