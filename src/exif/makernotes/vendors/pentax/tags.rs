// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Pentax::Main` IFD tag table (`Pentax.pm:859-3171`) —
//! the Phase-1 CAMERA-INDEXING subset.
//!
//! Phase 1 ports the cleanly-portable plain LEAF tags (scalar / enum-hash /
//! simple-ValueConv) that the K10D `Pentax.jpg` fixture emits, PLUS the
//! `0x003f LensRec` SubDirectory (the only sub-table needed for `LensType`).
//! Deferred to a follow-up (excluded from the conformance golden via `-x`):
//! the model-/`$count`-/`$format`-CONDITIONAL leaves (FocusMode 0x000d,
//! AFPointSelected 0x000e, AFPointsInFocus 0x000f/0x003c, ExposureCompensation
//! 0x0016, FocalLength 0x001d, EffectiveLV 0x002d, PictureMode 0x000b/0x0033,
//! RawDevelopmentProcess 0x0062), the multi-element-array PrintConvs
//! (FlashMode 0x000c, AutoBracketing 0x0018, DriveMode 0x0034), the encrypted
//! ShutterCount (0x005d), the `IsOffset => 2` preview pointer PreviewImageStart
//! (0x0004, needs the offset-rebasing subsystem), and ALL the binary SubDirectory
//! tables
//! (CameraSettings 0x0205, AEInfo 0x0206, LensInfo 0x0207, FlashInfo 0x0208,
//! CameraInfo 0x0215, BatteryInfo 0x0216, AFInfo 0x021f, WBLevels 0x022d,
//! ShakeReductionInfo 0x005c, PrintIM 0x0e00, …).

#![deny(clippy::indexing_slicing)]

use super::printconv::PentaxPrintConv;
use crate::exif::ifd::Format;
use crate::exif::makernotes::vendors::FormatOverride;

/// One ported `%Pentax::Main` tag.
#[derive(Debug, Clone, Copy)]
pub struct PentaxTag {
  /// Tag ID (`Pentax.pm` Main hash key).
  pub id: u16,
  /// `Name => '…'`.
  pub name: &'static str,
  /// PrintConv / ValueConv strategy.
  pub conv: PentaxPrintConv,
  /// `Some(SubTable::…)` for a SubDirectory pointer (Phase 1: only
  /// [`SubTable::LensRec`]).
  pub sub_table: Option<SubTable>,
  /// `Unknown => 1` in bundled (suppressed from default output). No ported
  /// Phase-1 leaf is `Unknown`, but the field mirrors the other vendors.
  pub unknown: bool,
  /// `Some(FormatOverride)` for a `Format => '…'` directive that re-reads the
  /// on-disk bytes with a different format; `None` ⇒ on-disk format.
  pub format: Option<FormatOverride>,
}

impl PentaxTag {
  /// The resolved tag name.
  #[must_use]
  #[inline(always)]
  pub const fn name(&self) -> &'static str {
    self.name
  }

  /// `true` when bundled marks the tag `Unknown => 1`.
  #[must_use]
  #[inline(always)]
  pub const fn is_unknown(&self) -> bool {
    self.unknown
  }

  /// The tag's optional `Format =>` directive.
  #[must_use]
  #[inline(always)]
  pub const fn format_override(&self) -> Option<FormatOverride> {
    self.format
  }

  /// The tag's [`SubTable`] pointer, if it is a SubDirectory row. `None` for a
  /// plain leaf. The shared `Walker`'s Pentax capture loop descends a
  /// `Some(SubTable::…)` entry (`LensRec` → the `LensType` leaf) and emits NO
  /// parent value, mirroring the Nikon/Sony SubDirectory handling.
  #[must_use]
  #[inline(always)]
  pub const fn sub_table(&self) -> Option<SubTable> {
    self.sub_table
  }
}

/// Pentax Main SubDirectory targets ported in Phase 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubTable {
  /// `%Pentax::LensRec` at `0x003f` (`Pentax.pm:4192`) — a `ProcessBinaryData`
  /// record whose position-0 `LensType` is an `int8u[2]` `(series, model)`
  /// pair resolved against `%pentaxLensTypes`. Phase 1 reads ONLY that field
  /// (the LensType leaf); the trailing `ExtenderStatus` byte is deferred.
  LensRec,
}

/// The ported `%Pentax::Main` rows — sorted by `id` for binary search.
pub const PENTAX_TAGS: &[PentaxTag] = &[
  PentaxTag {
    id: 0x0000,
    name: "PentaxVersion",
    conv: PentaxPrintConv::Version,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0001,
    name: "PentaxModelType",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0002,
    name: "PreviewImageSize",
    conv: PentaxPrintConv::PreviewImageSize,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0003,
    name: "PreviewImageLength",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0005,
    name: "PentaxModelID",
    conv: PentaxPrintConv::ModelId,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0006,
    name: "Date",
    conv: PentaxPrintConv::Date,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0007,
    name: "Time",
    conv: PentaxPrintConv::Time,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0008,
    name: "Quality",
    conv: PentaxPrintConv::Hash(QUALITY),
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0012,
    name: "ExposureTime",
    conv: PentaxPrintConv::ExposureTime,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0013,
    name: "FNumber",
    conv: PentaxPrintConv::FNumber,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0014,
    name: "ISO",
    conv: PentaxPrintConv::Hash(ISO),
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0017,
    name: "MeteringMode",
    conv: PentaxPrintConv::Hash(METERING_MODE),
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0019,
    name: "WhiteBalance",
    conv: PentaxPrintConv::Hash(WHITE_BALANCE),
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x001a,
    name: "WhiteBalanceMode",
    conv: PentaxPrintConv::Hash(WHITE_BALANCE_MODE),
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x001f,
    name: "Saturation",
    conv: PentaxPrintConv::Hash(SATURATION),
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0020,
    name: "Contrast",
    conv: PentaxPrintConv::Hash(CONTRAST),
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0021,
    name: "Sharpness",
    conv: PentaxPrintConv::Hash(SHARPNESS),
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0022,
    name: "WorldTimeLocation",
    conv: PentaxPrintConv::Hash(WORLD_TIME_LOCATION),
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0023,
    name: "HometownCity",
    conv: PentaxPrintConv::City,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0024,
    name: "DestinationCity",
    conv: PentaxPrintConv::City,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0025,
    name: "HometownDST",
    conv: PentaxPrintConv::Hash(DST),
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0026,
    name: "DestinationDST",
    conv: PentaxPrintConv::Hash(DST),
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0027,
    name: "DSPFirmwareVersion",
    conv: PentaxPrintConv::FirmwareId,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0028,
    name: "CPUFirmwareVersion",
    conv: PentaxPrintConv::FirmwareId,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0037,
    name: "ColorSpace",
    conv: PentaxPrintConv::Hash(COLOR_SPACE),
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x003d,
    name: "DataScaling",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x003e,
    name: "PreviewImageBorders",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x003f,
    name: "LensRec",
    conv: PentaxPrintConv::None,
    sub_table: Some(SubTable::LensRec),
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0040,
    name: "SensitivityAdjust",
    conv: PentaxPrintConv::SensitivityAdjust,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0041,
    name: "ImageEditCount",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0047,
    name: "CameraTemperature",
    conv: PentaxPrintConv::CameraTemperature,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0048,
    name: "AELock",
    conv: PentaxPrintConv::Hash(AE_LOCK),
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0049,
    name: "NoiseReduction",
    conv: PentaxPrintConv::Hash(NOISE_REDUCTION),
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x004f,
    name: "ImageTone",
    conv: PentaxPrintConv::Hash(IMAGE_TONE),
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0200,
    name: "BlackPoint",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0201,
    name: "WhitePoint",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0209,
    name: "AEMeteringSegments",
    conv: PentaxPrintConv::MeteringSegments,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x020a,
    name: "FlashMeteringSegments",
    conv: PentaxPrintConv::MeteringSegments,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x020b,
    name: "SlaveFlashMeteringSegments",
    conv: PentaxPrintConv::MeteringSegments,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x020d,
    name: "WB_RGGBLevelsDaylight",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x020e,
    name: "WB_RGGBLevelsShade",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x020f,
    name: "WB_RGGBLevelsCloudy",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0210,
    name: "WB_RGGBLevelsTungsten",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0211,
    name: "WB_RGGBLevelsFluorescentD",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0212,
    name: "WB_RGGBLevelsFluorescentN",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0213,
    name: "WB_RGGBLevelsFluorescentW",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0214,
    name: "WB_RGGBLevelsFlash",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
];

/// Look up a `%Pentax::Main` tag by ID. Returns `None` for an unported /
/// unknown tag (the caller then skips it, matching `ProcessExif`'s
/// `next unless $tagInfo` for an unknown ID in the default output).
#[must_use]
pub fn lookup(id: u16) -> Option<&'static PentaxTag> {
  match PENTAX_TAGS.binary_search_by_key(&id, |t| t.id) {
    Ok(i) => PENTAX_TAGS.get(i),
    Err(_) => None,
  }
}

/// The `Format =>` directive's FORMAT for tag `id` under `%Pentax::Main`, if
/// any — the per-table override the shared `Walker` resolves when
/// `active_table == Pentax`. `None` for an unknown tag or one with no
/// directive.
#[must_use]
pub fn format_override(id: u16) -> Option<Format> {
  let tag = lookup(id)?;
  if let Some(over) = tag.format_override() {
    // An EXPLICIT `Format => '…'` directive (none ported in Phase 1, but the
    // path mirrors Sony/Panasonic).
    return Some(over.format());
  }
  // The IMPLICIT-`undef` SubDirectory override (`Exif.pm:6733`): a SubDirectory
  // tag with no explicit `Format` reads as `undef`, so the WHOLE binary block
  // (`%Pentax::LensRec`) reaches the child + is exempt from the excessive-count
  // guard (`undef` is an exemption). Mirrors `nikon::format_override` — without
  // it the LensRec value span never materializes and `LensType` cannot emit.
  if tag.sub_table.is_some() {
    return Some(Format::Undef);
  }
  None
}

/// `true` when tag `id` is an IMPLICIT-`undef` SubDirectory under `%Pentax::Main`
/// — a SubDirectory row with no explicit `Format` (so [`format_override`] reads
/// it as `undef[N]`, the whole binary block). Its decoded leaf value is DEAD: the
/// Pentax capture loop dispatches it by re-slicing the on-disk SPAN
/// (`value_offset`/`value_size`) from the buffer, never the `ExifEntry`'s value.
/// So the shared `Walker` stores an EMPTY `RawValue::Bytes` for it instead of
/// `read_value`-cloning the (possibly crafted-huge, in-bounds) block — closing the
/// `N * value_size` heap amplification a crafted MakerNote with the SubDirectory
/// repeated across many entries would otherwise force. Mirrors
/// [`nikon::is_implicit_undef_subdir`](super::super::nikon::is_implicit_undef_subdir);
/// Phase 1 matches ONLY `0x003f LensRec` (the sole SubDirectory row).
#[must_use]
pub fn is_implicit_undef_subdir(id: u16) -> bool {
  lookup(id).is_some_and(|tag| tag.format_override().is_none() && tag.sub_table().is_some())
}

/// `QUALITY` PrintConv hash — sorted by key for binary search.
pub const QUALITY: &[(i64, &str)] = &[
  (0, "Good"),
  (1, "Better"),
  (2, "Best"),
  (3, "TIFF"),
  (4, "RAW"),
  (5, "Premium"),
  (7, "RAW (pixel shift enabled)"),
  (8, "Dynamic Pixel Shift"),
  (9, "Monochrome"),
  (65535, "n/a"),
];

/// `METERING_MODE` PrintConv hash — sorted by key for binary search.
pub const METERING_MODE: &[(i64, &str)] = &[
  (0, "Multi-segment"),
  (1, "Center-weighted average"),
  (2, "Spot"),
  (6, "Highlight"),
];

/// `WHITE_BALANCE` PrintConv hash — sorted by key for binary search.
pub const WHITE_BALANCE: &[(i64, &str)] = &[
  (0, "Auto"),
  (1, "Daylight"),
  (2, "Shade"),
  (3, "Fluorescent"),
  (4, "Tungsten"),
  (5, "Manual"),
  (6, "Daylight Fluorescent"),
  (7, "Day White Fluorescent"),
  (8, "White Fluorescent"),
  (9, "Flash"),
  (10, "Cloudy"),
  (11, "Warm White Fluorescent"),
  (14, "Multi Auto"),
  (15, "Color Temperature Enhancement"),
  (17, "Kelvin"),
  (65534, "Unknown"),
  (65535, "User-Selected"),
];

/// `WHITE_BALANCE_MODE` PrintConv hash — sorted by key for binary search.
pub const WHITE_BALANCE_MODE: &[(i64, &str)] = &[
  (1, "Auto (Daylight)"),
  (2, "Auto (Shade)"),
  (3, "Auto (Flash)"),
  (4, "Auto (Tungsten)"),
  (6, "Auto (Daylight Fluorescent)"),
  (7, "Auto (Day White Fluorescent)"),
  (8, "Auto (White Fluorescent)"),
  (10, "Auto (Cloudy)"),
  (65534, "Unknown"),
  (65535, "User-Selected"),
];

/// `WORLD_TIME_LOCATION` PrintConv hash — sorted by key for binary search.
pub const WORLD_TIME_LOCATION: &[(i64, &str)] = &[(0, "Hometown"), (1, "Destination")];

/// `DST` PrintConv hash — sorted by key for binary search.
pub const DST: &[(i64, &str)] = &[(0, "No"), (1, "Yes")];

/// `COLOR_SPACE` PrintConv hash — sorted by key for binary search.
pub const COLOR_SPACE: &[(i64, &str)] = &[(0, "sRGB"), (1, "Adobe RGB")];

/// `AE_LOCK` PrintConv hash — sorted by key for binary search.
pub const AE_LOCK: &[(i64, &str)] = &[(0, "Off"), (1, "On")];

/// `NOISE_REDUCTION` PrintConv hash — sorted by key for binary search.
pub const NOISE_REDUCTION: &[(i64, &str)] = &[(0, "Off"), (1, "On")];

/// `IMAGE_TONE` PrintConv hash — sorted by key for binary search.
pub const IMAGE_TONE: &[(i64, &str)] = &[
  (0, "Natural"),
  (1, "Bright"),
  (2, "Portrait"),
  (3, "Landscape"),
  (4, "Vibrant"),
  (5, "Monochrome"),
  (6, "Muted"),
  (7, "Reversal Film"),
  (8, "Bleach Bypass"),
  (9, "Radiant"),
  (10, "Cross Processing"),
  (11, "Flat"),
  (256, "Standard"),
  (257, "Vivid"),
  (258, "Monotone"),
  (259, "Soft Monotone"),
  (260, "Hard Monotone"),
  (261, "Hi-contrast B&W"),
  (262, "Positive Film"),
  (263, "Bleach Bypass 2"),
  (264, "Retro"),
  (265, "HDR Tone"),
  (266, "Cross Processing 2"),
  (267, "Negative Film"),
  (32768, "Standard"),
  (32769, "Hard"),
  (32770, "Soft"),
  (33024, "Monochrome"),
];

/// `SATURATION` PrintConv hash — sorted by key for binary search.
pub const SATURATION: &[(i64, &str)] = &[
  (0, "-2 (low)"),
  (1, "0 (normal)"),
  (2, "+2 (high)"),
  (3, "-1 (medium low)"),
  (4, "+1 (medium high)"),
  (5, "-3 (very low)"),
  (6, "+3 (very high)"),
  (7, "-4 (minimum)"),
  (8, "+4 (maximum)"),
  (65535, "None"),
];

/// `CONTRAST` PrintConv hash — sorted by key for binary search.
pub const CONTRAST: &[(i64, &str)] = &[
  (0, "-2 (low)"),
  (1, "0 (normal)"),
  (2, "+2 (high)"),
  (3, "-1 (medium low)"),
  (4, "+1 (medium high)"),
  (5, "-3 (very low)"),
  (6, "+3 (very high)"),
  (7, "-4 (minimum)"),
  (8, "+4 (maximum)"),
  (65535, "n/a"),
];

/// `SHARPNESS` PrintConv hash — sorted by key for binary search.
pub const SHARPNESS: &[(i64, &str)] = &[
  (0, "-2 (soft)"),
  (1, "0 (normal)"),
  (2, "+2 (hard)"),
  (3, "-1 (medium soft)"),
  (4, "+1 (medium hard)"),
  (5, "-3 (very soft)"),
  (6, "+3 (very hard)"),
  (7, "-4 (minimum)"),
  (8, "+4 (maximum)"),
];

/// `ISO` PrintConv hash — sorted by key for binary search.
pub const ISO: &[(i64, &str)] = &[
  (3, "50"),
  (4, "64"),
  (5, "80"),
  (6, "100"),
  (7, "125"),
  (8, "160"),
  (9, "200"),
  (10, "250"),
  (11, "320"),
  (12, "400"),
  (13, "500"),
  (14, "640"),
  (15, "800"),
  (16, "1000"),
  (17, "1250"),
  (18, "1600"),
  (19, "2000"),
  (20, "2500"),
  (21, "3200"),
  (22, "4000"),
  (23, "5000"),
  (24, "6400"),
  (25, "8000"),
  (26, "10000"),
  (27, "12800"),
  (28, "16000"),
  (29, "20000"),
  (30, "25600"),
  (31, "32000"),
  (32, "40000"),
  (33, "51200"),
  (34, "64000"),
  (35, "80000"),
  (36, "102400"),
  (37, "128000"),
  (38, "160000"),
  (39, "204800"),
  (40, "256000"),
  (41, "320000"),
  (42, "409600"),
  (43, "512000"),
  (44, "640000"),
  (45, "819200"),
  (50, "50"),
  (100, "100"),
  (200, "200"),
  (258, "50"),
  (259, "70"),
  (260, "100"),
  (261, "140"),
  (262, "200"),
  (263, "280"),
  (264, "400"),
  (265, "560"),
  (266, "800"),
  (267, "1100"),
  (268, "1600"),
  (269, "2200"),
  (270, "3200"),
  (271, "4500"),
  (272, "6400"),
  (273, "9000"),
  (274, "12800"),
  (275, "18000"),
  (276, "25600"),
  (277, "36000"),
  (278, "51200"),
  (279, "72000"),
  (280, "102400"),
  (281, "144000"),
  (282, "204800"),
  (283, "288000"),
  (284, "409600"),
  (285, "576000"),
  (286, "819200"),
  (400, "400"),
  (800, "800"),
  (1600, "1600"),
  (3200, "3200"),
  (65534, "Auto 2"),
  (65535, "Auto"),
];

#[cfg(test)]
mod tests;
