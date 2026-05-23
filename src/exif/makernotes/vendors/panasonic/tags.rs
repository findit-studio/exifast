// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Panasonic::Main` IFD tag table (`Panasonic.pm:265-1601`).
//!
//! Faithful 1:1 port against bundled ExifTool 13.59. Every numeric key of
//! the Main hash gets exactly one row here. The bundled `%Panasonic::Main`
//! has **136 numeric tag IDs** (the loaded-module key count — the higher
//! "≈161" figure counts the `0x..` lines in the source TEXT, which also
//! includes commented-out entries like `# 0x22 …`, `#0x8007 …`, and the
//! `0x00 => 'Normal'` PrintConv sub-keys inside the ContrastMode hash).
//!
//! - LEAF tags: each carries its `name`, `unknown` flag (only 0x63
//!   `RecognizedFaceFlags` is `Unknown => 1`, `Panasonic.pm:1025`), and a
//!   [`PanasonicPrintConv`] strategy.
//! - SubDirectory pointers (`FaceDetInfo` 0x4e, `FaceRecInfo` 0x61,
//!   `PrintIM` 0x0e00, `TimeInfo` 0x2003) are recorded as [`SubTable`]
//!   so the dispatcher can surface the raw blob; the dedicated walkers are
//!   deferred follow-ups (see the deferral issues linked from #62). They
//!   are the ONLY four SubDirectory entries in the Main hash.
//! - Conditional ARRAY rows (`0x0f` AFAreaMode FZ10 vs other; `0x2c`
//!   ContrastMode 4-way per-model) collapse to the bundled NON-model-gated
//!   ("other models" / final) branch, exactly as the Apple/Canon ports do
//!   for their conditional tags — the per-body decoding is deferred. The
//!   primary `Name` is identical across all branches in both cases.
//!
//! The `Format` directive in bundled (e.g. `Format => 'int16s'` on tags whose
//! `Writable` is `undef`/`int16u`) RE-INTERPRETS the on-disk value bytes
//! (`Exif.pm:6728-6745`). This port carries the directive on the [`format`]
//! [override field](PanasonicTag::format) and the walker
//! ([`body`](super::body)) applies it when the on-disk format differs — so a
//! `Writable => 'int16u'` / `Format => 'int16s'` row is read SIGNED (0x23
//! WhiteBalanceBias `ff fd` ⇒ -3 ⇒ ValueConv -1, not 65533), and the
//! signed-pair rows (Transform/HighlightShadow) and the int32u-from-rational
//! rows (FilterEffect/PostFocusMerging) read their faithful value SHAPE. Only
//! the FilterEffect/PostFocusMerging PrintConv HASH (keyed on the re-formatted
//! pair) remains deferred — the value read itself is faithful and pinned by
//! `tests/panasonic_main_format.rs`.

use super::printconv::PanasonicPrintConv;
use crate::exif::ifd::Format;
use crate::exif::makernotes::vendors::FormatOverride;

/// One Panasonic Main IFD tag.
#[derive(Debug, Clone, Copy)]
pub struct PanasonicTag {
  /// Tag ID (`Panasonic.pm` Main hash key).
  pub id: u16,
  /// `Name => '…'` from bundled.
  pub name: &'static str,
  /// PrintConv strategy.
  pub conv: PanasonicPrintConv,
  /// `Some(SubTable::…)` when the tag is a SubDirectory pointer.
  pub sub_table: Option<SubTable>,
  /// `Unknown => 1` in bundled (`ExifTool.pm:9179-9185` suppresses such
  /// tags from default output). Only 0x63 `RecognizedFaceFlags` sets this.
  pub unknown: bool,
  /// `Some(FormatOverride)` when bundled carries a `Format => '…'` directive
  /// that RE-INTERPRETS the entry's on-disk value bytes with a different
  /// format (`Exif.pm:6728-6745`); `None` ⇒ read with the on-disk format.
  /// Many `%Panasonic::Main` rows are `Writable => 'int16u'` but `Format =>
  /// 'int16s'` (so the on-disk unsigned bytes are read SIGNED — e.g. 0x23
  /// WhiteBalanceBias `ff fd` ⇒ -1, not 65533); pinned by
  /// `tests/panasonic_main_format.rs`. See [`FormatOverride`] for the
  /// read-count rule.
  pub format: Option<FormatOverride>,
}

impl PanasonicTag {
  /// `true` when bundled marks this tag `Unknown => 1` — suppressed in the
  /// default (`-j`, no `-u`) output (`ExifTool.pm:9179-9185`). Mirrors the
  /// Apple/Canon `is_unknown()` accessor.
  #[must_use]
  #[inline(always)]
  pub const fn is_unknown(&self) -> bool {
    self.unknown
  }
}

/// Panasonic Main SubDirectory targets. The Main hash has exactly four
/// SubDirectory entries; Phase 3 doesn't walk any of them natively (the
/// camera-indexing data is all in the LEAF tags), so each SubDirectory
/// blob is surfaced as a raw value (presence + size) and the dedicated
/// walker is deferred per follow-up issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubTable {
  /// `%Panasonic::FaceDetInfo` at 0x4e (`Panasonic.pm:936-942`). Deferred.
  FaceDetInfo,
  /// `%Panasonic::FaceRecInfo` at 0x61 (`Panasonic.pm:1007-1012`). Deferred.
  FaceRecInfo,
  /// `%Panasonic::TimeInfo` at 0x2003 (`Panasonic.pm:1524-1527`). Deferred.
  TimeInfo,
  /// `PrintIM::Main` at 0x0e00 (`Panasonic.pm:1518-1523`) — handled by a
  /// separate module. Surfaced raw.
  PrintIm,
}

/// `%Panasonic::Main` (`Panasonic.pm:265-1601`). Sorted by tag ID.
///
/// 136 rows — one per numeric key of the bundled hash.
pub const PANASONIC_TAGS: &[PanasonicTag] = &[
  // 0x01 ImageQuality (Panasonic.pm:270-285)
  PanasonicTag {
    id: 0x01,
    name: "ImageQuality",
    conv: PanasonicPrintConv::ImageQuality,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x02 FirmwareVersion (Panasonic.pm:286-302)
  PanasonicTag {
    id: 0x02,
    name: "FirmwareVersion",
    conv: PanasonicPrintConv::FirmwareVersion,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x03 WhiteBalance (Panasonic.pm:303-322)
  PanasonicTag {
    id: 0x03,
    name: "WhiteBalance",
    conv: PanasonicPrintConv::WhiteBalance,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x07 FocusMode (Panasonic.pm:323-335)
  PanasonicTag {
    id: 0x07,
    name: "FocusMode",
    conv: PanasonicPrintConv::FocusMode,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x0f AFAreaMode (Panasonic.pm:336-382) — conditional ARRAY; collapse to
  // the "other models" branch (the FZ10 branch differs only in PrintConv).
  PanasonicTag {
    id: 0x0f,
    name: "AFAreaMode",
    conv: PanasonicPrintConv::AfAreaMode,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x1a ImageStabilization (Panasonic.pm:383-399)
  PanasonicTag {
    id: 0x1a,
    name: "ImageStabilization",
    conv: PanasonicPrintConv::ImageStabilization,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x1c MacroMode (Panasonic.pm:400-409)
  PanasonicTag {
    id: 0x1c,
    name: "MacroMode",
    conv: PanasonicPrintConv::MacroMode,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x1f ShootingMode (Panasonic.pm:410-415) — %shootingMode
  PanasonicTag {
    id: 0x1f,
    name: "ShootingMode",
    conv: PanasonicPrintConv::ShootingMode,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x20 Audio (Panasonic.pm:416-424)
  PanasonicTag {
    id: 0x20,
    name: "Audio",
    conv: PanasonicPrintConv::Audio,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x21 DataDump (Panasonic.pm:425-429) — Binary, kept raw.
  PanasonicTag {
    id: 0x21,
    name: "DataDump",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x23 WhiteBalanceBias (Panasonic.pm:431-439)
  PanasonicTag {
    id: 0x23,
    name: "WhiteBalanceBias",
    conv: PanasonicPrintConv::WhiteBalanceBias,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16s, None)),
  },
  // 0x24 FlashBias (Panasonic.pm:440-448)
  PanasonicTag {
    id: 0x24,
    name: "FlashBias",
    conv: PanasonicPrintConv::FlashBias,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16s, None)),
  },
  // 0x25 InternalSerialNumber (Panasonic.pm:449-463)
  PanasonicTag {
    id: 0x25,
    name: "InternalSerialNumber",
    conv: PanasonicPrintConv::InternalSerialNumber,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x26 PanasonicExifVersion (Panasonic.pm:464-467)
  PanasonicTag {
    id: 0x26,
    name: "PanasonicExifVersion",
    conv: PanasonicPrintConv::PanasonicExifVersion,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x27 VideoFrameRate (Panasonic.pm:468-476)
  PanasonicTag {
    id: 0x27,
    name: "VideoFrameRate",
    conv: PanasonicPrintConv::VideoFrameRate,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x28 ColorEffect (Panasonic.pm:477-490)
  PanasonicTag {
    id: 0x28,
    name: "ColorEffect",
    conv: PanasonicPrintConv::ColorEffect,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x29 TimeSincePowerOn (Panasonic.pm:491-528)
  PanasonicTag {
    id: 0x29,
    name: "TimeSincePowerOn",
    conv: PanasonicPrintConv::TimeSincePowerOn,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2a BurstMode (Panasonic.pm:530-544)
  PanasonicTag {
    id: 0x2a,
    name: "BurstMode",
    conv: PanasonicPrintConv::BurstMode,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2b SequenceNumber (Panasonic.pm:545-548) — int32u passthrough.
  PanasonicTag {
    id: 0x2b,
    name: "SequenceNumber",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2c ContrastMode (Panasonic.pm:549-660) — conditional ARRAY; collapse
  // to the first (PrintHex, non-DC/non-GF) branch.
  PanasonicTag {
    id: 0x2c,
    name: "ContrastMode",
    conv: PanasonicPrintConv::ContrastMode,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2d NoiseReduction (Panasonic.pm:661-679)
  PanasonicTag {
    id: 0x2d,
    name: "NoiseReduction",
    conv: PanasonicPrintConv::NoiseReduction,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x2e SelfTimer (Panasonic.pm:680-694)
  PanasonicTag {
    id: 0x2e,
    name: "SelfTimer",
    conv: PanasonicPrintConv::SelfTimer,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x30 Rotation (Panasonic.pm:695-704)
  PanasonicTag {
    id: 0x30,
    name: "Rotation",
    conv: PanasonicPrintConv::Rotation,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x31 AFAssistLamp (Panasonic.pm:705-716)
  PanasonicTag {
    id: 0x31,
    name: "AFAssistLamp",
    conv: PanasonicPrintConv::AfAssistLamp,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x32 ColorMode (Panasonic.pm:717-726)
  PanasonicTag {
    id: 0x32,
    name: "ColorMode",
    conv: PanasonicPrintConv::ColorMode,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x33 BabyAge (Panasonic.pm:727-733) — "9999:99:99 00:00:00" => "(not set)".
  PanasonicTag {
    id: 0x33,
    name: "BabyAge",
    conv: PanasonicPrintConv::BabyAge,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x34 OpticalZoomMode (Panasonic.pm:734-741)
  PanasonicTag {
    id: 0x34,
    name: "OpticalZoomMode",
    conv: PanasonicPrintConv::OpticalZoomMode,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x35 ConversionLens (Panasonic.pm:742-751)
  PanasonicTag {
    id: 0x35,
    name: "ConversionLens",
    conv: PanasonicPrintConv::ConversionLens,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x36 TravelDay (Panasonic.pm:752-757)
  PanasonicTag {
    id: 0x36,
    name: "TravelDay",
    conv: PanasonicPrintConv::TravelDay,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x38 BatteryLevel (Panasonic.pm:760-772)
  PanasonicTag {
    id: 0x38,
    name: "BatteryLevel",
    conv: PanasonicPrintConv::BatteryLevel,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x39 Contrast (Panasonic.pm:773-778) — Exif::printParameter.
  PanasonicTag {
    id: 0x39,
    name: "Contrast",
    conv: PanasonicPrintConv::PrintParameter,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16s, None)),
  },
  // 0x3a WorldTimeLocation (Panasonic.pm:779-786)
  PanasonicTag {
    id: 0x3a,
    name: "WorldTimeLocation",
    conv: PanasonicPrintConv::WorldTimeLocation,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x3b TextStamp (Panasonic.pm:787-792)
  PanasonicTag {
    id: 0x3b,
    name: "TextStamp",
    conv: PanasonicPrintConv::TextStamp,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x3c ProgramISO (Panasonic.pm:793-802)
  PanasonicTag {
    id: 0x3c,
    name: "ProgramISO",
    conv: PanasonicPrintConv::ProgramIso,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x3d AdvancedSceneType (Panasonic.pm:803-808) — int16u passthrough.
  PanasonicTag {
    id: 0x3d,
    name: "AdvancedSceneType",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x3e TextStamp (Panasonic.pm:809-814)
  PanasonicTag {
    id: 0x3e,
    name: "TextStamp",
    conv: PanasonicPrintConv::TextStamp,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x3f FacesDetected (Panasonic.pm:815-818) — int16u passthrough.
  PanasonicTag {
    id: 0x3f,
    name: "FacesDetected",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x40 Saturation (Panasonic.pm:819-824) — Exif::printParameter.
  PanasonicTag {
    id: 0x40,
    name: "Saturation",
    conv: PanasonicPrintConv::PrintParameter,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16s, None)),
  },
  // 0x41 Sharpness (Panasonic.pm:825-830) — Exif::printParameter.
  PanasonicTag {
    id: 0x41,
    name: "Sharpness",
    conv: PanasonicPrintConv::PrintParameter,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16s, None)),
  },
  // 0x42 FilmMode (Panasonic.pm:831-849)
  PanasonicTag {
    id: 0x42,
    name: "FilmMode",
    conv: PanasonicPrintConv::FilmMode,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x43 JPEGQuality (Panasonic.pm:850-860)
  PanasonicTag {
    id: 0x43,
    name: "JPEGQuality",
    conv: PanasonicPrintConv::JpegQuality,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x44 ColorTempKelvin (Panasonic.pm:861-864) — int16u passthrough.
  PanasonicTag {
    id: 0x44,
    name: "ColorTempKelvin",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16u, None)),
  },
  // 0x45 BracketSettings (Panasonic.pm:865-877)
  PanasonicTag {
    id: 0x45,
    name: "BracketSettings",
    conv: PanasonicPrintConv::BracketSettings,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x46 WBShiftAB (Panasonic.pm:878-883) — int16s passthrough.
  PanasonicTag {
    id: 0x46,
    name: "WBShiftAB",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16s, None)),
  },
  // 0x47 WBShiftGM (Panasonic.pm:884-889) — int16s passthrough.
  PanasonicTag {
    id: 0x47,
    name: "WBShiftGM",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16s, None)),
  },
  // 0x48 FlashCurtain (Panasonic.pm:890-898)
  PanasonicTag {
    id: 0x48,
    name: "FlashCurtain",
    conv: PanasonicPrintConv::FlashCurtain,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x49 LongExposureNoiseReduction (Panasonic.pm:899-906)
  PanasonicTag {
    id: 0x49,
    name: "LongExposureNoiseReduction",
    conv: PanasonicPrintConv::LongExposureNoiseReduction,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x4b PanasonicImageWidth (Panasonic.pm:908-911) — int32u passthrough.
  PanasonicTag {
    id: 0x4b,
    name: "PanasonicImageWidth",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x4c PanasonicImageHeight (Panasonic.pm:912-915) — int32u passthrough.
  PanasonicTag {
    id: 0x4c,
    name: "PanasonicImageHeight",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x4d AFPointPosition (Panasonic.pm:916-935) — rational64u[2]; decimal-pair
  // ValueConv + sentinel/`%.2g` PrintConv.
  PanasonicTag {
    id: 0x4d,
    name: "AFPointPosition",
    conv: PanasonicPrintConv::AfPointPosition,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x4e FaceDetInfo (Panasonic.pm:936-942) — SubDirectory, deferred.
  PanasonicTag {
    id: 0x4e,
    name: "FaceDetInfo",
    conv: PanasonicPrintConv::None,
    sub_table: Some(SubTable::FaceDetInfo),
    unknown: false,
    format: None,
  },
  // 0x51 LensType (Panasonic.pm:944-949) — string, ValueConv trims trailing
  // spaces (`s/ +$//`).
  PanasonicTag {
    id: 0x51,
    name: "LensType",
    conv: PanasonicPrintConv::TrimTrailingSpaces,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x52 LensSerialNumber (Panasonic.pm:950-955) — string, trailing-space trim.
  PanasonicTag {
    id: 0x52,
    name: "LensSerialNumber",
    conv: PanasonicPrintConv::TrimTrailingSpaces,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x53 AccessoryType (Panasonic.pm:956-961) — string, trailing-space trim.
  PanasonicTag {
    id: 0x53,
    name: "AccessoryType",
    conv: PanasonicPrintConv::TrimTrailingSpaces,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x54 AccessorySerialNumber (Panasonic.pm:962-967) — string, trailing-space
  // trim.
  PanasonicTag {
    id: 0x54,
    name: "AccessorySerialNumber",
    conv: PanasonicPrintConv::TrimTrailingSpaces,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x59 Transform (Panasonic.pm:970-983) — int16s pair, PrintConv hash.
  PanasonicTag {
    id: 0x59,
    name: "Transform",
    conv: PanasonicPrintConv::Transform,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16s, Some(2))),
  },
  // 0x5d IntelligentExposure (Panasonic.pm:987-997)
  PanasonicTag {
    id: 0x5d,
    name: "IntelligentExposure",
    conv: PanasonicPrintConv::IntelligentExposure,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x60 LensFirmwareVersion (Panasonic.pm:999-1006) — int8u[4]; tr/ /./.
  PanasonicTag {
    id: 0x60,
    name: "LensFirmwareVersion",
    conv: PanasonicPrintConv::LensFirmwareVersion,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int8u, Some(4))),
  },
  // 0x61 FaceRecInfo (Panasonic.pm:1007-1012) — SubDirectory, deferred.
  PanasonicTag {
    id: 0x61,
    name: "FaceRecInfo",
    conv: PanasonicPrintConv::None,
    sub_table: Some(SubTable::FaceRecInfo),
    unknown: false,
    format: None,
  },
  // 0x62 FlashWarning (Panasonic.pm:1013-1017)
  PanasonicTag {
    id: 0x62,
    name: "FlashWarning",
    conv: PanasonicPrintConv::FlashWarning,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x63 RecognizedFaceFlags (Panasonic.pm:1018-1026) — Unknown => 1.
  PanasonicTag {
    id: 0x63,
    name: "RecognizedFaceFlags",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: true,
    format: Some(FormatOverride::new(Format::Int8u, Some(4))),
  },
  // 0x65 Title (Panasonic.pm:1027-1031) — string.
  PanasonicTag {
    id: 0x65,
    name: "Title",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Ascii, None)),
  },
  // 0x66 BabyName (Panasonic.pm:1032-1037) — string.
  PanasonicTag {
    id: 0x66,
    name: "BabyName",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Ascii, None)),
  },
  // 0x67 Location (Panasonic.pm:1038-1043) — string.
  PanasonicTag {
    id: 0x67,
    name: "Location",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Ascii, None)),
  },
  // 0x69 Country (Panasonic.pm:1045-1050) — string.
  PanasonicTag {
    id: 0x69,
    name: "Country",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Ascii, None)),
  },
  // 0x6b State (Panasonic.pm:1052-1057) — string.
  PanasonicTag {
    id: 0x6b,
    name: "State",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Ascii, None)),
  },
  // 0x6d City (Panasonic.pm:1059-1065) — string.
  PanasonicTag {
    id: 0x6d,
    name: "City",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Ascii, None)),
  },
  // 0x6f Landmark (Panasonic.pm:1067-1072) — string.
  PanasonicTag {
    id: 0x6f,
    name: "Landmark",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Ascii, None)),
  },
  // 0x70 IntelligentResolution (Panasonic.pm:1073-1085)
  PanasonicTag {
    id: 0x70,
    name: "IntelligentResolution",
    conv: PanasonicPrintConv::IntelligentResolution,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x76 MergedImages (Panasonic.pm:1089-1093) — int16u passthrough.
  PanasonicTag {
    id: 0x76,
    name: "MergedImages",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x77 BurstSpeed (Panasonic.pm:1094-1098) — int16u passthrough.
  PanasonicTag {
    id: 0x77,
    name: "BurstSpeed",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x79 IntelligentD-Range (Panasonic.pm:1099-1108)
  PanasonicTag {
    id: 0x79,
    name: "IntelligentD-Range",
    conv: PanasonicPrintConv::IntelligentDRange,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x7c ClearRetouch (Panasonic.pm:1110-1114)
  PanasonicTag {
    id: 0x7c,
    name: "ClearRetouch",
    conv: PanasonicPrintConv::OffOn,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x80 City2 (Panasonic.pm:1115-1121) — string.
  PanasonicTag {
    id: 0x80,
    name: "City2",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Ascii, None)),
  },
  // 0x86 ManometerPressure (Panasonic.pm:1127-1135) — int16u/10, "%.1f kPa".
  PanasonicTag {
    id: 0x86,
    name: "ManometerPressure",
    conv: PanasonicPrintConv::ManometerPressure,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x89 PhotoStyle (Panasonic.pm:1136-1155)
  PanasonicTag {
    id: 0x89,
    name: "PhotoStyle",
    conv: PanasonicPrintConv::PhotoStyle,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x8a ShadingCompensation (Panasonic.pm:1156-1163)
  PanasonicTag {
    id: 0x8a,
    name: "ShadingCompensation",
    conv: PanasonicPrintConv::OffOn,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x8b WBShiftIntelligentAuto (Panasonic.pm:1164-1169) — int16s passthrough.
  PanasonicTag {
    id: 0x8b,
    name: "WBShiftIntelligentAuto",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16s, None)),
  },
  // 0x8c AccelerometerZ (Panasonic.pm:1170-1175) — int16s passthrough.
  PanasonicTag {
    id: 0x8c,
    name: "AccelerometerZ",
    conv: PanasonicPrintConv::AccelerometerSint,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16s, None)),
  },
  // 0x8d AccelerometerX (Panasonic.pm:1176-1181) — int16s passthrough.
  PanasonicTag {
    id: 0x8d,
    name: "AccelerometerX",
    conv: PanasonicPrintConv::AccelerometerSint,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16s, None)),
  },
  // 0x8e AccelerometerY (Panasonic.pm:1182-1187) — int16s passthrough.
  PanasonicTag {
    id: 0x8e,
    name: "AccelerometerY",
    conv: PanasonicPrintConv::AccelerometerSint,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16s, None)),
  },
  // 0x8f CameraOrientation (Panasonic.pm:1188-1199)
  PanasonicTag {
    id: 0x8f,
    name: "CameraOrientation",
    conv: PanasonicPrintConv::CameraOrientation,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x90 RollAngle (Panasonic.pm:1200-1207) — int16s/10 (no PrintConv).
  PanasonicTag {
    id: 0x90,
    name: "RollAngle",
    conv: PanasonicPrintConv::RollAngle,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16s, None)),
  },
  // 0x91 PitchAngle (Panasonic.pm:1208-1215) — -int16s/10 (no PrintConv).
  PanasonicTag {
    id: 0x91,
    name: "PitchAngle",
    conv: PanasonicPrintConv::PitchAngle,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16s, None)),
  },
  // 0x92 WBShiftCreativeControl (Panasonic.pm:1216-1221) — int8s passthrough.
  PanasonicTag {
    id: 0x92,
    name: "WBShiftCreativeControl",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int8s, None)),
  },
  // 0x93 SweepPanoramaDirection (Panasonic.pm:1222-1232)
  PanasonicTag {
    id: 0x93,
    name: "SweepPanoramaDirection",
    conv: PanasonicPrintConv::SweepPanoramaDirection,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x94 SweepPanoramaFieldOfView (Panasonic.pm:1233-1236) — int16u passthrough.
  PanasonicTag {
    id: 0x94,
    name: "SweepPanoramaFieldOfView",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x96 TimerRecording (Panasonic.pm:1237-1246)
  PanasonicTag {
    id: 0x96,
    name: "TimerRecording",
    conv: PanasonicPrintConv::TimerRecording,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x9d InternalNDFilter (Panasonic.pm:1247-1250) — rational, raw.
  PanasonicTag {
    id: 0x9d,
    name: "InternalNDFilter",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x9e HDR (Panasonic.pm:1251-1263)
  PanasonicTag {
    id: 0x9e,
    name: "HDR",
    conv: PanasonicPrintConv::Hdr,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x9f ShutterType (Panasonic.pm:1264-1272)
  PanasonicTag {
    id: 0x9f,
    name: "ShutterType",
    conv: PanasonicPrintConv::ShutterType,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xa1 FilterEffect (Panasonic.pm:1274-1304) — `Format => 'int32u'` re-reads
  // the 8 on-disk rational64u bytes as int32u[2]; the PrintConv keys on the
  // space-joined pair.
  PanasonicTag {
    id: 0xa1,
    name: "FilterEffect",
    conv: PanasonicPrintConv::FilterEffect,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int32u, None)),
  },
  // 0xa3 ClearRetouchValue (Panasonic.pm:1305-1309) — rational, raw.
  PanasonicTag {
    id: 0xa3,
    name: "ClearRetouchValue",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xa7 OutputLUT (Panasonic.pm:1310-1318) — Binary, kept raw.
  PanasonicTag {
    id: 0xa7,
    name: "OutputLUT",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xab TouchAE (Panasonic.pm:1319-1323)
  PanasonicTag {
    id: 0xab,
    name: "TouchAE",
    conv: PanasonicPrintConv::OffOn,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xac MonochromeFilterEffect (Panasonic.pm:1324-1328)
  PanasonicTag {
    id: 0xac,
    name: "MonochromeFilterEffect",
    conv: PanasonicPrintConv::MonochromeFilterEffect,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xad HighlightShadow (Panasonic.pm:1329-1334) — int16s pair, raw.
  PanasonicTag {
    id: 0xad,
    name: "HighlightShadow",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16s, Some(2))),
  },
  // 0xaf TimeStamp (Panasonic.pm:1335-1342) — string date; `PrintConv =>
  // '$self->ConvertDateTime($val)'` (identity under default options).
  PanasonicTag {
    id: 0xaf,
    name: "TimeStamp",
    conv: PanasonicPrintConv::TimeStamp,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb3 VideoBurstResolution (Panasonic.pm:1343-1347)
  PanasonicTag {
    id: 0xb3,
    name: "VideoBurstResolution",
    conv: PanasonicPrintConv::VideoBurstResolution,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb4 MultiExposure (Panasonic.pm:1348-1352)
  PanasonicTag {
    id: 0xb4,
    name: "MultiExposure",
    conv: PanasonicPrintConv::MultiExposure,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xb9 RedEyeRemoval (Panasonic.pm:1353-1357)
  PanasonicTag {
    id: 0xb9,
    name: "RedEyeRemoval",
    conv: PanasonicPrintConv::OffOn,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xbb VideoBurstMode (Panasonic.pm:1358-1374) — int32u PrintHex hash.
  PanasonicTag {
    id: 0xbb,
    name: "VideoBurstMode",
    conv: PanasonicPrintConv::VideoBurstMode,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xbc DiffractionCorrection (Panasonic.pm:1375-1379)
  PanasonicTag {
    id: 0xbc,
    name: "DiffractionCorrection",
    conv: PanasonicPrintConv::DiffractionCorrection,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xbd FocusBracket (Panasonic.pm:1380-1385) — int16s passthrough.
  PanasonicTag {
    id: 0xbd,
    name: "FocusBracket",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16s, None)),
  },
  // 0xbe LongExposureNRUsed (Panasonic.pm:1386-1390) — 1=>No,2=>Yes.
  PanasonicTag {
    id: 0xbe,
    name: "LongExposureNRUsed",
    conv: PanasonicPrintConv::NoYes12,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xbf PostFocusMerging (Panasonic.pm:1391-1396) — int32u[2] pair hash
  // (`Format => 'int32u', Count => 2`).
  PanasonicTag {
    id: 0xbf,
    name: "PostFocusMerging",
    conv: PanasonicPrintConv::PostFocusMerging,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int32u, Some(2))),
  },
  // 0xc1 VideoPreburst (Panasonic.pm:1397-1401) — 0=>No,1=>"4K or 6K".
  PanasonicTag {
    id: 0xc1,
    name: "VideoPreburst",
    conv: PanasonicPrintConv::VideoPreburst,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xc4 LensTypeMake (Panasonic.pm:1412-1416) — int16u; Condition on
  // format/value, default rendering.
  PanasonicTag {
    id: 0xc4,
    name: "LensTypeMake",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xc5 LensTypeModel (Panasonic.pm:1417-1428) — int16u; RawConv undef-drop
  // (zero ⇒ absent) + byte-swap ValueConv (0x1234 → "34 12"). The Olympus
  // Composite LensID that combines this with LensTypeMake is deferred.
  PanasonicTag {
    id: 0xc5,
    name: "LensTypeModel",
    conv: PanasonicPrintConv::LensTypeModel,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xca SensorType (Panasonic.pm:1402-1409)
  PanasonicTag {
    id: 0xca,
    name: "SensorType",
    conv: PanasonicPrintConv::SensorType,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xd1 ISO (Panasonic.pm:1429-1433) — int32u (RawConv undef >0xfffffff0).
  PanasonicTag {
    id: 0xd1,
    name: "ISO",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xd2 MonochromeGrainEffect (Panasonic.pm:1434-1443)
  PanasonicTag {
    id: 0xd2,
    name: "MonochromeGrainEffect",
    conv: PanasonicPrintConv::OffLowStdHigh,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xd4 HybridLogGamma (Panasonic.pm:1444-1448)
  PanasonicTag {
    id: 0xd4,
    name: "HybridLogGamma",
    conv: PanasonicPrintConv::OffOn,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xd6 NoiseReductionStrength (Panasonic.pm:1449-1452) — rational64s, raw.
  PanasonicTag {
    id: 0xd6,
    name: "NoiseReductionStrength",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xde AFAreaSize (Panasonic.pm:1453-1460) — rational64u[2]; decimal-pair
  // ValueConv + `/^4194303\.9/ → "n/a"` PrintConv.
  PanasonicTag {
    id: 0xde,
    name: "AFAreaSize",
    conv: PanasonicPrintConv::AfAreaSize,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xe4 LensTypeModel (Panasonic.pm:1461-1472) — int16u; same RawConv
  // undef-drop + byte-swap ValueConv as 0xc5.
  PanasonicTag {
    id: 0xe4,
    name: "LensTypeModel",
    conv: PanasonicPrintConv::LensTypeModel,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xe8 MinimumISO (Panasonic.pm:1473-1476) — int32u passthrough.
  PanasonicTag {
    id: 0xe8,
    name: "MinimumISO",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xe9 AFSubjectDetection (Panasonic.pm:1477-1496)
  PanasonicTag {
    id: 0xe9,
    name: "AFSubjectDetection",
    conv: PanasonicPrintConv::AfSubjectDetection,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xee DynamicRangeBoost (Panasonic.pm:1497-1501)
  PanasonicTag {
    id: 0xee,
    name: "DynamicRangeBoost",
    conv: PanasonicPrintConv::OffOn,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xf1 LUT1Name (Panasonic.pm:1502-1505) — string.
  PanasonicTag {
    id: 0xf1,
    name: "LUT1Name",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xf3 LUT1Opacity (Panasonic.pm:1506-1509) — int8u passthrough.
  PanasonicTag {
    id: 0xf3,
    name: "LUT1Opacity",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xf4 LUT2Name (Panasonic.pm:1510-1513) — string.
  PanasonicTag {
    id: 0xf4,
    name: "LUT2Name",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0xf5 LUT2Opacity (Panasonic.pm:1514-1517) — int8u passthrough.
  PanasonicTag {
    id: 0xf5,
    name: "LUT2Opacity",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x0e00 PrintIM (Panasonic.pm:1518-1523) — SubDirectory.
  PanasonicTag {
    id: 0x0e00,
    name: "PrintIM",
    conv: PanasonicPrintConv::None,
    sub_table: Some(SubTable::PrintIm),
    unknown: false,
    format: None,
  },
  // 0x2003 TimeInfo (Panasonic.pm:1524-1527) — SubDirectory, deferred.
  PanasonicTag {
    id: 0x2003,
    name: "TimeInfo",
    conv: PanasonicPrintConv::None,
    sub_table: Some(SubTable::TimeInfo),
    unknown: false,
    format: None,
  },
  // 0x8000 MakerNoteVersion (Panasonic.pm:1528-1531) — undef passthrough.
  PanasonicTag {
    id: 0x8000,
    name: "MakerNoteVersion",
    conv: PanasonicPrintConv::PanasonicExifVersion,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Undef, None)),
  },
  // 0x8001 SceneMode (Panasonic.pm:1532-1540) — {0=>'Off', %shootingMode}.
  PanasonicTag {
    id: 0x8001,
    name: "SceneMode",
    conv: PanasonicPrintConv::SceneMode,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x8002 HighlightWarning (Panasonic.pm:1541-1545)
  PanasonicTag {
    id: 0x8002,
    name: "HighlightWarning",
    conv: PanasonicPrintConv::HighlightWarning,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x8003 DarkFocusEnvironment (Panasonic.pm:1546-1550) — 1=>No,2=>Yes.
  PanasonicTag {
    id: 0x8003,
    name: "DarkFocusEnvironment",
    conv: PanasonicPrintConv::NoYes12,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x8004 WBRedLevel (Panasonic.pm:1551-1554) — int16u passthrough.
  PanasonicTag {
    id: 0x8004,
    name: "WBRedLevel",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x8005 WBGreenLevel (Panasonic.pm:1555-1558) — int16u passthrough.
  PanasonicTag {
    id: 0x8005,
    name: "WBGreenLevel",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x8006 WBBlueLevel (Panasonic.pm:1559-1562) — int16u passthrough.
  PanasonicTag {
    id: 0x8006,
    name: "WBBlueLevel",
    conv: PanasonicPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x8008 TextStamp (Panasonic.pm:1568-1573)
  PanasonicTag {
    id: 0x8008,
    name: "TextStamp",
    conv: PanasonicPrintConv::TextStamp,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x8009 TextStamp (Panasonic.pm:1574-1579)
  PanasonicTag {
    id: 0x8009,
    name: "TextStamp",
    conv: PanasonicPrintConv::TextStamp,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x8010 BabyAge (Panasonic.pm:1580-1586)
  PanasonicTag {
    id: 0x8010,
    name: "BabyAge",
    conv: PanasonicPrintConv::BabyAge,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // 0x8012 Transform (Panasonic.pm:1587-1600) — int16s pair, PrintConv hash.
  PanasonicTag {
    id: 0x8012,
    name: "Transform",
    conv: PanasonicPrintConv::Transform,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16s, Some(2))),
  },
];

/// Binary-search the table by tag ID.
#[must_use]
pub fn lookup(tag_id: u16) -> Option<&'static PanasonicTag> {
  match PANASONIC_TAGS.binary_search_by_key(&tag_id, |t| t.id) {
    Ok(i) => Some(&PANASONIC_TAGS[i]),
    Err(_) => None,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn table_sorted_for_binary_search() {
    let mut prev: i64 = -1;
    for t in PANASONIC_TAGS {
      assert!(
        i64::from(t.id) > prev,
        "PANASONIC_TAGS not strictly sorted: {} after {}",
        t.id,
        prev
      );
      prev = i64::from(t.id);
    }
  }

  #[test]
  fn lookup_image_quality() {
    let t = lookup(0x01).expect("ImageQuality present");
    assert_eq!(t.name, "ImageQuality");
    assert_eq!(t.conv, PanasonicPrintConv::ImageQuality);
  }

  #[test]
  fn lookup_lens_type() {
    let t = lookup(0x51).expect("LensType present");
    assert_eq!(t.name, "LensType");
  }

  #[test]
  fn lookup_unknown_tag() {
    assert!(lookup(0xFFFF).is_none());
  }

  /// 0x63 is the ONLY `Unknown => 1` tag in the Main hash (`Panasonic.pm:1025`).
  #[test]
  fn recognized_face_flags_is_unknown() {
    let t = lookup(0x63).expect("RecognizedFaceFlags present");
    assert_eq!(t.name, "RecognizedFaceFlags");
    assert!(t.is_unknown());
    assert_eq!(PANASONIC_TAGS.iter().filter(|t| t.unknown).count(), 1);
  }

  /// Bundled `%Panasonic::Main` has 136 numeric keys.
  #[test]
  fn table_has_136_rows() {
    assert_eq!(PANASONIC_TAGS.len(), 136);
  }

  /// Spot-check the IDs the previous (wrong-version) table mis-mapped.
  #[test]
  fn corrected_mappings() {
    assert_eq!(lookup(0x60).unwrap().name, "LensFirmwareVersion");
    assert_eq!(lookup(0x62).unwrap().name, "FlashWarning");
    assert_eq!(lookup(0x65).unwrap().name, "Title");
    assert_eq!(lookup(0x90).unwrap().name, "RollAngle");
    assert_eq!(lookup(0x91).unwrap().name, "PitchAngle");
    assert_eq!(lookup(0xc4).unwrap().name, "LensTypeMake");
    assert_eq!(lookup(0x8002).unwrap().name, "HighlightWarning");
  }
}
