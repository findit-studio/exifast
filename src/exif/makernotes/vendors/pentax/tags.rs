// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Pentax::Main` IFD tag table (`Pentax.pm:859-3171`) —
//! the Phase-1 CAMERA-INDEXING subset.
//!
//! Phase 1 ports the cleanly-portable plain LEAF tags (scalar / enum-hash /
//! simple-ValueConv) that the K10D `Pentax.jpg` fixture emits, PLUS the
//! `0x003f LensRec` SubDirectory (`LensType`); Phase 2a adds the K10D variants
//! of the `CameraSettings`/`AEInfo`/`FlashInfo` binary SubDirectory tables.
//! Deferred to a follow-up (excluded from the conformance golden via `-x`):
//! the model-/`$count`-/`$format`-CONDITIONAL leaves (FocusMode 0x000d,
//! AFPointSelected 0x000e, AFPointsInFocus 0x000f/0x003c, ExposureCompensation
//! 0x0016, FocalLength 0x001d, EffectiveLV 0x002d, PictureMode 0x000b/0x0033,
//! RawDevelopmentProcess 0x0062), the multi-element-array PrintConvs
//! (FlashMode 0x000c, AutoBracketing 0x0018, DriveMode 0x0034), the encrypted
//! ShutterCount (0x005d), the `IsOffset => 2` preview pointer PreviewImageStart
//! (0x0004, needs the offset-rebasing subsystem), and the still-deferred binary
//! SubDirectory tables
//! (BatteryInfo 0x0216, AFInfo 0x021f, WBLevels 0x022d,
//! ShakeReductionInfo 0x005c, PrintIM 0x0e00, …).
//!
//! Phase 2a (#262) adds the K10D variants of three binary SubDirectory tables —
//! `%Pentax::CameraSettings` (0x0205), `%Pentax::AEInfo` (0x0206) and
//! `%Pentax::FlashInfo` (0x0208) — selected by their `$count` `Condition`s so a
//! non-K10D record size falls through to the deferred `*Unknown`/variant tables
//! and emits nothing (the scope-fence). Phase 2b (#262) adds the K10D
//! `%Pentax::LensInfo2` (0x0207) with its nested `%Pentax::LensData` SubDirectory
//! (the five lens-detail leaves), `$count`-gated the same way. Phase 2c (#262)
//! adds the UNCONDITIONAL `%Pentax::CameraInfo` (0x0215) — a fixed `int32u`
//! binary table emitting `ManufactureDate`, `ProductionCode` and
//! `InternalSerialNumber` (its offset-0 `PentaxModelID` is owned by the Phase-1
//! `0x0005` leaf and is not re-emitted).

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

  /// The ExifTool `Priority => N` of this `%Pentax::Main` leaf — `0` for a
  /// `Priority => 0` row (never overrides an earlier same-`(doc, family1, name)`
  /// tag, `ExifTool.pm:9544-9560`), `1` (the default) otherwise. The two walked
  /// `%Pentax::Main` `Priority => 0` rows are `0x0012 ExposureTime`
  /// (`Pentax.pm:1474`) and `0x0013 FNumber` (`Pentax.pm:1484`). The
  /// `Priority => 0` rows in walked SUB-tables (`LensRec` `LensType`,
  /// `LensData` `LensFocalLength`) are marked at their own emit sites.
  #[must_use]
  #[inline(always)]
  pub const fn tag_priority(&self) -> u8 {
    match self.id {
      0x0012 | 0x0013 => 0,
      _ => 1,
    }
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
  /// `Some(SubTable::…)` entry (`LensRec` → the `LensType` leaf;
  /// `CameraSettings`/`AEInfo`/`FlashInfo` → their binary leaf records) and
  /// emits NO parent value, mirroring the Nikon/Sony SubDirectory handling.
  #[must_use]
  #[inline(always)]
  pub const fn sub_table(&self) -> Option<SubTable> {
    self.sub_table
  }
}

/// Pentax Main SubDirectory targets ported so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubTable {
  /// `%Pentax::LensRec` at `0x003f` (`Pentax.pm:4192`) — a `ProcessBinaryData`
  /// record whose position-0 `LensType` is an `int8u[2]` `(series, model)`
  /// pair resolved against `%pentaxLensTypes`. Phase 1 reads ONLY that field
  /// (the LensType leaf); the trailing `ExtenderStatus` byte is deferred.
  LensRec,
  /// `%Pentax::CameraSettings` at `0x0205` (`Pentax.pm:2784-2799`,
  /// `:3361-3768`) — a `ProcessBinaryData`/`BigEndian` record. The K10D
  /// variant is selected by `Condition => '$count < 25'` (`Pentax.pm:2788`);
  /// a `$count >= 25` (K-01) entry falls through to the deferred
  /// `CameraSettingsUnknown` table and emits nothing. The K10D-offset-13+
  /// fields are additionally `$$self{Model} =~ /(K10D|GX10)\b/`-gated.
  CameraSettings,
  /// `%Pentax::LensInfo2` at `0x0207` (`Pentax.pm:2821-2850`, `:4240-4271`) — a
  /// `ProcessBinaryData`/`BigEndian` record (21+ bytes: `LensType` `int8u[4]`
  /// at offset 0, then a NESTED `LensData` `undef[17]` SubDirectory at offset
  /// 4). The K10D variant is selected by
  /// `Condition => '$count != 90 and $count != 91 and $count != 80 and
  /// $count != 128 and $count != 168'` (`Pentax.pm:2847`); a `$count` in
  /// `{90,91,80,128,168}` falls through to the deferred
  /// `LensInfo3`/`LensInfo4`/`LensInfo5` tables and emits nothing (the
  /// scope-fence). Phase 2b emits ONLY the five nested `LensData` lens-detail
  /// leaves; `LensType` is owned by the Phase-1 `0x003f LensRec` row and is NOT
  /// re-emitted here (the `LensInfo2`-offset-0 `LensType` is skipped).
  LensInfo,
  /// `%Pentax::AEInfo` at `0x0206` (`Pentax.pm:2800-2820`, `:3778-3990`) — a
  /// `ProcessBinaryData` record. The K10D variant is selected by
  /// `Condition => '$count <= 25 and $count != 21'` (`Pentax.pm:2804`); the
  /// `$count == 21` (AEInfo2/K-01), `$count == 48|64` (AEInfo3) and the
  /// `$count == 34` (AEInfoUnknown/Q) variants are deferred and emit nothing.
  AEInfo,
  /// `%Pentax::FlashInfo` at `0x0208` (`Pentax.pm:2852-2862`, `:4580-4708`) —
  /// a `ProcessBinaryData` record. The K10D variant is selected by
  /// `Condition => '$count == 27'` (`Pentax.pm:2855`); any other `$count`
  /// falls through to the deferred `FlashInfoUnknown` table and emits nothing.
  FlashInfo,
  /// `%Pentax::CameraInfo` at `0x0215` (`Pentax.pm:2940-2944`, `:4717-4754`) — a
  /// fixed `ProcessBinaryData` record (`FORMAT => 'int32u'`, so element offset N
  /// = byte 4N) in the inherited MakerNote (BigEndian) order. UNCONDITIONAL: the
  /// Main row carries NO `Condition` / `$count` gate and NO model variant, so it
  /// applies to every Pentax body. Phase 2c emits the three serviceable-data
  /// scalars (offset 1 `ManufactureDate`, offset 2 `ProductionCode` `int32u[2]`,
  /// offset 4 `InternalSerialNumber`); the offset-0 `PentaxModelID` is owned by
  /// the Phase-1 `0x0005` Main leaf and is NOT re-emitted here.
  CameraInfo,
  /// `%Pentax::SRInfo` at `0x005c` (`Pentax.pm:2258-2262`, `:3172-3228`) — a
  /// `ProcessBinaryData` record. The first variant is selected by `Condition =>
  /// '$count == 4'` (`Pentax.pm:2260`); a `$count != 4` (2-byte K-3) record
  /// falls through to the deferred `%Pentax::SRInfo2` variant and emits nothing
  /// (the scope-fence). `Format => 'undef'` ⇒ the whole 4-byte block reaches the
  /// child. Emits the four shake-reduction leaves (SRResult, ShakeReduction,
  /// SRHalfPressTime, SRFocalLength).
  SrInfo,
  /// `%Pentax::BatteryInfo` at `0x0216` (`Pentax.pm:2945-2951`, `:4757-4989`) — a
  /// `ProcessBinaryData` / `BigEndian` record. UNCONDITIONAL (no `$count` gate),
  /// but its leaves are heavily `$$self{Model}`-gated. The K10D variant emits
  /// PowerSource, BodyBatteryState, GripBatteryState and the four A/D voltage
  /// measurements.
  BatteryInfo,
  /// `%Pentax::AFInfo` at `0x021f` (`Pentax.pm:2980-2990`, `:4992`) — a
  /// `ProcessBinaryData` / `BigEndian` record (the `undef`-format sub-table needs
  /// explicit BigEndian for its `int16u`/`int16s` leaves). UNCONDITIONAL. The
  /// K10D variant emits AFPredictor (int16s @ 4), AFDefocus (int8u @ 6),
  /// AFIntegrationTime (@ 7) and AFPointsInFocus (@ 11); the two `Unknown => 1`
  /// AFPointsUnknown1/2 (int16u @ 0/2) are suppressed without `-U`.
  AfInfo,
  /// `%Pentax::ColorInfo` at `0x0222` (`Pentax.pm:3001-3004`, `:5258-5270`) — a
  /// `ProcessBinaryData` record with `FORMAT => 'int8s'`. UNCONDITIONAL. Emits
  /// the two white-balance-shift leaves WBShiftAB (@ 16) and WBShiftGM (@ 17).
  ColorInfo,
  /// `%Pentax::TimeInfo` at `0x006b` (`Pentax.pm:2366-2370`, `:3305-3336`) — the
  /// world-time settings (`int8u`, inherits the parent IFD order). Emits
  /// WorldTimeLocation / HometownDST / DestinationDST / HometownCity /
  /// DestinationCity.
  TimeInfo,
  /// `%Pentax::LensCorr` at `0x007d` (`Pentax.pm:2580-2584`, `:3339-3358`) — the
  /// lens distortion / aberration correction flags (`int8u`). Emits
  /// DistortionCorrection / ChromaticAberrationCorrection /
  /// PeripheralIlluminationCorr / DiffractionCorrection.
  LensCorr,
  /// `%Pentax::FaceInfo` at `0x0060` (`Pentax.pm:2293-2297`, `:3264-3280`) — face
  /// detection (`int8u`). Emits FacesDetected (@0) + FacePosition (@2, int8u[2]).
  /// The Main `0x0060` row has NO `Condition` (a single `{...}`, applied to every
  /// body, K-3 Mark III included), so the dispatch is UNCONDITIONAL — there is no
  /// model gate here. The K-3III's distinct `%FaceInfoK3III` is a SEPARATE tag id
  /// (`0x040b`), not a 0x0060 variant, and is a deferred (unported) follow-up.
  FaceInfo,
  /// `%Pentax::AWBInfo` at `0x0068` (`Pentax.pm:2343-2347`, `:3283-3302`) — the
  /// automatic white-balance settings (`int8u`). Emits WhiteBalanceAutoAdjustment
  /// (@0) + TungstenAWB (@1, K-5 and later).
  AwbInfo,
  /// `%Pentax::EVStepInfo` at `0x0224` (`Pentax.pm:3006-3009`, `:5273-5294`) —
  /// `int8u`. Emits EVSteps (@0) / SensitivitySteps (@1) / LiveView (@3).
  EvStepInfo,
  /// `%Pentax::LevelInfo` at `0x022b` (`Pentax.pm:3044-3052`, `:5701-5769`) — the
  /// electronic-level info, `FORMAT => 'int8s'`. The non-K-3III variant. Emits
  /// LevelOrientation / CompositionAdjust / RollAngle / PitchAngle /
  /// CompositionAdjustX / CompositionAdjustY / CompositionAdjustRotation.
  LevelInfo,
  /// `%Pentax::KelvinWB` at `0x0221` (`Pentax.pm:2949-2952`, `:5233-5255`) — the
  /// Kelvin white-balance gains, `FORMAT => 'int16u'` (inherits the parent IFD
  /// order). Emits KelvinWB_Daylight + KelvinWB_01..16 (each int16u[4] via the
  /// `%kelvinWB` ValueConv).
  KelvinWb,
  /// `%Pentax::CAFPointInfo` at `0x0238` (`Pentax.pm:3087-3090`, `:5202-5230`) —
  /// the contrast-detect AF-point info (`int8u`). Emits NumCAFPoints / CAFGridSize
  /// / CAFPointsInFocus / CAFPointsSelected.
  CafPointInfo,
  /// `%Pentax::FilterInfo` at `0x022a` (`Pentax.pm:3030-3043`, `:5660-...`) — the
  /// digital-filter info. The non-RICOH (BigEndian) variant. Emits
  /// SourceDirectoryIndex (@byte 0) + SourceFileIndex (@byte 2); the 20
  /// `DigitalFilterNN` blobs are deferred.
  FilterInfo,
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
    id: 0x000c,
    name: "FlashMode",
    conv: PentaxPrintConv::FlashMode,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x000d,
    name: "FocusMode",
    conv: PentaxPrintConv::Hash(FOCUS_MODE),
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x000e,
    // The "other models" variant (`Pentax.pm:1375-1408`) the K-S2 selects: an
    // int16u[N] ARRAY PrintConv, NOT the single 11-point hash. The element count
    // is derived from the on-disk byte size — the K10D `Pentax.jpg` is
    // int16u[1] (`'Center'`), the K-S2 int16u[2] (`'Center; Single Point'`) — so
    // NO format override (the on-disk format is already int16u).
    name: "AFPointSelected",
    conv: PentaxPrintConv::AfPointSelected,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x000f,
    // The `/K-(3|S1|S2)\b/` variant (`Pentax.pm:1409-1446`): int32u, PrintHex,
    // `{0=>'(none)', BITMASK=>{...}}`. The K-S2 value 0x2000 → 'Center'.
    name: "AFPointsInFocus",
    conv: PentaxPrintConv::AfPointsInFocus,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int32u, Some(1))),
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
    id: 0x0016,
    name: "ExposureCompensation",
    conv: PentaxPrintConv::ExposureCompensation,
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
    id: 0x0018,
    name: "AutoBracketing",
    conv: PentaxPrintConv::AutoBracketing,
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
    id: 0x001d,
    name: "FocalLength",
    conv: PentaxPrintConv::FocalLength,
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
    id: 0x002d,
    name: "EffectiveLV",
    conv: PentaxPrintConv::EffectiveLv,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16s, None)),
  },
  PentaxTag {
    id: 0x0032,
    name: "ImageEditing",
    conv: PentaxPrintConv::StringKeyedHash(super::printconv::IMAGE_EDITING),
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int8u, Some(4))),
  },
  PentaxTag {
    id: 0x0033,
    name: "PictureMode",
    conv: PentaxPrintConv::PictureMode,
    sub_table: None,
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0034,
    name: "DriveMode",
    conv: PentaxPrintConv::DriveMode,
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
    id: 0x004d,
    name: "FlashExposureComp",
    conv: PentaxPrintConv::FlashExposureComp,
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
    id: 0x005c,
    name: "ShakeReductionInfo",
    conv: PentaxPrintConv::None,
    sub_table: Some(SubTable::SrInfo),
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x005d,
    name: "ShutterCount",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // `0x0060 FaceInfo` (`Pentax.pm:2293-2297`) — `Format => 'undef'` SubDirectory.
  PentaxTag {
    id: 0x0060,
    name: "FaceInfo",
    conv: PentaxPrintConv::None,
    sub_table: Some(SubTable::FaceInfo),
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0062,
    name: "RawDevelopmentProcess",
    conv: PentaxPrintConv::Hash(RAW_DEVELOPMENT_PROCESS),
    sub_table: None,
    unknown: false,
    format: None,
  },
  // `0x0067 Hue` (`Pentax.pm:2325-2341`) — int16u, unconditional enum hash.
  PentaxTag {
    id: 0x0067,
    name: "Hue",
    conv: PentaxPrintConv::Hash(HUE),
    sub_table: None,
    unknown: false,
    format: None,
  },
  // `0x0068 AWBInfo` (`Pentax.pm:2343-2347`) — `Format => 'undef'` SubDirectory.
  PentaxTag {
    id: 0x0068,
    name: "AWBInfo",
    conv: PentaxPrintConv::None,
    sub_table: Some(SubTable::AwbInfo),
    unknown: false,
    format: None,
  },
  // `0x0069 DynamicRangeExpansion` (`Pentax.pm:2349-2364`) — `Format => 'int8u',
  // Count => 4`; a 2-positioned ARRAY PrintConv (`'Off; Auto; 0; 0'`).
  PentaxTag {
    id: 0x0069,
    name: "DynamicRangeExpansion",
    conv: PentaxPrintConv::ArrayHash(super::printconv::DYNAMIC_RANGE_EXPANSION),
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int8u, Some(4))),
  },
  // `0x006b TimeInfo` (`Pentax.pm:2366-2370`) — `Format => 'undef'` SubDirectory.
  PentaxTag {
    id: 0x006b,
    name: "TimeInfo",
    conv: PentaxPrintConv::None,
    sub_table: Some(SubTable::TimeInfo),
    unknown: false,
    format: None,
  },
  // `0x006c HighLowKeyAdj` (`Pentax.pm:2371-2388`) — int16s `Count => 2`, a
  // PrintConv keyed on the SPACE-JOINED `"adj 0"` pair (e.g. `"0 0" => 0`).
  PentaxTag {
    id: 0x006c,
    name: "HighLowKeyAdj",
    conv: PentaxPrintConv::StringKeyedHash(super::printconv::HIGH_LOW_KEY_ADJ),
    sub_table: None,
    unknown: false,
    format: None,
  },
  // `0x0070 FineSharpness` (`Pentax.pm:2433-2443`) — int8u `Count => -1` (1 for
  // K20/K200, 2 for K-5+); a 2-positioned ARRAY PrintConv (`'Off; Normal'`). The
  // element count is derived from the on-disk byte size (no count override).
  PentaxTag {
    id: 0x0070,
    name: "FineSharpness",
    conv: PentaxPrintConv::ArrayHash(super::printconv::FINE_SHARPNESS),
    sub_table: None,
    unknown: false,
    format: None,
  },
  // `0x0071 HighISONoiseReduction` (`Pentax.pm:2445-2467`) — `Format => 'int8u'`
  // (no `Count`); a 3-positioned ARRAY PrintConv (`'Auto; Inactive'` for the
  // K-S2's 2 values). The explicit `Format` re-reads the entry as `int8u[N]`
  // regardless of the on-disk TIFF type (`Exif.pm:6735-6744`).
  PentaxTag {
    id: 0x0071,
    name: "HighISONoiseReduction",
    conv: PentaxPrintConv::ArrayHash(super::printconv::HIGH_ISO_NOISE_REDUCTION),
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int8u, None)),
  },
  // `0x0072 AFAdjustment` (`Pentax.pm:2468-2470`) — int16s, no conv.
  PentaxTag {
    id: 0x0072,
    name: "AFAdjustment",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // `0x0073 MonochromeFilterEffect` (`Pentax.pm:2471-2486`) — int16u enum hash.
  PentaxTag {
    id: 0x0073,
    name: "MonochromeFilterEffect",
    conv: PentaxPrintConv::Hash(MONOCHROME_FILTER_EFFECT),
    sub_table: None,
    unknown: false,
    format: None,
  },
  // `0x0074 MonochromeToning` (`Pentax.pm:2487-2503`) — int16u enum hash.
  PentaxTag {
    id: 0x0074,
    name: "MonochromeToning",
    conv: PentaxPrintConv::Hash(MONOCHROME_TONING),
    sub_table: None,
    unknown: false,
    format: None,
  },
  // `0x0076 FaceDetect` (`Pentax.pm:2505-2522`) — int8u, a 2-entry CODE PrintConv
  // array (`'Off; 0 faces detected; 0'`); the trailing element passes through raw.
  PentaxTag {
    id: 0x0076,
    name: "FaceDetect",
    conv: PentaxPrintConv::FaceDetect,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // `0x0077 FaceDetectFrameSize` (`Pentax.pm:2524-2528`) — int16u `Count => 2`,
  // the default space-joined pair (`'0 0'`).
  PentaxTag {
    id: 0x0077,
    name: "FaceDetectFrameSize",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // `0x0079 ShadowCorrection` (`Pentax.pm:2530-2543`) — int8u `Count => -1`, a
  // run-keyed hash (`'2 4' => 'Auto'`).
  PentaxTag {
    id: 0x0079,
    name: "ShadowCorrection",
    conv: PentaxPrintConv::StringKeyedHash(super::printconv::SHADOW_CORRECTION),
    sub_table: None,
    unknown: false,
    format: None,
  },
  // `0x007b CrossProcess` (`Pentax.pm:2565-2578`) — int8u enum hash.
  PentaxTag {
    id: 0x007b,
    name: "CrossProcess",
    conv: PentaxPrintConv::Hash(CROSS_PROCESS),
    sub_table: None,
    unknown: false,
    format: None,
  },
  // `0x007d LensCorr` (`Pentax.pm:2580-2584`) — `Format => 'undef'` SubDirectory.
  PentaxTag {
    id: 0x007d,
    name: "LensCorr",
    conv: PentaxPrintConv::None,
    sub_table: Some(SubTable::LensCorr),
    unknown: false,
    format: None,
  },
  // `0x007f BleachBypassToning` (`Pentax.pm:2585-2607`) — int16u enum hash.
  PentaxTag {
    id: 0x007f,
    name: "BleachBypassToning",
    conv: PentaxPrintConv::Hash(super::printconv::BLEACH_BYPASS_TONING),
    sub_table: None,
    unknown: false,
    format: None,
  },
  // `0x0080 AspectRatio` (`Pentax.pm:2609-2617`) — int8u enum hash.
  PentaxTag {
    id: 0x0080,
    name: "AspectRatio",
    conv: PentaxPrintConv::Hash(super::printconv::ASPECT_RATIO),
    sub_table: None,
    unknown: false,
    format: None,
  },
  // `0x0085 HDR` (`Pentax.pm:2637-...`) — `Format => 'int8u', Count => 4`; a
  // 3-positioned ARRAY PrintConv (`'Off; Auto-align Off; n/a; 0'`).
  PentaxTag {
    id: 0x0085,
    name: "HDR",
    conv: PentaxPrintConv::ArrayHash(super::printconv::HDR),
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int8u, Some(4))),
  },
  // `0x0092 IntervalShooting` (`Pentax.pm:2690-2707`) — int16u `Count => 2`:
  // `'0 0' => 'Off'` plus the `OTHER => sub` (`s/(\d+) (\d+)/Shot $1 of $2/`).
  PentaxTag {
    id: 0x0092,
    name: "IntervalShooting",
    conv: PentaxPrintConv::IntervalShooting,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // `0x0096 ClarityControl` (`Pentax.pm:2727-2745`) — int8s `Count => 2`:
  // `'0 0' => 'Off'` plus the `OTHER => sub` (`^1 (-?\d+)$ → %+d` / `0`).
  PentaxTag {
    id: 0x0096,
    name: "ClarityControl",
    conv: PentaxPrintConv::ClarityControl,
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
    id: 0x0205,
    name: "CameraSettings",
    conv: PentaxPrintConv::None,
    sub_table: Some(SubTable::CameraSettings),
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0206,
    name: "AEInfo",
    conv: PentaxPrintConv::None,
    sub_table: Some(SubTable::AEInfo),
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0207,
    name: "LensInfo",
    conv: PentaxPrintConv::None,
    sub_table: Some(SubTable::LensInfo),
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0208,
    name: "FlashInfo",
    conv: PentaxPrintConv::None,
    sub_table: Some(SubTable::FlashInfo),
    unknown: false,
    format: None,
  },
  // `0x0209 AEMeteringSegments` (`Pentax.pm:5360-...`) — `Format => 'int8u',
  // Count => -1` (variable: 16 segments on the K10D, 77 on the K-5, 4050 on the
  // K-3). `Count => -1` ⇒ NO bundled count (the walker recomputes
  // `int(size/1)` from the on-disk byte span, `Exif.pm:6743`); the explicit
  // `Format` re-reads as `int8u[N]` regardless of the on-disk TIFF type.
  PentaxTag {
    id: 0x0209,
    name: "AEMeteringSegments",
    conv: PentaxPrintConv::MeteringSegments,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int8u, None)),
  },
  // `0x020a FlashMeteringSegments` (`Pentax.pm`) — `Format => 'int8u', Count =>
  // -1` (variable-length, as 0x0209).
  PentaxTag {
    id: 0x020a,
    name: "FlashMeteringSegments",
    conv: PentaxPrintConv::MeteringSegments,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int8u, None)),
  },
  // `0x020b SlaveFlashMeteringSegments` (`Pentax.pm`) — `Format => 'int8u',
  // Count => -1` (variable-length, as 0x0209).
  PentaxTag {
    id: 0x020b,
    name: "SlaveFlashMeteringSegments",
    conv: PentaxPrintConv::MeteringSegments,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int8u, None)),
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
  PentaxTag {
    id: 0x0215,
    name: "CameraInfo",
    conv: PentaxPrintConv::None,
    sub_table: Some(SubTable::CameraInfo),
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0216,
    name: "BatteryInfo",
    conv: PentaxPrintConv::None,
    sub_table: Some(SubTable::BatteryInfo),
    unknown: false,
    format: None,
  },
  // `0x021c ColorMatrixA2` (`Pentax.pm:2968-2972`) — `Format => 'int16s', Count
  // => 9`, the default space-joined run (no conv). `0x021d ColorMatrixB2` likewise.
  PentaxTag {
    id: 0x021c,
    name: "ColorMatrixA2",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16s, Some(9))),
  },
  PentaxTag {
    id: 0x021d,
    name: "ColorMatrixB2",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: Some(FormatOverride::new(Format::Int16s, Some(9))),
  },
  PentaxTag {
    id: 0x021f,
    name: "AFInfo",
    conv: PentaxPrintConv::None,
    sub_table: Some(SubTable::AfInfo),
    unknown: false,
    format: None,
  },
  // `0x0221 KelvinWB` (`Pentax.pm:2949-2952`) — `Format => 'undef'` SubDirectory.
  PentaxTag {
    id: 0x0221,
    name: "KelvinWB",
    conv: PentaxPrintConv::None,
    sub_table: Some(SubTable::KelvinWb),
    unknown: false,
    format: None,
  },
  PentaxTag {
    id: 0x0222,
    name: "ColorInfo",
    conv: PentaxPrintConv::None,
    sub_table: Some(SubTable::ColorInfo),
    unknown: false,
    format: None,
  },
  // `0x0224 EVStepInfo` (`Pentax.pm:3006-3009`) — `Format => 'undef'`
  // SubDirectory.
  PentaxTag {
    id: 0x0224,
    name: "EVStepInfo",
    conv: PentaxPrintConv::None,
    sub_table: Some(SubTable::EvStepInfo),
    unknown: false,
    format: None,
  },
  // `0x0229 SerialNumber` (`Pentax.pm:3025-3029`) — `Writable => 'string'`, no
  // PrintConv/ValueConv. The on-disk `string` is NUL-trimmed (`s/\0.*//s`) with
  // trailing spaces preserved by the shared `Walker`, then passes through.
  PentaxTag {
    id: 0x0229,
    name: "SerialNumber",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // `0x022a FilterInfo` (`Pentax.pm:3030-3043`) — the non-RICOH (BigEndian)
  // `Format => 'undef'` SubDirectory. Only SourceDirectoryIndex / SourceFileIndex
  // are ported (the 20 DigitalFilter blobs are deferred).
  PentaxTag {
    id: 0x022a,
    name: "FilterInfo",
    conv: PentaxPrintConv::None,
    sub_table: Some(SubTable::FilterInfo),
    unknown: false,
    format: None,
  },
  // `0x022b LevelInfo` (`Pentax.pm:3044-3052`) — the non-K-3III `Format =>
  // 'undef'` SubDirectory.
  PentaxTag {
    id: 0x022b,
    name: "LevelInfo",
    conv: PentaxPrintConv::None,
    sub_table: Some(SubTable::LevelInfo),
    unknown: false,
    format: None,
  },
  // `0x022e Artist` (`Pentax.pm:3058-3062`) — `string` (K-5/K-x AVI videos;
  // `Groups => { 2 => 'Author' }`, a family-2 axis not reflected in the
  // family-1 `Pentax:` token). Left blank by the K-x ⇒ the empty string.
  PentaxTag {
    id: 0x022e,
    name: "Artist",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // `0x022f Copyright` (`Pentax.pm:3063-3067`) — `string`, `Groups => { 2 =>
  // 'Author' }`. Blank on the K-x ⇒ the empty string.
  PentaxTag {
    id: 0x022f,
    name: "Copyright",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // `0x0230 FirmwareVersion` (`Pentax.pm:3068-3076`) — `string`, videos only.
  // The K-x value `"K-x Ver 1.00"` carries trailing spaces the `string` decode
  // preserves (only the NUL terminator is trimmed), NOT the EXIF Make/Model/
  // Software RawConv whitespace trim (that gate is EXIF-only).
  PentaxTag {
    id: 0x0230,
    name: "FirmwareVersion",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // `0x0231 ContrastDetectAFArea` (`Pentax.pm:3066-3084`) — int16u `Count => 4`,
  // the default space-joined run (no conv).
  PentaxTag {
    id: 0x0231,
    name: "ContrastDetectAFArea",
    conv: PentaxPrintConv::None,
    sub_table: None,
    unknown: false,
    format: None,
  },
  // `0x0238 CAFPointInfo` (`Pentax.pm:3087-3090`) — `Format => 'undef'`
  // SubDirectory.
  PentaxTag {
    id: 0x0238,
    name: "CAFPointInfo",
    conv: PentaxPrintConv::None,
    sub_table: Some(SubTable::CafPointInfo),
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
/// matches the implicit-`undef` SubDirectory rows `0x003f LensRec`, `0x0205`
/// CameraSettings, `0x0206` AEInfo, `0x0207` LensInfo, `0x0208` FlashInfo and
/// `0x0215` CameraInfo.
#[must_use]
pub fn is_implicit_undef_subdir(id: u16) -> bool {
  lookup(id).is_some_and(|tag| tag.format_override().is_none() && tag.sub_table().is_some())
}

/// Outcome of the `%Pentax::Main` per-leaf `Condition` selection — the
/// count-/`Make`-/`Model`-/on-disk-`$format`-conditioned Main LEAVES whose
/// ExifTool definition is an array-of-variants (`0xNN => [{ Condition => ... },
/// { ... }]`) or a single row carrying a `Condition`. The shared
/// [`PentaxPrintConv::apply`](super::printconv::PentaxPrintConv::apply) /
/// [`FormatOverride`] decoder has no `$count`/`$$self{Make}`/`$$self{Model}`/
/// `$format` context, so the branch is selected HERE (mirroring ExifTool's
/// `GetTagInfo` Condition scan) and only the variant the ported decoder
/// faithfully implements is allowed to emit.
///
/// # The structural invariant (EXHAUSTIVE — every conditioned Main leaf is enumerated)
///
/// [`conditional_leaf`] matches on the FULL set of `%Pentax::Main` LEAF ids the
/// #173 + #311 commits ported that carry a `Pentax.pm` `Condition`. Each leaf is
/// EXPLICITLY one of:
///
/// * **gated** — the leaf carries a `Condition` in `Pentax.pm` (a `$$self{Model}`
///   regex, a `$$self{Make}` regex, a `$count` gate, an on-disk `$format` gate,
///   or an ARRAY of variants selected by such a `Condition`); the arm emits ONLY
///   for the exact `(count, Make, Model, on-disk format)` the ported decoder was
///   transcribed and VERIFIED against (the `Pentax.jpg` K10D / `Pentax.avi` K-x /
///   `JPEG_pentax_ks2.jpg` K-S2 fixtures), and returns
///   [`ConditionalLeaf::Suppress`] for every OTHER context so the leaf emits
///   NOTHING — never the ported variant's layout/`ValueConv`/decoder flattened
///   onto a Make/Model/count/format it was not decoded for; OR
/// * **confirmed unconditional** — the leaf has NO `Condition` in `Pentax.pm`
///   (a `Count => N` element-count is NOT a `Condition`; it fixes the array
///   length, not the variant), verified against the source, so it emits for
///   every context (`ConditionalLeaf::Emit`).
///
/// All conditioned/enumerated Main LEAF ids have an EXPLICIT arm — the #173 set
/// (7 gated + 5 confirmed-unconditional + `0x005d ShutterCount`) PLUS the #311
/// `0x000f AFPointsInFocus` model-BITMASK gate; the catch-all
/// `_ => EmitUnported` is reserved for the pre-#173 Phase-1/2 leaves (audited in
/// their own phases) and unported ids. (The two #311 conditioned SubDirectory
/// rows — `0x022a FilterInfo` `Make`-forced byte order, `0x022b LevelInfo` /
/// `LevelInfoK3III` model variant — are NOT leaves: their `Condition` selects an
/// axis at the subdirectory-dispatch site in `exif/mod.rs`, not here, so they do
/// not need a `conditional_leaf` arm.) The invariant is therefore STRUCTURAL,
/// not comment-dependent: a `EmitUnported` outcome PROVES the id is not an
/// enumerated conditioned leaf, so reclassifying a leaf (or a future audit error)
/// cannot silently route one through the default and emit the ported decoder. The
/// [`conditional_leaf_173_leaves_are_structurally_handled`] and
/// [`conditional_leaf_311_leaves_are_structurally_handled`] tests fail if any
/// enumerated id is covered only by the fallback. Adding a new conditional leaf
/// must add its explicit arm here.
///
/// The remaining model-/count-specific variants are DEFERRED (suppressed)
/// pending a real fixture for each (see the #173/#311 multi-model follow-up
/// issue).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionalLeaf {
  /// Not a conditional leaf, or the entry matches the ported variant — apply
  /// the row's [`PentaxPrintConv`](super::printconv::PentaxPrintConv) /
  /// [`FormatOverride`] and emit as usual.
  Emit,
  /// The entry's `count`/`Make`/`Model`/on-disk `$format` selects a DIFFERENT
  /// ExifTool variant than the one the port implements — emit nothing (the
  /// scope-fence).
  Suppress,
  /// The id is NOT a #173 leaf — a pre-#173 Phase-1/2 leaf (audited in its own
  /// phase) or an unported id — so [`conditional_leaf`] applies no #173 gate and
  /// the row emits as usual. Behaves exactly like [`Emit`](Self::Emit) for the
  /// caller (it is NOT suppressed); the SEPARATE variant exists only so the
  /// structural test can prove that NO #173 leaf reaches the catch-all (every
  /// #173 leaf has an explicit `Emit`/`Suppress` arm, never `EmitUnported`).
  EmitUnported,
}

impl ConditionalLeaf {
  /// `true` when the leaf must NOT emit (the non-ported variant).
  #[must_use]
  pub const fn is_suppressed(self) -> bool {
    matches!(self, ConditionalLeaf::Suppress)
  }
}

/// `true` when `model` contains `needle` followed by a Perl `\b` word boundary
/// (the model strings are ASCII, so `\b` after the token = end-of-string or a
/// non-`[A-Za-z0-9_]` char). Mirrors `subtables::model_matches_any` for the
/// `%Pentax::Main` leaves whose `Condition` is a `$$self{Model} =~ /(...)\b/`
/// model regex (`0x000e AFPointSelected`).
fn model_word_match(model: &str, needle: &str) -> bool {
  let mut from = 0;
  while let Some(rel) = model.get(from..).and_then(|sub| sub.find(needle)) {
    let start = from + rel;
    let end = start + needle.len();
    let boundary_ok = model
      .get(end..)
      .and_then(|sub| sub.chars().next())
      .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
    if boundary_ok {
      return true;
    }
    from = end;
  }
  false
}

/// `true` when `s` starts with `prefix` (a Perl `/^prefix/` anchored, NON-`\b`
/// match — `$$self{Make} =~ /^Asahi/` / `/^(PENTAX|RICOH)/`). The Make strings
/// are ASCII; ExifTool's `^` anchors at string start with no trailing boundary,
/// so a plain prefix test is faithful (`"PENTAX Corporation"` matches
/// `/^PENTAX/`, `"Asahi Optical Co.,Ltd"` matches `/^Asahi/`).
fn make_prefix_match(s: &str, prefix: &str) -> bool {
  s.starts_with(prefix)
}

/// `true` when the `%Pentax::Main` `0x001d FocalLength` ÷10 (Optio) variant
/// (`Pentax.pm:1740-1751`) is selected: `$self->{Model} =~ /^PENTAX Optio
/// (30|33WR|43WR|450|550|555|750Z|X)\b/`. The port implements the ÷100 variant
/// (variant 2, K10D and most bodies), so a Model matching this Optio list MUST
/// be suppressed (its FocalLength is 10× different).
fn is_optio_div10_focal_length(model: &str) -> bool {
  // `/^PENTAX Optio (30|33WR|43WR|450|550|555|750Z|X)\b/` — the `^`-anchored
  // prefix, then one of the alternatives followed by a `\b`.
  const PREFIX: &str = "PENTAX Optio ";
  let Some(rest) = model.strip_prefix(PREFIX) else {
    return false;
  };
  // The alternation, longest-first so a prefix alternative (e.g. "33") cannot
  // shadow a longer token ("33WR") — Perl tries them left-to-right but each is
  // pinned by the trailing `\b`, so any order that respects `\b` is equivalent;
  // longest-first keeps the boundary check correct for the shared tokens.
  for tok in ["33WR", "43WR", "750Z", "450", "550", "555", "30", "X"] {
    if let Some(after) = rest.strip_prefix(tok) {
      // `\b` after the token: end-of-string or a non-word char. The next char
      // after a digit token must NOT be `[A-Za-z0-9_]` (so "30" does not match
      // "300"); after "X" likewise.
      let boundary_ok = after
        .chars()
        .next()
        .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
      if boundary_ok {
        return true;
      }
    }
  }
  false
}

/// `true` when the `%Pentax::Main` `0x000f AFPointsInFocus` int32u BITMASK variant
/// (`Pentax.pm:1409-1446`) is selected: `$$self{Model} =~ /K-(3|S1|S2)\b/` — the
/// K-3, K-S1 and K-S2 bodies (`Notes => 'K-3, K-S1 and K-S2 only'`). The port
/// implements ONLY this variant; the second `Notes => 'other models'` int16u enum
/// variant (`Pentax.pm:1447-1465`) is DEFERRED, so a model NOT matching this regex
/// MUST suppress (its 0x000f is a 10-entry enum, NOT the 27-bit bitmask).
///
/// The Perl alternation `(3|S1|S2)` follows the literal `K-`, and the `\b` pins
/// the END of the chosen token: `K-3\b` matches `"PENTAX K-3"` and `"PENTAX K-3
/// Mark III"` (the `3` is followed by a space) but NOT `"PENTAX K-30"` (the `3` is
/// followed by the word char `0`); `K-S1\b` / `K-S2\b` likewise. The `K-` prefix
/// is NOT itself `\b`-anchored at its left (Perl scans for the substring), so a
/// `"PENTAX K-3"` matches via the embedded `K-3`.
fn is_afpoints_in_focus_bitmask(model: &str) -> bool {
  // `/K-(3|S1|S2)\b/` — find `K-`, then one of `3` / `S1` / `S2` pinned by a
  // trailing `\b` (end-of-string or a non-`[A-Za-z0-9_]` char). Reuse
  // `model_word_match` per fully-expanded alternative so the `\b` and the
  // substring scan stay token-for-token faithful.
  model_word_match(model, "K-3")
    || model_word_match(model, "K-S1")
    || model_word_match(model, "K-S2")
}

/// Select the ExifTool `Condition` branch for a count-/`Make`-/`Model`-/on-disk-
/// `$format`-conditioned `%Pentax::Main` LEAF and report whether the ported
/// decoder may emit it.
///
/// `id` is the Main tag id, `count` the IFD entry element COUNT (ExifTool's
/// `$count`), `model` the parent `$$self{Model}`, `make` the parent
/// `$$self{Make}`, `on_disk_format` the entry's pre-`Format`-override on-disk
/// TIFF format (ExifTool's `$format`). Only the leaves carrying a `Pentax.pm`
/// `Condition` are gated; every confirmed-unconditional leaf returns
/// [`ConditionalLeaf::Emit`].
///
/// Gated leaves and the variant the port implements (all others ⇒ `Suppress`):
///
/// * `0x000d FocusMode` (`Pentax.pm:1170-1217`) — variant 1
///   `Condition => '$$self{Make} !~ /^Asahi/'` (the "Pentax models" hash). The
///   "Asahi models" variant (a DIFFERENT 4-entry hash) is DEFERRED, so an Asahi
///   body ⇒ `Suppress` (never the Pentax-models labels). A `None` Make (MOV/AVI
///   videos carry no Make) is `!~ /^Asahi/` (Perl undef never matches) ⇒ the
///   ported variant, mirroring the ExifTool comment "can't test for PENTAX
///   because MOV videos don't have Make".
/// * `0x000e AFPointSelected` (`Pentax.pm:1219-1408`) — the `Notes => 'other
///   models'` variant (the 18-entry [`AF_POINT_SELECTED`] element-0 hash), which
///   the K10D selects (it is neither `/(K-1|645Z)\b/` nor `/(K-3|KP)\b/`). The
///   K-1/645Z and K-3/KP model variants (different point hashes) and the count-2
///   second positional element (the Single-Point/Expanded-Area hash) are
///   DEFERRED.
/// * `0x000f AFPointsInFocus` (`Pentax.pm:1409-1465`, #311) — variant 1, the
///   int32u 27-bit BITMASK, `Condition => '$$self{Model} =~ /K-(3|S1|S2)\b/'`
///   (`Notes => 'K-3, K-S1 and K-S2 only'`). A model NOT matching — INCLUDING a
///   `None` model (undef `=~` is false) — ⇒ `Suppress`, because its 0x000f is the
///   DEFERRED variant 2 (`Notes => 'other models'`, the int16u 10-entry enum
///   `{0xffff=>'None', 0=>'Fixed Center or Multiple', …}`), never the bitmask
///   flattened onto a foreign layout.
/// * `0x0016 ExposureCompensation` (`Pentax.pm:1593-1614`) — variant 1
///   `Condition => '$count == 1'` (int16u, `($val-50)/10`). The count-2 variant
///   (a 2nd, meaning-unknown value) is DEFERRED.
/// * `0x001d FocalLength` (`Pentax.pm:1738-1758`) — variant 2 (`$val/100`, the
///   K100D / *istD / most-bodies layout), selected when the Model does NOT match
///   `/^PENTAX Optio (30|33WR|43WR|450|550|555|750Z|X)\b/`. An Optio body in that
///   list uses variant 1 (`$val/10`, a 10× different focal length) ⇒ `Suppress`.
/// * `0x002d EffectiveLV` (`Pentax.pm:1884-1903`) — variant 1
///   `Condition => '$format eq "int16u"'` (re-read as int16s, `$val/1024`). The
///   variant-2 `$format eq "int32u"` record (re-read as int32s) is DEFERRED, and
///   any OTHER on-disk format matches NEITHER ExifTool variant ⇒ `Suppress`
///   (never the int16s decoder applied to a non-int16u record).
/// * `0x004d FlashExposureComp` (`Pentax.pm:2182-2198`) — variant 1
///   `Condition => '$count == 1'` (int32s, `$val/256`). The count-2 K-3 int8s
///   array variant (`ValueConv => ['$val/6']`, the 2nd value's meaning unknown)
///   is DEFERRED.
/// * `0x0062 RawDevelopmentProcess` (`Pentax.pm:2298-2323`) — the single row
///   `Condition => '$$self{Make} =~ /^(PENTAX|RICOH)/'` (rules out Kodak, which
///   reuses this tag id with a different meaning). A Make that is neither PENTAX
///   nor RICOH — INCLUDING a `None` Make — ⇒ `Suppress` (Perl `undef =~` is
///   false), so the [`RAW_DEVELOPMENT_PROCESS`] hash never decodes a foreign
///   vendor's value.
///
/// Confirmed UNCONDITIONAL #173 Main leaves (no `Pentax.pm` `Condition`; a
/// `Count => N` is an element count, not a variant gate) ⇒ always `Emit`, each
/// via an EXPLICIT arm (not the catch-all): `0x000c FlashMode` (array PrintConv,
/// `Count => -1`), `0x0018 AutoBracketing` (`Count => -1`), `0x0032 ImageEditing`
/// (`Count => 4`, `Format => int8u`), `0x0033 PictureMode` (`Count => 3`,
/// `Relist`), `0x0034 DriveMode` (`Count => 4`). `0x005d ShutterCount` also has
/// an explicit `Emit` arm so it is structurally enumerated, but its REAL gate
/// (`length($val)==4` RawConv) lives at its own emit site, NOT here. Every other
/// id (pre-#173 / unported) returns [`ConditionalLeaf::EmitUnported`].
#[must_use]
pub fn conditional_leaf(
  id: u16,
  count: usize,
  model: Option<&str>,
  make: Option<&str>,
  on_disk_format: Format,
) -> ConditionalLeaf {
  /// Sugar: `cond` true ⇒ `Emit`, else `Suppress`.
  const fn gate(cond: bool) -> ConditionalLeaf {
    if cond {
      ConditionalLeaf::Emit
    } else {
      ConditionalLeaf::Suppress
    }
  }
  match id {
    // ---- GATED #173 leaves ----
    // `$$self{Make} !~ /^Asahi/` selects the ported "Pentax models" variant; an
    // Asahi body (the deferred "Asahi models" hash) ⇒ suppress. A `None` Make
    // (videos) is `!~ /^Asahi/` ⇒ emit.
    0x000d => gate(make.is_none_or(|m| !make_prefix_match(m, "Asahi"))),
    // The "other models" variant — selected when the model is NOT K-1/645Z and
    // NOT K-3/KP (those use the deferred model-keyed 0x000e arms). The
    // [`PentaxPrintConv::AfPointSelected`] conv now renders the FULL int16u[N]
    // array (element 0 the 11-point hash, element 1 the Single-Point/Expanded-Area
    // hash), so BOTH the K10D single-element (`'Center'`) and the K-S2
    // two-element (`'Center; Single Point'`) records emit. A `None` model can only
    // be the non-K-1/3 arm.
    0x000e => {
      let is_k1_645z =
        model.is_some_and(|m| model_word_match(m, "K-1") || model_word_match(m, "645Z"));
      let is_k3_kp = model.is_some_and(|m| model_word_match(m, "K-3") || model_word_match(m, "KP"));
      gate(!is_k1_645z && !is_k3_kp)
    }
    // `0x000f AFPointsInFocus` (`Pentax.pm:1409-1465`) — TWO variants selected by
    // `Condition`. The port implements variant 1, the int32u 27-bit BITMASK
    // (`PrintHex`, `{0=>'(none)', BITMASK=>{...}}`), whose `Condition` is
    // `$$self{Model} =~ /K-(3|S1|S2)\b/` (`Notes => 'K-3, K-S1 and K-S2 only'`).
    // A model NOT matching ⇒ suppress: its 0x000f is variant 2 (the int16u
    // `Notes => 'other models'` 10-entry enum, `{0xffff=>'None', 0=>'Fixed
    // Center or Multiple', …}`), a DIFFERENT layout/PrintConv that is DEFERRED, so
    // it must NOT be flattened onto the 27-bit bitmask. A `None` model (videos)
    // cannot match the regex (undef `=~` is false) ⇒ suppress. Only the K-3 /
    // K-S2 bodies carry a Main 0x000f (the K-1/KP/K-70 0x000f is the unrelated
    // `0x0238 CAFPointInfo` undef[17] internal; the K10D/K-x/K-5 II have no Main
    // 0x000f — their `AFPointsInFocus` is the separate `0x021f AFInfo` leaf), so
    // this gate is byte-identical across every active and held fixture.
    0x000f => gate(model.is_some_and(is_afpoints_in_focus_bitmask)),
    // `$count == 1` selects the ported int16u variant; the count-2 variant is
    // deferred.
    0x0016 => gate(count == 1),
    // `$val/100` (variant 2) is the ported FocalLength; an Optio body in the
    // `/^PENTAX Optio (30|33WR|43WR|450|550|555|750Z|X)\b/` list uses the
    // deferred `$val/10` variant ⇒ suppress (10× different).
    0x001d => gate(!model.is_some_and(is_optio_div10_focal_length)),
    // `$format eq "int16u"` selects the ported (int16s re-read) variant; the
    // `$format eq "int32u"` variant is deferred, and any other on-disk format
    // matches NEITHER ExifTool variant ⇒ suppress.
    0x002d => gate(matches!(on_disk_format, Format::Int16u)),
    // `0x004d FlashExposureComp` — BOTH variants are ported: the `$count == 1`
    // int32s (`$val/256`) and the `Count => 2` int8s array (`$val/6`).
    // [`PentaxPrintConv::FlashExposureComp`] branches on the element count, so the
    // leaf emits unconditionally (every record matches one variant).
    0x004d => ConditionalLeaf::Emit,
    // `$$self{Make} =~ /^(PENTAX|RICOH)/` rules out Kodak (which reuses this
    // id); a non-PENTAX/RICOH Make — including a `None` Make — ⇒ suppress.
    0x0062 => {
      gate(make.is_some_and(|m| make_prefix_match(m, "PENTAX") || make_prefix_match(m, "RICOH")))
    }
    // ---- Confirmed-UNCONDITIONAL #173 leaves (no `Pentax.pm` Condition) ----
    // A `Count => N` is an element count, NOT a variant gate, so each emits for
    // every context. These have EXPLICIT `Emit` arms (not the catch-all) so the
    // no-flattening invariant is STRUCTURAL: every #173 leaf is matched here, and
    // `_` is reserved for pre-#173 / unported ids alone.
    //
    // `0x000c FlashMode` (array PrintConv, `Count => -1`).
    0x000c => ConditionalLeaf::Emit,
    // `0x0018 AutoBracketing` (`Count => -1`).
    0x0018 => ConditionalLeaf::Emit,
    // `0x0032 ImageEditing` (`Count => 4`, `Format => int8u`).
    0x0032 => ConditionalLeaf::Emit,
    // `0x0033 PictureMode` (`Count => 3`, `Relist`).
    0x0033 => ConditionalLeaf::Emit,
    // `0x0034 DriveMode` (`Count => 4`).
    0x0034 => ConditionalLeaf::Emit,
    // `0x005d ShutterCount` has its REAL gate (`length($val)==4` RawConv) at its
    // own emit site, NOT here; routed through `conditional_leaf` it is
    // unconditional (`Emit`). The explicit arm keeps it out of the catch-all so
    // all 13 #173 Main leaf ids are structurally enumerated.
    0x005d => ConditionalLeaf::Emit,
    // ONLY pre-#173 Phase-1/2 leaves and unported ids reach this catch-all; no
    // #173 leaf falls through (the structural test in `tags/tests.rs` proves it).
    _ => ConditionalLeaf::EmitUnported,
  }
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

/// `0x000d FocusMode` PrintConv (the non-Asahi K10D variant,
/// `Pentax.pm:1174-1206`, `PrintHex`) — sorted by key for binary search.
pub const FOCUS_MODE: &[(i64, &str)] = &[
  (0x00, "Normal"),
  (0x01, "Macro"),
  (0x02, "Infinity"),
  (0x03, "Manual"),
  (0x04, "Super Macro"),
  (0x05, "Pan Focus"),
  (0x06, "Auto-area"),
  (0x07, "Zone Select"),
  (0x08, "Select"),
  (0x09, "Pinpoint"),
  (0x0a, "Tracking"),
  (0x0b, "Continuous"),
  (0x0c, "Snap"),
  (0x10, "AF-S (Focus-priority)"),
  (0x11, "AF-C (Focus-priority)"),
  (0x12, "AF-A (Focus-priority)"),
  (0x20, "Contrast-detect (Focus-priority)"),
  (0x21, "Tracking Contrast-detect (Focus-priority)"),
  (0x110, "AF-S (Release-priority)"),
  (0x111, "AF-C (Release-priority)"),
  (0x112, "AF-A (Release-priority)"),
  (0x120, "Contrast-detect (Release-priority)"),
  (0x8003, "Manual (Macro)"),
  (0x8006, "Auto-area (Macro)"),
  (0x8007, "Zone Select (Macro)"),
  (0x8008, "Select (Macro)"),
  (0x8009, "Pinpoint (Macro)"),
  (0x800a, "Tracking (Macro)"),
  (0x800b, "Continuous (Macro)"),
];

/// `0x000e AFPointSelected` element-0 PrintConv (the "other models" K10D
/// variant, `Pentax.pm:1380-1399`) — sorted by key for binary search. The value
/// is a single `int16u`, so only this (element-0) hash applies; the element-1
/// hash (extended tracking, `Pentax.pm:1400-1407`) is unreachable for a
/// one-element value and is not ported.
pub const AF_POINT_SELECTED: &[(i64, &str)] = &[
  (0, "None"),
  (1, "Upper-left"),
  (2, "Top"),
  (3, "Upper-right"),
  (4, "Left"),
  (5, "Mid-left"),
  (6, "Center"),
  (7, "Mid-right"),
  (8, "Right"),
  (9, "Lower-left"),
  (10, "Bottom"),
  (11, "Lower-right"),
  (0xfffa, "Auto 2"),
  (0xfffb, "AF Select"),
  (0xfffc, "Face Detect AF"),
  (0xfffd, "Automatic Tracking AF"),
  (0xfffe, "Fixed Center"),
  (0xffff, "Auto"),
];

/// `0x0062 RawDevelopmentProcess` PrintConv (`Pentax.pm:2302-2323`) — sorted by
/// key for binary search.
pub const RAW_DEVELOPMENT_PROCESS: &[(i64, &str)] = &[
  (1, "1 (K10D,K200D,K2000,K-m)"),
  (3, "3 (K20D)"),
  (4, "4 (K-7)"),
  (5, "5 (K-x)"),
  (6, "6 (645D)"),
  (7, "7 (K-r)"),
  (8, "8 (K-5,K-5II,K-5IIs)"),
  (9, "9 (Q)"),
  (10, "10 (K-01,K-30,K-50,K-500)"),
  (11, "11 (Q10)"),
  (12, "12 (MX-1,Q-S1,Q7)"),
  (13, "13 (K-3,K-3II)"),
  (14, "14 (645Z)"),
  (15, "15 (K-S1,K-S2)"),
  (16, "16 (K-1)"),
  (17, "17 (K-70)"),
  (18, "18 (KP)"),
  (19, "19 (GR III)"),
  (20, "20 (K-3III)"),
  (21, "21 (K-3IIIMonochrome)"),
];

/// `0x0067 Hue` PrintConv (`Pentax.pm:2329-2340`) — sorted by key. The integer
/// labels (`0 => -2`, …) are stored as their decimal text and render as BARE
/// JSON numbers via the `EscapeJSON` number gate; the textual `Normal`/`None`
/// labels render as strings.
pub const HUE: &[(i64, &str)] = &[
  (0, "-2"),
  (1, "Normal"),
  (2, "2"),
  (3, "-1"),
  (4, "1"),
  (5, "-3"),
  (6, "3"),
  (7, "-4"),
  (8, "4"),
  (65535, "None"),
];

/// `0x0073 MonochromeFilterEffect` PrintConv (`Pentax.pm:2475-2485`) — sorted by
/// key (ExifTool lists `65535` first; binary search requires ascending order).
pub const MONOCHROME_FILTER_EFFECT: &[(i64, &str)] = &[
  (1, "Green"),
  (2, "Yellow"),
  (3, "Orange"),
  (4, "Red"),
  (5, "Magenta"),
  (6, "Blue"),
  (7, "Cyan"),
  (8, "Infrared"),
  (65535, "None"),
];

/// `0x0074 MonochromeToning` PrintConv (`Pentax.pm:2491-2502`) — sorted by key.
/// The integer labels (`0 => -4`, … `4 => 0`, …) render as bare JSON numbers.
pub const MONOCHROME_TONING: &[(i64, &str)] = &[
  (0, "-4"),
  (1, "-3"),
  (2, "-2"),
  (3, "-1"),
  (4, "0"),
  (5, "1"),
  (6, "2"),
  (7, "3"),
  (8, "4"),
  (65535, "None"),
];

/// `0x007b CrossProcess` PrintConv (`Pentax.pm:2569-2577`) — sorted by key.
pub const CROSS_PROCESS: &[(i64, &str)] = &[
  (0, "Off"),
  (1, "Random"),
  (2, "Preset 1"),
  (3, "Preset 2"),
  (4, "Preset 3"),
  (33, "Favorite 1"),
  (34, "Favorite 2"),
  (35, "Favorite 3"),
];

#[cfg(test)]
mod tests;
