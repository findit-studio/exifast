// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Nikon MakerNote tag tables — `%Image::ExifTool::Nikon::Main`
//! (`Nikon.pm:1778-3260`) plus the readable, UNENCRYPTED sub-tables the
//! bundled fixtures exercise (`%Nikon::AFInfo`, `%Nikon::ColorBalance3`).
//!
//! ## Scope (first Nikon PR)
//!
//! Every readable scalar tag in `%Nikon::Main` is ported with its faithful
//! `Name` + conversion ([`super::printconv::NikonConv`]). The table-level
//! `PRINT_CONV => \&FormatString` is the default for string tags
//! ([`NikonConv::FormatString`]).
//!
//! - `AFInfo` (0x0088, `Nikon.pm:2113-2158`) — a `ProcessBinaryData` table
//!   (BigEndian for DSLRs), UNENCRYPTED → AFAreaMode / AFPoint /
//!   AFPointsInFocus. WALKED.
//! - `ColorBalance0103` (0x0097 `0103` variant, `Nikon.pm:2980`/
//!   `Nikon.pm` `%ColorBalance3`) — D70/D70s, UNENCRYPTED, `Start =>
//!   '$valuePtr + 20'`, 4×int16u → WB_RGBGLevels. WALKED.
//!
//! ## Deferred (encrypted — need `Nikon::Decrypt`, a follow-up issue)
//!
//! `LensData` (0x0098), `ShotInfo*` (0x0091), `FlashInfo*` (0x00a8), and the
//! ENCRYPTED `ColorBalance` variants (0x0097 `0205`/`0209`/`02xx`) are
//! `ProcessNikonEncrypted` sub-tables keyed on the SerialNumber +
//! ShutterCount XOR keystream (`Nikon.pm:13604` `Decrypt`). They carry a
//! deferred [`SubTable`] marker so the parent is NOT emitted (the #177/#223
//! bogus-parent rule), and their decrypted children stay unported here.

#![deny(clippy::indexing_slicing)]

use super::printconv::NikonConv;
use crate::exif::makernotes::vendors::FormatOverride;

/// One Nikon MakerNote leaf / SubDirectory tag.
///
/// D8: no public fields — accessors only.
#[derive(Debug, Clone, Copy)]
pub struct NikonTag {
  /// Nikon IFD tag ID (`Nikon::Main` hash key).
  id: u16,
  /// `Name => '…'` from bundled.
  name: &'static str,
  /// Conversion strategy ([`NikonConv`]).
  conv: NikonConv,
  /// A `Format => '…'` directive that re-reads the value bytes with a
  /// different TIFF format (`None` for most tags).
  format: Option<FormatOverride>,
  /// SubDirectory dispatch target — `Some(_)` when this tag points at a
  /// child table (the value is NOT emitted as a leaf; the #177/#223 rule).
  sub_table: Option<SubTable>,
  /// `Flags => 'SubIFD'` (`$$tagInfo{SubIFD}`) — the SubDirectory value is an
  /// IFD OFFSET (`Start => '$val'`), read with an INTEGER format to locate the
  /// child IFD; it is EXCLUDED from the implicit-`undef` SubDirectory override
  /// (`Exif.pm:6733` `not $$tagInfo{SubIFD}`). Only `PreviewIFD` (0x0011,
  /// `Nikon.pm:1875`) and `NikonScanIFD` (0x0e10, `Nikon.pm:3229`) carry it in
  /// `%Nikon::Main`; every other SubDirectory is a binary block.
  sub_ifd: bool,
  /// `Unknown => 1` / hidden-by-default in bundled (suppressed in `-j`).
  unknown: bool,
}

impl NikonTag {
  /// Nikon IFD tag ID.
  #[must_use]
  #[inline(always)]
  pub const fn id(&self) -> u16 {
    self.id
  }

  /// Tag `Name`.
  #[must_use]
  #[inline(always)]
  pub const fn name(&self) -> &'static str {
    self.name
  }

  /// Conversion strategy.
  #[must_use]
  #[inline(always)]
  pub const fn conv(&self) -> NikonConv {
    self.conv
  }

  /// The optional `Format => '…'` directive.
  #[must_use]
  #[inline(always)]
  pub const fn format(&self) -> Option<FormatOverride> {
    self.format
  }

  /// SubDirectory dispatch target, if this tag is a sub-table pointer.
  #[must_use]
  #[inline(always)]
  pub const fn sub_table(&self) -> Option<SubTable> {
    self.sub_table
  }

  /// `true` when bundled marks this SubDirectory tag `Flags => 'SubIFD'` — its
  /// value is an IFD OFFSET (not a binary block), so the implicit-`undef`
  /// SubDirectory format override (`Exif.pm:6733`) does NOT apply.
  #[must_use]
  #[inline(always)]
  pub const fn is_sub_ifd(&self) -> bool {
    self.sub_ifd
  }

  /// `true` when bundled marks this tag `Unknown => 1` (suppressed in `-j`).
  #[must_use]
  #[inline(always)]
  pub const fn is_unknown(&self) -> bool {
    self.unknown
  }
}

/// Nikon `Main` SubDirectory targets — the ones the port walks plus the
/// ENCRYPTED ones it defers (marker-only, so no bogus parent is emitted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubTable {
  /// `%Nikon::AFInfo` (`Nikon.pm:2113-2158`) — `ProcessBinaryData`,
  /// BigEndian for DSLRs. AFAreaMode (0) / AFPoint (1) / AFPointsInFocus (2).
  /// WALKED.
  AfInfo,
  /// `%Nikon::ColorBalance3` (`%ColorBalance3`) — D70/D70s, `Start =>
  /// '$valuePtr + 20'`, 4×int16u → WB_RGBGLevels. UNENCRYPTED. WALKED.
  ColorBalance0103,
  /// `LensData00`/`01`/`02`/… (0x0098) — `ProcessNikonEncrypted`. DEFERRED.
  LensData,
  /// `ShotInfo*` (0x0091) — `ProcessNikonEncrypted`. DEFERRED.
  ShotInfo,
  /// `FlashInfo*` (0x00a8) — `ProcessNikonEncrypted`. DEFERRED.
  FlashInfo,
  /// The ENCRYPTED `ColorBalance` variants (0x0097 `0205`/`0209`/`02xx`) —
  /// `ProcessNikonEncrypted`. DEFERRED. (The unencrypted `0100`/`0102`/`0103`
  /// route to [`Self::ColorBalance0103`] / are walked.)
  ColorBalanceEncrypted,
  /// Any OTHER `%Nikon::Main` SubDirectory (`PreviewIFD`, `VRInfo`,
  /// `PictureControl`, `ISOInfo`, `WorldTime`, `LocationInfo`, `HDRInfo`,
  /// `AFInfo2`, `NikonSettings`, …) — present in the table so the parent
  /// pointer is suppressed, but the child table is not ported in this PR.
  OtherDeferred,
}

impl SubTable {
  /// `true` when the port walks this sub-table natively (emits its leaves);
  /// `false` when it is deferred (the parent is suppressed, no leaves).
  #[must_use]
  #[inline(always)]
  pub const fn is_walked(self) -> bool {
    matches!(self, SubTable::AfInfo | SubTable::ColorBalance0103)
  }
}

/// `%Image::ExifTool::Nikon::Main` (`Nikon.pm:1778-3260`). Sorted by tag ID
/// for binary-search lookup. Only the readable scalar tags + the
/// fixture-exercised sub-tables are ported; encrypted/Drop'd long-tail
/// sub-tables carry a deferred [`SubTable`] marker.
pub const NIKON_TAGS: &[NikonTag] = &[
  tag(0x0001, "MakerNoteVersion", NikonConv::MakerNoteVersion),
  tag(0x0002, "ISO", NikonConv::Iso),
  tag(0x0003, "ColorMode", NikonConv::FormatString),
  tag(0x0004, "Quality", NikonConv::FormatString),
  tag(0x0005, "WhiteBalance", NikonConv::FormatString),
  tag(0x0006, "Sharpness", NikonConv::FormatString),
  tag(0x0007, "FocusMode", NikonConv::FormatString),
  tag(0x0008, "FlashSetting", NikonConv::FormatString),
  tag(0x0009, "FlashType", NikonConv::FormatString),
  tag(0x000b, "WhiteBalanceFineTune", NikonConv::Raw),
  tag(0x000c, "WB_RBLevels", NikonConv::Raw),
  tag(
    0x000d,
    "ProgramShift",
    NikonConv::SignedFractionPrintFraction,
  ),
  tag(0x000e, "ExposureDifference", NikonConv::ExposureDifference),
  tag(0x000f, "ISOSelection", NikonConv::FormatString),
  // 0x0010 — DataDump (`Nikon.pm:1865`) — `Binary => 1`, no PrintConv.
  // Emits the `(Binary data N bytes, …)` placeholder via `Raw` → Bytes.
  tag(0x0010, "DataDump", NikonConv::Raw),
  // 0x0011 PreviewIFD (`Nikon.pm:1872-1880`) — `Flags => 'SubIFD'`, `Start =>
  // '$val'`: an IFD-pointer, NOT a binary block. EXCLUDED from the
  // implicit-`undef` override (`Exif.pm:6733`).
  sub_ifd(0x0011, "PreviewIFD", SubTable::OtherDeferred),
  tag(0x0012, "FlashExposureComp", NikonConv::FlashExposureComp),
  tag(0x0013, "ISOSetting", NikonConv::IsoSetting),
  sub(0x0014, "ColorBalanceA", SubTable::OtherDeferred),
  tag(0x0016, "ImageBoundary", NikonConv::Raw),
  tag(
    0x0017,
    "ExternalFlashExposureComp",
    NikonConv::FlashExposureComp,
  ),
  tag(
    0x0018,
    "FlashExposureBracketValue",
    NikonConv::BracketFloat1,
  ),
  tag(
    0x0019,
    "ExposureBracketValue",
    NikonConv::ExposureBracketRational,
  ),
  tag(0x001a, "ImageProcessing", NikonConv::FormatString),
  // 0x001b CropHiSpeed (`Nikon.pm:1974`) — `int16u[7]`, the `%cropHiSpeed`
  // `OTHER` sub formats the full record (crop mode + the cropped geometry).
  tag(0x001b, "CropHiSpeed", NikonConv::CropHiSpeed),
  tag(
    0x001c,
    "ExposureTuning",
    NikonConv::SignedFractionPrintFraction,
  ),
  // 0x001d — SerialNumber (`Nikon.pm:1990`) — `PrintConv => undef` disables
  // the inherited FormatString.
  tag(0x001d, "SerialNumber", NikonConv::Raw),
  tag(0x001e, "ColorSpace", NikonConv::ColorSpace),
  sub(0x001f, "VRInfo", SubTable::OtherDeferred),
  tag(0x0020, "ImageAuthentication", NikonConv::OffOn),
  sub(0x0021, "FaceDetect", SubTable::OtherDeferred),
  tag(0x0022, "ActiveD-Lighting", NikonConv::ActiveDLighting),
  sub(0x0023, "PictureControlData", SubTable::OtherDeferred),
  sub(0x0024, "WorldTime", SubTable::OtherDeferred),
  sub(0x0025, "ISOInfo", SubTable::OtherDeferred),
  tag(0x002a, "VignetteControl", NikonConv::VignetteControl),
  sub(0x002b, "DistortInfo", SubTable::OtherDeferred),
  sub(0x002c, "UnknownInfo", SubTable::OtherDeferred),
  sub(0x0032, "UnknownInfo2", SubTable::OtherDeferred),
  tag(0x0034, "ShutterMode", NikonConv::ShutterMode),
  sub(0x0035, "HDRInfo", SubTable::OtherDeferred),
  tag(0x0037, "MechanicalShutterCount", NikonConv::Raw),
  sub(0x0039, "LocationInfo", SubTable::OtherDeferred),
  tag(0x003d, "BlackLevel", NikonConv::Raw),
  tag(0x003e, "ImageSizeRAW", NikonConv::ImageSizeRaw),
  tag(0x003f, "WhiteBalanceFineTune", NikonConv::Raw),
  tag(0x0044, "JPGCompression", NikonConv::JpgCompression),
  tag(0x0045, "CropArea", NikonConv::Raw),
  sub(0x004e, "NikonSettings", SubTable::OtherDeferred),
  tag(0x004f, "ColorTemperatureAuto", NikonConv::Raw),
  sub(0x0051, "MakerNotes0x51", SubTable::OtherDeferred),
  sub(0x0056, "MakerNotes0x56", SubTable::OtherDeferred),
  tag(0x0080, "ImageAdjustment", NikonConv::FormatString),
  tag(0x0081, "ToneComp", NikonConv::FormatString),
  tag(0x0082, "AuxiliaryLens", NikonConv::FormatString),
  tag(0x0083, "LensType", NikonConv::LensType),
  tag(0x0084, "Lens", NikonConv::Lens),
  tag(0x0085, "ManualFocusDistance", NikonConv::Raw),
  tag(0x0086, "DigitalZoom", NikonConv::Raw),
  tag(0x0087, "FlashMode", NikonConv::FlashMode),
  sub(0x0088, "AFInfo", SubTable::AfInfo),
  tag(0x0089, "ShootingMode", NikonConv::ShootingMode),
  tag(0x008b, "LensFStops", NikonConv::LensFStops),
  // 0x008c — ContrastCurve (`Nikon.pm:2200`) — `Binary`/`Drop`, no PrintConv.
  tag(0x008c, "ContrastCurve", NikonConv::Raw),
  tag(0x008d, "ColorHue", NikonConv::FormatString),
  tag(0x008f, "SceneMode", NikonConv::FormatString),
  tag(0x0090, "LightSource", NikonConv::FormatString),
  sub(0x0091, "ShotInfo", SubTable::ShotInfo),
  tag(0x0092, "HueAdjustment", NikonConv::Raw),
  tag(0x0093, "NEFCompression", NikonConv::NefCompression),
  tag(0x0094, "SaturationAdj", NikonConv::Raw),
  tag(0x0095, "NoiseReduction", NikonConv::FormatString),
  // 0x0096 — NEFLinearizationTable (`Nikon.pm`) — `Binary`/`Drop`, no PrintConv.
  tag(0x0096, "NEFLinearizationTable", NikonConv::Raw),
  // 0x0097 — ColorBalance: the unencrypted `0103` (D70/D70s) is WALKED; the
  // other variants (encrypted `02xx`, the early `0100`/`0102`) carry a deferred
  // marker (the dispatcher inspects the version prefix at parse time).
  sub(0x0097, "ColorBalance", SubTable::ColorBalance0103),
  sub(0x0098, "LensData", SubTable::LensData),
  tag(0x0099, "RawImageCenter", NikonConv::Raw),
  tag(0x009a, "SensorPixelSize", NikonConv::SensorPixelSize),
  tag(0x009c, "SceneAssist", NikonConv::FormatString),
  tag(0x009d, "DateStampMode", NikonConv::DateStampMode),
  // 0x009e RetouchHistory (`Nikon.pm:2935`) — `int16u[10]`; ValueConv trims
  // trailing " 0", the ARRAY PrintConv maps each via `%retouchValues`.
  tag(0x009e, "RetouchHistory", NikonConv::RetouchHistory),
  tag(0x00a0, "SerialNumber", NikonConv::FormatString),
  tag(0x00a2, "ImageDataSize", NikonConv::Raw),
  tag(0x00a5, "ImageCount", NikonConv::Raw),
  tag(0x00a6, "DeletedImageCount", NikonConv::Raw),
  tag(0x00a7, "ShutterCount", NikonConv::ShutterCount),
  sub(0x00a8, "FlashInfo", SubTable::FlashInfo),
  tag(0x00a9, "ImageOptimization", NikonConv::FormatString),
  tag(0x00aa, "Saturation", NikonConv::FormatString),
  tag(0x00ab, "VariProgram", NikonConv::FormatString),
  tag(0x00ac, "ImageStabilization", NikonConv::FormatString),
  tag(0x00ad, "AFResponse", NikonConv::FormatString),
  // 0x00b0 MultiExposure / MultiExposure2 (`Nikon.pm:3029`) — ProcessBinaryData
  // SubDirectory(s); deferred (no bogus parent).
  sub(0x00b0, "MultiExposure", SubTable::OtherDeferred),
  tag(0x00b1, "HighISONoiseReduction", NikonConv::HighIsoNr),
  tag(0x00b3, "ToningEffect", NikonConv::FormatString),
  // 0x00b6 PowerUpTime (`Nikon.pm:3071`) — `undef`, RawConv → date/time string.
  tag(0x00b6, "PowerUpTime", NikonConv::PowerUpTime),
  // 0x00b7 AFInfo2 (`Nikon.pm:3095`) — versioned ProcessBinaryData SubDirectory.
  sub(0x00b7, "AFInfo2", SubTable::OtherDeferred),
  // 0x00b8 FileInfo (`Nikon.pm:3122`) — ProcessBinaryData SubDirectory.
  sub(0x00b8, "FileInfo", SubTable::OtherDeferred),
  // 0x00b9 AFTune (`Nikon.pm:3153`) — ProcessBinaryData SubDirectory.
  sub(0x00b9, "AFTune", SubTable::OtherDeferred),
  // 0x00bb RetouchInfo (`Nikon.pm:3158`) — ProcessBinaryData SubDirectory.
  sub(0x00bb, "RetouchInfo", SubTable::OtherDeferred),
  // 0x00bd PictureControlData (`Nikon.pm:3163`) — Binary SubDirectory.
  sub(0x00bd, "PictureControlData", SubTable::OtherDeferred),
  // 0x00bf SilentPhotography (`Nikon.pm:3170`) — `%offOn`.
  tag(0x00bf, "SilentPhotography", NikonConv::OffOn),
  // 0x00c3 BarometerInfo (`Nikon.pm:3174`) — ProcessBinaryData SubDirectory.
  sub(0x00c3, "BarometerInfo", SubTable::OtherDeferred),
  // 0x0e00 PrintIM (`Nikon.pm:3181`) — the PrintIM SubDirectory.
  sub(0x0e00, "PrintIM", SubTable::OtherDeferred),
  // 0x0e01 NikonCaptureData (`Nikon.pm:3192`) — Binary/Drop SubDirectory.
  sub(0x0e01, "NikonCaptureData", SubTable::OtherDeferred),
  // 0x0e09 NikonCaptureVersion (`Nikon.pm:3209`) — `string`, PrintConv => undef.
  tag(0x0e09, "NikonCaptureVersion", NikonConv::Raw),
  // 0x0e0e NikonCaptureOffsets (`Nikon.pm:3216`) — SubDirectory.
  sub(0x0e0e, "NikonCaptureOffsets", SubTable::OtherDeferred),
  // 0x0e10 NikonScanIFD (`Nikon.pm:3226-3234`) — `Flags => 'SubIFD'`, `Start =>
  // '$val'`: an IFD-pointer, EXCLUDED from the implicit-`undef` override.
  sub_ifd(0x0e10, "NikonScanIFD", SubTable::OtherDeferred),
  // 0x0e13 NikonCaptureEditVersions (`Nikon.pm:3235`) — Binary/Drop SubDirectory.
  sub(0x0e13, "NikonCaptureEditVersions", SubTable::OtherDeferred),
  // 0x0e1d NikonICCProfile (`Nikon.pm:3257`) — Binary SubDirectory.
  sub(0x0e1d, "NikonICCProfile", SubTable::OtherDeferred),
  // 0x0e1e NikonCaptureOutput (`Nikon.pm:3270`) — Binary SubDirectory.
  sub(0x0e1e, "NikonCaptureOutput", SubTable::OtherDeferred),
  // 0x0e22 NEFBitDepth (`Nikon.pm:3280`) — `int16u[4]`, space-joined PrintConv.
  tag(0x0e22, "NEFBitDepth", NikonConv::NefBitDepth),
];

/// `%Image::ExifTool::Nikon::Type2` (`Nikon.pm:5369-5382`) — the OLD Nikon
/// MakerNote layout (`"Nikon\0\x01"`, `MakerNoteNikon2`, `MakerNotes.pm:537-545`),
/// e.g. the early E-series Coolpix. EXACTLY eight tags, all PLAIN name
/// mappings: the table has NO table-level `PRINT_CONV` (unlike `%Nikon::Main`)
/// and not one tag carries a `PrintConv`/`ValueConv`/`Format`, so every value
/// is emitted as the raw `ReadValue` scalar ([`NikonConv::Raw`] = identity).
/// Sorted by tag ID for the binary-search [`lookup`].
///
/// CRUX: the IDs 0x0003..0x000b are SHARED with `%Nikon::Main` but name
/// DIFFERENT tags (0x0003 = `Quality` here vs `ColorMode` in `Main`,
/// 0x0007 = `WhiteBalance` here vs `FocusMode` in `Main`, …) — so a type-2
/// MakerNote MUST be walked against THIS table, never `Main`, or the camera
/// data is mislabelled.
pub const NIKON_TYPE2_TAGS: &[NikonTag] = &[
  tag(0x0003, "Quality", NikonConv::Raw),
  tag(0x0004, "ColorMode", NikonConv::Raw),
  tag(0x0005, "ImageAdjustment", NikonConv::Raw),
  tag(0x0006, "CCDSensitivity", NikonConv::Raw),
  tag(0x0007, "WhiteBalance", NikonConv::Raw),
  tag(0x0008, "Focus", NikonConv::Raw),
  tag(0x000a, "DigitalZoom", NikonConv::Raw),
  tag(0x000b, "Converter", NikonConv::Raw),
];

/// Which Nikon tag table a MakerNote IFD is walked against — selected by the
/// header layout (`MakerNotes.pm:48-554`):
///
/// - [`Self::Main`] — `%Image::ExifTool::Nikon::Main` (`Nikon.pm:1778`): the
///   modern type-3 (`"Nikon\0\x02"`) AND headerless Nikon3 (`Make =~
///   /^NIKON/i`) layouts.
/// - [`Self::Type2`] — `%Image::ExifTool::Nikon::Type2` (`Nikon.pm:5369`): the
///   OLD type-2 (`"Nikon\0\x01"`) layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NikonTable {
  /// `%Nikon::Main` — type-3 + headerless.
  Main,
  /// `%Nikon::Type2` — the `"Nikon\0\x01"` layout.
  Type2,
}

impl NikonTable {
  /// The ID-sorted backing slice for this table.
  #[must_use]
  #[inline(always)]
  const fn slice(self) -> &'static [NikonTag] {
    match self {
      NikonTable::Main => NIKON_TAGS,
      NikonTable::Type2 => NIKON_TYPE2_TAGS,
    }
  }

  /// Resolve a tag ID against this table via binary search.
  #[must_use]
  #[inline]
  pub fn lookup(self, id: u16) -> Option<&'static NikonTag> {
    let table = self.slice();
    match table.binary_search_by_key(&id, NikonTag::id) {
      Ok(i) => table.get(i),
      Err(_) => None,
    }
  }
}

/// `%Image::ExifTool::Nikon::AFInfo` (`Nikon.pm:2113-2158`) — a
/// `ProcessBinaryData` table. Position-keyed (byte offset). BigEndian for
/// DSLRs (`$$self{Model} =~ /^NIKON D/i`), LittleEndian otherwise.
pub const AF_INFO: &[AfInfoEntry] = &[
  AfInfoEntry {
    offset: 0,
    name: "AFAreaMode",
    conv: NikonConv::AfAreaMode,
    format: crate::exif::ifd::Format::Int8u,
  },
  AfInfoEntry {
    offset: 1,
    name: "AFPoint",
    conv: NikonConv::AfPoint,
    format: crate::exif::ifd::Format::Int8u,
  },
  AfInfoEntry {
    offset: 2,
    name: "AFPointsInFocus",
    conv: NikonConv::AfPointsInFocus,
    format: crate::exif::ifd::Format::Int16u,
  },
];

/// One `%Nikon::AFInfo` binary-data position.
#[derive(Debug, Clone, Copy)]
pub struct AfInfoEntry {
  /// Byte offset within the AFInfo blob (the `ProcessBinaryData` index).
  pub offset: usize,
  /// Tag `Name`.
  pub name: &'static str,
  /// PrintConv strategy.
  pub conv: NikonConv,
  /// On-disk format of this position.
  pub format: crate::exif::ifd::Format,
}

/// `const`-fn leaf-tag constructor (no sub-table, no format override).
const fn tag(id: u16, name: &'static str, conv: NikonConv) -> NikonTag {
  NikonTag {
    id,
    name,
    conv,
    format: None,
    sub_table: None,
    sub_ifd: false,
    unknown: false,
  }
}

/// `const`-fn SubDirectory-tag constructor (a BINARY-block sub-table: NOT a
/// `SubIFD`, so the implicit-`undef` override `Exif.pm:6733` applies).
const fn sub(id: u16, name: &'static str, sub_table: SubTable) -> NikonTag {
  NikonTag {
    id,
    name,
    conv: NikonConv::Raw,
    format: None,
    sub_table: Some(sub_table),
    sub_ifd: false,
    unknown: false,
  }
}

/// `const`-fn `SubIFD`-pointer constructor (`Flags => 'SubIFD'`, `Start =>
/// '$val'`): the value is an IFD offset read as an integer — EXCLUDED from the
/// implicit-`undef` SubDirectory override (`Exif.pm:6733` `not
/// $$tagInfo{SubIFD}`).
const fn sub_ifd(id: u16, name: &'static str, sub_table: SubTable) -> NikonTag {
  NikonTag {
    id,
    name,
    conv: NikonConv::Raw,
    format: None,
    sub_table: Some(sub_table),
    sub_ifd: true,
    unknown: false,
  }
}

/// Resolve a tag ID against `%Nikon::Main` (the ID-sorted [`NIKON_TAGS`]) via
/// binary search. Convenience for the [`NikonTable::Main`] path; the walker
/// dispatches on [`NikonTable`] so the type-2 layout uses [`NIKON_TYPE2_TAGS`].
#[must_use]
#[inline]
pub fn lookup(id: u16) -> Option<&'static NikonTag> {
  NikonTable::Main.lookup(id)
}

#[cfg(test)]
mod tests {
  use super::*;

  /// `NIKON_TAGS` is sorted by tag ID — required for `binary_search`.
  #[test]
  fn nikon_tags_sorted_by_id() {
    let mut prev: Option<u16> = None;
    for t in NIKON_TAGS {
      if let Some(p) = prev {
        assert!(
          t.id > p,
          "Nikon tag table out of order: 0x{:04x} after 0x{:04x}",
          t.id,
          p
        );
      }
      prev = Some(t.id);
    }
  }

  /// Camera-indexing tags are present with the faithful names.
  #[test]
  fn lookup_finds_core_tags() {
    assert_eq!(lookup(0x0001).unwrap().name(), "MakerNoteVersion");
    assert_eq!(lookup(0x0004).unwrap().name(), "Quality");
    assert_eq!(lookup(0x0005).unwrap().name(), "WhiteBalance");
    assert_eq!(lookup(0x0007).unwrap().name(), "FocusMode");
    assert_eq!(lookup(0x0083).unwrap().name(), "LensType");
    assert_eq!(lookup(0x0084).unwrap().name(), "Lens");
    assert_eq!(lookup(0x0089).unwrap().name(), "ShootingMode");
    assert_eq!(lookup(0x001d).unwrap().name(), "SerialNumber");
    assert_eq!(lookup(0x00a7).unwrap().name(), "ShutterCount");
  }

  /// The encrypted sub-tables carry a DEFERRED (`!is_walked`) marker so the
  /// parent pointer is suppressed (#177/#223), while the two unencrypted ones
  /// are walked.
  #[test]
  fn encrypted_subdirs_are_deferred() {
    assert_eq!(
      lookup(0x0091).unwrap().sub_table(),
      Some(SubTable::ShotInfo)
    );
    assert!(!SubTable::ShotInfo.is_walked());
    assert_eq!(
      lookup(0x0098).unwrap().sub_table(),
      Some(SubTable::LensData)
    );
    assert!(!SubTable::LensData.is_walked());
    assert_eq!(
      lookup(0x00a8).unwrap().sub_table(),
      Some(SubTable::FlashInfo)
    );
    assert!(!SubTable::FlashInfo.is_walked());
    // Walked sub-tables.
    assert_eq!(lookup(0x0088).unwrap().sub_table(), Some(SubTable::AfInfo));
    assert!(SubTable::AfInfo.is_walked());
    assert_eq!(
      lookup(0x0097).unwrap().sub_table(),
      Some(SubTable::ColorBalance0103)
    );
    assert!(SubTable::ColorBalance0103.is_walked());
  }

  /// `Flags => 'SubIFD'` (`$$tagInfo{SubIFD}`) is set on EXACTLY the two
  /// IFD-pointer SubDirectories in `%Nikon::Main` — PreviewIFD (0x0011,
  /// `Nikon.pm:1875`) and NikonScanIFD (0x0e10, `Nikon.pm:3229`) — and on no
  /// binary-block sub-table; it gates the implicit-`undef` override
  /// (`Exif.pm:6733` `not $$tagInfo{SubIFD}`).
  #[test]
  fn sub_ifd_flag_only_on_ifd_pointers() {
    assert!(
      lookup(0x0011).unwrap().is_sub_ifd(),
      "PreviewIFD is a SubIFD"
    );
    assert!(
      lookup(0x0e10).unwrap().is_sub_ifd(),
      "NikonScanIFD is a SubIFD"
    );
    // Binary-block sub-tables are NOT SubIFD ⇒ they GET the undef override.
    for id in [0x0088u16, 0x0097, 0x0091, 0x0098, 0x00a8, 0x001f, 0x0e00] {
      let t = lookup(id).unwrap_or_else(|| panic!("0x{id:04x} missing"));
      assert!(t.sub_table().is_some(), "0x{id:04x} is a SubDirectory");
      assert!(
        !t.is_sub_ifd(),
        "0x{id:04x} is a binary block, NOT a SubIFD"
      );
    }
    // No leaf tag is ever a SubIFD.
    assert!(!lookup(0x0083).unwrap().is_sub_ifd()); // LensType (leaf)
  }

  /// An unknown ID returns `None`.
  #[test]
  fn lookup_unknown_is_none() {
    assert!(lookup(0xFFFF).is_none());
    assert!(lookup(0x7777).is_none());
  }

  /// These readable scalars carry the faithful name + a leaf conv (no
  /// sub-table) so they emit as values, not bogus parents.
  #[test]
  fn newly_ported_readable_scalars() {
    for (id, name) in [
      (0x001b, "CropHiSpeed"),
      (0x009e, "RetouchHistory"),
      (0x00b6, "PowerUpTime"),
      (0x00bf, "SilentPhotography"),
      (0x0e09, "NikonCaptureVersion"),
      (0x0e22, "NEFBitDepth"),
    ] {
      let t = lookup(id).unwrap_or_else(|| panic!("0x{id:04x} missing"));
      assert_eq!(t.name(), name);
      assert!(
        t.sub_table().is_none(),
        "0x{id:04x} {name} is a readable scalar, not a SubDirectory"
      );
    }
  }

  /// Every long-tail `%Nikon::Main` SubDirectory is DEFERRED (`!is_walked`) so
  /// the parent pointer is suppressed (#177/#223) — none emits a bogus parent.
  #[test]
  fn newly_deferred_subdirs_emit_no_parent() {
    for id in [
      0x00b0, 0x00b7, 0x00b8, 0x00b9, 0x00bb, 0x00bd, 0x00c3, 0x0e00, 0x0e01, 0x0e0e, 0x0e10,
      0x0e13, 0x0e1d, 0x0e1e,
    ] {
      let t = lookup(id).unwrap_or_else(|| panic!("0x{id:04x} missing"));
      let sub = t
        .sub_table()
        .unwrap_or_else(|| panic!("0x{id:04x} must be SubDirectory-marked"));
      assert!(
        !sub.is_walked(),
        "0x{id:04x} {} must be deferred (no bogus parent)",
        t.name()
      );
    }
  }

  /// `%Nikon::Type2` (`Nikon.pm:5369-5382`) is EXACTLY the eight plain
  /// name-mapped tags, ID-sorted, every one a leaf `NikonConv::Raw` (no
  /// PrintConv/ValueConv/Format/sub-table). Crucially the SHARED IDs name
  /// DIFFERENT tags than `%Nikon::Main`.
  #[test]
  fn type2_table_is_the_eight_plain_tags() {
    let expect = [
      (0x0003u16, "Quality"),
      (0x0004, "ColorMode"),
      (0x0005, "ImageAdjustment"),
      (0x0006, "CCDSensitivity"),
      (0x0007, "WhiteBalance"),
      (0x0008, "Focus"),
      (0x000a, "DigitalZoom"),
      (0x000b, "Converter"),
    ];
    assert_eq!(NIKON_TYPE2_TAGS.len(), 8);
    let mut prev: Option<u16> = None;
    for (id, name) in expect {
      let t = NikonTable::Type2
        .lookup(id)
        .unwrap_or_else(|| panic!("Type2 0x{id:04x} missing"));
      assert_eq!(t.name(), name);
      assert!(t.sub_table().is_none(), "Type2 tags are leaves");
      assert!(!t.is_sub_ifd());
      assert!(!t.is_unknown());
      assert!(matches!(t.conv(), NikonConv::Raw), "Type2 tags are raw");
      assert!(t.format().is_none(), "no Format directive");
      if let Some(p) = prev {
        assert!(id > p, "Type2 table out of order");
      }
      prev = Some(id);
    }
    // The shared IDs diverge from %Nikon::Main — Type2 0x0003/0x0007 name
    // Quality/WhiteBalance, where Main names ColorMode/FocusMode.
    assert_eq!(NikonTable::Type2.lookup(0x0003).unwrap().name(), "Quality");
    assert_eq!(NikonTable::Main.lookup(0x0003).unwrap().name(), "ColorMode");
    assert_eq!(
      NikonTable::Type2.lookup(0x0007).unwrap().name(),
      "WhiteBalance"
    );
    assert_eq!(NikonTable::Main.lookup(0x0007).unwrap().name(), "FocusMode");
    // An ID outside the eight is unknown in Type2 (e.g. LensType 0x0083 is a
    // Main-only tag) — so it is dropped on the type-2 path.
    assert!(NikonTable::Type2.lookup(0x0083).is_none());
    assert!(NikonTable::Type2.lookup(0x0001).is_none()); // MakerNoteVersion is Main-only
  }

  /// The AFInfo binary-data positions are the faithful three.
  #[test]
  fn af_info_positions() {
    assert_eq!(AF_INFO.len(), 3);
    assert_eq!(AF_INFO.first().unwrap().name, "AFAreaMode");
    assert_eq!(AF_INFO.get(1).unwrap().name, "AFPoint");
    assert_eq!(AF_INFO.get(2).unwrap().name, "AFPointsInFocus");
  }
}
