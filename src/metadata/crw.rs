// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! The faithful Canon CRW (CIFF) parse layer — a typed mirror of the records
//! decoded by [`crate::formats::crw::ProcessCrw`].
//!
//! These structs follow the source-format shape (`CanonRaw.pm`'s
//! `%Image::ExifTool::CanonRaw::Main` record table + its binary sub-tables —
//! `MakeModel`, `ImageFormat`, `TimeStamp`, `ExposureInfo`, …). The CRW
//! container ALSO dispatches a handful of records to the ALREADY-PORTED
//! `Image::ExifTool::Canon` MakerNote sub-tables (`Canon::CameraSettings`,
//! `Canon::ShotInfo`, `Canon::FocalLength`, `Canon::AFInfo`,
//! `Canon::FileInfo`), whose decoded `(name, value)` emissions are carried
//! here verbatim and re-rendered per [`ConvMode`](crate::emit::ConvMode) at
//! emission time.
//!
//! The normalized [`crate::metadata::MediaMetadata`] projection (golden L2) is
//! built FROM this layer via the [`crate::metadata::Project`] impl on
//! [`crate::formats::crw::ProcessCrw`]'s `Meta`.
//!
//! D8: no public struct fields anywhere; accessors only. Enums are
//! newtype/unit-only.

#![cfg(feature = "crw")]

use crate::exif::ifd::ByteOrder;
use smol_str::SmolStr;
use std::vec::Vec;

// ===========================================================================
// CrwSubTable — which already-ported Canon MakerNote sub-table a CIFF record
// dispatches to (CanonRaw.pm:229-310)
// ===========================================================================

/// The already-ported `Image::ExifTool::Canon` MakerNote sub-table a
/// `CanonRaw::Main` record dispatches to (`CanonRaw.pm:229-310`). The CRW
/// walker reuses the existing Canon decoders for these records, so their
/// emissions carry the `Canon` family-1 group (not `CanonRaw`).
///
/// D8: enum unit-variant only; `as_str` + predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CrwSubTable {
  /// `0x1029` `CanonFocalLength` → `Canon::FocalLength` (`CanonRaw.pm:229`).
  FocalLength,
  /// `0x102a` `CanonShotInfo` → `Canon::ShotInfo` (`CanonRaw.pm:234`).
  ShotInfo,
  /// `0x102d` `CanonCameraSettings` → `Canon::CameraSettings`
  /// (`CanonRaw.pm:243`).
  CameraSettings,
  /// `0x1038` `CanonAFInfo` → `Canon::AFInfo` (`CanonRaw.pm:289`).
  AfInfo,
  /// `0x1093` `CanonFileInfo` → `Canon::FileInfo` (`CanonRaw.pm:294`).
  FileInfo,
  /// `0x1031` `SensorInfo` → `Canon::SensorInfo` (`CanonRaw.pm:149-153`).
  /// Sensor + black-mask border coordinates.
  SensorInfo,
  /// `0x10a9` `ColorBalance` → `Canon::ColorBalance` (`CanonRaw.pm:203-207`).
  /// The `WB_RGGBLevels{Auto,Daylight,…}` quads.
  ColorBalance,
}

impl CrwSubTable {
  /// The `Canon::*` table name (for diagnostics/tests).
  #[must_use]
  #[inline]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::FocalLength => "Canon::FocalLength",
      Self::ShotInfo => "Canon::ShotInfo",
      Self::CameraSettings => "Canon::CameraSettings",
      Self::AfInfo => "Canon::AFInfo",
      Self::FileInfo => "Canon::FileInfo",
      Self::SensorInfo => "Canon::SensorInfo",
      Self::ColorBalance => "Canon::ColorBalance",
    }
  }
}

// ===========================================================================
// CrwSubTableBlock — a retained Canon sub-table record (raw bytes + kind)
// ===========================================================================

/// A `CanonRaw::Main` record that dispatches to a ported `Canon::*` MakerNote
/// sub-table: the kind plus the RAW value bytes (`$$valPt`, in the file's byte
/// order). The bytes are retained so [`crate::formats::crw::ProcessCrw`]'s
/// `Taggable` impl can re-run the existing Canon decoder for the requested
/// [`ConvMode`](crate::emit::ConvMode) (`-j` PrintConv vs `-n` ValueConv),
/// exactly as the EXIF/JPEG MakerNote path does.
///
/// D8: no public fields; accessors only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrwSubTableBlock {
  kind: CrwSubTable,
  bytes: Vec<u8>,
}

impl CrwSubTableBlock {
  /// Construct from the sub-table kind and the raw value bytes.
  #[must_use]
  #[inline]
  pub fn new(kind: CrwSubTable, bytes: Vec<u8>) -> Self {
    Self { kind, bytes }
  }

  /// Which `Canon::*` sub-table this record feeds.
  #[must_use]
  #[inline]
  pub const fn kind(&self) -> CrwSubTable {
    self.kind
  }

  /// The raw value bytes (`$$valPt`).
  #[must_use]
  #[inline]
  pub fn bytes(&self) -> &[u8] {
    &self.bytes
  }
}

// ===========================================================================
// Structural CanonRaw sub-table records (the SubDirectory-record tables)
// ===========================================================================

/// `%Image::ExifTool::CanonRaw::TimeStamp` (`CanonRaw.pm:427-454`). FORMAT
/// `int32u`, FIRST_ENTRY 0, `GROUPS => { 0 => 'MakerNotes', 2 => 'Time' }`.
/// Reached via the `0x180e TimeStamp` SubDirectory record (`CanonRaw.pm:
/// 271-277`).
///
/// D8: no public fields; accessors only.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CrwTimeStamp {
  /// Position 0 `DateTimeOriginal` (`CanonRaw.pm:435-443`) — `int32u` Unix
  /// time, `ValueConv => 'ConvertUnixTime($val)'` (the rendered
  /// `"YYYY:MM:DD HH:MM:SS"` GMT string; the `ConvertDateTime` PrintConv is a
  /// no-op without a custom date format, so `-j` and `-n` agree).
  date_time_original: Option<SmolStr>,
  /// Position 1 `TimeZoneCode` (`CanonRaw.pm:444-449`) — `int32s`,
  /// `ValueConv => '$val / 3600'`. Stored as the POST-ValueConv `f64`: Perl's
  /// `/` is FLOATING-POINT division, so a `+5:30` zone (`19800`) yields `5.5`,
  /// NOT `5` (oracle-confirmed). No `PrintConv` ⇒ `-j` and `-n` agree.
  time_zone_code: Option<f64>,
  /// Position 2 `TimeZoneInfo` (`CanonRaw.pm:450-453`) — `int32u` (raw; set
  /// to `0x80000000` when `TimeZoneCode` is valid).
  time_zone_info: Option<u32>,
}

impl CrwTimeStamp {
  /// `DateTimeOriginal` as the rendered `ConvertUnixTime` string.
  #[must_use]
  #[inline]
  pub fn date_time_original(&self) -> Option<&str> {
    self.date_time_original.as_deref()
  }

  /// `TimeZoneCode` (hours, after the `$val / 3600` FLOATING-POINT ValueConv).
  #[must_use]
  #[inline]
  pub const fn time_zone_code(&self) -> Option<f64> {
    self.time_zone_code
  }

  /// `TimeZoneInfo` (raw int32u).
  #[must_use]
  #[inline]
  pub const fn time_zone_info(&self) -> Option<u32> {
    self.time_zone_info
  }

  /// Crate-private setter for `DateTimeOriginal`.
  pub(crate) fn set_date_time_original(&mut self, v: SmolStr) {
    self.date_time_original = Some(v);
  }

  /// Crate-private setter for `TimeZoneCode` (post-ValueConv `f64`).
  pub(crate) fn set_time_zone_code(&mut self, v: f64) {
    self.time_zone_code = Some(v);
  }

  /// Crate-private setter for `TimeZoneInfo`.
  pub(crate) fn set_time_zone_info(&mut self, v: u32) {
    self.time_zone_info = Some(v);
  }

  /// `true` when no position was decoded.
  #[must_use]
  #[inline]
  pub fn is_empty(&self) -> bool {
    self.date_time_original.is_none()
      && self.time_zone_code.is_none()
      && self.time_zone_info.is_none()
  }
}

/// `%Image::ExifTool::CanonRaw::ExposureInfo` (`CanonRaw.pm:522-545`). FORMAT
/// `float`, FIRST_ENTRY 0, `GROUPS => { 0 => 'MakerNotes', 2 => 'Image' }`.
/// Reached via the `0x1818 ExposureInfo` SubDirectory record (`CanonRaw.pm:
/// 310-315`).
///
/// Each position is stored as its RAW `float` (pre-ValueConv); the
/// per-position ValueConv + PrintConv is applied at emission so the `-j` and
/// `-n` views diverge faithfully:
/// - position 1 `ShutterSpeedValue` ValueConv `abs($val)<100 ? 1/(2**$val) : 0`
///   then PrintConv `Exif::PrintExposureTime` (`CanonRaw.pm:531-537`);
/// - position 2 `ApertureValue` ValueConv `2 ** ($val / 2)` then PrintConv
///   `sprintf("%.1f")` (`CanonRaw.pm:538-544`).
///
/// D8: no public fields; accessors only.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CrwExposureInfo {
  /// Position 0 `ExposureCompensation` (`CanonRaw.pm:530`) — `float`, no conv.
  exposure_compensation: Option<f64>,
  /// Position 1 `ShutterSpeedValue` (`CanonRaw.pm:531-537`) — RAW `float`
  /// apex value (pre-ValueConv). The ValueConv/PrintConv are applied at
  /// emission.
  shutter_speed_value: Option<f64>,
  /// Position 2 `ApertureValue` (`CanonRaw.pm:538-544`) — RAW `float` apex
  /// value (pre-ValueConv). The ValueConv/PrintConv are applied at emission.
  aperture_value: Option<f64>,
}

impl CrwExposureInfo {
  /// `ExposureCompensation` (`float`, no conv).
  #[must_use]
  #[inline]
  pub const fn exposure_compensation(&self) -> Option<f64> {
    self.exposure_compensation
  }
  /// `ShutterSpeedValue` RAW apex value (pre-ValueConv).
  #[must_use]
  #[inline]
  pub const fn shutter_speed_value(&self) -> Option<f64> {
    self.shutter_speed_value
  }
  /// `ApertureValue` RAW apex value (pre-ValueConv).
  #[must_use]
  #[inline]
  pub const fn aperture_value(&self) -> Option<f64> {
    self.aperture_value
  }

  /// `true` when no position was decoded.
  #[must_use]
  #[inline]
  pub fn is_empty(&self) -> bool {
    *self == Self::default()
  }

  // ---- crate-private setters (used by the CIFF walker) ----
  pub(crate) fn set_exposure_compensation(&mut self, v: f64) {
    self.exposure_compensation = Some(v);
  }
  pub(crate) fn set_shutter_speed_value(&mut self, v: f64) {
    self.shutter_speed_value = Some(v);
  }
  pub(crate) fn set_aperture_value(&mut self, v: f64) {
    self.aperture_value = Some(v);
  }
}

/// `%Image::ExifTool::CanonRaw::FlashInfo` (`CanonRaw.pm:510-520`). FORMAT
/// `float`, FIRST_ENTRY 0, `GROUPS => { 0 => 'MakerNotes', 2 => 'Image' }`.
/// Reached via the `0x1813 FlashInfo` SubDirectory record (`CanonRaw.pm:
/// 285-291`). Neither position has a `ValueConv`/`PrintConv`, so the `-j` and
/// `-n` views are identical (the bare float).
///
/// D8: no public fields; accessors only.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CrwFlashInfo {
  /// Position 0 `FlashGuideNumber` (`CanonRaw.pm:518`) — `float`, no conv.
  flash_guide_number: Option<f64>,
  /// Position 1 `FlashThreshold` (`CanonRaw.pm:519`) — `float`, no conv.
  flash_threshold: Option<f64>,
}

impl CrwFlashInfo {
  /// `FlashGuideNumber` (`float`).
  #[must_use]
  #[inline]
  pub const fn flash_guide_number(&self) -> Option<f64> {
    self.flash_guide_number
  }
  /// `FlashThreshold` (`float`).
  #[must_use]
  #[inline]
  pub const fn flash_threshold(&self) -> Option<f64> {
    self.flash_threshold
  }

  /// `true` when no position was decoded.
  #[must_use]
  #[inline]
  pub fn is_empty(&self) -> bool {
    *self == Self::default()
  }

  // ---- crate-private setters (used by the CIFF walker) ----
  pub(crate) fn set_flash_guide_number(&mut self, v: f64) {
    self.flash_guide_number = Some(v);
  }
  pub(crate) fn set_flash_threshold(&mut self, v: f64) {
    self.flash_threshold = Some(v);
  }
}

/// `%Image::ExifTool::CanonRaw::WhiteSample` (`CanonRaw.pm:586-601`, ref 1/4).
/// FORMAT `int16u`, FIRST_ENTRY 1, `GROUPS => { 0 => 'MakerNotes', 2 =>
/// 'Camera' }`. Reached via the `0x1030 WhiteSample` SubDirectory record
/// (`CanonRaw.pm:141-148`), which carries a
/// `Validate => 'Canon::Validate($dirData,$subdirStart,$size)'` gate (the
/// first `int16u` must equal the block byte length, `Canon.pm:10322-10333`).
///
/// Named positions (`CanonRaw.pm:593-600`): position 1 `WhiteSampleWidth`,
/// 2 `WhiteSampleHeight`, 3 `WhiteSampleLeftBorder`, 4 `WhiteSampleTopBorder`,
/// 5 `WhiteSampleBits`, then `0x37` (=55) `BlackLevels` (`Format =>
/// 'int16u[4]'`). The byte offset of position N is `N * 2` (ExifTool's
/// `ProcessBinaryData` indexes by `index * formatSize`; `FIRST_ENTRY` does NOT
/// shift the offset, `ExifTool.pm:9933`). No `PrintConv` on any position ⇒ the
/// `-j` and `-n` views are identical.
///
/// D8: no public fields; accessors only.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CrwWhiteSample {
  /// Position 1 `WhiteSampleWidth` (`CanonRaw.pm:593`) — `int16u`.
  white_sample_width: Option<u16>,
  /// Position 2 `WhiteSampleHeight` (`CanonRaw.pm:594`) — `int16u`.
  white_sample_height: Option<u16>,
  /// Position 3 `WhiteSampleLeftBorder` (`CanonRaw.pm:595`) — `int16u`.
  white_sample_left_border: Option<u16>,
  /// Position 4 `WhiteSampleTopBorder` (`CanonRaw.pm:596`) — `int16u`.
  white_sample_top_border: Option<u16>,
  /// Position 5 `WhiteSampleBits` (`CanonRaw.pm:597`) — `int16u`.
  white_sample_bits: Option<u16>,
  /// Position `0x37` `BlackLevels` (`CanonRaw.pm:600`) — `int16u[4]`, the
  /// available leading words (1..=4) rendered space-joined at emission. A
  /// truncated block yields fewer than 4 words (bundled's `ReadValue` returns
  /// only the words present, `CanonRaw_records` oracle).
  black_levels: Vec<u16>,
}

impl CrwWhiteSample {
  /// `WhiteSampleWidth`.
  #[must_use]
  #[inline]
  pub const fn white_sample_width(&self) -> Option<u16> {
    self.white_sample_width
  }
  /// `WhiteSampleHeight`.
  #[must_use]
  #[inline]
  pub const fn white_sample_height(&self) -> Option<u16> {
    self.white_sample_height
  }
  /// `WhiteSampleLeftBorder`.
  #[must_use]
  #[inline]
  pub const fn white_sample_left_border(&self) -> Option<u16> {
    self.white_sample_left_border
  }
  /// `WhiteSampleTopBorder`.
  #[must_use]
  #[inline]
  pub const fn white_sample_top_border(&self) -> Option<u16> {
    self.white_sample_top_border
  }
  /// `WhiteSampleBits`.
  #[must_use]
  #[inline]
  pub const fn white_sample_bits(&self) -> Option<u16> {
    self.white_sample_bits
  }
  /// `BlackLevels` — the available `int16u[4]` words (0..=4 present).
  #[must_use]
  #[inline]
  pub fn black_levels(&self) -> &[u16] {
    &self.black_levels
  }

  /// `true` when no position was decoded.
  #[must_use]
  #[inline]
  pub fn is_empty(&self) -> bool {
    *self == Self::default()
  }

  // ---- crate-private setters (used by the CIFF walker) ----
  pub(crate) fn set_white_sample_width(&mut self, v: u16) {
    self.white_sample_width = Some(v);
  }
  pub(crate) fn set_white_sample_height(&mut self, v: u16) {
    self.white_sample_height = Some(v);
  }
  pub(crate) fn set_white_sample_left_border(&mut self, v: u16) {
    self.white_sample_left_border = Some(v);
  }
  pub(crate) fn set_white_sample_top_border(&mut self, v: u16) {
    self.white_sample_top_border = Some(v);
  }
  pub(crate) fn set_white_sample_bits(&mut self, v: u16) {
    self.white_sample_bits = Some(v);
  }
  pub(crate) fn set_black_levels(&mut self, v: Vec<u16>) {
    self.black_levels = v;
  }
}

/// `%Image::ExifTool::CanonRaw::ImageInfo` (`CanonRaw.pm:547-570`). FORMAT
/// `int32u`, FIRST_ENTRY 0, `GROUPS => { 0 => 'MakerNotes', 2 => 'Image' }`.
/// Reached via the `0x1810 ImageInfo` SubDirectory record (`CanonRaw.pm:
/// 278-284`).
///
/// D8: no public fields; accessors only.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CrwImageInfo {
  /// Position 0 `ImageWidth` (`CanonRaw.pm:556`) — `int32u`.
  image_width: Option<u32>,
  /// Position 1 `ImageHeight` (`CanonRaw.pm:557`) — `int32u`.
  image_height: Option<u32>,
  /// Position 2 `PixelAspectRatio` (`CanonRaw.pm:558-561`) — `float`.
  pixel_aspect_ratio: Option<f64>,
  /// Position 3 `Rotation` (`CanonRaw.pm:562-566`) — `int32s`.
  rotation: Option<i32>,
  /// Position 4 `ComponentBitDepth` (`CanonRaw.pm:567`) — `int32u`.
  component_bit_depth: Option<u32>,
  /// Position 5 `ColorBitDepth` (`CanonRaw.pm:568`) — `int32u`.
  color_bit_depth: Option<u32>,
  /// Position 6 `ColorBW` (`CanonRaw.pm:569`) — `int32u`.
  color_bw: Option<u32>,
}

impl CrwImageInfo {
  /// `ImageWidth`.
  #[must_use]
  #[inline]
  pub const fn image_width(&self) -> Option<u32> {
    self.image_width
  }
  /// `ImageHeight`.
  #[must_use]
  #[inline]
  pub const fn image_height(&self) -> Option<u32> {
    self.image_height
  }
  /// `PixelAspectRatio` (float).
  #[must_use]
  #[inline]
  pub const fn pixel_aspect_ratio(&self) -> Option<f64> {
    self.pixel_aspect_ratio
  }
  /// `Rotation` (int32s).
  #[must_use]
  #[inline]
  pub const fn rotation(&self) -> Option<i32> {
    self.rotation
  }
  /// `ComponentBitDepth`.
  #[must_use]
  #[inline]
  pub const fn component_bit_depth(&self) -> Option<u32> {
    self.component_bit_depth
  }
  /// `ColorBitDepth`.
  #[must_use]
  #[inline]
  pub const fn color_bit_depth(&self) -> Option<u32> {
    self.color_bit_depth
  }
  /// `ColorBW`.
  #[must_use]
  #[inline]
  pub const fn color_bw(&self) -> Option<u32> {
    self.color_bw
  }

  /// `true` when no position was decoded.
  #[must_use]
  #[inline]
  pub fn is_empty(&self) -> bool {
    *self == Self::default()
  }

  // ---- crate-private setters (used by the CIFF walker) ----
  pub(crate) fn set_image_width(&mut self, v: u32) {
    self.image_width = Some(v);
  }
  pub(crate) fn set_image_height(&mut self, v: u32) {
    self.image_height = Some(v);
  }
  pub(crate) fn set_pixel_aspect_ratio(&mut self, v: f64) {
    self.pixel_aspect_ratio = Some(v);
  }
  pub(crate) fn set_rotation(&mut self, v: i32) {
    self.rotation = Some(v);
  }
  pub(crate) fn set_component_bit_depth(&mut self, v: u32) {
    self.component_bit_depth = Some(v);
  }
  pub(crate) fn set_color_bit_depth(&mut self, v: u32) {
    self.color_bit_depth = Some(v);
  }
  pub(crate) fn set_color_bw(&mut self, v: u32) {
    self.color_bw = Some(v);
  }
}

/// `%Image::ExifTool::CanonRaw::DecoderTable` (`CanonRaw.pm:572-583`, ref 4).
/// FORMAT `int32u`, FIRST_ENTRY 0, `GROUPS => { 0 => 'MakerNotes', 2 =>
/// 'Camera' }`. Reached via the `0x1835 DecoderTable` SubDirectory record
/// (`CanonRaw.pm:327-331`). Positions 0/2/3 are named; position 1 is unnamed.
///
/// D8: no public fields; accessors only.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CrwDecoderTable {
  /// Position 0 `DecoderTableNumber` (`CanonRaw.pm:580`) — `int32u`.
  decoder_table_number: Option<u32>,
  /// Position 2 `CompressedDataOffset` (`CanonRaw.pm:581`) — `int32u`.
  compressed_data_offset: Option<u32>,
  /// Position 3 `CompressedDataLength` (`CanonRaw.pm:582`) — `int32u`.
  compressed_data_length: Option<u32>,
}

impl CrwDecoderTable {
  /// `DecoderTableNumber`.
  #[must_use]
  #[inline]
  pub const fn decoder_table_number(&self) -> Option<u32> {
    self.decoder_table_number
  }
  /// `CompressedDataOffset`.
  #[must_use]
  #[inline]
  pub const fn compressed_data_offset(&self) -> Option<u32> {
    self.compressed_data_offset
  }
  /// `CompressedDataLength`.
  #[must_use]
  #[inline]
  pub const fn compressed_data_length(&self) -> Option<u32> {
    self.compressed_data_length
  }

  /// `true` when no position was decoded.
  #[must_use]
  #[inline]
  pub fn is_empty(&self) -> bool {
    *self == Self::default()
  }

  // ---- crate-private setters (used by the CIFF walker) ----
  pub(crate) fn set_decoder_table_number(&mut self, v: u32) {
    self.decoder_table_number = Some(v);
  }
  pub(crate) fn set_compressed_data_offset(&mut self, v: u32) {
    self.compressed_data_offset = Some(v);
  }
  pub(crate) fn set_compressed_data_length(&mut self, v: u32) {
    self.compressed_data_length = Some(v);
  }
}

/// `%Image::ExifTool::CanonRaw::RawJpgInfo` (`CanonRaw.pm:480-508`). FORMAT
/// `int16u`, FIRST_ENTRY 1, `GROUPS => { 0 => 'MakerNotes', 2 => 'Image' }`.
/// Reached via the `0x10b5 RawJpgInfo` SubDirectory record (`CanonRaw.pm:
/// 208-214`). Position 0 (`RawJpgInfoSize`) is commented out in bundled, so
/// it is not emitted.
///
/// D8: no public fields; accessors only.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CrwRawJpgInfo {
  /// Position 1 `RawJpgQuality` (`CanonRaw.pm:489-497`) — `int16u`, PrintConv
  /// (`1 => Economy, 2 => Normal, 3 => Fine, 5 => Superfine`). Raw int kept;
  /// the PrintConv is applied at emission.
  raw_jpg_quality: Option<u16>,
  /// Position 2 `RawJpgSize` (`CanonRaw.pm:498-505`) — `int16u`, PrintConv
  /// (`0 => Large, 1 => Medium, 2 => Small`). Raw int kept.
  raw_jpg_size: Option<u16>,
  /// Position 3 `RawJpgWidth` (`CanonRaw.pm:506`) — `int16u`.
  raw_jpg_width: Option<u16>,
  /// Position 4 `RawJpgHeight` (`CanonRaw.pm:507`) — `int16u`.
  raw_jpg_height: Option<u16>,
}

impl CrwRawJpgInfo {
  /// `RawJpgQuality` (raw int; PrintConv applied at emission).
  #[must_use]
  #[inline]
  pub const fn raw_jpg_quality(&self) -> Option<u16> {
    self.raw_jpg_quality
  }
  /// `RawJpgSize` (raw int; PrintConv applied at emission).
  #[must_use]
  #[inline]
  pub const fn raw_jpg_size(&self) -> Option<u16> {
    self.raw_jpg_size
  }
  /// `RawJpgWidth`.
  #[must_use]
  #[inline]
  pub const fn raw_jpg_width(&self) -> Option<u16> {
    self.raw_jpg_width
  }
  /// `RawJpgHeight`.
  #[must_use]
  #[inline]
  pub const fn raw_jpg_height(&self) -> Option<u16> {
    self.raw_jpg_height
  }

  /// `true` when no position was decoded.
  #[must_use]
  #[inline]
  pub fn is_empty(&self) -> bool {
    *self == Self::default()
  }

  // ---- crate-private setters (used by the CIFF walker) ----
  pub(crate) fn set_raw_jpg_quality(&mut self, v: u16) {
    self.raw_jpg_quality = Some(v);
  }
  pub(crate) fn set_raw_jpg_size(&mut self, v: u16) {
    self.raw_jpg_size = Some(v);
  }
  pub(crate) fn set_raw_jpg_width(&mut self, v: u16) {
    self.raw_jpg_width = Some(v);
  }
  pub(crate) fn set_raw_jpg_height(&mut self, v: u16) {
    self.raw_jpg_height = Some(v);
  }
}

// ===========================================================================
// CrwRawArray — a NAMED `CanonRaw::Main` record with NO sub-tags / PrintConv,
// whose whole value ExifTool extracts as a numeric array (`ReadValue`)
// ===========================================================================

/// A `%CanonRaw::Main` record that is NAMED but carries no `SubDirectory`, no
/// `PrintConv`, and no `Format` override beyond the `tagType`-derived one —
/// `NullRecord` (`0x0000`), `CanonColorInfo1` (`0x0032`) and `CanonColorInfo2`
/// (`0x102c`). ExifTool reads the whole record value as an array of the
/// `%crwTagFormat{tagType}` format (`int8u` for `0x0000`/`0x0032`, `int16u`
/// for `0x102c`, `CanonRaw.pm:36-44`/`:685`) and emits it via `FoundTag` with
/// NO conversion (`CanonRaw.pm:798-800`).
///
/// The element count is `int(size / formatSize)` (`CanonRaw.pm:735-740`), so an
/// odd remnant byte is dropped (oracle-confirmed: a 5-byte `int16u` record
/// emits 2 values). ExifTool's default rendering is a single bare scalar when
/// the count is 1, else the values space-joined (`"1 2 3 4"`). No `PrintConv`
/// ⇒ the `-j` and `-n` views are identical.
///
/// The decoded values fit `u32` (the widest format here is `int16u`), so they
/// are widened to `u64`. D8: no public fields; accessors only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrwRawArray {
  /// The record's tag Name (`NullRecord` / `CanonColorInfo1` /
  /// `CanonColorInfo2`).
  name: SmolStr,
  /// The decoded array elements (per the `tagType` format), in file order.
  values: Vec<u64>,
}

impl CrwRawArray {
  /// Construct from the tag Name and the decoded array elements.
  #[must_use]
  #[inline]
  pub fn new(name: SmolStr, values: Vec<u64>) -> Self {
    Self { name, values }
  }

  /// The record's tag Name.
  #[must_use]
  #[inline]
  pub fn name(&self) -> &str {
    &self.name
  }

  /// The decoded array elements (per the `tagType` format), in file order.
  #[must_use]
  #[inline]
  pub fn values(&self) -> &[u64] {
    &self.values
  }
}

// ===========================================================================
// CrwMeta — the faithful CRW (CIFF) parse layer
// ===========================================================================

/// The faithful Canon CRW parse layer — a typed mirror of the
/// `%Image::ExifTool::CanonRaw::Main` records decoded by
/// [`crate::formats::crw::ProcessCrw`] (golden L1).
///
/// **Field shape follows `CanonRaw.pm`'s record table.** Every record is
/// optional (a stripped CRW can omit any of them). The SCALAR records are
/// stored as their RAW Rust value (the NUL-trimmed string, the raw `u32`/`f32`
/// etc.); the per-record PrintConv vs ValueConv choice is applied at emission
/// time in [`crate::formats::crw::ProcessCrw`]'s `Taggable` impl so the `-j`
/// and `-n` views diverge faithfully (e.g. `FileFormat` `0x00020001` ⇒ `"CRW"`
/// vs `131073`; `CanonModelID` ⇒ a `%canonModelID` name vs the raw int).
///
/// The records that dispatch to ported `Canon::*` MakerNote sub-tables are
/// retained as [`CrwSubTableBlock`]s ([`Self::sub_table_blocks`]); the byte
/// order + IFD0 `Model` + container `FILE_TYPE` needed to re-decode them are
/// carried alongside.
///
/// D8: no public fields; accessors only. The lifetime `'a` is a phantom today
/// (`CrwMeta` owns its data — every value is transformed during the CIFF
/// walk), kept for GAT uniformity with the other format `Meta` types.
#[derive(Debug, Clone, PartialEq)]
pub struct CrwMeta<'a> {
  // ----- byte order + cross-table context -------------------------------
  /// The CIFF header byte order (`ProcessCRW` `SetByteOrder`, `CanonRaw.pm:
  /// 818`). Drives the sub-table re-decode + the `File:ExifByteOrder`-style
  /// numeric reads.
  order: ByteOrder,
  /// `$$self{Model}` — the IFD0-equivalent body model from the `MakeModel`
  /// sub-table (`CanonRaw::MakeModel` Model, `CanonRaw.pm:417`). Threaded into
  /// the Canon sub-table Conditions (SerialNumber PrintConv, FileInfo
  /// position-1 list, …).
  model: Option<SmolStr>,
  // ----- CanonRaw::Main SCALAR records ----------------------------------
  /// `0x080b CanonFirmwareVersion` (`CanonRaw.pm:204`) — string.
  firmware_version: Option<SmolStr>,
  /// `0x080c ComponentVersion` (`CanonRaw.pm:205`) — string.
  component_version: Option<SmolStr>,
  /// `0x080d ROMOperationMode` (`CanonRaw.pm:206`) — string[8].
  rom_operation_mode: Option<SmolStr>,
  /// `0x0810 OwnerName` (`CanonRaw.pm:207`) — string[32].
  owner_name: Option<SmolStr>,
  /// `0x0815 CanonImageType` (`CanonRaw.pm:208`) — string[32].
  image_type: Option<SmolStr>,
  /// `0x0816 OriginalFileName` (`CanonRaw.pm:209`) — string[32].
  original_file_name: Option<SmolStr>,
  /// `0x0817 ThumbnailFileName` (`CanonRaw.pm:210`) — string[32].
  thumbnail_file_name: Option<SmolStr>,
  /// `MakeModel` sub-table `Make` (`CanonRaw.pm:411`).
  make: Option<SmolStr>,
  // (Model is stored in `model` above — it is ALSO emitted as `CanonRaw:Model`.)
  /// `ImageFormat` sub-table `FileFormat` (`CanonRaw.pm:464`) — raw `int32u`,
  /// PrintHex PrintConv (`0x00020001` ⇒ `"CRW"`).
  file_format: Option<u32>,
  /// `ImageFormat` sub-table `TargetCompressionRatio` (`CanonRaw.pm:474`) —
  /// `float`.
  target_compression_ratio: Option<f64>,
  /// `0x101c BaseISO` (`CanonRaw.pm:198`) — `int16u`.
  base_iso: Option<u16>,
  /// `0x1834 CanonModelID` (`CanonRaw.pm:303`) — raw `int32u`; PrintHex +
  /// `%canonModelID` PrintConv.
  model_id: Option<u32>,
  /// `0x183b SerialNumberFormat` (`CanonRaw.pm:316`) — raw `int32u`; PrintHex
  /// PrintConv (`0x90000000` ⇒ `"Format 1"`, `0xa0000000` ⇒ `"Format 2"`).
  serial_number_format: Option<u32>,
  /// `0x100a TargetImageType` (`CanonRaw.pm:86-93`) — `int16u`, PrintConv
  /// (`0 => 'Real-world Subject', 1 => 'Written Document'`). Raw int kept.
  target_image_type: Option<u16>,
  /// `0x1010 ShutterReleaseMethod` (`CanonRaw.pm:94-101`) — `int16u`, PrintConv
  /// (`0 => 'Single Shot', 2 => 'Continuous Shooting'`). Raw int kept; the
  /// PrintConv is applied at emission (a miss falls back to the raw int per
  /// ExifTool's default PrintConv).
  shutter_release_method: Option<u16>,
  /// `0x1011 ShutterReleaseTiming` (`CanonRaw.pm:102-109`) — `int16u`, PrintConv
  /// (`0 => 'Priority on shutter', 1 => 'Priority on focus'`). Raw int kept.
  shutter_release_timing: Option<u16>,
  /// `0x1016 ReleaseSetting` (`CanonRaw.pm:110`) — `int16u`, no PrintConv ⇒ the
  /// bare int in both `-j` and `-n`.
  release_setting: Option<u16>,
  /// `0x1806 SelfTimerTime` (`CanonRaw.pm:234-241`) — `int32u`,
  /// `ValueConv => '$val / 1000'`, `PrintConv => '"$val s"'`. Stored as the
  /// POST-ValueConv `f64` (the `$val / 1000` value, FLOATING-POINT — a `10500`
  /// raw yields `10.5`); the `-j` view appends `" s"` to that value, the `-n`
  /// view emits the bare number.
  self_timer_time: Option<f64>,
  /// `0x1807 TargetDistanceSetting` (`CanonRaw.pm:242-247`) — `Format =>
  /// 'float'`, `PrintConv => '"$val mm"'`. Stored as the raw `f64` float; the
  /// `-j` view appends `" mm"`, the `-n` view emits the bare float.
  target_distance_setting: Option<f64>,
  /// `0x1804 RecordID` (`CanonRaw.pm:233`) — `int32u`, no PrintConv.
  record_id: Option<u32>,
  /// `0x1817 FileNumber` (`CanonRaw.pm:303-309`) — `int32u`,
  /// `PrintConv => '$_=$val;s/(\d+)(\d{4})/$1-$2/;$_'` (`116-1602`). Raw kept.
  file_number: Option<u32>,
  /// `0x1814 MeasuredEV` (`CanonRaw.pm:292-302`) — `float`,
  /// `ValueConv => '$val + 5'`. Stored POST-ValueConv (the `+ 5` value); no
  /// PrintConv ⇒ `-j` and `-n` agree.
  measured_ev: Option<f64>,
  /// `0x180b SerialNumber` (`CanonRaw.pm:248-270`) — `int32u`, model-
  /// conditional PrintConv. Raw `int32u` kept; the conv is applied at
  /// emission keyed on `$$self{Model}` (`sprintf("%x-%.5d",…)` for an
  /// `EOS D30`, else `sprintf("%.10d",$val)` for any `EOS`). For a non-EOS
  /// PowerShot body bundled's third arm is `UnknownNumber` (`Unknown => 1`),
  /// so this typed field is set ONLY for an EOS body.
  serial_number: Option<u32>,
  /// `0x0805 UserComment` (`CanonRaw.pm:65-69`) — `string[256]`. The second
  /// arm of the `0x0805` conditional list (the `$$self{DIR_NAME} ne
  /// "ImageDescription"` case).
  user_comment: Option<SmolStr>,
  /// `0x0805 CanonFileDescription` (`CanonRaw.pm:60-64`) — `string[32]`. The
  /// first arm of the `0x0805` conditional list (`$$self{DIR_NAME} eq
  /// "ImageDescription"`).
  canon_file_description: Option<SmolStr>,
  /// `0x10ae ColorTemperature` (`CanonRaw.pm:215-218`) — `int16u`, no
  /// PrintConv.
  color_temperature: Option<u16>,
  /// `0x10b4 ColorSpace` (`CanonRaw.pm:219-227`) — `int16u`, PrintConv
  /// (`1 => sRGB, 2 => Adobe RGB, 0xffff => Uncalibrated`). Raw int kept.
  color_space: Option<u16>,
  // ----- structural sub-table records (the SubDirectory-record tables) --
  /// `0x180e TimeStamp` → [`CrwTimeStamp`] (`CanonRaw.pm:271-277`/`:427-454`).
  time_stamp: Option<CrwTimeStamp>,
  /// `0x1810 ImageInfo` → [`CrwImageInfo`] (`CanonRaw.pm:278-284`/`:547-570`).
  image_info: Option<CrwImageInfo>,
  /// `0x1835 DecoderTable` → [`CrwDecoderTable`] (`CanonRaw.pm:327-331`/
  /// `:572-583`).
  decoder_table: Option<CrwDecoderTable>,
  /// `0x10b5 RawJpgInfo` → [`CrwRawJpgInfo`] (`CanonRaw.pm:208-214`/`:480-508`).
  raw_jpg_info: Option<CrwRawJpgInfo>,
  /// `0x1818 ExposureInfo` → [`CrwExposureInfo`] (`CanonRaw.pm:310-315`/
  /// `:522-545`).
  exposure_info: Option<CrwExposureInfo>,
  /// `0x1813 FlashInfo` → [`CrwFlashInfo`] (`CanonRaw.pm:285-291`/`:510-520`).
  flash_info: Option<CrwFlashInfo>,
  /// `0x1030 WhiteSample` → [`CrwWhiteSample`] (`CanonRaw.pm:141-148`/
  /// `:586-601`).
  white_sample: Option<CrwWhiteSample>,
  // ----- Canon::* MakerNote sub-table records ---------------------------
  /// Records dispatched to ported `Canon::*` MakerNote sub-tables, in walk
  /// order ([`CrwSubTableBlock`]). Re-decoded per [`ConvMode`] at emission.
  sub_table_blocks: Vec<CrwSubTableBlock>,
  // ----- binary image records (rendered as the placeholder) -------------
  /// `RawData` (0x2005) / `JpgFromRaw` (0x2007) / `ThumbnailImage` (0x2008) /
  /// `FreeBytes` (0x0001) records — `(tag Name, byte length)` in walk order.
  /// Each renders as the universal `(Binary data N bytes, use -b option to
  /// extract)` placeholder (`CanonRaw.pm:319-330` `Binary => 1`; `FreeBytes`
  /// `CanonRaw.pm:56-60` `Format => 'undef', Binary => 1`).
  binary_records: Vec<(SmolStr, usize)>,
  /// The NAMED no-conv array records (`NullRecord` 0x0000 / `CanonColorInfo1`
  /// 0x0032 / `CanonColorInfo2` 0x102c) in walk order — each emits its whole
  /// value as a `%crwTagFormat{tagType}` array (space-joined, or a bare scalar
  /// for a single element). See [`CrwRawArray`].
  raw_arrays: Vec<CrwRawArray>,
  /// Phantom carry of `'a` for GAT uniformity.
  _lifetime: core::marker::PhantomData<&'a ()>,
}

impl CrwMeta<'_> {
  /// An empty `CrwMeta` for the given header byte order — every record `None`,
  /// no sub-table blocks. The starting point the CIFF walker fills.
  #[must_use]
  #[inline]
  pub const fn new(order: ByteOrder) -> Self {
    Self {
      order,
      model: None,
      firmware_version: None,
      component_version: None,
      rom_operation_mode: None,
      owner_name: None,
      image_type: None,
      original_file_name: None,
      thumbnail_file_name: None,
      make: None,
      file_format: None,
      target_compression_ratio: None,
      base_iso: None,
      model_id: None,
      serial_number_format: None,
      target_image_type: None,
      shutter_release_method: None,
      shutter_release_timing: None,
      release_setting: None,
      self_timer_time: None,
      target_distance_setting: None,
      record_id: None,
      file_number: None,
      measured_ev: None,
      serial_number: None,
      user_comment: None,
      canon_file_description: None,
      color_temperature: None,
      color_space: None,
      time_stamp: None,
      image_info: None,
      decoder_table: None,
      raw_jpg_info: None,
      exposure_info: None,
      flash_info: None,
      white_sample: None,
      sub_table_blocks: Vec::new(),
      binary_records: Vec::new(),
      raw_arrays: Vec::new(),
      _lifetime: core::marker::PhantomData,
    }
  }

  // ===== byte order + context ===========================================

  /// The CIFF header byte order.
  #[must_use]
  #[inline]
  pub const fn byte_order(&self) -> ByteOrder {
    self.order
  }

  /// `$$self{Model}` (the `MakeModel` sub-table Model). Also emitted as
  /// `CanonRaw:Model`.
  #[must_use]
  #[inline]
  pub fn model(&self) -> Option<&str> {
    self.model.as_deref()
  }

  // ===== scalar accessors ===============================================

  /// `0x080a` `MakeModel.Make` (`CanonRaw.pm:411`).
  #[must_use]
  #[inline]
  pub fn make(&self) -> Option<&str> {
    self.make.as_deref()
  }

  /// `0x080b CanonFirmwareVersion` (`CanonRaw.pm:204`).
  #[must_use]
  #[inline]
  pub fn firmware_version(&self) -> Option<&str> {
    self.firmware_version.as_deref()
  }

  /// `0x080c ComponentVersion` (`CanonRaw.pm:205`).
  #[must_use]
  #[inline]
  pub fn component_version(&self) -> Option<&str> {
    self.component_version.as_deref()
  }

  /// `0x080d ROMOperationMode` (`CanonRaw.pm:206`).
  #[must_use]
  #[inline]
  pub fn rom_operation_mode(&self) -> Option<&str> {
    self.rom_operation_mode.as_deref()
  }

  /// `0x0810 OwnerName` (`CanonRaw.pm:207`).
  #[must_use]
  #[inline]
  pub fn owner_name(&self) -> Option<&str> {
    self.owner_name.as_deref()
  }

  /// `0x0815 CanonImageType` (`CanonRaw.pm:208`).
  #[must_use]
  #[inline]
  pub fn image_type(&self) -> Option<&str> {
    self.image_type.as_deref()
  }

  /// `0x0816 OriginalFileName` (`CanonRaw.pm:209`).
  #[must_use]
  #[inline]
  pub fn original_file_name(&self) -> Option<&str> {
    self.original_file_name.as_deref()
  }

  /// `0x0817 ThumbnailFileName` (`CanonRaw.pm:210`).
  #[must_use]
  #[inline]
  pub fn thumbnail_file_name(&self) -> Option<&str> {
    self.thumbnail_file_name.as_deref()
  }

  /// `ImageFormat.FileFormat` (`CanonRaw.pm:464`) — raw `int32u`.
  #[must_use]
  #[inline]
  pub const fn file_format(&self) -> Option<u32> {
    self.file_format
  }

  /// `ImageFormat.TargetCompressionRatio` (`CanonRaw.pm:474`) — `float`.
  #[must_use]
  #[inline]
  pub const fn target_compression_ratio(&self) -> Option<f64> {
    self.target_compression_ratio
  }

  /// `0x101c BaseISO` (`CanonRaw.pm:198`) — `int16u`.
  #[must_use]
  #[inline]
  pub const fn base_iso(&self) -> Option<u16> {
    self.base_iso
  }

  /// `0x1834 CanonModelID` (`CanonRaw.pm:303`) — raw `int32u`.
  #[must_use]
  #[inline]
  pub const fn model_id(&self) -> Option<u32> {
    self.model_id
  }

  /// `0x183b SerialNumberFormat` (`CanonRaw.pm:316`) — raw `int32u`.
  #[must_use]
  #[inline]
  pub const fn serial_number_format(&self) -> Option<u32> {
    self.serial_number_format
  }

  /// `0x100a TargetImageType` (`CanonRaw.pm:86-93`) — raw `int16u`.
  #[must_use]
  #[inline]
  pub const fn target_image_type(&self) -> Option<u16> {
    self.target_image_type
  }

  /// `0x1010 ShutterReleaseMethod` (`CanonRaw.pm:94-101`) — raw `int16u`.
  #[must_use]
  #[inline]
  pub const fn shutter_release_method(&self) -> Option<u16> {
    self.shutter_release_method
  }

  /// `0x1011 ShutterReleaseTiming` (`CanonRaw.pm:102-109`) — raw `int16u`.
  #[must_use]
  #[inline]
  pub const fn shutter_release_timing(&self) -> Option<u16> {
    self.shutter_release_timing
  }

  /// `0x1016 ReleaseSetting` (`CanonRaw.pm:110`) — raw `int16u`.
  #[must_use]
  #[inline]
  pub const fn release_setting(&self) -> Option<u16> {
    self.release_setting
  }

  /// `0x1806 SelfTimerTime` (`CanonRaw.pm:234-241`) — `int32u`, post-ValueConv
  /// (`$val / 1000`).
  #[must_use]
  #[inline]
  pub const fn self_timer_time(&self) -> Option<f64> {
    self.self_timer_time
  }

  /// `0x1807 TargetDistanceSetting` (`CanonRaw.pm:242-247`) — `float`.
  #[must_use]
  #[inline]
  pub const fn target_distance_setting(&self) -> Option<f64> {
    self.target_distance_setting
  }

  /// `0x1804 RecordID` (`CanonRaw.pm:233`) — `int32u`.
  #[must_use]
  #[inline]
  pub const fn record_id(&self) -> Option<u32> {
    self.record_id
  }

  /// `0x1817 FileNumber` (`CanonRaw.pm:303-309`) — raw `int32u`.
  #[must_use]
  #[inline]
  pub const fn file_number(&self) -> Option<u32> {
    self.file_number
  }

  /// `0x1814 MeasuredEV` (`CanonRaw.pm:292-302`) — `float`, post-ValueConv
  /// (the `$val + 5` value).
  #[must_use]
  #[inline]
  pub const fn measured_ev(&self) -> Option<f64> {
    self.measured_ev
  }

  /// `0x180b SerialNumber` (`CanonRaw.pm:248-270`) — raw `int32u` (EOS body
  /// only).
  #[must_use]
  #[inline]
  pub const fn serial_number(&self) -> Option<u32> {
    self.serial_number
  }

  /// `0x0805 UserComment` (`CanonRaw.pm:65-69`).
  #[must_use]
  #[inline]
  pub fn user_comment(&self) -> Option<&str> {
    self.user_comment.as_deref()
  }

  /// `0x0805 CanonFileDescription` (`CanonRaw.pm:60-64`).
  #[must_use]
  #[inline]
  pub fn canon_file_description(&self) -> Option<&str> {
    self.canon_file_description.as_deref()
  }

  /// `0x10ae ColorTemperature` (`CanonRaw.pm:215-218`) — `int16u`.
  #[must_use]
  #[inline]
  pub const fn color_temperature(&self) -> Option<u16> {
    self.color_temperature
  }

  /// `0x10b4 ColorSpace` (`CanonRaw.pm:219-227`) — raw `int16u`.
  #[must_use]
  #[inline]
  pub const fn color_space(&self) -> Option<u16> {
    self.color_space
  }

  /// `0x180e TimeStamp` sub-table ([`CrwTimeStamp`]).
  #[must_use]
  #[inline]
  pub const fn time_stamp(&self) -> Option<&CrwTimeStamp> {
    self.time_stamp.as_ref()
  }

  /// `0x1810 ImageInfo` sub-table ([`CrwImageInfo`]).
  #[must_use]
  #[inline]
  pub const fn image_info(&self) -> Option<&CrwImageInfo> {
    self.image_info.as_ref()
  }

  /// `0x1835 DecoderTable` sub-table ([`CrwDecoderTable`]).
  #[must_use]
  #[inline]
  pub const fn decoder_table(&self) -> Option<&CrwDecoderTable> {
    self.decoder_table.as_ref()
  }

  /// `0x10b5 RawJpgInfo` sub-table ([`CrwRawJpgInfo`]).
  #[must_use]
  #[inline]
  pub const fn raw_jpg_info(&self) -> Option<&CrwRawJpgInfo> {
    self.raw_jpg_info.as_ref()
  }

  /// `0x1818 ExposureInfo` sub-table ([`CrwExposureInfo`]).
  #[must_use]
  #[inline]
  pub const fn exposure_info(&self) -> Option<&CrwExposureInfo> {
    self.exposure_info.as_ref()
  }

  /// `0x1813 FlashInfo` sub-table ([`CrwFlashInfo`]).
  #[must_use]
  #[inline]
  pub const fn flash_info(&self) -> Option<&CrwFlashInfo> {
    self.flash_info.as_ref()
  }

  /// `0x1030 WhiteSample` sub-table ([`CrwWhiteSample`]).
  #[must_use]
  #[inline]
  pub const fn white_sample(&self) -> Option<&CrwWhiteSample> {
    self.white_sample.as_ref()
  }

  // ===== Canon sub-table blocks =========================================

  /// The records dispatched to ported `Canon::*` MakerNote sub-tables, in
  /// walk order ([`CrwSubTableBlock`]).
  #[must_use]
  #[inline]
  pub fn sub_table_blocks(&self) -> &[CrwSubTableBlock] {
    &self.sub_table_blocks
  }

  /// The binary image records (`RawData`/`JpgFromRaw`/`ThumbnailImage`/
  /// `FreeBytes`) as `(tag Name, byte length)` in walk order — each renders as
  /// the `(Binary data N bytes, …)` placeholder (`CanonRaw.pm:319-330`/`:56-60`).
  #[must_use]
  #[inline]
  pub fn binary_records(&self) -> &[(SmolStr, usize)] {
    &self.binary_records
  }

  /// The NAMED no-conv array records (`NullRecord`/`CanonColorInfo1`/
  /// `CanonColorInfo2`) in walk order ([`CrwRawArray`]).
  #[must_use]
  #[inline]
  pub fn raw_arrays(&self) -> &[CrwRawArray] {
    &self.raw_arrays
  }

  // ===== setters (crate-private, used by the CIFF walker) ===============

  /// Set `$$self{Model}` (and the emitted `CanonRaw:Model`).
  pub(crate) fn set_model(&mut self, v: SmolStr) {
    self.model = Some(v);
  }

  /// Set `MakeModel.Make`.
  pub(crate) fn set_make(&mut self, v: SmolStr) {
    self.make = Some(v);
  }

  /// Set `0x080b CanonFirmwareVersion`.
  pub(crate) fn set_firmware_version(&mut self, v: SmolStr) {
    self.firmware_version = Some(v);
  }

  /// Set `0x080c ComponentVersion`.
  pub(crate) fn set_component_version(&mut self, v: SmolStr) {
    self.component_version = Some(v);
  }

  /// Set `0x080d ROMOperationMode`.
  pub(crate) fn set_rom_operation_mode(&mut self, v: SmolStr) {
    self.rom_operation_mode = Some(v);
  }

  /// Set `0x0810 OwnerName`.
  pub(crate) fn set_owner_name(&mut self, v: SmolStr) {
    self.owner_name = Some(v);
  }

  /// Set `0x0815 CanonImageType`.
  pub(crate) fn set_image_type(&mut self, v: SmolStr) {
    self.image_type = Some(v);
  }

  /// Set `0x0816 OriginalFileName`.
  pub(crate) fn set_original_file_name(&mut self, v: SmolStr) {
    self.original_file_name = Some(v);
  }

  /// Set `0x0817 ThumbnailFileName`.
  pub(crate) fn set_thumbnail_file_name(&mut self, v: SmolStr) {
    self.thumbnail_file_name = Some(v);
  }

  /// Set `ImageFormat.FileFormat` (raw `int32u`).
  pub(crate) fn set_file_format(&mut self, v: u32) {
    self.file_format = Some(v);
  }

  /// Set `ImageFormat.TargetCompressionRatio`.
  pub(crate) fn set_target_compression_ratio(&mut self, v: f64) {
    self.target_compression_ratio = Some(v);
  }

  /// Set `0x101c BaseISO`.
  pub(crate) fn set_base_iso(&mut self, v: u16) {
    self.base_iso = Some(v);
  }

  /// Set `0x1834 CanonModelID` (raw `int32u`).
  pub(crate) fn set_model_id(&mut self, v: u32) {
    self.model_id = Some(v);
  }

  /// Set `0x183b SerialNumberFormat` (raw `int32u`).
  pub(crate) fn set_serial_number_format(&mut self, v: u32) {
    self.serial_number_format = Some(v);
  }

  /// Set `0x100a TargetImageType` (raw `int16u`).
  pub(crate) fn set_target_image_type(&mut self, v: u16) {
    self.target_image_type = Some(v);
  }

  /// Set `0x1010 ShutterReleaseMethod` (raw `int16u`).
  pub(crate) fn set_shutter_release_method(&mut self, v: u16) {
    self.shutter_release_method = Some(v);
  }

  /// Set `0x1011 ShutterReleaseTiming` (raw `int16u`).
  pub(crate) fn set_shutter_release_timing(&mut self, v: u16) {
    self.shutter_release_timing = Some(v);
  }

  /// Set `0x1016 ReleaseSetting` (raw `int16u`).
  pub(crate) fn set_release_setting(&mut self, v: u16) {
    self.release_setting = Some(v);
  }

  /// Set `0x1806 SelfTimerTime` (post-ValueConv `$val / 1000` float).
  pub(crate) fn set_self_timer_time(&mut self, v: f64) {
    self.self_timer_time = Some(v);
  }

  /// Set `0x1807 TargetDistanceSetting` (raw `float`).
  pub(crate) fn set_target_distance_setting(&mut self, v: f64) {
    self.target_distance_setting = Some(v);
  }

  /// Set `0x1804 RecordID`.
  pub(crate) fn set_record_id(&mut self, v: u32) {
    self.record_id = Some(v);
  }

  /// Set `0x1817 FileNumber` (raw `int32u`).
  pub(crate) fn set_file_number(&mut self, v: u32) {
    self.file_number = Some(v);
  }

  /// Set `0x1814 MeasuredEV` (post-ValueConv float).
  pub(crate) fn set_measured_ev(&mut self, v: f64) {
    self.measured_ev = Some(v);
  }

  /// Set `0x180b SerialNumber` (raw `int32u`; EOS body only).
  pub(crate) fn set_serial_number(&mut self, v: u32) {
    self.serial_number = Some(v);
  }

  /// Set `0x0805 UserComment`.
  pub(crate) fn set_user_comment(&mut self, v: SmolStr) {
    self.user_comment = Some(v);
  }

  /// Set `0x0805 CanonFileDescription`.
  pub(crate) fn set_canon_file_description(&mut self, v: SmolStr) {
    self.canon_file_description = Some(v);
  }

  /// Set `0x10ae ColorTemperature` (`int16u`).
  pub(crate) fn set_color_temperature(&mut self, v: u16) {
    self.color_temperature = Some(v);
  }

  /// Set `0x10b4 ColorSpace` (raw `int16u`).
  pub(crate) fn set_color_space(&mut self, v: u16) {
    self.color_space = Some(v);
  }

  /// Set the `0x180e TimeStamp` sub-table.
  pub(crate) fn set_time_stamp(&mut self, v: CrwTimeStamp) {
    self.time_stamp = Some(v);
  }

  /// Set the `0x1810 ImageInfo` sub-table.
  pub(crate) fn set_image_info(&mut self, v: CrwImageInfo) {
    self.image_info = Some(v);
  }

  /// Set the `0x1835 DecoderTable` sub-table.
  pub(crate) fn set_decoder_table(&mut self, v: CrwDecoderTable) {
    self.decoder_table = Some(v);
  }

  /// Set the `0x10b5 RawJpgInfo` sub-table.
  pub(crate) fn set_raw_jpg_info(&mut self, v: CrwRawJpgInfo) {
    self.raw_jpg_info = Some(v);
  }

  /// Set the `0x1818 ExposureInfo` sub-table.
  pub(crate) fn set_exposure_info(&mut self, v: CrwExposureInfo) {
    self.exposure_info = Some(v);
  }

  /// Set the `0x1813 FlashInfo` sub-table.
  pub(crate) fn set_flash_info(&mut self, v: CrwFlashInfo) {
    self.flash_info = Some(v);
  }

  /// Set the `0x1030 WhiteSample` sub-table.
  pub(crate) fn set_white_sample(&mut self, v: CrwWhiteSample) {
    self.white_sample = Some(v);
  }

  /// Append a Canon-sub-table record block.
  pub(crate) fn push_sub_table_block(&mut self, block: CrwSubTableBlock) {
    self.sub_table_blocks.push(block);
  }

  /// Append a binary image record by `(name, byte length)` — the
  /// `(Binary data N bytes, …)` placeholder source. Used by the CIFF walker.
  pub(crate) fn push_binary_inner(&mut self, name: &'static str, len: usize) {
    self.binary_records.push((SmolStr::new_static(name), len));
  }

  /// Append a NAMED no-conv array record (`NullRecord`/`CanonColorInfo1`/
  /// `CanonColorInfo2`). Used by the CIFF walker.
  pub(crate) fn push_raw_array(&mut self, record: CrwRawArray) {
    self.raw_arrays.push(record);
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn empty_meta_has_no_records() {
    let m = CrwMeta::new(ByteOrder::Little);
    assert_eq!(m.byte_order(), ByteOrder::Little);
    assert!(m.make().is_none());
    assert!(m.model().is_none());
    assert!(m.file_format().is_none());
    assert!(m.model_id().is_none());
    assert!(m.sub_table_blocks().is_empty());
  }

  #[test]
  fn setters_populate_scalars() {
    let mut m = CrwMeta::new(ByteOrder::Little);
    m.set_make("Canon".into());
    m.set_model("Canon EOS DIGITAL REBEL".into());
    m.set_file_format(0x0002_0001);
    m.set_model_id(0x0114_0000);
    assert_eq!(m.make(), Some("Canon"));
    assert_eq!(m.model(), Some("Canon EOS DIGITAL REBEL"));
    assert_eq!(m.file_format(), Some(0x0002_0001));
    assert_eq!(m.model_id(), Some(0x0114_0000));
  }

  #[test]
  fn sub_table_block_round_trip() {
    let mut m = CrwMeta::new(ByteOrder::Big);
    m.push_sub_table_block(CrwSubTableBlock::new(
      CrwSubTable::CameraSettings,
      std::vec![1, 2, 3, 4],
    ));
    let b = &m.sub_table_blocks()[0];
    assert_eq!(b.kind(), CrwSubTable::CameraSettings);
    assert_eq!(b.kind().as_str(), "Canon::CameraSettings");
    assert_eq!(b.bytes(), &[1, 2, 3, 4]);
  }
}
