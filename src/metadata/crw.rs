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
  // ----- Canon::* MakerNote sub-table records ---------------------------
  /// Records dispatched to ported `Canon::*` MakerNote sub-tables, in walk
  /// order ([`CrwSubTableBlock`]). Re-decoded per [`ConvMode`] at emission.
  sub_table_blocks: Vec<CrwSubTableBlock>,
  // ----- binary image records (rendered as the placeholder) -------------
  /// `RawData` (0x2005) / `JpgFromRaw` (0x2007) / `ThumbnailImage` (0x2008)
  /// records — `(tag Name, byte length)` in walk order. Each renders as the
  /// universal `(Binary data N bytes, use -b option to extract)` placeholder
  /// (`CanonRaw.pm:319-330`, `Binary => 1`).
  binary_records: Vec<(SmolStr, usize)>,
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
      sub_table_blocks: Vec::new(),
      binary_records: Vec::new(),
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

  // ===== Canon sub-table blocks =========================================

  /// The records dispatched to ported `Canon::*` MakerNote sub-tables, in
  /// walk order ([`CrwSubTableBlock`]).
  #[must_use]
  #[inline]
  pub fn sub_table_blocks(&self) -> &[CrwSubTableBlock] {
    &self.sub_table_blocks
  }

  /// The binary image records (`RawData`/`JpgFromRaw`/`ThumbnailImage`) as
  /// `(tag Name, byte length)` in walk order — each renders as the
  /// `(Binary data N bytes, …)` placeholder (`CanonRaw.pm:319-330`).
  #[must_use]
  #[inline]
  pub fn binary_records(&self) -> &[(SmolStr, usize)] {
    &self.binary_records
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

  /// Append a Canon-sub-table record block.
  pub(crate) fn push_sub_table_block(&mut self, block: CrwSubTableBlock) {
    self.sub_table_blocks.push(block);
  }

  /// Append a binary image record by `(name, byte length)` — the
  /// `(Binary data N bytes, …)` placeholder source. Used by the CIFF walker.
  pub(crate) fn push_binary_inner(&mut self, name: &'static str, len: usize) {
    self.binary_records.push((SmolStr::new_static(name), len));
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
