// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Canon MakerNotes — Phase-2 port.
//!
//! Bundled source: `lib/Image/ExifTool/Canon.pm` —
//! `%Image::ExifTool::Canon::Main` (`Canon.pm:1221-2209`).
//!
//! ## Phase 2 scope
//!
//! - `Canon::Main` IFD ([`tags::CANON_TAGS`]) — every named LEAF tag
//!   (~78 entries) with simple PrintConv.
//! - `%canonLensTypes` lookup ([`lens_types::CANON_LENS_TYPES`]) —
//!   534 entries, sorted by `(key_int, key_frac)` for binary search.
//! - `%canonModelID` lookup ([`model_ids::CANON_MODEL_IDS`]) —
//!   357 entries, sorted by ID.
//! - `Canon::CameraSettings` binary sub-table
//!   ([`camera_settings::CAMERA_SETTINGS`]) — 37 named positions
//!   covering LensType / Max+MinFocalLength / FocalUnits / Max+MinAperture /
//!   MacroMode / FlashMode / DriveMode / FocusMode / ExposureMode / etc.
//! - `Canon::FocalLength` binary sub-table — FocalType + FocalLength
//!   (with FocalUnits scaling from CameraSettings).
//! - `Canon::FileInfo` binary sub-table ([`file_info::FILE_INFO`]) —
//!   BracketMode / BracketValue / BracketShotNumber / WBBracketMode /
//!   FilterEffect / ToningEffect / LiveViewShooting (model-agnostic) PLUS
//!   the model-conditional FileNumber / ShutterCount (position 1) and
//!   FocusDistanceUpper / Lower (positions 20/21) — issue #88.
//! - `Canon::ShotInfo` binary sub-table ([`shot_info::CanonShotInfo`]) —
//!   WhiteBalance / SequenceNumber / CameraTemperature / FlashGuideNumber /
//!   AutoExposureBracketing / AEBBracketValue / ControlMode /
//!   FocusDistanceUpper / Lower / MeasuredEV2 / BulbDuration / NDFilter /
//!   FlashOutput (issue #86 part 1). AEBBracketValue uses the shared
//!   [`camera_settings::canon_ev`] APEX decoder.
//! - `Canon::AFInfo` + `Canon::AFInfo2` binary sub-tables
//!   ([`af_info::CanonAFInfo`]) — the `ProcessSerialData` variable-length
//!   reader: NumAFPoints / ValidAFPoints / CanonImage{Width,Height} /
//!   AFImage{Width,Height} / AFArea{Width,Height}(s) / AFAreaXPositions /
//!   AFAreaYPositions / AFPointsInFocus (DecodeBits) / AFAreaMode (v2) /
//!   AFPointsSelected (v2 EOS) / PrimaryAFPoint (non-EOS) — issue #86
//!   part 2.
//!
//! ## Deferred (follow-up issues off #84/#85/#87)
//!
//! - `Canon::ColorData1..12` — raw-color-processing sensor data; #84
//!   (LOW indexing value).
//! - `Canon::CameraInfoXXX` per-model sub-tables (`Canon.pm:1307-1494`
//!   conditional list, ~40 model-specific tables) — #85; the high-
//!   value `CanonCameraSettings` already gives lens/focal/aperture. This
//!   is where `ContinuousShootingSpeed` lives (NOT in ShotInfo).
//! - `Canon::CustomFunctions1`..`Functions5DmkIII` — body-config
//!   tables; #87.
//! - The model-conditional `FocalPlaneX/YSize` at FocalLength[2,3] —
//!   defer (PowerShot+older-EOS-only).
//!
//! The full `Canon::ShotInfo` sub-table (every emitting position 1-33) and
//! the AFInfo `Canon_AFInfo_0x000b` 8-word PowerShot layout (the
//! `AFInfoCount == 36` branch at index 11) are now ported (#164).
//!
//! ## D8 compliance
//!
//! No public fields. Every accessor is `const fn` where possible.

// Golden-v2 Contract 3c (Phase C, slice w2d): panic-safety by construction —
// every raw index/slice in this Canon MakerNote dispatcher is dominated by a
// preceding length/offset guard and converted to a checked `.get()` form. The
// parent `exif` deny propagates here; this file-level deny re-asserts it (the
// sibling Canon submodules + this `mod.rs` re-assert over the makernotes
// `#![allow]` shim while the rest of the subtree stays slice E's scope).
#![deny(clippy::indexing_slicing)]

pub mod af_info;
pub mod body;
pub mod camera_settings;
pub mod color_balance;
pub mod file_info;
pub mod focal_length;
pub mod lens_types;
pub mod model_ids;
pub mod printconv;
pub mod sensor_info;
pub mod serial_info;
pub mod shot_info;
pub mod tags;

use crate::exif::makernotes::VendorEmission;
use crate::value::{Group, Metadata, TagValue};
use smol_str::SmolStr;
use std::vec::Vec;

pub use af_info::CanonAFInfo;
pub use body::{CanonEntry, walk_canon_body, walk_canon_in_tiff};
pub use camera_settings::CAMERA_SETTINGS;
pub use file_info::{FILE_INFO, FileInfoDecoded};
pub use lens_types::{CANON_LENS_TYPES, CanonLensType};
pub use model_ids::{CANON_MODEL_IDS, CanonModelEntry};
pub use printconv::CanonPrintConv;
pub use shot_info::CanonShotInfo;
pub use tags::{CANON_TAGS, CanonTag, SubTable};

use super::super::super::ifd::{ByteOrder, RawValue};

/// Decoded Canon MakerNotes data — populated by [`parse`] when the
/// dispatcher resolved [`Vendor::Canon`](crate::exif::makernotes::Vendor).
///
/// D8: no public fields; accessor-only. `PartialEq` only because the
/// struct carries `(f64, f64)` for `focal_range_mm`; `f64` is not `Eq`.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct MakerNotesCanon {
  // ---- camera-identity (Phase 2 ship-bar) ----
  /// Canon Main 0x10 (`CanonModelID`) — the body identification ID
  /// (lookup against `%canonModelID`).
  model_id: Option<u32>,
  /// Resolved model name from `%canonModelID`.
  model_name: Option<SmolStr>,
  /// Canon Main 0x07 (`CanonFirmwareVersion`) — body firmware string.
  firmware_version: Option<SmolStr>,
  /// Canon Main 0x0c (`SerialNumber`) — body serial number.
  serial_number: Option<u64>,
  /// Canon Main 0x96 (`InternalSerialNumber`) — internal body S/N
  /// (different from the user-facing 0x0c serial).
  internal_serial_number: Option<SmolStr>,
  /// Canon Main 0x95 (`LensModel`) — EXIF-style lens model string when
  /// present (newer Canon bodies write this; older bodies use
  /// CameraSettings[22] LensType instead).
  lens_model_string: Option<SmolStr>,
  /// Canon Main 0x06 (`CanonImageType`) — short image-type identity
  /// string like "Canon EOS DIGITAL REBEL CMOS RAW".
  image_type: Option<SmolStr>,
  /// Canon Main 0x09 (`OwnerName`) — the body's user-set owner name.
  owner_name: Option<SmolStr>,
  // ---- lens-identity (CameraSettings) ----
  /// CameraSettings[22] (`LensType`) — the Canon LensID; lookup
  /// against `%canonLensTypes`.
  lens_type: Option<u16>,
  /// Resolved lens name (or `Unknown (N)` if not in the table).
  lens_name: Option<SmolStr>,
  /// CameraSettings[23,24] — Max/Min focal length in mm (after FocalUnits scaling).
  focal_range_mm: Option<(f64, f64)>,
  // ---- file identity ----
  /// Canon Main 0x08 (`FileNumber`) — body's image counter.
  file_number: Option<u32>,
  /// Canon Main 0x28 (`ImageUniqueID`) — 16-byte hex-encoded unique ID.
  image_unique_id: Option<SmolStr>,
  // ---- deep sub-tables (issue #86 / #88) ----
  /// `Canon::ShotInfo` (Main 0x04) decoded surface.
  shot_info: Option<CanonShotInfo>,
  /// `Canon::AFInfo` (Main 0x12), `Canon::AFInfo2` (Main 0x26) or
  /// `AFInfo3` (Main 0x3c, same AFInfo2 table) decoded surface.
  af_info: Option<CanonAFInfo>,
  /// `Canon::FileInfo` (Main 0x93) model-conditional decode (FileNumber /
  /// ShutterCount / FocusDistance).
  file_info: Option<FileInfoDecoded>,
}

impl MakerNotesCanon {
  /// Build an empty placeholder.
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {
      model_id: None,
      model_name: None,
      firmware_version: None,
      serial_number: None,
      internal_serial_number: None,
      lens_model_string: None,
      image_type: None,
      owner_name: None,
      lens_type: None,
      lens_name: None,
      focal_range_mm: None,
      file_number: None,
      image_unique_id: None,
      shot_info: None,
      af_info: None,
      file_info: None,
    }
  }

  /// `CanonModelID` (`Canon.pm:1583-1589`) — `int32u`. Bundled looks
  /// up `%canonModelID` for a human name.
  #[must_use]
  #[inline(always)]
  pub const fn model_id(&self) -> Option<u32> {
    self.model_id
  }

  /// Resolved model name (from `%canonModelID`).
  #[must_use]
  #[inline]
  pub fn model_name(&self) -> Option<&str> {
    self.model_name.as_deref()
  }

  /// `CanonFirmwareVersion` (`Canon.pm:1256-1259`).
  #[must_use]
  #[inline]
  pub fn firmware_version(&self) -> Option<&str> {
    self.firmware_version.as_deref()
  }

  /// `SerialNumber` (`Canon.pm:1281-1306`) — raw int32u; the user-facing
  /// rendering depends on body model.
  #[must_use]
  #[inline(always)]
  pub const fn serial_number(&self) -> Option<u64> {
    self.serial_number
  }

  /// `InternalSerialNumber` (`Canon.pm:1835-1845`) — body-internal S/N.
  #[must_use]
  #[inline]
  pub fn internal_serial_number(&self) -> Option<&str> {
    self.internal_serial_number.as_deref()
  }

  /// EXIF-style `LensModel` (Canon Main 0x95) — written by newer bodies
  /// in addition to the CameraSettings LensType ID.
  #[must_use]
  #[inline]
  pub fn lens_model_string(&self) -> Option<&str> {
    self.lens_model_string.as_deref()
  }

  /// `CanonImageType` (`Canon.pm:1251-1255`).
  #[must_use]
  #[inline]
  pub fn image_type(&self) -> Option<&str> {
    self.image_type.as_deref()
  }

  /// `OwnerName` (`Canon.pm:1267-1273`).
  #[must_use]
  #[inline]
  pub fn owner_name(&self) -> Option<&str> {
    self.owner_name.as_deref()
  }

  /// Canon LensType ID (CameraSettings position 22).
  #[must_use]
  #[inline(always)]
  pub const fn lens_type(&self) -> Option<u16> {
    self.lens_type
  }

  /// Resolved lens name from `%canonLensTypes`. Prefer this over
  /// [`Self::lens_model_string`] for older bodies that don't write
  /// EXIF LensModel.
  #[must_use]
  #[inline]
  pub fn lens_name(&self) -> Option<&str> {
    self.lens_name.as_deref()
  }

  /// `(min_focal_mm, max_focal_mm)` from `CameraSettings[23,24]` scaled
  /// by `FocalUnits` (position 25).
  #[must_use]
  #[inline(always)]
  pub const fn focal_range_mm(&self) -> Option<(f64, f64)> {
    self.focal_range_mm
  }

  /// `FileNumber` (`Canon.pm:1260-1266`) — body image counter.
  #[must_use]
  #[inline(always)]
  pub const fn file_number(&self) -> Option<u32> {
    self.file_number
  }

  /// `ImageUniqueID` (`Canon.pm:1725-1734`).
  #[must_use]
  #[inline]
  pub fn image_unique_id(&self) -> Option<&str> {
    self.image_unique_id.as_deref()
  }

  /// `Canon::ShotInfo` (Main 0x04) decoded surface — `Canon.pm:2772-3051`
  /// (issue #86). `None` when the body wrote no ShotInfo sub-directory.
  #[must_use]
  #[inline(always)]
  pub const fn shot_info(&self) -> Option<&CanonShotInfo> {
    self.shot_info.as_ref()
  }

  /// `Canon::AFInfo` (Main 0x12), `Canon::AFInfo2` (Main 0x26) or `AFInfo3`
  /// (Main 0x3c, same AFInfo2 table) decoded surface — `Canon.pm:6432-6603`
  /// (issue #86). Inspect [`CanonAFInfo::is_v2`] to tell which record
  /// version was decoded (AFInfo3 reports `is_v2() == true`).
  #[must_use]
  #[inline(always)]
  pub const fn af_info(&self) -> Option<&CanonAFInfo> {
    self.af_info.as_ref()
  }

  /// `Canon::FileInfo` (Main 0x93) model-conditional decode — FileNumber /
  /// ShutterCount / FocusDistance (`Canon.pm:6842-7038`, issue #88).
  #[must_use]
  #[inline(always)]
  pub const fn file_info(&self) -> Option<&FileInfoDecoded> {
    self.file_info.as_ref()
  }

  /// Position-1 `FileNumber` from `Canon::FileInfo` (20D/350D/30D/400D).
  /// Distinct from the Main-IFD 0x08 [`Self::file_number`].
  #[must_use]
  #[inline]
  pub fn file_number_decoded(&self) -> Option<u32> {
    self
      .file_info
      .as_ref()
      .and_then(FileInfoDecoded::file_number)
  }

  /// Position-1 `ShutterCount` from `Canon::FileInfo` (1D/1Ds/1Ds Mk II).
  #[must_use]
  #[inline]
  pub fn shutter_count_decoded(&self) -> Option<u32> {
    self
      .file_info
      .as_ref()
      .and_then(FileInfoDecoded::shutter_count)
  }

  /// `(upper_m, lower_m)` focus-distance pair from `Canon::FileInfo`
  /// positions 20/21. `f64::INFINITY` encodes the bundled `"inf"`. Returns
  /// `None` when position 20 was zero/absent.
  #[must_use]
  #[inline]
  pub fn focus_distance_decoded(&self) -> Option<(f64, Option<f64>)> {
    let fi = self.file_info.as_ref()?;
    let upper = fi.focus_distance_upper_m()?;
    Some((upper, fi.focus_distance_lower_m()))
  }
}

/// Parse a Canon MakerNote blob into a [`MakerNotesCanon`] + the
/// `(group, name, value)` emissions for the MakerNotes JSON sink.
///
/// This wrapper treats the blob as a stand-alone byte slice — out-of-
/// line offsets resolve against the blob itself. Use [`parse_in_tiff`]
/// when the caller has the surrounding TIFF block (the faithful
/// behaviour, since Canon's MakerNotes inherit the parent's `Base`).
#[must_use]
pub fn parse(blob: &[u8], parent_order: ByteOrder) -> (MakerNotesCanon, Vec<VendorEmission>) {
  // Standalone-blob convenience entry: no parent container context, so
  // `model`/`file_type` are `None` (the FILE_TYPE-keyed CRW clause is off).
  parse_in_tiff(blob, 0, blob.len(), parent_order, true, None, None)
}

/// Re-dispatch a Canon CTMD `MakerNoteCanon` (`0x927c`) embedded TIFF block
/// through `Canon::Main` — the `%Canon::ExifInfo` `ProcessProc => ProcessTIFF`
/// hop (`Canon.pm:9845-9852`).
///
/// Unlike the JPEG/TIFF MakerNote (a bare IFD embedded in the parent TIFF), the
/// CTMD `0x927c` block is a COMPLETE TIFF: `ProcessExifInfo` re-dispatches it via
/// `ProcessTIFF` (Canon.pm:10745-10751), so it carries its own `II*\0` / `MM\0*`
/// header + IFD0 offset, and IFD0 IS the Canon MakerNote (`Canon::Main` tags at
/// the top level). This parses the header (the block's OWN byte order, which may
/// differ from the parent), then walks IFD0 with [`parse_in_tiff`] at `mn_offset
/// = ifd0_offset` — the block is self-contained (its out-of-line value offsets
/// are relative to its own start, ExifTool's `DataPos => -($pos + 8)`,
/// Canon.pm:10748), so it walks at base 0.
///
/// Returns the cached [`VendorEmission`]s for `print_conv` (the `Unknown => 1`
/// flag is preserved for the caller's engine to suppress). An empty `Vec` for a
/// block with no valid TIFF header / IFD0 offset. `model` is the body
/// `$$self{Model}` in effect at this block's `ProcessExifInfo` walk position —
/// the IFD0 `Model` of a preceding in-sample `0x8769` `ExifIFD` block
/// (Canon.pm:10739-10751), used to evaluate model-conditional Canon sub-tables
/// (`Canon::ShotInfo` `CameraTemperature`, `Canon::FileInfo` position 1); `None`
/// when no preceding `0x8769` set one. `file_type` is `None` (a `.mov`/`.cr3`
/// container is never "CRW", so the ShotInfo CRW clause stays off).
#[must_use]
pub fn redispatch_ctmd_makernote(
  tiff_block: &[u8],
  print_conv: bool,
  model: Option<&str>,
) -> Vec<VendorEmission> {
  // TIFF header: `[II/MM][0x2a][ifd0_offset:u32]` (8 bytes). Bail on a short /
  // unrecognized header (ExifTool's `ProcessTIFF` would `return 0`).
  let Some(order) = tiff_block
    .first_chunk::<2>()
    .and_then(|m| ByteOrder::from_marker(m))
  else {
    return Vec::new();
  };
  let Some(ifd0_offset) = crate::exif::ifd::get_u32(tiff_block, 4, order) else {
    return Vec::new();
  };
  let ifd0_offset = ifd0_offset as usize;
  // `$offset >= 8 or return 0` (ExifTool.pm:8639): the IFD0 pointer must clear
  // the 8-byte header, and stay within the block.
  if ifd0_offset < 8 || ifd0_offset >= tiff_block.len() {
    return Vec::new();
  }
  // `mn_len` spans from IFD0 to the block end (the walker bounds-checks each
  // entry against `tiff_data.len()` anyway).
  let mn_len = tiff_block.len() - ifd0_offset;
  let (_, emissions) = parse_in_tiff(
    tiff_block,
    ifd0_offset,
    mn_len,
    order,
    print_conv,
    model,
    /* file_type */ None,
  );
  emissions
}

/// The PARSE-time diagnostics a Canon CTMD `MakerNoteCanon` (`0x927c`) embedded
/// TIFF block raises when re-dispatched through `Canon::Main` — the same
/// `%Canon::ExifInfo` `ProcessProc => ProcessTIFF` hop [`redispatch_ctmd_makernote`]
/// walks for emission (`Canon.pm:9845-9852`).
///
/// Bundled re-dispatches the block via `ProcessTIFF` → `ProcessExif` with
/// `$tagTablePtr = Canon::Main` (`Canon.pm:10745-10751`). The ONLY `$et->Warn`
/// that path raises for a structurally-bad block is `ProcessExif`'s top-level
/// IFD0-readability gate (`Exif.pm:6342-6399`) — `Bad <dir> directory`
/// (`Exif.pm:6383`) / `Illegal <dir> directory size` (`Exif.pm:6397`). That gate
/// is tag-table-INDEPENDENT (it runs before any `Canon::Main` lookup), so it
/// matches the standard Exif walker's IFD0 gate verbatim; this reuses
/// [`parse_standalone_tiff_with_base`](crate::exif::parse_standalone_tiff_with_base)
/// (the 1:1 `ProcessExif` port) and keeps ONLY those top-level structural
/// diagnostics (still named `IFD0` — the caller re-maps the token to the
/// `MakerNotes` re-dispatch DirName + forces `$inMakerNotes` minor).
///
/// Crucially, `Canon::Main` has NO Exif sub-directory pointers (`0x8769`
/// ExifIFD / `0x8825` GPS / `0xa005` Interop are NOT `Canon::Main` keys — its
/// own sub-tables are `ProcessBinaryData`, never `ProcessExif` IFD sub-dirs), so
/// a crafted IFD0 carrying such a pointer is NEVER followed and raises NO nested
/// `Bad ExifIFD directory` / `Bad GPS directory`. Dropping every non-top-level
/// diagnostic here is what makes that faithful (the standard Exif walker WOULD
/// follow `0x8769` and emit a spurious nested warning — the bug this fixes).
///
/// A block whose TIFF header does not even parse yields no diagnostics (bundled
/// `ProcessTIFF` `return 0` with no `Bad directory` warning).
///
/// Per-entry value-offset diagnostics (`Bad offset for MakerNotes <tag>` /
/// `Suspicious MakerNotes offset for <tag>`; `Exif.pm:6549`/`:6660`/`:6675`)
/// that bundled's `ProcessExif`-under-`Canon::Main` raises for a READABLE IFD0
/// with a bad value pointer are surfaced SEPARATELY by
/// [`redispatch_ctmd_makernote_value_offset_diagnostics`] (the generic Exif
/// walker reused here models a RAF-backed NON-MakerNotes directory, so it would
/// raise the wrong `Error reading value` text and abort — the in-memory
/// `$inMakerNotes` path warns `Bad offset` / `Suspicious offset` and CONTINUES).
#[must_use]
pub fn redispatch_ctmd_makernote_diagnostics(
  tiff_block: &[u8],
) -> Vec<crate::diagnostics::Diagnostic> {
  use crate::diagnostics::Diagnose;
  // The 1:1 `ProcessExif` IFD0 gate. A header that does not parse ⇒ `None` ⇒ no
  // diagnostic (bundled `ProcessTIFF` `return 0`, no warning).
  let Some(meta) = crate::exif::parse_standalone_tiff_with_base(
    tiff_block, /* base */ 0, /* tiff_type_is_tiff */ false,
    // An embedded `MakerNoteCanon` blob re-dispatched FROM MEMORY is not a
    // top-level `$raf`-backed file, so the CR2 magic is NOT checked (this
    // caller reads only the IFD0 structural diagnostics, never `is_cr2_magic`).
    /* standalone_tiff */
    false, /* file_type */ None,
  ) else {
    return Vec::new();
  };
  // Keep ONLY the top-level IFD0 STRUCTURAL diagnostics — the table-independent
  // readability gate (`Exif.pm:6383`/`:6397`). Nested sub-dir warnings (from
  // following an Exif pointer the generic walker would chase) are NOT what
  // `Canon::Main` raises (it has no Exif sub-dirs); the per-entry value-offset
  // warnings are surfaced by `redispatch_ctmd_makernote_value_offset_diagnostics`
  // with the faithful `$inMakerNotes` text instead of the generic walker's
  // RAF-path `Error reading value`.
  meta
    .diagnostics()
    .into_iter()
    .filter(|d| {
      // ONLY the unreadable/overrunning-directory gate (`Bad <dir> directory`,
      // `Exif.pm:6383`). The `Illegal <dir> directory size` warning
      // (`Exif.pm:6397`) is owned by
      // [`redispatch_ctmd_makernote_value_offset_diagnostics`] (its
      // [`body::classify_canon_directory`] gate), which emits it at the faithful
      // NON-minor level — keeping it here would double-warn AND force it minor.
      d.message().starts_with("Bad IFD0 directory")
    })
    .collect()
}

/// The PER-ENTRY value-offset diagnostics a Canon CTMD `MakerNoteCanon`
/// (`0x927c`) block raises for a READABLE IFD0 whose entry has a bad OUT-OF-LINE
/// value pointer — the `$inMakerNotes` branch of `ProcessExif`-under-`Canon::Main`
/// (`Canon.pm:9845-9852` → `Exif.pm` value-pointer handling).
///
/// This CANNOT reuse the generic Exif walker
/// ([`parse_standalone_tiff_with_base`]) because that walker models a RAF-backed,
/// NON-MakerNotes standalone-TIFF directory: an out-of-bounds out-of-line value
/// takes the `if ($raf)` branch and warns `Error reading value for $dir entry
/// $index …` (`Exif.pm:6594`) then ABORTS the directory (`return 0`,
/// `Exif.pm:6602`). The CTMD `0x927c` block is re-dispatched FROM MEMORY with
/// `$inMakerNotes = 1` (`$$et{INDENT}`-level state set by `ProcessTIFF`), so it
/// takes the no-RAF `else` branch and warns the DIFFERENT text — and CONTINUES
/// the walk (`$bad = 1`, not an abort). This diagnostic-only walk models that
/// branch directly, mirroring [`body::walk_canon_in_tiff`]'s IFD0 parse:
///
/// - `$suspect = $warnCount` if the offset points into the TIFF header
///   (`$valuePtr < 8 and not ZeroOffsetOK`, `Exif.pm:6538`) OR overlaps the
///   directory (`$valuePtr < $dirEnd and $valuePtr+$size > $dirStart`,
///   `Exif.pm:6549`). `Canon::Main` is NOT `ZeroOffsetOK`.
/// - if the value is OUT of bounds (`$valuePtr + $size > $dataLen`,
///   `Exif.pm:6551`; `$valuePtr < 0` is impossible for a `u32` offset) and there
///   is no RAF ⇒ `Bad offset for $dir $tagStr` (`Exif.pm:6660`) + `++$warnCount`
///   ⇒ the trailing `$suspect == $warnCount` test (`Exif.pm:6672`) is now FALSE,
///   so a suspect offset that is ALSO out-of-bounds reports ONLY `Bad offset`.
/// - else if the offset was suspect ⇒ `Suspicious $dir offset for $tagStr`
///   (`Exif.pm:6675`).
///
/// EMISSION: a SUSPECT offset is IN bounds, so bundled's `next`
/// (Exif.pm:6672-6678) SKIPS the entry and emits no value. The shared emission
/// walker [`body::walk_canon_in_tiff`] now `next`-skips the same suspect-offset
/// entry (the identical `value_ptr < 8 || (value_ptr < dir_end && value_end >
/// dir_start)` condition), so the SKIP and this WARNING always agree and no
/// spurious tag is emitted. The `Bad offset` (out-of-bounds) case is likewise
/// dropped by both bundled and the walker.
///
/// `$dir` is the literal token `IFD0` here — the caller
/// ([`crate::formats::canon_ctmd`]) re-maps it to the `$inMakerNotes` `MakerNotes`
/// DirName AND forces the `[minor]` level via the SAME `push_redispatch_diagnostic`
/// path the structural diagnostics use (every emitted `Diagnostic` is already
/// [`Diagnostic::warn_minor`], `$inMakerNotes` ⇒ minor, but the level is forced
/// there regardless). `$tagStr` is resolved against `%Canon::Main`
/// ([`tags::lookup`]) — `$$tagInfo{Name}`, e.g. `CanonFirmwareVersion`; an
/// unknown tag is `tag 0x%.4x` (`Exif.pm:6674`). The diagnostics are emitted in
/// IFD-entry order (matching bundled's walk position). Only OUT-OF-LINE entries
/// (`$size > 4`) carry a value pointer; an inline value (`$size <= 4`) cannot be
/// mis-offset. A header / IFD0 that does not parse yields no per-entry
/// diagnostic (the structural path already covered `Bad … directory`).
#[must_use]
pub fn redispatch_ctmd_makernote_value_offset_diagnostics(
  tiff_block: &[u8],
) -> Vec<crate::diagnostics::Diagnostic> {
  use crate::diagnostics::Diagnostic;
  use crate::exif::ifd::{get_u16, get_u32};
  use body::{CanonDirShape, CanonEntryClass, classify_canon_directory, classify_canon_entry};
  let mut out = Vec::new();
  // TIFF header — bail (no diagnostic) on a short/unrecognized header or an
  // IFD0 pointer that fails the `>= 8`/in-bounds gate (the structural path
  // raised `Bad … directory` for an in-bounds-but-unreadable directory).
  let Some(order) = tiff_block
    .first_chunk::<2>()
    .and_then(|m| ByteOrder::from_marker(m))
  else {
    return out;
  };
  let Some(ifd0_offset) = get_u32(tiff_block, 4, order) else {
    return out;
  };
  let dir_start = ifd0_offset as usize;
  if dir_start < 8 || dir_start >= tiff_block.len() {
    return out;
  }
  // `$dataLen` — the whole re-dispatched TIFF block (`$dataPos == 0`, so a
  // stored value pointer is already a block-relative index — oracle-confirmed).
  let data_len = tiff_block.len();
  // The directory-shape gate — the SAME [`classify_canon_directory`] the
  // emission walk ([`body::walk_canon_in_tiff`]) runs, so the SKIP and the
  // WARNING agree by construction (the R8 fix: the prior `dir_end + 4 <=
  // data_len` gate suppressed the per-entry warnings for a `0`/`2`-byte IFD tail
  // while the emission still skipped — they now share one gate). An
  // `AbortBadDirectory` is the STRUCTURAL path's `Bad <dir> directory`
  // (not raised here); an `AbortIllegalSize` is the NON-minor `Illegal <dir>
  // directory size (<n> entries)` (`Exif.pm:6397`; `$dir` re-mapped by the
  // caller).
  let (num_entries, dir_end) =
    match classify_canon_directory(tiff_block, dir_start, data_len, order) {
      CanonDirShape::Walk {
        num_entries,
        dir_end,
      } => (num_entries, dir_end),
      CanonDirShape::AbortBadDirectory => return out,
      CanonDirShape::AbortIllegalSize { num_entries } => {
        out.push(Diagnostic::warn(std::format!(
          "Illegal IFD0 directory size ({num_entries} entries)"
        )));
        return out;
      }
    };
  let entries_start = dir_start + 2;
  // `$warnCount` (`Exif.pm:6453`) — the per-entry warning counter. Once it
  // exceeds ten, ExifTool emits `Too many warnings -- $dir parsing aborted`
  // (`Warn(..., 2)`, the capital-M `[Minor]` level) at the TOP of the loop and
  // `return 0`s (`Exif.pm:6455-6456`), so the LATER bad entries are never warned
  // about. Tracked here in lock-step with [`body::walk_canon_in_tiff`]'s
  // emission abort (the SAME `bumps_warn_count` predicate), so the SKIP and the
  // WARNING stop on the same entry. (In practice the abort warning is the 12th
  // distinct one and is deduped behind the first `Bad …` warning — first-wins —
  // so it is rarely the surviving `Doc<N>:Track<N>:Warning`; emitting it keeps
  // the warning STREAM faithful regardless.)
  let mut warn_count: u32 = 0;
  for i in 0..num_entries {
    if warn_count > 10 {
      // `Warn("Too many warnings -- $dir parsing aborted", 2)` — `$dir` is the
      // literal `IFD0` token the caller re-maps to `MakerNotes`; ignorable `2`
      // ⇒ `[Minor]` (`warn_minor_behavioral`).
      out.push(Diagnostic::warn_minor_behavioral(
        "Too many warnings -- IFD0 parsing aborted".to_string(),
      ));
      break;
    }
    let entry_off = entries_start + 12 * i;
    let Some(tag_id) = get_u16(tiff_block, entry_off, order) else {
      continue;
    };
    // `$tagStr = $tagInfo ? $$tagInfo{Name} : sprintf('tag 0x%.4x', $tagID)`
    // (`Exif.pm:6674`) — resolved against `%Canon::Main`. The `Invalid size`
    // warning instead uses `TagName` (`Exif.pm:6252-6256`) — `tag 0x%.4x` plus
    // ` Name` for a known tag.
    let known = tags::lookup(tag_id).map(|t| t.name());
    let tag_str = match known {
      Some(name) => name.to_string(),
      None => std::format!("tag 0x{tag_id:04x}"),
    };
    let tag_name = match known {
      Some(name) => std::format!("tag 0x{tag_id:04x} {name}"),
      None => std::format!("tag 0x{tag_id:04x}"),
    };
    let class = classify_canon_entry(
      tiff_block, entry_off, i, dir_start, dir_end, data_len, order,
    );
    // `++$warnCount` for the counted classes (`Exif.pm:6472`/6507/6661/6676).
    if class.bumps_warn_count() {
      warn_count = warn_count.saturating_add(1);
    }
    match class {
      // A read entry (inline or valid out-of-line) raises no value-offset
      // warning. `SilentBadFormat` (a `0` code = IFD zero-padding) is silent by
      // construction (`Exif.pm:6470`).
      CanonEntryClass::Read { .. } | CanonEntryClass::SilentBadFormat { .. } => {}
      // `Bad format (<code>) for <dir> entry <index>` (`Exif.pm:6471`), MINOR
      // (`$inMakerNotes`). For `index == 0` ExifTool ALSO aborts the directory —
      // there are no later entries to warn about, so stopping here matches.
      CanonEntryClass::BadFormat { code, abort } => {
        out.push(Diagnostic::warn_minor(std::format!(
          "Bad format ({code}) for IFD0 entry {i}"
        )));
        if abort {
          break;
        }
      }
      // `Invalid size (<size>) for <dir> <TagName>` (`Exif.pm:6506`), MINOR.
      CanonEntryClass::InvalidSize { size } => {
        out.push(Diagnostic::warn_minor(std::format!(
          "Invalid size ({size}) for IFD0 {tag_name}"
        )));
      }
      // Out of bounds + no RAF ⇒ `Bad offset for <dir> <tagStr>` (`Exif.pm:6660`),
      // MINOR. The `++$warnCount` it does means a co-incident suspect offset is
      // NOT also reported (`$suspect != $warnCount` at `Exif.pm:6672`) — the
      // classifier already gives `BadOffset` precedence over `Suspicious`.
      CanonEntryClass::BadOffset => {
        out.push(Diagnostic::warn_minor(std::format!(
          "Bad offset for IFD0 {tag_str}"
        )));
      }
      // In bounds but suspect ⇒ `Suspicious <dir> offset for <tagStr>`
      // (`Exif.pm:6675`), MINOR.
      CanonEntryClass::Suspicious => {
        out.push(Diagnostic::warn_minor(std::format!(
          "Suspicious IFD0 offset for {tag_str}"
        )));
      }
    }
  }
  out
}

/// Parse with the parent TIFF context.
///
/// `tiff_data` is the parent TIFF block; `mn_offset` is the MakerNote
/// blob's position within `tiff_data`; `mn_len` is the blob length.
/// Out-of-line value offsets in the Canon IFD are TIFF-relative (Canon
/// inherits the parent `Base`). `model` is the parent body's
/// `$$self{Model}` (from IFD0), used to evaluate the FocalLength
/// FocalPlaneX/YSize `Condition` (`Canon.pm:2735-2739`).
///
/// `file_type` is the container's detected `$$self{FILE_TYPE}` — threaded
/// into `Canon::ShotInfo` position 22's RawConv (`Canon.pm:2977`/`:2990`),
/// which keeps a raw-0 ExposureTime only for a CRW container. `None` when the
/// container type is unknown; the embedded JPEG/PNG callers pass `None` (a
/// JPEG/PNG container is never "CRW", so the CRW clause is correctly false).
#[must_use]
pub fn parse_in_tiff(
  tiff_data: &[u8],
  mn_offset: usize,
  mn_len: usize,
  parent_order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
  file_type: Option<&str>,
) -> (MakerNotesCanon, Vec<VendorEmission>) {
  let mut typed = MakerNotesCanon::new();
  let mut emissions: Vec<VendorEmission> = Vec::new();
  let entries = body::walk_canon_in_tiff(tiff_data, mn_offset, mn_len, parent_order, model);
  // Pass 1: walk the Main IFD entries, surfacing leaves and dispatching
  // recognized binary sub-tables. We need to capture FocalUnits from
  // the CameraSettings sub-table (position 25) BEFORE we process the
  // FocalLength sub-table (which uses FocalUnits for scaling). So we
  // do this in TWO passes: first compute the FocalUnits hint by
  // dispatching CameraSettings, then process FocalLength with it.
  let mut focal_units: Option<u16> = None;
  let mut focal_length_data: Option<Vec<u8>> = None;
  // `$$self{LensType}` DataMember — set by CameraSettings position 22's
  // `RawConv => '$val ? $$self{LensType} = $val : undef'` (`Canon.pm:2503`).
  // FileInfo position 16 (`MacroMagnification`, `Canon.pm:6998-7005`) gates
  // on it (`$$self{LensType} == 124`). ExifTool resolves it during the
  // CameraSettings walk (Canon tag 0x01), which precedes FileInfo
  // (0x93) in IFD tag order; we capture it in this sub-pass so the
  // dependency holds regardless of IFD entry order.
  let mut lens_type: Option<u16> = None;
  // Sub-pass: find CameraSettings + FocalLength sub-table data.
  for entry in &entries {
    let Some(def) = tags::lookup(entry.tag_id) else {
      continue;
    };
    let Some(sub) = def.sub_table() else { continue };
    if sub == SubTable::CameraSettings {
      focal_units = read_focal_units(&entry.value, parent_order);
      // Capture the `$$self{LensType}` DataMember (CameraSettings pos 22,
      // `Canon.pm:2503`) for FileInfo position 16's `Condition`.
      let blob_bytes = reserialize_int_array(&entry.value, parent_order);
      camera_settings::parse_with_lens_id_capture(
        &blob_bytes,
        parent_order,
        print_conv,
        &mut lens_type,
      );
    }
    if sub == SubTable::FocalLength {
      // Reserialize the int16u words into bytes for the sub-table parser.
      focal_length_data = Some(reserialize_int_array(&entry.value, parent_order));
    }
  }
  // Now do the main walk.
  for entry in &entries {
    let Some(def) = tags::lookup(entry.tag_id) else {
      continue; // Unknown tag — bundled would emit it under 'Tag 0xNNNN'; we omit.
    };
    // `Unknown => 1` tags (e.g. `0x3 CanonFlashInfo`, `Canon.pm:1239`) are
    // SUPPRESSED in the default (`-j`, no `-u`) output —
    // `ExifTool.pm:9179-9185` returns undef for them unless
    // `-u`/Verbose/HTML_DUMP/Validate is set. We no longer skip them at the
    // collection site: each leaf emission carries `def.is_unknown()` and the
    // emission engine drops the Unknown ones (the legacy `serialize_tags`
    // read-path filters them too). The single `Unknown` Canon::Main tag
    // (`0x03 CanonFlashInfo`) has no sub-table, so it reaches the leaf arm
    // below and is emitted with the flag set; no `Unknown` tag is a
    // typed-accessor source, so nothing else changes.
    if let Some(sub) = def.sub_table() {
      // SubDirectory tag: process the sub-table if Phase 2 handles it;
      // otherwise emit the SubDirectory tag's RAW bytes/name so the
      // caller can see it was present (faithful to ExifTool's verbose
      // output, but simplified — bundled would emit each sub-tag with
      // its own group; the port defers the sub-walk to a follow-up).
      match sub {
        SubTable::CameraSettings => {
          let blob_bytes = reserialize_int_array(&entry.value, parent_order);
          let mut lens_id: Option<u16> = None;
          let cs = camera_settings::parse_with_lens_id_capture(
            &blob_bytes,
            parent_order,
            print_conv,
            &mut lens_id,
          );
          // Capture focal range from the parsed CameraSettings results.
          let mut min_focal: Option<f64> = None;
          let mut max_focal: Option<f64> = None;
          for (n, v) in &cs {
            match n.as_str() {
              "MaxFocalLength" => {
                if let Some(mm) = focal_mm_from_tag_value(v) {
                  max_focal = Some(mm);
                }
              }
              "MinFocalLength" => {
                if let Some(mm) = focal_mm_from_tag_value(v) {
                  min_focal = Some(mm);
                }
              }
              _ => {}
            }
          }
          if let (Some(min), Some(max)) = (min_focal, max_focal) {
            typed.focal_range_mm = Some((min, max));
          }
          // Capture lens identity from the parsed CameraSettings.
          if let Some(id) = lens_id {
            typed.lens_type = Some(id);
            typed.lens_name = lens_types::lookup_name(id);
          }
          // Sub-table position tags are never `Unknown` (they are explicit
          // BinaryData positions), so each emits with `unknown = false`.
          for (name, value) in cs {
            emissions.push(VendorEmission::new(name, value, false));
          }
        }
        SubTable::FileInfo => {
          let blob_bytes = reserialize_int_array(&entry.value, parent_order);
          // Thread the `$$self{LensType}` DataMember (captured from
          // CameraSettings above) and `$$self{Model}` (the parent IFD0 Model,
          // `$$self{Model}`): `lens_type` + `model` gate FileInfo position 16
          // (`MacroMagnification`, `Canon.pm:7002-7005`), and `model`
          // additionally keys the position-1 conditional list
          // (FileNumber/ShutterCount, `Canon.pm:6848-6927`, issue #88). We use
          // the IFD0 Model (not the resolved `%canonModelID` name) because
          // bundled keys these Conditions on `$$self{Model}`.
          let (fi, decoded) =
            file_info::parse_with_model(&blob_bytes, parent_order, print_conv, lens_type, model);
          if decoded != FileInfoDecoded::default() {
            typed.file_info = Some(decoded);
          }
          // Sub-table position tags are never `Unknown` (they are explicit
          // BinaryData positions), so each emits with `unknown = false`.
          for (name, value) in fi {
            emissions.push(VendorEmission::new(name, value, false));
          }
        }
        SubTable::ShotInfo => {
          let blob_bytes = reserialize_int_array(&entry.value, parent_order);
          // Thread the container `$$self{FILE_TYPE}` into ShotInfo position
          // 22's RawConv (CRW-allows-0, `Canon.pm:2977`/`:2990`).
          let (si, em) = shot_info::parse(&blob_bytes, parent_order, print_conv, model, file_type);
          if !si.is_empty() {
            typed.shot_info = Some(si);
          }
          // ShotInfo decodes explicit BinaryData positions; the `Unknown`
          // ones are already excluded inside `shot_info::parse`, so each
          // emitted leaf carries `unknown = false`.
          for (name, value) in em {
            emissions.push(VendorEmission::new(name, value, false));
          }
        }
        SubTable::AfInfo => {
          let blob_bytes = reserialize_int_array(&entry.value, parent_order);
          let (af, em) = af_info::parse_af_info(&blob_bytes, parent_order, print_conv, model);
          if !af.is_empty() {
            typed.af_info = Some(af);
          }
          // AFInfo's `Unknown` scalars (AFInfoSize, etc.) are excluded inside
          // `parse_af_info` (bundled hides them without `-u`); the emitted
          // leaves are explicit positions, so `unknown = false`.
          for (name, value) in em {
            emissions.push(VendorEmission::new(name, value, false));
          }
        }
        SubTable::AfInfo2 => {
          let blob_bytes = reserialize_int_array(&entry.value, parent_order);
          // `Canon::Main` 0x26 `Condition => '$$valPt !~ /^\0\0\0\0/'`
          // (`Canon.pm:1713`): the AFInfo2 SubDirectory is NOT entered when
          // the first four bytes are all zero (e.g. the all-zero 0x26 record
          // in 60D MOV-video thumbnails). Bundled emits NOTHING for it;
          // skipping the walk keeps the default `-j`/`-n` output faithful.
          if !first4_all_zero(&blob_bytes) {
            let (af, em) = af_info::parse_af_info2(&blob_bytes, parent_order, print_conv, model);
            if !af.is_empty() {
              typed.af_info = Some(af);
            }
            for (name, value) in em {
              emissions.push(VendorEmission::new(name, value, false));
            }
          }
        }
        SubTable::AfInfo3 => {
          // `Canon::Main` 0x3c `AFInfo3` (`Canon.pm:1764-1770`): the SAME
          // `Canon::AFInfo2` walker, but `$$self{AFInfo3} = 1` is set (which
          // suppresses the index-14 PrimaryAFPoint). Unlike 0x26 there is NO
          // all-zero `Condition` on 0x3c, so the walk always runs.
          let blob_bytes = reserialize_int_array(&entry.value, parent_order);
          let (af, em) = af_info::parse_af_info3(&blob_bytes, parent_order, print_conv, model);
          if !af.is_empty() {
            typed.af_info = Some(af);
          }
          for (name, value) in em {
            emissions.push(VendorEmission::new(name, value, false));
          }
        }
        SubTable::FocalLength => {
          if let Some(ref bytes) = focal_length_data {
            let fl = focal_length::parse(bytes, parent_order, print_conv, focal_units, model);
            for (name, value) in fl {
              emissions.push(VendorEmission::new(name, value, false));
            }
          }
        }
        SubTable::SensorInfo => {
          // `Canon::SensorInfo` (`Canon.pm:7411-7434`): FORMAT int16s,
          // FIRST_ENTRY 1. Sensor + black-mask border coordinates. No
          // `PrintConv` on any position ⇒ `-j` and `-n` agree.
          let blob_bytes = reserialize_int_array(&entry.value, parent_order);
          let si = sensor_info::parse(&blob_bytes, parent_order, print_conv);
          // Explicit BinaryData positions are never `Unknown`.
          for (name, value) in si {
            emissions.push(VendorEmission::new(name, value, false));
          }
        }
        SubTable::ColorBalance => {
          // `Canon::ColorBalance` (`Canon.pm:7268-7293`): FORMAT int16s,
          // FIRST_ENTRY 0. The WB_RGGBLevels quads. `model` selects the
          // position-29 name (WB_RGGBLevelsCustom vs the D60 BlackLevels,
          // `Canon.pm:7282-7290`). No `PrintConv` ⇒ `-j` and `-n` agree.
          let blob_bytes = reserialize_int_array(&entry.value, parent_order);
          let cb = color_balance::parse(&blob_bytes, parent_order, print_conv, model);
          for (name, value) in cb {
            emissions.push(VendorEmission::new(name, value, false));
          }
        }
        _ => {
          // Every deferred Canon::Main SubDirectory (`is_walked() == false`):
          // the Phase-2 raw set (Panorama / MyColors / FaceDetect1 / FaceDetect2
          // / ContrastInfo / WBInfo / ProcessingInfo / MovieInfo / LensInfo) PLUS
          // the #223 swept-from-`None` set (CameraInfo / CropInfo /
          // CustomFunctions{,1D,2} / AspectInfo / MeasuredColor / ColorData /
          // AFMicroAdj / UnknownD30 / FaceDetect3 / TimeInfo / PersonalFunctions
          // / PersonalFunctionValues / CanonFlags / ModifiedInfo /
          // PreviewImageInfo / ColorInfo / VignettingCorr{,2} / LightingOpt /
          // AmbienceInfo / MultiExp / FilterInfo / HDRInfo / LogInfo / AFConfig /
          // RawBurstModeRoll / FocusBracketingInfo / LevelInfo). A SubDirectory
          // row DESCENDS into a child table and NEVER emits the parent pointer as
          // a value: ExifTool's
          // `ProcessExif` enters the `if ($subdir)` block (`Exif.pm:6919`),
          // processes the sub-directory, then hits `next unless $doMaker or
          // $$et{REQ_TAG_LOOKUP}{…} or $$tagInfo{BlockExtract}`
          // (`Exif.pm:7103-7104`) — for a plain SubDirectory tag in default
          // output (no value emission) that `next` SKIPS `FoundTag`
          // (`Exif.pm:7180`), so the parent is ABSENT from default `-j` output
          // (every deferred `%Canon::Main` SubDirectory row here is a pure
          // descend-no-parent-value pointer — none is `Writable`/`MakerNotes`/
          // `BlockExtract`). The port DEFERS the child-table walk, so the
          // faithful behaviour is to emit NEITHER the parent nor (for now) the
          // children: skip the emission. Mirrors the Sony/Panasonic
          // `if def.sub_table.is_some() { continue; }` guard (issue #177).
          // Previously this arm emitted the SubDirectory's raw value, leaking a
          // bogus `Canon:ProcessingInfo` (and the other deferred parents) that
          // ExifTool never emits.
        }
      }
    } else if entry.tag_id == 0x96 && model.is_some_and(printconv::model_matches_eos_5d) {
      // `0x96` MODEL-CONDITIONAL LIST (`Canon.pm:1834-1846`): for an
      // EOS-5D body the FIRST arm wins — `SerialInfo`, the SubDirectory
      // pointer to `%Canon::SerialInfo` (`Canon.pm:1836-1838`). ExifTool
      // descends into that child table and emits ITS leaves
      // (`InternalSerialNumber2` / `InternalSerialNumber`) but NEVER the
      // `SerialInfo` parent value (`Exif.pm:7103-7104` `next` skips `FoundTag`
      // for a no-value SubDirectory) — so the parent is correctly absent (issue
      // #177). The walker captured the raw on-disk SerialInfo blob verbatim
      // (`RawValue::Bytes`, un-stripped — the trailing-`0xff`/NUL `string`
      // semantics belong only to the SECOND arm `InternalSerialNumber`), so
      // decode it here (`serial_info::parse`). The two leaves are
      // family-1 `Canon` like every other Canon MakerNote tag; each carries the
      // `Camera` family-2 group of the SerialInfo table, but the JSON sink keys
      // on family-1 (`-G1`). `populate_typed` is (correctly) not run for this
      // arm — the typed `internal_serial_number` accessor tracks only the
      // model-agnostic SECOND-arm leaf, which an EOS-5D body never takes.
      let blob = match &entry.value {
        // The faithful `$$valPt` view the body walker captured for the 5D arm.
        RawValue::Bytes(b) => b.as_slice(),
        // Defensive: the walker always rewrites a 5D `0x96` to `Bytes`; any
        // other shape means no SerialInfo blob to decode — emit nothing.
        _ => &[],
      };
      for (name, value) in serial_info::parse(blob, print_conv) {
        // Explicit BinaryData positions are never `Unknown`.
        emissions.push(VendorEmission::new(name, value, false));
      }
    } else if entry.tag_id == 0x28 {
      // `ImageUniqueID` (`Canon.pm:1726-1735`): the table forces
      // `Format => 'undef'`, so the walker captured the ORIGINAL on-disk
      // value bytes as `RawValue::Bytes` ([`body::walk_canon_in_tiff`]) —
      // ExifTool reads `int8u[16]` / `int16u[8]` / `int32u[4]` / `undef[16]`
      // / `float[4]` / `double[2]` / `rational[2]` all as the SAME literal
      // bytes (the verbose dump: `int8u[16] read as undef[16]`;
      // oracle-verified identical hex across every shape and both byte
      // orders). `RawConv => '$val eq "\0" x 16 ? undef : $val'` drops the
      // value ONLY when it is EXACTLY sixteen NUL bytes (Perl string
      // equality — NOT `/^\0+$/`, so a SHORT all-zero value of any other
      // length is NOT dropped); `ValueConv => 'unpack("H*", $val)'` renders
      // the survivor as lowercase hex. Operate on the original undef bytes,
      // never the lossy numeric decode.
      let val_bytes: &[u8] = match &entry.value {
        // The faithful `Format => 'undef'` view captured at walk time.
        RawValue::Bytes(b) => b,
        // Defensive: if the walker did not rewrite this entry (it always
        // does for an in-bounds 0x28), treat as no value — emit nothing.
        _ => &[],
      };
      // `$val eq "\0" x 16` — EXACTLY sixteen NUL bytes (oracle: an all-zero
      // `int8u[16]` is dropped, but an all-zero `int8u[8]` emits
      // "0000000000000000"). A length other than 16 — or any non-NUL byte —
      // is NOT equal and survives the RawConv.
      let is_undef = val_bytes.len() == 16 && val_bytes.iter().all(|&b| b == 0);
      if is_undef {
        // RawConv undef ⇒ tag not extracted (emit NOTHING; the typed
        // `image_unique_id` stays unset).
      } else {
        let hex = hex_lower(val_bytes);
        typed.image_unique_id = Some(SmolStr::from(&hex));
        // No `PrintConv` on 0x28, so `-j` and `-n` agree (the ValueConv hex
        // is the final value). `Writable`, non-`Unknown` ⇒ `unknown = false`.
        emissions.push(VendorEmission::new(
          "ImageUniqueID".into(),
          TagValue::Str(SmolStr::from(hex)),
          false,
        ));
      }
    } else {
      // Leaf tag: apply PrintConv + emit. `model` threads the parent
      // body `$$self{Model}` into the conditional SerialNumber PrintConv
      // (`Canon.pm:1282-1306`). For non-EOS-5D bodies tag `0x96` falls
      // here as the LIST's SECOND arm, `InternalSerialNumber`
      // (`Canon.pm:1840-1845`) — the `0xff` strip already ran in
      // `walk_canon_in_tiff`.
      let val = def.conv().apply(&entry.value, print_conv, model);
      populate_typed(&mut typed, entry);
      // Carry the tag's `Unknown` flag (the single Unknown Canon::Main tag,
      // `0x03 CanonFlashInfo`, lands here); the engine suppresses it.
      emissions.push(VendorEmission::new(
        def.name().into(),
        val,
        def.is_unknown(),
      ));
    }
  }
  (typed, emissions)
}

/// Emit Canon MakerNotes into a [`Metadata`] sink under the
/// `("MakerNotes","MakerNotes")` group. Uses the blob as a stand-alone
/// byte slice — for parent-TIFF-context resolution use [`parse_in_tiff`]
/// directly.
pub fn parse_into_metadata(
  blob: &[u8],
  parent_order: ByteOrder,
  print_conv: bool,
  into: &mut Metadata,
) {
  let group = Group::new("MakerNotes", "MakerNotes");
  // Standalone-blob entry point — no parent `$$self{Model}` / `$$self{FILE_TYPE}`
  // context, so the FocalPlaneX/YSize `Condition` and the ShotInfo pos-22
  // CRW clause both evaluate as for an undef container.
  let (_typed, emissions) =
    parse_in_tiff(blob, 0, blob.len(), parent_order, print_conv, None, None);
  for e in emissions {
    // Unknown-suppression is the engine's job; this raw `Metadata`-sink
    // helper applies it inline so it matches the default-output contract.
    if e.unknown() {
      continue;
    }
    into.push(group.clone(), e.name(), e.value().clone());
  }
}

/// Populate the typed struct from one Main-IFD leaf-tag emission. Reads the
/// entry's pre-PrintConv [`RawValue`] directly (every typed source here is a
/// string/integer leaf, not a PrintConv string), so the converted `TagValue`
/// is not needed.
fn populate_typed(typed: &mut MakerNotesCanon, entry: &CanonEntry) {
  match entry.tag_id {
    0x06 => {
      if let RawValue::Text { text: s, .. } = &entry.value {
        typed.image_type = Some(s.as_str().into());
      }
    }
    0x07 => {
      if let RawValue::Text { text: s, .. } = &entry.value {
        typed.firmware_version = Some(s.as_str().into());
      }
    }
    0x08 => {
      if let RawValue::U64(v) = &entry.value
        && let Some(&n) = v.first()
      {
        typed.file_number = Some(n as u32);
      }
    }
    0x09 => {
      if let RawValue::Text { text: s, .. } = &entry.value {
        typed.owner_name = Some(s.as_str().into());
      }
    }
    0x0c => {
      if let RawValue::U64(v) = &entry.value
        && let Some(&n) = v.first()
      {
        typed.serial_number = Some(n);
      }
    }
    0x10 => {
      if let RawValue::U64(v) = &entry.value
        && let Some(&n) = v.first()
      {
        let id = n as u32;
        typed.model_id = Some(id);
        typed.model_name = model_ids::lookup_name(id);
      }
    }
    // 0x28 (`ImageUniqueID`) is handled in the dispatch loop's dedicated
    // `Format => 'undef'` arm (raw-byte RawConv + hex ValueConv) and never
    // reaches the generic leaf path, so it has no `populate_typed` case.
    0x95 => {
      if let RawValue::Text { text: s, .. } = &entry.value {
        typed.lens_model_string = Some(s.as_str().into());
      }
    }
    0x96 => {
      if let RawValue::Text { text: s, .. } = &entry.value {
        typed.internal_serial_number = Some(s.as_str().into());
      }
    }
    _ => {}
  }
}

/// Extract a focal-length-in-mm from a TagValue (e.g. `"55 mm"` ⇒ 55.0).
fn focal_mm_from_tag_value(v: &TagValue) -> Option<f64> {
  match v {
    TagValue::Str(s) => {
      let trimmed = s.trim_end_matches(" mm");
      trimmed.parse::<f64>().ok()
    }
    TagValue::F64(f) => Some(*f),
    TagValue::I64(n) => Some(*n as f64),
    TagValue::U64(n) => Some(*n as f64),
    _ => None,
  }
}

/// Read FocalUnits from a CameraSettings RawValue (the entry value
/// before sub-table parsing). Returns `None` if the words are absent.
fn read_focal_units(raw: &RawValue, parent_order: ByteOrder) -> Option<u16> {
  // The CameraSettings entry value is stored as a list of int16s words
  // (RawValue::I64) OR as raw bytes; reserialize to bytes and read
  // position 25 directly.
  let bytes = reserialize_int_array(raw, parent_order);
  if bytes.len() < 2 * 26 {
    return None;
  }
  let pos = 2 * 25;
  // The `bytes.len() < 52` guard makes `bytes.get(pos..pos+2)` (`pos == 50`)
  // `Some` and its `try_into()` to `[u8; 2]` succeed — the checked,
  // byte-identical form of `[bytes[pos], bytes[pos+1]]`.
  let arr: [u8; 2] = bytes.get(pos..pos + 2)?.try_into().ok()?;
  let raw_int = match parent_order {
    ByteOrder::Little => i16::from_le_bytes(arr),
    ByteOrder::Big => i16::from_be_bytes(arr),
  };
  if raw_int <= 0 {
    None
  } else {
    Some(raw_int as u16)
  }
}

/// `$$valPt =~ /^\0\0\0\0/` test (`Canon.pm:1713`, the 0x26 CanonAFInfo2
/// `Condition`): `true` when the blob's first four bytes are all zero.
/// A blob shorter than four bytes cannot match `/^\0\0\0\0/`, so it is
/// NOT treated as all-zero (bundled would still enter the SubDirectory and
/// let `ProcessSerialData` decode whatever fits).
fn first4_all_zero(blob: &[u8]) -> bool {
  // `blob.get(..4)` folds the `blob.len() >= 4` guard into the access — the
  // checked, byte-identical form of `blob.len() >= 4 && blob[..4].iter()...`.
  blob
    .get(..4)
    .is_some_and(|head| head.iter().all(|&b| b == 0))
}

/// Lowercase, separator-free hex of a byte string — ExifTool's
/// `unpack("H*", $val)` (the `ImageUniqueID` ValueConv, `Canon.pm:1733`).
fn hex_lower(bytes: &[u8]) -> std::string::String {
  use std::fmt::Write;
  let mut out = std::string::String::with_capacity(bytes.len() * 2);
  for &b in bytes {
    let _ = write!(&mut out, "{b:02x}");
  }
  out
}

/// Reserialize a RawValue (int16s/int16u/Bytes) back into bytes in the
/// parent IFD's byte order. The CameraSettings/FileInfo/FocalLength
/// sub-table parsers want the BYTE blob (`$$valPt`), not the decoded
/// `i64` array — bundled `ProcessBinaryData` reads bytes too.
fn reserialize_int_array(raw: &RawValue, order: ByteOrder) -> Vec<u8> {
  match raw {
    RawValue::I64(words) => {
      let mut out = Vec::with_capacity(words.len() * 2);
      for &w in words {
        let w16 = w as i16;
        let bytes = match order {
          ByteOrder::Little => w16.to_le_bytes(),
          ByteOrder::Big => w16.to_be_bytes(),
        };
        out.extend_from_slice(&bytes);
      }
      out
    }
    RawValue::U64(words) => {
      let mut out = Vec::with_capacity(words.len() * 2);
      for &w in words {
        let w16 = w as u16;
        let bytes = match order {
          ByteOrder::Little => w16.to_le_bytes(),
          ByteOrder::Big => w16.to_be_bytes(),
        };
        out.extend_from_slice(&bytes);
      }
      out
    }
    RawValue::Bytes(b) => b.clone(),
    _ => Vec::new(),
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

  /// Synthetic Canon body with one Main entry (CanonImageType, ASCII).
  ///
  /// Layout: 2 bytes count, then one 12-byte entry. For out-of-line
  /// values the offset is 14 (just after the entry) and the value
  /// bytes follow. For inline values the entry's last 4 bytes hold
  /// the value.
  fn one_main_entry_blob(tag: u16, format: u16, count: u32, value_bytes: &[u8]) -> Vec<u8> {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(&[0x01, 0x00]); // 1 entry LE
    blob.extend_from_slice(&tag.to_le_bytes());
    blob.extend_from_slice(&format.to_le_bytes());
    blob.extend_from_slice(&count.to_le_bytes());
    // Element sizes by TIFF format code (index 0 unused; codes 1-13).
    let elem_sizes: [usize; 14] = [0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8, 4];
    let elem_size = if (format as usize) < elem_sizes.len() {
      elem_sizes[format as usize]
    } else {
      1
    };
    let total = elem_size * count as usize;
    if total <= 4 {
      let mut padded = std::vec![0u8; 4];
      padded[..value_bytes.len()].copy_from_slice(value_bytes);
      blob.extend_from_slice(&padded);
    } else {
      // Out-of-line: data sits at offset 14 (right after the entry).
      blob.extend_from_slice(&(14u32).to_le_bytes());
      blob.extend_from_slice(value_bytes);
    }
    blob
  }

  #[test]
  fn parse_canon_image_type_inline() {
    let value = b"Canon EOS\x00";
    let blob = one_main_entry_blob(0x06, 0x02, value.len() as u32, value);
    let (typed, emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(typed.image_type(), Some("Canon EOS"));
    assert!(emissions.iter().any(|e| e.name() == "CanonImageType"));
  }

  #[test]
  fn parse_canon_model_id_resolves_against_model_table() {
    // CanonModelID = 0x1140000 → "EOS D30"
    let blob = one_main_entry_blob(0x10, 0x04, 1, &(0x1140000u32).to_le_bytes());
    let (typed, emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(typed.model_id(), Some(0x1140000));
    assert_eq!(typed.model_name(), Some("EOS D30"));
    let v = emissions
      .iter()
      .find(|e| e.name() == "CanonModelID")
      .map(|e| e.value().clone())
      .unwrap();
    assert_eq!(v, TagValue::Str("EOS D30".into()));
  }

  #[test]
  fn parse_canon_firmware_version_string() {
    let value = b"1.0.1\x00";
    let blob = one_main_entry_blob(0x07, 0x02, value.len() as u32, value);
    let (typed, _emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(typed.firmware_version(), Some("1.0.1"));
  }

  #[test]
  fn parse_canon_serial_number() {
    let blob = one_main_entry_blob(0x0c, 0x04, 1, &(560018150u32).to_le_bytes());
    let (typed, emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(typed.serial_number(), Some(560018150));
    // PrintConv pads to 10 digits (default branch, no Model context).
    let v = emissions
      .iter()
      .find(|e| e.name() == "SerialNumber")
      .map(|e| e.value().clone())
      .unwrap();
    assert_eq!(v, TagValue::Str("0560018150".into()));
  }

  /// The model-conditional SerialNumber (`Canon.pm:1282-1306`) threads
  /// `$$self{Model}` through `parse_in_tiff` → leaf-tag `apply`. An
  /// `EOS-1D` body uses `sprintf("%.6u", $val)`.
  #[test]
  fn parse_canon_serial_number_eos_1d_uses_model() {
    let blob = one_main_entry_blob(0x0c, 0x04, 1, &(500292u32).to_le_bytes());
    let (_typed, emissions) = parse_in_tiff(
      &blob,
      0,
      blob.len(),
      ByteOrder::Little,
      true,
      Some("Canon EOS-1D Mark IV"),
      None,
    );
    let v = emissions
      .iter()
      .find(|e| e.name() == "SerialNumber")
      .map(|e| e.value().clone())
      .unwrap();
    assert_eq!(v, TagValue::Str("500292".into()));
  }

  #[test]
  fn parse_canon_file_number() {
    let blob = one_main_entry_blob(0x08, 0x04, 1, &(1181861u32).to_le_bytes());
    let (typed, emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(typed.file_number(), Some(1181861));
    let v = emissions
      .iter()
      .find(|e| e.name() == "FileNumber")
      .map(|e| e.value().clone())
      .unwrap();
    assert_eq!(v, TagValue::Str("118-1861".into()));
  }

  /// End-to-end `0x96` InternalSerialNumber (`Canon.pm:1841-1845`): the
  /// trailing-`0xff` strip is reflected in BOTH the typed accessor and
  /// the MakerNotes emission, with no U+FFFD leakage (Kiss X3).
  #[test]
  fn parse_internal_serial_number_strips_trailing_ff() {
    let value = b"ABC123\xff\xff\xff";
    let blob = one_main_entry_blob(0x96, 0x02, value.len() as u32, value);
    let (typed, emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(typed.internal_serial_number(), Some("ABC123"));
    let v = emissions
      .iter()
      .find(|e| e.name() == "InternalSerialNumber")
      .map(|e| e.value().clone())
      .unwrap();
    assert_eq!(v, TagValue::Str("ABC123".into()));
  }

  /// A clean `0x96` value passes through unchanged end-to-end.
  #[test]
  fn parse_internal_serial_number_clean_unchanged() {
    let value = b"H1234567";
    let blob = one_main_entry_blob(0x96, 0x02, value.len() as u32, value);
    let (typed, _emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(typed.internal_serial_number(), Some("H1234567"));
  }

  /// `0x96` MODEL-CONDITIONAL LIST (`Canon.pm:1834-1846`), FIRST arm: an
  /// EOS-5D body routes `0x96` to the `SerialInfo` SubDirectory
  /// (`Canon.pm:1836-1838`), NOT `InternalSerialNumber`. ExifTool descends
  /// into `%Canon::SerialInfo` and emits its leaves (`InternalSerialNumber2` /
  /// `InternalSerialNumber`) but NEVER the `SerialInfo` parent value; the port
  /// decodes the sub-table (#175) while still suppressing the bogus parent
  /// (#177). The typed `internal_serial_number` accessor (the model-agnostic
  /// SECOND-arm leaf) stays unset — an EOS-5D never takes that arm.
  ///
  /// Oracle (`perl exiftool -G1 -j` on a crafted EOS 5D Mark II with this
  /// SerialInfo blob): `Canon:InternalSerialNumber2 = "ABC123XYZ"`,
  /// `Canon:InternalSerialNumber = "DEF456"`.
  #[test]
  fn parse_eos_5d_0x96_decodes_serialinfo_subtable() {
    let value = b"ABC123XYZDEF456\x00";
    let blob = one_main_entry_blob(0x96, 0x02, value.len() as u32, value);
    let (typed, emissions) = parse_in_tiff(
      &blob,
      0,
      blob.len(),
      ByteOrder::Little,
      true,
      Some("Canon EOS 5D Mark II"),
      None,
    );
    // The bogus `SerialInfo` SubDirectory parent is NEVER emitted (#177)…
    assert!(
      !emissions.iter().any(|e| e.name() == "SerialInfo"),
      "EOS 5D must NOT emit the bogus SerialInfo SubDirectory parent (#177)"
    );
    // …but its decoded leaves ARE (#175).
    let isn2 = emissions
      .iter()
      .find(|e| e.name() == "InternalSerialNumber2")
      .map(|e| e.value().clone());
    assert_eq!(isn2, Some(TagValue::Str("ABC123XYZ".into())));
    let isn = emissions
      .iter()
      .find(|e| e.name() == "InternalSerialNumber")
      .map(|e| e.value().clone());
    assert_eq!(isn, Some(TagValue::Str("DEF456".into())));
    // The typed `internal_serial_number` tracks only the model-agnostic
    // SECOND-arm leaf, which an EOS-5D never takes — it stays unset.
    assert_eq!(typed.internal_serial_number(), None);
  }

  /// `RawConv => '$val =~ /^\w{6}/ ? $val : undef'` (`Canon.pm:7154`/`:7159`):
  /// a SerialInfo `InternalSerialNumber2` whose first six bytes are NOT all
  /// word characters is dropped, exactly like the oracle returns undef. The
  /// valid offset-9 `InternalSerialNumber` still emits.
  #[test]
  fn parse_eos_5d_0x96_rawconv_drops_non_word_internal_serial2() {
    let value = b"!!ABC123ZDEF456\x00";
    let blob = one_main_entry_blob(0x96, 0x02, value.len() as u32, value);
    let (_typed, emissions) = parse_in_tiff(
      &blob,
      0,
      blob.len(),
      ByteOrder::Little,
      true,
      Some("Canon EOS 5D Mark III"),
      None,
    );
    assert!(
      !emissions
        .iter()
        .any(|e| e.name() == "InternalSerialNumber2"),
      "non-/^\\w{{6}}/ InternalSerialNumber2 must be dropped (RawConv undef)"
    );
    let isn = emissions
      .iter()
      .find(|e| e.name() == "InternalSerialNumber")
      .map(|e| e.value().clone());
    assert_eq!(isn, Some(TagValue::Str("DEF456".into())));
  }

  /// `/EOS 5D/` is an UNANCHORED substring (`Canon.pm:1837`) — base
  /// "EOS 5D" matches just as "EOS 5D Mark IV" does; the SerialInfo
  /// sub-table is decoded (and the bogus parent suppressed, #177) for either
  /// spelling.
  #[test]
  fn parse_eos_5d_base_model_0x96_decodes_serialinfo() {
    let value = b"WXYZ12ABCSER789\x00";
    let blob = one_main_entry_blob(0x96, 0x02, value.len() as u32, value);
    let (typed, emissions) = parse_in_tiff(
      &blob,
      0,
      blob.len(),
      ByteOrder::Little,
      true,
      Some("Canon EOS 5D"),
      None,
    );
    assert!(!emissions.iter().any(|e| e.name() == "SerialInfo"));
    let isn2 = emissions
      .iter()
      .find(|e| e.name() == "InternalSerialNumber2")
      .map(|e| e.value().clone());
    assert_eq!(isn2, Some(TagValue::Str("WXYZ12ABC".into())));
    // The typed `internal_serial_number` (SECOND-arm) stays unset.
    assert_eq!(typed.internal_serial_number(), None);
  }

  /// `0x96` SECOND arm for a NON-EOS-5D body (e.g. Kiss X3 / EOS 50D):
  /// `InternalSerialNumber` with the trailing-`0xff` strip applied.
  #[test]
  fn parse_non_5d_0x96_emits_internal_serial_stripped() {
    let value = b"ABC123\xff\xff\xff";
    let blob = one_main_entry_blob(0x96, 0x02, value.len() as u32, value);
    let (typed, emissions) = parse_in_tiff(
      &blob,
      0,
      blob.len(),
      ByteOrder::Little,
      true,
      Some("Canon EOS 50D"),
      None,
    );
    assert!(!emissions.iter().any(|e| e.name() == "SerialInfo"));
    assert_eq!(typed.internal_serial_number(), Some("ABC123"));
    let v = emissions
      .iter()
      .find(|e| e.name() == "InternalSerialNumber")
      .map(|e| e.value().clone())
      .unwrap();
    assert_eq!(v, TagValue::Str("ABC123".into()));
  }

  /// Model ABSENT → fall back to `InternalSerialNumber` (the LIST's
  /// model-agnostic second arm), strip applied.
  #[test]
  fn parse_model_absent_0x96_emits_internal_serial() {
    let value = b"ABC123\xff";
    let blob = one_main_entry_blob(0x96, 0x02, value.len() as u32, value);
    let (typed, emissions) = parse(&blob, ByteOrder::Little);
    assert!(!emissions.iter().any(|e| e.name() == "SerialInfo"));
    assert_eq!(typed.internal_serial_number(), Some("ABC123"));
    assert!(emissions.iter().any(|e| e.name() == "InternalSerialNumber"));
  }

  #[test]
  fn empty_blob_yields_empty() {
    let (typed, emissions) = parse(&[], ByteOrder::Little);
    assert_eq!(typed, MakerNotesCanon::new());
    assert!(emissions.is_empty());
  }

  // -- R6-2: 0x927c per-entry value-offset diagnostics ------------------------

  /// Build a complete LE TIFF whose IFD0 has ONE out-of-line entry (tag/format/
  /// count) with the given raw value pointer. `trailer_len` extra zero bytes pad
  /// the block so an in-bounds offset has somewhere to point.
  fn ctmd_makernote_one_entry(
    tag: u16,
    format: u16,
    count: u32,
    value_ptr: u32,
    trailer_len: usize,
  ) -> Vec<u8> {
    let mut t: Vec<u8> = std::vec![b'I', b'I', 0x2a, 0x00, 0x08, 0x00, 0x00, 0x00];
    t.extend_from_slice(&1u16.to_le_bytes()); // 1 entry
    t.extend_from_slice(&tag.to_le_bytes());
    t.extend_from_slice(&format.to_le_bytes());
    t.extend_from_slice(&count.to_le_bytes());
    t.extend_from_slice(&value_ptr.to_le_bytes());
    t.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0
    t.extend(std::iter::repeat_n(0u8, trailer_len));
    t
  }

  /// An out-of-line value pointer past the block end ⇒ `Bad offset for IFD0
  /// <Name>` (Exif.pm:6660; no RAF). The caller re-maps `IFD0` → `MakerNotes`.
  #[test]
  fn ctmd_value_offset_bad_offset() {
    // 0x0007 CanonFirmwareVersion, ASCII count 8 (out-of-line), ptr past EOF.
    let t = ctmd_makernote_one_entry(0x0007, 2, 8, 0x7000_0000, 8);
    let d = redispatch_ctmd_makernote_value_offset_diagnostics(&t);
    assert_eq!(d.len(), 1, "exactly one value-offset diagnostic");
    assert_eq!(d[0].message(), "Bad offset for IFD0 CanonFirmwareVersion");
    assert_eq!(d[0].ignorable(), 1, "$inMakerNotes ⇒ minor");
  }

  /// An in-bounds out-of-line value pointer that OVERLAPS the directory ⇒
  /// `Suspicious IFD0 offset for <Name>` (Exif.pm:6549/6675).
  #[test]
  fn ctmd_value_offset_suspicious() {
    // ptr = 10 (inside the IFD directory at 8..22), size 8, block big enough.
    let t = ctmd_makernote_one_entry(0x0007, 2, 8, 10, 16);
    let d = redispatch_ctmd_makernote_value_offset_diagnostics(&t);
    assert_eq!(d.len(), 1);
    assert_eq!(
      d[0].message(),
      "Suspicious IFD0 offset for CanonFirmwareVersion"
    );
    assert_eq!(d[0].ignorable(), 1);
  }

  /// An out-of-bounds offset that is ALSO suspect reports ONLY `Bad offset`
  /// (bundled's `++$warnCount` makes `$suspect != $warnCount`, Exif.pm:6672).
  #[test]
  fn ctmd_value_offset_bad_offset_suppresses_suspicious() {
    // The block is header(8) + IFD(2 + 12 + 4) = 26 bytes (trailer 0). ptr = 4
    // (< 8 ⇒ suspect) AND size 23 ⇒ 4+23=27 > 26 ⇒ out of bounds. The Bad-offset
    // warning fires; the suspect Suspicious does NOT.
    let t = ctmd_makernote_one_entry(0x0007, 2, 23, 4, 0);
    assert_eq!(t.len(), 26);
    let d = redispatch_ctmd_makernote_value_offset_diagnostics(&t);
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].message(), "Bad offset for IFD0 CanonFirmwareVersion");
  }

  /// A well-formed in-bounds out-of-line value raises NO value-offset diagnostic.
  #[test]
  fn ctmd_value_offset_clean_no_diagnostic() {
    // ptr = 22 (just after the 22-byte header+IFD), size 8, 8-byte trailer.
    let t = ctmd_makernote_one_entry(0x0007, 2, 8, 22, 8);
    let d = redispatch_ctmd_makernote_value_offset_diagnostics(&t);
    assert!(
      d.is_empty(),
      "a clean out-of-line value warns nothing: {d:?}"
    );
  }

  /// An inline value (`size <= 4`) can never be mis-offset ⇒ no diagnostic even
  /// with a degenerate inline-value field.
  #[test]
  fn ctmd_value_offset_inline_never_warns() {
    // 0x0007 ASCII count 3 ⇒ size 3 ≤ 4 (inline); the "ptr" field IS the value.
    let t = ctmd_makernote_one_entry(0x0007, 2, 3, 0x7000_0000, 8);
    let d = redispatch_ctmd_makernote_value_offset_diagnostics(&t);
    assert!(d.is_empty(), "an inline value never warns: {d:?}");
  }
}
