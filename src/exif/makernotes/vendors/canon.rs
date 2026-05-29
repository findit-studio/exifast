// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Canon MakerNotes — Phase 2 placeholder.
//!
//! Bundled source: `lib/Image/ExifTool/Canon.pm` — `%Image::ExifTool::
//! Canon::Main` plus the binary-data subtables (`CameraSettings`,
//! `ShotInfo`, `FileInfo`, …). This is the LARGEST per-vendor table
//! bundled — Canon.pm is ~10k lines. Phase 2 ports the subset that
//! drives camera-metadata identification (Make, Model, LensModel,
//! FocalLength).
//!
//! Phase 1 surfaces this empty struct so the dispatcher resolves to
//! `Vendor::Canon` and the [`MakerNotesMeta`](super::super::MakerNotesMeta)
//! has a stable accessor surface.

/// Canon-specific MakerNote-decoded data — Phase 2 placeholder.
///
/// D8: no public fields; accessor stubs return `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CanonMakerNote {}

impl CanonMakerNote {
  /// Build an empty Canon placeholder. Phase 2 will replace with a
  /// constructor that walks the Canon IFD.
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {}
  }

  /// Canon `LensModel` (`Canon.pm:CanonLensType` resolved via
  /// `%canonLensTypes`). Phase 1 returns `None`; Phase 2 will decode
  /// the IFD-emitted value.
  #[must_use]
  #[inline(always)]
  pub const fn lens_model(&self) -> Option<&str> {
    None
  }

  /// Canon firmware revision (`Canon.pm:FirmwareVersion`).
  /// Phase 1 returns `None`; Phase 2 will decode.
  #[must_use]
  #[inline(always)]
  pub const fn firmware_version(&self) -> Option<&str> {
    None
  }

  /// Canon body serial number (`Canon.pm:SerialNumber`).
  /// Phase 1 returns `None`; Phase 2 will decode.
  #[must_use]
  #[inline(always)]
  pub const fn serial_number(&self) -> Option<&str> {
    None
  }
}
