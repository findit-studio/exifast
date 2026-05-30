// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! DJI MakerNotes — Phase 4 placeholder.
//!
//! Bundled source: `lib/Image/ExifTool/DJI.pm` — `%Image::ExifTool::DJI
//! ::Main` plus `%Image::ExifTool::DJI::Info` (the debug-info variant —
//! `MakerNotes.pm:93-97`). DJI files include drone telemetry (GPS,
//! gimbal angles, flight state) — Phase 4 ports the subset that drives
//! Drone identification.
//!
//! Phase 1 surfaces this empty struct so the dispatcher resolves to
//! `Vendor::Dji`.

/// DJI-specific MakerNote-decoded data — Phase 4 placeholder.
///
/// D8: no public fields; accessor stubs return `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DjiMakerNote {}

impl DjiMakerNote {
  /// Build an empty DJI placeholder. Phase 4 will replace with a
  /// constructor that walks the DJI IFD / Info-blob.
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {}
  }

  /// DJI drone model (`DJI.pm:DroneModel`). Phase 1 returns `None`.
  #[must_use]
  #[inline(always)]
  pub const fn drone_model(&self) -> Option<&str> {
    None
  }

  /// DJI camera serial (`DJI.pm:SerialNumber`). Phase 1 returns
  /// `None`.
  #[must_use]
  #[inline(always)]
  pub const fn serial_number(&self) -> Option<&str> {
    None
  }
}
