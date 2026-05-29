// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Panasonic MakerNotes — Phase 3 placeholder.
//!
//! Bundled source: `lib/Image/ExifTool/Panasonic.pm` — `%Image::ExifTool::
//! Panasonic::Main`. Note Leica's many maker-note variants ALL route to
//! Panasonic tag tables (`MakerNotes.pm:600-731`) — the Panasonic-Leica
//! tag-table affinity is a known bundled quirk. Phase 3 ports the
//! Panasonic table; Leica decoding piggy-backs.
//!
//! Phase 1 surfaces this empty struct so the dispatcher resolves to
//! `Vendor::Panasonic` and the [`MakerNotesMeta`](super::super::MakerNotesMeta)
//! has a stable accessor surface.

/// Panasonic-specific MakerNote-decoded data — Phase 3 placeholder.
///
/// D8: no public fields; accessor stubs return `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PanasonicMakerNote {}

impl PanasonicMakerNote {
  /// Build an empty Panasonic placeholder. Phase 3 will replace with
  /// a constructor that walks the Panasonic IFD.
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {}
  }

  /// Panasonic `LensType` (`Panasonic.pm:LensType`). Phase 1 returns
  /// `None`.
  #[must_use]
  #[inline(always)]
  pub const fn lens_type(&self) -> Option<&str> {
    None
  }

  /// Panasonic body model name (`Panasonic.pm:CameraModel`). Phase 1
  /// returns `None`.
  #[must_use]
  #[inline(always)]
  pub const fn camera_model(&self) -> Option<&str> {
    None
  }
}
