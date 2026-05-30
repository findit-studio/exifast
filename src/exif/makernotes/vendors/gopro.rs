// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! GoPro MakerNotes — Phase 4 placeholder.
//!
//! Bundled source: `lib/Image/ExifTool/GoPro.pm` — `%Image::ExifTool::
//! GoPro::Main`. Note `MakerNotes.pm` itself has NO explicit GoPro entry
//! — bundled identifies GoPro via the generic Exif IFD + the `Make` /
//! `Model` tags (`MakerNotes.pm:1117-1126` `MakerNoteUnknown` catches
//! it). Phase 4 will add the Phase-4 GoPro vendor dispatch + the
//! `GoPro.pm` table.
//!
//! Phase 1 surfaces this empty struct so the API surface is stable
//! when Phase 4 lands.

/// GoPro-specific MakerNote-decoded data — Phase 4 placeholder.
///
/// D8: no public fields; accessor stubs return `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct GoProMakerNote {}

impl GoProMakerNote {
  /// Build an empty GoPro placeholder. Phase 4 will replace with
  /// a constructor that walks the GoPro data.
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {}
  }

  /// GoPro model (`GoPro.pm:CameraModel`). Phase 1 returns `None`.
  #[must_use]
  #[inline(always)]
  pub const fn camera_model(&self) -> Option<&str> {
    None
  }

  /// GoPro firmware (`GoPro.pm:Firmware`). Phase 1 returns `None`.
  #[must_use]
  #[inline(always)]
  pub const fn firmware(&self) -> Option<&str> {
    None
  }
}
