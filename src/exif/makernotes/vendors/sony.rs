// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Sony MakerNotes — Phase 3 placeholder.
//!
//! Bundled source: `lib/Image/ExifTool/Sony.pm` — `%Image::ExifTool::
//! Sony::Main` (Sony's 4 numbered tables; the dispatcher
//! `MakerNotes.pm:1031-1099` may select any of them by signature).
//! Phase 3 ports the subset that drives camera-metadata identification.
//!
//! Phase 1 surfaces this empty struct so the dispatcher resolves to
//! `Vendor::Sony` and the [`MakerNotesMeta`](super::super::MakerNotesMeta)
//! has a stable accessor surface.

/// Sony-specific MakerNote-decoded data — Phase 3 placeholder.
///
/// D8: no public fields; accessor stubs return `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SonyMakerNote {}

impl SonyMakerNote {
  /// Build an empty Sony placeholder. Phase 3 will replace with a
  /// constructor that walks the Sony IFD.
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {}
  }

  /// Sony `LensType` (`Sony.pm:SonyLensType`). Phase 1 returns `None`.
  #[must_use]
  #[inline(always)]
  pub const fn lens_type(&self) -> Option<&str> {
    None
  }

  /// Sony body model id (`Sony.pm:ModelID`). Phase 1 returns `None`.
  #[must_use]
  #[inline(always)]
  pub const fn model_id(&self) -> Option<u32> {
    None
  }
}
