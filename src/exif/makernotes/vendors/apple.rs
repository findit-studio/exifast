// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Apple iOS MakerNotes — Phase 2 placeholder.
//!
//! Bundled source: `lib/Image/ExifTool/Apple.pm` — `%Image::ExifTool::
//! Apple::Main`. This module port is **Phase 2** (iPhone is a
//! rescope-priority camera).
//!
//! Phase 1 surfaces this empty struct so the dispatcher resolves to
//! `Vendor::Apple` and the [`MakerNotesMeta`](super::super::MakerNotesMeta)
//! has a stable accessor surface. Phase 2 will populate the tag fields
//! and per-tag conversions.

/// Apple-specific MakerNote-decoded data — Phase 2 placeholder.
///
/// D8: no public fields; accessor stubs return `None` today and will
/// return decoded values in Phase 2.
///
/// `#[non_exhaustive]`: the Phase-2 port will add private fields without
/// a breaking change to downstream `match` arms (none exist today —
/// the struct has no constructible variants — but the marker makes the
/// API growth path explicit).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AppleMakerNote {}

impl AppleMakerNote {
  /// Build an empty Apple placeholder. Phase 2 will replace with a
  /// constructor that walks the Apple IFD.
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {}
  }

  /// HDR mode (`HDRImageType`, `Apple.pm:38`). Phase 1 returns `None`;
  /// Phase 2 will decode the IFD-emitted value.
  #[must_use]
  #[inline(always)]
  pub const fn hdr_image_type(&self) -> Option<u16> {
    None
  }

  /// Acceleration vector (`AccelerationVector`, `Apple.pm:79`). Phase
  /// 1 returns `None`; Phase 2 will decode the triple-rational tuple.
  #[must_use]
  #[inline(always)]
  pub const fn acceleration_vector(&self) -> Option<(f64, f64, f64)> {
    None
  }

  /// Live-Photo identifier (`ContentIdentifier`, `Apple.pm:177`).
  /// Phase 1 returns `None`; Phase 2 will decode the UUID string.
  #[must_use]
  #[inline(always)]
  pub const fn content_identifier(&self) -> Option<&str> {
    None
  }
}
