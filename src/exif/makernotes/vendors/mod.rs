// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Per-vendor MakerNote-decoded structs.
//!
//! - Phase 2 ports populate `apple::MakerNotesApple` and
//!   `canon::MakerNotesCanon` from real IFD bodies.
//! - Phase 3/4/deferred modules are empty shells exposing a stable
//!   accessor surface (`SonyMakerNote`, `PanasonicMakerNote`,
//!   `GoProMakerNote`, `DjiMakerNote`).
//!
//! Type aliases preserve the Phase-1 API names (`AppleMakerNote`,
//! `CanonMakerNote`) for downstream `match` arms — `MakerNotesApple`
//! and `MakerNotesCanon` are the canonical names per the
//! [[exifast-api-conventions]] memory ("no module-name stutter" naming).

pub mod apple;
pub mod canon;
pub mod dji;
pub mod gopro;
pub mod panasonic;
pub mod sony;

pub use apple::MakerNotesApple;
pub use canon::MakerNotesCanon;
pub use dji::DjiMakerNote;
pub use gopro::GoProMakerNote;
pub use panasonic::PanasonicMakerNote;
pub use sony::SonyMakerNote;

/// Compatibility alias — Phase-1 API name preserved.
pub type AppleMakerNote = MakerNotesApple;
/// Compatibility alias — Phase-1 API name preserved.
pub type CanonMakerNote = MakerNotesCanon;

/// One vendor MakerNote emission — the rendered `(name, value)` pair plus the
/// `Unknown => 1` flag the emission engine uses to suppress it from default
/// output (`ExifTool.pm:9179-9185`).
///
/// This carries the `Unknown` flag THROUGH the cached emissions instead of the
/// vendor pre-filtering it at collection time: the vendor body decoder emits a
/// named/rendered tag for EVERY leaf it recognizes (Unknown or not), and the
/// shared engine ([`run_emission`](crate::emit::run_emission)) drops the
/// `Unknown` ones once — exactly as it does for every other format, so the
/// per-vendor `if def.is_unknown() { continue; }` is gone.
///
/// D8: no public fields; accessors only. The constructor is `pub(crate)` (only
/// the in-crate vendor body parsers build these), but the read accessors are
/// `pub` so the captured-MakerNote accessors
/// ([`MakerNote::emissions_print_conv`](crate::exif::MakerNote::emissions_print_conv))
/// remain usable from outside the crate.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq)]
pub struct VendorEmission {
  /// The resolved tag name (the vendor table's `Name`).
  name: smol_str::SmolStr,
  /// The rendered value for the active [`ConvMode`](crate::emit::ConvMode).
  value: crate::value::TagValue,
  /// ExifTool's `Unknown => 1` flag — `true` ⇒ the engine suppresses this tag
  /// from default output.
  unknown: bool,
}

#[cfg(feature = "alloc")]
impl VendorEmission {
  /// Compose a vendor emission from its name, rendered value, and `Unknown`
  /// flag. (`pub(crate)`: only the in-crate vendor body parsers build these.)
  #[must_use]
  #[inline(always)]
  pub(crate) fn new(name: smol_str::SmolStr, value: crate::value::TagValue, unknown: bool) -> Self {
    Self {
      name,
      value,
      unknown,
    }
  }

  /// The resolved tag name.
  #[must_use]
  #[inline(always)]
  pub fn name(&self) -> &str {
    self.name.as_str()
  }

  /// The rendered value.
  #[must_use]
  #[inline(always)]
  pub const fn value(&self) -> &crate::value::TagValue {
    &self.value
  }

  /// Whether this emission carries ExifTool's `Unknown => 1` flag — the
  /// emission engine suppresses such tags from default output
  /// (`ExifTool.pm:9179-9185`).
  #[must_use]
  #[inline(always)]
  pub const fn unknown(&self) -> bool {
    self.unknown
  }
}
