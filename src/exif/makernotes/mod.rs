// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Vendor MakerNotes — `Image::ExifTool::MakerNotes` (Phil Harvey,
//! 11/11/2004) Phase-1 infrastructure port.
//!
//! ## What this module owns
//!
//! `MakerNotes.pm` is the dispatcher for every camera vendor's private
//! IFD inside the ExifIFD's 0x927C `MakerNote` tag. This module ports
//! ONLY the infrastructure shared across all vendors:
//!
//! 1. The signature/make dispatch table ([`dispatch`]) — bundled
//!    `@Image::ExifTool::MakerNotes::Main` (`MakerNotes.pm:35-1127`).
//! 2. The `SubDirectory{ByteOrder}` resolution ([`resolve_child_byte_order`])
//!    — `Unknown` body-marker probe + explicit overrides.
//! 3. The `SubDirectory{Base}` rebase formulas ([`resolve_child_base`])
//!    — Apple's `$start - 14`, FujiFilm's `$start`, Leica7's `-$base`,
//!    Canon's inherited base, …
//! 4. The Phase 2+ vendor surface — per-vendor placeholder structs in
//!    [`vendors`] that decoded data hangs off of.
//!
//! ## Phase scope
//!
//! Phase 1 (THIS module) does ONLY signature detection + the
//! `SubDirectory` directive surface. Per-vendor TAG TABLES (the
//! `%Image::ExifTool::Vendor::Main` hashes — Canon.pm, Apple.pm, Sony.pm,
//! …) are deferred to Phase 2-4:
//!
//! - Phase 2: Apple + Canon (rescope-priority cameras).
//! - Phase 3: Sony + Panasonic (mirrorless / Lumix).
//! - Phase 4: GoPro + DJI (action cams / drones).
//! - Phase ∞ (deferred): Nikon, Pentax, Fuji, Olympus, Casio, Kyocera,
//!   Leica, Minolta, Ricoh, Samsung, Sanyo, Sigma — the long-tail.
//!
//! ## D8 compliance
//!
//! No public struct fields. Every accessor is `const fn` where possible.
//! Enums are unit-variant or carry only newtype payloads. See
//! `exifast-api-conventions`.

pub mod byte_order;
pub mod detected;
pub mod dispatcher;
pub mod offset;
pub mod vendor;
pub mod vendors;

pub use byte_order::{ByteOrderSource, resolve_child_byte_order};
pub use detected::{BaseRule, ChildByteOrder, DetectedMakerNote};
pub use dispatcher::dispatch;
pub use offset::resolve_child_base;
pub use vendor::{Vendor, VendorStatus};
pub use vendors::{
  AppleMakerNote, CanonMakerNote, DjiMakerNote, GoProMakerNote, PanasonicMakerNote, SonyMakerNote,
};

/// Typed MakerNotes metadata — the top-level surface for vendor MakerNote
/// data, sitting on the parent [`ExifMeta`](crate::exif::ExifMeta).
///
/// Phase 1 carries ONLY the [`Vendor`] identification + the
/// [`DetectedMakerNote`] dispatch outcome; the per-vendor decoded slots
/// are stable surface but populate as `None` until Phase 2-4 ports the
/// corresponding tag tables.
///
/// Faithful: `MakerNotes.pm` returns a per-vendor subdirectory tag
/// table; the port's `MakerNotesMeta` is the typed surface that table
/// emits into (Phase 2+).
///
/// D8: no public fields; accessors only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakerNotesMeta {
  /// The dispatched vendor (newtype-only D8 enum).
  detected: DetectedMakerNote,
  /// Apple decoded data — populated only when [`Vendor::Apple`]
  /// dispatched AND the Phase-2 Apple port runs.
  apple: Option<AppleMakerNote>,
  /// Canon decoded data — Phase 2.
  canon: Option<CanonMakerNote>,
  /// Sony decoded data — Phase 3.
  sony: Option<SonyMakerNote>,
  /// Panasonic decoded data — Phase 3.
  panasonic: Option<PanasonicMakerNote>,
  /// GoPro decoded data — Phase 4.
  gopro: Option<GoProMakerNote>,
  /// DJI decoded data — Phase 4.
  dji: Option<DjiMakerNote>,
}

impl MakerNotesMeta {
  /// Build a `MakerNotesMeta` from a dispatch outcome. Phase 1 leaves
  /// every per-vendor slot empty; Phase 2-4 will populate the matching
  /// slot during the IFD walk.
  #[must_use]
  #[inline]
  pub const fn from_detected(detected: DetectedMakerNote) -> Self {
    Self {
      detected,
      apple: None,
      canon: None,
      sony: None,
      panasonic: None,
      gopro: None,
      dji: None,
    }
  }

  /// The dispatched [`Vendor`] — the most useful Phase-1 accessor.
  /// Even without per-vendor tag tables, the vendor identification
  /// alone is camera-metadata-meaningful (it gates per-vendor handling
  /// downstream).
  #[must_use]
  #[inline(always)]
  pub const fn vendor(&self) -> Vendor {
    self.detected.vendor()
  }

  /// The full dispatch outcome — vendor + body offset + base rule +
  /// byte-order directive + NotIFD flag.
  #[must_use]
  #[inline(always)]
  pub const fn detected(&self) -> DetectedMakerNote {
    self.detected
  }

  /// Apple decoded data. Phase 1 returns `None` even when
  /// [`Vendor::Apple`] dispatched; Phase 2 will populate.
  #[must_use]
  #[inline(always)]
  pub const fn apple(&self) -> Option<&AppleMakerNote> {
    self.apple.as_ref()
  }

  /// Canon decoded data. Phase 1 returns `None`; Phase 2 will populate.
  #[must_use]
  #[inline(always)]
  pub const fn canon(&self) -> Option<&CanonMakerNote> {
    self.canon.as_ref()
  }

  /// Sony decoded data. Phase 1 returns `None`; Phase 3 will populate.
  #[must_use]
  #[inline(always)]
  pub const fn sony(&self) -> Option<&SonyMakerNote> {
    self.sony.as_ref()
  }

  /// Panasonic decoded data. Phase 1 returns `None`; Phase 3 will
  /// populate.
  #[must_use]
  #[inline(always)]
  pub const fn panasonic(&self) -> Option<&PanasonicMakerNote> {
    self.panasonic.as_ref()
  }

  /// GoPro decoded data. Phase 1 returns `None`; Phase 4 will populate.
  #[must_use]
  #[inline(always)]
  pub const fn gopro(&self) -> Option<&GoProMakerNote> {
    self.gopro.as_ref()
  }

  /// DJI decoded data. Phase 1 returns `None`; Phase 4 will populate.
  #[must_use]
  #[inline(always)]
  pub const fn dji(&self) -> Option<&DjiMakerNote> {
    self.dji.as_ref()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// `MakerNotesMeta::from_detected` round-trips the vendor.
  #[test]
  fn from_detected_round_trips_vendor() {
    let d = dispatch(
      b"Apple iOS\x00\x00\x01MM",
      Some("Apple"),
      Some("iPhone 13"),
      None,
    );
    let meta = MakerNotesMeta::from_detected(d);
    assert!(meta.vendor().is_apple());
    assert_eq!(meta.detected().body_offset(), 14);
  }

  /// All per-vendor accessors return `None` in Phase 1.
  #[test]
  fn phase1_vendor_slots_are_empty() {
    let d = dispatch(b"Apple iOS\x00\x00\x01MM", Some("Apple"), None, None);
    let meta = MakerNotesMeta::from_detected(d);
    assert!(meta.apple().is_none());
    assert!(meta.canon().is_none());
    assert!(meta.sony().is_none());
    assert!(meta.panasonic().is_none());
    assert!(meta.gopro().is_none());
    assert!(meta.dji().is_none());
  }

  /// Unknown MakerNote builds an `Unknown` meta.
  #[test]
  fn unknown_dispatches_to_unknown_vendor() {
    let d = dispatch(b"some-random-bytes", Some("RandomVendor"), None, None);
    let meta = MakerNotesMeta::from_detected(d);
    assert!(meta.vendor().is_unknown());
  }
}
