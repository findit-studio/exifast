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
//! - Phase 4: DJI (drones). GoPro is intentionally NOT a MakerNote
//!   vendor — bundled has no `MakerNoteGoPro` (see `vendors/mod.rs`).
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
#[cfg(feature = "alloc")]
pub use vendors::VendorEmission;
pub use vendors::{
  AppleMakerNote, CanonMakerNote, DjiMakerNote, PanasonicMakerNote, SonyMakerNote,
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
#[derive(Debug, Clone, PartialEq)]
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
      dji: None,
    }
  }

  /// Replace the Apple slot — used by the IFD walker during walk to
  /// populate the typed surface from the parsed Apple body.
  #[inline(always)]
  pub fn set_apple(&mut self, apple: AppleMakerNote) {
    self.apple = Some(apple);
  }

  /// Replace the Canon slot — used by the IFD walker during walk.
  #[inline(always)]
  pub fn set_canon(&mut self, canon: CanonMakerNote) {
    self.canon = Some(canon);
  }

  /// Replace the Sony slot — used by the IFD walker during walk (Phase 3).
  #[inline(always)]
  pub fn set_sony(&mut self, sony: SonyMakerNote) {
    self.sony = Some(sony);
  }

  /// Replace the Panasonic slot — used by the IFD walker during walk
  /// (Phase 3).
  #[inline(always)]
  pub fn set_panasonic(&mut self, panasonic: PanasonicMakerNote) {
    self.panasonic = Some(panasonic);
  }

  /// Replace the DJI slot — used by the IFD walker during walk
  /// (Phase 4).
  #[inline(always)]
  pub fn set_dji(&mut self, dji: DjiMakerNote) {
    self.dji = Some(dji);
  }

  /// Build a `MakerNotesMeta` and POPULATE the per-vendor slot when the
  /// dispatcher resolved a supported vendor.
  ///
  /// Phase 2 populates [`Self::apple`] / [`Self::canon`]; Phase 3 adds
  /// [`Self::sony`] / [`Self::panasonic`]; Phase 4 adds [`Self::dji`]
  /// (full Main table). GoPro is not a MakerNote vendor (bundled has no
  /// `MakerNoteGoPro`) — see `vendors/mod.rs`.
  ///
  /// `blob` is the raw 0x927C MakerNote value; `parent_order` is the
  /// parent IFD walk's byte order (used as the body-marker fallback per
  /// [`resolve_child_byte_order`]). The standalone `blob` IS the parser's
  /// TIFF context (`mn_offset == 0`, `mn_len == blob.len()`), so a vendor's
  /// out-of-line value offsets resolve against the blob itself — correct
  /// when the blob is self-contained (the common case for a captured
  /// MakerNote value).
  ///
  /// ## Sony / Panasonic gating — the variant gate cannot be bypassed
  ///
  /// The dispatcher collapses every Sony/Panasonic `MakerNotes.pm` variant
  /// to [`Vendor::Sony`] / [`Vendor::Panasonic`], but only a SUBSET routes
  /// to `%Sony::Main` / `%Panasonic::Main`. This constructor runs the Main
  /// parser through the SAME gated entry the production `ProcessExif` IFD
  /// walk uses — [`vendors::sony::parse_main_gated`] and
  /// [`vendors::panasonic::parse_main_gated`] — so:
  ///
  /// - A non-Main Sony variant (a `SEMC MS\0` SonyEricsson blob, a
  ///   `SONY PIC\0` Sony4 blob, …) returns `None` from the gate and the
  ///   [`sony`](Self::sony) slot stays ABSENT — no spurious Main tag from a
  ///   coincidental tag-id collision.
  /// - A Panasonic Type2 (`MKE`) blob returns `None` and the
  ///   [`panasonic`](Self::panasonic) slot stays ABSENT (Type2 is a
  ///   `ProcessBinaryData` table, unported).
  /// - A Panasonic `MakerNotePanasonic3` (DC-FT7, `Base => 12`) blob threads
  ///   the dispatched [`BaseRule`](crate::exif::makernotes::BaseRule) through
  ///   the gate, so an out-of-line value (e.g. `LensType`) is read at the
  ///   `+12` base instead of 12 bytes early.
  /// - A cross-vendor `MakerNoteLeica10` (`LEICA CAMERA AG\0` signature)
  ///   blob routes to `%Panasonic::Main` via
  ///   [`vendors::panasonic::parse_leica10_gated`] and populates the
  ///   [`panasonic`](Self::panasonic) slot. The make-only `MakerNoteLeica`
  ///   (Leica1, `$$self{Make} eq "LEICA"`) route shares the same Sony5
  ///   make-less caveat below — it cannot fire here.
  ///
  /// ## Sony5 / Leica1 make-less caveat (`make`/`model` unavailable here)
  ///
  /// The Sony gate's `routes_to_main` make-condition (`MakerNoteSony5`'s
  /// `Make =~ /^SONY/` headerless arm, `MakerNotes.pm:1072-1075`) and the
  /// make-only `MakerNoteLeica` (Leica1, `$$self{Make} eq "LEICA"`,
  /// `:602`) need the IFD0 `$$self{Make}`/`$$self{Model}`. THIS constructor
  /// carries NO Make/Model (it receives only the already-computed `detected`
  /// + the raw blob), so it passes `make = model = None`. The PREFIXED Main
  /// variants (`SONY DSC`/`SONY CAM`/`SONY MOBILE`/`VHAB`/TF1, and the
  /// signature-gated `MakerNoteLeica10` `LEICA CAMERA AG\0`) carry their own
  /// signature and resolve here regardless of Make; a HEADERLESS Sony5 blob
  /// (identified ONLY by `Make =~ /^SONY/`) and a make-only Leica1 blob gate
  /// `false` without the Make, leaving the slot absent. That is the FAITHFUL
  /// choice for this make-less entry — leaving the slot absent is correct (no
  /// wrong values), whereas an ungated Main parse would re-introduce the
  /// spurious-tag bug for the non-Main variants.
  ///
  /// To resolve the make-only variants, use
  /// [`from_blob_with_context`](Self::from_blob_with_context) — it threads the
  /// IFD0 `Make`/`Model` into the SAME gates the production `ProcessExif` walk
  /// uses, so a headerless Sony5 / make-only Leica1 blob populates its slot.
  /// `from_blob` is the no-context convenience for callers that have only the
  /// captured blob.
  #[must_use]
  #[inline]
  pub fn from_blob(
    detected: DetectedMakerNote,
    blob: &[u8],
    parent_order: crate::exif::ifd::ByteOrder,
  ) -> Self {
    Self::from_blob_with_context(detected, blob, parent_order, None, None)
  }

  /// Build a `MakerNotesMeta` from a captured blob WITH the IFD0
  /// `$$self{Make}`/`$$self{Model}` context, populating the per-vendor slot
  /// when the dispatcher resolved a supported vendor.
  ///
  /// This is the context-bearing form of [`from_blob`](Self::from_blob): the
  /// `make`/`model` are threaded into the SAME gated entries the production
  /// `ProcessExif` IFD walk uses, so the MAKE-ONLY variants resolve here too:
  ///
  /// - **Headerless `MakerNoteSony5`** (`MakerNotes.pm:1070-1082`) — the
  ///   `routes_to_main` make-gate `Make =~ /^SONY/` (or the HASSELBLAD-rebrand
  ///   arm) needs `make`; with it, a headerless Sony5 body decodes through
  ///   `%Sony::Main` and populates the [`sony`](Self::sony) slot.
  /// - **Make-only `MakerNoteLeica` (Leica1)** (`:599-608`) — the
  ///   `Condition` `$$self{Make} eq "LEICA"` needs `make`; with it, a
  ///   `LEICA`-make body decodes through `%Panasonic::Main` (Leica1 routes
  ///   there, `:604`) and populates the [`panasonic`](Self::panasonic) slot.
  /// - `model` additionally selects the model-conditional Sony AF rows
  ///   (0x201c/0x201e/0x2020/0x2022, `Sony.pm`) and Panasonic 0x0f/0x2c
  ///   branches — exactly as the production walk threads `$$self{Model}`.
  ///
  /// The gating contract is otherwise identical to [`from_blob`]: a non-Main
  /// Sony variant / Panasonic Type2 (`MKE`) / genuinely-Leica-table blob
  /// returns `None` from its gate and leaves the slot ABSENT (no spurious
  /// tags), and the `MakerNotePanasonic3` (`Base => 12`) base-rule is threaded
  /// through. Pass `make`/`model` as the IFD0 values (`None` if unknown — then
  /// this behaves exactly like [`from_blob`]).
  #[must_use]
  pub fn from_blob_with_context(
    detected: DetectedMakerNote,
    blob: &[u8],
    parent_order: crate::exif::ifd::ByteOrder,
    make: Option<&str>,
    model: Option<&str>,
  ) -> Self {
    let mut meta = Self::from_detected(detected);
    match detected.vendor() {
      Vendor::Apple => {
        let (typed, _emissions) = vendors::apple::parse(blob, parent_order);
        meta.apple = Some(typed);
      }
      Vendor::Canon => {
        let (typed, _emissions) = vendors::canon::parse(blob, parent_order);
        meta.canon = Some(typed);
      }
      Vendor::Sony => {
        // Route through the SINGLE gated entry (same as `ProcessExif`): the
        // `routes_to_main` variant gate lives inside it. `make`/`model` are
        // threaded so the headerless Sony5 make-gate + the model-conditional
        // AF rows resolve; without them (the `from_blob` path) only the
        // prefixed Main variants parse.
        let body_off = detected.body_offset() as usize;
        if let Some((typed, _emissions)) = vendors::sony::parse_main_gated(
          blob,
          0,
          blob.len(),
          body_off,
          parent_order,
          true,
          make,
          model,
        ) {
          meta.sony = Some(typed);
        }
      }
      Vendor::Panasonic => {
        // Route through the SINGLE gated entry (same as `ProcessExif`): the
        // `Panasonic`-prefix gate + the `Base => 12` base-rule threading
        // live inside it. A Type2/`MKE` blob leaves the slot absent; a
        // DC-FT7 out-of-line value is read at the correct `+12` base.
        // `model` selects the 0x0f/0x2c model-conditional branches.
        if let Some((typed, _emissions)) = vendors::panasonic::parse_main_gated(
          blob,
          0,
          blob.len(),
          parent_order,
          true,
          model,
          detected.base_rule(),
        ) {
          meta.panasonic = Some(typed);
        }
      }
      Vendor::Leica => {
        // Cross-vendor routes: TWO Leica variants decode with the PANASONIC
        // Main table —
        //   - `MakerNoteLeica` (Leica1, `MakerNotes.pm:599-608`) — make-only
        //     `$$self{Make} eq "LEICA"` (`:602`), `Start => '$valuePtr + 8'`
        //     (`:606`).
        //   - `MakerNoteLeica10` (`:724-730`) — `LEICA CAMERA AG\0` signature
        //     (`:725`), `Start => '$valuePtr + 18'` (`:728`).
        // Route through the SAME SINGLE gated entries as `ProcessExif`
        // (`parse_leica1_gated` / `parse_leica10_gated`), so a
        // genuinely-Leica-table blob (`LEICA\0\0\0`, …) returns `None` from
        // both and the Panasonic slot stays ABSENT (those tables are
        // unported/deferred). The body offset is the dispatched
        // `body_offset()` (8 for Leica1, 18 for Leica10). The resulting tags
        // are `%Panasonic::Main` tags ⇒ they populate the Panasonic slot
        // (bundled emits them as `Panasonic:*`).
        //
        // Leica1 is tried FIRST, mirroring `%Main` order (Leica1 `:599`
        // precedes Leica10 `:724`): its `Condition` reads `$$self{Make}`,
        // threaded here as `make` — with `make == "LEICA"` a make-only Leica1
        // body resolves; without the make (the `from_blob` path) the Leica1
        // gate yields `None` and only the signature-gated Leica10 route
        // decodes. The two are mutually exclusive for real bodies (Leica1
        // make is exactly "LEICA"; Leica10 bodies report "LEICA CAMERA AG").
        let body_off = detected.body_offset() as usize;
        let parsed = vendors::panasonic::parse_leica1_gated(
          blob,
          0,
          blob.len(),
          body_off,
          parent_order,
          true,
          make,
          model,
        )
        .or_else(|| {
          vendors::panasonic::parse_leica10_gated(
            blob,
            0,
            blob.len(),
            body_off,
            parent_order,
            true,
            model,
          )
        });
        if let Some((typed, _emissions)) = parsed {
          meta.panasonic = Some(typed);
        }
      }
      Vendor::Dji => {
        let (typed, _emissions) = vendors::dji::parse(blob, parent_order);
        meta.dji = Some(typed);
      }
      _ => {}
    }
    meta
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
