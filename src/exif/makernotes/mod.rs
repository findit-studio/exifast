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
//!
//! ## Single-walker invariant (#243)
//!
//! For each migrated vendor (Apple, Canon, Sony, Panasonic, Nikon) the
//! Main-IFD MakerNote walk is the ONE isolated helper
//! `crate::exif::<v>_makernote_isolated` — a fresh shared `Walker` (the
//! faithful `ProcessExif`) routed from BOTH the `-j` collection path and the
//! `-n` `MakerNoteValueConvDecode::recompute`. The parallel per-vendor
//! `walk_<v>_in_tiff` / `parse_in_tiff` oracle was DELETED in #243 phase 5
//! (closes #230 / #231); do not reintroduce a second per-vendor Main walker —
//! a single walker is the only way the `-j`/`-n` byte-identity contract is
//! enforced by construction (two walkers can drift). The compiler is the
//! enforcement: the oracle entry points and their pub-use re-exports are gone,
//! so any reintroduced reference fails to build.
//!
//! The two cross-vendor **Leica** routes that decode with `%Panasonic::Main`
//! (`MakerNoteLeica` / Leica1 @ body offset 8, `MakerNoteLeica10` @ body offset
//! 18) were FOLDED onto the same shared `Walker` in #255: `parse_leica1_gated`
//! / `parse_leica10_gated` apply their make / signature gate then call the
//! generalized `crate::exif::panasonic_makernote_isolated_with_offset` (the
//! body of `panasonic_makernote_isolated` parameterized over the body offset).
//! Panasonic/Leica therefore have NO per-vendor walker — the last
//! `walk_panasonic_in_tiff` + `parse_in_tiff` oracle is gone, so the shared
//! `Walker` is the SOLE Main-IFD walker for EVERY migrated vendor + the Leica
//! cross-tables. The other nine **Leica2-9** `MakerNotes.pm` variants route to
//! the unported `Panasonic::Leica2..Leica9` tables (the dispatcher classifies
//! them but emits nothing) and are a SEPARATE follow-up; if ported, Leica7
//! (`MakerNoteLeica7`, M-Monochrom Typ 246, `MakerNotes.pm:690-700`) carries
//! `Base => '-$base'` ("uses absolute file offsets, not based on TIFF header
//! offset") AND is a `LeicaTrailer` special-case — a NEGATED out-of-line base,
//! distinct from the inherit (0) / `Base => 12` addends the current
//! `value_offset_base` thread handles, so it needs a signed/negated base path.
//!
//! EXCEPTIONS, by design: Canon's CTMD re-dispatch
//! (`redispatch_ctmd_makernote`) and the Panasonic `%Panasonic::Main` automatic
//! route both go through the shared `Walker` (the isolated helpers), NOT a
//! per-vendor oracle. DJI is the one unmigrated vendor and retains its own
//! `parse` / `parse_in_tiff`.

// NOTE: no file-level `#![deny(clippy::indexing_slicing)]` here. This is a
// PARENT module (it declares `pub mod dispatcher;` + `pub mod vendors;`), and
// an inner `#![deny]` lint attribute cascades into ALL descendant modules —
// including `dispatcher` and `vendors::canon`, which are owned by wave-2
// slice D and are NOT yet checked-indexing-clean. Matching the established
// Phase-C pattern (`src/formats/mod.rs` carries no such deny either), the
// deny lives on the LEAF files only (`byte_order`/`detected`/`offset`/
// `vendor` + each vendor leaf); this parent has no raw indexing of its own.

pub mod byte_order;
pub mod detected;
pub mod dispatcher;
pub mod fixbase;
pub mod offset;
pub mod subdir;
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
  AppleMakerNote, CanonMakerNote, DjiMakerNote, MakerNotesLeica, MakerNotesNikon, MakerNotesPentax,
  MakerNotesSamsung, PanasonicMakerNote, SonyMakerNote,
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
  /// Nikon decoded data — populated when [`Vendor::Nikon`] dispatched AND
  /// the Nikon port runs (`%Nikon::Main`, the readable scalars + AFInfo +
  /// ColorBalance).
  nikon: Option<MakerNotesNikon>,
  /// Pentax decoded data — populated when [`Vendor::Pentax`] dispatched AND
  /// the Pentax port runs (`%Pentax::Main`, the readable scalars + LensType).
  pentax: Option<MakerNotesPentax>,
  /// Samsung decoded data — populated when [`Vendor::Samsung`] dispatched AND
  /// the Samsung Type2 port runs (`%Samsung::Type2`, the plain leaves +
  /// PictureWizard).
  samsung: Option<MakerNotesSamsung>,
  /// Leica decoded data — populated when [`Vendor::Leica`] dispatched to one of
  /// the Leica2..Leica9 variant tables (`%Panasonic::Leica2`..`Leica9`, the
  /// plain camera-identity leaves). The Leica1/Leica10 cross-vendor routes
  /// populate [`panasonic`](Self::panasonic) instead (they are Panasonic tags).
  leica: Option<MakerNotesLeica>,
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
      nikon: None,
      pentax: None,
      samsung: None,
      leica: None,
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

  /// Replace the Nikon slot — used by the IFD walker during walk.
  #[inline(always)]
  pub fn set_nikon(&mut self, nikon: MakerNotesNikon) {
    self.nikon = Some(nikon);
  }

  /// Replace the Pentax slot — used by the IFD walker during walk.
  #[inline(always)]
  pub fn set_pentax(&mut self, pentax: MakerNotesPentax) {
    self.pentax = Some(pentax);
  }

  /// Replace the Samsung slot — used by the IFD walker during walk.
  #[inline(always)]
  pub fn set_samsung(&mut self, samsung: MakerNotesSamsung) {
    self.samsung = Some(samsung);
  }

  /// Replace the Leica slot — used by the IFD walker during walk (#259).
  #[inline(always)]
  pub fn set_leica(&mut self, leica: MakerNotesLeica) {
    self.leica = Some(leica);
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
  /// parser through the SAME gated path the production `ProcessExif` IFD
  /// walk uses — the shared `Walker`'s isolated Sony/Panasonic helpers, which
  /// apply the [`vendors::sony::routes_to_main`] /
  /// [`vendors::panasonic::routes_to_main`] variant gate FIRST — so:
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
        // Thread the IFD0 `Make` so the format-16 (`int64u`) Apple carve-out
        // gates on `Make eq 'Apple'` (`Exif.pm:6464`) — a non-Apple container
        // with an Apple-signature blob rejects code 16. Route through the SAME
        // isolated shared-`Walker` helper the production `-j`/`-n` dispatch uses
        // (`exif::apple_makernote_isolated`); with `print_conv = true` it builds
        // the typed slot from the walked entries (byte-identical to the retired
        // `apple::parse` oracle). The emissions are discarded — `from_blob` sets
        // only the typed slot.
        let (_emissions, typed) =
          crate::exif::apple_makernote_isolated(blob, parent_order, true, make);
        meta.apple = typed;
      }
      Vendor::Canon => {
        // Route through the SAME isolated shared-`Walker` helper the production
        // `-j`/`-n` dispatch uses (`exif::canon_makernote_isolated`), over the
        // captured blob (`mn_offset = 0`, `mn_len = blob.len()`). With
        // `print_conv = true` it returns the typed slot built from the walked
        // entries (byte-identical to the retired `canon::parse` oracle — a
        // short/rejected MakerNote still yields `Some(empty)`, never `None`).
        // The emissions are discarded — `from_blob` sets only the typed slot.
        let (_emissions, typed) = crate::exif::canon_makernote_isolated(
          blob,
          0,
          blob.len(),
          parent_order,
          None,
          None,
          true,
        );
        meta.canon = typed;
      }
      Vendor::Sony => {
        // Route through the SAME isolated shared-`Walker` helper the production
        // `-j`/`-n` dispatch uses (`exif::sony_makernote_isolated`): the
        // `routes_to_main` variant gate lives inside it. `make`/`model` are
        // threaded so the headerless Sony5 make-gate + the model-conditional
        // AF rows resolve; without them (the `from_blob` path) only the
        // prefixed Main variants parse.
        let body_off = detected.body_offset() as usize;
        if let Some((_emissions, typed)) = crate::exif::sony_makernote_isolated(
          blob,
          0,
          blob.len(),
          body_off,
          parent_order,
          make,
          model,
          // The `from_blob` path has no parent IFD0, so `$$self{Software}` is
          // unavailable; the `Tag9401` ISOInfo Software-disambiguated rows fall
          // through (the non-Software-keyed `Ver9401` rows still resolve).
          None,
          true,
        ) {
          meta.sony = Some(typed);
        }
      }
      Vendor::Panasonic => {
        // Route through the SAME isolated shared-`Walker` helper the production
        // `-j`/`-n` dispatch uses (`exif::panasonic_makernote_isolated`): the
        // `Panasonic`-prefix variant gate lives inside it, and the `Base => 12`
        // base-rule is resolved at the call site (`main_base_offset`) EXACTLY as
        // the production dispatch does, then threaded as the out-of-line-offset
        // base. A Type2/`MKE` blob leaves the slot absent; a DC-FT7 out-of-line
        // value is read at the correct `+12` base. `model` selects the
        // 0x0f/0x2c model-conditional branches.
        if let Some((_emissions, typed)) = crate::exif::panasonic_makernote_isolated(
          blob,
          0,
          blob.len(),
          vendors::panasonic::main_base_offset(detected.base_rule()),
          parent_order,
          model,
          true,
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
        } else if let Some(variant) = vendors::leica::discriminate_variant(blob, make, model) {
          // The Leica2..Leica9 variant tables (#259). Leica1/Leica10 did not
          // match, so route the blob through the SAME isolated shared-`Walker`
          // helper the production `-j`/`-n` dispatch uses
          // (`exif::leica_makernote_isolated`), over the captured blob
          // (`mn_offset = 0`, `mn_len = blob.len()`). The dispatched `detected`
          // carries the per-variant `Start`/`Base`/`ByteOrder`; `model` threads
          // the Leica6 Typ-006 `Condition`. The emissions are discarded —
          // `from_blob` sets only the typed slot. A genuinely-unrecognized blob
          // returns `None` from `discriminate_variant` and leaves the slot absent.
          meta.leica = Some(
            crate::exif::leica_makernote_isolated(
              blob,
              0,
              blob.len(),
              variant,
              detected,
              parent_order,
              // The blob IS the whole buffer here (`mn_offset = 0`), with no
              // parent TIFF slice — so the parent base is 0 and Leica7's
              // `-$base` rebase is a no-op (`-0`). A Leica7 blob whose value
              // pointers are absolute FILE offsets is only faithfully decoded on
              // the in-TIFF path (which threads the real parent base); this
              // blob-only constructor decodes blob-relative pointers, unchanged.
              0,
              model,
              true,
            )
            .map(|(_emissions, typed)| typed)
            .unwrap_or_default(),
          );
        }
      }
      Vendor::Dji => {
        let (typed, _emissions) = vendors::dji::parse(blob, parent_order);
        meta.dji = Some(typed);
      }
      // Nikon has THREE layouts with DIFFERENT base semantics, and only ONE is
      // faithfully decodable from the captured blob ALONE — hence the `Nikon\0
      // \x02` guard:
      //   - type-3 (`Nikon\0\x02…`, `MakerNotes.pm:51-58`) carries a
      //     SELF-CONTAINED embedded TIFF (`Base => '$start - 8'` rebases its
      //     out-of-line offsets to blob offset 10) ⇒ the blob IS the TIFF
      //     context, so the standalone-blob walk is faithful.
      //   - type-2 (`Nikon\0\x01`, `MakerNotes.pm:539-545`) and headerless
      //     Nikon3 (`MakerNotes.pm:546-554`) have NO `Base` override ⇒ their
      //     out-of-line value offsets are PARENT-TIFF-relative. This blob-only
      //     constructor has NO parent TIFF, so an absolute offset would index
      //     INTO the blob and read out-of-line values from the wrong bytes
      //     (garbage) or fall outside it. The production decode never reaches
      //     here — `Exif`'s MakerNote arm calls `nikon::parse_in_tiff` with the
      //     real parent TIFF (`src/exif/mod.rs`) — so this gate is purely
      //     defensive for direct `from_blob`/`from_blob_with_context` callers
      //     (tests/tools). They fall to the `_` arm below ⇒ the Nikon slot
      //     stays UNPOPULATED (no mis-rebased garbage; the vendor is still
      //     identified via `detected`).
      // `model` threads the AFInfo byte-order + ShootingMode bit-5 `Condition`s.
      Vendor::Nikon if blob.starts_with(b"Nikon\x00\x02") => {
        // Route through the SAME isolated shared-`Walker` helper the production
        // `-j`/`-n` dispatch uses (`exif::nikon_makernote_isolated`), over the
        // captured blob (`mn_offset = 0`, `mn_len = blob.len()`). The guard above
        // restricts this to the self-contained type-3 layout, so the standalone
        // walk is faithful when the embedded TIFF is well-formed. With
        // `print_conv = true` the helper returns the typed slot built from the
        // walked entries (byte-identical to the retired `nikon::parse` oracle).
        // The 8-byte `Nikon\0\x02` signature guard does NOT prove a valid
        // embedded TIFF at offset 10, so a SHORT/MALFORMED type-3 header makes
        // `resolve_layout`/`parse_embedded_tiff` reject it and the helper
        // returns `None`. In that case fall back to the empty-but-PRESENT typed
        // slot, preserving the retired `nikon::parse` constructor contract: a
        // signature match ALWAYS populates `meta.nikon` (empty if the walk
        // yields nothing), never leaving it absent. The emissions are discarded
        // — `from_blob` sets only the typed slot.
        meta.nikon = Some(
          crate::exif::nikon_makernote_isolated(blob, 0, blob.len(), parent_order, model, true)
            .map(|(_emissions, typed)| typed)
            .unwrap_or_default(),
        );
      }
      Vendor::Pentax => {
        // Route through the SAME isolated shared-`Walker` helper the production
        // `-j`/`-n` dispatch uses (`exif::pentax_makernote_isolated`), over the
        // captured blob (`mn_offset = 0`, `mn_len = blob.len()`). The Pentax
        // primary (`AOC\0`) inherits the parent base and is self-contained, so
        // the standalone-blob walk is faithful; the dispatched `detected` carries
        // the body offset / `Unknown` byte order / `FixBase` the helper threads.
        // `make`/`model` are threaded so the FixBase heuristic's PENTAX
        // absolute-addressing arm fires; a dispatched `NotIFD => 1` variant
        // (Pentax4, an unported binary table) emits NOTHING — the helper gates it
        // internally, so this arm never produces bogus `%Pentax::Main` tags.
        // With `print_conv = true` it returns the typed slot built from the
        // walked entries; a short/rejected/NotIFD MakerNote yields `Some(empty)`.
        // The emissions are discarded — `from_blob` sets only the typed slot.
        meta.pentax = Some(
          crate::exif::pentax_makernote_isolated(
            blob,
            0,
            blob.len(),
            detected,
            parent_order,
            make,
            model,
            true,
          )
          .map(|(_emissions, typed)| typed)
          .unwrap_or_default(),
        );
      }
      Vendor::Samsung => {
        // Route through the SAME isolated shared-`Walker` helper the production
        // `-j`/`-n` dispatch uses (`exif::samsung_makernote_isolated`), over the
        // captured blob (`mn_offset = 0`, `mn_len = blob.len()`). The
        // `MakerNoteSamsung2` body offset is 0, it inherits the parent base and
        // probes its own byte order (`ByteOrder => Unknown`), so the
        // standalone-blob walk is faithful when the blob is the captured Type2
        // value; the dispatched `detected` carries the `FixBase => 1` heuristic
        // the helper threads. With `print_conv = true` it returns the typed slot
        // built from the walked entries; a short/rejected MakerNote yields
        // `Some(empty)`. The emissions are discarded — `from_blob` sets only the
        // typed slot. Note: a standalone JPEG/PNG-embedded Samsung2 body relies
        // on its EXIF-format magic to dispatch here; an SRW-only body needs the
        // container's `TIFF_TYPE`, which the production walk threads.
        meta.samsung = Some(
          crate::exif::samsung_makernote_isolated(
            blob,
            0,
            blob.len(),
            detected,
            parent_order,
            make,
            model,
            // No container `TIFF_TYPE` here (`from_blob` is the standalone-blob
            // path) ⇒ the `0x0035 PreviewIFD` SRW gate fails, so it is not
            // descended — and `from_blob` only wants the typed slot anyway (#242).
            None,
            true,
          )
          .map(|(_emissions, typed)| typed)
          .unwrap_or_default(),
        );
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

  /// Nikon decoded data. `None` unless [`Vendor::Nikon`] dispatched and the
  /// Nikon port ran.
  #[must_use]
  #[inline(always)]
  pub const fn nikon(&self) -> Option<&MakerNotesNikon> {
    self.nikon.as_ref()
  }

  /// Pentax decoded data. `None` unless [`Vendor::Pentax`] dispatched and the
  /// Pentax port ran.
  #[must_use]
  #[inline(always)]
  pub const fn pentax(&self) -> Option<&MakerNotesPentax> {
    self.pentax.as_ref()
  }

  /// Samsung decoded data. `None` unless [`Vendor::Samsung`] dispatched and the
  /// Samsung Type2 port ran.
  #[must_use]
  #[inline(always)]
  pub const fn samsung(&self) -> Option<&MakerNotesSamsung> {
    self.samsung.as_ref()
  }

  /// Leica decoded data — populated when the dispatcher resolved
  /// [`Vendor::Leica`](Vendor::Leica) to a Leica2..Leica9 variant table (#259).
  /// `None` for the Leica1/Leica10 cross-vendor routes (see
  /// [`panasonic`](Self::panasonic)).
  #[must_use]
  #[inline(always)]
  pub const fn leica(&self) -> Option<&MakerNotesLeica> {
    self.leica.as_ref()
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
