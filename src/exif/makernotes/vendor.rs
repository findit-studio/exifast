// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Vendor identity — the unit-variant enum carried by every detected
//! MakerNote and the per-vendor type slots on [`MakerNotesMeta`].
//!
//! Faithful to `MakerNotes.pm`'s `@Image::ExifTool::MakerNotes::Main`
//! (`MakerNotes.pm:35-1127`): each entry there resolves to one of the
//! variants here. A NAMED variant is reserved for every vendor the bundled
//! dispatcher distinguishes; the [`Unknown`] catch-all preserves
//! "`MakerNoteUnknown`" (`MakerNotes.pm:1117-1126`) — a maker note whose
//! bytes match none of the explicit signature/make conditions.
//!
//! ## D8 — unit-variants + `const` predicates
//!
//! Per `exifast-api-conventions` (no public struct fields; enums newtype
//! or unit-variant only): every variant is a unit-variant; the enum
//! carries NO inline payload. The vendor-specific decoded data lives in
//! per-vendor structs reached via [`MakerNotesMeta`](super::MakerNotesMeta).
//!
//! ## Phase-status tagging
//!
//! `MakerNotes` is being landed across waves. This module surfaces the
//! IMPLEMENTATION-STATUS bucket each vendor is currently in:
//!
//! - **Phase 1 (this PR)**: dispatcher infrastructure + signature
//!   detection. Every variant resolves; no per-vendor tag tables are
//!   walked yet.
//! - **Phase 2**: Apple + Canon (rescope-priority cameras: iPhone, EOS).
//! - **Phase 3**: Sony + Panasonic (mirrorless / Lumix).
//! - **Phase 4**: GoPro + DJI (action cams / drones).
//! - **Deferred (Phase ∞)**: long-tail vendors (Nikon, Pentax, Fuji,
//!   Olympus, Casio, Kyocera, Leica, Minolta, Ricoh, Samsung, Sanyo,
//!   Sigma) — kept under the dispatcher umbrella issue.

/// Implementation status of a vendor's MakerNote parser.
///
/// Phase 1 lands the dispatcher (every variant identifies); per-vendor
/// tag tables land later. See [`Vendor::status`].
///
/// D8: unit-variants + `const` predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VendorStatus {
  /// Phase 2 — Apple/Canon (rescope-priority).
  Phase2,
  /// Phase 3 — Sony/Panasonic.
  Phase3,
  /// Phase 4 — GoPro/DJI.
  Phase4,
  /// Phase ∞ (deferred) — long-tail vendor. Identifies in Phase 1, but
  /// no Phase-N tag table is currently scheduled.
  Deferred,
  /// The unidentified catch-all (`MakerNoteUnknown`,
  /// `MakerNotes.pm:1117-1126`). Identification itself is the only
  /// "decode" performed.
  Unknown,
}

impl VendorStatus {
  /// A short label for the status (`"phase2"`, `"deferred"`, …).
  /// Lower-case ASCII for log lines / diagnostics.
  #[must_use]
  #[inline(always)]
  pub const fn as_str(self) -> &'static str {
    match self {
      VendorStatus::Phase2 => "phase2",
      VendorStatus::Phase3 => "phase3",
      VendorStatus::Phase4 => "phase4",
      VendorStatus::Deferred => "deferred",
      VendorStatus::Unknown => "unknown",
    }
  }

  /// `true` if a per-vendor tag table is currently scheduled (Phase 2-4).
  #[must_use]
  #[inline(always)]
  pub const fn is_scheduled(self) -> bool {
    matches!(
      self,
      VendorStatus::Phase2 | VendorStatus::Phase3 | VendorStatus::Phase4
    )
  }

  /// `true` for the deferred (long-tail) bucket.
  #[must_use]
  #[inline(always)]
  pub const fn is_deferred(self) -> bool {
    matches!(self, VendorStatus::Deferred)
  }

  /// `true` for the unidentified catch-all.
  #[must_use]
  #[inline(always)]
  pub const fn is_unknown(self) -> bool {
    matches!(self, VendorStatus::Unknown)
  }
}

/// MakerNote vendor — the dispatch outcome of
/// `Image::ExifTool::MakerNotes::Main` (`MakerNotes.pm:35-1127`).
///
/// `#[non_exhaustive]`: a Phase-2/3/4 port may add a sub-variant within a
/// vendor family (`Sony2`, `Olympus3`, …) — bundled has e.g. `MakerNoteSony`
/// vs `MakerNoteSony2`/`...5`, distinguished here by the per-vendor decoder
/// rather than by adding an enum variant. The non-exhaustive marker keeps
/// downstream `match` arms tolerant of additional vendors.
///
/// D8: unit-variants only (no inline payload); the per-vendor structs hang
/// off [`MakerNotesMeta`](super::MakerNotesMeta) as `Option<…>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Vendor {
  /// Apple (iOS — `MakerNoteApple`, `MakerNotes.pm:38-46`).
  Apple,
  /// Canon (`MakerNoteCanon`, `MakerNotes.pm:61-69`).
  Canon,
  /// Casio (`MakerNoteCasio` + `MakerNoteCasio2`,
  /// `MakerNotes.pm:71-79`/`:81-91`). Deferred long-tail.
  Casio,
  /// DJI drones (`MakerNoteDJI` + `MakerNoteDJIInfo`,
  /// `MakerNotes.pm:93-106`).
  Dji,
  /// FLIR thermal (`MakerNoteFLIR`, `MakerNotes.pm:108-117`).
  Flir,
  /// FujiFilm (`MakerNoteFujiFilm`, `MakerNotes.pm:118-134`).
  /// Deferred long-tail.
  Fuji,
  /// General Imaging GE (`MakerNoteGE` + `MakerNoteGE2`,
  /// `MakerNotes.pm:135-160`). Deferred long-tail.
  Ge,
  /// Google HDR+ (`MakerNoteGoogle`, `MakerNotes.pm:161-167`). The
  /// dispatcher distinguishes it; Phase 1 surfaces as `Google` (no
  /// per-vendor decode yet).
  Google,
  /// GoPro action cameras. The bundled dispatcher does NOT carry a
  /// dedicated `MakerNoteGoPro` entry — GoPro MakerNotes attach via the
  /// generic Exif IFD without a vendor signature, so identification is
  /// by `$$self{Make}` only. Phase 4 will add the explicit signature.
  GoPro,
  /// Hasselblad (`MakerNoteHasselblad`, `MakerNotes.pm:169-182`).
  /// Deferred long-tail.
  Hasselblad,
  /// HP / Hewlett-Packard / Vivitar variants (`MakerNoteHP` /
  /// `MakerNoteHP2` / `MakerNoteHP4` / `MakerNoteHP6`,
  /// `MakerNotes.pm:185-223`). Deferred long-tail.
  Hp,
  /// ISL (`MakerNoteISL`, used by Samsung GX20 samples,
  /// `MakerNotes.pm:225-234`). Deferred long-tail.
  Isl,
  /// JVC / Victor (`MakerNoteJVC` + `MakerNoteJVCText`,
  /// `MakerNotes.pm:236-251`). Deferred long-tail.
  Jvc,
  /// Kodak (a large family — `MakerNoteKodak1a`..`MakerNoteKodakUnknown`,
  /// `MakerNotes.pm:253-481`). Deferred long-tail.
  Kodak,
  /// Kyocera (`MakerNoteKyocera`, `MakerNotes.pm:483-492`). Deferred
  /// long-tail.
  Kyocera,
  /// Leica (eight numbered variants — `MakerNoteLeica`..`MakerNoteLeica10`,
  /// `MakerNotes.pm:600-731`). Deferred long-tail.
  Leica,
  /// Konica Minolta / Minolta (`MakerNoteMinolta` /
  /// `MakerNoteMinolta2` / `MakerNoteMinolta3`,
  /// `MakerNotes.pm:495-526`). Deferred long-tail.
  Minolta,
  /// Motorola (`MakerNoteMotorola`, `MakerNotes.pm:528-535`). Deferred
  /// long-tail.
  Motorola,
  /// Nikon (`MakerNoteNikon` / `MakerNoteNikon2` / `MakerNoteNikon3`,
  /// `MakerNotes.pm:51-58`/`:539-554`). Deferred long-tail.
  Nikon,
  /// Nintendo (`MakerNoteNintendo`, `MakerNotes.pm:557-563`). Deferred
  /// long-tail.
  Nintendo,
  /// Olympus / OM System / EPSON (`MakerNoteOlympus` /
  /// `MakerNoteOlympus2` / `MakerNoteOlympus3`,
  /// `MakerNotes.pm:566-597`). Deferred long-tail.
  Olympus,
  /// Panasonic (`MakerNotePanasonic` / `MakerNotePanasonic2` /
  /// `MakerNotePanasonic3`, `MakerNotes.pm:732-760`).
  Panasonic,
  /// Pentax / Asahi (`MakerNotePentax`..`MakerNotePentax6`,
  /// `MakerNotes.pm:763-839`). Deferred long-tail.
  Pentax,
  /// PhaseOne (`MakerNotePhaseOne`, `MakerNotes.pm:841-852`). Deferred
  /// long-tail.
  PhaseOne,
  /// Reconyx trail cameras (a family — `MakerNoteReconyxHyperFire` /
  /// `MakerNoteReconyxUltraFire` / `MakerNoteReconyxHyperFire2` /
  /// `MakerNoteReconyxMicroFire` / `MakerNoteReconyxHyperFire4K`,
  /// `MakerNotes.pm:854-895`). Deferred long-tail.
  Reconyx,
  /// Ricoh (`MakerNoteRicoh` / `MakerNoteRicoh2` / `MakerNoteRicohText` /
  /// `MakerNoteRicohPentax`, `MakerNotes.pm:897-948`). Deferred
  /// long-tail.
  Ricoh,
  /// Samsung STMN/SRW (`MakerNoteSamsung1a` / `MakerNoteSamsung1b` /
  /// `MakerNoteSamsung2`, `MakerNotes.pm:950-979`). Deferred long-tail.
  Samsung,
  /// Sanyo (`MakerNoteSanyo` / `MakerNoteSanyoC4` /
  /// `MakerNoteSanyoPatch`, `MakerNotes.pm:981-1014`). Deferred
  /// long-tail.
  Sanyo,
  /// Sigma / Foveon (`MakerNoteSigma`, `MakerNotes.pm:1016-1029`).
  /// Deferred long-tail.
  Sigma,
  /// Sony (six numbered variants — `MakerNoteSony`..`MakerNoteSony5`,
  /// `MakerNoteSonyEricsson`, `MakerNoteSonySRF`,
  /// `MakerNotes.pm:1031-1099`).
  Sony,
  /// The unidentified catch-all (`MakerNoteUnknown`,
  /// `MakerNotes.pm:1117-1126`) — a maker note whose bytes match no
  /// explicit signature and whose `$$self{Make}` matches no vendor.
  Unknown,
}

impl Vendor {
  /// The bundled `Name` for this vendor's PRIMARY dispatch entry — used in
  /// diagnostics and matches the `MakerNotes.pm` `Name => '…'` field of
  /// the first (most-common) variant in the family.
  #[must_use]
  #[inline]
  pub const fn name(self) -> &'static str {
    match self {
      Vendor::Apple => "MakerNoteApple",
      Vendor::Canon => "MakerNoteCanon",
      Vendor::Casio => "MakerNoteCasio",
      Vendor::Dji => "MakerNoteDJI",
      Vendor::Flir => "MakerNoteFLIR",
      Vendor::Fuji => "MakerNoteFujiFilm",
      Vendor::Ge => "MakerNoteGE",
      Vendor::Google => "MakerNoteGoogle",
      Vendor::GoPro => "MakerNoteGoPro",
      Vendor::Hasselblad => "MakerNoteHasselblad",
      Vendor::Hp => "MakerNoteHP",
      Vendor::Isl => "MakerNoteISL",
      Vendor::Jvc => "MakerNoteJVC",
      Vendor::Kodak => "MakerNoteKodak",
      Vendor::Kyocera => "MakerNoteKyocera",
      Vendor::Leica => "MakerNoteLeica",
      Vendor::Minolta => "MakerNoteMinolta",
      Vendor::Motorola => "MakerNoteMotorola",
      Vendor::Nikon => "MakerNoteNikon",
      Vendor::Nintendo => "MakerNoteNintendo",
      Vendor::Olympus => "MakerNoteOlympus",
      Vendor::Panasonic => "MakerNotePanasonic",
      Vendor::Pentax => "MakerNotePentax",
      Vendor::PhaseOne => "MakerNotePhaseOne",
      Vendor::Reconyx => "MakerNoteReconyxHyperFire",
      Vendor::Ricoh => "MakerNoteRicoh",
      Vendor::Samsung => "MakerNoteSamsung",
      Vendor::Sanyo => "MakerNoteSanyo",
      Vendor::Sigma => "MakerNoteSigma",
      Vendor::Sony => "MakerNoteSony",
      Vendor::Unknown => "MakerNoteUnknown",
    }
  }

  /// The ExifTool FAMILY-1 group name for this vendor's MakerNote tags
  /// (the `"<family1>:<Name>"` key prefix under `-G1`).
  ///
  /// The per-vendor tag tables (`Apple.pm`/`Canon.pm`) declare only
  /// `GROUPS => { 0 => 'MakerNotes', … }` (`Apple.pm:28`, `Canon.pm:1225`),
  /// so family-0 is the literal `"MakerNotes"`. Under `-G1` ExifTool
  /// instead emits the family-1 group, which it derives from the MakerNote
  /// MODULE/vendor — i.e. the VENDOR name (`exiftool -j -G1` emits
  /// `Apple:RunTime` on an iPhone, `Canon:LensType` on a Canon).
  ///
  /// Only the vendors that currently emit cached MakerNote tags (Phase 2:
  /// Apple, Canon) have a distinct group here; the rest fall back to the
  /// family-0 `"MakerNotes"` since they emit nothing at the serializer's
  /// MakerNote site yet.
  #[must_use]
  #[inline]
  pub const fn group1(self) -> &'static str {
    match self {
      Vendor::Apple => "Apple",
      Vendor::Canon => "Canon",
      _ => "MakerNotes",
    }
  }

  /// The implementation status of this vendor's MakerNote port.
  ///
  /// Phase 2 = Apple / Canon (rescope-priority).
  /// Phase 3 = Sony / Panasonic.
  /// Phase 4 = GoPro / DJI.
  /// Phase ∞ (deferred) = every other named vendor.
  #[must_use]
  #[inline]
  pub const fn status(self) -> VendorStatus {
    match self {
      Vendor::Apple | Vendor::Canon => VendorStatus::Phase2,
      Vendor::Sony | Vendor::Panasonic => VendorStatus::Phase3,
      Vendor::GoPro | Vendor::Dji => VendorStatus::Phase4,
      Vendor::Unknown => VendorStatus::Unknown,
      Vendor::Casio
      | Vendor::Flir
      | Vendor::Fuji
      | Vendor::Ge
      | Vendor::Google
      | Vendor::Hasselblad
      | Vendor::Hp
      | Vendor::Isl
      | Vendor::Jvc
      | Vendor::Kodak
      | Vendor::Kyocera
      | Vendor::Leica
      | Vendor::Minolta
      | Vendor::Motorola
      | Vendor::Nikon
      | Vendor::Nintendo
      | Vendor::Olympus
      | Vendor::Pentax
      | Vendor::PhaseOne
      | Vendor::Reconyx
      | Vendor::Ricoh
      | Vendor::Samsung
      | Vendor::Sanyo
      | Vendor::Sigma => VendorStatus::Deferred,
    }
  }

  /// `true` if this vendor identifies via a byte-signature on the raw
  /// MakerNote blob (`MakerNotes.pm` `$$valPt =~ /.../`). The rest
  /// identify ONLY by `$$self{Make}` (and have no header to strip).
  ///
  /// Phase 1 uses this for diagnostics — `is_signature_based` is the
  /// predicate surface for callers that want to enumerate
  /// signature-bearing vendors. (The unsigned vendors below are the ones
  /// the dispatcher matches on `$$self{Make}` alone.)
  #[must_use]
  #[inline]
  pub const fn is_signature_based(self) -> bool {
    // The unsigned vendors (make-only dispatch in MakerNotes.pm) — every
    // other vendor has at least one signature variant.
    !matches!(
      self,
      Vendor::Canon // make-only (`$$self{Make} =~ /^Canon/`)
        | Vendor::GoPro // make-only (Phase-4 placeholder)
        | Vendor::Unknown // the catch-all
    )
  }

  // ----- variant predicates (D8 §3 — every variant gets a const predicate)

  /// `true` if this is [`Vendor::Apple`].
  #[must_use]
  #[inline(always)]
  pub const fn is_apple(self) -> bool {
    matches!(self, Vendor::Apple)
  }

  /// `true` if this is [`Vendor::Canon`].
  #[must_use]
  #[inline(always)]
  pub const fn is_canon(self) -> bool {
    matches!(self, Vendor::Canon)
  }

  /// `true` if this is [`Vendor::Sony`].
  #[must_use]
  #[inline(always)]
  pub const fn is_sony(self) -> bool {
    matches!(self, Vendor::Sony)
  }

  /// `true` if this is [`Vendor::Panasonic`].
  #[must_use]
  #[inline(always)]
  pub const fn is_panasonic(self) -> bool {
    matches!(self, Vendor::Panasonic)
  }

  /// `true` if this is [`Vendor::GoPro`].
  #[must_use]
  #[inline(always)]
  pub const fn is_gopro(self) -> bool {
    matches!(self, Vendor::GoPro)
  }

  /// `true` if this is [`Vendor::Dji`].
  #[must_use]
  #[inline(always)]
  pub const fn is_dji(self) -> bool {
    matches!(self, Vendor::Dji)
  }

  /// `true` if this is [`Vendor::Nikon`].
  #[must_use]
  #[inline(always)]
  pub const fn is_nikon(self) -> bool {
    matches!(self, Vendor::Nikon)
  }

  /// `true` if this is [`Vendor::Pentax`].
  #[must_use]
  #[inline(always)]
  pub const fn is_pentax(self) -> bool {
    matches!(self, Vendor::Pentax)
  }

  /// `true` if this is [`Vendor::Olympus`].
  #[must_use]
  #[inline(always)]
  pub const fn is_olympus(self) -> bool {
    matches!(self, Vendor::Olympus)
  }

  /// `true` if this is [`Vendor::Fuji`].
  #[must_use]
  #[inline(always)]
  pub const fn is_fuji(self) -> bool {
    matches!(self, Vendor::Fuji)
  }

  /// `true` if this is [`Vendor::Leica`].
  #[must_use]
  #[inline(always)]
  pub const fn is_leica(self) -> bool {
    matches!(self, Vendor::Leica)
  }

  /// `true` if this is [`Vendor::Samsung`].
  #[must_use]
  #[inline(always)]
  pub const fn is_samsung(self) -> bool {
    matches!(self, Vendor::Samsung)
  }

  /// `true` if this is [`Vendor::Minolta`].
  #[must_use]
  #[inline(always)]
  pub const fn is_minolta(self) -> bool {
    matches!(self, Vendor::Minolta)
  }

  /// `true` if this is [`Vendor::Kodak`].
  #[must_use]
  #[inline(always)]
  pub const fn is_kodak(self) -> bool {
    matches!(self, Vendor::Kodak)
  }

  /// `true` if this is [`Vendor::Ricoh`].
  #[must_use]
  #[inline(always)]
  pub const fn is_ricoh(self) -> bool {
    matches!(self, Vendor::Ricoh)
  }

  /// `true` if this is [`Vendor::Sanyo`].
  #[must_use]
  #[inline(always)]
  pub const fn is_sanyo(self) -> bool {
    matches!(self, Vendor::Sanyo)
  }

  /// `true` if this is [`Vendor::Sigma`].
  #[must_use]
  #[inline(always)]
  pub const fn is_sigma(self) -> bool {
    matches!(self, Vendor::Sigma)
  }

  /// `true` if this is [`Vendor::Casio`].
  #[must_use]
  #[inline(always)]
  pub const fn is_casio(self) -> bool {
    matches!(self, Vendor::Casio)
  }

  /// `true` if this is [`Vendor::Kyocera`].
  #[must_use]
  #[inline(always)]
  pub const fn is_kyocera(self) -> bool {
    matches!(self, Vendor::Kyocera)
  }

  /// `true` if this is [`Vendor::Unknown`] (no signature/make matched).
  #[must_use]
  #[inline(always)]
  pub const fn is_unknown(self) -> bool {
    matches!(self, Vendor::Unknown)
  }
}
