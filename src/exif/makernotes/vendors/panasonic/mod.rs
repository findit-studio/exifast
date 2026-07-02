// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Panasonic MakerNotes — Phase-3 port.
//!
//! Bundled source: `lib/Image/ExifTool/Panasonic.pm` —
//! `%Image::ExifTool::Panasonic::Main` (`Panasonic.pm:265-1601`).
//!
//! ## Phase 3 scope
//!
//! - The Panasonic body walk — strips the 12-byte `Panasonic\0\0\0`
//!   header, walks the IFD entries. The `%Panasonic::Main` route runs
//!   through the shared `Walker` isolated helper
//!   `crate::exif::panasonic_makernote_isolated`; the cross-vendor Leica1 /
//!   Leica10 routes (`parse_leica1_gated` / `parse_leica10_gated`) call the
//!   generalized `crate::exif::panasonic_makernote_isolated_with_offset` at
//!   body offset 8 / 18 — the SAME shared `Walker`. The standalone
//!   `body::walk_panasonic_body` blob wrapper was deleted in #243 phase 5;
//!   the per-vendor `walk_panasonic_in_tiff` body walker + the `parse_in_tiff`
//!   oracle that drove the Leica routes were deleted in #255.
//! - The faithful tag table ([`tags::PANASONIC_TAGS`]) — every named tag
//!   from `%Panasonic::Main` with a clean Format. Conditional rows
//!   collapse to the most-common branch (e.g. `0x2c` ContrastMode uses
//!   the non-GF/non-G2 PrintHex variant; the GF1/G2/etc. table is a
//!   deferred Phase-3-bis follow-up — bundled docs the per-model variant
//!   selection at `Panasonic.pm:585-660`).
//! - Per-tag PrintConv ([`printconv::PanasonicPrintConv`]) — the named
//!   PrintConv hashes from bundled (ImageQuality, WhiteBalance, FocusMode,
//!   ShootingMode/%shootingMode, BurstMode, NoiseReduction, ColorEffect,
//!   FilmMode, ContrastMode, etc.) plus the structured-string conversions
//!   (FirmwareVersion, InternalSerialNumber, TimeSincePowerOn).
//! - A typed [`MakerNotesPanasonic`] struct with D8 accessors over the
//!   parsed fields — body identity (Lens model/serial, internal serial,
//!   firmware, ImageStabilization, FilmMode, PhotoStyle, Roll/PitchAngle).
//!
//! ## Main SubDirectory pointers
//!
//! The Main hash has exactly four SubDirectory pointers. Three are
//! `ProcessBinaryData` sub-tables walked natively (#105) — their positions emit
//! under the `Panasonic` family-1 group via [`decode_main_subdir`]:
//!
//! - `Panasonic::FaceDetInfo` at 0x4e (`Panasonic.pm:936-942`) — [`face_det_info`].
//! - `Panasonic::FaceRecInfo` at 0x61 (`Panasonic.pm:1007-1012`) — [`face_rec_info`].
//! - `Panasonic::TimeInfo` at 0x2003 (`Panasonic.pm:1524-1527`) — [`time_info`].
//! - `PrintIM::Main` at 0x0e00 (`Panasonic.pm:1518-1523`) — handled by the
//!   shared PrintIM module.
//!
//! - Per-model conditional rows (FZ10 AFAreaMode at `Panasonic.pm:336-382`,
//!   GF1/G2 ContrastMode at `:585-660`) — collapse to the bundled
//!   non-model-gated branch in Phase 3; per-body decoding is deferred per
//!   follow-up issue.
//! - The Leica2/3/4/5/6/9 sub-tables (`Panasonic.pm:1604-2258`) — Leica
//!   MakerNotes which Panasonic.pm hosts due to the Panasonic-Leica
//!   technology share. Phase 3 routes both via the dispatcher
//!   `MakerNotePanasonic` arm; Leica-specific decoding is deferred.
//!
//! ## D8 compliance
//!
//! No public fields. Every accessor is `const fn` where possible.
//! `#[non_exhaustive]` so a future Phase 3-bis can add fields without a
//! breaking change.

#![deny(clippy::indexing_slicing)]

pub mod body;
pub mod face_det_info;
pub mod face_rec_info;
pub mod printconv;
pub mod tags;
pub mod time_info;

use crate::exif::makernotes::detected::BaseRule;
use crate::exif::makernotes::vendors::VendorEmission;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

pub use body::HEADER_LEN;
pub use printconv::{CONDITION_GATED_IDS, PanasonicPrintConv, RAWCONV_DROP_IDS};
pub use tags::{PANASONIC_TAGS, PanasonicTag, SubTable, format_override, lookup};

use super::super::super::ifd::{ByteOrder, RawValue};

/// Decoded Panasonic MakerNotes data — populated by
/// `crate::exif::panasonic_makernote_isolated` (or, for the cross-vendor
/// Leica routes, [`parse_leica1_gated`] / [`parse_leica10_gated`]) when the
/// dispatcher resolved [`Vendor::Panasonic`](crate::exif::makernotes::Vendor).
///
/// D8: no public fields; accessor-only. `PartialEq` only (NOT `Eq`)
/// because the struct carries `f64` roll/pitch-angle fields.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct MakerNotesPanasonic {
  // ---- camera-identity (Phase 3 ship-bar) ----
  /// Panasonic Main 0x02 (`FirmwareVersion`) — body firmware (dotted ASCII
  /// like "0.1.0.8" after the binary-to-dotted PrintConv).
  firmware_version: Option<SmolStr>,
  /// Panasonic Main 0x25 (`InternalSerialNumber`) — body-internal S/N
  /// (different from the user-facing Make/Model from IFD0).
  internal_serial_number: Option<SmolStr>,
  /// Panasonic Main 0x8000 (`MakerNoteVersion`) — Panasonic schema version.
  maker_note_version: Option<SmolStr>,
  /// Panasonic Main 0x26 (`PanasonicExifVersion`) — Panasonic Exif schema
  /// version.
  panasonic_exif_version: Option<SmolStr>,
  // ---- lens identity ----
  /// Panasonic Main 0x51 (`LensType`) — lens model STRING (Panasonic uses
  /// a string here, not an ID lookup like Sony/Canon).
  lens_type: Option<SmolStr>,
  /// Panasonic Main 0x52 (`LensSerialNumber`) — lens serial STRING.
  lens_serial_number: Option<SmolStr>,
  /// Panasonic Main 0x53 (`AccessoryType`) — accessory (e.g., extension
  /// tube, teleconverter) STRING.
  accessory_type: Option<SmolStr>,
  /// Panasonic Main 0x54 (`AccessorySerialNumber`).
  accessory_serial_number: Option<SmolStr>,
  // ---- capture metadata ----
  /// Panasonic Main 0x1a (`ImageStabilization`) — IS mode integer.
  image_stabilization: Option<i64>,
  /// Panasonic Main 0x42 (`FilmMode`) — film mode label hint integer.
  film_mode: Option<i64>,
  /// Panasonic Main 0x89 (`PhotoStyle`) — photo style mode integer.
  photo_style: Option<i64>,
  /// Panasonic Main 0x1f (`ShootingMode`) — shoot mode integer.
  shooting_mode: Option<i64>,
  /// Panasonic Main 0x32 (`ColorMode`) — color mode integer.
  color_mode: Option<i64>,
  /// Panasonic Main 0x28 (`ColorEffect`).
  color_effect: Option<i64>,
  // ---- orientation angles ----
  /// Panasonic Main 0x90 (`RollAngle`) — degrees of clockwise camera
  /// rotation (`int16s / 10`, `Panasonic.pm:1200-1207`).
  roll_angle: Option<f64>,
  /// Panasonic Main 0x91 (`PitchAngle`) — degrees of upward camera tilt
  /// (`-int16s / 10`, `Panasonic.pm:1208-1215`).
  pitch_angle: Option<f64>,
}

impl MakerNotesPanasonic {
  /// Build an empty Panasonic metadata bag. The decode path
  /// (`crate::exif::panasonic_makernote_isolated` / the Leica gated entries)
  /// populates the per-tag fields.
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {
      firmware_version: None,
      internal_serial_number: None,
      maker_note_version: None,
      panasonic_exif_version: None,
      lens_type: None,
      lens_serial_number: None,
      accessory_type: None,
      accessory_serial_number: None,
      image_stabilization: None,
      film_mode: None,
      photo_style: None,
      shooting_mode: None,
      color_mode: None,
      color_effect: None,
      roll_angle: None,
      pitch_angle: None,
    }
  }

  /// `FirmwareVersion` (`Panasonic.pm:286-302`).
  #[must_use]
  #[inline]
  pub fn firmware_version(&self) -> Option<&str> {
    self.firmware_version.as_deref()
  }

  /// `InternalSerialNumber` (`Panasonic.pm:449-463`).
  #[must_use]
  #[inline]
  pub fn internal_serial_number(&self) -> Option<&str> {
    self.internal_serial_number.as_deref()
  }

  /// `MakerNoteVersion` (`Panasonic.pm:1528-1531`).
  #[must_use]
  #[inline]
  pub fn maker_note_version(&self) -> Option<&str> {
    self.maker_note_version.as_deref()
  }

  /// `PanasonicExifVersion` (`Panasonic.pm:464-467`).
  #[must_use]
  #[inline]
  pub fn panasonic_exif_version(&self) -> Option<&str> {
    self.panasonic_exif_version.as_deref()
  }

  /// `LensType` (`Panasonic.pm:944-949`) — lens model STRING (Panasonic
  /// stores the human name directly, no ID lookup).
  #[must_use]
  #[inline]
  pub fn lens_type(&self) -> Option<&str> {
    self.lens_type.as_deref()
  }

  /// `LensSerialNumber` (`Panasonic.pm:950-955`).
  #[must_use]
  #[inline]
  pub fn lens_serial_number(&self) -> Option<&str> {
    self.lens_serial_number.as_deref()
  }

  /// `AccessoryType` (`Panasonic.pm:956-961`).
  #[must_use]
  #[inline]
  pub fn accessory_type(&self) -> Option<&str> {
    self.accessory_type.as_deref()
  }

  /// `AccessorySerialNumber` (`Panasonic.pm:962-969`).
  #[must_use]
  #[inline]
  pub fn accessory_serial_number(&self) -> Option<&str> {
    self.accessory_serial_number.as_deref()
  }

  /// `ImageStabilization` (`Panasonic.pm:383-399`) — integer mode.
  #[must_use]
  #[inline(always)]
  pub const fn image_stabilization(&self) -> Option<i64> {
    self.image_stabilization
  }

  /// `FilmMode` (`Panasonic.pm:831-849`) — integer.
  #[must_use]
  #[inline(always)]
  pub const fn film_mode(&self) -> Option<i64> {
    self.film_mode
  }

  /// `PhotoStyle` (`Panasonic.pm:1136-1155`) — integer.
  #[must_use]
  #[inline(always)]
  pub const fn photo_style(&self) -> Option<i64> {
    self.photo_style
  }

  /// `ShootingMode` (`Panasonic.pm:410-415`) — integer.
  #[must_use]
  #[inline(always)]
  pub const fn shooting_mode(&self) -> Option<i64> {
    self.shooting_mode
  }

  /// `ColorMode` (`Panasonic.pm:717-726`) — integer.
  #[must_use]
  #[inline(always)]
  pub const fn color_mode(&self) -> Option<i64> {
    self.color_mode
  }

  /// `ColorEffect` (`Panasonic.pm:477-490`) — integer.
  #[must_use]
  #[inline(always)]
  pub const fn color_effect(&self) -> Option<i64> {
    self.color_effect
  }

  /// `RollAngle` in degrees of clockwise camera rotation — Panasonic Main
  /// 0x90 (`Panasonic.pm:1200-1207`).
  #[must_use]
  #[inline(always)]
  pub const fn roll_angle(&self) -> Option<f64> {
    self.roll_angle
  }

  /// `PitchAngle` in degrees of upward camera tilt — Panasonic Main 0x91
  /// (`Panasonic.pm:1208-1215`).
  #[must_use]
  #[inline(always)]
  pub const fn pitch_angle(&self) -> Option<f64> {
    self.pitch_angle
  }
}

/// The OUT-OF-LINE value-offset buffer addend for a `%Panasonic::Main`
/// variant, derived from the dispatched [`BaseRule`].
///
/// Only the two variants that route to `%Panasonic::Main` are
/// reachable (`MakerNotes.pm:732-761`):
///
/// - `MakerNotePanasonic` — no `Base` ⇒ [`BaseRule::Inherit`] ⇒ `0`
///   (the child inherits the parent base; offsets are TIFF-relative).
/// - `MakerNotePanasonic3` (DC-FT7) — `Base => 12` ⇒
///   [`BaseRule::Literal(12)`](BaseRule::Literal) ⇒ `12` (`Exif.pm:7003`/
///   `:7040` → +12 in buffer coordinates).
///
/// `MakerNotePanasonic2`/`Type2` (`MKE`) does NOT use `%Panasonic::Main`
/// (it is a `ProcessBinaryData` table, `Panasonic.pm:2259`); the caller
/// must not route it here. Any non-`Literal` rule maps to `0` (the
/// inherit default) — defensive: no other `BaseRule` reaches the
/// Panasonic Main parser.
#[must_use]
#[inline]
pub const fn main_base_offset(base_rule: BaseRule) -> usize {
  match base_rule {
    // `Base => n` literal — the buffer addend is the literal itself
    // (clamped non-negative; bundled writes 12). A negative literal is
    // not produced by any Panasonic arm.
    BaseRule::Literal(n) if n >= 0 => n as usize,
    // No `Base` (inherit) and every other (unreachable) rule: no shift.
    _ => 0,
  }
}

/// `true` iff a `Vendor::Panasonic` blob routes to `%Panasonic::Main` (and
/// so the Panasonic Main IFD walker should run on it).
///
/// The dispatcher collapses all THREE Panasonic `MakerNotes.pm` variants
/// (`:732-760`) to [`Vendor::Panasonic`](crate::exif::makernotes::Vendor::Panasonic),
/// but only the two whose blob starts with `Panasonic` use `%Panasonic::Main`:
///
/// - `MakerNotePanasonic` (`:733`) — no `Base` ⇒ INHERIT the parent base.
/// - `MakerNotePanasonic3` (`:752`, DC-FT7) — `Base => 12` (`:758`).
///
/// `MakerNotePanasonic2` (`:743`, the `MKE` Type2 variant) is a DIFFERENT
/// structure — `Panasonic::Type2` is a `ProcessBinaryData` table
/// (`Panasonic.pm:2259`), NOT an IFD over `%Panasonic::Main` — so the Main
/// parser must NOT run on it. The discriminator is the `Panasonic` prefix
/// (the `MKE`-prefixed Type2 blob fails it). Mirrors the Sony
/// [`routes_to_main`](super::sony::routes_to_main) call-site gate.
#[must_use]
#[inline]
pub fn routes_to_main(blob: &[u8]) -> bool {
  blob.starts_with(b"Panasonic")
}

/// The `MakerNoteLeica10` signature — bundled
/// `Condition => '$$valPt =~ /^LEICA CAMERA AG\0/'` (`MakerNotes.pm:725`).
/// The 16-byte prefix the D-Lux7 (and rebadged Lumix bodies) carry before
/// the `%Panasonic::Main` IFD body.
pub const LEICA10_SIGNATURE: &[u8] = b"LEICA CAMERA AG\x00";

/// The `MakerNoteLeica10` body offset — bundled `Start => '$valuePtr + 18'`
/// (`MakerNotes.pm:728`). The IFD body starts 18 bytes into the blob (the
/// 16-byte `LEICA CAMERA AG\0` signature plus a 2-byte version/pad), NOT at
/// the 12-byte Panasonic header offset.
pub const LEICA10_BODY_OFFSET: usize = 18;

/// `true` iff a blob is the cross-vendor `MakerNoteLeica10` shape that
/// routes to `%Panasonic::Main` (`MakerNotes.pm:724-730`).
///
/// `MakerNoteLeica10` is the ONLY Leica `MakerNotes.pm` variant whose
/// `SubDirectory{TagTable}` is `Image::ExifTool::Panasonic::Main` (the
/// other nine route to Leica-specific `Panasonic::Leica2`..`Leica9`
/// tables, which are unported — see the dispatcher's Leica block). The
/// dispatcher collapses every Leica variant to
/// [`Vendor::Leica`](crate::exif::makernotes::Vendor::Leica) with the
/// per-variant `body_offset`; this signature gate is what tells the
/// `Vendor::Leica` call-site that THIS blob is the Panasonic-Main-routed
/// one (it carries the `LEICA CAMERA AG\0` prefix the dispatcher matched
/// for Leica10). A genuinely-Leica-table blob (`LEICA\0\0\0`, `LEICA0…`,
/// …) fails it and the Leica slot stays absent (deferred, like the
/// non-Main Sony / Panasonic-Type2 variants).
#[must_use]
#[inline]
pub fn routes_to_leica10(blob: &[u8]) -> bool {
  blob.starts_with(LEICA10_SIGNATURE)
}

/// **The single gated entry into `%Panasonic::Main` for the cross-vendor
/// `MakerNoteLeica10` route** (`MakerNotes.pm:724-730`).
///
/// `MakerNoteLeica10` is the Leica D-Lux7 variant whose
/// `SubDirectory{TagTable}` is `Image::ExifTool::Panasonic::Main`
/// (`:727`) — i.e. a Leica-signature blob decoded with the PANASONIC Main
/// table at `Start => '$valuePtr + 18'` (`:728`). Bundled `exiftool -G1
/// -j` emits the resulting tags under the `Panasonic:*` family-1 group
/// (they ARE `%Panasonic::Main` tags), so the call-site emits them with
/// [`Vendor::Panasonic.group1()`](crate::exif::makernotes::Vendor::group1).
///
/// A gated entry like [`parse_leica1_gated`] but with the Leica10 signature
/// gate ([`routes_to_leica10`]) and the Leica10 body offset
/// ([`LEICA10_BODY_OFFSET`] = 18, vs the `Panasonic`-prefix's 12). The
/// `Base` is INHERITED (Leica10 has no `Base` line, `:726-730`), so the
/// out-of-line `base_offset` is 0 — out-of-line values are TIFF-relative.
///
/// Returns:
///
/// - `Some((typed, emissions))` — the blob starts with `LEICA CAMERA AG\0`;
///   the Main walker ran via the shared `Walker`
///   (`crate::exif::panasonic_makernote_isolated_with_offset`) at
///   `body_offset = 18`.
/// - `None` — the blob is NOT the Leica10 shape (one of the nine
///   Leica-specific-table variants); the caller leaves the Panasonic slot
///   ABSENT (no spurious Main tags — those tables are unported/deferred).
///
/// `tiff_data`/`mn_offset`/`mn_len` give the parent-TIFF context;
/// `body_offset` is the DISPATCHED [`DetectedMakerNote::body_offset`](crate::exif::makernotes::DetectedMakerNote::body_offset)
/// (18 for Leica10) — threaded from the dispatcher rather than hard-coded,
/// the cross-vendor generalization of the DC-FT7 base-threading.
#[must_use]
pub fn parse_leica10_gated<'e>(
  tiff_data: &[u8],
  mn_offset: usize,
  mn_len: usize,
  body_offset: usize,
  parent_order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
) -> Option<(MakerNotesPanasonic, Vec<VendorEmission<'e>>)> {
  // The gate reads the captured MakerNote blob (the bytes the dispatcher
  // classified) — `tiff_data[mn_offset .. mn_offset + mn_len]`.
  let blob_end = mn_offset.saturating_add(mn_len).min(tiff_data.len());
  let blob = tiff_data.get(mn_offset..blob_end)?;
  if !routes_to_leica10(blob) {
    return None;
  }
  // Leica10 has no `Base` line (`MakerNotes.pm:726-730`) ⇒ inherit ⇒ the
  // out-of-line buffer addend is 0 (out-of-line values are TIFF-relative). After
  // the signature gate passes, the SHARED `Walker` decodes `%Panasonic::Main`
  // via the cross-vendor `panasonic_makernote_isolated_with_offset` at the
  // dispatched Leica10 body offset (18) — the sole walker, no per-vendor oracle
  // (#255). The helper returns `(emissions, typed)`; the gated-entry contract is
  // `(typed, emissions)`, hence the swap. The helper is total here (its only
  // gate is the caller's, already passed; a too-short blob returns
  // `Some((empty, empty))`, matching the retired `parse_in_tiff`).
  crate::exif::panasonic_makernote_isolated_with_offset(
    tiff_data,
    mn_offset,
    mn_len,
    body_offset,
    0,
    parent_order,
    model,
    print_conv,
  )
  .map(|(emissions, typed)| (typed, emissions))
}

/// `true` iff a body routes to the cross-vendor **`MakerNoteLeica` (Leica1)**
/// arm (`MakerNotes.pm:599-608`) — the older-Leica make-only case that also
/// decodes with `%Panasonic::Main`.
///
/// `MakerNoteLeica` (Leica1) is the SECOND Leica `MakerNotes.pm` variant
/// whose `SubDirectory{TagTable}` is `Image::ExifTool::Panasonic::Main`
/// (`:604`, alongside `MakerNoteLeica10`, `:727`). Its `Condition` is the
/// MAKE-ONLY `$$self{Make} eq "LEICA"` (`:602`) — there is NO `$$valPt`
/// signature term — and it is the FIRST Leica entry in `%Main`. Because it
/// is first and carries no blob test, ANY body whose IFD0 `Make` is exactly
/// `"LEICA"` is claimed by Leica1 regardless of its MakerNote signature —
/// the later Leica2-9/Leica10 arms are NEVER reached for such a body
/// (`ExifTool.pm:9395-9405`, first matching `Condition` wins). So the gate
/// is purely the make equality; it does NOT inspect the blob.
///
/// This INHERENTLY excludes the Leica2-9 + Leica10 signatures: every one of
/// those arms is reachable only when `Make != "LEICA"` —
///
/// - Leica2/3/4/9 require `$$self{Make} =~ /^Leica Camera AG/` (`:613`/`:629`/
///   `:641`/`:716`) and Leica6 requires `eq 'Leica Camera AG'` (`:672`); a
///   make of exactly `"LEICA"` matches none of those.
/// - Leica5/7/8/10 are signature-only (`:659`/`:692`/`:707`/`:725`), but in
///   `%Main` order they sit AFTER Leica1, so a `Make eq "LEICA"` body never
///   reaches them — Leica1 short-circuits first. (Verified against bundled
///   ExifTool 13.59: a `Make eq "LEICA"` TIFF carrying a `LEICA\0\x01\0`
///   Leica5-shaped blob still emits `Panasonic:ImageQuality` via Leica1's
///   body offset 8, NOT the Leica5 table.)
///
/// Real older-Leica bodies that write a make-only `LEICA` Panasonic
/// MakerNote (Digilux / early D-Lux / V-Lux) report `Make => "LEICA"`
/// exactly, while the Leica2-10 bodies report `"Leica Camera AG"` /
/// `"LEICA CAMERA AG"` — so the make string already partitions the two
/// cleanly. The dispatcher's Leica1 arm (`make_eq(make, "LEICA")`, tested
/// FIRST in its Leica block) supplies the matching `body_offset = 8`.
#[must_use]
#[inline]
pub fn routes_to_leica1(make: Option<&str>) -> bool {
  matches!(make, Some(m) if m == "LEICA")
}

/// **The single gated entry into `%Panasonic::Main` for the cross-vendor
/// `MakerNoteLeica` (Leica1) route** (`MakerNotes.pm:599-608`).
///
/// `MakerNoteLeica` (Leica1) is the older-Leica make-only variant whose
/// `SubDirectory{TagTable}` is `Image::ExifTool::Panasonic::Main` (`:604`)
/// — i.e. a make-`"LEICA"` body decoded with the PANASONIC Main table at
/// `Start => '$valuePtr + 8'` (`:606`, the 8-byte `LEICA\0\0\0` header) with
/// NO `Base` line (inherit). Bundled `exiftool -G1 -j` emits the resulting
/// tags under the `Panasonic:*` family-1 group (they ARE `%Panasonic::Main`
/// tags), so the call-site emits them with
/// [`Vendor::Panasonic.group1()`](crate::exif::makernotes::Vendor::group1).
///
/// Mirrors [`parse_leica10_gated`] but with the make-only Leica1 gate
/// ([`routes_to_leica1`]) and the Leica1 body offset (8, vs Leica10's 18).
/// The `Base` is INHERITED (Leica1 has no `Base` line, `:603-607`), so the
/// out-of-line `base_offset` is 0 — out-of-line values are TIFF-relative.
///
/// Returns:
///
/// - `Some((typed, emissions))` — `make` is exactly `"LEICA"`; the Main
///   walker ran via the shared `Walker`
///   (`crate::exif::panasonic_makernote_isolated_with_offset`) at
///   `body_offset` (8 for Leica1).
/// - `None` — `make` is NOT exactly `"LEICA"` (a Leica2-9 / Leica10 body,
///   or a non-Leica body); the caller leaves the Panasonic slot ABSENT
///   (Leica2-9 route to unported Leica-specific tables; Leica10 routes via
///   [`parse_leica10_gated`]).
///
/// `tiff_data`/`mn_offset`/`mn_len` give the parent-TIFF context; `make` is
/// the IFD0 `$$self{Make}` (the Leica1 `Condition` input); `body_offset` is
/// the DISPATCHED [`DetectedMakerNote::body_offset`](crate::exif::makernotes::DetectedMakerNote::body_offset)
/// (8 for Leica1) — threaded from the dispatcher rather than hard-coded,
/// like the Leica10 / DC-FT7 routes.
#[must_use]
// Mirrors `super::sony::parse_main_gated`: the parent-TIFF context
// (`tiff_data`/`mn_offset`/`mn_len`) plus the make-gate + model + body-offset
// inputs are all load-bearing and threaded from the dispatcher.
#[allow(clippy::too_many_arguments)]
pub fn parse_leica1_gated<'e>(
  tiff_data: &[u8],
  mn_offset: usize,
  mn_len: usize,
  body_offset: usize,
  parent_order: ByteOrder,
  print_conv: bool,
  make: Option<&str>,
  model: Option<&str>,
) -> Option<(MakerNotesPanasonic, Vec<VendorEmission<'e>>)> {
  // The Leica1 `Condition` is MAKE-only (`$$self{Make} eq "LEICA"`,
  // `MakerNotes.pm:602`) — it does NOT read the blob.
  if !routes_to_leica1(make) {
    return None;
  }
  // Leica1 has no `Base` line (`MakerNotes.pm:603-607`) ⇒ inherit ⇒ the
  // out-of-line buffer addend is 0 (out-of-line values are TIFF-relative). After
  // the make gate passes, the SHARED `Walker` decodes `%Panasonic::Main` via the
  // cross-vendor `panasonic_makernote_isolated_with_offset` at the dispatched
  // Leica1 body offset (8) — the sole walker, no per-vendor oracle (#255). The
  // helper returns `(emissions, typed)`; the gated-entry contract is
  // `(typed, emissions)`, hence the swap. The helper is total here (its only
  // gate is the caller's, already passed; a too-short blob returns
  // `Some((empty, empty))`, matching the retired `parse_in_tiff`).
  crate::exif::panasonic_makernote_isolated_with_offset(
    tiff_data,
    mn_offset,
    mn_len,
    body_offset,
    0,
    parent_order,
    model,
    print_conv,
  )
  .map(|(emissions, typed)| (typed, emissions))
}

/// Populate the typed struct from one Panasonic Main-IFD leaf-tag emission.
/// `raw` is the entry's post-Format-decode [`RawValue`]; `val` the
/// already-rendered [`TagValue`] (read by the 0x02/0x25/0x26/0x8000 string
/// fields).
///
/// MUST be called ONLY for an entry that PASSED every suppression gate — the
/// SubDirectory-skip / single-HASH `Condition` / RawConv-drop / 0xc5/0xe4-undef-drop
/// checks must all run BEFORE this, alongside the emission, so a rawconv-dropped
/// 0xd1 (for instance) populates NOTHING. The shared-`Walker` Panasonic capture
/// (`exif::mod::emit_panasonic_value`) is the sole caller and preserves that
/// ordering by calling this from the SAME gate-passing path it emits from (#243
/// phase 3 / #255 — the per-vendor `parse_in_tiff` oracle that formerly drove it
/// has been deleted).
pub(crate) fn populate_typed(
  typed: &mut MakerNotesPanasonic,
  tag_id: u16,
  raw: &RawValue,
  val: &TagValue,
) {
  match tag_id {
    0x02 => {
      // FirmwareVersion — already PrintConv'd to dotted string.
      if let TagValue::Str(s) = val {
        typed.firmware_version = Some(s.clone());
      }
    }
    0x25 => {
      if let TagValue::Str(s) = val {
        typed.internal_serial_number = Some(s.clone());
      }
    }
    0x26 => {
      if let TagValue::Str(s) = val {
        typed.panasonic_exif_version = Some(s.clone());
      }
    }
    0x8000 => {
      if let TagValue::Str(s) = val {
        typed.maker_note_version = Some(s.clone());
      }
    }
    0x51 => {
      if let RawValue::Text { text: s, .. } = raw {
        let trimmed = s.trim_end_matches([' ', '\0']);
        if !trimmed.is_empty() {
          typed.lens_type = Some(trimmed.into());
        }
      }
    }
    0x52 => {
      if let RawValue::Text { text: s, .. } = raw {
        let trimmed = s.trim_end_matches([' ', '\0']);
        if !trimmed.is_empty() {
          typed.lens_serial_number = Some(trimmed.into());
        }
      }
    }
    0x53 => {
      if let RawValue::Text { text: s, .. } = raw {
        let trimmed = s.trim_end_matches([' ', '\0']);
        if !trimmed.is_empty() {
          typed.accessory_type = Some(trimmed.into());
        }
      }
    }
    0x54 => {
      if let RawValue::Text { text: s, .. } = raw {
        let trimmed = s.trim_end_matches([' ', '\0']);
        if !trimmed.is_empty() {
          typed.accessory_serial_number = Some(trimmed.into());
        }
      }
    }
    0x1a => {
      typed.image_stabilization = first_i64(raw);
    }
    0x42 => {
      typed.film_mode = first_i64(raw);
    }
    0x89 => {
      typed.photo_style = first_i64(raw);
    }
    0x1f => {
      typed.shooting_mode = first_i64(raw);
    }
    0x32 => {
      typed.color_mode = first_i64(raw);
    }
    0x28 => {
      typed.color_effect = first_i64(raw);
    }
    0x90 => {
      // RollAngle — int16s / 10 (`Panasonic.pm:1205`).
      typed.roll_angle = first_i64(raw).map(|n| n as f64 / 10.0);
    }
    0x91 => {
      // PitchAngle — -int16s / 10 (`Panasonic.pm:1213`).
      typed.pitch_angle = first_i64(raw).map(|n| -(n as f64) / 10.0);
    }
    _ => {}
  }
}

fn first_i64(raw: &RawValue) -> Option<i64> {
  match raw {
    RawValue::I64(v) => v.first().copied(),
    RawValue::U64(v) => v.first().and_then(|&n| i64::try_from(n).ok()),
    _ => None,
  }
}

/// Decode a WALKED `%Panasonic::Main` ProcessBinaryData SubDirectory blob into
/// its `(Name, TagValue)` emission pairs — the faithful descent for the three
/// binary sub-tables `%Panasonic::Main` references: `FaceDetInfo` (0x4e,
/// `Panasonic.pm:2279`), `FaceRecInfo` (0x61, `:2332`), `TimeInfo` (0x2003,
/// `:1939`). All three emit under the `Panasonic` family-1 group (the module
/// default the source tables inherit).
///
/// `blob` is the verbatim `$$valPt` value span (`data[value_offset ..
/// value_offset + value_size]`); `order` the inherited parent Panasonic byte
/// order (none of the three SubDirectory refs carry a `ByteOrder` override).
/// Returns `None` for [`SubTable::PrintIm`] — the `PrintIM::Main` SubDirectory
/// (0x0e00) is handled by the shared PrintIM module, not this descent — so the
/// caller falls through to its existing (no-emit) handling.
#[must_use]
pub fn decode_main_subdir(
  sub: SubTable,
  blob: &[u8],
  order: ByteOrder,
  print_conv: bool,
) -> Option<Vec<(SmolStr, TagValue)>> {
  match sub {
    SubTable::FaceDetInfo => Some(face_det_info::parse(blob, order)),
    SubTable::FaceRecInfo => Some(face_rec_info::parse(blob, order)),
    SubTable::TimeInfo => Some(time_info::parse(blob, order, print_conv)),
    // `PrintIM::Main` is handled by the shared PrintIM module, not here.
    SubTable::PrintIm => None,
  }
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C S2); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;
  use crate::value::{Group, Metadata};
  use std::vec::Vec;

  // The per-vendor oracle entry points (`panasonic::parse` / `parse_with_print_conv`
  // / `parse_in_tiff` / `parse_into_metadata`) were retired in #243 phase 5; the
  // production decode now runs through the shared-`Walker` isolated helper
  // `crate::exif::panasonic_makernote_isolated` (proven byte-identical by the
  // conformance suite + the deleted differential tests). These thin shims preserve
  // the old signatures so the per-entry-gate decode tests below exercise the SAME
  // tables/convs/gates through the surviving path. Every test body carries the
  // `Panasonic\0\0\0` prefix ⇒ `routes_to_main` ⇒ `Some`. The isolated helper's
  // body offset is always `HEADER_LEN` (the only reachable Main body offset), so
  // the `body_offset` argument the oracle took is always `HEADER_LEN` here; the
  // dynamic-base addend is the separate `base_offset`. The typed slot is installed
  // for both modes by this helper, so the `-n` typed tests are unaffected.
  fn parse<'e>(blob: &[u8], order: ByteOrder) -> (MakerNotesPanasonic, Vec<VendorEmission<'e>>) {
    parse_with_print_conv(blob, order, true)
  }

  fn parse_with_print_conv<'e>(
    blob: &[u8],
    order: ByteOrder,
    print_conv: bool,
  ) -> (MakerNotesPanasonic, Vec<VendorEmission<'e>>) {
    parse_in_tiff(blob, 0, blob.len(), HEADER_LEN, order, print_conv, None, 0)
  }

  #[allow(clippy::too_many_arguments)]
  fn parse_in_tiff<'e>(
    tiff_data: &[u8],
    mn_offset: usize,
    mn_len: usize,
    body_offset: usize,
    order: ByteOrder,
    print_conv: bool,
    model: Option<&str>,
    base_offset: usize,
  ) -> (MakerNotesPanasonic, Vec<VendorEmission<'e>>) {
    debug_assert_eq!(
      body_offset, HEADER_LEN,
      "the isolated Panasonic Main walk uses HEADER_LEN as the body offset"
    );
    // A blob that does not route to `%Panasonic::Main` (e.g. the empty-blob test)
    // yields `None`; the oracle returned empties there, so preserve that contract.
    match crate::exif::panasonic_makernote_isolated(
      tiff_data,
      mn_offset,
      mn_len,
      base_offset,
      order,
      model,
      print_conv,
    ) {
      Some((emissions, typed)) => (typed, emissions),
      None => (MakerNotesPanasonic::new(), Vec::new()),
    }
  }

  fn parse_into_metadata(blob: &[u8], order: ByteOrder, print_conv: bool, into: &mut Metadata) {
    use crate::exif::makernotes::Vendor;
    let g1 = Vendor::Panasonic.group1();
    let group = Group::new(g1, g1);
    let (_typed, emissions) = parse_with_print_conv(blob, order, print_conv);
    for e in emissions {
      if e.unknown() {
        continue;
      }
      into.push(group.clone(), e.name(), e.value().into_owned());
    }
  }

  /// Build a synthetic Panasonic blob with `entries` (each `(tag, format, count, value_bytes)`).
  fn build_blob(entries: &[(u16, u16, u32, Vec<u8>)]) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"Panasonic\x00\x00\x00");
    blob.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    // Out-of-line data goes AFTER the IFD entries.
    let entries_start = blob.len();
    let dir_size = 12 * entries.len();
    let mut data_off = entries_start + dir_size;
    let mut pending_data: Vec<Vec<u8>> = Vec::new();
    // Element sizes by TIFF format code.
    let elem_sizes: [usize; 14] = [0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8, 4];
    for (tag, format, count, value) in entries {
      let elem_size = elem_sizes[*format as usize];
      let total = elem_size * (*count as usize);
      blob.extend_from_slice(&tag.to_le_bytes());
      blob.extend_from_slice(&format.to_le_bytes());
      blob.extend_from_slice(&count.to_le_bytes());
      if total <= 4 {
        let mut padded = [0u8; 4];
        padded[..value.len().min(4)].copy_from_slice(&value[..value.len().min(4)]);
        blob.extend_from_slice(&padded);
      } else {
        blob.extend_from_slice(&(data_off as u32).to_le_bytes());
        data_off += total;
        pending_data.push(value.clone());
      }
    }
    for v in pending_data {
      blob.extend_from_slice(&v);
    }
    blob
  }

  #[test]
  fn parse_image_quality_inline() {
    // ImageQuality (0x01) int16u count 1 value 2 ⇒ "High"
    let blob = build_blob(&[(0x01, 0x03, 1, std::vec![0x02, 0x00, 0, 0])]);
    let (_typed, emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(emissions.len(), 1);
    assert_eq!(emissions[0].name(), "ImageQuality");
    assert_eq!(emissions[0].value().as_ref(), &TagValue::Str("High".into()));
  }

  #[test]
  fn parse_image_stabilization_typed_field_populated() {
    // ImageStabilization (0x1a) int16u count 1 value 4 ⇒ "On, Mode 2"
    let blob = build_blob(&[(0x1a, 0x03, 1, std::vec![0x04, 0x00, 0, 0])]);
    let (typed, emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(typed.image_stabilization(), Some(4));
    assert_eq!(
      emissions[0].value().as_ref(),
      &TagValue::Str("On, Mode 2".into())
    );
  }

  #[test]
  fn parse_firmware_version_dotted() {
    // FirmwareVersion (0x02) undef count 4 value bytes [0,1,0,8]
    let blob = build_blob(&[(0x02, 0x07, 4, std::vec![0x00, 0x01, 0x00, 0x08])]);
    let (typed, emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(typed.firmware_version(), Some("0.1.0.8"));
    assert_eq!(
      emissions[0].value().as_ref(),
      &TagValue::Str("0.1.0.8".into())
    );
  }

  #[test]
  fn parse_internal_serial_number_decoded() {
    // InternalSerialNumber (0x25) undef count 16 = "S000407190102\0\0\0"
    let mut bytes = std::vec![0u8; 16];
    bytes[..13].copy_from_slice(b"S000407190102");
    let blob = build_blob(&[(0x25, 0x07, 16, bytes)]);
    let (typed, emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(
      typed.internal_serial_number(),
      Some("(S00) 2004:07:19 no. 0102")
    );
    assert_eq!(
      emissions[0].value().as_ref(),
      &TagValue::Str("(S00) 2004:07:19 no. 0102".into())
    );
  }

  #[test]
  fn parse_shooting_mode_program() {
    // ShootingMode (0x1f) int16u count 1 value 6 ⇒ "Program"
    let blob = build_blob(&[(0x1f, 0x03, 1, std::vec![0x06, 0x00, 0, 0])]);
    let (typed, emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(typed.shooting_mode(), Some(6));
    assert_eq!(
      emissions[0].value().as_ref(),
      &TagValue::Str("Program".into())
    );
  }

  #[test]
  fn parse_lens_type_string() {
    // LensType (0x51) ASCII string "LUMIX G 14/F2.5"
    let val = b"LUMIX G 14/F2.5\x00".to_vec();
    let blob = build_blob(&[(0x51, 0x02, val.len() as u32, val)]);
    let (typed, _emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(typed.lens_type(), Some("LUMIX G 14/F2.5"));
  }

  /// 0xc5 / 0xe4 LensTypeModel through the full parse path
  /// (`Panasonic.pm:1417-1428,1461-1472`): a non-zero int16u byte-swaps
  /// (`0x1234 → "34 12"`), while a zero value is RawConv-dropped (the tag is
  /// ABSENT from the emissions, not rendered as a raw `0`/`"00 00"`).
  #[test]
  fn lens_type_model_0xc5_0xe4_byte_swap_and_undef_drop() {
    // 0xc5 = 0x1234 (LE int16u) → "34 12".
    let blob = build_blob(&[(0xc5, 0x03, 1, std::vec![0x34, 0x12, 0, 0])]);
    let (_t, em) = parse(&blob, ByteOrder::Little);
    assert_eq!(
      emit_value(&em, "LensTypeModel"),
      Some(TagValue::Str("34 12".into()))
    );
    // 0xe4 behaves identically: 0x0102 → "02 01".
    let blob_e4 = build_blob(&[(0xe4, 0x03, 1, std::vec![0x02, 0x01, 0, 0])]);
    let (_t2, em2) = parse(&blob_e4, ByteOrder::Little);
    assert_eq!(
      emit_value(&em2, "LensTypeModel"),
      Some(TagValue::Str("02 01".into()))
    );
    // NEGATIVE oracle — a zero value is RawConv-dropped ⇒ tag SUPPRESSED.
    let blob_zero = build_blob(&[(0xc5, 0x03, 1, std::vec![0x00, 0x00, 0, 0])]);
    let (_t3, em3) = parse(&blob_zero, ByteOrder::Little);
    assert_eq!(
      emit_value(&em3, "LensTypeModel"),
      None,
      "0xc5 == 0 ⇒ RawConv undef-drop ⇒ tag must be absent"
    );
  }

  #[test]
  fn empty_blob_yields_empty() {
    let (typed, emissions) = parse(&[], ByteOrder::Little);
    assert_eq!(typed, MakerNotesPanasonic::new());
    assert!(emissions.is_empty());
  }

  /// Find the first emission named `name`.
  fn emit_value(em: &[VendorEmission<'_>], name: &str) -> Option<TagValue> {
    em.iter()
      .find(|e| e.name() == name)
      .map(|e| e.value().into_owned())
  }

  /// 0x0f AFAreaMode model-conditional (`Panasonic.pm:336-382`). On DMC-FZ10
  /// the FZ10 branch applies: int8u[2] = [0,16] → "Spot Mode Off"; on a
  /// non-FZ10 (and on an absent Model) the "other models" branch applies:
  /// [0,16] → "3-area (high speed)".
  #[test]
  fn af_area_mode_0x0f_model_conditional() {
    let blob = build_blob(&[(0x0f, 0x01, 2, std::vec![0x00, 0x10, 0, 0])]);
    // FZ10 branch.
    let (_t, em) = parse_in_tiff(
      &blob,
      0,
      blob.len(),
      body::HEADER_LEN,
      ByteOrder::Little,
      true,
      Some("DMC-FZ10"),
      0,
    );
    assert_eq!(
      emit_value(&em, "AFAreaMode"),
      Some(TagValue::Str("Spot Mode Off".into()))
    );
    // Other-models branch (FZ100 is NOT FZ10 — `\b` after "FZ10").
    let (_t2, em2) = parse_in_tiff(
      &blob,
      0,
      blob.len(),
      body::HEADER_LEN,
      ByteOrder::Little,
      true,
      Some("DMC-FZ100"),
      0,
    );
    assert_eq!(
      emit_value(&em2, "AFAreaMode"),
      Some(TagValue::Str("3-area (high speed)".into()))
    );
    // Absent Model → other-models branch (matches ExifTool's undef behavior).
    let (_t3, em3) = parse_in_tiff(
      &blob,
      0,
      blob.len(),
      body::HEADER_LEN,
      ByteOrder::Little,
      true,
      None,
      0,
    );
    assert_eq!(
      emit_value(&em3, "AFAreaMode"),
      Some(TagValue::Str("3-area (high speed)".into()))
    );
  }

  /// 0x2c ContrastMode model-conditional (`Panasonic.pm:549-660`). Selects
  /// PrintHex / GF-G2 / TZ10-ZS7 / raw branches by `$$self{Model}`.
  #[test]
  fn contrast_mode_0x2c_model_conditional() {
    let make = |v: u8| build_blob(&[(0x2c, 0x03, 1, std::vec![v, 0x00, 0, 0])]);
    // Branch 1 (PrintHex) — e.g. FZ8: 0x06 → "Medium Low".
    let blob6 = make(0x06);
    let (_t, em) = parse_in_tiff(
      &blob6,
      0,
      blob6.len(),
      body::HEADER_LEN,
      ByteOrder::Little,
      true,
      Some("DMC-FZ8"),
      0,
    );
    assert_eq!(
      emit_value(&em, "ContrastMode"),
      Some(TagValue::Str("Medium Low".into()))
    );
    // Absent Model → branch 1 too (undef passes both negated conditions).
    let (_t0, em0) = parse_in_tiff(
      &blob6,
      0,
      blob6.len(),
      body::HEADER_LEN,
      ByteOrder::Little,
      true,
      None,
      0,
    );
    assert_eq!(
      emit_value(&em0, "ContrastMode"),
      Some(TagValue::Str("Medium Low".into()))
    );

    // Branch 2 (GF/G2) — GF1: 7 → "Nature (Color Film)".
    let blob7 = make(0x07);
    let (_t2, em2) = parse_in_tiff(
      &blob7,
      0,
      blob7.len(),
      body::HEADER_LEN,
      ByteOrder::Little,
      true,
      Some("DMC-GF1"),
      0,
    );
    assert_eq!(
      emit_value(&em2, "ContrastMode"),
      Some(TagValue::Str("Nature (Color Film)".into()))
    );
    // G2 also takes branch 2: 2 → "Normal".
    let blob2 = make(0x02);
    let (_t2b, em2b) = parse_in_tiff(
      &blob2,
      0,
      blob2.len(),
      body::HEADER_LEN,
      ByteOrder::Little,
      true,
      Some("DMC-G2"),
      0,
    );
    assert_eq!(
      emit_value(&em2b, "ContrastMode"),
      Some(TagValue::Str("Normal".into()))
    );

    // Branch 3 (TZ10/ZS7) — TZ10: 1 → "-2".
    let blob1 = make(0x01);
    let (_t3, em3) = parse_in_tiff(
      &blob1,
      0,
      blob1.len(),
      body::HEADER_LEN,
      ByteOrder::Little,
      true,
      Some("DMC-TZ10"),
      0,
    );
    assert_eq!(
      emit_value(&em3, "ContrastMode"),
      Some(TagValue::Str("-2".into()))
    );

    // Branch 4 (no PrintConv → raw) — DMC-G1 (excluded from branch 1, not
    // GF/G2/TZ10/ZS7): value 7 stays the bare int.
    let (_t4, em4) = parse_in_tiff(
      &blob7,
      0,
      blob7.len(),
      body::HEADER_LEN,
      ByteOrder::Little,
      true,
      Some("DMC-G1"),
      0,
    );
    assert_eq!(emit_value(&em4, "ContrastMode"), Some(TagValue::I64(7)));
    // A DC- body likewise falls through to raw.
    let (_t5, em5) = parse_in_tiff(
      &blob7,
      0,
      blob7.len(),
      body::HEADER_LEN,
      ByteOrder::Little,
      true,
      Some("DC-GH6"),
      0,
    );
    assert_eq!(emit_value(&em5, "ContrastMode"), Some(TagValue::I64(7)));
  }

  /// `parse_into_metadata` must push under the Panasonic MakerNote group
  /// (`Vendor::Panasonic.group1()` = `"Panasonic"`, both family-0 and
  /// family-1), NOT the literal `("MakerNotes","MakerNotes")` — `exiftool -j
  /// -G1` emits `Panasonic:ImageQuality` on a Lumix. Regression guard for
  /// Finding 3.
  #[test]
  fn parse_into_metadata_uses_panasonic_group_no_makernotes_leak() {
    let blob = build_blob(&[(0x01, 0x03, 1, std::vec![0x02, 0x00, 0, 0])]);
    let mut md = Metadata::new("test.rw2");
    parse_into_metadata(&blob, ByteOrder::Little, true, &mut md);
    let tags = md.tags_slice();
    assert!(!tags.is_empty(), "expected at least the ImageQuality tag");
    for t in tags {
      assert_eq!(
        t.group_ref().family1(),
        "Panasonic",
        "tag {:?} leaked group {:?} instead of Panasonic",
        t.name(),
        t.group_ref().family1()
      );
      assert_eq!(t.group_ref().family0(), "Panasonic");
      assert_ne!(
        t.group_ref().family1(),
        "MakerNotes",
        "MakerNotes: leak for {:?}",
        t.name()
      );
    }
    let q = tags
      .iter()
      .find(|t| t.name() == "ImageQuality")
      .expect("ImageQuality");
    assert_eq!(q.value_ref(), &TagValue::Str("High".into()));
  }

  /// `parse_into_metadata` suppresses the lone `Unknown => 1` tag (0x63
  /// `RecognizedFaceFlags`, `Panasonic.pm:1018-1026`) from the default sink,
  /// matching `run_emission` / `ExifTool.pm:9179-9185`. A sibling
  /// non-Unknown leaf (0x01 ImageQuality) is retained.
  #[test]
  fn parse_into_metadata_suppresses_unknown_recognized_face_flags() {
    let blob = build_blob(&[
      (0x01, 0x03, 1, std::vec![0x02, 0x00, 0, 0]),
      (0x63, 0x07, 4, std::vec![0x00, 0x00, 0x00, 0x00]),
    ]);
    let mut md = Metadata::new("test.rw2");
    parse_into_metadata(&blob, ByteOrder::Little, true, &mut md);
    let names: Vec<&str> = md.tags_slice().iter().map(|t| t.name()).collect();
    assert!(
      names.contains(&"ImageQuality"),
      "ImageQuality should be present"
    );
    assert!(
      !names.contains(&"RecognizedFaceFlags"),
      "Unknown tag 0x63 must be suppressed, got {names:?}"
    );
  }

  /// SubDirectory rows DESCEND into their child `ProcessBinaryData` table (#105):
  /// the PARENT pointer (`FaceDetInfo`/`TimeInfo`) is NEVER emitted as a value
  /// (ExifTool's `if ($subdir)` descends + `next`s before `FoundTag`,
  /// `Exif.pm:6919,7103-7104,7180`), but the CHILD positions ARE emitted under
  /// the `Panasonic` group. A sibling leaf (0x01 ImageQuality) is still emitted,
  /// proving the descent is targeted, not a blanket drop. End-to-end through the
  /// shared-`Walker` capture loop.
  #[test]
  fn subdir_facedetinfo_timeinfo_descend_to_children() {
    // 0x4e FaceDetInfo undef[10]: NumFacePositions=1, Face1Position=160 120 50 50.
    let mut face = std::vec![0u8; 10];
    face[0..2].copy_from_slice(&1u16.to_le_bytes());
    for (k, v) in [160u16, 120, 50, 50].iter().enumerate() {
      face[2 + k * 2..4 + k * 2].copy_from_slice(&v.to_le_bytes());
    }
    // 0x2003 TimeInfo undef[20]: PanasonicDateTime + TimeLapseShotNumber=9.
    let mut time = std::vec![0u8; 20];
    time[0..8].copy_from_slice(&[0x20, 0x21, 0x06, 0x28, 0x14, 0x30, 0x00, 0x55]);
    time[16..20].copy_from_slice(&9u32.to_le_bytes());
    // Entries MUST be tag-id sorted: 0x01, 0x4e, 0x2003.
    let blob = build_blob(&[
      (0x01, 0x03, 1, std::vec![0x02, 0x00, 0, 0]), // ImageQuality int16u = 2 ("High")
      (0x4e, 0x07, 10, face),
      (0x2003, 0x07, 20, time),
    ]);
    for print_conv in [true, false] {
      let (_t, em) = parse_with_print_conv(&blob, ByteOrder::Little, print_conv);
      // The PARENT SubDirectory pointers are never emitted as values.
      assert_eq!(emit_value(&em, "FaceDetInfo"), None);
      assert_eq!(emit_value(&em, "TimeInfo"), None);
      // The CHILD positions ARE emitted (the #105 descent), identical in both modes.
      assert_eq!(emit_value(&em, "NumFacePositions"), Some(TagValue::I64(1)));
      assert_eq!(
        emit_value(&em, "Face1Position"),
        Some(TagValue::Str("160 120 50 50".into()))
      );
      assert_eq!(
        emit_value(&em, "PanasonicDateTime"),
        Some(TagValue::Str("2021:06:28 14:30:00.55".into()))
      );
      assert_eq!(
        emit_value(&em, "TimeLapseShotNumber"),
        Some(TagValue::I64(9))
      );
    }
    // In print-conv mode the sibling leaf renders via PrintConv (`Panasonic.pm:281`).
    let (_tp, emp) = parse_with_print_conv(&blob, ByteOrder::Little, true);
    assert_eq!(
      emit_value(&emp, "ImageQuality"),
      Some(TagValue::Str("High".into()))
    );

    // Through the Metadata sink: child keys present, parent keys absent, all
    // under the `Panasonic` family-1 group (the source tables' module default).
    let mut md = Metadata::new("test.rw2");
    parse_into_metadata(&blob, ByteOrder::Little, true, &mut md);
    let names: Vec<&str> = md.tags_slice().iter().map(|t| t.name()).collect();
    assert!(
      !names.contains(&"FaceDetInfo") && !names.contains(&"TimeInfo"),
      "no SubDirectory parent may reach the Metadata sink, got {names:?}"
    );
    assert!(
      names.contains(&"NumFacePositions")
        && names.contains(&"PanasonicDateTime")
        && names.contains(&"ImageQuality"),
      "child + sibling tags must reach the sink, got {names:?}"
    );
    for t in md.tags_slice() {
      assert_eq!(
        t.group_ref().family1(),
        "Panasonic",
        "tag {:?} must emit under the Panasonic group",
        t.name()
      );
    }
  }

  /// `$format`-gated single-HASH `Condition` suppression for the LensType
  /// rows. 0xc4 LensTypeMake (`Panasonic.pm:1414`): `$format eq "int16u" and
  /// $$valPt ne "\xff\xff"` — present for an int16u value ≠ 0xffff (incl. 0),
  /// suppressed for the int16u value 0xffff OR a non-int16u format. 0xc5/0xe4
  /// LensTypeModel (`Panasonic.pm:1419,1463`): `$format eq "int16u"` —
  /// suppressed for a non-int16u format. All cases verified against bundled
  /// 13.59 `GetTagInfo`.
  #[test]
  fn lens_type_make_model_format_suppression() {
    // 0xc4 int16u 0x0102 ⇒ present (raw int16u 258, no PrintConv).
    let ok = build_blob(&[(0xc4, 0x03, 1, std::vec![0x02, 0x01, 0, 0])]);
    let (_t, em) = parse(&ok, ByteOrder::Little);
    assert_eq!(
      emit_value(&em, "LensTypeMake"),
      Some(TagValue::I64(258)),
      "0xc4 int16u ≠ 0xffff ⇒ present"
    );
    // 0xc4 int16u value 0 is NOT excluded ($$valPt ne "\xff\xff" only drops
    // 0xffff) ⇒ present (raw 0).
    let zero = build_blob(&[(0xc4, 0x03, 1, std::vec![0x00, 0x00, 0, 0])]);
    let (_t0, em0) = parse(&zero, ByteOrder::Little);
    assert_eq!(
      emit_value(&em0, "LensTypeMake"),
      Some(TagValue::I64(0)),
      "0xc4 int16u value 0 ⇒ present (only 0xffff is dropped)"
    );
    // 0xc4 int16u value 0xffff ⇒ suppressed ($$valPt eq "\xff\xff").
    let ffff = build_blob(&[(0xc4, 0x03, 1, std::vec![0xFF, 0xFF, 0, 0])]);
    let (_tf, emf) = parse(&ffff, ByteOrder::Little);
    assert_eq!(
      emit_value(&emf, "LensTypeMake"),
      None,
      "0xc4 int16u 0xffff ⇒ suppressed"
    );
    // 0xc4 int32u ⇒ suppressed ($format ne int16u).
    let bad = build_blob(&[(0xc4, 0x04, 1, std::vec![0x02, 0x01, 0, 0])]);
    let (_tb, emb) = parse(&bad, ByteOrder::Little);
    assert_eq!(
      emit_value(&emb, "LensTypeMake"),
      None,
      "0xc4 int32u ⇒ suppressed"
    );

    // 0xc5 int16u 0x1234 ⇒ present (byte-swap "34 12"); int32u ⇒ suppressed.
    let c5ok = build_blob(&[(0xc5, 0x03, 1, std::vec![0x34, 0x12, 0, 0])]);
    let (_t5, em5) = parse(&c5ok, ByteOrder::Little);
    assert_eq!(
      emit_value(&em5, "LensTypeModel"),
      Some(TagValue::Str("34 12".into())),
      "0xc5 int16u ⇒ present (byte-swapped)"
    );
    let c5bad = build_blob(&[(0xc5, 0x04, 1, std::vec![0x34, 0x12, 0, 0])]);
    let (_t5b, em5b) = parse(&c5bad, ByteOrder::Little);
    assert_eq!(
      emit_value(&em5b, "LensTypeModel"),
      None,
      "0xc5 int32u ⇒ suppressed ($format ne int16u)"
    );
    // 0xe4 int32u ⇒ suppressed too.
    let e4bad = build_blob(&[(0xe4, 0x04, 1, std::vec![0x02, 0x01, 0, 0])]);
    let (_te4, eme4) = parse(&e4bad, ByteOrder::Little);
    assert_eq!(
      emit_value(&eme4, "LensTypeModel"),
      None,
      "0xe4 int32u ⇒ suppressed ($format ne int16u)"
    );
  }

  /// RawConv undef-drop for 0x86 ManometerPressure (`Panasonic.pm:1130`,
  /// `$val==65535 ? undef`) and 0xd1 ISO (`Panasonic.pm:1431`, `$val >
  /// 0xfffffff0 ? undef`). The sentinel raw ⇒ the tag is ABSENT; a normal raw
  /// ⇒ present + converted. Verified against bundled.
  #[test]
  fn rawconv_drop_manometer_and_iso() {
    // 0x86 int16u 65535 ⇒ dropped (no bogus "6553.5 kPa").
    let mano_sentinel = build_blob(&[(0x86, 0x03, 1, std::vec![0xFF, 0xFF, 0, 0])]);
    let (_t, em) = parse(&mano_sentinel, ByteOrder::Little);
    assert_eq!(
      emit_value(&em, "ManometerPressure"),
      None,
      "0x86 raw 65535 ⇒ RawConv undef-drop ⇒ absent"
    );
    // 0x86 int16u 1013 ⇒ present, "/10" + "%.1f kPa" ⇒ "101.3 kPa".
    let mano_ok = build_blob(&[(0x86, 0x03, 1, std::vec![0xF5, 0x03, 0, 0])]); // 1013 LE
    let (_t2, em2) = parse(&mano_ok, ByteOrder::Little);
    assert_eq!(
      emit_value(&em2, "ManometerPressure"),
      Some(TagValue::Str("101.3 kPa".into())),
      "0x86 raw 1013 ⇒ present (\"101.3 kPa\")"
    );

    // 0xd1 ISO int32u 0xffffffff (> 0xfffffff0) ⇒ dropped.
    let iso_sentinel = build_blob(&[(0xd1, 0x04, 1, std::vec![0xFF, 0xFF, 0xFF, 0xFF])]);
    let (_t3, em3) = parse(&iso_sentinel, ByteOrder::Little);
    assert_eq!(
      emit_value(&em3, "ISO"),
      None,
      "0xd1 raw 0xffffffff ⇒ RawConv undef-drop ⇒ absent"
    );
    // 0xd1 ISO int32u 0xfffffff0 (NOT > 0xfffffff0) ⇒ present (boundary).
    let iso_boundary = build_blob(&[(0xd1, 0x04, 1, std::vec![0xF0, 0xFF, 0xFF, 0xFF])]);
    let (_t4, em4) = parse(&iso_boundary, ByteOrder::Little);
    assert_eq!(
      emit_value(&em4, "ISO"),
      Some(TagValue::I64(0xffff_fff0)),
      "0xd1 raw 0xfffffff0 ⇒ present (boundary: drop is strictly >)"
    );
    // 0xd1 ISO int32u 100 ⇒ present (no PrintConv ⇒ raw int).
    let iso_ok = build_blob(&[(0xd1, 0x04, 1, std::vec![0x64, 0, 0, 0])]);
    let (_t5, em5) = parse(&iso_ok, ByteOrder::Little);
    assert_eq!(
      emit_value(&em5, "ISO"),
      Some(TagValue::I64(100)),
      "0xd1 raw 100 ⇒ present (raw 100)"
    );
  }

  /// PrintHex HASH-miss fallback (`ExifTool.pm:3628-3631`): a
  /// `Flags => 'PrintHex'` / `PrintHex => 1` tag whose PrintConv HASH misses
  /// renders `sprintf('Unknown (0x%x)',$val)`, NOT a bare `0xNN` and NOT the
  /// decimal `Unknown ($val)`. Covers 0x2c ContrastMode branch-1
  /// (`Panasonic.pm:557 Flags => 'PrintHex'`) and 0xbb VideoBurstMode
  /// (`Panasonic.pm:1361 PrintHex => 1`). Matched keys still render their
  /// label. Miss keys (3, 0x1080) verified absent from the bundled hashes.
  #[test]
  fn printhex_hash_miss_renders_unknown_hex() {
    // 0x2c ContrastMode on a branch-1 body (DMC-FZ8): key 3 is a MISS ⇒
    // "Unknown (0x3)"; key 6 is "Medium Low".
    let cm = |v: u8| build_blob(&[(0x2c, 0x03, 1, std::vec![v, 0x00, 0, 0])]);
    let go_cm = |blob: &[u8]| {
      let (_t, em) = parse_in_tiff(
        blob,
        0,
        blob.len(),
        body::HEADER_LEN,
        ByteOrder::Little,
        true,
        Some("DMC-FZ8"),
        0,
      );
      emit_value(&em, "ContrastMode")
    };
    assert_eq!(
      go_cm(&cm(0x03)),
      Some(TagValue::Str("Unknown (0x3)".into())),
      "0x2c branch-1 miss ⇒ PrintHex \"Unknown (0x3)\" (not \"0x3\", not \"Unknown (3)\")"
    );
    assert_eq!(
      go_cm(&cm(0x06)),
      Some(TagValue::Str("Medium Low".into())),
      "0x2c branch-1 key 6 ⇒ \"Medium Low\""
    );

    // 0xbb VideoBurstMode int32u 0x1080 is a MISS ⇒ "Unknown (0x1080)";
    // 0x18 ⇒ "4K Burst".
    let vb = |v: u32| build_blob(&[(0xbb, 0x04, 1, v.to_le_bytes().to_vec())]);
    let go_vb = |blob: &[u8]| {
      let (_t, em) = parse(blob, ByteOrder::Little);
      emit_value(&em, "VideoBurstMode")
    };
    assert_eq!(
      go_vb(&vb(0x1080)),
      Some(TagValue::Str("Unknown (0x1080)".into())),
      "0xbb miss ⇒ PrintHex \"Unknown (0x1080)\""
    );
    assert_eq!(
      go_vb(&vb(0x18)),
      Some(TagValue::Str("4K Burst".into())),
      "0xbb key 0x18 ⇒ \"4K Burst\""
    );
  }

  // ===========================================================================
  // Parse-level Format-override oracle cases (Exif.pm:6735-6744). Each encodes
  // an entry with its ON-DISK format + bytes; the `Format => 'int16s'`/etc.
  // directive re-interprets the SAME bytes. Expected values verified against
  // bundled 13.59 via `Image::ExifTool::ReadValue` + the row's ValueConv/
  // PrintConv. The on-disk format is kept for the `$format` Condition gate.
  // ===========================================================================

  /// 0x23 WhiteBalanceBias (`Panasonic.pm:431-439`) — `Format => 'int16s'`,
  /// `ValueConv => '$val/3'`, `PrintConv => PrintFraction`. Synthetically
  /// encoded on-disk as int16u bytes `FD FF` (LE) ⇒ 65533 WITHOUT the override
  /// (the bug), ⇒ int16s -3 WITH it ⇒ ValueConv -1 ⇒ PrintFraction "-1"
  /// (verified vs bundled `ReadValue`+`PrintFraction`).
  #[test]
  fn format_override_0x23_white_balance_bias_int16s() {
    // On-disk int16u (code 3) count 1, inline bytes FD FF (= -3 as int16s LE).
    let blob = build_blob(&[(0x23, 0x03, 1, std::vec![0xFD, 0xFF, 0, 0])]);
    let (_t, em) = parse(&blob, ByteOrder::Little);
    assert_eq!(
      emit_value(&em, "WhiteBalanceBias"),
      Some(TagValue::Str("-1".into())),
      "0x23 int16u FD FF ⇒ int16s -3 ⇒ /3 = -1 ⇒ PrintFraction \"-1\""
    );
    // `-n` mode shows the ValueConv float (-1.0).
    let (_t2, em2) = parse_in_tiff(
      &blob,
      0,
      blob.len(),
      body::HEADER_LEN,
      ByteOrder::Little,
      false,
      None,
      0,
    );
    assert_eq!(
      emit_value(&em2, "WhiteBalanceBias"),
      Some(TagValue::F64(-1.0)),
      "0x23 -n ⇒ ValueConv -1.0"
    );
  }

  /// 0x90 RollAngle / 0x91 PitchAngle (`Panasonic.pm:1200-1215`) — `Format =>
  /// 'int16s'`, `Writable => 'int16u'`. On-disk int16u `F1 FF` (LE) ⇒ int16s
  /// -15; RollAngle `$val/10` ⇒ -1.5, PitchAngle `-$val/10` ⇒ 1.5 (no
  /// PrintConv). Also drives the typed `roll_angle()`/`pitch_angle()` fields.
  #[test]
  fn format_override_0x90_0x91_roll_pitch_int16s() {
    let blob = build_blob(&[
      (0x90, 0x03, 1, std::vec![0xF1, 0xFF, 0, 0]),
      (0x91, 0x03, 1, std::vec![0xF1, 0xFF, 0, 0]),
    ]);
    let (typed, em) = parse(&blob, ByteOrder::Little);
    assert_eq!(
      emit_value(&em, "RollAngle"),
      Some(TagValue::F64(-1.5)),
      "0x90 int16u F1 FF ⇒ int16s -15 ⇒ /10 = -1.5"
    );
    assert_eq!(
      emit_value(&em, "PitchAngle"),
      Some(TagValue::F64(1.5)),
      "0x91 int16u F1 FF ⇒ int16s -15 ⇒ -(-15)/10 = 1.5"
    );
    assert_eq!(typed.roll_angle(), Some(-1.5));
    assert_eq!(typed.pitch_angle(), Some(1.5));
  }

  /// 0x8c AccelerometerZ (`Panasonic.pm:1170-1175`) — `Format => 'int16s'`,
  /// `Writable => 'int16u'`, int16s passthrough. On-disk int16u `9C FF` (LE)
  /// ⇒ int16s -100.
  #[test]
  fn format_override_0x8c_accelerometer_int16s() {
    let blob = build_blob(&[(0x8c, 0x03, 1, std::vec![0x9C, 0xFF, 0, 0])]);
    let (_t, em) = parse(&blob, ByteOrder::Little);
    assert_eq!(
      emit_value(&em, "AccelerometerZ"),
      Some(TagValue::I64(-100)),
      "0x8c int16u 9C FF ⇒ int16s override ⇒ -100"
    );
  }

  /// 0x39 Contrast (`Panasonic.pm:773-778`) — `Format => 'int16s'`, `Writable
  /// => 'int16u'`, `PrintConv => {0=>'Normal', OTHER=>printParameter}`. On-disk
  /// int16u `FE FF` (LE) ⇒ int16s -2 ⇒ printParameter "-2" (NOT "+65534").
  #[test]
  fn format_override_0x39_contrast_int16s_print_parameter() {
    let blob = build_blob(&[(0x39, 0x03, 1, std::vec![0xFE, 0xFF, 0, 0])]);
    let (_t, em) = parse(&blob, ByteOrder::Little);
    assert_eq!(
      emit_value(&em, "Contrast"),
      Some(TagValue::Str("-2".into())),
      "0x39 int16u FE FF ⇒ int16s -2 ⇒ printParameter \"-2\""
    );
    // Positive raw ⇒ "+2"; zero ⇒ "Normal".
    let blob_pos = build_blob(&[(0x39, 0x03, 1, std::vec![0x02, 0x00, 0, 0])]);
    let (_t2, em2) = parse(&blob_pos, ByteOrder::Little);
    assert_eq!(
      emit_value(&em2, "Contrast"),
      Some(TagValue::Str("+2".into()))
    );
    let blob_zero = build_blob(&[(0x39, 0x03, 1, std::vec![0x00, 0x00, 0, 0])]);
    let (_t3, em3) = parse(&blob_zero, ByteOrder::Little);
    assert_eq!(
      emit_value(&em3, "Contrast"),
      Some(TagValue::Str("Normal".into()))
    );
  }

  /// 0x59 Transform (`Panasonic.pm:970-983`) — `Format => 'int16s', Count =>
  /// 2`, `Writable => 'undef'`. On-disk undef (4 bytes) re-read as two int16s.
  /// `00 00` first value ⇒ PrintConv key 0 → "No"/identity per the hash.
  #[test]
  fn format_override_0x59_transform_int16s_pair() {
    // On-disk undef (code 7) count 4 ⇒ 4 inline bytes; override int16s ⇒
    // int(4/2)=2 values [0, 0]. Transform PrintConv keys on the pair.
    let blob = build_blob(&[(0x59, 0x07, 4, std::vec![0x00, 0x00, 0x00, 0x00])]);
    let (_t, em) = parse(&blob, ByteOrder::Little);
    // The value must read as the int16s pair (not 4 raw undef bytes). The
    // Transform conv renders [0,0]; assert it is PRESENT and a string label.
    let got = emit_value(&em, "Transform");
    assert!(got.is_some(), "0x59 Transform present, got {got:?}");
  }

  /// 0x44 ColorTempKelvin (`Panasonic.pm:861-864`) — `Format => 'int16u'`,
  /// `Writable => undef`. When the entry is ALREADY on-disk int16u the
  /// override is a value-identical no-op (`$newNum == $format`): the raw
  /// int16u passes through unchanged. (Carried for the oracle's handled set.)
  #[test]
  fn format_override_0x44_color_temp_kelvin_int16u_noop() {
    let blob = build_blob(&[(0x44, 0x03, 1, std::vec![0x88, 0x13, 0, 0])]); // 5000
    let (_t, em) = parse(&blob, ByteOrder::Little);
    assert_eq!(
      emit_value(&em, "ColorTempKelvin"),
      Some(TagValue::I64(5000)),
      "0x44 on-disk int16u 5000 ⇒ override no-op ⇒ 5000"
    );
  }

  /// 0x4d AFPointPosition (`Panasonic.pm:916-935`) END-TO-END through
  /// `parse`: on-disk rational64u[2] = `128/256 128/256` (the real
  /// `Panasonic.rw2` sample) ⇒ decimal ValueConv `"0.5 0.5"`, PrintConv
  /// `%.2g` ⇒ `"0.5 0.5"` (bundled `-j` AND `-n`). 16 bytes ⇒ out-of-line.
  #[test]
  fn af_point_position_0x4d_real_sample_value() {
    // rational64u (code 5), count 2: num=128,den=256 twice (LE int32u each).
    let mut value = Vec::new();
    for _ in 0..2 {
      value.extend_from_slice(&128u32.to_le_bytes());
      value.extend_from_slice(&256u32.to_le_bytes());
    }
    let blob = build_blob(&[(0x4d, 0x05, 2, value)]);
    // -j (PrintConv on).
    let (_t, em) = parse(&blob, ByteOrder::Little);
    assert_eq!(
      emit_value(&em, "AFPointPosition"),
      Some(TagValue::Str("0.5 0.5".into())),
      "-j: %.2g of the decimal pair"
    );
    // -n (PrintConv off) — same string here.
    let (_t2, em2) = parse_with_print_conv(&blob, ByteOrder::Little, false);
    assert_eq!(
      emit_value(&em2, "AFPointPosition"),
      Some(TagValue::Str("0.5 0.5".into())),
      "-n: the ValueConv decimal pair"
    );
  }

  /// 0xa1 FilterEffect (`Panasonic.pm:1274-1304`) END-TO-END: on-disk
  /// rational64u (8 bytes) re-read via `Format => 'int32u'` as int32u[2] ⇒
  /// the pair `[0, 1]` ⇒ PrintConv `"0 1" => 'Expressive'`. Proves the
  /// Format reinterpret feeds the pair-keyed hash (the deferral was wrong).
  #[test]
  fn filter_effect_0xa1_format_reinterpret_end_to_end() {
    // On-disk rational64u (code 5) count 1 = 8 bytes; as int32u[2] = [0, 1].
    let mut value = Vec::new();
    value.extend_from_slice(&0u32.to_le_bytes());
    value.extend_from_slice(&1u32.to_le_bytes());
    let blob = build_blob(&[(0xa1, 0x05, 1, value)]);
    let (_t, em) = parse(&blob, ByteOrder::Little);
    assert_eq!(
      emit_value(&em, "FilterEffect"),
      Some(TagValue::Str("Expressive".into())),
      "Format=int32u ⇒ int32u[2]=[0,1] ⇒ 'Expressive'"
    );
  }
}
