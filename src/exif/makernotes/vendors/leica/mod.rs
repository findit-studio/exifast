// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Leica MakerNotes — the `%Image::ExifTool::Panasonic::Leica2`..`Leica9`
//! variant-table port (`Panasonic.pm:1604-2256`).
//!
//! The MakerNotes dispatcher (`MakerNotes.pm:611-721`) detects EIGHT Leica
//! signature variants (Leica2..Leica9) — all `Vendor::Leica`, each with its own
//! `Base`/byte-order rules — and resolves them to one of SIX distinct tables
//! (Leica7 reuses `%Leica6`, Leica8 reuses `%Leica5`). The shared `Walker`
//! walks each under [`TableRef::Leica`](crate::exif::makernotes::subdir::TableRef::Leica)
//! carrying the [`tags::LeicaVariant`] payload, applying the dispatched
//! `Start`/`Base`/`ByteOrder` per the descriptor (the same machinery the other
//! migrated vendors use, #243 phase 3).
//!
//! Leica1 + Leica10 are NOT here — they reuse `%Panasonic::Main` (they are
//! Panasonic tags) and emit under the `Panasonic` group via the
//! `panasonic::parse_leica{1,10}_gated` cross-vendor route.
//!
//! ## Leica7 `Base => '-$base'` (`NegativeOfBase`)
//!
//! Leica7 (`MakerNotes.pm:699`) is the ONLY `Base => '-$base'` in the module —
//! its out-of-line value pointers are ABSOLUTE FILE offsets, so the inline-IFD
//! walk must rebase them to the slice it walks by SUBTRACTING the parent TIFF
//! base. The isolated helper therefore maps `NegativeOfBase` to
//! `value_offset_base = -parent_base`, where `parent_base` is the base of the
//! IFD that contains the 0x927c MakerNote entry (threaded from the parent
//! `Walker`):
//!
//! * For a standalone / base-0 TIFF `parent_base == 0`, so `value_offset_base =
//!   -0 = 0` — identical to `Inherit`, and an absolute pointer resolves directly
//!   against the buffer.
//! * For a real JPEG `APP1` Exif block the TIFF is SLICED at its NONZERO file
//!   offset and walked with that base retained, so an absolute Leica7 pointer
//!   `P` resolves at `data[P - parent_base]` — the slice-relative index. (A
//!   hardcoded `value_offset_base = 0` would read these from the wrong offset /
//!   out of bounds — the production bug the base-0 standalone fixture missed.)
//!
//! `value_offset_base` is a signed `i64`, so the negated base is expressible
//! directly; the value-resolution site range-checks the result both ends
//! (`off_signed >= 0 && off + size <= len`), so a pointer landing outside the
//! slice is dropped, never wrapped. (The Leica7 *trailer* layout some JPEGs use
//! — a `ProcessLeicaTrailer` blob whose base is the trailer's absolute file
//! position — is a separate, deferred case.) Verified byte-exact against the
//! `perl exiftool` oracle on the crafted standalone + nonzero-base Leica7
//! fixtures (`tests/exif_makernotes_dispatch.rs`).
//!
//! ## D8 compliance
//!
//! No public fields on the typed surface. `#[non_exhaustive]` so a future phase
//! can add fields without a breaking change.

#![deny(clippy::indexing_slicing)]

pub mod data1;
pub mod focus_info;
pub mod lens_types;
pub mod printconv;
pub mod serial_info;
pub mod shot_info;
pub mod tags;

use crate::exif::ifd::{ByteOrder, RawValue};
use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

pub use lens_types::{LEICA_LENS_TYPES, LeicaLensType};
pub use printconv::LeicaPrintConv;
pub use tags::{
  LEICA2_TAGS, LEICA3_TAGS, LEICA4_TAGS, LEICA5_TAGS, LEICA6_TAGS, LEICA9_TAGS, LeicaCondition,
  LeicaSubTable, LeicaTag, LeicaVariant, SUBDIR_TAGS, format_override, lookup,
};

/// Decoded Leica MakerNotes data — populated by
/// [`crate::exif::leica_makernote_isolated`] when the dispatcher resolved
/// [`Vendor::Leica`](crate::exif::makernotes::Vendor::Leica) to one of the
/// Leica2..Leica9 variant tables.
///
/// D8: no public fields; accessor-only. The fields are the cross-variant
/// camera-identity leaves (lens + serial); their tag IDs differ per variant, so
/// [`populate_typed`] keys off `(variant, tag_id)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MakerNotesLeica {
  /// The resolved lens name — Leica2 0x310 / Leica5 0x0303 (string) / Leica6
  /// 0x303 (trimmed string). For the `%leicaLensTypes`-coded variants this is
  /// the looked-up name; for the string variants it is the raw lens string.
  lens_name: Option<SmolStr>,
  /// The camera serial number — Leica2 0x303 (`sprintf("%.7d")`) / Leica5
  /// 0x0305 (int32u).
  serial_number: Option<SmolStr>,
}

impl MakerNotesLeica {
  /// Build an empty Leica metadata bag.
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {
      lens_name: None,
      serial_number: None,
    }
  }

  /// The resolved lens name (LensType / lens string). `None` when no lens leaf
  /// was emitted.
  #[must_use]
  #[inline]
  pub fn lens_name(&self) -> Option<&str> {
    self.lens_name.as_deref()
  }

  /// The camera serial number. `None` when no serial leaf was emitted.
  #[must_use]
  #[inline]
  pub fn serial_number(&self) -> Option<&str> {
    self.serial_number.as_deref()
  }
}

/// Populate the typed struct from one gate-passing Leica leaf-tag emission.
/// `rendered` is the already-PrintConv-rendered lens/serial value (so the typed
/// `lens_name` carries the resolved `%leicaLensTypes` name, not the raw int).
///
/// MUST be called ONLY for an entry that the capture loop actually emits, so a
/// dropped/Condition-failed entry populates no typed field — mirroring the
/// Sony/Samsung/Pentax contract.
pub(crate) fn populate_typed(
  typed: &mut MakerNotesLeica,
  variant: LeicaVariant,
  tag_id: u16,
  rendered: &crate::value::TagValue,
  raw: &RawValue,
) {
  use crate::value::TagValue;
  // The lens leaf — its ID differs per variant.
  let is_lens = matches!(
    (variant, tag_id),
    (LeicaVariant::Leica2, 0x310) | (LeicaVariant::Leica5, 0x0303) | (LeicaVariant::Leica6, 0x303)
  );
  if is_lens {
    if let TagValue::Str(s) = rendered {
      typed.lens_name = Some(s.clone());
    }
    return;
  }
  // The serial leaf.
  let is_serial = matches!(
    (variant, tag_id),
    (LeicaVariant::Leica2, 0x303) | (LeicaVariant::Leica5, 0x0305)
  );
  if is_serial {
    match rendered {
      TagValue::Str(s) => typed.serial_number = Some(s.clone()),
      _ => {
        // The int32u Leica5 serial (no PrintConv) — render the first integer.
        if let RawValue::U64(v) = raw {
          if let Some(&n) = v.first() {
            typed.serial_number = Some(SmolStr::from(std::format!("{n}")));
          }
        }
      }
    }
  }
}

/// Decode a WALKED Leica `ProcessBinaryData` SubDirectory blob into its
/// `(Name, TagValue, Priority)` emission triples — the faithful descent for the
/// Leica binary sub-tables (#105): `SerialInfo` (Leica3 0x0b), `FocusInfo`
/// (Leica5 0x040a), `ShotInfo` (Leica5 0x0410), `Data1` (Subdir 0x3901). All
/// emit under the `Leica` family-1 group (`Panasonic.pm` declares `GROUPS => { 1
/// => 'Leica' }` for these tables).
///
/// The third triple element is the row's ExifTool `Priority => N` for duplicate
/// handling — the default `1` for most rows, but `0` for the two `Priority => 0`
/// rows reachable here: `Data1` `LensType` (`Panasonic.pm:1981`) and `FocusInfo`
/// `FocalLength` (`Panasonic.pm:2102`). The capture loop emits each via
/// [`write_vendor_value_with_priority`](crate::exif) so a `Priority => 0` leaf
/// never overrides a higher-priority same-`(group, name)` sibling — e.g. a later
/// `Data1` `LensType` must NOT replace the Subdir `0x3405 LensType` in the shared
/// de-dup (`ExifTool.pm:9544-9560`).
///
/// `blob` is the verbatim `$$valPt` value span; `order` the byte order the
/// parent Leica IFD was walked under.
#[must_use]
pub fn decode_leica_subdir(
  sub: LeicaSubTable,
  blob: &[u8],
  order: ByteOrder,
  print_conv: bool,
) -> Vec<(SmolStr, TagValue, u8)> {
  match sub {
    LeicaSubTable::SerialInfo => serial_info::parse(blob, print_conv),
    LeicaSubTable::FocusInfo => focus_info::parse(blob, order, print_conv),
    LeicaSubTable::ShotInfo => shot_info::parse(blob, order, print_conv),
    LeicaSubTable::Data1 => data1::parse(blob, order, print_conv),
    // `%Panasonic::Data2` is an EMPTY table (no named positions) — descends
    // but emits nothing.
    LeicaSubTable::Data2 => Vec::new(),
  }
}

/// Re-discriminate WHICH Leica2..Leica9 variant table a `Vendor::Leica` blob
/// resolves to, from the blob signature + the parent `Make`/`Model` — the
/// faithful mirror of the dispatcher's sub-arm gating (`MakerNotes.pm:611-721`).
///
/// The dispatcher collapses all the Leica variants onto `Vendor::Leica` and
/// hands back only the `Base`/`Start`/`ByteOrder` of the matched arm; the
/// production decode needs the VARIANT to pick the table. This re-runs the SAME
/// signature tests (in `%Main` order), mapping the eight signature variants onto
/// the six table-bearing [`LeicaVariant`]s (Leica7→Leica6, Leica8→Leica5). It
/// returns `None` for the cross-vendor Leica1/Leica10 routes (handled by the
/// `%Panasonic::Main` path) and for an unrecognized blob.
///
/// `blob` is the captured MakerNote value (`blob[..body_offset]` is the vendor
/// header). The tests read bytes 5..8 exactly as the dispatcher does.
#[must_use]
pub fn discriminate_variant(
  blob: &[u8],
  make: Option<&str>,
  model: Option<&str>,
) -> Option<LeicaVariant> {
  let make = make.unwrap_or("");
  let model = model.unwrap_or("");
  let ag_make = make.starts_with("Leica Camera AG");
  // Leica1 (`MakerNotes.pm:600`) — make-only `eq "LEICA"`, the %Panasonic::Main
  // route. NOT a variant table.
  if make == "LEICA" {
    return None;
  }
  // Leica10 (`:724`) — `LEICA CAMERA AG\0` signature, the %Panasonic::Main route.
  if blob.starts_with(b"LEICA CAMERA AG\x00") {
    return None;
  }
  if blob.starts_with(b"LEICA") {
    let b6 = blob.get(5).copied();
    let b7 = blob.get(6).copied();
    let b8 = blob.get(7).copied();
    // Leica2 (`:611`) — `^Leica Camera AG` make + `LEICA\0\0\0`.
    if ag_make && b6 == Some(0x00) && b7 == Some(0x00) && b8 == Some(0x00) {
      return Some(LeicaVariant::Leica2);
    }
    // Leica4 (`:639`) — `^Leica Camera AG` make + `LEICA0` (byte 5 = '0').
    if ag_make && b6 == Some(b'0') {
      return Some(LeicaVariant::Leica4);
    }
    // Leica5 (`:650`) — SIG-ONLY `LEICA\0[\x01\x04\x05\x06\x07\x10\x1a]\0`.
    if b6 == Some(0x00)
      && matches!(b7, Some(0x01 | 0x04 | 0x05 | 0x06 | 0x07 | 0x10 | 0x1a))
      && b8 == Some(0x00)
    {
      return Some(LeicaVariant::Leica5);
    }
    // Leica6 (`:666`) — make+model gated (S2 / M-Typ240 / S-Typ006), MUST precede
    // Leica7 in `%Main` order. Make is `eq` (exact).
    if make == "Leica Camera AG"
      && (model == "S2" || model == "LEICA M (Typ 240)" || model == "LEICA S (Typ 006)")
    {
      return Some(LeicaVariant::Leica6);
    }
    // Leica7 (`:690`) — SIG-ONLY `LEICA\0\x02\xff` → reuses the Leica6 table.
    if b6 == Some(0x00) && b7 == Some(0x02) && b8 == Some(0xff) {
      return Some(LeicaVariant::Leica6);
    }
    // Leica8 (`:703`) — SIG-ONLY `LEICA\0[\x08\x09\x0a]\0` → reuses the Leica5 table.
    if b6 == Some(0x00) && matches!(b7, Some(0x08 | 0x09 | 0x0a)) && b8 == Some(0x00) {
      return Some(LeicaVariant::Leica5);
    }
    // Leica9 (`:714`) — `^Leica Camera AG` make + `LEICA\0\x02\0`.
    if ag_make && b6 == Some(0x00) && b7 == Some(0x02) && b8 == Some(0x00) {
      return Some(LeicaVariant::Leica9);
    }
    // No generic LEICA fallback (faithful to bundled).
    return None;
  }
  // Leica3 (`:626`) — `^Leica Camera AG` make, NON-`LEICA` blob, Model not S2 /
  // M-Typ240. (Leica6's non-LEICA-blob make+model fallback is the %Panasonic
  // route's concern via the dispatcher; here a non-LEICA blob that satisfies
  // Leica3 lands on the Leica3 table.)
  if ag_make && !blob.starts_with(b"LEICA") && model != "S2" && model != "LEICA M (Typ 240)" {
    return Some(LeicaVariant::Leica3);
  }
  None
}

#[cfg(test)]
mod tests;
