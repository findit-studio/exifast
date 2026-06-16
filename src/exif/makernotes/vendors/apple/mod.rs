// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Apple iOS MakerNotes — Phase-2 port.
//!
//! Bundled source: `lib/Image/ExifTool/Apple.pm` —
//! `%Image::ExifTool::Apple::Main` (`Apple.pm:24-320`).
//!
//! ## Phase 2 scope
//!
//! - The Apple body walker ([`body::walk_apple_body`]) — strips the
//!   14-byte `Apple iOS\0\0\x01MM` header, reads the body's `MM`/`II`
//!   marker, walks the IFD entries.
//! - The faithful tag table ([`tags::APPLE_TAGS`]) — every named tag
//!   from `%Apple::Main` with a clean Format. The `ConvertPLIST`
//!   ValueConv tags emit raw bytes (Phase 2 forward-item: a follow-up
//!   issue tracks porting `Image::ExifTool::PLIST::ProcessBinaryPLIST`).
//! - Per-tag PrintConv ([`printconv::ApplePrintConv`]) — the named
//!   PrintConv hashes from bundled (NoYes, HDRImageType,
//!   ImageCaptureType, CameraType) plus the inline sprintf expressions
//!   (FocusDistanceRange, AFPerformance).
//! - A typed [`MakerNotesApple`] struct (formerly `AppleMakerNote`) with
//!   D8 accessors over the parsed fields — Make/Model upstream from the
//!   parent Exif IFD; this struct surfaces Apple-specific identity
//!   (HDR type, image-capture type, content/burst/image-unique IDs,
//!   camera type, software version through `OISMode`, focus/AE state).
//!
//! ## D8 compliance
//!
//! No public fields; every accessor is `const fn` where possible.
//! `#[non_exhaustive]` so a future Phase 2-bis can add fields without a
//! breaking change to downstream `match` arms.

#![deny(clippy::indexing_slicing)]

pub mod body;
pub mod printconv;
pub mod tags;

use crate::exif::makernotes::VendorEmission;
use crate::value::{Group, Metadata};
use smol_str::SmolStr;
use std::vec::Vec;

pub use body::{AppleEntry, ParsedValue, walk_apple_body};
pub use printconv::ApplePrintConv;
pub use tags::{APPLE_TAGS, AppleTag, lookup};

use super::super::super::ifd::{ByteOrder, RawValue};

/// Decoded Apple iOS MakerNotes data — populated by [`parse`] when the
/// dispatcher resolved [`Vendor::Apple`](crate::exif::makernotes::Vendor).
///
/// D8: no public fields; accessor-only. `PartialEq` only (NOT `Eq`)
/// because the struct carries `f64` fields (Apple's `AccelerationVector`
/// and `FocusDistanceRange`); `f64` is not `Eq` (NaN-vs-NaN).
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct MakerNotesApple {
  // ---- camera-identity hints (Phase 2 ship-bar) ----
  /// `MakerNoteVersion` (tag 0x0001) — `int32s`. Apple internal
  /// versioning for the MakerNote schema; useful as an identity-shard.
  maker_note_version: Option<i64>,
  /// `CameraType` (tag 0x002e) — back/front/wide-angle. Useful for
  /// scene-classification in indexing.
  camera_type: Option<i64>,
  /// `HDRImageType` (tag 0x000a) — HDR-flag for image grouping.
  hdr_image_type: Option<i64>,
  /// `ImageCaptureType` (tag 0x0014) — ProRAW/Portrait/Photo distinction.
  image_capture_type: Option<i64>,
  // ---- cross-image grouping IDs ----
  /// `BurstUUID` (tag 0x000b) — shared across all images in a burst.
  burst_uuid: Option<SmolStr>,
  /// `ContentIdentifier` (tag 0x0011) — Live-Photo link to the video.
  content_identifier: Option<SmolStr>,
  /// `ImageUniqueID` (tag 0x0015) — Apple-internal-unique image ID.
  image_unique_id: Option<SmolStr>,
  // ---- capture metadata ----
  /// `AccelerationVector` (tag 0x0008) — 3-rational orientation hint.
  acceleration_vector: Option<(f64, f64, f64)>,
  /// `FocusDistanceRange` (tag 0x000c) — `(near_m, far_m)`.
  focus_distance_range: Option<(f64, f64)>,
  /// `ColorTemperature` (tag 0x002d) — Kelvin.
  color_temperature: Option<i64>,
  /// `HDRHeadroom` (tag 0x0021) — rational stop-margin for HDR.
  hdr_headroom: Option<(i64, i64)>,
  /// `OISMode` (tag 0x000f) — optical-image-stabilization mode hint.
  ois_mode: Option<i64>,
}

impl MakerNotesApple {
  /// Build an empty Apple metadata bag. Phase 2's [`parse`] populates
  /// the per-tag fields.
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {
      maker_note_version: None,
      camera_type: None,
      hdr_image_type: None,
      image_capture_type: None,
      burst_uuid: None,
      content_identifier: None,
      image_unique_id: None,
      acceleration_vector: None,
      focus_distance_range: None,
      color_temperature: None,
      hdr_headroom: None,
      ois_mode: None,
    }
  }

  /// `MakerNoteVersion` — Apple's internal MakerNote schema version
  /// (`Apple.pm:30-33`, int32s).
  #[must_use]
  #[inline(always)]
  pub const fn maker_note_version(&self) -> Option<i64> {
    self.maker_note_version
  }

  /// `CameraType` (`Apple.pm:221-229`). 0 = Back Wide Angle, 1 = Back
  /// Normal, 6 = Front.
  #[must_use]
  #[inline(always)]
  pub const fn camera_type(&self) -> Option<i64> {
    self.camera_type
  }

  /// `CameraType` rendered as a PrintConv label.
  #[must_use]
  pub fn camera_type_label(&self) -> Option<&'static str> {
    Some(match self.camera_type? {
      0 => "Back Wide Angle",
      1 => "Back Normal",
      6 => "Front",
      _ => return None,
    })
  }

  /// `HDRImageType` (`Apple.pm:80-88`). 3 = HDR Image, 4 = Original.
  #[must_use]
  #[inline(always)]
  pub const fn hdr_image_type(&self) -> Option<i64> {
    self.hdr_image_type
  }

  /// `ImageCaptureType` (`Apple.pm:122-133`). 1=ProRAW, 2=Portrait,
  /// 10=Photo, 11=Manual Focus, 12=Scene.
  #[must_use]
  #[inline(always)]
  pub const fn image_capture_type(&self) -> Option<i64> {
    self.image_capture_type
  }

  /// `BurstUUID` (`Apple.pm:89-93`) — shared across burst-mode shots.
  #[must_use]
  #[inline]
  pub fn burst_uuid(&self) -> Option<&str> {
    self.burst_uuid.as_deref()
  }

  /// `ContentIdentifier` (`Apple.pm:112-119`) — Live-Photo grouping.
  #[must_use]
  #[inline]
  pub fn content_identifier(&self) -> Option<&str> {
    self.content_identifier.as_deref()
  }

  /// `ImageUniqueID` (`Apple.pm:134-137`) — Apple's internal unique ID.
  #[must_use]
  #[inline]
  pub fn image_unique_id(&self) -> Option<&str> {
    self.image_unique_id.as_deref()
  }

  /// `AccelerationVector` (`Apple.pm:62-78`). `(x, y, z)` in units of g.
  #[must_use]
  #[inline(always)]
  pub const fn acceleration_vector(&self) -> Option<(f64, f64, f64)> {
    self.acceleration_vector
  }

  /// `FocusDistanceRange` (`Apple.pm:94-103`) — `(near_m, far_m)`.
  #[must_use]
  #[inline(always)]
  pub const fn focus_distance_range(&self) -> Option<(f64, f64)> {
    self.focus_distance_range
  }

  /// `ColorTemperature` (`Apple.pm:216-219`) — Kelvin.
  #[must_use]
  #[inline(always)]
  pub const fn color_temperature(&self) -> Option<i64> {
    self.color_temperature
  }

  /// `HDRHeadroom` (`Apple.pm:174-177`) — `(numerator, denominator)`.
  #[must_use]
  #[inline(always)]
  pub const fn hdr_headroom(&self) -> Option<(i64, i64)> {
    self.hdr_headroom
  }

  /// `OISMode` (`Apple.pm:106-110`) — optical-image-stabilization mode.
  #[must_use]
  #[inline(always)]
  pub const fn ois_mode(&self) -> Option<i64> {
    self.ois_mode
  }
}

/// Parse the captured Apple MakerNote blob into a [`MakerNotesApple`]
/// plus the (group, name, value) triples for the `MakerNotes:` JSON
/// group.
///
/// `blob` is the raw 0x927C value; `parent_order` is the parent IFD
/// walk's byte order (used as the body-marker-fallback per
/// [`super::super::byte_order::resolve_child_byte_order`]). `make` is the
/// parent IFD0 `Make` — threaded into the body walker so the format-16
/// (`int64u`) Apple carve-out gates on `Make eq 'Apple'` exactly
/// (`Exif.pm:6464`); pass the captured IFD0 Make (`None` if unknown, which
/// then rejects code 16 like any non-Apple Make).
///
/// Returns `(typed, emissions)` — the typed struct + the ordered
/// [`VendorEmission`] list (each carrying the `Unknown => 1` flag) for the
/// emission engine.
#[must_use]
pub fn parse(
  blob: &[u8],
  parent_order: ByteOrder,
  make: Option<&str>,
) -> (MakerNotesApple, Vec<VendorEmission>) {
  parse_with_print_conv(blob, parent_order, true, make)
}

/// Like [`parse`] but lets the caller toggle PrintConv (`-n` mode emits
/// the post-ValueConv raw scalar; the typed struct is the same either
/// way). `make` is the parent IFD0 `Make`, threaded into the body walker for
/// the `Make eq 'Apple'` format-16 carve-out gate (`Exif.pm:6464`).
#[must_use]
pub fn parse_with_print_conv(
  blob: &[u8],
  parent_order: ByteOrder,
  print_conv: bool,
  make: Option<&str>,
) -> (MakerNotesApple, Vec<VendorEmission>) {
  let mut typed = MakerNotesApple::new();
  let mut emissions: Vec<VendorEmission> = Vec::new();
  if blob.len() < 14 {
    return (typed, emissions);
  }
  let entries = body::walk_apple_body(blob, 14, parent_order, make);
  for entry in &entries {
    let Some(def) = tags::lookup(entry.tag_id) else {
      continue;
    };
    // Render the value with the per-tag PrintConv and emit it WITH the
    // `Unknown => 1` flag (`Apple.pm`). Unknown-suppression is the emission
    // engine's job (`ExifTool.pm:9179-9185` returns undef for Unknown tags
    // unless `-u`/Verbose/HTML_DUMP/Validate) — carried here, dropped there,
    // so no per-vendor `if def.is_unknown() { continue; }`. The typed
    // accessors are not populated from any Unknown tag, so nothing else
    // depends on the old skip.
    let value = def.conv().apply(entry.value.raw(), print_conv);
    emissions.push(VendorEmission::new(
      def.name().into(),
      value,
      def.is_unknown(),
    ));
    populate_typed(&mut typed, entry);
  }
  (typed, emissions)
}

/// Mirror of [`parse_with_print_conv`] that emits straight into a
/// [`Metadata`] sink under the `("MakerNotes","MakerNotes")` group —
/// used by the engine when emitting Apple tags into the JSON document.
pub fn parse_into_metadata(
  blob: &[u8],
  parent_order: ByteOrder,
  print_conv: bool,
  make: Option<&str>,
  into: &mut Metadata,
) {
  let group = Group::new("MakerNotes", "MakerNotes");
  let (_typed, emissions) = parse_with_print_conv(blob, parent_order, print_conv, make);
  for e in emissions {
    // Unknown-suppression is the engine's job; this raw `Metadata`-sink
    // helper applies it inline so it matches the default-output contract.
    if e.unknown() {
      continue;
    }
    into.push(group.clone(), e.name(), e.value().clone());
  }
}

/// Populate the typed struct with the parsed value for `entry`. Only
/// the tags surfaced via accessor on [`MakerNotesApple`] are routed
/// here; other tags surface only via the emissions list.
fn populate_typed(typed: &mut MakerNotesApple, entry: &AppleEntry) {
  populate_typed_value(typed, entry.tag_id, entry.value.raw());
}

/// Populate the typed struct from a `(tag_id, value)` pair — the per-tag
/// routing the oracle ([`populate_typed`]) and the shared-`Walker` isolated
/// path ([`crate::exif::apple_makernote_isolated`]) BOTH call, so the typed
/// surface is single-sourced (#243 phase 3). Only the tags surfaced via
/// accessor on [`MakerNotesApple`] are routed here; other tags surface only
/// via the emissions list.
pub fn populate_typed_value(typed: &mut MakerNotesApple, tag_id: u16, value: &RawValue) {
  match tag_id {
    0x0001 => {
      typed.maker_note_version = value.first_i64();
    }
    0x002e => {
      typed.camera_type = value.first_i64();
    }
    0x000a => {
      typed.hdr_image_type = value.first_i64();
    }
    0x0014 => {
      typed.image_capture_type = value.first_i64();
    }
    0x000b => {
      if let RawValue::Text { text: s, .. } = value {
        typed.burst_uuid = Some(s.as_str().into());
      }
    }
    0x0011 => {
      if let RawValue::Text { text: s, .. } = value {
        typed.content_identifier = Some(s.as_str().into());
      }
    }
    0x0015 => {
      if let RawValue::Text { text: s, .. } = value {
        typed.image_unique_id = Some(s.as_str().into());
      }
    }
    0x0008 => {
      // `[r0, r1, r2, ..]` matches len ≥ 3 and binds the first three — the
      // checked form is byte-identical to the `rs.len() >= 3` guard + `rs[0..2]`.
      if let RawValue::Rational(rs) = value
        && let [r0, r1, r2, ..] = rs.as_slice()
      {
        let x = rational_f64(r0);
        let y = rational_f64(r1);
        let z = rational_f64(r2);
        if let (Some(x), Some(y), Some(z)) = (x, y, z) {
          typed.acceleration_vector = Some((x, y, z));
        }
      }
    }
    0x000c => {
      // `[r0, r1, ..]` matches len ≥ 2 and binds the first two — the checked
      // form is byte-identical to the `rs.len() >= 2` guard + `rs[0..1]`.
      if let RawValue::Rational(rs) = value
        && let [r0, r1, ..] = rs.as_slice()
      {
        let a = rational_f64(r0);
        let b = rational_f64(r1);
        if let (Some(a), Some(b)) = (a, b) {
          let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
          typed.focus_distance_range = Some((lo, hi));
        }
      }
    }
    0x002d => {
      typed.color_temperature = value.first_i64();
    }
    0x0021 => {
      if let RawValue::Rational(rs) = value
        && let Some(r) = rs.first()
      {
        typed.hdr_headroom = Some((r.numerator(), r.denominator()));
      }
    }
    0x000f => {
      typed.ois_mode = value.first_i64();
    }
    _ => {}
  }
}

fn rational_f64(r: &crate::value::Rational) -> Option<f64> {
  if r.denominator() == 0 {
    return None;
  }
  Some(r.numerator() as f64 / r.denominator() as f64)
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C S2); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;
  use crate::value::TagValue;

  /// Build a 1-entry Apple MakerNote blob with the given tag.
  fn one_entry_blob(tag_id: u16, format_code: u16, count: u32, value_bytes: [u8; 4]) -> Vec<u8> {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"Apple iOS\x00\x00\x01MM");
    blob.extend_from_slice(b"MM");
    blob.extend_from_slice(&[0x00, 0x01]); // 1 entry
    blob.extend_from_slice(&tag_id.to_be_bytes());
    blob.extend_from_slice(&format_code.to_be_bytes());
    blob.extend_from_slice(&count.to_be_bytes());
    blob.extend_from_slice(&value_bytes);
    blob
  }

  #[test]
  fn parse_makernoteversion_populates_typed() {
    // int32s = format code 9, count 1, value 4
    let blob = one_entry_blob(0x0001, 0x0009, 1, [0x00, 0x00, 0x00, 0x04]);
    let (typed, emissions) = parse(&blob, ByteOrder::Big, Some("Apple"));
    assert_eq!(typed.maker_note_version(), Some(4));
    assert_eq!(emissions.len(), 1);
    assert_eq!(emissions[0].name(), "MakerNoteVersion");
    assert_eq!(emissions[0].value(), &TagValue::I64(4));
  }

  #[test]
  fn parse_hdr_image_type_print_conv() {
    let blob = one_entry_blob(0x000a, 0x0009, 1, [0x00, 0x00, 0x00, 0x03]); // 3 = HDR Image
    let (typed, emissions) = parse(&blob, ByteOrder::Big, Some("Apple"));
    assert_eq!(typed.hdr_image_type(), Some(3));
    assert_eq!(emissions.len(), 1);
    assert_eq!(emissions[0].value(), &TagValue::Str("HDR Image".into()));
  }

  #[test]
  fn parse_camera_type_print_conv() {
    let blob = one_entry_blob(0x002e, 0x0009, 1, [0x00, 0x00, 0x00, 0x00]); // 0 = Back Wide Angle
    let (typed, emissions) = parse(&blob, ByteOrder::Big, Some("Apple"));
    assert_eq!(typed.camera_type(), Some(0));
    assert_eq!(typed.camera_type_label(), Some("Back Wide Angle"));
    assert_eq!(
      emissions[0].value(),
      &TagValue::Str("Back Wide Angle".into())
    );
  }

  #[test]
  fn parse_unknown_image_capture_type_renders_unknown_label() {
    let blob = one_entry_blob(0x0014, 0x0009, 1, [0x00, 0x00, 0x00, 0x05]); // 5 = unknown
    let (typed, emissions) = parse(&blob, ByteOrder::Big, Some("Apple"));
    assert_eq!(typed.image_capture_type(), Some(5));
    assert_eq!(emissions[0].value(), &TagValue::Str("Unknown (5)".into()));
  }

  #[test]
  fn parse_with_print_conv_off_emits_raw_int() {
    let blob = one_entry_blob(0x000a, 0x0009, 1, [0x00, 0x00, 0x00, 0x03]);
    let (_typed, emissions) = parse_with_print_conv(&blob, ByteOrder::Big, false, Some("Apple"));
    assert_eq!(emissions[0].value(), &TagValue::I64(3));
  }

  #[test]
  fn empty_blob_yields_empty() {
    let (typed, emissions) = parse(&[], ByteOrder::Big, Some("Apple"));
    assert_eq!(typed, MakerNotesApple::new());
    assert!(emissions.is_empty());
  }

  #[test]
  fn too_short_blob_yields_empty() {
    let (typed, emissions) = parse(b"Apple iOS\x00", ByteOrder::Big, Some("Apple"));
    assert_eq!(typed, MakerNotesApple::new());
    assert!(emissions.is_empty());
  }
}
