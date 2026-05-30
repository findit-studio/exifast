// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Canon MakerNotes — Phase-2 port.
//!
//! Bundled source: `lib/Image/ExifTool/Canon.pm` —
//! `%Image::ExifTool::Canon::Main` (`Canon.pm:1221-2209`).
//!
//! ## Phase 2 scope
//!
//! - `Canon::Main` IFD ([`tags::CANON_TAGS`]) — every named LEAF tag
//!   (~78 entries) with simple PrintConv.
//! - `%canonLensTypes` lookup ([`lens_types::CANON_LENS_TYPES`]) —
//!   534 entries, sorted by `(key_int, key_frac)` for binary search.
//! - `%canonModelID` lookup ([`model_ids::CANON_MODEL_IDS`]) —
//!   357 entries, sorted by ID.
//! - `Canon::CameraSettings` binary sub-table
//!   ([`camera_settings::CAMERA_SETTINGS`]) — 37 named positions
//!   covering LensType / Max+MinFocalLength / FocalUnits / Max+MinAperture /
//!   MacroMode / FlashMode / DriveMode / FocusMode / ExposureMode / etc.
//! - `Canon::FocalLength` binary sub-table — FocalType + FocalLength
//!   (with FocalUnits scaling from CameraSettings).
//! - `Canon::FileInfo` binary sub-table ([`file_info::FILE_INFO`]) —
//!   BracketMode / BracketValue / BracketShotNumber / WBBracketMode /
//!   FilterEffect / ToningEffect / LiveViewShooting (model-agnostic
//!   subset; FileNumber/ShutterCount at position 1 are model-conditional
//!   and deferred).
//!
//! ## Deferred (Phase 2+1 follow-up)
//!
//! - `Canon::ShotInfo` (~70 tags) — ISO encoding via `Canon::CanonEv`,
//!   AF-info, sequence-number; file a follow-up issue.
//! - `Canon::AFInfo` + `Canon::AFInfo2` — AF point geometry; file
//!   follow-up.
//! - `Canon::ColorData1..12` — raw-color-processing sensor data; file
//!   the umbrella issue tagged from #62 (LOW indexing value).
//! - `Canon::CameraInfoXXX` per-model sub-tables (`Canon.pm:1307-1494`
//!   conditional list, ~40 model-specific tables) — defer; the high-
//!   value `CanonCameraSettings` already gives lens/focal/aperture.
//! - `Canon::CustomFunctions1`..`Functions5DmkIII` — body-config
//!   tables; defer.
//! - The complex per-model `FileNumber`/`ShutterCount` decode at
//!   `FileInfo[1]` (six conditional model variants) — defer.
//!
//! ## D8 compliance
//!
//! No public fields. Every accessor is `const fn` where possible.

pub mod body;
pub mod camera_settings;
pub mod file_info;
pub mod focal_length;
pub mod lens_types;
pub mod model_ids;
pub mod printconv;
pub mod tags;

use crate::exif::makernotes::VendorEmission;
use crate::value::{Group, Metadata, TagValue};
use smol_str::SmolStr;
use std::vec::Vec;

pub use body::{CanonEntry, walk_canon_body, walk_canon_in_tiff};
pub use camera_settings::CAMERA_SETTINGS;
pub use file_info::FILE_INFO;
pub use lens_types::{CANON_LENS_TYPES, CanonLensType};
pub use model_ids::{CANON_MODEL_IDS, CanonModelEntry};
pub use printconv::CanonPrintConv;
pub use tags::{CANON_TAGS, CanonTag, SubTable};

use super::super::super::ifd::{ByteOrder, RawValue};

/// Decoded Canon MakerNotes data — populated by [`parse`] when the
/// dispatcher resolved [`Vendor::Canon`](crate::exif::makernotes::Vendor).
///
/// D8: no public fields; accessor-only. `PartialEq` only because the
/// struct carries `(f64, f64)` for `focal_range_mm`; `f64` is not `Eq`.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct MakerNotesCanon {
  // ---- camera-identity (Phase 2 ship-bar) ----
  /// Canon Main 0x10 (`CanonModelID`) — the body identification ID
  /// (lookup against `%canonModelID`).
  model_id: Option<u32>,
  /// Resolved model name from `%canonModelID`.
  model_name: Option<SmolStr>,
  /// Canon Main 0x07 (`CanonFirmwareVersion`) — body firmware string.
  firmware_version: Option<SmolStr>,
  /// Canon Main 0x0c (`SerialNumber`) — body serial number.
  serial_number: Option<u64>,
  /// Canon Main 0x96 (`InternalSerialNumber`) — internal body S/N
  /// (different from the user-facing 0x0c serial).
  internal_serial_number: Option<SmolStr>,
  /// Canon Main 0x95 (`LensModel`) — EXIF-style lens model string when
  /// present (newer Canon bodies write this; older bodies use
  /// CameraSettings[22] LensType instead).
  lens_model_string: Option<SmolStr>,
  /// Canon Main 0x06 (`CanonImageType`) — short image-type identity
  /// string like "Canon EOS DIGITAL REBEL CMOS RAW".
  image_type: Option<SmolStr>,
  /// Canon Main 0x09 (`OwnerName`) — the body's user-set owner name.
  owner_name: Option<SmolStr>,
  // ---- lens-identity (CameraSettings) ----
  /// CameraSettings[22] (`LensType`) — the Canon LensID; lookup
  /// against `%canonLensTypes`.
  lens_type: Option<u16>,
  /// Resolved lens name (or `Unknown (N)` if not in the table).
  lens_name: Option<SmolStr>,
  /// CameraSettings[23,24] — Max/Min focal length in mm (after FocalUnits scaling).
  focal_range_mm: Option<(f64, f64)>,
  // ---- file identity ----
  /// Canon Main 0x08 (`FileNumber`) — body's image counter.
  file_number: Option<u32>,
  /// Canon Main 0x28 (`ImageUniqueID`) — 16-byte hex-encoded unique ID.
  image_unique_id: Option<SmolStr>,
}

impl MakerNotesCanon {
  /// Build an empty placeholder.
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {
      model_id: None,
      model_name: None,
      firmware_version: None,
      serial_number: None,
      internal_serial_number: None,
      lens_model_string: None,
      image_type: None,
      owner_name: None,
      lens_type: None,
      lens_name: None,
      focal_range_mm: None,
      file_number: None,
      image_unique_id: None,
    }
  }

  /// `CanonModelID` (`Canon.pm:1583-1589`) — `int32u`. Bundled looks
  /// up `%canonModelID` for a human name.
  #[must_use]
  #[inline(always)]
  pub const fn model_id(&self) -> Option<u32> {
    self.model_id
  }

  /// Resolved model name (from `%canonModelID`).
  #[must_use]
  #[inline]
  pub fn model_name(&self) -> Option<&str> {
    self.model_name.as_deref()
  }

  /// `CanonFirmwareVersion` (`Canon.pm:1256-1259`).
  #[must_use]
  #[inline]
  pub fn firmware_version(&self) -> Option<&str> {
    self.firmware_version.as_deref()
  }

  /// `SerialNumber` (`Canon.pm:1281-1306`) — raw int32u; the user-facing
  /// rendering depends on body model.
  #[must_use]
  #[inline(always)]
  pub const fn serial_number(&self) -> Option<u64> {
    self.serial_number
  }

  /// `InternalSerialNumber` (`Canon.pm:1835-1845`) — body-internal S/N.
  #[must_use]
  #[inline]
  pub fn internal_serial_number(&self) -> Option<&str> {
    self.internal_serial_number.as_deref()
  }

  /// EXIF-style `LensModel` (Canon Main 0x95) — written by newer bodies
  /// in addition to the CameraSettings LensType ID.
  #[must_use]
  #[inline]
  pub fn lens_model_string(&self) -> Option<&str> {
    self.lens_model_string.as_deref()
  }

  /// `CanonImageType` (`Canon.pm:1251-1255`).
  #[must_use]
  #[inline]
  pub fn image_type(&self) -> Option<&str> {
    self.image_type.as_deref()
  }

  /// `OwnerName` (`Canon.pm:1267-1273`).
  #[must_use]
  #[inline]
  pub fn owner_name(&self) -> Option<&str> {
    self.owner_name.as_deref()
  }

  /// Canon LensType ID (CameraSettings position 22).
  #[must_use]
  #[inline(always)]
  pub const fn lens_type(&self) -> Option<u16> {
    self.lens_type
  }

  /// Resolved lens name from `%canonLensTypes`. Prefer this over
  /// [`Self::lens_model_string`] for older bodies that don't write
  /// EXIF LensModel.
  #[must_use]
  #[inline]
  pub fn lens_name(&self) -> Option<&str> {
    self.lens_name.as_deref()
  }

  /// `(min_focal_mm, max_focal_mm)` from `CameraSettings[23,24]` scaled
  /// by `FocalUnits` (position 25).
  #[must_use]
  #[inline(always)]
  pub const fn focal_range_mm(&self) -> Option<(f64, f64)> {
    self.focal_range_mm
  }

  /// `FileNumber` (`Canon.pm:1260-1266`) — body image counter.
  #[must_use]
  #[inline(always)]
  pub const fn file_number(&self) -> Option<u32> {
    self.file_number
  }

  /// `ImageUniqueID` (`Canon.pm:1725-1734`).
  #[must_use]
  #[inline]
  pub fn image_unique_id(&self) -> Option<&str> {
    self.image_unique_id.as_deref()
  }
}

/// Parse a Canon MakerNote blob into a [`MakerNotesCanon`] + the
/// `(group, name, value)` emissions for the MakerNotes JSON sink.
///
/// This wrapper treats the blob as a stand-alone byte slice — out-of-
/// line offsets resolve against the blob itself. Use [`parse_in_tiff`]
/// when the caller has the surrounding TIFF block (the faithful
/// behaviour, since Canon's MakerNotes inherit the parent's `Base`).
#[must_use]
pub fn parse(blob: &[u8], parent_order: ByteOrder) -> (MakerNotesCanon, Vec<VendorEmission>) {
  parse_in_tiff(blob, 0, blob.len(), parent_order, true, None)
}

/// Parse with the parent TIFF context.
///
/// `tiff_data` is the parent TIFF block; `mn_offset` is the MakerNote
/// blob's position within `tiff_data`; `mn_len` is the blob length.
/// Out-of-line value offsets in the Canon IFD are TIFF-relative (Canon
/// inherits the parent `Base`). `model` is the parent body's
/// `$$self{Model}` (from IFD0), used to evaluate the FocalLength
/// FocalPlaneX/YSize `Condition` (`Canon.pm:2735-2739`).
#[must_use]
pub fn parse_in_tiff(
  tiff_data: &[u8],
  mn_offset: usize,
  mn_len: usize,
  parent_order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
) -> (MakerNotesCanon, Vec<VendorEmission>) {
  let mut typed = MakerNotesCanon::new();
  let mut emissions: Vec<VendorEmission> = Vec::new();
  let entries = body::walk_canon_in_tiff(tiff_data, mn_offset, mn_len, parent_order, model);
  // Pass 1: walk the Main IFD entries, surfacing leaves and dispatching
  // recognized binary sub-tables. We need to capture FocalUnits from
  // the CameraSettings sub-table (position 25) BEFORE we process the
  // FocalLength sub-table (which uses FocalUnits for scaling). So we
  // do this in TWO passes: first compute the FocalUnits hint by
  // dispatching CameraSettings, then process FocalLength with it.
  let mut focal_units: Option<u16> = None;
  let mut focal_length_data: Option<Vec<u8>> = None;
  // `$$self{LensType}` DataMember — set by CameraSettings position 22's
  // `RawConv => '$val ? $$self{LensType} = $val : undef'` (`Canon.pm:2503`).
  // FileInfo position 16 (`MacroMagnification`, `Canon.pm:6998-7005`) gates
  // on it (`$$self{LensType} == 124`). ExifTool resolves it during the
  // CameraSettings walk (Canon tag 0x01), which precedes FileInfo
  // (0x93) in IFD tag order; we capture it in this sub-pass so the
  // dependency holds regardless of IFD entry order.
  let mut lens_type: Option<u16> = None;
  // Sub-pass: find CameraSettings + FocalLength sub-table data first.
  for entry in &entries {
    let Some(def) = tags::lookup(entry.tag_id) else {
      continue;
    };
    let Some(sub) = def.sub_table() else { continue };
    if sub == SubTable::CameraSettings {
      focal_units = read_focal_units(&entry.value, parent_order);
      // Capture the `$$self{LensType}` DataMember (CameraSettings pos 22,
      // `Canon.pm:2503`) for FileInfo position 16's `Condition`.
      let blob_bytes = reserialize_int_array(&entry.value, parent_order);
      camera_settings::parse_with_lens_id_capture(
        &blob_bytes,
        parent_order,
        print_conv,
        &mut lens_type,
      );
    }
    if sub == SubTable::FocalLength {
      // Reserialize the int16u words into bytes for the sub-table parser.
      focal_length_data = Some(reserialize_int_array(&entry.value, parent_order));
    }
  }
  // Now do the main walk.
  for entry in &entries {
    let Some(def) = tags::lookup(entry.tag_id) else {
      continue; // Unknown tag — bundled would emit it under 'Tag 0xNNNN'; we omit.
    };
    // `Unknown => 1` tags (e.g. `0x3 CanonFlashInfo`, `Canon.pm:1239`) are
    // SUPPRESSED in the default (`-j`, no `-u`) output —
    // `ExifTool.pm:9179-9185` returns undef for them unless
    // `-u`/Verbose/HTML_DUMP/Validate is set. We no longer skip them at the
    // collection site: each leaf emission carries `def.is_unknown()` and the
    // emission engine drops the Unknown ones (the legacy `serialize_tags`
    // read-path filters them too). The single `Unknown` Canon::Main tag
    // (`0x03 CanonFlashInfo`) has no sub-table, so it reaches the leaf arm
    // below and is emitted with the flag set; no `Unknown` tag is a
    // typed-accessor source, so nothing else changes.
    if let Some(sub) = def.sub_table() {
      // SubDirectory tag: process the sub-table if Phase 2 handles it;
      // otherwise emit the SubDirectory tag's RAW bytes/name so the
      // caller can see it was present (faithful to ExifTool's verbose
      // output, but simplified — bundled would emit each sub-tag with
      // its own group; the port defers the sub-walk to a follow-up).
      match sub {
        SubTable::CameraSettings => {
          let blob_bytes = reserialize_int_array(&entry.value, parent_order);
          let mut lens_id: Option<u16> = None;
          let cs = camera_settings::parse_with_lens_id_capture(
            &blob_bytes,
            parent_order,
            print_conv,
            &mut lens_id,
          );
          // Capture focal range from the parsed CameraSettings results.
          let mut min_focal: Option<f64> = None;
          let mut max_focal: Option<f64> = None;
          for (n, v) in &cs {
            match n.as_str() {
              "MaxFocalLength" => {
                if let Some(mm) = focal_mm_from_tag_value(v) {
                  max_focal = Some(mm);
                }
              }
              "MinFocalLength" => {
                if let Some(mm) = focal_mm_from_tag_value(v) {
                  min_focal = Some(mm);
                }
              }
              _ => {}
            }
          }
          if let (Some(min), Some(max)) = (min_focal, max_focal) {
            typed.focal_range_mm = Some((min, max));
          }
          // Capture lens identity from the parsed CameraSettings.
          if let Some(id) = lens_id {
            typed.lens_type = Some(id);
            typed.lens_name = lens_types::lookup_name(id);
          }
          // Sub-table position tags are never `Unknown` (they are explicit
          // BinaryData positions), so each emits with `unknown = false`.
          for (name, value) in cs {
            emissions.push(VendorEmission::new(name, value, false));
          }
        }
        SubTable::FileInfo => {
          let blob_bytes = reserialize_int_array(&entry.value, parent_order);
          // Thread the `$$self{LensType}` DataMember (captured from
          // CameraSettings above) and `$$self{Model}` — both gate
          // FileInfo position 16 (`MacroMagnification`, `Canon.pm:7002-7005`).
          let fi = file_info::parse(&blob_bytes, parent_order, print_conv, lens_type, model);
          for (name, value) in fi {
            emissions.push(VendorEmission::new(name, value, false));
          }
        }
        SubTable::FocalLength => {
          if let Some(ref bytes) = focal_length_data {
            let fl = focal_length::parse(bytes, parent_order, print_conv, focal_units, model);
            for (name, value) in fl {
              emissions.push(VendorEmission::new(name, value, false));
            }
          }
        }
        _ => {
          // Deferred sub-table — emit the SubDirectory tag's raw value
          // so downstream users see "this sub-directory was present"
          // (Phase 2+1 will walk these). Carry the tag's `Unknown` flag.
          let val = def.conv().apply(&entry.value, print_conv, model);
          emissions.push(VendorEmission::new(
            def.name().into(),
            val,
            def.is_unknown(),
          ));
        }
      }
    } else if entry.tag_id == 0x96 && model.is_some_and(printconv::model_matches_eos_5d) {
      // `0x96` MODEL-CONDITIONAL LIST (`Canon.pm:1834-1846`): for an
      // EOS-5D body the FIRST arm wins — `SerialInfo`, a SubDirectory to
      // `Canon::SerialInfo`. That sub-table decode is DEFERRED (a deep
      // binary table, like ShotInfo/ColorData), so we emit it the SAME
      // way as the other deferred Canon::Main SubDirectories (the `_ =>`
      // arm above): the first-arm `Name` paired with the raw value
      // (`walk_canon_in_tiff` left it as un-stripped `RawValue::Bytes`).
      // CRITICALLY: this is NOT `InternalSerialNumber` and the
      // trailing-`0xff` `ValueConv` strip does NOT apply, so we also skip
      // `populate_typed` (the typed `internal_serial_number` stays unset).
      let val = CanonPrintConv::None.apply(&entry.value, print_conv, model);
      // `0x96` is not `Unknown` (it is the conditional SerialInfo/
      // InternalSerialNumber tag), so emit with `unknown = false`.
      emissions.push(VendorEmission::new("SerialInfo".into(), val, false));
    } else {
      // Leaf tag: apply PrintConv + emit. `model` threads the parent
      // body `$$self{Model}` into the conditional SerialNumber PrintConv
      // (`Canon.pm:1282-1306`). For non-EOS-5D bodies tag `0x96` falls
      // here as the LIST's SECOND arm, `InternalSerialNumber`
      // (`Canon.pm:1840-1845`) — the `0xff` strip already ran in
      // `walk_canon_in_tiff`.
      let val = def.conv().apply(&entry.value, print_conv, model);
      populate_typed(&mut typed, entry, &val);
      // Carry the tag's `Unknown` flag (the single Unknown Canon::Main tag,
      // `0x03 CanonFlashInfo`, lands here); the engine suppresses it.
      emissions.push(VendorEmission::new(
        def.name().into(),
        val,
        def.is_unknown(),
      ));
    }
  }
  (typed, emissions)
}

/// Emit Canon MakerNotes into a [`Metadata`] sink under the
/// `("MakerNotes","MakerNotes")` group. Uses the blob as a stand-alone
/// byte slice — for parent-TIFF-context resolution use [`parse_in_tiff`]
/// directly.
pub fn parse_into_metadata(
  blob: &[u8],
  parent_order: ByteOrder,
  print_conv: bool,
  into: &mut Metadata,
) {
  let group = Group::new("MakerNotes", "MakerNotes");
  // Standalone-blob entry point — no parent `$$self{Model}` context, so
  // the FocalPlaneX/YSize `Condition` evaluates as for an undef Model.
  let (_typed, emissions) = parse_in_tiff(blob, 0, blob.len(), parent_order, print_conv, None);
  for e in emissions {
    // Unknown-suppression is the engine's job; this raw `Metadata`-sink
    // helper applies it inline so it matches the default-output contract.
    if e.unknown() {
      continue;
    }
    into.push(group.clone(), e.name(), e.value().clone());
  }
}

/// Populate the typed struct from one Main-IFD leaf-tag emission.
fn populate_typed(typed: &mut MakerNotesCanon, entry: &CanonEntry, val: &TagValue) {
  match entry.tag_id {
    0x06 => {
      if let RawValue::Text(s) = &entry.value {
        typed.image_type = Some(s.as_str().into());
      }
    }
    0x07 => {
      if let RawValue::Text(s) = &entry.value {
        typed.firmware_version = Some(s.as_str().into());
      }
    }
    0x08 => {
      if let RawValue::U64(v) = &entry.value
        && let Some(&n) = v.first()
      {
        typed.file_number = Some(n as u32);
      }
    }
    0x09 => {
      if let RawValue::Text(s) = &entry.value {
        typed.owner_name = Some(s.as_str().into());
      }
    }
    0x0c => {
      if let RawValue::U64(v) = &entry.value
        && let Some(&n) = v.first()
      {
        typed.serial_number = Some(n);
      }
    }
    0x10 => {
      if let RawValue::U64(v) = &entry.value
        && let Some(&n) = v.first()
      {
        let id = n as u32;
        typed.model_id = Some(id);
        typed.model_name = model_ids::lookup_name(id);
      }
    }
    0x28 => {
      // ImageUniqueID — undef[16]; PrintConv emits hex.
      if let TagValue::Str(s) = val {
        typed.image_unique_id = Some(s.clone());
      }
    }
    0x95 => {
      if let RawValue::Text(s) = &entry.value {
        typed.lens_model_string = Some(s.as_str().into());
      }
    }
    0x96 => {
      if let RawValue::Text(s) = &entry.value {
        typed.internal_serial_number = Some(s.as_str().into());
      }
    }
    _ => {}
  }
}

/// Extract a focal-length-in-mm from a TagValue (e.g. `"55 mm"` ⇒ 55.0).
fn focal_mm_from_tag_value(v: &TagValue) -> Option<f64> {
  match v {
    TagValue::Str(s) => {
      let trimmed = s.trim_end_matches(" mm");
      trimmed.parse::<f64>().ok()
    }
    TagValue::F64(f) => Some(*f),
    TagValue::I64(n) => Some(*n as f64),
    TagValue::U64(n) => Some(*n as f64),
    _ => None,
  }
}

/// Read FocalUnits from a CameraSettings RawValue (the entry value
/// before sub-table parsing). Returns `None` if the words are absent.
fn read_focal_units(raw: &RawValue, parent_order: ByteOrder) -> Option<u16> {
  // The CameraSettings entry value is stored as a list of int16s words
  // (RawValue::I64) OR as raw bytes; reserialize to bytes and read
  // position 25 directly.
  let bytes = reserialize_int_array(raw, parent_order);
  if bytes.len() < 2 * 26 {
    return None;
  }
  let pos = 2 * 25;
  let arr: [u8; 2] = [bytes[pos], bytes[pos + 1]];
  let raw_int = match parent_order {
    ByteOrder::Little => i16::from_le_bytes(arr),
    ByteOrder::Big => i16::from_be_bytes(arr),
  };
  if raw_int <= 0 {
    None
  } else {
    Some(raw_int as u16)
  }
}

/// Reserialize a RawValue (int16s/int16u/Bytes) back into bytes in the
/// parent IFD's byte order. The CameraSettings/FileInfo/FocalLength
/// sub-table parsers want the BYTE blob (`$$valPt`), not the decoded
/// `i64` array — bundled `ProcessBinaryData` reads bytes too.
fn reserialize_int_array(raw: &RawValue, order: ByteOrder) -> Vec<u8> {
  match raw {
    RawValue::I64(words) => {
      let mut out = Vec::with_capacity(words.len() * 2);
      for &w in words {
        let w16 = w as i16;
        let bytes = match order {
          ByteOrder::Little => w16.to_le_bytes(),
          ByteOrder::Big => w16.to_be_bytes(),
        };
        out.extend_from_slice(&bytes);
      }
      out
    }
    RawValue::U64(words) => {
      let mut out = Vec::with_capacity(words.len() * 2);
      for &w in words {
        let w16 = w as u16;
        let bytes = match order {
          ByteOrder::Little => w16.to_le_bytes(),
          ByteOrder::Big => w16.to_be_bytes(),
        };
        out.extend_from_slice(&bytes);
      }
      out
    }
    RawValue::Bytes(b) => b.clone(),
    _ => Vec::new(),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Synthetic Canon body with one Main entry (CanonImageType, ASCII).
  ///
  /// Layout: 2 bytes count, then one 12-byte entry. For out-of-line
  /// values the offset is 14 (just after the entry) and the value
  /// bytes follow. For inline values the entry's last 4 bytes hold
  /// the value.
  fn one_main_entry_blob(tag: u16, format: u16, count: u32, value_bytes: &[u8]) -> Vec<u8> {
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(&[0x01, 0x00]); // 1 entry LE
    blob.extend_from_slice(&tag.to_le_bytes());
    blob.extend_from_slice(&format.to_le_bytes());
    blob.extend_from_slice(&count.to_le_bytes());
    // Element sizes by TIFF format code (index 0 unused; codes 1-13).
    let elem_sizes: [usize; 14] = [0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8, 4];
    let elem_size = if (format as usize) < elem_sizes.len() {
      elem_sizes[format as usize]
    } else {
      1
    };
    let total = elem_size * count as usize;
    if total <= 4 {
      let mut padded = std::vec![0u8; 4];
      padded[..value_bytes.len()].copy_from_slice(value_bytes);
      blob.extend_from_slice(&padded);
    } else {
      // Out-of-line: data sits at offset 14 (right after the entry).
      blob.extend_from_slice(&(14u32).to_le_bytes());
      blob.extend_from_slice(value_bytes);
    }
    blob
  }

  #[test]
  fn parse_canon_image_type_inline() {
    let value = b"Canon EOS\x00";
    let blob = one_main_entry_blob(0x06, 0x02, value.len() as u32, value);
    let (typed, emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(typed.image_type(), Some("Canon EOS"));
    assert!(emissions.iter().any(|e| e.name() == "CanonImageType"));
  }

  #[test]
  fn parse_canon_model_id_resolves_against_model_table() {
    // CanonModelID = 0x1140000 → "EOS D30"
    let blob = one_main_entry_blob(0x10, 0x04, 1, &(0x1140000u32).to_le_bytes());
    let (typed, emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(typed.model_id(), Some(0x1140000));
    assert_eq!(typed.model_name(), Some("EOS D30"));
    let v = emissions
      .iter()
      .find(|e| e.name() == "CanonModelID")
      .map(|e| e.value().clone())
      .unwrap();
    assert_eq!(v, TagValue::Str("EOS D30".into()));
  }

  #[test]
  fn parse_canon_firmware_version_string() {
    let value = b"1.0.1\x00";
    let blob = one_main_entry_blob(0x07, 0x02, value.len() as u32, value);
    let (typed, _emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(typed.firmware_version(), Some("1.0.1"));
  }

  #[test]
  fn parse_canon_serial_number() {
    let blob = one_main_entry_blob(0x0c, 0x04, 1, &(560018150u32).to_le_bytes());
    let (typed, emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(typed.serial_number(), Some(560018150));
    // PrintConv pads to 10 digits (default branch, no Model context).
    let v = emissions
      .iter()
      .find(|e| e.name() == "SerialNumber")
      .map(|e| e.value().clone())
      .unwrap();
    assert_eq!(v, TagValue::Str("0560018150".into()));
  }

  /// The model-conditional SerialNumber (`Canon.pm:1282-1306`) threads
  /// `$$self{Model}` through `parse_in_tiff` → leaf-tag `apply`. An
  /// `EOS-1D` body uses `sprintf("%.6u", $val)`.
  #[test]
  fn parse_canon_serial_number_eos_1d_uses_model() {
    let blob = one_main_entry_blob(0x0c, 0x04, 1, &(500292u32).to_le_bytes());
    let (_typed, emissions) = parse_in_tiff(
      &blob,
      0,
      blob.len(),
      ByteOrder::Little,
      true,
      Some("Canon EOS-1D Mark IV"),
    );
    let v = emissions
      .iter()
      .find(|e| e.name() == "SerialNumber")
      .map(|e| e.value().clone())
      .unwrap();
    assert_eq!(v, TagValue::Str("500292".into()));
  }

  #[test]
  fn parse_canon_file_number() {
    let blob = one_main_entry_blob(0x08, 0x04, 1, &(1181861u32).to_le_bytes());
    let (typed, emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(typed.file_number(), Some(1181861));
    let v = emissions
      .iter()
      .find(|e| e.name() == "FileNumber")
      .map(|e| e.value().clone())
      .unwrap();
    assert_eq!(v, TagValue::Str("118-1861".into()));
  }

  /// End-to-end `0x96` InternalSerialNumber (`Canon.pm:1841-1845`): the
  /// trailing-`0xff` strip is reflected in BOTH the typed accessor and
  /// the MakerNotes emission, with no U+FFFD leakage (Kiss X3).
  #[test]
  fn parse_internal_serial_number_strips_trailing_ff() {
    let value = b"ABC123\xff\xff\xff";
    let blob = one_main_entry_blob(0x96, 0x02, value.len() as u32, value);
    let (typed, emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(typed.internal_serial_number(), Some("ABC123"));
    let v = emissions
      .iter()
      .find(|e| e.name() == "InternalSerialNumber")
      .map(|e| e.value().clone())
      .unwrap();
    assert_eq!(v, TagValue::Str("ABC123".into()));
  }

  /// A clean `0x96` value passes through unchanged end-to-end.
  #[test]
  fn parse_internal_serial_number_clean_unchanged() {
    let value = b"H1234567";
    let blob = one_main_entry_blob(0x96, 0x02, value.len() as u32, value);
    let (typed, _emissions) = parse(&blob, ByteOrder::Little);
    assert_eq!(typed.internal_serial_number(), Some("H1234567"));
  }

  /// `0x96` MODEL-CONDITIONAL LIST (`Canon.pm:1834-1846`), FIRST arm: an
  /// EOS-5D body routes `0x96` to the `SerialInfo` SubDirectory (deferred
  /// raw blob), NOT `InternalSerialNumber`. The trailing-`0xff` strip
  /// MUST NOT apply, and the typed `internal_serial_number` stays unset.
  #[test]
  fn parse_eos_5d_0x96_emits_serialinfo_not_internal_serial() {
    let value = b"ABC123\xff\xff\xff";
    let blob = one_main_entry_blob(0x96, 0x02, value.len() as u32, value);
    let (typed, emissions) = parse_in_tiff(
      &blob,
      0,
      blob.len(),
      ByteOrder::Little,
      true,
      Some("Canon EOS 5D Mark II"),
    );
    // First arm: SerialInfo, raw (un-stripped) blob.
    assert!(
      !emissions.iter().any(|e| e.name() == "InternalSerialNumber"),
      "EOS 5D must NOT emit InternalSerialNumber"
    );
    let v = emissions
      .iter()
      .find(|e| e.name() == "SerialInfo")
      .map(|e| e.value().clone())
      .expect("EOS 5D must emit SerialInfo");
    assert_eq!(v, TagValue::Bytes(value.to_vec()));
    // Typed accessor for InternalSerialNumber stays unset.
    assert_eq!(typed.internal_serial_number(), None);
  }

  /// `/EOS 5D/` is an UNANCHORED substring (`Canon.pm:1837`) — base
  /// "EOS 5D" matches just as "EOS 5D Mark IV" does.
  #[test]
  fn parse_eos_5d_base_model_0x96_emits_serialinfo() {
    let value = b"WXYZ";
    let blob = one_main_entry_blob(0x96, 0x02, value.len() as u32, value);
    let (typed, emissions) = parse_in_tiff(
      &blob,
      0,
      blob.len(),
      ByteOrder::Little,
      true,
      Some("Canon EOS 5D"),
    );
    assert!(emissions.iter().any(|e| e.name() == "SerialInfo"));
    assert!(!emissions.iter().any(|e| e.name() == "InternalSerialNumber"));
    assert_eq!(typed.internal_serial_number(), None);
  }

  /// `0x96` SECOND arm for a NON-EOS-5D body (e.g. Kiss X3 / EOS 50D):
  /// `InternalSerialNumber` with the trailing-`0xff` strip applied.
  #[test]
  fn parse_non_5d_0x96_emits_internal_serial_stripped() {
    let value = b"ABC123\xff\xff\xff";
    let blob = one_main_entry_blob(0x96, 0x02, value.len() as u32, value);
    let (typed, emissions) = parse_in_tiff(
      &blob,
      0,
      blob.len(),
      ByteOrder::Little,
      true,
      Some("Canon EOS 50D"),
    );
    assert!(!emissions.iter().any(|e| e.name() == "SerialInfo"));
    assert_eq!(typed.internal_serial_number(), Some("ABC123"));
    let v = emissions
      .iter()
      .find(|e| e.name() == "InternalSerialNumber")
      .map(|e| e.value().clone())
      .unwrap();
    assert_eq!(v, TagValue::Str("ABC123".into()));
  }

  /// Model ABSENT → fall back to `InternalSerialNumber` (the LIST's
  /// model-agnostic second arm), strip applied.
  #[test]
  fn parse_model_absent_0x96_emits_internal_serial() {
    let value = b"ABC123\xff";
    let blob = one_main_entry_blob(0x96, 0x02, value.len() as u32, value);
    let (typed, emissions) = parse(&blob, ByteOrder::Little);
    assert!(!emissions.iter().any(|e| e.name() == "SerialInfo"));
    assert_eq!(typed.internal_serial_number(), Some("ABC123"));
    assert!(emissions.iter().any(|e| e.name() == "InternalSerialNumber"));
  }

  #[test]
  fn empty_blob_yields_empty() {
    let (typed, emissions) = parse(&[], ByteOrder::Little);
    assert_eq!(typed, MakerNotesCanon::new());
    assert!(emissions.is_empty());
  }
}
