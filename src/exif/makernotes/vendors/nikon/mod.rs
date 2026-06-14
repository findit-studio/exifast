// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Nikon MakerNotes — `%Image::ExifTool::Nikon::Main` (`Nikon.pm:1778`) +
//! `%Image::ExifTool::Nikon::Type2` (`Nikon.pm:5369`) port.
//!
//! The dispatcher ([`crate::exif::makernotes::dispatch`]) classifies the three
//! Nikon MakerNote layouts (type-3 `"Nikon\0\x02"`, type-2 `"Nikon\0\x01"`,
//! headerless Nikon3 `Make =~ /^NIKON/i`); this module parses the body of
//! whichever layout matched, walks the IFD against the layout-selected tag
//! table ([`NikonTable`]: `%Nikon::Main` for type-3 / headerless,
//! `%Nikon::Type2` for the old type-2 layout, `MakerNotes.pm:537-554`), and
//! emits the readable tags under the `MakerNotes:Nikon` group (family-0
//! `MakerNotes`, family-1 `Nikon` — see [`Vendor::group1`]).
//!
//! ## Header / embedded-TIFF base (the crux)
//!
//! The modern **type-3** layout (D70/D2Hs/most DSLRs) is `"Nikon\0"` + a
//! 2-byte version + 2 pad bytes, then a SELF-CONTAINED embedded TIFF at blob
//! offset 10 (`MM`/`II` + `0x002a` + the IFD0 offset). The IFD's out-of-line
//! value offsets are relative to that embedded TIFF header (the bundled
//! `Base => '$start - 8'` rebase, `MakerNotes.pm:56`), so this module walks
//! the IFD with `value_base = 10`. The byte order is read from the embedded
//! marker, NOT inherited from the parent (`ByteOrder => 'Unknown'`,
//! `MakerNotes.pm:57`) — a NEF written big-endian inside a little-endian TIFF
//! still decodes correctly.
//!
//! ## Scope
//!
//! See [`tags`]: every readable `%Nikon::Main` scalar + the two UNENCRYPTED
//! fixture sub-tables (`AFInfo`, `ColorBalance0103`). The ENCRYPTED
//! sub-tables (`LensData`/`ShotInfo`/`FlashInfo`/encrypted `ColorBalance`)
//! are deferred (they need `Nikon::Decrypt`) — they carry a deferred
//! [`tags::SubTable`] marker so the parent pointer is NOT emitted (the
//! #177/#223 bogus-parent rule).

#![deny(clippy::indexing_slicing)]

pub mod body;
pub mod printconv;
pub mod tags;

use crate::exif::ifd::{ByteOrder, Format, read_value};
use crate::exif::makernotes::VendorEmission;
use crate::value::{Group, Metadata, TagValue};
use smol_str::SmolStr;
use std::vec::Vec;

pub use body::{NikonEntry, ParsedValue, walk_nikon_ifd};
pub use printconv::NikonConv;
pub use tags::{NIKON_TAGS, NIKON_TYPE2_TAGS, NikonTable, NikonTag, SubTable};

/// Decoded Nikon MakerNotes — the typed camera-identity surface populated by
/// [`parse`].
///
/// D8: no public fields; accessor-only. `#[non_exhaustive]` so future Nikon
/// sub-tables can add fields without a breaking change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MakerNotesNikon {
  /// `MakerNoteVersion` (0x0001) rendered string (e.g. `"2.10"`).
  maker_note_version: Option<SmolStr>,
  /// `Quality` (0x0004) — title-cased.
  quality: Option<SmolStr>,
  /// `WhiteBalance` (0x0005) — title-cased.
  white_balance: Option<SmolStr>,
  /// `FocusMode` (0x0007) — title-cased.
  focus_mode: Option<SmolStr>,
  /// `LensType` (0x0083) rendered string (e.g. `"G"`, `"D"`).
  lens_type: Option<SmolStr>,
  /// `Lens` (0x0084) rendered string (e.g. `"18-70mm f/3.5-4.5"`).
  lens: Option<SmolStr>,
  /// `ShootingMode` (0x0089) rendered string.
  shooting_mode: Option<SmolStr>,
  /// `SerialNumber` (0x001d / 0x00a0) string.
  serial_number: Option<SmolStr>,
  /// `ShutterCount` (0x00a7).
  shutter_count: Option<i64>,
}

impl MakerNotesNikon {
  /// Build an empty Nikon metadata bag.
  #[must_use]
  #[inline]
  pub fn new() -> Self {
    Self::default()
  }

  /// `MakerNoteVersion` (0x0001).
  #[must_use]
  #[inline]
  pub fn maker_note_version(&self) -> Option<&str> {
    self.maker_note_version.as_deref()
  }

  /// `Quality` (0x0004).
  #[must_use]
  #[inline]
  pub fn quality(&self) -> Option<&str> {
    self.quality.as_deref()
  }

  /// `WhiteBalance` (0x0005).
  #[must_use]
  #[inline]
  pub fn white_balance(&self) -> Option<&str> {
    self.white_balance.as_deref()
  }

  /// `FocusMode` (0x0007).
  #[must_use]
  #[inline]
  pub fn focus_mode(&self) -> Option<&str> {
    self.focus_mode.as_deref()
  }

  /// `LensType` (0x0083).
  #[must_use]
  #[inline]
  pub fn lens_type(&self) -> Option<&str> {
    self.lens_type.as_deref()
  }

  /// `Lens` (0x0084).
  #[must_use]
  #[inline]
  pub fn lens(&self) -> Option<&str> {
    self.lens.as_deref()
  }

  /// `ShootingMode` (0x0089).
  #[must_use]
  #[inline]
  pub fn shooting_mode(&self) -> Option<&str> {
    self.shooting_mode.as_deref()
  }

  /// `SerialNumber` (0x001d / 0x00a0).
  #[must_use]
  #[inline]
  pub fn serial_number(&self) -> Option<&str> {
    self.serial_number.as_deref()
  }

  /// `ShutterCount` (0x00a7).
  #[must_use]
  #[inline(always)]
  pub const fn shutter_count(&self) -> Option<i64> {
    self.shutter_count
  }
}

/// Resolve the IFD layout from the captured MakerNote bytes + the parent TIFF
/// context. Returns the slice to walk (`walk_in_blob`) plus the IFD start,
/// byte order, out-of-line value base WITHIN that slice, and the TAG TABLE
/// ([`NikonTable`]) the walk is keyed against. `None` for a blob too short /
/// malformed to walk.
///
/// Mirrors the three `MakerNotes.pm` Nikon arms — their `TagTable` AND their
/// `Base`/`ByteOrder`/`Start` semantics:
///
/// - `"Nikon\0\x02"` (type 3, `MakerNotes.pm:51-58`) → `%Nikon::Main`, an
///   EMBEDDED TIFF at blob offset 10. `Base => '$start - 8'` makes out-of-line
///   offsets relative to the EMBEDDED TIFF header, so the IFD is SELF-CONTAINED
///   in the blob: walk the BLOB, `value_base = 10`. The byte order + IFD0
///   offset come from the embedded marker (`ByteOrder => 'Unknown'`).
/// - `"Nikon\0\x01"` (type 2, `MakerNotes.pm:537-545`) → `%Nikon::Type2`, IFD
///   at offset 8, FIXED `LittleEndian` (NOT a marker probe), NO `Base` override
///   ⇒ out-of-line offsets are PARENT-TIFF-relative: walk the parent `data`,
///   IFD at `mn_offset + 8`, `value_base = 0` (offsets are already
///   TIFF-absolute). The DIFFERENT table is the crux — IDs 0x0003..0x000b
///   name different tags than `%Nikon::Main`.
/// - headerless Nikon3 (`MakerNotes.pm:546-554`) → `%Nikon::Main`, the blob IS
///   the IFD, NO `Base` override ⇒ PARENT-TIFF-relative: walk the parent
///   `data`, IFD at `mn_offset`, `value_base = 0`. The byte order inherits the
///   parent walk (`ByteOrder => 'Unknown'`).
fn resolve_layout(blob: &[u8], parent_order: ByteOrder) -> Option<Layout> {
  if blob.starts_with(b"Nikon\x00\x02") {
    // Type 3: `%Nikon::Main`, self-contained embedded TIFF at blob offset 10.
    let (order, ifd_offset) = body::parse_embedded_tiff(blob, 10)?;
    Some(Layout {
      table: NikonTable::Main,
      walk_in_blob: true,
      ifd_offset,
      order,
      value_base: 10,
    })
  } else if blob.starts_with(b"Nikon\x00\x01") {
    // Type 2: `%Nikon::Type2`, IFD at blob offset 8, FIXED little-endian
    // (`MakerNotes.pm:544`, NOT a marker probe); offsets are
    // parent-TIFF-relative (walked in `data` by the caller).
    Some(Layout {
      table: NikonTable::Type2,
      walk_in_blob: false,
      ifd_offset: 8,
      order: ByteOrder::Little,
      value_base: 0,
    })
  } else {
    // Headerless Nikon3: `%Nikon::Main`, the blob IS the IFD, offsets
    // parent-TIFF-relative.
    Some(Layout {
      table: NikonTable::Main,
      walk_in_blob: false,
      ifd_offset: 0,
      order: parent_order,
      value_base: 0,
    })
  }
}

/// The resolved walk parameters (see [`resolve_layout`]).
#[derive(Debug, Clone, Copy)]
struct Layout {
  /// The tag table this IFD is walked against (type-2 ⇒ [`NikonTable::Type2`];
  /// type-3 / headerless ⇒ [`NikonTable::Main`]). Drives BOTH the walker's
  /// unknown-tag skip and the emission-loop lookup, so a type-2 IFD's
  /// 0x0003..0x000b are named by `%Nikon::Type2`, never `%Nikon::Main`.
  table: NikonTable,
  /// `true` ⇒ walk the captured blob (type-3, self-contained); `false` ⇒
  /// walk the parent TIFF `data` (type-2 / headerless Nikon3).
  walk_in_blob: bool,
  /// IFD start offset within the chosen slice.
  ifd_offset: usize,
  /// Byte order of the IFD walk.
  order: ByteOrder,
  /// Out-of-line value base within the chosen slice (type-3 ⇒ 10; else 0).
  value_base: usize,
}

/// Parse the captured Nikon MakerNote blob into a [`MakerNotesNikon`] + the
/// ordered [`VendorEmission`] list for the `MakerNotes:Nikon` group.
///
/// Standalone-blob entry point: the blob IS the TIFF context (out-of-line
/// offsets resolve against the blob itself). Correct for the SELF-CONTAINED
/// type-3 layout; for type-2 / headerless Nikon3 (whose offsets are
/// parent-TIFF-relative) use [`parse_in_tiff`] with the real TIFF block.
///
/// `parent_order` is the parent IFD walk's byte order (the headerless
/// fallback); `model` threads the `ShootingMode` bit-5 + AFInfo byte-order
/// `Condition`s.
#[must_use]
pub fn parse(
  blob: &[u8],
  parent_order: ByteOrder,
  model: Option<&str>,
) -> (MakerNotesNikon, Vec<VendorEmission>) {
  parse_in_tiff(blob, 0, blob.len(), parent_order, true, model)
}

/// Standalone-blob parse with the PrintConv flag (`-n` toggle). Equivalent to
/// [`parse_in_tiff`] over the whole blob; the type-3 layout is self-contained
/// so this is faithful for it, and a standalone type-2 / Nikon3 blob (no
/// parent TIFF) still walks its IFD (only its out-of-line offsets, which would
/// be TIFF-relative, may not resolve — the captured-blob case the JSON walker
/// uses passes the FULL parent TIFF via [`parse_in_tiff`]).
#[must_use]
pub fn parse_with_print_conv(
  blob: &[u8],
  parent_order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
) -> (MakerNotesNikon, Vec<VendorEmission>) {
  parse_in_tiff(blob, 0, blob.len(), parent_order, print_conv, model)
}

/// Like [`parse`] but resolves out-of-line offsets against the PARENT TIFF
/// block (`data`), at `mn_offset`/`mn_len` — needed for the type-2 /
/// headerless Nikon3 layouts whose offsets are TIFF-relative. The type-3
/// embedded-TIFF layout is self-contained and walks the captured blob
/// regardless of `data`.
///
/// `print_conv` toggles PrintConv (`-n` mode emits the post-ValueConv scalar).
#[must_use]
pub fn parse_in_tiff(
  data: &[u8],
  mn_offset: usize,
  mn_len: usize,
  parent_order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
) -> (MakerNotesNikon, Vec<VendorEmission>) {
  let mut typed = MakerNotesNikon::new();
  let mut emissions: Vec<VendorEmission> = Vec::new();
  // The captured MakerNote bytes (for header detection).
  let mn_end = mn_offset.saturating_add(mn_len);
  let Some(blob) = data.get(mn_offset..mn_end.min(data.len())) else {
    return (typed, emissions);
  };
  let Some(layout) = resolve_layout(blob, parent_order) else {
    return (typed, emissions);
  };
  // Choose the slice + IFD offset the walker operates on. Type-3 walks the
  // captured blob (self-contained embedded TIFF); type-2 / headerless walk the
  // PARENT TIFF (out-of-line offsets are TIFF-relative). The walker bounds the
  // directory + values to the chosen buffer length, matching ExifTool's
  // `ProcessExif` `DataLen` bound (the parent EXIF buffer for an in-place
  // MakerNote — see [`walk_nikon_ifd`]).
  let (walk_data, ifd_offset): (&[u8], usize) = if layout.walk_in_blob {
    (blob, layout.ifd_offset)
  } else {
    (data, mn_offset.saturating_add(layout.ifd_offset))
  };
  let entries = walk_nikon_ifd(
    walk_data,
    ifd_offset,
    layout.order,
    layout.value_base,
    layout.table,
  );
  for entry in &entries {
    let Some(def) = layout.table.lookup(entry.tag_id) else {
      continue; // Unknown tag — verbose-only in ExifTool; omit.
    };
    if let Some(sub) = def.sub_table() {
      // SubDirectory tag: walk the readable sub-tables; DEFER (emit nothing —
      // neither parent nor children) for the encrypted/long-tail ones. A
      // SubDirectory pointer NEVER emits the parent value (`Exif.pm:7103`
      // `next` skips `FoundTag`), so a deferred subdir is silent — the
      // #177/#223 bogus-parent rule.
      match sub {
        SubTable::AfInfo => {
          emit_af_info(walk_data, entry, layout, print_conv, model, &mut emissions);
        }
        SubTable::ColorBalance0103 => {
          emit_color_balance(walk_data, entry, layout, print_conv, &mut emissions);
        }
        // Deferred (encrypted / unported child table): emit nothing.
        SubTable::LensData
        | SubTable::ShotInfo
        | SubTable::FlashInfo
        | SubTable::ColorBalanceEncrypted
        | SubTable::OtherDeferred => {}
      }
      continue;
    }
    // Leaf tag.
    let parsed = ParsedValue::new(entry.value.clone());
    // A `None` is a `RawConv => … : undef` drop (only JPGCompression 0 among
    // the ported tags) — the tag is NOT emitted (neither typed nor parity).
    // `layout.order` is `GetByteOrder()` for the Main IFD (PowerUpTime RawConv).
    let Some(value) = def.conv().apply(&parsed, print_conv, model, layout.order) else {
      continue;
    };
    // The typed convenience surface ([`MakerNotesNikon`]) is keyed by the
    // `%Nikon::Main` tag IDs it documents; the type-2 layout reuses those IDs
    // (0x0003..0x000b) for DIFFERENT `%Nikon::Type2` tags, so populating the
    // Main-semantic fields from a type-2 walk would mislabel them. Only the
    // Main path feeds `typed`; the type-2 path emits through the authoritative
    // `emissions` list alone (with its faithful `%Nikon::Type2` names).
    if layout.table == NikonTable::Main {
      populate_typed(&mut typed, entry.tag_id, &value, def.name());
    }
    emissions.push(VendorEmission::new(
      def.name().into(),
      value,
      def.is_unknown(),
    ));
  }
  (typed, emissions)
}

/// Emit the `%Nikon::AFInfo` (0x0088) leaves — a `ProcessBinaryData` table
/// read BigEndian for DSLRs (`$$self{Model} =~ /^NIKON D/i`), LittleEndian
/// otherwise (`Nikon.pm:2113-2158`). The AFInfo blob is the entry's value
/// bytes (read fresh from the blob via the recorded `value_offset`/`size`).
fn emit_af_info(
  walk_data: &[u8],
  entry: &NikonEntry,
  layout: Layout,
  print_conv: bool,
  model: Option<&str>,
  emissions: &mut Vec<VendorEmission>,
) {
  // The AFInfo SubDirectory's own byte order (the table-level `ByteOrder`
  // directive). DSLRs → BigEndian; else LittleEndian. The parent IFD's order
  // does NOT carry into a `ProcessBinaryData` table with an explicit
  // `ByteOrder`.
  let sub_order = if model.is_some_and(model_is_nikon_dslr) {
    ByteOrder::Big
  } else {
    ByteOrder::Little
  };
  let _ = layout;
  let Some(sub) = walk_data.get(entry.value_offset..entry.value_offset + entry.value_size) else {
    return;
  };
  for pos in tags::AF_INFO {
    // Read `pos.format` at byte offset `pos.offset` within the sub-blob.
    let elem = pos.format.byte_size();
    if elem == 0 || pos.offset + elem > sub.len() {
      continue;
    }
    let avail = sub.len() - pos.offset;
    let Some(raw) = read_value(sub, pos.offset, pos.format, 1, avail, sub_order) else {
      continue;
    };
    let parsed = ParsedValue::new(raw);
    // No AFInfo position has a `RawConv … undef`, but honour the drop contract
    // uniformly: a `None` skips emission. The sub-table byte order is the AFInfo
    // `ByteOrder` directive (`sub_order`).
    let Some(value) = pos.conv.apply(&parsed, print_conv, model, sub_order) else {
      continue;
    };
    emissions.push(VendorEmission::new(pos.name.into(), value, false));
  }
}

/// Emit `%Nikon::ColorBalance3` (0x0097, the `0103` D70/D70s variant):
/// `Start => '$valuePtr + 20'`, then `WB_RGBGLevels = int16u[4]` at the
/// SubDirectory's offset 0, in the SubDirectory's byte order (inherited from
/// the embedded TIFF). UNENCRYPTED.
///
/// The other 0x0097 variants (encrypted `02xx`, the early `0100`/`0102`) are
/// NOT walked here — the version prefix gates them; a non-`0103` prefix emits
/// nothing (deferred). This keeps the byte-exact D70/.nef WB_RGBGLevels while
/// the encrypted variants await `Nikon::Decrypt`.
fn emit_color_balance(
  walk_data: &[u8],
  entry: &NikonEntry,
  layout: Layout,
  print_conv: bool,
  emissions: &mut Vec<VendorEmission>,
) {
  let Some(sub) = walk_data.get(entry.value_offset..entry.value_offset + entry.value_size) else {
    return;
  };
  // The version prefix is the first 4 ASCII bytes of the ColorBalance value.
  let prefix = sub.get(0..4).unwrap_or(&[]);
  if prefix != b"0103" {
    // Not the unencrypted D70 variant — deferred (encrypted or unported).
    return;
  }
  // `Start => '$valuePtr + 20'` (`Nikon.pm:2705`) then `WB_RGBGLevels =
  // int16u[4]` at the ColorBalance3 table's offset 0 (`Nikon.pm:5327-5335`) —
  // 8 bytes. The child read is bounded by the PARENT tag's declared value
  // (ExifTool's `ProcessBinaryData` `DirLen` = the parent value size adjusted
  // by the `Start` delta, and it stops when no bytes remain), so read EXACTLY
  // those 8 bytes from WITHIN `sub` at offset 20 — NOT from the remaining
  // `walk_data` tail. A ColorBalance value shorter than 28 bytes (20-byte
  // `Start` delta + the 8-byte record) cannot hold the record: emit nothing
  // rather than over-reading the next IFD entry / trailing buffer.
  let Some(record) = sub.get(20..28) else {
    return;
  };
  // 4 × int16u, in the SubDirectory's inherited byte order.
  let Some(raw) = read_value(record, 0, Format::Int16u, 4, record.len(), layout.order) else {
    return;
  };
  let parsed = ParsedValue::new(raw);
  // `NikonConv::Raw` never suppresses; the `else` is unreachable in practice.
  let Some(value) = NikonConv::Raw.apply(&parsed, print_conv, None, layout.order) else {
    return;
  };
  emissions.push(VendorEmission::new("WB_RGBGLevels".into(), value, false));
}

/// `$$self{Model} =~ /^NIKON D/i` (`Nikon.pm:2115`) — the AFInfo BigEndian
/// gate (the Nikon DSLR `D`-series).
fn model_is_nikon_dslr(model: &str) -> bool {
  let m = model.trim_start();
  // Case-insensitive `^NIKON D`.
  let bytes = m.as_bytes();
  let prefix = b"NIKON D";
  if bytes.len() < prefix.len() {
    return false;
  }
  bytes
    .iter()
    .zip(prefix.iter())
    .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// Populate the typed struct from a leaf tag's rendered value.
fn populate_typed(typed: &mut MakerNotesNikon, tag_id: u16, value: &TagValue, _name: &str) {
  let as_str = |v: &TagValue| -> Option<SmolStr> {
    match v {
      TagValue::Str(s) => Some(s.clone()),
      _ => None,
    }
  };
  match tag_id {
    0x0001 => typed.maker_note_version = as_str(value),
    0x0004 => typed.quality = as_str(value),
    0x0005 => typed.white_balance = as_str(value),
    0x0007 => typed.focus_mode = as_str(value),
    0x0083 => typed.lens_type = as_str(value),
    0x0084 => typed.lens = as_str(value),
    0x0089 => typed.shooting_mode = as_str(value),
    // SerialNumber: 0x001d (string) and 0x00a0 (string). 0x001d wins when both
    // present (it is the canonical body serial); but `populate_typed` runs in
    // IFD order, so the LATER one would overwrite — guard 0x00a0 to not clobber
    // an existing 0x001d value.
    0x001d => {
      typed.serial_number = match value {
        TagValue::Str(s) => Some(s.clone()),
        TagValue::I64(n) => Some(SmolStr::new(n.to_string())),
        _ => typed.serial_number.take(),
      };
    }
    0x00a0 => {
      if typed.serial_number.is_none() {
        typed.serial_number = as_str(value);
      }
    }
    0x00a7 => {
      if let TagValue::I64(n) = value {
        typed.shutter_count = Some(*n);
      }
    }
    _ => {}
  }
}

/// Emit Nikon MakerNotes into a [`Metadata`] sink under the
/// `("MakerNotes","Nikon")` group — the family-0 `MakerNotes`, family-1
/// `Nikon` axis bundled `exiftool -G1` uses.
pub fn parse_into_metadata(
  blob: &[u8],
  parent_order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
  into: &mut Metadata,
) {
  let group = Group::new("MakerNotes", "Nikon");
  let (_typed, emissions) = parse_with_print_conv(blob, parent_order, print_conv, model);
  for e in emissions {
    if e.unknown() {
      continue;
    }
    into.push(group.clone(), e.name(), e.value().clone());
  }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  /// A synthetic type-3 blob with Quality + LensType decodes through the full
  /// parse path, emitting title-cased Quality + the LensType bitmask string.
  #[test]
  fn parse_type3_quality_and_lens_type() {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"Nikon\x00\x02\x10\x00\x00");
    b.extend_from_slice(b"MM");
    b.extend_from_slice(&[0x00, 0x2a]);
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x08]); // IFD0 at blob 18
    b.extend_from_slice(&[0x00, 0x02]); // 2 entries
    // Quality = "FINE" (string[4], inline).
    b.extend_from_slice(&[0x00, 0x04]);
    b.extend_from_slice(&[0x00, 0x02]);
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]);
    b.extend_from_slice(b"FINE");
    // LensType = 0x06 (int8u, inline) → "G".
    b.extend_from_slice(&[0x00, 0x83]);
    b.extend_from_slice(&[0x00, 0x01]); // int8u
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // count 1
    b.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]); // value 6
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD

    let (typed, emissions) = parse(&b, ByteOrder::Big, Some("NIKON D70"));
    assert_eq!(typed.quality(), Some("Fine"));
    assert_eq!(typed.lens_type(), Some("G"));
    let names: Vec<&str> = emissions.iter().map(|e| e.name()).collect();
    assert!(names.contains(&"Quality"));
    assert!(names.contains(&"LensType"));
    let q = emissions.iter().find(|e| e.name() == "Quality").unwrap();
    assert_eq!(q.value(), &TagValue::Str(SmolStr::new("Fine")));
  }

  /// A deferred (encrypted) SubDirectory pointer (LensData 0x0098, ShotInfo
  /// 0x0091, FlashInfo 0x00a8) emits NEITHER a parent NOR children — the
  /// #177/#223 bogus-parent rule.
  #[test]
  fn deferred_encrypted_subdir_emits_no_parent() {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"Nikon\x00\x02\x10\x00\x00");
    b.extend_from_slice(b"MM");
    b.extend_from_slice(&[0x00, 0x2a]);
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x08]);
    b.extend_from_slice(&[0x00, 0x01]); // 1 entry
    // ShotInfo (0x0091): undef, count 4 (inline "0206").
    b.extend_from_slice(&[0x00, 0x91]);
    b.extend_from_slice(&[0x00, 0x07]); // undef
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // count 4
    b.extend_from_slice(b"0206");
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let (_typed, emissions) = parse(&b, ByteOrder::Big, Some("NIKON D2Hs"));
    // No "ShotInfo" parent, no ShotInfoVersion child.
    assert!(
      emissions.iter().all(|e| e.name() != "ShotInfo"),
      "deferred ShotInfo parent must NOT be emitted"
    );
    assert!(
      emissions.iter().all(|e| e.name() != "ShotInfoVersion"),
      "deferred ShotInfo children must NOT be emitted (no Decrypt)"
    );
  }

  /// `model_is_nikon_dslr` matches the `^NIKON D` (case-insensitive) gate.
  #[test]
  fn nikon_dslr_gate() {
    assert!(model_is_nikon_dslr("NIKON D70"));
    assert!(model_is_nikon_dslr("NIKON D2Hs"));
    assert!(model_is_nikon_dslr("nikon d850"));
    assert!(!model_is_nikon_dslr("NIKON E775")); // Coolpix
    assert!(!model_is_nikon_dslr("COOLPIX P900"));
  }

  /// AFInfo (0x0088, BigEndian for DSLRs) decodes AFAreaMode/AFPoint at byte
  /// offsets 0/1 — a synthetic blob mirroring the D70 record shape.
  #[test]
  fn af_info_subdir_decodes() {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"Nikon\x00\x02\x10\x00\x00");
    b.extend_from_slice(b"MM");
    b.extend_from_slice(&[0x00, 0x2a]);
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x08]);
    b.extend_from_slice(&[0x00, 0x01]); // 1 entry
    // AFInfo (0x0088): undef, count 4 (inline) → [0,0,0,1].
    // byte0 AFAreaMode=0 (Single Area), byte1 AFPoint=0 (Center),
    // bytes2-3 AFPointsInFocus=0x0001 (Center).
    b.extend_from_slice(&[0x00, 0x88]);
    b.extend_from_slice(&[0x00, 0x07]); // undef
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // count 4
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let (_typed, emissions) = parse(&b, ByteOrder::Big, Some("NIKON D70"));
    let get = |n: &str| {
      emissions
        .iter()
        .find(|e| e.name() == n)
        .map(|e| e.value().clone())
    };
    assert_eq!(
      get("AFAreaMode"),
      Some(TagValue::Str(SmolStr::new("Single Area")))
    );
    assert_eq!(get("AFPoint"), Some(TagValue::Str(SmolStr::new("Center"))));
    assert_eq!(
      get("AFPointsInFocus"),
      Some(TagValue::Str(SmolStr::new("Center")))
    );
  }

  /// END-TO-END of the implicit-`undef` SubDirectory override (`Exif.pm:6733`):
  /// an AFInfo (0x0088) whose ON-DISK format is a huge numeric `int32u` count
  /// (> 100000) is read as `undef` and so is NOT excessive-count-skipped — the
  /// AFInfo children (AFAreaMode/AFPoint/AFPointsInFocus) STILL emit, exactly as
  /// `perl exiftool 13.59` does (verbose: `int32u[100001] read as undef[400004]`
  /// → AFInfo BinaryData directory processed). Pre-fix the entry was dropped by
  /// the excessive-count guard and NO AFInfo child emitted.
  #[test]
  fn af_info_int32u_excessive_count_read_as_undef_emits_children() {
    let count: u32 = 100_001; // *4 = 400004 bytes (> 100000)
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"Nikon\x00\x02\x10\x00\x00"); // header (10)
    b.extend_from_slice(b"MM");
    b.extend_from_slice(&[0x00, 0x2a]);
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x08]); // IFD0 at embedded+8 = blob 18
    b.extend_from_slice(&[0x00, 0x01]); // 1 entry
    // AFInfo (0x0088): int32u, huge count, OUT-OF-LINE (400004 > 4). The value
    // offset is embedded-relative (blob = 10 + embedded). Entry table is 18..32;
    // next-IFD ptr 32..36; the AFInfo block starts at embedded offset 26 (blob
    // 36), fully in-bounds.
    let block_emb: u32 = 26; // blob 36
    b.extend_from_slice(&[0x00, 0x88]);
    b.extend_from_slice(&[0x00, 0x04]); // int32u
    b.extend_from_slice(&count.to_be_bytes());
    b.extend_from_slice(&block_emb.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD
    debug_assert_eq!(b.len(), 36); // == 10 + 26
    // The AFInfo block: byte0 AFAreaMode=0 (Single Area), byte1 AFPoint=0
    // (Center), bytes2-3 AFPointsInFocus=0x0001 (Center); then padded to the
    // full declared 400004-byte size so the block is in-bounds.
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    b.resize(36 + (count as usize) * 4, 0);

    let (_typed, emissions) = parse(&b, ByteOrder::Big, Some("NIKON D70"));
    let get = |n: &str| {
      emissions
        .iter()
        .find(|e| e.name() == n)
        .map(|e| e.value().clone())
    };
    assert_eq!(
      get("AFAreaMode"),
      Some(TagValue::Str(SmolStr::new("Single Area"))),
      "AFInfo children emit (read as undef, NOT excessive-count-skipped)"
    );
    assert_eq!(get("AFPoint"), Some(TagValue::Str(SmolStr::new("Center"))));
    assert_eq!(
      get("AFPointsInFocus"),
      Some(TagValue::Str(SmolStr::new("Center")))
    );
  }

  /// A ColorBalance (0x0097) whose declared value is too short to hold the
  /// `0103` record (count 4 = just the `"0103"` prefix) emits NO WB_RGBGLevels
  /// and does NOT over-read into the adjacent IFD bytes. ExifTool bounds the
  /// `ColorBalance3` child by the PARENT tag's value size (`Start => '$valuePtr
  /// + 20'` then `int16u[4]` = needs 28 bytes); a 4-byte value cannot supply
  /// the record, so nothing is produced. The trailing bytes here would, if
  /// (wrongly) over-read from the buffer tail, decode a bogus level set —
  /// guarding the over-read fix.
  #[test]
  fn color_balance_short_value_emits_no_levels() {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"Nikon\x00\x02\x10\x00\x00");
    b.extend_from_slice(b"MM");
    b.extend_from_slice(&[0x00, 0x2a]);
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x08]); // IFD0 at blob 18
    b.extend_from_slice(&[0x00, 0x01]); // 1 entry
    // ColorBalance (0x0097): undef, count 4 = "0103" (inline — fits in 4 bytes).
    b.extend_from_slice(&[0x00, 0x97]);
    b.extend_from_slice(&[0x00, 0x07]); // undef
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // count 4
    b.extend_from_slice(b"0103"); // inline value (only the version prefix)
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD
    // Trailing bytes that a buggy `value_offset + 20` over-read would pick up as
    // a (bogus) int16u[4] WB_RGBGLevels — present to prove they are NOT read.
    b.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);

    let (_typed, emissions) = parse(&b, ByteOrder::Big, Some("NIKON D70"));
    assert!(
      emissions.iter().all(|e| e.name() != "WB_RGBGLevels"),
      "a short ColorBalance value must emit no WB_RGBGLevels (no over-read), got {emissions:?}"
    );
    // And no bogus ColorBalance parent (the SubDirectory pointer never emits it).
    assert!(emissions.iter().all(|e| e.name() != "ColorBalance"));
  }

  /// An empty / too-short blob yields nothing (no panic).
  #[test]
  fn empty_blob_is_empty() {
    let (typed, emissions) = parse(b"", ByteOrder::Big, None);
    assert_eq!(typed, MakerNotesNikon::new());
    assert!(emissions.is_empty());
  }

  /// DIVERGENCE ORACLE (end-to-end): the embedded-TIFF IFD0-offset field is
  /// IGNORED — `Start => '$valuePtr + 18'` (`MakerNotes.pm:54`) walks the Main
  /// IFD at the FIXED `tiff_at + 8` regardless of the field. A blob whose field
  /// points at a SECOND valid-looking IFD (a decoy Quality "FAKE") must emit the
  /// real fixed-start IFD's LensType and NONE of the decoy's tags. (Only the
  /// `MM`/`II` marker is read from the embedded header; the field is not.)
  #[test]
  fn type3_embedded_ifd0_field_ignored_walks_fixed_start() {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"Nikon\x00\x02\x10\x00\x00"); // type-3 header (10)
    b.extend_from_slice(b"MM"); // embedded TIFF, big-endian
    b.extend_from_slice(&[0x00, 0x2a]); // magic
    // IFD0-offset field = 40 (NOT 8): if followed it points the Main IFD at
    // tiff_at(10) + 40 = blob 50 — the DECOY IFD below. ExifTool ignores it.
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x28]);
    // REAL IFD at the FIXED start (blob 18): LensType (0x0083) int8u = 6 → "G".
    b.extend_from_slice(&[0x00, 0x01]); // 1 entry
    b.extend_from_slice(&[0x00, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01]);
    b.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]);
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD
    // Pad to blob 50, then the DECOY IFD: Quality (0x0004) string[4] = "FAKE".
    while b.len() < 50 {
      b.push(0);
    }
    b.extend_from_slice(&[0x00, 0x01]); // 1 entry
    b.extend_from_slice(&[0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04]);
    b.extend_from_slice(b"FAKE"); // inline value
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD

    let (typed, emissions) = parse(&b, ByteOrder::Big, Some("NIKON D70"));
    // The real fixed-start LensType is emitted; the decoy Quality is NOT.
    assert_eq!(
      typed.lens_type(),
      Some("G"),
      "the fixed-start IFD's LensType must decode"
    );
    assert_eq!(
      typed.quality(),
      None,
      "the decoy IFD (field-pointed) must NOT be walked"
    );
    assert!(
      emissions.iter().all(|e| e.name() != "Quality"),
      "the decoy Quality tag must be absent, got {emissions:?}"
    );
    assert!(emissions.iter().any(|e| e.name() == "LensType"));
  }

  /// End-to-end (type-2): an out-of-line value whose full length runs PAST the
  /// parent EXIF buffer is DROPPED, not emitted as a truncated partial tail —
  /// matching ExifTool (`$valuePtr + $size > $dataLen` ⇒ `$bad`, no emission;
  /// verified: ExifTool emits only a `[minor] Bad offset` warning, no tag).
  /// A legitimately in-bounds entry in the same MakerNote still decodes. (The
  /// directory entry table itself is bounded to the buffer, ExifTool's
  /// `DataLen` bound — NOT to the shorter declared MakerNote length.)
  ///
  /// Uses `%Nikon::Type2` tags (Quality 0x0003 in-bounds, Converter 0x000b
  /// out-of-line) since the type-2 layout is walked against that table.
  #[test]
  fn nikon_type2_out_of_line_value_past_buffer_is_dropped() {
    // Parent TIFF (little-endian, type-2 LE). MakerNote at offset 8.
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&[b'I', b'I', 0x2a, 0x00, 0x08, 0x00, 0x00, 0x00]);
    let mn_offset = data.len(); // 8
    // Type-2 header "Nikon\0\x01" + 1 pad byte; IFD begins at blob offset 8.
    data.extend_from_slice(b"Nikon\x00\x01\x00");
    let ifd_at = data.len(); // = mn_offset + 8
    data.extend_from_slice(&[0x02, 0x00]); // 2 entries (LE)
    // Entry 0 — Quality (0x0003) ASCII "F" (count 2, inline) → in-bounds.
    data.extend_from_slice(&[0x03, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00]);
    data.extend_from_slice(&[b'F', 0x00, 0x00, 0x00]);
    // Entry 1 — Converter (0x000b) rational64u[4] = 32 bytes, OUT-OF-LINE at a
    // parent-relative offset whose full 32 bytes run past the buffer end.
    let value_off = (data.len() + 8) as u32; // points just after this IFD
    data.extend_from_slice(&[0x0b, 0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00]);
    data.extend_from_slice(&value_off.to_le_bytes()); // out-of-line offset
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD
    // Supply only 8 of the 32 value bytes (truncated past EOF).
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x01]);
    let mn_len = data.len() - mn_offset;
    let _ = ifd_at;

    let (_typed, emissions) = parse_in_tiff(
      &data,
      mn_offset,
      mn_len,
      ByteOrder::Little,
      true,
      Some("NIKON E990"),
    );
    // The in-bounds Quality decodes; the truncated out-of-line Converter is
    // dropped (NOT a partial-tail value).
    let get = |n: &str| {
      emissions
        .iter()
        .find(|e| e.name() == n)
        .map(|e| e.value().clone())
    };
    assert_eq!(get("Quality"), Some(TagValue::Str(SmolStr::new("F"))));
    assert!(
      emissions.iter().all(|e| e.name() != "Converter"),
      "a value running past the buffer must be dropped, not partial-decoded"
    );
  }

  /// Build a parent little-endian TIFF wrapping a type-2 (`"Nikon\0\x01"`)
  /// MakerNote whose IFD (at blob offset 8, little-endian) carries the given
  /// `entries` (each a full 12-byte IFD entry). Returns `(data, mn_offset,
  /// mn_len)` for [`parse_in_tiff`]. The MakerNote value is placed out-of-line
  /// after IFD0 so out-of-line offsets are parent-TIFF-relative (the no-`Base`
  /// type-2 semantics).
  fn type2_in_tiff(entries: &[[u8; 12]]) -> (Vec<u8>, usize, usize) {
    // Build the type-2 MakerNote blob: header (8 bytes) + LE IFD at offset 8.
    let mut mn: Vec<u8> = Vec::new();
    mn.extend_from_slice(b"Nikon\x00\x01"); // 7 bytes
    mn.push(0x00); // pad → entry count at blob offset 8
    let n = u16::try_from(entries.len()).unwrap();
    mn.extend_from_slice(&n.to_le_bytes());
    for e in entries {
      mn.extend_from_slice(e);
    }
    mn.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD = 0
    // Container TIFF: II header, IFD0 (Make=NIKON), MakerNote out-of-line.
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&[b'I', b'I', 0x2a, 0x00, 0x08, 0x00, 0x00, 0x00]);
    // IFD0: 2 entries (Make, MakerNote) + next-IFD. Size = 2 + 2*12 + 4 = 30.
    let ifd0_start = 8usize;
    let ifd0_size = 2 + 2 * 12 + 4;
    let ool = ifd0_start + ifd0_size;
    let make = b"NIKON\x00";
    let off_make = ool as u32;
    let off_mn = (ool + make.len()) as u32;
    data.extend_from_slice(&[0x02, 0x00]); // 2 entries
    // Make (0x010f) ASCII, out-of-line.
    data.extend_from_slice(&[0x0f, 0x01, 0x02, 0x00]);
    data.extend_from_slice(&(make.len() as u32).to_le_bytes());
    data.extend_from_slice(&off_make.to_le_bytes());
    // MakerNote (0x927c) UNDEFINED, out-of-line.
    data.extend_from_slice(&[0x7c, 0x92, 0x07, 0x00]);
    data.extend_from_slice(&(mn.len() as u32).to_le_bytes());
    data.extend_from_slice(&off_mn.to_le_bytes());
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD
    debug_assert_eq!(data.len(), ool);
    data.extend_from_slice(make);
    let mn_offset = data.len();
    data.extend_from_slice(&mn);
    let mn_len = data.len() - mn_offset;
    (data, mn_offset, mn_len)
  }

  /// One 12-byte little-endian IFD entry (tag, format, count, 4 inline value
  /// bytes).
  fn le_entry(tag: u16, fmt: u16, count: u32, val: [u8; 4]) -> [u8; 12] {
    let mut e = [0u8; 12];
    e[0..2].copy_from_slice(&tag.to_le_bytes());
    e[2..4].copy_from_slice(&fmt.to_le_bytes());
    e[4..8].copy_from_slice(&count.to_le_bytes());
    e[8..12].copy_from_slice(&val);
    e
  }

  /// REGRESSION ORACLE: a type-2 (`"Nikon\0\x01"`) MakerNote is walked
  /// against `%Nikon::Type2`, NOT `%Nikon::Main` — so 0x0003 emits as
  /// `Quality` (the Type2 name), NOT `ColorMode` (the Main name for the same
  /// ID). Byte-exact to `perl exiftool 13.59` on the crafted blob: `Quality`,
  /// `WhiteBalance`, `DigitalZoom`, `Converter` — the four Type2 tags supplied.
  #[test]
  fn nikon_type2_uses_type2_table() {
    let entries = [
      le_entry(0x0003, 2, 2, [b'F', 0x00, 0x00, 0x00]), // Quality "F"
      le_entry(0x0007, 2, 2, [b'A', 0x00, 0x00, 0x00]), // WhiteBalance "A"
      le_entry(0x000a, 3, 1, [0x02, 0x00, 0x00, 0x00]), // DigitalZoom int16u 2
      le_entry(0x000b, 3, 1, [0x01, 0x00, 0x00, 0x00]), // Converter int16u 1
    ];
    let (data, mn_offset, mn_len) = type2_in_tiff(&entries);
    let (_typed, emissions) = parse_in_tiff(
      &data,
      mn_offset,
      mn_len,
      ByteOrder::Little,
      true,
      Some("NIKON E990"),
    );
    let get = |n: &str| {
      emissions
        .iter()
        .find(|e| e.name() == n)
        .map(|e| e.value().clone())
    };
    // The Type2 names — matching the oracle exactly.
    assert_eq!(get("Quality"), Some(TagValue::Str(SmolStr::new("F"))));
    assert_eq!(get("WhiteBalance"), Some(TagValue::Str(SmolStr::new("A"))));
    // A single small int16u renders to `I64` (render.rs: U64→I64 when it fits).
    assert_eq!(get("DigitalZoom"), Some(TagValue::I64(2)));
    assert_eq!(get("Converter"), Some(TagValue::I64(1)));
    // 0x0003 is Quality, NEVER the Main name ColorMode (the bug).
    assert!(
      emissions.iter().all(|e| e.name() != "ColorMode"),
      "type-2 0x0003 must be Quality (Type2), not ColorMode (Main): {emissions:?}"
    );
    // And the typed Main-semantic surface is NOT populated from a type-2 walk
    // (0x0004/0x0007 mean different tags there).
    assert_eq!(_typed.quality(), None);
    assert_eq!(_typed.focus_mode(), None);
  }

  /// A type-2 value is read LITTLE-ENDIAN (the `MakerNotes.pm:544` fixed
  /// `ByteOrder => 'LittleEndian'`), regardless of the parent TIFF order. Here
  /// the parent is passed BIG-endian, yet DigitalZoom (0x000a) int16u with LE
  /// bytes `02 00` reads `2` — proving the type-2 path forces LE (a big-endian
  /// read of `02 00` would be `0x0200 = 512`).
  #[test]
  fn nikon_type2_little_endian() {
    let entries = [le_entry(0x000a, 3, 1, [0x02, 0x00, 0x00, 0x00])]; // DigitalZoom
    let (data, mn_offset, mn_len) = type2_in_tiff(&entries);
    // Parent order BIG — the type-2 arm must IGNORE it and force LE.
    let (_typed, emissions) = parse_in_tiff(
      &data,
      mn_offset,
      mn_len,
      ByteOrder::Big,
      true,
      Some("NIKON E990"),
    );
    let dz = emissions
      .iter()
      .find(|e| e.name() == "DigitalZoom")
      .map(|e| e.value().clone());
    assert_eq!(
      dz,
      Some(TagValue::I64(2)),
      "type-2 forces LittleEndian: `02 00` is 2, not 512 (BE)"
    );
  }

  /// The type-2 IFD is read at `Start => '$valuePtr + 8'` — the entry count
  /// sits at blob offset 8 (after the 8-byte `"Nikon\0\x01"`+pad header). A
  /// decoy IFD planted at blob offset 0 (a different tag) is NOT walked; only
  /// the real IFD at +8 emits. Proves the +8 start.
  #[test]
  fn nikon_type2_start_plus_8() {
    // Real IFD at +8 carries Quality (0x0003). To prove +8 (not +0), we hand-
    // build the MakerNote so its FIRST 8 bytes ("Nikon\0\x01"+pad) would, if
    // (wrongly) read as an IFD at offset 0, parse a bogus entry count from the
    // ASCII header bytes — never the real IFD. The +8 walk finds Quality.
    let entries = [le_entry(0x0003, 2, 2, [b'F', 0x00, 0x00, 0x00])];
    let (data, mn_offset, mn_len) = type2_in_tiff(&entries);
    // Sanity: the entry count u16 lives at blob offset 8 within the MakerNote.
    let mn = &data[mn_offset..mn_offset + mn_len];
    assert_eq!(&mn[0..8], b"Nikon\x00\x01\x00", "8-byte type-2 header");
    assert_eq!(
      u16::from_le_bytes([mn[8], mn[9]]),
      1,
      "the IFD entry count (1) is at blob offset 8 — the +8 Start"
    );
    let (_typed, emissions) = parse_in_tiff(
      &data,
      mn_offset,
      mn_len,
      ByteOrder::Little,
      true,
      Some("NIKON E990"),
    );
    assert!(
      emissions.iter().any(|e| e.name() == "Quality"),
      "the IFD at +8 must be walked (Quality emitted): {emissions:?}"
    );
  }
}
