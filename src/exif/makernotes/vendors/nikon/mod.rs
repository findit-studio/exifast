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
//! See [`tags`]: every readable `%Nikon::Main` scalar + the UNENCRYPTED
//! fixture sub-tables (`AFInfo`, `ColorBalance0103`, `LensData00`/`01`, and the
//! UNENCRYPTED plaintext `FlashInfo0100`). `LensData` decrypts the `02xx`+ arms
//! ([`decrypt`]); `FlashInfo` (0x00a8) is unencrypted `ProcessBinaryData`
//! version-dispatched on the 4-byte `FlashInfoVersion` prefix
//! ([`emit_flash_info`], `Nikon.pm:2987-3009`) — only the `0100`/`0101` arm is
//! ported here, other versions emit nothing (a committed follow-up). The
//! deferred `ShotInfo` (0x0091) + encrypted `ColorBalance` carry a deferred
//! [`tags::SubTable`] marker so the parent pointer is NOT emitted (the
//! #177/#223 bogus-parent rule).

#![deny(clippy::indexing_slicing)]

pub mod body;
pub mod decrypt;
pub mod printconv;
pub mod tags;

use crate::exif::ifd::{ByteOrder, Format, RawValue, read_value};
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
  // PRE-SCAN for the decryption keys (`Nikon.pm:14199-14203`
  // `PrescanExif(... 0x001d, 0x00a7 ...)`): ExifTool reads SerialNumber
  // (0x001d) and ShutterCount (0x00a7) from the IFD BEFORE processing it, so
  // the keys are available to ANY encrypted sub-table regardless of its IFD
  // position. The MakerNote IFD is tag-ID-ordered (0x001d < 0x00a7 < 0x0098),
  // so they precede LensData in walk order anyway, but a separate pass makes
  // the capture order-independent (and only ever runs on the Main table — the
  // Type2 layout has no encrypted sub-tables / 0x001d/0x00a7 semantics).
  let decrypt_keys = if layout.table == NikonTable::Main {
    scan_decrypt_keys(
      walk_data,
      ifd_offset,
      layout.order,
      layout.value_base,
      model,
    )
  } else {
    None
  };
  // The RAW `FocusMode` (`$$self{FocusMode}`) from tag 0x0007 (`Nikon.pm:1816`,
  // RawConv `$$self{FocusMode} = $val`) — gates the LensData0800 Z telemetry's
  // `FocusMode ne "Manual"` members (0x4c/0x56). UNLIKE the decrypt keys (which
  // ExifTool genuinely pre-scans, `Nikon.pm:14199-14203`), 0x0007 is a NORMAL
  // RawConv DataMember set DURING the IFD walk: `$$self{FocusMode}` holds
  // whatever the LAST-walked 0x0007 entry stored AT the moment the 0x0098
  // LensData SubDirectory is processed. So the gate must see the value
  // POSITIONALLY — the last 0x0007 BEFORE this 0x0098 in walk order (`None` /
  // `undef ne "Manual"` = open when no 0x0007 precedes it). The IFD is normally
  // tag-ID-ordered (0x0007 < 0x0098), so this matches the pre-scan for a
  // well-formed MakerNote; it differs only for an unsorted/duplicate IFD where a
  // `FocusMode = Manual` follows the LensData. The type-2 layout reuses 0x0007
  // for a different tag, so only the Main table tracks it.
  let track_focus_mode = layout.table == NikonTable::Main;
  let mut focus_mode: Option<SmolStr> = None;
  for entry in &entries {
    // Capture the running `$$self{FocusMode}` the instant tag 0x0007 is walked,
    // BEFORE any later 0x0098 reaches `emit_lens_data` (the RawConv stores the
    // raw on-disk string; a non-`Text` 0x0007 leaves the member unchanged, as
    // `as_text` returns `None` and we keep the prior value).
    if track_focus_mode
      && entry.tag_id == 0x0007
      && let Some(s) = ParsedValue::new(entry.value.clone()).as_text()
    {
      focus_mode = Some(SmolStr::new(s));
    }
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
        SubTable::LensData => {
          emit_lens_data(
            walk_data,
            entry,
            layout,
            print_conv,
            decrypt_keys,
            focus_mode.as_deref(),
            &mut emissions,
          );
        }
        SubTable::FlashInfo => {
          emit_flash_info(walk_data, entry, layout, print_conv, &mut emissions);
        }
        // Deferred (encrypted / unported child table): emit nothing.
        SubTable::ShotInfo | SubTable::ColorBalanceEncrypted | SubTable::OtherDeferred => {}
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

/// Emit the `%Nikon::FlashInfo0100` leaves (0x00a8) — an UNENCRYPTED plaintext
/// `ProcessBinaryData` table (NO `DecryptStart` on any arm), version-dispatched
/// on the 4-byte `FlashInfoVersion` prefix (`Nikon.pm:2987-3009`). Only the
/// `010[01]` arm (`%Nikon::FlashInfo0100`, `Nikon.pm:10810`) is ported here;
/// every other version (`0102`/`010[345]`/`0106`/`010[78]`/`030[01]`/other)
/// emits NOTHING (a committed follow-up) — the dispatch is a one-line addition
/// per arm. FlashInfo0100 has NO `ByteOrder` SubDirectory directive, so it
/// inherits the parent MakerNote IFD order; every member is a single int8u/int8s
/// byte, so the order is irrelevant for these reads.
///
/// The fields are read at their byte offsets into the value, in offset order,
/// honouring the byte-9 dual read (`FlashCommanderMode` Mask 0x80 then
/// `FlashControlMode` Mask 0x7f), the three DataMembers (`FlashControlMode`,
/// `FlashGroup{A,B}ControlMode`), the offset-10/17/18 `>= 0x06` Manual/comp
/// conditionals, and the offset-11/12/13 `RawConv => '$val ? $val : undef'`
/// drops. A field whose offset is past the available value length emits nothing
/// (bounds-safe, like [`emit_color_balance`]).
fn emit_flash_info(
  walk_data: &[u8],
  entry: &NikonEntry,
  layout: Layout,
  print_conv: bool,
  emissions: &mut Vec<VendorEmission>,
) {
  let Some(sub) = walk_data.get(entry.value_offset..entry.value_offset + entry.value_size) else {
    return;
  };
  // `FlashInfoVersion` = the first 4 ASCII bytes (`Format => 'string[4]'`).
  let Some(version) = sub.get(0..4).and_then(|v| <&[u8; 4]>::try_from(v).ok()) else {
    return;
  };
  // The 0x00a8 conditional SubDirectory list (`Nikon.pm:2987-3009`): only the
  // `010[01]` arm (FlashInfo0100) is ported. Any other version is deferred —
  // emit nothing (the parent SubDirectory pointer is already suppressed by the
  // deferred dispatch; a follow-up adds the remaining arms here).
  if !matches!(version, b"0100" | b"0101") {
    return;
  }
  // offset 0 `FlashInfoVersion` (`string[4]`, no conversion — verbatim).
  emissions.push(VendorEmission::new(
    "FlashInfoVersion".into(),
    TagValue::Str(SmolStr::new(String::from_utf8_lossy(version))),
    false,
  ));
  // The shared int8u read + conv push (`FORMAT => 'int8u'` is the table
  // default). A byte past the value length emits nothing; a `None` from a
  // RawConv-undef drop (FlashFocalLength/RepeatingFlashRate 0) is skipped.
  let push_u8 =
    |emissions: &mut Vec<VendorEmission>, offset: usize, name: &'static str, conv: NikonConv| {
      let Some(&byte) = sub.get(offset) else {
        return;
      };
      let parsed = ParsedValue::new(RawValue::U64(std::vec![u64::from(byte)]));
      if let Some(value) = conv.apply(&parsed, print_conv, None, layout.order) {
        emissions.push(VendorEmission::new(name.into(), value, false));
      }
    };

  // offset 4 `FlashSource` (int8u).
  push_u8(emissions, 4, "FlashSource", NikonConv::FlashSource);

  // offset 6 `ExternalFlashFirmware` (`int8u[2]`): the value is the space-joined
  // pair "A B"; the PrintConv looks it up in `%flashFirmware`, with an OTHER
  // sub `sprintf('%d.%.2d (Unknown model)', A, B)`. `-n` emits the raw "A B".
  if let (Some(&a), Some(&b)) = (sub.get(6), sub.get(7)) {
    let joined = std::format!("{a} {b}");
    let value = if print_conv {
      match flash_firmware_label(&joined) {
        Some(s) => TagValue::Str(SmolStr::new(s)),
        // OTHER => sprintf('%d.%.2d (Unknown model)', split(' ', $val)).
        None => TagValue::Str(SmolStr::new(std::format!("{a}.{b:02} (Unknown model)"))),
      }
    } else {
      TagValue::Str(SmolStr::new(joined))
    };
    emissions.push(VendorEmission::new(
      "ExternalFlashFirmware".into(),
      value,
      false,
    ));
  }

  // offset 8 `ExternalFlashFlags` (int8u BITMASK).
  push_u8(
    emissions,
    8,
    "ExternalFlashFlags",
    NikonConv::ExternalFlashFlags,
  );

  // offset 9 read TWICE (two tags from one byte, via Mask + BitShift; ExifTool
  // `$val = ($val & $mask) >> $bitShift`, `ExifTool.pm:10079`):
  //   9.1 FlashCommanderMode — Mask 0x80 ⇒ (byte9 & 0x80) >> 7; {0=>Off,1=>On}.
  //   9.2 FlashControlMode    — Mask 0x7f ⇒ (byte9 & 0x7f); DataMember; the
  //                             %flashControlMode hash.
  let flash_control_mode: Option<i64> = sub.get(9).map(|&b9| {
    let commander = i64::from((b9 & 0x80) >> 7);
    let parsed = ParsedValue::new(RawValue::I64(std::vec![commander]));
    if let Some(value) = NikonConv::OffOn.apply(&parsed, print_conv, None, layout.order) {
      emissions.push(VendorEmission::new(
        "FlashCommanderMode".into(),
        value,
        false,
      ));
    }
    let control = i64::from(b9 & 0x7f);
    let parsed = ParsedValue::new(RawValue::I64(std::vec![control]));
    if let Some(value) = NikonConv::FlashControlMode.apply(&parsed, print_conv, None, layout.order)
    {
      emissions.push(VendorEmission::new("FlashControlMode".into(), value, false));
    }
    control
  });

  // offset 10 CONDITIONAL on the FlashControlMode DataMember:
  //   >= 0x06 ⇒ FlashOutput (int8u, 2**(-val/6), Full/%); else FlashCompensation
  //   (int8s, -val/6, PrintFraction). A missing byte 9 leaves the member undef;
  //   ExifTool's `$$self{FlashControlMode} >= 0x06` is then `undef >= 6` = false
  //   ⇒ the FlashCompensation arm.
  emit_flash_output_or_comp(
    sub,
    10,
    flash_control_mode,
    print_conv,
    layout.order,
    "FlashOutput",
    "FlashCompensation",
    NikonConv::FlashCompensation,
    emissions,
  );

  // offset 11 FlashFocalLength (int8u, RawConv 0⇒undef, "$val mm").
  push_u8(
    emissions,
    11,
    "FlashFocalLength",
    NikonConv::FlashFocalLength,
  );
  // offset 12 RepeatingFlashRate (int8u, RawConv 0⇒undef, "$val Hz").
  push_u8(
    emissions,
    12,
    "RepeatingFlashRate",
    NikonConv::RepeatingFlashRate,
  );
  // offset 13 RepeatingFlashCount (int8u, RawConv 0⇒undef, no PrintConv — the
  // raw integer).
  if let Some(&byte) = sub.get(13)
    && byte != 0
  {
    emissions.push(VendorEmission::new(
      "RepeatingFlashCount".into(),
      TagValue::I64(i64::from(byte)),
      false,
    ));
  }
  // offset 14 FlashGNDistance (int8u, %flashGNDistance).
  push_u8(emissions, 14, "FlashGNDistance", NikonConv::FlashGnDistance);

  // offset 15/16 FlashGroup{A,B}ControlMode (int8u, Mask 0x0f ⇒ byte & 0x0f;
  // DataMembers; %flashControlMode).
  let group_a_mode = emit_masked_control_mode(
    sub,
    15,
    "FlashGroupAControlMode",
    print_conv,
    layout.order,
    emissions,
  );
  let group_b_mode = emit_masked_control_mode(
    sub,
    16,
    "FlashGroupBControlMode",
    print_conv,
    layout.order,
    emissions,
  );

  // offset 17 CONDITIONAL on FlashGroupAControlMode: >= 0x06 ⇒ FlashGroupAOutput
  // (2**(-val/6)); else FlashGroupACompensation (int8s, -val/6, '%+.1f'/0).
  emit_flash_output_or_comp(
    sub,
    17,
    group_a_mode,
    print_conv,
    layout.order,
    "FlashGroupAOutput",
    "FlashGroupACompensation",
    NikonConv::FlashGroupCompensation,
    emissions,
  );
  // offset 18 CONDITIONAL on FlashGroupBControlMode (same as 17, group B).
  emit_flash_output_or_comp(
    sub,
    18,
    group_b_mode,
    print_conv,
    layout.order,
    "FlashGroupBOutput",
    "FlashGroupBCompensation",
    NikonConv::FlashGroupCompensation,
    emissions,
  );
}

/// `%flashFirmware` (`Nikon.pm:767-789`) — the `ExternalFlashFirmware` "A B"
/// space-joined lookup. Returns `None` for an unlisted pair (the caller renders
/// the OTHER `sprintf('%d.%.2d (Unknown model)', A, B)`).
fn flash_firmware_label(joined: &str) -> Option<&'static str> {
  Some(match joined {
    "0 0" => "n/a",
    "1 1" => "1.01 (SB-800 or Metz 58 AF-1)",
    "1 3" => "1.03 (SB-800)",
    "2 1" => "2.01 (SB-800)",
    "2 4" => "2.04 (SB-600)",
    "2 5" => "2.05 (SB-600)",
    "3 1" => "3.01 (SU-800 Remote Commander)",
    "4 1" => "4.01 (SB-400)",
    "4 2" => "4.02 (SB-400)",
    "4 4" => "4.04 (SB-400)",
    "5 1" => "5.01 (SB-900)",
    "5 2" => "5.02 (SB-900)",
    "6 1" => "6.01 (SB-700)",
    "7 1" => "7.01 (SB-910)",
    "14 3" => "14.03 (SB-5000)",
    _ => return None,
  })
}

/// A `%Nikon::FlashInfo0100` `int8u Mask 0x0f` control-mode DataMember (offset
/// 15/16). Reads byte at `offset`, masks to `byte & 0x0f` (BitShift 0), emits
/// it via `%flashControlMode`, and RETURNS the masked value (the DataMember the
/// offset-17/18 conditional reads). `None` when the byte is past the value
/// length (the member emits nothing and the conditional sees `undef`).
fn emit_masked_control_mode(
  sub: &[u8],
  offset: usize,
  name: &'static str,
  print_conv: bool,
  order: ByteOrder,
  emissions: &mut Vec<VendorEmission>,
) -> Option<i64> {
  let &byte = sub.get(offset)?;
  let masked = i64::from(byte & 0x0f);
  let parsed = ParsedValue::new(RawValue::I64(std::vec![masked]));
  if let Some(value) = NikonConv::FlashControlMode.apply(&parsed, print_conv, None, order) {
    emissions.push(VendorEmission::new(name.into(), value, false));
  }
  Some(masked)
}

/// The shared offset-10/17/18 `FlashControlMode`-gated conditional
/// (`Nikon.pm:10854-10881`/`10920-10940`): `>= 0x06` ⇒ the `Output` tag (int8u,
/// `NikonConv::FlashOutput`); else the `Comp` tag (int8s `Format` override,
/// `comp_conv` = `FlashCompensation` PrintFraction at offset 10 /
/// `FlashGroupCompensation` `%+.1f` at offset 17/18). `mode` is the gating
/// DataMember (`None` = `undef >= 0x06` = false ⇒ the Comp arm). A byte past the
/// value length emits nothing.
#[expect(clippy::too_many_arguments)]
fn emit_flash_output_or_comp(
  sub: &[u8],
  offset: usize,
  mode: Option<i64>,
  print_conv: bool,
  order: ByteOrder,
  output_name: &'static str,
  comp_name: &'static str,
  comp_conv: NikonConv,
  emissions: &mut Vec<VendorEmission>,
) {
  let Some(&byte) = sub.get(offset) else {
    return;
  };
  if mode.is_some_and(|m| m >= 0x06) {
    // The `Manual`-arm `FlashOutput` (int8u).
    let parsed = ParsedValue::new(RawValue::U64(std::vec![u64::from(byte)]));
    if let Some(value) = NikonConv::FlashOutput.apply(&parsed, print_conv, None, order) {
      emissions.push(VendorEmission::new(output_name.into(), value, false));
    }
  } else {
    // The `Compensation`-arm (int8s `Format` override — the byte is signed).
    let parsed = ParsedValue::new(RawValue::I64(std::vec![i64::from(byte as i8)]));
    if let Some(value) = comp_conv.apply(&parsed, print_conv, None, order) {
      emissions.push(VendorEmission::new(comp_name.into(), value, false));
    }
  }
}

/// The decryption keys captured for the encrypted Nikon sub-tables —
/// ExifTool's `$$et{NikonSerialKey}` (the derived serial key) and
/// `$$et{NikonCountKey}` (the raw ShutterCount).
#[derive(Debug, Clone, Copy)]
struct DecryptKeys {
  /// `SerialKey($et, SerialNumber)` (`Nikon.pm:14202`) — the serial key, after
  /// the numeric/string derivation ([`decrypt::serial_key`]).
  serial: u32,
  /// `ShutterCount` (0x00a7) raw value (`Nikon.pm:14203`) — the count key.
  count: u32,
}

/// Capture the decryption keys via ExifTool's `PrescanExif` pre-scan
/// (`Nikon.pm:14199-14203`): the `SerialNumber` (0x001d) `ReadValue` `$val` →
/// the `SerialKey` derivation, and the `ShutterCount` (0x00a7) `$val` → the
/// count key. Returns `None` only when no usable `ShutterCount` (0x00a7) is
/// present; an ABSENT `SerialNumber` defaults to serial key 0 (ExifTool seeds
/// its prescan with `0x001d => 0`), so encrypted LensData still decrypts
/// without `0x001d`.
///
/// The capture runs over the RAW IFD via [`body::prescan_decrypt_keys`], NOT the
/// post-`walk_nikon_ifd` entries: ExifTool's prescan uses LOOSER entry gates than
/// the main walk (no suspicious-offset / excessive-count / warn-abort), so a
/// 0x001d / 0x00a7 the walk would drop is still keyed here (see that function).
/// Both keys derive from the post-`ReadValue` `$val` STRING (`Nikon.pm:14122`),
/// FORMAT-AGNOSTIC: an integer-format `0x001d`/`0x00a7` renders to its decimal,
/// an ASCII one to its string, so a present-but-integer serial and an ASCII-digit
/// count feed `SerialKey` and the `/^\d+$/` count test just like the native
/// format (see [`decrypt::serial_key`] and [`ParsedValue::single_digit_count`]).
///
/// `model` threads IFD0 `Model` for the `SerialKey` `D50` discriminator.
fn scan_decrypt_keys(
  blob: &[u8],
  ifd_offset: usize,
  order: ByteOrder,
  value_base: usize,
  model: Option<&str>,
) -> Option<DecryptKeys> {
  // ExifTool captures the keys with a SEPARATE PrescanExif pass over the raw IFD
  // (NOT the main extraction walk) — see [`body::prescan_decrypt_keys`].
  let (serial_val, count_val) = body::prescan_decrypt_keys(blob, ifd_offset, order, value_base);
  // `%needTags = (0x001d => 0, …)` (`Nikon.pm:14200`): the prescan seeds
  // `0x001d => 0`, so a TRULY ABSENT — or gated-out — `SerialNumber` decrypts
  // with serial key 0 (`SerialKey($et, 0)` ⇒ 0). A PRESENT 0x001d feeds
  // `SerialKey` its format-agnostic `ReadValue` `$val` (ASCII string or rendered
  // integer), yielding the digit value or the D50/0x60 string fallback;
  // `serial_key` is always `Some`, so `unwrap_or(0x60)` never fires.
  let serial = match serial_val {
    Some(raw) => {
      let rendered = raw.val_bytes();
      let s = std::string::String::from_utf8_lossy(&rendered);
      decrypt::serial_key(&s, model).unwrap_or(0x60)
    }
    None => 0,
  };
  // `$$et{NikonCountKey} = $needTags{0x00a7}` (`:14203`), gated by
  // `$count =~ /^\d+$/` in `ProcessNikonEncrypted` (`:13948`): only a SINGLE
  // all-digit `ShutterCount` unlocks decryption (a multi-element `int32u[2]` ⇒
  // `"100 0"`, a negative, or a non-digit value fails and leaves it undefined).
  let count = count_val.and_then(|raw| ParsedValue::new(raw).single_digit_count())?;
  Some(DecryptKeys { serial, count })
}

/// The `%Nikon::LensData*` layout the 4-byte `LensDataVersion` prefix selects
/// — the faithful port of the `0x0098` conditional SubDirectory list
/// (`Nikon.pm:2814-2899`). Each arm carries its member table, whether the body
/// after the version is encrypted (`ProcessProc => \&ProcessNikonEncrypted` +
/// `DecryptStart => 4`), and the table's `ByteOrder` (only `0800` overrides it
/// to LittleEndian — but every PORTED `0800` member is a single byte, so the
/// override is recorded for fidelity and is a no-op on those reads).
struct LensDataLayout {
  /// The member positions to read off the (decrypted) block.
  table: &'static [tags::LensDataEntry],
  /// `true` when the body after the 4-byte version is encrypted
  /// (`DecryptStart => 4`); decrypt with the captured serial/count keys first.
  encrypted: bool,
  /// `Some` when this `0800` layout gates its members on the forward-looking
  /// `$$self{OldLensData}` flag (`Nikon.pm:5726-5731`): the `undef[17]` at this
  /// offset sets the flag UNLESS it is `/^.\0+$/s` (first byte anything, the
  /// other 16 all NUL). When the flag is clear the gated members are skipped.
  old_lens_data_gate: Option<usize>,
  /// `true` for the `0800` (Z6/Z7/Z9) layout, which ALSO carries the NEW Z-lens
  /// telemetry block (offsets 0x2f onward — `NewLensData`, `LensID` int16u + the
  /// `FocusMode`-gated focus telemetry, `Nikon.pm:5809-5961`). Decoded by
  /// [`emit_lens_data_0800_new`] after the legacy block.
  has_z_block: bool,
  /// The SubDirectory's `ByteOrder` (`MakerNotes.pm`/`Nikon.pm:2887` —
  /// `0800` overrides it to `LittleEndian`; every other LensData table inherits
  /// the parent MakerNote IFD's order). Drives the MULTI-BYTE Z-block reads
  /// (int16u/int32s); the legacy block's int8u members are order-agnostic.
  order: Option<ByteOrder>,
}

/// Resolve the `LensDataVersion` prefix to its [`LensDataLayout`]
/// (`Nikon.pm:2814-2899`). NEVER returns `None` for a readable 4-byte version —
/// an unrecognized version falls through to the `LensDataUnknown` arm
/// (`Nikon.pm:2890-2898`), which emits ONLY `LensDataVersion` (its table has no
/// other member), so no `0x0098` SubDirectory is ever silently dropped.
fn lens_data_layout(version: &[u8; 4]) -> LensDataLayout {
  match version {
    b"0100" => LensDataLayout {
      table: tags::LENS_DATA_00,
      encrypted: false,
      old_lens_data_gate: None,
      has_z_block: false,
      order: None,
    },
    b"0101" => LensDataLayout {
      table: tags::LENS_DATA_01,
      encrypted: false,
      old_lens_data_gate: None,
      has_z_block: false,
      order: None,
    },
    // `$$valPt =~ /^020[1-3]/` — encrypted, read against `%LensData01`.
    [b'0', b'2', b'0', b'1' | b'2' | b'3'] => LensDataLayout {
      table: tags::LENS_DATA_01,
      encrypted: true,
      old_lens_data_gate: None,
      has_z_block: false,
      order: None,
    },
    // `$$valPt =~ /^0204/` (D90, D7000) — `%LensData0204`.
    b"0204" => LensDataLayout {
      table: tags::LENS_DATA_0204,
      encrypted: true,
      old_lens_data_gate: None,
      has_z_block: false,
      order: None,
    },
    // `$$valPt =~ /^040[01]/` (Nikon 1 J1/V1/J2) — `%LensData0400`.
    [b'0', b'4', b'0', b'0' | b'1'] => LensDataLayout {
      table: tags::LENS_DATA_0400,
      encrypted: true,
      old_lens_data_gate: None,
      has_z_block: false,
      order: None,
    },
    // `$$valPt =~ /^0402/` (Nikon 1 J3/S1/V2) — `%LensData0402`.
    b"0402" => LensDataLayout {
      table: tags::LENS_DATA_0402,
      encrypted: true,
      old_lens_data_gate: None,
      has_z_block: false,
      order: None,
    },
    // `$$valPt =~ /^0403/` (Nikon 1 J4/J5) — `%LensData0403`.
    b"0403" => LensDataLayout {
      table: tags::LENS_DATA_0403,
      encrypted: true,
      old_lens_data_gate: None,
      has_z_block: false,
      order: None,
    },
    // `$$valPt =~ /^080[012]/` (Z6/Z7/Z9) — `%LensData0800` (LittleEndian, the
    // `ByteOrder => 'LittleEndian'` SubDirectory override, `Nikon.pm:2887`). The
    // legacy OldLensData block is gated on the `undef[17]` at 0x03; the NEW Z
    // telemetry block (0x2f onward) is decoded by [`emit_lens_data_0800_new`].
    [b'0', b'8', b'0', b'0' | b'1' | b'2'] => LensDataLayout {
      table: tags::LENS_DATA_0800_OLD,
      encrypted: true,
      old_lens_data_gate: Some(0x03),
      has_z_block: true,
      order: Some(ByteOrder::Little),
    },
    // `LensDataUnknown` fallback (`Nikon.pm:2890-2898`) — emit ONLY the version.
    _ => LensDataLayout {
      table: &[],
      encrypted: true,
      old_lens_data_gate: None,
      has_z_block: false,
      order: None,
    },
  }
}

/// `$$self{OldLensData}` (`Nikon.pm:5726-5731`): the forward-looking `undef[17]`
/// RawConv sets the flag UNLESS the 17 bytes are `/^.\0+$/s` — i.e. the first
/// byte is anything and bytes 1..17 are ALL NUL. A block too short to hold the
/// 17 bytes leaves the flag unset (the `Format => 'undef[17]'` read fails),
/// matching ExifTool's `last`-on-short-read in `ProcessBinaryData`.
fn old_lens_data_present(body: &[u8], gate_offset: usize) -> bool {
  let end = gate_offset.saturating_add(17);
  let Some(window) = body.get(gate_offset..end) else {
    return false;
  };
  // `/^.\0+$/s`: at least the lead byte + one NUL, and every byte after the
  // first is NUL. `OldLensData` is set when this does NOT match — i.e. some
  // byte from index 1 onward is non-zero.
  match window.split_first() {
    Some((_lead, rest)) => rest.iter().any(|&b| b != 0),
    None => false,
  }
}

/// Emit the `%Nikon::LensData*` leaves (0x0098). The `LensDataVersion` (first 4
/// ASCII bytes, `Format => 'string[4]'`) version-dispatches the layout exactly
/// as `Nikon.pm:2814-2899` does:
///
/// - `0100` → [`tags::LENS_DATA_00`], UNENCRYPTED.
/// - `0101` → [`tags::LENS_DATA_01`], UNENCRYPTED.
/// - `020[1-3]` → [`tags::LENS_DATA_01`], `040[01]`/`0402`/`0403`/`0204`/
///   `080[012]` → their own tables — all ENCRYPTED: the bytes AFTER the 4-byte
///   version are DECRYPTED first ([`decrypt::decrypt`] with `DecryptStart => 4`,
///   `Nikon.pm:2836`) using the captured serial/count keys.
/// - ANY other version → the `LensDataUnknown` arm (`Nikon.pm:2890`), an empty
///   member table — ENCRYPTED (`ProcessProc => \&ProcessNikonEncrypted`,
///   `DecryptStart => 4`), so ONLY `LensDataVersion` is emitted, and only when
///   the decryption keys are valid.
///
/// `LensDataVersion` is emitted for a readable 4-byte version of an UNENCRYPTED
/// layout (`0100`/`0101`) unconditionally, and of an ENCRYPTED layout ONLY once
/// the serial/count key gate has passed. An encrypted layout without valid keys
/// emits NOTHING — not even `LensDataVersion`: ExifTool's `ProcessNikonEncrypted`
/// returns 0 before its callback reads the cleartext `string[4]` at offset 0
/// (`Nikon.pm:13948-13961`), so the whole `0x0098` SubDirectory yields no tags.
/// The maximum byte offset a [`LensDataLayout`] actually reads — the largest
/// member `offset + size` in its table, plus the `0800` Z telemetry's
/// `0x60`-byte window (it reads up to `LensMountType` at `0x5f`). Used to cap
/// the encrypted-blob clone + decrypt to ONLY the bytes the decode consumes, so
/// a crafted in-bounds LensData value near the size ceiling cannot force a large
/// heap copy + linear decrypt of bytes that are never read. The stream cipher is
/// causal (each byte's keystream depends only on earlier bytes), so decrypting
/// the needed prefix is byte-identical to decrypting the whole block.
fn lens_data_read_extent(plan: &LensDataLayout) -> usize {
  let table_max = plan
    .table
    .iter()
    .map(|e| {
      e.offset
        + match &e.read {
          tags::LensRead::Byte => 1,
          tags::LensRead::Str(len) => *len,
        }
    })
    .max()
    .unwrap_or(0);
  // The `0800` Z telemetry ([`emit_lens_data_0800_new`]) reads up to
  // `LensMountType` at `0x5f` (one byte ⇒ `0x60`).
  let z_max = if plan.has_z_block { 0x60 } else { 0 };
  table_max.max(z_max)
}

fn emit_lens_data(
  walk_data: &[u8],
  entry: &NikonEntry,
  layout: Layout,
  print_conv: bool,
  keys: Option<DecryptKeys>,
  focus_mode: Option<&str>,
  emissions: &mut Vec<VendorEmission>,
) {
  let Some(sub) = walk_data.get(entry.value_offset..entry.value_offset + entry.value_size) else {
    return;
  };
  // `LensDataVersion` = the first 4 ASCII bytes (`Format => 'string[4]'`).
  let Some(version) = sub.get(0..4).and_then(|v| <&[u8; 4]>::try_from(v).ok()) else {
    return;
  };
  let plan = lens_data_layout(version);
  // An ENCRYPTED layout (every `02xx`/`04xx`/`08xx` arm AND the LensDataUnknown
  // fallback — all `ProcessProc => \&ProcessNikonEncrypted`, `Nikon.pm:2834-
  // 2897`) is processed by `ProcessNikonEncrypted`, which RETURNS 0 (extracting
  // NOTHING — not even the cleartext `LensDataVersion` at offset 0) when the
  // serial/count keys are missing/invalid (`Nikon.pm:13948-13961`). The keys
  // are valid IFF `scan_decrypt_keys` returned `Some` (the serial defaults to 0
  // and the count is a single `/^\d+$/` scalar), so gate the WHOLE emission on
  // it BEFORE pushing `LensDataVersion`. An UNENCRYPTED layout (`0100`/`0101`)
  // uses plain `ProcessBinaryData` with no key check, so it always emits.
  let valid_keys = if plan.encrypted {
    let Some(keys) = keys else {
      return; // ProcessNikonEncrypted returned 0 — emit nothing at all.
    };
    Some(keys)
  } else {
    None
  };
  // `LensDataVersion` itself is emitted as the 4-char ASCII string (it is never
  // encrypted, so read from the original cleartext `version` bytes). This is
  // emitted for EVERY readable 4-byte version once the key gate (encrypted
  // layouts) has passed — incl. the LensDataUnknown fallback, so no decryptable
  // `0x0098` SubDirectory is silently dropped.
  let version_str = SmolStr::new(String::from_utf8_lossy(version));
  emissions.push(VendorEmission::new(
    "LensDataVersion".into(),
    TagValue::Str(version_str),
    false,
  ));
  if plan.table.is_empty() {
    return; // LensDataUnknown — only the version, no members.
  }
  // The decoded body buffer: the raw bytes for an unencrypted layout, or a
  // decrypted copy for the `02xx`+ layouts. The 4-byte version prefix is NEVER
  // encrypted (`DecryptStart => 4`).
  let decoded: std::borrow::Cow<'_, [u8]> = if let Some(keys) = valid_keys {
    // Cap the clone+decrypt to the byte range this layout actually reads
    // (R2: a crafted in-bounds LensData value near the size ceiling otherwise
    // forces a large heap copy + linear decrypt of bytes never read).
    let cap = lens_data_read_extent(&plan).min(sub.len());
    let mut buf = sub.get(..cap).unwrap_or(sub).to_vec();
    let len = buf.len().saturating_sub(4);
    decrypt::decrypt(&mut buf, 4, len, keys.serial, keys.count);
    std::borrow::Cow::Owned(buf)
  } else {
    std::borrow::Cow::Borrowed(sub)
  };
  let body = decoded.as_ref();
  // The byte order for MULTI-BYTE members: the SubDirectory's `ByteOrder` when
  // the layout overrides it (`0800` ⇒ LittleEndian, `Nikon.pm:2887`), else the
  // parent MakerNote IFD's order. The legacy block's int8u members are
  // order-agnostic, but the Z block's int16u/int32s reads need it.
  let sub_order = plan.order.unwrap_or(layout.order);
  // The `0800` OldLensData members are gated on the forward-looking flag; when
  // it is clear (the `undef[17]` is `/^.\0+$/`), skip the LEGACY block (no member
  // emits) — but the NEW Z telemetry below is INDEPENDENTLY gated on
  // `NewLensData`, so it is still decoded. (`ProcessBinaryData` walks every
  // table key; only the per-member `Condition` decides emission.)
  let legacy_gate_open = plan
    .old_lens_data_gate
    .is_none_or(|gate| old_lens_data_present(body, gate));
  if legacy_gate_open {
    for pos in plan.table {
      match pos.read {
        // The default `int8u` member: a single byte at its offset. The sub-table
        // byte order does not affect a one-byte read. Read from `body`
        // (post-decrypt for the encrypted layouts).
        tags::LensRead::Byte => {
          let Some(&byte) = body.get(pos.offset) else {
            continue; // member past the (short) block — emit nothing for it.
          };
          let raw = RawValue::U64(std::vec![u64::from(byte)]);
          let parsed = ParsedValue::new(raw);
          let Some(value) = pos.conv.apply(&parsed, print_conv, None, layout.order) else {
            continue;
          };
          emissions.push(VendorEmission::new(pos.name.into(), value, false));
        }
        // `LensModel`, `Format => 'string[len]'`: `len` ASCII bytes, NUL-truncated
        // (`ReadValue`'s `s/\0.*//s`). An entirely-empty (all-NUL) field yields the
        // empty string, which ExifTool still emits (the `040x`/`0402`/`0403`
        // tables have no RawConv suppressing it).
        tags::LensRead::Str(len) => {
          let end = pos.offset.saturating_add(len);
          let Some(window) = body.get(pos.offset..end) else {
            continue; // field runs past the (short) block — drop it.
          };
          let trimmed = match window.iter().position(|&b| b == 0) {
            Some(nul) => window.get(..nul).unwrap_or(window),
            None => window,
          };
          let value = TagValue::Str(SmolStr::from(crate::convert::fix_utf8(trimmed)));
          emissions.push(VendorEmission::new(pos.name.into(), value, false));
        }
      }
    }
  }
  // The NEW Z-lens telemetry block (`Nikon.pm:5809-5961`) — only the `0800`
  // layout carries it; gated internally on `NewLensData`/`LensID`/`FocusMode`.
  if plan.has_z_block {
    emit_lens_data_0800_new(body, sub_order, print_conv, focus_mode, emissions);
  }
}

/// Decode the NEW Z-lens telemetry of `%Nikon::LensData0800` (`Nikon.pm:5809-
/// 5961`) off the DECRYPTED block `body`, in the SubDirectory's `order`
/// (LittleEndian for `0800`). This is the faithful port of `ProcessBinaryData`
/// over the table keys `0x2f..=0x5f`, honouring the DATAMEMBER state machine and
/// each member's `Condition`/`Format`/`ValueConv`/`PrintConv`/`Mask`:
///
/// - `0x2f` `NewLensData` (`undef[17]`, RawConv `$$self{NewLensData} = 1 unless
///   $val =~ /^.\0+$/s`) — the forward-looking flag that gates the rest. Hidden.
/// - `0x30` `LensID` (`int16u`, `Condition => $$self{NewLensData}`, RawConv
///   `$$self{LensID} = $val`) — the ~80-entry Z-lens PrintConv
///   ([`NikonConv::LensId`]). A non-zero LensID ⇒ a native Z lens.
/// - `0x34` `LensFirmwareVersion` (`int16u`, `Condition => $$self{LensID} and
///   $$self{LensID} != 0`) — the V.R.M PrintConv ([`NikonConv::LensFirmwareZ`]).
/// - `0x36` `MaxAperture` / `0x38` `FNumber` (`int16u`, `Condition =>
///   $$self{NewLensData}`, `2**($val/384-1)`, [`NikonConv::LensApertureZ`]).
/// - `0x3c` `FocalLength` (`int16u`, `Condition => $$self{NewLensData}`,
///   PrintConv `"$val mm"`, [`NikonConv::FocalLengthZ`]).
/// - `0x4c` `FocusDistanceRangeWidth` (`int8u`, `Unknown => 1`, `Condition =>
///   $$self{LensID} … and $$self{FocusMode} ne "Manual"`).
/// - `0x4e` `FocusDistance` (`int16u`, `Condition => $$self{LensID} …`, RawConv
///   `$val/256` then `2**(($val-80)/12)`, [`NikonConv::FocusDistanceZ`]).
/// - `0x56` `LensDriveEnd` (`int8u`, `Unknown => 1`, `Condition => … FocusMode
///   ne "Manual"`) — the `No`/`CFD`/`Inf` RawConv label.
/// - `0x58` `FocusStepsFromInfinity` (`int8u`, `Unknown => 1`, `Condition =>
///   $$self{LensID} …`).
/// - `0x5a` `LensPositionAbsolute` (`int32s`, `Condition => $$self{LensID} …`).
/// - `0x5f` `LensMountType` (`int8u`, `Mask => 0x01`, `{0=>'Z-mount',
///   1=>'F-mount'}`).
///
/// The three `Unknown => 1` members (0x4c/0x56/0x58) are emitted with the
/// `unknown` flag so the engine suppresses them from default output but keeps
/// them under `-u` — byte-exact with ExifTool's default `-j` (`ProcessBinaryData`
/// `next if $$tagInfo{Unknown}` at `ExifTool.pm:9945` for `Unknown=0`).
fn emit_lens_data_0800_new(
  body: &[u8],
  order: ByteOrder,
  print_conv: bool,
  focus_mode: Option<&str>,
  emissions: &mut Vec<VendorEmission>,
) {
  // `0x2f` NewLensData (`undef[17]`): set the flag UNLESS `/^.\0+$/s` (the lead
  // byte is anything and bytes 1..17 are all NUL) — the same forward-look test
  // as OldLensData. A block too short to hold the 17 bytes leaves it clear
  // (the `Format => 'undef[17]'` read fails ⇒ no DataMember set).
  let new_lens_data = old_lens_data_present(body, 0x2f);
  // `0x30` LensID (`int16u`, `Condition => $$self{NewLensData}`, RawConv
  // `$$self{LensID} = $val`). Read only when NewLensData is set; an absent /
  // short-block / NewLensData-clear LensID leaves it `None`, which suppresses
  // every LensID-gated member below. NOTE: we do NOT early-return on a clear
  // NewLensData — `LensMountType` (0x5f) has NO `Condition` in ExifTool, so it
  // must still be emitted when byte 0x5f is present (R3 fix).
  let lens_id: Option<u16> = if new_lens_data {
    read_z_int16u(body, 0x30, order)
  } else {
    None
  };
  if let Some(id) = lens_id {
    let raw = RawValue::U64(std::vec![u64::from(id)]);
    let parsed = ParsedValue::new(raw);
    if let Some(value) = NikonConv::LensId.apply(&parsed, print_conv, None, order) {
      emissions.push(VendorEmission::new("LensID".into(), value, false));
    }
  }
  // `$$self{LensID} and $$self{LensID} != 0` — the native-Z-lens gate shared by
  // 0x34/0x4c/0x4e/0x56/0x58/0x5a.
  let z_lens = lens_id.is_some_and(|id| id != 0);
  // `$$self{FocusMode} ne "Manual"` — an ABSENT FocusMode is `undef ne
  // "Manual"` = TRUE in Perl, so the gate is open unless FocusMode is exactly
  // "Manual" (the RAW on-disk string).
  let not_manual = focus_mode != Some("Manual");

  // `0x34` LensFirmwareVersion (`int16u`, `Condition => $$self{LensID} and
  // $$self{LensID} != 0`).
  if z_lens {
    emit_z_int16u(
      body,
      0x34,
      order,
      print_conv,
      NikonConv::LensFirmwareZ,
      false,
      "LensFirmwareVersion",
      emissions,
    );
  }
  // `0x36` MaxAperture / `0x38` FNumber / `0x3c` FocalLength — gated on
  // `$$self{NewLensData}`.
  if new_lens_data {
    emit_z_int16u(
      body,
      0x36,
      order,
      print_conv,
      NikonConv::LensApertureZ,
      false,
      "MaxAperture",
      emissions,
    );
    emit_z_int16u(
      body,
      0x38,
      order,
      print_conv,
      NikonConv::LensApertureZ,
      false,
      "FNumber",
      emissions,
    );
    emit_z_int16u(
      body,
      0x3c,
      order,
      print_conv,
      NikonConv::FocalLengthZ,
      false,
      "FocalLength",
      emissions,
    );
  }
  // `0x4c` FocusDistanceRangeWidth (`int8u`, `Unknown => 1`, gated on z_lens AND
  // FocusMode ne "Manual"). Its RawConv sets `$$self{FocusDistanceRangeWidth}`,
  // but that DataMember is consumed only by LensDriveEnd's RawConv (handled
  // there); the Unknown flag suppresses it from default output.
  if z_lens && not_manual {
    emit_z_int8u(
      body,
      0x4c,
      print_conv,
      NikonConv::Raw,
      true,
      "FocusDistanceRangeWidth",
      emissions,
    );
  }
  // `0x4e` FocusDistance (`int16u`, gated on z_lens). The PrintConv references
  // `$$self{FocusStepsFromInfinity}`, which is `Unknown => 1` and therefore NEVER
  // set in default mode (`next if Unknown` at `ExifTool.pm:9945`), so the "Inf"
  // branch is unreachable — [`NikonConv::FocusDistanceZ`] formats accordingly.
  if z_lens {
    emit_z_int16u(
      body,
      0x4e,
      order,
      print_conv,
      NikonConv::FocusDistanceZ,
      false,
      "FocusDistance",
      emissions,
    );
  }
  // `0x56` LensDriveEnd (`int8u`, `Unknown => 1`, gated on z_lens AND not
  // Manual). STATEFUL RawConv (`Nikon.pm:5933-5939`):
  //   unless (defined $$self{FocusDistanceRangeWidth}
  //           and not $$self{FocusDistanceRangeWidth}) {
  //     if ($val == 0) { $$self{LensDriveEnd} = "No" }
  //     else           { $$self{LensDriveEnd} = "CFD" }
  //   } else           { $$self{LensDriveEnd} = "Inf" }
  // The RawConv's RETURN value (a Perl assignment yields its RHS) is the emitted
  // `$val` — the STRING "No"/"CFD"/"Inf", NOT the raw int8u. It reads the 0x4c
  // `FocusDistanceRangeWidth` DataMember, set by 0x4c's RawConv `$$self{...} =
  // $val`. That DataMember is set ONLY when 0x4c is EXTRACTED; 0x4c is `Unknown
  // => 1`, so it is set IFF the member survives the binary-table Unknown gate
  // (`ExifTool.pm:9945` `next if Unknown and Unknown > $unknown`). LensDriveEnd
  // is ITSELF `Unknown => 1` ⇒ observable only under `-u`, and in `-u` the
  // lower-index 0x4c is ALSO extracted and runs FIRST, so whenever LensDriveEnd
  // is visible its DataMember IS defined = the raw byte at 0x4c (byte 0x56 sits
  // above 0x4c, so reaching 0x56 guarantees 0x4c is in-block). Thus the faithful
  // mapping reads BOTH bytes off the same decrypted `body`:
  //   FocusDistanceRangeWidth(0x4c) == 0 → "Inf";
  //   else LensDriveEnd(0x56) == 0      → "No"; else → "CFD".
  // exifast has NO `-u` mode — the engine ALWAYS drops `Unknown => 1` tags
  // (`run_emission`'s `if e.unknown() { continue }`), so LensDriveEnd NEVER
  // reaches output; it is emitted (unknown-flagged) and converted faithfully for
  // correctness, exercised directly via [`lens_drive_end`].
  if z_lens
    && not_manual
    && let Some(&byte) = body.get(0x56)
  {
    let focus_distance_range_width = body.get(0x4c).copied();
    let label = lens_drive_end(byte, focus_distance_range_width);
    emissions.push(VendorEmission::new(
      "LensDriveEnd".into(),
      TagValue::Str(SmolStr::new(label)),
      true,
    ));
  }
  // `0x58` FocusStepsFromInfinity (`int8u`, `Unknown => 1`, gated on z_lens).
  if z_lens {
    emit_z_int8u(
      body,
      0x58,
      print_conv,
      NikonConv::Raw,
      true,
      "FocusStepsFromInfinity",
      emissions,
    );
  }
  // `0x5a` LensPositionAbsolute (`int32s`, gated on z_lens). NOT Unknown.
  if z_lens {
    emit_z_int32s(
      body,
      0x5a,
      order,
      print_conv,
      "LensPositionAbsolute",
      emissions,
    );
  }
  // `0x5f` LensMountType (`int8u`, `Mask => 0x01`, `{0=>'Z-mount',1=>'F-mount'}`).
  // NO Condition — always emitted when the byte is present. The Mask is applied
  // BEFORE the PrintConv (`ExifTool.pm:10079` `$val = ($val & $mask) >> 0`).
  if let Some(&byte) = body.get(0x5f) {
    let masked = i64::from(byte & 0x01);
    let raw = RawValue::I64(std::vec![masked]);
    let parsed = ParsedValue::new(raw);
    if let Some(value) = NikonConv::LensMountType.apply(&parsed, print_conv, None, order) {
      emissions.push(VendorEmission::new("LensMountType".into(), value, false));
    }
  }
}

/// Read an `int16u` member at `offset` off the decrypted Z block in `order`
/// (the faithful `ReadValue($dataPt, $entry, 'int16u', 1, $more)`). `None` when
/// the 2 bytes do not fit (a short block — `ProcessBinaryData` `last if $more <=
/// 0`), so the member emits nothing.
fn read_z_int16u(body: &[u8], offset: usize, order: ByteOrder) -> Option<u16> {
  let avail = body.len().checked_sub(offset)?;
  let raw = read_value(body, offset, Format::Int16u, 1, avail, order)?;
  match raw {
    RawValue::U64(v) => v.first().and_then(|&n| u16::try_from(n).ok()),
    _ => None,
  }
}

/// Emit one `int16u` Z member: read it in `order`, apply `conv`, push under
/// `name` with the `unknown` flag. A short block (member past the end) emits
/// nothing.
fn emit_z_int16u(
  body: &[u8],
  offset: usize,
  order: ByteOrder,
  print_conv: bool,
  conv: NikonConv,
  unknown: bool,
  name: &'static str,
  emissions: &mut Vec<VendorEmission>,
) {
  let Some(n) = read_z_int16u(body, offset, order) else {
    return;
  };
  let raw = RawValue::U64(std::vec![u64::from(n)]);
  let parsed = ParsedValue::new(raw);
  if let Some(value) = conv.apply(&parsed, print_conv, None, order) {
    emissions.push(VendorEmission::new(name.into(), value, unknown));
  }
}

/// Emit one `int8u` Z member at `offset` (the default `FORMAT => 'int8u'`): a
/// single byte, order-agnostic. A short block emits nothing.
fn emit_z_int8u(
  body: &[u8],
  offset: usize,
  print_conv: bool,
  conv: NikonConv,
  unknown: bool,
  name: &'static str,
  emissions: &mut Vec<VendorEmission>,
) {
  let Some(&byte) = body.get(offset) else {
    return;
  };
  let raw = RawValue::U64(std::vec![u64::from(byte)]);
  let parsed = ParsedValue::new(raw);
  if let Some(value) = conv.apply(&parsed, print_conv, None, ByteOrder::Little) {
    emissions.push(VendorEmission::new(name.into(), value, unknown));
  }
}

/// The `0x56` `LensDriveEnd` RawConv (`Nikon.pm:5933-5939`) — the STATEFUL
/// label derived from the `LensDriveEnd` byte (`val`) and the `0x4c`
/// `FocusDistanceRangeWidth` DataMember (`fdrw`, the raw byte at 0x4c, `None`
/// when undefined — but see [`emit_lens_data_0800_new`]: when LensDriveEnd is
/// reached, 0x4c is always in-block, so `fdrw` is `Some`):
///
/// ```text
/// unless (defined $fdrw and not $fdrw) {       # !(fdrw defined && fdrw == 0)
///     if ($val == 0) { "No" } else { "CFD" }
/// } else { "Inf" }                              #   fdrw defined && fdrw == 0
/// ```
///
/// i.e. `Inf` iff `FocusDistanceRangeWidth` is defined and `0`; otherwise `No`
/// for `val == 0` and `CFD` for `val != 0`. Returns the `&'static str` the
/// RawConv's terminal assignment yields (the emitted `$val`).
#[must_use]
const fn lens_drive_end(val: u8, fdrw: Option<u8>) -> &'static str {
  match fdrw {
    Some(0) => "Inf",
    _ if val == 0 => "No",
    _ => "CFD",
  }
}

/// Emit `LensPositionAbsolute` (`0x5a`, `int32s`): read 4 bytes in `order` as a
/// signed int, no ValueConv/PrintConv (rendered as the bare integer). A short
/// block emits nothing.
fn emit_z_int32s(
  body: &[u8],
  offset: usize,
  order: ByteOrder,
  print_conv: bool,
  name: &'static str,
  emissions: &mut Vec<VendorEmission>,
) {
  let avail = match body.len().checked_sub(offset) {
    Some(a) => a,
    None => return,
  };
  let Some(raw) = read_value(body, offset, Format::Int32s, 1, avail, order) else {
    return;
  };
  let parsed = ParsedValue::new(raw);
  // No ValueConv/PrintConv on LensPositionAbsolute ⇒ the default `ReadValue`
  // render (the signed integer).
  if let Some(value) = NikonConv::Raw.apply(&parsed, print_conv, None, order) {
    emissions.push(VendorEmission::new(name.into(), value, false));
  }
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

  /// A deferred (encrypted) SubDirectory pointer (ShotInfo 0x0091) emits
  /// NEITHER a parent NOR children — the #177/#223 bogus-parent rule. (LensData
  /// 0x0098 defers only the PARENT; FlashInfo 0x00a8 is now WALKED — see
  /// [`flash_info_0100_decodes`].)
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

  // ---- LensData version-dispatch (0x0098) ---------------------------------
  //
  // Each test crafts a self-contained type-3 Nikon blob carrying SerialNumber
  // (0x001d), ShutterCount (0x00a7) and a LensData (0x0098) block whose
  // encrypted body was produced by ENCRYPTING a known plaintext with this
  // module's own symmetric `decrypt` (the `cipher_is_symmetric` property), so
  // the decode round-trips a KNOWN field set. The expected rendered values are
  // the `perl exiftool 13.59` oracle (verified out-of-band on the identical
  // crafted bytes — see the issue-#227 verification notes).

  /// The crafted-blob serial/count keys (numeric serial `12345678` ⇒ the key is
  /// the integer itself; ShutterCount `100`).
  const KEY_SERIAL: u32 = 12_345_678;
  const KEY_COUNT: u32 = 100;

  /// Build a self-contained type-3 Nikon blob (the `parse()` standalone path)
  /// with SerialNumber=`12345678`, ShutterCount=`100`, and a `0x0098` LensData
  /// value of `lens_block` (the version prefix + already-encrypted body, or a
  /// cleartext body for the unencrypted `0100`/`0101`).
  fn type3_with_lens_data(lens_block: &[u8]) -> Vec<u8> {
    // Embedded TIFF (big-endian) at blob offset 10; IFD0 at embedded+8 (blob
    // 18). Out-of-line value offsets are embedded-relative (value_base 10).
    let serial = b"12345678\x00"; // 9 bytes (out-of-line)
    let n_entries: u16 = 3;
    // value area begins after count(2) + 3*12 + next(4) = 42 ⇒ embedded 8+42=50.
    let val_emb: u32 = 8 + 2 + u32::from(n_entries) * 12 + 4;
    let off_serial = val_emb;
    let off_lens = off_serial + serial.len() as u32;
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"Nikon\x00\x02\x10\x00\x00"); // 10-byte type-3 header
    b.extend_from_slice(b"MM");
    b.extend_from_slice(&[0x00, 0x2a]);
    b.extend_from_slice(&8u32.to_be_bytes()); // IFD0 at embedded+8
    b.extend_from_slice(&n_entries.to_be_bytes());
    // 0x001d SerialNumber — ASCII, out-of-line.
    b.extend_from_slice(&0x001du16.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x02]); // string
    b.extend_from_slice(&(serial.len() as u32).to_be_bytes());
    b.extend_from_slice(&off_serial.to_be_bytes());
    // 0x0098 LensData — undef, out-of-line.
    b.extend_from_slice(&0x0098u16.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x07]); // undef
    b.extend_from_slice(&(lens_block.len() as u32).to_be_bytes());
    b.extend_from_slice(&off_lens.to_be_bytes());
    // 0x00a7 ShutterCount — int32u, inline = 100.
    b.extend_from_slice(&0x00a7u16.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x04]); // int32u
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&KEY_COUNT.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD
    debug_assert_eq!(b.len() as u32, 10 + off_serial);
    b.extend_from_slice(serial);
    b.extend_from_slice(lens_block);
    b
  }

  /// Like [`type3_with_lens_data`] but ALSO carries a `FocusMode` (tag 0x0007)
  /// string so the LensData0800 Z `FocusMode ne "Manual"` gate can be exercised.
  /// `focus_mode` is the RAW on-disk bytes (NUL-terminated as the camera writes
  /// it). Four out-of-line entries in tag-ID order: 0x0007, 0x001d, 0x0098, plus
  /// the inline 0x00a7.
  fn type3_with_focus_mode_and_lens_data(focus_mode: &[u8], lens_block: &[u8]) -> Vec<u8> {
    let serial = b"12345678\x00"; // 9 bytes (out-of-line)
    let n_entries: u16 = 4;
    // value area begins after count(2) + 4*12 + next(4) = 54 ⇒ embedded 8+54=62.
    let val_emb: u32 = 8 + 2 + u32::from(n_entries) * 12 + 4;
    let off_focus = val_emb;
    let off_serial = off_focus + focus_mode.len() as u32;
    let off_lens = off_serial + serial.len() as u32;
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"Nikon\x00\x02\x10\x00\x00"); // 10-byte type-3 header
    b.extend_from_slice(b"MM");
    b.extend_from_slice(&[0x00, 0x2a]);
    b.extend_from_slice(&8u32.to_be_bytes()); // IFD0 at embedded+8
    b.extend_from_slice(&n_entries.to_be_bytes());
    // 0x0007 FocusMode — ASCII, out-of-line.
    b.extend_from_slice(&0x0007u16.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x02]); // string
    b.extend_from_slice(&(focus_mode.len() as u32).to_be_bytes());
    b.extend_from_slice(&off_focus.to_be_bytes());
    // 0x001d SerialNumber — ASCII, out-of-line.
    b.extend_from_slice(&0x001du16.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x02]); // string
    b.extend_from_slice(&(serial.len() as u32).to_be_bytes());
    b.extend_from_slice(&off_serial.to_be_bytes());
    // 0x0098 LensData — undef, out-of-line.
    b.extend_from_slice(&0x0098u16.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x07]); // undef
    b.extend_from_slice(&(lens_block.len() as u32).to_be_bytes());
    b.extend_from_slice(&off_lens.to_be_bytes());
    // 0x00a7 ShutterCount — int32u, inline = 100.
    b.extend_from_slice(&0x00a7u16.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x04]); // int32u
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&KEY_COUNT.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD
    debug_assert_eq!(b.len() as u32, 10 + off_focus);
    b.extend_from_slice(focus_mode);
    b.extend_from_slice(serial);
    b.extend_from_slice(lens_block);
    b
  }

  /// Like [`type3_with_focus_mode_and_lens_data`] but with the IFD entry RECORDS
  /// in the UNSORTED order `0x001d, 0x0098, 0x00a7, 0x0007` — so the `0x0098`
  /// LensData is WALKED BEFORE the `0x0007` `FocusMode` entry. This exercises the
  /// positional `$$self{FocusMode}` gate: at the LensData position no `0x0007`
  /// has run yet, so the member is `undef` (`undef ne "Manual"` = TRUE ⇒ open),
  /// even though a later `0x0007 = "Manual"` exists. The value AREA layout is
  /// unchanged (offsets are record-order-independent); only the 4 entry records
  /// are reordered.
  fn type3_lens_data_before_focus_mode(focus_mode: &[u8], lens_block: &[u8]) -> Vec<u8> {
    let serial = b"12345678\x00"; // 9 bytes (out-of-line)
    let n_entries: u16 = 4;
    let val_emb: u32 = 8 + 2 + u32::from(n_entries) * 12 + 4;
    let off_focus = val_emb;
    let off_serial = off_focus + focus_mode.len() as u32;
    let off_lens = off_serial + serial.len() as u32;
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"Nikon\x00\x02\x10\x00\x00"); // 10-byte type-3 header
    b.extend_from_slice(b"MM");
    b.extend_from_slice(&[0x00, 0x2a]);
    b.extend_from_slice(&8u32.to_be_bytes()); // IFD0 at embedded+8
    b.extend_from_slice(&n_entries.to_be_bytes());
    // 0x001d SerialNumber — ASCII, out-of-line (a prescan key; order-independent).
    b.extend_from_slice(&0x001du16.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x02]); // string
    b.extend_from_slice(&(serial.len() as u32).to_be_bytes());
    b.extend_from_slice(&off_serial.to_be_bytes());
    // 0x0098 LensData — undef, out-of-line. WALKED BEFORE 0x0007 below.
    b.extend_from_slice(&0x0098u16.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x07]); // undef
    b.extend_from_slice(&(lens_block.len() as u32).to_be_bytes());
    b.extend_from_slice(&off_lens.to_be_bytes());
    // 0x00a7 ShutterCount — int32u, inline = 100 (a prescan key).
    b.extend_from_slice(&0x00a7u16.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x04]); // int32u
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&KEY_COUNT.to_be_bytes());
    // 0x0007 FocusMode — ASCII, out-of-line. AFTER 0x0098 in walk order.
    b.extend_from_slice(&0x0007u16.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x02]); // string
    b.extend_from_slice(&(focus_mode.len() as u32).to_be_bytes());
    b.extend_from_slice(&off_focus.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD
    debug_assert_eq!(b.len() as u32, 10 + off_focus);
    b.extend_from_slice(focus_mode);
    b.extend_from_slice(serial);
    b.extend_from_slice(lens_block);
    b
  }

  /// Encrypt `plain` (the cleartext version+body) with this module's symmetric
  /// cipher (`DecryptStart => 4`, the crafted keys) — the inverse of the read
  /// path, used to forge an encrypted LensData block from a known plaintext.
  fn encrypt_lens(plain: &[u8]) -> Vec<u8> {
    let mut buf = plain.to_vec();
    let len = buf.len().saturating_sub(4);
    decrypt::decrypt(&mut buf, 4, len, KEY_SERIAL, KEY_COUNT);
    buf
  }

  fn lens_get(emissions: &[VendorEmission], name: &str) -> Option<TagValue> {
    emissions
      .iter()
      .find(|e| e.name() == name)
      .map(|e| e.value().clone())
  }

  fn str_val(s: &str) -> TagValue {
    TagValue::Str(SmolStr::new(s))
  }

  /// `LensDataVersion 0204` (D90/D7000) DISPATCHES to `%LensData0204` (NOT the
  /// Unknown fallback) and decodes its 13 shifted-offset members byte-exact to
  /// the `perl exiftool` oracle (the offsets differ from 0101 by the +1 shift at
  /// 0x09). This is the OLD-BUG-FIXED case: pre-fix a `0204` block emitted
  /// NOTHING (not even `LensDataVersion`); now the full member set emits.
  #[test]
  fn lens_data_0204_dispatches_and_decodes() {
    // Known plaintext: "0204" + body bytes at the 0204 offsets (see the table).
    let mut plain = [0u8; 20];
    plain[0..4].copy_from_slice(b"0204");
    plain[0x04] = 0x40; // ExitPupilPosition raw 64 → 2048/64 = "32.0 mm"
    plain[0x05] = 0x18; // AFAperture raw 24 → 2**(24/24) = "2.0"
    plain[0x08] = 0x2a; // FocusPosition raw 0x2a → "0x2a"
    plain[0x0a] = 0x14; // FocusDistance raw 20 → "0.03 m"
    plain[0x0b] = 0x76; // FocalLength raw 118 → "151.0 mm"
    plain[0x0c] = 0x18; // LensIDNumber 24
    plain[0x0d] = 0x18; // LensFStops raw 24 → 24/12 = "2.00"
    plain[0x0e] = 0x18; // MinFocalLength raw 24 → "10.0 mm"
    plain[0x0f] = 0x18; // MaxFocalLength raw 24 → "10.0 mm"
    plain[0x10] = 0x30; // MaxApertureAtMinFocal raw 48 → "4.0"
    plain[0x11] = 0x30; // MaxApertureAtMaxFocal raw 48 → "4.0"
    plain[0x12] = 0x07; // MCUVersion 7
    plain[0x13] = 0x42; // EffectiveMaxAperture raw 66 → "6.7"
    let blob = type3_with_lens_data(&encrypt_lens(&plain));

    let (_t, em) = parse(&blob, ByteOrder::Big, Some("NIKON D7000"));
    assert_eq!(lens_get(&em, "LensDataVersion"), Some(str_val("0204")));
    assert_eq!(lens_get(&em, "ExitPupilPosition"), Some(str_val("32.0 mm")));
    assert_eq!(lens_get(&em, "AFAperture"), Some(str_val("2.0")));
    assert_eq!(lens_get(&em, "FocusPosition"), Some(str_val("0x2a")));
    assert_eq!(lens_get(&em, "FocusDistance"), Some(str_val("0.03 m")));
    assert_eq!(lens_get(&em, "FocalLength"), Some(str_val("151.0 mm")));
    assert_eq!(lens_get(&em, "LensIDNumber"), Some(TagValue::I64(24)));
    assert_eq!(lens_get(&em, "LensFStops"), Some(str_val("2.00")));
    assert_eq!(lens_get(&em, "MinFocalLength"), Some(str_val("10.0 mm")));
    assert_eq!(lens_get(&em, "MaxFocalLength"), Some(str_val("10.0 mm")));
    assert_eq!(lens_get(&em, "MaxApertureAtMinFocal"), Some(str_val("4.0")));
    assert_eq!(lens_get(&em, "MaxApertureAtMaxFocal"), Some(str_val("4.0")));
    assert_eq!(lens_get(&em, "MCUVersion"), Some(TagValue::I64(7)));
    assert_eq!(lens_get(&em, "EffectiveMaxAperture"), Some(str_val("6.7")));
  }

  #[test]
  fn lens_data_read_extent_is_bounded_per_layout() {
    // The decrypt cap is the layout's largest member offset+size — small and
    // FIXED per version, NEVER the (attacker-controlled) declared blob length.
    assert_eq!(lens_data_read_extent(&lens_data_layout(b"0204")), 0x14);
    assert_eq!(
      lens_data_read_extent(&lens_data_layout(b"0403")),
      0x2ac + 64
    );
    // 0800: the Z telemetry reads up to LensMountType 0x5f ⇒ 0x60.
    let e0800 = lens_data_read_extent(&lens_data_layout(b"0800"));
    assert!((0x60..0x100).contains(&e0800), "0800 extent {e0800:#x}");
  }

  #[test]
  fn lens_data_large_in_bounds_value_caps_decrypt() {
    // R2: a crafted encrypted LensData declaring a huge in-bounds value must NOT
    // clone+decrypt the whole blob — only the layout's read window (0x14 for
    // 0204). The first bytes carry the real members; the 60 KB tail is padding
    // the cap never decrypts. Decoding still succeeds (the cipher is causal).
    let mut plain = vec![0u8; 60_000];
    plain[0..4].copy_from_slice(b"0204");
    plain[0x04] = 0x40; // ExitPupilPosition → "32.0 mm"
    plain[0x0c] = 0x18; // LensIDNumber 24
    plain[0x13] = 0x42; // EffectiveMaxAperture → "6.7"
    let blob = type3_with_lens_data(&encrypt_lens(&plain));
    let (_t, em) = parse(&blob, ByteOrder::Big, Some("NIKON D7000"));
    assert_eq!(lens_get(&em, "LensDataVersion"), Some(str_val("0204")));
    assert_eq!(lens_get(&em, "ExitPupilPosition"), Some(str_val("32.0 mm")));
    assert_eq!(lens_get(&em, "LensIDNumber"), Some(TagValue::I64(24)));
    assert_eq!(lens_get(&em, "EffectiveMaxAperture"), Some(str_val("6.7")));
    // The decrypt window is the 0204 layout (0x14), not the 60 KB value.
    assert_eq!(lens_data_read_extent(&lens_data_layout(b"0204")), 0x14);
  }

  #[test]
  fn encrypted_lens_data_decrypts_without_serial_number() {
    // R4: ExifTool seeds its prescan with `0x001d => 0`, so encrypted LensData
    // with ShutterCount (0x00a7) but NO SerialNumber (0x001d) still decrypts
    // with serial key 0. The 0204 block is encrypted with serial key 0 + the
    // count, embedded in a type-3 MakerNote carrying 0x00a7 but no 0x001d.
    let mut plain = [0u8; 20];
    plain[0..4].copy_from_slice(b"0204");
    plain[0x04] = 0x40; // ExitPupilPosition → "32.0 mm"
    plain[0x0c] = 0x18; // LensIDNumber 24
    plain[0x13] = 0x42; // EffectiveMaxAperture → "6.7"
    let mut enc = plain.to_vec();
    let len = enc.len() - 4;
    decrypt::decrypt(&mut enc, 4, len, 0, KEY_COUNT); // serial key 0
    // Type-3 MakerNote: 2 out-of-line/inline entries (0x0098 LensData, 0x00a7
    // ShutterCount) — tag-ID-ordered, NO 0x001d SerialNumber.
    let n_entries: u16 = 2;
    let off_lens: u32 = 8 + 2 + u32::from(n_entries) * 12 + 4; // embedded-relative
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"Nikon\x00\x02\x10\x00\x00");
    b.extend_from_slice(b"MM");
    b.extend_from_slice(&[0x00, 0x2a]);
    b.extend_from_slice(&8u32.to_be_bytes());
    b.extend_from_slice(&n_entries.to_be_bytes());
    b.extend_from_slice(&0x0098u16.to_be_bytes()); // LensData, undef, out-of-line
    b.extend_from_slice(&[0x00, 0x07]);
    b.extend_from_slice(&(enc.len() as u32).to_be_bytes());
    b.extend_from_slice(&off_lens.to_be_bytes());
    b.extend_from_slice(&0x00a7u16.to_be_bytes()); // ShutterCount, int32u, inline
    b.extend_from_slice(&[0x00, 0x04]);
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&KEY_COUNT.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD
    b.extend_from_slice(&enc);
    let (_t, em) = parse(&b, ByteOrder::Big, Some("NIKON D7000"));
    // Decryption succeeded with the default serial key 0 (no 0x001d present).
    assert_eq!(lens_get(&em, "LensDataVersion"), Some(str_val("0204")));
    assert_eq!(lens_get(&em, "ExitPupilPosition"), Some(str_val("32.0 mm")));
    assert_eq!(lens_get(&em, "LensIDNumber"), Some(TagValue::I64(24)));
    assert_eq!(lens_get(&em, "EffectiveMaxAperture"), Some(str_val("6.7")));
  }

  /// `LensDataVersion 0400` (Nikon 1 J1/V1/J2) dispatches to `%LensData0400` and
  /// decodes the `LensModel` `string[64]` at offset 0x18a (the only readable
  /// member). Byte-exact to the `perl exiftool` oracle. Proves the
  /// large-offset string read + the `040[01]` alternation arm.
  #[test]
  fn lens_data_0400_decodes_lens_model() {
    let model = b"1 NIKKOR VR 10-30mm f/3.5-5.6";
    let mut plain = std::vec![0u8; 0x18a + 64];
    plain[0..4].copy_from_slice(b"0400");
    plain
      .get_mut(0x18a..0x18a + model.len())
      .unwrap()
      .copy_from_slice(model);
    let blob = type3_with_lens_data(&encrypt_lens(&plain));

    let (_t, em) = parse(&blob, ByteOrder::Big, Some("NIKON 1 J1"));
    assert_eq!(lens_get(&em, "LensDataVersion"), Some(str_val("0400")));
    assert_eq!(
      lens_get(&em, "LensModel"),
      Some(str_val("1 NIKKOR VR 10-30mm f/3.5-5.6"))
    );
    // The `0401` sibling shares the same table/arm.
    let mut plain2 = plain.clone();
    plain2[0..4].copy_from_slice(b"0401");
    let blob2 = type3_with_lens_data(&encrypt_lens(&plain2));
    let (_t2, em2) = parse(&blob2, ByteOrder::Big, Some("NIKON 1 J2"));
    assert_eq!(lens_get(&em2, "LensDataVersion"), Some(str_val("0401")));
    assert_eq!(
      lens_get(&em2, "LensModel"),
      Some(str_val("1 NIKKOR VR 10-30mm f/3.5-5.6"))
    );
  }

  /// `LensDataVersion 0402` decodes `LensModel` (`string[64]`) at offset 0x18b,
  /// and `0403` at offset 0x2ac — the per-version offsets matter. Byte-exact to
  /// the `perl exiftool` oracle.
  #[test]
  fn lens_data_0402_0403_decode_lens_model() {
    let model402 = b"1 NIKKOR 11-27.5mm f/3.5-5.6";
    let mut p402 = std::vec![0u8; 0x18b + 64];
    p402[0..4].copy_from_slice(b"0402");
    p402
      .get_mut(0x18b..0x18b + model402.len())
      .unwrap()
      .copy_from_slice(model402);
    let (_t, em) = parse(
      &type3_with_lens_data(&encrypt_lens(&p402)),
      ByteOrder::Big,
      Some("NIKON 1 J3"),
    );
    assert_eq!(lens_get(&em, "LensDataVersion"), Some(str_val("0402")));
    assert_eq!(
      lens_get(&em, "LensModel"),
      Some(str_val("1 NIKKOR 11-27.5mm f/3.5-5.6"))
    );

    let model403 = b"1 NIKKOR VR 10-100mm f/4-5.6";
    let mut p403 = std::vec![0u8; 0x2ac + 64];
    p403[0..4].copy_from_slice(b"0403");
    p403
      .get_mut(0x2ac..0x2ac + model403.len())
      .unwrap()
      .copy_from_slice(model403);
    let (_t2, em2) = parse(
      &type3_with_lens_data(&encrypt_lens(&p403)),
      ByteOrder::Big,
      Some("NIKON 1 J4"),
    );
    assert_eq!(lens_get(&em2, "LensDataVersion"), Some(str_val("0403")));
    assert_eq!(
      lens_get(&em2, "LensModel"),
      Some(str_val("1 NIKKOR VR 10-100mm f/4-5.6"))
    );
  }

  /// `LensDataVersion 080[012]` (Z6/Z7/Z9) dispatches to `%LensData0800` and,
  /// when the forward-looking `OldLensData` flag is SET (the `undef[17]` at 0x03
  /// is NOT `/^.\0+$/`), decodes the LEGACY block (offsets 0x04-0x14, a second
  /// +1 shift). Byte-exact to the `perl exiftool` oracle.
  #[test]
  fn lens_data_0800_old_block_decodes() {
    let mut plain = [0u8; 0x15];
    plain[0..4].copy_from_slice(b"0800");
    plain[0x04] = 0x40; // ExitPupilPosition → "32.0 mm"
    plain[0x05] = 0x18; // AFAperture → "2.0"
    plain[0x0b] = 0x14; // FocusDistance → "0.03 m"
    plain[0x0c] = 0x76; // FocalLength → "151.0 mm"
    plain[0x0d] = 0x18; // LensIDNumber 24
    plain[0x0e] = 0x18; // LensFStops → "2.00"
    plain[0x0f] = 0x18; // MinFocalLength → "10.0 mm"
    plain[0x10] = 0x18; // MaxFocalLength → "10.0 mm"
    plain[0x11] = 0x30; // MaxApertureAtMinFocal → "4.0"
    plain[0x12] = 0x30; // MaxApertureAtMaxFocal → "4.0"
    plain[0x13] = 0x07; // MCUVersion 7
    plain[0x14] = 0x42; // EffectiveMaxAperture → "6.7"
    let (_t, em) = parse(
      &type3_with_lens_data(&encrypt_lens(&plain)),
      ByteOrder::Big,
      Some("NIKON Z 6"),
    );
    assert_eq!(lens_get(&em, "LensDataVersion"), Some(str_val("0800")));
    assert_eq!(lens_get(&em, "ExitPupilPosition"), Some(str_val("32.0 mm")));
    assert_eq!(lens_get(&em, "AFAperture"), Some(str_val("2.0")));
    assert_eq!(lens_get(&em, "FocusDistance"), Some(str_val("0.03 m")));
    assert_eq!(lens_get(&em, "FocalLength"), Some(str_val("151.0 mm")));
    assert_eq!(lens_get(&em, "LensIDNumber"), Some(TagValue::I64(24)));
    assert_eq!(lens_get(&em, "LensFStops"), Some(str_val("2.00")));
    assert_eq!(lens_get(&em, "MCUVersion"), Some(TagValue::I64(7)));
    assert_eq!(lens_get(&em, "EffectiveMaxAperture"), Some(str_val("6.7")));
  }

  /// `LensDataVersion 0800` with the `OldLensData` flag CLEAR (the `undef[17]`
  /// at 0x03 IS `/^.\0+$/` — all bytes after the lead are NUL) emits ONLY
  /// `LensDataVersion`, NO legacy members (the `Condition => '$$self{OldLensData}'`
  /// gate). Matches the `perl exiftool` oracle on the gate-off crafted bytes.
  #[test]
  fn lens_data_0800_gate_off_emits_only_version() {
    let mut plain = [0u8; 0x15];
    plain[0..4].copy_from_slice(b"0800");
    // bytes 0x04.. all zero ⇒ undef[17] at 0x03 = lead + 16 NULs ⇒ flag clear.
    let (_t, em) = parse(
      &type3_with_lens_data(&encrypt_lens(&plain)),
      ByteOrder::Big,
      Some("NIKON Z 6"),
    );
    assert_eq!(lens_get(&em, "LensDataVersion"), Some(str_val("0800")));
    for name in [
      "ExitPupilPosition",
      "AFAperture",
      "FocusDistance",
      "FocalLength",
      "LensIDNumber",
      "MCUVersion",
      "EffectiveMaxAperture",
    ] {
      assert!(
        lens_get(&em, name).is_none(),
        "0800 gate-off must suppress {name}, got {em:?}"
      );
    }
  }

  /// `LensDataVersion 0800` NEW Z-lens telemetry (`Nikon.pm:5809-5961`): with
  /// the legacy `OldLensData` gate CLEAR (so the legacy block is silent) but the
  /// forward-looking `NewLensData` flag SET, the Z block (0x2f onward) decodes.
  /// All multi-byte members are read LittleEndian (the `0800` `ByteOrder`
  /// override). The expected rendered values were cross-checked against the
  /// actual `Nikon.pm` PrintConv/ValueConv expressions evaluated in Perl.
  #[test]
  fn lens_data_0800_z_telemetry_decodes() {
    // 0x60 bytes so the block reaches LensMountType (0x5f). 0x03..0x14 left NUL
    // ⇒ OldLensData gate CLEAR. The Z block is filled from 0x30.
    let mut plain = [0u8; 0x60];
    plain[0..4].copy_from_slice(b"0800");
    // 0x30 LensID int16u LE = 13 → "Nikkor Z 24-70mm f/2.8 S" (also makes the
    // NewLensData undef[17] at 0x2f non-`/^.\0+$/` ⇒ flag SET, z_lens TRUE).
    plain[0x30..0x32].copy_from_slice(&13u16.to_le_bytes());
    // 0x34 LensFirmwareVersion int16u LE = 0x0123 (291) → "1.2.3".
    plain[0x34..0x36].copy_from_slice(&0x0123u16.to_le_bytes());
    // 0x36 MaxAperture int16u LE = 768 → 2**(768/384-1)=2.0 → "2.0".
    plain[0x36..0x38].copy_from_slice(&768u16.to_le_bytes());
    // 0x38 FNumber int16u LE = 1152 → 2**(1152/384-1)=4.0 → "4.0".
    plain[0x38..0x3a].copy_from_slice(&1152u16.to_le_bytes());
    // 0x3c FocalLength int16u LE = 50 → "50 mm".
    plain[0x3c..0x3e].copy_from_slice(&50u16.to_le_bytes());
    // 0x4c FocusDistanceRangeWidth int8u (Unknown=1) — emitted but unknown-flagged.
    plain[0x4c] = 0x05;
    // 0x4e FocusDistance int16u LE = 24576 → raw/256=96 → 2**((96-80)/12)=2.52 → "2.52 m".
    plain[0x4e..0x50].copy_from_slice(&24576u16.to_le_bytes());
    // 0x56 LensDriveEnd int8u (Unknown=1) / 0x58 FocusStepsFromInfinity (Unknown=1).
    plain[0x56] = 0x02;
    plain[0x58] = 0x07;
    // 0x5a LensPositionAbsolute int32s LE = 58000 → I64(58000). NOT Unknown.
    plain[0x5a..0x5e].copy_from_slice(&58000i32.to_le_bytes());
    // 0x5f LensMountType int8u, Mask 0x01 = 0xf1 → masked 1 → "F-mount".
    plain[0x5f] = 0xf1;
    let (_t, em) = parse(
      &type3_with_lens_data(&encrypt_lens(&plain)),
      ByteOrder::Big,
      Some("NIKON Z 6"),
    );
    assert_eq!(lens_get(&em, "LensDataVersion"), Some(str_val("0800")));
    // The legacy block is gated OFF — no OldLensData members.
    assert!(lens_get(&em, "ExitPupilPosition").is_none());
    // Z telemetry (camera-identity, NOT unknown-flagged).
    assert_eq!(
      lens_get(&em, "LensID"),
      Some(str_val("Nikkor Z 24-70mm f/2.8 S"))
    );
    assert_eq!(lens_get(&em, "LensFirmwareVersion"), Some(str_val("1.2.3")));
    assert_eq!(lens_get(&em, "MaxAperture"), Some(str_val("2.0")));
    assert_eq!(lens_get(&em, "FNumber"), Some(str_val("4.0")));
    assert_eq!(lens_get(&em, "FocalLength"), Some(str_val("50 mm")));
    assert_eq!(lens_get(&em, "FocusDistance"), Some(str_val("2.52 m")));
    assert_eq!(
      lens_get(&em, "LensPositionAbsolute"),
      Some(TagValue::I64(58000))
    );
    assert_eq!(lens_get(&em, "LensMountType"), Some(str_val("F-mount")));
    // The three `Unknown => 1` members ARE emitted (the raw `parse()` Vec keeps
    // them) but carry the unknown flag, so default `-j` output suppresses them.
    for name in [
      "FocusDistanceRangeWidth",
      "LensDriveEnd",
      "FocusStepsFromInfinity",
    ] {
      let e = em.iter().find(|e| e.name() == name);
      assert!(
        e.is_some_and(VendorEmission::unknown),
        "{name} must be present and unknown-flagged: {em:?}"
      );
    }
    // LensDriveEnd's STATEFUL RawConv renders the string label, not the raw byte
    // — here 0x4c FocusDistanceRangeWidth=0x05 (non-zero) and 0x56=0x02
    // (non-zero) ⇒ "CFD" (still unknown-flagged, so output-suppressed).
    assert_eq!(lens_get(&em, "LensDriveEnd"), Some(str_val("CFD")));
  }

  /// The `0x56` `LensDriveEnd` stateful RawConv (`Nikon.pm:5933-5939`): `Inf`
  /// iff `FocusDistanceRangeWidth` (0x4c) is defined and `0`;
  /// otherwise `No` for byte `0` and `CFD` for a non-zero byte. (LensDriveEnd is
  /// `Unknown => 1` and thus never surfaces in exifast output — `run_emission`
  /// always drops Unknown tags — so the conversion is verified directly here.)
  #[test]
  fn lens_drive_end_stateful_rawconv() {
    // FocusDistanceRangeWidth defined and 0 ⇒ "Inf", regardless of the 0x56 byte.
    assert_eq!(lens_drive_end(0, Some(0)), "Inf");
    assert_eq!(lens_drive_end(2, Some(0)), "Inf");
    // FocusDistanceRangeWidth defined and non-zero ⇒ byte 0 → "No", else "CFD".
    assert_eq!(lens_drive_end(0, Some(5)), "No");
    assert_eq!(lens_drive_end(2, Some(5)), "CFD");
    // FocusDistanceRangeWidth undefined (`unless defined …` ⇒ first branch) ⇒
    // byte 0 → "No", else "CFD" (never "Inf").
    assert_eq!(lens_drive_end(0, None), "No");
    assert_eq!(lens_drive_end(2, None), "CFD");
  }

  /// `LensDataVersion 0800` with `NewLensData` CLEAR (the `undef[17]` at 0x2f is
  /// `/^.\0+$/` — all bytes after the lead are NUL) suppresses the ENTIRE Z
  /// block: no `LensID`/`MaxAperture`/`LensMountType`. Only `LensDataVersion`
  /// (and any gated-on legacy members, here also off) survives.
  #[test]
  fn lens_data_0800_z_gate_off_suppresses_z_block() {
    let mut plain = [0u8; 0x60];
    plain[0..4].copy_from_slice(b"0800");
    // 0x2f..0x40 all NUL ⇒ NewLensData undef[17] = lead + NULs ⇒ flag CLEAR.
    // Put data at 0x5f to prove even the unconditional LensMountType is gated:
    // it is NOT — LensMountType has no Condition — but with the block all-NUL it
    // renders Z-mount (masked 0). Assert the CONDITIONAL Z members are absent.
    let (_t, em) = parse(
      &type3_with_lens_data(&encrypt_lens(&plain)),
      ByteOrder::Big,
      Some("NIKON Z 6"),
    );
    assert_eq!(lens_get(&em, "LensDataVersion"), Some(str_val("0800")));
    for name in [
      "LensID",
      "LensFirmwareVersion",
      "MaxAperture",
      "FNumber",
      "FocalLength",
      "FocusDistance",
      "LensPositionAbsolute",
    ] {
      assert!(
        lens_get(&em, name).is_none(),
        "NewLensData-clear must suppress Z member {name}, got {em:?}"
      );
    }
    // LensMountType (0x5f) has NO `Condition` ⇒ it emits even with NewLensData
    // clear (R3); the all-NUL block masks to 0 ⇒ "Z-mount".
    assert_eq!(lens_get(&em, "LensMountType"), Some(str_val("Z-mount")));
  }

  #[test]
  fn lens_data_0800_lens_mount_type_emits_when_new_lens_data_clear() {
    // R3 regression: NewLensData clear (0x2f window all-NUL) but byte 0x5f set ⇒
    // LensMountType still emits (no `Condition` in ExifTool), while the
    // NewLensData-gated members stay suppressed.
    let mut plain = [0u8; 0x60];
    plain[0..4].copy_from_slice(b"0800");
    plain[0x5f] = 0x01; // masked 0x01 ⇒ "F-mount"
    let (_t, em) = parse(
      &type3_with_lens_data(&encrypt_lens(&plain)),
      ByteOrder::Big,
      Some("NIKON Z 6"),
    );
    assert_eq!(lens_get(&em, "LensID"), None); // NewLensData-gated ⇒ suppressed
    assert_eq!(lens_get(&em, "LensMountType"), Some(str_val("F-mount")));
  }

  /// `FocusMode` gating (`Nikon.pm:5918`/`5935`): the two `FocusMode ne
  /// "Manual"` members (0x4c `FocusDistanceRangeWidth`, 0x56 `LensDriveEnd`) key
  /// on the RAW on-disk `$$self{FocusMode}` string (set by tag 0x0007's
  /// RawConv). With FocusMode exactly "Manual" their `Condition` is FALSE ⇒ they
  /// are SUPPRESSED (not even unknown-flagged present), while the LensID-only
  /// member 0x4e `FocusDistance` still emits.
  #[test]
  fn lens_data_0800_z_focus_mode_manual_gate() {
    let mut plain = [0u8; 0x60];
    plain[0..4].copy_from_slice(b"0800");
    plain[0x30..0x32].copy_from_slice(&13u16.to_le_bytes()); // LensID 13 (z_lens)
    plain[0x4c] = 0x05; // FocusDistanceRangeWidth (FocusMode-gated)
    plain[0x4e..0x50].copy_from_slice(&24576u16.to_le_bytes()); // FocusDistance (LensID-only)
    plain[0x56] = 0x02; // LensDriveEnd (FocusMode-gated)
    // The crafted RAW 0x0007 string is exactly "Manual" ⇒ the gate closes.
    let blob = type3_with_focus_mode_and_lens_data(b"Manual\x00", &encrypt_lens(&plain));
    let (_t, em) = parse(&blob, ByteOrder::Big, Some("NIKON Z 6"));
    // LensID-only member still emits.
    assert_eq!(lens_get(&em, "FocusDistance"), Some(str_val("2.52 m")));
    // FocusMode-ne-Manual members suppressed entirely (Condition false ⇒ not
    // emitted at all, not merely unknown-flagged).
    assert!(
      em.iter().all(|e| e.name() != "FocusDistanceRangeWidth"),
      "FocusMode==Manual must drop FocusDistanceRangeWidth: {em:?}"
    );
    assert!(
      em.iter().all(|e| e.name() != "LensDriveEnd"),
      "FocusMode==Manual must drop LensDriveEnd: {em:?}"
    );
  }

  /// `$$self{FocusMode}` is POSITIONAL, not pre-scanned (`Nikon.pm:1816`: a
  /// normal RawConv set during the IFD walk, NOT a `PrescanExif` tag). When the
  /// `0x0098` LensData0800 is WALKED BEFORE the `0x0007 = "Manual"` entry (an
  /// unsorted/duplicate MakerNote), the member is still `undef` at the LensData
  /// position, so `undef ne "Manual"` is TRUE ⇒ the `FocusMode ne "Manual"` Z
  /// members (0x4c `FocusDistanceRangeWidth`, 0x56 `LensDriveEnd`) DO emit —
  /// matching ExifTool (a pre-scan would have WRONGLY suppressed them with the
  /// later value). The same plaintext in tag-ID order (0x0007 first) keeps them
  /// suppressed, proving the well-formed case is unchanged.
  #[test]
  fn lens_data_0800_focus_mode_after_lensdata_uses_undef() {
    let mut plain = [0u8; 0x60];
    plain[0..4].copy_from_slice(b"0800");
    plain[0x30..0x32].copy_from_slice(&13u16.to_le_bytes()); // LensID 13 (native Z ⇒ NewLensData set)
    plain[0x4c] = 0x05; // FocusDistanceRangeWidth (FocusMode-gated)
    plain[0x4e..0x50].copy_from_slice(&24576u16.to_le_bytes()); // FocusDistance (LensID-only)
    plain[0x56] = 0x02; // LensDriveEnd (FocusMode-gated)
    let enc = encrypt_lens(&plain);

    // LensData walked BEFORE the (later) 0x0007 = "Manual" ⇒ FocusMode is `undef`
    // at the LensData position ⇒ the gate is OPEN ⇒ the two members emit
    // (Unknown => 1, so present-and-unknown-flagged like the Z telemetry test).
    let before = type3_lens_data_before_focus_mode(b"Manual\x00", &enc);
    let (_t, em) = parse(&before, ByteOrder::Big, Some("NIKON Z 6"));
    assert_eq!(
      lens_get(&em, "LensID"),
      Some(str_val("Nikkor Z 24-70mm f/2.8 S"))
    );
    assert_eq!(lens_get(&em, "FocusDistance"), Some(str_val("2.52 m")));
    for name in ["FocusDistanceRangeWidth", "LensDriveEnd"] {
      let e = em.iter().find(|e| e.name() == name);
      assert!(
        e.is_some_and(VendorEmission::unknown),
        "0x0098-before-0x0007: {name} must emit (gate open via undef): {em:?}"
      );
    }

    // The SAME plaintext in well-formed tag-ID order (0x0007 = "Manual" FIRST)
    // closes the gate ⇒ the two members are suppressed (the existing-behavior
    // guard for a normally-ordered MakerNote).
    let after = type3_with_focus_mode_and_lens_data(b"Manual\x00", &enc);
    let (_t2, em2) = parse(&after, ByteOrder::Big, Some("NIKON Z 6"));
    assert_eq!(lens_get(&em2, "FocusDistance"), Some(str_val("2.52 m")));
    for name in ["FocusDistanceRangeWidth", "LensDriveEnd"] {
      assert!(
        em2.iter().all(|e| e.name() != name),
        "tag-ID order with FocusMode==Manual must drop {name}: {em2:?}"
      );
    }
  }

  /// An UNRECOGNIZED `LensDataVersion` (e.g. `9999`) falls through to the
  /// `LensDataUnknown` arm (`Nikon.pm:2890`) — it emits ONLY `LensDataVersion`
  /// (no members, no panic), matching the `perl exiftool` oracle. This is the
  /// "no version silently dropped" guarantee for future/unknown versions.
  #[test]
  fn lens_data_unknown_version_emits_only_version() {
    let plain = b"9999\xaa\xbb\xcc\xdd\xee\xff";
    let (_t, em) = parse(
      &type3_with_lens_data(&encrypt_lens(plain)),
      ByteOrder::Big,
      Some("NIKON D9999"),
    );
    assert_eq!(lens_get(&em, "LensDataVersion"), Some(str_val("9999")));
    // No `LensData*` member tags beyond the version.
    let member_names = [
      "ExitPupilPosition",
      "AFAperture",
      "FocusPosition",
      "FocusDistance",
      "FocalLength",
      "LensIDNumber",
      "LensFStops",
      "MCUVersion",
      "EffectiveMaxAperture",
      "LensModel",
    ];
    for name in member_names {
      assert!(
        lens_get(&em, name).is_none(),
        "LensDataUnknown must emit no {name}"
      );
    }
  }

  /// THE OLD BUG, FIXED: before the version-dispatch completion, ANY
  /// `LensDataVersion` above `0203` (here `0204`) returned from `emit_lens_data`
  /// WITHOUT EMITTING ANYTHING — not even `LensDataVersion`. Now every readable
  /// `0x0098` block emits at least `LensDataVersion`. This asserts the
  /// regression directly: a `>0203` version is NEVER silent.
  #[test]
  fn lens_data_above_0203_is_never_silent() {
    for ver in [b"0204", b"0400", b"0402", b"0403", b"0800", b"9999"] {
      // A minimal block: just the version + a few body bytes (enough to be a
      // readable 4-byte version; members may or may not decode, but the version
      // MUST always appear).
      let mut plain = [0u8; 8];
      plain[0..4].copy_from_slice(ver);
      let (_t, em) = parse(
        &type3_with_lens_data(&encrypt_lens(&plain)),
        ByteOrder::Big,
        Some("NIKON D7000"),
      );
      let v = String::from_utf8_lossy(ver).into_owned();
      assert_eq!(
        lens_get(&em, "LensDataVersion"),
        Some(str_val(&v)),
        "version {v} must emit LensDataVersion (the old-bug-fixed guarantee)"
      );
    }
  }

  /// Bounds-safety: a TRUNCATED encrypted block (version present, body cut
  /// short before a version's member offsets) emits `LensDataVersion` and never
  /// panics — the per-member `get`/`get(..len)` reads simply skip absent
  /// members. Covers the `string[64]` member running past a short block too.
  #[test]
  fn lens_data_truncated_block_no_panic() {
    // 0204 with only 6 bytes (version + 2 body bytes): most members are absent.
    let plain = b"0204\x40\x18";
    let (_t, em) = parse(
      &type3_with_lens_data(&encrypt_lens(plain)),
      ByteOrder::Big,
      Some("NIKON D7000"),
    );
    assert_eq!(lens_get(&em, "LensDataVersion"), Some(str_val("0204")));
    // ExitPupilPosition (0x04) is present; the later members are not — no panic.
    assert_eq!(lens_get(&em, "ExitPupilPosition"), Some(str_val("32.0 mm")));
    assert!(lens_get(&em, "EffectiveMaxAperture").is_none());

    // 0400 whose block is far shorter than the 0x18a LensModel offset: the
    // string read is skipped, only LensDataVersion emits, no panic.
    let short0400 = b"0400\x00\x00\x00\x00";
    let (_t2, em2) = parse(
      &type3_with_lens_data(&encrypt_lens(short0400)),
      ByteOrder::Big,
      Some("NIKON 1 J1"),
    );
    assert_eq!(lens_get(&em2, "LensDataVersion"), Some(str_val("0400")));
    assert!(lens_get(&em2, "LensModel").is_none());
  }

  /// REGRESSION GUARD: the unencrypted `0101` (D70/D70s) path is unchanged by
  /// the version-dispatch refactor — it still decodes `%LensData01` members from
  /// the CLEARTEXT block (no keys needed). A representative member decodes to
  /// the oracle value.
  #[test]
  fn lens_data_0101_unencrypted_unchanged() {
    // Cleartext 0101 block (unencrypted): a value at FocalLength (0x0a).
    let mut plain = [0u8; 0x13];
    plain[0..4].copy_from_slice(b"0101");
    plain[0x0a] = 0x76; // FocalLength raw 118 → "151.0 mm"
    plain[0x0b] = 0x18; // LensIDNumber 24
    // NOTE: 0101 is UNENCRYPTED — feed the cleartext block directly.
    let (_t, em) = parse(
      &type3_with_lens_data(&plain),
      ByteOrder::Big,
      Some("NIKON D70"),
    );
    assert_eq!(lens_get(&em, "LensDataVersion"), Some(str_val("0101")));
    assert_eq!(lens_get(&em, "FocalLength"), Some(str_val("151.0 mm")));
    assert_eq!(lens_get(&em, "LensIDNumber"), Some(TagValue::I64(24)));
  }

  /// The set of `LensData*` member tag names — used by the encrypted-no-decode
  /// regression tests to assert that NOTHING (not even `LensDataVersion`) is
  /// emitted when `ProcessNikonEncrypted` would return 0.
  const LENS_MEMBER_NAMES: [&str; 11] = [
    "LensDataVersion",
    "ExitPupilPosition",
    "AFAperture",
    "FocusPosition",
    "FocusDistance",
    "FocalLength",
    "LensIDNumber",
    "LensFStops",
    "MCUVersion",
    "EffectiveMaxAperture",
    "LensModel",
  ];

  /// Build a type-3 Nikon blob with a `0x0098` LensData value but NO 0x001d /
  /// 0x00a7 — so `scan_decrypt_keys` finds no ShutterCount and returns `None`.
  /// A single out-of-line `0x0098` entry; no SerialNumber, no ShutterCount.
  fn type3_lens_data_only(lens_block: &[u8]) -> Vec<u8> {
    let n_entries: u16 = 1;
    let off_lens: u32 = 8 + 2 + u32::from(n_entries) * 12 + 4; // embedded-relative
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"Nikon\x00\x02\x10\x00\x00");
    b.extend_from_slice(b"MM");
    b.extend_from_slice(&[0x00, 0x2a]);
    b.extend_from_slice(&8u32.to_be_bytes());
    b.extend_from_slice(&n_entries.to_be_bytes());
    b.extend_from_slice(&0x0098u16.to_be_bytes()); // LensData, undef, out-of-line
    b.extend_from_slice(&[0x00, 0x07]);
    b.extend_from_slice(&(lens_block.len() as u32).to_be_bytes());
    b.extend_from_slice(&off_lens.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD
    b.extend_from_slice(lens_block);
    b
  }

  /// An ENCRYPTED `0204` LensData with NO ShutterCount (0x00a7) — and hence no
  /// count key — mirrors `ProcessNikonEncrypted` returning 0
  /// (`Nikon.pm:13948-13961`): the SubDirectory yields NO tags AT ALL, including
  /// no `LensDataVersion`. The cleartext `string[4]` at offset 0 is read only
  /// AFTER the key gate inside the encrypted ProcessProc, so a missing count key
  /// suppresses the version too.
  #[test]
  fn encrypted_lens_data_no_shutter_count_emits_nothing() {
    let mut plain = [0u8; 20];
    plain[0..4].copy_from_slice(b"0204");
    plain[0x04] = 0x40; // a would-be ExitPupilPosition, must NOT surface
    let blob = type3_lens_data_only(&encrypt_lens(&plain));
    let (_t, em) = parse(&blob, ByteOrder::Big, Some("NIKON D7000"));
    for name in LENS_MEMBER_NAMES {
      assert!(
        lens_get(&em, name).is_none(),
        "encrypted LensData without ShutterCount must emit no {name}"
      );
    }
  }

  /// A MULTI-ELEMENT ShutterCount (`int32u[2]`, prescan-rendered `"100 0"`)
  /// fails ExifTool's `$count =~ /^\d+$/` (`Nikon.pm:13948`), so the count key
  /// stays undefined and the encrypted `0204` LensData decrypts to nothing — no
  /// members AND no `LensDataVersion` (the encrypted key gate fails). Taking
  /// only the first element (`100`) would have wrongly unlocked decryption.
  #[test]
  fn encrypted_lens_data_multielement_shutter_count_rejected() {
    let mut plain = [0u8; 20];
    plain[0..4].copy_from_slice(b"0204");
    plain[0x04] = 0x40;
    let enc = encrypt_lens(&plain);
    // Type-3 MakerNote: 0x0098 LensData (out-of-line) + 0x00a7 as int32u[2]
    // (out-of-line, value `[100, 0]`). Tag-ID-ordered; NO 0x001d.
    let n_entries: u16 = 2;
    let val_emb: u32 = 8 + 2 + u32::from(n_entries) * 12 + 4;
    let off_lens = val_emb;
    let off_count = off_lens + enc.len() as u32;
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"Nikon\x00\x02\x10\x00\x00");
    b.extend_from_slice(b"MM");
    b.extend_from_slice(&[0x00, 0x2a]);
    b.extend_from_slice(&8u32.to_be_bytes());
    b.extend_from_slice(&n_entries.to_be_bytes());
    b.extend_from_slice(&0x0098u16.to_be_bytes()); // LensData, undef, out-of-line
    b.extend_from_slice(&[0x00, 0x07]);
    b.extend_from_slice(&(enc.len() as u32).to_be_bytes());
    b.extend_from_slice(&off_lens.to_be_bytes());
    b.extend_from_slice(&0x00a7u16.to_be_bytes()); // ShutterCount, int32u[2], out-of-line
    b.extend_from_slice(&[0x00, 0x04]); // int32u
    b.extend_from_slice(&2u32.to_be_bytes()); // count = 2 ⇒ out-of-line
    b.extend_from_slice(&off_count.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD
    b.extend_from_slice(&enc);
    b.extend_from_slice(&100u32.to_be_bytes()); // count[0] = 100
    b.extend_from_slice(&0u32.to_be_bytes()); // count[1] = 0
    let (_t, em) = parse(&b, ByteOrder::Big, Some("NIKON D7000"));
    for name in LENS_MEMBER_NAMES {
      assert!(
        lens_get(&em, name).is_none(),
        "int32u[2] ShutterCount must reject decryption — no {name}"
      );
    }
  }

  /// FORMAT-AGNOSTIC key derivation: the prescan keys come from the `ReadValue`
  /// `$val` STRING (`Nikon.pm:14122`), so an INTEGER-format `0x001d`
  /// (`int32u 12345678` ⇒ `SerialKey("12345678") = 12345678`) and an ASCII
  /// `0x00a7` (`string "100"` ⇒ `"100" =~ /^\d+$/` ⇒ count 100) derive the SAME
  /// keys as the native `string 0x001d` + `int32u 0x00a7` layout. The block is
  /// encrypted with `KEY_SERIAL`/`KEY_COUNT`, so a correct decode proves the
  /// derivation reached exactly those keys despite the swapped storage formats.
  #[test]
  fn decrypt_keys_integer_serial_and_ascii_count() {
    // Known 0204 plaintext (a subset of the dispatch test's field set).
    let mut plain = [0u8; 20];
    plain[0..4].copy_from_slice(b"0204");
    plain[0x04] = 0x40; // ExitPupilPosition → "32.0 mm"
    plain[0x0c] = 0x18; // LensIDNumber 24
    plain[0x13] = 0x42; // EffectiveMaxAperture → "6.7"
    let enc = encrypt_lens(&plain); // keys: KEY_SERIAL=12345678, KEY_COUNT=100

    // Type-3 IFD, tag-ID order: 0x001d as int32u (inline = 12345678), 0x0098
    // LensData (out-of-line), 0x00a7 as ASCII "100\0" (string, inline).
    let n_entries: u16 = 3;
    let off_lens: u32 = 8 + 2 + u32::from(n_entries) * 12 + 4; // embedded-relative
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"Nikon\x00\x02\x10\x00\x00");
    b.extend_from_slice(b"MM");
    b.extend_from_slice(&[0x00, 0x2a]);
    b.extend_from_slice(&8u32.to_be_bytes());
    b.extend_from_slice(&n_entries.to_be_bytes());
    // 0x001d SerialNumber — int32u (NOT a string), inline = 12345678. ReadValue
    // renders "12345678", which SerialKey uses verbatim as the key.
    b.extend_from_slice(&0x001du16.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x04]); // int32u
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&KEY_SERIAL.to_be_bytes());
    // 0x0098 LensData — undef, out-of-line.
    b.extend_from_slice(&0x0098u16.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x07]); // undef
    b.extend_from_slice(&(enc.len() as u32).to_be_bytes());
    b.extend_from_slice(&off_lens.to_be_bytes());
    // 0x00a7 ShutterCount — string "100\0" (ASCII digits, NOT int32u), inline.
    // ReadValue NUL-trims to "100", which matches /^\d+$/ ⇒ count 100.
    b.extend_from_slice(&0x00a7u16.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x02]); // string
    b.extend_from_slice(&4u32.to_be_bytes()); // 4 bytes ⇒ inline
    b.extend_from_slice(b"100\x00");
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD
    b.extend_from_slice(&enc);
    let (_t, em) = parse(&b, ByteOrder::Big, Some("NIKON D7000"));
    // Decoded ⇒ the integer serial + ASCII count derived KEY_SERIAL/KEY_COUNT.
    assert_eq!(lens_get(&em, "LensDataVersion"), Some(str_val("0204")));
    assert_eq!(lens_get(&em, "ExitPupilPosition"), Some(str_val("32.0 mm")));
    assert_eq!(lens_get(&em, "LensIDNumber"), Some(TagValue::I64(24)));
    assert_eq!(lens_get(&em, "EffectiveMaxAperture"), Some(str_val("6.7")));

    // Cross-check the helpers in isolation: the integer 0x001d renders the digit
    // string SerialKey keys on, and the ASCII "100" passes the count /^\d+$/.
    assert_eq!(
      decrypt::serial_key("12345678", Some("NIKON D7000")),
      Some(KEY_SERIAL)
    );
    let ascii_count = ParsedValue::new(RawValue::Text {
      text: "100".into(),
      raw: Box::from(&b"100"[..]),
    });
    assert_eq!(ascii_count.single_digit_count(), Some(KEY_COUNT));
  }

  /// REGRESSION GUARD (the key gate is ENCRYPTED-ONLY): an UNENCRYPTED `0101`
  /// LensData with NO SerialNumber (0x001d) and NO ShutterCount (0x00a7) STILL
  /// emits `LensDataVersion` + its members — `0100`/`0101` use plain
  /// `ProcessBinaryData` (`Nikon.pm:2818`/`2823`, no `ProcessProc`), which has no
  /// key check. Proves Finding 1's gate does not over-suppress the unencrypted
  /// layouts.
  #[test]
  fn unencrypted_lens_data_0101_emits_without_keys() {
    let mut plain = [0u8; 0x13];
    plain[0..4].copy_from_slice(b"0101");
    plain[0x0a] = 0x76; // FocalLength raw 118 → "151.0 mm"
    plain[0x0b] = 0x18; // LensIDNumber 24
    // UNENCRYPTED — cleartext block, NO 0x001d / 0x00a7 in the IFD.
    let (_t, em) = parse(
      &type3_lens_data_only(&plain),
      ByteOrder::Big,
      Some("NIKON D70"),
    );
    assert_eq!(lens_get(&em, "LensDataVersion"), Some(str_val("0101")));
    assert_eq!(lens_get(&em, "FocalLength"), Some(str_val("151.0 mm")));
    assert_eq!(lens_get(&em, "LensIDNumber"), Some(TagValue::I64(24)));
  }

  /// Build a type-3 Nikon blob with a single out-of-line `0x00a8` FlashInfo
  /// value (UNENCRYPTED, so no key prescan is needed). Mirrors
  /// [`type3_lens_data_only`] for the FlashInfo SubDirectory.
  fn type3_flash_info(flash_block: &[u8]) -> Vec<u8> {
    let n_entries: u16 = 1;
    let off_flash: u32 = 8 + 2 + u32::from(n_entries) * 12 + 4; // embedded-relative
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"Nikon\x00\x02\x10\x00\x00");
    b.extend_from_slice(b"MM");
    b.extend_from_slice(&[0x00, 0x2a]);
    b.extend_from_slice(&8u32.to_be_bytes());
    b.extend_from_slice(&n_entries.to_be_bytes());
    b.extend_from_slice(&0x00a8u16.to_be_bytes()); // FlashInfo, undef, out-of-line
    b.extend_from_slice(&[0x00, 0x07]);
    b.extend_from_slice(&(flash_block.len() as u32).to_be_bytes());
    b.extend_from_slice(&off_flash.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD
    b.extend_from_slice(flash_block);
    b
  }

  /// `%Nikon::FlashInfo0100` (0x00a8) decode — a crafted `0100` block exercising
  /// the full conditional matrix, BYTE-EXACT to the `perl exiftool 13.59`
  /// ProcessBinaryData oracle (verified directly against
  /// `Image::ExifTool::Nikon::FlashInfo0100`):
  ///   FlashSource Internal, ExternalFlashFirmware OTHER `"9.05 (Unknown
  ///   model)"`, ExternalFlashFlags BITMASK `Fired, Bounce Flash, Wide Flash
  ///   Adapter`, FlashCommanderMode On + FlashControlMode Manual (byte-9 dual
  ///   read), the Manual-branch FlashOutput `25%`, FlashFocalLength `35 mm`,
  ///   RepeatingFlashRate `10 Hz`, RepeatingFlashCount `3`, FlashGNDistance
  ///   `1.0 m`, FlashGroupAControlMode Manual → FlashGroupAOutput `50%`,
  ///   FlashGroupBControlMode iTTL → FlashGroupBCompensation `-1.5`.
  #[test]
  fn flash_info_0100_decodes() {
    let block: Vec<u8> = b"0100"
      .iter()
      .copied()
      .chain([2, 48, 9, 5, 0x15, 0x86, 12, 35, 10, 3, 10, 0x06, 0x02, 6, 9])
      .collect();
    let (_t, em) = parse(&type3_flash_info(&block), ByteOrder::Big, Some("NIKON D70"));
    let get = |n: &str| lens_get(&em, n);
    assert_eq!(get("FlashInfoVersion"), Some(str_val("0100")));
    assert_eq!(get("FlashSource"), Some(str_val("Internal")));
    assert_eq!(
      get("ExternalFlashFirmware"),
      Some(str_val("9.05 (Unknown model)"))
    );
    assert_eq!(
      get("ExternalFlashFlags"),
      Some(str_val("Fired, Bounce Flash, Wide Flash Adapter"))
    );
    assert_eq!(get("FlashCommanderMode"), Some(str_val("On")));
    assert_eq!(get("FlashControlMode"), Some(str_val("Manual")));
    // FlashControlMode Manual (0x06) ⇒ the Output arm at offset 10, NOT the
    // FlashCompensation arm.
    assert_eq!(get("FlashOutput"), Some(str_val("25%")));
    assert!(get("FlashCompensation").is_none());
    assert_eq!(get("FlashFocalLength"), Some(str_val("35 mm")));
    assert_eq!(get("RepeatingFlashRate"), Some(str_val("10 Hz")));
    assert_eq!(get("RepeatingFlashCount"), Some(TagValue::I64(3)));
    assert_eq!(get("FlashGNDistance"), Some(str_val("1.0 m")));
    assert_eq!(get("FlashGroupAControlMode"), Some(str_val("Manual")));
    assert_eq!(get("FlashGroupBControlMode"), Some(str_val("iTTL")));
    // GroupA Manual (0x06) ⇒ Output arm; GroupB iTTL (0x02) ⇒ Compensation arm.
    assert_eq!(get("FlashGroupAOutput"), Some(str_val("50%")));
    assert!(get("FlashGroupACompensation").is_none());
    assert_eq!(get("FlashGroupBCompensation"), Some(str_val("-1.5")));
    assert!(get("FlashGroupBOutput").is_none());
    // No bogus FlashInfo parent (the SubDirectory pointer never emits it).
    assert!(em.iter().all(|e| e.name() != "FlashInfo"));
  }

  /// `%Nikon::FlashInfo0100` — the all-Off fixture shape (NikonD2Hs/D70 oracle):
  /// firmware `"0 0"` → `"n/a"`, flags `0` → `"(none)"`, the byte-9 Off/Off, the
  /// FlashControlMode-Off branch ⇒ FlashCompensation `0` (a BARE number, NOT the
  /// FlashOutput arm), GN `0`, both group comps `0`. The offset-11/12/13
  /// `RawConv => '$val ? $val : undef'` drops (focal/rate/count 0) emit NOTHING.
  #[test]
  fn flash_info_0100_all_off_with_rawconv_drops() {
    // 19 bytes, all zero after the version + firmware "0 0" + the GN/groups 0.
    let mut block = std::vec![0u8; 19];
    block.get_mut(0..4).unwrap().copy_from_slice(b"0100");
    let (_t, em) = parse(
      &type3_flash_info(&block),
      ByteOrder::Big,
      Some("NIKON D2Hs"),
    );
    let get = |n: &str| lens_get(&em, n);
    assert_eq!(get("FlashInfoVersion"), Some(str_val("0100")));
    assert_eq!(get("FlashSource"), Some(str_val("None")));
    assert_eq!(get("ExternalFlashFirmware"), Some(str_val("n/a")));
    assert_eq!(get("ExternalFlashFlags"), Some(str_val("(none)")));
    assert_eq!(get("FlashCommanderMode"), Some(str_val("Off")));
    assert_eq!(get("FlashControlMode"), Some(str_val("Off")));
    // FlashControlMode Off (< 0x06) ⇒ FlashCompensation; -0/6 = 0 ⇒
    // `PrintFraction(0)` = the STRING "0" (the shared `SignedFractionPrintFraction`
    // contract), which the JSON layer serializes as the BARE number 0 — matching
    // the oracle `"Nikon:FlashCompensation": 0`.
    assert_eq!(get("FlashCompensation"), Some(str_val("0")));
    assert!(get("FlashOutput").is_none());
    assert_eq!(get("FlashGNDistance"), Some(str_val("0")));
    assert_eq!(get("FlashGroupAControlMode"), Some(str_val("Off")));
    assert_eq!(get("FlashGroupBControlMode"), Some(str_val("Off")));
    assert_eq!(get("FlashGroupACompensation"), Some(TagValue::I64(0)));
    assert_eq!(get("FlashGroupBCompensation"), Some(TagValue::I64(0)));
    // RawConv `$val ? $val : undef` drops for a 0 byte — NOT emitted.
    assert!(
      get("FlashFocalLength").is_none(),
      "FlashFocalLength 0 must drop (RawConv undef)"
    );
    assert!(
      get("RepeatingFlashRate").is_none(),
      "RepeatingFlashRate 0 must drop (RawConv undef)"
    );
    assert!(
      get("RepeatingFlashCount").is_none(),
      "RepeatingFlashCount 0 must drop (RawConv undef)"
    );
  }

  /// `%Nikon::FlashInfo0100` — a NON-`0100`/`0101` version (`0103`) is DEFERRED:
  /// the dispatch emits NOTHING (no FlashInfoVersion, no children, no parent),
  /// matching the still-unported FlashInfo0103 arm. A `0101` version IS walked.
  #[test]
  fn flash_info_version_dispatch_gate() {
    // 0103 — deferred arm, emits nothing.
    let mut v0103 = std::vec![0u8; 19];
    v0103.get_mut(0..4).unwrap().copy_from_slice(b"0103");
    let (_t, em) = parse(&type3_flash_info(&v0103), ByteOrder::Big, Some("NIKON D80"));
    assert!(
      em.iter().all(|e| !e.name().starts_with("Flash")),
      "a 0103 FlashInfo must emit nothing (deferred), got {em:?}"
    );
    // 0101 — walked (same FlashInfo0100 table as 0100).
    let mut v0101 = std::vec![0u8; 19];
    v0101.get_mut(0..4).unwrap().copy_from_slice(b"0101");
    let (_t, em) = parse(&type3_flash_info(&v0101), ByteOrder::Big, Some("NIKON D80"));
    assert_eq!(lens_get(&em, "FlashInfoVersion"), Some(str_val("0101")));
    assert_eq!(lens_get(&em, "FlashSource"), Some(str_val("None")));
  }

  /// `%Nikon::FlashInfo0100` `-n` mode (PrintConv off): the post-ValueConv raw
  /// scalars (the firmware "A B" join, the raw int8u flags/GN, the
  /// FlashControlMode masked integer) — verified against `perl exiftool -n`.
  #[test]
  fn flash_info_0100_value_mode() {
    let block: Vec<u8> = b"0100"
      .iter()
      .copied()
      .chain([2, 48, 9, 5, 0x15, 0x86, 12, 35, 10, 3, 10, 0x06, 0x02, 6, 9])
      .collect();
    // print_conv = false ⇒ -n.
    let (_t, em) = parse_with_print_conv(
      &type3_flash_info(&block),
      ByteOrder::Big,
      false,
      Some("NIKON D70"),
    );
    let get = |n: &str| lens_get(&em, n);
    assert_eq!(get("FlashInfoVersion"), Some(str_val("0100")));
    assert_eq!(get("FlashSource"), Some(TagValue::I64(2)));
    // int8u[2] raw join "A B".
    assert_eq!(get("ExternalFlashFirmware"), Some(str_val("9 5")));
    assert_eq!(get("ExternalFlashFlags"), Some(TagValue::I64(0x15)));
    assert_eq!(get("FlashCommanderMode"), Some(TagValue::I64(1)));
    assert_eq!(get("FlashControlMode"), Some(TagValue::I64(6)));
    // FlashOutput -n: post-ValueConv 2**(-12/6) = 0.25.
    assert_eq!(get("FlashOutput"), Some(TagValue::F64(0.25)));
    assert_eq!(get("FlashFocalLength"), Some(TagValue::I64(35)));
    assert_eq!(get("RepeatingFlashRate"), Some(TagValue::I64(10)));
    assert_eq!(get("FlashGNDistance"), Some(TagValue::I64(10)));
    assert_eq!(get("FlashGroupAControlMode"), Some(TagValue::I64(6)));
    assert_eq!(get("FlashGroupBControlMode"), Some(TagValue::I64(2)));
    // GroupB Compensation -n: post-ValueConv -9/6 = -1.5.
    assert_eq!(get("FlashGroupBCompensation"), Some(TagValue::F64(-1.5)));
  }
}
