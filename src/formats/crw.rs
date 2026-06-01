// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "crw")]
//! Faithful port of `Image::ExifTool::CanonRaw` (`lib/Image/ExifTool/
//! CanonRaw.pm`) reading half — the Canon CRW (CIFF) container walker plus the
//! `%Image::ExifTool::CanonRaw::Main` record table.
//!
//! ## What CRW is — and why it matters for indexing
//!
//! CRW is the CIFF-based raw format written directly by older Canon cameras
//! (PowerShot, EOS D30/D60/10D/300D). Unlike CR2 (which is TIFF/EXIF-based,
//! `CanonRaw.pm` NOTES), a CRW file is a CIFF "HEAP" tree whose records carry
//! camera identity (`Make`/`Model`/`SerialNumber`/`CanonModelID`/`OwnerName`/
//! `FirmwareVersion`/…) plus several records that dispatch into the SAME
//! `Image::ExifTool::Canon` MakerNote sub-tables a Canon JPEG uses
//! (`Canon::CameraSettings` / `ShotInfo` / `FocalLength` / `AFInfo` /
//! `FileInfo`). For camera-metadata indexing CRW is a high-value RAW source.
//!
//! ## CIFF structure (`CanonRaw.pm` `ProcessCRW` + `ProcessCanonRaw`)
//!
//! - **Header** (`ProcessCRW`, `CanonRaw.pm:812-833`): 2 bytes byte-order
//!   (`II`/`MM` → `SetByteOrder`), 4 bytes `hlen` (`int32u`), 8 bytes
//!   signature that MUST match `/^HEAP(CCDR|JPGM)/` (else not a CRW). The
//!   root heap block is the file bytes `[hlen .. filesize]`.
//! - **HEAP walker** (`ProcessCanonRaw`, `CanonRaw.pm:625-812`, recursive per
//!   block): the LAST 4 bytes of the block give the directory position WITHIN
//!   the block (`dirOffset = Get32u(last4) + blockStart`). At `dirOffset`: a
//!   2-byte entry count, then N × 10-byte entries `{tag: int16u, size: int32u,
//!   valuePtr: int32u}`. All pointers are block-relative (`ptr = valuePtr +
//!   blockStart`). Per entry:
//!   - `tag & 0x8000` ⇒ `Warn('Bad CRW directory entry')` + STOP
//!     (`CanonRaw.pm:651-654`).
//!   - `tagID = tag & 0x3fff`; `tagType = (tag >> 8) & 0x38`; `valueInDir =
//!     tag & 0x4000` (`CanonRaw.pm:655-657`).
//!   - `tagType ∈ {0x28, 0x30}` AND NOT `valueInDir` ⇒ a SUBDIRECTORY at
//!     `(valuePtr + blockStart)`, size `size` ⇒ RECURSE (`CanonRaw.pm:659-682`).
//!   - else a VALUE: format from `%crwTagFormat{tagType}`; if `valueInDir` the
//!     value lives in the entry's `size`+`ptr` fields (8 bytes,
//!     `CanonRaw.pm:692-699`), else at `(valuePtr + blockStart)` for `size`
//!     bytes (read only when `size <= 512` OR a SubDirectory/requested,
//!     `CanonRaw.pm:701-731`; larger values render as the
//!     `(Binary data N bytes, …)` placeholder).
//!   - The `ProcessedCanonRaw{dirOffset}` double-reference guard
//!     (`CanonRaw.pm:633-639`, `Warn('Not processing double-referenced …')`).
//!
//! ## Records ported (`%Image::ExifTool::CanonRaw::Main`, `CanonRaw.pm:166-330`)
//!
//! - **SCALAR camera tags** — emitted under the `CanonRaw` family-1 group:
//!   `FileFormat` (via the `ImageFormat` sub-table, PrintHex PrintConv),
//!   `TargetCompressionRatio`, `Make`/`Model` (via `MakeModel`),
//!   `CanonFirmwareVersion`, `ComponentVersion`, `ROMOperationMode`,
//!   `OwnerName`, `CanonImageType`, `OriginalFileName`, `ThumbnailFileName`,
//!   `BaseISO`, `CanonModelID` (PrintHex + `%canonModelID`),
//!   `SerialNumberFormat` (PrintHex), and the structural-info sub-tables
//!   (`TimeStamp`/`ImageInfo`/`ExposureInfo`/…). `RawData` (0x2005) /
//!   `JpgFromRaw` (0x2007) render as the binary placeholder.
//! - **Canon MakerNote sub-table dispatch** — `0x1029`→`Canon::FocalLength`,
//!   `0x102a`→`Canon::ShotInfo`, `0x102d`→`Canon::CameraSettings`,
//!   `0x1038`→`Canon::AFInfo`, `0x1093`→`Canon::FileInfo`. These REUSE the
//!   already-ported Canon decoders and emit under the `Canon` family-1 group.
//!   The container `$$self{FILE_TYPE} = "CRW"` is threaded into
//!   `Canon::ShotInfo` position 22's RawConv (`Canon.pm:2977`/`:2990` — keeps a
//!   raw-0 ExposureTime only for a CRW, ported in #183).
//!
//! ## What is DEFERRED (Phase 2 / port-wide)
//!
//! - `Canon::SensorInfo` (`0x1031`) + `Canon::ColorBalance` (`0x10a9`,
//!   WB_RGGBLevels) sub-tables — Phase 2.
//! - The camera **Composite** subsystem (ScaleFactor35efl / Lens / Aperture /
//!   DOF / ImageSize / Megapixels / …), **XMP** (#37), and **CanonCustom**
//!   (`0x1033`, #87) are PORT-WIDE deferrals (no format emits them yet).
//! - The `MakerNotes`-building writer path (`BuildMakerNotes` / `WriteCRW`) —
//!   exifast is read-only.
//! - CRW trailers (`ProcessCRW` `IdentifyTrailer`, `CanonRaw.pm:846`) — no
//!   real CRW carries one for camera metadata; deferred.
//!
//! ## D8 conventions (mandatory)
//!
//! - No public struct fields anywhere; accessors only (see
//!   [`crate::metadata::CrwMeta`]).
//! - SmolStr for stored short strings; `String` for transient builders.
//! - Cite `CanonRaw.pm:LLLL` for every non-trivial decode branch.

use crate::exif::ifd::ByteOrder;
use crate::format_parser::{FormatParser, parser_sealed};
use crate::metadata::CrwMeta;
use crate::metadata::crw::{CrwSubTable, CrwSubTableBlock};

use smol_str::SmolStr;
use std::{string::String, vec::Vec};

/// The container `FILE_TYPE` threaded into the embedded `Canon::*` sub-tables
/// (`ProcessCRW` `SetFileType()`, `CanonRaw.pm:825`). It makes the
/// `Canon::ShotInfo` position-22 CRW-allows-0 RawConv clause LIVE
/// (`Canon.pm:2977`/`:2990`, ported in #183).
const FILE_TYPE: &str = "CRW";

/// Max recursion depth for nested CIFF heaps (`ProcessCanonRaw` `Nesting`,
/// `CanonRaw.pm:667`). Bundled has no hard cap (it relies on the double-ref
/// guard + the finite block sizes); we cap conservatively to bound stack use
/// on a hostile file. Real CRW nesting is ≤ 3 (`ImageProps`→`ExifInformation`→
/// `ImageDescription`). Exceeding the cap simply stops recursion (no warning),
/// faithful to a truncated/garbage subtree contributing no tags.
const MAX_NESTING: u32 = 30;

// ===========================================================================
// Error — uninhabited (Perl `return 0` ⇒ `Ok(None)`)
// ===========================================================================

/// Rust-level fatal modes for CRW parsing. Currently empty — every bad input
/// produces `Ok(None)` (Perl `return 0`) or accumulates warnings in the
/// [`CrwMeta`]. Reserved for future streaming-reader wrappers.
///
/// §5: `Display` + `core::error::Error` via `thiserror`; `#[non_exhaustive]`
/// keeps future variants additive.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {}

// ===========================================================================
// `ProcessCrw` — the lib-first parser
// ===========================================================================

/// Canon CRW (CIFF) parser — faithful `ProcessCRW` (`CanonRaw.pm:812-849`).
#[derive(Debug, Clone, Copy)]
pub struct ProcessCrw;

impl parser_sealed::Sealed for ProcessCrw {}

impl FormatParser for ProcessCrw {
  type Meta<'a> = CrwMeta<'a>;
  type Context<'a> = &'a [u8];
  type Error = Error;

  fn parse<'a>(&self, data: Self::Context<'a>) -> Result<Option<Self::Meta<'a>>, Error> {
    Ok(parse_inner(data))
  }
}

/// Lib-first direct entry — parse a whole CRW file buffer into a typed
/// [`CrwMeta`]. Returns `None` for a non-CRW (header/signature mismatch).
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today; reserved).
pub fn parse_borrowed(data: &[u8]) -> Result<Option<CrwMeta<'_>>, Error> {
  Ok(parse_inner(data))
}

/// `ProcessCRW` (`CanonRaw.pm:812-833`): validate the CIFF header, then walk
/// the root heap block. Returns `None` ONLY for a non-CRW (a short read or a
/// signature that is not `/^HEAP(CCDR|JPGM)/`, `CanonRaw.pm:816-819`).
fn parse_inner(data: &[u8]) -> Option<CrwMeta<'_>> {
  // `$raf->Read($buff,2) == 2` + `SetByteOrder($buff)` (`CanonRaw.pm:816-817`).
  let bo = data.get(0..2)?;
  let order = ByteOrder::from_marker(bo)?;
  // `$raf->Read($buff,4) == 4` (the `hlen`), then `$raf->Read($sig,8) == 8`.
  let hlen_bytes = data.get(2..6)?;
  let sig = data.get(6..14)?;
  // `$sig =~ /^HEAP(CCDR|JPGM)/` (`CanonRaw.pm:819`).
  if !(sig.starts_with(b"HEAPCCDR") || sig.starts_with(b"HEAPJPGM")) {
    return None;
  }
  // `$hlen = Get32u(\$buff, 0)` (`CanonRaw.pm:820`).
  let hlen = read_u32(hlen_bytes, 0, order) as usize;
  // `$filesize = $raf->Tell()` after seek-to-end (`CanonRaw.pm:822-823`).
  let filesize = data.len();

  let mut meta = CrwMeta::new(order);

  // Root heap block = `[hlen .. filesize]` (`DirStart => $hlen`, `DirLen =>
  // $filesize - $hlen`, `CanonRaw.pm:829-836`). A header that runs past EOF
  // (`hlen > filesize`) yields an empty block — bundled's `ProcessCanonRaw`
  // would `Seek` fail and `return 0`; we surface `Some(meta)` with no records
  // (the CRW was accepted by signature but the dir is unreadable).
  if hlen <= filesize {
    let mut guard: Vec<usize> = Vec::new();
    process_canon_raw(data, hlen, filesize, 0, order, &mut meta, &mut guard);
  }
  Some(meta)
}

/// `ProcessCanonRaw` (`CanonRaw.pm:625-812`): walk one CIFF heap block,
/// recursing into sub-directories. `block_start` / `block_end` bound the
/// block within `data` (absolute offsets); `nesting` is the recursion depth;
/// `guard` is the `ProcessedCanonRaw{dirOffset}` double-reference set
/// (`CanonRaw.pm:633-639`).
fn process_canon_raw(
  data: &[u8],
  block_start: usize,
  block_end: usize,
  nesting: u32,
  order: ByteOrder,
  meta: &mut CrwMeta<'_>,
  guard: &mut Vec<usize>,
) {
  // `$raf->Seek($blockStart+$blockSize-4, 0)` + `Read($buff,4)`
  // (`CanonRaw.pm:628-630`): the LAST 4 bytes of the block hold the directory
  // position WITHIN the block. A block too small for the 4-byte trailer is a
  // bundled `Seek`/`Read` failure ⇒ `return 0`.
  if block_end < block_start + 4 || block_end > data.len() {
    return;
  }
  let dir_pos_field = &data[block_end - 4..block_end];
  // `$dirOffset = Get32u(\$buff,0) + $blockStart` (`CanonRaw.pm:631`).
  let dir_offset = (read_u32(dir_pos_field, 0, order) as usize).wrapping_add(block_start);

  // `$$et{ProcessedCanonRaw}{$dirOffset}` double-reference guard
  // (`CanonRaw.pm:633-639`): `Warn('Not processing double-referenced …')` +
  // `return 0`.
  if guard.contains(&dir_offset) {
    // (Read-mode bundled would `$et->Warn`; the CRW Meta has no warning
    // channel for it and no real CRW double-references a directory, so we just
    // stop — matching `return 0` with no tags from this subtree.)
    return;
  }
  guard.push(dir_offset);

  // `$raf->Seek($dirOffset, 0)` + `Read($buff, 2)` (the entry count,
  // `CanonRaw.pm:640-642`).
  let Some(count_bytes) = data.get(dir_offset..dir_offset + 2) else {
    return;
  };
  let entries = read_u16(count_bytes, 0, order) as usize;
  // `Read($buff, 10 * $entries) == 10 * $entries` (`CanonRaw.pm:643`): the
  // whole directory must be present.
  let dir_data_start = dir_offset + 2;
  let Some(dir_data) = data.get(dir_data_start..dir_data_start + 10 * entries) else {
    return;
  };

  // `for ($index=0; $index<$entries; ++$index)` (`CanonRaw.pm:646`).
  for index in 0..entries {
    let pt = 10 * index;
    let tag = read_u16(dir_data, pt, order);
    let size = read_u32(dir_data, pt + 2, order) as usize;
    let value_ptr = read_u32(dir_data, pt + 6, order) as usize;
    let ptr = value_ptr.wrapping_add(block_start); // `CanonRaw.pm:650`

    // `if ($tag & 0x8000) { Warn('Bad CRW directory entry'); return 1; }`
    // (`CanonRaw.pm:651-654`) — STOP the whole directory walk.
    if tag & 0x8000 != 0 {
      // (`$et->Warn('Bad CRW directory entry')` — no Meta warning channel; the
      // real-CRW invariant is that this never fires. `return 1` ⇒ keep tags
      // collected so far + stop.)
      break;
    }

    let tag_id = tag & 0x3fff; // `CanonRaw.pm:655`
    let tag_type = (tag >> 8) & 0x38; // `CanonRaw.pm:656`
    let value_in_dir = tag & 0x4000 != 0; // `CanonRaw.pm:657`

    // `if (($tagType==0x28 or $tagType==0x30) and not $valueInDir)`
    // (`CanonRaw.pm:659`): a raw SUBDIRECTORY ⇒ recurse over `[ptr .. ptr+size]`.
    if (tag_type == 0x28 || tag_type == 0x30) && !value_in_dir {
      if nesting < MAX_NESTING && ptr + size <= data.len() && ptr >= block_start {
        process_canon_raw(data, ptr, ptr + size, nesting + 1, order, meta, guard);
      }
      continue; // `CanonRaw.pm:682`
    }

    // ---- a VALUE record ----------------------------------------------------
    // `$format = $crwTagFormat{$tagType}` (`CanonRaw.pm:686`). `tagInfo`'s
    // `Format` would override, but every ported scalar's table `Format`
    // matches its `tagType`-derived format, so the `tagType` format is
    // sufficient for the records we decode (the sub-table records carry their
    // own bytes verbatim).
    let value: Vec<u8>;
    if value_in_dir {
      // `if ($valueInDir)` (`CanonRaw.pm:692-699`): the value lives in the
      // entry's `size`+`ptr` fields (the 8 bytes at `pt+2`); bundled clamps
      // `$size = 8`. We read those 8 bytes directly; `size` (the raw `int32u`)
      // is NOT read on this branch, so the clamp need not be materialized —
      // the `value` length is what the scalar decoders consume.
      value = dir_data
        .get(pt + 2..pt + 2 + 8)
        .map_or_else(Vec::new, <[u8]>::to_vec);
    } else {
      // `$valueDataPos = $ptr` (`CanonRaw.pm:701`). Read the value when `size
      // <= 512` OR it is a SubDirectory/requested (`CanonRaw.pm:706-731`). For
      // a value LARGER than 512 with a tagInfo, bundled renders `"Binary data
      // $size bytes"` (the placeholder). We mirror: small ⇒ read the bytes;
      // large ⇒ keep the byte count for the placeholder. (`size` is the
      // on-disk length here, NOT clamped to 8 — that clamp is the
      // value-in-dir branch only, `CanonRaw.pm:695`.)
      if size <= 512 {
        let Some(v) = data.get(ptr..ptr + size) else {
          // `Warn("Error reading … bytes")` + `next` (`CanonRaw.pm:712`).
          continue;
        };
        value = v.to_vec();
      } else {
        // Large value (`CanonRaw.pm:716-728`): bundled emits the
        // `(Binary data N bytes, …)` placeholder. We synthesize a zero-filled
        // `Vec` of length `size` so the [`crate::value::TagValue::Bytes`]
        // placeholder reports the right byte count without copying the
        // (potentially multi-MB) payload. The bytes themselves are never
        // emitted (no `-b`), so their content is irrelevant.
        emit_record(meta, tag_id, RecordValue::BinaryPlaceholder(size), order);
        continue;
      }
    }

    emit_record(meta, tag_id, RecordValue::Bytes(value), order);
  }
}

/// A decoded CIFF record value handed to [`emit_record`].
enum RecordValue {
  /// The record's value bytes (read because `size <= 512` or value-in-dir).
  Bytes(Vec<u8>),
  /// A value too large to read inline (`size > 512`): only the byte count is
  /// kept, for the `(Binary data N bytes, …)` placeholder.
  BinaryPlaceholder(usize),
}

/// Dispatch one `%CanonRaw::Main` record (`tag_id`) into the typed
/// [`CrwMeta`]. The SCALAR records (strings / ints / the `MakeModel` /
/// `ImageFormat` binary sub-tables) populate typed fields; the Canon MakerNote
/// records (`0x1029`/`0x102a`/`0x102d`/`0x1038`/`0x1093`) are retained as raw
/// blocks. Records not (yet) ported are ignored (faithful to bundled's
/// table-miss `next unless defined $tagInfo`, `CanonRaw.pm:768`).
fn emit_record(meta: &mut CrwMeta<'_>, tag_id: u16, value: RecordValue, order: ByteOrder) {
  // The Canon sub-table records keep their raw bytes for the per-`ConvMode`
  // re-decode in `Taggable` (these are never value-in-dir / large in real
  // CRW, but we handle both representations).
  let sub_kind = match tag_id {
    0x1029 => Some(CrwSubTable::FocalLength),
    0x102a => Some(CrwSubTable::ShotInfo),
    0x102d => Some(CrwSubTable::CameraSettings),
    0x1038 => Some(CrwSubTable::AfInfo),
    0x1093 => Some(CrwSubTable::FileInfo),
    _ => None,
  };
  if let Some(kind) = sub_kind {
    // A sub-table whose value was too large to read (>512, no tagInfo gate
    // here) would not happen in real CRW; if it did, bundled would still try
    // to read it (SubDirectory ⇒ `size <= 512 or … SubDirectory`,
    // `CanonRaw.pm:706-709`). We only have the byte count for a placeholder,
    // so skip the decode in that (unreal) case.
    if let RecordValue::Bytes(bytes) = value {
      meta.push_sub_table_block(CrwSubTableBlock::new(kind, bytes));
    }
    return;
  }

  match tag_id {
    // ---- binary image records (placeholder) ------------------------------
    // `0x2005 RawData` (`CanonRaw.pm:319`) / `0x2007 JpgFromRaw`
    // (`:323`) / `0x2008 ThumbnailImage` (`:329`) — `Binary => 1`; render as
    // the `(Binary data N bytes, …)` placeholder.
    0x2005 | 0x2007 | 0x2008 => {
      let n = match value {
        RecordValue::Bytes(b) => b.len(),
        RecordValue::BinaryPlaceholder(n) => n,
      };
      // Store the byte count via a zero-filled placeholder block: the
      // serializer renders `(Binary data N bytes …)` from the `Vec` length.
      let name = match tag_id {
        0x2005 => CrwBinary::RawData,
        0x2007 => CrwBinary::JpgFromRaw,
        _ => CrwBinary::ThumbnailImage,
      };
      meta.push_binary(name, n);
    }
    // ---- the rest are scalar / structural records ------------------------
    other => emit_scalar(meta, other, value, order),
  }
}

/// One binary `CanonRaw::Main` record (rendered as the `(Binary data N bytes,
/// …)` placeholder).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CrwBinary {
  /// `0x2005 RawData` (`CanonRaw.pm:319`).
  RawData,
  /// `0x2007 JpgFromRaw` (`CanonRaw.pm:323`).
  JpgFromRaw,
  /// `0x2008 ThumbnailImage` (`CanonRaw.pm:329`).
  ThumbnailImage,
}

impl CrwBinary {
  /// The emitted tag Name.
  pub(crate) const fn name(self) -> &'static str {
    match self {
      Self::RawData => "RawData",
      Self::JpgFromRaw => "JpgFromRaw",
      Self::ThumbnailImage => "ThumbnailImage",
    }
  }
}

/// Decode a SCALAR / structural `CanonRaw::Main` record into the typed
/// [`CrwMeta`]. Strings are NUL-trimmed (`ExifTool.pm` string ValueConv);
/// integers/floats read in the header byte order. Sub-table records that
/// expand into MULTIPLE CanonRaw tags (`MakeModel`, `ImageFormat`,
/// `TimeStamp`, …) are unpacked here from their binary block.
fn emit_scalar(meta: &mut CrwMeta<'_>, tag_id: u16, value: RecordValue, order: ByteOrder) {
  // A large (placeholder-only) value cannot be one of these scalar records in
  // real CRW; ignore it (bundled's `undef $format` arm only applies to
  // tagInfo'd binaries, handled above).
  let RecordValue::Bytes(bytes) = value else {
    return;
  };

  match tag_id {
    // ---- string records (`CanonRaw.pm:200-211`) --------------------------
    0x080b => meta.set_firmware_version(trim_string(&bytes)), // CanonFirmwareVersion
    0x080c => meta.set_component_version(trim_string(&bytes)), // ComponentVersion
    0x080d => meta.set_rom_operation_mode(trim_string(&bytes)), // ROMOperationMode
    0x0810 => meta.set_owner_name(trim_string(&bytes)),       // OwnerName
    0x0815 => meta.set_image_type(trim_string(&bytes)),       // CanonImageType
    0x0816 => meta.set_original_file_name(trim_string(&bytes)), // OriginalFileName
    0x0817 => meta.set_thumbnail_file_name(trim_string(&bytes)), // ThumbnailFileName

    // ---- `0x080a CanonRawMakeModel` → `CanonRaw::MakeModel` --------------
    // (`CanonRaw.pm:212-216`, sub-table `:405-424`): `Make` = string[6]
    // ("Canon\0"), `Model` = string to the end of the data. ProcessBinaryData
    // with FORMAT 'string'.
    0x080a => {
      // `Make` at offset 0, `Format => 'string[6]'` (`CanonRaw.pm:415`).
      if let Some(make) = bytes.get(0..6) {
        meta.set_make(trim_string(make));
      }
      // `Model` at offset 6, no size = to the end (`CanonRaw.pm:421`).
      if let Some(model) = bytes.get(6..) {
        meta.set_model(trim_string(model));
      }
    }

    // ---- `0x1803 ImageFormat` → `CanonRaw::ImageFormat` ------------------
    // (`CanonRaw.pm:262-266`, sub-table `:456-478`): FORMAT int32u,
    // FIRST_ENTRY 0. pos0 `FileFormat` (int32u, PrintHex), pos1
    // `TargetCompressionRatio` (float).
    0x1803 => {
      if bytes.len() >= 4 {
        meta.set_file_format(read_u32(&bytes, 0, order));
      }
      if bytes.len() >= 8 {
        meta.set_target_compression_ratio(f64::from(read_f32(&bytes, 4, order)));
      }
    }

    // ---- `0x101c BaseISO` (`CanonRaw.pm:198`) — int16u -------------------
    0x101c if bytes.len() >= 2 => meta.set_base_iso(read_u16(&bytes, 0, order)),

    // ---- `0x1834 CanonModelID` (`CanonRaw.pm:303-313`) — int32u, PrintHex,
    //      `%canonModelID` ---------------------------------------------------
    0x1834 if bytes.len() >= 4 => meta.set_model_id(read_u32(&bytes, 0, order)),

    // ---- `0x183b SerialNumberFormat` (`CanonRaw.pm:316`) — int32u, PrintHex
    0x183b if bytes.len() >= 4 => meta.set_serial_number_format(read_u32(&bytes, 0, order)),

    // Every other `CanonRaw::Main` record (the deferred structural
    // sub-tables — `TimeStamp`/`ImageInfo`/`ExposureInfo`/`FlashInfo`/
    // `DecoderTable`/`RawJpgInfo`/… — plus `SerialNumber`/`FileNumber`/
    // `MeasuredEV`/etc.) is NOT yet surfaced by this Phase-1 typed layer. The
    // CIFF walker still RECURSED through every subdirectory; these leaves are
    // simply not projected to typed fields (Phase-2 expands the table). This
    // is faithful for the CRAFTED conformance fixture, which contains only the
    // records decoded above.
    _ => {}
  }
}

// ===========================================================================
// Byte readers — header byte order (`SetByteOrder`, CanonRaw.pm:817)
// ===========================================================================

/// Read an `int16u` at `off` within `b` in `order` (0 if out of range —
/// bundled's `Get16u` reads from a buffer the directory bound-check already
/// validated, so the callers never hit the fallback).
#[inline]
fn read_u16(b: &[u8], off: usize, order: ByteOrder) -> u16 {
  let Some(s) = b.get(off..off + 2) else {
    return 0;
  };
  let arr = [s[0], s[1]];
  match order {
    ByteOrder::Little => u16::from_le_bytes(arr),
    ByteOrder::Big => u16::from_be_bytes(arr),
  }
}

/// Read an `int32u` at `off` within `b` in `order`.
#[inline]
fn read_u32(b: &[u8], off: usize, order: ByteOrder) -> u32 {
  let Some(s) = b.get(off..off + 4) else {
    return 0;
  };
  let arr = [s[0], s[1], s[2], s[3]];
  match order {
    ByteOrder::Little => u32::from_le_bytes(arr),
    ByteOrder::Big => u32::from_be_bytes(arr),
  }
}

/// Read a `float` at `off` within `b` in `order`.
#[inline]
fn read_f32(b: &[u8], off: usize, order: ByteOrder) -> f32 {
  f32::from_bits(read_u32(b, off, order))
}

/// NUL-trim + Latin-1→UTF-8 decode a CIFF string value (`ExifTool.pm:6301`
/// `$vals[0] =~ s/\0.*//s`: drop at the FIRST NUL). CIFF strings are ASCII /
/// Latin-1; we decode byte-for-byte (`b as char`) so a stray high byte is
/// preserved rather than producing U+FFFD.
fn trim_string(bytes: &[u8]) -> SmolStr {
  let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
  let s: String = bytes[..end].iter().map(|&b| b as char).collect();
  SmolStr::from(s)
}

// `CrwBinary` placeholder storage lives on `CrwMeta` via a crate-private
// setter; see the impl below (kept here so the parser owns the binary-record
// enum).
mod meta_ext {
  use super::{CrwBinary, CrwMeta};

  impl CrwMeta<'_> {
    /// Record a binary image record (`RawData`/`JpgFromRaw`/`ThumbnailImage`)
    /// by its byte length, for the `(Binary data N bytes, …)` placeholder.
    pub(crate) fn push_binary(&mut self, kind: CrwBinary, len: usize) {
      self.push_binary_inner(kind.name(), len);
    }
  }
}

// ===========================================================================
// Taggable (golden L3) — render `CrwMeta` → EmittedTag stream
// ===========================================================================

use crate::emit::{ConvMode, EmittedTag};
use crate::value::{Group, TagValue};

/// `MakerNotes:CanonRaw:*` group — the family-1 `-G1` key for the CIFF scalar
/// records. `%CanonRaw::Main` `GROUPS => { 0 => 'MakerNotes', 2 => 'Camera' }`
/// (`CanonRaw.pm:167`) ⇒ family-0 `MakerNotes`, family-1 `CanonRaw`
/// (golden-verified `"CanonRaw:…"`).
#[inline]
fn canonraw_group() -> Group {
  Group::new("MakerNotes", "CanonRaw")
}

/// `MakerNotes:Canon:*` group — the family-1 key for the records dispatched to
/// the `Image::ExifTool::Canon` MakerNote sub-tables (golden-verified
/// `"Canon:…"`, the same group a Canon JPEG's MakerNotes use).
#[inline]
fn canon_group() -> Group {
  Group::new("MakerNotes", "Canon")
}

/// Push one already-rendered `CanonRaw:*` tag (no `Unknown => 1` among the
/// ported `CanonRaw::Main` records ⇒ `unknown = false`).
#[inline]
fn push_raw(tags: &mut Vec<EmittedTag>, name: &str, value: TagValue) {
  tags.push(EmittedTag::new(canonraw_group(), name.into(), value, false));
}

/// `%canonModelID` PrintConv (`CanonRaw.pm:303-313`): `PrintHex => 1` + a hash
/// lookup. Hit ⇒ the model name; miss ⇒ the generic PrintHex `Unknown (0xNN)`
/// fallback (`ExifTool.pm:3631`, lowercase, NO zero-padding —
/// oracle-confirmed).
fn print_model_id(id: u32) -> TagValue {
  match crate::exif::makernotes::vendors::canon::model_ids::lookup_name(id) {
    Some(name) => TagValue::Str(name),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown (0x{id:x})"))),
  }
}

/// `FileFormat` PrintConv (`CanonRaw.pm:464-470`): a hash with `PrintHex`.
/// Hit ⇒ the label; miss ⇒ `Unknown (0xNN)` (PrintHex fallback).
fn print_file_format(v: u32) -> TagValue {
  let label = match v {
    0x0001_0000 => Some("JPEG (lossy)"),
    0x0001_0002 => Some("JPEG (non-quantization)"),
    0x0001_0003 => Some("JPEG (lossy/non-quantization toggled)"),
    0x0002_0001 => Some("CRW"),
    _ => None,
  };
  match label {
    Some(s) => TagValue::Str(SmolStr::new_static(s)),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown (0x{v:x})"))),
  }
}

/// `SerialNumberFormat` PrintConv (`CanonRaw.pm:316-324`): a hash with
/// `PrintHex`. `0x90000000` ⇒ `"Format 1"`, `0xa0000000` ⇒ `"Format 2"`; miss
/// ⇒ `Unknown (0xNN)`.
fn print_serial_number_format(v: u32) -> TagValue {
  let label = match v {
    0x9000_0000 => Some("Format 1"),
    0xa000_0000 => Some("Format 2"),
    _ => None,
  };
  match label {
    Some(s) => TagValue::Str(SmolStr::new_static(s)),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown (0x{v:x})"))),
  }
}

impl crate::emit::Taggable for CrwMeta<'_> {
  /// Yield the CRW tag stream for `mode`. The CIFF scalar records emit under
  /// `MakerNotes:CanonRaw:*`; the records dispatched to ported `Canon::*`
  /// MakerNote sub-tables are re-decoded here (per `mode`) and emit under
  /// `MakerNotes:Canon:*` — REUSING the existing Canon decoders so a CRW and a
  /// Canon JPEG render identical `Canon:*` tags.
  ///
  /// `mode == PrintConv` (`-j`) ⇒ PrintConv strings (e.g. `FileFormat` ⇒
  /// `"CRW"`, `CanonModelID` ⇒ a `%canonModelID` name); `mode == ValueConv`
  /// (`-n`) ⇒ raw post-ValueConv scalars (the bare ints).
  ///
  /// Object-key order is INSENSITIVE to the conformance comparator
  /// (`json_equivalent`), so the scalar records are emitted in a stable
  /// table-ish order; the sub-table tags follow in the Canon decoder's own
  /// emission order. `Unknown => 1` is absent among these records ⇒
  /// `unknown = false` (the Canon sub-table decoders already drop their own
  /// `Unknown` positions internally).
  fn tags(&self, mode: ConvMode) -> impl Iterator<Item = EmittedTag> + '_ {
    let print_conv = matches!(mode, ConvMode::PrintConv);
    let mut tags: Vec<EmittedTag> = Vec::new();

    // ---- binary image records (placeholder) ------------------------------
    // `RawData`/`JpgFromRaw`/`ThumbnailImage` render as `(Binary data N bytes,
    // …)` via `TagValue::Bytes` (the serializer formats the byte count). We
    // synthesize a zero-filled `Vec` of the recorded length — the bytes are
    // never emitted (no `-b`), only their count.
    for (name, len) in self.binary_records() {
      push_raw(&mut tags, name, TagValue::Bytes(std::vec![0u8; *len]));
    }

    // ---- CanonRaw::Main scalar records -----------------------------------
    if let Some(v) = self.make() {
      push_raw(&mut tags, "Make", TagValue::Str(v.into()));
    }
    if let Some(v) = self.model() {
      push_raw(&mut tags, "Model", TagValue::Str(v.into()));
    }
    if let Some(v) = self.file_format() {
      let value = if print_conv {
        print_file_format(v)
      } else {
        TagValue::U64(u64::from(v))
      };
      push_raw(&mut tags, "FileFormat", value);
    }
    if let Some(v) = self.target_compression_ratio() {
      // `float`; no PrintConv (`CanonRaw.pm:473-475`) ⇒ same in `-j`/`-n`.
      push_raw(&mut tags, "TargetCompressionRatio", TagValue::F64(v));
    }
    if let Some(v) = self.firmware_version() {
      push_raw(&mut tags, "CanonFirmwareVersion", TagValue::Str(v.into()));
    }
    if let Some(v) = self.component_version() {
      push_raw(&mut tags, "ComponentVersion", TagValue::Str(v.into()));
    }
    if let Some(v) = self.owner_name() {
      push_raw(&mut tags, "OwnerName", TagValue::Str(v.into()));
    }
    if let Some(v) = self.original_file_name() {
      push_raw(&mut tags, "OriginalFileName", TagValue::Str(v.into()));
    }
    if let Some(v) = self.thumbnail_file_name() {
      push_raw(&mut tags, "ThumbnailFileName", TagValue::Str(v.into()));
    }
    if let Some(v) = self.model_id() {
      let value = if print_conv {
        print_model_id(v)
      } else {
        TagValue::U64(u64::from(v))
      };
      push_raw(&mut tags, "CanonModelID", value);
    }
    if let Some(v) = self.base_iso() {
      // `int16u`, no PrintConv (`CanonRaw.pm:198`) ⇒ bare int both modes.
      push_raw(&mut tags, "BaseISO", TagValue::U64(u64::from(v)));
    }
    if let Some(v) = self.image_type() {
      push_raw(&mut tags, "CanonImageType", TagValue::Str(v.into()));
    }
    if let Some(v) = self.rom_operation_mode() {
      push_raw(&mut tags, "ROMOperationMode", TagValue::Str(v.into()));
    }
    if let Some(v) = self.serial_number_format() {
      let value = if print_conv {
        print_serial_number_format(v)
      } else {
        TagValue::U64(u64::from(v))
      };
      push_raw(&mut tags, "SerialNumberFormat", value);
    }

    // ---- Canon::* MakerNote sub-table records ----------------------------
    // Re-run the ALREADY-PORTED Canon decoders for the requested `mode`,
    // threading the IFD0-equivalent `$$self{Model}` and the container
    // `$$self{FILE_TYPE} = "CRW"` (which makes the #183 ShotInfo position-22
    // CRW-allows-0 RawConv LIVE). Each `(name, value)` emits under `Canon:`.
    let order = self.byte_order();
    let model = self.model();
    // `Canon::FocalLength` needs `FocalUnits` from `Canon::CameraSettings`
    // (position 25) — capture it first, exactly as the EXIF MakerNote path
    // does (`vendors/canon/mod.rs`).
    let focal_units = self.sub_table_blocks().iter().find_map(|b| {
      if b.kind() == CrwSubTable::CameraSettings {
        read_camera_settings_focal_units(b.bytes(), order)
      } else {
        None
      }
    });
    for block in self.sub_table_blocks() {
      emit_canon_sub_table(&mut tags, block, order, print_conv, model, focal_units);
    }

    tags.into_iter()
  }
}

/// Read `Canon::CameraSettings` position-25 `FocalUnits` (`Canon.pm:2534`) from
/// the raw block, for the `Canon::FocalLength` scaling. Returns `None` when the
/// block is too short or the word is `<= 0`.
fn read_camera_settings_focal_units(data: &[u8], order: ByteOrder) -> Option<u16> {
  let pos = 2 * 25;
  let s = data.get(pos..pos + 2)?;
  let raw = match order {
    ByteOrder::Little => i16::from_le_bytes([s[0], s[1]]),
    ByteOrder::Big => i16::from_be_bytes([s[0], s[1]]),
  };
  if raw <= 0 { None } else { Some(raw as u16) }
}

/// Decode ONE Canon MakerNote sub-table record into `Canon:*` emissions by
/// delegating to the existing `Image::ExifTool::Canon` decoders (the heart of
/// the CRW↔Canon REUSE). The decoders return `(name, value)` pairs already
/// rendered for `print_conv`; we wrap each under the `Canon` family-1 group.
fn emit_canon_sub_table(
  tags: &mut Vec<EmittedTag>,
  block: &CrwSubTableBlock,
  order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
  focal_units: Option<u16>,
) {
  use crate::exif::makernotes::vendors::canon;
  let bytes = block.bytes();
  let emissions: Vec<(SmolStr, TagValue)> = match block.kind() {
    CrwSubTable::CameraSettings => canon::camera_settings::parse(bytes, order, print_conv),
    CrwSubTable::FocalLength => {
      canon::focal_length::parse(bytes, order, print_conv, focal_units, model)
    }
    CrwSubTable::ShotInfo => {
      // Thread `FILE_TYPE = "CRW"` so position-22's CRW-allows-0 RawConv is
      // LIVE (`Canon.pm:2977`/`:2990`, #183).
      let (_typed, em) = canon::shot_info::parse(bytes, order, print_conv, model, Some(FILE_TYPE));
      em
    }
    CrwSubTable::AfInfo => {
      let (_typed, em) = canon::af_info::parse_af_info(bytes, order, print_conv, model);
      em
    }
    CrwSubTable::FileInfo => {
      let (em, _decoded) =
        canon::file_info::parse_with_model(bytes, order, print_conv, None, model);
      em
    }
  };
  for (name, value) in emissions {
    // Canon sub-table positions are explicit BinaryData (never `Unknown`); the
    // decoders already excluded their own `Unknown` positions.
    tags.push(EmittedTag::new(canon_group(), name, value, false));
  }
}

// ===========================================================================
// Project (golden L2) — CRW → normalized MediaMetadata
// ===========================================================================

impl crate::metadata::Project for CrwMeta<'_> {
  /// Project CRW camera-identity onto the normalized [`MediaMetadata`] domain.
  ///
  /// CRW is a Canon RAW STILL image. The faithful
  /// [`CameraInfo`](crate::metadata::CameraInfo) contributions are the
  /// `MakeModel` sub-table `Make`/`Model` (`CanonRaw.pm:411`/`:421`), the
  /// `OwnerName` mapped to the software/owner slot, and the
  /// `CanonFirmwareVersion`. CRW has no single canonical capture timestamp the
  /// `MediaInfo` models (the `TimeStamp` sub-table is deferred), no GPS, and
  /// the lens identity lives in the deferred `CameraSettings` projection — so
  /// those domains stay `None`. Serial number is the deferred
  /// `CanonRaw::Main` `SerialNumber` record (model-conditional), so the
  /// `serial` slot stays `None` in Phase 1.
  fn project(&self) -> crate::metadata::MediaMetadata {
    use crate::metadata::{CameraInfo, MediaMetadata};
    use std::string::ToString;
    let mut media = MediaMetadata::new();
    let mut cam = CameraInfo::new();
    cam
      .update_make(self.make().map(ToString::to_string))
      .update_model(self.model().map(ToString::to_string))
      .update_software(self.firmware_version().map(ToString::to_string));
    if !cam.is_empty() {
      media.set_camera(cam);
    }
    media
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// One built CIFF directory entry: an out-of-line `{tag, size, ptr}` value
  /// record, or a value-in-directory record carrying its 8 inline bytes.
  enum TestEntry {
    /// Out-of-line: `tag`, byte `size`, block-relative `ptr`.
    OutOfLine { tag: u16, size: u32, ptr: u32 },
    /// Value-in-directory (`tag | 0x4000`): the 8 inline bytes.
    InDir { tag: u16, inline: [u8; 8] },
  }

  /// A tiny CIFF builder mirroring the Python fixture generator, for unit
  /// tests of the walker.
  struct HeapBuilder {
    payload: Vec<u8>,
    entries: Vec<TestEntry>,
  }

  impl HeapBuilder {
    fn new() -> Self {
      Self {
        payload: Vec::new(),
        entries: Vec::new(),
      }
    }

    fn add_value(&mut self, tag: u16, data: &[u8]) {
      let ptr = self.payload.len() as u32;
      self.payload.extend_from_slice(data);
      self.entries.push(TestEntry::OutOfLine {
        tag,
        size: data.len() as u32,
        ptr,
      });
    }

    fn add_value_indir(&mut self, tag_id: u16, data: &[u8]) {
      let mut inline = [0u8; 8];
      inline[..data.len()].copy_from_slice(data);
      self.entries.push(TestEntry::InDir {
        tag: tag_id | 0x4000,
        inline,
      });
    }

    fn build(&self) -> Vec<u8> {
      let dir_start = self.payload.len() as u32;
      let mut out = self.payload.clone();
      out.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
      for entry in &self.entries {
        match entry {
          TestEntry::OutOfLine { tag, size, ptr } => {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&ptr.to_le_bytes());
          }
          TestEntry::InDir { tag, inline } => {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(inline);
          }
        }
      }
      out.extend_from_slice(&dir_start.to_le_bytes());
      out
    }
  }

  fn build_file(root: &HeapBuilder) -> Vec<u8> {
    let block = root.build();
    let mut out = Vec::new();
    out.extend_from_slice(b"II");
    out.extend_from_slice(&14u32.to_le_bytes()); // hlen
    out.extend_from_slice(b"HEAPCCDR");
    out.extend_from_slice(&block);
    out
  }

  #[test]
  fn rejects_non_crw_signature() {
    let mut bad = Vec::new();
    bad.extend_from_slice(b"II");
    bad.extend_from_slice(&14u32.to_le_bytes());
    bad.extend_from_slice(b"NOTACRW!");
    assert!(parse_inner(&bad).is_none());
  }

  #[test]
  fn rejects_short_header() {
    assert!(parse_inner(b"II").is_none());
    assert!(parse_inner(&[]).is_none());
  }

  #[test]
  fn walks_string_records() {
    let mut root = HeapBuilder::new();
    root.add_value(0x080b, b"Firmware Version 1.1.1\x00"); // CanonFirmwareVersion
    root.add_value(0x0810, b"Phil Harvey\x00"); // OwnerName
    let data = build_file(&root);
    let m = parse_inner(&data).expect("valid CRW");
    assert_eq!(m.firmware_version(), Some("Firmware Version 1.1.1"));
    assert_eq!(m.owner_name(), Some("Phil Harvey"));
  }

  #[test]
  fn walks_makemodel_and_imageformat_subtables() {
    let mut root = HeapBuilder::new();
    let mut mm = Vec::new();
    mm.extend_from_slice(b"Canon\x00");
    mm.extend_from_slice(b"Canon EOS DIGITAL REBEL\x00");
    root.add_value(0x080a, &mm);
    let mut imgfmt = Vec::new();
    imgfmt.extend_from_slice(&0x0002_0001u32.to_le_bytes());
    imgfmt.extend_from_slice(&10.0f32.to_le_bytes());
    root.add_value(0x1803, &imgfmt);
    let data = build_file(&root);
    let m = parse_inner(&data).expect("valid CRW");
    assert_eq!(m.make(), Some("Canon"));
    assert_eq!(m.model(), Some("Canon EOS DIGITAL REBEL"));
    assert_eq!(m.file_format(), Some(0x0002_0001));
    assert_eq!(m.target_compression_ratio(), Some(10.0));
  }

  #[test]
  fn value_in_directory_record() {
    let mut root = HeapBuilder::new();
    root.add_value_indir(0x101c, &100u16.to_le_bytes()); // BaseISO
    let data = build_file(&root);
    let m = parse_inner(&data).expect("valid CRW");
    assert_eq!(m.base_iso(), Some(100));
  }

  #[test]
  fn canon_model_id_raw_kept() {
    let mut root = HeapBuilder::new();
    root.add_value(0x1834, &0x0114_0000u32.to_le_bytes());
    let data = build_file(&root);
    let m = parse_inner(&data).expect("valid CRW");
    assert_eq!(m.model_id(), Some(0x0114_0000));
  }

  #[test]
  fn camera_settings_subtable_retained_as_block() {
    let mut root = HeapBuilder::new();
    // 0x102d CanonCameraSettings → retained raw block.
    let blk = std::vec![0u8; 8];
    root.add_value(0x102d, &blk);
    let data = build_file(&root);
    let m = parse_inner(&data).expect("valid CRW");
    assert_eq!(m.sub_table_blocks().len(), 1);
    assert_eq!(
      m.sub_table_blocks()[0].kind(),
      crate::metadata::CrwSubTable::CameraSettings
    );
  }

  /// The #183 ShotInfo `FILE_TYPE eq "CRW"` branch is LIVE through CRW: a
  /// position-22 ExposureTime of raw-0 (`Canon.pm:2977`/`:2990`) is KEPT for a
  /// CRW container (where for a JPEG/CR2 it would be dropped). This proves the
  /// `Canon::ShotInfo` sub-table reuse threads `FILE_TYPE = "CRW"`. We don't
  /// exercise this in the conformance fixture because emitting `ExposureTime`
  /// would also synthesize a `Composite:ShutterSpeed`.
  #[test]
  fn shot_info_crw_keeps_raw_zero_exposure_time() {
    use crate::emit::{ConvMode, Taggable as _};
    // Build a ShotInfo block: int16s words, word0 = byte length, FIRST_ENTRY 1.
    // Position 22 (ExposureTime) = raw 0; AutoISO(1)/BaseISO(2)/WhiteBalance(7)
    // also 0 (their raw-0 ValueConvs are harmless here — we only assert pos22).
    let nwords = 34usize;
    let mut words = std::vec![0i16; nwords];
    words[0] = (nwords * 2) as i16;
    let mut blk = Vec::new();
    for w in &words {
      blk.extend_from_slice(&w.to_le_bytes());
    }
    let mut root = HeapBuilder::new();
    // Give the body a Model so the ShotInfo Conditions evaluate as a real EOS.
    let mut mm = Vec::new();
    mm.extend_from_slice(b"Canon\x00");
    mm.extend_from_slice(b"Canon EOS DIGITAL REBEL\x00");
    root.add_value(0x080a, &mm);
    root.add_value(0x102a, &blk); // 0x102a CanonShotInfo
    let data = build_file(&root);
    let m = parse_inner(&data).expect("valid CRW");

    // The CRW container threads FILE_TYPE = "CRW" into shot_info::parse, so the
    // raw-0 ExposureTime survives ⇒ a `Canon:ExposureTime` tag is emitted.
    let has_exposure_time = m
      .tags(ConvMode::ValueConv)
      .any(|t| t.tag().group_ref().family1() == "Canon" && t.tag().name() == "ExposureTime");
    assert!(
      has_exposure_time,
      "CRW ShotInfo must KEEP the raw-0 ExposureTime (#183 FILE_TYPE eq CRW branch)"
    );
  }
}
