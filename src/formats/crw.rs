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
//!   (`TimeStamp`/`ImageInfo`/`ExposureInfo`/…). `FreeBytes` (0x0001) /
//!   `RawData` (0x2005) / `JpgFromRaw` (0x2007) render as the binary
//!   placeholder.
//! - **Canon MakerNote sub-table dispatch** — `0x1029`→`Canon::FocalLength`,
//!   `0x102a`→`Canon::ShotInfo`, `0x102d`→`Canon::CameraSettings`,
//!   `0x1038`→`Canon::AFInfo`, `0x1093`→`Canon::FileInfo`. These REUSE the
//!   already-ported Canon decoders and emit under the `Canon` family-1 group.
//!   The container `$$self{FILE_TYPE} = "CRW"` is threaded into
//!   `Canon::ShotInfo` position 22's RawConv (`Canon.pm:2977`/`:2990` — keeps a
//!   raw-0 ExposureTime only for a CRW, ported in #183).
//!
//! ## Records ported (continued — the CRW completion)
//!
//! - The rest of the `%CanonRaw::Main` SCALAR table — `TargetImageType`
//!   (`0x100a`), `RecordID` (`0x1804`), `FileNumber` (`0x1817`, dash
//!   PrintConv), `MeasuredEV` (`0x1814`, `$val+5`), `SerialNumber` (`0x180b`,
//!   model-conditional PrintConv), `UserComment`/`CanonFileDescription`
//!   (`0x0805`, DIR_NAME-conditional), `ColorTemperature` (`0x10ae`),
//!   `ColorSpace` (`0x10b4`, PrintConv) — plus the structural SubDirectory
//!   records read-as-a-value then re-dispatched as ProcessBinaryData:
//!   `TimeStamp` (`0x180e` → DateTimeOriginal/TimeZoneCode/TimeZoneInfo),
//!   `ImageInfo` (`0x1810` → ImageWidth/Height/PixelAspectRatio/Rotation/
//!   Component+ColorBitDepth/ColorBW), `DecoderTable` (`0x1835` →
//!   DecoderTableNumber/CompressedDataOffset/Length), `RawJpgInfo` (`0x10b5`
//!   → RawJpgQuality/Size/Width/Height), `ExposureInfo` (`0x1818` →
//!   ExposureCompensation/ShutterSpeedValue/ApertureValue), `FlashInfo`
//!   (`0x1813` → FlashGuideNumber/FlashThreshold), `WhiteSample` (`0x1030` →
//!   WhiteSample{Width,Height,LeftBorder,TopBorder,Bits}/BlackLevels, gated on
//!   the `Canon::Validate` length check).
//! - `Canon::SensorInfo` (`0x1031`) + `Canon::ColorBalance` (`0x10a9`) — the
//!   NAMED tags (Sensor*/BlackMask*Border + WB_RGGBLevels{…}/BlackLevels),
//!   ported as walked Canon sub-tables ([`crate::exif::makernotes::vendors::
//!   canon::sensor_info`] / [`…::color_balance`]) so they emit for BOTH the
//!   CRW dispatch and the normal EXIF MakerNote path.
//! - The FINAL scalar tags — `ShutterReleaseMethod` (`0x1010`, PrintConv),
//!   `ShutterReleaseTiming` (`0x1011`, PrintConv), `ReleaseSetting` (`0x1016`,
//!   no conv), `SelfTimerTime` (`0x1806`, `$val/1000` ValueConv + `"$val s"`
//!   PrintConv), `TargetDistanceSetting` (`0x1807`, `Format => 'float'` +
//!   `"$val mm"` PrintConv) — plus the NAMED no-conv records `NullRecord`
//!   (`0x0000`, int8u[]), `CanonColorInfo1` (`0x0032`, int8u[]) and
//!   `CanonColorInfo2` (`0x102c`, int16u[]) emitted as the whole-value
//!   `%crwTagFormat{tagType}` array, and `FreeBytes` (`0x0001`, `Format =>
//!   'undef', Binary => 1`) as the `(Binary data N bytes …)` placeholder.
//!
//! ### Coverage status — EVERY `%CanonRaw::Main` entry is now handled
//!
//! The only entries NOT emitted by default are `CanonFlashInfo` (`0x1028`,
//! `Unknown => 1`, suppressed unless `-u`) and `CustomFunctions` (`0x1033`,
//! the `CanonCustom` deferral #87 — read-then-ignored, faithful to bundled
//! when no consumer extracts it). Both are faithful to bundled's default
//! output. A CRW carrying any other `%CanonRaw::Main` record produces
//! byte-identical output to bundled 13.59.
//!
//! ## What is DEFERRED (port-wide)
//!
//! - The camera **Composite** subsystem (ScaleFactor35efl / Lens / Aperture /
//!   DOF / ImageSize / Megapixels / …), **XMP** (#37), and **CanonCustom**
//!   (`0x1033`, #87) are PORT-WIDE deferrals (no format emits them yet).
//! - The raw `Canon::ColorData` arrays (`0x10a8`/`0x10ad`/… and the
//!   `Canon::Main` `0x4001`) stay deferred (#84) — only the NAMED ColorBalance
//!   tags are surfaced.
//! - The `CanonRaw::ExposureInfo` (`0x1818`), `FlashInfo` (`0x1813`) and
//!   `WhiteSample` (`0x1030`) binary sub-tables ARE ported (faithful 1:1 —
//!   the named positions under the `CanonRaw` family-1 group, the
//!   `ShutterSpeedValue`/`ApertureValue` ValueConv+PrintConv, and the
//!   `WhiteSample` `Canon::Validate` length gate).
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
    // The root heap's `$$self{DIR_NAME}` is the file-level dir (not
    // `ImageDescription`), so `0x0805` would resolve as `UserComment` there
    // (it never appears at the root in practice).
    process_canon_raw(
      data,
      hlen,
      filesize,
      0,
      order,
      &mut meta,
      &mut guard,
      CrwDir::Other,
    );
  }
  Some(meta)
}

/// `$$self{DIR_NAME}` for the directory currently being walked — the ONLY
/// bundled CanonRaw record whose decode depends on it is `0x0805` (the
/// `CanonFileDescription`/`UserComment` conditional list, `CanonRaw.pm:60-69`,
/// `Condition => '$self->{DIR_NAME} eq "ImageDescription"'`). We track just
/// that distinction; every other directory is `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CrwDir {
  /// Inside the `0x2804 ImageDescription` subdirectory (`CanonRaw.pm:364-368`).
  ImageDescription,
  /// Any other directory (root / `ImageProps` / `ExifInformation` / …).
  Other,
}

/// `ProcessCanonRaw` (`CanonRaw.pm:625-812`): walk one CIFF heap block,
/// recursing into sub-directories. `block_start` / `block_end` bound the
/// block within `data` (absolute offsets); `nesting` is the recursion depth;
/// `guard` is the `ProcessedCanonRaw{dirOffset}` double-reference set
/// (`CanonRaw.pm:633-639`); `dir_name` is `$$self{DIR_NAME}` (the only
/// DIR_NAME-sensitive record is `0x0805`, `CanonRaw.pm:60-69`).
// The arg list mirrors the bundled `ProcessCanonRaw` dirInfo fields (block
// bounds + nesting + byte order + the Meta sink + the double-ref guard +
// DIR_NAME); bundling them into a struct would obscure the 1:1 transcription.
#[allow(clippy::too_many_arguments)]
fn process_canon_raw(
  data: &[u8],
  block_start: usize,
  block_end: usize,
  nesting: u32,
  order: ByteOrder,
  meta: &mut CrwMeta<'_>,
  guard: &mut Vec<usize>,
  dir_name: CrwDir,
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
        // The child `$$self{DIR_NAME}` = the SubDirectory record's `Name`
        // (`ProcessCanonRaw` sets `DirName => $name`, `CanonRaw.pm:665`). The
        // only DIR_NAME-sensitive record is `0x0805`, gated on
        // `"ImageDescription"` (`0x2804`, `CanonRaw.pm:364`); every other
        // subdir name is irrelevant ⇒ `Other`.
        let child_dir = if tag_id == 0x2804 {
          CrwDir::ImageDescription
        } else {
          CrwDir::Other
        };
        process_canon_raw(
          data,
          ptr,
          ptr + size,
          nesting + 1,
          order,
          meta,
          guard,
          child_dir,
        );
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
      // `$valueDataPos = $ptr` (`CanonRaw.pm:701`). The bundled read gate
      // (`CanonRaw.pm:707-709`):
      //
      // ```perl
      // if ($size <= 512 or ($verbose > 2 and $size <= 65536)
      //     or ($tagInfo and ($$tagInfo{SubDirectory}
      //     or grep(/^$$tagInfo{Name}$/i, $et->GetRequestedTags()) )))
      // ```
      //
      // reads the value bytes when `size <= 512` OR the tag has a
      // `SubDirectory` (the "or if this is a SubDirectory" clause) OR the tag
      // was specifically requested. We have no `-verbose`/requested-tags
      // surface (those only widen WHICH large binary LEAVES get read for `-b`),
      // so the faithful gate is `size <= 512 || is_subdirectory_tag(tag_id)`.
      //
      // A SubDirectory record whose block exceeds 512 bytes (the concrete real
      // case is `WhiteSample` 0x1030 — its named fields are "followed by the
      // encrypted white sample values", `CanonRaw.pm:598`, so the block can run
      // long while the named tags all live in the first ~118 bytes) MUST be
      // read in full: the sub-table extracts its named tags from the front.
      // Dropping it to the `(Binary data N bytes)` placeholder loses those tags.
      //
      // A NON-SubDirectory record larger than 512 (the binary LEAVES `RawData`
      // 0x2005 / `JpgFromRaw` 0x2007 / `ThumbnailImage` 0x2008,
      // `CanonRaw.pm:716-728`) keeps the placeholder. (`size` is the on-disk
      // length here, NOT clamped to 8 — that clamp is the value-in-dir branch
      // only, `CanonRaw.pm:695`.)
      if size <= 512 || is_subdirectory_tag(tag_id) {
        // ExifTool's read is file-bounded: `Read($value,$size) == $size` fails
        // when the block runs past EOF, hitting `Warn("Error reading … bytes")`
        // + `next` (`CanonRaw.pm:712-715`). We mirror with a bounded slice —
        // the SubDirectory read is NOT capped below the real data (faithfulness
        // = read the whole subdir value), only bounded by the bytes physically
        // present.
        let Some(v) = data.get(ptr..ptr + size) else {
          continue;
        };
        value = v.to_vec();
      } else {
        // Large binary LEAF (`CanonRaw.pm:716-728`): bundled emits the
        // `(Binary data N bytes, …)` placeholder. We carry only the byte count
        // so the [`crate::value::TagValue::Bytes`] placeholder reports the
        // right length without copying the (potentially multi-MB) payload. The
        // bytes themselves are never emitted (no `-b`), so their content is
        // irrelevant.
        emit_record(
          meta,
          tag_id,
          RecordValue::BinaryPlaceholder(size),
          order,
          dir_name,
        );
        continue;
      }
    }

    emit_record(meta, tag_id, RecordValue::Bytes(value), order, dir_name);
  }
}

/// `$$tagInfo{SubDirectory}` for a `%CanonRaw::Main` VALUE record — the read
/// gate's "or if this is a SubDirectory" clause (`CanonRaw.pm:707-709`,
/// commented "or if this is a SubDirectory", `:711-712`). A record whose tag
/// carries a `SubDirectory` is read REGARDLESS of size; its sub-table then
/// extracts the named tags from the front of the (possibly long) block.
///
/// This is the SINGLE source of truth for the gate: it enumerates EVERY
/// `%CanonRaw::Main` tag that reaches the value branch (i.e. NOT a `tagType`
/// 0x28/0x30 raw-HEAP subdir — those `0x2804`/`0x2807`/`0x300a`/… containers
/// take the recurse arm at `process_canon_raw` above, `CanonRaw.pm:659-682`,
/// and never hit this gate) AND carries a `SubDirectory`. Cross-checked against
/// `%Image::ExifTool::CanonRaw::Main` (`CanonRaw.pm:166-345`); see the bundled
/// `grep` in the commit. Each entry below is also dispatched by [`emit_record`]
/// (the `0x1029/0x102a/0x102d/0x1031/0x1038/0x1093/0x10a9` Canon sub-table map)
/// or [`emit_scalar`] (the `0x080a` MakeModel + the `0x1803/0x180e/0x1810/
/// 0x1813/0x1818/0x1835/0x10b5/0x1030` structural sub-tables); keep this list
/// and those dispatch arms in lock-step.
///
/// `0x1033 CustomFunctions` is a `SubDirectory` in bundled (so it IS read
/// regardless of size, `CanonRaw.pm:154-165`) but its sub-table (`CanonCustom`)
/// is a PORT-WIDE deferral (#87) — the port does not dispatch it, so whether
/// its block is read or placeholdered is OBSERVATIONALLY identical. We still
/// list it so the gate stays a faithful mirror of `$$tagInfo{SubDirectory}`
/// (reading-then-ignoring is exactly bundled's behavior when no consumer
/// extracts the block), and so a future #87 port needs no gate change.
#[inline]
const fn is_subdirectory_tag(tag_id: u16) -> bool {
  matches!(
    tag_id,
    // MakeModel (string sub-table → Make/Model).
    0x080a
      // Canon::* MakerNote sub-tables (the CRW_SUBDIR dispatch in emit_record).
      | 0x1029 | 0x102a | 0x102d | 0x1031 | 0x1038 | 0x1093 | 0x10a9
      // CanonCustom (deferred #87 — read-then-ignore, faithful to bundled).
      | 0x1033
      // Structural CanonRaw sub-tables (the emit_scalar arms).
      | 0x1803 | 0x180e | 0x1810 | 0x1813 | 0x1818 | 0x1835 | 0x10b5
      // WhiteSample (the >512 real case — named fields + encrypted tail).
      | 0x1030
  )
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
/// records (`0x1029`/`0x102a`/`0x102d`/`0x1031`/`0x1038`/`0x1093`/`0x10a9`) are
/// retained as raw blocks. `dir_name` is `$$self{DIR_NAME}` (only the `0x0805`
/// record reads it). Records not ported are ignored (faithful to bundled's
/// table-miss `next unless defined $tagInfo`, `CanonRaw.pm:760`).
fn emit_record(
  meta: &mut CrwMeta<'_>,
  tag_id: u16,
  value: RecordValue,
  order: ByteOrder,
  dir_name: CrwDir,
) {
  // The Canon sub-table records keep their raw bytes for the per-`ConvMode`
  // re-decode in `Taggable` (these are never value-in-dir / large in real
  // CRW, but we handle both representations).
  let sub_kind = match tag_id {
    0x1029 => Some(CrwSubTable::FocalLength),
    0x102a => Some(CrwSubTable::ShotInfo),
    0x102d => Some(CrwSubTable::CameraSettings),
    0x1031 => Some(CrwSubTable::SensorInfo),
    0x1038 => Some(CrwSubTable::AfInfo),
    0x1093 => Some(CrwSubTable::FileInfo),
    0x10a9 => Some(CrwSubTable::ColorBalance),
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
    // `0x0001 FreeBytes` (`CanonRaw.pm:56-60`, `Format => 'undef', Binary =>
    // 1`) / `0x2005 RawData` (`:319`) / `0x2007 JpgFromRaw` (`:323`) /
    // `0x2008 ThumbnailImage` (`:329`) — all `Binary => 1`; render as the
    // `(Binary data N bytes, …)` placeholder. `FreeBytes` is a binary LEAF at
    // ANY size: `Binary => 1` renders the value as the placeholder even when
    // the bytes were read inline (`size <= 512`), exactly like the image
    // records (oracle-confirmed: a 10-byte FreeBytes ⇒ `(Binary data 10
    // bytes)`).
    0x0001 | 0x2005 | 0x2007 | 0x2008 => {
      let n = match value {
        RecordValue::Bytes(b) => b.len(),
        RecordValue::BinaryPlaceholder(n) => n,
      };
      // Store the byte count via a zero-filled placeholder block: the
      // serializer renders `(Binary data N bytes …)` from the `Vec` length.
      let name = match tag_id {
        0x0001 => CrwBinary::FreeBytes,
        0x2005 => CrwBinary::RawData,
        0x2007 => CrwBinary::JpgFromRaw,
        _ => CrwBinary::ThumbnailImage,
      };
      meta.push_binary(name, n);
    }
    // ---- the rest are scalar / structural records ------------------------
    other => emit_scalar(meta, other, value, order, dir_name),
  }
}

/// One binary `CanonRaw::Main` record (rendered as the `(Binary data N bytes,
/// …)` placeholder).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CrwBinary {
  /// `0x0001 FreeBytes` (`CanonRaw.pm:56-60`, `Format => 'undef', Binary => 1`).
  FreeBytes,
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
      Self::FreeBytes => "FreeBytes",
      Self::RawData => "RawData",
      Self::JpgFromRaw => "JpgFromRaw",
      Self::ThumbnailImage => "ThumbnailImage",
    }
  }
}

/// Decode a SCALAR / structural `CanonRaw::Main` record into the typed
/// [`CrwMeta`]. Strings are NUL-trimmed (`ExifTool.pm` string ValueConv);
/// integers/floats read in the header byte order. The SubDirectory records
/// that are read as a VALUE then re-dispatched as a ProcessBinaryData
/// sub-table on `\$value` (`TimeStamp`/`ImageInfo`/`DecoderTable`/
/// `RawJpgInfo`, `CanonRaw.pm:762-796`) are unpacked here from their block.
/// `dir_name` is `$$self{DIR_NAME}` (only `0x0805` reads it).
fn emit_scalar(
  meta: &mut CrwMeta<'_>,
  tag_id: u16,
  value: RecordValue,
  order: ByteOrder,
  dir_name: CrwDir,
) {
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

    // ---- `0x0805` conditional list (`CanonRaw.pm:60-72`) -----------------
    // First arm `CanonFileDescription` (`string[32]`) when `$$self{DIR_NAME}
    // eq "ImageDescription"`; else second arm `UserComment` (`string[256]`).
    // (The third arm is unreachable — both arms here are string records.)
    0x0805 => match dir_name {
      CrwDir::ImageDescription => meta.set_canon_file_description(trim_string(&bytes)),
      CrwDir::Other => meta.set_user_comment(trim_string(&bytes)),
    },

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

    // ---- `0x100a TargetImageType` (`CanonRaw.pm:86-93`) — int16u, PrintConv
    0x100a if bytes.len() >= 2 => meta.set_target_image_type(read_u16(&bytes, 0, order)),

    // ---- `0x1010 ShutterReleaseMethod` (`CanonRaw.pm:94-101`) — int16u, PrintConv
    0x1010 if bytes.len() >= 2 => meta.set_shutter_release_method(read_u16(&bytes, 0, order)),

    // ---- `0x1011 ShutterReleaseTiming` (`CanonRaw.pm:102-109`) — int16u, PrintConv
    0x1011 if bytes.len() >= 2 => meta.set_shutter_release_timing(read_u16(&bytes, 0, order)),

    // ---- `0x1016 ReleaseSetting` (`CanonRaw.pm:110`) — int16u, no conv ----
    0x1016 if bytes.len() >= 2 => meta.set_release_setting(read_u16(&bytes, 0, order)),

    // ---- `0x1806 SelfTimerTime` (`CanonRaw.pm:234-241`) — int32u ----------
    // `ValueConv => '$val / 1000'` (FLOAT division — a `10500` raw yields
    // `10.5`); store the POST-ValueConv float. The `"$val s"` PrintConv runs
    // at emission.
    0x1806 if bytes.len() >= 4 => {
      meta.set_self_timer_time(f64::from(read_u32(&bytes, 0, order)) / 1000.0);
    }

    // ---- `0x1807 TargetDistanceSetting` (`CanonRaw.pm:242-247`) — float ---
    // `Format => 'float'` (overrides the int32u tagType); the `"$val mm"`
    // PrintConv runs at emission.
    0x1807 if bytes.len() >= 4 => {
      meta.set_target_distance_setting(f64::from(read_f32(&bytes, 0, order)));
    }

    // ---- `0x101c BaseISO` (`CanonRaw.pm:198`) — int16u -------------------
    0x101c if bytes.len() >= 2 => meta.set_base_iso(read_u16(&bytes, 0, order)),

    // ---- `0x10ae ColorTemperature` (`CanonRaw.pm:215-218`) — int16u ------
    0x10ae if bytes.len() >= 2 => meta.set_color_temperature(read_u16(&bytes, 0, order)),

    // ---- `0x10b4 ColorSpace` (`CanonRaw.pm:219-227`) — int16u, PrintConv -
    0x10b4 if bytes.len() >= 2 => meta.set_color_space(read_u16(&bytes, 0, order)),

    // ---- `0x1804 RecordID` (`CanonRaw.pm:233`) — int32u ------------------
    0x1804 if bytes.len() >= 4 => meta.set_record_id(read_u32(&bytes, 0, order)),

    // ---- `0x1817 FileNumber` (`CanonRaw.pm:303-309`) — int32u, dash conv -
    0x1817 if bytes.len() >= 4 => meta.set_file_number(read_u32(&bytes, 0, order)),

    // ---- `0x1814 MeasuredEV` (`CanonRaw.pm:292-302`) — float, +5 ValueConv
    0x1814 if bytes.len() >= 4 => {
      // `ValueConv => '$val + 5'`: store the POST-ValueConv float.
      meta.set_measured_ev(f64::from(read_f32(&bytes, 0, order)) + 5.0);
    }

    // ---- `0x180b SerialNumber` (`CanonRaw.pm:248-270`) — int32u ----------
    // Conditional list: `EOS D30` → `%x-%.5d`; any `EOS` → `%.10d`; else
    // `UnknownNumber` (`Unknown => 1`). We store the raw int32u for an EOS
    // body only (the Model is captured by `0x080a`, which precedes this in
    // the CIFF walk — CameraSpecification follows CanonRawMakeModel,
    // `CanonRaw.pm` real-CRW ordering); for a non-EOS PowerShot body the
    // record is `UnknownNumber` and SUPPRESSED by default, so we skip it.
    0x180b if bytes.len() >= 4 && model_is_eos(meta.model()) => {
      meta.set_serial_number(read_u32(&bytes, 0, order));
    }

    // ---- `0x1803 ImageFormat` → `CanonRaw::ImageFormat` ------------------
    // (`CanonRaw.pm:228-232`, sub-table `:456-478`): FORMAT int32u,
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

    // ---- `0x180e TimeStamp` → `CanonRaw::TimeStamp` ----------------------
    // (`CanonRaw.pm:271-277`, sub-table `:427-454`): FORMAT int32u,
    // FIRST_ENTRY 0. pos0 `DateTimeOriginal` (Unix→ConvertUnixTime), pos1
    // `TimeZoneCode` (int32s, `$val/3600`), pos2 `TimeZoneInfo` (int32u).
    0x180e => {
      let mut ts = crate::metadata::CrwTimeStamp::default();
      if bytes.len() >= 4 {
        let unix = i64::from(read_u32(&bytes, 0, order));
        ts.set_date_time_original(SmolStr::from(crate::datetime::convert_unix_time(unix)));
      }
      if bytes.len() >= 8 {
        // `int32s`, `ValueConv => '$val / 3600'`. Perl's `/` is FLOATING-POINT
        // division, so a `+5:30` zone (`19800`) MUST yield `5.5`, NOT a
        // truncated `5` (oracle-confirmed). Divide as f64.
        let tz = f64::from(read_i32(&bytes, 4, order)) / 3600.0;
        ts.set_time_zone_code(tz);
      }
      if bytes.len() >= 12 {
        ts.set_time_zone_info(read_u32(&bytes, 8, order));
      }
      if !ts.is_empty() {
        meta.set_time_stamp(ts);
      }
    }

    // ---- `0x1810 ImageInfo` → `CanonRaw::ImageInfo` ----------------------
    // (`CanonRaw.pm:278-284`, sub-table `:547-570`): FORMAT int32u,
    // FIRST_ENTRY 0. pos0 ImageWidth, 1 ImageHeight, 2 PixelAspectRatio
    // (float), 3 Rotation (int32s), 4 ComponentBitDepth, 5 ColorBitDepth,
    // 6 ColorBW.
    0x1810 => {
      let mut ii = crate::metadata::CrwImageInfo::default();
      let mut ii_set = false;
      // Decode each position (PixelAspectRatio is a float, Rotation an int32s,
      // the rest int32u). FIRST_ENTRY 0 ⇒ position N at byte offset 4*N.
      if bytes.len() >= 4 {
        ii.set_image_width(read_u32(&bytes, 0, order));
        ii_set = true;
      }
      if bytes.len() >= 8 {
        ii.set_image_height(read_u32(&bytes, 4, order));
        ii_set = true;
      }
      if bytes.len() >= 12 {
        ii.set_pixel_aspect_ratio(f64::from(read_f32(&bytes, 8, order)));
        ii_set = true;
      }
      if bytes.len() >= 16 {
        ii.set_rotation(read_i32(&bytes, 12, order));
        ii_set = true;
      }
      if bytes.len() >= 20 {
        ii.set_component_bit_depth(read_u32(&bytes, 16, order));
        ii_set = true;
      }
      if bytes.len() >= 24 {
        ii.set_color_bit_depth(read_u32(&bytes, 20, order));
        ii_set = true;
      }
      if bytes.len() >= 28 {
        ii.set_color_bw(read_u32(&bytes, 24, order));
        ii_set = true;
      }
      if ii_set {
        meta.set_image_info(ii);
      }
    }

    // ---- `0x1835 DecoderTable` → `CanonRaw::DecoderTable` ----------------
    // (`CanonRaw.pm:327-331`, sub-table `:572-583`): FORMAT int32u,
    // FIRST_ENTRY 0. pos0 DecoderTableNumber, pos2 CompressedDataOffset,
    // pos3 CompressedDataLength (pos1 unnamed).
    0x1835 => {
      let mut dt = crate::metadata::CrwDecoderTable::default();
      let mut dt_set = false;
      if bytes.len() >= 4 {
        dt.set_decoder_table_number(read_u32(&bytes, 0, order));
        dt_set = true;
      }
      // pos1 (byte offset 4) is unnamed — skipped.
      if bytes.len() >= 12 {
        dt.set_compressed_data_offset(read_u32(&bytes, 8, order));
        dt_set = true;
      }
      if bytes.len() >= 16 {
        dt.set_compressed_data_length(read_u32(&bytes, 12, order));
        dt_set = true;
      }
      if dt_set {
        meta.set_decoder_table(dt);
      }
    }

    // ---- `0x10b5 RawJpgInfo` → `CanonRaw::RawJpgInfo` --------------------
    // (`CanonRaw.pm:208-214`, sub-table `:480-508`): FORMAT int16u,
    // FIRST_ENTRY 1. pos1 RawJpgQuality (PrintConv), pos2 RawJpgSize
    // (PrintConv), pos3 RawJpgWidth, pos4 RawJpgHeight. pos0 is commented out.
    0x10b5 => {
      let mut rj = crate::metadata::CrwRawJpgInfo::default();
      let mut rj_set = false;
      // FIRST_ENTRY 1 ⇒ position N is at byte offset 2*N. pos1 ⇒ offset 2.
      if bytes.len() >= 4 {
        rj.set_raw_jpg_quality(read_u16(&bytes, 2, order));
        rj_set = true;
      }
      if bytes.len() >= 6 {
        rj.set_raw_jpg_size(read_u16(&bytes, 4, order));
        rj_set = true;
      }
      if bytes.len() >= 8 {
        rj.set_raw_jpg_width(read_u16(&bytes, 6, order));
        rj_set = true;
      }
      if bytes.len() >= 10 {
        rj.set_raw_jpg_height(read_u16(&bytes, 8, order));
        rj_set = true;
      }
      if rj_set {
        meta.set_raw_jpg_info(rj);
      }
    }

    // ---- `0x1818 ExposureInfo` → `CanonRaw::ExposureInfo` ----------------
    // (`CanonRaw.pm:310-315`, sub-table `:522-545`): FORMAT float, FIRST_ENTRY
    // 0. pos0 `ExposureCompensation`, pos1 `ShutterSpeedValue` (raw apex;
    // ValueConv/PrintConv at emission), pos2 `ApertureValue` (raw apex). Byte
    // offset of position N = `4 * N` (`ExifTool.pm:9933`).
    0x1818 => {
      let mut ei = crate::metadata::CrwExposureInfo::default();
      let mut ei_set = false;
      if bytes.len() >= 4 {
        ei.set_exposure_compensation(f64::from(read_f32(&bytes, 0, order)));
        ei_set = true;
      }
      if bytes.len() >= 8 {
        // Store the RAW apex value; the `abs($val)<100 ? 1/(2**$val) : 0`
        // ValueConv + `PrintExposureTime` PrintConv run at emission.
        ei.set_shutter_speed_value(f64::from(read_f32(&bytes, 4, order)));
        ei_set = true;
      }
      if bytes.len() >= 12 {
        // Store the RAW apex value; the `2 ** ($val / 2)` ValueConv +
        // `sprintf("%.1f")` PrintConv run at emission.
        ei.set_aperture_value(f64::from(read_f32(&bytes, 8, order)));
        ei_set = true;
      }
      if ei_set {
        meta.set_exposure_info(ei);
      }
    }

    // ---- `0x1813 FlashInfo` → `CanonRaw::FlashInfo` ----------------------
    // (`CanonRaw.pm:285-291`, sub-table `:510-520`): FORMAT float, FIRST_ENTRY
    // 0. pos0 `FlashGuideNumber`, pos1 `FlashThreshold` (no conv either).
    0x1813 => {
      let mut fi = crate::metadata::CrwFlashInfo::default();
      let mut fi_set = false;
      if bytes.len() >= 4 {
        fi.set_flash_guide_number(f64::from(read_f32(&bytes, 0, order)));
        fi_set = true;
      }
      if bytes.len() >= 8 {
        fi.set_flash_threshold(f64::from(read_f32(&bytes, 4, order)));
        fi_set = true;
      }
      if fi_set {
        meta.set_flash_info(fi);
      }
    }

    // ---- `0x1030 WhiteSample` → `CanonRaw::WhiteSample` ------------------
    // (`CanonRaw.pm:141-148`, sub-table `:586-601`): FORMAT int16u, FIRST_ENTRY
    // 1. pos1 `WhiteSampleWidth`, 2 `WhiteSampleHeight`, 3
    // `WhiteSampleLeftBorder`, 4 `WhiteSampleTopBorder`, 5 `WhiteSampleBits`,
    // 0x37(=55) `BlackLevels` (int16u[4]). Byte offset of position N = `2 * N`
    // (`ExifTool.pm:9933` — FIRST_ENTRY does NOT shift the offset). The
    // SubDirectory carries a `Validate` gate (`Canon::Validate`,
    // `Canon.pm:10322-10333`): the first int16u (offset 0) must equal the block
    // byte length, else bundled warns `Invalid WhiteSample data` and emits
    // NOTHING. We replicate the SUPPRESSION (the Warn has no Meta channel).
    0x1030 => {
      // `Validate($dirData, 0, $size)`: `Get16u(data, 0) == size`.
      let valid = bytes
        .len()
        .try_into()
        .ok()
        .is_some_and(|size: u16| read_u16(&bytes, 0, order) == size);
      if valid {
        let mut ws = crate::metadata::CrwWhiteSample::default();
        let mut ws_set = false;
        // FORMAT int16u; byte offset = 2 * position (position 1..=5).
        if let Some(v) = read_u16_at(&bytes, 2, order) {
          ws.set_white_sample_width(v); // position 1
          ws_set = true;
        }
        if let Some(v) = read_u16_at(&bytes, 4, order) {
          ws.set_white_sample_height(v); // position 2
          ws_set = true;
        }
        if let Some(v) = read_u16_at(&bytes, 6, order) {
          ws.set_white_sample_left_border(v); // position 3
          ws_set = true;
        }
        if let Some(v) = read_u16_at(&bytes, 8, order) {
          ws.set_white_sample_top_border(v); // position 4
          ws_set = true;
        }
        if let Some(v) = read_u16_at(&bytes, 10, order) {
          ws.set_white_sample_bits(v); // position 5
          ws_set = true;
        }
        // `BlackLevels` at position 0x37 (=55) ⇒ byte offset 110, `int16u[4]`.
        // ExifTool's `ReadValue` returns ONLY the words present, so a block
        // that runs out mid-quad yields fewer than 4 (the `CanonRaw_records`
        // oracle shows `"129 130 131"` — 3 words). The whole entry is dropped
        // only when no word is present (offset 110 past EOF).
        const BLACK_LEVELS_OFFSET: usize = 2 * 0x37; // = 110
        let mut black = Vec::new();
        for i in 0..4usize {
          match read_u16_at(&bytes, BLACK_LEVELS_OFFSET + 2 * i, order) {
            Some(v) => black.push(v),
            None => break,
          }
        }
        if !black.is_empty() {
          ws.set_black_levels(black);
          ws_set = true;
        }
        if ws_set {
          meta.set_white_sample(ws);
        }
      }
    }

    // ---- `0x1834 CanonModelID` (`CanonRaw.pm:316-326`) — int32u, PrintHex,
    //      `%canonModelID` ---------------------------------------------------
    0x1834 if bytes.len() >= 4 => meta.set_model_id(read_u32(&bytes, 0, order)),

    // ---- `0x183b SerialNumberFormat` (`CanonRaw.pm:332-341`) — int32u, PrintHex
    0x183b if bytes.len() >= 4 => meta.set_serial_number_format(read_u32(&bytes, 0, order)),

    // ---- NAMED no-conv array records (`CanonRaw.pm:55-61`/`:128-135`) -----
    // `NullRecord` (0x0000) / `CanonColorInfo1` (0x0032) / `CanonColorInfo2`
    // (0x102c) are NAMED but carry no `SubDirectory`, no `PrintConv` and no
    // `Format` override, so ExifTool reads the whole record as a
    // `%crwTagFormat{tagType}` array and emits it via `FoundTag` with no conv
    // (`CanonRaw.pm:798-800`). The element count is `int(size / formatSize)`
    // (`CanonRaw.pm:735-740`). The format is fixed by the tag_id's tagType
    // bits: 0x0000/0x0032 ⇒ tagType 0x00 ⇒ int8u; 0x102c ⇒ tagType 0x10 ⇒
    // int16u (`CanonRaw.pm:36-44`). (Verified vs `perl exiftool -G1`.)
    0x0000 | 0x0032 | 0x102c => {
      let name = match tag_id {
        0x0000 => "NullRecord",
        0x0032 => "CanonColorInfo1",
        _ => "CanonColorInfo2",
      };
      // int16u for 0x102c (tagType 0x10), int8u for 0x0000/0x0032 (tagType 0x00).
      let values = if tag_id == 0x102c {
        decode_u16_array(&bytes, order)
      } else {
        decode_u8_array(&bytes)
      };
      if !values.is_empty() {
        meta.push_raw_array(crate::metadata::CrwRawArray::new(
          SmolStr::new_static(name),
          values,
        ));
      }
    }

    // Every other `CanonRaw::Main` record is not surfaced here: the only
    // remaining named scalar leaf is `CanonFlashInfo` (0x1028, `Unknown => 1`),
    // SUPPRESSED by default (`next unless …` — it only appears with `-u`,
    // oracle-confirmed). `CustomFunctions` (0x1033) dispatches to `CanonCustom`
    // (a PORT-WIDE deferral, #87 — read-then-ignored, faithful to bundled when
    // no consumer extracts it). The structural binary sub-tables that DO carry
    // named tags — `ExposureInfo` (0x1818), `FlashInfo` (0x1813), `WhiteSample`
    // (0x1030) — are decoded in the arms above. The CIFF walker still RECURSED
    // through every subdirectory.
    _ => {}
  }
}

/// Decode a CIFF `int8u[N]` record value (`%crwTagFormat{0x00}`,
/// `CanonRaw.pm:37`): one element per byte. `ReadValue` yields the count
/// `int(size / 1)` = `size` elements.
fn decode_u8_array(bytes: &[u8]) -> std::vec::Vec<u64> {
  bytes.iter().map(|&b| u64::from(b)).collect()
}

/// Decode a CIFF `int16u[N]` record value (`%crwTagFormat{0x10}`,
/// `CanonRaw.pm:39`) in `order`: the count is `int(size / 2)`, so a trailing
/// odd byte is dropped (`CanonRaw.pm:735-740`, oracle-confirmed).
fn decode_u16_array(bytes: &[u8], order: ByteOrder) -> std::vec::Vec<u64> {
  bytes
    .chunks_exact(2)
    .map(|c| {
      let arr = [c[0], c[1]];
      let v = match order {
        ByteOrder::Little => u16::from_le_bytes(arr),
        ByteOrder::Big => u16::from_be_bytes(arr),
      };
      u64::from(v)
    })
    .collect()
}

/// `$$self{Model} =~ /EOS/` — the SerialNumber conditional gate
/// (`CanonRaw.pm:259`). The `EOS D30\b` first arm differs only in the
/// PrintConv (`%x-%.5d` vs `%.10d`), applied at emission; here we only need
/// "is this an EOS body" to decide whether the record is `SerialNumber`
/// (vs the PowerShot `UnknownNumber`, suppressed by default).
fn model_is_eos(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.contains("EOS"))
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

/// Read an `int16u` at `off` within `b` in `order`, returning `None` when the
/// word is past the end of `b`. Used for the `WhiteSample` named positions,
/// where ExifTool's `ReadValue` yields undef past the block (so a position
/// beyond the data is simply not emitted) — distinct from [`read_u16`], whose
/// 0-on-miss fallback would falsely emit a `0`.
#[inline]
fn read_u16_at(b: &[u8], off: usize, order: ByteOrder) -> Option<u16> {
  let s = b.get(off..off + 2)?;
  let arr = [s[0], s[1]];
  Some(match order {
    ByteOrder::Little => u16::from_le_bytes(arr),
    ByteOrder::Big => u16::from_be_bytes(arr),
  })
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

/// Read an `int32s` at `off` within `b` in `order` (for `Rotation` /
/// `TimeZoneCode`).
#[inline]
fn read_i32(b: &[u8], off: usize, order: ByteOrder) -> i32 {
  read_u32(b, off, order) as i32
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

/// Render an `int16u[N]` array as ExifTool's default space-joined string
/// (e.g. `"129 130 131"`) — the `WhiteSample` `BlackLevels` rendering.
fn join_u16(words: &[u16]) -> String {
  use std::fmt::Write;
  let mut s = String::new();
  for (i, w) in words.iter().enumerate() {
    if i != 0 {
      s.push(' ');
    }
    let _ = write!(s, "{w}");
  }
  s
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

/// `TargetImageType` PrintConv (`CanonRaw.pm:89-92`): `0 => 'Real-world
/// Subject', 1 => 'Written Document'`; miss ⇒ the generic `Unknown (N)`
/// (no `PrintHex`, so decimal).
fn print_target_image_type(v: u16) -> TagValue {
  let label = match v {
    0 => Some("Real-world Subject"),
    1 => Some("Written Document"),
    _ => None,
  };
  match label {
    Some(s) => TagValue::Str(SmolStr::new_static(s)),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
  }
}

/// `ShutterReleaseMethod` PrintConv (`CanonRaw.pm:97-100`): `0 => 'Single
/// Shot', 2 => 'Continuous Shooting'`; miss ⇒ `Unknown (N)` (no `PrintHex`, so
/// decimal — oracle-confirmed `"Unknown (1)"`).
fn print_shutter_release_method(v: u16) -> TagValue {
  let label = match v {
    0 => Some("Single Shot"),
    2 => Some("Continuous Shooting"),
    _ => None,
  };
  match label {
    Some(s) => TagValue::Str(SmolStr::new_static(s)),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
  }
}

/// `ShutterReleaseTiming` PrintConv (`CanonRaw.pm:105-108`): `0 => 'Priority on
/// shutter', 1 => 'Priority on focus'`; miss ⇒ `Unknown (N)` (decimal).
fn print_shutter_release_timing(v: u16) -> TagValue {
  let label = match v {
    0 => Some("Priority on shutter"),
    1 => Some("Priority on focus"),
    _ => None,
  };
  match label {
    Some(s) => TagValue::Str(SmolStr::new_static(s)),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
  }
}

/// Perl's default NV stringification (`%.15g`) for a PrintConv string
/// interpolation like `"$val s"` / `"$val mm"`. ExifTool interpolates the
/// post-ValueConv number into the PrintConv string via Perl's default scalar
/// stringification, which is `%.15g` (`$Config{nvgformat}` ⇒ `g`, `$DIG = 15`).
/// An integer-valued NV renders without a fraction (`10.0` ⇒ `"10"`); a
/// fraction renders with its `%g` digits (`10.5` ⇒ `"10.5"`). The crate's
/// shared [`crate::value::format_g`] is exactly this formatter.
fn fmt_perl_num(v: f64) -> String {
  if v.is_finite() {
    crate::value::format_g(v, 15)
  } else {
    // A non-finite SelfTimerTime/TargetDistanceSetting cannot arise from a CRW
    // (int32u/float reads are always finite); mirror Perl's casing defensively.
    crate::value::perl_nonfinite_str(v).map_or_else(|| v.to_string(), str::to_owned)
  }
}

/// Render a NAMED no-conv array record value (`NullRecord`/`CanonColorInfo1`/
/// `CanonColorInfo2`) the way ExifTool's `ReadValue` + default rendering does:
/// a single bare scalar when the count is 1, else the elements space-joined
/// (`"1 2 3 4"`). A single element ⇒ [`TagValue::U64`] (the bare number the
/// oracle emits); multiple ⇒ a [`TagValue::Str`] (non-numeric, compared
/// exactly). An empty value yields an empty string (never reached — the walker
/// drops empty arrays).
fn render_raw_array(values: &[u64]) -> TagValue {
  match values {
    [single] => TagValue::U64(*single),
    _ => {
      use std::fmt::Write;
      let mut s = String::new();
      for (i, v) in values.iter().enumerate() {
        if i != 0 {
          s.push(' ');
        }
        let _ = write!(s, "{v}");
      }
      TagValue::Str(SmolStr::from(s))
    }
  }
}

/// `ColorSpace` PrintConv (`CanonRaw.pm:222-226`): `1 => 'sRGB', 2 => 'Adobe
/// RGB', 0xffff => 'Uncalibrated'`; miss ⇒ `Unknown (N)` (decimal).
fn print_color_space(v: u16) -> TagValue {
  let label = match v {
    1 => Some("sRGB"),
    2 => Some("Adobe RGB"),
    0xffff => Some("Uncalibrated"),
    _ => None,
  };
  match label {
    Some(s) => TagValue::Str(SmolStr::new_static(s)),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
  }
}

/// `RawJpgQuality` PrintConv (`CanonRaw.pm:491-496`): `1 => 'Economy', 2 =>
/// 'Normal', 3 => 'Fine', 5 => 'Superfine'`; miss ⇒ `Unknown (N)`.
fn print_raw_jpg_quality(v: u16) -> TagValue {
  let label = match v {
    1 => Some("Economy"),
    2 => Some("Normal"),
    3 => Some("Fine"),
    5 => Some("Superfine"),
    _ => None,
  };
  match label {
    Some(s) => TagValue::Str(SmolStr::new_static(s)),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
  }
}

/// `RawJpgSize` PrintConv (`CanonRaw.pm:500-504`): `0 => 'Large', 1 =>
/// 'Medium', 2 => 'Small'`; miss ⇒ `Unknown (N)`.
fn print_raw_jpg_size(v: u16) -> TagValue {
  let label = match v {
    0 => Some("Large"),
    1 => Some("Medium"),
    2 => Some("Small"),
    _ => None,
  };
  match label {
    Some(s) => TagValue::Str(SmolStr::new_static(s)),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
  }
}

/// `FileNumber` PrintConv (`CanonRaw.pm:307`): `$_=$val;s/(\d+)(\d{4})/$1-$2/`.
/// Render `$val` as its decimal string, then insert a dash before the LAST
/// four digits (the greedy `\d+` keeps exactly 4 for `\d{4}`). When the
/// decimal has fewer than 5 digits the regex does not match and the bare
/// decimal string is returned (faithful to the no-substitution case).
fn print_file_number(v: u32) -> String {
  let s = std::format!("{v}");
  // `(\d+)(\d{4})` — match only when there are at least 5 digits (need ≥1 for
  // `\d+` plus 4 for `\d{4}`). The substitution splits 4 digits off the end.
  if s.len() >= 5 {
    let split = s.len() - 4;
    std::format!("{}-{}", &s[..split], &s[split..])
  } else {
    s
  }
}

/// `SerialNumber` PrintConv (`CanonRaw.pm:248-264`), model-conditional:
/// - `$$self{Model} =~ /EOS D30\b/` ⇒ `sprintf("%x-%.5d", $val>>16,
///   $val&0xffff)` (hex high word, dash, zero-padded-5 low word).
/// - any other `EOS` ⇒ `sprintf("%.10d", $val)` (zero-padded-10 decimal).
///
/// (A non-EOS body never reaches here — the record is `UnknownNumber`, never
/// stored as `SerialNumber`.)
fn print_serial_number(v: u32, model: Option<&str>) -> String {
  if model_is_eos_d30(model) {
    std::format!("{:x}-{:05}", v >> 16, v & 0xffff)
  } else {
    std::format!("{v:010}")
  }
}

/// `$$self{Model} =~ /EOS D30\b/` (`CanonRaw.pm:252`) — exact `EOS D30` word
/// boundary (so `EOS D30` / `Canon EOS D30` match; `EOS D300`/`EOS D3000` do
/// NOT). Selects the `SerialNumber` D30 PrintConv variant.
fn model_is_eos_d30(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  let nb = b"EOS D30";
  let bytes = m.as_bytes();
  let mut i = 0;
  while i + nb.len() <= bytes.len() {
    if &bytes[i..i + nb.len()] == nb {
      match bytes.get(i + nb.len()) {
        None => return true,
        Some(&c) => {
          if !(c.is_ascii_alphanumeric() || c == b'_') {
            return true;
          }
        }
      }
    }
    i += 1;
  }
  false
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
    // `FreeBytes`/`RawData`/`JpgFromRaw`/`ThumbnailImage` render as `(Binary
    // data N bytes, …)` via `TagValue::Bytes` (the serializer formats the byte
    // count). We synthesize a zero-filled `Vec` of the recorded length — the
    // bytes are never emitted (no `-b`), only their count.
    for (name, len) in self.binary_records() {
      push_raw(&mut tags, name, TagValue::Bytes(std::vec![0u8; *len]));
    }

    // ---- NAMED no-conv array records (`NullRecord`/`CanonColorInfo1`/
    // `CanonColorInfo2`) ---------------------------------------------------
    // ExifTool emits the whole record value as a `%crwTagFormat{tagType}`
    // array with NO conversion: a single bare scalar when the count is 1, else
    // the elements space-joined (`"1 2 3 4"`). No `PrintConv` ⇒ identical in
    // `-j`/`-n`.
    for rec in self.raw_arrays() {
      let value = render_raw_array(rec.values());
      push_raw(&mut tags, rec.name(), value);
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

    // ---- newly-ported scalar records -------------------------------------
    if let Some(v) = self.target_image_type() {
      // `int16u`, PrintConv (`CanonRaw.pm:87-92`).
      let value = if print_conv {
        print_target_image_type(v)
      } else {
        TagValue::U64(u64::from(v))
      };
      push_raw(&mut tags, "TargetImageType", value);
    }
    if let Some(v) = self.shutter_release_method() {
      // `int16u`, PrintConv (`CanonRaw.pm:97-100`).
      let value = if print_conv {
        print_shutter_release_method(v)
      } else {
        TagValue::U64(u64::from(v))
      };
      push_raw(&mut tags, "ShutterReleaseMethod", value);
    }
    if let Some(v) = self.shutter_release_timing() {
      // `int16u`, PrintConv (`CanonRaw.pm:105-108`).
      let value = if print_conv {
        print_shutter_release_timing(v)
      } else {
        TagValue::U64(u64::from(v))
      };
      push_raw(&mut tags, "ShutterReleaseTiming", value);
    }
    if let Some(v) = self.release_setting() {
      // `int16u`, no PrintConv (`CanonRaw.pm:110`) ⇒ bare int both modes.
      push_raw(&mut tags, "ReleaseSetting", TagValue::U64(u64::from(v)));
    }
    if let Some(v) = self.self_timer_time() {
      // `int32u`, ValueConv `$val / 1000` already applied; PrintConv `"$val s"`
      // (`CanonRaw.pm:237-240`).
      let value = if print_conv {
        TagValue::Str(SmolStr::from(std::format!("{} s", fmt_perl_num(v))))
      } else {
        TagValue::F64(v)
      };
      push_raw(&mut tags, "SelfTimerTime", value);
    }
    if let Some(v) = self.target_distance_setting() {
      // `float`, PrintConv `"$val mm"` (`CanonRaw.pm:245`).
      let value = if print_conv {
        TagValue::Str(SmolStr::from(std::format!("{} mm", fmt_perl_num(v))))
      } else {
        TagValue::F64(v)
      };
      push_raw(&mut tags, "TargetDistanceSetting", value);
    }
    if let Some(v) = self.record_id() {
      // `int32u`, no PrintConv (`CanonRaw.pm:233`).
      push_raw(&mut tags, "RecordID", TagValue::U64(u64::from(v)));
    }
    if let Some(v) = self.file_number() {
      // `int32u`, dash PrintConv (`CanonRaw.pm:307`).
      let value = if print_conv {
        TagValue::Str(SmolStr::from(print_file_number(v)))
      } else {
        TagValue::U64(u64::from(v))
      };
      push_raw(&mut tags, "FileNumber", value);
    }
    if let Some(v) = self.serial_number() {
      // `int32u`, model-conditional PrintConv (`CanonRaw.pm:248-264`).
      let value = if print_conv {
        TagValue::Str(SmolStr::from(print_serial_number(v, self.model())))
      } else {
        TagValue::U64(u64::from(v))
      };
      push_raw(&mut tags, "SerialNumber", value);
    }
    if let Some(v) = self.user_comment() {
      // `string[256]`, no PrintConv (`CanonRaw.pm:65-69`).
      push_raw(&mut tags, "UserComment", TagValue::Str(v.into()));
    }
    if let Some(v) = self.canon_file_description() {
      // `string[32]`, no PrintConv (`CanonRaw.pm:60-64`).
      push_raw(&mut tags, "CanonFileDescription", TagValue::Str(v.into()));
    }
    if let Some(v) = self.measured_ev() {
      // `float`, ValueConv `$val + 5` already applied; no PrintConv
      // (`CanonRaw.pm:292-302`) ⇒ same float in `-j`/`-n`.
      push_raw(&mut tags, "MeasuredEV", TagValue::F64(v));
    }
    if let Some(v) = self.color_temperature() {
      // `int16u`, no PrintConv (`CanonRaw.pm:215-218`).
      push_raw(&mut tags, "ColorTemperature", TagValue::U64(u64::from(v)));
    }
    if let Some(v) = self.color_space() {
      // `int16u`, PrintConv (`CanonRaw.pm:222-226`).
      let value = if print_conv {
        print_color_space(v)
      } else {
        TagValue::U64(u64::from(v))
      };
      push_raw(&mut tags, "ColorSpace", value);
    }

    // ---- structural sub-table records ------------------------------------
    // `TimeStamp` (`CanonRaw.pm:427-454`): DateTimeOriginal / TimeZoneCode /
    // TimeZoneInfo.
    if let Some(ts) = self.time_stamp() {
      if let Some(dt) = ts.date_time_original() {
        // `ConvertUnixTime` ValueConv + `ConvertDateTime` PrintConv (a no-op
        // without a custom date format) ⇒ same string in `-j`/`-n`.
        push_raw(&mut tags, "DateTimeOriginal", TagValue::Str(dt.into()));
      }
      if let Some(tz) = ts.time_zone_code() {
        // `int32s`, FLOAT ValueConv `$val/3600` (e.g. `19800` ⇒ `5.5`); no
        // PrintConv ⇒ same value in both modes. `TagValue::F64` renders an
        // integral zone (`0` ⇒ `0.0`) value-equivalently to the golden `0`.
        push_raw(&mut tags, "TimeZoneCode", TagValue::F64(tz));
      }
      if let Some(tzi) = ts.time_zone_info() {
        push_raw(&mut tags, "TimeZoneInfo", TagValue::U64(u64::from(tzi)));
      }
    }
    // `ImageInfo` (`CanonRaw.pm:547-570`).
    if let Some(ii) = self.image_info() {
      if let Some(v) = ii.image_width() {
        push_raw(&mut tags, "ImageWidth", TagValue::U64(u64::from(v)));
      }
      if let Some(v) = ii.image_height() {
        push_raw(&mut tags, "ImageHeight", TagValue::U64(u64::from(v)));
      }
      if let Some(v) = ii.pixel_aspect_ratio() {
        // `float`, no PrintConv ⇒ same in both modes.
        push_raw(&mut tags, "PixelAspectRatio", TagValue::F64(v));
      }
      if let Some(v) = ii.rotation() {
        // `int32s`, no PrintConv.
        push_raw(&mut tags, "Rotation", TagValue::I64(i64::from(v)));
      }
      if let Some(v) = ii.component_bit_depth() {
        push_raw(&mut tags, "ComponentBitDepth", TagValue::U64(u64::from(v)));
      }
      if let Some(v) = ii.color_bit_depth() {
        push_raw(&mut tags, "ColorBitDepth", TagValue::U64(u64::from(v)));
      }
      if let Some(v) = ii.color_bw() {
        push_raw(&mut tags, "ColorBW", TagValue::U64(u64::from(v)));
      }
    }
    // `DecoderTable` (`CanonRaw.pm:572-583`).
    if let Some(dt) = self.decoder_table() {
      if let Some(v) = dt.decoder_table_number() {
        push_raw(&mut tags, "DecoderTableNumber", TagValue::U64(u64::from(v)));
      }
      if let Some(v) = dt.compressed_data_offset() {
        push_raw(
          &mut tags,
          "CompressedDataOffset",
          TagValue::U64(u64::from(v)),
        );
      }
      if let Some(v) = dt.compressed_data_length() {
        push_raw(
          &mut tags,
          "CompressedDataLength",
          TagValue::U64(u64::from(v)),
        );
      }
    }
    // `RawJpgInfo` (`CanonRaw.pm:480-508`).
    if let Some(rj) = self.raw_jpg_info() {
      if let Some(v) = rj.raw_jpg_quality() {
        let value = if print_conv {
          print_raw_jpg_quality(v)
        } else {
          TagValue::U64(u64::from(v))
        };
        push_raw(&mut tags, "RawJpgQuality", value);
      }
      if let Some(v) = rj.raw_jpg_size() {
        let value = if print_conv {
          print_raw_jpg_size(v)
        } else {
          TagValue::U64(u64::from(v))
        };
        push_raw(&mut tags, "RawJpgSize", value);
      }
      if let Some(v) = rj.raw_jpg_width() {
        push_raw(&mut tags, "RawJpgWidth", TagValue::U64(u64::from(v)));
      }
      if let Some(v) = rj.raw_jpg_height() {
        push_raw(&mut tags, "RawJpgHeight", TagValue::U64(u64::from(v)));
      }
    }
    // `ExposureInfo` (`CanonRaw.pm:522-545`).
    if let Some(ei) = self.exposure_info() {
      if let Some(v) = ei.exposure_compensation() {
        // `float`, no conv ⇒ same value in `-j`/`-n`.
        push_raw(&mut tags, "ExposureCompensation", TagValue::F64(v));
      }
      if let Some(raw) = ei.shutter_speed_value() {
        // ValueConv `abs($val)<100 ? 1/(2**$val) : 0` (`CanonRaw.pm:533`).
        let secs = if raw.abs() < 100.0 {
          1.0 / 2.0_f64.powf(raw)
        } else {
          0.0
        };
        let value = if print_conv {
          // PrintConv `Exif::PrintExposureTime` (`CanonRaw.pm:535`).
          TagValue::Str(SmolStr::from(crate::exif::tables::print_exposure_time(
            secs,
          )))
        } else {
          TagValue::F64(secs)
        };
        push_raw(&mut tags, "ShutterSpeedValue", value);
      }
      if let Some(raw) = ei.aperture_value() {
        // ValueConv `2 ** ($val / 2)` (`CanonRaw.pm:540`).
        let fnum = 2.0_f64.powf(raw / 2.0);
        let value = if print_conv {
          // PrintConv `sprintf("%.1f", $val)` (`CanonRaw.pm:542`).
          TagValue::Str(SmolStr::from(std::format!("{fnum:.1}")))
        } else {
          TagValue::F64(fnum)
        };
        push_raw(&mut tags, "ApertureValue", value);
      }
    }
    // `FlashInfo` (`CanonRaw.pm:510-520`) — neither position has a conv.
    if let Some(fi) = self.flash_info() {
      if let Some(v) = fi.flash_guide_number() {
        push_raw(&mut tags, "FlashGuideNumber", TagValue::F64(v));
      }
      if let Some(v) = fi.flash_threshold() {
        push_raw(&mut tags, "FlashThreshold", TagValue::F64(v));
      }
    }
    // `WhiteSample` (`CanonRaw.pm:586-601`) — int16u positions + the
    // `BlackLevels` int16u[4] quad (space-joined). No PrintConv on any.
    if let Some(ws) = self.white_sample() {
      if let Some(v) = ws.white_sample_width() {
        push_raw(&mut tags, "WhiteSampleWidth", TagValue::U64(u64::from(v)));
      }
      if let Some(v) = ws.white_sample_height() {
        push_raw(&mut tags, "WhiteSampleHeight", TagValue::U64(u64::from(v)));
      }
      if let Some(v) = ws.white_sample_left_border() {
        push_raw(
          &mut tags,
          "WhiteSampleLeftBorder",
          TagValue::U64(u64::from(v)),
        );
      }
      if let Some(v) = ws.white_sample_top_border() {
        push_raw(
          &mut tags,
          "WhiteSampleTopBorder",
          TagValue::U64(u64::from(v)),
        );
      }
      if let Some(v) = ws.white_sample_bits() {
        push_raw(&mut tags, "WhiteSampleBits", TagValue::U64(u64::from(v)));
      }
      let black = ws.black_levels();
      if !black.is_empty() {
        // `int16u[4]` rendered as ExifTool's default space-joined string
        // (e.g. `"129 130 131"` for a 3-word remnant). No PrintConv.
        push_raw(
          &mut tags,
          "BlackLevels",
          TagValue::Str(SmolStr::from(join_u16(black))),
        );
      }
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
    CrwSubTable::SensorInfo => canon::sensor_info::parse(bytes, order, print_conv),
    CrwSubTable::ColorBalance => canon::color_balance::parse(bytes, order, print_conv, model),
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
  /// `CanonFirmwareVersion` (the software slot), and the body
  /// `SerialNumber` (the `0x180b` record, EOS-only) mapped to the `serial`
  /// slot. We use the bare decimal serial string (`SerialNumber.to_string()`)
  /// — the SAME normalized form the Canon-JPEG `MakerNote` projection uses
  /// (`project.rs` `canon.serial_number()`), NOT the zero-padded `%.10d`
  /// PrintConv. The lens identity lives in the `CameraSettings` projection
  /// (not modeled here), and CRW has no GPS, so those domains stay `None`.
  fn project(&self) -> crate::metadata::MediaMetadata {
    use crate::metadata::{CameraInfo, MediaMetadata};
    use std::string::ToString;
    let mut media = MediaMetadata::new();
    let mut cam = CameraInfo::new();
    cam
      .update_make(self.make().map(ToString::to_string))
      .update_model(self.model().map(ToString::to_string))
      .update_serial(self.serial_number().map(|n| n.to_string()))
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

  /// Collect the `CanonRaw:` family-1 `(name, value)` pairs for a mode.
  fn canonraw_tags(m: &CrwMeta<'_>, mode: crate::emit::ConvMode) -> Vec<(String, TagValue)> {
    use crate::emit::Taggable as _;
    m.tags(mode)
      .filter(|t| t.tag().group_ref().family1() == "CanonRaw")
      .map(|t| (t.tag().name().to_string(), t.tag().value_ref().clone()))
      .collect()
  }

  fn find_tag(pairs: &[(String, TagValue)], name: &str) -> Option<TagValue> {
    pairs
      .iter()
      .find(|(k, _)| k == name)
      .map(|(_, v)| v.clone())
  }

  /// `ExposureInfo` (0x1818): pos0 `ExposureCompensation` (no conv), pos1
  /// `ShutterSpeedValue` (ValueConv `1/(2**$val)` + `PrintExposureTime`), pos2
  /// `ApertureValue` (ValueConv `2**($val/2)` + `sprintf("%.1f")`). Verified vs
  /// `perl exiftool -G1` on a crafted heap (NOT a conformance fixture — these
  /// positions synthesize `Composite:Aperture`/`ShutterSpeed`).
  #[test]
  fn exposure_info_value_and_print_conv() {
    use crate::emit::ConvMode;
    let mut root = HeapBuilder::new();
    // floats: ExposureComp 0.5, ShutterSpeedValue apex 8.0, ApertureValue apex 5.0.
    let mut blk = Vec::new();
    blk.extend_from_slice(&0.5f32.to_le_bytes());
    blk.extend_from_slice(&8.0f32.to_le_bytes());
    blk.extend_from_slice(&5.0f32.to_le_bytes());
    root.add_value(0x1818, &blk);
    let data = build_file(&root);
    let m = parse_inner(&data).expect("valid CRW");

    // -j (PrintConv).
    let j = canonraw_tags(&m, ConvMode::PrintConv);
    assert_eq!(
      find_tag(&j, "ExposureCompensation"),
      Some(TagValue::F64(0.5))
    );
    // 1/(2**8) = 1/256 -> PrintExposureTime -> "1/256".
    assert_eq!(
      find_tag(&j, "ShutterSpeedValue"),
      Some(TagValue::Str("1/256".into()))
    );
    // 2**(5/2) = 5.656854 -> sprintf("%.1f") -> "5.7".
    assert_eq!(
      find_tag(&j, "ApertureValue"),
      Some(TagValue::Str("5.7".into()))
    );

    // -n (ValueConv): post-ValueConv floats.
    let n = canonraw_tags(&m, ConvMode::ValueConv);
    assert_eq!(
      find_tag(&n, "ExposureCompensation"),
      Some(TagValue::F64(0.5))
    );
    assert_eq!(
      find_tag(&n, "ShutterSpeedValue"),
      Some(TagValue::F64(0.003_906_25))
    );
    match find_tag(&n, "ApertureValue") {
      Some(TagValue::F64(v)) => assert!((v - 5.656_854_249_492_38).abs() < 1e-9),
      other => panic!("ApertureValue -n: {other:?}"),
    }
  }

  /// `ShutterSpeedValue` ValueConv clamps `abs($val) >= 100` to 0
  /// (`CanonRaw.pm:533`).
  #[test]
  fn shutter_speed_value_out_of_range_is_zero() {
    use crate::emit::ConvMode;
    let mut root = HeapBuilder::new();
    let mut blk = Vec::new();
    blk.extend_from_slice(&0.0f32.to_le_bytes()); // ExposureCompensation
    blk.extend_from_slice(&150.0f32.to_le_bytes()); // ShutterSpeedValue apex (>=100)
    root.add_value(0x1818, &blk);
    let data = build_file(&root);
    let m = parse_inner(&data).expect("valid CRW");
    let n = canonraw_tags(&m, ConvMode::ValueConv);
    assert_eq!(find_tag(&n, "ShutterSpeedValue"), Some(TagValue::F64(0.0)));
  }

  /// `FlashInfo` (0x1813): both positions are bare floats (no conv) ⇒ identical
  /// in `-j`/`-n`.
  #[test]
  fn flash_info_floats() {
    use crate::emit::ConvMode;
    let mut root = HeapBuilder::new();
    let mut blk = Vec::new();
    blk.extend_from_slice(&12.0f32.to_le_bytes());
    blk.extend_from_slice(&0.5f32.to_le_bytes());
    root.add_value(0x1813, &blk);
    let data = build_file(&root);
    let m = parse_inner(&data).expect("valid CRW");
    for mode in [ConvMode::PrintConv, ConvMode::ValueConv] {
      let t = canonraw_tags(&m, mode);
      assert_eq!(find_tag(&t, "FlashGuideNumber"), Some(TagValue::F64(12.0)));
      assert_eq!(find_tag(&t, "FlashThreshold"), Some(TagValue::F64(0.5)));
    }
  }

  /// `WhiteSample` (0x1030): named int16u positions read at byte offset
  /// `2*position` (FIRST_ENTRY does NOT shift, `ExifTool.pm:9933`), the
  /// pos-0x37 `BlackLevels` int16u[4] space-joined. A valid block has its first
  /// int16u == block byte length (`Canon::Validate`).
  #[test]
  fn white_sample_positions_and_black_levels() {
    use crate::emit::ConvMode;
    const S: usize = 116;
    let mut ws = std::vec![0u8; S];
    let set =
      |buf: &mut [u8], off: usize, v: u16| buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    set(&mut ws, 0, S as u16); // Validate: first u16 == size
    set(&mut ws, 2, 80); // WhiteSampleWidth (pos1)
    set(&mut ws, 4, 5); // WhiteSampleHeight (pos2)
    set(&mut ws, 6, 7); // WhiteSampleLeftBorder (pos3)
    set(&mut ws, 8, 12); // WhiteSampleTopBorder (pos4)
    set(&mut ws, 10, 0); // WhiteSampleBits (pos5)
    set(&mut ws, 110, 128); // BlackLevels[0] (pos0x37, offset 110)
    set(&mut ws, 112, 129);
    set(&mut ws, 114, 130); // [3] would be at 116 — past EOF ⇒ 3 words only.
    let mut root = HeapBuilder::new();
    root.add_value(0x1030, &ws);
    let data = build_file(&root);
    let m = parse_inner(&data).expect("valid CRW");
    let t = canonraw_tags(&m, ConvMode::PrintConv);
    assert_eq!(find_tag(&t, "WhiteSampleWidth"), Some(TagValue::U64(80)));
    assert_eq!(find_tag(&t, "WhiteSampleHeight"), Some(TagValue::U64(5)));
    assert_eq!(
      find_tag(&t, "WhiteSampleLeftBorder"),
      Some(TagValue::U64(7))
    );
    assert_eq!(
      find_tag(&t, "WhiteSampleTopBorder"),
      Some(TagValue::U64(12))
    );
    assert_eq!(find_tag(&t, "WhiteSampleBits"), Some(TagValue::U64(0)));
    // 3-word remnant (offset 116 is past EOF) ⇒ "128 129 130".
    assert_eq!(
      find_tag(&t, "BlackLevels"),
      Some(TagValue::Str("128 129 130".into()))
    );
  }

  /// The SubDirectory read-gate fix (`CanonRaw.pm:707-709`): a record whose tag
  /// has a `SubDirectory` is read REGARDLESS of size — so a `WhiteSample`
  /// (0x1030) block LARGER than the 512-byte threshold keeps its named tags
  /// (they live in the first ~118 bytes; the rest is the "encrypted white
  /// sample values" tail, `CanonRaw.pm:598`). Before the fix the >512 block was
  /// dropped to a `(Binary data N bytes)` placeholder and ALL named tags were
  /// lost. This is the focused unit guard for the gap.
  #[test]
  fn white_sample_over_512_keeps_named_tags() {
    use crate::emit::ConvMode;
    // A 600-byte block (> the 512-byte read threshold): offset-0 length word =
    // 600 (Canon::Validate), named fields up front, the rest an arbitrary
    // non-zero "encrypted" tail.
    const S: usize = 600;
    let mut ws = std::vec![0u8; S];
    let set =
      |buf: &mut [u8], off: usize, v: u16| buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    set(&mut ws, 0, S as u16); // Validate: first u16 == block byte size
    set(&mut ws, 2, 4096); // WhiteSampleWidth (pos1)
    set(&mut ws, 4, 3072); // WhiteSampleHeight (pos2)
    set(&mut ws, 6, 11); // WhiteSampleLeftBorder (pos3)
    set(&mut ws, 8, 19); // WhiteSampleTopBorder (pos4)
    set(&mut ws, 10, 14); // WhiteSampleBits (pos5)
    set(&mut ws, 110, 128); // BlackLevels[0] (pos 0x37, offset 110)
    set(&mut ws, 112, 129);
    set(&mut ws, 114, 130);
    set(&mut ws, 116, 131); // all 4 words present ⇒ "128 129 130 131"
    for (i, b) in ws.iter_mut().enumerate().skip(118) {
      *b = (i % 251) as u8; // arbitrary "encrypted" tail
    }
    let mut root = HeapBuilder::new();
    root.add_value(0x1030, &ws);
    let data = build_file(&root);
    let m = parse_inner(&data).expect("valid CRW");

    // The >512 SubDirectory block was READ (not placeholdered) ⇒ the typed
    // WhiteSample is populated and every named tag is emitted.
    assert!(
      m.white_sample().is_some(),
      "the >512-byte WhiteSample block must be read, not dropped to a placeholder"
    );
    let t = canonraw_tags(&m, ConvMode::PrintConv);
    assert_eq!(find_tag(&t, "WhiteSampleWidth"), Some(TagValue::U64(4096)));
    assert_eq!(find_tag(&t, "WhiteSampleHeight"), Some(TagValue::U64(3072)));
    assert_eq!(
      find_tag(&t, "WhiteSampleLeftBorder"),
      Some(TagValue::U64(11))
    );
    assert_eq!(
      find_tag(&t, "WhiteSampleTopBorder"),
      Some(TagValue::U64(19))
    );
    assert_eq!(find_tag(&t, "WhiteSampleBits"), Some(TagValue::U64(14)));
    assert_eq!(
      find_tag(&t, "BlackLevels"),
      Some(TagValue::Str("128 129 130 131".into()))
    );
    // And the block must NOT have produced a `RawData`/binary placeholder.
    assert!(m.binary_records().is_empty());
  }

  /// A LARGE NON-SubDirectory binary LEAF (`RawData` 0x2005) is still rendered
  /// as the `(Binary data N bytes)` placeholder — the read-gate fix must NOT
  /// widen the read to plain binary leaves (`CanonRaw.pm:716-728`). Confirms the
  /// `is_subdirectory_tag` predicate excludes 0x2005/0x2007/thumbnail.
  #[test]
  fn large_binary_leaf_still_placeholdered() {
    // A 4096-byte RawData block (> 512). It is NOT a SubDirectory, so it must
    // keep the placeholder (only the byte count is retained).
    let blk = std::vec![0xabu8; 4096];
    let mut root = HeapBuilder::new();
    root.add_value(0x2005, &blk); // RawData (binary leaf)
    let data = build_file(&root);
    let m = parse_inner(&data).expect("valid CRW");
    // No bytes copied — only the (name, len) placeholder record.
    assert_eq!(m.binary_records().len(), 1);
    assert_eq!(m.binary_records()[0].0.as_str(), "RawData");
    assert_eq!(m.binary_records()[0].1, 4096);
    // The predicate itself: leaves are NOT SubDirectory; the dispatched sub-
    // tables ARE.
    assert!(!is_subdirectory_tag(0x2005));
    assert!(!is_subdirectory_tag(0x2007));
    assert!(!is_subdirectory_tag(0x2008));
    assert!(is_subdirectory_tag(0x1030)); // WhiteSample
    assert!(is_subdirectory_tag(0x102d)); // CameraSettings
    assert!(is_subdirectory_tag(0x080a)); // MakeModel
  }

  /// `WhiteSample` `Canon::Validate` gate (`Canon.pm:10322-10333`): a block
  /// whose first int16u != the block byte length is INVALID — bundled warns
  /// `Invalid WhiteSample data` and emits NOTHING. The port has no warning
  /// channel, but must replicate the SUPPRESSION.
  #[test]
  fn white_sample_invalid_length_suppressed() {
    use crate::emit::ConvMode;
    const S: usize = 116;
    let mut ws = std::vec![0u8; S];
    let set =
      |buf: &mut [u8], off: usize, v: u16| buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    set(&mut ws, 0, 100); // first u16 (100) != size (116) ⇒ INVALID
    set(&mut ws, 2, 80);
    let mut root = HeapBuilder::new();
    root.add_value(0x1030, &ws);
    let data = build_file(&root);
    let m = parse_inner(&data).expect("valid CRW");
    assert!(m.white_sample().is_none());
    let t = canonraw_tags(&m, ConvMode::PrintConv);
    assert!(find_tag(&t, "WhiteSampleWidth").is_none());
    assert!(find_tag(&t, "BlackLevels").is_none());
  }

  /// `TimeStamp` `TimeZoneCode` (0x180e pos1) is `$val/3600` FLOAT division: a
  /// `+5:30` zone (19800) must yield `5.5`, NOT a truncated `5`.
  #[test]
  fn timestamp_fractional_timezone_code() {
    use crate::emit::ConvMode;
    let mut root = HeapBuilder::new();
    let mut blk = Vec::new();
    blk.extend_from_slice(&1_068_485_966u32.to_le_bytes()); // DateTimeOriginal
    blk.extend_from_slice(&19_800i32.to_le_bytes()); // TimeZoneCode raw (=5.5h)
    blk.extend_from_slice(&0x8000_0000u32.to_le_bytes()); // TimeZoneInfo
    root.add_value(0x180e, &blk);
    let data = build_file(&root);
    let m = parse_inner(&data).expect("valid CRW");
    assert_eq!(m.time_stamp().and_then(|ts| ts.time_zone_code()), Some(5.5));
    for mode in [ConvMode::PrintConv, ConvMode::ValueConv] {
      let t = canonraw_tags(&m, mode);
      assert_eq!(find_tag(&t, "TimeZoneCode"), Some(TagValue::F64(5.5)));
      assert_eq!(
        find_tag(&t, "DateTimeOriginal"),
        Some(TagValue::Str("2003:11:10 17:39:26".into()))
      );
    }
  }

  /// The five remaining `CanonRaw::Main` scalar tags (`CanonRaw.pm:94-247`):
  /// `ShutterReleaseMethod` (0x1010, PrintConv), `ShutterReleaseTiming` (0x1011,
  /// PrintConv), `ReleaseSetting` (0x1016, no conv), `SelfTimerTime` (0x1806,
  /// `$val/1000` ValueConv + `"$val s"` PrintConv) and `TargetDistanceSetting`
  /// (0x1807, `Format => 'float'` + `"$val mm"` PrintConv). Values verified vs
  /// `perl exiftool 13.59 -G1 -j`/`-n` on a crafted heap.
  #[test]
  fn remaining_scalars_value_and_print_conv() {
    use crate::emit::ConvMode;
    let mut root = HeapBuilder::new();
    root.add_value(0x1010, &0u16.to_le_bytes()); // ShutterReleaseMethod = Single Shot
    root.add_value(0x1011, &1u16.to_le_bytes()); // ShutterReleaseTiming = Priority on focus
    root.add_value(0x1016, &3u16.to_le_bytes()); // ReleaseSetting = 3
    root.add_value(0x1806, &10_000u32.to_le_bytes()); // SelfTimerTime 10000/1000 = 10 -> "10 s"
    root.add_value(0x1807, &1234.0f32.to_le_bytes()); // TargetDistanceSetting -> "1234 mm"
    let data = build_file(&root);
    let m = parse_inner(&data).expect("valid CRW");

    // Typed-layer values (post-ValueConv where applicable).
    assert_eq!(m.shutter_release_method(), Some(0));
    assert_eq!(m.shutter_release_timing(), Some(1));
    assert_eq!(m.release_setting(), Some(3));
    assert_eq!(m.self_timer_time(), Some(10.0));
    assert_eq!(m.target_distance_setting(), Some(1234.0));

    // -j (PrintConv).
    let j = canonraw_tags(&m, ConvMode::PrintConv);
    assert_eq!(
      find_tag(&j, "ShutterReleaseMethod"),
      Some(TagValue::Str("Single Shot".into()))
    );
    assert_eq!(
      find_tag(&j, "ShutterReleaseTiming"),
      Some(TagValue::Str("Priority on focus".into()))
    );
    assert_eq!(find_tag(&j, "ReleaseSetting"), Some(TagValue::U64(3)));
    assert_eq!(
      find_tag(&j, "SelfTimerTime"),
      Some(TagValue::Str("10 s".into()))
    );
    assert_eq!(
      find_tag(&j, "TargetDistanceSetting"),
      Some(TagValue::Str("1234 mm".into()))
    );

    // -n (ValueConv): the bare post-ValueConv numbers.
    let n = canonraw_tags(&m, ConvMode::ValueConv);
    assert_eq!(find_tag(&n, "ShutterReleaseMethod"), Some(TagValue::U64(0)));
    assert_eq!(find_tag(&n, "ShutterReleaseTiming"), Some(TagValue::U64(1)));
    assert_eq!(find_tag(&n, "ReleaseSetting"), Some(TagValue::U64(3)));
    assert_eq!(find_tag(&n, "SelfTimerTime"), Some(TagValue::F64(10.0)));
    assert_eq!(
      find_tag(&n, "TargetDistanceSetting"),
      Some(TagValue::F64(1234.0))
    );
  }

  /// The `ShutterReleaseMethod`/`ShutterReleaseTiming` PrintConv MISS renders
  /// as `"Unknown (N)"` (no `PrintHex`, decimal) — the ExifTool default-PrintConv
  /// fallback (oracle-confirmed `"Unknown (1)"`), and `SelfTimerTime`/
  /// `TargetDistanceSetting` interpolate a FRACTIONAL value (`10500/1000 = 10.5`
  /// ⇒ `"10.5 s"`; `2.5` ⇒ `"2.5 mm"`).
  #[test]
  fn remaining_scalars_miss_and_fractional() {
    use crate::emit::ConvMode;
    let mut root = HeapBuilder::new();
    root.add_value(0x1010, &1u16.to_le_bytes()); // miss
    root.add_value(0x1011, &5u16.to_le_bytes()); // miss
    root.add_value(0x1806, &10_500u32.to_le_bytes()); // 10.5 s
    root.add_value(0x1807, &2.5f32.to_le_bytes()); // 2.5 mm
    let data = build_file(&root);
    let m = parse_inner(&data).expect("valid CRW");
    let j = canonraw_tags(&m, ConvMode::PrintConv);
    assert_eq!(
      find_tag(&j, "ShutterReleaseMethod"),
      Some(TagValue::Str("Unknown (1)".into()))
    );
    assert_eq!(
      find_tag(&j, "ShutterReleaseTiming"),
      Some(TagValue::Str("Unknown (5)".into()))
    );
    assert_eq!(
      find_tag(&j, "SelfTimerTime"),
      Some(TagValue::Str("10.5 s".into()))
    );
    assert_eq!(
      find_tag(&j, "TargetDistanceSetting"),
      Some(TagValue::Str("2.5 mm".into()))
    );
    let n = canonraw_tags(&m, ConvMode::ValueConv);
    assert_eq!(find_tag(&n, "SelfTimerTime"), Some(TagValue::F64(10.5)));
    assert_eq!(
      find_tag(&n, "TargetDistanceSetting"),
      Some(TagValue::F64(2.5))
    );
  }

  /// The NAMED no-conv array records (`CanonRaw.pm:55-61`/`:128-135`):
  /// `NullRecord` (0x0000, int8u[4]), `CanonColorInfo1` (0x0032, int8u[6]) and
  /// `CanonColorInfo2` (0x102c, int16u[8]) emit their whole value as a
  /// `%crwTagFormat{tagType}` array — space-joined for >1 element, a bare scalar
  /// for 1, identical in `-j`/`-n` (no PrintConv). Values verified vs `perl
  /// exiftool 13.59 -G1 -j`/`-n`.
  #[test]
  fn raw_array_records_space_joined() {
    use crate::emit::ConvMode;
    let mut root = HeapBuilder::new();
    root.add_value(0x0000, &[1u8, 2, 3, 4]); // NullRecord int8u[4]
    root.add_value(0x0032, &[10u8, 20, 30, 40, 50, 60]); // CanonColorInfo1 int8u[6]
    let mut ci2 = Vec::new();
    for w in [1u16, 2, 3, 4, 5, 6, 7, 8] {
      ci2.extend_from_slice(&w.to_le_bytes());
    }
    root.add_value(0x102c, &ci2); // CanonColorInfo2 int16u[8]
    let data = build_file(&root);
    let m = parse_inner(&data).expect("valid CRW");
    assert_eq!(m.raw_arrays().len(), 3);
    for mode in [ConvMode::PrintConv, ConvMode::ValueConv] {
      let t = canonraw_tags(&m, mode);
      assert_eq!(
        find_tag(&t, "NullRecord"),
        Some(TagValue::Str("1 2 3 4".into()))
      );
      assert_eq!(
        find_tag(&t, "CanonColorInfo1"),
        Some(TagValue::Str("10 20 30 40 50 60".into()))
      );
      assert_eq!(
        find_tag(&t, "CanonColorInfo2"),
        Some(TagValue::Str("1 2 3 4 5 6 7 8".into()))
      );
    }
  }

  /// A single-element array record renders as a BARE scalar (the oracle's bare
  /// number), and an `int16u` record drops a trailing odd byte
  /// (`int(size/2)` elements, `CanonRaw.pm:735-740`).
  #[test]
  fn raw_array_single_element_and_odd_remnant() {
    use crate::emit::ConvMode;
    let mut root = HeapBuilder::new();
    root.add_value(0x0032, &[99u8]); // CanonColorInfo1 single int8u -> bare 99
    // CanonColorInfo2: 5 bytes -> int(5/2)=2 elements, last byte dropped.
    root.add_value(0x102c, &[1u8, 0, 2, 0, 0x99]);
    let data = build_file(&root);
    let m = parse_inner(&data).expect("valid CRW");
    let t = canonraw_tags(&m, ConvMode::PrintConv);
    assert_eq!(find_tag(&t, "CanonColorInfo1"), Some(TagValue::U64(99)));
    assert_eq!(
      find_tag(&t, "CanonColorInfo2"),
      Some(TagValue::Str("1 2".into()))
    );
  }

  /// `FreeBytes` (0x0001, `Format => 'undef', Binary => 1`) renders as the
  /// `(Binary data N bytes, …)` placeholder at ANY size — exercising both the
  /// small (read-inline) and large (>512 placeholder-only) paths. Verified vs
  /// `perl exiftool 13.59 -G1` (`(Binary data 10 bytes …)`).
  #[test]
  fn free_bytes_binary_placeholder() {
    // Small (read inline, size <= 512): still a placeholder via `Binary => 1`.
    let mut root = HeapBuilder::new();
    root.add_value(0x0001, &(0u8..10).collect::<Vec<u8>>());
    let data = build_file(&root);
    let m = parse_inner(&data).expect("valid CRW");
    assert_eq!(m.binary_records().len(), 1);
    assert_eq!(m.binary_records()[0].0.as_str(), "FreeBytes");
    assert_eq!(m.binary_records()[0].1, 10);

    // Large (> 512): the placeholder-only path keeps the byte count, no copy.
    let mut root2 = HeapBuilder::new();
    root2.add_value(0x0001, &std::vec![0u8; 768]);
    let data2 = build_file(&root2);
    let m2 = parse_inner(&data2).expect("valid CRW");
    assert_eq!(m2.binary_records().len(), 1);
    assert_eq!(m2.binary_records()[0].0.as_str(), "FreeBytes");
    assert_eq!(m2.binary_records()[0].1, 768);
    // FreeBytes is a binary LEAF, NOT a SubDirectory.
    assert!(!is_subdirectory_tag(0x0001));
  }
}
