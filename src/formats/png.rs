// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "png")]
//! Faithful port of `Image::ExifTool::PNG` (`lib/Image/ExifTool/PNG.pm`)
//! reading half — the PNG chunk walker plus the chunk dispatchers we need
//! for camera-metadata extraction.
//!
//! ## What PNG is — and why it matters for indexing
//!
//! A PNG screenshot/photo from a modern phone (iPhone, Android) embeds
//! camera Exif via the `eXIf` chunk (`PNG.pm:309-317`, the PNG-1.5 chunk
//! added by the 2017 specification). For camera-metadata indexing this is
//! a high-value file type alongside JPEG: every camera shot routed through
//! a sharing/screenshot pipeline that landed in PNG carries its Make /
//! Model / DateTime / GPS in `eXIf`.
//!
//! ## Structure (`PNG.pm:1410-1685 ProcessPNG`)
//!
//! - **PNG signature** — `\x89PNG\r\n\x1a\n` (`PNG.pm:62`), 8 bytes. The
//!   MNG / JNG sibling signatures (`PNG.pm:63-64`) are deferred (not in
//!   camera-metadata scope).
//! - **Chunk loop** — `[length: u32 BE] [type: 4 ASCII] [data: length bytes]
//!   [crc: u32 BE]`. The walker validates CRC ONLY in verbose / validate
//!   modes (`PNG.pm:1612-1619`); by default a bad CRC is silently accepted
//!   to match bundled.
//! - **`IHDR`** (`PNG.pm:193-196`, sub-table `:387-423`) — image header:
//!   width, height, bit-depth, color-type, compression, filter, interlace.
//! - **`pHYs`** (`PNG.pm:216-222`, sub-table `:441-468`) — physical pixel
//!   dimensions: PixelsPerUnitX, PixelsPerUnitY, PixelUnits (0=unknown,
//!   1=meters).
//! - **`iCCP`** (`PNG.pm:171-181`) — ICC profile. The profile NAME (the
//!   keyword before the NUL separator) IS captured. The profile BODY bytes
//!   are now zlib-INFLATED (a corrupt stream warns `Error inflating iCCP`),
//!   but the inflated ICC profile is NOT further decoded into `ICC_Profile:*`
//!   tags — that needs a dedicated `ICC_Profile` sub-port (color management,
//!   out of camera-metadata scope), which is still deferred. So on inflate
//!   success the body is simply not emitted (no warning, no fabricated tags).
//! - **`tEXt` / `zTXt` / `iTXt`** (`PNG.pm:258-260`, `294-300`, `197-203`,
//!   `:1325-1351`) — textual metadata. `tEXt` is plain Latin-1; `zTXt` is
//!   zlib-compressed Latin-1; `iTXt` is UTF-8 with optional language tag.
//!   The compressed variants are now zlib-INFLATED via the pure-Rust
//!   `miniz_oxide` inflater (`PNG.pm:929-948 FoundPNG`, the
//!   `Compress::Zlib::inflate` arm) and stored exactly as the uncompressed
//!   chunk would be — `zTXt` → the `tEXt` keyword→record path (Latin-1),
//!   compressed `iTXt` → the uncompressed `iTXt` path (UTF-8). A corrupt
//!   stream warns `Error inflating <keyword>` (`PNG.pm:942`); a non-zero
//!   compression method warns `Unknown compression method <n> for <keyword>`
//!   (`PNG.pm:952`).
//! - **ImageMagick `Raw profile type X` chunks** (`PNG.pm:689-762`,
//!   `ProcessProfile` `:1155-1281`) — ImageMagick (and other tools) write
//!   EXIF / ICC / IPTC / XMP / Photoshop into PNG as `tEXt` / `zTXt` chunks
//!   whose keyword is `Raw profile type <X>` and whose body is
//!   `\n<type>\n  <len>\n<hex-encoded bytes>`. The body is hex-decoded
//!   (`PNG.pm:1169`) and dispatched to the embedded module. Each WELL-FORMED
//!   raw profile becomes a [`crate::metadata::PngExifEvent`] in the ordered
//!   [`crate::metadata::PngMeta::exif_events`] stream the `eXIf` chunk also
//!   feeds: the EXIF-bearing variants — `Raw profile type exif` (`:710`) and
//!   the EXIF-content arm of `Raw profile type APP1` (`:689`) — push
//!   [`crate::metadata::PngExifEvent::ExifProfile`]; the non-EXIF variants —
//!   `icc` / `icm` (ICC_Profile), `iptc` / `8bim` (Photoshop), `xmp`, the XMP
//!   arm of `APP1`, AND any unrecognized-content `exif`/`APP1` — push
//!   [`crate::metadata::PngExifEvent::ResetOnlyProfile`] (no ported sub-module,
//!   so no tags, but `ProcessProfile` STILL resets `$$et{PROCESSED}`,
//!   `PNG.pm:1193`, which the event models — oracle-verified). The wrong-size
//!   warning (`:1172`) and the `Unknown raw profile` warning (`:1267`) are
//!   still emitted. A MALFORMED raw profile (framing fails, `:1166`) pushes NO
//!   event (bundled `return 0`s before the reset). In NO case is the
//!   `PNG:"Raw profile type X"` keyword=hex text tag emitted (bundled emits the
//!   DECODED tags or nothing).
//! - **`eXIf` / `zXIf`** (`PNG.pm:309-317`, `:1358-1404`) — the Exif TIFF
//!   block. A normal `eXIf` (`II`/`MM` header) is appended to
//!   [`crate::metadata::PngMeta::exif_events`] as a
//!   [`crate::metadata::PngExifEvent::NativeTiff`] (no PROCESSED reset)
//!   and dispatched to [`crate::exif::parse_exif_block`] at serialize time.
//!   The `zXIf`
//!   compressed-EXIF variant (a `\0`-prefixed body, `PNG.pm:1378-1383`) is
//!   now zlib-INFLATED to the underlying TIFF block and captured the same
//!   way (`zXIf` was never widely adopted but bundled handles it).
//! - **`bKGD`** (`PNG.pm:128-131`) — background color.
//! - **`tIME`** (`PNG.pm:262-275`) — last-modification timestamp.
//!
//! Trailing-text-after-IDAT detection (`PNG.pm:1595-1605`) is preserved:
//! a `tEXt` / `zTXt` / `iTXt` / `eXIf` chunk that follows an `IDAT` raises
//! the `Text/EXIF chunk(s) found after PNG <chunk> (may be ignored by some
//! readers)` warning (read-mode `$msg = 'may be ignored by some readers'`,
//! `PNG.pm:1598`).
//!
//! ## What is DEFERRED
//!
//! - **`iCCP` ICC-profile *tag* decode** — the `iCCP` body IS now zlib-
//!   inflated, but turning the inflated ICC profile into `ICC_Profile:*`
//!   tags requires a dedicated `ICC_Profile` module port (color management,
//!   out of the camera-metadata scope) which exifast does NOT have. The
//!   profile NAME is emitted; the inflated body is dropped. This is a
//!   missing-sub-port deferral, NOT a zlib deferral.
//! - **APNG animation frames** (`fcTL` / `fdAT`, `PNG.pm:766-825`) — not
//!   in camera-metadata scope.
//! - **Private/vendor chunks** (the lowercase-second-char convention, the
//!   `iDOT` / `cpIp` / `meTa` / `caBX` private chunks `PNG.pm:331-373`) —
//!   defer all body parsing; chunk-walk continues past them. The SEAL /
//!   JUMBF / Photoshop / IPTC chunks similarly require their own large
//!   sub-ports (Phase-2+).
//! - **MNG / JNG** sibling containers (`PNG.pm:63-64`) — same chunk-walk
//!   but different signature + small chunk-table additions; not in
//!   camera-metadata scope.
//!
//! ## D8 conventions (mandatory)
//!
//! - No public struct fields anywhere; accessors only (see
//!   [`crate::metadata::PngMeta`]).
//! - SmolStr for stored keyword names / language tags / ICC profile
//!   names (bounded-short); `String` for the unbounded text-record values.
//! - Cite `PNG.pm:LLLL` for every non-trivial decode branch.

use crate::format_parser::{FormatParser, parser_sealed};
use crate::metadata::PngExifEvent;
use crate::metadata::png::IhdrFields;
use crate::metadata::{PngDynamicProfileTag, PngMeta, PngTextRecord};

use smol_str::SmolStr;
use std::{string::String, vec::Vec};

// ===========================================================================
// PNG signature + chunk-name constants
// ===========================================================================

/// The PNG signature — `PNG.pm:62`: `\x89PNG\r\n\x1a\n` (8 bytes).
///
/// The MNG (`\x8aMNG\r\n\x1a\n`) and JNG (`\x8bJNG\r\n\x1a\n`) sibling
/// signatures (`PNG.pm:63-64`) are deferred (not in camera-metadata scope).
pub const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

/// Threshold above which a chunk's declared `length` is treated as
/// corrupt (`PNG.pm:1490`: `if ($len > 0x7fffffff)`).
const MAX_CHUNK_LENGTH: usize = 0x7fff_ffff;

// ===========================================================================
// CRC-32 — bundled `CalculateCRC` (`WritePNG.pl:20-42`)
// ===========================================================================

/// PNG CRC-32 (polynomial `0xedb88320` — ITU-T V.42, identical to ZIP/
/// Ethernet). Faithful to bundled `CalculateCRC` (`WritePNG.pl:20-42`):
/// `$crc ^= 0xffffffff; … return $crc ^ 0xffffffff;` (the 1's complement
/// pre/post-condition).
///
/// Test-only: the read path no longer validates chunk CRCs (bundled does so
/// only in verbose/validate mode, `PNG.pm:123-124`), so this helper is used
/// solely by the test PNG-builder and the CRC unit tests.
#[cfg(test)]
fn crc32(bytes: &[u8]) -> u32 {
  let mut crc: u32 = 0xffff_ffff;
  for &b in bytes {
    let mut c = (crc ^ u32::from(b)) & 0xff;
    for _ in 0..8 {
      c = if (c & 1) != 0 {
        0xedb8_8320 ^ (c >> 1)
      } else {
        c >> 1
      };
    }
    crc = c ^ (crc >> 8);
  }
  crc ^ 0xffff_ffff
}

// ===========================================================================
// Chunk classification (bundled `%isDatChunk` / `%isTxtChunk`,
// `PNG.pm:92-93`)
// ===========================================================================

/// `%isDatChunk` (`PNG.pm:92`) — image-data chunks. For a PNG these are
/// just `IDAT`; the JNG arms (`JDAT` / `JDAA`) are deferred.
const fn is_data_chunk(chunk: &[u8; 4]) -> bool {
  matches!(chunk, b"IDAT" | b"JDAT" | b"JDAA")
}

/// `%isTxtChunk` (`PNG.pm:93`) — text-bearing chunks: `tEXt`/`zTXt`/`iTXt`
/// + `eXIf`. Used to detect "text/EXIF chunk found after IDAT".
const fn is_text_chunk(chunk: &[u8; 4]) -> bool {
  matches!(chunk, b"tEXt" | b"zTXt" | b"iTXt" | b"eXIf" | b"zxIf")
}

/// `%stdCase` (`PNG.pm:56`): `('zxif' => 'zxIf', exif => 'eXIf')` — the
/// case-correction map for chunk types whose canonical case changed since the
/// first PNG-EXIF implementations. Bundled's `ProcessPNG` (`PNG.pm:1640-1648`)
/// applies it when a chunk type is NOT already a recognized table key AND
/// `$stdCase{lc $chunk}` exists: it rewrites the chunk to the canonical case so
/// the EXIF extraction dispatch (`PNG.pm:1653`) sees `eXIf`/`zxIf`, and (in read
/// mode) warns `"$chunk chunk should be $stdChunk"`.
///
/// Returns the canonical chunk type for a case variant of `eXIf`/`zxIf` — i.e.
/// when `chunk.lc() ∈ {"exif","zxif"}` but `chunk` is NOT already the canonical
/// `eXIf`/`zxIf` (those are recognized table keys, so bundled's `not
/// $$tagTablePtr{$chunk}` guard excludes them). `None` for any other chunk type
/// (only `exif`/`zxif` are in `%stdCase`).
fn std_case(chunk: &[u8; 4]) -> Option<&'static [u8; 4]> {
  // Already canonical ⇒ recognized table key ⇒ stdCase does NOT fire.
  if matches!(chunk, b"eXIf" | b"zxIf") {
    return None;
  }
  let lc = chunk.map(|b| b.to_ascii_lowercase());
  match &lc {
    b"exif" => Some(b"eXIf"),
    b"zxif" => Some(b"zxIf"),
    _ => None,
  }
}

// ===========================================================================
// `ProcessPng` — the lib-first parser
// ===========================================================================

/// PNG parser — faithful `ProcessPNG` (`PNG.pm:1410-1685`).
#[derive(Debug, Clone, Copy)]
pub struct ProcessPng;

impl parser_sealed::Sealed for ProcessPng {}

impl FormatParser for ProcessPng {
  type Meta<'a> = PngMeta<'a>;
  type Context<'a> = &'a [u8];

  fn parse<'a>(&self, data: Self::Context<'a>) -> Option<Self::Meta<'a>> {
    parse_inner(data)
  }
}

/// Lib-first direct entry — parse a whole PNG file buffer into a typed
/// [`PngMeta`]. Returns `None` ONLY for a non-PNG (signature mismatch).
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today; reserved).
pub fn parse_borrowed(data: &[u8]) -> Option<PngMeta<'_>> {
  parse_inner(data)
}

/// The chunk walker proper. `PNG.pm:1424` `return 0 unless $raf->Read($sig,8)
/// == 8 and $pngLookup{$sig}` ⇒ signature mismatch / short read returns
/// `None`. Otherwise this ALWAYS returns `Some(meta)` (truncations and CRC
/// failures land as warnings in the [`PngMeta`]).
fn parse_inner(data: &[u8]) -> Option<PngMeta<'_>> {
  // `PNG.pm:1424` signature gate.
  if data.len() < PNG_SIGNATURE.len() || &data[..PNG_SIGNATURE.len()] != PNG_SIGNATURE {
    return None;
  }

  let mut meta = PngMeta::new();
  // Cursor sits just past the 8-byte signature (`PNG.pm:1424` consumed it).
  let mut pos = PNG_SIGNATURE.len();
  // `$wasHdr` / `$wasDat` / `$wasEnd` (`PNG.pm:1421`). `wasHdr` flags the
  // first chunk-name check (`PNG.pm:1504-1512`); `wasDat` records the
  // most recent IDAT/JDAT/JDAA seen, used to detect a text/EXIF chunk
  // AFTER the image data (`PNG.pm:1595-1605`).
  let mut was_hdr = false;
  let mut was_dat: Option<[u8; 4]> = None;
  // `$wasEnd` (`PNG.pm:1421`/`:1479`): set once the `IEND`/`MEND` end chunk has
  // been consumed. After that, bundled does NOT stop unconditionally — it keeps
  // reading: a 0-byte read is the normal end, but any remaining bytes are a
  // TRAILER that bundled processes as further chunks under the `Trailer`
  // family-1 group (`PNG.pm:1479-1484`, `SET_GROUP1 = 'Trailer'`).
  let mut was_end = false;
  // The first "Text/EXIF chunk(s) found after PNG <chunk>" warning is
  // emitted ONCE (bundled's `[x2]` aggregation is the writer mode; in
  // read mode every text-after-IDAT raises a fresh `$et->Warn`, but the
  // document-level FIRST-warning rule keeps only the first one).
  // We emit on every occurrence — the `TagMap::write_warning` first-of-
  // each-message dedup matches bundled's `[x2]` suffix output via the
  // document layer.
  loop {
    // `PNG.pm:1477`: read the 8-byte chunk header (length + type).
    let Some(header) = data.get(pos..pos + 8) else {
      // Fewer than 8 bytes remain. `PNG.pm:1479-1488`:
      //  * AFTER `IEND` (`$wasEnd`): a 0-byte read is the normal end of the PNG
      //    (`last unless $n`, no warning). A SHORT (1..8-byte) trailer fires the
      //    minor `Trailer data after PNG IEND chunk` warning (`PNG.pm:1481`)
      //    then stops (`last if $n < 8`, `PNG.pm:1483`) — the bytes are too
      //    short to form a chunk header, so nothing is extracted.
      //  * MID-walk (not `$wasEnd`): a truncated image (`PNG.pm:1486`
      //    `Warn("Truncated $fileType image") unless $wasEnd`).
      let _ = was_hdr;
      if was_end {
        if data.get(pos..pos + 1).is_some() {
          // 1..8 trailer bytes after IEND: warn (minor) then stop.
          meta.push_warning(String::from("Trailer data after PNG IEND chunk"));
          meta.begin_trailer();
        }
        // else: clean end of PNG (0 trailer bytes) — no warning.
      } else {
        meta.push_warning(String::from("Truncated PNG image"));
      }
      return Some(meta);
    };

    // `PNG.pm:1479-1484`: a full (>=8-byte) header read AFTER `IEND` is the
    // start of a TRAILER chunk. Fire the minor `Trailer data after PNG IEND
    // chunk` warning (bundled re-`Warn`s it on EVERY trailing chunk; the
    // document layer dedups to `[x2]…`, first-wins for `ExifTool:Warning`) and
    // switch the walk into trailer mode so each trailing chunk's PNG-level tags
    // carry the `Trailer` family-1 override (`SET_GROUP1 = 'Trailer'`).
    if was_end {
      meta.push_warning(String::from("Trailer data after PNG IEND chunk"));
      meta.begin_trailer();
    }

    let len_be = [header[0], header[1], header[2], header[3]];
    let len = u32::from_be_bytes(len_be) as usize;
    let chunk_type: [u8; 4] = [header[4], header[5], header[6], header[7]];

    // `PNG.pm:1490-1492`: `if ($len > 0x7fffffff)`. The warning is gated
    // `unless ($wasEnd)` (`PNG.pm:1491`) — in a trailer, bundled stops without
    // warning.
    if len > MAX_CHUNK_LENGTH {
      if !was_end {
        meta.push_warning(String::from("Invalid PNG chunk size"));
      }
      return Some(meta);
    }

    // `PNG.pm:1504-1512`: first chunk must be `IHDR` (the PNG header).
    if !was_hdr {
      if &chunk_type == b"IHDR" {
        was_hdr = true;
      } else if &chunk_type == b"CgBI" {
        // `PNG.pm:1507`: Apple iPhone non-standard prefix chunk.
        meta.push_warning(String::from("Non-standard PNG image (Apple iPhone format)"));
      } else {
        meta.push_warning(String::from("PNG image did not start with IHDR"));
      }
    }

    // Advance past the 8-byte header to the chunk payload start.
    pos += 8;

    // `PNG.pm:1546-1574`: the `IEND` end chunk — read its 4-byte CRC, set
    // `$wasEnd`, then `next` (`PNG.pm:1574`). `IEND` carries an empty payload
    // (`len == 0` always). It does NOT stop the walk: bundled keeps reading,
    // and any bytes AFTER the IEND CRC are processed as a TRAILER (handled at
    // the loop top, `PNG.pm:1479-1484`).
    if &chunk_type == b"IEND" {
      // `PNG.pm:1548-1551`: `$raf->Read($cbuf, 4)`; a truncated CRC warns
      // (`unless $wasEnd`, so only on the FIRST IEND) and stops the walk.
      if data.get(pos..pos + 4).is_none() {
        if !was_end {
          meta.push_warning(String::from("Truncated PNG IEND chunk"));
        }
        return Some(meta);
      }
      // `PNG.pm:1553`: `$wasEnd = 1`. Advance past the 4-byte CRC and continue;
      // the next iteration's header read decides normal-end vs trailer.
      was_end = true;
      pos += 4;
      continue;
    }

    // `PNG.pm:1607-1610`: read `dbuf` (the chunk data) + `cbuf` (the 4-byte
    // CRC). A short read warns `Corrupted $fileType image` (`PNG.pm:1608`,
    // gated `unless $wasEnd` — suppressed in a trailer) and stops.
    let Some(chunk_data) = data.get(pos..pos + len) else {
      if !was_end {
        meta.push_warning(String::from("Corrupted PNG image"));
      }
      return Some(meta);
    };
    // Bounds check ONLY: the 4-byte CRC field must be present (a chunk whose
    // declared length runs past EOF is truncated). bundled validates the CRC
    // VALUE in verbose/validate mode ONLY (`PNG.pm:123-124`, `:1612-1619`); the
    // default `extract_info` read path does NOT — so we do NOT compute it, and
    // never copy the (potentially multi-MB) IDAT/JDAT/JDAA pixel data into a
    // CRC buffer just to discard the result. This is faithful: bundled
    // `perl exiftool` without `-validate`/`-verbose` emits no `Bad CRC` warning.
    // A future validate mode should CRC INCREMENTALLY over the `chunk_type` +
    // `chunk_data` slices, never a concatenated buffer.
    if data.get(pos + len..pos + len + 4).is_none() {
      if !was_end {
        meta.push_warning(String::from("Corrupted PNG image"));
      }
      return Some(meta);
    }

    // `PNG.pm:1595-1605`: text/EXIF chunk AFTER an IDAT/JDAT/JDAA raises
    // `Text/EXIF chunk(s) found after $$et{FileType} $wasDat ($msg)`
    // (read mode: `$msg = 'may be ignored by some readers'`).
    if is_text_chunk(&chunk_type)
      && let Some(was) = was_dat
    {
      let was_str = was.iter().map(|&b| b as char).collect::<String>();
      let msg = std::format!(
        "Text/EXIF chunk(s) found after PNG {was_str} (may be ignored by some readers)",
      );
      meta.push_warning(msg);
    }

    // Track data-chunk position for the after-IDAT check above.
    if is_data_chunk(&chunk_type) {
      was_dat = Some(chunk_type);
    }

    // `PNG.pm:1640-1648`: translate the case of chunk names whose canonical
    // case changed since the first implementation (`%stdCase`, `PNG.pm:56`).
    // This fires AFTER the after-IDAT text-chunk check (`PNG.pm:1595`, which
    // tests the ON-DISK name — a lowercase `exif` is NOT in `%isTxtChunk`, so a
    // case-variant EXIF after IDAT does NOT raise the text-after-IDAT warning,
    // oracle-confirmed) and BEFORE the extraction dispatch (`PNG.pm:1653`).
    // In read mode bundled warns `"$chunk chunk should be $stdChunk"` using the
    // ON-DISK chunk bytes for `$chunk` and the canonical for `$stdChunk`, then
    // rewrites `$chunk` to the canonical so the EXIF dispatch sees `eXIf`/`zxIf`.
    let dispatch_type = if let Some(std) = std_case(&chunk_type) {
      let on_disk = chunk_type.iter().map(|&b| b as char).collect::<String>();
      let std_str = std.iter().map(|&b| b as char).collect::<String>();
      meta.push_warning(std::format!("{on_disk} chunk should be {std_str}"));
      *std
    } else {
      chunk_type
    };

    // `PNG.pm:1650-1657`: only extract from chunks in our tables. We
    // dispatch each ported chunk inline (on the case-normalized chunk type).
    dispatch_chunk(&mut meta, &dispatch_type, chunk_data);

    // Advance past chunk data + CRC.
    pos += len + 4;
  }
}

// ===========================================================================
// Chunk dispatcher — per-type body parsers
// ===========================================================================

/// Dispatch one chunk's payload to its sub-handler (`PNG.pm:1653-1657`
/// `if ($$tagTablePtr{$chunk}) { FoundPNG(...) }`).
///
/// Unknown chunks are silently ignored (bundled's table-miss branch). The
/// `IEND` terminator and the data chunks (`IDAT`/`JDAT`/`JDAA`) are NOT
/// dispatched here — they are handled by the outer walker.
fn dispatch_chunk(meta: &mut PngMeta<'_>, chunk: &[u8; 4], data: &[u8]) {
  match chunk {
    // ----- IHDR (PNG.pm:193-196, sub-table :387-423) ----------------------
    b"IHDR" => decode_ihdr(meta, data),
    // ----- pHYs (PNG.pm:216-222, sub-table :441-468) ---------------------
    b"pHYs" => decode_phys(meta, data),
    // ----- iCCP (PNG.pm:171-181) -----------------------------------------
    b"iCCP" => decode_iccp(meta, data),
    // ----- tEXt / zTXt / iTXt --------------------------------------------
    b"tEXt" => decode_text(meta, data),
    b"zTXt" => decode_ztxt(meta, data),
    b"iTXt" => decode_itxt(meta, data),
    // ----- eXIf / zxIf (PNG.pm:309-330) ---------------------------------
    // Both route to `ProcessPNG_eXIf` (`PNG.pm:1358`); `decode_exif` handles
    // the `II`/`MM` (uncompressed `eXIf`) AND the `\0`-prefixed compressed
    // (`zxIf`, `%stdCase` `PNG.pm:56`) bodies.
    b"eXIf" | b"zxIf" => decode_exif(meta, chunk, data),
    // ----- bKGD (PNG.pm:128-131) ----------------------------------------
    b"bKGD" => decode_bkgd(meta, data),
    // ----- tIME (PNG.pm:262-275) ----------------------------------------
    b"tIME" => decode_time(meta, data),
    // Every other chunk is in bundled's table (`acTL`, `cHRM`, `dSIG`, …)
    // but we DO NOT extract their tags in this Phase-2 port — they are
    // valid PNG chunks the walker skips silently (`PNG.pm:1657` table
    // miss). The chunk walker continues to the next chunk; this matches
    // bundled when the chunk is recognized but has no extractor.
    _ => {}
  }
}

// ===========================================================================
// IHDR decoder — PNG.pm:193-196 + sub-table :387-423
// ===========================================================================

/// `IHDR` decoder (`PNG.pm:387-423`). Always exactly 13 bytes:
///
/// | offset | length | field        | type   |
/// |--------|--------|--------------|--------|
/// | 0      | 4      | ImageWidth   | int32u |
/// | 4      | 4      | ImageHeight  | int32u |
/// | 8      | 1      | BitDepth     | int8u  |
/// | 9      | 1      | ColorType    | int8u  |
/// | 10     | 1      | Compression  | int8u  |
/// | 11     | 1      | Filter       | int8u  |
/// | 12     | 1      | Interlace    | int8u  |
fn decode_ihdr(meta: &mut PngMeta<'_>, data: &[u8]) {
  // A short/oversized IHDR is corrupt; bundled silently ignores the
  // missing tags through `ProcessBinaryData`'s out-of-range checks. We
  // require all 13 bytes — anything shorter ⇒ skip.
  if data.len() < 13 {
    return;
  }
  meta.set_ihdr(IhdrFields {
    width: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
    height: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
    bit_depth: data[8],
    color_type: data[9],
    compression: data[10],
    filter: data[11],
    interlace: data[12],
  });
}

// ===========================================================================
// pHYs decoder — PNG.pm:441-468
// ===========================================================================

/// `pHYs` decoder (`PNG.pm:441-468`). Always exactly 9 bytes:
///
/// | offset | length | field          | type   |
/// |--------|--------|----------------|--------|
/// | 0      | 4      | PixelsPerUnitX | int32u |
/// | 4      | 4      | PixelsPerUnitY | int32u |
/// | 8      | 1      | PixelUnits     | int8u  |
fn decode_phys(meta: &mut PngMeta<'_>, data: &[u8]) {
  if data.len() < 9 {
    return;
  }
  let ppu_x = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
  let ppu_y = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
  let units = data[8];
  meta.set_phys(ppu_x, ppu_y, units);
}

// ===========================================================================
// zlib inflate — bundled `Compress::Zlib::inflate` (PNG.pm:929-948)
// ===========================================================================

/// Outcome of inflating a PNG compressed-chunk payload, mirroring the three
/// branches of bundled's `FoundPNG` decompression (`PNG.pm:929-948`).
enum Inflate {
  /// `compression_method == 0` (deflate) and the zlib stream inflated cleanly
  /// — bundled's `$stat == Z_STREAM_END` arm (`PNG.pm:936-939`: `$val = $v2;
  /// $compressed = 0; $wasCompressed = 1`).
  Ok(Vec<u8>),
  /// `compression_method == 0` but the zlib stream is corrupt — bundled's
  /// `$deflateErr = "Error inflating $tag"` arm (`PNG.pm:942`).
  Error,
  /// `compression_method != 0` — bundled's `$deflateErr = "Unknown
  /// compression method $compressed for $tag"` arm (`PNG.pm:951`), where
  /// `$compressed` here is `(2 + method) - 2 == method`.
  UnknownMethod(u8),
}

/// Inflate a PNG compressed-chunk payload (`method_byte` + ZLIB-wrapped
/// deflate bytes), faithful to bundled `FoundPNG` (`PNG.pm:929-948`).
///
/// Bundled sets `$compressed = 2 + unpack('C', $val)` (`PNG.pm:1294` /
/// `:1346`); `$compressed == 2` (method byte 0) is "Inflate/Deflate"
/// (`PNG.pm:933`), anything higher is an unknown method. PNG compressed
/// chunks are ZLIB-wrapped (RFC 1950) deflate — NOT raw deflate — so we call
/// [`miniz_oxide::inflate::decompress_to_vec_zlib`] (the zlib variant that
/// validates + strips the 2-byte zlib header and the trailing Adler-32),
/// matching `Compress::Zlib::inflate`.
fn inflate_chunk(method_byte: u8, compressed: &[u8]) -> Inflate {
  if method_byte != 0 {
    // `PNG.pm:951`: `$compressed -= 2` then `"Unknown compression method
    // $compressed for $tag"`; `$compressed` was `2 + method_byte`, so the
    // reported number is the raw method byte.
    return Inflate::UnknownMethod(method_byte);
  }
  match miniz_oxide::inflate::decompress_to_vec_zlib(compressed) {
    Ok(bytes) => Inflate::Ok(bytes),
    // `PNG.pm:942`: any inflate failure (init failure or `$stat !=
    // Z_STREAM_END`) ⇒ `Error inflating $tag`.
    Err(_) => Inflate::Error,
  }
}

// ===========================================================================
// ImageMagick "Raw profile type X" chunks — ProcessProfile (PNG.pm:1155-1281)
// ===========================================================================

/// `Image::ExifTool::exifAPP1hdr` (`ExifTool.pm:1240`): the legacy
/// `Exif\0\0` 6-byte APP1 marker some writers prepend to a TIFF block.
const EXIF_APP1_HDR: &[u8] = b"Exif\0\0";

/// `Image::ExifTool::xmpAPP1hdr` (`ExifTool.pm:1241`): the XMP APP1 namespace
/// marker. A `Raw profile type APP1` / `exif` body that starts with this is
/// XMP, not EXIF (`PNG.pm:1236`).
const XMP_APP1_HDR: &[u8] = b"http://ns.adobe.com/xap/1.0/\0";

/// The kind of an ImageMagick `Raw profile type X` chunk keyword
/// (`PNG.pm:689-762`). ImageMagick (and other tools) write EXIF / ICC / IPTC /
/// XMP / Photoshop into PNG as `tEXt` / `zTXt` chunks whose keyword is
/// `Raw profile type <X>` and whose body is `\n<type>\n  <len>\n<hex bytes>`;
/// bundled routes each to `ProcessProfile` (`PNG.pm:698`/`:716`/`:724`/…) which
/// hex-decodes the body and dispatches to the embedded module's table.
///
/// Only the keywords with a registered `SubDirectory` (`PNG.pm:689-762`) are
/// classified here. Every OTHER keyword (ordinary `Comment` / `Title` / … AND
/// any *unregistered* `Raw profile type *` keyword) returns `None` from
/// [`raw_profile_kind`] and stays on the plain-text-record path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawProfileKind {
  /// `Raw profile type exif` (`PNG.pm:710`, Name `EXIF_Profile`) OR
  /// `Raw profile type APP1` (`PNG.pm:689`, Name `APP1_Profile`). BOTH register
  /// `TagTable => Exif::Main` as their (first / read-time) variant, so bundled
  /// dispatches both through the identical `$tagTablePtr eq $exifTable` branch
  /// of `ProcessProfile` (`PNG.pm:1216-1265`) — the embedded-module choice
  /// (EXIF vs XMP vs raw TIFF) is then keyed purely on the decoded CONTENT, not
  /// the keyword. `name` is the `SubDirectory` tag Name used in the wrong-size
  /// warning (`PNG.pm:1172`): `EXIF_Profile` for `exif`, `APP1_Profile` for
  /// `APP1`.
  ExifTable { name: &'static str },
  /// A profile whose embedded module exifast does NOT port — `icc` / `icm`
  /// (→ `ICC_Profile::Main`, `PNG.pm:719`/`:727`), `iptc` / `8bim`
  /// (→ `Photoshop::Main`, `PNG.pm:735`/`:755`), `xmp` (→ `XMP::Main`,
  /// `PNG.pm:746`). The body IS hex-decoded + the wrong-size warning IS still
  /// emitted (faithful to `ProcessProfile`, which runs before the module
  /// dispatch), but the decoded bytes are then SUPPRESSED (no tags) — the
  /// missing-sub-port deferral. `name` is the wrong-size-warning Name.
  SuppressedTable { name: &'static str },
}

/// Map a `tEXt` / `zTXt` keyword to its [`RawProfileKind`], or `None` for an
/// ordinary keyword (`Comment` / `Title` / … or any keyword that is NOT a
/// registered `Raw profile type X` SubDirectory).
///
/// The registered set is `%Image::ExifTool::PNG::Main` (`PNG.pm:689-762`):
/// `APP1` (`:689`), `exif` (`:710`), `icc` (`:719`), `icm` (`:727`), `iptc`
/// (`:735`), `xmp` (`:746`), `8bim` (`:755`). Resolution follows bundled
/// `FoundPNG` (`PNG.pm:919-921`): exact lookup, then `ucfirst($tag)` — so a
/// lowercase-first keyword (ImageMagick writes `raw profile type exif`) still
/// resolves to the registered profile (and decodes + resets `$$et{PROCESSED}`),
/// rather than falling to the dynamic-tag path. Like Perl `ucfirst`, only the
/// FIRST char is upper-cased — all-caps / mid-word Title-case variants do NOT
/// resolve. The wrong-size-warning Name (`PNG.pm:1172`) is carried in the variant.
fn raw_profile_kind(keyword: &str) -> Option<RawProfileKind> {
  // The registered keys all start "Raw …", so matching the first-byte-
  // upper-cased keyword covers exact-case AND lowercase-first.
  match ucfirst_ascii(keyword).as_bytes() {
    // EXIF-capable profiles (Exif::Main table → content-keyed dispatch).
    b"Raw profile type exif" => Some(RawProfileKind::ExifTable {
      name: "EXIF_Profile",
    }),
    b"Raw profile type APP1" => Some(RawProfileKind::ExifTable {
      name: "APP1_Profile",
    }),
    // Profiles whose module is not ported → decode body + warn-on-size, suppress.
    b"Raw profile type icc" | b"Raw profile type icm" => Some(RawProfileKind::SuppressedTable {
      name: "ICC_Profile",
    }),
    b"Raw profile type iptc" => Some(RawProfileKind::SuppressedTable {
      name: "IPTC_Profile",
    }),
    b"Raw profile type 8bim" => Some(RawProfileKind::SuppressedTable {
      name: "Photoshop_Profile",
    }),
    b"Raw profile type xmp" => Some(RawProfileKind::SuppressedTable {
      name: "XMP_Profile",
    }),
    _ => None,
  }
}

/// ASCII `ucfirst` (Perl `ucfirst`, restricted to ASCII — PNG keywords are
/// ASCII): upper-case the first byte when it is an ASCII lowercase letter, else
/// borrow unchanged (no allocation for the common already-capital case).
fn ucfirst_ascii(s: &str) -> std::borrow::Cow<'_, str> {
  match s.as_bytes().first() {
    Some(b) if b.is_ascii_lowercase() => {
      let mut out = String::with_capacity(s.len());
      out.push(b.to_ascii_uppercase() as char);
      out.push_str(&s[1..]);
      std::borrow::Cow::Owned(out)
    }
    _ => std::borrow::Cow::Borrowed(s),
  }
}

/// `PNG.pm:1122`: bundled flags the dynamically-added tag `Binary => 1` iff the
/// ORIGINAL keyword `$tag =~ /^Raw profile type /` — case-sensitive, with
/// literal single spaces (the match runs on the raw keyword, NOT the
/// whitespace-collapsed tag name). Oracle-confirmed: a double-space
/// `Raw  profile  type  generic` keyword does NOT match (its value emits as
/// plain text), but `Raw profile type generic` / `Raw profile type exifZ` do.
const RAW_PROFILE_PREFIX: &str = "Raw profile type ";

/// Normalize a PNG keyword to the tag NAME bundled assigns a dynamically-added
/// tag (the `FoundPNG` `else` branch, `PNG.pm:1116-1124`, plus the universal
/// `GetTagInfoList` normalization at `ExifTool.pm:9256-9257`):
///
/// 1. `($name = $tag) =~ s/\s+(.)/\u$1/g` (`PNG.pm:1118`) — collapse each run
///    of whitespace and uppercase the FOLLOWING character (the first character
///    is NOT touched here).
/// 2. `$name =~ tr/-_a-zA-Z0-9//dc` (`ExifTool.pm:9256`) — drop every character
///    that is not `[-_a-zA-Z0-9]` (the collapsed spaces are already gone; a
///    stray punctuation byte would be stripped here).
/// 3. `$name = ucfirst $name` (`ExifTool.pm:9257`) — capitalize the first
///    letter. (So a lowercase `raw profile type generic` → `RawProfileTypeGeneric`,
///    oracle-confirmed.)
///
/// Examples (oracle `-j -G1`): `Raw profile type exif` → `RawProfileTypeExif`,
/// `Raw profile type APP1` → `RawProfileTypeAPP1`, `Raw profile type 8bim` →
/// `RawProfileType8bim`, `Raw profile type generic` → `RawProfileTypeGeneric`.
fn png_dynamic_tag_name(keyword: &str) -> String {
  let mut name = String::with_capacity(keyword.len());
  // Step 1: collapse whitespace runs, uppercasing the char after each run.
  // `prev_ws` starts true so a LEADING whitespace run also uppercases the next
  // char — matching `s/\s+(.)/\u$1/g` (which anchors on a `\s+` run anywhere).
  let mut prev_ws = false;
  for ch in keyword.chars() {
    if ch.is_whitespace() {
      prev_ws = true;
      continue;
    }
    if prev_ws {
      // `\u$1` uppercases just this one char (its full Unicode upper-case).
      for up in ch.to_uppercase() {
        name.push(up);
      }
    } else {
      name.push(ch);
    }
    prev_ws = false;
  }
  // Step 2: `tr/-_a-zA-Z0-9//dc` — keep only `[-_a-zA-Z0-9]`.
  name.retain(|c| c == '-' || c == '_' || c.is_ascii_alphanumeric());
  // Step 3: `ucfirst` — capitalize the first character.
  if let Some(first) = name.chars().next()
    && !first.is_uppercase()
  {
    let mut out = String::with_capacity(name.len());
    for up in first.to_uppercase() {
      out.push(up);
    }
    out.push_str(&name[first.len_utf8()..]);
    return out;
  }
  name
}

/// The `FoundPNG` `else`-branch hook (`PNG.pm:1116-1124`): a chunk keyword for
/// which NO `tagInfo` resolved becomes a DYNAMIC tag. `value` is the chunk's
/// DECODED value bytes (`$val` after `PNG.pm:964` `Decode` — Latin-1→UTF-8 for
/// `tEXt`/`zTXt`, UTF-8 for `iTXt`), which `-b` re-emits verbatim. The tag name
/// is [`png_dynamic_tag_name`]; the `Binary => 1` flag (`PNG.pm:1122`) is set
/// iff the ORIGINAL keyword matches [`RAW_PROFILE_PREFIX`]. Pushes a
/// [`PngDynamicProfileTag`]; emits NO [`PngExifEvent`] (this path never reaches
/// `ProcessProfile`, so it performs NO `$$et{PROCESSED}` reset).
fn push_dynamic_profile(meta: &mut PngMeta<'_>, keyword: &str, value: Vec<u8>) {
  let name = png_dynamic_tag_name(keyword);
  let binary = keyword.starts_with(RAW_PROFILE_PREFIX);
  meta.push_dynamic_profile_tag(PngDynamicProfileTag::new(name.into(), value, binary));
}

/// The hex-decoded payload of a `Raw profile type X` body — `ProcessProfile`
/// (`PNG.pm:1166-1174`). `bytes` is the hex-decoded profile; `name` is the
/// SubDirectory tag Name (for the wrong-size warning). Returns `None` when the
/// body does not match ImageMagick's `^\n(.*?)\n\s*(\d+)\n(.*)$` framing
/// (`PNG.pm:1166` `return 0`).
struct DecodedProfile {
  bytes: Vec<u8>,
  /// The profile-type line (`$1`, e.g. `b"exif"` / `b"APP1"` / `b"generic
  /// profile"`) — verbatim bytes, used for the `Unknown raw profile '<type>'`
  /// warning (`PNG.pm:1267-1269`).
  profile_type: Vec<u8>,
  /// `Some(warning)` when the declared `<len>` disagreed with the actual
  /// decoded length (`PNG.pm:1171-1173`). Already formatted with the tag Name.
  size_warning: Option<String>,
}

/// Decode an ImageMagick profile body, faithful to `ProcessProfile`
/// (`PNG.pm:1166-1174`).
///
/// Bundled: `return 0 unless $$dataPt =~ /^\n(.*?)\n\s*(\d+)\n(.*)/s;` — the
/// body must be a newline, a profile-type line, a (whitespace-indented) decimal
/// length line, then the hex payload (the final `(.*)` is DOTALL — it spans the
/// remaining newlines). `my $buff = pack('H*', join('',split(' ',$3)));` —
/// the payload is hex, whitespace-separated (every run of ASCII whitespace is
/// removed before `pack('H*', …)`). When the declared `<len>` (`$2`) differs
/// from the actual decoded byte count, bundled warns `"$tagName is wrong size
/// (should be $len bytes but is $actualLen)"` (`PNG.pm:1172`) and continues
/// with the actual bytes.
///
/// `name` is the SubDirectory tag Name (`EXIF_Profile` / `APP1_Profile` /
/// `ICC_Profile` / …) used verbatim in that warning.
fn process_profile(body: &[u8], name: &str) -> Option<DecodedProfile> {
  // `^\n` — the body must begin with a newline (`PNG.pm:1166`).
  let rest = body.strip_prefix(b"\n")?;
  // `(.*?)\n` — the profile-type line (non-greedy up to the first `\n`). We do
  // not USE the profile type for routing (we key on content like bundled's
  // EXIF arm), but the `Unknown raw profile '<type>'` warning needs it, so
  // capture it.
  let type_end = rest.iter().position(|&b| b == b'\n')?;
  let profile_type = &rest[..type_end];
  let after_type = &rest[type_end + 1..];
  // `\s*(\d+)\n` — optional leading ASCII whitespace, then a decimal length,
  // then a newline. Perl `\s` is `[ \t\n\r\f\v]`; `\d` is `[0-9]`.
  let mut i = 0;
  while i < after_type.len() && after_type[i].is_ascii_whitespace() {
    i += 1;
  }
  let digit_start = i;
  while i < after_type.len() && after_type[i].is_ascii_digit() {
    i += 1;
  }
  // Need at least one digit and a terminating `\n` (`PNG.pm:1166` `(\d+)\n`).
  if i == digit_start || after_type.get(i) != Some(&b'\n') {
    return None;
  }
  // `$2` is ASCII digits — parse as the declared length. A value that overflows
  // `usize` cannot equal any real decoded length, so the wrong-size branch
  // fires; saturate to keep the comparison well-defined.
  let declared_len: usize = core::str::from_utf8(&after_type[digit_start..i])
    .ok()
    .and_then(|s| s.parse::<usize>().ok())
    .unwrap_or(usize::MAX);
  let hex_region = &after_type[i + 1..];

  // `pack('H*', join('',split(' ',$3)))` — strip ALL ASCII whitespace, then
  // hex-decode. Perl's `pack('H*', …)` ignores a trailing nibble (an odd-length
  // hex string drops the last char); non-hex chars decode as 0 in `pack` but
  // ImageMagick always emits clean hex, so we treat a stray non-hex nibble as a
  // decode stop (faithful enough for real input — see the module docs).
  let mut decoded = Vec::with_capacity(hex_region.len() / 2);
  let mut hi: Option<u8> = None;
  for &b in hex_region {
    if b.is_ascii_whitespace() {
      continue;
    }
    let Some(nib) = hex_nibble(b) else {
      // Non-hex, non-space char: bundled `pack('H*')` would treat it as 0, but
      // real ImageMagick output never contains one. Stop decoding here (the
      // wrong-size warning then reports the short length, matching a truncated
      // profile).
      break;
    };
    match hi.take() {
      None => hi = Some(nib),
      Some(h) => decoded.push((h << 4) | nib),
    }
  }
  // `pack('H*', …)` on an odd nibble count drops the dangling nibble — so a
  // leftover `hi` contributes nothing.

  let actual_len = decoded.len();
  let size_warning = if declared_len != actual_len {
    Some(std::format!(
      "{name} is wrong size (should be {declared_len} bytes but is {actual_len})"
    ))
  } else {
    None
  };
  Some(DecodedProfile {
    bytes: decoded,
    profile_type: profile_type.to_vec(),
    size_warning,
  })
}

/// ASCII hex nibble (`0-9A-Fa-f`) → value, or `None`. (`pack('H*', …)` is
/// case-insensitive.)
const fn hex_nibble(b: u8) -> Option<u8> {
  match b {
    b'0'..=b'9' => Some(b - b'0'),
    b'a'..=b'f' => Some(b - b'a' + 10),
    b'A'..=b'F' => Some(b - b'A' + 10),
    _ => None,
  }
}

/// Route the hex-decoded EXIF-table profile bytes (`exif` / `APP1`) exactly as
/// `ProcessProfile`'s `$tagTablePtr eq $exifTable` branch (`PNG.pm:1216-1270`).
///
/// The content keying (the SAME order bundled uses):
/// 1. `^Exif\0\0` (`PNG.pm:1216`, `$exifAPP1hdr`) — strip the 6-byte marker,
///    the remainder is a TIFF block → capture as the EXIF block.
/// 2. `^http://ns.adobe.com/xap/1.0/\0` (`PNG.pm:1236`, `$xmpAPP1hdr`) — XMP →
///    DEFERRED (no XMP module; suppress, no tags, no warning).
/// 3. `^(MM\0\x2a|II\x2a\0)` (`PNG.pm:1250`) — a bare TIFF → capture as the
///    EXIF block.
/// 4. else (`PNG.pm:1266-1269`) — warn `Unknown raw profile '<type>'` (the
///    profile-type string with control / high bytes replaced by `.`), suppress.
///
/// EVERY arm of this routine has reached `ProcessProfile`'s content dispatch,
/// which means the profile body was WELL-FORMED — and bundled has ALREADY reset
/// `$$et{PROCESSED}` (`PNG.pm:1193`) at this point, BEFORE the content keying.
/// So all four arms emit a PROCESSED-reset event:
/// - a TIFF match ([`PngExifEvent::ExifProfile`]) resets AND walks the TIFF;
/// - the XMP / unknown-content arms ([`PngExifEvent::ResetOnlyProfile`]) reset
///   with no EXIF tags (oracle-verified: an `exif`/`APP1` profile whose content
///   is XMP or unrecognized STILL un-blocks a following `eXIf` at the same IFD0
///   `$addr`).
///
/// The events are recorded in walk order alongside any native `eXIf`;
/// `tags()` / `project()` / the warning-drain replay the shared-`$$et{PROCESSED}`
/// algorithm over the ordered [`PngMeta::exif_events`] stream, so an EXIF TIFF's
/// embedded IFD0 / ExifIFD / GPS / MakerNotes flow through the golden path with
/// the correct cross-source reset + blocking.
fn route_exif_profile(meta: &mut PngMeta<'_>, bytes: Vec<u8>, profile_type: &[u8]) {
  // 1. `Exif\0\0`-prefixed TIFF — strip the marker (`PNG.pm:1219-1221`).
  if let Some(tiff) = bytes.strip_prefix(EXIF_APP1_HDR) {
    // A bare `Exif\0\0` with no TIFF after it is degenerate; capture whatever
    // remains (the EXIF walker returns `None` on a non-TIFF, emitting nothing).
    meta.push_exif_event(PngExifEvent::ExifProfile(tiff.to_vec()));
    return;
  }
  // 2. XMP APP1 — no ported XMP module (#37), so no tags. But `ProcessProfile`
  //    has already RESET `$$et{PROCESSED}` (`PNG.pm:1193`) before this XMP
  //    dispatch (oracle-confirmed: a `Raw profile type {exif,APP1}` carrying XMP
  //    un-blocks a following same-`$addr` `eXIf`), so emit a reset-only event.
  if bytes.starts_with(XMP_APP1_HDR) {
    meta.push_exif_event(PngExifEvent::ResetOnlyProfile);
    return;
  }
  // 3. Bare TIFF (`II\x2a\0` / `MM\0\x2a`) — capture directly.
  if bytes.starts_with(b"II\x2a\0") || bytes.starts_with(b"MM\0\x2a") {
    meta.push_exif_event(PngExifEvent::ExifProfile(bytes));
    return;
  }
  // 4. Unknown raw profile (`PNG.pm:1266-1269`): the profile-type string with
  //    control (`\x00-\x1f`) and high (`\x7f-\xff`) bytes replaced by `.`
  //    (`$profName =~ tr/\x00-\x1f\x7f-\xff/./`). The reset has ALREADY happened
  //    (oracle-confirmed: a well-formed but unrecognized-content `exif` profile
  //    un-blocks a following same-`$addr` `eXIf`), so emit a reset-only event in
  //    ADDITION to the warning.
  let prof_name: String = profile_type
    .iter()
    .map(|&b| {
      if (0x20..=0x7e).contains(&b) {
        b as char
      } else {
        '.'
      }
    })
    .collect();
  meta.push_warning(std::format!("Unknown raw profile '{prof_name}'"));
  meta.push_exif_event(PngExifEvent::ResetOnlyProfile);
}

/// Handle a recognized `Raw profile type X` chunk body — `ProcessProfile`
/// (`PNG.pm:1155-1281`) reached via the chunk's `SubDirectory` `ProcessProc`.
///
/// `body` is the RAW (Latin-1 / inflated) chunk value — ImageMagick's
/// `\n<type>\n  <len>\n<hex bytes>`. Faithful sequence:
/// 1. `process_profile` matches the framing + hex-decodes (`PNG.pm:1166-1170`).
///    A body that does not match the framing ⇒ bundled `return 0` ⇒ we emit
///    nothing (and, crucially, still NO plain-text record — the keyword is a
///    recognized SubDirectory either way).
/// 2. Any wrong-size warning (`PNG.pm:1172`) is pushed.
/// 3. The decoded bytes route per kind: [`RawProfileKind::ExifTable`] →
///    [`route_exif_profile`] (content-keyed EXIF/XMP/TIFF dispatch);
///    [`RawProfileKind::SuppressedTable`] → suppressed (no ported module).
///
/// In NO case is a `PNG:"Raw profile type X"` text record pushed (bundled emits
/// the DECODED tags or nothing — never the keyword=hex text tag).
fn handle_raw_profile(meta: &mut PngMeta<'_>, kind: RawProfileKind, body: &[u8]) {
  let name = match kind {
    RawProfileKind::ExifTable { name } | RawProfileKind::SuppressedTable { name } => name,
  };
  // `PNG.pm:1166` `return 0 unless …` — a malformed body decodes to nothing.
  let Some(profile) = process_profile(body, name) else {
    return;
  };
  // `PNG.pm:1172` wrong-size warning (emitted before the module dispatch).
  if let Some(w) = profile.size_warning {
    meta.push_warning(w);
  }
  match kind {
    // EXIF / APP1 → the `$tagTablePtr eq $exifTable` content-keyed branch
    // (which itself emits the reset event — `ExifProfile` or `ResetOnlyProfile`
    // per content).
    RawProfileKind::ExifTable { .. } => {
      route_exif_profile(meta, profile.bytes, &profile.profile_type);
    }
    // ICC / IPTC / XMP / Photoshop → module not ported; no tags emitted.
    // Bundled would `ProcessDirectory` into ICC_Profile / Photoshop / XMP, but
    // crucially `ProcessProfile` has ALREADY RESET `$$et{PROCESSED}`
    // (`PNG.pm:1193`) before that module dispatch — oracle-confirmed: a
    // well-formed `icc`/`iptc`/`8bim`/`xmp` profile un-blocks a following
    // same-`$addr` `eXIf`. So emit a reset-only event (the deferred module's
    // tags stay unemitted; the cross-source reset is the load-bearing effect).
    RawProfileKind::SuppressedTable { .. } => {
      meta.push_exif_event(PngExifEvent::ResetOnlyProfile);
    }
  }
}

// ===========================================================================
// iCCP decoder — PNG.pm:171-181 (NAME + inflate body; ICC tag decode deferred)
// ===========================================================================

/// `iCCP` decoder (`PNG.pm:1288-1318 ProcessPNG_Compressed` with the
/// `iCCP` arm at `:1301-1313`).
///
/// Layout: `keyword \0 compression_method compressed_profile_bytes`.
/// We capture the keyword (`FoundPNG($et, ..., 'iCCP-name', $tag)`,
/// `PNG.pm:1304`). The profile bytes ARE compressed (`compressed = 2 +
/// unpack('C', $val)`, `PNG.pm:1294`); bundled then inflates them and routes
/// the result to the `ICC_Profile` sub-table.
///
/// We inflate the body via [`inflate_chunk`] to faithfully reproduce bundled's
/// inflate-error vs unknown-method warnings (`PNG.pm:942` / `:951`, the
/// deflate-error tag name is the chunk name `iCCP`). On inflate SUCCESS the
/// inflated ICC profile is NOT further decoded — turning it into
/// `ICC_Profile:*` tags needs a dedicated `ICC_Profile` module port (color
/// management, out of camera-metadata scope) which exifast does NOT have. That
/// ICC-tag decode is the remaining deferral (it is NO LONGER a zlib gap); the
/// profile NAME is still emitted and the inflated body is dropped (no warning,
/// no fabricated tags).
fn decode_iccp(meta: &mut PngMeta<'_>, data: &[u8]) {
  // `PNG.pm:1291`: `my ($tag, $val) = split /\0/, ${$$dirInfo{DataPt}}, 2;`
  let Some(nul) = data.iter().position(|&b| b == 0) else {
    return;
  };
  let (keyword_bytes, after) = data.split_at(nul);
  // Skip the NUL separator. `after[0]` is the compression-method byte
  // (`PNG.pm:1294`); bundled requires at least one byte beyond it for the
  // payload.
  if after.len() < 2 {
    return;
  }
  // Keyword is Latin-1 (`PNG.pm:1304` uses bundled's text path).
  let keyword = decode_latin1(keyword_bytes);
  if keyword.is_empty() {
    return;
  }
  meta.set_icc_profile_name(SmolStr::new(&keyword));
  // `compressed = 2 + method` (`PNG.pm:1294`); the compression-method byte is
  // `after[1]`, the compressed profile starts at `after[2]`.
  let method = after[1];
  let payload = &after[2..];
  match inflate_chunk(method, payload) {
    // Inflated cleanly: the ICC profile is available but we do NOT decode it
    // into `ICC_Profile:*` tags (no ICC_Profile sub-port — deferred). Bundled
    // emits no warning here; neither do we. The profile NAME is already set.
    Inflate::Ok(_inflated) => {}
    // `PNG.pm:942`: corrupt zlib ⇒ `Error inflating $tag` (tag = chunk `iCCP`).
    Inflate::Error => {
      meta.push_warning(String::from("Error inflating iCCP"));
    }
    // `PNG.pm:951`: `Unknown compression method <method> for iCCP`.
    Inflate::UnknownMethod(m) => {
      meta.push_warning(std::format!("Unknown compression method {m} for iCCP"));
    }
  }
}

// ===========================================================================
// tEXt decoder — PNG.pm:258-261 + :1325-1332
// ===========================================================================

/// `tEXt` decoder (`PNG.pm:1325-1332 ProcessPNG_tEXt`).
///
/// Layout: `keyword \0 latin1_value` (`PNG.pm:1328` `split /\0/, …, 2`).
/// Both keyword and value are Latin-1 (bundled `enc = 'Latin'`,
/// `PNG.pm:1331`).
///
/// A keyword with NO NUL is malformed; bundled then calls `FoundPNG` with
/// `$val = undef` and the helper returns 0 (`PNG.pm:911`). We silently skip
/// the chunk in that case.
fn decode_text(meta: &mut PngMeta<'_>, data: &[u8]) {
  let Some(nul) = data.iter().position(|&b| b == 0) else {
    return;
  };
  let (keyword_bytes, after) = data.split_at(nul);
  // Skip the NUL. The remaining bytes are the Latin-1 value (which, for a
  // `Raw profile type X` chunk, is the ImageMagick hex-profile body — pure
  // ASCII, so the raw bytes ARE the body bundled hands to `ProcessProfile`).
  let value_bytes = &after[1..];
  let keyword = decode_latin1(keyword_bytes);
  if keyword.is_empty() {
    return;
  }
  // A REGISTERED `Raw profile type X` keyword routes to `ProcessProfile`
  // (`PNG.pm:698`/…): hex-decode + dispatch the embedded module, emitting NO
  // text tag. `tEXt` carries no language field, so the SubDirectory always
  // resolves (no `GetLangInfo` detour). Operate on the RAW value bytes (the
  // body is ASCII hex/whitespace).
  if let Some(kind) = raw_profile_kind(&keyword) {
    handle_raw_profile(meta, kind, value_bytes);
    return;
  }
  let value = decode_latin1(value_bytes);
  // An UNREGISTERED `Raw profile type *` keyword has no table entry, so
  // `FoundPNG` falls into its dynamic-tag `else` branch (`PNG.pm:1116-1124`):
  // a `Binary => 1` `RawProfileType<X>` tag carrying the DECODED value bytes
  // (oracle-confirmed for `Raw profile type generic`). Decode-then-store, so
  // the stored bytes match `-b` (Latin-1→UTF-8, `PNG.pm:964`).
  if keyword.starts_with(RAW_PROFILE_PREFIX) {
    push_dynamic_profile(meta, &keyword, value.into_bytes());
    return;
  }
  meta.push_text_record(PngTextRecord::new_text(SmolStr::new(&keyword), value));
}

// ===========================================================================
// zTXt decoder — PNG.pm:294-300 + :1288-1318 (zlib inflate + tEXt record path)
// ===========================================================================

/// `zTXt` decoder (`PNG.pm:1288-1318 ProcessPNG_Compressed`, called through
/// the `zTXt` arm of the chunk table at `PNG.pm:294-300`).
///
/// Layout: `keyword \0 compression_method compressed_latin1_value`. The
/// keyword always precedes the compression flag.
///
/// On a clean inflate (`PNG.pm:936-939`) the decompressed bytes are decoded as
/// Latin-1 (bundled's `enc => 'Latin'`, `PNG.pm:1315`, runs because
/// `$compressed` is reset to 0 after inflate) and stored through the EXACT
/// `tEXt` keyword→record path ([`PngTextRecord::new_text`]) — so `tags()`
/// emits `PNG:<keyword>` identically to a plain `tEXt`. A corrupt stream warns
/// `Error inflating <keyword>` (`PNG.pm:942`); a non-zero compression method
/// warns `Unknown compression method <n> for <keyword>` (`PNG.pm:951`). In
/// both warning cases the record carries an empty value (the still-compressed
/// bytes are not emitted as text).
fn decode_ztxt(meta: &mut PngMeta<'_>, data: &[u8]) {
  let Some(nul) = data.iter().position(|&b| b == 0) else {
    return;
  };
  let (keyword_bytes, after) = data.split_at(nul);
  // Skip NUL + compression-method byte. We need at least one byte for the
  // compression method to consider the chunk well-formed.
  if after.len() < 2 {
    return;
  }
  let keyword = decode_latin1(keyword_bytes);
  if keyword.is_empty() {
    return;
  }
  // `compressed = 2 + method` (`PNG.pm:1294`); method byte = `after[1]`, the
  // compressed value starts at `after[2]`.
  let method = after[1];
  let payload = &after[2..];
  match inflate_chunk(method, payload) {
    Inflate::Ok(inflated) => {
      // A REGISTERED `Raw profile type X` zTXt routes the INFLATED bytes to
      // `ProcessProfile` (`PNG.pm:1315` resolves the keyword's SubDirectory
      // AFTER inflate; the embedded-module dispatch then runs on `$val`),
      // emitting NO text tag. `zTXt` carries no language field, so the
      // SubDirectory always resolves. The body is the hex-profile (ASCII), so
      // the inflated raw bytes ARE bundled's `$val`.
      if let Some(kind) = raw_profile_kind(&keyword) {
        handle_raw_profile(meta, kind, &inflated);
        return;
      }
      // `PNG.pm:1315` `enc => 'Latin'`: the decompressed bytes are Latin-1.
      let value = decode_latin1(&inflated);
      // An UNREGISTERED `Raw profile type *` keyword → the dynamic `Binary => 1`
      // `RawProfileType<X>` tag (`PNG.pm:1116-1124`), carrying the DECODED
      // (inflated, Latin-1→UTF-8) value bytes that `-b` re-emits.
      if keyword.starts_with(RAW_PROFILE_PREFIX) {
        push_dynamic_profile(meta, &keyword, value.into_bytes());
        return;
      }
      // Store EXACTLY as `tEXt` would (same keyword→record path) so emission
      // is byte-identical to an uncompressed `tEXt` of the same value.
      meta.push_text_record(PngTextRecord::new_text(SmolStr::new(&keyword), value));
    }
    Inflate::Error => {
      // Keep the keyword (chunk recognized) with an empty value; warn.
      meta.push_text_record(PngTextRecord::new_ztxt_deferred(SmolStr::new(&keyword)));
      meta.push_warning(std::format!("Error inflating {keyword}"));
    }
    Inflate::UnknownMethod(m) => {
      // `PNG.pm:951`: `Unknown compression method $compressed for $tag`. The
      // tag IS the keyword in bundled.
      meta.push_text_record(PngTextRecord::new_ztxt_deferred(SmolStr::new(&keyword)));
      meta.push_warning(std::format!("Unknown compression method {m} for {keyword}"));
    }
  }
}

// ===========================================================================
// iTXt decoder — PNG.pm:197-203 + :1339-1351
// ===========================================================================

/// `iTXt` decoder (`PNG.pm:1339-1351 ProcessPNG_iTXt`).
///
/// Layout: `keyword \0 [compressed_flag: 1] [compression_method: 1]
///   language \0 translated_keyword \0 utf8_value`.
///
/// `PNG.pm:1342-1345`:
/// ```text
/// my ($tag, $dat) = split /\0/, ${$$dirInfo{DataPt}}, 2;
/// return 0 unless defined $dat and length($dat) >= 4;
/// my ($compressed, $meth) = unpack('CC', $dat);
/// my ($lang, $trans, $val) = split /\0/, substr($dat, 2), 3;
/// ```
///
/// The keyword is Latin-1 (`PNG.pm:1325-1331`); the language tag is RFC
/// 3066 ASCII; the translated keyword + value are UTF-8 (`enc = 'UTF8'`,
/// `PNG.pm:1350`). When `compressed != 0` the trailing value bytes are
/// zlib-compressed (`PNG.pm:1347` sets `$compressed = 2 + $meth`); bundled
/// inflates them in `FoundPNG` and the result is decoded as UTF-8. We do the
/// same via [`inflate_chunk`] and store the record through the EXACT
/// uncompressed-`iTXt` path (same keyword / language / translated-keyword,
/// `compressed = false`) so `tags()` emits `PNG:<keyword>[-<lang>]`
/// identically. A corrupt stream warns `Error inflating <keyword>`
/// (`PNG.pm:942`); a non-zero compression method warns `Unknown compression
/// method <n> for <keyword>` (`PNG.pm:951`) — in both warning cases the
/// record keeps an empty value and stays flagged compressed (not emitted).
/// Note bundled splits language / translated-keyword / value off the STILL-
/// COMPRESSED `$dat` (`split /\0/, …, 3`) before inflating, so the value
/// field is the raw deflate stream — which we then inflate.
fn decode_itxt(meta: &mut PngMeta<'_>, data: &[u8]) {
  // `PNG.pm:1342`: `split /\0/, …, 2` — keyword to first NUL, then dat.
  let Some(nul) = data.iter().position(|&b| b == 0) else {
    return;
  };
  let (keyword_bytes, after) = data.split_at(nul);
  let dat = &after[1..]; // skip NUL
  // `PNG.pm:1343`: `length($dat) >= 4` — compressed + method + 2 NULs.
  if dat.len() < 4 {
    return;
  }
  let compressed = dat[0] != 0;
  let method = dat[1];
  // `PNG.pm:1345`: `split /\0/, substr($dat, 2), 3` — language, translated
  // keyword, then the value (which may contain raw NULs in compressed
  // payloads — but `split /\0/, …, 3` keeps the third field as the rest
  // of the string). We replicate that semantics: find the first NUL
  // (language end), the second NUL (translated-keyword end), then value
  // is the remainder.
  let rest = &dat[2..];
  let nul1 = rest.iter().position(|&b| b == 0);
  let Some(n1) = nul1 else { return };
  let (language_bytes, after_l) = rest.split_at(n1);
  let rest2 = &after_l[1..]; // skip NUL
  let Some(n2) = rest2.iter().position(|&b| b == 0) else {
    return;
  };
  let (translated_bytes, after_t) = rest2.split_at(n2);
  let value_bytes = &after_t[1..]; // skip NUL

  let keyword = decode_latin1(keyword_bytes);
  if keyword.is_empty() {
    return;
  }
  // Language tag: ASCII per RFC 3066; preserve the bytes verbatim via UTF-8
  // fix (a stray non-ASCII byte is `?`).
  let language = SmolStr::new(crate::convert::fix_utf8(language_bytes));
  let translated = SmolStr::new(crate::convert::fix_utf8(translated_bytes));

  if compressed {
    // `value_bytes` is the raw zlib deflate stream (`PNG.pm:1347`). Inflate
    // it; on success decode as UTF-8 and store as an UNCOMPRESSED iTXt record
    // (`compressed = false`) so emission is byte-identical to a plain iTXt.
    match inflate_chunk(method, value_bytes) {
      Inflate::Ok(inflated) => {
        // `PNG.pm:1350` `enc => 'UTF8'`: decode the inflated bytes as UTF-8
        // (`fix_utf8` repairs stray bytes via the bundled XMP::FixUTF8 walker).
        let value = crate::convert::fix_utf8(&inflated);
        route_itxt_raw_profile_or_text(meta, &keyword, value, language, translated);
      }
      Inflate::Error => {
        meta.push_text_record(PngTextRecord::new_itxt(
          SmolStr::new(&keyword),
          String::new(),
          language,
          translated,
          true,
        ));
        meta.push_warning(std::format!("Error inflating {keyword}"));
      }
      Inflate::UnknownMethod(m) => {
        meta.push_text_record(PngTextRecord::new_itxt(
          SmolStr::new(&keyword),
          String::new(),
          language,
          translated,
          true,
        ));
        meta.push_warning(std::format!("Unknown compression method {m} for {keyword}"));
      }
    }
  } else {
    // Value is UTF-8 per the spec; `fix_utf8` repairs stray bytes via the
    // bundled XMP::FixUTF8 walker.
    let value = crate::convert::fix_utf8(value_bytes);
    route_itxt_raw_profile_or_text(meta, &keyword, value, language, translated);
  }
}

/// The shared `iTXt` routing for a cleanly-decoded value (`PNG.pm:1339-1351` →
/// `FoundPNG`), covering BOTH the compressed-and-inflated and the uncompressed
/// arms. `value` is the DECODED (UTF-8) value; `language` / `translated` are the
/// iTXt subfields. The keyword decides the destination:
///
/// 1. **Registered raw-profile SubDirectory keyword + EMPTY language** →
///    `handle_raw_profile` (`ProcessProfile`): the SubDirectory resolves, the
///    embedded module is dispatched, and `$$et{PROCESSED}` is reset
///    (`PNG.pm:1193`). This is the current EXIF-decode behaviour.
/// 2. **Registered raw-profile SubDirectory keyword + NON-EMPTY language** →
///    `push_dynamic_profile`. `GetLangInfo` returns `undef` for a SubDirectory
///    tag (`PNG.pm:895`), so `FoundPNG` cannot resolve a localized tagInfo and
///    falls into its dynamic-tag `else` branch (`PNG.pm:1116-1124`) — a
///    `Binary => 1` `RawProfileType<X>` tag carrying the raw value bytes, with
///    NO `ProcessProfile` and NO `$$et{PROCESSED}` reset (oracle-confirmed: a
///    language-tagged raw-profile-exif between two `eXIf` chunks does NOT
///    un-block the second).
/// 3. **An UNREGISTERED `Raw profile type *` keyword** (any language) → the same
///    dynamic-tag `else` branch → `push_dynamic_profile`.
/// 4. **Any other keyword** → the ordinary `iTXt` text record.
fn route_itxt_raw_profile_or_text(
  meta: &mut PngMeta<'_>,
  keyword: &str,
  value: String,
  language: SmolStr,
  translated: SmolStr,
) {
  if let Some(kind) = raw_profile_kind(keyword) {
    // Registered SubDirectory. Empty language → `ProcessProfile` (decode +
    // reset). Non-empty language → `GetLangInfo` undef → dynamic binary tag.
    if language.is_empty() {
      handle_raw_profile(meta, kind, value.as_bytes());
    } else {
      push_dynamic_profile(meta, keyword, value.into_bytes());
    }
    return;
  }
  // Unregistered `Raw profile type *` keyword → dynamic binary tag (any lang).
  if keyword.starts_with(RAW_PROFILE_PREFIX) {
    push_dynamic_profile(meta, keyword, value.into_bytes());
    return;
  }
  meta.push_text_record(PngTextRecord::new_itxt(
    SmolStr::new(keyword),
    value,
    language,
    translated,
    false,
  ));
}

// ===========================================================================
// eXIf decoder — PNG.pm:309-317 + :1358-1404
// ===========================================================================

/// `eXIf` decoder (`PNG.pm:1358-1404 ProcessPNG_eXIf`).
///
/// `PNG.pm:1368-1373`: tolerate the legacy `Exif\0\0` 6-byte prefix some
/// writers inserted (bundled emits a warning and strips it). After that,
/// `PNG.pm:1374-1384`:
/// ```text
/// if ($$dataPt =~ /^(\0|II|MM)/) { $type = $1; }
/// else { $et->Warn("Invalid $tag chunk"); return 0; }
/// ```
/// The `\0` arm is for compressed EXIF (`zXIf`, never widely adopted); the
/// `II` / `MM` arms are a normal TIFF. For the normal case we capture the
/// (possibly stripped) bytes as a [`PngExifEvent::NativeTiff`] event (no
/// PROCESSED reset) in walk order; the IFD chain is decoded at serialize time
/// by [`crate::exif::parse_exif_block`].
///
/// For the `\0` (zXIf) arm, `PNG.pm:1378-1381`:
/// ```text
/// if ($type eq "\0") {            # is this compressed EXIF?
///     my $buf = substr($$dataPt, 5);
///     return FoundPNG($et, ..., $$tagInfo{TagID}, \$buf, 2, $outBuff);
/// }
/// ```
/// i.e. skip the `\0` type byte + a 4-byte (unused, uncompressed-length)
/// field, INFLATE the remaining deflate stream (compression code `2` =
/// Inflate/Deflate, no method byte), and feed the inflated TIFF block to the
/// SAME `ProcessTIFF` path. We inflate via [`inflate_chunk`] (method `0`) and
/// capture the inflated block exactly like the uncompressed `eXIf` (re-applying
/// the `Exif\0\0`-strip + `II`/`MM` validation, since bundled re-enters
/// `ProcessPNG_eXIf` on the inflated buffer); a corrupt stream warns
/// `Error inflating $tag` (`PNG.pm:943`).
fn decode_exif(meta: &mut PngMeta<'_>, chunk: &[u8; 4], data: &[u8]) {
  // `$tag = $$tagInfo{TagID}` (`PNG.pm:1364`) — the (case-normalized) chunk
  // type, interpolated into the `Invalid $tag chunk` (`PNG.pm:1382`) and
  // `Error inflating $tag` (`PNG.pm:943`) warnings. `chunk` is `eXIf`/`zxIf`.
  let tag = core::str::from_utf8(chunk).unwrap_or("eXIf");
  // `PNG.pm:1368-1373`: improper `Exif\0\0` prefix.
  let block: &[u8] = if data.starts_with(b"Exif\0\0") {
    meta.push_warning(String::from("Improper \"Exif00\" header in EXIF chunk"));
    &data[6..]
  } else {
    data
  };
  // `PNG.pm:1374-1384`: validate the TIFF header byte-order marker. We
  // don't validate the magic ourselves — the Exif walker
  // (`parse_exif_block`) does, returning `None` on a bad block. But the
  // BUNDLED warning fires from inside `ProcessPNG_eXIf` before
  // `ProcessTIFF` runs, so we emit it here too.
  if block.is_empty() {
    meta.push_warning(format!("Invalid {tag} chunk"));
    return;
  }
  let first = block[0];
  if first != 0 && !block.starts_with(b"II") && !block.starts_with(b"MM") {
    meta.push_warning(format!("Invalid {tag} chunk"));
    return;
  }
  if first == 0 {
    // `PNG.pm:1378-1381`: zXIf compressed EXIF. Skip the `\0` type byte + a
    // 4-byte (unused) field — `substr($$dataPt, 5)` — and inflate the rest as
    // a deflate stream (compression code 2, no method byte to validate).
    let payload = match block.get(5..) {
      Some(p) => p,
      // A `\0`-typed block shorter than 5 bytes has no compressed payload;
      // bundled's `substr($$dataPt, 5)` would be empty and inflate fails.
      None => {
        meta.push_warning(format!("Error inflating {tag}"));
        return;
      }
    };
    match inflate_chunk(0, payload) {
      Inflate::Ok(tiff) => {
        // Bundled re-enters `ProcessPNG_eXIf` on the INFLATED buffer via
        // `FoundPNG(..., level 2)` (`PNG.pm:1389`), keeping the same `$tag`, so
        // apply the SAME `Exif\0\0`-strip + `II`/`MM` validation as the
        // uncompressed path: an inflated `Exif00`-prefixed block is stripped
        // (+warned) then decoded; a non-`II`/`MM` inflated block is
        // `Invalid $tag chunk`. Then capture as a native event (no PROCESSED
        // reset, `PNG.pm:1358`).
        let inner: &[u8] = if tiff.starts_with(b"Exif\0\0") {
          meta.push_warning(String::from("Improper \"Exif00\" header in EXIF chunk"));
          &tiff[6..]
        } else {
          &tiff
        };
        if inner.is_empty() || (!inner.starts_with(b"II") && !inner.starts_with(b"MM")) {
          meta.push_warning(format!("Invalid {tag} chunk"));
        } else {
          meta.push_exif_event(PngExifEvent::NativeTiff(inner.to_vec()));
        }
      }
      // `PNG.pm:943`: corrupt zlib ⇒ `Error inflating $tag`.
      // (`UnknownMethod` is unreachable here — method is hard-coded 0.)
      Inflate::Error | Inflate::UnknownMethod(_) => {
        meta.push_warning(format!("Error inflating {tag}"));
      }
    }
    return;
  }
  // Capture the block as a native event in walk order; the replay runs the Exif
  // walker over the shared `$$et{PROCESSED}` set with NO reset (`PNG.pm:1358`).
  meta.push_exif_event(PngExifEvent::NativeTiff(block.to_vec()));
}

// ===========================================================================
// bKGD decoder — PNG.pm:128-131
// ===========================================================================

/// `bKGD` decoder (`PNG.pm:128-131`).
///
/// `ValueConv => 'join(" ",unpack(length($val) < 2 ? "C" : "n*", $val))'`:
/// 1 byte ⇒ a single int8u; ≥ 2 bytes ⇒ space-separated int16u BE values.
fn decode_bkgd(meta: &mut PngMeta<'_>, data: &[u8]) {
  if data.is_empty() {
    return;
  }
  let value = if data.len() < 2 {
    // Single int8u (palette index).
    std::format!("{}", data[0])
  } else {
    // Series of int16u BE values.
    let mut s = String::new();
    let mut first = true;
    let mut i = 0;
    while i + 2 <= data.len() {
      let v = u16::from_be_bytes([data[i], data[i + 1]]);
      if !first {
        s.push(' ');
      }
      s.push_str(&std::format!("{v}"));
      first = false;
      i += 2;
    }
    s
  };
  meta.set_background_color(value);
}

// ===========================================================================
// tIME decoder — PNG.pm:262-275
// ===========================================================================

/// `tIME` decoder (`PNG.pm:262-275`).
///
/// `ValueConv => 'sprintf("%.4d:%.2d:%.2d %.2d:%.2d:%.2d", unpack("nC5",
/// $val))'`. The payload is `year:u16 BE, month:u8, day:u8, hour:u8,
/// minute:u8, second:u8` — 7 bytes.
fn decode_time(meta: &mut PngMeta<'_>, data: &[u8]) {
  if data.len() < 7 {
    return;
  }
  let year = u16::from_be_bytes([data[0], data[1]]);
  let s = std::format!(
    "{:04}:{:02}:{:02} {:02}:{:02}:{:02}",
    year,
    data[2],
    data[3],
    data[4],
    data[5],
    data[6],
  );
  meta.set_modify_date(s);
}

// ===========================================================================
// Latin-1 → UTF-8 decoder
// ===========================================================================

/// Decode Latin-1 (ISO-8859-1) bytes to UTF-8.
///
/// Each byte 0x00-0xFF maps directly to its Unicode codepoint U+0000-U+00FF
/// (Latin-1 is a 1-to-1 mapping). Bundled's `enc => 'Latin'` (`PNG.pm:1331`)
/// uses Perl's `Encode::Latin1` which has the same semantics.
fn decode_latin1(bytes: &[u8]) -> String {
  let mut s = String::with_capacity(bytes.len());
  for &b in bytes {
    s.push(b as char);
  }
  s
}

// ===========================================================================
// `Taggable` — the golden-pattern emission path
// ===========================================================================

/// family-0 == family-1 == `"PNG"` for the `%Image::ExifTool::PNG::Main`
/// table (`PNG.pm:99` `GROUPS => { 2 => 'Image' }`; group0/group1 default to
/// the module name `PNG`). Used as both groups for every Main-table tag.
const GROUP_PNG: &str = "PNG";

/// family-1 `"PNG-pHYs"` for the pHYs sub-table (`PNG.pm:446`
/// `GROUPS => { 1 => 'PNG-pHYs', 2 => 'Image' }`); family-0 stays `"PNG"`
/// (only group1 is overridden, not group0).
const GROUP_PNG_PHYS: &str = "PNG-pHYs";

/// The family-1 group override bundled applies to every tag extracted from a
/// post-`IEND` TRAILER chunk (`PNG.pm:1484` `$$et{SET_GROUP1} = 'Trailer'`).
const GROUP_TRAILER: &str = "Trailer";

/// Apply bundled's TRAILER family-1 override (`$$et{SET_GROUP1} = 'Trailer'`,
/// `PNG.pm:1484`) to one emitted tag's [`Group`](crate::value::Group), faithful
/// to how `GetGroup` (`ExifTool.pm:3860`) resolves the live global.
///
/// The override replaces the family-1 group with `"Trailer"` UNLESS the tag
/// already carries an EXPLICIT family-1 group set by the `Exif::Main` table's
/// `SET_GROUP1 => 1` mechanism (`Exif.pm:416` → `SetGroup`, `Exif.pm:7183`,
/// which records `TAG_EXTRA{G1}` and so wins over the global at
/// `ExifTool.pm:3860`). Those explicit groups are exactly the `Exif::Main`-table
/// IFD names — `IFD0`, the trailing `IFD<n>`, `ExifIFD`, `InteropIFD`
/// (`Exif.pm:412`/`:487`/`:2008`/`:2722`, all sharing `Exif::Main`). Every OTHER
/// family-1 group — PNG-level (`PNG`/`PNG-pHYs`), the `File:ExifByteOrder` tag
/// (family-1 `File`), the GPS sub-IFD (its `GPS::Main` table has NO
/// `SET_GROUP1`, so its family-1 is a table default that the global overrides),
/// and MakerNotes vendor groups — shifts to `Trailer` (oracle-verified against
/// `perl exiftool -j -G1` 13.59: `Trailer:ExifByteOrder`, `Trailer:GPSLatitudeRef`,
/// but `IFD0:Make` / `ExifIFD:DateTimeOriginal` / `IFD1:Artist` UNCHANGED).
/// family-0 is never touched (`PNG.pm` overrides only group1).
#[cfg(feature = "alloc")]
fn apply_trailer_group(g: crate::value::Group) -> crate::value::Group {
  if is_exif_main_ifd_group(g.family1()) {
    g
  } else {
    crate::value::Group::new(g.family0(), GROUP_TRAILER)
  }
}

/// `true` if `family1` is an `Exif::Main`-table IFD family-1 group name —
/// `IFD0`, a trailing `IFD<n>` (all digits after `IFD`), `ExifIFD`, or
/// `InteropIFD`. These IFDs share `Image::ExifTool::Exif::Main`, whose
/// `SET_GROUP1 => 1` (`Exif.pm:416`) records an EXPLICIT family-1 group that
/// wins over the trailer's `SET_GROUP1` global; the GPS sub-IFD (`GPS::Main`,
/// no `SET_GROUP1`) and every non-EXIF group do NOT match and so shift to
/// `Trailer`.
#[cfg(feature = "alloc")]
fn is_exif_main_ifd_group(family1: &str) -> bool {
  match family1 {
    "ExifIFD" | "InteropIFD" => true,
    // "IFD0", "IFD1", "IFD2", … "IFD4294967295" — the literal `IFD` prefix
    // followed by ≥1 decimal digits (the trailing-IFD numbering, `Exif.pm:7215`).
    s => s
      .strip_prefix("IFD")
      .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())),
  }
}

#[cfg(feature = "alloc")]
impl crate::emit::Taggable for PngMeta<'_> {
  /// Yield PNG tags in faithful `PNG.pm` chunk-table emission order — the
  /// golden-pattern parallel to the retired inherent `serialize_tags`.
  ///
  /// Emission order (unchanged from the retired sink): IHDR sub-table
  /// (ImageWidth / ImageHeight / BitDepth / ColorType / Compression / Filter /
  /// Interlace, `PNG.pm:387-423` offset order), then bKGD `BackgroundColor`
  /// (`PNG.pm:128-131`), then the pHYs sub-table (PixelsPerUnitX /
  /// PixelsPerUnitY / PixelUnits, `PNG.pm:441-468`), then tIME `ModifyDate`
  /// (`PNG.pm:262-275`), then iCCP `ProfileName` (`PNG.pm:182-190`), then the
  /// text records (tEXt / zTXt / iTXt) in chunk-walk order, then — LAST — the
  /// chained eXIf Exif sub-Meta's tags (IFD0 / ExifIFD / GPS / …,
  /// `PNG.pm:309-317`).
  ///
  /// The SINK changes (an [`EmittedTag`](crate::emit::EmittedTag) per value
  /// instead of `out.write_u64`/`out.write_str`); the value variants
  /// ([`TagValue::U64`](crate::value::TagValue::U64) for the int8u/int32u
  /// scalars, exactly what the retired `out.write_u64` produced;
  /// [`TagValue::Str`](crate::value::TagValue::Str) for the PrintConv labels /
  /// text values), the emission ORDER, the eXIf-chain position, and every
  /// PrintConv-vs-ValueConv branch are preserved verbatim. Every PNG tag is a
  /// known tag ⇒ `unknown: false` (the engine's `Unknown` gate is a no-op for
  /// PNG).
  ///
  /// `mode == PrintConv` (`-j`) ⇒ PrintConv strings (ColorType →
  /// `"Grayscale"`, Compression → `"Deflate/Inflate"`, …); `mode ==
  /// ValueConv` (`-n`) ⇒ the post-ValueConv raw scalars (the bare u8/u32).
  ///
  /// **Warnings are NOT part of this tag stream**
  /// ([`run_emission`](crate::emit::run_emission) has no warning channel). The
  /// PNG walker's accumulated warnings (`Truncated PNG image`, `Text/EXIF
  /// chunk(s) found after PNG IDAT …`, the zlib `Error inflating <chunk>` /
  /// `Unknown compression method <n> for <chunk>` warnings, …) are drained by
  /// the `AnyMeta::Png` dispatch arm AFTER `run_emission`, in the same order
  /// the retired `serialize_tags` emitted them.
  fn tags(
    &self,
    mode: crate::emit::ConvMode,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    use crate::emit::EmittedTag;
    use crate::value::{Group, TagValue};

    let print_conv = matches!(mode, crate::emit::ConvMode::PrintConv);
    // family-0 == family-1 == "PNG" (Main table); the pHYs sub-table keeps
    // family-0 "PNG" but family-1 "PNG-pHYs" (PNG.pm:446). When the chunk that
    // produced the tag is a post-`IEND` TRAILER chunk, the family-1 group
    // shifts to `Trailer` (`PNG.pm:1484`); `trailing == false` ⇒ the standard
    // (IEND-last) group, byte-identical to before this trailer support.
    let png_group = |trailing: bool| {
      if trailing {
        Group::new(GROUP_PNG, GROUP_TRAILER)
      } else {
        Group::new(GROUP_PNG, GROUP_PNG)
      }
    };
    let phys_group = |trailing: bool| {
      if trailing {
        Group::new(GROUP_PNG, GROUP_TRAILER)
      } else {
        Group::new(GROUP_PNG, GROUP_PNG_PHYS)
      }
    };
    // Per-structural-chunk trailing flags (cheap; computed once).
    let ihdr_t = self.ihdr_is_trailing();
    let bkgd_t = self.bkgd_is_trailing();
    let phys_t = self.phys_is_trailing();
    let time_t = self.time_is_trailing();
    let iccp_t = self.iccp_is_trailing();

    let mut tags: Vec<EmittedTag> = Vec::new();

    // ---- IHDR sub-table (PNG.pm:387-423) -----------------------------
    // Bundled `ProcessBinaryData` emits in offset order:
    // ImageWidth, ImageHeight, BitDepth, ColorType, Compression, Filter,
    // Interlace.
    if let Some(w) = self.width() {
      tags.push(EmittedTag::new(
        png_group(ihdr_t),
        "ImageWidth".into(),
        TagValue::U64(u64::from(w)),
        false,
      ));
    }
    if let Some(h) = self.height() {
      tags.push(EmittedTag::new(
        png_group(ihdr_t),
        "ImageHeight".into(),
        TagValue::U64(u64::from(h)),
        false,
      ));
    }
    if let Some(d) = self.bit_depth() {
      tags.push(EmittedTag::new(
        png_group(ihdr_t),
        "BitDepth".into(),
        TagValue::U64(u64::from(d)),
        false,
      ));
    }
    if let Some(ct) = self.color_type() {
      // PNG.pm:400-410. Unknown color-types (`PngColorType::Other`) fall
      // through to the raw u8 value (bundled's PrintConv-miss renders the
      // raw number); -n always emits the raw byte.
      if print_conv && let Some(label) = ct.print_conv() {
        tags.push(EmittedTag::new(
          png_group(ihdr_t),
          "ColorType".into(),
          TagValue::Str(label.into()),
          false,
        ));
      } else {
        tags.push(EmittedTag::new(
          png_group(ihdr_t),
          "ColorType".into(),
          TagValue::U64(u64::from(ct.as_byte())),
          false,
        ));
      }
    }
    if let Some(c) = self.compression() {
      if print_conv && c == 0 {
        tags.push(EmittedTag::new(
          png_group(ihdr_t),
          "Compression".into(),
          TagValue::Str("Deflate/Inflate".into()),
          false,
        ));
      } else {
        tags.push(EmittedTag::new(
          png_group(ihdr_t),
          "Compression".into(),
          TagValue::U64(u64::from(c)),
          false,
        ));
      }
    }
    if let Some(f) = self.filter() {
      if print_conv && f == 0 {
        tags.push(EmittedTag::new(
          png_group(ihdr_t),
          "Filter".into(),
          TagValue::Str("Adaptive".into()),
          false,
        ));
      } else {
        tags.push(EmittedTag::new(
          png_group(ihdr_t),
          "Filter".into(),
          TagValue::U64(u64::from(f)),
          false,
        ));
      }
    }
    if let Some(i) = self.interlace() {
      // PNG.pm:419-422.
      let label = if print_conv {
        match i {
          0 => Some("Noninterlaced"),
          1 => Some("Adam7 Interlace"),
          _ => None,
        }
      } else {
        None
      };
      if let Some(s) = label {
        tags.push(EmittedTag::new(
          png_group(ihdr_t),
          "Interlace".into(),
          TagValue::Str(s.into()),
          false,
        ));
      } else {
        tags.push(EmittedTag::new(
          png_group(ihdr_t),
          "Interlace".into(),
          TagValue::U64(u64::from(i)),
          false,
        ));
      }
    }

    // ---- bKGD (PNG.pm:128-131) -------------------------------------
    if let Some(bg) = self.background_color() {
      // ValueConv is the string; PrintConv is identity. A single-int8u value
      // renders as the bare number `0`; multi-int16u values stay a string.
      // We coerce a parseable single u64 to `TagValue::U64` so the JSON path
      // emits a bare number (matching bundled's number-of-one emission) —
      // identical to the retired `out.write_u64`/`out.write_str` split.
      if let Ok(n) = bg.parse::<u64>() {
        tags.push(EmittedTag::new(
          png_group(bkgd_t),
          "BackgroundColor".into(),
          TagValue::U64(n),
          false,
        ));
      } else {
        tags.push(EmittedTag::new(
          png_group(bkgd_t),
          "BackgroundColor".into(),
          TagValue::Str(bg.into()),
          false,
        ));
      }
    }

    // ---- pHYs (PNG.pm:441-468) -------------------------------------
    // PROCESS_PROC is `ProcessBinaryData` with sub-table key 'PNG-pHYs'
    // (`GROUPS => { 1 => 'PNG-pHYs' }`, `PNG.pm:446`).
    if let Some(x) = self.pixels_per_unit_x() {
      tags.push(EmittedTag::new(
        phys_group(phys_t),
        "PixelsPerUnitX".into(),
        TagValue::U64(u64::from(x)),
        false,
      ));
    }
    if let Some(y) = self.pixels_per_unit_y() {
      tags.push(EmittedTag::new(
        phys_group(phys_t),
        "PixelsPerUnitY".into(),
        TagValue::U64(u64::from(y)),
        false,
      ));
    }
    if let Some(u) = self.pixel_units() {
      let label = if print_conv {
        match u {
          0 => Some("Unknown"),
          1 => Some("meters"),
          _ => None,
        }
      } else {
        None
      };
      if let Some(s) = label {
        tags.push(EmittedTag::new(
          phys_group(phys_t),
          "PixelUnits".into(),
          TagValue::Str(s.into()),
          false,
        ));
      } else {
        tags.push(EmittedTag::new(
          phys_group(phys_t),
          "PixelUnits".into(),
          TagValue::U64(u64::from(u)),
          false,
        ));
      }
    }

    // ---- tIME (PNG.pm:262-275) -------------------------------------
    if let Some(d) = self.modify_date() {
      tags.push(EmittedTag::new(
        png_group(time_t),
        "ModifyDate".into(),
        TagValue::Str(d.into()),
        false,
      ));
    }

    // ---- iCCP-name (PNG.pm:182-190 + 1304) ----------------------------
    if let Some(name) = self.icc_profile_name() {
      tags.push(EmittedTag::new(
        png_group(iccp_t),
        "ProfileName".into(),
        TagValue::Str(name.into()),
        false,
      ));
    }

    // ---- Text records (tEXt / zTXt / iTXt) ----------------------------
    // Bundled `FoundPNG` resolves the keyword against `%PNG::TextualData`
    // (PNG.pm:592-763). Each `(keyword, value)` pair becomes a tag named
    // by the keyword (with first-letter-uppercased fallback,
    // `PNG.pm:919-921`). Unknown keywords are emitted verbatim (bundled
    // creates a dynamic tag, see PNG.pm:600-601 NOTES). For `iTXt` the
    // resolved tag has the `-<lang>` suffix when language is present
    // (PNG.pm:916-918). XMP-formatted iTXt (`XML:com.adobe.xmp` keyword)
    // dispatches to the XMP processor — DEFERRED (no XMP port).
    for (ti, r) in self.text_records().iter().enumerate() {
      // Post-`IEND` TRAILER text records carry the `Trailer` family-1 override.
      let r_trailing = self.text_record_is_trailing(ti);
      // XMP arm: keyword `XML:com.adobe.xmp` is a known iTXt SubDirectory
      // that bundles to the XMP parser. We have no XMP port (deferred,
      // Phase-3+); the XMP table values are not emitted. The chunk
      // itself is still recognized.
      if r.keyword() == "XML:com.adobe.xmp" {
        continue;
      }
      // Compressed records: keyword preserved, value empty — the
      // warning fired during the chunk walk. Skip emission.
      if r.is_compressed() {
        continue;
      }
      // Resolve the tag name: bundled's PNG.pm:919-921 looks up the
      // keyword, then `ucfirst()` falls back. Most well-known keywords
      // ARE already capitalised (`Title`, `Author`, …) so the upper-
      // case-first behaviour is a no-op for them. We emit the keyword
      // verbatim — matching bundled for the unregistered-keyword case
      // (PNG.pm:600-601 dynamic-tag NOTES); for the registered ones the
      // value matches (the table entry's `Name` is the keyword unmodified
      // for every PNG.pm:626-679 row except "Creation Time" → "CreationTime"
      // — which we map below).
      let name = png_text_tag_name(r.keyword());
      // ValueConv on the resolved tag — three date tags have one in the read
      // path we port; every other textual tag emits its value verbatim:
      //  - `CreationTime` (`'Creation Time' => { RawConv => \&ConvertPNGDate }`,
      //    PNG.pm:630-639) converts the RFC-1123 string to EXIF format
      //    (`Mon, 1 Jan 2018 12:10:22 EST` → `2018:01:01 12:10:22-05:00`).
      //  - `CreateDate`/`ModDate` (the ImageMagick `create-date`/`modify-date`
      //    rows, PNG.pm:658-677) convert via `XMP::ConvertXMPDate`
      //    (`2024-01-15T10:30:00+00:00` → `2024:01:15 10:30:00+00:00`).
      // In all three the `PrintConv` (`$self->ConvertDateTime($val)`) is an
      // identity for the default date format once the value is EXIF-formatted,
      // so `-j` and `-n` coincide (oracle-verified) — apply in BOTH modes.
      let value: String = match name.as_str() {
        "CreationTime" => convert_png_date(r.value()),
        "CreateDate" | "ModDate" => convert_xmp_date(r.value()),
        _ => String::from(r.value()),
      };
      // Suffix with `-<lang>` for non-empty iTXt language tags. Bundled
      // `FoundPNG` (PNG.pm:914-918) builds the tag ID as `$tag . '-' .
      // StandardLangCase($lang)` — the language subtag is normalized
      // (primary subtag lower-cased, a 2-letter region subtag upper-cased),
      // NOT blanket-lower-cased. `standard_lang_case` (PNG.pm:796-802).
      if let Some(lang) = r.language()
        && !lang.is_empty()
      {
        let lang_norm = standard_lang_case(lang);
        let qualified = std::format!("{name}-{lang_norm}");
        tags.push(EmittedTag::new(
          png_group(r_trailing),
          qualified.into(),
          TagValue::Str(value.into()),
          false,
        ));
        continue;
      }
      tags.push(EmittedTag::new(
        png_group(r_trailing),
        name.into(),
        TagValue::Str(value.into()),
        false,
      ));
    }

    // ---- Dynamically-added profile tags (PNG.pm:1116-1124) ------------
    // Tags `FoundPNG` created in its dynamic-tag `else` branch: a registered
    // raw-profile keyword in a language-tagged `iTXt` (`GetLangInfo` → undef,
    // `PNG.pm:895`), or any unregistered `Raw profile type *` keyword. Bundled
    // sets `$$tagInfo{Binary} = 1 if $tag =~ /^Raw profile type /`
    // (`PNG.pm:1122`); a binary tag's value renders as the universal
    // `(Binary data N bytes, use -b option to extract)` placeholder
    // ([`TagValue::Bytes`]) at ANY size — oracle-confirmed, NO size threshold.
    // A non-binary dynamic tag (a keyword whose original form does not match the
    // regex) emits its decoded value as plain text. All carry the same `PNG`
    // family-1 group as the text records; NONE participate in the EXIF event
    // stream below (they never reached `ProcessProfile`).
    for (di, d) in self.dynamic_profile_tags().iter().enumerate() {
      // Post-`IEND` TRAILER dynamic tags carry the `Trailer` family-1 override.
      let d_trailing = self.dynamic_tag_is_trailing(di);
      let value = if d.is_binary() {
        TagValue::Bytes(d.value().to_vec())
      } else {
        // Decoded value as UTF-8 text (the bytes are the post-`Decode` `$val`).
        TagValue::Str(SmolStr::new(crate::convert::fix_utf8(d.value())))
      };
      tags.push(EmittedTag::new(
        png_group(d_trailing),
        d.name().into(),
        value,
        false,
      ));
    }

    // ---- eXIf / Raw-profile EXIF — chain the Exif sub-Meta's tag stream ----
    // The TIFF block carries its own IFD0/ExifIFD/GPS chain. We replay the whole
    // ordered EXIF event stream through the SHARED-`$$et{PROCESSED}` model
    // ([`replay_exif_events`]) and splice each parsed `ExifMeta`'s `Taggable`
    // stream into PNG's at this position — exactly as bundled's `ProcessPNG_eXIf`
    // / `ProcessProfile` → `ProcessTIFF` dispatches each IFD's tags under its
    // family-1 group (IFD0/ExifIFD/GPS/…) AFTER the PNG-level tags. `ExifMeta` is
    // `Taggable`, so its tags flow through the same engine.
    //
    // CHUNK-ORDER replay (`ExifTool.pm:9061-9072` object-level cycle-guard +
    // `PNG.pm:1193` `ProcessProfile` reset) — see [`replay_exif_events`], which
    // returns one [`EventReplay`] per event IN ORDER (so the enumerate index
    // keys [`event_is_trailing`](PngMeta::event_is_trailing)). A BLOCKED event
    // yields an `ExifMeta` with no entries (and the cycle-guard warning, drained
    // separately); a reset-only profile yields no `meta` at all. We emit the
    // parsed events IN ORDER; the engine's last-wins `TagMap` dedup then keeps
    // every unique tag while letting a later event overwrite an earlier one on
    // overlap (= bundled's per-tag IFD0 merge). (Each parsed `ExifMeta` borrows
    // `&self` only for its `extend` — its owned `EmittedTag`s outlive it.)
    //
    // TRAILER (post-`IEND`) EXIF events: bundled's `SET_GROUP1 = 'Trailer'`
    // (`PNG.pm:1484`) shifts the family-1 group of the PNG-level `ExifByteOrder`
    // tag (`File` → `Trailer`) and the GPS sub-IFD (`GPS` → `Trailer`) while the
    // `Exif::Main`-table IFDs (`IFD0`/`ExifIFD`/`IFD<n>`/`InteropIFD`) keep their
    // explicit group ([`apply_trailer_group`]). A non-trailing event's tags are
    // emitted UNCHANGED (the standard byte-identical path).
    #[cfg(feature = "exif")]
    for (ei, replay) in replay_exif_events(self.exif_events())
      .into_iter()
      .enumerate()
    {
      if let Some(exif_meta) = replay.meta() {
        if self.event_is_trailing(ei) {
          for e in exif_meta.tags(mode) {
            let unknown = e.unknown();
            let tag = e.into_tag();
            tags.push(EmittedTag::new(
              apply_trailer_group(tag.group_ref().clone()),
              tag.name().into(),
              tag.value_ref().clone(),
              unknown,
            ));
          }
        } else {
          tags.extend(exif_meta.tags(mode));
        }
      }
    }

    tags.into_iter()
  }
}

#[cfg(feature = "alloc")]
impl crate::diagnostics::Diagnose for PngMeta<'_> {
  /// PNG's diagnostics in the retired drain order:
  /// (a) the PNG walker's own accumulated warnings (`Truncated PNG image`
  ///     PNG.pm:1486, `Text/EXIF chunk(s) found after …` PNG.pm:1598, the zlib
  ///     inflate-error warnings, the `Invalid eXIf chunk` / `Improper "Exif00"
  ///     header …` warnings, …) BEFORE the eXIf dispatch;
  /// (b) the embedded eXIf / Raw-profile EXIF sub-Metas' diagnostics, IN CHUNK
  ///     ORDER via the SAME shared-`$$et{PROCESSED}` event replay `tags()` /
  ///     `project()` use ([`replay_exif_events`], `ExifTool.pm:9061-9072` +
  ///     `PNG.pm:1193`). For each EXIF event: its own EXIF warnings (via the
  ///     parsed [`ExifMeta`](crate::exif::ExifMeta)'s `Diagnose` impl), then the
  ///     cross-source cycle-guard warning(s) the walk raised
  ///     (`ExifTool.pm:9068`).
  /// The PNG-level warnings always precede the EXIF ones (PNG walks first), so
  /// the document-level `first_warning` is unchanged. Byte-identical net
  /// `TagMap`.
  fn diagnostics(&self) -> std::vec::Vec<crate::diagnostics::Diagnostic> {
    let mut out = std::vec::Vec::new();
    out.extend(
      self
        .warnings()
        .iter()
        .map(crate::diagnostics::Diagnostic::warn),
    );
    #[cfg(feature = "exif")]
    for replay in replay_exif_events(self.exif_events()) {
      if let Some(exif_meta) = replay.meta() {
        out.extend(crate::diagnostics::Diagnose::diagnostics(exif_meta));
      }
      out.extend(
        replay
          .cycle_guard_warnings()
          .iter()
          .map(|w| crate::diagnostics::Diagnostic::warn(w.as_str())),
      );
    }
    out
  }
}

/// The result of replaying ONE [`PngExifEvent`] through the shared
/// `$$et{PROCESSED}` model ([`replay_exif_events`]): the parsed
/// [`crate::exif::ExifMeta`] (whatever directories were NOT blocked by the
/// cross-source cycle-guard) plus the cross-source cycle-guard warnings the
/// event raised.
///
/// - A [`PngExifEvent::ResetOnlyProfile`] only clears the shared set; it carries
///   no EXIF block, so [`meta`](Self::meta) is `None` and
///   [`cycle_guard_warnings`](Self::cycle_guard_warnings) is empty — it
///   contributes no tags and no warnings, only the reset (which un-blocks a
///   later same-`$addr` directory).
/// - A [`PngExifEvent::NativeTiff`] / [`PngExifEvent::ExifProfile`] whose IFD0
///   `$addr` was already claimed (by an earlier event's IFD0 OR a trailing IFD)
///   is BLOCKED: its IFD0 directory is skipped, so `meta` carries no tags and
///   `cycle_guard_warnings` holds the
///   `"IFD0 pointer references previous <prev> directory"` warning.
/// - A processed EXIF event's `meta` carries its tags (and its own `$et->Warn`
///   corpus, surfaced via [`crate::exif::ExifMeta::warnings`]) and
///   `cycle_guard_warnings` is empty.
///
/// [`meta`](Self::meta) is `None` for a reset-only event AND for an EXIF block
/// that is not a valid TIFF header (same gate as
/// [`crate::exif::parse_exif_block`]).
#[cfg(feature = "exif")]
pub(crate) struct EventReplay<'a> {
  meta: Option<crate::exif::ExifMeta<'a>>,
  cycle_guard_warnings: Vec<SmolStr>,
}

#[cfg(feature = "exif")]
impl<'a> EventReplay<'a> {
  /// The parsed EXIF block (`None` for a reset-only event, a non-TIFF block, or
  /// `Some` with empty entries for a fully-blocked EXIF event).
  #[inline]
  pub(crate) fn meta(&self) -> Option<&crate::exif::ExifMeta<'a>> {
    self.meta.as_ref()
  }

  /// The cross-source cycle-guard warnings this event raised (empty unless its
  /// IFD0 collided with an already-processed directory).
  #[inline]
  pub(crate) fn cycle_guard_warnings(&self) -> &[SmolStr] {
    &self.cycle_guard_warnings
  }
}

/// Replay bundled's OBJECT-LEVEL `ProcessTIFF` / `ProcessProfile` sequence over
/// the PNG's ordered [`PngExifEvent`] stream, threading ONE shared
/// `$$et{PROCESSED}` set. This is the single shared decision used by tag
/// emission ([`ProcessPng`]'s `tags()`), the domain projection
/// ([`crate::metadata::Project`] for [`PngMeta`]), and the warning drain
/// ([`PngMeta::diagnostics`](crate::diagnostics::Diagnose::diagnostics)), so all
/// three agree on exactly which directories win and which warn.
///
/// **The coherent event model (bundled's object-level sequence).** A PNG's
/// EXIF-bearing chunks form an ORDERED event stream (chunk/walk order). Bundled
/// replays them through ONE `$$et{PROCESSED}` (a `HashMap<addr, IfdName>`):
///
/// ```text
/// processed = {}
/// for ev in events (chunk order):
///     match ev:
///       ResetOnlyProfile  => processed.clear()                       // PNG.pm:1193 reset, no EXIF
///       ExifProfile(b)    => { processed.clear(); walk(b) }          // reset, then ProcessTIFF
///       NativeTiff(b)     => walk(b)                                 // ProcessTIFF (guard may skip/warn)
/// ```
///
/// `walk` = [`crate::exif::parse_exif_block_with_shared_processed`]: it records
/// each non-zero-`DirLen` chain directory's `$addr → $dirName`
/// (`ExifTool.pm:9071`) — IFD0 AND every trailing IFD (IFD1/IFD2/…) — into the
/// shared set, and re-entering an already-recorded `$addr` trips the cycle-guard
/// (warn `"<DirName> pointer references previous <prev> directory"` +
/// `return 0`, `ExifTool.pm:9067-9070`). The `DirLen=0` sub-IFDs
/// (ExifIFD/GPS/InteropIFD) intentionally SKIP the guard (`ExifTool.pm:9052`)
/// and are reprocessed across events — the EXIF walker already mirrors this.
/// The set is NOT reset between native events — ONLY a profile event resets it
/// (`PNG.pm:1193`), and it does so for EVERY well-formed profile (EXIF-bearing
/// or reset-only), which is why a `ResetOnlyProfile` between two same-`$addr`
/// `eXIf` chunks un-blocks the second (oracle-verified).
///
/// A malformed raw profile never reaches this stream (it produced no event), so
/// it neither resets nor processes — faithfully matching bundled, whose
/// `ProcessProfile` `return 0`s before the reset on a framing failure
/// (`PNG.pm:1166`). A malformed EXIF header likewise yields `meta = None` and
/// registers no `$addr` (bundled only guards a directory whose
/// `DirStart`/`DataPos` are defined, `ExifTool.pm:9062-9065`).
///
/// **INFEASIBLE (documented, not chased).** With 3+ EXIF events sharing one
/// `$addr` (or certain same-`$addr` orderings) bundled's emergent
/// C-buffer/offset arithmetic yields CONTROL-CHAR GARBAGE values (e.g.
/// `IFD0:Make = "\x1a"`) alongside the cycle-guard warning(s). That is behavior
/// BEYOND the documented cycle-guard (`ExifTool.pm:9066-9072`), which simply
/// warns + skips. This port reproduces the DOCUMENTED algorithm: clean values
/// for the processed events + one cycle-guard warning per blocked directory. We
/// deliberately do NOT reproduce the garbage bytes (see
/// `engine_three_same_offset_sources_clean_values_not_garbage`).
#[cfg(feature = "exif")]
pub(crate) fn replay_exif_events(events: &[PngExifEvent]) -> Vec<EventReplay<'_>> {
  // ExifTool's object-level `$$et{PROCESSED}` (ExifTool.pm:9066-9071): every
  // non-zero-`DirLen` chain directory's `$addr → $dirName`, shared across every
  // `ProcessTIFF` call in the file.
  let mut processed: std::collections::HashMap<usize, crate::exif::IfdName> =
    std::collections::HashMap::new();
  let mut out = Vec::with_capacity(events.len());
  for event in events {
    match event {
      // A well-formed non-EXIF profile: `ProcessProfile` resets
      // `$$et{PROCESSED}` (PNG.pm:1193) but emits no EXIF tags/warnings.
      PngExifEvent::ResetOnlyProfile => {
        processed.clear();
        out.push(EventReplay {
          meta: None,
          cycle_guard_warnings: Vec::new(),
        });
      }
      // EXIF raw profile: `ProcessProfile` resets FIRST (PNG.pm:1193), then
      // dispatches the TIFF to `ProcessTIFF`.
      PngExifEvent::ExifProfile(block) => {
        processed.clear();
        out.push(walk_shared(block, &mut processed));
      }
      // Native `eXIf`/`zxIf`: `ProcessTIFF` over the shared set, NO reset.
      PngExifEvent::NativeTiff(block) => {
        out.push(walk_shared(block, &mut processed));
      }
    }
  }
  out
}

/// Walk one EXIF block against the shared `$$et{PROCESSED}` map and wrap the
/// result as an [`EventReplay`]. Per-event TIFF blocks are already
/// `Exif\0\0`-stripped and start at the block (Base/DataPos/BASE all 0), so
/// `base = 0` — the IFD0 `$addr` reduces to the IFD0 pointer in the 8-byte
/// header, matching the recorded key.
#[cfg(feature = "exif")]
fn walk_shared<'a>(
  block: &'a [u8],
  processed: &mut std::collections::HashMap<usize, crate::exif::IfdName>,
) -> EventReplay<'a> {
  let (meta, cycle_guard_warnings) =
    crate::exif::parse_exif_block_with_shared_processed(block, 0, processed);
  EventReplay {
    meta,
    cycle_guard_warnings,
  }
}

/// Map a PNG text keyword to its bundled `%PNG::TextualData` Name (`PNG.pm:
/// 626-679`).
///
/// The non-identity mappings are `"Creation Time" → "CreationTime"`
/// (`PNG.pm:631`), `"Warning" → "PNGWarning"` (`PNG.pm:643`), `"create-date"
/// → "CreateDate"` (`PNG.pm:660`), `"modify-date" → "ModDate"`
/// (`PNG.pm:669`), `"aesthetic_score" → "AestheticScore"` (`PNG.pm:657`).
///
/// For every other keyword, bundled's `FoundPNG` (`PNG.pm:919-921`) consults
/// the table FIRST with the verbatim keyword, then with the first letter
/// uppercased as a fallback (`# some software forgets to capitalize first
/// letter`). The fallback only matters for keywords whose first letter is
/// ASCII lowercase AND whose ucfirst-form IS a registered table entry —
/// e.g. `comment` → `Comment` (registered at `PNG.pm:645`). For unknown
/// keywords bundled creates a dynamic tag with the LOOKUP key (which is
/// the original keyword); the emitted family-1 group name therefore retains
/// the original casing.
///
/// We faithfully apply the same heuristic: if the verbatim keyword is NOT
/// in the recognized set but the ucfirst-form IS, we emit the ucfirst-form.
/// Otherwise the keyword is emitted verbatim.
fn png_text_tag_name(keyword: &str) -> String {
  // Exact-match rewrites (PNG.pm registered keywords whose `Name` differs
  // from the keyword string).
  match keyword {
    "Creation Time" => return String::from("CreationTime"),
    "Warning" => return String::from("PNGWarning"),
    "create-date" => return String::from("CreateDate"),
    "modify-date" => return String::from("ModDate"),
    "aesthetic_score" => return String::from("AestheticScore"),
    _ => {}
  }
  // Identity-match against a registered table entry (PNG.pm:626-688).
  if is_registered_textual_keyword(keyword) {
    return String::from(keyword);
  }
  // Bundled's `ucfirst()` fallback (PNG.pm:919-921). Only apply when the
  // first letter is ASCII lowercase AND the ucfirst-form IS registered;
  // otherwise emit the original.
  if let Some(first) = keyword.chars().next()
    && first.is_ascii_lowercase()
  {
    let mut ucfirst = String::with_capacity(keyword.len());
    ucfirst.push(first.to_ascii_uppercase());
    ucfirst.push_str(&keyword[first.len_utf8()..]);
    if is_registered_textual_keyword(&ucfirst) {
      return ucfirst;
    }
  }
  String::from(keyword)
}

/// `%monthNum` (`PNG.pm:808-811`) — three-letter English month abbreviation
/// (matched case-insensitively, then `ucfirst lc` normalized) → 1-based month
/// number. `Jan` = 1 … `Dec` = 12.
fn month_num(mon: &str) -> Option<u32> {
  // Bundled keys this with `ucfirst lc $mon` (PNG.pm:839). The regex already
  // guarantees `mon` is one of the 12 abbreviations (in some case), so an
  // ASCII-lowercase compare of the whole 3-letter token is equivalent.
  Some(match mon.to_ascii_lowercase().as_str() {
    "jan" => 1,
    "feb" => 2,
    "mar" => 3,
    "apr" => 4,
    "may" => 5,
    "jun" => 6,
    "jul" => 7,
    "aug" => 8,
    "sep" => 9,
    "oct" => 10,
    "nov" => 11,
    "dec" => 12,
    _ => return None,
  })
}

/// `%tzConv` (`PNG.pm:812-830`) — RFC-1123 named-zone / military-letter time
/// zone → `±HH:MM` offset. Looked up by `uc $tz` (`PNG.pm:842`). Copied in
/// full, INCLUDING the military single-letter A-Z entries (J is intentionally
/// absent in RFC-822, matching bundled — `%tzConv` has no `J`). Returns the
/// canonical offset string, or `None` for an unrecognized alpha zone (bundled's
/// `else { last }` non-standard-date arm).
fn tz_conv(tz: &str) -> Option<&'static str> {
  Some(match tz.to_ascii_uppercase().as_str() {
    // (UTC not in spec -- PH addition)
    "UT" | "GMT" | "UTC" => "+00:00",
    "EST" => "-05:00",
    "EDT" => "-04:00",
    "CST" => "-06:00",
    "CDT" => "-05:00",
    "MST" => "-07:00",
    "MDT" => "-06:00",
    "PST" => "-08:00",
    "PDT" => "-07:00",
    "A" => "-01:00",
    "N" => "+01:00",
    "B" => "-02:00",
    "O" => "+02:00",
    "C" => "-03:00",
    "P" => "+03:00",
    "D" => "-04:00",
    "Q" => "+04:00",
    "E" => "-05:00",
    "R" => "+05:00",
    "F" => "-06:00",
    "S" => "+06:00",
    "G" => "-07:00",
    "T" => "+07:00",
    "H" => "-08:00",
    "U" => "+08:00",
    "I" => "-09:00",
    "V" => "+09:00",
    "K" => "-10:00",
    "W" => "+10:00",
    "L" => "-11:00",
    "X" => "+11:00",
    "M" => "-12:00",
    "Y" => "+12:00",
    "Z" => "+00:00",
    _ => return None,
  })
}

/// Convert a PNG (RFC-1123) date/time string to EXIF format — a faithful port
/// of `ConvertPNGDate` (`PNG.pm:832-855`), used as the `RawConv`/`ValueConv`
/// for the `CreationTime` tag (`PNG.pm:630-639`, `Creation Time` =>
/// `{ ValueConv => \&ConvertPNGDate }`).
///
/// Bundled's body:
///
/// ```text
/// while ($val =~ /(\d+)\s*(Jan|Feb|...|Dec)\s*(\d+)\s+(\d+):(\d{2})(:\d{2})?\s*(\S*)/i) {
///     my ($day,$mon,$yr,$hr,$min,$sec,$tz) = ($1,$2,$3,$4,$5,$6,$7);
///     $yr += $yr > 70 ? 1900 : 2000 if $yr < 100;   # boost 2-digit year
///     $mon = $monthNum{ucfirst lc $mon} or return $val;
///     if (not $tz)                       { $tz = '' }
///     elsif ($tzConv{uc $tz})            { $tz = $tzConv{uc $tz} }
///     elsif ($tz =~ /^([-+]\d+):?(\d{2})/) { $tz = $1 . ':' . $2 }
///     else                               { last }   # (non-standard date)
///     return sprintf("%.4d:%.2d:%.2d %.2d:%.2d%s%s",
///                    $yr,$mon,$day,$hr,$min,$sec||':00',$tz);
/// }
/// # (StrictDate/Validate warning omitted — those options are off in extract_info)
/// return $val;
/// ```
///
/// The standard input is e.g. `"Mon, 1 Jan 2018 12:10:22 EST"` (RFC-1123
/// §5.2.14); the output is `"2018:01:01 12:10:22-05:00"`. On NO regex match —
/// or a recognized regex match whose alpha time zone is unknown (the `last`
/// arm) — the value is returned VERBATIM. We do NOT emit the `Non standard PNG
/// date/time format` warning: bundled gates it on `StrictDate`/`Validate`
/// (`PNG.pm:851`), both of which are off in `extract_info`.
///
/// This is verified `-j` (print_conv)- and `-n`-identical against the bundled
/// `perl exiftool` oracle: the `PrintConv` (`$self->ConvertDateTime($val)`,
/// `PNG.pm:637`) is an identity for the default date format (the value is
/// already in EXIF format), so print- and value-conv outputs coincide.
fn convert_png_date(val: &str) -> String {
  match try_convert_png_date(val) {
    Some(converted) => converted,
    None => String::from(val),
  }
}

/// The regex-match + conversion core. Returns `Some(exif_date)` on a faithful
/// match (the `return sprintf(...)` arm) and `None` for both the no-match case
/// and the `last`-arm (unknown alpha zone) case — i.e. every path where
/// bundled falls through to `return $val`.
fn try_convert_png_date(val: &str) -> Option<String> {
  let bytes = val.as_bytes();

  // The Perl pattern is an UNanchored `while ($val =~ /.../)` search — it scans
  // for the first byte offset at which the pattern matches. We replicate the
  // search by trying each candidate start of group 1 (a run of ASCII digits).
  let mut start = 0;
  while start < bytes.len() {
    // Group 1 `(\d+)` — day. Must begin with a digit.
    if !bytes[start].is_ascii_digit() {
      start += 1;
      continue;
    }
    if let Some(out) = match_png_date_at(val, start) {
      return out;
    }
    // Advance past this digit run so the next search start is a fresh token
    // boundary (mirrors Perl's regex engine retrying later offsets).
    start += 1;
  }
  None
}

/// Attempt the full `(\d+)\s*(Mon)\s*(\d+)\s+(\d+):(\d{2})(:\d{2})?\s*(\S*)`
/// match anchored at byte offset `start` (the start of group 1). Returns:
/// - `Some(Some(s))` — a complete match that produced the EXIF date `s`
///   (bundled's `return sprintf`);
/// - `Some(None)` — a complete regex match whose alpha time zone is unknown
///   (bundled's `last` ⇒ fall through to `return $val`);
/// - `None` — the pattern did NOT match at `start` (keep searching).
#[allow(clippy::too_many_lines)]
fn match_png_date_at(val: &str, start: usize) -> Option<Option<String>> {
  let bytes = val.as_bytes();
  let mut i = start;

  // `(\d+)` — day (group 1). Greedy run of ASCII digits.
  let day_start = i;
  while i < bytes.len() && bytes[i].is_ascii_digit() {
    i += 1;
  }
  let day: u32 = val[day_start..i].parse().ok()?;

  // `\s*` — optional whitespace.
  i = skip_ws(bytes, i);

  // `(Jan|Feb|...|Dec)` — month (group 2), case-insensitive, exactly 3 letters.
  if i + 3 > bytes.len() {
    return None;
  }
  // The 3 month bytes must be ASCII letters before we treat them as a str
  // token (keeps the slice on a UTF-8 boundary and matches the regex's
  // `[A-Za-z]`-only month alternation).
  if !bytes[i..i + 3].iter().all(u8::is_ascii_alphabetic) {
    return None;
  }
  let mon = &val[i..i + 3];
  let mon_num = month_num(mon)?;
  i += 3;

  // `\s*` — optional whitespace.
  i = skip_ws(bytes, i);

  // `(\d+)` — year (group 3).
  let yr_start = i;
  while i < bytes.len() && bytes[i].is_ascii_digit() {
    i += 1;
  }
  if i == yr_start {
    return None;
  }
  let mut yr: u32 = val[yr_start..i].parse().ok()?;
  // 2-digit-year boost (`PNG.pm:838`): `$yr += $yr > 70 ? 1900 : 2000 if $yr <
  // 100`.
  if yr < 100 {
    yr += if yr > 70 { 1900 } else { 2000 };
  }

  // `\s+` — MANDATORY whitespace before the time.
  let after_yr = i;
  i = skip_ws(bytes, i);
  if i == after_yr {
    return None;
  }

  // `(\d+)` — hour (group 4).
  let hr_start = i;
  while i < bytes.len() && bytes[i].is_ascii_digit() {
    i += 1;
  }
  if i == hr_start {
    return None;
  }
  let hr: u32 = val[hr_start..i].parse().ok()?;

  // `:` — literal colon.
  if bytes.get(i) != Some(&b':') {
    return None;
  }
  i += 1;

  // `(\d{2})` — minute (group 5), EXACTLY two digits.
  if i + 2 > bytes.len() || !bytes[i].is_ascii_digit() || !bytes[i + 1].is_ascii_digit() {
    return None;
  }
  let min = &val[i..i + 2];
  i += 2;

  // `(:\d{2})?` — optional seconds (group 6), INCLUDING the leading colon.
  let mut sec = "";
  if bytes.get(i) == Some(&b':')
    && i + 3 <= bytes.len()
    && bytes[i + 1].is_ascii_digit()
    && bytes[i + 2].is_ascii_digit()
  {
    sec = &val[i..i + 3]; // e.g. ":22" (colon included, matching `$sec`)
    i += 3;
  }

  // `\s*` — optional whitespace before the zone.
  i = skip_ws(bytes, i);

  // `(\S*)` — time zone (group 7): a run of non-whitespace (possibly empty).
  let tz_start = i;
  while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
    i += 1;
  }
  let tz_raw = &val[tz_start..i];

  // Resolve the zone (`PNG.pm:840-848`).
  let tz: String = if tz_raw.is_empty() {
    // `if (not $tz) { $tz = '' }`
    String::new()
  } else if let Some(named) = tz_conv(tz_raw) {
    // `elsif ($tzConv{uc $tz}) { $tz = $tzConv{uc $tz} }`
    String::from(named)
  } else if let Some(numeric) = parse_numeric_tz(tz_raw) {
    // `elsif ($tz =~ /^([-+]\d+):?(\d{2})/) { $tz = $1 . ':' . $2 }`
    numeric
  } else {
    // `else { last }` — non-standard date ⇒ bundled returns the value verbatim.
    return Some(None);
  };

  // `$sec || ':00'` (`PNG.pm:849`): a captured `:SS` is kept verbatim; an empty
  // seconds group defaults to `:00`.
  let sec_out = if sec.is_empty() { ":00" } else { sec };

  // `sprintf("%.4d:%.2d:%.2d %.2d:%.2d%s%s", yr, mon, day, hr, min, sec, tz)`.
  // `min` is already exactly two digits; `sec_out` carries its own colon.
  Some(Some(std::format!(
    "{yr:04}:{mon_num:02}:{day:02} {hr:02}:{min}{sec_out}{tz}"
  )))
}

/// Skip a run of ASCII whitespace starting at `i`, returning the new index.
/// Mirrors Perl `\s` (`[ \t\n\r\f\x0b]`); [`u8::is_ascii_whitespace`] is the
/// same set minus vertical-tab `\x0b`, which never appears in PNG dates.
fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
  while i < bytes.len() && bytes[i].is_ascii_whitespace() {
    i += 1;
  }
  i
}

/// `(\S*)` numeric-zone arm of `ConvertPNGDate` (`PNG.pm:844`):
/// `^([-+]\d+):?(\d{2})` → `$1 . ':' . $2`. The match is UNanchored at the end
/// (`/^.../` with no `$`), so trailing junk after the 2-digit group is ignored.
/// Group 1 is `[-+]\d+` (sign + one-or-more digits — the hours, which bundled
/// does NOT re-pad), group 2 is the final two digits (minutes). Returns
/// `Some("<±HH>:<MM>")` or `None` if the token isn't a numeric zone.
fn parse_numeric_tz(tz: &str) -> Option<String> {
  let bytes = tz.as_bytes();
  // `[-+]`
  let sign = *bytes.first()?;
  if sign != b'-' && sign != b'+' {
    return None;
  }
  // `\d+` — the hours (group 1 includes the sign). Greedy, but group 2 needs the
  // final two digits, so the hours run is "all leading digits except the last
  // two that group 2 claims". Perl's greedy `\d+` then backtracks two digits for
  // `(\d{2})`; replicate by locating the maximal digit run, then splitting off
  // the trailing two.
  let mut j = 1;
  while j < bytes.len() && bytes[j].is_ascii_digit() {
    j += 1;
  }
  let digit_run = &tz[1..j];
  // Optional literal `:` between the two `\d` groups (`:?`). If present, group 1
  // is the digits before it and group 2 the two after it.
  if let Some(&c) = bytes.get(j)
    && c == b':'
  {
    // `[-+]\d+ : \d{2}` — colon form. Group 1 = sign+digit_run (≥1 digit),
    // group 2 = exactly the next two digits.
    if !digit_run.is_empty()
      && bytes.len() >= j + 3
      && bytes[j + 1].is_ascii_digit()
      && bytes[j + 2].is_ascii_digit()
    {
      let hours = &tz[..j]; // sign + hour digits
      let mins = &tz[j + 1..j + 3];
      return Some(std::format!("{hours}:{mins}"));
    }
    return None;
  }
  // No colon: the maximal digit run must hold ≥3 digits so group 1 keeps ≥1 and
  // group 2 takes the last two (e.g. `+0530` → `+05` `:` `30`). Perl's `\d+`
  // backtracks the final two digits to `(\d{2})`.
  if digit_run.len() < 3 {
    return None;
  }
  let split = j - 2; // index of the first of the two minute digits
  let hours = &tz[..split]; // sign + hour digits
  let mins = &tz[split..j];
  Some(std::format!("{hours}:{mins}"))
}

/// Convert an XMP/ISO-8601 date to EXIF date format — a faithful port of
/// `Image::ExifTool::XMP::ConvertXMPDate` (`XMP.pm:3383-3394`), the `ValueConv`
/// for the ImageMagick-written `create-date → CreateDate` and `modify-date →
/// ModDate` text tags (`PNG.pm:658-677`). Called in scalar context with no
/// `$unsure` argument (so `$unsure` is false):
///
/// ```text
/// if ($val =~ /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}:\d{2})(:\d{2})?\s*(\S*)$/) {
///     my $s = $5 || '';           # seconds may be missing
///     $val = "$1:$2:$3 $4$s$6";   # convert back to EXIF time format
/// } elsif (not $unsure and $val =~ /^(\d{4})(-\d{2}){0,2}/) {
///     $val =~ tr/-/:/;
/// }
/// return $val;
/// ```
///
/// Branch 1 (the anchored full datetime) reformats `YYYY-MM-DD[T ]HH:MM[:SS]<tz>`
/// to `YYYY:MM:DD HH:MM[:SS]<tz>` (e.g. `2024-01-15T10:30:00+00:00` →
/// `2024:01:15 10:30:00+00:00`); the whitespace between the optional seconds and
/// the timezone is dropped (`\s*` is not captured). Branch 2 (a string beginning
/// with a 4-digit year) replaces EVERY `-` with `:` (`2024-01-15` →
/// `2024:01:15`, `2024` → `2024`). Anything else is returned verbatim.
///
/// The `PrintConv` (`$self->ConvertDateTime($val)`, `PNG.pm:665`) is an identity
/// for the default date format once the value is already EXIF-formatted, so `-j`
/// and `-n` coincide (oracle-verified) — we apply this conversion in BOTH
/// [`ConvMode`]s, exactly like the sibling [`convert_png_date`].
fn convert_xmp_date(val: &str) -> String {
  if let Some(exif) = try_xmp_full_datetime(val) {
    return exif;
  }
  // Branch 2 (`elsif`, reached only when branch 1 did not match): a string whose
  // first four bytes are ASCII digits (`^(\d{4})`; the `(-\d{2}){0,2}` group is
  // optional) → `tr/-/:/` over the WHOLE string.
  let b = val.as_bytes();
  if b.len() >= 4 && b[..4].iter().all(u8::is_ascii_digit) {
    return val.replace('-', ":");
  }
  String::from(val)
}

/// Branch 1 of [`convert_xmp_date`] — the anchored
/// `^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}:\d{2})(:\d{2})?\s*(\S*)$` match. Returns
/// the reformatted EXIF date on a full match, else `None` (so the caller falls
/// through to branch 2 / the verbatim return).
fn try_xmp_full_datetime(val: &str) -> Option<String> {
  let b = val.as_bytes();
  // The fixed prefix `YYYY-MM-DD[T ]HH:MM` occupies bytes 0..16.
  if b.len() < 16 {
    return None;
  }
  let digits = |r: &[u8]| r.iter().all(u8::is_ascii_digit);
  if !digits(&b[0..4]) || b[4] != b'-' || !digits(&b[5..7]) || b[7] != b'-' || !digits(&b[8..10]) {
    return None;
  }
  // `[T ]`
  if b[10] != b'T' && b[10] != b' ' {
    return None;
  }
  // `(\d{2}:\d{2})` — HH:MM at bytes 11..16 (group 4).
  if !digits(&b[11..13]) || b[13] != b':' || !digits(&b[14..16]) {
    return None;
  }
  let mut i = 16;
  // `(:\d{2})?` — optional seconds; the leading colon is part of `$5`.
  let secs: &str = if i + 3 <= b.len() && b[i] == b':' && digits(&b[i + 1..i + 3]) {
    let s = &val[i..i + 3];
    i += 3;
    s
  } else {
    ""
  };
  // `\s*` then `(\S*)$` — skip whitespace; the remainder (the timezone, `$6`)
  // must hold NO further whitespace or the anchored `$` cannot match.
  i = skip_ws(b, i);
  let tz = &val[i..];
  if tz.bytes().any(|c| c.is_ascii_whitespace()) {
    return None;
  }
  // `"$1:$2:$3 $4$s$6"` — year:month:day, space, HH:MM, seconds, timezone.
  let date = std::format!("{}:{}:{}", &val[0..4], &val[5..7], &val[8..10]);
  let hm = &val[11..16]; // "HH:MM" (group 4)
  Some(std::format!("{date} {hm}{secs}{tz}"))
}

/// Normalize a language code to ExifTool's standard case — a faithful port of
/// `PNG::StandardLangCase` (`PNG.pm:796-802`, itself copied from `XMP.pm`):
///
/// ```text
/// sub StandardLangCase($) {
///     my $lang = shift;
///     # make 2nd subtag uppercase only if it is 2 letters
///     return lc($1) . uc($2) . lc($3) if $lang =~ /^([a-z]{2,3}|[xi])(-[a-z]{2})\b(.*)/i;
///     return lc($lang);
/// }
/// ```
///
/// The case-insensitive regex (`/i`) decomposes the tag into:
/// - `$1` — the primary subtag: `[a-z]{2,3}` (2-3 letters) OR a single `x`/`i`.
/// - `$2` — `-[a-z]{2}` (a hyphen + EXACTLY 2 letters) followed by a `\b` word
///   boundary (so a 3-letter region like `-usa` does NOT match — the `\b`
///   between the 2nd letter and a 3rd word-char fails).
/// - `$3` — the rest (`.*`).
///
/// When it matches, the result is `lc($1) . uc($2) . lc($3)`: the primary
/// subtag is lower-cased, the 2-letter region subtag is UPPER-cased (the
/// leading hyphen in `$2` is unaffected by `uc`), and the remainder is
/// lower-cased — e.g. `en-us` → `en-US`, `EN-US` → `en-US`, `EN-US-x-foo` →
/// `en-US-x-foo`. When it does NOT match (no 2-letter region — e.g. `en`,
/// `en-usa`, `de`), the whole tag is simply lower-cased (`EN` → `en`).
///
/// ExifTool's `\b` matches between a word char (`[A-Za-z0-9_]`) and a non-word
/// char (or string end). We replicate that exactly for the boundary after the
/// 2-letter region.
fn standard_lang_case(lang: &str) -> String {
  let bytes = lang.as_bytes();
  // Try the `^([a-z]{2,3}|[xi])(-[a-z]{2})\b(.*)$` match, case-insensitively.
  //
  // Primary subtag `$1`: a single `x`/`i`, OR 2-3 ASCII letters. The Perl
  // alternation is ordered `[a-z]{2,3}|[xi]`: for a lone `x`/`i` the first
  // branch needs ≥2 letters so it fails and the `[xi]` branch matches length
  // 1. For `xi`/`ix`/`xx` (2 letters) the first branch matches length 2. So
  // the effective primary-subtag length is: 2 or 3 if the first 2-3 bytes are
  // ASCII letters (greedy, longest that still lets the rest match), else 1 if
  // the first byte is `x`/`i`. We must also leave room for `-[a-z]{2}` next.
  let is_ascii_alpha = |b: u8| b.is_ascii_alphabetic();

  // Helper: does a `-[a-z]{2}` + `\b` start at byte index `i`?
  let region_ok = |i: usize| -> bool {
    // need '-' then exactly 2 ASCII letters
    if bytes.get(i) != Some(&b'-') {
      return false;
    }
    let (Some(&c1), Some(&c2)) = (bytes.get(i + 1), bytes.get(i + 2)) else {
      return false;
    };
    if !is_ascii_alpha(c1) || !is_ascii_alpha(c2) {
      return false;
    }
    // `\b` after the 2nd letter: boundary between a word char (the letter)
    // and the next char being a non-word char OR end-of-string. The next
    // byte (at i+3) must NOT be a word char `[A-Za-z0-9_]`.
    match bytes.get(i + 3) {
      None => true,
      Some(&n) => !(n.is_ascii_alphanumeric() || n == b'_'),
    }
  };

  // Determine the primary-subtag length that lets `$2` match. Perl's regex
  // engine backtracks `[a-z]{2,3}` from 3 down to 2; emulate by preferring 3,
  // then 2, then the single `[xi]` branch.
  let mut matched: Option<(usize, usize)> = None; // (primary_len, region_start)
  // `[a-z]{2,3}` branch: try length 3 then 2.
  for plen in [3usize, 2usize] {
    if bytes.len() >= plen && bytes[..plen].iter().all(|&b| is_ascii_alpha(b)) && region_ok(plen) {
      matched = Some((plen, plen));
      break;
    }
  }
  // `[xi]` branch (single char), only if the 2-3 letter branch didn't match.
  if matched.is_none()
    && let Some(&b0) = bytes.first()
    && (b0 == b'x' || b0 == b'X' || b0 == b'i' || b0 == b'I')
    && region_ok(1)
  {
    matched = Some((1, 1));
  }

  match matched {
    Some((plen, region_start)) => {
      // `$1` = bytes[..plen]; `$2` = bytes[region_start..region_start+3]
      // (the `-` + 2 letters); `$3` = the rest.
      let primary = &lang[..plen];
      let region = &lang[region_start..region_start + 3];
      let rest = &lang[region_start + 3..];
      let mut out = String::with_capacity(lang.len());
      out.push_str(&primary.to_ascii_lowercase());
      out.push_str(&region.to_ascii_uppercase());
      out.push_str(&rest.to_ascii_lowercase());
      out
    }
    None => lang.to_ascii_lowercase(),
  }
}

/// The set of registered `%PNG::TextualData` keywords whose `Name` is the
/// keyword string itself (`PNG.pm:626-688`). The non-identity mappings
/// (`Creation Time`, `Warning`, `create-date`, `modify-date`,
/// `aesthetic_score`) are handled by their own arm in [`png_text_tag_name`].
fn is_registered_textual_keyword(name: &str) -> bool {
  matches!(
    name,
    "Title"
      | "Author"
      | "Description"
      | "Copyright"
      | "Software"
      | "Disclaimer"
      | "Source"
      | "Comment"
      | "Collection"
      | "Artist"
      | "Document"
      | "Label"
      | "Make"
      | "Model"
      | "parameters"
      | "TimeStamp"
      | "URL"
  )
}

// ===========================================================================
// `Project` — the normalized cross-format domain projection (golden L2)
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::metadata::Project for PngMeta<'_> {
  /// Project PNG metadata onto the normalized [`MediaMetadata`] domain.
  ///
  /// PNG carries its camera/lens/GPS/capture facts EXCLUSIVELY in its EXIF
  /// sources — native `eXIf`/`zxIf` chunks (`PNG.pm:309-317`) and ImageMagick
  /// `Raw profile type {exif,APP1}` chunks (`PNG.pm:1216-1265`), all dispatched
  /// to `Image::ExifTool::Exif` via `ProcessTIFF`. We project each NON-BLOCKED
  /// source (via [`parse_exif_block`](crate::exif::parse_exif_block) +
  /// the EXIF [`Project`](crate::metadata::Project) impl — the same fold
  /// EXIF IFDs + vendor MakerNote → camera / lens / GPS / capture the
  /// standalone EXIF arm uses) and merge them in CHUNK (walk) ORDER so the
  /// projected camera/lens/GPS reflects the SAME winning set as
  /// [`ProcessPng`]'s `tags()`. The PNG-OWNED structural fact is the IHDR pixel
  /// dimensions, surfaced on [`MediaInfo`](crate::metadata::MediaInfo).
  /// Everything PNG cannot decode stays `None`.
  ///
  /// **Chunk-order-aware fold (`ExifTool.pm:9061-9072` + `PNG.pm:1193`).**
  /// Which events contribute is decided by [`replay_exif_events`] (the shared
  /// `$$et{PROCESSED}` cycle-guard: a directory is blocked only when its `$addr`
  /// was already processed; a profile event first clears the set), exactly as
  /// tag emission. The non-blocked projections are folded LATER-WINS (each new
  /// event is the higher-priority left of the
  /// [`merge`](crate::metadata::MediaMetadata::merge), the accumulator fills
  /// gaps), mirroring the last-wins `TagMap` dedup. The merged EXIF projection
  /// is then the higher-priority side over the PNG dimensions (which fill the
  /// `MediaInfo` width/height the EXIF blocks may not carry). This is ADDITIVE
  /// over tag emission — it reads the already-parsed `Meta` and never touches
  /// tag output.
  fn project(&self) -> crate::metadata::MediaMetadata {
    // PNG-owned structural facts (IHDR dimensions, `PNG.pm:391-398`).
    let mut png_media = crate::metadata::MediaMetadata::new();
    png_media.media_mut().update_width(self.width());
    png_media.media_mut().update_height(self.height());

    // The eXIf / Raw-profile EXIF fold (camera/lens/GPS/capture). Replay the
    // shared-`$$et{PROCESSED}` event stream and merge each parsed (non-blocked)
    // one LATER-WINS (new event on the left of `merge`), matching `tags()`. A
    // blocked event's `ExifMeta` has no entries ⇒ projects to an empty
    // `MediaMetadata`; a reset-only profile yields no `meta` ⇒ contributes
    // nothing.
    #[cfg(feature = "exif")]
    {
      let mut acc: Option<crate::metadata::MediaMetadata> = None;
      for replay in replay_exif_events(self.exif_events()) {
        if let Some(exif_meta) = replay.meta() {
          let projected = crate::metadata::Project::project(exif_meta);
          // Later event wins: it is the higher-priority left side; the
          // accumulated earlier projection fills the gaps.
          acc = Some(match acc {
            Some(prev) => projected.merge(prev),
            None => projected,
          });
        }
      }
      if let Some(exif_media) = acc {
        // EXIF (camera facts) is higher-priority; the PNG dimensions fill gaps.
        return exif_media.merge(png_media);
      }
    }

    png_media
  }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  /// Assert the PNG captured EXACTLY ONE EXIF event, of the given kind
  /// (`expect_profile` = `true` ⇒ [`PngExifEvent::ExifProfile`], `false` ⇒
  /// [`PngExifEvent::NativeTiff`]) carrying `block`.
  fn assert_single_exif_event(meta: &PngMeta<'_>, expect_profile: bool, block: &[u8]) {
    let evs = meta.exif_events();
    assert_eq!(evs.len(), 1, "expected one EXIF event, got {evs:?}");
    if expect_profile {
      assert!(
        evs[0].is_exif_profile(),
        "expected ExifProfile, got {evs:?}"
      );
    } else {
      assert!(evs[0].is_native(), "expected NativeTiff, got {evs:?}");
    }
    assert_eq!(evs[0].block(), Some(block));
  }

  /// `standard_lang_case` faithfully ports `PNG::StandardLangCase`
  /// (`PNG.pm:796-802`): the primary subtag is lower-cased and a 2-letter
  /// region subtag is UPPER-cased; with no 2-letter region the whole tag is
  /// lower-cased.
  #[test]
  fn standard_lang_case_normalizes_region_subtag() {
    // Primary lower + 2-letter region upper (the required `en-us` case).
    assert_eq!(standard_lang_case("en-us"), "en-US");
    assert_eq!(standard_lang_case("EN-US"), "en-US");
    assert_eq!(standard_lang_case("En-Us"), "en-US");
    // 3-letter primary subtag still normalizes its 2-letter region.
    assert_eq!(standard_lang_case("yue-CN"), "yue-CN");
    assert_eq!(standard_lang_case("YUE-cn"), "yue-CN");
    // No region: whole tag lower-cased.
    assert_eq!(standard_lang_case("EN"), "en");
    assert_eq!(standard_lang_case("de"), "de");
    // A 3-letter "region" is NOT a 2-letter region (the `\b` fails), so the
    // whole tag is just lower-cased (region NOT upper-cased).
    assert_eq!(standard_lang_case("en-usa"), "en-usa");
    // Trailing subtags after a 2-letter region: region upper, rest lower.
    assert_eq!(standard_lang_case("EN-US-X-FOO"), "en-US-x-foo");
    // Single-letter `x`/`i` primary subtag branch (`[xi]`) + 2-letter region.
    assert_eq!(standard_lang_case("X-GB"), "x-GB");
    assert_eq!(standard_lang_case("i-NL"), "i-NL");
    // Empty / degenerate inputs lower-case cleanly.
    assert_eq!(standard_lang_case(""), "");
    assert_eq!(standard_lang_case("C"), "c");
  }

  /// Build a synthetic well-formed chunk: `[len BE][type][data][crc BE]`.
  fn chunk(chunk_type: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let len = u32::try_from(data.len()).expect("test chunk fits in u32");
    let mut buf = Vec::with_capacity(8 + data.len() + 4);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(chunk_type);
    buf.extend_from_slice(data);
    // CRC over [type, data].
    let mut crc_buf = Vec::with_capacity(4 + data.len());
    crc_buf.extend_from_slice(chunk_type);
    crc_buf.extend_from_slice(data);
    let crc = crc32(&crc_buf);
    buf.extend_from_slice(&crc.to_be_bytes());
    buf
  }

  fn synthetic_png(chunks: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(PNG_SIGNATURE);
    for c in chunks {
      out.extend_from_slice(c);
    }
    // IEND terminator (already part of `chunks` if the caller wanted one).
    out
  }

  /// A bare-minimum PNG: signature + IHDR + IEND.
  fn minimal_png_bytes() -> Vec<u8> {
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&16u32.to_be_bytes()); // width
    ihdr.extend_from_slice(&16u32.to_be_bytes()); // height
    ihdr.push(1); // bit_depth
    ihdr.push(0); // color_type Grayscale
    ihdr.push(0); // compression
    ihdr.push(0); // filter
    ihdr.push(0); // interlace
    let all = vec![chunk(b"IHDR", &ihdr), chunk(b"IEND", &[])];
    synthetic_png(&all)
  }

  #[test]
  fn signature_rejects_non_png() {
    assert!(parse_borrowed(b"NOTAPNG\0").is_none());
    assert!(parse_borrowed(b"\x89PNG\r\n\x1a").is_none()); // 7 bytes
    assert!(parse_borrowed(&[]).is_none());
  }

  #[test]
  fn signature_accepts_canonical_png() {
    let bytes = minimal_png_bytes();
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert_eq!(meta.dimensions(), Some((16, 16)));
    assert_eq!(meta.bit_depth(), Some(1));
    assert!(meta.color_type().expect("ihdr").is_grayscale());
    assert_eq!(meta.compression(), Some(0));
    assert_eq!(meta.filter(), Some(0));
    assert_eq!(meta.interlace(), Some(0));
  }

  #[test]
  fn ihdr_with_oversized_chunk_length_yields_warning() {
    // Length field = 0x80000000 (just over MAX_CHUNK_LENGTH).
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    bytes.extend_from_slice(&0x80000000u32.to_be_bytes());
    bytes.extend_from_slice(b"IHDR");
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert!(meta.warnings().iter().any(|w| w.contains("chunk size")));
  }

  #[test]
  fn truncated_after_signature_yields_warning() {
    // Only the signature.
    let bytes = PNG_SIGNATURE.to_vec();
    let meta = parse_borrowed(&bytes).expect("png parses");
    // No IHDR seen; the walker tries to read the next 8-byte header,
    // sees zero remaining bytes, warns and exits.
    assert!(meta.warnings().iter().any(|w| w.contains("Truncated")));
  }

  #[test]
  fn phys_decodes_pixels_per_meter() {
    // pHYs = (2834, 2834, meters=1)
    let mut phys = Vec::new();
    phys.extend_from_slice(&2834u32.to_be_bytes());
    phys.extend_from_slice(&2834u32.to_be_bytes());
    phys.push(1);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"pHYs", &phys));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert_eq!(meta.pixels_per_unit_x(), Some(2834));
    assert_eq!(meta.pixels_per_unit_y(), Some(2834));
    assert_eq!(meta.pixel_units(), Some(1));
    let (dx, dy) = meta.dpi().expect("dpi");
    assert!((dx - 71.9836).abs() < 1e-9);
    assert!((dy - 71.9836).abs() < 1e-9);
  }

  #[test]
  fn text_keyword_value_decoded_as_latin1() {
    // tEXt: keyword "Comment\0value with é (0xe9)"
    let mut payload = Vec::new();
    payload.extend_from_slice(b"Comment\0value ");
    payload.push(0xe9); // Latin-1 'é'
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"tEXt", &payload));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert_eq!(meta.text_records().len(), 1);
    let r = &meta.text_records()[0];
    assert!(r.kind().is_text());
    assert_eq!(r.keyword(), "Comment");
    assert_eq!(r.value(), "value \u{e9}"); // 'é' as UTF-8
  }

  #[test]
  fn itxt_keyword_value_decoded_as_utf8() {
    // iTXt: keyword "Title\0", comp=0, method=0, lang="en\0", trans="\0",
    // value="Hello"
    let mut payload = Vec::new();
    payload.extend_from_slice(b"Title\0");
    payload.push(0); // compressed=0
    payload.push(0); // method=0
    payload.extend_from_slice(b"en\0");
    payload.extend_from_slice(b"\0");
    payload.extend_from_slice(b"Hello");
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"iTXt", &payload));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert_eq!(meta.text_records().len(), 1);
    let r = &meta.text_records()[0];
    assert!(r.kind().is_itxt());
    assert_eq!(r.keyword(), "Title");
    assert_eq!(r.language(), Some("en"));
    assert_eq!(r.translated_keyword(), Some(""));
    assert_eq!(r.value(), "Hello");
    assert!(!r.is_compressed());
  }

  /// A minimal hand-rolled zlib (RFC 1950) wrapper around a STORED (no-
  /// compression) deflate block — lets the in-crate unit tests build a valid
  /// inflatable payload without a deflate encoder. Layout: `0x78 0x01`
  /// (zlib header, CM=8/CINFO=7, FCHECK), one final stored block
  /// (`0x01` BFINAL=1/BTYPE=00, `LEN`/`~LEN` little-endian, then the literal
  /// bytes), then the big-endian Adler-32 of the uncompressed data.
  fn zlib_store(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x78);
    out.push(0x01);
    let len = u16::try_from(data.len()).expect("test payload < 64KiB");
    out.push(0x01); // BFINAL=1, BTYPE=00 (stored)
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&(!len).to_le_bytes());
    out.extend_from_slice(data);
    // Adler-32 (RFC 1950) over the uncompressed bytes, big-endian.
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
      a = (a + u32::from(byte)) % 65521;
      b = (b + a) % 65521;
    }
    out.extend_from_slice(&((b << 16) | a).to_be_bytes());
    out
  }

  #[test]
  fn itxt_compressed_inflates_to_uncompressed_record() {
    // iTXt: keyword "Foo", compressed=1, method=0, empty lang/trans, value =
    // zlib("Bar"). The new inflate path stores it as an UNCOMPRESSED record.
    let mut payload = Vec::new();
    payload.extend_from_slice(b"Foo\0");
    payload.push(1); // compressed=1
    payload.push(0); // method=0
    payload.extend_from_slice(b"\0\0"); // empty lang, empty trans
    payload.extend_from_slice(&zlib_store(b"Bar")); // zlib-wrapped value
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"iTXt", &payload));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    let r = &meta.text_records()[0];
    // After inflate the record is no longer flagged compressed and carries the
    // decoded UTF-8 value — emission is identical to a plain iTXt.
    assert!(!r.is_compressed());
    assert_eq!(r.keyword(), "Foo");
    assert_eq!(r.value(), "Bar");
    assert!(meta.warnings().is_empty(), "got {:?}", meta.warnings());
  }

  #[test]
  fn itxt_compressed_corrupt_stream_warns_error_inflating() {
    // iTXt with a corrupt zlib stream ⇒ `Error inflating Foo` (PNG.pm:942).
    let mut payload = Vec::new();
    payload.extend_from_slice(b"Foo\0");
    payload.push(1); // compressed=1
    payload.push(0); // method=0
    payload.extend_from_slice(b"\0\0"); // empty lang, empty trans
    payload.extend_from_slice(b"\x78\x9c\xde\xad\xbe\xef"); // corrupt stream
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"iTXt", &payload));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    let r = &meta.text_records()[0];
    assert!(r.is_compressed());
    assert_eq!(r.value(), "");
    assert!(
      meta.warnings().iter().any(|w| w == "Error inflating Foo"),
      "got {:?}",
      meta.warnings(),
    );
    // The retired `Install Compress::Zlib` warning must NEVER appear now.
    assert!(
      !meta
        .warnings()
        .iter()
        .any(|w| w.contains("Install Compress::Zlib")),
    );
  }

  #[test]
  fn ztxt_inflates_to_text_record() {
    // zTXt "Description" with zlib("hi there") ⇒ a plain tEXt-style record.
    let mut payload = Vec::new();
    payload.extend_from_slice(b"Description\0");
    payload.push(0); // compression method byte (deflate)
    payload.extend_from_slice(&zlib_store(b"hi there"));
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"zTXt", &payload));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert_eq!(meta.text_records().len(), 1);
    let r = &meta.text_records()[0];
    // Stored through the tEXt path: kind = tEXt, value decoded, NOT compressed.
    assert!(r.kind().is_text());
    assert!(!r.is_compressed());
    assert_eq!(r.keyword(), "Description");
    assert_eq!(r.value(), "hi there");
    assert!(meta.warnings().is_empty(), "got {:?}", meta.warnings());
  }

  #[test]
  fn ztxt_corrupt_stream_warns_error_inflating() {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"Description\0");
    payload.push(0); // method = deflate
    payload.extend_from_slice(b"\x78\x9c\xde\xad\xbe\xef"); // corrupt stream
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"zTXt", &payload));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    let r = &meta.text_records()[0];
    assert!(r.kind().is_ztxt());
    assert!(r.is_compressed());
    assert_eq!(r.keyword(), "Description");
    assert!(
      meta
        .warnings()
        .iter()
        .any(|w| w == "Error inflating Description"),
    );
  }

  #[test]
  fn ztxt_unknown_method_warns() {
    // Non-zero compression method ⇒ `Unknown compression method N for <kw>`.
    let mut payload = Vec::new();
    payload.extend_from_slice(b"Comment\0");
    payload.push(5); // method = 5 (unknown)
    payload.extend_from_slice(b"\x01\x02\x03");
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"zTXt", &payload));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert!(
      meta
        .warnings()
        .iter()
        .any(|w| w == "Unknown compression method 5 for Comment"),
    );
  }

  #[test]
  fn iccp_captures_profile_name_and_inflates_body() {
    // iCCP: name "sRGB IEC61966-2.1", body = zlib(<fake profile>). Inflate
    // succeeds; the inflated ICC profile is NOT decoded into tags (deferred),
    // so NO warning fires and only the profile NAME is captured.
    let mut payload = Vec::new();
    payload.extend_from_slice(b"sRGB IEC61966-2.1\0");
    payload.push(0); // compression method = deflate
    payload.extend_from_slice(&zlib_store(b"not-a-real-icc-profile"));
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"iCCP", &payload));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert_eq!(meta.icc_profile_name(), Some("sRGB IEC61966-2.1"));
    // No warning on clean inflate; the ICC-tag decode is deferred silently.
    assert!(meta.warnings().is_empty(), "got {:?}", meta.warnings());
  }

  #[test]
  fn iccp_corrupt_body_warns_error_inflating() {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"sRGB\0");
    payload.push(0); // method = deflate
    payload.extend_from_slice(b"\x78\x9c\xde\xad\xbe\xef"); // corrupt stream
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"iCCP", &payload));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert_eq!(meta.icc_profile_name(), Some("sRGB"));
    assert!(meta.warnings().iter().any(|w| w == "Error inflating iCCP"));
  }

  #[test]
  fn zxif_inflates_compressed_exif_block() {
    // zXIf: eXIf chunk, body = \0 + 4 unused bytes + zlib(<minimal TIFF>).
    let mut tiff = Vec::new();
    tiff.extend_from_slice(b"II"); // little-endian
    tiff.extend_from_slice(&0x002a_u16.to_le_bytes()); // magic 42
    tiff.extend_from_slice(&0x0000_0008_u32.to_le_bytes()); // IFD0 at 8
    tiff.extend_from_slice(&0x0000_u16.to_le_bytes()); // 0 entries
    tiff.extend_from_slice(&0x0000_0000_u32.to_le_bytes()); // next-IFD = 0
    let mut body = Vec::new();
    body.push(0); // `\0` compressed-EXIF type marker
    body.extend_from_slice(&[0, 0, 0, 0]); // 4-byte unused field
    body.extend_from_slice(&zlib_store(&tiff));
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"eXIf", &body));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    // The captured block is the INFLATED TIFF, ready for parse_exif_block —
    // a single native (non-profile) source.
    assert_single_exif_event(&meta, false, &tiff);
    assert!(meta.warnings().is_empty(), "got {:?}", meta.warnings());
  }

  #[test]
  fn zxif_corrupt_stream_warns_error_inflating() {
    let mut body = Vec::new();
    body.push(0); // `\0` compressed-EXIF marker
    body.extend_from_slice(&[0, 0, 0, 0]);
    body.extend_from_slice(b"\x78\x9c\xde\xad\xbe\xef"); // corrupt
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"eXIf", &body));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert!(meta.exif_events().is_empty());
    assert!(meta.warnings().iter().any(|w| w == "Error inflating eXIf"));
  }

  #[test]
  fn exif_chunk_captures_tiff_block() {
    // Minimal TIFF: II*\0[8]offset; IFD0 entries=0; no next-IFD.
    let mut tiff = Vec::new();
    tiff.extend_from_slice(b"II"); // little-endian
    tiff.extend_from_slice(&0x002a_u16.to_le_bytes()); // magic 42
    tiff.extend_from_slice(&0x0000_0008_u32.to_le_bytes()); // IFD0 at 8
    tiff.extend_from_slice(&0x0000_u16.to_le_bytes()); // 0 entries
    tiff.extend_from_slice(&0x0000_0000_u32.to_le_bytes()); // next-IFD = 0
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"eXIf", &tiff));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert_single_exif_event(&meta, false, &tiff);
  }

  #[test]
  fn exif_chunk_with_legacy_exif00_prefix_emits_warning_and_strips_it() {
    // `Exif\0\0` + TIFF.
    let mut tiff = Vec::new();
    tiff.extend_from_slice(b"Exif\0\0");
    let inner_start = tiff.len();
    tiff.extend_from_slice(b"II");
    tiff.extend_from_slice(&0x002a_u16.to_le_bytes());
    tiff.extend_from_slice(&0x0000_0008_u32.to_le_bytes());
    tiff.extend_from_slice(&0x0000_u16.to_le_bytes());
    tiff.extend_from_slice(&0x0000_0000_u32.to_le_bytes());
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"eXIf", &tiff));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert_single_exif_event(&meta, false, &tiff[inner_start..]);
    assert!(meta.warnings().iter().any(|w| w.contains("Exif00")),);
  }

  #[test]
  fn exif_chunk_with_invalid_header_is_warned() {
    // Not II/MM/\0 — invalid.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"eXIf", b"XX\0bad"));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert!(meta.exif_events().is_empty());
    assert!(meta.warnings().iter().any(|w| w == "Invalid eXIf chunk"));
  }

  #[test]
  fn bkgd_single_byte_palette_index() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 3, 0, 0, 0]); // Palette color type
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"bKGD", &[0]));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert_eq!(meta.background_color(), Some("0"));
  }

  #[test]
  fn bkgd_rgb_three_int16u() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    let mut bkgd = Vec::new();
    bkgd.extend_from_slice(&1u16.to_be_bytes());
    bkgd.extend_from_slice(&2u16.to_be_bytes());
    bkgd.extend_from_slice(&3u16.to_be_bytes());
    bytes.extend_from_slice(&chunk(b"bKGD", &bkgd));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert_eq!(meta.background_color(), Some("1 2 3"));
  }

  #[test]
  fn time_decoder_emits_yyyy_mm_dd_hh_mm_ss() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    let mut t = Vec::new();
    t.extend_from_slice(&2025u16.to_be_bytes()); // year
    t.extend_from_slice(&[5, 22, 9, 30, 15]); // month, day, hour, min, sec
    bytes.extend_from_slice(&chunk(b"tIME", &t));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert_eq!(meta.modify_date(), Some("2025:05:22 09:30:15"));
  }

  #[test]
  fn text_after_idat_warns_about_post_idat_text() {
    // IHDR + IDAT + tEXt + IEND. The tEXt after IDAT triggers the
    // "Text/EXIF chunk(s) found after PNG IDAT (may be ignored …)" warning.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"IDAT", b"\x00")); // minimal IDAT
    bytes.extend_from_slice(&chunk(b"tEXt", b"Comment\0Hi"));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert!(
      meta
        .warnings()
        .iter()
        .any(|w| w.contains("Text/EXIF chunk(s) found after PNG IDAT")),
    );
  }

  #[test]
  fn non_starting_with_ihdr_emits_warning() {
    // Sig + bKGD (not IHDR) + IEND.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    bytes.extend_from_slice(&chunk(b"bKGD", &[0]));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert!(
      meta
        .warnings()
        .iter()
        .any(|w| w.contains("did not start with IHDR")),
    );
  }

  #[test]
  fn apple_cgbi_first_emits_warning() {
    // Sig + CgBI + IHDR + IEND.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    bytes.extend_from_slice(&chunk(b"CgBI", &[0, 0, 0, 0]));
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert!(
      meta
        .warnings()
        .iter()
        .any(|w| w.contains("Apple iPhone format")),
    );
  }

  #[test]
  fn crc32_matches_known_value() {
    // CRC of "123456789" is 0xCBF43926 (standard CRC-32 test vector).
    assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    // Empty input.
    assert_eq!(crc32(b""), 0);
  }

  // ---- ImageMagick "Raw profile type X" — ProcessProfile (PNG.pm:1155-1281) --

  #[test]
  fn raw_profile_kind_classifies_registered_keywords() {
    // EXIF-capable profiles → the Exif::Main content-keyed branch.
    assert_eq!(
      raw_profile_kind("Raw profile type exif"),
      Some(RawProfileKind::ExifTable {
        name: "EXIF_Profile"
      }),
    );
    assert_eq!(
      raw_profile_kind("Raw profile type APP1"),
      Some(RawProfileKind::ExifTable {
        name: "APP1_Profile"
      }),
    );
    // Unported-module profiles → suppressed (body decoded, then dropped).
    assert!(matches!(
      raw_profile_kind("Raw profile type icc"),
      Some(RawProfileKind::SuppressedTable {
        name: "ICC_Profile"
      }),
    ));
    assert!(matches!(
      raw_profile_kind("Raw profile type icm"),
      Some(RawProfileKind::SuppressedTable {
        name: "ICC_Profile"
      }),
    ));
    assert!(matches!(
      raw_profile_kind("Raw profile type iptc"),
      Some(RawProfileKind::SuppressedTable {
        name: "IPTC_Profile"
      }),
    ));
    assert!(matches!(
      raw_profile_kind("Raw profile type 8bim"),
      Some(RawProfileKind::SuppressedTable {
        name: "Photoshop_Profile"
      }),
    ));
    assert!(matches!(
      raw_profile_kind("Raw profile type xmp"),
      Some(RawProfileKind::SuppressedTable {
        name: "XMP_Profile"
      }),
    ));
    // Ordinary keywords + unregistered raw-profile keywords are NOT classified.
    assert_eq!(raw_profile_kind("Comment"), None);
    assert_eq!(raw_profile_kind("Title"), None);
    assert_eq!(raw_profile_kind("Raw profile type generic profile"), None);
    // ucfirst fallback (PNG.pm:919): a LOWERCASE-first registered keyword
    // (ImageMagick's form) STILL resolves — only the first char is upper-cased.
    assert_eq!(
      raw_profile_kind("raw profile type exif"),
      Some(RawProfileKind::ExifTable {
        name: "EXIF_Profile",
      })
    );
    // ...but a mid-word Title-case variant does NOT (ucfirst only touches char 0).
    assert_eq!(raw_profile_kind("Raw Profile Type Exif"), None);
    // ...nor all-caps.
    assert_eq!(raw_profile_kind("RAW PROFILE TYPE EXIF"), None);
  }

  #[test]
  fn png_dynamic_tag_name_matches_bundled_normalization() {
    // `s/\s+(.)/\u$1/g` + `tr/-_a-zA-Z0-9//dc` + `ucfirst`
    // (PNG.pm:1118 + ExifTool.pm:9256-9257), all oracle-verified.
    assert_eq!(
      png_dynamic_tag_name("Raw profile type exif"),
      "RawProfileTypeExif"
    );
    // APP1 / 8bim keep their case after the space (no LETTER follows them).
    assert_eq!(
      png_dynamic_tag_name("Raw profile type APP1"),
      "RawProfileTypeAPP1"
    );
    assert_eq!(
      png_dynamic_tag_name("Raw profile type 8bim"),
      "RawProfileType8bim"
    );
    assert_eq!(
      png_dynamic_tag_name("Raw profile type icc"),
      "RawProfileTypeIcc"
    );
    assert_eq!(
      png_dynamic_tag_name("Raw profile type generic"),
      "RawProfileTypeGeneric"
    );
    // ucfirst (step 3): a lowercase-`r` keyword still capitalizes the first
    // letter (oracle: "raw profile type generic" → "RawProfileTypeGeneric").
    assert_eq!(
      png_dynamic_tag_name("raw profile type generic"),
      "RawProfileTypeGeneric"
    );
    // Multiple whitespace runs collapse (oracle: "Raw  profile  type  generic"
    // → "RawProfileTypeGeneric"); note this keyword does NOT match the
    // single-space Binary regex, but the NAME normalization is the same.
    assert_eq!(
      png_dynamic_tag_name("Raw  profile  type  generic"),
      "RawProfileTypeGeneric"
    );
  }

  #[test]
  fn raw_profile_binary_flag_keyed_on_original_keyword() {
    // `$$tagInfo{Binary} = 1 if $tag =~ /^Raw profile type /` (PNG.pm:1122) —
    // case-sensitive, literal single spaces, on the ORIGINAL keyword.
    assert!("Raw profile type exif".starts_with(RAW_PROFILE_PREFIX));
    assert!("Raw profile type generic".starts_with(RAW_PROFILE_PREFIX));
    assert!("Raw profile type exifZ".starts_with(RAW_PROFILE_PREFIX));
    // lowercase + double-space do NOT match (→ plain-text dynamic tag).
    assert!(!"raw profile type generic".starts_with(RAW_PROFILE_PREFIX));
    assert!(!"Raw  profile  type  generic".starts_with(RAW_PROFILE_PREFIX));
    assert!(!"Comment".starts_with(RAW_PROFILE_PREFIX));
  }

  #[test]
  fn process_profile_hex_decodes_whitespace_separated_body() {
    // Body framing `\n<type>\n  <len>\n<hex>` (PNG.pm:1166). The hex is
    // whitespace-separated (newlines + spaces) and stripped before decode.
    let body = b"\nexif\n       6\n0102 03\n0405\n06\n";
    let p = process_profile(body, "EXIF_Profile").expect("framing matches");
    assert_eq!(p.bytes, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    assert_eq!(p.profile_type, b"exif");
    assert!(p.size_warning.is_none(), "len 6 matches 6 decoded bytes");
  }

  #[test]
  fn process_profile_wrong_size_warning_uses_tag_name_and_actual_len() {
    // Declared 9 but only 3 bytes decode ⇒ PNG.pm:1172 warning with the tag
    // Name, and the decode CONTINUES with the actual bytes.
    let body = b"\nexif\n       9\n01 02 03\n";
    let p = process_profile(body, "EXIF_Profile").expect("framing matches");
    assert_eq!(p.bytes, vec![0x01, 0x02, 0x03]);
    assert_eq!(
      p.size_warning.as_deref(),
      Some("EXIF_Profile is wrong size (should be 9 bytes but is 3)"),
    );
  }

  #[test]
  fn process_profile_rejects_malformed_framing() {
    // No leading newline ⇒ PNG.pm:1166 `return 0`.
    assert!(process_profile(b"exif\n6\n010203", "EXIF_Profile").is_none());
    // Missing length line.
    assert!(process_profile(b"\nexif\n010203", "EXIF_Profile").is_none());
    // Length line with no digits.
    assert!(process_profile(b"\nexif\n  \nfff", "EXIF_Profile").is_none());
  }

  #[test]
  fn process_profile_odd_nibble_dropped_like_pack_h_star() {
    // `pack('H*', "abc")` drops the dangling nibble — 1 byte from 3 nibbles.
    let body = b"\nexif\n       1\nabc\n";
    let p = process_profile(body, "EXIF_Profile").expect("framing matches");
    assert_eq!(p.bytes, vec![0xab]); // 'c' is the dropped odd nibble
  }

  #[test]
  fn route_exif_profile_captures_exif00_prefixed_block() {
    // `Exif\0\0` + TIFF → strip the 6-byte marker, push the bare TIFF as a
    // PROFILE source (no "Improper Exif00" warning — that is the eXIf-chunk
    // path, not ProcessProfile).
    let mut m = PngMeta::new();
    let mut block = b"Exif\0\0".to_vec();
    block.extend_from_slice(b"II\x2a\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    let inner = block[6..].to_vec();
    route_exif_profile(&mut m, block, b"exif");
    assert_single_exif_event(&m, true, &inner);
    assert!(m.warnings().is_empty(), "got {:?}", m.warnings());
  }

  #[test]
  fn route_exif_profile_xmp_content_emits_reset_only_no_warning() {
    // An XMP-namespace body has no ported XMP module ⇒ no EXIF tags, no
    // warning. But `ProcessProfile` has ALREADY reset `$$et{PROCESSED}`
    // (PNG.pm:1193) before this XMP dispatch (oracle-confirmed: such a profile
    // un-blocks a following same-addr eXIf), so it emits ONE reset-only event.
    let mut m = PngMeta::new();
    let mut block = b"http://ns.adobe.com/xap/1.0/\0".to_vec();
    block.extend_from_slice(b"<x:xmpmeta/>");
    route_exif_profile(&mut m, block, b"APP1");
    let evs = m.exif_events();
    assert_eq!(evs.len(), 1, "expected one reset-only event, got {evs:?}");
    assert!(evs[0].is_reset_only());
    assert!(m.warnings().is_empty(), "got {:?}", m.warnings());
  }

  #[test]
  fn route_exif_profile_unknown_content_warns_and_emits_reset_only() {
    // Neither TIFF nor XMP nor Exif00 ⇒ `Unknown raw profile '<type>'`
    // (PNG.pm:1266-1269), with control/high bytes dotted. The reset has ALREADY
    // happened (oracle-confirmed: a well-formed unrecognized-content profile
    // un-blocks a following same-addr eXIf), so a reset-only event is ALSO
    // pushed in addition to the warning.
    let mut m = PngMeta::new();
    route_exif_profile(&mut m, b"NOT_A_TIFF".to_vec(), b"ex\x01if");
    let evs = m.exif_events();
    assert_eq!(evs.len(), 1, "expected one reset-only event, got {evs:?}");
    assert!(evs[0].is_reset_only());
    assert_eq!(m.warnings(), &["Unknown raw profile 'ex.if'".to_string()]);
  }

  /// Build a minimal complete little-endian TIFF whose IFD0 sits at offset
  /// `ifd0` and carries a single inline `Orientation` (0x0112, SHORT) tag with
  /// value `val`, next-IFD pointer = `next_ifd`. Complete enough for the EXIF
  /// walker to actually walk IFD0 (so the shared-`$$et{PROCESSED}` replay
  /// registers `ifd0` and — when `next_ifd != 0` — the trailing IFD's offset
  /// too). The 8-byte header → `ifd0` gap is zero-filled.
  #[cfg(feature = "exif")]
  fn tiff_ifd0(ifd0: u32, val: u16, next_ifd: u32) -> Vec<u8> {
    assert!(ifd0 >= 8, "IFD0 cannot overlap the 8-byte TIFF header");
    let mut t = Vec::new();
    t.extend_from_slice(b"II");
    t.extend_from_slice(&0x002a_u16.to_le_bytes());
    t.extend_from_slice(&ifd0.to_le_bytes());
    t.resize(ifd0 as usize, 0); // zero-pad header → IFD0
    t.extend_from_slice(&1u16.to_le_bytes()); // 1 entry
    t.extend_from_slice(&0x0112_u16.to_le_bytes()); // Orientation
    t.extend_from_slice(&0x0003_u16.to_le_bytes()); // SHORT
    t.extend_from_slice(&1u32.to_le_bytes()); // count 1
    t.extend_from_slice(&u32::from(val).to_le_bytes()); // inline value
    t.extend_from_slice(&next_ifd.to_le_bytes()); // next-IFD pointer
    t
  }

  /// Like [`tiff_ifd0`] but also lays down a trailing IFD1 at offset
  /// `ifd1_off` (reached via IFD0's next-IFD pointer), carrying an inline
  /// `Orientation` = `ifd1_val`. The IFD0→IFD1 chain is what makes the shared
  /// `$$et{PROCESSED}` set record BOTH `ifd0` and `ifd1_off`, so a later
  /// source's IFD0 landing on `ifd1_off` collides cross-source (the
  /// trailing-IFD case the IFD0-only model missed).
  #[cfg(feature = "exif")]
  fn tiff_ifd0_and_ifd1(val: u16, ifd1_off: u32, ifd1_val: u16) -> Vec<u8> {
    let mut t = tiff_ifd0(8, val, ifd1_off); // IFD0 @8 → IFD1 @ifd1_off
    t.resize(ifd1_off as usize, 0); // pad up to IFD1
    t.extend_from_slice(&1u16.to_le_bytes()); // 1 entry
    t.extend_from_slice(&0x0112_u16.to_le_bytes()); // Orientation
    t.extend_from_slice(&0x0003_u16.to_le_bytes()); // SHORT
    t.extend_from_slice(&1u32.to_le_bytes()); // count 1
    t.extend_from_slice(&u32::from(ifd1_val).to_le_bytes()); // inline value
    t.extend_from_slice(&0u32.to_le_bytes()); // no further IFD
    t
  }

  #[cfg(feature = "exif")]
  #[test]
  fn replay_exif_events_shared_processed_cycle_guard() {
    // The shared-`$$et{PROCESSED}` event replay (`ExifTool.pm:9061-9072` +
    // `PNG.pm:1193`). An EXIF event's IFD0 is BLOCKED only when its `$addr`
    // matches an already-recorded chain directory (IFD0 OR trailing IFD); an
    // `ExifProfile` OR `ResetOnlyProfile` event first CLEARS the processed set.
    // We assert, per event, whether it CONTRIBUTED tags (non-empty `ExifMeta`)
    // and whether it raised a cross-source cycle-guard warning.
    //
    // `(contributed, n_cycle_warnings, first_cycle_warning_or_empty)`.
    let collect = |evs: &[PngExifEvent]| -> Vec<(bool, usize, String)> {
      replay_exif_events(evs)
        .iter()
        .map(|r| {
          let contributed = r.meta().is_some_and(|m| !m.entries().is_empty());
          let w = r.cycle_guard_warnings();
          (
            contributed,
            w.len(),
            w.first().map(|s| s.to_string()).unwrap_or_default(),
          )
        })
        .collect()
    };
    // IFD0 offset is the discriminator; `val` keeps the blocks distinct.
    let exif = |ifd0: u32, val: u16| PngExifEvent::NativeTiff(tiff_ifd0(ifd0, val, 0));
    let prof = |ifd0: u32, val: u16| PngExifEvent::ExifProfile(tiff_ifd0(ifd0, val, 0));
    let reset = || PngExifEvent::ResetOnlyProfile;
    const W_IFD0: &str = "IFD0 pointer references previous IFD0 directory";

    // eXIf@8 THEN profile@8: eXIf processes (addr 8 done), profile RESETS the
    // set then processes ⇒ BOTH contribute, NO cycle warning.
    assert_eq!(
      collect(&[exif(8, 1), prof(8, 2)]),
      vec![(true, 0, String::new()), (true, 0, String::new())],
    );
    // profile@8 THEN eXIf@8: profile resets+processes (addr 8 done), eXIf
    // collides on addr 8 ⇒ eXIf BLOCKED + cycle warning (the discriminating drop).
    assert_eq!(
      collect(&[prof(8, 1), exif(8, 2)]),
      vec![(true, 0, String::new()), (false, 1, W_IFD0.to_string())],
    );
    // eXIf@8 THEN eXIf@8: first processes, second collides ⇒ BLOCKED + warning.
    assert_eq!(
      collect(&[exif(8, 1), exif(8, 2)]),
      vec![(true, 0, String::new()), (false, 1, W_IFD0.to_string())],
    );
    // profile@8 THEN profile@8: each resets ⇒ BOTH contribute, NO warning.
    assert_eq!(
      collect(&[prof(8, 1), prof(8, 2)]),
      vec![(true, 0, String::new()), (true, 0, String::new())],
    );
    // THE OFFSET DISCRIMINATOR: profile@8 THEN eXIf@40 — DIFFERENT addr ⇒ NO
    // collision, BOTH contribute.
    assert_eq!(
      collect(&[prof(8, 1), exif(40, 2)]),
      vec![(true, 0, String::new()), (true, 0, String::new())],
    );
    // THE RESET-ONLY DISCRIMINATOR (the new event): eXIf@8 THEN ResetOnlyProfile
    // THEN eXIf@8. The reset-only event clears the set (contributing NO tags and
    // NO warning), so the SECOND eXIf@8 re-processes cleanly ⇒ BOTH eXIf
    // contribute, NO cycle warning (oracle-verified: an icc/iptc/8bim/xmp or
    // XMP-content profile un-blocks the following same-addr eXIf).
    assert_eq!(
      collect(&[exif(8, 1), reset(), exif(8, 2)]),
      vec![
        (true, 0, String::new()),
        (false, 0, String::new()), // reset-only: no meta, no warning
        (true, 0, String::new()),
      ],
    );
    // 3 native events all @8: first processes, next two collide ⇒ 2 BLOCKED
    // (so the drain emits the cycle warning TWICE, matching bundled `[x2]`).
    assert_eq!(
      collect(&[exif(8, 1), exif(8, 2), exif(8, 3)]),
      vec![
        (true, 0, String::new()),
        (false, 1, W_IFD0.to_string()),
        (false, 1, W_IFD0.to_string()),
      ],
    );
    // Malformed header is attempted (meta None — no tags) and registers no addr,
    // so two malformed events do not collide with each other (no warnings).
    let bad = |b: &[u8]| PngExifEvent::NativeTiff(b.to_vec());
    assert_eq!(
      collect(&[bad(b"II\x2a"), bad(b"XX")]),
      vec![(false, 0, String::new()), (false, 0, String::new())],
    );
  }

  #[cfg(feature = "exif")]
  #[test]
  fn replay_exif_events_cross_source_trailing_ifd_collision() {
    // THE TRAILING-IFD CASE the IFD0-only model missed. Event 1 = IFD0@8 +
    // trailing IFD1@40; event 2 = IFD0@40. Event 1 records BOTH addr 8 (IFD0)
    // and addr 40 (IFD1) in the shared `$$et{PROCESSED}`. Event 2's IFD0 (addr
    // 40) therefore collides with the RECORDED TRAILING IFD ⇒ BLOCKED, and the
    // cycle-guard warning names the previous directory `IFD1` (not `IFD0`),
    // exactly as bundled 13.59 (see tests/png.rs's oracle-verified twin).
    let ev1 = PngExifEvent::NativeTiff(tiff_ifd0_and_ifd1(1, 40, 2));
    let ev2 = PngExifEvent::NativeTiff(tiff_ifd0(40, 3, 0));
    let events = [ev1, ev2];
    let replays = replay_exif_events(&events);
    // Event 1 contributes (IFD0 + IFD1 tags), no cycle warning.
    assert!(replays[0].meta().is_some_and(|m| !m.entries().is_empty()));
    assert!(replays[0].cycle_guard_warnings().is_empty());
    // Event 2's IFD0 is blocked by event 1's trailing IFD1 ⇒ no tags + the
    // `references previous IFD1` warning.
    assert!(replays[1].meta().is_some_and(|m| m.entries().is_empty()));
    assert_eq!(
      replays[1].cycle_guard_warnings(),
      &[SmolStr::from(
        "IFD0 pointer references previous IFD1 directory"
      )],
    );
  }

  #[test]
  fn raw_profile_exif_text_routes_to_exif_event_no_text_record() {
    // End-to-end through decode_text: a `Raw profile type exif` tEXt yields a
    // single ExifProfile event (for the chained EXIF walk) and pushes NO
    // text record.
    let mut tiff = Vec::new();
    tiff.extend_from_slice(b"II");
    tiff.extend_from_slice(&0x002a_u16.to_le_bytes());
    tiff.extend_from_slice(&0x0000_0008_u32.to_le_bytes());
    tiff.extend_from_slice(&0x0000_u16.to_le_bytes()); // 0 entries
    tiff.extend_from_slice(&0x0000_0000_u32.to_le_bytes());
    // Build the hex body `\nexif\n  <len>\n<hex>`.
    let hexstr: String = tiff.iter().map(|b| std::format!("{b:02x}")).collect();
    let mut body = std::format!("\nexif\n{:8}\n", tiff.len()).into_bytes();
    body.extend_from_slice(hexstr.as_bytes());
    body.push(b'\n');
    let mut payload = b"Raw profile type exif\0".to_vec();
    payload.extend_from_slice(&body);

    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&1u32.to_be_bytes());
    ihdr.extend_from_slice(&1u32.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr));
    bytes.extend_from_slice(&chunk(b"tEXt", &payload));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    // The decoded TIFF lands as a single ExifProfile event (walk order),
    // surfaced by `exif_events` for the chained walk.
    assert_single_exif_event(&meta, true, &tiff);
    assert!(
      meta.text_records().is_empty(),
      "raw-profile keyword must NOT push a text record, got {:?}",
      meta.text_records(),
    );
    assert!(meta.warnings().is_empty(), "got {:?}", meta.warnings());
  }

  #[test]
  fn truncated_mid_chunk_data_yields_warning() {
    // Sig + IHDR header declaring 100 bytes but only 5 provided.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    bytes.extend_from_slice(&100u32.to_be_bytes());
    bytes.extend_from_slice(b"IHDR");
    bytes.extend_from_slice(b"\x00\x00\x00\x00\x00");
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert!(meta.warnings().iter().any(|w| w == "Corrupted PNG image"),);
  }

  #[test]
  fn chunk_with_bad_crc_does_not_warn_in_default_mode() {
    // Construct a chunk whose CRC is intentionally wrong. Bundled only
    // verifies CRC under `-verbose` / `-validate`; in the default mode
    // (which `extract_info` uses) the CRC is silently accepted.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    // Hand-build the IHDR with a wrong CRC.
    bytes.extend_from_slice(&13u32.to_be_bytes());
    bytes.extend_from_slice(b"IHDR");
    bytes.extend_from_slice(&ihdr_data);
    bytes.extend_from_slice(&0xdead_beef_u32.to_be_bytes()); // intentional bad CRC
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    // The IHDR data should still have decoded; default mode does NOT warn
    // about bad CRC.
    assert_eq!(meta.dimensions(), Some((1, 1)));
    assert!(meta.warnings().iter().all(|w| !w.contains("Bad CRC")));
  }
}
