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
//!   (`PNG.pm:1169`) and dispatched to the embedded module. The dispatch splits:
//!   - **EXIF-bearing** — `Raw profile type exif` (`:710`) and the EXIF-content
//!     arm of `Raw profile type APP1` (`:689`) push
//!     [`crate::metadata::PngExifEvent::ExifProfile`] (reset + `ProcessTIFF`)
//!     into the ordered [`crate::metadata::PngMeta::exif_events`] stream the
//!     `eXIf` chunk also feeds.
//!   - **XMP** — `Raw profile type xmp` (`:746`) and the XMP-content arm of
//!     `Raw profile type {exif,APP1}` (`:1236`) hex-decode to a raw XMP packet
//!     that `ProcessProfile` feeds to `ProcessDirectory(XMP::Main)` =
//!     `ProcessXMP`. exifast HAS a ported XMP module, so (when the `xmp` feature
//!     is built) the packet is captured into
//!     [`crate::metadata::PngMeta::xmp_profiles`] and decoded into `XMP-*:*`
//!     tags via [`crate::formats::xmp::parse_borrowed`]; the `$$et{PROCESSED}`
//!     reset (`:1193`) is modeled by a parallel
//!     [`crate::metadata::PngExifEvent::ResetOnlyProfile`]. Without the `xmp`
//!     feature the packet is dropped (faithful "no module") but the reset stays.
//!   - **No ported module** — `icc` / `icm` (ICC_Profile), `iptc` / `8bim`
//!     (Photoshop), AND any unrecognized-content `exif`/`APP1` — push
//!     [`crate::metadata::PngExifEvent::ResetOnlyProfile`] (no tags, but
//!     `ProcessProfile` STILL resets `$$et{PROCESSED}`, `:1193`, which the event
//!     models — oracle-verified). ICC_Profile / Photoshop / IPTC remain deferred
//!     (no ported module; tracked under #179 follow-ups).
//!   The wrong-size warning (`:1172`) and the `Unknown raw profile` warning
//!   (`:1267`) are still emitted. A MALFORMED raw profile (framing fails,
//!   `:1166`) pushes NO event (bundled `return 0`s before the reset). In NO case
//!   is the `PNG:"Raw profile type X"` keyword=hex text tag emitted (bundled
//!   emits the DECODED tags or nothing).
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
//! - **Private/vendor chunks** (the lowercase-second-char convention,
//!   `PNG.pm:331-382`). The two `Binary => 1` chunks with NO SubDirectory ARE
//!   ported, each emitted as the `(Binary data N bytes, …)` placeholder
//!   (rendered from the payload LENGTH alone — the bytes are never retained):
//!   - **`iDOT`** (Apple `AppleDataOffsets`, `PNG.pm:331-342`) — `decode_idot`.
//!   - **`gdAT`** (`GainMapImage`, `Groups => { 2 => 'Preview' }`,
//!     `PNG.pm:374-378`) — `decode_gdat`.
//!   The four genuinely-subsystem chunks all dispatch into large SubDirectory
//!   subsystems exifast does not have, so they are still deferred (chunk-walk
//!   continues past them):
//!   - **`caBX`** (`JUMBF`, `PNG.pm:343-346`) → `Jpeg2000::Main` — the whole
//!     JUMBF / C2PA box subsystem (`Jpeg2000.pm`, ~1700 lines).
//!   - **`cpIp`** (`OLEInfo`, `PNG.pm:354-365`) → `FlashPix::Main` via
//!     `ProcessFPX` (~1200 lines, the OLE compound-document parser). Its
//!     `Condition` also mutates `FileType PNG → "PNG Plus"`.
//!   - **`meTa`** (`PNG.pm:368-372`) → `XMP::XML` (`ProcessXMP` bare-XML path,
//!     UTF-16 BOM XML). exifast's XMP port accepts only XMP-rooted input.
//!   - **`seAl`** (`SEAL`, `PNG.pm:380-382`) → `XMP::SEAL` via `ProcessSEAL`
//!     (SEAL content-authentication, delegates to `ProcessXMP` + `FoundSEAL`).
//!   For a chunk whose SubDirectory extracts NOTHING, bundled falls back to
//!   emitting the chunk as a `Binary` tag under its Name (`PNG.pm:1107`/`1116`-
//!   `1146`, `$compressed = 1` at `:1028`); but for any real sample the
//!   subsystem extracts tags, so a binary-fallback-only port would diverge —
//!   each needs its full sub-port. (#142)
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

// Golden-v2 Contract 3c (Phase C, slice S2): panic-safety by construction —
// every raw index/slice is converted to a checked `.get()` form below.
#![deny(clippy::indexing_slicing)]

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
    // The leaf `FormatParser::parse` Context is the byte slice alone — no
    // extension channel. The engine dispatch uses the extension-aware
    // [`parse_with_ext`] instead (see the `AnyParser::Png` arm), so the
    // `.apng`-extension `PNG → APNG` promotion of the after-IDAT warning's
    // FileType reaches that path; here it stays `acTL`-driven only.
    parse_inner(data, None)
  }
}

/// Lib-first direct entry — parse a whole PNG file buffer into a typed
/// [`PngMeta`]. Returns `None` ONLY for a non-PNG (signature mismatch).
///
/// The filename/extension is unknown on this direct path, so the firing-point
/// `$$et{FileType}` of the after-IDAT warning is driven solely by the in-stream
/// `acTL` override (no extension-derived `PNG → APNG` promotion). Callers that
/// know the file extension (the engine dispatch) use [`parse_with_ext`].
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today; reserved).
pub fn parse_borrowed(data: &[u8]) -> Option<PngMeta<'_>> {
  parse_inner(data, None)
}

/// Extension-aware entry — parse a whole PNG file buffer, threading the
/// uppercased dotless file extension (`$$self{FILE_EXT}`) so the after-IDAT
/// `Text/EXIF chunk(s) found after <FileType> IDAT` warning can reflect the
/// extension-derived `SetFileType` promotion.
///
/// ExifTool runs `SetFileType` BEFORE the chunk walk (ExifTool.pm:9677-9706):
/// a PNG-signature file named with a PNG-rooted extension takes that sub-type
/// as `$$et{FileType}` via the `%fileTypeLookup` sub-type-by-extension rule
/// (`APNG`/`MNG`/`JNG` all map to base module `PNG`, [`crate::filetype_data`])
/// the instant the type is set, with NO `acTL` required — `.apng`→`APNG`,
/// `.mng`→`MNG`, `.jng`→`JNG`, else `PNG`. The `acTL` chunk's
/// `OverrideFileType("APNG", …)` (PNG.pm:776) is a SECOND, in-stream source
/// that SUPERSEDES the extension with `APNG`. So at the firing point the
/// warning's FileType is `APNG` iff an `acTL` has already been dispatched,
/// otherwise the extension-resolved sub-type — exactly what [`parse_inner`]
/// threads here. `ext` borrows on an independent (elided) lifetime; only
/// `data` drives the returned Meta.
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today; reserved).
pub fn parse_with_ext<'a>(data: &'a [u8], ext: Option<&str>) -> Option<PngMeta<'a>> {
  parse_inner(data, ext)
}

/// The chunk walker proper. `PNG.pm:1424` `return 0 unless $raf->Read($sig,8)
/// == 8 and $pngLookup{$sig}` ⇒ signature mismatch / short read returns
/// `None`. Otherwise this ALWAYS returns `Some(meta)` (truncations and CRC
/// failures land as warnings in the [`PngMeta`]).
fn parse_inner<'a>(data: &'a [u8], ext: Option<&str>) -> Option<PngMeta<'a>> {
  // `PNG.pm:1424` signature gate. Checked `.get()`: a too-short buffer makes
  // `.get(..N)` `None` (≠ `Some(sig)`) ⇒ same early-return as the old
  // `data.len() < N` guard ⇒ byte-identical.
  if data.get(..PNG_SIGNATURE.len()) != Some(PNG_SIGNATURE.as_slice()) {
    return None;
  }

  // Extension-derived FileType (ExifTool's `SetFileType` BEFORE the walk,
  // ExifTool.pm:9677-9706). A PNG-signature file is detected as base type
  // `PNG`; the sub-type-by-extension rule (ExifTool.pm:9686-9692) then
  // promotes it to whatever PNG-rooted sub-type the file's extension names —
  // `.apng`→`APNG`, `.mng`→`MNG`, `.jng`→`JNG` (each row roots to `PNG` in
  // [`crate::filetype_data`]), or stays `PNG` for `.png`/no ext. `ext` arrives
  // already uppercased + dotless (`$$self{FILE_EXT}`). This resolved STRING is
  // the firing-point `$$et{FileType}` the after-IDAT warning interpolates, the
  // single source of truth (the OTHER source being the `acTL` `OverrideFileType`,
  // which supersedes it once seen). Storing the full string — not just an
  // `== "APNG"` bool — closes the warning-FileType-source class for ALL
  // PNG-rooted extensions at once (oracle-verified vs bundled 13.59: `.png`→
  // `after PNG IDAT`, `.apng`→`APNG`, `.mng`→`MNG`, `.jng`→`JNG`; an `acTL`
  // before IDAT overrides any of them → `APNG`).
  let ext_file_type = crate::parser::resolved_file_type_name("PNG", None, ext);

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

    // `header` is `data.get(pos..pos + 8)` (length exactly 8). Checked-indexing
    // (Phase C S2): the slice-pattern binds the same 8 bytes `header[0..8]` did;
    // the `else` is unreachable (the `.get(pos..pos + 8)` above succeeded) ⇒
    // byte-identical.
    let &[h0, h1, h2, h3, h4, h5, h6, h7, ..] = header else {
      return Some(meta);
    };
    let len_be = [h0, h1, h2, h3];
    let len = u32::from_be_bytes(len_be) as usize;
    let chunk_type: [u8; 4] = [h4, h5, h6, h7];

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
      // `$$et{FileType}` interpolates the CURRENT resolved FileType at the
      // point the warning fires (`PNG.pm:1604`), NOT a fixed `PNG`. That value
      // has TWO sources:
      //
      //   (a) the EXTENSION-derived `SetFileType`, run BEFORE the walk: a
      //       PNG-signature file named with a PNG-rooted extension takes that
      //       sub-type as `$$et{FileType}` from the start (ExifTool.pm:9686-9692),
      //       with NO `acTL` required — `.apng`→`APNG`, `.mng`→`MNG`,
      //       `.jng`→`JNG`, else `PNG`. `ext_file_type` is that full resolved
      //       string (computed once at the top via the same
      //       `resolved_file_type_name` resolution as finalization);
      //   (b) the `acTL` `AnimationFrames` RawConv (`PNG.pm:776`
      //       `OverrideFileType("APNG", …)`), which promotes the FileType to
      //       `APNG` the instant its `acTL` chunk is dispatched (`FoundPNG`,
      //       `PNG.pm:1653`) — superseding the extension type. An `acTL` SEEN
      //       EARLIER in the walk (before this IDAT) makes it say `APNG`, while
      //       an `acTL` that comes AFTER (or is absent) does not. `meta.is_apng()`
      //       reads that exact walk-time state: `set_animation_frames` ran only
      //       for an already-dispatched `acTL` (an earlier loop iteration), so a
      //       post-IDAT `acTL` is not yet reflected — preserving ExifTool's
      //       firing-point semantics.
      //
      // The firing-point FileType is therefore `APNG` when the `acTL` override
      // has already fired, otherwise the extension-resolved string. Using the
      // full string — not an `== "APNG"` collapse — closes the
      // warning-FileType-source class for ALL PNG-rooted extensions
      // (oracle-verified vs bundled 13.59: `.png`→`PNG`, `.apng`→`APNG`,
      // `.mng`→`MNG`, `.jng`→`JNG`; `acTL`-before any of them → `APNG`;
      // `.mng` `acTL`-AFTER → `MNG` at the firing point, even though the final
      // FileType becomes `APNG`).
      let file_type = if meta.is_apng() {
        "APNG"
      } else {
        ext_file_type
      };
      let was_str = was.iter().map(|&b| b as char).collect::<String>();
      let msg = std::format!(
        "Text/EXIF chunk(s) found after {file_type} {was_str} (may be ignored by some readers)",
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
    // ----- iDOT (PNG.pm:331-342) -----------------------------------------
    b"iDOT" => decode_idot(meta, data),
    // ----- gdAT (PNG.pm:374-378) -----------------------------------------
    b"gdAT" => decode_gdat(meta, data),
    // ----- acTL (PNG.pm:302-307, sub-table :766-782) ---------------------
    b"acTL" => decode_actl(meta, data),
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
    // Every other chunk is in bundled's table (`cHRM`, `dSIG`, …) but we DO
    // NOT extract their tags in this Phase-2 port — they are valid PNG chunks
    // the walker skips silently (`PNG.pm:1657` table miss). The chunk walker
    // continues to the next chunk; this matches bundled when the chunk is
    // recognized but has no extractor. (`fcTL`/`fdAT` are likewise skipped —
    // bundled has NO table for them, `PNG.pm:329-330` is comment-only — so the
    // APNG metadata is the `acTL` summary alone, oracle-verified vs 13.59.)
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
  // Checked-indexing (Phase C S2): the slice-pattern binds the same 13 bytes
  // `data[0..13]` did; a shorter buffer takes the same skip path as the old
  // `data.len() < 13` guard ⇒ byte-identical.
  let &[d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, ..] = data else {
    return;
  };
  meta.set_ihdr(IhdrFields {
    width: u32::from_be_bytes([d0, d1, d2, d3]),
    height: u32::from_be_bytes([d4, d5, d6, d7]),
    bit_depth: d8,
    color_type: d9,
    compression: d10,
    filter: d11,
    interlace: d12,
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
  // Checked-indexing (Phase C S2): the slice-pattern binds the same 9 bytes
  // `data[0..9]` did; a shorter buffer skips like the old guard ⇒ byte-identical.
  let &[d0, d1, d2, d3, d4, d5, d6, d7, units, ..] = data else {
    return;
  };
  let ppu_x = u32::from_be_bytes([d0, d1, d2, d3]);
  let ppu_y = u32::from_be_bytes([d4, d5, d6, d7]);
  meta.set_phys(ppu_x, ppu_y, units);
}

// ===========================================================================
// iDOT decoder — PNG.pm:331-342
// ===========================================================================

/// `iDOT` decoder (`PNG.pm:331-342`, ref NealKrawetz). Apple's private
/// "data offsets" chunk:
///
/// ```text
/// iDOT => {
///     Name => 'AppleDataOffsets',
///     Binary => 1,
///     # int32u Divisor, Unknown, TotalDividedHeight, Size,
///     #        DividedHeight1, DividedHeight2, IDAT_Offset2
/// },
/// ```
///
/// The table has `Name => 'AppleDataOffsets', Binary => 1` and NO
/// `SubDirectory` — so `FoundPNG` (`PNG.pm:970-1148`) resolves the tagInfo,
/// finds no SubDirectory, and stores the WHOLE raw chunk value under
/// `PNG:AppleDataOffsets`. Because the tag is `Binary => 1` it renders as the
/// universal `(Binary data N bytes, use -b option to extract)` placeholder at
/// any size (oracle-verified vs bundled 13.59); `-b` extracts the raw bytes,
/// but the JSON path consults only the byte LENGTH. We retain the length, not
/// the payload — a crafted large-but-present `iDOT` chunk passes the chunk
/// bounds but never forces a payload-sized clone. The chunk's internal int32u
/// layout documented above is informational only (bundled never decodes the
/// sub-fields — there is no sub-table).
fn decode_idot(meta: &mut PngMeta<'_>, data: &[u8]) {
  meta.set_apple_data_offsets(data.len());
}

// ===========================================================================
// gdAT decoder — PNG.pm:374-378
// ===========================================================================

/// `gdAT` decoder (`PNG.pm:374-378`). The gain-map preview image chunk:
///
/// ```text
/// gdAT => {
///     Name => 'GainMapImage',
///     Groups => { 2 => 'Preview' },
///     Binary => 1,
/// },
/// ```
///
/// Identical shape to `iDOT`: `Name => 'GainMapImage', Binary => 1` with NO
/// `SubDirectory`, so `FoundPNG` stores the WHOLE chunk value under
/// `PNG:GainMapImage` and renders the universal `(Binary data N bytes, use -b
/// option to extract)` placeholder (`-j`); `-b` extracts the raw embedded
/// image. The only extra is the family-2 `Preview` group (`Groups => { 2 =>
/// 'Preview' }`), which does not affect the `-G1` family-1 group (`PNG`). As
/// with `iDOT` we retain only the byte LENGTH — the embedded gain-map image
/// (a full PNG/HEIC payload) is never cloned. Oracle-verified vs bundled
/// 13.59.
fn decode_gdat(meta: &mut PngMeta<'_>, data: &[u8]) {
  meta.set_gain_map_image(data.len());
}

// ===========================================================================
// acTL decoder — PNG.pm:302-307 + sub-table :766-782
// ===========================================================================

/// `acTL` decoder — the animated-PNG Animation Control chunk
/// (`PNG.pm:302-307`), whose SubDirectory is the `AnimationControl`
/// `ProcessBinaryData` table (`PNG.pm:766-782`, `FORMAT => 'int32u'`):
///
/// ```text
/// 0 => { Name => 'AnimationFrames',
///        RawConv => '$self->OverrideFileType("APNG", undef, "PNG"); $val' },
/// 1 => { Name => 'AnimationPlays', PrintConv => '$val || "inf"' },
/// ```
///
/// The chunk payload is two big-endian `int32u`: `num_frames` then
/// `num_plays` (the APNG spec's acTL layout). `ProcessBinaryData` reads each
/// field at its `int32u` offset and emits it IFF `offset + size` is within the
/// chunk length (`ExifTool.pm`: `my $more = $size - $entry; last if $more <=
/// 0`). So each field is INDEPENDENTLY available:
///
/// * bytes `0..4` present (len ≥ 4) ⇒ `AnimationFrames`,
/// * bytes `4..8` present (len ≥ 8) ⇒ `AnimationPlays`.
///
/// A runt 4-to-7-byte acTL therefore emits `AnimationFrames` (and fires the
/// `APNG` FileType override) but NOT `AnimationPlays`; a `< 4`-byte acTL emits
/// neither and leaves `File:FileType` as `PNG`. We mirror this per-field with
/// safe slicing rather than gating both tags on the full 8 bytes (the latter
/// would wrongly drop the frame count + the `APNG` promotion for a 4-to-7-byte
/// acTL). Oracle-verified vs bundled 13.59 at 4/7/8-byte (and `< 4`) lengths.
///
/// `AnimationFrames`'s RawConv emits the raw `num_frames` value UNCHANGED; its
/// only side effect is `OverrideFileType("APNG", undef, "PNG")` (`PNG.pm:776`),
/// modelled by [`PngMeta::is_apng`] driving the `File:FileType` promotion in
/// the parser — so the override is gated on `AnimationFrames` (len ≥ 4), NOT on
/// `AnimationPlays`. `AnimationPlays`'s `$val || "inf"` PrintConv (`0` ⇒
/// `"inf"`) is applied at emission.
fn decode_actl(meta: &mut PngMeta<'_>, data: &[u8]) {
  // Per-field `ProcessBinaryData` availability (the #128 MPEG / #149 av1C
  // class). `AnimationFrames` (offset 0) needs bytes `0..4`; setting it also
  // arms the `APNG` FileType override ([`PngMeta::is_apng`]). `AnimationPlays`
  // (offset 4) needs bytes `4..8` and is independent of the frame count — a
  // 4-to-7-byte acTL omits it.
  if let Some(&frames) = data.first_chunk::<4>() {
    meta.set_animation_frames(u32::from_be_bytes(frames));
  }
  if let Some(plays) = data.get(4..8).and_then(|s| <[u8; 4]>::try_from(s).ok()) {
    meta.set_animation_plays(u32::from_be_bytes(plays));
  }
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

/// Outcome of a size-bounded zXIf inflate ([`inflate_chunk_limited`]). Unlike
/// [`Inflate`], the failure arm carries the number of transient output bytes
/// [`miniz_oxide`] actually MATERIALIZED before giving up, so the caller can
/// charge that allocation to the file-wide budget ([`MAX_ZXIF_INFLATE_TOTAL`]).
/// This is what makes the memory bound COMPREHENSIVE: a FAILED inflate — most
/// importantly a CAP-HIT, where miniz grows its buffer all the way to `max_size`
/// before refusing — counts toward the running total exactly like a successful
/// one, so a PNG of many over-cap zXIf chunks cannot replay a near-cap inflate
/// ATTEMPT per chunk (the prior code charged only on success, leaving the budget
/// untouched after each cap-hit warning — finding 1).
enum LimitedInflate {
  /// Clean inflate ⇒ the decompressed buffer (charged on retain/re-entry).
  Ok(Vec<u8>),
  /// Inflate failed — corrupt zlib OR the `max_size` cap was hit. `allocated`
  /// is the transient output miniz held before aborting (`DecompressError.output`
  /// length): exactly `max_size` on a cap-hit (`HasMoreOutput` returns the buffer
  /// grown to the limit), and only the small initial buffer for an early
  /// corruption error. Both map to bundled's single `Error inflating $tag` arm
  /// (`PNG.pm:943`); the caller charges `allocated` so a cap-hit EXHAUSTS the
  /// file-wide budget (`remaining == 0` ⇒ later chunks skip with no further
  /// inflate attempt) while a small corrupt chunk barely dents it.
  Err { allocated: usize },
}

/// Inflate a PNG compressed-chunk payload (method `0`, ZLIB-wrapped deflate)
/// bounded to at most `max_size` DECOMPRESSED bytes — the DoS-guarded sibling of
/// [`inflate_chunk`] used ONLY on the nested-zXIf re-entry path
/// ([`process_exif_block`], `PNG.pm:1389`), where an attacker controls the
/// decompressed content and can chain large expansions.
///
/// Same faithful semantics as [`inflate_chunk`] (`PNG.pm:929-948`): a clean
/// inflate ⇒ [`LimitedInflate::Ok`], a corrupt stream ⇒ [`LimitedInflate::Err`]
/// (the `Error inflating $tag` arm). The ONE addition is the size cap:
/// [`miniz_oxide`]'s `decompress_to_vec_zlib_with_limit` never grows its output
/// buffer past `max_size`, returning `Err(HasMoreOutput)` (with the buffer grown
/// to exactly `max_size`) if the stream would exceed it — so an over-budget level
/// is reported as [`LimitedInflate::Err`] (semantically "could not decompress this
/// chain", the same `Error inflating <tag>` warning bundled raises for any
/// aborted inflate) rather than allocating an unbounded buffer. The failure arm
/// reports `allocated` = the bytes miniz transiently held (`DecompressError`'s
/// `output` length) so the caller can charge that transient peak to the file-wide
/// budget. `max_size == 0` ⇒ immediate `Err { allocated: 0 }` (the budget is
/// already exhausted — never call the inflater with a zero cap; no allocation).
fn inflate_chunk_limited(compressed: &[u8], max_size: usize) -> LimitedInflate {
  if max_size == 0 {
    return LimitedInflate::Err { allocated: 0 };
  }
  match miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(compressed, max_size) {
    Ok(bytes) => LimitedInflate::Ok(bytes),
    // `DecompressError.output` is the partial buffer miniz materialized before
    // aborting: `max_size` on a cap-hit (`HasMoreOutput`), or the small initial
    // buffer (`min(2*input.len(), max_size)`) on an early corruption error. Both
    // are the actual transient allocation for this attempt — charge exactly that
    // (clamped to `max_size`, which it never exceeds) so the file-wide bound
    // accounts for FAILED inflates too.
    Err(e) => LimitedInflate::Err {
      allocated: e.output.len().min(max_size),
    },
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
  /// (→ `Photoshop::Main`, `PNG.pm:735`/`:755`). The body IS hex-decoded + the
  /// wrong-size warning IS still emitted (faithful to `ProcessProfile`, which
  /// runs before the module dispatch), but the decoded bytes are then
  /// SUPPRESSED (no tags) — the missing-sub-port deferral. `name` is the
  /// wrong-size-warning Name.
  SuppressedTable { name: &'static str },
  /// `Raw profile type xmp` (`PNG.pm:746`, Name `XMP_Profile`) → `XMP::Main`.
  /// `ProcessProfile` hex-decodes the body and dispatches it to
  /// `ProcessDirectory(XMP::Main)` = `ProcessXMP` on the RAW packet (no header
  /// strip). exifast HAS a ported XMP module ([`crate::formats::xmp`], built
  /// when the `xmp` feature is active), so the decoded packet is captured for
  /// `XMP-*` tag emission — while the `$$et{PROCESSED}` reset (`PNG.pm:1193`)
  /// is still modeled by the `ResetOnlyProfile` event the same chunk pushes.
  /// `name` is the wrong-size-warning Name (`XMP_Profile`).
  XmpTable { name: &'static str },
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
    // XMP → the ported XMP module (decode the packet into XMP-* tags).
    b"Raw profile type xmp" => Some(RawProfileKind::XmpTable {
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
  // Checked-indexing (Phase C S2): `type_end` is a `position()` result (so
  // `rest[..type_end]` / `rest[type_end + 1..]` are in-range); every
  // `after_type[i]` had an `i < after_type.len()` guard; `digit_start..i` and
  // `i + 1..` are in-range after the digit scan + `\n` check ⇒ byte-identical.
  let type_end = rest.iter().position(|&b| b == b'\n')?;
  let profile_type = rest.get(..type_end).unwrap_or(&[]);
  let after_type = rest.get(type_end + 1..).unwrap_or(&[]);
  // `\s*(\d+)\n` — optional leading ASCII whitespace, then a decimal length,
  // then a newline. Perl `\s` is `[ \t\n\r\f\v]`; `\d` is `[0-9]`.
  let mut i = 0;
  while after_type.get(i).is_some_and(u8::is_ascii_whitespace) {
    i += 1;
  }
  let digit_start = i;
  while after_type.get(i).is_some_and(u8::is_ascii_digit) {
    i += 1;
  }
  // Need at least one digit and a terminating `\n` (`PNG.pm:1166` `(\d+)\n`).
  if i == digit_start || after_type.get(i) != Some(&b'\n') {
    return None;
  }
  // `$2` is ASCII digits — parse as the declared length. A value that overflows
  // `usize` cannot equal any real decoded length, so the wrong-size branch
  // fires; saturate to keep the comparison well-defined.
  let declared_len: usize = after_type
    .get(digit_start..i)
    .and_then(|d| core::str::from_utf8(d).ok())
    .and_then(|s| s.parse::<usize>().ok())
    .unwrap_or(usize::MAX);
  let hex_region = after_type.get(i + 1..).unwrap_or(&[]);

  // `pack('H*', join('',split(' ',$3)))` — strip ASCII whitespace, then
  // hex-decode exactly as Perl `pack('H*', …)`:
  //   * `split ' '` (the magic single-space form) splits on RUNS of whitespace
  //     `[ \t\n\r\f\v]+` and strips leading whitespace; `join ''` collapses the
  //     fields — net effect is "remove all ASCII whitespace" (matched by the
  //     `is_ascii_whitespace` skip below).
  //   * `pack('H*')` then maps EVERY remaining char to a nibble via libperl's
  //     `(isALPHA(c) ? c + 9 : c) & 0xf` (empirically verified against Perl for
  //     all bytes 0..=255). So non-hex chars do NOT stop the decode — they
  //     contribute a (wrapped) nibble, exactly like ImageMagick-clean hex.
  //   * an odd final nibble is the HIGH half of a trailing byte whose low half
  //     is `0` (Perl pads, e.g. `pack('H*',"abc")` → `ab a0`… → `0xab 0xc0`).
  let mut decoded = Vec::with_capacity(hex_region.len().div_ceil(2));
  let mut hi: Option<u8> = None;
  for &b in hex_region {
    if b.is_ascii_whitespace() {
      continue;
    }
    let nib = pack_h_nibble(b);
    match hi.take() {
      None => hi = Some(nib),
      Some(h) => decoded.push((h << 4) | nib),
    }
  }
  // A leftover high nibble is Perl's odd-length pad: emit `<hi>0`.
  if let Some(h) = hi {
    decoded.push(h << 4);
  }

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

/// One Perl `pack('H*', …)` hex nibble: libperl's
/// `(isALPHA(c) ? c + 9 : c) & 0xf`. For `0-9A-Fa-f` this is the usual hex
/// value; for any other byte it is the SAME wrapped low nibble Perl produces
/// (verified against Perl `pack`/`unpack` for every byte `0..=255`), so a
/// noncanonical raw-profile chunk decodes byte-for-byte like ExifTool instead
/// of truncating at the first non-hex char.
const fn pack_h_nibble(b: u8) -> u8 {
  // `isALPHA` is the C-locale ASCII test: `A-Z` / `a-z` only (bytes ≥ 128 and
  // all symbols take the bare `& 0xf` branch).
  if b.is_ascii_alphabetic() {
    b.wrapping_add(9) & 0x0f
  } else {
    b & 0x0f
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
  // 2. XMP APP1 (`PNG.pm:1236`) — strip the 29-byte `$xmpAPP1hdr` marker
  //    (`$dirInfo{DirStart} += $hdrLen`) and dispatch the remaining RAW XMP
  //    packet to `ProcessDirectory(XMP::Main)` = `ProcessXMP`. Capture the
  //    stripped packet for `XMP-*` tag emission (when the `xmp` feature is
  //    built). `ProcessProfile` has already RESET `$$et{PROCESSED}`
  //    (`PNG.pm:1193`) before this dispatch (oracle-confirmed: a `Raw profile
  //    type {exif,APP1}` carrying XMP un-blocks a following same-`$addr`
  //    `eXIf`), modeled by the `ResetOnlyProfile` event `capture_xmp_profile`
  //    pushes.
  if let Some(packet) = bytes.strip_prefix(XMP_APP1_HDR) {
    capture_xmp_profile(meta, packet.to_vec());
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
///    [`RawProfileKind::XmpTable`] → [`capture_xmp_profile`] (decode the packet
///    into `XMP-*` tags via the ported XMP module + reset);
///    [`RawProfileKind::SuppressedTable`] → suppressed (ICC / IPTC / Photoshop
///    module not ported) + reset.
///
/// In NO case is a `PNG:"Raw profile type X"` text record pushed (bundled emits
/// the DECODED tags or nothing — never the keyword=hex text tag).
fn handle_raw_profile(meta: &mut PngMeta<'_>, kind: RawProfileKind, body: &[u8]) {
  let name = match kind {
    RawProfileKind::ExifTable { name }
    | RawProfileKind::SuppressedTable { name }
    | RawProfileKind::XmpTable { name } => name,
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
    // ICC / IPTC / Photoshop → module not ported; no tags emitted. Bundled
    // would `ProcessDirectory` into ICC_Profile / Photoshop, but crucially
    // `ProcessProfile` has ALREADY RESET `$$et{PROCESSED}` (`PNG.pm:1193`)
    // before that module dispatch — oracle-confirmed: a well-formed
    // `icc`/`iptc`/`8bim` profile un-blocks a following same-`$addr` `eXIf`. So
    // emit a reset-only event (the deferred module's tags stay unemitted; the
    // cross-source reset is the load-bearing effect).
    RawProfileKind::SuppressedTable { .. } => {
      meta.push_exif_event(PngExifEvent::ResetOnlyProfile);
    }
    // XMP → `ProcessDirectory(XMP::Main)` = `ProcessXMP` on the RAW hex-decoded
    // packet (`PNG.pm:746` → `ProcessProfile`'s `$tagTablePtr ne $exifTable`
    // branch, no header strip). Capture the packet for `XMP-*` tag emission;
    // ALSO push the `ResetOnlyProfile` event so the `$$et{PROCESSED}` reset
    // (`PNG.pm:1193`) un-blocks a following same-`$addr` `eXIf` exactly as
    // before. When the `xmp` feature is NOT built the packet is dropped (the
    // PNG port falls back to the faithful "no XMP module" reset-only behaviour).
    RawProfileKind::XmpTable { .. } => {
      capture_xmp_profile(meta, profile.bytes);
    }
  }
}

/// Capture a hex-decoded XMP packet for `XMP-*` tag emission and push the
/// `$$et{PROCESSED}` reset event (`PNG.pm:1193`) the XMP profile dispatch
/// performs. The packet is stored only when the `xmp` feature is built;
/// otherwise just the reset is modeled (faithful "no ported XMP module").
fn capture_xmp_profile(meta: &mut PngMeta<'_>, packet: Vec<u8>) {
  #[cfg(feature = "xmp")]
  meta.push_xmp_profile(packet);
  #[cfg(not(feature = "xmp"))]
  let _ = packet;
  // The reset is performed for EVERY well-formed profile (`PNG.pm:1193`),
  // independent of whether the XMP tags are emitted.
  meta.push_exif_event(PngExifEvent::ResetOnlyProfile);
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
  // `after[1]`, the compressed profile starts at `after[2]`. Checked-indexing
  // (Phase C S2): the `after.len() < 2` guard makes both `Some` ⇒ byte-identical.
  let method = after.get(1).copied().unwrap_or(0);
  let payload = after.get(2..).unwrap_or(&[]);
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
  // Checked-indexing (Phase C S2): `after` always holds the NUL at index 0, so
  // `after.get(1..)` is `Some` ⇒ byte-identical to `&after[1..]`.
  let value_bytes = after.get(1..).unwrap_or(&[]);
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
  // compressed value starts at `after[2]`. Checked-indexing (Phase C S2): the
  // `after.len() < 2` guard makes both `Some` ⇒ byte-identical.
  let method = after.get(1).copied().unwrap_or(0);
  let payload = after.get(2..).unwrap_or(&[]);
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
  // Checked-indexing (Phase C S2): `after`/`after_l`/`after_t` each hold a NUL
  // at index 0, so `.get(1..)` is `Some`; `dat[0]`/`dat[1]`/`dat[2..]` are
  // bounded by the `dat.len() < 4` guard ⇒ byte-identical.
  let dat = after.get(1..).unwrap_or(&[]); // skip NUL
  // `PNG.pm:1343`: `length($dat) >= 4` — compressed + method + 2 NULs.
  if dat.len() < 4 {
    return;
  }
  let compressed = dat.first().copied().unwrap_or(0) != 0;
  let method = dat.get(1).copied().unwrap_or(0);
  // `PNG.pm:1345`: `split /\0/, substr($dat, 2), 3` — language, translated
  // keyword, then the value (which may contain raw NULs in compressed
  // payloads — but `split /\0/, …, 3` keeps the third field as the rest
  // of the string). We replicate that semantics: find the first NUL
  // (language end), the second NUL (translated-keyword end), then value
  // is the remainder.
  let rest = dat.get(2..).unwrap_or(&[]);
  let nul1 = rest.iter().position(|&b| b == 0);
  let Some(n1) = nul1 else { return };
  let (language_bytes, after_l) = rest.split_at(n1);
  let rest2 = after_l.get(1..).unwrap_or(&[]); // skip NUL
  let Some(n2) = rest2.iter().position(|&b| b == 0) else {
    return;
  };
  let (translated_bytes, after_t) = rest2.split_at(n2);
  let value_bytes = after_t.get(1..).unwrap_or(&[]); // skip NUL

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
  process_exif_block(meta, tag, data, 0);
}

/// Recursion-depth ceiling for nested zXIf inflate re-entry. Bundled's
/// `ProcessPNG_eXIf` → `FoundPNG` (level 2, `PNG.pm:1389`) → `ProcessPNG_eXIf`
/// loop has NO explicit cap — it relies on a level's `substr`/inflate failing —
/// so a maliciously crafted chunk that inflates to ANOTHER `\0`-typed (still
/// compressed) block at every level would recurse unboundedly (a stack-/CPU-
/// exhaustion DoS). Realistic input is at most doubly compressed (depth 2), so
/// this generous ceiling never fires on a well-formed file yet bounds the
/// pathological nest. At the ceiling we STOP and raise the `Error inflating
/// <tag>` warning — bundled would itself bottom out in `Error inflating` a level
/// or two deeper (a crafted nest can only end in an inflate/`substr` failure, not
/// a valid TIFF, beyond a sane depth), so the shape matches its
/// "could-not-decompress-this-chain" signal (`PNG.pm:943`, the same warning the
/// `PNG_nested_zxif` fixture pins) rather than a bespoke cap message.
const MAX_ZXIF_DEPTH: u32 = 8;

/// FILE-WIDE cumulative decompressed-size budget (bytes) for ALL zXIf inflation
/// in one PNG parse — every `zxIf`/`eXIf` chunk's nested-inflate chain (the
/// depth-`0` on-disk chunk + every `PNG.pm:1389` re-entry on an inflated buffer)
/// charges against this one aggregate cap, tracked on
/// [`crate::metadata::PngMeta::zxif_inflated_total`] across the whole walk.
///
/// Bundled's `Compress::Zlib::inflate` (`PNG.pm:937`) is UNBOUNDED — it inflates
/// each level's whole zlib stream into memory before recursing, so a small
/// crafted chunk that decompresses to a large `\0`-typed block (which then
/// decompresses to another large block, …) can force large allocations and
/// bottom out in an OOM. Worse, a successful `II`/`MM` inflate is retained as a
/// [`crate::metadata::PngExifEvent::NativeTiff`] that lives in
/// [`crate::metadata::PngMeta`] for the rest of the parse — so a small PNG with
/// MANY independent `zxIf` chunks, each inflating to a near-cap valid TIFF, would
/// accumulate retained EXIF memory as O(chunks × cap) if the budget reset per
/// chunk. We therefore bound the SUM of ALL inflated bytes across the ENTIRE file
/// to this single cap, so the COMPREHENSIVE invariant holds — at every instant the
/// total live zXIf-inflated memory (the one transient inflate buffer + every
/// retained TIFF) is ≤ this cap:
/// * each level's inflate is size-limited to the budget REMAINING after every
///   prior chunk's inflation ([`miniz_oxide`]'s `decompress_to_vec_zlib_with_limit`,
///   which never grows its buffer past the cap);
/// * EVERY inflate is charged to the file-wide running total — a successful one by
///   its output length, AND a FAILED one (corrupt OR cap-hit) by the bytes miniz
///   transiently materialized ([`LimitedInflate::Err`]'s `allocated`); a cap-hit
///   therefore allocates ~the cap and charges ~the cap, exhausting the budget so a
///   later over-cap chunk short-circuits (`remaining == 0`) rather than replaying a
///   near-cap inflate ATTEMPT per chunk;
/// * a retained `II`/`MM` TIFF is MOVED out of the (already-charged) inflate buffer
///   rather than cloned, so retention never transiently doubles the live buffer.
///
/// Once the aggregate is exhausted any further inflate stops with the same `Error
/// inflating <tag>` warning bundled raises for any aborted inflate (`PNG.pm:943`).
/// So total inflated-and-retained EXIF memory for the whole PNG is ≤ this cap (peak
/// included), NOT O(chunks × cap) and not 2× the cap.
///
/// 64 MiB is far above any realistic EXIF/TIFF zXIf payload — a compressed-EXIF
/// chunk carries a TIFF block (IFDs + at most an embedded preview), KB-to-low-MB
/// even for a RAW preview, and a real PNG carries at most ONE small (typically
/// uncompressed) `eXIf` — so this never fires on a well-formed file yet caps the
/// crafted decompression-bomb / many-zXIf chain at one bounded buffer's worth of
/// retained memory for the whole parse.
const MAX_ZXIF_INFLATE_TOTAL: usize = 64 * 1024 * 1024;

/// One `ProcessPNG_eXIf` pass (`PNG.pm:1358-1404`) over an EXIF `block`, faithful
/// down to the nested-zXIf re-entry. `depth` is the inflate-recursion level
/// (`0` = the on-disk `eXIf`/`zxIf` chunk; `n > 0` = the `n`-th `FoundPNG`
/// level-2 re-entry on an inflated buffer, `PNG.pm:1389`). The SAME logic runs
/// at every level (bundled re-enters this very subroutine):
///
/// 1. `^Exif\0\0` (`PNG.pm:1368`) ⇒ warn `Improper "Exif00" header …`, strip 6.
/// 2. `^(\0|II|MM)` (`PNG.pm:1374`): neither ⇒ warn `Invalid <tag> chunk`, stop.
/// 3. `II`/`MM` ⇒ a real TIFF: capture a native event (`ProcessTIFF`, NO
///    `$$et{PROCESSED}` reset, `PNG.pm:1358`).
/// 4. `\0` (`PNG.pm:1378`, compressed EXIF) ⇒ `substr($$dataPt, 5)` then inflate
///    (compression code 2, no method byte); a block shorter than 5 bytes makes
///    `substr` empty/`undef` so the inflate fails ⇒ `Error inflating <tag>`
///    (oracle-confirmed: bundled emits exactly this for a degenerate inner `\0`
///    block, with a harmless `substr outside of string` Perl notice). On a clean
///    inflate, RE-ENTER on the inflated buffer (`PNG.pm:1389`).
///
/// Bundled re-enters this very subroutine recursively for a `\0`-typed level
/// (`ProcessPNG_eXIf` → `FoundPNG` → `ProcessPNG_eXIf`), holding every parent
/// buffer live on the Perl stack. We unwrap the zXIf nest ITERATIVELY instead
/// (semantically identical — the same steps 1-4 at each level), which releases
/// each inflated buffer before inflating the next and lets us bound the work by
/// both DEPTH ([`MAX_ZXIF_DEPTH`], per chain) and CUMULATIVE decompressed SIZE
/// ([`MAX_ZXIF_INFLATE_TOTAL`], FILE-WIDE across every chunk via
/// [`PngMeta::zxif_inflated_total`]); either cap ⇒ the `Error inflating <tag>`
/// warning (the aborted-inflate shape, `PNG.pm:943`). Only one inflated buffer is
/// ever alive at a time, AND a clean `II`/`MM` inflate is MOVED (not cloned) into a
/// retained [`PngExifEvent::NativeTiff`] in `meta` — so charging EVERY inflate's
/// transient bytes to the file-wide running total (a success by its output length,
/// a corrupt/cap-hit failure by the bytes miniz materialized) bounds the TOTAL
/// inflated-and-retained EXIF memory for the whole PNG to the cap AT EVERY INSTANT,
/// defeating a many-`zxIf` decompression-bomb that would otherwise accumulate
/// O(chunks × cap) of retained buffers (see [`MAX_ZXIF_INFLATE_TOTAL`] for the
/// full invariant).
fn process_exif_block(meta: &mut PngMeta<'_>, tag: &str, block: &[u8], depth: u32) {
  // The buffer currently under inspection. At depth 0 it is `None` and the level
  // is a view into the on-disk chunk (`block`, borrowed from the file — already
  // resident, NOT zXIf-inflated memory). At depth ≥ 1 it is `Some(inflated)`: the
  // most recent inflated buffer, which we OWN. It is REPLACED (the previous one
  // dropped) when a `\0`-typed level inflates the next — so at most one inflated
  // buffer is held at a time (vs bundled's full recursive stack).
  //
  // COMPREHENSIVE MEMORY INVARIANT: at every instant the TOTAL live zXIf-inflated
  // memory — the transient buffer (`owned` here, or the one miniz is growing) PLUS
  // every retained `NativeTiff` charged into `meta` so far — is ≤
  // `MAX_ZXIF_INFLATE_TOTAL`. Four things uphold it together: (a) only ONE inflate
  // buffer is alive at a time (the iterative unwrap drops each before the next);
  // (b) EVERY inflate is charged to the file-wide total — a successful one by its
  // output length, a FAILED/cap-hit one by the bytes miniz transiently allocated
  // (`LimitedInflate::Err { allocated }`) — so an over-cap chunk EXHAUSTS the
  // budget and later chunks short-circuit (`remaining == 0`) instead of replaying a
  // near-cap inflate ATTEMPT each; (c) an `II`/`MM` inflate is MOVED (not cloned)
  // into its retained `NativeTiff`, so retaining it does NOT transiently double the
  // live buffer — the one already-charged buffer simply becomes the retained one;
  // (d) the retained `NativeTiff` is a `Box<[u8]>` (built via `into_boxed_slice`),
  // whose allocation is EXACTLY its length BY CONSTRUCTION — a boxed slice carries
  // no excess capacity. This makes the `inner.len()` charge in (b) the EXACT
  // retained-allocation size at the TYPE LEVEL, not allocator-dependent: miniz
  // sizes its output buffer from the COMPRESSED input
  // (`min(2*input.len(), max_size)`) and only `truncate`s on success (capacity
  // unchanged), so a tiny TIFF inflated from a stream with large trailing padding
  // would otherwise retain a near-cap CAPACITY while charging only its few-byte
  // LENGTH — an O(chunks × cap) capacity-vs-length undercharge. Storing the
  // retained buffer as a boxed slice closes that dimension STRUCTURALLY and
  // DEFINITIVELY: capacity == length is a TYPE GUARANTEE (not the
  // allocator-defined `shrink_to_fit`, whose Vec contract MAY leave excess
  // capacity), so the summed retained allocation is the summed charged length,
  // ≤ the cap. No other allocator dimension contributes a payload-scaled term: the
  // transient inflate buffer's own capacity is bounded by `max_size` (the budget),
  // and the per-chunk event `Vec` / tag `BTreeMap` overhead is O(metadata-count),
  // not O(payload-size).
  let mut owned: Option<Vec<u8>> = None;
  let mut depth = depth;
  loop {
    let cur: &[u8] = owned.as_deref().unwrap_or(block);
    // 1. `PNG.pm:1368-1373`: improper `Exif\0\0` prefix. `prefix` is the byte
    //    offset of the level within `cur` (6 after the strip, else 0) — recorded
    //    so a retained `II`/`MM` level can be MOVED out of `owned` (drain the
    //    prefix) rather than cloned (finding 2).
    let prefix: usize = if cur.starts_with(b"Exif\0\0") {
      meta.push_warning(String::from("Improper \"Exif00\" header in EXIF chunk"));
      6
    } else {
      0
    };
    // `cur.get(prefix..)` is `Some`: `prefix` is 0, or 6 under a len-≥-6 guard.
    let level: &[u8] = cur.get(prefix..).unwrap_or_default();
    // 2. `PNG.pm:1374-1384`: the TIFF byte-order marker must be `\0`/`II`/`MM`.
    let Some(&first) = level.first() else {
      meta.push_warning(format!("Invalid {tag} chunk"));
      return;
    };
    if first != 0 && !level.starts_with(b"II") && !level.starts_with(b"MM") {
      meta.push_warning(format!("Invalid {tag} chunk"));
      return;
    }
    if first != 0 {
      // 3. `II`/`MM` real TIFF: capture as a native event in walk order; the
      //    replay runs the Exif walker over the shared `$$et{PROCESSED}` set
      //    with NO reset (`PNG.pm:1358`). The retained block is exactly `level`
      //    (`cur[prefix..]`, which always runs to the end of `cur`).
      //    - depth ≥ 1: `cur` IS the inflated `owned` buffer (already charged to
      //      the file-wide total when it was inflated). MOVE it into the event —
      //      drain the `Exif\0\0` prefix in place if present — so retention adds
      //      NO new allocation and never doubles the live inflated memory.
      //    - depth 0: `cur` is the borrowed on-disk chunk (not inflatable memory,
      //      not charged), so the retained TIFF must be COPIED out of the file
      //      slice — this is the ordinary uncompressed `eXIf` path, unchanged.
      // The retained TIFF is a `Box<[u8]>`: its allocation is EXACTLY its length
      // by construction (a boxed slice carries no excess capacity), so the
      // `meta.add_zxif_inflated(len)` charge below equals the retained allocation
      // at the type level — see the memory invariant above. `into_boxed_slice`
      // reallocates the (possibly over-capacity) inflated `Vec` down to exactly
      // its length; it preserves the bytes.
      let tiff: Box<[u8]> = match owned.take() {
        Some(mut buf) => {
          buf.drain(..prefix);
          buf.into_boxed_slice()
        }
        // depth 0: `owned` is `None`, so `cur == block` and the level is
        // `block[prefix..]` — re-slice `block` directly (NOT `level`, which
        // borrows `owned` and would clash with the `take()` above) and copy it.
        None => Box::from(block.get(prefix..).unwrap_or_default()),
      };
      // A retained depth-≥1 TIFF was inflated and ALREADY charged when it was
      // inflated; the depth-0 path copies from the borrowed on-disk chunk (not
      // zXIf-inflated memory), so neither re-charges here. The charge happens at
      // the inflate site (`add_zxif_inflated(inner.len())`); a boxed slice makes
      // that recorded length the exact retained allocation.
      meta.push_exif_event(PngExifEvent::NativeTiff(tiff));
      return;
    }
    // 4. `\0`-typed ⇒ compressed EXIF (zXIf); inflate + re-enter (`PNG.pm:1389`).
    // DoS guard: a malicious chunk could inflate to ANOTHER `\0`-typed block at
    // every level. Bundled has no cap; we bound the unwrap. At the ceiling STOP
    // with the aborted-inflate warning (a crafted nest can only bottom out in
    // an inflate/`substr` failure beyond a sane depth — `PNG.pm:943` shape).
    if depth >= MAX_ZXIF_DEPTH {
      meta.push_warning(format!("Error inflating {tag}"));
      return;
    }
    // `substr($$dataPt, 5)`: skip the `\0` type byte + the 4-byte (unused)
    // uncompressed-length field. A block shorter than 5 bytes has no payload —
    // bundled's `substr` is empty/`undef` so the deflate fails ⇒ `Error
    // inflating $tag` (oracle-confirmed for the degenerate inner `\0` block).
    let Some(payload_off) = prefix.checked_add(5) else {
      meta.push_warning(format!("Error inflating {tag}"));
      return;
    };
    let Some(payload) = cur.get(payload_off..) else {
      meta.push_warning(format!("Error inflating {tag}"));
      return;
    };
    // Size-bounded inflate: cap THIS level to the budget REMAINING after every
    // prior chunk's inflation (FILE-WIDE, `PngMeta::zxif_inflated_total`), so the
    // SUM of all inflated bytes across the WHOLE PNG — transient buffers AND the
    // retained `NativeTiff`s — never exceeds `MAX_ZXIF_INFLATE_TOTAL`. A prior
    // chunk that already exhausted the budget leaves `remaining == 0`, which
    // `inflate_chunk_limited` reports as `Err { allocated: 0 }` immediately (no
    // allocation, no near-cap re-attempt).
    let remaining = MAX_ZXIF_INFLATE_TOTAL.saturating_sub(meta.zxif_inflated_total());
    match inflate_chunk_limited(payload, remaining) {
      // `PNG.pm:1389`: re-enter on the INFLATED buffer (same `$tag`). A nested
      // zXIf (inflated block is itself `\0`-typed) inflates AGAIN next iteration;
      // an inflated `Exif00`/non-`II`/`MM` block is handled by steps 1-3 above.
      // Charge the output to the file-wide running total: if the inflated block is
      // an `II`/`MM` TIFF it is RETAINED (`NativeTiff`, by MOVE) so its bytes stay
      // accounted for the rest of the parse; if it is another `\0`/`Exif00`/invalid
      // level its transient bytes still count, keeping a multi-chunk bomb bounded.
      LimitedInflate::Ok(inner) => {
        // `decompress_to_vec_zlib_with_limit` sizes its output buffer from the
        // COMPRESSED input length — `vec![0; min(2*input.len(), max_size)]`
        // up front (miniz_oxide 0.9.1 inflate/mod.rs:212) — and on success only
        // `truncate`s the buffer to the decompressed length (`:226`), which does
        // NOT release the over-allocated CAPACITY. So a crafted payload of a tiny
        // valid zlib stream followed by large trailing padding inflates to a tiny
        // `II`/`MM` TIFF whose backing `Vec` still holds a near-`max_size`
        // CAPACITY. That buffer is then either re-inflated (dropped next
        // iteration) or RETAINED in a `NativeTiff` for the rest of the parse.
        // We charge `inner.len()` (the LENGTH, not the capacity); the
        // capacity-vs-length gap that would otherwise reopen the O(chunks × cap)
        // retained-memory DoS (each chunk charges a few bytes yet retains a
        // near-cap allocation) is closed at the RETENTION site, NOT here: an
        // `II`/`MM` level is stored as a `Box<[u8]>` (`into_boxed_slice`), whose
        // allocation is EXACTLY its length BY CONSTRUCTION, so the recorded length
        // equals the retained allocation at the type level — not dependent on an
        // allocator-defined `shrink_to_fit` (whose Rust contract MAY leave excess
        // capacity). The live + retained total is thus the sum of the small TIFF
        // lengths — bounded by the cap, never their pre-shrink capacities.
        // Beyond-faithful hardening: ExifTool 13.59 has NO zXIf size cap.
        meta.add_zxif_inflated(inner.len());
        owned = Some(inner);
        depth += 1;
      }
      // `PNG.pm:943`: corrupt zlib OR the file-wide size cap was hit ⇒ `Error
      // inflating $tag`. Charge `allocated` — the bytes miniz transiently
      // materialized for this attempt (== the cap on a cap-hit, small for an early
      // corruption error) — to the file-wide total BEFORE warning, so a single
      // over-cap chunk exhausts the budget and the NEXT over-cap chunk short-
      // circuits at `remaining == 0` instead of forcing another near-cap inflate
      // (finding 1). The transient buffer is already freed (the inflater returned).
      LimitedInflate::Err { allocated } => {
        meta.add_zxif_inflated(allocated);
        meta.push_warning(format!("Error inflating {tag}"));
        return;
      }
    }
  }
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
  // Checked-indexing (Phase C S2): `data[0]` runs in the `len < 2` arm after
  // the non-empty guard (len == 1); the `data[i]`/`data[i + 1]` reads sit under
  // `while i + 2 <= data.len()` so `data.get(i..i + 2)` is `Some` ⇒
  // byte-identical.
  let value = if data.len() < 2 {
    // Single int8u (palette index).
    std::format!("{}", data.first().copied().unwrap_or(0))
  } else {
    // Series of int16u BE values.
    let mut s = String::new();
    let mut first = true;
    let mut i = 0;
    while i + 2 <= data.len() {
      let v = match data.get(i..i + 2) {
        Some(&[hi, lo, ..]) => u16::from_be_bytes([hi, lo]),
        _ => break,
      };
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
  // Checked-indexing (Phase C S2): the slice-pattern binds the same 7 bytes
  // `data[0..7]` did; a shorter buffer skips like the old `data.len() < 7`
  // guard ⇒ byte-identical.
  let &[d0, d1, mon, day, hour, min, sec, ..] = data else {
    return;
  };
  let year = u16::from_be_bytes([d0, d1]);
  let s = std::format!("{year:04}:{mon:02}:{day:02} {hour:02}:{min:02}:{sec:02}");
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
/// already carries an EXPLICIT family-1 group (the `$grps[1] or …` rule,
/// `ExifTool.pm:9475`) — the `Exif::Main`-table IFDs (`IFD0`/`IFD<n>`/`ExifIFD`/
/// `InteropIFD`, via `SET_GROUP1 => 1`, `Exif.pm:416`) and the XMP namespace
/// groups (`XMP-<ns>`, via `SetGroup`, `XMP.pm:3717`) — see
/// [`has_explicit_family1_group`]. Every OTHER family-1 group — PNG-level
/// (`PNG`/`PNG-pHYs`), the `File:ExifByteOrder` tag (family-1 `File`), the GPS
/// sub-IFD (its `GPS::Main` table has NO `SET_GROUP1`, so its family-1 is a table
/// default that the global overrides), and MakerNotes vendor groups — shifts to
/// `Trailer` (oracle-verified against `perl exiftool -j -G1` 13.59:
/// `Trailer:ExifByteOrder`, `Trailer:GPSLatitudeRef`, but `IFD0:Make` /
/// `ExifIFD:DateTimeOriginal` / `IFD1:Artist` / `XMP-dc:Format` UNCHANGED).
/// family-0 is never touched (`PNG.pm` overrides only group1).
#[cfg(feature = "alloc")]
fn apply_trailer_group(g: crate::value::Group) -> crate::value::Group {
  if has_explicit_family1_group(g.family1()) {
    g
  } else {
    crate::value::Group::new(g.family0(), GROUP_TRAILER)
  }
}

/// `true` if `family1` is a family-1 group name that the tag carries EXPLICITLY
/// (via its table's `GROUPS{1}` / `SET_GROUP1 => 1`), so the FoundTag rule
/// `$grps[1] or $grps[1] = $$self{SET_GROUP1}` (`ExifTool.pm:9475`) keeps it and
/// the trailer's `SET_GROUP1 = 'Trailer'` global does NOT override it. Two
/// families qualify:
///
/// - **`Exif::Main`-table IFDs** — `IFD0`, a trailing `IFD<n>` (all digits after
///   `IFD`), `ExifIFD`, `InteropIFD`. These share `Image::ExifTool::Exif::Main`,
///   whose `SET_GROUP1 => 1` (`Exif.pm:416` → `SetGroup`, `Exif.pm:7183`) records
///   the explicit family-1 group. (The GPS sub-IFD's `GPS::Main` has NO
///   `SET_GROUP1`, so `GPS` does NOT match and shifts to `Trailer`.)
/// - **XMP namespace groups** — `XMP-<ns>` (`XMP-dc`, `XMP-exif`, `XMP-x`,
///   `XMP-tiff`, `XMP-rdf`, …, plus the `XMP-XML` lastUpdate group). The XMP
///   reader assigns each tag its namespace-derived family-1 group via
///   `SetGroup("XMP-$ns")` (`XMP.pm:3717`), an explicit `$grps[1]` — so a
///   post-`IEND` raw-profile XMP keeps `XMP-dc:Format` (oracle-confirmed against
///   `perl exiftool -G1` 13.59: a TRAILER `Raw profile type xmp` still emits
///   `XMP-dc:Format`, NOT `Trailer:Format`), exactly like the `Exif::Main` IFDs.
///
/// Every OTHER family-1 group — PNG-level (`PNG`/`PNG-pHYs`), `File`
/// (`ExifByteOrder`), the GPS sub-IFD, MakerNotes vendor groups — has no explicit
/// `$grps[1]` and so shifts to `Trailer`.
#[cfg(feature = "alloc")]
fn has_explicit_family1_group(family1: &str) -> bool {
  match family1 {
    "ExifIFD" | "InteropIFD" => true,
    // "IFD0", "IFD1", "IFD2", … "IFD4294967295" — the literal `IFD` prefix
    // followed by ≥1 decimal digits (the trailing-IFD numbering, `Exif.pm:7215`).
    s if s
      .strip_prefix("IFD")
      .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())) =>
    {
      true
    }
    // "XMP-<ns>" — every XMP tag's namespace-derived family-1 group
    // (`XMP.pm:3717` `SetGroup`); the on-disk XMP reader sets it explicitly.
    s => s.starts_with("XMP-"),
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
    opts: crate::emit::EmitOptions,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    let mode = opts.mode;
    use crate::emit::EmittedTag;
    use crate::value::{Group, TagValue, binary_placeholder};

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

    // ---- acTL sub-table (animated PNG, PNG.pm:766-782) ----------------
    // `AnimationControl` (`ProcessBinaryData`, `FORMAT => 'int32u'`) emits in
    // offset order: AnimationFrames (tag 0), AnimationPlays (tag 1). Present
    // only for an APNG (an `acTL` chunk was seen). `AnimationFrames` is the
    // raw `num_frames` (its RawConv emits `$val` unchanged; the
    // `OverrideFileType("APNG", …)` side effect promotes `File:FileType` via
    // [`PngMeta::is_apng`], applied in the parser). `AnimationPlays` is
    // `$val || "inf"` (`0` ⇒ `"inf"` under PrintConv; the raw int under `-n`).
    //
    // PER-FIELD PROVENANCE (the iDOT/gdAT pattern): each field carries its own
    // pre-`IEND` (`PNG:`) and post-`IEND` trailer (`Trailer:`, `PNG.pm:1484`)
    // occurrence. A PNG may carry `acTL` in BOTH regions; bundled emits each
    // occurrence's fields under its OWN family-1 group. The two fields are
    // INDEPENDENT — a 4-to-7-byte trailer `acTL` supplies only
    // `AnimationFrames` (bytes `0..4`), so `Trailer:AnimationFrames` is emitted
    // while the main `PNG:AnimationPlays` stays under `PNG` (NOT re-grouped to
    // `Trailer`). Emitted in chunk-walk order: the main pair (Frames, Plays)
    // then the trailer pair (Frames, Plays). Oracle-verified vs bundled 13.59.
    //
    // PNG.pm:780 `PrintConv => '$val || "inf"'` for AnimationPlays — a `0` play
    // count (the APNG "infinite loop" sentinel) renders as the string `"inf"`
    // under PrintConv; any non-zero count stays the bare number; `-n` always
    // emits the raw int.
    let push_plays = |group: Group, plays: u32, tags: &mut Vec<EmittedTag>| {
      if print_conv && plays == 0 {
        tags.push(EmittedTag::new(
          group,
          "AnimationPlays".into(),
          TagValue::Str("inf".into()),
          false,
        ));
      } else {
        tags.push(EmittedTag::new(
          group,
          "AnimationPlays".into(),
          TagValue::U64(u64::from(plays)),
          false,
        ));
      }
    };
    if let Some(frames) = self.animation_frames_main() {
      tags.push(EmittedTag::new(
        png_group(false),
        "AnimationFrames".into(),
        TagValue::U64(u64::from(frames)),
        false,
      ));
    }
    if let Some(plays) = self.animation_plays_main() {
      push_plays(png_group(false), plays, &mut tags);
    }
    if let Some(frames) = self.animation_frames_trailer() {
      tags.push(EmittedTag::new(
        png_group(true),
        "AnimationFrames".into(),
        TagValue::U64(u64::from(frames)),
        false,
      ));
    }
    if let Some(plays) = self.animation_plays_trailer() {
      push_plays(png_group(true), plays, &mut tags);
    }

    // ---- iDOT (PNG.pm:331-342) -------------------------------------
    // Apple's `AppleDataOffsets` — `Binary => 1`, NO SubDirectory. Emitted
    // (in chunk-walk order, right after the IHDR sub-table tags) as the
    // universal `(Binary data N bytes, …)` placeholder, rendered from the
    // stored LENGTH alone (the payload was never retained) via
    // [`binary_placeholder`]. A PNG may carry `iDOT` BOTH before `IEND`
    // (→ `PNG:AppleDataOffsets`) AND after it (→ `Trailer:AppleDataOffsets`,
    // `SET_GROUP1 = 'Trailer'`, `PNG.pm:1484`); bundled emits BOTH under their
    // distinct family-1 groups, so each occurrence is emitted from its own
    // per-group slot. Oracle-verified vs bundled 13.59.
    if let Some(len) = self.apple_data_offsets_main_len() {
      tags.push(EmittedTag::new(
        png_group(false),
        "AppleDataOffsets".into(),
        TagValue::Str(binary_placeholder(len as u64)),
        false,
      ));
    }
    if let Some(len) = self.apple_data_offsets_trailer_len() {
      tags.push(EmittedTag::new(
        png_group(true),
        "AppleDataOffsets".into(),
        TagValue::Str(binary_placeholder(len as u64)),
        false,
      ));
    }

    // ---- gdAT (PNG.pm:374-378) -------------------------------------
    // `GainMapImage` — `Binary => 1`, `Groups => { 2 => 'Preview' }`, NO
    // SubDirectory (the same shape as `iDOT`). Emitted (in chunk-walk order)
    // as the `(Binary data N bytes, …)` placeholder, rendered from the stored
    // LENGTH alone. The family-2 `Preview` group does not surface at `-G1`.
    // Like `iDOT` a pre-`IEND` `gdAT` (→ `PNG:GainMapImage`) and a post-`IEND`
    // trailer `gdAT` (→ `Trailer:GainMapImage`, `PNG.pm:1484`) BOTH emit under
    // their distinct family-1 groups. Oracle-verified vs bundled 13.59.
    if let Some(len) = self.gain_map_image_main_len() {
      tags.push(EmittedTag::new(
        png_group(false),
        "GainMapImage".into(),
        TagValue::Str(binary_placeholder(len as u64)),
        false,
      ));
    }
    if let Some(len) = self.gain_map_image_trailer_len() {
      tags.push(EmittedTag::new(
        png_group(true),
        "GainMapImage".into(),
        TagValue::Str(binary_placeholder(len as u64)),
        false,
      ));
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
          for e in exif_meta.tags(opts) {
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
          tags.extend(exif_meta.tags(opts));
        }
      }
    }

    // ---- Raw-profile XMP — chain the XMP sub-Meta's tag stream -------------
    // A `Raw profile type xmp` chunk (`PNG.pm:746`) and the XMP-content arm of
    // `Raw profile type {exif,APP1}` (`PNG.pm:1236`) feed the hex-decoded packet
    // to `ProcessDirectory(XMP::Main)` = `ProcessXMP`. We parse each captured
    // packet through the ported XMP module ([`crate::formats::xmp`]) and splice
    // its `Taggable` stream (the `XMP-*:*` tags under family-0 `XMP`) here. The
    // engine's last-wins `TagMap` dedup keeps every unique tag (multiple XMP
    // profiles are uncommon but merge faithfully). Object key order is
    // conformance-insensitive, so the splice position (after the EXIF chain)
    // does not affect output. A post-`IEND` TRAILER XMP profile carries the
    // `Trailer` family-1 override (`PNG.pm:1484`); the `XMP-*` groups are not
    // `Exif::Main` IFDs, so [`apply_trailer_group`] shifts them to `Trailer`.
    #[cfg(feature = "xmp")]
    for (xi, packet) in self.xmp_profiles().iter().enumerate() {
      let Some(xmp_meta) = crate::formats::xmp::parse_borrowed(packet) else {
        continue;
      };
      if self.xmp_is_trailing(xi) {
        for e in xmp_meta.tags(opts) {
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
        tags.extend(xmp_meta.tags(opts));
      }
    }

    tags.into_iter()
  }
}

/// Whether a PNG walker warning was raised by bundled as MINOR
/// (`$et->Warn($msg, 1)` ⇒ a `[minor] ` prefix, `ExifTool.pm:5630`), keyed on
/// the BARE message (the [`PngMeta::warnings`] store keeps messages un-prefixed;
/// the prefix is mechanism-applied at drain time, the single source of truth —
/// see [`crate::diagnostics::Diagnostic::warn_minor`]). Only THREE PNG walker
/// warnings carry the minor flag in `PNG.pm`:
///
/// - `Trailer data after PNG IEND chunk` (`PNG.pm:1481` `$et->Warn(..., 1)`).
/// - `Text/EXIF chunk(s) found after <FileType> <chunk> (…)` (`PNG.pm:1604`
///   `$et->Warn(..., 1)`; `<FileType>` is `PNG` or `APNG`, see the emission).
/// - `<chunk> chunk should be <std>` (the `%stdCase` case-fix, `PNG.pm:1650`
///   `$et->Warn(..., 1)`).
///
/// Every OTHER PNG warning (`Error inflating …`, `Invalid … chunk`,
/// `Truncated …`, `Corrupted …`, `Unknown raw profile …`, `Unknown compression
/// method …`, `Improper "Exif00" header …`, `Non-standard PNG …`, `PNG image
/// did not start with IHDR`, `Invalid PNG chunk size`) is a plain `$et->Warn`
/// (no minor flag) ⇒ no prefix. Oracle-confirmed against `perl exiftool` 13.59.
fn png_warning_is_minor(msg: &str) -> bool {
  msg == "Trailer data after PNG IEND chunk"
    // `Text/EXIF chunk(s) found after <FileType> <chunk> (…)` (`PNG.pm:1604`).
    // The `<FileType>` is interpolated from `$$et{FileType}` — `PNG`, or `APNG`
    // once an `acTL` chunk fired the `AnimationFrames` RawConv override
    // (`PNG.pm:776`). The minor flag attaches to the whole `Text/EXIF chunk(s)
    // found after …` warning regardless of which FileType word it carries, so
    // match the FileType-independent prefix + suffix.
    || (msg.starts_with("Text/EXIF chunk(s) found after ")
      && msg.ends_with("(may be ignored by some readers)"))
    || msg.ends_with(" chunk should be eXIf")
    || msg.ends_with(" chunk should be zxIf")
}

/// Re-scope one diagnostic raised while parsing a post-`IEND` TRAILER chunk to
/// the `Trailer` family-1 group (`PNG.pm:1484` `$$et{SET_GROUP1} = 'Trailer'`),
/// mirroring `$grps[1] or $grps[1] = $$self{SET_GROUP1}` (`ExifTool.pm:9475`).
///
/// An embedded eXIf / raw-profile-XMP sub-Meta raises its `$et->Warn`/`$et->Error`
/// while the PNG chunk walker is in trailer mode, so a DOCUMENT-level diagnostic
/// (`group == None` — the `Warning`/`Error` FoundTag has no explicit `$grps[1]`)
/// surfaces as `Trailer:Warning`/`Trailer:Error` rather than the document-level
/// `ExifTool:Warning`/`:Error` (exactly the [`apply_trailer_group`] tag-side
/// shift, applied to the diagnostic channel). A diagnostic that ALREADY carries
/// an explicit group keeps it (the `$grps[1] or …` short-circuit) — though the
/// embedded EXIF/XMP `Diagnose` impls only yield document-level diagnostics, so
/// in practice every trailing one is re-scoped. The severity / `ignorable` minor
/// flag / `no_count` bit are preserved.
#[cfg(feature = "alloc")]
fn rescope_trailing_diag(d: crate::diagnostics::Diagnostic) -> crate::diagnostics::Diagnostic {
  if d.group().is_some() {
    return d;
  }
  crate::diagnostics::Diagnostic::new(
    d.message().into(),
    d.severity(),
    Some(GROUP_TRAILER.into()),
    d.ignorable(),
    d.no_count(),
  )
}

#[cfg(feature = "alloc")]
impl crate::diagnostics::Diagnose for PngMeta<'_> {
  /// PNG's document diagnostics, replayed at their CHUNK-WALK position via the
  /// ordered [`PngMeta::diag_order`](crate::metadata::png::PngMeta) interleave —
  /// the SAME serial order ExifTool's chunk walk (`PNG.pm:1410-1685`) emits them
  /// in. Three sources fold onto one walk axis (each [`PngDiagStep`] advancing
  /// one cursor):
  /// (a) the PNG walker's own warnings (`Truncated PNG image` PNG.pm:1486,
  ///     `Text/EXIF chunk(s) found after …` PNG.pm:1598, the zlib inflate-error
  ///     warnings, `Invalid eXIf chunk` / `Improper "Exif00" header …`, the
  ///     raw-profile `… is wrong size` / `Unknown raw profile …` warnings, …);
  /// (b) the embedded eXIf / Raw-profile EXIF sub-Metas' diagnostics, via the
  ///     SAME shared-`$$et{PROCESSED}` event replay `tags()` / `project()` use
  ///     ([`replay_exif_events`], `ExifTool.pm:9061-9072` + `PNG.pm:1193`) — for
  ///     each EXIF event: its own EXIF warnings (the parsed
  ///     [`ExifMeta`](crate::exif::ExifMeta)'s `Diagnose`), then the cross-source
  ///     cycle-guard warning(s) the walk raised (`ExifTool.pm:9068`);
  /// (c) the raw-profile XMP sub-Metas' decode warnings (`ProcessXMP` records at
  ///     most one first-occurrence `$et->Warn`, e.g. `XMP is double UTF-encoded`
  ///     XMP.pm:4491), each dispatched at its `Raw profile type {xmp,exif,APP1}`
  ///     chunk position (`PNG.pm:746`/`:1236`).
  ///
  /// Folding (c) onto the walk axis (rather than draining it dead-last, the #205
  /// bug) is load-bearing: `Warning` is `Priority=0` first-wins
  /// (`ExifTool.pm:5404-5417`), so a malformed XMP raw-profile that precedes a
  /// later chunk's warning must surface as the document FIRST `ExifTool:Warning`
  /// — exactly as bundled. The three cursors consume their streams in push order,
  /// so each source's internal order is preserved while the sources interleave at
  /// their true chunk positions. For a PNG whose only diagnostics are PNG-level
  /// (no embedded EXIF, no XMP raw-profile) the result is byte-identical to the
  /// pre-#205 flat `self.warnings()` drain (the `diag_order` is then all
  /// `Warning` steps in push order).
  fn diagnostics(&self) -> std::vec::Vec<crate::diagnostics::Diagnostic> {
    use crate::metadata::png::PngDiagStep;
    let mut out = std::vec::Vec::new();
    // Precompute the EXIF event replays once (one per event, IN ORDER); the
    // `ExifEvent` cursor walks them in lockstep with the event push order.
    // `png` chains `exif` (`Cargo.toml`), so this file always builds with
    // `feature = "exif"` — the guard mirrors the rest of the module.
    #[cfg(feature = "exif")]
    let replays = replay_exif_events(self.exif_events());
    // Each cursor is enumerated so the trailing-watermark predicates
    // (`event_is_trailing` / `warning_is_trailing` / `xmp_is_trailing`) can
    // re-scope a TRAILER-chunk diagnostic to the `Trailer` family-1 group
    // (`PNG.pm:1484`) — for the warning, EXIF, AND XMP sources alike.
    #[cfg(feature = "exif")]
    let mut event_cursor = replays.iter().enumerate();
    let mut warn_cursor = self.warnings().iter().enumerate();
    #[cfg(feature = "xmp")]
    let mut xmp_cursor = self.xmp_profiles().iter().enumerate();

    for step in self.diag_order() {
      match step {
        PngDiagStep::Warning => {
          if let Some((wi, w)) = warn_cursor.next() {
            // `PNG.pm:1481-1484`: a warning raised while parsing a post-`IEND`
            // TRAILER chunk runs under `$$et{SET_GROUP1} = 'Trailer'`, so its
            // `FoundTag('Warning', …)` resolves the family-1 group to `Trailer`
            // (`ExifTool.pm:9475`) and surfaces as the `Trailer:Warning` TAG
            // rather than the document-level `ExifTool:Warning`. The minor flag
            // (`$et->Warn(..., 1)`) is reconstructed by message shape, faithful
            // to the three minor PNG walker warnings (see `png_warning_is_minor`).
            let minor = png_warning_is_minor(w);
            out.push(match (self.warning_is_trailing(wi), minor) {
              (false, false) => crate::diagnostics::Diagnostic::warn(w),
              (false, true) => crate::diagnostics::Diagnostic::warn_minor(w),
              (true, false) => crate::diagnostics::Diagnostic::warn_in_group(GROUP_TRAILER, w),
              (true, true) => crate::diagnostics::Diagnostic::new(
                w.into(),
                crate::diagnostics::Severity::Warn,
                Some(GROUP_TRAILER.into()),
                1,
                false,
              ),
            });
          }
        }
        // `png` chains `exif` (`Cargo.toml`), so this arm always runs; the
        // `cfg` mirrors the rest of the module's belt-and-suspenders gating.
        #[cfg(feature = "exif")]
        PngDiagStep::ExifEvent => {
          if let Some((ei, replay)) = event_cursor.next() {
            // `PNG.pm:1484`: an embedded-EXIF event parsed from a post-`IEND`
            // TRAILER `eXIf`/`Raw profile type exif` chunk raises its EXIF
            // `$et->Warn`/`$et->Error` AND any cross-source cycle-guard warning
            // under `SET_GROUP1 = 'Trailer'`, so each document-level diagnostic
            // surfaces as `Trailer:Warning`/`:Error` (mirroring the tag-side
            // `apply_trailer_group`). A non-trailing event's diagnostics are
            // emitted UNCHANGED (the standard byte-identical path).
            let trailing = self.event_is_trailing(ei);
            let rescope = |d: crate::diagnostics::Diagnostic| {
              if trailing {
                rescope_trailing_diag(d)
              } else {
                d
              }
            };
            if let Some(exif_meta) = replay.meta() {
              out.extend(
                crate::diagnostics::Diagnose::diagnostics(exif_meta)
                  .into_iter()
                  .map(rescope),
              );
            }
            out.extend(
              replay
                .cycle_guard_warnings()
                .iter()
                .map(|w| rescope(crate::diagnostics::Diagnostic::warn(w.as_str()))),
            );
          }
        }
        #[cfg(not(feature = "exif"))]
        PngDiagStep::ExifEvent => {}
        #[cfg(feature = "xmp")]
        PngDiagStep::Xmp => {
          if let Some((xi, packet)) = xmp_cursor.next()
            && let Some(xmp_meta) = crate::formats::xmp::parse_borrowed(packet)
          {
            // `PNG.pm:1484`: a post-`IEND` TRAILER `Raw profile type xmp` chunk
            // raises its `ProcessXMP` `$et->Warn` (e.g. `XMP is double
            // UTF-encoded`) under `SET_GROUP1 = 'Trailer'`, so the document-level
            // XMP diagnostic surfaces as `Trailer:Warning` (where priority-0
            // first-wins then resolves it against any earlier `Trailer:Warning`,
            // e.g. the `Text/EXIF chunk(s) found after IDAT` walker warning).
            let trailing = self.xmp_is_trailing(xi);
            out.extend(
              crate::diagnostics::Diagnose::diagnostics(&xmp_meta)
                .into_iter()
                .map(|d| {
                  if trailing {
                    rescope_trailing_diag(d)
                  } else {
                    d
                  }
                }),
            );
          }
        }
      }
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
  // Checked-indexing (Phase C S2): every `bytes[i]` below had a preceding
  // `i < bytes.len()` guard and the `bytes[i..i + N]` windows had an
  // `i + N <= bytes.len()` guard, so the `.get()` forms read the same bytes and
  // take the same branches ⇒ byte-identical.
  while start < bytes.len() {
    // Group 1 `(\d+)` — day. Must begin with a digit.
    if !bytes.get(start).is_some_and(u8::is_ascii_digit) {
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

  // `(\d+)` — day (group 1). Greedy run of ASCII digits. Checked-indexing
  // (Phase C S2): the `i < bytes.len()` guards become `.get(i)` and the
  // `i + N <= bytes.len()` window guards become `.get(i..i + N)` ⇒
  // byte-identical (the `val[a..b]` slices are `&str`, unaffected by the lint).
  let day_start = i;
  while bytes.get(i).is_some_and(u8::is_ascii_digit) {
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
  if !bytes
    .get(i..i + 3)
    .is_some_and(|m| m.iter().all(u8::is_ascii_alphabetic))
  {
    return None;
  }
  let mon = &val[i..i + 3];
  let mon_num = month_num(mon)?;
  i += 3;

  // `\s*` — optional whitespace.
  i = skip_ws(bytes, i);

  // `(\d+)` — year (group 3).
  let yr_start = i;
  while bytes.get(i).is_some_and(u8::is_ascii_digit) {
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
  while bytes.get(i).is_some_and(u8::is_ascii_digit) {
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
  if !bytes
    .get(i..i + 2)
    .is_some_and(|m| m.iter().all(u8::is_ascii_digit))
  {
    return None;
  }
  let min = &val[i..i + 2];
  i += 2;

  // `(:\d{2})?` — optional seconds (group 6), INCLUDING the leading colon.
  let mut sec = "";
  if bytes.get(i) == Some(&b':')
    && bytes
      .get(i + 1..i + 3)
      .is_some_and(|d| d.iter().all(u8::is_ascii_digit))
  {
    sec = &val[i..i + 3]; // e.g. ":22" (colon included, matching `$sec`)
    i += 3;
  }

  // `\s*` — optional whitespace before the zone.
  i = skip_ws(bytes, i);

  // `(\S*)` — time zone (group 7): a run of non-whitespace (possibly empty).
  let tz_start = i;
  while bytes.get(i).is_some_and(|b| !b.is_ascii_whitespace()) {
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
  // Checked `.get()` (Phase C S2): folds the `i < bytes.len()` guard ⇒
  // byte-identical.
  while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
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
  // Checked-indexing (Phase C S2): the `j < bytes.len()` guard becomes
  // `.get(j)`; the `bytes.len() >= j + 3` window guard becomes `.get(j + 1..
  // j + 3)` ⇒ byte-identical (the `tz[..]` slices are `&str`, unaffected).
  let mut j = 1;
  while bytes.get(j).is_some_and(u8::is_ascii_digit) {
    j += 1;
  }
  let digit_run = &tz[1..j];
  // Optional literal `:` between the two `\d` groups (`:?`). If present, group 1
  // is the digits before it and group 2 the two after it.
  if bytes.get(j) == Some(&b':') {
    // `[-+]\d+ : \d{2}` — colon form. Group 1 = sign+digit_run (≥1 digit),
    // group 2 = exactly the next two digits.
    if !digit_run.is_empty()
      && bytes
        .get(j + 1..j + 3)
        .is_some_and(|d| d.iter().all(u8::is_ascii_digit))
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
  // Checked `.get()` (Phase C S2): `b.get(..4)` is `Some` iff `b.len() >= 4` ⇒
  // byte-identical.
  if b.get(..4).is_some_and(|h| h.iter().all(u8::is_ascii_digit)) {
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
  // Checked `.get()` (Phase C S2): `digits(a, b)` is `Some-and-all-digit` iff
  // the old `b[a..b].iter().all(..)` ran in-range and matched; `at(i, c)`
  // matches the old `b[i] == c`; the `b.len() < 16` guard already makes the
  // bytes 0..16 windows present, and `i + 3 <= b.len()` guards the seconds
  // window ⇒ byte-identical.
  let digits = |a: usize, c: usize| {
    b.get(a..c)
      .is_some_and(|r| r.iter().all(u8::is_ascii_digit))
  };
  let at = |i: usize, c: u8| b.get(i) == Some(&c);
  if !digits(0, 4) || !at(4, b'-') || !digits(5, 7) || !at(7, b'-') || !digits(8, 10) {
    return None;
  }
  // `[T ]`
  if !at(10, b'T') && !at(10, b' ') {
    return None;
  }
  // `(\d{2}:\d{2})` — HH:MM at bytes 11..16 (group 4).
  if !digits(11, 13) || !at(13, b':') || !digits(14, 16) {
    return None;
  }
  let mut i = 16;
  // `(:\d{2})?` — optional seconds; the leading colon is part of `$5`.
  let secs: &str = if at(i, b':') && digits(i + 1, i + 3) {
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
  // `[a-z]{2,3}` branch: try length 3 then 2. Checked `.get()` (Phase C S2):
  // `bytes.get(..plen)` is `Some` iff `bytes.len() >= plen` ⇒ byte-identical.
  for plen in [3usize, 2usize] {
    if bytes
      .get(..plen)
      .is_some_and(|h| h.iter().all(|&b| is_ascii_alpha(b)))
      && region_ok(plen)
    {
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
    // Raw-profile XMP fold (creator / title / description / GPS). Parse each
    // captured packet through the ported XMP module and merge LATER-WINS, the
    // same accumulation the EXIF fold uses. XMP is then merged UNDER the EXIF
    // facts (EXIF/MakerNote camera data is the higher-priority source; XMP fills
    // gaps), and the PNG IHDR dimensions fill any remaining `MediaInfo` gap.
    #[cfg(feature = "xmp")]
    let xmp_media: Option<crate::metadata::MediaMetadata> = {
      let mut acc: Option<crate::metadata::MediaMetadata> = None;
      for packet in self.xmp_profiles() {
        if let Some(xmp_meta) = crate::formats::xmp::parse_borrowed(packet) {
          let projected = crate::metadata::Project::project(&xmp_meta);
          acc = Some(match acc {
            Some(prev) => projected.merge(prev),
            None => projected,
          });
        }
      }
      acc
    };
    #[cfg(not(feature = "xmp"))]
    let xmp_media: Option<crate::metadata::MediaMetadata> = None;

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
        // EXIF (camera facts) is higher-priority; XMP fills gaps, then the PNG
        // dimensions fill any remaining `MediaInfo` gap.
        let merged = match xmp_media {
          Some(xmp) => exif_media.merge(xmp),
          None => exif_media,
        };
        return merged.merge(png_media);
      }
    }

    // No EXIF source (or `exif` disabled): XMP (if any) is the camera-facts
    // source over the PNG dimensions.
    if let Some(xmp) = xmp_media {
      return xmp.merge(png_media);
    }

    png_media
  }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C S2); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
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
  fn idot_apple_data_offsets_captured_as_binary() {
    // iDOT: Apple data offsets — 7 int32u (28 bytes), the layout documented at
    // PNG.pm:331-342. Only the LENGTH is retained; it emits as the binary
    // `(Binary data 28 bytes, …)` placeholder under `PNG:AppleDataOffsets`.
    let mut idot = Vec::new();
    for v in [2u32, 0, 1, 0x28, 1, 1, 0x100] {
      idot.extend_from_slice(&v.to_be_bytes());
    }
    assert_eq!(idot.len(), 28);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&2u32.to_be_bytes());
    ihdr_data.extend_from_slice(&2u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"iDOT", &idot));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert_eq!(meta.apple_data_offsets_main_len(), Some(28));
    assert!(meta.warnings().is_empty(), "got {:?}", meta.warnings());
    // The emitted tag renders the binary placeholder (matches bundled).
    let emitted: Vec<_> = crate::emit::Taggable::tags(
      &meta,
      crate::emit::EmitOptions::g1(crate::emit::ConvMode::PrintConv, false),
    )
    .collect();
    let idot_tag = emitted
      .iter()
      .find(|t| t.tag().name() == "AppleDataOffsets")
      .expect("AppleDataOffsets emitted");
    assert_eq!(idot_tag.tag().group_ref().family1(), "PNG");
    assert_eq!(
      idot_tag.tag().value_ref(),
      &crate::value::TagValue::Str(crate::value::binary_placeholder(28))
    );
  }

  #[test]
  fn gdat_gain_map_image_captured_as_binary() {
    // gdAT (PNG.pm:374-378): `GainMapImage`, `Binary => 1`, NO SubDirectory —
    // the same shape as iDOT. Only the LENGTH is retained; it emits as the
    // `(Binary data N bytes, …)` placeholder under `PNG:GainMapImage`. The
    // payload here stands in for an embedded gain-map image.
    let gdat = vec![0xABu8; 20];
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"gdAT", &gdat));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert_eq!(meta.gain_map_image_main_len(), Some(20));
    assert!(meta.warnings().is_empty(), "got {:?}", meta.warnings());
    let emitted: Vec<_> = crate::emit::Taggable::tags(
      &meta,
      crate::emit::EmitOptions::g1(crate::emit::ConvMode::PrintConv, false),
    )
    .collect();
    let gdat_tag = emitted
      .iter()
      .find(|t| t.tag().name() == "GainMapImage")
      .expect("GainMapImage emitted");
    assert_eq!(gdat_tag.tag().group_ref().family1(), "PNG");
    assert_eq!(
      gdat_tag.tag().value_ref(),
      &crate::value::TagValue::Str(crate::value::binary_placeholder(20))
    );
  }

  #[test]
  fn large_idot_chunk_stores_length_not_payload() {
    // Regression (#142 Codex F1): a large-but-present iDOT chunk must NOT be
    // cloned. The chunk passes the PNG length/CRC bounds, but the parser
    // retains only the byte LENGTH — `PngMeta` has no payload buffer for it —
    // so the stored representation is length-only and the normal `-j` output
    // renders the placeholder from that count alone (no payload-sized alloc in
    // either decode OR tags()).
    const BIG: usize = 8 * 1024 * 1024; // 8 MiB, well under MAX_CHUNK_LENGTH.
    let idot = vec![0u8; BIG];
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"iDOT", &idot));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    // Stored representation is the LENGTH, not the 8 MiB payload.
    assert_eq!(meta.apple_data_offsets_main_len(), Some(BIG));
    // The emitted placeholder is derived from the length alone.
    let emitted: Vec<_> = crate::emit::Taggable::tags(
      &meta,
      crate::emit::EmitOptions::g1(crate::emit::ConvMode::PrintConv, false),
    )
    .collect();
    let idot_tag = emitted
      .iter()
      .find(|t| t.tag().name() == "AppleDataOffsets")
      .expect("AppleDataOffsets emitted");
    assert_eq!(
      idot_tag.tag().value_ref(),
      &crate::value::TagValue::Str(crate::value::binary_placeholder(BIG as u64))
    );
  }

  #[test]
  fn idot_before_and_after_iend_emit_under_both_groups() {
    // #142 (Codex [medium]): a PNG carrying `iDOT` BOTH pre-`IEND` (28 bytes)
    // and as a post-`IEND` TRAILER chunk (4 bytes) emits BOTH placeholders —
    // `PNG:AppleDataOffsets` AND `Trailer:AppleDataOffsets` — under their
    // DISTINCT family-1 groups (oracle-verified vs bundled 13.59). The
    // singleton model lost the main; the per-group slots keep both, still
    // length-only.
    let main_idot = {
      let mut v = Vec::new();
      for x in [2u32, 0, 1, 0x28, 1, 1, 0x100] {
        v.extend_from_slice(&x.to_be_bytes());
      }
      v
    };
    assert_eq!(main_idot.len(), 28);
    let trailer_idot = 0xDEAD_BEEFu32.to_be_bytes().to_vec(); // 4 bytes
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"iDOT", &main_idot));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    bytes.extend_from_slice(&chunk(b"iDOT", &trailer_idot));
    let meta = parse_borrowed(&bytes).expect("png parses");
    // Both per-group LENGTHS survive (length-only — no payload retained).
    assert_eq!(meta.apple_data_offsets_main_len(), Some(28));
    assert_eq!(meta.apple_data_offsets_trailer_len(), Some(4));
    // The post-`IEND` entry warning is document-level (raised before
    // `SET_GROUP1`), so the PNG-level `warnings()` list carries it.
    assert_eq!(
      meta.warnings(),
      &["Trailer data after PNG IEND chunk".to_string()]
    );
    let emitted: Vec<_> = crate::emit::Taggable::tags(
      &meta,
      crate::emit::EmitOptions::g1(crate::emit::ConvMode::PrintConv, false),
    )
    .collect();
    // Exactly two `AppleDataOffsets` tags, one per family-1 group.
    let offsets: Vec<_> = emitted
      .iter()
      .filter(|t| t.tag().name() == "AppleDataOffsets")
      .collect();
    assert_eq!(
      offsets.len(),
      2,
      "expected PNG: + Trailer: AppleDataOffsets"
    );
    let main = offsets
      .iter()
      .find(|t| t.tag().group_ref().family1() == "PNG")
      .expect("PNG:AppleDataOffsets emitted");
    let trailer = offsets
      .iter()
      .find(|t| t.tag().group_ref().family1() == "Trailer")
      .expect("Trailer:AppleDataOffsets emitted");
    assert_eq!(
      main.tag().value_ref(),
      &crate::value::TagValue::Str(crate::value::binary_placeholder(28))
    );
    assert_eq!(
      trailer.tag().value_ref(),
      &crate::value::TagValue::Str(crate::value::binary_placeholder(4))
    );
  }

  #[test]
  fn gdat_before_and_after_iend_emit_under_both_groups() {
    // #142 (Codex [medium]): the same per-group split for `gdAT`. A pre-`IEND`
    // `gdAT` (20 bytes → `PNG:GainMapImage`) and a post-`IEND` trailer `gdAT`
    // (8 bytes → `Trailer:GainMapImage`) BOTH emit. Length-only.
    let main_gdat = vec![0xABu8; 20];
    let trailer_gdat = vec![1u8, 2, 3, 4, 5, 6, 7, 8]; // 8 bytes
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"gdAT", &main_gdat));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    bytes.extend_from_slice(&chunk(b"gdAT", &trailer_gdat));
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert_eq!(meta.gain_map_image_main_len(), Some(20));
    assert_eq!(meta.gain_map_image_trailer_len(), Some(8));
    let emitted: Vec<_> = crate::emit::Taggable::tags(
      &meta,
      crate::emit::EmitOptions::g1(crate::emit::ConvMode::PrintConv, false),
    )
    .collect();
    let images: Vec<_> = emitted
      .iter()
      .filter(|t| t.tag().name() == "GainMapImage")
      .collect();
    assert_eq!(images.len(), 2, "expected PNG: + Trailer: GainMapImage");
    let main = images
      .iter()
      .find(|t| t.tag().group_ref().family1() == "PNG")
      .expect("PNG:GainMapImage emitted");
    let trailer = images
      .iter()
      .find(|t| t.tag().group_ref().family1() == "Trailer")
      .expect("Trailer:GainMapImage emitted");
    assert_eq!(
      main.tag().value_ref(),
      &crate::value::TagValue::Str(crate::value::binary_placeholder(20))
    );
    assert_eq!(
      trailer.tag().value_ref(),
      &crate::value::TagValue::Str(crate::value::binary_placeholder(8))
    );
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
  fn text_after_idat_with_prior_actl_warns_apng() {
    // #141: IHDR + acTL(≥4 bytes, sets APNG) + IDAT + tEXt + IEND. The acTL is
    // dispatched (set_animation_frames → is_apng) BEFORE the post-IDAT tEXt
    // warning fires, so the warning interpolates the APNG FileType (PNG.pm:1604
    // `$$et{FileType}`). Oracle-verified vs 13.59 (`found after APNG IDAT`).
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    let mut actl = 2u32.to_be_bytes().to_vec();
    actl.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&chunk(b"acTL", &actl));
    bytes.extend_from_slice(&chunk(b"IDAT", b"\x00"));
    bytes.extend_from_slice(&chunk(b"tEXt", b"Comment\0Hi"));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert!(meta.is_apng(), "acTL should mark APNG");
    assert!(
      meta
        .warnings()
        .iter()
        .any(|w| w.contains("Text/EXIF chunk(s) found after APNG IDAT")),
      "expected APNG-form warning, got {:?}",
      meta.warnings(),
    );
    assert!(
      !meta
        .warnings()
        .iter()
        .any(|w| w.contains("found after PNG IDAT")),
      "must not emit the PNG-form warning, got {:?}",
      meta.warnings(),
    );
    // The minor classifier still recognizes the APNG form.
    let warn = meta
      .warnings()
      .iter()
      .find(|w| w.contains("found after APNG IDAT"))
      .expect("APNG warning present");
    assert!(png_warning_is_minor(warn), "APNG form must be minor");
  }

  #[test]
  fn text_after_idat_with_actl_after_warns_png_firing_point() {
    // #141 firing-point: IHDR + IDAT + tEXt + acTL + IEND. The acTL comes AFTER
    // the post-IDAT tEXt, so set_animation_frames has NOT run when the warning
    // fires — is_apng() is still false there → the warning says PNG, even though
    // the final PngMeta IS an APNG. Oracle-verified vs 13.59.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"IDAT", b"\x00"));
    bytes.extend_from_slice(&chunk(b"tEXt", b"Comment\0Hi"));
    let mut actl = 2u32.to_be_bytes().to_vec();
    actl.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&chunk(b"acTL", &actl));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert!(meta.is_apng(), "the final meta is still an APNG");
    assert!(
      meta
        .warnings()
        .iter()
        .any(|w| w.contains("Text/EXIF chunk(s) found after PNG IDAT")),
      "expected the PNG-form warning at firing point, got {:?}",
      meta.warnings(),
    );
    assert!(
      !meta
        .warnings()
        .iter()
        .any(|w| w.contains("found after APNG IDAT")),
      "must not say APNG when acTL fires after the warning, got {:?}",
      meta.warnings(),
    );
  }

  /// IHDR + IDAT + tEXt + IEND named `.apng`, with NO `acTL`. ExifTool's
  /// `SetFileType` runs BEFORE the chunk walk and promotes the PNG-signature
  /// file to `$$et{FileType} = APNG` from the `.apng` extension alone
  /// (ExifTool.pm:9686-9692), so the after-IDAT warning interpolates `APNG`
  /// even though no `acTL` was ever seen (`is_apng()` stays false). This is the
  /// EXTENSION-derived source of the firing-point FileType — the path the
  /// `.png`-named R3 tests never exercised. Oracle-verified vs bundled 13.59
  /// (`-warning` on a `.apng` with IDAT+tEXt → `found after APNG IDAT`).
  #[test]
  fn text_after_idat_apng_extension_no_actl_warns_apng() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"IDAT", b"\x00"));
    bytes.extend_from_slice(&chunk(b"tEXt", b"Comment\0Hi"));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    // `$$self{FILE_EXT}` is uppercased + dotless.
    let meta = parse_with_ext(&bytes, Some("APNG")).expect("png parses");
    assert!(!meta.is_apng(), "no acTL ⇒ not APNG by the acTL source");
    assert!(
      meta
        .warnings()
        .iter()
        .any(|w| w.contains("Text/EXIF chunk(s) found after APNG IDAT")),
      "extension-derived APNG must reach the warning, got {:?}",
      meta.warnings(),
    );
    assert!(
      !meta
        .warnings()
        .iter()
        .any(|w| w.contains("found after PNG IDAT")),
      "must not emit the PNG-form warning for a .apng file, got {:?}",
      meta.warnings(),
    );
    let warn = meta
      .warnings()
      .iter()
      .find(|w| w.contains("found after APNG IDAT"))
      .expect("APNG warning present");
    assert!(png_warning_is_minor(warn), "APNG form must be minor");
  }

  /// IHDR + IDAT + tEXt + acTL + IEND named `.apng`. The `acTL` comes AFTER the
  /// warning fires (so `is_apng()` is still false at the firing point), yet the
  /// warning still says `APNG` — because the EXTENSION already resolved the
  /// FileType to `APNG` before the walk. Confirms the two sources compose: even
  /// when the `acTL`-derived source has not yet fired, the extension-derived one
  /// carries the firing-point FileType. Oracle-verified vs bundled 13.59.
  #[test]
  fn text_after_idat_apng_extension_actl_after_warns_apng() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"IDAT", b"\x00"));
    bytes.extend_from_slice(&chunk(b"tEXt", b"Comment\0Hi"));
    let mut actl = 2u32.to_be_bytes().to_vec();
    actl.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&chunk(b"acTL", &actl));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_with_ext(&bytes, Some("APNG")).expect("png parses");
    assert!(meta.is_apng(), "the final meta is an APNG (acTL seen)");
    assert!(
      meta
        .warnings()
        .iter()
        .any(|w| w.contains("Text/EXIF chunk(s) found after APNG IDAT")),
      "the .apng extension carries APNG even before the late acTL, got {:?}",
      meta.warnings(),
    );
    assert!(
      !meta
        .warnings()
        .iter()
        .any(|w| w.contains("found after PNG IDAT")),
      "must not emit the PNG-form warning for a .apng file, got {:?}",
      meta.warnings(),
    );
  }

  /// The negative control via the extension-aware entry: the SAME IDAT+tEXt
  /// bytes named `.png` (a non-promoting extension) keep the PNG-form warning —
  /// no `acTL`, no `.apng` ⇒ `$$et{FileType} = PNG`. Guards that threading the
  /// extension does NOT spuriously upgrade an ordinary PNG. Oracle-verified vs
  /// bundled 13.59 (`.png` with IDAT+tEXt → `found after PNG IDAT`).
  #[test]
  fn text_after_idat_png_extension_no_actl_warns_png() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"IDAT", b"\x00"));
    bytes.extend_from_slice(&chunk(b"tEXt", b"Comment\0Hi"));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_with_ext(&bytes, Some("PNG")).expect("png parses");
    assert!(!meta.is_apng());
    assert!(
      meta
        .warnings()
        .iter()
        .any(|w| w.contains("Text/EXIF chunk(s) found after PNG IDAT")),
      "a .png extension must keep the PNG-form warning, got {:?}",
      meta.warnings(),
    );
    assert!(
      !meta
        .warnings()
        .iter()
        .any(|w| w.contains("found after APNG IDAT")),
      "must not upgrade an ordinary .png to APNG, got {:?}",
      meta.warnings(),
    );
  }

  /// #141 structural close: a PNG-signature file named with a PNG-ROOTED
  /// extension OTHER than `.apng` (`.mng`/`.jng`, which `%fileTypeLookup` roots
  /// to base module `PNG`, [`crate::filetype_data`]) makes ExifTool's
  /// pre-walk `SetFileType` resolve `$$et{FileType}` to that sub-type, so the
  /// after-IDAT warning interpolates `MNG`/`JNG` — NOT `PNG`. Storing the full
  /// resolved FileType string (not an `== "APNG"` bool) is what makes the
  /// warning track the extension for every PNG-rooted type. Oracle-verified vs
  /// bundled 13.59: a PNG-signature `.mng` with IDAT+tEXt → `found after MNG
  /// IDAT`; the same bytes `.jng` → `found after JNG IDAT`.
  #[test]
  fn text_after_idat_png_rooted_extension_warns_resolved_file_type() {
    for (ext, expect) in [("MNG", "MNG"), ("JNG", "JNG")] {
      let mut bytes = Vec::new();
      bytes.extend_from_slice(PNG_SIGNATURE);
      let mut ihdr_data = Vec::new();
      ihdr_data.extend_from_slice(&1u32.to_be_bytes());
      ihdr_data.extend_from_slice(&1u32.to_be_bytes());
      ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
      bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
      bytes.extend_from_slice(&chunk(b"IDAT", b"\x00"));
      bytes.extend_from_slice(&chunk(b"tEXt", b"Comment\0Hi"));
      bytes.extend_from_slice(&chunk(b"IEND", &[]));
      // `$$self{FILE_EXT}` is uppercased + dotless.
      let meta = parse_with_ext(&bytes, Some(ext)).expect("png parses");
      assert!(!meta.is_apng(), "{ext}: no acTL ⇒ not APNG");
      let needle = std::format!("Text/EXIF chunk(s) found after {expect} IDAT");
      assert!(
        meta.warnings().iter().any(|w| w.contains(&needle)),
        "{ext}: expected {needle:?}, got {:?}",
        meta.warnings(),
      );
      // The PNG-collapse bug emitted `after PNG IDAT` for these extensions.
      assert!(
        !meta
          .warnings()
          .iter()
          .any(|w| w.contains("found after PNG IDAT")),
        "{ext}: must not collapse to the PNG-form warning, got {:?}",
        meta.warnings(),
      );
      let warn = meta
        .warnings()
        .iter()
        .find(|w| w.contains(&needle))
        .expect("warning present");
      assert!(png_warning_is_minor(warn), "{ext}: form must be minor");
    }
  }

  /// #141 acTL override supersedes a non-APNG PNG-rooted extension: a
  /// PNG-signature file named `.mng` with an `acTL` BEFORE the IDAT. The `acTL`
  /// `OverrideFileType("APNG", …)` (`PNG.pm:776`) fires first, so the
  /// firing-point `$$et{FileType}` is `APNG`, not the extension's `MNG`.
  /// Oracle-verified vs bundled 13.59 (`.mng` + acTL-before → `found after APNG
  /// IDAT`).
  #[test]
  fn text_after_idat_mng_extension_actl_before_warns_apng() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    let mut actl = 2u32.to_be_bytes().to_vec();
    actl.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&chunk(b"acTL", &actl));
    bytes.extend_from_slice(&chunk(b"IDAT", b"\x00"));
    bytes.extend_from_slice(&chunk(b"tEXt", b"Comment\0Hi"));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_with_ext(&bytes, Some("MNG")).expect("png parses");
    assert!(meta.is_apng(), "acTL should mark APNG");
    assert!(
      meta
        .warnings()
        .iter()
        .any(|w| w.contains("Text/EXIF chunk(s) found after APNG IDAT")),
      "acTL must supersede the .mng extension, got {:?}",
      meta.warnings(),
    );
    assert!(
      !meta
        .warnings()
        .iter()
        .any(|w| w.contains("found after MNG IDAT")),
      "must not say MNG once acTL has overridden, got {:?}",
      meta.warnings(),
    );
  }

  /// #141 firing-point with a non-APNG PNG-rooted extension: a PNG-signature
  /// `.mng` whose `acTL` comes AFTER the post-IDAT tEXt. At the warning's firing
  /// point the `acTL` override has not yet fired (`is_apng()` false), so the
  /// warning uses the extension-resolved `MNG` — even though the FINAL FileType
  /// becomes `APNG` once the late `acTL` is dispatched. This is the case that
  /// proves storing the extension STRING (not an APNG bool) is required:
  /// is_apng-false must fall back to `MNG`, not `PNG`. Oracle-verified vs
  /// bundled 13.59 (`.mng` + acTL-after → File:FileType=APNG, warning `found
  /// after MNG IDAT`).
  #[test]
  fn text_after_idat_mng_extension_actl_after_warns_mng_firing_point() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&1u32.to_be_bytes());
    ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr_data));
    bytes.extend_from_slice(&chunk(b"IDAT", b"\x00"));
    bytes.extend_from_slice(&chunk(b"tEXt", b"Comment\0Hi"));
    let mut actl = 2u32.to_be_bytes().to_vec();
    actl.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&chunk(b"acTL", &actl));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    let meta = parse_with_ext(&bytes, Some("MNG")).expect("png parses");
    assert!(meta.is_apng(), "the final meta is an APNG (late acTL seen)");
    assert!(
      meta
        .warnings()
        .iter()
        .any(|w| w.contains("Text/EXIF chunk(s) found after MNG IDAT")),
      "firing point predates the late acTL ⇒ MNG, got {:?}",
      meta.warnings(),
    );
    assert!(
      !meta
        .warnings()
        .iter()
        .any(|w| w.contains("found after APNG IDAT") || w.contains("found after PNG IDAT")),
      "must be neither APNG (acTL not yet fired) nor PNG (collapse bug), got {:?}",
      meta.warnings(),
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
    // XMP → the ported XMP module (decoded into `XMP-*` tags, #179) rather than
    // suppressed.
    assert!(matches!(
      raw_profile_kind("Raw profile type xmp"),
      Some(RawProfileKind::XmpTable {
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
  fn process_profile_odd_nibble_padded_like_pack_h_star() {
    // Oracle: `perl -e 'print unpack("H*", pack("H*","abc"))'` → `abc0`. Perl
    // pads the dangling nibble as the HIGH half of a `<hi>0` byte (it does NOT
    // drop it), so 3 nibbles → 2 bytes `0xab 0xc0`.
    let body = b"\nexif\n       2\nabc\n";
    let p = process_profile(body, "EXIF_Profile").expect("framing matches");
    assert_eq!(p.bytes, vec![0xab, 0xc0]);
    assert!(p.size_warning.is_none(), "len 2 matches 2 decoded bytes");
  }

  #[test]
  fn process_profile_single_odd_nibble_pads_low_zero() {
    // Oracle: `pack("H*","a")` → `a0`. One nibble → one byte `0xa0`.
    let body = b"\nexif\n       1\na\n";
    let p = process_profile(body, "EXIF_Profile").expect("framing matches");
    assert_eq!(p.bytes, vec![0xa0]);
  }

  #[test]
  fn process_profile_non_hex_decodes_via_pack_nibble_rule() {
    // The whole point of the fix: a non-hex char does NOT stop the decode —
    // `pack('H*')` maps it through `(isALPHA? c+9 : c) & 0xf`. Oracle outputs:
    //   pack("H*","zc") → "3c"  ('z'=0x7a → (0x7a+9)&0xf = 3)
    //   pack("H*","g0") → "00"  ('g'=0x67 → (0x67+9)&0xf = 0)
    let zc = process_profile(b"\nexif\n       1\nzc\n", "EXIF_Profile").unwrap();
    assert_eq!(zc.bytes, vec![0x3c]);
    let g0 = process_profile(b"\nexif\n       1\ng0\n", "EXIF_Profile").unwrap();
    assert_eq!(g0.bytes, vec![0x00]);
    // A non-hex char mid-stream keeps decoding the rest (no truncation):
    //   pack("H*","01g203") → "01" . "02" . "03" with 'g'→0 ⇒ 0x01 0x02 0x03.
    let mid = process_profile(b"\nexif\n       3\n01g203\n", "EXIF_Profile").unwrap();
    assert_eq!(mid.bytes, vec![0x01, 0x02, 0x03]);
  }

  #[test]
  fn pack_h_nibble_matches_perl_for_all_bytes() {
    // `(isALPHA(c) ? c + 9 : c) & 0xf`, verified against Perl `pack('H*')` for
    // every byte 0..=255. Spot-check the canonical hex set plus the boundary
    // chars that distinguish the alpha (+9) branch from the bare-mask branch.
    for (b, want) in [
      (b'0', 0x0),
      (b'9', 0x9),
      (b'a', 0xa),
      (b'f', 0xf),
      (b'A', 0xa),
      (b'F', 0xf),
      (b'g', 0x0), // 0x67 alpha → (0x67+9)&0xf
      (b'z', 0x3), // 0x7a alpha → (0x7a+9)&0xf
      (b'G', 0x0),
      (b'Z', 0x3),
      (b'!', 0x1), // 0x21 not alpha → 0x21&0xf
      (b'@', 0x0), // 0x40 not alpha
      (b'/', 0xf), // 0x2f not alpha
      (b':', 0xa), // 0x3a not alpha
      (b'`', 0x0), // 0x60 not alpha (just below 'a')
      (b'{', 0xb), // 0x7b not alpha (just above 'z')
      (0x80, 0x0), // high byte: not alpha
      (0xff, 0xf),
    ] {
      assert_eq!(pack_h_nibble(b), want, "byte {b:#04x}");
    }
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
  fn route_exif_profile_xmp_content_captures_packet_and_resets() {
    // An `Exif`/`APP1`-table profile whose decoded content is `$xmpAPP1hdr`-led
    // XMP (PNG.pm:1236): strip the marker, CAPTURE the remaining XMP packet for
    // tag emission (#179), and — since `ProcessProfile` has ALREADY reset
    // `$$et{PROCESSED}` (PNG.pm:1193) before this dispatch (oracle-confirmed:
    // such a profile un-blocks a following same-addr eXIf) — push ONE
    // reset-only event. No warning either way.
    let mut m = PngMeta::new();
    let mut block = b"http://ns.adobe.com/xap/1.0/\0".to_vec();
    block.extend_from_slice(b"<x:xmpmeta/>");
    route_exif_profile(&mut m, block, b"APP1");
    let evs = m.exif_events();
    assert_eq!(evs.len(), 1, "expected one reset-only event, got {evs:?}");
    assert!(evs[0].is_reset_only());
    assert!(m.warnings().is_empty(), "got {:?}", m.warnings());
    #[cfg(feature = "xmp")]
    {
      assert_eq!(m.xmp_profiles().len(), 1);
      assert_eq!(m.xmp_profiles()[0], b"<x:xmpmeta/>");
    }
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
    let exif = |ifd0: u32, val: u16| PngExifEvent::NativeTiff(tiff_ifd0(ifd0, val, 0).into());
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
    let bad = |b: &[u8]| PngExifEvent::NativeTiff(b.into());
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
    let ev1 = PngExifEvent::NativeTiff(tiff_ifd0_and_ifd1(1, 40, 2).into());
    let ev2 = PngExifEvent::NativeTiff(tiff_ifd0(40, 3, 0).into());
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

  /// Build an ImageMagick `Raw profile type <profile_type>` tEXt chunk body
  /// (`\n<type>\n<8-wide len>\n<hex>\n`) for `payload`, returning the full
  /// `keyword\0body` chunk-data slice the tEXt decoder receives.
  fn raw_profile_payload(profile_type: &str, payload: &[u8]) -> Vec<u8> {
    let hexstr: String = payload.iter().map(|b| std::format!("{b:02x}")).collect();
    let mut body = std::format!("\n{profile_type}\n{:8}\n", payload.len()).into_bytes();
    body.extend_from_slice(hexstr.as_bytes());
    body.push(b'\n');
    let mut data = std::format!("Raw profile type {profile_type}\0").into_bytes();
    data.extend_from_slice(&body);
    data
  }

  /// Wrap `tEXt` chunk data into a minimal IHDR + tEXt + IEND PNG buffer.
  fn png_with_text(text_data: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&1u32.to_be_bytes());
    ihdr.extend_from_slice(&1u32.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    bytes.extend_from_slice(&chunk(b"IHDR", &ihdr));
    bytes.extend_from_slice(&chunk(b"tEXt", text_data));
    bytes.extend_from_slice(&chunk(b"IEND", &[]));
    bytes
  }

  /// A small, valid XMP packet carrying one `dc:creator` (`PNG.pm:746` →
  /// `ProcessXMP` recognizes the `<?xpacket`/`<x:xmpmeta` root).
  const XMP_TEST_PACKET: &[u8] = br#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">
   <dc:creator><rdf:Seq><rdf:li>Ansel Adams</rdf:li></rdf:Seq></dc:creator>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"#;

  #[cfg(feature = "xmp")]
  #[test]
  fn raw_profile_xmp_text_captures_packet_and_resets() {
    // `Raw profile type xmp` (PNG.pm:746): the hex-decoded packet is CAPTURED
    // for XMP tag emission AND a `ResetOnlyProfile` event is pushed (the
    // `$$et{PROCESSED}` reset, PNG.pm:1193). No text record, no warning.
    let data = raw_profile_payload("xmp", XMP_TEST_PACKET);
    let bytes = png_with_text(&data);
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert_eq!(meta.xmp_profiles().len(), 1, "one XMP packet captured");
    assert_eq!(
      meta.xmp_profiles()[0],
      XMP_TEST_PACKET,
      "captured packet is the raw hex-decoded XMP (no header strip)"
    );
    // The PROCESSED reset is still modeled (un-blocks a following same-$addr eXIf).
    assert_eq!(meta.exif_events().len(), 1);
    assert!(meta.exif_events()[0].is_reset_only());
    assert!(
      meta.text_records().is_empty(),
      "xmp raw-profile keyword must NOT push a text record"
    );
    assert!(meta.warnings().is_empty(), "got {:?}", meta.warnings());
  }

  #[cfg(feature = "xmp")]
  #[test]
  fn raw_profile_app1_xmp_content_strips_marker_and_captures() {
    // `Raw profile type APP1` whose decoded content is the `$xmpAPP1hdr`-led XMP
    // (PNG.pm:1236): strip the 29-byte marker, capture the remaining raw packet.
    let mut content = XMP_APP1_HDR.to_vec();
    content.extend_from_slice(XMP_TEST_PACKET);
    let data = raw_profile_payload("APP1", &content);
    let bytes = png_with_text(&data);
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert_eq!(meta.xmp_profiles().len(), 1);
    assert_eq!(
      meta.xmp_profiles()[0],
      XMP_TEST_PACKET,
      "the $xmpAPP1hdr marker is stripped before capture"
    );
    assert_eq!(meta.exif_events().len(), 1);
    assert!(meta.exif_events()[0].is_reset_only());
  }

  #[cfg(feature = "xmp")]
  #[test]
  fn raw_profile_xmp_emits_xmp_tags_through_taggable() {
    // End-to-end through the golden emission engine: the captured XMP packet's
    // `XMP-dc:Creator` reaches PNG's `tags()` stream (chained via the ported
    // XMP module's `Taggable`).
    use crate::emit::{ConvMode, Taggable};
    let data = raw_profile_payload("xmp", XMP_TEST_PACKET);
    let bytes = png_with_text(&data);
    let meta = parse_borrowed(&bytes).expect("png parses");
    let creator = meta
      .tags(crate::emit::EmitOptions::g1(ConvMode::PrintConv, false))
      .find(|t| t.tag().name() == "Creator")
      .expect("XMP-dc:Creator emitted from the raw-profile-xmp chunk");
    assert_eq!(creator.tag().group_ref().family0(), "XMP");
    assert_eq!(creator.tag().group_ref().family1(), "XMP-dc");
  }

  #[cfg(feature = "xmp")]
  #[test]
  fn raw_profile_xmp_wrong_size_still_warns() {
    // The wrong-size warning (PNG.pm:1172) fires before the module dispatch —
    // unchanged by the XMP decode. Declare a bogus length.
    let hexstr: String = XMP_TEST_PACKET
      .iter()
      .map(|b| std::format!("{b:02x}"))
      .collect();
    // Declared length 9999 ≠ actual — forces the wrong-size warning.
    let mut body = b"\nxmp\n    9999\n".to_vec();
    body.extend_from_slice(hexstr.as_bytes());
    body.push(b'\n');
    let mut data = b"Raw profile type xmp\0".to_vec();
    data.extend_from_slice(&body);
    let bytes = png_with_text(&data);
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert!(
      meta
        .warnings()
        .iter()
        .any(|w| w.contains("XMP_Profile is wrong size")),
      "got {:?}",
      meta.warnings()
    );
    // Despite the size mismatch the packet is still captured (bundled continues
    // with the actual bytes).
    assert_eq!(meta.xmp_profiles().len(), 1);
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

  // ─── nested-zXIf DoS bounds (#178 round 2) ────────────────────────────────

  /// Wrap `inner` as one zXIf level: the `\0` type byte + the 4-byte (ignored)
  /// uncompressed-length field + a ZLIB-wrapped deflate of `inner`
  /// (`PNG.pm:1378`/`:1386`). Re-applying this nests the zXIf one level deeper.
  fn zxif_wrap(inner: &[u8]) -> Vec<u8> {
    let comp = miniz_oxide::deflate::compress_to_vec_zlib(inner, 6);
    let mut body = Vec::with_capacity(5 + comp.len());
    body.push(0); // `\0` type byte ⇒ compressed EXIF
    body.extend_from_slice(&(inner.len() as u32).to_be_bytes()); // unused length field
    body.extend_from_slice(&comp);
    body
  }

  /// A minimal valid little-endian TIFF (`II*`, IFD0 at offset 8, zero entries)
  /// — a clean innermost block so the ONLY thing that stops the unwrap is the
  /// DoS cap, not an inflate/`substr` failure at the bottom.
  fn minimal_ii_tiff() -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(b"II");
    t.extend_from_slice(&42u16.to_le_bytes());
    t.extend_from_slice(&8u32.to_le_bytes());
    t.extend_from_slice(&0u16.to_le_bytes()); // 0 IFD entries
    t.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0
    t
  }

  #[test]
  fn nested_zxif_depth_cap_bounds_recursion_with_inflate_warning() {
    // A crafted zXIf chain of MAX_ZXIF_DEPTH + several levels of VALID `\0`-
    // compression over a clean inner TIFF. Bundled (no cap) would unwrap every
    // level and extract the inner TIFF; the port stops at `MAX_ZXIF_DEPTH` and
    // raises `Error inflating zxIf` (the aborted-inflate shape) instead of
    // recursing unboundedly — bounding a stack/CPU-exhaustion DoS. The unwrap is
    // iterative, so this returns promptly (no deep recursion).
    let mut body = minimal_ii_tiff();
    for _ in 0..(MAX_ZXIF_DEPTH + 4) {
      body = zxif_wrap(&body);
    }
    let bytes = synthetic_png(&[chunk(b"zxIf", &body), chunk(b"IEND", &[])]);
    let meta = parse_borrowed(&bytes).expect("png parses");
    // The depth cap fired: the aborted-inflate warning, and NO inner TIFF tag.
    assert!(
      meta.warnings().iter().any(|w| w == "Error inflating zxIf"),
      "depth cap must raise the aborted-inflate warning, got {:?}",
      meta.warnings(),
    );
    assert!(
      meta.exif_events().is_empty(),
      "no EXIF event should be captured past the depth cap, got {:?}",
      meta.exif_events(),
    );
  }

  #[test]
  fn nested_zxif_size_cap_bounds_inflate_with_warning() {
    // A SINGLE zXIf level whose payload decompresses to MORE than the cumulative
    // size budget (`MAX_ZXIF_INFLATE_TOTAL`). Bundled (no cap) inflates the whole
    // buffer into memory; the port's size-limited inflate
    // (`decompress_to_vec_zlib_with_limit`) refuses to grow past the budget and
    // reports it as the aborted-inflate `Error inflating zxIf` — bounding a
    // decompression-bomb OOM. miniz never allocates past the cap, so this stays
    // within one bounded buffer's worth of memory.
    let oversize = MAX_ZXIF_INFLATE_TOTAL + 4 * 1024 * 1024;
    // A run of zeros compresses to a tiny zlib stream but inflates back to its
    // full length (the classic compression bomb). The `\0` type byte + length
    // field precede the compressed stream (`PNG.pm:1386` `substr($$dataPt, 5)`).
    let body = {
      let zeros = std::vec![0u8; oversize];
      let comp = miniz_oxide::deflate::compress_to_vec_zlib(&zeros, 6);
      // `zeros` is dropped here so only the (tiny) compressed stream is held
      // through the parse; the inflate is then bounded to the budget.
      let mut b = Vec::with_capacity(5 + comp.len());
      b.push(0);
      b.extend_from_slice(&0u32.to_be_bytes());
      b.extend_from_slice(&comp);
      b
    };
    let bytes = synthetic_png(&[chunk(b"zxIf", &body), chunk(b"IEND", &[])]);
    let meta = parse_borrowed(&bytes).expect("png parses");
    assert!(
      meta.warnings().iter().any(|w| w == "Error inflating zxIf"),
      "size cap must raise the aborted-inflate warning, got {:?}",
      meta.warnings(),
    );
    assert!(
      meta.exif_events().is_empty(),
      "no EXIF event should be captured when the size cap fires, got {:?}",
      meta.exif_events(),
    );
  }

  #[test]
  fn multiple_zxif_chunks_share_one_filewide_inflate_budget() {
    // The reviewer's exact aggregate-DoS case (#178/#180 follow-up): a SINGLE
    // small PNG carrying MANY independent `zxIf` chunks, EACH of which inflates
    // to a VALID `II`/`MM` TIFF that INDIVIDUALLY stays well below the per-chunk
    // cap but COLLECTIVELY exceeds `MAX_ZXIF_INFLATE_TOTAL`. A clean `II`/`MM`
    // inflate is RETAINED as a `PngExifEvent::NativeTiff` that lives in
    // `PngMeta` for the whole parse — so were the inflate budget reset per chunk
    // (call-local), every chunk would succeed and retained EXIF memory would grow
    // as O(chunks × cap). With the FILE-WIDE budget the cumulative inflated +
    // retained total is bounded to the single cap: once it is exhausted, a further
    // chunk's inflate stops with `Error inflating zxIf` (the aborted-inflate
    // shape, `PNG.pm:943`) and is NOT retained.
    //
    // Each chunk inflates to a valid little-endian TIFF (`II*`, IFD0 at offset 8,
    // 0 entries) padded with trailing zeros to ~24 MiB; three such chunks sum to
    // ~72 MiB > the 64 MiB cap. The body is built/compressed ONCE (the chunks are
    // identical) so the test allocates only one 24 MiB buffer transiently.
    const PER_CHUNK_INFLATED: usize = 24 * 1024 * 1024;
    const CHUNKS: usize = 3;
    // Sanity: each chunk is individually under the cap, but they collectively
    // exceed it — the only way to bound retention is a shared file-wide budget.
    assert!(PER_CHUNK_INFLATED < MAX_ZXIF_INFLATE_TOTAL);
    assert!(PER_CHUNK_INFLATED * CHUNKS > MAX_ZXIF_INFLATE_TOTAL);

    let body = {
      // A minimal valid `II` TIFF header, then zero-padding so the inflated block
      // is `II`-led (retained as `NativeTiff`) yet large.
      let mut tiff = minimal_ii_tiff();
      tiff.resize(PER_CHUNK_INFLATED, 0);
      zxif_wrap(&tiff)
    };

    let mut chunks = std::vec![chunk(b"IHDR", &{
      let mut ihdr = Vec::new();
      ihdr.extend_from_slice(&1u32.to_be_bytes()); // width
      ihdr.extend_from_slice(&1u32.to_be_bytes()); // height
      ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // depth/color/comp/filter/interlace
      ihdr
    })];
    for _ in 0..CHUNKS {
      chunks.push(chunk(b"zxIf", &body));
    }
    chunks.push(chunk(b"IEND", &[]));
    let bytes = synthetic_png(&chunks);

    let meta = parse_borrowed(&bytes).expect("png parses");

    // The aggregate budget fired: at least one chunk could NOT inflate once the
    // file-wide total was exhausted.
    assert!(
      meta.warnings().iter().any(|w| w == "Error inflating zxIf"),
      "the file-wide inflate budget must abort a chunk with the aborted-inflate \
       warning once the cumulative total is exhausted, got {:?}",
      meta.warnings(),
    );

    // Retention is BOUNDED: the sum of all retained `NativeTiff` bytes is ≤ the
    // single file-wide cap (NOT O(chunks × cap)). A per-chunk-reset budget would
    // have retained all 3 chunks (~72 MiB); the file-wide budget caps it.
    let retained: usize = meta
      .exif_events()
      .iter()
      .filter_map(PngExifEvent::block)
      .map(<[u8]>::len)
      .sum();
    assert!(
      retained <= MAX_ZXIF_INFLATE_TOTAL,
      "total retained inflated-TIFF bytes must be bounded by the file-wide cap \
       ({MAX_ZXIF_INFLATE_TOTAL}), got {retained}",
    );
    // Concretely: fewer than `CHUNKS` chunks were retained (the budget stopped the
    // last one) — proving the budget did NOT reset per chunk.
    assert!(
      meta.exif_events().len() < CHUNKS,
      "the file-wide budget must stop at least one chunk from being retained \
       (a per-chunk reset would retain all {CHUNKS}), got {} events",
      meta.exif_events().len(),
    );
  }

  #[test]
  fn multiple_oversized_failing_zxif_chunks_exhaust_budget_after_the_first() {
    // Finding 1 (the FAILED-inflate accounting hole): a PNG with MANY independent
    // `zxIf` chunks, EACH of which would inflate PAST the cap (so each FAILS with
    // the limit error and is discarded). The prior code charged the file-wide total
    // only on `Inflate::Ok`, so every failing chunk forced ANOTHER near-cap inflate
    // ATTEMPT (miniz grows its buffer to `max_size` before reporting HasMoreOutput)
    // — O(chunks) transient ~64 MiB allocations, the budget never moving. The fix
    // charges the cap-hit's transient allocation: the FIRST chunk saturates the
    // file-wide total to the cap, so EVERY later chunk sees `remaining == 0` and is
    // refused IMMEDIATELY by `inflate_chunk_limited` (no miniz call, no allocation).
    //
    // The body is built/compressed ONCE (the chunks are identical) and only the
    // FIRST chunk performs a real (capped) inflate, so the whole test costs a single
    // transient ~64 MiB buffer — the later chunks short-circuit.
    let oversize = MAX_ZXIF_INFLATE_TOTAL + 4 * 1024 * 1024;
    let body = {
      // A run of zeros: tiny compressed, inflates back to `oversize` (> cap).
      let zeros = std::vec![0u8; oversize];
      let comp = miniz_oxide::deflate::compress_to_vec_zlib(&zeros, 6);
      let mut b = Vec::with_capacity(5 + comp.len());
      b.push(0); // `\0` type byte ⇒ compressed EXIF
      b.extend_from_slice(&0u32.to_be_bytes()); // unused length field
      b.extend_from_slice(&comp);
      b
    };

    const CHUNKS: usize = 4;
    let mut chunks = std::vec![chunk(b"IHDR", &{
      let mut ihdr = Vec::new();
      ihdr.extend_from_slice(&1u32.to_be_bytes()); // width
      ihdr.extend_from_slice(&1u32.to_be_bytes()); // height
      ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // depth/color/comp/filter/interlace
      ihdr
    })];
    for _ in 0..CHUNKS {
      chunks.push(chunk(b"zxIf", &body));
    }
    chunks.push(chunk(b"IEND", &[]));
    let bytes = synthetic_png(&chunks);

    let meta = parse_borrowed(&bytes).expect("png parses");

    // Every over-cap chunk reports the aborted-inflate warning — one per chunk.
    let errs = meta
      .warnings()
      .iter()
      .filter(|w| *w == "Error inflating zxIf")
      .count();
    assert_eq!(
      errs,
      CHUNKS,
      "each over-cap chunk must raise the aborted-inflate warning, got {:?}",
      meta.warnings(),
    );
    // Nothing is retained (no chunk yields a valid TIFF).
    assert!(
      meta.exif_events().is_empty(),
      "no EXIF event should be retained from failing chunks, got {:?}",
      meta.exif_events(),
    );
    // THE key assertion: the file-wide total is charged EXACTLY the cap — the first
    // chunk's cap-hit charged `max_size == cap`, and every later chunk short-
    // circuited at `remaining == 0` and charged nothing. The pre-fix code left this
    // at 0 (failed inflates were never charged), which is what let each chunk replay
    // a near-cap inflate. So this both proves the budget is exhausted after the
    // first AND that the later chunks added no further allocation.
    assert_eq!(
      meta.zxif_inflated_total(),
      MAX_ZXIF_INFLATE_TOTAL,
      "the first over-cap chunk must saturate the file-wide budget to exactly the \
       cap (and later chunks must add nothing, having short-circuited)",
    );
  }

  #[test]
  fn near_cap_valid_zxif_retained_by_move_charges_one_buffer_no_double() {
    // Finding 2 (the retain-clone peak): a SINGLE `zxIf` that inflates to a valid
    // near-cap `II`/`MM` TIFF. The prior code did `NativeTiff(level.to_vec())` —
    // CLONING the inflated buffer into the retained event while the local inflate
    // buffer was still alive ⇒ ~2× the cap live at the instant of retention. The fix
    // MOVES the inflated buffer into the event (no clone), so the single already-
    // charged buffer simply BECOMES the retained one: peak == one buffer ≤ cap.
    //
    // Deterministic proof within unit-test reach: the retained block length equals
    // the full inflated length (the move preserved the whole buffer), AND the file-
    // wide total was charged EXACTLY ONCE (== that length) — a near-cap value that
    // leaves < that length of budget remaining, i.e. only ONE near-cap buffer's
    // worth was ever accounted (a second near-cap chunk would now be refused).
    const INFLATED: usize = MAX_ZXIF_INFLATE_TOTAL - 1024 * 1024; // ~63 MiB, near cap
    assert!(INFLATED < MAX_ZXIF_INFLATE_TOTAL);

    let body = {
      // A minimal valid little-endian TIFF, zero-padded to ~63 MiB so the inflated
      // block is `II`-led (retained) yet near the cap. Compressed ONCE (a run of
      // mostly zeros compresses tiny); the ~63 MiB buffer is dropped after compress.
      let mut tiff = minimal_ii_tiff();
      tiff.resize(INFLATED, 0);
      zxif_wrap(&tiff)
    };
    let bytes = synthetic_png(&[
      chunk(b"IHDR", &{
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&1u32.to_be_bytes());
        ihdr.extend_from_slice(&1u32.to_be_bytes());
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
        ihdr
      }),
      chunk(b"zxIf", &body),
      chunk(b"IEND", &[]),
    ]);

    let meta = parse_borrowed(&bytes).expect("png parses");
    assert!(
      meta.warnings().is_empty(),
      "a clean near-cap zXIf must not warn, got {:?}",
      meta.warnings(),
    );
    // Exactly one retained TIFF, holding the WHOLE inflated buffer (the move kept
    // every byte; a sub-slice clone or truncation would shorten it).
    let blocks: Vec<&[u8]> = meta
      .exif_events()
      .iter()
      .filter_map(PngExifEvent::block)
      .collect();
    assert_eq!(blocks.len(), 1, "one native TIFF expected");
    assert_eq!(
      blocks[0].len(),
      INFLATED,
      "the retained TIFF must be the whole moved inflate buffer",
    );
    assert!(
      blocks[0].starts_with(b"II"),
      "retained block is the II TIFF"
    );
    // The file-wide total was charged EXACTLY the inflated length — ONCE. The move
    // means retention added no second allocation; a clone would still charge once
    // here (the charge is on inflate, not retain) but would have transiently held
    // TWO near-cap buffers at the retain instant. The single charge == retained len
    // is the accounting that the peak is one buffer ≤ cap, NOT 2× the cap.
    assert_eq!(
      meta.zxif_inflated_total(),
      INFLATED,
      "the near-cap inflate must be charged exactly once (no double-buffer / clone)",
    );
    // Corollary: the remaining budget is now < INFLATED, so only ONE near-cap
    // buffer's worth is accounted file-wide (peak bounded by the cap).
    assert!(
      MAX_ZXIF_INFLATE_TOTAL - meta.zxif_inflated_total() < INFLATED,
      "after one near-cap retain the remaining budget must be below another \
       near-cap buffer — the peak is bounded to one buffer",
    );
  }

  #[test]
  fn tiny_tiff_with_padded_zlib_stream_retained_boxed_exact_no_undercharge() {
    // The capacity-vs-length follow-up (#178/#180 rounds 5-6): a `zxIf` payload that
    // decompresses to a TINY `II`/`MM` TIFF but whose miniz output `Vec` holds a
    // near-cap CAPACITY. `decompress_to_vec_zlib_with_limit` sizes its output buffer
    // from the COMPRESSED-input length — `vec![0; min(2*input.len(), max_size)]` up
    // front (miniz_oxide 0.9.1) — and on success only `truncate`s to the decompressed
    // length, leaving that capacity intact. So a tiny valid zlib stream followed by
    // large trailing PADDING (the padding inflates nothing but inflates `input.len()`)
    // yields a 14-byte TIFF in a Vec whose capacity is ~2× the padding. Charging only
    // `len` (14) would undercharge if the retained allocation kept that capacity: each
    // chunk would retain a near-cap ALLOCATION (in a `NativeTiff`) while the file-wide
    // total barely moves — O(chunks × cap) retained CAPACITY even though every charged
    // LENGTH is tiny. The fix retains the inflated TIFF as a `Box<[u8]>`
    // (`into_boxed_slice`), whose allocation is EXACTLY its length BY CONSTRUCTION (a
    // boxed slice carries no excess capacity) — so the charge is exact and the
    // retained allocation equals the (tiny) retained length, GUARANTEED by the type,
    // not by an allocator-dependent `shrink_to_fit`.
    //
    // Build one chunk: a minimal `II` TIFF, zlib-compressed, then ~24 MiB of trailing
    // zero padding appended AFTER the compressed stream (so the inflate payload —
    // `cur[5..]`, i.e. `comp + padding` — is ~24 MiB ⇒ a ~48 MiB miniz output buffer
    // for a 14-byte result). MANY such chunks: a naive `Vec`-retain of miniz's output
    // would retain ~48 MiB of capacity each (O(chunks × cap)); the fix retains each as
    // a 14-byte `Box<[u8]>` whose allocation is exactly its length by construction.
    const PADDING: usize = 24 * 1024 * 1024;
    const CHUNKS: usize = 4;
    let tiff = minimal_ii_tiff();
    let tiny_len = tiff.len();
    let body = {
      let comp = miniz_oxide::deflate::compress_to_vec_zlib(&tiff, 6);
      let mut b = Vec::with_capacity(5 + comp.len() + PADDING);
      b.push(0); // `\0` type byte ⇒ compressed EXIF
      b.extend_from_slice(&(tiny_len as u32).to_be_bytes()); // unused length field
      b.extend_from_slice(&comp);
      // Trailing padding: NOT part of the zlib stream (the stream ends at `Done`),
      // but it inflates `payload.len()` so miniz pre-allocates ~2× it.
      b.resize(b.len() + PADDING, 0);
      b
    };

    let mut chunks = std::vec![chunk(b"IHDR", &{
      let mut ihdr = Vec::new();
      ihdr.extend_from_slice(&1u32.to_be_bytes()); // width
      ihdr.extend_from_slice(&1u32.to_be_bytes()); // height
      ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // depth/color/comp/filter/interlace
      ihdr
    })];
    for _ in 0..CHUNKS {
      chunks.push(chunk(b"zxIf", &body));
    }
    chunks.push(chunk(b"IEND", &[]));
    let bytes = synthetic_png(&chunks);

    let meta = parse_borrowed(&bytes).expect("png parses");

    // A tiny valid TIFF is NOT an over-cap inflate: every chunk inflates cleanly, so
    // there is no aborted-inflate warning. (The trailing padding past the zlib stream
    // is benign — miniz stops at the stream's `Done`.)
    assert!(
      meta.warnings().iter().all(|w| w != "Error inflating zxIf"),
      "a tiny TIFF with trailing zlib padding must inflate cleanly, got {:?}",
      meta.warnings(),
    );

    // EVERY chunk is retained (its charge is the tiny TIFF length, so the file-wide
    // budget is never exhausted) — proving the undercharge is precisely the danger the
    // capacity dimension posed: with a near-cap `Vec`-retain, all CHUNKS would also be
    // retained but each holding a ~48 MiB CAPACITY (O(chunks × cap) live), while the
    // charged total stayed near zero. As `Box<[u8]>` the retained allocation collapses
    // to the retained length.
    let retained: Vec<&[u8]> = meta
      .exif_events()
      .iter()
      .filter_map(|ev| match ev {
        PngExifEvent::NativeTiff(v) => Some(v.as_ref()),
        _ => None,
      })
      .collect();
    assert_eq!(
      retained.len(),
      CHUNKS,
      "every tiny-TIFF chunk inflates cleanly and is retained, got {} events",
      meta.exif_events().len(),
    );

    // The structural close, BY CONSTRUCTION: each retained buffer is a `Box<[u8]>`,
    // whose backing allocation is EXACTLY its length (a boxed slice has no excess
    // capacity — capacity == len is a type-level guarantee, not an allocator-dependent
    // `shrink_to_fit` result). So summing `len()` gives the EXACT total retained bytes.
    // Each is the tiny TIFF (`tiny_len`), NOT a near-cap allocation.
    let mut total_retained = 0usize;
    for v in &retained {
      assert_eq!(
        v.len(),
        tiny_len,
        "the retained boxed block is the tiny inflated TIFF (its allocation == its \
         length by construction), not the ~48 MiB padding capacity; got len {}",
        v.len(),
      );
      assert!(v.starts_with(b"II"), "retained block is the II TIFF");
      // A `Box<[u8]>`'s allocation size IS its length (exact by construction).
      total_retained += v.len();
    }

    // Total retained ALLOCATION is bounded by the cap — accurately. As `Box<[u8]>` it
    // is just `CHUNKS * tiny_len` (a few dozen bytes); a near-cap `Vec`-retain would be
    // `CHUNKS * ~48 MiB` (~192 MiB) ≫ the 64 MiB cap, the reopened O(chunks × cap) DoS.
    assert!(
      total_retained <= MAX_ZXIF_INFLATE_TOTAL,
      "total retained allocation must be bounded by the file-wide cap \
       ({MAX_ZXIF_INFLATE_TOTAL}); got {total_retained}",
    );

    // The file-wide charge equals the summed retained LENGTH (== the retained
    // allocation, by construction), so the accounting is exact: the charge is neither
    // an under- nor over-count of the live retained memory — independent of the
    // allocator (no `shrink_to_fit` microstructure gap behind a boxed slice).
    assert_eq!(
      meta.zxif_inflated_total(),
      CHUNKS * tiny_len,
      "the file-wide total must charge exactly the summed retained length",
    );
    assert_eq!(
      meta.zxif_inflated_total(),
      total_retained,
      "charge == retained allocation: the capacity-vs-length gap is closed at the type \
       level (Box<[u8]> is exact by construction)",
    );
  }
}
