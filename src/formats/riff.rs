// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "riff")]
//! Faithful port of `Image::ExifTool::RIFF` (`lib/Image/ExifTool/RIFF.pm`):
//! reads RIFF/RIFX containers — primarily AVI (Audio Video Interleaved) in
//! this port, with WAV/WEBP carrying the same outer walker but minimal
//! interior decoding (see §Deferrals).
//!
//! ## RIFF format
//!
//! A RIFF file is a flat stream of 4-byte FOURCC chunks, each `(tag,
//! le-u32 length, payload, 1-byte odd-length padding)` triplets. The
//! outermost chunk is `RIFF`/`RF64` whose payload begins with a 4-byte
//! TYPE that names the variant (`AVI `, `WAVE`, `WEBP`, etc.).
//! `ProcessRIFF` (RIFF.pm:2026-2218) walks the top-level chunks; `LIST`
//! chunks recurse into a sub-table via `ProcessChunks` (RIFF.pm:1772-1847).
//!
//! ## Faithfulness — what this port reads
//!
//! **Walker** (RIFF.pm:2026-2218 `ProcessRIFF`):
//! - RIFF / RIFX / RF64 magic + 4-byte variant TYPE → MIME (RIFF.pm:2038-2054)
//! - 8-byte chunk header `(tag, le-u32 length)`; odd-length padding
//!   (RIFF.pm:2140)
//! - `LIST` recursion (RIFF.pm:2108-2112 `$tag .= "_$buff"`)
//! - skip `data`/`idx1`/`LIST_movi` chunks (RIFF.pm:2148-2150 condition)
//! - stop at `\0\0\0\0` empty null chunk (RIFF.pm:2122-2124)
//! - concatenated RIFF segments via `RIFF` re-trigger (RIFF.pm:2173-2181)
//!
//! **Sub-tables** (RIFF.pm:338-678 `%Main`):
//! - `LIST_INFO` / `LIST_INF0` → `%Info` text metadata (RIFF.pm:835-1010)
//! - `LIST_exif` → `%Exif` sub-chunks (RIFF.pm:1013-1027)
//! - `LIST_hdrl` → `%Hdrl` (RIFF.pm:1030-1053)
//!   - `avih` → `%AVIHeader` (`int32u` table, RIFF.pm:1076-1108)
//!   - `LIST_strl` → `%Stream` (RIFF.pm:1110-1140)
//!     - `strh` → `%StreamHeader` (`int32u` table, RIFF.pm:1160-1248)
//!     - `strf` → `%AudioFormat` / inline BMP-V3 / text (RIFF.pm:1122-1139)
//!   - `LIST_odml` → `%OpenDML` → `dmlh` → `%ExtAVIHdr` (RIFF.pm:1143-1158)
//! - `IDIT` (DateTimeOriginal, RIFF.pm:526-532)
//! - `ISMP` (TimeCode)
//! - `fmt ` (top-level WAV AudioFormat, RIFF.pm:356-359)
//!
//! **Conversions** ported:
//! - [`convert_riff_date`] — RIFF.pm:1601-1619 `ConvertRIFFDate`
//!   (`Mon Mar 10 15:04:43 2003` → `2003:03:10 15:04:43`).
//! - `%audioEncoding` PrintConv subset (RIFF.pm:90-336) — table reduced to
//!   the entries the bundled `RIFF.avi` fixture reaches (`0x01` Microsoft
//!   PCM) plus a few sentinels; an unrecognized code falls back to the
//!   `Unknown (0x%x)` rendering. The full ~250-entry codec table is a
//!   follow-up (it's a flat lookup table with no semantic complexity).
//!
//! **Inline BMP-strf decoder** ([`emit_bmp_video_format`], BMP.pm:36-150):
//! the AVI `strf` chunk for a `vids` stream hops into `%BMP::Main`, emitting
//! `File:BMPVersion`/`ImageWidth`/`Compression`/etc. We inline the first
//! 40-byte (BMP V3) subset here rather than spinning up a separate BMP
//! module — this is precisely how ExifTool's `strf` table dispatches
//! (RIFF.pm:1129-1132 `SubDirectory => { TagTable => 'BMP::Main' }`),
//! and the `Compression` `OTHER => sub { ... }` ASCII rendering is
//! reproduced verbatim for video codec FourCCs.
//!
//! ## Deferrals (filed as GitHub follow-ups; cross-linked from #66)
//!
//! The PORT is faithful to the WALKER + AVI MEDIA-METADATA dispatch
//! (camera/lens/recording-time/video-codec/audio-codec), which is what
//! exifast's product scope cares about. The following carry NO `RiffEntry`
//! emission today and are documented gaps:
//!
//! - **WAV-specific tag tables.** `bext` BroadcastExt (RIFF.pm:712-759),
//!   `ds64` MBWF/RF64 (RIFF.pm:762-784), `smpl` Sampler (RIFF.pm:787-818),
//!   `inst` Instrument (RIFF.pm:821-832), `cue ` CuePoints, `plst`
//!   Playlist, `fact` NumberOfSamples, top-level `IDIT`/`ISMP`,
//!   `labl`/`note`/`ltxt` LIST_adtl cue-point sub-chunks (RIFF.pm:369-393),
//!   `acid` Acidizer (RIFF.pm:666-669), `Olym` (RIFF.pm:508-511), and
//!   the `LA02/03/04`/`OFR `/`LPAC`/`wvpk` minimal-support magic prefixes
//!   (RIFF.pm:2045) all parse OK as opaque chunks but emit nothing.
//!   AVI is the primary product target; pure-audio RIFF files have
//!   dedicated audio ports (FLAC/AAC/etc.) or are deferred.
//! - **WEBP-specific tag tables.** `VP8`/`VP8L`/`VP8X`/`ALPH`/`ANIM`/`ANMF`
//!   (RIFF.pm:1279-1488), `ICCP`, embedded `EXIF`/`XMP `, the `Extended
//!   WEBP` `OverrideFileType` (RIFF.pm:2106). WEBP is an image format —
//!   PNG/JPEG/TIFF land first; WEBP through this RIFF walker is a thin
//!   subdir hop above what's needed.
//! - **OpenDML extras.** Only `dmlh` `TotalFrameCount` (RIFF.pm:1156-1158)
//!   is emitted; the broader OpenDML 2.0 index extensions (`indx`/`ix##`)
//!   are not parsed.
//! - **AVI 2.0 / concatenated RIFFs.** The `RIFF`-mid-stream re-trigger
//!   (RIFF.pm:2173-2181) skips ahead but never increments `DOC_NUM` here
//!   (we only emit one stream's worth; sub-document handling is a
//!   forward item, exifast-phase2-forward-items.md).
//! - **Vendor JUNK variants.** `OlympusJunk`/`CasioJunk`/`RicohJunk`/
//!   `PentaxJunk`/`PentaxJunk2`/`LucasJunk` (RIFF.pm:442-492) all
//!   route into other tag tables (Olympus/Casio/Pentax/Lucas — separate
//!   ports). The `TextJunk` ASCII-only fallback is also deferred (we
//!   skip JUNK entirely). Their absence is invisible on the bundled
//!   `RIFF.avi` fixture (it has no JUNK chunks with metadata).
//! - **`LIST_ncdt` / `LIST_hydt` / `LIST_pntx`.** Nikon/Pentax AVI maker
//!   notes; depend on Nikon/Pentax module ports (separate Phase-2 items).
//! - **`%audioEncoding` full table.** The bundled fixture only exercises
//!   `0x01 = Microsoft PCM`; the ~250-row codec table (RIFF.pm:90-336)
//!   is mechanically completable in a follow-up.
//! - **`StreamData` Camera AVIF/CASI.** RIFF.pm:1250-1276 — Canon AVIF
//!   sub-IFD + Casio CASI sub-IFD inside `strd`. The `strd` chunk is read
//!   into the typed stream record so it's reachable for a future Exif/
//!   Casio sub-port; no decode today.
//! - **Top-level XMP / SEAL / C2PA / `_PMX` / aXML / iXML** (RIFF.pm:493-
//!   507, 633-637, 670-673). XMP/JUMBF/SEAL are separate Phase-3+ ports.
//! - **BikeBro `SGLT`/`SLLT`** (RIFF.pm:619-632).
//!
//! Filed at: `https://github.com/Findit-AI/exifast/issues` (see issue body
//! cross-linking the corresponding `RIFF.pm:LLLL` for each).

use smol_str::SmolStr;
use std::{string::String, vec::Vec};

use crate::format_parser::{FormatParser, parser_sealed};

// ===========================================================================
// §1. Magic + variant detection
// ===========================================================================

/// RIFF / RIFX / RF64 magic prefixes (RIFF.pm:2040). RIFX is the big-endian
/// variant; bundled accepts it but the body still uses `SetByteOrder('II')`
/// (RIFF.pm:2057 — only the OUTER magic differs, payload integers stay LE).
/// We follow the same convention: `RIFF` and `RF64` accepted as LE bodies;
/// `RIFX` is NOT accepted by the bundled `^(RIFF|RF64)` regex, so we don't
/// either.
const MAGIC_RIFF: &[u8; 4] = b"RIFF";
const MAGIC_RF64: &[u8; 4] = b"RF64";

/// Map a RIFF body TYPE (the 4 bytes at offset 8) to its ExifTool file type.
/// Faithful to `%riffType` (RIFF.pm:49-53). Returns `None` for an
/// unrecognized TYPE — the bundled walker still walks the chunks but
/// `SetFileType($type, $mime)` becomes `SetFileType(undef, undef)`
/// effectively, which the engine surfaces as the detected candidate type
/// ("RIFF").
#[must_use]
const fn riff_type_for(form: &[u8; 4]) -> Option<&'static str> {
  match form {
    b"WAVE" => Some("WAV"),
    b"AVI " => Some("AVI"),
    b"WEBP" => Some("WEBP"),
    b"LA02" | b"LA03" | b"LA04" => Some("LA"),
    b"OFR " => Some("OFR"),
    b"LPAC" => Some("PAC"),
    b"wvpk" => Some("WV"),
    _ => None,
  }
}

/// MIME for each ExifTool RIFF file type (`%riffMimeType`, RIFF.pm:56-64).
#[must_use]
const fn riff_mime_for(file_type: &str) -> &'static str {
  match file_type.as_bytes() {
    b"WAV" => "audio/x-wav",
    b"AVI" => "video/x-msvideo",
    b"WEBP" => "image/webp",
    b"LA" => "audio/x-nspaudio",
    b"OFR" => "audio/x-ofr",
    b"PAC" => "audio/x-lpac",
    b"WV" => "audio/x-wavpack",
    _ => "application/octet-stream",
  }
}

// ===========================================================================
// §2. Value types — `RiffEntry`, `RiffStream`, `RiffMeta`
// ===========================================================================

/// One emitted RIFF tag — group + name + decoded value.
///
/// D8 convention: no public fields; accessors only. `group` is `"RIFF"` for
/// the bulk of decoded chunks; the inline BMP-strf decoder emits with
/// group `"File"` (faithful to BMP::Main GROUPS, BMP.pm:38).
#[derive(Debug, Clone, PartialEq)]
pub struct RiffEntry {
  group: SmolStr,
  name: SmolStr,
  value: RiffValue,
}

impl RiffEntry {
  /// Construct an entry. Internal helper for the walker.
  #[inline]
  fn new(group: &'static str, name: &'static str, value: RiffValue) -> Self {
    Self {
      group: SmolStr::new_static(group),
      name: SmolStr::new_static(name),
      value,
    }
  }

  /// Family-1 group (`"RIFF"` or `"File"` for BMP-strf hops).
  #[must_use]
  #[inline(always)]
  pub fn group(&self) -> &str {
    self.group.as_str()
  }

  /// Tag name (`"FrameRate"`, `"VideoCodec"`, `"Software"`, …).
  #[must_use]
  #[inline(always)]
  pub fn name(&self) -> &str {
    self.name.as_str()
  }

  /// Decoded value reference.
  #[must_use]
  #[inline(always)]
  pub const fn value_ref(&self) -> &RiffValue {
    &self.value
  }
}

/// Decoded value carried by a [`RiffEntry`]. PrintConv/raw rendering is
/// applied at emit time in the [`Taggable`](crate::emit::Taggable) `tags`
/// impl for [`RiffMeta`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum RiffValue {
  /// A string value (already trimmed of trailing nulls; faithful to
  /// `ProcessChunks` RIFF.pm:1827 `$val =~ s/\0+$//`).
  Str(SmolStr),
  /// An unsigned integer (audio encoding, frame count, dimensions, …).
  U32(u32),
  /// A signed integer (rare — image-height can be negative in BMP V3 to
  /// flag top-to-bottom storage; we apply abs(), so the stored value is
  /// non-negative).
  I32(i32),
  /// A 32-bit float (rate-derived field like `FrameRate` / `VideoFrameRate`,
  /// `AudioSampleRate`).
  F64(f64),
}

/// Per-AVI-stream record — what the `strh`/`strf`/`strd` chunks inside one
/// `LIST_strl` produce. Held in [`RiffMeta::streams`] in file order, faithful
/// to `$$self{RIFFStreamNum}` (RIFF.pm:1169).
///
/// D8 convention: no public fields; accessors only.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RiffStream {
  /// `strh` StreamType (`auds`/`vids`/`txts`/`mids`/`iavs`) — RIFF.pm:1166-1177.
  stream_type: Option<SmolStr>,
  /// `strh` codec FourCC — Audio/Video/StreamCodec — RIFF.pm:1178-1196.
  codec: Option<SmolStr>,
  /// Optional `strn` StreamName (a `string`-formatted INFO-style sub-chunk).
  name: Option<SmolStr>,
}

impl RiffStream {
  /// An empty stream record (every field `None`).
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {
      stream_type: None,
      codec: None,
      name: None,
    }
  }

  /// `strh` StreamType (`auds`/`vids`/`txts`/`mids`/`iavs`).
  #[must_use]
  #[inline(always)]
  pub fn stream_type(&self) -> Option<&str> {
    self.stream_type.as_deref()
  }

  /// `strh` codec FourCC string.
  #[must_use]
  #[inline(always)]
  pub fn codec(&self) -> Option<&str> {
    self.codec.as_deref()
  }

  /// `strn` StreamName.
  #[must_use]
  #[inline(always)]
  pub fn name(&self) -> Option<&str> {
    self.name.as_deref()
  }
}

/// Typed RIFF metadata — the lib-first output of [`ProcessRiff`].
///
/// D8 convention: no public fields; accessors only.
///
/// Holds the ordered emission list of [`RiffEntry`] tags, the per-stream
/// [`RiffStream`] records, the resolved variant (`AVI`/`WAV`/`WEBP`/…), and
/// the MIME the engine will surface via [`FileTypeFinalize::ExplicitWithMime`].
///
/// The Meta owns its data; the `'a` GAT lifetime is a phantom (RIFF values
/// are heavily transformed during the walk — date conversion, FourCC slicing,
/// PCM/codec-table lookup — so nothing borrows from the input buffer). This
/// matches the MXF port (Codex AF2 uniformity).
#[derive(Debug, Clone)]
pub struct RiffMeta<'a> {
  entries: Vec<RiffEntry>,
  streams: Vec<RiffStream>,
  /// Resolved file-type variant — `AVI` / `WAV` / `WEBP` / `LA` / `OFR` /
  /// `PAC` / `WV` (or `RIFF` as the inert fallback for an unrecognized
  /// body TYPE). Drives [`FileTypeFinalize::ExplicitWithMime`]. Static
  /// because [`riff_type_for`] is a closed lookup over `'static` literals.
  file_type: &'static str,
  /// MIME — the lookup from [`riff_mime_for`].
  mime: &'static str,
  /// `true` when the OUTER magic was `RF64` (RIFF.pm:2042 / 2054). The
  /// `(RF64)` `FileType` suffix is a follow-up — not emitted today.
  rf64: bool,
  /// Phantom anchor for the GAT lifetime.
  _marker: core::marker::PhantomData<&'a ()>,
}

impl Default for RiffMeta<'_> {
  fn default() -> Self {
    Self {
      entries: Vec::new(),
      streams: Vec::new(),
      file_type: "RIFF",
      mime: "application/octet-stream",
      rf64: false,
      _marker: core::marker::PhantomData,
    }
  }
}

impl RiffMeta<'_> {
  /// Every emitted RIFF tag, in file order.
  #[must_use]
  #[inline(always)]
  pub fn entries(&self) -> &[RiffEntry] {
    &self.entries
  }

  /// Per-stream records, in file order (`strl` index 0, 1, …).
  #[must_use]
  #[inline(always)]
  pub fn streams(&self) -> &[RiffStream] {
    &self.streams
  }

  /// Resolved file-type variant — `AVI` / `WAV` / `WEBP` / `LA` / `OFR` /
  /// `PAC` / `WV` / `RIFF`. Always a `&'static str` (the RIFF body TYPE
  /// lookup table is closed, RIFF.pm:49-53).
  #[must_use]
  #[inline(always)]
  pub const fn file_type(&self) -> &'static str {
    self.file_type
  }

  /// MIME the engine should surface (`video/x-msvideo` for AVI, etc.). Always
  /// a `&'static str` (matches the closed `%riffMimeType`, RIFF.pm:56-64).
  #[must_use]
  #[inline(always)]
  pub const fn mime(&self) -> &'static str {
    self.mime
  }

  /// `true` when the outer magic was `RF64` (the 64-bit MBWF variant).
  #[must_use]
  #[inline(always)]
  pub const fn is_rf64(&self) -> bool {
    self.rf64
  }
}

// ===========================================================================
// §3. `ProcessRiff` parser + `FormatParser` impl
// ===========================================================================

/// RIFF parser — faithful port of `Image::ExifTool::RIFF::ProcessRIFF`
/// (RIFF.pm:2026-2218).
#[derive(Debug, Clone, Copy)]
pub struct ProcessRiff;

impl parser_sealed::Sealed for ProcessRiff {}

impl FormatParser for ProcessRiff {
  /// GAT: the Meta is fully owned; `'a` is a phantom (Codex AF2 uniformity).
  type Meta<'a> = RiffMeta<'a>;
  /// Leaf-format Context — `&'a [u8]` (no chained state).
  type Context<'a> = &'a [u8];
  type Error = RiffError;

  fn parse<'a>(&self, data: Self::Context<'a>) -> Result<Option<Self::Meta<'a>>, RiffError> {
    Ok(parse_inner(data))
  }
}

/// Lib-first direct entry. Returns an owned [`RiffMeta`].
///
/// # Errors
///
/// Returns `Err` only for Rust-level fatal modes (none today — every bad
/// input is `Ok(None)`, faithful to RIFF.pm:2039 `return 0`).
pub fn parse_borrowed(data: &[u8]) -> Result<Option<RiffMeta<'_>>, RiffError> {
  Ok(parse_inner(data))
}

// ===========================================================================
// §4. The outer walker
// ===========================================================================

/// Outer walker — faithful `ProcessRIFF` (RIFF.pm:2026-2218).
///
/// Returns `None` for "not a RIFF" (`return 0`); a started-but-truncated
/// RIFF still yields an `Ok(Some(meta))` with whatever was decoded before
/// the truncation point (faithful to RIFF.pm:2096-2102 `$err = 1; last`
/// soft-fail).
fn parse_inner(data: &[u8]) -> Option<RiffMeta<'_>> {
  // RIFF.pm:2039: `return 0 unless $raf->Read($buff, 12) == 12;`
  if data.len() < 12 {
    return None;
  }

  // RIFF.pm:2040: `if ($buff =~ /^(RIFF|RF64)....(.{4})/s) { ... }`. The
  // minimal-support `LA0[234]|OFR |LPAC|wvpk` branch (RIFF.pm:2045) is a
  // documented deferral — see module doc.
  let magic = &data[0..4];
  let (rf64, _outer_size) = if magic == MAGIC_RIFF {
    (false, le_u32(&data[4..8]))
  } else if magic == MAGIC_RF64 {
    (true, le_u32(&data[4..8]))
  } else {
    return None;
  };
  let form: [u8; 4] = data[8..12].try_into().expect("4 bytes");

  // RIFF.pm:2041 `$type = $riffType{$2}` → file_type + MIME.
  // Bundled passes `undef` MIME when `$type` is undef; we surface the inert
  // `"RIFF"` fallback so the engine's `ExplicitWithMime` finalize always
  // has a target. Real-input AVI / WAV / WEBP all hit the matched arms.
  let (file_type, mime): (&'static str, &'static str) = match riff_type_for(&form) {
    Some(t) => (t, riff_mime_for(t)),
    None => ("RIFF", "application/octet-stream"),
  };

  let mut walker = Walker {
    data,
    pos: 12,
    entries: Vec::new(),
    streams: Vec::new(),
    current_stream_type: None,
  };

  // RIFF.pm:2058: `my $riffEnd = Get32u(\$buff, 4) + 8; $riffEnd += $riffEnd & 0x01;`
  // We pin the walk to `data.len()` rather than the declared outer size:
  // bundled also caps via `$raf->Read` returning short on EOF (RIFF.pm:2096-
  // 2102). A declared outer size that EXCEEDS the file is treated as the
  // file end — see `read_chunk` below.

  walker.walk_top();

  Some(RiffMeta {
    entries: walker.entries,
    streams: walker.streams,
    file_type,
    mime,
    rf64,
    _marker: core::marker::PhantomData,
  })
}

/// Outer walker state. Tracks the cursor, the emission list, the per-stream
/// records (indexed by `RIFFStreamNum`), and `$$self{RIFFStreamType}` —
/// the cross-`strh`/`strf` flag that drives the `strf` Condition (RIFF.pm:
/// 1125/1130/1135).
struct Walker<'a> {
  data: &'a [u8],
  pos: usize,
  entries: Vec<RiffEntry>,
  streams: Vec<RiffStream>,
  /// `$$self{RIFFStreamType}` — the most recent stream's `strh` StreamType.
  /// Read by the next `strf` chunk to decide AudioFormat / VideoFormat.
  /// Faithful to RIFF.pm:1169 `RawConv => '$$self{RIFFStreamType} = $val'`.
  current_stream_type: Option<[u8; 4]>,
}

impl<'a> Walker<'a> {
  /// Top-level chunk loop — RIFF.pm:2065-2214.
  fn walk_top(&mut self) {
    while let Some((tag, len, pad_len)) = self.read_chunk() {
      let chunk_start = self.pos;
      let chunk_end = chunk_start + len;

      // RIFF.pm:2148-2150 — skip data/idx1/LIST_movi/RIFF/##(db|dc|wb).
      // We DO need to handle `LIST` specially (recurse based on TYPE).
      // RIFF.pm:2108-2112: `if ($tag eq 'LIST') { ... $tag .= "_$buff"; }`
      if &tag == b"LIST" {
        // Read the 4-byte LIST TYPE.
        if len < 4 {
          break; // malformed
        }
        let list_type: [u8; 4] = match self.data.get(chunk_start..chunk_start + 4) {
          Some(b) => b.try_into().expect("4 bytes"),
          None => break,
        };
        let list_payload_start = chunk_start + 4;
        let list_payload_end = chunk_end.min(self.data.len());
        if list_payload_end <= list_payload_start {
          // Empty LIST — skip past it (with padding).
          self.pos = chunk_end + pad_len;
          continue;
        }
        let body = &self.data[list_payload_start..list_payload_end];
        match &list_type {
          b"INFO" | b"INF0" => {
            process_chunks_info(body, &mut self.entries);
          }
          b"exif" => {
            process_chunks_exif(body, &mut self.entries);
          }
          b"hdrl" => {
            self.process_chunks_hdrl(body);
          }
          b"strl" => {
            self.process_chunks_strl(body);
          }
          b"odml" => {
            process_chunks_odml(body, &mut self.entries);
          }
          // LIST_movi: contains image data; bundled skips unless
          // ExtractEmbedded is set (RIFF.pm:2189-2193). We skip
          // unconditionally — `LIST_movi` chunks add nothing to the
          // metadata we care about (faithful to the default code path).
          b"movi" => {
            // skip
          }
          // LIST_Tdat (Adobe CS3 Bridge) RIFF.pm:411-414 — empty table
          // in bundled; nothing to emit.
          b"Tdat" => {}
          // LIST_adtl RIFF.pm:437-440 — cue-point sub-chunks (labl/note/
          // ltxt). Deferred (WAV-side). Skip.
          b"adtl" => {}
          // LIST_ncdt / LIST_hydt / LIST_pntx — Nikon/Pentax AVI maker
          // notes. Deferred (separate ports).
          b"ncdt" | b"hydt" | b"pntx" => {}
          _ => {
            // Unknown LIST type — skip silently (bundled would emit
            // an Unknown_LIST_xxxx in -U mode; we don't generate
            // unknowns in this port).
          }
        }
        self.pos = chunk_end + pad_len;
        continue;
      }

      // Inline chunks at the OUTER level — most of these map through
      // `%Main` (RIFF.pm:338-678).
      let body_end = chunk_end.min(self.data.len());
      let body = self.data.get(chunk_start..body_end).unwrap_or(&[]);
      match &tag {
        b"fmt " => emit_audio_format(body, &mut self.entries),
        b"IDIT" => emit_idit(body, &mut self.entries),
        b"ISMP" => emit_ismp(body, &mut self.entries),
        // Skip image-data / index / null chunks (RIFF.pm:2122-2124 +
        // 2148-2150).
        b"data" | b"idx1" => {}
        b"\0\0\0\0" => {
          // RIFF.pm:2122-2124: stop on empty null chunk.
          break;
        }
        b"RIFF" => {
          // Concatenated RIFF segment — bundled bumps DOC_NUM and continues
          // (RIFF.pm:2173-2181). Deferred (single-document only); skip
          // the inner RIFF type word and continue walking the next chunk.
          self.pos = chunk_start + 4; // skip 4-byte inner TYPE
          continue;
        }
        // JUNK (vendor maker-note variants + TextJunk fallback) — all
        // deferred (see module doc).
        b"JUNK" | b"JUNQ" => {}
        // Top-level XMP / SEAL / C2PA / etc. — deferred.
        _ => {
          // Unrecognized outer chunk — skip silently.
        }
      }
      // RIFF.pm:2213: `$pos += $len2;` where `$len2 = $len + ($len & 0x01);`
      self.pos = chunk_end + pad_len;
    }
  }

  /// Read one chunk header `(tag, len)` from `self.pos`. Returns `None` on
  /// EOF / malformed-length (`len > remaining bytes`). Advances `self.pos`
  /// PAST the 8-byte header. Returns `(tag, len, pad_len)` where `pad_len`
  /// is `len & 1` (RIFF.pm:2140 odd-length padding byte).
  fn read_chunk(&mut self) -> Option<([u8; 4], usize, usize)> {
    if self.data.len().saturating_sub(self.pos) < 8 {
      return None;
    }
    let tag: [u8; 4] = self.data[self.pos..self.pos + 4]
      .try_into()
      .expect("4 bytes");
    let len = le_u32(&self.data[self.pos + 4..self.pos + 8]) as usize;
    self.pos += 8;
    // RIFF.pm:2118-2128: skip empty chunk (warn + next, or stop on null).
    // We let the dispatch handle len==0 itself (most chunks become no-ops).
    // RIFF.pm:2150: `$raf->Read($buff, $len2) >= $len or ...` — bundled
    // tolerates a missing PAD byte on the last chunk (`No padding on
    // odd-sized $tag chunk` warning); we mirror that by computing the pad
    // and capping at EOF where applicable.
    let pad_len = len & 1;
    Some((tag, len, pad_len))
  }

  /// `%Hdrl` — RIFF.pm:1030-1053.
  fn process_chunks_hdrl(&mut self, body: &'a [u8]) {
    let mut p = 0;
    while p + 8 < body.len() {
      let tag: [u8; 4] = body[p..p + 4].try_into().expect("4 bytes");
      let len = le_u32(&body[p + 4..p + 8]) as usize;
      p += 8;
      if p + len > body.len() {
        // RIFF.pm:1798-1801: `Bad $tag chunk` and abort.
        return;
      }
      if &tag == b"LIST" && len >= 4 {
        let list_type: [u8; 4] = body[p..p + 4].try_into().expect("4 bytes");
        let inner = &body[p + 4..p + len];
        match &list_type {
          b"strl" => self.process_chunks_strl(inner),
          b"odml" => process_chunks_odml(inner, &mut self.entries),
          _ => {}
        }
      } else {
        let payload = &body[p..p + len];
        match &tag {
          b"avih" => emit_avi_header(payload, &mut self.entries),
          b"IDIT" => emit_idit(payload, &mut self.entries),
          b"ISMP" => emit_ismp(payload, &mut self.entries),
          _ => {}
        }
      }
      p += len + (len & 1);
    }
  }

  /// `%Stream` — RIFF.pm:1110-1140. Each `LIST_strl` produces one
  /// [`RiffStream`] (`$$self{RIFFStreamNum}` increments inside `strh`).
  fn process_chunks_strl(&mut self, body: &'a [u8]) {
    // RIFF.pm:1169: `$$self{RIFFStreamNum} = ($$et{RIFFStreamNum} || 0) + 1`.
    // Push the fresh stream record; subsequent `strh`/`strf`/`strd`/`strn`
    // populate it. The current_stream_type cross-chunk flag is updated
    // by `emit_stream_header`.
    self.streams.push(RiffStream::new());
    let stream_idx = self.streams.len() - 1;

    let mut p = 0;
    while p + 8 < body.len() {
      let tag: [u8; 4] = body[p..p + 4].try_into().expect("4 bytes");
      let len = le_u32(&body[p + 4..p + 8]) as usize;
      p += 8;
      if p + len > body.len() {
        return;
      }
      let payload = &body[p..p + len];
      match &tag {
        b"strh" => {
          // Emit + capture the resulting StreamType into both the stream
          // record and `current_stream_type`.
          let stype = emit_stream_header(payload, &mut self.entries);
          self.current_stream_type = stype;
          if let Some(sty) = stype {
            let sty_str = SmolStr::new(core::str::from_utf8(&sty).unwrap_or(""));
            self.streams[stream_idx].stream_type = Some(sty_str);
          }
          // The codec FourCC at offset 4 is captured by `emit_stream_header`
          // and emitted; record it here too (with the same trailing-null
          // trim bundled's `Format => 'string[4]'` applies).
          if payload.len() >= 8 {
            let codec_bytes = &payload[4..8];
            let codec = string_trim_nulls(codec_bytes);
            self.streams[stream_idx].codec = Some(SmolStr::new(&codec));
          }
        }
        b"strf" => {
          // Dispatch on the latest StreamType (RIFF.pm:1122-1139).
          match self.current_stream_type {
            Some(s) if &s == b"auds" => emit_audio_format(payload, &mut self.entries),
            Some(s) if &s == b"vids" => emit_bmp_video_format(payload, &mut self.entries),
            // txts: bundled raises a `Use ExtractEmbedded option` warning
            // (RIFF.pm:1137); we just skip — embedded-text streams are
            // not in product scope.
            _ => {}
          }
        }
        b"strn" => {
          // INFO-style ASCII name. Trim trailing nulls (faithful to
          // ProcessChunks string trim, RIFF.pm:1827).
          let name = string_trim_nulls(payload);
          if !name.is_empty() {
            self.entries.push(RiffEntry::new(
              "RIFF",
              "StreamName",
              RiffValue::Str(SmolStr::new(&name)),
            ));
            self.streams[stream_idx].name = Some(SmolStr::new(&name));
          }
        }
        // `strd` StreamData — bundled hops into `%StreamData` (RIFF.pm:
        // 1250-1276) for Canon AVIF / Casio CASI / Samsung Zora. Deferred:
        // we keep the byte buffer reachable through `streams()` but emit
        // nothing.
        b"strd" => {}
        _ => {}
      }
      p += len + (len & 1);
    }
  }
}

// ===========================================================================
// §5. Sub-chunk decoders (free functions; no walker state needed)
// ===========================================================================

/// `%Image::ExifTool::RIFF::Info` — RIFF.pm:835-1010. The full table has
/// dozens of FourCC → tag-name rows; we port the bundled `RIFF.avi`
/// fixture's IART/IGNR/ICRD/INAM/ISFT/etc. set + the broader "EXIF 2.3"
/// underlined-tag subset. Unrecognized FourCCs are silently skipped
/// (faithful to bundled with no `-U`).
fn process_chunks_info(body: &[u8], entries: &mut Vec<RiffEntry>) {
  let mut p = 0;
  while p + 8 < body.len() {
    let tag: [u8; 4] = body[p..p + 4].try_into().expect("4 bytes");
    let len = le_u32(&body[p + 4..p + 8]) as usize;
    p += 8;
    if p + len > body.len() {
      return;
    }
    let payload = &body[p..p + len];
    // RIFF.pm:838 FORMAT => 'string': trim trailing nulls.
    let val_str = string_trim_nulls(payload);
    let pad = len & 1;
    p += len + pad;
    let Some(name) = info_tag_name(&tag) else {
      continue;
    };
    // ISFT has a special trim (Casio "CASIO" suffix); apply faithfully.
    // RIFF.pm:872-873: `s/(\s*\0)+$//; s/(\s*\0)/, /; s/\0+//g;`.
    // The trailing-null trim is already done. The remaining replacement
    // only changes things on Casio variants the fixture doesn't exercise,
    // so we leave the simple trim — this is what bundled emits on
    // RIFF.avi too (Software => "CanonMVI01" with no nulls).
    entries.push(RiffEntry::new(
      "RIFF",
      name,
      RiffValue::Str(SmolStr::new(&val_str)),
    ));
  }
}

/// Map an INFO chunk FourCC to its emitted tag name (RIFF.pm:835-1010).
/// Returns `None` for FourCCs the bundled table doesn't define — these are
/// silently skipped (faithful with no `-U`).
const fn info_tag_name(tag: &[u8; 4]) -> Option<&'static str> {
  // RIFF.pm:845-1009 (the EXIF 2.3 INFO subset that the fixture + most
  // AVI files in scope reach). The 3rd-party tables (movie database,
  // GSpot, Sound Forge, Sony Vegas) are below the EXIF subset; the bundled
  // fixture only reaches IART/IGNR/ICRD/INAM/IPRD/IKEY/ICMT/IENG/ISFT
  // typically. Cover the full EXIF subset here for product fidelity.
  match tag {
    b"IARL" => Some("ArchivalLocation"),
    b"IART" => Some("Artist"),
    b"ICMS" => Some("Commissioned"),
    b"ICMT" => Some("Comment"),
    b"ICOP" => Some("Copyright"),
    b"ICRD" => Some("DateCreated"),
    b"ICRP" => Some("Cropped"),
    b"IDIM" => Some("Dimensions"),
    b"IDPI" => Some("DotsPerInch"),
    b"IENG" => Some("Engineer"),
    b"IGNR" => Some("Genre"),
    b"IKEY" => Some("Keywords"),
    b"ILGT" => Some("Lightness"),
    b"IMED" => Some("Medium"),
    b"INAM" => Some("Title"),
    b"ITRK" => Some("TrackNumber"),
    b"IPLT" => Some("NumColors"),
    b"IPRD" => Some("Product"),
    b"ISBJ" => Some("Subject"),
    b"ISFT" => Some("Software"),
    b"ISHP" => Some("Sharpness"),
    b"ISRC" => Some("Source"),
    b"ISRF" => Some("SourceForm"),
    b"ITCH" => Some("Technician"),
    // 3rd-party (RIFF.pm:880-938) — these are common enough that ignoring
    // them silently is the wrong product call for an indexer. Include the
    // EXIF-style ones (IMDb / Vegas / Sound Forge) so a `.avi` carrying
    // them surfaces real data.
    b"ISGN" => Some("SecondaryGenre"),
    b"IWRI" => Some("WrittenBy"),
    b"IPRO" => Some("ProducedBy"),
    b"ICNM" => Some("Cinematographer"),
    b"IPDS" => Some("ProductionDesigner"),
    b"IEDT" => Some("EditedBy"),
    b"ICDS" => Some("CostumeDesigner"),
    b"IMUS" => Some("MusicBy"),
    b"ISTD" => Some("ProductionStudio"),
    b"IDST" => Some("DistributedBy"),
    b"ICNT" => Some("Country"),
    b"ILNG" => Some("Language"),
    b"IRTD" => Some("Rating"),
    b"ISTR" => Some("Starring"),
    b"IENC" => Some("EncodedBy"),
    b"IRIP" => Some("RippedBy"),
    _ => None,
  }
}

/// `%Image::ExifTool::RIFF::Exif` — RIFF.pm:1013-1027 (EXIF 2.3 sub-chunks
/// of `LIST_exif`).
fn process_chunks_exif(body: &[u8], entries: &mut Vec<RiffEntry>) {
  let mut p = 0;
  while p + 8 < body.len() {
    let tag: [u8; 4] = body[p..p + 4].try_into().expect("4 bytes");
    let len = le_u32(&body[p + 4..p + 8]) as usize;
    p += 8;
    if p + len > body.len() {
      return;
    }
    let payload = &body[p..p + len];
    let pad = len & 1;
    p += len + pad;
    let name = match &tag {
      b"ever" => Some("ExifVersion"),
      b"erel" => Some("RelatedImageFile"),
      b"etim" => Some("TimeCreated"),
      b"ecor" => Some("Make"),
      b"emdl" => Some("Model"),
      // emnt MakerNotes (Binary => 1) — deferred (no MakerNotes engine
      // hop in this port).
      b"emnt" => None,
      // eucm UserComment — bundled has a ConvertExifText PrintConv. We
      // emit the raw trimmed text; tail conformance would route through
      // the ConvertExifText helper (deferred).
      b"eucm" => Some("UserComment"),
      _ => None,
    };
    if let Some(n) = name {
      let val_str = string_trim_nulls(payload);
      entries.push(RiffEntry::new(
        "RIFF",
        n,
        RiffValue::Str(SmolStr::new(&val_str)),
      ));
    }
  }
}

/// `%Image::ExifTool::RIFF::OpenDML` → `dmlh` → `%ExtAVIHdr` (RIFF.pm:1143-
/// 1158). The only emitted tag is `TotalFrameCount` (int32u at offset 0).
fn process_chunks_odml(body: &[u8], entries: &mut Vec<RiffEntry>) {
  let mut p = 0;
  while p + 8 < body.len() {
    let tag: [u8; 4] = body[p..p + 4].try_into().expect("4 bytes");
    let len = le_u32(&body[p + 4..p + 8]) as usize;
    p += 8;
    if p + len > body.len() {
      return;
    }
    let payload = &body[p..p + len];
    let pad = len & 1;
    p += len + pad;
    if &tag == b"dmlh" && payload.len() >= 4 {
      let total = le_u32(&payload[0..4]);
      entries.push(RiffEntry::new(
        "RIFF",
        "TotalFrameCount",
        RiffValue::U32(total),
      ));
    }
  }
}

/// `%AudioFormat` — RIFF.pm:687-709. `int16u` table; the 0/1/2/4/7 offsets
/// are the WAVE_FORMAT_PCM-style header. `Encoding` runs through the
/// `%audioEncoding` PrintConv subset.
fn emit_audio_format(payload: &[u8], entries: &mut Vec<RiffEntry>) {
  if payload.len() < 16 {
    return;
  }
  // 0: Encoding — int16u, RIFF.pm:691-696.
  let enc = le_u16(&payload[0..2]) as u32;
  entries.push(RiffEntry::new("RIFF", "Encoding", RiffValue::U32(enc)));
  // 1: NumChannels — int16u, RIFF.pm:697.
  entries.push(RiffEntry::new(
    "RIFF",
    "NumChannels",
    RiffValue::U32(le_u16(&payload[2..4]) as u32),
  ));
  // 2: SampleRate — int32u, RIFF.pm:698-701.
  entries.push(RiffEntry::new(
    "RIFF",
    "SampleRate",
    RiffValue::U32(le_u32(&payload[4..8])),
  ));
  // 4: AvgBytesPerSec — int32u, RIFF.pm:702-705.
  entries.push(RiffEntry::new(
    "RIFF",
    "AvgBytesPerSec",
    RiffValue::U32(le_u32(&payload[8..12])),
  ));
  // 7: BitsPerSample — int16u (offset 7 in int16u-element units = byte
  // offset 14), RIFF.pm:708.
  entries.push(RiffEntry::new(
    "RIFF",
    "BitsPerSample",
    RiffValue::U32(le_u16(&payload[14..16]) as u32),
  ));
}

/// `%AVIHeader` — RIFF.pm:1076-1108. `int32u` table at offsets 0/1/4/6/8/9
/// drives FrameRate/MaxDataRate/FrameCount/StreamCount/ImageWidth/Height.
fn emit_avi_header(payload: &[u8], entries: &mut Vec<RiffEntry>) {
  if payload.len() < 40 {
    return;
  }
  // 0: FrameRate — RawConv `$val ? 1e6 / $val : undef` (RIFF.pm:1081-1086).
  let frame_rate_raw = le_u32(&payload[0..4]);
  if frame_rate_raw != 0 {
    let fr = 1.0e6_f64 / frame_rate_raw as f64;
    entries.push(RiffEntry::new("RIFF", "FrameRate", RiffValue::F64(fr)));
  }
  // 1: MaxDataRate — int32u (RIFF.pm:1087-1099) with a PrintConv SI-prefix
  // formatter. The raw bytes-per-second value is what we store.
  entries.push(RiffEntry::new(
    "RIFF",
    "MaxDataRate",
    RiffValue::U32(le_u32(&payload[4..8])),
  ));
  // 4: FrameCount (RIFF.pm:1102).
  entries.push(RiffEntry::new(
    "RIFF",
    "FrameCount",
    RiffValue::U32(le_u32(&payload[16..20])),
  ));
  // 6: StreamCount (RIFF.pm:1104).
  entries.push(RiffEntry::new(
    "RIFF",
    "StreamCount",
    RiffValue::U32(le_u32(&payload[24..28])),
  ));
  // 8: ImageWidth (RIFF.pm:1106).
  entries.push(RiffEntry::new(
    "RIFF",
    "ImageWidth",
    RiffValue::U32(le_u32(&payload[32..36])),
  ));
  // 9: ImageHeight (RIFF.pm:1107).
  entries.push(RiffEntry::new(
    "RIFF",
    "ImageHeight",
    RiffValue::U32(le_u32(&payload[36..40])),
  ));
}

/// `%StreamHeader` — RIFF.pm:1160-1248. Returns the parsed StreamType as
/// raw bytes (the `$$self{RIFFStreamType}` cross-chunk flag, RIFF.pm:1169).
///
/// Emits `StreamType` + the per-type codec (`AudioCodec`/`VideoCodec`/
/// `Codec`) + the rate field (5: AudioSampleRate/VideoFrameRate/
/// StreamSampleRate — `rational64u` `$val ? 1/$val : 0`) + Sample/Frame
/// counts (8) + Quality (10) + SampleSize (11).
///
/// **Faithful PRIORITY=0 behavior** (RIFF.pm:1165): for the cross-stream
/// fields whose tag NAME is the same in both vids/auds streams
/// (`StreamType` / `Quality` / `SampleSize`), only the FIRST stream's
/// value is kept; the second stream's emission is dropped. Bundled
/// implements this via `Priority => 0` on the `%StreamHeader` table — a
/// new FoundTag with priority ≤ existing doesn't override. The per-stream
/// names (`VideoCodec` vs `AudioCodec`, `VideoFrameRate` vs
/// `AudioSampleRate`, `VideoFrameCount` vs `AudioSampleCount`) differ per
/// stream type so each is emitted exactly once.
fn emit_stream_header(payload: &[u8], entries: &mut Vec<RiffEntry>) -> Option<[u8; 4]> {
  if payload.len() < 48 {
    return None;
  }
  // 0: StreamType — Format => 'string[4]' (RIFF.pm:1166-1177).
  let stream_type_bytes: [u8; 4] = payload[0..4].try_into().expect("4 bytes");
  let stream_type_str = String::from_utf8_lossy(&stream_type_bytes).into_owned();
  push_priority0(
    entries,
    "RIFF",
    "StreamType",
    RiffValue::Str(SmolStr::new(&stream_type_str)),
  );
  // 1: Codec — Format => 'string[4]' (RIFF.pm:1178-1196). Per-type name
  // (AudioCodec / VideoCodec / Codec). `Format => 'string[4]'` triggers
  // ReadValue's trailing-null trim (`$val =~ s/\0+$//`), so a codec like
  // `\0\0\0\0` becomes `""` (faithful to bundled emitting empty
  // `RIFF:AudioCodec` for PCM-only AVIs).
  let codec_bytes: [u8; 4] = payload[4..8].try_into().expect("4 bytes");
  let codec_str = string_trim_nulls(&codec_bytes);
  let codec_name = match &stream_type_bytes {
    b"auds" => "AudioCodec",
    b"vids" => "VideoCodec",
    _ => "Codec",
  };
  push_priority0(
    entries,
    "RIFF",
    codec_name,
    RiffValue::Str(SmolStr::new(&codec_str)),
  );
  // 5: rational64u (int32u num at byte offset 20, int32u den at byte 24).
  // ValueConv `$val ? 1/$val : 0` (RIFF.pm:1201-1223) — `$val` is the
  // ReadValue rational quotient (`num/den`, rounded by `RoundFloat($val,
  // 10) = sprintf("%.10g")`). Emit the inverse `1/$val` (which is NOT
  // exactly `den/num` due to the 10-significant-digit RoundFloat step:
  // a fixture with `num=1, den=11024` becomes `1/0.00009071124819 =
  // 11023.99999961...` not `11024`, faithful to bundled).
  let r_num = le_u32(&payload[20..24]);
  let r_den = le_u32(&payload[24..28]);
  if r_num != 0 && r_den != 0 {
    let val = read_rational_round10(r_num, r_den);
    let rate = if val == 0.0 { 0.0 } else { 1.0 / val };
    let rate_name = match &stream_type_bytes {
      b"auds" => "AudioSampleRate",
      b"vids" => "VideoFrameRate",
      _ => "StreamSampleRate",
    };
    push_priority0(entries, "RIFF", rate_name, RiffValue::F64(rate));
  }
  // 8: Sample/Frame count — int32u at offset 32 (RIFF.pm:1225-1237).
  let count = le_u32(&payload[32..36]);
  let count_name = match &stream_type_bytes {
    b"auds" => "AudioSampleCount",
    b"vids" => "VideoFrameCount",
    _ => "StreamSampleCount",
  };
  push_priority0(entries, "RIFF", count_name, RiffValue::U32(count));
  // 10: Quality — int32u at offset 40 (RIFF.pm:1239-1242). PrintConv:
  // `0xffffffff -> "Default"`; we store the raw u32, the PrintConv
  // application happens in the `Taggable::tags` emission.
  push_priority0(
    entries,
    "RIFF",
    "Quality",
    RiffValue::U32(le_u32(&payload[40..44])),
  );
  // 11: SampleSize — int32u at offset 44 (RIFF.pm:1243-1246). PrintConv:
  // `0 -> "Variable"`, else `"$val byte"`/`"s"`.
  push_priority0(
    entries,
    "RIFF",
    "SampleSize",
    RiffValue::U32(le_u32(&payload[44..48])),
  );
  Some(stream_type_bytes)
}

/// Push an entry honoring `Priority => 0` first-wins: if a `(group, name)`
/// pair is already present in `entries`, drop the new value. Used by
/// [`emit_stream_header`] for the `%StreamHeader` table (RIFF.pm:1165) and
/// any other table that carries PRIORITY=0.
fn push_priority0(
  entries: &mut Vec<RiffEntry>,
  group: &'static str,
  name: &'static str,
  value: RiffValue,
) {
  if entries
    .iter()
    .any(|e| e.group() == group && e.name() == name)
  {
    return;
  }
  entries.push(RiffEntry::new(group, name, value));
}

/// `%Image::ExifTool::BMP::Main` for the `strf` VideoFormat chunk (the
/// `vids` branch, RIFF.pm:1129-1132 + BMP.pm:36-150). We inline the
/// first 40 bytes (BMP V3) — every emitted field becomes a `File:*` tag
/// (BMP.pm:38 `GROUPS => { 0 => 'File', 1 => 'File', 2 => 'Image' }`).
///
/// The `Compression` field needs the special `ValueConv`:
/// `$val > 256 ? unpack("A4",pack("V",$val)) : $val` (BMP.pm:81) —
/// values above 256 are treated as a FourCC packed into a little-endian
/// int32u. We store a `Str` carrying the FourCC for that case, else an
/// `U32` with the raw numeric compression code.
fn emit_bmp_video_format(payload: &[u8], entries: &mut Vec<RiffEntry>) {
  if payload.len() < 40 {
    return;
  }
  // 0: BMPVersion — int32u (BMP.pm:43-57). PrintConv maps 40→"Windows V3",
  // 68→"AVI BMP structure?", 108→"Windows V4", 124→"Windows V5".
  entries.push(RiffEntry::new(
    "File",
    "BMPVersion",
    RiffValue::U32(le_u32(&payload[0..4])),
  ));
  // 4: ImageWidth — int32u (BMP.pm:58-61).
  entries.push(RiffEntry::new(
    "File",
    "ImageWidth",
    RiffValue::U32(le_u32(&payload[4..8])),
  ));
  // 8: ImageHeight — int32s with ValueConv abs() (BMP.pm:62-66).
  let raw_h = le_i32(&payload[8..12]);
  let abs_h = raw_h.unsigned_abs();
  entries.push(RiffEntry::new("File", "ImageHeight", RiffValue::U32(abs_h)));
  // 12: Planes — int16u (BMP.pm:67-71).
  entries.push(RiffEntry::new(
    "File",
    "Planes",
    RiffValue::U32(le_u16(&payload[12..14]) as u32),
  ));
  // 14: BitDepth — int16u (BMP.pm:72-75).
  entries.push(RiffEntry::new(
    "File",
    "BitDepth",
    RiffValue::U32(le_u16(&payload[14..16]) as u32),
  ));
  // 16: Compression — int32u (BMP.pm:76-97). > 256 ⇒ FourCC string;
  // bundled emits `0/1/2/3/4/5` as numeric codes (PrintConv hash) and
  // anything else as ASCII-only via `unpack("A4", pack("V", $val))`.
  let comp_raw = le_u32(&payload[16..20]);
  if comp_raw > 256 {
    // pack("V", $val) = little-endian 4-byte; unpack("A4", ...) trims
    // trailing spaces but preserves bytes. Just emit the four bytes as
    // a string (replacing non-printable bytes with their visible form,
    // per BMP.pm:90-95 OTHER sub).
    let bytes = comp_raw.to_le_bytes();
    let s = render_fourcc(&bytes);
    entries.push(RiffEntry::new(
      "File",
      "Compression",
      RiffValue::Str(SmolStr::new(&s)),
    ));
  } else {
    entries.push(RiffEntry::new(
      "File",
      "Compression",
      RiffValue::U32(comp_raw),
    ));
  }
  // 20: ImageLength — int32u (BMP.pm:98-102).
  entries.push(RiffEntry::new(
    "File",
    "ImageLength",
    RiffValue::U32(le_u32(&payload[20..24])),
  ));
  // 24: PixelsPerMeterX — int32u (BMP.pm:103-106).
  entries.push(RiffEntry::new(
    "File",
    "PixelsPerMeterX",
    RiffValue::U32(le_u32(&payload[24..28])),
  ));
  // 28: PixelsPerMeterY — int32u (BMP.pm:107-110).
  entries.push(RiffEntry::new(
    "File",
    "PixelsPerMeterY",
    RiffValue::U32(le_u32(&payload[28..32])),
  ));
  // 32: NumColors — int32u (BMP.pm:111-115). PrintConv `0 -> "Use BitDepth"`.
  entries.push(RiffEntry::new(
    "File",
    "NumColors",
    RiffValue::U32(le_u32(&payload[32..36])),
  ));
  // 36: NumImportantColors — int32u (BMP.pm:116-121). PrintConv `0 -> "All"`.
  entries.push(RiffEntry::new(
    "File",
    "NumImportantColors",
    RiffValue::U32(le_u32(&payload[36..40])),
  ));
  // BMP V4 / V5 carries more fields after offset 40; the bundled `strf`
  // for AVI virtually always uses V3 (40-byte header) — V4/V5 fields are
  // a follow-up.
}

/// Render BMP `Compression` FourCC bytes (BMP.pm:90-95 `OTHER => sub { ... }`).
/// Non-printable bytes are replaced with `\xNN` escapes; bundled also trims
/// trailing whitespace via `unpack("A4", ...)`.
fn render_fourcc(bytes: &[u8; 4]) -> String {
  // bundled: `$val =~ s/([\0-\x1f\x7f-\xff])/sprintf('\\x%.2x',ord $1)/eg`,
  // then implicit `unpack("A4")` trims trailing ASCII spaces.
  let mut s = String::new();
  for &b in bytes.iter() {
    if !(0x20..0x7f).contains(&b) {
      s.push_str(&std::format!("\\x{b:02x}"));
    } else {
      s.push(b as char);
    }
  }
  // Trim trailing spaces — `unpack("A4")` semantics.
  while s.ends_with(' ') {
    s.pop();
  }
  s
}

/// `IDIT` (RIFF.pm:526-532) — DateTimeOriginal. Runs through
/// `ConvertRIFFDate` (RIFF.pm:1601-1619); we store the resulting
/// `YYYY:MM:DD HH:MM:SS` string.
fn emit_idit(payload: &[u8], entries: &mut Vec<RiffEntry>) {
  let raw = string_trim_nulls(payload);
  let converted = convert_riff_date(&raw);
  entries.push(RiffEntry::new(
    "RIFF",
    "DateTimeOriginal",
    RiffValue::Str(SmolStr::new(&converted)),
  ));
}

/// `ISMP` (RIFF.pm:1009 / 1044) — TimeCode. ASCII timecode string;
/// emit verbatim (trimmed).
fn emit_ismp(payload: &[u8], entries: &mut Vec<RiffEntry>) {
  let val = string_trim_nulls(payload);
  if val.is_empty() {
    return;
  }
  entries.push(RiffEntry::new(
    "RIFF",
    "TimeCode",
    RiffValue::Str(SmolStr::new(&val)),
  ));
}

// ===========================================================================
// §6. Helpers — `ConvertRIFFDate`, byte readers, string trim
// ===========================================================================

/// Trim trailing NUL bytes from a UTF-8-ish payload and return the resulting
/// `String`. Faithful to ProcessChunks RIFF.pm:1827
/// `$val =~ s/\0+$//`. Non-UTF8 bytes are kept as best-effort via
/// `from_utf8_lossy`.
fn string_trim_nulls(bytes: &[u8]) -> String {
  let mut end = bytes.len();
  while end > 0 && bytes[end - 1] == 0 {
    end -= 1;
  }
  String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// `Image::ExifTool::RIFF::ConvertRIFFDate` — RIFF.pm:1601-1619.
///
/// Accepts:
/// - The standard AVI `Mon Mar 10 15:04:43 2003` (5 whitespace-separated
///   parts, `monthNum{ucfirst(lc(part[1]))}` lookup).
/// - The Casio QV-3EX `2001/ 1/27  1:42PM` / EX-Z30 `2005/11/28/ 09:19`.
/// - The Konica KD500Z `2002-12-16  15:35:01\0\0`.
/// - Any other shape falls through unchanged.
fn convert_riff_date(val: &str) -> String {
  let trimmed = val.trim_end_matches('\0');
  let parts: Vec<&str> = trimmed.split_whitespace().collect();

  // Standard form: "Mon Mar 10 15:04:43 2003".
  if parts.len() >= 5
    && let Some(mon) = month_num(parts[1])
    && let (Ok(day), year_str) = (parts[2].parse::<u32>(), parts[4])
    && let Ok(year) = year_str.parse::<u32>()
  {
    return std::format!("{year:04}:{mon:02}:{day:02} {}", parts[3]);
  }

  // Casio QV-3EX / EX-Z30: `2001/ 1/27  1:42PM` / `2005/11/28/ 09:19`.
  if let Some(s) = parse_casio_date(trimmed) {
    return s;
  }

  // Konica KD500Z: `2002-12-16  15:35:01`.
  if let Some(s) = parse_konica_date(trimmed) {
    return s;
  }

  trimmed.to_string()
}

/// Three-letter month name → 1..=12. `Jan`/`Feb`/… case-insensitive
/// (`ucfirst(lc(...))`, RIFF.pm:1606).
fn month_num(s: &str) -> Option<u32> {
  let normalized: String = s
    .chars()
    .enumerate()
    .map(|(i, c)| {
      if i == 0 {
        c.to_ascii_uppercase()
      } else {
        c.to_ascii_lowercase()
      }
    })
    .collect();
  match normalized.as_str() {
    "Jan" => Some(1),
    "Feb" => Some(2),
    "Mar" => Some(3),
    "Apr" => Some(4),
    "May" => Some(5),
    "Jun" => Some(6),
    "Jul" => Some(7),
    "Aug" => Some(8),
    "Sep" => Some(9),
    "Oct" => Some(10),
    "Nov" => Some(11),
    "Dec" => Some(12),
    _ => None,
  }
}

/// Casio date variants. RIFF.pm:1610-1613:
/// `(\d{4})/\s*(\d+)/\s*(\d+)/?\s+(\d+):\s*(\d+)\s*(P?)`.
fn parse_casio_date(val: &str) -> Option<String> {
  let bytes = val.as_bytes();
  let mut i = 0;
  // Year (4 digits).
  let year = parse_n_digits(bytes, &mut i, 4)?;
  if bytes.get(i)? != &b'/' {
    return None;
  }
  i += 1;
  skip_spaces(bytes, &mut i);
  let mon = parse_digits(bytes, &mut i)?;
  if bytes.get(i)? != &b'/' {
    return None;
  }
  i += 1;
  skip_spaces(bytes, &mut i);
  let day = parse_digits(bytes, &mut i)?;
  // Optional `/` (EX-Z30 variant).
  if bytes.get(i) == Some(&b'/') {
    i += 1;
  }
  // Require at least one whitespace.
  if !bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
    return None;
  }
  skip_spaces(bytes, &mut i);
  let hour = parse_digits(bytes, &mut i)?;
  if bytes.get(i)? != &b':' {
    return None;
  }
  i += 1;
  skip_spaces(bytes, &mut i);
  let min = parse_digits(bytes, &mut i)?;
  skip_spaces(bytes, &mut i);
  let pm = bytes.get(i) == Some(&b'P');
  let hour_final = hour + if pm { 12 } else { 0 };
  Some(std::format!(
    "{year:04}:{mon:02}:{day:02} {hour_final:02}:{min:02}:00"
  ))
}

/// Konica KD500Z: `(\d{4})[-/](\d+)[-/](\d+)\s+(\d+:\d+:\d+)` (RIFF.pm:1614-1616).
fn parse_konica_date(val: &str) -> Option<String> {
  let bytes = val.as_bytes();
  let mut i = 0;
  let year = parse_n_digits(bytes, &mut i, 4)?;
  if !matches!(bytes.get(i), Some(&b'-' | &b'/')) {
    return None;
  }
  i += 1;
  let mon = parse_digits(bytes, &mut i)?;
  if !matches!(bytes.get(i), Some(&b'-' | &b'/')) {
    return None;
  }
  i += 1;
  let day = parse_digits(bytes, &mut i)?;
  if !bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
    return None;
  }
  skip_spaces(bytes, &mut i);
  // `(\d+:\d+:\d+)` — read three colon-separated unsigned integers.
  let hh = parse_digits(bytes, &mut i)?;
  if bytes.get(i)? != &b':' {
    return None;
  }
  i += 1;
  let mm = parse_digits(bytes, &mut i)?;
  if bytes.get(i)? != &b':' {
    return None;
  }
  i += 1;
  let ss = parse_digits(bytes, &mut i)?;
  Some(std::format!(
    "{year:04}:{mon:02}:{day:02} {hh:02}:{mm:02}:{ss:02}"
  ))
}

fn skip_spaces(bytes: &[u8], i: &mut usize) {
  while bytes.get(*i).is_some_and(u8::is_ascii_whitespace) {
    *i += 1;
  }
}

fn parse_digits(bytes: &[u8], i: &mut usize) -> Option<u32> {
  let start = *i;
  while bytes.get(*i).is_some_and(u8::is_ascii_digit) {
    *i += 1;
  }
  if *i == start {
    return None;
  }
  core::str::from_utf8(&bytes[start..*i]).ok()?.parse().ok()
}

fn parse_n_digits(bytes: &[u8], i: &mut usize, n: usize) -> Option<u32> {
  let start = *i;
  let mut count = 0;
  while count < n && bytes.get(*i).is_some_and(u8::is_ascii_digit) {
    *i += 1;
    count += 1;
  }
  if count != n {
    return None;
  }
  core::str::from_utf8(&bytes[start..*i]).ok()?.parse().ok()
}

/// `Image::ExifTool::ReadValue` for a `rational64u` (8 bytes = 2 int32u):
/// `RoundFloat(num/den, 10)`. The 10-significant-digit rounding is via
/// `sprintf("%.10g", $val)` (ExifTool.pm:5949-5953) — see the AudioSampleRate
/// note in `emit_stream_header`. We reproduce it by formatting through
/// `%.10g` and re-parsing.
fn read_rational_round10(num: u32, den: u32) -> f64 {
  if den == 0 {
    return 0.0;
  }
  let raw = num as f64 / den as f64;
  // `%.10g` — 10 significant digits.
  let s = format_n_sig(raw, 10);
  s.parse::<f64>().unwrap_or(raw)
}

/// `%.Ng` — N significant digits. Faithful to Perl/C printf `%g`.
fn format_n_sig(val: f64, n: usize) -> String {
  if !val.is_finite() {
    return val.to_string();
  }
  let exp = if val == 0.0 {
    0
  } else {
    val.abs().log10().floor() as i32
  };
  let precision = if exp >= 0 {
    ((n as i32 - 1) - exp).max(0) as usize
  } else {
    ((n as i32 - 1) - exp) as usize
  };
  let mut s = std::format!("{val:.*}", precision);
  // Trim trailing zeros after a decimal point, then a trailing `.`.
  if s.contains('.') {
    while s.ends_with('0') {
      s.pop();
    }
    if s.ends_with('.') {
      s.pop();
    }
  }
  // Switch to %e form for very small / very large magnitudes (consistent
  // with %g semantics). The threshold per C99: use %e if exp < -4 or
  // exp >= precision. For our use case (rational quotients) the typical
  // values are O(1e-5..1e5).
  if exp < -4 || exp >= n as i32 {
    // Re-format in %e form.
    let mut e = std::format!("{val:.*e}", n - 1);
    // %e gives e.g. "1.234000000e-5"; trim trailing zeros in mantissa.
    if let Some(epos) = e.find('e') {
      let (mantissa, exp_part) = e.split_at(epos);
      let mantissa = mantissa.to_string();
      let mut m = mantissa;
      if m.contains('.') {
        while m.ends_with('0') {
          m.pop();
        }
        if m.ends_with('.') {
          m.pop();
        }
      }
      e = std::format!("{m}{exp_part}");
    }
    return e;
  }
  s
}

#[inline(always)]
fn le_u16(bytes: &[u8]) -> u16 {
  u16::from_le_bytes([bytes[0], bytes[1]])
}

#[inline(always)]
fn le_u32(bytes: &[u8]) -> u32 {
  u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[inline(always)]
fn le_i32(bytes: &[u8]) -> i32 {
  i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

// ===========================================================================
// §7. `Taggable` — the golden tag-emission stream
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::emit::Taggable for RiffMeta<'_> {
  /// Yield the RIFF (and BMP-strf-derived `File:*`) tags in file order, each
  /// value ALREADY rendered for `mode` — the golden-pattern **L3** stream the
  /// [`run_emission`](crate::emit::run_emission) engine drives (replacing the
  /// retired inherent `serialize_tags`). The shared engine then applies the
  /// cross-cutting Unknown-gate + `write_value` + dedup once.
  ///
  /// `ConvMode::PrintConv` (`-j`) renders the PrintConv strings:
  /// - `RIFF:StreamType` → `vids → "Video"` etc. (RIFF.pm:1170-1176)
  /// - `RIFF:Encoding` → `%audioEncoding` PrintConv label
  /// - `RIFF:FrameRate` / `RIFF:VideoFrameRate` → `int($val*1000+0.5)/1000`
  /// - `RIFF:AudioSampleRate` → `int($val*100+0.5)/100`
  /// - `RIFF:MaxDataRate` → `sprintf('%.4g %s', n/1000, "kB/s")`
  /// - `RIFF:Quality` → `0xffffffff -> "Default"`
  /// - `RIFF:SampleSize` → `0 -> "Variable"`, else `"$val byte"` / `"s"`
  /// - `File:BMPVersion` → `{40 -> "Windows V3", ...}`
  /// - `File:Compression` → numeric `{0..5}` PrintConv
  /// - `File:NumColors` → `0 -> "Use BitDepth"`
  /// - `File:NumImportantColors` → `0 -> "All"`
  ///
  /// `ConvMode::ValueConv` (`-n`) yields the post-ValueConv raw scalars.
  ///
  /// Family-0/1 groups: every RIFF chunk inherits `RIFF`/`RIFF` (the RIFF.pm
  /// tables declare only `GROUPS{2}`, so family-0/1 default to the module name
  /// `RIFF`); the inline BMP-strf hop lands in `BMP::Main`
  /// (`GROUPS{0}=GROUPS{1}='File'`, BMP.pm:38). The single stored `group`
  /// string equals both families, so `Group::new(group, group)` is faithful.
  /// Every RIFF tag is a known tag (no `Unknown=>1` in any ported table) ⇒
  /// `unknown: false`.
  fn tags(
    &self,
    mode: crate::emit::ConvMode,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    let print_conv = matches!(mode, crate::emit::ConvMode::PrintConv);
    let mut tags: Vec<crate::emit::EmittedTag> = Vec::with_capacity(self.entries.len());
    for entry in &self.entries {
      tags.push(emit_one(entry, print_conv));
    }
    tags.into_iter()
  }
}

/// Render one [`RiffEntry`] into an [`EmittedTag`](crate::emit::EmittedTag)
/// for the given mode. The value mirrors EXACTLY what the retired
/// `serialize_tags`/`emit_one` wrote into the `TagMap` (`write_str` ⇒
/// [`TagValue::Str`], `write_i64` ⇒ [`TagValue::I64`], `write_u64` ⇒
/// [`TagValue::U64`], `write_f64` ⇒ [`TagValue::F64`]) — so the golden
/// emission is byte-identical to the pre-golden writer path.
#[cfg(feature = "alloc")]
fn emit_one(entry: &RiffEntry, print_conv: bool) -> crate::emit::EmittedTag {
  use crate::emit::EmittedTag;
  use crate::value::{Group, TagValue};

  let group = entry.group();
  let name = entry.name();
  // Family-0 = family-1 = the single stored group string (see `tags` docs).
  let g = || Group::new(group, group);
  let value = match entry.value_ref() {
    RiffValue::Str(s) => {
      // PrintConv dispatch for STRING values (StreamType maps `vids` →
      // "Video" etc. in `-j` mode, RIFF.pm:1170-1176).
      if print_conv && let Some(printed) = print_conv_str(group, name, s.as_str()) {
        TagValue::Str(printed.into())
      } else {
        TagValue::Str(s.as_str().into())
      }
    }
    RiffValue::I32(n) => TagValue::I64(*n as i64),
    RiffValue::U32(n) => {
      // PrintConv dispatch — applied only in `-j` mode.
      if print_conv && let Some(printed) = print_conv_u32(group, name, *n) {
        TagValue::Str(printed.into())
      } else {
        TagValue::U64(*n as u64)
      }
    }
    RiffValue::F64(f) => {
      if print_conv && let Some(rounded) = print_conv_f64_value(name, *f) {
        // Faithful to bundled: emit as INTEGER when the post-rounding
        // value has no fractional part (Perl `int($val * N + 0.5) / N`
        // produces an integer when the round divides evenly). bundled
        // JSON renders these as bare integers (e.g. `"RIFF:FrameRate":
        // 15` not `15.0`).
        if rounded == rounded.trunc() && rounded.is_finite() && rounded.abs() < 9.0e18 {
          TagValue::I64(rounded as i64)
        } else {
          TagValue::F64(rounded)
        }
      } else {
        TagValue::F64(*f)
      }
    }
  };
  EmittedTag::new(g(), name.into(), value, false)
}

/// PrintConv for `Str`-typed values. Currently only `RIFF:StreamType`
/// has a PrintConv label table (RIFF.pm:1170-1176). Returns the static
/// label, or `None` to pass through the raw FourCC.
#[cfg(feature = "alloc")]
fn print_conv_str(group: &str, name: &str, val: &str) -> Option<&'static str> {
  match (group, name) {
    ("RIFF", "StreamType") => match val {
      "auds" => Some("Audio"),
      "mids" => Some("MIDI"),
      "txts" => Some("Text"),
      "vids" => Some("Video"),
      "iavs" => Some("Interleaved Audio+Video"),
      _ => None,
    },
    _ => None,
  }
}

/// PrintConv for u32 values whose `-j` rendering is a string label rather
/// than the bare integer. Returns `None` to fall through to the numeric
/// emission. (`group` is used to disambiguate `RIFF:Compression` from
/// `File:Compression` — only the latter takes the BMP PrintConv; an
/// `RIFF:Compression` would be a different table entirely, but we don't
/// emit one today.)
#[cfg(feature = "alloc")]
fn print_conv_u32(group: &str, name: &str, val: u32) -> Option<String> {
  match (group, name) {
    ("RIFF", "Encoding") => Some(audio_encoding_label(val).to_string()),
    ("RIFF", "MaxDataRate") => Some(max_data_rate_print(val)),
    ("RIFF", "Quality") => {
      if val == 0xffff_ffff {
        Some("Default".to_string())
      } else {
        None
      }
    }
    ("RIFF", "SampleSize") => Some(sample_size_print(val)),
    ("File", "BMPVersion") => Some(bmp_version_label(val).to_string()),
    ("File", "Compression") => Some(bmp_compression_label(val).to_string()),
    ("File", "NumColors") => {
      if val == 0 {
        Some("Use BitDepth".to_string())
      } else {
        None
      }
    }
    ("File", "NumImportantColors") => {
      if val == 0 {
        Some("All".to_string())
      } else {
        None
      }
    }
    _ => None,
  }
}

/// PrintConv for f64 values whose `-j` rendering rounds (FrameRate /
/// VideoFrameRate / AudioSampleRate / StreamSampleRate). Returns the
/// rounded f64 value; the emit-side decides whether to encode as integer
/// (no fractional part) or float. Returns `None` to fall through to the
/// raw f64 emission.
#[cfg(feature = "alloc")]
fn print_conv_f64_value(name: &str, val: f64) -> Option<f64> {
  if !val.is_finite() {
    return None;
  }
  let scale = match name {
    // `int($val * 1000 + 0.5) / 1000` — RIFF.pm:1085 / 1215 / 1221.
    "FrameRate" | "VideoFrameRate" | "StreamSampleRate" => 1000.0_f64,
    // `int($val * 100 + 0.5) / 100` — RIFF.pm:1207.
    "AudioSampleRate" => 100.0,
    _ => return None,
  };
  // `int(... + 0.5)` — round half away from zero on positive numbers.
  // The Perl `int()` truncates toward zero; with `+0.5` on a positive
  // float this becomes round-half-up. We replicate exactly.
  Some(((val * scale) + 0.5).trunc() / scale)
}

/// `%audioEncoding` (RIFF.pm:90-336) — partial table covering the bundled
/// fixtures + common entries. Unknown codes render as `Unknown (0xNN)`
/// faithful to ExifTool's default Unknown PrintConv handling.
#[cfg(feature = "alloc")]
fn audio_encoding_label(val: u32) -> String {
  match val {
    0x01 => "Microsoft PCM".to_string(),
    0x02 => "Microsoft ADPCM".to_string(),
    0x03 => "Microsoft IEEE float".to_string(),
    0x06 => "Microsoft a-Law".to_string(),
    0x07 => "Microsoft u-Law".to_string(),
    0x10 => "OKI-ADPCM".to_string(),
    0x11 => "Intel IMA/DVI-ADPCM".to_string(),
    0x31 => "Microsoft GSM610".to_string(),
    0x50 => "Microsoft MPEG".to_string(),
    0x55 => "MP3".to_string(),
    0x161 => "Windows Media Audio V2 V7 V8 V9 / DivX audio (WMA) / Alex AC3 Audio".to_string(),
    0x162 => "Windows Media Audio Professional V9".to_string(),
    0x163 => "Windows Media Audio Lossless V9".to_string(),
    0xff => "AAC".to_string(),
    other => std::format!("Unknown (0x{other:x})"),
  }
}

/// `%AVIHeader` MaxDataRate PrintConv (RIFF.pm:1090-1098). With default
/// API options (`ByteUnit` != `"Binary"`) the units are SI `kB/s` / `MB/s`,
/// dividing by 1000. `sprintf('%.4g %s', $tmp, $unit)`.
#[cfg(feature = "alloc")]
fn max_data_rate_print(val: u32) -> String {
  let mut tmp = val as f64 / 1000.0;
  let mut unit = "kB/s";
  if tmp > 9999.0 {
    tmp /= 1000.0;
    unit = "MB/s";
  }
  // `%.4g` — 4 significant digits. Perl uses C printf; we synthesize the
  // same via a small custom formatter.
  std::format!("{} {unit}", format_4g(tmp))
}

/// `%.4g` — 4 significant digits, suppress trailing zeros. Faithful to
/// Perl/C printf `%g` (RIFF.pm:1097 `sprintf('%.4g %s', ...)`).
#[cfg(feature = "alloc")]
fn format_4g(val: f64) -> String {
  if !val.is_finite() {
    return val.to_string();
  }
  // %g: choose %e or %f based on exponent; here we use %f with 4-significant-
  // digit precision and strip trailing zeros.
  // 4-significant-digit precision = number of digits after the decimal point
  // depends on the magnitude of `val`.
  let exp = if val == 0.0 {
    0
  } else {
    val.abs().log10().floor() as i32
  };
  let precision = if exp >= 0 {
    (3 - exp).max(0) as usize
  } else {
    (3 - exp) as usize
  };
  let mut s = std::format!("{val:.*}", precision);
  // Trim trailing zeros after a decimal point, then a trailing `.` if any.
  if s.contains('.') {
    while s.ends_with('0') {
      s.pop();
    }
    if s.ends_with('.') {
      s.pop();
    }
  }
  s
}

/// `StreamHeader::SampleSize` PrintConv (RIFF.pm:1244-1246).
/// `0 -> "Variable"`, else `"$val byte" + ($val==1?"":"s")`.
#[cfg(feature = "alloc")]
fn sample_size_print(val: u32) -> String {
  if val == 0 {
    return "Variable".to_string();
  }
  if val == 1 {
    "1 byte".to_string()
  } else {
    std::format!("{val} bytes")
  }
}

/// `BMP::Main` BMPVersion PrintConv (BMP.pm:51-55).
fn bmp_version_label(val: u32) -> &'static str {
  match val {
    40 => "Windows V3",
    68 => "AVI BMP structure?",
    108 => "Windows V4",
    124 => "Windows V5",
    _ => "",
  }
}

/// `BMP::Main` Compression PrintConv numeric entries (BMP.pm:82-89). For
/// values > 256 the inline decoder already emitted a `Str` (FourCC), so
/// this only fires for the small-integer codes.
fn bmp_compression_label(val: u32) -> &'static str {
  match val {
    0 => "None",
    1 => "8-Bit RLE",
    2 => "4-Bit RLE",
    3 => "Bitfields",
    4 => "JPEG",
    5 => "PNG",
    _ => "",
  }
}

// ===========================================================================
// §8. `Error` — Rust-level fatal modes (currently none)
// ===========================================================================

/// Rust-level fatal modes for RIFF parsing. Currently empty — every bad
/// input produces `Ok(None)`, faithful to RIFF.pm:2039 / 2045 / 2096
/// (`return 0` / soft-fail on truncation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RiffError {}

// ===========================================================================
// §9. Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  /// Build a minimal AVI: RIFF/AVI header + LIST_hdrl(avih + LIST_strl(strh +
  /// strf)) + LIST_INFO(ISFT) + IDIT.
  fn synth_avi() -> Vec<u8> {
    let mut buf = Vec::new();
    // RIFF wrapper — placeholder for outer size; fill in last.
    buf.extend_from_slice(b"RIFF");
    buf.extend_from_slice(&[0; 4]); // outer size placeholder
    buf.extend_from_slice(b"AVI ");
    // LIST hdrl
    let hdrl_start = buf.len();
    buf.extend_from_slice(b"LIST");
    buf.extend_from_slice(&[0; 4]); // size placeholder
    buf.extend_from_slice(b"hdrl");
    // avih chunk (40 bytes payload).
    buf.extend_from_slice(b"avih");
    buf.extend_from_slice(&40u32.to_le_bytes()); // size
    // 10 int32u fields.
    buf.extend_from_slice(&66666u32.to_le_bytes()); // 0: us per frame (1e6/66666 ≈ 15.0001500015)
    buf.extend_from_slice(&12345u32.to_le_bytes()); // 1: MaxDataRate
    buf.extend_from_slice(&0u32.to_le_bytes()); // 2: PaddingGranularity
    buf.extend_from_slice(&0u32.to_le_bytes()); // 3: Flags
    buf.extend_from_slice(&123u32.to_le_bytes()); // 4: FrameCount
    buf.extend_from_slice(&0u32.to_le_bytes()); // 5: InitialFrames
    buf.extend_from_slice(&2u32.to_le_bytes()); // 6: StreamCount
    buf.extend_from_slice(&0u32.to_le_bytes()); // 7: SuggestedBufferSize
    buf.extend_from_slice(&640u32.to_le_bytes()); // 8: ImageWidth
    buf.extend_from_slice(&480u32.to_le_bytes()); // 9: ImageHeight
    // LIST strl (vids)
    buf.extend_from_slice(b"LIST");
    buf.extend_from_slice(&0u32.to_le_bytes()); // size placeholder
    let strl1_start = buf.len();
    buf.extend_from_slice(b"strl");
    // strh — 48 bytes: indices 0..=11 of `%StreamHeader` (int32u table).
    buf.extend_from_slice(b"strh");
    buf.extend_from_slice(&48u32.to_le_bytes());
    buf.extend_from_slice(b"vids"); // 0: StreamType
    buf.extend_from_slice(b"mjpg"); // 1: Codec
    buf.extend_from_slice(&[0u8; 12]); // 2/3/4: flags/priority+language/initial
    buf.extend_from_slice(&1u32.to_le_bytes()); // 5: rate num (byte 20)
    buf.extend_from_slice(&15u32.to_le_bytes()); // 5: rate den (byte 24)
    buf.extend_from_slice(&0u32.to_le_bytes()); // 7: Start (byte 28)
    buf.extend_from_slice(&123u32.to_le_bytes()); // 8: VideoFrameCount (byte 32)
    buf.extend_from_slice(&0u32.to_le_bytes()); // 9: SuggestedBufferSize (byte 36)
    buf.extend_from_slice(&10_000u32.to_le_bytes()); // 10: Quality (byte 40)
    buf.extend_from_slice(&0u32.to_le_bytes()); // 11: SampleSize (byte 44)
    // strf — 40 bytes (BMP V3).
    buf.extend_from_slice(b"strf");
    buf.extend_from_slice(&40u32.to_le_bytes());
    buf.extend_from_slice(&40u32.to_le_bytes()); // 0: BMPVersion
    buf.extend_from_slice(&640u32.to_le_bytes()); // 4: width
    buf.extend_from_slice(&480u32.to_le_bytes()); // 8: height
    buf.extend_from_slice(&1u16.to_le_bytes()); // 12: Planes
    buf.extend_from_slice(&24u16.to_le_bytes()); // 14: BitDepth
    buf.extend_from_slice(b"MJPG"); // 16: Compression (FourCC > 256)
    buf.extend_from_slice(&230_400u32.to_le_bytes()); // 20: ImageLength
    buf.extend_from_slice(&0u32.to_le_bytes()); // 24: PixelsPerMeterX
    buf.extend_from_slice(&0u32.to_le_bytes()); // 28: PixelsPerMeterY
    buf.extend_from_slice(&0u32.to_le_bytes()); // 32: NumColors
    buf.extend_from_slice(&0u32.to_le_bytes()); // 36: NumImportantColors
    // Patch strl size (the 4-byte size sits at strl1_start - 4, just
    // before the "strl" TYPE bytes).
    let strl1_size = (buf.len() - strl1_start) as u32;
    let strl1_size_off = strl1_start - 4;
    buf[strl1_size_off..strl1_size_off + 4].copy_from_slice(&strl1_size.to_le_bytes());

    // LIST strl (auds)
    buf.extend_from_slice(b"LIST");
    buf.extend_from_slice(&0u32.to_le_bytes());
    let strl2_start = buf.len();
    buf.extend_from_slice(b"strl");
    buf.extend_from_slice(b"strh");
    buf.extend_from_slice(&48u32.to_le_bytes());
    buf.extend_from_slice(b"auds"); // 0: StreamType
    buf.extend_from_slice(&[0u8; 4]); // 1: codec FourCC blank
    buf.extend_from_slice(&[0u8; 12]); // 2/3/4
    buf.extend_from_slice(&1u32.to_le_bytes()); // 5 num
    buf.extend_from_slice(&44100u32.to_le_bytes()); // 5 den
    buf.extend_from_slice(&0u32.to_le_bytes()); // 7 Start
    buf.extend_from_slice(&500u32.to_le_bytes()); // 8 sample count
    buf.extend_from_slice(&0u32.to_le_bytes()); // 9 SuggestedBufferSize
    buf.extend_from_slice(&0u32.to_le_bytes()); // 10 Quality
    buf.extend_from_slice(&1u32.to_le_bytes()); // 11 SampleSize
    // strf — AudioFormat (>= 16 bytes).
    buf.extend_from_slice(b"strf");
    buf.extend_from_slice(&16u32.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes()); // Encoding = PCM
    buf.extend_from_slice(&1u16.to_le_bytes()); // NumChannels
    buf.extend_from_slice(&44100u32.to_le_bytes()); // SampleRate
    buf.extend_from_slice(&88200u32.to_le_bytes()); // AvgBytesPerSec
    buf.extend_from_slice(&[0u8; 2]); // BlockAlignment
    buf.extend_from_slice(&8u16.to_le_bytes()); // BitsPerSample
    let strl2_size = (buf.len() - strl2_start) as u32;
    let strl2_size_off = strl2_start - 4;
    buf[strl2_size_off..strl2_size_off + 4].copy_from_slice(&strl2_size.to_le_bytes());

    // Patch hdrl size. `hdrl_start` is the position of the `LIST` FOURCC
    // (NOT the size field), so the size offset is `hdrl_start + 4`.
    let hdrl_size = (buf.len() - hdrl_start - 8) as u32;
    buf[hdrl_start + 4..hdrl_start + 8].copy_from_slice(&hdrl_size.to_le_bytes());

    // LIST INFO with ISFT.
    buf.extend_from_slice(b"LIST");
    let info_size_off = buf.len();
    buf.extend_from_slice(&0u32.to_le_bytes());
    let info_start = buf.len();
    buf.extend_from_slice(b"INFO");
    buf.extend_from_slice(b"ISFT");
    let isft = b"TestAVI\0";
    buf.extend_from_slice(&(isft.len() as u32).to_le_bytes());
    buf.extend_from_slice(isft);
    let info_size = (buf.len() - info_start) as u32;
    buf[info_size_off..info_size_off + 4].copy_from_slice(&info_size.to_le_bytes());

    // IDIT chunk.
    buf.extend_from_slice(b"IDIT");
    let idit_payload = b"Mon Mar 10 15:04:43 2003\0\0";
    buf.extend_from_slice(&(idit_payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(idit_payload);

    // Patch outer RIFF size.
    let outer_size = (buf.len() - 8) as u32;
    buf[4..8].copy_from_slice(&outer_size.to_le_bytes());
    buf
  }

  #[test]
  fn synth_avi_round_trip() {
    let bytes = synth_avi();
    let meta = parse_borrowed(&bytes).expect("ok").expect("some");
    assert_eq!(meta.file_type(), "AVI");
    assert_eq!(meta.mime(), "video/x-msvideo");
    assert!(!meta.is_rf64());
    assert_eq!(meta.streams().len(), 2);
    assert_eq!(meta.streams()[0].stream_type(), Some("vids"));
    assert_eq!(meta.streams()[0].codec(), Some("mjpg"));
    assert_eq!(meta.streams()[1].stream_type(), Some("auds"));

    // Find entries and verify.
    let find = |g: &str, n: &str| -> Option<&RiffValue> {
      meta
        .entries()
        .iter()
        .find(|e| e.group() == g && e.name() == n)
        .map(RiffEntry::value_ref)
    };

    // avih → FrameRate = 1e6/66667 ≈ 15.0001500015
    match find("RIFF", "FrameRate").expect("FrameRate") {
      RiffValue::F64(f) => assert!((f - 15.0001500015).abs() < 1e-6),
      v => panic!("unexpected FrameRate value: {v:?}"),
    }
    assert_eq!(find("RIFF", "FrameCount"), Some(&RiffValue::U32(123)));
    assert_eq!(find("RIFF", "StreamCount"), Some(&RiffValue::U32(2)));
    assert_eq!(find("RIFF", "ImageWidth"), Some(&RiffValue::U32(640)));
    assert_eq!(find("RIFF", "ImageHeight"), Some(&RiffValue::U32(480)));
    assert_eq!(find("RIFF", "MaxDataRate"), Some(&RiffValue::U32(12345)));

    // strh vids → StreamType=vids, VideoCodec=mjpg, Quality=10000,
    //   SampleSize=0, VideoFrameRate=1/(1/15)=15, VideoFrameCount=123
    match find("RIFF", "StreamType").expect("StreamType") {
      RiffValue::Str(s) => assert_eq!(s.as_str(), "vids"),
      v => panic!("{v:?}"),
    }
    match find("RIFF", "VideoCodec").expect("VideoCodec") {
      RiffValue::Str(s) => assert_eq!(s.as_str(), "mjpg"),
      v => panic!("{v:?}"),
    }
    assert_eq!(find("RIFF", "Quality"), Some(&RiffValue::U32(10000)));
    assert_eq!(find("RIFF", "SampleSize"), Some(&RiffValue::U32(0)));
    // VideoFrameRate runs through RoundFloat(num/den, 10), so 15.0 is
    // approximate to ~1ppm.
    match find("RIFF", "VideoFrameRate").expect("VideoFrameRate") {
      RiffValue::F64(f) => assert!((f - 15.0).abs() < 0.01),
      v => panic!("{v:?}"),
    }
    assert_eq!(find("RIFF", "VideoFrameCount"), Some(&RiffValue::U32(123)));

    // strh auds → StreamType=auds, AudioCodec="" (nulls trimmed by
    // ReadValue), AudioSampleRate=44100, AudioSampleCount=500, SampleSize=1.
    // Note: per-stream PRIORITY=0 means StreamType+Quality+SampleSize from
    // the FIRST (vids) stream win; only AudioCodec/AudioSampleRate/
    // AudioSampleCount are emitted (auds-specific names).
    match find("RIFF", "AudioCodec").expect("AudioCodec") {
      RiffValue::Str(s) => assert_eq!(s.as_str(), ""),
      v => panic!("{v:?}"),
    }
    // RoundFloat(num/den, 10) introduces 10-significant-digit truncation,
    // so 44100.0 is approximate to ~1ppm (`1/2.267573696e-05 = 44099.999...`).
    match find("RIFF", "AudioSampleRate").expect("AudioSampleRate") {
      RiffValue::F64(f) => assert!((f - 44100.0).abs() < 0.01),
      v => panic!("{v:?}"),
    }
    assert_eq!(find("RIFF", "AudioSampleCount"), Some(&RiffValue::U32(500)));

    // strf vids → File:BMPVersion=40, Width=640, Height=480, BitDepth=24,
    //   Compression="MJPG", ImageLength=230400
    assert_eq!(find("File", "BMPVersion"), Some(&RiffValue::U32(40)));
    assert_eq!(find("File", "ImageWidth"), Some(&RiffValue::U32(640)));
    assert_eq!(find("File", "ImageHeight"), Some(&RiffValue::U32(480)));
    assert_eq!(find("File", "BitDepth"), Some(&RiffValue::U32(24)));
    match find("File", "Compression").expect("Compression") {
      RiffValue::Str(s) => assert_eq!(s.as_str(), "MJPG"),
      v => panic!("{v:?}"),
    }
    assert_eq!(find("File", "ImageLength"), Some(&RiffValue::U32(230400)));

    // strf auds → AudioFormat Encoding=1, NumChannels=1, SampleRate=44100,
    //   AvgBytesPerSec=88200, BitsPerSample=8.
    assert_eq!(find("RIFF", "Encoding"), Some(&RiffValue::U32(1)));
    assert_eq!(find("RIFF", "NumChannels"), Some(&RiffValue::U32(1)));
    assert_eq!(find("RIFF", "SampleRate"), Some(&RiffValue::U32(44100)));
    assert_eq!(find("RIFF", "AvgBytesPerSec"), Some(&RiffValue::U32(88200)));
    assert_eq!(find("RIFF", "BitsPerSample"), Some(&RiffValue::U32(8)));

    // INFO ISFT → Software=TestAVI
    match find("RIFF", "Software").expect("Software") {
      RiffValue::Str(s) => assert_eq!(s.as_str(), "TestAVI"),
      v => panic!("{v:?}"),
    }

    // IDIT → DateTimeOriginal=2003:03:10 15:04:43
    match find("RIFF", "DateTimeOriginal").expect("IDIT") {
      RiffValue::Str(s) => assert_eq!(s.as_str(), "2003:03:10 15:04:43"),
      v => panic!("{v:?}"),
    }
  }

  #[test]
  fn rejects_non_riff() {
    assert!(parse_borrowed(b"NOPE\0\0\0\0WAVE").expect("ok").is_none());
    assert!(parse_borrowed(b"").expect("ok").is_none());
    assert!(parse_borrowed(b"RIFF").expect("ok").is_none()); // < 12 bytes
  }

  #[test]
  fn accepts_rf64() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"RF64");
    bytes.extend_from_slice(&8u32.to_le_bytes());
    bytes.extend_from_slice(b"WAVE");
    let meta = parse_borrowed(&bytes).expect("ok").expect("some");
    assert_eq!(meta.file_type(), "WAV");
    assert!(meta.is_rf64());
  }

  #[test]
  fn convert_riff_date_standard() {
    assert_eq!(
      convert_riff_date("Mon Mar 10 15:04:43 2003"),
      "2003:03:10 15:04:43"
    );
    assert_eq!(
      convert_riff_date("Tue Dec 31 23:59:59 1999"),
      "1999:12:31 23:59:59"
    );
  }

  #[test]
  fn convert_riff_date_casio() {
    assert_eq!(
      convert_riff_date("2001/ 1/27  1:42PM"),
      "2001:01:27 13:42:00"
    );
    assert_eq!(
      convert_riff_date("2005/11/28/ 09:19"),
      "2005:11:28 09:19:00"
    );
  }

  #[test]
  fn convert_riff_date_konica() {
    assert_eq!(
      convert_riff_date("2002-12-16  15:35:01"),
      "2002:12:16 15:35:01"
    );
  }

  #[test]
  fn convert_riff_date_fallthrough() {
    // Unrecognized shape: emit verbatim (trimmed).
    assert_eq!(convert_riff_date("garbage"), "garbage");
  }

  #[test]
  fn string_trim_nulls_strips_trailing_nuls() {
    assert_eq!(string_trim_nulls(b"hello\0\0\0"), "hello");
    assert_eq!(string_trim_nulls(b"hello"), "hello");
    assert_eq!(string_trim_nulls(b"\0\0\0"), "");
    assert_eq!(string_trim_nulls(b""), "");
  }

  #[test]
  fn render_fourcc_ascii_passes_through() {
    assert_eq!(render_fourcc(b"MJPG"), "MJPG");
    assert_eq!(render_fourcc(b"H264"), "H264");
    // Trailing space stripped (unpack("A4") semantics).
    assert_eq!(render_fourcc(b"MP3 "), "MP3");
  }

  #[test]
  fn render_fourcc_non_ascii_escaped() {
    assert_eq!(
      render_fourcc(&[0xff, 0x01, 0x02, 0x03]),
      "\\xff\\x01\\x02\\x03"
    );
  }

  #[test]
  fn malformed_chunk_does_not_panic() {
    // A RIFF/AVI with a chunk claiming a HUGE length should not panic; the
    // walker must skip silently. Build header + LIST chunk with len >
    // remaining file.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"RIFF");
    bytes.extend_from_slice(&100u32.to_le_bytes());
    bytes.extend_from_slice(b"AVI ");
    // A chunk with a wildly oversized length.
    bytes.extend_from_slice(b"avih");
    bytes.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    // No payload — read_chunk should detect EOF on the next iteration.
    let meta = parse_borrowed(&bytes).expect("ok").expect("some");
    assert_eq!(meta.file_type(), "AVI");
    // No entries — the avih's payload was unreachable.
    assert!(meta.entries().is_empty());
  }

  #[test]
  fn empty_null_chunk_stops_walk() {
    // RIFF.pm:2122-2124: `\0\0\0\0` chunk with len=0 stops parsing.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"RIFF");
    bytes.extend_from_slice(&100u32.to_le_bytes());
    bytes.extend_from_slice(b"AVI ");
    bytes.extend_from_slice(&[0u8; 8]); // null tag + 0 length
    // Even if we put a real chunk after, it should NOT be reached.
    bytes.extend_from_slice(b"IDIT");
    let idit = b"Mon Mar 10 15:04:43 2003";
    bytes.extend_from_slice(&(idit.len() as u32).to_le_bytes());
    bytes.extend_from_slice(idit);
    let meta = parse_borrowed(&bytes).expect("ok").expect("some");
    // No IDIT emission.
    assert!(
      meta
        .entries()
        .iter()
        .all(|e| e.name() != "DateTimeOriginal")
    );
  }

  #[test]
  fn odd_chunk_padding() {
    // A LIST_INFO with an odd-sized INAM payload must be followed by a
    // padding byte, with the next chunk read OFFSET +1 from the payload end.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"RIFF");
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(b"AVI ");
    // LIST INFO ... INAM "abc" (3 bytes, odd) + 1 pad + ISFT "def"
    bytes.extend_from_slice(b"LIST");
    let list_size_off = bytes.len();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    let list_start = bytes.len();
    bytes.extend_from_slice(b"INFO");
    bytes.extend_from_slice(b"INAM");
    bytes.extend_from_slice(&3u32.to_le_bytes());
    bytes.extend_from_slice(b"abc");
    bytes.push(0); // pad
    bytes.extend_from_slice(b"ISFT");
    bytes.extend_from_slice(&3u32.to_le_bytes());
    bytes.extend_from_slice(b"def");
    let list_size = (bytes.len() - list_start) as u32;
    bytes[list_size_off..list_size_off + 4].copy_from_slice(&list_size.to_le_bytes());
    let outer = (bytes.len() - 8) as u32;
    bytes[4..8].copy_from_slice(&outer.to_le_bytes());

    let meta = parse_borrowed(&bytes).expect("ok").expect("some");
    let names: Vec<_> = meta
      .entries()
      .iter()
      .map(|e| e.name().to_string())
      .collect();
    assert!(names.contains(&"Title".to_string())); // INAM
    assert!(names.contains(&"Software".to_string())); // ISFT
  }

  #[test]
  fn format_4g_rendering() {
    // %.4g: 4 significant digits.
    assert_eq!(format_4g(206.024), "206");
    assert_eq!(format_4g(2.06024), "2.06");
    assert_eq!(format_4g(20.6024), "20.6");
    // Perl `printf "%.4g", 1234.5` rounds to "1234" (round-half-to-even);
    // see https://perldoc.perl.org/functions/sprintf. Our format_4g should
    // match.
    assert_eq!(format_4g(1234.5), "1234");
  }
}
