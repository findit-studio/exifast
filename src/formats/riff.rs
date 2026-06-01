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
//! - `%audioEncoding` PrintConv (RIFF.pm:90-335) — the FULL "TwoCC" codec
//!   table is transcribed in [`audio_encoding_label`]; an unrecognized code
//!   falls back to the `Unknown (0x%x)` rendering (ExifTool's default hash
//!   PrintConv miss).
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
  /// `true` when the walker hit a truncated chunk (a declared chunk length
  /// extending past EOF). Surfaced by [`RiffMeta::diagnostics`](crate::diagnostics::Diagnose::diagnostics)
  /// as the bundled terminal warning `Error reading RIFF file (corrupted?)`
  /// (RIFF.pm:2216, `$err and $et->Warn(...)`).
  corrupted: bool,
  /// `Some(code_page)` when a CSET-declared NUMERIC charset was used to decode
  /// at least one non-empty INFO string — ExifTool's `Decode` warns once
  /// `Unsupported character set (<N>)` (ExifTool.pm:6359-6363). Surfaced by
  /// [`RiffMeta::diagnostics`](crate::diagnostics::Diagnose::diagnostics) as an
  /// `ExifTool:Warning`.
  unsupported_charset: Option<u16>,
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
      corrupted: false,
      unsupported_charset: None,
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

  fn parse<'a>(&self, data: Self::Context<'a>) -> Option<Self::Meta<'a>> {
    parse_inner(data)
  }
}

/// Lib-first direct entry. Returns an owned [`RiffMeta`].
///
/// # Errors
///
/// Returns `Err` only for Rust-level fatal modes (none today — every bad
/// input is `Ok(None)`, faithful to RIFF.pm:2039 `return 0`).
pub fn parse_borrowed(data: &[u8]) -> Option<RiffMeta<'_>> {
  parse_inner(data)
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
    charset: Charset::Latin,
    unsupported_charset: None,
    err: false,
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
    corrupted: walker.err,
    unsupported_charset: walker.unsupported_charset,
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
  /// Active charset for `INFO`/`exif` string decoding (RIFF.pm:1782-1790).
  /// Starts [`Charset::Latin`] (the default `'Latin'`/cp1252); a `CSET` chunk
  /// with a non-zero `CodePage` switches it to [`Charset::Raw`]
  /// (`$$self{CodePage}` is numeric ⇒ the `%csType` lookup misses ⇒ raw
  /// passthrough), while a `CodePage=0` CSET resets it back to
  /// [`Charset::Latin`]. The RawConv overwrites `$$self{CodePage}` on every
  /// CSET and the gate uses the LATEST value, so the most recent CSET wins.
  charset: Charset,
  /// The numeric code page from the FIRST `Decode` that hit an unsupported
  /// (numeric) charset with a non-empty string — surfaced ONCE as
  /// `Unsupported character set (<N>)` (ExifTool.pm:6359-6363, the
  /// `DecodeWarn$set` once-guard). `None` until such a decode happens.
  unsupported_charset: Option<u16>,
  /// `$err` (RIFF.pm:2096/2150/2216) — set when a declared-length chunk could
  /// not be fully read (truncated). Drives the terminal
  /// `Error reading RIFF file (corrupted?)` warning.
  err: bool,
}

impl<'a> Walker<'a> {
  /// Top-level chunk loop — RIFF.pm:2065-2214.
  fn walk_top(&mut self) {
    while let Some((tag, len, pad_len)) = self.read_chunk() {
      let chunk_start = self.pos;
      let chunk_end = chunk_start + len;

      // RIFF.pm:2122-2124: an empty `\0\0\0\0` chunk (len 0) stops the walk.
      // Checked BEFORE the truncation guard (bundled's `$len<=0` block at
      // 2118 precedes the read at 2150).
      if len == 0 && &tag == b"\0\0\0\0" {
        break;
      }
      // RIFF.pm:2173-2181: a mid-stream `RIFF` re-trigger only reads the
      // 4-byte inner TYPE word and continues (concatenated video). It does
      // NOT read the declared `$len2`, so the truncation guard must not apply.
      // Sub-document (`DOC_NUM`) accumulation is deferred (single-document).
      if &tag == b"RIFF" {
        self.pos = chunk_start + 4; // skip the 4-byte inner TYPE
        continue;
      }

      // Finding 4 (RIFF.pm:2150 `$raf->Read($buff,$len2) >= $len or $err=1,next`,
      // and the symmetric `$raf->Seek($len2,1) or $err=1,next` at 2209): a
      // chunk whose DECLARED length runs past EOF is NEVER dispatched —
      // bundled's read/seek fails, sets `$err`, and `next`s WITHOUT calling
      // `HandleTag` (so no partial-payload tags are emitted), then warns once
      // at the end (RIFF.pm:2216 `$err and $et->Warn('Error reading RIFF file
      // (corrupted?)')`). We replicate: mark `err`, skip the dispatch, and
      // advance past EOF (the walk then ends — `read_chunk` finds < 8 bytes).
      if chunk_end > self.data.len() {
        self.err = true;
        self.pos = chunk_end + pad_len;
        continue;
      }

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
        // The declared body is fully present (guarded above), so the LIST
        // payload end is the true chunk end.
        let list_payload_end = chunk_end;
        if list_payload_end <= list_payload_start {
          // Empty LIST — skip past it (with padding).
          self.pos = chunk_end + pad_len;
          continue;
        }
        let body = &self.data[list_payload_start..list_payload_end];
        match &list_type {
          b"INFO" | b"INF0" => {
            process_chunks_info(
              body,
              &mut self.entries,
              self.charset,
              &mut self.unsupported_charset,
            );
          }
          b"exif" => {
            // NOTE: `%RIFF::Exif` (RIFF.pm:1013-1027) has NO `FORMAT =>
            // 'string'`, so ProcessChunks does NOT charset-decode its values
            // (the `$format eq 'string'` branch, RIFF.pm:1825-1830, is
            // skipped). They pass through raw (verified vs bundled: an `ecor`
            // with a high byte keeps the byte, JSON-escaped to `?`). So the
            // CSET charset is intentionally NOT threaded here.
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
      // `%Main` (RIFF.pm:338-678). The declared body is fully present here
      // (guarded above), so the slice is exactly the chunk payload.
      let body = &self.data[chunk_start..chunk_end];
      match &tag {
        b"fmt " => emit_audio_format(body, &mut self.entries),
        b"IDIT" => emit_idit(body, &mut self.entries),
        b"ISMP" => emit_ismp(body, &mut self.entries),
        // CSET (RIFF.pm:533-536 → `%RIFF::CSET`, ProcessBinaryData int16u):
        // emits `CodePage`/`CountryCode`/`LanguageCode`/`Dialect`
        // (RIFF.pm:1063-1073) AND sets `$$self{CodePage}` (RIFF.pm:1067-1069
        // RawConv `$$self{CodePage} = $val`). The subsequent INFO ProcessChunks
        // then resolves its `$charset` via the TRUTHINESS gate at
        // RIFF.pm:1784-1789:
        //
        //   unless ($charset) {                 # CharsetRIFF default 0 → enter
        //       if ($$et{CodePage}) {           # TRUTHY ⇒ NON-ZERO only
        //           $charset = $$et{CodePage};  # numeric code page
        //       } elsif (defined $charset and $charset eq '0') {
        //           $charset = 'Latin';         # 0 / no-CSET ⇒ cp1252
        //       }
        //   }
        //
        // So a NON-ZERO `CodePage` makes `$charset` the NUMERIC code page;
        // `Image::ExifTool::Decode` keys `%csType` by charset NAME, so the
        // number misses ⇒ raw passthrough + an `Unsupported character set
        // (<N>)` warning — modeled as `Charset::Raw(code_page)`. A `CodePage`
        // of **0** is FALSY, so it falls through to the `'Latin'` branch
        // (`CharsetRIFF` defaults to `0` ⇒ `defined && eq '0'`), exactly like
        // having no CSET at all: cp1252 decode, NO warning
        // (`Charset::Latin`, the initial default).
        //
        // The RawConv overwrites `$$self{CodePage}` on EVERY CSET, and the gate
        // resolves the LATEST value — so the most recent CSET is AUTHORITATIVE:
        // a `CodePage=1252` followed by a `CodePage=0` ends up Latin (the 0
        // RESETS the prior Raw, no warning). We therefore assign `self.charset`
        // for EVERY parsed CSET, not just the non-zero ones (verified vs bundled
        // 13.59: `CSET CodePage=1252` → `CSET CodePage=0` → `IART=Caf\xe9` emits
        // `RIFF:CodePage=0`, `RIFF:Artist="Café"`, and NO `ExifTool:Warning`).
        b"CSET" => {
          if let Some(code_page) = emit_cset(body, &mut self.entries) {
            self.charset = if code_page == 0 {
              Charset::Latin
            } else {
              Charset::Raw(code_page)
            };
          }
        }
        // Skip image-data / index chunks (RIFF.pm:2148-2150).
        b"data" | b"idx1" => {}
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

/// `%Image::ExifTool::RIFF::Info` — RIFF.pm:835-1010. Emits the COMPLETE
/// table (all 87 FourCC → tag-name rows; see [`info_tag_name`]): the EXIF 2.3
/// subset, the IMDb / MovieID / Morgan / GSpot / Sound Forge / Sony Vegas
/// 3rd-party rows, and the INFO-level `IDIT`/`ISMP`. Unrecognized FourCCs are
/// silently skipped (faithful to bundled with no `-U`).
///
/// String values are decoded through the active [`Charset`] (RIFF.pm:1829)
/// — the default is `'Latin'`/cp1252, NOT UTF-8. The per-tag ValueConvs are
/// applied here (`ICRD` RIFF.pm:853, `ISFT` RIFF.pm:873, `TLEN` RIFF.pm:933,
/// `TCOD`/`TCDO` RIFF.pm:948/954, `DTIM` RIFF.pm:988-998, `IDIT` RIFF.pm:1006);
/// the PrintConvs run later at emit time. When the active charset is an
/// unsupported (CSET numeric) code page, the first non-empty decode records
/// the `Unsupported character set (<N>)` warning in `unsupported_charset`
/// (ExifTool.pm:6349-6363).
fn process_chunks_info(
  body: &[u8],
  entries: &mut Vec<RiffEntry>,
  charset: Charset,
  unsupported_charset: &mut Option<u16>,
) {
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
    let Some(name) = info_tag_name(&tag) else {
      // Unknown tag — no `$tagInfo`, so ExifTool never calls `Decode`
      // (RIFF.pm:1810-1830): it neither emits nor triggers the
      // unsupported-charset warning. Skip silently (no `-U`).
      continue;
    };
    // RIFF.pm:1826-1829 — trim trailing NULs from the raw bytes, THEN decode
    // through the active charset (cp1252 by default). Per-tag ValueConvs run
    // AFTER the decode (HandleTag stores the decoded `$val`, then ValueConv).
    let raw = trim_trailing_nulls(payload);
    // ExifTool.pm:6349-6363 — `Decode($val, $charset)` warns once
    // `Unsupported character set (<N>)` when the (numeric) `$from` charset is
    // not in `%csType` AND `length $val` (post-NUL-trim) is non-zero. The
    // `DecodeWarn$set` once-guard ⇒ record only the first occurrence.
    if !raw.is_empty()
      && let Some(cp) = charset.unsupported_code_page()
      && unsupported_charset.is_none()
    {
      *unsupported_charset = Some(cp);
    }
    let decoded = charset.decode(raw);
    // Per-tag ValueConv (RIFF.pm:835-1009). Numeric ValueConvs (`TLEN`,
    // `TCOD`, `TCDO`) coerce the decoded string via Perl numeric semantics
    // and store an `F64` (their PrintConv runs at emit time); the date
    // ValueConvs (`DTIM`, `IDIT`) and `ICRD`/`ISFT` rewrite the string.
    let value: Option<RiffValue> = match &tag {
      // ICRD DateCreated — ValueConv `$_=$val; s/-/:/g; $_` (RIFF.pm:853).
      b"ICRD" => Some(RiffValue::Str(SmolStr::new(decoded.replace('-', ":")))),
      // ISFT Software — ValueConv `s/(\s*\0)+$//; s/(\s*\0)/, /; s/\0+//g`
      // (RIFF.pm:873): trim trailing space-runs-before-NUL, replace the first
      // embedded `[\s]*\0` with ", ", drop any remaining NULs. (Casio writes
      // "CASIO" after the first NUL.)
      b"ISFT" => Some(RiffValue::Str(SmolStr::new(isft_value_conv(&decoded)))),
      // TLEN Length — ValueConv `$val/1000` (RIFF.pm:933). PrintConv
      // `"$val s"` runs at emit time.
      b"TLEN" => Some(RiffValue::F64(
        crate::convert::perl_str_to_f64(&decoded) / 1000.0,
      )),
      // TCOD StartTimecode / TCDO EndTimecode — ValueConv `$val * 1e-7`
      // (RIFF.pm:948/954). PrintConv `ConvertTimecode` runs at emit time.
      b"TCOD" | b"TCDO" => Some(RiffValue::F64(
        crate::convert::perl_str_to_f64(&decoded) * 1e-7,
      )),
      // DTIM DateTimeOriginal — ValueConv (RIFF.pm:988-998); may return undef
      // (when the value is not exactly two space-separated FILETIME halves),
      // in which case the tag is dropped.
      b"DTIM" => dtim_value_conv(&decoded).map(|s| RiffValue::Str(SmolStr::new(s))),
      // IDIT DateTimeOriginal — ValueConv `ConvertRIFFDate($val)`
      // (RIFF.pm:1006). PrintConv `ConvertDateTime` is identity here.
      b"IDIT" => Some(RiffValue::Str(SmolStr::new(convert_riff_date(&decoded)))),
      // STAT Statistics (RIFF.pm:973-983) — no ValueConv; the list PrintConv
      // runs at emit time. All other entries pass the decoded string through.
      _ => Some(RiffValue::Str(SmolStr::new(decoded))),
    };
    if let Some(value) = value {
      entries.push(RiffEntry::new("RIFF", name, value));
    }
  }
}

/// `ISFT` Software ValueConv (RIFF.pm:873): `s/(\s*\0)+$//; s/(\s*\0)/, /;
/// s/\0+//g`. Faithful transliteration:
/// 1. strip a trailing run of `(\s*\0)+` (whitespace-then-NUL groups);
/// 2. replace the FIRST remaining `\s*\0` with `", "`;
/// 3. delete all remaining NULs.
fn isft_value_conv(val: &str) -> String {
  // (1) `s/(\s*\0)+$//` — repeatedly drop a trailing `\s*\0` group (a NUL
  // preceded by 0+ ASCII-whitespace bytes). `\s` is matched as ASCII
  // whitespace; UTF-8 continuation bytes (0x80-0xbf) are never ASCII
  // whitespace, so the byte-level scan is safe on the decoded string.
  let mut bytes: Vec<u8> = val.as_bytes().to_vec();
  while bytes.last() == Some(&0) {
    let mut ws_start = bytes.len() - 1; // index of the trailing NUL
    while ws_start > 0 && (bytes[ws_start - 1] as char).is_ascii_whitespace() {
      ws_start -= 1;
    }
    bytes.truncate(ws_start);
  }
  // (2) `s/(\s*\0)/, /` — replace the FIRST `\s*\0` group with ", ".
  // Find the first NUL; back up over its leading ASCII whitespace.
  if let Some(nul) = bytes.iter().position(|&b| b == 0) {
    let mut ws_start = nul;
    while ws_start > 0 && (bytes[ws_start - 1] as char).is_ascii_whitespace() {
      ws_start -= 1;
    }
    let mut out = Vec::with_capacity(bytes.len() + 2);
    out.extend_from_slice(&bytes[..ws_start]);
    out.extend_from_slice(b", ");
    // (3) `s/\0+//g` on the remainder — copy the rest, dropping NULs.
    out.extend(bytes[nul + 1..].iter().copied().filter(|&b| b != 0));
    bytes = out;
  }
  // The decode already produced valid UTF-8; the surgery only removes NULs /
  // splices ASCII ", ", so the bytes stay valid UTF-8.
  String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// Map an INFO chunk FourCC to its emitted tag name — the COMPLETE
/// `%Image::ExifTool::RIFF::Info` table (RIFF.pm:835-1010, all 87 entries).
/// Returns `None` for FourCCs the bundled table doesn't define — those are
/// silently skipped (faithful with no `-U`). The per-tag ValueConv/PrintConv
/// (`ICRD`/`ISFT`/`TLEN`/`TCOD`/`TCDO`/`DTIM`/`STAT`/`IDIT`) are applied by
/// the caller ([`process_chunks_info`] for the ValueConv, [`emit_one`]/
/// [`print_conv_str`]/[`print_conv_f64_string`] for the PrintConv).
const fn info_tag_name(tag: &[u8; 4]) -> Option<&'static str> {
  match tag {
    // ----- EXIF 2.3 INFO subset (RIFF.pm:845-878) -----------------------
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
    // ----- Internet movie database (RIFF.pm:882-896, ref 12) ------------
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
    // ----- MovieID (RIFF.pm:897-908, ref 12) ----------------------------
    b"TITL" => Some("Title"),
    b"DIRC" => Some("Directory"),
    b"YEAR" => Some("Year"),
    b"GENR" => Some("Genre"),
    b"COMM" => Some("Comments"),
    b"LANG" => Some("Language"),
    b"AGES" => Some("Rated"),
    b"STAR" => Some("Starring"),
    b"CODE" => Some("EncodedBy"),
    b"PRT1" => Some("Part"),
    b"PRT2" => Some("NumberOfParts"),
    // ----- Morgan Multimedia (RIFF.pm:909-927, ref 12) ------------------
    b"IAS1" => Some("FirstLanguage"),
    b"IAS2" => Some("SecondLanguage"),
    b"IAS3" => Some("ThirdLanguage"),
    b"IAS4" => Some("FourthLanguage"),
    b"IAS5" => Some("FifthLanguage"),
    b"IAS6" => Some("SixthLanguage"),
    b"IAS7" => Some("SeventhLanguage"),
    b"IAS8" => Some("EighthLanguage"),
    b"IAS9" => Some("NinthLanguage"),
    b"ICAS" => Some("DefaultAudioStream"),
    b"IBSU" => Some("BaseURL"),
    b"ILGU" => Some("LogoURL"),
    b"ILIU" => Some("LogoIconURL"),
    b"IWMU" => Some("WatermarkURL"),
    b"IMIU" => Some("MoreInfoURL"),
    b"IMBI" => Some("MoreInfoBannerImage"),
    b"IMBU" => Some("MoreInfoBannerURL"),
    b"IMIT" => Some("MoreInfoText"),
    // ----- GSpot (RIFF.pm:928-930, ref 12) ------------------------------
    b"IENC" => Some("EncodedBy"),
    b"IRIP" => Some("RippedBy"),
    // ----- Sound Forge Pro (RIFF.pm:931-938) ----------------------------
    b"DISP" => Some("SoundSchemeTitle"),
    b"TLEN" => Some("Length"),
    b"TRCK" => Some("TrackNumber"),
    b"TURL" => Some("URL"),
    b"TVER" => Some("Version"),
    b"LOCA" => Some("Location"),
    b"TORG" => Some("Organization"),
    // ----- Sony Vegas / SCLive / Adobe Premiere (RIFF.pm:939-1000, ref 11)
    b"TAPE" => Some("TapeName"),
    b"TCOD" => Some("StartTimecode"),
    b"TCDO" => Some("EndTimecode"),
    b"VMAJ" => Some("VegasVersionMajor"),
    b"VMIN" => Some("VegasVersionMinor"),
    b"CMNT" => Some("Comment"),
    b"RATE" => Some("Rate"),
    b"STAT" => Some("Statistics"),
    b"DTIM" => Some("DateTimeOriginal"),
    // ----- INFO-level IDIT / ISMP (RIFF.pm:1001-1009) -------------------
    b"IDIT" => Some("DateTimeOriginal"),
    b"ISMP" => Some("TimeCode"),
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
  // 0: StreamType — Format => 'string[4]' (RIFF.pm:1166-1177). `string_trim_nulls`
  // trims trailing NULs (the `string[4]` ReadValue trim) and renders any invalid
  // UTF-8 byte as `?` (ExifTool's JSON FixUTF8), NOT U+FFFD.
  let stream_type_bytes: [u8; 4] = payload[0..4].try_into().expect("4 bytes");
  let stream_type_str = string_trim_nulls(&stream_type_bytes);
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

/// `%Image::ExifTool::RIFF::CSET` (RIFF.pm:1063-1073) via `ProcessBinaryData`,
/// `FORMAT => 'int16u'`: emits `CodePage`(0) / `CountryCode`(1) /
/// `LanguageCode`(2) / `Dialect`(3), each an int16u read at its byte offset
/// (0/2/4/6). `ProcessBinaryData` emits only the fields whose bytes are
/// present (verified vs bundled: a 2-byte CSET emits just `CodePage`). The
/// `CodePage` `RawConv => '$$self{CodePage} = $val'` (RIFF.pm:1069) is modeled
/// by returning the numeric code page so the caller switches the INFO charset
/// to [`Charset::Raw`]. Returns `None` when the chunk is too short to hold
/// even `CodePage` (no charset switch, no fields).
fn emit_cset(body: &[u8], entries: &mut Vec<RiffEntry>) -> Option<u16> {
  // ProcessBinaryData reads int16u entries; a field at index `i` lives at byte
  // offset `2*i` and is emitted only if `2*i + 2 <= len`.
  const FIELDS: [(usize, &str); 4] = [
    (0, "CodePage"),
    (1, "CountryCode"),
    (2, "LanguageCode"),
    (3, "Dialect"),
  ];
  let mut code_page = None;
  for (idx, name) in FIELDS {
    let off = idx * 2;
    if off + 2 > body.len() {
      break;
    }
    let val = le_u16(&body[off..off + 2]);
    if idx == 0 {
      code_page = Some(val);
    }
    entries.push(RiffEntry::new("RIFF", name, RiffValue::U32(u32::from(val))));
  }
  code_page
}

/// `DTIM` DateTimeOriginal ValueConv (RIFF.pm:988-998). The raw value is two
/// space-separated 64-bit FILETIME halves (`hi lo`, 100-ns ticks since
/// 1601-01-01). Faithful transliteration:
///
/// - Split on whitespace; unless EXACTLY two parts, return `undef` (drop tag).
/// - If the raw already matches `^\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}$`
///   (the Kodak EASYSHARE Sport stores it pre-formatted), return it verbatim.
/// - Else `$val = 1e-7 * (hi*4294967296 + lo)`; shift from the 1601 epoch to
///   the Unix epoch (`-= 134774*24*3600`) unless `$val == 0`; then
///   `ConvertUnixTime($val)`.
fn dtim_value_conv(val: &str) -> Option<String> {
  let parts: Vec<&str> = val.split_whitespace().collect();
  // RIFF.pm:990 `return undef unless @v == 2;`. The split happens BEFORE the
  // Kodak-string short-circuit, so the pre-formatted string (which has two
  // whitespace-separated parts: "2021:06:15" and "12:30:45") survives.
  if parts.len() != 2 {
    return None;
  }
  // RIFF.pm:992 — Kodak EASYSHARE Sport pre-formatted passthrough.
  if is_kodak_datetime(val) {
    return Some(val.to_string());
  }
  // RIFF.pm:994 `$val = 1e-7 * ($v[0] * 4294967296 + $v[1]);` — Perl coerces
  // each half through numeric context (leading-digit prefix).
  let hi = crate::convert::perl_str_to_f64(parts[0]);
  let lo = crate::convert::perl_str_to_f64(parts[1]);
  let mut secs = 1e-7 * (hi * 4_294_967_296.0 + lo);
  // RIFF.pm:996 `$val -= 134774 * 24 * 3600 if $val != 0;`.
  if secs != 0.0 {
    secs -= 134_774.0 * 24.0 * 3600.0;
  }
  // RIFF.pm:997 `return Image::ExifTool::ConvertUnixTime($val);` (float form).
  Some(crate::datetime::convert_unix_time_f64(secs))
}

/// `true` when `val` matches the Perl regex `^\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}$`
/// (RIFF.pm:992) — the Kodak pre-formatted DateTimeOriginal passthrough.
fn is_kodak_datetime(val: &str) -> bool {
  let b = val.as_bytes();
  // `YYYY:MM:DD HH:MM:SS` — exactly 19 bytes with fixed digit/colon/space slots.
  if b.len() != 19 {
    return false;
  }
  // Digit positions: 0-3, 5-6, 8-9, 11-12, 14-15, 17-18.
  let digit = |i: usize| b[i].is_ascii_digit();
  let digits_ok = (0..=3).all(digit)
    && [5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
      .iter()
      .all(|&i| digit(i));
  // Separators: ':' at 4,7,13,16 and ' ' at 10.
  digits_ok && b[4] == b':' && b[7] == b':' && b[10] == b' ' && b[13] == b':' && b[16] == b':'
}

// ===========================================================================
// §6. Helpers — `ConvertRIFFDate`, byte readers, string trim
// ===========================================================================

/// Trim trailing NUL bytes from a payload, returning the raw byte slice.
/// Faithful to ProcessChunks RIFF.pm:1827 `$val =~ s/\0+$//`. The CALLER
/// then decodes through the active charset (see [`Charset::decode`]).
fn trim_trailing_nulls(bytes: &[u8]) -> &[u8] {
  let mut end = bytes.len();
  while end > 0 && bytes[end - 1] == 0 {
    end -= 1;
  }
  &bytes[..end]
}

/// Trim trailing NUL bytes from a UTF-8-ish payload and return the resulting
/// `String`. Faithful to ProcessChunks RIFF.pm:1827
/// `$val =~ s/\0+$//`. Non-UTF8 bytes are kept as best-effort via
/// `from_utf8_lossy`. Used for FourCC-style fields (`StreamType`, codec,
/// `strn`) that bundled reads via `Format => 'string[4]'` — those do NOT pass
/// through the CSET charset (only `INFO`/`exif` string chunks decoded by
/// `ProcessChunks` do, RIFF.pm:1825-1829).
///
/// **Invalid-byte rendering:** invalid UTF-8 bytes become a single ASCII `?`
/// each (via [`crate::convert::fix_utf8`], the port of `XMP::FixUTF8` that
/// ExifTool's JSON writer applies at `exiftool:3822`), NOT the
/// `from_utf8_lossy` U+FFFD replacement char. Verified vs the bundled oracle:
/// an `exif`-LIST `ecor` of `Mak\xe9\xff` emits `"Mak??"`, and a `strn`
/// StreamName of `Strm\xe9\xff` emits `"Strm??"` (NOT `Mak\u{FFFD}…`).
fn string_trim_nulls(bytes: &[u8]) -> String {
  crate::convert::fix_utf8(trim_trailing_nulls(bytes))
}

/// Active RIFF string charset (RIFF.pm:1782-1790). `ProcessChunks` decodes
/// `INFO`/`exif` string chunks through `$et->Decode($val, $charset)`.
///
/// The resolution follows the truthiness gate at RIFF.pm:1784-1789
/// (`CharsetRIFF` defaults to `0`):
///
/// - **Default** (no `CSET` chunk, or the LATEST `CSET` has `CodePage==0`):
///   `$charset` resolves to the NAME `'Latin'` (RIFF.pm:1788 — `$$et{CodePage}`
///   is unset or `0` ⇒ FALSY, so the `elsif defined $charset and $charset eq
///   '0'` branch fires) ⇒ cp1252 → UTF-8 decode
///   ([`crate::charset::decode_latin`]), NO warning. Because the `CodePage`
///   RawConv (RIFF.pm:1067-1069) overwrites `$$et{CodePage}` on EVERY CSET and
///   the gate reads the LATEST value, a `CodePage==0` CSET RESETS a prior
///   non-zero `Raw` back to Latin — it is not merely a no-op (verified vs
///   bundled 13.59: `CSET CodePage=1252` → `CSET CodePage=0` → `IART=Caf\xe9` →
///   `RIFF:Artist="Café"`, no `ExifTool:Warning`).
/// - **`CSET` chunk with a NON-ZERO `CodePage`**: `$$et{CodePage}` is TRUTHY,
///   so `$charset` is the NUMERIC code page (RIFF.pm:1785-1786).
///   `Image::ExifTool::Decode` keys its `%csType` table by NAME, so a numeric
///   code page never matches ⇒ NO remapping (raw byte passthrough;
///   `ExifTool.pm:6351-6363`). We model this as [`Charset::Raw`] carrying the
///   numeric code page (verified vs bundled: a `CSET CodePage=1252` file emits
///   the literal input bytes, not a cp1252-decoded string, and warns
///   `Unsupported character set (1252)`). The dead `%code2charset` table
///   (RIFF.pm:67-88) is NEVER referenced in bundled, so it does NOT translate
///   the number to a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Charset {
  /// Default `'Latin'` (cp1252) decoding.
  Latin,
  /// A `CSET` code page was declared — raw passthrough (`%csType` miss). The
  /// `u16` is the declared numeric code page (`$$self{CodePage}`), surfaced
  /// in the `Unsupported character set (<N>)` warning (ExifTool.pm:6359-6363).
  Raw(u16),
}

impl Charset {
  /// Decode raw (already trailing-NUL-trimmed) chunk bytes to a `String` per
  /// the active charset. `Latin` ⇒ cp1252→UTF-8 ([`crate::charset::decode_latin`],
  /// always valid UTF-8); `Raw` ⇒ the bytes pass through unremapped, with
  /// invalid UTF-8 rendered as ASCII `?` per ExifTool's JSON `FixUTF8`
  /// ([`crate::convert::fix_utf8`]) — NOT the `from_utf8_lossy` U+FFFD char
  /// (verified vs bundled: a CSET file with an `IART` of `Caf\xe9\xff Test`
  /// emits `"Caf?? Test"`, two `?` for the two invalid bytes).
  fn decode(self, bytes: &[u8]) -> String {
    match self {
      Charset::Latin => crate::charset::decode_latin(bytes),
      Charset::Raw(_) => crate::convert::fix_utf8(bytes),
    }
  }

  /// `true` when this is an unsupported (numeric code page) charset, i.e. the
  /// `Decode` path that warns `Unsupported character set (<N>)`. The numeric
  /// code page is returned for the warning message.
  const fn unsupported_code_page(self) -> Option<u16> {
    match self {
      Charset::Latin => None,
      Charset::Raw(cp) => Some(cp),
    }
  }
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

/// `Image::ExifTool::RIFF::ConvertTimecode($val)` — RIFF.pm:1625-1638. The
/// `StartTimecode`/`EndTimecode` PrintConv: a duration in seconds (`f64`, the
/// `$val * 1e-7` ValueConv result) rendered as `H:MM:SS.ss`.
///
/// Faithful transliteration: `int()` truncates toward zero (Perl `int` on an
/// NV); the seconds field is `sprintf('%05.2f', $val)`; the round-off guard
/// (`$ss >= 60`) compares the *numeric* string back to 60 and carries.
fn convert_timecode(val: f64) -> String {
  // RIFF.pm:1628-1631 — `int($val/3600)`, then `int(remainder/60)`.
  let mut hr = (val / 3600.0).trunc();
  let after_hr = val - hr * 3600.0;
  let mut min = (after_hr / 60.0).trunc();
  let sec = after_hr - min * 60.0;
  // RIFF.pm:1632 `my $ss = sprintf('%05.2f', $val);` — 2-decimal, zero-padded
  // to width 5 (e.g. `05.00`, `59.99`).
  let mut ss = format!("{sec:05.2}");
  // RIFF.pm:1633-1636 `if ($ss >= 60)` — Perl numifies the string for the
  // comparison; the `%05.2f` rounding can produce "60.00" from e.g. 59.999.
  if ss.parse::<f64>().unwrap_or(0.0) >= 60.0 {
    ss = "00.00".to_string();
    min += 1.0;
    if min >= 60.0 {
      min -= 60.0;
      hr += 1.0;
    }
  }
  // RIFF.pm:1637 `sprintf('%d:%.2d:%s', $hr, $min, $ss)` — `$hr`/`$min` are
  // NV-typed; `%d` truncates toward zero. Cast the small h/m back to i64.
  format!("{}:{:02}:{}", hr as i64, min as i64, ss)
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
impl crate::diagnostics::Diagnose for RiffMeta<'_> {
  /// RIFF's two `$et->Warn` paths as [`Diagnostic`](crate::diagnostics::Diagnostic)
  /// warnings, in occurrence order:
  ///  1. `Unsupported character set (<N>)` — fired mid-walk by `Decode`
  ///     (ExifTool.pm:6359-6363, RIFF.pm:1829) the first time a CSET-declared
  ///     NUMERIC charset decodes a non-empty INFO string (the code page is
  ///     recorded once in the `unsupported_charset` field).
  ///  2. `Error reading RIFF file (corrupted?)` — the terminal corruption
  ///     notice for a declared-length chunk that runs past EOF (RIFF.pm:2216
  ///     `$err and $et->Warn(...)`; the `corrupted` field).
  /// The charset warning precedes the corruption notice (mid-walk before
  /// end-of-walk); the default `-j` output surfaces only the FIRST recorded
  /// warning. The other `ProcessChunks` warning paths (`Bad ... data`) abort
  /// the sub-walk silently (no tags), matching bundled's `return 0`. Both fire
  /// OUTSIDE a RIFF `SET_GROUP1` scope ⇒ family-0 `ExifTool:Warning` (unlike
  /// the MXF/Matroska group-scoped seam).
  fn diagnostics(&self) -> std::vec::Vec<crate::diagnostics::Diagnostic> {
    let mut out = std::vec::Vec::new();
    if let Some(code_page) = self.unsupported_charset {
      out.push(crate::diagnostics::Diagnostic::warn(std::format!(
        "Unsupported character set ({code_page})"
      )));
    }
    if self.corrupted {
      out.push(crate::diagnostics::Diagnostic::warn(
        "Error reading RIFF file (corrupted?)",
      ));
    }
    out
  }
}

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
      // "Video" etc.; STAT runs the list PrintConv) in `-j` mode.
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
      // PrintConv whose `-j` rendering is a STRING (TLEN `"$val s"`,
      // TCOD/TCDO `ConvertTimecode`) — checked first; these names are NOT in
      // `print_conv_f64_value` (no rounding) so the `-n` path emits the raw
      // F64 below.
      if print_conv && let Some(printed) = print_conv_f64_string(name, *f) {
        TagValue::Str(printed.into())
      } else if print_conv && let Some(rounded) = print_conv_f64_value(name, *f) {
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

/// PrintConv for `Str`-typed values. `RIFF:StreamType` maps the FourCC to a
/// label (RIFF.pm:1170-1176); `RIFF:Statistics` runs the Sony Vegas list
/// PrintConv (RIFF.pm:977-982). Returns the rendered string, or `None` to pass
/// the stored value through unchanged.
#[cfg(feature = "alloc")]
fn print_conv_str(group: &str, name: &str, val: &str) -> Option<String> {
  match (group, name) {
    ("RIFF", "StreamType") => match val {
      "auds" => Some("Audio".to_string()),
      "mids" => Some("MIDI".to_string()),
      "txts" => Some("Text".to_string()),
      "vids" => Some("Video".to_string()),
      "iavs" => Some("Interleaved Audio+Video".to_string()),
      _ => None,
    },
    // STAT Statistics (RIFF.pm:977-982) — a Perl LIST PrintConv applied to the
    // space-separated values: `"$val frames captured"`, `"$val dropped"`,
    // `"Data rate $val"`, `{ 0 => 'Bad', 1 => 'OK' }`. Values BEYOND the four
    // list slots are emitted verbatim (Perl's list-PrintConv passes the extra
    // values through unchanged); a value SHORT of four leaves later slots
    // absent. The rendered parts are joined with "; " (verified vs bundled:
    // "7318 0 3.430307 1" ⇒ "7318 frames captured; 0 dropped; Data rate
    // 3.430307; OK").
    ("RIFF", "Statistics") => Some(stat_print_conv(val)),
    _ => None,
  }
}

/// PrintConv for f64 values whose `-j` rendering is a STRING. `RIFF:Length`
/// (TLEN) is `"$val s"` (RIFF.pm:933); `RIFF:StartTimecode`/`RIFF:EndTimecode`
/// (TCOD/TCDO) run [`convert_timecode`] (RIFF.pm:949/955). `$val` is the
/// post-ValueConv f64; Perl interpolates it via `%.15g` (its default NV
/// stringification), matched by [`crate::value::format_g`].
#[cfg(feature = "alloc")]
fn print_conv_f64_string(name: &str, val: f64) -> Option<String> {
  match name {
    "Length" => Some(std::format!("{} s", crate::value::format_g(val, 15))),
    "StartTimecode" | "EndTimecode" => Some(convert_timecode(val)),
    _ => None,
  }
}

/// `STAT` Statistics list-PrintConv (RIFF.pm:977-982). ExifTool splits the
/// value with `split ' ', $value` (ExifTool.pm:3553, awk-split: runs of
/// whitespace collapsed, leading/trailing stripped), renders element `i` with
/// the `i`-th PrintConv slot, and joins the rendered parts with `"; "` (the
/// `$convType eq 'PrintConv' ? '; ' : ' '` join, ExifTool.pm:3697).
#[cfg(feature = "alloc")]
fn stat_print_conv(val: &str) -> String {
  let parts: Vec<&str> = val.split_whitespace().collect();
  let mut out: Vec<String> = Vec::with_capacity(parts.len());
  for (i, p) in parts.iter().enumerate() {
    let rendered = match i {
      0 => std::format!("{p} frames captured"),
      1 => std::format!("{p} dropped"),
      2 => std::format!("Data rate {p}"),
      3 => match *p {
        // `{ 0 => 'Bad', 1 => 'OK' }` — a hash PrintConv. An unmatched value
        // passes through unchanged (default hash-miss behavior, no `-U` here:
        // ExifTool emits the raw value for an unlisted key).
        "0" => "Bad".to_string(),
        "1" => "OK".to_string(),
        other => other.to_string(),
      },
      // Beyond the 4 list slots: passthrough (Perl emits extra values raw).
      _ => (*p).to_string(),
    };
    out.push(rendered);
  }
  out.join("; ")
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

/// `%audioEncoding` (RIFF.pm:90-335) — the FULL "TwoCC" audio-encoding
/// PrintConv table, transcribed verbatim (codes + names) from bundled. An
/// unrecognized code renders as `Unknown (0xNN)`, faithful to ExifTool's
/// default hash-PrintConv miss handling (verified vs bundled: `0x9999` →
/// `"Unknown (0x9999)"`). The lookup is a closed `match` over `'static`
/// literals (no allocation for the matched arm — the caller owns the
/// `to_string`; the `Unknown` arm is the only formatting path).
#[cfg(feature = "alloc")]
fn audio_encoding_label(val: u32) -> String {
  // RIFF.pm:92-334. Every entry below is byte-for-byte the bundled name.
  let s: &'static str = match val {
    0x01 => "Microsoft PCM",
    0x02 => "Microsoft ADPCM",
    0x03 => "Microsoft IEEE float",
    0x04 => "Compaq VSELP",
    0x05 => "IBM CVSD",
    0x06 => "Microsoft a-Law",
    0x07 => "Microsoft u-Law",
    0x08 => "Microsoft DTS",
    0x09 => "DRM",
    0x0a => "WMA 9 Speech",
    0x0b => "Microsoft Windows Media RT Voice",
    0x10 => "OKI-ADPCM",
    0x11 => "Intel IMA/DVI-ADPCM",
    0x12 => "Videologic Mediaspace ADPCM",
    0x13 => "Sierra ADPCM",
    0x14 => "Antex G.723 ADPCM",
    0x15 => "DSP Solutions DIGISTD",
    0x16 => "DSP Solutions DIGIFIX",
    0x17 => "Dialoic OKI ADPCM",
    0x18 => "Media Vision ADPCM",
    0x19 => "HP CU",
    0x1a => "HP Dynamic Voice",
    0x20 => "Yamaha ADPCM",
    0x21 => "SONARC Speech Compression",
    0x22 => "DSP Group True Speech",
    0x23 => "Echo Speech Corp.",
    0x24 => "Virtual Music Audiofile AF36",
    0x25 => "Audio Processing Tech.",
    0x26 => "Virtual Music Audiofile AF10",
    0x27 => "Aculab Prosody 1612",
    0x28 => "Merging Tech. LRC",
    0x30 => "Dolby AC2",
    0x31 => "Microsoft GSM610",
    0x32 => "MSN Audio",
    0x33 => "Antex ADPCME",
    0x34 => "Control Resources VQLPC",
    0x35 => "DSP Solutions DIGIREAL",
    0x36 => "DSP Solutions DIGIADPCM",
    0x37 => "Control Resources CR10",
    0x38 => "Natural MicroSystems VBX ADPCM",
    0x39 => "Crystal Semiconductor IMA ADPCM",
    0x3a => "Echo Speech ECHOSC3",
    0x3b => "Rockwell ADPCM",
    0x3c => "Rockwell DIGITALK",
    0x3d => "Xebec Multimedia",
    0x40 => "Antex G.721 ADPCM",
    0x41 => "Antex G.728 CELP",
    0x42 => "Microsoft MSG723",
    0x43 => "IBM AVC ADPCM",
    0x45 => "ITU-T G.726",
    0x50 => "Microsoft MPEG",
    0x51 => "RT23 or PAC",
    0x52 => "InSoft RT24",
    0x53 => "InSoft PAC",
    0x55 => "MP3",
    0x59 => "Cirrus",
    0x60 => "Cirrus Logic",
    0x61 => "ESS Tech. PCM",
    0x62 => "Voxware Inc.",
    0x63 => "Canopus ATRAC",
    0x64 => "APICOM G.726 ADPCM",
    0x65 => "APICOM G.722 ADPCM",
    0x66 => "Microsoft DSAT",
    0x67 => "Microsoft DSAT DISPLAY",
    0x69 => "Voxware Byte Aligned",
    0x70 => "Voxware AC8",
    0x71 => "Voxware AC10",
    0x72 => "Voxware AC16",
    0x73 => "Voxware AC20",
    0x74 => "Voxware MetaVoice",
    0x75 => "Voxware MetaSound",
    0x76 => "Voxware RT29HW",
    0x77 => "Voxware VR12",
    0x78 => "Voxware VR18",
    0x79 => "Voxware TQ40",
    0x7a => "Voxware SC3",
    0x7b => "Voxware SC3",
    0x80 => "Soundsoft",
    0x81 => "Voxware TQ60",
    0x82 => "Microsoft MSRT24",
    0x83 => "AT&T G.729A",
    0x84 => "Motion Pixels MVI MV12",
    0x85 => "DataFusion G.726",
    0x86 => "DataFusion GSM610",
    0x88 => "Iterated Systems Audio",
    0x89 => "Onlive",
    0x8a => "Multitude, Inc. FT SX20",
    0x8b => "Infocom ITS A/S G.721 ADPCM",
    0x8c => "Convedia G729",
    0x8d => "Not specified congruency, Inc.",
    0x91 => "Siemens SBC24",
    0x92 => "Sonic Foundry Dolby AC3 APDIF",
    0x93 => "MediaSonic G.723",
    0x94 => "Aculab Prosody 8kbps",
    0x97 => "ZyXEL ADPCM",
    0x98 => "Philips LPCBB",
    0x99 => "Studer Professional Audio Packed",
    0xa0 => "Malden PhonyTalk",
    0xa1 => "Racal Recorder GSM",
    0xa2 => "Racal Recorder G720.a",
    0xa3 => "Racal G723.1",
    0xa4 => "Racal Tetra ACELP",
    0xb0 => "NEC AAC NEC Corporation",
    0xff => "AAC",
    0x100 => "Rhetorex ADPCM",
    0x101 => "IBM u-Law",
    0x102 => "IBM a-Law",
    0x103 => "IBM ADPCM",
    0x111 => "Vivo G.723",
    0x112 => "Vivo Siren",
    0x120 => "Philips Speech Processing CELP",
    0x121 => "Philips Speech Processing GRUNDIG",
    0x123 => "Digital G.723",
    0x125 => "Sanyo LD ADPCM",
    0x130 => "Sipro Lab ACEPLNET",
    0x131 => "Sipro Lab ACELP4800",
    0x132 => "Sipro Lab ACELP8V3",
    0x133 => "Sipro Lab G.729",
    0x134 => "Sipro Lab G.729A",
    0x135 => "Sipro Lab Kelvin",
    0x136 => "VoiceAge AMR",
    0x140 => "Dictaphone G.726 ADPCM",
    0x150 => "Qualcomm PureVoice",
    0x151 => "Qualcomm HalfRate",
    0x155 => "Ring Zero Systems TUBGSM",
    0x160 => "Microsoft Audio1",
    0x161 => "Windows Media Audio V2 V7 V8 V9 / DivX audio (WMA) / Alex AC3 Audio",
    0x162 => "Windows Media Audio Professional V9",
    0x163 => "Windows Media Audio Lossless V9",
    0x164 => "WMA Pro over S/PDIF",
    0x170 => "UNISYS NAP ADPCM",
    0x171 => "UNISYS NAP ULAW",
    0x172 => "UNISYS NAP ALAW",
    0x173 => "UNISYS NAP 16K",
    0x174 => "MM SYCOM ACM SYC008 SyCom Technologies",
    0x175 => "MM SYCOM ACM SYC701 G726L SyCom Technologies",
    0x176 => "MM SYCOM ACM SYC701 CELP54 SyCom Technologies",
    0x177 => "MM SYCOM ACM SYC701 CELP68 SyCom Technologies",
    0x178 => "Knowledge Adventure ADPCM",
    0x180 => "Fraunhofer IIS MPEG2AAC",
    0x190 => "Digital Theater Systems DTS DS",
    0x200 => "Creative Labs ADPCM",
    0x202 => "Creative Labs FASTSPEECH8",
    0x203 => "Creative Labs FASTSPEECH10",
    0x210 => "UHER ADPCM",
    0x215 => "Ulead DV ACM",
    0x216 => "Ulead DV ACM",
    0x220 => "Quarterdeck Corp.",
    0x230 => "I-Link VC",
    0x240 => "Aureal Semiconductor Raw Sport",
    0x241 => "ESST AC3",
    0x250 => "Interactive Products HSX",
    0x251 => "Interactive Products RPELP",
    0x260 => "Consistent CS2",
    0x270 => "Sony SCX",
    0x271 => "Sony SCY",
    0x272 => "Sony ATRAC3",
    0x273 => "Sony SPC",
    0x280 => "TELUM Telum Inc.",
    0x281 => "TELUMIA Telum Inc.",
    0x285 => "Norcom Voice Systems ADPCM",
    0x300 => "Fujitsu FM TOWNS SND",
    0x301 => "Fujitsu (not specified)",
    0x302 => "Fujitsu (not specified)",
    0x303 => "Fujitsu (not specified)",
    0x304 => "Fujitsu (not specified)",
    0x305 => "Fujitsu (not specified)",
    0x306 => "Fujitsu (not specified)",
    0x307 => "Fujitsu (not specified)",
    0x308 => "Fujitsu (not specified)",
    0x350 => "Micronas Semiconductors, Inc. Development",
    0x351 => "Micronas Semiconductors, Inc. CELP833",
    0x400 => "Brooktree Digital",
    0x401 => "Intel Music Coder (IMC)",
    0x402 => "Ligos Indeo Audio",
    0x450 => "QDesign Music",
    0x500 => "On2 VP7 On2 Technologies",
    0x501 => "On2 VP6 On2 Technologies",
    0x680 => "AT&T VME VMPCM",
    0x681 => "AT&T TCP",
    0x700 => "YMPEG Alpha (dummy for MPEG-2 compressor)",
    0x8ae => "ClearJump LiteWave (lossless)",
    0x1000 => "Olivetti GSM",
    0x1001 => "Olivetti ADPCM",
    0x1002 => "Olivetti CELP",
    0x1003 => "Olivetti SBC",
    0x1004 => "Olivetti OPR",
    0x1100 => "Lernout & Hauspie",
    0x1101 => "Lernout & Hauspie CELP codec",
    0x1102 => "Lernout & Hauspie SBC codec",
    0x1103 => "Lernout & Hauspie SBC codec",
    0x1104 => "Lernout & Hauspie SBC codec",
    0x1400 => "Norris Comm. Inc.",
    0x1401 => "ISIAudio",
    0x1500 => "AT&T Soundspace Music Compression",
    0x181c => "VoxWare RT24 speech codec",
    0x181e => "Lucent elemedia AX24000P Music codec",
    0x1971 => "Sonic Foundry LOSSLESS",
    0x1979 => "Innings Telecom Inc. ADPCM",
    0x1c07 => "Lucent SX8300P speech codec",
    0x1c0c => "Lucent SX5363S G.723 compliant codec",
    0x1f03 => "CUseeMe DigiTalk (ex-Rocwell)",
    0x1fc4 => "NCT Soft ALF2CD ACM",
    0x2000 => "FAST Multimedia DVM",
    0x2001 => "Dolby DTS (Digital Theater System)",
    0x2002 => "RealAudio 1 / 2 14.4",
    0x2003 => "RealAudio 1 / 2 28.8",
    0x2004 => "RealAudio G2 / 8 Cook (low bitrate)",
    0x2005 => "RealAudio 3 / 4 / 5 Music (DNET)",
    0x2006 => "RealAudio 10 AAC (RAAC)",
    0x2007 => "RealAudio 10 AAC+ (RACP)",
    0x2500 => "Reserved range to 0x2600 Microsoft",
    0x3313 => "makeAVIS (ffvfw fake AVI sound from AviSynth scripts)",
    0x4143 => "Divio MPEG-4 AAC audio",
    0x4201 => "Nokia adaptive multirate",
    0x4243 => "Divio G726 Divio, Inc.",
    0x434c => "LEAD Speech",
    0x564c => "LEAD Vorbis",
    0x5756 => "WavPack Audio",
    0x674f => "Ogg Vorbis (mode 1)",
    0x6750 => "Ogg Vorbis (mode 2)",
    0x6751 => "Ogg Vorbis (mode 3)",
    0x676f => "Ogg Vorbis (mode 1+)",
    0x6770 => "Ogg Vorbis (mode 2+)",
    0x6771 => "Ogg Vorbis (mode 3+)",
    0x7000 => "3COM NBX 3Com Corporation",
    0x706d => "FAAD AAC",
    0x7a21 => "GSM-AMR (CBR, no SID)",
    0x7a22 => "GSM-AMR (VBR, including SID)",
    0xa100 => "Comverse Infosys Ltd. G723 1",
    0xa101 => "Comverse Infosys Ltd. AVQSBC",
    0xa102 => "Comverse Infosys Ltd. OLDSBC",
    0xa103 => "Symbol Technologies G729A",
    0xa104 => "VoiceAge AMR WB VoiceAge Corporation",
    0xa105 => "Ingenient Technologies Inc. G726",
    0xa106 => "ISO/MPEG-4 advanced audio Coding",
    0xa107 => "Encore Software Ltd G726",
    0xa109 => "Speex ACM Codec xiph.org",
    0xdfac => "DebugMode SonicFoundry Vegas FrameServer ACM Codec",
    0xe708 => "Unknown -",
    0xf1ac => "Free Lossless Audio Codec FLAC",
    0xfffe => "Extensible",
    0xffff => "Development",
    other => return std::format!("Unknown (0x{other:x})"),
  };
  s.to_string()
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
// §9. Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  /// Whether the terminal `Error reading RIFF file (corrupted?)` warning
  /// (RIFF.pm:2216) is present in the Meta's
  /// [`Diagnose`](crate::diagnostics::Diagnose) stream — the test read-back
  /// that replaced the retired `is_corrupted()` accessor.
  fn corrupted_warned(meta: &RiffMeta<'_>) -> bool {
    crate::diagnostics::Diagnose::diagnostics(meta)
      .iter()
      .any(|d| d.message() == "Error reading RIFF file (corrupted?)")
  }

  /// The `Some(code_page)` carried by the `Unsupported character set (<N>)`
  /// warning (ExifTool.pm:6359-6363), parsed back out of the Meta's
  /// [`Diagnose`](crate::diagnostics::Diagnose) stream — the test read-back
  /// that replaced the retired `unsupported_charset() -> Option<u16>` accessor.
  /// `None` when no such warning was raised.
  fn charset_warn_code(meta: &RiffMeta<'_>) -> Option<u16> {
    crate::diagnostics::Diagnose::diagnostics(meta)
      .iter()
      .find_map(|d| {
        d.message()
          .strip_prefix("Unsupported character set (")
          .and_then(|rest| rest.strip_suffix(')'))
          .and_then(|n| n.parse::<u16>().ok())
      })
  }

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
    let meta = parse_borrowed(&bytes).expect("some");
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
    assert!(parse_borrowed(b"NOPE\0\0\0\0WAVE").is_none());
    assert!(parse_borrowed(b"").is_none());
    assert!(parse_borrowed(b"RIFF").is_none()); // < 12 bytes
  }

  #[test]
  fn accepts_rf64() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"RF64");
    bytes.extend_from_slice(&8u32.to_le_bytes());
    bytes.extend_from_slice(b"WAVE");
    let meta = parse_borrowed(&bytes).expect("some");
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
    let meta = parse_borrowed(&bytes).expect("some");
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
    let meta = parse_borrowed(&bytes).expect("some");
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

    let meta = parse_borrowed(&bytes).expect("some");
    let names: Vec<_> = meta
      .entries()
      .iter()
      .map(|e| e.name().to_string())
      .collect();
    assert!(names.contains(&"Title".to_string())); // INAM
    assert!(names.contains(&"Software".to_string())); // ISFT
  }

  #[test]
  fn audio_encoding_full_table_spot_checks() {
    // Codes OUTSIDE the previous partial table (RIFF.pm:90-335).
    assert_eq!(audio_encoding_label(0xfffe), "Extensible"); // :333
    assert_eq!(audio_encoding_label(0xffff), "Development"); // :334
    assert_eq!(audio_encoding_label(0x2000), "FAST Multimedia DVM"); // :295
    assert_eq!(audio_encoding_label(0x5756), "WavPack Audio"); // :310
    assert_eq!(
      audio_encoding_label(0xf1ac),
      "Free Lossless Audio Codec FLAC"
    ); // :332
    assert_eq!(audio_encoding_label(0x0a), "WMA 9 Speech"); // :101
    // Still-correct partial-table entries.
    assert_eq!(audio_encoding_label(0x01), "Microsoft PCM");
    assert_eq!(audio_encoding_label(0x55), "MP3");
    // Unknown code → default hash-PrintConv miss rendering.
    assert_eq!(audio_encoding_label(0x9999), "Unknown (0x9999)");
  }

  #[test]
  fn isft_value_conv_casio_embedded_null() {
    // RIFF.pm:873 — Casio "EXILIM\0CASIO" → "EXILIM, CASIO".
    assert_eq!(isft_value_conv("EXILIM\u{0}CASIO"), "EXILIM, CASIO");
    // No NULs → unchanged.
    assert_eq!(isft_value_conv("CanonMVI01"), "CanonMVI01");
    // Trailing `\s*\0` run stripped (`s/(\s*\0)+$//`).
    assert_eq!(isft_value_conv("Foo \u{0} \u{0}"), "Foo");
    // First embedded `\s*\0` → ", " (leading whitespace absorbed), remaining
    // NULs dropped (`s/\0+//g`).
    assert_eq!(isft_value_conv("A \u{0}B\u{0}C"), "A, BC");
  }

  #[test]
  fn info_latin_cp1252_decode() {
    // RIFF.pm:1788/1829 — default charset is 'Latin' (cp1252). An INFO IART
    // with high bytes 0xe9/0x80 decodes to "Café €", NOT UTF-8-lossy.
    let mut buf = Vec::new();
    buf.extend_from_slice(b"RIFF");
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(b"WAVE");
    let iart = b"Caf\xe9 \x80\x00";
    let mut info = Vec::new();
    info.extend_from_slice(b"INFO");
    info.extend_from_slice(b"IART");
    info.extend_from_slice(&(iart.len() as u32).to_le_bytes());
    info.extend_from_slice(iart);
    buf.extend_from_slice(b"LIST");
    buf.extend_from_slice(&(info.len() as u32).to_le_bytes());
    buf.extend_from_slice(&info);
    let outer = (buf.len() - 8) as u32;
    buf[4..8].copy_from_slice(&outer.to_le_bytes());

    let meta = parse_borrowed(&buf).expect("some");
    let artist = meta
      .entries()
      .iter()
      .find(|e| e.name() == "Artist")
      .and_then(|e| match e.value_ref() {
        RiffValue::Str(s) => Some(s.as_str()),
        _ => None,
      })
      .expect("Artist");
    assert_eq!(artist, "Caf\u{00e9} \u{20ac}");
  }

  #[test]
  fn cset_chunk_switches_to_raw_passthrough() {
    // RIFF.pm:533/1786 — a CSET chunk sets a NUMERIC CodePage; `%csType` is
    // keyed by NAME, so the lookup misses ⇒ raw passthrough (no cp1252 remap).
    // A 0x80 byte stays raw, rendered as `?` by ExifTool's JSON FixUTF8 (NOT
    // U+FFFD, NOT the cp1252 € it would be under the default 'Latin' charset).
    let mut buf = Vec::new();
    buf.extend_from_slice(b"RIFF");
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(b"WAVE");
    // CSET: int16u CodePage=1252, CountryCode=1, LanguageCode=9, Dialect=1.
    buf.extend_from_slice(b"CSET");
    buf.extend_from_slice(&8u32.to_le_bytes());
    buf.extend_from_slice(&1252u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&9u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    let iart = b"x\x80\x00"; // odd len 3 → needs a pad byte
    let mut info = Vec::new();
    info.extend_from_slice(b"INFO");
    info.extend_from_slice(b"IART");
    info.extend_from_slice(&(iart.len() as u32).to_le_bytes());
    info.extend_from_slice(iart);
    info.push(0); // pad (odd payload)
    buf.extend_from_slice(b"LIST");
    buf.extend_from_slice(&(info.len() as u32).to_le_bytes());
    buf.extend_from_slice(&info);
    let outer = (buf.len() - 8) as u32;
    buf[4..8].copy_from_slice(&outer.to_le_bytes());

    let meta = parse_borrowed(&buf).expect("some");
    let find = |name: &str| -> Option<&RiffValue> {
      meta
        .entries()
        .iter()
        .find(|e| e.name() == name)
        .map(RiffEntry::value_ref)
    };
    // Raw 0x80 is invalid UTF-8 → ASCII `?` (FixUTF8, RIFF.pm raw passthrough).
    match find("Artist") {
      Some(RiffValue::Str(s)) => assert_eq!(s.as_str(), "x?"),
      other => panic!("Artist: {other:?}"),
    }
    // The CSET binary SubDirectory fields (RIFF.pm:1063-1073).
    assert_eq!(find("CodePage"), Some(&RiffValue::U32(1252)));
    assert_eq!(find("CountryCode"), Some(&RiffValue::U32(1)));
    assert_eq!(find("LanguageCode"), Some(&RiffValue::U32(9)));
    assert_eq!(find("Dialect"), Some(&RiffValue::U32(1)));
    // The numeric code page triggers the once `Unsupported character set`
    // warning (ExifTool.pm:6359-6363).
    assert_eq!(charset_warn_code(&meta), Some(1252));
  }

  #[test]
  fn cset_empty_string_does_not_warn() {
    // ExifTool.pm:6349 `length $val` — an all-NUL INFO string (trimmed to
    // empty) is decoded but does NOT trigger the unsupported-charset warning.
    let mut buf = Vec::new();
    buf.extend_from_slice(b"RIFF");
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(b"WAVE");
    buf.extend_from_slice(b"CSET");
    buf.extend_from_slice(&2u32.to_le_bytes());
    buf.extend_from_slice(&1252u16.to_le_bytes());
    let iart = b"\x00\x00"; // all-NUL → trims to empty
    let mut info = Vec::new();
    info.extend_from_slice(b"INFO");
    info.extend_from_slice(b"IART");
    info.extend_from_slice(&(iart.len() as u32).to_le_bytes());
    info.extend_from_slice(iart);
    buf.extend_from_slice(b"LIST");
    buf.extend_from_slice(&(info.len() as u32).to_le_bytes());
    buf.extend_from_slice(&info);
    let outer = (buf.len() - 8) as u32;
    buf[4..8].copy_from_slice(&outer.to_le_bytes());

    let meta = parse_borrowed(&buf).expect("some");
    // Only CodePage emitted (2-byte CSET); empty IART → Artist == "".
    assert_eq!(
      meta
        .entries()
        .iter()
        .find(|e| e.name() == "CodePage")
        .map(RiffEntry::value_ref),
      Some(&RiffValue::U32(1252))
    );
    // No warning: the decoded string was empty (length 0).
    assert_eq!(charset_warn_code(&meta), None);
  }

  #[test]
  fn cset_code_page_zero_falls_back_to_latin() {
    // RIFF.pm:1784-1789 truthiness gate — a CSET `CodePage` of 0 is FALSY, so
    // `if ($$et{CodePage})` is false and the `elsif (defined $charset and
    // $charset eq '0')` branch fires (`CharsetRIFF` defaults to `0`), making
    // `$charset = 'Latin'`. The INFO string is then cp1252-decoded with NO
    // `Unsupported character set` warning — EXACTLY like having no CSET at all.
    // Verified vs bundled 13.59: `CodePage=0` + `IART=Caf\xe9` ⇒
    // `RIFF:Artist="Café"`, NO `ExifTool:Warning` (whereas a non-zero
    // unsupported code page raw-passes + warns — see
    // `cset_chunk_switches_to_raw_passthrough`).
    let mut buf = Vec::new();
    buf.extend_from_slice(b"RIFF");
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(b"WAVE");
    // CSET: int16u CodePage=0, CountryCode=1, LanguageCode=9, Dialect=1.
    buf.extend_from_slice(b"CSET");
    buf.extend_from_slice(&8u32.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&9u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    let iart = b"Caf\xe9"; // cp1252 'é' (0xe9) — odd len 4 → no pad
    let mut info = Vec::new();
    info.extend_from_slice(b"INFO");
    info.extend_from_slice(b"IART");
    info.extend_from_slice(&(iart.len() as u32).to_le_bytes());
    info.extend_from_slice(iart);
    buf.extend_from_slice(b"LIST");
    buf.extend_from_slice(&(info.len() as u32).to_le_bytes());
    buf.extend_from_slice(&info);
    let outer = (buf.len() - 8) as u32;
    buf[4..8].copy_from_slice(&outer.to_le_bytes());

    let meta = parse_borrowed(&buf).expect("some");
    let find = |name: &str| -> Option<&RiffValue> {
      meta
        .entries()
        .iter()
        .find(|e| e.name() == name)
        .map(RiffEntry::value_ref)
    };
    // CodePage=0 IS emitted as a tag (the int16u SubDirectory field).
    assert_eq!(find("CodePage"), Some(&RiffValue::U32(0)));
    // 0xe9 decodes through cp1252 ('Latin') to 'é' (U+00E9) — NOT the raw `?`
    // a numeric code page would produce.
    match find("Artist") {
      Some(RiffValue::Str(s)) => assert_eq!(s.as_str(), "Caf\u{00e9}"),
      other => panic!("Artist: {other:?}"),
    }
    // NO unsupported-charset warning: 0 fell back to the supported 'Latin'.
    assert_eq!(charset_warn_code(&meta), None);
  }

  #[test]
  fn repeated_cset_code_page_zero_resets_prior_raw_to_latin() {
    // RIFF.pm:1067-1069 — the `CodePage` RawConv (`$$self{CodePage} = $val`)
    // overwrites `$$self{CodePage}` on EVERY CSET, and the truthiness gate
    // (RIFF.pm:1784-1789) resolves the LATEST value. So a `CodePage=1252`
    // followed by a `CodePage=0` ends up Latin: the trailing 0 RESETS the
    // prior `Raw(1252)`. Verified vs bundled 13.59 (`CSET 1252` → `CSET 0` →
    // `IART=Caf\xe9`): `RIFF:CodePage=0`, `RIFF:Artist="Café"`, NO
    // `ExifTool:Warning`. The pre-R4 code only assigned on the non-zero CSET,
    // so it stayed `Raw(1252)` → `Caf?` + a spurious unsupported-charset warn.
    let mut buf = Vec::new();
    buf.extend_from_slice(b"RIFF");
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(b"WAVE");
    // First CSET: CodePage=1252 (would set Raw(1252)).
    buf.extend_from_slice(b"CSET");
    buf.extend_from_slice(&8u32.to_le_bytes());
    buf.extend_from_slice(&1252u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&9u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    // Second CSET: CodePage=0 (resets back to Latin).
    buf.extend_from_slice(b"CSET");
    buf.extend_from_slice(&8u32.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&9u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    let iart = b"Caf\xe9"; // cp1252 'é' (0xe9) — even len 4 → no pad
    let mut info = Vec::new();
    info.extend_from_slice(b"INFO");
    info.extend_from_slice(b"IART");
    info.extend_from_slice(&(iart.len() as u32).to_le_bytes());
    info.extend_from_slice(iart);
    buf.extend_from_slice(b"LIST");
    buf.extend_from_slice(&(info.len() as u32).to_le_bytes());
    buf.extend_from_slice(&info);
    let outer = (buf.len() - 8) as u32;
    buf[4..8].copy_from_slice(&outer.to_le_bytes());

    // Drive the walker directly to inspect the resolved active charset: the
    // SECOND CSET (`CodePage=0`) must leave it `Charset::Latin`, not the
    // `Charset::Raw(1252)` the first CSET set.
    let mut walker = Walker {
      data: &buf,
      pos: 12,
      entries: Vec::new(),
      streams: Vec::new(),
      current_stream_type: None,
      charset: Charset::Latin,
      unsupported_charset: None,
      err: false,
    };
    walker.walk_top();
    assert_eq!(
      walker.charset,
      Charset::Latin,
      "the trailing CodePage=0 CSET must reset the active charset to Latin"
    );
    assert_eq!(
      walker.charset.unsupported_code_page(),
      None,
      "Latin is a supported charset (no unsupported-charset code page)"
    );

    // End-to-end: the INFO IART decodes through cp1252 (Latin), and there is
    // NO unsupported-charset warning (the Raw(1252) was reset).
    let meta = parse_borrowed(&buf).expect("some");
    let find = |name: &str| -> Option<&RiffValue> {
      meta
        .entries()
        .iter()
        .find(|e| e.name() == name)
        .map(RiffEntry::value_ref)
    };
    // Both CSETs emit a `CodePage` entry (faithful to bundled's per-CSET
    // ProcessBinaryData); the engine's TagMap dedup keeps the LAST (0) — see
    // the `RIFF_cset_reset_info.wav` golden (`RIFF:CodePage=0`). Assert the
    // last-wins value here.
    let last_code_page = meta
      .entries()
      .iter()
      .rev()
      .find(|e| e.name() == "CodePage")
      .map(RiffEntry::value_ref);
    assert_eq!(last_code_page, Some(&RiffValue::U32(0)));
    // 0xe9 decodes through cp1252 ('Latin') to 'é' — NOT the raw `?` a numeric
    // code page would produce.
    match find("Artist") {
      Some(RiffValue::Str(s)) => assert_eq!(s.as_str(), "Caf\u{00e9}"),
      other => panic!("Artist: {other:?}"),
    }
    // No spurious warning — the prior Raw(1252) was reset by the CodePage=0.
    assert_eq!(charset_warn_code(&meta), None);
  }

  #[test]
  fn info_level_idit_converts_riff_date() {
    // RIFF.pm:1002-1008 — an INFO-level `IDIT` runs through `ConvertRIFFDate`.
    let mut buf = Vec::new();
    buf.extend_from_slice(b"RIFF");
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(b"WAVE");
    let idit = b"Mon Mar 10 15:04:43 2003\x00";
    let mut info = Vec::new();
    info.extend_from_slice(b"INFO");
    info.extend_from_slice(b"IDIT");
    info.extend_from_slice(&(idit.len() as u32).to_le_bytes());
    info.extend_from_slice(idit);
    buf.extend_from_slice(b"LIST");
    buf.extend_from_slice(&(info.len() as u32).to_le_bytes());
    buf.extend_from_slice(&info);
    let outer = (buf.len() - 8) as u32;
    buf[4..8].copy_from_slice(&outer.to_le_bytes());

    let meta = parse_borrowed(&buf).expect("some");
    match meta
      .entries()
      .iter()
      .find(|e| e.name() == "DateTimeOriginal")
      .map(RiffEntry::value_ref)
    {
      Some(RiffValue::Str(s)) => assert_eq!(s.as_str(), "2003:03:10 15:04:43"),
      other => panic!("DateTimeOriginal: {other:?}"),
    }
  }

  #[test]
  fn dtim_value_conv_drops_non_pair_and_passes_kodak_string() {
    // RIFF.pm:990 `return undef unless @v == 2` — a single token drops.
    assert_eq!(dtim_value_conv("123456"), None);
    // RIFF.pm:992 — a pre-formatted Kodak string passes through verbatim.
    assert_eq!(
      dtim_value_conv("2021:06:15 12:30:45").as_deref(),
      Some("2021:06:15 12:30:45")
    );
    // Not the Kodak shape (wrong separators) but two tokens → FILETIME math.
    // `0 0` ⇒ secs 0 ⇒ ConvertUnixTime(0) ⇒ the 0000 sentinel.
    assert_eq!(
      dtim_value_conv("0 0").as_deref(),
      Some("0000:00:00 00:00:00")
    );
  }

  #[test]
  fn convert_timecode_matches_bundled() {
    // RIFF.pm:1625-1638. `36050000000 * 1e-7 = 3605` ⇒ "1:00:05.00".
    assert_eq!(convert_timecode(3605.0), "1:00:05.00");
    // `15500000 * 1e-7 = 1.55` ⇒ "0:00:01.55".
    assert_eq!(convert_timecode(1.55), "0:00:01.55");
    // Round-off guard: 59.999 → "%05.2f" rounds to "60.00" ⇒ carry to 1:00.
    assert_eq!(convert_timecode(59.999), "0:01:00.00");
    // Zero.
    assert_eq!(convert_timecode(0.0), "0:00:00.00");
  }

  #[test]
  fn stat_print_conv_list() {
    // RIFF.pm:977-982 — the Sony Vegas list PrintConv, joined with "; ".
    assert_eq!(
      stat_print_conv("7318 0 3.430307 1"),
      "7318 frames captured; 0 dropped; Data rate 3.430307; OK"
    );
    // capture flag 0 ⇒ "Bad".
    assert_eq!(
      stat_print_conv("0 5 1234.5 0"),
      "0 frames captured; 5 dropped; Data rate 1234.5; Bad"
    );
    // An unlisted capture flag passes through; extra values pass through raw.
    assert_eq!(
      stat_print_conv("1 2 3 9 extra"),
      "1 frames captured; 2 dropped; Data rate 3; 9; extra"
    );
  }

  #[test]
  fn truncated_known_chunk_skipped_and_marks_corrupted() {
    // RIFF.pm:2150/2216 — a `fmt ` declaring 16 bytes but with only 12 present
    // is NOT dispatched (no Encoding/etc. tags) and sets the corruption flag.
    let mut buf = Vec::new();
    buf.extend_from_slice(b"RIFF");
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(b"WAVE");
    buf.extend_from_slice(b"fmt ");
    buf.extend_from_slice(&16u32.to_le_bytes()); // declares 16
    buf.extend_from_slice(&1u16.to_le_bytes()); // Encoding (only 12 bytes follow)
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(&44100u32.to_le_bytes());
    buf.extend_from_slice(&176_400u32.to_le_bytes());
    let outer = (buf.len() - 8) as u32;
    buf[4..8].copy_from_slice(&outer.to_le_bytes());

    let meta = parse_borrowed(&buf).expect("some");
    assert!(corrupted_warned(&meta), "truncated fmt must mark corrupted");
    assert!(
      meta.entries().iter().all(|e| e.name() != "Encoding"),
      "truncated fmt must NOT emit partial-payload tags"
    );
  }

  #[test]
  fn full_chunk_at_eof_not_marked_corrupted() {
    // A `fmt ` whose declared length is exactly satisfied at EOF must parse
    // (no false-positive corruption flag).
    let mut buf = Vec::new();
    buf.extend_from_slice(b"RIFF");
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(b"WAVE");
    buf.extend_from_slice(b"fmt ");
    buf.extend_from_slice(&16u32.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes()); // Encoding=PCM
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&8000u32.to_le_bytes());
    buf.extend_from_slice(&8000u32.to_le_bytes());
    buf.extend_from_slice(&[0u8; 2]);
    buf.extend_from_slice(&8u16.to_le_bytes());
    let outer = (buf.len() - 8) as u32;
    buf[4..8].copy_from_slice(&outer.to_le_bytes());

    let meta = parse_borrowed(&buf).expect("some");
    assert!(!corrupted_warned(&meta));
    assert!(meta.entries().iter().any(|e| e.name() == "Encoding"));
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
