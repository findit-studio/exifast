// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "riff")]
//! Faithful port of `Image::ExifTool::RIFF` (`lib/Image/ExifTool/RIFF.pm`):
//! reads RIFF/RIFX containers — primarily AVI (Audio Video Interleaved) in
//! this port, plus the WEBP chunk tables (VP8X/VP8/VP8L/ALPH dimensions +
//! flags, embedded EXIF/XMP) and the WAV outer walker with minimal interior
//! decoding (see §Deferrals).
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
//! - **WEBP container chunks (PORTED, #153/#160).** `VP8X` (WebP_Flags BITMASK
//!   + 24-bit canvas dims + the `Extended WEBP` `OverrideFileType`,
//!   RIFF.pm:2106), `VP8 ` (lossy VP8Version + dims + scales), `VP8L`
//!   (lossless dims + AlphaIsUsed + the `(lossless)` FileType suffix), and
//!   `ALPH` (RIFF.pm:1279-1497) emit their `RIFF:*` tags; the embedded
//!   `EXIF`/`Exif` chunk re-walks through the shared `ProcessTIFF` IFD parser
//!   ([`crate::exif::parse_exif_block`]) and the `XMP `/`XMP\0` chunk through
//!   the ported XMP module ([`crate::formats::xmp::parse_borrowed`]) — the same
//!   container→EXIF/XMP seam PNG's `eXIf`/raw-profile path uses. Still deferred:
//!   `ANIM`/`ANMF` (animation Duration), and the `ICCP` ICC-profile decode
//!   (exifast has no ported `ICC_Profile` module — the same color-management
//!   deferral PNG `iCCP` / JPEG `APP2` ICC carry; the profile is captured-but-
//!   not-decoded).
//! - **OpenDML extras.** Only `dmlh` `TotalFrameCount` (RIFF.pm:1156-1158)
//!   is emitted; the broader OpenDML 2.0 index extensions (`indx`/`ix##`)
//!   are not parsed.
//! - **AVI 2.0 / concatenated RIFFs.** The `RIFF`-mid-stream re-trigger
//!   (RIFF.pm:2173-2181) skips ahead but never increments `DOC_NUM` here
//!   (we only emit one stream's worth; sub-document handling is a
//!   forward item, exifast-phase2-forward-items.md).
//! - **Vendor JUNK variants (PARTIALLY PORTED, #154).** The `%Main` `JUNK`
//!   Condition list (RIFF.pm:442-492) is dispatched in [`Walker::dispatch_junk`].
//!   PORTED: `PentaxJunk` (`^IIII\x01\0` → `%Pentax::Junk`, one `Model`
//!   `string[32]`) + `PentaxJunk2` (`^PENTDigital Camera` → `%Pentax::Junk2`,
//!   Make/Model/FNumber/DateTime1/DateTime2 + thumbnail dims) — both emit under
//!   `MakerNotes:Pentax:*`; and `TextJunk` (the ASCII-only RawConv fallback →
//!   `RIFF:TextJunk`). Still DEFERRED (vendor subsystems / need a real sample):
//!   `OlympusJunk` (`%Olympus::AVI` — a 332-entry `%olympusCameraTypes`
//!   PrintConv + `ThumbInfo` SubDirectory), `CasioJunk` (`%Exif::Main` IFD0
//!   `Start=>10`/BigEndian — the embedded-EXIF offset/Base mechanics need a real
//!   Casio EX-S600 AVI), `RicohJunk` (`%Ricoh::AVI` sub-chunk processor + a
//!   `%Ricoh::Main` MakerNote), `LucasJunk` (`%QuickTime::Stream` via
//!   `ProcessLucas`, a timed-metadata subsystem), and the `PentaxJunk2`
//!   `ThumbnailImage` binary leaf (`ValidateImage`). The bundled `RIFF.avi`
//!   fixture has no JUNK chunk, so the ported subset only fires for the crafted
//!   `AVI_textjunk`/`AVI_pentaxjunk`/`AVI_pentaxjunk2` fixtures.
//! - **`LIST_ncdt` / `LIST_hydt` / `LIST_pntx`.** Nikon/Pentax AVI maker
//!   notes; depend on Nikon/Pentax module ports (separate Phase-2 items).
//! - **`strd` StreamData (PARTIALLY PORTED, #158).** The `%RIFF::StreamData`
//!   table (RIFF.pm:1250-1276, `ProcessStreamData` at RIFF.pm:1699-1748) keys
//!   on the `strd` chunk's leading 4-byte tag ID and is dispatched in
//!   [`Walker::dispatch_strd`]. PORTED: `Zora` (`RIFF:VendorName` — the whole
//!   payload, NULs deleted), `CASI` (`%Casio::AVI` `Software` — the whole
//!   payload as a C-string, `Casio.pm:2006-2015`), and the `unknown` fallback
//!   (`RIFF:UnknownData` — the whole payload iff all-printable). Still DEFERRED:
//!   `AVIF` (Canon, RIFF.pm:1257-1265 → `Exif::Main` IFD0 with `Start => 8`,
//!   forced `LittleEndian`) — it re-dispatches a HEADERLESS IFD0 (no TIFF
//!   byte-order/magic header) through `ProcessExif` with the `ProcessStreamData`
//!   `Base`/`DataPos` offset arithmetic (RIFF.pm:1716-1737), a re-dispatch entry
//!   exifast's `exif` module does not yet expose, and the IsOffset/thumbnail
//!   mechanics it carries need a real Canon AVIF to pin byte-exact (the same
//!   embedded-EXIF `Start`/`Base` deferral the `CasioJunk` JUNK variant carries).
//!   The bundled `RIFF.avi`/`Pentax.avi` fixtures have no `strd`, so the ported
//!   subset fires only for the crafted `AVI_strd_{zora,casi,unknown}` fixtures.
//! - **Top-level XMP / SEAL / C2PA / `_PMX` / aXML / iXML** (RIFF.pm:493-
//!   507, 633-637, 670-673). XMP/JUMBF/SEAL are separate Phase-3+ ports.
//! - **BikeBro `SGLT`/`SLLT`** (RIFF.pm:619-632).
//!
//! Filed at: `https://github.com/Findit-AI/exifast/issues` (see issue body
//! cross-linking the corresponding `RIFF.pm:LLLL` for each).

// Golden-v2 Contract 3c (Phase C, slice S2): panic-safety by construction —
// every raw index/slice is converted to a checked `.get()` form below.
#![deny(clippy::indexing_slicing)]

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

/// Append ` (lossless)` to the CURRENT RIFF FileType for a `VP8L` chunk
/// (RIFF.pm:1330-1334 `$$self{VALUE}{FileType} . ' (lossless)'`).
///
/// The base is whatever FileType is current when the `VP8L` chunk is walked:
/// the form-type base (`%riffType`: `WAV`/`AVI`/`WEBP`/`LA`/`OFR`/`PAC`/`WV`,
/// or the inert `RIFF` fallback) OR the `Extended WEBP` a prior `VP8X` set on a
/// WEBP form. The result is kept a `&'static str` (the engine's
/// `ExplicitWithMime`/`ExplicitWithMimeAndExt` finalize requires `'static`) by
/// enumerating the closed set rather than allocating. A non-WEBP base yields
/// e.g. `WAV (lossless)` — matching bundled 13.59 — while the MIME is left
/// unchanged by the caller.
///
/// **Idempotent & preserving** (the append must be applied AT MOST ONCE).
/// ExifTool's RawConv (RIFF.pm:1332) literally appends ` (lossless)` to
/// whatever `FileType` currently holds — but the walker re-runs this for EVERY
/// valid `VP8L` chunk, feeding back the PREVIOUS override. A second `VP8L`
/// therefore sees an already-suffixed `current` (e.g. `WAV (lossless)` /
/// `Extended WEBP (lossless)`). For such an already-lossless input we return it
/// UNCHANGED — never double-appending and never collapsing an unrecognized
/// already-lossless type into `RIFF (lossless)`. The set of reachable `current`
/// values is closed (a `%riffType`/`RIFF` base, an `Extended WEBP` from a prior
/// `VP8X`, or one of this function's own outputs), so the already-lossless
/// states are enumerated explicitly to keep the `&'static str` (no owned
/// `String`/allocation needed).
#[must_use]
const fn vp8l_lossless_file_type(current: &str) -> &'static str {
  match current.as_bytes() {
    b"WEBP" => "WEBP (lossless)",
    b"Extended WEBP" => "Extended WEBP (lossless)",
    b"WAV" => "WAV (lossless)",
    b"AVI" => "AVI (lossless)",
    b"LA" => "LA (lossless)",
    b"OFR" => "OFR (lossless)",
    b"PAC" => "PAC (lossless)",
    b"WV" => "WV (lossless)",
    // Already-lossless inputs (a SECOND walked `VP8L` is fed the prior override)
    // are returned UNCHANGED — the append happens at most once. Enumerated to
    // preserve the exact `&'static str` rather than re-appending or falling
    // through to the `RIFF (lossless)` arm below.
    b"WEBP (lossless)" => "WEBP (lossless)",
    b"Extended WEBP (lossless)" => "Extended WEBP (lossless)",
    b"WAV (lossless)" => "WAV (lossless)",
    b"AVI (lossless)" => "AVI (lossless)",
    b"LA (lossless)" => "LA (lossless)",
    b"OFR (lossless)" => "OFR (lossless)",
    b"PAC (lossless)" => "PAC (lossless)",
    b"WV (lossless)" => "WV (lossless)",
    b"RIFF (lossless)" => "RIFF (lossless)",
    // The inert `RIFF` fallback (an unrecognized form type) and any other
    // not-yet-lossless value append literally once (bundled appends to whatever
    // `FileType` holds).
    _ => "RIFF (lossless)",
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
  /// ExifTool `Priority => N` for this tag's duplicate handling (default `1`).
  /// The WEBP `VP8`/`VP8L` `ImageWidth`/`ImageHeight` are `Priority => 0`
  /// (RIFF.pm:1301/1312/1329/1340), so when an Extended-WEBP `VP8X` already
  /// emitted the canvas `ImageWidth`/`ImageHeight` (priority `1`), the
  /// lossy/lossless bitstream's duplicate NEVER overrides it — ExifTool keeps
  /// the `VP8X` value and demotes the bitstream pair to the `-a`-only
  /// `RIFF:Copy1` (absent from the default `-j`/`-n` output). Threaded to
  /// [`crate::emit::EmittedTag::new_with_priority`] so the shared `TagMap`
  /// dedup reproduces that first-wins exactly.
  priority: u8,
}

impl RiffEntry {
  /// Construct an entry with ExifTool's default duplicate `Priority => 1`.
  /// Internal helper for the walker.
  #[inline]
  fn new(group: &'static str, name: &'static str, value: RiffValue) -> Self {
    Self::new_with_priority(group, name, value, 1)
  }

  /// Construct an entry carrying an explicit ExifTool `Priority => N`
  /// (RIFF.pm `Priority => 0` for the `VP8`/`VP8L` dimension duplicates).
  #[inline]
  fn new_with_priority(
    group: &'static str,
    name: &'static str,
    value: RiffValue,
    priority: u8,
  ) -> Self {
    Self {
      group: SmolStr::new_static(group),
      name: SmolStr::new_static(name),
      value,
      priority,
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

  /// ExifTool `Priority => N` for this tag (default `1`; `0` for the
  /// `VP8`/`VP8L` dimension duplicates that never override a `VP8X` canvas).
  #[must_use]
  #[inline(always)]
  pub const fn priority(&self) -> u8 {
    self.priority
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
  /// A 64-bit unsigned integer. Used by the WAV-specific chunks whose raw
  /// values exceed `u32`: `ds64` `int64u` sizes (RIFF.pm:762-784, rendered
  /// via `ConvertFileSize`), `bext` `TimeReference` (the combined 64-bit
  /// sample count `low + high * 2^32`, RIFF.pm:739-744), and
  /// `NumberOfSamples64` (RIFF.pm:780).
  U64(u64),
  /// A signed integer (rare — image-height can be negative in BMP V3 to
  /// flag top-to-bottom storage; we apply abs(), so the stored value is
  /// non-negative; the `inst` chunk's `int8s` fields, RIFF.pm:824-831).
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

/// One embedded WEBP metadata chunk captured during the walk, in chunk order.
///
/// RIFF.pm dispatches EVERY `EXIF`/`Exif` and `XMP `/`XMP\0` chunk it walks
/// (RIFF.pm:557-587) — to `ProcessTIFF` and `ProcessXMP` respectively — so a
/// file carrying repeated metadata chunks contributes the tags of ALL of them.
/// The payload is a sub-slice BORROWED from the input (zero-copy); it is
/// re-parsed at emit time. The `improper_header` / `incorrect_tag_id` flags
/// drive the per-chunk minor warnings (`$self->Warn(..., 1)`, RIFF.pm:567/585).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebpMetaChunk<'a> {
  /// An `EXIF`/`Exif` chunk — a complete TIFF block (`II*\0`/`MM\0*`), with any
  /// leading `Exif\0\0` header already stripped (RIFF.pm:557-572). `improper`
  /// is `true` for the `Exif\0\0`-prefixed form (the `[minor] Improper EXIF
  /// header` warning, RIFF.pm:567).
  Exif { block: &'a [u8], improper: bool },
  /// An `XMP `/`XMP\0` chunk — a standard XMP packet (RIFF.pm:577-587).
  /// `incorrect_id` is `true` for the non-standard `XMP\0` tag ID (the
  /// `[minor] Incorrect XMP tag ID` warning, RIFF.pm:582-587).
  Xmp {
    packet: &'a [u8],
    incorrect_id: bool,
  },
}

/// Which Pentax `%Main` JUNK SubDirectory matched the `JUNK` chunk's leading
/// signature (RIFF.pm:469-478). Both are `ProcessBinaryData` camera tables
/// emitting under family-0 `MakerNotes`, family-1 `Pentax`
/// (`Pentax.pm:6409-6418` / `:6610-6658`). The matched payload is captured for
/// the emit-time decode (`tags()`), mirroring the `pentax_makernote` re-dispatch
/// — the field offsets/formats are tiny fixed binary-data leaves, so the
/// variant alone selects the right offset map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PentaxJunkVariant {
  /// `PentaxJunk` — Optio RS1000 (`$$valPt =~ /^IIII\x01\0/`,
  /// `%Pentax::Junk`, RIFF.pm:469-473). A single `Model` `string[32]` at 0x0c.
  Junk,
  /// `PentaxJunk2` — Optio RZ18 (`$$valPt =~ /^PENTDigital Camera/`,
  /// `%Pentax::Junk2`, RIFF.pm:474-478). `Make`/`Model`/`FNumber`/`DateTime1`/
  /// `DateTime2` (+ the thumbnail leaves at 0x12b+, captured-but-out-of-range
  /// for a minimal chunk).
  Junk2,
}

/// Which `%RIFF::StreamData` row the `strd` chunk's leading 4-byte tag ID
/// matched (`RIFF.pm:1250-1276`, `ProcessStreamData` at `RIFF.pm:1699-1748`).
/// `ProcessStreamData` keys the table by the first 4 bytes of the chunk
/// (`my $tag = substr($$dataPt, $start, 4)`, `RIFF.pm:1709`); the matched
/// payload is captured for the emit-time decode (`tags()`), mirroring the
/// `pentax_junk_records` re-dispatch. The leaf renderings are tiny fixed string
/// conversions, so the variant alone selects the right one.
///
/// The Canon `AVIF` row (`RIFF.pm:1257-1265` → `Exif::Main` IFD0 with
/// `Start => 8`, forced `LittleEndian`) is NOT a variant here: it re-dispatches
/// a HEADERLESS IFD0 (no TIFF byte-order/magic header) through `ProcessExif`
/// with the `ProcessStreamData` `Base`/`DataPos` offset arithmetic
/// (`RIFF.pm:1716-1737`) — a re-dispatch entry exifast's `exif` module does not
/// yet expose, and the IsOffset/thumbnail mechanics it carries need a real
/// Canon AVIF to pin byte-exact. Deferred (see the module doc + #158).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StrdVariant {
  /// `Zora` — Samsung PL90 AVI (`RIFF.pm:1270` `Zora => 'VendorName'`). A plain
  /// tag (NO `SubDirectory`/`Format`), so `ProcessStreamData` falls into the
  /// `HandleTag` else-branch (`RIFF.pm:1738-1745`) with `Start => $start, Size
  /// => $size` — i.e. the value is the WHOLE `strd` payload (INCLUDING the
  /// 4-byte `Zora` tag ID), run through ExifTool's default string rendering
  /// (`EscapeJSON`'s `tr/\0//d` — DELETE every NUL — then `FixUTF8`). Emits
  /// `RIFF:VendorName` (the table declares only `GROUPS{2}=Video`, so
  /// family-0/1 default to the module name `RIFF`).
  VendorName,
  /// `CASI` — Casio GV-10 AVI (`RIFF.pm:1266-1269` → `%Casio::AVI`,
  /// `Casio.pm:2006-2015`). A `ProcessBinaryData` table with one leaf: offset 0
  /// `Software` `Format => 'string'`. `ProcessStreamData` enters the table at
  /// `DirStart = $start` (no `Start` override ⇒ `$offset = 0`), so offset 0 is
  /// the `CASI` tag ID itself ⇒ `Software` = the WHOLE payload (including
  /// `CASI`) read as a C-string (TRUNCATED at the first NUL, then `FixUTF8`).
  /// Emits `Casio:Software` (family-0 `MakerNotes`, family-1 `Casio`).
  CasioData,
  /// The `unknown` fallback (`RIFF.pm:1271-1275`). `ProcessStreamData` looks up
  /// the `unknown` row when the 4-byte tag ID matches no named row
  /// (`RIFF.pm:1711-1713`); `UnknownData`'s `RawConv =>
  /// '$_=$val; /^[^\0-\x1f\x7f-\xff]+$/ ? $_ : undef'` keeps the value ONLY when
  /// the WHOLE payload (tag ID included) is printable ASCII (0x20-0x7e) with NO
  /// control/high byte and NO trailing NUL (unlike the JUNK `TextJunk` RawConv,
  /// which DOES allow trailing NULs). Emits `RIFF:UnknownData`.
  UnknownData,
}

/// Typed RIFF metadata — the lib-first output of [`ProcessRiff`].
///
/// D8 convention: no public fields; accessors only.
///
/// Holds the ordered emission list of [`RiffEntry`] tags, the per-stream
/// [`RiffStream`] records, the resolved variant (`AVI`/`WAV`/`WEBP`/…), and
/// the MIME the engine will surface via [`FileTypeFinalize::ExplicitWithMime`].
///
/// The Meta owns MOST of its data — RIFF values are heavily transformed during
/// the walk (date conversion, FourCC slicing, PCM/codec-table lookup), so the
/// emitted entries borrow nothing. The one exception is the raw Pentax AVI
/// MakerNote payload AND the embedded WEBP `EXIF`/`XMP ` chunk payloads, each
/// held as a `&'a [u8]` sub-slice of the input (zero-copy; decoded at emit
/// time, #153/#157) — so the `'a` GAT lifetime is a real input borrow rather
/// than the MXF-style phantom.
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
  /// The raw Pentax AVI MakerNote payload (`hymn`/`mknt` sub-chunk of
  /// `LIST_hydt`/`LIST_pntx`, `Pentax.pm:6373-6395`) — a sub-slice BORROWED
  /// from the input (no second allocation; the `'a` input lifetime carries it),
  /// decoded at emit time (when the `-j`/`-n` mode is known) through the shared
  /// `%Pentax::Main` walker, mirroring the Canon CTMD re-dispatch. `None` for a
  /// non-Pentax AVI (#157).
  pentax_makernote: Option<&'a [u8]>,
  /// The embedded WEBP metadata chunks (`EXIF`/`Exif` TIFF blocks and
  /// `XMP `/`XMP\0` packets) in WALK ORDER (RIFF.pm:557-587). ExifTool
  /// dispatches EVERY such chunk occurrence as it walks (each EXIF block to
  /// `ProcessTIFF`, each XMP packet to `ProcessXMP`), so a file with repeated
  /// metadata chunks retains the tags of ALL of them (later chunks last-win
  /// only on a per-tag collision). Each payload is a sub-slice BORROWED from
  /// the input (zero-copy); replayed in this order at emit time through the
  /// shared [`crate::exif::parse_exif_block`] / [`crate::formats::xmp::parse_borrowed`]
  /// seams (the same ones PNG `eXIf`/raw-profile XMP use). Empty for a non-WEBP
  /// RIFF or a WEBP with no metadata chunks.
  webp_meta: Vec<WebpMetaChunk<'a>>,
  /// `true` when a `VP8X` (on a WEBP form) or `VP8L` chunk fired
  /// `OverrideFileType(..., 'webp')` (RIFF.pm:2106 / 1332) — the explicit
  /// `webp` `$normExt`. Drives `File:FileTypeExtension = webp` even for a
  /// non-WEBP base type (e.g. a `WAV (lossless)` from a WAVE+VP8L). A plain
  /// WEBP gets its `webp` extension from the `%fileTypeExt` default, not this
  /// flag.
  webp_ext_override: bool,
  /// The matched Pentax vendor `JUNK` SubDirectories (`PentaxJunk`/`PentaxJunk2`,
  /// RIFF.pm:469-478) and their borrowed payloads, in WALK ORDER. ExifTool
  /// re-runs the matched SubDirectory on EVERY `JUNK` chunk it walks, so a
  /// repeated/mixed `JUNK` retains a record per matched chunk that has at least
  /// one in-range leaf; each payload is a sub-slice BORROWED from the input
  /// (zero-copy), decoded at emit time through the variant's tiny
  /// `ProcessBinaryData` offset map and emitted under family-0 `MakerNotes`,
  /// family-1 `Pentax`. The central `TagMap` resolves duplicates PER LEAF
  /// (last-wins per tag name), so a full `PentaxJunk2` followed by a SHORTER
  /// same-signature one keeps the earlier chunk's `Model`/`FNumber`/`DateTime`
  /// while the later `Make` wins. A signature-only chunk with no in-range leaf is
  /// dropped (it would emit nothing — byte-identical to the full replay, but
  /// bounds the Vec against a crafted tiny-chunk repeat). Empty for a `JUNK` that
  /// matched no vendor signature or the `TextJunk` fallback (#154, #422).
  pentax_junk_records: Vec<(PentaxJunkVariant, &'a [u8])>,
  /// The matched `strd` (StreamData) chunks whose leading 4-byte tag ID hit a
  /// `%RIFF::StreamData` row (`Zora`/`CASI`/the `unknown` fallback —
  /// `RIFF.pm:1250-1276`), in WALK ORDER. ExifTool runs `ProcessStreamData` on
  /// EVERY `strd` it walks (one per `LIST_strl`), so a multi-stream AVI retains
  /// a record per matched `strd` (each rendered under its variant's tag); a
  /// later same-named record is resolved by the normal `TagMap` duplicate rules
  /// at emit (last-wins for these undef-priority tags), not dropped at capture.
  /// Each payload is a sub-slice BORROWED from the input (zero-copy); decoded at
  /// emit time through the variant's tiny fixed string conversion. Empty for a
  /// non-vendor / absent `strd`; a Canon `AVIF` strd is recognized-but-deferred
  /// (see [`StrdVariant`]) so it neither emits nor blocks a later `strd` (#158).
  strd_records: Vec<(StrdVariant, &'a [u8])>,
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
      pentax_makernote: None,
      webp_meta: Vec::new(),
      webp_ext_override: false,
      pentax_junk_records: Vec::new(),
      strd_records: Vec::new(),
    }
  }
}

impl<'a> RiffMeta<'a> {
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

  /// The FIRST embedded WEBP EXIF TIFF block (`EXIF`/`Exif` chunk, `Exif\0\0`
  /// header already stripped), borrowed from the input, or `None` if this is
  /// not a WEBP carrying an EXIF chunk. A WEBP may carry several EXIF chunks
  /// (all replayed at emit time, in walk order); this accessor surfaces only
  /// the first for callers that want a single block. Re-walked via
  /// [`crate::exif::parse_exif_block`].
  #[must_use]
  #[inline]
  pub fn webp_exif(&self) -> Option<&'a [u8]> {
    self.webp_meta.iter().find_map(|c| match *c {
      WebpMetaChunk::Exif { block, .. } => Some(block),
      WebpMetaChunk::Xmp { .. } => None,
    })
  }

  /// The FIRST embedded WEBP XMP packet (`XMP `/`XMP\0` chunk), borrowed from
  /// the input, or `None` if this is not a WEBP carrying an XMP chunk. A WEBP
  /// may carry several XMP chunks (all replayed at emit time, in walk order);
  /// this accessor surfaces only the first. Parsed via
  /// [`crate::formats::xmp::parse_borrowed`].
  #[must_use]
  #[inline]
  pub fn webp_xmp(&self) -> Option<&'a [u8]> {
    self.webp_meta.iter().find_map(|c| match *c {
      WebpMetaChunk::Xmp { packet, .. } => Some(packet),
      WebpMetaChunk::Exif { .. } => None,
    })
  }

  /// `true` when a `VP8X` (WEBP-form) or `VP8L` chunk applied the explicit
  /// `webp` file-type extension override (RIFF.pm:2106 / 1332). The engine's
  /// finalize uses this to surface `File:FileTypeExtension = webp` even when
  /// the base file type is non-WEBP (e.g. a `WAV (lossless)` from a WAVE
  /// carrying a `VP8L` chunk).
  #[must_use]
  #[inline(always)]
  pub const fn webp_ext_override(&self) -> bool {
    self.webp_ext_override
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
  /// GAT: `'a` is the input borrow carrying the zero-copy Pentax AVI
  /// MakerNote sub-slice (#157); all other RIFF data is owned.
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
  let magic = data.get(0..4);
  let (rf64, _outer_size) = if magic == Some(MAGIC_RIFF.as_slice()) {
    (false, le_u32_at(data, 4))
  } else if magic == Some(MAGIC_RF64.as_slice()) {
    (true, le_u32_at(data, 4))
  } else {
    return None;
  };
  let form: [u8; 4] = fourcc_at(data, 8);

  // RIFF.pm:2041 `$type = $riffType{$2}` → file_type + MIME.
  // Bundled passes `undef` MIME when `$type` is undef; we surface the inert
  // `"RIFF"` fallback so the engine's `ExplicitWithMime` finalize always
  // has a target. Real-input AVI / WAV / WEBP all hit the matched arms.
  let (base_file_type, mime): (&'static str, &'static str) = match riff_type_for(&form) {
    Some(t) => (t, riff_mime_for(t)),
    None => ("RIFF", "application/octet-stream"),
  };
  // RIFF.pm:2106 gates the `Extended WEBP` override on `$type eq 'WEBP'` (the
  // ORIGINAL form-type lookup), so a non-WEBP RIFF (WAV/AVI/private form)
  // carrying a top-level `VP8X` must NOT be promoted to WEBP.
  let form_is_webp = riff_type_for(&form) == Some("WEBP");

  let mut walker = Walker {
    data,
    pos: 12,
    entries: Vec::new(),
    streams: Vec::new(),
    current_stream_type: None,
    charset: Charset::Latin,
    unsupported_charset: None,
    err: false,
    pentax_makernote: None,
    base_file_type,
    form_is_webp,
    webp_file_type_override: None,
    webp_ext_override: false,
    webp_meta: Vec::new(),
    pentax_junk_records: Vec::new(),
    strd_records: Vec::new(),
  };

  // RIFF.pm:2058: `my $riffEnd = Get32u(\$buff, 4) + 8; $riffEnd += $riffEnd & 0x01;`
  // We pin the walk to `data.len()` rather than the declared outer size:
  // bundled also caps via `$raf->Read` returning short on EOF (RIFF.pm:2096-
  // 2102). A declared outer size that EXCEEDS the file is treated as the
  // file end — see `read_chunk` below.

  walker.walk_top();

  // RIFF.pm:2106 / RIFF.pm:1332: the `VP8X` (`Extended WEBP`) and `VP8L`
  // (` (lossless)`) `OverrideFileType` results, resolved during the walk
  // (the VP8X branch is gated on the WEBP form type; VP8L appends to whatever
  // FileType is current). MIME is left UNCHANGED — both `OverrideFileType`
  // calls pass an undef/empty `$mimeType` (`%mimeType` has no `Extended WEBP`
  // / ` (lossless)` key), so `SetFileType`'s form-type MIME stands.
  let file_type = walker.webp_file_type_override.unwrap_or(base_file_type);
  let webp_ext_override = walker.webp_ext_override;

  Some(RiffMeta {
    entries: walker.entries,
    streams: walker.streams,
    file_type,
    mime,
    rf64,
    corrupted: walker.err,
    unsupported_charset: walker.unsupported_charset,
    pentax_makernote: walker.pentax_makernote,
    webp_meta: walker.webp_meta,
    webp_ext_override,
    pentax_junk_records: walker.pentax_junk_records,
    strd_records: walker.strd_records,
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
  /// The Pentax AVI MakerNote payload — the `hymn` (or Q-S1 `mknt`) sub-chunk
  /// of `LIST_hydt`/`LIST_pntx` (`Pentax.pm:6373-6395`). A sub-slice BORROWED
  /// from `data` (zero-copy — no owned duplicate of the payload); decoded at
  /// emit time (when the `-j`/`-n` mode is known) through the shared
  /// `%Pentax::Main` walker. `None` for a non-Pentax AVI (#157).
  pentax_makernote: Option<&'a [u8]>,
  /// The ORIGINAL form-type's `SetFileType` value (`%riffType` lookup of the
  /// 4cc after `RIFF`/`RF64`, RIFF.pm:2041/2053) — `WAV` / `AVI` / `WEBP` / …
  /// / `RIFF`. The `VP8L` RawConv appends ` (lossless)` to the CURRENT FileType
  /// (RIFF.pm:1332 `$$self{VALUE}{FileType} . ' (lossless)'`), which starts as
  /// this base; read at the `VP8L` chunk.
  base_file_type: &'static str,
  /// `true` when the form type (`$type`) is `WEBP` — RIFF.pm:2106 gates the
  /// `Extended WEBP` `OverrideFileType` on `$type eq 'WEBP'`, so a `VP8X` chunk
  /// in a non-WEBP RIFF (WAV/AVI/private form) must NOT promote to WEBP.
  form_is_webp: bool,
  /// The resolved `OverrideFileType` result so far: `Some("Extended WEBP")`
  /// after a `VP8X` on a WEBP form (RIFF.pm:2106), and/or the
  /// ` (lossless)`-suffixed type after a `VP8L` (RIFF.pm:1332). `None` until an
  /// override fires; the post-walk `file_type` falls back to `base_file_type`.
  /// MIME is NEVER changed by these overrides (both pass an undef `$mimeType`).
  webp_file_type_override: Option<&'static str>,
  /// `true` once a `VP8X` (WEBP form) or `VP8L` chunk fired
  /// `OverrideFileType(..., 'webp')` — the explicit `webp` `$normExt`
  /// (RIFF.pm:2106 / 1332). Surfaced to the engine to force
  /// `File:FileTypeExtension = webp` even for a non-WEBP base type.
  webp_ext_override: bool,
  /// The embedded WEBP metadata chunks (`EXIF`/`Exif` blocks + `XMP `/`XMP\0`
  /// packets) in WALK ORDER — ExifTool dispatches EVERY such chunk it walks
  /// (RIFF.pm:557-587), so this is an ORDERED LIST, not a single slot. Each
  /// payload is borrowed from the input (zero-copy); replayed at emit time
  /// through [`crate::exif::parse_exif_block`] / [`crate::formats::xmp::parse_borrowed`].
  /// Empty until a metadata chunk is seen.
  webp_meta: Vec<WebpMetaChunk<'a>>,
  /// The matched Pentax vendor `JUNK` SubDirectories (`PentaxJunk`/`PentaxJunk2`,
  /// RIFF.pm:469-478) and their borrowed payloads, in WALK ORDER — ExifTool
  /// re-runs the matched SubDirectory on EVERY `JUNK` chunk it walks (`HandleTag`
  /// at each walk position), so a repeated/mixed `JUNK` retains one record per
  /// matched chunk that has at least one in-range leaf, NOT a single slot. Each
  /// chunk's in-range leaves are replayed at emit time through the variant's
  /// `ProcessBinaryData` offset map, and the central `TagMap` resolves duplicates
  /// PER LEAF (last-wins per tag) — so a full `PentaxJunk2` followed by a SHORTER
  /// same-signature one keeps the first chunk's `Model`/`FNumber`/`DateTime` (the
  /// short one lacks them) while the later `Make` wins. A signature-only chunk
  /// that can emit no leaf is not retained (no output either way; bounds the Vec
  /// against a crafted tiny-chunk repeat). Each payload is borrowed from `data`
  /// (zero-copy). Empty until such a `JUNK` is seen (#154, #422).
  pentax_junk_records: Vec<(PentaxJunkVariant, &'a [u8])>,
  /// The matched `%RIFF::StreamData` rows (`Zora`/`CASI`/`unknown`,
  /// `RIFF.pm:1250-1276`) and their borrowed `strd` payloads, in WALK ORDER —
  /// ExifTool's `ProcessStreamData` runs on EVERY `strd` chunk it walks (one per
  /// `LIST_strl`, RIFF.pm:1110-1140), so a multi-stream AVI yields one record
  /// per matched `strd`, not a single slot. Each payload is borrowed from `data`
  /// (zero-copy); replayed at emit time through the variant's tiny fixed string
  /// conversion. Empty until such a `strd` is seen; a later record with the same
  /// rendered tag is resolved by the normal `TagMap` duplicate rules at emit,
  /// not blocked here (#158).
  strd_records: Vec<(StrdVariant, &'a [u8])>,
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
        let Some(body) = self.data.get(list_payload_start..list_payload_end) else {
          break;
        };
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
          // LIST_adtl RIFF.pm:437-440 → `%Main` — cue-point sub-chunks
          // (labl/note/ltxt, RIFF.pm:369-390).
          b"adtl" => {
            process_chunks_adtl(body, &mut self.entries);
          }
          // LIST_ncdt — Nikon AVI maker notes. Deferred (a separate
          // follow-up; no fixture in the suite).
          b"ncdt" => {}
          // LIST_hydt / LIST_pntx — Pentax AVI maker notes (`Pentax.pm:6373-
          // 6395`, `%Pentax::AVI`). Capture the `hymn`/`mknt` sub-chunk payload
          // for the emit-time `%Pentax::Main` re-dispatch (#157).
          b"hydt" | b"pntx" => self.process_chunks_hydt(body),
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
      let Some(body) = self.data.get(chunk_start..chunk_end) else {
        break;
      };
      match &tag {
        b"fmt " => emit_audio_format(body, &mut self.entries),
        // WAV-specific sub-chunks (RIFF.pm:360-668). Each is a
        // `ProcessBinaryData`/`RawConv` table dispatched at the top level.
        b"bext" => emit_bext(body, &mut self.entries),
        b"ds64" => emit_ds64(body, &mut self.entries),
        b"smpl" => emit_smpl(body, &mut self.entries),
        b"inst" => emit_inst(body, &mut self.entries),
        b"acid" => emit_acid(body, &mut self.entries),
        // `fact` NumberOfSamples — RawConv `Get32u(\$val, 0)` (RIFF.pm:512-515).
        b"fact" => {
          if body.len() >= 4 {
            self.entries.push(RiffEntry::new(
              "RIFF",
              "NumberOfSamples",
              RiffValue::U32(le_u32_at(body, 0)),
            ));
          }
        }
        // `cue ` CuePoints / `plst` Playlist — `Binary => 1` (RIFF.pm:516-524).
        // No sub-table; the whole chunk renders as the binary placeholder.
        b"cue " => {
          self.entries.push(RiffEntry::new(
            "RIFF",
            "CuePoints",
            RiffValue::Str(crate::value::binary_data_placeholder(body.len()).into()),
          ));
        }
        b"plst" => {
          self.entries.push(RiffEntry::new(
            "RIFF",
            "Playlist",
            RiffValue::Str(crate::value::binary_data_placeholder(body.len()).into()),
          ));
        }
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
        // WEBP extended-format chunk (`VP8X`, RIFF.pm:603-606 -> `%RIFF::VP8X`,
        // RIFF.pm:1351-1379). Emits `WebP_Flags`/`ImageWidth`/`ImageHeight`. The
        // `Extended WEBP` promotion is GATED on the WEBP form type (RIFF.pm:2106
        // `... if $tag eq 'VP8X' and $type eq 'WEBP'`): a `VP8X` in a non-WEBP
        // RIFF (WAV/AVI/private form) emits the tags but does NOT promote — so
        // the file is not mis-finalized as WEBP. When it fires, the explicit
        // `webp` `$normExt` is recorded for `File:FileTypeExtension`.
        b"VP8X" => {
          emit_webp_vp8x(body, &mut self.entries);
          if self.form_is_webp {
            self.webp_file_type_override = Some("Extended WEBP");
            self.webp_ext_override = true;
          }
        }
        // WEBP lossy bitstream (`VP8 `, RIFF.pm:593-597 -> `%RIFF::VP8`,
        // RIFF.pm:1279-1319). The Condition `^...\x9d\x01\x2a` gates dispatch
        // (RIFF.pm:595); a non-matching body is the deferred `UnknownEXIF`-style
        // miss (no tags). The `ImageWidth`/`ImageHeight` are `Priority => 0`
        // (RIFF.pm:1301/1312) -> they never override a `VP8X` canvas.
        b"VP8 " => emit_webp_vp8(body, &mut self.entries),
        // WEBP lossless (`VP8L`, RIFF.pm:598-601 -> `%RIFF::VP8L`,
        // RIFF.pm:1322-1348). Condition `^\x2f` (RIFF.pm:600); the `ImageWidth`
        // RawConv (RIFF.pm:1330-1334) APPENDS ` (lossless)` to the CURRENT
        // FileType — `$$self{VALUE}{FileType} . ' (lossless)'`, with the
        // explicit `webp` `$normExt`. That base is whatever FileType is current
        // when the chunk is walked: a prior `VP8X` may have set `Extended WEBP`,
        // otherwise it is the form-type base (`WEBP`/`WAV`/`AVI`/…). This is NOT
        // gated on the WEBP form, so a non-WEBP RIFF carrying a `VP8L` becomes
        // e.g. `WAV (lossless)` (verified vs bundled 13.59) — but its MIME and
        // base type are preserved (it is NOT finalized as WEBP).
        b"VP8L" => {
          if emit_webp_vp8l(body, &mut self.entries) {
            let current = self.webp_file_type_override.unwrap_or(self.base_file_type);
            self.webp_file_type_override = Some(vp8l_lossless_file_type(current));
            self.webp_ext_override = true;
          }
        }
        // WEBP alpha (`ALPH`, RIFF.pm:615-618 -> `%RIFF::ALPH`,
        // RIFF.pm:1467-1497). Emits AlphaPreprocessing/Filtering/Compression.
        b"ALPH" => emit_webp_alph(body, &mut self.entries),
        // WEBP embedded EXIF (`EXIF`/`Exif`, RIFF.pm:557-576). A complete TIFF
        // block dispatched to the standard `ProcessTIFF` IFD walker. Three
        // bundled conditions: a bare `II*\0`/`MM\0*` header (Start=0); an
        // `Exif\0\0`-prefixed block (Start=6, `Improper EXIF header` warning);
        // else the deferred `UnknownEXIF` (Binary => 1). We CAPTURE the TIFF
        // slice here (zero-copy) and re-walk it at emit time via
        // [`crate::exif::parse_exif_block`] (the QuickTime/PNG `eXIf` seam).
        b"EXIF" | b"Exif" => {
          if matches!(body.get(0..4), Some(b"II\x2a\x00" | b"MM\x00\x2a")) {
            // RIFF dispatches EVERY EXIF chunk it walks (RIFF.pm:557-563), so
            // append to the ordered list — a file with repeated EXIF chunks
            // keeps the tags of all of them (later chunks last-win per-tag).
            self.webp_meta.push(WebpMetaChunk::Exif {
              block: body,
              improper: false,
            });
          } else if body.get(0..6) == Some(b"Exif\x00\x00")
            && let Some(block) = body.get(6..)
            && matches!(block.get(0..4), Some(b"II\x2a\x00" | b"MM\x00\x2a"))
          {
            // RIFF.pm:567/571 `Start => 6` -> the TIFF block begins after the
            // 6-byte `Exif\0\0` header; bundled accepts it with a minor
            // `Warn("Improper EXIF header", 1)`.
            self.webp_meta.push(WebpMetaChunk::Exif {
              block,
              improper: true,
            });
          }
          // else: `UnknownEXIF` (Binary => 1) -- deferred, no emission.
        }
        // WEBP embedded XMP (`XMP `, RIFF.pm:577-580; the incorrect `XMP\0`
        // variant, RIFF.pm:582-587). A standard XMP packet dispatched to
        // `ProcessXMP`. We CAPTURE the packet and parse it at emit time via the
        // ported [`crate::formats::xmp::parse_borrowed`] (PNG raw-profile seam).
        b"XMP " => self.webp_meta.push(WebpMetaChunk::Xmp {
          packet: body,
          incorrect_id: false,
        }),
        b"XMP\x00" => self.webp_meta.push(WebpMetaChunk::Xmp {
          packet: body,
          incorrect_id: true,
        }),
        // WEBP embedded ICC profile (`ICCP`, RIFF.pm:588-592 -> ICC_Profile::
        // Main). exifast has NO ported ICC_Profile module (color management is
        // out of the camera-metadata scope -- the same deferral PNG `iCCP` and
        // JPEG `APP2` ICC carry), so the profile is not decoded into
        // `ICC_Profile:*` tags. Skipped (no fixture in the suite carries ICCP).
        b"ICCP" => {}
        // Skip image-data / index chunks (RIFF.pm:2148-2150).
        b"data" | b"idx1" => {}
        // JUNK — the `%Main` `JUNK` Condition list (RIFF.pm:442-492). The
        // ported subset: `PentaxJunk`/`PentaxJunk2` (captured for the emit-time
        // `MakerNotes:Pentax:*` decode) and the `TextJunk` ASCII fallback
        // (emitted as `RIFF:TextJunk`). The remaining vendor variants
        // (`OlympusJunk`/`CasioJunk`/`RicohJunk`/`LucasJunk`) route into
        // separate vendor subsystems and are still deferred — see
        // [`Walker::dispatch_junk`] / the module doc.
        b"JUNK" => self.dispatch_junk(body),
        // JUNQ — `%Main` `OldXMP` (`Binary => 1`, RIFF.pm:498-502), a SEPARATE
        // tag from the JUNK Condition list (it is NOT a `JUNK` variant). The
        // Adobe Bridge old-XMP backup; deferred (no XMP-block re-dispatch here).
        b"JUNQ" => {}
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
    let tag: [u8; 4] = fourcc_at(self.data, self.pos);
    let len = le_u32_at(self.data, self.pos + 4) as usize;
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
      let tag: [u8; 4] = fourcc_at(body, p);
      let len = le_u32_at(body, p + 4) as usize;
      p += 8;
      if p + len > body.len() {
        // RIFF.pm:1798-1801: `Bad $tag chunk` and abort.
        return;
      }
      if &tag == b"LIST" && len >= 4 {
        let list_type: [u8; 4] = fourcc_at(body, p);
        let Some(inner) = body.get(p + 4..p + len) else {
          return;
        };
        match &list_type {
          b"strl" => self.process_chunks_strl(inner),
          b"odml" => process_chunks_odml(inner, &mut self.entries),
          _ => {}
        }
      } else {
        let Some(payload) = body.get(p..p + len) else {
          return;
        };
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
      let tag: [u8; 4] = fourcc_at(body, p);
      let len = le_u32_at(body, p + 4) as usize;
      p += 8;
      if p + len > body.len() {
        return;
      }
      let Some(payload) = body.get(p..p + len) else {
        return;
      };
      match &tag {
        b"strh" => {
          // Emit + capture the resulting StreamType into both the stream
          // record and `current_stream_type`.
          let stype = emit_stream_header(payload, &mut self.entries);
          self.current_stream_type = stype;
          if let Some(sty) = stype
            && let Some(stream) = self.streams.get_mut(stream_idx)
          {
            // `strh` StreamType is a raw 4-byte FourCC (`auds`/`vids`/…),
            // captured here UNTRIMMED (the raw `fourcc_at` bytes). Decode via
            // the `EscapeJSON` tail order — DELETE NULs (`tr/\0//d`,
            // exiftool:3820) THEN run `FixUTF8` (exiftool:3824) — rather than the
            // prior bare `fix_utf8` (which repaired before the NUL deletion) or
            // silently dropping a non-UTF-8 FourCC to "". The NUL-strip precedes
            // the repair, so a trailing-NUL / NUL-split non-UTF-8 FourCC
            // reassembles faithfully (`C2 00 A9` → `©`, not `??`), and a trailing
            // NUL is removed before the `TrackKind` match. For the real all-ASCII
            // 4-byte FourCCs (no NUL, valid UTF-8) `escape_json_raw_bytes` is
            // identity → byte-identical (#53/FU-12).
            let sty_str = SmolStr::new(crate::convert::escape_json_raw_bytes(&sty));
            stream.stream_type = Some(sty_str);
          }
          // The codec FourCC at offset 4 is captured by `emit_stream_header`
          // and emitted; record it here too (with the same trailing-null
          // trim bundled's `Format => 'string[4]'` applies).
          if let Some(codec_bytes) = payload.get(4..8)
            && let Some(stream) = self.streams.get_mut(stream_idx)
          {
            let codec = string_trim_nulls(codec_bytes);
            stream.codec = Some(SmolStr::new(&codec));
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
            if let Some(stream) = self.streams.get_mut(stream_idx) {
              stream.name = Some(SmolStr::new(&name));
            }
          }
        }
        // `strd` StreamData — bundled hops into `%StreamData`
        // (`RIFF.pm:1250-1276`, `ProcessStreamData` at `RIFF.pm:1699-1748`) and
        // keys the table by the leading 4-byte tag ID. PORTED (#158): the
        // `Zora` (`RIFF:VendorName`) / `CASI` (`Casio:Software`) / `unknown`
        // (`RIFF:UnknownData`) rows — see [`Walker::dispatch_strd`]. The Canon
        // `AVIF` IFD0 re-dispatch is deferred (see [`StrdVariant`]).
        b"strd" => self.dispatch_strd(payload),
        _ => {}
      }
      p += len + (len & 1);
    }
  }

  /// `LIST_hydt` / `LIST_pntx` — Pentax AVI MakerNotes (`Pentax.pm:6373-6395`,
  /// the `%Pentax::AVI` table). Scan the LIST's sub-chunks for the `hymn` (the
  /// K-x/K-70 form) or the Q-S1 `mknt` chunk and capture its RAW payload for the
  /// emit-time `%Pentax::Main` re-dispatch (#157). The walk is mode-agnostic
  /// (the `-j`/`-n` rendering happens at `tags()` time), so this only stores the
  /// bytes; the decode runs in [`RiffMeta::tags`]
  /// ([`crate::emit::Taggable`]) via
  /// [`crate::exif::makernotes::vendors::pentax::redispatch_avi_makernote`],
  /// mirroring the Canon CTMD precedent. The LIST_ncdt (Nikon AVI) path stays a
  /// no-op — a separate follow-up (no fixture).
  ///
  /// `body` is the LIST payload AFTER the 4-byte LIST type (it begins at the
  /// first sub-chunk header). Sub-chunk framing is the standard
  /// `[FourCC][int32u len][payload][pad]`. The FIRST `hymn`/`mknt` wins (a
  /// single MakerNote per file in practice; bundled's `%Pentax::AVI` has one row
  /// each and last would overwrite, but there is never more than one).
  fn process_chunks_hydt(&mut self, body: &'a [u8]) {
    let mut p = 0usize;
    while p + 8 <= body.len() {
      let tag: [u8; 4] = fourcc_at(body, p);
      let len = le_u32_at(body, p + 4) as usize;
      p += 8;
      let Some(payload) = body.get(p..p.checked_add(len).unwrap_or(usize::MAX)) else {
        // A sub-chunk whose declared length runs past the LIST body — stop
        // (bundled's read fails and aborts the sub-walk).
        return;
      };
      if (&tag == b"hymn" || &tag == b"mknt") && self.pentax_makernote.is_none() {
        // Borrow the sub-slice of the input (it already carries `'a`) — NO
        // owned copy, so a crafted multi-MB hymn payload cannot double resident
        // memory during parse (#157 Codex R1). The emit-time re-dispatch in
        // `RiffMeta::tags` operates over this borrow.
        self.pentax_makernote = Some(payload);
      }
      p += len + (len & 1);
    }
  }

  /// Dispatch a `JUNK` chunk through the `%Main` `JUNK` Condition list
  /// (RIFF.pm:442-492). The list is tried IN ORDER; the FIRST matching
  /// `$$valPt` signature wins (the bundled `HandleTag` array-of-conditions
  /// semantics). Ported subset:
  /// - `PentaxJunk`  — `^IIII\x01\0`        → captured (`MakerNotes:Pentax:*`).
  /// - `PentaxJunk2` — `^PENTDigital Camera` → captured (`MakerNotes:Pentax:*`).
  /// - `TextJunk`    — RawConv ASCII fallback → `RIFF:TextJunk`.
  ///
  /// Still-deferred vendor variants whose signatures are checked here ONLY so a
  /// matching chunk is NOT mis-emitted as `TextJunk` (they route into separate
  /// vendor subsystems / need a real sample — #154):
  /// - `OlympusJunk` — `^OLYMDigital Camera`  → `%Olympus::AVI` (a 332-entry
  ///   `%olympusCameraTypes` PrintConv + a `ThumbInfo` SubDirectory).
  /// - `CasioJunk`   — `^QVMI`                → `%Exif::Main` IFD0 (`Start=>10`,
  ///   BigEndian) — the embedded-EXIF `Start`/`Base` offset mechanics need a
  ///   real Casio EX-S600 AVI to pin byte-exact.
  /// - `RicohJunk`   — `^ucmt`                → `%Ricoh::AVI` sub-chunk
  ///   processor (`ucmt`/`mnrt`/`rdc2`/`thum`, incl. a `%Ricoh::Main` MakerNote).
  /// - `LucasJunk`   — `^0G(DA|PS)`           → `%QuickTime::Stream` via
  ///   `ProcessLucas` (a timed-metadata subsystem).
  ///
  /// `body` is the full `JUNK` chunk payload (already bounds-checked by the
  /// caller). EACH matched Pentax `JUNK` is captured in WALK ORDER (zero-copy
  /// borrow, appended — never overwritten), mirroring `strd_records`: ExifTool
  /// re-runs the matched SubDirectory on every `JUNK` chunk, so emit-time replay
  /// of each chunk's in-range leaves + the central `TagMap` per-leaf dedup keeps
  /// the union (last-wins per tag) — see the per-signature notes below. The
  /// `TextJunk` value is decoded + pushed immediately (a single tag, so its
  /// repeat last-wins via the same `TagMap` dedup).
  fn dispatch_junk(&mut self, body: &'a [u8]) {
    // RIFF.pm:445 `OlympusJunk` `^OLYMDigital Camera` — deferred (subsystem).
    if body.starts_with(b"OLYMDigital Camera") {
      return;
    }
    // RIFF.pm:450 `CasioJunk` `^QVMI` — deferred (needs a real sample).
    if body.starts_with(b"QVMI") {
      return;
    }
    // RIFF.pm:463 `RicohJunk` `^ucmt` — deferred (subsystem).
    if body.starts_with(b"ucmt") {
      return;
    }
    // RIFF.pm:471 `PentaxJunk` `^IIII\x01\0` — Optio RS1000. EACH matched chunk
    // that CAN emit a leaf is appended in walk order (no overwrite): ExifTool
    // re-runs the matched SubDirectory on EVERY `JUNK` chunk it walks (`HandleTag`
    // at each walk position), emitting that chunk's in-range leaves, then the
    // central `TagMap` resolves duplicates PER LEAF via the normal `Priority => 1`
    // tag-overwrite (last-walked wins per tag). Replaying every record preserves
    // the earlier leaves a later SHORTER chunk lacks (verified vs bundled 13.59).
    // A signature-only chunk with NO in-range leaf is NOT retained — it would
    // emit nothing, so dropping it is byte-identical to the full replay while
    // bounding the record Vec against a crafted tiny-chunk repeat (#422).
    if body.starts_with(b"IIII\x01\x00") {
      if pentax_junk_has_in_range_leaf(PentaxJunkVariant::Junk, body.len()) {
        self
          .pentax_junk_records
          .push((PentaxJunkVariant::Junk, body));
      }
      return;
    }
    // RIFF.pm:476 `PentaxJunk2` `^PENTDigital Camera` — Optio RZ18. Same
    // retain-each-that-emits in walk order as `PentaxJunk` above; the per-leaf
    // `TagMap` dedup at emit keeps the union (last-wins per tag), so a full
    // `PentaxJunk2` followed by a shorter same-signature one keeps the first
    // chunk's `Model`/`FNumber`/`DateTime` while the later `Make` wins (bundled
    // 13.59). A signature-only chunk shorter than the first leaf (`Make` @ 0x12)
    // emits nothing and is NOT retained (#422).
    if body.starts_with(b"PENTDigital Camera") {
      if pentax_junk_has_in_range_leaf(PentaxJunkVariant::Junk2, body.len()) {
        self
          .pentax_junk_records
          .push((PentaxJunkVariant::Junk2, body));
      }
      return;
    }
    // RIFF.pm:481 `LucasJunk` `^0G(DA|PS)` — Lucas LK-7900 Ace; deferred.
    if body.starts_with(b"0GDA") || body.starts_with(b"0GPS") {
      return;
    }
    // RIFF.pm:488 `TextJunk` — the ASCII fallback. RawConv
    // `$val =~ /^([^\0-\x1f\x7f-\xff]+)\0*$/ ? $1 : undef`: a NON-EMPTY leading
    // run of printable bytes (0x20-0x7e — neither a control 0x00-0x1f nor a
    // high byte 0x7f-0xff), followed ONLY by NUL padding to the end. On a match
    // the captured `$1` (the printable run) becomes `RIFF:TextJunk`; otherwise
    // the tag is dropped (undef).
    if let Some(text) = text_junk_raw_conv(body) {
      self.entries.push(RiffEntry::new(
        "RIFF",
        "TextJunk",
        RiffValue::Str(text.into()),
      ));
    }
  }

  /// Dispatch a `strd` (StreamData) chunk through `%RIFF::StreamData`
  /// (`RIFF.pm:1250-1276`, `ProcessStreamData` at `RIFF.pm:1699-1748`). The
  /// table is keyed by the leading 4-byte tag ID (`my $tag = substr($$dataPt,
  /// $start, 4)`, `RIFF.pm:1709`); a hit appends `(variant, payload)` for the
  /// emit-time decode, the unrecognized-but-printable case falls to the
  /// `unknown` row, and everything else is dropped. ExifTool re-runs
  /// `ProcessStreamData` on EVERY `strd` chunk it walks (one per `LIST_strl`,
  /// each calling `HandleTag` at its walk position), so a multi-stream AVI with
  /// several `strd` chunks records EACH — there is no first-match-wins gate.
  /// Same-named records (e.g. two `Zora` streams) are resolved by the normal
  /// `TagMap` duplicate rules at emit (last-wins for these undef-priority tags),
  /// matching bundled 13.59.
  ///
  /// Ported rows:
  /// - `Zora` (`RIFF.pm:1270`) → `RIFF:VendorName` — captured.
  /// - `CASI` (`RIFF.pm:1266-1269`, `%Casio::AVI`) → `Casio:Software` — captured.
  /// - `unknown` (`RIFF.pm:1271-1275`) → `RIFF:UnknownData` — captured iff the
  ///   payload passes the all-printable `RawConv` (checked here so a binary
  ///   `strd` is dropped without storing).
  ///
  /// Deferred row (checked here ONLY so it is NOT mis-captured as `unknown`):
  /// - `AVIF` (`RIFF.pm:1257-1265`, Canon) → `Exif::Main` IFD0 — the headerless
  ///   IFD0 re-dispatch (see [`StrdVariant`]). Recognized so it is skipped
  ///   without capture, yet does NOT abort the walk of any later `strd`.
  ///
  /// `body` is the full `strd` chunk payload (already bounds-checked by the
  /// caller). `ProcessStreamData` requires `$size >= 4` (`RIFF.pm:1705`) — a
  /// shorter chunk has no 4-byte tag ID and emits nothing.
  fn dispatch_strd(&mut self, body: &'a [u8]) {
    // `RIFF.pm:1705` `return 0 if $size < 4` — no tag ID, nothing to key on.
    let Some(tag) = body.get(0..4) else {
      return;
    };
    match tag {
      // `RIFF.pm:1270` `Zora => 'VendorName'`.
      b"Zora" => self.strd_records.push((StrdVariant::VendorName, body)),
      // `RIFF.pm:1266-1269` `CASI` → `%Casio::AVI` (`Software`).
      b"CASI" => self.strd_records.push((StrdVariant::CasioData, body)),
      // `RIFF.pm:1257-1265` `AVIF` → `Exif::Main` IFD0 — deferred (the
      // headerless-IFD0 re-dispatch + `Base`/offset mechanics; see
      // [`StrdVariant`]). Recognized so it does NOT fall to `unknown`.
      b"AVIF" => {}
      // `RIFF.pm:1271-1275` `unknown` fallback: keep the whole payload as
      // `UnknownData` ONLY when its `RawConv` accepts it (all printable, no
      // trailing NUL). A binary/unprintable payload is dropped.
      _ => {
        if unknown_data_raw_conv(body) {
          self.strd_records.push((StrdVariant::UnknownData, body));
        }
      }
    }
  }
}

/// `%RIFF::StreamData` `UnknownData` RawConv (`RIFF.pm:1274`):
/// `$_=$val; /^[^\0-\x1f\x7f-\xff]+$/ ? $_ : undef`.
///
/// Returns `true` iff the WHOLE value is a non-empty run of printable bytes
/// (0x20-0x7e — neither a control 0x00-0x1f nor a high byte 0x7f-0xff), with NO
/// trailing NUL allowance. This is STRICTER than the JUNK `TextJunk` RawConv
/// (`RIFF.pm:490`, `/^([^\0-\x1f\x7f-\xff]+)\0*$/`), which captures a leading
/// printable run followed by trailing NULs: here a single trailing NUL fails the
/// `$`-anchored whole-string match (verified vs bundled 13.59: `XXXXhello` →
/// `UnknownData`, `XXXXhello\0` → no tag).
fn unknown_data_raw_conv(body: &[u8]) -> bool {
  !body.is_empty() && body.iter().all(|&b| (0x20..=0x7e).contains(&b))
}

/// `TextJunk` RawConv (RIFF.pm:490):
/// `$val =~ /^([^\0-\x1f\x7f-\xff]+)\0*$/ ? $1 : undef`.
///
/// Returns `Some($1)` — the leading run of printable bytes (0x20-0x7e) — iff the
/// WHOLE value is that non-empty run followed only by trailing NULs; otherwise
/// `None` (the tag is dropped). The match is start- AND end-anchored, so ANY
/// byte that is neither printable nor a trailing NUL (e.g. a control byte, a
/// high byte, or a NUL with a printable byte after it) fails the whole match.
/// The captured run is pure 0x20-0x7e, so it is valid UTF-8 (a [`SmolStr`] is
/// built directly).
#[cfg(feature = "alloc")]
fn text_junk_raw_conv(body: &[u8]) -> Option<SmolStr> {
  // `[^\0-\x1f\x7f-\xff]+` — the leading printable run (bytes 0x20..=0x7e).
  let printable_end = body
    .iter()
    .position(|&b| !(0x20..=0x7e).contains(&b))
    .unwrap_or(body.len());
  // `+` ⇒ the run must be non-empty.
  if printable_end == 0 {
    return None;
  }
  // `\0*$` — every remaining byte must be a NUL (the run is end-anchored).
  if !body
    .get(printable_end..)
    .is_some_and(|tail| tail.iter().all(|&b| b == 0))
  {
    return None;
  }
  // `$1` — the printable run (guaranteed 0x20..=0x7e ⇒ valid UTF-8/ASCII).
  body
    .get(..printable_end)
    .and_then(|run| core::str::from_utf8(run).ok())
    .map(SmolStr::new)
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
    let tag: [u8; 4] = fourcc_at(body, p);
    let len = le_u32_at(body, p + 4) as usize;
    p += 8;
    if p + len > body.len() {
      return;
    }
    let Some(payload) = body.get(p..p + len) else {
      return;
    };
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
    while ws_start > 0
      && bytes
        .get(ws_start - 1)
        .is_some_and(|&b| (b as char).is_ascii_whitespace())
    {
      ws_start -= 1;
    }
    bytes.truncate(ws_start);
  }
  // (2) `s/(\s*\0)/, /` — replace the FIRST `\s*\0` group with ", ".
  // Find the first NUL; back up over its leading ASCII whitespace.
  if let Some(nul) = bytes.iter().position(|&b| b == 0) {
    let mut ws_start = nul;
    while ws_start > 0
      && bytes
        .get(ws_start - 1)
        .is_some_and(|&b| (b as char).is_ascii_whitespace())
    {
      ws_start -= 1;
    }
    let mut out = Vec::with_capacity(bytes.len() + 2);
    out.extend_from_slice(bytes.get(..ws_start).unwrap_or(&bytes));
    out.extend_from_slice(b", ");
    // (3) `s/\0+//g` on the remainder — copy the rest, dropping NULs.
    out.extend(
      bytes
        .get(nul + 1..)
        .unwrap_or(&[])
        .iter()
        .copied()
        .filter(|&b| b != 0),
    );
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
    let tag: [u8; 4] = fourcc_at(body, p);
    let len = le_u32_at(body, p + 4) as usize;
    p += 8;
    if p + len > body.len() {
      return;
    }
    let Some(payload) = body.get(p..p + len) else {
      return;
    };
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
    let tag: [u8; 4] = fourcc_at(body, p);
    let len = le_u32_at(body, p + 4) as usize;
    p += 8;
    if p + len > body.len() {
      return;
    }
    let Some(payload) = body.get(p..p + len) else {
      return;
    };
    let pad = len & 1;
    p += len + pad;
    if &tag == b"dmlh" && payload.len() >= 4 {
      let total = le_u32_at(payload, 0);
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
  let enc = le_u16_at(payload, 0) as u32;
  entries.push(RiffEntry::new("RIFF", "Encoding", RiffValue::U32(enc)));
  // 1: NumChannels — int16u, RIFF.pm:697.
  entries.push(RiffEntry::new(
    "RIFF",
    "NumChannels",
    RiffValue::U32(le_u16_at(payload, 2) as u32),
  ));
  // 2: SampleRate — int32u, RIFF.pm:698-701.
  entries.push(RiffEntry::new(
    "RIFF",
    "SampleRate",
    RiffValue::U32(le_u32_at(payload, 4)),
  ));
  // 4: AvgBytesPerSec — int32u, RIFF.pm:702-705.
  entries.push(RiffEntry::new(
    "RIFF",
    "AvgBytesPerSec",
    RiffValue::U32(le_u32_at(payload, 8)),
  ));
  // 7: BitsPerSample — int16u (offset 7 in int16u-element units = byte
  // offset 14), RIFF.pm:708.
  entries.push(RiffEntry::new(
    "RIFF",
    "BitsPerSample",
    RiffValue::U32(le_u16_at(payload, 14) as u32),
  ));
}

/// Read a fixed-width `string[N]` field at byte `off` (faithful to ExifTool's
/// `ReadValue($_, 'string', N)`). ExifTool CLAMPS a fixed `string` to the bytes
/// actually available from the offset — `ReadValue` shortens the count when
/// `$len * $count > $size` (`ExifTool.pm:6301-6303`: `$count = int($size/$len)`),
/// so a short read returns the AVAILABLE bytes (a PARTIAL string), and returns
/// `undef` ONLY when ZERO bytes remain (`$count < 1`). `ProcessBinaryData` reaches
/// the field whenever its offset is in range (`$more = $size - $entry`,
/// `last if $more <= 0`, `:9963-9964`), i.e. iff `off < payload.len()` — so the
/// field emits a string of `min(N, payload.len() - off)` bytes and emits NOTHING
/// only when `off >= payload.len()`. The `string` format then TRUNCATES at the
/// first NUL (`$val =~ s/\0.*//s if $format eq 'string'`, `:6311`, `:10038`), so
/// an EMBEDDED NUL ends the value — the bytes after it are dropped, NOT retained.
/// Invalid UTF-8 is rendered as `?` per the JSON FixUTF8 step.
///
/// Every caller is a genuine ExifTool `string[N]` field (bext `Description`/
/// `Originator`/`OriginatorReference`/`DateTimeOriginal`/`CodingHistory`,
/// `%Pentax::Junk*` `Make`/`Model`/`DateTime1`/`DateTime2`), so both the
/// clamp-to-available read and the first-NUL truncation are correct for all of
/// them. A fully-available field reads exactly `N` bytes (the clamp is a no-op),
/// so every full-width golden is unchanged. The `undef[N]` fields (`BWF_UMID`)
/// take their own ValueConv path, NOT this helper.
#[cfg(feature = "alloc")]
fn string_field(payload: &[u8], off: usize, len: usize) -> Option<String> {
  // `ReadValue` clamps a fixed string to the available byte count: read
  // `min(len, payload.len() - off)` bytes, dropping ONLY when zero bytes remain
  // at the offset. ExifTool drops at `off >= payload.len()` (`$more <= 0` ⇒
  // `last`, `:9964`; or `$count < 1` ⇒ `undef`, `:6303`) — i.e. the field needs
  // at LEAST one byte past `off`. `payload.get(off..)` alone returns `Some(&[])`
  // for `off == payload.len()`, so filter the zero-length tail to `None`.
  payload
    .get(off..)
    .filter(|tail| !tail.is_empty())
    .map(|tail| {
      let take = len.min(tail.len());
      let window = tail.get(..take).unwrap_or(tail);
      // `string` format: end the value at the first NUL (the C-string
      // terminator), then FixUTF8 (`string_trim_nulls`'s trailing-NUL trim is
      // then a no-op). The `..end` index is `position`-bounded (`< window.len()`)
      // or the full length, so `get` always succeeds; the panic-free `get` keeps
      // `indexing_slicing` clean.
      let end = window.iter().position(|&b| b == 0).unwrap_or(window.len());
      string_trim_nulls(window.get(..end).unwrap_or(window))
    })
}

/// `bext` BroadcastExtension (RIFF.pm:712-759) — the Broadcast Audio Extension
/// chunk (EBU Tech 3285). `ProcessBinaryData` over fixed-offset fields. All
/// emit under family-1 `RIFF` (the table declares only `GROUPS{2}=Audio`).
///
/// `DateTimeOriginal` runs the date ValueConv `tr/-/:/; s/^(\d{4}:\d{2}:\d{2})
/// /$1 /` (RIFF.pm:736); `TimeReference` combines the `int32u[2]` pair into the
/// 64-bit sample count `low + high * 2^32` (RIFF.pm:743); `BWF_UMID` is the
/// `undef[64]` hex-encoded, uppercased, with a single trailing `0{64}` group
/// stripped (RIFF.pm:752); `CodingHistory` is `string[$size-602]`
/// (RIFF.pm:755-758) — emitted only when the chunk extends past offset 602.
#[cfg(feature = "alloc")]
fn emit_bext(payload: &[u8], entries: &mut Vec<RiffEntry>) {
  // 0: Description string[256].
  if let Some(s) = string_field(payload, 0, 256) {
    entries.push(RiffEntry::new(
      "RIFF",
      "Description",
      RiffValue::Str(s.into()),
    ));
  }
  // 256: Originator string[32].
  if let Some(s) = string_field(payload, 256, 32) {
    entries.push(RiffEntry::new(
      "RIFF",
      "Originator",
      RiffValue::Str(s.into()),
    ));
  }
  // 288: OriginatorReference string[32].
  if let Some(s) = string_field(payload, 288, 32) {
    entries.push(RiffEntry::new(
      "RIFF",
      "OriginatorReference",
      RiffValue::Str(s.into()),
    ));
  }
  // 320: DateTimeOriginal string[18] + date ValueConv (RIFF.pm:731-738).
  if let Some(raw) = string_field(payload, 320, 18) {
    entries.push(RiffEntry::new(
      "RIFF",
      "DateTimeOriginal",
      RiffValue::Str(bext_datetime_value_conv(&raw).into()),
    ));
  }
  // 338: TimeReference int32u[2] → low + high * 2^32 (RIFF.pm:739-744).
  if payload.len() >= 346 {
    let low = le_u32_at(payload, 338) as u64;
    let high = le_u32_at(payload, 342) as u64;
    let combined = low.wrapping_add(high.wrapping_mul(4_294_967_296));
    entries.push(RiffEntry::new(
      "RIFF",
      "TimeReference",
      RiffValue::U64(combined),
    ));
  }
  // 346: BWFVersion int16u (RIFF.pm:745-748).
  if payload.len() >= 348 {
    entries.push(RiffEntry::new(
      "RIFF",
      "BWFVersion",
      RiffValue::U32(le_u16_at(payload, 346) as u32),
    ));
  }
  // 348: BWF_UMID undef[64] → hex, strip trailing 0{64}, uppercase
  // (RIFF.pm:749-753).
  if let Some(window) = payload.get(348..348usize.saturating_add(64)) {
    entries.push(RiffEntry::new(
      "RIFF",
      "BWF_UMID",
      RiffValue::Str(bext_umid_value_conv(window).into()),
    ));
  }
  // 602: CodingHistory string[$size-602] (RIFF.pm:755-758). Emitted only when
  // the chunk extends past 602 (a positive `$size-602` count).
  if payload.len() > 602
    && let Some(s) = string_field(payload, 602, payload.len() - 602)
  {
    entries.push(RiffEntry::new(
      "RIFF",
      "CodingHistory",
      RiffValue::Str(s.into()),
    ));
  }
}

/// `bext` `DateTimeOriginal` ValueConv (RIFF.pm:736):
/// `$_=$val; tr/-/:/; s/^(\d{4}:\d{2}:\d{2})/$1 /; $_`. Translates every `-`
/// to `:` then inserts a space after a leading `yyyy:mm:dd`.
#[cfg(feature = "alloc")]
fn bext_datetime_value_conv(raw: &str) -> String {
  // `tr/-/:/` — every hyphen becomes a colon.
  let translated: String = raw
    .chars()
    .map(|c| if c == '-' { ':' } else { c })
    .collect();
  // `s/^(\d{4}:\d{2}:\d{2})/$1 /` — anchored at start: 4 digits, ':', 2 digits,
  // ':', 2 digits ⇒ insert a single space after the 10-char date.
  let b = translated.as_bytes();
  let is_date_prefix = b.len() >= 10
    && b.first().is_some_and(u8::is_ascii_digit)
    && b.get(1).is_some_and(u8::is_ascii_digit)
    && b.get(2).is_some_and(u8::is_ascii_digit)
    && b.get(3).is_some_and(u8::is_ascii_digit)
    && b.get(4) == Some(&b':')
    && b.get(5).is_some_and(u8::is_ascii_digit)
    && b.get(6).is_some_and(u8::is_ascii_digit)
    && b.get(7) == Some(&b':')
    && b.get(8).is_some_and(u8::is_ascii_digit)
    && b.get(9).is_some_and(u8::is_ascii_digit);
  if is_date_prefix {
    let (date, rest) = translated.split_at(10);
    std::format!("{date} {rest}")
  } else {
    translated
  }
}

/// `bext` `BWF_UMID` ValueConv (RIFF.pm:752):
/// `$_=unpack("H*",$val); s/0{64}$//; uc $_`. Lowercase hex of the 64 raw
/// bytes (128 hex chars), strip a single trailing run of exactly 64 `0`s, then
/// uppercase the whole string.
#[cfg(feature = "alloc")]
fn bext_umid_value_conv(window: &[u8]) -> String {
  // `unpack("H*", $val)` — lowercase hex, high nibble first.
  let mut hex = String::with_capacity(window.len().saturating_mul(2));
  for &b in window {
    hex.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
    hex.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
  }
  // `s/0{64}$//` — remove a trailing run of EXACTLY 64 '0' chars (anchored at
  // end). Perl's `0{64}` matches 64 consecutive zeros; a longer trailing run
  // leaves the excess (matches the LAST 64). We strip the final 64 chars iff
  // they are all '0'.
  if hex.len() >= 64
    && hex
      .get(hex.len() - 64..)
      .is_some_and(|tail| tail.bytes().all(|c| c == b'0'))
  {
    hex.truncate(hex.len() - 64);
  }
  // `uc $_`.
  hex.to_ascii_uppercase()
}

/// `ds64` DataSize64 chunk (RIFF.pm:762-784) — 64-bit sizes for MBWF/RF64
/// files. `FORMAT => 'int64u'`: `RIFFSize64` (0), `DataSize64` (1),
/// `NumberOfSamples64` (2). The first two render via `ConvertFileSize`
/// (applied at emit time); `NumberOfSamples64` has no PrintConv. The trailing
/// chunk-override table (RIFF.pm:781-783) is NOT implemented (bundled doesn't
/// either).
#[cfg(feature = "alloc")]
fn emit_ds64(payload: &[u8], entries: &mut Vec<RiffEntry>) {
  if payload.len() >= 8 {
    entries.push(RiffEntry::new(
      "RIFF",
      "RIFFSize64",
      RiffValue::U64(le_u64_at(payload, 0)),
    ));
  }
  if payload.len() >= 16 {
    entries.push(RiffEntry::new(
      "RIFF",
      "DataSize64",
      RiffValue::U64(le_u64_at(payload, 8)),
    ));
  }
  if payload.len() >= 24 {
    entries.push(RiffEntry::new(
      "RIFF",
      "NumberOfSamples64",
      RiffValue::U64(le_u64_at(payload, 16)),
    ));
  }
}

/// `smpl` Sampler chunk (RIFF.pm:787-818) — `FORMAT => 'int32u'`. Nine
/// int32u scalars (offsets 0..32) then `SamplerData undef[$size-40]` at byte
/// 36. `SMPTEFormat` (5) takes a hash PrintConv; `SMPTEOffset` (6) takes the
/// `HH:MM:SS:FF` hex ValueConv (RIFF.pm:809-813); `SamplerData` (9) is the
/// binary placeholder, emitted only when `$size >= 40` (a non-negative
/// `undef[$size-40]` count — verified vs bundled: `$size=36` ⇒ no emission,
/// `$size=40` ⇒ "0 bytes").
#[cfg(feature = "alloc")]
fn emit_smpl(payload: &[u8], entries: &mut Vec<RiffEntry>) {
  // int32u scalars 0..=8 at byte offsets 0,4,...,32. Each emits independently
  // when its 4-byte window is in range (ProcessBinaryData skips out-of-range).
  const NAMES: [&str; 9] = [
    "Manufacturer",
    "Product",
    "SamplePeriod",
    "MIDIUnityNote",
    "MIDIPitchFraction",
    "SMPTEFormat",
    "SMPTEOffset",
    "NumSampleLoops",
    "SamplerDataLen",
  ];
  for (i, name) in NAMES.iter().enumerate() {
    let off = i.saturating_mul(4);
    if payload.len() < off.saturating_add(4) {
      break;
    }
    let raw = le_u32_at(payload, off);
    let value = if *name == "SMPTEOffset" {
      // ValueConv: 8-hex-digit `HH:MM:SS:FF` (RIFF.pm:809-813).
      RiffValue::Str(smpte_offset_value_conv(raw).into())
    } else {
      RiffValue::U32(raw)
    };
    entries.push(RiffEntry::new("RIFF", name, value));
  }
  // 9: SamplerData undef[$size-40] at byte 36 (RIFF.pm:817). `$size` = chunk
  // payload length. Emit iff `$size - 40 >= 0` (a non-negative count).
  if payload.len() >= 40 {
    let data_len = payload.len() - 40;
    entries.push(RiffEntry::new(
      "RIFF",
      "SamplerData",
      RiffValue::Str(crate::value::binary_data_placeholder(data_len).into()),
    ));
  }
}

/// `smpl` `SMPTEOffset` ValueConv (RIFF.pm:809-813):
/// `sprintf('%.8x', $val)` then `s/(..)(..)(..)(..)/$1:$2:$3:$4/` ⇒
/// 8-hex-digit value split into four colon-separated byte pairs `HH:MM:SS:FF`.
#[cfg(feature = "alloc")]
fn smpte_offset_value_conv(val: u32) -> String {
  let hex = std::format!("{val:08x}");
  // The hex is always exactly 8 chars; split into 4 pairs.
  let b = hex.as_bytes();
  let pair = |i: usize| -> &str {
    b.get(i..i + 2)
      .and_then(|s| core::str::from_utf8(s).ok())
      .unwrap_or("00")
  };
  std::format!("{}:{}:{}:{}", pair(0), pair(2), pair(4), pair(6))
}

/// `inst` Instrument chunk (RIFF.pm:821-832) — `FORMAT => 'int8s'`. Seven
/// signed-byte fields. All emit under family-1 `RIFF`.
#[cfg(feature = "alloc")]
fn emit_inst(payload: &[u8], entries: &mut Vec<RiffEntry>) {
  const NAMES: [&str; 7] = [
    "UnshiftedNote",
    "FineTune",
    "Gain",
    "LowNote",
    "HighNote",
    "LowVelocity",
    "HighVelocity",
  ];
  for (i, name) in NAMES.iter().enumerate() {
    if payload.len() <= i {
      break;
    }
    entries.push(RiffEntry::new(
      "RIFF",
      name,
      RiffValue::I32(le_i8_at(payload, i) as i32),
    ));
  }
}

/// `acid` Acidizer chunk (RIFF.pm:1500-1545) — written by Acidizer.
/// `AcidizerFlags` (0, int32u) takes the BITMASK PrintConv; `RootNote` (4,
/// int16u) the note-name hash; `Beats` (12, int32u); `Meter` (16, int16u[2])
/// the swap PrintConv (stored "DEN NUM"); `Tempo` (20, float).
#[cfg(feature = "alloc")]
fn emit_acid(payload: &[u8], entries: &mut Vec<RiffEntry>) {
  // 0: AcidizerFlags int32u.
  if payload.len() >= 4 {
    entries.push(RiffEntry::new(
      "RIFF",
      "AcidizerFlags",
      RiffValue::U32(le_u32_at(payload, 0)),
    ));
  }
  // 4: RootNote int16u.
  if payload.len() >= 6 {
    entries.push(RiffEntry::new(
      "RIFF",
      "RootNote",
      RiffValue::U32(le_u16_at(payload, 4) as u32),
    ));
  }
  // 12: Beats int32u.
  if payload.len() >= 16 {
    entries.push(RiffEntry::new(
      "RIFF",
      "Beats",
      RiffValue::U32(le_u32_at(payload, 12)),
    ));
  }
  // 16: Meter int16u[2] — stored space-joined "DEN NUM" (the ReadValue of an
  // int16u[2]); the swap to "NUM/DEN" is the PrintConv (RIFF.pm:1536-1540).
  if payload.len() >= 20 {
    let den = le_u16_at(payload, 16);
    let num = le_u16_at(payload, 18);
    entries.push(RiffEntry::new(
      "RIFF",
      "Meter",
      RiffValue::Str(std::format!("{den} {num}").into()),
    ));
  }
  // 20: Tempo float.
  if payload.len() >= 24 {
    entries.push(RiffEntry::new(
      "RIFF",
      "Tempo",
      RiffValue::F64(le_f32_at(payload, 20) as f64),
    ));
  }
}

/// `VP8X` WEBP extended-info chunk (RIFF.pm:1351-1379, `%RIFF::VP8X`,
/// `ProcessBinaryData`, little-endian). Emits (in offset order):
/// - `WebP_Flags` (offset 0, int32u) — the BITMASK flags word (PrintConv at
///   emit time, [`print_conv_u32`]); stored as the RAW int (`-n` => `28`).
/// - `ImageWidth` (offset 4, int32u, ValueConv `($val & 0xffffff) + 1`).
/// - `ImageHeight` (offset 6, int32u, ValueConv `($val >> 8) + 1`).
///
/// The offset-4 and offset-6 int32u reads OVERLAP (ExifTool reads a full
/// `int32u` at each byte offset); a 10-byte VP8X data block satisfies both.
#[cfg(feature = "alloc")]
fn emit_webp_vp8x(body: &[u8], entries: &mut Vec<RiffEntry>) {
  // 0: WebP_Flags int32u (raw; BITMASK PrintConv applied at emit time).
  if body.len() >= 4 {
    entries.push(RiffEntry::new(
      "RIFF",
      "WebP_Flags",
      RiffValue::U32(le_u32_at(body, 0)),
    ));
  }
  // 4: ImageWidth int32u, ValueConv `($val & 0xffffff) + 1`.
  if body.len() >= 8 {
    let raw = le_u32_at(body, 4);
    entries.push(RiffEntry::new(
      "RIFF",
      "ImageWidth",
      RiffValue::U32((raw & 0x00ff_ffff) + 1),
    ));
  }
  // 6: ImageHeight int32u, ValueConv `($val >> 8) + 1`.
  if body.len() >= 10 {
    let raw = le_u32_at(body, 6);
    entries.push(RiffEntry::new(
      "RIFF",
      "ImageHeight",
      RiffValue::U32((raw >> 8) + 1),
    ));
  }
}

/// `VP8 ` WEBP lossy bitstream (RIFF.pm:1279-1319, `%RIFF::VP8`,
/// `ProcessBinaryData`, little-endian). The `%Main` Condition `^...\x9d\x01\x2a`
/// (RIFF.pm:595) gates dispatch — bytes 3..6 must be `9d 01 2a`. Emits:
/// - `VP8Version` (offset 0, Mask `0x0e` => `(b0 & 0x0e) >> 1`; PrintConv).
/// - `ImageWidth` (offset 6, int16u, Mask `0x3fff`; `Priority => 0`).
/// - `HorizontalScale` (offset 6, int16u, Mask `0xc000` => `>> 14`).
/// - `ImageHeight` (offset 8, int16u, Mask `0x3fff`; `Priority => 0`).
/// - `VerticalScale` (offset 8, int16u, Mask `0xc000` => `>> 14`).
///
/// The `ImageWidth`/`ImageHeight` carry `Priority => 0` so an Extended-WEBP
/// `VP8X` canvas (emitted first, priority `1`) is NEVER overridden — ExifTool
/// demotes the bitstream pair to the `-a`-only `RIFF:Copy1`.
#[cfg(feature = "alloc")]
fn emit_webp_vp8(body: &[u8], entries: &mut Vec<RiffEntry>) {
  // %Main Condition `^...\x9d\x01\x2a` (RIFF.pm:595): a non-matching body is the
  // deferred `UnknownEXIF`-style miss (no tags).
  if body.get(3..6) != Some(b"\x9d\x01\x2a") {
    return;
  }
  // 0: VP8Version Mask 0x0e (BitShift 1).
  if let Some(&b0) = body.first() {
    entries.push(RiffEntry::new(
      "RIFF",
      "VP8Version",
      RiffValue::U32(u32::from((b0 & 0x0e) >> 1)),
    ));
  }
  // 6: ImageWidth int16u Mask 0x3fff (Priority 0); HorizontalScale Mask 0xc000.
  if body.len() >= 8 {
    let w = le_u16_at(body, 6);
    entries.push(RiffEntry::new_with_priority(
      "RIFF",
      "ImageWidth",
      RiffValue::U32(u32::from(w & 0x3fff)),
      0,
    ));
    entries.push(RiffEntry::new(
      "RIFF",
      "HorizontalScale",
      RiffValue::U32(u32::from((w & 0xc000) >> 14)),
    ));
  }
  // 8: ImageHeight int16u Mask 0x3fff (Priority 0); VerticalScale Mask 0xc000.
  if body.len() >= 10 {
    let h = le_u16_at(body, 8);
    entries.push(RiffEntry::new_with_priority(
      "RIFF",
      "ImageHeight",
      RiffValue::U32(u32::from(h & 0x3fff)),
      0,
    ));
    entries.push(RiffEntry::new(
      "RIFF",
      "VerticalScale",
      RiffValue::U32(u32::from((h & 0xc000) >> 14)),
    ));
  }
}

/// `VP8L` WEBP lossless info (RIFF.pm:1322-1348, `%RIFF::VP8L`,
/// `ProcessBinaryData`, little-endian). The `%Main` Condition `^\x2f`
/// (RIFF.pm:600) gates dispatch — byte 0 must be `0x2f`. Emits:
/// - `ImageWidth` (offset 1, int16u, ValueConv `($val & 0x3fff) + 1`;
///   `Priority => 0`; RawConv appends ` (lossless)` to the FileType).
/// - `ImageHeight` (offset 2, int32u, ValueConv `(($val >> 6) & 0x3fff) + 1`;
///   `Priority => 0`).
/// - `AlphaIsUsed` (offset 4, Mask `0x10` => `(b4 & 0x10) >> 4`; PrintConv).
///
/// Returns `true` when the lossless ImageWidth was emitted (so the caller can
/// apply the `(lossless)` FileType override, RIFF.pm:1330-1334).
#[cfg(feature = "alloc")]
fn emit_webp_vp8l(body: &[u8], entries: &mut Vec<RiffEntry>) -> bool {
  // %Main Condition `^\x2f` (RIFF.pm:600).
  if body.first() != Some(&0x2f) {
    return false;
  }
  let mut emitted_width = false;
  // 1: ImageWidth int16u, ValueConv `($val & 0x3fff) + 1` (Priority 0).
  if body.len() >= 3 {
    let raw = le_u16_at(body, 1);
    entries.push(RiffEntry::new_with_priority(
      "RIFF",
      "ImageWidth",
      RiffValue::U32(u32::from(raw & 0x3fff) + 1),
      0,
    ));
    emitted_width = true;
  }
  // 2: ImageHeight int32u, ValueConv `(($val >> 6) & 0x3fff) + 1` (Priority 0).
  if body.len() >= 6 {
    let raw = le_u32_at(body, 2);
    entries.push(RiffEntry::new_with_priority(
      "RIFF",
      "ImageHeight",
      RiffValue::U32(((raw >> 6) & 0x3fff) + 1),
      0,
    ));
  }
  // 4: AlphaIsUsed Mask 0x10 (BitShift 4).
  if let Some(&b4) = body.get(4) {
    entries.push(RiffEntry::new(
      "RIFF",
      "AlphaIsUsed",
      RiffValue::U32(u32::from((b4 & 0x10) >> 4)),
    ));
  }
  emitted_width
}

/// `ALPH` WEBP alpha info (RIFF.pm:1467-1497, `%RIFF::ALPH`,
/// `ProcessBinaryData`). All three fields read byte 0 with `Mask => 0x03`
/// (BitShift 0 — ExifTool's auto-`BitShift` is the lowest set bit of the mask,
/// so the SAME low 2 bits feed every field, verbatim per the table). Emits:
/// - `AlphaPreprocessing` (offset 0,   Mask `0x03`; PrintConv).
/// - `AlphaFiltering`     (offset 0.1, Mask `0x03`; PrintConv).
/// - `AlphaCompression`   (offset 0.2, Mask `0x03`; PrintConv).
#[cfg(feature = "alloc")]
fn emit_webp_alph(body: &[u8], entries: &mut Vec<RiffEntry>) {
  let Some(&b0) = body.first() else { return };
  let v = u32::from(b0 & 0x03);
  entries.push(RiffEntry::new(
    "RIFF",
    "AlphaPreprocessing",
    RiffValue::U32(v),
  ));
  entries.push(RiffEntry::new("RIFF", "AlphaFiltering", RiffValue::U32(v)));
  entries.push(RiffEntry::new(
    "RIFF",
    "AlphaCompression",
    RiffValue::U32(v),
  ));
}

/// `labl`/`note` ValueConv (RIFF.pm:372/377): `my $str=substr($val,4);
/// $str=~s/\0+$//; unpack("V",$val) . " " . $str`. The leading `int32u`
/// cue-point ID, a space, then the trailing NUL-trimmed text. Shared by both
/// `CuePointLabel` and `CuePointNote` (identical conv). Returns `None` when
/// the payload is shorter than the 4-byte ID.
#[cfg(feature = "alloc")]
fn cue_label_value_conv(payload: &[u8]) -> Option<String> {
  if payload.len() < 4 {
    return None;
  }
  let id = le_u32_at(payload, 0);
  let text = payload.get(4..).map(string_trim_nulls).unwrap_or_default();
  Some(std::format!("{id} {text}"))
}

/// `ltxt` LabeledText ValueConv (RIFF.pm:383-389):
/// `my @a = unpack('VVa4vvvv', $val); $a[2] = "'$a[2]'"; my $txt =
/// substr($val,18); $txt=~s/\0+$//; return join(' ', @a, $txt)`. Fields:
/// CuePointID Length Purpose(quoted 4-byte FourCC) Country Language Dialect
/// Codepage, then the NUL-trimmed text. Returns `None` when the payload is
/// shorter than the 18-byte fixed header.
#[cfg(feature = "alloc")]
fn ltxt_value_conv(payload: &[u8]) -> Option<String> {
  if payload.len() < 18 {
    return None;
  }
  let cue_id = le_u32_at(payload, 0);
  let length = le_u32_at(payload, 4);
  // `a4` — 4 raw bytes verbatim (Perl `a4` keeps trailing NULs AND spaces, NO
  // trim — unlike `A4`). The bytes pass straight through the ValueConv (no
  // `\x`-escape regex, unlike `render_fourcc`); invalid UTF-8 renders as `?`
  // (the JSON FixUTF8 step) and any NUL is removed by the JSON `tr/\0//d`. So
  // a Purpose of `b"rgn "` stays `'rgn '` (trailing space KEPT — verified vs
  // bundled 13.59).
  let purpose_bytes = fourcc_at(payload, 8);
  let purpose = crate::convert::fix_utf8(&purpose_bytes);
  let country = le_u16_at(payload, 12);
  let language = le_u16_at(payload, 14);
  let dialect = le_u16_at(payload, 16);
  // `vvvv` is 4 `int16u`; the 4th (Codepage) is at byte 18 — but `unpack`
  // reads only as many as the buffer has. ExifTool's `unpack('VVa4vvvv', $val)`
  // on an 18-byte-minimum buffer yields Country/Language/Dialect from bytes
  // 12/14/16 and Codepage from byte 18 (absent ⇒ undef ⇒ empty in the join).
  let codepage_present = payload.len() >= 20;
  let codepage = if codepage_present {
    Some(le_u16_at(payload, 18))
  } else {
    None
  };
  // `$txt = substr($val, 18)` — the text starts at byte 18 (NOT 20); the
  // `vvvv` overlaps the text region for short records, but ExifTool slices the
  // text from offset 18 regardless.
  let text = payload.get(18..).map(string_trim_nulls).unwrap_or_default();
  // `join(' ', @a, $txt)` — @a is the 7 unpacked fields (Purpose already
  // quoted); a missing trailing int16u contributes an empty field.
  let mut out = std::format!("{cue_id} {length} '{purpose}' {country} {language} {dialect}");
  match codepage {
    Some(cp) => out.push_str(&std::format!(" {cp}")),
    None => out.push(' '),
  }
  out.push(' ');
  out.push_str(&text);
  Some(out)
}

/// Walk an `adtl` LIST body (RIFF.pm:437-440 → `%Main`) emitting the
/// `labl`/`note`/`ltxt` cue-point sub-chunks (RIFF.pm:369-390). Each is a
/// `(FOURCC, le-u32 length, payload)` triplet with odd-length padding, like
/// the top-level walker. All three carry `Priority => 0` ("so they are stored
/// in sequence"): the tag NAME (`CuePointLabel`/`CuePointNote`/`LabeledText`)
/// is fixed per sub-chunk type regardless of the embedded cue-point ID, so a
/// second sub-chunk of the same type collides on `(group, name)` and ExifTool
/// keeps the FIRST-extracted. We route every emission through
/// [`push_priority0`] to model that walk-first-wins survivor.
#[cfg(feature = "alloc")]
fn process_chunks_adtl(body: &[u8], entries: &mut Vec<RiffEntry>) {
  let mut p: usize = 0;
  while body.len().saturating_sub(p) >= 8 {
    let tag = fourcc_at(body, p);
    let len = le_u32_at(body, p + 4) as usize;
    let payload_start = p + 8;
    let Some(payload) = body.get(payload_start..payload_start.saturating_add(len)) else {
      break; // declared length runs past the LIST body — stop (faithful skip)
    };
    match &tag {
      b"labl" => {
        if let Some(v) = cue_label_value_conv(payload) {
          push_priority0(entries, "RIFF", "CuePointLabel", RiffValue::Str(v.into()));
        }
      }
      b"note" => {
        if let Some(v) = cue_label_value_conv(payload) {
          push_priority0(entries, "RIFF", "CuePointNote", RiffValue::Str(v.into()));
        }
      }
      b"ltxt" => {
        if let Some(v) = ltxt_value_conv(payload) {
          push_priority0(entries, "RIFF", "LabeledText", RiffValue::Str(v.into()));
        }
      }
      _ => {}
    }
    // Advance past payload + odd-length pad byte (RIFF.pm:2140).
    p = payload_start.saturating_add(len).saturating_add(len & 1);
  }
}

/// `%AVIHeader` — RIFF.pm:1076-1108. `int32u` table at offsets 0/1/4/6/8/9
/// drives FrameRate/MaxDataRate/FrameCount/StreamCount/ImageWidth/Height.
fn emit_avi_header(payload: &[u8], entries: &mut Vec<RiffEntry>) {
  if payload.len() < 40 {
    return;
  }
  // 0: FrameRate — RawConv `$val ? 1e6 / $val : undef` (RIFF.pm:1081-1086).
  let frame_rate_raw = le_u32_at(payload, 0);
  if frame_rate_raw != 0 {
    let fr = 1.0e6_f64 / frame_rate_raw as f64;
    entries.push(RiffEntry::new("RIFF", "FrameRate", RiffValue::F64(fr)));
  }
  // 1: MaxDataRate — int32u (RIFF.pm:1087-1099) with a PrintConv SI-prefix
  // formatter. The raw bytes-per-second value is what we store.
  entries.push(RiffEntry::new(
    "RIFF",
    "MaxDataRate",
    RiffValue::U32(le_u32_at(payload, 4)),
  ));
  // 4: FrameCount (RIFF.pm:1102).
  entries.push(RiffEntry::new(
    "RIFF",
    "FrameCount",
    RiffValue::U32(le_u32_at(payload, 16)),
  ));
  // 6: StreamCount (RIFF.pm:1104).
  entries.push(RiffEntry::new(
    "RIFF",
    "StreamCount",
    RiffValue::U32(le_u32_at(payload, 24)),
  ));
  // 8: ImageWidth (RIFF.pm:1106).
  entries.push(RiffEntry::new(
    "RIFF",
    "ImageWidth",
    RiffValue::U32(le_u32_at(payload, 32)),
  ));
  // 9: ImageHeight (RIFF.pm:1107).
  entries.push(RiffEntry::new(
    "RIFF",
    "ImageHeight",
    RiffValue::U32(le_u32_at(payload, 36)),
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
  let stream_type_bytes: [u8; 4] = fourcc_at(payload, 0);
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
  let codec_bytes: [u8; 4] = fourcc_at(payload, 4);
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
  let r_num = le_u32_at(payload, 20);
  let r_den = le_u32_at(payload, 24);
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
  let count = le_u32_at(payload, 32);
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
    RiffValue::U32(le_u32_at(payload, 40)),
  );
  // 11: SampleSize — int32u at offset 44 (RIFF.pm:1243-1246). PrintConv:
  // `0 -> "Variable"`, else `"$val byte"`/`"s"`.
  push_priority0(
    entries,
    "RIFF",
    "SampleSize",
    RiffValue::U32(le_u32_at(payload, 44)),
  );
  Some(stream_type_bytes)
}

/// Push an entry honoring `Priority => 0` first-wins: if a `(group, name)`
/// pair is already present in `entries`, drop the new value. Used by
/// [`emit_stream_header`] for the `%StreamHeader` table (RIFF.pm:1165), by
/// [`process_chunks_adtl`] for the `labl`/`note`/`ltxt` cue-point tags
/// (RIFF.pm:371-390), and any other table that carries PRIORITY=0.
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
    RiffValue::U32(le_u32_at(payload, 0)),
  ));
  // 4: ImageWidth — int32u (BMP.pm:58-61).
  entries.push(RiffEntry::new(
    "File",
    "ImageWidth",
    RiffValue::U32(le_u32_at(payload, 4)),
  ));
  // 8: ImageHeight — int32s with ValueConv abs() (BMP.pm:62-66).
  let raw_h = le_i32_at(payload, 8);
  let abs_h = raw_h.unsigned_abs();
  entries.push(RiffEntry::new("File", "ImageHeight", RiffValue::U32(abs_h)));
  // 12: Planes — int16u (BMP.pm:67-71).
  entries.push(RiffEntry::new(
    "File",
    "Planes",
    RiffValue::U32(le_u16_at(payload, 12) as u32),
  ));
  // 14: BitDepth — int16u (BMP.pm:72-75).
  entries.push(RiffEntry::new(
    "File",
    "BitDepth",
    RiffValue::U32(le_u16_at(payload, 14) as u32),
  ));
  // 16: Compression — int32u (BMP.pm:76-97). > 256 ⇒ FourCC string;
  // bundled emits `0/1/2/3/4/5` as numeric codes (PrintConv hash) and
  // anything else as ASCII-only via `unpack("A4", pack("V", $val))`.
  let comp_raw = le_u32_at(payload, 16);
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
    RiffValue::U32(le_u32_at(payload, 20)),
  ));
  // 24: PixelsPerMeterX — int32u (BMP.pm:103-106).
  entries.push(RiffEntry::new(
    "File",
    "PixelsPerMeterX",
    RiffValue::U32(le_u32_at(payload, 24)),
  ));
  // 28: PixelsPerMeterY — int32u (BMP.pm:107-110).
  entries.push(RiffEntry::new(
    "File",
    "PixelsPerMeterY",
    RiffValue::U32(le_u32_at(payload, 28)),
  ));
  // 32: NumColors — int32u (BMP.pm:111-115). PrintConv `0 -> "Use BitDepth"`.
  entries.push(RiffEntry::new(
    "File",
    "NumColors",
    RiffValue::U32(le_u32_at(payload, 32)),
  ));
  // 36: NumImportantColors — int32u (BMP.pm:116-121). PrintConv `0 -> "All"`.
  entries.push(RiffEntry::new(
    "File",
    "NumImportantColors",
    RiffValue::U32(le_u32_at(payload, 36)),
  ));
  // BMP V4 / V5 carries more fields after offset 40; the bundled `strf`
  // for AVI virtually always uses V3 (40-byte header) — V4/V5 fields are
  // a follow-up.
}

/// Render BMP `Compression` FourCC bytes (BMP.pm:90-95 `OTHER => sub { ... }`).
/// Non-printable bytes are replaced with `\xNN` escapes; bundled also trims
/// trailing whitespace via `unpack("A4", ...)`.
fn render_fourcc(bytes: &[u8; 4]) -> String {
  use core::fmt::Write as _;
  // bundled: `$val =~ s/([\0-\x1f\x7f-\xff])/sprintf('\\x%.2x',ord $1)/eg`,
  // then implicit `unpack("A4")` trims trailing ASCII spaces.
  // Worst case is 4 escaped bytes (`\xNN` each = 4 chars).
  let mut s = String::with_capacity(bytes.len() * 4);
  for &b in bytes.iter() {
    if !(0x20..0x7f).contains(&b) {
      let _ = write!(&mut s, "\\x{b:02x}");
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
    let val = le_u16_at(body, off);
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
  // each half through numeric context (leading-digit prefix). `.get()` is
  // checked; the `parts.len() != 2` guard above makes both indices present.
  let hi = crate::convert::perl_str_to_f64(parts.first().copied().unwrap_or(""));
  let lo = crate::convert::perl_str_to_f64(parts.get(1).copied().unwrap_or(""));
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
  // Digit positions: 0-3, 5-6, 8-9, 11-12, 14-15, 17-18. (Checked `.get()` —
  // the `len() == 19` guard above makes every index in-range ⇒ byte-identical.)
  let digit = |i: usize| b.get(i).is_some_and(u8::is_ascii_digit);
  let sep = |i: usize, c: u8| b.get(i) == Some(&c);
  let digits_ok = (0..=3).all(digit)
    && [5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
      .iter()
      .all(|&i| digit(i));
  // Separators: ':' at 4,7,13,16 and ' ' at 10.
  digits_ok && sep(4, b':') && sep(7, b':') && sep(10, b' ') && sep(13, b':') && sep(16, b':')
}

// ===========================================================================
// §6. Helpers — `ConvertRIFFDate`, byte readers, string trim
// ===========================================================================

/// Trim trailing NUL bytes from a payload, returning the raw byte slice.
/// Faithful to ProcessChunks RIFF.pm:1827 `$val =~ s/\0+$//`. The CALLER
/// then decodes through the active charset (see [`Charset::decode`]).
fn trim_trailing_nulls(bytes: &[u8]) -> &[u8] {
  let mut end = bytes.len();
  while end > 0 && bytes.get(end - 1) == Some(&0) {
    end -= 1;
  }
  bytes.get(..end).unwrap_or(bytes)
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

  // Standard form: "Mon Mar 10 15:04:43 2003". `.get()` is checked; the
  // `parts.len() >= 5` guard makes indices 1..=4 present ⇒ byte-identical.
  if parts.len() >= 5
    && let Some(mon) = parts.get(1).and_then(|p| month_num(p))
    && let (Some(Ok(day)), Some(year_str)) = (parts.get(2).map(|p| p.parse::<u32>()), parts.get(4))
    && let Ok(year) = year_str.parse::<u32>()
  {
    return std::format!(
      "{year:04}:{mon:02}:{day:02} {}",
      parts.get(3).copied().unwrap_or("")
    );
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
  core::str::from_utf8(bytes.get(start..*i)?)
    .ok()?
    .parse()
    .ok()
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
  core::str::from_utf8(bytes.get(start..*i)?)
    .ok()?
    .parse()
    .ok()
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
  // Slice-pattern (NOT indexing — checked-indexing retrofit, Phase C S2): for
  // every caller `bytes` is a slice of length ≥ 2 (the `le_u16_at` window / a
  // guarded `&buf[a..a+2]`), so this binds the same two bytes `bytes[0..2]` did;
  // the `else` is the unreachable no-panic arm.
  let [a, b, ..] = *bytes else { return 0 };
  u16::from_le_bytes([a, b])
}

#[inline(always)]
fn le_u32(bytes: &[u8]) -> u32 {
  let [a, b, c, d, ..] = *bytes else { return 0 };
  u32::from_le_bytes([a, b, c, d])
}

#[inline(always)]
fn le_i32(bytes: &[u8]) -> i32 {
  let [a, b, c, d, ..] = *bytes else { return 0 };
  i32::from_le_bytes([a, b, c, d])
}

/// Read a little-endian `u16` at byte offset `off` — the checked-indexing form
/// of `le_u16(&buf[off..off + 2])` (Phase C S2). `buf.get(off..off + 2)` early-
/// returns `0` for an out-of-range window (which every CALLER's preceding
/// length guard already excludes ⇒ byte-identical), so no raw slice is taken.
#[inline(always)]
fn le_u16_at(buf: &[u8], off: usize) -> u16 {
  buf.get(off..off.saturating_add(2)).map_or(0, le_u16)
}

/// Read a little-endian `u32` at byte offset `off` — the checked form of
/// `le_u32(&buf[off..off + 4])` (Phase C S2; see [`le_u16_at`]).
#[inline(always)]
fn le_u32_at(buf: &[u8], off: usize) -> u32 {
  buf.get(off..off.saturating_add(4)).map_or(0, le_u32)
}

/// Read a little-endian `i32` at byte offset `off` — the checked form of
/// `le_i32(&buf[off..off + 4])` (Phase C S2; see [`le_u16_at`]).
#[inline(always)]
fn le_i32_at(buf: &[u8], off: usize) -> i32 {
  buf.get(off..off.saturating_add(4)).map_or(0, le_i32)
}

/// Read a 4-byte FourCC at byte offset `off` — the checked form of
/// `buf[off..off + 4].try_into().expect("4 bytes")` (Phase C S2). The window
/// `buf.get(off..off + 4)` is `Some` for every CALLER (a preceding length
/// guard), so `[0; 4]` is the unreachable no-panic fallback ⇒ byte-identical.
#[inline(always)]
fn fourcc_at(buf: &[u8], off: usize) -> [u8; 4] {
  buf
    .get(off..off.saturating_add(4))
    .and_then(|s| <[u8; 4]>::try_from(s).ok())
    .unwrap_or([0; 4])
}

/// Read a little-endian `u64` at byte offset `off` — the checked form of
/// `le_u64(&buf[off..off + 8])` (Phase C S2; see [`le_u16_at`]). Used by the
/// `ds64` `int64u` table (RIFF.pm:762-784).
#[inline(always)]
fn le_u64_at(buf: &[u8], off: usize) -> u64 {
  buf
    .get(off..off.saturating_add(8))
    .and_then(|s| <[u8; 8]>::try_from(s).ok())
    .map_or(0, u64::from_le_bytes)
}

/// Read a signed `int8s` at byte offset `off` — the `inst` chunk's fields
/// (RIFF.pm:824-831, `FORMAT => 'int8s'`). Out-of-range ⇒ `0` (every caller
/// guards the length first ⇒ byte-identical).
#[inline(always)]
fn le_i8_at(buf: &[u8], off: usize) -> i8 {
  buf.get(off).map_or(0, |&b| b as i8)
}

/// Read a little-endian 32-bit `float` at byte offset `off` — the `acid`
/// `Tempo` field (RIFF.pm:1542-1544, `Format => 'float'`). The decoded `f32`
/// is widened to `f64` for [`RiffValue::F64`].
#[inline(always)]
fn le_f32_at(buf: &[u8], off: usize) -> f32 {
  buf
    .get(off..off.saturating_add(4))
    .and_then(|s| <[u8; 4]>::try_from(s).ok())
    .map_or(0.0, f32::from_le_bytes)
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
    // WEBP embedded EXIF/XMP: replay EVERY captured metadata chunk in WALK
    // ORDER (RIFF.pm dispatches each one as it walks, RIFF.pm:557-587). For
    // each chunk, the in-walk minor warning (the `Exif\0\0`-header
    // `Improper EXIF header`, RIFF.pm:567 / the `XMP\0` `Incorrect XMP tag ID`,
    // RIFF.pm:585 — BOTH `$self->Warn(..., 1)`, so `[minor]`-prefixed) precedes
    // that chunk's re-walked sub-Meta diagnostics (the same chunk-then-subdir
    // order PNG's `eXIf` seam uses). With repeated chunks the warnings emit in
    // walk order, matching the `Warning` priority-0 first-extracted-by-position
    // rule. All fire BEFORE the end-of-walk corruption notice.
    for chunk in &self.webp_meta {
      match *chunk {
        #[cfg(feature = "exif")]
        WebpMetaChunk::Exif { block, improper } => {
          if improper {
            out.push(crate::diagnostics::Diagnostic::warn_minor(
              "Improper EXIF header",
            ));
          }
          if let Some(exif_meta) = crate::exif::parse_exif_block(block) {
            out.extend(crate::diagnostics::Diagnose::diagnostics(&exif_meta));
          }
        }
        #[cfg(feature = "xmp")]
        WebpMetaChunk::Xmp {
          packet,
          incorrect_id,
        } => {
          if incorrect_id {
            out.push(crate::diagnostics::Diagnostic::warn_minor(
              "Incorrect XMP tag ID",
            ));
          }
          if let Some(xmp_meta) = crate::formats::xmp::parse_borrowed(packet) {
            out.extend(crate::diagnostics::Diagnose::diagnostics(&xmp_meta));
          }
        }
        #[cfg(not(feature = "exif"))]
        WebpMetaChunk::Exif { .. } => {}
        #[cfg(not(feature = "xmp"))]
        WebpMetaChunk::Xmp { .. } => {}
      }
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
    opts: crate::emit::EmitOptions,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    let mode = opts.mode;
    let print_conv = matches!(mode, crate::emit::ConvMode::PrintConv);
    let mut tags: Vec<crate::emit::EmittedTag> = Vec::with_capacity(self.entries.len());
    for entry in &self.entries {
      tags.push(emit_one(entry, print_conv));
    }
    // Pentax AVI MakerNote (`hymn`/`mknt`, `%Pentax::AVI` → `%Pentax::Main`,
    // `Pentax.pm:6373-6395`): decode the captured payload through the shared
    // `%Pentax::Main` walker at the now-known mode, and emit each leaf under
    // family-0 `MakerNotes`, family-1 `Pentax` (the `%Pentax::Main` `GROUPS`
    // — `exiftool -G1 -j` emits `Pentax:LensType` etc.), mirroring the
    // QuickTime Canon CTMD re-dispatch. ExifTool walks the `LIST_hydt` after
    // the AVI header/stream chunks, so these append AFTER the `RIFF:`/`File:`
    // stream (the conformance gate is object-key-order-insensitive regardless).
    // The engine's central Unknown-suppression drops any `Unknown=>1` leaf, so
    // the flag is carried through verbatim.
    #[cfg(feature = "alloc")]
    if let Some(payload) = self.pentax_makernote.as_deref() {
      let group = crate::value::Group::new("MakerNotes", "Pentax");
      let emissions =
        crate::exif::makernotes::vendors::pentax::redispatch_avi_makernote(payload, print_conv);
      for e in emissions {
        tags.push(crate::emit::EmittedTag::new(
          group.clone(),
          smol_str::SmolStr::new(e.name()),
          e.value().clone(),
          e.unknown(),
        ));
      }
    }
    // Pentax vendor `JUNK` (`PentaxJunk`/`PentaxJunk2`, RIFF.pm:469-478): replay
    // EACH captured chunk in WALK ORDER, decoding it through the variant's tiny
    // `ProcessBinaryData` offset map (`%Pentax::Junk` / `%Pentax::Junk2`,
    // `Pentax.pm:6409` / `:6610`) and emitting each in-range leaf under family-0
    // `MakerNotes`, family-1 `Pentax` (the table `GROUPS` — `exiftool -G1 -j`
    // emits `Pentax:Model` etc.). ExifTool re-runs the SubDirectory on every
    // `JUNK` chunk, so the central `TagMap` resolves a per-tag collision to the
    // LAST-walked chunk (`Priority => 1`); replaying all records keeps the union
    // (a later SHORTER chunk's missing leaves fall back to the earlier chunk's),
    // matching bundled 13.59 (#422). Mode-aware so the `FNumber` `%.1f` PrintConv
    // applies only under `-j`.
    #[cfg(feature = "alloc")]
    for &(variant, payload) in &self.pentax_junk_records {
      emit_pentax_junk(variant, payload, print_conv, &mut tags);
    }
    // `strd` StreamData (`Zora`/`CASI`/`unknown`, `%RIFF::StreamData`,
    // `RIFF.pm:1250-1276`): decode EACH captured payload in WALK ORDER through
    // the matched row's fixed string conversion and emit its leaf. The three
    // ported rows carry NO PrintConv/ValueConv (plain `VendorName`/`Software`/
    // `UnknownData` strings), so the rendering is mode-independent (`-j` ≡ `-n`)
    // — no `print_conv` arg. ExifTool walks the `strd` inside `LIST_strl` (after
    // the `strh`/`strf` siblings), once per stream, so a multi-stream AVI emits
    // one leaf per matched `strd`; a same-named repeat (two `Zora` streams →
    // `RIFF:VendorName` twice) is resolved by the `TagMap` priority-1 duplicate
    // rule downstream (last-walked wins, matching bundled 13.59). Appends after
    // the `RIFF:`/`File:` stream (the conformance gate is key-order-insensitive
    // regardless).
    #[cfg(feature = "alloc")]
    for &(variant, payload) in &self.strd_records {
      emit_strd(variant, payload, &mut tags);
    }
    // WEBP embedded EXIF/XMP (`EXIF`/`Exif` + `XMP `/`XMP\0` chunks,
    // RIFF.pm:557-587): replay EVERY captured chunk in WALK ORDER. Each EXIF
    // chunk's TIFF block is re-walked through the shared `ProcessTIFF` parser
    // ([`crate::exif::parse_exif_block`]) and each XMP packet through the ported
    // XMP module ([`crate::formats::xmp::parse_borrowed`]); their `Taggable`
    // streams splice here, flowing through the same `run_emission` engine —
    // exactly as bundled dispatches each WEBP `EXIF`/`XMP ` SubDirectory to
    // `Exif::Main`/`ProcessTIFF` / `ProcessXMP` (the PNG `eXIf`/raw-profile
    // seams). With repeated chunks, ALL of their distinct tags are retained;
    // the engine's central last-wins dedup resolves a per-tag collision to the
    // LATER (walk-order) chunk, matching bundled (e.g. two `EXIF` chunks
    // carrying `Artist` then `Make` keep both; two carrying `Artist` keep the
    // second's value).
    for chunk in &self.webp_meta {
      match *chunk {
        #[cfg(feature = "exif")]
        WebpMetaChunk::Exif { block, .. } => {
          if let Some(exif_meta) = crate::exif::parse_exif_block(block) {
            tags.extend(exif_meta.tags(opts));
          }
        }
        #[cfg(feature = "xmp")]
        WebpMetaChunk::Xmp { packet, .. } => {
          if let Some(xmp_meta) = crate::formats::xmp::parse_borrowed(packet) {
            tags.extend(xmp_meta.tags(opts));
          }
        }
        #[cfg(not(feature = "exif"))]
        WebpMetaChunk::Exif { .. } => {}
        #[cfg(not(feature = "xmp"))]
        WebpMetaChunk::Xmp { .. } => {}
      }
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
    RiffValue::U64(n) => {
      // PrintConv dispatch for 64-bit values (ds64 `ConvertFileSize`) —
      // applied only in `-j` mode; otherwise the raw `u64` is emitted.
      if print_conv && let Some(printed) = print_conv_u64(name, *n) {
        TagValue::Str(printed.into())
      } else {
        TagValue::U64(*n)
      }
    }
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
  // The WEBP `VP8`/`VP8L` dimension duplicates carry `Priority => 0` so they
  // never override the `VP8X` canvas `ImageWidth`/`ImageHeight` (RIFF.pm:1301/
  // 1312/1329/1340); every other RIFF tag keeps the default `Priority => 1`.
  EmittedTag::new_with_priority(g(), name.into(), value, false, entry.priority())
}

/// `true` iff a `PentaxJunk`/`PentaxJunk2` `JUNK` payload of `payload_len` bytes
/// has AT LEAST ONE in-range fixed-offset leaf — i.e. [`emit_pentax_junk`] would
/// emit something for it. The earliest leaf of each table is a `string[N]`, and
/// `ProcessBinaryData` reaches a leaf whenever its OFFSET is in range
/// (`$more = $size - $entry`, `last if $more <= 0`, `ExifTool.pm:9963-9964`),
/// while a fixed `string` CLAMPS to the available bytes (`ReadValue`,
/// `:6301-6311`) — so the string leaf emits (a partial value) as soon as ONE byte
/// lies past its offset. "Has a leaf" therefore reduces to clearing the SMALLEST
/// leaf's OFFSET (`payload_len > off`), NOT `off + len`:
/// - `Junk`  (`Pentax.pm:6409-6418`): the lone `Model` `string[32]` @ 0x0c ⇒
///   `payload_len > 0x0c` (`>= 13`).
/// - `Junk2` (`Pentax.pm:6610-6658`): the first leaf `Make` `string[24]` @ 0x12 ⇒
///   `payload_len > 0x12` (`>= 19`); every other leaf (`Model` @ 0x2c, `FNumber`
///   @ 0x5e, the `DateTime`s, the thumbnail dims) lies further out, so `Make` is
///   the threshold.
///
/// Used by [`Walker::dispatch_junk`] to drop a signature-only chunk (a 6-byte
/// `IIII\x01\0` or 18-byte `PENTDigital Camera` — both with `payload_len == the
/// leaf offset`, ZERO bytes at the leaf) that matches the condition but emits
/// nothing: replaying it would push a no-output record (memory/CPU amplification
/// on a crafted repeat) yet contribute ZERO leaves, so skipping it is
/// byte-identical to the full replay. A chunk with ≥1 byte at the smallest leaf
/// offset IS retained — it emits a partial (clamped) string, which must
/// participate in the per-leaf last-wins union (#422).
fn pentax_junk_has_in_range_leaf(variant: PentaxJunkVariant, payload_len: usize) -> bool {
  let smallest_leaf_off = match variant {
    // `%Pentax::Junk` (`Pentax.pm:6409-6418`): `Model` `string[32]` @ 0x0c.
    PentaxJunkVariant::Junk => 0x0c,
    // `%Pentax::Junk2` (`Pentax.pm:6610-6658`): `Make` `string[24]` @ 0x12 is the
    // earliest leaf; ≥1 byte past it means at least one leaf is in range.
    PentaxJunkVariant::Junk2 => 0x12,
  };
  // `string` clamps to the available bytes (drops only at ZERO bytes), so the
  // leaf needs `payload_len > off`, i.e. ≥1 byte at the offset.
  payload_len > smallest_leaf_off
}

/// Decode + emit a Pentax vendor `JUNK` payload (`PentaxJunk`/`PentaxJunk2`,
/// RIFF.pm:469-478 → `%Pentax::Junk` / `%Pentax::Junk2`, `Pentax.pm:6409-6418` /
/// `:6610-6658`). Both are `ProcessBinaryData` tables under family-0
/// `MakerNotes`, family-1 `Pentax`; each fixed-offset leaf emits independently
/// iff its offset is in range. A `string[N]` leaf ([`string_field`]) CLAMPS to
/// the available bytes — it emits a PARTIAL value when ≥1 byte lies at its offset,
/// dropping only at ZERO bytes (faithful to `ReadValue`); a numeric leaf
/// (`FNumber` rational, the thumbnail ints) needs its FULL fixed window
/// (`payload.get(off..off+size)`) since `ReadValue` returns `undef` for a partial
/// fixed-width number.
///
/// `FNumber` is a `rational64u` (two LE `int32u`: numerator, denominator) decoded
/// by [`pentax_fnumber_value`] — the `sprintf("%.1f",$val)` PrintConv under `-j`
/// (a bare JSON number, `.0` preserved), the raw quotient / `"inf"`/`"undef"` word
/// under `-n`, with a zero denominator EMITTED (not suppressed) so the derived
/// `Composite:Aperture` follows.
/// `ThumbnailImage` (`PentaxJunk2` 0x133, `undef[$val{0x12f}]` + `ValidateImage`)
/// is the lone DEFERRED leaf (the binary preview needs the `ValidateImage`/
/// Composite-preview path); its dimension siblings (`ThumbnailWidth`/`Height`/
/// `Length`) are plain ints and ARE emitted when in range.
#[cfg(feature = "alloc")]
fn emit_pentax_junk(
  variant: PentaxJunkVariant,
  payload: &[u8],
  print_conv: bool,
  tags: &mut Vec<crate::emit::EmittedTag>,
) {
  use crate::emit::EmittedTag;
  use crate::value::{Group, TagValue};

  // Family-0 `MakerNotes`, family-1 `Pentax` (the `%Pentax::Junk*` `GROUPS`).
  // A free helper (not a `tags`-capturing closure) keeps each push an
  // independent `&mut` borrow.
  fn push_str(
    tags: &mut Vec<EmittedTag>,
    payload: &[u8],
    name: &'static str,
    off: usize,
    len: usize,
  ) {
    if let Some(s) = string_field(payload, off, len) {
      tags.push(EmittedTag::new(
        Group::new("MakerNotes", "Pentax"),
        name.into(),
        TagValue::Str(s.into()),
        false,
      ));
    }
  }
  let group = || Group::new("MakerNotes", "Pentax");

  match variant {
    // `%Pentax::Junk` (`Pentax.pm:6409-6418`): one `Model` `string[32]` @ 0x0c.
    PentaxJunkVariant::Junk => {
      push_str(tags, payload, "Model", 0x0c, 32);
    }
    // `%Pentax::Junk2` (`Pentax.pm:6610-6658`).
    PentaxJunkVariant::Junk2 => {
      // 0x12 Make string[24]; 0x2c Model string[24].
      push_str(tags, payload, "Make", 0x12, 24);
      push_str(tags, payload, "Model", 0x2c, 24);
      // 0x5e FNumber rational64u, PrintConv `sprintf("%.1f",$val)`.
      if let Some(window) = payload.get(0x5e..0x5e + 8) {
        let num = le_u32_at(window, 0);
        let denom = le_u32_at(window, 4);
        if let Some(value) = pentax_fnumber_value(num, denom, print_conv) {
          tags.push(EmittedTag::new(group(), "FNumber".into(), value, false));
        }
      }
      // 0x83 DateTime1 string[24]; 0x9d DateTime2 string[24].
      push_str(tags, payload, "DateTime1", 0x83, 24);
      push_str(tags, payload, "DateTime2", 0x9d, 24);
      // 0x12b ThumbnailWidth int16u; 0x12d ThumbnailHeight int16u;
      // 0x12f ThumbnailLength int32u (the dimension siblings of the deferred
      // 0x133 `ThumbnailImage`). Each emits iff its window is in range.
      if let Some(w) = payload.get(0x12b..0x12b + 2) {
        tags.push(EmittedTag::new(
          group(),
          "ThumbnailWidth".into(),
          TagValue::U64(u64::from(le_u16_at(w, 0))),
          false,
        ));
      }
      if let Some(h) = payload.get(0x12d..0x12d + 2) {
        tags.push(EmittedTag::new(
          group(),
          "ThumbnailHeight".into(),
          TagValue::U64(u64::from(le_u16_at(h, 0))),
          false,
        ));
      }
      if let Some(l) = payload.get(0x12f..0x12f + 4) {
        tags.push(EmittedTag::new(
          group(),
          "ThumbnailLength".into(),
          TagValue::U64(u64::from(le_u32_at(l, 0))),
          false,
        ));
      }
      // 0x133 ThumbnailImage `undef[$val{0x12f}]` + `ValidateImage` — DEFERRED
      // (the binary preview / `ValidateImage` path; out of range for a minimal
      // chunk anyway).
    }
  }
}

/// Emit the single leaf for a matched `strd` (StreamData) chunk
/// (`%RIFF::StreamData`, `RIFF.pm:1250-1276`). Each ported row maps the WHOLE
/// `strd` payload (the 4-byte tag ID INCLUDED — `ProcessStreamData` keeps `Start
/// => $start`, never skipping the tag, `RIFF.pm:1742`) through a fixed string
/// conversion:
///
/// - [`StrdVariant::VendorName`] (`Zora`): a PLAIN tag (no `Format`) ⇒ ExifTool's
///   default string rendering, which DELETES every NUL then `FixUTF8`s
///   ([`crate::convert::escape_json_raw_bytes`] — exactly `EscapeJSON`'s
///   `tr/\0//d` order). Emits `RIFF:VendorName` (family-0/1 `RIFF`). Verified vs
///   bundled 13.59: `Zora` + `AB\0CD\0\0` → `"ZoraABCD"` (internal NUL removed).
/// - [`StrdVariant::CasioData`] (`CASI`): `%Casio::AVI` offset-0 `Software`
///   `Format => 'string'` ⇒ a C-string TRUNCATED at the first NUL then `FixUTF8`
///   ([`string_field`] over the whole payload). Emits `Casio:Software` (family-0
///   `MakerNotes`, family-1 `Casio` — the `%Casio::AVI` `GROUPS`,
///   `Casio.pm:2008`). Verified: `CASI` + `XY\0ZW\0` → `"CASIXY"` (truncated).
/// - [`StrdVariant::UnknownData`] (`unknown` fallback): the value already passed
///   the all-printable `RawConv` ([`unknown_data_raw_conv`]) at capture, so it
///   carries no NUL/control/high byte — emitted verbatim as `RIFF:UnknownData`.
#[cfg(feature = "alloc")]
fn emit_strd(variant: StrdVariant, payload: &[u8], tags: &mut Vec<crate::emit::EmittedTag>) {
  use crate::emit::EmittedTag;
  use crate::value::{Group, TagValue};

  let (group, name, value): (Group, &'static str, String) = match variant {
    // `Zora => 'VendorName'` (`RIFF.pm:1270`). Default-string ⇒ delete-all-NULs.
    StrdVariant::VendorName => (
      Group::new("RIFF", "RIFF"),
      "VendorName",
      crate::convert::escape_json_raw_bytes(payload),
    ),
    // `CASI` → `%Casio::AVI` offset-0 `Software` `Format => 'string'`
    // (`Casio.pm:2011-2014`) ⇒ truncate-at-first-NUL. `string_field` over the
    // whole payload (offset 0, full length) reproduces the C-string read.
    StrdVariant::CasioData => (
      Group::new("MakerNotes", "Casio"),
      "Software",
      string_field(payload, 0, payload.len()).unwrap_or_default(),
    ),
    // `unknown` fallback (`RIFF.pm:1271-1275`). Already all-printable (no NUL),
    // so a verbatim UTF-8 string. `escape_json_raw_bytes` is identity here (no
    // NUL to strip; the bytes are ASCII so `FixUTF8` is a no-op) — used for a
    // single conversion path.
    StrdVariant::UnknownData => (
      Group::new("RIFF", "RIFF"),
      "UnknownData",
      crate::convert::escape_json_raw_bytes(payload),
    ),
  };
  tags.push(EmittedTag::new(
    group,
    name.into(),
    TagValue::Str(value.into()),
    false,
  ));
}

/// `%Pentax::Junk2` `FNumber` (`rational64u`, `PrintConv => 'sprintf("%.1f",$val)'`,
/// `Pentax.pm:6633-6636`) as the [`TagValue`](crate::value::TagValue) for `mode`.
///
/// `$val` is ExifTool's `ReadValue` of the `rational64u` — the
/// `RoundFloat(num/denom, 10)` quotient for a nonzero denominator, or the bare
/// word `"inf"` (numerator ≠ 0) / `"undef"` (`0/0`) for a zero denominator
/// (`ExifTool.pm` `GetRational64u`). Shared with [`crate::value::Rational`] via
/// `exiftool_val_str` so the `$val` text is identical to every other rational.
///
/// * `-n` (`print_conv == false`) → the `$val` LEXEME ITSELF, emitted as a
///   [`Str`](crate::value::TagValue::Str): the exact `RoundFloat(num/denom, 10)`
///   token for a nonzero denominator, or the bare word `"inf"`/`"undef"` for a
///   zero one. The token is an `escape_json_is_number` string, so the production
///   JSON renderer writes it BARE, byte-for-byte (`4/1` → `4`, `4000000001/4` →
///   `1000000000`, `225/100` → `2.25`, `1/3` → `0.3333333333`, `28/10` → `2.8`,
///   AND exponent-form `1/100000` → `1e-05`, `1/30000` → `3.333333333e-05`),
///   while `"inf"`/`"undef"` fail the gate and stay QUOTED. Emitting the LEXEME
///   (not a float the serializer re-renders) preserves every case with NO
///   round-trip — a `serialize_f64`/Ryū re-render of a scientific-notation `$val`
///   diverges (`1e-05` → `0.00001`, `1e-06` → `1e-6`). This is ALSO the value
///   `Composite:Aperture` selects as its operand (the composite resolves `$val[i]`
///   from the ValueConv view): the numeric-string FNumber is Perl-truthy, selected
///   verbatim, and `PrintFNumber` formats it under `-j` (`4` → `4.0`, `0.3333333333`
///   → `0.33`, `1e-05` → `0.00`) / passes it through under `-n`; a zero-denominator
///   FNumber carries the literal `"inf"`/`"undef"` through unchanged.
/// * `-j` (`print_conv == true`) → `sprintf("%.1f",$val)` as a
///   [`Str`](crate::value::TagValue::Str): `format!("{:.1}")` of the RoundFloat'd
///   `$val` (Rust's `{:.1}` is round-HALF-EVEN, byte-identical to Perl's `%.1f` —
///   `225/100` → `"2.2"`, `235/100` → `"2.4"`, `1/3` → `"0.3"`), rendered as a BARE
///   JSON number by the EscapeJSON gate (`4/1` → `4.0`, `.0` PRESERVED). A
///   zero-denominator `$val`
///   numifies through Perl's `%.1f`: `"inf"` → `Inf` → `sprintf("%.1f",Inf)` =
///   `"Inf"` (titlecase, QUOTED, NOT a number); `"undef"` → numeric `0` →
///   `sprintf("%.1f",0)` = `"0.0"` (a bare JSON `0.0`).
///
/// Never returns `None` for an in-range window — a zero-denominator rational is
/// EMITTED (the `"inf"`/`"undef"`/`"Inf"`/`"0.0"` forms), NOT suppressed, matching
/// bundled (which emits `Pentax:FNumber` + the derived `Composite:Aperture` for a
/// degenerate rational). `None` is reserved for a future ValueConv that drops a
/// value, keeping the call site uniform with the other leaves.
#[cfg(feature = "alloc")]
fn pentax_fnumber_value(num: u32, denom: u32, print_conv: bool) -> Option<crate::value::TagValue> {
  use crate::value::{Rational, TagValue};
  // The ExifTool `$val` text (`RoundFloat(n/d, 10)` quotient, or `"inf"`/`"undef"`).
  let rat = Rational::rational64(i64::from(num), i64::from(denom));
  if denom == 0 {
    // `$val` is the bare word `"inf"`/`"undef"` (`exiftool_val_str`).
    let word = rat.exiftool_val_str();
    return Some(if print_conv {
      // `sprintf("%.1f",$val)`: Perl numifies the word — `"inf"` → `Inf` →
      // `"Inf"` (titlecase), `"undef"` → `0` → `"0.0"`.
      TagValue::Str(if num != 0 { "Inf".into() } else { "0.0".into() })
    } else {
      // The raw `$val` word, rendered as a quoted JSON string.
      TagValue::Str(word.into())
    });
  }
  // ExifTool's `$val` for a `rational64u` is `RoundFloat(num/denom, 10)` — the
  // quotient rounded to 10 significant figures (`exiftool_val_str` = `format_g(_,
  // 10)`) — applied BEFORE both the `%.1f` PrintConv AND the `-n`/Composite
  // ValueConv view. This `$val` STRING (ExifTool's exact `ReadValue` token) is the
  // SINGLE source of truth for both views; deriving either from a re-rendered f64
  // loses the token (`format_g(_, 10)` emits scientific notation at exponent < -4
  // with a 2-digit exponent — a tiny `1/100000` is `$val` `1e-05`, but a
  // `serialize_f64` round-trip is `0.00001`; `1/1000000` is `1e-06` but Ryū is
  // `1e-6`; `4000000001/4` raw `1000000000.25` rounds to `1000000000`; `1/3` raw
  // 15-digit rounds to `0.3333333333`).
  let val = rat.exiftool_val_str();
  Some(if print_conv {
    // `sprintf("%.1f",$val)` of the RoundFloat'd value. Numify the `$val` token to
    // the f64 it denotes, then `format!("{:.1}")` (round-HALF-EVEN, matching Perl's
    // `%.1f`); the resulting numeric string (`"4.0"`/`"2.2"`/`"1000000000.0"`/
    // `"0.3"`, and `"0.0"` for a tiny exponent value like `1e-05`) renders as a
    // BARE JSON number through the serializer's EscapeJSON gate, `.0` preserved.
    let rounded: f64 = val
      .parse()
      .unwrap_or_else(|_| f64::from(num) / f64::from(denom));
    TagValue::Str(std::format!("{rounded:.1}").into())
  } else {
    // `-n` / the `Composite:Aperture` ValueConv operand: emit the `$val` LEXEME
    // DIRECTLY (the exact `RoundFloat(num/denom, 10)` token), NOT a float that the
    // serializer re-renders. The token is an `escape_json_is_number` string, so the
    // production JSON renderer (`JsonTagValue` → `RawValue`) writes it BARE,
    // byte-for-byte — preserving every case with no round-trip: WHOLE (`4/1` → `4`,
    // `4000000001/4` → `1000000000`), FRACTIONAL (`225/100` → `2.25`, `1/3` →
    // `0.3333333333`, real `28/10` → `2.8`), and EXPONENT-form (`1/100000` →
    // `1e-05`, `1/30000` → `3.333333333e-05`) — exactly bundled's `-n` token, which
    // a `serialize_f64`/Ryū round-trip of the same value would diverge from. As the
    // `Composite:Aperture` operand it is Perl-truthy (a nonzero numeric string),
    // selected verbatim (`selected_scalar`), and rendered by `PrintFNumber` under
    // `-j` (the `Str` is IsFloat-classified: `4` → `4.0`, `1e-05` → `0.00`) /
    // passed through under `-n` (the bare lexeme).
    TagValue::Str(val.into())
  })
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
    // `acid` `Meter` int16u[2] (RIFF.pm:1536-1540). The ValueConv space-joins
    // the two ints as "DENOMINATOR NUMERATOR" (ReadValue of `int16u[2]`); the
    // PrintConv `$val =~ s/(\d+) (\d+)/$2\/$1/` swaps them to "NUMERATOR/
    // DENOMINATOR". A value not matching `\d+ \d+` passes through unchanged.
    ("RIFF", "Meter") => Some(acidizer_meter_print(val)),
    _ => None,
  }
}

/// `acid` `Meter` PrintConv (RIFF.pm:1539) — `s/(\d+) (\d+)/$2\/$1/`. Swaps
/// the first two whitespace-free decimal runs "A B" → "B/A". A value that
/// does not match the pattern is returned verbatim (faithful to Perl's `s///`
/// no-op on a non-match).
#[cfg(feature = "alloc")]
fn acidizer_meter_print(val: &str) -> String {
  // The stored value is always exactly "DEN NUM" from `read_int16u_pair`; the
  // Perl regex matches the FIRST "\d+ \d+" anywhere in the string and swaps.
  let mut parts = val.splitn(2, ' ');
  if let (Some(a), Some(b)) = (parts.next(), parts.next())
    && !a.is_empty()
    && a.bytes().all(|c| c.is_ascii_digit())
    && !b.is_empty()
    && b.bytes().all(|c| c.is_ascii_digit())
  {
    return std::format!("{b}/{a}");
  }
  val.to_string()
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
    // `acid` Acidizer (RIFF.pm:1500-1545).
    ("RIFF", "AcidizerFlags") => Some(acidizer_flags_print(val)),
    // `RootNote` / `SMPTEFormat` are plain `PrintConv => { ... }` hashes with
    // NO `OTHER`/`PrintHex` (RIFF.pm:1508-1531 / 797-805), so a hash MISS
    // renders ExifTool's generic fallback `Unknown ($val)` with the DECIMAL
    // `$val` (ExifTool.pm:3622), NOT a raw number.
    ("RIFF", "RootNote") => Some(
      acidizer_root_note_label(val).map_or_else(|| std::format!("Unknown ({val})"), str::to_string),
    ),
    // `smpl` Sampler `SMPTEFormat` hash (RIFF.pm:796-805).
    ("RIFF", "SMPTEFormat") => {
      Some(smpte_format_label(val).map_or_else(|| std::format!("Unknown ({val})"), str::to_string))
    }
    // WEBP `VP8X` WebP_Flags BITMASK (RIFF.pm:1361-1367) — DecodeBits over a
    // 32-bit word; `0 => "(none)"`, set bit `n` => label or `"[n]"`, joined ", ".
    ("RIFF", "WebP_Flags") => Some(webp_flags_print(val)),
    // WEBP `VP8 ` VP8Version hash (RIFF.pm:1290-1295). A plain `PrintConv => {}`
    // with no `OTHER` => a hash MISS renders ExifTool's generic `Unknown ($val)`.
    ("RIFF", "VP8Version") => Some(
      webp_vp8_version_label(val).map_or_else(|| std::format!("Unknown ({val})"), str::to_string),
    ),
    // WEBP `ALPH` AlphaPreprocessing hash (RIFF.pm:1474-1477).
    ("RIFF", "AlphaPreprocessing") => Some(
      match val {
        0 => "none",
        1 => "Level Reduction",
        _ => return Some(std::format!("Unknown ({val})")),
      }
      .to_string(),
    ),
    // WEBP `ALPH` AlphaFiltering hash (RIFF.pm:1482-1487).
    ("RIFF", "AlphaFiltering") => Some(
      match val {
        0 => "none",
        1 => "Horizontal",
        2 => "Vertical",
        3 => "Gradient",
        _ => return Some(std::format!("Unknown ({val})")),
      }
      .to_string(),
    ),
    // WEBP `ALPH` AlphaCompression hash (RIFF.pm:1492-1495).
    ("RIFF", "AlphaCompression") => Some(
      match val {
        0 => "none",
        1 => "Lossless",
        _ => return Some(std::format!("Unknown ({val})")),
      }
      .to_string(),
    ),
    // WEBP `VP8L` AlphaIsUsed hash (RIFF.pm:1346).
    ("RIFF", "AlphaIsUsed") => Some(
      match val {
        0 => "No",
        1 => "Yes",
        _ => return Some(std::format!("Unknown ({val})")),
      }
      .to_string(),
    ),
    _ => None,
  }
}

/// PrintConv for `u64`-typed values. The `ds64` `RIFFSize64`/`DataSize64`
/// fields render via `ConvertFileSize` (RIFF.pm:772/778). `NumberOfSamples64`
/// (RIFF.pm:780) and `bext` `TimeReference` (RIFF.pm:739-744) have NO
/// PrintConv ⇒ `None` (raw integer emission).
#[cfg(feature = "alloc")]
fn print_conv_u64(name: &str, val: u64) -> Option<String> {
  match name {
    "RIFFSize64" | "DataSize64" => Some(convert_file_size_decimal(val)),
    _ => None,
  }
}

/// Faithful `ConvertFileSize` (ExifTool.pm:6851-6871), the default decimal
/// (`else`) branch — the `ByteUnit eq 'Binary'` arm is gated on the
/// `ByteUnit` option which this read path does not expose (YAGNI; consistent
/// with the no-options deferrals, mirrors `parser.rs::convert_file_size`).
/// Perl `sprintf("%.1f"/"%.0f", …)` rounds half-to-even on the IEEE-754
/// quotients, byte-identical to Rust `{:.1}`/`{:.0}` (verified vs bundled
/// 13.59: 5000000 → "5.0 MB", 4000000 → "4.0 MB").
#[cfg(feature = "alloc")]
fn convert_file_size_decimal(val: u64) -> String {
  let v = val as f64;
  if val < 2000 {
    std::format!("{val} bytes")
  } else if val < 10000 {
    std::format!("{:.1} kB", v / 1000.0)
  } else if val < 2_000_000 {
    std::format!("{:.0} kB", v / 1000.0)
  } else if val < 10_000_000 {
    std::format!("{:.1} MB", v / 1_000_000.0)
  } else if val < 2_000_000_000 {
    std::format!("{:.0} MB", v / 1_000_000.0)
  } else if val < 10_000_000_000 {
    std::format!("{:.1} GB", v / 1_000_000_000.0)
  } else {
    std::format!("{:.0} GB", v / 1_000_000_000.0)
  }
}

/// `acid` `AcidizerFlags` BITMASK PrintConv (RIFF.pm:1506-1512). DecodeBits
/// over a 32-bit word (default `BitsPerWord`); bit `n` → label or `"[n]"`,
/// joined with `", "`, `0` → `"(none)"`.
#[cfg(feature = "alloc")]
fn acidizer_flags_print(val: u32) -> String {
  const FLAGS: &[(u8, &str)] = &[
    (0, "One shot"),
    (1, "Root note set"),
    (2, "Stretch"),
    (3, "Disk-based"),
    (4, "High octave"),
  ];
  crate::convert::decode_bits(&val.to_string(), Some(FLAGS), 0)
}

/// `VP8X` `WebP_Flags` BITMASK PrintConv (RIFF.pm:1361-1367). DecodeBits over a
/// 32-bit word (default `BitsPerWord`): bit `n` => label or `"[n]"`, joined with
/// `", "`, `0` => `"(none)"`. Bits {1:Animation, 2:XMP, 3:EXIF, 4:Alpha,
/// 5:ICC Profile}.
#[cfg(feature = "alloc")]
fn webp_flags_print(val: u32) -> String {
  const FLAGS: &[(u8, &str)] = &[
    (1, "Animation"),
    (2, "XMP"),
    (3, "EXIF"),
    (4, "Alpha"),
    (5, "ICC Profile"),
  ];
  crate::convert::decode_bits(&val.to_string(), Some(FLAGS), 0)
}

/// `VP8 ` `VP8Version` hash PrintConv (RIFF.pm:1290-1295). The post-Mask
/// (`0x0e >> 1`) reconstruction-method code 0..=3. Returns `None` for an
/// unlisted key; the caller renders the generic `Unknown ($val)` fallback (this
/// plain hash has no `OTHER`/`PrintHex`).
#[cfg(feature = "alloc")]
const fn webp_vp8_version_label(val: u32) -> Option<&'static str> {
  match val {
    0 => Some("0 (bicubic reconstruction, normal loop)"),
    1 => Some("1 (bilinear reconstruction, simple loop)"),
    2 => Some("2 (bilinear reconstruction, no loop)"),
    3 => Some("3 (no reconstruction, no loop)"),
    _ => None,
  }
}

/// `acid` `RootNote` hash PrintConv (RIFF.pm:1517-1530). MIDI note numbers
/// `0x30..=0x47` map to note names (`0x30 => C`, `0x3c => High C`, …). Returns
/// `None` for an unlisted key; the caller renders the generic
/// `Unknown ($val)` fallback (this plain hash has no `OTHER`/`PrintHex`).
#[cfg(feature = "alloc")]
const fn acidizer_root_note_label(val: u32) -> Option<&'static str> {
  Some(match val {
    0x30 => "C",
    0x31 => "C#",
    0x32 => "D",
    0x33 => "D#",
    0x34 => "E",
    0x35 => "F",
    0x36 => "F#",
    0x37 => "G",
    0x38 => "G#",
    0x39 => "A",
    0x3a => "A#",
    0x3b => "B",
    0x3c => "High C",
    0x3d => "High C#",
    0x3e => "High D",
    0x3f => "High D#",
    0x40 => "High E",
    0x41 => "High F",
    0x42 => "High F#",
    0x43 => "High G",
    0x44 => "High G#",
    0x45 => "High A",
    0x46 => "High A#",
    0x47 => "High B",
    _ => return None,
  })
}

/// `smpl` `SMPTEFormat` hash PrintConv (RIFF.pm:798-804). Returns `None` for
/// an unlisted key; the caller renders the generic `Unknown ($val)` fallback
/// (this plain hash has no `OTHER`/`PrintHex`).
#[cfg(feature = "alloc")]
const fn smpte_format_label(val: u32) -> Option<&'static str> {
  Some(match val {
    0 => "none",
    24 => "24 fps",
    25 => "25 fps",
    29 => "29 fps",
    30 => "30 fps",
    _ => return None,
  })
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
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C S2); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
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
  fn strl_stream_type_nul_bearing_fourcc_reassembles_via_escapejson_order() {
    // A crafted `strh` StreamType FourCC whose UTF-8 is SPLIT by an embedded NUL
    // and trailed by a NUL: `C2 00 A9 00`. The raw `strh` StreamType is captured
    // UNTRIMMED (`fourcc_at`, the 4 raw bytes) into `RiffStream::stream_type`.
    // Bundled emits raw on-disk strings through `EscapeJSON`, which DELETES NULs
    // FIRST (`tr/\0//d`, exiftool:3820) then runs `FixUTF8` (exiftool:3824): the
    // NUL-strip rejoins `C2 A9` → `©`. The prior bare `fix_utf8(b"\xc2\x00\xa9\x00")`
    // ran the repair BEFORE the NUL deletion → it flagged the `C2`/`A9` halves
    // separately (the NULs break the sequence) → `"?\0?\0"`. The fix routes
    // through `escape_json_raw_bytes` (NUL-strip → `FixUTF8`) → the faithful `©`.
    //
    // Drive `process_chunks_strl` directly (the `body` it expects begins at the
    // first sub-chunk header, AFTER the `strl` LIST type).
    let mut body = Vec::new();
    body.extend_from_slice(b"strh");
    body.extend_from_slice(&48u32.to_le_bytes());
    body.extend_from_slice(b"\xc2\x00\xa9\x00"); // 0: StreamType (© split + trailed by NUL)
    body.extend_from_slice(&[0u8; 44]); // remaining 44 bytes of the 48-byte strh
    let mut walker = Walker {
      data: &body,
      pos: 0,
      entries: Vec::new(),
      streams: Vec::new(),
      current_stream_type: None,
      charset: Charset::Latin,
      unsupported_charset: None,
      err: false,
      pentax_makernote: None,
      base_file_type: "RIFF",
      form_is_webp: false,
      webp_file_type_override: None,
      webp_ext_override: false,
      webp_meta: Vec::new(),
      pentax_junk_records: Vec::new(),
      strd_records: Vec::new(),
    };
    walker.process_chunks_strl(&body);
    assert_eq!(walker.streams.len(), 1, "one strl → one stream record");
    assert_eq!(
      walker.streams[0].stream_type(),
      Some("©"),
      "NUL-split StreamType is repaired in EscapeJSON order (NUL-strip then FixUTF8)"
    );
  }

  #[test]
  fn strl_stream_type_real_fourcc_is_byte_identical_under_escapejson() {
    // The real all-ASCII 4-byte FourCCs (`vids`/`auds`/…) carry no NUL and are
    // valid UTF-8, so `escape_json_raw_bytes` is identity on them — the captured
    // `stream_type` is byte-identical to the prior `fix_utf8` path (no behavior
    // change for real data), keeping the downstream `TrackKind` match intact.
    let mut body = Vec::new();
    body.extend_from_slice(b"strh");
    body.extend_from_slice(&48u32.to_le_bytes());
    body.extend_from_slice(b"vids"); // 0: StreamType
    body.extend_from_slice(&[0u8; 44]);
    let mut walker = Walker {
      data: &body,
      pos: 0,
      entries: Vec::new(),
      streams: Vec::new(),
      current_stream_type: None,
      charset: Charset::Latin,
      unsupported_charset: None,
      err: false,
      pentax_makernote: None,
      base_file_type: "RIFF",
      form_is_webp: false,
      webp_file_type_override: None,
      webp_ext_override: false,
      webp_meta: Vec::new(),
      pentax_junk_records: Vec::new(),
      strd_records: Vec::new(),
    };
    walker.process_chunks_strl(&body);
    assert_eq!(walker.streams.len(), 1);
    assert_eq!(walker.streams[0].stream_type(), Some("vids"));
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
  fn pentax_avi_hymn_payload_is_borrowed_not_copied() {
    // #157 Codex R1: `process_chunks_hydt` must BORROW the `hymn` payload as a
    // sub-slice of the input, never clone it — else a crafted multi-MB `hymn`
    // in an otherwise-small AVI would double resident memory during parse. Build
    // a `LIST_hydt` body with a large (256 KiB) `hymn` chunk and assert the
    // captured payload points INTO the input buffer (zero-copy), full length.
    const HYMN_LEN: usize = 256 * 1024;
    let mut body = Vec::new();
    body.extend_from_slice(b"hymn");
    body.extend_from_slice(&(HYMN_LEN as u32).to_le_bytes());
    body.resize(body.len() + HYMN_LEN, 0xab); // the large payload
    let mut walker = Walker {
      data: &body,
      pos: 0,
      entries: Vec::new(),
      streams: Vec::new(),
      current_stream_type: None,
      charset: Charset::Latin,
      unsupported_charset: None,
      err: false,
      pentax_makernote: None,
      base_file_type: "RIFF",
      form_is_webp: false,
      webp_file_type_override: None,
      webp_ext_override: false,
      webp_meta: Vec::new(),
      pentax_junk_records: Vec::new(),
      strd_records: Vec::new(),
    };
    walker.process_chunks_hydt(&body);
    let captured = walker
      .pentax_makernote
      .expect("the hymn payload is captured");
    assert_eq!(
      captured.len(),
      HYMN_LEN,
      "the full hymn payload is captured"
    );
    // ZERO-COPY PROOF: the captured slice lives INSIDE the input buffer's
    // address range — a borrow, not an owned second allocation. A reintroduced
    // `.to_vec()` would place it outside this range and fail the assert.
    let base = body.as_ptr() as usize;
    let cap_ptr = captured.as_ptr() as usize;
    assert!(
      cap_ptr >= base && cap_ptr.saturating_add(captured.len()) <= base.saturating_add(body.len()),
      "the captured hymn payload borrows from the input buffer (no copy)"
    );
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
      pentax_makernote: None,
      base_file_type: "RIFF",
      form_is_webp: false,
      webp_file_type_override: None,
      webp_ext_override: false,
      webp_meta: Vec::new(),
      pentax_junk_records: Vec::new(),
      strd_records: Vec::new(),
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

  /// Build a RIFF file: 'RIFF' + size + `form`, then the given chunk bytes.
  fn riff_with(form: &[u8; 4], chunks: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"RIFF");
    buf.extend_from_slice(&0u32.to_le_bytes()); // patched below
    buf.extend_from_slice(form);
    buf.extend_from_slice(chunks);
    let outer = (buf.len() - 8) as u32;
    buf[4..8].copy_from_slice(&outer.to_le_bytes());
    buf
  }

  /// One RIFF chunk: `tag` + LE32 len + body (+ a pad byte for an odd length).
  fn chunk(tag: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(tag);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    if body.len() & 1 == 1 {
      out.push(0);
    }
    out
  }

  #[test]
  fn non_webp_riff_with_vp8x_vp8l_is_not_finalized_as_webp() {
    // #153 Codex R1 (RIFF.pm:2106 / 1332): the `Extended WEBP` `OverrideFileType`
    // is gated on `$type eq 'WEBP'`, so a non-WEBP RIFF (here a WAVE) carrying
    // a top-level `VP8X` must NOT be promoted to WEBP. The (ungated) `VP8L`
    // RawConv appends ` (lossless)` to the CURRENT FileType, but the base type
    // and MIME are preserved. Verified vs bundled 13.59: a WAVE + VP8X + VP8L
    // ⇒ `File:FileType = "WAV (lossless)"`, `File:MIMEType = audio/x-wav`,
    // `File:FileTypeExtension = webp`.
    let vp8x_body = [0u8; 10]; // flags=0, width int24, height int24 (→ 1x1)
    let vp8l_body = [0x2fu8, 0, 0, 0, 0]; // Condition `^\x2f`; width/height/alpha
    let mut chunks = chunk(b"VP8X", &vp8x_body);
    chunks.extend_from_slice(&chunk(b"VP8L", &vp8l_body));
    let bytes = riff_with(b"WAVE", &chunks);
    let meta = parse_borrowed(&bytes).expect("WAVE parses");

    // The VP8X promotion is GATED OUT (form is WAVE, not WEBP); VP8L appends
    // ` (lossless)` to the WAV base. NOT WEBP / Extended WEBP.
    assert_eq!(meta.file_type(), "WAV (lossless)");
    assert!(
      !meta.file_type().contains("WEBP"),
      "a non-WEBP RIFF carrying VP8X/VP8L must not be finalized as WEBP"
    );
    // MIME is unchanged — both OverrideFileType calls pass an undef $mimeType.
    assert_eq!(meta.mime(), "audio/x-wav");
    // The VP8L override fired `OverrideFileType(..., 'webp')` ⇒ webp extension.
    assert!(meta.webp_ext_override());
    // The VP8X tags are still emitted (the chunk is dispatched; only the
    // FileType promotion is gated).
    assert!(
      meta.entries().iter().any(|e| e.name() == "WebP_Flags"),
      "the VP8X chunk still emits its tags on a non-WEBP form"
    );
  }

  #[test]
  fn non_webp_riff_with_only_vp8x_keeps_base_type_and_extension() {
    // #153 Codex R1 corner: a non-WEBP RIFF with ONLY a `VP8X` (no `VP8L`) fires
    // NO `OverrideFileType` at all (the VP8X branch is gated on the WEBP form;
    // no VP8L append). Verified vs bundled 13.59: WAVE + VP8X ⇒ `WAV`,
    // extension `wav`, MIME `audio/x-wav` — i.e. the base type/extension stand.
    let vp8x_body = [0u8; 10];
    let bytes = riff_with(b"WAVE", &chunk(b"VP8X", &vp8x_body));
    let meta = parse_borrowed(&bytes).expect("WAVE parses");
    assert_eq!(meta.file_type(), "WAV");
    assert_eq!(meta.mime(), "audio/x-wav");
    assert!(
      !meta.webp_ext_override(),
      "a gated-out VP8X must NOT apply the webp file-type extension"
    );
  }

  #[test]
  fn private_riff_form_with_vp8l_appends_lossless_to_inert_riff() {
    // #153 Codex R1: an unrecognized RIFF form type (`%riffType` miss) finalizes to
    // the inert `RIFF` base; a `VP8L` chunk appends ` (lossless)` to it — never
    // promoting to WEBP. The MIME is the inert octet-stream fallback.
    let vp8l_body = [0x2fu8, 0, 0, 0, 0];
    let bytes = riff_with(b"ABCD", &chunk(b"VP8L", &vp8l_body));
    let meta = parse_borrowed(&bytes).expect("private RIFF parses");
    assert_eq!(meta.file_type(), "RIFF (lossless)");
    assert!(!meta.file_type().contains("WEBP"));
    assert_eq!(meta.mime(), "application/octet-stream");
  }

  #[test]
  fn webp_with_two_vp8l_chunks_keeps_single_lossless_suffix() {
    // #153 Codex R2 (RIFF.pm:1332): the `VP8L` RawConv re-runs for EVERY valid
    // `VP8L` chunk, and the walker feeds back the PREVIOUS override as the
    // CURRENT FileType. A second walked `VP8L` therefore sees `WEBP (lossless)`
    // (the first override). The append must be IDEMPOTENT — the FileType stays
    // `WEBP (lossless)`, NOT double-suffixed and NOT rewritten to the
    // unrecognized-type `RIFF (lossless)` fallback.
    let vp8l_body = [0x2fu8, 0, 0, 0, 0]; // Condition `^\x2f`
    let mut chunks = chunk(b"VP8L", &vp8l_body);
    chunks.extend_from_slice(&chunk(b"VP8L", &vp8l_body));
    let bytes = riff_with(b"WEBP", &chunks);
    let meta = parse_borrowed(&bytes).expect("WEBP parses");

    // The second VP8L must not corrupt the FileType.
    assert_eq!(meta.file_type(), "WEBP (lossless)");
    assert!(
      !meta.file_type().contains("RIFF"),
      "a second VP8L must NOT rewrite the FileType to RIFF (lossless)"
    );
    assert!(
      !meta.file_type().contains("(lossless) (lossless)"),
      "the ` (lossless)` suffix must be appended at most once"
    );
    assert_eq!(meta.mime(), "image/webp");
  }

  #[test]
  fn non_webp_riff_with_two_vp8l_chunks_keeps_single_lossless_suffix() {
    // #153 Codex R2 (RIFF.pm:1332): same idempotence guarantee for a NON-WEBP
    // form. A WAVE carrying two valid `VP8L` chunks finalizes to `WAV (lossless)`
    // after the first; the second `VP8L` sees `WAV (lossless)` as the current
    // FileType and must leave it UNCHANGED — never collapsing the already-
    // suffixed (non-base) value into `RIFF (lossless)`, never double-appending.
    let vp8l_body = [0x2fu8, 0, 0, 0, 0];
    let mut chunks = chunk(b"VP8L", &vp8l_body);
    chunks.extend_from_slice(&chunk(b"VP8L", &vp8l_body));
    let bytes = riff_with(b"WAVE", &chunks);
    let meta = parse_borrowed(&bytes).expect("WAVE parses");

    assert_eq!(meta.file_type(), "WAV (lossless)");
    assert!(
      !meta.file_type().contains("RIFF"),
      "a second VP8L on a non-WEBP form must NOT rewrite to RIFF (lossless)"
    );
    assert!(
      !meta.file_type().contains("(lossless) (lossless)"),
      "the ` (lossless)` suffix must be appended at most once"
    );
    // MIME stays the WAV form's — the lossless override never touches MIME.
    assert_eq!(meta.mime(), "audio/x-wav");
  }

  #[cfg(feature = "exif")]
  #[test]
  fn repeated_webp_exif_chunks_retain_tags_from_every_chunk() {
    // #153 Codex R1 (RIFF.pm:557-576): RIFF dispatches EVERY `EXIF` chunk it walks,
    // so a WEBP carrying two EXIF chunks — the first with IFD0:Artist, the
    // second with IFD0:Make — must retain BOTH tags (a single Option would drop
    // the first chunk entirely). Verified vs bundled 13.59 (both `IFD0:Artist`
    // and `IFD0:Make` are emitted).
    use crate::emit::{ConvMode, Taggable};
    // A minimal `II*\0` TIFF with one ASCII IFD0 tag `tag_id` = `val` (≤4 bytes,
    // stored inline).
    fn tiff_one_ascii(tag_id: u16, val: &[u8]) -> Vec<u8> {
      assert!(val.len() <= 4);
      let mut t = Vec::new();
      t.extend_from_slice(b"II\x2a\x00");
      t.extend_from_slice(&8u32.to_le_bytes()); // IFD0 at offset 8
      t.extend_from_slice(&1u16.to_le_bytes()); // 1 entry
      t.extend_from_slice(&tag_id.to_le_bytes());
      t.extend_from_slice(&2u16.to_le_bytes()); // type ASCII
      t.extend_from_slice(&(val.len() as u32).to_le_bytes());
      let mut vo = val.to_vec();
      vo.resize(4, 0);
      t.extend_from_slice(&vo);
      t.extend_from_slice(&0u32.to_le_bytes()); // next IFD = 0
      t
    }
    let vp8x_body = [0u8; 10];
    let exif1 = tiff_one_ascii(0x013b, b"AA\x00"); // Artist = "AA"
    let exif2 = tiff_one_ascii(0x010f, b"MK\x00"); // Make = "MK"
    let mut chunks = chunk(b"VP8X", &vp8x_body);
    chunks.extend_from_slice(&chunk(b"EXIF", &exif1));
    chunks.extend_from_slice(&chunk(b"EXIF", &exif2));
    let bytes = riff_with(b"WEBP", &chunks);
    let meta = parse_borrowed(&bytes).expect("WEBP parses");

    let emitted: Vec<_> = meta
      .tags(crate::emit::EmitOptions::g1(ConvMode::PrintConv, false))
      .collect();
    let artist = emitted
      .iter()
      .find(|t| t.tag().name() == "Artist")
      .expect("the FIRST EXIF chunk's IFD0:Artist must survive");
    let make = emitted
      .iter()
      .find(|t| t.tag().name() == "Make")
      .expect("the SECOND EXIF chunk's IFD0:Make must survive");
    assert_eq!(artist.tag().group_ref().family1(), "IFD0");
    assert_eq!(make.tag().group_ref().family1(), "IFD0");
    // The captured-chunk list holds both EXIF chunks, in walk order.
    assert_eq!(meta.webp_meta.len(), 2);
  }

  #[test]
  fn pentax_junk_in_range_leaf_threshold_matches_smallest_leaf_offset() {
    // The predicate clears the SMALLEST leaf's OFFSET (not `off + len`), because
    // a `string[N]` leaf CLAMPS to the available bytes and emits a PARTIAL value
    // as soon as ≥1 byte lies at its offset (ExifTool `ReadValue`,
    // `ExifTool.pm:6301-6311`). `Junk` `Model` @ 0x0c ⇒ `len > 0x0c` (≥13);
    // `Junk2` `Make` @ 0x12 ⇒ `len > 0x12` (≥19). `len == off` (zero bytes at the
    // leaf) has NO leaf; `len == off + 1` (one byte) DOES (a 1-char partial).
    assert!(!pentax_junk_has_in_range_leaf(
      PentaxJunkVariant::Junk,
      0x0c
    )); // 12: off, 0 bytes
    assert!(pentax_junk_has_in_range_leaf(
      PentaxJunkVariant::Junk,
      0x0c + 1
    )); // 13: 1 byte
    assert!(!pentax_junk_has_in_range_leaf(
      PentaxJunkVariant::Junk2,
      0x12
    )); // 18: off, 0 bytes
    assert!(pentax_junk_has_in_range_leaf(
      PentaxJunkVariant::Junk2,
      0x12 + 1
    )); // 19: 1 byte
    // The signature-only crafted payloads (6-byte `IIII\x01\0`, 18-byte
    // `PENTDigital Camera`) are both AT/below the leaf offset (6 ≤ 0x0c, 18 ==
    // 0x12) ⇒ zero bytes at the leaf ⇒ no leaf. (The 18-byte `Junk2` sig is the
    // exact boundary: `18 > 0x12` is FALSE, so it still drops.)
    assert!(!pentax_junk_has_in_range_leaf(PentaxJunkVariant::Junk, 6));
    assert!(!pentax_junk_has_in_range_leaf(PentaxJunkVariant::Junk2, 18));
  }

  #[test]
  fn dispatch_junk_drops_signature_only_chunks_bounding_the_record_vec() {
    // #422 [medium]: a crafted RIFF repeating tiny signature-only Pentax JUNK
    // chunks (6-byte `IIII\x01\0`, 18-byte `PENTDigital Camera`) matches the
    // condition but `emit_pentax_junk` emits NOTHING (every fixed-offset leaf is
    // out of range). The dispatch must NOT retain such no-output records, else a
    // large Vec accumulates with no contribution to the output (memory/CPU
    // amplification). Drive `dispatch_junk` directly with 1000 of each and assert
    // `pentax_junk_records` stays EMPTY.
    let empty: &[u8] = &[];
    let mut walker = Walker {
      data: empty,
      pos: 0,
      entries: Vec::new(),
      streams: Vec::new(),
      current_stream_type: None,
      charset: Charset::Latin,
      unsupported_charset: None,
      err: false,
      pentax_makernote: None,
      base_file_type: "RIFF",
      form_is_webp: false,
      webp_file_type_override: None,
      webp_ext_override: false,
      webp_meta: Vec::new(),
      pentax_junk_records: Vec::new(),
      strd_records: Vec::new(),
    };
    let junk_sig = b"IIII\x01\x00"; // 6 bytes ≤ `Junk` Model offset 0x0c ⇒ 0 bytes at the leaf.
    let junk2_sig = b"PENTDigital Camera"; // 18 bytes == `Junk2` Make offset 0x12 ⇒ 0 bytes at the leaf.
    for _ in 0..1000 {
      walker.dispatch_junk(junk_sig);
      walker.dispatch_junk(junk2_sig);
    }
    assert!(
      walker.pentax_junk_records.is_empty(),
      "signature-only Pentax JUNK chunks (no in-range leaf) must NOT be retained \
       (bounded allocation, no amplification): got {} records",
      walker.pentax_junk_records.len()
    );
  }

  #[test]
  fn dispatch_junk_retains_a_chunk_with_an_in_range_leaf() {
    // The positive control: a chunk with ≥1 byte at the smallest leaf's OFFSET IS
    // retained and replayed (the guard only drops the no-output chunks). The
    // boundary is exactly `len > off`: a 13-byte `Junk` (Model @ 0x0c, 1 byte) and
    // a 19-byte `Junk2` (Make @ 0x12, 1 byte) each produce one record — they emit
    // a 1-char PARTIAL string, so they must participate in the per-leaf last-wins.
    let mut junk = vec![0u8; 0x0c + 1]; // 13 bytes: Model @ 0x0c has exactly 1 byte
    junk[0..4].copy_from_slice(b"IIII");
    junk[4..6].copy_from_slice(b"\x01\x00");
    junk[0x0c] = b'Z';
    let mut junk2 = vec![0u8; 0x12 + 1]; // 19 bytes: Make @ 0x12 has exactly 1 byte
    junk2[0..18].copy_from_slice(b"PENTDigital Camera");
    junk2[0x12] = b'Z';

    let owned = junk.clone();
    let owned2 = junk2.clone();
    let mut walker = Walker {
      data: &owned,
      pos: 0,
      entries: Vec::new(),
      streams: Vec::new(),
      current_stream_type: None,
      charset: Charset::Latin,
      unsupported_charset: None,
      err: false,
      pentax_makernote: None,
      base_file_type: "RIFF",
      form_is_webp: false,
      webp_file_type_override: None,
      webp_ext_override: false,
      webp_meta: Vec::new(),
      pentax_junk_records: Vec::new(),
      strd_records: Vec::new(),
    };
    walker.dispatch_junk(&owned);
    walker.dispatch_junk(&owned2);
    assert_eq!(
      walker.pentax_junk_records.len(),
      2,
      "a chunk with at least one in-range leaf must be retained"
    );
    assert_eq!(walker.pentax_junk_records[0].0, PentaxJunkVariant::Junk);
    assert_eq!(walker.pentax_junk_records[1].0, PentaxJunkVariant::Junk2);
  }

  #[test]
  fn pentax_junk_signature_only_flood_emits_nothing_and_is_bounded_end_to_end() {
    use crate::emit::{ConvMode, Taggable};
    // The full-walk view of #422: an AVI carrying 1000 tiny signature-only
    // Pentax JUNK chunks parses to ZERO retained records and emits NO Pentax
    // leaf — byte-identical to the same AVI with none of those chunks, while the
    // record Vec is bounded (not 1000).
    let mut chunks = Vec::new();
    for _ in 0..1000 {
      chunks.extend_from_slice(&chunk(b"JUNK", b"IIII\x01\x00"));
      chunks.extend_from_slice(&chunk(b"JUNK", b"PENTDigital Camera"));
    }
    let bytes = riff_with(b"AVI ", &chunks);
    let meta = parse_borrowed(&bytes).expect("AVI parses");
    assert!(
      meta.pentax_junk_records.is_empty(),
      "no signature-only chunk is retained: got {} records",
      meta.pentax_junk_records.len()
    );
    let emitted: Vec<_> = meta
      .tags(crate::emit::EmitOptions::g1(ConvMode::PrintConv, false))
      .collect();
    assert!(
      !emitted
        .iter()
        .any(|t| t.tag().group_ref().family1() == "Pentax"),
      "a signature-only JUNK flood must emit no Pentax leaf"
    );

    // The control: one FULL `Junk2` followed by 1000 tiny ones. The full chunk's
    // `Make` is retained + emitted; the tiny chunks add no record (still 1).
    let mut full = vec![0u8; 0x66];
    full[0..18].copy_from_slice(b"PENTDigital Camera");
    full[0x12..0x12 + 6].copy_from_slice(b"PENTAX");
    let mut chunks2 = chunk(b"JUNK", &full);
    for _ in 0..1000 {
      chunks2.extend_from_slice(&chunk(b"JUNK", b"PENTDigital Camera"));
    }
    let bytes2 = riff_with(b"AVI ", &chunks2);
    let meta2 = parse_borrowed(&bytes2).expect("AVI parses");
    assert_eq!(
      meta2.pentax_junk_records.len(),
      1,
      "only the full chunk (with an in-range leaf) is retained; the tiny ones are dropped"
    );
    let emitted2: Vec<_> = meta2
      .tags(crate::emit::EmitOptions::g1(ConvMode::PrintConv, false))
      .collect();
    assert!(
      emitted2
        .iter()
        .any(|t| t.tag().name() == "Make" && t.tag().group_ref().family1() == "Pentax"),
      "the full chunk's Make must still emit"
    );
  }
}
