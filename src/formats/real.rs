// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "real")]
//! Faithful port of `Image::ExifTool::Real` (lib/Image/ExifTool/Real.pm).
//!
//! Reads RealMedia (RM/RV/RMVB), RealAudio (RA), and RealMedia Metafile
//! (RAM/RPM) files. The two file families share one `Image::ExifTool::Real`
//! module in bundled Perl (Real.pm:516-690 `ProcessReal`) and one
//! [`ProcessReal`] ZST here. Magic byte sequences (Real.pm:523):
//!
//! - `.RMF\x00\x00\x00\x12` → RealMedia (RM); chunked container
//!   (PROP / MDPR / CONT / DATA / INDX / RJMD / …).
//! - `.ra\xfd`              → RealAudio (RA); fixed-layout header + ID3 footer.
//! - `pnm://` / `rtsp://` / `http://` → RAM/RPM Metafile (text URLs + titles).
//!
//! The fixture set under `tests/fixtures/Real.{rm,ra}` exercises the RM
//! and RA codepaths; the RAM/RPM Metafile codepath is faithfully ported
//! but not currently covered by a committed fixture (it has no bundled
//! `t/images/Real.ram`).
//!
//! ## RealMedia chunk walk (Real.pm:602-657)
//!
//! After validating the 18-byte RMF header (`.RMF\0\0\0\x12` + 8 more
//! bytes), the parser walks **chunks** of the form:
//!
//! ```text
//! +------+------+--------+------- … --------+
//! | tag  | size | vers   | tag-specific body |
//! | 4 B  | u32  | u16    | (size - 10 bytes) |
//! +------+------+--------+------- … --------+
//! ```
//!
//! The walk stops at the `"DATA"` tag (Real.pm:609) — this port follows the
//! same convention. Each recognized chunk dispatches into a `SubDirectory`
//! sub-parser:
//!
//! - **PROP** → `Image::ExifTool::Real::Properties` (Real.pm:88-113):
//!   `ProcessSerialData`, fixed sequence of int32u/int16u fields
//!   (MaxBitrate / AvgBitrate / MaxPacketSize / AvgPacketSize / NumPackets
//!   / Duration / Preroll / IndexOffset / DataOffset / NumStreams / Flags).
//!   File-type group is `Real-PROP`.
//! - **MDPR** → `Image::ExifTool::Real::MediaProps` (Real.pm:115-183):
//!   `ProcessSerialData`, fixed sequence with embedded variable-length
//!   string fields (StreamName, StreamMimeType) and a conditional logical-
//!   fileinfo sub-table dispatch (Real.pm:139-183). Group is `Real-MDPR`
//!   for the first stream; `Real-MDPR2`/`Real-MDPR3`/… for subsequent
//!   streams (`SET_GROUP1 = '+N'`, Real.pm:632-636).
//! - **CONT** → `Image::ExifTool::Real::ContentDescr` (Real.pm:236-249):
//!   `ProcessSerialData`, 4 length-prefixed strings (Title / Author /
//!   Copyright / Comment). Group is `Real-CONT`.
//!
//! After the chunk walk, the parser scans the file footer (Real.pm:661-688)
//! for a `RMJE...` block carrying the embedded RJMD metadata block, then
//! the optional 128-byte ID3v1 trailer.
//!
//! ## RealAudio fixed header (Real.pm:565-590)
//!
//! For the `.ra\xfd` magic the parser reads a 4-byte preamble (magic +
//! version + 2 reserved) followed by a 512-byte fixed-layout header. The
//! version byte at offset 4-5 selects one of three tag tables:
//!
//! - `vers == 3` → `Real::AudioV3` (Real.pm:270-287)
//! - `vers == 4` → `Real::AudioV4` (Real.pm:289-325) ← fixture's version
//! - `vers == 5` → `Real::AudioV5` (Real.pm:327-350)
//!
//! Each table is read as a `ProcessSerialData` chain of fixed-format scalars
//! and variable-length strings; family-1 group is `Real-RA3`/`Real-RA4`/
//! `Real-RA5` respectively.
//!
//! ## Faithful deferrals (visible)
//!
//! Bundled `perl exiftool` emits `Composite:DateTimeOriginal: 2003` for
//! `Real.rm` — derived from the embedded `ID3v1:Year` via the engine-level
//! Composite synthesis layer. Composite tag synthesis is engine-level (not
//! `Real.pm`); this port FAITHFULLY DEFERS it to a future Phase-3+
//! infrastructure PR, mirroring the precedent set by Red.pm. The golden
//! `tests/golden/Real.rm.{json,n.json}` strips that one Composite line per
//! established precedent.

// Golden-v2 Contract 3c (Phase C, slice w2a): panic-safety by construction —
// every raw index/slice is converted to a checked `.get()` form below.
#![deny(clippy::indexing_slicing)]

use crate::{
  convert::{fix_utf8, write_convert_bitrate},
  datetime::convert_duration as convert_duration_string,
  format_parser::{FormatParser, parser_sealed},
};

// ===========================================================================
// Public re-export — keep all callers anchored on a single canonical name.
// ===========================================================================

// ===========================================================================
// `RealMeta<'a>` — typed metadata
// ===========================================================================

/// Which RealAudio sub-version a `.ra\xfd` header decoded as (Real.pm:577).
///
/// D8 convention: unit-only enum (no fields). Variants are RA3/RA4/RA5 plus
/// a lossless `Other` carrier for the on-disk u16 when the version byte
/// falls outside the bundled-supported {3, 4, 5} set; this round-trips
/// through `-n` output as the raw integer (matching bundled Perl's
/// "Unsupported RealAudio version" Warn + silent skip).
///
/// `#[non_exhaustive]` follows §2: future bundled-Real upstream versions
/// (RA6 etc.) would add new variants here.
#[non_exhaustive]
#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  derive_more::IsVariant,
  derive_more::Unwrap,
  derive_more::TryUnwrap,
)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
pub enum RealAudioVersion {
  /// RA3 — `.ra\xfd 0x0003` (Real.pm:72-73, `Real::AudioV3` table).
  Ra3,
  /// RA4 — `.ra\xfd 0x0004` (Real.pm:73, `Real::AudioV4` table). The
  /// `tests/fixtures/Real.ra` fixture is this version.
  Ra4,
  /// RA5 — `.ra\xfd 0x0005` (Real.pm:74, `Real::AudioV5` table).
  Ra5,
  /// Off-table on-disk version byte (lossless carrier — bundled Perl
  /// `Warn("Unsupported RealAudio version")` and emits no codec tags).
  Other(u16),
}

impl RealAudioVersion {
  /// Decode the on-disk u16 version into the typed variant.
  #[must_use]
  #[inline(always)]
  pub const fn from_raw(v: u16) -> Self {
    match v {
      3 => Self::Ra3,
      4 => Self::Ra4,
      5 => Self::Ra5,
      other => Self::Other(other),
    }
  }

  /// Family-1 group string for this version (e.g. `"Real-RA4"`). Returns
  /// `None` for the [`RealAudioVersion::Other`] arm — no codec table is
  /// dispatched there.
  #[must_use]
  #[inline(always)]
  pub const fn group1(self) -> Option<&'static str> {
    match self {
      Self::Ra3 => Some("Real-RA3"),
      Self::Ra4 => Some("Real-RA4"),
      Self::Ra5 => Some("Real-RA5"),
      Self::Other(_) => None,
    }
  }
}

impl core::fmt::Display for RealAudioVersion {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::Ra3 => f.write_str("RA3"),
      Self::Ra4 => f.write_str("RA4"),
      Self::Ra5 => f.write_str("RA5"),
      Self::Other(v) => write!(f, "RA{v}"),
    }
  }
}

/// Which family of Real file (RM vs RA vs RAM/RPM). D8 unit-only enum.
///
/// `#[non_exhaustive]` for future bundled-Real expansions (e.g. SMIL).
/// Variants are unit-only (§2): RAM and RPM are SEPARATE variants rather
/// than one variant with a bool, so the `derive_more::IsVariant` /
/// `TryUnwrap` derives (which require unit-or-newtype variants) work and
/// the surface stays explicit.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::IsVariant)]
pub enum RealKind {
  /// `.RMF` — RealMedia container (Real.pm:527-529).
  Rm,
  /// `.ra\xfd` — RealAudio fixed-layout header (Real.pm:530-532).
  Ra,
  /// `pnm://` / `rtsp://` / `http://` — RAM Metafile (Real.pm:533-555).
  Ram,
  /// `pnm://` / `rtsp://` / `http://` with a `.RPM` file extension —
  /// RealMedia Plug-in Metafile (Real.pm:536).
  Rpm,
}

impl RealKind {
  /// File-type string passed to `SetFileType` (Real.pm:529/532/536):
  /// `"RM"` / `"RA"` / `"RAM"` / `"RPM"`.
  #[must_use]
  #[inline(always)]
  pub const fn file_type(self) -> &'static str {
    match self {
      Self::Rm => "RM",
      Self::Ra => "RA",
      Self::Ram => "RAM",
      Self::Rpm => "RPM",
    }
  }
}

/// One Real Properties (PROP) sub-stream.
#[derive(Debug, Clone, Default)]
struct PropTags {
  max_bitrate: Option<u32>,
  avg_bitrate: Option<u32>,
  max_packet_size: Option<u32>,
  avg_packet_size: Option<u32>,
  num_packets: Option<u32>,
  duration_ms: Option<u32>,
  preroll_ms: Option<u32>,
  num_streams: Option<u16>,
  flags: Option<u16>,
}

/// One Real MediaProps (MDPR) chunk — repeats once per audio/video/event
/// stream, with optional logical-fileinfo properties (Real.pm:139-182).
#[derive(Debug, Clone, Default)]
struct MdprStream {
  stream_number: Option<u16>,
  stream_max_bitrate: Option<u32>,
  stream_avg_bitrate: Option<u32>,
  stream_max_packet_size: Option<u32>,
  stream_avg_packet_size: Option<u32>,
  stream_start_time: Option<u32>,
  stream_preroll_ms: Option<u32>,
  stream_duration_ms: Option<u32>,
  stream_name: Option<String>,
  stream_mime_type: Option<String>,
  /// `Real-MDPR{N}:FileInfoVersion` — present only when MIME is
  /// `logical-fileinfo` (Real.pm:141 conditional).
  file_info_version: Option<u16>,
  /// Dynamic `(Name, FormattedValue, FormattedValueRaw)` properties from
  /// the logical-fileinfo sub-table (Real.pm:186-234). The "Raw" variant
  /// carries the `-n` form (e.g. ContentRating raw int = `1`); when the
  /// PrintConv is identity the two strings are identical. Stored in
  /// emit order.
  file_info_props: Vec<FileInfoProp>,
}

/// One dynamic logical-fileinfo property.
#[derive(Debug, Clone)]
struct FileInfoProp {
  /// `Real-MDPR{N}:<Name>` — the dynamic-name as derived by Real.pm:196-220.
  /// A short tag identifier (stored, feeds the emitted tag name) ⇒ `SmolStr`.
  name: smol_str::SmolStr,
  /// PrintConv form (`-j`); identical to `value_raw` for identity converters.
  value_print: String,
  /// Post-ValueConv form (`-n`); typically a bare integer string for the
  /// ContentRating hash, the bare date for CreateDate/ModifyDate, the
  /// passthrough value otherwise.
  value_raw: String,
  /// `true` when the bundled `-n` output for this property is a bare JSON
  /// number (the on-disk u32 for the ContentRating PrintConv). Used by the
  /// `serialize_tags` `-n` path to choose a numeric emit over a string.
  emit_raw_as_int: bool,
}

/// One Real ContentDescription (CONT) chunk's 4 length-prefixed strings.
#[derive(Debug, Clone, Default)]
struct ContTags {
  title: Option<String>,
  author: Option<String>,
  copyright: Option<String>,
  comment: Option<String>,
}

/// One Real Metadata (RJMD) tag (Real.pm:252-268).
#[derive(Debug, Clone)]
struct RjmdTag {
  /// Final tag name after `tr/A-Za-z0-9//dc` + `ucfirst` then the Perl
  /// `%Real::Metadata` static-rename table (`Album/Name → AlbumName`,
  /// `Track/Category → TrackCategory`, …). A short tag identifier ⇒ `SmolStr`.
  name: smol_str::SmolStr,
  /// The post-ValueConv string (used for both `-j` and `-n`; the Real
  /// metadata table has no PrintConv toggles).
  value: String,
  /// `true` when the on-disk type was 4 (`int32u`) AND the bundled
  /// `-n`/`-j` output is a bare JSON number rather than a string.
  emit_as_int: bool,
  /// Raw int32u value (only meaningful when `emit_as_int` is `true`).
  raw_int: u32,
}

/// One Real AudioV3/V4/V5 codec field. Emit order is insertion order.
/// Bundled `Real::AudioV*` tables have NO PrintConv toggles (every entry
/// is a pass-through int32u/string), so `-j` and `-n` agree on the value
/// — `value` is the single source of truth for both modes.
#[derive(Debug, Clone)]
struct RaCodecField {
  /// A static codec-field identifier (`"Channels"`, `"Title"`, …) ⇒ `SmolStr`.
  name: smol_str::SmolStr,
  value: String,
  /// `true` when the bundled `-n`/`-j` output is a bare JSON number.
  emit_as_int: bool,
}

/// One line extracted from a RAM/RPM Metafile (Real.pm:551-553). Each
/// non-empty line of the metafile is tagged `url` when it begins with a
/// `[a-z]{3,4}://` URI scheme, else `txt`. Stored in file order; the
/// `serialize_tags` Metafile path replays them through last-wins `insert`,
/// so a metafile with several `url` lines surfaces the LAST as `Real:URL`
/// (verified against bundled `perl exiftool` 13.58: `-G4` shows the final
/// line as the primary instance, earlier lines as `Copy{N}`).
#[derive(Debug, Clone)]
struct MetafileLine {
  /// `true` when the line matched `^[a-z]{3,4}://` (Real.pm:552) ⇒ emitted
  /// as `Real:URL`; `false` ⇒ emitted as `Real:Text`.
  is_url: bool,
  /// The chomped line text (Real.pm:543 `chomp $buff`).
  text: String,
}

/// Typed Real metadata — the lib-first output of [`ProcessReal`].
///
/// Holds:
///
/// - [`kind`](Self::kind): which Real family (RM / RA / Metafile).
/// - [`prop`](Self::prop): the PROP chunk's 9 fields (RM only).
/// - [`mdpr_streams`](Self::mdpr_streams): one entry per MDPR chunk in
///   bundle-emit order (`Real-MDPR`, `Real-MDPR2`, …, `Real-MDPR{N}`).
/// - [`cont`](Self::cont): the CONT chunk's title/author/copyright/comment
///   strings (RM only).
/// - [`rjmd_tags`](Self::rjmd_tags): the RJMD-footer metadata block tags.
/// - [`ra_version`](Self::ra_version) + [`ra_fields`](Self::ra_fields): the
///   RA codec-table fields (RA only).
/// - [`id3v1`](Self::id3v1): the optional 128-byte ID3v1 trailer (RM only).
/// - `metafile_lines`: the RAM/RPM Metafile `url`/`txt` lines (RAM/RPM only).
///
/// **D8 — no public fields, accessors only.**
#[derive(Debug, Clone)]
pub struct RealMeta<'a> {
  kind: RealKind,
  prop: PropTags,
  mdpr_streams: Vec<MdprStream>,
  cont: ContTags,
  rjmd_tags: Vec<RjmdTag>,
  ra_version: Option<RealAudioVersion>,
  ra_fields: Vec<RaCodecField>,
  id3v1: Option<crate::formats::id3::Id3v1Meta<'a>>,
  /// RAM/RPM Metafile `url`/`txt` lines in file order (Real.pm:551-553).
  /// Empty for RM/RA.
  metafile_lines: Vec<MetafileLine>,
  _phantom: core::marker::PhantomData<&'a ()>,
}

impl<'a> RealMeta<'a> {
  /// The Real family (RM / RA / RAM / RPM).
  #[must_use]
  #[inline(always)]
  pub const fn kind(&self) -> RealKind {
    self.kind
  }

  /// `File:MIMEType` override (Real.pm:639-657): when the RM file has
  /// exactly one stream whose `MimeType` is NOT `logical-fileinfo` AND
  /// that MimeType has non-zero length, bundled `ProcessReal` overrides
  /// the engine's table-derived MIMEType with the stream's MimeType.
  /// Returns the override target, or `None` when the override does NOT
  /// fire (multi-stream files, RA, Metafile, or zero non-logical-fileinfo
  /// streams, or every non-logical stream MIME is empty).
  ///
  /// The returned slice is borrowed from the `String` stored on the
  /// matching `MdprStream::stream_mime_type` — but exposed via a
  /// `&'static str` is impossible here (the override target is content-
  /// derived). The accessor returns `Option<&str>` borrowing from
  /// `self`; the engine clones to `String` (used only for the
  /// `File:MIMEType` JSON insertion).
  ///
  /// **Codex R1 F1 — faithful empty-MIME filtering.** Bundled
  /// Real.pm:641 has a `if ($mime)` Perl-falsy guard that drops empty
  /// AND undefined MIMEs BEFORE pushing into `@mimeTypes`. The Rust
  /// filter chain composes the three exclusions (None, `^logical-`,
  /// empty) in exactly the order bundled does (truthy-or-falsy guard
  /// at 641 + `^logical-` filter at 644). Empirically verified on the
  /// synthesized `tests/fixtures/real_synth_2_empty_audio.rm` fixture:
  /// 1 empty + 1 audio stream ⇒ bundled @mimeTypes = ["audio/x-pn-…"]
  /// (length 1) ⇒ override FIRES with `audio/x-pn-realaudio`. The
  /// `mime_override_*` unit tests in this module pin each branch.
  #[must_use]
  pub fn mime_override(&self) -> Option<&str> {
    if !matches!(self.kind, RealKind::Rm) {
      return None;
    }
    // Real.pm:641 `if ($mime)`     — Perl-falsy drops empty/undef MIMEs.
    // Real.pm:644 `push @mimeTypes, $mime unless $mime =~ /^logical-/`.
    // Real.pm:654 `if (@mimeTypes == 1 and length $mimeTypes[0])`.
    //
    // The three composed filters below mirror the bundled exclusion
    // set (commutative composition; the order is chosen for clarity,
    // not faithfulness). The `length $mimeTypes[0]` check at line 654
    // is subsumed by the `!is_empty()` filter — once the falsy guard
    // at 641 has dropped empties, the surviving element cannot be
    // empty, so the `length` check is a tautology here.
    let mut filtered = self
      .mdpr_streams
      .iter()
      .filter_map(|s| s.stream_mime_type.as_deref())
      .filter(|m| !m.starts_with("logical-"))
      .filter(|m| !m.is_empty());
    let first = filtered.next()?;
    if filtered.next().is_some() {
      // More than one non-logical stream ⇒ no override.
      return None;
    }
    Some(first)
  }

  /// `Real-PROP:NumStreams` (RM only). `None` for RA / Metafile.
  #[must_use]
  #[inline(always)]
  pub const fn num_streams(&self) -> Option<u16> {
    self.prop.num_streams
  }

  /// `Real-PROP:Flags` raw u16 bitmask (RM only). The PrintConv form is
  /// rendered via [`Self::flags_print`].
  #[must_use]
  #[inline(always)]
  pub const fn flags_raw(&self) -> Option<u16> {
    self.prop.flags
  }

  /// PrintConv form of `Real-PROP:Flags` (BITMASK, Real.pm:106-112). `None`
  /// when no PROP chunk was decoded.
  #[must_use]
  pub fn flags_print(&self) -> Option<String> {
    self.prop.flags.map(|v| flags_print_conv(u32::from(v)))
  }

  /// `Real-PROP:Duration` in milliseconds (raw int32u; ValueConv divides
  /// by 1000). `None` when no PROP chunk was decoded.
  #[must_use]
  #[inline(always)]
  pub const fn duration_ms(&self) -> Option<u32> {
    self.prop.duration_ms
  }

  /// Number of MDPR sub-streams parsed.
  #[must_use]
  #[inline(always)]
  pub fn stream_count(&self) -> usize {
    self.mdpr_streams.len()
  }

  /// CONT chunk Title (RM only).
  #[must_use]
  pub fn title(&self) -> Option<&str> {
    self.cont.title.as_deref()
  }

  /// CONT chunk Author (RM only).
  #[must_use]
  pub fn author(&self) -> Option<&str> {
    self.cont.author.as_deref()
  }

  /// CONT chunk Copyright (RM only).
  #[must_use]
  pub fn copyright(&self) -> Option<&str> {
    self.cont.copyright.as_deref()
  }

  /// CONT chunk Comment (RM only).
  #[must_use]
  pub fn comment(&self) -> Option<&str> {
    self.cont.comment.as_deref()
  }

  /// RealAudio sub-version (RA only). `None` for RM / Metafile.
  #[must_use]
  #[inline(always)]
  pub const fn ra_version(&self) -> Option<RealAudioVersion> {
    self.ra_version
  }

  /// The optional ID3v1 trailer Meta — set only when the RM footer scan
  /// found a 128-byte `TAG` block (Real.pm:678-687).
  #[must_use]
  pub fn id3v1(&self) -> Option<&crate::formats::id3::Id3v1Meta<'a>> {
    self.id3v1.as_ref()
  }
}

// ===========================================================================
// `ProcessReal` — the lib-first parser
// ===========================================================================

/// Real parser — faithful port of `Image::ExifTool::Real::ProcessReal`
/// (Real.pm:516-690). Handles RM/RA/RAM/RPM via the magic prefix dispatch.
#[derive(Debug, Clone, Copy)]
pub struct ProcessReal;

impl parser_sealed::Sealed for ProcessReal {}

impl FormatParser for ProcessReal {
  /// Leaf format: the Meta borrows from the input `'a` (Codex AF2).
  type Meta<'a> = RealMeta<'a>;
  /// Leaf format Context is `&'a [u8]`.
  type Context<'a> = &'a [u8];
  /// Rust-level fatal error.

  /// Parse a Real file's bytes into a typed [`RealMeta`], or `None` if the
  /// buffer is not a Real file (no magic match — Real.pm:523).
  ///
  /// The leaf-style [`FormatParser::parse`] has no extension channel, so
  /// the Metafile branch sees `ext = None` ⇒ it defaults to `RAM`
  /// (Real.pm:536 `($ext and $ext eq 'RPM')` is false). Callers that
  /// need the RAM-vs-RPM distinction use [`parse_with_ext`] (the engine
  /// dispatch in `AnyParser::parse_any` does).
  fn parse<'a>(&self, data: Self::Context<'a>) -> Option<Self::Meta<'a>> {
    parse_inner(data, None)
  }
}

/// Lib-first direct entry — alias for [`FormatParser::parse`].
///
/// The Metafile branch defaults to `RAM` (no extension channel — see
/// [`parse_with_ext`] for the RAM-vs-RPM-aware entry).
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (currently none — every bad
/// input is `Ok(None)` per Perl `return 0`).
pub fn parse_borrowed(data: &[u8]) -> Option<RealMeta<'_>> {
  parse_inner(data, None)
}

/// Extension-aware Real entry — faithful to `ProcessReal` reading
/// `$$et{FILE_EXT}` (Real.pm:535) to distinguish RAM (default) from RPM.
///
/// `ext` is the uppercased, dotless file extension (`$$self{FILE_EXT}`,
/// ExifTool.pm:2966) — e.g. `Some("RPM")`, `Some("RAM")`, or `None` when
/// the source has no extension. It is consumed only during this call; the
/// returned [`RealMeta`] borrows solely from `data`, so a transient `ext`
/// string may be dropped while the meta lives on.
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (currently none — every bad
/// input is `Ok(None)` per Perl `return 0`).
pub fn parse_with_ext<'a>(data: &'a [u8], ext: Option<&str>) -> Option<RealMeta<'a>> {
  parse_inner(data, ext)
}

fn parse_inner<'a>(data: &'a [u8], ext: Option<&str>) -> Option<RealMeta<'a>> {
  // Real.pm:522 — `$raf->Read($buff,8) == 8`.
  if data.len() < 8 {
    return None;
  }
  // Real.pm:523 — magic dispatch.
  if data.starts_with(b".RMF") {
    return Some(parse_rm(data));
  }
  if data.starts_with(b".ra\xfd") {
    return Some(parse_ra(data));
  }
  if data.starts_with(b"pnm://") || data.starts_with(b"rtsp://") || data.starts_with(b"http://") {
    // Real.pm:533-555 — Metafile branch. `parse_metafile` itself decides
    // acceptance (Real.pm:546 http-URL gate); a rejected buffer returns
    // `Ok(None)` ⇒ `return 0` ⇒ the engine candidate loop continues.
    return parse_metafile(data, ext);
  }
  None
}

// ===========================================================================
// `Real::Properties` (Real.pm:88-113) — PROP chunk ProcessSerialData
// ===========================================================================

/// Read the PROP body as ProcessSerialData with FORMAT='int32u' (Real.pm:92).
/// Field 9 uses `Format => 'int16u'` (Real.pm:102) and field 10 ditto
/// (Real.pm:104-112). All fields are MM (big-endian).
fn parse_prop(body: &[u8]) -> PropTags {
  // `body.get(off..off + N)?` returns `Some` on exactly the same `off + N <=
  // body.len()` condition as the original explicit guard, and `None`
  // otherwise (byte-identical) — the `try_into` over an N-byte slice never fails.
  let read_u32 = |off: usize| -> Option<u32> {
    Some(u32::from_be_bytes(body.get(off..off + 4)?.try_into().ok()?))
  };
  let read_u16 = |off: usize| -> Option<u16> {
    Some(u16::from_be_bytes(body.get(off..off + 2)?.try_into().ok()?))
  };
  // Real.pm:93-105 sequence: 9 × int32u at offsets 0, 4, 8, 12, 16, 20, 24,
  // 28, 32; then int16u NumStreams at 36; then int16u Flags at 38.
  PropTags {
    max_bitrate: read_u32(0),
    avg_bitrate: read_u32(4),
    max_packet_size: read_u32(8),
    avg_packet_size: read_u32(12),
    num_packets: read_u32(16),
    duration_ms: read_u32(20),
    preroll_ms: read_u32(24),
    // `IndexOffset` (off 28) + `DataOffset` (off 32) are `Unknown => 1`
    // (Real.pm:100-101) ⇒ not emitted under default options; we don't
    // need to store them.
    num_streams: read_u16(36),
    flags: read_u16(38),
  }
}

/// Real.pm:103-112 BITMASK ⇒ Allow Recording | Perfect Play | Live | Allow
/// Download. Bundled `DecodeBits` joins set names with `", "` (engine
/// helper, ExifTool.pm:5894-5901); for `Flags = 9` ⇒ bits 0+3 ⇒
/// `"Allow Recording, Allow Download"`.
fn flags_print_conv(raw: u32) -> String {
  const NAMES: &[(u8, &str)] = &[
    (0, "Allow Recording"),
    (1, "Perfect Play"),
    (2, "Live"),
    (3, "Allow Download"),
  ];
  // Faithful `DecodeBits($val, $$conv{BITMASK}, $$tagInfo{BitsPerWord}=16)`.
  let mut parts: Vec<&'static str> = Vec::new();
  for i in 0..16 {
    if (raw & (1 << i)) != 0 {
      match NAMES.iter().find(|(k, _)| *k == i) {
        Some((_, name)) => parts.push(name),
        None => {
          // Fall back to `[N]` faithful to engine helper for off-table
          // bits (this Flags field has no off-table bits in real RM
          // files; defensive).
          let bracketed: &'static str = match i {
            // small set covering 4..=15 to avoid allocation; in
            // practice never hit.
            4 => "[4]",
            5 => "[5]",
            6 => "[6]",
            7 => "[7]",
            8 => "[8]",
            9 => "[9]",
            10 => "[10]",
            11 => "[11]",
            12 => "[12]",
            13 => "[13]",
            14 => "[14]",
            15 => "[15]",
            _ => "[?]",
          };
          parts.push(bracketed);
        }
      }
    }
  }
  if parts.is_empty() {
    "(none)".to_string()
  } else {
    parts.join(", ")
  }
}

// ===========================================================================
// `Real::MediaProps` (Real.pm:115-183) — MDPR chunk ProcessSerialData
// ===========================================================================

/// Read one MDPR body. Faithful to the bundled fixed sequence (Real.pm:
/// 121-182), including the conditional logical-fileinfo sub-table.
fn parse_mdpr(body: &[u8]) -> MdprStream {
  let mut s = MdprStream::default();
  if body.len() < 36 {
    return s;
  }
  // Real.pm:121 — `StreamNumber Format => 'int16u'` at offset 0. The
  // `body.len() < 36` guard above proves offset 0..2 exists, so `.get(0..2)`
  // always hits (byte-identical); the `try_into` over the 2-byte slice never fails.
  s.stream_number = body
    .get(0..2)
    .map(|b| u16::from_be_bytes(b.try_into().unwrap_or_default()));
  // Real.pm:122-127 — five int32u fields. Bundled FORMAT='int32u' applies
  // starting at offset 2 (after the int16u override at field 0). Wait —
  // Perl ProcessSerialData with FORMAT='int32u' but field 0 has
  // `Format => 'int16u'`. So fields 1..7 are int32u starting at offset 2.
  // The closure now returns `Option`: `body.get(off..off + 4)?` yields `Some`
  // on exactly the caller-guaranteed in-bounds offsets (all < 30 ≤ body.len()),
  // and the result feeds the already-`Option` fields unchanged (byte-identical).
  let read_u32 = |off: usize| -> Option<u32> {
    Some(u32::from_be_bytes(body.get(off..off + 4)?.try_into().ok()?))
  };
  s.stream_max_bitrate = read_u32(2);
  s.stream_avg_bitrate = read_u32(6);
  s.stream_max_packet_size = read_u32(10);
  s.stream_avg_packet_size = read_u32(14);
  s.stream_start_time = read_u32(18);
  s.stream_preroll_ms = read_u32(22);
  s.stream_duration_ms = read_u32(26);
  // Real.pm:129 — StreamNameLen int8u at offset 30 (in range per the len≥36
  // guard; the `.get()` failing recovers on the same `return s` path).
  let Some(&stream_name_len_byte) = body.get(30) else {
    return s;
  };
  let stream_name_len = stream_name_len_byte as usize;
  // Real.pm:130 — StreamName string[$val{8}] at offset 31..31+nameLen.
  let mut cursor = 31;
  // `body.get(cursor..cursor + stream_name_len)` is `Some` on exactly the
  // original `cursor + stream_name_len <= body.len()` condition, `None`
  // otherwise (byte-identical: the `else` keeps the same `return s` recovery).
  let Some(name_slice) = body.get(cursor..cursor + stream_name_len) else {
    return s;
  };
  // Real.pm:130 — `Format => 'string[$val{8}]'` ⇒ ReadValue's `s/\0.*//s`
  // first-NUL truncation (ExifTool.pm:6300) applies; see [`null_truncate`].
  s.stream_name = Some(raw_bytes_to_json_string(null_truncate(name_slice)));
  cursor += stream_name_len;
  // Real.pm:131 — StreamMimeLen int8u at next offset (the original
  // `cursor >= body.len()` guard ≡ `.get(cursor)` returning `None`).
  let Some(&stream_mime_len_byte) = body.get(cursor) else {
    return s;
  };
  let stream_mime_len = stream_mime_len_byte as usize;
  cursor += 1;
  // Real.pm:132-136 — StreamMimeType string[$val{10}].
  let Some(mime_slice) = body.get(cursor..cursor + stream_mime_len) else {
    return s;
  };
  // Real.pm:132-136 — `Format => 'string[$val{10}]'` ⇒ ReadValue's
  // first-NUL truncation (ExifTool.pm:6300) applies BEFORE storage.
  // Bundled then runs `$mime =~ s/\0.*//s` AGAIN at Real.pm:643 before
  // pushing to `@mimeTypes`; since both truncations are at the FIRST NUL,
  // applying it once here yields the same value (mime_override sees the
  // truncated form). Codex R2 finding — without this, embedded NULs leak
  // through `Real-MDPR:StreamMimeType` AND `File:MIMEType`.
  s.stream_mime_type = Some(raw_bytes_to_json_string(null_truncate(mime_slice)));
  cursor += stream_mime_len;
  // Real.pm:137 — FileInfoLen int32u (the BE u32 size of the trailing payload).
  if cursor + 4 > body.len() {
    return s;
  }
  // In range per the guard above ⇒ `read_u32` is `Some`; the `else` keeps the
  // same `return s` recovery (byte-identical).
  let Some(file_info_len) = read_u32(cursor) else {
    return s;
  };
  let file_info_len = file_info_len as usize;
  cursor += 4;
  // Real.pm:138-143 — FileInfoLen2 (gates the logical-fileinfo path).
  // Condition: `$self->{RealStreamMime} eq "logical-fileinfo"`. Faithful
  // to the bundled Condition gate (Real.pm:140-141 — if the condition
  // fails, subsequent tags are NOT processed).
  let is_logical_fileinfo = s
    .stream_mime_type
    .as_deref()
    .is_some_and(|m| m == "logical-fileinfo");
  if !is_logical_fileinfo {
    // Bundled: condition fails ⇒ skip the remaining FileInfo* / Physical*
    // tags. Stream emits only the head fields above.
    let _ = file_info_len;
    return s;
  }
  if cursor + 4 > body.len() {
    return s;
  }
  let Some(file_info_len2) = read_u32(cursor) else {
    return s;
  };
  let file_info_len2 = file_info_len2 as usize;
  cursor += 4;
  // Real.pm:144-147 — FileInfoVersion int16u. The `cursor + 2 > body.len()`
  // guard ≡ `.get(cursor..cursor + 2)` returning `None`; the 2-byte `try_into`
  // never fails (byte-identical; same `return s` recovery).
  let Some(fiv) = body.get(cursor..cursor + 2) else {
    return s;
  };
  s.file_info_version = Some(u16::from_be_bytes(fiv.try_into().unwrap_or_default()));
  cursor += 2;
  // Real.pm:148-152 — PhysicalStreams int16u (`Unknown => 1` ⇒ stored only
  // for sizing the next two tags).
  let Some(ps) = body.get(cursor..cursor + 2) else {
    return s;
  };
  let physical_streams = u16::from_be_bytes(ps.try_into().unwrap_or_default()) as usize;
  cursor += 2;
  // Real.pm:153-157 — PhysicalStreamNumbers int16u[$val{15}].
  cursor += physical_streams * 2;
  // Real.pm:158-162 — DataOffsets int32u[$val{15}].
  cursor += physical_streams * 4;
  // Real.pm:163-167 — NumRules int16u.
  let Some(nr) = body.get(cursor..cursor + 2) else {
    return s;
  };
  let num_rules = u16::from_be_bytes(nr.try_into().unwrap_or_default()) as usize;
  cursor += 2;
  // Real.pm:168-172 — PhysicalStreamNumberMap int16u[$val{18}].
  cursor += num_rules * 2;
  // Real.pm:173-177 — NumProperties int16u. (Read but the bundled walk
  // does not actually use it; the FileInfo dynamic walk is bounded by
  // FileInfoLen2 - bookkeeping bytes via the formula at Real.pm:179-182.)
  if cursor + 2 > body.len() {
    return s;
  }
  cursor += 2;
  // Real.pm:178-182 — FileInfoProperties: format
  // `undef[$val{13}-$val{15}*6-$val{18}*2-12]`.
  let prop_len = file_info_len2
    .saturating_sub(physical_streams * 6)
    .saturating_sub(num_rules * 2)
    .saturating_sub(12);
  // (Cursor is past the bookkeeping bytes; the formula's `-12` is the
  // 12 bytes of fixed header BEFORE PhysicalStreams = FileInfoLen(4) +
  // FileInfoLen2(4) + FileInfoVersion(2) + PhysicalStreams(2). The body
  // remaining at `cursor` is `body.len() - cursor` bytes — must contain
  // the FileInfoProperties.)
  let end = cursor.saturating_add(prop_len).min(body.len());
  // `cursor <= body.len()` (the NumProperties guard above proved `cursor + 2 <=
  // body.len()` before `cursor += 2`) and `end = min(cursor + prop_len,
  // body.len()) >= cursor`, so `cursor..end` is a valid in-bounds range and
  // `.get()` always hits (byte-identical; the `else` keeps the `return s` recovery).
  let Some(props) = body.get(cursor..end) else {
    return s;
  };
  s.file_info_props = parse_real_properties(props);
  s
}

/// Decode a raw byte slice to a JSON-friendly Rust [`String`] faithful to
/// bundled `exiftool`'s emission. Bundled Real.pm stores the raw on-disk
/// bytes (no `Decode($val, 'Latin')` is called); the JSON escaper then
/// runs `Image::ExifTool::XMP::FixUTF8` (exiftool:3822), which replaces
/// every invalid UTF-8 byte (and the non-characters U+FFFE/U+FFFF) with
/// ASCII `?`. We reuse the shared [`crate::convert::fix_utf8`] helper so
/// both this format and the engine-level JSON path stay in lock-step.
///
/// Rationale (vs a naive Latin-1 → UTF-8 expansion): bundled-Perl
/// `f\xfcr universelle zusammenh\xe4nge` ⇒ `"f?r universelle zusammenh?nge"`
/// (the on-disk Latin-1 small-u-umlaut + ä become `?`), NOT `"für universelle
/// zusammenhänge"`. The Real.ra fixture is the on-bench-mark for this:
/// `tests/golden/Real.ra.json` shows the bundled `?`-replaced form.
fn raw_bytes_to_json_string(bytes: &[u8]) -> String {
  fix_utf8(bytes)
}

/// Truncate a byte slice at the first NUL byte (everything before it is
/// kept; everything from the NUL onward is dropped). If no NUL exists, the
/// whole slice is returned unchanged.
///
/// This mirrors bundled exiftool's `ReadValue` (ExifTool.pm:6300):
///
/// ```perl
/// $vals[0] =~ s/\0.*//s if $format eq 'string';
/// ```
///
/// — i.e. EVERY field whose `Format => 'string[N]'` (the only format that
/// hits this branch besides bare `string`) is silently first-NUL truncated
/// after the raw `substr` read. Sites in this module that store the result
/// of a `string[N]` Real.pm field MUST use this helper, not a trailing-NUL
/// strip; otherwise embedded NULs leak through to JSON (Codex R2 finding
/// on `Real-MDPR:StreamMimeType`).
///
/// This includes:
///
/// - `Real::MediaProps` (Real.pm:115-183) — `StreamName`, `StreamMimeType`.
/// - `Real::ContentDescr` (Real.pm:236-249) — `Title`, `Author`,
///   `Copyright`, `Comment`.
/// - `Real::AudioV3/V4` (Real.pm:270-325) — `Title`, `Artist`, `Copyright`,
///   `Comment` (handled by [`ra_text_field`]).
/// - `Real::Metadata` RJMD value-string types (Real.pm:31-37 maps types
///   1/2/6/8/7 to `'string'`; ReadValue is what truncates them).
/// - `ProcessRealMeta` tag-name read (Real.pm:450 — the only site where
///   bundled itself spells the regex `s/\0.*//s` explicitly).
///
/// EXCLUDED: `undef[N]` fields (FourCC1/2/3, FileInfoProperties body),
/// where `ReadValue` returns raw bytes WITHOUT truncating at NULs.
fn null_truncate(bytes: &[u8]) -> &[u8] {
  let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
  // `end <= bytes.len()` (it is a `position` index or `bytes.len()`), so
  // `.get(..end)` always hits; `unwrap_or(bytes)` is the unreachable fallback
  // (byte-identical to the raw `&bytes[..end]`).
  bytes.get(..end).unwrap_or(bytes)
}

// ===========================================================================
// `Real::FileInfo` (Real.pm:186-234) — `ProcessRealProperties` (Real.pm:356-417)
// ===========================================================================

/// Faithful port of `ProcessRealProperties` (Real.pm:356-417). Walks
/// length-prefixed NameValueProperty triples; for each one whose version
/// is 0 it reads the type (u32 BE) + valLen (u16 BE) + raw value, maps
/// to a known tag (Real::FileInfo, Real.pm:186-234) or synthesizes a
/// dynamic name (Real.pm:395-399), then applies the matching ValueConv
/// / PrintConv.
fn parse_real_properties(body: &[u8]) -> Vec<FileInfoProp> {
  let mut out: Vec<FileInfoProp> = Vec::new();
  let mut pos: usize = 0;
  while pos + 6 <= body.len() {
    // Real.pm:369 — `($size, $vers) = unpack("x${pos}Nn", $$dataPt)`. The
    // `pos + 6 <= body.len()` loop bound proves this 6-byte window exists, so
    // the destructure always binds (byte-identical; `break` ≡ the loop exit).
    let Some(&[h0, h1, h2, h3, h4, h5]) = body.get(pos..pos + 6) else {
      break;
    };
    let size = u32::from_be_bytes([h0, h1, h2, h3]) as usize;
    let vers = u16::from_be_bytes([h4, h5]);
    // Real.pm:370 — `last if $size < 6`.
    if size < 6 {
      break;
    }
    // Real.pm:371-374 — non-zero version ⇒ skip whole entry.
    if vers != 0 {
      pos = pos.saturating_add(size);
      continue;
    }
    pos += 6;
    // Real.pm:377 — `tagLen = unpack("x${pos}C", $$dataPt)`. The original
    // `pos >= body.len()` guard ≡ `.get(pos)` returning `None` (same `break`).
    let Some(&tag_len_byte) = body.get(pos) else {
      break;
    };
    let tag_len = tag_len_byte as usize;
    pos += 1;
    // Real.pm:380 — `last if $pos + $tagLen > $dirLen` ≡ `.get(pos..pos+tagLen)`
    // returning `None` (byte-identical; same `break`).
    let Some(tag_raw) = body.get(pos..pos + tag_len) else {
      break;
    };
    let tag_str = raw_bytes_to_json_string(null_truncate(tag_raw));
    pos += tag_len;
    // Real.pm:384 — `last if $pos + 6 > $dirLen`. The 6-byte window destructure
    // recovers on the same `break` (byte-identical).
    let Some(&[p0, p1, p2, p3, p4, p5]) = body.get(pos..pos + 6) else {
      break;
    };
    // Real.pm:385 — `($type, $valLen) = unpack("x${pos}Nn", $$dataPt)`.
    let prop_type = u32::from_be_bytes([p0, p1, p2, p3]);
    let val_len = u16::from_be_bytes([p4, p5]) as usize;
    pos += 6;
    // Real.pm:388 — `last if $pos + $valLen > $dirLen` ≡ `.get(pos..pos+valLen)`
    // returning `None` (byte-identical; same `break`).
    let Some(raw_val) = body.get(pos..pos + val_len) else {
      break;
    };
    pos += val_len;
    // Real.pm:389-391 — `format = $propertyType{$type} || 'undef'`;
    // Real::propertyType = ( 0 => 'int32u', 2 => 'string' ).
    // Real.pm:393-400 — `tagInfo` lookup; if absent and the tag name is
    // a valid `\w+` after stripping whitespace ⇒ synthesize.
    let (info_name_opt, found_in_table) = resolve_file_info_tag(&tag_str);
    let Some(info_name) = info_name_opt else {
      // No tag info (off-table + non-`\w+`) ⇒ ExifTool drops it
      // (Real.pm:397 `next unless $tagName =~ /^\w+$/`).
      continue;
    };
    // ContentRating (PrintConv hash); CreateDate/ModifyDate (ValueConv);
    // bare tags (no conv).
    match prop_type {
      0 => {
        // int32u. The `raw_val.len() < 4` guard ≡ `.get(0..4)` returning
        // `None`; the `continue` recovery is byte-identical.
        let Some(&[r0, r1, r2, r3]) = raw_val.get(0..4) else {
          continue;
        };
        let val_u32 = u32::from_be_bytes([r0, r1, r2, r3]);
        if info_name == "ContentRating" {
          let print = content_rating_print(val_u32);
          out.push(FileInfoProp {
            name: info_name.as_str().into(),
            value_print: print.to_string(),
            value_raw: val_u32.to_string(),
            emit_raw_as_int: true,
          });
        } else if info_name == "Indexable" {
          let print = match val_u32 {
            0 => "False",
            1 => "True",
            _ => "",
          };
          out.push(FileInfoProp {
            name: info_name.as_str().into(),
            value_print: print.to_string(),
            value_raw: val_u32.to_string(),
            emit_raw_as_int: true,
          });
        } else {
          let v = val_u32.to_string();
          out.push(FileInfoProp {
            name: info_name.as_str().into(),
            value_print: v.clone(),
            value_raw: v,
            emit_raw_as_int: true,
          });
        }
      }
      2 => {
        // string — Latin-1 decode, NUL-truncated.
        let s = raw_bytes_to_json_string(null_truncate(raw_val));
        let (vc_print, _was_dated) = apply_file_info_value_conv(&info_name, &s, found_in_table);
        out.push(FileInfoProp {
          name: info_name.as_str().into(),
          value_print: vc_print.clone(),
          value_raw: vc_print,
          emit_raw_as_int: false,
        });
      }
      _ => {
        // `undef` format ⇒ bundled `ReadValue` returns the raw bytes
        // joined with ` `; in practice no Real fixture exercises this
        // path through a known tag, so emit a raw Latin-1 decode for
        // future-proofness.
        let s = raw_bytes_to_json_string(raw_val);
        out.push(FileInfoProp {
          name: info_name.as_str().into(),
          value_print: s.clone(),
          value_raw: s,
          emit_raw_as_int: false,
        });
      }
    }
  }
  out
}

/// Real.pm:393-400 — `GetTagInfo` over `%Real::FileInfo` (Real.pm:186-234)
/// or synthesized dynamic name.
///
/// Returns `(Some(name), found_in_table)`.
fn resolve_file_info_tag(tag: &str) -> (Option<String>, bool) {
  // Real.pm:186-234 explicit entries (note: tag-id keys verbatim).
  let static_name = match tag {
    "Indexable" => Some("Indexable"),
    "Keywords" => Some("Keywords"),
    "Description" => Some("Description"),
    "File ID" => Some("FileID"),
    "Content Rating" => Some("ContentRating"),
    "Audiences" => Some("Audiences"),
    "audioMode" => Some("AudioMode"),
    "Creation Date" => Some("CreateDate"),
    "Generated By" => Some("Software"),
    "Modification Date" => Some("ModifyDate"),
    "Target Audiences" => Some("TargetAudiences"),
    "Audio Format" => Some("AudioFormat"),
    "Video Quality" => Some("VideoQuality"),
    "videoMode" => Some("VideoMode"),
    _ => None,
  };
  if let Some(n) = static_name {
    return (Some(n.to_string()), true);
  }
  // Real.pm:395-398 — synthesize: drop whitespace; if remainder is `\w+`
  // ⇒ `ucfirst`; else drop.
  let stripped: String = tag.chars().filter(|c| !c.is_whitespace()).collect();
  if stripped.is_empty() {
    return (None, false);
  }
  // Perl `\w` is `[A-Za-z0-9_]`; we faithfully match.
  let is_wordy = stripped
    .chars()
    .all(|c| c.is_ascii_alphanumeric() || c == '_');
  if !is_wordy {
    return (None, false);
  }
  // ucfirst.
  let mut chars = stripped.chars();
  let first = chars.next().unwrap();
  let name = format!("{}{}", first.to_ascii_uppercase(), chars.as_str());
  (Some(name), false)
}

/// Real.pm:197-208 — ContentRating PrintConv hash.
fn content_rating_print(v: u32) -> &'static str {
  match v {
    0 => "No Rating",
    1 => "All Ages",
    2 => "Older Children",
    3 => "Younger Teens",
    4 => "Older Teens",
    5 => "Adult Supervision Recommended",
    6 => "Adults Only",
    _ => "",
  }
}

/// Real.pm:213-218 / :223-228 — CreateDate / ModifyDate ValueConv.
///
/// `$val =~ m{(\d+)/(\d+)/(\d+)\s+(\d+):(\d+):(\d+)} ?
///  sprintf("%.4d:%.2d:%.2d %.2d:%.2d:%.2d", $3, $2, $1, $4, $5, $6) : $val`.
///
/// Bundled-Perl semantics: `(\d+)` greedily matches one or more digits at
/// each capture, `\s+` is one or more whitespace; on a hit the order is
/// `$3:$2:$1 $4:$5:$6` (Y/M/D + H/M/S). On a miss the input is returned
/// unchanged.
///
/// Returns `(rewritten_value, did_match)`.
fn rewrite_date_mm_dd_yyyy(s: &str) -> (String, bool) {
  // Faithful match: scan for the leftmost position where the m/d/y H:M:S
  // pattern matches greedily. Bundled regex captures variable-width
  // digits (1+) for each numeric field — Real.pm's only producers emit
  // ASCII-only `(\d+)/(\d+)/(\d+) (\d+):(\d+):(\d+)`. We do a simple
  // left-to-right scan.
  let bytes = s.as_bytes();
  // Every `bytes[X]` below sits behind a `X < bytes.len()` (loop) or
  // `X >= bytes.len() || …` (short-circuit) guard, so the `.get(X)` form
  // returns `Some` on exactly the same in-range condition and `None`
  // otherwise — byte-identical (`is_some_and` / `== Some(&b'…')` collapse to
  // the original predicate when in range, and to `false`/`!=` when not).
  // Try every starting position (Perl `m{…}` without anchors is `.*?`-prefixed).
  for start in 0..bytes.len() {
    if !bytes.get(start).is_some_and(u8::is_ascii_digit) {
      continue;
    }
    // Greedy digits.
    let mut i = start;
    while i < bytes.len() && bytes.get(i).is_some_and(u8::is_ascii_digit) {
      i += 1;
    }
    if i >= bytes.len() || bytes.get(i) != Some(&b'/') || i == start {
      continue;
    }
    let g1 = &s[start..i];
    let m_start = i + 1;
    let mut j = m_start;
    while j < bytes.len() && bytes.get(j).is_some_and(u8::is_ascii_digit) {
      j += 1;
    }
    if j >= bytes.len() || bytes.get(j) != Some(&b'/') || j == m_start {
      continue;
    }
    let g2 = &s[m_start..j];
    let d_start = j + 1;
    let mut k = d_start;
    while k < bytes.len() && bytes.get(k).is_some_and(u8::is_ascii_digit) {
      k += 1;
    }
    if k == d_start {
      continue;
    }
    let g3 = &s[d_start..k];
    // Require \s+ then H:M:S.
    let mut ws = k;
    while ws < bytes.len() && bytes.get(ws).is_some_and(u8::is_ascii_whitespace) {
      ws += 1;
    }
    if ws == k {
      continue;
    }
    let h_start = ws;
    let mut l = h_start;
    while l < bytes.len() && bytes.get(l).is_some_and(u8::is_ascii_digit) {
      l += 1;
    }
    if l >= bytes.len() || bytes.get(l) != Some(&b':') || l == h_start {
      continue;
    }
    let g4 = &s[h_start..l];
    let mi_start = l + 1;
    let mut m_idx = mi_start;
    while m_idx < bytes.len() && bytes.get(m_idx).is_some_and(u8::is_ascii_digit) {
      m_idx += 1;
    }
    if m_idx >= bytes.len() || bytes.get(m_idx) != Some(&b':') || m_idx == mi_start {
      continue;
    }
    let g5 = &s[mi_start..m_idx];
    let sec_start = m_idx + 1;
    let mut p = sec_start;
    while p < bytes.len() && bytes.get(p).is_some_and(u8::is_ascii_digit) {
      p += 1;
    }
    if p == sec_start {
      continue;
    }
    let g6 = &s[sec_start..p];
    // Parse to integers (saturate at u32 for `%.4d`; the format is
    // `%.4d:%.2d:%.2d %.2d:%.2d:%.2d` — zero-pad to width.
    let parse_or = |t: &str| t.parse::<u64>().unwrap_or(0);
    let yyyy = parse_or(g3);
    let mm = parse_or(g2);
    let dd = parse_or(g1);
    let hh = parse_or(g4);
    let mi = parse_or(g5);
    let ss = parse_or(g6);
    let out = format!("{yyyy:04}:{mm:02}:{dd:02} {hh:02}:{mi:02}:{ss:02}");
    return (out, true);
  }
  (s.to_string(), false)
}

/// Real.pm CreateDate/ModifyDate ValueConv (Real.pm:213-218 / :223-228).
/// Identity for non-date tags. Returns `(converted_value, was_date_tag)`.
fn apply_file_info_value_conv(name: &str, raw: &str, _found_in_table: bool) -> (String, bool) {
  if matches!(name, "CreateDate" | "ModifyDate") {
    let (v, _matched) = rewrite_date_mm_dd_yyyy(raw);
    return (v, true);
  }
  // Codex round-1 audit: for the bundled fixture every other Real::FileInfo
  // table entry passes through unchanged (no ValueConv beyond the date
  // pair) — and the dynamic synthesized tags are likewise identity.
  (raw.to_string(), false)
}

// ===========================================================================
// `Real::ContentDescr` (Real.pm:236-249) — CONT chunk ProcessSerialData
// ===========================================================================

/// Read the CONT chunk body as 4 length-prefixed Latin-1 strings.
/// FORMAT='int16u' (Real.pm:240).
fn parse_cont(body: &[u8]) -> ContTags {
  let mut c = ContTags::default();
  let mut cursor: usize = 0;
  // `b.get(pos..pos + 2)?` is `Some` on exactly the original `pos + 2 <=
  // b.len()` condition and `None` otherwise (byte-identical); the 2-byte
  // `try_into` never fails.
  let read_len = |b: &[u8], pos: usize| -> Option<usize> {
    Some(u16::from_be_bytes(b.get(pos..pos + 2)?.try_into().ok()?) as usize)
  };
  for (i, field) in [
    &mut c.title,
    &mut c.author,
    &mut c.copyright,
    &mut c.comment,
  ]
  .iter_mut()
  .enumerate()
  {
    let len = match read_len(body, cursor) {
      Some(l) => l,
      None => return c,
    };
    cursor += 2;
    // `body.get(cursor..cursor + len)` is `Some` on exactly the original
    // `cursor + len <= body.len()` condition; `None` ⇒ the same `return c`
    // truncation recovery (byte-identical).
    let Some(field_slice) = body.get(cursor..cursor + len) else {
      // Bundled `ReadValue` returns truncated; we drop to None.
      let _ = i;
      return c;
    };
    // Real.pm:242/244/246/248 — each CONT field is `Format => 'string[…]'`,
    // so ReadValue's first-NUL truncation (ExifTool.pm:6300) applies; see
    // [`null_truncate`].
    let s = raw_bytes_to_json_string(null_truncate(field_slice));
    **field = Some(s);
    cursor += len;
  }
  c
}

// ===========================================================================
// `Real::Metadata` (Real.pm:252-268) — `ProcessRealMeta` (Real.pm:423-510)
// ===========================================================================

/// Faithful port of `ProcessRealMeta` (Real.pm:423-510). Walks the RJMD
/// metadata block recursively (sub-properties via `Prefix`).
fn parse_real_meta(body: &[u8], prefix: &str, out: &mut Vec<RjmdTag>) {
  let dir_len = body.len();
  let mut pos: usize = 0;
  while pos + 28 <= dir_len {
    // Every `read_u32` call site is in range: the 7 header reads sit behind
    // the `pos + 28 <= dir_len` loop bound (`pos..pos+28`), and the
    // value-length read behind the `value_pos + 4 > dir_len` guard below — so
    // `body.get(off..off + 4)` always hits and the `0` fallback is unreachable
    // (byte-identical to the raw 4-byte index).
    let read_u32 = |off: usize| -> u32 {
      body
        .get(off..off + 4)
        .map_or(0, |b| u32::from_be_bytes(b.try_into().unwrap_or([0; 4])))
    };
    // Real.pm:439-440 — 7 × N (u32 BE).
    let size = read_u32(pos) as usize;
    let typ = read_u32(pos + 4);
    let _flags = read_u32(pos + 8);
    let mut value_pos = read_u32(pos + 12) as usize;
    let _sub_prop_pos = read_u32(pos + 16) as usize;
    let num_sub_props = read_u32(pos + 20) as usize;
    let name_len = read_u32(pos + 24) as usize;
    // Real.pm:443-444 — value_pos / sub_prop_pos relative to record start
    // ⇒ make pointers RELATIVE TO DIR START.
    value_pos = value_pos.saturating_add(pos);
    let sub_prop_pos = _sub_prop_pos.saturating_add(pos);
    // Real.pm:445 — `last if $pos + $size > $dirEnd`.
    if pos.saturating_add(size) > dir_len || size < 28 {
      break;
    }
    // Real.pm:446 — `last if $pos + 28 + $nameLen > $dirEnd`.
    if pos + 28 + name_len > dir_len {
      break;
    }
    // Real.pm:447 — `last if $valuePos <  $pos + 28 + $nameLen`.
    if value_pos < pos + 28 + name_len {
      break;
    }
    // Real.pm:448 — `last if $valuePos + 4 > $dirEnd`.
    if value_pos + 4 > dir_len {
      break;
    }
    // Real.pm:449-451 — name read + truncate at first NUL + prefix join. The
    // `pos + 28 + name_len > dir_len` guard above ≡ `.get()` returning `None`
    // (byte-identical; the `else` keeps the same `break` recovery).
    let Some(name_raw) = body.get(pos + 28..pos + 28 + name_len) else {
      break;
    };
    let name_str = raw_bytes_to_json_string(null_truncate(name_raw));
    let full_tag = if prefix.is_empty() {
      name_str
    } else {
      format!("{prefix}/{name_str}")
    };
    // Real.pm:452-454 — valueLen + value_pos shift.
    let value_len = read_u32(value_pos) as usize;
    let value_data_pos = value_pos + 4;
    if value_data_pos + value_len > dir_len {
      break;
    }
    // Real.pm:456 — `format = $metadataFormat{$type}`.
    //   1 => 'string', 2 => 'string', 3 => 'flag', 4 => 'int32u',
    //   5 => 'undef', 6 => 'string', 7 => 'string' (date), 8 => 'string',
    //   9 => undef (grouping), 10 => undef (reference).
    // Real.pm:457-466 — `GetTagInfo`/dynamic-name synthesis. Apply the
    // RJMD-name remap (Real.pm:264-268). `resolve_rjmd_tag` builds the name in
    // a transient `String` (a builder — String per the project rule); the
    // STORED field is a short tag identifier ⇒ `SmolStr`.
    let resolved_name = smol_str::SmolStr::from(resolve_rjmd_tag(&full_tag));
    // Real.pm:468-490 — emit if `$valueLen && $format`.
    if value_len > 0 {
      // The `value_data_pos + value_len > dir_len` guard above ≡ `.get()`
      // returning `None` (byte-identical; same `break` recovery).
      let Some(raw_value) = body.get(value_data_pos..value_data_pos + value_len) else {
        break;
      };
      match typ {
        1 | 2 | 6 | 8 => {
          // string-shaped formats — Latin-1 decode, NUL-trim.
          let s = raw_bytes_to_json_string(null_truncate(raw_value));
          out.push(RjmdTag {
            name: resolved_name,
            value: s,
            emit_as_int: false,
            raw_int: 0,
          });
        }
        3 => {
          // flag: 1 byte (int8u) or 4 bytes (int32u) per Real.pm:470-471.
          // `value_len == 4` ⇒ `raw_value` is 4 bytes (so `.get(0..4)` hits);
          // else `value_len > 0` ⇒ `raw_value` is non-empty (so `.first()`
          // hits). Both `.unwrap_or(0)` fallbacks are unreachable (byte-identical).
          let v: u32 = if value_len == 4 {
            raw_value
              .get(0..4)
              .map_or(0, |b| u32::from_be_bytes(b.try_into().unwrap_or([0; 4])))
          } else {
            raw_value.first().copied().unwrap_or(0) as u32
          };
          out.push(RjmdTag {
            name: resolved_name,
            value: v.to_string(),
            emit_as_int: true,
            raw_int: v,
          });
        }
        4 => {
          // int32u. The `value_len >= 4` guard ⇒ `raw_value` is ≥ 4 bytes, so
          // `.get(0..4)` hits and the `0` fallback is unreachable (byte-identical).
          if value_len >= 4 {
            let v = raw_value
              .get(0..4)
              .map_or(0, |b| u32::from_be_bytes(b.try_into().unwrap_or([0; 4])));
            out.push(RjmdTag {
              name: resolved_name,
              value: v.to_string(),
              emit_as_int: true,
              raw_int: v,
            });
          }
        }
        7 => {
          // date (string YYYYMMDDhhmmss…).
          let raw_s = raw_bytes_to_json_string(null_truncate(raw_value));
          let v = date_value_conv_yyyymmddhhmmss(&raw_s);
          out.push(RjmdTag {
            name: resolved_name,
            value: v,
            emit_as_int: false,
            raw_int: 0,
          });
        }
        _ => {
          // type 5/9/10/etc: bundled emits raw text via ReadValue for
          // type-5 'undef' (joined-byte ints); we emit the Latin-1 decode
          // as best-effort. Types 9/10 have format=undef ⇒ no emit.
          if typ == 5 {
            let s = raw_bytes_to_json_string(raw_value);
            out.push(RjmdTag {
              name: resolved_name,
              value: s,
              emit_as_int: false,
              raw_int: 0,
            });
          }
        }
      }
    }
    // Real.pm:492-502 — sub-properties dispatch.
    if num_sub_props > 0 {
      // dirStart = valuePos + valueLen + numSubProps*8
      let dir_start = value_pos + 4 + value_len + num_sub_props * 8;
      let _ = sub_prop_pos;
      if dir_start <= pos + size {
        // dirLen = pos + size - dirStart. `dir_start <= pos+size <= dir_len`
        // and `sub_end >= dir_start`, so `.get(dir_start..sub_end)` always hits
        // (byte-identical; the `else` recovery skips the sub-dispatch, matching
        // the bundled `last`-style bail on an out-of-range sub-directory).
        let sub_dir_len = (pos + size).saturating_sub(dir_start);
        let sub_end = dir_start.saturating_add(sub_dir_len).min(dir_len);
        if let Some(sub_body) = body.get(dir_start..sub_end) {
          // Recurse with the FULL tag as new prefix (Real.pm:499 `Prefix =>
          // $tag`). Real.pm:451 path stores `$tag = $prefix . $tag` ⇒ already
          // prefix-joined; passing `full_tag` (the assembled prefix-and-self)
          // matches bundled. `name_raw` is the SAME `pos+28..pos+28+name_len`
          // slice already bound above (the literal on-disk name, pre-rename).
          let new_prefix_full = if prefix.is_empty() {
            raw_bytes_to_json_string(null_truncate(name_raw))
          } else {
            format!(
              "{prefix}/{}",
              raw_bytes_to_json_string(null_truncate(name_raw))
            )
          };
          parse_real_meta(sub_body, &new_prefix_full, out);
        }
      }
    }
    // Real.pm:503 — `$pos += $size`.
    pos = pos.saturating_add(size);
  }
}

/// Real.pm:264-268 — `Real::Metadata` table rename. Apply the static
/// `tag/Subtag → CamelCase` map; otherwise pass the `tr/A-Za-z0-9//dc`-
/// stripped form.
fn resolve_rjmd_tag(full_tag: &str) -> String {
  // Real.pm explicit entries.
  match full_tag {
    "Album/Name" => return "AlbumName".to_string(),
    "Track/Category" => return "TrackCategory".to_string(),
    "Track/Comments" => return "TrackComments".to_string(),
    "Track/Lyrics" => return "TrackLyrics".to_string(),
    _ => {}
  }
  // Real.pm:459-462 — dynamic name: strip non-`[A-Za-z0-9]` then `ucfirst`.
  let mut buf = String::with_capacity(full_tag.len());
  for c in full_tag.chars() {
    if c.is_ascii_alphanumeric() {
      buf.push(c);
    }
  }
  if buf.is_empty() {
    return String::new();
  }
  // ucfirst.
  let mut chars = buf.chars();
  let first = chars.next().unwrap().to_ascii_uppercase();
  let mut out = String::with_capacity(buf.len());
  out.push(first);
  out.extend(chars);
  out
}

/// Real.pm:475-478 — date ValueConv `s/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/$1:$2:$3 $4:$5:$6/`.
/// On a miss the input is returned unchanged.
fn date_value_conv_yyyymmddhhmmss(s: &str) -> String {
  let bytes = s.as_bytes();
  if bytes.len() < 14 {
    return s.to_string();
  }
  // Faithful regex anchor: matches at position 0 (no leading `^?` in the
  // Perl). The bundled regex is `/^(\d{4})(\d{2})…/`. The `bytes.len() < 14`
  // guard above proves the 14-byte prefix exists, so `.get(..14)` always hits
  // (byte-identical to the raw `bytes[..14]`).
  if !bytes
    .get(..14)
    .is_some_and(|b| b.iter().all(u8::is_ascii_digit))
  {
    return s.to_string();
  }
  let y = &s[0..4];
  let mo = &s[4..6];
  let d = &s[6..8];
  let h = &s[8..10];
  let mi = &s[10..12];
  let se = &s[12..14];
  let rest = &s[14..];
  format!("{y}:{mo}:{d} {h}:{mi}:{se}{rest}")
}

// ===========================================================================
// RM driver — magic + chunk walk + RJMD footer + ID3v1 trailer
// ===========================================================================

fn parse_rm(data: &[u8]) -> RealMeta<'_> {
  let mut meta = RealMeta {
    kind: RealKind::Rm,
    prop: PropTags::default(),
    mdpr_streams: Vec::new(),
    cont: ContTags::default(),
    rjmd_tags: Vec::new(),
    ra_version: None,
    ra_fields: Vec::new(),
    id3v1: None,
    metafile_lines: Vec::new(),
    _phantom: core::marker::PhantomData,
  };
  // Real.pm:595 — skip rest of RM header: `$size = unpack('x4N', $buff); seek($size-8, 1)`.
  // The 18-byte RMF header is `.RMF \0\0\0\x12 \0\x01\0\0\0\0\0\0\0\x06` —
  // size at offset 4 = 0x12 = 18. We position after the 18-byte header.
  if data.len() < 8 {
    return meta;
  }
  // The `data.len() < 8` guard proves bytes 4..8 exist (byte-identical);
  // the 4-byte `try_into` never fails.
  let Some(size_bytes) = data.get(4..8) else {
    return meta;
  };
  let size = u32::from_be_bytes(size_bytes.try_into().unwrap_or_default()) as usize;
  if size < 8 {
    return meta;
  }
  let mut cursor = size;
  if cursor > data.len() {
    return meta;
  }
  // Real.pm:602-651 — chunk walk. `last if $tag eq 'DATA'` (Real.pm:609).
  while cursor + 10 <= data.len() {
    // The `cursor + 10 <= data.len()` loop bound proves the 8-byte chunk
    // header exists, so the destructure always binds (byte-identical; `break`
    // ≡ the loop exit). `tag` is a `[u8; 4]` array (const indexing, not flagged).
    let Some(&[t0, t1, t2, t3, s0, s1, s2, s3]) = data.get(cursor..cursor + 8) else {
      break;
    };
    let tag = [t0, t1, t2, t3];
    let chunk_size = u32::from_be_bytes([s0, s1, s2, s3]) as usize;
    // Real.pm:606 — null-tag terminator.
    if tag == [0, 0, 0, 0] {
      break;
    }
    // Real.pm:609 — bundled stops at DATA under default verbose.
    if &tag == b"DATA" {
      break;
    }
    // Real.pm:611-614 — bad chunk size guards.
    if (chunk_size & 0x8000_0000) != 0 || chunk_size < 10 {
      break;
    }
    // Read the chunk body (size - 10 bytes after the 10-byte header).
    let body_start = cursor + 10;
    let body_end = cursor.saturating_add(chunk_size).min(data.len());
    if body_start > body_end {
      break;
    }
    // `body_start <= body_end <= data.len()` (the guard above + the `min`),
    // so `.get()` always hits (byte-identical; the `else` keeps the `break`).
    let Some(body) = data.get(body_start..body_end) else {
      break;
    };
    match &tag {
      b"PROP" => {
        meta.prop = parse_prop(body);
      }
      b"MDPR" => {
        meta.mdpr_streams.push(parse_mdpr(body));
      }
      b"CONT" => {
        meta.cont = parse_cont(body);
      }
      // RJMD as a chunk is unusual (Real.pm:62 registers it but the typical
      // RJMD location is the footer). Process it the same way if seen.
      b"RJMD" => {
        // Bundled `RJMD` chunk has identical inner layout; first 4 bytes
        // are version, then the metadata records. The footer-RJMD has 4
        // version bytes of `0000 0001` followed by the records.
        // `body.len() > 4` ⇒ `.get(4..)` is `Some` (byte-identical).
        if let Some(rjmd_body) = body.get(4..) {
          parse_real_meta(rjmd_body, "", &mut meta.rjmd_tags);
        }
      }
      _ => {}
    }
    cursor = cursor.saturating_add(chunk_size);
    if cursor >= data.len() {
      break;
    }
  }
  // Real.pm:661-688 — footer RJMD + ID3v1.
  parse_rm_footer(data, &mut meta);
  meta
}

/// Real.pm:661-688 — footer scan: `seek(-140, 2) ; read(12) ; /^RMJE/ ;
/// metaSize = unpack('x8N', $buff) ; seek(-metaSize-12, 1) ;
/// read($metaSize) ; /^RJMD/ ; ProcessRealMeta(DirStart=8, DirLen=size-8)`.
/// Then `seek(-128, 2) ; read(128) ; /^TAG/ ; ID3v1 decode`.
fn parse_rm_footer<'a>(data: &'a [u8], meta: &mut RealMeta<'a>) {
  let n = data.len();
  // Footer needs ≥ 140 bytes for the RMJE scan and ≥ 128 for ID3v1.
  if n < 140 {
    return;
  }
  // RMJE marker at offset n-140; read 12 bytes there. The `n < 140` guard
  // proves `rmje_off..rmje_off + 12` (= `n-140 .. n-128`) is in range, so
  // `.get()` always hits (byte-identical; the `else` skips the RMJE scan).
  let rmje_off = n - 140;
  if let Some(rmje_buf) = data.get(rmje_off..rmje_off + 12)
    && rmje_buf.starts_with(b"RMJE")
  {
    // metaSize = unpack('x8N') ⇒ u32 BE at byte 8 within the 12-byte buf;
    // `rmje_buf` is exactly 12 bytes so `.get(8..12)` always hits.
    let meta_size = rmje_buf
      .get(8..12)
      .map_or(0, |b| u32::from_be_bytes(b.try_into().unwrap_or_default()))
      as usize;
    // Current file pos after reading 12 bytes = n-140+12 = n-128. Seek
    // back -metaSize-12 ⇒ n-128 - meta_size - 12 = n - 140 - meta_size.
    if meta_size > 0 && rmje_off >= meta_size {
      let rjmd_off = rmje_off - meta_size;
      // `rjmd_off + meta_size == rmje_off <= n`, so this range is in bounds;
      // `.get()` always hits (byte-identical; the `if let` keeps ID3v1 running).
      if let Some(rjmd_buf) = data.get(rjmd_off..rjmd_off + meta_size) {
        // Real.pm:665 — `$buff =~ /^RJMD/`. Real.pm:670 — DirStart=8.
        if rjmd_buf.starts_with(b"RJMD")
          && meta_size > 8
          && let Some(rjmd_body) = rjmd_buf.get(8..)
        {
          parse_real_meta(rjmd_body, "", &mut meta.rjmd_tags);
        }
      }
    }
  }
  // ID3v1 trailer.
  if n >= 128 {
    let id3_off = n - 128;
    // `id3_off == n-128 <= n`, so `.get(id3_off..)` always hits (byte-identical).
    let Some(id3_buf) = data.get(id3_off..) else {
      return;
    };
    if id3_buf.starts_with(b"TAG") {
      // Parse via the ID3v1 module. We construct a fresh `Metadata` sink
      // and pluck the per-tag values out. The Id3v1Meta type lives in
      // `formats::id3::process` and is normally produced by the ID3
      // engine; here we synthesize it via the typed-Meta helpers.
      meta.id3v1 = crate::formats::id3::parse_id3v1_from_block(id3_buf);
    }
  }
}

// ===========================================================================
// RA driver — `.ra\xfd` 4-byte preamble + 512-byte header
// ===========================================================================

fn parse_ra(data: &[u8]) -> RealMeta<'_> {
  let mut meta = RealMeta {
    kind: RealKind::Ra,
    prop: PropTags::default(),
    mdpr_streams: Vec::new(),
    cont: ContTags::default(),
    rjmd_tags: Vec::new(),
    ra_version: None,
    ra_fields: Vec::new(),
    id3v1: None,
    metafile_lines: Vec::new(),
    _phantom: core::marker::PhantomData,
  };
  // Real.pm:566 — `($vers, $extra) = unpack('x4nn', $buff)`. Vers at
  // offset 4..6 of the file (after `.ra\xfd`).
  if data.len() < 8 {
    return meta;
  }
  // The `data.len() < 8` guard proves bytes 4..8 exist, so the destructure
  // always binds (byte-identical; `else` keeps the `return meta` recovery).
  let Some(&[_, _, _, _, v0, v1, e0, e1]) = data.get(0..8) else {
    return meta;
  };
  let vers = u16::from_be_bytes([v0, v1]);
  let _extra = u16::from_be_bytes([e0, e1]);
  let raver = RealAudioVersion::from_raw(vers);
  meta.ra_version = Some(raver);
  // Real.pm:569 — read up to 512 bytes starting at position 8 (after the
  // 8-byte preamble: magic+vers+extra). `data.len() > 8` ⇒ `8 <=
  // data.len().min(520) <= data.len()`, so `.get()` always hits (byte-identical).
  let header = if data.len() > 8 {
    match data.get(8..data.len().min(8 + 512)) {
      Some(h) => h,
      None => return meta,
    }
  } else {
    return meta;
  };
  match raver {
    RealAudioVersion::Ra3 => parse_ra3(header, &mut meta),
    RealAudioVersion::Ra4 => parse_ra4(header, &mut meta),
    RealAudioVersion::Ra5 => parse_ra5(header, &mut meta),
    RealAudioVersion::Other(_) => {
      // Bundled `Warn('Unsupported RealAudio version')` ⇒ no codec tags.
    }
  }
  meta
}

/// Format a u32 as either the unsigned-decimal integer (when `>=0`) or the
/// signed-decimal representation (matching Perl's int32u rendering — the
/// bundled fixtures only emit non-negative values).
fn fmt_u32(v: u32) -> String {
  v.to_string()
}

// ── Real::AudioV3 (Real.pm:270-287) ────────────────────────────────────────

fn parse_ra3(header: &[u8], meta: &mut RealMeta<'_>) {
  // FORMAT='int8u' default but every emitted field declares its own format.
  // Field 0 Channels int16u, Field 2 BytesPerMinute int16u, Field 3
  // AudioBytes int32u, Field 4 TitleLen int8u, Field 5 Title string[len],
  // Field 6 ArtistLen int8u, Field 7 Artist string[len], Field 8
  // CopyrightLen int8u, Field 9 Copyright string[len], Field 10 CommentLen
  // int8u, Field 11 Comment string[len].
  //
  // Field 1 (Unknown int16u[3]) is `Unknown => 1` ⇒ default suppressed.
  // `header.get(off..off + N)?` returns `Some` on exactly the original
  // `off + N <= header.len()` condition, `None` otherwise (byte-identical).
  let read_u16 = |off: usize| -> Option<u16> {
    Some(u16::from_be_bytes(
      header.get(off..off + 2)?.try_into().ok()?,
    ))
  };
  let read_u32 = |off: usize| -> Option<u32> {
    Some(u32::from_be_bytes(
      header.get(off..off + 4)?.try_into().ok()?,
    ))
  };
  // The ProcessSerialData walk for V3 starts at offset 0 of the header
  // (post-preamble), reading the int16u/int32u/string-fields sequentially.
  let mut cursor = 0usize;
  // Field 0 Channels (int16u).
  if let Some(v) = read_u16(cursor) {
    meta.ra_fields.push(RaCodecField {
      name: "Channels".into(),
      value: u32::from(v).to_string(),
      emit_as_int: true,
    });
    cursor += 2;
  }
  // Field 1 Unknown int16u[3] = 6 bytes (suppressed).
  cursor += 6;
  // Field 2 BytesPerMinute (int16u).
  if let Some(v) = read_u16(cursor) {
    meta.ra_fields.push(RaCodecField {
      name: "BytesPerMinute".into(),
      value: u32::from(v).to_string(),
      emit_as_int: true,
    });
    cursor += 2;
  }
  // Field 3 AudioBytes (int32u).
  if let Some(v) = read_u32(cursor) {
    meta.ra_fields.push(RaCodecField {
      name: "AudioBytes".into(),
      value: fmt_u32(v),
      emit_as_int: true,
    });
    cursor += 4;
  }
  // Field 4 TitleLen (int8u) → Field 5 Title string[len].
  cursor = ra_text_field(header, cursor, "Title", meta);
  cursor = ra_text_field(header, cursor, "Artist", meta);
  cursor = ra_text_field(header, cursor, "Copyright", meta);
  let _ = ra_text_field(header, cursor, "Comment", meta);
}

// ── Real::AudioV4 (Real.pm:289-325) ────────────────────────────────────────
//
// FORMAT='int16u'; numerous Unknown fields suppress most output. The
// emitted set under default options is: AudioBytes (#6 int32u),
// BytesPerMinute (#7 int32u), AudioFrameSize (#10 int16u default),
// SampleRate (#13 int16u), BitsPerSample (#15 int16u), Channels (#16
// int16u), Title (#23 int8u len + string), Artist (#25 int8u len +
// string), Copyright (#27 int8u len + string), Comment (#29 int8u len +
// string).
fn parse_ra4(header: &[u8], meta: &mut RealMeta<'_>) {
  // `b.get(off..off + N)?` returns `Some` on exactly the original `off + N <=
  // b.len()` condition, `None` otherwise (byte-identical); the N-byte
  // `try_into` never fails.
  let read_u16 = |b: &[u8], off: usize| -> Option<u16> {
    Some(u16::from_be_bytes(b.get(off..off + 2)?.try_into().ok()?))
  };
  let read_u32 = |b: &[u8], off: usize| -> Option<u32> {
    Some(u32::from_be_bytes(b.get(off..off + 4)?.try_into().ok()?))
  };
  // Cursor walk; default FORMAT='int16u' means each int16u field is 2 bytes;
  // explicit `Format => 'int32u'` is 4. Reset.
  let mut cursor: usize = 0;
  // Field 0 FourCC1 Format='undef[4]' (4 bytes, Unknown ⇒ suppressed).
  cursor += 4;
  // Field 1 AudioFileSize int32u Unknown.
  cursor += 4;
  // Field 2 Version2 int16u (default, Unknown).
  cursor += 2;
  // Field 3 HeaderSize int32u Unknown.
  cursor += 4;
  // Field 4 CodecFlavorID int16u (default, Unknown).
  cursor += 2;
  // Field 5 CodedFrameSize int32u Unknown.
  cursor += 4;
  // Field 6 AudioBytes int32u — EMIT.
  if let Some(v) = read_u32(header, cursor) {
    meta.ra_fields.push(RaCodecField {
      name: "AudioBytes".into(),
      value: fmt_u32(v),
      emit_as_int: true,
    });
  }
  cursor += 4;
  // Field 7 BytesPerMinute int32u — EMIT.
  if let Some(v) = read_u32(header, cursor) {
    meta.ra_fields.push(RaCodecField {
      name: "BytesPerMinute".into(),
      value: fmt_u32(v),
      emit_as_int: true,
    });
  }
  cursor += 4;
  // Field 8 Unknown int32u.
  cursor += 4;
  // Field 9 SubPacketH int16u (default, Unknown).
  cursor += 2;
  // Field 10 AudioFrameSize int16u (default) — EMIT (no Unknown tag).
  if let Some(v) = read_u16(header, cursor) {
    meta.ra_fields.push(RaCodecField {
      name: "AudioFrameSize".into(),
      value: u32::from(v).to_string(),
      emit_as_int: true,
    });
  }
  cursor += 2;
  // Field 11 SubPacketSize int16u (default, Unknown).
  cursor += 2;
  // Field 12 Unknown int16u.
  cursor += 2;
  // Field 13 SampleRate int16u — EMIT.
  if let Some(v) = read_u16(header, cursor) {
    meta.ra_fields.push(RaCodecField {
      name: "SampleRate".into(),
      value: u32::from(v).to_string(),
      emit_as_int: true,
    });
  }
  cursor += 2;
  // Field 14 Unknown int16u.
  cursor += 2;
  // Field 15 BitsPerSample int16u — EMIT.
  if let Some(v) = read_u16(header, cursor) {
    meta.ra_fields.push(RaCodecField {
      name: "BitsPerSample".into(),
      value: u32::from(v).to_string(),
      emit_as_int: true,
    });
  }
  cursor += 2;
  // Field 16 Channels int16u — EMIT.
  if let Some(v) = read_u16(header, cursor) {
    meta.ra_fields.push(RaCodecField {
      name: "Channels".into(),
      value: u32::from(v).to_string(),
      emit_as_int: true,
    });
  }
  cursor += 2;
  // Field 17 FourCC2Len int8u + Field 18 FourCC2 undef[4] (Unknown).
  if cursor < header.len() {
    let four_cc_len = header.get(cursor).copied().unwrap_or(0) as usize;
    cursor += 1;
    cursor += four_cc_len;
  }
  // Field 19 FourCC3Len int8u + Field 20 FourCC3 undef[4] (Unknown).
  if cursor < header.len() {
    let four_cc_len = header.get(cursor).copied().unwrap_or(0) as usize;
    cursor += 1;
    cursor += four_cc_len;
  }
  // Field 21 Unknown int8u + Field 22 Unknown int16u (default).
  cursor += 1;
  cursor += 2;
  // Field 23 TitleLen int8u + Field 24 Title string.
  cursor = ra_text_field(header, cursor, "Title", meta);
  // Field 25 ArtistLen + Field 26 Artist string.
  cursor = ra_text_field(header, cursor, "Artist", meta);
  // Field 27 CopyrightLen + Field 28 Copyright string.
  cursor = ra_text_field(header, cursor, "Copyright", meta);
  // Field 29 CommentLen + Field 30 Comment string.
  let _ = ra_text_field(header, cursor, "Comment", meta);
}

// ── Real::AudioV5 (Real.pm:327-350) ────────────────────────────────────────
//
// V5 has NO Title/Artist/Copyright/Comment trailer (no string fields in
// the table); emits SampleRate / BitsPerSample / Channels / AudioBytes /
// BytesPerMinute (every other field is Unknown).
fn parse_ra5(header: &[u8], meta: &mut RealMeta<'_>) {
  // `b.get(off..off + N)?` returns `Some` on exactly the original `off + N <=
  // b.len()` condition, `None` otherwise (byte-identical); the N-byte
  // `try_into` never fails.
  let read_u16 = |b: &[u8], off: usize| -> Option<u16> {
    Some(u16::from_be_bytes(b.get(off..off + 2)?.try_into().ok()?))
  };
  let read_u32 = |b: &[u8], off: usize| -> Option<u32> {
    Some(u32::from_be_bytes(b.get(off..off + 4)?.try_into().ok()?))
  };
  let mut cursor: usize = 0;
  // Field 0 FourCC1 undef[4] Unknown.
  cursor += 4;
  // Field 1 AudioFileSize int32u Unknown.
  cursor += 4;
  // Field 2 Version2 int16u Unknown.
  cursor += 2;
  // Field 3 HeaderSize int32u Unknown.
  cursor += 4;
  // Field 4 CodecFlavorID int16u Unknown.
  cursor += 2;
  // Field 5 CodedFrameSize int32u Unknown.
  cursor += 4;
  // Field 6 AudioBytes int32u — EMIT.
  if let Some(v) = read_u32(header, cursor) {
    meta.ra_fields.push(RaCodecField {
      name: "AudioBytes".into(),
      value: fmt_u32(v),
      emit_as_int: true,
    });
  }
  cursor += 4;
  // Field 7 BytesPerMinute int32u — EMIT.
  if let Some(v) = read_u32(header, cursor) {
    meta.ra_fields.push(RaCodecField {
      name: "BytesPerMinute".into(),
      value: fmt_u32(v),
      emit_as_int: true,
    });
  }
  cursor += 4;
  // Field 8 Unknown int32u.
  cursor += 4;
  // Field 9 SubPacketH int16u Unknown.
  cursor += 2;
  // Field 10 FrameSize int16u Unknown.
  cursor += 2;
  // Field 11 SubPacketSize int16u Unknown.
  cursor += 2;
  // Field 12 SampleRate int16u — EMIT.
  if let Some(v) = read_u16(header, cursor) {
    meta.ra_fields.push(RaCodecField {
      name: "SampleRate".into(),
      value: u32::from(v).to_string(),
      emit_as_int: true,
    });
  }
  cursor += 2;
  // Field 13 SampleRate2 int16u Unknown.
  cursor += 2;
  // Field 14 BitsPerSample int32u — EMIT.
  if let Some(v) = read_u32(header, cursor) {
    meta.ra_fields.push(RaCodecField {
      name: "BitsPerSample".into(),
      value: fmt_u32(v),
      emit_as_int: true,
    });
  }
  cursor += 4;
  // Field 15 Channels int16u — EMIT.
  if let Some(v) = read_u16(header, cursor) {
    meta.ra_fields.push(RaCodecField {
      name: "Channels".into(),
      value: u32::from(v).to_string(),
      emit_as_int: true,
    });
  }
  // Remaining Genr/FourCC3 (Unknown) skipped.
}

/// Helper: read an int8u length followed by a Latin-1 string of that length,
/// emit as a RA text codec field. Returns the cursor after the field.
fn ra_text_field(header: &[u8], cursor: usize, name: &str, meta: &mut RealMeta<'_>) -> usize {
  // The original `cursor >= header.len()` guard ≡ `.get(cursor)` returning
  // `None` (byte-identical; same `return cursor` recovery).
  let Some(&len_byte) = header.get(cursor) else {
    return cursor;
  };
  let len = len_byte as usize;
  let start = cursor + 1;
  // `header.get(start..start + len)` is `Some` on exactly the original
  // `start + len <= header.len()` condition; `None` ⇒ the same
  // `return header.len()` overflow recovery (byte-identical).
  let Some(raw) = header.get(start..start + len) else {
    // Bundled would emit a partial; we drop on overflow (no value).
    return header.len();
  };
  let s = raw_bytes_to_json_string(null_truncate(raw));
  if !s.is_empty() {
    meta.ra_fields.push(RaCodecField {
      name: name.into(),
      value: s,
      emit_as_int: false,
    });
  }
  start + len
}

// ===========================================================================
// RAM/RPM driver (Real.pm:533-555) — text-line scan
// ===========================================================================

/// Detect the input record separator the way bundled
/// `Image::ExifTool::PostScript::GetInputRecordSeparator` does
/// (PostScript.pm:192-213): scan the first 256 bytes, locate the first
/// `\x0a` (LF) and first `\x0d` (CR); a CR immediately followed by LF ⇒
/// `"\r\n"`, CR alone ⇒ `"\r"`, LF alone ⇒ `"\n"`. When neither byte
/// appears the Perl returns `undef` and Real.pm:538's `|| "\n"` falls
/// back to LF — we return `b"\n"` directly for the same net result.
fn input_record_separator(data: &[u8]) -> &'static [u8] {
  // `data.len().min(256) <= data.len()`, so `.get(..n)` always hits;
  // `unwrap_or(data)` is the unreachable fallback (byte-identical).
  let window = data.get(..data.len().min(256)).unwrap_or(data);
  // Perl `pos()` after a `/g` match is the offset of the byte AFTER the
  // match; we mirror that with `position(..) + 1`.
  let lf = window.iter().position(|&b| b == 0x0a).map(|i| i + 1);
  let cr = window.iter().position(|&b| b == 0x0d).map(|i| i + 1);
  match (lf, cr) {
    // `$diff = $a - $d` with 999 sentinels for "not found".
    (Some(a), Some(d)) if a == d + 1 => b"\r\n",
    (Some(a), Some(d)) if a + 1 == d => b"\n\r",
    (Some(a), Some(d)) if a > d => b"\r",
    (Some(a), Some(d)) if a < d => b"\n",
    (Some(_), None) => b"\n", // LF found, CR absent ⇒ `$diff = a - 999 < 0`.
    (None, Some(_)) => b"\r", // CR found, LF absent ⇒ `$diff = 999 - d > 0`.
    // Neither byte: Perl `$sep = undef` ⇒ Real.pm:538 `|| "\n"`.
    _ => b"\n",
  }
}

/// Parse RAM/RPM Metafile (Real.pm:533-555). Bundled `ProcessReal` seeks
/// to byte 0 and `ReadLine`-walks the file using the record separator from
/// `GetInputRecordSeparator` (Real.pm:538). For each line: a line longer
/// than 256 bytes aborts the loop (`last`, Real.pm:541 — already-accepted
/// file stays accepted), an empty/falsy line is skipped (`next unless
/// $buff`, Real.pm:542), and the rest is `chomp`-ed (Real.pm:543).
///
/// The FIRST non-empty line gates file-type acceptance (`if ($type)`,
/// Real.pm:544-549): when that line begins with `http` it must ALSO end
/// in `.ra`/`.rm`/`.rv`/`.rmvb`/`.smil` (case-insensitive) or bundled
/// `return 0` (Real.pm:546) — the file is NOT a Real metafile. Once the
/// gate passes, `$type` is `undef`'d so it fires exactly once. Every
/// non-empty line is then tagged `url` when it matches `^[a-z]{3,4}://`
/// (case-sensitive, Real.pm:552) else `txt`, and emitted via `HandleTag`.
///
/// RAM vs RPM: Real.pm:535-536 reads `$$et{FILE_EXT}` — `RPM` iff the
/// uppercased extension is exactly `"RPM"`, else `RAM`.
///
/// Returns `None` when the gate rejects the buffer (faithful `return 0`),
/// so the engine's candidate loop falls through (typically to `TXT`).
fn parse_metafile<'a>(data: &'a [u8], ext: Option<&str>) -> Option<RealMeta<'a>> {
  // Real.pm:535-536 — `$type = ($ext and $ext eq 'RPM') ? 'RPM' : 'RAM'`.
  // `$$et{FILE_EXT}` is already uppercased (ExifTool.pm:2966 → exifast
  // `file_ext_for_name`), so the comparison is a plain `== "RPM"`.
  let kind = if ext == Some("RPM") {
    RealKind::Rpm
  } else {
    RealKind::Ram
  };

  let sep = input_record_separator(data);
  // `if ($type) { ... }` — the first-non-empty-line acceptance gate; once
  // it fires we set `gated = true` so it never re-runs (Perl `undef $type`).
  let mut gated = false;
  let mut lines: Vec<MetafileLine> = Vec::new();

  // Real.pm:539-540 — `$raf->Seek(0,0); while ($raf->ReadLine($buff))`.
  // `ReadLine` keeps the separator on each chunk; the final chunk may have
  // no trailing separator. We replicate that by splitting INCLUSIVELY.
  let mut rest = data;
  while !rest.is_empty() {
    // `idx` is a `find_subslice` match offset ⇒ `idx + sep.len() <= rest.len()`,
    // and `rest.len()..` is the always-valid trailing empty slice, so every
    // `.get()` here hits; the fallbacks are unreachable (byte-identical).
    let (raw_line, tail) = match find_subslice(rest, sep) {
      Some(idx) => (
        rest.get(..idx + sep.len()).unwrap_or(rest),
        rest.get(idx + sep.len()..).unwrap_or(&[]),
      ),
      None => (rest, rest.get(rest.len()..).unwrap_or(&[])),
    };
    rest = tail;
    // Real.pm:541 — `last if length $buff > 256` (length is of the
    // UN-chomped line, separator included; aborts the whole loop).
    if raw_line.len() > 256 {
      break;
    }
    // Real.pm:543 — `chomp $buff` strips ONE trailing record separator.
    let line = chomp(raw_line, sep);
    // Real.pm:542 — `next unless $buff` (Perl-falsy: empty string skipped).
    if line.is_empty() {
      continue;
    }
    if !gated {
      // Real.pm:546 — `return 0 if $buff =~ /^http/ and
      //                 $buff !~ /\.(ra|rm|rv|rmvb|smil)$/i`.
      if line.starts_with(b"http") && !has_real_metafile_extension(line) {
        return None;
      }
      // `SetFileType($type)` happens here (Real.pm:547); `undef $type`
      // ⇒ the gate is one-shot.
      gated = true;
    }
    // Real.pm:552 — `$buff =~ m{^[a-z]{3,4}://} ? 'url' : 'txt'`. The
    // scheme class is lowercase-only and case-SENSITIVE.
    let is_url = uri_scheme_prefix(line);
    lines.push(MetafileLine {
      is_url,
      text: raw_bytes_to_json_string(line),
    });
  }

  Some(RealMeta {
    kind,
    prop: PropTags::default(),
    mdpr_streams: Vec::new(),
    cont: ContTags::default(),
    rjmd_tags: Vec::new(),
    ra_version: None,
    ra_fields: Vec::new(),
    id3v1: None,
    metafile_lines: lines,
    _phantom: core::marker::PhantomData,
  })
}

/// `index($haystack, $needle)` — first byte offset of `needle` in
/// `haystack`, or `None`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
  if needle.is_empty() || needle.len() > haystack.len() {
    return None;
  }
  haystack.windows(needle.len()).position(|w| w == needle)
}

/// Perl `chomp $buff` against the active `$/` record separator: strip ONE
/// trailing `sep` occurrence if present (Real.pm:543). `chomp` removes at
/// most one separator and only when the string actually ends with it.
fn chomp<'a>(line: &'a [u8], sep: &[u8]) -> &'a [u8] {
  if line.ends_with(sep) {
    // `ends_with(sep)` ⇒ `line.len() >= sep.len()`, so `.get(..n)` always
    // hits; `unwrap_or(line)` is the unreachable fallback (byte-identical).
    line.get(..line.len() - sep.len()).unwrap_or(line)
  } else {
    line
  }
}

/// `$buff =~ /^[a-z]{3,4}://` — line begins with a 3-or-4-char lowercase
/// URI scheme followed by `://` (Real.pm:552, case-sensitive).
fn uri_scheme_prefix(line: &[u8]) -> bool {
  let scheme_len = line.iter().take_while(|&&b| b.is_ascii_lowercase()).count();
  (3..=4).contains(&scheme_len) && line.get(scheme_len..scheme_len + 3) == Some(b"://")
}

/// `$buff =~ /\.(ra|rm|rv|rmvb|smil)$/i` — line ends in one of the Real
/// media extensions (case-insensitive, Real.pm:546). Used by the
/// `http`-line acceptance gate.
fn has_real_metafile_extension(line: &[u8]) -> bool {
  const EXTS: [&[u8]; 5] = [b".ra", b".rm", b".rv", b".rmvb", b".smil"];
  EXTS.iter().any(|ext| {
    // The `line.len() >= ext.len()` guard ⇒ `.get(line.len()-ext.len()..)`
    // always hits (byte-identical to the raw trailing slice).
    line.len() >= ext.len()
      && line
        .get(line.len() - ext.len()..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(ext))
  })
}

// ===========================================================================
// `Taggable` — the golden-pattern emission path
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::emit::Taggable for RealMeta<'_> {
  /// Yield Real tags faithfully to bundled `perl exiftool` emission order:
  /// PROP first, then each MDPR stream in order (Real-MDPR, Real-MDPR2,
  /// Real-MDPR3, …), then CONT, then RJMD, then ID3v1 — for RM; the codec-
  /// table fields under `Real-RA{3,4,5}` — for RA; the `url`/`txt` lines
  /// under `Real` — for RAM/RPM. The golden-pattern parallel to the retired
  /// `serialize_tags`: the SINK changes (an
  /// [`EmittedTag`](crate::emit::EmittedTag) per value instead of
  /// `out.write_*`); the [`RealKind`] dispatch, the per-stream MDPR group
  /// numbering, the per-tag PrintConv/ValueConv branches, the value variants,
  /// and the id3v1-chain POSITION are all preserved verbatim.
  ///
  /// `mode == PrintConv` (`-j`) ⇒ PrintConv strings (bitrate `"32 kbps"`,
  /// duration `"1.86 s"`, Flags BITMASK names, ContentRating name, ID3v1
  /// Genre name); `mode == ValueConv` (`-n`) ⇒ post-ValueConv raw scalars
  /// (bitrate bare int, duration f64 / `0`, Flags raw u16, ContentRating raw
  /// int, ID3v1 Genre raw byte).
  ///
  /// **Groups (family0 / family1):** every Real-* subgroup keeps family-0 =
  /// the module name `"Real"` (the bundled `Image::ExifTool::Real` tables
  /// carry only a family-2 `GROUPS{2}`, so family-0 falls back to the module
  /// name) with family-1 the literal subgroup string — `"Real-PROP"`,
  /// `"Real-MDPR"`/`"Real-MDPR{N}"`, `"Real-CONT"`, `"Real-RJMD"`,
  /// `"Real-RA{3,4,5}"`, and the metafile `"Real"`. The chained ID3v1 tags
  /// keep family-0/1 both `"ID3v1"` (via [`Id3v1Meta`](crate::formats::id3::Id3v1Meta)'s
  /// own `Taggable`). The sink keys on family-1 only (`exiftool:2948`), so
  /// these family-1 strings are the byte-exact conformance surface.
  ///
  /// Every Real tag is a known tag ⇒ `unknown: false`. Real emits no
  /// `Unknown => 1` tags (the `Unknown => 1` PROP/MDPR/RA fields are dropped
  /// at PARSE time — never stored) and no warnings/errors (Real.pm `return 0`
  /// on bad input; the "Unsupported RealAudio version" `Warn` produces no
  /// tags AND no tagmap warning), so the `AnyMeta::Real` arm needs no drain.
  fn tags(
    &self,
    opts: crate::emit::EmitOptions,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    let mode = opts.mode;
    use crate::emit::EmittedTag;

    let print_conv = matches!(mode, crate::emit::ConvMode::PrintConv);
    let mut tags: Vec<EmittedTag> = Vec::new();
    match self.kind {
      RealKind::Rm => self.emit_rm(print_conv, &mut tags),
      RealKind::Ra => self.emit_ra(&mut tags),
      RealKind::Ram | RealKind::Rpm => self.emit_metafile(&mut tags),
    }
    // Chained ID3v1 sub-Meta (RM only; Real.pm:678-687). `Id3v1Meta::tags()`
    // reproduces the retired `emit_id3v1` byte-for-byte (proven by the
    // `id3v1_taggable_matches_reference_emission` differential test + the
    // `real_synth_id3v1_*` conformance fixtures), so chaining it here at the
    // SAME position the old `serialize_rm` called `emit_id3v1` keeps the
    // net output identical. ID3v1 has no warnings/errors to drain.
    if let Some(id3) = &self.id3v1 {
      tags.extend(id3.tags(opts));
    }
    tags.into_iter()
  }
}

#[cfg(feature = "alloc")]
impl RealMeta<'_> {
  /// Push the RM tags (PROP → MDPR streams → CONT → RJMD) in bundled order.
  /// The chained ID3v1 trailer is appended by [`Taggable::tags`] AFTER these
  /// (same position the retired `serialize_rm` called `emit_id3v1`).
  fn emit_rm(&self, print_conv: bool, out: &mut Vec<crate::emit::EmittedTag>) {
    // PROP family-1 = "Real-PROP".
    let prop_group = group1("Real-PROP");
    if let Some(v) = self.prop.max_bitrate {
      push_bitrate(out, &prop_group, "MaxBitrate", v, print_conv);
    }
    if let Some(v) = self.prop.avg_bitrate {
      push_bitrate(out, &prop_group, "AvgBitrate", v, print_conv);
    }
    if let Some(v) = self.prop.max_packet_size {
      push_u64(out, &prop_group, "MaxPacketSize", u64::from(v));
    }
    if let Some(v) = self.prop.avg_packet_size {
      push_u64(out, &prop_group, "AvgPacketSize", u64::from(v));
    }
    if let Some(v) = self.prop.num_packets {
      push_u64(out, &prop_group, "NumPackets", u64::from(v));
    }
    if let Some(ms) = self.prop.duration_ms {
      push_duration(out, &prop_group, "Duration", ms, print_conv);
    }
    if let Some(ms) = self.prop.preroll_ms {
      push_duration(out, &prop_group, "Preroll", ms, print_conv);
    }
    if let Some(v) = self.prop.num_streams {
      push_u64(out, &prop_group, "NumStreams", u64::from(v));
    }
    if let Some(v) = self.prop.flags {
      if print_conv {
        push_str(out, &prop_group, "Flags", flags_print_conv(u32::from(v)));
      } else {
        push_u64(out, &prop_group, "Flags", u64::from(v));
      }
    }
    // Each MDPR stream — first stream is `Real-MDPR`, subsequent `Real-MDPR{N}`.
    for (i, stream) in self.mdpr_streams.iter().enumerate() {
      // Real.pm:632-636 — `SET_GROUP1 = '+N'` where the FIRST occurrence
      // is NOT renamed (`Real-MDPR`), the second is `Real-MDPR2`, etc.
      // (bundled's `$dirCount{$tag} += 1` and `++$dirCount{$tag}` start
      // at 2.)
      let group = if i == 0 {
        group1("Real-MDPR")
      } else {
        crate::value::Group::new("Real", format!("Real-MDPR{}", i + 1))
      };
      emit_mdpr(stream, &group, print_conv, out);
    }
    // CONT.
    let cont_group = group1("Real-CONT");
    if let Some(s) = &self.cont.title {
      push_str(out, &cont_group, "Title", s.clone());
    }
    if let Some(s) = &self.cont.author {
      push_str(out, &cont_group, "Author", s.clone());
    }
    if let Some(s) = &self.cont.copyright {
      push_str(out, &cont_group, "Copyright", s.clone());
    }
    if let Some(s) = &self.cont.comment {
      push_str(out, &cont_group, "Comment", s.clone());
    }
    // RJMD.
    let rjmd_group = group1("Real-RJMD");
    for tag in &self.rjmd_tags {
      // RJMD has no PrintConv hashes today; -j and -n agree on raw int (the
      // retired `serialize_rm` wrote `raw_int` in BOTH branches).
      if tag.emit_as_int {
        push_u64(out, &rjmd_group, &tag.name, u64::from(tag.raw_int));
      } else {
        push_str(out, &rjmd_group, &tag.name, tag.value.clone());
      }
    }
  }

  /// Push the RA codec-table fields under `Real-RA{3,4,5}` (Real.pm:270-350).
  fn emit_ra(&self, out: &mut Vec<crate::emit::EmittedTag>) {
    // Family-1 group depends on the version (Real-RA3 / Real-RA4 / Real-RA5).
    let Some(name) = self.ra_version.and_then(RealAudioVersion::group1) else {
      return;
    };
    let group = group1(name);
    for field in &self.ra_fields {
      if field.emit_as_int {
        // Emit as numeric — bundled `-j` and `-n` both render bare JSON
        // integers for these table entries (no PrintConv toggles).
        if let Ok(n) = field.value.parse::<u64>() {
          push_u64(out, &group, &field.name, n);
        } else {
          push_str(out, &group, &field.name, field.value.clone());
        }
      } else {
        push_str(out, &group, &field.name, field.value.clone());
      }
    }
  }

  /// Push the RAM/RPM Metafile `url`/`txt` lines (Real.pm:551-553). The
  /// `Real::Metafile` table maps `url => 'URL'` / `txt => 'Text'` with NO
  /// PrintConv, so `-j` and `-n` agree. The table has `GROUPS => { 2 =>
  /// 'Video' }` and no family-0/1 override, so family-0/1 both fall back to
  /// the module name `Real` (verified against bundled `perl exiftool` 13.58:
  /// `Real:URL` / `Real:Text`).
  ///
  /// Each line is pushed in file order; the [`TagMap`](crate::tagmap::TagMap)
  /// sink is last-wins-in-place, which is exactly the bundled JSON-writer
  /// behavior for the repeated `URL`/`Text` tag names (without `-a`, the LAST
  /// instance of a duplicate tag is the displayed value — `-G4` confirms the
  /// final line as the primary, earlier lines as `Copy{N}`).
  fn emit_metafile(&self, out: &mut Vec<crate::emit::EmittedTag>) {
    let group = group1("Real");
    for line in &self.metafile_lines {
      let name = if line.is_url { "URL" } else { "Text" };
      push_str(out, &group, name, line.text.clone());
    }
  }
}

/// A Real-* family-1 group with family-0 fixed to the module name `"Real"`.
#[cfg(feature = "alloc")]
#[inline]
fn group1(family1: &str) -> crate::value::Group {
  crate::value::Group::new("Real", family1)
}

/// Push a `TagValue::Str` (known tag).
#[cfg(feature = "alloc")]
#[inline]
fn push_str(
  out: &mut Vec<crate::emit::EmittedTag>,
  group: &crate::value::Group,
  name: &str,
  value: impl Into<smol_str::SmolStr>,
) {
  out.push(crate::emit::EmittedTag::new(
    group.clone(),
    name.into(),
    crate::value::TagValue::Str(value.into()),
    false,
  ));
}

/// Push a `TagValue::U64` (known tag).
#[cfg(feature = "alloc")]
#[inline]
fn push_u64(
  out: &mut Vec<crate::emit::EmittedTag>,
  group: &crate::value::Group,
  name: &str,
  value: u64,
) {
  out.push(crate::emit::EmittedTag::new(
    group.clone(),
    name.into(),
    crate::value::TagValue::U64(value),
    false,
  ));
}

/// Push `(group, name) = bitrate` in PrintConv (`-j`: `ConvertBitrate`) or
/// raw (`-n`: bare int) form. Faithful to the retired `emit_bitrate`.
#[cfg(feature = "alloc")]
fn push_bitrate(
  out: &mut Vec<crate::emit::EmittedTag>,
  group: &crate::value::Group,
  name: &str,
  bps: u32,
  print_conv: bool,
) {
  if print_conv {
    let mut s = String::new();
    let _ = write_convert_bitrate(&mut s, f64::from(bps));
    push_str(out, group, name, s);
  } else {
    push_u64(out, group, name, u64::from(bps));
  }
}

/// Push `(group, name) = duration` from milliseconds. ValueConv divides by
/// 1000; PrintConv applies `ConvertDuration` (datetime.rs). Faithful to the
/// retired `emit_duration`.
#[cfg(feature = "alloc")]
fn push_duration(
  out: &mut Vec<crate::emit::EmittedTag>,
  group: &crate::value::Group,
  name: &str,
  ms: u32,
  print_conv: bool,
) {
  let secs = f64::from(ms) / 1000.0;
  if print_conv {
    push_str(out, group, name, convert_duration_string(secs));
  } else {
    // -n: bundled emits the post-ValueConv numeric (e.g. `0.095`, `1.857`,
    // `0` for zero-duration). For zero we want the bare integer `0`
    // (matches bundled `"Real-MDPR2:StreamDuration": 0`); for fractional
    // values we want the f64 token.
    if ms == 0 {
      push_u64(out, group, name, 0);
    } else {
      out.push(crate::emit::EmittedTag::new(
        group.clone(),
        name.into(),
        crate::value::TagValue::F64(secs),
        false,
      ));
    }
  }
}

/// Push one MDPR stream's tags into the given family-1 group. Faithful to
/// the retired `serialize_mdpr`.
#[cfg(feature = "alloc")]
fn emit_mdpr(
  s: &MdprStream,
  group: &crate::value::Group,
  print_conv: bool,
  out: &mut Vec<crate::emit::EmittedTag>,
) {
  if let Some(v) = s.stream_number {
    push_u64(out, group, "StreamNumber", u64::from(v));
  }
  if let Some(v) = s.stream_max_bitrate {
    push_bitrate(out, group, "StreamMaxBitrate", v, print_conv);
  }
  if let Some(v) = s.stream_avg_bitrate {
    push_bitrate(out, group, "StreamAvgBitrate", v, print_conv);
  }
  if let Some(v) = s.stream_max_packet_size {
    push_u64(out, group, "StreamMaxPacketSize", u64::from(v));
  }
  if let Some(v) = s.stream_avg_packet_size {
    push_u64(out, group, "StreamAvgPacketSize", u64::from(v));
  }
  if let Some(v) = s.stream_start_time {
    push_u64(out, group, "StreamStartTime", u64::from(v));
  }
  if let Some(ms) = s.stream_preroll_ms {
    push_duration(out, group, "StreamPreroll", ms, print_conv);
  }
  if let Some(ms) = s.stream_duration_ms {
    push_duration(out, group, "StreamDuration", ms, print_conv);
  }
  if let Some(name) = &s.stream_name {
    if !name.is_empty() {
      push_str(out, group, "StreamName", name.clone());
    }
  }
  if let Some(mime) = &s.stream_mime_type {
    if !mime.is_empty() {
      push_str(out, group, "StreamMimeType", mime.clone());
    }
  }
  if let Some(v) = s.file_info_version {
    push_u64(out, group, "FileInfoVersion", u64::from(v));
  }
  // Dynamic FileInfo properties.
  for prop in &s.file_info_props {
    if prop.emit_raw_as_int && !print_conv {
      // -n: emit the on-disk int.
      if let Ok(n) = prop.value_raw.parse::<u64>() {
        push_u64(out, group, &prop.name, n);
      } else {
        push_str(out, group, &prop.name, prop.value_raw.clone());
      }
    } else if print_conv {
      push_str(out, group, &prop.name, prop.value_print.clone());
    } else {
      // -n string property (no PrintConv toggle).
      push_str(out, group, &prop.name, prop.value_raw.clone());
    }
  }
}

// ===========================================================================
// `Project` — the normalized cross-format domain projection (golden L2)
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::metadata::Project for RealMeta<'_> {
  /// Project Real metadata onto the normalized
  /// [`MediaMetadata`](crate::metadata::MediaMetadata) domain.
  ///
  /// Real carries no camera / lens / GPS / capture facts (those domains stay
  /// `None`). The structural contribution is the
  /// [`MediaInfo`](crate::metadata::MediaInfo):
  ///
  /// - **Tracks** — for RM, one [`TrackKind`](crate::metadata::TrackKind) per
  ///   MDPR stream, classified by its `StreamMimeType` (`audio/*` ⇒
  ///   [`TrackKind::Audio`], `video/*` ⇒ [`TrackKind::Video`]); the
  ///   `logical-fileinfo` metadata stream and any other MIME contribute no
  ///   track. For RA (a single RealAudio stream) the track list is one
  ///   [`TrackKind::Audio`]. RAM/RPM metafiles are text playlists with no
  ///   decodable streams ⇒ no tracks.
  /// - **Duration** — for RM, the PROP `Duration` (milliseconds ÷ 1000),
  ///   which is the only clean duration accessor on [`RealMeta`]. RA / RAM /
  ///   RPM expose no duration accessor ⇒ `None`.
  fn project(&self) -> crate::metadata::MediaMetadata {
    use crate::metadata::TrackKind;
    let mut media = crate::metadata::MediaMetadata::new();
    let info = media.media_mut();
    match self.kind {
      RealKind::Rm => {
        for s in &self.mdpr_streams {
          match s.stream_mime_type.as_deref() {
            Some(m) if m.starts_with("audio/") => {
              info.track_kinds_mut().push(TrackKind::Audio);
            }
            Some(m) if m.starts_with("video/") => {
              info.track_kinds_mut().push(TrackKind::Video);
            }
            _ => {}
          }
        }
        if let Some(ms) = self.prop.duration_ms {
          info.update_duration(Some(core::time::Duration::from_millis(u64::from(ms))));
        }
      }
      RealKind::Ra => {
        info.track_kinds_mut().push(TrackKind::Audio);
      }
      RealKind::Ram | RealKind::Rpm => {}
    }
    media
  }
}

// ===========================================================================
// Optional serde `Serialize` impl for `Rendered<'_, '_, RealMeta<'_>>`
// ===========================================================================
//
// The public `Rendered` wrapper in `format_parser.rs` already drives
// `serialize_tags` for ANY `AnyMeta` arm; no per-format `Serialize` impl
// is required here.

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2a); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;
  #[test]
  fn real_audio_version_from_raw_round_trip() {
    assert_eq!(RealAudioVersion::from_raw(3), RealAudioVersion::Ra3);
    assert_eq!(RealAudioVersion::from_raw(4), RealAudioVersion::Ra4);
    assert_eq!(RealAudioVersion::from_raw(5), RealAudioVersion::Ra5);
    assert_eq!(RealAudioVersion::from_raw(7), RealAudioVersion::Other(7));
  }

  #[test]
  fn real_audio_version_group1() {
    assert_eq!(RealAudioVersion::Ra3.group1(), Some("Real-RA3"));
    assert_eq!(RealAudioVersion::Ra4.group1(), Some("Real-RA4"));
    assert_eq!(RealAudioVersion::Ra5.group1(), Some("Real-RA5"));
    assert_eq!(RealAudioVersion::Other(7).group1(), None);
  }

  #[test]
  fn real_kind_file_type() {
    assert_eq!(RealKind::Rm.file_type(), "RM");
    assert_eq!(RealKind::Ra.file_type(), "RA");
    assert_eq!(RealKind::Ram.file_type(), "RAM");
    assert_eq!(RealKind::Rpm.file_type(), "RPM");
  }

  #[test]
  fn flags_print_conv_decodes_observed_fixture_value() {
    // The Real.rm fixture's Flags = 9 = bits 0 + 3.
    assert_eq!(flags_print_conv(9), "Allow Recording, Allow Download");
    assert_eq!(flags_print_conv(0), "(none)");
    assert_eq!(
      flags_print_conv(0xf),
      "Allow Recording, Perfect Play, Live, Allow Download"
    );
  }

  #[test]
  fn rewrite_date_mm_dd_yyyy_matches_bundled_oracle() {
    // Bundled-Perl on Real.rm: `5/12/2004 9:54:03` → `2004:12:05 09:54:03`.
    assert_eq!(
      rewrite_date_mm_dd_yyyy("5/12/2004 9:54:03"),
      ("2004:12:05 09:54:03".to_string(), true)
    );
    // No match ⇒ identity.
    assert_eq!(
      rewrite_date_mm_dd_yyyy("not a date"),
      ("not a date".to_string(), false)
    );
  }

  #[test]
  fn date_value_conv_yyyymmddhhmmss_matches_bundled() {
    // YYYYMMDDhhmmss → YYYY:MM:DD hh:mm:ss.
    assert_eq!(
      date_value_conv_yyyymmddhhmmss("20040512095403"),
      "2004:05:12 09:54:03"
    );
    // Short input ⇒ identity.
    assert_eq!(date_value_conv_yyyymmddhhmmss("2004"), "2004");
  }

  #[test]
  fn resolve_rjmd_tag_static_map() {
    assert_eq!(resolve_rjmd_tag("Album/Name"), "AlbumName");
    assert_eq!(resolve_rjmd_tag("Track/Category"), "TrackCategory");
    assert_eq!(resolve_rjmd_tag("Track/Comments"), "TrackComments");
    assert_eq!(resolve_rjmd_tag("Track/Lyrics"), "TrackLyrics");
    // Dynamic: `tr/A-Za-z0-9//dc` + ucfirst.
    assert_eq!(
      resolve_rjmd_tag("Statistics/CDInfo Source"),
      "StatisticsCDInfoSource"
    );
  }

  #[test]
  fn content_rating_print_matches_table() {
    assert_eq!(content_rating_print(0), "No Rating");
    assert_eq!(content_rating_print(1), "All Ages");
    assert_eq!(content_rating_print(6), "Adults Only");
    assert_eq!(content_rating_print(7), "");
  }

  #[test]
  fn parse_inner_rejects_short_buffer() {
    assert!(parse_inner(&[], None).is_none());
    assert!(parse_inner(&[0u8; 4], None).is_none());
  }

  #[test]
  fn parse_inner_rejects_bad_magic() {
    assert!(parse_inner(b"NOMAGIC1", None).is_none());
  }

  #[test]
  fn parse_inner_accepts_rm_magic() {
    let mut buf = b".RMF\x00\x00\x00\x12".to_vec();
    buf.resize(64, 0);
    let m = parse_inner(&buf, None).expect("RM accepted");
    assert_eq!(m.kind(), RealKind::Rm);
  }

  #[test]
  fn parse_inner_accepts_ra_magic() {
    let mut buf = b".ra\xfd\x00\x04\x00\x00".to_vec();
    buf.resize(520, 0);
    let m = parse_inner(&buf, None).expect("RA accepted");
    assert_eq!(m.kind(), RealKind::Ra);
    assert_eq!(m.ra_version(), Some(RealAudioVersion::Ra4));
  }

  #[test]
  fn parse_inner_accepts_pnm_uri_metafile() {
    // RAM URL line.
    let m = parse_inner(b"pnm://host/file.ra\n", None).expect("metafile accepted");
    assert_eq!(m.kind(), RealKind::Ram);
  }

  // ----------------------------------------------------------------------
  // PR #33 Copilot finding — RAM/RPM Metafile branch (Real.pm:533-555)
  // ----------------------------------------------------------------------

  /// Collect the `(is_url, text)` lines from a parsed Metafile meta.
  fn metafile_lines_of(m: &RealMeta<'_>) -> Vec<(bool, String)> {
    m.metafile_lines
      .iter()
      .map(|l| (l.is_url, l.text.clone()))
      .collect()
  }

  #[test]
  fn parse_metafile_defaults_to_ram_without_rpm_ext() {
    // Real.pm:535-536 — `($ext and $ext eq 'RPM') ? 'RPM' : 'RAM'`. No
    // extension, or any extension other than the exact `"RPM"`, ⇒ RAM.
    for ext in [None, Some("RAM"), Some("SMIL"), Some("rpm")] {
      let m = parse_metafile(b"pnm://host/clip.rm\n", ext)
        .unwrap_or_else(|| panic!("metafile accepted for ext={ext:?}"));
      assert_eq!(m.kind(), RealKind::Ram, "ext={ext:?}");
    }
  }

  #[test]
  fn parse_metafile_rpm_only_for_uppercase_rpm_ext() {
    // `$$et{FILE_EXT}` is pre-uppercased — the comparison is `eq 'RPM'`.
    let m = parse_metafile(b"pnm://host/clip.rm\n", Some("RPM")).expect("accepted");
    assert_eq!(m.kind(), RealKind::Rpm);
  }

  #[test]
  fn parse_metafile_http_gate_rejects_non_real_extension() {
    // Real.pm:546 — first non-empty line starts with `http` but does NOT
    // end in `.ra/.rm/.rv/.rmvb/.smil` ⇒ `return 0` ⇒ `parse_metafile`
    // yields `None` so the engine candidate loop falls through (to TXT).
    assert!(parse_metafile(b"http://host/page.html\n", None).is_none());
    assert!(parse_metafile(b"http://host/index\n", Some("RAM")).is_none());
    // The reject decision is taken on the FIRST non-empty line only — a
    // bad http first line rejects the whole file even if a later line
    // would have qualified.
    assert!(parse_metafile(b"http://host/page.html\nhttp://host/ok.rm\n", None).is_none());
    // `parse_inner` propagates the `None` (the magic prefix matched, but
    // the Metafile branch declined).
    assert!(parse_inner(b"http://host/page.html\n", None).is_none());
  }

  #[test]
  fn parse_metafile_http_gate_accepts_real_extension() {
    // Real.pm:546 — a `http` first line ENDING in a Real media extension
    // passes the gate (case-insensitive). Each accepted suffix variant.
    for line in [
      &b"http://host/a.ra\n"[..],
      &b"http://host/a.RM\n"[..],
      &b"http://host/a.rv\n"[..],
      &b"http://host/a.rmvb\n"[..],
      &b"http://host/a.SMIL\n"[..],
    ] {
      let m = parse_metafile(line, None)
        .unwrap_or_else(|| panic!("expected accept for {:?}", core::str::from_utf8(line)));
      assert_eq!(m.kind(), RealKind::Ram);
    }
  }

  #[test]
  fn parse_metafile_url_vs_text_classification() {
    // Real.pm:552 — `^[a-z]{3,4}://` ⇒ url, else txt. The `pnm`/`rtsp`
    // lines are urls; the plain line is text.
    let m = parse_metafile(
      b"pnm://host/a.rm\nrtsp://host/b.rm\nplain playlist note\n",
      None,
    )
    .expect("accepted");
    assert_eq!(
      metafile_lines_of(&m),
      vec![
        (true, "pnm://host/a.rm".to_string()),
        (true, "rtsp://host/b.rm".to_string()),
        (false, "plain playlist note".to_string()),
      ]
    );
  }

  #[test]
  fn parse_metafile_uri_scheme_class_is_3_or_4_lowercase() {
    // `[a-z]{3,4}` — a 5-char scheme (`https`) or an uppercase scheme is
    // NOT a url under Real.pm:552; it falls to `txt`.
    let m = parse_metafile(b"pnm://host/seed.rm\nhttps://host/x\nHTTP://host/y\n", None)
      .expect("accepted");
    assert_eq!(
      metafile_lines_of(&m),
      vec![
        (true, "pnm://host/seed.rm".to_string()),
        (false, "https://host/x".to_string()),
        (false, "HTTP://host/y".to_string()),
      ]
    );
  }

  #[test]
  fn parse_metafile_skips_empty_lines() {
    // Real.pm:542 — `next unless $buff` drops empty lines; they produce
    // no `url`/`txt` tag and do NOT consume the one-shot acceptance gate.
    let m = parse_metafile(b"pnm://host/a.rm\n\n\nplain\n", None).expect("accepted");
    assert_eq!(
      metafile_lines_of(&m),
      vec![
        (true, "pnm://host/a.rm".to_string()),
        (false, "plain".to_string()),
      ]
    );
  }

  #[test]
  fn parse_metafile_aborts_loop_on_overlong_line() {
    // Real.pm:541 — `last if length $buff > 256` aborts the WHOLE loop.
    // An accepted file stays accepted, but lines AT or AFTER the overlong
    // line are not emitted. Line 1 (short url) is kept; line 2 is 300
    // bytes (> 256) ⇒ loop stops; line 3 never reached.
    let mut data = b"pnm://host/a.rm\n".to_vec();
    data.extend(core::iter::repeat_n(b'x', 300));
    data.push(b'\n');
    data.extend_from_slice(b"pnm://host/never.rm\n");
    let m = parse_metafile(&data, None).expect("accepted");
    assert_eq!(
      metafile_lines_of(&m),
      vec![(true, "pnm://host/a.rm".to_string())]
    );
  }

  #[test]
  fn parse_metafile_final_line_without_separator() {
    // `ReadLine` yields a final chunk with no trailing separator; it is
    // still scanned (Real.pm walks until EOF).
    let m = parse_metafile(b"pnm://host/a.rm\nlast line no newline", None).expect("accepted");
    assert_eq!(
      metafile_lines_of(&m),
      vec![
        (true, "pnm://host/a.rm".to_string()),
        (false, "last line no newline".to_string()),
      ]
    );
  }

  #[test]
  fn parse_metafile_crlf_separator() {
    // `GetInputRecordSeparator` (PostScript.pm:192-213): a `\r\n`-delimited
    // metafile uses `"\r\n"` as `$/`; `chomp` then strips the full CRLF.
    let m = parse_metafile(b"pnm://host/a.rm\r\nplain text\r\n", None).expect("accepted");
    assert_eq!(
      metafile_lines_of(&m),
      vec![
        (true, "pnm://host/a.rm".to_string()),
        (false, "plain text".to_string()),
      ]
    );
  }

  #[test]
  fn input_record_separator_detection() {
    // LF-only ⇒ "\n"; CR before LF ⇒ "\r\n"; CR-only ⇒ "\r"; neither ⇒
    // "\n" (Perl `undef` → Real.pm:538 `|| "\n"`).
    assert_eq!(input_record_separator(b"abc\ndef"), b"\n");
    assert_eq!(input_record_separator(b"abc\r\ndef"), b"\r\n");
    assert_eq!(input_record_separator(b"abc\rdef"), b"\r");
    assert_eq!(input_record_separator(b"no terminators here"), b"\n");
  }

  #[test]
  fn null_truncate_stops_at_first_nul() {
    // Bundled `ReadValue` (ExifTool.pm:6300) applies `s/\0.*//s` whenever
    // `format eq 'string'`. EVERY `Format => 'string[N]'` field in Real.pm
    // (StreamName, StreamMimeType, CONT Title/Author/Copyright/Comment,
    // AudioV3/V4 Title/Artist/Copyright/Comment, RJMD string/date types)
    // funnels through this regex. The R2 finding pinned StreamMimeType as
    // the symptomatic case (`audio/x\0pn-realaudio` ⇒ `audio/x`).
    assert_eq!(null_truncate(b"abc\0xyz"), b"abc");
    assert_eq!(null_truncate(b"abc"), b"abc");
    assert_eq!(null_truncate(b"\0"), b"");
    assert_eq!(null_truncate(b""), b"");
    // The exact byte pattern from the Codex R2 fixture / Real.pm:643.
    assert_eq!(null_truncate(b"audio/x\0pn-realaudio"), b"audio/x");
  }

  // ----------------------------------------------------------------------
  // Codex R1 F1 — `mime_override` correspondence to bundled Real.pm:639-657
  // ----------------------------------------------------------------------
  //
  // Bundled (Real.pm:639-657):
  //
  // ```perl
  // my $mime = $$et{RealStreamMime};
  // if ($mime) {                           # 641: Perl-falsy skip — '' and undef out
  //     delete $$et{RealStreamMime};
  //     $mime =~ s/\0.*//s;
  //     push @mimeTypes, $mime unless $mime =~ /^logical-/;  # 644
  // }
  // …
  // if (@mimeTypes == 1 and length $mimeTypes[0]) {  # 654
  //     $$et{VALUE}{MIMEType} = $mimeTypes[0];
  // }
  // ```
  //
  // Critical observation (verified empirically against bundled exiftool
  // 13.58 on `tests/fixtures/real_synth_*.rm`): line 641's `if ($mime)`
  // is a PERL-FALSY GUARD that drops empty AND undefined MIMEs BEFORE
  // they reach `@mimeTypes`. So the count at line 654 reflects only
  // the NON-empty NON-logical MIMEs. The current Rust filter chain
  // (`filter_map(stream_mime_type) → filter(!starts_with("logical-"))
  // → filter(!is_empty())`) is the precise faithful analog of this
  // composition (the order of the two filters does not matter — they
  // commute — but isolating both is clearer than collapsing them).
  //
  // These unit tests pin the EMPIRICALLY-VERIFIED bundled behavior for
  // each of the 5 finding-listed cases.

  fn synth_rm_meta_with_mimes<'a>(mimes: &[Option<&str>]) -> RealMeta<'a> {
    RealMeta {
      kind: RealKind::Rm,
      prop: PropTags::default(),
      mdpr_streams: mimes
        .iter()
        .map(|m| MdprStream {
          stream_mime_type: m.map(|s| s.to_owned()),
          ..MdprStream::default()
        })
        .collect(),
      cont: ContTags::default(),
      rjmd_tags: Vec::new(),
      ra_version: None,
      ra_fields: Vec::new(),
      id3v1: None,
      metafile_lines: Vec::new(),
      _phantom: core::marker::PhantomData,
    }
  }

  #[test]
  fn mime_override_none_when_zero_non_logical_streams() {
    // Bundled @mimeTypes empty ⇒ count != 1 ⇒ no override.
    let m = synth_rm_meta_with_mimes(&[]);
    assert_eq!(m.mime_override(), None);
    let m = synth_rm_meta_with_mimes(&[Some("logical-fileinfo")]);
    assert_eq!(m.mime_override(), None, "logical-* filtered by line 644");
  }

  #[test]
  fn mime_override_none_when_single_stream_empty_mime() {
    // Bundled: `$mime = ""` ⇒ falsy ⇒ `if ($mime)` SKIPS ⇒ @mimeTypes
    // stays empty ⇒ count != 1 ⇒ no override.
    let m = synth_rm_meta_with_mimes(&[Some("")]);
    assert_eq!(m.mime_override(), None);
  }

  #[test]
  fn mime_override_fires_when_single_audio_stream() {
    // Bundled @mimeTypes = ["audio/x-pn-realaudio"] ⇒ count == 1 AND
    // non-empty ⇒ override fires.
    let m = synth_rm_meta_with_mimes(&[Some("audio/x-pn-realaudio")]);
    assert_eq!(m.mime_override(), Some("audio/x-pn-realaudio"));
  }

  #[test]
  fn mime_override_none_when_two_audio_streams() {
    // Bundled @mimeTypes = ["audio/x-pn-realaudio", "audio/x-pn-realaudio"]
    // ⇒ count == 2 ⇒ override does NOT fire.
    let m = synth_rm_meta_with_mimes(&[Some("audio/x-pn-realaudio"), Some("audio/x-pn-realaudio")]);
    assert_eq!(m.mime_override(), None);
  }

  #[test]
  fn mime_override_fires_when_empty_plus_audio_streams() {
    // Bundled VERIFIED EMPIRICALLY on `real_synth_2_empty_audio.rm`:
    // Stream 0 has `$mime = ""` ⇒ Real.pm:641 SKIPS (empty is falsy).
    // Stream 1 has `$mime = "audio/x-pn-realaudio"` ⇒ pushed. Final
    // @mimeTypes = ["audio/x-pn-realaudio"] (length 1, non-empty) ⇒
    // override FIRES with `audio/x-pn-realaudio`. This contradicts a
    // naive reading of the Codex R1 F1 description; the Codex finding's
    // "count == 2 ⇒ no override" assumption was based on counting
    // empties — bundled does not count empties.
    let m = synth_rm_meta_with_mimes(&[Some(""), Some("audio/x-pn-realaudio")]);
    assert_eq!(
      m.mime_override(),
      Some("audio/x-pn-realaudio"),
      "bundled `if ($mime)` filter at Real.pm:641 drops the empty stream BEFORE counting"
    );
  }

  #[test]
  fn mime_override_none_for_non_rm() {
    let mut m = synth_rm_meta_with_mimes(&[Some("audio/x-pn-realaudio")]);
    m.kind = RealKind::Ra;
    assert_eq!(m.mime_override(), None, "override applies to RM only");
    m.kind = RealKind::Ram;
    assert_eq!(m.mime_override(), None);
    m.kind = RealKind::Rpm;
    assert_eq!(m.mime_override(), None);
  }

  #[test]
  fn mime_override_filters_logical_fileinfo_then_counts() {
    // 1 logical + 1 audio: bundled filters the logical, leaving 1 audio
    // ⇒ override fires.
    let m = synth_rm_meta_with_mimes(&[Some("logical-fileinfo"), Some("audio/x-pn-realaudio")]);
    assert_eq!(m.mime_override(), Some("audio/x-pn-realaudio"));
    // 2 audio + 1 logical: bundled filters the logical, leaving 2 audio
    // ⇒ count==2 ⇒ no override.
    let m = synth_rm_meta_with_mimes(&[
      Some("audio/x-pn-realaudio"),
      Some("logical-fileinfo"),
      Some("audio/x-pn-realaudio"),
    ]);
    assert_eq!(m.mime_override(), None);
  }

  // ----------------------------------------------------------------------
  // Golden-pattern `Taggable` / `Project` (#30 — real migrated last)
  // ----------------------------------------------------------------------
  //
  // These drive the same `run_emission` engine the production
  // `AnyMeta::Real` arm uses, asserting the byte-exact family-1 / value /
  // order contract the `Real.*` + `real_synth_*` conformance fixtures pin
  // at the JSON level. Fixtures are read through the typed parser entry
  // (`parse_borrowed` for `.rm`/`.ra`, `parse_with_ext` for `.ram`/`.rpm`).

  #[cfg(feature = "alloc")]
  fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name),
    )
    .unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
  }

  /// Run `run_emission` over a `RealMeta` and return the resulting `TagMap`.
  #[cfg(feature = "alloc")]
  fn emit(m: &RealMeta<'_>, print_conv: bool) -> crate::tagmap::TagMap {
    let mut tm = crate::tagmap::TagMap::new();
    crate::emit::run_emission(
      m,
      crate::emit::EmitOptions::g1(crate::emit::ConvMode::from_print_conv(print_conv), false),
      &mut tm,
    );
    tm
  }

  /// Ordered `family1:name` keys from a `TagMap` (the engine preserves
  /// emission order; `entries()` is first-occurrence order).
  #[cfg(feature = "alloc")]
  fn keys(tm: &crate::tagmap::TagMap) -> Vec<String> {
    tm.entries()
      .iter()
      .map(|(_, g, n, _, _)| std::format!("{g}:{n}"))
      .collect()
  }

  #[cfg(feature = "alloc")]
  #[test]
  fn taggable_emits_rm_prop_mdpr_print_and_raw() {
    let data = fixture("Real.rm");
    let m = parse_borrowed(&data).expect("RM parses");

    // -j (PrintConv): bitrate/duration/Flags render as strings.
    let pj = emit(&m, true);
    assert_eq!(
      pj.get_str("Real-PROP", "MaxBitrate").as_deref(),
      Some("32 kbps")
    );
    assert_eq!(
      pj.get_str("Real-PROP", "Duration").as_deref(),
      Some("0.10 s")
    );
    assert_eq!(pj.get_str("Real-PROP", "NumStreams").as_deref(), Some("2"));
    assert_eq!(
      pj.get_str("Real-PROP", "Flags").as_deref(),
      Some("Allow Recording, Allow Download")
    );
    // First MDPR stream is family-1 `Real-MDPR`.
    assert_eq!(
      pj.get_str("Real-MDPR", "StreamNumber").as_deref(),
      Some("0")
    );
    assert_eq!(
      pj.get_str("Real-MDPR", "StreamMimeType").as_deref(),
      Some("audio/x-pn-realaudio")
    );
    assert_eq!(
      pj.get_str("Real-MDPR", "StreamDuration").as_deref(),
      Some("1.86 s")
    );
    // Second stream is the numbered `Real-MDPR2`, with the logical-fileinfo
    // dynamic props (ContentRating PrintConv name, date ValueConv).
    assert_eq!(
      pj.get_str("Real-MDPR2", "ContentRating").as_deref(),
      Some("All Ages")
    );
    assert_eq!(
      pj.get_str("Real-MDPR2", "CreateDate").as_deref(),
      Some("2004:12:05 09:54:03")
    );

    // -n (ValueConv): bitrate bare int, duration f64 / 0, Flags raw u16,
    // ContentRating raw int.
    let pn = emit(&m, false);
    assert_eq!(
      pn.get_str("Real-PROP", "MaxBitrate").as_deref(),
      Some("32041")
    );
    assert_eq!(
      pn.get_str("Real-PROP", "Duration").as_deref(),
      Some("0.095")
    );
    assert_eq!(pn.get_str("Real-PROP", "Flags").as_deref(), Some("9"));
    assert_eq!(
      pn.get_str("Real-MDPR", "StreamDuration").as_deref(),
      Some("1.857")
    );
    // Zero-duration stream emits the bare integer `0` (not `0.0`).
    assert_eq!(
      pn.get_str("Real-MDPR2", "StreamDuration").as_deref(),
      Some("0")
    );
    assert_eq!(
      pn.get_str("Real-MDPR2", "ContentRating").as_deref(),
      Some("1")
    );
  }

  #[cfg(feature = "alloc")]
  #[test]
  fn taggable_emits_ra_header_under_versioned_group() {
    let data = fixture("Real.ra");
    let m = parse_borrowed(&data).expect("RA parses");
    assert_eq!(m.ra_version(), Some(RealAudioVersion::Ra4));
    // The RA fixture decodes as RA4 ⇒ codec fields live under `Real-RA4`.
    // (Identity table: -j and -n agree on the value.)
    for print_conv in [true, false] {
      let tm = emit(&m, print_conv);
      // At least one numeric codec field + the string Title are present and
      // grouped under the versioned family-1.
      assert!(
        tm.get("Real-RA4", "Channels").is_some(),
        "RA4 Channels present (print_conv={print_conv})"
      );
      // Every emitted RA tag is under `Real-RA4` (no leakage to other groups).
      for k in keys(&tm) {
        assert!(
          k.starts_with("Real-RA4:"),
          "RA tag {k} grouped under Real-RA4"
        );
      }
    }
  }

  #[cfg(feature = "alloc")]
  #[test]
  fn taggable_group_family0_is_real_across_subgroups() {
    // Build the tag stream directly to inspect the FULL Group (family-0 +
    // family-1), which the `TagMap` sink collapses to family-1 only.
    use crate::emit::{ConvMode, Taggable};
    let rm = fixture("Real.rm");
    let m = parse_borrowed(&rm).expect("RM parses");
    let tags: Vec<_> = m
      .tags(crate::emit::EmitOptions::g1(ConvMode::PrintConv, false))
      .collect();
    // Every Real-* subgroup carries family-0 = the module name "Real"; the
    // chained ID3v1 carries family-0/1 both "ID3v1".
    let mut saw_prop = false;
    let mut saw_mdpr = false;
    let mut saw_mdpr2 = false;
    let mut saw_cont = false;
    let mut saw_rjmd = false;
    let mut saw_id3v1 = false;
    for t in &tags {
      let g = t.tag().group_ref();
      match g.family1() {
        "Real-PROP" => {
          assert_eq!(g.family0(), "Real");
          saw_prop = true;
        }
        "Real-MDPR" => {
          assert_eq!(g.family0(), "Real");
          saw_mdpr = true;
        }
        "Real-MDPR2" => {
          assert_eq!(g.family0(), "Real");
          saw_mdpr2 = true;
        }
        "Real-CONT" => {
          assert_eq!(g.family0(), "Real");
          saw_cont = true;
        }
        "Real-RJMD" => {
          assert_eq!(g.family0(), "Real");
          saw_rjmd = true;
        }
        "ID3v1" => {
          // Chained ID3v1 trailer: family-0 is the ID3 module group
          // (exiftool `ID3:ID3v1:*`), NOT the family-1 frame group.
          assert_eq!(g.family0(), "ID3");
          saw_id3v1 = true;
        }
        other => panic!("unexpected family-1 group {other} in RM stream"),
      }
    }
    assert!(saw_prop && saw_mdpr && saw_mdpr2 && saw_cont && saw_rjmd && saw_id3v1);

    // RA header subgroup: family-0 "Real", family-1 "Real-RA4".
    let ra = fixture("Real.ra");
    let mra = parse_borrowed(&ra).expect("RA parses");
    let ra_tags: Vec<_> = mra
      .tags(crate::emit::EmitOptions::g1(ConvMode::PrintConv, false))
      .collect();
    assert!(!ra_tags.is_empty());
    for t in &ra_tags {
      assert_eq!(t.tag().group_ref().family0(), "Real");
      assert_eq!(t.tag().group_ref().family1(), "Real-RA4");
    }

    // Metafile subgroup: family-0/1 both "Real".
    let ram = fixture("real_synth_ram_pnm.ram");
    let mram = parse_with_ext(&ram, Some("RAM")).expect("RAM parses");
    let ram_tags: Vec<_> = mram
      .tags(crate::emit::EmitOptions::g1(ConvMode::PrintConv, false))
      .collect();
    assert!(!ram_tags.is_empty());
    for t in &ram_tags {
      assert_eq!(t.tag().group_ref().family0(), "Real");
      assert_eq!(t.tag().group_ref().family1(), "Real");
      assert!(matches!(t.tag().name(), "URL" | "Text"));
    }
  }

  #[cfg(feature = "alloc")]
  #[test]
  fn taggable_chains_id3v1_after_real_tags() {
    // Real.rm carries a normal-genre ID3v1 trailer; the chained sub-Meta's
    // tags follow ALL the Real-* tags (PROP→MDPR→CONT→RJMD), at the position
    // the retired `emit_id3v1` ran.
    let data = fixture("Real.rm");
    let m = parse_borrowed(&data).expect("RM parses");

    let pj = emit(&m, true);
    assert_eq!(
      pj.get_str("ID3v1", "Title").as_deref(),
      Some("This is a title")
    );
    // Year is a bare JSON number (I64 branch).
    assert_eq!(
      pj.get("ID3v1", "Year"),
      Some(&crate::value::TagValue::I64(2003))
    );
    // -j Genre = the %genre name.
    assert_eq!(pj.get_str("ID3v1", "Genre").as_deref(), Some("Rock & Roll"));

    // Ordering: the first ID3v1 key appears AFTER the last Real- key.
    let ks = keys(&pj);
    let last_real = ks
      .iter()
      .rposition(|k| k.starts_with("Real-"))
      .expect("Real- keys");
    let first_id3 = ks
      .iter()
      .position(|k| k.starts_with("ID3v1:"))
      .expect("ID3v1 keys");
    assert!(
      first_id3 > last_real,
      "ID3v1 tags chained after Real-* tags (first_id3={first_id3}, last_real={last_real})"
    );

    // -n Genre = the raw byte (78 for the Real.rm trailer).
    let pn = emit(&m, false);
    assert_eq!(
      pn.get("ID3v1", "Genre"),
      Some(&crate::value::TagValue::U64(78))
    );
  }

  #[cfg(feature = "alloc")]
  #[test]
  fn taggable_chains_id3v1_sparse_genre_and_empty_title() {
    // The synthesized fixtures prove the chain reproduces `emit_id3v1`'s
    // edge branches: present-but-empty Title (`Some("")`) and a sparse genre
    // byte (no %genre entry ⇒ `Unknown (n)` in -j, raw byte in -n).
    let empty = fixture("real_synth_id3v1_empty_title.rm");
    let me = parse_borrowed(&empty).expect("RM parses");
    let ej = emit(&me, true);
    // Present-but-empty Title is emitted as the empty string (faithful).
    assert_eq!(
      ej.get("ID3v1", "Title"),
      Some(&crate::value::TagValue::Str("".into()))
    );

    let sparse = fixture("real_synth_id3v1_sparse_genre.rm");
    let ms = parse_borrowed(&sparse).expect("RM parses");
    let sj = emit(&ms, true);
    // Sparse genre ⇒ `Unknown (n)` PrintConv string.
    let g = sj.get_str("ID3v1", "Genre").expect("Genre present");
    assert!(
      g.starts_with("Unknown ("),
      "sparse genre renders Unknown (n): {g}"
    );
    // -n ⇒ the raw byte as a JSON number.
    let sn = emit(&ms, false);
    assert!(matches!(
      sn.get("ID3v1", "Genre"),
      Some(crate::value::TagValue::U64(_))
    ));
  }

  #[cfg(feature = "alloc")]
  #[test]
  fn taggable_metafile_emits_url_and_text_under_real() {
    // Drive the typed parser on a synthesized metafile and assert the
    // `Real:URL` / `Real:Text` emission (last-wins-in-place dedup keeps the
    // final URL line).
    let m = parse_metafile(
      b"pnm://host/a.rm\nrtsp://host/b.rm\nplain note\n",
      Some("RAM"),
    )
    .expect("metafile accepted");
    let tm = emit(&m, true);
    // Two URL lines collapse to the LAST (faithful TagMap last-wins).
    assert_eq!(
      tm.get_str("Real", "URL").as_deref(),
      Some("rtsp://host/b.rm")
    );
    assert_eq!(tm.get_str("Real", "Text").as_deref(), Some("plain note"));
  }

  #[cfg(feature = "alloc")]
  #[test]
  fn project_rm_audio_track_and_duration() {
    use crate::metadata::{Project, TrackKind};
    let data = fixture("Real.rm");
    let m = parse_borrowed(&data).expect("RM parses");
    let md = m.project();
    // Real.rm: stream 0 is audio/x-pn-realaudio ⇒ one Audio track; stream 1
    // is logical-fileinfo ⇒ no track.
    assert_eq!(md.media().track_kinds(), &[TrackKind::Audio]);
    // PROP Duration = 95 ms ⇒ duration set from ms.
    assert_eq!(
      md.media().duration(),
      Some(core::time::Duration::from_millis(95))
    );
    // Real carries no camera/lens/gps/capture facts.
    assert!(md.camera().is_none());
    assert!(md.gps().is_none());
  }

  #[cfg(feature = "alloc")]
  #[test]
  fn project_ra_is_single_audio_track() {
    use crate::metadata::{Project, TrackKind};
    let data = fixture("Real.ra");
    let m = parse_borrowed(&data).expect("RA parses");
    let md = m.project();
    // RA is a single RealAudio stream ⇒ one Audio track, no duration accessor.
    assert_eq!(md.media().track_kinds(), &[TrackKind::Audio]);
    assert_eq!(md.media().duration(), None);
  }

  #[cfg(feature = "alloc")]
  #[test]
  fn project_metafile_has_no_tracks() {
    use crate::metadata::Project;
    let m = parse_metafile(b"pnm://host/a.rm\n", Some("RAM")).expect("metafile accepted");
    let md = m.project();
    // RAM/RPM are text playlists ⇒ no decodable streams.
    assert!(md.media().track_kinds().is_empty());
    assert_eq!(md.media().duration(), None);
  }
}
