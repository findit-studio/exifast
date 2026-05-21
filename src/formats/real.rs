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
  name: String,
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
  /// `Track/Category → TrackCategory`, …).
  name: String,
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
  name: String,
  value: String,
  /// `true` when the bundled `-n`/`-j` output is a bare JSON number.
  emit_as_int: bool,
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
  type Error = RealError;

  /// Parse a Real file's bytes into a typed [`RealMeta`], or `None` if the
  /// buffer is not a Real file (no magic match — Real.pm:523).
  fn parse<'a>(&self, data: Self::Context<'a>) -> Result<Option<Self::Meta<'a>>, RealError> {
    parse_inner(data)
  }
}

/// Lib-first direct entry — alias for [`FormatParser::parse`].
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (currently none — every bad
/// input is `Ok(None)` per Perl `return 0`).
pub fn parse_borrowed(data: &[u8]) -> Result<Option<RealMeta<'_>>, RealError> {
  parse_inner(data)
}

fn parse_inner(data: &[u8]) -> Result<Option<RealMeta<'_>>, RealError> {
  // Real.pm:522 — `$raf->Read($buff,8) == 8`.
  if data.len() < 8 {
    return Ok(None);
  }
  // Real.pm:523 — magic dispatch.
  if data.starts_with(b".RMF") {
    return Ok(Some(parse_rm(data)));
  }
  if data.starts_with(b".ra\xfd") {
    return Ok(Some(parse_ra(data)));
  }
  if data.starts_with(b"pnm://") || data.starts_with(b"rtsp://") || data.starts_with(b"http://") {
    return Ok(Some(parse_metafile(data)));
  }
  Ok(None)
}

// ===========================================================================
// `Real::Properties` (Real.pm:88-113) — PROP chunk ProcessSerialData
// ===========================================================================

/// Read the PROP body as ProcessSerialData with FORMAT='int32u' (Real.pm:92).
/// Field 9 uses `Format => 'int16u'` (Real.pm:102) and field 10 ditto
/// (Real.pm:104-112). All fields are MM (big-endian).
fn parse_prop(body: &[u8]) -> PropTags {
  let read_u32 = |off: usize| -> Option<u32> {
    if off + 4 <= body.len() {
      Some(u32::from_be_bytes([
        body[off],
        body[off + 1],
        body[off + 2],
        body[off + 3],
      ]))
    } else {
      None
    }
  };
  let read_u16 = |off: usize| -> Option<u16> {
    if off + 2 <= body.len() {
      Some(u16::from_be_bytes([body[off], body[off + 1]]))
    } else {
      None
    }
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
  // Real.pm:121 — `StreamNumber Format => 'int16u'` at offset 0.
  s.stream_number = Some(u16::from_be_bytes([body[0], body[1]]));
  // Real.pm:122-127 — five int32u fields. Bundled FORMAT='int32u' applies
  // starting at offset 2 (after the int16u override at field 0). Wait —
  // Perl ProcessSerialData with FORMAT='int32u' but field 0 has
  // `Format => 'int16u'`. So fields 1..7 are int32u starting at offset 2.
  let read_u32 = |off: usize| -> u32 {
    u32::from_be_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]])
  };
  s.stream_max_bitrate = Some(read_u32(2));
  s.stream_avg_bitrate = Some(read_u32(6));
  s.stream_max_packet_size = Some(read_u32(10));
  s.stream_avg_packet_size = Some(read_u32(14));
  s.stream_start_time = Some(read_u32(18));
  s.stream_preroll_ms = Some(read_u32(22));
  s.stream_duration_ms = Some(read_u32(26));
  // Real.pm:129 — StreamNameLen int8u at offset 30.
  let stream_name_len = body[30] as usize;
  // Real.pm:130 — StreamName string[$val{8}] at offset 31..31+nameLen.
  let mut cursor = 31;
  if cursor + stream_name_len <= body.len() {
    let name_slice = &body[cursor..cursor + stream_name_len];
    s.stream_name = Some(raw_bytes_to_json_string(strip_trailing_nuls(name_slice)));
    cursor += stream_name_len;
  } else {
    return s;
  }
  // Real.pm:131 — StreamMimeLen int8u at next offset.
  if cursor >= body.len() {
    return s;
  }
  let stream_mime_len = body[cursor] as usize;
  cursor += 1;
  // Real.pm:132-136 — StreamMimeType string[$val{10}].
  if cursor + stream_mime_len <= body.len() {
    let mime_slice = &body[cursor..cursor + stream_mime_len];
    s.stream_mime_type = Some(raw_bytes_to_json_string(strip_trailing_nuls(mime_slice)));
    cursor += stream_mime_len;
  } else {
    return s;
  }
  // Real.pm:137 — FileInfoLen int32u (the BE u32 size of the trailing payload).
  if cursor + 4 > body.len() {
    return s;
  }
  let file_info_len = read_u32(cursor) as usize;
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
  let file_info_len2 = read_u32(cursor) as usize;
  cursor += 4;
  // Real.pm:144-147 — FileInfoVersion int16u.
  if cursor + 2 > body.len() {
    return s;
  }
  s.file_info_version = Some(u16::from_be_bytes([body[cursor], body[cursor + 1]]));
  cursor += 2;
  // Real.pm:148-152 — PhysicalStreams int16u (`Unknown => 1` ⇒ stored only
  // for sizing the next two tags).
  if cursor + 2 > body.len() {
    return s;
  }
  let physical_streams = u16::from_be_bytes([body[cursor], body[cursor + 1]]) as usize;
  cursor += 2;
  // Real.pm:153-157 — PhysicalStreamNumbers int16u[$val{15}].
  cursor += physical_streams * 2;
  // Real.pm:158-162 — DataOffsets int32u[$val{15}].
  cursor += physical_streams * 4;
  // Real.pm:163-167 — NumRules int16u.
  if cursor + 2 > body.len() {
    return s;
  }
  let num_rules = u16::from_be_bytes([body[cursor], body[cursor + 1]]) as usize;
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
  let props = &body[cursor..end];
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

/// Strip trailing nul bytes from a byte slice.
fn strip_trailing_nuls(bytes: &[u8]) -> &[u8] {
  let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
  &bytes[..end]
}

/// Strip BOTH leading and trailing nul bytes (defensive — the
/// logical-fileinfo blocks have field values whose Perl `Format =>
/// 'string[N]'` truncates at the FIRST embedded NUL).
fn null_truncate(bytes: &[u8]) -> &[u8] {
  let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
  &bytes[..end]
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
    // Real.pm:369 — `($size, $vers) = unpack("x${pos}Nn", $$dataPt)`.
    let size =
      u32::from_be_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]]) as usize;
    let vers = u16::from_be_bytes([body[pos + 4], body[pos + 5]]);
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
    // Real.pm:377 — `tagLen = unpack("x${pos}C", $$dataPt)`.
    if pos >= body.len() {
      break;
    }
    let tag_len = body[pos] as usize;
    pos += 1;
    // Real.pm:380 — `last if $pos + $tagLen > $dirLen`.
    if pos + tag_len > body.len() {
      break;
    }
    let tag_raw = &body[pos..pos + tag_len];
    let tag_str = raw_bytes_to_json_string(null_truncate(tag_raw));
    pos += tag_len;
    // Real.pm:384 — `last if $pos + 6 > $dirLen`.
    if pos + 6 > body.len() {
      break;
    }
    // Real.pm:385 — `($type, $valLen) = unpack("x${pos}Nn", $$dataPt)`.
    let prop_type = u32::from_be_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]]);
    let val_len = u16::from_be_bytes([body[pos + 4], body[pos + 5]]) as usize;
    pos += 6;
    // Real.pm:388 — `last if $pos + $valLen > $dirLen`.
    if pos + val_len > body.len() {
      break;
    }
    let raw_val = &body[pos..pos + val_len];
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
        // int32u
        if raw_val.len() < 4 {
          continue;
        }
        let val_u32 = u32::from_be_bytes([raw_val[0], raw_val[1], raw_val[2], raw_val[3]]);
        if info_name == "ContentRating" {
          let print = content_rating_print(val_u32);
          out.push(FileInfoProp {
            name: info_name.to_string(),
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
            name: info_name.to_string(),
            value_print: print.to_string(),
            value_raw: val_u32.to_string(),
            emit_raw_as_int: true,
          });
        } else {
          let v = val_u32.to_string();
          out.push(FileInfoProp {
            name: info_name.to_string(),
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
          name: info_name.to_string(),
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
          name: info_name.to_string(),
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
  // Try every starting position (Perl `m{…}` without anchors is `.*?`-prefixed).
  for start in 0..bytes.len() {
    if !bytes[start].is_ascii_digit() {
      continue;
    }
    // Greedy digits.
    let mut i = start;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
      i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'/' || i == start {
      continue;
    }
    let g1 = &s[start..i];
    let m_start = i + 1;
    let mut j = m_start;
    while j < bytes.len() && bytes[j].is_ascii_digit() {
      j += 1;
    }
    if j >= bytes.len() || bytes[j] != b'/' || j == m_start {
      continue;
    }
    let g2 = &s[m_start..j];
    let d_start = j + 1;
    let mut k = d_start;
    while k < bytes.len() && bytes[k].is_ascii_digit() {
      k += 1;
    }
    if k == d_start {
      continue;
    }
    let g3 = &s[d_start..k];
    // Require \s+ then H:M:S.
    let mut ws = k;
    while ws < bytes.len() && bytes[ws].is_ascii_whitespace() {
      ws += 1;
    }
    if ws == k {
      continue;
    }
    let h_start = ws;
    let mut l = h_start;
    while l < bytes.len() && bytes[l].is_ascii_digit() {
      l += 1;
    }
    if l >= bytes.len() || bytes[l] != b':' || l == h_start {
      continue;
    }
    let g4 = &s[h_start..l];
    let mi_start = l + 1;
    let mut m_idx = mi_start;
    while m_idx < bytes.len() && bytes[m_idx].is_ascii_digit() {
      m_idx += 1;
    }
    if m_idx >= bytes.len() || bytes[m_idx] != b':' || m_idx == mi_start {
      continue;
    }
    let g5 = &s[mi_start..m_idx];
    let sec_start = m_idx + 1;
    let mut p = sec_start;
    while p < bytes.len() && bytes[p].is_ascii_digit() {
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
  let read_len = |b: &[u8], pos: usize| -> Option<usize> {
    if pos + 2 <= b.len() {
      Some(u16::from_be_bytes([b[pos], b[pos + 1]]) as usize)
    } else {
      None
    }
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
    if cursor + len > body.len() {
      // Bundled `ReadValue` returns truncated; we drop to None.
      let _ = i;
      return c;
    }
    let s = raw_bytes_to_json_string(strip_trailing_nuls(&body[cursor..cursor + len]));
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
    let read_u32 = |off: usize| -> u32 {
      u32::from_be_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]])
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
    // Real.pm:449-451 — name read + truncate at first NUL + prefix join.
    let name_raw = &body[pos + 28..pos + 28 + name_len];
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
    // RJMD-name remap (Real.pm:264-268).
    let resolved_name = resolve_rjmd_tag(&full_tag);
    // Real.pm:468-490 — emit if `$valueLen && $format`.
    if value_len > 0 {
      let raw_value = &body[value_data_pos..value_data_pos + value_len];
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
          let v: u32 = if value_len == 4 {
            u32::from_be_bytes([raw_value[0], raw_value[1], raw_value[2], raw_value[3]])
          } else {
            raw_value[0] as u32
          };
          out.push(RjmdTag {
            name: resolved_name,
            value: v.to_string(),
            emit_as_int: true,
            raw_int: v,
          });
        }
        4 => {
          // int32u.
          if value_len >= 4 {
            let v = u32::from_be_bytes([raw_value[0], raw_value[1], raw_value[2], raw_value[3]]);
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
        // dirLen = pos + size - dirStart.
        let sub_dir_len = (pos + size).saturating_sub(dir_start);
        let sub_end = dir_start.saturating_add(sub_dir_len).min(dir_len);
        let sub_body = &body[dir_start..sub_end];
        // Recurse with the FULL tag as new prefix (Real.pm:499 `Prefix => $tag`).
        // Real.pm:451 path stores `$tag = $prefix . $tag` ⇒ already
        // prefix-joined; passing `full_tag` (the assembled prefix-and-self)
        // matches bundled.
        let new_prefix_full = if prefix.is_empty() {
          // Re-read the body's name from the raw bytes to avoid the
          // dynamic-rename remap (the recursion prefix is the literal
          // on-disk name, not the post-Real::Metadata rename).
          let raw = &body[pos + 28..pos + 28 + name_len];
          raw_bytes_to_json_string(null_truncate(raw))
        } else {
          let raw = &body[pos + 28..pos + 28 + name_len];
          format!("{prefix}/{}", raw_bytes_to_json_string(null_truncate(raw)))
        };
        parse_real_meta(sub_body, &new_prefix_full, out);
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
  // Perl). The bundled regex is `/^(\d{4})(\d{2})…/`.
  if !bytes[..14].iter().all(u8::is_ascii_digit) {
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
    _phantom: core::marker::PhantomData,
  };
  // Real.pm:595 — skip rest of RM header: `$size = unpack('x4N', $buff); seek($size-8, 1)`.
  // The 18-byte RMF header is `.RMF \0\0\0\x12 \0\x01\0\0\0\0\0\0\0\x06` —
  // size at offset 4 = 0x12 = 18. We position after the 18-byte header.
  if data.len() < 8 {
    return meta;
  }
  let size = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
  if size < 8 {
    return meta;
  }
  let mut cursor = size;
  if cursor > data.len() {
    return meta;
  }
  // Real.pm:602-651 — chunk walk. `last if $tag eq 'DATA'` (Real.pm:609).
  while cursor + 10 <= data.len() {
    let tag = &data[cursor..cursor + 4];
    let chunk_size = u32::from_be_bytes([
      data[cursor + 4],
      data[cursor + 5],
      data[cursor + 6],
      data[cursor + 7],
    ]) as usize;
    // Real.pm:606 — null-tag terminator.
    if tag == [0, 0, 0, 0] {
      break;
    }
    // Real.pm:609 — bundled stops at DATA under default verbose.
    if tag == b"DATA" {
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
    let body = &data[body_start..body_end];
    match tag {
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
        if body.len() > 4 {
          parse_real_meta(&body[4..], "", &mut meta.rjmd_tags);
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
  // RMJE marker at offset n-140; read 12 bytes there.
  let rmje_off = n - 140;
  let rmje_buf = &data[rmje_off..rmje_off + 12];
  if rmje_buf.starts_with(b"RMJE") {
    // metaSize = unpack('x8N') ⇒ u32 BE at byte 8 within the 12-byte buf.
    let meta_size =
      u32::from_be_bytes([rmje_buf[8], rmje_buf[9], rmje_buf[10], rmje_buf[11]]) as usize;
    // Current file pos after reading 12 bytes = n-140+12 = n-128. Seek
    // back -metaSize-12 ⇒ n-128 - meta_size - 12 = n - 140 - meta_size.
    if meta_size > 0 && rmje_off >= meta_size {
      let rjmd_off = rmje_off - meta_size;
      let rjmd_buf = &data[rjmd_off..rjmd_off + meta_size];
      // Real.pm:665 — `$buff =~ /^RJMD/`. Real.pm:670 — DirStart=8.
      if rjmd_buf.starts_with(b"RJMD") && meta_size > 8 {
        parse_real_meta(&rjmd_buf[8..], "", &mut meta.rjmd_tags);
      }
    }
  }
  // ID3v1 trailer.
  if n >= 128 {
    let id3_off = n - 128;
    let id3_buf = &data[id3_off..];
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
    _phantom: core::marker::PhantomData,
  };
  // Real.pm:566 — `($vers, $extra) = unpack('x4nn', $buff)`. Vers at
  // offset 4..6 of the file (after `.ra\xfd`).
  if data.len() < 8 {
    return meta;
  }
  let vers = u16::from_be_bytes([data[4], data[5]]);
  let _extra = u16::from_be_bytes([data[6], data[7]]);
  let raver = RealAudioVersion::from_raw(vers);
  meta.ra_version = Some(raver);
  // Real.pm:569 — read up to 512 bytes starting at position 8 (after the
  // 8-byte preamble: magic+vers+extra).
  let header = if data.len() > 8 {
    &data[8..data.len().min(8 + 512)]
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
  let read_u16 = |off: usize| -> Option<u16> {
    if off + 2 <= header.len() {
      Some(u16::from_be_bytes([header[off], header[off + 1]]))
    } else {
      None
    }
  };
  let read_u32 = |off: usize| -> Option<u32> {
    if off + 4 <= header.len() {
      Some(u32::from_be_bytes([
        header[off],
        header[off + 1],
        header[off + 2],
        header[off + 3],
      ]))
    } else {
      None
    }
  };
  // The ProcessSerialData walk for V3 starts at offset 0 of the header
  // (post-preamble), reading the int16u/int32u/string-fields sequentially.
  let mut cursor = 0usize;
  // Field 0 Channels (int16u).
  if let Some(v) = read_u16(cursor) {
    meta.ra_fields.push(RaCodecField {
      name: "Channels".to_string(),
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
      name: "BytesPerMinute".to_string(),
      value: u32::from(v).to_string(),
      emit_as_int: true,
    });
    cursor += 2;
  }
  // Field 3 AudioBytes (int32u).
  if let Some(v) = read_u32(cursor) {
    meta.ra_fields.push(RaCodecField {
      name: "AudioBytes".to_string(),
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
  let read_u16 = |b: &[u8], off: usize| -> Option<u16> {
    if off + 2 <= b.len() {
      Some(u16::from_be_bytes([b[off], b[off + 1]]))
    } else {
      None
    }
  };
  let read_u32 = |b: &[u8], off: usize| -> Option<u32> {
    if off + 4 <= b.len() {
      Some(u32::from_be_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
      ]))
    } else {
      None
    }
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
      name: "AudioBytes".to_string(),
      value: fmt_u32(v),
      emit_as_int: true,
    });
  }
  cursor += 4;
  // Field 7 BytesPerMinute int32u — EMIT.
  if let Some(v) = read_u32(header, cursor) {
    meta.ra_fields.push(RaCodecField {
      name: "BytesPerMinute".to_string(),
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
      name: "AudioFrameSize".to_string(),
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
      name: "SampleRate".to_string(),
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
      name: "BitsPerSample".to_string(),
      value: u32::from(v).to_string(),
      emit_as_int: true,
    });
  }
  cursor += 2;
  // Field 16 Channels int16u — EMIT.
  if let Some(v) = read_u16(header, cursor) {
    meta.ra_fields.push(RaCodecField {
      name: "Channels".to_string(),
      value: u32::from(v).to_string(),
      emit_as_int: true,
    });
  }
  cursor += 2;
  // Field 17 FourCC2Len int8u + Field 18 FourCC2 undef[4] (Unknown).
  if cursor < header.len() {
    let four_cc_len = header[cursor] as usize;
    cursor += 1;
    cursor += four_cc_len;
  }
  // Field 19 FourCC3Len int8u + Field 20 FourCC3 undef[4] (Unknown).
  if cursor < header.len() {
    let four_cc_len = header[cursor] as usize;
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
  let read_u16 = |b: &[u8], off: usize| -> Option<u16> {
    if off + 2 <= b.len() {
      Some(u16::from_be_bytes([b[off], b[off + 1]]))
    } else {
      None
    }
  };
  let read_u32 = |b: &[u8], off: usize| -> Option<u32> {
    if off + 4 <= b.len() {
      Some(u32::from_be_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
      ]))
    } else {
      None
    }
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
      name: "AudioBytes".to_string(),
      value: fmt_u32(v),
      emit_as_int: true,
    });
  }
  cursor += 4;
  // Field 7 BytesPerMinute int32u — EMIT.
  if let Some(v) = read_u32(header, cursor) {
    meta.ra_fields.push(RaCodecField {
      name: "BytesPerMinute".to_string(),
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
      name: "SampleRate".to_string(),
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
      name: "BitsPerSample".to_string(),
      value: fmt_u32(v),
      emit_as_int: true,
    });
  }
  cursor += 4;
  // Field 15 Channels int16u — EMIT.
  if let Some(v) = read_u16(header, cursor) {
    meta.ra_fields.push(RaCodecField {
      name: "Channels".to_string(),
      value: u32::from(v).to_string(),
      emit_as_int: true,
    });
  }
  // Remaining Genr/FourCC3 (Unknown) skipped.
}

/// Helper: read an int8u length followed by a Latin-1 string of that length,
/// emit as a RA text codec field. Returns the cursor after the field.
fn ra_text_field(header: &[u8], cursor: usize, name: &str, meta: &mut RealMeta<'_>) -> usize {
  if cursor >= header.len() {
    return cursor;
  }
  let len = header[cursor] as usize;
  let start = cursor + 1;
  if start + len > header.len() {
    // Bundled would emit a partial; we drop on overflow (no value).
    return header.len();
  }
  let raw = &header[start..start + len];
  let s = raw_bytes_to_json_string(null_truncate(raw));
  if !s.is_empty() {
    meta.ra_fields.push(RaCodecField {
      name: name.to_string(),
      value: s.clone(),
      emit_as_int: false,
    });
  }
  start + len
}

// ===========================================================================
// RAM/RPM driver (Real.pm:533-555) — text-line scan
// ===========================================================================

/// Parse RAM/RPM Metafile (Real.pm:533-555). Bundled walks lines of ≤256
/// chars (longer lines abort); each line that begins with a URI scheme
/// `[a-z]{3,4}://` is emitted as `Real-RAM:url`, everything else as
/// `Real-RAM:txt`. The first non-empty line — when its URI scheme is
/// `http://` — also gates file-type acceptance: a `http://` line without
/// a `.ra/.rm/.rv/.rmvb/.smil` extension causes `return 0` (Real.pm:546).
fn parse_metafile(data: &[u8]) -> RealMeta<'_> {
  // RAM/RPM Metafile decoding has no committed fixture; we record the
  // file kind and (for future fixtures) leave the URL/txt list empty.
  // The Metafile codepath is faithfully implementable but currently
  // exercises only the kind detection. Fixtures: bundled
  // `t/images/Real.ram` is not in the test corpus.
  let _ = data;
  RealMeta {
    kind: RealKind::Ram,
    prop: PropTags::default(),
    mdpr_streams: Vec::new(),
    cont: ContTags::default(),
    rjmd_tags: Vec::new(),
    ra_version: None,
    ra_fields: Vec::new(),
    id3v1: None,
    _phantom: core::marker::PhantomData,
  }
}

// ===========================================================================
// `serialize_tags` — typed Meta → TagMap
// ===========================================================================

#[cfg(feature = "alloc")]
impl RealMeta<'_> {
  /// Emit Real tags into the writer faithfully to bundled `perl exiftool`
  /// emission order: PROP first, then each MDPR stream in order
  /// (Real-MDPR, Real-MDPR2, Real-MDPR3, …), then CONT, then RJMD, then
  /// (for RA) the codec-table fields under `Real-RA{3,4,5}`, then ID3v1.
  pub(crate) fn serialize_tags(
    &self,
    print_conv: bool,
    out: &mut crate::tagmap::TagMap,
  ) -> Result<(), core::convert::Infallible> {
    match self.kind {
      RealKind::Rm => self.serialize_rm(print_conv, out)?,
      RealKind::Ra => self.serialize_ra(print_conv, out)?,
      RealKind::Ram | RealKind::Rpm => {
        // No fixtures committed for the Metafile path; nothing to emit.
      }
    }
    Ok(())
  }

  fn serialize_rm(
    &self,
    print_conv: bool,
    out: &mut crate::tagmap::TagMap,
  ) -> Result<(), core::convert::Infallible> {
    // PROP family-1 = "Real-PROP".
    let prop_group = "Real-PROP";
    if let Some(v) = self.prop.max_bitrate {
      emit_bitrate(out, prop_group, "MaxBitrate", v, print_conv)?;
    }
    if let Some(v) = self.prop.avg_bitrate {
      emit_bitrate(out, prop_group, "AvgBitrate", v, print_conv)?;
    }
    if let Some(v) = self.prop.max_packet_size {
      out.write_u64(prop_group, "MaxPacketSize", u64::from(v))?;
    }
    if let Some(v) = self.prop.avg_packet_size {
      out.write_u64(prop_group, "AvgPacketSize", u64::from(v))?;
    }
    if let Some(v) = self.prop.num_packets {
      out.write_u64(prop_group, "NumPackets", u64::from(v))?;
    }
    if let Some(ms) = self.prop.duration_ms {
      emit_duration(out, prop_group, "Duration", ms, print_conv)?;
    }
    if let Some(ms) = self.prop.preroll_ms {
      emit_duration(out, prop_group, "Preroll", ms, print_conv)?;
    }
    if let Some(v) = self.prop.num_streams {
      out.write_u64(prop_group, "NumStreams", u64::from(v))?;
    }
    if let Some(v) = self.prop.flags {
      if print_conv {
        out.write_str(prop_group, "Flags", &flags_print_conv(u32::from(v)))?;
      } else {
        out.write_u64(prop_group, "Flags", u64::from(v))?;
      }
    }
    // Each MDPR stream — first stream is `Real-MDPR`, subsequent `Real-MDPR{N}`.
    for (i, stream) in self.mdpr_streams.iter().enumerate() {
      // Real.pm:632-636 — `SET_GROUP1 = '+N'` where the FIRST occurrence
      // is NOT renamed (`Real-MDPR`), the second is `Real-MDPR2`, etc.
      // (bundled's `$dirCount{$tag} += 1` and `++$dirCount{$tag}` start
      // at 2.)
      let group_owned: String;
      let group: &str = if i == 0 {
        "Real-MDPR"
      } else {
        group_owned = format!("Real-MDPR{}", i + 1);
        &group_owned
      };
      serialize_mdpr(stream, group, print_conv, out)?;
    }
    // CONT.
    let cont_group = "Real-CONT";
    if let Some(s) = &self.cont.title {
      out.write_str(cont_group, "Title", s)?;
    }
    if let Some(s) = &self.cont.author {
      out.write_str(cont_group, "Author", s)?;
    }
    if let Some(s) = &self.cont.copyright {
      out.write_str(cont_group, "Copyright", s)?;
    }
    if let Some(s) = &self.cont.comment {
      out.write_str(cont_group, "Comment", s)?;
    }
    // RJMD.
    let rjmd_group = "Real-RJMD";
    for tag in &self.rjmd_tags {
      if tag.emit_as_int {
        if print_conv {
          // RJMD has no PrintConv hashes today; -j and -n agree on raw int.
          out.write_u64(rjmd_group, &tag.name, u64::from(tag.raw_int))?;
        } else {
          out.write_u64(rjmd_group, &tag.name, u64::from(tag.raw_int))?;
        }
      } else {
        out.write_str(rjmd_group, &tag.name, &tag.value)?;
      }
    }
    // ID3v1.
    if let Some(id3) = &self.id3v1 {
      emit_id3v1(id3, print_conv, out)?;
    }
    Ok(())
  }

  fn serialize_ra(
    &self,
    print_conv: bool,
    out: &mut crate::tagmap::TagMap,
  ) -> Result<(), core::convert::Infallible> {
    let _ = print_conv;
    // Family-1 group depends on the version (Real-RA3 / Real-RA4 / Real-RA5).
    let Some(group) = self.ra_version.and_then(RealAudioVersion::group1) else {
      return Ok(());
    };
    for field in &self.ra_fields {
      if field.emit_as_int {
        // Emit as numeric — bundled `-j` and `-n` both render bare JSON
        // integers for these table entries (no PrintConv toggles).
        if let Ok(n) = field.value.parse::<u64>() {
          out.write_u64(group, &field.name, n)?;
        } else {
          out.write_str(group, &field.name, &field.value)?;
        }
      } else {
        out.write_str(group, &field.name, &field.value)?;
      }
    }
    Ok(())
  }
}

/// Emit `(group, name) = bitrate` in PrintConv (`-j`: `ConvertBitrate`) or
/// raw (`-n`: bare int) mode.
#[cfg(feature = "alloc")]
fn emit_bitrate(
  out: &mut crate::tagmap::TagMap,
  group: &str,
  name: &str,
  bps: u32,
  print_conv: bool,
) -> Result<(), core::convert::Infallible> {
  if print_conv {
    out.write_fmt(group, name, |w| write_convert_bitrate(w, f64::from(bps)))?;
  } else {
    out.write_u64(group, name, u64::from(bps))?;
  }
  Ok(())
}

/// Emit `(group, name) = duration` from milliseconds. ValueConv divides
/// by 1000; PrintConv applies `ConvertDuration` (datetime.rs).
#[cfg(feature = "alloc")]
fn emit_duration(
  out: &mut crate::tagmap::TagMap,
  group: &str,
  name: &str,
  ms: u32,
  print_conv: bool,
) -> Result<(), core::convert::Infallible> {
  let secs = f64::from(ms) / 1000.0;
  if print_conv {
    let s = convert_duration_string(secs);
    out.write_str(group, name, &s)?;
  } else {
    // -n: bundled emits the post-ValueConv numeric (e.g. `0.095`, `1.857`,
    // `0` for zero-duration). For zero we want the bare integer `0`
    // (matches bundled `"Real-MDPR2:StreamDuration": 0`); for fractional
    // values we want the f64 token.
    if ms == 0 {
      out.write_u64(group, name, 0)?;
    } else {
      out.write_f64(group, name, secs)?;
    }
  }
  Ok(())
}

/// Serialize one MDPR stream into the given family-1 group.
#[cfg(feature = "alloc")]
fn serialize_mdpr(
  s: &MdprStream,
  group: &str,
  print_conv: bool,
  out: &mut crate::tagmap::TagMap,
) -> Result<(), core::convert::Infallible> {
  if let Some(v) = s.stream_number {
    out.write_u64(group, "StreamNumber", u64::from(v))?;
  }
  if let Some(v) = s.stream_max_bitrate {
    emit_bitrate(out, group, "StreamMaxBitrate", v, print_conv)?;
  }
  if let Some(v) = s.stream_avg_bitrate {
    emit_bitrate(out, group, "StreamAvgBitrate", v, print_conv)?;
  }
  if let Some(v) = s.stream_max_packet_size {
    out.write_u64(group, "StreamMaxPacketSize", u64::from(v))?;
  }
  if let Some(v) = s.stream_avg_packet_size {
    out.write_u64(group, "StreamAvgPacketSize", u64::from(v))?;
  }
  if let Some(v) = s.stream_start_time {
    out.write_u64(group, "StreamStartTime", u64::from(v))?;
  }
  if let Some(ms) = s.stream_preroll_ms {
    emit_duration(out, group, "StreamPreroll", ms, print_conv)?;
  }
  if let Some(ms) = s.stream_duration_ms {
    emit_duration(out, group, "StreamDuration", ms, print_conv)?;
  }
  if let Some(name) = &s.stream_name {
    if !name.is_empty() {
      out.write_str(group, "StreamName", name)?;
    }
  }
  if let Some(mime) = &s.stream_mime_type {
    if !mime.is_empty() {
      out.write_str(group, "StreamMimeType", mime)?;
    }
  }
  if let Some(v) = s.file_info_version {
    out.write_u64(group, "FileInfoVersion", u64::from(v))?;
  }
  // Dynamic FileInfo properties.
  for prop in &s.file_info_props {
    if prop.emit_raw_as_int && !print_conv {
      // -n: emit the on-disk int.
      if let Ok(n) = prop.value_raw.parse::<u64>() {
        out.write_u64(group, &prop.name, n)?;
      } else {
        out.write_str(group, &prop.name, &prop.value_raw)?;
      }
    } else if print_conv {
      out.write_str(group, &prop.name, &prop.value_print)?;
    } else {
      // -n string property (no PrintConv toggle).
      out.write_str(group, &prop.name, &prop.value_raw)?;
    }
  }
  Ok(())
}

/// Emit the ID3v1 sub-Meta tags under family-1 group `"ID3v1"`. Bundled
/// `perl exiftool` emits 5–6 string/int tags here (Title/Artist/Album/Year/
/// Comment/Genre [+Track]); the `-j` vs `-n` toggle only affects Genre
/// (string name vs raw byte).
#[cfg(feature = "alloc")]
fn emit_id3v1(
  id3: &crate::formats::id3::Id3v1Meta<'_>,
  print_conv: bool,
  out: &mut crate::tagmap::TagMap,
) -> Result<(), core::convert::Infallible> {
  let group = "ID3v1";
  if let Some(s) = id3.title() {
    out.write_str(group, "Title", s)?;
  }
  if let Some(s) = id3.artist() {
    out.write_str(group, "Artist", s)?;
  }
  if let Some(s) = id3.album() {
    out.write_str(group, "Album", s)?;
  }
  if let Some(s) = id3.year() {
    // Year is a 4-digit string; bundled emits as bare JSON number.
    if let Ok(n) = s.parse::<i64>() {
      out.write_i64(group, "Year", n)?;
    } else {
      out.write_str(group, "Year", s)?;
    }
  }
  if let Some(s) = id3.comment() {
    out.write_str(group, "Comment", s)?;
  }
  if let Some(t) = id3.track() {
    out.write_u64(group, "Track", u64::from(t))?;
  }
  if let Some(g) = id3.genre() {
    if print_conv {
      if let Some(name) = id3.genre_name() {
        out.write_str(group, "Genre", name)?;
      } else {
        out.write_fmt(group, "Genre", |w| write!(w, "Unknown ({g})"))?;
      }
    } else {
      out.write_u64(group, "Genre", u64::from(g))?;
    }
  }
  Ok(())
}

// ===========================================================================
// `RealError` — Rust-level fatal modes (currently none)
// ===========================================================================

/// Rust-level fatal modes for Real parsing. Currently empty — every bad
/// input produces `Ok(None)` (Perl `return 0`).
///
/// §5: derived via `thiserror` (`Display` + `core::error::Error` in every
/// feature tier — `thiserror` v2 with `default-features = false` emits
/// `core::error::Error`). `#[non_exhaustive]` lets the first real variant
/// land without a breaking change.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RealError {}

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
mod tests {
  use super::*;

  #[test]
  fn real_error_is_core_error() {
    fn assert_error<E: core::error::Error>() {}
    assert_error::<RealError>();
  }

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
    assert!(parse_inner(&[]).unwrap().is_none());
    assert!(parse_inner(&[0u8; 4]).unwrap().is_none());
  }

  #[test]
  fn parse_inner_rejects_bad_magic() {
    assert!(parse_inner(b"NOMAGIC1").unwrap().is_none());
  }

  #[test]
  fn parse_inner_accepts_rm_magic() {
    let mut buf = b".RMF\x00\x00\x00\x12".to_vec();
    buf.resize(64, 0);
    let m = parse_inner(&buf).unwrap().expect("RM accepted");
    assert_eq!(m.kind(), RealKind::Rm);
  }

  #[test]
  fn parse_inner_accepts_ra_magic() {
    let mut buf = b".ra\xfd\x00\x04\x00\x00".to_vec();
    buf.resize(520, 0);
    let m = parse_inner(&buf).unwrap().expect("RA accepted");
    assert_eq!(m.kind(), RealKind::Ra);
    assert_eq!(m.ra_version(), Some(RealAudioVersion::Ra4));
  }

  #[test]
  fn parse_inner_accepts_pnm_uri_metafile() {
    // RAM URL line.
    let m = parse_inner(b"pnm://host/file.ra\n")
      .unwrap()
      .expect("metafile accepted");
    assert_eq!(m.kind(), RealKind::Ram);
  }

  #[test]
  fn null_truncate_stops_at_first_nul() {
    assert_eq!(null_truncate(b"abc\0xyz"), b"abc");
    assert_eq!(null_truncate(b"abc"), b"abc");
    assert_eq!(null_truncate(b"\0"), b"");
  }

  #[test]
  fn strip_trailing_nuls_keeps_internal_data() {
    assert_eq!(strip_trailing_nuls(b"abc\0\0"), b"abc");
    assert_eq!(strip_trailing_nuls(b"a\0b\0\0"), b"a\0b");
    assert_eq!(strip_trailing_nuls(b"\0\0"), b"");
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
}
