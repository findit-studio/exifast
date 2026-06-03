// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "aiff")]
//! Faithful port of `Image::ExifTool::AIFF` (lib/Image/ExifTool/AIFF.pm).
//! Implements `ProcessAIFF` (AIFF.pm:184-273), the four tag tables
//! (`%AIFF::Main`, `%AIFF::Common`, `%AIFF::FormatVers`, `%AIFF::Comment`),
//! and the custom `ProcessComment` chunk decoder (AIFF.pm:155-178).
//!
//! A typed [`Meta<'a>`] is produced by the
//! [`crate::format_parser::FormatParser`] trait; the engine entry `process`
//! drives the typed `serialize_tags` path into the engine
//! `tagmap::TagMap` so the serialized JSON stays
//! byte-exact with bundled `perl exiftool`.
//!
//! ## Notable deferrals (in-code) — Phase-2 forward-items
//!
//! 1. **`'ID3 '` chunk (AIFF.pm:69-75)** — `SubDirectory => { TagTable =>
//!    'Image::ExifTool::ID3::Main', ProcessProc => &ProcessID3 }`. The
//!    ID3 chunk dispatch from AIFF is deferred per
//!    `[[exifast-phase2-forward-items]]`; we recognize the chunk but skip
//!    its body (no `File:ID3Size`, no `ID3v2_*` tags). Pinned via the
//!    `aiff_id3_chunk_subdirectory_dispatch_deferred_conformance` test
//!    which is `#[ignore]`-d. SharedFlags::DoneID3 is NOT touched here
//!    because the chunk body is not actually parsed.
//!
//! 2. **DjVu sub-table dispatch (AIFF.pm:204)** — when `AT&TFORM` is followed
//!    by `DJVU` or `DJVM`, AIFF.pm routes the chunk loop to
//!    `Image::ExifTool::DjVu::Main`. Out of Stage-1 audio/video scope
//!    (DjVu = document image). Detection IS faithful (SetFileType +
//!    accept) and the AIFF.pm:206 `' (multi-page)'` FileType suffix for
//!    `DJVM` is also faithful. Only the DjVu sub-table dispatch is
//!    deferred. A bare `AT&TFORM` without the DJVU/DJVM tail still
//!    rejects (AIFF.pm:199).
//!
//! ## Composite Duration — emitted inline per Codex R4
//!
//! `%AIFF::Composite Duration` (AIFF.pm:136-145) is computed by
//! [`Meta`] post-chunk-loop and emitted by the sink. RawConv is
//! `$val[1]/$val[0]` (NumSampleFrames / SampleRate); PrintConv via
//! [`crate::datetime::convert_duration`]. The Composite runtime / D11
//! conversion context aren't required for this single self-contained tag
//! (its RawConv is pure — no `$$self{TimeScale}` etc.). The Composite
//! tag is dropped when either input is 0 (Perl `($val[0] and $val[1])`).
//!
//! Codex R6+R7+R8+R9 surfaced multiple sample-rate edge cases — all are
//! pinned by adversarial conformance fixtures:
//! - non-integer rates (`AIFC_noninteger_rate.aifc`)
//! - integer rates above i64 (`AIFF_ext_int_overflow.aif`)
//! - negative integer rates above i64 magnitude (`AIFF_ext_int_neg_overflow.aif`)
//! - non-finite Inf/NaN rates (`AIFF_inf_sample_rate.aif`,
//!   `AIFF_zero_sig_max_exp.aif`, `AIFF_first_overflow_zero_sig.aif`)
//! - exact integers above 2^53 but routed via NV (`AIFF_r10_exp53_fits_i64.aif`)

// Golden-v2 Contract 3c (Phase C, slice w2c): panic-safety by construction —
// every raw index/slice on the input buffer is converted to a checked `.get()`
// form below. Each conversion is byte-identical: the preceding length guard
// (`data.len() < 12`/`< 16`, the chunk-loop `pos + 8 > data.len()` /
// `pos + len > data.len()` breaks, the comment `pos + size > data.len()`
// break, the `body.len() < 4` / `data.len() <= 2` guards) already proves the
// read in range, so the `.get()` always yields the same bytes via the same
// recovery (reject / break / short-read) it had before.
#![deny(clippy::indexing_slicing)]

use crate::{
  charset::decode_macroman,
  datetime::{AIFF_EPOCH_OFFSET, convert_datetime, convert_duration, convert_unix_time},
  format_parser::{FormatParser, parser_sealed},
  processbinarydata::process_binary_data,
  tagtable::{PrintConv, PrintConvHash, PrintValue, TagDef, TagId, TagTable, ValueConv},
  value::{Metadata, TagValue, perl_nonfinite_str},
};
use std::{
  string::{String, ToString},
  vec::Vec,
};

/// The xtask-GENERATED `%AIFF::Main` table (`cargo xtask gen-tables --kind
/// tagdef --module AIFF::Main`), transcribed from `exiftool -listx`. Consulted
/// by [`aiff_main_get`] ONLY as the ADDITIVE fallback — the hand `static`s
/// shadow every key they define (hand wins on collision). Load-bearing in two
/// ways `-listx` cannot express: (1) NAME/AUTH/`(c) `/ANNO carry a MacRoman
/// `decode_macroman_tagvalue` *ValueConv* that the generated twin lacks
/// (`ValueConv::None`), and (2) the four SubDirectory chunk keys (`FVER`,
/// `COMM`, `COMT`, `ID3 `) are NOT in `-listx` at all (it omits the
/// subdirectory dispatch rows), so the hand layer is the ONLY source for them.
/// The generated table therefore contributes 0 new tags and exists as the
/// drift guard (`tests/xtask_check.rs`).
#[path = "aiff_main_generated.rs"]
mod main_generated;

/// The xtask-GENERATED `%AIFF::Common` table (`cargo xtask gen-tables --kind
/// tagdef --module AIFF::Common`). Consulted by [`aiff_common_get`] ONLY as
/// the ADDITIVE fallback. Load-bearing for `CompressorName` (MacRoman
/// `decode_macroman_tagvalue` *ValueConv* + `pstring` Format) and the
/// `with_format` overrides on NumSampleFrames/SampleRate that `-listx` cannot
/// express — the hand `static`s shadow each one. Contributes 0 new tags; it is
/// the drift guard (`tests/xtask_check.rs`).
#[path = "aiff_common_generated.rs"]
mod common_generated;

// =============================================================================
// %AIFF::Main (AIFF.pm:31-82)
//
// Family-0 group "AIFF" (AIFF.pm:32 `GROUPS => { 2 => 'Audio' }` sets family-2
// only; the table's package is `Image::ExifTool::AIFF::Main` so family-0/1
// is "AIFF" per ExifTool's convention — verified against the AIFF.aif oracle
// which prints `AIFF:Name`, `AIFF:Author`, etc. under `-G1`).
//
// Scalar tags (NAME/AUTH/(c) /ANNO/APPL) all apply `Decode($val, "MacRoman")`
// in their Perl source (AIFF.pm:53/58/63/67; APPL is "ApplicationData" with
// no ValueConv but its first 4 bytes are the application signature — we
// emit the raw bytes verbatim, matching the oracle's `"AAAAappdat"`).
// =============================================================================

/// AIFF.pm:53,58,63,67,115,132 `Decode($val, "MacRoman")`. The chunk-loop
/// strips trailing NULs (AIFF.pm:250) BEFORE this ValueConv runs, so any
/// trailing-NUL handling here would be defensive only.
fn decode_macroman_tagvalue(v: &TagValue) -> TagValue {
  // The chunk loop passes the raw bytes as TagValue::Bytes (no UTF-8
  // assumption); decode them via the faithful MacRoman table and emit Str.
  // For TagValue::Str passthrough (already UTF-8), re-encode each char from
  // its lossless single-byte mapping is impossible — so we only support
  // Bytes here (the only producer). Defensive: pass through Str unchanged.
  match v {
    TagValue::Bytes(b) => TagValue::Str(decode_macroman(b).into()),
    other => other.clone(),
  }
}

// AIFF.pm:39-42 — FVER subdirectory (FormatVersion).
static FORMAT_VERSION_TAG: TagDef =
  TagDef::new("FormatVersion", "AIFF", ValueConv::None, PrintConv::None);

// AIFF.pm:43-46 — COMM subdirectory (Common).
static COMMON_TAG: TagDef = TagDef::new("Common", "AIFF", ValueConv::None, PrintConv::None);

// AIFF.pm:47-50 — COMT subdirectory (Comment).
static COMMENT_TAG: TagDef = TagDef::new("Comment", "AIFF", ValueConv::None, PrintConv::None);

// AIFF.pm:51-54 — NAME tag.
static NAME_TAG: TagDef = TagDef::new(
  "Name",
  "AIFF",
  ValueConv::Func(decode_macroman_tagvalue),
  PrintConv::None,
);

// AIFF.pm:55-59 — AUTH tag.
static AUTHOR_TAG: TagDef = TagDef::new(
  "Author",
  "AIFF",
  ValueConv::Func(decode_macroman_tagvalue),
  PrintConv::None,
);

// AIFF.pm:60-64 — '(c) ' tag (Copyright).
static COPYRIGHT_TAG: TagDef = TagDef::new(
  "Copyright",
  "AIFF",
  ValueConv::Func(decode_macroman_tagvalue),
  PrintConv::None,
);

// AIFF.pm:65-68 — ANNO tag.
static ANNOTATION_TAG: TagDef = TagDef::new(
  "Annotation",
  "AIFF",
  ValueConv::Func(decode_macroman_tagvalue),
  PrintConv::None,
);

// AIFF.pm:69-75 — 'ID3 ' tag (SubDirectory to ID3::Main). DEFERRED per the
// module-level doc; we keep the TagDef so the chunk is recognized but the
// chunk body is dropped (no SubDirectory dispatch implemented for ID3 yet).
static ID3_TAG: TagDef = TagDef::new("ID3", "AIFF", ValueConv::None, PrintConv::None);

// AIFF.pm:76 — APPL tag (ApplicationData), no ValueConv.
static APPLICATION_DATA_TAG: TagDef =
  TagDef::new("ApplicationData", "AIFF", ValueConv::None, PrintConv::None);

/// `%AIFF::Main` lookup (AIFF.pm:31-82). Keys are 4-character chunk IDs.
fn aiff_main_get(id: TagId) -> Option<&'static TagDef> {
  // Hand-first (additive-codegen invariant): the hand `static`s WIN on every
  // key they define. The MacRoman ValueConvs (NAME/AUTH/`(c) `/ANNO) and the
  // SubDirectory keys (FVER/COMM/COMT/ID3 — absent from `-listx`) make the
  // hand layer authoritative, so [`main_generated::get`] never fires at
  // runtime — it is the drift guard.
  let hand = match id {
    TagId::Str("FVER") => Some(&FORMAT_VERSION_TAG),
    TagId::Str("COMM") => Some(&COMMON_TAG),
    TagId::Str("COMT") => Some(&COMMENT_TAG),
    TagId::Str("NAME") => Some(&NAME_TAG),
    TagId::Str("AUTH") => Some(&AUTHOR_TAG),
    TagId::Str("(c) ") => Some(&COPYRIGHT_TAG),
    TagId::Str("ANNO") => Some(&ANNOTATION_TAG),
    TagId::Str("ID3 ") => Some(&ID3_TAG),
    TagId::Str("APPL") => Some(&APPLICATION_DATA_TAG),
    _ => None,
  };
  hand.or_else(|| main_generated::get(id))
}

/// `%AIFF::Main` (AIFF.pm:31-82). family-0 group "AIFF".
pub static AIFF_MAIN: TagTable = TagTable::new("AIFF", aiff_main_get);

// =============================================================================
// %AIFF::Common (AIFF.pm:84-117)
//
// PROCESS_PROC = ProcessBinaryData, FORMAT = 'int16u'. Six tags.
// =============================================================================

static NUM_CHANNELS_TAG: TagDef =
  TagDef::new("NumChannels", "AIFF", ValueConv::None, PrintConv::None);

static NUM_SAMPLE_FRAMES_TAG: TagDef =
  TagDef::new("NumSampleFrames", "AIFF", ValueConv::None, PrintConv::None).with_format("int32u");

static SAMPLE_SIZE_TAG: TagDef =
  TagDef::new("SampleSize", "AIFF", ValueConv::None, PrintConv::None);

static SAMPLE_RATE_TAG: TagDef =
  TagDef::new("SampleRate", "AIFF", ValueConv::None, PrintConv::None).with_format("extended");

/// AIFF.pm:95-110 — `CompressionType` PrintConv hash.
static COMPRESSION_TYPE_TAG: TagDef = TagDef::new(
  "CompressionType",
  "AIFF",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("NONE", PrintValue::Str("None")),
    ("ACE2", PrintValue::Str("ACE 2-to-1")),
    ("ACE8", PrintValue::Str("ACE 8-to-3")),
    ("MAC3", PrintValue::Str("MAC 3-to-1")),
    ("MAC6", PrintValue::Str("MAC 6-to-1")),
    ("sowt", PrintValue::Str("Little-endian, no compression")),
    ("alaw", PrintValue::Str("a-law")),
    ("ALAW", PrintValue::Str("A-law")),
    ("ulaw", PrintValue::Str("mu-law")),
    ("ULAW", PrintValue::Str("Mu-law")),
    ("GSM ", PrintValue::Str("GSM")),
    ("G722", PrintValue::Str("G722")),
    ("G726", PrintValue::Str("G726")),
    ("G728", PrintValue::Str("G728")),
  ])),
)
.with_format("string[4]");

// AIFF.pm:115 `ValueConv => '$self->Decode($val, "MacRoman")'` on the
// CompressorName pstring. The pstring path in [`process_binary_data`] emits
// `TagValue::Bytes` (raw byte string, faithful to Perl `substr` — Codex R1
// fix: a prior `from_utf8(...).unwrap_or_default()` here would have
// corrupted any high-byte MacRoman payload such as `0x80` → "Ä" into the
// empty string). The shared [`decode_macroman_tagvalue`] now handles Bytes
// directly; no separate helper is needed.
static COMPRESSOR_NAME_TAG: TagDef = TagDef::new(
  "CompressorName",
  "AIFF",
  ValueConv::Func(decode_macroman_tagvalue),
  PrintConv::None,
)
.with_format("pstring");

fn aiff_common_get(id: TagId) -> Option<&'static TagDef> {
  // Hand-first (additive-codegen invariant): the hand `static`s WIN on every
  // key they define. `CompressorName` (MacRoman ValueConv + `pstring` Format)
  // and the `with_format` overrides are the load-bearing collisions, so
  // [`common_generated::get`] never fires — it is the drift guard.
  let hand = match id {
    TagId::Int(0) => Some(&NUM_CHANNELS_TAG),
    TagId::Int(1) => Some(&NUM_SAMPLE_FRAMES_TAG),
    TagId::Int(3) => Some(&SAMPLE_SIZE_TAG),
    TagId::Int(4) => Some(&SAMPLE_RATE_TAG),
    TagId::Int(9) => Some(&COMPRESSION_TYPE_TAG),
    TagId::Int(11) => Some(&COMPRESSOR_NAME_TAG),
    _ => None,
  };
  hand.or_else(|| common_generated::get(id))
}

/// `%AIFF::Common` (AIFF.pm:84-117). family-0 group "AIFF".
pub static AIFF_COMMON: TagTable = TagTable::new("AIFF", aiff_common_get);

/// Sorted integer keys of `%AIFF::Common` (ExifTool `sort { $a <=> $b }
/// TagTableKeys`, ExifTool.pm:9907). Required by [`process_binary_data`]
/// to walk tags in numeric order so the `entry >= size` early-exit works.
pub const AIFF_COMMON_KEYS: &[i64] = &[0, 1, 3, 4, 9, 11];

// =============================================================================
// %AIFF::FormatVers (AIFF.pm:119-123)
//
// PROCESS_PROC = ProcessBinaryData, FORMAT = 'int32u'. One tag.
// %timeInfo (AIFF.pm:24-28): ValueConv subtracts AIFF_EPOCH_OFFSET and calls
// ConvertUnixTime; PrintConv calls ConvertDateTime (identity under default
// options).
// =============================================================================

/// AIFF.pm:24-26 `ValueConv => 'ConvertUnixTime($val - ((66*365+17)*24*3600))'`.
/// Applied to a raw int32u from the bit stream; subtract AIFF/Mac → Unix
/// epoch offset, run `ConvertUnixTime` (GMT branch under `TZ=UTC`).
fn aiff_time_value_conv(v: &TagValue) -> TagValue {
  match v {
    TagValue::I64(n) => {
      // AIFF.pm:26 `$val - ((66 * 365 + 17) * 24 * 3600)`. Faithful to
      // Perl: plain signed subtraction. The input is an `int32u` widened
      // to `i64` (range `[0, u32::MAX]`), so `n - AIFF_EPOCH_OFFSET`
      // lands in `[-2_082_844_800, 2_212_122_495]` — well within `i64`
      // bounds, no overflow possible. Negative results are FAITHFUL
      // (pre-1970 Mac/AIFF timestamps round through gmtime).
      let unix = *n - AIFF_EPOCH_OFFSET;
      TagValue::Str(convert_unix_time(unix).into())
    }
    other => other.clone(),
  }
}

/// AIFF.pm:27 `PrintConv => '$self->ConvertDateTime($val)'`. Under the AIFF
/// read path no `DateFormat` is set, so `ConvertDateTime` is identity
/// ([`convert_datetime`]). Modeled as a `Func` so future `DateFormat`
/// derivation can replace the body without touching the table.
fn aiff_datetime_print_conv(v: &TagValue) -> TagValue {
  match v {
    TagValue::Str(s) => TagValue::Str(convert_datetime(s).into()),
    other => other.clone(),
  }
}

static FORMAT_VERSION_TIME_TAG: TagDef = TagDef::new(
  "FormatVersionTime",
  "AIFF",
  ValueConv::Func(aiff_time_value_conv),
  PrintConv::Func(aiff_datetime_print_conv),
);

fn aiff_format_vers_get(id: TagId) -> Option<&'static TagDef> {
  match id {
    TagId::Int(0) => Some(&FORMAT_VERSION_TIME_TAG),
    _ => None,
  }
}

/// `%AIFF::FormatVers` (AIFF.pm:119-123).
pub static AIFF_FORMAT_VERS: TagTable = TagTable::new("AIFF", aiff_format_vers_get);

/// Sorted integer keys of `%AIFF::FormatVers`.
pub const AIFF_FORMAT_VERS_KEYS: &[i64] = &[0];

// =============================================================================
// %AIFF::Comment (AIFF.pm:125-134)
//
// PROCESS_PROC = ProcessComment (custom, AIFF.pm:155-178). Three tags
// (CommentTime, MarkerID, Comment). The custom proc walks numComments
// (u16) × (time u32, markerID u16, size u16, text<size>), padding each
// comment to even byte count.
// =============================================================================

static COMMENT_TIME_TAG: TagDef = TagDef::new(
  "CommentTime",
  "AIFF",
  ValueConv::Func(aiff_time_value_conv),
  PrintConv::Func(aiff_datetime_print_conv),
);

static MARKER_ID_TAG: TagDef = TagDef::new("MarkerID", "AIFF", ValueConv::None, PrintConv::None);

static COMMENT_TEXT_TAG: TagDef = TagDef::new(
  "Comment",
  "AIFF",
  ValueConv::Func(decode_macroman_tagvalue),
  PrintConv::None,
);

fn aiff_comment_get(id: TagId) -> Option<&'static TagDef> {
  match id {
    TagId::Int(0) => Some(&COMMENT_TIME_TAG),
    TagId::Int(1) => Some(&MARKER_ID_TAG),
    TagId::Int(2) => Some(&COMMENT_TEXT_TAG),
    _ => None,
  }
}

/// `%AIFF::Comment` (AIFF.pm:125). Custom dispatch via [`stage_comment`].
pub static AIFF_COMMENT: TagTable = TagTable::new("AIFF", aiff_comment_get);

// =============================================================================
// Typed Meta — `Meta<'a>`
// =============================================================================

/// AIFF / AIFC magic from the FORM header. AIFF.pm:209-210 reads
/// `FORM....(AIF(F|C))` and uses `$1` as the SetFileType argument:
/// `"AIFF"` or `"AIFC"`. The two share every tag table — the difference
/// is solely the FileType / FileTypeExtension / MIMEType triplet.
///
/// `Djvu` carries the AT&TFORM body. AIFF.pm:206 appends `" (multi-page)"`
/// to FileType when the tail is `DJVM` (see [`Meta::djvu_multi_page`]).
/// Body parsing under the DjVu arm is deferred per the module-level doc.
///
/// §2: `#[non_exhaustive]` (the FORM-magic vocabulary may grow with future
/// container variants), `is_*` predicates, and a `Display` routed through the
/// single [`Self::as_file_type`] source of truth.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, derive_more::IsVariant, derive_more::Display)]
#[display("{}", self.as_file_type())]
pub enum Magic {
  /// `FORM....AIFF` (AIFF.pm:209-210, `$1 == "AIFF"`).
  Aiff,
  /// `FORM....AIFC` (AIFF.pm:209-210, `$1 == "AIFC"`).
  Aifc,
  /// `AT&TFORM` + (`DJVU` | `DJVM`) at bytes 12..16 (AIFF.pm:194-207).
  Djvu,
}

impl Magic {
  /// The `$1` capture form as a `&'static str` — the argument to
  /// `SetFileType` (`"AIFF"` / `"AIFC"`) or the AIFF.pm:202 explicit
  /// `"DJVU"`. Single source of truth for [`core::fmt::Display`] (§2).
  #[must_use]
  #[inline(always)]
  pub const fn as_file_type(self) -> &'static str {
    match self {
      Magic::Aiff => "AIFF",
      Magic::Aifc => "AIFC",
      Magic::Djvu => "DJVU",
    }
  }
}

/// 80-bit IEEE-754 extended-precision SampleRate decode (Writer.pl:4501-4506,
/// dispatched through [`crate::processbinarydata::process_binary_data`] →
/// `get_extended`).
///
/// Three faithful Perl scalar shapes (Codex R7+R8+R9+R10):
/// - [`Self::Int`] — exact integer in `i64::MIN..=i64::MAX` (Perl IV path).
///   Emitted as a bare JSON number.
/// - [`Self::BigUInt`] — exact positive integer in `(i64::MAX, u64::MAX]`
///   (Perl UV path). Emitted as a QUOTED JSON string (`EscapeJSON`'s
///   > 15-digit gate).
/// - [`Self::Float`] — non-integer OR signed-magnitude > `2^63`
///   (Perl NV fallback). May be non-finite (Inf / NaN) for adversarial
///   inputs; non-finite values emit as quoted `"Inf"`/`"-Inf"`/`"NaN"`
///   via [`crate::value::perl_nonfinite_str`].
///
/// D8: newtype-style enum, no public fields.
///
/// §1/§2: a [`Self::Float`] f64 arm precludes `Eq`/`Hash` (NaN ≠ NaN) — the
/// derive stops at `Debug, Clone`. §2 supplies `is_*` predicates and
/// `unwrap`/`try_unwrap` accessors so callers never hand-match; all three
/// variants are newtypes (no struct-style or multi-field tuple variants).
/// `#[non_exhaustive]` reserves headroom for further Perl scalar shapes.
#[non_exhaustive]
#[derive(Debug, Clone, derive_more::IsVariant, derive_more::Unwrap, derive_more::TryUnwrap)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
pub enum SampleRate {
  /// Perl IV path: exact integer in `i64::MIN..=i64::MAX`.
  Int(i64),
  /// Perl UV path: exact positive integer in `(i64::MAX, u64::MAX]`.
  /// Stored as the decimal-string form Perl would emit.
  BigUInt(String),
  /// Perl NV path: f64 (may be non-finite for adversarial inputs).
  Float(f64),
}

impl SampleRate {
  /// Convert the sample rate to an `f64` for arithmetic (Composite Duration).
  /// Faithful to Perl `0 + $val` numeric coercion:
  /// - `Int` → `n as f64`
  /// - `BigUInt(s)` → `s.parse::<f64>()` (atof-like)
  /// - `Float(x)` → `x` (preserves Inf/NaN through to Duration `nf / sr`).
  ///
  /// Returns `None` only for the (impossible-in-practice) case where a
  /// `BigUInt` string fails to parse as f64 — we keep the path defensive.
  #[must_use]
  #[inline]
  pub fn as_f64(&self) -> Option<f64> {
    match self {
      SampleRate::Int(n) => Some(*n as f64),
      SampleRate::BigUInt(s) => s.parse::<f64>().ok(),
      SampleRate::Float(x) => Some(*x),
    }
  }
}

/// `%AIFF::Common`'s `CompressionType` post-decode shape (AIFC only).
/// AIFF.pm:95-110 PrintConv hash. The on-disk bytes are a fixed 4-byte
/// string; we stash the raw 4-byte tag here so `serialize_tags` can
/// re-apply the PrintConv hash lookup at sink time.
///
/// Codex R3 — the on-disk byte string may carry HIGH bytes (e.g. `\x80ABC`);
/// `RawText` holds the raw 4 bytes and the sink path runs
/// [`crate::convert::fix_utf8`] for the byte-exact `?ABC` rendering Perl
/// uses (XMP.pm:2943 FixUTF8 under EscapeJSON).
///
/// D8 — newtype variants, no public fields.
///
/// §2: single newtype variant with an `is_*` predicate + `unwrap`/`try_unwrap`
/// accessors; `#[non_exhaustive]` reserves room for a future decoded shape.
/// The borrowed view ([`Self::raw_text`]) projects the inner `Vec<u8>` to a
/// `&[u8]` slice (§3) — callers never see the owning `Vec`.
#[non_exhaustive]
#[derive(Debug, Clone, derive_more::IsVariant, derive_more::Unwrap, derive_more::TryUnwrap)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
pub enum CompressionType {
  /// `RawText` is the trimmed 4-byte string-fixed value as stored on
  /// disk (after [`process_binary_data`]'s `strip_at_first_null`). The
  /// sink path translates this via:
  /// 1. PrintConv hash lookup with key = `fix_utf8(bytes)` (Perl `$val`
  ///    UTF-8-coerced string); miss → `"Unknown (X)"` where X is the
  ///    UTF-8-coerced text.
  /// 2. `-n` (PrintConv off): emit the raw UTF-8-coerced text bare
  ///    (the bundled-Perl `-n` output for a missing hash key is the
  ///    raw text, e.g. `"NONE"` → `"None"` only under `-j`).
  RawText(Vec<u8>),
}

impl CompressionType {
  /// Borrowed view of the raw 4-byte string-fixed CompressionType value
  /// (§3: `Vec<u8>` projected to `&[u8]`). The sink keys the PrintConv
  /// hash on `fix_utf8(self.raw_text())`.
  #[must_use]
  #[inline(always)]
  pub fn raw_text(&self) -> &[u8] {
    match self {
      CompressionType::RawText(b) => b.as_slice(),
    }
  }
}

/// One `%AIFF::Comment` entry. AIFF.pm:155-178 walks `numComments` × (time
/// u32, markerID u16, size u16, text<size>); we capture the post-ValueConv
/// outputs per comment so `serialize_tags` can re-emit in the same order
/// the chunk loop produced them.
///
/// `comment_time` is the post-ValueConv `ConvertUnixTime` formatted string
/// (e.g. `"2004:03:08 05:28:46"`). `marker_id` is `None` when the on-disk
/// markerID was 0 (Perl `$et->HandleTag($tagTablePtr, 1, $markerID) if
/// $markerID;`). `comment` is the post-`Decode(MacRoman)` text.
///
/// D8 — private fields, accessors only.
#[derive(Debug, Clone)]
pub struct Comment {
  /// AIFF.pm:169 — `CommentTime` post-ValueConv. ConvertUnixTime
  /// produces `"YYYY:MM:DD HH:MM:SS"` (24h GMT).
  comment_time: String,
  /// AIFF.pm:170 — `MarkerID`. `None` when the raw u16 was 0.
  marker_id: Option<u16>,
  /// AIFF.pm:173-174 — `Comment` text, post-`Decode(MacRoman)`.
  comment: String,
}

impl Comment {
  /// `CommentTime` as the formatted `"YYYY:MM:DD HH:MM:SS"` string
  /// (§3: `String` projected to `&str`).
  #[must_use]
  #[inline(always)]
  pub fn comment_time(&self) -> &str {
    &self.comment_time
  }

  /// `MarkerID` raw u16. `None` when the on-disk value was 0 (Perl
  /// `if $markerID` gate).
  #[must_use]
  #[inline(always)]
  pub const fn marker_id(&self) -> Option<u16> {
    self.marker_id
  }

  /// `Comment` text, MacRoman-decoded (§3: `String` projected to `&str`).
  #[must_use]
  #[inline(always)]
  pub fn comment(&self) -> &str {
    &self.comment
  }
}

/// `%AIFF::Common` (COMM chunk) post-decode shape. All five numeric
/// fields plus the AIFC-only `CompressionType` / `CompressorName`.
///
/// D8 — private fields, accessors only.
#[derive(Debug, Clone)]
pub struct Common {
  /// AIFF.pm:88 — NumChannels, raw int16u.
  num_channels: u16,
  /// AIFF.pm:89 — NumSampleFrames, raw int32u.
  num_sample_frames: u32,
  /// AIFF.pm:90 — SampleSize, raw int16u.
  sample_size: u16,
  /// AIFF.pm:91 — SampleRate, 80-bit extended decoded value.
  sample_rate: SampleRate,
  /// AIFF.pm:92-111 — `CompressionType` (AIFC only). Raw 4-byte string;
  /// PrintConv hash applied at sink time. `None` for AIFF (no chunk
  /// content past offset 8) OR a truncated COMM chunk where bytes 18..22
  /// are unavailable.
  compression_type: Option<CompressionType>,
  /// AIFF.pm:112-116 — `CompressorName` (AIFC only). Post-`Decode(MacRoman)`
  /// pstring. `None` for AIFF OR for AIFC files lacking the pstring tail.
  compressor_name: Option<String>,
}

impl Common {
  /// NumChannels, raw int16u (Copy → by value, bare name; §3).
  #[must_use]
  #[inline(always)]
  pub const fn num_channels(&self) -> u16 {
    self.num_channels
  }
  /// NumSampleFrames, raw int32u (Copy → by value).
  #[must_use]
  #[inline(always)]
  pub const fn num_sample_frames(&self) -> u32 {
    self.num_sample_frames
  }
  /// SampleSize, raw int16u (Copy → by value).
  #[must_use]
  #[inline(always)]
  pub const fn sample_size(&self) -> u16 {
    self.sample_size
  }
  /// SampleRate, 80-bit extended decoded (§3: non-`Copy` borrow ⇒ `_ref`).
  #[must_use]
  #[inline(always)]
  pub const fn sample_rate_ref(&self) -> &SampleRate {
    &self.sample_rate
  }
  /// `CompressionType` (AIFC). `None` for AIFF or short COMM (§3:
  /// `Option<T>` non-`Copy` ⇒ `Option<&T>` with the `_ref` name).
  #[must_use]
  #[inline(always)]
  pub const fn compression_type_ref(&self) -> Option<&CompressionType> {
    self.compression_type.as_ref()
  }
  /// `CompressorName` (AIFC, MacRoman-decoded pstring). `None` for AIFF
  /// (§3: `Option<String>` projected to the `Option<&str>` view).
  #[must_use]
  #[inline(always)]
  pub fn compressor_name(&self) -> Option<&str> {
    self.compressor_name.as_deref()
  }
}

/// One chronological emission entry. The chunk loop produces these in the
/// order encountered in the file; [`Meta::events`] preserves that
/// order so `serialize_tags` emits byte-exact-to-Perl iteration.
///
/// Each variant is the smallest typed shape sufficient to re-emit with
/// PrintConv toggled at sink time.
#[derive(Debug, Clone)]
enum AiffEvent {
  /// `FVER` (FormatVersionTime). Post-ValueConv `ConvertUnixTime` string.
  FormatVersionTime(String),
  /// `COMM` (Common) — emits its 4-6 sub-fields. Carries the typed
  /// [`Common`] for the sink to walk in `process_binary_data` order.
  Common(Common),
  /// `COMT` (Comment) — one entry per `numComments`. The sink emits the
  /// per-comment tags in `(CommentTime, [MarkerID], Comment)` order
  /// (faithful to AIFF.pm:169-174).
  Comment(Comment),
  /// `NAME` — MacRoman-decoded text scalar. Last-write-wins via the push
  /// (see `Metadata::push` semantics + the `AIFF_dup_name` golden).
  Name(String),
  /// `AUTH` — MacRoman-decoded text scalar.
  Author(String),
  /// `(c) ` — MacRoman-decoded text scalar.
  Copyright(String),
  /// `ANNO` — MacRoman-decoded text scalar.
  Annotation(String),
  /// `APPL` — raw bytes. Sink path applies `fix_utf8` (XMP.pm:2943).
  ApplicationData(Vec<u8>),
  /// A `$et->Warn(...)` (e.g. "Skipping large Common chunk (> 100 MB)").
  Warning(String),
}

/// Typed AIFF metadata — the lib-first output of [`ProcessAiff`].
///
/// Captures the `%AIFF::Main` / `%AIFF::Common` / `%AIFF::FormatVers` /
/// `%AIFF::Comment` chunk-loop emissions in CHRONOLOGICAL order (so the
/// sink re-emits byte-exact-to-Perl, including duplicate-NAME-chunk
/// last-write-wins semantics — the `AIFF_dup_name.aif` golden pins this).
/// Library callers reading `.common()` get the COMM-chunk fields directly;
/// `.comments()` returns the per-COMT-entry list; `.name()` / `.author()`
/// etc. return the LAST chunk of each kind (Perl FoundTag semantics).
///
/// **D8 — no public fields, accessors only.**
///
/// **Lifetimes.** `Meta` owns its strings (MacRoman decode produces
/// owned `String`; the on-disk byte slices are not borrowed past the
/// parse). The `<'a>` lifetime parameter is held for shape parity with
/// the rest of Phase F's typed Metas and to allow a future zero-alloc
/// pass to borrow from input.
///
/// ## Library usage
///
/// ```ignore
/// use exifast::format_parser::FormatParser;
/// use exifast::formats::aiff::ProcessAiff;
///
/// let bytes = std::fs::read("track.aif")?;
/// if let Some(aiff) = ProcessAiff.parse(&bytes)? {
///     if let Some(c) = aiff.common() {
///         println!("Channels: {}", c.num_channels());
///         println!("Sample rate: {:?}", c.sample_rate_ref());
///     }
///     if let Some(d) = aiff.duration() {
///         println!("Duration: {} s", d.as_secs_f64());
///     }
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct Meta<'a> {
  /// AIFF / AIFC / DJVU magic.
  magic: Magic,
  /// True iff [`Self::magic`] is `Djvu` AND the on-disk tail at bytes
  /// 12..16 was `DJVM` (multi-page). AIFF.pm:206 appends ` (multi-page)`
  /// to FileType in that case.
  djvm_multi_page: bool,
  /// Chronological emission events from the chunk loop. Lifetime-tied
  /// to allocations made during parse (strings + bytes are owned, no
  /// borrow into input).
  events: Vec<AiffEvent>,
  /// Composite `Duration` (AIFF.pm:136-145) — `RawConv` is
  /// `$val[1]/$val[0]` (NumSampleFrames / SampleRate). `None` when
  /// either input is 0 (Perl `($val[0] and $val[1])` gate) or when
  /// no COMM chunk was extracted.
  ///
  /// May be non-finite (`Inf` / `NaN`) for adversarial SampleRate
  /// extended values; the sink renders those via [`perl_nonfinite_str`].
  composite_duration: Option<f64>,
  /// Phantom carry of `'a` for future zero-alloc evolution.
  _lifetime: core::marker::PhantomData<&'a ()>,
}

impl Meta<'_> {
  /// AIFF / AIFC / DJVU magic from the FORM header (AIFF.pm:209-210)
  /// (Copy → by value, bare name; §3).
  #[must_use]
  #[inline(always)]
  pub const fn magic(&self) -> Magic {
    self.magic
  }

  /// True iff [`Self::magic`] == `Djvu` AND the 4-byte tail at
  /// bytes 12..16 was `DJVM` (AIFF.pm:206 multi-page).
  #[must_use]
  #[inline(always)]
  pub const fn djvu_multi_page(&self) -> bool {
    self.djvm_multi_page
  }

  /// `%AIFF::Common` (COMM chunk) post-decode. `None` if no COMM chunk
  /// was found. When multiple COMM chunks appear (pathological), returns
  /// the LAST per Perl FoundTag last-write-wins.
  #[must_use]
  pub fn common(&self) -> Option<&Common> {
    self.events.iter().rev().find_map(|e| {
      if let AiffEvent::Common(c) = e {
        Some(c)
      } else {
        None
      }
    })
  }

  /// Per-`%AIFF::Comment` entries in chronological (in-file) order.
  /// Empty when no COMT chunk is present.
  pub fn comments(&self) -> impl Iterator<Item = &Comment> {
    self.events.iter().filter_map(|e| match e {
      AiffEvent::Comment(c) => Some(c),
      _ => None,
    })
  }

  /// `NAME` scalar (MacRoman-decoded). Last-write-wins if multiple NAME
  /// chunks appear (faithful to Perl FoundTag) — see `AIFF_dup_name.aif`.
  #[must_use]
  pub fn name(&self) -> Option<&str> {
    self.events.iter().rev().find_map(|e| {
      if let AiffEvent::Name(s) = e {
        Some(s.as_str())
      } else {
        None
      }
    })
  }

  /// `AUTH` scalar (MacRoman-decoded).
  #[must_use]
  pub fn author(&self) -> Option<&str> {
    self.events.iter().rev().find_map(|e| {
      if let AiffEvent::Author(s) = e {
        Some(s.as_str())
      } else {
        None
      }
    })
  }

  /// `(c) ` scalar (MacRoman-decoded).
  #[must_use]
  pub fn copyright(&self) -> Option<&str> {
    self.events.iter().rev().find_map(|e| {
      if let AiffEvent::Copyright(s) = e {
        Some(s.as_str())
      } else {
        None
      }
    })
  }

  /// `ANNO` scalar (MacRoman-decoded).
  #[must_use]
  pub fn annotation(&self) -> Option<&str> {
    self.events.iter().rev().find_map(|e| {
      if let AiffEvent::Annotation(s) = e {
        Some(s.as_str())
      } else {
        None
      }
    })
  }

  /// `APPL` chunk raw bytes (first 4 are the application signature).
  /// The sink path applies `fix_utf8` for the JSON emission.
  #[must_use]
  pub fn application_data(&self) -> Option<&[u8]> {
    self.events.iter().rev().find_map(|e| {
      if let AiffEvent::ApplicationData(b) = e {
        Some(b.as_slice())
      } else {
        None
      }
    })
  }

  /// `%AIFF::FormatVers FormatVersionTime` (post-ValueConv
  /// `ConvertUnixTime`).
  #[must_use]
  pub fn format_version_time(&self) -> Option<&str> {
    self.events.iter().rev().find_map(|e| {
      if let AiffEvent::FormatVersionTime(s) = e {
        Some(s.as_str())
      } else {
        None
      }
    })
  }

  /// Composite `Duration` (AIFF.pm:136-145) as a [`core::time::Duration`].
  ///
  /// `None` if SampleRate or NumSampleFrames is 0 (Perl `($val[0] and
  /// $val[1])` ⇒ undef), OR if no COMM was found, OR if the computed
  /// duration is non-finite (Inf/NaN) — the sink path still EMITS the
  /// raw f64 via [`Self::composite_duration_secs`] in those cases
  /// (matching the bundled-Perl `"Inf"`/`"NaN"` strings), but the typed
  /// `Duration` accessor refuses to construct an invalid value.
  #[must_use]
  pub fn duration(&self) -> Option<core::time::Duration> {
    let secs = self.composite_duration?;
    if !secs.is_finite() || secs < 0.0 {
      return None;
    }
    Some(core::time::Duration::from_secs_f64(secs))
  }

  /// Composite `Duration` raw seconds (may be non-finite). Library
  /// callers wanting the typed `Duration` should use [`Self::duration`];
  /// this accessor exposes the raw f64 (for sink-time PrintConv +
  /// non-finite rendering).
  #[must_use]
  #[inline(always)]
  pub const fn composite_duration_secs(&self) -> Option<f64> {
    self.composite_duration
  }

  /// Warnings emitted during the chunk loop (e.g. "Skipping large
  /// Common chunk (> 100 MB)"). Empty for the common-case files.
  pub fn warnings(&self) -> impl Iterator<Item = &str> {
    self.events.iter().filter_map(|e| match e {
      AiffEvent::Warning(w) => Some(w.as_str()),
      _ => None,
    })
  }
}

// =============================================================================
// `ProcessAiff` — the lib-first parser
// =============================================================================

/// AIFF parser — faithful `ProcessAIFF` (AIFF.pm:184-273).
#[derive(Debug, Clone, Copy)]
pub struct ProcessAiff;

impl parser_sealed::Sealed for ProcessAiff {}

impl FormatParser for ProcessAiff {
  /// Spec §8: leaf format with no shared state. SharedFlags interaction:
  /// if AIFF gets an ID3 chunk, the bundled would set DoneID3 — since
  /// ID3 chunk dispatch is deferred per [[exifast-phase2-forward-items]],
  /// AIFF does not touch DoneID3.
  /// GAT: the Meta borrows from the input `'a` (Codex AF2).
  type Meta<'a> = Meta<'a>;
  /// Leaf format Context is `&'a [u8]`.
  type Context<'a> = &'a [u8];
  /// Rust-level fatal error (none today; AIFF parsing has no I/O modes —
  /// every bad input is `Ok(None)` per Perl `return 0`).

  /// Parse an AIFF/AIFC/DJVU file's bytes into a typed [`Meta`], or
  /// `None` if the buffer is not a recognized FORM container (AIFF.pm:191
  /// short read, :209 magic mismatch, :199 AT&TFORM tail mismatch).
  fn parse<'a>(&self, data: Self::Context<'a>) -> Option<Self::Meta<'a>> {
    parse_inner(data)
  }
}

/// Lib-first direct entry. Same as [`FormatParser::parse`] but returns an
/// [`Meta`] that may borrow from the input buffer (currently every
/// string is owned, but the `<'a>` is reserved for future zero-alloc).
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today; reserved for
/// future I/O wrappers).
pub fn parse_borrowed(data: &[u8]) -> Option<Meta<'_>> {
  parse_inner(data)
}

fn parse_inner(data: &[u8]) -> Option<Meta<'_>> {
  // AIFF.pm:191 `return 0 unless $raf->Read($buff, 12) == 12`.
  if data.len() < 12 {
    return None;
  }
  // AIFF.pm:194-207 DjVu arm. `AT&TFORM` magic + (`DJVU`|`DJVM`) at
  // bytes 12..16. Bundled reads 4 EXTRA bytes (`return 0 unless
  // $raf->Read($buf2,4) == 4 and $buf2 =~ /^(DJVU|DJVM)/`); resulting
  // file type is `'DJVU'` (AIFF.pm:202), with `' (multi-page)'`
  // appended when the tail was `DJVM` (AIFF.pm:206).
  let mut djvm_multi_page = false;
  let magic: Magic = if data.starts_with(b"AT&TFORM") {
    if data.len() < 16 {
      return None;
    }
    // `data.len() >= 16` ⇒ `.get(12..16)` is always `Some(&data[12..16])`;
    // the byte-string match arms and the `_` reject are byte-identical to the
    // prior `match &data[12..16]`.
    match data.get(12..16) {
      Some(b"DJVU") => {}
      Some(b"DJVM") => djvm_multi_page = true,
      _ => return None,
    }
    Magic::Djvu
  } else {
    // AIFF.pm:209 `return 0 unless $buff =~ /^FORM....(AIF(F|C))/s`.
    // `data.len() >= 12` (top guard) ⇒ `starts_with` ≡ `&data[0..4] == b"FORM"`
    // and `.get(8..12)` is always `Some(&data[8..12])` — both byte-identical.
    if !data.starts_with(b"FORM") {
      return None;
    }
    match data.get(8..12) {
      Some(b"AIFF") => Magic::Aiff,
      Some(b"AIFC") => Magic::Aifc,
      _ => return None,
    }
  };

  // DjVu branch — faithfully stop after SetFileType (Stage-2 defer per
  // module doc). AIFF.pm:204-207 would build a DjVu tag table here and
  // run the chunk loop; we have no DjVu module ported, so the chunk
  // loop is skipped. This is identical to AIFF.pm's `fast3` mode
  // (AIFF.pm:203 `return 1 if $fast3`).
  if magic == Magic::Djvu {
    return Some(Meta {
      magic,
      djvm_multi_page,
      events: Vec::new(),
      composite_duration: None,
      _lifetime: core::marker::PhantomData,
    });
  }

  // AIFF.pm:215 `SetByteOrder('MM')` — AIFF is big-endian throughout.
  // AIFF.pm:220-270 chunk loop.
  let mut events: Vec<AiffEvent> = Vec::new();
  let mut pos: usize = 12;
  // Faithful Perl outer-loop counter (`for ($n=0;;++$n)`, AIFF.pm:220).
  // See the AIFF.pm:259 empty-chunk semantics doc at the loop body.
  let mut n: u32 = 0;
  loop {
    // AIFF.pm:221 `$raf->Read($buff, 8) == 8 or last`. `checked_add`
    // defends a saturating `pos == usize::MAX` from a prior huge-`len2`
    // iteration (32-bit `usize` host); the parser exits cleanly there.
    if pos.checked_add(8).map_or(true, |n| n > data.len()) {
      break;
    }
    // AIFF.pm:223 `my ($tag, $len) = unpack('a4N', $buff)`. The
    // `pos + 8 > data.len()` break above guarantees both 4-byte reads are in
    // range, so `.get(..)` + `[u8; 4]` `try_into` always succeed; the `break`
    // fallback reuses the same short-read exit (byte-identical).
    let Some(tag_bytes) = data
      .get(pos..pos + 4)
      .and_then(|s| <[u8; 4]>::try_from(s).ok())
    else {
      break;
    };
    let Some(len) = data
      .get(pos + 4..pos + 8)
      .and_then(|s| <[u8; 4]>::try_from(s).ok())
      .map(|a| u32::from_be_bytes(a) as usize)
    else {
      break;
    };
    pos += 8; // AIFF.pm:222 `$pos += 8`.
    // AIFF.pm:227 `my $len2 = $len + ($len & 0x01)` — chunks padded to
    // an even number of bytes. Perl scalars are 64-bit; on a 32-bit
    // host `usize` is 32-bit and `len + 1` would wrap when
    // `len == u32::MAX`. We `saturating_add`: `len2` then equals
    // `usize::MAX`, which is guaranteed `> data.len()` so the
    // short-read / unknown-chunk EOF arms both still fire correctly.
    let len2 = len.saturating_add(len & 0x01);
    let tag_str = match core::str::from_utf8(&tag_bytes) {
      Ok(s) => tag_str_to_static(s),
      Err(_) => "", // non-UTF-8 chunk id ⇒ skip via aiff_main_get miss
    };
    let mut tag_info = (AIFF_MAIN.get())(TagId::Str(tag_str));

    // AIFF.pm:228-241 large-chunk handling.
    if len2 > 100_000_000 {
      // AIFF.pm:229-236: `LargeFileSupport` default is `1` (truthy,
      // ExifTool.pm:1167 `[ 'LargeFileSupport', 1, ... ]`), so the
      // `if (not $et->Options('LargeFileSupport'))` and `elsif (... eq
      // '2')` branches BOTH fall through under default options. We
      // faithfully emulate the default-LFS-on Perl behavior, which
      // means neither the "End of processing" nor the "Skipping large
      // chunk (LargeFileSupport is 2)" branch fires. The fall-through
      // reaches AIFF.pm:237-240: known tagInfo ⇒ "Skipping large
      // $$tagInfo{Name} chunk (> 100 MB)" + `undef $tagInfo` so the
      // chunk body is skipped via the `else { Seek }` arm.
      if let Some(def) = tag_info {
        events.push(AiffEvent::Warning(format!(
          "Skipping large {} chunk (> 100 MB)",
          def.name(),
        )));
        tag_info = None;
      }
    }

    if let Some(def) = tag_info {
      // AIFF.pm:248 `$raf->Read($buff, $len2) >= $len or $err=1, last`.
      // Need enough bytes for the (unpadded) `$len` data; the +1 pad
      // byte is allowed to be missing. `pos.checked_add(len)` defends
      // 32-bit `usize` hosts against overflow.
      let need = pos.checked_add(len);
      if need.map_or(true, |n| n > data.len()) {
        events.push(AiffEvent::Warning(format!(
          "Error reading {} file (corrupted?)",
          magic.as_file_type(),
        )));
        break;
      }
      // `need = pos + len <= data.len()` (the guard just above breaks
      // otherwise), so `.get(pos..pos + len)` is always `Some` here; the
      // `break` fallback is unreachable and matches that short-read exit
      // (byte-identical to the prior `&data[pos..pos + len]`).
      let Some(body) = data.get(pos..pos + len) else {
        break;
      };
      // Dispatch by chunk:
      //   COMM  → process_binary_data(AIFF_COMMON, FORMAT=int16u)  → Common
      //   FVER  → process_binary_data(AIFF_FORMAT_VERS, FORMAT=int32u) → str
      //   COMT  → stage_comment (custom)                              → Comment×n
      //   ID3   → deferred (skip body; recognized but no tags emitted)
      //   else  → scalar tag (NAME/AUTH/(c) /ANNO/APPL) — trim trailing
      //           NULs (AIFF.pm:249-251) and decode/copy per def.
      match tag_str {
        "COMM" => {
          if let Some(common) = stage_common(body) {
            events.push(AiffEvent::Common(common));
          }
        }
        "FVER" => {
          if let Some(s) = stage_format_version_time(body) {
            events.push(AiffEvent::FormatVersionTime(s));
          }
        }
        "COMT" => {
          stage_comments(body, &mut events);
        }
        "ID3 " => {
          // Faithful defer (see module doc): skip the ID3 chunk body.
          // SharedFlags::DoneID3 is NOT touched here per
          // [[exifast-phase2-forward-items]] — the bundled-Perl would
          // dispatch to ProcessID3 which then sets DoneID3; since we
          // don't dispatch, we keep DoneID3 untouched.
          let _ = def; // intentional: TagDef recognized but body skipped
        }
        _ => {
          // Scalar tag (NAME, AUTH, '(c) ', ANNO, APPL — all defined
          // in %AIFF::Main with ValueConv `Decode($val, "MacRoman")`
          // for the text tags, no SubDirectory, no Binary).
          let stripped = strip_trailing_nuls(body);
          stage_scalar(tag_str, stripped, &mut events);
        }
      }
      pos = pos.saturating_add(len2); // AIFF.pm:268 `$pos += $len2`.
      // AIFF.pm:269 `$n = 0;` then the for-step `++$n` at top of next:
      n = 0;
      n = n.saturating_add(1);
    } else if len == 0 {
      // AIFF.pm:220,258-261. Perl `for ($n=0;;++$n)` increments `$n`
      // at the END of every iteration; the empty-chunk branch ALSO
      // does `next if ++$n < 100` (AIFF.pm:259), so when the body's
      // `++$n` is STILL `< 100` the loop `next`s — that ALSO runs
      // the for-step `++$n`. Net: `$n` bumps by 2 per consecutive
      // empty chunk on the success path. The abort fires when the
      // body's `++$n` produces `$n >= 100`. So abort at the **51st**
      // consecutive empty chunk from start-of-file, and at the
      // **50th** from a known-tag reset (Codex R1 boundary fix).
      n = n.saturating_add(1); // AIFF.pm:259 `++$n`
      if n >= 100 {
        events.push(AiffEvent::Warning(
          "Aborting scan.  Too many empty chunks".to_string(),
        ));
        break;
      }
      n = n.saturating_add(1); // for-step `++$n` after `next`
    // No `pos += len2` here (len == 0, len2 == 0) — fall-through to top.
    } else {
      // AIFF.pm:265-267 `else { $raf->Seek($len2, 1) or $err=1, last }`.
      // Unknown chunk with non-zero length: skip its body. Perl's
      // `Seek` past EOF is BENIGN on a regular RAF; the next
      // iteration's `Read($buff, 8)` returns 0 and the loop exits
      // without setting `$err`. So we advance `pos` saturating; the
      // next iteration's `pos + 8 > data.len()` check exits cleanly
      // with no "Error reading..." warning.
      pos = pos.saturating_add(len2);
      n = 0;
      n = n.saturating_add(1);
    }
  }

  // AIFF.pm:148 `Image::ExifTool::AddCompositeTags('Image::ExifTool::AIFF')`
  // — compute the %AIFF::Composite Duration tag. AIFF.pm:136-145 defines
  // one composite, `Duration`, with:
  //   `Require => { 0 => 'AIFF:SampleRate', 1 => 'AIFF:NumSampleFrames' }`
  //   `RawConv => '($val[0] and $val[1]) ? $val[1] / $val[0] : undef'`
  //   `PrintConv => 'ConvertDuration($val)'`
  let composite_duration = compute_composite_duration(&events);

  Some(Meta {
    magic,
    djvm_multi_page,
    events,
    composite_duration,
    _lifetime: core::marker::PhantomData,
  })
}

/// AIFF.pm:136-145 composite Duration. `RawConv = $val[1] / $val[0]`
/// (NumSampleFrames / SampleRate). `None` when either input is 0 (Perl
/// `($val[0] and $val[1])` ⇒ undef) or when no COMM was extracted.
///
/// May return a NON-FINITE f64 (Inf / NaN) for adversarial SampleRate
/// extended values; the sink emits those via [`perl_nonfinite_str`].
fn compute_composite_duration(events: &[AiffEvent]) -> Option<f64> {
  // Walk back through events to find the LAST Common (faithful to
  // Perl `FoundTag` last-write-wins for the rare multi-COMM case).
  let common = events.iter().rev().find_map(|e| match e {
    AiffEvent::Common(c) => Some(c),
    _ => None,
  })?;
  // NumSampleFrames is always int32u (Perl IV) — non-zero gate.
  let nf = common.num_sample_frames;
  if nf == 0 {
    return None;
  }
  // SampleRate via Perl `0 + $val` coercion (Int → f64, BigUInt → atof,
  // Float → identity).
  let sr = common.sample_rate.as_f64()?;
  if sr == 0.0 {
    return None;
  }
  Some(f64::from(nf) / sr)
}

/// AIFF.pm:155-178 ProcessComment. Reads `numComments` (u16) then for
/// each: time u32, markerID u16, size u16, text<size>; size is rounded
/// up to even per :175.
fn stage_comments(data: &[u8], events: &mut Vec<AiffEvent>) {
  // AIFF.pm:161 `return 0 unless $dirLen > 2`.
  if data.len() <= 2 {
    return;
  }
  // AIFF.pm:162 `my $numComments = unpack('n', $$dataPt)`. `data.len() > 2`
  // (guard above) ⇒ `first_chunk::<2>` is always `Some` (the `0` fallback is
  // unreachable) — byte-identical to the prior `[data[0], data[1]]` read.
  let num_comments = data
    .first_chunk::<2>()
    .copied()
    .map_or(0, u16::from_be_bytes) as usize;
  let mut pos: usize = 2;
  for _ in 0..num_comments {
    // AIFF.pm:167 `last if $pos + 8 > $dirLen`.
    if pos + 8 > data.len() {
      break;
    }
    // `pos + 8 <= data.len()` (guard above) ⇒ each `.get(..)` + `try_into`
    // always succeeds; the `break` fallback is unreachable and reuses the same
    // short-read exit (byte-identical to the prior fixed-offset reads).
    let Some(time) = data
      .get(pos..pos + 4)
      .and_then(|s| <[u8; 4]>::try_from(s).ok())
      .map(u32::from_be_bytes)
    else {
      break;
    };
    let Some(marker_id) = data
      .get(pos + 4..pos + 6)
      .and_then(|s| <[u8; 2]>::try_from(s).ok())
      .map(u16::from_be_bytes)
    else {
      break;
    };
    let Some(size) = data
      .get(pos + 6..pos + 8)
      .and_then(|s| <[u8; 2]>::try_from(s).ok())
      .map(|a| u16::from_be_bytes(a) as usize)
    else {
      break;
    };
    // AIFF.pm:169 `$et->HandleTag($tagTablePtr, 0, $time);`. ValueConv
    // is ConvertUnixTime (post-AIFF_EPOCH_OFFSET).
    let comment_time = convert_unix_time(i64::from(time) - AIFF_EPOCH_OFFSET);
    // AIFF.pm:170 `$et->HandleTag($tagTablePtr, 1, $markerID) if $markerID;`.
    let marker_id_opt = if marker_id != 0 {
      Some(marker_id)
    } else {
      None
    };
    pos += 8; // AIFF.pm:171 `$pos += 8`.
    // AIFF.pm:172 `last if $pos + $size > $dirLen`.
    if pos + size > data.len() {
      // Faithful: when the size overruns, AIFF.pm emits CommentTime +
      // optionally MarkerID for this entry but NOT Comment text, then
      // `last`s. We push the entry as a partial comment? No — Perl
      // pushes CommentTime/MarkerID via HandleTag BEFORE the gate at
      // :172. We mirror that by pushing a Comment with empty text.
      // BUT: that would diverge from the bundled-Perl which DROPS the
      // text tag entirely on overrun. Let's emit the entry with the
      // already-extracted fields and an empty `comment` string —
      // matching the per-tag emission count Perl produces.
      //
      // (Cross-checked: the AIFF.aif fixture exercises one full
      // comment; no fixture today triggers the overrun, so this
      // branch is defensive.)
      events.push(AiffEvent::Comment(Comment {
        comment_time,
        marker_id: marker_id_opt,
        comment: String::new(),
      }));
      break;
    }
    // AIFF.pm:173-174 `my $val = substr($$dataPt, $pos, $size);
    // $et->HandleTag($tagTablePtr, 2, $val)`. `pos + size <= data.len()` (the
    // guard just above breaks otherwise), so `.get(pos..pos + size)` is always
    // `Some`; the `break` fallback is unreachable (byte-identical).
    let Some(raw_bytes) = data.get(pos..pos + size) else {
      break;
    };
    // ValueConv = Decode(MacRoman).
    let comment = decode_macroman(raw_bytes);
    events.push(AiffEvent::Comment(Comment {
      comment_time,
      marker_id: marker_id_opt,
      comment,
    }));
    // AIFF.pm:175 `++$size if $size & 0x01` — pad to even.
    let padded = size + (size & 1);
    pos += padded;
  }
}

/// `%AIFF::Common` (COMM chunk) processor. Walks the 6-key table via
/// the existing [`process_binary_data`] (which is the shared engine
/// path used by every Format=int16u table) into a staging Metadata,
/// then lifts the tags into a typed [`Common`].
///
/// We call with `print_conv_enabled = false` so the staging values are
/// POST-ValueConv but PRE-PrintConv: the sink path applies PrintConv
/// based on the runtime flag.
fn stage_common(body: &[u8]) -> Option<Common> {
  let mut staging = Metadata::new("aiff-common-staging");
  process_binary_data(
    body,
    "int16u",
    &AIFF_COMMON,
    AIFF_COMMON_KEYS,
    &mut staging,
    /* print_conv_enabled = */ false,
  );

  let mut num_channels: Option<u16> = None;
  let mut num_sample_frames: Option<u32> = None;
  let mut sample_size: Option<u16> = None;
  let mut sample_rate: Option<SampleRate> = None;
  let mut compression_type: Option<CompressionType> = None;
  let mut compressor_name: Option<String> = None;

  for tag in staging.tags_slice() {
    match tag.name() {
      "NumChannels" => {
        if let TagValue::I64(n) = tag.value_ref() {
          num_channels = Some(*n as u16);
        }
      }
      "NumSampleFrames" => {
        if let TagValue::I64(n) = tag.value_ref() {
          num_sample_frames = Some(*n as u32);
        }
      }
      "SampleSize" => {
        if let TagValue::I64(n) = tag.value_ref() {
          sample_size = Some(*n as u16);
        }
      }
      "SampleRate" => {
        sample_rate = Some(match tag.value_ref() {
          TagValue::I64(n) => SampleRate::Int(*n),
          TagValue::F64(x) => SampleRate::Float(*x),
          TagValue::Str(s) => SampleRate::BigUInt(s.to_string()),
          _ => SampleRate::Int(0), // defensive: get_extended doesn't produce others
        });
      }
      "CompressionType" => {
        // Post-ValueConv is identity (None); the value arrives as the
        // raw 4-byte string (process_binary_data routes `Bytes` through
        // fix_utf8 for the Str output under print_conv=false). We
        // re-capture the raw 4 bytes here by recovering the FixUTF8'd
        // string (compression types are ASCII 4-char codes; the
        // FixUTF8 transform is a no-op for them).
        //
        // For high-byte adversarial inputs (Codex R3 fix; e.g.
        // `\x80ABC`), the value arrives as a `TagValue::Str` carrying
        // the FixUTF8-rendered text (e.g. `?ABC`) — we store that as
        // the RawText since the PrintConv hash lookup uses the same
        // FixUTF8 form for keying.
        let raw = match tag.value_ref() {
          TagValue::Str(s) => s.as_bytes().to_vec(),
          TagValue::Bytes(b) => b.clone(),
          _ => Vec::new(),
        };
        compression_type = Some(CompressionType::RawText(raw));
      }
      "CompressorName" => {
        // Post-ValueConv `Decode(MacRoman)` ⇒ TagValue::Str.
        if let TagValue::Str(s) = tag.value_ref() {
          compressor_name = Some(s.to_string());
        }
      }
      _ => {}
    }
  }

  // A COMM chunk is "present enough" if it has at least the first 4
  // mandatory fields (channels, frames, size, rate). When truncated
  // we still emit whatever subset PBD's `entry >= size` early-exit
  // produced (matches AIFC_truncated_comm.aifc which has channels,
  // frames, size, rate, and the start of CompressionType).
  let (Some(num_channels), Some(num_sample_frames), Some(sample_size), Some(sample_rate)) =
    (num_channels, num_sample_frames, sample_size, sample_rate)
  else {
    return None;
  };

  Some(Common {
    num_channels,
    num_sample_frames,
    sample_size,
    sample_rate,
    compression_type,
    compressor_name,
  })
}

/// `%AIFF::FormatVers` (FVER chunk) — one int32u → ConvertUnixTime str.
fn stage_format_version_time(body: &[u8]) -> Option<String> {
  if body.len() < 4 {
    return None;
  }
  // `body.len() >= 4` ⇒ `first_chunk::<4>` is always `Some` (the `0` fallback
  // is unreachable) — byte-identical to the prior `[body[0]..body[3]]` read.
  let raw = body
    .first_chunk::<4>()
    .copied()
    .map_or(0, u32::from_be_bytes);
  // ValueConv: ConvertUnixTime(raw - AIFF_EPOCH_OFFSET).
  Some(convert_unix_time(i64::from(raw) - AIFF_EPOCH_OFFSET))
}

/// Scalar text chunk (NAME, AUTH, '(c) ', ANNO, APPL). The chunk body
/// has already been NUL-trimmed (AIFF.pm:250). Text tags apply MacRoman
/// decode; APPL keeps raw bytes (sink path runs FixUTF8 on it).
fn stage_scalar(tag_str: &str, stripped: &[u8], events: &mut Vec<AiffEvent>) {
  match tag_str {
    "NAME" => events.push(AiffEvent::Name(decode_macroman(stripped))),
    "AUTH" => events.push(AiffEvent::Author(decode_macroman(stripped))),
    "(c) " => events.push(AiffEvent::Copyright(decode_macroman(stripped))),
    "ANNO" => events.push(AiffEvent::Annotation(decode_macroman(stripped))),
    "APPL" => events.push(AiffEvent::ApplicationData(stripped.to_vec())),
    _ => {} // unknown — handled by the `else` arm in the chunk loop
  }
}

/// Trim trailing NULs from a scalar chunk (AIFF.pm:250 `$buff =~ s/\0+$//`).
/// Applied to non-SubDirectory, non-Binary chunks before HandleTag.
fn strip_trailing_nuls(b: &[u8]) -> &[u8] {
  let mut end = b.len();
  // `end > 0` (and `end <= b.len()` always) ⇒ `end - 1 < b.len()`, so
  // `.get(end - 1)` is always `Some`; `.get(..end)` is likewise always `Some`
  // (`end <= b.len()`). Both are byte-identical to the prior `b[end - 1]` /
  // `&b[..end]` (the `unwrap_or(b)` fallback is unreachable).
  while end > 0 && b.get(end - 1) == Some(&0) {
    end -= 1;
  }
  b.get(..end).unwrap_or(b)
}

/// Convert a runtime `&str` chunk tag into a `'static` reference that
/// matches the `TagId::Str(&'static str)` arms in [`aiff_main_get`].
fn tag_str_to_static(s: &str) -> &'static str {
  match s {
    "FVER" => "FVER",
    "COMM" => "COMM",
    "COMT" => "COMT",
    "NAME" => "NAME",
    "AUTH" => "AUTH",
    "(c) " => "(c) ",
    "ANNO" => "ANNO",
    "ID3 " => "ID3 ",
    "APPL" => "APPL",
    _ => "",
  }
}

// ===========================================================================
// `Taggable` — the golden-pattern emission path
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::diagnostics::Diagnose for Meta<'_> {
  /// AIFF's `$et->Warn("Skipping large ... chunk")` (AIFF.pm) as
  /// [`Diagnostic`](crate::diagnostics::Diagnostic) warnings, in chunk-loop
  /// order. AIFF emits no `$et->Error` (the short-header reject returns
  /// `Ok(None)` ⇒ the engine's post-loop `ExifTool:Error` fires instead).
  fn diagnostics(&self) -> std::vec::Vec<crate::diagnostics::Diagnostic> {
    self
      .warnings()
      .map(crate::diagnostics::Diagnostic::warn)
      .collect()
  }
}

#[cfg(feature = "alloc")]
impl crate::emit::Taggable for Meta<'_> {
  /// Yield AIFF tags in faithful chunk-order plus the post-loop Composite
  /// `Duration`. The golden-pattern parallel to the retired
  /// `serialize_tags`: the SINK changes (an [`EmittedTag`](crate::emit::EmittedTag)
  /// per value instead of `out.write_*`), but the emission ORDER, the
  /// per-tag PrintConv/ValueConv branches, and the value variants are
  /// preserved verbatim.
  ///
  /// `mode == PrintConv` (`-j`) ⇒ PrintConv-formatted strings;
  /// `mode == ValueConv` (`-n`) ⇒ post-ValueConv raw scalars.
  ///
  /// Group: AIFF tags use `family0 = family1 = "AIFF"` (AIFF.pm:32 sets only
  /// `GROUPS{2} => 'Audio'`, so family-0/1 default to the table name "AIFF",
  /// verified against the `AIFF.aif` oracle's `AIFF:Name` etc.). The post-loop
  /// Composite `Duration` (AIFF.pm:136-145) is in ExifTool's own `Composite`
  /// table ⇒ `family0 = family1 = "Composite"`. Only family-1 reaches the
  /// `-G1` conformance key (`exiftool:2948`); family-0 is carried faithfully
  /// for the later `iter_tags`. Every AIFF tag is a known tag (no `Unknown=>1`
  /// in any AIFF table) ⇒ `unknown: false`.
  ///
  /// The DjVu branch (AIFF.pm:202-207) emits NO body tags — only the File:*
  /// triplet from `SetFileType` (driven outside the emission path by the
  /// engine's `finalize_file_type` arm). The `(multi-page)` suffix is handled
  /// there too.
  ///
  /// Warnings ([`AiffEvent::Warning`]) are NOT part of the tag stream:
  /// `run_emission` has no warning channel. They are drained from
  /// [`Meta::warnings`] in the `AnyMeta::Aiff` `serialize_tags` arm
  /// (`format_parser.rs`), surfacing through `TagMap::first_warning` as the
  /// `ExifTool:Warning` tag — faithful, and order-independent of the tag
  /// stream (warnings accumulate in their own channel).
  fn tags(
    &self,
    mode: crate::emit::ConvMode,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    use crate::emit::EmittedTag;
    use crate::value::{Group, TagValue};

    // Family-0/1 "AIFF" for every AIFF tag (see fn docs).
    let aiff = || Group::new("AIFF", "AIFF");
    // `-j` (PrintConv) vs `-n` (ValueConv) maps to the `print_conv` bool the
    // retired `serialize_tags` threaded.
    let print_conv = matches!(mode, crate::emit::ConvMode::PrintConv);

    let mut tags: Vec<EmittedTag> = Vec::new();

    // DjVu body parsing is deferred (see module doc). The emission path emits
    // nothing here; the File:FileType suffix is handled by the engine's
    // `finalize_file_type` arm.
    if self.magic == Magic::Djvu {
      return tags.into_iter();
    }

    for ev in &self.events {
      match ev {
        // Warnings are surfaced via the arm draining `Meta::warnings()`, not
        // through the tag stream (`run_emission` has no warning channel).
        AiffEvent::Warning(_) => {}
        AiffEvent::FormatVersionTime(s) => {
          // ValueConv ConvertUnixTime ⇒ already formatted; PrintConv
          // ConvertDateTime is identity under default options ⇒ same
          // string under `-j` and `-n`.
          tags.push(EmittedTag::new(
            aiff(),
            "FormatVersionTime".into(),
            TagValue::Str(s.as_str().into()),
            false,
          ));
        }
        AiffEvent::Common(c) => push_common(&mut tags, c, print_conv),
        AiffEvent::Comment(c) => push_comment(&mut tags, c),
        AiffEvent::Name(s) => tags.push(EmittedTag::new(
          aiff(),
          "Name".into(),
          TagValue::Str(s.as_str().into()),
          false,
        )),
        AiffEvent::Author(s) => tags.push(EmittedTag::new(
          aiff(),
          "Author".into(),
          TagValue::Str(s.as_str().into()),
          false,
        )),
        AiffEvent::Copyright(s) => tags.push(EmittedTag::new(
          aiff(),
          "Copyright".into(),
          TagValue::Str(s.as_str().into()),
          false,
        )),
        AiffEvent::Annotation(s) => tags.push(EmittedTag::new(
          aiff(),
          "Annotation".into(),
          TagValue::Str(s.as_str().into()),
          false,
        )),
        AiffEvent::ApplicationData(b) => {
          // Bundled-Perl emits APPL raw bytes through FixUTF8 (XMP.pm:2943
          // under EscapeJSON). Codex R3 verified an APPL signature like
          // `\x80ABC` lands as `"?ABC"` in JSON. We materialize the
          // FixUTF8 text here and emit as Str (the sink's Str path
          // ⇒ Metadata::push of TagValue::Str ⇒ EscapeJSON of an
          // already-valid UTF-8 string, identity).
          let fixed = crate::convert::fix_utf8(b);
          tags.push(EmittedTag::new(
            aiff(),
            "ApplicationData".into(),
            TagValue::Str(fixed.as_str().into()),
            false,
          ));
        }
      }
    }

    // Composite Duration (AIFF.pm:136-145). Emitted POST-chunk-loop in the
    // bundled-Perl AddCompositeTags pass. Group is ExifTool's own `Composite`
    // table (family-0/1 = "Composite").
    if let Some(secs) = self.composite_duration {
      let value = if print_conv {
        // PrintConv = ConvertDuration. ConvertDuration's `unless
        // IsFloat($time)` early-return is wired through
        // `perl_nonfinite_str` for byte-exact casing of Inf/NaN — but
        // `convert_duration` already routes non-finite values through it, so
        // the formatted string is byte-exact either way.
        TagValue::Str(convert_duration(secs).into())
      } else if let Some(non_finite) = perl_nonfinite_str(secs) {
        // `-n` mode, non-finite. Perl still emits the titlecase text (the
        // serializer's `EscapeJSON` quotes non-numeric scalars); a
        // `TagValue::Str` reproduces that quoted string.
        TagValue::Str(non_finite.into())
      } else {
        // `-n` mode, finite. `TagValue::F64` routes through the serializer's
        // bare-number gate (byte-identical to the retired `write_f64`).
        TagValue::F64(secs)
      };
      tags.push(EmittedTag::new(
        Group::new("Composite", "Composite"),
        "Duration".into(),
        value,
        false,
      ));
    }

    tags.into_iter()
  }
}

/// Push the `%AIFF::Common` (COMM) sub-fields in `ExifTool.pm:9907`
/// `sort { $a <=> $b }` iteration order — keys 0, 1, 3, 4, 9, 11. Each tag is
/// emitted exactly as `process_binary_data` + `convert::apply` produced it
/// (byte-identical to the retired `sink_common`).
#[cfg(feature = "alloc")]
fn push_common(tags: &mut Vec<crate::emit::EmittedTag>, c: &Common, print_conv: bool) {
  use crate::emit::EmittedTag;
  use crate::value::{Group, TagValue};
  let aiff = || Group::new("AIFF", "AIFF");

  // 0 NumChannels (int16u)
  tags.push(EmittedTag::new(
    aiff(),
    "NumChannels".into(),
    TagValue::I64(i64::from(c.num_channels)),
    false,
  ));
  // 1 NumSampleFrames (int32u)
  tags.push(EmittedTag::new(
    aiff(),
    "NumSampleFrames".into(),
    TagValue::U64(u64::from(c.num_sample_frames)),
    false,
  ));
  // 3 SampleSize (int16u)
  tags.push(EmittedTag::new(
    aiff(),
    "SampleSize".into(),
    TagValue::I64(i64::from(c.sample_size)),
    false,
  ));
  // 4 SampleRate (extended)
  push_sample_rate(tags, &c.sample_rate);
  // 9 CompressionType (string[4], AIFC only). PrintConv hash applied here
  //   (or `-n` raw text).
  if let Some(CompressionType::RawText(raw)) = &c.compression_type {
    let key = crate::convert::fix_utf8(raw);
    let value = if print_conv {
      // PrintConv hash lookup. Miss ⇒ "Unknown (X)" where X is the
      // FixUTF8-coerced text (faithful to ExifTool's default-PrintConv
      // fallback path).
      match key.as_str() {
        "NONE" => TagValue::Str("None".into()),
        "ACE2" => TagValue::Str("ACE 2-to-1".into()),
        "ACE8" => TagValue::Str("ACE 8-to-3".into()),
        "MAC3" => TagValue::Str("MAC 3-to-1".into()),
        "MAC6" => TagValue::Str("MAC 6-to-1".into()),
        "sowt" => TagValue::Str("Little-endian, no compression".into()),
        "alaw" => TagValue::Str("a-law".into()),
        "ALAW" => TagValue::Str("A-law".into()),
        "ulaw" => TagValue::Str("mu-law".into()),
        "ULAW" => TagValue::Str("Mu-law".into()),
        "GSM " => TagValue::Str("GSM".into()),
        "G722" => TagValue::Str("G722".into()),
        "G726" => TagValue::Str("G726".into()),
        "G728" => TagValue::Str("G728".into()),
        other => TagValue::Str(format!("Unknown ({other})").into()),
      }
    } else {
      // `-n`: emit the raw FixUTF8'd text. Faithful to Perl `-j -n`:
      // the value is whatever `$val` was after ValueConv (None ⇒ raw
      // FixUTF8 string).
      TagValue::Str(key.as_str().into())
    };
    tags.push(EmittedTag::new(
      aiff(),
      "CompressionType".into(),
      value,
      false,
    ));
  }
  // 11 CompressorName (pstring, MacRoman-decoded)
  push_compressor_name(tags, c);
}

/// Push `CompressorName` (pstring, MacRoman-decoded) when present. No
/// conversions — identical under `-j`/`-n` (byte-identical to the retired
/// `sink_compressor_name`).
#[cfg(feature = "alloc")]
fn push_compressor_name(tags: &mut Vec<crate::emit::EmittedTag>, c: &Common) {
  use crate::emit::EmittedTag;
  use crate::value::{Group, TagValue};
  if let Some(name) = &c.compressor_name {
    tags.push(EmittedTag::new(
      Group::new("AIFF", "AIFF"),
      "CompressorName".into(),
      TagValue::Str(name.as_str().into()),
      false,
    ));
  }
}

/// Push the `SampleRate` (80-bit extended) in its faithful Perl scalar shape
/// (byte-identical to the retired `sink_sample_rate`):
///   - [`SampleRate::Int`] ⇒ `TagValue::I64` (bare number JSON)
///   - [`SampleRate::BigUInt`] ⇒ `TagValue::Str` (serializer quotes the
///     > 15-digit text — the Perl UV path)
///   - [`SampleRate::Float`] finite ⇒ `TagValue::F64` (bare number JSON);
///     non-finite ⇒ `TagValue::Str("Inf"/"-Inf"/"NaN")` via
///     [`perl_nonfinite_str`].
#[cfg(feature = "alloc")]
fn push_sample_rate(tags: &mut Vec<crate::emit::EmittedTag>, sr: &SampleRate) {
  use crate::emit::EmittedTag;
  use crate::value::{Group, TagValue};
  let value = match sr {
    SampleRate::Int(n) => TagValue::I64(*n),
    SampleRate::BigUInt(s) => TagValue::Str(s.as_str().into()),
    SampleRate::Float(x) => match perl_nonfinite_str(*x) {
      Some(non_finite) => TagValue::Str(non_finite.into()),
      None => TagValue::F64(*x),
    },
  };
  tags.push(EmittedTag::new(
    Group::new("AIFF", "AIFF"),
    "SampleRate".into(),
    value,
    false,
  ));
}

/// Push one `%AIFF::Comment` entry's sub-fields in `(CommentTime, [MarkerID],
/// Comment)` order (AIFF.pm:169-174; byte-identical to the retired
/// `sink_comment`).
#[cfg(feature = "alloc")]
fn push_comment(tags: &mut Vec<crate::emit::EmittedTag>, c: &Comment) {
  use crate::emit::EmittedTag;
  use crate::value::{Group, TagValue};
  let aiff = || Group::new("AIFF", "AIFF");
  // AIFF.pm:169 — CommentTime always emitted. PrintConv is identity
  // (ConvertDateTime under default options).
  tags.push(EmittedTag::new(
    aiff(),
    "CommentTime".into(),
    TagValue::Str(c.comment_time.as_str().into()),
    false,
  ));
  // AIFF.pm:170 — MarkerID emitted only when non-zero (we stash None
  // when raw was 0).
  if let Some(mid) = c.marker_id {
    tags.push(EmittedTag::new(
      aiff(),
      "MarkerID".into(),
      TagValue::I64(i64::from(mid)),
      false,
    ));
  }
  // AIFF.pm:173-174 — Comment text emitted regardless (when truncated
  // we emit empty per the stage_comments overrun branch).
  tags.push(EmittedTag::new(
    aiff(),
    "Comment".into(),
    TagValue::Str(c.comment.as_str().into()),
    false,
  ));
}

// ===========================================================================
// `Project` — the normalized cross-format domain projection (golden L2)
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::metadata::Project for Meta<'_> {
  /// Project AIFF metadata onto the normalized [`MediaMetadata`] domain.
  ///
  /// AIFF is an audio container (`%AIFF::Main` `GROUPS{2} => 'Audio'`,
  /// AIFF.pm:32). The faithful [`MediaInfo`](crate::metadata::MediaInfo)
  /// contributions are the recording duration (the Composite `Duration`,
  /// AIFF.pm:136-145, when finite and non-negative) and a single audio
  /// [`TrackKind`](crate::metadata::TrackKind). Dimensions / created stay
  /// `None` (AIFF decodes neither pixel size nor a container creation
  /// timestamp — `FormatVersionTime`/`CommentTime` are chunk-local, not the
  /// file's creation time). Camera / lens / GPS / capture stay `None`
  /// (AIFF carries no such facts).
  fn project(&self) -> crate::metadata::MediaMetadata {
    use crate::metadata::TrackKind;
    let mut media = crate::metadata::MediaMetadata::new();
    // `Meta::duration` already gates to finite, non-negative seconds (returns
    // `None` for the Inf/NaN/negative adversarial Composite values), so the
    // domain duration is faithfully populated only for sane inputs.
    media.media_mut().update_duration(self.duration());
    media.media_mut().track_kinds_mut().push(TrackKind::Audio);
    media
  }
}

// ===========================================================================
// Engine entry — typed parse + File:* + sink into `Metadata`
// ===========================================================================

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2c); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  #[test]
  fn main_table_and_keys_resolve_per_aiff_pm() {
    let g = AIFF_MAIN.get();
    assert_eq!(g(TagId::Str("FVER")).unwrap().name(), "FormatVersion");
    assert_eq!(g(TagId::Str("COMM")).unwrap().name(), "Common");
    assert_eq!(g(TagId::Str("COMT")).unwrap().name(), "Comment");
    assert_eq!(g(TagId::Str("NAME")).unwrap().name(), "Name");
    assert_eq!(g(TagId::Str("AUTH")).unwrap().name(), "Author");
    assert_eq!(g(TagId::Str("(c) ")).unwrap().name(), "Copyright");
    assert_eq!(g(TagId::Str("ANNO")).unwrap().name(), "Annotation");
    assert_eq!(g(TagId::Str("ID3 ")).unwrap().name(), "ID3");
    assert_eq!(g(TagId::Str("APPL")).unwrap().name(), "ApplicationData");
    assert!(g(TagId::Str("XXXX")).is_none());
  }

  #[test]
  fn common_keys_in_ascending_order_match_aiff_pm() {
    // AIFF.pm:88-115: keys 0, 1, 3, 4, 9, 11. ExifTool `sort { $a <=> $b }`.
    assert_eq!(AIFF_COMMON_KEYS, &[0, 1, 3, 4, 9, 11]);
    let g = AIFF_COMMON.get();
    for &k in AIFF_COMMON_KEYS {
      assert!(
        g(TagId::Int(k)).is_some(),
        "AIFF_COMMON_KEYS entry {k} missing"
      );
    }
  }

  #[test]
  fn compression_type_printconv_table_matches_aiff_pm() {
    let def = (AIFF_COMMON.get())(TagId::Int(9)).unwrap();
    assert_eq!(def.name(), "CompressionType");
    let h = match def.print_conv() {
      PrintConv::Hash(h) => h,
      _ => panic!("expected Hash print_conv"),
    };
    let entries = h.direct_entries();
    assert_eq!(entries.len(), 14);
    assert_eq!(entries[0], ("NONE", PrintValue::Str("None")));
    assert_eq!(
      entries[5],
      ("sowt", PrintValue::Str("Little-endian, no compression"))
    );
    assert_eq!(entries[10], ("GSM ", PrintValue::Str("GSM")));
  }

  // The engine path is now `crate::parser::extract_info`. These run it and
  // assert on the parsed JSON object (replacing the retired `ProcessAiff::process`
  // + `TagMap` tests).
  fn engine_obj(name: &str, data: &[u8]) -> serde_json::Map<String, serde_json::Value> {
    let json = crate::parser::extract_info(name, data, true);
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    v.as_array().unwrap()[0].as_object().unwrap().clone()
  }
  /// `true` if the engine finalized a File:FileType in the AIFF family
  /// (AIFF/AIFC/DJVU/DJVU (multi-page)).
  fn aiff_typed(obj: &serde_json::Map<String, serde_json::Value>) -> bool {
    matches!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("AIFF" | "AIFC" | "DJVU" | "DJVU (multi-page)")
    )
  }

  #[test]
  fn rejects_non_form_data() {
    assert!(!aiff_typed(&engine_obj("x", b"NOFORMxxxAIFF")));
  }

  #[test]
  fn rejects_short_data() {
    assert!(!aiff_typed(&engine_obj("x", b"FORM\x00\x00")));
  }

  #[test]
  fn djvu_signature_sets_file_type_and_accepts_with_no_body_tags() {
    let obj = engine_obj("x.djvu", b"AT&TFORMxxxxDJVU");
    assert_eq!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("DJVU")
    );
    // No body tags (only SourceFile + ExifTool:* + File:*).
    let body: Vec<&String> = obj
      .keys()
      .filter(|k| *k != "SourceFile" && !k.starts_with("ExifTool:") && !k.starts_with("File:"))
      .collect();
    assert!(body.is_empty(), "no body tags allowed: {body:?}");
  }

  #[test]
  fn at_t_form_without_djvu_djvm_rejects() {
    assert!(!aiff_typed(&engine_obj("x", b"AT&TFORMxxxxFOOO")));
  }

  #[test]
  fn djvm_signature_appends_multi_page_suffix_to_file_type() {
    let obj = engine_obj("x.djvu", b"AT&TFORMxxxxDJVM");
    assert_eq!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("DJVU (multi-page)")
    );
    assert_eq!(
      obj.get("File:FileTypeExtension").and_then(|v| v.as_str()),
      Some("djvu")
    );
    assert_eq!(
      obj.get("File:MIMEType").and_then(|v| v.as_str()),
      Some("image/vnd.djvu")
    );
  }

  #[test]
  fn aiff_minimal_header_accepts_and_sets_file_type() {
    let obj = engine_obj("x.aif", b"FORM\x00\x00\x00\x04AIFF");
    assert_eq!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("AIFF")
    );
  }

  #[test]
  fn aifc_magic_sets_file_type_aifc() {
    let obj = engine_obj("x.aifc", b"FORM\x00\x00\x00\x04AIFC");
    assert_eq!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("AIFC")
    );
  }

  /// Synthesize an AIFF stream with `n_empty` zero-length unknown chunks.
  fn aiff_with_n_empty_chunks(n_empty: usize) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(b"FORM\x00\x00\x00\x04AIFF");
    for _ in 0..n_empty {
      v.extend_from_slice(b"XXXX\x00\x00\x00\x00");
    }
    v
  }

  #[test]
  fn empty_chunk_streak_below_threshold_does_not_abort() {
    // Perl `for ($n=0;;++$n)` cadence: 50 empties from $n=0 ⇒ no abort.
    let obj = engine_obj("x.aif", &aiff_with_n_empty_chunks(50));
    assert!(
      obj
        .get("ExifTool:Warning")
        .and_then(|v| v.as_str())
        .is_none_or(|w| !w.contains("Aborting scan")),
      "warning: {:?}",
      obj.get("ExifTool:Warning")
    );
  }

  #[test]
  fn empty_chunk_streak_at_threshold_aborts_at_perl_iter_51() {
    // 51 consecutive empty chunks from $n=0 ⇒ Warn + last.
    let obj = engine_obj("x.aif", &aiff_with_n_empty_chunks(60));
    assert_eq!(
      obj.get("ExifTool:Warning").and_then(|v| v.as_str()),
      Some("Aborting scan.  Too many empty chunks")
    );
  }

  #[test]
  fn id3_chunk_recognized_then_silently_skipped() {
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(b"FORM");
    let body_inner = b"ID3 \x00\x00\x00\x04ID3v";
    let total = 4 + body_inner.len();
    data.extend_from_slice(&(total as u32).to_be_bytes());
    data.extend_from_slice(b"AIFF");
    data.extend_from_slice(body_inner);
    let obj = engine_obj("x.aif", &data);
    assert!(obj.contains_key("File:FileType"));
    assert!(
      !obj.keys().any(|k| k.starts_with("AIFF:")),
      "no AIFF:* tags expected from silent ID3 skip"
    );
    assert!(!obj.contains_key("ExifTool:Warning"));
  }

  #[test]
  fn composite_duration_emitted_when_both_inputs_nonzero() {
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(b"FORM");
    // COMM with SampleRate=22050, NumSampleFrames=44100.
    let mut comm_body: Vec<u8> = Vec::new();
    comm_body.extend_from_slice(&1u16.to_be_bytes()); // NumCh
    comm_body.extend_from_slice(&44100u32.to_be_bytes()); // NumSampleFrames
    comm_body.extend_from_slice(&8u16.to_be_bytes()); // SampleSize
    comm_body.extend_from_slice(&0x400D_u16.to_be_bytes()); // extended exp
    comm_body.extend_from_slice(&0xAC44_0000_0000_0000_u64.to_be_bytes()); // sig
    let mut comm_chunk: Vec<u8> = Vec::new();
    comm_chunk.extend_from_slice(b"COMM");
    comm_chunk.extend_from_slice(&(comm_body.len() as u32).to_be_bytes());
    comm_chunk.extend_from_slice(&comm_body);
    let body = [b"AIFF".as_slice(), &comm_chunk].concat();
    data.extend_from_slice(&(body.len() as u32).to_be_bytes());
    data.extend_from_slice(&body);
    let obj = engine_obj("x.aif", &data);
    assert_eq!(
      obj.get("Composite:Duration").and_then(|v| v.as_str()),
      Some("2.00 s")
    );
  }

  #[test]
  fn composite_duration_skipped_when_sample_rate_zero() {
    let data = std::fs::read(format!(
      "{}/tests/fixtures/AIFF.aif",
      env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read AIFF.aif fixture");
    let obj = engine_obj("x.aif", &data);
    assert!(
      !obj.contains_key("Composite:Duration"),
      "Composite:Duration must NOT be emitted when SampleRate=0"
    );
  }

  #[test]
  fn stage_comments_handles_truncated_input() {
    // numComments=2 but only one fits — second iteration `last`s.
    let mut events: Vec<AiffEvent> = Vec::new();
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&2u16.to_be_bytes()); // numComments
    data.extend_from_slice(&0u32.to_be_bytes()); // time
    data.extend_from_slice(&0u16.to_be_bytes()); // markerID = 0 ⇒ None
    data.extend_from_slice(&4u16.to_be_bytes()); // size
    data.extend_from_slice(b"abcd"); // text
    // Second comment header truncated: data ends after first.
    stage_comments(&data, &mut events);
    assert_eq!(events.len(), 1, "one Comment per stage; got {:?}", events);
    if let AiffEvent::Comment(c) = &events[0] {
      assert_eq!(c.marker_id(), None);
      assert_eq!(c.comment(), "abcd");
    } else {
      panic!("expected Comment event");
    }
  }

  #[test]
  fn strip_trailing_nuls_handles_edges() {
    assert_eq!(strip_trailing_nuls(b""), b"");
    assert_eq!(strip_trailing_nuls(b"abc"), b"abc");
    assert_eq!(strip_trailing_nuls(b"abc\0"), b"abc");
    assert_eq!(strip_trailing_nuls(b"abc\0\0\0"), b"abc");
    assert_eq!(strip_trailing_nuls(b"\0\0"), b"");
  }

  #[test]
  fn typed_meta_accessors_round_trip_via_parse_borrowed() {
    // Synthesize a tiny AIFF with NAME and COMM ⇒ exercise the typed
    // accessor surface (common, name, duration).
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(b"FORM");
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(b"AIFF");
    // COMM
    let mut comm_body: Vec<u8> = Vec::new();
    comm_body.extend_from_slice(&2u16.to_be_bytes()); // NumCh
    comm_body.extend_from_slice(&88200u32.to_be_bytes()); // NumSampleFrames
    comm_body.extend_from_slice(&16u16.to_be_bytes()); // SampleSize
    comm_body.extend_from_slice(&0x400D_u16.to_be_bytes()); // extended exp 22050
    comm_body.extend_from_slice(&0xAC44_0000_0000_0000_u64.to_be_bytes()); // sig
    body.extend_from_slice(b"COMM");
    body.extend_from_slice(&(comm_body.len() as u32).to_be_bytes());
    body.extend_from_slice(&comm_body);
    // NAME
    body.extend_from_slice(b"NAME");
    body.extend_from_slice(&5u32.to_be_bytes());
    body.extend_from_slice(b"Hello");
    body.extend_from_slice(&[0]); // even-length pad
    data.extend_from_slice(&(body.len() as u32).to_be_bytes());
    data.extend_from_slice(&body);

    let meta = parse_borrowed(&data).expect("AIFF parsed");
    assert_eq!(meta.magic(), Magic::Aiff);
    assert_eq!(meta.name(), Some("Hello"));
    let common = meta.common().expect("COMM extracted");
    assert_eq!(common.num_channels(), 2);
    assert_eq!(common.num_sample_frames(), 88200);
    assert_eq!(common.sample_size(), 16);
    // 22050 from 0x400D AC44... extended ⇒ get_extended returns F64
    // (exp != 0 ⇒ Perl NV path even for integer-valued results). Codex
    // R10 documented this divergence; the SampleRate variant matches.
    assert!(
      matches!(common.sample_rate_ref(), SampleRate::Float(x) if (*x - 22050.0).abs() < 1e-9)
    );
    let dur = meta.duration().expect("duration finite & positive");
    assert!((dur.as_secs_f64() - 4.0).abs() < 1e-9);
  }

  // ---------- §2/§3 convention surface -----------------------------------

  #[test]
  fn aiff_magic_predicates_and_display_route_through_as_file_type() {
    // §2: is_* predicates (derive_more::IsVariant).
    assert!(Magic::Aiff.is_aiff());
    assert!(Magic::Aifc.is_aifc());
    assert!(Magic::Djvu.is_djvu());
    assert!(!Magic::Aiff.is_djvu());
    // §2: Display is the single `as_file_type` source of truth.
    for m in [Magic::Aiff, Magic::Aifc, Magic::Djvu] {
      assert_eq!(m.to_string(), m.as_file_type());
    }
    assert_eq!(Magic::Aifc.to_string(), "AIFC");
  }

  #[test]
  fn aiff_sample_rate_predicates_and_unwrap_accessors() {
    let i = SampleRate::Int(44_100);
    assert!(i.is_int());
    assert_eq!(*i.unwrap_int_ref(), 44_100);
    let b = SampleRate::BigUInt("18446744073709551615".into());
    assert!(b.is_big_u_int());
    assert!(b.try_unwrap_float_ref().is_err());
    let f = SampleRate::Float(48_000.5);
    assert!(f.is_float());
    assert!((f.try_unwrap_float_ref().copied().unwrap() - 48_000.5).abs() < 1e-9);
    // Non-finite faithful behavior preserved through as_f64.
    assert!(
      SampleRate::Float(f64::INFINITY)
        .as_f64()
        .unwrap()
        .is_infinite()
    );
  }

  #[test]
  fn aiff_compression_type_raw_text_projects_to_slice() {
    let c = CompressionType::RawText(b"NONE".to_vec());
    assert!(c.is_raw_text());
    assert_eq!(c.raw_text(), b"NONE");
    assert_eq!(c.unwrap_raw_text_ref().as_slice(), b"NONE");
  }
  // ---------- golden-pattern `Taggable` / `Project` surface --------------

  /// Drive the `Meta` through the golden-pattern engine
  /// ([`run_emission`](crate::emit::run_emission)) for `mode` and return the
  /// resulting [`TagMap`](crate::tagmap::TagMap) — the production sink path.
  fn emit_into_tagmap(meta: &Meta<'_>, mode: crate::emit::ConvMode) -> crate::tagmap::TagMap {
    let mut w = crate::tagmap::TagMap::new();
    crate::emit::run_emission(meta, mode, &mut w);
    w
  }

  /// AIFC.aifc: the COMM sub-fields (incl. the CompressionType PrintConv
  /// hash + CompressorName + the Int(0) SampleRate) and the FormatVersionTime
  /// / Name scalars emit byte-identically to the `AIFC.aifc` golden under
  /// both `-j` and `-n`.
  #[test]
  fn taggable_emits_aifc_common_and_scalars() {
    use crate::emit::ConvMode;
    let data = std::fs::read(format!(
      "{}/tests/fixtures/AIFC.aifc",
      env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read AIFC.aifc fixture");
    let meta = parse_borrowed(&data).expect("AIFC parsed");

    // -j (PrintConv).
    let w = emit_into_tagmap(&meta, ConvMode::PrintConv);
    assert_eq!(
      w.get_str("AIFF", "FormatVersionTime"),
      Some("1990:05:23 14:40:00".to_string())
    );
    assert_eq!(w.get_str("AIFF", "NumChannels"), Some("1".to_string()));
    assert_eq!(
      w.get_str("AIFF", "NumSampleFrames"),
      Some("11554".to_string())
    );
    assert_eq!(w.get_str("AIFF", "SampleSize"), Some("8".to_string()));
    // SampleRate Int(0) ⇒ bare number "0".
    assert_eq!(w.get("AIFF", "SampleRate"), Some(&TagValue::I64(0)));
    // CompressionType PrintConv hash: "NONE" ⇒ "None".
    assert_eq!(
      w.get_str("AIFF", "CompressionType"),
      Some("None".to_string())
    );
    assert_eq!(
      w.get_str("AIFF", "CompressorName"),
      Some("Not Compressed".to_string())
    );
    assert_eq!(
      w.get_str("AIFF", "Name"),
      Some("ExifTool test AIFC".to_string())
    );

    // -n (ValueConv): CompressionType emits the raw FixUTF8 text "NONE".
    let w = emit_into_tagmap(&meta, ConvMode::ValueConv);
    assert_eq!(
      w.get_str("AIFF", "CompressionType"),
      Some("NONE".to_string())
    );
    assert_eq!(w.get("AIFF", "SampleRate"), Some(&TagValue::I64(0)));
  }

  /// AIFF_duration.aif: the post-loop Composite `Duration` lands under the
  /// `Composite` family-1 group as the ConvertDuration string `"2.00 s"`
  /// (`-j`) / the bare number `2` from `F64(2.0)` (`-n`) — byte-identical to
  /// the `AIFF_duration.aif` golden.
  #[test]
  fn taggable_emits_composite_duration() {
    use crate::emit::ConvMode;
    let data = std::fs::read(format!(
      "{}/tests/fixtures/AIFF_duration.aif",
      env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read AIFF_duration.aif fixture");
    let meta = parse_borrowed(&data).expect("AIFF parsed");

    // -j: ConvertDuration string, under the Composite (-G1) group.
    let w = emit_into_tagmap(&meta, ConvMode::PrintConv);
    assert_eq!(
      w.get_str("Composite", "Duration"),
      Some("2.00 s".to_string())
    );
    assert_eq!(w.get_str("AIFF", "SampleRate"), Some("22050".to_string()));

    // -n: finite f64 ⇒ bare number (serializer renders 2.0 as `2`); assert
    // the variant carried is F64 so the bare-number gate applies.
    let w = emit_into_tagmap(&meta, ConvMode::ValueConv);
    assert_eq!(w.get("Composite", "Duration"), Some(&TagValue::F64(2.0)));
  }

  /// `tags()` yields AIFF tags under family-0/1 `"AIFF"` and the Composite
  /// `Duration` under family-0/1 `"Composite"`; no tag is `Unknown=>1`.
  #[test]
  fn taggable_group_family0_family1_and_unknown() {
    use crate::emit::{ConvMode, Taggable};
    let data = std::fs::read(format!(
      "{}/tests/fixtures/AIFF_duration.aif",
      env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read AIFF_duration.aif fixture");
    let meta = parse_borrowed(&data).expect("AIFF parsed");
    let tags: Vec<_> = meta.tags(ConvMode::PrintConv).collect();

    let mut saw_aiff = false;
    let mut saw_composite = false;
    for t in &tags {
      assert!(!t.unknown(), "no AIFF table carries Unknown=>1");
      match t.tag().name() {
        "Duration" => {
          // Composite table is its own group0/1.
          assert_eq!(t.tag().group_ref().family0(), "Composite");
          assert_eq!(t.tag().group_ref().family1(), "Composite");
          saw_composite = true;
        }
        _ => {
          assert_eq!(t.tag().group_ref().family0(), "AIFF");
          assert_eq!(t.tag().group_ref().family1(), "AIFF");
          saw_aiff = true;
        }
      }
    }
    assert!(saw_aiff, "expected at least one AIFF-group tag");
    assert!(saw_composite, "expected the Composite Duration tag");
    // Emission order: the COMM sub-fields precede the post-loop Duration.
    assert_eq!(tags.last().unwrap().tag().name(), "Duration");
  }

  /// The DjVu branch (`AT&TFORM` + `DJVU`) emits NO body tags through the
  /// `Taggable` stream — the File:* triplet is the engine's job.
  #[test]
  fn taggable_djvu_emits_no_body_tags() {
    use crate::emit::{ConvMode, Taggable};
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(b"AT&TFORM");
    data.extend_from_slice(&0u32.to_be_bytes()); // FORM length (unused here)
    data.extend_from_slice(b"DJVU");
    let meta = parse_borrowed(&data).expect("DjVu parsed");
    assert_eq!(meta.magic(), Magic::Djvu);
    assert_eq!(meta.tags(ConvMode::PrintConv).count(), 0);
  }

  /// `project()` populates one audio [`TrackKind`] plus the finite Composite
  /// `Duration`; camera / lens / GPS / capture / dimensions / created stay
  /// empty (AIFF carries none of those).
  #[test]
  fn project_populates_audio_track_and_duration() {
    use crate::metadata::{Project, TrackKind};
    let data = std::fs::read(format!(
      "{}/tests/fixtures/AIFF_duration.aif",
      env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read AIFF_duration.aif fixture");
    let meta = parse_borrowed(&data).expect("AIFF parsed");
    let projected = meta.project();

    assert_eq!(projected.media().track_kinds(), &[TrackKind::Audio]);
    assert!(projected.media().has_audio());
    assert!(!projected.media().has_video());
    // The Composite Duration (2 s) flows into the domain duration.
    assert_eq!(
      projected.media().duration().map(|d| d.as_secs_f64()),
      Some(2.0)
    );
    // AIFF decodes no pixel size / container creation timestamp.
    assert!(projected.media().width().is_none());
    assert!(projected.media().height().is_none());
    assert!(projected.media().created().is_none());
    // No camera / lens / GPS / capture facts.
    assert!(projected.camera().is_none());
    assert!(projected.lens().is_none());
    assert!(projected.gps().is_none());
    assert!(projected.capture().is_none());
  }

  /// A file with no finite Composite Duration (the `AIFF.aif` oracle has
  /// SampleRate=0 ⇒ no Duration) still projects the audio track kind, with
  /// the domain duration left `None`.
  #[test]
  fn project_audio_track_without_duration() {
    use crate::metadata::{Project, TrackKind};
    let data = std::fs::read(format!(
      "{}/tests/fixtures/AIFF.aif",
      env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read AIFF.aif fixture");
    let meta = parse_borrowed(&data).expect("AIFF parsed");
    let projected = meta.project();
    assert_eq!(projected.media().track_kinds(), &[TrackKind::Audio]);
    assert!(projected.media().duration().is_none());
  }
}
