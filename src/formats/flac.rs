// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "flac")]
//! Faithful port of `Image::ExifTool::FLAC` (lib/Image/ExifTool/FLAC.pm).
//!
//! A typed [`Meta<'a>`] is produced by the
//! [`crate::format_parser::FormatParser`] trait; the golden-pattern
//! [`Taggable`](crate::emit::Taggable) impl emits StreamInfo/Picture/Composite
//! plus the list-aware VorbisComment stream through the generic
//! [`run_emission`](crate::emit::run_emission) engine, so the serialized JSON
//! stays byte-exact with bundled `perl exiftool`.
//!
//! ## What FLAC is
//!
//! Free Lossless Audio Codec. ExifTool's FLAC reader (FLAC.pm:239-280)
//! reads the `fLaC` magic + a chain of metadata blocks; each block carries
//! a 4-byte header (`last-flag<<7 | block_type` + 24-bit BE length) +
//! payload. Block types we extract:
//!
//! - 0 StreamInfo (FLAC.pm:27-30) → 9 bit-field tags via bit-stream walk
//! - 4 VorbisComment (FLAC.pm:46-49) → inline Vorbis comment block
//! - 6 Picture (FLAC.pm:51-54) → binary-data layout with var_pstr32 strings
//!
//! Other blocks (Padding, SeekTable, Application, CueSheet) are skipped
//! faithfully; the `Application/riff` arm (RIFF::Main) is deferred until
//! RIFF.pm lands.
//!
//! ## ID3 chaining (FLAC.pm:243-247)
//!
//! Bundled FLAC reads ID3v2 first via `ID3::ProcessID3` — sets `$$et{DoneID3}`
//! and continues to the FLAC body iff the ID3 path returns 0. The FLAC body
//! starts AFTER the ID3v2 header (10-byte hdr + synchsafe-encoded payload
//! length + optional 10-byte v2.4 footer if `flags & 0x10`).
//!
//! F1 (Codex adversarial): the typed parser nests an `Id3Meta` sub-Meta on
//! `flac::Meta` via the SAME entry APE/DSF use
//! (`crate::formats::id3::process::parse_id3_with_hdr_end`). The `Taggable`
//! impl splices the chained ID3 tags (`File:ID3Size` + every `ID3v2_*:*`
//! frame) BEFORE the FLAC body tags — so the golden emission path matches
//! bundled `perl exiftool` byte-for-byte on ID3-prefixed FLAC fixtures (no
//! hand-trimming required).

// Golden-v2 Contract 3c (Phase C, slice B / w2b): panic-safety by construction —
// every raw index/slice is converted to a checked `.get()` form below.
#![deny(clippy::indexing_slicing)]

use core::time::Duration;
use std::borrow::Cow;
use std::string::String;
use std::vec::Vec;

use crate::format_parser::{FormatParser, parser_sealed};
use crate::tagtable::{PrintConv, TagDef, TagId, TagTable, ValueConv};
use crate::value::TagValue;

/// xtask-GENERATED `%FLAC::StreamInfo` table (`cargo xtask gen-tables --kind
/// tagdef --module FLAC::StreamInfo`). Consulted by [`flac_streaminfo_get`]
/// ONLY as the ADDITIVE fallback — the hand `static`s shadow every `Bit*` key
/// (hand wins on collision). LOAD-BEARING: `-listx` carries no ValueConv
/// expression, so the generated twins of `Channels` / `BitsPerSample`
/// (`$val + 1`) and `MD5Signature` (`unpack("H*",$val)` hex) are
/// `ValueConv::None` and WOULD REGRESS those fields if they won. The hand
/// entries (with their `ValueConv::Func`) win, so output is byte-identical;
/// the generated layer is the drift guard, contributing 0 new tags.
#[path = "flac_streaminfo_generated.rs"]
mod streaminfo_generated;

/// xtask-GENERATED `%Vorbis::Comments` table (`cargo xtask gen-tables --kind
/// tagdef --module Vorbis::Comments`). Consulted by [`vorbis_comments_get`]
/// ONLY as the ADDITIVE fallback. LOAD-BEARING: the hand list-tags
/// (Artist/Performer/Contact carry `.with_list(true)`) and the
/// auto-name/dynamic-add behaviour are not expressible via `-listx`, so the
/// hand layer must win. The drift guard regenerates from the same
/// `Vorbis::Comments` table OGG checks (`ogg_generated.rs`); 0 new tags.
#[path = "flac_vorbis_generated.rs"]
mod vorbis_generated;

/// xtask-GENERATED `%FLAC::Picture` table — DRIFT-GUARD ONLY (no wire). FLAC
/// Picture tags are emitted via the typed [`Picture`] struct (the golden
/// `FLAC_picture.flac` proves byte-identical), NOT through a `TagId`-keyed
/// `fn get` lookup — there is no hand `flac_picture_get` to fall through into.
/// The committed table exists solely so `tests/xtask_check.rs` fails if a
/// future ExifTool version shifts `%FLAC::Picture` (PictureType PrintConv map,
/// field set); it is never consulted at runtime. `#[allow(dead_code)]` because
/// `get` has no caller by design.
#[path = "flac_picture_generated.rs"]
#[allow(dead_code)]
mod picture_generated;

/// xtask-GENERATED `%FLAC::Main` table — DRIFT-GUARD ONLY (no wire). FLAC
/// metadata-block dispatch is a `match block_type` in [`parse_inner`] (the
/// block-type integer is NOT a `TagId` lookup), and every `%FLAC::Main` tag is
/// an `Unknown`/`Binary` skip-block (Padding/SeekTable/CueSheet/
/// ApplicationUnknown) that is never emitted. The committed table is the drift
/// guard only; `#[allow(dead_code)]` because `get` has no caller by design.
#[path = "flac_main_generated.rs"]
#[allow(dead_code)]
mod main_generated;

// ===========================================================================
// Static %FLAC::StreamInfo + %FLAC::Picture + %Vorbis::Comments tables
//
// Kept ALONGSIDE the typed Meta so the engine entry `process` (and
// downstream consumers such as `tests/flac_streaminfo.rs`) keep their
// faithful tag-table identities (group strings, ValueConv functions, list
// flags, etc.). The typed parser does NOT depend on these tables for
// extraction — it consumes raw bytes directly — but the sink path emits
// family-1 groups derived from `TABLE.group0()` so the tables remain the
// source of truth for group identity.
// ===========================================================================

// ----- %FLAC::StreamInfo (FLAC.pm:59-82) ----------------------------------

/// FLAC.pm:70,74 — `ValueConv => '$val + 1'` for Channels (Bit100-102) and
/// BitsPerSample (Bit103-107). Pure on `TagValue::I64`; falls through for any
/// other variant (defensive — an unexpected non-I64 here would indicate a
/// bit-stream extraction bug).
fn streaminfo_add_one(v: &TagValue) -> TagValue {
  match v {
    TagValue::I64(n) => TagValue::I64(n.saturating_add(1)),
    other => other.clone(),
  }
}

/// FLAC.pm:80 — `ValueConv => 'unpack("H*",$val)'`. Bit144-271 (MD5Signature)
/// carries `Format => 'undef'` (FLAC.pm:79); the bit-stream emits the raw 16
/// bytes as `TagValue::Bytes`; this renders them as lowercase hex exactly as
/// Perl's `unpack("H*", ...)` does.
fn streaminfo_unpack_h_star(v: &TagValue) -> TagValue {
  match v {
    TagValue::Bytes(b) => TagValue::Str(format_md5_hex(b).into()),
    other => other.clone(),
  }
}

/// Render 16 raw MD5 bytes as 32 lowercase hex characters — faithful to
/// Perl `unpack("H*", $val)` (FLAC.pm:80).
fn format_md5_hex(b: &[u8]) -> String {
  use core::fmt::Write as _;
  let mut s = String::with_capacity(b.len() * 2);
  for x in b {
    let _ = write!(&mut s, "{x:02x}");
  }
  s
}

// FLAC.pm:63  'Bit000-015' => 'BlockSizeMin'
static FLAC_BLOCK_SIZE_MIN: TagDef =
  TagDef::new("BlockSizeMin", "FLAC", ValueConv::None, PrintConv::None);
// FLAC.pm:64  'Bit016-031' => 'BlockSizeMax'
static FLAC_BLOCK_SIZE_MAX: TagDef =
  TagDef::new("BlockSizeMax", "FLAC", ValueConv::None, PrintConv::None);
// FLAC.pm:65  'Bit032-055' => 'FrameSizeMin'
static FLAC_FRAME_SIZE_MIN: TagDef =
  TagDef::new("FrameSizeMin", "FLAC", ValueConv::None, PrintConv::None);
// FLAC.pm:66  'Bit056-079' => 'FrameSizeMax'
static FLAC_FRAME_SIZE_MAX: TagDef =
  TagDef::new("FrameSizeMax", "FLAC", ValueConv::None, PrintConv::None);
// FLAC.pm:67  'Bit080-099' => 'SampleRate'
static FLAC_SAMPLE_RATE: TagDef =
  TagDef::new("SampleRate", "FLAC", ValueConv::None, PrintConv::None);
// FLAC.pm:68-71  'Bit100-102' => { Name => 'Channels', ValueConv => '$val + 1' }
static FLAC_CHANNELS: TagDef = TagDef::new(
  "Channels",
  "FLAC",
  ValueConv::Func(streaminfo_add_one),
  PrintConv::None,
);
// FLAC.pm:72-75  'Bit103-107' => { Name => 'BitsPerSample', ValueConv => '$val + 1' }
static FLAC_BITS_PER_SAMPLE: TagDef = TagDef::new(
  "BitsPerSample",
  "FLAC",
  ValueConv::Func(streaminfo_add_one),
  PrintConv::None,
);
// FLAC.pm:76  'Bit108-143' => 'TotalSamples'
static FLAC_TOTAL_SAMPLES: TagDef =
  TagDef::new("TotalSamples", "FLAC", ValueConv::None, PrintConv::None);
// FLAC.pm:77-81  'Bit144-271' => { Name => 'MD5Signature', Format => 'undef',
//                                   ValueConv => 'unpack("H*",$val)' }
static FLAC_MD5_SIGNATURE: TagDef = TagDef::new(
  "MD5Signature",
  "FLAC",
  ValueConv::Func(streaminfo_unpack_h_star),
  PrintConv::None,
)
.with_format("undef"); // FLAC.pm:79

fn flac_streaminfo_get(id: TagId) -> Option<&'static TagDef> {
  // Hand-first (additive-codegen invariant): the hand `static`s WIN on every
  // `Bit*` key. `FLAC_CHANNELS` / `FLAC_BITS_PER_SAMPLE` (`ValueConv::Func`
  // `$val + 1`) and `FLAC_MD5_SIGNATURE` (`ValueConv::Func` hex unpack) are the
  // load-bearing collisions — the generated twins carry `ValueConv::None` and
  // would regress them. The hand layer is complete for all 9 keys, so
  // [`streaminfo_generated::get`] never fires — it is the drift guard.
  let hand = match id {
    TagId::Str("Bit000-015") => Some(&FLAC_BLOCK_SIZE_MIN),
    TagId::Str("Bit016-031") => Some(&FLAC_BLOCK_SIZE_MAX),
    TagId::Str("Bit032-055") => Some(&FLAC_FRAME_SIZE_MIN),
    TagId::Str("Bit056-079") => Some(&FLAC_FRAME_SIZE_MAX),
    TagId::Str("Bit080-099") => Some(&FLAC_SAMPLE_RATE),
    TagId::Str("Bit100-102") => Some(&FLAC_CHANNELS),
    TagId::Str("Bit103-107") => Some(&FLAC_BITS_PER_SAMPLE),
    TagId::Str("Bit108-143") => Some(&FLAC_TOTAL_SAMPLES),
    TagId::Str("Bit144-271") => Some(&FLAC_MD5_SIGNATURE),
    _ => None,
  };
  hand.or_else(|| streaminfo_generated::get(id))
}

/// Faithful `%Image::ExifTool::FLAC::StreamInfo` (FLAC.pm:59-82). Kept public
/// for downstream tests and shared bit-stream callers (e.g.
/// `tests/flac_streaminfo.rs`); the typed [`Meta`] parser does not
/// consult it directly.
pub static FLAC_STREAMINFO_TABLE: TagTable = TagTable::new("FLAC", flac_streaminfo_get);

/// The 9 `Bit<a>-<b>` keys of `%FLAC::StreamInfo` (ExifTool `sort keys`,
/// FLAC.pm:172) in ASCENDING bit-offset order — required invariant for
/// [`crate::bitstream::process_bit_stream`].
pub const FLAC_STREAMINFO_BIT_KEYS: &[&str] = &[
  "Bit000-015", // BlockSizeMin   (FLAC.pm:63)
  "Bit016-031", // BlockSizeMax   (FLAC.pm:64)
  "Bit032-055", // FrameSizeMin   (FLAC.pm:65)
  "Bit056-079", // FrameSizeMax   (FLAC.pm:66)
  "Bit080-099", // SampleRate     (FLAC.pm:67)
  "Bit100-102", // Channels       (FLAC.pm:68)
  "Bit103-107", // BitsPerSample  (FLAC.pm:72)
  "Bit108-143", // TotalSamples   (FLAC.pm:76)
  "Bit144-271", // MD5Signature   (FLAC.pm:77)
];

// ----- %FLAC::Picture (FLAC.pm:84-134) ------------------------------------

/// Map a raw `PictureType` int32u to its bundled-Perl PrintConv string
/// (`%FLAC::Picture{PictureType}`, FLAC.pm:88-113). `None` for any value
/// outside the 0..=20 table (faithful: `Unknown (N)` is NOT in the table;
/// for an unknown code ExifTool's default `PrintConv` falls back to the
/// numeric value as a string).
///
/// `pub(crate)` so OGG's `METADATA_BLOCK_PICTURE` SubDirectory hop
/// (R3 F2 — Vorbis.pm:122-134) can resolve the same PrintConv on the
/// decoded payload (the on-wire structure is identical to FLAC's type-6
/// block).
#[must_use]
pub(crate) const fn picture_type_name(code: u32) -> Option<&'static str> {
  match code {
    0 => Some("Other"),
    1 => Some("32x32 PNG Icon"),
    2 => Some("Other Icon"),
    3 => Some("Front Cover"),
    4 => Some("Back Cover"),
    5 => Some("Leaflet"),
    6 => Some("Media"),
    7 => Some("Lead Artist"),
    8 => Some("Artist"),
    9 => Some("Conductor"),
    10 => Some("Band"),
    11 => Some("Composer"),
    12 => Some("Lyricist"),
    13 => Some("Recording Studio or Location"),
    14 => Some("Recording Session"),
    15 => Some("Performance"),
    16 => Some("Capture from Movie or Video"),
    17 => Some("Bright(ly) Colored Fish"),
    18 => Some("Illustration"),
    19 => Some("Band Logo"),
    20 => Some("Publisher Logo"),
    _ => None,
  }
}

// ----- %Vorbis::Comments (Vorbis.pm:72-135) -------------------------------
//
// The named-tag map below mirrors the subset of Vorbis.pm:80-121 ported in
// the original FLAC port. Family-0 group "Vorbis" (matches bundled-Perl
// JSON keys `"Vorbis:Vendor"` etc.); family-1 also "Vorbis" — none of the
// entries carry a `Groups => { 1 => ... }` override.
//
// `List => 1` keys: ARTIST (:85), PERFORMER (:86), CONTACT (:94).
// These accumulate into a JSON array via `Metadata::push_listable` on the
// bridge path; the typed Meta exposes them as `Vec<&'a str>`.

static V_VENDOR: TagDef = TagDef::new("Vendor", "Vorbis", ValueConv::None, PrintConv::None);
static V_TITLE: TagDef = TagDef::new("Title", "Vorbis", ValueConv::None, PrintConv::None);
static V_VERSION: TagDef = TagDef::new("Version", "Vorbis", ValueConv::None, PrintConv::None);
static V_ALBUM: TagDef = TagDef::new("Album", "Vorbis", ValueConv::None, PrintConv::None);
static V_TRACKNUMBER: TagDef =
  TagDef::new("TrackNumber", "Vorbis", ValueConv::None, PrintConv::None);
static V_ARTIST: TagDef =
  TagDef::new("Artist", "Vorbis", ValueConv::None, PrintConv::None).with_list(true);
static V_PERFORMER: TagDef =
  TagDef::new("Performer", "Vorbis", ValueConv::None, PrintConv::None).with_list(true);
static V_COPYRIGHT: TagDef = TagDef::new("Copyright", "Vorbis", ValueConv::None, PrintConv::None);
static V_LICENSE: TagDef = TagDef::new("License", "Vorbis", ValueConv::None, PrintConv::None);
static V_ORGANIZATION: TagDef =
  TagDef::new("Organization", "Vorbis", ValueConv::None, PrintConv::None);
static V_DESCRIPTION: TagDef =
  TagDef::new("Description", "Vorbis", ValueConv::None, PrintConv::None);
static V_GENRE: TagDef = TagDef::new("Genre", "Vorbis", ValueConv::None, PrintConv::None);
static V_DATE: TagDef = TagDef::new("Date", "Vorbis", ValueConv::None, PrintConv::None);
static V_LOCATION: TagDef = TagDef::new("Location", "Vorbis", ValueConv::None, PrintConv::None);
static V_CONTACT: TagDef =
  TagDef::new("Contact", "Vorbis", ValueConv::None, PrintConv::None).with_list(true);
static V_ISRC: TagDef = TagDef::new("ISRCNumber", "Vorbis", ValueConv::None, PrintConv::None);
static V_COVERARTMIME: TagDef = TagDef::new(
  "CoverArtMIMEType",
  "Vorbis",
  ValueConv::None,
  PrintConv::None,
);
static V_REPLAYGAIN_TRACK_PEAK: TagDef = TagDef::new(
  "ReplayGainTrackPeak",
  "Vorbis",
  ValueConv::None,
  PrintConv::None,
);
static V_REPLAYGAIN_TRACK_GAIN: TagDef = TagDef::new(
  "ReplayGainTrackGain",
  "Vorbis",
  ValueConv::None,
  PrintConv::None,
);
static V_REPLAYGAIN_ALBUM_PEAK: TagDef = TagDef::new(
  "ReplayGainAlbumPeak",
  "Vorbis",
  ValueConv::None,
  PrintConv::None,
);
static V_REPLAYGAIN_ALBUM_GAIN: TagDef = TagDef::new(
  "ReplayGainAlbumGain",
  "Vorbis",
  ValueConv::None,
  PrintConv::None,
);
static V_ENCODED_USING: TagDef =
  TagDef::new("EncodedUsing", "Vorbis", ValueConv::None, PrintConv::None);
static V_ENCODED_BY: TagDef = TagDef::new("EncodedBy", "Vorbis", ValueConv::None, PrintConv::None);
static V_COMMENT: TagDef = TagDef::new("Comment", "Vorbis", ValueConv::None, PrintConv::None);
static V_DIRECTOR: TagDef = TagDef::new("Director", "Vorbis", ValueConv::None, PrintConv::None);
static V_PRODUCER: TagDef = TagDef::new("Producer", "Vorbis", ValueConv::None, PrintConv::None);
static V_COMPOSER: TagDef = TagDef::new("Composer", "Vorbis", ValueConv::None, PrintConv::None);
static V_ACTOR: TagDef = TagDef::new("Actor", "Vorbis", ValueConv::None, PrintConv::None);
static V_ENCODER: TagDef = TagDef::new("Encoder", "Vorbis", ValueConv::None, PrintConv::None);
static V_ENCODER_OPTIONS: TagDef =
  TagDef::new("EncoderOptions", "Vorbis", ValueConv::None, PrintConv::None);
static V_COVERART: TagDef = TagDef::new("CoverArt", "Vorbis", ValueConv::None, PrintConv::None);
static V_METADATA_BLOCK_PICTURE: TagDef =
  TagDef::new("Picture", "Vorbis", ValueConv::None, PrintConv::None);

/// Named Vorbis comment keys (Vorbis.pm:80-121) → static `TagDef`.
/// Both `vorbis_comments_get` and the typed Meta's emission path consult
/// this slice (single source of truth for the named-key set).
const VORBIS_NAMED_TAGS: &[(&str, &TagDef)] = &[
  ("vendor", &V_VENDOR),
  ("TITLE", &V_TITLE),
  ("VERSION", &V_VERSION),
  ("ALBUM", &V_ALBUM),
  ("TRACKNUMBER", &V_TRACKNUMBER),
  ("ARTIST", &V_ARTIST),
  ("PERFORMER", &V_PERFORMER),
  ("COPYRIGHT", &V_COPYRIGHT),
  ("LICENSE", &V_LICENSE),
  ("ORGANIZATION", &V_ORGANIZATION),
  ("DESCRIPTION", &V_DESCRIPTION),
  ("GENRE", &V_GENRE),
  ("DATE", &V_DATE),
  ("LOCATION", &V_LOCATION),
  ("CONTACT", &V_CONTACT),
  ("ISRC", &V_ISRC),
  ("COVERARTMIME", &V_COVERARTMIME),
  ("REPLAYGAIN_TRACK_PEAK", &V_REPLAYGAIN_TRACK_PEAK),
  ("REPLAYGAIN_TRACK_GAIN", &V_REPLAYGAIN_TRACK_GAIN),
  ("REPLAYGAIN_ALBUM_PEAK", &V_REPLAYGAIN_ALBUM_PEAK),
  ("REPLAYGAIN_ALBUM_GAIN", &V_REPLAYGAIN_ALBUM_GAIN),
  ("ENCODED_USING", &V_ENCODED_USING),
  ("ENCODED_BY", &V_ENCODED_BY),
  ("COMMENT", &V_COMMENT),
  ("DIRECTOR", &V_DIRECTOR),
  ("PRODUCER", &V_PRODUCER),
  ("COMPOSER", &V_COMPOSER),
  ("ACTOR", &V_ACTOR),
  ("ENCODER", &V_ENCODER),
  ("ENCODER_OPTIONS", &V_ENCODER_OPTIONS),
  ("COVERART", &V_COVERART),
  ("METADATA_BLOCK_PICTURE", &V_METADATA_BLOCK_PICTURE),
];

fn vorbis_comments_get(id: TagId) -> Option<&'static TagDef> {
  // Hand-first (additive-codegen invariant): the hand `VORBIS_NAMED_TAGS`
  // slice WINS on every key it defines. The list-tags
  // (Artist/Performer/Contact, `.with_list(true)`) are not expressible via
  // `-listx`, so the hand layer must win. The hand layer covers every
  // `%Vorbis::Comments` key, so [`vorbis_generated::get`] never fires — it is
  // the drift guard, not new coverage.
  let hand = match id {
    TagId::Str(key) => VORBIS_NAMED_TAGS
      .iter()
      .find(|(k, _)| *k == key)
      .map(|(_, def)| *def),
    _ => None,
  };
  hand.or_else(|| vorbis_generated::get(id))
}

/// Faithful `%Image::ExifTool::Vorbis::Comments` (Vorbis.pm:72-135), subset.
/// `group0 = "Vorbis"`; family-1 also `"Vorbis"`.
pub static VORBIS_COMMENTS_TABLE: TagTable = TagTable::new("Vorbis", vorbis_comments_get);

/// Lookup `tag` (uppercase Vorbis key OR the literal `"vendor"`) in the
/// static named-tag slice. Returns `Some(&'static TagDef)` for known keys;
/// `None` for unrecognized keys (the auto-name path handles those).
fn lookup_vorbis_named(tag: &str) -> Option<&'static TagDef> {
  VORBIS_NAMED_TAGS
    .iter()
    .find(|(k, _)| *k == tag)
    .map(|(_, def)| *def)
}

// ===========================================================================
// Typed Meta — `Meta<'a>`, `VorbisItem<'a>`, `Picture<'a>`
// ===========================================================================

/// Decoded StreamInfo block (FLAC.pm:59-82). All fields are post-ValueConv.
/// `None` if a field cannot be extracted from a truncated/short StreamInfo
/// payload (faithful: bundled `process_bit_stream` silently drops late
/// fields once `i2 >= dirLen`).
///
/// D8 convention: PRIVATE fields, accessors only on [`Meta`].
#[derive(Debug, Clone, Default)]
struct StreamInfo {
  block_size_min: Option<u32>,
  block_size_max: Option<u32>,
  frame_size_min: Option<u32>,
  frame_size_max: Option<u32>,
  sample_rate: Option<u32>,
  /// Post-ValueConv (`$val + 1`).
  channels: Option<u8>,
  /// Post-ValueConv (`$val + 1`).
  bits_per_sample: Option<u8>,
  total_samples: Option<u64>,
  /// Raw 16 bytes; hex-encoded at emit time per FLAC.pm:80
  /// `unpack("H*", $val)`.
  md5_signature: Option<[u8; 16]>,
}

/// One Vorbis comment entry (Vorbis.pm:175-203). Carries the typed
/// disposition of the comment so the sink can render byte-exact JSON
/// without re-routing through table lookups at emit time:
///
/// * Vendor — the leading `vendor` block (Vorbis.pm:181-187), exactly one
///   per VorbisComment block.
/// * Named — a known key in `VORBIS_NAMED_TAGS`.
/// * Auto — an unknown key, auto-named via the regex transform at
///   Vorbis.pm:188-196.
/// * CoverArt — `COVERART` (Vorbis.pm:97-105) base64-decoded bytes;
///   rendered as the universal Binary placeholder.
/// * PictureRecursionWarning — `METADATA_BLOCK_PICTURE` (Vorbis.pm:
///   122-135) faithfully emits ONLY a Warning (bundled ProcessDirectory
///   recursion-guard always fires; verified 2026-05-20).
///
/// Strings use `Cow<'a, str>` to remain zero-alloc for well-formed UTF-8
/// (the Vorbis spec mandates UTF-8); pathological non-UTF-8 input falls
/// back to `String::from_utf8_lossy` (owned) — faithful to Perl's
/// `$et->Decode($val,'UTF8')` lossy behavior.
///
/// §2: every variant is unit or **newtype** — the multi-field `Named`/`Auto`
/// payloads are extracted into the named structs [`VorbisNamed`] /
/// [`VorbisAuto`] (private fields + accessors) so each variant hands back one
/// coherent, independently-named payload. `#[non_exhaustive]` reserves room
/// for future Vorbis dispositions; `is_*` + `unwrap`/`try_unwrap` accessors
/// keep callers off hand-matching.
#[non_exhaustive]
#[derive(Debug, Clone, derive_more::IsVariant, derive_more::Unwrap, derive_more::TryUnwrap)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
pub enum VorbisItem<'a> {
  /// `vendor` (Vorbis.pm:181-187). Exactly one per block.
  Vendor(Cow<'a, str>),
  /// A known Vorbis key (payload [`VorbisNamed`]). For list-tags
  /// (Artist/Performer/Contact), each emission is one item; the sink/bridge
  /// coalesces same-name repeats into a JSON array.
  Named(VorbisNamed<'a>),
  /// Unknown Vorbis key → auto-named (Vorbis.pm:188-196), payload
  /// [`VorbisAuto`]. The name is owned (synthesized via regex transform;
  /// cannot borrow from input).
  Auto(VorbisAuto<'a>),
  /// `COVERART` (Vorbis.pm:97-105) base64-decoded bytes.
  CoverArt(Vec<u8>),
  /// `METADATA_BLOCK_PICTURE` (Vorbis.pm:122-135) — faithful disposition is
  /// a single Warning, no tag emission. The payload carries the raw base64
  /// for debug visibility but is not emitted.
  PictureRecursionWarning(Cow<'a, str>),
}

/// Payload for [`VorbisItem::Named`] — a known Vorbis comment key
/// (Vorbis.pm:80-121). §2 named-struct extraction: PRIVATE fields, accessors
/// only.
#[derive(Debug, Clone)]
pub struct VorbisNamed<'a> {
  /// bundled-Perl tag name (e.g. `"Title"`).
  name: &'static str,
  /// raw UTF-8 value (post-Decode).
  value: Cow<'a, str>,
  /// Vorbis.pm `List => 1` flag (drives `push_listable` semantics at the
  /// legacy-bridge sink).
  listable: bool,
}

impl<'a> VorbisNamed<'a> {
  /// Construct a named Vorbis comment payload.
  #[must_use]
  #[inline(always)]
  pub const fn new(name: &'static str, value: Cow<'a, str>, listable: bool) -> Self {
    Self {
      name,
      value,
      listable,
    }
  }
  /// Bundled-Perl tag name (e.g. `"Title"`).
  #[must_use]
  #[inline(always)]
  pub const fn name(&self) -> &'static str {
    self.name
  }
  /// Raw UTF-8 value, post-Decode (§3: `Cow` projected to `&str`).
  #[must_use]
  #[inline(always)]
  pub fn value(&self) -> &str {
    &self.value
  }
  /// Vorbis.pm `List => 1` flag.
  #[must_use]
  #[inline(always)]
  pub const fn is_listable(&self) -> bool {
    self.listable
  }
}

/// Payload for [`VorbisItem::Auto`] — an unknown Vorbis key auto-named via the
/// Vorbis.pm:188-196 regex transform. §2 named-struct extraction: PRIVATE
/// fields, accessors only.
#[derive(Debug, Clone)]
pub struct VorbisAuto<'a> {
  /// Auto-derived name (owned; synthesized via the Vorbis.pm regex transform,
  /// cannot borrow from input). A short tag identifier (stored, feeds the
  /// emitted tag name) ⇒ `SmolStr`; the regex transform builds it in a
  /// transient `String` (a builder — String per the rule), converted here.
  name: smol_str::SmolStr,
  /// raw UTF-8 value.
  value: Cow<'a, str>,
}

impl<'a> VorbisAuto<'a> {
  /// Construct an auto-named Vorbis comment payload.
  #[must_use]
  #[inline(always)]
  pub const fn new(name: smol_str::SmolStr, value: Cow<'a, str>) -> Self {
    Self { name, value }
  }
  /// Auto-derived name (§3: `SmolStr` projected to `&str`).
  #[must_use]
  #[inline(always)]
  pub fn name(&self) -> &str {
    self.name.as_str()
  }
  /// Raw UTF-8 value (§3: `Cow` projected to `&str`).
  #[must_use]
  #[inline(always)]
  pub fn value(&self) -> &str {
    &self.value
  }
}

/// One FLAC Picture metadata block (block_type 6) — FLAC.pm:84-134.
/// `data` length may be SMALLER than `length` if the declared bytes were
/// truncated (faithful ExifTool::ReadValue clamp at ExifTool.pm:6290-6298;
/// rare but real).
#[derive(Debug, Clone)]
pub struct Picture<'a> {
  /// FLAC.pm:88-113 PrintConv key (raw int32u).
  picture_type: u32,
  /// FLAC.pm:115-117 `Format => 'var_pstr32'`. UTF-8 string borrowed from
  /// input on the happy path; lossy String fallback on non-UTF-8.
  mime_type: Cow<'a, str>,
  /// FLAC.pm:118-122 `Format => 'var_pstr32', ValueConv => Decode UTF8`.
  description: Cow<'a, str>,
  width: u32,
  height: u32,
  bits_per_pixel: u32,
  indexed_colors: u32,
  /// Declared length (FLAC.pm:127). May exceed `data.len()` on truncation.
  length: u32,
  /// Raw bytes (clamped to remaining payload, FLAC.pm:128-133 `Format =>
  /// 'undef[$val{7}]'` via ExifTool::ReadValue clamp). Borrowed from input.
  data: &'a [u8],
}

impl Picture<'_> {
  /// Picture type code (FLAC.pm:88-113 raw int32u, ID3-spec Picture type)
  /// (Copy → by value, bare name; §3).
  #[must_use]
  #[inline(always)]
  pub const fn picture_type(&self) -> u32 {
    self.picture_type
  }
  /// Picture type PrintConv string (e.g. `"Front Cover"`); `None` for codes
  /// outside the bundled 0..=20 table (raw numeric used in that case).
  #[must_use]
  #[inline(always)]
  pub const fn picture_type_name(&self) -> Option<&'static str> {
    picture_type_name(self.picture_type)
  }
  /// MIME type, e.g. `"image/png"` (§3: `Cow` projected to `&str`).
  #[must_use]
  #[inline(always)]
  pub fn mime_type(&self) -> &str {
    &self.mime_type
  }
  /// Description, UTF-8 (§3: `Cow` projected to `&str`).
  #[must_use]
  #[inline(always)]
  pub fn description(&self) -> &str {
    &self.description
  }
  /// Picture width in pixels (Copy → by value).
  #[must_use]
  #[inline(always)]
  pub const fn width(&self) -> u32 {
    self.width
  }
  /// Picture height in pixels (Copy → by value).
  #[must_use]
  #[inline(always)]
  pub const fn height(&self) -> u32 {
    self.height
  }
  /// Bits per pixel (Copy → by value).
  #[must_use]
  #[inline(always)]
  pub const fn bits_per_pixel(&self) -> u32 {
    self.bits_per_pixel
  }
  /// Indexed colors (0 for non-paletted) (Copy → by value).
  #[must_use]
  #[inline(always)]
  pub const fn indexed_colors(&self) -> u32 {
    self.indexed_colors
  }
  /// Declared length in bytes (may exceed `data().len()` on truncation)
  /// (Copy → by value).
  #[must_use]
  #[inline(always)]
  pub const fn length(&self) -> u32 {
    self.length
  }
  /// Raw picture bytes (borrowed from input; clamped to remaining payload)
  /// (§3: byte view `&[u8]`).
  #[must_use]
  #[inline(always)]
  pub const fn data(&self) -> &[u8] {
    self.data
  }
}

/// Typed FLAC metadata — the lib-first output of [`ProcessFlac`].
///
/// Faithful to FLAC.pm:239-280 + Vorbis.pm:157-210 (the inline Vorbis
/// comment subset reachable from FLAC's VorbisComment block) +
/// FLAC.pm:84-134 (the Picture sub-block).
///
/// **D8 — no public fields, accessors only.**
///
/// **Lifetimes.** `Meta` borrows from the input bytes where possible:
/// Vorbis values and Picture mime/description/data slices are
/// `Cow<'a, str>` / `&'a [u8]`. Synthesized strings (auto-derived Vorbis
/// names, lossy UTF-8 fallbacks) are owned. The StreamInfo scalars and
/// composite [`Duration`] are owned primitives.
#[derive(Debug, Clone, Default)]
pub struct Meta<'a> {
  stream_info: StreamInfo,
  vorbis: Vec<VorbisItem<'a>>,
  pictures: Vec<Picture<'a>>,
  /// FLAC.pm:278 — `$err and Warn('Format error in FLAC file')`. Carried as
  /// a boolean so the sink can emit the canonical warning text without
  /// duplication.
  format_error: bool,
  /// Chained ID3 sub-Meta from the FLAC.pm:243-247 embedded ProcessID3 call
  /// (`unless ($$et{DoneID3}) { ID3::ProcessID3($et, $dirInfo) }`). `Some`
  /// when an ID3v2 PREFIX (in front of the `fLaC` magic) was detected and
  /// parsed via [`crate::formats::id3::process::parse_id3_with_hdr_end`].
  /// Carries `File:ID3Size` + any `ID3v2_*:*` frame tags; the golden
  /// [`Taggable`](crate::emit::Taggable) impl splices them BEFORE the FLAC
  /// body tags so the stream stays faithful to bundled (ID3 is processed
  /// first, then the `fLaC` magic check & FLAC body extraction at
  /// FLAC.pm:254-278). Same nesting pattern as `ape::Meta::id3` and
  /// `dsf::Meta::id3`.
  ///
  /// F1 (Codex adversarial): bundled emits `File:ID3Size` for every
  /// ID3-prefixed FLAC (even a 10-byte empty header); the pre-F1 code
  /// skipped the prefix bytes to reach `fLaC` but never emitted the ID3
  /// content, forcing a hand-trimmed golden. Nesting the typed ID3 parser
  /// closes that hole.
  #[cfg(feature = "id3")]
  id3: Option<crate::formats::id3::Id3Meta<'a>>,
}

impl<'a> Meta<'a> {
  /// FLAC.pm:63 BlockSizeMin (`Bit000-015`) (Copy → by value; §3).
  #[must_use]
  #[inline(always)]
  pub const fn block_size_min(&self) -> Option<u32> {
    self.stream_info.block_size_min
  }
  /// FLAC.pm:64 BlockSizeMax (`Bit016-031`) (Copy → by value).
  #[must_use]
  #[inline(always)]
  pub const fn block_size_max(&self) -> Option<u32> {
    self.stream_info.block_size_max
  }
  /// FLAC.pm:65 FrameSizeMin (`Bit032-055`) (Copy → by value).
  #[must_use]
  #[inline(always)]
  pub const fn frame_size_min(&self) -> Option<u32> {
    self.stream_info.frame_size_min
  }
  /// FLAC.pm:66 FrameSizeMax (`Bit056-079`) (Copy → by value).
  #[must_use]
  #[inline(always)]
  pub const fn frame_size_max(&self) -> Option<u32> {
    self.stream_info.frame_size_max
  }
  /// FLAC.pm:67 SampleRate Hz (`Bit080-099`) (Copy → by value).
  #[must_use]
  #[inline(always)]
  pub const fn sample_rate(&self) -> Option<u32> {
    self.stream_info.sample_rate
  }
  /// FLAC.pm:68-71 Channels (post-ValueConv `$val + 1`) (Copy → by value).
  #[must_use]
  #[inline(always)]
  pub const fn channels(&self) -> Option<u8> {
    self.stream_info.channels
  }
  /// FLAC.pm:72-75 BitsPerSample (post-ValueConv `$val + 1`) (Copy → by value).
  #[must_use]
  #[inline(always)]
  pub const fn bits_per_sample(&self) -> Option<u8> {
    self.stream_info.bits_per_sample
  }
  /// FLAC.pm:76 TotalSamples (Copy → by value).
  #[must_use]
  #[inline(always)]
  pub const fn total_samples(&self) -> Option<u64> {
    self.stream_info.total_samples
  }
  /// FLAC.pm:77-81 MD5Signature raw 16 bytes. Use [`md5_hex`](Self::md5_hex)
  /// for the bundled-Perl `unpack("H*", ...)` rendering. (`[u8; 16]` is
  /// `Copy` ⇒ returned by value, bare name; §3.)
  #[must_use]
  #[inline(always)]
  pub const fn md5_signature(&self) -> Option<[u8; 16]> {
    self.stream_info.md5_signature
  }
  /// Bundled-Perl hex rendering of [`md5_signature`](Self::md5_signature)
  /// (32 lowercase hex characters). Allocates a [`String`] on every call;
  /// callers needing zero-alloc should use the raw bytes.
  #[must_use]
  pub fn md5_hex(&self) -> Option<String> {
    self
      .stream_info
      .md5_signature
      .as_ref()
      .map(|b| format_md5_hex(b))
  }
  /// Vorbis comment entries (Vorbis.pm:175-203), in extraction order
  /// (the bundled-Perl loop order: vendor first, then each user comment)
  /// (§3: `Vec` projected to `&[T]`).
  #[must_use]
  #[inline(always)]
  pub const fn vorbis_items(&self) -> &[VorbisItem<'a>] {
    self.vorbis.as_slice()
  }
  /// Picture frames (FLAC.pm:51-54). One entry per Picture block (§3: `Vec`
  /// projected to `&[T]`).
  #[must_use]
  #[inline(always)]
  pub const fn pictures(&self) -> &[Picture<'a>] {
    self.pictures.as_slice()
  }
  /// `Composite:Duration` — FLAC.pm:137-149 `($val[0] and $val[1]) ?
  /// $val[1] / $val[0] : undef`. Computed lazily from
  /// [`total_samples`](Self::total_samples) /
  /// [`sample_rate`](Self::sample_rate); both must be > 0.
  ///
  /// `core::time::Duration` is nanosecond-precise — the ratio is constructed
  /// via [`Duration::from_secs_f64`] which loses sub-microsecond precision
  /// only on very long files (`>4 yr at 1ns precision`). Bundled
  /// ExifTool's PrintConv `ConvertDuration` rounds to integer seconds for
  /// `time >= 30`, so the precision loss is unobservable at emit time.
  #[must_use]
  pub fn duration(&self) -> Option<Duration> {
    let ts = self.stream_info.total_samples?;
    let sr = self.stream_info.sample_rate?;
    if ts == 0 || sr == 0 {
      return None;
    }
    let secs = (ts as f64) / f64::from(sr);
    if !secs.is_finite() || secs < 0.0 {
      return None;
    }
    // Duration::from_secs_f64 panics on negative/NaN/Inf — we filter above.
    Some(Duration::from_secs_f64(secs))
  }
  /// Chained ID3 sub-Meta (FLAC.pm:243-247 embedded `ProcessID3`). `Some`
  /// when an ID3v2 PREFIX was detected and parsed; the golden
  /// [`Taggable`](crate::emit::Taggable) impl splices its `File:ID3Size` +
  /// frame tags BEFORE the FLAC body tags (faithful bundled order).
  ///
  /// §3: non-`Copy` borrow ⇒ `_ref` suffix.
  #[cfg(feature = "id3")]
  #[must_use]
  #[inline(always)]
  pub const fn id3_ref(&self) -> Option<&crate::formats::id3::Id3Meta<'_>> {
    self.id3.as_ref()
  }
}

// ===========================================================================
// `ProcessFlac` — the lib-first parser
// ===========================================================================

/// FLAC parser. Faithful `ProcessFLAC` (FLAC.pm:239-280) — `fLaC` magic +
/// metadata-block chain walk.
#[derive(Debug, Clone, Copy)]
pub struct ProcessFlac;

impl parser_sealed::Sealed for ProcessFlac {}

/// Per-format context for FLAC. Carries the input bytes plus a reference to
/// the cross-format [`SharedFlags`](crate::format_parser::SharedFlags) that
/// tracks `$$et{DoneID3}` for the FLAC.pm:243-247 ID3-chain handoff.
///
/// **Side effects on the shared flags PERSIST regardless of return value**
/// (faithful to ExifTool's `$self` model). Today this PR only **reads**
/// `done_id3` from the shared state; the actual `set_done_id3` call lands
/// when F2 ID3 migrates (then the bridge plumbing wires it up end-to-end).
pub struct Context<'a> {
  /// File bytes — typically the whole file (FLAC parsing is offset-based).
  data: &'a [u8],
  /// Cross-format shared state.
  shared: &'a mut crate::format_parser::SharedFlags,
}

impl<'a> Context<'a> {
  /// Construct a FLAC parser context.
  #[must_use]
  #[inline(always)]
  pub const fn new(data: &'a [u8], shared: &'a mut crate::format_parser::SharedFlags) -> Self {
    Self { data, shared }
  }

  /// File bytes accessor (§3: byte view `&[u8]`).
  #[must_use]
  #[inline(always)]
  pub const fn data(&self) -> &'a [u8] {
    self.data
  }

  /// Shared flags (read-only access; §3: non-`Copy` borrow projection).
  #[must_use]
  #[inline(always)]
  pub const fn shared(&self) -> &crate::format_parser::SharedFlags {
    self.shared
  }
}

impl FormatParser for ProcessFlac {
  /// GAT: the Meta borrows from the input `'a` directly (including borrowed
  /// Vorbis-comment strings and the picture payload), publishing into the
  /// closed [`AnyMeta`](crate::format_parser::AnyMeta) enum with no `'static`
  /// upgrade (Codex AF2).
  type Meta<'a> = Meta<'a>;
  /// Spec §6.1: chained-format context with shared flags.
  type Context<'a> = Context<'a>;
  /// Rust-level fatal error type (no variants today; reserved for future
  /// I/O wrappers).

  /// Run the typed parser. Returns:
  /// - `Ok(Some(meta))` — FLAC magic accepted; tags extracted (FLAC.pm:279
  ///   `return 1`).
  /// - `Ok(None)` — magic rejected (FLAC.pm:254 `or return 0`).
  /// - `Err(_)` — unreachable today.
  fn parse<'a>(&self, ctx: Self::Context<'a>) -> Option<Self::Meta<'a>> {
    parse_inner(ctx.data, ctx.shared)
  }
}

/// Lib-first direct entry. Same as [`FormatParser::parse`] but returns a
/// [`Meta`] that borrows from the input buffer — zero allocation on
/// the happy-path UTF-8.
///
/// `shared` borrows independently of `data` (decoupled lifetimes): the
/// returned `Meta<'a>` borrows only from `data`, so the closed
/// [`crate::format_parser::AnyParser`] dispatch can pass a transient
/// `shared` without pinning the returned `AnyMeta<'a>` (Codex AF2).
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today; reserved for
/// future I/O wrappers).
pub fn parse_borrowed<'a>(
  data: &'a [u8],
  shared: &mut crate::format_parser::SharedFlags,
) -> Option<Meta<'a>> {
  parse_inner(data, shared)
}

/// Inner parser — produces a borrow-from-input [`Meta`].
fn parse_inner<'a>(
  data: &'a [u8],
  shared: &mut crate::format_parser::SharedFlags,
) -> Option<Meta<'a>> {
  // -- FLAC.pm:243-247 — embedded ID3 (`ProcessID3`) ----------------------
  //
  //    unless ($$et{DoneID3}) {
  //        require Image::ExifTool::ID3;
  //        Image::ExifTool::ID3::ProcessID3($et, $dirInfo) and return 1;
  //    }
  //
  // Run the typed ID3 parser BEFORE the `fLaC` magic check (F1, Codex
  // adversarial): bundled emits `File:ID3Size` + every ID3v2 frame tag for
  // every ID3-prefixed FLAC, including the empty-header case (`File:ID3Size
  // = 10`); the pre-F1 code just skipped the prefix bytes to reach `fLaC`
  // and silently dropped that content. `parse_id3_with_hdr_end` is the
  // SAME entry APE/DSF use (`ape::parse_full_chained`, `dsf::Meta::id3`)
  // and returns the typed `Id3Meta` + the post-ID3v2-header offset
  // (`$hdrEnd`, ID3.pm:1504). The recursion guard (ID3.pm:1435
  // `return 0 if $$et{DoneID3}`) is honoured: only call when ID3 has not
  // already run on this chain. (`flac` requires `id3` in Cargo.toml so
  // this code path is the only one — see [`Meta::id3_ref`].)
  let (id3, offset) = if shared.done_id3().is_none() {
    crate::formats::id3::process::parse_id3_with_hdr_end(
      data,
      Some(&mut *shared),
      /* print_conv */ true,
    )
  } else {
    (None, shared.id3_hdr_end().unwrap_or(0))
  };

  // -- FLAC.pm:254 — `fLaC` magic check -----------------------------------
  // `$raf->Read($buff, 4) == 4 and $buff eq 'fLaC' or return 0`
  // Checked-indexing (Phase C w2b): `data.get(offset..offset + 4) !=
  // Some(b"fLaC")` folds the old `data.len() < offset + 4 || &data[..] != …`
  // (the `Some` arm requires the window in bounds) ⇒ byte-identical.
  if data.get(offset..offset + 4) != Some(&b"fLaC"[..]) {
    return None;
  }

  // -- FLAC.pm:256-280 — block chain walk ---------------------------------
  // SetByteOrder('MM') is implicit (every multi-byte read below uses BE).
  let mut meta = Meta::default();
  meta.id3 = id3;
  let mut pos = offset + 4;
  loop {
    // FLAC.pm:260 — `$raf->Read($buff, 4) == 4 or last` (silent exit; no err).
    if pos + 4 > data.len() {
      break;
    }
    // Checked-indexing (Phase C w2b): the `pos + 4 > data.len()` guard makes
    // `data.get(pos..pos + 4)` `Some` (a 4-byte window) ⇒ byte-identical.
    let header: [u8; 4] = match data.get(pos..pos + 4) {
      Some(&[b0, b1, b2, b3]) => [b0, b1, b2, b3],
      _ => [0; 4],
    };
    pos += 4;
    // FLAC.pm:261 — `my $flag = unpack('C', $buff)`.
    let flag = header[0];
    // FLAC.pm:262 — `my $size = unpack('N', $buff) & 0x00ffffff`.
    let size = (u32::from_be_bytes(header) & 0x00ff_ffff) as usize;
    // FLAC.pm:264 — `$last = $flag & 0x80`.
    let is_last = (flag & 0x80) != 0;
    // FLAC.pm:265 — `$tag = $flag & 0x7f`.
    let block_type = flag & 0x7f;
    // FLAC.pm:263 — `$raf->Read($buff, $size) == $size or $err = 1, last`.
    // Panic-free: saturating_sub avoids `usize` underflow per the
    // [[exifast-phase2-forward-items]] underflow-footgun guidance.
    if size > data.len().saturating_sub(pos) {
      meta.format_error = true;
      break;
    }
    // Checked-indexing (Phase C w2b): the `size > data.len() - pos` guard makes
    // `pos + size <= data.len()` ⇒ `data.get(pos..pos + size)` is `Some` ⇒
    // byte-identical.
    let payload = data.get(pos..pos + size).unwrap_or(&[]);
    pos += size;
    match block_type {
      // FLAC.pm:27-30 — `0 => StreamInfo` (SubDirectory → %FLAC::StreamInfo,
      // PROCESS_PROC = ProcessBitStream, GROUPS => { 2 => Audio }).
      0 => {
        meta.stream_info = parse_streaminfo(payload);
      }
      // FLAC.pm:31 — `1 => Padding` (Binary+Unknown → skip).
      1 => {}
      // FLAC.pm:32-44 — `2 => Application` (two-arm Condition).
      // `riff` arm (RIFF::Main subdirectory) DEFERRED until RIFF.pm lands.
      // ApplicationUnknown is Binary+Unknown → skip.
      2 => {}
      // FLAC.pm:45 — `3 => SeekTable` (Binary+Unknown → skip).
      3 => {}
      // FLAC.pm:46-49 — `4 => VorbisComment` (SubDirectory → %Vorbis::Comments).
      4 => {
        parse_vorbis_comments(payload, &mut meta.vorbis);
      }
      // FLAC.pm:50 — `5 => CueSheet` (Binary+Unknown → skip).
      5 => {}
      // FLAC.pm:51-54 — `6 => Picture` (SubDirectory → %FLAC::Picture).
      6 => {
        if let Some(p) = parse_flac_picture(payload) {
          meta.pictures.push(p);
        }
      }
      // FLAC.pm:55-56 — 7..=126 Reserved, 127 Invalid; no entry in %FLAC::Main.
      _ => {}
    }
    // FLAC.pm:276 — `last if $last`.
    if is_last {
      break;
    }
  }
  Some(meta)
}

/// Compute the byte offset where the FLAC body starts after an optional
/// ID3v2 prefix. Returns 0 if no ID3 prefix is present. Faithful to the
/// `FLAC.pm:243-247` skip + the `ID3.pm:1484-1487 v2.4 footer` skip
/// (R2-F1).
///
/// Used only when the `id3` feature is OFF — the default path runs the
/// typed `parse_id3_with_hdr_end` to also capture `File:ID3Size` + frame
/// tags (F1). Kept so the `cargo build --no-default-features --features
/// std,flac` tier compiles without dragging in `id3`.
#[cfg(not(feature = "id3"))]
fn id3v2_prefix_offset(data: &[u8]) -> usize {
  if data.len() < 10 || !data.starts_with(b"ID3") {
    return 0;
  }
  let major = data[3];
  let minor = data[4];
  let flags = data[5];
  let b6 = data[6];
  let b7 = data[7];
  let b8 = data[8];
  let b9 = data[9];
  // Synchsafe encoding requires every high bit clear; rejected values bail.
  if major == 0xff || minor == 0xff || (b6 | b7 | b8 | b9) & 0x80 != 0 {
    return 0;
  }
  let size = (u32::from(b6) << 21) | (u32::from(b7) << 14) | (u32::from(b8) << 7) | u32::from(b9);
  let mut advance = 10usize.saturating_add(size as usize);
  // ID3.pm:1484-1487 — `if ($flags & 0x10) { $raf->Seek(10, 1); }`.
  if flags & 0x10 != 0 {
    advance = advance.saturating_add(10);
  }
  advance.min(data.len())
}

/// Extract the 9 StreamInfo bit-fields per FLAC.pm:59-82 from a 34-byte (272-
/// bit) StreamInfo block payload. Returns a partially-populated [`StreamInfo`]
/// when the payload is truncated (faithful to the bit-stream walker's
/// `i2 >= dirLen` early-exit semantics).
///
/// The bit layout (big-endian byte order):
/// ```text
///   Bit000-015  BlockSizeMin     16 bits → bytes 0..2
///   Bit016-031  BlockSizeMax     16 bits → bytes 2..4
///   Bit032-055  FrameSizeMin     24 bits → bytes 4..7
///   Bit056-079  FrameSizeMax     24 bits → bytes 7..10
///   Bit080-099  SampleRate       20 bits → bytes 10..13 (upper 4 of byte 12)
///   Bit100-102  Channels          3 bits → byte 12 bits 3..1
///   Bit103-107  BitsPerSample     5 bits → byte 12 bit 0 + byte 13 bits 7..4
///   Bit108-143  TotalSamples     36 bits → byte 13 lower 4 bits + bytes 14..18
///   Bit144-271  MD5Signature    128 bits → bytes 18..34
/// ```
fn parse_streaminfo(payload: &[u8]) -> StreamInfo {
  // Helper: read N big-endian bytes as u64; returns None if any byte missing.
  // Checked-indexing (Phase C w2b): `payload.get(s..s + N)` is `Some` iff the
  // old `payload.len() < s + N` guard was false ⇒ byte-identical.
  let read_be_u16 = |s: usize| match payload.get(s..s + 2) {
    Some(&[b0, b1]) => Some(u16::from_be_bytes([b0, b1]) as u32),
    _ => None,
  };
  let read_be_u24 = |s: usize| match payload.get(s..s + 3) {
    Some(&[b0, b1, b2]) => Some((u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2)),
    _ => None,
  };
  let mut si = StreamInfo {
    block_size_min: read_be_u16(0),
    block_size_max: read_be_u16(2),
    frame_size_min: read_be_u24(4),
    frame_size_max: read_be_u24(7),
    ..StreamInfo::default()
  };
  // SampleRate (20 bits) at bits 80..100: bytes 10..13 with the upper 4
  // bits of byte 12 belonging to SampleRate. The Perl bit-stream walker
  // (FLAC.pm:158-233) handles this as a multi-byte unsigned-integer
  // accumulation with high/low byte masking; we open-code the equivalent.
  // Checked-indexing (Phase C w2b): each `payload[k]` below sits inside a
  // `payload.len() >= N` guard (k < N), so `.get(k).copied().unwrap_or(0)` and
  // the MD5 `.get(18..34)` window are byte-identical (fallbacks unreachable).
  let at = |k: usize| payload.get(k).copied().unwrap_or(0);
  if payload.len() >= 13 {
    let sr = (u32::from(at(10)) << 12) | (u32::from(at(11)) << 4) | (u32::from(at(12)) >> 4);
    si.sample_rate = Some(sr);
    // Channels (3 bits) at bits 100..103 = byte 12 bits 3..1 = (byte12 >> 1)
    // & 0x07. ValueConv `$val + 1` (FLAC.pm:70).
    let raw_channels = (at(12) >> 1) & 0x07;
    si.channels = Some(raw_channels.saturating_add(1));
    if payload.len() >= 14 {
      // BitsPerSample (5 bits) at bits 103..108 = (byte12 & 0x01) << 4 |
      // (byte13 >> 4). ValueConv `$val + 1` (FLAC.pm:74).
      let raw_bps = ((at(12) & 0x01) << 4) | (at(13) >> 4);
      si.bits_per_sample = Some(raw_bps.saturating_add(1));
      // TotalSamples (36 bits) at bits 108..144 = (byte13 & 0x0f) << 32 |
      // bytes 14..18.
      if payload.len() >= 18 {
        let ts: u64 = (u64::from(at(13) & 0x0f) << 32)
          | (u64::from(at(14)) << 24)
          | (u64::from(at(15)) << 16)
          | (u64::from(at(16)) << 8)
          | u64::from(at(17));
        si.total_samples = Some(ts);
      }
    }
  }
  // MD5Signature (128 bits) at bits 144..272 = bytes 18..34.
  if payload.len() >= 34 {
    let mut md5 = [0u8; 16];
    if let Some(slice) = payload.get(18..34) {
      md5.copy_from_slice(slice);
    }
    si.md5_signature = Some(md5);
  }
  si
}

/// Faithful port of `Image::ExifTool::Vorbis::ProcessComments`
/// (Vorbis.pm:157-210), scoped to the FLAC VorbisComment-block consumer.
///
/// Returns nothing — items are appended to `out`. The function records a
/// terminal "Format error in Vorbis comments" warning by pushing a
/// synthetic `VorbisItem::Auto(VorbisAuto)` item — but
/// since this internal item is invisible to the sink's filter we instead
/// rely on the legacy-bridge wrapping the call and detecting truncation
/// via the same exit conditions. To keep the typed API clean, this fn just
/// stops early on malformed input; the bridge re-runs the same checks to
/// emit the warning faithfully (single-source-of-truth pattern).
fn parse_vorbis_comments<'a>(payload: &'a [u8], out: &mut Vec<VorbisItem<'a>>) {
  let _ = process_vorbis_comments(payload, out);
}

/// Internal worker — returns `true` (Perl `return 1` at Vorbis.pm:205) on
/// success, `false` (`return 0` at :209) on malformed input. The boolean
/// drives the bridge's warning emission; the typed Meta itself does not
/// store the format-error flag for VorbisComments (the warning is a
/// Perl-side `$et->Warn` recorded as ExifTool:Warning).
fn process_vorbis_comments<'a>(payload: &'a [u8], out: &mut Vec<VorbisItem<'a>>) -> bool {
  let end = payload.len();
  let mut pos: usize = 0;
  // Checked-indexing (Phase C w2b): every `payload[pos..]` u32 read below sits
  // behind a `pos + 4 > end` guard and every byte-range slice behind a
  // `len > end - pos` guard, so `payload.get(pos..pos + 4)` / `.get(pos..pos +
  // len)` are `Some` exactly where the old raw indexing was in range ⇒
  // byte-identical. `le_u32_at` folds the 4-byte read.
  let le_u32_at = |p: usize| -> u32 {
    match payload.get(p..p + 4) {
      Some(&[b0, b1, b2, b3]) => u32::from_le_bytes([b0, b1, b2, b3]),
      _ => 0,
    }
  };

  // -- Vendor (Vorbis.pm:181-187) -----------------------------------------
  if pos + 4 > end {
    return false; // Format error — bridge surfaces the warning.
  }
  let vendor_len = le_u32_at(pos) as usize;
  pos += 4;
  if vendor_len > end.saturating_sub(pos) {
    return false;
  }
  let vendor_bytes = payload.get(pos..pos + vendor_len).unwrap_or(&[]);
  pos += vendor_len;
  out.push(VorbisItem::Vendor(bytes_to_cow_utf8(vendor_bytes)));

  // -- Count (Vorbis.pm:184) ----------------------------------------------
  // `$num = ($pos + 4 < $end) ? Get32u : 0;` — STRICT `<`. Exact 4 trailing
  // bytes after vendor satisfies `pos+4 == end` and stays out of the loop.
  let num: usize = if 4 < end.saturating_sub(pos) {
    let n = le_u32_at(pos) as usize;
    pos += 4;
    n
  } else {
    0
  };

  // -- Comments (Vorbis.pm:175-203) ---------------------------------------
  for _ in 0..num {
    if pos + 4 > end {
      return false; // Vorbis.pm:168 truncated mid-header.
    }
    let len = le_u32_at(pos) as usize;
    pos += 4;
    if len > end.saturating_sub(pos) {
      return false; // Vorbis.pm:170 truncated mid-value.
    }
    let comment = payload.get(pos..pos + len).unwrap_or(&[]);
    pos += len;
    // Vorbis.pm:176 `(.*?)=(.*)` — split on FIRST `=`.
    let Some(eq) = comment.iter().position(|&b| b == b'=') else {
      return false; // Vorbis.pm:208-209.
    };
    // `eq` is a `position` index into `comment` ⇒ `..eq` / `eq + 1..` are in
    // range ⇒ `.get(..)` is `Some` ⇒ byte-identical.
    let (key_bytes, val_bytes) = (
      comment.get(..eq).unwrap_or(&[]),
      comment.get(eq + 1..).unwrap_or(&[]),
    );
    // Vorbis.pm:177 — `uc $1` (ASCII uppercase the key).
    let tag_upper = ascii_uppercase(key_bytes);
    let val = bytes_to_cow_utf8(val_bytes);
    match tag_upper.as_str() {
      "COVERART" => {
        // Vorbis.pm:97-105 — base64-decode + Binary emission.
        let bytes = decode_base64(&val);
        out.push(VorbisItem::CoverArt(bytes));
      }
      "METADATA_BLOCK_PICTURE" => {
        // Vorbis.pm:122-135 — bundled ProcessDirectory recursion guard
        // (ExifTool.pm:9056-9059) fires invariably. Faithful disposition:
        // emit only the warning, no Picture sub-fields.
        out.push(VorbisItem::PictureRecursionWarning(val));
      }
      _ => {
        if let Some(def) = lookup_vorbis_named(&tag_upper) {
          out.push(VorbisItem::Named(VorbisNamed::new(
            def.name(),
            val,
            def.list(),
          )));
        } else {
          out.push(VorbisItem::Auto(VorbisAuto::new(
            vorbis_derive_name(&tag_upper).into(),
            val,
          )));
        }
      }
    }
  }
  true
}

/// Decode a FLAC Picture block body (FLAC.pm:84-134) into a typed
/// [`Picture`]. Returns `None` if the header bytes (PictureType +
/// MIME length-word) are truncated — for any later truncation the
/// declared length is clamped to the remaining bytes (ExifTool::ReadValue
/// clamp at ExifTool.pm:6290-6298) and partial data is preserved.
///
/// `pub(crate)` so the OGG/Vorbis `METADATA_BLOCK_PICTURE` SubDirectory
/// hop (R3 F2 — Vorbis.pm:122-134) can reuse it on the base64-decoded
/// payload (same on-wire structure as FLAC's METADATA_BLOCK type 6).
pub(crate) fn parse_flac_picture(payload: &[u8]) -> Option<Picture<'_>> {
  let mut pos = 0usize;
  // -- index 0: PictureType (int32u BE) -----------------------------------
  if payload.len() < pos + 4 {
    return None;
  }
  // Checked-indexing (Phase C w2b): the `payload.len() < pos + 4` guard makes
  // `payload.get(pos..pos + 4)` `Some` ⇒ byte-identical.
  let picture_type = match payload.get(pos..pos + 4) {
    Some(&[b0, b1, b2, b3]) => u32::from_be_bytes([b0, b1, b2, b3]),
    _ => 0,
  };
  pos += 4;
  // -- index 1: PictureMIMEType (var_pstr32) ------------------------------
  let mime = read_var_pstr32_cow(payload, &mut pos)?;
  // -- index 2: PictureDescription (var_pstr32, UTF-8) --------------------
  let description = read_var_pstr32_cow(payload, &mut pos)?;
  // -- indices 3..7: 5 × int32u BE ----------------------------------------
  let width = read_be_u32(payload, &mut pos)?;
  let height = read_be_u32(payload, &mut pos)?;
  let bits_per_pixel = read_be_u32(payload, &mut pos)?;
  let indexed_colors = read_be_u32(payload, &mut pos)?;
  let length = read_be_u32(payload, &mut pos)?;
  // -- index 8: Picture (undef[$val{7}]) ----------------------------------
  // ExifTool::ReadValue clamp (ExifTool.pm:6290-6298): a too-large
  // declared length DOES NOT drop the field; it emits the partial bytes
  // that actually fit. PictureLength == 0 falls through as an empty
  // emission (still a valid tag).
  let remaining = payload.len().saturating_sub(pos);
  let actual = (length as usize).min(remaining);
  // ExifTool.pm:6292 `count < 1 and return undef` — only when DECLARED > 0
  // AND nothing remains. If declared 0, we emit an empty data slice
  // (faithful: empty picture is still a tag, just zero bytes).
  let data = if actual == 0 && length > 0 {
    // No payload bytes left for a declared >0 length ⇒ no Picture tag.
    return Some(Picture {
      picture_type,
      mime_type: mime,
      description,
      width,
      height,
      bits_per_pixel,
      indexed_colors,
      length,
      data: &[],
    });
    // Note: ReadValue with count == 0 returns undef ⇒ no Picture tag in
    // the Perl path. The bridge skips emission of the Picture sub-field
    // by checking `length > 0 && data.is_empty()`.
  } else {
    // Checked-indexing (Phase C w2b): `actual = (length).min(remaining)` with
    // `remaining = payload.len() - pos` ⇒ `pos + actual <= payload.len()` ⇒
    // `payload.get(pos..pos + actual)` is `Some` ⇒ byte-identical.
    payload.get(pos..pos + actual).unwrap_or(&[])
  };
  Some(Picture {
    picture_type,
    mime_type: mime,
    description,
    width,
    height,
    bits_per_pixel,
    indexed_colors,
    length,
    data,
  })
}

/// Read a `var_pstr32` field: 4-byte BE length + that many UTF-8 bytes.
/// Returns `None` if either the length-word or the payload is truncated.
fn read_var_pstr32_cow<'a>(payload: &'a [u8], pos: &mut usize) -> Option<Cow<'a, str>> {
  let end = payload.len();
  if end < *pos + 4 {
    return None;
  }
  // Checked-indexing (Phase C w2b): the `end < *pos + 4` then `len > end -
  // *pos` guards make `payload.get(*pos..*pos + 4)` / `.get(*pos..*pos + len)`
  // `Some` ⇒ byte-identical.
  let len = match payload.get(*pos..*pos + 4) {
    Some(&[b0, b1, b2, b3]) => u32::from_be_bytes([b0, b1, b2, b3]) as usize,
    _ => 0,
  };
  *pos += 4;
  if len > end.saturating_sub(*pos) {
    return None;
  }
  let bytes = payload.get(*pos..*pos + len).unwrap_or(&[]);
  *pos += len;
  Some(bytes_to_cow_utf8(bytes))
}

/// Read 4 bytes BE as u32, advancing `*pos` past the field. `None` on
/// truncation.
fn read_be_u32(payload: &[u8], pos: &mut usize) -> Option<u32> {
  if payload.len() < *pos + 4 {
    return None;
  }
  // Checked-indexing (Phase C w2b): the `payload.len() < *pos + 4` guard makes
  // `payload.get(*pos..*pos + 4)` `Some` ⇒ byte-identical.
  let n = match payload.get(*pos..*pos + 4) {
    Some(&[b0, b1, b2, b3]) => u32::from_be_bytes([b0, b1, b2, b3]),
    _ => 0,
  };
  *pos += 4;
  Some(n)
}

/// Convert raw bytes to a [`Cow<'a, str>`] — borrowed when valid UTF-8,
/// owned (with U+FFFD replacement) otherwise. Faithful to Perl
/// `$et->Decode($val,'UTF8')` lossy semantics.
fn bytes_to_cow_utf8(bytes: &[u8]) -> Cow<'_, str> {
  match core::str::from_utf8(bytes) {
    Ok(s) => Cow::Borrowed(s),
    Err(_) => Cow::Owned(String::from_utf8_lossy(bytes).into_owned()),
  }
}

/// ASCII-uppercase a byte slice. Vorbis spec mandates ASCII tag keys
/// (Vorbis.pm:177 `uc $1` is equivalent for ASCII).
fn ascii_uppercase(bytes: &[u8]) -> String {
  let mut s = String::with_capacity(bytes.len());
  for &b in bytes {
    if b.is_ascii_lowercase() {
      s.push((b - 0x20) as char);
    } else {
      s.push(b as char);
    }
  }
  s
}

/// Derive a tag name from an unknown Vorbis comment key per Vorbis.pm:190-193:
/// ```text
/// my $name = ucfirst(lc($tag));
/// $name =~ s/[^\w-]+(.?)/\U$1/sg;
/// $name =~ s/([a-z0-9])_([a-z])/$1\U$2/g;
/// ```
fn vorbis_derive_name(tag: &str) -> String {
  // Step 1: lowercase, then ucfirst.
  let lc: String = tag.chars().flat_map(char::to_lowercase).collect();
  let ucfirst: String = {
    let mut cs = lc.chars();
    match cs.next() {
      Some(c) => c.to_uppercase().chain(cs).collect::<String>(),
      None => String::new(),
    }
  };
  // Step 2: s/[^\w-]+(.?)/\U$1/sg
  let after_step2: String = {
    let chars: Vec<char> = ucfirst.chars().collect();
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
    let mut out = String::with_capacity(chars.len());
    let mut i = 0;
    // Checked-indexing (Phase C w2b): `chars.get(i)` is `Some` exactly where the
    // old `i < chars.len()` + `chars[i]` pair was in range ⇒ byte-identical.
    while let Some(&c) = chars.get(i) {
      if is_word(c) {
        out.push(c);
        i += 1;
      } else {
        while chars.get(i).is_some_and(|&c| !is_word(c)) {
          i += 1;
        }
        if let Some(&c) = chars.get(i) {
          for u in c.to_uppercase() {
            out.push(u);
          }
          i += 1;
        }
      }
    }
    out
  };
  // Step 3: s/([a-z0-9])_([a-z])/$1\U$2/g
  let chars: Vec<char> = after_step2.chars().collect();
  let mut out = String::with_capacity(chars.len());
  let mut i = 0;
  // Checked-indexing (Phase C w2b): `chars.get(i)` is `Some` while the old
  // `i < chars.len()` held; the triple-match arm previously gated on
  // `i + 2 < chars.len()` so `chars.get(i + 1)`/`chars.get(i + 2)` are `Some`
  // exactly on that branch ⇒ byte-identical.
  while let Some(&c0) = chars.get(i) {
    let c1 = chars.get(i + 1).copied();
    let c2 = chars.get(i + 2).copied();
    if i + 2 < chars.len()
      && (c0.is_ascii_lowercase() || c0.is_ascii_digit())
      && c1 == Some('_')
      && c2.is_some_and(|c| c.is_ascii_lowercase())
    {
      out.push(c0);
      if let Some(c) = c2 {
        for u in c.to_uppercase() {
          out.push(u);
        }
      }
      i += 3;
    } else {
      out.push(c0);
      i += 1;
    }
  }
  out
}

/// Faithful Rust port of `Image::ExifTool::XMP::DecodeBase64` (XMP.pm:2978-
/// 3011). Permissive: deletes `=` and whitespace, truncates at first
/// non-alphabet character (R2-F4 fix).
fn decode_base64(s: &str) -> Vec<u8> {
  let val = |c: u8| -> Option<u8> {
    match c {
      b'A'..=b'Z' => Some(c - b'A'),
      b'a'..=b'z' => Some(26 + (c - b'a')),
      b'0'..=b'9' => Some(52 + (c - b'0')),
      b'+' => Some(62),
      b'/' => Some(63),
      _ => None,
    }
  };
  let mut quartet: [u8; 4] = [0; 4];
  let mut q_len: usize = 0;
  let mut out: Vec<u8> = Vec::with_capacity(s.len() * 3 / 4);
  for &b in s.as_bytes() {
    if b == b'=' || matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0c) {
      continue;
    }
    let Some(v) = val(b) else {
      break;
    };
    // Checked-indexing (Phase C w2b): `q_len` is reset to 0 whenever it reaches
    // 4, so it is always in `0..4` here ⇒ `quartet.get_mut(q_len)` is `Some` ⇒
    // byte-identical to the previous `quartet[q_len] = v`.
    if let Some(slot) = quartet.get_mut(q_len) {
      *slot = v;
    }
    q_len += 1;
    if q_len == 4 {
      out.push((quartet[0] << 2) | (quartet[1] >> 4));
      out.push((quartet[1] << 4) | (quartet[2] >> 2));
      out.push((quartet[2] << 6) | quartet[3]);
      q_len = 0;
    }
  }
  if q_len >= 2 {
    out.push((quartet[0] << 2) | (quartet[1] >> 4));
  }
  if q_len >= 3 {
    out.push((quartet[1] << 4) | (quartet[2] >> 2));
  }
  out
}

// ===========================================================================
// `Taggable` — the golden-pattern emission path
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::diagnostics::Diagnose for Meta<'_> {
  /// FLAC's diagnostics in the retired drain order: (a) the chained ID3
  /// sub-Meta's own warnings then errors (BEFORE the FLAC body), (b) the
  /// FLAC.pm:278 "Format error in FLAC file" warning (was `flac_format_error_warned()`,
  /// now read from the inner `format_error` flag), (c) one "Picture pointer
  /// references previous VorbisComment directory" warning per
  /// METADATA_BLOCK_PICTURE Vorbis item (Vorbis.pm:122-135). Byte-identical net
  /// `TagMap`.
  fn diagnostics(&self) -> std::vec::Vec<crate::diagnostics::Diagnostic> {
    let mut out = std::vec::Vec::new();
    #[cfg(feature = "id3")]
    if let Some(id3) = self.id3_ref() {
      out.extend(crate::diagnostics::Diagnose::diagnostics(id3));
    }
    if self.format_error {
      out.push(crate::diagnostics::Diagnostic::warn(
        "Format error in FLAC file",
      ));
    }
    for item in self.vorbis_items() {
      if item.is_picture_recursion_warning() {
        out.push(crate::diagnostics::Diagnostic::warn(
          "Picture pointer references previous VorbisComment directory",
        ));
      }
    }
    out
  }
}

#[cfg(feature = "alloc")]
impl crate::emit::Taggable for Meta<'_> {
  /// Yield FLAC tags in bundled `perl exiftool -j -G1` order:
  /// (0) the chained ID3 sub-Meta (FLAC.pm:243-247 embedded `ProcessID3`) →
  /// `FLAC:*` StreamInfo (FLAC.pm:59-82) → `Vorbis:*` comments (Vorbis.pm:
  /// 175-203, vendor first then user comments in extraction order) →
  /// `FLAC:Picture*` (FLAC.pm:84-134, one Picture block at a time) →
  /// `Composite:Duration` (FLAC.pm:137-149).
  ///
  /// The golden-pattern parallel to the retired `serialize_tags`: the SINK
  /// changes (an [`EmittedTag`](crate::emit::EmittedTag) per value instead of
  /// `out.write_*`); the value variants (`TagValue::U64` for StreamInfo /
  /// Picture integers, `TagValue::Str` for MD5 hex / Vorbis scalars / Picture
  /// MIME+Description, `TagValue::List` for the Vorbis `List => 1` coalesce,
  /// `TagValue::Bytes` for CoverArt + the Picture binary), the emission ORDER,
  /// the ID3-chain position, and every PrintConv/ValueConv branch are
  /// preserved verbatim.
  ///
  /// `mode == PrintConv` (`-j`) ⇒ PrintConv strings (e.g. PictureType →
  /// "Front Cover", Duration → `ConvertDuration`); `mode == ValueConv` (`-n`)
  /// ⇒ post-ValueConv raw scalars.
  ///
  /// **Groups.** Family-0/1 both `"FLAC"` for StreamInfo + Picture, both
  /// `"Vorbis"` for Vorbis comments, both `"Composite"` for Duration (each
  /// sub-table's group0 == group1 — none carries a `Groups => { 1 => ... }`
  /// override). Every FLAC tag is a known tag ⇒ `unknown: false`.
  ///
  /// **List-tag note (Codex CF2).** Vorbis `List => 1` tags
  /// (Artist/Performer/Contact, Vorbis.pm:85/86/94) coalesce into a single
  /// `TagValue::List` at first-occurrence position (faithful `FoundTag`,
  /// ExifTool.pm:9505-9520). The flat `self.vorbis` stream may carry the same
  /// listable name more than once; we gather all its values (in encounter
  /// order) and emit ONE `EmittedTag` carrying the list at the first
  /// occurrence, skipping later repeats.
  ///
  /// **Warnings are NOT part of this tag stream** ([`run_emission`](crate::emit::run_emission)
  /// has no warning/error channel). The FLAC.pm:278 "Format error in FLAC
  /// file" warning, the Vorbis.pm:122-135 "Picture pointer references previous
  /// VorbisComment directory" recursion warning, and the chained ID3 sub-Meta's
  /// warnings/errors are drained by the `AnyMeta::Flac` dispatch arm AFTER
  /// `run_emission`, in the same order the retired `serialize_tags` emitted
  /// them (ID3 warnings/errors first — they were written during the top-of-fn
  /// `id3.serialize_tags` call — then the FLAC format-error, then each
  /// picture-recursion warning), so the net `TagMap` stays byte-identical.
  ///
  /// The File:* triplet is NOT emitted here — it is the engine
  /// ([`crate::parser::extract_info`]) `SetFileType` responsibility.
  fn tags(
    &self,
    opts: crate::emit::EmitOptions,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    let mode = opts.mode;
    use crate::emit::EmittedTag;
    use crate::value::{Group, TagValue};

    // family-0 == family-1 per sub-table (see fn docs). FLAC.pm StreamInfo /
    // Picture → "FLAC"; Vorbis.pm comments → "Vorbis"; Composite → "Composite".
    let flac_group = || Group::new("FLAC", "FLAC");
    let vorbis_group = || Group::new("Vorbis", "Vorbis");
    let composite_group = || Group::new("Composite", "Composite");
    let print_conv = matches!(mode, crate::emit::ConvMode::PrintConv);

    let mut tags: Vec<EmittedTag> = Vec::new();

    // (0) Chained ID3 sub-Meta (FLAC.pm:243-247 embedded `ProcessID3`).
    // Bundled runs `ProcessID3` BEFORE the FLAC body extraction (it's the
    // very first thing FLAC.pm:243-247 does — see ID3.pm:1606
    // `FoundTag('ID3Size', $id3Len)` and the ID3v2 header / v1 trailer
    // ProcessDirectory calls at ID3.pm:1607-1617), so `File:ID3Size` + every
    // `ID3v2_*:*` frame tag precedes the FLAC StreamInfo / Vorbis / Picture
    // tags. The retired sink called `id3.serialize_tags(print_conv, out)` at
    // this exact point; `Id3Meta` is `Taggable`, so its tags flow through the
    // same engine here. Its warnings/errors are drained by the `AnyMeta::Flac`
    // arm (matching the retired position — see fn docs).
    #[cfg(feature = "id3")]
    if let Some(id3) = self.id3.as_ref() {
      tags.extend(id3.tags(opts));
    }

    // -- StreamInfo (FLAC.pm:59-82) ---------------------------------------
    // ValueConv on Channels/BitsPerSample (`$val + 1`) is already applied on
    // the stored scalars. No PrintConv on any StreamInfo tag (FLAC.pm:59-82),
    // so -j and -n are identical here. MD5Signature ValueConv
    // (`unpack("H*",$val)`) is applied below via `format_md5_hex`.
    if let Some(v) = self.stream_info.block_size_min {
      tags.push(EmittedTag::new(
        flac_group(),
        "BlockSizeMin".into(),
        TagValue::U64(u64::from(v)),
        false,
      ));
    }
    if let Some(v) = self.stream_info.block_size_max {
      tags.push(EmittedTag::new(
        flac_group(),
        "BlockSizeMax".into(),
        TagValue::U64(u64::from(v)),
        false,
      ));
    }
    if let Some(v) = self.stream_info.frame_size_min {
      tags.push(EmittedTag::new(
        flac_group(),
        "FrameSizeMin".into(),
        TagValue::U64(u64::from(v)),
        false,
      ));
    }
    if let Some(v) = self.stream_info.frame_size_max {
      tags.push(EmittedTag::new(
        flac_group(),
        "FrameSizeMax".into(),
        TagValue::U64(u64::from(v)),
        false,
      ));
    }
    if let Some(v) = self.stream_info.sample_rate {
      tags.push(EmittedTag::new(
        flac_group(),
        "SampleRate".into(),
        TagValue::U64(u64::from(v)),
        false,
      ));
    }
    if let Some(v) = self.stream_info.channels {
      tags.push(EmittedTag::new(
        flac_group(),
        "Channels".into(),
        TagValue::U64(u64::from(v)),
        false,
      ));
    }
    if let Some(v) = self.stream_info.bits_per_sample {
      tags.push(EmittedTag::new(
        flac_group(),
        "BitsPerSample".into(),
        TagValue::U64(u64::from(v)),
        false,
      ));
    }
    if let Some(v) = self.stream_info.total_samples {
      tags.push(EmittedTag::new(
        flac_group(),
        "TotalSamples".into(),
        TagValue::U64(v),
        false,
      ));
    }
    if let Some(md5) = &self.stream_info.md5_signature {
      // unpack("H*",$val) — lowercase hex of all 16 bytes. The retired sink
      // used `write_fmt(|w| write!(w, "{x:02x}"))` → `TagValue::Str`; the
      // `format_md5_hex` String here renders identically.
      tags.push(EmittedTag::new(
        flac_group(),
        "MD5Signature".into(),
        TagValue::Str(format_md5_hex(md5).into()),
        false,
      ));
    }

    // -- VorbisComment (Vorbis.pm:175-203) --------------------------------
    // List=>1 tags coalesce into a single `TagValue::List` at FIRST-occurrence
    // position; we gather all values for each listable name (in encounter
    // order) and emit ONE list `EmittedTag` at the first occurrence, skipping
    // later repeats (Codex CF2). Non-listable scalars emit verbatim.
    let mut emitted_listable: Vec<&str> = Vec::new();
    for item in &self.vorbis {
      match item {
        VorbisItem::Vendor(s) => {
          tags.push(EmittedTag::new(
            vorbis_group(),
            "Vendor".into(),
            TagValue::Str(s.as_ref().into()),
            false,
          ));
        }
        VorbisItem::Named(named) => {
          if named.is_listable() {
            let key: &str = named.name();
            if emitted_listable.contains(&key) {
              // Already coalesced at first occurrence; skip the repeat.
              continue;
            }
            // Gather every value for this name across the stream, in order
            // (faithful `TagMap::write_str_list` → `TagValue::List(Str…)`).
            let items: Vec<TagValue> = self
              .vorbis
              .iter()
              .filter_map(|it| match it {
                VorbisItem::Named(n) if n.is_listable() && n.name() == key => {
                  Some(TagValue::Str(n.value().into()))
                }
                _ => None,
              })
              .collect();
            tags.push(EmittedTag::new(
              vorbis_group(),
              key.into(),
              TagValue::List(items),
              false,
            ));
            emitted_listable.push(key);
          } else {
            tags.push(EmittedTag::new(
              vorbis_group(),
              named.name().into(),
              TagValue::Str(named.value().into()),
              false,
            ));
          }
        }
        VorbisItem::Auto(auto) => {
          tags.push(EmittedTag::new(
            vorbis_group(),
            auto.name().into(),
            TagValue::Str(auto.value().into()),
            false,
          ));
        }
        VorbisItem::CoverArt(bytes) => {
          tags.push(EmittedTag::new(
            vorbis_group(),
            "CoverArt".into(),
            TagValue::Bytes(bytes.clone()),
            false,
          ));
        }
        // PictureRecursionWarning emits ONLY a warning, no tag — drained by
        // the `AnyMeta::Flac` arm (see fn docs).
        VorbisItem::PictureRecursionWarning(_) => {}
      }
    }

    // -- Picture (FLAC.pm:84-134) -----------------------------------------
    for p in &self.pictures {
      push_picture_tags(&mut tags, p, print_conv);
    }

    // -- Composite:Duration (FLAC.pm:137-149) -----------------------------
    if let Some(d) = self.duration() {
      let secs = d.as_secs_f64();
      let value = if print_conv {
        // ConvertDuration (the retired `write_fmt` → `TagValue::Str`).
        let mut s = String::new();
        let _ = write_convert_duration(&mut s, secs);
        TagValue::Str(s.into())
      } else {
        TagValue::F64(secs)
      };
      tags.push(EmittedTag::new(
        composite_group(),
        "Duration".into(),
        value,
        false,
      ));
    }

    tags.into_iter()
  }
}

/// Push a single [`Picture`]'s tags in faithful FLAC.pm:84-134 order onto
/// `tags`. Drops the Picture sub-field iff `length > 0 && data.is_empty()`
/// (ExifTool::ReadValue clamp at ExifTool.pm:6292 `count < 1 and return
/// undef`). Value variants match the retired `sink_picture`: `TagValue::Str`
/// for PictureType (PrintConv) / MIME / Description, `TagValue::U64` for the
/// numeric fields (incl. PictureType under `-n` and on a PrintConv hash miss),
/// `TagValue::Bytes` for the Picture binary.
#[cfg(feature = "alloc")]
fn push_picture_tags(tags: &mut Vec<crate::emit::EmittedTag>, p: &Picture<'_>, print_conv: bool) {
  use crate::emit::EmittedTag;
  use crate::value::{Group, TagValue};
  let group = || Group::new("FLAC", "FLAC");
  // PictureType — PrintConv hash (FLAC.pm:88-113). On a hash miss the Perl
  // default falls back to the numeric value as a string (we emit raw u32).
  let picture_type = if print_conv {
    match p.picture_type_name() {
      Some(name) => TagValue::Str(name.into()),
      None => TagValue::U64(u64::from(p.picture_type)),
    }
  } else {
    TagValue::U64(u64::from(p.picture_type))
  };
  tags.push(EmittedTag::new(
    group(),
    "PictureType".into(),
    picture_type,
    false,
  ));
  tags.push(EmittedTag::new(
    group(),
    "PictureMIMEType".into(),
    TagValue::Str(p.mime_type().into()),
    false,
  ));
  tags.push(EmittedTag::new(
    group(),
    "PictureDescription".into(),
    TagValue::Str(p.description().into()),
    false,
  ));
  tags.push(EmittedTag::new(
    group(),
    "PictureWidth".into(),
    TagValue::U64(u64::from(p.width)),
    false,
  ));
  tags.push(EmittedTag::new(
    group(),
    "PictureHeight".into(),
    TagValue::U64(u64::from(p.height)),
    false,
  ));
  tags.push(EmittedTag::new(
    group(),
    "PictureBitsPerPixel".into(),
    TagValue::U64(u64::from(p.bits_per_pixel)),
    false,
  ));
  tags.push(EmittedTag::new(
    group(),
    "PictureIndexedColors".into(),
    TagValue::U64(u64::from(p.indexed_colors)),
    false,
  ));
  tags.push(EmittedTag::new(
    group(),
    "PictureLength".into(),
    TagValue::U64(u64::from(p.length)),
    false,
  ));
  // Picture binary — skip emission when ReadValue's count-clamped-to-zero
  // sentinel fires (declared > 0 but no bytes left). The empty-payload case
  // (length == 0) still emits an empty `TagValue::Bytes` for the serializer
  // to render as `(Binary data 0 bytes, …)`.
  if p.length > 0 && p.data.is_empty() {
    // Faithful skip — ExifTool.pm:6292 returns undef → no tag.
  } else {
    tags.push(EmittedTag::new(
      group(),
      "Picture".into(),
      TagValue::Bytes(p.data.to_vec()),
      false,
    ));
  }
}

// ===========================================================================
// `Project` — the normalized cross-format domain projection (golden L2)
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::metadata::Project for Meta<'_> {
  /// Project FLAC metadata onto the normalized
  /// [`MediaMetadata`](crate::metadata::MediaMetadata) domain.
  ///
  /// FLAC is a lossless audio stream: it carries no camera / lens / GPS /
  /// capture facts (those domains stay `None`). The structural contributions
  /// are one audio [`TrackKind`](crate::metadata::TrackKind) (FLAC files are
  /// audio-only — `%FLAC::StreamInfo` `GROUPS{2} => 'Audio'`, FLAC.pm:60) and
  /// the `Composite:Duration` (FLAC.pm:137-149 `TotalSamples / SampleRate`),
  /// which `Meta` already exposes as a clean `Option<Duration>` accessor
  /// ([`Meta::duration`]) — so unlike DSF (raw `SampleCount` only), FLAC has a
  /// faithful decoded duration to surface. Dimensions / created stay `None`.
  fn project(&self) -> crate::metadata::MediaMetadata {
    use crate::metadata::TrackKind;
    let mut media = crate::metadata::MediaMetadata::new();
    media.media_mut().track_kinds_mut().push(TrackKind::Audio);
    media.media_mut().update_duration(self.duration());
    media
  }
}

/// Format-into-writer port of `Image::ExifTool::ConvertDuration`
/// (ExifTool.pm:6866-6884). Writes directly into a [`core::fmt::Write`]
/// sink — no intermediate `String` allocation.
pub fn write_convert_duration<W: core::fmt::Write + ?Sized>(
  w: &mut W,
  time: f64,
) -> core::fmt::Result {
  if !time.is_finite() {
    return write!(w, "{time}");
  }
  if time == 0.0 {
    return w.write_str("0 s");
  }
  let (sign, mut t) = if time > 0.0 { ("", time) } else { ("-", -time) };
  if t < 30.0 {
    return write!(w, "{sign}{t:.2} s");
  }
  t += 0.5;
  let mut h: i64 = (t / 3600.0) as i64;
  t -= (h as f64) * 3600.0;
  let m: i64 = (t / 60.0) as i64;
  t -= (m as f64) * 60.0;
  let s_int: i64 = t as i64;
  if h > 24 {
    let d = h / 24;
    h -= d * 24;
    return write!(w, "{sign}{d} days {h}:{m:02}:{s_int:02}");
  }
  write!(w, "{sign}{h}:{m:02}:{s_int:02}")
}

// ===========================================================================
// Engine entry — typed parse + File:* + sink into `Metadata`
// ===========================================================================

// ===========================================================================
// Warning/error drain rationale (golden pattern)
//
// The golden [`Taggable`] impl above yields only the TAG stream; the
// `run_emission` engine has no warning/error channel. FLAC's three warning
// sources — the chained ID3 sub-Meta's warnings/errors (FLAC.pm:243-247), the
// FLAC.pm:278 "Format error in FLAC file" warning, and the Vorbis.pm:122-135
// "Picture pointer references previous VorbisComment directory" recursion
// warning (one per METADATA_BLOCK_PICTURE comment) — are drained by the
// `AnyMeta::Flac` dispatch arm in `format_parser.rs` AFTER `run_emission`, in
// the exact order the retired `serialize_tags` emitted them (ID3 warnings then
// errors, then the FLAC format-error, then each picture-recursion warning), so
// `TagMap::first_warning`/`first_error` and the net `TagMap` stay
// byte-identical. The Vorbis "Format error in Vorbis comments" warning was
// never emitted by the retired `serialize_tags` path either (the typed Meta
// stops early on malformed input without recording it), so the net output is
// unchanged. List coalescing (Vorbis ARTIST/PERFORMER/CONTACT, Vorbis.pm:
// 85/86/94) is reproduced as ONE `EmittedTag` carrying a `TagValue::List`,
// byte-identical to the retired `TagMap::write_str_list`.
// ===========================================================================

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2b); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;
  use crate::emit::{ConvMode, Taggable};
  use crate::tagmap::TagMap;

  // ---------- StreamInfo bit-stream decoding -----------------------------

  fn fixture(path: &str) -> Vec<u8> {
    let root = env!("CARGO_MANIFEST_DIR");
    std::fs::read(format!("{root}/tests/fixtures/{path}")).expect("fixture exists")
  }

  /// Drive a [`Meta`] through the golden [`run_emission`](crate::emit) engine
  /// PLUS the `AnyMeta::Flac` arm's warning/error drain, in the SAME order the
  /// arm uses: (a) the chained ID3 sub-Meta's warnings then errors, (b) the
  /// FLAC.pm:278 "Format error in FLAC file" warning, (c) one "Picture pointer
  /// references previous VorbisComment directory" warning per
  /// METADATA_BLOCK_PICTURE Vorbis item. Mirrors `format_parser.rs` exactly so
  /// the in-module tests exercise the same net `TagMap` the engine produces.
  /// `print_conv` ⇒ `-j`, else `-n`.
  fn emit_via_engine(meta: &Meta<'_>, print_conv: bool, out: &mut TagMap) {
    crate::emit::run_emission(
      meta,
      crate::emit::EmitOptions::g1(ConvMode::from_print_conv(print_conv), false),
      out,
    );
    crate::diagnostics::run_diagnostics(meta, out);
  }

  /// Whether the FLAC.pm:278 "Format error in FLAC file" warning is present in
  /// the Meta's [`Diagnose`](crate::diagnostics::Diagnose) stream — the test
  /// read-back that replaced the retired `flac_format_error_warned()` bool accessor.
  fn flac_format_error_warned(meta: &Meta<'_>) -> bool {
    crate::diagnostics::Diagnose::diagnostics(meta)
      .iter()
      .any(|d| d.message() == "Format error in FLAC file")
  }

  #[test]
  fn parse_streaminfo_matches_flac_flac_fixture() {
    // Real fixture: tests/fixtures/FLAC.flac at offset 8 (after `fLaC` +
    // 4-byte block header) holds the 34-byte StreamInfo body.
    let data = fixture("FLAC.flac");
    let payload = &data[8..8 + 34];
    let si = parse_streaminfo(payload);
    assert_eq!(si.block_size_min, Some(4608));
    assert_eq!(si.block_size_max, Some(4608));
    assert_eq!(si.frame_size_min, Some(16_777_215));
    assert_eq!(si.frame_size_max, Some(0));
    assert_eq!(si.sample_rate, Some(8000));
    assert_eq!(si.channels, Some(2)); // raw 1 + 1
    assert_eq!(si.bits_per_sample, Some(8)); // raw 7 + 1
    assert_eq!(si.total_samples, Some(0));
    assert_eq!(
      format_md5_hex(si.md5_signature.as_ref().unwrap()),
      "d41d8cd98f00b204e9800998ecf8427e"
    );
  }

  #[test]
  fn parse_streaminfo_truncated_drops_late_fields() {
    // 6 bytes — only BlockSizeMin (bytes 0..2) + BlockSizeMax (bytes 2..4)
    // fully fit; FrameSizeMin needs bytes 4..7 (one byte short).
    let si = parse_streaminfo(&[0, 18, 0, 18, 0, 0]);
    assert_eq!(si.block_size_min, Some(18));
    assert_eq!(si.block_size_max, Some(18));
    assert!(si.frame_size_min.is_none());
    assert!(si.md5_signature.is_none());
  }

  // ---------- Vorbis comment decoding ------------------------------------

  fn make_vorbis(vendor: &[u8], comments: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&(vendor.len() as u32).to_le_bytes());
    v.extend_from_slice(vendor);
    v.extend_from_slice(&(comments.len() as u32).to_le_bytes());
    for c in comments {
      v.extend_from_slice(&(c.len() as u32).to_le_bytes());
      v.extend_from_slice(c);
    }
    v
  }

  #[test]
  fn process_vorbis_comments_emits_vendor_and_named() {
    let payload = make_vorbis(b"vendor", &[b"TITLE=Hi", b"COPYRIGHT=PH"]);
    let mut items = Vec::new();
    assert!(process_vorbis_comments(&payload, &mut items));
    assert!(matches!(&items[0], VorbisItem::Vendor(c) if c == "vendor"));
    assert!(
      matches!(&items[1], VorbisItem::Named(n) if n.name() == "Title" && n.value() == "Hi" && !n.is_listable())
    );
    assert!(
      matches!(&items[2], VorbisItem::Named(n) if n.name() == "Copyright" && n.value() == "PH")
    );
  }

  #[test]
  fn process_vorbis_comments_artist_is_listable() {
    let payload = make_vorbis(b"v", &[b"ARTIST=Alice", b"ARTIST=Bob"]);
    let mut items = Vec::new();
    assert!(process_vorbis_comments(&payload, &mut items));
    let names: Vec<_> = items
      .iter()
      .filter_map(|i| match i {
        VorbisItem::Named(n) => Some((n.name(), n.is_listable())),
        _ => None,
      })
      .collect();
    assert_eq!(names, vec![("Artist", true), ("Artist", true)]);
  }

  #[test]
  fn process_vorbis_comments_unknown_tag_derives_name() {
    let payload = make_vorbis(b"v", &[b"FOO_BAR=42", b"X.Y=z"]);
    let mut items = Vec::new();
    assert!(process_vorbis_comments(&payload, &mut items));
    let names: Vec<_> = items
      .iter()
      .filter_map(|i| match i {
        VorbisItem::Auto(a) => Some((a.name().to_string(), a.value().to_string())),
        _ => None,
      })
      .collect();
    assert_eq!(
      names,
      vec![
        ("FooBar".to_string(), "42".to_string()),
        ("XY".to_string(), "z".to_string()),
      ]
    );
  }

  #[test]
  fn process_vorbis_comments_coverart_decodes_base64() {
    let payload = make_vorbis(b"v", &[b"COVERART=AAEC"]);
    let mut items = Vec::new();
    assert!(process_vorbis_comments(&payload, &mut items));
    let last = items.last().unwrap();
    assert!(matches!(last, VorbisItem::CoverArt(b) if b == &[0u8, 1, 2]));
  }

  #[test]
  fn process_vorbis_comments_metadata_block_picture_emits_warning_item() {
    let payload = make_vorbis(b"v", &[b"METADATA_BLOCK_PICTURE=AAAA"]);
    let mut items = Vec::new();
    assert!(process_vorbis_comments(&payload, &mut items));
    assert!(matches!(
      items.last().unwrap(),
      VorbisItem::PictureRecursionWarning(_)
    ));
  }

  #[test]
  fn process_vorbis_comments_format_error_on_missing_equals() {
    let payload = make_vorbis(b"v", &[b"GOOD=ok", b"NOEQUALS"]);
    let mut items = Vec::new();
    assert!(!process_vorbis_comments(&payload, &mut items));
    // Vendor + GOOD (auto-named "Good") got through before the bad one.
    assert!(matches!(&items[0], VorbisItem::Vendor(_)));
    // "GOOD" is not in the static named-tag set ⇒ Auto-routed with the
    // derived name "Good" (Vorbis.pm:188-196 path).
    assert!(matches!(
      &items[1],
      VorbisItem::Auto(a) if a.name() == "Good"
    ));
  }

  #[test]
  fn process_vorbis_comments_exact_4_trailing_bytes_is_clean() {
    // R1-F4 regression pin: Vorbis.pm:184 strict `<`.
    let mut payload = Vec::new();
    payload.extend_from_slice(&(1u32).to_le_bytes());
    payload.push(b'v');
    payload.extend_from_slice(&[0x01u8, 0, 0, 0]);
    let mut items = Vec::new();
    assert!(process_vorbis_comments(&payload, &mut items));
    assert!(matches!(&items[0], VorbisItem::Vendor(_)));
    assert_eq!(items.len(), 1);
  }

  #[test]
  fn vorbis_derive_name_matches_perl_regex_transforms() {
    assert_eq!(vorbis_derive_name("FOO_BAR"), "FooBar");
    assert_eq!(vorbis_derive_name("X.Y"), "XY");
    assert_eq!(vorbis_derive_name("FOO BAR_BAZ"), "FooBarBaz");
    assert_eq!(vorbis_derive_name("HELLO"), "Hello");
    assert_eq!(vorbis_derive_name(""), "");
    assert_eq!(vorbis_derive_name("FOO."), "Foo");
    assert_eq!(vorbis_derive_name("FOO_"), "Foo_");
  }

  // ---------- Base64 decode ----------------------------------------------

  #[test]
  fn decode_base64_matches_perl_decodebase64() {
    assert_eq!(decode_base64(""), Vec::<u8>::new());
    assert_eq!(decode_base64("Q2F0"), b"Cat");
    assert_eq!(decode_base64("ZmlzaA=="), b"fish");
    assert_eq!(decode_base64("Q 2 F\n0"), b"Cat");
    assert_eq!(decode_base64("Q2F0!garbage"), b"Cat");
    assert_eq!(decode_base64("Q2F"), b"Ca");
    assert_eq!(decode_base64("AA==AA"), [0u8, 0, 0]);
    assert_eq!(decode_base64("AA=="), [0u8]);
    assert_eq!(decode_base64("  A B \nC=="), [0u8, 0x10]);
  }

  // ---------- FLAC Picture block decode ----------------------------------

  fn synth_picture_payload(pic_type: u32, picture_len: u32, picture_bytes: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&pic_type.to_be_bytes());
    p.extend_from_slice(&9u32.to_be_bytes());
    p.extend_from_slice(b"image/png");
    p.extend_from_slice(&1u32.to_be_bytes());
    p.extend_from_slice(b"X");
    p.extend_from_slice(&8u32.to_be_bytes());
    p.extend_from_slice(&8u32.to_be_bytes());
    p.extend_from_slice(&24u32.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes());
    p.extend_from_slice(&picture_len.to_be_bytes());
    p.extend_from_slice(picture_bytes);
    p
  }

  #[test]
  fn parse_flac_picture_extracts_all_fields() {
    let payload = synth_picture_payload(3, 4, &[0xDE, 0xAD, 0xBE, 0xEF]);
    let p = parse_flac_picture(&payload).expect("parses");
    assert_eq!(p.picture_type(), 3);
    assert_eq!(p.picture_type_name(), Some("Front Cover"));
    assert_eq!(p.mime_type(), "image/png");
    assert_eq!(p.description(), "X");
    assert_eq!(p.width(), 8);
    assert_eq!(p.height(), 8);
    assert_eq!(p.bits_per_pixel(), 24);
    assert_eq!(p.indexed_colors(), 0);
    assert_eq!(p.length(), 4);
    assert_eq!(p.data(), &[0xDE, 0xAD, 0xBE, 0xEF]);
  }

  #[test]
  fn parse_flac_picture_clamps_to_remaining() {
    // Declare 1M bytes but only provide 2 — faithful ReadValue clamp.
    let payload = synth_picture_payload(3, 1_000_000, &[0xAA, 0xBB]);
    let p = parse_flac_picture(&payload).expect("parses");
    assert_eq!(p.length(), 1_000_000);
    assert_eq!(p.data(), &[0xAA, 0xBB]);
  }

  // ---------- End-to-end ProcessFlac via FormatParser trait ---------------

  #[test]
  fn process_flac_typed_parser_extracts_real_fixture() {
    let data = fixture("FLAC.flac");
    let mut shared = crate::format_parser::SharedFlags::new();
    let meta = parse_borrowed(&data, &mut shared).expect("flac");
    assert_eq!(meta.block_size_min(), Some(4608));
    assert_eq!(meta.sample_rate(), Some(8000));
    assert_eq!(meta.channels(), Some(2));
    assert_eq!(meta.total_samples(), Some(0));
    assert_eq!(
      meta.md5_hex(),
      Some("d41d8cd98f00b204e9800998ecf8427e".to_string())
    );
    // Vorbis comment block carries vendor + 6 user comments.
    let vendors: Vec<_> = meta
      .vorbis_items()
      .iter()
      .filter_map(|i| match i {
        VorbisItem::Vendor(s) => Some(s.as_ref()),
        _ => None,
      })
      .collect();
    assert_eq!(vendors, vec!["reference libFLAC 1.1.2 20050205"]);
    // Title comment present.
    assert!(meta.vorbis_items().iter().any(|i| matches!(
      i,
      VorbisItem::Named(n) if n.name() == "Title" && n.value() == "ExifTool test"
    )));
    // No pictures in this fixture.
    assert!(meta.pictures().is_empty());
    // No format error.
    assert!(!flac_format_error_warned(&meta));
  }

  #[test]
  fn process_flac_typed_rejects_missing_magic() {
    let mut shared = crate::format_parser::SharedFlags::new();
    assert!(parse_borrowed(b"not-flac-data-here", &mut shared).is_none());
  }

  #[test]
  fn process_flac_typed_id3_prefix_then_flac_extracts() {
    let body = fixture("FLAC.flac");
    let mut data = Vec::new();
    data.extend_from_slice(&[b'I', b'D', b'3', 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    data.extend_from_slice(&body);
    let mut shared = crate::format_parser::SharedFlags::new();
    let meta = parse_borrowed(&data, &mut shared).expect("flac");
    assert_eq!(meta.sample_rate(), Some(8000));
  }

  #[test]
  fn process_flac_typed_panics_free_on_truncated_header() {
    // Just `fLaC` — magic OK, no blocks. format_error stays false (silent
    // exit on pos+4 > len, faithful).
    let mut shared = crate::format_parser::SharedFlags::new();
    let meta = parse_borrowed(b"fLaC", &mut shared).expect("flac");
    assert!(meta.stream_info.block_size_min.is_none());
    assert!(!flac_format_error_warned(&meta));
  }

  #[test]
  fn process_flac_typed_oversized_block_sets_format_error() {
    let data: &[u8] = &[b'f', b'L', b'a', b'C', 0x80, 0xff, 0xff, 0xff];
    let mut shared = crate::format_parser::SharedFlags::new();
    let meta = parse_borrowed(data, &mut shared).expect("flac");
    assert!(flac_format_error_warned(&meta));
  }

  // ---------- Engine entry (`extract_info`) -------------------------------
  // The engine path is now `crate::parser::extract_info`. These tests run it
  // and assert on the parsed JSON object (replacing the retired
  // `ProcessFlac::process` + `TagMap` tests).

  fn engine_obj(data: &[u8], print_on: bool) -> serde_json::Map<String, serde_json::Value> {
    let json = crate::parser::extract_info("x.flac", data, print_on);
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    v.as_array().unwrap()[0].as_object().unwrap().clone()
  }

  #[test]
  fn bridge_extracts_flac_flac_fixture() {
    let obj = engine_obj(&fixture("FLAC.flac"), true);
    let s = |k: &str| obj.get(k).and_then(|v| v.as_str());
    assert_eq!(s("File:FileType"), Some("FLAC"));
    assert_eq!(
      obj.get("FLAC:BlockSizeMin").and_then(|v| v.as_i64()),
      Some(4608)
    );
    assert_eq!(obj.get("FLAC:Channels").and_then(|v| v.as_i64()), Some(2));
    assert_eq!(
      obj.get("FLAC:BitsPerSample").and_then(|v| v.as_i64()),
      Some(8)
    );
    assert_eq!(
      s("FLAC:MD5Signature"),
      Some("d41d8cd98f00b204e9800998ecf8427e")
    );
    assert_eq!(s("Vorbis:Vendor"), Some("reference libFLAC 1.1.2 20050205"));
    assert_eq!(s("Vorbis:Title"), Some("ExifTool test"));
    assert!(!obj.contains_key("ExifTool:Warning"));
  }

  #[test]
  fn bridge_rejects_missing_magic() {
    let obj = engine_obj(b"not-flac-here", true);
    assert_ne!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("FLAC")
    );
  }

  #[test]
  fn bridge_id3_prefix_then_flac_extracts() {
    let body = fixture("FLAC.flac");
    let mut data = Vec::new();
    data.extend_from_slice(&[b'I', b'D', b'3', 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    data.extend_from_slice(&body);
    let obj = engine_obj(&data, true);
    assert_eq!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("FLAC")
    );
    assert!(obj.contains_key("FLAC:BlockSizeMin"));
    assert!(!obj.contains_key("ExifTool:Error"));
  }

  #[test]
  fn bridge_truncated_block_emits_format_error_warning() {
    let obj = engine_obj(&fixture("bad_flac.flac"), true);
    assert_eq!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("FLAC")
    );
    assert_eq!(
      obj.get("ExifTool:Warning").and_then(|v| v.as_str()),
      Some("Format error in FLAC file")
    );
  }

  #[test]
  fn bridge_multi_artist_coalesces_into_list() {
    let obj = engine_obj(&fixture("FLAC_multi_artist.flac"), true);
    match obj.get("Vorbis:Artist") {
      Some(serde_json::Value::Array(items)) => {
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].as_str(), Some("Alice"));
        assert_eq!(items[1].as_str(), Some("Bob"));
      }
      other => panic!("expected List(Artist), got {other:?}"),
    }
  }

  #[test]
  fn bridge_picture_block_emits_all_subfields() {
    // Order is preserved by the golden engine -> `TagMap` entries (the JSON
    // object loses key order).
    let data = fixture("FLAC_picture.flac");
    let mut shared = crate::format_parser::SharedFlags::new();
    let meta = parse_borrowed(&data, &mut shared).unwrap();
    let mut tm = TagMap::new();
    emit_via_engine(&meta, true, &mut tm);
    let names: Vec<&str> = tm
      .entries()
      .iter()
      .filter_map(|(_, _, g, n, _, _)| (g == "FLAC").then_some(n.as_str()))
      .filter(|n| n.starts_with("Picture"))
      .collect();
    assert_eq!(
      names,
      vec![
        "PictureType",
        "PictureMIMEType",
        "PictureDescription",
        "PictureWidth",
        "PictureHeight",
        "PictureBitsPerPixel",
        "PictureIndexedColors",
        "PictureLength",
        "Picture",
      ]
    );
    let obj = engine_obj(&fixture("FLAC_picture.flac"), true);
    assert_eq!(
      obj.get("FLAC:PictureType").and_then(|v| v.as_str()),
      Some("Front Cover")
    );
  }

  #[test]
  fn bridge_coverart_emits_binary_bytes() {
    let obj = engine_obj(&fixture("FLAC_coverart.flac"), true);
    // Binary ⇒ the no-`-b` placeholder string. The cover art is a Vorbis
    // comment (`Vorbis:CoverArt`).
    assert!(
      obj
        .get("Vorbis:CoverArt")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s.contains("Binary data")),
      "CoverArt binary placeholder: {:?}",
      obj.get("Vorbis:CoverArt")
    );
  }

  #[test]
  fn bridge_metadata_block_picture_emits_recursion_warning() {
    let obj = engine_obj(&fixture("FLAC_mbpicture.flac"), true);
    assert_eq!(
      obj.get("ExifTool:Warning").and_then(|v| v.as_str()),
      Some("Picture pointer references previous VorbisComment directory")
    );
    // No Picture* sub-fields.
    assert!(
      !obj.keys().any(|k| k == "FLAC:PictureType"
        || k == "FLAC:PictureMIMEType"
        || k == "FLAC:PictureWidth"),
      "no Picture sub-fields under METADATA_BLOCK_PICTURE recursion-guard path"
    );
  }

  #[test]
  fn bridge_composite_duration_emitted_when_both_present() {
    let obj = engine_obj(&fixture("FLAC_duration.flac"), true);
    assert_eq!(
      obj.get("Composite:Duration").and_then(|v| v.as_str()),
      Some("0:00:30")
    );
    // -n mode emits the raw f64.
    let obj = engine_obj(&fixture("FLAC_duration.flac"), false);
    assert_eq!(
      obj.get("Composite:Duration").and_then(|v| v.as_f64()),
      Some(30.0)
    );
  }

  // ---------- golden-pattern emission via TagMap -------------------------

  #[test]
  fn sink_into_map_writer_emits_streaminfo_tags() {
    let data = fixture("FLAC.flac");
    let mut shared = crate::format_parser::SharedFlags::new();
    let meta = parse_borrowed(&data, &mut shared).unwrap();
    let mut w = TagMap::new();
    emit_via_engine(&meta, true, &mut w);
    let g = |n: &str| w.get("FLAC", n).cloned();
    assert!(g("BlockSizeMin").is_some());
    assert!(g("Channels").is_some());
    assert!(g("MD5Signature").is_some());
    // Vendor in Vorbis group.
    assert!(w.get("Vorbis", "Vendor").is_some());
  }

  /// Codex CF2: the golden engine coalesces repeated Vorbis List=>1 entries
  /// (ARTIST/PERFORMER/CONTACT) into a single first-occurrence-position
  /// `TagValue::List`, so a `TagMap` consumer builds a JSON array instead of
  /// last-write-wins.
  #[test]
  fn sink_list_coalesces_repeated_artist_via_json_writer() {
    // Two ARTIST entries (listable) plus a non-listable TITLE between
    // pins both ordering and the first-occurrence-position contract.
    let meta = Meta {
      stream_info: StreamInfo::default(),
      vorbis: vec![
        VorbisItem::Named(VorbisNamed::new("Artist", Cow::Borrowed("Alice"), true)),
        VorbisItem::Named(VorbisNamed::new("Title", Cow::Borrowed("Song"), false)),
        VorbisItem::Named(VorbisNamed::new("Artist", Cow::Borrowed("Bob"), true)),
      ],
      pictures: vec![],
      format_error: false,
      id3: None,
    };
    let mut md = TagMap::new();
    emit_via_engine(&meta, true, &mut md);
    // One Artist tag carrying a 2-element list (not two scalars).
    match md.get("Vorbis", "Artist") {
      Some(TagValue::List(items)) => {
        assert_eq!(items.len(), 2);
        assert!(matches!(&items[0], TagValue::Str(s) if s == "Alice"));
        assert!(matches!(&items[1], TagValue::Str(s) if s == "Bob"));
      }
      other => panic!("expected coalesced TagValue::List, got {other:?}"),
    }
    // Title still a plain scalar.
    assert!(matches!(md.get("Vorbis", "Title"), Some(TagValue::Str(s)) if s == "Song"));
  }

  // ---------- ConvertDuration oracle table -------------------------------

  fn fmt_duration(t: f64) -> String {
    let mut s = String::new();
    write_convert_duration(&mut s, t).unwrap();
    s
  }

  #[test]
  fn convert_duration_matches_oracle() {
    assert_eq!(fmt_duration(0.0), "0 s");
    assert_eq!(fmt_duration(1.543125), "1.54 s");
    assert_eq!(fmt_duration(29.999), "30.00 s");
    assert_eq!(fmt_duration(30.0), "0:00:30");
    assert_eq!(fmt_duration(3600.0), "1:00:00");
    assert_eq!(fmt_duration(86400.0 * 2.0 + 3661.0), "2 days 1:01:01");
    assert_eq!(fmt_duration(-1.543125), "-1.54 s");
    assert_eq!(fmt_duration(-30.0), "-0:00:30");
  }

  // ---------- StreamInfo + Vorbis static-table identity ------------------

  #[test]
  fn streaminfo_table_is_faithful_to_flac_pm() {
    let g = FLAC_STREAMINFO_TABLE.get();
    assert_eq!(FLAC_STREAMINFO_TABLE.group0(), "FLAC");
    assert_eq!(g(TagId::Str("Bit000-015")).unwrap().name(), "BlockSizeMin");
    assert_eq!(g(TagId::Str("Bit016-031")).unwrap().name(), "BlockSizeMax");
    assert_eq!(g(TagId::Str("Bit032-055")).unwrap().name(), "FrameSizeMin");
    assert_eq!(g(TagId::Str("Bit056-079")).unwrap().name(), "FrameSizeMax");
    assert_eq!(g(TagId::Str("Bit080-099")).unwrap().name(), "SampleRate");
    assert_eq!(g(TagId::Str("Bit100-102")).unwrap().name(), "Channels");
    assert_eq!(g(TagId::Str("Bit103-107")).unwrap().name(), "BitsPerSample");
    assert_eq!(g(TagId::Str("Bit108-143")).unwrap().name(), "TotalSamples");
    assert_eq!(g(TagId::Str("Bit144-271")).unwrap().name(), "MD5Signature");
    assert!(matches!(
      g(TagId::Str("Bit100-102")).unwrap().value_conv(),
      ValueConv::Func(_)
    ));
    assert_eq!(g(TagId::Str("Bit144-271")).unwrap().format(), Some("undef"));
  }

  #[test]
  fn vorbis_table_named_tags_are_faithful() {
    let g = VORBIS_COMMENTS_TABLE.get();
    assert_eq!(VORBIS_COMMENTS_TABLE.group0(), "Vorbis");
    let cases: &[(&str, &str, bool)] = &[
      ("vendor", "Vendor", false),
      ("TITLE", "Title", false),
      ("ARTIST", "Artist", true),
      ("PERFORMER", "Performer", true),
      ("CONTACT", "Contact", true),
      ("COPYRIGHT", "Copyright", false),
      ("ISRC", "ISRCNumber", false),
      ("REPLAYGAIN_TRACK_PEAK", "ReplayGainTrackPeak", false),
      ("COVERART", "CoverArt", false),
      ("METADATA_BLOCK_PICTURE", "Picture", false),
    ];
    for (k, expected_name, expected_list) in cases {
      let d = g(TagId::Str(k)).unwrap_or_else(|| panic!("missing {k}"));
      assert_eq!(d.name(), *expected_name, "{k}");
      assert_eq!(d.list(), *expected_list, "{k} list flag");
    }
  }

  #[test]
  fn streaminfo_value_conv_fns_are_faithful() {
    assert_eq!(streaminfo_add_one(&TagValue::I64(1)), TagValue::I64(2));
    assert_eq!(streaminfo_add_one(&TagValue::I64(7)), TagValue::I64(8));
    assert_eq!(
      streaminfo_add_one(&TagValue::I64(i64::MAX)),
      TagValue::I64(i64::MAX) // saturating
    );
    assert_eq!(
      streaminfo_unpack_h_star(&TagValue::Bytes(vec![
        0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42,
        0x7e,
      ])),
      TagValue::Str("d41d8cd98f00b204e9800998ecf8427e".into())
    );
  }

  // ---------- §2/§3 convention surface -----------------------------------

  #[test]
  fn vorbis_item_predicates_and_newtype_payload_accessors() {
    // §2: every variant is unit/newtype with is_* predicates + unwrap.
    let vendor = VorbisItem::Vendor(Cow::Borrowed("libFLAC"));
    assert!(vendor.is_vendor());
    assert_eq!(vendor.unwrap_vendor_ref(), "libFLAC");

    let named = VorbisItem::Named(VorbisNamed::new("Artist", Cow::Borrowed("Alice"), true));
    assert!(named.is_named());
    let n = named.unwrap_named_ref();
    assert_eq!(n.name(), "Artist");
    assert_eq!(n.value(), "Alice");
    assert!(n.is_listable());

    let auto = VorbisItem::Auto(VorbisAuto::new("FooBar".into(), Cow::Borrowed("42")));
    assert!(auto.is_auto());
    let a = auto.unwrap_auto_ref();
    assert_eq!(a.name(), "FooBar");
    assert_eq!(a.value(), "42");

    let cover = VorbisItem::CoverArt(vec![1, 2, 3]);
    assert!(cover.is_cover_art());
    assert!(named.try_unwrap_cover_art_ref().is_err());
  }
  // ---------- Golden-pattern `Taggable` / `Project` ----------------------

  /// `Taggable::tags(-j)` yields the StreamInfo set (no PrintConv) through
  /// `run_emission`: SampleRate/Channels/BitsPerSample/TotalSamples are raw
  /// numerics, MD5Signature is the lowercase-hex string.
  #[test]
  fn taggable_emits_streaminfo_print_conv() {
    let data = fixture("FLAC.flac");
    let mut shared = crate::format_parser::SharedFlags::new();
    let meta = parse_borrowed(&data, &mut shared).unwrap();
    let mut w = TagMap::new();
    crate::emit::run_emission(
      &meta,
      crate::emit::EmitOptions::g1(ConvMode::PrintConv, false),
      &mut w,
    );
    assert_eq!(w.get_str("FLAC", "SampleRate"), Some("8000".to_string()));
    assert_eq!(w.get_str("FLAC", "Channels"), Some("2".to_string()));
    assert_eq!(w.get_str("FLAC", "BitsPerSample"), Some("8".to_string()));
    assert_eq!(w.get_str("FLAC", "TotalSamples"), Some("0".to_string()));
    assert_eq!(
      w.get_str("FLAC", "MD5Signature"),
      Some("d41d8cd98f00b204e9800998ecf8427e".to_string())
    );
    // A single (non-listable) Vorbis field stays a plain scalar.
    assert_eq!(
      w.get_str("Vorbis", "Title"),
      Some("ExifTool test".to_string())
    );
    assert_eq!(
      w.get_str("Vorbis", "Vendor"),
      Some("reference libFLAC 1.1.2 20050205".to_string())
    );
  }

  /// `Taggable::tags` reproduces the Vorbis `List => 1` coalesce as ONE
  /// `EmittedTag` carrying a `TagValue::List` (multi-artist fixture), driven
  /// through `run_emission` — the `-n` value is identical (no PrintConv on
  /// Vorbis fields).
  #[test]
  fn taggable_emits_vorbis_multi_artist_list() {
    let data = fixture("FLAC_multi_artist.flac");
    let mut shared = crate::format_parser::SharedFlags::new();
    let meta = parse_borrowed(&data, &mut shared).unwrap();
    for mode in [ConvMode::PrintConv, ConvMode::ValueConv] {
      let mut w = TagMap::new();
      crate::emit::run_emission(&meta, crate::emit::EmitOptions::g1(mode, false), &mut w);
      match w.get("Vorbis", "Artist") {
        Some(TagValue::List(items)) => {
          assert_eq!(items.len(), 2, "mode={mode:?}");
          assert!(matches!(&items[0], TagValue::Str(s) if s == "Alice"));
          assert!(matches!(&items[1], TagValue::Str(s) if s == "Bob"));
        }
        other => panic!("expected coalesced Artist List, got {other:?} (mode={mode:?})"),
      }
    }
  }

  /// `Taggable::tags(-j)` renders the Picture block: PictureType resolves via
  /// the PrintConv hash ("Front Cover"), and the Picture binary is a
  /// `TagValue::Bytes`. `-n` emits the raw numeric PictureType.
  #[test]
  fn taggable_emits_picture_tags() {
    let data = fixture("FLAC_picture.flac");
    let mut shared = crate::format_parser::SharedFlags::new();
    let meta = parse_borrowed(&data, &mut shared).unwrap();
    // -j: PrintConv name + binary bytes.
    let mut w = TagMap::new();
    crate::emit::run_emission(
      &meta,
      crate::emit::EmitOptions::g1(ConvMode::PrintConv, false),
      &mut w,
    );
    assert_eq!(
      w.get_str("FLAC", "PictureType"),
      Some("Front Cover".to_string())
    );
    assert!(matches!(w.get("FLAC", "Picture"), Some(TagValue::Bytes(_))));
    // -n: raw numeric PictureType (3 = Front Cover).
    let mut wn = TagMap::new();
    crate::emit::run_emission(
      &meta,
      crate::emit::EmitOptions::g1(ConvMode::ValueConv, false),
      &mut wn,
    );
    assert_eq!(wn.get_str("FLAC", "PictureType"), Some("3".to_string()));
  }

  /// Group identity: StreamInfo + Picture tags carry family-0/1 `"FLAC"`,
  /// Vorbis comments `"Vorbis"`, and `Composite:Duration` `"Composite"`
  /// (each sub-table group0 == group1). Every tag is known ⇒ `!unknown`.
  #[test]
  fn taggable_group_family0_and_family1_per_subtable() {
    let data = fixture("FLAC_duration.flac");
    let mut shared = crate::format_parser::SharedFlags::new();
    let meta = parse_borrowed(&data, &mut shared).unwrap();
    let tags: Vec<_> = meta
      .tags(crate::emit::EmitOptions::g1(ConvMode::PrintConv, false))
      .collect();
    assert!(!tags.is_empty());
    let mut saw_flac = false;
    let mut saw_vorbis = false;
    let mut saw_composite = false;
    for t in &tags {
      let g = t.tag().group_ref();
      // family-0 always equals family-1 across FLAC's sub-tables.
      assert_eq!(g.family0(), g.family1(), "tag {}", t.tag().name());
      assert!(!t.unknown());
      match g.family1() {
        "FLAC" => saw_flac = true,
        "Vorbis" => saw_vorbis = true,
        "Composite" => saw_composite = true,
        other => panic!("unexpected FLAC group {other:?} for {}", t.tag().name()),
      }
    }
    assert!(saw_flac, "StreamInfo FLAC:* tags present");
    assert!(saw_vorbis, "Vorbis:* tags present");
    assert!(saw_composite, "Composite:Duration present");
  }

  /// `Composite:Duration` (FLAC.pm:137-149): `-j` is `ConvertDuration`
  /// ("0:00:30"), `-n` is the raw f64 (30.0).
  #[test]
  fn taggable_emits_composite_duration() {
    let data = fixture("FLAC_duration.flac");
    let mut shared = crate::format_parser::SharedFlags::new();
    let meta = parse_borrowed(&data, &mut shared).unwrap();
    let mut w = TagMap::new();
    crate::emit::run_emission(
      &meta,
      crate::emit::EmitOptions::g1(ConvMode::PrintConv, false),
      &mut w,
    );
    assert_eq!(
      w.get_str("Composite", "Duration"),
      Some("0:00:30".to_string())
    );
    let mut wn = TagMap::new();
    crate::emit::run_emission(
      &meta,
      crate::emit::EmitOptions::g1(ConvMode::ValueConv, false),
      &mut wn,
    );
    assert!(matches!(wn.get("Composite", "Duration"), Some(TagValue::F64(x)) if *x == 30.0));
  }

  /// An ID3-prefixed FLAC (the `FLAC_id3_prefix.flac` fixture) splices the
  /// chained ID3 tags FIRST inside `tags()` — proving the `id3.tags(mode)`
  /// position matches the retired `id3.serialize_tags` call site (BEFORE the
  /// FLAC body). `File:ID3Size` precedes `FLAC:SampleRate`.
  #[test]
  #[cfg(feature = "id3")]
  fn taggable_chains_id3_before_flac_body() {
    let data = fixture("FLAC_id3_prefix.flac");
    let mut shared = crate::format_parser::SharedFlags::new();
    let meta = parse_borrowed(&data, &mut shared).unwrap();
    assert!(meta.id3_ref().is_some(), "fixture carries an ID3v2 prefix");
    let names: Vec<String> = meta
      .tags(crate::emit::EmitOptions::g1(ConvMode::PrintConv, false))
      .map(|t| std::format!("{}:{}", t.tag().group_ref().family1(), t.tag().name()))
      .collect();
    let id3_pos = names
      .iter()
      .position(|n| n.starts_with("ID3v2") || n == "File:ID3Size")
      .expect("an ID3 tag is spliced");
    let flac_pos = names
      .iter()
      .position(|n| n == "FLAC:SampleRate")
      .expect("FLAC:SampleRate emitted");
    assert!(
      id3_pos < flac_pos,
      "ID3 tags must precede the FLAC body (id3_pos={id3_pos}, flac_pos={flac_pos}): {names:?}"
    );
    // Driven through the engine arm, both the ID3 prefix and the FLAC body land.
    let mut w = TagMap::new();
    emit_via_engine(&meta, true, &mut w);
    assert_eq!(w.get_str("FLAC", "SampleRate"), Some("8000".to_string()));
    assert!(
      w.entries()
        .iter()
        .any(|(_, _, g, n, _, _)| g.starts_with("ID3v2") || (g == "File" && n == "ID3Size")),
      "ID3 tags present in the engine output"
    );
  }

  /// `Project` reports FLAC as audio-only (one `TrackKind::Audio`) and folds
  /// the FLAC.pm:137-149 `Composite:Duration` (`TotalSamples / SampleRate`)
  /// into `MediaInfo`. No camera / lens / GPS / capture / dimensions.
  #[test]
  fn project_is_audio_with_duration() {
    use crate::metadata::{Project, TrackKind};
    let data = fixture("FLAC_duration.flac");
    let mut shared = crate::format_parser::SharedFlags::new();
    let meta = parse_borrowed(&data, &mut shared).unwrap();
    let md = Project::project(&meta);
    assert_eq!(md.media().track_kinds(), &[TrackKind::Audio]);
    assert_eq!(md.media().duration(), Some(Duration::from_secs(30)));
    assert!(md.media().width().is_none());
    assert!(md.media().height().is_none());
    assert!(md.camera().is_none());
    assert!(md.lens().is_none());
    assert!(md.gps().is_none());
    assert!(md.capture().is_none());
  }

  /// `Project` on a FLAC with no usable `TotalSamples`/`SampleRate` leaves
  /// duration `None` (still audio-only) — matches [`Meta::duration`].
  #[test]
  fn project_no_duration_when_streaminfo_lacks_samples() {
    use crate::metadata::{Project, TrackKind};
    // FLAC.flac has TotalSamples == 0 ⇒ duration() is None.
    let data = fixture("FLAC.flac");
    let mut shared = crate::format_parser::SharedFlags::new();
    let meta = parse_borrowed(&data, &mut shared).unwrap();
    assert!(meta.duration().is_none());
    let md = Project::project(&meta);
    assert_eq!(md.media().track_kinds(), &[TrackKind::Audio]);
    assert!(md.media().duration().is_none());
  }
}
