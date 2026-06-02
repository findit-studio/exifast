// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "ogg")]
//! Faithful port of `Image::ExifTool::Ogg` (`lib/Image/ExifTool/Ogg.pm`)
//! — Ogg container framing + inline Vorbis-comment block (vendor +
//! N KEY=VALUE comments) extraction. The Vorbis-comment block is shared
//! by all three codec wrappers (Vorbis::Comments per-Vorbis.pm:154-210,
//! Theora::Comments delegating per-Theora.pm:32-37, Opus::Tags delegating
//! per-Opus.pm:32).
//!
//! The container parser (`ProcessOGG`, Ogg.pm:75-197) walks pages until
//! it has accumulated each stream's leading packets, then dispatches the
//! packet to its codec's comments handler.
//!
//! A typed [`Meta<'a>`] is produced by the
//! [`crate::format_parser::FormatParser`] trait; the engine entry `process`
//! re-emits through the `Metadata` push path (list-aware for Vorbis
//! Artist/Performer/Contact) so the serialized JSON stays byte-exact with
//! bundled `perl exiftool`.
//!
//! ## Deliberate Phase-2 deferrals (see `docs/superpowers/plans/`):
//! - **`%Image::ExifTool::Theora::Identification` (Theora.pm:42-104)** —
//!   Theora is a video codec with a larger binary table (rational pixel
//!   aspect / framerate / colourspace) and no Theora corpus fixture
//!   exists in the suite. Queued for the dedicated Theora.pm PR. The
//!   `OverrideFileType('OGV')` call (Ogg.pm:49) DOES fire when a Theora
//!   packet is seen, even with the table deferred. (R2 F-OGG-TRIM
//!   re-landed Vorbis::Identification + Opus::Header here; only
//!   Theora::Identification remains deferred.)
//! - **FLAC-in-Ogg transport** (Ogg.pm:176-179, 190-195): the `\x7fFLAC`
//!   packet arm that delegates to `Image::ExifTool::FLAC::ProcessFLAC`
//!   is deferred until the FLAC port lands (row 8). A `\x7fFLAC`-magic
//!   packet is silently ignored here.
//! - **ID3 wrapper** (Ogg.pm:79-83): leading/trailing-ID3 detection
//!   delegates to `Image::ExifTool::ID3::ProcessID3`. Deferred until the
//!   ID3 port (row 2) lands.
//! - **`Composite:Duration`** (Vorbis.pm:138-147): requires both the
//!   Composite engine + a `File:FileSize` source — deferred to a Stage-2
//!   Composite-infrastructure PR.
//! - **`Vorbis::Comments` → `METADATA_BLOCK_PICTURE` SubDirectory hop to
//!   `FLAC::Picture`** (Vorbis.pm:122-134): the engine has no
//!   SubDirectory-from-tag plumbing. The base64-decode RawConv still
//!   fires (raw bytes), which serializes as the `(Binary data N bytes,
//!   use -b option to extract)` placeholder, identical to `COVERART`
//!   downstream.

// Golden-v2 Contract 3c (Phase C, slice B / w2b): panic-safety by construction —
// every raw index/slice is converted to a checked `.get()` form below.
#![deny(clippy::indexing_slicing)]

use crate::{
  convert::{apply, base64_decode},
  format_parser::{FormatParser, parser_sealed},
  tagtable::{PrintConv, TagDef, ValueConv},
  value::{Group, Metadata, TagValue},
};
use smol_str::SmolStr;
use std::collections::HashMap;

// ===========================================================================
// Constants from Ogg.pm
// ===========================================================================

/// `$MAX_PACKETS = 2` (Ogg.pm:22) — maximum packets to scan from each
/// stream at start of file.
const MAX_PACKETS: u32 = 2;

// ===========================================================================
// Codec-specific identification-header tables — STATUS
// ===========================================================================
//
// R2 F-OGG-TRIM (this commit): Vorbis::Identification (Vorbis.pm:40-70)
// + Opus::Header (Opus.pm:36-51) are PORTED below — the R1 deferral was
// reverted when round-2 review showed it created new conformance hand-
// trims that violate the 1:1 bar. Theora::Identification (Theora.pm:42-104)
// remains deferred (no fixture; on the dedicated Theora.pm queue).
//
// Signedness audit (D5 — faithfulness to bundled ExifTool, NOT upstream
// codec specs):
//   * Vorbis.pm:53,59,65 declare MaximumBitrate / NominalBitrate /
//     MinimumBitrate as `Format => 'int32u'` (UNSIGNED). The Vorbis I
//     specification describes them as signed 32-bit integers (RFC-style
//     spec text); the port follows ExifTool's unsigned reading.
//   * Opus.pm:48 declares OutputGain as `Format => 'int16u'` (UNSIGNED).
//     RFC 7845 §5.1 specifies a signed 16-bit LE field (Q7.8 fixed-point
//     dB gain); the port follows ExifTool's unsigned reading.
//   * Theora.pm (deferred) uses only `int8u` / `int16u` / `int32u` /
//     `int8u[3]` / `int16u[3]` / `rational64u`; no signedness mismatch
//     vs the Theora spec to audit when that PR lands.
//
// The `OverrideFileType('OGV')` / `OverrideFileType('OPUS')` calls
// (Ogg.pm:49-50) live in `process_packet` — file-type override fires
// whenever the corresponding header packet is seen.

// ===========================================================================
// Vorbis::Comments — faithful %Vorbis::Comments (Vorbis.pm:72-135)
//
// Tag IDs are STRING keys (the uppercased Vorbis comment KEY). Each entry is
// the rename hint (`Name => '...'`) + optional Groups/List/RawConv. The
// dynamic-add path (Vorbis.pm:189-196) covers unknown keys: we resolve them
// at parse time via [`vorbis_comment_compute_name`].
// ===========================================================================

fn coverart_valueconv(v: &TagValue) -> TagValue {
  // Vorbis.pm:101-104 `ValueConv => 'require XMP; XMP::DecodeBase64($val)'`.
  // The result is raw bytes; the serializer renders as the binary
  // placeholder.
  match v {
    TagValue::Str(s) => TagValue::Bytes(base64_decode(s)),
    other => other.clone(),
  }
}

fn metadata_block_picture_valueconv(v: &TagValue) -> TagValue {
  // Vorbis.pm:122-134 `Binary => 1, RawConv => 'XMP::DecodeBase64($val)'`.
  // The RawConv decodes base64 to raw bytes; the SubDirectory hop to
  // `FLAC::Picture` (Vorbis.pm:130-133) then parses the resulting payload.
  // R3 F2: the SubDirectory hop is now intercepted by
  // `process_vorbis_comments` BEFORE this ValueConv runs (see the
  // `METADATA_BLOCK_PICTURE` branch in that function), so the decoded
  // bytes are parsed into an `OggPicture` and emitted as `FLAC:Picture*`
  // fields. This ValueConv is kept as the fallback for any future call
  // site that bypasses the comments-level intercept; today it's
  // unreachable.
  coverart_valueconv(v)
}

// Vorbis.pm:80 `vendor => { Notes => 'from comment header' }`
static VC_VENDOR: TagDef = TagDef::new("Vendor", "Vorbis", ValueConv::None, PrintConv::None);
// Vorbis.pm:81 TITLE
static VC_TITLE: TagDef = TagDef::new("Title", "Vorbis", ValueConv::None, PrintConv::None);
// Vorbis.pm:82 VERSION
static VC_VERSION: TagDef = TagDef::new("Version", "Vorbis", ValueConv::None, PrintConv::None);
// Vorbis.pm:83 ALBUM
static VC_ALBUM: TagDef = TagDef::new("Album", "Vorbis", ValueConv::None, PrintConv::None);
// Vorbis.pm:84 TRACKNUMBER -> TrackNumber
static VC_TRACK_NUMBER: TagDef =
  TagDef::new("TrackNumber", "Vorbis", ValueConv::None, PrintConv::None);
// Vorbis.pm:85 ARTIST => List=>1
// R1-F2: `.with_list(true)` opts into `Metadata::push_listable` semantics —
// repeated ARTIST occurrences accumulate into a single `TagValue::List`
// at first-occurrence position (faithful ExifTool.pm:9505-9520 FoundTag),
// matching the FLAC Vorbis-comment path. Previously a HashMap-accumulator
// + sorted-key flush produced alphabetical (not first-occurrence) emission
// order — see the `ogg_vorbis_interleaved_list_conformance` test.
static VC_ARTIST: TagDef =
  TagDef::new("Artist", "Vorbis", ValueConv::None, PrintConv::None).with_list(true);
// Vorbis.pm:86 PERFORMER => List=>1
static VC_PERFORMER: TagDef =
  TagDef::new("Performer", "Vorbis", ValueConv::None, PrintConv::None).with_list(true);
// Vorbis.pm:87 COPYRIGHT
static VC_COPYRIGHT: TagDef = TagDef::new("Copyright", "Vorbis", ValueConv::None, PrintConv::None);
// Vorbis.pm:88 LICENSE
static VC_LICENSE: TagDef = TagDef::new("License", "Vorbis", ValueConv::None, PrintConv::None);
// Vorbis.pm:89 ORGANIZATION
static VC_ORGANIZATION: TagDef =
  TagDef::new("Organization", "Vorbis", ValueConv::None, PrintConv::None);
// Vorbis.pm:90 DESCRIPTION
static VC_DESCRIPTION: TagDef =
  TagDef::new("Description", "Vorbis", ValueConv::None, PrintConv::None);
// Vorbis.pm:91 GENRE
static VC_GENRE: TagDef = TagDef::new("Genre", "Vorbis", ValueConv::None, PrintConv::None);
// Vorbis.pm:92 DATE
static VC_DATE: TagDef = TagDef::new("Date", "Vorbis", ValueConv::None, PrintConv::None);
// Vorbis.pm:93 LOCATION
static VC_LOCATION: TagDef = TagDef::new("Location", "Vorbis", ValueConv::None, PrintConv::None);
// Vorbis.pm:94 CONTACT => List=>1
static VC_CONTACT: TagDef =
  TagDef::new("Contact", "Vorbis", ValueConv::None, PrintConv::None).with_list(true);
// Vorbis.pm:95 ISRC => Name 'ISRCNumber'
static VC_ISRC: TagDef = TagDef::new("ISRCNumber", "Vorbis", ValueConv::None, PrintConv::None);
// Vorbis.pm:96 COVERARTMIME => CoverArtMIMEType
static VC_COVERART_MIME: TagDef = TagDef::new(
  "CoverArtMIMEType",
  "Vorbis",
  ValueConv::None,
  PrintConv::None,
);
// Vorbis.pm:97-105 COVERART => CoverArt (base64 -> bytes)
static VC_COVERART: TagDef = TagDef::new(
  "CoverArt",
  "Vorbis",
  ValueConv::Func(coverart_valueconv),
  PrintConv::None,
);
// Vorbis.pm:106-109 REPLAYGAIN_*
static VC_REPLAYGAIN_TRACK_PEAK: TagDef = TagDef::new(
  "ReplayGainTrackPeak",
  "Vorbis",
  ValueConv::None,
  PrintConv::None,
);
static VC_REPLAYGAIN_TRACK_GAIN: TagDef = TagDef::new(
  "ReplayGainTrackGain",
  "Vorbis",
  ValueConv::None,
  PrintConv::None,
);
static VC_REPLAYGAIN_ALBUM_PEAK: TagDef = TagDef::new(
  "ReplayGainAlbumPeak",
  "Vorbis",
  ValueConv::None,
  PrintConv::None,
);
static VC_REPLAYGAIN_ALBUM_GAIN: TagDef = TagDef::new(
  "ReplayGainAlbumGain",
  "Vorbis",
  ValueConv::None,
  PrintConv::None,
);
// Vorbis.pm:111-113 ENCODED_USING / ENCODED_BY / COMMENT
static VC_ENCODED_USING: TagDef =
  TagDef::new("EncodedUsing", "Vorbis", ValueConv::None, PrintConv::None);
static VC_ENCODED_BY: TagDef = TagDef::new("EncodedBy", "Vorbis", ValueConv::None, PrintConv::None);
static VC_COMMENT: TagDef = TagDef::new("Comment", "Vorbis", ValueConv::None, PrintConv::None);
// Vorbis.pm:115-118 DIRECTOR / PRODUCER / COMPOSER / ACTOR (Theora docs)
static VC_DIRECTOR: TagDef = TagDef::new("Director", "Vorbis", ValueConv::None, PrintConv::None);
static VC_PRODUCER: TagDef = TagDef::new("Producer", "Vorbis", ValueConv::None, PrintConv::None);
static VC_COMPOSER: TagDef = TagDef::new("Composer", "Vorbis", ValueConv::None, PrintConv::None);
static VC_ACTOR: TagDef = TagDef::new("Actor", "Vorbis", ValueConv::None, PrintConv::None);
// Vorbis.pm:120-121 ENCODER / ENCODER_OPTIONS (Opus)
static VC_ENCODER: TagDef = TagDef::new("Encoder", "Vorbis", ValueConv::None, PrintConv::None);
static VC_ENCODER_OPTIONS: TagDef =
  TagDef::new("EncoderOptions", "Vorbis", ValueConv::None, PrintConv::None);
// Vorbis.pm:122-134 METADATA_BLOCK_PICTURE
static VC_METADATA_BLOCK_PICTURE: TagDef = TagDef::new(
  "Picture",
  "Vorbis",
  ValueConv::Func(metadata_block_picture_valueconv),
  PrintConv::None,
);

/// Resolve a known `%Vorbis::Comments` KEY to its `&'static TagDef`, OR
/// `None` if it must go through the dynamic-add path
/// (Vorbis.pm:189-196).
fn vorbis_comment_known(key: &str) -> Option<&'static TagDef> {
  Some(match key {
    "vendor" => &VC_VENDOR,
    "TITLE" => &VC_TITLE,
    "VERSION" => &VC_VERSION,
    "ALBUM" => &VC_ALBUM,
    "TRACKNUMBER" => &VC_TRACK_NUMBER,
    "ARTIST" => &VC_ARTIST,
    "PERFORMER" => &VC_PERFORMER,
    "COPYRIGHT" => &VC_COPYRIGHT,
    "LICENSE" => &VC_LICENSE,
    "ORGANIZATION" => &VC_ORGANIZATION,
    "DESCRIPTION" => &VC_DESCRIPTION,
    "GENRE" => &VC_GENRE,
    "DATE" => &VC_DATE,
    "LOCATION" => &VC_LOCATION,
    "CONTACT" => &VC_CONTACT,
    "ISRC" => &VC_ISRC,
    "COVERARTMIME" => &VC_COVERART_MIME,
    "COVERART" => &VC_COVERART,
    "REPLAYGAIN_TRACK_PEAK" => &VC_REPLAYGAIN_TRACK_PEAK,
    "REPLAYGAIN_TRACK_GAIN" => &VC_REPLAYGAIN_TRACK_GAIN,
    "REPLAYGAIN_ALBUM_PEAK" => &VC_REPLAYGAIN_ALBUM_PEAK,
    "REPLAYGAIN_ALBUM_GAIN" => &VC_REPLAYGAIN_ALBUM_GAIN,
    "ENCODED_USING" => &VC_ENCODED_USING,
    "ENCODED_BY" => &VC_ENCODED_BY,
    "COMMENT" => &VC_COMMENT,
    "DIRECTOR" => &VC_DIRECTOR,
    "PRODUCER" => &VC_PRODUCER,
    "COMPOSER" => &VC_COMPOSER,
    "ACTOR" => &VC_ACTOR,
    "ENCODER" => &VC_ENCODER,
    "ENCODER_OPTIONS" => &VC_ENCODER_OPTIONS,
    "METADATA_BLOCK_PICTURE" => &VC_METADATA_BLOCK_PICTURE,
    _ => return None,
  })
}

/// Faithful name-synthesis for an unknown Vorbis comment KEY
/// (Vorbis.pm:189-196):
///
/// ```text
/// my $name = ucfirst(lc($tag));
/// $name =~ s/[^\w-]+(.?)/\U$1/sg;          # strip non-word, uppercase next
/// $name =~ s/([a-z0-9])_([a-z])/$1\U$2/g;  # underscore -> camelCase
/// ```
///
/// `\w` in Perl is `[A-Za-z0-9_]`.
fn vorbis_comment_compute_name(tag: &str) -> String {
  // ucfirst(lc(...))
  let lower: String = tag.chars().flat_map(|c| c.to_lowercase()).collect();
  let mut chars = lower.chars();
  let mut name = match chars.next() {
    None => String::new(),
    Some(first) => {
      let mut s = String::with_capacity(lower.len());
      for upper_first in first.to_uppercase() {
        s.push(upper_first);
      }
      s.extend(chars);
      s
    }
  };
  // `s/[^\w-]+(.?)/\U$1/sg` — repeatedly strip runs of non-word, non-`-`
  // chars; uppercase the (optional) following character. `(.?)` matches 0
  // or 1 char.
  name = strip_non_word_and_uppercase_next(&name);
  // `s/([a-z0-9])_([a-z])/$1\U$2/g` — replace `<lower-or-digit>_<lower>`
  // with `<same>` + uppercase next char. Iterates left-to-right; ExifTool
  // uses `/g` which is a non-overlapping global, so an overlap like
  // `a_b_c` matches `a_b` (replaces to `aB`, leaves `_c`), then continues
  // scanning past the replacement (advances past `aB`), so `B_c` is the
  // next candidate (B is uppercase ⇒ no further match).
  name = underscore_camelcase(&name);
  name
}

fn strip_non_word_and_uppercase_next(s: &str) -> String {
  fn is_word_or_dash(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
  }
  let mut out = String::with_capacity(s.len());
  let mut chars = s.chars().peekable();
  while let Some(c) = chars.next() {
    if is_word_or_dash(c) {
      out.push(c);
      continue;
    }
    // Consume the run of non-word characters.
    while let Some(&nxt) = chars.peek() {
      if is_word_or_dash(nxt) {
        break;
      }
      chars.next();
    }
    // `(.?)` — optionally consume one following char and uppercase it.
    if let Some(next) = chars.next() {
      for u in next.to_uppercase() {
        out.push(u);
      }
    }
  }
  out
}

fn underscore_camelcase(s: &str) -> String {
  // Faithful port of Perl `s/([a-z0-9])_([a-z])/$1\U$2/g` (Vorbis.pm:193).
  //
  // Perl `s///g` semantics: each successful match mutates the string and
  // the regex engine's `pos()` cursor advances past the END of the
  // replacement. The next match attempt starts from the post-replacement
  // cursor — so when `c_d` becomes `cD`, the cursor sits on `D`, and the
  // next character checked for `[a-z0-9]` is `D` (now UPPERCASE), which
  // does NOT match `[a-z0-9]`. This is why
  //   `abc_def_g_h` => `abcDefG_h` (the trailing `_h` is preserved
  //   because `G` is uppercase after the prior replacement).
  //
  // The previous implementation walked the ORIGINAL input and tested
  // `bytes[i-1]` against the ORIGINAL lowercase character — which still
  // matched after the replacement should have already capitalised it,
  // diverging from Perl on every multi-underscore chain that touches a
  // single-letter segment (`abc_def_g_h` => `abcDefGH`, `A_b_c_d` =>
  // `A_bCD` vs Perl's `A_bC_d`). Codex round-3 F2 caught this; the new
  // cursor-over-MUTATED-output semantics restore byte-exact match with
  // bundled Perl. See conformance fixture
  // `synthetic_vorbis_specialkeys.ogg` for the empirical pin.
  let bytes: Vec<char> = s.chars().collect();
  let mut out: Vec<char> = Vec::with_capacity(bytes.len());
  let mut i = 0usize;
  // Checked-indexing (Phase C w2b): `bytes.get(i)` is `Some` exactly when the
  // old `i < bytes.len()` + `bytes[i]` pair was in range ⇒ byte-identical.
  while let Some(&c) = bytes.get(i) {
    // The predicate uses `out.last()` — the most-recently-pushed char,
    // which reflects the mutated-output state (so a just-uppercased `B`
    // does NOT satisfy the `[a-z0-9]` precondition for the next `_`).
    let prev_lower_or_digit = out
      .last()
      .map(|&p| p.is_ascii_lowercase() || p.is_ascii_digit())
      .unwrap_or(false);
    // `next` is the `bytes[i + 1]` char (if any); `next_lower` reuses it so
    // the uppercase-into-output step below needs no second raw index.
    let next = bytes.get(i + 1).copied();
    let next_lower = next.is_some_and(|n| n.is_ascii_lowercase());
    if c == '_' && prev_lower_or_digit && next_lower {
      // Drop the underscore and uppercase the next char into the output.
      // `next_lower` guarantees `next` is `Some` here ⇒ byte-identical to the
      // previous `bytes[i + 1].to_uppercase()`.
      if let Some(n) = next {
        for u in n.to_uppercase() {
          out.push(u);
        }
      }
      i += 2;
    } else {
      out.push(c);
      i += 1;
    }
  }
  out.into_iter().collect()
}

// ===========================================================================
// Vorbis::Identification + Opus::Header binary tables
//
// R2 F-OGG-TRIM: the codec-identification binary tables are IN SCOPE for
// this PR after all — round-2 review showed the R1 deferral was creating
// new conformance hand-trims (`-x Vorbis:VorbisVersion -x Vorbis:AudioChannels
// -x Vorbis:SampleRate -x Vorbis:NominalBitrate ...` and `-x Opus:*`) and
// the trims violated the "no hand-trims beyond the formally-accepted-
// deferral list" 1:1 bar. The tables are bounded (a handful of fixed-offset
// fields per codec); they're now ported here directly so the goldens can
// be regenerated UNTRIMMED.
//
// Theora::Identification (Theora.pm:42-104) stays deferred — Theora is a
// VIDEO format whose tags carry the `Theora` group, no in-scope Ogg-Theora
// fixture exists, and the bundled fixture for `OverrideFileType('OGV')`
// would need a real .ogv corpus. Theora is on the queue for the dedicated
// Theora.pm PR; the `OverrideFileType('OGV')` retains for any `\x80theora`
// / `\x81theora` packet seen (Ogg.pm:49).
//
// Faithful Perl reference for the in-scope tables:
//
// %Image::ExifTool::Vorbis::Identification (Vorbis.pm:40-70):
//   0  => VorbisVersion (int32u)
//   4  => AudioChannels (int8u — default Format unless declared)
//   5  => SampleRate (int32u)
//   9  => MaximumBitrate (int32u; RawConv '$val || undef'; PrintConv ConvertBitrate)
//  13  => NominalBitrate (int32u; RawConv '$val || undef'; PrintConv ConvertBitrate)
//  17  => MinimumBitrate (int32u; RawConv '$val || undef'; PrintConv ConvertBitrate)
//
// %Image::ExifTool::Opus::Header (Opus.pm:36-51):
//   0  => OpusVersion (int8u — default Format)
//   1  => AudioChannels (int8u — default Format)
//   4  => SampleRate (int32u)
//   8  => OutputGain (int16u; ValueConv '10 ** ($val/5120)')
//
// Note 1: Opus.pm:48 declares OutputGain as `Format => 'int16u'` (UNSIGNED);
// RFC 7845 §5.1 specifies a signed 16-bit field (Q7.8 fixed-point dB gain),
// but D5 is faithfulness to bundled ExifTool, NOT to upstream codec specs —
// so the port follows Opus.pm and reads unsigned.
// Note 2: Vorbis.pm:53,59,65 declare MaximumBitrate / NominalBitrate /
// MinimumBitrate as `Format => 'int32u'` (UNSIGNED). The Vorbis I
// specification describes them as signed 32-bit integers; ExifTool emits
// the unsigned reading. The port follows ExifTool.
// Note 3: Vorbis identification fields are all LITTLE-ENDIAN
// (`PROCESS_PROC => \&ProcessBinaryData` + no `ByteOrder` override on the
// Identification table; the Vorbis I spec is LE, and Ogg.pm sets `II`
// via `Image::ExifTool::SetByteOrder('II')` at Ogg.pm:101). Opus header
// fields are also LE (RFC 7845 §5.1).
// ===========================================================================

/// Typed Vorbis-identification-packet payload (Vorbis.pm:40-70).
///
/// Holds the six fields the bundled `Vorbis::Identification` ProcessBinaryData
/// table extracts from the `\x01vorbis` packet's 23-byte fixed-offset payload.
/// **Every field is `Option<...>`** because bundled `ProcessBinaryData`
/// (ExifTool.pm:9866-10065) iterates the tag table per-FIELD: each declared
/// offset is independently checked against `$entry >= $size` (line 9927)
/// before extracting the value, so a short payload silently emits the
/// *subset* of fields whose `offset + width <= payload.len()`. Bitrate fields
/// also carry the RawConv `'$val || undef'` drop-zero behaviour
/// (Vorbis.pm:55,61,67).
///
/// Codex R3 F3: pre-fix the helper rejected the WHOLE table on a payload
/// shorter than the largest declared offset (21 bytes), so a 9-byte payload
/// emitted nothing even though bundled would emit VorbisVersion / AudioChannels
/// / SampleRate. The fix is per-field offset-checked extraction with `Option`
/// on every field, faithful to ProcessBinaryData's iterate-and-skip semantics.
///
/// §1: no public fields. §3: accessor returns `Option<primitive>` (the
/// contained primitives are `Copy`) directly, not a reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VorbisIdentification {
  /// `Vorbis:VorbisVersion` (offset 0, int32u). Vorbis.pm:43-46. `None` when
  /// payload shorter than 4 bytes.
  vorbis_version: Option<u32>,
  /// `Vorbis:AudioChannels` (offset 4, int8u). Vorbis.pm:47 — no explicit
  /// Format ⇒ table's default `int8u`. `None` when payload shorter than 5
  /// bytes. Stored as u8 (faithful width).
  audio_channels: Option<u8>,
  /// `Vorbis:SampleRate` (offset 5, int32u). Vorbis.pm:48-51. `None` when
  /// payload shorter than 9 bytes.
  sample_rate: Option<u32>,
  /// `Vorbis:MaximumBitrate` (offset 9, int32u). Vorbis.pm:52-57. `None`
  /// when payload shorter than 13 bytes OR when RawConv `'$val || undef'`
  /// drops the zero value.
  maximum_bitrate: Option<u32>,
  /// `Vorbis:NominalBitrate` (offset 13, int32u). Vorbis.pm:58-63. `None`
  /// when payload shorter than 17 bytes OR when RawConv drops a zero raw.
  nominal_bitrate: Option<u32>,
  /// `Vorbis:MinimumBitrate` (offset 17, int32u). Vorbis.pm:64-69. `None`
  /// when payload shorter than 21 bytes OR when RawConv drops a zero raw.
  minimum_bitrate: Option<u32>,
}

impl VorbisIdentification {
  /// True iff at least one field was successfully populated. The parse
  /// helper [`parse_vorbis_identification`] returns this struct even on a
  /// short payload; the caller uses [`Self::is_empty`] to distinguish a
  /// fully-empty result (faithful: bundled ProcessBinaryData emits zero
  /// tags when the payload doesn't reach offset 0+width).
  #[must_use]
  #[inline(always)]
  pub const fn is_empty(&self) -> bool {
    self.vorbis_version.is_none()
      && self.audio_channels.is_none()
      && self.sample_rate.is_none()
      && self.maximum_bitrate.is_none()
      && self.nominal_bitrate.is_none()
      && self.minimum_bitrate.is_none()
  }
  /// `Vorbis:VorbisVersion` raw value (Vorbis.pm:43-46, int32u), `None`
  /// when the payload was too short to cover offset 0..4 (R3 F3 per-field).
  #[must_use]
  #[inline(always)]
  pub const fn vorbis_version(&self) -> Option<u32> {
    self.vorbis_version
  }
  /// `Vorbis:AudioChannels` raw value (Vorbis.pm:47, int8u), `None` when
  /// the payload was too short to cover offset 4 (R3 F3 per-field).
  #[must_use]
  #[inline(always)]
  pub const fn audio_channels(&self) -> Option<u8> {
    self.audio_channels
  }
  /// `Vorbis:SampleRate` raw value in Hz (Vorbis.pm:48-51, int32u), `None`
  /// when the payload was too short to cover offset 5..9 (R3 F3 per-field).
  #[must_use]
  #[inline(always)]
  pub const fn sample_rate(&self) -> Option<u32> {
    self.sample_rate
  }
  /// `Vorbis:MaximumBitrate` raw bps, `None` when out-of-bounds OR
  /// `bundled-RawConv` would drop the tag (raw == 0). Vorbis.pm:52-57.
  #[must_use]
  #[inline(always)]
  pub const fn maximum_bitrate(&self) -> Option<u32> {
    self.maximum_bitrate
  }
  /// `Vorbis:NominalBitrate` raw bps, `None` when out-of-bounds OR raw == 0.
  /// Vorbis.pm:58-63.
  #[must_use]
  #[inline(always)]
  pub const fn nominal_bitrate(&self) -> Option<u32> {
    self.nominal_bitrate
  }
  /// `Vorbis:MinimumBitrate` raw bps, `None` when out-of-bounds OR raw == 0.
  /// Vorbis.pm:64-69.
  #[must_use]
  #[inline(always)]
  pub const fn minimum_bitrate(&self) -> Option<u32> {
    self.minimum_bitrate
  }
}

/// Parse the Vorbis identification packet's payload (the bytes AFTER the
/// `\x01vorbis` magic) into [`VorbisIdentification`]. **Per-field**
/// offset-checked extraction — faithful to bundled `ProcessBinaryData`
/// (ExifTool.pm:9866-10065), which iterates the table and skips any field
/// whose `entry+width` lies past the payload end (ExifTool.pm:9927 `next if
/// $entry >= $size` and 9953 `last if $more <= 0`).
///
/// Codex R3 F3: pre-fix the helper required `payload.len() >= 21` (the
/// largest declared offset+width); a 9-byte payload would emit NOTHING
/// even though bundled would emit version/channels/sample-rate. Now each
/// field is independently bounds-checked: `[0..4]` for VorbisVersion,
/// `[4..5]` for AudioChannels, `[5..9]` for SampleRate, and `[9..13]`,
/// `[13..17]`, `[17..21]` for the three bitrates.
///
/// Returns `None` ONLY when the payload is so short that NO field is
/// populated (`payload.len() < 4`, so even VorbisVersion can't be read).
/// On a short-but-non-empty payload, returns `Some(VorbisIdentification)`
/// with the in-range fields populated and the out-of-range fields `None`.
fn parse_vorbis_identification(payload: &[u8]) -> Option<VorbisIdentification> {
  // `SetByteOrder('II')` (Ogg.pm:101) — every multi-byte field is LE.
  //
  // Per-field offset+width check (ExifTool.pm:9927 `next if $entry >=
  // $size`): each field is emitted only if its full width fits in the
  // payload. Bundled does NOT all-or-nothing; an 9-byte payload emits
  // VorbisVersion / AudioChannels / SampleRate, then skips the three
  // bitrate fields (offset 9 + 4 = 13 > 9, etc.).
  // Checked-indexing (Phase C w2b): `payload.get(a..b)` is `Some` iff
  // `payload.len() >= b`, which is EXACTLY the old `len >= N` guard for each
  // field, and the 4-byte windows destructure to the same `from_le_bytes`
  // input ⇒ byte-identical. `.get(off..off+4)` likewise mirrors the
  // `len < offset + 4` bitrate guard.
  let le_u32 = |a: usize| -> Option<u32> {
    match payload.get(a..a + 4) {
      Some(&[b0, b1, b2, b3]) => Some(u32::from_le_bytes([b0, b1, b2, b3])),
      _ => None,
    }
  };
  let vorbis_version = le_u32(0);
  let audio_channels = payload.get(4).copied();
  let sample_rate = le_u32(5);
  let read_bitrate = |offset: usize| -> Option<u32> {
    // RawConv `'$val || undef'` — drop zero. Vorbis.pm:55,61,67.
    le_u32(offset).filter(|&raw| raw != 0)
  };
  let id = VorbisIdentification {
    vorbis_version,
    audio_channels,
    sample_rate,
    maximum_bitrate: read_bitrate(9),
    nominal_bitrate: read_bitrate(13),
    minimum_bitrate: read_bitrate(17),
  };
  // `None` ONLY when payload was too short for even VorbisVersion — keeping
  // the call-site `match` shape (the recorder still treats `None` as "no
  // identification packet seen at all").
  if id.is_empty() { None } else { Some(id) }
}

/// Typed Opus-header-packet payload (Opus.pm:36-51).
///
/// Holds the four fields the bundled `Opus::Header` ProcessBinaryData table
/// extracts from the `OpusHead` packet's 19-byte fixed-offset payload.
/// **Every field is `Option<...>`** because bundled `ProcessBinaryData`
/// (ExifTool.pm:9927) iterates the tag table per-FIELD and skips any field
/// whose declared offset is out of bounds — a short payload silently emits
/// only the in-range subset.
///
/// `output_gain` is the POST-ValueConv computed gain (Opus.pm:49
/// `ValueConv => '10 ** ($val/5120)'`); the raw `int16u` is converted at
/// parse time to match the bundled `$val` ValueConv chain.
///
/// Codex R3 F3: pre-fix the helper rejected the WHOLE table on payloads
/// shorter than 10 bytes (the largest offset+width). Per-field offset
/// checks are the fix; faithful to bundled.
///
/// §1: no public fields. §3: accessor returns `Option<primitive>` directly.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct OpusHeader {
  /// `Opus:OpusVersion` (offset 0, int8u). Opus.pm:39. `None` when payload
  /// is empty.
  opus_version: Option<u8>,
  /// `Opus:AudioChannels` (offset 1, int8u). Opus.pm:40. `None` when
  /// payload is shorter than 2 bytes.
  audio_channels: Option<u8>,
  /// `Opus:SampleRate` (offset 4, int32u). Opus.pm:42-45. `None` when
  /// payload is shorter than 8 bytes.
  sample_rate: Option<u32>,
  /// `Opus:OutputGain` post-ValueConv. Opus.pm:46-50 — raw int16u read at
  /// offset 8, then `10 ** ($val/5120)`. Stored as `f64`. `None` when
  /// payload is shorter than 10 bytes.
  output_gain: Option<f64>,
}

impl OpusHeader {
  /// True iff at least one field was successfully populated.
  #[must_use]
  #[inline(always)]
  pub const fn is_empty(&self) -> bool {
    self.opus_version.is_none()
      && self.audio_channels.is_none()
      && self.sample_rate.is_none()
      && self.output_gain.is_none()
  }
  /// `Opus:OpusVersion` raw value (Opus.pm:39, int8u). `None` when out of
  /// bounds (R3 F3 per-field).
  #[must_use]
  #[inline(always)]
  pub const fn opus_version(&self) -> Option<u8> {
    self.opus_version
  }
  /// `Opus:AudioChannels` raw value (Opus.pm:40, int8u). `None` when out
  /// of bounds (R3 F3 per-field).
  #[must_use]
  #[inline(always)]
  pub const fn audio_channels(&self) -> Option<u8> {
    self.audio_channels
  }
  /// `Opus:SampleRate` raw value in Hz (Opus.pm:42-45, int32u). `None`
  /// when out of bounds (R3 F3 per-field).
  #[must_use]
  #[inline(always)]
  pub const fn sample_rate(&self) -> Option<u32> {
    self.sample_rate
  }
  /// `Opus:OutputGain` POST-ValueConv (Opus.pm:46-50: `10 ** ($val/5120)`).
  /// `None` when out of bounds (R3 F3 per-field).
  #[must_use]
  #[inline(always)]
  pub const fn output_gain(&self) -> Option<f64> {
    self.output_gain
  }
}

/// Parse the Opus header packet's payload (the bytes AFTER the `OpusHead`
/// magic) into [`OpusHeader`]. **Per-field** offset-checked extraction —
/// faithful to bundled `ProcessBinaryData` (ExifTool.pm:9927).
///
/// Codex R3 F3: pre-fix the helper required `payload.len() >= 10`. A short
/// payload (e.g. 5 bytes) silently dropped EVERY field even though bundled
/// would emit OpusVersion / AudioChannels / SampleRate when their declared
/// offsets fit.
///
/// Returns `None` ONLY when the payload is empty (no field can be read).
/// On a short payload, returns `Some(OpusHeader)` with the in-range fields
/// populated.
fn parse_opus_header(payload: &[u8]) -> Option<OpusHeader> {
  // Opus header fields are LE (RFC 7845 §5.1; ProcessBinaryData inherits
  // `II` from Ogg.pm:101).
  //
  // Checked-indexing (Phase C w2b): `payload.get(i)` / `payload.get(a..b)` are
  // `Some` iff the old `len >= N` guard held, and the windows destructure to
  // the same `from_le_bytes` inputs ⇒ byte-identical.
  let opus_version = payload.first().copied();
  let audio_channels = payload.get(1).copied();
  // Note: offset 2 is `PreSkip` (int16u), commented out in Opus.pm:41
  // — INTENTIONALLY not ported (commented in bundled ⇒ deliberately not
  // emitted).
  let sample_rate = match payload.get(4..8) {
    Some(&[b0, b1, b2, b3]) => Some(u32::from_le_bytes([b0, b1, b2, b3])),
    _ => None,
  };
  let output_gain = match payload.get(8..10) {
    Some(&[b0, b1]) => {
      let raw_gain = u16::from_le_bytes([b0, b1]);
      // Opus.pm:49 `ValueConv => '10 ** ($val/5120)'`. Raw is int16u in this
      // table; the post-ValueConv value is what bundled emits in both `-j`
      // and `-j -n` (-n shows the post-ValueConv value pre-PrintConv).
      Some(10.0_f64.powf(f64::from(raw_gain) / 5120.0))
    }
    _ => None,
  };
  let header = OpusHeader {
    opus_version,
    audio_channels,
    sample_rate,
    output_gain,
  };
  if header.is_empty() {
    None
  } else {
    Some(header)
  }
}

// ===========================================================================
// OggPicture — owned form of a Vorbis::Comments METADATA_BLOCK_PICTURE
//
// R3 F2 (Codex adversarial). Bundled Vorbis.pm:122-134 defines:
//
//   METADATA_BLOCK_PICTURE => {
//     Name => 'Picture', Binary => 1,
//     RawConv => 'XMP::DecodeBase64($val)',
//     SubDirectory => { TagTable => 'Image::ExifTool::FLAC::Picture',
//                        ByteOrder => 'BigEndian' },
//   };
//
// The base64-decoded payload has the SAME on-wire structure as a FLAC
// METADATA_BLOCK type 6 (PictureType / MIMEType / Description /
// Width / Height / BitsPerPixel / IndexedColors / Length / Picture
// data; FLAC.pm:84-134). Pre-fix the OGG parser stopped at the
// base64 decode and emitted a single `Vorbis:Picture` blob —
// silent loss of every Picture:* sub-field that bundled emits.
//
// Implementation: parse the decoded payload via
// `flac::parse_flac_picture` (same routine FLAC uses for its type-6
// block), then OWN the fields (allocate `String` / `Vec<u8>` so the
// typed Meta doesn't borrow from a temporary base64 buffer). The
// emission path mirrors `flac::sink_picture` but writes directly
// against an `OggPicture` (no lifetime juggling needed).
// ===========================================================================

/// Owned form of a FLAC Picture METADATA_BLOCK, used by the Vorbis
/// `METADATA_BLOCK_PICTURE` SubDirectory hop (Vorbis.pm:122-134). The
/// base64-decoded payload from the Vorbis comment is parsed via
/// [`crate::formats::flac::parse_flac_picture`] (same on-wire layout as
/// FLAC's type-6 metadata block, FLAC.pm:84-134) and the resulting
/// borrowed `Picture<'_>` is cloned into owned fields so the typed
/// `ogg::Meta` doesn't borrow from a temporary base64 buffer.
///
/// **D8 — no public fields, accessors only.** §3 projections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OggPicture {
  /// `FLAC:PictureType` raw int32u (FLAC.pm:88-113 PrintConv hash key).
  picture_type: u32,
  /// `FLAC:PictureMIMEType` (FLAC.pm:115-117, `Format => 'var_pstr32'`),
  /// UTF-8 string. Owned `String` (the base64-decoded buffer is dropped
  /// after parse).
  mime_type: String,
  /// `FLAC:PictureDescription` (FLAC.pm:118-122, UTF-8 var_pstr32).
  description: String,
  /// `FLAC:PictureWidth` (FLAC.pm:123, int32u BE).
  width: u32,
  /// `FLAC:PictureHeight` (FLAC.pm:124, int32u BE).
  height: u32,
  /// `FLAC:PictureBitsPerPixel` (FLAC.pm:125, int32u BE).
  bits_per_pixel: u32,
  /// `FLAC:PictureIndexedColors` (FLAC.pm:126, int32u BE).
  indexed_colors: u32,
  /// `FLAC:PictureLength` (FLAC.pm:127) — DECLARED length, may exceed
  /// `data.len()` on truncation (faithful ExifTool::ReadValue clamp).
  length: u32,
  /// `FLAC:Picture` raw bytes (FLAC.pm:128-133 `Format => 'undef[$val{7}]'`,
  /// clamped to remaining payload). Owned `Vec<u8>`.
  data: Vec<u8>,
}

impl OggPicture {
  /// `FLAC:PictureType` raw code (Copy → by value; §3).
  #[must_use]
  #[inline(always)]
  pub const fn picture_type(&self) -> u32 {
    self.picture_type
  }
  /// Bundled-Perl PrintConv string for [`Self::picture_type`] (e.g.
  /// `"Front Cover"`), `None` for out-of-table codes (raw int emitted
  /// in that case). Reuses the FLAC PrintConv map.
  #[must_use]
  #[inline(always)]
  pub fn picture_type_name(&self) -> Option<&'static str> {
    crate::formats::flac::picture_type_name(self.picture_type)
  }
  /// MIME type, e.g. `"image/png"`. §3 string projection.
  #[must_use]
  #[inline(always)]
  pub fn mime_type(&self) -> &str {
    self.mime_type.as_str()
  }
  /// Description (UTF-8). §3 string projection.
  #[must_use]
  #[inline(always)]
  pub fn description(&self) -> &str {
    self.description.as_str()
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
  /// Indexed-palette colour count, 0 for non-paletted (Copy → by value).
  #[must_use]
  #[inline(always)]
  pub const fn indexed_colors(&self) -> u32 {
    self.indexed_colors
  }
  /// Declared length in bytes (may exceed `data().len()` on truncation;
  /// Copy → by value).
  #[must_use]
  #[inline(always)]
  pub const fn length(&self) -> u32 {
    self.length
  }
  /// Picture binary payload (clamped to remaining bytes per
  /// ExifTool::ReadValue, ExifTool.pm:6290-6298). §3 byte-slice
  /// projection.
  #[must_use]
  #[inline(always)]
  pub fn data(&self) -> &[u8] {
    self.data.as_slice()
  }
}

/// Parse a base64-decoded METADATA_BLOCK_PICTURE payload into an owned
/// [`OggPicture`]. Returns `None` when the on-wire bytes are too truncated
/// to even read PictureType + MIME length (same threshold as
/// [`crate::formats::flac::parse_flac_picture`]).
fn parse_metadata_block_picture(payload: &[u8]) -> Option<OggPicture> {
  // The on-wire layout is identical to FLAC's METADATA_BLOCK type 6, so
  // delegate the binary unpack to the FLAC helper and clone the borrowed
  // fields into owned ones.
  let picture = crate::formats::flac::parse_flac_picture(payload)?;
  Some(OggPicture {
    picture_type: picture.picture_type(),
    mime_type: picture.mime_type().to_string(),
    description: picture.description().to_string(),
    width: picture.width(),
    height: picture.height(),
    bits_per_pixel: picture.bits_per_pixel(),
    indexed_colors: picture.indexed_colors(),
    length: picture.length(),
    data: picture.data().to_vec(),
  })
}

// ===========================================================================
// Vorbis comments — ProcessComments (Vorbis.pm:154-210)
// ===========================================================================

/// Read a u32 little-endian at `pos` in `data`. `pos` is passed by value
/// (NOT a cursor); the caller is responsible for advancing it after a
/// successful read. Returns `None` if `pos + 4 > data.len()`.
fn read_u32_le(data: &[u8], pos: usize) -> Option<u32> {
  // Checked-indexing (Phase C w2b): destructure the `.get(pos..pos+4)?` window
  // (already `Some` with exactly 4 bytes) instead of raw `bytes[0..3]` ⇒
  // byte-identical.
  let &[b0, b1, b2, b3] = data.get(pos..pos + 4)? else {
    return None;
  };
  Some(u32::from_le_bytes([b0, b1, b2, b3]))
}

/// Process a Vorbis-comment block. `data` is the comment-packet payload
/// (after the 7-byte `\x03vorbis` magic for Vorbis, or after the 8-byte
/// `OpusTags` magic for Opus), starting at the vendor-length u32le.
/// `meta` is the staging buffer for Vorbis-comment tags;
/// `picture_sink` accumulates `METADATA_BLOCK_PICTURE` payloads parsed
/// into [`OggPicture`] (R3 F2 — Vorbis.pm:122-134 SubDirectory hop).
fn process_vorbis_comments(
  data: &[u8],
  meta: &mut Metadata,
  picture_sink: &mut Vec<OggPicture>,
  print_conv_enabled: bool,
) -> bool {
  let end = data.len();
  let mut pos = 0usize;
  // Vendor (Vorbis.pm:182-187).
  let Some(vendor_len) = read_u32_le(data, pos) else {
    meta.push_warning("Format error in Vorbis comments");
    return false;
  };
  pos += 4;
  let vendor_len = vendor_len as usize;
  if pos.checked_add(vendor_len).map_or(true, |e| e > end) {
    meta.push_warning("Format error in Vorbis comments");
    return false;
  }
  // Checked-indexing (Phase C w2b): the `pos + vendor_len > end` guard above
  // (`end == data.len()`) makes `data.get(pos..pos + vendor_len)` always
  // `Some` ⇒ `.unwrap_or(&[])` is byte-identical.
  let vendor_bytes = data.get(pos..pos + vendor_len).unwrap_or(&[]);
  pos += vendor_len;
  // Vorbis.pm:184 `$num = ($pos + 4 < $end) ? Get32u($dataPt,$pos) : 0`.
  let num: u32 = if pos + 4 < end {
    let Some(n) = read_u32_le(data, pos) else {
      meta.push_warning("Format error in Vorbis comments");
      return false;
    };
    n
  } else {
    0
  };
  pos += 4;
  // Push the vendor tag (always emitted regardless of num).
  let vendor_str = String::from_utf8_lossy(vendor_bytes).into_owned();
  push_vorbis_comment(
    meta,
    "vendor",
    TagValue::Str(SmolStr::from(vendor_str)),
    print_conv_enabled,
  );
  // R1-F2: List tags (ARTIST, PERFORMER, CONTACT — Vorbis.pm:85,86,94)
  // are routed through `Metadata::push_listable` AT ENCOUNTER TIME — same
  // path FLAC's Vorbis-comment block uses (`src/formats/flac.rs:892`).
  // This makes interleaved comments faithful: bundled ExifTool's
  // `FoundTag` (ExifTool.pm:9505-9520) accumulates a `List => 1` tag in
  // place at the FIRST occurrence's position. A previous HashMap-and-
  // flush implementation sorted keys alphabetically at the end, which
  // worked for `ARTIST` * N alone (alphabetical-of-one) but emitted
  // interleaved (`ARTIST=Alice; TITLE=Song; ARTIST=Bob`) in the wrong
  // order vs bundled. Pinned by `ogg_vorbis_interleaved_list_conformance`.
  // Read `num` comments.
  for _ in 0..num {
    let Some(comment_len) = read_u32_le(data, pos) else {
      meta.push_warning("Format error in Vorbis comments");
      return false;
    };
    let comment_len = comment_len as usize;
    pos += 4;
    if pos.checked_add(comment_len).map_or(true, |e| e > end) {
      meta.push_warning("Format error in Vorbis comments");
      return false;
    }
    // Checked-indexing (Phase C w2b): the `pos + comment_len > end` guard above
    // makes `data.get(pos..pos + comment_len)` always `Some` ⇒ byte-identical.
    let comment_bytes = data.get(pos..pos + comment_len).unwrap_or(&[]);
    pos += comment_len;
    // Split on first `=` (Vorbis.pm:176-177 `m/(.*?)=(.*)/s`).
    let Some(eq_idx) = comment_bytes.iter().position(|&b| b == b'=') else {
      // Malformed comment: Perl `last` exits the loop and emits the warning.
      meta.push_warning("Format error in Vorbis comments");
      return false;
    };
    // `eq_idx` is a `position` index into `comment_bytes`, so `..eq_idx` and
    // `eq_idx + 1..` are always in range ⇒ `.get(..)` is `Some`; byte-identical.
    let raw_key = String::from_utf8_lossy(comment_bytes.get(..eq_idx).unwrap_or(&[])).into_owned();
    let raw_val =
      String::from_utf8_lossy(comment_bytes.get(eq_idx + 1..).unwrap_or(&[])).into_owned();
    // Vorbis.pm:177 `$tag = uc $1`. Perl `uc` on a UTF-8 string upper-cases
    // ASCII letters in-place; non-ASCII is left alone (Perl, without locale
    // pragma, uppercases ASCII only). Vorbis comment keys are ASCII by
    // spec, so `to_ascii_uppercase` is the faithful path.
    let mut key: String = raw_key.to_ascii_uppercase();
    // Vorbis.pm:178-180 `$tag .= '_' if $specialTags{$tag}`. The
    // ExifTool-internal `%specialTags` set (ExifTool.pm:1228-1236) holds
    // 28 names like `NAMESPACE`, `PROCESS_PROC`, `GROUPS`, `AVOID`,
    // `IS_OFFSET`, `PREFERRED`, etc. Several of these (notably
    // `NAMESPACE`, `AVOID`, `NOTES`, `PREFERRED`, `TAG_PREFIX`,
    // `IS_OFFSET`, `LANG_INFO`) are short ASCII tokens that ARE
    // realistically plausible Vorbis-comment keys (Vorbis spec §5
    // permits any ASCII printable except `=`, so this is not "dead in
    // practice" — the collision-protection branch fires whenever
    // anyone tags an Ogg-Vorbis file with one of these keys). Codex
    // round-3 F1 caught the previous stub being incomplete; see
    // `is_special_tag` doc for the full ported hash and the
    // `synthetic_vorbis_specialkeys.ogg` conformance fixture.
    if is_special_tag(&key) {
      key.push('_');
    }
    // R3 F2 (Codex adversarial): `METADATA_BLOCK_PICTURE` is a Vorbis
    // comment KEY whose base64-decoded value carries a FLAC METADATA_BLOCK
    // type-6 (Picture) structure (Vorbis.pm:122-134, SubDirectory →
    // %FLAC::Picture FLAC.pm:84-134). Bundled emits the Picture sub-fields
    // (`FLAC:PictureType`, `:PictureMIMEType`, ...). The pre-fix code
    // base64-decoded the value into a single `Vorbis:Picture` blob —
    // silent loss of every sub-field.
    //
    // Intercept HERE (before push) so the binary payload becomes an
    // `OggPicture` in `picture_sink`, NOT a `Vorbis:Picture` blob in the
    // staging Metadata. Multiple METADATA_BLOCK_PICTURE comments in one
    // file (rare but in-spec) accumulate as separate `OggPicture` entries.
    if key == "METADATA_BLOCK_PICTURE" {
      let decoded = base64_decode(&raw_val);
      if let Some(picture) = parse_metadata_block_picture(&decoded) {
        picture_sink.push(picture);
      } else {
        // Truncated payload — bundled would emit an empty Picture or
        // skip; we choose "skip" to match the typical bundled behaviour
        // for malformed METADATA_BLOCK_PICTURE comments (no error in
        // bundled; the SubDirectory hop fails silently when ReadValue
        // returns undef on the header). No emission, no warning.
      }
      continue;
    }
    push_vorbis_comment(
      meta,
      &key,
      TagValue::Str(SmolStr::from(raw_val)),
      print_conv_enabled,
    );
  }
  // INTENTIONALLY NO trailing-data check here (Codex R2 [medium] disposition).
  //
  // The R2 finding proposed warning when `pos != end` after the comment
  // loop, citing `Vorbis.pm:154-210`. Reading those exact lines and
  // running bundled `perl exiftool` against a hand-built fixture
  // (`tests/fixtures/ogg_vorbis_trailing_garbage.ogg`: vendor + count=0 +
  // 3 trailing bytes) BOTH show no warning is emitted. ExifTool exits
  // `ProcessComments` via `$num-- or return 1` (Vorbis.pm:205) after the
  // Nth (or, when num==0, the vendor-init) iteration, BEFORE the next
  // iteration's `last if $pos+4 > $end` (line 168) can fall through to
  // the warning at line 208. Any bytes after the comment-count boundary
  // are silently ignored. The conformance test
  // `ogg_vorbis_trailing_garbage_conformance` (tests/conformance.rs)
  // pins this byte-exact match against the bundled golden.
  true
}

/// Push a single Vorbis comment. For known keys the resolved name comes
/// from [`vorbis_comment_known`]; for unknown keys the name is computed
/// via [`vorbis_comment_compute_name`]. When the matched `TagDef.list()`
/// is true (Vorbis.pm:85,86,94 — ARTIST, PERFORMER, CONTACT), the push
/// goes through `Metadata::push_listable` so repeats coalesce into a
/// `TagValue::List` AT FIRST-OCCURRENCE POSITION (faithful FoundTag —
/// ExifTool.pm:9505-9520). Identical seam to FLAC's Vorbis-comment path
/// (`src/formats/flac.rs:892`).
fn push_vorbis_comment(meta: &mut Metadata, key: &str, raw: TagValue, print_conv_enabled: bool) {
  if let Some(def) = vorbis_comment_known(key) {
    let out = apply(def, &raw, print_conv_enabled);
    let group = Group::new("Vorbis", def.group1());
    if def.list() {
      meta.push_listable(group, def.name(), out);
    } else {
      meta.push(group, def.name(), out);
    }
  } else {
    // Dynamic-add path (Vorbis.pm:189-196). Unknown keys have no
    // ValueConv/PrintConv (the added tagInfo is `{ Name => $name }`,
    // no List). Plain `push` preserves the first-wins semantics
    // bundled gives any tag without `List => 1`.
    let name = vorbis_comment_compute_name(key);
    meta.push(Group::new("Vorbis", "Vorbis"), SmolStr::from(name), raw);
  }
}

/// Faithful port of `Image::ExifTool::specialTags` (ExifTool.pm:1228-1236).
///
/// ```perl
/// # special tag names (not used for tag info)
/// %specialTags = map { $_ => 1 } qw(
///     TABLE_NAME       SHORT_NAME  PROCESS_PROC  WRITE_PROC  CHECK_PROC
///     GROUPS           FORMAT      FIRST_ENTRY   TAG_PREFIX  PRINT_CONV
///     WRITABLE         TABLE_DESC  NOTES         IS_OFFSET   IS_SUBDIR
///     EXTRACT_UNKNOWN  NAMESPACE   PREFERRED     SRC_TABLE   PRIORITY
///     AVOID            WRITE_GROUP LANG_INFO     VARS        DATAMEMBER
///     SET_GROUP1       PERMANENT   INIT_TABLE
/// );
/// ```
///
/// Used by `Vorbis.pm:178-180`:
///
/// ```perl
/// # Vorbis tag ID's are all capitals, so they may conflict with our
/// # internal tags --> protect against this by adding a trailing
/// # underline if necessary
/// $tag .= '_' if $Image::ExifTool::specialTags{$tag};
/// ```
///
/// Every key the bundled Perl dumps from `%specialTags` is present here
/// (28 keys; verified by `perl -e 'use Image::ExifTool; print
/// join(",", sort keys %Image::ExifTool::specialTags)'` against bundled
/// 13.58). Codex round-3 F1 flagged the previous stub omitting 15 keys
/// (`NAMESPACE`, `AVOID`, `IS_OFFSET`, `LANG_INFO`, `TAG_PREFIX`,
/// `PREFERRED`, `SHORT_NAME`, `TABLE_DESC`, `IS_SUBDIR`,
/// `EXTRACT_UNKNOWN`, `PRINT_CONV`, `SRC_TABLE`, `SET_GROUP1`,
/// `PERMANENT`, `INIT_TABLE`) AND including 3 extras not in Perl
/// (`PARENT`, `DID_TAG_ID`, `ID3`) — both now fixed.
///
/// Conformance fixture `synthetic_vorbis_specialkeys.ogg` exercises
/// `NAMESPACE`, `AVOID`, `IS_OFFSET`, `LANG_INFO`, `TAG_PREFIX`,
/// `PREFERRED`, `NOTES` (all of which collide ⇒ `_` suffix) byte-exact
/// against bundled `perl exiftool`.
fn is_special_tag(key: &str) -> bool {
  matches!(
    key,
    "TABLE_NAME"
      | "SHORT_NAME"
      | "PROCESS_PROC"
      | "WRITE_PROC"
      | "CHECK_PROC"
      | "GROUPS"
      | "FORMAT"
      | "FIRST_ENTRY"
      | "TAG_PREFIX"
      | "PRINT_CONV"
      | "WRITABLE"
      | "TABLE_DESC"
      | "NOTES"
      | "IS_OFFSET"
      | "IS_SUBDIR"
      | "EXTRACT_UNKNOWN"
      | "NAMESPACE"
      | "PREFERRED"
      | "SRC_TABLE"
      | "PRIORITY"
      | "AVOID"
      | "WRITE_GROUP"
      | "LANG_INFO"
      | "VARS"
      | "DATAMEMBER"
      | "SET_GROUP1"
      | "PERMANENT"
      | "INIT_TABLE"
  )
}

// ===========================================================================
// Packet dispatch (Ogg.pm:42-69 `ProcessPacket`)
// ===========================================================================

/// `\x01vorbis` (id), `\x03vorbis` (comments), `\x05vorbis` (setup).
/// Returns the packet-type byte + the codec subtable to dispatch into.
fn classify_packet(buff: &[u8]) -> Option<PacketKind> {
  // Checked-indexing (Phase C w2b): `buff.get(range) == Some(b"…")` folds the
  // old `buff.len() >= N && &buff[range] == …` pairs (the `Some` arm requires
  // the range in bounds, exactly matching the length guard) ⇒ byte-identical.
  // `buff.get(0)` (packet_type) is `Some` whenever the 7-byte magic matched.
  if buff.get(1..7) == Some(&b"vorbis"[..]) {
    return Some(PacketKind::Vorbis {
      packet_type: buff.first().copied().unwrap_or(0),
      payload_start: 7,
    });
  }
  if buff.get(1..7) == Some(&b"theora"[..]) {
    return Some(PacketKind::Theora {
      packet_type: buff.first().copied().unwrap_or(0),
      payload_start: 7,
    });
  }
  if buff.get(..8) == Some(&b"OpusHead"[..]) {
    return Some(PacketKind::Opus {
      kind: OpusKind::Head,
      payload_start: 8,
    });
  }
  if buff.get(..8) == Some(&b"OpusTags"[..]) {
    return Some(PacketKind::Opus {
      kind: OpusKind::Tags,
      payload_start: 8,
    });
  }
  if buff.get(..5) == Some(&b"\x7fFLAC"[..]) {
    // Ogg.pm:176-179. DEFERRED (ogg-flac transport awaits the FLAC port).
    return Some(PacketKind::Flac);
  }
  None
}

enum PacketKind {
  Vorbis {
    packet_type: u8,
    payload_start: usize,
  },
  Theora {
    packet_type: u8,
    payload_start: usize,
  },
  Opus {
    kind: OpusKind,
    payload_start: usize,
  },
  /// `\x7fFLAC` — deferred (FLAC-in-Ogg transport).
  Flac,
}

enum OpusKind {
  Head,
  Tags,
}

/// Per-packet outcome captured during `walk_packet`. Used by [`parse_inner`]
/// to lift the legacy push-style `process_vorbis_comments` emissions into the
/// typed [`Meta`] shape without rewriting the parser internals.
///
/// Comments-processed variants do NOT carry the family-1 group: the staging
/// metadata already records the group on each emitted tag (the
/// `process_vorbis_comments` / `process_vorbis_comments_with_group1`
/// dispatch sets it). The outcome enum only needs to track the
/// override-file-type decision; the per-tag group survives via the staging
/// `Tag::group()` accessor.
///
/// R2 F-OGG-TRIM extends the outcome with `VorbisId` and `OpusHeader`
/// variants so the identification fields can bubble up to [`parse_inner`]
/// for storage on [`Meta`]. The previous design used a `&mut Metadata`
/// staging buffer for ALL tags; the typed-Meta lift preserves bundled
/// emission order via dedicated fields rather than mixing identification
/// scalars into the comment-list shape.
#[derive(Debug, Clone, Copy)]
enum PacketOutcome {
  /// No action — packet not recognised by `classify_packet`, OR the packet
  /// was a recognised non-override / non-comments arm (Vorbis setup-header,
  /// short Vorbis identification payload). Comments-only Vorbis::Comments
  /// packets (Vorbis packet_type=3 with default group1) also map here:
  /// `process_vorbis_comments` has already emitted into the staging
  /// metadata, and no override is needed.
  None,
  /// Vorbis identification packet parsed (`\x01vorbis` + `Vorbis::
  /// Identification` table — Vorbis.pm:30-33,40-70). No override (Vorbis
  /// is the default OGG codec).
  VorbisId(VorbisIdentification),
  /// `OverrideFileType` to the given type (Ogg.pm:49 → "OGV"; :50 → "OPUS").
  /// Comments may OR may not have been processed alongside (Theora 0x81
  /// + Opus `OpusTags` both fire override AND comments).
  Override { file_type: &'static str },
  /// Opus header packet parsed (`OpusHead` + `Opus::Header` table —
  /// Opus.pm:36-51). ALSO carries the `OPUS` override (Ogg.pm:50 fires
  /// whenever the `OpusHead` packet is recognised).
  OpusHeader(OpusHeader),
  /// FLAC-in-Ogg `\x7fFLAC` — deferred (FLAC port not landed yet).
  /// Silent no-op preserves "container OK, no codec tags".
  FlacDeferred,
}

/// Faithful `ProcessPacket` (Ogg.pm:42-69) — dispatch one assembled packet
/// to its codec's comments handler. The `OverrideFileType('OGV')` /
/// `OverrideFileType('OPUS')` calls (Ogg.pm:49-50) live here and fire
/// whenever a Theora / Opus header packet is seen.
///
/// **R2 F-OGG-TRIM:** the Vorbis::Identification and Opus::Header
/// binary-table arms are NOW IN SCOPE (round-2 review showed the R1
/// deferral was creating goldens hand-trims). The Vorbis `packet_type=1`
/// arm parses `\x01vorbis` → [`PacketOutcome::VorbisId`]; the Opus
/// `OpusHead` arm parses → [`PacketOutcome::OpusHeader`] (which also
/// carries the `OPUS` override). Theora `\x80theora` →
/// `Theora::Identification` remains deferred (no Theora fixture; on the
/// dedicated Theora.pm queue).
fn process_packet(
  staging: &mut Metadata,
  picture_sink: &mut Vec<OggPicture>,
  print_conv_enabled: bool,
  buff: &[u8],
) -> PacketOutcome {
  let Some(kind) = classify_packet(buff) else {
    return PacketOutcome::None;
  };
  match kind {
    PacketKind::Vorbis {
      packet_type,
      payload_start,
    } => {
      // Borrow the payload slice directly out of `buff`; the downstream
      // `process_vorbis_comments` takes `&[u8]`, so the original
      // `payload_start.. .to_vec()` copy was avoidable.
      match packet_type {
        1 => {
          // Vorbis::Identification (Vorbis.pm:30-33, 40-70). R2 F-OGG-TRIM:
          // parse the 21-byte fixed-offset binary table. A short payload
          // (under 21 bytes) returns `None` from `parse_vorbis_identification`,
          // mirroring bundled `ProcessBinaryData`'s skip-on-out-of-bounds
          // semantics; in that case the outcome is `None` so the
          // identification fields are silently absent (bundled behaviour
          // exactly).
          // Checked-indexing (Phase C w2b): `classify_packet` validated the
          // magic at `payload_start` bytes, so `buff.get(payload_start..)` is
          // always `Some` ⇒ `.unwrap_or(&[])` is byte-identical.
          match parse_vorbis_identification(buff.get(payload_start..).unwrap_or(&[])) {
            Some(id) => PacketOutcome::VorbisId(id),
            None => PacketOutcome::None,
          }
        }
        3 => {
          // Vorbis::Comments (Vorbis.pm:34-37). No override; comments
          // have been emitted into the staging metadata. R3 F2:
          // `picture_sink` carries any `METADATA_BLOCK_PICTURE` payloads
          // back to the caller for emission as `FLAC:Picture*` fields.
          process_vorbis_comments(
            // Checked-indexing (Phase C w2b): `classify_packet` validated the
            // magic at `payload_start` bytes ⇒ `.get(payload_start..)` is `Some`.
            buff.get(payload_start..).unwrap_or(&[]),
            staging,
            picture_sink,
            print_conv_enabled,
          );
          PacketOutcome::None
        }
        _ => {
          // 0x05 Vorbis setup-header / others: tag-table has no entry, no-op.
          PacketOutcome::None
        }
      }
    }
    PacketKind::Theora {
      packet_type,
      payload_start,
    } => {
      // Ogg.pm:49 `$et->OverrideFileType('OGV')` when this stream is
      // Theora. RETAINED — file-type override is part of the container
      // scope and fires regardless of the codec-binary-table deferral.
      // Ogg.pm:62 `$$et{SET_GROUP1} = $type if $type eq 'Theora'`. Theora
      // tags carry the Theora group1; our tag-table already sets `Theora`.
      // Slice borrow rather than `to_vec()`: downstream accepts `&[u8]`.
      match packet_type {
        0x80 => {
          // Theora::Identification (Theora.pm:42-104) — STILL DEFERRED.
          // Theora is a VIDEO codec with a larger table (rational pixel
          // aspect, framerate, etc.) and we have no Ogg-Theora fixture
          // in the corpus. Queued for a dedicated Theora.pm PR; the
          // `OverrideFileType('OGV')` continues to fire on any
          // `\x80theora` packet seen.
          PacketOutcome::Override { file_type: "OGV" }
        }
        0x81 => {
          // Theora::Comments delegates to Vorbis::Comments (Theora.pm:32-37).
          // Ogg.pm:62 sets group1 to 'Theora' for Vorbis::Comments tags
          // when running under Theora.
          process_vorbis_comments_with_group1(
            // Checked-indexing (Phase C w2b): `classify_packet` validated the
            // magic at `payload_start` bytes ⇒ `.get(payload_start..)` is `Some`.
            buff.get(payload_start..).unwrap_or(&[]),
            staging,
            picture_sink,
            print_conv_enabled,
            "Theora",
          );
          PacketOutcome::Override { file_type: "OGV" }
        }
        _ => {
          // 0x82 Theora setup: no entry, no-op. But we DO still want the
          // file-type override to fire as soon as we recognise a Theora
          // stream (faithful to Ogg.pm:49 — `OverrideFileType` is
          // unconditional on any Theora packet within the container).
          PacketOutcome::Override { file_type: "OGV" }
        }
      }
    }
    PacketKind::Opus {
      kind,
      payload_start,
    } => {
      // Ogg.pm:50 `$et->OverrideFileType('OPUS')` when this stream is
      // Opus. RETAINED — same reasoning as the Theora `OGV` override.
      // Slice borrow rather than `to_vec()`: downstream accepts `&[u8]`.
      match kind {
        OpusKind::Head => {
          // Opus::Header (Opus.pm:36-51). R2 F-OGG-TRIM: parse the 10-byte
          // fixed-offset binary table. A short payload returns `None`
          // from `parse_opus_header` (mirroring bundled out-of-bounds
          // skip); in that case fall back to override-only.
          // Checked-indexing (Phase C w2b): `payload_start`-bytes magic was
          // validated by `classify_packet` ⇒ `.get(payload_start..)` is `Some`.
          match parse_opus_header(buff.get(payload_start..).unwrap_or(&[])) {
            Some(header) => PacketOutcome::OpusHeader(header),
            None => PacketOutcome::Override { file_type: "OPUS" },
          }
        }
        OpusKind::Tags => {
          // Opus.pm:32 delegates to Vorbis::Comments with the default
          // group1 (Vorbis).
          process_vorbis_comments(
            // Checked-indexing (Phase C w2b): `classify_packet` validated the
            // magic at `payload_start` bytes ⇒ `.get(payload_start..)` is `Some`.
            buff.get(payload_start..).unwrap_or(&[]),
            staging,
            picture_sink,
            print_conv_enabled,
          );
          PacketOutcome::Override { file_type: "OPUS" }
        }
      }
    }
    PacketKind::Flac => {
      // Ogg.pm:176-179, 190-195: FLAC-in-Ogg transport. The R3 F2 disposition
      // for the codec stream itself is FORMALLY ACCEPT-DEFERRED (see the
      // module-level note and `tests/conformance.rs`'s `flac_ogg_deferred`
      // marker); the bundled `FLAC.ogg` fixture would exercise it, and the
      // accumulation logic for `numFlac` header-packet packets is not yet
      // ported. See `parse_inner` for the loop-side handling: when a
      // `\x7fFLAC` packet is encountered the OGG body is REJECTED (the
      // OGG candidate returns `success() == false`), so dispatch falls
      // through to the FLAC top-level entry on the FLAC sub-stream. Today
      // the typed Meta therefore omits FLAC body tags emitted by bundled —
      // formally accepted-deferral until a follow-up PR ports the
      // `numFlac` accumulator. (The METADATA_BLOCK_PICTURE handler above
      // covers the other half of the original R3 F2 finding.)
      PacketOutcome::FlacDeferred
    }
  }
}

/// Variant of [`process_vorbis_comments`] that pushes tags with an
/// explicit family-1 group (used when the comments arrive under a
/// Theora stream — Ogg.pm:62 `$$et{SET_GROUP1} = $type`).
///
/// Implementation: parse comments into a side [`Metadata`], then merge
/// each emitted tag into the caller's metadata with the family-1 group
/// rewritten to `group1`. Family-0 (`"Vorbis"`) is preserved (Perl's
/// `SET_GROUP1` swaps ONLY family-1; family-0 is fixed by the tag table).
/// `picture_sink` is threaded through to `process_vorbis_comments` so
/// `METADATA_BLOCK_PICTURE` payloads under a Theora stream are still
/// collected (R3 F2).
fn process_vorbis_comments_with_group1(
  data: &[u8],
  meta: &mut Metadata,
  picture_sink: &mut Vec<OggPicture>,
  print_conv_enabled: bool,
  group1: &str,
) -> bool {
  let mut side = Metadata::new(meta.source_file());
  let ok = process_vorbis_comments(data, &mut side, picture_sink, print_conv_enabled);
  for tag in side.tags_slice() {
    meta.push(
      Group::new(tag.group_ref().family0(), group1),
      tag.name(),
      tag.value_ref().clone(),
    );
  }
  // Propagate any warnings the side-parse emitted.
  for w in side.warnings_slice() {
    meta.push_warning(w.clone());
  }
  ok
}

// ===========================================================================
// Typed Meta — `Meta<'a>`
// ===========================================================================

/// Typed OGG metadata — the lib-first output of [`ProcessOgg`].
///
/// Holds the post-parse emission state of an Ogg container walk:
///
/// 1. A file-type override (`Some("OGV")` for Theora, `Some("OPUS")` for
///    Opus, `None` for plain Vorbis) — applied after `SetFileType('OGG')`
///    by the bridge to mirror bundled `OverrideFileType` (Ogg.pm:49-50).
/// 2. An ordered list of `(group1, name, value)` emissions in the SAME
///    order bundled `perl exiftool -j -G1` produces them: vendor first,
///    then comments in encounter order with list-tags coalesced at first
///    occurrence (faithful FoundTag — ExifTool.pm:9505-9520).
/// 3. The accumulated warnings (`Lost synchronization`, `Missing page(s)
///    in Ogg file`, `Format error in Vorbis comments`) in occurrence order.
/// 4. `success`: whether ProcessOGG accepted at least one valid page (the
///    Perl `return $success` decision; controls SetFileType-emission and
///    File-format-error fallback).
///
/// **D8 — no public fields, accessors only.** Construct only via
/// [`ProcessOgg::parse`] or [`parse_borrowed`].
///
/// **Lifetimes.** Vorbis comment KEYs are uppercased + sometimes
/// synthesised, so we cannot borrow them from input. Vorbis VALs are
/// UTF-8-decoded from input bytes (potentially lossily). For Phase F4
/// the typed Meta carries owned [`SmolStr`] for both name and string
/// values: the typed Meta is a thin wrapper around the bundled-faithful
/// emission shape, and the `&'a` lifetime is reserved for future
/// zero-alloc revisions (Phase G + the bundled list-tag iterator
/// follow-ups). See `[[exifast-phase2-forward-items]]` →
/// "OGG zero-alloc revisit" for the eventual borrow-from-input plan.
#[derive(Debug, Clone)]
pub struct Meta<'a> {
  /// Chained ID3 sub-Meta from the Ogg.pm:79-83 embedded ProcessID3 call
  /// (`unless ($$et{DoneID3}) { ID3::ProcessID3($et, $dirInfo) }`). `Some`
  /// when an ID3v2 PREFIX (in front of the `OggS` magic) was detected and
  /// parsed via [`crate::formats::id3::process::parse_id3_with_hdr_end`].
  /// Carries `File:ID3Size` + any `ID3v2_*:*` frame tags; the typed
  /// `serialize_tags` sink emits them in the bundled-faithful order
  /// (`File:ID3Size` ⇒ Vorbis fields ⇒ `ID3v2_*:*` frame tags). Same
  /// nesting pattern as `ape::Meta::id3`, `flac::Meta::id3`,
  /// `dsf::Meta::id3`.
  ///
  /// R3 F1 (Codex adversarial): pre-fix the engine `AnyParser::Ogg` arm
  /// stripped the ID3v2 prefix to reparse `bytes[hdr_end..]` but never
  /// emitted the ID3 directory — silent metadata loss. Nesting the typed
  /// ID3 parser closes that hole (no hand-trim, no #[ignore] — the
  /// `ogg_id3_prefixed.ogg` fixture now reaches value-equivalent with
  /// the bundled golden).
  #[cfg(feature = "id3")]
  id3: Option<crate::formats::id3::Id3Meta<'a>>,
  /// `OverrideFileType` target (Ogg.pm:49-50). `Some("OPUS")` when an
  /// `OpusHead` or `OpusTags` packet was seen; `Some("OGV")` when a
  /// Theora `\x80theora` / `\x81theora` packet was seen; `None` otherwise.
  /// The bridge calls `ctx.override_file_type(value, None, None)` after
  /// `SetFileType('OGG')` to mirror bundled in-place mutation.
  file_type_override: Option<&'static str>,
  /// R2 F-OGG-TRIM: Vorbis identification fields parsed from the
  /// `\x01vorbis` packet (Vorbis.pm:40-70). `None` when no Vorbis
  /// identification packet was seen, OR when the payload was shorter than
  /// the 21-byte fixed window the table reads. Emits at the bundled
  /// emission position: BEFORE the Vorbis comment block (vendor + KEY=VALUE
  /// pairs) for a Vorbis-only stream, BEFORE comments for Opus too if the
  /// stream is mixed (real-world Opus uses `Opus:*` only; Vorbis ID +
  /// Opus header don't coexist in a single stream by spec).
  vorbis_identification: Option<VorbisIdentification>,
  /// R2 F-OGG-TRIM: Opus header fields parsed from the `OpusHead` packet
  /// (Opus.pm:36-51). `None` when no `OpusHead` packet was seen, OR when
  /// the payload was shorter than the 10-byte fixed window the table reads.
  /// Emits before the Vorbis-comment block on the same stream.
  opus_header: Option<OpusHeader>,
  /// R3 F2: `METADATA_BLOCK_PICTURE` payloads decoded into the FLAC
  /// `%FLAC::Picture` SubDirectory shape (Vorbis.pm:122-134 → FLAC.pm:
  /// 84-134). One entry per encountered `METADATA_BLOCK_PICTURE` Vorbis
  /// comment. Empty `Vec` when no METADATA_BLOCK_PICTURE comments were
  /// seen. Pre-fix the parser emitted only a single `Vorbis:Picture` blob
  /// (the base64-decoded payload); bundled emits `FLAC:Picture*` sub-
  /// fields. Codex round-3 caught this as silent metadata loss.
  pictures: Vec<OggPicture>,
  /// Emitted comment tags in bundled emission order (vendor first, then
  /// KEY=VALUE in encounter order; list-tags coalesced at first-occurrence
  /// position).
  comments: Vec<Comment>,
  /// `$et->Warn(...)` accumulator (Ogg.pm:97 + 158, Vorbis.pm:208) in
  /// occurrence order. Owned (`SmolStr`) — no `Box::leak` (Codex AF2).
  warnings: Vec<SmolStr>,
  /// `$success` — at least one valid 28-byte page accepted. Drives the
  /// bridge's `SetFileType` call AND the false-return (post-loop
  /// `File format error`) decision.
  success: bool,
  /// Carries the lifetime parameter for forward-compatibility with the
  /// borrow-from-input revisit. Today the typed Meta holds owned
  /// [`SmolStr`] / [`Vec<u8>`] (see struct-level docs), so the `'a`
  /// parameter is phantom; promoting it to a real borrow is a Phase G
  /// follow-up and does NOT change the API shape.
  _marker: core::marker::PhantomData<&'a ()>,
}

/// Payload of [`Comment::Scalar`] — a `Vorbis:<Name>` scalar string
/// (the vast majority of named tags: TITLE/ALBUM/GENRE/...).
///
/// §2: extracted from a former struct-style variant (`Scalar { group1,
/// name, value }`) into a named struct with private fields + accessors so
/// the variant is a clean newtype. §1: no public fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentScalar {
  /// Family-1 group ("Vorbis" by default; "Theora" under Theora streams).
  /// Owned (`SmolStr`) so the typed Meta needs no `Box::leak` for the
  /// rare non-`Vorbis`/`Theora` group (Codex AF2).
  group1: SmolStr,
  /// Resolved tag name (`Vorbis.pm:80-121` rename hint, or
  /// `vorbis_comment_compute_name` for unknown keys).
  name: SmolStr,
  /// UTF-8 string value (decoded from input bytes via
  /// `String::from_utf8_lossy`).
  value: SmolStr,
}

impl CommentScalar {
  /// Construct a scalar comment payload.
  #[must_use]
  #[inline(always)]
  pub fn new(
    group1: impl Into<SmolStr>,
    name: impl Into<SmolStr>,
    value: impl Into<SmolStr>,
  ) -> Self {
    Self {
      group1: group1.into(),
      name: name.into(),
      value: value.into(),
    }
  }
  /// Family-1 group (`"Vorbis"` / `"Theora"`). §3 string view (`&str`).
  #[must_use]
  #[inline(always)]
  pub fn group1(&self) -> &str {
    self.group1.as_str()
  }
  /// Resolved tag name. §3 string view (`&str`).
  #[must_use]
  #[inline(always)]
  pub fn name(&self) -> &str {
    self.name.as_str()
  }
  /// UTF-8 string value. §3 string view (`&str`).
  #[must_use]
  #[inline(always)]
  pub fn value(&self) -> &str {
    self.value.as_str()
  }
}

/// Payload of [`Comment::List`] — a `Vorbis:Artist`-style coalesced
/// list (Vorbis.pm:85,86,94 — ARTIST, PERFORMER, CONTACT). Emitted at
/// FIRST-occurrence position; repeats append (faithful `FoundTag` —
/// ExifTool.pm:9505-9520).
///
/// §2: extracted from a former struct-style variant into a named struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentList {
  /// Family-1 group ("Vorbis" by default; "Theora" under Theora streams).
  group1: SmolStr,
  /// Resolved tag name ("Artist" / "Performer" / "Contact").
  name: SmolStr,
  /// Coalesced UTF-8 string values, in encounter order.
  values: Vec<SmolStr>,
}

impl CommentList {
  /// Construct a list comment payload from coalesced values.
  #[must_use]
  #[inline(always)]
  pub fn new(group1: impl Into<SmolStr>, name: impl Into<SmolStr>, values: Vec<SmolStr>) -> Self {
    Self {
      group1: group1.into(),
      name: name.into(),
      values,
    }
  }
  /// Family-1 group (`"Vorbis"` / `"Theora"`). §3 string view (`&str`).
  #[must_use]
  #[inline(always)]
  pub fn group1(&self) -> &str {
    self.group1.as_str()
  }
  /// Resolved tag name. §3 string view (`&str`).
  #[must_use]
  #[inline(always)]
  pub fn name(&self) -> &str {
    self.name.as_str()
  }
  /// Coalesced values in encounter order. §3 slice projection — returns
  /// `&[SmolStr]`, never `&Vec<SmolStr>`.
  #[must_use]
  #[inline(always)]
  pub fn values_slice(&self) -> &[SmolStr] {
    self.values.as_slice()
  }
}

/// Payload of [`Comment::Binary`] — a `Vorbis:CoverArt` / `Vorbis:
/// Picture` base64-decoded raw byte blob. Renders downstream as `(Binary
/// data N bytes, use -b option to extract)`. The `Picture` SubDirectory
/// hop to `FLAC::Picture` is deferred (Vorbis.pm:122-134) — only the
/// raw-bytes form is emitted.
///
/// §2: extracted from a former struct-style variant into a named struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentBinary {
  /// Family-1 group ("Vorbis" by default; "Theora" under Theora streams).
  group1: SmolStr,
  /// "CoverArt" or "Picture".
  name: SmolStr,
  /// Base64-decoded raw bytes.
  bytes: Vec<u8>,
}

impl CommentBinary {
  /// Construct a binary comment payload from decoded bytes.
  #[must_use]
  #[inline(always)]
  pub fn new(group1: impl Into<SmolStr>, name: impl Into<SmolStr>, bytes: Vec<u8>) -> Self {
    Self {
      group1: group1.into(),
      name: name.into(),
      bytes,
    }
  }
  /// Family-1 group (`"Vorbis"` / `"Theora"`). §3 string view (`&str`).
  #[must_use]
  #[inline(always)]
  pub fn group1(&self) -> &str {
    self.group1.as_str()
  }
  /// Tag name (`"CoverArt"` / `"Picture"`). §3 string view (`&str`).
  #[must_use]
  #[inline(always)]
  pub fn name(&self) -> &str {
    self.name.as_str()
  }
  /// Base64-decoded raw bytes. §3 byte-slice projection — returns `&[u8]`,
  /// never `&Vec<u8>`.
  #[must_use]
  #[inline(always)]
  pub fn bytes(&self) -> &[u8] {
    self.bytes.as_slice()
  }
}

/// A single comment emission within an [`Meta`]. Mirrors the bundled
/// `HandleTag` family of pushes that `ProcessComments` emits per vendor
/// + per `KEY=VALUE` pair (Vorbis.pm:181-205).
///
/// §2: variants are **unit-or-newtype only** — each data-carrying arm wraps
/// a single named struct ([`CommentScalar`] / [`CommentList`] /
/// [`CommentBinary`]) whose fields are private with accessors, instead of
/// the former struct-style `{ … }` variants. `#[non_exhaustive]` guards
/// future emission shapes; predicates (`is_*`) and unwrap accessors are
/// derived (derive_more) so callers don't hand-match.
#[non_exhaustive]
#[derive(
  Debug, Clone, PartialEq, Eq, derive_more::IsVariant, derive_more::Unwrap, derive_more::TryUnwrap,
)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
pub enum Comment {
  /// `Vorbis:<Name>` scalar string — see [`CommentScalar`].
  Scalar(CommentScalar),
  /// `Vorbis:Artist`-style coalesced list — see [`CommentList`].
  List(CommentList),
  /// `Vorbis:CoverArt` / `Vorbis:Picture` raw bytes — see
  /// [`CommentBinary`].
  Binary(CommentBinary),
}

impl Meta<'_> {
  /// `OverrideFileType` target (`"OPUS"` or `"OGV"`), or `None` for plain
  /// Vorbis. Applied by the bridge after `SetFileType('OGG')` to mirror
  /// bundled Ogg.pm:49-50. `&'static str` payload is `Copy` ⇒ by value (§3).
  #[must_use]
  #[inline(always)]
  pub const fn file_type_override(&self) -> Option<&'static str> {
    self.file_type_override
  }

  /// Chained ID3 sub-Meta (Ogg.pm:79-83 embedded `ProcessID3`). `Some`
  /// when an ID3v2 PREFIX was detected and parsed; the typed
  /// `serialize_tags` sink emits its `File:ID3Size` + `ID3v2_*:*` frame
  /// tags. R3 F1: this closes the silent metadata-loss hole on
  /// ID3-prefixed Ogg.
  ///
  /// §3: non-`Copy` borrow ⇒ `_ref` suffix.
  #[cfg(feature = "id3")]
  #[must_use]
  #[inline(always)]
  pub const fn id3_ref(&self) -> Option<&crate::formats::id3::Id3Meta<'_>> {
    self.id3.as_ref()
  }

  /// Vorbis identification-packet fields (Vorbis.pm:40-70), or `None` if
  /// no `\x01vorbis` identification packet was parsed for this stream.
  /// Emits at bundled position — BEFORE the comment block. The contained
  /// value is `Copy` so the accessor returns it by value (§3).
  #[must_use]
  #[inline(always)]
  pub const fn vorbis_identification(&self) -> Option<VorbisIdentification> {
    self.vorbis_identification
  }

  /// Opus header-packet fields (Opus.pm:36-51), or `None` if no `OpusHead`
  /// packet was parsed. The contained value is `Copy` so the accessor
  /// returns it by value (§3).
  #[must_use]
  #[inline(always)]
  pub const fn opus_header(&self) -> Option<OpusHeader> {
    self.opus_header
  }

  /// `METADATA_BLOCK_PICTURE` payloads parsed from the Vorbis-comment
  /// block (R3 F2). One entry per `METADATA_BLOCK_PICTURE` comment;
  /// empty when none were seen. Mirrors `flac::Meta::pictures` shape
  /// but with owned strings/bytes (the base64-decoded buffer is dropped
  /// after parse). §3 slice projection.
  #[must_use]
  #[inline(always)]
  pub fn pictures(&self) -> &[OggPicture] {
    self.pictures.as_slice()
  }

  /// The emitted comment tags in bundled emission order. Each item is an
  /// [`Comment`] newtype arm with the resolved family-1 group, tag name,
  /// and value. §3 slice projection — returns `&[Comment]`, never
  /// `&Vec<Comment>`.
  #[must_use]
  #[inline(always)]
  pub fn comments(&self) -> &[Comment] {
    self.comments.as_slice()
  }

  /// Warnings accumulated during the parse, in occurrence order. Each
  /// element is the string bundled-Perl emits via `$et->Warn(...)`:
  /// `"Lost synchronization"` (Ogg.pm:97), `"Missing page(s) in Ogg
  /// file"` (Ogg.pm:158), or `"Format error in Vorbis comments"`
  /// (Vorbis.pm:208). §3 slice projection — returns `&[SmolStr]`.
  #[must_use]
  #[inline(always)]
  pub fn warnings(&self) -> &[SmolStr] {
    self.warnings.as_slice()
  }

  /// Whether ProcessOGG accepted at least one valid 28-byte page (Perl's
  /// `$success` flag — Ogg.pm:100-103). On `false`, the legacy bridge
  /// returns `false` from the engine entry `process` (no `SetFileType`
  /// fired); the engine post-loop emits `ExifTool:Error => "File format
  /// error"` (ExifTool.pm:3093). `bool` is `Copy` ⇒ by value (§3).
  #[must_use]
  #[inline(always)]
  pub const fn success(&self) -> bool {
    self.success
  }
}

// ===========================================================================
// Packet dispatch (Ogg.pm:42-69 `ProcessPacket`)
// ===========================================================================

/// Faithful `ProcessOGG` (Ogg.pm:75-197) container walker, lifted into the
/// new lib-first parser API.
#[derive(Debug, Clone, Copy)]
pub struct ProcessOgg;

impl parser_sealed::Sealed for ProcessOgg {}

impl FormatParser for ProcessOgg {
  /// GAT: the Meta borrows from the input `'a` directly (Codex AF2).
  type Meta<'a> = Meta<'a>;
  type Context<'a> = &'a [u8];

  /// Parse an Ogg file's bytes into a typed [`Meta`].
  ///
  /// `Ok(Some(meta))` is returned even when `meta.success() == false`
  /// (i.e. the bytes are not a valid Ogg stream): the typed Meta carries
  /// the parse outcome so the bridge can fall through to the engine's
  /// `File format error` path (Perl `return $success`). This shape
  /// differs from MOI/AAC/DV which use `Ok(None)` for "reject"; the
  /// reason is that OGG accumulates warnings during the walk that the
  /// bundled output preserves even when the page-acceptance test never
  /// passes (e.g. mid-stream `Lost synchronization`).
  ///
  /// **R5 (Codex adversarial)** — routes through [`parse_full_chained`]
  /// so the embedded ID3 chain (Ogg.pm:79-83) runs for ID3-prefixed Ogg
  /// streams and nests an [`crate::formats::id3::Id3Meta`] into the
  /// returned [`Meta`]. Pre-fix the trait impl called the body-only
  /// [`parse_inner`], which requires `OggS` at byte 0 — so an
  /// ID3v2-prefixed Ogg buffer returned `success = false` and the typed
  /// `FormatParser` surface silently dropped both the detected ID3 tags
  /// AND the OGG body. Only the crate-root `parse_ogg` was fixed in R4;
  /// R5 propagates the chain down to ALL public surfaces.
  ///
  /// A fresh [`crate::format_parser::SharedFlags`] is constructed per
  /// call (the trait's `&[u8]` Context has no chain state to thread).
  fn parse<'a>(&self, data: Self::Context<'a>) -> Option<Self::Meta<'a>> {
    // `ogg = ["flac", "id3"]` per Cargo.toml ⇒ `parse_full_chained` is
    // always present here.
    let mut shared = crate::format_parser::SharedFlags::default();
    parse_full_chained(data, &mut shared, /* print_conv */ true)
  }
}

/// Lib-first direct entry. Same as [`FormatParser::parse`] but exposes
/// the borrow-from-input form (`Meta<'_>`) and the `print_conv`
/// toggle. `print_conv_enabled = true` matches bundled `perl exiftool -j`;
/// `false` matches `-j -n`. The toggle gates `convert::apply`'s
/// ValueConv / PrintConv chain on the few tags that have one
/// (COVERART base64 ValueConv is always applied; for known tags in OGG
/// scope today PrintConv is `None` so the toggle is mostly cosmetic).
///
/// **R4 F2 (Codex adversarial)** — routes through [`parse_full_chained`]
/// so the embedded ID3 chain (Ogg.pm:79-83) runs for ID3-prefixed Ogg
/// streams. Pre-fix this entry called the bare [`parse_inner`], which
/// requires `OggS` at byte 0 — so an ID3v2-prefixed Ogg buffer returned
/// `success = false` and the public API silently dropped both the
/// detected ID3 tags AND the OGG body. The R3 fix went into the
/// engine path (`AnyParser::Ogg`); the lib-direct API bypassed it.
///
/// A fresh [`crate::format_parser::SharedFlags`] is constructed per
/// call (the public entry has no chain state to thread); the recursion
/// guard inside `parse_full_chained` only matters for the engine
/// path where ID3 may have already run on a prior format candidate.
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today; reserved for
/// future I/O wrappers).
pub fn parse_borrowed(data: &[u8], print_conv_enabled: bool) -> Option<Meta<'_>> {
  // `ogg = ["id3", "flac"]` per Cargo.toml ⇒ `id3` is always present here.
  let mut shared = crate::format_parser::SharedFlags::default();
  parse_full_chained(data, &mut shared, print_conv_enabled)
}

/// R3 F1: full-chained parse — runs the embedded ID3 chain (`unless
/// ($$et{DoneID3}) { ID3::ProcessID3 }`, Ogg.pm:79-83) and nests the typed
/// [`crate::formats::id3::Id3Meta`] into the returned [`Meta`]. Then runs
/// the OGG container walk over the POST-ID3-prefix slice (the same way
/// bundled `ProcessID3`'s audio-format loop seeks past `$hdrEnd` and
/// re-dispatches the OGG body, ID3.pm:1582-1601).
///
/// Bundled emits `File:ID3Size` for every ID3-prefixed Ogg-Vorbis stream
/// (even an empty 10-byte header); pre-fix the engine dispatch stripped the
/// ID3v2 prefix to reparse but never emitted the ID3 directory — silent
/// metadata loss caught by Codex round 3.
///
/// Returns `Some(Meta)` (with `id3` nested) whenever the OGG body parsed
/// successfully OR when the body parse rejected the slice (in which case
/// the typed Meta carries `success = false` so the engine continues the
/// candidate loop — and in particular the dispatch arm filters this case
/// out to allow MP3 dispatch on an `ID3-prefixed MP3` to win).
///
/// `#[cfg(feature = "id3")]`: the `ogg` Cargo feature pulls `id3` (Cargo
/// manifest), so this is the production path for the `OGG` file-type entry.
/// Lifetime `'a` borrows from `data` (the ID3 sub-Meta owns its strings;
/// the OGG Meta is mostly owned today — Phase G zero-alloc plan still
/// applies).
///
/// `print_conv` is forwarded to the OGG body parse (Vorbis comment PrintConv
/// toggle). The embedded ID3 chain is always staged in `print_conv: true`
/// mode (the `parse_id3_with_hdr_end` contract).
#[cfg(feature = "id3")]
pub(crate) fn parse_full_chained<'a>(
  data: &'a [u8],
  shared: &mut crate::format_parser::SharedFlags,
  print_conv: bool,
) -> Option<Meta<'a>> {
  // 1. Embedded ID3 (Ogg.pm:79-83). The recursion guard (ID3.pm:1435 `return
  //    0 if $$et{DoneID3}`) is honoured here via `shared.done_id3().is_none()`:
  //    only call when ID3 has not already run on this chain (a standalone
  //    OGG file-type entry always gets a fresh `SharedFlags`).
  let (id3, hdr_end) = if shared.done_id3().is_none() {
    crate::formats::id3::process::parse_id3_with_hdr_end(data, Some(&mut *shared), true)
  } else {
    (None, shared.id3_hdr_end().unwrap_or(0))
  };

  // 2. OGG container walk on the POST-ID3 slice. ID3.pm:1590 `Seek($hdrEnd,
  //    0)` followed by re-dispatch on the audio body — same semantics as
  //    `ape::parse_full_chained` (the body parser sees the bytes starting at
  //    the post-ID3-header offset).
  let body_slice = data.get(hdr_end..).unwrap_or(&[]);
  match parse_inner(body_slice, print_conv) {
    Some(mut meta) => {
      meta.id3 = id3;
      Some(meta)
    }
    // `parse_inner` always returns `Some` today (the typed Meta carries
    // `success` even for non-OGG input). The `None` arm is reachable only
    // if a future revision starts rejecting on Rust-level errors; treat as
    // "no Meta" so the candidate loop continues.
    None => None,
  }
}

/// Inner parser — produces a borrow-from-input [`Meta`] (technically
/// `Meta<'_>` with a phantom `'_` today; see [`Meta`] struct doc
/// re: zero-alloc revisit). The [`FormatParser::Meta`] GAT (`type
/// Meta<'a> = Meta<'a>`) returns this borrowed form directly into the
/// closed [`crate::format_parser::AnyMeta`] enum (Codex AF2).
fn parse_inner(data: &[u8], print_conv_enabled: bool) -> Option<Meta<'_>> {
  // Stage the legacy push-style emissions into a side `Metadata` so the
  // bundled-faithful list-coalesce + name-synthesis paths stay byte-exact
  // (faithful to Vorbis.pm:154-210 + ExifTool.pm:9505-9520). The side
  // Metadata is then transposed into typed `Meta` fields below.
  //
  // This pattern mirrors the AAC pilot (Phase F1) — the staging Metadata
  // is the simplest way to keep the established list-coalesce semantics
  // (FoundTag-like first-occurrence position + same-(group, name) repeats
  // coalesce into a single `TagValue::List`) inside the typed Meta.
  let mut staging = Metadata::new("ogg-staging");

  // R3 F2: `METADATA_BLOCK_PICTURE` Vorbis-comment payloads decoded into
  // owned `OggPicture` entries (Vorbis.pm:122-134 SubDirectory hop into
  // %FLAC::Picture). One entry per encountered comment; lifted into the
  // typed Meta below.
  let mut pictures: Vec<OggPicture> = Vec::new();

  // Container walker state — verbatim Perl ProcessOGG (Ogg.pm:75-197).
  let mut success = false;
  let mut packet_count: u32 = 0;
  let mut stream_count: u32 = 0;
  let mut current_stream: u32;
  let mut stream_page: HashMap<u32, Option<u32>> = HashMap::new();
  // Accumulated packet payload per stream (continuation pages concatenate
  // into the same entry).
  let mut val: HashMap<u32, Vec<u8>> = HashMap::new();

  let mut cursor: usize = 0;
  let mut current_flag: u8;
  let mut raf_done = false;

  // `OverrideFileType` decision (Ogg.pm:49-50). First-seen wins (mirrors
  // bundled — bundled `OverrideFileType` is idempotent for equal values
  // and does nothing for already-overridden, per ExifTool.pm:9715).
  let mut file_type_override: Option<&'static str> = None;
  // R2 F-OGG-TRIM: identification fields. First-seen wins for the same
  // reason `file_type_override` is first-wins: bundled `ProcessBinaryData`
  // emits the FIRST occurrence's value through `HandleTag`, and the
  // FoundTag de-dup is `(group, name)` ⇒ subsequent occurrences for the
  // same tag are dropped by `%NO_DUPS` priority (ExifTool.pm:9540).
  let mut vorbis_identification: Option<VorbisIdentification> = None;
  let mut opus_header: Option<OpusHeader> = None;

  loop {
    // Ogg.pm:94 `if ($raf and $raf->Read($buff, 28) == 28)` — the page
    // header read MUST succeed at exactly 28 bytes for the page to be
    // accepted. 27 bytes is one byte short of `Get8u(\$buff, 27)` (the
    // first segment-table entry, used later on Ogg.pm:147 `$dataLen =
    // Get8u(\$buff, 27)`). A 27-byte `OggS`-magic input is REJECTED:
    // the read returns 27, the `== 28` check fails, the loop never
    // accepts the page, `$success` stays 0 ⇒ post-loop finalization
    // emits `'File format error'` (ExifTool.pm:3093). See conformance
    // pin `ogg_truncated_error_conformance` (R1 F1 regression).
    let header_in_bounds = !raf_done && data.len() >= cursor + 28;
    // Checked-indexing (Phase C w2b): `data.get(cursor..cursor + 4) ==
    // Some(b"OggS")` is `true` under exactly the same conditions as the old
    // `header_in_bounds && &data[cursor..cursor + 4] == b"OggS"` (the `Some`
    // arm requires the window in bounds, which `header_in_bounds`'s
    // `len >= cursor + 28` guarantees) ⇒ byte-identical.
    let header_magic_ok = header_in_bounds && data.get(cursor..cursor + 4) == Some(&b"OggS"[..]);
    let read_ok = if header_in_bounds {
      if !header_magic_ok {
        // Ogg.pm:97 `$success and $et->Warn('Lost synchronization')`.
        if success {
          staging.push_warning("Lost synchronization");
        }
        false
      } else {
        true
      }
    } else {
      false
    };

    if read_ok {
      if !success {
        // Ogg.pm:101-104 — first valid page: SetFileType + SetByteOrder.
        // (SetFileType is fired by the bridge, not here — the typed
        // Meta records the success flag instead.)
        success = true;
      }
      // Ogg.pm:106 `$flag = Get8u(\$buff, 5)` — page-header byte 5.
      // Checked-indexing (Phase C w2b): reached only inside `if read_ok`, which
      // requires `header_in_bounds` (`data.len() >= cursor + 28`), so every
      // `cursor + k` (k <= 27) byte is in range ⇒ the `.get(...)` fallbacks
      // (`0`) are unreachable and the reads are byte-identical.
      current_flag = data.get(cursor + 5).copied().unwrap_or(0);
      // Ogg.pm:107 `$stream = Get32u(\$buff, 14)`.
      current_stream = match data.get(cursor + 14..cursor + 18) {
        Some(&[b0, b1, b2, b3]) => u32::from_le_bytes([b0, b1, b2, b3]),
        _ => 0,
      };
      if current_flag & 0x02 != 0 {
        // Ogg.pm:108-110 — BOS bit set.
        stream_count = stream_count.saturating_add(1);
        stream_page.insert(current_stream, Some(0));
      }
      // Ogg.pm:114 `++$packets unless $flag & 0x01`.
      if current_flag & 0x01 == 0 {
        packet_count = packet_count.saturating_add(1);
      }
    } else {
      // Ogg.pm:115-121 — no more data; if we still have a buffered
      // packet, take any stream and process it.
      if val.is_empty() {
        break;
      }
      // Take the first stream key we have (Ogg.pm:118 `($stream) = sort
      // keys %val`).
      let mut keys: Vec<u32> = val.keys().copied().collect();
      keys.sort();
      // Checked-indexing (Phase C w2b): reached only after the `val.is_empty()`
      // break above, so `keys` is non-empty ⇒ `keys.first()` is `Some` and
      // `.unwrap_or(0)` is byte-identical to the previous `keys[0]`.
      current_stream = keys.first().copied().unwrap_or(0);
      current_flag = 0;
      raf_done = true;
    }

    // Ogg.pm:122-140 — process the previously buffered packet.
    // (FLAC-in-Ogg `defined $numFlac` arm is DEFERRED; we fall straight
    // through to the regular packet-processing branch.)
    if val.contains_key(&current_stream) && current_flag & 0x01 == 0 {
      let owned = val.remove(&current_stream).unwrap();
      let outcome = process_packet(&mut staging, &mut pictures, print_conv_enabled, &owned);
      record_outcome(
        &mut file_type_override,
        &mut vorbis_identification,
        &mut opus_header,
        &outcome,
      );
      // Ogg.pm:133-136: stop if MAX_PACKETS reached AND no pending vals.
      if (packet_count > MAX_PACKETS.saturating_mul(stream_count) || raf_done) && val.is_empty() {
        break;
      }
    }
    // Ogg.pm:138-139 `last if $packets > $MAX_PACKETS * $streams and
    // not %val;`
    if packet_count > MAX_PACKETS.saturating_mul(stream_count) && val.is_empty() {
      break;
    }

    // If we were on the synthetic "raf_done" pass and have nothing to do,
    // exit the loop.
    if raf_done {
      break;
    }

    // Ogg.pm:142-153 — sequence number, segment table, data length.
    // Checked-indexing (Phase C w2b): control only reaches here when the
    // `if read_ok` branch ran this iteration (the `else` branch sets
    // `raf_done` and the `if raf_done { break }` above would have exited),
    // and `read_ok` required `header_in_bounds` (`data.len() >= cursor + 28`),
    // so every `cursor + k` (k <= 27) is in range ⇒ the `.get(...)` fallbacks
    // are unreachable and the reads are byte-identical.
    let page_num = match data.get(cursor + 18..cursor + 22) {
      Some(&[b0, b1, b2, b3]) => u32::from_le_bytes([b0, b1, b2, b3]),
      _ => 0,
    };
    let nseg = data.get(cursor + 26).copied().unwrap_or(0) as usize;
    // We need `27 + nseg` bytes to cover the header + segment table.
    if data.len() < cursor + 27 + nseg {
      break;
    }
    // Checked-indexing (Phase C w2b): the `data.len() < cursor + 27 + nseg`
    // guard above makes `data.get(cursor + 27..cursor + 27 + nseg)` always
    // `Some` ⇒ byte-identical.
    let seg_table = data.get(cursor + 27..cursor + 27 + nseg).unwrap_or(&[]);
    let data_len: usize = seg_table.iter().map(|&b| b as usize).sum();
    // Ogg.pm:154-162 — sequence-number check.
    let expected_opt = stream_page.get(&current_stream).copied().flatten();
    if let Some(expected) = expected_opt {
      if expected == page_num {
        stream_page.insert(current_stream, Some(expected + 1));
      } else {
        staging.push_warning("Missing page(s) in Ogg file");
        stream_page.insert(current_stream, None);
      }
    }
    // Ogg.pm:164 — read page data.
    let page_data_start = cursor + 27 + nseg;
    let page_data_end = page_data_start + data_len;
    if data.len() < page_data_end {
      break;
    }
    // Page bytes as a borrowed slice (no copy yet — the `val` HashMap
    // owns its own `Vec<u8>` per stream; we move the bytes into it only
    // when we actually start a new packet).
    //
    // Checked-indexing (Phase C w2b): the `data.len() < page_data_end` guard
    // above makes `data.get(page_data_start..page_data_end)` always `Some` ⇒
    // byte-identical.
    let page_bytes: &[u8] = data.get(page_data_start..page_data_end).unwrap_or(&[]);

    // Ogg.pm:170-179 — accumulate or start new packet.
    if let Some(existing) = val.get_mut(&current_stream) {
      // Continuation page — concatenate (Ogg.pm:171).
      existing.extend_from_slice(page_bytes);
    } else if current_flag & 0x01 == 0 {
      // New packet (not a continuation of one we aren't parsing).
      if classify_packet(page_bytes).is_some() {
        // Materialise the slice into the `val` map (this is the single
        // copy needed for the packet accumulator; the prior revision
        // double-copied via `page_data.clone()`).
        val.insert(current_stream, page_bytes.to_vec());
      }
    }
    // Ogg.pm:184-188 — EOS bit ⇒ process now.
    if current_flag & 0x04 != 0 && val.contains_key(&current_stream) {
      let owned = val.remove(&current_stream).unwrap();
      let outcome = process_packet(&mut staging, &mut pictures, print_conv_enabled, &owned);
      record_outcome(
        &mut file_type_override,
        &mut vorbis_identification,
        &mut opus_header,
        &outcome,
      );
    }
    cursor = page_data_end;
  }
  // Ogg.pm:196 `return $success`.

  // Lift staging metadata into typed Meta. Warnings are cloned into
  // owned `SmolStr` (no `Box::leak`); comments go through `tag_to_comment`
  // per element.
  let warnings: Vec<SmolStr> = staging
    .warnings_slice()
    .iter()
    .map(|w| staged_warning_to_owned(w.as_str()))
    .collect();
  let comments: Vec<Comment> = staging.tags_slice().iter().map(tag_to_comment).collect();
  Some(Meta {
    #[cfg(feature = "id3")]
    id3: None,
    file_type_override,
    vorbis_identification,
    opus_header,
    pictures,
    comments,
    warnings,
    success,
    _marker: core::marker::PhantomData,
  })
}

/// First-wins outcome reducer. Bundled `OverrideFileType`
/// (ExifTool.pm:9715) is idempotent for equal values and does nothing for
/// already-overridden values; bundled `FoundTag` (ExifTool.pm:9505-9520)
/// drops duplicate emissions for the same `(group, name)`. Both behaviours
/// collapse to "first-wins" for each of the three state slots.
fn record_outcome(
  override_state: &mut Option<&'static str>,
  vorbis_id_state: &mut Option<VorbisIdentification>,
  opus_header_state: &mut Option<OpusHeader>,
  outcome: &PacketOutcome,
) {
  match outcome {
    PacketOutcome::None | PacketOutcome::FlacDeferred => {}
    PacketOutcome::Override { file_type } => {
      if override_state.is_none() {
        *override_state = Some(*file_type);
      }
    }
    PacketOutcome::VorbisId(id) => {
      if vorbis_id_state.is_none() {
        *vorbis_id_state = Some(*id);
      }
      // Vorbis identification packets do NOT trigger a file-type override
      // (Ogg.pm:49-50 only fire for Theora / Opus); Vorbis is the default
      // OGG codec ⇒ no override needed.
    }
    PacketOutcome::OpusHeader(header) => {
      if opus_header_state.is_none() {
        *opus_header_state = Some(*header);
      }
      // Opus.pm:50 fires `OverrideFileType('OPUS')` whenever an `OpusHead`
      // packet is recognised, regardless of whether the binary table is
      // fully decodable.
      if override_state.is_none() {
        *override_state = Some("OPUS");
      }
    }
  }
}

/// Clone a staged warning string into the typed Meta's owned warning list.
/// The three strings OGG can emit (Ogg.pm:97, :158, Vorbis.pm:208) are all
/// `&'static str` literals in bundled-Perl; the typed Meta now carries them
/// as owned [`SmolStr`] (no `Box::leak`; Codex AF2). The short, fixed
/// literals are all SmolStr-inline (≤ 23 bytes), so this is allocation-free.
fn staged_warning_to_owned(w: &str) -> SmolStr {
  SmolStr::from(w)
}

/// Transpose a staged `Tag` (one row of the side `Metadata`) into a typed
/// [`Comment`]. Lossy on the [`TagValue`] enum because the typed
/// Meta's contract is "what bundled would emit": `TagValue::Str` ⇒
/// [`Comment::Scalar`], `TagValue::List` ⇒ [`Comment::List`],
/// `TagValue::Bytes` ⇒ [`Comment::Binary`]. Other `TagValue` variants
/// are not produced by the legacy parser for OGG (no I64/F64/Rational
/// paths in the Vorbis-comment block).
fn tag_to_comment(tag: &crate::value::Tag) -> Comment {
  // Family-1 group is bundled's `-G1` token. For OGG it's either "Vorbis"
  // (Vorbis::Comments / Opus comments) or "Theora" (Theora::Comments).
  // Stored owned (`SmolStr`) so an unforeseen group needs no `Box::leak`
  // (Codex AF2).
  let group1 = SmolStr::from(tag.group_ref().family1());
  let name = SmolStr::from(tag.name());
  match tag.value_ref() {
    TagValue::List(items) => {
      // List tags in OGG today: Artist / Performer / Contact.
      let values: Vec<SmolStr> = items
        .iter()
        .map(|v| match v {
          TagValue::Str(s) => s.clone(),
          // Defensive: bundled never produces non-string elements in a
          // Vorbis-comment list (no ValueConv runs on List tags for
          // ARTIST/PERFORMER/CONTACT). Fall back to a Display rendering.
          other => SmolStr::from(format!("{other:?}")),
        })
        .collect();
      Comment::List(CommentList::new(group1, name, values))
    }
    TagValue::Bytes(bytes) => Comment::Binary(CommentBinary::new(group1, name, bytes.clone())),
    TagValue::Str(s) => Comment::Scalar(CommentScalar::new(group1, name, s.clone())),
    // Other TagValue variants are unreachable from this module's emission
    // paths; render via Debug to preserve diagnostic fidelity without
    // panicking. Verified by the test
    // `parse_inner_only_emits_str_list_bytes_variants` below.
    other => Comment::Scalar(CommentScalar::new(
      group1,
      name,
      SmolStr::from(format!("{other:?}")),
    )),
  }
}

// ===========================================================================
// `Taggable` — the golden-pattern emission path
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::diagnostics::Diagnose for Meta<'_> {
  /// OGG's diagnostics in the retired drain order: (a) the chained ID3
  /// sub-Meta's own warnings then errors (BEFORE the OGG body), (b) OGG's own
  /// accumulated warnings (`Lost synchronization` Ogg.pm:97, `Missing page(s)
  /// in Ogg file` Ogg.pm:158, `Format error in Vorbis comments` Vorbis.pm:208)
  /// in occurrence order. Byte-identical net `TagMap`.
  fn diagnostics(&self) -> std::vec::Vec<crate::diagnostics::Diagnostic> {
    let mut out = std::vec::Vec::new();
    #[cfg(feature = "id3")]
    if let Some(id3) = self.id3_ref() {
      out.extend(crate::diagnostics::Diagnose::diagnostics(id3));
    }
    out.extend(
      self
        .warnings()
        .iter()
        .map(|w| crate::diagnostics::Diagnostic::warn(w.as_str())),
    );
    out
  }
}

#[cfg(feature = "alloc")]
impl crate::emit::Taggable for Meta<'_> {
  /// Yield OGG tags in bundled `perl exiftool -j -G1` emission order:
  ///   0. The chained ID3 sub-Meta (Ogg.pm:79-83 embedded `ProcessID3`),
  ///      spliced FIRST — `File:ID3Size` + every `ID3v2_*:*` frame tag.
  ///   1. Vorbis identification fields (when present), Vorbis.pm:40-70
  ///      DECLARED-OFFSET order: VorbisVersion / AudioChannels / SampleRate /
  ///      MaximumBitrate / NominalBitrate / MinimumBitrate.
  ///   2. Opus header fields (when present), Opus.pm:36-51 DECLARED-OFFSET
  ///      order: OpusVersion / AudioChannels / SampleRate / OutputGain.
  ///   3. Vorbis comments in encounter order — vendor first, then KEY=VALUE
  ///      pairs (list-tags coalesced at first occurrence — faithful
  ///      FoundTag, ExifTool.pm:9505-9520).
  ///   3b. `METADATA_BLOCK_PICTURE` Picture sub-fields (Vorbis.pm:122-134 →
  ///      `%FLAC::Picture`), one block at a time.
  ///
  /// The golden-pattern parallel to the retired `serialize_tags`: the SINK
  /// changes (an [`EmittedTag`](crate::emit::EmittedTag) per value instead of
  /// `out.write_*`); the value variants (`TagValue::U64` for the
  /// identification / header / Picture integers, `TagValue::Str` for Vorbis
  /// scalars / bitrate-PrintConv / Picture MIME+Description, `TagValue::F64`
  /// for Opus OutputGain, `TagValue::List` for the Vorbis `List => 1`
  /// coalesce, `TagValue::Bytes` for CoverArt + the Picture binary), the
  /// emission ORDER, the ID3-chain position, and every PrintConv / ValueConv
  /// branch are preserved verbatim.
  ///
  /// `mode == PrintConv` (`-j`) ⇒ PrintConv strings (Vorbis bitrate →
  /// `ConvertBitrate`, e.g. `"128 kbps"`; Picture type → `"Front Cover"`);
  /// `mode == ValueConv` (`-n`) ⇒ post-ValueConv raw scalars (bitrate → raw
  /// u32). Opus OutputGain's ValueConv `10**($val/5120)` runs in BOTH modes
  /// (it's a ValueConv, not a PrintConv), so the toggle has no effect there.
  ///
  /// **Groups.** Vorbis identification + comments carry family-0/1 `"Vorbis"`
  /// (`%Vorbis::Identification` / `%Vorbis::Comments` group0 == group1);
  /// comments under a Theora stream keep family-0 `"Vorbis"` but family-1
  /// `"Theora"` (Ogg.pm:62 `SET_GROUP1`), so the per-comment group1 is
  /// preserved exactly. Opus header tags carry family-0/1 `"Opus"`
  /// (`%Opus::Header`). `METADATA_BLOCK_PICTURE` Picture sub-fields carry
  /// family-0/1 `"FLAC"` (the SubDirectory target `%FLAC::Picture`). Every
  /// OGG tag is a known tag ⇒ `unknown: false`.
  ///
  /// **List-tag note (Codex CF2).** Vorbis `List => 1` tags
  /// (ARTIST/PERFORMER/CONTACT, Vorbis.pm:85/86/94) were already coalesced
  /// into a single [`Comment::List`] at first-occurrence position during the
  /// parse (faithful `FoundTag`); we emit ONE `EmittedTag` carrying a
  /// `TagValue::List` of the values in encounter order — byte-identical to
  /// the retired `TagMap::write_str_list`.
  ///
  /// **Warnings are NOT part of this tag stream** ([`run_emission`](crate::emit::run_emission)
  /// has no warning/error channel). The chained ID3 sub-Meta's warnings/errors
  /// and OGG's own accumulated warnings (`Lost synchronization` Ogg.pm:97,
  /// `Missing page(s) in Ogg file` Ogg.pm:158, `Format error in Vorbis
  /// comments` Vorbis.pm:208) are drained by the `AnyMeta::Ogg` dispatch arm
  /// AFTER `run_emission`, in the same order the retired `serialize_tags`
  /// emitted them (ID3 warnings then errors — they were written during the
  /// top-of-fn `id3.serialize_tags` call — then OGG's own warnings), so the
  /// net `TagMap` stays byte-identical.
  ///
  /// The File:* triplet (and the `OverrideFileType` OGV/OPUS decision) is NOT
  /// emitted here — that is the engine ([`crate::parser::extract_info`])
  /// `SetFileType` / `finalize_file_type` responsibility.
  fn tags(
    &self,
    mode: crate::emit::ConvMode,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    use crate::emit::EmittedTag;
    use crate::value::{Group, TagValue};

    let print_conv = matches!(mode, crate::emit::ConvMode::PrintConv);
    // family-0 == family-1 per sub-table: Vorbis identification/comments →
    // "Vorbis" (comments may override family-1 to "Theora"); Opus header →
    // "Opus". (`%Vorbis::Identification`/`%Vorbis::Comments`/`%Opus::Header`
    // each set group0 == group1.)
    let vorbis_group = || Group::new("Vorbis", "Vorbis");
    let opus_group = || Group::new("Opus", "Opus");

    let mut tags: Vec<EmittedTag> = Vec::new();

    // (0) Chained ID3 sub-Meta (Ogg.pm:79-83 embedded `ProcessID3`). Bundled
    // runs `ProcessID3` BEFORE the OGG container walk — `File:ID3Size` + every
    // `ID3v2_*:*` frame tag precede any Vorbis:* / Opus:* tag. The retired
    // sink called `id3.serialize_tags(print_conv, out)` at this exact point;
    // `Id3Meta` is `Taggable`, so its tags flow through the same engine here.
    // Its warnings/errors are drained by the `AnyMeta::Ogg` arm (matching the
    // retired position — see fn docs).
    #[cfg(feature = "id3")]
    if let Some(id3) = self.id3.as_ref() {
      tags.extend(id3.tags(mode));
    }

    // (1) Vorbis identification (Vorbis.pm:40-70). DECLARED-OFFSET order:
    // VorbisVersion (0), AudioChannels (4), SampleRate (5), MaximumBitrate
    // (9), NominalBitrate (13), MinimumBitrate (17). R3 F3 (per-field,
    // faithful ProcessBinaryData): every field is optional — emit only when
    // the parse populated it (ExifTool.pm:9927 iterate-and-skip).
    if let Some(id) = self.vorbis_identification {
      if let Some(v) = id.vorbis_version() {
        tags.push(EmittedTag::new(
          vorbis_group(),
          "VorbisVersion".into(),
          TagValue::U64(u64::from(v)),
          false,
        ));
      }
      if let Some(v) = id.audio_channels() {
        tags.push(EmittedTag::new(
          vorbis_group(),
          "AudioChannels".into(),
          TagValue::U64(u64::from(v)),
          false,
        ));
      }
      if let Some(v) = id.sample_rate() {
        tags.push(EmittedTag::new(
          vorbis_group(),
          "SampleRate".into(),
          TagValue::U64(u64::from(v)),
          false,
        ));
      }
      // Bitrate fields: RawConv `$val || undef` drops the zero case (already
      // filtered to `None` in `parse_vorbis_identification`); PrintConv runs
      // `ConvertBitrate` for `-j`, raw bps for `-j -n`.
      if let Some(bps) = id.maximum_bitrate() {
        tags.push(bitrate_tag("MaximumBitrate", bps, print_conv));
      }
      if let Some(bps) = id.nominal_bitrate() {
        tags.push(bitrate_tag("NominalBitrate", bps, print_conv));
      }
      if let Some(bps) = id.minimum_bitrate() {
        tags.push(bitrate_tag("MinimumBitrate", bps, print_conv));
      }
    }

    // (2) Opus header (Opus.pm:36-51). DECLARED-OFFSET order: OpusVersion
    // (0), AudioChannels (1), SampleRate (4), OutputGain (8). R3 F3
    // (per-field): emit only the in-range subset.
    if let Some(h) = self.opus_header {
      if let Some(v) = h.opus_version() {
        tags.push(EmittedTag::new(
          opus_group(),
          "OpusVersion".into(),
          TagValue::U64(u64::from(v)),
          false,
        ));
      }
      if let Some(v) = h.audio_channels() {
        tags.push(EmittedTag::new(
          opus_group(),
          "AudioChannels".into(),
          TagValue::U64(u64::from(v)),
          false,
        ));
      }
      if let Some(v) = h.sample_rate() {
        tags.push(EmittedTag::new(
          opus_group(),
          "SampleRate".into(),
          TagValue::U64(u64::from(v)),
          false,
        ));
      }
      // OutputGain post-ValueConv (`10**(raw/5120)`) — a bare number (`1`
      // when raw is 0, the common in-spec case). The serializer's JSON-number
      // gate renders integer-valued f64 without a trailing `.0`, matching
      // Perl's stringification.
      if let Some(g) = h.output_gain() {
        tags.push(EmittedTag::new(
          opus_group(),
          "OutputGain".into(),
          TagValue::F64(g),
          false,
        ));
      }
    }

    // (3) Vorbis comments (vendor + KEY=VALUE) — encounter order with
    // list-coalescing already applied during the parse (Codex CF2). Each
    // comment carries its own resolved family-1 group ("Vorbis", or "Theora"
    // under a Theora stream); family-0 stays "Vorbis" (the tag-table group0,
    // preserved on `SET_GROUP1` — Ogg.pm:62).
    for comment in &self.comments {
      match comment {
        Comment::Scalar(s) => {
          tags.push(EmittedTag::new(
            Group::new("Vorbis", s.group1()),
            s.name().into(),
            TagValue::Str(s.value().into()),
            false,
          ));
        }
        Comment::List(l) => {
          let items: Vec<TagValue> = l
            .values_slice()
            .iter()
            .map(|v| TagValue::Str(v.as_str().into()))
            .collect();
          tags.push(EmittedTag::new(
            Group::new("Vorbis", l.group1()),
            l.name().into(),
            TagValue::List(items),
            false,
          ));
        }
        Comment::Binary(b) => {
          tags.push(EmittedTag::new(
            Group::new("Vorbis", b.group1()),
            b.name().into(),
            TagValue::Bytes(b.bytes().to_vec()),
            false,
          ));
        }
      }
    }

    // (3b) `METADATA_BLOCK_PICTURE` payloads (Vorbis.pm:122-134 →
    // `%FLAC::Picture` FLAC.pm:84-134). Each Picture sub-field is emitted
    // under the `FLAC` family-1 group with the same names FLAC's own
    // `push_picture_tags` uses, so the value-multiset stays byte-for-byte.
    for p in &self.pictures {
      push_ogg_picture_tags(&mut tags, p, print_conv);
    }

    tags.into_iter()
  }
}

/// Build a single Vorbis bitrate `EmittedTag` (`MaximumBitrate` /
/// `NominalBitrate` / `MinimumBitrate`). `bps` is the raw u32 value (already
/// filtered against the `$val || undef` RawConv). The PrintConv path renders
/// through [`crate::convert::write_convert_bitrate`] (the bundled
/// `ConvertBitrate`, e.g. `"128 kbps"`) into a `TagValue::Str` — byte-
/// identical to the retired `out.write_fmt(...)`; the `-n` path emits the raw
/// u32 as `TagValue::U64`.
#[cfg(feature = "alloc")]
fn bitrate_tag(name: &'static str, bps: u32, print_conv: bool) -> crate::emit::EmittedTag {
  use crate::emit::EmittedTag;
  use crate::value::{Group, TagValue};
  let group = Group::new("Vorbis", "Vorbis");
  if print_conv {
    let mut s = std::string::String::new();
    let _ = crate::convert::write_convert_bitrate(&mut s, f64::from(bps));
    EmittedTag::new(group, name.into(), TagValue::Str(s.into()), false)
  } else {
    EmittedTag::new(group, name.into(), TagValue::U64(u64::from(bps)), false)
  }
}

/// Push one [`OggPicture`]'s tags in faithful FLAC.pm:84-134 order onto
/// `tags` (R3 F2: Vorbis `METADATA_BLOCK_PICTURE` SubDirectory hop into
/// `%FLAC::Picture`, Vorbis.pm:122-134). Mirrors `flac::push_picture_tags`:
/// `TagValue::Str` for PictureType (PrintConv) / MIME / Description,
/// `TagValue::U64` for the numeric fields (incl. PictureType under `-n` and
/// on a PrintConv hash miss), `TagValue::Bytes` for the Picture binary.
/// Drops the Picture sub-field iff `length > 0 && data.is_empty()`
/// (ExifTool::ReadValue clamp at ExifTool.pm:6292 `count < 1 and return
/// undef`).
#[cfg(feature = "alloc")]
fn push_ogg_picture_tags(
  tags: &mut Vec<crate::emit::EmittedTag>,
  p: &OggPicture,
  print_conv: bool,
) {
  use crate::emit::EmittedTag;
  use crate::value::{Group, TagValue};
  let group = || Group::new("FLAC", "FLAC");
  // PictureType — PrintConv hash (FLAC.pm:88-113). On a hash miss the Perl
  // default falls back to the numeric value as a string (we emit raw u32).
  let picture_type = if print_conv {
    match p.picture_type_name() {
      Some(name) => TagValue::Str(name.into()),
      None => TagValue::U64(u64::from(p.picture_type())),
    }
  } else {
    TagValue::U64(u64::from(p.picture_type()))
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
    TagValue::U64(u64::from(p.width())),
    false,
  ));
  tags.push(EmittedTag::new(
    group(),
    "PictureHeight".into(),
    TagValue::U64(u64::from(p.height())),
    false,
  ));
  tags.push(EmittedTag::new(
    group(),
    "PictureBitsPerPixel".into(),
    TagValue::U64(u64::from(p.bits_per_pixel())),
    false,
  ));
  tags.push(EmittedTag::new(
    group(),
    "PictureIndexedColors".into(),
    TagValue::U64(u64::from(p.indexed_colors())),
    false,
  ));
  tags.push(EmittedTag::new(
    group(),
    "PictureLength".into(),
    TagValue::U64(u64::from(p.length())),
    false,
  ));
  // Picture binary — same skip-on-zero-payload sentinel as FLAC
  // (FLAC.pm:128-133 + ExifTool.pm:6292 ReadValue clamp).
  if p.length() > 0 && p.data().is_empty() {
    // Faithful skip — bundled ReadValue returns undef ⇒ no tag.
  } else {
    tags.push(EmittedTag::new(
      group(),
      "Picture".into(),
      TagValue::Bytes(p.data().to_vec()),
      false,
    ));
  }
}

// ===========================================================================
// `Project` — the normalized cross-format domain projection (golden L2)
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::metadata::Project for Meta<'_> {
  /// Project OGG metadata onto the normalized
  /// [`MediaMetadata`](crate::metadata::MediaMetadata) domain.
  ///
  /// OGG (Vorbis / Opus / Theora-comments) is treated here as an audio
  /// container: it carries no camera / lens / GPS / capture facts (those
  /// domains stay `None`). The single structural contribution is one audio
  /// [`TrackKind`](crate::metadata::TrackKind) — `%Vorbis::Identification`
  /// (Vorbis.pm:42) and `%Opus::Header` (Opus.pm:38) both set
  /// `GROUPS{2} => 'Audio'`.
  ///
  /// **Duration is `None`.** Unlike FLAC (which exposes a clean decoded
  /// `Composite:Duration` from `TotalSamples / SampleRate`), OGG's
  /// `Composite:Duration` (Vorbis.pm:138-147) needs the Composite engine +
  /// a `File:FileSize` source and is on the formally-accepted deferral list
  /// (see the module-level "Deliberate Phase-2 deferrals" note); the typed
  /// [`Meta`] exposes no decoded `Option<Duration>` accessor, so there is
  /// nothing clean to surface here. Dimensions / created stay `None` too.
  fn project(&self) -> crate::metadata::MediaMetadata {
    use crate::metadata::TrackKind;
    let mut media = crate::metadata::MediaMetadata::new();
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
// contract (Phase C w2b); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;
  use crate::emit::{ConvMode, Taggable};
  use crate::tagmap::TagMap;

  /// Drive a typed [`Meta`] through the golden [`run_emission`](crate::emit)
  /// engine PLUS the `AnyMeta::Ogg` arm's warning/error drain, in the SAME
  /// order the arm uses: (a) the chained ID3 sub-Meta's warnings then errors,
  /// (b) OGG's own accumulated warnings in occurrence order. Mirrors
  /// `format_parser.rs` exactly so the in-module tests exercise the same net
  /// `TagMap` the engine produces. `print_conv` ⇒ `-j`, else `-n`.
  fn emit_via_engine(meta: &Meta<'_>, print_conv: bool, out: &mut TagMap) {
    crate::emit::run_emission(meta, ConvMode::from_print_conv(print_conv), out);
    crate::diagnostics::run_diagnostics(meta, out);
  }

  // `convert_bitrate` unit-tests live next to the helper in `convert.rs`
  // (the helper itself moved out of `formats/moi.rs` into `convert.rs` in
  // R2 F-OGG-TRIM so both `formats/moi.rs` and `formats/ogg.rs` can share
  // the faithful port). The breakpoints under `moi::tests` already cover
  // the bundled oracle (50, 999, 1000, 32000, 128000, 224000, 8.5e6, 1.5e9).

  #[test]
  fn base64_decode_examples() {
    // RFC 4648 test vectors.
    assert_eq!(base64_decode(""), b"");
    assert_eq!(base64_decode("Zg=="), b"f");
    assert_eq!(base64_decode("Zm8="), b"fo");
    assert_eq!(base64_decode("Zm9v"), b"foo");
    assert_eq!(base64_decode("Zm9vYg=="), b"foob");
    assert_eq!(base64_decode("Zm9vYmFy"), b"foobar");
    // Whitespace is ignored.
    assert_eq!(base64_decode("Zm9v\nYmFy"), b"foobar");
  }

  #[test]
  fn vorbis_comment_compute_name_examples() {
    // MEDIAJUKEBOX:TOOL NAME -> MediajukeboxToolName (per Vorbis.pm:190-193).
    assert_eq!(
      vorbis_comment_compute_name("MEDIAJUKEBOX:TOOL NAME"),
      "MediajukeboxToolName"
    );
    assert_eq!(
      vorbis_comment_compute_name("MEDIAJUKEBOX:TOOL VERSION"),
      "MediajukeboxToolVersion"
    );
    assert_eq!(
      vorbis_comment_compute_name("MEDIAJUKEBOX:DATE"),
      "MediajukeboxDate"
    );
    // Simple key (no non-word chars) — just ucfirst(lc).
    assert_eq!(vorbis_comment_compute_name("FOO"), "Foo");
    assert_eq!(vorbis_comment_compute_name("BAR_BAZ"), "BarBaz");
  }

  #[test]
  fn vorbis_comment_compute_name_mutate_and_resume() {
    // Codex round-3 F2: the second regex `s/([a-z0-9])_([a-z])/$1\U$2/g`
    // is `/g`-global with Perl's mutate-and-resume cursor semantics —
    // each replacement advances `pos()` past the END of the substituted
    // text, so the next match attempt sees the just-uppercased character
    // and the trailing `_x` segment is preserved (`B_x` does NOT match
    // because `B` is now uppercase). Oracle: `perl -e '$s=...; $s =~
    // s/[^\w-]+(.?)/\U$1/sg; $s =~ s/([a-z0-9])_([a-z])/$1\U$2/g; print
    // $s'` against bundled Perl 13.58. Every expected RHS below was
    // captured from that oracle.
    let cases: &[(&str, &str)] = &[
      ("TRACK_A_B", "TrackA_b"),
      ("SOMETHING_X_Y", "SomethingX_y"),
      ("FOO_BAR_X_Y", "FooBarX_y"),
      ("KEY_A_LONG_NAME", "KeyA_longName"),
      ("A_B_C_D_E", "A_bC_dE"),
      // Multi-letter segments behave the same as before.
      ("FOO_BAR", "FooBar"),
      ("MEDIAJUKEBOX_TOOL_NAME", "MediajukeboxToolName"),
      // Single-segment pair: no chain to expose the bug.
      ("A_B", "A_b"),
      // Trailing single-letter with prior multi-letter segment.
      ("FOO_BAR_X", "FooBarX"),
      // Lone underscore-prefixed (after ucfirst+lc, first char stays
      // uppercase, so second regex never matches the first underscore).
      ("X_Y", "X_y"),
      // Digit-then-letter is faithful: `[a-z0-9]` includes digits.
      ("A1_B_C_D", "A1B_cD"),
      // Multiple non-word chunks (first regex strips them, uppercases
      // the next char — that next char becomes uppercase, so the second
      // regex won't fire across it).
      ("MEDIAJUKEBOX:TOOL NAME", "MediajukeboxToolName"),
    ];
    for &(input, expected) in cases {
      let got = vorbis_comment_compute_name(input);
      assert_eq!(
        got, expected,
        "vorbis_comment_compute_name({input:?}) == {got:?}, expected {expected:?} \
         (Perl oracle: bundled 13.58)"
      );
    }
  }

  #[test]
  fn is_special_tag_full_perl_hash() {
    // Codex round-3 F1: `%specialTags` (ExifTool.pm:1228-1236) has 28
    // keys. Oracle: `perl -e 'use Image::ExifTool; print join(",", sort
    // keys %Image::ExifTool::specialTags)'` against bundled 13.58.
    // EVERY key below was emitted by that command; NO others were.
    let perl_keys = [
      "AVOID",
      "CHECK_PROC",
      "DATAMEMBER",
      "EXTRACT_UNKNOWN",
      "FIRST_ENTRY",
      "FORMAT",
      "GROUPS",
      "INIT_TABLE",
      "IS_OFFSET",
      "IS_SUBDIR",
      "LANG_INFO",
      "NAMESPACE",
      "NOTES",
      "PERMANENT",
      "PREFERRED",
      "PRINT_CONV",
      "PRIORITY",
      "PROCESS_PROC",
      "SET_GROUP1",
      "SHORT_NAME",
      "SRC_TABLE",
      "TABLE_DESC",
      "TABLE_NAME",
      "TAG_PREFIX",
      "VARS",
      "WRITABLE",
      "WRITE_GROUP",
      "WRITE_PROC",
    ];
    for key in perl_keys {
      assert!(
        is_special_tag(key),
        "is_special_tag({key:?}) must be true (key in bundled Perl %specialTags)"
      );
    }
    // Negative checks: a few common Vorbis-comment tokens that are NOT
    // in `%specialTags`. Includes the three keys the previous stub
    // erroneously had (`PARENT`, `DID_TAG_ID`, `ID3`).
    let not_in_perl = [
      "TITLE",
      "ARTIST",
      "ALBUM",
      "DATE",
      "TRACKNUMBER",
      "GENRE",
      "PARENT",     // was in stub, not in Perl
      "DID_TAG_ID", // was in stub, not in Perl
      "ID3",        // was in stub, not in Perl
    ];
    for key in not_in_perl {
      assert!(
        !is_special_tag(key),
        "is_special_tag({key:?}) must be false (key NOT in bundled Perl %specialTags)"
      );
    }
  }

  #[test]
  fn process_vorbis_comments_synthesises_special_tag_underscore_suffix() {
    // Codex round-3 F1: any comment KEY that hits `%specialTags`
    // (Vorbis.pm:180) gets a trailing `_` appended BEFORE the name
    // synthesis runs. Pin a handful of the previously-missing keys to
    // verify the lookup is wired through `process_vorbis_comments`.
    let vendor = b"vendor";
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&(vendor.len() as u32).to_le_bytes());
    data.extend_from_slice(vendor);
    let entries: &[&[u8]] = &[
      b"NAMESPACE=ns",
      b"AVOID=av",
      b"IS_OFFSET=io",
      b"LANG_INFO=li",
      b"TAG_PREFIX=tp",
      b"PREFERRED=pf",
      // A non-special key for contrast: must NOT get `_` suffix.
      b"TITLE=Plain",
    ];
    data.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
      data.extend_from_slice(&(e.len() as u32).to_le_bytes());
      data.extend_from_slice(e);
    }
    let mut meta = Metadata::new("x.ogg");
    let mut pictures: Vec<OggPicture> = Vec::new();
    assert!(process_vorbis_comments(
      &data,
      &mut meta,
      &mut pictures,
      true
    ));
    let names: Vec<&str> = meta.tags_slice().iter().map(|t| t.name()).collect();
    // Order: Vendor first, then comments in insertion order.
    assert_eq!(
      names,
      vec![
        "Vendor",
        "Namespace_",
        "Avoid_",
        "IsOffset_",
        "LangInfo_",
        "TagPrefix_",
        "Preferred_",
        "Title",
      ]
    );
  }

  #[test]
  fn classify_packet_recognizes_vorbis_theora_opus_flac() {
    assert!(classify_packet(b"\x01vorbis ...").is_some());
    assert!(classify_packet(b"\x03vorbis ...").is_some());
    assert!(classify_packet(b"\x80theora ...").is_some());
    assert!(classify_packet(b"OpusHead-blob").is_some());
    assert!(classify_packet(b"OpusTags-blob").is_some());
    assert!(classify_packet(b"\x7fFLAC..").is_some());
    assert!(classify_packet(b"random").is_none());
  }

  #[test]
  fn process_vorbis_comments_parses_simple_block() {
    // 4-byte LE vendor length + vendor + 4-byte LE num + entries.
    let vendor = b"vend";
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&(vendor.len() as u32).to_le_bytes());
    data.extend_from_slice(vendor);
    let entries: &[&[u8]] = &[b"TITLE=Hello", b"ARTIST=Alice", b"ARTIST=Bob"];
    data.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
      data.extend_from_slice(&(e.len() as u32).to_le_bytes());
      data.extend_from_slice(e);
    }
    let mut meta = Metadata::new("x.ogg");
    let mut pictures: Vec<OggPicture> = Vec::new();
    assert!(process_vorbis_comments(
      &data,
      &mut meta,
      &mut pictures,
      true
    ));
    // Vendor first, then Title, then a single Artist as a List of 2.
    let names: Vec<&str> = meta.tags_slice().iter().map(|t| t.name()).collect();
    assert_eq!(names, vec!["Vendor", "Title", "Artist"]);
    let artist = meta
      .tags_slice()
      .iter()
      .find(|t| t.name() == "Artist")
      .unwrap();
    if let TagValue::List(items) = artist.value_ref() {
      assert_eq!(items.len(), 2);
      assert_eq!(items[0], TagValue::Str("Alice".into()));
      assert_eq!(items[1], TagValue::Str("Bob".into()));
    } else {
      panic!("Artist should be List, got {:?}", artist.value_ref());
    }
  }

  #[test]
  fn process_vorbis_comments_warns_on_truncation() {
    // Vendor-length larger than available data.
    let data: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
    let mut meta = Metadata::new("x.ogg");
    let mut pictures: Vec<OggPicture> = Vec::new();
    assert!(!process_vorbis_comments(
      &data,
      &mut meta,
      &mut pictures,
      true
    ));
    assert_eq!(meta.warnings_slice()[0], "Format error in Vorbis comments");
  }

  // R2 F-OGG-TRIM: the Vorbis::Identification + Opus::Header binary
  // tables are NOW ported here, see the `parse_vorbis_identification` +
  // `parse_opus_header` helpers and their unit tests
  // (`vorbis_identification_typical_payload`,
  // `vorbis_identification_short_payload_rejected`,
  // `vorbis_identification_all_bitrates_nonzero`,
  // `opus_header_typical_payload`, `opus_header_nonzero_output_gain`,
  // `opus_header_short_payload_rejected`,
  // `vorbis_identification_emits_in_declared_offset_order`,
  // `vorbis_identification_n_mode_emits_raw_bitrate`,
  // `opus_header_serialize_emits_declared_order`). Theora::Identification
  // remains deferred until the dedicated Theora.pm PR.

  #[test]
  fn process_vorbis_comments_with_group1_retags_to_theora() {
    // Theora.pm:32-37 + Ogg.pm:62: Vorbis::Comments under a Theora stream
    // emits family-1 "Theora" instead of "Vorbis".
    let vendor = b"theora vendor";
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&(vendor.len() as u32).to_le_bytes());
    data.extend_from_slice(vendor);
    let entries: &[&[u8]] = &[b"TITLE=Movie"];
    data.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
      data.extend_from_slice(&(e.len() as u32).to_le_bytes());
      data.extend_from_slice(e);
    }
    let mut meta = Metadata::new("x.ogv");
    let mut pictures: Vec<OggPicture> = Vec::new();
    assert!(process_vorbis_comments_with_group1(
      &data,
      &mut meta,
      &mut pictures,
      true,
      "Theora"
    ));
    for t in meta.tags_slice() {
      // Family-0 stays "Vorbis" (from the tag table); family-1 is "Theora".
      assert_eq!(t.group_ref().family0(), "Vorbis");
      assert_eq!(t.group_ref().family1(), "Theora");
    }
  }

  #[test]
  fn classify_packet_rejects_short_buffers() {
    assert!(classify_packet(&[]).is_none());
    assert!(classify_packet(b"Op").is_none());
    assert!(classify_packet(b"\x01vorbi").is_none()); // missing trailing 's'
  }

  #[test]
  fn process_ogg_short_buffer_rejects_cleanly() {
    // Only the 4-byte `OggS` magic — header is far short of the 28-byte
    // minimum Ogg.pm:94 demands. The engine does not finalize OGG; the
    // post-loop emits a finalization error instead. (See also
    // `tests/conformance.rs::ogg_truncated_error_conformance`.)
    let json = crate::parser::extract_info("x.ogg", b"OggS", true);
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    let obj = v.as_array().unwrap()[0].as_object().unwrap();
    assert_ne!(
      obj.get("File:FileType").and_then(|x| x.as_str()),
      Some("OGG")
    );
  }

  // -------------------------------------------------------------------------
  // Lib-first typed Meta surface
  // -------------------------------------------------------------------------

  #[test]
  fn parse_borrowed_rejects_short_buffer() {
    // 4-byte OggS magic only — ProcessOGG never accepts a page, so success
    // is false but the typed Meta still exists with empty comments/warnings.
    let meta = parse_borrowed(b"OggS", true).expect("meta");
    assert!(!meta.success());
    assert!(meta.comments().is_empty());
    assert!(meta.warnings().is_empty());
    assert_eq!(meta.file_type_override(), None);
  }

  #[test]
  fn meta_sinker_emits_vorbis_scalars() {
    // Drive a typed Meta with a vendor + a non-list scalar; verify
    // serialize_tags emits both via write_str.
    let meta = Meta {
      #[cfg(feature = "id3")]
      id3: None,
      pictures: vec![],
      file_type_override: None,
      vorbis_identification: None,
      opus_header: None,
      comments: vec![
        Comment::Scalar(CommentScalar::new("Vorbis", "Vendor", "test vendor")),
        Comment::Scalar(CommentScalar::new("Vorbis", "Title", "Song")),
      ],
      warnings: vec![],
      success: true,
      _marker: core::marker::PhantomData,
    };
    let mut w = TagMap::new();
    emit_via_engine(&meta, true, &mut w);
    assert_eq!(
      w.get_str("Vorbis", "Vendor"),
      Some("test vendor".to_string())
    );
    assert_eq!(w.get_str("Vorbis", "Title"), Some("Song".to_string()));
  }

  /// Codex CF2: the typed `serialize_tags` List arm reaches
  /// `TagMap::write_str_list`, so a `TagMap` consumer gets a
  /// coalesced first-occurrence-position `TagValue::List` (faithful
  /// `FoundTag`, ExifTool.pm:9505-9520) instead of last-write-wins. Vorbis
  /// List=>1 tags: ARTIST/PERFORMER/CONTACT.
  #[test]
  fn meta_sinker_list_coalesces_into_tagvalue_list_via_json_writer() {
    use crate::value::TagValue;
    let meta = Meta {
      #[cfg(feature = "id3")]
      id3: None,
      pictures: vec![],
      file_type_override: None,
      vorbis_identification: None,
      opus_header: None,
      comments: vec![
        // A scalar BEFORE the list to pin first-occurrence position.
        Comment::Scalar(CommentScalar::new("Vorbis", "Title", "Song")),
        Comment::List(CommentList::new(
          "Vorbis",
          "Artist",
          vec![SmolStr::from("Alice"), SmolStr::from("Bob")],
        )),
      ],
      warnings: vec![],
      success: true,
      _marker: core::marker::PhantomData,
    };
    let mut md = TagMap::new();
    emit_via_engine(&meta, true, &mut md);
    let artist = md.get("Vorbis", "Artist").expect("Artist tag");
    match artist {
      TagValue::List(items) => {
        assert_eq!(items.len(), 2);
        assert!(matches!(&items[0], TagValue::Str(s) if s == "Alice"));
        assert!(matches!(&items[1], TagValue::Str(s) if s == "Bob"));
      }
      other => panic!("expected coalesced TagValue::List, got {other:?}"),
    }
  }

  #[test]
  fn meta_sinker_emits_warnings() {
    // A typed Meta with no comments but two warnings — serialize_tags
    // routes them to write_warning.
    let meta = Meta {
      #[cfg(feature = "id3")]
      id3: None,
      pictures: vec![],
      file_type_override: None,
      vorbis_identification: None,
      opus_header: None,
      comments: vec![],
      warnings: vec![
        SmolStr::from("Lost synchronization"),
        SmolStr::from("Missing page(s) in Ogg file"),
      ],
      success: false,
      _marker: core::marker::PhantomData,
    };
    let mut w = TagMap::new();
    emit_via_engine(&meta, true, &mut w);
    assert_eq!(
      w.warnings(),
      &[
        "Lost synchronization".to_string(),
        "Missing page(s) in Ogg file".to_string()
      ]
    );
  }

  #[test]
  fn format_parser_trait_returns_borrowed_meta() {
    // GAT path: `Meta<'a> = Meta<'a>` (phantom `'a`). Drive the trait
    // API with empty bytes and confirm the shape.
    let meta: Meta<'_> = <ProcessOgg as FormatParser>::parse(&ProcessOgg, b"").expect("meta");
    assert!(!meta.success());
  }

  #[test]
  fn typed_meta_owns_its_data() {
    // The typed Meta carries owned SmolStr/Vec<u8> (the `'a` lifetime is
    // phantom). Verify field accessors round-trip.
    let meta = Meta {
      #[cfg(feature = "id3")]
      id3: None,
      pictures: vec![],
      file_type_override: Some("OPUS"),
      vorbis_identification: None,
      opus_header: None,
      comments: vec![Comment::Scalar(CommentScalar::new("Vorbis", "Vendor", "v"))],
      warnings: vec![SmolStr::from("Lost synchronization")],
      success: true,
      _marker: core::marker::PhantomData,
    };
    assert_eq!(meta.file_type_override(), Some("OPUS"));
    assert!(meta.success());
    assert_eq!(meta.warnings(), &[SmolStr::from("Lost synchronization")]);
    assert_eq!(meta.comments().len(), 1);
    // §2: predicate + unwrap accessor on the public enum.
    let c = &meta.comments()[0];
    assert!(c.is_scalar());
    assert_eq!(c.unwrap_scalar_ref().value(), "v");
  }

  #[test]
  fn vorbis_identification_typical_payload() {
    // Synthetic Vorbis identification payload — 21 bytes minimum:
    //   offset 0..4   VorbisVersion = 0 (little-endian u32)
    //   offset 4      AudioChannels = 2
    //   offset 5..9   SampleRate = 44100
    //   offset 9..13  MaximumBitrate = 0 (RawConv `$val || undef` ⇒ None)
    //   offset 13..17 NominalBitrate = 128000
    //   offset 17..21 MinimumBitrate = 0 ⇒ None
    let mut payload = [0u8; 23];
    // VorbisVersion = 0 (already zeroed)
    payload[4] = 2; // AudioChannels = 2
    payload[5..9].copy_from_slice(&44100u32.to_le_bytes()); // SampleRate
    // MaximumBitrate = 0 (already zeroed)
    payload[13..17].copy_from_slice(&128_000u32.to_le_bytes()); // NominalBitrate
    // MinimumBitrate = 0
    let id = parse_vorbis_identification(&payload).expect("21-byte payload accepted");
    assert_eq!(id.vorbis_version(), Some(0));
    assert_eq!(id.audio_channels(), Some(2));
    assert_eq!(id.sample_rate(), Some(44100));
    assert_eq!(
      id.maximum_bitrate(),
      None,
      "zero bitrate dropped via RawConv"
    );
    assert_eq!(id.nominal_bitrate(), Some(128_000));
    assert_eq!(id.minimum_bitrate(), None);
  }

  #[test]
  fn vorbis_identification_empty_payload_rejected() {
    // R3 F3: per-field semantics. An EMPTY payload yields `None` (the helper
    // returns `None` only when not even VorbisVersion fits).
    let payload = [0u8; 0];
    assert!(parse_vorbis_identification(&payload).is_none());
  }

  #[test]
  fn vorbis_identification_short_payload_per_field_emit() {
    // R3 F3: per-FIELD offset-checked extraction. A 9-byte payload (covers
    // offsets 0..4 VorbisVersion, 4 AudioChannels, 5..9 SampleRate, but
    // NOT 9..13 MaximumBitrate / 13..17 NominalBitrate / 17..21
    // MinimumBitrate) emits only the in-range subset. Bundled
    // ProcessBinaryData (ExifTool.pm:9927 `next if $entry >= $size`)
    // does exactly this — the pre-fix all-or-nothing reject violated
    // faithfulness.
    let mut payload = [0u8; 9];
    payload[0..4].copy_from_slice(&0u32.to_le_bytes()); // VorbisVersion = 0
    payload[4] = 2; // AudioChannels
    payload[5..9].copy_from_slice(&44_100u32.to_le_bytes()); // SampleRate
    let id = parse_vorbis_identification(&payload).expect("9 bytes ⇒ Some(partial)");
    assert_eq!(id.vorbis_version(), Some(0));
    assert_eq!(id.audio_channels(), Some(2));
    assert_eq!(id.sample_rate(), Some(44_100));
    assert_eq!(
      id.maximum_bitrate(),
      None,
      "offset 9 out of bounds at len 9"
    );
    assert_eq!(id.nominal_bitrate(), None, "offset 13 out of bounds");
    assert_eq!(id.minimum_bitrate(), None, "offset 17 out of bounds");
  }

  #[test]
  fn vorbis_identification_just_first_field() {
    // R3 F3: a 4-byte payload covers ONLY VorbisVersion; all other fields
    // are out of bounds and emit `None`.
    let payload = 42u32.to_le_bytes();
    let id = parse_vorbis_identification(&payload).expect("4 bytes ⇒ Some(version-only)");
    assert_eq!(id.vorbis_version(), Some(42));
    assert_eq!(id.audio_channels(), None);
    assert_eq!(id.sample_rate(), None);
    assert_eq!(id.maximum_bitrate(), None);
    assert_eq!(id.nominal_bitrate(), None);
    assert_eq!(id.minimum_bitrate(), None);
  }

  #[test]
  fn vorbis_identification_too_short_for_first_field() {
    // R3 F3: a 3-byte payload doesn't even cover VorbisVersion (offset 0,
    // width 4); the helper returns `None` so the caller treats this as
    // "no identification packet seen".
    let payload = [0u8; 3];
    assert!(parse_vorbis_identification(&payload).is_none());
  }

  #[test]
  fn vorbis_identification_all_bitrates_nonzero() {
    // All three bitrate fields non-zero: each becomes Some(raw).
    let mut payload = [0u8; 21];
    payload[4] = 1;
    payload[5..9].copy_from_slice(&48_000u32.to_le_bytes());
    payload[9..13].copy_from_slice(&320_000u32.to_le_bytes());
    payload[13..17].copy_from_slice(&192_000u32.to_le_bytes());
    payload[17..21].copy_from_slice(&64_000u32.to_le_bytes());
    let id = parse_vorbis_identification(&payload).unwrap();
    assert_eq!(id.audio_channels(), Some(1));
    assert_eq!(id.sample_rate(), Some(48_000));
    assert_eq!(id.maximum_bitrate(), Some(320_000));
    assert_eq!(id.nominal_bitrate(), Some(192_000));
    assert_eq!(id.minimum_bitrate(), Some(64_000));
  }

  #[test]
  fn opus_header_typical_payload() {
    // Synthetic Opus header payload — at least 10 bytes:
    //   offset 0   OpusVersion = 1
    //   offset 1   AudioChannels = 2
    //   offset 2..4 PreSkip (int16u, NOT emitted per Opus.pm:41 comment)
    //   offset 4..8 SampleRate = 48000 (int32u LE)
    //   offset 8..10 OutputGain raw int16u = 0 ⇒ 10**(0/5120) = 1.0
    let mut payload = [0u8; 19];
    payload[0] = 1;
    payload[1] = 2;
    payload[4..8].copy_from_slice(&48_000u32.to_le_bytes());
    // OutputGain raw stays 0.
    let header = parse_opus_header(&payload).expect("10-byte payload accepted");
    assert_eq!(header.opus_version(), Some(1));
    assert_eq!(header.audio_channels(), Some(2));
    assert_eq!(header.sample_rate(), Some(48_000));
    // 10 ** (0 / 5120) = 10^0 = 1.0 exactly.
    let gain = header.output_gain().expect("output_gain present");
    assert!((gain - 1.0).abs() < 1e-12);
  }

  #[test]
  fn opus_header_nonzero_output_gain() {
    // OutputGain raw = 5120 ⇒ 10**(5120/5120) = 10.0
    let mut payload = [0u8; 10];
    payload[0] = 1;
    payload[1] = 1;
    payload[4..8].copy_from_slice(&48_000u32.to_le_bytes());
    payload[8..10].copy_from_slice(&5120u16.to_le_bytes());
    let header = parse_opus_header(&payload).unwrap();
    let gain = header.output_gain().expect("output_gain present");
    assert!(
      (gain - 10.0).abs() < 1e-10,
      "10^(5120/5120) must be exactly 10.0, got {gain}"
    );
  }

  #[test]
  fn opus_header_empty_payload_rejected() {
    // R3 F3: an EMPTY payload yields None (not even OpusVersion fits).
    let payload = [0u8; 0];
    assert!(parse_opus_header(&payload).is_none());
  }

  #[test]
  fn opus_header_short_payload_per_field_emit() {
    // R3 F3: per-field. A 5-byte payload covers OpusVersion (offset 0),
    // AudioChannels (offset 1), but NOT SampleRate (offset 4..8) and
    // NOT OutputGain (offset 8..10).
    let mut payload = [0u8; 5];
    payload[0] = 1;
    payload[1] = 2;
    let header = parse_opus_header(&payload).expect("partial Opus header populated");
    assert_eq!(header.opus_version(), Some(1));
    assert_eq!(header.audio_channels(), Some(2));
    assert_eq!(
      header.sample_rate(),
      None,
      "offset 4..8 out of bounds at len 5"
    );
    assert_eq!(header.output_gain(), None, "offset 8..10 out of bounds");
  }

  #[test]
  fn opus_header_just_first_byte() {
    // R3 F3: a 1-byte payload covers ONLY OpusVersion.
    let payload = [3u8; 1];
    let header = parse_opus_header(&payload).expect("partial");
    assert_eq!(header.opus_version(), Some(3));
    assert_eq!(header.audio_channels(), None);
    assert_eq!(header.sample_rate(), None);
    assert_eq!(header.output_gain(), None);
  }

  #[test]
  fn vorbis_identification_emits_in_declared_offset_order() {
    // serialize_tags emits the Vorbis identification fields in DECLARED
    // OFFSET order (Vorbis.pm:40-70): VorbisVersion / AudioChannels /
    // SampleRate / MaximumBitrate? / NominalBitrate? / MinimumBitrate?.
    // Zero-bitrate fields are dropped (RawConv `$val || undef`).
    let meta = Meta {
      #[cfg(feature = "id3")]
      id3: None,
      pictures: vec![],
      file_type_override: None,
      vorbis_identification: Some(VorbisIdentification {
        vorbis_version: Some(0),
        audio_channels: Some(2),
        sample_rate: Some(44100),
        maximum_bitrate: None,
        nominal_bitrate: Some(128_000),
        minimum_bitrate: None,
      }),
      opus_header: None,
      comments: vec![],
      warnings: vec![],
      success: true,
      _marker: core::marker::PhantomData,
    };
    let mut tm = TagMap::new();
    emit_via_engine(&meta, true, &mut tm);
    // The insertion order is exactly the declared-offset order: every key
    // present in the map appears, NOT including the dropped bitrate fields.
    let keys: Vec<String> = tm
      .entries()
      .iter()
      .map(|(g, n, _)| std::format!("{g}:{n}"))
      .collect();
    assert_eq!(
      keys,
      vec![
        "Vorbis:VorbisVersion",
        "Vorbis:AudioChannels",
        "Vorbis:SampleRate",
        "Vorbis:NominalBitrate",
      ],
      "declared-offset emission order"
    );
    // PrintConv on ⇒ NominalBitrate renders via ConvertBitrate ("128 kbps").
    assert_eq!(
      tm.get_str("Vorbis", "NominalBitrate"),
      Some("128 kbps".to_string()),
      "PrintConv ConvertBitrate output"
    );
  }

  #[test]
  fn vorbis_identification_n_mode_emits_raw_bitrate() {
    // `print_conv = false` ⇒ raw u32 bps (no ConvertBitrate). Pins the
    // `-n` mode emission shape for the bitrate fields.
    let meta = Meta {
      #[cfg(feature = "id3")]
      id3: None,
      pictures: vec![],
      file_type_override: None,
      vorbis_identification: Some(VorbisIdentification {
        vorbis_version: Some(0),
        audio_channels: Some(2),
        sample_rate: Some(44100),
        maximum_bitrate: None,
        nominal_bitrate: Some(128_000),
        minimum_bitrate: None,
      }),
      opus_header: None,
      comments: vec![],
      warnings: vec![],
      success: true,
      _marker: core::marker::PhantomData,
    };
    let mut tm = TagMap::new();
    emit_via_engine(&meta, false, &mut tm);
    // -n: NominalBitrate is the raw u32 = 128000 — written via write_u64,
    // so the TagMap holds a U64 value, not a Str.
    let v = tm.get("Vorbis", "NominalBitrate").expect("present");
    match v {
      TagValue::U64(n) => assert_eq!(*n, 128_000),
      other => panic!("expected U64(128000), got {other:?}"),
    }
  }

  #[test]
  fn vorbis_identification_partial_payload_serialize_emits_subset() {
    // R3 F3 regression pin: a partial VorbisIdentification (e.g. a 9-byte
    // payload yields VorbisVersion / AudioChannels / SampleRate only) must
    // emit ONLY the populated fields — not the bitrate trio. This pins the
    // per-field emit gate in `serialize_tags`.
    let meta = Meta {
      #[cfg(feature = "id3")]
      id3: None,
      pictures: vec![],
      file_type_override: None,
      vorbis_identification: Some(VorbisIdentification {
        vorbis_version: Some(0),
        audio_channels: Some(2),
        sample_rate: Some(44_100),
        maximum_bitrate: None,
        nominal_bitrate: None,
        minimum_bitrate: None,
      }),
      opus_header: None,
      comments: vec![],
      warnings: vec![],
      success: true,
      _marker: core::marker::PhantomData,
    };
    let mut tm = TagMap::new();
    emit_via_engine(&meta, true, &mut tm);
    let keys: Vec<String> = tm
      .entries()
      .iter()
      .map(|(g, n, _)| std::format!("{g}:{n}"))
      .collect();
    assert_eq!(
      keys,
      vec![
        "Vorbis:VorbisVersion",
        "Vorbis:AudioChannels",
        "Vorbis:SampleRate",
      ],
      "partial payload emits only populated fields (R3 F3)"
    );
  }

  #[test]
  fn opus_header_serialize_emits_declared_order() {
    // Opus.pm:36-51 declared-offset order: OpusVersion / AudioChannels /
    // SampleRate / OutputGain.
    let meta = Meta {
      #[cfg(feature = "id3")]
      id3: None,
      pictures: vec![],
      file_type_override: Some("OPUS"),
      vorbis_identification: None,
      opus_header: Some(OpusHeader {
        opus_version: Some(1),
        audio_channels: Some(2),
        sample_rate: Some(48_000),
        output_gain: Some(1.0),
      }),
      comments: vec![],
      warnings: vec![],
      success: true,
      _marker: core::marker::PhantomData,
    };
    let mut tm = TagMap::new();
    emit_via_engine(&meta, true, &mut tm);
    let keys: Vec<String> = tm
      .entries()
      .iter()
      .map(|(g, n, _)| std::format!("{g}:{n}"))
      .collect();
    assert_eq!(
      keys,
      vec![
        "Opus:OpusVersion",
        "Opus:AudioChannels",
        "Opus:SampleRate",
        "Opus:OutputGain",
      ],
      "declared-offset emission order"
    );
  }

  #[test]
  fn opus_header_partial_serialize_emits_subset() {
    // R3 F3: serialize emits only the in-range subset. A partial
    // OpusHeader with only OpusVersion + AudioChannels populated must
    // emit just those two keys.
    let meta = Meta {
      #[cfg(feature = "id3")]
      id3: None,
      pictures: vec![],
      file_type_override: Some("OPUS"),
      vorbis_identification: None,
      opus_header: Some(OpusHeader {
        opus_version: Some(1),
        audio_channels: Some(2),
        sample_rate: None,
        output_gain: None,
      }),
      comments: vec![],
      warnings: vec![],
      success: true,
      _marker: core::marker::PhantomData,
    };
    let mut tm = TagMap::new();
    emit_via_engine(&meta, true, &mut tm);
    let keys: Vec<String> = tm
      .entries()
      .iter()
      .map(|(g, n, _)| std::format!("{g}:{n}"))
      .collect();
    assert_eq!(
      keys,
      vec!["Opus:OpusVersion", "Opus:AudioChannels"],
      "Opus partial emits only populated fields (R3 F3)"
    );
  }

  #[test]
  fn parse_inner_only_emits_str_list_bytes_variants() {
    // Defensive: confirm that staging Metadata never holds anything other
    // than Str/List/Bytes for the OGG emission paths. If a future code
    // change introduces I64/F64 (e.g. via a ValueConv on a known tag),
    // the `tag_to_comment` Debug-string fallback would surface it; this
    // pin ensures no such regression slips in without an explicit test.
    let vendor = b"test";
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&(vendor.len() as u32).to_le_bytes());
    data.extend_from_slice(vendor);
    let entries: &[&[u8]] = &[b"TITLE=Hello", b"ARTIST=Alice", b"ARTIST=Bob"];
    data.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
      data.extend_from_slice(&(e.len() as u32).to_le_bytes());
      data.extend_from_slice(e);
    }
    let mut meta = Metadata::new("x.ogg");
    let mut pictures: Vec<OggPicture> = Vec::new();
    assert!(process_vorbis_comments(
      &data,
      &mut meta,
      &mut pictures,
      true
    ));
    for tag in meta.tags_slice() {
      match tag.value_ref() {
        TagValue::Str(_) | TagValue::List(_) | TagValue::Bytes(_) => {}
        other => panic!(
          "OGG staging Metadata produced unexpected variant: {other:?} (tag {})",
          tag.name()
        ),
      }
    }
  }

  // ---------- Golden-pattern `Taggable` / `Project` ----------------------

  fn fixture(path: &str) -> Vec<u8> {
    let root = env!("CARGO_MANIFEST_DIR");
    std::fs::read(format!("{root}/tests/fixtures/{path}")).expect("fixture exists")
  }

  /// `Taggable::tags` drives the Vorbis comment block through `run_emission`:
  /// the `Vorbis.ogg` fixture carries vendor + scalar comments (no PrintConv
  /// on any Vorbis comment ⇒ `-j` and `-n` identical). Vendor + a known
  /// scalar land under family-1 `"Vorbis"`.
  #[test]
  fn taggable_emits_vorbis_comments() {
    let data = fixture("Vorbis.ogg");
    let meta = parse_borrowed(&data, true).unwrap();
    let mut w = TagMap::new();
    crate::emit::run_emission(&meta, ConvMode::PrintConv, &mut w);
    // Vendor is always emitted (Vorbis.pm:181-187).
    assert!(w.get("Vorbis", "Vendor").is_some(), "Vorbis:Vendor present");
    // The fixture carries an ENCODER comment among others; at least one
    // scalar Vorbis comment beyond vendor must be present.
    assert!(
      w.entries()
        .iter()
        .any(|(g, n, _)| g == "Vorbis" && n != "Vendor"),
      "at least one Vorbis comment beyond vendor: {:?}",
      w.entries()
    );
  }

  /// `Taggable::tags` reproduces the Vorbis `List => 1` coalesce as ONE
  /// `EmittedTag` carrying a `TagValue::List` (interleaved multi-value
  /// fixture), driven through `run_emission` — the `-n` value is identical
  /// (no PrintConv on Vorbis comment fields). Proves first-occurrence-position
  /// coalescing survives the golden cutover.
  #[test]
  fn taggable_emits_vorbis_interleaved_list() {
    let data = fixture("ogg_vorbis_interleaved_list.ogg");
    let meta = parse_borrowed(&data, true).unwrap();
    // Find the coalesced list comment (ARTIST/PERFORMER/CONTACT) in the
    // typed Meta to learn its name + expected values.
    let list = meta
      .comments()
      .iter()
      .find_map(|c| c.try_unwrap_list_ref().ok())
      .expect("an interleaved List comment is present");
    let name = list.name().to_string();
    let expected: Vec<String> = list.values_slice().iter().map(|s| s.to_string()).collect();
    assert!(
      expected.len() >= 2,
      "interleaved fixture has >= 2 list values, got {expected:?}"
    );
    for mode in [ConvMode::PrintConv, ConvMode::ValueConv] {
      let mut w = TagMap::new();
      crate::emit::run_emission(&meta, mode, &mut w);
      match w.get("Vorbis", &name) {
        Some(TagValue::List(items)) => {
          let got: Vec<String> = items
            .iter()
            .map(|v| match v {
              TagValue::Str(s) => s.to_string(),
              other => panic!("non-Str list element {other:?}"),
            })
            .collect();
          assert_eq!(got, expected, "mode={mode:?} interleaved list order");
        }
        other => panic!("expected coalesced Vorbis:{name} List, got {other:?} (mode={mode:?})"),
      }
    }
  }

  /// `Taggable::tags(-j)` renders the Opus header (`synthetic_opus_minimal.opus`):
  /// OpusVersion / AudioChannels / SampleRate as raw numerics, OutputGain as
  /// the post-ValueConv f64. Group family-0/1 is `"Opus"`.
  #[test]
  fn taggable_emits_opus_header() {
    let data = fixture("synthetic_opus_minimal.opus");
    let meta = parse_borrowed(&data, true).unwrap();
    assert!(
      meta.opus_header().is_some(),
      "fixture carries an OpusHead packet"
    );
    let mut w = TagMap::new();
    crate::emit::run_emission(&meta, ConvMode::PrintConv, &mut w);
    // OpusVersion present and family-1 group is "Opus".
    assert!(w.get("Opus", "OpusVersion").is_some(), "Opus:OpusVersion");
    // No Vorbis-identification fields under an Opus stream.
    assert!(
      w.get("Vorbis", "VorbisVersion").is_none(),
      "Opus stream has no Vorbis:VorbisVersion"
    );
  }

  /// `Taggable::tags(-j)` renders the `METADATA_BLOCK_PICTURE` Picture
  /// sub-fields (the `Opus.opus` fixture carries one): PictureType resolves
  /// via the PrintConv hash ("Front Cover"), the Picture binary is a
  /// `TagValue::Bytes`, all under the `FLAC` family-1 group (the SubDirectory
  /// target). `-n` emits the raw numeric PictureType.
  #[test]
  fn taggable_emits_metadata_block_picture() {
    let data = fixture("Opus.opus");
    let meta = parse_borrowed(&data, true).unwrap();
    assert!(
      !meta.pictures().is_empty(),
      "Opus.opus carries a METADATA_BLOCK_PICTURE"
    );
    // -j: PrintConv name + binary bytes under the FLAC group.
    let mut w = TagMap::new();
    crate::emit::run_emission(&meta, ConvMode::PrintConv, &mut w);
    assert_eq!(
      w.get_str("FLAC", "PictureType"),
      Some("Front Cover".to_string())
    );
    assert!(matches!(w.get("FLAC", "Picture"), Some(TagValue::Bytes(_))));
    assert_eq!(
      w.get_str("FLAC", "PictureMIMEType"),
      Some("image/png".to_string())
    );
    // -n: raw numeric PictureType (3 = Front Cover).
    let mut wn = TagMap::new();
    crate::emit::run_emission(&meta, ConvMode::ValueConv, &mut wn);
    assert_eq!(wn.get_str("FLAC", "PictureType"), Some("3".to_string()));
  }

  /// Group identity: Vorbis identification + comments carry family-1
  /// `"Vorbis"`; Opus header tags `"Opus"`; Picture sub-fields `"FLAC"`. Each
  /// sub-table's family-0 == family-1. Every tag is known ⇒ `!unknown`.
  #[test]
  fn taggable_group_family0_and_family1_per_subtable() {
    // Opus.opus exercises Opus:* header tags + FLAC:* Picture sub-fields +
    // Vorbis:* comments in one stream.
    let data = fixture("Opus.opus");
    let meta = parse_borrowed(&data, true).unwrap();
    let tags: Vec<_> = meta.tags(ConvMode::PrintConv).collect();
    assert!(!tags.is_empty());
    let mut saw_opus = false;
    let mut saw_flac = false;
    let mut saw_vorbis = false;
    for t in &tags {
      let g = t.tag().group_ref();
      assert!(!t.unknown(), "tag {} should be known", t.tag().name());
      // family-0 == family-1 across OGG's sub-tables (Vorbis comments under a
      // Theora stream would differ, but Opus.opus has no Theora stream).
      assert_eq!(
        g.family0(),
        g.family1(),
        "tag {} family0 == family1",
        t.tag().name()
      );
      match g.family1() {
        "Opus" => saw_opus = true,
        "FLAC" => saw_flac = true,
        "Vorbis" => saw_vorbis = true,
        // ID3 prefix is possible on some fixtures but not Opus.opus.
        other => panic!("unexpected OGG group {other:?} for {}", t.tag().name()),
      }
    }
    assert!(saw_opus, "Opus:* header tags present");
    assert!(saw_flac, "FLAC:* Picture sub-fields present");
    assert!(saw_vorbis, "Vorbis:* comment tags present");
  }

  /// An ID3-prefixed OGG (`ogg_id3_prefixed.ogg`) splices the chained ID3 tags
  /// FIRST inside `tags()` — proving the `id3.tags(mode)` position matches the
  /// retired `id3.serialize_tags` call site (BEFORE the OGG body). A spliced
  /// ID3 tag precedes the first `Vorbis:*` tag.
  #[test]
  #[cfg(feature = "id3")]
  fn taggable_chains_id3_before_ogg_body() {
    let data = fixture("ogg_id3_prefixed.ogg");
    let meta = parse_borrowed(&data, true).unwrap();
    assert!(meta.id3_ref().is_some(), "fixture carries an ID3v2 prefix");
    let names: Vec<String> = meta
      .tags(ConvMode::PrintConv)
      .map(|t| std::format!("{}:{}", t.tag().group_ref().family1(), t.tag().name()))
      .collect();
    let id3_pos = names
      .iter()
      .position(|n| n.starts_with("ID3v2") || n == "File:ID3Size")
      .expect("an ID3 tag is spliced");
    let body_pos = names
      .iter()
      .position(|n| n.starts_with("Vorbis:") || n.starts_with("Opus:"))
      .expect("an OGG body tag emitted");
    assert!(
      id3_pos < body_pos,
      "ID3 tags must precede the OGG body (id3_pos={id3_pos}, body_pos={body_pos}): {names:?}"
    );
    // Driven through the engine arm, both the ID3 prefix and the OGG body land.
    let mut w = TagMap::new();
    emit_via_engine(&meta, true, &mut w);
    assert!(
      w.entries()
        .iter()
        .any(|(g, n, _)| g.starts_with("ID3v2") || (g == "File" && n == "ID3Size")),
      "ID3 tags present in the engine output"
    );
    assert!(
      w.entries().iter().any(|(g, _, _)| g == "Vorbis"),
      "OGG body tags present in the engine output"
    );
  }

  /// The bitrate PrintConv path: a Vorbis identification with a non-zero
  /// NominalBitrate emits `ConvertBitrate` ("128 kbps") under `-j` and the raw
  /// u32 under `-n` — driven through `run_emission` (proves `bitrate_tag`
  /// matches the retired `emit_bitrate` byte-for-byte).
  #[test]
  fn taggable_bitrate_printconv_vs_valueconv() {
    let meta = Meta {
      #[cfg(feature = "id3")]
      id3: None,
      pictures: vec![],
      file_type_override: None,
      vorbis_identification: Some(VorbisIdentification {
        vorbis_version: Some(0),
        audio_channels: Some(2),
        sample_rate: Some(44_100),
        maximum_bitrate: None,
        nominal_bitrate: Some(128_000),
        minimum_bitrate: None,
      }),
      opus_header: None,
      comments: vec![],
      warnings: vec![],
      success: true,
      _marker: core::marker::PhantomData,
    };
    let mut wj = TagMap::new();
    crate::emit::run_emission(&meta, ConvMode::PrintConv, &mut wj);
    assert_eq!(
      wj.get_str("Vorbis", "NominalBitrate"),
      Some("128 kbps".to_string())
    );
    let mut wn = TagMap::new();
    crate::emit::run_emission(&meta, ConvMode::ValueConv, &mut wn);
    assert!(matches!(wn.get("Vorbis", "NominalBitrate"), Some(TagValue::U64(n)) if *n == 128_000));
  }

  /// `Project` reports OGG as audio-only (one `TrackKind::Audio`), no
  /// camera / lens / GPS / capture / dimensions, and `duration == None`
  /// (Composite:Duration is a formally-accepted deferral — no clean decoded
  /// accessor on the typed Meta).
  #[test]
  fn project_is_audio_only_no_duration() {
    use crate::metadata::{Project, TrackKind};
    let data = fixture("Vorbis.ogg");
    let meta = parse_borrowed(&data, true).unwrap();
    let md = Project::project(&meta);
    assert_eq!(md.media().track_kinds(), &[TrackKind::Audio]);
    assert!(md.media().duration().is_none());
    assert!(md.media().width().is_none());
    assert!(md.media().height().is_none());
    assert!(md.camera().is_none());
    assert!(md.lens().is_none());
    assert!(md.gps().is_none());
    assert!(md.capture().is_none());
  }
}
