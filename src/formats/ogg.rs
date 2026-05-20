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
//! ## Deliberate Phase-2 deferrals (see `docs/superpowers/plans/`):
//! - **Codec-specific identification-header binary tables (R1 F2 scope
//!   tightening):** `%Image::ExifTool::Vorbis::Identification`
//!   (Vorbis.pm:40-70), `%Image::ExifTool::Opus::Header` (Opus.pm:36-51),
//!   and `%Image::ExifTool::Theora::Identification` (Theora.pm:42-104)
//!   are deferred to dedicated `Vorbis.pm` / `Opus.pm` / `Theora.pm`
//!   PRs. The `OverrideFileType('OGV')` / `OverrideFileType('OPUS')`
//!   calls (Ogg.pm:49-50) remain in scope — file-type override fires
//!   whenever the header packet is recognised. See the in-code
//!   `// Codec-specific identification-header tables — DEFERRED (R1 F2)`
//!   comment block for the full deferral rationale incl. the
//!   signed-vs-unsigned `Format` audit list each follow-up PR owes.
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

use crate::{
  convert::{apply, base64_decode},
  parser::{FormatParser, ParseContext},
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
// Codec-specific identification-header tables — DEFERRED (R1 F2)
// ===========================================================================
//
// The bundled-Perl tables `%Image::ExifTool::Vorbis::Identification`
// (Vorbis.pm:40-70), `%Image::ExifTool::Opus::Header` (Opus.pm:36-51), and
// `%Image::ExifTool::Theora::Identification` (Theora.pm:42-104) extract
// codec-specific binary fields (Vorbis bitrate/sample-rate/channels; Opus
// OutputGain/sample-rate/channels; Theora FrameRate/PixelAspect/etc.).
// These tables were initially ported in the first revision of this PR but
// have been REMOVED here to tighten this PR's scope back to its announced
// boundary — "Ogg container framing + inline Vorbis-comment block
// extraction". Codec-specific binary-field decoding is deferred to
// dedicated `Vorbis.pm` / `Opus.pm` / `Theora.pm` PRs.
//
// When those PRs land they MUST verify each field's signed-vs-unsigned
// `Format` against the bundled `.pm` declarations (D5 is faithfulness to
// the bundled ExifTool source, NOT to upstream codec specs):
//   * Vorbis.pm:53,59,65 declare MaximumBitrate / NominalBitrate /
//     MinimumBitrate as `Format => 'int32u'` (unsigned). The Vorbis I
//     specification itself describes them as signed 32-bit integers
//     (RFC-style spec text), but ExifTool emits the unsigned reading —
//     porting MUST match ExifTool, not the spec.
//   * Opus.pm:48 declares OutputGain as `Format => 'int16u'`. RFC 7845
//     §5.1 specifies a signed 16-bit LE field (Q7.8 fixed-point gain in
//     dB), but again ExifTool reads it unsigned — the port MUST match.
//   * Theora.pm uses only `int8u` / `int16u` / `int32u` / `int8u[3]` /
//     `int16u[3]` / `rational64u`; no signedness mismatch.
//
// The `OverrideFileType('OGV')` / `OverrideFileType('OPUS')` calls
// (Ogg.pm:49-50) live in `process_packet` and ARE retained — file-type
// override fires whenever the corresponding header packet is seen, even
// when the identification-binary table is not (yet) ported.
//
// Vorbis-comment-block parsing (vendor + N KEY=VALUE comments) IS in this
// PR's scope and IS retained — see `process_vorbis_comments` below.
//
// Forward reference (memory note): `exifast-phase2-forward-items` —
// "Vorbis.pm + Opus.pm codec-specific tags (identification-header binary
// fields) deferred to dedicated Vorbis/Opus PRs".

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
  // The SubDirectory hop to `FLAC::Picture` is deferred (see module doc).
  // For our scope: emit the decoded raw bytes (same shape as COVERART).
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
  while i < bytes.len() {
    let c = bytes[i];
    // The predicate uses `out.last()` — the most-recently-pushed char,
    // which reflects the mutated-output state (so a just-uppercased `B`
    // does NOT satisfy the `[a-z0-9]` precondition for the next `_`).
    let prev_lower_or_digit = out
      .last()
      .map(|&p| p.is_ascii_lowercase() || p.is_ascii_digit())
      .unwrap_or(false);
    let next_lower = bytes
      .get(i + 1)
      .map(|&n| n.is_ascii_lowercase())
      .unwrap_or(false);
    if c == '_' && prev_lower_or_digit && next_lower {
      // Drop the underscore and uppercase the next char into the output.
      for u in bytes[i + 1].to_uppercase() {
        out.push(u);
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
// Binary-data extraction — DEFERRED (R1 F2)
//
// The targeted `ProcessBinaryData` subset (`read_binary` /
// `process_binary_data` / `BinaryFormat` / `binary_table_offsets` /
// `binary_table_format` / `BinaryByteOrder { II, MM }`) lived here in the
// first revision of this PR to drive the three codec identification
// tables above. With those tables deferred (see the comment block at the
// top of this module), this entire engine-subset has no consumer in this
// PR and is REMOVED. The dedicated `Vorbis.pm` / `Opus.pm` / `Theora.pm`
// PRs (which will re-land the codec identification tables) will either
// promote a shared `ProcessBinaryData` into the engine layer (preferred
// long-term — `RIFF.pm`, `QuickTime.pm`, `FLAC.pm`, etc. all need it) or
// re-derive this targeted subset alongside the codec tables.
// ===========================================================================

// ===========================================================================
// Vorbis comments — ProcessComments (Vorbis.pm:154-210)
// ===========================================================================

/// Read a u32 little-endian at `pos` in `data`. `pos` is passed by value
/// (NOT a cursor); the caller is responsible for advancing it after a
/// successful read. Returns `None` if `pos + 4 > data.len()`.
fn read_u32_le(data: &[u8], pos: usize) -> Option<u32> {
  let bytes = data.get(pos..pos + 4)?;
  Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Process a Vorbis-comment block. `data` is the comment-packet payload
/// (after the 7-byte `\x03vorbis` magic for Vorbis, or after the 8-byte
/// `OpusTags` magic for Opus), starting at the vendor-length u32le.
/// `group1` is the family-1 group to use for the emitted tags (`Vorbis`
/// always — Ogg.pm: the dispatch resolves the SubDirectory but the
/// VorbisComments tag-table's group1 is always 'Vorbis').
fn process_vorbis_comments(data: &[u8], meta: &mut Metadata, print_conv_enabled: bool) -> bool {
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
  let vendor_bytes = &data[pos..pos + vendor_len];
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
    let comment_bytes = &data[pos..pos + comment_len];
    pos += comment_len;
    // Split on first `=` (Vorbis.pm:176-177 `m/(.*?)=(.*)/s`).
    let Some(eq_idx) = comment_bytes.iter().position(|&b| b == b'=') else {
      // Malformed comment: Perl `last` exits the loop and emits the warning.
      meta.push_warning("Format error in Vorbis comments");
      return false;
    };
    let raw_key = String::from_utf8_lossy(&comment_bytes[..eq_idx]).into_owned();
    let raw_val = String::from_utf8_lossy(&comment_bytes[eq_idx + 1..]).into_owned();
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
  if buff.len() >= 7 && &buff[1..7] == b"vorbis" {
    return Some(PacketKind::Vorbis {
      packet_type: buff[0],
      payload_start: 7,
    });
  }
  if buff.len() >= 7 && &buff[1..7] == b"theora" {
    return Some(PacketKind::Theora {
      packet_type: buff[0],
      payload_start: 7,
    });
  }
  if buff.len() >= 8 && &buff[..8] == b"OpusHead" {
    return Some(PacketKind::Opus {
      kind: OpusKind::Head,
      payload_start: 8,
    });
  }
  if buff.len() >= 8 && &buff[..8] == b"OpusTags" {
    return Some(PacketKind::Opus {
      kind: OpusKind::Tags,
      payload_start: 8,
    });
  }
  if buff.len() >= 5 && &buff[..5] == b"\x7fFLAC" {
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

/// Faithful `ProcessPacket` (Ogg.pm:42-69) — dispatch one assembled packet
/// to its codec's comments handler. The `OverrideFileType('OGV')` /
/// `OverrideFileType('OPUS')` calls (Ogg.pm:49-50) live here and fire
/// whenever a Theora / Opus header packet is seen, regardless of whether
/// the identification-binary table is ported.
///
/// **Scope tightening (R1 F2):** the identification-binary-table arms
/// (Vorbis packet_type=1 → `Vorbis::Identification`; Theora packet_type
/// =0x80 → `Theora::Identification`; Opus `OpusHead` → `Opus::Header`)
/// are DEFERRED to dedicated `Vorbis.pm` / `Opus.pm` / `Theora.pm` PRs —
/// see the top-of-module comment. Only the Vorbis-comments-block arms
/// (Vorbis packet_type=3, Theora packet_type=0x81, Opus `OpusTags`) are
/// in scope here.
fn process_packet(ctx: &mut ParseContext<'_>, buff: &[u8]) {
  let Some(kind) = classify_packet(buff) else {
    return;
  };
  // Snapshot the PrintConv switch up-front so the mutable `ctx.metadata()`
  // borrow inside each arm doesn't conflict with `ctx.print_conv_enabled()`.
  let print_conv_enabled = ctx.print_conv_enabled();
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
          // Vorbis::Identification (Vorbis.pm:30-33) — DEFERRED (R1 F2);
          // see top-of-module note. The bundled-Perl dispatch would
          // ProcessBinaryData over `%Vorbis::Identification` here.
        }
        3 => {
          // Vorbis::Comments (Vorbis.pm:34-37).
          process_vorbis_comments(&buff[payload_start..], ctx.metadata(), print_conv_enabled);
        }
        _ => {
          // 0x05 Vorbis setup-header / others: tag-table has no entry, no-op.
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
      ctx.override_file_type("OGV", None, None);
      // Ogg.pm:62 `$$et{SET_GROUP1} = $type if $type eq 'Theora'`. Theora
      // tags carry the Theora group1; our tag-table already sets `Theora`.
      // Slice borrow rather than `to_vec()`: downstream accepts `&[u8]`.
      match packet_type {
        0x80 => {
          // Theora::Identification (Theora.pm:42-104) — DEFERRED (R1 F2);
          // see top-of-module note.
        }
        0x81 => {
          // Theora::Comments delegates to Vorbis::Comments (Theora.pm:32-37).
          // Ogg.pm:62 sets group1 to 'Theora' for Vorbis::Comments tags
          // when running under Theora.
          process_vorbis_comments_with_group1(
            &buff[payload_start..],
            ctx.metadata(),
            print_conv_enabled,
            "Theora",
          );
        }
        _ => {
          // 0x82 Theora setup: no entry, no-op.
        }
      }
    }
    PacketKind::Opus {
      kind,
      payload_start,
    } => {
      // Ogg.pm:50 `$et->OverrideFileType('OPUS')` when this stream is
      // Opus. RETAINED — same reasoning as the Theora `OGV` override.
      ctx.override_file_type("OPUS", None, None);
      // Slice borrow rather than `to_vec()`: downstream accepts `&[u8]`.
      match kind {
        OpusKind::Head => {
          // Opus::Header (Opus.pm:36-51) — DEFERRED (R1 F2); see
          // top-of-module note. The `OpusHead` packet is still observed
          // (classify_packet recognises it) so the `OverrideFileType`
          // above fires; we just don't extract the binary fields.
        }
        OpusKind::Tags => {
          // Opus.pm:32 delegates to Vorbis::Comments with the default
          // group1 (Vorbis).
          process_vorbis_comments(&buff[payload_start..], ctx.metadata(), print_conv_enabled);
        }
      }
    }
    PacketKind::Flac => {
      // Ogg.pm:176-179, 190-195: FLAC-in-Ogg transport. DEFERRED.
      // TODO(ogg-flac, FORMATS.md row 9): wire `ProcessFLAC` once the FLAC
      // port lands. Silent no-op preserves "container OK, no codec tags".
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
fn process_vorbis_comments_with_group1(
  data: &[u8],
  meta: &mut Metadata,
  print_conv_enabled: bool,
  group1: &str,
) -> bool {
  let mut side = Metadata::new(meta.source_file());
  let ok = process_vorbis_comments(data, &mut side, print_conv_enabled);
  for tag in side.tags() {
    meta.push(
      Group::new(tag.group().family0(), group1),
      tag.name(),
      tag.value().clone(),
    );
  }
  // Propagate any warnings the side-parse emitted.
  for w in side.warnings() {
    meta.push_warning(w.clone());
  }
  ok
}

// ===========================================================================
// ProcessOGG — the container walker (Ogg.pm:75-197)
// ===========================================================================

/// OGG parser (faithful `ProcessOGG`, Ogg.pm:75-197).
pub struct ProcessOgg;

impl FormatParser for ProcessOgg {
  fn process(&self, ctx: &mut ParseContext<'_>) -> bool {
    // Ogg.pm:80-83 ID3 wrapper — DEFERRED (parallel ID3 PR). The
    // bundled-Perl `unless ($$et{DoneID3})` then ProcessID3 short-circuit
    // is replicated here by simply not attempting ID3 parsing.
    // TODO(id3-pathfinder, FORMATS.md row 2): wire ID3 wrap detection.

    // Borrow the file bytes directly. `ParseContext::data` returns
    // `&'a [u8]` (the file lifetime, NOT tied to `&ctx`), so subsequent
    // `ctx.metadata()` / `ctx.set_file_type()` calls below do not collide
    // with this borrow. Avoids the full-file copy the original revision
    // performed (AAC only copies its 7-byte header, which is why that
    // pathfinder did not need the lifetime-extended accessor).
    let data: &[u8] = ctx.data();

    // Container walker state.
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
      let header_magic_ok = header_in_bounds && &data[cursor..cursor + 4] == b"OggS";
      let read_ok = if header_in_bounds {
        if !header_magic_ok {
          // Ogg.pm:97 `$success and $et->Warn('Lost synchronization')`.
          if success {
            ctx.metadata().push_warning("Lost synchronization");
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
          success = true;
          ctx.set_file_type(None, None, None);
        }
        // Ogg.pm:106 `$flag = Get8u(\$buff, 5)` — page-header byte 5.
        current_flag = data[cursor + 5];
        // Ogg.pm:107 `$stream = Get32u(\$buff, 14)`.
        current_stream = u32::from_le_bytes([
          data[cursor + 14],
          data[cursor + 15],
          data[cursor + 16],
          data[cursor + 17],
        ]);
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
        current_stream = keys[0];
        current_flag = 0;
        raf_done = true;
      }

      // Ogg.pm:122-140 — process the previously buffered packet.
      // (FLAC-in-Ogg `defined $numFlac` arm is DEFERRED; we fall straight
      // through to the regular packet-processing branch.)
      if val.contains_key(&current_stream) && current_flag & 0x01 == 0 {
        let owned = val.remove(&current_stream).unwrap();
        process_assembled_packet(ctx, &owned);
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
      let page_num = u32::from_le_bytes([
        data[cursor + 18],
        data[cursor + 19],
        data[cursor + 20],
        data[cursor + 21],
      ]);
      let nseg = data[cursor + 26] as usize;
      // We need `27 + nseg` bytes to cover the header + segment table.
      if data.len() < cursor + 27 + nseg {
        break;
      }
      let seg_table = &data[cursor + 27..cursor + 27 + nseg];
      let data_len: usize = seg_table.iter().map(|&b| b as usize).sum();
      // Ogg.pm:154-162 — sequence-number check.
      let expected_opt = stream_page.get(&current_stream).copied().flatten();
      if let Some(expected) = expected_opt {
        if expected == page_num {
          stream_page.insert(current_stream, Some(expected + 1));
        } else {
          ctx.metadata().push_warning("Missing page(s) in Ogg file");
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
      let page_bytes: &[u8] = &data[page_data_start..page_data_end];

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
        process_assembled_packet(ctx, &owned);
      }
      cursor = page_data_end;
    }
    // Ogg.pm:196 `return $success`.
    success
  }
}

/// Dispatch an assembled packet. `process_packet` does codec-classification
/// and SubDirectory dispatch; this wrapper exists so the call site reads
/// like Perl `ProcessPacket($et, \$val{$stream})`.
fn process_assembled_packet(ctx: &mut ParseContext<'_>, buff: &[u8]) {
  process_packet(ctx, buff);
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  // `convert_bitrate` unit-tests REMOVED (R1 F2): `convert_bitrate` is a
  // PrintConv helper used only by the now-deferred Vorbis/Theora codec
  // binary tables. The engine-level `convert::convert_bitrate` (faithful
  // to ExifTool.pm:6891-6902) remains and its own engine-tier tests cover
  // the breakpoints — the duplicate cover here was only useful while the
  // Ogg PR was the first consumer of it.

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
    assert!(process_vorbis_comments(&data, &mut meta, true));
    let names: Vec<&str> = meta.tags().iter().map(|t| t.name()).collect();
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
    assert!(process_vorbis_comments(&data, &mut meta, true));
    // Vendor first, then Title, then a single Artist as a List of 2.
    let names: Vec<&str> = meta.tags().iter().map(|t| t.name()).collect();
    assert_eq!(names, vec!["Vendor", "Title", "Artist"]);
    let artist = meta.tags().iter().find(|t| t.name() == "Artist").unwrap();
    if let TagValue::List(items) = artist.value() {
      assert_eq!(items.len(), 2);
      assert_eq!(items[0], TagValue::Str("Alice".into()));
      assert_eq!(items[1], TagValue::Str("Bob".into()));
    } else {
      panic!("Artist should be List, got {:?}", artist.value());
    }
  }

  #[test]
  fn process_vorbis_comments_warns_on_truncation() {
    // Vendor-length larger than available data.
    let data: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
    let mut meta = Metadata::new("x.ogg");
    assert!(!process_vorbis_comments(&data, &mut meta, true));
    assert_eq!(meta.warnings()[0], "Format error in Vorbis comments");
  }

  // Tests `vorbis_identification_format_lookup`,
  // `process_vorbis_comments_zero_nominal_bitrate_dropped`,
  // `process_binary_data_opus_header_extracts_fields`, and
  // `binary_format_rational64u_emits_rational` REMOVED (R1 F2): they
  // exercise the deferred codec-identification binary tables and
  // `process_binary_data` / `read_binary` engine subset. The Vorbis/Opus
  // /Theora codec PRs that re-land those tables will re-derive these
  // tests against bundled-Perl oracle fixtures.

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
    assert!(process_vorbis_comments_with_group1(
      &data, &mut meta, true, "Theora"
    ));
    for t in meta.tags() {
      // Family-0 stays "Vorbis" (from the tag table); family-1 is "Theora".
      assert_eq!(t.group().family0(), "Vorbis");
      assert_eq!(t.group().family1(), "Theora");
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
    use crate::parser::ParseContext;
    let mut m = Metadata::new("x.ogg");
    // Only the 4-byte `OggS` magic — header is far short of the 28-byte
    // minimum Ogg.pm:94 demands. `ProcessOgg` returns false; nothing
    // pushed to metadata. (See also `tests/conformance.rs::
    // ogg_truncated_error_conformance` for the 27-byte boundary pin.)
    let mut ctx = ParseContext::new(b"OggS", "OGG", 0, "OGG", None, true, &mut m);
    assert!(!ProcessOgg.process(&mut ctx));
    assert!(m.tags().is_empty(), "no tags pushed before SetFileType");
  }

  // `binary_format_rational64u_emits_rational` REMOVED (R1 F2) — see the
  // shared "tests REMOVED" note further up in this module.
}
