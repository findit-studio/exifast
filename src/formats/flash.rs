// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "flash")]
//! Faithful port of `Image::ExifTool::Flash` (lib/Image/ExifTool/Flash.pm),
//! FLV (Flash Video) side only. SWF (Shockwave Flash) ProcessSWF is deferred
//! (no SWF fixture in this port's scope; the FORMATS.md row 18 target is FLV).
//!
//! A typed [`Meta<'a>`] is produced by the
//! [`crate::format_parser::FormatParser`] trait; the engine entry drives its
//! [`Taggable`](crate::emit::Taggable) impl through
//! [`run_emission`](crate::emit::run_emission) into
//! [`crate::tagmap::TagMap`] so the serialized JSON stays value-equivalent
//! with bundled `perl exiftool`.
//!
//! ## What FLV is
//!
//! FLV (Flash Video) is a tag stream container. After a 9-byte file header,
//! each tag is preceded by a 4-byte previous-tag-size and consists of an
//! 11-byte tag header (`type:u8`, `dataSize:u24`, `timestamp:u24`,
//! `tsExt:u8`, `streamId:u24`) followed by the tag body. ExifTool dispatches
//! three tag types:
//!
//! - `0x08` audio — the first byte of the body is an audio configuration
//!   octet (`%Flash::Audio` bit-stream table, Flash.pm:91-135).
//! - `0x09` video — the first byte of the body is a video configuration
//!   octet (`%Flash::Video` bit-stream table, Flash.pm:138-154).
//! - `0x12` script-data (Meta) — AMF0-encoded `onMetaData` payload walked by
//!   `ProcessMeta` (Flash.pm:290-461).
//!
//! AMF0 type codes processed (Flash.pm:301-454):
//!
//! | code | name        | notes                                              |
//! |-----:|-------------|----------------------------------------------------|
//! | 0x00 | double      | 8-byte BE f64                                      |
//! | 0x01 | boolean     | 1-byte u8 → `'No'/'Yes'/0/1` PrintConv             |
//! | 0x02 | string      | u16 length + bytes                                 |
//! | 0x03 | object      | key/value pairs; terminator `0x000009`             |
//! | 0x05 | null        | empty value                                        |
//! | 0x06 | undefined   | empty value                                        |
//! | 0x07 | reference   | u16 (ignored as scalar — handled but rarely seen)  |
//! | 0x08 | mixed-array | 4-byte array-index + key/value pairs               |
//! | 0x09 | object-end  | the structural sentinel (read inside object loops) |
//! | 0x0a | array       | u32 count + values (no keys)                       |
//! | 0x0b | date        | f64 ms + i16 tz (minutes)                          |
//! | 0x0c | long string | u32 length + bytes                                 |
//! | 0x0d | unsupported | empty value                                        |
//! | 0x0f | XML         | u32 length + bytes                                 |
//! | 0x10 | typed-object| u16 name length + name + object pairs              |
//!
//! AMF3 (code `0x11`), record set (`0x0e`), and movie-clip (`0x04`) are not
//! handled in bundled Flash.pm (`# can't add support for this without a
//! test sample`); the port mirrors that — unsupported codes accumulate an
//! `AMF <name> record not yet supported` warning and abort the meta packet.

// Golden-v2 Contract 3c (Phase C, slice B / w2b): panic-safety by construction —
// every raw index/slice is converted to a checked `.get()` form below.
#![deny(clippy::indexing_slicing)]

use crate::{
  convert::{
    fix_utf8, perl_str_to_f64, write_convert_bitrate, write_convert_duration,
    write_convert_duration_str,
  },
  format_parser::{FormatParser, parser_sealed},
};
use smol_str::SmolStr;

// ===========================================================================
// AMF type codes (Flash.pm:277-279 `@amfType`)
// ===========================================================================

/// Faithful copy of Flash.pm:277-279 `@amfType` — the by-code name array used
/// for warnings and `Format` arguments to HandleTag. Index = the AMF type
/// code; out-of-range codes get the `sprintf('type 0x%x',$type)` fallback
/// (Flash.pm:436/450).
const AMF_TYPE_NAMES: &[&str] = &[
  "double",      // 0x00
  "boolean",     // 0x01
  "string",      // 0x02
  "object",      // 0x03
  "movieClip",   // 0x04 (not supported, Flash.pm:402)
  "null",        // 0x05
  "undefined",   // 0x06
  "reference",   // 0x07
  "mixedArray",  // 0x08
  "objectEnd",   // 0x09
  "array",       // 0x0a
  "date",        // 0x0b
  "longString",  // 0x0c
  "unsupported", // 0x0d
  "recordSet",   // 0x0e (not supported, Flash.pm:433)
  "XML",         // 0x0f
  "typedObject", // 0x10
  "AMF3data",    // 0x11 (not supported, Flash.pm:434)
];

/// `@amfType[$type]` lookup with the `sprintf('type 0x%x', $type)` fallback.
/// Returns the borrowed `&'static str` for in-range codes and writes the
/// hex form into the caller's [`SmolStr`] buffer otherwise.
fn amf_type_name(code: u8) -> SmolStr {
  AMF_TYPE_NAMES.get(code as usize).map_or_else(
    || SmolStr::from(std::format!("type 0x{code:x}")),
    |s| SmolStr::new_static(s),
  )
}

/// `%isStruct` (Flash.pm:282) — codes that introduce a key/value substructure
/// (object, mixed-array, typed-object).
const fn is_struct(code: u8) -> bool {
  matches!(code, 0x03 | 0x08 | 0x10)
}

/// Max recursion depth for the AMF (`onMetaData`/`onXMPData`) script-data
/// walker (Golden-v2 Contract 3a). Bundled `ProcessMeta` recurses without a
/// hard cap (it relies on the finite `$dirLen`), but a hostile FLV can nest
/// AMF strict-arrays (`0x0a`) or objects (`0x03`/`0x08`/`0x10`) arbitrarily
/// deep, recursing the mutually-recursive `walk_pairs`/`walk_array`/
/// `collect_array_items` cluster until the stack overflows — a DoS. Real FLV
/// `onMetaData` nests a couple of levels (the `keyframes` object holds two
/// flat arrays), so this cap is a large superset that never trips on a real
/// file; the output stays byte-identical. Exceeding it stops recursion,
/// faithful to a truncated subtree contributing no further tags.
const MAX_AMF_DEPTH: u32 = 100;

/// `%processMetaPacket` (Flash.pm:34) — top-level script-data packet names
/// that drive the meta walker. The first string of a top-level meta tag is
/// the packet name; only `onMetaData` and `onXMPData` are walked
/// (Flash.pm:443-453).
fn is_processed_packet(name: &str) -> bool {
  matches!(name, "onMetaData" | "onXMPData")
}

// ===========================================================================
// Tag-name lookup (Flash.pm:157-247 `%Flash::Meta`)
// ===========================================================================

/// Maps an AMF key name (lower case, AMF0 string) to its emitted `Flash:*`
/// tag name + the PrintConv style and ValueConv multiplier. Faithful copy of
/// `%Image::ExifTool::Flash::Meta` (Flash.pm:157-247). Unrecognized keys go
/// through the auto-add path (`ucfirst($tag)`, Flash.pm:391).
///
/// `(name, value_conv, print_conv)` per entry:
///
/// - `value_conv` rescales the raw double via the tag's Perl `ValueConv`
///   (e.g. `$val * 1000` for `*datarate`).
/// - `print_conv` selects the PrintConv style applied at -j emit time.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(feature = "json"), allow(dead_code))]
struct MetaTag {
  /// Emitted name (e.g. `"AudioBitrate"`).
  name: &'static str,
  /// Optional ValueConv multiplier applied to the raw double (Perl
  /// `ValueConv => '$val * 1000'`).
  mul_1000: bool,
  /// PrintConv mode applied at `-j` emit time.
  pc: PrintConvMode,
  /// Trim trailing whitespace before emission (Perl `s/\s+$//`, Flash.pm:182).
  trim_trailing_ws: bool,
}

/// PrintConv variants for `%Flash::Meta` tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "json"), allow(dead_code))]
enum PrintConvMode {
  /// No PrintConv — emit raw scalar (string/number/bool) per the AMF type.
  None,
  /// `ConvertBitrate($val)` (Flash.pm:169/238).
  ConvertBitrate,
  /// `ConvertDuration($val)` (Flash.pm:192/221/226).
  ConvertDuration,
  /// `int($val * 1000 + 0.5) / 1000` (Flash.pm:197) — round to 3 decimal
  /// places, but `-j` and `-n` both emit the same numeric (Perl `%g`
  /// stringification trims trailing zeros, so the integer fixture value
  /// `20.0` round-trips as `20` regardless).
  RoundMilli,
  /// `int($val + 0.5)` (Flash.pm:231) — round to integer (totaldatarate
  /// PrintConv after `*1000`).
  RoundInt,
  /// `$self->ConvertDateTime($val)` (Flash.pm:214) — pass-through under
  /// default options (DateFormat unset; matches bundled output).
  ConvertDateTime,
}

/// Look up an AMF key in the `%Flash::Meta` table. Returns `Some(MetaTag)`
/// for explicit entries (Flash.pm:164-246) or `None` for the auto-add path
/// (Flash.pm:391: `AddTagToTable($subTablePtr, $tag, { Name => ucfirst($tag) })`,
/// gated to `$tag =~ /^\w+$/`).
fn lookup_meta(key: &str) -> Option<MetaTag> {
  // The Perl table uses lower-case keys throughout (Flash.pm:164-246).
  // Direct string match — small enough that a static phf is overkill.
  Some(match key {
    "audiocodecid" => MetaTag {
      name: "AudioCodecID",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "audiodatarate" => MetaTag {
      name: "AudioBitrate",
      mul_1000: true,
      pc: PrintConvMode::ConvertBitrate,
      trim_trailing_ws: false,
    },
    "audiodelay" => MetaTag {
      name: "AudioDelay",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "audiosamplerate" => MetaTag {
      name: "AudioSampleRate",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "audiosamplesize" => MetaTag {
      name: "AudioSampleSize",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "audiosize" => MetaTag {
      name: "AudioSize",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "bytelength" => MetaTag {
      name: "ByteLength",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "canseekontime" => MetaTag {
      name: "CanSeekOnTime",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "canSeekToEnd" => MetaTag {
      name: "CanSeekToEnd",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "creationdate" => MetaTag {
      name: "CreateDate",
      mul_1000: false,
      pc: PrintConvMode::None,
      // Flash.pm:182 — `$val=~s/\s+$//; $val` (trim trailing whitespace).
      trim_trailing_ws: true,
    },
    "createdby" => MetaTag {
      name: "CreatedBy",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "datasize" => MetaTag {
      name: "DataSize",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "duration" => MetaTag {
      name: "Duration",
      mul_1000: false,
      pc: PrintConvMode::ConvertDuration,
      trim_trailing_ws: false,
    },
    "filesize" => MetaTag {
      name: "FileSizeBytes",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "framerate" => MetaTag {
      name: "FrameRate",
      mul_1000: false,
      pc: PrintConvMode::RoundMilli,
      trim_trailing_ws: false,
    },
    "hasAudio" => MetaTag {
      name: "HasAudio",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "hasCuePoints" => MetaTag {
      name: "HasCuePoints",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "hasKeyframes" => MetaTag {
      name: "HasKeyFrames",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "hasMetadata" => MetaTag {
      name: "HasMetadata",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "hasVideo" => MetaTag {
      name: "HasVideo",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "height" => MetaTag {
      name: "ImageHeight",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "httphostheader" => MetaTag {
      name: "HTTPHostHeader",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "keyframesTimes" => MetaTag {
      name: "KeyFramesTimes",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "keyframesFilepositions" => MetaTag {
      name: "KeyFramePositions",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "lasttimestamp" => MetaTag {
      name: "LastTimeStamp",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "lastkeyframetimestamp" => MetaTag {
      name: "LastKeyFrameTime",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "metadatacreator" => MetaTag {
      name: "MetadataCreator",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "metadatadate" => MetaTag {
      name: "MetadataDate",
      mul_1000: false,
      pc: PrintConvMode::ConvertDateTime,
      trim_trailing_ws: false,
    },
    "purl" => MetaTag {
      name: "URL",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "pmsg" => MetaTag {
      name: "Message",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "sourcedata" => MetaTag {
      name: "SourceData",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "starttime" => MetaTag {
      name: "StartTime",
      mul_1000: false,
      pc: PrintConvMode::ConvertDuration,
      trim_trailing_ws: false,
    },
    "stereo" => MetaTag {
      name: "Stereo",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "totalduration" => MetaTag {
      // Flash.pm has TWO 'totalduration' entries (lines 224 + 233); Perl
      // hash deduplication keeps the LAST literal (`'TotalDuration'` plain
      // string, no PrintConv). Bundled `perl exiftool` reflects that.
      name: "TotalDuration",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "totaldatarate" => MetaTag {
      name: "TotalDataRate",
      mul_1000: true,
      pc: PrintConvMode::RoundInt,
      trim_trailing_ws: false,
    },
    "videocodecid" => MetaTag {
      name: "VideoCodecID",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "videodatarate" => MetaTag {
      name: "VideoBitrate",
      mul_1000: true,
      pc: PrintConvMode::ConvertBitrate,
      trim_trailing_ws: false,
    },
    "videosize" => MetaTag {
      name: "VideoSize",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    "width" => MetaTag {
      name: "ImageWidth",
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
    _ => return None,
  })
}

// ===========================================================================
// Typed Meta
// ===========================================================================

/// One emitted tag value. AMF carries doubles, booleans, strings, arrays of
/// the same; the typed value mirrors that.
///
/// `#[allow(dead_code)]` per-variant: when built without `alloc`, the
/// `serialize_tags` impl is gone and the variants are constructed but
/// never read. The variants are still load-bearing for parser correctness.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "json"), allow(dead_code))]
enum FlashValue {
  /// AMF double / typed numeric (after ValueConv multiplier, if any).
  Double(f64),
  /// AMF boolean (PrintConv `0 => 'No', 1 => 'Yes'` for values < 2;
  /// Flash.pm:329).
  Bool(u8),
  /// AMF string / long-string / XML (post-trim if `trim_trailing_ws`).
  Str(SmolStr),
  /// AMF date (Flash.pm:309-325) — a pre-formatted `"YYYY:MM:DD HH:MM:SS.ssssss±HH:MM"` string.
  Date(SmolStr),
  /// AMF strict-array (0x0a) emission: a heterogeneous list of non-struct
  /// children (Flash.pm:421-422 `push @vals, $v unless $isStruct{$t}`).
  /// Per bundled `HandleTag` (Flash.pm:394-400), bundled emits the FULL
  /// list as a single tag whose value is an array reference. The element
  /// shape is value-typed (Flash.pm 305-432): doubles → JSON numbers,
  /// strings/long-strings/XML → JSON strings, booleans → `"Yes"`/`"No"`
  /// strings (Flash.pm 329 applies inside ProcessMeta, NOT PrintConv),
  /// dates → pre-formatted date strings (Flash.pm 309-325). In `-n` mode
  /// bundled emits the same shapes (the bool-string and date-string
  /// conversions are pre-PrintConv).
  List(std::vec::Vec<FlashListItem>),
}

/// One element of a [`FlashValue::List`]. Mirrors the per-AMF-type emission
/// shape applied at serialize-time. Stored already-converted (booleans as
/// `"Yes"`/`"No"` strings, dates as formatted date strings) so the
/// `Vec<FlashListItem>` is a faithful one-to-one snapshot of bundled
/// `HandleTag`'s array-reference contents.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "json"), allow(dead_code))]
enum FlashListItem {
  /// Numeric element — emitted as a JSON number.
  Double(f64),
  /// Pre-converted string element — covers AMF strings, long-strings,
  /// XML, bool-as-`"Yes"`/`"No"` (Flash.pm:329 in-ProcessMeta path), and
  /// pre-formatted dates (Flash.pm:316-324).
  Str(SmolStr),
  /// Nested strict-array (Flash.pm:410-426 recursive). The inner
  /// `ProcessMeta` call for a child element whose type is `0x0a`
  /// constructs `$val = \@vals` and returns `(0x0a, $val)`; Frame 2's
  /// line 422 `push @vals, $v unless $isStruct{$t}` then nests the array
  /// reference into the outer list (`isStruct` is `{0x03,0x08,0x10}` —
  /// `0x0a` is NOT in it). Bundled JSON shape is `[[a,b],c,...]`.
  /// Mirrors Codex R2/F2: prior shape returned `AmfValue::StrictArray`
  /// from `read_value` WITHOUT consuming the nested count+payload,
  /// leaving the cursor mid-nested-array → silent data loss.
  List(std::vec::Vec<FlashListItem>),
}

/// One emitted Flash tag entry. The emit order is the bundled `FoundTag`
/// call order (Meta walk insertion order; Audio/Video bit-stream tags
/// emit at the moment the dispatching packet is read).
///
/// `#[allow(dead_code)]` on the non-alloc tier: the fields are read only
/// by `serialize_tags` (alloc-gated). The parser builds Entry instances
/// regardless of feature tier.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "json"), allow(dead_code))]
struct Entry {
  /// Emitted tag name (e.g. `"AudioBitrate"`, `"CuePoint0Name"`).
  name: SmolStr,
  /// Typed value.
  value: FlashValue,
  /// PrintConv mode (applied at `-j` emit time only).
  pc: PrintConvMode,
}

/// Typed FLV metadata — the lib-first output of [`ProcessFlv`].
///
/// **D8 — no public fields, accessors only.**
///
/// Holds the ordered list of emitted entries (faithful to bundled `FoundTag`
/// call order) plus any accumulated warnings (Flash.pm:353/437/456).
#[derive(Debug, Clone)]
pub struct Meta<'a> {
  /// Ordered list of emitted (name, value, PrintConv-mode) entries.
  entries: std::vec::Vec<Entry>,
  /// `$et->Warn` accumulator (Flash.pm:353 `Truncated ... record`, 437
  /// `AMF ... not yet supported`, 456 `Truncated AMF record 0x%x`,
  /// 504 `Bad <name> packet`, 511 `Truncated Meta packet`).
  warnings: std::vec::Vec<SmolStr>,
  /// Phantom lifetime — Meta is owned (AMF strings are post-`fix_utf8` via
  /// `SmolStr`); the GAT propagates the input lifetime per Codex AF2 but no
  /// field actually borrows.
  _ph: core::marker::PhantomData<&'a ()>,
}

impl Meta<'_> {
  /// All emitted Flash entries in extraction order (one entry per `FoundTag`
  /// call in bundled Flash.pm).
  #[must_use]
  #[inline(always)]
  pub fn entry_count(&self) -> usize {
    self.entries.len()
  }

  /// Accumulated warnings in `$et->Warn` call order (the document surfaces
  /// only the FIRST via `ExifTool:Warning`; this slice retains all of them
  /// for downstream tooling).
  #[must_use]
  #[inline(always)]
  pub fn warnings(&self) -> &[SmolStr] {
    self.warnings.as_slice()
  }
}

// ===========================================================================
// `ProcessFlv` — the lib-first parser
// ===========================================================================

/// FLV parser (faithful `ProcessFLV`, Flash.pm:467-525).
#[derive(Debug, Clone, Copy)]
pub struct ProcessFlv;

impl parser_sealed::Sealed for ProcessFlv {}

impl FormatParser for ProcessFlv {
  type Meta<'a> = Meta<'a>;
  type Context<'a> = &'a [u8];

  fn parse<'a>(&self, data: Self::Context<'a>) -> Option<Self::Meta<'a>> {
    parse_inner(data)
  }
}

/// Lib-first direct entry. Same as [`FormatParser::parse`] but returns the
/// [`Meta`] directly (no AnyError wrapping).
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today; reserved for
/// future I/O wrappers).
pub fn parse_borrowed(data: &[u8]) -> Option<Meta<'_>> {
  parse_inner(data)
}

/// Inner parser. Faithful to `ProcessFLV` (Flash.pm:467-525):
///
/// 1. 9-byte header: `FLV\x01` + flags + offset; reject on bad magic.
/// 2. `SetFileType` (Flash.pm:477) — engine handles via finalize.
/// 3. `Seek($offset-9, 1)` (Flash.pm:479) — skip extra header bytes.
/// 4. Loop reading 15-byte (prev-tag-size + 11-byte tag header) until
///    either flags satisfied (`!flags`) or EOF.
fn parse_inner(data: &[u8]) -> Option<Meta<'_>> {
  // Flash.pm:474 `$raf->Read($buff, 9) == 9 or return 0`.
  if data.len() < 9 {
    return None;
  }
  // Flash.pm:475 `$buff =~ /^FLV\x01/ or return 0`.
  // Checked-indexing (Phase C w2b): the `data.len() < 9` guard above makes
  // `data.get(..4)` / `data.get(4)` / `data.get(5..9)` all `Some`, so the
  // fallbacks are unreachable and every read is byte-identical.
  if data.get(..4) != Some(&b"FLV\x01"[..]) {
    return None;
  }
  // Flash.pm:478 `($flags, $offset) = unpack('x4CN', $buff)`.
  let mut flags = data.get(4).copied().unwrap_or(0);
  let offset = match data.get(5..9) {
    Some(&[b0, b1, b2, b3]) => u32::from_be_bytes([b0, b1, b2, b3]) as usize,
    _ => 0,
  };
  // Flash.pm:480 `$flags &= 0x05`.
  flags &= 0x05;

  // Flash.pm:479 `$raf->Seek($offset-9, 1) or return 1 if $offset > 9`.
  // The first tag stream starts at `offset` (which counts FROM the start of
  // the file — bundled `$offset - 9` is relative to the current position
  // RIGHT AFTER the 9-byte header read).
  let mut pos = if offset > 9 { offset } else { 9 };

  let mut entries: std::vec::Vec<Entry> = std::vec::Vec::new();
  let mut warnings: std::vec::Vec<SmolStr> = std::vec::Vec::new();
  let mut found: u8 = 0;

  // Flash.pm:483 `for (;;) { $raf->Read($buff, 15) == 15 or last; ... }`.
  loop {
    if pos + 15 > data.len() {
      break; // short read ⇒ Perl `last`
    }
    // Checked-indexing (Phase C w2b): the `pos + 15 > data.len()` guard makes
    // `data.get(pos..pos + 15)` always `Some` (a 15-byte window), so `head[4]`
    // ..`head[7]` destructure cleanly ⇒ byte-identical.
    let head = data.get(pos..pos + 15).unwrap_or(&[]);
    // Flash.pm:485-487 — the 4-byte prev-tag-size precedes the 11-byte tag
    // header. `$len = unpack('x4N', $buff)` extracts the BE u32 from
    // offset 4 of the 15-byte window: `(type << 24) | dataSize24`.
    let pack = match head.get(4..8) {
      Some(&[b0, b1, b2, b3]) => u32::from_be_bytes([b0, b1, b2, b3]),
      _ => 0,
    };
    let r#type = (pack >> 24) as u8;
    let len = (pack & 0x00ff_ffff) as usize;
    pos += 15; // advance past the prev-tag-size + tag-header

    // Flash.pm:488-491 — verbose-only logging skipped here.
    // Flash.pm:493 `undef $buff;` — `$buff` is the consumed-payload window
    // re-set per type below.

    let body_start = pos;
    let avail = data.len() - body_start; // bytes physically present after header

    // Codex PR #32 R13/F3 — faithful per-type body handling. Bundled
    // Flash.pm (lines 494-522) does NOT require the WHOLE declared body to
    // be present before dispatching: audio/video read only the FIRST config
    // byte (`$raf->Read($buff, 1) == 1`, Flash.pm:500), subtract it from
    // `$len`, then `last unless $flags` (line 521) BEFORE the residual
    // `Seek($len, 1)` (line 522). An audio/video-only file whose tag
    // declares a longer payload than is present still emits all its tags
    // with no warning, because the residual seek is never reached once the
    // last requested flag clears. Only the Meta branch (line 508) reads the
    // entire `$len` and warns `Truncated Meta packet` on a short read.
    //
    // `consumed` mirrors how many body bytes Perl's per-type `Read`
    // advanced the file pointer (1 for an audio/video config byte, `$len`
    // for a fully-read Meta body, 0 for a skipped/unhandled tag). The
    // trailing seek (Flash.pm:522 `$raf->Seek($len, 1) or last if $len`)
    // then skips the residual `len - consumed`; a seek that would run past
    // EOF short-seeks → Perl `last`, emulated by `break`.
    let consumed: usize;
    match r#type {
      0x08 => {
        // Flash.pm:496-507 — Audio (BitMask 0x04). First encounter reads ONE
        // config byte; later encounters skip the whole body.
        let mask: u8 = 0x04;
        if found & mask == 0 {
          found |= mask;
          flags &= !mask;
          // Flash.pm:500 `if ($len>=1 and $raf->Read($buff,1)==1)`.
          // Checked-indexing (Phase C w2b): `avail >= 1`
          // (`avail = data.len() - body_start`) ⇒ `data.get(body_start)` is
          // `Some` ⇒ `.unwrap_or(0)` is byte-identical.
          if len >= 1 && avail >= 1 {
            process_audio_octet(&mut entries, data.get(body_start).copied().unwrap_or(0));
            consumed = 1;
          } else {
            // Flash.pm:503-504 — short read of the config byte.
            warnings.push(SmolStr::new_static("Bad Audio packet"));
            break;
          }
        } else {
          // Already found — `$buff` undef, no HandleTag (Flash.pm:516 gated
          // on `defined $buff`); the whole body is seeked past below.
          consumed = 0;
        }
      }
      0x09 => {
        // Flash.pm:496-507 — Video (BitMask 0x01).
        let mask: u8 = 0x01;
        if found & mask == 0 {
          found |= mask;
          flags &= !mask;
          if len >= 1 && avail >= 1 {
            // Checked-indexing (Phase C w2b): `avail >= 1` ⇒ `data.get(body_start)`
            // is `Some` ⇒ byte-identical.
            process_video_octet(&mut entries, data.get(body_start).copied().unwrap_or(0));
            consumed = 1;
          } else {
            warnings.push(SmolStr::new_static("Bad Video packet"));
            break;
          }
        } else {
          consumed = 0;
        }
      }
      0x12 => {
        // Flash.pm:508-513 — Meta. `elsif ($raf->Read($buff,$len)==$len)`
        // reads the ENTIRE body before HandleTag; a short read warns
        // `Truncated Meta packet` and `last`s (Flash.pm:511). On success
        // `$len` is set to 0 (Flash.pm:509), so nothing is seeked after.
        if avail >= len {
          // Checked-indexing (Phase C w2b): `avail >= len`
          // (`avail = data.len() - body_start`) ⇒
          // `data.get(body_start..body_start + len)` is `Some` ⇒ byte-identical.
          let body = data.get(body_start..body_start + len).unwrap_or(&[]);
          process_meta(body, &mut entries, &mut warnings);
          consumed = len;
        } else {
          warnings.push(SmolStr::new_static("Truncated Meta packet"));
          break;
        }
      }
      _ => {
        // Unhandled type (no tagInfo/SubDirectory): `$buff` undef, no
        // HandleTag; `$len` unchanged → the whole body is seeked past.
        consumed = 0;
      }
    }

    // Flash.pm:521 `last unless $flags;` — happens BEFORE the residual seek.
    if flags == 0 {
      break;
    }

    // Flash.pm:522 `$raf->Seek($len, 1) or last if $len;` — skip the
    // residual `len - consumed` body bytes. A seek past EOF short-seeks →
    // Perl `last`. When fully consumed (residual 0) the pointer already
    // sits at `body_start + len`.
    if consumed < len {
      match body_start.checked_add(len) {
        Some(next) if next <= data.len() => pos = next,
        _ => break,
      }
    } else {
      pos = body_start + consumed;
    }
    continue;
  }

  Some(Meta {
    entries,
    warnings,
    _ph: core::marker::PhantomData,
  })
}

// ===========================================================================
// Audio / Video bit-stream packet decoders
// ===========================================================================

/// Decode the audio-configuration octet via the `%Flash::Audio` bit table
/// (Flash.pm:91-135). Big-endian: bit 0 is the MSB.
///
/// Layout (`Bit0-3`/`Bit4-5`/`Bit6`/`Bit7`):
///
/// - bits 0..=3 (MSB) — `AudioEncoding` (PrintConv hash, Flash.pm:96-113).
/// - bits 4..=5     — `AudioSampleRate` (ValueConv index → Hz hash,
///                    Flash.pm:114-122).
/// - bit  6         — `AudioBitsPerSample` (`ValueConv => '8 * ($val + 1)'`,
///                    Flash.pm:124-126).
/// - bit  7 (LSB)   — `AudioChannels` (`ValueConv => '$val + 1'`, PrintConv
///                    hash, Flash.pm:127-134).
fn process_audio_octet(entries: &mut std::vec::Vec<Entry>, byte: u8) {
  // AudioEncoding (`Bit0-3` ⇒ high nibble).
  let encoding = (byte >> 4) & 0x0f;
  entries.push(Entry {
    name: SmolStr::new_static("AudioEncoding"),
    value: FlashValue::Double(f64::from(encoding)),
    pc: PrintConvMode::None, // handled inline via AudioEncoding PrintConv
  });
  // The PrintConv mode for AudioEncoding is a hash, distinct from the
  // shared `PrintConvMode` modes; mark with a sentinel via a tagged enum
  // would over-engineer this — instead, the emit path matches on the
  // entry's `name` and applies the hash. To keep `PrintConvMode::None`'s
  // contract (no special handling), we re-route via the name. See
  // `serialize_tags` below.
  // (We store the raw nibble as a Double so the -n path emits the same
  // bare JSON number bundled Perl emits — `2` for AudioEncoding=2.)

  // AudioSampleRate (`Bit4-5`).
  let sr_idx = (byte >> 2) & 0x03;
  let sr_hz: u32 = match sr_idx {
    0 => 5512,
    1 => 11025,
    2 => 22050,
    3 => 44100,
    _ => unreachable!(),
  };
  entries.push(Entry {
    name: SmolStr::new_static("AudioSampleRate"),
    value: FlashValue::Double(f64::from(sr_hz)),
    pc: PrintConvMode::None,
  });

  // AudioBitsPerSample (`Bit6`): ValueConv `8 * ($val + 1)`.
  let bps_raw = (byte >> 1) & 0x01;
  let bps = 8 * (u32::from(bps_raw) + 1);
  entries.push(Entry {
    name: SmolStr::new_static("AudioBitsPerSample"),
    value: FlashValue::Double(f64::from(bps)),
    pc: PrintConvMode::None,
  });

  // AudioChannels (`Bit7`): ValueConv `$val + 1`, PrintConv hash.
  let ch_raw = byte & 0x01;
  let channels = u32::from(ch_raw) + 1;
  entries.push(Entry {
    name: SmolStr::new_static("AudioChannels"),
    value: FlashValue::Double(f64::from(channels)),
    pc: PrintConvMode::None,
  });
}

/// AudioEncoding PrintConv hash (Flash.pm:96-113). Used only by
/// `serialize_tags` (alloc-gated); the non-alloc tier doesn't reach it.
#[cfg_attr(not(feature = "json"), allow(dead_code))]
fn audio_encoding_pc(code: u32) -> Option<&'static str> {
  Some(match code {
    0 => "PCM-BE (uncompressed)",
    1 => "ADPCM",
    2 => "MP3",
    3 => "PCM-LE (uncompressed)",
    4 => "Nellymoser 16kHz Mono",
    5 => "Nellymoser 8kHz Mono",
    6 => "Nellymoser",
    7 => "G.711 A-law logarithmic PCM",
    8 => "G.711 mu-law logarithmic PCM",
    10 => "AAC",
    11 => "Speex",
    13 => "MP3 8-Khz",
    15 => "Device-specific sound",
    _ => return None,
  })
}

/// AudioChannels PrintConv hash (Flash.pm:130-133). Used only by
/// `serialize_tags` (alloc-gated); the non-alloc tier doesn't reach it.
#[cfg_attr(not(feature = "json"), allow(dead_code))]
fn audio_channels_pc(n: u32) -> Option<&'static str> {
  Some(match n {
    1 => "1 (mono)",
    2 => "2 (stereo)",
    _ => return None,
  })
}

/// Decode the video-configuration octet via the `%Flash::Video` bit table
/// (Flash.pm:138-154). The Perl table defines only `Bit4-7` — the high
/// nibble of the byte (in big-endian Bit ordering: bit-4 is the 4th MSB).
///
/// `Bit4-7` of an 8-bit MSB-first byte = `(byte >> 0) & 0x0f` — the low
/// nibble of the byte (FLAC.pm bit-extract: bit-0 is MSB, bit-7 is LSB,
/// so `Bit4-7` are the 4 LSBs).
fn process_video_octet(entries: &mut std::vec::Vec<Entry>, byte: u8) {
  let encoding = byte & 0x0f;
  entries.push(Entry {
    name: SmolStr::new_static("VideoEncoding"),
    value: FlashValue::Double(f64::from(encoding)),
    pc: PrintConvMode::None,
  });
}

/// VideoEncoding PrintConv hash (Flash.pm:144-153). Used only by
/// `serialize_tags` (alloc-gated); the non-alloc tier doesn't reach it.
#[cfg_attr(not(feature = "json"), allow(dead_code))]
fn video_encoding_pc(code: u32) -> Option<&'static str> {
  Some(match code {
    1 => "JPEG",
    2 => "Sorensen H.263",
    3 => "Screen Video",
    4 => "On2 VP6",
    5 => "On2 VP6 Alpha",
    6 => "Screen Video 2",
    7 => "H.264",
    _ => return None,
  })
}

// ===========================================================================
// AMF Meta packet processor (`ProcessMeta`, Flash.pm:290-461)
// ===========================================================================

/// Single AMF value type — either a leaf scalar emitted into [`Meta`] OR a
/// structural marker (object/array/object-end) the walker consumes.
///
/// `#[allow(dead_code)]` on the non-alloc tier: variant payloads are
/// matched on by the walker's struct-decode logic; the non-alloc tier
/// doesn't reach the alloc-gated serializer that further READS the fields
/// for emission.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "json"), allow(dead_code))]
enum AmfValue {
  /// AMF double (0x00) or typed numeric.
  Double(f64),
  /// AMF boolean (0x01) — raw u8.
  Boolean(u8),
  /// AMF string (0x02) or long-string (0x0c) or XML (0x0f).
  String(std::string::String),
  /// AMF date (0x0b) — pre-formatted "YYYY:MM:DD HH:MM:SS.ssssss±HH:MM".
  Date(std::string::String),
  /// AMF strict-array (0x0a) — structural marker. Carried by `read_value`
  /// only as the fallback if a 0x0a appears in a position where the
  /// walker did NOT dispatch to `walk_array` (defensive only — bundled's
  /// `process_meta` top-level + struct loops both branch on `is_struct`
  /// or `vtype == 0x0a` BEFORE calling read_value, so this variant
  /// should not surface in steady-state). Kept for defensive symmetry.
  StrictArray,
  /// AMF structure (object 0x03 / mixed-array 0x08 / typed-object 0x10).
  /// Carried only so the outer walker's last-value path can know
  /// `$isStruct{$t}` (Flash.pm:387/422) for the "ignore empty arrays" gate
  /// + "already handled" gate; no nested scalar is emitted from a Struct
  /// here.
  Struct,
  /// AMF object-end (0x09) sentinel (Flash.pm:389 `last if $t == 0x09`).
  ObjectEnd,
  /// AMF null (0x05) / undefined (0x06) / unsupported (0x0d) — empty value.
  Empty,
  /// AMF reference (0x07) — u16 (consumed for stream advancement only;
  /// bundled never emits a reference value at top level — the only branch
  /// that reaches `HandleTag` is the recursive call inside a struct, where
  /// `ref(\$val)` is scalar).
  Reference(#[allow(dead_code)] u16),
}

/// Outcome of [`read_value`]. Distinguishes a clean successful read from
/// a truncation (so callers can mirror bundled Flash.pm:455-457's
/// `Truncated AMF record 0x%x` warning) and from a clean end-of-buffer
/// (where bundled's inner ProcessMeta call's line 302 `last if $pos >=
/// $dirLen` exits BEFORE setting `$type` — no warning at that frame).
#[derive(Debug)]
#[cfg_attr(not(feature = "json"), allow(dead_code))]
enum ReadResult {
  /// Successful read; advance past the parsed value.
  Ok(AmfValue),
  /// Truncation detected by `read_value`. The carried `u8` is the LEAF
  /// type byte that was being read. `read_value` itself emits the
  /// `Truncated AMF record 0x%x` warning per Flash.pm:456; callers see
  /// this variant so they can decide whether to also propagate (the
  /// outer struct-walker drops its half-parsed children; the outer
  /// array-walker emits its OWN `Truncated AMF record 0xa` on top, per
  /// bundled's per-frame `$val=undef` semantic).
  Truncated(#[allow(dead_code)] u8),
  /// Unsupported AMF type byte (Flash.pm:435-439). `read_value` pushed
  /// the `AMF <name> record not yet supported` warning before returning;
  /// callers treat this as an abort cue (same as `Truncated` for control
  /// flow) but the top-level walker MUST NOT pop the warning under its
  /// "already had a value" rule — bundled's Flash.pm:437 Warn is
  /// unconditional (the `undef $type; last` at lines 438-439 still
  /// reaches line 455-457 with `$val` defined from a prior record, so
  /// the *truncation* warning at line 456 doesn't fire, but the
  /// dedicated unsupported-type warning at line 437 ALREADY fired).
  /// Mirrors Codex R2/F3: the prior `Truncated`-only discriminant let
  /// the top-level walker silently pop the unsupported diagnostic.
  Unsupported(#[allow(dead_code)] u8),
}

/// Outcome of [`walk_pairs`] / [`walk_array`]. Mirrors bundled Flash.pm's
/// `last Record` vs `last` (unlabeled) distinction inside the struct
/// branch's inner `for(;;)` pair loop (lines 348-401):
///
/// * `Continue` — exit the current walker via the object-end sentinel
///   (`0x09`, Flash.pm:389 `last if $t == 0x09` — unlabeled, so only the
///   inner for-loop exits; the outer `Record:` loop keeps going).
/// * `Abort` — every OTHER walker exit (truncated key payload, EOF before
///   a vtype byte, child scalar truncation/unsupported, child array
///   abort, etc.) maps to bundled's `last Record` (or to the line 386
///   `last Record unless defined $t and defined $v` triggered by a child
///   returning `(undef, _)` / `(_, undef)`). The OUTER walker (the
///   surrounding `Record:` for-loop or another `walk_pairs` frame) MUST
///   stop processing siblings on this signal.
///
/// Codex R4/F1: pre-fix, `walk_array` returned `()` and `walk_pairs`
/// unconditionally `continue`d after it → siblings after a failed array
/// were silently emitted (bundled drops them via `last Record`). The new
/// typed outcome makes the abort flow explicit and propagated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "json"), allow(dead_code))]
enum WalkOutcome {
  /// Normal exit — caller may continue processing siblings/records.
  Continue,
  /// `last Record` cue — outer walker must stop processing siblings and
  /// the surrounding `Record:` loop must terminate.
  Abort,
}

/// Outcome of [`collect_array_items`]. Distinguishes bundled Flash.pm's
/// two array-failure surfaces so callers can mirror line 455's
/// `$val=undef && $type=0xa` warning emission per their own bundled
/// frame state.
///
/// * `Ok(items)` — all elements consumed; the helper advanced past the
///   4-byte count and every per-element payload.
/// * `TruncatedCount` — `*pos + 4 > data.len()` at the count read
///   (Flash.pm:411 `last if $pos + 4 > $dirLen` — fires WITHOUT advancing
///   $pos and WITHOUT emitting any warning at this point). The post-loop
///   line 455 check (`not defined $val and defined $type`) THEN decides
///   emission based on the CALLER's $val-on-entry state:
///   * Top-level (`process_meta` direct dispatch): bundled's $val may be
///     set by prior records — gate on `top_val_seen`.
///   * Keyed-value (`walk_array` via `walk_pairs`): recursive ProcessMeta
///     call has a FRESH local $val=undef → ALWAYS emit.
///   * Nested (recursion inside `collect_array_items`): the recursion
///     site is itself a frame with $val=undef → both this frame AND the
///     inner frame emit; the recursion site pushes inner's, then this
///     frame returns `Abort` after pushing its own outer-frame warning
///     (matching the pre-R9 nested-Abort behavior).
/// * `Abort` — element-payload failure (truncated leaf, unsupported
///   element type, struct-intro fail, nested-array abort, etc.). The
///   helper's own frame-level `"Truncated AMF record 0xa"` warning is
///   ALREADY pushed before returning (matching the pre-R9 behavior — the
///   helper IS the outer 0xa frame from bundled's perspective for these
///   mid-loop failures). Callers treat as an abort cue (no extra push).
///
/// Codex PR #32 R9/F1 motivation: pre-R9 the helper returned `None`
/// SILENTLY on truncated-count, conflated with the element-failure
/// path. The keyed-value caller `walk_array` then propagated `Abort`
/// WITHOUT pushing any warning, dropping bundled's `Truncated AMF
/// record 0xa` (Flash.pm:455) for that branch. Silent metadata loss in
/// the malformed-AMF path — pinned by
/// `flash_keyed_array_truncated_count_conformance`.
#[derive(Debug)]
#[cfg_attr(not(feature = "json"), allow(dead_code))]
enum ArrayOutcome {
  /// Successful read of all `count` elements.
  Ok(std::vec::Vec<FlashListItem>),
  /// `*pos + 4 > data.len()` at the count read (Flash.pm:411). NO
  /// warning pushed by the helper — callers decide per their bundled
  /// frame state.
  TruncatedCount,
  /// Element-payload failure mid-loop. The helper has ALREADY pushed
  /// its own `"Truncated AMF record 0xa"` (the outer 0xa frame's line
  /// 455 emission) before returning. Callers treat as abort cue.
  Abort,
}

/// Outcome of [`consume_struct_intro`]. Distinguishes the bundled `last`
/// vs `last Record` cues for the struct-introducer paths (Flash.pm:343
/// for mixed-array top-index, lines 350-356 for typed-object name).
///
/// * `Ok` — introducer consumed cleanly.
/// * `Truncated(reason)` — bundled `last` / `last Record` cue. The
///   [`IntroTruncReason`] payload distinguishes:
///   * `TopIndex` — 0x08 line 343 (mixed-array top-index too short).
///     Helper pushed NO warning ($val='' suppresses line 455); the
///     caller must ALSO push no warning of its own. SILENT path.
///   * `NameLength` — 0x10 line 350 (typed-object 2-byte name-length
///     field too short). Same silent semantics as TopIndex.
///   * `TypedObjectName` — 0x10 lines 352-354 (name payload overrun).
///     Helper ALREADY pushed `"Truncated typedObject record"`
///     (Flash.pm:353 exact text). Callers must NOT push their own
///     frame warning either: the bundled `-j` JSON surface emits ONLY
///     the typedObject warning for this path (the outer `-v3` re-read
///     diagnostics don't reach JSON).
///
/// All three reasons require the caller to ABORT its loop (the bundled
/// `last Record` cue propagates upward), but they differ in WHICH
/// warning, if any, the caller should add on top.
///
/// Codex PR #32 R10 motivation: R9/F2 introduced silent
/// `IntroOutcome::Truncated` returns for 0x10 name-LENGTH and 0x08
/// top-index, but the strict-array element caller
/// [`collect_array_items`] wrapped EVERY `Truncated` with a single
/// `"Truncated AMF record 0xa"` push — converting bundled's silent
/// paths into user-visible warnings. Adding a reason payload lets the
/// caller route each path to the bundled-correct emission set:
///   * `TopIndex` / `NameLength` → caller pushes NOTHING.
///   * `TypedObjectName` → caller pushes NOTHING (helper already did).
///
/// Pinned by:
///   * `flash_array_typed_object_truncated_length_conformance` (R10),
///   * `flash_array_mixed_array_truncated_top_index_conformance` (R10),
///   * `flash_array_typed_object_truncated_name_conformance` (R9,
///     must STILL pass post-R10 — typedObject warning surfaces).
///
/// Codex PR #32 R9/F2 motivation (retained): pre-R9 `skip_struct_intro`
/// returned a silent `bool` and the 0x10 name-payload-overrun path was
/// lumped into a silent `false` return. Top-level callers
/// (`process_meta`) dropped the bundled `"Truncated typedObject
/// record"` warning; nested-in-array callers (`collect_array_items`)
/// emitted the WRONG warning text. Pinned by
/// `flash_typed_object_truncated_name_conformance` (top-level) and
/// `flash_array_typed_object_truncated_name_conformance` (nested).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(not(feature = "json"), allow(dead_code))]
enum IntroOutcome {
  /// Introducer (mixed-array top-index / typed-object name) consumed.
  Ok,
  /// Bundled `last` / `last Record` cue. The reason payload tells
  /// callers whether the helper already pushed a warning AND whether
  /// the caller should add its own frame-level warning. See
  /// [`IntroTruncReason`].
  Truncated(IntroTruncReason),
}

/// Which struct-introducer field ran out of bytes inside
/// [`consume_struct_intro`]. Drives the caller's warning emission
/// decision (Flash.pm:340-356, 455). See [`IntroOutcome::Truncated`]
/// for per-reason semantics.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(not(feature = "json"), allow(dead_code))]
enum IntroTruncReason {
  /// 0x08 mixed-array — the 4-byte top-index field is truncated
  /// (Flash.pm:343 `last if $pos + 4 > $dirLen`). SILENT.
  TopIndex,
  /// 0x10 typed-object — the 2-byte name-length field itself is
  /// truncated (Flash.pm:350 `last Record if $pos + 2 > $dirLen`).
  /// SILENT.
  NameLength,
  /// 0x10 typed-object — the name PAYLOAD overruns
  /// (Flash.pm:352-354). The helper pushed `"Truncated typedObject
  /// record"`; callers must abort their loop but NOT add another
  /// frame warning.
  TypedObjectName,
}

/// Which `%Flash::*` sub-table the current walk is operating against. Each
/// has its own key→name map (Flash.pm:157/250/267).
#[derive(Clone, Copy, Debug)]
enum SubTable {
  /// `%Flash::Meta` (Flash.pm:157-247) — the top-level onMetaData table.
  Meta,
  /// `%Flash::CuePoint` (Flash.pm:250-264).
  CuePoint,
  /// `%Flash::Parameter` (Flash.pm:267-274) — no explicit keys; everything
  /// auto-adds.
  Parameter,
}

/// `%Flash::CuePoint` (Flash.pm:257-263) — explicit table entries.
fn lookup_cuepoint(key: &str) -> Option<(&'static str, Option<SubTable>)> {
  Some(match key {
    "name" => ("Name", None),
    "type" => ("Type", None),
    "time" => ("Time", None),
    // Flash.pm:260-263 — `parameters` SubDirectory: tag-name `Parameter`,
    // descend into `%Flash::Parameter`.
    "parameters" => ("Parameter", Some(SubTable::Parameter)),
    _ => return None,
  })
}

/// SubDirectory hop on a RAW key (no prefix applied). Faithful to
/// Flash.pm:365-374 — the SubDir lookup uses the un-prefixed key. Returns
/// `Some((tag_rewrite, new_sub_table))` when the raw key has a
/// `SubDirectory => Image::ExifTool::Flash::*` entry, else `None`.
///
/// Faithfulness note: Flash.pm:370 guards the table-swap with
/// `if ($subTable =~ /^Image::ExifTool::Flash::/)`, so a SubDirectory whose
/// target lives OUTSIDE `Image::ExifTool::Flash::*` (notably the `liveXML →
/// XMP::Main` entry at Flash.pm:243-246) is NOT swapped here. Bundled Perl
/// instead passes the raw payload to `HandleTag`, which dispatches the
/// SubDirectory to the foreign module (XMP::Main) at engine level. The XMP
/// dispatch is handled separately in [`is_xmp_subdirectory_dispatch`] —
/// see that helper for the accepted-deferral contract.
fn raw_subdirectory_hop(table: SubTable, raw_key: &str) -> Option<(&'static str, SubTable)> {
  match (table, raw_key) {
    // Flash.pm:185-188.
    (SubTable::Meta, "cuePoints") => Some(("CuePoint", SubTable::CuePoint)),
    // Flash.pm:260-263.
    (SubTable::CuePoint, "parameters") => Some(("Parameter", SubTable::Parameter)),
    // Flash.pm:243-246 (`liveXML → XMP::Main`) is INTENTIONALLY NOT mapped
    // here — its SubDirectory target is foreign (not `Image::ExifTool::
    // Flash::*`), so Flash.pm:370's table-swap guard does NOT fire.
    // See [`is_xmp_subdirectory_dispatch`] for how the deferral surfaces.
    _ => None,
  }
}

/// ACCEPTED DEFERRAL (Codex PR #32 R6) — Flash.pm dispatches the `liveXML`
/// key (Flash.pm:243-246) through a SubDirectory pointing at
/// `Image::ExifTool::XMP::Main`. The XMP parser is FORMATS.md row 15
/// (XMP.pm + XMP2.pl, 6693 LOC) — a Phase-3+ infrastructure port. Tracked
/// in [[exifast-phase2-forward-items]].
///
/// Until the XMP infrastructure lands, we cannot reproduce the bundled
/// `XMP-*:*` tag set that Perl emits via `HandleTag → ProcessSubDir →
/// XMP::ProcessXMP`. The faithful interim behaviour is to:
///   1. Push a `Warning` so the deferral is VISIBLE (matches the bundled
///      `$et->Warn(...)` pattern — emitted via `ExifTool:Warning`).
///   2. SKIP the auto-add scalar fallback. Without this skip, the
///      unrecognized-key path at `resolve_emit` would manufacture a
///      `Flash:LiveXML` scalar containing the raw `<x:xmpmeta...>` blob —
///      a WRONG-SHAPE tag bundled Perl never emits.
///
/// Returns `true` when the (table, raw_key) pair is the XMP dispatch and
/// the value must be consumed-then-dropped with a deferral warning.
///
/// Codex PR #32 R7 — TOP-LEVEL ONLY. The XMP SubDirectory dispatch matches
/// bundled Flash.pm's behaviour ONLY when the raw key `liveXML` is the
/// final emitted tag (i.e. no parent prefix in effect). Walk:
///
///   * Flash.pm:365 probes the SubDirectory using the RAW (un-prefixed)
///     `$tag` against `$tagTablePtr` (still Meta).
///   * Line 370's guard `if ($subTable =~ /^Image::ExifTool::Flash::/)` is
///     FALSE for the foreign XMP target, so `$tag` is NOT rewritten and
///     `$subTablePtr` is NOT swapped.
///   * Line 380 then applies the parent-prefix: `$tag = $structName .
///     ucfirst($tag) if defined $structName`. For a nested `foo.liveXML`
///     this yields `$tag = "FooLiveXML"`.
///   * Line 390's lookup `$$subTablePtr{$tag}` runs against the un-swapped
///     Meta table, so `liveXML` (un-prefixed) is the ONLY key that matches
///     the SubDirectory entry. `FooLiveXML` falls through to AddTagToTable
///     (Flash.pm:390-393) and HandleTag emits a plain scalar
///     `Flash:FooLiveXML` — bundled does NOT dispatch the XMP packet here.
///
/// Pre-R7 gate `(SubTable::Meta && raw_key == "liveXML")` matched a NESTED
/// `liveXML` as well, dropping the auto-add scalar with the XMP-deferral
/// warning. Silent metadata loss on the nested branch — exactly what the
/// `flash_nested_livexml.flv` adversarial fixture pins. Gate the dispatch
/// on the un-prefixed-tag condition by requiring `struct_name.is_none()`
/// (matches the call site at the top of a `walk_pairs` frame where the
/// parent's `$structName` is `undef`).
///
/// Codex PR #32 R8 — `Option<&str>` lets the gate distinguish Perl's
/// `undef` (`None` = no struct in effect, top-level) from a DEFINED empty
/// string (`Some("")` = inside an object keyed by `""`). Bundled walks
/// the `Some("")` branch with `defined $structName` TRUE, so Flash.pm:380
/// applies the prefix (`"" . ucfirst("liveXML") = "LiveXML"`) and emits
/// `Flash:LiveXML` as a plain auto-add scalar — no XMP suppression.
/// Pre-R8 code collapsed both states under `is_empty()` and silently
/// dropped the empty-key `liveXML` child with an XMP-deferral warning.
/// See `flash_empty_key_livexml.flv` adversarial fixture (R8/F1).
fn is_xmp_subdirectory_dispatch(table: SubTable, struct_name: Option<&str>, raw_key: &str) -> bool {
  // Flash.pm:243-246 — the only entry whose SubDirectory target is NOT
  // `Image::ExifTool::Flash::*`. `liveXML` only appears under the Meta
  // sub-table (the `onXMPData` packet body); CuePoint/Parameter children
  // do not match. The `struct_name.is_none()` clause restricts the gate
  // to the TOP-LEVEL undef-structName case (Codex R7+R8 — see fn doc-
  // comment). `Some("")` (defined empty) is NOT top-level; it falls
  // through to the auto-add `Flash:LiveXML` emit path below.
  matches!(table, SubTable::Meta) && struct_name.is_none() && raw_key == "liveXML"
}

/// Resolve the FINAL emitted tag attributes for a scalar emission. The
/// input `full_key` is the FULL prefix-applied tag (Flash.pm:380 result).
/// Faithful to Flash.pm:390-394 — `$$subTablePtr{$tag}` lookup with the
/// full tag, else auto-add with `Name => ucfirst($tag)`.
fn resolve_emit(table: SubTable, full_key: &str) -> EmitResolution {
  match table {
    SubTable::Meta => {
      if let Some(t) = lookup_meta(full_key) {
        return EmitResolution {
          name: t.name.into(),
          mul_1000: t.mul_1000,
          pc: t.pc,
          trim_trailing_ws: t.trim_trailing_ws,
        };
      }
      EmitResolution {
        name: ucfirst(full_key),
        mul_1000: false,
        pc: PrintConvMode::None,
        trim_trailing_ws: false,
      }
    }
    SubTable::CuePoint => {
      if let Some((name, _sub)) = lookup_cuepoint(full_key) {
        return EmitResolution {
          name: name.into(),
          mul_1000: false,
          pc: PrintConvMode::None,
          trim_trailing_ws: false,
        };
      }
      EmitResolution {
        name: ucfirst(full_key),
        mul_1000: false,
        pc: PrintConvMode::None,
        trim_trailing_ws: false,
      }
    }
    SubTable::Parameter => EmitResolution {
      name: ucfirst(full_key),
      mul_1000: false,
      pc: PrintConvMode::None,
      trim_trailing_ws: false,
    },
  }
}

/// Scalar-emission resolution (Flash.pm:390-394). Separate from the
/// SubDirectory hop so the table-walk's SubDir detection (line 365) and
/// emission (line 391) match Perl exactly.
///
/// `#[allow(dead_code)]` on non-alloc: fields populate the emit-time path
/// only. The parser itself doesn't reach the alloc-gated emit.
#[cfg_attr(not(feature = "json"), allow(dead_code))]
struct EmitResolution {
  /// Final emitted tag name.
  name: std::string::String,
  mul_1000: bool,
  pc: PrintConvMode,
  trim_trailing_ws: bool,
}

/// Perl `ucfirst` (ASCII-only — our AMF keys are identifier-shaped).
fn ucfirst(s: &str) -> std::string::String {
  let mut chars = s.chars();
  match chars.next() {
    Some(c) => {
      let mut out = std::string::String::with_capacity(s.len());
      out.push(c.to_ascii_uppercase());
      out.push_str(chars.as_str());
      out
    }
    None => std::string::String::new(),
  }
}

/// Top-level meta packet processor (Flash.pm:290-461 in non-single mode).
/// Walks records in order; each record reads one AMF type+value pair.
///
/// Record loop semantics (Flash.pm:301-454):
///
/// - First record is the packet-name string (`onMetaData`/`onXMPData`):
///   gate-test, ignore otherwise (Flash.pm:444-447).
/// - Struct records (object/mixed-array/typed-object): recursive descent
///   walks the children; the struct itself doesn't emit a parent tag.
/// - Non-first scalar records: silently ignored (Flash.pm:449-452 verbose-only).
fn process_meta(
  data: &[u8],
  entries: &mut std::vec::Vec<Entry>,
  warnings: &mut std::vec::Vec<SmolStr>,
) {
  let mut pos = 0usize;
  let mut rec = 0usize;
  // Bundled Flash.pm:297 `my ($type, $val, $rec);` — `$val` PERSISTS
  // across iterations of the Record loop. Line 455 `not defined $val and
  // defined $type` then ONLY fires if no prior iteration successfully
  // assigned `$val`. We track this with a bool: `top_val_seen` becomes
  // true after the first record successfully reads a value; subsequent
  // truncations do NOT emit the warning (matches bundled — verified via
  // synthetic FLV where rec=1 truncated double after a valid rec=0
  // string did NOT warn).
  let mut top_val_seen = false;
  loop {
    if pos >= data.len() {
      break;
    }
    // Checked-indexing (Phase C w2b): the `pos >= data.len()` guard makes
    // `data.get(pos)` `Some` ⇒ `.unwrap_or(0)` is byte-identical.
    let r#type = data.get(pos).copied().unwrap_or(0);
    pos += 1;
    // Flash.pm:442-453 — top-level handling per record.
    if is_struct(r#type) {
      // Struct: consume struct introducer (4-byte mixed-array top-index OR
      // 2-byte+name for typed-object) THEN walk children with no
      // struct-name prefix. Bundled Flash.pm:340 sets `$val = ''` BEFORE
      // the intro check, so `$val` IS defined at the post-loop line 455
      // check (no extra "Truncated AMF record 0x%x" warning fires at
      // this top frame).
      //
      // Codex R9/F2 — `consume_struct_intro` pushes
      // `"Truncated typedObject record"` (Flash.pm:353) on a 0x10
      // typed-object name-payload overrun. Pre-R9 the silent `bool`
      // dropped this warning entirely at top level; pinned by
      // `flash_typed_object_truncated_name_conformance`.
      //
      // Codex PR #32 R10 — `IntroOutcome::Truncated(reason)` carries the
      // bundled `last` / `last Record` cue's reason. ALL reasons at
      // top-level terminate `process_meta` (bundled's outermost
      // ProcessMeta call ends here: line 354's `last Record` exits the
      // OUTERMOST Record loop). The reason payload is irrelevant at
      // this site because no enclosing array/struct frame can add its
      // own warning — the only emission decision is at the helper
      // level (typedObject-name-overrun pushes "Truncated typedObject
      // record"; the silent reasons push nothing).
      if matches!(
        consume_struct_intro(data, &mut pos, r#type, warnings),
        IntroOutcome::Truncated(_)
      ) {
        return;
      }
      // Codex R4/F1 — propagate `last Record` from the struct walk.
      // Bundled Flash.pm:382-386 (the surrounding outer Record loop
      // around the struct branch) terminates on a child's `last
      // Record` cue (truncated key, child scalar truncation,
      // unsupported AMF type, or a deeper nested abort). Mirror by
      // breaking the top-level Record loop when walk_pairs signals
      // Abort. Pre-fix `walk_pairs` returned `()`, so this loop
      // continued past a failed struct walk → spurious records
      // parsed from a wrong offset / siblings emitted that bundled
      // dropped.
      // Codex PR #32 R8 — top-level walk: bundled's
      // `$$dirInfo{StructName}` is `undef` at the outer Record loop's
      // entry (Flash.pm:296 `my ($type, $val, $rec)` does not assign
      // StructName), so we pass `None`. Pre-R8 passed `""` which
      // collapsed Perl's undef (top-level) vs defined-empty (empty-key
      // parent) — see R8/F1 fixture.
      let outcome = walk_pairs(
        0, // top-level packet walk — depth 0
        data,
        &mut pos,
        r#type,
        SubTable::Meta,
        None,
        entries,
        warnings,
      );
      // Treat the struct walk as setting `$val` (to the dummy '') for the
      // bundled semantics — the next iteration's truncation won't warn.
      top_val_seen = true;
      if outcome == WalkOutcome::Abort {
        break;
      }
    } else if r#type == 0x0a {
      // Codex R3/F3 — top-level strict-array (Flash.pm:410-426 reached
      // by the outer record loop, NOT only via struct children). Bundled
      // consumes the u32 count + every element (recursive ProcessMeta
      // call per element) then sets `$val = \@vals` and falls through to
      // line 442's `unless ($isStruct{$type})` block: 0x0a is NOT in
      // `%isStruct` so it enters the else at lines 448-452 (verbose-only
      // "ignored lone array value" — NO emit). Record loop then advances
      // to the next iteration. Prior shape called `read_value` here,
      // which returned `AmfValue::StrictArray` WITHOUT consuming the
      // count or elements → cursor desync → subsequent records parsed
      // from a wrong offset → silent data loss for the entire packet
      // tail. Mirror bundled by delegating to the shared
      // `collect_array_items` helper (refactored under R2/F2) which
      // consumes count+payload faithfully; we drop the returned list
      // (top-level lone arrays are not emitted per Flash.pm:449-452).
      //
      // Faithfulness chain at the top level differs from inside a
      // struct walk: bundled's Frame-2 (this loop) does NOT wrap the
      // array result in a `$val = \@vals` assignment under a tag name
      // — the array branch already populated `$val` directly, and the
      // verbose-only branch at 449-452 only logs. The packet-gate at
      // rec=0 (Flash.pm:444 `0x02 and not $rec`) doesn't match for
      // 0x0a so even rec=0 falls into the verbose-else (no `last`).
      // The bundled `unsupported`/`Truncated` warning paths from
      // `collect_array_items` are still active.
      //
      // This branch never emits a parent tag, so there is no owning-tag
      // ValueConv: pass `ArrayValueConv::NEUTRAL` (a lone top-level array is
      // verbose-only-ignored at Flash.pm:449-452).
      //
      // Codex PR #32 R8 — top-level strict-array: bundled enters the
      // 0x0a branch with `$structName` undef. We pass `None` so the
      // inner per-element walks ALSO inherit `None` (Flash.pm:418 does
      // not fire), and struct children inside emit un-prefixed
      // (`Flash:Name` last-wins for the
      // `flash_toplevel_array_objects.flv` fixture, R8/F2).
      match collect_array_items(
        0, // top-level lone array — depth 0
        data,
        &mut pos,
        SubTable::Meta,
        None,
        ArrayValueConv::NEUTRAL,
        entries,
        warnings,
      ) {
        ArrayOutcome::Ok(_collected) => {
          // Bundled Flash.pm:449-452 — verbose-only "ignored lone array
          // value". Drop the collected list silently.
          top_val_seen = true;
        }
        ArrayOutcome::TruncatedCount => {
          // Codex R9/F1 — bundled top-level: $val from prior records
          // (e.g. rec=0's `onMetaData` string) may still be defined.
          // Gate on `top_val_seen` per the same prior-records-define-
          // $val rule used by the scalar `ReadResult::Truncated` arm
          // below. If `top_val_seen=false`, $val=undef + $type=0xa →
          // push `"Truncated AMF record 0xa"`. If true, bundled stays
          // silent.
          if !top_val_seen {
            warnings.push(SmolStr::new_static("Truncated AMF record 0xa"));
          }
          break;
        }
        ArrayOutcome::Abort => {
          // Helper already pushed its own frame warning (and any leaf
          // diagnostics). Bundled's Frame 2 then `last Record` (line
          // 420's `last Record unless defined $v`). Mirror by breaking.
          break;
        }
      }
    } else {
      // Top-level scalar: read its value.
      match read_value(data, &mut pos, r#type, warnings) {
        ReadResult::Ok(vval) => {
          if rec == 0 {
            // Packet-gate (Flash.pm:444-447). Only processed packet names
            // continue the record loop; everything else `last`s.
            if let AmfValue::String(s) = &vval {
              if !is_processed_packet(s.as_str()) {
                break;
              }
            }
            // Non-string first records also fail the gate (lookup yields false).
          }
          top_val_seen = true;
          // else: silently ignored (Flash.pm:449-452 verbose-only).
        }
        ReadResult::Truncated(_) => {
          // Bundled Flash.pm:455-457 — emit "Truncated AMF record 0x%x"
          // ONLY if `$val` was never set by a prior record. We mirror by
          // gating on `top_val_seen`: at rec=0 (top_val_seen=false) the
          // warning is appropriate; at rec>0 (top_val_seen=true) bundled
          // silently exits because `$val` retains the prior value.
          //
          // `read_value` ALREADY pushed the warning unconditionally. To
          // mirror bundled's $val-retains semantic, we POP the warning
          // back off if we're at the top level with a prior successful
          // read. (read_value can't know its caller's context.)
          if top_val_seen {
            // Pop the just-emitted truncation warning so the top-level
            // truncation-after-valid-record case stays silent (bundled
            // behavior — `$val` still defined from prior record). The
            // warning we pop is the one read_value just pushed; per-
            // function design this is always the most recent.
            warnings.pop();
          }
          break;
        }
        ReadResult::Unsupported(_) => {
          // Codex R2/F3 — Flash.pm:437 Warn is UNCONDITIONAL (does not
          // gate on `$val` defined). We DO NOT pop the warning here; the
          // dedicated `"AMF <name> record not yet supported"` diagnostic
          // stays in `warnings` regardless of `top_val_seen`. Bundled
          // then `undef $type; last` (lines 438-439) before reaching
          // the post-loop truncation gate at 455 — so the truncation
          // warning never fires either way. Net: only the unsupported
          // diagnostic survives. Mirror by simply breaking; the warning
          // is already pushed by `read_value`.
          break;
        }
      }
    }
    rec += 1;
  }
}

/// Walk the children of an open struct: a sequence of `<u16-keylen><key
/// bytes><type byte><value>` pairs, terminated by the `0x00 0x00 0x09`
/// (zero-length key + object-end) sentinel.
///
/// `struct_type` is the AMF type byte that introduced this struct
/// (`0x03`/`0x08`/`0x10`); it drives the FAITHFUL warning text on a
/// truncated key (Flash.pm:353 `$et->Warn("Truncated $amfType[$type]
/// record")` — emits `Truncated object record` / `Truncated mixedArray
/// record` / `Truncated typedObject record` respectively).
///
/// `struct_name` is the prefix to prepend to each emitted child tag name
/// (Flash.pm:380 `$structName . ucfirst($tag)`).
///
/// Codex PR #32 R8 — `Option<&str>` distinguishes Perl's `undef` (`None`,
/// top-level / no struct in effect) from a DEFINED empty string
/// (`Some("")`, e.g. a child under a key `""`). Bundled gates BOTH the
/// prefix application (Flash.pm:380 `if defined $structName`) AND the
/// array-index append (Flash.pm:418 `if defined $structName`) on the
/// `defined` condition; the empty-string carrier still triggers both
/// (its emitted prefix is empty but the code path is the "defined"
/// branch). Pre-R8 `&str` + `is_empty()` collapsed both states:
///   * `liveXML` under an empty-key parent was suppressed via the XMP-
///     deferral path instead of emitted as `Flash:LiveXML` (R8/F1).
///   * Top-level strict-array struct children received spurious
///     `0Name`-style prefixes that bundled never appends (R8/F2).
fn walk_pairs(
  depth: u32,
  data: &[u8],
  pos: &mut usize,
  struct_type: u8,
  table: SubTable,
  struct_name: Option<&str>,
  entries: &mut std::vec::Vec<Entry>,
  warnings: &mut std::vec::Vec<SmolStr>,
) -> WalkOutcome {
  // Golden-v2 3a — recursion-depth guard for the AMF object/array cluster.
  // Real `onMetaData` nests a couple of levels, far below `MAX_AMF_DEPTH`, so
  // this never trips on a real file (byte-identical); it bounds stack growth
  // on a maliciously deep AMF tree. Stop as a bundled `last Record`.
  if depth >= MAX_AMF_DEPTH {
    return WalkOutcome::Abort;
  }
  loop {
    // Read key (u16-prefixed). Bundled Flash.pm:350 `last Record if $pos
    // + 2 > $dirLen` — no warning at this point ($val=''). Bundled DOES
    // exit the Record loop here (the `Record` label is explicit), so we
    // signal `Abort` for our caller (process_meta) to also stop the
    // outer record loop. NO warning is pushed (matches bundled — line
    // 455's `not defined $val` is false because $val='' from line 340).
    if *pos + 2 > data.len() {
      return WalkOutcome::Abort;
    }
    // Checked-indexing (Phase C w2b): the `*pos + 2 > data.len()` guard makes
    // `data.get(*pos..*pos + 2)` `Some` ⇒ byte-identical.
    let key_len = match data.get(*pos..*pos + 2) {
      Some(&[b0, b1]) => u16::from_be_bytes([b0, b1]) as usize,
      _ => 0,
    };
    if *pos + 2 + key_len > data.len() {
      // Flash.pm:352-354 — key payload truncation: emit
      // `Truncated <amfTypeName> record` where amfTypeName depends on the
      // OUTER struct type (`object` / `mixedArray` / `typedObject`),
      // then `last Record`.
      let name = amf_type_name(struct_type);
      warnings.push(SmolStr::from(std::format!("Truncated {name} record")));
      return WalkOutcome::Abort;
    }
    // Checked-indexing (Phase C w2b): the `*pos + 2 + key_len > data.len()`
    // guard makes `data.get(*pos + 2..*pos + 2 + key_len)` `Some` ⇒
    // byte-identical.
    let raw_key = data.get(*pos + 2..*pos + 2 + key_len).unwrap_or(&[]);
    // Flash.pm:357 `$tag = substr($$dataPt, $pos + 2, $len)` keeps the RAW
    // key bytes. The key reaches output as a tag NAME only through the
    // `/^\w+$/` auto-add gate (Flash.pm:390, our `is_word_key`), which
    // rejects any high byte regardless of UTF-8 validity (oracle:
    // `b\xffd` ⇒ tag dropped; valid sibling still emits). `is_word_key`
    // already replicates that byte-level rejection. We still decode via
    // `fix_utf8` (not `from_utf8_lossy`) so the data model matches
    // bundled's FixUTF8-at-JSON rendering — keeping every payload-derived
    // string on the single faithful seam (Codex PR #32 R18/F1
    // class-sweep). Both decodes feed the same gate decision; this is the
    // faithful representation, not a behavior change.
    let key = fix_utf8(raw_key);
    *pos += 2 + key_len;

    // Read value type byte. Bundled inner ProcessMeta line 302 `last if
    // $pos >= $dirLen` exits BEFORE setting `$type` → returns
    // `(undef, undef)`. Outer struct walker at line 386 then hits
    // `last Record unless defined $t and defined $v` → Abort. No
    // warning is pushed at the inner frame ($val='' kept; $type undef
    // at line 455 disables the warning either way).
    if *pos >= data.len() {
      return WalkOutcome::Abort;
    }
    // Checked-indexing (Phase C w2b): the `*pos >= data.len()` guard makes
    // `data.get(*pos)` `Some` ⇒ byte-identical.
    let vtype = data.get(*pos).copied().unwrap_or(0);
    *pos += 1;

    // Object-end sentinel: 0-length key + type 0x09. Bundled `last if
    // $t == 0x09` (Flash.pm:389) is UNLABELED — it exits ONLY the inner
    // for(;;) pair loop, NOT the outer Record loop. Net: subsequent
    // top-level records (after the struct closes) still process. Signal
    // `Continue` so process_meta moves to the next record.
    if vtype == 0x09 {
      return WalkOutcome::Continue;
    }

    // Flash.pm:365 — SubDirectory hop on the RAW (un-prefixed) key. If a
    // SubDir applies, rewrite `$tag` to the SubDir's `Name` AND swap the
    // active sub-table for the recursive walk.
    let (tag_after_subdir, sub_table_for_value): (std::string::String, SubTable) =
      match raw_subdirectory_hop(table, &key) {
        Some((new_name, new_table)) => (new_name.into(), new_table),
        None => (key.clone(), table),
      };
    // Flash.pm:380 — apply parent prefix: `$tag = $structName .
    // ucfirst($tag) if defined $structName`. The ucfirst is applied to
    // the SubDir-rewritten tag ONLY when `$structName` is defined.
    //
    // Codex PR #32 R8 — match Perl's `defined $structName` gate exactly:
    //
    //   * `struct_name == None` → Perl undef (top-level / no struct in
    //     effect). `$tag` is NOT modified at line 380; it stays as the
    //     raw lowercase AMF key (e.g. `duration`, `liveXML`). Downstream
    //     `resolve_emit` looks the lowercase key up in `%Flash::Meta` —
    //     a match yields the canonical name; a miss auto-adds with
    //     `ucfirst($tag)` (e.g. `liveXML` MISSES the Meta entry because
    //     of the SubDirectory dispatch at Flash.pm:243-246, and `liveXML`
    //     is then routed through `is_xmp_subdirectory_dispatch` ABOVE
    //     for the top-level XMP-deferral path).
    //
    //   * `struct_name == Some(s)` → Perl defined (possibly empty). Line
    //     380 fires: `$tag = $s . ucfirst($tag)`. Empty `s` produces just
    //     `ucfirst($tag)` (uppercase first char). The downstream
    //     `resolve_emit` Meta lookup then MISSES the lowercase-keyed
    //     entries (e.g. `LiveXML` misses the `liveXML` SubDirectory
    //     entry), so the auto-add path emits `Flash:LiveXML` as a plain
    //     scalar — exactly bundled's empty-key-parent behaviour.
    //
    // Pre-R8 code collapsed `Some("")` into the `None` branch, yielding
    // raw lowercase `liveXML` which then hit `is_xmp_subdirectory_dispatch`
    // and DROPPED the value with an XMP-deferral warning. The
    // `flash_empty_key_livexml.flv` adversarial fixture pins this
    // recovery.
    let full_tag = match struct_name {
      None => {
        // Perl undef — no prefix, no ucfirst (Flash.pm:380 does not fire).
        // The lowercase key reaches `resolve_emit` / the XMP gate as-is.
        tag_after_subdir.clone()
      }
      Some(prefix) => {
        // Perl defined (possibly empty). Apply `$prefix . ucfirst($tag)`.
        let mut s = std::string::String::with_capacity(prefix.len() + tag_after_subdir.len());
        s.push_str(prefix);
        let mut iter = tag_after_subdir.chars();
        if let Some(first) = iter.next() {
          s.push(first.to_ascii_uppercase());
          s.push_str(iter.as_str());
        }
        s
      }
    };

    if is_struct(vtype) {
      // Struct child: consume introducer, then recurse into child pairs
      // with the (possibly-swapped) sub-table and `full_tag` as the new
      // struct-name carry.
      //
      // Codex R9/F2 — `consume_struct_intro` pushes
      // `"Truncated typedObject record"` (Flash.pm:353) on a 0x10
      // typed-object name-payload overrun. Pre-R9 the silent `bool`
      // dropped this warning entirely for nested-in-struct typed-object
      // children too.
      //
      // Codex PR #32 R16/F1 — a STRUCT-VALUED child must NOT propagate
      // its inner abort as a PARENT abort. This site is bundled's
      // Flash.pm:382 recursive `ProcessMeta($et, $dirInfo,
      // $subTablePtr, 1)`. For a struct-typed value the recursive call
      // runs ITS OWN `$isStruct{$type}` branch (lines 337-411): line
      // 340 sets `$val = ''` UNCONDITIONALLY before the introducer
      // check, then the inner `for(;;)` pair loop runs. When that inner
      // loop terminates — via the introducer `last`/`last Record`
      // (lines 342/350/354), an unsupported-AMF child (lines 437-439
      // `undef $type; last`), a child scalar truncation, or a deeper
      // nested abort — control falls to `last if $single` (line 441)
      // and the child returns `($type, '')`: `$type` is the STRUCT type
      // (0x03/0x08/0x10), STILL DEFINED, and `$val=''` DEFINED. Back in
      // THIS parent walker (bundled's outer `for(;;)` pair loop), line
      // 386 `last Record unless defined $t and defined $v` does NOT
      // fire (both defined), and `next if $isStruct{$t}` (line 387)
      // CONTINUES the parent pair loop. The parent sibling that follows
      // the failed struct child IS therefore parsed.
      //
      // This mirrors the array-of-struct path: `collect_array_items`
      // already DISCARDS the `WalkOutcome` from a struct element's
      // recursive `walk_pairs` (Codex R5 FALSE-POSITIVE resolution,
      // same Flash.pm:340 `$val=''` semantics, pinned by
      // `flash_f5_array_struct_abort.flv`). The struct-IN-struct site
      // here has the identical Perl shape.
      //
      // Pre-R16 this branch `return`ed `WalkOutcome::Abort` for BOTH an
      // `IntroOutcome::Truncated` introducer AND a `walk_pairs == Abort`
      // child walk — silently dropping the parent sibling that bundled
      // emits. Pinned by `flash_r16_nested_struct_abort.flv`.
      //
      // The introducer is consumed for its side effects:
      // `consume_struct_intro` may push `"Truncated typedObject record"`
      // (Flash.pm:353, 0x10 name-payload overrun) and leaves `pos`
      // unadvanced on every `IntroOutcome::Truncated` path — matching
      // bundled's `$$dirInfo{Pos}` sitting just past the consumed type
      // byte.
      //
      // Codex PR #32 R17/F1 — branch on the `IntroOutcome`. Bundled's
      // struct branch (Flash.pm:337-401) is `$val=''` (line 340) THEN
      // the introducer check THEN the `for(;;)` pair loop. The
      // introducer checks `last` OUT of the struct branch BEFORE the
      // pair loop is ever entered:
      //   * 0x08 mixed array — line 342 `last if $pos + 4 > $dirLen`
      //     (top-index truncation),
      //   * 0x10 typed object — line 351 `last Record if $pos+2>$dirLen`
      //     / line 353 `Warn("Truncated typedObject record"); last
      //     Record` (name-length / name-payload truncation).
      // On any of these the inner ProcessMeta returns the child's
      // `($type, '')` dummy (line 441 `last if $single`) WITHOUT having
      // run a single pair iteration. The parent's outer Record loop
      // then sees a defined `($t,$v)`, `next if $isStruct{$t}` fires
      // (line 387), and the parent pair loop continues.
      //
      // Pre-R17 this branch ALWAYS called `walk_pairs` (bundled's
      // `for(;;)` pair loop) even for a `Truncated` introducer. For a
      // truncated `0x08` child whose remaining bytes parse as a key
      // length (e.g. `00 05`), `walk_pairs` pushed a spurious
      // `"Truncated mixedArray record"` (Flash.pm:354 — a warning that
      // only fires INSIDE the pair loop) BEFORE the parent could push
      // its own `"Truncated object record"`, changing both the
      // surfaced warning and the warning order. Mirrors the array
      // path's `IntroOutcome` branch (the strict-array struct-element
      // site). Pinned by `flash_r17_struct_child_trunc_intro`.
      match consume_struct_intro(data, pos, vtype, warnings) {
        IntroOutcome::Ok => {
          // Codex PR #32 R8 — recurse with `Some(full_tag)`. Once we're
          // inside a struct branch the carried `$structName` is ALWAYS
          // defined (Flash.pm:381 `$$dirInfo{StructName} = $tag` runs
          // unconditionally). Even at the top level (when our own
          // `struct_name` was `None`), the child walker sees a defined
          // (possibly empty) prefix — `full_tag` may be the raw
          // lowercase key (top-level case) or the prefix-applied
          // uppercase form.
          //
          // Codex PR #32 R16/F1 — DISCARD the recursive `WalkOutcome`.
          // An inner abort is the child's own `last Record`; bundled's
          // outer walker sees the child's `($type, '')` return and
          // continues (see the block comment above). Any warnings the
          // child pushed are preserved (shared `warnings` vec) and the
          // advanced cursor is preserved (shared `pos`).
          // A nested object is one level deeper (Golden-v2 3a).
          let _ = walk_pairs(
            depth + 1,
            data,
            pos,
            vtype,
            sub_table_for_value,
            Some(full_tag.as_str()),
            entries,
            warnings,
          );
        }
        IntroOutcome::Truncated(_) => {
          // Introducer truncated — bundled `last`s out of the struct
          // branch BEFORE the pair loop. `consume_struct_intro` left
          // `pos` unadvanced and (only for the `TypedObjectName`
          // reason) already pushed `"Truncated typedObject record"`.
          // Do NOT descend into `walk_pairs`. The parent pair loop
          // continues; its next key-length read / EOF check drives the
          // parent's own (correct) termination + warning.
        }
      }
      continue;
    }

    if vtype == 0x0a {
      // Array — recurse with per-element struct-name (Flash.pm:410-426).
      let resolved = resolve_emit(table, &full_tag);
      // Codex R4/F1 — propagate `last Record` from a failed child
      // array. Bundled at line 420 `last Record unless defined $v`
      // inside the 0x0a element loop OR line 437-439's unsupported
      // `undef $type; last` both leave the outer Frame's line 386
      // `last Record unless defined $t and defined $v` test failing,
      // aborting THIS struct walk's Record loop. Pre-fix: walk_array
      // returned `()` and we `continue`d, silently emitting subsequent
      // siblings (e.g. flash_f4_array_abort_sibling.flv's `Flash:After`).
      //
      // Codex PR #32 R8 — pass `Some(full_tag)`. The child array's
      // line 416 `my $structName = $$dirInfo{StructName}` then reads a
      // DEFINED prefix, and line 418 `$$dirInfo{StructName} =
      // $structName . $i if defined $structName` fires per element.
      // (Top-level strict-arrays don't reach this path — `process_meta`
      // dispatches them directly with `None` carrier.)
      // A child array is one level deeper (Golden-v2 3a).
      if walk_array(
        depth + 1,
        data,
        pos,
        sub_table_for_value,
        Some(full_tag.as_str()),
        &resolved,
        entries,
        warnings,
      ) == WalkOutcome::Abort
      {
        return WalkOutcome::Abort;
      }
      continue;
    }

    // Scalar: read value and emit. On truncation, `read_value` already
    // pushed the faithful `Truncated AMF record 0x%x` (Flash.pm:456),
    // and the outer frame's `$val=''` (line 340) keeps THIS frame
    // silent: we just abort the struct walk. On an unsupported AMF
    // type (Codex R2/F3), `read_value` pushed the dedicated `AMF <name>
    // record not yet supported` warning (Flash.pm:437); same control
    // flow (abort the walk) but the distinct warning text is preserved.
    // Codex R4/F1: abort PROPAGATES — `Truncated`/`Unsupported` from a
    // child scalar means the inner ProcessMeta returned `($type, undef)`
    // (or `(undef, undef)` for unsupported), and bundled Flash.pm:386's
    // `last Record unless defined $t and defined $v` fires → the outer
    // Record loop terminates. Subsequent siblings MUST be dropped.
    match read_value(data, pos, vtype, warnings) {
      ReadResult::Ok(val) => {
        if is_xmp_subdirectory_dispatch(table, struct_name, &key) {
          // Codex PR #32 R6 — Flash.pm:243-246 dispatches `liveXML` via
          // `SubDirectory => { TagTable => 'Image::ExifTool::XMP::Main' }`.
          // The XMP parser is FORMATS.md row 15 (6693 LOC, Phase-3+
          // accepted-deferral; see [`is_xmp_subdirectory_dispatch`]
          // module doc + [[exifast-phase2-forward-items]]).
          //
          // BEHAVIOR: consume the value (advance `pos` — already done by
          // `read_value`), DROP the would-be auto-add `Flash:LiveXML`
          // scalar (bundled never emits a `Flash:LiveXML` tag — it emits
          // `XMP-*:*` tags via XMP::ProcessXMP), and push a deferral
          // warning so the gap is VISIBLE in `ExifTool:Warning`.
          //
          // The bundled output will additionally contain `XMP-*:*` tags
          // for the parsed XMP packet; we cannot synthesize those without
          // the XMP parser. The divergence is pinned by the
          // `#[ignore]`-d `flash_xmp_livexml_subdirectory_deferred_conformance`
          // test (`tests/conformance.rs`) — when the XMP port lands, the
          // `#[ignore]` lifts and the warning emission is removed.
          //
          // Codex PR #32 R7+R8 — the gate is TOP-LEVEL-undef only:
          // `struct_name.is_none()` matches bundled's `not defined
          // $structName` condition (Flash.pm:380), which is exactly when
          // the un-prefixed Meta `liveXML` SubDirectory dispatches into
          // XMP. A NESTED `foo.liveXML` carries `Some("Foo")` and falls
          // through to the auto-add path below — emitting
          // `Flash:FooLiveXML` as a plain scalar, which is exactly what
          // bundled does (`flash_nested_livexml.flv`, R7).
          //
          // R8: an EMPTY-KEY parent (`{"": {liveXML: "..."}}`) carries
          // `Some("")` (defined, length 0). Bundled's prefix application
          // at line 380 fires (`$tag = "" . "LiveXML" = "LiveXML"`); the
          // line 390 SubDirectory lookup on `"LiveXML"` MISSES the
          // lowercase-keyed Meta entry; auto-add emits `Flash:LiveXML`
          // as a plain scalar. Pre-R8 `is_empty()` collapsed `Some("")`
          // into `None`, mis-routing the value through the XMP deferral
          // and dropping it silently. The `flash_empty_key_livexml.flv`
          // adversarial fixture (R8/F1) pins this recovery.
          let _ = val; // value consumed, but not emitted (XMP deferral)
          warnings.push(SmolStr::new_static(
            "XMP SubDirectory dispatch deferred (Phase-3+)",
          ));
        } else {
          let resolved = resolve_emit(table, &full_tag);
          emit_resolved(entries, &resolved.name, vtype, val, &resolved);
        }
      }
      ReadResult::Truncated(_) | ReadResult::Unsupported(_) => return WalkOutcome::Abort,
    }
  }
}

/// Walk an AMF strict-array (Flash.pm:410-426). Reads u32 count then
/// `count` elements; each element is recursively walked with a per-index
/// struct name (`<struct_name><i>`) for sub-struct emission. Non-struct
/// child values are collected and emitted as a heterogeneous list under
/// the parent name (Flash.pm:422 `push @vals, $v unless $isStruct{$t}`).
///
/// Faithfulness notes:
/// - Doubles are kept numeric, post-ValueConv (`*1000` only for tags with
///   that table mod — none of the realistic double-array tags do).
/// - Strings / long-strings / XML are pre-stringified via `fix_utf8`
///   (faithful `XMP::FixUTF8`: each invalid UTF-8 byte ⇒ `?`).
/// - Booleans are converted to `"Yes"`/`"No"` (Flash.pm:329 in-process,
///   so the same shape lands in both `-j` and `-n` modes).
/// - Dates are pre-formatted as `"YYYY:MM:DD HH:MM:SS.ssssss±HH:MM"`
///   (Flash.pm:316-324).
/// - On an element read failure (truncation or clean EOF without a type
///   byte), Flash.pm:419-426's inner ProcessMeta loop exits via `last
///   Record` BEFORE `$val = \@vals` is assigned. The outer Frame's line
///   455 then sees `$val == undef && $type == 0x0a` and emits
///   `Truncated AMF record 0xa` (Flash.pm:456). We mirror that exactly:
///   the warning is pushed under the OUTER 0x0a tag byte, NOT the leaf
///   element type, AND the half-collected list is DROPPED (faithful: Perl
///   never reaches the `\@vals` assignment).
fn walk_array(
  depth: u32,
  data: &[u8],
  pos: &mut usize,
  table: SubTable,
  struct_name: Option<&str>,
  parent_resolved: &EmitResolution,
  entries: &mut std::vec::Vec<Entry>,
  warnings: &mut std::vec::Vec<SmolStr>,
) -> WalkOutcome {
  // Golden-v2 3a — recursion-depth guard (same cluster as `walk_pairs`).
  if depth >= MAX_AMF_DEPTH {
    return WalkOutcome::Abort;
  }
  // Delegate to `collect_array_items` so nested strict-arrays can reuse
  // the same body (Codex R2/F2 — the prior shape called `read_value` on
  // a nested 0x0a element, which returned `AmfValue::StrictArray`
  // WITHOUT consuming the nested count+payload).
  // Codex PR #32 R15/F1 — carry the owning tag's TOP-LEVEL ValueConv policy
  // (both `$val * 1000` and `$val=~s/\s+$//`, ExifTool.pm:3567-3681) so each
  // top-level element of THIS strict array gets the bundled element-wise
  // conversion. R14/F1 (mul_1000) and R15/F1 (trim_trailing_ws) share this
  // carry; the nested-array recursion inside the helper resets to NEUTRAL.
  //
  // `walk_array` is a thin delegator over the SAME array frame, so it passes
  // its own `depth` (not `depth + 1`) to `collect_array_items`.
  match collect_array_items(
    depth,
    data,
    pos,
    table,
    struct_name,
    ArrayValueConv {
      mul_1000: parent_resolved.mul_1000,
      trim_trailing_ws: parent_resolved.trim_trailing_ws,
    },
    entries,
    warnings,
  ) {
    ArrayOutcome::Ok(collected) => {
      // Emit the (possibly empty? Flash.pm:388 `next if ref($v) eq
      // 'ARRAY' and not @$v` — the OUTER struct walker drops empty
      // arrays before the HandleTag call) collected list.
      if !collected.is_empty() {
        // Emit under the resolved (post-table-mapping) name, NOT the
        // struct carry. For `keyframesTimes` the resolved name is
        // `KeyFramesTimes`; for the auto-add case it's
        // `ucfirst(struct_name)`.
        let _ = struct_name;
        entries.push(Entry {
          name: SmolStr::from(parent_resolved.name.clone()),
          value: FlashValue::List(collected),
          pc: parent_resolved.pc,
        });
      }
      WalkOutcome::Continue
    }
    ArrayOutcome::TruncatedCount => {
      // Codex R9/F1 — bundled keyed-value 0x0a: line 382's recursive
      // `ProcessMeta($et, $dirInfo, $subTablePtr, 1)` has a FRESH local
      // $val=undef. Line 411's `last if $pos + 4 > $dirLen` then fires
      // without assigning $val; line 455 (`not defined $val and defined
      // $type`) emits `"Truncated AMF record 0xa"` because $type=0xa
      // was set at line 303. ALWAYS emit here (the recursive call's
      // $val=undef is the invariant — no `top_val_seen` gate).
      //
      // The helper returned `TruncatedCount` WITHOUT pushing — push
      // now to make the bundled diagnostic visible via
      // `ExifTool:Warning`. Pinned by
      // `flash_keyed_array_truncated_count_conformance`.
      warnings.push(SmolStr::new_static("Truncated AMF record 0xa"));
      WalkOutcome::Abort
    }
    ArrayOutcome::Abort => {
      // Codex R4/F1 — truncation / abort cue from `collect_array_items`.
      // Bundled inner ProcessMeta's `0x0a` branch (Flash.pm:410-426)
      // never reaches `$val = \@vals` on an element failure: the inner
      // `last Record` at line 420 OR an unsupported-type `undef $type;
      // last` (line 438-439) leaves `$val=undef` post-loop, returning
      // `(0x0a, undef)` (or `(undef, undef)` for the unsupported case)
      // to the outer struct walker. The outer at line 386 then hits
      // `last Record unless defined $t and defined $v` → ABORT.
      // `collect_array_items` already pushed the leaf diagnostic AND
      // the per-frame `Truncated AMF record 0xa` (or the bundled
      // unsupported warning). Signal abort so `walk_pairs` propagates
      // the `last Record` cue.
      WalkOutcome::Abort
    }
  }
}

/// Top-level ValueConv policy carried into [`collect_array_items`] for the
/// elements of a strict-array (0x0a) emitted under an owning tag.
///
/// Bundled `GetValue` (ExifTool.pm:3567-3681) applies the owning tag's
/// `ValueConv` to EACH TOP-LEVEL array element (the loop iterates
/// `$val = $$vals[$i]` and runs `eval $conv` per element), but NEVER
/// recurses into a nested arrayref element — a nested `$val` is itself an
/// array ref, and the regex/`*1000` ValueConv coerces the ref to a string
/// (its memory address) / number, not the inner scalars. So this policy is
/// applied at THIS array frame's scalar elements and a NEUTRAL policy
/// ([`ArrayValueConv::NEUTRAL`]) is passed into the nested-array recursion.
///
/// The two carried conversions are the only `%Flash::Meta` ValueConv shapes
/// (Flash.pm:157-247):
/// - `mul_1000` — `ValueConv => '$val * 1000'` (audio/video datarate,
///   Flash.pm:168/230/237); applied to a top-level DOUBLE element.
/// - `trim_trailing_ws` — `ValueConv => '$val=~s/\s+$//; $val'`
///   (`creationdate`, Flash.pm:182); applied to a top-level STRING element.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(feature = "json"), allow(dead_code))]
struct ArrayValueConv {
  /// `$val * 1000` applied to a top-level double element (Flash.pm:168/230/237).
  mul_1000: bool,
  /// `$val=~s/\s+$//` applied to a top-level string element (Flash.pm:182).
  trim_trailing_ws: bool,
}

impl ArrayValueConv {
  /// No ValueConv — used for the nested-array recursion (bundled never
  /// recurses the owning tag's ValueConv into a nested arrayref element) and
  /// for top-level lone arrays (verbose-only-ignored, no owning tag —
  /// Flash.pm:449-452).
  const NEUTRAL: Self = Self {
    mul_1000: false,
    trim_trailing_ws: false,
  };
}

/// Consume an AMF strict-array body (count:u32-BE + `count` elements)
/// and return the collected non-struct items. Returns `None` on
/// truncation / abort (the bundled `Truncated AMF record 0xa` is
/// already pushed onto `warnings`). Faithful to `ProcessMeta` Frame 2
/// (Flash.pm:410-426).
///
/// Sub-struct elements (`isStruct{$t}` — 0x03 / 0x08 / 0x10) recurse
/// into `walk_pairs` with a per-index struct-name carry (Flash.pm:418)
/// and emit their own tag entries; their value is NOT pushed into the
/// returned list (Flash.pm:422 `push @vals, $v unless $isStruct{$t}`).
///
/// Nested strict-array elements (`$t == 0x0a`) recurse into THIS fn —
/// the inner list is pushed as `FlashListItem::List(...)` into the
/// outer list (Flash.pm:422's `unless $isStruct{$t}` test — 0x0a is
/// NOT in `%isStruct`, so the inner `\@vals` reference IS pushed,
/// producing bundled's `[[a,b,...],...]` JSON shape).
#[allow(clippy::too_many_arguments)]
fn collect_array_items(
  depth: u32,
  data: &[u8],
  pos: &mut usize,
  table: SubTable,
  struct_name: Option<&str>,
  value_conv: ArrayValueConv,
  entries: &mut std::vec::Vec<Entry>,
  warnings: &mut std::vec::Vec<SmolStr>,
) -> ArrayOutcome {
  // Golden-v2 3a — recursion-depth guard (same cluster as `walk_pairs`).
  // Return an empty list (the "no further items" outcome) so the walk stops
  // without pushing a spurious truncation warning; a real file never reaches
  // this depth, so the output is unchanged.
  if depth >= MAX_AMF_DEPTH {
    return ArrayOutcome::Ok(std::vec::Vec::new());
  }
  if *pos + 4 > data.len() {
    // Bundled Flash.pm:411 `last if $pos + 4 > $dirLen` — no warning at
    // this point. The post-loop line 455 (`not defined $val and defined
    // $type`) check decides emission based on this frame's $val-on-entry
    // state, which depends on the CALLER's context:
    //
    //   * Top-level (`process_meta` direct dispatch): bundled's $val
    //     may be set from prior records — caller gates on `top_val_seen`.
    //   * Keyed-value (`walk_array` via `walk_pairs`): recursive
    //     ProcessMeta has a FRESH local $val=undef → caller ALWAYS
    //     emits at THIS frame.
    //   * Nested (recursion site inside this helper): the recursive
    //     ProcessMeta has $val=undef → caller emits for THIS frame.
    //
    // The discriminated [`ArrayOutcome::TruncatedCount`] return lets
    // callers apply the correct rule. Pre-R9 returned a SILENT `None`
    // conflated with element-failure — the keyed-value caller dropped
    // bundled's `"Truncated AMF record 0xa"` (Flash.pm:455). Pinned by
    // `flash_keyed_array_truncated_count_conformance` (R9/F1).
    return ArrayOutcome::TruncatedCount;
  }
  // Checked-indexing (Phase C w2b): the `*pos + 4 > data.len()` guard makes
  // `data.get(*pos..*pos + 4)` `Some` ⇒ byte-identical.
  let count = match data.get(*pos..*pos + 4) {
    Some(&[b0, b1, b2, b3]) => u32::from_be_bytes([b0, b1, b2, b3]) as usize,
    _ => 0,
  };
  *pos += 4;
  let mut collected: std::vec::Vec<FlashListItem> = std::vec::Vec::with_capacity(count.min(1024));
  for i in 0..count {
    if *pos >= data.len() {
      // Inner ProcessMeta call hit `last if $pos >= $dirLen` (Flash.pm:302)
      // before setting `$type`. The outer Frame's line 455 then sees
      // `$val == undef && $type == 0x0a` (the array type from this frame)
      // and emits `Truncated AMF record 0xa`. Drop the collected vals.
      warnings.push(SmolStr::new_static("Truncated AMF record 0xa"));
      return ArrayOutcome::Abort;
    }
    // Checked-indexing (Phase C w2b): the `*pos >= data.len()` guard makes
    // `data.get(*pos)` `Some` ⇒ byte-identical.
    let vtype = data.get(*pos).copied().unwrap_or(0);
    *pos += 1;
    if is_struct(vtype) {
      // Sub-struct: recurse with per-element struct name (Flash.pm:418).
      // Codex R9/F2 — `consume_struct_intro` now emits the bundled-
      // faithful `"Truncated typedObject record"` warning on a 0x10
      // typed-object name-payload overrun (Flash.pm:353 exact text).
      // Pre-R9 lumped this into a silent `false` return, and this
      // frame's fallback `"Truncated AMF record 0xa"` masked the
      // bundled-correct typedObject warning. Pinned by
      // `flash_array_typed_object_truncated_name_conformance`.
      //
      // Codex PR #32 R10 — pre-R10 R9 wrapped EVERY
      // `IntroOutcome::Truncated` in an extra
      // `"Truncated AMF record 0xa"` push. That was correct for the
      // typedObject-name-overrun case (the outer 0xa frame's $val=undef
      // bundled diagnostic chain) BUT WRONG for the silent reasons
      // (0x10 name-LENGTH truncation, 0x08 top-index truncation): the
      // inner returns `(type, '')` with $val defined, the array's
      // for-loop continues, $val=\@vals is assigned at line 426 → THIS
      // frame's $val IS defined → bundled line 455 emits NOTHING. The
      // R9 fallback push turned bundled-silent paths into user-visible
      // warnings. R10 fix: discriminate by reason.
      //
      // Even for `TypedObjectName`, bundled `-j` JSON surfaces ONLY
      // the helper's "Truncated typedObject record" — the outer 0xa
      // frame's `$val=undef + $type=0xa` line 455 emission DOES fire
      // in bundled (-v3 shows it as `Truncated AMF record 0xa`), but
      // the empirical `-j` JSON capture for
      // `flash_array_typed_object_truncated_name.flv` shows ONLY the
      // typedObject warning — because the `Warning` JSON key is
      // single-valued and the typedObject push happened FIRST. Our
      // emit pipeline keeps every warning in the `warnings` vec but
      // the JSON writer collapses to first-wins on Warning keys, so
      // pushing the array-frame warning second would still produce
      // the same JSON shape — BUT in the silent reasons we'd
      // introduce a spurious warning that the JSON would surface (no
      // earlier push). So the safe + bundled-faithful R10 behaviour
      // is: don't push the array-frame warning at all for any of the
      // three reasons. The bundled `-v3`-only second warning lives
      // outside the JSON surface.
      //
      // Pinned by `flash_array_typed_object_truncated_length_conformance`
      // and `flash_array_mixed_array_truncated_top_index_conformance`
      // (R10 silent paths) and
      // `flash_array_typed_object_truncated_name_conformance` (R9
      // typedObject-overrun, must still pass).
      //
      // Codex PR #32 R11/F1 — pre-R11 this arm `return`ed
      // `ArrayOutcome::Abort`, terminating the element loop here. That
      // diverges from Flash.pm: a struct-introducer truncation
      // (Flash.pm:340 `$val = ''` dummy, then a `last`/`last Record`
      // out of the introducer at lines 342/350/352-354) leaves the
      // inner ProcessMeta's `$val` DEFINED (`''`). The inner `$single`
      // call returns `($type, '')` — NOT `(undef, undef)` — so the
      // strict-array loop's `last Record unless defined $v`
      // (Flash.pm:420) is SATISFIED and the element loop CONTINUES to
      // `$i+1`. `0x03`/`0x08`/`0x10` are all in `%isStruct`, so
      // `push @vals, $v unless $isStruct{$t}` adds nothing — we
      // likewise collect no list item. `consume_struct_intro` already
      // left `pos` unadvanced (it returns before the `*pos +=` on
      // every `Truncated` path), mirroring bundled's `$$dirInfo{Pos}`
      // sitting right after the consumed type byte. The next element
      // (or count exhaustion / EOF) then drives the correct outcome:
      //   * `*pos >= data.len()` on the next iteration → the existing
      //     check pushes `"Truncated AMF record 0xa"` (Flash.pm:455:
      //     inner ProcessMeta hits `last if $pos >= $dirLen` →
      //     `(undef, undef)` → array loop `last Record` → THIS array
      //     frame's `$val=\@vals` at line 426 never assigned →
      //     `$val=undef + $type=0xa`).
      //   * count exhausted with no further element → loop ends →
      //     `ArrayOutcome::Ok` (Flash.pm: `$val = \@vals` runs, no
      //     warning).
      // For `TypedObjectName`, `consume_struct_intro` ALSO already
      // pushed `"Truncated typedObject record"`; `-j` JSON is
      // first-wins on the `Warning` key, so a later array-frame push
      // does not change the surfaced warning. Pinned by
      // `flash_array_struct_intro_trunc_continues_conformance` (R11/F1).
      match consume_struct_intro(data, pos, vtype, warnings) {
        IntroOutcome::Ok => { /* fall through to walk_pairs */ }
        IntroOutcome::Truncated(_) => {
          // Bundled returns `($type, '')` (defined) — the element loop
          // continues; collect no list item (struct types are never
          // pushed). Let the next iteration / count exhaustion decide
          // the array-frame warning + outcome.
          continue;
        }
      }
      // Codex PR #32 R8 — Flash.pm:418 array-index append is GATED on
      // `defined $structName`: `$$dirInfo{StructName} = $structName . $i
      // if defined $structName`. When `struct_name` is `None` (top-level
      // strict-array — bundled NEVER reaches this site at top-level
      // because `process_meta` dispatches 0x0a directly to
      // `collect_array_items` with `None`, but if it DID, bundled would
      // leave `$structName` undef so child elements would inherit the
      // un-prefixed walker), we propagate `None`. When defined (the
      // common nested case), we append the index per element.
      //
      // For the new `flash_toplevel_array_objects.flv` adversarial
      // fixture (R8/F2): a top-level strict-array with object elements,
      // `struct_name` is `None`, so we DO NOT append `0`/`1`. The child
      // `walk_pairs` then sees `Some("")` indirectly via `process_meta`
      // bypassing this site — instead, the carry from
      // `collect_array_items`-called-at-top-level passes `None` to the
      // inner `walk_pairs`, matching bundled's `defined $structName`
      // FALSE → line 380 doesn't fire → tag stays raw lowercase
      // (`name`) → `resolve_emit` auto-add ucfirsts → `Flash:Name`
      // last-wins. EMPIRICAL: bundled emits `Flash:Name: "B"` for the
      // 2-element fixture.
      let child_struct_name: Option<std::string::String> =
        struct_name.map(|s| std::format!("{s}{i}"));
      // Codex R5 (FALSE POSITIVE — see
      // `flash_amf_array_struct_element_failure_does_not_abort_conformance`
      // in tests/conformance.rs): the R5 finding asserted this site
      // should propagate `WalkOutcome::Abort` from `walk_pairs` by
      // returning `None`, mirroring bundled's array-loop abort. EMPIRICAL
      // VERIFICATION on `flash_f5_array_struct_abort.flv` shows bundled
      // does NOT abort: Flash.pm:340's `$val = ''` (struct branch dummy)
      // keeps `$val` defined across the inner pair-loop's `last Record`,
      // so the inner ProcessMeta returns `(0x03, '')` — not
      // `(undef, undef)` — and Flash.pm:420's `last Record unless
      // defined $v` is satisfied. The array element loop continues at
      // i+1 with the cursor wherever the failed inner pair-loop left
      // it; subsequent misparses are intentional bundled behaviour, not
      // a port bug. Discarding the `WalkOutcome` here is therefore
      // correct (matches bundled value-for-value). Propagating Abort
      // would diverge — e.g., bundled emits `Flash:Arr: [1.25e-308]`
      // for this fixture's cursor-desync misparse; an "abort"
      // propagation would drop it entirely.
      //
      // Contrast with the DIRECT-unsupported-scalar case (Codex R4/F1,
      // `flash_f4_array_abort_sibling.flv`) where bundled's inner
      // ProcessMeta hits Flash.pm:435-439's `undef $type; last` BEFORE
      // any `$val = ''` assignment, returning `(undef, undef)`, and the
      // array loop's line 420 DOES fire — that abort IS propagated by
      // `collect_array_items` returning `None` on `Unsupported` /
      // `Truncated` leaf reads (the `ReadResult::Truncated` /
      // `Unsupported` arms below in this fn's scalar branch).
      // A struct element nests one level deeper (Golden-v2 3a).
      let _ = walk_pairs(
        depth + 1,
        data,
        pos,
        vtype,
        table,
        child_struct_name.as_deref(),
        entries,
        warnings,
      );
      continue;
    }
    if vtype == 0x0a {
      // Codex R2/F2 — nested strict-array inside a strict-array. Bundled
      // Flash.pm:410-426 recurses: the inner ProcessMeta call (with
      // `$single=1`) runs the array branch at lines 410-426 to build
      // `$val = \@vals` and returns `(0x0a, $val)`. Frame 2 (this
      // walker) then `push @vals, $v unless $isStruct{$t}` — `0x0a` is
      // NOT in `%isStruct` so the nested list IS appended. Net JSON
      // shape: `[[a,b,...],...]` (verified via bundled on
      // `flash_f2_nested_array.flv`).
      //
      // Codex R4/F2 — the recursive call MUST carry the per-index
      // prefix. Bundled Flash.pm:417-418 sets
      // `$$dirInfo{StructName} = $structName . $i` BEFORE the
      // recursive ProcessMeta call, so the inner array's own line 416
      // capture (`$structName = $$dirInfo{StructName}`) reads the
      // per-index-prefixed name. Nested-array element names then build
      // correctly: `outerArr<i><j>.name` becomes `OuterArr<i><j>Name`,
      // not `OuterArr<j>Name` (silent first-wins collision). Verified
      // empirically on `flash_f4_nested_array_prefix.flv` — bundled
      // emits `OuterArr00Name/01Name/10Name/11Name`, four distinct
      // tags. Prior shape passed `struct_name` (the outer prefix,
      // unchanged) → both `outerArr[0]` and `outerArr[1]` recurse with
      // the same prefix → inner objects collide.
      //
      // Codex PR #32 R8 — Flash.pm:418's `if defined $structName`
      // gates the append. `None` (top-level strict-array nested case
      // — only reachable if the caller is itself a top-level array
      // calling THIS fn with `None`) propagates `None` to the inner
      // recursion. Empirically validated on
      // `flash_toplevel_array_objects.flv`: bundled does NOT prefix
      // children with index when the outer carry is undef.
      //
      // Prior shape: the leaf `read_value` branch at 0x0a returned
      // `AmfValue::StrictArray` WITHOUT consuming the nested
      // count+payload, leaving the cursor mid-nested-array → silent
      // data loss / spurious diagnostics on subsequent elements.
      let nested_struct_name: Option<std::string::String> =
        struct_name.map(|s| std::format!("{s}{i}"));
      // Codex PR #32 R14/F1 + R15/F1 — pass `ArrayValueConv::NEUTRAL` into
      // the nested recursion. The owning tag's ValueConv (`$val * 1000` OR
      // `$val=~s/\s+$//`) is a TOP-LEVEL conversion in bundled `GetValue`
      // (ExifTool.pm:3567-3681, iterating `$$vals[$i]`); a nested arrayref
      // element receives the conversion applied to the REF (Perl coercion →
      // a non-deterministic memory address / number — see the
      // `ArrayValueConv` header), NEVER element-wise into the inner scalars.
      // Recursing `mul_1000` here produced the bogus `[[1500,61000]]` for a
      // `totaldatarate` nested array; recursing `trim_trailing_ws` would
      // wrongly trim inner-array strings. Bundled does neither.
      // A nested strict-array is one level deeper (Golden-v2 3a).
      match collect_array_items(
        depth + 1,
        data,
        pos,
        table,
        nested_struct_name.as_deref(),
        ArrayValueConv::NEUTRAL,
        entries,
        warnings,
      ) {
        ArrayOutcome::Ok(nested) => collected.push(FlashListItem::List(nested)),
        ArrayOutcome::TruncatedCount => {
          // Codex R9/F1 — the inner frame had $val=undef + $type=0xa
          // at its line 455 check → bundled emits at the inner frame.
          // The inner helper returned `TruncatedCount` WITHOUT pushing,
          // so push the inner's warning now.
          warnings.push(SmolStr::new_static("Truncated AMF record 0xa"));
          // THIS frame ALSO has $val=undef (the `\@vals` assignment at
          // line 426 is never reached when the inner element failed),
          // and $type=0xa from this frame → bundled emits at this
          // frame too. Push for THIS frame.
          warnings.push(SmolStr::new_static("Truncated AMF record 0xa"));
          return ArrayOutcome::Abort;
        }
        ArrayOutcome::Abort => {
          // Inner already pushed its own frame warning(s). THIS frame's
          // `\@vals` is never assigned → $val=undef + $type=0xa →
          // bundled emits at THIS frame. Push and abort.
          warnings.push(SmolStr::new_static("Truncated AMF record 0xa"));
          return ArrayOutcome::Abort;
        }
      }
      continue;
    }
    match read_value(data, pos, vtype, warnings) {
      ReadResult::Ok(val) => {
        // Convert each non-struct AMF value to its emitted list-element
        // shape. Faithful to bundled Flash.pm:305-432 + HandleTag's
        // per-element rendering (numeric vs string).
        match val {
          AmfValue::Double(d) => {
            // Codex PR #32 R14/F1 — the owning tag's ValueConv (`$val * 1000`
            // for *bitrate/*datarate, Flash.pm:168/230/237) is applied by
            // bundled `GetValue` (ExifTool.pm:3567-3681) ONLY to TOP-LEVEL
            // arrayref elements; the loop iterates `$val = $$vals[$i]` and
            // never recurses into a nested arrayref element. So `mul_1000`
            // is honoured for a scalar element of THIS array (a top-level
            // element), but the nested-array recursion above passes
            // `ArrayValueConv::NEUTRAL` so inner doubles are NOT multiplied.
            let v = if value_conv.mul_1000 { d * 1000.0 } else { d };
            collected.push(FlashListItem::Double(v));
          }
          AmfValue::Boolean(b) => {
            // Flash.pm:329 `{0 => 'No', 1 => 'Yes'}->{$val} if $val < 2`
            // runs INSIDE ProcessMeta (pre-HandleTag, pre-PrintConv) so
            // both `-j` and `-n` see the string.
            collected.push(FlashListItem::Str(SmolStr::new_static(match b {
              0 => "No",
              1 => "Yes",
              // Out-of-range values are kept raw (Flash.pm: `< 2` guard
              // leaves them as numbers in Perl). Emit the raw u8 as a
              // number; treat as double-item in the list.
              _ => {
                collected.push(FlashListItem::Double(f64::from(b)));
                continue;
              }
            })));
          }
          AmfValue::String(mut s) => {
            // Codex PR #32 R19/F1 — bundled `GetValue` (ExifTool.pm:3519-3656)
            // runs the owning tag's ValueConv on EACH TOP-LEVEL array element
            // regardless of whether AMF carried it as a number or a numeric
            // string. So a strict array of strings under a `*datarate` tag is
            // numified per element exactly like the scalar case
            // (`audiodatarate ["65.8","abc"]` → `-j ["65.8 kbps","0 bps"]`,
            // `-n [65800,0]`; verified vs bundled on
            // `flash_amf_string_conv.flv`). The arithmetic ValueConv coerces
            // the string FIRST, so the element becomes a `FlashListItem::Double`
            // and the `pc`-aware list emit then applies ConvertBitrate /
            // RoundInt per element in `-j`.
            if value_conv.mul_1000 {
              collected.push(FlashListItem::Double(perl_str_to_f64(&s) * 1000.0));
            } else {
              // Codex PR #32 R15/F1 — the owning tag's string ValueConv
              // (`$val=~s/\s+$//; $val` for `creationdate`, Flash.pm:182) IS
              // applied per TOP-LEVEL element (a strict array `["A   ","B\t "]`
              // under `creationdate` → `["A","B"]` in BOTH `-j` and `-n`;
              // pinned by `flash_creationdate_strict_array.flv`). For a
              // no-ValueConv-with-PrintConv tag (duration/starttime/framerate)
              // the raw string is stored and the `pc`-aware list emit applies
              // ConvertDuration / RoundMilli per element in `-j`. Only honoured
              // for a scalar element of THIS array; the nested-array recursion
              // passes `ArrayValueConv::NEUTRAL` so inner-array strings are
              // neither trimmed nor numified.
              if value_conv.trim_trailing_ws {
                while s.as_bytes().last().is_some_and(u8::is_ascii_whitespace) {
                  s.pop();
                }
              }
              collected.push(FlashListItem::Str(SmolStr::from(s)));
            }
          }
          AmfValue::Date(s) => collected.push(FlashListItem::Str(SmolStr::from(s))),
          // Codex R3/F2 — bundled Flash.pm:417-422 pushes EVERY non-struct
          // `$v` into `@vals`. Lines 403-405 assign `$val = ''` for null
          // (0x05) / undefined (0x06) / object-end (0x09) / unsupported
          // (0x0d), and Frame 2's `unless $isStruct{$t}` test admits each
          // of them (`%isStruct` is `{0x03, 0x08, 0x10}`). Prior silent
          // drop turned bundled `["", "", 3, 4]` into `[4]` — silent
          // data loss matching neither `-j` nor `-n` bundled output.
          AmfValue::Empty | AmfValue::ObjectEnd => {
            collected.push(FlashListItem::Str(SmolStr::new_static("")));
          }
          // Codex R3/F2 — bundled Flash.pm:406-409 reads u16, line 422
          // pushes the numeric value. Element shape is a JSON number.
          AmfValue::Reference(v) => {
            collected.push(FlashListItem::Double(f64::from(v)));
          }
          // Struct shouldn't reach this branch (the `is_struct` gate
          // above handles them); guard defensively.
          // StrictArray is similarly handled by the `vtype == 0x0a`
          // branch above (Codex R2/F2 fix).
          AmfValue::Struct | AmfValue::StrictArray => {}
        }
      }
      ReadResult::Truncated(_) => {
        // Inner ProcessMeta call emitted its own `Truncated AMF record
        // 0x%x` for the LEAF type; the outer Frame 2 then ALSO emits
        // `Truncated AMF record 0xa` because its `$val = \@vals`
        // assignment is never reached. Mirror both: the leaf warning
        // was already pushed by `read_value`; push the array warning
        // here. (Verified on synthetic FLVs through bundled exiftool.)
        warnings.push(SmolStr::new_static("Truncated AMF record 0xa"));
        return ArrayOutcome::Abort;
      }
      ReadResult::Unsupported(_) => {
        // Codex R2/F3 — Flash.pm:437 unsupported Warn already pushed
        // by `read_value`. The inner recursive ProcessMeta returns
        // `(undef, undef)` (line 438 `undef $type`, no `$val`
        // assignment); the outer Frame 2's line 420 `last Record
        // unless defined $v` fires → array `$val=\@vals` never
        // assigned → post-loop line 455 sees `$type=0x0a` + `$val=undef`
        // → emits `Truncated AMF record 0xa`. Mirror BOTH warnings:
        // the unsupported diagnostic stays (preserved by read_value's
        // push), and we also push the array truncation marker.
        warnings.push(SmolStr::new_static("Truncated AMF record 0xa"));
        return ArrayOutcome::Abort;
      }
    }
  }
  ArrayOutcome::Ok(collected)
}

/// Consume the struct introducer that follows an `0x03`/`0x08`/`0x10` type
/// byte. Returns an [`IntroOutcome`] distinguishing successful consumption
/// from bundled `last` / `last Record` cues — the typed-object name
/// payload-overrun case pushes the bundled-faithful `"Truncated
/// typedObject record"` warning (Flash.pm:353).
///
/// Faithful Flash.pm:340-356 — the typed-object name reading is INSIDE
/// the inner pair loop (lines 348-363), so the same truncation logic
/// applies to both the typed-object name AND subsequent keys. We model
/// the name pass separately here (vs the key pass inside [`walk_pairs`])
/// to keep the structural intent obvious: bundled's `$getName=1` /
/// `next; # (ignore name for now)` flow is equivalent to "consume the
/// introducer string then enter the pair loop." Both passes share the
/// same `$amfType[$type]` warning text — for the introducer pass, $type
/// is the struct type byte (here 0x10 for typed-object).
///
/// Codex PR #32 R9/F2 — pre-R9 `skip_struct_intro` returned a silent
/// `bool` (false on any truncation) and the 0x10 name-payload-overrun
/// path was lumped with the 0x10 length-truncation path. Bundled
/// actually distinguishes:
///   * Length truncation (line 350 `last Record if $pos + 2 > $dirLen`)
///     → NO warning, just abort.
///   * Payload overrun (lines 352-354 `if ($pos + 2 + $len > $dirLen) {
///     $et->Warn("Truncated $amfType[$type] record"); last Record; }`)
///     → PUSH `"Truncated typedObject record"`, then abort.
///
/// We mirror that distinction; callers see [`IntroOutcome::Truncated`]
/// and propagate abort (the warning, if any, has been pushed already).
fn consume_struct_intro(
  data: &[u8],
  pos: &mut usize,
  vtype: u8,
  warnings: &mut std::vec::Vec<SmolStr>,
) -> IntroOutcome {
  match vtype {
    // Object (0x03) — no introducer to consume.
    0x03 => IntroOutcome::Ok,
    0x08 => {
      // Mixed-array — 4-byte top-index (Flash.pm:341-344). Bundled
      // `last if $pos + 4 > $dirLen` — `last` (unlabeled) targets the
      // OUTER Record loop because no inner for(;;) is open yet. NO
      // warning at this point ($val='' from line 340 keeps line 455
      // silent).
      if *pos + 4 > data.len() {
        return IntroOutcome::Truncated(IntroTruncReason::TopIndex);
      }
      *pos += 4;
      IntroOutcome::Ok
    }
    0x10 => {
      // Typed-object — u16-prefixed object name read INSIDE the inner
      // pair loop (Flash.pm:345-347 sets `$getName=1`, then the for(;;)
      // at line 348 reads the name via lines 350-356 — the same code
      // path that reads keys, with the `$getName` flag controlling
      // whether the value is consumed as a tag or discarded as the
      // object's name).
      //
      // Line 350 `last Record if $pos + 2 > $dirLen` — bundled `last
      // Record` (LABELED) exits the Record loop. NO warning ($val=''
      // from line 340 keeps line 455 silent). Codex PR #32 R10 — the
      // [`IntroTruncReason::NameLength`] payload tells callers this is
      // the SILENT path (do not add a caller-level frame warning).
      if *pos + 2 > data.len() {
        return IntroOutcome::Truncated(IntroTruncReason::NameLength);
      }
      // Checked-indexing (Phase C w2b): the `*pos + 2 > data.len()` guard makes
      // `data.get(*pos..*pos + 2)` `Some` ⇒ byte-identical.
      let name_len = match data.get(*pos..*pos + 2) {
        Some(&[b0, b1]) => u16::from_be_bytes([b0, b1]) as usize,
        _ => 0,
      };
      // Lines 352-354 `if ($pos + 2 + $len > $dirLen) {
      //   $et->Warn("Truncated $amfType[$type] record"); last Record; }`
      // — `$type` here is the OUTER struct type (0x10 = typed-object,
      // so `$amfType[$type] = "typedObject"`). This warning IS pushed.
      // Codex PR #32 R10 — [`IntroTruncReason::TypedObjectName`] tells
      // callers the helper ALREADY pushed the canonical warning; the
      // caller must abort but NOT add an extra frame warning.
      if *pos + 2 + name_len > data.len() {
        warnings.push(SmolStr::new_static("Truncated typedObject record"));
        return IntroOutcome::Truncated(IntroTruncReason::TypedObjectName);
      }
      *pos += 2 + name_len;
      IntroOutcome::Ok
    }
    _ => IntroOutcome::Ok,
  }
}

/// Emit one scalar entry under the resolved final name.
fn emit_resolved(
  entries: &mut std::vec::Vec<Entry>,
  name: &str,
  amf_type: u8,
  val: AmfValue,
  resolved: &EmitResolution,
) {
  // Flash.pm:390 — the auto-add gate is `/^\w+$/`. We've already
  // resolved/ucfirst'd the name above, so this is the sanity gate against
  // bogus keys.
  if !is_word_key(name) {
    return;
  }
  let value = match val {
    AmfValue::Double(d) => {
      let d = if resolved.mul_1000 { d * 1000.0 } else { d };
      FlashValue::Double(d)
    }
    AmfValue::Boolean(b) => FlashValue::Bool(b),
    AmfValue::String(mut s) => {
      // Codex PR #32 R19/F1 — bundled `GetValue` (ExifTool.pm:3519-3656)
      // applies the resolved tag's ValueConv/PrintConv to `$val` REGARDLESS
      // of whether AMF carried it as a number (0x00) or a numeric string
      // (0x02/0x0c/0x0f); Perl numeric coercion turns `"65.8"` into 65.8
      // inside an arithmetic ValueConv. Pre-R19 this arm only trimmed
      // `creationdate` whitespace and stored the raw string, so an
      // AMF-string-typed numeric field skipped its conversion. We replicate
      // the two `%Flash::Meta` ValueConv shapes here (Flash.pm:157-247):
      if resolved.mul_1000 {
        // `ValueConv => '$val * 1000'` (audio/video/total datarate,
        // Flash.pm:168/230/237). Perl arithmetic coerces the string to a
        // number FIRST (`"65.8" * 1000 == 65800`, `"abc" * 1000 == 0`,
        // `"12,5" * 1000 == 1000` — comma terminates the prefix), so the
        // value becomes numeric from this point on and follows the exact
        // same emit path as an AMF double (the `pc` ConvertBitrate / RoundInt
        // then applies in `-j`; the raw number in `-n`). Verified vs bundled
        // `-j`/`-n` on `flash_amf_string_conv.flv`.
        FlashValue::Double(perl_str_to_f64(&s) * 1000.0)
      } else if resolved.trim_trailing_ws {
        // `ValueConv => '$val=~s/\s+$//; $val'` (`creationdate`,
        // Flash.pm:182). A STRING ValueConv — the result stays a string
        // (the serializer's number-gate coerces a numeric-looking result
        // like a trimmed `"2020"` to a JSON number to match the oracle).
        while s.as_bytes().last().is_some_and(u8::is_ascii_whitespace) {
          s.pop();
        }
        FlashValue::Str(SmolStr::from(s))
      } else {
        // No ValueConv. Any PrintConv (Duration/StartTime ConvertDuration,
        // FrameRate RoundMilli, MetadataDate ConvertDateTime) is applied to
        // the STRING at `-j` emit time via the `pc`-aware `FlashValue::Str`
        // arm in `emit_entry`; under `-n` (or a `None`/pass-through pc) the
        // raw string is emitted and the serializer's number-gate coerces it
        // if numeric. Store the raw string + the resolved `pc` (carried in
        // the `Entry`).
        FlashValue::Str(SmolStr::from(s))
      }
    }
    AmfValue::Date(s) => FlashValue::Date(SmolStr::from(s)),
    // Codex R3/F1 — bundled Flash.pm:403-405 assigns `$val = ''` for null
    // (0x05), undefined (0x06), object-end (0x09) and unsupported-but-
    // present (0x0d). Frame 2's HandleTag is then called with `$v = ''`
    // (Flash.pm:394) so bundled emits an EMPTY STRING — silent drop was
    // the bug. (0x09 inside a struct's value position is short-circuited
    // by the caller as the object-end sentinel and never reaches here;
    // we keep the variant in the match for defensive symmetry but route
    // it through the same `""` emission so a hypothetical caller that
    // does pass it gets the bundled shape.)
    AmfValue::Empty | AmfValue::ObjectEnd => {
      let _ = amf_type;
      FlashValue::Str(SmolStr::new_static(""))
    }
    // Codex R3/F1 — bundled Flash.pm:406-409 sets `$val = Get16u(...)`
    // (u16) and HandleTag emits the numeric value. Prior silent-drop
    // matched neither bundled `-j` nor `-n` output.
    AmfValue::Reference(v) => {
      let _ = amf_type;
      FlashValue::Double(f64::from(v))
    }
    // StrictArray/Struct should never reach this branch (the walk_pairs
    // caller dispatches arrays via `walk_array` and structs via
    // `walk_pairs`/`consume_struct_intro` BEFORE calling `read_value`).
    // Keep the catch-all silent — bundled's recursive ProcessMeta would
    // never reach HandleTag with these markers either.
    AmfValue::StrictArray | AmfValue::Struct => {
      let _ = amf_type;
      return;
    }
  };
  entries.push(Entry {
    name: SmolStr::from(name.to_string()),
    value,
    pc: resolved.pc,
  });
}

/// Perl `/^\w+$/` — ASCII word characters `[A-Za-z0-9_]`. Bundled Flash.pm
/// runs this on the RAW key BYTES (Flash.pm:390), where `\w` (non-`/u`)
/// rejects every high byte regardless of UTF-8 validity (oracle: a
/// `b\xffd` key and a valid-UTF-8 `b\xc3\xa9d` key both drop). Our keys
/// arrive `fix_utf8`-decoded, but the byte-level `is_ascii_alphanumeric`
/// test below rejects the substituted `?` (and any non-ASCII char from a
/// valid multibyte key) identically — so the gate matches Perl exactly
/// on either decode path.
fn is_word_key(s: &str) -> bool {
  !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Push a faithful `Truncated AMF record 0x%x` warning for the given
/// AMF type byte (Flash.pm:456 `$et->Warn(sprintf("Truncated AMF record
/// 0x%x",$type))`). Centralized so the format string stays exact across
/// every walker.
fn push_truncated_amf_record(warnings: &mut std::vec::Vec<SmolStr>, vtype: u8) {
  warnings.push(SmolStr::from(std::format!(
    "Truncated AMF record 0x{vtype:x}"
  )));
}

/// Read one AMF0 SCALAR value of the given `type` from `data[*pos..]`.
/// Returns [`ReadResult::Ok`] on success (and advances `*pos`) or
/// [`ReadResult::Truncated`] on truncation. The caller has already
/// consumed the type byte and (for structures) the introducer. Faithful
/// to the `if-elsif` ladder in `ProcessMeta` (Flash.pm:301-440) for the
/// non-struct, non-array cases. On every truncation path this fn pushes
/// the `Truncated AMF record 0x%x` warning (Flash.pm:456) before
/// returning the [`ReadResult::Truncated`] variant, so a caller in the
/// FRAME-2 position (the surrounding struct or array walker) sees both
/// the warning AND the structural cue to abort.
fn read_value(
  data: &[u8],
  pos: &mut usize,
  r#type: u8,
  warnings: &mut std::vec::Vec<SmolStr>,
) -> ReadResult {
  match r#type {
    0x00 | 0x0b => {
      // double / date (Flash.pm:305-325)
      if *pos + 8 > data.len() {
        push_truncated_amf_record(warnings, r#type);
        return ReadResult::Truncated(r#type);
      }
      // Checked-indexing (Phase C w2b): the `*pos + 8 > data.len()` guard makes
      // `data.get(*pos..*pos + 8)` `Some` (an 8-byte window) ⇒ byte-identical.
      let raw = match data.get(*pos..*pos + 8) {
        Some(&[b0, b1, b2, b3, b4, b5, b6, b7]) => {
          f64::from_be_bytes([b0, b1, b2, b3, b4, b5, b6, b7])
        }
        _ => 0.0,
      };
      *pos += 8;
      if r#type == 0x00 {
        ReadResult::Ok(AmfValue::Double(raw))
      } else {
        // date: divide by 1000 ⇒ seconds since Unix epoch, then read 16-bit
        // signed tz (minutes from UTC).
        if *pos + 2 > data.len() {
          // Bundled Flash.pm:312 `last if $pos + 2 > $dirLen` — at this
          // point `$val` HAS been assigned (the f64 was already read), so
          // line 455 sees `$val` defined and DOES NOT emit the warning.
          // Mirror: emit the half-parsed date as a raw double with no tz
          // suffix? Actually bundled emits the bare `$val / 1000` since
          // it overwrote `$val` already (`$val /= 1000;` at line 310).
          // The post-loop emission then renders that bare double under
          // the tag name. To stay value-equivalent, we return the bare
          // double-as-AmfValue (NOT AmfValue::Date — that would still
          // format as a date string). No truncation warning.
          let secs = raw / 1000.0;
          return ReadResult::Ok(AmfValue::Double(secs));
        }
        // Checked-indexing (Phase C w2b): the `*pos + 2 > data.len()` guard
        // above makes `data.get(*pos..*pos + 2)` `Some` ⇒ byte-identical.
        let tz = match data.get(*pos..*pos + 2) {
          Some(&[b0, b1]) => i16::from_be_bytes([b0, b1]),
          _ => 0,
        };
        *pos += 2;
        let secs = raw / 1000.0;
        let s = convert_unix_time(secs, tz);
        ReadResult::Ok(AmfValue::Date(s))
      }
    }
    0x01 => {
      // boolean (Flash.pm:326-330). 1-byte u8; PrintConv `0 => 'No', 1 =>
      // 'Yes'` applied only at -j emit time.
      if *pos + 1 > data.len() {
        push_truncated_amf_record(warnings, r#type);
        return ReadResult::Truncated(r#type);
      }
      // Checked-indexing (Phase C w2b): the `*pos + 1 > data.len()` guard makes
      // `data.get(*pos)` `Some` ⇒ byte-identical.
      let v = data.get(*pos).copied().unwrap_or(0);
      *pos += 1;
      ReadResult::Ok(AmfValue::Boolean(v))
    }
    0x02 => {
      // string (Flash.pm:331-336). u16 length + UTF-8 bytes.
      if *pos + 2 > data.len() {
        push_truncated_amf_record(warnings, r#type);
        return ReadResult::Truncated(r#type);
      }
      // Checked-indexing (Phase C w2b): the `*pos + 2 > data.len()` then
      // `*pos + 2 + len > data.len()` guards make `data.get(*pos..*pos + 2)`
      // and `data.get(*pos + 2..*pos + 2 + len)` `Some` ⇒ byte-identical.
      let len = match data.get(*pos..*pos + 2) {
        Some(&[b0, b1]) => u16::from_be_bytes([b0, b1]) as usize,
        _ => 0,
      };
      if *pos + 2 + len > data.len() {
        push_truncated_amf_record(warnings, r#type);
        return ReadResult::Truncated(r#type);
      }
      let raw = data.get(*pos + 2..*pos + 2 + len).unwrap_or(&[]);
      *pos += 2 + len;
      // Flash.pm:333 `$val = substr($$dataPt, $pos + 2, $len)` keeps the
      // RAW bytes; the bundled `exiftool` JSON emitter applies
      // `XMP::FixUTF8` at serialization (`exiftool:3822`), replacing each
      // invalid UTF-8 byte with the literal ASCII `?` (XMP.pm:2948-2972).
      // `from_utf8_lossy` would instead emit U+FFFD — a byte-mismatch at
      // the conformance gate (Codex PR #32 R18/F1; oracle: `41 ff 42` ⇒
      // `"A?B"`, NOT `"A\u{FFFD}B"`). Apply `fix_utf8` at the parser seam.
      ReadResult::Ok(AmfValue::String(fix_utf8(raw)))
    }
    0x03 => {
      // object — pairs of u16-len-string keys + values. No introducer
      // beyond the type byte (already consumed). Caller dispatches to
      // `process_struct` to walk children.
      ReadResult::Ok(AmfValue::Struct)
    }
    0x05 | 0x06 | 0x09 | 0x0d => {
      // null / undefined / object-end / unsupported (Flash.pm:403-405).
      // Empty value. Object-end is the structural sentinel handled by
      // caller via `emitted_type == 0x09`.
      let v = if r#type == 0x09 {
        AmfValue::ObjectEnd
      } else {
        AmfValue::Empty
      };
      ReadResult::Ok(v)
    }
    0x07 => {
      // reference (Flash.pm:406-409). u16.
      if *pos + 2 > data.len() {
        push_truncated_amf_record(warnings, r#type);
        return ReadResult::Truncated(r#type);
      }
      // Checked-indexing (Phase C w2b): the `*pos + 2 > data.len()` guard makes
      // `data.get(*pos..*pos + 2)` `Some` ⇒ byte-identical.
      let v = match data.get(*pos..*pos + 2) {
        Some(&[b0, b1]) => u16::from_be_bytes([b0, b1]),
        _ => 0,
      };
      *pos += 2;
      ReadResult::Ok(AmfValue::Reference(v))
    }
    0x08 => {
      // mixed array (Flash.pm:341-344). Skip 4-byte top-array-index.
      if *pos + 4 > data.len() {
        push_truncated_amf_record(warnings, r#type);
        return ReadResult::Truncated(r#type);
      }
      *pos += 4;
      ReadResult::Ok(AmfValue::Struct)
    }
    0x0a => {
      // array (Flash.pm:410-426) — handled by `walk_array`, not via
      // `read_value`. If somehow reached as a top-level scalar in
      // process_meta's non-struct branch, mark as the strict-array
      // marker; the caller's first-record-string gate already rejects
      // any non-string rec=0 value, so this is defensive only.
      let _ = warnings;
      ReadResult::Ok(AmfValue::StrictArray)
    }
    0x0c | 0x0f => {
      // long string / XML (Flash.pm:427-432). u32 length + UTF-8 bytes.
      if *pos + 4 > data.len() {
        push_truncated_amf_record(warnings, r#type);
        return ReadResult::Truncated(r#type);
      }
      // Checked-indexing (Phase C w2b): the `*pos + 4 > data.len()` then
      // `*pos + 4 + len > data.len()` guards make `data.get(*pos..*pos + 4)`
      // and `data.get(*pos + 4..*pos + 4 + len)` `Some` ⇒ byte-identical.
      let len = match data.get(*pos..*pos + 4) {
        Some(&[b0, b1, b2, b3]) => u32::from_be_bytes([b0, b1, b2, b3]) as usize,
        _ => 0,
      };
      if *pos + 4 + len > data.len() {
        push_truncated_amf_record(warnings, r#type);
        return ReadResult::Truncated(r#type);
      }
      let raw = data.get(*pos + 4..*pos + 4 + len).unwrap_or(&[]);
      *pos += 4 + len;
      // Flash.pm:430 `$val = substr($$dataPt, $pos + 4, $len)` (long string
      // 0x0c / XML doc 0x0f) keeps RAW bytes too; same FixUTF8-at-JSON
      // semantics as the 0x02 string arm above (Codex PR #32 R18/F1
      // class-sweep). `fix_utf8` replaces each invalid byte with `?`.
      ReadResult::Ok(AmfValue::String(fix_utf8(raw)))
    }
    0x10 => {
      // typed-object (Flash.pm:345-347, 357-363). The first u16-prefixed
      // string is the object name (ignored), then key/value pairs.
      if *pos + 2 > data.len() {
        push_truncated_amf_record(warnings, r#type);
        return ReadResult::Truncated(r#type);
      }
      // Checked-indexing (Phase C w2b): the `*pos + 2 > data.len()` guard makes
      // `data.get(*pos..*pos + 2)` `Some` ⇒ byte-identical.
      let name_len = match data.get(*pos..*pos + 2) {
        Some(&[b0, b1]) => u16::from_be_bytes([b0, b1]) as usize,
        _ => 0,
      };
      if *pos + 2 + name_len > data.len() {
        push_truncated_amf_record(warnings, r#type);
        return ReadResult::Truncated(r#type);
      }
      *pos += 2 + name_len;
      ReadResult::Ok(AmfValue::Struct)
    }
    _ => {
      // Flash.pm:435-439 — unsupported AMF type. Emit Warn + abort the meta
      // packet. Distinct from truncation: bundled's line 437 Warn is
      // unconditional (it does NOT depend on `$val` being undef), so the
      // top-level walker's "pop the just-pushed truncation warning if a
      // prior record succeeded" rule MUST NOT apply here. We surface
      // `Unsupported(t)` so callers can branch on it (Codex R2/F3).
      let name = amf_type_name(r#type);
      warnings.push(SmolStr::from(std::format!(
        "AMF {name} record not yet supported"
      )));
      ReadResult::Unsupported(r#type)
    }
  }
}

// ===========================================================================
// `ConvertUnixTime` PrintConv used by AMF date type (Flash.pm:316)
// ===========================================================================

/// Faithful `Image::ExifTool::ConvertUnixTime($val, 0, 6)` + tz suffix
/// (Flash.pm:316-324). Emits `YYYY:MM:DD HH:MM:SS.ssssss±HH:MM` where the
/// date/time part is the UTC `gmtime()` of the input second (NO tz shift —
/// the suffix is appended as the AMF-recorded tz offset, NOT applied to
/// the displayed time).
fn convert_unix_time(secs: f64, tz_minutes: i16) -> std::string::String {
  let mut buf = std::string::String::with_capacity(34);
  // Codex PR #32 R11/F2 — bundled `ConvertUnixTime` (ExifTool.pm:6776)
  // returns the zero-time sentinel `'0000:00:00 00:00:00'` BEFORE any
  // `gmtime`/`$dec` fractional formatting: `return '0000:00:00 00:00:00'
  // if $time == 0;`. An AMF date of `0` milliseconds → `$val = 0/1000 =
  // 0` → this sentinel (NO `.ssssss` fraction). Flash.pm:317-324 still
  // appends the AMF tz suffix (`$val .= '+'; $val .= sprintf(...)`).
  // Pre-R11 we ran `unix_to_civil_micro(0.0)` → `1970:01:01
  // 00:00:00.000000` — diverging from bundled
  // `0000:00:00 00:00:00`. Pinned by
  // `flash_amf_date_zero_sentinel_conformance` (R11/F2).
  if secs == 0.0 {
    buf.push_str("0000:00:00 00:00:00");
    push_amf_tz_suffix(&mut buf, tz_minutes);
    return buf;
  }
  let (date_part, ss_int, ss_micro) = unix_to_civil_micro(secs);
  // `YYYY:MM:DD HH:MM:SS.ssssss` (6 fractional digits).
  // Codex PR #32 R12/F2 — bundled `ConvertUnixTime` (ExifTool.pm:6797)
  // formats the year with Perl `sprintf` `%4d`, which is MINIMUM-WIDTH
  // SPACE-padded, NOT zero-padded. A pre-1000 year (e.g. Unix second
  // -30641760000 → 0999-01-01 UTC) → bundled `" 999:01:01 ..."` (one
  // leading space) where the port's `{:04}` produced `"0999:..."`.
  // Mirror `%4d` with `{:>4}` (right-justify, space fill).
  buf.push_str(&std::format!(
    "{:>4}:{:02}:{:02} {:02}:{:02}:{:02}.{:06}",
    date_part.0,
    date_part.1,
    date_part.2,
    date_part.3,
    date_part.4,
    ss_int,
    ss_micro
  ));
  push_amf_tz_suffix(&mut buf, tz_minutes);
  buf
}

/// Append the AMF-recorded timezone suffix `±HH:MM` (Flash.pm:317-324)
/// to `buf`. The offset is the AMF-stored value in minutes; it is NOT
/// applied to the displayed time — bundled appends it verbatim after
/// the `ConvertUnixTime` result (Flash.pm: `$val .= '-'`/`'+'` then
/// `sprintf('%.2d:%.2d', int($tz/60), $tz%60)`).
fn push_amf_tz_suffix(buf: &mut std::string::String, tz_minutes: i16) {
  let (sign, tz_abs) = if tz_minutes < 0 {
    ('-', -i32::from(tz_minutes))
  } else {
    ('+', i32::from(tz_minutes))
  };
  buf.push(sign);
  buf.push_str(&std::format!("{:02}:{:02}", tz_abs / 60, tz_abs % 60));
}

/// Decompose a Unix second (allowed to be fractional) into civil
/// `(year, month, day, hour, minute, seconds_int, micro_remainder)`.
/// Avoids `chrono`/`time` dependencies: the formula is Howard Hinnant's
/// `civil_from_days` (well-known days-to-civil algorithm).
fn unix_to_civil_micro(secs: f64) -> ((i32, u32, u32, u32, u32), u32, u32) {
  // Integer seconds and microseconds. We round subseconds (negative inputs
  // are clamped to 0 for the fixture — bundled doesn't exercise pre-1970).
  let secs_int_signed = secs.trunc() as i64;
  // Microseconds: round subsecond fraction to nearest microsecond (matches
  // `sprintf('%06d', ms)` semantics in Perl's `ConvertUnixTime` with 6-digit
  // precision).
  let mut micro = ((secs - secs_int_signed as f64) * 1_000_000.0).round() as i64;
  let mut secs_int = secs_int_signed;
  if micro >= 1_000_000 {
    secs_int += 1;
    micro -= 1_000_000;
  } else if micro < 0 {
    secs_int -= 1;
    micro += 1_000_000;
  }

  // Compute civil from days-since-epoch.
  let days = secs_int.div_euclid(86_400);
  let tod = secs_int.rem_euclid(86_400);
  let hour = (tod / 3600) as u32;
  let minute = ((tod / 60) % 60) as u32;
  let sec = (tod % 60) as u32;

  // Days-to-civil (Howard Hinnant — shift to era starting at year -32768).
  // Days are reckoned from 1970-01-01 (epoch).
  let z = days + 719_468;
  let era = z.div_euclid(146_097);
  let doe = z.rem_euclid(146_097) as i64;
  let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
  let y = yoe + era * 400;
  let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  let mp = (5 * doy + 2) / 153;
  let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
  let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
  let y = (y + i64::from(m <= 2)) as i32;

  ((y, m, d, hour, minute), sec, micro as u32)
}

// ===========================================================================
// `Taggable` — the golden-pattern emission path
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::diagnostics::Diagnose for Meta<'_> {
  /// The FLV `$et->Warn` accumulators (Flash.pm:353/437/456/504/511) as
  /// [`Diagnostic`](crate::diagnostics::Diagnostic) warnings, in occurrence
  /// order.
  fn diagnostics(&self) -> std::vec::Vec<crate::diagnostics::Diagnostic> {
    self
      .warnings()
      .iter()
      .map(|w| crate::diagnostics::Diagnostic::warn(w.as_str()))
      .collect()
  }
}

#[cfg(feature = "alloc")]
impl crate::emit::Taggable for Meta<'_> {
  /// Yield Flash tags in Meta-walk order (faithful to bundled `FoundTag`
  /// call order — Flash.pm runs the audio/video bit-table emissions ALSO
  /// interleaved with meta packet emissions as the containing FLV tag is
  /// read) — the golden-pattern parallel to the retired `serialize_tags`:
  /// the SINK changes (an [`EmittedTag`](crate::emit::EmittedTag) per value
  /// instead of `out.write_*`), the per-tag PrintConv/ValueConv branches are
  /// preserved verbatim. The `Warn` emissions stay OUT of this stream
  /// (`run_emission` has no warning channel); the
  /// `format_parser::AnyMeta::Flv` arm drains [`Meta::warnings`] after the
  /// engine (Flash.pm:353/437/456/504/511).
  ///
  /// `mode == PrintConv` (`-j`) ⇒ PrintConv strings; `mode == ValueConv`
  /// (`-n`) ⇒ post-ValueConv raw scalars.
  ///
  /// Group: `family0` = `"Flash"` (the `%Flash::Main` table group);
  /// `family1` = `"Flash"` (the `-G1` key — constant for every FLV tag),
  /// byte-identical to the retired sink. No Flash tag is `Unknown => 1` ⇒
  /// `unknown: false`.
  #[cfg_attr(not(feature = "json"), allow(dead_code))]
  fn tags(
    &self,
    opts: crate::emit::EmitOptions,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    let mode = opts.mode;
    use crate::emit::EmittedTag;
    let print_conv = matches!(mode, crate::emit::ConvMode::PrintConv);
    let mut tags: std::vec::Vec<EmittedTag> = std::vec::Vec::with_capacity(self.entries.len());
    for entry in &self.entries {
      push_entry(&mut tags, entry, print_conv);
    }
    tags.into_iter()
  }
}

/// Push a single Flash entry as an [`EmittedTag`] (family0 `"Flash"`, family1
/// `"Flash"`, `unknown: false`). Preserves every per-value PrintConv/ValueConv
/// branch of the retired `emit_entry` verbatim.
#[cfg(feature = "alloc")]
#[cfg_attr(not(feature = "json"), allow(dead_code))]
fn push_entry(tags: &mut std::vec::Vec<crate::emit::EmittedTag>, entry: &Entry, print_conv: bool) {
  use crate::emit::EmittedTag;
  use crate::value::{Group, TagValue};
  const GROUP: &str = "Flash";
  let name = entry.name.as_str();
  // family0 "Flash" / family1 "Flash" for every Flash tag (constant).
  let push = |tags: &mut std::vec::Vec<EmittedTag>, value: TagValue| {
    tags.push(EmittedTag::new(
      Group::new(GROUP, GROUP),
      name.into(),
      value,
      false,
    ));
  };
  match &entry.value {
    FlashValue::Double(d) => {
      // Special-case: AudioEncoding / AudioChannels / VideoEncoding have
      // hash PrintConvs that don't fit the shared `PrintConvMode` enum.
      // The raw value is the post-ValueConv index/integer.
      //
      // Codex PR #32 R13/F2 — a Perl hash PrintConv MISS does NOT fall back
      // to the raw number under `-j`: ExifTool's `GetValue` (ExifTool.pm:
      // 3603-3625) sets `$value = "Unknown ($val)"` when `$$conv{$val}` is
      // undefined and the hash has no `BITMASK`/`OTHER`. So a reserved code
      // (e.g. AudioEncoding nibble 9, or any VideoEncoding gap) renders as
      // `Unknown (<code>)` under `-j`. Under `-n` PrintConv is skipped
      // entirely and the raw numeric passes through (handled below). None of
      // these three hashes declares `PrintHex`, so the `Unknown (0x%x)`
      // hex variant (ExifTool.pm:3616-3619) never applies — always decimal.
      if print_conv && matches!(name, "AudioEncoding" | "AudioChannels" | "VideoEncoding") {
        let code = *d as u32;
        let hit = match name {
          "AudioEncoding" => audio_encoding_pc(code),
          "AudioChannels" => audio_channels_pc(code),
          _ => video_encoding_pc(code),
        };
        match hit {
          Some(s) => push(tags, TagValue::Str(s.into())),
          None => push(tags, TagValue::Str(std::format!("Unknown ({code})").into())),
        }
        return;
      }
      match entry.pc {
        PrintConvMode::None | PrintConvMode::RoundMilli if !print_conv => {
          // `-n` raw — emit as integer when value is whole and fits.
          push(tags, fold_double(*d));
        }
        PrintConvMode::None => {
          // `-j` PrintConv-on but no PrintConv configured ⇒ same numeric
          // emission. Note: `width/height/datasize/...` are doubles in
          // AMF, but bundled Perl's number stringification drops trailing
          // `.0` so a whole-number double like `320.0` emits as `320`.
          push(tags, fold_double(*d));
        }
        PrintConvMode::ConvertBitrate => {
          if print_conv {
            push(tags, str_from_writer(|w| write_convert_bitrate(w, *d)));
          } else {
            push(tags, fold_double(*d));
          }
        }
        PrintConvMode::ConvertDuration => {
          if print_conv {
            push(tags, str_from_writer(|w| write_convert_duration(w, *d)));
          } else {
            push(tags, fold_double(*d));
          }
        }
        PrintConvMode::RoundMilli => {
          // Flash.pm:197 — `int($val * 1000 + 0.5) / 1000`. For -j we emit
          // the rounded numeric (the value-semantic gate matches `20`
          // against `20.0`). For -n same (handled above).
          let rounded = (d * 1000.0 + 0.5).trunc() / 1000.0;
          push(tags, fold_double(rounded));
        }
        PrintConvMode::RoundInt => {
          // Flash.pm:231 — `int($val + 0.5)`.
          let rounded = (d + 0.5).trunc();
          if print_conv {
            // -j: integer.
            push(tags, fold_double(rounded));
          } else {
            push(tags, fold_double(*d));
          }
        }
        PrintConvMode::ConvertDateTime => {
          // Default options: ConvertDateTime is a no-op pass-through;
          // emit the raw double.
          push(tags, fold_double(*d));
        }
      }
    }
    FlashValue::Bool(b) => {
      // Flash.pm:329 applies the `{0 => 'No', 1 => 'Yes'}` map INSIDE
      // ProcessMeta (the value-conv path, not PrintConv). Both `-j` and
      // `-n` then emit the STRING "Yes"/"No". For values ≥ 2 (illegal
      // boolean encoding) bundled keeps the raw u8 — we emit it as a
      // bare number, matching Perl's silent fallthrough.
      let _ = print_conv; // bundled doesn't gate on the -n flag here
      match b {
        0 => push(tags, TagValue::Str("No".into())),
        1 => push(tags, TagValue::Str("Yes".into())),
        _ => push(tags, TagValue::U64(u64::from(*b))),
      }
    }
    FlashValue::Str(s) => {
      // Codex PR #32 R19/F1 — apply the resolved tag's PrintConv to a
      // STRING-typed value (Flash.pm:157-247 + ExifTool.pm GetValue, which
      // runs the conv on `$val` whether it arrived as a number or a numeric
      // string). The two ValueConv shapes (`$val * 1000`, `s/\s+$//`) were
      // already resolved in `emit_resolved` (mul_1000 strings became
      // `FlashValue::Double`; `creationdate` was trimmed). Here only the
      // no-ValueConv tags with a PrintConv reach a non-`None` `pc`:
      //   * ConvertDuration (`duration`/`starttime`, Flash.pm:192/221) —
      //     IsFloat-guarded; a float-shaped string formats, else verbatim.
      //   * RoundMilli (`framerate`, Flash.pm:197) — `int($val*1000+0.5)/1000`
      //     with raw Perl arithmetic coercion (no IsFloat guard, comma
      //     terminates the prefix); always numeric in `-j`.
      //   * ConvertDateTime (`metadatadate`, Flash.pm:214) — pass-through
      //     under default options.
      // Under `-n` (PrintConv off) every arm emits the raw string; the
      // serializer's number-gate coerces a numeric-looking string to the
      // bare JSON number the oracle carries.
      match entry.pc {
        PrintConvMode::ConvertDuration if print_conv => {
          push(
            tags,
            str_from_writer(|w| write_convert_duration_str(w, s.as_str())),
          );
        }
        PrintConvMode::RoundMilli if print_conv => {
          // `int($val * 1000 + 0.5) / 1000` — raw arithmetic coercion of the
          // string (comma terminates; non-numeric ⇒ 0). Emit the rounded
          // numeric; the value-semantic gate matches the oracle's number.
          let rounded = (perl_str_to_f64(s.as_str()) * 1000.0 + 0.5).trunc() / 1000.0;
          push(tags, fold_double(rounded));
        }
        // None / ConvertDateTime (pass-through), or `-n` for any pc: emit the
        // raw string. ConvertBitrate / RoundInt never reach here on a string
        // (their tags carry `mul_1000`, so `emit_resolved` already numified
        // the value to `FlashValue::Double`).
        _ => push(tags, TagValue::Str(s.clone())),
      }
    }
    FlashValue::Date(s) => push(tags, TagValue::Str(s.clone())),
    FlashValue::List(items) => {
      // AMF strict-array (0x0a) — emit as a heterogeneous JSON array.
      // Each FlashListItem was already converted per-AMF-type at parse
      // time (doubles stay numeric; strings/longstrings/dates are
      // strings; booleans are `"Yes"`/`"No"` per Flash.pm:329). Codex
      // R2/F2 — nested-array elements recurse, yielding `[[a,b],c]`.
      //
      // Codex PR #32 R12/F1 — bundled `HandleTag` is called with the AMF
      // array reference itself (Flash.pm:394/516); ExifTool's `GetValue`
      // (ExifTool.pm:3567-3685) then iterates the arrayref and applies
      // the tag's PrintConv to EVERY element. For a known tag with a
      // PrintConv (Duration/StartTime/TotalDuration/AudioBitrate/
      // VideoBitrate/FrameRate/TotalDataRate) a strict-array value
      // therefore renders per-element: `duration` → `["1.50 s",
      // "0:01:01"]` under `-j`. Under `-n` PrintConv is skipped and the
      // raw numerics pass through (`[1.5,61]`). Pre-R12 the port emitted
      // the raw list for both modes, dropping the per-element PrintConv.
      let list: std::vec::Vec<TagValue> = items
        .iter()
        .map(|it| flash_list_item_with_pc(it, entry.pc, print_conv))
        .collect();
      push(tags, TagValue::List(list));
    }
  }
}

/// Build a [`TagValue::Str`](crate::value::TagValue::Str) by running a
/// `write_*` closure into a fresh `String` — the golden-pattern replacement
/// for the retired sink's `out.write_fmt(group, name, closure)` (an in-memory
/// `String` write is infallible, so the closure's `Result` is discarded).
#[cfg(feature = "alloc")]
#[cfg_attr(not(feature = "json"), allow(dead_code))]
fn str_from_writer(
  f: impl FnOnce(&mut dyn core::fmt::Write) -> core::fmt::Result,
) -> crate::value::TagValue {
  let mut s = std::string::String::new();
  let _ = f(&mut s);
  crate::value::TagValue::Str(s.into())
}

/// Convert one [`FlashListItem`] to its `TagValue` shape, applying the
/// owning tag's PrintConv (`pc`) per numeric element when `print_conv`
/// is set (`-j`).
///
/// Codex PR #32 R12/F1 — bundled ExifTool `GetValue` (ExifTool.pm:
/// 3567-3685) iterates an array-valued tag and runs the tag's PrintConv
/// over each element. The numeric variants here mirror the scalar
/// `FlashValue::Double` arm of [`emit_entry`]:
///   * [`PrintConvMode::ConvertDuration`] → `ConvertDuration($val)`
///     (Flash.pm:192/221/226).
///   * [`PrintConvMode::ConvertBitrate`] → `ConvertBitrate($val)`
///     (Flash.pm:169/238). The `*1000` ValueConv was already applied at
///     parse time (`walk_array` honours `parent_resolved.mul_1000`).
///   * [`PrintConvMode::RoundMilli`] → `int($val*1000+0.5)/1000`
///     (Flash.pm:197).
///   * [`PrintConvMode::RoundInt`] → `int($val+0.5)` (Flash.pm:231).
///   * [`PrintConvMode::ConvertDateTime`] / [`PrintConvMode::None`] are
///     numeric pass-throughs under default options.
///
/// Under `-n` (`print_conv == false`) PrintConv is skipped entirely and
/// the raw numeric passes through, matching bundled `-n`. Non-numeric
/// elements (strings/booleans/dates) are unaffected.
///
/// Codex PR #32 R13/F1 — bundled `GetValue` (ExifTool.pm:3567-3685)
/// iterates only the TOP-LEVEL arrayref with `$val = $$vals[$i]` and never
/// recurses into a nested arrayref element. The tag conversion is therefore
/// applied ONCE to each top-level element; a nested arrayref element is the
/// element the conversion sees, NOT its inner numbers. Concretely, a
/// `duration` strict-array `[1.5, [2,3], 61]` → bundled `Flash:Duration
/// ["1.50 s",[2,3],"0:01:01"]` under `-j` and `[1.5,[2,3],61]` under `-n`:
/// `ConvertDuration` runs on each top-level SCALAR, while the nested
/// arrayref `[2,3]` passes through with its inner numbers untouched (no
/// recursive descent). Pinned by `flash_duration_mixed_nested.flv`.
///
/// Codex PR #32 R14/F1 — what the owning conversion DOES to a nested
/// arrayref top-level element depends on the conversion (the conversion IS
/// applied; only the recursive descent into the arrayref is disabled):
///   * [`PrintConvMode::ConvertDuration`] (`ConvertDuration($val)`,
///     ExifTool.pm:6869 `return $time unless IsFloat($time)`) and
///     [`PrintConvMode::None`] return the arrayref unchanged → the nested
///     array renders RAW. This is DETERMINISTIC and byte-exact vs bundled.
///   * Arithmetic conversions ([`PrintConvMode::RoundMilli`] FrameRate
///     `int($val*1000+0.5)/1000`, [`PrintConvMode::RoundInt`] TotalDataRate
///     `int($val+0.5)`) and the `$val * 1000` ValueConv coerce an arrayref
///     to its Perl SV memory ADDRESS (a non-deterministic ASLR integer that
///     changes every run), then do arithmetic on it. [`PrintConvMode::
///     ConvertBitrate`] is fed the `$val * 1000` ValueConv result (already
///     an address-derived number, so `IsFloat` is true) → a `"<garbage>
///     Gbps"` string. These outputs are NON-REPRODUCIBLE: a strict 1:1 port
///     has no memory address to coerce and MUST NOT fabricate one. The
///     deterministic, defensible behavior is to render the nested arrayref
///     element RAW (the same shape `IsFloat`-guarded conversions produce),
///     declining to chase the irreproducible Perl pointer artifact. This is
///     a documented faithfulness LIMITATION confined to the degenerate
///     "nested arrayref as a top-level element of an arithmetic/bitrate
///     tag" input (no real FLV emits this; the conformance fixtures cover
///     the deterministic ConvertDuration path).
///
/// This function therefore applies `pc` ONLY to a top-level scalar element;
/// a nested [`FlashListItem::List`] is rendered raw via
/// [`flash_list_item_raw`] (no descent, no fabricated address).
#[cfg(feature = "alloc")]
#[cfg_attr(not(feature = "json"), allow(dead_code))]
fn flash_list_item_with_pc(
  item: &FlashListItem,
  pc: PrintConvMode,
  print_conv: bool,
) -> crate::value::TagValue {
  use crate::value::TagValue;
  match item {
    FlashListItem::Double(d) if print_conv => match pc {
      PrintConvMode::ConvertDuration => {
        let mut s = std::string::String::new();
        let _ = write_convert_duration(&mut s, *d);
        TagValue::Str(SmolStr::from(s))
      }
      PrintConvMode::ConvertBitrate => {
        let mut s = std::string::String::new();
        let _ = write_convert_bitrate(&mut s, *d);
        TagValue::Str(SmolStr::from(s))
      }
      PrintConvMode::RoundMilli => {
        let rounded = (d * 1000.0 + 0.5).trunc() / 1000.0;
        fold_double(rounded)
      }
      PrintConvMode::RoundInt => fold_double((d + 0.5).trunc()),
      PrintConvMode::None | PrintConvMode::ConvertDateTime => fold_double(*d),
    },
    // `-n`: PrintConv skipped — raw numeric pass-through.
    FlashListItem::Double(d) => fold_double(*d),
    // Codex PR #32 R19/F1 — a STRING element of a known-PrintConv tag gets
    // the SAME per-element PrintConv as a scalar string (the `*datarate`
    // ValueConv already numified its strings to `FlashListItem::Double` in
    // `collect_array_items`, so only the no-ValueConv-with-PrintConv tags
    // reach here with a string): ConvertDuration (IsFloat-guarded) and
    // RoundMilli (raw arithmetic coercion) in `-j`; raw string in `-n` or
    // for `None`/ConvertDateTime. Verified per-element vs bundled on
    // `flash_amf_string_conv.flv` (`duration ["1.5","notnum","12,5"]` →
    // `-j ["1.50 s","notnum","12.50 s"]`).
    FlashListItem::Str(s) if print_conv => match pc {
      PrintConvMode::ConvertDuration => {
        let mut out = std::string::String::new();
        let _ = write_convert_duration_str(&mut out, s.as_str());
        TagValue::Str(SmolStr::from(out))
      }
      PrintConvMode::RoundMilli => {
        let rounded = (perl_str_to_f64(s.as_str()) * 1000.0 + 0.5).trunc() / 1000.0;
        fold_double(rounded)
      }
      // None / ConvertDateTime (pass-through). ConvertBitrate / RoundInt are
      // unreachable on a string element (their tags numify via `mul_1000`).
      _ => TagValue::Str(s.clone()),
    },
    FlashListItem::Str(s) => TagValue::Str(s.clone()),
    // Codex R13/F1 — a nested arrayref is never iterated by `GetValue`, so
    // the owning tag PrintConv does NOT reach its elements: render raw.
    FlashListItem::List(items) => TagValue::List(items.iter().map(flash_list_item_raw).collect()),
  }
}

/// Render one [`FlashListItem`] WITHOUT applying any tag conversion, at every
/// depth. Used for nested arrayref elements (Codex R13/F1, R14/F1): bundled
/// `GetValue` (ExifTool.pm:3577 `$val = $$vals[0]` / 3678 `$val =
/// $$vals[$i]`) iterates only the single top-level arrayref, so the
/// conversion never descends into a nested arrayref and everything beneath
/// it stays raw. For `IsFloat`-guarded conversions (ConvertDuration) the
/// nested arrayref passes through unchanged → this raw rendering is
/// byte-exact vs bundled. For coercion conversions (arithmetic / `$val*1000`
/// / ConvertBitrate) bundled instead emits a non-reproducible memory-address
/// artifact (see [`flash_list_item_with_pc`]); the port deliberately renders
/// raw rather than fabricate an address. Numerics fold to `I64`/`F64` raw;
/// strings pass through; lists recurse raw.
#[cfg(feature = "alloc")]
#[cfg_attr(not(feature = "json"), allow(dead_code))]
fn flash_list_item_raw(item: &FlashListItem) -> crate::value::TagValue {
  use crate::value::TagValue;
  match item {
    FlashListItem::Double(d) => fold_double(*d),
    FlashListItem::Str(s) => TagValue::Str(s.clone()),
    FlashListItem::List(items) => TagValue::List(items.iter().map(flash_list_item_raw).collect()),
  }
}

/// Fold a double to `TagValue::I64` when it is integer-valued and fits
/// `i64` (matches bundled's Perl `%.15g` number stringification: `1.0`
/// emits as `1`), else `TagValue::F64`.
#[cfg(feature = "alloc")]
#[cfg_attr(not(feature = "json"), allow(dead_code))]
fn fold_double(d: f64) -> crate::value::TagValue {
  use crate::value::TagValue;
  if d.is_finite() && d.fract() == 0.0 && d >= i64::MIN as f64 && d <= i64::MAX as f64 {
    TagValue::I64(d as i64)
  } else {
    TagValue::F64(d)
  }
}

// ===========================================================================
// `Project` — the normalized cross-format domain projection (golden L2)
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::metadata::Project for Meta<'_> {
  /// Project Flash (FLV) metadata onto the normalized
  /// [`MediaMetadata`](crate::metadata::MediaMetadata) domain.
  ///
  /// FLV is a video container: the faithful structural contribution is one
  /// video [`TrackKind`](crate::metadata::TrackKind). A finer audio/video
  /// split is not surfaced here — the typed `Meta` records only the emitted
  /// `onMetaData` tags (which MAY include `audiocodecid` etc.), not a clean
  /// "this file carries an audio stream" accessor the projection can consume
  /// without re-parsing. Duration is left `None`: the decoded `Duration` is a
  /// `Flash:Duration` TAG (ConvertDuration / raw seconds) inside the tag
  /// stream, not a clean wall-clock accessor. Camera / lens / GPS / capture
  /// stay `None` (FLV carries no such facts).
  fn project(&self) -> crate::metadata::MediaMetadata {
    use crate::metadata::TrackKind;
    let mut media = crate::metadata::MediaMetadata::new();
    media.media_mut().track_kinds_mut().push(TrackKind::Video);
    media
  }
}

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

  #[test]
  fn flv_short_buffer_returns_none() {
    assert!(parse_borrowed(&[]).is_none());
    assert!(parse_borrowed(b"FLV").is_none());
  }

  #[test]
  fn flv_bad_magic_returns_none() {
    let bytes = [b'X', b'L', b'V', 0x01, 0x05, 0, 0, 0, 9];
    assert!(parse_borrowed(&bytes).is_none());
  }

  #[test]
  fn audio_octet_decodes_fixture() {
    // Mp3 (encoding=2), 11kHz (sr_idx=1), 16-bit (bps_raw=1), mono (ch=0).
    // octet = (2<<4) | (1<<2) | (1<<1) | 0 = 0x26.
    let mut entries = std::vec::Vec::new();
    process_audio_octet(&mut entries, 0x26);
    assert_eq!(entries.len(), 4);
    let names: std::vec::Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
      names,
      &[
        "AudioEncoding",
        "AudioSampleRate",
        "AudioBitsPerSample",
        "AudioChannels"
      ]
    );
    let nums: std::vec::Vec<f64> = entries
      .iter()
      .map(|e| match e.value {
        FlashValue::Double(d) => d,
        _ => f64::NAN,
      })
      .collect();
    assert_eq!(nums, &[2.0, 11025.0, 16.0, 1.0]);
  }

  #[test]
  fn video_octet_decodes_fixture() {
    // VP6 = encoding=4 ⇒ byte low nibble = 4.
    let mut entries = std::vec::Vec::new();
    process_video_octet(&mut entries, 0x44);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name.as_str(), "VideoEncoding");
    if let FlashValue::Double(d) = entries[0].value {
      assert!((d - 4.0).abs() < 1e-9);
    } else {
      panic!("expected Double");
    }
  }

  #[test]
  fn convert_unix_time_matches_perl_oracle() {
    // Flash:MetadataDate fixture: AMF date carries ms=1181660591528.55,
    // divided by 1000 ⇒ secs=1181660591.528.. (UTC = 2007:06:12 15:03:11);
    // tz=-240 (minutes). Bundled emits the UTC time literal with tz suffix
    // (NO local shift applied) ⇒ "2007:06:12 15:03:11.528553-04:00".
    let s = convert_unix_time(1_181_660_591.528_553, -240);
    assert_eq!(s, "2007:06:12 15:03:11.528553-04:00");
  }

  #[test]
  fn is_word_key_matches_perl_w() {
    assert!(is_word_key("test"));
    assert!(is_word_key("framerate"));
    assert!(is_word_key("Tag_foo"));
    assert!(is_word_key("123abc"));
    assert!(!is_word_key(""));
    assert!(!is_word_key("foo.bar"));
    assert!(!is_word_key("foo bar"));
    // Codex PR #32 R18/F1 — a `fix_utf8`-decoded bad-UTF-8 key carries the
    // ASCII `?` substitute, which fails the gate (matching Perl's
    // byte-level `\w` rejection of the original high byte). A valid
    // multibyte key likewise fails (`is_ascii_alphanumeric` is false for
    // non-ASCII). Both drop, identical to bundled (oracle: `b\xffd` key ⇒
    // dropped, valid sibling still emits).
    assert!(!is_word_key("b?d"));
    assert!(!is_word_key("café"));
  }

  #[test]
  fn lookup_meta_resolves_expected_entries() {
    assert_eq!(lookup_meta("audiodatarate").unwrap().name, "AudioBitrate");
    assert!(lookup_meta("audiodatarate").unwrap().mul_1000);
    assert_eq!(
      lookup_meta("duration").unwrap().pc,
      PrintConvMode::ConvertDuration
    );
    assert_eq!(lookup_meta("height").unwrap().name, "ImageHeight");
    assert!(lookup_meta("unknownkey").is_none());
  }

  // ---------------------------------------------------------------------
  // Codex R1/F1 — strict-array heterogeneous element collection
  // ---------------------------------------------------------------------

  #[test]
  fn read_value_double_returns_ok_on_full_buffer() {
    // Type 0x00 reads 8 BE bytes.
    let bytes = 1.5_f64.to_be_bytes();
    let mut pos = 0;
    let mut warnings = std::vec::Vec::new();
    match read_value(&bytes, &mut pos, 0x00, &mut warnings) {
      ReadResult::Ok(AmfValue::Double(d)) => assert!((d - 1.5).abs() < 1e-12),
      other => panic!("expected Ok(Double(1.5)), got {other:?}"),
    }
    assert!(warnings.is_empty());
  }

  #[test]
  fn read_value_truncated_double_emits_warning() {
    // F2 regression: 4 bytes (not 8) ⇒ Truncated AMF record 0x0.
    let bytes = [0u8, 0, 0, 0];
    let mut pos = 0;
    let mut warnings = std::vec::Vec::new();
    match read_value(&bytes, &mut pos, 0x00, &mut warnings) {
      ReadResult::Truncated(t) => assert_eq!(t, 0x00),
      other => panic!("expected Truncated(0x00), got {other:?}"),
    }
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].as_str(), "Truncated AMF record 0x0");
  }

  #[test]
  fn read_value_truncated_string_emits_warning() {
    // F2 regression: claim u16=100 but only 3 bytes available.
    let mut bytes = std::vec::Vec::new();
    bytes.extend_from_slice(&100u16.to_be_bytes());
    bytes.extend_from_slice(b"abc");
    let mut pos = 0;
    let mut warnings = std::vec::Vec::new();
    match read_value(&bytes, &mut pos, 0x02, &mut warnings) {
      ReadResult::Truncated(t) => assert_eq!(t, 0x02),
      other => panic!("expected Truncated(0x02), got {other:?}"),
    }
    assert_eq!(warnings[0].as_str(), "Truncated AMF record 0x2");
  }

  #[test]
  fn read_value_truncated_long_string_emits_warning() {
    // F2 regression for type 0x0c (longString).
    let mut bytes = std::vec::Vec::new();
    bytes.extend_from_slice(&1000u32.to_be_bytes());
    bytes.extend_from_slice(b"abc");
    let mut pos = 0;
    let mut warnings = std::vec::Vec::new();
    match read_value(&bytes, &mut pos, 0x0c, &mut warnings) {
      ReadResult::Truncated(t) => assert_eq!(t, 0x0c),
      other => panic!("expected Truncated(0x0c), got {other:?}"),
    }
    assert_eq!(warnings[0].as_str(), "Truncated AMF record 0xc");
  }

  #[test]
  fn read_value_string_applies_fix_utf8_not_lossy() {
    // Codex PR #32 R18/F1 — the AMF string (0x02) arm must decode RAW
    // bytes via `fix_utf8` (XMP::FixUTF8 — invalid byte ⇒ ASCII `?`),
    // NOT `from_utf8_lossy` (which would emit U+FFFD). Bundled oracle on
    // `41 ff 42`: `"A?B"`. Pin BOTH that the result is `A?B` AND that no
    // U+FFFD replacement char leaks in.
    let mut bytes = std::vec::Vec::new();
    bytes.extend_from_slice(&3u16.to_be_bytes());
    bytes.extend_from_slice(&[0x41, 0xff, 0x42]);
    let mut pos = 0;
    let mut warnings = std::vec::Vec::new();
    match read_value(&bytes, &mut pos, 0x02, &mut warnings) {
      ReadResult::Ok(AmfValue::String(s)) => {
        assert_eq!(s, "A?B");
        assert!(!s.contains('\u{FFFD}'), "must not materialize U+FFFD");
      }
      other => panic!("expected Ok(String), got {other:?}"),
    }
    assert!(warnings.is_empty());
  }

  #[test]
  fn read_value_long_string_and_xml_apply_fix_utf8() {
    // Codex PR #32 R18/F1 class-sweep — the long-string (0x0c) and XML
    // (0x0f) arms share Flash.pm:430's raw-byte `substr` + JSON-time
    // FixUTF8. Both must render `41 ff 42` ⇒ `"A?B"`.
    for vtype in [0x0c_u8, 0x0f_u8] {
      let mut bytes = std::vec::Vec::new();
      bytes.extend_from_slice(&3u32.to_be_bytes());
      bytes.extend_from_slice(&[0x41, 0xff, 0x42]);
      let mut pos = 0;
      let mut warnings = std::vec::Vec::new();
      match read_value(&bytes, &mut pos, vtype, &mut warnings) {
        ReadResult::Ok(AmfValue::String(s)) => {
          assert_eq!(s, "A?B", "type 0x{vtype:x}");
          assert!(!s.contains('\u{FFFD}'), "type 0x{vtype:x}: no U+FFFD");
        }
        other => panic!("type 0x{vtype:x}: expected Ok(String), got {other:?}"),
      }
      assert!(warnings.is_empty(), "type 0x{vtype:x}");
    }
  }

  #[test]
  fn read_value_truncated_date_no_warning_emits_bare_double() {
    // Subtle bundled-half-emit case (Flash.pm:309-313): the f64 parses
    // cleanly before the 2-byte tz check fails, so bundled assigns
    // `$val = $val / 1000` BEFORE the `last`. Line 455 then sees
    // `defined $val` ⇒ NO truncation warning. The half-parsed value is
    // emitted as a bare double. Pinned exactly.
    let bytes = 1000.0_f64.to_be_bytes(); // 1000 ms ⇒ 1.0 sec; no tz.
    let mut pos = 0;
    let mut warnings = std::vec::Vec::new();
    match read_value(&bytes, &mut pos, 0x0b, &mut warnings) {
      ReadResult::Ok(AmfValue::Double(d)) => assert!((d - 1.0).abs() < 1e-12),
      other => panic!("expected Ok(Double(1.0)), got {other:?}"),
    }
    assert!(
      warnings.is_empty(),
      "truncated date must NOT emit a warning (bundled $val already set)"
    );
  }

  #[test]
  fn push_truncated_amf_record_format_matches_perl() {
    // Faithfulness of the `sprintf("Truncated AMF record 0x%x", $type)`
    // format (Flash.pm:456) — Perl `%x` emits no leading zeros (so 0x2,
    // not 0x02).
    let mut w = std::vec::Vec::new();
    push_truncated_amf_record(&mut w, 0x02);
    assert_eq!(w[0].as_str(), "Truncated AMF record 0x2");
    let mut w = std::vec::Vec::new();
    push_truncated_amf_record(&mut w, 0x0a);
    assert_eq!(w[0].as_str(), "Truncated AMF record 0xa");
    let mut w = std::vec::Vec::new();
    push_truncated_amf_record(&mut w, 0x10);
    assert_eq!(w[0].as_str(), "Truncated AMF record 0x10");
  }

  // ---------------------------------------------------------------------
  // Codex R2/F3 — `ReadResult::Unsupported(t)` discriminant
  // ---------------------------------------------------------------------

  #[test]
  fn read_value_unsupported_amf3_emits_dedicated_warning() {
    // R2/F3: type 0x11 (AMF3 data) is in Flash.pm's "not supported"
    // bucket (line 434/437). Bundled emits `AMF AMF3data record not yet
    // supported` and `last`s. We now return `ReadResult::Unsupported(t)`
    // so the top-level walker can NOT pop the warning under its
    // "had-a-value" rule.
    let bytes = []; // no payload bytes — type-byte already consumed.
    let mut pos = 0;
    let mut warnings = std::vec::Vec::new();
    match read_value(&bytes, &mut pos, 0x11, &mut warnings) {
      ReadResult::Unsupported(t) => assert_eq!(t, 0x11),
      other => panic!("expected Unsupported(0x11), got {other:?}"),
    }
    assert_eq!(warnings.len(), 1);
    assert_eq!(
      warnings[0].as_str(),
      "AMF AMF3data record not yet supported"
    );
  }

  #[test]
  fn read_value_unsupported_movieclip_emits_dedicated_warning() {
    // Type 0x04 (movieClip) is similarly in the `else` arm of
    // Flash.pm:435-439 — not in any of the explicit branches.
    let bytes = [];
    let mut pos = 0;
    let mut warnings = std::vec::Vec::new();
    match read_value(&bytes, &mut pos, 0x04, &mut warnings) {
      ReadResult::Unsupported(t) => assert_eq!(t, 0x04),
      other => panic!("expected Unsupported(0x04), got {other:?}"),
    }
    assert_eq!(
      warnings[0].as_str(),
      "AMF movieClip record not yet supported"
    );
  }

  #[test]
  fn read_value_unsupported_out_of_range_uses_hex_fallback() {
    // Type 0x99 is out of `AMF_TYPE_NAMES`; falls back to
    // `sprintf("type 0x%x")` (Flash.pm:436).
    let bytes = [];
    let mut pos = 0;
    let mut warnings = std::vec::Vec::new();
    match read_value(&bytes, &mut pos, 0x99, &mut warnings) {
      ReadResult::Unsupported(t) => assert_eq!(t, 0x99),
      other => panic!("expected Unsupported(0x99), got {other:?}"),
    }
    assert_eq!(
      warnings[0].as_str(),
      "AMF type 0x99 record not yet supported"
    );
  }

  // ---------------------------------------------------------------------
  // Codex R2/F2 — nested strict-array cursor consumption
  // ---------------------------------------------------------------------

  #[test]
  fn collect_array_items_handles_nested_strict_array() {
    // Build an AMF strict-array body (NO 0x0a type byte — caller
    // consumed it): count=2; element[0] = nested 0x0a array of two
    // doubles; element[1] = double 99.
    let mut bytes = std::vec::Vec::new();
    bytes.extend_from_slice(&2u32.to_be_bytes()); // outer count
    // Element 0: type 0x0a + nested array
    bytes.push(0x0a);
    bytes.extend_from_slice(&2u32.to_be_bytes()); // inner count
    bytes.push(0x00); // double type
    bytes.extend_from_slice(&1.0_f64.to_be_bytes());
    bytes.push(0x00); // double type
    bytes.extend_from_slice(&2.0_f64.to_be_bytes());
    // Element 1: double 99
    bytes.push(0x00);
    bytes.extend_from_slice(&99.0_f64.to_be_bytes());
    let mut pos = 0;
    let mut entries = std::vec::Vec::new();
    let mut warnings = std::vec::Vec::new();
    let result = collect_array_items(
      0,
      &bytes,
      &mut pos,
      SubTable::Meta,
      Some("outerArr"),
      ArrayValueConv::NEUTRAL,
      &mut entries,
      &mut warnings,
    );
    let items = match result {
      ArrayOutcome::Ok(items) => items,
      other => panic!("collect should succeed; got {other:?}"),
    };
    assert_eq!(items.len(), 2, "outer list has 2 elements");
    match &items[0] {
      FlashListItem::List(inner) => {
        assert_eq!(inner.len(), 2);
        match (&inner[0], &inner[1]) {
          (FlashListItem::Double(a), FlashListItem::Double(b)) => {
            assert!((a - 1.0).abs() < 1e-12);
            assert!((b - 2.0).abs() < 1e-12);
          }
          other => panic!("nested elements not Double: {other:?}"),
        }
      }
      other => panic!("element[0] not a nested List: {other:?}"),
    }
    match &items[1] {
      FlashListItem::Double(d) => assert!((d - 99.0).abs() < 1e-12),
      other => panic!("element[1] not Double(99): {other:?}"),
    }
    assert!(
      warnings.is_empty(),
      "no truncation warnings on a well-formed nested array; got {warnings:?}"
    );
    // Cursor must be at end of buffer.
    assert_eq!(pos, bytes.len(), "cursor must advance through nested array");
  }

  #[test]
  fn collect_array_items_mul_1000_applies_only_to_top_level_scalars() {
    // Codex PR #32 R14/F1 — the owning tag ValueConv (`$val * 1000`,
    // Flash.pm:168/230/237) is a TOP-LEVEL conversion in bundled `GetValue`
    // (ExifTool.pm:3567-3672 iterates `$$vals[$i]`); it must NOT recurse
    // into a nested arrayref element. Build an array whose top-level
    // elements are: scalar `1.5`, a nested array `[1.5, 61]`, scalar `2.5`.
    // With `mul_1000 = true`: the two TOP-LEVEL scalars are multiplied
    // (1500, 2500); the nested array's inner doubles stay raw (1.5, 61).
    let mut bytes = std::vec::Vec::new();
    bytes.extend_from_slice(&3u32.to_be_bytes()); // outer count = 3
    // element[0]: scalar 1.5
    bytes.push(0x00);
    bytes.extend_from_slice(&1.5_f64.to_be_bytes());
    // element[1]: nested array [1.5, 61]
    bytes.push(0x0a);
    bytes.extend_from_slice(&2u32.to_be_bytes());
    bytes.push(0x00);
    bytes.extend_from_slice(&1.5_f64.to_be_bytes());
    bytes.push(0x00);
    bytes.extend_from_slice(&61.0_f64.to_be_bytes());
    // element[2]: scalar 2.5
    bytes.push(0x00);
    bytes.extend_from_slice(&2.5_f64.to_be_bytes());
    let mut pos = 0;
    let mut entries = std::vec::Vec::new();
    let mut warnings = std::vec::Vec::new();
    let result = collect_array_items(
      0,
      &bytes,
      &mut pos,
      SubTable::Meta,
      Some("dataRate"),
      ArrayValueConv {
        mul_1000: true, // *datarate ValueConv ON
        trim_trailing_ws: false,
      },
      &mut entries,
      &mut warnings,
    );
    let items = match result {
      ArrayOutcome::Ok(items) => items,
      other => panic!("collect should succeed; got {other:?}"),
    };
    assert_eq!(items.len(), 3);
    // Top-level scalars multiplied by 1000.
    match &items[0] {
      FlashListItem::Double(d) => assert!((d - 1500.0).abs() < 1e-9, "got {d}"),
      other => panic!("element[0] not Double(1500): {other:?}"),
    }
    match &items[2] {
      FlashListItem::Double(d) => assert!((d - 2500.0).abs() < 1e-9, "got {d}"),
      other => panic!("element[2] not Double(2500): {other:?}"),
    }
    // Nested array inner doubles are NOT multiplied (no recursion of the
    // top-level ValueConv into a nested arrayref — bundled coerces the ref
    // to a non-deterministic memory address instead; the port renders the
    // inner numbers raw rather than fabricate one).
    match &items[1] {
      FlashListItem::List(inner) => {
        assert_eq!(inner.len(), 2);
        match (&inner[0], &inner[1]) {
          (FlashListItem::Double(a), FlashListItem::Double(b)) => {
            assert!(
              (a - 1.5).abs() < 1e-12,
              "inner[0] must stay raw 1.5, got {a}"
            );
            assert!(
              (b - 61.0).abs() < 1e-12,
              "inner[1] must stay raw 61, got {b}"
            );
          }
          other => panic!("nested elements not Double: {other:?}"),
        }
      }
      other => panic!("element[1] not a nested List: {other:?}"),
    }
    assert!(
      warnings.is_empty(),
      "no warnings expected; got {warnings:?}"
    );
    assert_eq!(pos, bytes.len());
  }

  #[test]
  fn collect_array_items_trim_ws_applies_only_to_top_level_strings() {
    // Codex PR #32 R15/F1 — the owning tag string ValueConv
    // (`$val=~s/\s+$//; $val`, Flash.pm:182 for `creationdate`) is a
    // TOP-LEVEL conversion in bundled `GetValue` (ExifTool.pm:3567-3681
    // iterates `$$vals[$i]`); it trims each top-level string element but
    // must NOT recurse into a nested arrayref element. Build an array whose
    // top-level elements are: string "A   ", a nested array ["X   "],
    // string "B\t ". With `trim_trailing_ws = true`: the two TOP-LEVEL
    // strings are trimmed ("A","B"); the nested array's inner string stays
    // raw ("X   ").
    let push_str = |bytes: &mut std::vec::Vec<u8>, s: &str| {
      bytes.push(0x02); // AMF string
      bytes.extend_from_slice(&(s.len() as u16).to_be_bytes());
      bytes.extend_from_slice(s.as_bytes());
    };
    let mut bytes = std::vec::Vec::new();
    bytes.extend_from_slice(&3u32.to_be_bytes()); // outer count = 3
    push_str(&mut bytes, "A   "); // element[0]
    bytes.push(0x0a); // element[1]: nested array ["X   "]
    bytes.extend_from_slice(&1u32.to_be_bytes());
    push_str(&mut bytes, "X   ");
    push_str(&mut bytes, "B\t "); // element[2]
    let mut pos = 0;
    let mut entries = std::vec::Vec::new();
    let mut warnings = std::vec::Vec::new();
    let result = collect_array_items(
      0,
      &bytes,
      &mut pos,
      SubTable::Meta,
      Some("createDate"),
      ArrayValueConv {
        mul_1000: false,
        trim_trailing_ws: true, // creationdate ValueConv ON
      },
      &mut entries,
      &mut warnings,
    );
    let items = match result {
      ArrayOutcome::Ok(items) => items,
      other => panic!("collect should succeed; got {other:?}"),
    };
    assert_eq!(items.len(), 3);
    // Top-level strings trimmed.
    match &items[0] {
      FlashListItem::Str(s) => assert_eq!(s.as_str(), "A", "top-level[0] trimmed"),
      other => panic!("element[0] not Str(\"A\"): {other:?}"),
    }
    match &items[2] {
      FlashListItem::Str(s) => assert_eq!(s.as_str(), "B", "top-level[2] trimmed"),
      other => panic!("element[2] not Str(\"B\"): {other:?}"),
    }
    // Nested array inner string is NOT trimmed (no recursion of the
    // top-level ValueConv into a nested arrayref — bundled coerces the ref
    // to a string/number instead of trimming the inner scalars).
    match &items[1] {
      FlashListItem::List(inner) => {
        assert_eq!(inner.len(), 1);
        match &inner[0] {
          FlashListItem::Str(s) => {
            assert_eq!(s.as_str(), "X   ", "inner string must stay raw");
          }
          other => panic!("nested element not Str: {other:?}"),
        }
      }
      other => panic!("element[1] not a nested List: {other:?}"),
    }
    assert!(
      warnings.is_empty(),
      "no warnings expected; got {warnings:?}"
    );
    assert_eq!(pos, bytes.len());
  }

  #[test]
  fn collect_array_items_mul_1000_numifies_top_level_string_elements() {
    // Codex PR #32 R19/F1 — the owning tag's `$val * 1000` ValueConv
    // (Flash.pm:168/230/237) coerces a STRING element to a number via Perl
    // arithmetic BEFORE the multiply, exactly like the scalar case. Build an
    // array of two top-level string elements ("65.8", "abc") plus a nested
    // array ["77.7"]. With `mul_1000 = true`: "65.8"→65800, "abc"→0 (no
    // numeric prefix), and the nested-array string stays RAW (no recursion).
    let push_str = |bytes: &mut std::vec::Vec<u8>, s: &str| {
      bytes.push(0x02);
      bytes.extend_from_slice(&(s.len() as u16).to_be_bytes());
      bytes.extend_from_slice(s.as_bytes());
    };
    let mut bytes = std::vec::Vec::new();
    bytes.extend_from_slice(&3u32.to_be_bytes()); // outer count = 3
    push_str(&mut bytes, "65.8"); // element[0]
    bytes.push(0x0a); // element[1]: nested array ["77.7"]
    bytes.extend_from_slice(&1u32.to_be_bytes());
    push_str(&mut bytes, "77.7");
    push_str(&mut bytes, "abc"); // element[2]
    let mut pos = 0;
    let mut entries = std::vec::Vec::new();
    let mut warnings = std::vec::Vec::new();
    let result = collect_array_items(
      0,
      &bytes,
      &mut pos,
      SubTable::Meta,
      Some("dataRate"),
      ArrayValueConv {
        mul_1000: true,
        trim_trailing_ws: false,
      },
      &mut entries,
      &mut warnings,
    );
    let items = match result {
      ArrayOutcome::Ok(items) => items,
      other => panic!("collect should succeed; got {other:?}"),
    };
    assert_eq!(items.len(), 3);
    match &items[0] {
      FlashListItem::Double(d) => assert!((d - 65800.0).abs() < 1e-9, "got {d}"),
      other => panic!("element[0] not Double(65800): {other:?}"),
    }
    match &items[2] {
      // "abc" has no numeric prefix ⇒ 0 * 1000 = 0.
      FlashListItem::Double(d) => assert!(d.abs() < 1e-9, "non-numeric ⇒ 0, got {d}"),
      other => panic!("element[2] not Double(0): {other:?}"),
    }
    // Nested-array string stays RAW (no top-level ValueConv recursion).
    match &items[1] {
      FlashListItem::List(inner) => match &inner[0] {
        FlashListItem::Str(s) => assert_eq!(s.as_str(), "77.7", "inner string raw"),
        other => panic!("nested element not Str: {other:?}"),
      },
      other => panic!("element[1] not a nested List: {other:?}"),
    }
    assert!(warnings.is_empty(), "no warnings; got {warnings:?}");
    assert_eq!(pos, bytes.len());
  }

  #[test]
  fn flash_list_item_with_pc_applies_string_print_conv_per_element() {
    use crate::value::TagValue;
    // Codex PR #32 R19/F1 — a STRING list element of a no-ValueConv tag with
    // a PrintConv gets the per-element PrintConv at `-j` (ConvertDuration is
    // IsFloat-guarded; RoundMilli coerces raw), and the raw string at `-n`.
    // ConvertDuration, -j: float-shaped formats, non-float stays verbatim.
    let s_num = FlashListItem::Str(SmolStr::new_static("1.5"));
    let s_txt = FlashListItem::Str(SmolStr::new_static("notnum"));
    assert_eq!(
      flash_list_item_with_pc(&s_num, PrintConvMode::ConvertDuration, true),
      TagValue::Str(SmolStr::new_static("1.50 s"))
    );
    assert_eq!(
      flash_list_item_with_pc(&s_txt, PrintConvMode::ConvertDuration, true),
      TagValue::Str(SmolStr::new_static("notnum"))
    );
    // ConvertDuration, -n: raw string regardless.
    assert_eq!(
      flash_list_item_with_pc(&s_num, PrintConvMode::ConvertDuration, false),
      TagValue::Str(SmolStr::new_static("1.5"))
    );
    // RoundMilli, -j: raw arithmetic coercion (non-numeric ⇒ 0); folds to int.
    assert_eq!(
      flash_list_item_with_pc(&s_txt, PrintConvMode::RoundMilli, true),
      TagValue::I64(0)
    );
    assert_eq!(
      flash_list_item_with_pc(
        &FlashListItem::Str(SmolStr::new_static("29.97")),
        PrintConvMode::RoundMilli,
        true
      ),
      TagValue::F64(29.97)
    );
    // None: raw string in both modes.
    assert_eq!(
      flash_list_item_with_pc(&s_num, PrintConvMode::None, true),
      TagValue::Str(SmolStr::new_static("1.5"))
    );
  }

  #[test]
  fn collect_array_items_truncated_nested_array_signals_both_warnings() {
    // Codex R2/F2 — a nested array whose count overruns the buffer must
    // emit `Truncated AMF record 0xa` per OUTER frame (one warning from
    // the inner abort + one from this walker, mirroring bundled's
    // per-frame `$type=0xa, $val=undef`).
    let mut bytes = std::vec::Vec::new();
    bytes.extend_from_slice(&1u32.to_be_bytes()); // outer count=1
    bytes.push(0x0a); // nested array marker
    bytes.extend_from_slice(&5u32.to_be_bytes()); // inner count=5 (too many)
    bytes.push(0x00); // 1 partial element (one byte of u64)
    // (no remaining bytes for the rest)
    let mut pos = 0;
    let mut entries = std::vec::Vec::new();
    let mut warnings = std::vec::Vec::new();
    let result = collect_array_items(
      0,
      &bytes,
      &mut pos,
      SubTable::Meta,
      Some("outer"),
      ArrayValueConv::NEUTRAL,
      &mut entries,
      &mut warnings,
    );
    // Codex R9/F1 — the inner element-failure path pushes its own frame
    // warning and returns Abort; the outer recursion site then pushes
    // for THIS frame (the empty `\@vals` never reaches the assignment)
    // and returns Abort. Net: at minimum we expect the outer 0xa
    // warning + a leaf warning; ordering matches bundled chain.
    assert!(
      matches!(result, ArrayOutcome::Abort),
      "expected Abort on nested truncation; got {result:?}"
    );
    assert!(
      warnings
        .iter()
        .any(|w| w.as_str() == "Truncated AMF record 0xa"),
      "expected at least one 'Truncated AMF record 0xa'; got {warnings:?}"
    );
  }

  // ---------------------------------------------------------------------
  // Codex R9/F1 — `ArrayOutcome::TruncatedCount` discriminant unit test
  // ---------------------------------------------------------------------

  #[test]
  fn collect_array_items_truncated_count_returns_truncated_count_no_warning() {
    // Codex R9/F1 — when the helper enters with fewer than 4 bytes
    // available for the u32 count, bundled Flash.pm:411 fires `last if
    // $pos + 4 > $dirLen` WITHOUT pushing any warning at this point.
    // The helper returns `ArrayOutcome::TruncatedCount` and the caller
    // decides whether to emit (keyed-value caller ALWAYS emits because
    // the recursive ProcessMeta has fresh $val=undef; top-level caller
    // gates on `top_val_seen`).
    let bytes: [u8; 2] = [0x00, 0x01]; // only 2 bytes — count read needs 4
    let mut pos = 0;
    let mut entries = std::vec::Vec::new();
    let mut warnings = std::vec::Vec::new();
    let result = collect_array_items(
      0,
      &bytes,
      &mut pos,
      SubTable::Meta,
      Some("test"),
      ArrayValueConv::NEUTRAL,
      &mut entries,
      &mut warnings,
    );
    assert!(
      matches!(result, ArrayOutcome::TruncatedCount),
      "expected TruncatedCount; got {result:?}"
    );
    assert!(
      warnings.is_empty(),
      "TruncatedCount must NOT push warnings; caller decides; got {warnings:?}"
    );
    // Cursor must NOT advance — bundled `last if $pos + 4 > $dirLen`
    // does not consume the bytes.
    assert_eq!(pos, 0, "cursor must NOT advance on TruncatedCount");
  }

  // ---------------------------------------------------------------------
  // Codex R9/F2 — `consume_struct_intro` typed-object name-payload
  // overrun pushes `"Truncated typedObject record"`.
  // ---------------------------------------------------------------------

  #[test]
  fn consume_struct_intro_typed_object_name_payload_overrun_emits_warning() {
    // Codex R9/F2 — bundled Flash.pm:352-354 emits `et->Warn("Truncated
    // typedObject record")` when the declared name length overruns
    // the buffer. Pre-R9 `skip_struct_intro` silently returned false,
    // dropping the warning. Verify the new `consume_struct_intro`
    // pushes the exact bundled text. Codex PR #32 R10 — outcome now
    // carries `IntroTruncReason::TypedObjectName` to disambiguate
    // from silent paths (see `IntroOutcome` doc-comment).
    let bytes: [u8; 2] = [0x00, 0x05]; // claim 5-byte name, no payload
    let mut pos = 0;
    let mut warnings = std::vec::Vec::new();
    let outcome = consume_struct_intro(&bytes, &mut pos, 0x10, &mut warnings);
    assert_eq!(
      outcome,
      IntroOutcome::Truncated(IntroTruncReason::TypedObjectName)
    );
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].as_str(), "Truncated typedObject record");
    // Cursor must NOT advance — bundled `last Record` at line 354
    // does not consume the bytes.
    assert_eq!(pos, 0);
  }

  #[test]
  fn consume_struct_intro_typed_object_len_truncation_no_warning() {
    // Bundled Flash.pm:350 `last Record if $pos + 2 > $dirLen` — fires
    // WITHOUT a warning ($val='' from line 340 keeps line 455 silent).
    // Codex PR #32 R10 — `IntroTruncReason::NameLength` flags the
    // silent path so the strict-array caller skips its own frame
    // warning.
    let bytes: [u8; 1] = [0x00]; // not enough for the u16 length
    let mut pos = 0;
    let mut warnings = std::vec::Vec::new();
    let outcome = consume_struct_intro(&bytes, &mut pos, 0x10, &mut warnings);
    assert_eq!(
      outcome,
      IntroOutcome::Truncated(IntroTruncReason::NameLength)
    );
    assert!(
      warnings.is_empty(),
      "name-length truncation must NOT push a warning; got {warnings:?}"
    );
    assert_eq!(pos, 0);
  }

  #[test]
  fn consume_struct_intro_mixed_array_top_index_no_warning() {
    // Bundled Flash.pm:343 `last if $pos + 4 > $dirLen` — fires
    // WITHOUT a warning. Codex PR #32 R10 — `IntroTruncReason::TopIndex`
    // flags the silent path.
    let bytes: [u8; 3] = [0x00, 0x00, 0x00]; // not enough for the u32
    let mut pos = 0;
    let mut warnings = std::vec::Vec::new();
    let outcome = consume_struct_intro(&bytes, &mut pos, 0x08, &mut warnings);
    assert_eq!(outcome, IntroOutcome::Truncated(IntroTruncReason::TopIndex));
    assert!(warnings.is_empty());
    assert_eq!(pos, 0);
  }

  #[test]
  fn consume_struct_intro_object_passes_through() {
    // 0x03 (object) has NO introducer to consume.
    let bytes: [u8; 0] = [];
    let mut pos = 0;
    let mut warnings = std::vec::Vec::new();
    let outcome = consume_struct_intro(&bytes, &mut pos, 0x03, &mut warnings);
    assert_eq!(outcome, IntroOutcome::Ok);
    assert!(warnings.is_empty());
    assert_eq!(pos, 0);
  }

  /// Drive the `Meta` through the production sink path that replaced the
  /// retired `serialize_tags`: the golden-pattern engine
  /// ([`run_emission`](crate::emit::run_emission)) for the tag stream, then —
  /// exactly like the `format_parser::AnyMeta::Flv` arm — drain
  /// [`Meta::warnings`] into the [`TagMap`](crate::tagmap::TagMap).
  #[cfg(feature = "alloc")]
  fn emit_into_tagmap(meta: &Meta<'_>, print_conv: bool) -> crate::tagmap::TagMap {
    let mut w = crate::tagmap::TagMap::new();
    crate::emit::run_emission(
      meta,
      crate::emit::EmitOptions::g1(crate::emit::ConvMode::from_print_conv(print_conv), false),
      &mut w,
    );
    for warn in meta.warnings() {
      let _ = w.write_warning(warn.as_str());
    }
    w
  }

  #[test]
  fn taggable_emits_typed_tags() {
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/Flash.flv"
    ))
    .expect("read Flash.flv fixture");
    let meta = parse_borrowed(&bytes).expect("FLV accepted");
    // -j: PrintConv strings + the per-tag conversions.
    let tm = emit_into_tagmap(&meta, true);
    assert_eq!(tm.get_str("Flash", "AudioEncoding"), Some("MP3".into()));
    assert_eq!(
      tm.get_str("Flash", "AudioChannels"),
      Some("1 (mono)".into())
    );
    assert_eq!(tm.get_str("Flash", "Duration"), Some("3.09 s".into()));
    assert_eq!(tm.get_str("Flash", "VideoBitrate"), Some("419 kbps".into()));
    assert_eq!(tm.get_str("Flash", "HasVideo"), Some("Yes".into()));
    // -n: AudioEncoding PrintConv off ⇒ the raw numeric code (MP3 ⇒ 2).
    let tm = emit_into_tagmap(&meta, false);
    assert_eq!(tm.get_str("Flash", "AudioEncoding"), Some("2".into()));
    assert_eq!(tm.get_str("Flash", "ImageWidth"), Some("320".into()));
  }

  #[test]
  fn taggable_group_is_flash_family0_and_family1() {
    use crate::emit::{ConvMode, Taggable};
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/Flash.flv"
    ))
    .expect("read Flash.flv fixture");
    let meta = parse_borrowed(&bytes).expect("accepted");
    let tags: Vec<_> = meta
      .tags(crate::emit::EmitOptions::g1(ConvMode::PrintConv, false))
      .collect();
    assert!(!tags.is_empty(), "the onMetaData packet must yield tags");
    for t in &tags {
      // family0 = "Flash" (table group); family1 = "Flash" (constant -G1 key).
      assert_eq!(t.tag().group_ref().family0(), "Flash");
      assert_eq!(t.tag().group_ref().family1(), "Flash");
      assert!(!t.unknown(), "Flash has no Unknown=>1 tags");
    }
  }

  #[test]
  fn project_populates_video_track() {
    use crate::metadata::{Project, TrackKind};
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/Flash.flv"
    ))
    .expect("read Flash.flv fixture");
    let meta = parse_borrowed(&bytes).expect("accepted");
    let projected = meta.project();
    // FLV projects to a video container; the rest of MediaInfo is empty.
    assert_eq!(projected.media().track_kinds(), &[TrackKind::Video]);
    assert!(projected.media().has_video());
    assert!(projected.media().duration().is_none());
    assert!(projected.media().width().is_none());
    assert!(projected.media().created().is_none());
    // FLV carries no camera / lens / GPS / capture facts here.
    assert!(projected.camera().is_none());
    assert!(projected.lens().is_none());
    assert!(projected.gps().is_none());
    assert!(projected.capture().is_none());
  }

  #[test]
  fn deeply_nested_amf_arrays_do_not_overflow_the_stack() {
    // Golden-v2 Contract 3a — a hostile FLV can nest AMF strict-arrays
    // arbitrarily deep, recursing `collect_array_items` until the stack
    // overflows (a DoS). With `MAX_AMF_DEPTH` the walk stops at the cap and
    // returns. 100_000 is a superset of any real `onMetaData` nesting
    // (single-digit), so the cap never trips on a real file (byte-identical
    // output). Mirrors the well-formed `collect_array_items_handles_nested_
    // strict_array` fixture, just nested far past the budget.
    const N: usize = 100_000;
    // Body for `collect_array_items` (the leading 0x0a marker already
    // consumed by the caller): N nested strict-arrays, each `count=1` + a
    // `0x0a` element marker, innermost `count=0`.
    let mut bytes = std::vec::Vec::new();
    for _ in 0..N {
      bytes.extend_from_slice(&1u32.to_be_bytes()); // count = 1
      bytes.push(0x0a); // element[0] is a nested strict-array
    }
    bytes.extend_from_slice(&0u32.to_be_bytes()); // innermost count = 0
    let mut pos = 0;
    let mut entries = std::vec::Vec::new();
    let mut warnings = std::vec::Vec::new();
    // The depth budget bounds the recursion; this returns without overflowing.
    let _ = collect_array_items(
      0,
      &bytes,
      &mut pos,
      SubTable::Meta,
      Some("a"),
      ArrayValueConv::NEUTRAL,
      &mut entries,
      &mut warnings,
    );
  }
}
