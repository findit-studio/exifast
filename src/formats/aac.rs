// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "aac")]
//! Faithful port of `Image::ExifTool::AAC` (lib/Image/ExifTool/AAC.pm).
//! PROCESS_PROC is `FLAC::ProcessBitStream` (AAC.pm:29) → [`crate::bitstream`].
//!
//! A typed [`Meta<'a>`] is produced by the
//! [`crate::format_parser::FormatParser`] trait; it implements
//! [`crate::emit::Taggable`] (the golden-pattern emission path) so
//! [`crate::emit::run_emission`] drives its tags into the engine
//! `tagmap::TagMap`, keeping the serialized JSON byte-exact with bundled
//! `perl exiftool`. It also implements [`crate::metadata::Project`] for the
//! normalized cross-format domain layer.

// Golden-v2 Contract 3c (Phase C, slice w2a): panic-safety by construction —
// every raw index/slice is converted to a checked `.get()` form below.
#![deny(clippy::indexing_slicing)]

use crate::{
  bitstream::{BitOrder, process_bit_stream},
  format_parser::{FormatParser, parser_sealed},
  tagtable::{PrintConv, PrintConvHash, PrintValue, TagDef, TagId, TagTable, ValueConv},
  value::{Metadata, TagValue},
};

/// The xtask-GENERATED `%AAC::Main` table (`cargo xtask gen-tables --kind
/// tagdef --module AAC::Main`), transcribed from `exiftool -listx`. Consulted
/// by [`aac_get`] ONLY as the ADDITIVE fallback — the hand-written `static`s
/// below shadow every key they define (hand wins on collision). This is
/// load-bearing for `SampleRate`: `-listx` carries no `<values>` for a
/// code-valued *ValueConv*, so the generated twin has `ValueConv::None` and
/// would DROP the `%convSampleRate` index→Hz map; the hand `SAMPLE_RATE` (with
/// its `ValueConv::Hash`) wins, so output is byte-identical. The generated
/// table contributes 0 new tags and exists as the drift guard
/// (`tests/xtask_check.rs`) against a future ExifTool-version change.
#[path = "aac_generated.rs"]
mod generated;

/// `%convSampleRate` (AAC.pm:18-26) as a hash ValueConv (string keys —
/// ExifTool indexes the conv hash with the stringified `$val`).
const CONV_SAMPLE_RATE: &[(&str, PrintValue)] = &[
  ("0", PrintValue::I64(96000)),
  ("1", PrintValue::I64(88200)),
  ("2", PrintValue::I64(64000)),
  ("3", PrintValue::I64(48000)),
  ("4", PrintValue::I64(44100)),
  ("5", PrintValue::I64(32000)),
  ("6", PrintValue::I64(24000)),
  ("7", PrintValue::I64(22050)),
  ("8", PrintValue::I64(16000)),
  ("9", PrintValue::I64(12000)),
  ("10", PrintValue::I64(11025)),
  ("11", PrintValue::I64(8000)),
  ("12", PrintValue::I64(7350)),
];

// AAC.pm:38-42
static PROFILE_TYPE: TagDef = TagDef::new(
  "ProfileType",
  "AAC",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::Str("Main")),
    ("1", PrintValue::Str("Low Complexity")),
    ("2", PrintValue::Str("Scalable Sampling Rate")),
  ])),
);
// AAC.pm:46
static SAMPLE_RATE: TagDef = TagDef::new(
  "SampleRate",
  "AAC",
  ValueConv::Hash(PrintConvHash::direct(CONV_SAMPLE_RATE)),
  PrintConv::None,
);
// AAC.pm:51-60
static CHANNELS: TagDef = TagDef::new(
  "Channels",
  "AAC",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::Str("?")),
    ("1", PrintValue::I64(1)),
    ("2", PrintValue::I64(2)),
    ("3", PrintValue::I64(3)),
    ("4", PrintValue::I64(4)),
    ("5", PrintValue::I64(5)),
    ("6", PrintValue::Str("5+1")),
    ("7", PrintValue::Str("7+1")),
  ])),
);
// AAC.pm:71-74
static ENCODER: TagDef = TagDef::new("Encoder", "AAC", ValueConv::None, PrintConv::None);

fn aac_get(id: TagId) -> Option<&'static TagDef> {
  // Hand-first (the additive-codegen invariant, mirroring XMP `lookup_field`):
  // the hand `static`s WIN on every key they define. Critically `SAMPLE_RATE`
  // carries a `ValueConv::Hash` (`%convSampleRate`) that `-listx` cannot
  // express, so the hand entry must shadow its `ValueConv::None` generated twin
  // — guaranteeing no byte change. The generated layer is complete for the 4
  // `%AAC::Main` ids, so [`generated::get`] never fires; it is the drift guard.
  let hand = match id {
    TagId::Str("Bit016-017") => Some(&PROFILE_TYPE),
    TagId::Str("Bit018-021") => Some(&SAMPLE_RATE),
    TagId::Str("Bit023-025") => Some(&CHANNELS),
    TagId::Str("Encoder") => Some(&ENCODER),
    _ => None,
  };
  hand.or_else(|| generated::get(id))
}

/// `%AAC::Main` (AAC.pm:28). family-0 group "AAC"; family-1 "AAC" (`-G1` ⇒
/// `AAC:`); family-2 'Audio' (AAC.pm:30) is not emitted under `-G1`.
pub static AAC_MAIN: TagTable = TagTable::new("AAC", aac_get);

// TEMPLATE: keep AAC_BIT_KEYS in sync with aac_get's `Bit*` arms AND in
// ascending zero-padded bit-offset order — `bitstream::process_bit_stream`'s
// `i2 >= dirLen` early-exit silently skips later fields if mis-ordered.
/// Sorted `Bit<a>-<b>` keys of `%AAC::Main` (ExifTool `sort keys`,
/// FLAC.pm:172) in ASCENDING bit-offset order (required by
/// `bitstream::process_bit_stream`). `Encoder` is not a bit field (set via
/// HandleTag in ProcessAAC), so it is excluded here.
pub const AAC_BIT_KEYS: &[&str] = &["Bit016-017", "Bit018-021", "Bit023-025"];

// ===========================================================================
// Typed Meta — `Meta<'a>`
// ===========================================================================

/// Typed AAC metadata — the lib-first output of [`ProcessAac`].
///
/// Holds the **post-ValueConv** raw scalars (PrintConv is applied at emit
/// time by `serialize_tags`, mirroring ExifTool's
/// `$$self{OPTIONS}{PrintConv}` toggle). The bit-stream walker
/// ([`process_bit_stream`]) extracts `ProfileType` (raw), `SampleRate`
/// (post-hash-ValueConv u32), and `Channels` (raw); `Encoder` is the
/// ASCII string from the filler payload of the first AAC frame
/// (AAC.pm:130-133).
///
/// **D8 — no public fields, accessors only.**
///
/// **Lifetimes.** `Meta` borrows the Encoder string from the input
/// buffer (`encoder: Option<&'a str>`); other fields are owned primitives.
#[derive(Debug, Clone)]
pub struct Meta<'a> {
  /// ProfileType (raw 2-bit field at bits 16-17). PrintConv at emit time:
  /// 0→"Main", 1→"Low Complexity", 2→"Scalable Sampling Rate"; 3 is
  /// rejected upstream by [`ProcessAac::parse`]. Always present after the
  /// header gate.
  profile_type: u8,
  /// SampleRate in Hz (post-hash-ValueConv from the 4-bit index at bits
  /// 18-21). The ValueConv hash (`%convSampleRate`, AAC.pm:18-26) maps
  /// index ⇒ Hz; the index is constrained to 0..=12 upstream by
  /// [`ProcessAac::parse`].
  sample_rate: u32,
  /// Channels (raw 3-bit field at bits 23-25). PrintConv at emit time
  /// per `%AAC::Main{Channels}` (AAC.pm:51-60).
  channels: u8,
  /// Encoder string (ASCII, length ≥ 1) extracted from the filler payload
  /// of the first AAC frame (AAC.pm:112-137). Borrowed from the input
  /// buffer. `None` if there is no filler payload or if it doesn't match
  /// the printable-ASCII regex (AAC.pm:133 `/^[\x20-\x7e]+$/`).
  encoder: Option<&'a str>,
}

impl<'a> Meta<'a> {
  /// ProfileType raw value (0..=2).
  #[must_use]
  #[inline(always)]
  pub const fn profile_type(&self) -> u8 {
    self.profile_type
  }

  /// ProfileType PrintConv name (`%AAC::Main{ProfileType}`).
  #[must_use]
  #[inline(always)]
  pub const fn profile_type_name(&self) -> &'static str {
    match self.profile_type {
      0 => "Main",
      1 => "Low Complexity",
      2 => "Scalable Sampling Rate",
      _ => "Unknown", // unreachable: gated by `(t0 >> 16) & 0x03 != 3` (AAC.pm:102)
    }
  }

  /// SampleRate in Hz (e.g. 44100). Post-ValueConv (`%convSampleRate`).
  #[must_use]
  #[inline(always)]
  pub const fn sample_rate(&self) -> u32 {
    self.sample_rate
  }

  /// Channels raw value (0..=7).
  #[must_use]
  #[inline(always)]
  pub const fn channels(&self) -> u8 {
    self.channels
  }

  /// Encoder string borrowed from the input buffer, if present.
  #[must_use]
  #[inline(always)]
  pub const fn encoder(&self) -> Option<&'a str> {
    self.encoder
  }
}

// ===========================================================================
// `ProcessAac` — the lib-first parser
// ===========================================================================

/// AAC parser (faithful `ProcessAAC`, AAC.pm:81-140).
#[derive(Debug, Clone, Copy)]
pub struct ProcessAac;

impl parser_sealed::Sealed for ProcessAac {}

impl FormatParser for ProcessAac {
  type Meta<'a> = Meta<'a>;
  type Context<'a> = &'a [u8];

  fn parse<'a>(&self, data: Self::Context<'a>) -> Option<Self::Meta<'a>> {
    parse_inner(data)
  }
}

/// Lib-first direct entry. Same as [`FormatParser::parse`] but returns an
/// [`Meta`] that borrows from the input buffer (Encoder field).
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today; reserved for
/// future I/O wrappers).
pub fn parse_borrowed(data: &[u8]) -> Option<Meta<'_>> {
  parse_inner(data)
}

/// Inner parser — produces a borrow-from-input [`Meta`]. The
/// [`FormatParser::Meta`] GAT (`type Meta<'a> = Meta<'a>`) returns this
/// borrowed form directly into the closed [`crate::format_parser::AnyMeta`]
/// enum — no `'static` upgrade (Codex AF2).
fn parse_inner(data: &[u8]) -> Option<Meta<'_>> {
  // AAC.pm:99-105 header validation. A reject here returns `Ok(None)` —
  // Perl `return 0` BEFORE `$et->SetFileType()` (AAC.pm:107).
  if data.len() < 7 {
    return None; // $raf->Read($buff,7)==7 or return 0  (AAC.pm:99)
  }
  // The `data.len() < 7` guard above proves the 7-byte prefix exists, so the
  // `get(..7)? + try_into` always succeeds (byte-identical); the fixed-size
  // `[u8; 7]` makes the constant indexing below in-bounds by construction.
  let buff: [u8; 7] = data.get(..7)?.try_into().ok()?;
  if buff[0] != 0xff || (buff[1] != 0xf0 && buff[1] != 0xf1) {
    return None; // unless $buff =~ /^\xff[\xf0\xf1]/  (AAC.pm:100)
  }
  // my @t = unpack('NnC', $buff)  (AAC.pm:101)
  let t0 = u32::from_be_bytes([buff[0], buff[1], buff[2], buff[3]]); // $t[0] = 'N'
  let t1 = u16::from_be_bytes([buff[4], buff[5]]); // $t[1] = 'n'
  let t2 = buff[6]; // $t[2] = 'C'

  // Faithful 1:1 of AAC.pm:102-103. The shift offsets (>>16, >>12) are
  // ExifTool's own — they intentionally differ from the %AAC::Main bit
  // table's Bit016-017 / Bit018-021 extraction. Do NOT "correct" them.
  if (t0 >> 16) & 0x03 == 3 {
    return None; // AAC.pm:102 (reserved profile type)
  }
  if (t0 >> 12) & 0x0f > 12 {
    return None; // AAC.pm:103 (validate sampling frequency index)
  }
  // my $len = (($t[0] << 11) & 0x1800) | (($t[1] >> 5) & 0x07ff)  (AAC.pm:104)
  let len = (((t0 << 11) & 0x1800) | ((t1 as u32 >> 5) & 0x07ff)) as usize;
  if len < 7 {
    return None; // AAC.pm:105
  }

  // Bit-stream walk to extract ProfileType / SampleRate / Channels via
  // process_bit_stream into a side Metadata. The bit-stream walker is the
  // shared engine path used by AAC + FLAC StreamInfo + WavPack + MPC;
  // running it here is the simplest faithful path. We then transpose the
  // emitted (name, TagValue) triples into typed scalars on Meta.
  let mut staging = Metadata::new("aac-staging");
  // print_conv_enabled=false: we want the post-ValueConv raw scalars —
  // PrintConv is applied at sink time per Meta's design.
  process_bit_stream(
    &buff,
    BitOrder::Mm,
    AAC_BIT_KEYS,
    &AAC_MAIN,
    &mut staging,
    false,
  );

  // Lift from the staging Metadata into typed Meta fields. The bit-stream
  // walker always emits I64 for these short (≤2-byte) fields.
  let mut profile_type: u8 = 0;
  let mut sample_rate: u32 = 0;
  let mut channels: u8 = 0;
  for tag in staging.tags_slice() {
    match tag.name() {
      "ProfileType" => {
        if let TagValue::I64(n) = tag.value_ref() {
          profile_type = (*n as u64) as u8;
        }
      }
      "SampleRate" => {
        if let TagValue::I64(n) = tag.value_ref() {
          sample_rate = (*n as u64) as u32;
        }
      }
      "Channels" => {
        if let TagValue::I64(n) = tag.value_ref() {
          channels = (*n as u64) as u8;
        }
      }
      // `process_bit_stream` only ever pushes the `def.name()` of an
      // `AAC_BIT_KEYS` entry resolved through `aac_get` (a closed set:
      // ProfileType/SampleRate/Channels). Any other name means the keys,
      // the table, and this lift loop have drifted — a programming bug.
      // Debug-only signal; release behavior unchanged (silent no-op).
      other => debug_assert!(false, "aac lift: unknown staged tag {other:?}"),
    }
  }

  // Read the first frame data to check for a filler with the encoder name
  // (AAC.pm:112-137). The Perl `while` runs at most once: the body ends
  // with an unconditional `last` (AAC.pm:136).
  let encoder: Option<&str> = encoder_from_filler(data, t0, t2, len);

  Some(Meta {
    profile_type,
    sample_rate,
    channels,
    encoder,
  })
}

/// Extract the Encoder string from the first AAC frame's filler payload
/// (AAC.pm:112-137). Returns a slice borrowed from `data` (zero-alloc)
/// or `None` if there is no filler payload OR if it doesn't match the
/// printable-ASCII regex (AAC.pm:133 `/^[\x20-\x7e]+$/`).
fn encoder_from_filler(data: &[u8], t0: u32, t2: u8, len: usize) -> Option<&str> {
  // while ($len > 8 and $raf->Read($buff,$len-7) == $len-7)  (AAC.pm:113)
  if len <= 8 || data.len() < 7 + (len - 7) {
    return None;
  }
  // The `data.len() < 7 + (len - 7)` guard above proves this range exists.
  let frame = data.get(7..7 + (len - 7))?; // $buff (re-read), length == $len-7
  let no_crc = (t0 & 0x0001_0000) != 0; // my $noCRC = ($t[0] & 0x00010000)  (AAC.pm:114)
  let blocks = (t2 & 0x03) as usize; // my $blocks = ($t[2] & 0x03)  (AAC.pm:115)
  let mut pos = 0usize; // my $pos = 0  (AAC.pm:116)
  if !no_crc {
    pos += 2 + 2 * blocks; // $pos += 2 + 2 * $blocks unless $noCRC  (AAC.pm:117)
  }
  if pos + 2 > frame.len() {
    return None; // last if $pos + 2 > length($buff)  (AAC.pm:118)
  }
  // The `pos + 2 > frame.len()` guard above proves these two bytes exist.
  let tmp = u16::from_be_bytes(frame.get(pos..pos + 2)?.try_into().ok()?); // unpack "x${pos}n" (AAC.pm:119)
  let id = tmp >> 13; // my $id = $tmp >> 13  (AAC.pm:120)
  if id != 6 {
    return None; // AAC.pm:122 — not a filler element
  }
  let mut cnt = ((tmp >> 9) & 0x0f) as usize; // my $cnt = ($tmp >> 9) & 0x0f  (AAC.pm:123)
  pos += 1; // ++$pos  (AAC.pm:124)
  if cnt == 15 {
    // AAC.pm:125-127. The Perl arithmetic `$cnt += (($tmp>>1)&0xff) - 1`
    // is signed; reorder for usize safety. cnt==15 here, so `cnt - 1 == 14`
    // cannot underflow; identical to Perl's value.
    debug_assert_eq!(cnt, 15);
    cnt = cnt - 1 + (((tmp >> 1) & 0xff) as usize);
    pos += 1; // ++$pos  (AAC.pm:127)
  }
  if pos + cnt > frame.len() {
    return None; // AAC.pm:129 condition false
  }
  // The `pos + cnt > frame.len()` guard above proves this range exists.
  let dat = frame.get(pos..pos + cnt)?; // my $dat = substr($buff,$pos,$cnt)  (AAC.pm:130)
  // $dat =~ s/^\0+// ; $dat =~ s/\0+$//  (AAC.pm:131-132)
  let s = dat.iter().position(|&b| b != 0).unwrap_or(dat.len());
  let e = dat.iter().rposition(|&b| b != 0).map_or(s, |i| i + 1);
  // `s <= e <= dat.len()` by construction (position/rposition bounds), so
  // this sub-slice always exists (byte-identical to the raw `dat[s..e]`).
  let trimmed = dat.get(s..e)?;
  if trimmed.is_empty() {
    return None;
  }
  // HandleTag(Encoder=>$dat) if $dat =~ /^[\x20-\x7e]+$/  (AAC.pm:133)
  if !trimmed.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
    return None;
  }
  // `trimmed` is printable ASCII ⇒ valid UTF-8. The slice borrows the
  // staging frame's bytes, which are themselves borrowed from `data` —
  // the borrow propagates through the slice chain. Compute the absolute
  // offset into `data` so the returned `&str` carries the right lifetime.
  let frame_start = 7;
  let frame_offset = trimmed.as_ptr() as usize - frame.as_ptr() as usize;
  let abs_start = frame_start + frame_offset;
  let abs_end = abs_start + trimmed.len();
  // `abs_start..abs_end` indexes the same bytes as `trimmed` (a sub-slice of
  // `data`), so the range is in-bounds by construction (byte-identical).
  core::str::from_utf8(data.get(abs_start..abs_end)?).ok()
}

// ===========================================================================
// `Taggable` — the golden-pattern emission path
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::emit::Taggable for Meta<'_> {
  /// Yield AAC tags in `%AAC::Main` walk order (ProfileType, SampleRate,
  /// Channels, then Encoder) — faithful to AAC.pm:38-74 + the bit-stream
  /// walker. The golden-pattern parallel to the retired `serialize_tags`:
  /// the SINK changes (an [`EmittedTag`](crate::emit::EmittedTag) per value
  /// instead of `out.write_*`), the per-tag PrintConv/ValueConv branches are
  /// preserved verbatim.
  ///
  /// `mode == PrintConv` (`-j`) ⇒ PrintConv formatted values;
  /// `mode == ValueConv` (`-n`) ⇒ post-ValueConv raw scalars.
  ///
  /// Group: `family0` = `"AAC"` (the `%AAC::Main` table group — AAC.pm:28
  /// sets only `GROUPS{2} => 'Audio'`, so family0 defaults to the table
  /// name; matches [`AAC_MAIN`]`.group0()`); `family1` = `"AAC"` (the `-G1`
  /// key, unchanged from the retired `serialize_tags`). Every AAC tag is a
  /// known tag (no `Unknown => 1` in AAC.pm) ⇒ `unknown: false`.
  fn tags(
    &self,
    opts: crate::emit::EmitOptions,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    let mode = opts.mode;
    use crate::emit::EmittedTag;
    use crate::value::{Group, TagValue};

    // Family-0 "AAC" / family-1 "AAC" for every emitted tag (see fn docs).
    let group = || Group::new("AAC", "AAC");
    // `-j` (PrintConv) vs `-n` (ValueConv) maps to the `print_conv` bool the
    // retired `serialize_tags` threaded.
    let print_conv = matches!(mode, crate::emit::ConvMode::PrintConv);

    let mut tags: std::vec::Vec<EmittedTag> = std::vec::Vec::with_capacity(4);

    // ProfileType (raw u8, 0..=2). `write_str(name)` → `TagValue::Str`;
    // `write_u64(n)` → `TagValue::U64` (byte-identical to the retired sink).
    let profile_type = if print_conv {
      TagValue::Str(self.profile_type_name().into())
    } else {
      TagValue::U64(u64::from(self.profile_type))
    };
    tags.push(EmittedTag::new(
      group(),
      "ProfileType".into(),
      profile_type,
      false,
    ));

    // SampleRate (post-ValueConv u32; PrintConv is None for this tag, so -j
    // and -n emit the same numeric value).
    tags.push(EmittedTag::new(
      group(),
      "SampleRate".into(),
      TagValue::U64(u64::from(self.sample_rate)),
      false,
    ));

    // Channels (raw u8). PrintConv hash: 0 → "?", 1..=5 → numeric, 6 → "5+1",
    // 7 → "7+1". When PrintConv yields an integer (1..=5) the serializer emits
    // a bare JSON number — same as -n; when it yields a string ("?","5+1",
    // "7+1") it emits a quoted string.
    let channels = if print_conv {
      match self.channels {
        0 => TagValue::Str("?".into()),
        1..=5 => TagValue::U64(u64::from(self.channels)),
        6 => TagValue::Str("5+1".into()),
        7 => TagValue::Str("7+1".into()),
        // unreachable: Channels is a 3-bit field (0..=7).
        _ => TagValue::U64(u64::from(self.channels)),
      }
    } else {
      TagValue::U64(u64::from(self.channels))
    };
    tags.push(EmittedTag::new(group(), "Channels".into(), channels, false));

    // Encoder (optional ASCII string). No conversions — identical under -j/-n.
    if let Some(enc) = self.encoder {
      tags.push(EmittedTag::new(
        group(),
        "Encoder".into(),
        TagValue::Str(enc.into()),
        false,
      ));
    }

    tags.into_iter()
  }
}

// ===========================================================================
// `Project` — the normalized cross-format domain projection (golden L2)
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::metadata::Project for Meta<'_> {
  /// Project AAC metadata onto the normalized [`MediaMetadata`] domain.
  ///
  /// AAC is a bare audio bit-stream: it carries no camera / lens / GPS /
  /// capture facts (those domains stay `None`). Of the
  /// [`MediaInfo`](crate::metadata::MediaInfo) container fields
  /// (duration / dimensions / created / track kinds), AAC's scalars
  /// (ProfileType / SampleRate / Channels / Encoder) have no matching field —
  /// `MediaInfo` has no sample-rate or channel-count slot — so the single
  /// faithful contribution is one audio [`TrackKind`](crate::metadata::TrackKind):
  /// AAC files are audio-only (`%AAC::Main` `GROUPS{2} => 'Audio'`,
  /// AAC.pm:30). Duration / dimensions / created stay `None`.
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
// contract (Phase C w2a); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;
  #[test]
  fn table_and_keys_are_faithful() {
    let g = AAC_MAIN.get();
    assert_eq!(g(TagId::Str("Bit016-017")).unwrap().name(), "ProfileType");
    assert_eq!(g(TagId::Str("Bit018-021")).unwrap().name(), "SampleRate");
    assert!(matches!(
      g(TagId::Str("Bit018-021")).unwrap().value_conv(),
      ValueConv::Hash(_)
    ));
    assert_eq!(g(TagId::Str("Bit023-025")).unwrap().name(), "Channels");
    assert_eq!(g(TagId::Str("Encoder")).unwrap().name(), "Encoder");
    assert!(g(TagId::Str("Bit999")).is_none());
    assert!(g(TagId::Int(0)).is_none());
    assert_eq!(AAC_BIT_KEYS, &["Bit016-017", "Bit018-021", "Bit023-025"]);
    assert_eq!(AAC_MAIN.group0(), "AAC");
    // %convSampleRate spot-checks vs AAC.pm:18-26.
    assert_eq!(CONV_SAMPLE_RATE.len(), 13);
    assert_eq!(CONV_SAMPLE_RATE[4], ("4", PrintValue::I64(44100)));
    assert_eq!(CONV_SAMPLE_RATE[11], ("11", PrintValue::I64(8000)));
    for key in AAC_BIT_KEYS {
      assert!(
        g(TagId::Str(key)).is_some(),
        "AAC_BIT_KEYS entry {key:?} missing from aac_get"
      );
    }
  }

  /// Run the engine over `data` (named `x.aac`) in `-j` mode and return the
  /// single file object.
  fn engine_obj(data: &[u8]) -> serde_json::Map<String, serde_json::Value> {
    let json = crate::parser::extract_info("x.aac", data, true);
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    v.as_array().unwrap()[0].as_object().unwrap().clone()
  }

  #[test]
  fn rejects_non_aac_sync() {
    // A reject must not finalize AAC (return 0 happens before AAC.pm:107
    // `$et->SetFileType()`).
    let obj = engine_obj(&[0u8; 7]);
    assert_ne!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("AAC")
    );
    let obj2 = engine_obj(&[0xff, 0x00]);
    assert_ne!(
      obj2.get("File:FileType").and_then(|v| v.as_str()),
      Some("AAC")
    );
  }

  #[test]
  fn filler_cnt15_byte0_no_panic() {
    // Byte derivation:
    //   [0]=0xff [1]=0xf1 → sync OK, no_crc=true (bit16 of t0 set)
    //   t0 = 0xff_f1_00_00; (t0>>16)&0x03 = 0x01 ≠ 3 ✓; (t0>>12)&0x0f = 0x00 ≤ 12 ✓
    //   t1 = 0x02_80 → len = ((t0<<11)&0x1800)|((t1>>5)&0x07ff)
    //                       = 0 | ((0x0280>>5)&0x7ff) = 0x14 = 20 ✓ (≥7)
    //   no_crc=true → pos=0 after header; frame = data[7..20] (13 bytes)
    //   frame[0..2] = [0xde, 0x00] → tmp = 0xde00
    //   id  = 0xde00 >> 13 = 6 ✓ (filler element)
    //   cnt = (0xde00 >> 9) & 0x0f = 0x6f & 0x0f = 15 ✓ → enters cnt==15 branch
    //   (tmp>>1)&0xff = (0xde00>>1)&0xff = 0x6f00&0xff = 0 ✓ → byte==0 triggers bug
    //   After fix: cnt = 14 + 0 = 14; pos = 2
    //   pos + cnt = 16 > 13 (frame.len) → payload slice guard fails → no Encoder emitted
    // Must accept (return true) and emit NO Encoder tag.
    let input = [
      0xff, 0xf1, 0x00, 0x00, 0x02, 0x80, 0x00, // header: sync, len=20, no_crc
      0xde, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // frame: id=6 cnt=15 byte=0 …
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let obj = engine_obj(&input);
    assert!(!obj.contains_key("AAC:Encoder"));
    // Accept ⇒ the parser drove SetFileType (AAC.pm:107): File:* present.
    assert_eq!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("AAC")
    );
  }

  // ---------- Lib-first typed Meta surface --------------------------------

  #[test]
  fn parse_borrowed_extracts_fixture_fields() {
    // Real AAC.aac fixture header: ff f1 50 80 03 ff fc → ADTS, no_crc.
    // Synthesized minimal-but-valid prefix: borrowed from the bundled AAC.aac.
    let bytes = std::fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/AAC.aac"),
    )
    .expect("read AAC.aac fixture");
    let meta = parse_borrowed(&bytes).expect("parsed");
    // ProfileType = (0x50>>6)&0x03 raw extracted by process_bit_stream
    // ⇒ 1 (low complexity). bit-stream emits I64; typed Meta lifts to u8.
    assert_eq!(meta.profile_type(), 1);
    assert_eq!(meta.profile_type_name(), "Low Complexity");
    // SampleRate = ValueConv hash["4"] = 44100.
    assert_eq!(meta.sample_rate(), 44100);
    // Channels = 2.
    assert_eq!(meta.channels(), 2);
    // Encoder = "Lavc57.107.100" (printable ASCII, post-trim).
    assert_eq!(meta.encoder(), Some("Lavc57.107.100"));
  }

  #[test]
  fn parse_borrowed_rejects_short_buffer() {
    assert!(parse_borrowed(&[]).is_none());
    assert!(parse_borrowed(&[0xff, 0xf1]).is_none());
  }

  #[test]
  fn parse_borrowed_rejects_bad_sync() {
    let data = [0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert!(parse_borrowed(&data).is_none());
  }

  #[test]
  fn parse_borrowed_rejects_reserved_profile() {
    // (t0>>16)&0x03 == 3 ⇒ AAC.pm:102 reject.
    // Construct: ff f1 c0 00 ... ⇒ t0=ff_f1_c0_00; (t0>>16)&0x03 = 0xc0&3 = 0.
    // Try ff f1 ff 00 ⇒ t0 = ff_f1_ff_00; (t0>>16)&0x03 = 0xff&3 = 3 ⇒ reject.
    let data = [0xff, 0xf1, 0xff, 0x00, 0x00, 0x00, 0x00];
    assert!(parse_borrowed(&data).is_none());
  }

  /// Drive the `Meta` through the golden-pattern engine
  /// ([`run_emission`](crate::emit::run_emission)) for `mode` and return the
  /// resulting [`TagMap`](crate::tagmap::TagMap) — the production sink path.
  fn emit_into_tagmap(meta: &Meta<'_>, mode: crate::emit::ConvMode) -> crate::tagmap::TagMap {
    let mut w = crate::tagmap::TagMap::new();
    crate::emit::run_emission(meta, crate::emit::EmitOptions::g1(mode, false), &mut w);
    w
  }

  #[test]
  fn taggable_emits_typed_tags() {
    use crate::emit::ConvMode;
    let meta = Meta {
      profile_type: 1,
      sample_rate: 44100,
      channels: 2,
      encoder: Some("TestEncoder"),
    };
    // PrintConv on (-j).
    let w = emit_into_tagmap(&meta, ConvMode::PrintConv);
    assert_eq!(
      w.get_str("AAC", "ProfileType"),
      Some("Low Complexity".to_string())
    );
    assert_eq!(w.get_str("AAC", "SampleRate"), Some("44100".to_string()));
    assert_eq!(w.get_str("AAC", "Channels"), Some("2".to_string()));
    assert_eq!(w.get_str("AAC", "Encoder"), Some("TestEncoder".to_string()));

    // PrintConv off (-n).
    let w = emit_into_tagmap(&meta, ConvMode::ValueConv);
    assert_eq!(w.get_str("AAC", "ProfileType"), Some("1".to_string()));
    assert_eq!(w.get_str("AAC", "Channels"), Some("2".to_string()));
  }

  #[test]
  fn taggable_emits_channels_special_cases() {
    use crate::emit::ConvMode;
    // Channels=0 ⇒ "?"
    let meta = Meta {
      profile_type: 0,
      sample_rate: 44100,
      channels: 0,
      encoder: None,
    };
    let w = emit_into_tagmap(&meta, ConvMode::PrintConv);
    assert_eq!(w.get_str("AAC", "Channels"), Some("?".to_string()));
    // Channels=6 ⇒ "5+1"
    let meta = Meta {
      profile_type: 0,
      sample_rate: 44100,
      channels: 6,
      encoder: None,
    };
    let w = emit_into_tagmap(&meta, ConvMode::PrintConv);
    assert_eq!(w.get_str("AAC", "Channels"), Some("5+1".to_string()));
    // Channels=7 ⇒ "7+1"
    let meta = Meta {
      profile_type: 0,
      sample_rate: 44100,
      channels: 7,
      encoder: None,
    };
    let w = emit_into_tagmap(&meta, ConvMode::PrintConv);
    assert_eq!(w.get_str("AAC", "Channels"), Some("7+1".to_string()));
  }

  #[test]
  fn taggable_group_is_aac_family0_and_family1() {
    use crate::emit::{ConvMode, Taggable};
    let meta = Meta {
      profile_type: 1,
      sample_rate: 44100,
      channels: 2,
      encoder: Some("Enc"),
    };
    let tags: std::vec::Vec<_> = meta
      .tags(crate::emit::EmitOptions::g1(ConvMode::PrintConv, false))
      .collect();
    // ProfileType, SampleRate, Channels, Encoder — four tags, none Unknown.
    assert_eq!(tags.len(), 4);
    for t in &tags {
      // family0 = "AAC" (table group; AAC.pm:28 sets only GROUPS{2}='Audio').
      assert_eq!(t.tag().group_ref().family0(), "AAC");
      // family1 = "AAC" (the -G1 key, unchanged from serialize_tags).
      assert_eq!(t.tag().group_ref().family1(), "AAC");
      assert!(!t.unknown(), "AAC has no Unknown=>1 tags");
    }
    assert_eq!(tags[0].tag().name(), "ProfileType");
    assert_eq!(tags[3].tag().name(), "Encoder");
  }

  #[test]
  fn project_populates_audio_track_only() {
    use crate::metadata::{Project, TrackKind};
    let bytes = std::fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/AAC.aac"),
    )
    .expect("read AAC.aac fixture");
    let meta = parse_borrowed(&bytes).expect("parsed");
    let projected = meta.project();
    // The one faithful MediaInfo contribution: a single audio track kind.
    assert_eq!(projected.media().track_kinds(), &[TrackKind::Audio]);
    assert!(projected.media().has_audio());
    assert!(!projected.media().has_video());
    // MediaInfo carries no sample-rate/channel slot ⇒ the rest stays empty.
    assert!(projected.media().duration().is_none());
    assert!(projected.media().width().is_none());
    assert!(projected.media().height().is_none());
    assert!(projected.media().created().is_none());
    // AAC has no camera / lens / GPS / capture facts.
    assert!(projected.camera().is_none());
    assert!(projected.lens().is_none());
    assert!(projected.gps().is_none());
    assert!(projected.capture().is_none());
  }

  #[test]
  fn format_parser_trait_returns_meta_static() {
    let bytes = std::fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/AAC.aac"),
    )
    .expect("read AAC.aac fixture");
    let meta = <ProcessAac as FormatParser>::parse(&ProcessAac, &bytes).expect("parsed");
    assert_eq!(meta.profile_type(), 1);
    assert_eq!(meta.sample_rate(), 44100);
    assert_eq!(meta.encoder(), Some("Lavc57.107.100"));
  }
}
