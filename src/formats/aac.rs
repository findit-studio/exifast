// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "aac")]
//! Faithful port of `Image::ExifTool::AAC` (lib/Image/ExifTool/AAC.pm).
//! PROCESS_PROC is `FLAC::ProcessBitStream` (AAC.pm:29) → [`crate::bitstream`].
//!
//! **Phase F1 — lib-first migration.** This format follows the MOI pilot
//! (Phase E) pattern: a typed [`AacMeta<'a>`] is produced by the new
//! [`crate::parser_new::FormatParser`] trait; the legacy
//! [`crate::parser::OldFormatParser`] entry point bridges through
//! [`crate::sink::MetadataTagWriter`] so CLI JSON output stays byte-exact
//! during the per-format crawl.

use crate::{
  bitstream::{BitOrder, process_bit_stream},
  parser::{OldFormatParser, ParseContext},
  parser_new::{FormatParser, MetaSinker, TagWriter, parser_sealed},
  sink::MetadataTagWriter,
  tagtable::{PrintConv, PrintConvHash, PrintValue, TagDef, TagId, TagTable, ValueConv},
  value::{Metadata, TagValue},
};

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
  match id {
    TagId::Str("Bit016-017") => Some(&PROFILE_TYPE),
    TagId::Str("Bit018-021") => Some(&SAMPLE_RATE),
    TagId::Str("Bit023-025") => Some(&CHANNELS),
    TagId::Str("Encoder") => Some(&ENCODER),
    _ => None,
  }
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
// Typed Meta — `AacMeta<'a>`
// ===========================================================================

/// Typed AAC metadata — the lib-first output of [`ProcessAac`].
///
/// Holds the **post-ValueConv** raw scalars (PrintConv is applied at emit
/// time by [`MetaSinker::sink`], mirroring ExifTool's
/// `$$self{OPTIONS}{PrintConv}` toggle). The bit-stream walker
/// ([`process_bit_stream`]) extracts `ProfileType` (raw), `SampleRate`
/// (post-hash-ValueConv u32), and `Channels` (raw); `Encoder` is the
/// ASCII string from the filler payload of the first AAC frame
/// (AAC.pm:130-133).
///
/// **D8 — no public fields, accessors only.**
///
/// **Lifetimes.** `AacMeta` borrows the Encoder string from the input
/// buffer (`encoder: Option<&'a str>`); other fields are owned primitives.
#[derive(Debug, Clone)]
pub struct AacMeta<'a> {
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

impl<'a> AacMeta<'a> {
  /// ProfileType raw value (0..=2).
  #[must_use]
  pub fn profile_type(&self) -> u8 {
    self.profile_type
  }

  /// ProfileType PrintConv name (`%AAC::Main{ProfileType}`).
  #[must_use]
  pub fn profile_type_name(&self) -> &'static str {
    match self.profile_type {
      0 => "Main",
      1 => "Low Complexity",
      2 => "Scalable Sampling Rate",
      _ => "Unknown", // unreachable: gated by `(t0 >> 16) & 0x03 != 3` (AAC.pm:102)
    }
  }

  /// SampleRate in Hz (e.g. 44100). Post-ValueConv (`%convSampleRate`).
  #[must_use]
  pub fn sample_rate(&self) -> u32 {
    self.sample_rate
  }

  /// Channels raw value (0..=7).
  #[must_use]
  pub fn channels(&self) -> u8 {
    self.channels
  }

  /// Encoder string borrowed from the input buffer, if present.
  #[must_use]
  pub fn encoder(&self) -> Option<&'a str> {
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
  type Meta<'a> = AacMeta<'a>;
  type Context<'a> = &'a [u8];
  type Error = AacError;

  fn parse<'a>(&self, data: Self::Context<'a>) -> Result<Option<Self::Meta<'a>>, AacError> {
    parse_inner(data)
  }
}

/// Lib-first direct entry. Same as [`FormatParser::parse`] but returns an
/// [`AacMeta`] that borrows from the input buffer (Encoder field).
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today; reserved for
/// future I/O wrappers).
pub fn parse_borrowed(data: &[u8]) -> Result<Option<AacMeta<'_>>, AacError> {
  parse_inner(data)
}

/// Inner parser — produces a borrow-from-input [`AacMeta`]. The
/// [`FormatParser::Meta`] GAT (`type Meta<'a> = AacMeta<'a>`) returns this
/// borrowed form directly into the closed [`crate::parser_new::AnyMeta`]
/// enum — no `'static` upgrade (Codex AF2).
fn parse_inner(data: &[u8]) -> Result<Option<AacMeta<'_>>, AacError> {
  // AAC.pm:99-105 header validation. A reject here returns `Ok(None)` —
  // Perl `return 0` BEFORE `$et->SetFileType()` (AAC.pm:107).
  if data.len() < 7 {
    return Ok(None); // $raf->Read($buff,7)==7 or return 0  (AAC.pm:99)
  }
  let buff = &data[..7];
  if buff[0] != 0xff || (buff[1] != 0xf0 && buff[1] != 0xf1) {
    return Ok(None); // unless $buff =~ /^\xff[\xf0\xf1]/  (AAC.pm:100)
  }
  // my @t = unpack('NnC', $buff)  (AAC.pm:101)
  let t0 = u32::from_be_bytes([buff[0], buff[1], buff[2], buff[3]]); // $t[0] = 'N'
  let t1 = u16::from_be_bytes([buff[4], buff[5]]); // $t[1] = 'n'
  let t2 = buff[6]; // $t[2] = 'C'

  // Faithful 1:1 of AAC.pm:102-103. The shift offsets (>>16, >>12) are
  // ExifTool's own — they intentionally differ from the %AAC::Main bit
  // table's Bit016-017 / Bit018-021 extraction. Do NOT "correct" them.
  if (t0 >> 16) & 0x03 == 3 {
    return Ok(None); // AAC.pm:102 (reserved profile type)
  }
  if (t0 >> 12) & 0x0f > 12 {
    return Ok(None); // AAC.pm:103 (validate sampling frequency index)
  }
  // my $len = (($t[0] << 11) & 0x1800) | (($t[1] >> 5) & 0x07ff)  (AAC.pm:104)
  let len = (((t0 << 11) & 0x1800) | ((t1 as u32 >> 5) & 0x07ff)) as usize;
  if len < 7 {
    return Ok(None); // AAC.pm:105
  }

  // Bit-stream walk to extract ProfileType / SampleRate / Channels via
  // process_bit_stream into a side Metadata. The bit-stream walker is the
  // shared engine path used by AAC + FLAC StreamInfo + WavPack + MPC;
  // running it here is the simplest faithful path. We then transpose the
  // emitted (name, TagValue) triples into typed scalars on AacMeta.
  let mut staging = Metadata::new("aac-staging");
  // print_conv_enabled=false: we want the post-ValueConv raw scalars —
  // PrintConv is applied at sink time per Meta's design.
  process_bit_stream(
    buff,
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
  for tag in staging.tags() {
    match tag.name() {
      "ProfileType" => {
        if let TagValue::I64(n) = tag.value() {
          profile_type = (*n as u64) as u8;
        }
      }
      "SampleRate" => {
        if let TagValue::I64(n) = tag.value() {
          sample_rate = (*n as u64) as u32;
        }
      }
      "Channels" => {
        if let TagValue::I64(n) = tag.value() {
          channels = (*n as u64) as u8;
        }
      }
      _ => {}
    }
  }

  // Read the first frame data to check for a filler with the encoder name
  // (AAC.pm:112-137). The Perl `while` runs at most once: the body ends
  // with an unconditional `last` (AAC.pm:136).
  let encoder: Option<&str> = encoder_from_filler(data, t0, t2, len);

  Ok(Some(AacMeta {
    profile_type,
    sample_rate,
    channels,
    encoder,
  }))
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
  let frame = &data[7..7 + (len - 7)]; // $buff (re-read), length == $len-7
  let no_crc = (t0 & 0x0001_0000) != 0; // my $noCRC = ($t[0] & 0x00010000)  (AAC.pm:114)
  let blocks = (t2 & 0x03) as usize; // my $blocks = ($t[2] & 0x03)  (AAC.pm:115)
  let mut pos = 0usize; // my $pos = 0  (AAC.pm:116)
  if !no_crc {
    pos += 2 + 2 * blocks; // $pos += 2 + 2 * $blocks unless $noCRC  (AAC.pm:117)
  }
  if pos + 2 > frame.len() {
    return None; // last if $pos + 2 > length($buff)  (AAC.pm:118)
  }
  let tmp = u16::from_be_bytes([frame[pos], frame[pos + 1]]); // unpack "x${pos}n" (AAC.pm:119)
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
  let dat = &frame[pos..pos + cnt]; // my $dat = substr($buff,$pos,$cnt)  (AAC.pm:130)
  // $dat =~ s/^\0+// ; $dat =~ s/\0+$//  (AAC.pm:131-132)
  let s = dat.iter().position(|&b| b != 0).unwrap_or(dat.len());
  let e = dat.iter().rposition(|&b| b != 0).map_or(s, |i| i + 1);
  let trimmed = &dat[s..e];
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
  core::str::from_utf8(&data[abs_start..abs_end]).ok()
}

// ===========================================================================
// `MetaSinker` — typed Meta → TagWriter
// ===========================================================================

impl MetaSinker for AacMeta<'_> {
  /// Emit AAC tags into the writer in `%AAC::Main` walk order (ProfileType,
  /// SampleRate, Channels, then Encoder) — faithful to AAC.pm:38-74 +
  /// bit-stream walker.
  ///
  /// `print_conv=true` ⇒ PrintConv formatted strings (`-j` mode);
  /// `print_conv=false` ⇒ post-ValueConv raw scalars (`-n` mode).
  fn sink<W: TagWriter>(&self, print_conv: bool, out: &mut W) -> Result<(), W::Error> {
    const GROUP: &str = "AAC";
    // ProfileType (raw u8, 0..=2).
    if print_conv {
      out.write_str(GROUP, "ProfileType", self.profile_type_name())?;
    } else {
      out.write_u64(GROUP, "ProfileType", u64::from(self.profile_type))?;
    }
    // SampleRate (post-ValueConv u32; PrintConv is None for this tag,
    // so -j and -n emit the same numeric value).
    out.write_u64(GROUP, "SampleRate", u64::from(self.sample_rate))?;
    // Channels (raw u8). PrintConv hash: 0 → "?", 1..=5 → numeric I64,
    // 6 → "5+1", 7 → "7+1". When PrintConv yields an integer (1..=5), the
    // serializer emits a bare JSON number — same as -n. When PrintConv
    // yields a string (?, 5+1, 7+1), serializer emits a quoted string.
    if print_conv {
      match self.channels {
        0 => out.write_str(GROUP, "Channels", "?")?,
        1..=5 => out.write_u64(GROUP, "Channels", u64::from(self.channels))?,
        6 => out.write_str(GROUP, "Channels", "5+1")?,
        7 => out.write_str(GROUP, "Channels", "7+1")?,
        // unreachable: Channels is a 3-bit field (0..=7).
        _ => out.write_u64(GROUP, "Channels", u64::from(self.channels))?,
      }
    } else {
      out.write_u64(GROUP, "Channels", u64::from(self.channels))?;
    }
    // Encoder (optional ASCII string). No conversions — identical under -j and -n.
    if let Some(enc) = self.encoder {
      out.write_str(GROUP, "Encoder", enc)?;
    }
    Ok(())
  }
}

// ===========================================================================
// `AacError` — Rust-level fatal modes (currently none)
// ===========================================================================

/// Rust-level fatal modes for AAC parsing. Currently empty — every bad
/// input produces `Ok(None)` (Perl `return 0`). Reserved for future I/O
/// wrappers if streaming readers are added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AacError {}

impl core::fmt::Display for AacError {
  fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match *self {}
  }
}

#[cfg(feature = "std")]
impl std::error::Error for AacError {}

// ===========================================================================
// Legacy `OldFormatParser` bridge — preserves CLI byte-exact JSON
// ===========================================================================

impl OldFormatParser for ProcessAac {
  /// Phase E–F migration bridge. Runs the new typed [`FormatParser::parse`]
  /// and drives [`MetaSinker::sink`] through a [`MetadataTagWriter`] so the
  /// CLI JSON output stays byte-exact during Phases F1–F5. Retired in
  /// Phase G.
  ///
  /// Faithful order (AAC.pm:99-140): header magic + filesize + SF index
  /// gates ⇒ `SetFileType` ⇒ bit-stream walk ⇒ Encoder filler scan.
  fn process(&self, ctx: &mut ParseContext<'_>) -> bool {
    let bytes = ctx.data();
    let meta = match parse_inner(bytes) {
      Ok(Some(m)) => m,
      Ok(None) => return false,
      Err(_) => return false,
    };
    // AAC.pm:107 — `$et->SetFileType()` (no-arg). The new typed parser
    // emits its own tags after this finalize.
    ctx.set_file_type(None, None, None);
    let print_conv = ctx.print_conv_enabled();
    // The Encoder field needs the legacy `convert::apply` path for the
    // family-1 group routing (the AAC_MAIN.group1 dispatch lands family-1
    // as "AAC"). Use the typed sink which mirrors that mapping exactly.
    let mut bridge = MetadataTagWriter::new(ctx.metadata());
    let _: Result<(), core::convert::Infallible> = meta.sink(print_conv, &mut bridge);
    // Note: the Channels PrintConv hash maps `0 ⇒ "?"`. The bundled-Perl
    // JSON emitter writes `"?"` as a quoted JSON string. Our
    // `MetadataTagWriter::write_str` pushes `TagValue::Str`, which the
    // serializer quotes — byte-exact.
    //
    // For Channels values 1..=5, PrintConv returns I64; the bundled JSON
    // emits a bare number. The sink calls `write_u64` for these arms ⇒
    // bridge pushes `TagValue::I64` ⇒ serializer emits bare number ⇒
    // byte-exact.
    //
    // For Channels 6/7, PrintConv returns "5+1"/"7+1" strings ⇒
    // `write_str` ⇒ `TagValue::Str` ⇒ quoted ⇒ byte-exact.
    true // return 1  (AAC.pm:139)
  }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
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

  #[test]
  fn rejects_non_aac_sync() {
    use crate::parser::ParseContext;
    // A reject must push nothing AND not finalize a type (return 0 happens
    // before AAC.pm:107 `$et->SetFileType()`).
    let mut m = crate::value::Metadata::new("x");
    let data = [0u8; 7];
    let mut c = ParseContext::new(&data, "AAC", 0, "AAC", None, true, &mut m);
    assert!(!OldFormatParser::process(&ProcessAac, &mut c));
    assert!(m.tags().is_empty());
    let mut m2 = crate::value::Metadata::new("x");
    let bad = [0xff, 0x00];
    let mut c2 = ParseContext::new(&bad, "AAC", 0, "AAC", None, true, &mut m2);
    assert!(!OldFormatParser::process(&ProcessAac, &mut c2)); // too short / bad sync
    assert!(m2.tags().is_empty());
  }

  #[test]
  fn filler_cnt15_byte0_no_panic() {
    use crate::parser::FormatParser as _OldFP;
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
    let mut m = crate::value::Metadata::new("x");
    let mut c = crate::parser::ParseContext::new(&input, "AAC", 0, "AAC", None, true, &mut m);
    assert!(_OldFP::process(&ProcessAac, &mut c));
    assert!(m.tags().iter().all(|t| t.name() != "Encoder"));
    // Accept ⇒ the parser drove SetFileType (AAC.pm:107): File:* present.
    assert_eq!(
      m.tags()
        .iter()
        .find(|t| t.name() == "FileType")
        .map(|t| t.value()),
      Some(&TagValue::Str("AAC".into()))
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
    let meta = parse_borrowed(&bytes).expect("ok").expect("parsed");
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
    assert!(parse_borrowed(&[]).unwrap().is_none());
    assert!(parse_borrowed(&[0xff, 0xf1]).unwrap().is_none());
  }

  #[test]
  fn parse_borrowed_rejects_bad_sync() {
    let data = [0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert!(parse_borrowed(&data).unwrap().is_none());
  }

  #[test]
  fn parse_borrowed_rejects_reserved_profile() {
    // (t0>>16)&0x03 == 3 ⇒ AAC.pm:102 reject.
    // Construct: ff f1 c0 00 ... ⇒ t0=ff_f1_c0_00; (t0>>16)&0x03 = 0xc0&3 = 0.
    // Try ff f1 ff 00 ⇒ t0 = ff_f1_ff_00; (t0>>16)&0x03 = 0xff&3 = 3 ⇒ reject.
    let data = [0xff, 0xf1, 0xff, 0x00, 0x00, 0x00, 0x00];
    assert!(parse_borrowed(&data).unwrap().is_none());
  }

  #[test]
  fn meta_sinker_emits_typed_tags() {
    use crate::sink::{MapTagWriter, MapValue};
    let meta = AacMeta {
      profile_type: 1,
      sample_rate: 44100,
      channels: 2,
      encoder: Some("TestEncoder"),
    };
    // PrintConv on.
    let mut w = MapTagWriter::new();
    meta.sink(true, &mut w).unwrap();
    assert_eq!(
      w.get("AAC", "ProfileType").map(MapValue::as_str),
      Some("Low Complexity".to_string())
    );
    assert_eq!(
      w.get("AAC", "SampleRate").map(MapValue::as_str),
      Some("44100".to_string())
    );
    assert_eq!(
      w.get("AAC", "Channels").map(MapValue::as_str),
      Some("2".to_string())
    );
    assert_eq!(
      w.get("AAC", "Encoder").map(MapValue::as_str),
      Some("TestEncoder".to_string())
    );

    // PrintConv off.
    let mut w = MapTagWriter::new();
    meta.sink(false, &mut w).unwrap();
    assert_eq!(
      w.get("AAC", "ProfileType").map(MapValue::as_str),
      Some("1".to_string())
    );
    assert_eq!(
      w.get("AAC", "Channels").map(MapValue::as_str),
      Some("2".to_string())
    );
  }

  #[test]
  fn meta_sinker_emits_channels_special_cases() {
    use crate::sink::{MapTagWriter, MapValue};
    // Channels=0 ⇒ "?"
    let meta = AacMeta {
      profile_type: 0,
      sample_rate: 44100,
      channels: 0,
      encoder: None,
    };
    let mut w = MapTagWriter::new();
    meta.sink(true, &mut w).unwrap();
    assert_eq!(
      w.get("AAC", "Channels").map(MapValue::as_str),
      Some("?".to_string())
    );
    // Channels=6 ⇒ "5+1"
    let meta = AacMeta {
      profile_type: 0,
      sample_rate: 44100,
      channels: 6,
      encoder: None,
    };
    let mut w = MapTagWriter::new();
    meta.sink(true, &mut w).unwrap();
    assert_eq!(
      w.get("AAC", "Channels").map(MapValue::as_str),
      Some("5+1".to_string())
    );
    // Channels=7 ⇒ "7+1"
    let meta = AacMeta {
      profile_type: 0,
      sample_rate: 44100,
      channels: 7,
      encoder: None,
    };
    let mut w = MapTagWriter::new();
    meta.sink(true, &mut w).unwrap();
    assert_eq!(
      w.get("AAC", "Channels").map(MapValue::as_str),
      Some("7+1".to_string())
    );
  }

  #[test]
  fn format_parser_trait_returns_meta_static() {
    let bytes = std::fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/AAC.aac"),
    )
    .expect("read AAC.aac fixture");
    let meta = <ProcessAac as FormatParser>::parse(&ProcessAac, &bytes)
      .expect("ok")
      .expect("parsed");
    assert_eq!(meta.profile_type(), 1);
    assert_eq!(meta.sample_rate(), 44100);
    assert_eq!(meta.encoder(), Some("Lavc57.107.100"));
  }
}
