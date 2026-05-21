// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "mpeg-audio")]
//! Faithful port of `Image::ExifTool::MPEG` (lib/Image/ExifTool/MPEG.pm) —
//! AUDIO side only.
//!
//! A typed [`MpegAudioMeta<'a>`] is produced by the
//! [`crate::parser_new::FormatParser`] trait with a per-format
//! [`MpegAudioContext`] (data + start_offset + ext + shared flags). MPEG
//! audio is invoked internally by the MP3 file-type entry
//! ([`crate::formats::id3::ProcessMp3`]) via
//! [`ProcessMp3::process_with_start_offset`], which drives
//! the typed `serialize_tags` path into the engine
//! `tagmap::TagMap` so the serialized JSON stays
//! byte-exact with bundled `perl exiftool`.
//!
//! ## Ports
//!
//! - `%MPEG::Audio` (MPEG.pm:23-256) — the 11-tag bit-field table for the
//!   4-byte MPEG audio frame header.
//! - `ProcessFrameHeader` (MPEG.pm:441-457) — direct bit-extract from the
//!   32-bit big-endian header word into typed [`MpegAudioMeta`] fields
//!   (Phase F4 supersedes the [`crate::bitstream::process_bit_stream_cond`]
//!   path for the typed Meta).
//! - `ParseMPEGAudio` (MPEG.pm:464-581) — sync-scan, header-validate,
//!   extract, AND the post-header Xing/Info/LAME tail (MPEG.pm:501-578).
//! - `%MPEG::Xing` (MPEG.pm:323-337) and `%MPEG::Lame` (MPEG.pm:339-382) —
//!   the VBR/encoder sub-tables consumed by the post-header tail.
//! - `ProcessMP3` audio scan-buffer bounding (ID3.pm:1684-1729) — the
//!   wrapper at `ProcessMp3::process_with_start_offset` bounds `data` to
//!   ID3.pm:1704's `$scanLen` (8192 if `$$self{FILE_EXT} eq 'MP3'`, 256
//!   otherwise) BEFORE invoking the typed parser. Required to match bundled
//!   ExifTool's rejection of files where a valid sync byte appears beyond
//!   the scan boundary; without it, MP3 (weak magic) would falsely accept
//!   junk files on a stray late `\xff` (Codex R1/F1).
//!
//! ## Phase E discovery — `process_with_start_offset` API preservation
//!
//! The R5 fix introduced `ProcessMp3::process_with_start_offset` so the
//! ID3 wrapper (`src/formats/id3/process.rs:117`) could mirror bundled's
//! `Seek($hdrEnd, 0)` + `Read($buff, $scanLen)` pair (ID3.pm:1590 +
//! ID3.pm:1705). The public method signature is **preserved exactly** so
//! the ID3 wrapper code (`mpeg::ProcessMp3.process_with_start_offset(ctx,
//! hdr_end)`) keeps working byte-for-byte. It internally drives the typed
//! [`ProcessMpegAudio`] + `serialize_tags` path.
//!
//! ## Deferred (forward items, deliberately out of this PR's scope)
//!
//! - **MPEG video** (`%MPEG::Video`, `ProcessMPEG`, `ProcessMPEGVideo`,
//!   `ParseMPEGAudioVideo`, MPEG.pm:258-321 + 583-681) — separate port.
//! - **`%MPEG::Composite` (Duration/AudioBitrate)** (MPEG.pm:385-432) —
//!   Composite tags subsystem not yet ported (cross-module Require/Desire).
//! - **R8 set-then-reject** — MPEG.pm:496 `$et->SetFileType()` is called
//!   BEFORE the post-header Xing/LAME tail; the tail can `last` on any
//!   length / magic / flag check but never `return 0`, so the File:* tags
//!   from SetFileType always persist. The engine entry preserves this: it
//!   calls `ctx.set_file_type(None, None, None)` BEFORE sinking the typed
//!   Meta, so File:* lands first and persists if any later code returns false.

use std::{borrow::Cow, string::String};

use crate::{
  parser_new::{FormatParser, SharedFlags, parser_sealed},
  value::format_g,
};

// ===========================================================================
// `convert_bitrate` / `convert_lame_lowpass`
// ===========================================================================

/// Format-into-writer port of `Image::ExifTool::ConvertBitrate`
/// (ExifTool.pm:6891-6902). Writes the formatted bitrate string directly
/// into a [`core::fmt::Write`] sink — no intermediate `String` allocation.
///
/// Perl reference:
/// ```perl
/// my $bitrate = shift;
/// IsFloat($bitrate) or return $bitrate;
/// my @units = ('bps', 'kbps', 'Mbps', 'Gbps');
/// for (;;) {
///     my $units = shift @units;
///     $bitrate >= 1000 and @units and $bitrate /= 1000, next;
///     my $fmt = $bitrate < 100 ? '%.3g' : '%.0f';
///     return sprintf("$fmt $units", $bitrate);
/// }
/// ```
///
/// FORWARD-ITEM: Rust `{:.0}` rounds half-to-even; Perl `%.0f` on most
/// platforms rounds half-away-from-zero. Currently load-bearing only for
/// integer bitrates (every VC hash entry is a multiple of 1000, so /1000
/// stays integer-valued; no halves are produced). If a VBR Composite:
/// AudioBitrate (MPEG.pm:416-431) is later ported it can produce a half —
/// switch this arm to a half-away-from-zero rounder then, pinned by an
/// oracle golden.
pub fn write_convert_bitrate<W: core::fmt::Write + ?Sized>(
  w: &mut W,
  bitrate: f64,
) -> core::fmt::Result {
  if !bitrate.is_finite() {
    return write!(w, "{bitrate}");
  }
  const UNITS: &[&str] = &["bps", "kbps", "Mbps", "Gbps"];
  let mut b = bitrate;
  for (i, &unit) in UNITS.iter().enumerate() {
    let is_last = i + 1 == UNITS.len();
    if b >= 1000.0 && !is_last {
      b /= 1000.0;
      continue;
    }
    return if b < 100.0 {
      // `%.3g` — Perl `%g` strips trailing zeros. Share the engine helper.
      let formatted = format_g(b, 3);
      write!(w, "{formatted} {unit}")
    } else {
      write!(w, "{b:.0} {unit}")
    };
  }
  unreachable!("write_convert_bitrate loop must exit on the last unit");
}

/// Format-into-writer port of MPEG.pm:361 `PrintConv => '($val / 1000) . "
/// kHz"'`. ValueConv has already multiplied the raw byte by 100 (so the
/// caller passes `byte * 100`); a value like `16000` yields `"16 kHz"`.
/// Perl `.` is string concat; an integer-valued float prints as the
/// integer (no trailing `.0`), so we explicitly skip the decimal when the
/// quotient is integral.
pub fn write_lame_lowpass<W: core::fmt::Write + ?Sized>(
  w: &mut W,
  value: f64,
) -> core::fmt::Result {
  if !value.is_finite() {
    return write!(w, "{value}");
  }
  let q = value / 1000.0;
  if (q - q.round()).abs() < f64::EPSILON {
    write!(w, "{} kHz", q.round() as i64)
  } else {
    let s = format_g(q, 15);
    write!(w, "{s} kHz")
  }
}

// ===========================================================================
// Typed enums (D8 newtype-only)
// ===========================================================================

/// MPEG audio version (Bit11-12). Raw 2-bit field; bundled PrintConv hash
/// (MPEG.pm:25-33) maps 0 → 2.5, 2 → 2, 3 → 1; raw 1 is the reserved
/// version ID, which is rejected upstream by `check_header`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpegAudioVersion {
  /// raw=0 → "2.5".
  V2_5,
  /// raw=2 → "2".
  V2,
  /// raw=3 → "1".
  V1,
}

impl MpegAudioVersion {
  /// Decode the raw 2-bit field. Returns `None` for raw=1 (reserved); the
  /// header-validation gate ensures this is unreachable from `scan_for_header`.
  #[must_use]
  pub const fn from_raw(raw: u8) -> Option<Self> {
    match raw {
      0 => Some(Self::V2_5),
      2 => Some(Self::V2),
      3 => Some(Self::V1),
      _ => None,
    }
  }
  /// Raw 2-bit encoding (the on-disk value).
  #[must_use]
  pub const fn raw(self) -> u8 {
    match self {
      Self::V2_5 => 0,
      Self::V2 => 2,
      Self::V1 => 3,
    }
  }
}

/// MPEG audio layer (Bit13-14). Raw 2-bit field; bundled PrintConv hash
/// (MPEG.pm:34-42) maps 1 → 3, 2 → 2, 3 → 1; raw 0 is reserved, rejected
/// upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioLayer {
  /// raw=1 → "Layer III".
  L3,
  /// raw=2 → "Layer II".
  L2,
  /// raw=3 → "Layer I".
  L1,
}

impl AudioLayer {
  /// Decode the raw 2-bit field. Returns `None` for raw=0 (reserved).
  #[must_use]
  pub const fn from_raw(raw: u8) -> Option<Self> {
    match raw {
      1 => Some(Self::L3),
      2 => Some(Self::L2),
      3 => Some(Self::L1),
      _ => None,
    }
  }
  /// Raw 2-bit encoding.
  #[must_use]
  pub const fn raw(self) -> u8 {
    match self {
      Self::L3 => 1,
      Self::L2 => 2,
      Self::L1 => 3,
    }
  }
  /// Display layer number (1..3) for PrintConv emission.
  #[must_use]
  pub const fn display(self) -> u8 {
    match self {
      Self::L3 => 3,
      Self::L2 => 2,
      Self::L1 => 1,
    }
  }
}

/// MPEG audio bitrate (Bit16-19). Each (version, layer) tuple has its own
/// 15-entry value-conv table (MPEG.pm:44-164); raw=0 maps to the `"free"`
/// sentinel string; raw=15 (`0b1111`) is reserved, rejected upstream.
/// `Known(bps)` holds the post-ValueConv bitrate in bps; `Free` is the
/// `0 => 'free'` sentinel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioBitrate {
  /// raw=0 → "free" sentinel; ConvertBitrate IsFloat-rejects, passthrough.
  Free,
  /// Post-ValueConv bitrate in bps from the per-(version, layer) hash.
  Known(u32),
}

/// Channel mode (Bit24-25). Raw 2-bit field; PrintConv (MPEG.pm:200-209)
/// maps 0 → Stereo, 1 → Joint Stereo, 2 → Dual Channel, 3 → Single Channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelMode {
  /// raw=0 → "Stereo".
  Stereo,
  /// raw=1 → "Joint Stereo".
  JointStereo,
  /// raw=2 → "Dual Channel".
  DualChannel,
  /// raw=3 → "Single Channel".
  SingleChannel,
}

impl ChannelMode {
  /// Decode the raw 2-bit field. The bit-stream walker always produces
  /// a valid 0..3 value (the field is unconditional).
  #[must_use]
  pub const fn from_raw(raw: u8) -> Self {
    match raw & 0x03 {
      0 => Self::Stereo,
      1 => Self::JointStereo,
      2 => Self::DualChannel,
      _ => Self::SingleChannel,
    }
  }
  /// Raw 2-bit encoding.
  #[must_use]
  pub const fn raw(self) -> u8 {
    match self {
      Self::Stereo => 0,
      Self::JointStereo => 1,
      Self::DualChannel => 2,
      Self::SingleChannel => 3,
    }
  }
  /// PrintConv string (MPEG.pm:200-209).
  #[must_use]
  pub const fn print_conv(self) -> &'static str {
    match self {
      Self::Stereo => "Stereo",
      Self::JointStereo => "Joint Stereo",
      Self::DualChannel => "Dual Channel",
      Self::SingleChannel => "Single Channel",
    }
  }
}

/// ModeExtension (Bit26-27, condition Layer I or II). Raw 2-bit; PrintConv
/// (MPEG.pm:222-232) maps 0 → "Bands 4-31", 1 → "Bands 8-31", 2 → "Bands
/// 12-31", 3 → "Bands 16-31".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeExtension {
  /// raw=0 → "Bands 4-31".
  Bands4to31,
  /// raw=1 → "Bands 8-31".
  Bands8to31,
  /// raw=2 → "Bands 12-31".
  Bands12to31,
  /// raw=3 → "Bands 16-31".
  Bands16to31,
}

impl ModeExtension {
  /// Decode the raw 2-bit field.
  #[must_use]
  pub const fn from_raw(raw: u8) -> Self {
    match raw & 0x03 {
      0 => Self::Bands4to31,
      1 => Self::Bands8to31,
      2 => Self::Bands12to31,
      _ => Self::Bands16to31,
    }
  }
  /// Raw 2-bit encoding.
  #[must_use]
  pub const fn raw(self) -> u8 {
    match self {
      Self::Bands4to31 => 0,
      Self::Bands8to31 => 1,
      Self::Bands12to31 => 2,
      Self::Bands16to31 => 3,
    }
  }
  /// PrintConv string (MPEG.pm:222-232).
  #[must_use]
  pub const fn print_conv(self) -> &'static str {
    match self {
      Self::Bands4to31 => "Bands 4-31",
      Self::Bands8to31 => "Bands 8-31",
      Self::Bands12to31 => "Bands 12-31",
      Self::Bands16to31 => "Bands 16-31",
    }
  }
}

/// Emphasis (Bit30-31). Raw 2-bit; PrintConv (MPEG.pm:247-255) maps 0 →
/// "None", 1 → "50/15 ms", 2 → "reserved", 3 → "CCIT J.17". Raw=2 is
/// validated as the "reserved emphasis" reject by `check_header`
/// (MPEG.pm:484), so a parsed [`MpegAudioMeta`] never carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Emphasis {
  /// raw=0 → "None".
  None,
  /// raw=1 → "50/15 ms".
  FiftyFifteen,
  /// raw=2 → "reserved" (rejected upstream).
  Reserved,
  /// raw=3 → "CCIT J.17".
  CcitJ17,
}

impl Emphasis {
  /// Decode the raw 2-bit field.
  #[must_use]
  pub const fn from_raw(raw: u8) -> Self {
    match raw & 0x03 {
      0 => Self::None,
      1 => Self::FiftyFifteen,
      2 => Self::Reserved,
      _ => Self::CcitJ17,
    }
  }
  /// Raw 2-bit encoding.
  #[must_use]
  pub const fn raw(self) -> u8 {
    match self {
      Self::None => 0,
      Self::FiftyFifteen => 1,
      Self::Reserved => 2,
      Self::CcitJ17 => 3,
    }
  }
  /// PrintConv string (MPEG.pm:247-255).
  #[must_use]
  pub const fn print_conv(self) -> &'static str {
    match self {
      Self::None => "None",
      Self::FiftyFifteen => "50/15 ms",
      Self::Reserved => "reserved",
      Self::CcitJ17 => "CCIT J.17",
    }
  }
}

/// LameMethod (MPEG.pm:344-357). Raw byte AND-masked with 0x0f; PrintConv
/// hash maps 1..9. Note codes 5 and 3 both render `"VBR (old/rh)"`; we
/// preserve the raw byte so `-n` mode emits the exact on-disk value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LameMethod {
  /// raw=1 → "CBR".
  Cbr,
  /// raw=2 → "ABR".
  Abr,
  /// raw=3 → "VBR (old/rh)" (also raw=5).
  VbrOldRh,
  /// raw=4 → "VBR (new/mtrh)".
  VbrNewMtrh,
  /// raw=5 → "VBR (old/rh)" (same display as raw=3).
  VbrOldRhV5,
  /// raw=6 → "VBR".
  Vbr,
  /// raw=8 → "CBR (2-pass)".
  Cbr2Pass,
  /// raw=9 → "ABR (2-pass)".
  Abr2Pass,
  /// Unknown/out-of-table raw byte (rendered as raw integer under -j,
  /// since the PrintConv hash hash-misses and the value passes through).
  Unknown(u8),
}

impl LameMethod {
  /// Decode the raw post-mask 0x0f value.
  #[must_use]
  pub const fn from_raw(masked: u8) -> Self {
    match masked & 0x0f {
      1 => Self::Cbr,
      2 => Self::Abr,
      3 => Self::VbrOldRh,
      4 => Self::VbrNewMtrh,
      5 => Self::VbrOldRhV5,
      6 => Self::Vbr,
      8 => Self::Cbr2Pass,
      9 => Self::Abr2Pass,
      other => Self::Unknown(other),
    }
  }
  /// Raw post-mask value.
  #[must_use]
  pub const fn raw(self) -> u8 {
    match self {
      Self::Cbr => 1,
      Self::Abr => 2,
      Self::VbrOldRh => 3,
      Self::VbrNewMtrh => 4,
      Self::VbrOldRhV5 => 5,
      Self::Vbr => 6,
      Self::Cbr2Pass => 8,
      Self::Abr2Pass => 9,
      Self::Unknown(b) => b,
    }
  }
  /// PrintConv name; `None` for an unknown raw (the value passes through
  /// as the raw integer in the bundled emit path).
  #[must_use]
  pub const fn print_conv(self) -> Option<&'static str> {
    match self {
      Self::Cbr => Some("CBR"),
      Self::Abr => Some("ABR"),
      Self::VbrOldRh | Self::VbrOldRhV5 => Some("VBR (old/rh)"),
      Self::VbrNewMtrh => Some("VBR (new/mtrh)"),
      Self::Vbr => Some("VBR"),
      Self::Cbr2Pass => Some("CBR (2-pass)"),
      Self::Abr2Pass => Some("ABR (2-pass)"),
      Self::Unknown(_) => None,
    }
  }
}

/// LameStereoMode (MPEG.pm:369-381). Raw byte masked 0x1c then right-
/// shifted by 2 (BitShift derived from `Mask`'s lowest set bit per
/// ExifTool.pm:5907-5909). PrintConv hash maps 0..7; raw=5 is absent
/// from the hash and emits as the raw integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LameStereoMode {
  /// raw=0 → "Mono".
  Mono,
  /// raw=1 → "Stereo".
  Stereo,
  /// raw=2 → "Dual Channels".
  DualChannels,
  /// raw=3 → "Joint Stereo".
  JointStereo,
  /// raw=4 → "Forced Joint Stereo".
  ForcedJointStereo,
  /// raw=6 → "Auto".
  Auto,
  /// raw=7 → "Intensity Stereo".
  IntensityStereo,
  /// Unknown/out-of-table raw byte (raw=5 / >=8); falls through to raw
  /// integer emission.
  Unknown(u8),
}

impl LameStereoMode {
  /// Decode the post-mask+shift (`(b & 0x1c) >> 2`) value.
  #[must_use]
  pub const fn from_raw(shifted: u8) -> Self {
    match shifted {
      0 => Self::Mono,
      1 => Self::Stereo,
      2 => Self::DualChannels,
      3 => Self::JointStereo,
      4 => Self::ForcedJointStereo,
      6 => Self::Auto,
      7 => Self::IntensityStereo,
      other => Self::Unknown(other),
    }
  }
  /// Raw post-mask+shift value.
  #[must_use]
  pub const fn raw(self) -> u8 {
    match self {
      Self::Mono => 0,
      Self::Stereo => 1,
      Self::DualChannels => 2,
      Self::JointStereo => 3,
      Self::ForcedJointStereo => 4,
      Self::Auto => 6,
      Self::IntensityStereo => 7,
      Self::Unknown(b) => b,
    }
  }
  /// PrintConv name; `None` for an unknown raw.
  #[must_use]
  pub const fn print_conv(self) -> Option<&'static str> {
    match self {
      Self::Mono => Some("Mono"),
      Self::Stereo => Some("Stereo"),
      Self::DualChannels => Some("Dual Channels"),
      Self::JointStereo => Some("Joint Stereo"),
      Self::ForcedJointStereo => Some("Forced Joint Stereo"),
      Self::Auto => Some("Auto"),
      Self::IntensityStereo => Some("Intensity Stereo"),
      Self::Unknown(_) => None,
    }
  }
}

// ===========================================================================
// Typed Meta — `MpegAudioMeta<'a>`
// ===========================================================================

/// Typed MPEG audio metadata — the lib-first output of [`ProcessMpegAudio`].
///
/// Holds the **post-ValueConv** raw scalars (PrintConv is applied at emit
/// time by `serialize_tags`, mirroring ExifTool's
/// `$$self{OPTIONS}{PrintConv}` toggle). The audio frame header fields
/// (MPEG.pm:23-256) are mandatory; the Xing/Info VBR fields (MPEG.pm:323-
/// 337) and the LAME sub-table (MPEG.pm:339-382) are `Option<…>` because
/// they only appear in files carrying the post-header VBR/LAME annotation.
///
/// **D8 — no public fields, accessors only.**
///
/// **Lifetimes.** `MpegAudioMeta` borrows the LAME Encoder string from the
/// input buffer when it's a direct slice (LAME3.90+ 9-byte version or the
/// pre-3.90 20-byte fallback) — held as [`Cow::Borrowed`]. Synthesized
/// strings (`"RCA mp3PRO"`, `"Thomson mp3PRO <suffix>"`, `"Gogo (<3.0)"`)
/// use [`Cow::Owned`].
#[derive(Debug, Clone)]
pub struct MpegAudioMeta<'a> {
  // ───────────────────── Audio frame header (MPEG.pm:23-256) ─────────────────────
  /// Bit11-12 MPEGAudioVersion (MPEG.pm:25-33).
  mpeg_audio_version: MpegAudioVersion,
  /// Bit13-14 AudioLayer (MPEG.pm:34-42).
  audio_layer: AudioLayer,
  /// Bit16-19 AudioBitrate (MPEG.pm:44-164) — post-ValueConv from the
  /// per-(version, layer) hash; `Free` for raw=0.
  audio_bitrate: AudioBitrate,
  /// Bit20-21 SampleRate (MPEG.pm:166-196). Raw 0..2; the per-version
  /// PrintConv hash maps to Hz. `0` for unmapped (defensive — the check
  /// rejects raw=3).
  sample_rate_raw: u8,
  /// Bit24-25 ChannelMode (MPEG.pm:200-209).
  channel_mode: ChannelMode,
  /// Bit26 MSStereo (MPEG.pm:210-215) — emitted only when AudioLayer ==
  /// Layer III (raw=1). Raw 0 or 1.
  ms_stereo: Option<bool>,
  /// Bit26-27 ModeExtension (MPEG.pm:222-232) — emitted only when
  /// AudioLayer is Layer I or II.
  mode_extension: Option<ModeExtension>,
  /// Bit27 IntensityStereo (MPEG.pm:216-221) — emitted only when
  /// AudioLayer == Layer III. Raw 0 or 1.
  intensity_stereo: Option<bool>,
  /// Bit28 CopyrightFlag (MPEG.pm:233-239).
  copyright_flag: bool,
  /// Bit29 OriginalMedia (MPEG.pm:240-246).
  original_media: bool,
  /// Bit30-31 Emphasis (MPEG.pm:247-255).
  emphasis: Emphasis,
  // ───────────────────── Xing/Info VBR tail (MPEG.pm:501-578) ─────────────────────
  /// Xing key 1 — VBRFrames (MPEG.pm:327). Absent when not VBR / flag
  /// bit 0x01 unset / Info-frame / truncated.
  vbr_frames: Option<u32>,
  /// Xing key 2 — VBRBytes (MPEG.pm:328).
  vbr_bytes: Option<u32>,
  /// Xing key 3 — VBRScale (MPEG.pm:329).
  vbr_scale: Option<u32>,
  /// Xing key 4 — Encoder (MPEG.pm:330). Either a borrowed slice of the
  /// LAME version string (LAME3.90+ 9 bytes OR pre-3.90 20-byte
  /// fallback) or a synthesized owned `String` (RCA/THOMSON/MPGE).
  encoder: Option<Cow<'a, str>>,
  /// Xing key 5 — LameVBRQuality (MPEG.pm:331). `int((100-vbrScale)/10)`
  /// when LAME ≥ 3.90 AND `vbrScale ∈ [0, 100]` (with absent vbr_scale
  /// substituting 0 — bundled Perl's undef-promotes-to-0 semantics).
  lame_vbr_quality: Option<u8>,
  /// Xing key 6 — LameQuality (MPEG.pm:332). `(100-vbrScale) % 10`,
  /// same gates as `lame_vbr_quality`.
  lame_quality: Option<u8>,
  // ───────────────────── LAME sub-table (MPEG.pm:339-382) ─────────────────────
  /// MPEG::Lame offset 9 — LameMethod, mask 0x0f (no shift).
  lame_method: Option<LameMethod>,
  /// MPEG::Lame offset 10 — LameLowPassFilter, raw byte * 100.
  /// Stored as the post-ValueConv u32 (byte × 100); the PrintConv
  /// `($val / 1000) . " kHz"` is applied at sink time.
  lame_low_pass_filter: Option<u32>,
  /// MPEG::Lame offset 20 — LameBitrate, raw byte * 1000. Stored as
  /// post-ValueConv u32 bps; PrintConv ConvertBitrate at sink time.
  lame_bitrate: Option<u32>,
  /// MPEG::Lame offset 24 — LameStereoMode, mask 0x1c shifted right 2.
  lame_stereo_mode: Option<LameStereoMode>,
}

impl MpegAudioMeta<'_> {
  // ── Audio frame header accessors ───────────────────────────────────────

  /// MPEGAudioVersion (Bit11-12).
  #[must_use]
  pub fn mpeg_audio_version(&self) -> MpegAudioVersion {
    self.mpeg_audio_version
  }
  /// AudioLayer (Bit13-14).
  #[must_use]
  pub fn audio_layer(&self) -> AudioLayer {
    self.audio_layer
  }
  /// AudioBitrate (Bit16-19) — post-ValueConv `Free`/`Known(bps)`.
  #[must_use]
  pub fn audio_bitrate(&self) -> AudioBitrate {
    self.audio_bitrate
  }
  /// Raw SampleRate index (Bit20-21).
  #[must_use]
  pub fn sample_rate_raw(&self) -> u8 {
    self.sample_rate_raw
  }
  /// SampleRate in Hz from the per-version PrintConv hash; `None` if the
  /// raw value falls outside the table (defensive — the validation gate
  /// rejects raw=3).
  #[must_use]
  pub fn sample_rate_hz(&self) -> Option<u32> {
    sample_rate_lookup(self.mpeg_audio_version, self.sample_rate_raw)
  }
  /// ChannelMode (Bit24-25).
  #[must_use]
  pub fn channel_mode(&self) -> ChannelMode {
    self.channel_mode
  }
  /// MSStereo (Bit26) — emitted only for Layer III.
  #[must_use]
  pub fn ms_stereo(&self) -> Option<bool> {
    self.ms_stereo
  }
  /// ModeExtension (Bit26-27) — emitted only for Layer I/II.
  #[must_use]
  pub fn mode_extension(&self) -> Option<ModeExtension> {
    self.mode_extension
  }
  /// IntensityStereo (Bit27) — emitted only for Layer III.
  #[must_use]
  pub fn intensity_stereo(&self) -> Option<bool> {
    self.intensity_stereo
  }
  /// CopyrightFlag (Bit28).
  #[must_use]
  pub fn copyright_flag(&self) -> bool {
    self.copyright_flag
  }
  /// OriginalMedia (Bit29).
  #[must_use]
  pub fn original_media(&self) -> bool {
    self.original_media
  }
  /// Emphasis (Bit30-31).
  #[must_use]
  pub fn emphasis(&self) -> Emphasis {
    self.emphasis
  }

  // ── Xing tail accessors ────────────────────────────────────────────────

  /// VBRFrames (Xing key 1).
  #[must_use]
  pub fn vbr_frames(&self) -> Option<u32> {
    self.vbr_frames
  }
  /// VBRBytes (Xing key 2).
  #[must_use]
  pub fn vbr_bytes(&self) -> Option<u32> {
    self.vbr_bytes
  }
  /// VBRScale (Xing key 3).
  #[must_use]
  pub fn vbr_scale(&self) -> Option<u32> {
    self.vbr_scale
  }
  /// Encoder (Xing key 4) — `Cow<'a, str>` borrowed from input for LAME
  /// version strings; owned for synthesized fallback names.
  #[must_use]
  pub fn encoder(&self) -> Option<&str> {
    self.encoder.as_deref()
  }
  /// LameVBRQuality (Xing key 5).
  #[must_use]
  pub fn lame_vbr_quality(&self) -> Option<u8> {
    self.lame_vbr_quality
  }
  /// LameQuality (Xing key 6).
  #[must_use]
  pub fn lame_quality(&self) -> Option<u8> {
    self.lame_quality
  }

  // ── LAME sub-table accessors ───────────────────────────────────────────

  /// LameMethod (offset 9, mask 0x0f).
  #[must_use]
  pub fn lame_method(&self) -> Option<LameMethod> {
    self.lame_method
  }
  /// LameLowPassFilter (offset 10, ValueConv `* 100`).
  #[must_use]
  pub fn lame_low_pass_filter(&self) -> Option<u32> {
    self.lame_low_pass_filter
  }
  /// LameBitrate (offset 20, ValueConv `* 1000`).
  #[must_use]
  pub fn lame_bitrate(&self) -> Option<u32> {
    self.lame_bitrate
  }
  /// LameStereoMode (offset 24, mask 0x1c shifted right 2).
  #[must_use]
  pub fn lame_stereo_mode(&self) -> Option<LameStereoMode> {
    self.lame_stereo_mode
  }
}

// ===========================================================================
// Lookup tables — ValueConv hashes (MPEG.pm:44-196)
// ===========================================================================

/// MPEG.pm:44-164 — AudioBitrate ValueConv hash chooser. Returns the bps
/// for raw 1..14, `AudioBitrate::Free` for raw 0; raw 15 is rejected
/// upstream by `check_header`.
const fn audio_bitrate_lookup(
  version: MpegAudioVersion,
  layer: AudioLayer,
  raw: u8,
) -> AudioBitrate {
  // raw==0 ⇒ Free; raw==15 cannot reach this function (header validation rejects).
  if raw == 0 {
    return AudioBitrate::Free;
  }
  // MPEG.pm:50-66 / :74-90 / :98-114 / :122-138 / :146-162 tables.
  // Selected by (version, layer) — `V1` ↔ MPEG_Vers==3, `L1` ↔ MPEG_Layer==3
  // per the raw encoding (PrintConv inverts to display).
  let table: &[u32] = match (version, layer) {
    // MPEG.pm:44-68 — version 1 (V1), layer 1 (L1 display ⇒ raw L1).
    (MpegAudioVersion::V1, AudioLayer::L1) => &[
      32_000, 64_000, 96_000, 128_000, 160_000, 192_000, 224_000, 256_000, 288_000, 320_000,
      352_000, 384_000, 416_000, 448_000,
    ],
    // MPEG.pm:69-92 — version 1, layer 2.
    (MpegAudioVersion::V1, AudioLayer::L2) => &[
      32_000, 48_000, 56_000, 64_000, 80_000, 96_000, 112_000, 128_000, 160_000, 192_000, 224_000,
      256_000, 320_000, 384_000,
    ],
    // MPEG.pm:93-116 — version 1, layer 3.
    (MpegAudioVersion::V1, AudioLayer::L3) => &[
      32_000, 40_000, 48_000, 56_000, 64_000, 80_000, 96_000, 112_000, 128_000, 160_000, 192_000,
      224_000, 256_000, 320_000,
    ],
    // MPEG.pm:117-140 — version 2 or 2.5, layer 1.
    (MpegAudioVersion::V2 | MpegAudioVersion::V2_5, AudioLayer::L1) => &[
      32_000, 48_000, 56_000, 64_000, 80_000, 96_000, 112_000, 128_000, 144_000, 160_000, 176_000,
      192_000, 224_000, 256_000,
    ],
    // MPEG.pm:141-164 — version 2 or 2.5, layer 2 or 3.
    (MpegAudioVersion::V2 | MpegAudioVersion::V2_5, AudioLayer::L2 | AudioLayer::L3) => &[
      8_000, 16_000, 24_000, 32_000, 40_000, 48_000, 56_000, 64_000, 80_000, 96_000, 112_000,
      128_000, 144_000, 160_000,
    ],
  };
  // raw 1..14 indexes table[0..=13]. raw==15 rejected upstream — defensive
  // saturate to last entry. (Hand-written `min` to keep this `const fn` —
  // `usize::min` is not yet stable as a const-trait call.)
  let base = (raw as usize).saturating_sub(1);
  let last = table.len() - 1;
  let idx = if base < last { base } else { last };
  AudioBitrate::Known(table[idx])
}

/// MPEG.pm:166-196 — SampleRate PrintConv hash chooser. Raw 0..2 only;
/// raw==3 (reserved) rejected upstream by `check_header`.
const fn sample_rate_lookup(version: MpegAudioVersion, raw: u8) -> Option<u32> {
  // MPEG.pm:166-176 / :177-186 / :187-196 tables (3 entries each).
  let table: [u32; 3] = match version {
    MpegAudioVersion::V1 => [44_100, 48_000, 32_000], // MPEG.pm:166-176
    MpegAudioVersion::V2 => [22_050, 24_000, 16_000], // MPEG.pm:177-186
    MpegAudioVersion::V2_5 => [11_025, 12_000, 8_000], // MPEG.pm:187-196
  };
  match raw {
    0..=2 => Some(table[raw as usize]),
    _ => None,
  }
}

// ===========================================================================
// Header validation — MPEG.pm:474-490
// ===========================================================================

/// Reject-reason from header validation (MPEG.pm:474-490).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeaderCheck {
  /// All checks passed — emit.
  Ok,
  /// Top-11-bit sync failed (the `\xff` was a false alarm).
  Sync,
  /// One of the field validations failed.
  Validation,
}

/// Header validation per MPEG.pm:474-490. `word` is the 32-bit big-endian
/// audio-frame header. `mp3` is the MPEG.pm:485 `$mp3` flag: when set,
/// REQUIRE Layer III as well as the basic field validations.
fn check_header(word: u32, mp3: bool) -> HeaderCheck {
  // MPEG.pm:474 — top 11 bits all set.
  if (word & 0xffe0_0000) != 0xffe0_0000 {
    return HeaderCheck::Sync;
  }
  // MPEG.pm:479-485 — field validations.
  if (word & 0x0018_0000) == 0x0008_0000 // 01 is reserved version ID (MPEG.pm:479)
    || (word & 0x0006_0000) == 0x0000_0000 // 00 is reserved layer (MPEG.pm:480)
    || (word & 0x0000_f000) == 0x0000_0000 // 0000 is "free" bitrate (MPEG.pm:481)
    || (word & 0x0000_f000) == 0x0000_f000 // 1111 is bad bitrate (MPEG.pm:482)
    || (word & 0x0000_0c00) == 0x0000_0c00 // 11 is reserved sample rate (MPEG.pm:483)
    || (word & 0x0000_0003) == 0x0000_0002 // 10 is reserved emphasis (MPEG.pm:484)
    || (mp3 && (word & 0x0006_0000) != 0x0002_0000)
  // mp3-mode: require Layer III (MPEG.pm:485)
  {
    return HeaderCheck::Validation;
  }
  HeaderCheck::Ok
}

/// MPEG.pm:470-494 sync-scan loop. Returns `Some((word, pos_after))` where
/// `word` is the validated 4-byte big-endian header word and `pos_after`
/// is the Perl `pos($$buffPt)` right after the matched 4 bytes (MPEG.pm:
/// 492). Returns `None` when the buffer is exhausted (no valid header
/// found). The Xing/Info/LAME tail (MPEG.pm:501-578) reads relative to
/// `pos_after`.
fn scan_for_header(data: &[u8], mp3: bool, ext: &str) -> Option<(u32, usize)> {
  let mut p = 0usize;
  loop {
    // MPEG.pm:472 — `$$buffPt =~ m{(\xff.{3})}sg`. Find next `\xff`.
    let ff = data[p..].iter().position(|&b| b == 0xff)?;
    let start = p + ff;
    if start + 4 > data.len() {
      return None;
    }
    let word = u32::from_be_bytes([
      data[start],
      data[start + 1],
      data[start + 2],
      data[start + 3],
    ]);
    let next_pos = start + 4;
    match check_header(word, mp3) {
      HeaderCheck::Ok => return Some((word, next_pos)),
      HeaderCheck::Sync => {
        // MPEG.pm:474-476 — `pos -= 2`.
        p = next_pos.saturating_sub(2);
        if p <= start {
          p = start + 1;
        }
      }
      HeaderCheck::Validation => {
        // MPEG.pm:486-490 — give up unless $ext eq 'MP3'.
        if !ext.eq_ignore_ascii_case("MP3") {
          return None;
        }
        // MPEG.pm:489 — `pos -= 1`.
        p = next_pos.saturating_sub(1);
        if p <= start {
          p = start + 1;
        }
      }
    }
  }
}

// ===========================================================================
// Bit-field extraction from the 32-bit header word (MPEG.pm:23-256)
// ===========================================================================

/// Extract the typed audio-frame fields from the validated header word.
/// Faithful 1:1 of the `%MPEG::Audio` bit-key table: each tag's
/// `Bit<a>-<b>` is bits `[a..=b]` counting from MSB=0 of the 4-byte BE
/// header. `process_bit_stream_cond` reads the word as 32 BE bits, so
/// `Bit11-12` is `(word >> (31 - 12)) & 0x3` = `(word >> 19) & 0x3`.
fn extract_header_fields(word: u32) -> Option<MpegAudioMeta<'static>> {
  // Bit11-12: bits [11..=12] of the 32-bit BE word = mask 0x0018_0000, shift 19.
  let version_raw = ((word >> 19) & 0x03) as u8;
  let version = MpegAudioVersion::from_raw(version_raw)?;
  // Bit13-14: mask 0x0006_0000, shift 17.
  let layer_raw = ((word >> 17) & 0x03) as u8;
  let layer = AudioLayer::from_raw(layer_raw)?;
  // Bit16-19: mask 0x0000_f000, shift 12.
  let bitrate_raw = ((word >> 12) & 0x0f) as u8;
  let audio_bitrate = audio_bitrate_lookup(version, layer, bitrate_raw);
  // Bit20-21: mask 0x0000_0c00, shift 10.
  let sample_rate_raw = ((word >> 10) & 0x03) as u8;
  // Bit24-25: mask 0x0000_00c0, shift 6.
  let channel_raw = ((word >> 6) & 0x03) as u8;
  let channel_mode = ChannelMode::from_raw(channel_raw);
  // Layer III (raw L3 == 1) ⇒ MSStereo (Bit26) + IntensityStereo (Bit27).
  // Layer I/II (raw 2/3) ⇒ ModeExtension (Bit26-27).
  let ms_stereo;
  let intensity_stereo;
  let mode_extension;
  if matches!(layer, AudioLayer::L3) {
    // Bit26: mask 0x0000_0020, shift 5.
    ms_stereo = Some(((word >> 5) & 0x01) != 0);
    // Bit27: mask 0x0000_0010, shift 4.
    intensity_stereo = Some(((word >> 4) & 0x01) != 0);
    mode_extension = None;
  } else {
    // Bit26-27: mask 0x0000_0030, shift 4.
    let me_raw = ((word >> 4) & 0x03) as u8;
    mode_extension = Some(ModeExtension::from_raw(me_raw));
    ms_stereo = None;
    intensity_stereo = None;
  }
  // Bit28: mask 0x0000_0008, shift 3.
  let copyright_flag = ((word >> 3) & 0x01) != 0;
  // Bit29: mask 0x0000_0004, shift 2.
  let original_media = ((word >> 2) & 0x01) != 0;
  // Bit30-31: mask 0x0000_0003, shift 0.
  let emphasis_raw = (word & 0x03) as u8;
  let emphasis = Emphasis::from_raw(emphasis_raw);
  Some(MpegAudioMeta {
    mpeg_audio_version: version,
    audio_layer: layer,
    audio_bitrate,
    sample_rate_raw,
    channel_mode,
    ms_stereo,
    mode_extension,
    intensity_stereo,
    copyright_flag,
    original_media,
    emphasis,
    vbr_frames: None,
    vbr_bytes: None,
    vbr_scale: None,
    encoder: None,
    lame_vbr_quality: None,
    lame_quality: None,
    lame_method: None,
    lame_low_pass_filter: None,
    lame_bitrate: None,
    lame_stereo_mode: None,
  })
}

// ===========================================================================
// Xing/Info VBR tail + LAME sub-table (MPEG.pm:501-578)
// ===========================================================================

/// MPEG.pm:501-578 — the VBR Xing/Info + LAME header tail of
/// `ParseMPEGAudio`. Runs AFTER the audio frame header has been extracted;
/// reads relative to `pos`, the Perl `pos($$buffPt)` right after the 4-
/// byte header match. Mutates the typed `meta` in place; any length /
/// magic / state failure silently exits (Perl `last`) — leaving partial
/// progress.
fn parse_xing_lame_into<'a>(buff: &'a [u8], mut pos: usize, meta: &mut MpegAudioMeta<'a>) {
  // MPEG.pm:501-502 — `($$et{MPEG_Vers}, $$et{MPEG_Mode})` must be defined.
  let v = meta.mpeg_audio_version.raw();
  let m = meta.channel_mode.raw();
  let len = buff.len();
  // MPEG.pm:504 side-info offset:
  //   $v == 3 ? ($m == 3 ? 17 : 32) : ($m == 3 ? 9 : 17)
  let side = if v == 3 {
    if m == 3 { 17 } else { 32 }
  } else if m == 3 {
    9
  } else {
    17
  };
  pos = match pos.checked_add(side) {
    Some(n) => n,
    None => return,
  };
  // MPEG.pm:505 `last if $pos + 8 > $len`.
  if pos.checked_add(8).is_none_or(|end| end > len) {
    return;
  }
  // MPEG.pm:506 `my $buff = substr($$buffPt, $pos, 8)`.
  let head8 = &buff[pos..pos + 8];
  // MPEG.pm:508 `last unless $buff =~ /^(Xing|Info)/`.
  let magic_is_xing = head8.starts_with(b"Xing");
  let magic_is_info = head8.starts_with(b"Info");
  if !magic_is_xing && !magic_is_info {
    return;
  }
  // MPEG.pm:510 `my $flags = unpack('x4N', $buff)`.
  let flags = u32::from_be_bytes([head8[4], head8[5], head8[6], head8[7]]);
  // MPEG.pm:511 `my $isVBR = ($buff !~ /^Info/)`.
  let is_vbr = !magic_is_info;
  // MPEG.pm:512 `$pos += 8`.
  pos += 8;

  // MPEG.pm:513-517 — VBRFrames (key 1).
  let mut vbr_scale_inner: Option<u32> = None;
  if flags & 0x01 != 0 {
    if pos.checked_add(4).is_none_or(|end| end > len) {
      return;
    }
    if is_vbr {
      let n = u32::from_be_bytes([buff[pos], buff[pos + 1], buff[pos + 2], buff[pos + 3]]);
      meta.vbr_frames = Some(n);
    }
    pos += 4;
  }
  // MPEG.pm:518-522 — VBRBytes (key 2).
  if flags & 0x02 != 0 {
    if pos.checked_add(4).is_none_or(|end| end > len) {
      return;
    }
    if is_vbr {
      let n = u32::from_be_bytes([buff[pos], buff[pos + 1], buff[pos + 2], buff[pos + 3]]);
      meta.vbr_bytes = Some(n);
    }
    pos += 4;
  }
  // MPEG.pm:523-527 — TOC (skipped; 100 bytes, no tag).
  if flags & 0x04 != 0 {
    if pos.checked_add(100).is_none_or(|end| end > len) {
      return;
    }
    pos += 100;
  }
  // MPEG.pm:528-533 — VBRScale (key 3) AND captured for LameVBRQuality /
  // LameQuality at MPEG.pm:564-565.
  if flags & 0x08 != 0 {
    if pos.checked_add(4).is_none_or(|end| end > len) {
      return;
    }
    let n = u32::from_be_bytes([buff[pos], buff[pos + 1], buff[pos + 2], buff[pos + 3]]);
    vbr_scale_inner = Some(n);
    if is_vbr {
      meta.vbr_scale = Some(n);
    }
    pos += 4;
  }
  // MPEG.pm:535-558 — LAME branch.
  if flags & 0x10 != 0 {
    // MPEG.pm:537 `last if $pos + 348 > $len`.
    if pos.checked_add(348).is_none_or(|end| end > len) {
      return;
    }
  } else if pos.checked_add(4).is_some_and(|end| end <= len) {
    // MPEG.pm:538-557 — non-LAME-flag branch: identify alternate encoders.
    let lib = &buff[pos..pos + 4];
    if lib != b"LAME" && lib != b"GOGO" {
      // MPEG.pm:541-555 — fallback string matches across the whole buffer.
      let encoder_str: Option<Cow<'a, str>> = if find_subseq(buff, b"RCA mp3PRO Encoder").is_some()
      {
        // MPEG.pm:544 `$lib = 'RCA mp3PRO'`.
        Some(Cow::Owned(String::from("RCA mp3PRO")))
      } else if let Some(n) = find_subseq(buff, b"THOMSON mp3PRO Encoder") {
        // MPEG.pm:545 `$lib = 'Thomson mp3PRO'`; MPEG.pm:546 `$n += 22`;
        // MPEG.pm:547 `$lib .= ' ' . substr($$buffPt, $n, 6) if length(
        // $$buffPt) - $n >= 6`.
        let mut s = String::from("Thomson mp3PRO");
        let n2 = n + 22;
        if n2 <= len && len - n2 >= 6 {
          s.push(' ');
          // Use lossy UTF-8 conversion for the 6-byte suffix (defensive;
          // real files emit ASCII version tags).
          let suffix = &buff[n2..n2 + 6];
          s.push_str(&std::string::String::from_utf8_lossy(suffix));
        }
        Some(Cow::Owned(s))
      } else if find_subseq(buff, b"MPGE").is_some() {
        // MPEG.pm:549-550 `$lib = 'Gogo (<3.0)'`.
        Some(Cow::Owned(String::from("Gogo (<3.0)")))
      } else {
        // MPEG.pm:551 `last` — no recognized encoder.
        None
      };
      if let Some(s) = encoder_str {
        meta.encoder = Some(s);
      }
      // MPEG.pm:556 `last` — exit the tail regardless.
      return;
    }
    // lib == 'LAME' or 'GOGO' — fall through to the 9-byte LAME-version
    // check at MPEG.pm:559+.
  }
  // MPEG.pm:559-577 — LAME version + sub-table.
  let lame_len = len.saturating_sub(pos);
  if lame_len < 9 {
    return; // MPEG.pm:560 `last if $lameLen < 9`.
  }
  let enc = &buff[pos..pos + 9];
  // MPEG.pm:562 `if ($enc ge 'LAME3.90')` — Perl `ge` is bytewise ASCII.
  if enc >= b"LAME3.90" as &[u8] {
    // MPEG.pm:563 emit Encoder as the 9-byte version string. Borrow from
    // input when the bytes are valid UTF-8 (every real LAME-3.90+ tag is
    // printable ASCII). Defensive lossy fallback otherwise.
    let enc_cow = match core::str::from_utf8(enc) {
      Ok(s) => Cow::Borrowed(s),
      Err(_) => Cow::Owned(std::string::String::from_utf8_lossy(enc).into_owned()),
    };
    meta.encoder = Some(enc_cow);
    // MPEG.pm:563-565 — LameVBRQuality / LameQuality fire whenever
    // `$vbrScale <= 100`. Bundled Perl: when the Xing flags don't set the
    // VBRScale bit (0x08), `$vbrScale` stays undef and Perl's `<=` numeric
    // comparison treats undef as 0 (with a runtime warning). Faithful:
    // substitute 0 when `vbr_scale_inner` is None.
    let scale = vbr_scale_inner.unwrap_or(0);
    if scale <= 100 {
      meta.lame_vbr_quality = Some(((100 - scale) / 10) as u8);
      meta.lame_quality = Some(((100 - scale) % 10) as u8);
    }
    // MPEG.pm:568-573 — ProcessDirectory %MPEG::Lame at DirStart=$pos
    // over the rest of the buffer.
    parse_lame_into(buff, pos, meta);
  } else {
    // MPEG.pm:575 — non-LAME-≥3.90 fallback: emit Encoder as a 20-byte
    // substring (cropped to remaining bytes).
    let want = pos + 20;
    let end = want.min(len);
    let slice = &buff[pos..end];
    let enc_cow = match core::str::from_utf8(slice) {
      Ok(s) => Cow::Borrowed(s),
      Err(_) => Cow::Owned(std::string::String::from_utf8_lossy(slice).into_owned()),
    };
    meta.encoder = Some(enc_cow);
  }
}

/// Search for `needle` anywhere within `haystack`, returning the byte
/// offset of the first occurrence. Faithful to Perl `index($buff, $needle)
/// >= 0` (MPEG.pm:542/544/551) with the offset captured (the `THOMSON`
/// branch needs `$n` for the version suffix at MPEG.pm:546-547).
fn find_subseq(haystack: &[u8], needle: &[u8]) -> Option<usize> {
  if needle.is_empty() || needle.len() > haystack.len() {
    return None;
  }
  haystack.windows(needle.len()).position(|w| w == needle)
}

/// Faithful port of `ProcessBinaryData` applied to `%MPEG::Lame` at
/// `DirStart=$pos` with the buffer running to its end (MPEG.pm:568-573).
/// Inlined here because `ProcessBinaryData` is otherwise unported.
fn parse_lame_into<'a>(buff: &'a [u8], pos: usize, meta: &mut MpegAudioMeta<'a>) {
  let read_byte = |offset: usize| -> Option<u8> {
    let abs = pos.checked_add(offset)?;
    if abs < buff.len() {
      Some(buff[abs])
    } else {
      None
    }
  };
  // Offset 9: LameMethod, Mask 0x0f.
  if let Some(b) = read_byte(9) {
    meta.lame_method = Some(LameMethod::from_raw(b & 0x0f));
  }
  // Offset 10: LameLowPassFilter, ValueConv `$val * 100`.
  if let Some(b) = read_byte(10) {
    meta.lame_low_pass_filter = Some(u32::from(b) * 100);
  }
  // Offset 20: LameBitrate, ValueConv `$val * 1000`.
  if let Some(b) = read_byte(20) {
    meta.lame_bitrate = Some(u32::from(b) * 1000);
  }
  // Offset 24: LameStereoMode, Mask 0x1c shifted right 2.
  if let Some(b) = read_byte(24) {
    meta.lame_stereo_mode = Some(LameStereoMode::from_raw((b & 0x1c) >> 2));
  }
}

// ===========================================================================
// `MpegAudioContext` — per-format Context<'a> (spec §6.4)
// ===========================================================================

/// Per-format input view threaded into [`ProcessMpegAudio::parse`].
///
/// Spec §6.4 — leaf-but-chained: this format takes an already-bounded byte
/// slice (the caller's `ProcessMp3::process_with_start_offset` applies
/// the ID3.pm:1704 `$scanLen` bound BEFORE delegating). The `mp3` flag is
/// derived from the file extension by the caller per ID3.pm:1715-1717 (a
/// `.mus` extension drops the Layer III gate); `ext` is preserved for the
/// MPEG.pm:486-490 `give up unless $ext eq 'MP3'` retry on validation
/// reject.
///
/// The `&'a mut SharedFlags` reborrow is held for API-shape parity with
/// the spec §6.4 chained-format Context; the MPEG audio parser itself
/// neither reads nor writes any shared flag (the cross-format flags
/// `DoneID3` / `DoneAPE` are touched by the ID3/APE pair, not here).
pub struct MpegAudioContext<'a> {
  data: &'a [u8],
  /// MPEG.pm:466 `$mp3` — REQUIRE Layer III when set. Set by the caller
  /// from the file extension (ID3.pm:1715-1717: `$ext eq 'MUS' ? 0 : 1`).
  mp3: bool,
  /// Uppercased file extension (e.g. `"MP3"`, `"MUS"`). MPEG.pm:468 reads
  /// `$$et{FILE_EXT}`; the sync-scan uses this for the
  /// validation-reject-retry gate at MPEG.pm:488 (`return 0 unless $ext
  /// eq 'MP3'`).
  ext: &'a str,
  /// Shared cross-format flags — held for API-shape parity (spec §6.4);
  /// unused by this format's parser.
  #[allow(dead_code)]
  shared: &'a mut SharedFlags,
}

impl<'a> MpegAudioContext<'a> {
  /// Construct a context from an already-bounded byte slice + the file
  /// extension (uppercased; the empty string disables the
  /// validation-reject retry) + the caller-derived `mp3` flag.
  ///
  /// The `data` slice MUST be pre-bounded by the caller to the
  /// ID3.pm:1704 `$scanLen` window (8192 for `.mp3`, 256 otherwise) —
  /// `ProcessMp3::process_with_start_offset` applies that bound.
  pub fn new(data: &'a [u8], ext: &'a str, mp3: bool, shared: &'a mut SharedFlags) -> Self {
    Self {
      data,
      mp3,
      ext,
      shared,
    }
  }

  /// Borrow the input bytes.
  #[must_use]
  pub fn data(&self) -> &'a [u8] {
    self.data
  }
  /// Borrow the file extension string.
  #[must_use]
  pub fn ext(&self) -> &'a str {
    self.ext
  }
  /// The MPEG.pm:466 `$mp3` flag.
  #[must_use]
  pub fn mp3(&self) -> bool {
    self.mp3
  }
}

// ===========================================================================
// `ProcessMpegAudio` — the lib-first parser
// ===========================================================================

/// MPEG audio frame parser — faithful port of
/// `Image::ExifTool::MPEG::ParseMPEGAudio` (MPEG.pm:464-580). Reads a
/// 4-byte sync header followed by the optional Xing/Info VBR + LAME tail.
#[derive(Debug, Clone, Copy)]
pub struct ProcessMpegAudio;

impl parser_sealed::Sealed for ProcessMpegAudio {}

impl FormatParser for ProcessMpegAudio {
  /// GAT: the Meta borrows its `encoder` field from the input `'a` (Codex
  /// AF2).
  type Meta<'a> = MpegAudioMeta<'a>;
  type Context<'a> = MpegAudioContext<'a>;
  type Error = MpegAudioError;

  fn parse<'a>(&self, ctx: Self::Context<'a>) -> Result<Option<Self::Meta<'a>>, MpegAudioError> {
    parse_inner(ctx.data, ctx.mp3, ctx.ext)
  }
}

/// Lib-first direct entry. Same as [`FormatParser::parse`] but returns an
/// [`MpegAudioMeta`] that borrows from the input buffer (Encoder field).
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today; reserved for
/// future I/O wrappers).
pub fn parse_borrowed<'a>(
  data: &'a [u8],
  mp3: bool,
  ext: &str,
) -> Result<Option<MpegAudioMeta<'a>>, MpegAudioError> {
  parse_inner(data, mp3, ext)
}

/// Inner parser — produces a borrow-from-input [`MpegAudioMeta`] (the
/// `encoder` field borrows from `data`). The [`FormatParser::Meta`] GAT
/// (`type Meta<'a> = MpegAudioMeta<'a>`) returns this borrowed form
/// directly into the closed [`crate::parser_new::AnyMeta`] enum (Codex AF2).
fn parse_inner<'a>(
  data: &'a [u8],
  mp3: bool,
  ext: &str,
) -> Result<Option<MpegAudioMeta<'a>>, MpegAudioError> {
  // MPEG.pm:472 — `$$buffPt =~ m{(\xff.{3})}sg`. Returns `None` ⇒ Ok(None)
  // (Perl `return 0` BEFORE `$et->SetFileType()` at MPEG.pm:496).
  let (word, pos_after_header) = match scan_for_header(data, mp3, ext) {
    Some(pair) => pair,
    None => return Ok(None),
  };
  // MPEG.pm:498-499 — `ProcessFrameHeader($et, $tagTablePtr, $word)`. The
  // validated header word is bit-extracted into typed fields.
  let mut meta = match extract_header_fields(word) {
    Some(m) => m,
    // Defensive: `extract_header_fields` returns None only when the
    // version/layer raw values are reserved. `check_header` already
    // rejected those; treat as unreachable but defensive.
    None => return Ok(None),
  };
  // MPEG.pm:501-578 — Xing/Info VBR + LAME tail. Reads relative to
  // `pos_after_header`. The tail's `last` exits leave whatever was already
  // emitted in `meta` in place; the call always returns to the caller
  // (no fatal modes).
  parse_xing_lame_into(data, pos_after_header, &mut meta);
  Ok(Some(meta))
}

// ===========================================================================
// `serialize_tags` — typed Meta → TagMap
// ===========================================================================

#[cfg(feature = "alloc")]
impl MpegAudioMeta<'_> {
  /// Emit MPEG tags into the writer in `%MPEG::Audio` walk order
  /// (Bit11-12 → … → Bit30-31) then `%MPEG::Xing` keys 1..6 then
  /// `%MPEG::Lame` offsets 9/10/20/24 — faithful to MPEG.pm:23-256 +
  /// 323-337 + 339-382 iteration order.
  ///
  /// `print_conv=true` ⇒ PrintConv formatted strings (`-j` mode);
  /// `print_conv=false` ⇒ post-ValueConv raw scalars (`-n` mode).
  pub(crate) fn serialize_tags(
    &self,
    print_conv: bool,
    out: &mut crate::tagmap::TagMap,
  ) -> Result<(), core::convert::Infallible> {
    const GROUP: &str = "MPEG";

    // ─── Bit11-12 MPEGAudioVersion ────────────────────────────────────
    // -j (PrintConv hash): 0 → 2.5 (f64), 2 → 2 (i64), 3 → 1 (i64).
    // -n (raw): u8 of the on-disk 2-bit field.
    if print_conv {
      match self.mpeg_audio_version {
        MpegAudioVersion::V2_5 => out.write_f64(GROUP, "MPEGAudioVersion", 2.5)?,
        MpegAudioVersion::V2 => out.write_u64(GROUP, "MPEGAudioVersion", 2)?,
        MpegAudioVersion::V1 => out.write_u64(GROUP, "MPEGAudioVersion", 1)?,
      }
    } else {
      out.write_u64(
        GROUP,
        "MPEGAudioVersion",
        u64::from(self.mpeg_audio_version.raw()),
      )?;
    }

    // ─── Bit13-14 AudioLayer ──────────────────────────────────────────
    // -j (PrintConv hash): 1 → 3, 2 → 2, 3 → 1.
    // -n (raw): u8 1..3 on-disk.
    if print_conv {
      out.write_u64(GROUP, "AudioLayer", u64::from(self.audio_layer.display()))?;
    } else {
      out.write_u64(GROUP, "AudioLayer", u64::from(self.audio_layer.raw()))?;
    }

    // ─── Bit16-19 AudioBitrate ────────────────────────────────────────
    // -j: ConvertBitrate string. -n: post-ValueConv u32 OR the "free"
    // sentinel string passthrough.
    match (self.audio_bitrate, print_conv) {
      (AudioBitrate::Free, _) => {
        // "free" sentinel under -j: ConvertBitrate IsFloat-rejects ⇒
        // returns the string unchanged. Under -n: bare ValueConv
        // value is the string "free". Same emission either way.
        out.write_str(GROUP, "AudioBitrate", "free")?;
      }
      (AudioBitrate::Known(bps), true) => {
        out.write_fmt(GROUP, "AudioBitrate", |w| {
          write_convert_bitrate(w, f64::from(bps))
        })?;
      }
      (AudioBitrate::Known(bps), false) => {
        out.write_u64(GROUP, "AudioBitrate", u64::from(bps))?;
      }
    }

    // ─── Bit20-21 SampleRate ──────────────────────────────────────────
    // -j (PrintConv hash): Hz integer from per-version table.
    // -n (raw): u8 0..2 on-disk (no ValueConv).
    if print_conv {
      // If the version/raw combo is out of table (defensive), bundled
      // ExifTool falls back to "Unknown (raw)" via PrintConv default
      // — but raw=3 is rejected by `check_header`, so this branch is
      // unreachable from a successful parse. Emit raw as u64 as a
      // defensive fallback.
      if let Some(hz) = self.sample_rate_hz() {
        out.write_u64(GROUP, "SampleRate", u64::from(hz))?;
      } else {
        out.write_u64(GROUP, "SampleRate", u64::from(self.sample_rate_raw))?;
      }
    } else {
      out.write_u64(GROUP, "SampleRate", u64::from(self.sample_rate_raw))?;
    }

    // ─── Bit24-25 ChannelMode ─────────────────────────────────────────
    // -j: PrintConv string. -n: raw u8.
    if print_conv {
      out.write_str(GROUP, "ChannelMode", self.channel_mode.print_conv())?;
    } else {
      out.write_u64(GROUP, "ChannelMode", u64::from(self.channel_mode.raw()))?;
    }

    // ─── Bit26 MSStereo (Layer III only) ──────────────────────────────
    // -j: "Off" / "On". -n: 0 / 1.
    if let Some(b) = self.ms_stereo {
      if print_conv {
        out.write_str(GROUP, "MSStereo", if b { "On" } else { "Off" })?;
      } else {
        out.write_u64(GROUP, "MSStereo", u64::from(b))?;
      }
    }

    // ─── Bit26-27 ModeExtension (Layer I/II only) ─────────────────────
    // NOTE: bundled `sort keys %$tagTablePtr` orders `Bit26` <
    // `Bit26-27` < `Bit27` (lex). For Layer III the chooser emits
    // MSStereo (Bit26) and IntensityStereo (Bit27) and skips Bit26-27;
    // for Layer I/II it emits ModeExtension (Bit26-27) and skips
    // Bit26 + Bit27. Either way the emission order is monotonic.
    if let Some(me) = self.mode_extension {
      if print_conv {
        out.write_str(GROUP, "ModeExtension", me.print_conv())?;
      } else {
        out.write_u64(GROUP, "ModeExtension", u64::from(me.raw()))?;
      }
    }

    // ─── Bit27 IntensityStereo (Layer III only) ───────────────────────
    if let Some(b) = self.intensity_stereo {
      if print_conv {
        out.write_str(GROUP, "IntensityStereo", if b { "On" } else { "Off" })?;
      } else {
        out.write_u64(GROUP, "IntensityStereo", u64::from(b))?;
      }
    }

    // ─── Bit28 CopyrightFlag ──────────────────────────────────────────
    // -j: "True" / "False" — serialize.rs translates the Str("True")
    // / Str("False") into JSON booleans `true` / `false` (bundled
    // quirk handled engine-side). -n: 0 / 1.
    if print_conv {
      out.write_str(
        GROUP,
        "CopyrightFlag",
        if self.copyright_flag { "True" } else { "False" },
      )?;
    } else {
      out.write_u64(GROUP, "CopyrightFlag", u64::from(self.copyright_flag))?;
    }

    // ─── Bit29 OriginalMedia ──────────────────────────────────────────
    if print_conv {
      out.write_str(
        GROUP,
        "OriginalMedia",
        if self.original_media { "True" } else { "False" },
      )?;
    } else {
      out.write_u64(GROUP, "OriginalMedia", u64::from(self.original_media))?;
    }

    // ─── Bit30-31 Emphasis ────────────────────────────────────────────
    // -j: PrintConv string. -n: raw u8.
    if print_conv {
      out.write_str(GROUP, "Emphasis", self.emphasis.print_conv())?;
    } else {
      out.write_u64(GROUP, "Emphasis", u64::from(self.emphasis.raw()))?;
    }

    // ─── Xing keys 1..6 (MPEG.pm:327-332) ─────────────────────────────
    // VBRFrames / VBRBytes / VBRScale / Encoder / LameVBRQuality /
    // LameQuality — bare integers and the Encoder ASCII string.
    if let Some(n) = self.vbr_frames {
      out.write_u64(GROUP, "VBRFrames", u64::from(n))?;
    }
    if let Some(n) = self.vbr_bytes {
      out.write_u64(GROUP, "VBRBytes", u64::from(n))?;
    }
    if let Some(n) = self.vbr_scale {
      out.write_u64(GROUP, "VBRScale", u64::from(n))?;
    }
    if let Some(s) = self.encoder.as_deref() {
      out.write_str(GROUP, "Encoder", s)?;
    }
    if let Some(n) = self.lame_vbr_quality {
      out.write_u64(GROUP, "LameVBRQuality", u64::from(n))?;
    }
    if let Some(n) = self.lame_quality {
      out.write_u64(GROUP, "LameQuality", u64::from(n))?;
    }

    // ─── LAME sub-table offsets 9/10/20/24 (MPEG.pm:344-381) ──────────

    if let Some(method) = self.lame_method {
      if print_conv {
        if let Some(name) = method.print_conv() {
          out.write_str(GROUP, "LameMethod", name)?;
        } else {
          // PrintConv hash miss: bundled emits the raw integer
          // (PrintConv hash with no default — Perl's $$conv{$val}
          // returns undef ⇒ HandleTag returns the input unchanged).
          out.write_u64(GROUP, "LameMethod", u64::from(method.raw()))?;
        }
      } else {
        out.write_u64(GROUP, "LameMethod", u64::from(method.raw()))?;
      }
    }
    if let Some(v) = self.lame_low_pass_filter {
      if print_conv {
        out.write_fmt(GROUP, "LameLowPassFilter", |w| {
          write_lame_lowpass(w, f64::from(v))
        })?;
      } else {
        out.write_u64(GROUP, "LameLowPassFilter", u64::from(v))?;
      }
    }
    if let Some(v) = self.lame_bitrate {
      if print_conv {
        out.write_fmt(GROUP, "LameBitrate", |w| {
          write_convert_bitrate(w, f64::from(v))
        })?;
      } else {
        out.write_u64(GROUP, "LameBitrate", u64::from(v))?;
      }
    }
    if let Some(stereo) = self.lame_stereo_mode {
      if print_conv {
        if let Some(name) = stereo.print_conv() {
          out.write_str(GROUP, "LameStereoMode", name)?;
        } else {
          out.write_u64(GROUP, "LameStereoMode", u64::from(stereo.raw()))?;
        }
      } else {
        out.write_u64(GROUP, "LameStereoMode", u64::from(stereo.raw()))?;
      }
    }

    Ok(())
  }
}

// ===========================================================================
// `MpegAudioError` — Rust-level fatal modes (currently none)
// ===========================================================================

/// Rust-level fatal modes for MPEG audio parsing. Currently empty — every
/// bad input produces `Ok(None)` (Perl `return 0`). Reserved for future
/// I/O wrappers if streaming readers are added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpegAudioError {}

impl core::fmt::Display for MpegAudioError {
  fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match *self {}
  }
}

#[cfg(feature = "std")]
impl std::error::Error for MpegAudioError {}

// ===========================================================================
// `ProcessMp3` — raw MPEG-audio entry preserving R5 fix API
// ===========================================================================

/// MP3 / MPEG audio-frame parser handle. The `"MP3"` file-type slot in
/// [`crate::parser_new::any_parser_for`] always routes to
/// [`crate::formats::id3::ProcessMp3`] (the ID3 wrapper); this struct's
/// [`ProcessMp3::process_with_start_offset`] is the load-bearing entry for
/// that wrapper's chained MPEG-audio invocation — its public method
/// signature is preserved verbatim from the R5 fix.
pub struct ProcessMp3;

/// ID3.pm:1704 — `$scanLen` selection. Constant-fold-friendly helper so
/// the bound is documented at the call site AND in unit tests.
#[must_use]
pub(crate) const fn id3_process_mp3_scan_len(ext_is_mp3: bool) -> usize {
  if ext_is_mp3 { 8192 } else { 256 }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;
  use crate::tagmap::TagMap;

  // ───────────────────────── check_header ─────────────────────────

  #[test]
  fn check_header_basic_acceptance() {
    // MPEG-1 Layer III, 128 kbps / 44.1 kHz / Joint Stereo: 0xfffb904c.
    assert_eq!(check_header(0xfffb_904c, false), HeaderCheck::Ok);
    assert_eq!(check_header(0xfffb_904c, true), HeaderCheck::Ok);
  }

  #[test]
  fn check_header_rejects_each_invalid_field() {
    // MPEG.pm:479 — reserved version (Bit11-12 = 0b01).
    assert_eq!(check_header(0xffeb_9040, false), HeaderCheck::Validation);
    // MPEG.pm:480 — reserved layer.
    assert_eq!(check_header(0xfff9_9040, false), HeaderCheck::Validation);
    // MPEG.pm:481 — "free" bitrate.
    assert_eq!(check_header(0xfffb_0040, false), HeaderCheck::Validation);
    // MPEG.pm:482 — bad bitrate.
    assert_eq!(check_header(0xfffb_f040, false), HeaderCheck::Validation);
    // MPEG.pm:483 — reserved sample-rate.
    assert_eq!(check_header(0xfffb_9c40, false), HeaderCheck::Validation);
    // MPEG.pm:484 — reserved emphasis.
    assert_eq!(check_header(0xfffb_9042, false), HeaderCheck::Validation);
  }

  #[test]
  fn check_header_sync_reject() {
    assert_eq!(check_header(0x7fff_904c, false), HeaderCheck::Sync);
  }

  #[test]
  fn check_header_mp3_mode_rejects_non_layer3() {
    // Layer II under mp3-mode ⇒ Validation reject. (0xfffb→0xfffd toggles Bit13-14.)
    assert_eq!(check_header(0xfffd_904c, true), HeaderCheck::Validation);
    // Same header is Ok outside mp3-mode.
    assert_eq!(check_header(0xfffd_904c, false), HeaderCheck::Ok);
  }

  // ───────────────────────── scan_for_header ─────────────────────────

  #[test]
  fn scan_finds_header_at_offset() {
    let mut data = vec![0x00u8, 0x12, 0x34];
    data.extend_from_slice(&0xfffb_904c_u32.to_be_bytes());
    data.extend(std::iter::repeat(0).take(413));
    assert_eq!(scan_for_header(&data, false, "MP3"), Some((0xfffb_904c, 7)));
  }

  #[test]
  fn scan_skips_false_ff_then_finds_real_header() {
    let mut data = vec![0xff, 0x12, 0x34, 0x56];
    data.extend_from_slice(&0xfffb_904c_u32.to_be_bytes());
    assert_eq!(scan_for_header(&data, false, "MP3"), Some((0xfffb_904c, 8)));
  }

  #[test]
  fn scan_validation_reject_outside_mp3_ext_gives_up() {
    let data = [0xff, 0xfb, 0x00, 0x40];
    assert!(scan_for_header(&data, false, "WAV").is_none());
  }

  #[test]
  fn scan_validation_reject_inside_mp3_ext_keeps_scanning() {
    let mut data = vec![0xff, 0xfb, 0x00, 0x40];
    data.extend_from_slice(&0xfffb_904c_u32.to_be_bytes());
    assert_eq!(scan_for_header(&data, false, "MP3"), Some((0xfffb_904c, 8)));
  }

  // ───────────────────────── typed Meta extraction ─────────────────────────

  #[test]
  fn extract_header_fields_decodes_v1_l3_128k_441_js() {
    let m = extract_header_fields(0xfffb_904c).expect("typed extraction");
    assert_eq!(m.mpeg_audio_version(), MpegAudioVersion::V1);
    assert_eq!(m.audio_layer(), AudioLayer::L3);
    assert_eq!(m.audio_bitrate(), AudioBitrate::Known(128_000));
    assert_eq!(m.sample_rate_raw(), 0);
    assert_eq!(m.sample_rate_hz(), Some(44_100));
    assert_eq!(m.channel_mode(), ChannelMode::JointStereo);
    assert_eq!(m.ms_stereo(), Some(false));
    assert_eq!(m.intensity_stereo(), Some(false));
    assert_eq!(m.mode_extension(), None); // Layer III ⇒ no mode extension
    assert!(m.copyright_flag());
    assert!(m.original_media());
    assert_eq!(m.emphasis(), Emphasis::None);
  }

  #[test]
  fn extract_header_fields_decodes_layer2_mode_extension() {
    // Layer II header: 0xfffd904c — V1, L2 (raw=2), 160 kbps (raw=9 → V1L2[8]=160000),
    // sample rate index 0 (44100), JS, ME raw=0 ("Bands 4-31").
    let m = extract_header_fields(0xfffd_904c).expect("layer 2 extraction");
    assert_eq!(m.audio_layer(), AudioLayer::L2);
    assert_eq!(m.audio_bitrate(), AudioBitrate::Known(160_000));
    assert_eq!(m.ms_stereo(), None);
    assert_eq!(m.intensity_stereo(), None);
    assert_eq!(m.mode_extension(), Some(ModeExtension::Bands4to31));
  }

  // ───────────────────────── parse_borrowed direct entry ─────────────────────────

  #[test]
  fn parse_borrowed_extracts_fixture_fields() {
    // Bundled fixture MP3.mp3 — 4-byte canonical header at offset 0 +
    // payload bytes; the Xing tail is absent (no Xing/Info magic).
    let bytes = std::fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/MP3.mp3"),
    )
    .expect("read MP3.mp3 fixture");
    let meta = parse_borrowed(&bytes, true, "MP3")
      .expect("ok")
      .expect("parsed");
    assert_eq!(meta.mpeg_audio_version(), MpegAudioVersion::V1);
    assert_eq!(meta.audio_layer(), AudioLayer::L3);
    assert_eq!(meta.audio_bitrate(), AudioBitrate::Known(128_000));
    assert_eq!(meta.sample_rate_hz(), Some(44_100));
    assert_eq!(meta.channel_mode(), ChannelMode::JointStereo);
    assert_eq!(meta.encoder(), None); // no Xing/Info magic
  }

  #[test]
  fn parse_borrowed_rejects_short_buffer() {
    assert!(parse_borrowed(&[], true, "MP3").unwrap().is_none());
    assert!(
      parse_borrowed(&[0xff, 0xfb], true, "MP3")
        .unwrap()
        .is_none()
    );
  }

  #[test]
  fn parse_borrowed_rejects_bad_sync() {
    let data = [0x00; 32];
    assert!(parse_borrowed(&data, true, "MP3").unwrap().is_none());
  }

  // ───────────────────────── ConvertBitrate ─────────────────────────

  fn fmt_bitrate(b: f64) -> std::string::String {
    let mut s = std::string::String::new();
    write_convert_bitrate(&mut s, b).unwrap();
    s
  }

  #[test]
  fn convert_bitrate_matches_perl_oracle() {
    assert_eq!(fmt_bitrate(8_000.0), "8 kbps");
    assert_eq!(fmt_bitrate(64_000.0), "64 kbps");
    assert_eq!(fmt_bitrate(128_000.0), "128 kbps");
    assert_eq!(fmt_bitrate(320_000.0), "320 kbps");
    assert_eq!(fmt_bitrate(448_000.0), "448 kbps");
    assert_eq!(fmt_bitrate(1_000_000.0), "1 Mbps");
    assert_eq!(fmt_bitrate(2_500_000.0), "2.5 Mbps");
    assert_eq!(fmt_bitrate(10_000_000_000.0), "10 Gbps");
  }

  // ───────────────────────── LameLowPass ─────────────────────────

  fn fmt_lowpass(v: f64) -> std::string::String {
    let mut s = std::string::String::new();
    write_lame_lowpass(&mut s, v).unwrap();
    s
  }

  #[test]
  fn lame_lowpass_integer_and_fractional() {
    assert_eq!(fmt_lowpass(16_000.0), "16 kHz");
    assert_eq!(fmt_lowpass(16_500.0), "16.5 kHz");
  }

  // ───────────────────────── serialize_tags (TagMap) ─────────────────────────

  fn collect(buf: &[u8], print_conv: bool) -> TagMap {
    let mut w = TagMap::new();
    let meta = parse_borrowed(buf, true, "MP3")
      .expect("ok")
      .expect("parsed");
    meta.serialize_tags(print_conv, &mut w).unwrap();
    w
  }

  #[test]
  fn meta_sinker_emits_expected_tags_print_on() {
    // Synthesized canonical Layer III header + zero payload.
    let mut data = vec![0xff, 0xfb, 0x90, 0x4c];
    data.extend(std::iter::repeat(0).take(413));
    let w = collect(&data, true);
    let g = |n: &str| w.get_str("MPEG", n);
    assert_eq!(g("MPEGAudioVersion"), Some("1".into()));
    assert_eq!(g("AudioLayer"), Some("3".into()));
    assert_eq!(g("AudioBitrate"), Some("128 kbps".into()));
    assert_eq!(g("SampleRate"), Some("44100".into()));
    assert_eq!(g("ChannelMode"), Some("Joint Stereo".into()));
    assert_eq!(g("MSStereo"), Some("Off".into()));
    assert_eq!(g("IntensityStereo"), Some("Off".into()));
    assert_eq!(g("CopyrightFlag"), Some("True".into()));
    assert_eq!(g("OriginalMedia"), Some("True".into()));
    assert_eq!(g("Emphasis"), Some("None".into()));
    // No Xing tail.
    assert_eq!(g("VBRFrames"), None);
    assert_eq!(g("Encoder"), None);
  }

  #[test]
  fn meta_sinker_emits_expected_tags_print_off() {
    let mut data = vec![0xff, 0xfb, 0x90, 0x4c];
    data.extend(std::iter::repeat(0).take(413));
    let w = collect(&data, false);
    let g = |n: &str| w.get_str("MPEG", n);
    // -n: raw on-disk values + post-ValueConv numerics.
    assert_eq!(g("MPEGAudioVersion"), Some("3".into())); // raw V1==3
    assert_eq!(g("AudioLayer"), Some("1".into())); // raw L3==1
    assert_eq!(g("AudioBitrate"), Some("128000".into())); // post-VC u32
    assert_eq!(g("SampleRate"), Some("0".into())); // raw 0 (no VC in this tag)
    assert_eq!(g("ChannelMode"), Some("1".into())); // raw JS==1
    assert_eq!(g("MSStereo"), Some("0".into()));
    assert_eq!(g("IntensityStereo"), Some("0".into()));
    assert_eq!(g("CopyrightFlag"), Some("1".into()));
    assert_eq!(g("OriginalMedia"), Some("1".into()));
    assert_eq!(g("Emphasis"), Some("0".into()));
  }

  // ───────────────────────── Xing/LAME tail ─────────────────────────

  /// Build a minimal VBR Xing+LAME MP3 in memory: header 0xfffb_904c
  /// (MPEG-1 / Layer III / 128 kbps / 44.1 kHz / JointStereo) + 32-byte
  /// side-info + "Xing"+flags+VBRFrames/Bytes+TOC+Scale + 348-byte LAME
  /// block (`LAME3.99r\x04\xa0...0x80...0x0c...`).
  fn build_vbr_xing_lame_fixture() -> std::vec::Vec<u8> {
    let mut d = std::vec::Vec::with_capacity(504);
    d.extend_from_slice(&0xfffb_904c_u32.to_be_bytes());
    d.extend(std::iter::repeat(0).take(32));
    d.extend_from_slice(b"Xing");
    d.extend_from_slice(&0x1fu32.to_be_bytes()); // frames|bytes|toc|scale|lame
    d.extend_from_slice(&1000u32.to_be_bytes());
    d.extend_from_slice(&200_000u32.to_be_bytes());
    d.extend(std::iter::repeat(0).take(100));
    d.extend_from_slice(&78u32.to_be_bytes());
    let start = d.len();
    d.extend(std::iter::repeat(0).take(348));
    let stamp = |buf: &mut std::vec::Vec<u8>, off: usize, b: u8| buf[start + off] = b;
    for (i, b) in b"LAME3.99r".iter().enumerate() {
      stamp(&mut d, i, *b);
    }
    stamp(&mut d, 9, 0x04); // LameMethod: mask 0x0f → 4 → "VBR (new/mtrh)"
    stamp(&mut d, 10, 0xa0); // LameLowPassFilter: 0xa0=160 ×100 = 16000
    stamp(&mut d, 20, 0x80); // LameBitrate: 0x80=128 ×1000 = 128000
    stamp(&mut d, 24, 0x0c); // LameStereoMode: (0x0c & 0x1c)>>2 = 3 → "Joint Stereo"
    d
  }

  #[test]
  fn xing_lame_emits_typed_tags_print_on() {
    let data = build_vbr_xing_lame_fixture();
    let w = collect(&data, true);
    let g = |n: &str| w.get_str("MPEG", n);
    assert_eq!(g("VBRFrames"), Some("1000".into()));
    assert_eq!(g("VBRBytes"), Some("200000".into()));
    assert_eq!(g("VBRScale"), Some("78".into()));
    assert_eq!(g("Encoder"), Some("LAME3.99r".into()));
    assert_eq!(g("LameVBRQuality"), Some("2".into()));
    assert_eq!(g("LameQuality"), Some("2".into()));
    assert_eq!(g("LameMethod"), Some("VBR (new/mtrh)".into()));
    assert_eq!(g("LameLowPassFilter"), Some("16 kHz".into()));
    assert_eq!(g("LameBitrate"), Some("128 kbps".into()));
    assert_eq!(g("LameStereoMode"), Some("Joint Stereo".into()));
  }

  #[test]
  fn xing_lame_emits_typed_tags_print_off() {
    let data = build_vbr_xing_lame_fixture();
    let w = collect(&data, false);
    let g = |n: &str| w.get_str("MPEG", n);
    // VBRFrames, VBRBytes, VBRScale — no conversions.
    assert_eq!(g("VBRFrames"), Some("1000".into()));
    assert_eq!(g("Encoder"), Some("LAME3.99r".into()));
    // LAME: raw values (no PrintConv applied) — post-ValueConv numerics.
    assert_eq!(g("LameMethod"), Some("4".into()));
    assert_eq!(g("LameLowPassFilter"), Some("16000".into()));
    assert_eq!(g("LameBitrate"), Some("128000".into()));
    assert_eq!(g("LameStereoMode"), Some("3".into()));
  }

  #[test]
  fn info_frame_suppresses_vbr_tags() {
    // MPEG.pm:511 `my $isVBR = ($buff !~ /^Info/)` — Info-frame magic
    // suppresses VBRFrames/VBRBytes/VBRScale. LAME path can still run.
    let mut d = build_vbr_xing_lame_fixture();
    let xing_offset = 4 + 32;
    d[xing_offset..xing_offset + 4].copy_from_slice(b"Info");
    let w = collect(&d, true);
    assert_eq!(w.get("MPEG", "VBRFrames"), None);
    assert_eq!(w.get("MPEG", "VBRBytes"), None);
    assert_eq!(w.get("MPEG", "VBRScale"), None);
    // Encoder still emits from the LAME branch.
    assert_eq!(w.get_str("MPEG", "Encoder"), Some("LAME3.99r".into()));
  }

  #[test]
  fn no_xing_magic_silent_skip() {
    let mut d = std::vec::Vec::with_capacity(40);
    d.extend_from_slice(&0xfffb_904c_u32.to_be_bytes());
    d.extend(std::iter::repeat(0).take(36));
    let w = collect(&d, true);
    // Audio tags still emit.
    assert!(w.get("MPEG", "AudioBitrate").is_some());
    // No Xing tags.
    assert_eq!(w.get("MPEG", "VBRFrames"), None);
    assert_eq!(w.get("MPEG", "Encoder"), None);
  }

  #[test]
  fn xing_truncated_at_each_length_gate() {
    // Truncate before VBRFrames — MPEG.pm:516 `last`.
    let mut d = std::vec::Vec::with_capacity(44);
    d.extend_from_slice(&0xfffb_904c_u32.to_be_bytes());
    d.extend(std::iter::repeat(0).take(32));
    d.extend_from_slice(b"Xing");
    d.extend_from_slice(&0x01u32.to_be_bytes()); // VBRFrames-only flag
    // No VBRFrames data appended.
    let w = collect(&d, true);
    assert!(w.get("MPEG", "AudioBitrate").is_some());
    assert_eq!(w.get("MPEG", "VBRFrames"), None);
  }

  // ───────────────────────── raw-MP3 engine entry ─────────────────────────

  // The MP3 engine path is now `crate::parser::extract_info` (the synthetic
  // raw-MPEG buffers detect as MP3 by frame-sync magic). These run it and
  // assert on the parsed JSON object (replacing the retired
  // `ProcessMp3::process` + `TagMap` tests).
  fn engine_obj(
    name: &str,
    data: &[u8],
    print_on: bool,
  ) -> serde_json::Map<String, serde_json::Value> {
    let json = crate::parser::extract_info(name, data, print_on);
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    v.as_array().unwrap()[0].as_object().unwrap().clone()
  }

  #[test]
  fn bridge_parse_emits_expected_tags_print_on() {
    let mut data = vec![0xff, 0xfb, 0x90, 0x4c];
    data.extend(std::iter::repeat(0).take(413));
    let obj = engine_obj("x.mp3", &data, true);
    let s = |k: &str| obj.get(k).and_then(|v| v.as_str());
    assert_eq!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("MP3")
    );
    assert_eq!(
      obj.get("MPEG:MPEGAudioVersion").and_then(|v| v.as_u64()),
      Some(1)
    );
    assert_eq!(obj.get("MPEG:AudioLayer").and_then(|v| v.as_u64()), Some(3));
    assert_eq!(s("MPEG:AudioBitrate"), Some("128 kbps"));
    assert_eq!(
      obj.get("MPEG:SampleRate").and_then(|v| v.as_u64()),
      Some(44100)
    );
    assert_eq!(s("MPEG:ChannelMode"), Some("Joint Stereo"));
    assert_eq!(s("MPEG:MSStereo"), Some("Off"));
    assert_eq!(s("MPEG:IntensityStereo"), Some("Off"));
    // CopyrightFlag/OriginalMedia "True" → JSON bool true (EscapeJSON coercion).
    assert_eq!(
      obj.get("MPEG:CopyrightFlag").and_then(|v| v.as_bool()),
      Some(true)
    );
    assert_eq!(
      obj.get("MPEG:OriginalMedia").and_then(|v| v.as_bool()),
      Some(true)
    );
    assert_eq!(s("MPEG:Emphasis"), Some("None"));
    assert!(!obj.contains_key("MPEG:ModeExtension"));
  }

  #[test]
  fn bridge_parse_emits_expected_tags_print_off() {
    let mut data = vec![0xff, 0xfb, 0x90, 0x4c];
    data.extend(std::iter::repeat(0).take(413));
    let obj = engine_obj("x.mp3", &data, false);
    let u = |k: &str| obj.get(k).and_then(|v| v.as_u64());
    assert_eq!(u("MPEG:MPEGAudioVersion"), Some(3));
    assert_eq!(u("MPEG:AudioLayer"), Some(1));
    assert_eq!(u("MPEG:AudioBitrate"), Some(128000));
    assert_eq!(u("MPEG:SampleRate"), Some(0));
    assert_eq!(u("MPEG:ChannelMode"), Some(1));
    assert_eq!(u("MPEG:MSStereo"), Some(0));
    assert_eq!(u("MPEG:IntensityStereo"), Some(0));
    assert_eq!(u("MPEG:CopyrightFlag"), Some(1));
    assert_eq!(u("MPEG:OriginalMedia"), Some(1));
    assert_eq!(u("MPEG:Emphasis"), Some(0));
  }

  #[test]
  fn bridge_reject_returns_false_with_no_filetype_tag() {
    let obj = engine_obj("x.mp3", &[0x00u8; 32], true);
    assert_ne!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("MP3")
    );
  }

  #[test]
  fn bridge_parse_emits_xing_lame_tags() {
    let data = build_vbr_xing_lame_fixture();
    let obj = engine_obj("x.mp3", &data, true);
    let s = |k: &str| obj.get(k).and_then(|v| v.as_str());
    let u = |k: &str| obj.get(k).and_then(|v| v.as_u64());
    assert_eq!(u("MPEG:VBRFrames"), Some(1000));
    assert_eq!(u("MPEG:VBRBytes"), Some(200_000));
    assert_eq!(u("MPEG:VBRScale"), Some(78));
    assert_eq!(s("MPEG:Encoder"), Some("LAME3.99r"));
    assert_eq!(u("MPEG:LameVBRQuality"), Some(2));
    assert_eq!(u("MPEG:LameQuality"), Some(2));
    assert_eq!(s("MPEG:LameMethod"), Some("VBR (new/mtrh)"));
    assert_eq!(s("MPEG:LameLowPassFilter"), Some("16 kHz"));
    assert_eq!(s("MPEG:LameBitrate"), Some("128 kbps"));
    assert_eq!(s("MPEG:LameStereoMode"), Some("Joint Stereo"));
  }

  // ───────────────────────── ID3.pm:1684-1729 ProcessMP3 bounded-scan ─────────────────────────

  #[test]
  fn id3_process_mp3_scan_len_ext_branches() {
    assert_eq!(id3_process_mp3_scan_len(true), 8192);
    assert_eq!(id3_process_mp3_scan_len(false), 256);
  }

  /// F1/RED-GREEN: junk-`.mp3` with valid sync at offset 8200 (past
  /// $scanLen=8192) ⇒ reject.
  #[test]
  fn f1_bounded_scan_rejects_late_header_under_mp3_ext() {
    let mut filler = std::vec::Vec::with_capacity(8200);
    for i in 1..=8200u32 {
      filler.push(((i * 137 + 41) % 0xfe) as u8);
    }
    let mut data: std::vec::Vec<u8> = filler;
    data.extend_from_slice(&0xfffb_904c_u32.to_be_bytes());
    data.extend(std::iter::repeat(0).take(413));
    let obj = engine_obj("x.mp3", &data, true);
    assert_ne!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("MP3")
    );
  }

  #[test]
  fn f1_bounded_scan_accepts_header_at_8188() {
    let mut filler = std::vec::Vec::with_capacity(8188);
    for i in 1..=8188u32 {
      filler.push(((i * 137 + 41) % 0xfe) as u8);
    }
    let mut data: std::vec::Vec<u8> = filler;
    data.extend_from_slice(&0xfffb_904c_u32.to_be_bytes());
    data.extend(std::iter::repeat(0).take(413));
    let obj = engine_obj("x.mp3", &data, true);
    assert_eq!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("MP3")
    );
    assert!(obj.contains_key("MPEG:AudioBitrate"));
  }

  #[test]
  fn f1_bounded_scan_rejects_late_header_under_non_mp3_ext() {
    let mut filler = std::vec::Vec::with_capacity(256);
    for i in 1..=256u32 {
      filler.push(((i * 137 + 41) % 0xfe) as u8);
    }
    let mut data: std::vec::Vec<u8> = filler;
    data.extend_from_slice(&0xfffb_904c_u32.to_be_bytes());
    data.extend(std::iter::repeat(0).take(413));
    let obj = engine_obj("x.dat", &data, true);
    assert_ne!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("MP3")
    );
  }

  #[test]
  fn f1_bounded_scan_accepts_header_at_252_under_non_mp3_ext() {
    let mut filler = std::vec::Vec::with_capacity(252);
    for i in 1..=252u32 {
      filler.push(((i * 137 + 41) % 0xfe) as u8);
    }
    let mut data: std::vec::Vec<u8> = filler;
    data.extend_from_slice(&0xfffb_904c_u32.to_be_bytes());
    data.extend(std::iter::repeat(0).take(413));
    let obj = engine_obj("x.dat", &data, true);
    assert_eq!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("MP3")
    );
  }

  // ───────────────────────── FormatParser trait surface ─────────────────────────

  #[test]
  fn format_parser_trait_returns_meta_static() {
    let bytes = std::fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/MP3.mp3"),
    )
    .expect("read MP3.mp3 fixture");
    let mut shared = SharedFlags::new();
    let ctx = MpegAudioContext::new(&bytes, "MP3", true, &mut shared);
    let meta = <ProcessMpegAudio as FormatParser>::parse(&ProcessMpegAudio, ctx)
      .expect("ok")
      .expect("parsed");
    assert_eq!(meta.mpeg_audio_version(), MpegAudioVersion::V1);
    assert_eq!(meta.audio_layer(), AudioLayer::L3);
    assert_eq!(meta.audio_bitrate(), AudioBitrate::Known(128_000));
  }

  #[test]
  fn ms_stereo_layer3_on_off_emit() {
    // Toggle Bit26 in a Layer III header — verify the typed Meta and
    // the sink emission both reflect the bit.
    // Bit26 = byte[3] mask 0x20. Base header 0xfffb_904c byte[3]=0x4c
    // (bit 0x20 = 0). Set it: 0x6c.
    let header = 0xfffb_906c_u32;
    let m = extract_header_fields(header).unwrap();
    assert_eq!(m.ms_stereo(), Some(true));
    // Sink under -j.
    let mut w = TagMap::new();
    m.serialize_tags(true, &mut w).unwrap();
    assert_eq!(w.get_str("MPEG", "MSStereo"), Some("On".into()));
  }
}
