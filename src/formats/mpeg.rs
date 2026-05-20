//! Faithful port of `Image::ExifTool::MPEG` (lib/Image/ExifTool/MPEG.pm) —
//! AUDIO side only. Ports:
//!
//! - `%MPEG::Audio` (MPEG.pm:23-256) — the 11-tag bit-field table for the
//!   4-byte MPEG audio frame header.
//! - `ProcessFrameHeader` (MPEG.pm:441-457) — already subsumed by
//!   [`crate::bitstream::process_bit_stream_cond`].
//! - `ParseMPEGAudio` (MPEG.pm:464-581) — sync-scan, header-validate,
//!   dispatch, AND the post-header Xing/Info/LAME tail.
//! - `%MPEG::Xing` (MPEG.pm:323-337) and `%MPEG::Lame` (MPEG.pm:339-382) —
//!   the VBR/encoder sub-tables consumed by the post-header tail.
//! - `ProcessMP3` audio scan-buffer bounding (ID3.pm:1684-1729) — the
//!   wrapper at [`ProcessMp3::process`] bounds `data` to ID3.pm:1704's
//!   `$scanLen` (8192 if `$$self{FILE_EXT} eq 'MP3'`, 256 otherwise)
//!   BEFORE invoking [`parse_mpeg_audio`]. Required to match bundled
//!   ExifTool's rejection of files where a valid sync byte appears beyond
//!   the scan boundary; without it, MP3 (weak magic) accepts junk files
//!   on a stray late `\xff` (Codex R1/F1).
//!
//! ## Deferred (forward items, deliberately out of this PR's scope)
//!
//! - **MPEG video** (`%MPEG::Video`, `ProcessMPEG`, `ProcessMPEGVideo`,
//!   `ParseMPEGAudioVideo`, MPEG.pm:258-321 + 583-681) — separate port.
//! - **ID3 dispatch coordination** — the ID3 port is a parallel PR. In
//!   bundled ExifTool, `MP3`-typed files route to `ID3::ProcessMP3`
//!   (ExifTool.pm:893 `MP3 => 'ID3'`), which scans for `ID3` (v1/v2) tags
//!   and then calls back into `ParseMPEGAudio`. While ID3 is unmerged,
//!   THIS module registers as the `"MP3"` parser directly (its
//!   [`ProcessMp3::process`] entry point applies the ID3.pm:1684-1729
//!   `$scanLen` bound BEFORE delegating to [`parse_mpeg_audio`]); when
//!   ID3 lands it can register a wrapping parser at `"MP3"` that performs
//!   the same scan-buffer bound and delegates the audio side to
//!   [`parse_mpeg_audio`] (re-exported `pub(crate)`).
//! - **`%MPEG::Composite` (Duration/AudioBitrate)** (MPEG.pm:385-432) —
//!   Composite tags subsystem not yet ported (cross-module Require/Desire).
//! - **R8 set-then-reject** — MPEG.pm:496 `$et->SetFileType()` is called
//!   BEFORE the post-header Xing/LAME tail; the tail can `last` on any
//!   length / magic / flag check but never `return 0`, so the File:*
//!   tags from SetFileType always persist. Today both code paths (sync
//!   reject + Xing tail) return 1; the seam's persist-on-reject contract
//!   keeps that faithful for any future divergence.

use crate::{
  bitstream::{process_bit_stream_cond, BitOrder, FrameState},
  parser::{FormatParser, ParseContext},
  tagtable::{PrintConv, PrintConvHash, PrintValue, RawConv, TagDef, ValueConv},
  value::TagValue,
};

// ───────────────────────── ConvertBitrate ─────────────────────────

/// Faithful Rust port of `Image::ExifTool::ConvertBitrate` (ExifTool.pm:6891-
/// 6902). The PrintConv for every `AudioBitrate` arm (MPEG.pm:67/91/115/139/
/// 163). Returns the original value when it isn't numerical (Perl
/// `IsFloat` false ⇒ `return $bitrate`).
///
/// Algorithm (Perl):
///   `units = ('bps','kbps','Mbps','Gbps')`; while bitrate ≥ 1000 and more
///   units remain: `bitrate /= 1000; shift units`. Format:
///   `sprintf("%.3g %s", b, u)` if b < 100, else `sprintf("%.0f %s", b, u)`.
///
/// Inputs `0` ("free", from the `0 => 'free'` ValueConv-hash arm,
/// MPEG.pm:51) bypass via `TagValue::Str("free")` ⇒ IsFloat false ⇒ string
/// passthrough.
fn convert_bitrate(val: &TagValue) -> TagValue {
  // Perl `IsFloat($bitrate) or return $bitrate` (ExifTool.pm:6894) +
  // `for(;;) { ... }` (ExifTool.pm:6896-6901). Faithful: any non-numeric
  // input returns unchanged.
  let b = match val {
    TagValue::I64(n) => *n as f64,
    TagValue::F64(n) if n.is_finite() => *n,
    TagValue::Str(s) => match s.parse::<f64>() {
      Ok(n) if n.is_finite() => n,
      _ => return val.clone(), // IsFloat false ⇒ unchanged
    },
    _ => return val.clone(),
  };
  // Walk units: bps → kbps → Mbps → Gbps. After divide-by-1000 up to 3
  // times we exit either by `bitrate < 1000` or by exhausting the unit
  // list. Perl uses `shift @units` so `units` is removed-from-front; we
  // mirror with an index.
  let units = ["bps", "kbps", "Mbps", "Gbps"];
  let mut b = b;
  let mut i = 0usize;
  // `bitrate >= 1000 and @units and bitrate /= 1000, next;` — the test is
  // `i < units.len() - 1` because the next iteration must still have a unit
  // available (i.e. units list non-empty AFTER the `shift`).
  while b >= 1000.0 && i + 1 < units.len() {
    b /= 1000.0;
    i += 1;
  }
  let unit = units[i];
  // ExifTool.pm:6899: '%.3g' if bitrate < 100 else '%.0f'.
  let s = if b < 100.0 {
    // Perl `sprintf("%.3g", $b)` — 3 significant digits.
    crate::value::format_g(b, 3)
  } else {
    // Perl `sprintf("%.0f", $b)` — 0 decimal places (rounded).
    // FORWARD: Rust `{:.0}` rounds half-to-even; Perl `%.0f` on most
    // platforms rounds half-away-from-zero. Currently load-bearing only
    // for integer bitrates (every entry in `VC_BR_*` is a multiple of
    // 1000, so /1000 stays integer-valued and no halves are produced).
    // If a VBR Composite:AudioBitrate (MPEG.pm:416-431) is later ported
    // it can produce a half — switch this arm to a half-away-from-zero
    // rounder then, pinned by an oracle golden.
    format!("{:.0}", b)
  };
  TagValue::Str(format!("{s} {unit}").into())
}

// ───────────────────────── ValueConv hashes ─────────────────────────
//
// MPEG.pm AudioBitrate hashes 0..14 (per version+layer). Keyed by the
// **stringified** raw integer (Perl `$$conv{$val}` indexes the hash with the
// stringified scalar). `0 => 'free'` is a string sentinel; entries 1..14 are
// bare numbers (`Integer Hz`).

// MPEG.pm:50-66 — version 1, layer 1.
const VC_BR_V1_L1: &[(&str, PrintValue)] = &[
  ("0", PrintValue::Str("free")),
  ("1", PrintValue::I64(32000)),
  ("2", PrintValue::I64(64000)),
  ("3", PrintValue::I64(96000)),
  ("4", PrintValue::I64(128000)),
  ("5", PrintValue::I64(160000)),
  ("6", PrintValue::I64(192000)),
  ("7", PrintValue::I64(224000)),
  ("8", PrintValue::I64(256000)),
  ("9", PrintValue::I64(288000)),
  ("10", PrintValue::I64(320000)),
  ("11", PrintValue::I64(352000)),
  ("12", PrintValue::I64(384000)),
  ("13", PrintValue::I64(416000)),
  ("14", PrintValue::I64(448000)),
];

// MPEG.pm:74-90 — version 1, layer 2.
const VC_BR_V1_L2: &[(&str, PrintValue)] = &[
  ("0", PrintValue::Str("free")),
  ("1", PrintValue::I64(32000)),
  ("2", PrintValue::I64(48000)),
  ("3", PrintValue::I64(56000)),
  ("4", PrintValue::I64(64000)),
  ("5", PrintValue::I64(80000)),
  ("6", PrintValue::I64(96000)),
  ("7", PrintValue::I64(112000)),
  ("8", PrintValue::I64(128000)),
  ("9", PrintValue::I64(160000)),
  ("10", PrintValue::I64(192000)),
  ("11", PrintValue::I64(224000)),
  ("12", PrintValue::I64(256000)),
  ("13", PrintValue::I64(320000)),
  ("14", PrintValue::I64(384000)),
];

// MPEG.pm:98-114 — version 1, layer 3.
const VC_BR_V1_L3: &[(&str, PrintValue)] = &[
  ("0", PrintValue::Str("free")),
  ("1", PrintValue::I64(32000)),
  ("2", PrintValue::I64(40000)),
  ("3", PrintValue::I64(48000)),
  ("4", PrintValue::I64(56000)),
  ("5", PrintValue::I64(64000)),
  ("6", PrintValue::I64(80000)),
  ("7", PrintValue::I64(96000)),
  ("8", PrintValue::I64(112000)),
  ("9", PrintValue::I64(128000)),
  ("10", PrintValue::I64(160000)),
  ("11", PrintValue::I64(192000)),
  ("12", PrintValue::I64(224000)),
  ("13", PrintValue::I64(256000)),
  ("14", PrintValue::I64(320000)),
];

// MPEG.pm:122-138 — version 2 or 2.5, layer 1.
const VC_BR_V2_L1: &[(&str, PrintValue)] = &[
  ("0", PrintValue::Str("free")),
  ("1", PrintValue::I64(32000)),
  ("2", PrintValue::I64(48000)),
  ("3", PrintValue::I64(56000)),
  ("4", PrintValue::I64(64000)),
  ("5", PrintValue::I64(80000)),
  ("6", PrintValue::I64(96000)),
  ("7", PrintValue::I64(112000)),
  ("8", PrintValue::I64(128000)),
  ("9", PrintValue::I64(144000)),
  ("10", PrintValue::I64(160000)),
  ("11", PrintValue::I64(176000)),
  ("12", PrintValue::I64(192000)),
  ("13", PrintValue::I64(224000)),
  ("14", PrintValue::I64(256000)),
];

// MPEG.pm:146-162 — version 2 or 2.5, layer 2 or 3.
const VC_BR_V2_L23: &[(&str, PrintValue)] = &[
  ("0", PrintValue::Str("free")),
  ("1", PrintValue::I64(8000)),
  ("2", PrintValue::I64(16000)),
  ("3", PrintValue::I64(24000)),
  ("4", PrintValue::I64(32000)),
  ("5", PrintValue::I64(40000)),
  ("6", PrintValue::I64(48000)),
  ("7", PrintValue::I64(56000)),
  ("8", PrintValue::I64(64000)),
  ("9", PrintValue::I64(80000)),
  ("10", PrintValue::I64(96000)),
  ("11", PrintValue::I64(112000)),
  ("12", PrintValue::I64(128000)),
  ("13", PrintValue::I64(144000)),
  ("14", PrintValue::I64(160000)),
];

// ───────────────────────── Tag definitions ─────────────────────────

// MPEG.pm:25-33  Bit11-12 MPEGAudioVersion.
//   PrintConv 0 => 2.5, 2 => 2, 3 => 1.
//   RawConv sets MPEG_Vers.
static MPEG_AUDIO_VERSION: TagDef = TagDef::new(
  "MPEGAudioVersion",
  "MPEG",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::F64(2.5)),
    ("2", PrintValue::I64(2)),
    ("3", PrintValue::I64(1)),
  ])),
)
.with_raw_conv(RawConv::SetFrameState("MPEG_Vers"));

// MPEG.pm:34-42  Bit13-14 AudioLayer.
//   PrintConv 1 => 3, 2 => 2, 3 => 1.
//   RawConv sets MPEG_Layer.
static AUDIO_LAYER: TagDef = TagDef::new(
  "AudioLayer",
  "MPEG",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("1", PrintValue::I64(3)),
    ("2", PrintValue::I64(2)),
    ("3", PrintValue::I64(1)),
  ])),
)
.with_raw_conv(RawConv::SetFrameState("MPEG_Layer"));

// MPEG.pm:44-68 — Bit16-19 AudioBitrate, version 1, layer 1.
static AUDIO_BITRATE_V1_L1: TagDef = TagDef::new(
  "AudioBitrate",
  "MPEG",
  ValueConv::Hash(PrintConvHash::direct(VC_BR_V1_L1)),
  PrintConv::Func(convert_bitrate),
);
// MPEG.pm:69-92 — Bit16-19 AudioBitrate, version 1, layer 2.
static AUDIO_BITRATE_V1_L2: TagDef = TagDef::new(
  "AudioBitrate",
  "MPEG",
  ValueConv::Hash(PrintConvHash::direct(VC_BR_V1_L2)),
  PrintConv::Func(convert_bitrate),
);
// MPEG.pm:93-116 — Bit16-19 AudioBitrate, version 1, layer 3.
static AUDIO_BITRATE_V1_L3: TagDef = TagDef::new(
  "AudioBitrate",
  "MPEG",
  ValueConv::Hash(PrintConvHash::direct(VC_BR_V1_L3)),
  PrintConv::Func(convert_bitrate),
);
// MPEG.pm:117-140 — Bit16-19 AudioBitrate, version 2 or 2.5, layer 1.
static AUDIO_BITRATE_V2_L1: TagDef = TagDef::new(
  "AudioBitrate",
  "MPEG",
  ValueConv::Hash(PrintConvHash::direct(VC_BR_V2_L1)),
  PrintConv::Func(convert_bitrate),
);
// MPEG.pm:141-164 — Bit16-19 AudioBitrate, version 2 or 2.5, layer 2 or 3.
static AUDIO_BITRATE_V2_L23: TagDef = TagDef::new(
  "AudioBitrate",
  "MPEG",
  ValueConv::Hash(PrintConvHash::direct(VC_BR_V2_L23)),
  PrintConv::Func(convert_bitrate),
);

// MPEG.pm:166-176 — Bit20-21 SampleRate, version 1.
//   PrintConv 0 => 44100, 1 => 48000, 2 => 32000. NO ValueConv (-n shows raw).
static SAMPLE_RATE_V1: TagDef = TagDef::new(
  "SampleRate",
  "MPEG",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::I64(44100)),
    ("1", PrintValue::I64(48000)),
    ("2", PrintValue::I64(32000)),
  ])),
);
// MPEG.pm:177-186 — Bit20-21 SampleRate, version 2.
static SAMPLE_RATE_V2: TagDef = TagDef::new(
  "SampleRate",
  "MPEG",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::I64(22050)),
    ("1", PrintValue::I64(24000)),
    ("2", PrintValue::I64(16000)),
  ])),
);
// MPEG.pm:187-196 — Bit20-21 SampleRate, version 2.5.
static SAMPLE_RATE_V25: TagDef = TagDef::new(
  "SampleRate",
  "MPEG",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::I64(11025)),
    ("1", PrintValue::I64(12000)),
    ("2", PrintValue::I64(8000)),
  ])),
);

// MPEG.pm:200-209 — Bit24-25 ChannelMode. RawConv sets MPEG_Mode.
static CHANNEL_MODE: TagDef = TagDef::new(
  "ChannelMode",
  "MPEG",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::Str("Stereo")),
    ("1", PrintValue::Str("Joint Stereo")),
    ("2", PrintValue::Str("Dual Channel")),
    ("3", PrintValue::Str("Single Channel")),
  ])),
)
.with_raw_conv(RawConv::SetFrameState("MPEG_Mode"));

// MPEG.pm:210-215 — Bit26 MSStereo (Condition: layer 3).
static MS_STEREO: TagDef = TagDef::new(
  "MSStereo",
  "MPEG",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::Str("Off")),
    ("1", PrintValue::Str("On")),
  ])),
);
// MPEG.pm:216-221 — Bit27 IntensityStereo (Condition: layer 3).
static INTENSITY_STEREO: TagDef = TagDef::new(
  "IntensityStereo",
  "MPEG",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::Str("Off")),
    ("1", PrintValue::Str("On")),
  ])),
);
// MPEG.pm:222-232 — Bit26-27 ModeExtension (Condition: layer 1 or 2).
static MODE_EXTENSION: TagDef = TagDef::new(
  "ModeExtension",
  "MPEG",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::Str("Bands 4-31")),
    ("1", PrintValue::Str("Bands 8-31")),
    ("2", PrintValue::Str("Bands 12-31")),
    ("3", PrintValue::Str("Bands 16-31")),
  ])),
);

// MPEG.pm:233-239 — Bit28 CopyrightFlag. JSON quirk: True/False strings
// serialize as `true`/`false` JSON booleans (handled by serialize.rs).
static COPYRIGHT_FLAG: TagDef = TagDef::new(
  "CopyrightFlag",
  "MPEG",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::Str("False")),
    ("1", PrintValue::Str("True")),
  ])),
);
// MPEG.pm:240-246 — Bit29 OriginalMedia.
static ORIGINAL_MEDIA: TagDef = TagDef::new(
  "OriginalMedia",
  "MPEG",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::Str("False")),
    ("1", PrintValue::Str("True")),
  ])),
);
// MPEG.pm:247-255 — Bit30-31 Emphasis.
static EMPHASIS: TagDef = TagDef::new(
  "Emphasis",
  "MPEG",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::Str("None")),
    ("1", PrintValue::Str("50/15 ms")),
    ("2", PrintValue::Str("reserved")),
    ("3", PrintValue::Str("CCIT J.17")),
  ])),
);

// ───────────────────────── %MPEG::Xing (MPEG.pm:323-337) ─────────────────────────
//
// `GROUPS => { 2 => 'Audio' }`, `VARS => { ID_FMT => 'none' }`, keys 1..7.
// Keys 1-3 (VBRFrames/VBRBytes/VBRScale) and 5/6 (LameVBRQuality/LameQuality)
// are 32-bit big-endian unsigned values handled by the Perl
// `HandleTag($xingTable, K, $val)` calls at MPEG.pm:515/521/532/564/565.
// Key 4 (Encoder) is the 9-byte LAME version *or* the 20-byte fallback
// substring (MPEG.pm:563/575/553). Key 7 (LameHeader) is the SubDirectory
// for `%MPEG::Lame` — ExifTool documents this for the tag-list output but
// `HandleTag` is never invoked for it, so we model only the metadata
// (Name + SubDirectory pointer) and route to LAME parsing directly.

// MPEG.pm:327 `1 => { Name => 'VBRFrames' }` — bare integer.
static XING_VBR_FRAMES: TagDef = TagDef::new("VBRFrames", "MPEG", ValueConv::None, PrintConv::None);
// MPEG.pm:328 `2 => { Name => 'VBRBytes' }` — bare integer.
static XING_VBR_BYTES: TagDef = TagDef::new("VBRBytes", "MPEG", ValueConv::None, PrintConv::None);
// MPEG.pm:329 `3 => { Name => 'VBRScale' }` — bare integer.
static XING_VBR_SCALE: TagDef = TagDef::new("VBRScale", "MPEG", ValueConv::None, PrintConv::None);
// MPEG.pm:330 `4 => { Name => 'Encoder' }` — string (9-byte LAME version OR
// 20-byte fallback OR identified non-LAME encoder, MPEG.pm:553/563/575).
static XING_ENCODER: TagDef = TagDef::new("Encoder", "MPEG", ValueConv::None, PrintConv::None);
// MPEG.pm:331 `5 => { Name => 'LameVBRQuality' }` — bare integer.
static XING_LAME_VBR_QUALITY: TagDef =
  TagDef::new("LameVBRQuality", "MPEG", ValueConv::None, PrintConv::None);
// MPEG.pm:332 `6 => { Name => 'LameQuality' }` — bare integer.
static XING_LAME_QUALITY: TagDef =
  TagDef::new("LameQuality", "MPEG", ValueConv::None, PrintConv::None);

// ───────────────────────── %MPEG::Lame (MPEG.pm:339-382) ─────────────────────────
//
// `PROCESS_PROC => \&Image::ExifTool::ProcessBinaryData`, `GROUPS => { 2 =>
// 'Audio' }`. 4 tags keyed by BYTE OFFSET within the LAME header (counting
// from the 9-byte version string). Each carries `Mask`+`BitShift`:
// ExifTool.pm:5905-5910 derives `BitShift` from the lowest set bit of
// `Mask`, then ExifTool.pm:10067-10068 applies `($val & $mask) >>
// $bitShift` BEFORE ValueConv. We inline that computation in the parser
// (the runtime `with_mask`/Format-`int8u` plumbing is a forward item).
//
// Tags:
//   9   LameMethod         Mask 0x0f, hash PrintConv (8 entries).
//   10  LameLowPassFilter  ValueConv `$val * 100`; PrintConv "$val/1000 + ' kHz'".
//   20  LameBitrate        ValueConv `$val * 1000`; PrintConv ConvertBitrate.
//   24  LameStereoMode     Mask 0x1c (BitShift 2), hash PrintConv (7 entries).

/// Faithful port of MPEG.pm:361 PrintConv `'($val / 1000) . " kHz"'` —
/// integer/float divide-by-1000 + literal " kHz" suffix. ValueConv has
/// already multiplied the raw byte by 100, so `LameLowPassFilter = byte *
/// 100`; passing a value like 16000 yields `16 kHz`. Perl `.` is string
/// concat; the integer 16 stringifies as `"16"` (no trailing `.0`), so a
/// value-`is_finite` integer formats without a decimal point.
fn lame_lowpass_print(val: &TagValue) -> TagValue {
  let n = match val {
    TagValue::I64(n) => *n as f64,
    TagValue::F64(n) if n.is_finite() => *n,
    TagValue::Str(s) => match s.parse::<f64>() {
      Ok(n) if n.is_finite() => n,
      _ => return val.clone(),
    },
    _ => return val.clone(),
  };
  let q = n / 1000.0;
  // Perl `($val/1000) . " kHz"` — `/` is float divide. Stringification:
  // an integer-valued float prints as the integer (`16`), a fractional
  // value prints with the minimum digits Perl uses (`%g`-like).
  let s = if (q - q.round()).abs() < f64::EPSILON {
    format!("{}", q.round() as i64)
  } else {
    crate::value::format_g(q, 15)
  };
  TagValue::Str(format!("{s} kHz").into())
}

// MPEG.pm:344-357 — LameMethod, Mask 0x0f (no shift).
static LAME_METHOD: TagDef = TagDef::new(
  "LameMethod",
  "MPEG",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("1", PrintValue::Str("CBR")),
    ("2", PrintValue::Str("ABR")),
    ("3", PrintValue::Str("VBR (old/rh)")),
    ("4", PrintValue::Str("VBR (new/mtrh)")),
    ("5", PrintValue::Str("VBR (old/rh)")),
    ("6", PrintValue::Str("VBR")),
    ("8", PrintValue::Str("CBR (2-pass)")),
    ("9", PrintValue::Str("ABR (2-pass)")),
  ])),
);

// MPEG.pm:358-362 — LameLowPassFilter, ValueConv `$val * 100`, PrintConv
// `($val / 1000) . " kHz"`.
fn lame_lowpass_value(val: &TagValue) -> TagValue {
  match val {
    TagValue::I64(n) => TagValue::I64(n.saturating_mul(100)),
    TagValue::F64(n) if n.is_finite() => TagValue::F64(*n * 100.0),
    other => other.clone(),
  }
}
static LAME_LOWPASS_FILTER: TagDef = TagDef::new(
  "LameLowPassFilter",
  "MPEG",
  ValueConv::Func(lame_lowpass_value),
  PrintConv::Func(lame_lowpass_print),
);

// MPEG.pm:364-368 — LameBitrate, ValueConv `$val * 1000`, PrintConv
// `ConvertBitrate($val)`.
fn lame_bitrate_value(val: &TagValue) -> TagValue {
  match val {
    TagValue::I64(n) => TagValue::I64(n.saturating_mul(1000)),
    TagValue::F64(n) if n.is_finite() => TagValue::F64(*n * 1000.0),
    other => other.clone(),
  }
}
static LAME_BITRATE: TagDef = TagDef::new(
  "LameBitrate",
  "MPEG",
  ValueConv::Func(lame_bitrate_value),
  PrintConv::Func(convert_bitrate),
);

// MPEG.pm:369-381 — LameStereoMode, Mask 0x1c (BitShift 2 from
// ExifTool.pm:5907-5909).
static LAME_STEREO_MODE: TagDef = TagDef::new(
  "LameStereoMode",
  "MPEG",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::Str("Mono")),
    ("1", PrintValue::Str("Stereo")),
    ("2", PrintValue::Str("Dual Channels")),
    ("3", PrintValue::Str("Joint Stereo")),
    ("4", PrintValue::Str("Forced Joint Stereo")),
    ("6", PrintValue::Str("Auto")),
    ("7", PrintValue::Str("Intensity Stereo")),
  ])),
);

// ───────────────────────── Cond chooser + bit-key list ─────────────────────────

/// Sorted `Bit<a>-<b>` keys of `%MPEG::Audio` in ASCENDING bit-offset order
/// (the Perl `sort keys %$tagTablePtr` order for MPEG.pm:25-256). Note the
/// `Bit26` < `Bit26-27` < `Bit27` lex ordering — the chooser uses Condition
/// to pick which of `Bit26`/`Bit27`/`Bit26-27` is emitted per frame (they
/// are mutually exclusive: `Bit26`+`Bit27` for layer 3, `Bit26-27` for
/// layer 1/2).
const MPEG_AUDIO_BIT_KEYS: &[&str] = &[
  "Bit11-12", // MPEGAudioVersion (RawConv writes MPEG_Vers)
  "Bit13-14", // AudioLayer       (RawConv writes MPEG_Layer)
  "Bit16-19", // AudioBitrate     (5 Condition arms on MPEG_Vers/MPEG_Layer)
  "Bit20-21", // SampleRate       (3 Condition arms on MPEG_Vers)
  "Bit24-25", // ChannelMode      (RawConv writes MPEG_Mode)
  "Bit26",    // MSStereo         (Condition MPEG_Layer == 1, i.e. layer 3)
  "Bit26-27", // ModeExtension    (Condition MPEG_Layer > 1, i.e. layer 1 or 2)
  "Bit27",    // IntensityStereo  (Condition MPEG_Layer == 1)
  "Bit28",    // CopyrightFlag
  "Bit29",    // OriginalMedia
  "Bit30-31", // Emphasis
];

/// Faithful chooser for each `Bit<a>-<b>` key in `%MPEG::Audio`. Implements
/// the multi-arm Perl table: returns the first arm whose `Condition`
/// matches the current `FrameState`, or `None` if every arm rejects.
fn choose_mpeg_audio(key: &str, s: &FrameState) -> Option<&'static TagDef> {
  match key {
    "Bit11-12" => Some(&MPEG_AUDIO_VERSION), // unconditional
    "Bit13-14" => Some(&AUDIO_LAYER),        // unconditional
    "Bit16-19" => {
      // 5 arms (MPEG.pm:44-164). Perl evaluates `Condition` IN ORDER and
      // takes the FIRST match. Reads MPEG_Vers, MPEG_Layer (set above).
      let v = s.get("MPEG_Vers");
      let l = s.get("MPEG_Layer");
      // MPEG.pm:47 — '$self->{MPEG_Vers} == 3 and $self->{MPEG_Layer} == 3'.
      if v == Some(3) && l == Some(3) {
        Some(&AUDIO_BITRATE_V1_L1)
      // MPEG.pm:71 — '$self->{MPEG_Vers} == 3 and $self->{MPEG_Layer} == 2'.
      } else if v == Some(3) && l == Some(2) {
        Some(&AUDIO_BITRATE_V1_L2)
      // MPEG.pm:95 — '$self->{MPEG_Vers} == 3 and $self->{MPEG_Layer} == 1'.
      } else if v == Some(3) && l == Some(1) {
        Some(&AUDIO_BITRATE_V1_L3)
      // MPEG.pm:119 — '$self->{MPEG_Vers} != 3 and $self->{MPEG_Layer} == 3'.
      } else if v.is_some() && v != Some(3) && l == Some(3) {
        Some(&AUDIO_BITRATE_V2_L1)
      // MPEG.pm:143 — '$self->{MPEG_Vers} != 3 and $self->{MPEG_Layer}'
      // ("layer 2 or 3" per the Notes; '$self->{MPEG_Layer}' is Perl
      // truthy — i.e. non-zero, AND defined). Layer values 1,2 in raw
      // bits = "layer 3" and "layer 2"; layer raw=0 is "reserved" (the
      // sync-scan rejects). So `l != Some(0)` AND `l.is_some()`. Note
      // that `l == Some(3)` already matched the v2_l1 arm above — Perl's
      // first-match semantics prevent the wrong arm here.
      } else if v.is_some() && v != Some(3) && l.is_some() && l != Some(0) {
        Some(&AUDIO_BITRATE_V2_L23)
      } else {
        None // every arm rejects (e.g. MPEG_Vers undef) — no tag.
      }
    }
    "Bit20-21" => {
      // 3 arms (MPEG.pm:166-196). All read MPEG_Vers.
      match s.get("MPEG_Vers") {
        Some(3) => Some(&SAMPLE_RATE_V1),
        Some(2) => Some(&SAMPLE_RATE_V2),
        Some(0) => Some(&SAMPLE_RATE_V25),
        _ => None,
      }
    }
    "Bit24-25" => Some(&CHANNEL_MODE), // unconditional
    "Bit26" => {
      // MPEG.pm:212 — Condition '$self->{MPEG_Layer} == 1' (layer raw=1
      // is Layer III, per the AudioLayer PrintConv).
      if s.get("MPEG_Layer") == Some(1) {
        Some(&MS_STEREO)
      } else {
        None
      }
    }
    "Bit27" => {
      // MPEG.pm:218 — same condition.
      if s.get("MPEG_Layer") == Some(1) {
        Some(&INTENSITY_STEREO)
      } else {
        None
      }
    }
    "Bit26-27" => {
      // MPEG.pm:224 — Condition '$self->{MPEG_Layer} > 1' (layer raw=2/3,
      // i.e. Layer II / Layer I).
      match s.get("MPEG_Layer") {
        Some(l) if l > 1 => Some(&MODE_EXTENSION),
        _ => None,
      }
    }
    "Bit28" => Some(&COPYRIGHT_FLAG), // unconditional
    "Bit29" => Some(&ORIGINAL_MEDIA), // unconditional
    "Bit30-31" => Some(&EMPHASIS),    // unconditional
    _ => None,
  }
}

// ───────────────────────── ParseMPEGAudio ─────────────────────────

/// Reject-reason from header validation (MPEG.pm:474-490). On reject, the
/// Perl loop advances `pos` and retries:
/// - sync-bits failure ⇒ `pos -= 2` (MPEG.pm:475).
/// - validation failure ⇒ give up unless `$ext eq 'MP3'`, in which case
///   `pos -= 1` and continue (MPEG.pm:487-490).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeaderCheck {
  /// All checks passed — emit.
  Ok,
  /// Top-11-bit sync failed (the `\xff` was a false alarm). Faithful Perl
  /// is `pos -= 2` from the post-match position (MPEG.pm:475); our
  /// `scan_for_header` sets `p = next_pos - 2 = start + 2` (the same
  /// two-byte backup), with a `start + 1` fallback as a forward-progress
  /// guard if that backup would land at-or-before `start` (impossible at
  /// the current `next_pos = start + 4`, but defensive against any future
  /// arithmetic change).
  Sync,
  /// One of the field validations (version=01/layer=00/bitrate=0000-or-
  /// 1111/sample-rate=11/emphasis=10) failed. If `mp3` mode (caller is
  /// `ProcessMP3` in ID3.pm OR our `MP3` file-type), advance one byte and
  /// retry; else give up.
  Validation,
}

/// Header validation per MPEG.pm:474-490. `word` is the 32-bit big-endian
/// audio-frame header. `mp3` is the MPEG.pm:485 `$mp3` flag: when set,
/// REQUIRE Layer III as well as the basic field validations (without it,
/// the sync-scan is more permissive — i.e. accepts any of layers I-III).
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

/// Faithful port of `Image::ExifTool::MPEG::ParseMPEGAudio`
/// (MPEG.pm:464-580). Sync-scans the buffer for a valid MPEG audio frame
/// header, validates, emits the `%MPEG::Audio` tags via
/// [`process_bit_stream_cond`], and then delegates to [`parse_xing_lame`]
/// for the post-header Xing/Info/LAME VBR tail (MPEG.pm:501-578; R1-F2
/// port). The tail's many `last` exits leave already-emitted File:* and
/// audio-frame tags in place and `ParseMPEGAudio` still returns 1.
///
/// Returns true on accept (emitted ≥ 1 tag and `set_file_type` was
/// called); false on reject.
///
/// `mp3` mirrors MPEG.pm:466 `$mp3` — set when the caller has already
/// narrowed the file-type to MP3 (Layer III only). Plumbed by the caller
/// (`ProcessMp3::process` faithful to ID3.pm:1715-1717 — `my $mp3 = ($ext
/// eq 'MUS') ? 0 : 1; # MUS files are MP2`), NOT recomputed from `ctx`,
/// because the bundled algorithm explicitly drops the Layer III gate for
/// `.mus` files (which are MP2). Recomputing it from `ctx.file_type()`
/// would force Layer III validation on a valid Layer II `.mus` payload
/// dispatched through `ProcessMp3` (Codex R3 finding).
pub(crate) fn parse_mpeg_audio(ctx: &mut ParseContext<'_>, mp3: bool) -> bool {
  // MPEG.pm:468 `$$et{FILE_EXT}` + MPEG.pm:466 `$mp3` flag (the caller's).
  // We do the header sync first (read-only on `data`) then drop the
  // immutable borrow before the mutable `set_file_type`/`metadata` calls.
  // The sync-scan result captures everything we need so `data` can be
  // re-borrowed (via the original lifetime stored in `ctx`) below.
  let (header_word, pos_after_header) = {
    let ext = ctx.ext().unwrap_or("");
    let Some(result) = scan_for_header(ctx.data(), mp3, ext) else {
      return false; // MPEG.pm:472 `return 0`
    };
    result
  };

  // MPEG.pm:496 `$et->SetFileType()` — finalize file type BEFORE emitting
  // bit-stream tags. R8 pattern: this is the load-bearing call that
  // persists even if a downstream path later returns false (the Xing tail,
  // when ported). The seam's persist-on-reject contract handles that.
  ctx.set_file_type(None, None, None);

  let print_conv_enabled = ctx.print_conv_enabled();
  let mut state = FrameState::new();
  // MPEG.pm:498-499 — `ProcessFrameHeader($et, $tagTablePtr, $word)`.
  // The 4-byte big-endian header word is laid out exactly as
  // process_bit_stream_cond expects (bit 0 = MSB of byte 0).
  let header_bytes = header_word.to_be_bytes();
  process_bit_stream_cond(
    &header_bytes,
    BitOrder::Mm,
    MPEG_AUDIO_BIT_KEYS,
    "MPEG",
    choose_mpeg_audio,
    &mut state,
    ctx.metadata(),
    print_conv_enabled,
  );

  // MPEG.pm:501-578 — Xing/Info/LAME VBR tail. Reads relative to
  // `pos_after_header` (Perl `pos($$buffPt)` at MPEG.pm:492). Faithful:
  // the tail's many `last` exits leave the File:* + audio-frame tags in
  // place (`$et->SetFileType()` already ran above) and `ParseMPEGAudio`
  // still `return 1`s at MPEG.pm:580. We never `return 0` from here.
  //
  // Borrow-discipline: `ctx.data()` reborrows `&ctx` and `ctx.metadata()`
  // reborrows `&mut ctx`, so a naive sequenced call would conflict. The
  // split-borrow accessor `data_and_metadata()` returns both simultaneously
  // (the two fields are disjoint in `ParseContext`), so `parse_xing_lame`
  // takes a borrowed `&[u8]` — no clone of the scan buffer.
  let (data, meta) = ctx.data_and_metadata();
  parse_xing_lame(data, pos_after_header, &state, meta, print_conv_enabled);

  true // MPEG.pm:580 `return 1`
}

// ───────────────────────── parse_xing_lame ─────────────────────────

/// Faithful port of MPEG.pm:501-578 — the VBR Xing/Info + LAME header tail
/// of `ParseMPEGAudio`. Runs AFTER the audio frame header has been
/// extracted (and `SetFileType` called); reads relative to `pos`, the
/// Perl `pos($$buffPt)` right after the 4-byte header match.
///
/// Side-info offset (MPEG.pm:503): `$v == 3 ? ($m == 3 ? 17 : 32) : ($m
/// == 3 ?  9 : 17)` where `$v = $$self{MPEG_Vers}`, `$m = $$self{MPEG_Mode}`.
/// `pos += that offset`, then look for `^(Xing|Info)` in the next 8 bytes
/// (MPEG.pm:506-508). Any length / magic / state failure exits the tail
/// silently (Perl `last`) — caller still returns 1.
fn parse_xing_lame(
  buff: &[u8],
  mut pos: usize,
  state: &FrameState,
  into: &mut crate::value::Metadata,
  print_conv_enabled: bool,
) {
  // MPEG.pm:501-502 — `($$et{MPEG_Vers}, $$et{MPEG_Mode})`. Both must be
  // defined; either being None aborts the tail (Perl `while (defined $v
  // and defined $m)`).
  let (Some(v), Some(m)) = (state.get("MPEG_Vers"), state.get("MPEG_Mode")) else {
    return;
  };
  let len = buff.len();
  // MPEG.pm:504 side-info offset.
  let side = if v == 3 {
    if m == 3 {
      17
    } else {
      32
    }
  } else if m == 3 {
    9
  } else {
    17
  };
  pos = match pos.checked_add(side) {
    Some(n) => n,
    None => return, // overflow guard (Perl runs in unbounded ints)
  };
  // MPEG.pm:505 `last if $pos + 8 > $len`.
  if pos.checked_add(8).map_or(true, |end| end > len) {
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
  // MPEG.pm:510 `my $flags = unpack('x4N', $buff)` — bytes 4..8 of the
  // 8-byte block as big-endian u32.
  let flags = u32::from_be_bytes([head8[4], head8[5], head8[6], head8[7]]);
  // MPEG.pm:511 `my $isVBR = ($buff !~ /^Info/)` — Info-frame is CBR.
  let is_vbr = !magic_is_info;
  // MPEG.pm:512 `$pos += 8`.
  pos += 8;

  // Helper: emit a Xing tag via the convert pipeline (faithful HandleTag).
  let emit = |into: &mut crate::value::Metadata, def: &'static TagDef, raw: TagValue| {
    let out = crate::convert::apply(def, &raw, print_conv_enabled);
    into.push(
      crate::value::Group::new("MPEG", def.group1()),
      def.name(),
      out,
    );
  };

  // MPEG.pm:513-517 — VBRFrames (key 1).
  let mut vbr_scale: Option<i64> = None;
  if flags & 0x01 != 0 {
    if pos.checked_add(4).map_or(true, |end| end > len) {
      return;
    }
    if is_vbr {
      let n = i64::from(u32::from_be_bytes([
        buff[pos],
        buff[pos + 1],
        buff[pos + 2],
        buff[pos + 3],
      ]));
      emit(into, &XING_VBR_FRAMES, TagValue::I64(n));
    }
    pos += 4;
  }
  // MPEG.pm:518-522 — VBRBytes (key 2).
  if flags & 0x02 != 0 {
    if pos.checked_add(4).map_or(true, |end| end > len) {
      return;
    }
    if is_vbr {
      let n = i64::from(u32::from_be_bytes([
        buff[pos],
        buff[pos + 1],
        buff[pos + 2],
        buff[pos + 3],
      ]));
      emit(into, &XING_VBR_BYTES, TagValue::I64(n));
    }
    pos += 4;
  }
  // MPEG.pm:523-527 — TOC (skipped; 100 bytes, no tag).
  if flags & 0x04 != 0 {
    if pos.checked_add(100).map_or(true, |end| end > len) {
      return;
    }
    pos += 100;
  }
  // MPEG.pm:528-533 — VBRScale (key 3) AND captured for LameVBRQuality/
  // LameQuality at MPEG.pm:564-565.
  if flags & 0x08 != 0 {
    if pos.checked_add(4).map_or(true, |end| end > len) {
      return;
    }
    let n = i64::from(u32::from_be_bytes([
      buff[pos],
      buff[pos + 1],
      buff[pos + 2],
      buff[pos + 3],
    ]));
    vbr_scale = Some(n);
    if is_vbr {
      emit(into, &XING_VBR_SCALE, TagValue::I64(n));
    }
    pos += 4;
  }
  // MPEG.pm:535-558 — LAME branch.
  if flags & 0x10 != 0 {
    // MPEG.pm:537 `last if $pos + 348 > $len`.
    if pos.checked_add(348).map_or(true, |end| end > len) {
      return;
    }
  } else if pos.checked_add(4).is_some_and(|end| end <= len) {
    // MPEG.pm:538-557 — non-LAME-flag branch: identify alternate encoders.
    let lib = &buff[pos..pos + 4];
    if lib != b"LAME" && lib != b"GOGO" {
      // MPEG.pm:541-555 — fallback string matches across the whole buffer.
      let encoder_str: Option<String> = if find_subseq(buff, b"RCA mp3PRO Encoder").is_some() {
        Some("RCA mp3PRO".to_string())
      } else if let Some(n) = find_subseq(buff, b"THOMSON mp3PRO Encoder") {
        // MPEG.pm:545 `$lib = 'Thomson mp3PRO'`; MPEG.pm:546 `$n += 22`;
        // MPEG.pm:547 `$lib .= ' ' . substr($$buffPt, $n, 6) if length(
        // $$buffPt) - $n >= 6`.
        let mut s = String::from("Thomson mp3PRO");
        let n2 = n + 22;
        if n2 <= len && len - n2 >= 6 {
          s.push(' ');
          s.push_str(&String::from_utf8_lossy(&buff[n2..n2 + 6]));
        }
        Some(s)
      } else if find_subseq(buff, b"MPGE").is_some() {
        Some("Gogo (<3.0)".to_string())
      } else {
        None
      };
      if let Some(s) = encoder_str {
        emit(into, &XING_ENCODER, TagValue::Str(s.into()));
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
  // MPEG.pm:562 `if ($enc ge 'LAME3.90')` — Perl `ge` is bytewise ASCII
  // comparison; faithful via `>=` on the byte slice.
  if enc >= b"LAME3.90" as &[u8] {
    // MPEG.pm:563 emit Encoder as the 9-byte version string.
    let enc_str = String::from_utf8_lossy(enc).into_owned();
    emit(into, &XING_ENCODER, TagValue::Str(enc_str.into()));
    // MPEG.pm:563-565 — LameVBRQuality / LameQuality fire whenever
    // `$vbrScale <= 100`. `$vbrScale` is declared `my $vbrScale;` at
    // MPEG.pm:510 and ONLY assigned at MPEG.pm:531 inside `if ($flags &
    // 0x08)`; absent that flag bit, it stays undef. Perl's `<=` on undef
    // runs in numeric context — undef promotes to 0 (with a runtime
    // "Use of uninitialized value" warning), so the comparison succeeds
    // and the calc emits `LameVBRQuality = int((100-0)/10) = 10` and
    // `LameQuality = (100-0) % 10 = 0`. Bundled `perl exiftool` on the
    // VBR_no_vbrscale.mp3 fixture confirms byte-exact. Faithful port:
    // substitute 0 when `vbr_scale` is None.
    let scale = vbr_scale.unwrap_or(0);
    if (0..=100).contains(&scale) {
      emit(
        into,
        &XING_LAME_VBR_QUALITY,
        TagValue::I64((100 - scale) / 10),
      );
      emit(into, &XING_LAME_QUALITY, TagValue::I64((100 - scale) % 10));
    }
    // MPEG.pm:568-573 — ProcessDirectory %MPEG::Lame at DirStart=$pos
    // over the rest of the buffer. Faithful inline:
    process_lame_binary(buff, pos, into, print_conv_enabled);
  } else {
    // MPEG.pm:575 — non-LAME-≥3.90 fallback: emit Encoder as a 20-byte
    // substring (cropped to remaining bytes).
    let want = pos + 20;
    let end = want.min(len);
    let enc_str = String::from_utf8_lossy(&buff[pos..end]).into_owned();
    emit(into, &XING_ENCODER, TagValue::Str(enc_str.into()));
  }
  // MPEG.pm:577 `last` — single-pass while.
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
/// Inlined here because `ProcessBinaryData` is otherwise unported; the
/// LAME table has 4 byte-indexed tags (offsets 9/10/20/24) with optional
/// `Mask` (ExifTool.pm:10067-10068 applies `($val & $mask) >>
/// $$tagInfo{BitShift}` BEFORE ValueConv, with `BitShift` derived from
/// `Mask`'s lowest set bit at ExifTool.pm:5905-5910).
fn process_lame_binary(
  buff: &[u8],
  pos: usize,
  into: &mut crate::value::Metadata,
  print_conv_enabled: bool,
) {
  // Helper: read byte at offset (relative to `pos`), apply mask+shift,
  // run through ValueConv/PrintConv, emit.
  let read_byte = |buff: &[u8], offset: usize| -> Option<u8> {
    let abs = pos.checked_add(offset)?;
    if abs < buff.len() {
      Some(buff[abs])
    } else {
      None
    }
  };
  let emit = |into: &mut crate::value::Metadata, def: &'static TagDef, raw_byte: u8| {
    let raw = TagValue::I64(i64::from(raw_byte));
    let out = crate::convert::apply(def, &raw, print_conv_enabled);
    into.push(
      crate::value::Group::new("MPEG", def.group1()),
      def.name(),
      out,
    );
  };
  // Offset 9: LameMethod, Mask 0x0f (BitShift 0 — lowest set bit at 0).
  if let Some(b) = read_byte(buff, 9) {
    emit(into, &LAME_METHOD, b & 0x0f);
  }
  // Offset 10: LameLowPassFilter, no Mask (whole byte).
  if let Some(b) = read_byte(buff, 10) {
    emit(into, &LAME_LOWPASS_FILTER, b);
  }
  // Offset 20: LameBitrate, no Mask.
  if let Some(b) = read_byte(buff, 20) {
    emit(into, &LAME_BITRATE, b);
  }
  // Offset 24: LameStereoMode, Mask 0x1c (BitShift 2 — lowest set bit at 2,
  // ExifTool.pm:5907-5909 derivation).
  if let Some(b) = read_byte(buff, 24) {
    emit(into, &LAME_STEREO_MODE, (b & 0x1c) >> 2);
  }
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
    // MPEG.pm:472 — `$$buffPt =~ m{(\xff.{3})}sg`. Find next `\xff`; the
    // 3 bytes after must also exist (else give up).
    let ff = data[p..].iter().position(|&b| b == 0xff)?;
    let start = p + ff;
    if start + 4 > data.len() {
      return None; // MPEG.pm:472 (no full 4-byte match possible)
    }
    let word = u32::from_be_bytes([
      data[start],
      data[start + 1],
      data[start + 2],
      data[start + 3],
    ]);
    let next_pos = start + 4; // Perl `pos` after matching 4 bytes
    match check_header(word, mp3) {
      HeaderCheck::Ok => return Some((word, next_pos)),
      HeaderCheck::Sync => {
        // MPEG.pm:474-476 — `pos -= 2` so the next find can latch onto a
        // `\xff` that started inside our candidate. We were at `pos =
        // next_pos`; backing up by 2 lands at `next_pos - 2 = start + 2`.
        // Our forward scan should pick up from there.
        p = next_pos.saturating_sub(2);
        // Guard: ensure forward progress (p MUST advance past start, else
        // we'd re-find the same `\xff` and loop forever).
        if p <= start {
          p = start + 1;
        }
      }
      HeaderCheck::Validation => {
        // MPEG.pm:486-490 — give up unless $ext eq 'MP3'.
        if !ext.eq_ignore_ascii_case("MP3") {
          return None;
        }
        // MPEG.pm:489 — `pos -= 1`. We were at `next_pos = start + 4`;
        // `pos -= 1` ⇒ next find starts at `start + 3`, ensuring the
        // current `\xff` (at `start`) is past.
        p = next_pos.saturating_sub(1);
        if p <= start {
          p = start + 1;
        }
      }
    }
  }
}

// ───────────────────────── FormatParser registration ─────────────────────────

/// MP3 / MPEG audio-frame parser. Registered in `formats::parser_for` at
/// the `"MP3"` file-type slot (until the ID3 parallel PR lands; see
/// module-header note).
///
/// This entry point applies the ID3.pm:1684-1729 `ProcessMP3` scan-buffer
/// bound BEFORE delegating to [`parse_mpeg_audio`]: ID3.pm:1704
/// `my $scanLen = ($$et{FILE_EXT} and $$et{FILE_EXT} eq 'MP3') ? 8192 : 256;`
/// — when invoked from a non-MP3-extension context (ID3.pm `ProcessMP3`
/// recovers MP3 from a stray sync byte in the first 256 bytes) we must
/// not silently accept a candidate sync past that boundary. Without this
/// bound, MP3 (weak magic) would falsely accept any file containing a
/// late `\xff` followed by 3 bytes that pass `check_header` — exactly
/// the gap Codex R1/F1 flagged.
pub struct ProcessMp3;

/// ID3.pm:1704 — `$scanLen` selection. Constant-fold-friendly helper so
/// the bound is documented at the call site AND in unit tests.
#[must_use]
pub(crate) const fn id3_process_mp3_scan_len(ext_is_mp3: bool) -> usize {
  // ID3.pm:1704: 8192 if FILE_EXT eq 'MP3', else 256. The Perl `eq`
  // compares against the uppercased `$$self{FILE_EXT}` (ExifTool.pm:2966
  // `GetFileExtension` returns it uppercased), so a case-insensitive
  // match on the Rust side (which already uppercases) is faithful.
  if ext_is_mp3 {
    8192
  } else {
    256
  }
}

impl ProcessMp3 {
  /// Offset-aware variant of [`ProcessMp3::process`] that mirrors bundled's
  /// `$raf->Seek($hdrEnd, 0)` + `$raf->Read($buff, $scanLen)` sequence at
  /// ID3.pm:1590 + ID3.pm:1705. Used by the ID3 dispatcher
  /// (`crate::formats::id3::process::ProcessMp3`) AFTER `process_id3_inner`
  /// returns: when an ID3v2 prefix was found, the audio loop seeks PAST the
  /// header (offset = bundled `$hdrEnd` = ID3.pm:1504) so that
  /// `ParseMPEGAudio` gets a FRESH $scanLen-byte window starting at the
  /// post-ID3 file position. Without this offset plumbing, a file with a
  /// large ID3v2 tag (e.g. embedded APIC artwork >8 KiB) would lose all
  /// MPEG audio tags because the 8192-byte scan window from offset 0 never
  /// reaches the post-ID3 audio frame.
  ///
  /// `start_offset` is bundled `$hdrEnd` (ID3.pm:1504). `0` reproduces the
  /// no-ID3 / raw-MP3 path of the trait `process` impl (byte-exact).
  /// `start_offset > data.len()` saturates to an empty slice (mirrors
  /// bundled's seek-past-EOF behavior — same pattern as `ape::ape_slice`
  /// at ape.rs:1024).
  pub(crate) fn process_with_start_offset(
    &self,
    ctx: &mut ParseContext<'_>,
    start_offset: usize,
  ) -> bool {
    // ID3.pm:1684-1729 `sub ProcessMP3`: when not ID3-tagged (raw-MP3
    // path = `start_offset == 0`), the recover path is
    // `$raf->Read($buff, $scanLen)` + `ParseMPEGAudio($et, \$buff, $mp3)`.
    // When ID3-tagged, bundled does `$raf->Seek($hdrEnd, 0)` first
    // (ID3.pm:1590) — the SAME read+parse pair, just from a non-zero file
    // position. The Perl `$buff` is a HARD slice — the bytes BEYOND
    // `$scanLen` are simply absent from the parser's view, so a late sync
    // byte cannot be latched. We emulate by bounding `data` to
    // `[start_offset..start_offset+scan_len]` BEFORE invoking
    // `parse_mpeg_audio`; `set_file_type`'s first-call-wins guard makes
    // the bounded buffer behave identically for the SetFileType branch.
    //
    // Borrow discipline: snapshot every immutable scalar/string input
    // from `ctx` FIRST (owned `SmolStr` / `Copy` locals); only then
    // grab `(&data, &mut meta)` via the disjoint-field split-borrow
    // accessor `data_and_metadata()`. The bounded slice is then a
    // sub-slice of the original `data` — no `Vec<u8>` copy.
    let ext_is_mp3 = ctx.ext().is_some_and(|e| e.eq_ignore_ascii_case("MP3"));
    let scan_len = id3_process_mp3_scan_len(ext_is_mp3);
    // ID3.pm:1715-1717 `my $ext = $$et{FILE_EXT} || ''; my $mp3 = ($ext eq
    // 'MUS') ? 0 : 1;  # MUS files are MP2 / ParseMPEGAudio($et, \$buff,
    // $mp3)`. The caller's `$mp3` flag is computed from the file
    // extension, NOT from the candidate file-type: bundled drops the
    // Layer III gate when FILE_EXT is `MUS` (Layer II audio dressed in a
    // `.mus` container). Without this caller-plumbed flag, a valid Layer
    // II `.mus` dispatched through `ProcessMp3` would be rejected by
    // MPEG.pm:485's `$mp3` Layer III check (Codex R3 finding). Case-
    // insensitive on the Rust side because `file_ext_for_name` already
    // uppercases (faithful to the Perl `eq 'MUS'` comparing against an
    // uppercased FILE_EXT from `GetFileExtension`, ExifTool.pm:2966).
    let mp3 = !ctx.ext().is_some_and(|e| e.eq_ignore_ascii_case("MUS"));
    // Owned snapshots of the non-data, non-metadata inputs (these reborrow
    // `&self`, so they must complete before the split-borrow below — but
    // they're tiny: SmolStr inline for the common short strings).
    let file_type_owned: smol_str::SmolStr = smol_str::SmolStr::new(ctx.file_type());
    let parent_type_owned: smol_str::SmolStr = smol_str::SmolStr::new(ctx.parent_type());
    let header_skip = ctx.header_skip();
    let ext_owned: Option<smol_str::SmolStr> = ctx.ext().map(smol_str::SmolStr::new);
    let print_conv_enabled = ctx.print_conv_enabled();
    // Split borrow: `(&data, &mut meta)` via disjoint fields — avoids the
    // prior `data.to_vec()` (up to 8 KiB per `ProcessMp3::process` call).
    let (data, meta) = ctx.data_and_metadata();
    // Slice from `start_offset` (bundled `$raf->Seek($hdrEnd, 0)` at
    // ID3.pm:1590). `get(start_offset..).unwrap_or(&[])` saturates to
    // empty when `start_offset > data.len()` (faithful to bundled's
    // seek-past-EOF: the subsequent `$raf->Read` returns 0 bytes and
    // ParseMPEGAudio's scan finds nothing). Same pattern as `ape.rs:1024`.
    let post_id3 = data.get(start_offset..).unwrap_or(&[]);
    let bounded_len = scan_len.min(post_id3.len());
    let bounded = &post_id3[..bounded_len];
    let mut sub = ParseContext::new(
      bounded,
      &file_type_owned,
      header_skip,
      &parent_type_owned,
      ext_owned,
      print_conv_enabled,
      meta,
    );
    parse_mpeg_audio(&mut sub, mp3)
  }
}

impl FormatParser for ProcessMp3 {
  fn process(&self, ctx: &mut ParseContext<'_>) -> bool {
    // Raw-MP3 dispatch path (no preceding ID3) — `$hdrEnd == 0`. Delegates
    // to the offset-aware variant with `start_offset = 0` so the bounded
    // slice IS `data[..scan_len]` byte-for-byte unchanged.
    self.process_with_start_offset(ctx, 0)
  }
}

// ───────────────────────── tests ─────────────────────────

#[cfg(test)]
mod tests {
  use super::*;
  use crate::value::Metadata;

  fn ctx_over<'a>(meta: &'a mut Metadata, data: &'a [u8], ft: &'a str) -> ParseContext<'a> {
    let ext = crate::filetype::file_ext_for_name(meta.source_file());
    ParseContext::new(data, ft, 0, ft, ext, true, meta)
  }

  #[test]
  fn check_header_basic_acceptance() {
    // Faithful MPEG-1 Layer III header for 128 kbps / 44.1 kHz / Joint Stereo:
    //   0xfffb904c (synthesized above; oracle: `perl exiftool mp3test.mp3`).
    assert_eq!(check_header(0xfffb_904c, false), HeaderCheck::Ok);
    assert_eq!(check_header(0xfffb_904c, true), HeaderCheck::Ok); // mp3 mode also Ok (Layer III)
  }

  #[test]
  fn check_header_rejects_each_invalid_field() {
    // Each fixture flips ONE byte of the canonical 0xfffb_904c header to
    // trigger exactly one MPEG.pm:479-484 reject. Comments cite the Perl
    // mask under test; the chosen word changes only the offending bits
    // from the base header.

    // MPEG.pm:479 — reserved version (Bit11-12 = 0b01 → byte 1 = 0xeb).
    assert_eq!(check_header(0xffeb_9040, false), HeaderCheck::Validation);
    // MPEG.pm:480 — reserved layer (Bit13-14 = 0b00 → byte 1 = 0xf9).
    assert_eq!(check_header(0xfff9_9040, false), HeaderCheck::Validation);
    // MPEG.pm:481 — "free" bitrate (Bit16-19 = 0b0000 → byte 2 = 0x00).
    assert_eq!(check_header(0xfffb_0040, false), HeaderCheck::Validation);
    // MPEG.pm:482 — bad bitrate (Bit16-19 = 0b1111 → byte 2 = 0xf0).
    assert_eq!(check_header(0xfffb_f040, false), HeaderCheck::Validation);
    // MPEG.pm:483 — reserved sample-rate (Bit20-21 = 0b11 → byte 2 = 0x9c).
    assert_eq!(check_header(0xfffb_9c40, false), HeaderCheck::Validation);
    // MPEG.pm:484 — reserved emphasis (Bit30-31 = 0b10 → byte 3 = 0x42).
    assert_eq!(check_header(0xfffb_9042, false), HeaderCheck::Validation);
  }

  #[test]
  fn check_header_sync_reject() {
    // Sync bits not all 1 (e.g. top byte 0x7f). Reports Sync (NOT
    // Validation) so the scan advances by a different amount.
    assert_eq!(check_header(0x7fff_904c, false), HeaderCheck::Sync);
  }

  #[test]
  fn check_header_mp3_mode_rejects_non_layer3() {
    // MPEG.pm:485 mask 0x060000 is the Layer raw bits (Bit13-14 of the
    // word = byte 1 mask 0x06); mp3-mode requires `($word & 0x060000) ==
    // 0x020000`, i.e. Layer raw = 1 (display "Layer III" via MPEG.pm:38
    // `1 => 3`). Construct a Layer-II variant of the canonical Layer-III
    // header 0xfffb_904c by flipping byte-1 mask 0x06 (0xfb → 0xfd):
    assert_eq!(check_header(0xfffd_904c, true), HeaderCheck::Validation);
    // Same header is valid OUTSIDE mp3-mode (Layer II is accepted when
    // `ParseMPEGAudio` is called from a non-MP3 context, e.g.
    // ParseMPEGAudioVideo).
    assert_eq!(check_header(0xfffd_904c, false), HeaderCheck::Ok);
  }

  #[test]
  fn scan_finds_header_at_offset() {
    // Build a fixture with 3 leading garbage bytes then the valid header.
    let mut data = vec![0x00u8, 0x12, 0x34]; // garbage
    data.extend_from_slice(&0xfffb_904c_u32.to_be_bytes());
    data.extend(std::iter::repeat(0).take(413));
    // Word found, `pos_after` is `start + 4` = 3 + 4 = 7.
    assert_eq!(scan_for_header(&data, false, "MP3"), Some((0xfffb_904c, 7)));
  }

  #[test]
  fn scan_skips_false_ff_then_finds_real_header() {
    // A `\xff` followed by 0x12 (sync bits fail) must NOT abort the scan —
    // we advance and find the real header later.
    let mut data = vec![0xff, 0x12, 0x34, 0x56]; // false sync (sync-bit fail)
    data.extend_from_slice(&0xfffb_904c_u32.to_be_bytes());
    // Real header starts at offset 4 ⇒ `pos_after` = 8.
    assert_eq!(scan_for_header(&data, false, "MP3"), Some((0xfffb_904c, 8)));
  }

  #[test]
  fn scan_validation_reject_outside_mp3_ext_gives_up() {
    // A `\xff` followed by validation-fail (free bitrate). Without `$ext eq
    // MP3`, MPEG.pm:488 returns 0 immediately.
    let data = [0xff, 0xfb, 0x00, 0x40]; // free bitrate (Validation reject)
    assert!(scan_for_header(&data, false, "WAV").is_none()); // non-MP3 ext: give up
  }

  #[test]
  fn scan_validation_reject_inside_mp3_ext_keeps_scanning() {
    // With ext=MP3, validation rejects advance and retry. Append a real
    // header after the bad bytes:
    let mut data = vec![0xff, 0xfb, 0x00, 0x40]; // bad bitrate
    data.extend_from_slice(&0xfffb_904c_u32.to_be_bytes());
    // Real header starts at offset 4 ⇒ `pos_after` = 8.
    assert_eq!(scan_for_header(&data, false, "MP3"), Some((0xfffb_904c, 8)));
  }

  #[test]
  fn parse_emits_expected_tags_print_on() {
    // Synthesized 4-byte header followed by 413 zero bytes (we don't reach
    // the Xing tail).
    let mut data = vec![0xff, 0xfb, 0x90, 0x4c];
    data.extend(std::iter::repeat(0).take(413));
    let mut m = Metadata::new("x.mp3");
    let mut c = ctx_over(&mut m, &data, "MP3");
    assert!(ProcessMp3.process(&mut c));
    let names_vals: Vec<_> = m
      .tags()
      .iter()
      .map(|t| (t.name(), t.value().clone()))
      .collect();
    // The frame above decodes as: version=1, layer=3 (display), bitrate=128 kbps,
    // sample-rate=44100, channel=Joint Stereo, ms-stereo=Off, intensity=Off,
    // copyright=True, original=True, emphasis=None.
    assert!(names_vals.contains(&("FileType", TagValue::Str("MP3".into()))));
    assert!(names_vals.contains(&("MPEGAudioVersion", TagValue::I64(1))));
    assert!(names_vals.contains(&("AudioLayer", TagValue::I64(3))));
    assert!(names_vals.contains(&("AudioBitrate", TagValue::Str("128 kbps".into()))));
    assert!(names_vals.contains(&("SampleRate", TagValue::I64(44100))));
    assert!(names_vals.contains(&("ChannelMode", TagValue::Str("Joint Stereo".into()))));
    assert!(names_vals.contains(&("MSStereo", TagValue::Str("Off".into()))));
    assert!(names_vals.contains(&("IntensityStereo", TagValue::Str("Off".into()))));
    assert!(names_vals.contains(&("CopyrightFlag", TagValue::Str("True".into()))));
    assert!(names_vals.contains(&("OriginalMedia", TagValue::Str("True".into()))));
    assert!(names_vals.contains(&("Emphasis", TagValue::Str("None".into()))));
    // ModeExtension MUST NOT be emitted (layer 3 ⇒ Bit26 & Bit27, not Bit26-27).
    assert!(!names_vals.iter().any(|(n, _)| *n == "ModeExtension"));
  }

  #[test]
  fn parse_emits_expected_tags_print_off() {
    // Same fixture, -n: raw integer values (no PrintConv). ValueConv still
    // applies (e.g. AudioBitrate goes through the VC hash → 128000).
    let mut data = vec![0xff, 0xfb, 0x90, 0x4c];
    data.extend(std::iter::repeat(0).take(413));
    let mut m = Metadata::new("x.mp3");
    let ext = crate::filetype::file_ext_for_name(m.source_file());
    let mut c = ParseContext::new(&data, "MP3", 0, "MP3", ext, false, &mut m);
    assert!(ProcessMp3.process(&mut c));
    let names_vals: Vec<_> = m
      .tags()
      .iter()
      .map(|t| (t.name(), t.value().clone()))
      .collect();
    // Raw values: ver=3, layer=1 (raw), bitrate VC = 128000, sr=0 (no VC!),
    // ch=1, mss=0, intensity=0, copy=1, orig=1, emph=0.
    assert!(names_vals.contains(&("MPEGAudioVersion", TagValue::I64(3))));
    assert!(names_vals.contains(&("AudioLayer", TagValue::I64(1))));
    assert!(names_vals.contains(&("AudioBitrate", TagValue::I64(128000))));
    assert!(names_vals.contains(&("SampleRate", TagValue::I64(0))));
    assert!(names_vals.contains(&("ChannelMode", TagValue::I64(1))));
    assert!(names_vals.contains(&("MSStereo", TagValue::I64(0))));
    assert!(names_vals.contains(&("IntensityStereo", TagValue::I64(0))));
    assert!(names_vals.contains(&("CopyrightFlag", TagValue::I64(1))));
    assert!(names_vals.contains(&("OriginalMedia", TagValue::I64(1))));
    assert!(names_vals.contains(&("Emphasis", TagValue::I64(0))));
  }

  #[test]
  fn reject_returns_false_with_no_filetype_tag() {
    // Faithful MPEG.pm:472 `return 0` — buffer with no \xff sync byte. NO
    // SetFileType call ⇒ no File:* tags.
    let data = [0x00u8; 32];
    let mut m = Metadata::new("x.mp3");
    let mut c = ctx_over(&mut m, &data, "MP3");
    assert!(!ProcessMp3.process(&mut c));
    assert!(m.tags().iter().all(|t| t.name() != "FileType"));
  }

  #[test]
  fn convert_bitrate_faithful() {
    // ExifTool.pm:6891-6902 — faithful port.
    // Below 100 -> %.3g. We feed integers (post-ValueConv shape).
    assert_eq!(
      convert_bitrate(&TagValue::I64(8000)),
      TagValue::Str("8 kbps".into())
    );
    assert_eq!(
      convert_bitrate(&TagValue::I64(64000)),
      TagValue::Str("64 kbps".into())
    );
    // 128000 -> 128 kbps (b=128 -> >= 100 -> %.0f).
    assert_eq!(
      convert_bitrate(&TagValue::I64(128000)),
      TagValue::Str("128 kbps".into())
    );
    // 320000 -> 320 kbps.
    assert_eq!(
      convert_bitrate(&TagValue::I64(320000)),
      TagValue::Str("320 kbps".into())
    );
    // 448000 -> 448 kbps.
    assert_eq!(
      convert_bitrate(&TagValue::I64(448000)),
      TagValue::Str("448 kbps".into())
    );
    // "free" sentinel ⇒ IsFloat false ⇒ unchanged.
    assert_eq!(
      convert_bitrate(&TagValue::Str("free".into())),
      TagValue::Str("free".into())
    );
    // Bare integer "32" string -> IsFloat true -> "32 bps" (b<1000).
    // Hmm actually only if it parses. Let's not test that case (no MPEG
    // call-site produces a Str of digits — VC hash maps directly to I64).
  }

  #[test]
  fn convert_bitrate_higher_units() {
    // 1,000,000 -> 1 Mbps (b=1000 -> /1000 -> 1; b<100 -> %.3g -> "1").
    assert_eq!(
      convert_bitrate(&TagValue::I64(1_000_000)),
      TagValue::Str("1 Mbps".into())
    );
    // 2_500_000 -> 2.5 Mbps (b=2500 → /1000 → 2.5; b<100 → %.3g → "2.5").
    assert_eq!(
      convert_bitrate(&TagValue::I64(2_500_000)),
      TagValue::Str("2.5 Mbps".into())
    );
    // 1e10 -> 10 Gbps (b=1e10 → /1000 thrice → 10; b<100 → %.3g → "10").
    assert_eq!(
      convert_bitrate(&TagValue::I64(10_000_000_000)),
      TagValue::Str("10 Gbps".into())
    );
  }

  // ─────────── F1: ID3.pm:1684-1729 ProcessMP3 bounded-scan ───────────

  #[test]
  fn id3_process_mp3_scan_len_ext_branches() {
    // ID3.pm:1704: 8192 if FILE_EXT eq 'MP3', else 256. Pin both arms so a
    // refactor never silently loses the bound.
    assert_eq!(id3_process_mp3_scan_len(true), 8192);
    assert_eq!(id3_process_mp3_scan_len(false), 256);
  }

  /// F1/RED-GREEN: a synthesized junk-`.mp3` whose first 8192 bytes contain
  /// no valid MPEG audio sync, with a perfectly valid Layer III header at
  /// offset 8200. Bundled ExifTool's `ProcessMP3` (ID3.pm:1704 `$scanLen
  /// = 8192`) reads only the first 8192 bytes and rejects ⇒ `File format
  /// error`. WITHOUT the bound, our unbounded `scan_for_header` would
  /// latch onto the 0xff at offset 8200 and falsely accept — exactly the
  /// gap Codex R1/F1 flagged.
  ///
  /// Composition: 8200 bytes of `((i*137+41) % 0xfe)` filler (no `0xff`
  /// among the filler, no all-same-byte; mirrors the conformance fixture)
  /// then the canonical Layer III header `0xfffb_904c` then 413 zero
  /// payload bytes. With the F1 fix, `ProcessMp3::process` must:
  /// 1) reject the bounded buffer ⇒ return false,
  /// 2) emit NO File:* tags (SetFileType never called).
  #[test]
  fn f1_bounded_scan_rejects_late_header_under_mp3_ext() {
    let mut filler = Vec::with_capacity(8200);
    for i in 1..=8200u32 {
      filler.push(((i * 137 + 41) % 0xfe) as u8);
    }
    let mut data: Vec<u8> = filler;
    data.extend_from_slice(&0xfffb_904c_u32.to_be_bytes()); // header at 8200
    data.extend(std::iter::repeat(0).take(413));
    let mut m = Metadata::new("x.mp3");
    let ext = crate::filetype::file_ext_for_name(m.source_file());
    let mut c = ParseContext::new(&data, "MP3", 0, "MP3", ext, true, &mut m);
    let rv = ProcessMp3.process(&mut c);
    assert!(
      !rv,
      "ProcessMP3 must reject when valid sync byte is past $scanLen=8192 \
       (ID3.pm:1704). Got accept ⇒ unbounded scan ⇒ Codex R1/F1 unfixed."
    );
    // SetFileType was never called → no File:* tags slipped through.
    assert!(
      m.tags().iter().all(|t| t.name() != "FileType"),
      "Rejected MP3 must not have finalized File:FileType."
    );
  }

  /// F1/GREEN-anchor: same shape but header at offset 8188 (so its 4 bytes
  /// span 8188..8192, still fully within the 8192-byte scan buffer).
  /// Bundled ExifTool accepts ⇒ exifast must too.
  #[test]
  fn f1_bounded_scan_accepts_header_at_8188() {
    let mut filler = Vec::with_capacity(8188);
    for i in 1..=8188u32 {
      filler.push(((i * 137 + 41) % 0xfe) as u8);
    }
    let mut data: Vec<u8> = filler;
    data.extend_from_slice(&0xfffb_904c_u32.to_be_bytes()); // header at 8188
    data.extend(std::iter::repeat(0).take(413));
    let mut m = Metadata::new("x.mp3");
    let ext = crate::filetype::file_ext_for_name(m.source_file());
    let mut c = ParseContext::new(&data, "MP3", 0, "MP3", ext, true, &mut m);
    assert!(ProcessMp3.process(&mut c));
    assert!(m.tags().iter().any(|t| t.name() == "FileType"));
    assert!(m.tags().iter().any(|t| t.name() == "AudioBitrate"));
  }

  /// F1/non-MP3-ext-branch: same junk-prefix shape, header at offset 256,
  /// extension `.dat` (any non-MP3) ⇒ scan_len = 256. The `0xff` byte at
  /// offset 256 lives JUST PAST the scan boundary (offsets 0..255 only):
  /// no sync can be found ⇒ reject. Without the bound a late `0xff`
  /// would be found ⇒ false accept.
  ///
  /// Important: this exercises `ProcessMp3::process` DIRECTLY (skipping
  /// the detection front-end which would never route a `.dat` to MP3 in
  /// real disk flow; the scan_len=256 branch in `ProcessMp3` is exercised
  /// when ID3::ProcessMP3 invokes us with a non-MP3 extension on a file
  /// that DID match ID3 magic — that path will be wired up by the ID3
  /// parallel PR, but the bound itself must be correct here).
  #[test]
  fn f1_bounded_scan_rejects_late_header_under_non_mp3_ext() {
    let mut filler = Vec::with_capacity(256);
    for i in 1..=256u32 {
      filler.push(((i * 137 + 41) % 0xfe) as u8);
    }
    let mut data: Vec<u8> = filler;
    data.extend_from_slice(&0xfffb_904c_u32.to_be_bytes()); // header at 256
    data.extend(std::iter::repeat(0).take(413));
    let mut m = Metadata::new("x.dat");
    let ext = crate::filetype::file_ext_for_name(m.source_file());
    let mut c = ParseContext::new(&data, "MP3", 0, "MP3", ext, true, &mut m);
    assert!(!ProcessMp3.process(&mut c));
    assert!(m.tags().iter().all(|t| t.name() != "FileType"));
  }

  /// F1/non-MP3-ext-GREEN: header at offset 252 (so its 4 bytes span
  /// 252..255, fully within scan_len=256). Must accept.
  #[test]
  fn f1_bounded_scan_accepts_header_at_252_under_non_mp3_ext() {
    let mut filler = Vec::with_capacity(252);
    for i in 1..=252u32 {
      filler.push(((i * 137 + 41) % 0xfe) as u8);
    }
    let mut data: Vec<u8> = filler;
    data.extend_from_slice(&0xfffb_904c_u32.to_be_bytes()); // header at 252
    data.extend(std::iter::repeat(0).take(413));
    let mut m = Metadata::new("x.dat");
    let ext = crate::filetype::file_ext_for_name(m.source_file());
    let mut c = ParseContext::new(&data, "MP3", 0, "MP3", ext, true, &mut m);
    assert!(ProcessMp3.process(&mut c));
    assert!(m.tags().iter().any(|t| t.name() == "FileType"));
  }

  // ─────────── F2: %MPEG::Xing + %MPEG::Lame tail ───────────

  /// Build a minimal VBR Xing+LAME MP3 in memory: header 0xfffb_904c
  /// (MPEG-1 / Layer III / 128 kbps / 44.1 kHz / JointStereo) + 32-byte
  /// side-info + "Xing"+flags+VBRFrames/Bytes+TOC+Scale + 348-byte LAME
  /// block (`LAME3.99r\x04\xa0...0x80...0x0c...`). Total: 504 bytes.
  fn build_vbr_xing_lame_fixture() -> Vec<u8> {
    let mut d = Vec::with_capacity(504);
    d.extend_from_slice(&0xfffb_904c_u32.to_be_bytes()); // audio header
    d.extend(std::iter::repeat(0).take(32)); // side info (joint stereo, v1 ⇒ 32)
    d.extend_from_slice(b"Xing"); // magic
    d.extend_from_slice(&0x1fu32.to_be_bytes()); // flags: frames|bytes|toc|scale|lame
    d.extend_from_slice(&1000u32.to_be_bytes()); // VBRFrames
    d.extend_from_slice(&200_000u32.to_be_bytes()); // VBRBytes
    d.extend(std::iter::repeat(0).take(100)); // TOC (skipped)
    d.extend_from_slice(&78u32.to_be_bytes()); // VBRScale (LameVBRQuality=2, LameQuality=2)
                                               // LAME block starts here. Pre-fill 348 bytes so the LAME-flag length
                                               // gate (MPEG.pm:537 `last if $pos + 348 > $len`) passes.
    let start = d.len();
    d.extend(std::iter::repeat(0).take(348));
    // Stamp the LAME fields by absolute offset into `d`.
    let stamp = |buf: &mut Vec<u8>, off: usize, b: u8| buf[start + off] = b;
    // Offsets 0..8 inside the LAME block: "LAME3.99r" (9 bytes).
    for (i, b) in b"LAME3.99r".iter().enumerate() {
      stamp(&mut d, i, *b);
    }
    stamp(&mut d, 9, 0x04); // LameMethod: raw byte; mask 0x0f → 4 → "VBR (new/mtrh)"
    stamp(&mut d, 10, 0xa0); // LameLowPassFilter: 0xa0=160 → ×100 = 16000 → "16 kHz"
    stamp(&mut d, 20, 0x80); // LameBitrate: 0x80=128 → ×1000 = 128000 → "128 kbps"
    stamp(&mut d, 24, 0x0c); // LameStereoMode: (0x0c & 0x1c)>>2 = 3 → "Joint Stereo"
    d
  }

  #[test]
  fn parse_emits_xing_lame_tags_print_on() {
    let data = build_vbr_xing_lame_fixture();
    let mut m = Metadata::new("x.mp3");
    let mut c = ctx_over(&mut m, &data, "MP3");
    assert!(ProcessMp3.process(&mut c));
    let names_vals: Vec<_> = m
      .tags()
      .iter()
      .map(|t| (t.name(), t.value().clone()))
      .collect();
    // Xing tags (MPEG.pm:327-332).
    assert!(names_vals.contains(&("VBRFrames", TagValue::I64(1000))));
    assert!(names_vals.contains(&("VBRBytes", TagValue::I64(200_000))));
    assert!(names_vals.contains(&("VBRScale", TagValue::I64(78))));
    assert!(names_vals.contains(&("Encoder", TagValue::Str("LAME3.99r".into()))));
    assert!(names_vals.contains(&("LameVBRQuality", TagValue::I64(2))));
    assert!(names_vals.contains(&("LameQuality", TagValue::I64(2))));
    // Lame sub-table (MPEG.pm:344-381).
    assert!(names_vals.contains(&("LameMethod", TagValue::Str("VBR (new/mtrh)".into()))));
    assert!(names_vals.contains(&("LameLowPassFilter", TagValue::Str("16 kHz".into()))));
    assert!(names_vals.contains(&("LameBitrate", TagValue::Str("128 kbps".into()))));
    assert!(names_vals.contains(&("LameStereoMode", TagValue::Str("Joint Stereo".into()))));
  }

  #[test]
  fn parse_emits_xing_lame_tags_print_off() {
    // -n: raw values pass-through; ValueConvs still apply (×100, ×1000).
    let data = build_vbr_xing_lame_fixture();
    let mut m = Metadata::new("x.mp3");
    let ext = crate::filetype::file_ext_for_name(m.source_file());
    let mut c = ParseContext::new(&data, "MP3", 0, "MP3", ext, false, &mut m);
    assert!(ProcessMp3.process(&mut c));
    let names_vals: Vec<_> = m
      .tags()
      .iter()
      .map(|t| (t.name(), t.value().clone()))
      .collect();
    // Unconverted raw integers / strings.
    assert!(names_vals.contains(&("VBRFrames", TagValue::I64(1000))));
    assert!(names_vals.contains(&("Encoder", TagValue::Str("LAME3.99r".into()))));
    assert!(names_vals.contains(&("LameMethod", TagValue::I64(4))));
    assert!(names_vals.contains(&("LameLowPassFilter", TagValue::I64(16_000))));
    assert!(names_vals.contains(&("LameBitrate", TagValue::I64(128_000))));
    assert!(names_vals.contains(&("LameStereoMode", TagValue::I64(3))));
  }

  #[test]
  fn parse_info_frame_suppresses_vbr_tags() {
    // MPEG.pm:511 `my $isVBR = ($buff !~ /^Info/)` — Info-frame magic does
    // NOT emit VBRFrames/VBRBytes/VBRScale (the `if $isVBR` gates at
    // MPEG.pm:515/521/532). LAME path can still run (Encoder emitted).
    let mut d = build_vbr_xing_lame_fixture();
    // Replace "Xing" with "Info".
    let xing_offset = 4 + 32;
    d[xing_offset..xing_offset + 4].copy_from_slice(b"Info");
    let mut m = Metadata::new("x.mp3");
    let mut c = ctx_over(&mut m, &d, "MP3");
    assert!(ProcessMp3.process(&mut c));
    let names: Vec<_> = m.tags().iter().map(|t| t.name()).collect();
    assert!(!names.contains(&"VBRFrames"));
    assert!(!names.contains(&"VBRBytes"));
    assert!(!names.contains(&"VBRScale"));
    // Encoder still emitted from the LAME block (MPEG.pm:563).
    assert!(names.contains(&"Encoder"));
  }

  #[test]
  fn parse_no_xing_magic_silent_skip() {
    // Audio header + side-info bytes that do NOT start with Xing/Info ⇒
    // MPEG.pm:508 `last`. Audio tags must still emit; no Xing tags.
    let mut d = Vec::with_capacity(40);
    d.extend_from_slice(&0xfffb_904c_u32.to_be_bytes());
    d.extend(std::iter::repeat(0).take(36));
    let mut m = Metadata::new("x.mp3");
    let mut c = ctx_over(&mut m, &d, "MP3");
    assert!(ProcessMp3.process(&mut c));
    let names: Vec<_> = m.tags().iter().map(|t| t.name()).collect();
    assert!(names.contains(&"AudioBitrate"));
    assert!(!names.contains(&"VBRFrames"));
    assert!(!names.contains(&"Encoder"));
  }

  #[test]
  fn parse_xing_truncated_at_each_length_gate() {
    // Each length gate in MPEG.pm:505/516/520/525/530/537 must silently
    // exit. Build a buffer that PASSES the audio header + side-info but
    // is truncated mid-VBR-tail; the audio tags emit, the Xing tags do
    // not.
    // Header + 32 side-info + "Xing" + flags (12 bytes used out of the
    // first 13 of `head8`+flags), but truncate before VBRFrames.
    let mut d = Vec::with_capacity(44);
    d.extend_from_slice(&0xfffb_904c_u32.to_be_bytes());
    d.extend(std::iter::repeat(0).take(32));
    d.extend_from_slice(b"Xing");
    d.extend_from_slice(&0x01u32.to_be_bytes()); // flag VBRFrames only
                                                 // Truncate: do NOT append the 4-byte VBRFrames; MPEG.pm:516 `last if
                                                 // $pos + 4 > $len`.
    let mut m = Metadata::new("x.mp3");
    let mut c = ctx_over(&mut m, &d, "MP3");
    assert!(ProcessMp3.process(&mut c));
    let names: Vec<_> = m.tags().iter().map(|t| t.name()).collect();
    assert!(names.contains(&"AudioBitrate"));
    assert!(!names.contains(&"VBRFrames"));
  }

  #[test]
  fn lame_lowpass_print_integer_and_fractional() {
    // 16_000 → "16 kHz" (16000/1000 = 16.0; integer-valued formats w/o
    // decimal).
    assert_eq!(
      lame_lowpass_print(&TagValue::I64(16_000)),
      TagValue::Str("16 kHz".into())
    );
    // 16_500 → "16.5 kHz" (fractional preserves the digits).
    assert_eq!(
      lame_lowpass_print(&TagValue::I64(16_500)),
      TagValue::Str("16.5 kHz".into())
    );
  }
}
