// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "mpc")]
//! Faithful port of `Image::ExifTool::MPC` (lib/Image/ExifTool/MPC.pm).
//! PROCESS_PROC is `FLAC::ProcessBitStream` (MPC.pm:22) → [`crate::bitstream`].
//!
//! A typed [`MpcMeta<'a>`] is produced by the
//! [`crate::parser_new::FormatParser`] trait; the engine entry `process`
//! drives the typed `serialize_tags` path into the engine
//! `tagmap::TagMap` so the serialized JSON stays
//! byte-exact with bundled `perl exiftool`.
//!
//! ## Chained-format role
//!
//! Unlike the F1 leaves (AAC/DV — single-format, no chained sub-blocks),
//! MPC is a chained format (MPC.pm:84-87, 111-113):
//!
//! 1. **Leading ID3** — `unless ($$et{DoneID3}) { ProcessID3 ... and return 1; }`
//!    (MPC.pm:84-87). The bundled audio-loop (ID3.pm:1582-1601) recursively
//!    re-enters ProcessMPC with `DoneID3` set when ID3 detects a prefix; our
//!    flattened single-pass model runs ID3 first, then the MP+ header from
//!    the post-ID3 offset (mirrors APE.pm:122-127 / [`crate::formats::ape`]'s
//!    APE-style flatten).
//! 2. **APE trailer** — `Image::ExifTool::APE::ProcessAPE(...)` (MPC.pm:111-113).
//!    Always invoked after the MP+ header, even on the non-SV7 warning arm;
//!    bundled returns 1 regardless (void context, MPC.pm:113-115).
//!
//! ID3 and APE are dispatched by the engine entry `process` via the chained
//! helpers (`crate::formats::id3::process::process_id3_chained`,
//! `crate::formats::ape::ProcessApe::process_trailer_only`) on the
//! `ParseContext` value sink. The typed [`MpcMeta<'a>`] carries
//! [`Option<&'a [u8]>`] byte placeholders for the ID3-prefix and APE-trailer
//! slices so a future pass can compose them with the typed `Id3Meta`/`ApeMeta`.
//!
//! ## %MPC::Main table (MPC.pm:21-72)
//!
//! Bit fields walked by `process_bit_stream` (MPC.pm:22 `PROCESS_PROC =>
//! \&Image::ExifTool::FLAC::ProcessBitStream`) on the 32-byte MP+ header
//! with byte order `'II'` (MPC.pm:98).
//!
//! | Bit range  | Tag                  | PrintConv                    |
//! |-----------|----------------------|------------------------------|
//! | 032-063   | TotalFrames          | none                         |
//! | 080-081   | SampleRate           | hash (0/1/2/3 ⇒ Hz numbers)  |
//! | 084-087   | Quality              | hash (1..15, sparse strings) |
//! | 088-093   | MaxBand              | none                         |
//! | 096-111   | ReplayGainTrackPeak  | none                         |
//! | 112-127   | ReplayGainTrackGain  | none                         |
//! | 128-143   | ReplayGainAlbumPeak  | none                         |
//! | 144-159   | ReplayGainAlbumGain  | none                         |
//! | 179       | FastSeek             | hash (0/1 ⇒ No/Yes)          |
//! | 191       | Gapless              | hash (0/1 ⇒ No/Yes)          |
//! | 216-223   | EncoderVersion       | func (`$val =~ s/(\d)(\d)(\d)$/$1.$2.$3/`) |

use crate::{
  bitstream::{BitOrder, process_bit_stream},
  parser_new::{FormatParser, SharedFlags, parser_sealed},
  tagtable::{PrintConv, PrintConvHash, PrintValue, TagDef, TagId, TagTable, ValueConv},
  value::{Metadata, TagValue},
};

// ===========================================================================
// `%MPC::Main` tag table (MPC.pm:21-72)
//
// Retained so the [`process_bit_stream`] engine (and the engine entry
// `process` below) can drive the same FLAC::ProcessBitStream PROCESS_PROC as
// bundled Perl. The typed [`MpcMeta`] holds the raw bit-field scalars
// (post-bit-stream, pre-PrintConv); PrintConv is applied at emit time by
// `serialize_tags` to mirror ExifTool's `$$self{OPTIONS}{PrintConv}`
// toggle (ExifTool.pm:5710).
// ===========================================================================

// MPC.pm:28 — TotalFrames (Bit032-063 = 32-bit integer): no PrintConv.
static TOTAL_FRAMES: TagDef = TagDef::new("TotalFrames", "MPC", ValueConv::None, PrintConv::None);

// MPC.pm:29-37 — SampleRate. Hash PrintConv: int-keyed in Perl, string-keyed
// in our model (Perl `$$conv{$val}` keys are stringified). VALUES are bare
// numbers (e.g. `0 => 44100`) ⇒ PrintValue::I64 — matches AAC.pm's identical
// `%convSampleRate` shape, faithfully a hash-of-int → -j emits JSON numbers.
static SAMPLE_RATE: TagDef = TagDef::new(
  "SampleRate",
  "MPC",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::I64(44100)),
    ("1", PrintValue::I64(48000)),
    ("2", PrintValue::I64(37800)),
    ("3", PrintValue::I64(32000)),
  ])),
);

// MPC.pm:38-54 — Quality. Hash PrintConv: keys `1, 5, 6, 7, 8, 9, 10, 11,
// 12, 13, 14, 15` (sparse — the Perl table has NO entries for 2/3/4: a
// `Quality` raw value of 2/3/4 falls through to ExifTool's generic
// `Unknown (N)` fallback per `ExifTool.pm:3622`). Values are strings: some
// look like bare integers in quotes (e.g. `5 => '0'`, `6 => '1'`); Perl
// preserves string vs int via the literal, so these are STRING values in
// the Perl source ⇒ emit as PrintValue::Str under -j.
static QUALITY: TagDef = TagDef::new(
  "Quality",
  "MPC",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("1", PrintValue::Str("Unstable/Experimental")),
    ("5", PrintValue::Str("0")),
    ("6", PrintValue::Str("1")),
    ("7", PrintValue::Str("2 (Telephone)")),
    ("8", PrintValue::Str("3 (Thumb)")),
    ("9", PrintValue::Str("4 (Radio)")),
    ("10", PrintValue::Str("5 (Standard)")),
    ("11", PrintValue::Str("6 (Xtreme)")),
    ("12", PrintValue::Str("7 (Insane)")),
    ("13", PrintValue::Str("8 (BrainDead)")),
    ("14", PrintValue::Str("9")),
    ("15", PrintValue::Str("10")),
  ])),
);

// MPC.pm:55 — MaxBand (6-bit integer): no PrintConv.
static MAX_BAND: TagDef = TagDef::new("MaxBand", "MPC", ValueConv::None, PrintConv::None);

// MPC.pm:56-59 — ReplayGain* (each a 16-bit integer): no PrintConv.
static REPLAY_GAIN_TRACK_PEAK: TagDef = TagDef::new(
  "ReplayGainTrackPeak",
  "MPC",
  ValueConv::None,
  PrintConv::None,
);
static REPLAY_GAIN_TRACK_GAIN: TagDef = TagDef::new(
  "ReplayGainTrackGain",
  "MPC",
  ValueConv::None,
  PrintConv::None,
);
static REPLAY_GAIN_ALBUM_PEAK: TagDef = TagDef::new(
  "ReplayGainAlbumPeak",
  "MPC",
  ValueConv::None,
  PrintConv::None,
);
static REPLAY_GAIN_ALBUM_GAIN: TagDef = TagDef::new(
  "ReplayGainAlbumGain",
  "MPC",
  ValueConv::None,
  PrintConv::None,
);

// MPC.pm:60-63 — FastSeek (1-bit). Hash PrintConv 0=>'No', 1=>'Yes'.
static FAST_SEEK: TagDef = TagDef::new(
  "FastSeek",
  "MPC",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::Str("No")),
    ("1", PrintValue::Str("Yes")),
  ])),
);

// MPC.pm:64-67 — Gapless (1-bit). Hash PrintConv 0=>'No', 1=>'Yes'.
static GAPLESS: TagDef = TagDef::new(
  "Gapless",
  "MPC",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::Str("No")),
    ("1", PrintValue::Str("Yes")),
  ])),
);

/// MPC.pm:70 `$val =~ s/(\d)(\d)(\d)$/$1.$2.$3/; $val`.
///
/// Perl's `=~ s/(\d)(\d)(\d)$/$1.$2.$3/` performs ONE substitution at the
/// tail of `$val`'s stringified scalar (the regex is tail-anchored on three
/// trailing digits). Faithful Rust transliteration:
///
/// - **Match path** (the value's last 3 chars are ASCII digits): insert
///   `.` between them and return as `TagValue::Str` (the substitution always
///   produces a string in Perl, because the `$1.$2.$3` replacement contains
///   non-digit characters; the JSON writer then emits a JSON string).
/// - **No-match path** (Perl `s///` left `$val` unchanged): return the
///   ORIGINAL `TagValue` UNCHANGED, faithfully preserving its scalar type.
///   Perl's failed `s///` does NOT coerce a dual-typed `$val` to a string;
///   if the bit-stream produced a `TagValue::I64`, the JSON writer must
///   still emit a JSON number. Forcing `TagValue::Str` here would break
///   byte-exactness on a 1- or 2-digit version (e.g. an integer `15` would
///   serialize as JSON `"15"` instead of `15`).
///
/// The byte 0x73 (115 decimal) from the oracle MPC.mpc header takes the
/// match path and yields `"1.1.5"`, byte-exact vs bundled Perl.
fn encoder_version_print(val: &TagValue) -> TagValue {
  // Stringify the way Perl's `$val =~ s/.../.../ ` would see it. The
  // string is consumed only to check the regex tail and to build the
  // dotted output; on no-match the ORIGINAL `val` is returned unchanged
  // (preserving its scalar type — see fn doc).
  let s: String = match val {
    TagValue::I64(n) => n.to_string(),
    TagValue::Str(s) => s.to_string(),
    // F64/Bool/Rational/Bytes/List don't appear here (the bit-stream
    // ValueConv produces an integer for the 8-bit EncoderVersion field),
    // but be defensive: an unexpected non-numeric scalar matches no Perl
    // `\d` and falls to the no-match path ⇒ return `val` unchanged.
    _ => return val.clone(),
  };
  let bytes = s.as_bytes();
  if bytes.len() < 3 || !bytes[bytes.len() - 3..].iter().all(u8::is_ascii_digit) {
    // No-match: Perl's `s///` leaves `$val` unchanged ⇒ return the ORIGINAL
    // (preserving I64 vs Str typing). Forcing `TagValue::Str(s)` here would
    // turn a 2-digit version like `15` into JSON `"15"` instead of `15`,
    // diverging from bundled `perl exiftool`.
    return val.clone();
  }
  let (head, tail) = s.split_at(s.len() - 3);
  // Tail is exactly 3 ASCII digits; insert dots: "abc" -> "a.b.c". The
  // substitution always produces a string in Perl (the `$1.$2.$3` replacement
  // contains non-digit chars), so the match-path return is `TagValue::Str`.
  let mut out = String::with_capacity(head.len() + 5);
  out.push_str(head);
  let tb = tail.as_bytes();
  out.push(tb[0] as char);
  out.push('.');
  out.push(tb[1] as char);
  out.push('.');
  out.push(tb[2] as char);
  TagValue::Str(out.into())
}

// MPC.pm:68-71 — EncoderVersion. Func PrintConv per MPC.pm:70.
static ENCODER_VERSION: TagDef = TagDef::new(
  "EncoderVersion",
  "MPC",
  ValueConv::None,
  PrintConv::Func(encoder_version_print),
);

fn mpc_get(id: TagId) -> Option<&'static TagDef> {
  match id {
    TagId::Str("Bit032-063") => Some(&TOTAL_FRAMES),
    TagId::Str("Bit080-081") => Some(&SAMPLE_RATE),
    TagId::Str("Bit084-087") => Some(&QUALITY),
    TagId::Str("Bit088-093") => Some(&MAX_BAND),
    TagId::Str("Bit096-111") => Some(&REPLAY_GAIN_TRACK_PEAK),
    TagId::Str("Bit112-127") => Some(&REPLAY_GAIN_TRACK_GAIN),
    TagId::Str("Bit128-143") => Some(&REPLAY_GAIN_ALBUM_PEAK),
    TagId::Str("Bit144-159") => Some(&REPLAY_GAIN_ALBUM_GAIN),
    TagId::Str("Bit179") => Some(&FAST_SEEK),
    TagId::Str("Bit191") => Some(&GAPLESS),
    TagId::Str("Bit216-223") => Some(&ENCODER_VERSION),
    _ => None,
  }
}

/// `%MPC::Main` (MPC.pm:21-72). family-0 group "MPC"; family-1 "MPC".
/// Family-2 'Audio' (MPC.pm:23 `GROUPS => {2=>'Audio'}`) is not emitted
/// under `-G1` (the JSON key prefix is family-1, not family-2).
pub static MPC_MAIN: TagTable = TagTable::new("MPC", mpc_get);

// TEMPLATE: keep MPC_BIT_KEYS in sync with mpc_get's `Bit*` arms AND in
// ascending zero-padded bit-offset order — `bitstream::process_bit_stream`'s
// `i2 >= dirLen` early-exit silently skips later fields if mis-ordered.
/// Sorted `Bit<a>-<b>` keys of `%MPC::Main` (ExifTool `sort keys`,
/// FLAC.pm:172) in ASCENDING bit-offset order (required by
/// `bitstream::process_bit_stream`).
pub const MPC_BIT_KEYS: &[&str] = &[
  "Bit032-063", // TotalFrames        (MPC.pm:28)
  "Bit080-081", // SampleRate         (MPC.pm:29)
  "Bit084-087", // Quality            (MPC.pm:38)
  "Bit088-093", // MaxBand            (MPC.pm:55)
  "Bit096-111", // ReplayGainTrackPeak (MPC.pm:56)
  "Bit112-127", // ReplayGainTrackGain (MPC.pm:57)
  "Bit128-143", // ReplayGainAlbumPeak (MPC.pm:58)
  "Bit144-159", // ReplayGainAlbumGain (MPC.pm:59)
  "Bit179",     // FastSeek           (MPC.pm:60)
  "Bit191",     // Gapless            (MPC.pm:64)
  "Bit216-223", // EncoderVersion     (MPC.pm:68)
];

// ===========================================================================
// Typed Meta — `MpcMeta<'a>`
// ===========================================================================

/// SV7 header bit-field scalars (MPC.pm:21-72), post-bit-stream extraction
/// and pre-PrintConv. The bit-stream walker
/// ([`process_bit_stream`]) emits these as `TagValue::I64`; the typed
/// values here are the lifted primitives with the smallest faithful width
/// (e.g. 32-bit `TotalFrames`, 16-bit `ReplayGain*`, 8-bit `EncoderVersion`).
///
/// PrintConv (`%SampleRate`, `%Quality`, `%FastSeek/Gapless`,
/// [`encoder_version_print`]) is applied at emit time by `serialize_tags`
/// — `print_conv=true` ⇒ formatted strings or substituted numbers; `false` ⇒
/// the raw scalars here as JSON numbers.
///
/// **D8 — no public fields, accessors only.** Construct only via the parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MpcSv7Header {
  /// Bit032-063 — `TotalFrames` raw u32 (MPC.pm:28).
  total_frames: u32,
  /// Bit080-081 — `SampleRate` raw index (0..=3, MPC.pm:29-37).
  /// PrintConv hash maps 0⇒44100, 1⇒48000, 2⇒37800, 3⇒32000.
  sample_rate_index: u8,
  /// Bit084-087 — `Quality` raw index (1..=15, MPC.pm:38-54). The PrintConv
  /// hash is sparse (no entries for 2/3/4); fall-through emits the generic
  /// `Unknown (N)` form (ExifTool.pm:3622).
  quality_index: u8,
  /// Bit088-093 — `MaxBand` raw 6-bit integer (MPC.pm:55).
  max_band: u8,
  /// Bit096-111 — `ReplayGainTrackPeak` raw u16 (MPC.pm:56).
  replay_gain_track_peak: u16,
  /// Bit112-127 — `ReplayGainTrackGain` raw u16 (MPC.pm:57).
  replay_gain_track_gain: u16,
  /// Bit128-143 — `ReplayGainAlbumPeak` raw u16 (MPC.pm:58).
  replay_gain_album_peak: u16,
  /// Bit144-159 — `ReplayGainAlbumGain` raw u16 (MPC.pm:59).
  replay_gain_album_gain: u16,
  /// Bit179 — `FastSeek` raw 1-bit (MPC.pm:60-63).
  fast_seek: u8,
  /// Bit191 — `Gapless` raw 1-bit (MPC.pm:64-67).
  gapless: u8,
  /// Bit216-223 — `EncoderVersion` raw 8-bit (MPC.pm:68-71). PrintConv runs
  /// `$val =~ s/(\d)(\d)(\d)$/$1.$2.$3/` — `115` ⇒ `"1.1.5"`.
  encoder_version: u8,
}

impl MpcSv7Header {
  /// `TotalFrames` raw u32 (MPC.pm:28).
  #[must_use]
  pub const fn total_frames(&self) -> u32 {
    self.total_frames
  }
  /// `SampleRate` raw index (0..=3, MPC.pm:29-37). Use
  /// [`Self::sample_rate_hz`] for the PrintConv-mapped Hz number.
  #[must_use]
  pub const fn sample_rate_index(&self) -> u8 {
    self.sample_rate_index
  }
  /// `SampleRate` in Hz from the MPC.pm:31-36 PrintConv hash. `None` if the
  /// raw index is off-table (unreachable: bit field is 2-bit, all 4 values
  /// are mapped).
  #[must_use]
  pub const fn sample_rate_hz(&self) -> Option<u32> {
    match self.sample_rate_index {
      0 => Some(44100), // MPC.pm:32
      1 => Some(48000), // MPC.pm:33
      2 => Some(37800), // MPC.pm:34
      3 => Some(32000), // MPC.pm:35
      _ => None,        // unreachable for a 2-bit index
    }
  }
  /// `Quality` raw index (1..=15, MPC.pm:38-54).
  #[must_use]
  pub const fn quality_index(&self) -> u8 {
    self.quality_index
  }
  /// `Quality` PrintConv string (MPC.pm:38-54). `None` on a hash miss
  /// (raw 0, 2, 3, 4 — sparse keys); the legacy bridge then emits the
  /// generic `Unknown (N)` fallback (ExifTool.pm:3622).
  #[must_use]
  pub const fn quality_name(&self) -> Option<&'static str> {
    match self.quality_index {
      1 => Some("Unstable/Experimental"),
      5 => Some("0"),
      6 => Some("1"),
      7 => Some("2 (Telephone)"),
      8 => Some("3 (Thumb)"),
      9 => Some("4 (Radio)"),
      10 => Some("5 (Standard)"),
      11 => Some("6 (Xtreme)"),
      12 => Some("7 (Insane)"),
      13 => Some("8 (BrainDead)"),
      14 => Some("9"),
      15 => Some("10"),
      _ => None,
    }
  }
  /// `MaxBand` raw 6-bit (MPC.pm:55).
  #[must_use]
  pub const fn max_band(&self) -> u8 {
    self.max_band
  }
  /// `ReplayGainTrackPeak` raw u16 (MPC.pm:56).
  #[must_use]
  pub const fn replay_gain_track_peak(&self) -> u16 {
    self.replay_gain_track_peak
  }
  /// `ReplayGainTrackGain` raw u16 (MPC.pm:57).
  #[must_use]
  pub const fn replay_gain_track_gain(&self) -> u16 {
    self.replay_gain_track_gain
  }
  /// `ReplayGainAlbumPeak` raw u16 (MPC.pm:58).
  #[must_use]
  pub const fn replay_gain_album_peak(&self) -> u16 {
    self.replay_gain_album_peak
  }
  /// `ReplayGainAlbumGain` raw u16 (MPC.pm:59).
  #[must_use]
  pub const fn replay_gain_album_gain(&self) -> u16 {
    self.replay_gain_album_gain
  }
  /// `FastSeek` raw 1-bit (MPC.pm:60-63). `true` ⇒ "Yes".
  #[must_use]
  pub const fn fast_seek(&self) -> bool {
    self.fast_seek != 0
  }
  /// `Gapless` raw 1-bit (MPC.pm:64-67). `true` ⇒ "Yes".
  #[must_use]
  pub const fn gapless(&self) -> bool {
    self.gapless != 0
  }
  /// `EncoderVersion` raw byte (MPC.pm:68-71). Use
  /// [`Self::encoder_version_str`] for the dotted PrintConv form.
  #[must_use]
  pub const fn encoder_version(&self) -> u8 {
    self.encoder_version
  }
}

/// Typed MPC metadata — the lib-first output of [`ProcessMpc`].
///
/// Holds the typed bit-field scalars from the SV7 header (when present) +
/// the version-specific warning string (when the MP+ version is anything
/// other than SV7, MPC.pm:107-109). PrintConv (hash + func) is applied at
/// emit time by `serialize_tags` to mirror ExifTool's
/// `$$self{OPTIONS}{PrintConv}` toggle (ExifTool.pm:5710).
///
/// ## Chained sub-blocks
///
/// MPC dispatches both ID3 (MPC.pm:84-87) and APE (MPC.pm:111-113). The typed
/// [`MpcMeta`] captures their input byte slices as `Option<&'a [u8]>`
/// placeholders so a future pass can compose them with the typed
/// [`crate::formats::id3::Id3Meta`] / [`crate::formats::ape::ApeMeta`]; the
/// engine entry `process` below dispatches both on the `ParseContext` value
/// sink, so the serialized JSON is byte-exact with bundled `perl exiftool`.
///
/// **D8 — no public fields, accessors only.**
///
/// **Lifetimes.** `'a` is held for the ID3/APE byte placeholders that
/// borrow from the input slice; the SV7 header is owned primitives.
#[derive(Debug, Clone, Copy)]
pub struct MpcMeta<'a> {
  /// MP+ version low nibble (MPC.pm:93 `ord($1) & 0x0f`). The SV7 bit
  /// walker only runs when `version == 0x07`; other versions trigger the
  /// MPC.pm:107-109 warning arm.
  version: u8,
  /// SV7 header fields (MPC.pm:21-72). `Some` iff the MP+ version low
  /// nibble is `0x07`; `None` for the non-SV7 warning arm
  /// (MPC.pm:107-109).
  sv7_header: Option<MpcSv7Header>,
  /// Whether the non-SV7 warning (MPC.pm:108 `'Audio info currently not
  /// extracted from this version MPC file'`) should be emitted.
  warn_unsupported_version: bool,
  /// **Phase F5 placeholder.** Byte slice of any ID3-prefix block seen
  /// BEFORE the MP+ magic (MPC.pm:84-87). The legacy bridge dispatches it
  /// through [`crate::formats::id3::process::process_id3_chained`]; the
  /// typed `Id3Meta` from the parallel F2 agent will eventually consume
  /// this slice (Phase F5-integration). Today: always `None` — F5 does NOT
  /// pre-scan for ID3 (the bridge calls ID3 directly on `ctx.data()`).
  id3_prefix: Option<&'a [u8]>,
  /// **Phase F5 placeholder.** Byte slice of any APE trailer block seen
  /// AFTER the MP+ header (MPC.pm:111-113). The legacy bridge dispatches
  /// it through [`crate::formats::ape::ProcessApe::process_trailer_only`];
  /// the typed `ApeMeta` from the parallel F3 agent will eventually
  /// consume this slice. Today: always `None` for the same reason as
  /// `id3_prefix`.
  ape_trailer: Option<&'a [u8]>,
}

impl<'a> MpcMeta<'a> {
  /// MP+ version low nibble (MPC.pm:93). `0x07` ⇒ SV7 path; anything else
  /// ⇒ warning arm (MPC.pm:107-109).
  #[must_use]
  pub const fn version(&self) -> u8 {
    self.version
  }
  /// SV7 header fields, present iff [`Self::version`] returned `0x07`.
  #[must_use]
  pub const fn sv7_header(&self) -> Option<&MpcSv7Header> {
    self.sv7_header.as_ref()
  }
  /// `true` if the MPC.pm:108 warning (`'Audio info currently not extracted
  /// from this version MPC file'`) should be emitted.
  #[must_use]
  pub const fn warn_unsupported_version(&self) -> bool {
    self.warn_unsupported_version
  }
  /// **Phase F5 placeholder.** ID3-prefix bytes (always `None` today; see
  /// the field-level doc).
  #[must_use]
  pub const fn id3_prefix(&self) -> Option<&'a [u8]> {
    self.id3_prefix
  }
  /// **Phase F5 placeholder.** APE-trailer bytes (always `None` today; see
  /// the field-level doc).
  #[must_use]
  pub const fn ape_trailer(&self) -> Option<&'a [u8]> {
    self.ape_trailer
  }
}

// ===========================================================================
// `MpcContext<'a>` — per-format input view for chained dispatch
// ===========================================================================

/// Per-format input view for [`ProcessMpc`]. Wraps the input bytes and a
/// mutable [`SharedFlags`] handle, faithful to spec §6.4: "Leaves (MOI,
/// AAC, DV, Audible) take just `&'a [u8]`; chained formats (ID3 → APE,
/// APE → ID3, MPC → ID3 + APE, …) wrap `&'a [u8]` + `&'a mut SharedFlags`."
///
/// MPC chains BOTH ID3 (MPC.pm:84-87) and APE (MPC.pm:111-113), so it
/// carries the SharedFlags. The Phase F5 typed [`ProcessMpc::parse`] does
/// NOT itself dispatch to ID3/APE (those typed parsers land in the parallel
/// F2/F3 agents and the F5-integration composes them); the field is in the
/// surface for forward compatibility.
///
/// D8: PRIVATE fields, accessors only.
#[derive(Debug)]
pub struct MpcContext<'a> {
  data: &'a [u8],
  // Held for cross-format chained dispatch. F5's typed `parse` does not
  // mutate the shared flags directly — they're threaded so a future
  // F5-integration pass can chain into typed `Id3Meta` / `ApeMeta`.
  #[allow(dead_code)]
  shared: &'a mut SharedFlags,
}

impl<'a> MpcContext<'a> {
  /// Construct a chained-MPC context with the input bytes and a mutable
  /// [`SharedFlags`] handle.
  #[must_use]
  pub fn new(data: &'a [u8], shared: &'a mut SharedFlags) -> Self {
    Self { data, shared }
  }
  /// Borrow the input bytes.
  #[must_use]
  pub const fn data(&self) -> &'a [u8] {
    self.data
  }
  /// Borrow the cross-format shared flags. Phase G integration will use
  /// this to thread `done_id3` / `done_ape` updates from typed `Id3Meta` /
  /// `ApeMeta` runs.
  pub fn shared(&mut self) -> &mut SharedFlags {
    self.shared
  }
}

// ===========================================================================
// `ProcessMpc` — the lib-first parser
// ===========================================================================

/// MPC parser (faithful `ProcessMPC`, MPC.pm:79-116).
#[derive(Debug, Clone, Copy)]
pub struct ProcessMpc;

impl parser_sealed::Sealed for ProcessMpc {}

impl FormatParser for ProcessMpc {
  /// GAT: the Meta borrows from the input `'a` (Codex AF2).
  type Meta<'a> = MpcMeta<'a>;
  /// Chained-format Context: `data + SharedFlags`. See [`MpcContext`].
  type Context<'a> = MpcContext<'a>;
  /// Rust-level fatal error (currently none — every bad input is `Ok(None)`).
  type Error = MpcError;

  /// Parse an MPC file's bytes into a typed [`MpcMeta`], or `None` if the
  /// buffer is not a valid MP+ stream (short read or wrong magic; MPC.pm:92).
  ///
  /// Reads the 32-byte MP+ header, validates the magic (MPC.pm:92), and
  /// extracts the SV7 bit-fields when `vers == 0x07`. The chained ID3
  /// (MPC.pm:84-87) and APE (MPC.pm:111-113) dispatches are driven by the
  /// engine entry [`ProcessMpc::process`] (which owns the `ParseContext`
  /// value sink), not by this header-only typed `parse`.
  fn parse<'a>(&self, ctx: Self::Context<'a>) -> Result<Option<Self::Meta<'a>>, MpcError> {
    parse_inner(ctx.data())
  }
}

/// Lib-first direct entry. Same as [`FormatParser::parse`] but returns an
/// [`MpcMeta`] that borrows from the input buffer (for the F5 placeholder
/// byte slices; the SV7 header is owned).
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today; reserved for
/// future I/O wrappers).
pub fn parse_borrowed(data: &[u8]) -> Result<Option<MpcMeta<'_>>, MpcError> {
  parse_inner(data)
}

/// Inner parser — produces a borrow-from-input [`MpcMeta`]. The
/// [`FormatParser::Meta`] GAT (`type Meta<'a> = MpcMeta<'a>`) returns
/// this borrowed form directly into the closed
/// [`crate::parser_new::AnyMeta`] enum (Codex AF2). The `id3_prefix` /
/// `ape_trailer` placeholders are always `None` in F5.
fn parse_inner(data: &[u8]) -> Result<Option<MpcMeta<'_>>, MpcError> {
  // MPC.pm:92 `$raf->Read($buff,32) == 32 and $buff =~ /^MP\+(.)/s or return 0`.
  if data.len() < 32 {
    return Ok(None); // short read ⇒ Perl `$raf->Read != 32` ⇒ return 0
  }
  let hdr = &data[..32];
  if &hdr[..3] != b"MP+" {
    return Ok(None); // magic mismatch ⇒ Perl regex no-match ⇒ return 0
  }
  // MPC.pm:93 `my $vers = ord($1) & 0x0f` — low nibble of byte 3.
  let version = hdr[3] & 0x0f;

  // MPC.pm:97-106 — SV7 path: ProcessDirectory(MPC::Main) over the 32-byte
  // header, byte order 'II' (MPC.pm:98). `Options('Verbose')` (MPC.pm:100)
  // is faithfully deferred (no Verbose option on the read path).
  let (sv7_header, warn_unsupported_version) = if version == 0x07 {
    (Some(extract_sv7_header(hdr)), false)
  } else {
    // MPC.pm:107-109 `$et->Warn('Audio info currently not extracted from
    // this version MPC file')`.
    (None, true)
  };

  Ok(Some(MpcMeta {
    version,
    sv7_header,
    warn_unsupported_version,
    // F5 placeholders — see field docs on `MpcMeta`.
    id3_prefix: None,
    ape_trailer: None,
  }))
}

/// Extract the SV7 bit-fields from the 32-byte MP+ header. Reuses
/// [`process_bit_stream`] (the shared FLAC::ProcessBitStream engine) for
/// byte-exact extraction faithful to MPC.pm:22, then lifts the emitted
/// `TagValue::I64` scalars into typed primitives on [`MpcSv7Header`].
///
/// The bit-stream walker pushes into a side [`Metadata`] (`print_conv=false`
/// so the staged values are post-ValueConv raw scalars — `ValueConv::None`
/// for every MPC field, so these are the literal bit-extracted integers).
/// `serialize_tags` applies PrintConv at emit time.
fn extract_sv7_header(hdr: &[u8]) -> MpcSv7Header {
  // Staging Metadata captures the bit-stream walker's emissions. The walker
  // always emits `TagValue::I64` for these ≤ 32-bit fields (see the AAC
  // pilot — same pattern), so the lift is a direct `as` cast.
  let mut staging = Metadata::new("mpc-staging");
  process_bit_stream(
    hdr,
    BitOrder::Ii, // MPC.pm:98 SetByteOrder('II') — little-endian
    MPC_BIT_KEYS,
    &MPC_MAIN,
    &mut staging,
    /* print_conv_enabled */ false,
  );

  // Defaults are 0 for every field — the bit-stream walker hits every key
  // for a well-formed 32-byte header; on a short buffer the walker breaks
  // early via FLAC.pm:177 `last if $i2 >= $dirLen`. The 32-byte gate above
  // ensures the full walk in production; the defaults guard against
  // pathological inputs.
  let mut h = MpcSv7Header {
    total_frames: 0,
    sample_rate_index: 0,
    quality_index: 0,
    max_band: 0,
    replay_gain_track_peak: 0,
    replay_gain_track_gain: 0,
    replay_gain_album_peak: 0,
    replay_gain_album_gain: 0,
    fast_seek: 0,
    gapless: 0,
    encoder_version: 0,
  };
  for tag in staging.tags() {
    let TagValue::I64(n) = tag.value() else {
      continue; // unreachable for these fields under print_conv=false
    };
    let n = *n;
    match tag.name() {
      "TotalFrames" => h.total_frames = n as u32,
      "SampleRate" => h.sample_rate_index = n as u8,
      "Quality" => h.quality_index = n as u8,
      "MaxBand" => h.max_band = n as u8,
      "ReplayGainTrackPeak" => h.replay_gain_track_peak = n as u16,
      "ReplayGainTrackGain" => h.replay_gain_track_gain = n as u16,
      "ReplayGainAlbumPeak" => h.replay_gain_album_peak = n as u16,
      "ReplayGainAlbumGain" => h.replay_gain_album_gain = n as u16,
      "FastSeek" => h.fast_seek = n as u8,
      "Gapless" => h.gapless = n as u8,
      "EncoderVersion" => h.encoder_version = n as u8,
      _ => {}
    }
  }
  h
}

// ===========================================================================
// `serialize_tags` — typed Meta → TagMap
// ===========================================================================

#[cfg(feature = "alloc")]
impl MpcMeta<'_> {
  /// Emit MPC tags into the writer in `%MPC::Main` walk order (MPC.pm:21-72:
  /// TotalFrames, SampleRate, Quality, MaxBand, ReplayGain×4, FastSeek,
  /// Gapless, EncoderVersion) — faithful to the bundled-Perl bit-stream
  /// iteration order.
  ///
  /// `print_conv=true` ⇒ PrintConv formatted values (`-j` mode):
  /// - `SampleRate` ⇒ Hz number from the hash (e.g. `44100`)
  /// - `Quality` ⇒ named string from the hash (e.g. `"5 (Standard)"`)
  /// - `FastSeek` / `Gapless` ⇒ `"No"` / `"Yes"`
  /// - `EncoderVersion` ⇒ dotted string (e.g. `"1.1.5"`)
  ///
  /// `print_conv=false` ⇒ post-ValueConv raw scalars (`-n` mode): every
  /// field emits its raw integer (sample_rate_index, quality_index, etc.).
  ///
  /// **Non-SV7 arm.** When [`MpcMeta::sv7_header`] is `None`
  /// (MPC.pm:107-109), no MPC:* tags are emitted; the warning is pushed by
  /// the legacy bridge or directly by a lib caller via
  /// `TagMap::write_warning` at the end of this fn.
  pub(crate) fn serialize_tags(
    &self,
    print_conv: bool,
    out: &mut crate::tagmap::TagMap,
  ) -> Result<(), core::convert::Infallible> {
    const GROUP: &str = "MPC";

    if let Some(h) = self.sv7_header.as_ref() {
      // MPC.pm:28 — TotalFrames: no conversions, identical under -j and -n.
      out.write_u64(GROUP, "TotalFrames", u64::from(h.total_frames))?;

      // MPC.pm:29-37 — SampleRate. -j: hash hit yields the Hz integer
      // (PrintValue::I64). -n: raw index.
      if print_conv {
        // sample_rate_hz() is always Some for a 2-bit index (all 4
        // values mapped); fall through to raw if ever None.
        match h.sample_rate_hz() {
          Some(hz) => out.write_u64(GROUP, "SampleRate", u64::from(hz))?,
          None => out.write_u64(GROUP, "SampleRate", u64::from(h.sample_rate_index))?,
        }
      } else {
        out.write_u64(GROUP, "SampleRate", u64::from(h.sample_rate_index))?;
      }

      // MPC.pm:38-54 — Quality. -j: hash hit yields a PrintValue::Str
      // (e.g. "5 (Standard)" for index 10); miss falls back to "Unknown
      // (N)" (ExifTool.pm:3622 — the generic PrintConv hash-miss path).
      // -n: raw index.
      if print_conv {
        if let Some(name) = h.quality_name() {
          out.write_str(GROUP, "Quality", name)?;
        } else {
          let idx = h.quality_index;
          out.write_fmt(GROUP, "Quality", |w| write!(w, "Unknown ({idx})"))?;
        }
      } else {
        out.write_u64(GROUP, "Quality", u64::from(h.quality_index))?;
      }

      // MPC.pm:55 — MaxBand: no conversions.
      out.write_u64(GROUP, "MaxBand", u64::from(h.max_band))?;

      // MPC.pm:56-59 — ReplayGain×4: no conversions.
      out.write_u64(
        GROUP,
        "ReplayGainTrackPeak",
        u64::from(h.replay_gain_track_peak),
      )?;
      out.write_u64(
        GROUP,
        "ReplayGainTrackGain",
        u64::from(h.replay_gain_track_gain),
      )?;
      out.write_u64(
        GROUP,
        "ReplayGainAlbumPeak",
        u64::from(h.replay_gain_album_peak),
      )?;
      out.write_u64(
        GROUP,
        "ReplayGainAlbumGain",
        u64::from(h.replay_gain_album_gain),
      )?;

      // MPC.pm:60-63 — FastSeek. -j: 0⇒"No", 1⇒"Yes". -n: raw 0/1.
      if print_conv {
        out.write_str(
          GROUP,
          "FastSeek",
          if h.fast_seek != 0 { "Yes" } else { "No" },
        )?;
      } else {
        out.write_u64(GROUP, "FastSeek", u64::from(h.fast_seek))?;
      }

      // MPC.pm:64-67 — Gapless. Same shape as FastSeek.
      if print_conv {
        out.write_str(GROUP, "Gapless", if h.gapless != 0 { "Yes" } else { "No" })?;
      } else {
        out.write_u64(GROUP, "Gapless", u64::from(h.gapless))?;
      }

      // MPC.pm:68-71 — EncoderVersion. -j: dotted via the substitution
      // function (115 ⇒ "1.1.5"). -n: raw byte (115). The match path is
      // unconditional for valid 3-digit numbers: every u8 ≥ 100 takes the
      // match path; u8 < 100 (1- or 2-digit) takes the no-match path and
      // emits the raw integer faithfully.
      if print_conv {
        // Stringify the raw u8 and apply the Perl `s/(\d)(\d)(\d)$/$1.$2.$3/`
        // substitution. For raw byte n:
        //   n >= 100 ⇒ 3 trailing digits ⇒ match ⇒ "head.lhs.mid.tail"
        //   n < 100  ⇒ no match ⇒ emit raw integer
        // (This mirrors `encoder_version_print` above with the I64 input.)
        let n = u32::from(h.encoder_version);
        let s = n.to_string();
        let bytes = s.as_bytes();
        if bytes.len() >= 3 && bytes[bytes.len() - 3..].iter().all(u8::is_ascii_digit) {
          out.write_fmt(GROUP, "EncoderVersion", |w| {
            let (head, tail) = s.split_at(s.len() - 3);
            let tb = tail.as_bytes();
            w.write_str(head)?;
            w.write_char(tb[0] as char)?;
            w.write_char('.')?;
            w.write_char(tb[1] as char)?;
            w.write_char('.')?;
            w.write_char(tb[2] as char)?;
            Ok(())
          })?;
        } else {
          // No-match path: emit the raw integer faithfully (Perl `s///`
          // leaves $val unchanged, preserving I64 typing — the JSON
          // writer emits a bare number, NOT a quoted string).
          out.write_u64(GROUP, "EncoderVersion", u64::from(h.encoder_version))?;
        }
      } else {
        out.write_u64(GROUP, "EncoderVersion", u64::from(h.encoder_version))?;
      }
    }

    // MPC.pm:107-109 — non-SV7 warning. Emit AFTER the (empty) tag block;
    // bundled `perl exiftool -j -G1` surfaces `ExifTool:Warning` as the
    // first non-File: entry (the serializer emits the warning at the front
    // of the JSON object). Both the engine [`TagMap`] and lib callers
    // (TagMap) route this through `TagMap::write_warning`.
    if self.warn_unsupported_version {
      out.write_warning("Audio info currently not extracted from this version MPC file")?;
    }
    Ok(())
  }
}

// ===========================================================================
// `MpcError` — Rust-level fatal modes (currently none)
// ===========================================================================

/// Rust-level fatal modes for MPC parsing. Currently empty — every bad
/// input produces `Ok(None)` (Perl `return 0`). Reserved for future I/O
/// wrappers if streaming readers are added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpcError {}

impl core::fmt::Display for MpcError {
  fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match *self {}
  }
}

#[cfg(feature = "std")]
impl std::error::Error for MpcError {}

// ===========================================================================
// Engine entry — typed parse + File:* + sink into `Metadata`
// ===========================================================================

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser_new::FormatParser;
  use crate::tagmap::TagMap;

  // ---------- Tag table + bit-keys faithfulness --------------------------

  #[test]
  fn table_and_keys_are_faithful() {
    let g = MPC_MAIN.get();
    // MPC.pm:28
    assert_eq!(g(TagId::Str("Bit032-063")).unwrap().name(), "TotalFrames");
    // MPC.pm:29-37: SampleRate (Hash PrintConv 0..3)
    let sr = g(TagId::Str("Bit080-081")).unwrap();
    assert_eq!(sr.name(), "SampleRate");
    assert!(matches!(sr.print_conv(), PrintConv::Hash(_)));
    // MPC.pm:38-54: Quality (Hash PrintConv 1..15)
    let q = g(TagId::Str("Bit084-087")).unwrap();
    assert_eq!(q.name(), "Quality");
    // MPC.pm:55
    assert_eq!(g(TagId::Str("Bit088-093")).unwrap().name(), "MaxBand");
    // MPC.pm:56-59
    assert_eq!(
      g(TagId::Str("Bit096-111")).unwrap().name(),
      "ReplayGainTrackPeak"
    );
    assert_eq!(
      g(TagId::Str("Bit112-127")).unwrap().name(),
      "ReplayGainTrackGain"
    );
    assert_eq!(
      g(TagId::Str("Bit128-143")).unwrap().name(),
      "ReplayGainAlbumPeak"
    );
    assert_eq!(
      g(TagId::Str("Bit144-159")).unwrap().name(),
      "ReplayGainAlbumGain"
    );
    // MPC.pm:60-63 FastSeek (Hash 0/1 -> No/Yes)
    assert_eq!(g(TagId::Str("Bit179")).unwrap().name(), "FastSeek");
    // MPC.pm:64-67 Gapless (Hash 0/1 -> No/Yes)
    assert_eq!(g(TagId::Str("Bit191")).unwrap().name(), "Gapless");
    // MPC.pm:68-71 EncoderVersion (Func PrintConv)
    assert_eq!(
      g(TagId::Str("Bit216-223")).unwrap().name(),
      "EncoderVersion"
    );
    // Bad key -> None
    assert!(g(TagId::Str("Bit999")).is_none());
    assert!(g(TagId::Int(0)).is_none());
    // group0 = "MPC" (MPC.pm:21 package; MPC.pm:23 GROUPS=>{2=>'Audio'} is the
    // family-2 group which is not emitted under -G1).
    assert_eq!(MPC_MAIN.group0(), "MPC");
    // TEMPLATE INVARIANT: every MPC_BIT_KEYS entry must resolve through mpc_get.
    for key in MPC_BIT_KEYS {
      assert!(
        g(TagId::Str(key)).is_some(),
        "MPC_BIT_KEYS entry {key:?} missing from mpc_get"
      );
    }
    // Ascending bit-offset order (required by process_bit_stream's i2>=dirLen).
    let mut prev = 0usize;
    for key in MPC_BIT_KEYS {
      let n: usize = key
        .strip_prefix("Bit")
        .and_then(|s| s.split('-').next())
        .and_then(|s| s.parse().ok())
        .unwrap();
      assert!(n >= prev, "MPC_BIT_KEYS not ascending at {key:?}");
      prev = n;
    }
  }

  #[test]
  fn encoder_version_print_conv_inserts_dots() {
    // MPC.pm:70 `$val =~ s/(\d)(\d)(\d)$/$1.$2.$3/; $val`
    // Oracle: bundled Perl on the synthesized SV7 fixture returns "1.1.5"
    // for the EncoderVersion byte 0x73 (== 115 decimal). The PrintConv runs
    // on the stringified ValueConv result (Bit216-223 ⇒ integer 115). The
    // match-path output is always a `TagValue::Str` because the `$1.$2.$3`
    // replacement contains non-digit characters (the dots).
    let def = MPC_MAIN.get()(TagId::Str("Bit216-223")).unwrap();
    let out = crate::convert::apply(def, &TagValue::I64(115), true);
    assert_eq!(out, TagValue::Str("1.1.5".into()));
    // Below-100 (2 digits): no substitution (regex tail-anchored on 3
    // digits) ⇒ Perl's failed `s///` leaves `$val` UNCHANGED. Faithful
    // Rust preserves the ORIGINAL scalar type: `TagValue::I64(15)` stays
    // `TagValue::I64(15)`, so the JSON writer emits `15` (number), not
    // `"15"` (string). Caught by Copilot review on PR #7.
    let out_lt100 = crate::convert::apply(def, &TagValue::I64(15), true);
    assert_eq!(out_lt100, TagValue::I64(15));
    // 4-digit value: only the LAST three digits are rewritten (Perl substitutes
    // the trailing `(\d)(\d)(\d)$`). `1234` ⇒ `12.3.4` (leading `1`, then dots
    // between the trailing three).
    let out_4d = crate::convert::apply(def, &TagValue::I64(1234), true);
    assert_eq!(out_4d, TagValue::Str("12.3.4".into()));
    // -n: print_conv_enabled=false ⇒ raw integer flows through unchanged.
    let raw = crate::convert::apply(def, &TagValue::I64(115), false);
    assert_eq!(raw, TagValue::I64(115));
    // No-match on a non-digit-tail Str: returns the ORIGINAL Str unchanged
    // (no panic, no coercion). Pins that the no-match path is type-faithful
    // for both TagValue::I64 and TagValue::Str inputs.
    let out_alpha = crate::convert::apply(def, &TagValue::Str("ABC".into()), true);
    assert_eq!(out_alpha, TagValue::Str("ABC".into()));
    // No-match short Str: < 3 chars ⇒ Perl regex no-match ⇒ unchanged.
    let out_short = crate::convert::apply(def, &TagValue::Str("ab".into()), true);
    assert_eq!(out_short, TagValue::Str("ab".into()));
  }

  // ---------- Reject paths (Perl `return 0`) -----------------------------

  /// Run the engine over `data` (named `x.mpc`) and return the file object.
  fn engine_obj(data: &[u8]) -> serde_json::Map<String, serde_json::Value> {
    let json = crate::parser::extract_info("x.mpc", data, true);
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    v.as_array().unwrap()[0].as_object().unwrap().clone()
  }

  #[test]
  fn rejects_non_mpc_magic() {
    // MPC.pm:92 `... $buff =~ /^MP\+(.)/s or return 0` — magic mismatch
    // returns 0 BEFORE SetFileType (MPC.pm:94), so MPC is not finalized.
    let obj = engine_obj(&[0u8; 32]);
    assert_ne!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("MPC")
    );
  }

  #[test]
  fn rejects_short_read() {
    // MPC.pm:92 `$raf->Read($buff,32) == 32 ...` — < 32 bytes ⇒ return 0.
    let obj = engine_obj(b"MP+\x07\x00\x00\x00");
    assert_ne!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("MPC")
    );
  }

  // ---------- Lib-first typed Meta surface --------------------------------

  #[test]
  fn parse_borrowed_rejects_short_buffer() {
    assert!(parse_borrowed(&[]).unwrap().is_none());
    assert!(parse_borrowed(b"MP+\x07").unwrap().is_none());
  }

  #[test]
  fn parse_borrowed_rejects_non_mpc_magic() {
    let data = [0u8; 32];
    assert!(parse_borrowed(&data).unwrap().is_none());
  }

  #[test]
  fn parse_borrowed_extracts_sv7_fixture_fields() {
    // Real MPC.mpc fixture is 32 bytes starting `MP+\x07...`. Oracle SV7
    // header from bundled `perl exiftool`:
    //   TotalFrames=102, SampleRate=44100 (idx=0), Quality="5 (Standard)"
    //   (idx=10), MaxBand=28, ReplayGain*=0, FastSeek=No (0), Gapless=Yes
    //   (1), EncoderVersion="1.1.5" (raw=115).
    let bytes = std::fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/MPC.mpc"),
    )
    .expect("read MPC.mpc fixture");
    let meta = parse_borrowed(&bytes).expect("ok").expect("parsed");
    assert_eq!(meta.version(), 0x07);
    let h = meta.sv7_header().expect("SV7 header present");
    assert_eq!(h.total_frames(), 102);
    assert_eq!(h.sample_rate_index(), 0);
    assert_eq!(h.sample_rate_hz(), Some(44100));
    assert_eq!(h.quality_index(), 10);
    assert_eq!(h.quality_name(), Some("5 (Standard)"));
    assert_eq!(h.max_band(), 28);
    assert_eq!(h.replay_gain_track_peak(), 0);
    assert_eq!(h.replay_gain_track_gain(), 0);
    assert_eq!(h.replay_gain_album_peak(), 0);
    assert_eq!(h.replay_gain_album_gain(), 0);
    assert!(!h.fast_seek()); // 0 ⇒ No
    assert!(h.gapless()); // 1 ⇒ Yes
    assert_eq!(h.encoder_version(), 115);
    assert!(!meta.warn_unsupported_version());
    // F5 placeholders are always None.
    assert!(meta.id3_prefix().is_none());
    assert!(meta.ape_trailer().is_none());
  }

  #[test]
  fn parse_borrowed_warns_on_non_sv7_version() {
    // sv8.mpc fixture: `MP+\x08...` ⇒ version=8 ⇒ warning arm.
    let bytes = std::fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sv8.mpc"),
    )
    .expect("read sv8.mpc fixture");
    let meta = parse_borrowed(&bytes).expect("ok").expect("parsed");
    assert_eq!(meta.version(), 0x08);
    assert!(meta.sv7_header().is_none());
    assert!(meta.warn_unsupported_version());
  }

  #[test]
  fn format_parser_trait_returns_meta_static() {
    // Drive the trait via the chained-format Context.
    let bytes = std::fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/MPC.mpc"),
    )
    .expect("read MPC.mpc fixture");
    let mut shared = SharedFlags::new();
    let ctx = MpcContext::new(&bytes, &mut shared);
    let meta = <ProcessMpc as FormatParser>::parse(&ProcessMpc, ctx)
      .expect("ok")
      .expect("parsed");
    let h = meta.sv7_header().expect("SV7 header");
    assert_eq!(h.total_frames(), 102);
    assert_eq!(h.encoder_version(), 115);
  }

  // ---------- serialize_tags: -j (PrintConv on) ------------------------------

  #[test]
  fn meta_sinker_emits_sv7_print_conv_strings() {
    // Build an SV7 MpcMeta with the MPC.mpc fixture values; sink -j.
    let h = MpcSv7Header {
      total_frames: 102,
      sample_rate_index: 0,
      quality_index: 10,
      max_band: 28,
      replay_gain_track_peak: 0,
      replay_gain_track_gain: 0,
      replay_gain_album_peak: 0,
      replay_gain_album_gain: 0,
      fast_seek: 0,
      gapless: 1,
      encoder_version: 115,
    };
    let meta = MpcMeta {
      version: 0x07,
      sv7_header: Some(h),
      warn_unsupported_version: false,
      id3_prefix: None,
      ape_trailer: None,
    };
    let mut w = TagMap::new();
    meta.serialize_tags(true, &mut w).unwrap();
    assert_eq!(w.get_str("MPC", "TotalFrames"), Some("102".to_string()));
    // SampleRate -j: PrintConv hash hit ⇒ 44100 (number)
    assert_eq!(w.get_str("MPC", "SampleRate"), Some("44100".to_string()));
    // Quality -j: hash hit ⇒ "5 (Standard)"
    assert_eq!(
      w.get_str("MPC", "Quality"),
      Some("5 (Standard)".to_string())
    );
    assert_eq!(w.get_str("MPC", "MaxBand"), Some("28".to_string()));
    assert_eq!(w.get_str("MPC", "FastSeek"), Some("No".to_string()));
    assert_eq!(w.get_str("MPC", "Gapless"), Some("Yes".to_string()));
    // EncoderVersion -j: 115 ⇒ "1.1.5"
    assert_eq!(
      w.get_str("MPC", "EncoderVersion"),
      Some("1.1.5".to_string())
    );
    // No warning when sv7_header is Some.
    assert!(w.warnings().is_empty());
  }

  #[test]
  fn meta_sinker_emits_sv7_print_conv_off_raw_scalars() {
    let h = MpcSv7Header {
      total_frames: 102,
      sample_rate_index: 0,
      quality_index: 10,
      max_band: 28,
      replay_gain_track_peak: 0,
      replay_gain_track_gain: 0,
      replay_gain_album_peak: 0,
      replay_gain_album_gain: 0,
      fast_seek: 0,
      gapless: 1,
      encoder_version: 115,
    };
    let meta = MpcMeta {
      version: 0x07,
      sv7_header: Some(h),
      warn_unsupported_version: false,
      id3_prefix: None,
      ape_trailer: None,
    };
    let mut w = TagMap::new();
    meta.serialize_tags(false, &mut w).unwrap();
    // SampleRate -n: raw idx = 0
    assert_eq!(w.get_str("MPC", "SampleRate"), Some("0".to_string()));
    // Quality -n: raw idx = 10
    assert_eq!(w.get_str("MPC", "Quality"), Some("10".to_string()));
    // FastSeek -n: 0
    assert_eq!(w.get_str("MPC", "FastSeek"), Some("0".to_string()));
    // Gapless -n: 1
    assert_eq!(w.get_str("MPC", "Gapless"), Some("1".to_string()));
    // EncoderVersion -n: raw 115
    assert_eq!(w.get_str("MPC", "EncoderVersion"), Some("115".to_string()));
  }

  #[test]
  fn meta_sinker_emits_warning_on_non_sv7() {
    // sv8 path: sv7_header=None, warn_unsupported_version=true.
    let meta = MpcMeta {
      version: 0x08,
      sv7_header: None,
      warn_unsupported_version: true,
      id3_prefix: None,
      ape_trailer: None,
    };
    // -j
    let mut w = TagMap::new();
    meta.serialize_tags(true, &mut w).unwrap();
    // No MPC:* tags emitted (sv7_header is None). The format-tag entries
    // carry the `"<Group1>:<Name>"` keys; warnings live in their own
    // accumulator (`TagMap::warnings`).
    assert!(w.entries().iter().all(|(k, _)| !k.starts_with("MPC:")));
    // The warning is pushed through write_warning ⇒ TagMap::warnings.
    assert_eq!(
      w.warnings(),
      &["Audio info currently not extracted from this version MPC file"]
    );
    // -n: identical (no MPC:* tags, same warning).
    let mut w = TagMap::new();
    meta.serialize_tags(false, &mut w).unwrap();
    assert_eq!(
      w.warnings(),
      &["Audio info currently not extracted from this version MPC file"]
    );
  }

  #[test]
  fn meta_sinker_emits_quality_unknown_fallback() {
    // Quality raw=2 (sparse — MPC.pm:38-54 has no key for 2) ⇒ -j must
    // emit "Unknown (2)" per ExifTool.pm:3622. -n: raw 2.
    let h = MpcSv7Header {
      total_frames: 0,
      sample_rate_index: 0,
      quality_index: 2,
      max_band: 0,
      replay_gain_track_peak: 0,
      replay_gain_track_gain: 0,
      replay_gain_album_peak: 0,
      replay_gain_album_gain: 0,
      fast_seek: 0,
      gapless: 0,
      encoder_version: 0,
    };
    let meta = MpcMeta {
      version: 0x07,
      sv7_header: Some(h),
      warn_unsupported_version: false,
      id3_prefix: None,
      ape_trailer: None,
    };
    let mut w = TagMap::new();
    meta.serialize_tags(true, &mut w).unwrap();
    assert_eq!(w.get_str("MPC", "Quality"), Some("Unknown (2)".to_string()));
    let mut w = TagMap::new();
    meta.serialize_tags(false, &mut w).unwrap();
    assert_eq!(w.get_str("MPC", "Quality"), Some("2".to_string()));
  }

  #[test]
  fn meta_sinker_encoder_version_lt_100_emits_raw() {
    // No-match path: 2-digit value ⇒ Perl `s///` no-match ⇒ original
    // I64 preserved. Both -j and -n emit the raw integer.
    let h = MpcSv7Header {
      total_frames: 0,
      sample_rate_index: 0,
      quality_index: 1,
      max_band: 0,
      replay_gain_track_peak: 0,
      replay_gain_track_gain: 0,
      replay_gain_album_peak: 0,
      replay_gain_album_gain: 0,
      fast_seek: 0,
      gapless: 0,
      encoder_version: 15, // 2-digit ⇒ no-match
    };
    let meta = MpcMeta {
      version: 0x07,
      sv7_header: Some(h),
      warn_unsupported_version: false,
      id3_prefix: None,
      ape_trailer: None,
    };
    let mut w = TagMap::new();
    meta.serialize_tags(true, &mut w).unwrap();
    assert_eq!(w.get_str("MPC", "EncoderVersion"), Some("15".to_string()));
  }
}
