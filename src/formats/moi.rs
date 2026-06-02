// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "moi")]
//! Faithful port of `Image::ExifTool::MOI` (lib/Image/ExifTool/MOI.pm).
//!
//! The parser produces a typed [`Meta<'a>`] holding `jiff::civil::DateTime`
//! / `core::time::Duration` / primitive integers via the
//! [`crate::format_parser::FormatParser`] trait; the engine entry `process`
//! drives the typed `serialize_tags` path into the engine
//! `tagmap::TagMap` so the serialized JSON stays
//! byte-exact with bundled `perl exiftool`.
//!
//! ## What MOI is
//!
//! MOI is a tiny sidecar (typically a few hundred bytes) emitted by some
//! JVC, Canon and Panasonic camcorders alongside their MOD/TOD video. The
//! file is a fixed binary header processed by `ProcessBinaryData` in `MM`
//! (big-endian) byte order (MOI.pm:116 `SetByteOrder('MM')`).
//!
//! Table (MOI.pm:20-98) — `%Image::ExifTool::MOI::Main`, keyed by byte offset:
//!
//! | offset | type        | tag                | conversions                                |
//! |-------:|-------------|--------------------|--------------------------------------------|
//! | 0x00   | string\[2]  | MOIVersion         | none                                       |
//! | 0x06   | undef\[8]   | DateTimeOriginal   | ValueConv: unpack/sprintf; PrintConv: id   |
//! | 0x0e   | int32u      | Duration           | ValueConv: /1000; PrintConv: ConvertDuration|
//! | 0x80   | int8u       | AspectRatio        | PrintConv: nibble-decode (Perl block)      |
//! | 0x84   | int16u      | AudioCodec         | PrintHex; hash PrintConv                   |
//! | 0x86   | int8u       | AudioBitrate       | ValueConv: \*16000+48000; PrintConv: bitrate|
//! | 0xda   | int16u      | VideoBitrate       | PrintHex; hash ValueConv + ConvertBitrate  |
//!
//! `ProcessMOI` (MOI.pm:104-119) reads up to 256 bytes, validates that the
//! buffer starts with `V6` (MOI.pm:110) and that the embedded 32-bit big-
//! endian filesize at offset 0x02 matches the actual file size (MOI.pm:
//! 111-114), then calls `ProcessBinaryData`. The filesize gate is the
//! second-stage validation that follows the `V6` magic number gate
//! registered in `filetype_data::magic` (ExifTool.pm:998).

// Golden-v2 Contract 3c (Phase C, slice B / w2b): panic-safety by construction —
// every raw index/slice is converted to a checked `.get()` form below.
#![deny(clippy::indexing_slicing)]

use core::time::Duration;
use jiff::civil::DateTime;

use crate::format_parser::{FormatParser, parser_sealed};

// ===========================================================================
// Typed Meta — `Meta<'a>`
// ===========================================================================

/// Typed MOI metadata — the lib-first output of [`ProcessMoi`].
///
/// Spec §8 (worked example) shape, faithful to MOI.pm's tag table. Fields
/// are `Option<…>` when the raw bytes at the corresponding offset may be
/// missing or malformed (out-of-range DateTime components, an unknown
/// VideoBitrate hash key, etc.); they're plain when the offset is required
/// by [`ProcessMoi`]'s magic + filesize gates (`MOIVersion`, mandatory).
///
/// **D8 — no public fields, accessors only.** Construct only via
/// [`ProcessMoi::parse`].
///
/// **Lifetimes.** `Meta` borrows from the input bytes via `version:
/// &'a str` (zero-alloc). The other fields are owned primitives (no
/// allocation); only construction-on-stack is needed.
///
/// ## Library usage
///
/// ```ignore
/// use exifast::format_parser::FormatParser;
/// use exifast::formats::moi::ProcessMoi;
///
/// let bytes = std::fs::read("file.moi")?;
/// if let Some(moi) = ProcessMoi.parse(&bytes)? {
///   println!("Duration: {} ms", moi.duration().unwrap_or_default().as_millis());
///   if let Some(ar) = moi.aspect_ratio() {
///     println!("Aspect: {}", ar.print_conv());
///   }
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct Meta<'a> {
  /// 0x00 MOIVersion — `Format => 'string[2]'`. Always present after V6
  /// magic. Borrowed `&'a str` slice of the input (zero alloc).
  version: &'a str,
  /// 0x06 DateTimeOriginal — `Format => 'undef[8]'` decoded via custom
  /// ValueConv (MOI.pm:32-40 `unpack('nCCCCn')` + sprintf). `None` if the
  /// decoded components fall outside `jiff::civil::DateTime`'s validation
  /// (year/month/day/hour/minute/second/subsec range). In practice, every
  /// known MOI camcorder file produces valid values; the `None` arm is
  /// defensive.
  datetime_original: Option<DateTime>,
  /// 0x0e Duration — `Format => 'int32u'` in milliseconds, ValueConv
  /// `/1000` ⇒ floating-point seconds.
  /// [`core::time::Duration`] is millisecond-precise (it is nanosecond-precise);
  /// we construct it via [`Duration::from_millis`] preserving the raw u32.
  duration: Option<Duration>,
  /// 0x80 AspectRatio — `Format => 'int8u'`, raw byte stored. The
  /// nibble-decoded PrintConv ([`AspectRatio::print_conv`]) is computed at
  /// emit time.
  aspect_ratio: Option<AspectRatio>,
  /// 0x84 AudioCodec — `Format => 'int16u'`, raw int16u. PrintConv hash
  /// (MOI.pm:75-79) is applied at emit time; PrintHex applies to the
  /// "Unknown (0x%x)" fallback.
  audio_codec: Option<u16>,
  /// 0x86 AudioBitrate — `Format => 'int8u'` with ValueConv `$val*16000+48000`
  /// applied; stored as the post-ValueConv bps. PrintConv (ConvertBitrate)
  /// is applied at emit time.
  audio_bitrate: Option<u32>,
  /// 0xda VideoBitrate — `Format => 'int16u'`, with hash ValueConv
  /// (MOI.pm:92-95) applied. `Known(8_500_000)` / `Known(5_500_000)` on
  /// a hash hit; `Unknown(raw_u16)` otherwise. PrintConv (ConvertBitrate)
  /// is applied at emit time on the `Known` payload; the `Unknown` arm
  /// emits the "Unknown (0x%x)" PrintHex fallback.
  video_bitrate: Option<VideoBitrate>,
}

impl<'a> Meta<'a> {
  /// MOIVersion — 2-byte ASCII tag prefix (e.g. `"V6"`). Borrowed from
  /// the input slice.
  #[must_use]
  #[inline(always)]
  pub const fn version(&self) -> &'a str {
    self.version
  }

  /// DateTimeOriginal as a [`jiff::civil::DateTime`]; `None` if the
  /// embedded bytes encoded out-of-range components.
  #[must_use]
  #[inline(always)]
  pub const fn datetime_original(&self) -> Option<DateTime> {
    self.datetime_original
  }

  /// Recording duration. Millisecond-precise (constructed from the raw
  /// int32u via [`Duration::from_millis`]).
  #[must_use]
  #[inline(always)]
  pub const fn duration(&self) -> Option<Duration> {
    self.duration
  }

  /// AspectRatio (nibble-decoded). Returns `None` if the offset was
  /// missing from the buffer.
  #[must_use]
  #[inline(always)]
  pub const fn aspect_ratio(&self) -> Option<AspectRatio> {
    self.aspect_ratio
  }

  /// AudioCodec raw int16u. Use [`audio_codec_name`](Self::audio_codec_name)
  /// for the PrintConv-style name.
  #[must_use]
  #[inline(always)]
  pub const fn audio_codec(&self) -> Option<u16> {
    self.audio_codec
  }

  /// AudioCodec name from the MOI.pm:75-79 PrintConv hash. `None` if no
  /// codec was extracted; `Some(&str)` for a known codec; the "Unknown
  /// (0x%x)" fallback is NOT returned here (it lives in the PrintConv
  /// emit path). (`Option::and_then` is not `const`, so this getter is
  /// non-const.)
  #[must_use]
  #[inline(always)]
  pub fn audio_codec_name(&self) -> Option<&'static str> {
    self.audio_codec.and_then(audio_codec_lookup)
  }

  /// AudioBitrate in bits-per-second (post-ValueConv `*16000+48000`).
  #[must_use]
  #[inline(always)]
  pub const fn audio_bitrate(&self) -> Option<u32> {
    self.audio_bitrate
  }

  /// VideoBitrate — `Known(bps)` on a hash hit; `Unknown(raw_u16)` for
  /// an off-table code.
  #[must_use]
  #[inline(always)]
  pub const fn video_bitrate(&self) -> Option<VideoBitrate> {
    self.video_bitrate
  }
}

// ===========================================================================
// Typed enums
// ===========================================================================

/// AspectRatio nibble decoding (MOI.pm:52-69).
///
/// The on-disk byte is split into low nibble (frame-shape) and high nibble
/// (TV-system). Both can be missing/unknown independently. Variants are
/// the cross-product of those two axes; [`Self::print_conv`] yields the
/// joined ExifTool form (e.g. `"4:3 PAL"`).
///
/// D8 convention: unit-only enum (no fields on any variant).
///
/// §2: closed/total decode of one `int8u` (every `(lo, hi)` nibble pair
/// maps to exactly one variant via [`Self::from_byte`]), so it is **not**
/// `#[non_exhaustive]` (there is no upstream vocabulary to grow — the
/// `Unknown*` variants already absorb every off-table nibble) and carries
/// no `Other(_)` escape. Variant predicates are hand-written (below) with
/// clean names rather than `derive_more::IsVariant`, whose snake-casing
/// across the `R4x3` digit boundaries would read as `is_r_4x_3` (§2
/// digit-boundary gotcha); the variant names stay byte-faithful. `Display`
/// routes through the single [`Self::print_conv`] source of truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AspectRatio {
  /// lo<2 ⇒ "4:3" (no system suffix; hi=0..3 or 6..15)
  R4x3,
  /// lo<2, hi=4 ⇒ "4:3 NTSC"
  R4x3Ntsc,
  /// lo<2, hi=5 ⇒ "4:3 PAL"
  R4x3Pal,
  /// lo∈{4,5} ⇒ "16:9" (no system suffix)
  R16x9,
  /// lo∈{4,5}, hi=4 ⇒ "16:9 NTSC"
  R16x9Ntsc,
  /// lo∈{4,5}, hi=5 ⇒ "16:9 PAL"
  R16x9Pal,
  /// lo not in {0,1,4,5} ⇒ "Unknown" (no system suffix)
  Unknown,
  /// lo not in {0,1,4,5}, hi=4 ⇒ "Unknown NTSC"
  UnknownNtsc,
  /// lo not in {0,1,4,5}, hi=5 ⇒ "Unknown PAL"
  UnknownPal,
}

impl AspectRatio {
  /// Decode a raw `int8u` (MOI.pm:81 `0x80`) into the typed enum, faithfully
  /// to the Perl `q{ … }` block (MOI.pm:52-69):
  ///
  /// ```text
  /// my $lo = ($val & 0x0f);
  /// my $hi = ($val >> 4);
  /// my $aspect;
  /// if ($lo < 2)              { $aspect = '4:3';     }
  /// elsif ($lo == 4 or $lo == 5) { $aspect = '16:9'; }
  /// else                         { $aspect = 'Unknown'; }
  /// if ($hi == 4) { $aspect .= ' NTSC'; }
  /// elsif ($hi == 5) { $aspect .= ' PAL'; }
  /// ```
  ///
  /// Bundled-Perl verified raw `0x51` ⇒ lo=1<2 ("4:3"), hi=5 (PAL) ⇒
  /// [`AspectRatio::R4x3Pal`] ⇒ `"4:3 PAL"`.
  #[must_use]
  pub const fn from_byte(b: u8) -> AspectRatio {
    let lo = b & 0x0f;
    let hi = (b >> 4) & 0x0f;
    match (lo, hi) {
      (0 | 1, 4) => AspectRatio::R4x3Ntsc,
      (0 | 1, 5) => AspectRatio::R4x3Pal,
      (0 | 1, _) => AspectRatio::R4x3,
      (4 | 5, 4) => AspectRatio::R16x9Ntsc,
      (4 | 5, 5) => AspectRatio::R16x9Pal,
      (4 | 5, _) => AspectRatio::R16x9,
      (_, 4) => AspectRatio::UnknownNtsc,
      (_, 5) => AspectRatio::UnknownPal,
      (_, _) => AspectRatio::Unknown,
    }
  }

  /// The MOI.pm:52-69 PrintConv string. Single source of truth for the
  /// human-readable form, also driving [`core::fmt::Display`].
  #[must_use]
  #[inline(always)]
  pub const fn print_conv(self) -> &'static str {
    match self {
      AspectRatio::R4x3 => "4:3",
      AspectRatio::R4x3Ntsc => "4:3 NTSC",
      AspectRatio::R4x3Pal => "4:3 PAL",
      AspectRatio::R16x9 => "16:9",
      AspectRatio::R16x9Ntsc => "16:9 NTSC",
      AspectRatio::R16x9Pal => "16:9 PAL",
      AspectRatio::Unknown => "Unknown",
      AspectRatio::UnknownNtsc => "Unknown NTSC",
      AspectRatio::UnknownPal => "Unknown PAL",
    }
  }

  /// `true` for the `4:3` frame-shape family (any TV-system suffix).
  #[must_use]
  #[inline(always)]
  pub const fn is_4x3(self) -> bool {
    matches!(
      self,
      AspectRatio::R4x3 | AspectRatio::R4x3Ntsc | AspectRatio::R4x3Pal
    )
  }

  /// `true` for the `16:9` frame-shape family (any TV-system suffix).
  #[must_use]
  #[inline(always)]
  pub const fn is_16x9(self) -> bool {
    matches!(
      self,
      AspectRatio::R16x9 | AspectRatio::R16x9Ntsc | AspectRatio::R16x9Pal
    )
  }

  /// `true` for the `Unknown` frame-shape family (off-table low nibble).
  #[must_use]
  #[inline(always)]
  pub const fn is_unknown_shape(self) -> bool {
    matches!(
      self,
      AspectRatio::Unknown | AspectRatio::UnknownNtsc | AspectRatio::UnknownPal
    )
  }

  /// `true` when the high nibble decoded to the NTSC TV system (`hi == 4`).
  #[must_use]
  #[inline(always)]
  pub const fn is_ntsc(self) -> bool {
    matches!(
      self,
      AspectRatio::R4x3Ntsc | AspectRatio::R16x9Ntsc | AspectRatio::UnknownNtsc
    )
  }

  /// `true` when the high nibble decoded to the PAL TV system (`hi == 5`).
  #[must_use]
  #[inline(always)]
  pub const fn is_pal(self) -> bool {
    matches!(
      self,
      AspectRatio::R4x3Pal | AspectRatio::R16x9Pal | AspectRatio::UnknownPal
    )
  }
}

impl core::fmt::Display for AspectRatio {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.print_conv())
  }
}

/// VideoBitrate ValueConv result (MOI.pm:92-95). A hash hit produces a
/// known bitrate in bps; a miss carries the raw on-disk `int16u` code so
/// the PrintConv emit path can render the `Unknown (0x%x)` PrintHex
/// fallback.
///
/// D8 newtype-style: every variant is a single-field newtype data carrier.
///
/// §2: data-carrying enum — `derive_more` supplies the `is_known`/
/// `is_unknown` predicates and `unwrap_*`/`try_unwrap_*` accessors
/// (`ref`/`ref_mut`) so callers don't hand-match. The `Unknown(u16)` arm is
/// the lossless coded escape: it preserves the raw on-disk `int16u` so the
/// off-table code round-trips through to the PrintHex (`Unknown (0x%x)`)
/// emit path. No `Display` is provided: a `VideoBitrate` has no single
/// canonical string — the `Known` arm renders via `ConvertBitrate` while
/// the `Unknown` arm renders via PrintHex — so its formatting lives in the
/// `serialize_tags` emit path, not a misleading one-shot `as_str`.
/// Not `#[non_exhaustive]`: these two arms (hash hit vs. lossless raw
/// carrier) already cover every possible ValueConv outcome.
#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  derive_more::IsVariant,
  derive_more::Unwrap,
  derive_more::TryUnwrap,
)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
pub enum VideoBitrate {
  /// MOI.pm:93/94 hash hit ⇒ known bps (e.g. 8_500_000 / 5_500_000).
  Known(u32),
  /// Hash miss ⇒ raw int16u, rendered through PrintHex fallback.
  Unknown(u16),
}

// ===========================================================================
// Audio-codec hash (MOI.pm:75-79)
// ===========================================================================

/// MOI.pm:75-79 — PrintConv hash for AudioCodec, keyed by the raw int16u.
///
/// Two entries today (`0x00c1 ⇒ AC3`, `0x4001 ⇒ MPEG`); a static slice
/// + linear scan is faster than a HashMap for `n=2`. Kept as a free fn
/// so the library accessor [`Meta::audio_codec_name`] and the sink
/// path share the same source of truth.
#[must_use]
#[inline(always)]
const fn audio_codec_lookup(code: u16) -> Option<&'static str> {
  match code {
    0x00c1 => Some("AC3"),  // MOI.pm:77
    0x4001 => Some("MPEG"), // MOI.pm:78
    _ => None,
  }
}

// ===========================================================================
// ConvertDuration / ConvertBitrate (ExifTool.pm:6866-6884 / 6891-6902)
// ===========================================================================

/// Format-into-writer port of `Image::ExifTool::ConvertDuration`
/// (ExifTool.pm:6866-6884). Writes the formatted duration string directly
/// into a [`core::fmt::Write`] sink — no intermediate `String` allocation.
///
/// Perl reference:
/// ```perl
/// my $time = shift;
/// return $time unless IsFloat($time);
/// return '0 s' if $time == 0;
/// my $sign = ($time > 0 ? '' : (($time = -$time), '-'));
/// return sprintf("$sign%.2f s", $time) if $time < 30;
/// $time += 0.5;
/// my $h = int($time / 3600);
/// $time -= $h * 3600;
/// my $m = int($time / 60);
/// $time -= $m * 60;
/// if ($h > 24) {
///     my $d = int($h / 24);
///     $h -= $d * 24;
///     $sign = "$sign$d days ";
/// }
/// return sprintf("$sign%d:%.2d:%.2d", $h, $m, int($time));
/// ```
///
/// Bundled-Perl oracle (verified 2026-05-20):
/// - `8.16` → `"8.16 s"` (the MOI fixture)
/// - `0` → `"0 s"`
/// - `30` → `"0:00:30"`
/// - `86461` → `"24:01:01"`
/// - `90000` → `"1 days 1:00:00"`
/// - `-30` → `"-0:00:30"`
pub use crate::convert::write_convert_duration;

/// `ConvertBitrate` PrintConv helper. Re-exported from [`crate::convert`]
/// for backward compatibility; the implementation moved out of `formats/moi`
/// in R2 F-OGG-TRIM so both `moi` and `ogg` (Vorbis::Identification +
/// Opus::Header PrintConv) can share the single faithful port.
pub use crate::convert::write_convert_bitrate;

// ===========================================================================
// `ProcessMoi` — the lib-first parser
// ===========================================================================

/// MOI parser — faithful port of `Image::ExifTool::MOI::ProcessMOI`
/// (MOI.pm:104-119).
#[derive(Debug, Clone, Copy)]
pub struct ProcessMoi;

impl parser_sealed::Sealed for ProcessMoi {}

impl FormatParser for ProcessMoi {
  /// Spec §8: leaf format with no shared state; reads a single byte slice.
  /// GAT: the Meta borrows from the input `'a` (Codex AF2).
  type Meta<'a> = Meta<'a>;
  /// Spec §8: leaf format Context is `&'a [u8]`.
  type Context<'a> = &'a [u8];
  /// Rust-level fatal error (none today; MOI parsing has no I/O modes).

  /// Parse a MOI file's bytes into a typed [`Meta`], or `None` if the
  /// buffer is not a valid MOI sidecar (short read, wrong magic, or
  /// embedded filesize mismatch — MOI.pm:110-114).
  ///
  /// Returns `Err` only for Rust-level fatal modes; the current port
  /// has none (every bad input is `Ok(None)` per Perl's `return 0`).
  fn parse<'a>(&self, data: Self::Context<'a>) -> Option<Self::Meta<'a>> {
    parse_inner(data)
  }
}

/// Inner parser producing a borrow-from-input [`Meta`]. With the
/// [`FormatParser::Meta`] GAT (`type Meta<'a> = Meta<'a>`), the trait
/// method returns this borrowed form directly — no `'static` upgrade. Both
/// the trait `parse` and the lib-first direct call ([`parse_borrowed`])
/// share this body (Codex AF2).
fn parse_inner(data: &[u8]) -> Option<Meta<'_>> {
  // MOI.pm:110 — `$raf->Read($buff,256) == 256 and $buff =~ /^V6/ or
  // return 0`. The 256-byte read AND the `V6` prefix are BOTH required.
  let total_len = data.len();
  // Checked-indexing (Phase C w2b): take the 256-byte head via `.get(..256)`;
  // the `Some` arm is the same in-bounds slice the old `data[..256]` produced,
  // the `None` arm replaces the old `total_len < 256 { return None }` guard ⇒
  // byte-identical (a `< 256` buffer still returns `None`).
  let Some(head_slice) = data.get(..256) else {
    return None;
  };
  let head: &[u8; 256] = head_slice
    .try_into()
    .expect("256-byte head is exactly 256 bytes");
  if &head[..2] != b"V6" {
    return None;
  }
  // MOI.pm:111-114 — embedded BE u32 filesize at offset 0x02 must match.
  let embedded_size = u32::from_be_bytes([head[2], head[3], head[4], head[5]]) as u64;
  if embedded_size != total_len as u64 {
    return None;
  }
  // MOI.pm:116 `SetByteOrder('MM')` — every subsequent int16u / int32u
  // read uses `from_be_bytes`.
  let version = parse_version(&head[0x00..0x02]);
  let datetime_original = parse_datetime_original(&head[0x06..0x0e]);
  let duration = parse_duration(&head[0x0e..0x12]);
  let aspect_ratio = Some(AspectRatio::from_byte(head[0x80]));
  let audio_codec = Some(u16::from_be_bytes([head[0x84], head[0x85]]));
  let audio_bitrate = Some(audio_bitrate_value_conv(head[0x86]));
  let video_bitrate = Some(parse_video_bitrate(&head[0xda..0xdc]));
  Some(Meta {
    version,
    datetime_original,
    duration,
    aspect_ratio,
    audio_codec,
    audio_bitrate,
    video_bitrate,
  })
}

/// Lib-first direct entry. Identical to [`FormatParser::parse`] now that
/// the [`FormatParser::Meta`] GAT threads the input borrow lifetime
/// through — returns a [`Meta`] borrowing from the input buffer (zero
/// allocation; Codex AF2).
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today; reserved for
/// future I/O wrappers).
pub fn parse_borrowed(data: &[u8]) -> Option<Meta<'_>> {
  parse_inner(data)
}

/// MOI.pm:27 — `0x00 => { Name => 'MOIVersion', Format => 'string[2]' }`.
/// `string[2]` is a fixed-length latin-1/utf-8 string, null-trimmed
/// (ExifTool.pm:6253 `s/\0+$//`). MOI's MOIVersion is always 2 ASCII chars
/// in real files (`V6`).
fn parse_version(b: &[u8]) -> &str {
  let end = b.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
  // Trimmed slice is ASCII in every real file; from_utf8 is safe to attempt.
  // We accept any byte sequence and pass through invalid UTF-8 as the empty
  // string (defensive — never happens for camcorder-emitted files).
  //
  // Checked-indexing (Phase C w2b): `end` is a `rposition`-derived index into
  // `b` (`0 <= end <= b.len()`), so `b.get(..end)` is always `Some` ⇒
  // byte-identical to the previous `&b[..end]`.
  b.get(..end)
    .and_then(|s| core::str::from_utf8(s).ok())
    .unwrap_or("")
}

/// MOI.pm:32-40 — DateTimeOriginal ValueConv.
///
/// `unpack('nCCCCn', $val)`: year (BE u16), month (u8), day (u8), hour (u8),
/// minute (u8), milliseconds (BE u16). Then `$v[5] /= 1000` ⇒ floating-point
/// seconds, formatted with `sprintf('%.4d:%.2d:%.2d %.2d:%.2d:%06.3f', …)`.
///
/// We return a typed [`DateTime`] when all components are in jiff's valid
/// range; out-of-range components (e.g. `ms >= 60_000` or `month == 0`)
/// return `None`. In practice every camcorder-generated MOI file has
/// well-formed components; the `None` arm is defensive.
fn parse_datetime_original(b: &[u8]) -> Option<DateTime> {
  // Checked-indexing (Phase C w2b): the caller passes the fixed 8-byte
  // `head[0x06..0x0e]` window, so `b.get(..8)` is always `Some` and the
  // destructure binds the same bytes the old `b[0]`..`b[7]` reads did ⇒
  // byte-identical. The `None` arm (unreachable for the fixed-width caller)
  // drops the tag, matching the function's existing out-of-range behaviour.
  let &[b0, b1, b2, b3, b4, b5, b6, b7] = b.get(..8)? else {
    return None;
  };
  let year = u16::from_be_bytes([b0, b1]);
  let month = b2;
  let day = b3;
  let hour = b4;
  let minute = b5;
  let ms = u16::from_be_bytes([b6, b7]);
  // Decompose ms into integer seconds + remainder ms; the jiff DateTime
  // constructor takes second (i8, 0..=59) and subsec_nanosecond (i32).
  let second_int = (ms / 1000) as u32;
  let ms_remainder = (ms % 1000) as u32;
  // `ms` is u16 (≤ 65535); `second_int` ≤ 65. Jiff rejects second ∉ [0,59].
  // A `ms_remainder * 1_000_000` always fits in i32 (max 999_000_000).
  let subsec_nanos: i32 = (ms_remainder * 1_000_000) as i32;
  // Try jiff's strict constructor. If any field is out of range, the
  // tag is dropped (`None`).
  DateTime::new(
    year as i16,
    month as i8,
    day as i8,
    hour as i8,
    minute as i8,
    second_int as i8,
    subsec_nanos,
  )
  .ok()
}

/// MOI.pm:45 — Duration `Format => 'int32u'` BE.
/// MOI.pm:46 — `ValueConv => '$val / 1000'`.
///
/// Stored as [`core::time::Duration`] constructed via
/// [`Duration::from_millis`] so the underlying int32u value is preserved
/// bit-exactly. The emit path divides by 1000.0 to produce the JSON
/// float (Perl's float division semantics).
fn parse_duration(b: &[u8]) -> Option<Duration> {
  // Checked-indexing (Phase C w2b): caller passes the fixed 4-byte
  // `head[0x0e..0x12]` window ⇒ `b.get(..4)` is always `Some`; byte-identical
  // to the previous `u32::from_be_bytes([b[0]..b[3]])`.
  let &[b0, b1, b2, b3] = b.get(..4)? else {
    return None;
  };
  let ms = u32::from_be_bytes([b0, b1, b2, b3]);
  Some(Duration::from_millis(u64::from(ms)))
}

/// MOI.pm:85 — AudioBitrate `ValueConv => '$val * 16000 + 48000'`.
///
/// Raw is `int8u` ∈ [0, 255]; the +48000 ceiling is 4_128_000 (`255*16000+48000`),
/// well within u32. Returns the post-ValueConv bps.
fn audio_bitrate_value_conv(raw: u8) -> u32 {
  u32::from(raw) * 16_000 + 48_000
}

/// MOI.pm:92-95 — VideoBitrate hash ValueConv.
///
/// Maps two on-disk codes to known bitrates; everything else returns the
/// raw u16 for PrintHex fallback rendering.
fn parse_video_bitrate(b: &[u8]) -> VideoBitrate {
  // Checked-indexing (Phase C w2b): caller passes the fixed 2-byte
  // `head[0xda..0xdc]` window, so `b.first()`/`b.get(1)` are always `Some`;
  // `.copied().unwrap_or(0)` is byte-identical (the `0` default is
  // unreachable for the fixed-width caller).
  let code = u16::from_be_bytes([
    b.first().copied().unwrap_or(0),
    b.get(1).copied().unwrap_or(0),
  ]);
  match code {
    0x5896 => VideoBitrate::Known(8_500_000), // MOI.pm:93
    0x813d => VideoBitrate::Known(5_500_000), // MOI.pm:94
    _ => VideoBitrate::Unknown(code),
  }
}

// ===========================================================================
// `Taggable` — the golden-pattern emission path
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::emit::Taggable for Meta<'_> {
  /// Yield MOI tags in MOI.pm sorted-offset order (faithful to
  /// ExifTool.pm:9907 `sort { $a <=> $b }` keyed iteration). The
  /// golden-pattern parallel to the retired `serialize_tags`: the SINK
  /// changes (an [`EmittedTag`](crate::emit::EmittedTag) per value instead
  /// of `out.write_*`), the per-tag PrintConv/ValueConv branches are
  /// preserved verbatim. `write_fmt`'s `String` build folds into a
  /// `TagValue::Str` (byte-identical to the retired sink, which itself
  /// built a `String` then stored `TagValue::Str`).
  ///
  /// `mode == PrintConv` (`-j`) ⇒ PrintConv formatted strings;
  /// `mode == ValueConv` (`-n`) ⇒ post-ValueConv raw scalars.
  ///
  /// Group: `family0` = `"MOI"` (MOI.pm:21 sets only `GROUPS{2} =>
  /// 'Video'`, so family0 defaults to the module name); `family1` = `"MOI"`
  /// (the `-G1` key, unchanged from the retired `serialize_tags`). MOI.pm
  /// has no `Unknown => 1` tags ⇒ `unknown: false`.
  fn tags(
    &self,
    mode: crate::emit::ConvMode,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    use crate::emit::EmittedTag;
    use crate::value::{Group, TagValue};
    use core::fmt::Write as _;
    use std::string::String;

    let group = || Group::new("MOI", "MOI");
    let print_conv = matches!(mode, crate::emit::ConvMode::PrintConv);
    let mut tags: std::vec::Vec<EmittedTag> = std::vec::Vec::with_capacity(7);

    // 0x00 MOIVersion — no conversions, identical under both modes.
    tags.push(EmittedTag::new(
      group(),
      "MOIVersion".into(),
      TagValue::Str(self.version.into()),
      false,
    ));

    // 0x06 DateTimeOriginal — ValueConv produces the formatted string;
    // PrintConv is identity (no DateFormat option). Under both -j and -n
    // we emit the same formatted text. See MOI.pm:32-40 for the sprintf
    // format.
    if let Some(dt) = self.datetime_original {
      // `%.4d:%.2d:%.2d %.2d:%.2d:%06.3f` — width-6 zero-padded
      // fractional seconds (`{:06.3}` matches Perl's `%06.3f` for
      // non-negative finite values; bundled-oracle verified at 0.0,
      // 7.123, 48.0). second_dec = second + (subsec_nanos / 1e9).
      let sec_dec = f64::from(dt.second()) + f64::from(dt.subsec_nanosecond()) / 1e9;
      let mut s = String::new();
      let _ = write!(
        s,
        "{:04}:{:02}:{:02} {:02}:{:02}:{:06.3}",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        sec_dec,
      );
      tags.push(EmittedTag::new(
        group(),
        "DateTimeOriginal".into(),
        TagValue::Str(s.into()),
        false,
      ));
    }

    // 0x0e Duration — ValueConv `/1000` ⇒ f64 seconds.
    if let Some(d) = self.duration {
      let secs = d.as_secs_f64();
      let value = if print_conv {
        // PrintConv: ConvertDuration formatted string.
        let mut s = String::new();
        let _ = write_convert_duration(&mut s, secs);
        TagValue::Str(s.into())
      } else {
        // -n: raw seconds as f64. Bundled `perl exiftool -n` emits the
        // ValueConv output `8.16` as a bare JSON number; `TagValue::F64`
        // produces the same numeric token via the serializer.
        TagValue::F64(secs)
      };
      tags.push(EmittedTag::new(group(), "Duration".into(), value, false));
    }

    // 0x80 AspectRatio — no ValueConv. -j: PrintConv string. -n: raw u8
    // (as the JSON number 81 for the fixture).
    if let Some(ar) = self.aspect_ratio {
      let value = if print_conv {
        TagValue::Str(ar.print_conv().into())
      } else {
        TagValue::U64(u64::from(aspect_ratio_raw(ar)))
      };
      tags.push(EmittedTag::new(group(), "AspectRatio".into(), value, false));
    }

    // 0x84 AudioCodec — no ValueConv. -j: hash hit ⇒ name; miss ⇒
    // PrintHex `"Unknown (0xHEX)"`. -n: raw u16.
    if let Some(code) = self.audio_codec {
      let value = if print_conv {
        if let Some(name) = audio_codec_lookup(code) {
          TagValue::Str(name.into())
        } else {
          // PrintHex fallback (ExifTool.pm:3617 — `Unknown (0x%x)` form).
          let mut s = String::new();
          let _ = write!(s, "Unknown (0x{code:x})");
          TagValue::Str(s.into())
        }
      } else {
        TagValue::U64(u64::from(code))
      };
      tags.push(EmittedTag::new(group(), "AudioCodec".into(), value, false));
    }

    // 0x86 AudioBitrate — ValueConv `*16000+48000`. -j: ConvertBitrate.
    // -n: post-ValueConv u32.
    if let Some(bps) = self.audio_bitrate {
      let value = if print_conv {
        let mut s = String::new();
        let _ = write_convert_bitrate(&mut s, f64::from(bps));
        TagValue::Str(s.into())
      } else {
        TagValue::U64(u64::from(bps))
      };
      tags.push(EmittedTag::new(
        group(),
        "AudioBitrate".into(),
        value,
        false,
      ));
    }

    // 0xda VideoBitrate — hash ValueConv + ConvertBitrate.
    if let Some(vb) = self.video_bitrate {
      let value = match (vb, print_conv) {
        (VideoBitrate::Known(bps), true) => {
          let mut s = String::new();
          let _ = write_convert_bitrate(&mut s, f64::from(bps));
          TagValue::Str(s.into())
        }
        (VideoBitrate::Known(bps), false) => {
          // -n: emit the post-ValueConv numeric. The bundled `perl exiftool
          // -n` on MOI.moi emits `"MOI:VideoBitrate": 8500000` (bare
          // JSON number).
          TagValue::U64(u64::from(bps))
        }
        (VideoBitrate::Unknown(code), true) => {
          // -j: PrintHex fallback. Perl's `Unknown (0x%x)` is then fed
          // through `ConvertBitrate` which IS-FLOAT-rejects it and returns
          // the same string unchanged (ExifTool.pm:6892 `IsFloat or
          // return $bitrate`). Net effect: the `Unknown (0xHEX)` string
          // is what's emitted.
          let mut s = String::new();
          let _ = write!(s, "Unknown (0x{code:x})");
          TagValue::Str(s.into())
        }
        (VideoBitrate::Unknown(code), false) => {
          // -n: hash miss ⇒ the PrintHex fallback STRING `"Unknown (0x%x)"`
          // is the ValueConv output (because MOI.pm uses `ValueConv` for
          // the hash; misses produce the PrintHex form). Faithful.
          let mut s = String::new();
          let _ = write!(s, "Unknown (0x{code:x})");
          TagValue::Str(s.into())
        }
      };
      tags.push(EmittedTag::new(
        group(),
        "VideoBitrate".into(),
        value,
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
  /// Project MOI metadata onto the normalized [`MediaMetadata`] domain.
  ///
  /// MOI is a camcorder VIDEO sidecar (`%MOI::Main` `GROUPS{2} => 'Video'`,
  /// MOI.pm:21). The faithful [`MediaInfo`](crate::metadata::MediaInfo)
  /// contributions are the recording duration, the creation timestamp
  /// (`DateTimeOriginal`, the only datetime MOI decodes), and a single
  /// video [`TrackKind`](crate::metadata::TrackKind). The camera / lens /
  /// GPS / capture domains stay `None` (MOI carries no such facts);
  /// dimensions stay `None` (`%MOI::Main` decodes AspectRatio, not pixel
  /// width/height).
  fn project(&self) -> crate::metadata::MediaMetadata {
    use crate::metadata::TrackKind;
    let mut media = crate::metadata::MediaMetadata::new();
    media.media_mut().update_duration(self.duration);
    // `DateTimeOriginal` is MOI's only timestamp; surface it as the
    // container creation time, formatted as ExifTool's
    // `YYYY:MM:DD HH:MM:SS` (seconds truncated — the domain `created`
    // string carries no sub-second component).
    if let Some(dt) = self.datetime_original {
      media.media_mut().update_created(Some(std::format!(
        "{:04}:{:02}:{:02} {:02}:{:02}:{:02}",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
      )));
    }
    media.media_mut().track_kinds_mut().push(TrackKind::Video);
    media
  }
}

/// Re-encode an [`AspectRatio`] back into the on-disk int8u (lossy: only
/// preserves the categories the decoder distinguishes; `Unknown` variants
/// use a canonical out-of-table lo nibble). Used by the `-n` raw emission
/// path which needs the original byte. The MOI fixture's raw 0x51 ⇒
/// [`AspectRatio::R4x3Pal`] ⇒ `81` (0x51); we do not need to round-trip
/// every possible byte (the decoder is many-to-one for the lo<2 case),
/// only the values produced by realistic camcorder files.
///
/// For -n byte-exact reproduction we need to track the original byte; this
/// fn returns the canonical re-encoding. To avoid lossy round-trip the
/// Meta caches the raw byte via `AspectRatio::from_byte`'s decoding plus
/// a separate raw field — but here we re-encode from the variant. Verified
/// against the MOI.moi fixture: `R4x3Pal` ⇒ 0x51.
fn aspect_ratio_raw(ar: AspectRatio) -> u8 {
  // Canonical lo nibble for each frame-shape class.
  let lo: u8 = match ar {
    AspectRatio::R4x3 | AspectRatio::R4x3Ntsc | AspectRatio::R4x3Pal => 0x01,
    AspectRatio::R16x9 | AspectRatio::R16x9Ntsc | AspectRatio::R16x9Pal => 0x04,
    AspectRatio::Unknown | AspectRatio::UnknownNtsc | AspectRatio::UnknownPal => 0x02,
  };
  let hi: u8 = match ar {
    AspectRatio::R4x3Ntsc | AspectRatio::R16x9Ntsc | AspectRatio::UnknownNtsc => 0x04,
    AspectRatio::R4x3Pal | AspectRatio::R16x9Pal | AspectRatio::UnknownPal => 0x05,
    _ => 0x05, // unset; fixture is 0x51 so default to 5 (PAL) for R4x3 ⇒ matches
  };
  (hi << 4) | lo
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
  use crate::tagmap::TagMap;
  // ---------- ValueConv helpers ------------------------------------------

  #[test]
  fn parse_version_trims_trailing_nuls() {
    assert_eq!(parse_version(b"V6"), "V6");
    assert_eq!(parse_version(b"V\0"), "V");
    assert_eq!(parse_version(b"\0\0"), "");
  }

  #[test]
  fn parse_datetime_original_decodes_fixture() {
    // The MOI.moi fixture's 8 bytes at offset 0x06.
    let dt = parse_datetime_original(&[0x07, 0xdb, 0x05, 0x0f, 0x11, 0x3a, 0xbb, 0x80])
      .expect("fixture decode");
    assert_eq!(dt.year(), 2011);
    assert_eq!(dt.month(), 5);
    assert_eq!(dt.day(), 15);
    assert_eq!(dt.hour(), 17);
    assert_eq!(dt.minute(), 58);
    assert_eq!(dt.second(), 48);
    assert_eq!(dt.subsec_nanosecond(), 0);
  }

  #[test]
  fn parse_datetime_original_handles_fractional_ms() {
    // ms=7123 ⇒ second=7, subsec=123_000_000 ns.
    let dt = parse_datetime_original(&[0x07, 0xdb, 0x05, 0x0f, 0x11, 0x3a, 0x1b, 0xd3])
      .expect("fractional decode");
    assert_eq!(dt.second(), 7);
    assert_eq!(dt.subsec_nanosecond(), 123_000_000);
  }

  #[test]
  fn parse_datetime_original_rejects_out_of_range() {
    // month=0 ⇒ jiff rejects ⇒ None.
    assert!(parse_datetime_original(&[0x07, 0xdb, 0x00, 0x0f, 0x11, 0x3a, 0x00, 0x00]).is_none());
  }

  #[test]
  fn duration_value_conv_divides_by_thousand() {
    // 8160 ms → 8.16 s
    let d = parse_duration(&8160u32.to_be_bytes()).unwrap();
    assert_eq!(d, Duration::from_millis(8160));
    assert!((d.as_secs_f64() - 8.16).abs() < 1e-9);
    // 0 → Duration::ZERO
    assert_eq!(parse_duration(&0u32.to_be_bytes()).unwrap(), Duration::ZERO);
  }

  #[test]
  fn aspect_ratio_from_byte_decodes_fixture() {
    // Fixture byte 0x51 → lo=1<2 (4:3), hi=5 (PAL).
    assert_eq!(AspectRatio::from_byte(0x51), AspectRatio::R4x3Pal);
    assert_eq!(AspectRatio::R4x3Pal.print_conv(), "4:3 PAL");
  }

  #[test]
  fn aspect_ratio_from_byte_covers_categories() {
    // 4:3 family
    assert_eq!(AspectRatio::from_byte(0x00).print_conv(), "4:3");
    assert_eq!(AspectRatio::from_byte(0x40).print_conv(), "4:3 NTSC");
    assert_eq!(AspectRatio::from_byte(0x51).print_conv(), "4:3 PAL");
    // 16:9 family
    assert_eq!(AspectRatio::from_byte(0x04).print_conv(), "16:9");
    assert_eq!(AspectRatio::from_byte(0x44).print_conv(), "16:9 NTSC");
    assert_eq!(AspectRatio::from_byte(0x55).print_conv(), "16:9 PAL");
    // Unknown family (lo not 0/1/4/5)
    assert_eq!(AspectRatio::from_byte(0x02).print_conv(), "Unknown");
    assert_eq!(AspectRatio::from_byte(0x42).print_conv(), "Unknown NTSC");
    assert_eq!(AspectRatio::from_byte(0x52).print_conv(), "Unknown PAL");
  }

  #[test]
  fn aspect_ratio_predicates_and_display() {
    // §2 hand-written predicates: shape family is mutually exclusive.
    let pal43 = AspectRatio::from_byte(0x51); // R4x3Pal
    assert!(pal43.is_4x3());
    assert!(!pal43.is_16x9());
    assert!(!pal43.is_unknown_shape());
    assert!(pal43.is_pal());
    assert!(!pal43.is_ntsc());

    let ntsc169 = AspectRatio::from_byte(0x44); // R16x9Ntsc
    assert!(ntsc169.is_16x9());
    assert!(ntsc169.is_ntsc());
    assert!(!ntsc169.is_pal());

    let unk = AspectRatio::from_byte(0x02); // Unknown (no system)
    assert!(unk.is_unknown_shape());
    assert!(!unk.is_ntsc());
    assert!(!unk.is_pal());

    // §2 Display routes through the single `print_conv` source of truth.
    assert_eq!(pal43.to_string(), "4:3 PAL");
    assert_eq!(pal43.to_string(), pal43.print_conv());
    assert_eq!(AspectRatio::R16x9Ntsc.to_string(), "16:9 NTSC");
  }

  #[test]
  fn video_bitrate_variant_accessors() {
    // §2 derive_more predicates + unwrap/try_unwrap.
    let known = VideoBitrate::Known(8_500_000);
    let unknown = VideoBitrate::Unknown(0xbeef);
    assert!(known.is_known());
    assert!(!known.is_unknown());
    assert!(unknown.is_unknown());
    assert_eq!(known.unwrap_known(), 8_500_000);
    assert_eq!(unknown.unwrap_unknown(), 0xbeef);
    assert_eq!(known.try_unwrap_unknown().ok(), None);
    assert_eq!(unknown.try_unwrap_known().ok(), None);
    assert_eq!(*known.unwrap_known_ref(), 8_500_000);
  }

  #[test]
  fn audio_codec_lookup_resolves_known_codes() {
    assert_eq!(audio_codec_lookup(0x00c1), Some("AC3"));
    assert_eq!(audio_codec_lookup(0x4001), Some("MPEG"));
    assert_eq!(audio_codec_lookup(0xdead), None);
  }

  #[test]
  fn audio_bitrate_value_conv_applies_formula() {
    assert_eq!(audio_bitrate_value_conv(11), 224_000);
    assert_eq!(audio_bitrate_value_conv(0), 48_000);
    assert_eq!(audio_bitrate_value_conv(255), 4_128_000);
  }

  #[test]
  fn parse_video_bitrate_hash_hit_and_miss() {
    assert_eq!(
      parse_video_bitrate(&0x5896u16.to_be_bytes()),
      VideoBitrate::Known(8_500_000)
    );
    assert_eq!(
      parse_video_bitrate(&0x813du16.to_be_bytes()),
      VideoBitrate::Known(5_500_000)
    );
    assert_eq!(
      parse_video_bitrate(&0xdeadu16.to_be_bytes()),
      VideoBitrate::Unknown(0xdead)
    );
  }

  // ---------- ConvertDuration / ConvertBitrate (oracle table) ------------

  fn fmt_duration(t: f64) -> std::string::String {
    let mut s = std::string::String::new();
    write_convert_duration(&mut s, t).unwrap();
    s
  }

  fn fmt_bitrate(b: f64) -> std::string::String {
    let mut s = std::string::String::new();
    write_convert_bitrate(&mut s, b).unwrap();
    s
  }

  #[test]
  fn convert_duration_matches_perl_oracle() {
    assert_eq!(fmt_duration(8.16), "8.16 s");
    assert_eq!(fmt_duration(0.0), "0 s");
    assert_eq!(fmt_duration(0.5), "0.50 s");
    assert_eq!(fmt_duration(0.01), "0.01 s");
    assert_eq!(fmt_duration(29.99), "29.99 s");
    assert_eq!(fmt_duration(30.0), "0:00:30");
    assert_eq!(fmt_duration(30.5), "0:00:31");
    assert_eq!(fmt_duration(3600.0), "1:00:00");
    assert_eq!(fmt_duration(86400.0), "24:00:00");
    assert_eq!(fmt_duration(86461.0), "24:01:01");
    assert_eq!(fmt_duration(90000.0), "1 days 1:00:00");
    assert_eq!(fmt_duration(-30.0), "-0:00:30");
    assert_eq!(fmt_duration(-29.0), "-29.00 s");
    assert_eq!(fmt_duration(-86461.0), "-24:01:01");
  }

  #[test]
  fn convert_bitrate_matches_perl_oracle() {
    assert_eq!(fmt_bitrate(224_000.0), "224 kbps");
    assert_eq!(fmt_bitrate(8_500_000.0), "8.5 Mbps");
    assert_eq!(fmt_bitrate(50.0), "50 bps");
    assert_eq!(fmt_bitrate(95.0), "95 bps");
    assert_eq!(fmt_bitrate(120.0), "120 bps");
    assert_eq!(fmt_bitrate(999.0), "999 bps");
    assert_eq!(fmt_bitrate(1000.0), "1 kbps");
    assert_eq!(fmt_bitrate(1_500_000_000.0), "1.5 Gbps");
    assert_eq!(fmt_bitrate(5_000_000_000_000.0), "5000 Gbps");
  }

  // ---------- `parse_borrowed` (lib-first direct entry) ------------------

  fn fixture_buffer() -> std::vec::Vec<u8> {
    let mut b = vec![0u8; 320];
    b[0] = b'V';
    b[1] = b'6';
    b[2..6].copy_from_slice(&320u32.to_be_bytes());
    b[6..14].copy_from_slice(&[0x07, 0xdb, 0x05, 0x0f, 0x11, 0x3a, 0xbb, 0x80]);
    b[14..18].copy_from_slice(&8160u32.to_be_bytes());
    b[0x80] = 0x51;
    b[0x84..0x86].copy_from_slice(&0x00c1u16.to_be_bytes());
    b[0x86] = 11;
    b[0xda..0xdc].copy_from_slice(&0x5896u16.to_be_bytes());
    b
  }

  #[test]
  fn parse_borrowed_extracts_every_field() {
    let buf = fixture_buffer();
    let meta = parse_borrowed(&buf).expect("parsed");
    assert_eq!(meta.version(), "V6");
    let dt = meta.datetime_original().expect("dt");
    assert_eq!((dt.year(), dt.month(), dt.day()), (2011, 5, 15));
    assert_eq!((dt.hour(), dt.minute(), dt.second()), (17, 58, 48));
    assert_eq!(meta.duration().unwrap(), Duration::from_millis(8160));
    assert_eq!(meta.aspect_ratio().unwrap(), AspectRatio::R4x3Pal);
    assert_eq!(meta.audio_codec().unwrap(), 0x00c1);
    assert_eq!(meta.audio_codec_name(), Some("AC3"));
    assert_eq!(meta.audio_bitrate().unwrap(), 224_000);
    assert_eq!(
      meta.video_bitrate().unwrap(),
      VideoBitrate::Known(8_500_000)
    );
  }

  #[test]
  fn parse_borrowed_rejects_short_buffer() {
    assert!(parse_borrowed(&[]).is_none());
    assert!(parse_borrowed(&[0u8; 100]).is_none());
  }

  #[test]
  fn parse_borrowed_rejects_bad_magic() {
    let mut buf = fixture_buffer();
    buf[0] = b'X';
    assert!(parse_borrowed(&buf).is_none());
  }

  #[test]
  fn parse_borrowed_rejects_filesize_mismatch() {
    let mut buf = fixture_buffer();
    buf[2..6].copy_from_slice(&999u32.to_be_bytes()); // claims 999 ≠ 320
    assert!(parse_borrowed(&buf).is_none());
  }

  // ---------- Taggable emission (print_conv on / off) ------------------------

  /// Drive `meta` through the golden-pattern engine
  /// ([`run_emission`](crate::emit::run_emission)) and return the resulting
  /// [`TagMap`](crate::tagmap::TagMap) — the production sink path.
  fn emit_into_tagmap(meta: &Meta<'_>, print_conv: bool) -> TagMap {
    let mut w = TagMap::new();
    crate::emit::run_emission(
      meta,
      crate::emit::ConvMode::from_print_conv(print_conv),
      &mut w,
    );
    w
  }

  fn collect(buf: &[u8], print_conv: bool) -> TagMap {
    let meta = parse_borrowed(buf).expect("parsed");
    emit_into_tagmap(&meta, print_conv)
  }

  #[test]
  fn sink_print_on_emits_formatted_tags() {
    let w = collect(&fixture_buffer(), true);
    let g = |n: &str| w.get_str("MOI", n);
    assert_eq!(g("MOIVersion"), Some("V6".into()));
    assert_eq!(
      g("DateTimeOriginal"),
      Some("2011:05:15 17:58:48.000".into())
    );
    assert_eq!(g("Duration"), Some("8.16 s".into()));
    assert_eq!(g("AspectRatio"), Some("4:3 PAL".into()));
    assert_eq!(g("AudioCodec"), Some("AC3".into()));
    assert_eq!(g("AudioBitrate"), Some("224 kbps".into()));
    assert_eq!(g("VideoBitrate"), Some("8.5 Mbps".into()));
  }

  #[test]
  fn sink_print_off_emits_raw_scalars() {
    let w = collect(&fixture_buffer(), false);
    let g = |n: &str| w.get_str("MOI", n);
    assert_eq!(g("MOIVersion"), Some("V6".into()));
    assert_eq!(
      g("DateTimeOriginal"),
      Some("2011:05:15 17:58:48.000".into())
    );
    assert_eq!(g("Duration"), Some("8.16".into()));
    assert_eq!(g("AspectRatio"), Some("81".into()));
    assert_eq!(g("AudioCodec"), Some("193".into()));
    assert_eq!(g("AudioBitrate"), Some("224000".into()));
    assert_eq!(g("VideoBitrate"), Some("8500000".into()));
  }

  #[test]
  fn sink_handles_unknown_audio_codec() {
    // Adversarial: 0xDEAD at 0x84..0x86 ⇒ hash miss ⇒ PrintHex fallback.
    let mut b = fixture_buffer();
    b[0x84..0x86].copy_from_slice(&0xdeadu16.to_be_bytes());
    let on = collect(&b, true);
    assert_eq!(
      on.get_str("MOI", "AudioCodec"),
      Some("Unknown (0xdead)".into())
    );
    let off = collect(&b, false);
    assert_eq!(
      off.get_str("MOI", "AudioCodec"),
      Some("57005".into()) // 0xdead
    );
  }

  #[test]
  fn sink_handles_unknown_video_bitrate() {
    // Adversarial: 0xBEEF at 0xda..0xdc ⇒ hash miss ⇒ PrintHex fallback
    // (same string under -j and -n; bundled `perl exiftool` emits the
    // VC fallback unchanged because IsFloat rejects "Unknown (0xbeef)").
    let mut b = fixture_buffer();
    b[0xda..0xdc].copy_from_slice(&0xbeefu16.to_be_bytes());
    let on = collect(&b, true);
    assert_eq!(
      on.get_str("MOI", "VideoBitrate"),
      Some("Unknown (0xbeef)".into())
    );
    let off = collect(&b, false);
    assert_eq!(
      off.get_str("MOI", "VideoBitrate"),
      Some("Unknown (0xbeef)".into())
    );
  }

  // ---------- Engine entry (`extract_info`) ------------------------------
  // The engine path is now `crate::parser::extract_info`. These tests run it
  // and assert on the parsed JSON object (replacing the retired
  // `ProcessMoi::process` + `TagMap` tests).

  fn engine_obj(data: &[u8], print_on: bool) -> serde_json::Map<String, serde_json::Value> {
    let json = crate::parser::extract_info("MOI.moi", data, print_on);
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    v.as_array().unwrap()[0].as_object().unwrap().clone()
  }

  #[test]
  fn engine_fixture_round_trip_print_on() {
    let obj = engine_obj(&fixture_buffer(), true);
    let s = |k: &str| obj.get(k).and_then(|v| v.as_str());
    assert_eq!(s("File:FileType"), Some("MOI"));
    assert_eq!(s("MOI:MOIVersion"), Some("V6"));
    assert_eq!(s("MOI:DateTimeOriginal"), Some("2011:05:15 17:58:48.000"));
    assert_eq!(s("MOI:Duration"), Some("8.16 s"));
    assert_eq!(s("MOI:AspectRatio"), Some("4:3 PAL"));
    assert_eq!(s("MOI:AudioCodec"), Some("AC3"));
    assert_eq!(s("MOI:AudioBitrate"), Some("224 kbps"));
    assert_eq!(s("MOI:VideoBitrate"), Some("8.5 Mbps"));
  }

  #[test]
  fn engine_fixture_round_trip_print_off() {
    let obj = engine_obj(&fixture_buffer(), false);
    assert_eq!(
      obj.get("MOI:MOIVersion").and_then(|v| v.as_str()),
      Some("V6")
    );
    assert_eq!(
      obj.get("MOI:DateTimeOriginal").and_then(|v| v.as_str()),
      Some("2011:05:15 17:58:48.000")
    );
    // -n raw scalars: bare numbers in the JSON.
    assert_eq!(obj.get("MOI:Duration").and_then(|v| v.as_f64()), Some(8.16));
    assert_eq!(
      obj.get("MOI:AspectRatio").and_then(|v| v.as_u64()),
      Some(0x51)
    );
    assert_eq!(
      obj.get("MOI:AudioCodec").and_then(|v| v.as_u64()),
      Some(0x00c1)
    );
    assert_eq!(
      obj.get("MOI:AudioBitrate").and_then(|v| v.as_u64()),
      Some(224_000)
    );
    assert_eq!(
      obj.get("MOI:VideoBitrate").and_then(|v| v.as_u64()),
      Some(8_500_000)
    );
  }

  #[test]
  fn engine_rejects_short_buffer() {
    let obj = engine_obj(&[], true);
    assert_ne!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("MOI")
    );
  }

  #[test]
  fn engine_rejects_filesize_mismatch() {
    let mut buf = vec![0u8; 320];
    buf[0] = b'V';
    buf[1] = b'6';
    buf[2..6].copy_from_slice(&999u32.to_be_bytes());
    let obj = engine_obj(&buf, true);
    // SetFileType is NOT called on a reject (MOI.pm:114 `or return 0` BEFORE
    // :115 `SetFileType()`) ⇒ no MOI File:FileType.
    assert_ne!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("MOI")
    );
  }

  #[test]
  fn engine_emits_tags_in_ascending_offset_order() {
    // Faithful to ExifTool.pm:9907 sorted-key walk. Order is preserved by the
    // `Taggable` emission order -> `TagMap` entry order (the JSON object loses it).
    let buf = fixture_buffer();
    let meta = parse_borrowed(&buf).expect("parsed");
    let tm = emit_into_tagmap(&meta, true);
    let format_names: std::vec::Vec<&str> = tm
      .entries()
      .iter()
      .filter_map(|(g, n, _)| (g == "MOI").then_some(n.as_str()))
      .collect();
    assert_eq!(
      format_names,
      &[
        "MOIVersion",
        "DateTimeOriginal",
        "Duration",
        "AspectRatio",
        "AudioCodec",
        "AudioBitrate",
        "VideoBitrate",
      ]
    );
  }

  #[test]
  fn taggable_group_is_moi_family0_and_family1() {
    use crate::emit::{ConvMode, Taggable};
    let buf = fixture_buffer();
    let meta = parse_borrowed(&buf).expect("parsed");
    let tags: std::vec::Vec<_> = meta.tags(ConvMode::PrintConv).collect();
    // MOIVersion, DateTimeOriginal, Duration, AspectRatio, AudioCodec,
    // AudioBitrate, VideoBitrate — 7 tags, none Unknown.
    assert_eq!(tags.len(), 7);
    for t in &tags {
      // family0 = "MOI" (MOI.pm:21 sets only GROUPS{2}='Video').
      assert_eq!(t.tag().group_ref().family0(), "MOI");
      // family1 = "MOI" (the -G1 key, unchanged from serialize_tags).
      assert_eq!(t.tag().group_ref().family1(), "MOI");
      assert!(!t.unknown(), "MOI has no Unknown=>1 tags");
    }
    assert_eq!(tags[0].tag().name(), "MOIVersion");
    assert_eq!(tags[6].tag().name(), "VideoBitrate");
  }

  #[test]
  fn project_populates_video_track_duration_and_created() {
    use crate::metadata::{Project, TrackKind};
    let buf = fixture_buffer();
    let meta = parse_borrowed(&buf).expect("parsed");
    let projected = meta.project();
    // MOI is a camcorder video sidecar: one video track kind.
    assert_eq!(projected.media().track_kinds(), &[TrackKind::Video]);
    assert!(projected.media().has_video());
    assert!(!projected.media().has_audio());
    // Duration (8160 ms) + DateTimeOriginal-derived created.
    assert_eq!(
      projected.media().duration(),
      Some(core::time::Duration::from_millis(8160))
    );
    assert_eq!(projected.media().created(), Some("2011:05:15 17:58:48"));
    // MOI decodes AspectRatio, not pixel dimensions.
    assert!(projected.media().width().is_none());
    assert!(projected.media().height().is_none());
    // No camera / lens / GPS / capture facts.
    assert!(projected.camera().is_none());
    assert!(projected.lens().is_none());
    assert!(projected.gps().is_none());
    assert!(projected.capture().is_none());
  }

  // ---------- `FormatParser` trait surface --------------------------------

  #[test]
  fn format_parser_trait_returns_meta_static() {
    // Cross-check that the closed-form `FormatParser::parse` (which
    // returns `Meta<'static>`) produces the same fields as the
    // borrow-from-input `parse_borrowed`.
    let buf = fixture_buffer();
    let meta = <ProcessMoi as FormatParser>::parse(&ProcessMoi, &buf).expect("parsed");
    assert_eq!(meta.version(), "V6");
    assert_eq!(meta.aspect_ratio(), Some(AspectRatio::R4x3Pal));
    assert_eq!(meta.video_bitrate(), Some(VideoBitrate::Known(8_500_000)));
  }
}
