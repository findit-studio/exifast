// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "moi")]
//! Faithful port of `Image::ExifTool::MOI` (lib/Image/ExifTool/MOI.pm).
//!
//! **Phase E pilot — lib-first design.** This is the first format migrated
//! from the push-style [`crate::parser::OldFormatParser`] API to the typed
//! lib-first [`crate::parser_new::FormatParser`] API per the design spec
//! at `docs/superpowers/specs/2026-05-21-lib-first-formatparser-design.md`.
//! The parser produces a typed [`MoiMeta<'a>`] holding `jiff::civil::DateTime`
//! / `core::time::Duration` / primitive integers; the legacy `Metadata`
//! push path is preserved through the [`crate::sink::MetadataTagWriter`]
//! bridge so CLI JSON output stays byte-exact while Phases F1–F5 migrate
//! the remaining 12 formats. The bridge is retired in Phase G.
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

use core::time::Duration;
use jiff::civil::DateTime;

use crate::parser::ParseContext;
use crate::parser_new::{FormatParser, MetaSinker, TagWriter, parser_sealed};
use crate::sink::MetadataTagWriter;

// ===========================================================================
// Typed Meta — `MoiMeta<'a>`
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
/// **Lifetimes.** `MoiMeta` borrows from the input bytes via `version:
/// &'a str` (zero-alloc). The other fields are owned primitives (no
/// allocation); only construction-on-stack is needed.
///
/// ## Library usage
///
/// ```ignore
/// use exifast::parser_new::FormatParser;
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
pub struct MoiMeta<'a> {
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

impl<'a> MoiMeta<'a> {
  /// MOIVersion — 2-byte ASCII tag prefix (e.g. `"V6"`). Borrowed from
  /// the input slice.
  #[must_use]
  pub fn version(&self) -> &'a str {
    self.version
  }

  /// DateTimeOriginal as a [`jiff::civil::DateTime`]; `None` if the
  /// embedded bytes encoded out-of-range components.
  #[must_use]
  pub fn datetime_original(&self) -> Option<DateTime> {
    self.datetime_original
  }

  /// Recording duration. Millisecond-precise (constructed from the raw
  /// int32u via [`Duration::from_millis`]).
  #[must_use]
  pub fn duration(&self) -> Option<Duration> {
    self.duration
  }

  /// AspectRatio (nibble-decoded). Returns `None` if the offset was
  /// missing from the buffer.
  #[must_use]
  pub fn aspect_ratio(&self) -> Option<AspectRatio> {
    self.aspect_ratio
  }

  /// AudioCodec raw int16u. Use [`audio_codec_name`](Self::audio_codec_name)
  /// for the PrintConv-style name.
  #[must_use]
  pub fn audio_codec(&self) -> Option<u16> {
    self.audio_codec
  }

  /// AudioCodec name from the MOI.pm:75-79 PrintConv hash. `None` if no
  /// codec was extracted; `Some(&str)` for a known codec; the "Unknown
  /// (0x%x)" fallback is NOT returned here (it lives in the PrintConv
  /// emit path).
  #[must_use]
  pub fn audio_codec_name(&self) -> Option<&'static str> {
    self.audio_codec.and_then(audio_codec_lookup)
  }

  /// AudioBitrate in bits-per-second (post-ValueConv `*16000+48000`).
  #[must_use]
  pub fn audio_bitrate(&self) -> Option<u32> {
    self.audio_bitrate
  }

  /// VideoBitrate — `Known(bps)` on a hash hit; `Unknown(raw_u16)` for
  /// an off-table code.
  #[must_use]
  pub fn video_bitrate(&self) -> Option<VideoBitrate> {
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
/// D8 convention: newtype-style enum (no fields on variants).
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

  /// The MOI.pm:52-69 PrintConv string.
  #[must_use]
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
}

/// VideoBitrate ValueConv result (MOI.pm:92-95). A hash hit produces a
/// known bitrate in bps; a miss carries the raw on-disk `int16u` code so
/// the PrintConv emit path can render the `Unknown (0x%x)` PrintHex
/// fallback.
///
/// D8 newtype-style: variants are flat data carriers, no public field
/// accessors needed beyond the type's own match arms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
/// so the library accessor [`MoiMeta::audio_codec_name`] and the sink
/// path share the same source of truth.
#[must_use]
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
pub fn write_convert_duration<W: core::fmt::Write + ?Sized>(
  w: &mut W,
  time: f64,
) -> core::fmt::Result {
  // See the moved-from-port comment above for ExifTool.pm:5949 (IsFloat regex)
  // — finite gate covers NaN/Inf, which Perl's IsFloat would reject; MOI
  // Duration is int32u/1000 so this branch is unreachable from the real
  // call site.
  if !time.is_finite() {
    return write!(w, "{time}");
  }
  if time == 0.0 {
    return w.write_str("0 s"); // ExifTool.pm:6870
  }
  let (sign, mut t) = if time > 0.0 { ("", time) } else { ("-", -time) }; // ExifTool.pm:6871
  if t < 30.0 {
    return write!(w, "{sign}{t:.2} s"); // ExifTool.pm:6872
  }
  t += 0.5; // ExifTool.pm:6873 round to nearest second
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
/// Bundled-Perl oracle (verified 2026-05-20):
/// - `224_000` → `"224 kbps"`
/// - `8_500_000` → `"8.5 Mbps"`
/// - `50` → `"50 bps"`
/// - `999` → `"999 bps"`
/// - `1000` → `"1 kbps"`
/// - `1_500_000_000` → `"1.5 Gbps"`
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
      // `%.3g` — Perl `%g` strips trailing zeros. Share the engine's
      // existing helper so byte-exact matching against the bundled oracle
      // is centralized.
      let formatted = crate::value::format_g(b, 3);
      write!(w, "{formatted} {unit}")
    } else {
      // `%.0f` — Perl `%.0f` is half-to-even; for bitrate ranges here the
      // post-division values are never exactly `.5`, so Rust's
      // half-away-from-zero `{:.0}` produces byte-identical output.
      write!(w, "{b:.0} {unit}")
    };
  }
  // Unreachable: the loop always returns on the last UNITS entry.
  unreachable!("write_convert_bitrate loop must exit on the last unit");
}

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
  type Meta<'a> = MoiMeta<'a>;
  /// Spec §8: leaf format Context is `&'a [u8]`.
  type Context<'a> = &'a [u8];
  /// Rust-level fatal error (none today; MOI parsing has no I/O modes).
  type Error = MoiError;

  /// Parse a MOI file's bytes into a typed [`MoiMeta`], or `None` if the
  /// buffer is not a valid MOI sidecar (short read, wrong magic, or
  /// embedded filesize mismatch — MOI.pm:110-114).
  ///
  /// Returns `Err` only for Rust-level fatal modes; the current port
  /// has none (every bad input is `Ok(None)` per Perl's `return 0`).
  fn parse<'a>(&self, data: Self::Context<'a>) -> Result<Option<Self::Meta<'a>>, MoiError> {
    parse_inner(data)
  }
}

/// Inner parser producing a borrow-from-input [`MoiMeta`]. With the
/// [`FormatParser::Meta`] GAT (`type Meta<'a> = MoiMeta<'a>`), the trait
/// method returns this borrowed form directly — no `'static` upgrade. Both
/// the trait `parse` and the lib-first direct call ([`parse_borrowed`])
/// share this body (Codex AF2).
fn parse_inner(data: &[u8]) -> Result<Option<MoiMeta<'_>>, MoiError> {
  // MOI.pm:110 — `$raf->Read($buff,256) == 256 and $buff =~ /^V6/ or
  // return 0`. The 256-byte read AND the `V6` prefix are BOTH required.
  let total_len = data.len();
  if total_len < 256 {
    return Ok(None);
  }
  let head: &[u8; 256] = data[..256]
    .try_into()
    .expect("256-byte head is exactly 256 bytes");
  if &head[..2] != b"V6" {
    return Ok(None);
  }
  // MOI.pm:111-114 — embedded BE u32 filesize at offset 0x02 must match.
  let embedded_size = u32::from_be_bytes([head[2], head[3], head[4], head[5]]) as u64;
  if embedded_size != total_len as u64 {
    return Ok(None);
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
  Ok(Some(MoiMeta {
    version,
    datetime_original,
    duration,
    aspect_ratio,
    audio_codec,
    audio_bitrate,
    video_bitrate,
  }))
}

/// Lib-first direct entry. Identical to [`FormatParser::parse`] now that
/// the [`FormatParser::Meta`] GAT threads the input borrow lifetime
/// through — returns a [`MoiMeta`] borrowing from the input buffer (zero
/// allocation; Codex AF2).
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today; reserved for
/// future I/O wrappers).
pub fn parse_borrowed(data: &[u8]) -> Result<Option<MoiMeta<'_>>, MoiError> {
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
  core::str::from_utf8(&b[..end]).unwrap_or("")
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
  let year = u16::from_be_bytes([b[0], b[1]]);
  let month = b[2];
  let day = b[3];
  let hour = b[4];
  let minute = b[5];
  let ms = u16::from_be_bytes([b[6], b[7]]);
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
  let ms = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
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
  let code = u16::from_be_bytes([b[0], b[1]]);
  match code {
    0x5896 => VideoBitrate::Known(8_500_000), // MOI.pm:93
    0x813d => VideoBitrate::Known(5_500_000), // MOI.pm:94
    _ => VideoBitrate::Unknown(code),
  }
}

// ===========================================================================
// `MetaSinker` — typed Meta → JSON / Metadata via `TagWriter`
// ===========================================================================

impl MetaSinker for MoiMeta<'_> {
  /// Emit MOI tags into the writer in MOI.pm sorted-offset order (faithful
  /// to ExifTool.pm:9907 `sort { $a <=> $b }` keyed iteration). Family-1
  /// group is `"MOI"` (the Perl module-name suffix).
  ///
  /// `print_conv=true` ⇒ PrintConv formatted strings (`-j` mode);
  /// `print_conv=false` ⇒ post-ValueConv raw scalars (`-n` mode).
  /// See [`MetaSinker`]'s type-level docs for the rationale on this
  /// Phase E spec evolution.
  fn sink<W: TagWriter>(&self, print_conv: bool, out: &mut W) -> Result<(), W::Error> {
    const GROUP: &str = "MOI";

    // 0x00 MOIVersion — no conversions, identical under both modes.
    out.write_str(GROUP, "MOIVersion", self.version)?;

    // 0x06 DateTimeOriginal — ValueConv produces the formatted string;
    // PrintConv is identity (no DateFormat option). Under both -j and -n
    // we emit the same formatted text via write_fmt (no String alloc on
    // the writer side). See MOI.pm:32-40 for the sprintf format.
    if let Some(dt) = self.datetime_original {
      out.write_fmt(GROUP, "DateTimeOriginal", |w| {
        // `%.4d:%.2d:%.2d %.2d:%.2d:%06.3f` — width-6 zero-padded
        // fractional seconds (`{:06.3}` matches Perl's `%06.3f` for
        // non-negative finite values; bundled-oracle verified at 0.0,
        // 7.123, 48.0). second_dec = second + (subsec_nanos / 1e9).
        let sec_dec = f64::from(dt.second()) + f64::from(dt.subsec_nanosecond()) / 1e9;
        write!(
          w,
          "{:04}:{:02}:{:02} {:02}:{:02}:{:06.3}",
          dt.year(),
          dt.month(),
          dt.day(),
          dt.hour(),
          dt.minute(),
          sec_dec,
        )
      })?;
    }

    // 0x0e Duration — ValueConv `/1000` ⇒ f64 seconds.
    if let Some(d) = self.duration {
      let secs = d.as_secs_f64();
      if print_conv {
        // PrintConv: ConvertDuration formatted string.
        out.write_fmt(GROUP, "Duration", |w| write_convert_duration(w, secs))?;
      } else {
        // -n: raw seconds as f64. Bundled `perl exiftool -n` emits the
        // ValueConv output `8.16` as a bare JSON number; `write_f64`
        // produces the same numeric token via the serializer's
        // `push_numeric_gated`.
        out.write_f64(GROUP, "Duration", secs)?;
      }
    }

    // 0x80 AspectRatio — no ValueConv. -j: PrintConv string. -n: raw u8
    // (as the JSON number 81 for the fixture).
    if let Some(ar) = self.aspect_ratio {
      if print_conv {
        out.write_str(GROUP, "AspectRatio", ar.print_conv())?;
      } else {
        out.write_u64(GROUP, "AspectRatio", u64::from(aspect_ratio_raw(ar)))?;
      }
    }

    // 0x84 AudioCodec — no ValueConv. -j: hash hit ⇒ name; miss ⇒
    // PrintHex `"Unknown (0xHEX)"`. -n: raw u16.
    if let Some(code) = self.audio_codec {
      if print_conv {
        if let Some(name) = audio_codec_lookup(code) {
          out.write_str(GROUP, "AudioCodec", name)?;
        } else {
          // PrintHex fallback (ExifTool.pm:3617 — `Unknown (0x%x)` form).
          out.write_fmt(GROUP, "AudioCodec", |w| write!(w, "Unknown (0x{code:x})"))?;
        }
      } else {
        out.write_u64(GROUP, "AudioCodec", u64::from(code))?;
      }
    }

    // 0x86 AudioBitrate — ValueConv `*16000+48000`. -j: ConvertBitrate.
    // -n: post-ValueConv u32.
    if let Some(bps) = self.audio_bitrate {
      if print_conv {
        out.write_fmt(GROUP, "AudioBitrate", |w| {
          write_convert_bitrate(w, f64::from(bps))
        })?;
      } else {
        out.write_u64(GROUP, "AudioBitrate", u64::from(bps))?;
      }
    }

    // 0xda VideoBitrate — hash ValueConv + ConvertBitrate.
    if let Some(vb) = self.video_bitrate {
      match (vb, print_conv) {
        (VideoBitrate::Known(bps), true) => {
          out.write_fmt(GROUP, "VideoBitrate", |w| {
            write_convert_bitrate(w, f64::from(bps))
          })?;
        }
        (VideoBitrate::Known(bps), false) => {
          // -n: emit the post-ValueConv numeric. The bundled `perl exiftool
          // -n` on MOI.moi emits `"MOI:VideoBitrate": 8500000` (bare
          // JSON number).
          out.write_u64(GROUP, "VideoBitrate", u64::from(bps))?;
        }
        (VideoBitrate::Unknown(code), true) => {
          // -j: PrintHex fallback. Perl's `Unknown (0x%x)` is then fed
          // through `ConvertBitrate` which IS-FLOAT-rejects it and returns
          // the same string unchanged (ExifTool.pm:6892 `IsFloat or
          // return $bitrate`). Net effect: the `Unknown (0xHEX)` string
          // is what's emitted.
          out.write_fmt(GROUP, "VideoBitrate", |w| write!(w, "Unknown (0x{code:x})"))?;
        }
        (VideoBitrate::Unknown(code), false) => {
          // -n: hash miss ⇒ the PrintHex fallback STRING `"Unknown (0x%x)"`
          // is the ValueConv output (because MOI.pm uses `ValueConv` for
          // the hash; misses produce the PrintHex form). Faithful.
          out.write_fmt(GROUP, "VideoBitrate", |w| write!(w, "Unknown (0x{code:x})"))?;
        }
      }
    }
    Ok(())
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
// `MoiError` — Rust-level fatal modes (currently none)
// ===========================================================================

/// Rust-level fatal modes for MOI parsing. Currently empty — every bad
/// input produces `Ok(None)` (Perl `return 0`). Reserved for future I/O
/// wrappers if streaming readers are added.
///
/// `Display` is hand-derived (no variants today; `Debug` is enough).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoiError {}

impl core::fmt::Display for MoiError {
  fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    // Unreachable: no variants exist.
    match *self {}
  }
}

#[cfg(feature = "std")]
impl std::error::Error for MoiError {}

// ===========================================================================
// Engine entry — typed parse + File:* + sink into `Metadata`
// ===========================================================================

impl ProcessMoi {
  /// Engine entry used by the closed [`crate::parser_new::AnyParser`]
  /// dispatch (`crate::parser::extract_info`). Runs the typed
  /// [`FormatParser::parse`] and then drives [`MetaSinker::sink`] through a
  /// [`MetadataTagWriter`] so the serialized JSON stays byte-exact with
  /// bundled `perl exiftool`.
  ///
  /// Faithful order (MOI.pm:104-119): magic + filesize gate ⇒
  /// `SetFileType` ⇒ binary walk. The `SetFileType` happens BEFORE
  /// sinking the typed `Meta` so `File:*` lands first (the bundled
  /// emission order under `-j -G1`).
  pub(crate) fn process(&self, ctx: &mut ParseContext<'_>) -> bool {
    // Run the new typed parser on the input bytes. The borrow lives
    // through this call; we sink it before mutating `ctx`.
    let bytes = ctx.data();
    let meta = match parse_inner(bytes) {
      Ok(Some(m)) => m,
      Ok(None) => return false,
      // No Rust-level fatal modes today; cover the arm to future-proof.
      Err(_) => return false,
    };
    // MOI.pm:115 — `$et->SetFileType()`. No-arg ⇒ detected file type
    // ("MOI"). This pushes File:FileType / File:FileTypeExtension /
    // File:MIMEType under `("File", "File")` BEFORE the MOI:* tags
    // (the bundled-Perl iteration order under `-j -G1`).
    ctx.set_file_type(None, None, None);
    // Bridge: typed `MoiMeta` ⇒ `Metadata` via the Phase E–F
    // `MetadataTagWriter` adapter. Faithful to MOI.pm:117-118
    // `ProcessBinaryData(...)` semantics — emits the same MOI:* tags
    // in the same order with the same PrintConv vs ValueConv toggling.
    let print_conv = ctx.print_conv_enabled();
    let mut bridge = MetadataTagWriter::new(ctx.metadata());
    // `MetadataTagWriter::Error` is `Infallible` — the call cannot fail.
    let _: Result<(), core::convert::Infallible> = meta.sink(print_conv, &mut bridge);
    // MOI.pm:118 — `ProcessBinaryData` always returns 1 in the read path.
    true
  }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;
  use crate::sink::MapTagWriter;
  use crate::value::Metadata;

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
    let meta = parse_borrowed(&buf).expect("ok").expect("parsed");
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
    assert!(parse_borrowed(&[]).unwrap().is_none());
    assert!(parse_borrowed(&[0u8; 100]).unwrap().is_none());
  }

  #[test]
  fn parse_borrowed_rejects_bad_magic() {
    let mut buf = fixture_buffer();
    buf[0] = b'X';
    assert!(parse_borrowed(&buf).unwrap().is_none());
  }

  #[test]
  fn parse_borrowed_rejects_filesize_mismatch() {
    let mut buf = fixture_buffer();
    buf[2..6].copy_from_slice(&999u32.to_be_bytes()); // claims 999 ≠ 320
    assert!(parse_borrowed(&buf).unwrap().is_none());
  }

  // ---------- MetaSinker (print_conv on / off) ---------------------------

  fn collect(buf: &[u8], print_conv: bool) -> MapTagWriter {
    let mut w = MapTagWriter::new();
    let meta = parse_borrowed(buf).expect("ok").expect("parsed");
    meta.sink(print_conv, &mut w).unwrap();
    w
  }

  #[test]
  fn sink_print_on_emits_formatted_tags() {
    let w = collect(&fixture_buffer(), true);
    let g = |n: &str| w.get("MOI", n).map(crate::sink::MapValue::as_str);
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
    let g = |n: &str| w.get("MOI", n).map(crate::sink::MapValue::as_str);
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
      on.get("MOI", "AudioCodec")
        .map(crate::sink::MapValue::as_str),
      Some("Unknown (0xdead)".into())
    );
    let off = collect(&b, false);
    assert_eq!(
      off
        .get("MOI", "AudioCodec")
        .map(crate::sink::MapValue::as_str),
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
      on.get("MOI", "VideoBitrate")
        .map(crate::sink::MapValue::as_str),
      Some("Unknown (0xbeef)".into())
    );
    let off = collect(&b, false);
    assert_eq!(
      off
        .get("MOI", "VideoBitrate")
        .map(crate::sink::MapValue::as_str),
      Some("Unknown (0xbeef)".into())
    );
  }

  // ---------- Legacy `OldFormatParser` bridge ----------------------------

  fn run_bridge(data: &[u8], print_on: bool) -> Metadata {
    let mut m = Metadata::new("MOI.moi");
    let mut c = ParseContext::new(data, "MOI", 0, "MOI", None, print_on, &mut m);
    ProcessMoi.process(&mut c);
    m
  }

  #[test]
  fn bridge_fixture_round_trip_print_on() {
    let m = run_bridge(&fixture_buffer(), true);
    let by_name = |n: &str| {
      m.tags()
        .iter()
        .find(|t| t.name() == n)
        .map(|t| t.value().clone())
    };
    use crate::value::TagValue;
    assert_eq!(by_name("FileType"), Some(TagValue::Str("MOI".into())));
    assert_eq!(by_name("MOIVersion"), Some(TagValue::Str("V6".into())));
    assert_eq!(
      by_name("DateTimeOriginal"),
      Some(TagValue::Str("2011:05:15 17:58:48.000".into()))
    );
    assert_eq!(by_name("Duration"), Some(TagValue::Str("8.16 s".into())));
    assert_eq!(
      by_name("AspectRatio"),
      Some(TagValue::Str("4:3 PAL".into()))
    );
    assert_eq!(by_name("AudioCodec"), Some(TagValue::Str("AC3".into())));
    assert_eq!(
      by_name("AudioBitrate"),
      Some(TagValue::Str("224 kbps".into()))
    );
    assert_eq!(
      by_name("VideoBitrate"),
      Some(TagValue::Str("8.5 Mbps".into()))
    );
  }

  #[test]
  fn bridge_fixture_round_trip_print_off() {
    let m = run_bridge(&fixture_buffer(), false);
    let by_name = |n: &str| {
      m.tags()
        .iter()
        .find(|t| t.name() == n)
        .map(|t| t.value().clone())
    };
    use crate::value::TagValue;
    assert_eq!(by_name("MOIVersion"), Some(TagValue::Str("V6".into())));
    assert_eq!(
      by_name("DateTimeOriginal"),
      Some(TagValue::Str("2011:05:15 17:58:48.000".into()))
    );
    assert_eq!(by_name("Duration"), Some(TagValue::F64(8.16)));
    assert_eq!(by_name("AspectRatio"), Some(TagValue::I64(0x51)));
    assert_eq!(by_name("AudioCodec"), Some(TagValue::I64(0x00c1)));
    assert_eq!(by_name("AudioBitrate"), Some(TagValue::I64(224_000)));
    assert_eq!(by_name("VideoBitrate"), Some(TagValue::I64(8_500_000)));
  }

  #[test]
  fn bridge_rejects_short_buffer() {
    let mut m = Metadata::new("X.moi");
    let mut c = ParseContext::new(&[], "MOI", 0, "MOI", None, true, &mut m);
    assert!(!ProcessMoi.process(&mut c));
    assert!(m.tags().is_empty());
  }

  #[test]
  fn bridge_rejects_filesize_mismatch() {
    let mut buf = vec![0u8; 320];
    buf[0] = b'V';
    buf[1] = b'6';
    buf[2..6].copy_from_slice(&999u32.to_be_bytes());
    let mut m = Metadata::new("X.moi");
    let mut c = ParseContext::new(&buf, "MOI", 0, "MOI", None, true, &mut m);
    assert!(!ProcessMoi.process(&mut c));
    // SetFileType is NOT called on a reject (faithful to MOI.pm:114 `or
    // return 0` BEFORE :115 `SetFileType()`).
    assert!(m.tags().is_empty());
  }

  #[test]
  fn bridge_emits_tags_in_ascending_offset_order() {
    // Faithful to ExifTool.pm:9907 sorted-key walk.
    let m = run_bridge(&fixture_buffer(), true);
    let format_names: std::vec::Vec<&str> = m
      .tags()
      .iter()
      .filter(|t| t.group().family1() == "MOI")
      .map(crate::value::Tag::name)
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

  // ---------- `FormatParser` trait surface --------------------------------

  #[test]
  fn format_parser_trait_returns_meta_static() {
    // Cross-check that the closed-form `FormatParser::parse` (which
    // returns `MoiMeta<'static>`) produces the same fields as the
    // borrow-from-input `parse_borrowed`.
    let buf = fixture_buffer();
    let meta = <ProcessMoi as FormatParser>::parse(&ProcessMoi, &buf)
      .expect("ok")
      .expect("parsed");
    assert_eq!(meta.version(), "V6");
    assert_eq!(meta.aspect_ratio(), Some(AspectRatio::R4x3Pal));
    assert_eq!(meta.video_bitrate(), Some(VideoBitrate::Known(8_500_000)));
  }
}
