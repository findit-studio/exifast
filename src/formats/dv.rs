#![cfg(feature = "dv")]
//! Faithful port of `Image::ExifTool::DV` (`lib/Image/ExifTool/DV.pm`).
//! Module-name dispatch: `%moduleName{DV}` defaults to `Module("DV")`
//! (no explicit row, so Perl `$module = $type`); registered in
//! [`crate::format_parser::any_parser_for`].
//!
//! A typed [`Meta<'a>`] is produced by the
//! [`crate::format_parser::FormatParser`] trait; the engine entry
//! `process` drives the typed `serialize_tags` path into the engine
//! `tagmap::TagMap` so the serialized JSON stays
//! byte-exact with bundled `perl exiftool`.

use crate::{
  format_parser::{FormatParser, parser_sealed},
  tagtable::{PrintConv, TagDef, TagId, TagTable, ValueConv},
  value::{TagValue, format_g},
};

/// One row of `@dvProfiles` (DV.pm:21-113). All fields are derived
/// directly from the Perl table; `frame_rate_num`/`frame_rate_den` carry
/// the Perl rational so the post-`int($val*1000+0.5)/1000` PrintConv lands
/// on the exact same `f64` as `%.3g` of `30000/1001`.
///
/// D8: PRIVATE fields, accessors only; `const fn new` for `static` use.
struct Profile {
  dsf: u8,
  video_stype: u8,
  frame_size: u32,
  video_format: &'static str,
  colorimetry: &'static str,
  // Perl source: `FrameRate => 30000/1001` — Perl evaluates the literal at
  // parse time as `f64`. We carry the rational components so the f64 is
  // computed in Rust identically (`num as f64 / den as f64`).
  frame_rate_num: u32,
  frame_rate_den: u32,
  image_height: u32,
  image_width: u32,
}

impl Profile {
  /// Construct a profile row (DV.pm:21-113). The 9 named arguments mirror
  /// the 9 keys of a Perl `@dvProfiles` hash literal one-for-one; this is
  /// the only constructor (D8: PRIVATE fields, `const fn new` required for
  /// `static` use). `#[allow(clippy::too_many_arguments)]` is preferred
  /// over a `ProfileBuilder` here: the Perl table is a flat
  /// `(DSF, VideoSType, FrameSize, VideoFormat, Colorimetry, FrameRate,
  /// ImageHeight, ImageWidth)` rendering (FrameRate splits into 2 fields),
  /// and a builder would obscure the line-by-line faithful-1:1 mapping.
  #[must_use]
  #[inline(always)]
  #[allow(clippy::too_many_arguments)]
  const fn new(
    dsf: u8,
    video_stype: u8,
    frame_size: u32,
    video_format: &'static str,
    colorimetry: &'static str,
    frame_rate_num: u32,
    frame_rate_den: u32,
    image_height: u32,
    image_width: u32,
  ) -> Self {
    Self {
      dsf,
      video_stype,
      frame_size,
      video_format,
      colorimetry,
      frame_rate_num,
      frame_rate_den,
      image_height,
      image_width,
    }
  }

  /// DV.pm `DSF` field.
  #[must_use]
  #[inline(always)]
  const fn dsf(&self) -> u8 {
    self.dsf
  }
  /// DV.pm `VideoSType` field (`0x0` / `0x4` / `0x14` / `0x18` / `0x1`).
  #[must_use]
  #[inline(always)]
  const fn video_stype(&self) -> u8 {
    self.video_stype
  }
  /// DV.pm `FrameSize` field (bytes per video frame).
  #[must_use]
  #[inline(always)]
  const fn frame_size(&self) -> u32 {
    self.frame_size
  }
  /// DV.pm `VideoFormat` field (the descriptive string).
  #[must_use]
  #[inline(always)]
  const fn video_format(&self) -> &'static str {
    self.video_format
  }
  /// DV.pm `Colorimetry` field.
  #[must_use]
  #[inline(always)]
  const fn colorimetry(&self) -> &'static str {
    self.colorimetry
  }
  /// `FrameRate` as a Rust `f64` (`num/den`). (`f64::from` is not a
  /// `const` trait call, so this getter is non-const.)
  #[must_use]
  #[inline(always)]
  fn frame_rate_f64(&self) -> f64 {
    f64::from(self.frame_rate_num) / f64::from(self.frame_rate_den)
  }
  /// DV.pm `ImageHeight` field.
  #[must_use]
  #[inline(always)]
  const fn image_height(&self) -> u32 {
    self.image_height
  }
  /// DV.pm `ImageWidth` field.
  #[must_use]
  #[inline(always)]
  const fn image_width(&self) -> u32 {
    self.image_width
  }
}

/// `@dvProfiles` (DV.pm:21-113), in faithful index order — DV.pm:183-186
/// scans the table in order and stops at the FIRST `dsf`/`stype` match.
/// `[2]` is the SMPTE-314M PAL 4:1:1 row that DV.pm:180 forces explicitly
/// for the 576i50 25Mbps 4:1:1 special case.
static DV_PROFILES: &[Profile] = &[
  // [0] DV.pm:22-30 — IEC 61834 NTSC 525/60.
  Profile::new(
    0,
    0x0,
    120_000,
    "IEC 61834, SMPTE-314M - 525/60 (NTSC)",
    "4:1:1",
    30_000,
    1_001,
    480,
    720,
  ),
  // [1] DV.pm:31-39 — IEC 61834 PAL 625/50 4:2:0.
  Profile::new(
    1,
    0x0,
    144_000,
    "IEC 61834 - 625/50 (PAL)",
    "4:2:0",
    25,
    1,
    576,
    720,
  ),
  // [2] DV.pm:40-48 — SMPTE-314M PAL 625/50 4:1:1 (DV.pm:180 special case).
  Profile::new(
    1,
    0x0,
    144_000,
    "SMPTE-314M - 625/50 (PAL)",
    "4:1:1",
    25,
    1,
    576,
    720,
  ),
  // [3] DV.pm:49-57 — DVCPRO50 NTSC.
  Profile::new(
    0,
    0x4,
    240_000,
    "DVCPRO50: SMPTE-314M - 525/60 (NTSC) 50 Mbps",
    "4:2:2",
    30_000,
    1_001,
    480,
    720,
  ),
  // [4] DV.pm:58-66 — DVCPRO50 PAL.
  Profile::new(
    1,
    0x4,
    288_000,
    "DVCPRO50: SMPTE-314M - 625/50 (PAL) 50 Mbps",
    "4:2:2",
    25,
    1,
    576,
    720,
  ),
  // [5] DV.pm:67-75 — DVCPRO HD 1080i60 NTSC base.
  Profile::new(
    0,
    0x14,
    480_000,
    "DVCPRO HD: SMPTE-370M - 1080i60 100 Mbps",
    "4:2:2",
    30_000,
    1_001,
    1080,
    1280,
  ),
  // [6] DV.pm:76-84 — DVCPRO HD 1080i50 PAL base.
  Profile::new(
    1,
    0x14,
    576_000,
    "DVCPRO HD: SMPTE-370M - 1080i50 100 Mbps",
    "4:2:2",
    25,
    1,
    1080,
    1440,
  ),
  // [7] DV.pm:85-93 — DVCPRO HD 720p60 NTSC base.
  Profile::new(
    0,
    0x18,
    240_000,
    "DVCPRO HD: SMPTE-370M - 720p60 100 Mbps",
    "4:2:2",
    60_000,
    1_001,
    720,
    960,
  ),
  // [8] DV.pm:94-102 — DVCPRO HD 720p50 PAL base.
  Profile::new(
    1,
    0x18,
    288_000,
    "DVCPRO HD: SMPTE-370M - 720p50 100 Mbps",
    "4:2:2",
    50,
    1,
    720,
    960,
  ),
  // [9] DV.pm:103-112 — IEC 61883-5 PAL.
  Profile::new(
    1,
    0x1,
    144_000,
    "IEC 61883-5 - 625/50 (PAL)",
    "4:2:0",
    25,
    1,
    576,
    720,
  ),
];

/// `@dvTags` (DV.pm:116-121) — the FIXED emission order.
const DV_TAGS: &[&str] = &[
  "DateTimeOriginal",
  "ImageWidth",
  "ImageHeight",
  "Duration",
  "TotalBitrate",
  "VideoFormat",
  "VideoScanType",
  "FrameRate",
  "AspectRatio",
  "Colorimetry",
  "AudioChannels",
  "AudioSampleRate",
  "AudioBitsPerSample",
];

// %DV::Main tag defs (DV.pm:123-145). family-0 = "DV"; family-1 = "DV"
// (DV.pm:125 sets family-2 "Video"; AudioChannels/Rate/BitsPerSample
// promote family-2 to "Audio" per DV.pm:142-144). family-2 is not
// emitted under `-G1`.

fn print_conv_duration(v: &TagValue) -> TagValue {
  TagValue::Str(convert_duration_str(v).into())
}
fn print_conv_bitrate(v: &TagValue) -> TagValue {
  TagValue::Str(convert_bitrate_str(v).into())
}
fn print_conv_frame_rate(v: &TagValue) -> TagValue {
  // DV.pm:139 `int($val * 1000 + 0.5) / 1000` — Perl `int` is
  // truncation toward 0, equivalent to `floor` for non-negative reals.
  match v {
    TagValue::F64(n) => {
      let r = ((*n * 1000.0 + 0.5).floor()) / 1000.0;
      TagValue::F64(r)
    }
    other => other.clone(),
  }
}

// DV.pm:128-132 `DateTimeOriginal => { PrintConv => '$self->
// ConvertDateTime($val)' }`. Under default options (no DateFormat / no
// GlobalTimeShift) ConvertDateTime returns $date unchanged
// (ExifTool.pm:6611-6680). PrintConv::None is the faithful equivalent —
// D11 conversion context is deliberately deferred (ID3 deriving it).
static DATE_TIME_ORIGINAL: TagDef =
  TagDef::new("DateTimeOriginal", "DV", ValueConv::None, PrintConv::None); // DV.pm:128
static IMAGE_WIDTH: TagDef = TagDef::new("ImageWidth", "DV", ValueConv::None, PrintConv::None); // DV.pm:133
static IMAGE_HEIGHT: TagDef = TagDef::new("ImageHeight", "DV", ValueConv::None, PrintConv::None); // DV.pm:134
static DURATION: TagDef = TagDef::new(
  "Duration", // DV.pm:135 PrintConv => 'ConvertDuration($val)'
  "DV",
  ValueConv::None,
  PrintConv::Func(print_conv_duration),
);
static TOTAL_BITRATE: TagDef = TagDef::new(
  "TotalBitrate", // DV.pm:136 PrintConv => 'ConvertBitrate($val)'
  "DV",
  ValueConv::None,
  PrintConv::Func(print_conv_bitrate),
);
static VIDEO_FORMAT: TagDef = TagDef::new("VideoFormat", "DV", ValueConv::None, PrintConv::None); // DV.pm:137
static VIDEO_SCAN_TYPE: TagDef =
  TagDef::new("VideoScanType", "DV", ValueConv::None, PrintConv::None); // DV.pm:138
static FRAME_RATE: TagDef = TagDef::new(
  "FrameRate", // DV.pm:139 PrintConv => 'int($val * 1000 + 0.5) / 1000'
  "DV",
  ValueConv::None,
  PrintConv::Func(print_conv_frame_rate),
);
static ASPECT_RATIO: TagDef = TagDef::new("AspectRatio", "DV", ValueConv::None, PrintConv::None); // DV.pm:140
static COLORIMETRY: TagDef = TagDef::new("Colorimetry", "DV", ValueConv::None, PrintConv::None); // DV.pm:141
static AUDIO_CHANNELS: TagDef =
  TagDef::new("AudioChannels", "DV", ValueConv::None, PrintConv::None); // DV.pm:142
static AUDIO_SAMPLE_RATE: TagDef =
  TagDef::new("AudioSampleRate", "DV", ValueConv::None, PrintConv::None); // DV.pm:143
static AUDIO_BITS_PER_SAMPLE: TagDef =
  TagDef::new("AudioBitsPerSample", "DV", ValueConv::None, PrintConv::None); // DV.pm:144

fn dv_get(id: TagId) -> Option<&'static TagDef> {
  match id {
    TagId::Str("DateTimeOriginal") => Some(&DATE_TIME_ORIGINAL),
    TagId::Str("ImageWidth") => Some(&IMAGE_WIDTH),
    TagId::Str("ImageHeight") => Some(&IMAGE_HEIGHT),
    TagId::Str("Duration") => Some(&DURATION),
    TagId::Str("TotalBitrate") => Some(&TOTAL_BITRATE),
    TagId::Str("VideoFormat") => Some(&VIDEO_FORMAT),
    TagId::Str("VideoScanType") => Some(&VIDEO_SCAN_TYPE),
    TagId::Str("FrameRate") => Some(&FRAME_RATE),
    TagId::Str("AspectRatio") => Some(&ASPECT_RATIO),
    TagId::Str("Colorimetry") => Some(&COLORIMETRY),
    TagId::Str("AudioChannels") => Some(&AUDIO_CHANNELS),
    TagId::Str("AudioSampleRate") => Some(&AUDIO_SAMPLE_RATE),
    TagId::Str("AudioBitsPerSample") => Some(&AUDIO_BITS_PER_SAMPLE),
    _ => None,
  }
}

/// `%Image::ExifTool::DV::Main` (DV.pm:124).
pub static DV_MAIN: TagTable = TagTable::new("DV", dv_get);

/// `sub ConvertDuration` (ExifTool.pm:6866-6884). Faithful 1:1.
fn convert_duration_str(v: &TagValue) -> String {
  let mut t: f64 = match v {
    TagValue::F64(n) => *n,
    TagValue::I64(n) => *n as f64,
    other => return format!("{other:?}"),
  };
  if t == 0.0 {
    return "0 s".to_string(); // ExifTool.pm:6870
  }
  let sign = if t > 0.0 {
    ""
  } else {
    t = -t;
    "-"
  }; // ExifTool.pm:6871
  if t < 30.0 {
    return format!("{sign}{t:.2} s"); // ExifTool.pm:6872
  }
  t += 0.5; // ExifTool.pm:6873
  let h_total: i64 = (t / 3600.0).trunc() as i64;
  let t_after_h = t - (h_total as f64) * 3600.0;
  let m: i64 = (t_after_h / 60.0).trunc() as i64;
  let t_after_m = t_after_h - (m as f64) * 60.0;
  let secs: i64 = t_after_m.trunc() as i64;
  let (prefix, h_final) = if h_total > 24 {
    let d = h_total / 24;
    (format!("{sign}{d} days "), h_total - d * 24)
  } else {
    (sign.to_string(), h_total)
  };
  format!("{prefix}{h_final}:{m:02}:{secs:02}") // ExifTool.pm:6883
}

/// `sub ConvertBitrate` (ExifTool.pm:6891-6902). Faithful 1:1.
fn convert_bitrate_str(v: &TagValue) -> String {
  let mut b: f64 = match v {
    TagValue::F64(n) => *n,
    TagValue::I64(n) => *n as f64,
    other => return format!("{other:?}"),
  };
  let units = ["bps", "kbps", "Mbps", "Gbps"];
  let mut idx = 0usize;
  while idx + 1 < units.len() && b >= 1000.0 {
    b /= 1000.0;
    idx += 1;
  }
  let formatted = if b < 100.0 {
    format_g(b, 3) // ExifTool.pm:6899 %.3g
  } else {
    format!("{b:.0}") // ExifTool.pm:6899 %.0f
  };
  format!("{formatted} {}", units[idx])
}

/// Locate the first DIF header in the 12 KiB buffer.
///
/// DV.pm:159-168. Primary regex `\x1f\x07\0[\x3f\xbf]` ⇒ `$start = pos -
/// 4`. Fallback regex `[\0\xff]\x3f\x07\0.{76}\xff\x3f\x07\x01` ⇒
/// `next if pos - 163 < 0; $start = pos - 163`. Returns the first
/// satisfying `$start`, or `None`.
///
/// **Perl `/g` non-overlapping semantics.** On a match at index `i`,
/// Perl `pos` advances to the END of that match (`i + match_len`); the
/// NEXT scan resumes there, never at `i + 1`. So a guarded-out fallback
/// match at offset `i₁ < 79` is followed by a resume at `i₁ + 84`, NOT
/// at `i₁ + 1`: any overlapping match at `i₂ ∈ (i₁, i₁ + 84)` is
/// invisible to Perl. The primary scan has no guard (the only outcome
/// is `return Some(i)`), but is written with the same advancement
/// shape for consistency. Codex R1 found a concrete counterexample:
/// a 200-byte buffer with fallback heads at offsets 75 and 79 sharing
/// tails at 155 and 159. Perl `/g` yields ONE match ending at 159 →
/// `$start = -4 < 0` → undef; an overlapping `i += 1` scan instead
/// returns `start = 0`, accepting a buffer ExifTool rejects.
fn find_dif_start(buff: &[u8]) -> Option<usize> {
  // Primary: 4-byte window. (No skip path; the only outcome is return.)
  if buff.len() >= 4 {
    let mut i = 0usize;
    while i + 4 <= buff.len() {
      let w = &buff[i..i + 4];
      if w[0] == 0x1f && w[1] == 0x07 && w[2] == 0x00 && (w[3] == 0x3f || w[3] == 0xbf) {
        // pos == i + 4, $start == pos - 4 == i.
        return Some(i);
      }
      i += 1;
    }
  }
  // Fallback: 84-byte window (4 head + 76 wildcard + 4 tail). On a
  // guarded-out match Perl `/g` advances `pos` to the END of the match
  // (`i + 84`), so resume there — non-overlapping — NOT at `i + 1`.
  if buff.len() >= 84 {
    let mut i = 0usize;
    while i + 84 <= buff.len() {
      let head = &buff[i..i + 4];
      let tail = &buff[i + 80..i + 84];
      let head_ok = (head[0] == 0x00 || head[0] == 0xff)
        && head[1] == 0x3f
        && head[2] == 0x07
        && head[3] == 0x00;
      let tail_ok = tail[0] == 0xff && tail[1] == 0x3f && tail[2] == 0x07 && tail[3] == 0x01;
      if head_ok && tail_ok {
        // pos = i + 84; $start = pos - 163 = i - 79; require i >= 79.
        if i >= 79 {
          return Some(i - 79);
        }
        // Guard failed (`next` in Perl). Perl `/g` advances pos to the
        // end of this match (`i + 84`), so resume there — NOT i + 1.
        i += 84;
        continue;
      }
      i += 1;
    }
  }
  None
}

/// VAUX-block scan (DV.pm:203-237).
///
/// The Perl `last` at DV.pm:232 exits ONLY the inner `foreach $j`, so a
/// LATER block can re-set date/time. We follow that exactly: the FINAL
/// successful pair (date+time) wins, not the first.
fn extract_vaux_meta(
  buff: &[u8],
  start: usize,
) -> (Option<String>, Option<String>, Option<bool>, Option<bool>) {
  let mut date_str: Option<String> = None;
  let mut time_str: Option<String> = None;
  let mut is_16_9: Option<bool> = None;
  let mut interlace_set: Option<bool> = None;
  let mut vaux_pos = start;
  // DV.pm:203 `for ($i=1; $i<6; ++$i)` ⇒ 5 iterations.
  for _ in 1..6 {
    vaux_pos += 80; // DV.pm:204
    if vaux_pos >= buff.len() {
      return (date_str, time_str, is_16_9, interlace_set);
    }
    let block_type = buff[vaux_pos];
    if (block_type & 0xf0) != 0x50 {
      continue; // DV.pm:206
    }
    // DV.pm:207 `for ($j=0; $j<15; ++$j)`.
    for j in 0..15usize {
      let p = vaux_pos + j * 5 + 3; // DV.pm:208
      // Guard against running past the buffer: every Get8u must be in
      // range (`p+0` through `p+4` for the 4-byte date/time fields).
      if p + 4 >= buff.len() {
        break;
      }
      let pack_type = buff[p]; // DV.pm:209
      if pack_type == 0x61 {
        // DV.pm:210 video control.
        let apt = buff[start + 4] & 0x07; // DV.pm:211
        let t = buff[p + 2]; // DV.pm:212
        let aspect_bits = t & 0x07;
        // DV.pm:213
        is_16_9 = Some(aspect_bits == 0x02 || (apt == 0 && aspect_bits == 0x07));
        // DV.pm:214
        interlace_set = Some((buff[p + 3] & 0x10) != 0);
      } else if pack_type == 0x62 {
        // DV.pm:215 date.
        // DV.pm:217 unpack 4 bytes at $p+1; byte 0 = timezone (ignored).
        let d1 = buff[p + 2];
        let d2 = buff[p + 3];
        let d3 = buff[p + 4];
        // DV.pm:219 `sprintf('%.2x:%.2x:%.2x', $d[3], $d[2] & 0x1f,
        // $d[1] & 0x3f)`.
        let s = format!("{:02x}:{:02x}:{:02x}", d3, d2 & 0x1f, d1 & 0x3f);
        if s.bytes().any(|b| (b'a'..=b'f').contains(&b)) {
          // DV.pm:220-221 invalid date (any non-decimal hex nibble).
          date_str = None;
        } else {
          // DV.pm:223-224 century: `($date lt '9') ? '20' : '19'`. Perl
          // string-`lt` of the 8-char `NN:MM:DD` against the 1-char `'9'`
          // compares byte-by-byte to the shorter length: true iff first
          // byte of $date < '9'.
          let first = s.as_bytes()[0];
          let century = if first < b'9' { "20" } else { "19" };
          date_str = Some(format!("{century}{s}"));
        }
        time_str = None; // DV.pm:226
      } else if pack_type == 0x63 && date_str.is_some() {
        // DV.pm:227 time (only after a successful date in this block).
        // DV.pm:229 `Get32u(\$buff, $p+1) & 0x007f7f3f` — computed then
        // discarded; preserved as a faithful no-op.
        let _val =
          u32::from_be_bytes([buff[p + 1], buff[p + 2], buff[p + 3], buff[p + 4]]) & 0x007f_7f3f;
        let t1 = buff[p + 2];
        let t2 = buff[p + 3];
        let t3 = buff[p + 4];
        // DV.pm:231.
        time_str = Some(format!(
          "{:02x}:{:02x}:{:02x}",
          t3 & 0x3f,
          t2 & 0x7f,
          t1 & 0x7f
        ));
        break; // DV.pm:232 `last` ⇒ exit the INNER loop only
      } else {
        // DV.pm:233-235 else ⇒ undef $time (must be consecutive).
        time_str = None;
      }
    }
  }
  (date_str, time_str, is_16_9, interlace_set)
}

/// Computed result of the bytewise parse (`compute`). Distinguishes the
/// Perl reject paths from the two accept paths so each is independently
/// testable; the live driver matches and runs the `&mut ctx` finalize.
///
/// §2: private intermediate enum (never crosses the crate boundary, so no
/// `Display`/lossless-escape surface) — `derive_more::IsVariant` supplies
/// the variant predicates. All variants are unit or single-field newtype
/// (`Found`), satisfying the unit-or-newtype-only rule.
#[derive(derive_more::IsVariant)]
enum Parsed<'a> {
  /// DV.pm:158 `or return 0` — `$raf->Read` empty.
  RejectEmpty,
  /// DV.pm:167 `return 0 unless defined $start` — no DIF header.
  RejectNoDif,
  /// DV.pm:171 `return 0 if $start + 80 * 6 > $len` — buffer too short.
  RejectShortDif,
  /// DV.pm:188 `Warn("Unrecognized DV profile"), return 1`. Carries
  /// `'a` only for shape parity with [`Parsed::Found`]; no borrow today.
  UnrecognizedProfile,
  /// DV.pm:267-270 — emit tags in @dvTags order.
  Found(Meta<'a>),
}

// ===========================================================================
// Typed Meta — `Meta<'a>`
// ===========================================================================

/// Typed DV metadata — the lib-first output of [`ProcessDv`].
///
/// Holds the post-ValueConv raw scalars from `ProcessDV` (DV.pm:151-273)
/// plus the `Profile`/`VideoFormat`/`Colorimetry` `&'static str` slices
/// borrowed from [`DV_PROFILES`]. PrintConv (`ConvertDuration`,
/// `ConvertBitrate`, FrameRate rounding) is applied at emit time by
/// `serialize_tags` to mirror ExifTool's
/// `$$self{OPTIONS}{PrintConv}` toggle.
///
/// **D8 — no public fields, accessors only.**
///
/// **Lifetimes.** `'a` is held for shape parity with formats that
/// borrow string slices from the input; DV's only string fields are
/// `&'static str` from the profile table, so `'a` is effectively
/// `'static` in practice. The `date_time_original` is the only owned
/// allocation (`String` produced by the VAUX scan).
#[derive(Debug, Clone)]
pub struct Meta<'a> {
  /// `DateTimeOriginal` — VAUX-decoded date/time. `None` when the
  /// VAUX scan failed or rejected the hex-component decode
  /// (DV.pm:220-221).
  date_time_original: Option<String>,
  /// `ImageWidth` from the matched [`Profile`].
  image_width: u32,
  /// `ImageHeight` from the matched [`Profile`].
  image_height: u32,
  /// `Duration` in seconds = file-size / byte-rate (DV.pm:196).
  duration: f64,
  /// `TotalBitrate` in bps = 8 * frame-size * frame-rate (DV.pm:194).
  total_bitrate: f64,
  /// `VideoFormat` from the matched [`Profile`].
  video_format: &'a str,
  /// `VideoScanType` — `Some("Interlaced")` / `Some("Progressive")` if the
  /// VAUX `0x61` pack was found; `None` otherwise (DV.pm:242).
  video_scan_type: Option<&'a str>,
  /// `FrameRate` in Hz = profile.frame_rate_num / profile.frame_rate_den.
  frame_rate: f64,
  /// `AspectRatio` — `"16:9"` / `"4:3"` from the VAUX `0x61` pack
  /// (DV.pm:241); `None` if not present.
  aspect_ratio: Option<&'a str>,
  /// `Colorimetry` from the matched [`Profile`].
  colorimetry: &'a str,
  /// `AudioChannels` — DV.pm:258-262 (0/2/4/8). `None` if no audio pack.
  audio_channels: Option<i64>,
  /// `AudioSampleRate` — DV.pm:256-257 (48000/44100/32000). `None` if
  /// no audio pack.
  audio_sample_rate: Option<i64>,
  /// `AudioBitsPerSample` — DV.pm:263 (12 or 16). `None` if no audio
  /// pack.
  audio_bits_per_sample: Option<i64>,
}

impl<'a> Meta<'a> {
  /// `DateTimeOriginal` as a fixed-format `"YYYY:MM:DD hh:mm:ss"` string
  /// (DV.pm:239). `None` if the VAUX scan failed. (`Option::as_deref` is
  /// not `const`, so this getter is non-const.)
  #[must_use]
  #[inline(always)]
  pub fn date_time_original(&self) -> Option<&str> {
    self.date_time_original.as_deref()
  }
  /// `ImageWidth` in pixels (DV.pm `@dvProfiles{ImageWidth}`).
  #[must_use]
  #[inline(always)]
  pub const fn image_width(&self) -> u32 {
    self.image_width
  }
  /// `ImageHeight` in pixels.
  #[must_use]
  #[inline(always)]
  pub const fn image_height(&self) -> u32 {
    self.image_height
  }
  /// `Duration` in seconds (file-size / byte-rate, DV.pm:196).
  #[must_use]
  #[inline(always)]
  pub const fn duration_secs(&self) -> f64 {
    self.duration
  }
  /// `TotalBitrate` in bits-per-second (DV.pm:194).
  #[must_use]
  #[inline(always)]
  pub const fn total_bitrate_bps(&self) -> f64 {
    self.total_bitrate
  }
  /// `VideoFormat` (e.g. `"IEC 61834 - 625/50 (PAL)"`).
  #[must_use]
  #[inline(always)]
  pub const fn video_format(&self) -> &'a str {
    self.video_format
  }
  /// `VideoScanType` — `"Interlaced"` / `"Progressive"`. `None` if no
  /// VAUX `0x61` pack.
  #[must_use]
  #[inline(always)]
  pub const fn video_scan_type(&self) -> Option<&'a str> {
    self.video_scan_type
  }
  /// `FrameRate` raw value in Hz (post-ValueConv `num/den`,
  /// pre-PrintConv rounding).
  #[must_use]
  #[inline(always)]
  pub const fn frame_rate(&self) -> f64 {
    self.frame_rate
  }
  /// `AspectRatio` — `"16:9"` / `"4:3"`. `None` if no VAUX `0x61` pack.
  #[must_use]
  #[inline(always)]
  pub const fn aspect_ratio(&self) -> Option<&'a str> {
    self.aspect_ratio
  }
  /// `Colorimetry` (e.g. `"4:2:0"`).
  #[must_use]
  #[inline(always)]
  pub const fn colorimetry(&self) -> &'a str {
    self.colorimetry
  }
  /// `AudioChannels` count. `None` if no audio pack.
  #[must_use]
  #[inline(always)]
  pub const fn audio_channels(&self) -> Option<i64> {
    self.audio_channels
  }
  /// `AudioSampleRate` in Hz. `None` if no audio pack.
  #[must_use]
  #[inline(always)]
  pub const fn audio_sample_rate(&self) -> Option<i64> {
    self.audio_sample_rate
  }
  /// `AudioBitsPerSample` in bits (12 or 16). `None` if no audio pack.
  #[must_use]
  #[inline(always)]
  pub const fn audio_bits_per_sample(&self) -> Option<i64> {
    self.audio_bits_per_sample
  }
}

/// Bytewise parse of the 12 KiB window. `total_len` is the full file
/// length (`$$et{VALUE}{FileSize}`, used by DV.pm:196 for Duration).
fn compute(buff: &[u8], total_len: usize) -> Parsed<'static> {
  if buff.is_empty() {
    return Parsed::RejectEmpty;
  }
  let Some(start) = find_dif_start(buff) else {
    return Parsed::RejectNoDif; // DV.pm:167
  };
  // DV.pm:171 — must have ≥ 6 DIF blocks (480 bytes). Equivalent to
  // Perl `if $start + 80 * 6 > $len`; `checked_add` guards the unsigned
  // arithmetic if `start` is implausibly large (a saturating `usize::MAX`
  // start is rejected via the overflow branch).
  let need = match start.checked_add(80 * 6) {
    Some(n) => n,
    None => return Parsed::RejectShortDif,
  };
  if need > buff.len() {
    return Parsed::RejectShortDif;
  }
  let dsf: u8 = (buff[start + 3] & 0x80) >> 7; // DV.pm:176
  let stype: u8 = buff[start + 80 * 5 + 48 + 3] & 0x1f; // DV.pm:177

  // DV.pm:180 special-case probe uses `Get8u(\$buff, 4)` — ABSOLUTE offset 4,
  // NOT `$pos + 4` / `$start + 4`. The two preceding probes (DV.pm:176-177)
  // DO use `$pos`, so the literal `4` here is a deliberate choice in the
  // bundled Perl, not a typo: it inspects the APT bits of the FIRST DIF
  // block in the file (header sector 0, block 0), regardless of where the
  // parser's `$start` landed. We mirror it faithfully as `buff[4]`. If this
  // ever turns out to be a bug in the oracle, the fix must come from
  // upstream ExifTool first.
  let profile_idx: Option<usize> = if dsf == 1 && stype == 0 && (buff[4] & 0x07) != 0 {
    Some(2) // DV.pm:180-181 special case ⇒ @dvProfiles[2]
  } else {
    DV_PROFILES
      .iter()
      .position(|p| p.dsf() == dsf && p.video_stype() == stype)
  };
  let Some(profile_idx) = profile_idx else {
    return Parsed::UnrecognizedProfile; // DV.pm:188
  };
  let profile = &DV_PROFILES[profile_idx];
  // DV.pm:193-196.
  let byte_rate: f64 = f64::from(profile.frame_size()) * profile.frame_rate_f64();
  let total_bitrate: f64 = 8.0 * byte_rate;
  // DV.pm:196 — Duration uses the FULL file size (`$$et{VALUE}{FileSize}`),
  // not the 12 KiB window. Faithful equivalent: `ctx.data().len()`.
  let duration: f64 = (total_len as f64) / byte_rate;

  // DV.pm:198-244 VAUX scan.
  let (date_str, time_str, is_16_9, interlace_set) = extract_vaux_meta(buff, start);
  let mut date_time_original: Option<String> = None;
  let mut aspect_ratio: Option<&'static str> = None;
  let mut video_scan_type: Option<&'static str> = None;
  if let (Some(d), Some(t)) = (date_str.as_deref(), time_str.as_deref()) {
    date_time_original = Some(format!("{d} {t}")); // DV.pm:239
    if let Some(is16) = is_16_9 {
      aspect_ratio = Some(if is16 { "16:9" } else { "4:3" }); // DV.pm:241
      let interlace = interlace_set.unwrap_or(false);
      video_scan_type = Some(if interlace {
        "Interlaced"
      } else {
        "Progressive"
      });
      // DV.pm:242
    }
  }

  // DV.pm:247-264 audio.
  let mut audio_channels: Option<i64> = None;
  let mut audio_sample_rate: Option<i64> = None;
  let mut audio_bits_per_sample: Option<i64> = None;
  let audio_pos = start + 80 * 6 + 80 * 16 * 3 + 3; // DV.pm:250
  if audio_pos + 4 < buff.len() && buff[audio_pos] == 0x50 {
    let _smpls = buff[audio_pos + 1]; // DV.pm:252 (Perl never uses $smpls — faithful no-op)
    let freq = (buff[audio_pos + 4] >> 3) & 0x07; // DV.pm:253
    let mut a_stype = buff[audio_pos + 3] & 0x1f; // DV.pm:254
    let quant = buff[audio_pos + 4] & 0x07; // DV.pm:255
    if freq < 3 {
      audio_sample_rate = Some(match freq {
        0 => 48_000,
        1 => 44_100,
        2 => 32_000,
        _ => unreachable!(), // gated by `freq < 3`
      });
    }
    if a_stype < 3 {
      if a_stype == 0 && quant != 0 && freq == 2 {
        a_stype = 2; // DV.pm:260
      }
      audio_channels = Some(match a_stype {
        0 => 2,
        1 => 0,
        2 => 4,
        3 => 8,
        _ => unreachable!(), // gated above
      });
    }
    audio_bits_per_sample = Some(if quant != 0 { 12 } else { 16 }); // DV.pm:263
  }

  Parsed::Found(Meta {
    date_time_original,
    image_width: profile.image_width(),
    image_height: profile.image_height(),
    duration,
    total_bitrate,
    video_format: profile.video_format(),
    video_scan_type,
    frame_rate: profile.frame_rate_f64(),
    aspect_ratio,
    colorimetry: profile.colorimetry(),
    audio_channels,
    audio_sample_rate,
    audio_bits_per_sample,
  })
}

// ===========================================================================
// `ProcessDv` — the lib-first parser
// ===========================================================================

/// DV parser. Faithful `ProcessDV` (DV.pm:151-273).
#[derive(Debug, Clone, Copy)]
pub struct ProcessDv;

impl parser_sealed::Sealed for ProcessDv {}

/// Result of a typed `ProcessDv::parse`. Distinguishes the recognized-but-
/// unrecognized-profile branch (DV.pm:188 `Warn(...), return 1`) from the
/// full-data success branch (DV.pm:267-270). Both are positive
/// `Some(...)` returns: the legacy bridge translates them into
/// `Warn` + return-true vs. tag-emission + return-true respectively.
///
/// The `Parsed::Reject*` arms map to `Ok(None)` (Perl `return 0`).
///
/// §2: data-carrying enum — `derive_more` supplies `is_*` predicates and
/// `unwrap_*`/`try_unwrap_*` accessors (`ref`/`ref_mut`) so callers don't
/// hand-match; `Display` is routed through the single [`Self::as_str`]
/// label. Closed semantic vocabulary (the two terminal outcomes of a DV
/// parse), so no open `Other(_)` / coded `Unknown(n)` escape applies; still
/// `#[non_exhaustive]` so a future outcome variant is non-breaking.
#[non_exhaustive]
#[derive(Debug, Clone, derive_more::IsVariant, derive_more::Unwrap, derive_more::TryUnwrap)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
pub enum ParseOutcome<'a> {
  /// DV.pm:188 — recognized DIF header but no profile match. Bundled
  /// Perl emits `Warning => "Unrecognized DV profile"` and returns 1
  /// without pushing any DV:* tags.
  UnrecognizedProfile,
  /// DV.pm:267-270 — full success; emit tags in @dvTags order.
  Meta(Meta<'a>),
}

impl ParseOutcome<'_> {
  /// Stable label for each outcome (single source of truth for `Display`).
  #[must_use]
  #[inline(always)]
  pub const fn as_str(&self) -> &'static str {
    match self {
      ParseOutcome::UnrecognizedProfile => "UnrecognizedProfile",
      ParseOutcome::Meta(_) => "Meta",
    }
  }
}

impl core::fmt::Display for ParseOutcome<'_> {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

impl FormatParser for ProcessDv {
  /// Spec §8: leaf format with no shared state; reads a single byte slice.
  /// GAT: the Meta is parameterized by `'a`, though every string field
  /// actually originates from the `'static` [`DV_PROFILES`] table (Codex
  /// AF2).
  type Meta<'a> = ParseOutcome<'a>;
  /// Spec §8: leaf format Context is `&'a [u8]`.
  type Context<'a> = &'a [u8];
  /// Rust-level fatal error (none today; DV parsing has no I/O modes).
  type Error = Error;

  /// Parse a DV file's bytes into a typed [`ParseOutcome`], or `None`
  /// if the buffer is not a valid DV file (short read, no DIF header,
  /// fewer than 6 blocks). Returns `Err` only for Rust-level fatal
  /// modes; the current port has none.
  fn parse<'a>(&self, data: Self::Context<'a>) -> Result<Option<Self::Meta<'a>>, Error> {
    // `parse_outcome` yields a `ParseOutcome<'static>`; covariance widens
    // it to the caller's `'a`.
    Ok(parse_outcome(data))
  }
}

/// Lib-first direct entry. Same as [`FormatParser::parse`] but produces
/// a `ParseOutcome` whose `Meta` arm carries borrows out of
/// [`DV_PROFILES`] (i.e. `'static` in practice; the `&str` slices are
/// const-table entries).
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today; reserved for
/// future I/O wrappers).
pub fn parse_borrowed(data: &[u8]) -> Result<Option<ParseOutcome<'static>>, Error> {
  Ok(parse_outcome(data))
}

fn parse_outcome(data: &[u8]) -> Option<ParseOutcome<'static>> {
  let total_len = data.len();
  let cap = total_len.min(12_000);
  match compute(&data[..cap], total_len) {
    Parsed::RejectEmpty | Parsed::RejectNoDif | Parsed::RejectShortDif => None,
    Parsed::UnrecognizedProfile => Some(ParseOutcome::UnrecognizedProfile),
    Parsed::Found(meta) => Some(ParseOutcome::Meta(meta)),
  }
}

// NOTE: DV's typed parser always produces `Meta<'static>` because every
// `&'a str` field originates from the `'static` [`DV_PROFILES`] table; the
// `FormatParser::Meta` GAT (`type Meta<'a> = ParseOutcome<'a>`) widens
// it to the caller's `'a` by covariance (Codex AF2). The `<'a>` parameter
// is kept on the struct for shape parity with the rest of the Phase F1
// leaves and to leave room for future bytes-borrowed accessors (e.g. a
// raw DIF-block view).

// ===========================================================================
// `serialize_tags` — typed Meta → TagMap
// ===========================================================================

#[cfg(feature = "alloc")]
impl Meta<'_> {
  /// Emit DV tags into the writer in `@dvTags` order (DV.pm:116-121) —
  /// faithful to the bundled-Perl iteration.
  ///
  /// `print_conv=true` ⇒ PrintConv formatted strings (`-j` mode);
  /// `print_conv=false` ⇒ post-ValueConv raw scalars (`-n` mode).
  pub(crate) fn serialize_tags(
    &self,
    print_conv: bool,
    out: &mut crate::tagmap::TagMap,
  ) -> Result<(), core::convert::Infallible> {
    const GROUP: &str = "DV";
    for &tag_name in DV_TAGS {
      match tag_name {
        "DateTimeOriginal" => {
          if let Some(s) = self.date_time_original.as_deref() {
            // DV.pm:128 PrintConv => ConvertDateTime; default options
            // pass through unchanged ⇒ same string under -j and -n.
            out.write_str(GROUP, "DateTimeOriginal", s)?;
          }
        }
        "ImageWidth" => out.write_u64(GROUP, "ImageWidth", u64::from(self.image_width))?,
        "ImageHeight" => out.write_u64(GROUP, "ImageHeight", u64::from(self.image_height))?,
        "Duration" => {
          if print_conv {
            // PrintConv: ConvertDuration formatted string.
            out.write_fmt(GROUP, "Duration", |w| {
              w.write_str(&convert_duration_str(&TagValue::F64(self.duration)))
            })?;
          } else {
            out.write_f64(GROUP, "Duration", self.duration)?;
          }
        }
        "TotalBitrate" => {
          if print_conv {
            out.write_fmt(GROUP, "TotalBitrate", |w| {
              w.write_str(&convert_bitrate_str(&TagValue::F64(self.total_bitrate)))
            })?;
          } else {
            out.write_f64(GROUP, "TotalBitrate", self.total_bitrate)?;
          }
        }
        "VideoFormat" => out.write_str(GROUP, "VideoFormat", self.video_format)?,
        "VideoScanType" => {
          if let Some(s) = self.video_scan_type {
            out.write_str(GROUP, "VideoScanType", s)?;
          }
        }
        "FrameRate" => {
          if print_conv {
            // DV.pm:139 PrintConv: int($val * 1000 + 0.5) / 1000.
            let rounded = ((self.frame_rate * 1000.0 + 0.5).floor()) / 1000.0;
            out.write_f64(GROUP, "FrameRate", rounded)?;
          } else {
            out.write_f64(GROUP, "FrameRate", self.frame_rate)?;
          }
        }
        "AspectRatio" => {
          if let Some(s) = self.aspect_ratio {
            out.write_str(GROUP, "AspectRatio", s)?;
          }
        }
        "Colorimetry" => out.write_str(GROUP, "Colorimetry", self.colorimetry)?,
        "AudioChannels" => {
          if let Some(n) = self.audio_channels {
            out.write_i64(GROUP, "AudioChannels", n)?;
          }
        }
        "AudioSampleRate" => {
          if let Some(n) = self.audio_sample_rate {
            out.write_i64(GROUP, "AudioSampleRate", n)?;
          }
        }
        "AudioBitsPerSample" => {
          if let Some(n) = self.audio_bits_per_sample {
            out.write_i64(GROUP, "AudioBitsPerSample", n)?;
          }
        }
        _ => {} // unreachable: DV_TAGS is a fixed const list
      }
    }
    Ok(())
  }
}

// ===========================================================================
// `Error` — Rust-level fatal modes (currently none)
// ===========================================================================

/// Rust-level fatal modes for DV parsing. Currently empty — every bad
/// input produces `Ok(None)` (Perl `return 0`). Reserved for future I/O
/// wrappers if streaming readers are added.
///
/// §5: derived via `thiserror` (`Display` + `core::error::Error` in every
/// feature tier — `thiserror` v2 with `default-features = false` emits
/// `core::error::Error`, so `Error` is a real `Error` even on no-std).
/// `#[non_exhaustive]` lets the first real variant land without a breaking
/// change. The derive expands `Display` to an empty `match *self {}`, so no
/// `#[error(…)]` attribute is needed while the enum has no variants.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {}

// ===========================================================================
// Engine entry — typed parse + File:* + sink into `Metadata`
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn dv_error_is_core_error() {
    // §5: thiserror v2 (default-features=false) makes the empty error enum
    // a real `core::error::Error` in every feature tier.
    fn assert_error<E: core::error::Error>() {}
    assert_error::<Error>();
  }

  #[test]
  fn profiles_and_tag_order_are_faithful() {
    // DV.pm:21-113 → 10 entries; DV.pm:116-121 → 13 tags.
    assert_eq!(DV_PROFILES.len(), 10);
    assert_eq!(DV_TAGS.len(), 13);
    // [1] PAL 25Mbps 4:2:0 default — the DV.dv oracle's selected row.
    assert_eq!(DV_PROFILES[1].video_format(), "IEC 61834 - 625/50 (PAL)");
    assert_eq!(DV_PROFILES[1].colorimetry(), "4:2:0");
    assert_eq!(DV_PROFILES[1].frame_rate_f64(), 25.0);
    // [2] SMPTE-314M PAL 4:1:1 (DV.pm:180 special case index).
    assert_eq!(DV_PROFILES[2].video_format(), "SMPTE-314M - 625/50 (PAL)");
    assert_eq!(DV_PROFILES[2].colorimetry(), "4:1:1");
    // [0] NTSC frame rate is 30000/1001.
    let ntsc = DV_PROFILES[0].frame_rate_f64();
    assert!((ntsc - 30000.0 / 1001.0).abs() < 1e-12);
    // [7] 720p60 is 60000/1001.
    let ntsc_720p = DV_PROFILES[7].frame_rate_f64();
    assert!((ntsc_720p - 60000.0 / 1001.0).abs() < 1e-12);
    // Every @dvTags entry has a %DV::Main def.
    for &t in DV_TAGS {
      assert!(
        (DV_MAIN.get())(TagId::Str(t)).is_some(),
        "DV_TAGS entry {t:?} missing from dv_get"
      );
    }
    assert!((DV_MAIN.get())(TagId::Str("NoSuchTag")).is_none());
    assert!((DV_MAIN.get())(TagId::Int(0)).is_none());
    assert_eq!(DV_MAIN.group0(), "DV");
  }

  #[test]
  fn convert_duration_faithful_to_perl() {
    // Verified against bundled Perl ConvertDuration.
    assert_eq!(
      convert_duration_str(&TagValue::F64(0.00122222222222222)),
      "0.00 s"
    );
    assert_eq!(convert_duration_str(&TagValue::F64(0.0)), "0 s");
    assert_eq!(convert_duration_str(&TagValue::F64(29.95)), "29.95 s");
    // == 30 exactly ⇒ NOT < 30 ⇒ H:MM:SS branch → 0:00:30.
    assert_eq!(convert_duration_str(&TagValue::F64(30.0)), "0:00:30");
    assert_eq!(convert_duration_str(&TagValue::F64(3600.0)), "1:00:00");
    assert_eq!(
      convert_duration_str(&TagValue::F64(90061.0)),
      "1 days 1:01:01"
    );
    assert_eq!(convert_duration_str(&TagValue::F64(-3600.0)), "-1:00:00");
    // I64 input (defensive — Perl IsFloat(0) is true).
    assert_eq!(convert_duration_str(&TagValue::I64(0)), "0 s");
  }

  #[test]
  fn convert_bitrate_faithful_to_perl() {
    // Oracle: DV.dv has TotalBitrate = 8 * 144000 * 25 = 28_800_000.
    assert_eq!(
      convert_bitrate_str(&TagValue::F64(28_800_000.0)),
      "28.8 Mbps"
    );
    assert_eq!(convert_bitrate_str(&TagValue::F64(100.0)), "100 bps");
    assert_eq!(convert_bitrate_str(&TagValue::F64(50.0)), "50 bps");
    assert_eq!(convert_bitrate_str(&TagValue::F64(123.456)), "123 bps");
    assert_eq!(convert_bitrate_str(&TagValue::F64(999.0)), "999 bps");
    assert_eq!(convert_bitrate_str(&TagValue::F64(1000.0)), "1 kbps");
    assert_eq!(convert_bitrate_str(&TagValue::F64(1.5)), "1.5 bps");
    assert_eq!(convert_bitrate_str(&TagValue::I64(28_800_000)), "28.8 Mbps");
  }

  #[test]
  fn frame_rate_round_faithful() {
    // DV.pm:139 `int($val * 1000 + 0.5) / 1000`.
    let r25 = print_conv_frame_rate(&TagValue::F64(25.0));
    assert_eq!(r25, TagValue::F64(25.0));
    let r2997 = match print_conv_frame_rate(&TagValue::F64(30000.0 / 1001.0)) {
      TagValue::F64(n) => n,
      _ => panic!("not F64"),
    };
    assert!((r2997 - 29.97).abs() < 1e-9, "got {r2997}");
    let r5994 = match print_conv_frame_rate(&TagValue::F64(60000.0 / 1001.0)) {
      TagValue::F64(n) => n,
      _ => panic!("not F64"),
    };
    assert!((r5994 - 59.94).abs() < 1e-9, "got {r5994}");
  }

  #[test]
  fn find_dif_start_matches_primary_form() {
    let mut buff = vec![0u8; 600];
    buff[0..4].copy_from_slice(&[0x1f, 0x07, 0x00, 0xbf]);
    assert_eq!(find_dif_start(&buff), Some(0));
  }

  #[test]
  fn find_dif_start_fallback_perl_g_non_overlapping_regression() {
    // Codex R1 regression: fallback-regex `/g` scan in Perl is
    // NON-OVERLAPPING (`pos` advances to the END of every match, not
    // `+1`). Build a 200-byte buffer with fallback signatures at
    // offsets 75 and 79 (overlapping inside one 84-byte window). Perl
    // `/g`: ONE match ending at 159 (the first head, the first head's
    // tail at 155), $start = 159 - 163 = -4 < 0, guard skips, no more
    // matches → undef. A naïve overlapping `i += 1` scan would find
    // the second match (head at 79, tail at 159) and return
    // start = 79 - 79 = 0, accepting a buffer Perl rejects.
    let mut buff = vec![0u8; 200];
    buff[75..79].copy_from_slice(&[0x00, 0x3f, 0x07, 0x00]); // head #1
    buff[155..159].copy_from_slice(&[0xff, 0x3f, 0x07, 0x01]); // tail #1
    buff[79..83].copy_from_slice(&[0x00, 0x3f, 0x07, 0x00]); // head #2 (inside #1)
    buff[159..163].copy_from_slice(&[0xff, 0x3f, 0x07, 0x01]); // tail #2
    assert_eq!(find_dif_start(&buff), None);

    // Sanity: a primary match anywhere still wins (primary scan runs
    // first, so the fallback never sees this case).
    let mut buff_with_primary = buff.clone();
    buff_with_primary[10..14].copy_from_slice(&[0x1f, 0x07, 0x00, 0x3f]);
    assert_eq!(find_dif_start(&buff_with_primary), Some(10));

    // Sanity: a fallback match whose `i >= 79` is still accepted (the
    // fix advances PAST guard-failures, not past every fallback match).
    let mut buff_ok = vec![0u8; 300];
    buff_ok[79..83].copy_from_slice(&[0x00, 0x3f, 0x07, 0x00]); // head at 79
    buff_ok[159..163].copy_from_slice(&[0xff, 0x3f, 0x07, 0x01]); // tail at 159
    assert_eq!(find_dif_start(&buff_ok), Some(0)); // 79 - 79 = 0
  }

  #[test]
  fn find_dif_start_handles_short_or_empty_buff() {
    assert_eq!(find_dif_start(b""), None);
    assert_eq!(find_dif_start(b"\x1f\x07\x00"), None);
    // 3 bytes ≠ pattern: still None.
    assert_eq!(find_dif_start(b"\x00\x00\x00"), None);
  }

  // The engine path is now `crate::parser::extract_info`. These tests run it
  // and assert on the parsed JSON object, replacing the retired
  // `ProcessDv::process` + `TagMap` tests.
  fn engine_obj(data: &[u8], print_on: bool) -> serde_json::Map<String, serde_json::Value> {
    let json = crate::parser::extract_info("x.dv", data, print_on);
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    v.as_array().unwrap()[0].as_object().unwrap().clone()
  }
  /// `true` if the engine finalized the file as `DV`.
  fn is_dv(obj: &serde_json::Map<String, serde_json::Value>) -> bool {
    obj.get("File:FileType").and_then(|v| v.as_str()) == Some("DV")
  }

  #[test]
  fn process_rejects_empty_buffer() {
    assert!(!is_dv(&engine_obj(&[], true)));
  }

  #[test]
  fn process_rejects_no_dif_header() {
    assert!(!is_dv(&engine_obj(&vec![0u8; 200], true)));
  }

  #[test]
  fn process_rejects_when_dif_header_lacks_six_blocks() {
    // 4-byte magic at offset 0; len 4 ⇒ start+480 > 4 ⇒ DV.pm:171 reject.
    assert!(!is_dv(&engine_obj(&[0x1f, 0x07, 0x00, 0x3f], true)));
  }

  #[test]
  fn process_rejects_when_six_blocks_truncated() {
    let mut data = vec![0u8; 479];
    data[0..4].copy_from_slice(&[0x1f, 0x07, 0x00, 0x3f]);
    assert!(!is_dv(&engine_obj(&data, true)));
  }

  #[test]
  fn unrecognized_profile_warns_and_accepts() {
    // dsf=0 stype=0x1f (no profile match). Special-case fails (dsf!=1).
    let mut data = vec![0u8; 480];
    data[0..4].copy_from_slice(&[0x1f, 0x07, 0x00, 0x3f]);
    data[451] = 0x1f; // buff[start + 80*5 + 48 + 3]
    let obj = engine_obj(&data, true);
    // File:* pushed (SetFileType BEFORE the warning, DV.pm:173).
    assert!(is_dv(&obj));
    assert_eq!(
      obj.get("ExifTool:Warning").and_then(|v| v.as_str()),
      Some("Unrecognized DV profile")
    );
    // No DV:* tags (the unrecognized-profile branch returns 1 before HandleTag).
    assert!(!obj.keys().any(|k| k.starts_with("DV:")));
  }

  #[test]
  fn date_with_invalid_hex_is_rejected() {
    // PAL DIF (dsf=1, stype=0 ⇒ profile[1]) with a date pack whose nibble
    // forces an `a-f` letter in the hex sprintf — DV.pm:220-221 rejects.
    let mut data = vec![0u8; 8000];
    data[0..4].copy_from_slice(&[0x1f, 0x07, 0x00, 0xbf]); // dsf=1
    data[80] = 0x50;
    data[83] = 0x62;
    data[84] = 0x00;
    data[85] = 0x05;
    data[86] = 0x12;
    data[87] = 0xaa; // sprintf("%.2x", 0xaa) = "aa" ⇒ contains a-f
    let obj = engine_obj(&data, true);
    assert!(!obj.contains_key("DV:DateTimeOriginal"));
    assert!(obj.contains_key("DV:ImageWidth"));
  }

  #[test]
  fn frame_rate_print_conv_applies_in_emission() {
    // NTSC profile[0]: dsf=0, stype=0. buff[3]=0x3f, buff[451]=0.
    let mut data = vec![0u8; 8000];
    data[0..4].copy_from_slice(&[0x1f, 0x07, 0x00, 0x3f]);
    data[451] = 0x00;
    let obj = engine_obj(&data, true);
    // FrameRate → 29.97 after PrintConv.
    let n = obj
      .get("DV:FrameRate")
      .and_then(|v| v.as_f64())
      .expect("FrameRate");
    assert!((n - 29.97).abs() < 1e-9, "got {n}");
    // -n: raw 30000/1001.
    let obj2 = engine_obj(&data, false);
    let n2 = obj2.get("DV:FrameRate").and_then(|v| v.as_f64()).unwrap();
    assert!((n2 - 30000.0 / 1001.0).abs() < 1e-12);
  }

  #[test]
  fn special_case_pal_25_411_selects_profile_index_2() {
    // dsf=1, stype=0, buff[4]&0x07 != 0 ⇒ DV.pm:180 special case ⇒
    // @dvProfiles[2] (SMPTE-314M PAL 4:1:1).
    let mut data = vec![0u8; 8000];
    data[0..4].copy_from_slice(&[0x1f, 0x07, 0x00, 0xbf]); // dsf=1
    data[4] = 0x01; // buff[4] & 0x07 == 1 (non-zero)
    data[451] = 0; // stype = 0
    let obj = engine_obj(&data, true);
    assert_eq!(
      obj.get("DV:VideoFormat").and_then(|v| v.as_str()),
      Some("SMPTE-314M - 625/50 (PAL)")
    );
    assert_eq!(
      obj.get("DV:Colorimetry").and_then(|v| v.as_str()),
      Some("4:1:1")
    );
  }

  #[test]
  fn unrecognized_profile_branch_no_emission_no_panic() {
    // Edge: stype=0x1f, dsf=1, buff[4]&0x07=0 ⇒ special-case false ⇒
    // foreach finds no match ⇒ Warn + return 1, no DV:* tags.
    let mut data = vec![0u8; 480];
    data[0..4].copy_from_slice(&[0x1f, 0x07, 0x00, 0xbf]); // dsf=1
    data[451] = 0x1f;
    let obj = engine_obj(&data, true);
    assert_eq!(
      obj.get("ExifTool:Warning").and_then(|v| v.as_str()),
      Some("Unrecognized DV profile")
    );
    assert!(!obj.keys().any(|k| k.starts_with("DV:")));
  }

  // ---------- Lib-first typed Meta surface --------------------------------

  #[test]
  fn parse_borrowed_returns_meta_outcome_for_pal_default() {
    // PAL 25Mbps 4:2:0 default — profile[1].
    let mut data = vec![0u8; 8000];
    data[0..4].copy_from_slice(&[0x1f, 0x07, 0x00, 0xbf]); // dsf=1
    data[451] = 0x00; // stype = 0 ⇒ profile[1] (PAL)
    let outcome = parse_borrowed(&data).expect("ok").expect("parsed");
    match outcome {
      ParseOutcome::Meta(m) => {
        assert_eq!(m.image_width(), 720);
        assert_eq!(m.image_height(), 576);
        assert_eq!(m.video_format(), "IEC 61834 - 625/50 (PAL)");
        assert_eq!(m.colorimetry(), "4:2:0");
        assert!((m.frame_rate() - 25.0).abs() < 1e-12);
      }
      ParseOutcome::UnrecognizedProfile => panic!("expected Meta"),
    }
  }

  #[test]
  fn parse_borrowed_returns_unrecognized_for_off_table_stype() {
    let mut data = vec![0u8; 480];
    data[0..4].copy_from_slice(&[0x1f, 0x07, 0x00, 0x3f]);
    data[451] = 0x1f;
    let outcome = parse_borrowed(&data).expect("ok").expect("parsed");
    assert!(matches!(outcome, ParseOutcome::UnrecognizedProfile));
  }

  #[test]
  fn parse_borrowed_rejects_empty() {
    assert!(parse_borrowed(&[]).unwrap().is_none());
  }

  #[test]
  fn dv_parse_outcome_variant_accessors_and_display() {
    // §2 derive_more predicates + unwrap/try_unwrap + Display-via-as_str.
    let unrecognized: ParseOutcome<'static> = ParseOutcome::UnrecognizedProfile;
    assert!(unrecognized.is_unrecognized_profile());
    assert!(!unrecognized.is_meta());
    assert_eq!(unrecognized.as_str(), "UnrecognizedProfile");
    assert_eq!(unrecognized.to_string(), "UnrecognizedProfile");
    assert!(unrecognized.try_unwrap_meta().is_err());

    let meta = Meta {
      date_time_original: None,
      image_width: 720,
      image_height: 576,
      duration: 1.0,
      total_bitrate: 1.0,
      video_format: "x",
      video_scan_type: None,
      frame_rate: 25.0,
      aspect_ratio: None,
      colorimetry: "4:2:0",
      audio_channels: None,
      audio_sample_rate: None,
      audio_bits_per_sample: None,
    };
    let outcome = ParseOutcome::Meta(meta);
    assert!(outcome.is_meta());
    assert_eq!(outcome.as_str(), "Meta");
    assert_eq!(outcome.to_string(), "Meta");
    assert_eq!(outcome.unwrap_meta().image_width(), 720);
  }

  #[test]
  fn meta_sinker_emits_typed_tags() {
    use crate::tagmap::TagMap;
    // Construct a Meta directly so we don't depend on a fixture.
    let meta = Meta {
      date_time_original: Some("2024:01:15 12:30:45".to_string()),
      image_width: 720,
      image_height: 576,
      duration: 8.16,
      total_bitrate: 28_800_000.0,
      video_format: "IEC 61834 - 625/50 (PAL)",
      video_scan_type: Some("Interlaced"),
      frame_rate: 25.0,
      aspect_ratio: Some("16:9"),
      colorimetry: "4:2:0",
      audio_channels: Some(2),
      audio_sample_rate: Some(32_000),
      audio_bits_per_sample: Some(16),
    };
    // PrintConv on: ConvertDuration/ConvertBitrate strings, FrameRate rounded.
    let mut w = TagMap::new();
    meta.serialize_tags(true, &mut w).unwrap();
    assert_eq!(w.get_str("DV", "Duration"), Some("8.16 s".to_string()));
    assert_eq!(
      w.get_str("DV", "TotalBitrate"),
      Some("28.8 Mbps".to_string())
    );
    assert_eq!(w.get_str("DV", "FrameRate"), Some("25".to_string()));
    assert_eq!(w.get_str("DV", "ImageWidth"), Some("720".to_string()));
    assert_eq!(
      w.get_str("DV", "VideoFormat"),
      Some("IEC 61834 - 625/50 (PAL)".to_string())
    );
    // PrintConv off: raw scalars (Duration as f64, etc.).
    let mut w = TagMap::new();
    meta.serialize_tags(false, &mut w).unwrap();
    assert_eq!(w.get_str("DV", "Duration"), Some("8.16".to_string()));
    assert_eq!(
      w.get_str("DV", "TotalBitrate"),
      Some("28800000".to_string())
    );
  }

  #[test]
  fn format_parser_trait_returns_outcome() {
    let mut data = vec![0u8; 8000];
    data[0..4].copy_from_slice(&[0x1f, 0x07, 0x00, 0xbf]);
    data[451] = 0x00;
    let outcome = <ProcessDv as FormatParser>::parse(&ProcessDv, &data)
      .expect("ok")
      .expect("parsed");
    assert!(matches!(outcome, ParseOutcome::Meta(_)));
  }
}
