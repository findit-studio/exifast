// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "red")]
//! Faithful port of `Image::ExifTool::Red` (`lib/Image/ExifTool/Red.pm`):
//! reads Redcode R3D version 1 + version 2 video files.
//!
//! **Phase F1 — lib-first migration.** Follows the MOI pilot (Phase E) +
//! AAC/DV pattern: a typed [`Meta<'a>`] is produced by the new
//! [`crate::format_parser::FormatParser`] trait; the engine entry
//! `process` drives the typed `serialize_tags` path into the engine
//! `tagmap::TagMap` so the serialized JSON stays
//! byte-exact with bundled `perl exiftool`.
//!
//! ## R3D structure (Red.pm:219-223)
//!
//!  - Each block begins with `int32u block-size` then a 4-byte block-type.
//!  - The first block is `RED1` (version 1) or `RED2` (version 2).
//!  - In version 2 blocks start on `0x1000`-byte boundaries (immaterial here:
//!    we only parse the first block + its embedded Red directory).
//!
//! The first block is the file header followed (for RED2) by `count` 0x18-byte
//! `rdi` records, then `count` 0x14-byte `rda`, then `count` 0x10-byte `rdx`,
//! then the **Red directory** (`int16u dirLen` + `int16u entryLen, int16u tagId,
//! data...` entries).
//!
//! Each directory tag-ID is 16 bits: the **top 4 bits encode the format code**
//! (Red.pm:281 `$fmt = $redFormat{$tag >> 12}`) — see [`red_format`].
//!
//! Byte order: **MM (big-endian)** for the entire file (Red.pm:231
//! `SetByteOrder('MM')`).
//!
//! ## Faithful deferrals
//!
//! Bundled `perl exiftool` emits five `Composite:*` tags for `Red.r3d`
//! (`Aperture`, `DateTimeOriginal`, `ImageSize`, `Megapixels`,
//! `FocalLength35efl`). Composite tag synthesis is engine-level (not in
//! `Red.pm` — see `Image::ExifTool::AddCompositeTags` and the ~30 `.pm`
//! files that register Composite tables). This port FAITHFULLY DEFERS the
//! Composite layer to a future Phase-3+ infrastructure PR; the goldens in
//! `tests/golden/Red.r3d.{json,n.json}` were stripped of those 5 lines
//! accordingly (the surrounding JSON stays valid). See also the
//! `exifast-phase2-forward-items` memory entry.

use crate::{
  convert::{ByteOrder, read_value},
  format_parser::{FormatParser, parser_sealed},
  value::{Rational, TagValue, format_g},
};

// ── ValueConv / PrintConv helpers ────────────────────────────────────────

/// Perl's *arithmetic-context* string-to-number coercion, returning an
/// `f64`. Mirrors what Perl does when a string `$val` is fed into `/`, `*`,
/// `+`, or `int()` (e.g. `"1000 2000" / 10 == 100`, `"undef" * 1000 == 0`,
/// `"inf" * 1000 == Inf`, `"abc" + 0 == 0`).
///
/// **Codex round-4 F1+F2:** the arithmetic ValueConv/PrintConv paths in
/// Red.pm (`$val / 10`, `$val / 1000`, `int($val * 1000 + 0.5) / 1000`)
/// receive either a typed numeric scalar or a space-joined `TagValue::Str`
/// — the latter when (a) the directory walk reads `count > 1` for a
/// numeric tag (overlong adversarial directory entry) and `read_value`
/// joins the elements with `' '`, or (b) `Rational::exiftool_val_str`
/// returns the bare words `"inf"` / `"undef"` for a zero-denominator
/// rational32u (Red.pm:166-170 RED1 FrameRate at offset 0x3e). Perl's
/// numeric coercion then takes the leading numeric prefix as f64 — that
/// is what this helper reproduces. No leading prefix ⇒ `0.0` (matching
/// `"abc"+0==0`, `"undef"+0==0`). Recognized words `"inf"`/`"infinity"`/
/// `"nan"` (any case, optional leading sign) ⇒ `±Inf` / `NaN`, matching
/// Perl's `"inf"+0==Inf`, `"nan"+0==NaN`.
///
/// **Safety:** compare on raw `bytes[after_sign..]` (a byte slice — no
/// UTF-8 boundary requirement) rather than slicing into `&s[..]`. A
/// 3-byte string slice like `&s[..3]` PANICS when the 3-byte mark
/// splits a multi-byte UTF-8 codepoint.
fn perl_arithmetic_to_f64(s: &str) -> f64 {
  let bytes = s.as_bytes();
  let mut i = 0;
  while i < bytes.len() && bytes[i].is_ascii_whitespace() {
    i += 1;
  }
  let start = i;
  if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
    i += 1;
  }
  let after_sign = i;
  let is_neg = i > start && bytes[start] == b'-';
  let after_sign_bytes = &bytes[after_sign..];
  let starts_with_ci = |needle: &[u8]| -> bool {
    after_sign_bytes.len() >= needle.len()
      && after_sign_bytes[..needle.len()]
        .iter()
        .zip(needle.iter())
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
  };
  if starts_with_ci(b"inf") {
    return if is_neg {
      f64::NEG_INFINITY
    } else {
      f64::INFINITY
    };
  }
  if starts_with_ci(b"nan") {
    return f64::NAN;
  }
  let digits_start = i;
  while i < bytes.len() && bytes[i].is_ascii_digit() {
    i += 1;
  }
  let had_int_digits = i > digits_start;
  if i < bytes.len() && bytes[i] == b'.' {
    i += 1;
    let frac_start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
      i += 1;
    }
    if !had_int_digits && i == frac_start {
      return 0.0;
    }
  } else if !had_int_digits {
    return 0.0;
  }
  if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
    let exp_word_start = i;
    i += 1;
    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
      i += 1;
    }
    let exp_digits_start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
      i += 1;
    }
    if i == exp_digits_start {
      i = exp_word_start;
    }
  }
  s[start..i].parse::<f64>().unwrap_or(0.0)
}

/// Red.pm:56 / :61 / :66 OtherDate1/2/3 ValueConv:
/// `$val =~ s/(\d{4})_(\d{2})_/$1:$2:/; $val =~ tr/_/ /; $val`.
fn other_date_value_conv(s: &str) -> String {
  let s = replace_yyyy_mm_underscore(s);
  s.replace('_', " ")
}

/// Helper: replace first `<4 digits>_<2 digits>_` with `<4 digits>:<2 digits>:`.
fn replace_yyyy_mm_underscore(s: &str) -> String {
  let b = s.as_bytes();
  for i in 0..b.len().saturating_sub(7) {
    if b[i..i + 4].iter().all(u8::is_ascii_digit)
      && b[i + 4] == b'_'
      && b[i + 5].is_ascii_digit()
      && b[i + 6].is_ascii_digit()
      && b[i + 7] == b'_'
    {
      let mut out = String::with_capacity(s.len());
      out.push_str(&s[..i]);
      out.push_str(&s[i..i + 4]);
      out.push(':');
      out.push_str(&s[i + 5..i + 7]);
      out.push(':');
      out.push_str(&s[i + 8..]);
      return out;
    }
  }
  s.to_string()
}

/// Red.pm:72 DateTimeOriginal ValueConv:
/// `$val =~ s/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})/$1:$2:$3 $4:$5:/`.
fn datetime_original_value_conv(s: &str) -> String {
  let b = s.as_bytes();
  for i in 0..b.len().saturating_sub(11) {
    if b[i..i + 12].iter().all(u8::is_ascii_digit) {
      let mut out = String::with_capacity(s.len() + 4);
      out.push_str(&s[..i]);
      out.push_str(&s[i..i + 4]);
      out.push(':');
      out.push_str(&s[i + 4..i + 6]);
      out.push(':');
      out.push_str(&s[i + 6..i + 8]);
      out.push(' ');
      out.push_str(&s[i + 8..i + 10]);
      out.push(':');
      out.push_str(&s[i + 10..i + 12]);
      out.push(':');
      out.push_str(&s[i + 12..]);
      return out;
    }
  }
  s.to_string()
}

/// Red.pm:82 / :95 — `s/(\d{4})(\d{2})/$1:$2:/` on `YYYYMMDD`.
fn date_created_value_conv(s: &str) -> String {
  let b = s.as_bytes();
  for i in 0..b.len().saturating_sub(5) {
    if b[i..i + 6].iter().all(u8::is_ascii_digit) {
      let mut out = String::with_capacity(s.len() + 2);
      out.push_str(&s[..i]);
      out.push_str(&s[i..i + 4]);
      out.push(':');
      out.push_str(&s[i + 4..i + 6]);
      out.push(':');
      out.push_str(&s[i + 6..]);
      return out;
    }
  }
  s.to_string()
}

/// Red.pm:87 / :100 — `s/(\d{2})(\d{2})/$1:$2:/` on `HHMMSS`.
fn time_created_value_conv(s: &str) -> String {
  let b = s.as_bytes();
  for i in 0..b.len().saturating_sub(3) {
    if b[i..i + 4].iter().all(u8::is_ascii_digit) {
      let mut out = String::with_capacity(s.len() + 2);
      out.push_str(&s[..i]);
      out.push_str(&s[i..i + 2]);
      out.push(':');
      out.push_str(&s[i + 2..i + 4]);
      out.push(':');
      out.push_str(&s[i + 4..]);
      return out;
    }
  }
  s.to_string()
}

/// Red.pm:141 — `FNumber` ValueConv `$val / 10`.
fn divide_by_10(v: &TagValue) -> f64 {
  match v {
    TagValue::I64(n) => *n as f64 / 10.0,
    TagValue::F64(n) => *n / 10.0,
    TagValue::Str(s) => perl_arithmetic_to_f64(s) / 10.0,
    _ => 0.0,
  }
}

/// Red.pm:147 — `FocusDistance` ValueConv `$val / 1000`.
fn divide_by_1000(v: &TagValue) -> f64 {
  match v {
    TagValue::I64(n) => *n as f64 / 1000.0,
    TagValue::F64(n) => *n / 1000.0,
    TagValue::Str(s) => perl_arithmetic_to_f64(s) / 1000.0,
    _ => 0.0,
  }
}

/// Red.pm:147 — `FocusDistance` PrintConv `"$val m"`.
fn focus_distance_print_conv(v: f64) -> String {
  let text = if v.is_finite() {
    format_g(v, 15)
  } else {
    v.to_string()
  };
  let mut out = String::with_capacity(text.len() + 2);
  out.push_str(&text);
  out.push_str(" m");
  out
}

/// Red.pm:134, :169, :202 — FrameRate / OriginalFrameRate PrintConv:
/// `int($val * 1000 + 0.5) / 1000`.
///
/// **Subtle (Codex round-1 F1):** for a `TagValue::Rational`, Perl's
/// `ReadValue` has ALREADY passed the value through `RoundFloat(num/denom,
/// 7)` before PrintConv runs. Boundary case: `1106/101 = 10.95049504…`
/// exact ⇒ Rust would emit `10.95`, but Perl rounds to `"10.9505"` first
/// ⇒ PrintConv emits `10.951`. The Rational branch below mirrors Perl
/// faithfully by going through `exiftool_val_str()` (the SAME `%.{sig}g`
/// formatter; sig=7 for rational32) and re-parsing as f64.
///
/// **Codex round-4 F2:** `Rational` with denominator 0 — reachable for
/// RED1 `FrameRate` when the denominator bytes are `\x00\x00`. Route
/// through [`perl_arithmetic_to_f64`].
///
/// **Codex round-5 F1:** Perl `int($x)` operates in NV space (double),
/// not IV (i64). Keep the truncation in `f64` via `.trunc()`.
///
/// **Codex round-6 F1:** for negative inputs in `(-0.0005, 0.0)`,
/// `f64::trunc()` returns negative zero in IEEE-754. Perl's `int()`
/// does not preserve the sign of zero. Normalize via `scaled.trunc() +
/// 0.0` (IEEE: `-0.0 + 0.0 == +0.0`).
fn round_to_3dp(v: &TagValue) -> f64 {
  let f = match v {
    TagValue::F64(n) if n.is_finite() => *n,
    TagValue::Rational(r) => perl_arithmetic_to_f64(&r.exiftool_val_str()),
    TagValue::Str(s) => perl_arithmetic_to_f64(s),
    TagValue::F64(n) => return *n,
    _ => return 0.0,
  };
  if !f.is_finite() {
    return f;
  }
  let scaled = f * 1000.0 + 0.5;
  if !scaled.is_finite() {
    return scaled / 1000.0;
  }
  let truncated = scaled.trunc() + 0.0;
  truncated / 1000.0
}

/// Red.pm:201 — RED2 FrameRate ValueConv:
/// `my @a = split " ", $val; ($a[1] * 0x10000 + $a[2]) / $a[0]`.
///
/// Under [`read_value`]'s count-shortening, `$val` may arrive as 2- or
/// 1-element shape. Perl's `split " ", $val` followed by `($a[1]*0x10000
/// + $a[2])/$a[0]` coerces missing indices to 0.
fn red2_frame_rate_value_conv(v: &TagValue) -> Option<f64> {
  let owned: String;
  let s = match v {
    TagValue::Str(s) => s.as_ref(),
    TagValue::I64(n) => {
      owned = n.to_string();
      owned.as_str()
    }
    TagValue::F64(n) if n.is_finite() => {
      owned = n.to_string();
      owned.as_str()
    }
    _ => return None,
  };
  let parts: Vec<&str> = s.split_whitespace().collect();
  let parse = |p: &str| p.parse::<i64>().ok();
  let a = parts.first().and_then(|p| parse(p))?;
  if a == 0 {
    return None;
  }
  let b = parts.get(1).and_then(|p| parse(p)).unwrap_or(0);
  let c = parts.get(2).and_then(|p| parse(p)).unwrap_or(0);
  Some((b as f64 * 65536.0 + c as f64) / a as f64)
}

/// Codex round-3 F1: detect the `($a[0] == 0)` case for RED2 FrameRate.
fn red2_frame_rate_first_word_is_zero(v: &TagValue) -> bool {
  match v {
    TagValue::I64(0) => true,
    TagValue::F64(n) => *n == 0.0,
    TagValue::Str(s) => {
      s.split_whitespace()
        .next()
        .and_then(|p| p.parse::<i64>().ok())
        == Some(0)
    }
    _ => false,
  }
}

// ── %redFormat (Red.pm:22-33) ────────────────────────────────────────────

/// Red.pm:22-33 `%redFormat`. Top-4-bits of the directory tag-ID resolve
/// to the format string.
const fn red_format(idx: u8) -> Option<&'static str> {
  match idx {
    0 => Some("int8u"),
    1 => Some("string"),
    2 => Some("float"),
    3 => Some("int8u"),
    4 => Some("int16u"),
    5 => Some("int8s"),
    6 => Some("int32s"),
    7 => Some("undef"),
    8 => Some("int32u"),
    9 => Some("undef"),
    _ => None,
  }
}

/// Mirror of `convert::format_size` for the Red.pm subset.
fn format_size_of(fmt: &str) -> usize {
  match fmt {
    "int8u" | "int8s" | "string" | "undef" => 1,
    "int16u" => 2,
    "int32u" | "int32s" | "rational32u" | "float" => 4,
    _ => 0,
  }
}

// ===========================================================================
// Typed Meta — `Meta<'a>`
// ===========================================================================

/// Typed R3D metadata — the lib-first output of [`ProcessR3D`].
///
/// Red.pm's `%Main` table has many tags (Red.pm:39-151) that may or may not
/// appear in any given file. Each tag is exposed as an `Option<T>` accessor
/// (D8: no public fields).
///
/// **D8 — no public fields, accessors only.**
///
/// **Composite tags: DEFERRED** per `docs/superpowers/plans/2026-05-20-
/// red-port.md`. Composite tag synthesis is engine-level (Red.pm itself
/// does not register `Composite => ...`), and this port consciously
/// FAITHFULLY DEFERS the Composite layer.
#[derive(Debug, Clone, Default)]
pub struct Meta<'a> {
  /// `RedcodeVersion` from offset 0x07 — single ASCII digit byte.
  redcode_version: Option<u8>,
  /// `ImageWidth` from the RED1/RED2 header subtable.
  image_width: Option<u32>,
  /// `ImageHeight` from the RED1/RED2 header subtable.
  image_height: Option<u32>,
  /// `FrameRate` — RED1 rational32u or RED2 int16u[3] post-ValueConv.
  frame_rate: Option<FrameRate>,
  /// `OriginalFileName` from RED1 header (`string[32]` at 0x43).
  red1_original_file_name: Option<&'a str>,

  // Format-1 (string) tags from `%Main`.
  start_edge_code: Option<&'a str>,
  start_timecode: Option<&'a str>,
  other_date_1: Option<String>,
  other_date_2: Option<String>,
  other_date_3: Option<String>,
  date_time_original: Option<String>,
  serial_number: Option<&'a str>,
  camera_type: Option<&'a str>,
  reel_number: Option<R3dStrOrInt<'a>>,
  take: Option<&'a str>,
  date_created: Option<String>,
  time_created: Option<String>,
  firmware_version: Option<&'a str>,
  reel_timecode: Option<&'a str>,
  storage_type: Option<&'a str>,
  storage_format_date: Option<String>,
  storage_format_time: Option<String>,
  storage_serial_number: Option<&'a str>,
  storage_model: Option<&'a str>,
  aspect_ratio: Option<&'a str>,
  revision: Option<&'a str>,
  original_file_name: Option<&'a str>,
  lens_make: Option<&'a str>,
  lens_number: Option<&'a str>,
  lens_model: Option<&'a str>,
  model: Option<&'a str>,
  camera_operator: Option<&'a str>,
  video_format: Option<&'a str>,
  filter: Option<&'a str>,
  brain: Option<&'a str>,
  sensor: Option<&'a str>,
  quality: Option<&'a str>,

  // Format-2 (float) tags.
  color_temperature: Option<Value<'a>>,
  rgb_curves: Option<Value<'a>>,
  original_frame_rate: Option<Value<'a>>,

  // Format-4 (int16u) tags.
  crop_area: Option<Value<'a>>,
  iso: Option<Value<'a>>,
  f_number: Option<f64>,
  focal_length: Option<Value<'a>>,

  // Format-6 (int32s) tags.
  focus_distance: Option<f64>,

  /// Warnings to emit (all reachable warnings in Red.pm are static).
  warnings: Vec<&'static str>,

  /// Order in which directory tags appeared in the binary (Red.pm:
  /// 277-291). Faithful: directory tags emit in walk order, not `%Main`
  /// hash order.
  directory_tag_order: Vec<DirectoryTag>,
}

/// One value extracted via [`read_value`] from a directory entry.
/// `#[non_exhaustive]`: a new typed value kind can be added without a
/// breaking change for downstream matchers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Value<'a> {
  /// `int8u` / `int16u` / `int32u` count==1 typed scalar.
  I64(i64),
  /// `float` count==1 typed scalar.
  F64(f64),
  /// `string` / `undef` / count>1 space-joined.
  Str(R3dStrCow<'a>),
  /// Raw bytes.
  Bytes(Vec<u8>),
  /// Rational32u.
  Rational(Rational),
}

impl<'a> Value<'a> {
  /// True iff this is an [`Value::I64`].
  #[must_use]
  #[inline(always)]
  pub const fn is_i64(&self) -> bool {
    matches!(self, Value::I64(_))
  }
  /// True iff this is an [`Value::F64`].
  #[must_use]
  #[inline(always)]
  pub const fn is_f64(&self) -> bool {
    matches!(self, Value::F64(_))
  }
  /// True iff this is an [`Value::Str`].
  #[must_use]
  #[inline(always)]
  pub const fn is_str(&self) -> bool {
    matches!(self, Value::Str(_))
  }
  /// True iff this is an [`Value::Bytes`].
  #[must_use]
  #[inline(always)]
  pub const fn is_bytes(&self) -> bool {
    matches!(self, Value::Bytes(_))
  }
  /// True iff this is an [`Value::Rational`].
  #[must_use]
  #[inline(always)]
  pub const fn is_rational(&self) -> bool {
    matches!(self, Value::Rational(_))
  }

  /// The integer payload of an [`Value::I64`], else `None`.
  #[must_use]
  #[inline(always)]
  pub const fn try_unwrap_i64(&self) -> Option<i64> {
    match self {
      Value::I64(n) => Some(*n),
      _ => None,
    }
  }
  /// The float payload of an [`Value::F64`], else `None`.
  #[must_use]
  #[inline(always)]
  pub const fn try_unwrap_f64(&self) -> Option<f64> {
    match self {
      Value::F64(f) => Some(*f),
      _ => None,
    }
  }
  /// The string payload of an [`Value::Str`] (borrow), else `None`.
  #[must_use]
  #[inline(always)]
  pub const fn try_unwrap_str(&self) -> Option<&R3dStrCow<'a>> {
    match self {
      Value::Str(s) => Some(s),
      _ => None,
    }
  }
  /// The byte payload of an [`Value::Bytes`], else `None`.
  #[must_use]
  #[inline(always)]
  pub fn try_unwrap_bytes(&self) -> Option<&[u8]> {
    match self {
      Value::Bytes(b) => Some(b.as_slice()),
      _ => None,
    }
  }
  /// The rational payload of an [`Value::Rational`], else `None`.
  #[must_use]
  #[inline(always)]
  pub const fn try_unwrap_rational(&self) -> Option<Rational> {
    match self {
      Value::Rational(r) => Some(*r),
      _ => None,
    }
  }
}

/// Borrowed-or-owned `&str` carry. Distinct from `std::borrow::Cow` to
/// avoid the cross-feature `alloc::borrow` dance. `#[non_exhaustive]`:
/// stays open for a future carry kind without breaking downstream matchers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum R3dStrCow<'a> {
  /// Borrowed from input.
  Borrowed(&'a str),
  /// Owned (e.g. space-joined `read_value` result).
  Owned(String),
}

impl<'a> R3dStrCow<'a> {
  /// Returns the underlying `&str` (the canonical string view).
  #[must_use]
  #[inline(always)]
  pub fn as_str(&self) -> &str {
    match self {
      R3dStrCow::Borrowed(s) => s,
      R3dStrCow::Owned(s) => s.as_str(),
    }
  }

  /// True iff this is an [`R3dStrCow::Borrowed`].
  #[must_use]
  #[inline(always)]
  pub const fn is_borrowed(&self) -> bool {
    matches!(self, R3dStrCow::Borrowed(_))
  }
  /// True iff this is an [`R3dStrCow::Owned`].
  #[must_use]
  #[inline(always)]
  pub const fn is_owned(&self) -> bool {
    matches!(self, R3dStrCow::Owned(_))
  }

  /// The input-borrowed slice of an [`R3dStrCow::Borrowed`], else `None`.
  #[must_use]
  #[inline(always)]
  pub const fn try_unwrap_borrowed(&self) -> Option<&'a str> {
    match self {
      R3dStrCow::Borrowed(s) => Some(s),
      _ => None,
    }
  }
  /// The owned string of an [`R3dStrCow::Owned`] (borrow), else `None`.
  #[must_use]
  #[inline(always)]
  pub fn try_unwrap_owned(&self) -> Option<&str> {
    match self {
      R3dStrCow::Owned(s) => Some(s.as_str()),
      _ => None,
    }
  }
}

/// `ReelNumber` typed carry (string or coerced integer).
/// `#[non_exhaustive]`: kept open for a future carry kind.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum R3dStrOrInt<'a> {
  /// Borrowed string slice.
  Str(&'a str),
  /// Typed integer.
  I64(i64),
}

impl<'a> R3dStrOrInt<'a> {
  /// True iff this is an [`R3dStrOrInt::Str`].
  #[must_use]
  #[inline(always)]
  pub const fn is_str(&self) -> bool {
    matches!(self, R3dStrOrInt::Str(_))
  }
  /// True iff this is an [`R3dStrOrInt::I64`].
  #[must_use]
  #[inline(always)]
  pub const fn is_i64(&self) -> bool {
    matches!(self, R3dStrOrInt::I64(_))
  }

  /// The input-borrowed slice of an [`R3dStrOrInt::Str`], else `None`.
  #[must_use]
  #[inline(always)]
  pub const fn try_unwrap_str(&self) -> Option<&'a str> {
    match self {
      R3dStrOrInt::Str(s) => Some(s),
      _ => None,
    }
  }
  /// The integer payload of an [`R3dStrOrInt::I64`], else `None`.
  #[must_use]
  #[inline(always)]
  pub const fn try_unwrap_i64(&self) -> Option<i64> {
    match self {
      R3dStrOrInt::I64(n) => Some(*n),
      _ => None,
    }
  }
}

/// `FrameRate` in the typed Meta. `#[non_exhaustive]`: kept open for a
/// future frame-rate representation without a breaking change.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum FrameRate {
  /// RED1 `rational32u` at 0x3e.
  Rational(Rational),
  /// RED2 post-ValueConv F64.
  F64(f64),
}

impl FrameRate {
  /// True iff this is a [`FrameRate::Rational`] (RED1 `rational32u`).
  #[must_use]
  #[inline(always)]
  pub const fn is_rational(&self) -> bool {
    matches!(self, FrameRate::Rational(_))
  }
  /// True iff this is a [`FrameRate::F64`] (RED2 post-ValueConv).
  #[must_use]
  #[inline(always)]
  pub const fn is_f64(&self) -> bool {
    matches!(self, FrameRate::F64(_))
  }

  /// The rational payload of a [`FrameRate::Rational`], else `None`.
  #[must_use]
  #[inline(always)]
  pub const fn try_unwrap_rational(&self) -> Option<Rational> {
    match self {
      FrameRate::Rational(r) => Some(*r),
      _ => None,
    }
  }
  /// The float payload of a [`FrameRate::F64`], else `None`.
  #[must_use]
  #[inline(always)]
  pub const fn try_unwrap_f64(&self) -> Option<f64> {
    match self {
      FrameRate::F64(f) => Some(*f),
      _ => None,
    }
  }
}

/// Directory tag identifier — used for emission ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryTag(u16);

impl DirectoryTag {
  /// Construct from the 16-bit Red `%Main` tag ID.
  #[must_use]
  #[inline(always)]
  pub const fn new(id: u16) -> Self {
    Self(id)
  }
  /// The 16-bit Red `%Main` tag ID.
  #[must_use]
  #[inline(always)]
  pub const fn id(self) -> u16 {
    self.0
  }
}

impl<'a> Meta<'a> {
  /// `RedcodeVersion` — ASCII digit byte (`b'1'` or `b'2'`).
  #[must_use]
  #[inline(always)]
  pub const fn redcode_version(&self) -> Option<u8> {
    self.redcode_version
  }
  /// `RedcodeVersion` as a `&'static str` ("1"/"2").
  #[must_use]
  #[inline(always)]
  pub const fn redcode_version_str(&self) -> Option<&'static str> {
    match self.redcode_version {
      Some(b'1') => Some("1"),
      Some(b'2') => Some("2"),
      _ => None,
    }
  }
  /// `ImageWidth` from header subtable.
  #[must_use]
  #[inline(always)]
  pub const fn image_width(&self) -> Option<u32> {
    self.image_width
  }
  /// `ImageHeight` from header subtable.
  #[must_use]
  #[inline(always)]
  pub const fn image_height(&self) -> Option<u32> {
    self.image_height
  }
  /// `FrameRate` (borrow of the non-`Copy` [`FrameRate`]).
  #[must_use]
  #[inline(always)]
  pub const fn frame_rate_ref(&self) -> Option<&FrameRate> {
    self.frame_rate.as_ref()
  }
  /// RED1 header `OriginalFileName`.
  #[must_use]
  #[inline(always)]
  pub const fn red1_original_file_name(&self) -> Option<&'a str> {
    self.red1_original_file_name
  }
  /// `StartEdgeCode` (0x1000).
  #[must_use]
  #[inline(always)]
  pub const fn start_edge_code(&self) -> Option<&'a str> {
    self.start_edge_code
  }
  /// `StartTimecode` (0x1001).
  #[must_use]
  #[inline(always)]
  pub const fn start_timecode(&self) -> Option<&'a str> {
    self.start_timecode
  }
  /// `OtherDate1` (0x1002).
  #[must_use]
  #[inline(always)]
  pub fn other_date_1(&self) -> Option<&str> {
    self.other_date_1.as_deref()
  }
  /// `OtherDate2` (0x1003).
  #[must_use]
  #[inline(always)]
  pub fn other_date_2(&self) -> Option<&str> {
    self.other_date_2.as_deref()
  }
  /// `OtherDate3` (0x1004).
  #[must_use]
  #[inline(always)]
  pub fn other_date_3(&self) -> Option<&str> {
    self.other_date_3.as_deref()
  }
  /// `DateTimeOriginal` (0x1005).
  #[must_use]
  #[inline(always)]
  pub fn date_time_original(&self) -> Option<&str> {
    self.date_time_original.as_deref()
  }
  /// `SerialNumber` (0x1006).
  #[must_use]
  #[inline(always)]
  pub const fn serial_number(&self) -> Option<&'a str> {
    self.serial_number
  }
  /// `CameraType` (0x1019).
  #[must_use]
  #[inline(always)]
  pub const fn camera_type(&self) -> Option<&'a str> {
    self.camera_type
  }
  /// `ReelNumber` (0x101a) — borrow of the non-`Copy` [`R3dStrOrInt`].
  #[must_use]
  #[inline(always)]
  pub const fn reel_number_ref(&self) -> Option<&R3dStrOrInt<'a>> {
    self.reel_number.as_ref()
  }
  /// `Take` (0x101b).
  #[must_use]
  #[inline(always)]
  pub const fn take(&self) -> Option<&'a str> {
    self.take
  }
  /// `DateCreated` (0x1023).
  #[must_use]
  #[inline(always)]
  pub fn date_created(&self) -> Option<&str> {
    self.date_created.as_deref()
  }
  /// `TimeCreated` (0x1024).
  #[must_use]
  #[inline(always)]
  pub fn time_created(&self) -> Option<&str> {
    self.time_created.as_deref()
  }
  /// `FirmwareVersion` (0x1025).
  #[must_use]
  #[inline(always)]
  pub const fn firmware_version(&self) -> Option<&'a str> {
    self.firmware_version
  }
  /// `ReelTimecode` (0x1029).
  #[must_use]
  #[inline(always)]
  pub const fn reel_timecode(&self) -> Option<&'a str> {
    self.reel_timecode
  }
  /// `StorageType` (0x102a).
  #[must_use]
  #[inline(always)]
  pub const fn storage_type(&self) -> Option<&'a str> {
    self.storage_type
  }
  /// `StorageFormatDate` (0x1030).
  #[must_use]
  #[inline(always)]
  pub fn storage_format_date(&self) -> Option<&str> {
    self.storage_format_date.as_deref()
  }
  /// `StorageFormatTime` (0x1031).
  #[must_use]
  #[inline(always)]
  pub fn storage_format_time(&self) -> Option<&str> {
    self.storage_format_time.as_deref()
  }
  /// `StorageSerialNumber` (0x1032).
  #[must_use]
  #[inline(always)]
  pub const fn storage_serial_number(&self) -> Option<&'a str> {
    self.storage_serial_number
  }
  /// `StorageModel` (0x1033).
  #[must_use]
  #[inline(always)]
  pub const fn storage_model(&self) -> Option<&'a str> {
    self.storage_model
  }
  /// `AspectRatio` (0x1036).
  #[must_use]
  #[inline(always)]
  pub const fn aspect_ratio(&self) -> Option<&'a str> {
    self.aspect_ratio
  }
  /// `Revision` (0x1042).
  #[must_use]
  #[inline(always)]
  pub const fn revision(&self) -> Option<&'a str> {
    self.revision
  }
  /// `OriginalFileName` (0x1056) — directory tag.
  #[must_use]
  #[inline(always)]
  pub const fn original_file_name(&self) -> Option<&'a str> {
    self.original_file_name
  }
  /// `LensMake` (0x106e).
  #[must_use]
  #[inline(always)]
  pub const fn lens_make(&self) -> Option<&'a str> {
    self.lens_make
  }
  /// `LensNumber` (0x106f).
  #[must_use]
  #[inline(always)]
  pub const fn lens_number(&self) -> Option<&'a str> {
    self.lens_number
  }
  /// `LensModel` (0x1070).
  #[must_use]
  #[inline(always)]
  pub const fn lens_model(&self) -> Option<&'a str> {
    self.lens_model
  }
  /// `Model` (0x1071).
  #[must_use]
  #[inline(always)]
  pub const fn model(&self) -> Option<&'a str> {
    self.model
  }
  /// `CameraOperator` (0x107c).
  #[must_use]
  #[inline(always)]
  pub const fn camera_operator(&self) -> Option<&'a str> {
    self.camera_operator
  }
  /// `VideoFormat` (0x1086).
  #[must_use]
  #[inline(always)]
  pub const fn video_format(&self) -> Option<&'a str> {
    self.video_format
  }
  /// `Filter` (0x1096).
  #[must_use]
  #[inline(always)]
  pub const fn filter(&self) -> Option<&'a str> {
    self.filter
  }
  /// `Brain` (0x10a0).
  #[must_use]
  #[inline(always)]
  pub const fn brain(&self) -> Option<&'a str> {
    self.brain
  }
  /// `Sensor` (0x10a1).
  #[must_use]
  #[inline(always)]
  pub const fn sensor(&self) -> Option<&'a str> {
    self.sensor
  }
  /// `Quality` (0x10be).
  #[must_use]
  #[inline(always)]
  pub const fn quality(&self) -> Option<&'a str> {
    self.quality
  }
  /// `ColorTemperature` (0x200d) — borrow of the non-`Copy` [`Value`].
  #[must_use]
  #[inline(always)]
  pub const fn color_temperature_ref(&self) -> Option<&Value<'a>> {
    self.color_temperature.as_ref()
  }
  /// `RGBCurves` (0x204b) — borrow of the non-`Copy` [`Value`].
  #[must_use]
  #[inline(always)]
  pub const fn rgb_curves_ref(&self) -> Option<&Value<'a>> {
    self.rgb_curves.as_ref()
  }
  /// `OriginalFrameRate` (0x2066) — borrow of the non-`Copy` [`Value`].
  #[must_use]
  #[inline(always)]
  pub const fn original_frame_rate_ref(&self) -> Option<&Value<'a>> {
    self.original_frame_rate.as_ref()
  }
  /// `CropArea` (0x4037) — borrow of the non-`Copy` [`Value`].
  #[must_use]
  #[inline(always)]
  pub const fn crop_area_ref(&self) -> Option<&Value<'a>> {
    self.crop_area.as_ref()
  }
  /// `ISO` (0x403b) — borrow of the non-`Copy` [`Value`].
  #[must_use]
  #[inline(always)]
  pub const fn iso_ref(&self) -> Option<&Value<'a>> {
    self.iso.as_ref()
  }
  /// `FNumber` (0x406a) post-ValueConv.
  #[must_use]
  #[inline(always)]
  pub const fn f_number(&self) -> Option<f64> {
    self.f_number
  }
  /// `FocalLength` (0x406b) — borrow of the non-`Copy` [`Value`].
  #[must_use]
  #[inline(always)]
  pub const fn focal_length_ref(&self) -> Option<&Value<'a>> {
    self.focal_length.as_ref()
  }
  /// `FocusDistance` (0x606c) post-ValueConv.
  #[must_use]
  #[inline(always)]
  pub const fn focus_distance(&self) -> Option<f64> {
    self.focus_distance
  }
  /// Warnings emitted during parsing, in emission order.
  #[must_use]
  #[inline(always)]
  pub fn warnings(&self) -> &[&'static str] {
    self.warnings.as_slice()
  }
  /// Order in which directory tags appeared in the binary.
  #[must_use]
  #[inline(always)]
  pub fn directory_tag_order(&self) -> &[DirectoryTag] {
    self.directory_tag_order.as_slice()
  }
}

// ===========================================================================
// `ProcessR3D` — the lib-first parser
// ===========================================================================

/// `Image::ExifTool::Red::ProcessR3D` (Red.pm:212-295). Faithful read-only
/// port.
#[derive(Debug, Clone, Copy)]
pub struct ProcessR3D;

impl parser_sealed::Sealed for ProcessR3D {}

impl FormatParser for ProcessR3D {
  /// GAT: the Meta borrows from the input `'a` (Codex AF2).
  type Meta<'a> = Meta<'a>;
  /// Spec §8: leaf format Context is `&'a [u8]`.
  type Context<'a> = &'a [u8];
  type Error = Error;

  fn parse<'a>(&self, data: Self::Context<'a>) -> Result<Option<Self::Meta<'a>>, Error> {
    Ok(parse_inner(data))
  }
}

/// Lib-first direct entry. Returns an [`Meta`] that borrows from the
/// input buffer (zero-alloc for `&'a str` fields).
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today).
pub fn parse_borrowed(data: &[u8]) -> Result<Option<Meta<'_>>, Error> {
  Ok(parse_inner(data))
}

fn parse_inner<'a>(data: &'a [u8]) -> Option<Meta<'a>> {
  // Red.pm:225 magic.
  if data.len() < 8 {
    return None;
  }
  if data[0] != 0 || data[1] != 0 {
    return None;
  }
  if &data[4..7] != b"RED" {
    return None;
  }
  let ver: u8 = match data[7] {
    b'1' => 1,
    b'2' => 2,
    _ => return None,
  };
  // Red.pm:227 size.
  let size = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
  // Red.pm:228.
  if size < 8 {
    return None;
  }

  let mut meta = Meta::default();

  // Red.pm:236 — `$raf->Read($buf2, $size-8) == $size-8 or return
  // $et->Warn($errTrunc)`. Short-circuits Red.pm:240 HandleTag, so no
  // RedcodeVersion etc. is emitted for this truncated shape.
  if data.len() < size {
    meta.warnings.push("Truncated R3D file");
    return Some(meta);
  }

  // Red.pm:240 HandleTag("RED$ver", ...) — header subtable extraction.
  if ver == 1 {
    extract_red1_header(&mut meta, data, size);
  } else {
    extract_red2_header(&mut meta, data, size);
  }

  // Red.pm:244-256: compute directory slice (`buff`) and start position.
  // Slice into `data` directly so resulting `&'a str` payloads borrow
  // from the original input.
  let (buff, mut pos): (&'a [u8], usize) = if ver == 1 {
    // Red.pm:246.
    if data.len() <= size {
      meta.warnings.push("Truncated R3D file");
      return Some(meta);
    }
    let take = (data.len() - size).min(0x10000);
    (&data[size..size + take], 0x22usize)
  } else {
    // Red.pm:251-252.
    if size < 0x44 {
      meta.warnings.push("Truncated R3D file");
      return Some(meta);
    }
    let first_block = &data[..size];
    let rdi = first_block[0x40] as usize;
    let rda = first_block[0x41] as usize;
    let rdx = first_block[0x42] as usize;
    let p = 0x44usize + 0x18 * rdi + 0x14 * rda + 0x10 * rdx;
    (first_block, p)
  };

  // Red.pm:257-273.
  let dir_len: Option<usize>;
  let dir_end: usize;
  if pos + 8 > buff.len() {
    match scan_for_red_directory(buff) {
      Some(p) => {
        pos = p;
        dir_end = buff.len();
        dir_len = None;
        meta
          .warnings
          .push("This R3D file is different. Please submit a sample for testing");
      }
      None => {
        meta
          .warnings
          .push("Can't find Red directory. Please submit sample for testing");
        return Some(meta);
      }
    }
  } else {
    let len = u16::from_be_bytes([buff[pos], buff[pos + 1]]) as usize;
    pos += 2;
    if !(300..2048).contains(&len) || pos + len > buff.len() {
      match scan_for_red_directory(buff) {
        Some(p) => {
          pos = p;
          dir_end = buff.len();
          dir_len = None;
          meta
            .warnings
            .push("This R3D file is different. Please submit a sample for testing");
        }
        None => {
          meta
            .warnings
            .push("Can't find Red directory. Please submit sample for testing");
          return Some(meta);
        }
      }
    } else {
      dir_len = Some(len);
      dir_end = pos + len;
    }
  }

  walk_red_directory(&mut meta, buff, pos, dir_end, dir_len);

  Some(meta)
}

/// Red.pm:266 fallback regex: `$buff =~ /\0\x0f\x10[\0\x06]/g`.
fn scan_for_red_directory(buf: &[u8]) -> Option<usize> {
  (0..buf.len().saturating_sub(3)).find(|&i| {
    buf[i] == 0x00
      && buf[i + 1] == 0x0f
      && buf[i + 2] == 0x10
      && (buf[i + 3] == 0x00 || buf[i + 3] == 0x06)
  })
}

/// RED1 header subtable read (Red.pm:154-172).
fn extract_red1_header<'a>(meta: &mut Meta<'a>, data: &'a [u8], size: usize) {
  let cap = size.min(data.len());
  let buf = &data[..cap];

  if let Some(TagValue::Str(s)) = read_value(buf, 0x07, "string", 1, ByteOrder::Mm) {
    if let Some(b) = s.as_bytes().first() {
      meta.redcode_version = Some(*b);
    }
  }
  if let Some(TagValue::I64(n)) = read_value(buf, 0x36, "int16u", 1, ByteOrder::Mm) {
    meta.image_width = Some(n.clamp(0, i64::from(u32::MAX)) as u32);
  }
  if let Some(TagValue::I64(n)) = read_value(buf, 0x3a, "int16u", 1, ByteOrder::Mm) {
    meta.image_height = Some(n.clamp(0, i64::from(u32::MAX)) as u32);
  }
  if let Some(v) = read_value(buf, 0x3e, "rational32u", 1, ByteOrder::Mm) {
    if let TagValue::Rational(r) = v {
      meta.frame_rate = Some(FrameRate::Rational(r));
    }
  }
  meta.red1_original_file_name = borrowed_string(data, 0x43, 32);
}

/// RED2 header subtable read (Red.pm:175-206).
fn extract_red2_header<'a>(meta: &mut Meta<'a>, data: &'a [u8], size: usize) {
  let cap = size.min(data.len());
  let buf = &data[..cap];

  if let Some(TagValue::Str(s)) = read_value(buf, 0x07, "string", 1, ByteOrder::Mm) {
    if let Some(b) = s.as_bytes().first() {
      meta.redcode_version = Some(*b);
    }
  }
  if let Some(TagValue::I64(n)) = read_value(buf, 0x4c, "int32u", 1, ByteOrder::Mm) {
    meta.image_width = Some(n.clamp(0, i64::from(u32::MAX)) as u32);
  }
  if let Some(TagValue::I64(n)) = read_value(buf, 0x50, "int32u", 1, ByteOrder::Mm) {
    meta.image_height = Some(n.clamp(0, i64::from(u32::MAX)) as u32);
  }
  if let Some(raw) = read_value(buf, 0x56, "int16u", 3, ByteOrder::Mm) {
    if !red2_frame_rate_first_word_is_zero(&raw) {
      if let Some(v) = red2_frame_rate_value_conv(&raw) {
        meta.frame_rate = Some(FrameRate::F64(v));
      }
    }
  }
}

/// Read a NUL-trimmed `string[N]` slice borrowed from `data`.
fn borrowed_string(data: &[u8], offset: usize, max_len: usize) -> Option<&str> {
  let end = (offset + max_len).min(data.len());
  if offset >= end {
    return None;
  }
  let slice = &data[offset..end];
  let trimmed_len = slice.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
  if trimmed_len == 0 {
    return None;
  }
  core::str::from_utf8(&slice[..trimmed_len]).ok()
}

/// Red.pm:277-291 directory walk.
fn walk_red_directory<'a>(
  meta: &mut Meta<'a>,
  buff: &'a [u8],
  mut pos: usize,
  dir_end: usize,
  dir_len: Option<usize>,
) {
  let dir_len_truthy = dir_len.is_some();
  while pos + 4 <= dir_end {
    let len = u16::from_be_bytes([buff[pos], buff[pos + 1]]) as usize;
    if len < 4 || pos + len > dir_end {
      break;
    }
    let tag = u16::from_be_bytes([buff[pos + 2], buff[pos + 3]]);
    let fmt_idx = (tag >> 12) as u8;
    let fmt = match red_format(fmt_idx) {
      Some(f) => f,
      None => {
        if dir_len_truthy {
          meta.warnings.push("Unknown format code");
        }
        break;
      }
    };
    let payload_off = pos + 4;
    let payload_size = len - 4;
    let elem = format_size_of(fmt);
    if elem > 0 && payload_size > 0 {
      let count = payload_size / elem;
      if count > 0 {
        if let Some(v) = read_value(buff, payload_off, fmt, count, ByteOrder::Mm) {
          dispatch_directory_tag(meta, tag, v, buff, payload_off, payload_size);
        }
      }
    } else if fmt == "string" || fmt == "undef" {
      if let Some(v) = read_value(buff, payload_off, fmt, payload_size, ByteOrder::Mm) {
        dispatch_directory_tag(meta, tag, v, buff, payload_off, payload_size);
      }
    }
    pos += len;
  }
}

/// Route a directory entry's `read_value` result into the matching
/// [`Meta`] field. For string-typed fields we additionally pull a
/// borrowed slice from the input buffer (zero-alloc).
fn dispatch_directory_tag<'a>(
  meta: &mut Meta<'a>,
  tag: u16,
  v: TagValue,
  buff: &'a [u8],
  payload_off: usize,
  payload_size: usize,
) {
  let borrowed = |off: usize, len: usize| -> Option<&'a str> {
    let end = (off + len).min(buff.len());
    if off >= end {
      return None;
    }
    let slice = &buff[off..end];
    let trimmed = slice.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    if trimmed == 0 {
      return None;
    }
    core::str::from_utf8(&slice[..trimmed]).ok()
  };

  let to_value = |v: TagValue| -> Value<'a> {
    match v {
      TagValue::I64(n) => Value::I64(n),
      // RED tags never emit a u64 today (read_value yields I64/Rational/Str);
      // keep the lossy-on-overflow `as i64` only as an exhaustiveness arm —
      // the JSON output path never routes a R3D tag through it.
      TagValue::U64(n) => Value::I64(n as i64),
      TagValue::F64(n) => Value::F64(n),
      TagValue::Str(s) => Value::Str(R3dStrCow::Owned(s.to_string())),
      TagValue::Bytes(b) => Value::Bytes(b),
      TagValue::Rational(r) => Value::Rational(r),
      TagValue::Bool(b) => Value::I64(i64::from(b)),
      TagValue::List(_) | TagValue::Map(_) => Value::Str(R3dStrCow::Owned(String::new())),
    }
  };

  let dir_tag = DirectoryTag::new(tag);
  match tag {
    0x1000 => {
      meta.start_edge_code = borrowed(payload_off, payload_size);
      if meta.start_edge_code.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x1001 => {
      meta.start_timecode = borrowed(payload_off, payload_size);
      if meta.start_timecode.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x1002 => {
      if let TagValue::Str(s) = v {
        meta.other_date_1 = Some(other_date_value_conv(s.as_str()));
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x1003 => {
      if let TagValue::Str(s) = v {
        meta.other_date_2 = Some(other_date_value_conv(s.as_str()));
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x1004 => {
      if let TagValue::Str(s) = v {
        meta.other_date_3 = Some(other_date_value_conv(s.as_str()));
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x1005 => {
      if let TagValue::Str(s) = v {
        meta.date_time_original = Some(datetime_original_value_conv(s.as_str()));
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x1006 => {
      meta.serial_number = borrowed(payload_off, payload_size);
      if meta.serial_number.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x1019 => {
      meta.camera_type = borrowed(payload_off, payload_size);
      if meta.camera_type.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x101a => match v {
      TagValue::Str(_) => {
        if let Some(slice) = borrowed(payload_off, payload_size) {
          meta.reel_number = Some(R3dStrOrInt::Str(slice));
          meta.directory_tag_order.push(dir_tag);
        }
      }
      TagValue::I64(n) => {
        meta.reel_number = Some(R3dStrOrInt::I64(n));
        meta.directory_tag_order.push(dir_tag);
      }
      _ => {}
    },
    0x101b => {
      meta.take = borrowed(payload_off, payload_size);
      if meta.take.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x1023 => {
      if let TagValue::Str(s) = v {
        meta.date_created = Some(date_created_value_conv(s.as_str()));
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x1024 => {
      if let TagValue::Str(s) = v {
        meta.time_created = Some(time_created_value_conv(s.as_str()));
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x1025 => {
      meta.firmware_version = borrowed(payload_off, payload_size);
      if meta.firmware_version.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x1029 => {
      meta.reel_timecode = borrowed(payload_off, payload_size);
      if meta.reel_timecode.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x102a => {
      meta.storage_type = borrowed(payload_off, payload_size);
      if meta.storage_type.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x1030 => {
      if let TagValue::Str(s) = v {
        meta.storage_format_date = Some(date_created_value_conv(s.as_str()));
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x1031 => {
      if let TagValue::Str(s) = v {
        meta.storage_format_time = Some(time_created_value_conv(s.as_str()));
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x1032 => {
      meta.storage_serial_number = borrowed(payload_off, payload_size);
      if meta.storage_serial_number.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x1033 => {
      meta.storage_model = borrowed(payload_off, payload_size);
      if meta.storage_model.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x1036 => {
      meta.aspect_ratio = borrowed(payload_off, payload_size);
      if meta.aspect_ratio.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x1042 => {
      meta.revision = borrowed(payload_off, payload_size);
      if meta.revision.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x1056 => {
      meta.original_file_name = borrowed(payload_off, payload_size);
      if meta.original_file_name.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x106e => {
      meta.lens_make = borrowed(payload_off, payload_size);
      if meta.lens_make.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x106f => {
      meta.lens_number = borrowed(payload_off, payload_size);
      if meta.lens_number.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x1070 => {
      meta.lens_model = borrowed(payload_off, payload_size);
      if meta.lens_model.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x1071 => {
      meta.model = borrowed(payload_off, payload_size);
      if meta.model.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x107c => {
      meta.camera_operator = borrowed(payload_off, payload_size);
      if meta.camera_operator.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x1086 => {
      meta.video_format = borrowed(payload_off, payload_size);
      if meta.video_format.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x1096 => {
      meta.filter = borrowed(payload_off, payload_size);
      if meta.filter.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x10a0 => {
      meta.brain = borrowed(payload_off, payload_size);
      if meta.brain.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x10a1 => {
      meta.sensor = borrowed(payload_off, payload_size);
      if meta.sensor.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }
    0x10be => {
      meta.quality = borrowed(payload_off, payload_size);
      if meta.quality.is_some() {
        meta.directory_tag_order.push(dir_tag);
      }
    }

    0x200d => {
      meta.color_temperature = Some(to_value(v));
      meta.directory_tag_order.push(dir_tag);
    }
    0x204b => {
      meta.rgb_curves = Some(to_value(v));
      meta.directory_tag_order.push(dir_tag);
    }
    0x2066 => {
      meta.original_frame_rate = Some(to_value(v));
      meta.directory_tag_order.push(dir_tag);
    }

    0x4037 => {
      meta.crop_area = Some(to_value(v));
      meta.directory_tag_order.push(dir_tag);
    }
    0x403b => {
      meta.iso = Some(to_value(v));
      meta.directory_tag_order.push(dir_tag);
    }
    0x406a => {
      meta.f_number = Some(divide_by_10(&v));
      meta.directory_tag_order.push(dir_tag);
    }
    0x406b => {
      meta.focal_length = Some(to_value(v));
      meta.directory_tag_order.push(dir_tag);
    }

    0x606c => {
      meta.focus_distance = Some(divide_by_1000(&v));
      meta.directory_tag_order.push(dir_tag);
    }

    _ => {
      // Unknown tag — faithfully drop.
    }
  }
}

// ===========================================================================
// `serialize_tags` — typed Meta → TagMap
// ===========================================================================

const GROUP: &str = "Red";

#[cfg(feature = "alloc")]
impl Meta<'_> {
  /// Emit R3D tags into the writer in faithful Red.pm emission order:
  ///
  /// 1. RED1/RED2 header subtable fields (Red.pm:240 HandleTag).
  /// 2. Directory tags in walk order (Red.pm:277-291).
  /// 3. Warnings via `TagMap::write_warning`.
  ///
  /// `print_conv=true` ⇒ PrintConv formatted strings (`-j`);
  /// `print_conv=false` ⇒ post-ValueConv raw scalars (`-n`).
  pub(crate) fn serialize_tags(
    &self,
    print_conv: bool,
    out: &mut crate::tagmap::TagMap,
  ) -> Result<(), core::convert::Infallible> {
    // 1. Header subtable fields.
    if let Some(v) = self.redcode_version_str() {
      // RedcodeVersion is an ASCII digit string; ExifTool's JSON emitter
      // numerically-coerces such strings under -j and -n.
      let n: u64 = v.parse().unwrap_or(0);
      out.write_u64(GROUP, "RedcodeVersion", n)?;
    }
    if let Some(w) = self.image_width {
      out.write_u64(GROUP, "ImageWidth", u64::from(w))?;
    }
    if let Some(h) = self.image_height {
      out.write_u64(GROUP, "ImageHeight", u64::from(h))?;
    }
    if let Some(fr) = &self.frame_rate {
      // Red.pm:169/202 PrintConv `int($val*1000+0.5)/1000`.
      let pre_pc: TagValue = match fr {
        FrameRate::Rational(r) => TagValue::Rational(r.clone()),
        FrameRate::F64(n) => TagValue::F64(*n),
      };
      if print_conv {
        out.write_f64(GROUP, "FrameRate", round_to_3dp(&pre_pc))?;
      } else {
        // -n raw: Rational → `%.7g` text → f64.
        let raw_f = match fr {
          FrameRate::Rational(r) => perl_arithmetic_to_f64(&r.exiftool_val_str()),
          FrameRate::F64(n) => *n,
        };
        out.write_f64(GROUP, "FrameRate", raw_f)?;
      }
    }
    if let Some(n) = self.red1_original_file_name {
      out.write_str(GROUP, "OriginalFileName", n)?;
    }

    // 2. Directory tags in walk order.
    for dt in &self.directory_tag_order {
      self.sink_directory_tag(*dt, print_conv, out)?;
    }

    // 3. Warnings.
    for w in &self.warnings {
      out.write_warning(w)?;
    }
    Ok(())
  }
}

impl Meta<'_> {
  /// Emit a single directory tag.
  fn sink_directory_tag(
    &self,
    dt: DirectoryTag,
    print_conv: bool,
    out: &mut crate::tagmap::TagMap,
  ) -> Result<(), core::convert::Infallible> {
    match dt.id() {
      0x1000 => {
        if let Some(v) = self.start_edge_code {
          out.write_str(GROUP, "StartEdgeCode", v)?;
        }
      }
      0x1001 => {
        if let Some(v) = self.start_timecode {
          out.write_str(GROUP, "StartTimecode", v)?;
        }
      }
      0x1002 => {
        if let Some(v) = self.other_date_1.as_deref() {
          out.write_str(GROUP, "OtherDate1", v)?;
        }
      }
      0x1003 => {
        if let Some(v) = self.other_date_2.as_deref() {
          out.write_str(GROUP, "OtherDate2", v)?;
        }
      }
      0x1004 => {
        if let Some(v) = self.other_date_3.as_deref() {
          out.write_str(GROUP, "OtherDate3", v)?;
        }
      }
      0x1005 => {
        if let Some(v) = self.date_time_original.as_deref() {
          // Red.pm:73 PrintConv `$self->ConvertDateTime($val)` is the
          // identity under default options.
          out.write_str(GROUP, "DateTimeOriginal", v)?;
        }
      }
      0x1006 => {
        if let Some(v) = self.serial_number {
          out.write_str(GROUP, "SerialNumber", v)?;
        }
      }
      0x1019 => {
        if let Some(v) = self.camera_type {
          out.write_str(GROUP, "CameraType", v)?;
        }
      }
      0x101a => {
        if let Some(v) = &self.reel_number {
          // Bundled output: JSON integer when on-disk numeric.
          match v {
            R3dStrOrInt::Str(s) => out.write_str(GROUP, "ReelNumber", s)?,
            R3dStrOrInt::I64(n) => out.write_i64(GROUP, "ReelNumber", *n)?,
          }
        }
      }
      0x101b => {
        if let Some(v) = self.take {
          out.write_str(GROUP, "Take", v)?;
        }
      }
      0x1023 => {
        if let Some(v) = self.date_created.as_deref() {
          out.write_str(GROUP, "DateCreated", v)?;
        }
      }
      0x1024 => {
        if let Some(v) = self.time_created.as_deref() {
          out.write_str(GROUP, "TimeCreated", v)?;
        }
      }
      0x1025 => {
        if let Some(v) = self.firmware_version {
          out.write_str(GROUP, "FirmwareVersion", v)?;
        }
      }
      0x1029 => {
        if let Some(v) = self.reel_timecode {
          out.write_str(GROUP, "ReelTimecode", v)?;
        }
      }
      0x102a => {
        if let Some(v) = self.storage_type {
          out.write_str(GROUP, "StorageType", v)?;
        }
      }
      0x1030 => {
        if let Some(v) = self.storage_format_date.as_deref() {
          out.write_str(GROUP, "StorageFormatDate", v)?;
        }
      }
      0x1031 => {
        if let Some(v) = self.storage_format_time.as_deref() {
          out.write_str(GROUP, "StorageFormatTime", v)?;
        }
      }
      0x1032 => {
        if let Some(v) = self.storage_serial_number {
          out.write_str(GROUP, "StorageSerialNumber", v)?;
        }
      }
      0x1033 => {
        if let Some(v) = self.storage_model {
          out.write_str(GROUP, "StorageModel", v)?;
        }
      }
      0x1036 => {
        if let Some(v) = self.aspect_ratio {
          out.write_str(GROUP, "AspectRatio", v)?;
        }
      }
      0x1042 => {
        if let Some(v) = self.revision {
          out.write_str(GROUP, "Revision", v)?;
        }
      }
      0x1056 => {
        if let Some(v) = self.original_file_name {
          out.write_str(GROUP, "OriginalFileName", v)?;
        }
      }
      0x106e => {
        if let Some(v) = self.lens_make {
          out.write_str(GROUP, "LensMake", v)?;
        }
      }
      0x106f => {
        if let Some(v) = self.lens_number {
          out.write_str(GROUP, "LensNumber", v)?;
        }
      }
      0x1070 => {
        if let Some(v) = self.lens_model {
          out.write_str(GROUP, "LensModel", v)?;
        }
      }
      0x1071 => {
        if let Some(v) = self.model {
          out.write_str(GROUP, "Model", v)?;
        }
      }
      0x107c => {
        if let Some(v) = self.camera_operator {
          out.write_str(GROUP, "CameraOperator", v)?;
        }
      }
      0x1086 => {
        if let Some(v) = self.video_format {
          out.write_str(GROUP, "VideoFormat", v)?;
        }
      }
      0x1096 => {
        if let Some(v) = self.filter {
          out.write_str(GROUP, "Filter", v)?;
        }
      }
      0x10a0 => {
        if let Some(v) = self.brain {
          out.write_str(GROUP, "Brain", v)?;
        }
      }
      0x10a1 => {
        if let Some(v) = self.sensor {
          out.write_str(GROUP, "Sensor", v)?;
        }
      }
      0x10be => {
        if let Some(v) = self.quality {
          out.write_str(GROUP, "Quality", v)?;
        }
      }
      0x200d => {
        if let Some(v) = &self.color_temperature {
          emit_r3d_value(out, "ColorTemperature", v)?;
        }
      }
      0x204b => {
        if let Some(v) = &self.rgb_curves {
          emit_r3d_value(out, "RGBCurves", v)?;
        }
      }
      0x2066 => {
        if let Some(v) = &self.original_frame_rate {
          // Red.pm:131-135 PrintConv `int($val*1000+0.5)/1000`.
          if print_conv {
            let raw: TagValue = match v {
              Value::I64(n) => TagValue::I64(*n),
              Value::F64(n) => TagValue::F64(*n),
              Value::Str(s) => TagValue::Str(s.as_str().into()),
              Value::Bytes(_) => TagValue::I64(0),
              Value::Rational(r) => TagValue::Rational(r.clone()),
            };
            out.write_f64(GROUP, "OriginalFrameRate", round_to_3dp(&raw))?;
          } else {
            emit_r3d_value(out, "OriginalFrameRate", v)?;
          }
        }
      }
      0x4037 => {
        if let Some(v) = &self.crop_area {
          emit_r3d_value(out, "CropArea", v)?;
        }
      }
      0x403b => {
        if let Some(v) = &self.iso {
          emit_r3d_value(out, "ISO", v)?;
        }
      }
      0x406a => {
        if let Some(v) = self.f_number {
          out.write_f64(GROUP, "FNumber", v)?;
        }
      }
      0x406b => {
        if let Some(v) = &self.focal_length {
          emit_r3d_value(out, "FocalLength", v)?;
        }
      }
      0x606c => {
        if let Some(v) = self.focus_distance {
          if print_conv {
            // Red.pm:147 PrintConv `"$val m"`.
            out.write_fmt(GROUP, "FocusDistance", |w| {
              w.write_str(&focus_distance_print_conv(v))
            })?;
          } else {
            out.write_f64(GROUP, "FocusDistance", v)?;
          }
        }
      }
      _ => {}
    }
    Ok(())
  }
}

/// Emit a generic `Value` (no per-tag PrintConv).
#[cfg(feature = "alloc")]
fn emit_r3d_value(
  out: &mut crate::tagmap::TagMap,
  name: &str,
  v: &Value<'_>,
) -> Result<(), core::convert::Infallible> {
  match v {
    Value::I64(n) => out.write_i64(GROUP, name, *n),
    Value::F64(n) => out.write_f64(GROUP, name, *n),
    Value::Str(s) => out.write_str(GROUP, name, s.as_str()),
    Value::Bytes(b) => out.write_bytes(GROUP, name, b),
    Value::Rational(r) => {
      let f = perl_arithmetic_to_f64(&r.exiftool_val_str());
      out.write_f64(GROUP, name, f)
    }
  }
}

// ===========================================================================
// `Error` — Rust-level fatal modes (currently none)
// ===========================================================================

/// Rust-level fatal modes for R3D parsing. Currently empty — every bad
/// input produces `Ok(None)` (Perl `return 0`).
///
/// §5: derived via `thiserror` (v2, `default-features = false` ⇒
/// `core::error::Error`), `#[non_exhaustive]` so variants can be added
/// without a breaking change. Variant names are kept stable for
/// [`crate::format_parser::AnyError`]'s `From`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {}

// ===========================================================================
// Engine entry — typed parse + File:* + sink into `Metadata`
// ===========================================================================

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn red_format_table_matches_pm() {
    assert_eq!(red_format(0), Some("int8u"));
    assert_eq!(red_format(1), Some("string"));
    assert_eq!(red_format(2), Some("float"));
    assert_eq!(red_format(3), Some("int8u"));
    assert_eq!(red_format(4), Some("int16u"));
    assert_eq!(red_format(5), Some("int8s"));
    assert_eq!(red_format(6), Some("int32s"));
    assert_eq!(red_format(7), Some("undef"));
    assert_eq!(red_format(8), Some("int32u"));
    assert_eq!(red_format(9), Some("undef"));
    assert_eq!(red_format(10), None);
    assert_eq!(red_format(15), None);
  }

  #[test]
  fn frame_rate_predicates_and_unwrap_accessors() {
    let r = FrameRate::Rational(Rational::rational32(24000, 1001));
    assert!(r.is_rational() && !r.is_f64());
    assert_eq!(
      r.try_unwrap_rational(),
      Some(Rational::rational32(24000, 1001))
    );
    assert_eq!(r.try_unwrap_f64(), None);

    let f = FrameRate::F64(25.0);
    assert!(f.is_f64() && !f.is_rational());
    assert_eq!(f.try_unwrap_f64(), Some(25.0));
    assert_eq!(f.try_unwrap_rational(), None);
  }

  #[test]
  fn r3d_value_predicates_and_unwrap_accessors() {
    let i = Value::I64(3);
    assert!(i.is_i64());
    assert_eq!(i.try_unwrap_i64(), Some(3));
    assert_eq!(i.try_unwrap_f64(), None);

    let s = Value::Str(R3dStrCow::Borrowed("xy"));
    assert!(s.is_str());
    assert_eq!(s.try_unwrap_str().map(R3dStrCow::as_str), Some("xy"));
    assert!(s.try_unwrap_bytes().is_none());

    let b = Value::Bytes(vec![9, 8]);
    assert!(b.is_bytes());
    assert_eq!(b.try_unwrap_bytes(), Some(&[9u8, 8][..]));

    let rat = Value::Rational(Rational::rational32(10, 2));
    assert!(rat.is_rational());
    assert_eq!(rat.try_unwrap_rational(), Some(Rational::rational32(10, 2)));
  }

  #[test]
  fn r3d_str_cow_and_str_or_int_accessors() {
    let bor = R3dStrCow::Borrowed("a");
    assert!(bor.is_borrowed() && !bor.is_owned());
    assert_eq!(bor.try_unwrap_borrowed(), Some("a"));
    assert_eq!(bor.try_unwrap_owned(), None);
    assert_eq!(bor.as_str(), "a");

    let own = R3dStrCow::Owned(String::from("b"));
    assert!(own.is_owned() && !own.is_borrowed());
    assert_eq!(own.try_unwrap_owned(), Some("b"));
    assert_eq!(own.try_unwrap_borrowed(), None);

    let s = R3dStrOrInt::Str("r1");
    assert!(s.is_str() && !s.is_i64());
    assert_eq!(s.try_unwrap_str(), Some("r1"));
    assert_eq!(s.try_unwrap_i64(), None);

    let n = R3dStrOrInt::I64(5);
    assert!(n.is_i64() && !n.is_str());
    assert_eq!(n.try_unwrap_i64(), Some(5));
    assert_eq!(n.try_unwrap_str(), None);
  }

  // The engine path is now `crate::parser::extract_info`. These run it and
  // assert on the parsed JSON object (replacing the retired `ProcessR3D::process`
  // + `TagMap` tests).
  fn engine_obj(data: &[u8]) -> serde_json::Map<String, serde_json::Value> {
    let json = crate::parser::extract_info("Red.r3d", data, true);
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    v.as_array().unwrap()[0].as_object().unwrap().clone()
  }
  fn is_r3d(obj: &serde_json::Map<String, serde_json::Value>) -> bool {
    obj.get("File:FileType").and_then(|v| v.as_str()) == Some("R3D")
  }

  #[test]
  fn reject_short_input() {
    assert!(!is_r3d(&engine_obj(&[0u8; 7])));
  }

  #[test]
  fn reject_bad_magic() {
    assert!(!is_r3d(&engine_obj(b"\x00\x00\x00\x10ABCD")));
  }

  #[test]
  fn reject_size_less_than_8() {
    assert!(!is_r3d(&engine_obj(b"\x00\x00\x00\x04RED1")));
  }

  #[test]
  fn truncated_header_emits_warning_and_filetype_triplet() {
    // size = 0x40 — header validates, SetFileType runs, then Read($size-8)
    // fails ⇒ Warn("Truncated R3D file"). Faithful: no header tag emission.
    let obj = engine_obj(b"\x00\x00\x00\x40RED1");
    assert!(obj.contains_key("File:FileType"));
    assert!(obj.contains_key("File:FileTypeExtension"));
    assert!(obj.contains_key("File:MIMEType"));
    assert_eq!(
      obj.get("ExifTool:Warning").and_then(|v| v.as_str()),
      Some("Truncated R3D file")
    );
  }

  #[test]
  fn other_date_value_conv_preserves_non_ascii_text() {
    assert_eq!(other_date_value_conv("é2016_01_18_é"), "é2016:01:18 é");
    assert_eq!(other_date_value_conv("é2016_01_18_T_é"), "é2016:01:18 T é");
    assert_eq!(other_date_value_conv("é_é"), "é é");
  }

  #[test]
  fn other_date_value_conv_replaces_first_only() {
    assert_eq!(other_date_value_conv("2016_01_18"), "2016:01:18");
    assert_eq!(other_date_value_conv("2016_01_18_UTC"), "2016:01:18 UTC");
  }

  #[test]
  fn date_time_original_value_conv_splits_into_yyyy_mm_dd_hh_mm_ss() {
    assert_eq!(
      datetime_original_value_conv("20160118213555"),
      "2016:01:18 21:35:55"
    );
  }

  #[test]
  fn date_time_original_value_conv_preserves_non_ascii_text() {
    assert_eq!(
      datetime_original_value_conv("ééé20160118213555ééé"),
      "ééé2016:01:18 21:35:55ééé"
    );
    assert_eq!(date_created_value_conv("é20160118é"), "é2016:01:18é");
    assert_eq!(time_created_value_conv("é213555é"), "é21:35:55é");
  }

  #[test]
  fn date_time_original_value_conv_skips_partial_digit_prefix() {
    assert_eq!(
      datetime_original_value_conv("1234567890xx20160118213555"),
      "1234567890xx2016:01:18 21:35:55"
    );
    assert_eq!(
      datetime_original_value_conv("012345678920160118213555"),
      "0123:45:67 89:20:160118213555"
    );
    assert_eq!(
      datetime_original_value_conv("abcdefg20160118213555"),
      "abcdefg2016:01:18 21:35:55"
    );
    assert_eq!(datetime_original_value_conv("01234567890"), "01234567890");
  }

  #[test]
  fn date_created_value_conv_inserts_colons() {
    assert_eq!(date_created_value_conv("20160118"), "2016:01:18");
  }

  #[test]
  fn time_created_value_conv_inserts_colons() {
    assert_eq!(time_created_value_conv("213555"), "21:35:55");
  }

  #[test]
  fn red2_frame_rate_value_conv_matches_pm() {
    let v = red2_frame_rate_value_conv(&TagValue::Str("1001 0 24000".into()));
    assert!((v.unwrap() - 24000.0 / 1001.0).abs() < 1e-12);
  }

  #[test]
  fn red2_frame_rate_value_conv_partial_inputs_match_perl() {
    assert_eq!(
      red2_frame_rate_value_conv(&TagValue::Str("1001 0".into())),
      Some(0.0)
    );
    assert_eq!(red2_frame_rate_value_conv(&TagValue::I64(1001)), Some(0.0));
    assert_eq!(
      red2_frame_rate_value_conv(&TagValue::Str("1001".into())),
      Some(0.0)
    );
  }

  #[test]
  fn red2_frame_rate_first_word_is_zero_classifies_all_read_value_shapes() {
    assert!(red2_frame_rate_first_word_is_zero(&TagValue::Str(
      "0 0 24000".into()
    )));
    assert!(red2_frame_rate_first_word_is_zero(&TagValue::Str(
      "0 1001".into()
    )));
    assert!(red2_frame_rate_first_word_is_zero(&TagValue::I64(0)));
    assert!(!red2_frame_rate_first_word_is_zero(&TagValue::Str(
      "1001 0 24000".into()
    )));
    assert!(!red2_frame_rate_first_word_is_zero(&TagValue::I64(1001)));
    assert!(red2_frame_rate_first_word_is_zero(&TagValue::F64(0.0)));
    assert!(!red2_frame_rate_first_word_is_zero(&TagValue::F64(23.976)));
    assert!(!red2_frame_rate_first_word_is_zero(&TagValue::Str(
      "abc".into()
    )));
    assert!(!red2_frame_rate_first_word_is_zero(&TagValue::Str(
      "".into()
    )));
  }

  #[test]
  fn round_to_3dp_matches_pm_int_pattern() {
    assert_eq!(round_to_3dp(&TagValue::F64(24000.0 / 1001.0)), 23.976);
    assert_eq!(
      round_to_3dp(&TagValue::Rational(Rational::rational32(24000, 1001))),
      23.976
    );
  }

  #[test]
  fn round_to_3dp_rational_routes_through_roundfloat_7g_first() {
    // Codex round-1 F1: 1106/101 rounds to "10.9505" first ⇒ 10.951.
    assert_eq!(
      round_to_3dp(&TagValue::Rational(Rational::rational32(1106, 101))),
      10.951
    );
    // F64 path: exact f64 ⇒ 10.95.
    assert_eq!(round_to_3dp(&TagValue::F64(1106.0 / 101.0)), 10.95);
  }

  #[test]
  fn focus_distance_value_conv_and_print_conv() {
    assert_eq!(divide_by_1000(&TagValue::I64(-1)), -0.001);
    assert_eq!(focus_distance_print_conv(-0.001), "-0.001 m");
  }

  #[test]
  fn divide_by_10_produces_float() {
    assert_eq!(divide_by_10(&TagValue::I64(49)), 4.9);
  }

  #[test]
  fn perl_arithmetic_to_f64_matches_oracle() {
    assert_eq!(perl_arithmetic_to_f64(""), 0.0);
    assert_eq!(perl_arithmetic_to_f64("  "), 0.0);
    assert_eq!(perl_arithmetic_to_f64("0"), 0.0);
    assert_eq!(perl_arithmetic_to_f64("-1"), -1.0);
    assert_eq!(perl_arithmetic_to_f64("1.5"), 1.5);
    assert_eq!(perl_arithmetic_to_f64("1.5e2"), 150.0);
    assert_eq!(perl_arithmetic_to_f64("1.5e"), 1.5);
    assert_eq!(perl_arithmetic_to_f64("1e"), 1.0);
    assert_eq!(perl_arithmetic_to_f64("abc"), 0.0);
    assert_eq!(perl_arithmetic_to_f64("1000 2000"), 1000.0);
    assert_eq!(perl_arithmetic_to_f64("  123 "), 123.0);
    assert_eq!(perl_arithmetic_to_f64("+"), 0.0);
    assert_eq!(perl_arithmetic_to_f64("-"), 0.0);
    assert_eq!(perl_arithmetic_to_f64("1."), 1.0);
    assert_eq!(perl_arithmetic_to_f64(".5"), 0.5);
    assert_eq!(perl_arithmetic_to_f64("-.5"), -0.5);
    assert_eq!(perl_arithmetic_to_f64("1.5abc"), 1.5);
    assert_eq!(perl_arithmetic_to_f64("0x10"), 0.0);
    assert_eq!(perl_arithmetic_to_f64("inf"), f64::INFINITY);
    assert_eq!(perl_arithmetic_to_f64("-inf"), f64::NEG_INFINITY);
    assert_eq!(perl_arithmetic_to_f64("Inf"), f64::INFINITY);
    assert_eq!(perl_arithmetic_to_f64("INF"), f64::INFINITY);
    assert_eq!(perl_arithmetic_to_f64("infinity"), f64::INFINITY);
    assert!(perl_arithmetic_to_f64("nan").is_nan());
    assert!(perl_arithmetic_to_f64("NaN").is_nan());
    assert_eq!(perl_arithmetic_to_f64("undef"), 0.0);
    assert_eq!(perl_arithmetic_to_f64("true"), 0.0);
  }

  #[test]
  fn perl_arithmetic_to_f64_non_ascii_does_not_panic() {
    assert_eq!(perl_arithmetic_to_f64("éé"), 0.0);
    assert_eq!(perl_arithmetic_to_f64("é"), 0.0);
    assert_eq!(perl_arithmetic_to_f64("éinf"), 0.0);
    assert_eq!(perl_arithmetic_to_f64("日本"), 0.0);
    assert_eq!(perl_arithmetic_to_f64("infé"), f64::INFINITY);
    assert!(perl_arithmetic_to_f64("nanñ").is_nan());
  }

  #[test]
  fn perl_arithmetic_to_f64_inf_with_trailing_junk_matches_perl() {
    assert_eq!(perl_arithmetic_to_f64("infjunk"), f64::INFINITY);
    assert_eq!(perl_arithmetic_to_f64("infinite"), f64::INFINITY);
    assert_eq!(perl_arithmetic_to_f64("infx"), f64::INFINITY);
    assert!(perl_arithmetic_to_f64("nanx").is_nan());
    assert_eq!(perl_arithmetic_to_f64("+inf"), f64::INFINITY);
    assert!(perl_arithmetic_to_f64("-nanx").is_nan());
    assert_eq!(perl_arithmetic_to_f64(" inf"), f64::INFINITY);
    assert!(perl_arithmetic_to_f64(" nan").is_nan());
    assert_eq!(perl_arithmetic_to_f64(" +infx"), f64::INFINITY);
  }

  #[test]
  fn divide_by_10_perl_coerces_overlong_str_to_leading_number() {
    assert_eq!(divide_by_10(&TagValue::Str("123 456".into())), 12.3);
    assert_eq!(divide_by_10(&TagValue::Str("abc".into())), 0.0);
    assert_eq!(divide_by_10(&TagValue::Str("".into())), 0.0);
  }

  #[test]
  fn divide_by_1000_perl_coerces_overlong_str_to_leading_number() {
    assert_eq!(divide_by_1000(&TagValue::Str("1000 2000".into())), 1.0);
    assert_eq!(divide_by_1000(&TagValue::Str("-500 0 0".into())), -0.5);
    assert_eq!(divide_by_1000(&TagValue::Str("0 0".into())), 0.0);
  }

  #[test]
  fn round_to_3dp_coerces_overlong_str() {
    assert_eq!(round_to_3dp(&TagValue::Str("23.976 30".into())), 23.976);
    assert_eq!(round_to_3dp(&TagValue::Str("abc".into())), 0.0);
  }

  #[test]
  fn round_to_3dp_zero_denom_rational_emits_perl_coercion() {
    // Rational(0, 0).exiftool_val_str ⇒ "undef" ⇒ 0.0
    assert_eq!(
      round_to_3dp(&TagValue::Rational(Rational::rational32(0, 0))),
      0.0
    );
    // Rational(N, 0).exiftool_val_str ⇒ "inf" ⇒ Inf
    let inf = round_to_3dp(&TagValue::Rational(Rational::rational32(24000, 0)));
    assert!(inf.is_infinite() && inf.is_sign_positive());
  }

  #[test]
  fn round_to_3dp_preserves_large_finite_floats() {
    let big = 3.40282346638529e38_f64;
    assert_eq!(round_to_3dp(&TagValue::F64(big)), big);
    assert_eq!(round_to_3dp(&TagValue::F64(1.844e19)), 1.844e19);
    assert_eq!(round_to_3dp(&TagValue::F64(-3.4e38)), -3.4e38);
    assert_eq!(round_to_3dp(&TagValue::F64(9.0e15)), 9.0e15);
    let n = round_to_3dp(&TagValue::F64(1e20));
    assert!((n - 1e20).abs() / 1e20 < 1e-15);
  }

  #[test]
  fn round_to_3dp_negative_near_zero_normalizes_to_positive_zero() {
    let n = round_to_3dp(&TagValue::F64(-0.001));
    assert_eq!(n, 0.0);
    assert!(!n.is_sign_negative());
    for v in [-0.0006_f64, -0.0009, -0.001, -0.0005001] {
      let n = round_to_3dp(&TagValue::F64(v));
      assert_eq!(n, 0.0);
      assert!(!n.is_sign_negative());
    }
    assert_eq!(round_to_3dp(&TagValue::F64(-1.5)), -1.499);
    assert_eq!(round_to_3dp(&TagValue::F64(-0.5)), -0.499);
  }

  #[test]
  fn round_to_3dp_handles_overflow_to_infinity() {
    let near_max = f64::MAX / 100.0;
    let n = round_to_3dp(&TagValue::F64(near_max));
    assert!(n.is_infinite() || n == near_max);
  }

  // ---- Typed Meta surface tests ------------------------------------------

  #[test]
  fn r3d_meta_default_is_empty() {
    let m = Meta::default();
    assert_eq!(m.redcode_version(), None);
    assert_eq!(m.image_width(), None);
    assert!(m.directory_tag_order().is_empty());
    assert!(m.warnings().is_empty());
  }

  #[test]
  fn parse_borrowed_returns_meta_for_real_fixture() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/Red.r3d");
    let bytes = std::fs::read(&path).expect("read Red.r3d fixture");
    let meta = parse_borrowed(&bytes)
      .expect("ok")
      .expect("real Red.r3d parses");
    assert_eq!(meta.redcode_version(), Some(b'2'));
    assert_eq!(meta.image_width(), Some(5120));
    assert_eq!(meta.image_height(), Some(2560));
    match meta.frame_rate_ref() {
      Some(FrameRate::F64(n)) => {
        assert!((n - 24000.0 / 1001.0).abs() < 1e-12);
      }
      other => panic!("expected RED2 FrameRate::F64, got {other:?}"),
    }
    assert_eq!(meta.start_edge_code(), Some("01:49:54:11"));
    assert_eq!(meta.serial_number(), Some("130-246-CE5"));
    assert_eq!(meta.firmware_version(), Some("6.2.34"));
    assert_eq!(meta.original_file_name(), Some("A106_C037_0118G5_002.R3D"));
    assert_eq!(meta.f_number(), Some(4.9));
    assert_eq!(meta.focus_distance(), Some(-0.001));
    assert!(meta.warnings().is_empty());
  }

  #[test]
  fn format_parser_trait_returns_meta_static() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/Red.r3d");
    let bytes = std::fs::read(&path).expect("read Red.r3d fixture");
    let meta = <ProcessR3D as FormatParser>::parse(&ProcessR3D, &bytes)
      .expect("ok")
      .expect("real Red.r3d parses");
    assert_eq!(meta.image_width(), Some(5120));
    assert_eq!(meta.start_edge_code(), Some("01:49:54:11"));
  }

  #[test]
  fn meta_sinker_emits_typed_tags_via_map_writer() {
    use crate::tagmap::TagMap;
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/Red.r3d");
    let bytes = std::fs::read(&path).expect("read Red.r3d fixture");
    let meta = parse_borrowed(&bytes)
      .expect("ok")
      .expect("real Red.r3d parses");
    // PrintConv ON.
    let mut w = TagMap::new();
    meta.serialize_tags(true, &mut w).unwrap();
    assert_eq!(w.get_str("Red", "RedcodeVersion"), Some("2".to_string()));
    assert_eq!(w.get_str("Red", "ImageWidth"), Some("5120".to_string()));
    assert_eq!(w.get_str("Red", "FrameRate"), Some("23.976".to_string()));
    assert_eq!(
      w.get_str("Red", "FocusDistance"),
      Some("-0.001 m".to_string())
    );
    // PrintConv OFF (raw F64).
    let mut w = TagMap::new();
    meta.serialize_tags(false, &mut w).unwrap();
    let fr = w.get("Red", "FrameRate").unwrap();
    let raw_f = match fr {
      TagValue::F64(n) => *n,
      other => panic!("expected F64 for FrameRate, got {other:?}"),
    };
    assert!((raw_f - 24000.0 / 1001.0).abs() < 1e-6);
    let fd = w.get("Red", "FocusDistance").unwrap();
    let raw_fd = match fd {
      TagValue::F64(n) => *n,
      other => panic!("expected F64 for FocusDistance, got {other:?}"),
    };
    assert_eq!(raw_fd, -0.001);
  }
}
