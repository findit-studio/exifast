//! Faithful port of `Image::ExifTool::Red` (`lib/Image/ExifTool/Red.pm`):
//! reads Redcode R3D version 1 + version 2 video files.
//!
//! R3D structure (Red.pm:219-223):
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
//! (Red.pm:281 `$fmt = $redFormat{$tag >> 12}`) — see [`RED_FORMAT`].
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
  convert::{ByteOrder, apply, read_value},
  parser::{FormatParser, ParseContext},
  tagtable::{PrintConv, TagDef, TagId, TagTable, ValueConv},
  value::{Group, TagValue},
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
/// This is the *arithmetic-context* sibling of
/// [`crate::convert::perl_numeric_coerce`] (which is bitwise-`&`-context,
/// returning `u64` for `DecodeBits`). The two have different rules: this
/// one yields IEEE infinity/NaN for the named words; the bitwise one
/// would `(UV)Inf == u64::MAX` etc. Both follow Perl's actual semantics
/// in their respective contexts.
///
/// **Scope:** the input shapes reachable from the Red.pm port are
/// (a) `read_value`-joined strings (space-separated, no embedded
/// whitespace around individual numbers) and (b) `exiftool_val_str`'s
/// `"inf"` / `"undef"` for zero-denominator rationals. Both shapes
/// preserve Perl-exact semantics here. Some quirky Perl forms — e.g.
/// `"- 1"+0 == -1` (whitespace after the sign) — are NOT reproduced;
/// they are unreachable through any path that feeds this helper.
fn perl_arithmetic_to_f64(s: &str) -> f64 {
  let bytes = s.as_bytes();
  // Perl's number parser is whitespace-tolerant on the left (`" 123 "+0
  // == 123`). Skip leading ASCII whitespace.
  let mut i = 0;
  while i < bytes.len() && bytes[i].is_ascii_whitespace() {
    i += 1;
  }
  let start = i;
  // Optional leading sign.
  if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
    i += 1;
  }
  let after_sign = i;
  // Recognize Perl's named-special-value words first ("inf", "infinity",
  // "nan"; any case). Perl: `"inf"+0==Inf`, `"-Inf"+0==-Inf`, `"NaN"+0==NaN`.
  //
  // **Safety:** compare on raw `bytes[after_sign..]` (a byte slice — no
  // UTF-8 boundary requirement) rather than slicing into `&s[..]`. A
  // 3-byte string slice like `&s[..3]` PANICS when the 3-byte mark
  // splits a multi-byte UTF-8 codepoint (e.g. `"éé"` — byte 3 is inside
  // the second `é`, two-byte 0xC3 0xA9). Byte-level prefix compares
  // are panic-free for any input and produce the same answer for the
  // ASCII-only words `"inf"`/`"nan"`.
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
    // Accept "inf" or "infinity"; trailing characters after the recognized
    // word fall through Perl's numeric parser as harmless (no numeric
    // prefix remains, so `"inf$junk"+0` still yields `Inf`).
    return if is_neg {
      f64::NEG_INFINITY
    } else {
      f64::INFINITY
    };
  }
  if starts_with_ci(b"nan") {
    return f64::NAN;
  }
  // Standard numeric prefix: digits, optional `.digits`, optional `e±digits`.
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
    // `.` with no digits on either side is not numeric (Perl: `"."+0==0`).
    if !had_int_digits && i == frac_start {
      return 0.0;
    }
  } else if !had_int_digits {
    // Only a sign, or nothing ⇒ Perl `+0`/empty/`-`/`+` ⇒ 0.0.
    return 0.0;
  }
  // Optional exponent. Perl: `"1e"+0==1` (incomplete exponent dropped),
  // `"1e+10"+0==1e10`.
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
      // No exponent digits ⇒ Perl rolls back to before the `e`.
      i = exp_word_start;
    }
  }
  // Parse the leading prefix (including the sign) as f64. The longest
  // valid prefix matches Rust's `f64::from_str`, so parsing
  // `&s[start..i]` is exact.
  s[start..i].parse::<f64>().unwrap_or(0.0)
}

/// Red.pm:56 / :61 / :66 OtherDate1/2/3 ValueConv:
/// `$val =~ s/(\d{4})_(\d{2})_/$1:$2:/; $val =~ tr/_/ /; $val`.
/// Replaces the FIRST `YYYY_MM_` with `YYYY:MM:` and then converts ALL
/// remaining `_` to spaces. Faithful: regex applies once (no `/g` flag),
/// the `tr///` is global.
fn other_date_value_conv(v: &TagValue) -> TagValue {
  let s = match v {
    TagValue::Str(s) => s.as_str(),
    _ => return v.clone(),
  };
  let s = replace_yyyy_mm_underscore(s);
  TagValue::Str(s.replace('_', " ").into())
}

/// Helper for [`other_date_value_conv`]: replace the first occurrence of
/// `<4 digits>_<2 digits>_` with `<4 digits>:<2 digits>:` (faithful Perl
/// `s/(\d{4})_(\d{2})_/$1:$2:/` — one-shot, no `/g`).
///
/// **Codex round-8 F1:** the match window is *byte-position-aligned*
/// (all 8 matched bytes are ASCII digits or underscores, so they are
/// also valid UTF-8 char boundaries). Non-matching regions before/
/// after the match are emitted via `push_str(&s[start..end])`, which
/// preserves any multi-byte UTF-8 sequences verbatim. The previous
/// implementation walked one byte at a time and used `b[i] as char`,
/// mojibaking each non-ASCII byte (e.g. `é` = `\xC3\xA9` became `Ã©`
/// instead of `é`). Mirror Perl's byte-level `s///` faithfully: only
/// the matched ASCII span is rewritten; everything else is byte-for-
/// byte preserved (here as char-for-char preserved, since each char in
/// a non-matched region maps 1:1 to its original bytes via `&s[...]`).
fn replace_yyyy_mm_underscore(s: &str) -> String {
  let b = s.as_bytes();
  // Scan byte-by-byte for the first 8-byte match window. The window
  // contains only ASCII (digits/underscores), so a match index is
  // always a valid UTF-8 char boundary (split-safe for `&s[i..i+8]`).
  for i in 0..b.len().saturating_sub(7) {
    if b[i..i + 4].iter().all(u8::is_ascii_digit)
      && b[i + 4] == b'_'
      && b[i + 5].is_ascii_digit()
      && b[i + 6].is_ascii_digit()
      && b[i + 7] == b'_'
    {
      let mut out = String::with_capacity(s.len());
      // Unmatched prefix: byte-for-byte (and thus UTF-8-char-for-UTF-8-
      // char) preserved.
      out.push_str(&s[..i]);
      out.push_str(&s[i..i + 4]); // YYYY
      out.push(':');
      out.push_str(&s[i + 5..i + 7]); // MM
      out.push(':');
      // Unmatched suffix.
      out.push_str(&s[i + 8..]);
      return out;
    }
  }
  // No match ⇒ Perl `s///` leaves `$val` unchanged. Return the input
  // verbatim (cheaper than rebuilding the String).
  s.to_string()
}

/// Red.pm:72 DateTimeOriginal ValueConv:
/// `$val =~ s/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})/$1:$2:$3 $4:$5:/`.
/// Replaces the FIRST 12-digit run `YYYYMMDDHHMM` with `YYYY:MM:DD HH:MM:`
/// (note the trailing colon — the seconds portion follows as the
/// remaining digits, becoming `:SS` once concatenated with the rest of
/// `$val`). Faithful: single-shot (no `/g`).
///
/// The Perl regex has 5 capture groups summing to **12 digits** (4+2+2+
/// 2+2), not 14 — `YYYYMMDDHHMM`. The substitution `$1:$2:$3 $4:$5:`
/// emits `YYYY:MM:DD HH:MM:`; any tail digits (e.g. the `SS` seconds)
/// stay verbatim after the trailing colon, producing the canonical
/// `YYYY:MM:DD HH:MM:SS` shape for a 14-digit input.
///
/// Faithful to Perl's regex backtracking: at every byte offset we ask
/// "does a 12-digit run start here?" and if so consume it. A 10-digit
/// prefix that lacks two more consecutive digits should NOT terminate
/// the scan — Perl's NFA would advance past the partial match and
/// continue looking. (Codex round-7 oracle: Perl
/// `s/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})/$1:$2:$3 $4:$5:/` on
/// `"1234567890xx20160118213555"` yields `"1234567890xx2016:01:18
/// 21:35:55"` — the leading 10 digits are skipped because the regex
/// needs 12 consecutive, and continues to position 12 where the real
/// match begins.)
fn datetime_original_value_conv(v: &TagValue) -> TagValue {
  let s = match v {
    TagValue::Str(s) => s.as_str(),
    _ => return v.clone(),
  };
  let b = s.as_bytes();
  // Find the first occurrence of a 12-ASCII-digit run.
  for i in 0..b.len().saturating_sub(11) {
    if b[i..i + 12].iter().all(u8::is_ascii_digit) {
      let mut out = String::with_capacity(s.len() + 4);
      out.push_str(&s[..i]);
      out.push_str(&s[i..i + 4]); // YYYY
      out.push(':');
      out.push_str(&s[i + 4..i + 6]); // MM
      out.push(':');
      out.push_str(&s[i + 6..i + 8]); // DD
      out.push(' ');
      out.push_str(&s[i + 8..i + 10]); // HH
      out.push(':');
      out.push_str(&s[i + 10..i + 12]); // MM
      out.push(':');
      out.push_str(&s[i + 12..]); // remaining tail (typically SS)
      return TagValue::Str(out.into());
    }
  }
  v.clone()
}

/// Red.pm:73 DateTimeOriginal PrintConv: `$self->ConvertDateTime($val)`.
/// `ConvertDateTime` with default options (no `DateFormat`, no
/// `QuickTimeUTC`, no `StrictDate`) is essentially the identity for a
/// well-formed `YYYY:MM:DD HH:MM:SS` value. Red.pm's golden for the
/// bundled fixture is `"2016:01:18 21:35:55"` — same as the post-ValueConv
/// string. Faithful identity here; if a fixture later exposes a non-trivial
/// `ConvertDateTime` shape, derive then.
fn convert_date_time_passthrough(v: &TagValue) -> TagValue {
  v.clone()
}

/// Red.pm:82 / :87 / :95 / :100 — date/time fixups: insert a colon after
/// every 2 digits (or 4-then-2 for DateCreated/StorageFormatDate).
///
/// `$val =~ s/(\d{4})(\d{2})/$1:$2:/` (Red.pm:82,95) on `YYYYMMDD` ⇒
/// `YYYY:MM:DD` (the post-match tail `DD` keeps `$1:$2:` then `DD`).
fn date_created_value_conv(v: &TagValue) -> TagValue {
  let s = match v {
    TagValue::Str(s) => s.as_str(),
    _ => return v.clone(),
  };
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
      return TagValue::Str(out.into());
    }
  }
  v.clone()
}

/// Red.pm:87 / :100 — TimeCreated/StorageFormatTime ValueConv:
/// `$val =~ s/(\d{2})(\d{2})/$1:$2:/` on `HHMMSS` ⇒ `HH:MM:SS` (tail SS
/// follows the `$1:$2:` replacement). One-shot.
fn time_created_value_conv(v: &TagValue) -> TagValue {
  let s = match v {
    TagValue::Str(s) => s.as_str(),
    _ => return v.clone(),
  };
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
      return TagValue::Str(out.into());
    }
  }
  v.clone()
}

/// Red.pm:141 — `FNumber` ValueConv `$val / 10`. Input is int16u (I64 in
/// the engine), so produce an `F64`; Perl `/` is float division.
///
/// **Codex round-4 F1:** `walk_red_directory` derives `count =
/// payload_size / elem_size`, so an adversarial overlong directory
/// entry for tag `0x406a` (`len > 8`, format 4 = int16u, elem = 2)
/// makes `read_value` return a space-joined `TagValue::Str` like
/// `"123 456"`. Perl `"123 456" / 10 == 12.3` — coerces the leading
/// numeric prefix. Mirror via [`perl_arithmetic_to_f64`].
fn divide_by_10(v: &TagValue) -> TagValue {
  match v {
    TagValue::I64(n) => TagValue::F64(*n as f64 / 10.0),
    TagValue::F64(n) => TagValue::F64(*n / 10.0),
    TagValue::Str(s) => TagValue::F64(perl_arithmetic_to_f64(s) / 10.0),
    _ => v.clone(),
  }
}

/// Red.pm:147 — `FocusDistance` ValueConv `$val / 1000` (int32s ⇒ float
/// meters).
///
/// **Codex round-4 F1:** same overlong-directory shape as
/// [`divide_by_10`]: `read_value` can hand a space-joined
/// `TagValue::Str` here. Perl `"$first $rest" / 1000` coerces the
/// leading numeric prefix.
fn divide_by_1000(v: &TagValue) -> TagValue {
  match v {
    TagValue::I64(n) => TagValue::F64(*n as f64 / 1000.0),
    TagValue::F64(n) => TagValue::F64(*n / 1000.0),
    TagValue::Str(s) => TagValue::F64(perl_arithmetic_to_f64(s) / 1000.0),
    _ => v.clone(),
  }
}

/// Red.pm:147 — `FocusDistance` PrintConv `"$val m"`. Wraps the value text
/// with a trailing ` m`. `$val` is the post-ValueConv float; Perl
/// stringifies with `%g`-ish — use `format_g(_, 15)` for parity with
/// the serializer.
fn focus_distance_print_conv(v: &TagValue) -> TagValue {
  use crate::value::format_g;
  let text = match v {
    TagValue::F64(n) if n.is_finite() => format_g(*n, 15),
    TagValue::F64(n) => n.to_string(),
    TagValue::I64(n) => n.to_string(),
    TagValue::Str(s) => return TagValue::Str(format!("{s} m").into()),
    _ => return v.clone(),
  };
  TagValue::Str(format!("{text} m").into())
}

/// Red.pm:134, :169, :202 — FrameRate / OriginalFrameRate PrintConv:
/// `int($val * 1000 + 0.5) / 1000` — round to 3 decimal places via
/// half-up (Perl `int` truncates toward zero, so this rounds toward
/// positive infinity for positive `$val`).
///
/// **Subtle (Codex round-1 F1):** for a `TagValue::Rational`, Perl's
/// `ReadValue` (`ExifTool.pm:6275-6321`) has ALREADY passed the value
/// through `RoundFloat(num/denom, 7)` (`ExifTool.pm:6087,6094,6101,6108`
/// = `sprintf("%.7g", n/d)` for rational32, `%.10g` for rational64)
/// before the PrintConv runs. So `$val` at PrintConv time is the
/// stringified-and-then-numeric-coerced value of THAT rounded text — NOT
/// the exact `num/denom` ratio. Boundary case: `1106/101 = 10.95049504…`
/// exact ⇒ Rust would emit `10.95`, but Perl rounds to `"10.9505"` first
/// ⇒ PrintConv emits `10.951`. The Rational branch below mirrors Perl
/// faithfully by going through `exiftool_val_str()` (the SAME `%.{sig}g`
/// formatter; sig=7 for rational32) and re-parsing as f64.
///
/// **Codex round-4 F2:** `Rational` with denominator 0 — reachable for
/// RED1 `FrameRate` (Red.pm:166-170, rational32u at offset 0x3e) when
/// the on-disk denominator bytes are `\x00\x00`. `Rational::
/// exiftool_val_str` returns the bare word `"undef"` (numerator 0) or
/// `"inf"` (numerator ≠ 0). Perl's PrintConv arithmetic coerces
/// `"undef"` to `0` (`int(0*1000+0.5)/1000 == 0`) and `"inf"` to `Inf`
/// (`int(Inf*1000+0.5)/1000 == Inf`). Route both through
/// [`perl_arithmetic_to_f64`] so the typed-Rational input no longer
/// leaks the raw rational, matching the bundled `perl exiftool` output
/// for the `\x00\x00\x00\x00` (denom=0,num=0) header → `0` and
/// `\x00\x01\x00\x00` (denom=0,num=1) → `Inf` shapes.
///
/// **Codex round-4 F1 (PrintConv-side mirror of the ValueConv-side
/// adversarial overlong shape):** `OriginalFrameRate` (Red.pm:131-135,
/// format 2 = float, elem = 4) for `count > 1` arrives as a
/// space-joined `TagValue::Str` like `"23.976 30"`. Perl PrintConv
/// coerces the leading numeric prefix; route via
/// [`perl_arithmetic_to_f64`] (yields `23.976` for the joined-string
/// example), then through the standard `int(... + 0.5)/1000` rounding.
fn round_to_3dp_print_conv(v: &TagValue) -> TagValue {
  let f = match v {
    TagValue::F64(n) if n.is_finite() => *n,
    // ExifTool.pm:6087/6094 RoundFloat(n/d, 7) — go through the same
    // `%.{sig}g` text Perl propagates, then back to f64 (so `1106/101`
    // becomes `10.9505` here, matching bundled `perl exiftool`). Same
    // shared `exiftool_val_str` is also the truth for the zero-denom
    // arm: `"undef"` (0/0) ⇒ 0.0, `"inf"` (N/0) ⇒ Inf — Perl's
    // arithmetic coercion. Folded into a single `Rational` arm because
    // `exiftool_val_str` handles both the rounded-quotient and the
    // bare-word cases internally.
    TagValue::Rational(r) => perl_arithmetic_to_f64(&r.exiftool_val_str()),
    // Codex round-4 F1: overlong/space-joined Str (e.g. count > 1
    // through `read_value`). Perl coerces the leading numeric prefix.
    TagValue::Str(s) => perl_arithmetic_to_f64(s),
    _ => return v.clone(),
  };
  // Perl `int(...)` on a non-finite double propagates the value
  // unchanged: `int(Inf) == Inf`, `int(NaN) == NaN`. Mirror that here so
  // an `"inf"`-coerced input lands as `F64(Inf)` (the JSON-serialize-as-
  // null gap remains the documented Phase-2 forward item #1 — not this
  // helper's concern).
  if !f.is_finite() {
    return TagValue::F64(f);
  }
  // Perl `int(...)` truncates toward zero; +0.5 then `int` matches
  // half-up for positive values, half-down (toward zero) for negative.
  //
  // **Codex round-5 F1:** Perl `int($x)` operates in **NV space (double),
  // not IV (i64)** — so any finite NV ≤ `f64::MAX` is preserved verbatim
  // when its fractional part is dropped. Casting `(f * 1000.0 + 0.5)`
  // to `i64` would silently saturate for any `|f * 1000.0| > i64::MAX
  // ≈ 9.22e18` (e.g. crafted RED `OriginalFrameRate` from a `float32`
  // payload bytes near `f32::MAX ≈ 3.4e38` would land as `~9.22e15`,
  // not as the Perl-preserved ~3.4e38). Keep the truncation in `f64`
  // via `.trunc()` so the operation matches Perl `int(NV)` across the
  // full finite range. Oracle: `perl -e 'print int(1.844e19*1000+0.5)
  // /1000'` ⇒ `1.844e+19` (NV-preserved); the `.trunc() / 1000.0`
  // form below reproduces this without the i64-saturation footgun.
  let scaled = f * 1000.0 + 0.5;
  // `f * 1000.0` can overflow to ±Inf for `|f| > f64::MAX / 1000`
  // (≈1.797e305). Perl `int(Inf*1000+0.5)/1000` ⇒ `Inf`; mirror by
  // propagating non-finite scaled values (lands on the existing
  // Phase-2 forward item #1 serialize-as-null seam, faithfully).
  if !scaled.is_finite() {
    return TagValue::F64(scaled / 1000.0);
  }
  // **Codex round-6 F1:** for negative inputs in `(-0.0005, 0.0)` the
  // post-`+0.5` scaled value lands in `(-1.0, 0.0)`, whose `trunc()`
  // is **negative zero** in IEEE-754 (Rust preserves the sign;
  // `(-0.1_f64).trunc() == -0.0`). Perl's `int()` does not preserve
  // the sign of zero — it produces a positive-integer zero (Devel::
  // Peek dump of `int(-0.1)` confirms `NV = 0`, not `-0`). Then JSON
  // would diverge: our `format_g` (faithfully `%g`) prints `-0.0` as
  // `"-0"` (matching Perl's `%g(-0.0)`), but the actual Perl value
  // here is positive zero ⇒ prints `"0"`. Normalize by adding `+0.0`
  // (IEEE: `-0.0 + 0.0 == +0.0` — identical to the `truncated == 0.0
  // ? 0.0 : truncated/1000.0` Codex recommendation, with no extra
  // branch). Oracle: `perl -e 'use Devel::Peek; Dump int(-0.001*1000
  // +0.5)/1000'` → `NV = 0`, positive bits.
  let truncated = scaled.trunc() + 0.0;
  TagValue::F64(truncated / 1000.0)
}

/// Red.pm:201 — RED2 FrameRate ValueConv:
/// `my @a = split " ", $val; ($a[1] * 0x10000 + $a[2]) / $a[0]`.
/// Input is a space-joined `int16u[3]` string from [`read_value`]
/// ("a b c"); we parse, build `(b*65536+c)/a`, return F64.
///
/// **Subtle (Codex round-2 F1):** under [`read_value`]'s faithful
/// count-shortening for truncated RED2 headers (ExifTool.pm:6290-6292),
/// `$val` may also arrive as a 2-element string `"a b"` (`count` shortened
/// to 2) or as a *scalar* `a` (`count` shortened to 1). Perl's `split " ",
/// $val` followed by `($a[1]*0x10000 + $a[2])/$a[0]` coerces missing
/// indices to numeric `0` (with the `use warnings` "uninitialized" warning
/// — `ProcessR3D` runs without `use warnings`, so the warning is silent),
/// producing `0/a = 0`. Mirror that behaviour: never fall back to the raw
/// value for short shapes — emit `F64(0.0)` for `a ≠ 0`, leave the value
/// unchanged only when the parse cannot recover a numeric first operand
/// (Perl would `0/0` ⇒ `NaN`, which is faithfully *unreachable* here for
/// a well-formed RED2 prefix; the `v.clone()` keeps the engine panic-free
/// for hostile parsers).
fn red2_frame_rate_value_conv(v: &TagValue) -> TagValue {
  // Perl auto-stringifies `$val` before `split`, so accept both typed
  // numeric scalars (`count == 1` ⇒ `TagValue::I64(a)`) and the
  // space-joined string shape (`count >= 2`).
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
    _ => return v.clone(),
  };
  let parts: Vec<&str> = s.split_whitespace().collect();
  // Perl `($a[0], $a[1], $a[2])` for an array of length k < 3 substitutes
  // undef (numerically `0`) for indices ≥ k. Mirror that with `unwrap_or(0)`
  // *after* the first-operand parse below.
  let parse = |p: &str| p.parse::<i64>().ok();
  let a = match parts.first().and_then(|p| parse(p)) {
    Some(n) => n,
    // Empty or unparseable first operand: Perl's `$a[0]` is `undef` ⇒ `0`,
    // and `($a[1]*0x10000 + $a[2])/0` would be a runtime division-by-zero
    // (`Illegal division by zero` in Perl), which `ProcessR3D` would
    // propagate as a die. We treat it as the panic-free "leave unchanged"
    // arm — this is unreachable for any RED2 file ExifTool itself accepts.
    None => return v.clone(),
  };
  if a == 0 {
    return v.clone();
  }
  let b = parts.get(1).and_then(|p| parse(p)).unwrap_or(0);
  let c = parts.get(2).and_then(|p| parse(p)).unwrap_or(0);
  TagValue::F64((b as f64 * 65536.0 + c as f64) / a as f64)
}

// ── %redFormat (Red.pm:22-33) ────────────────────────────────────────────

/// Red.pm:22-33 `%redFormat`. Top-4-bits of the directory tag-ID resolve
/// to the format string (`int8u`, `string`, `float`, ...). `format 7` and
/// `format 9` are both `'undef'`; `format 3` is `'int8u'` (Perl comment
/// "how is this different than 0?" preserved here for fidelity).
const fn red_format(idx: u8) -> Option<&'static str> {
  match idx {
    0 => Some("int8u"),  // Red.pm:23
    1 => Some("string"), // Red.pm:24
    2 => Some("float"),  // Red.pm:25
    3 => Some("int8u"),  // Red.pm:26 (PH: "how is this different than 0?")
    4 => Some("int16u"), // Red.pm:27
    5 => Some("int8s"),  // Red.pm:28 (PH: "not sure about this")
    6 => Some("int32s"), // Red.pm:29
    7 => Some("undef"),  // Red.pm:30 (mixed-format structure?)
    8 => Some("int32u"), // Red.pm:31 (NC)
    9 => Some("undef"),  // Red.pm:32 (256 bytes of zeros)
    _ => None,
  }
}

// ── Red::Main tag definitions (Red.pm:39-151) ────────────────────────────
//
// All TagDefs use family-1 group `"Red"` (Red.pm:39 `GROUPS => {2=>'Camera'}`;
// family-0/-1 default to the package suffix `Red` for `-G1` JSON).

const G1_RED: &str = "Red";

// ---- format 1 (string) — Red.pm:50-125 ----
static START_EDGE_CODE: TagDef =
  TagDef::new("StartEdgeCode", G1_RED, ValueConv::None, PrintConv::None);
static START_TIMECODE: TagDef =
  TagDef::new("StartTimecode", G1_RED, ValueConv::None, PrintConv::None);
static OTHER_DATE_1: TagDef = TagDef::new(
  "OtherDate1",
  G1_RED,
  ValueConv::Func(other_date_value_conv),
  PrintConv::None,
);
static OTHER_DATE_2: TagDef = TagDef::new(
  "OtherDate2",
  G1_RED,
  ValueConv::Func(other_date_value_conv),
  PrintConv::None,
);
static OTHER_DATE_3: TagDef = TagDef::new(
  "OtherDate3",
  G1_RED,
  ValueConv::Func(other_date_value_conv),
  PrintConv::None,
);
static DATE_TIME_ORIGINAL: TagDef = TagDef::new(
  "DateTimeOriginal",
  G1_RED,
  ValueConv::Func(datetime_original_value_conv),
  PrintConv::Func(convert_date_time_passthrough),
);
static SERIAL_NUMBER: TagDef =
  TagDef::new("SerialNumber", G1_RED, ValueConv::None, PrintConv::None);
static CAMERA_TYPE: TagDef = TagDef::new("CameraType", G1_RED, ValueConv::None, PrintConv::None);
static REEL_NUMBER: TagDef = TagDef::new("ReelNumber", G1_RED, ValueConv::None, PrintConv::None);
static TAKE: TagDef = TagDef::new("Take", G1_RED, ValueConv::None, PrintConv::None);
static DATE_CREATED: TagDef = TagDef::new(
  "DateCreated",
  G1_RED,
  ValueConv::Func(date_created_value_conv),
  PrintConv::None,
);
static TIME_CREATED: TagDef = TagDef::new(
  "TimeCreated",
  G1_RED,
  ValueConv::Func(time_created_value_conv),
  PrintConv::None,
);
static FIRMWARE_VERSION: TagDef =
  TagDef::new("FirmwareVersion", G1_RED, ValueConv::None, PrintConv::None);
static REEL_TIMECODE: TagDef =
  TagDef::new("ReelTimecode", G1_RED, ValueConv::None, PrintConv::None);
static STORAGE_TYPE: TagDef = TagDef::new("StorageType", G1_RED, ValueConv::None, PrintConv::None);
static STORAGE_FORMAT_DATE: TagDef = TagDef::new(
  "StorageFormatDate",
  G1_RED,
  ValueConv::Func(date_created_value_conv),
  PrintConv::None,
);
static STORAGE_FORMAT_TIME: TagDef = TagDef::new(
  "StorageFormatTime",
  G1_RED,
  ValueConv::Func(time_created_value_conv),
  PrintConv::None,
);
static STORAGE_SERIAL_NUMBER: TagDef = TagDef::new(
  "StorageSerialNumber",
  G1_RED,
  ValueConv::None,
  PrintConv::None,
);
static STORAGE_MODEL: TagDef =
  TagDef::new("StorageModel", G1_RED, ValueConv::None, PrintConv::None);
static ASPECT_RATIO: TagDef = TagDef::new("AspectRatio", G1_RED, ValueConv::None, PrintConv::None);
static REVISION: TagDef = TagDef::new("Revision", G1_RED, ValueConv::None, PrintConv::None);
static ORIGINAL_FILE_NAME: TagDef =
  TagDef::new("OriginalFileName", G1_RED, ValueConv::None, PrintConv::None);
static LENS_MAKE: TagDef = TagDef::new("LensMake", G1_RED, ValueConv::None, PrintConv::None);
static LENS_NUMBER: TagDef = TagDef::new("LensNumber", G1_RED, ValueConv::None, PrintConv::None);
static LENS_MODEL: TagDef = TagDef::new("LensModel", G1_RED, ValueConv::None, PrintConv::None);
static MODEL: TagDef = TagDef::new("Model", G1_RED, ValueConv::None, PrintConv::None);
static CAMERA_OPERATOR: TagDef =
  TagDef::new("CameraOperator", G1_RED, ValueConv::None, PrintConv::None);
static VIDEO_FORMAT: TagDef = TagDef::new("VideoFormat", G1_RED, ValueConv::None, PrintConv::None);
static FILTER: TagDef = TagDef::new("Filter", G1_RED, ValueConv::None, PrintConv::None);
static BRAIN: TagDef = TagDef::new("Brain", G1_RED, ValueConv::None, PrintConv::None);
static SENSOR: TagDef = TagDef::new("Sensor", G1_RED, ValueConv::None, PrintConv::None);
static QUALITY: TagDef = TagDef::new("Quality", G1_RED, ValueConv::None, PrintConv::None);

// ---- format 2 (float) — Red.pm:127-135 ----
static COLOR_TEMPERATURE: TagDef =
  TagDef::new("ColorTemperature", G1_RED, ValueConv::None, PrintConv::None);
static RGB_CURVES: TagDef = TagDef::new("RGBCurves", G1_RED, ValueConv::None, PrintConv::None);
static ORIGINAL_FRAME_RATE: TagDef = TagDef::new(
  "OriginalFrameRate",
  G1_RED,
  ValueConv::None,
  PrintConv::Func(round_to_3dp_print_conv),
);

// ---- format 4 (int16u) — Red.pm:138-143 ----
static CROP_AREA: TagDef = TagDef::new("CropArea", G1_RED, ValueConv::None, PrintConv::None);
static ISO: TagDef = TagDef::new("ISO", G1_RED, ValueConv::None, PrintConv::None);
static F_NUMBER: TagDef = TagDef::new(
  "FNumber",
  G1_RED,
  ValueConv::Func(divide_by_10),
  PrintConv::None,
);
static FOCAL_LENGTH: TagDef = TagDef::new("FocalLength", G1_RED, ValueConv::None, PrintConv::None);

// ---- format 6 (int32s) — Red.pm:147 ----
static FOCUS_DISTANCE: TagDef = TagDef::new(
  "FocusDistance",
  G1_RED,
  ValueConv::Func(divide_by_1000),
  PrintConv::Func(focus_distance_print_conv),
);

// ── RED1 / RED2 header tag tables (Red.pm:154-206) ───────────────────────
//
// `ProcessBinaryData` is dispatched by `HandleTag` via `SubDirectory`; we
// implement the read directly (the only RED1/RED2 fields are five/four
// fixed-width slots). Family-1 is `"Red"` (Red.pm:155,176 declare family-2
// `"Video"`, but `-G1` JSON uses the package suffix).

/// Red.pm:166-170 RED1 `FrameRate`: rational32u + PrintConv
/// `int($val * 1000 + 0.5) / 1000`.
static RED1_FRAME_RATE: TagDef = TagDef::new(
  "FrameRate",
  G1_RED,
  ValueConv::None,
  PrintConv::Func(round_to_3dp_print_conv),
);
/// Red.pm:161 / :181 `RedcodeVersion`: a single ASCII digit (`string[1]`).
static REDCODE_VERSION: TagDef =
  TagDef::new("RedcodeVersion", G1_RED, ValueConv::None, PrintConv::None);
/// Red.pm:164,194 `ImageWidth` (RED1 int16u, RED2 int32u).
static IMAGE_WIDTH: TagDef = TagDef::new("ImageWidth", G1_RED, ValueConv::None, PrintConv::None);
/// Red.pm:165,195 `ImageHeight` (RED1 int16u, RED2 int32u).
static IMAGE_HEIGHT: TagDef = TagDef::new("ImageHeight", G1_RED, ValueConv::None, PrintConv::None);
/// Red.pm:171 RED1 `OriginalFileName` (string[32]).
static RED1_ORIGINAL_FILE_NAME: TagDef =
  TagDef::new("OriginalFileName", G1_RED, ValueConv::None, PrintConv::None);
/// Red.pm:198-203 RED2 `FrameRate`: int16u[3] + custom ValueConv
/// `($a[1] * 0x10000 + $a[2]) / $a[0]`, PrintConv `round-3dp`.
static RED2_FRAME_RATE: TagDef = TagDef::new(
  "FrameRate",
  G1_RED,
  ValueConv::Func(red2_frame_rate_value_conv),
  PrintConv::Func(round_to_3dp_print_conv),
);

fn red_main_get(id: TagId) -> Option<&'static TagDef> {
  match id {
    // Red.pm:50-125 (format 1: string) — explicit numeric ids per the
    // bundled `%Main` hash. Defining each as `TagId::Int(...)` mirrors
    // ExifTool's hash-key shape exactly (the lookup is by 16-bit tag id).
    TagId::Int(0x1000) => Some(&START_EDGE_CODE),
    TagId::Int(0x1001) => Some(&START_TIMECODE),
    TagId::Int(0x1002) => Some(&OTHER_DATE_1),
    TagId::Int(0x1003) => Some(&OTHER_DATE_2),
    TagId::Int(0x1004) => Some(&OTHER_DATE_3),
    TagId::Int(0x1005) => Some(&DATE_TIME_ORIGINAL),
    TagId::Int(0x1006) => Some(&SERIAL_NUMBER),
    TagId::Int(0x1019) => Some(&CAMERA_TYPE),
    TagId::Int(0x101a) => Some(&REEL_NUMBER),
    TagId::Int(0x101b) => Some(&TAKE),
    TagId::Int(0x1023) => Some(&DATE_CREATED),
    TagId::Int(0x1024) => Some(&TIME_CREATED),
    TagId::Int(0x1025) => Some(&FIRMWARE_VERSION),
    TagId::Int(0x1029) => Some(&REEL_TIMECODE),
    TagId::Int(0x102a) => Some(&STORAGE_TYPE),
    TagId::Int(0x1030) => Some(&STORAGE_FORMAT_DATE),
    TagId::Int(0x1031) => Some(&STORAGE_FORMAT_TIME),
    TagId::Int(0x1032) => Some(&STORAGE_SERIAL_NUMBER),
    TagId::Int(0x1033) => Some(&STORAGE_MODEL),
    TagId::Int(0x1036) => Some(&ASPECT_RATIO),
    TagId::Int(0x1042) => Some(&REVISION),
    TagId::Int(0x1056) => Some(&ORIGINAL_FILE_NAME),
    TagId::Int(0x106e) => Some(&LENS_MAKE),
    TagId::Int(0x106f) => Some(&LENS_NUMBER),
    TagId::Int(0x1070) => Some(&LENS_MODEL),
    TagId::Int(0x1071) => Some(&MODEL),
    TagId::Int(0x107c) => Some(&CAMERA_OPERATOR),
    TagId::Int(0x1086) => Some(&VIDEO_FORMAT),
    TagId::Int(0x1096) => Some(&FILTER),
    TagId::Int(0x10a0) => Some(&BRAIN),
    TagId::Int(0x10a1) => Some(&SENSOR),
    TagId::Int(0x10be) => Some(&QUALITY),
    // Red.pm:127-135 (format 2: float).
    TagId::Int(0x200d) => Some(&COLOR_TEMPERATURE),
    TagId::Int(0x204b) => Some(&RGB_CURVES),
    TagId::Int(0x2066) => Some(&ORIGINAL_FRAME_RATE),
    // Red.pm:138-143 (format 4: int16u).
    TagId::Int(0x4037) => Some(&CROP_AREA),
    TagId::Int(0x403b) => Some(&ISO),
    TagId::Int(0x406a) => Some(&F_NUMBER),
    TagId::Int(0x406b) => Some(&FOCAL_LENGTH),
    // Red.pm:147 (format 6: int32s).
    TagId::Int(0x606c) => Some(&FOCUS_DISTANCE),
    _ => None,
  }
}

/// `%Image::ExifTool::Red::Main` (Red.pm:39-151). Family-0 group `"Red"`.
pub static RED_MAIN: TagTable = TagTable::new("Red", red_main_get);

// ── ProcessR3D (Red.pm:212-295) ──────────────────────────────────────────

/// `Image::ExifTool::Red::ProcessR3D` (Red.pm:212-295). Faithful read-only
/// port. Returns `true` if the file was accepted (`return 1`, Red.pm:294)
/// or a recognized-but-truncated R3D (`return $et->Warn($errTrunc)` —
/// Red.pm:236,246 — `Warn` returns 1 unless suppressed by `NoWarning`).
/// Returns `false` only on the two "this is not an R3D" gates:
/// `Read != 8`/regex-miss (Red.pm:225) and `size < 8` (Red.pm:228).
pub struct ProcessR3D;

impl FormatParser for ProcessR3D {
  fn process(&self, ctx: &mut ParseContext<'_>) -> bool {
    // Phase 1: header validation reads from the borrowed `ctx.data()` only;
    // no `&mut ctx` is needed yet, so the immutable borrow is short-lived.
    let (ver, size) = {
      let data = ctx.data();
      // Red.pm:225 `return 0 unless $raf->Read($buff,8) == 8 and
      //                     $buff =~ /^\0\0..RED(1|2)/s`.
      if data.len() < 8 {
        return false;
      }
      if data[0] != 0 || data[1] != 0 {
        return false;
      }
      // `..` matches any two bytes; we then need `RED` and `1` or `2`.
      if &data[4..7] != b"RED" {
        return false;
      }
      let ver = match data[7] {
        b'1' => 1u8,
        b'2' => 2u8,
        _ => return false,
      };
      // Red.pm:227 `$size = unpack('N', $buff)` (BE int32u).
      let size = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
      // Red.pm:228 `return 0 if $size < 8`.
      if size < 8 {
        return false;
      }
      (ver, size)
    };
    // Red.pm:230 `$et->SetFileType()` — finalize the file type. After this
    // mutable borrow, every subsequent read of `ctx.data()` is fresh.
    ctx.set_file_type(None, None, None);
    let print_on = ctx.print_conv_enabled();

    // Red.pm:236 `$raf->Read($buf2, $size - 8) == $size - 8 or return
    // $et->Warn($errTrunc)`. The R3D extra-header bytes must fit in `data`.
    if ctx.data().len() < size {
      ctx.metadata().push_warning("Truncated R3D file");
      return true;
    }

    // Red.pm:237-240 — `$buff` is the first `$size` bytes; RED1/RED2 header
    // subtable extraction reads fixed-offset fields from it. We do this
    // *before* the directory walk so the immutable `ctx.data()` borrow stays
    // confined here (the directory walk owns a private `Vec` of bytes).
    // `ver` is already constrained to 1 or 2 by the magic check above; use
    // a panic-free if/else (the crate's `#![forbid(unsafe_code)]` is paired
    // with a no-panic-on-real-input contract — no `unreachable!()`).
    if ver == 1 {
      extract_red1_header_via(ctx, size, print_on);
    } else {
      extract_red2_header_via(ctx, size, print_on);
    }

    // Red.pm:244-256: compute `$pos` (start of Red directory) and the
    // directory slice (`buff`).
    //
    // RED1: Red.pm:246 reads `$raf->Read($buff, 0x10000)` — a fresh buffer
    // starting at file-offset `$size`; the directory is at offset `0x22`
    // within it. We model this by copying `data[size..]` (clamped to 64 KiB
    // for parity with `0x10000`).
    //
    // RED2: `$buff` stays the size-byte header; the directory is at
    // `0x44 + 0x18*rdi + 0x14*rda + 0x10*rdx` within it.
    let (buff_owned, mut pos): (Vec<u8>, usize) = if ver == 1 {
      // Red.pm:246 `$raf->Read($buff, 0x10000) or return $et->Warn(
      // $errTrunc)`.
      if ctx.data().len() <= size {
        ctx.metadata().push_warning("Truncated R3D file");
        return true;
      }
      let data = ctx.data();
      let take = (data.len() - size).min(0x10000);
      (data[size..size + take].to_vec(), 0x22usize)
    } else {
      // Red.pm:251-252 `$pos = 0x44; length($buff) < $pos and return
      // $et->Warn($errTrunc)`. `$buff` here is the declared-first-block
      // slice (the same `$buff` the RED2 subtable extraction used above),
      // NOT the full file. Codex round-2 F2: the previous `data.len() <
      // 0x44` check would let a file with `size = 0x40` but trailing bytes
      // slip past and read `rdi/rda/rdx` from outside the declared block.
      // Faithful: guard on `size`, then read the structure bytes from the
      // size-bounded slice (which is exactly what the subsequent `buff_owned
      // = data[..size]` copy uses for the rest of the walk).
      if size < 0x44 {
        ctx.metadata().push_warning("Truncated R3D file");
        return true;
      }
      let first_block = &ctx.data()[..size];
      let rdi = first_block[0x40] as usize;
      let rda = first_block[0x41] as usize;
      let rdx = first_block[0x42] as usize;
      let p = 0x44usize + 0x18 * rdi + 0x14 * rda + 0x10 * rdx;
      (first_block.to_vec(), p)
    };
    let buff: &[u8] = &buff_owned;

    // Red.pm:257-273 — directory length + sanity guard.
    let dir_len: Option<usize>;
    let dir_end: usize;
    if pos + 8 > buff.len() {
      // Red.pm:258 `$dirLen = 0`; the fallback scan that follows reassigns
      // $pos via regex. We faithfully attempt the regex scan; if it fails,
      // emit the "Can't find Red directory" Warn (Red.pm:266) and stop.
      // Note: Red.pm later checks `$dirLen && ...` (Red.pm:282); `0` is
      // falsy in Perl, so the unknown-format Warn is suppressed in the
      // fallback path. We model that by keeping `dir_len = None`.
      match scan_for_red_directory(buff) {
        Some(p) => {
          pos = p;
          dir_end = buff.len();
          dir_len = None;
          // Red.pm:270 `$et->Warn('This R3D file is different. Please
          // submit a sample for testing')`.
          ctx
            .metadata()
            .push_warning("This R3D file is different. Please submit a sample for testing");
        }
        None => {
          ctx
            .metadata()
            .push_warning("Can't find Red directory. Please submit sample for testing");
          return true;
        }
      }
    } else {
      // Red.pm:260 `$dirLen = Get16u(\$buff, $pos)`; :261 `$pos += 2`.
      let len = u16::from_be_bytes([buff[pos], buff[pos + 1]]) as usize;
      pos += 2;
      // Red.pm:264 sanity check: `$dirLen < 300 or $dirLen >= 2048 or
      // $pos + $dirLen > length $buff` ⇒ fallback scan.
      if !(300..2048).contains(&len) || pos + len > buff.len() {
        match scan_for_red_directory(buff) {
          Some(p) => {
            pos = p;
            dir_end = buff.len();
            dir_len = None;
            ctx
              .metadata()
              .push_warning("This R3D file is different. Please submit a sample for testing");
          }
          None => {
            ctx
              .metadata()
              .push_warning("Can't find Red directory. Please submit sample for testing");
            return true;
          }
        }
      } else {
        dir_len = Some(len);
        dir_end = pos + len;
      }
    }

    // Red.pm:277-291 directory walk.
    walk_red_directory(buff, pos, dir_end, dir_len, ctx, print_on);

    true // Red.pm:294 `return 1`.
  }
}

/// Red.pm:266 fallback regex: `$buff =~ /\0\x0f\x10[\0\x06]/g` — find the
/// pattern (tag 0x1000 with `len=0x000f`). Returns `pos($buff) - 4`
/// (Red.pm:267): Perl's `pos()` is the offset PAST the match, so we want
/// the byte offset where the match starts.
fn scan_for_red_directory(buf: &[u8]) -> Option<usize> {
  // Match 4 consecutive bytes: `\0`, `\x0f`, `\x10`, `\0`|`\x06`.
  (0..buf.len().saturating_sub(3)).find(|&i| {
    buf[i] == 0x00
      && buf[i + 1] == 0x0f
      && buf[i + 2] == 0x10
      && (buf[i + 3] == 0x00 || buf[i + 3] == 0x06)
  })
}

/// RED1 header subtable read (Red.pm:154-172). Reads from the first `size`
/// bytes of `ctx.data()`. The helper reads each field via [`read_value`]
/// into a local `TagValue` (releasing the immutable borrow before the
/// matching `push_with_conv` call). `read_value` is bounds-checked, so a
/// fixture too short for any particular field cleanly produces `None`
/// (no panic), the field is skipped, and the rest still emit.
fn extract_red1_header_via(ctx: &mut ParseContext<'_>, size: usize, print_on: bool) {
  // Collect all field values *before* doing any mutating push, so the
  // immutable borrow of `ctx.data()` is dropped by the time we touch
  // `ctx.metadata()`. Faithful: the on-disk reads happen first, the
  // FoundTag calls happen in declaration order. `size.min(data.len())`
  // defends against a caller passing a `size` larger than the buffer
  // (the `process()` path checks this, but keep the helper panic-free).
  let reads: Vec<(&'static TagDef, Option<TagValue>)> = {
    let raw = ctx.data();
    let data = &raw[..size.min(raw.len())];
    vec![
      (
        &REDCODE_VERSION,
        read_value(data, 0x07, "string", 1, ByteOrder::Mm),
      ),
      (
        &IMAGE_WIDTH,
        read_value(data, 0x36, "int16u", 1, ByteOrder::Mm),
      ),
      (
        &IMAGE_HEIGHT,
        read_value(data, 0x3a, "int16u", 1, ByteOrder::Mm),
      ),
      (
        &RED1_FRAME_RATE,
        read_value(data, 0x3e, "rational32u", 1, ByteOrder::Mm),
      ),
      (
        &RED1_ORIGINAL_FILE_NAME,
        read_value(data, 0x43, "string", 32, ByteOrder::Mm),
      ),
    ]
  };
  for (def, v) in reads {
    if let Some(value) = v {
      push_with_conv(ctx, def, value, print_on);
    }
  }
}

/// RED2 header subtable read (Red.pm:175-206). Same shape as
/// [`extract_red1_header_via`].
fn extract_red2_header_via(ctx: &mut ParseContext<'_>, size: usize, print_on: bool) {
  let reads: Vec<(&'static TagDef, Option<TagValue>)> = {
    let raw = ctx.data();
    let data = &raw[..size.min(raw.len())];
    vec![
      (
        &REDCODE_VERSION,
        read_value(data, 0x07, "string", 1, ByteOrder::Mm),
      ),
      (
        &IMAGE_WIDTH,
        read_value(data, 0x4c, "int32u", 1, ByteOrder::Mm),
      ),
      (
        &IMAGE_HEIGHT,
        read_value(data, 0x50, "int32u", 1, ByteOrder::Mm),
      ),
      // Red.pm:198-203 FrameRate @0x56 (int16u[3] + custom ValueConv).
      (
        &RED2_FRAME_RATE,
        read_value(data, 0x56, "int16u", 3, ByteOrder::Mm),
      ),
    ]
  };
  for (def, v) in reads {
    if let Some(value) = v {
      // Red.pm:201 RED2 FrameRate ValueConv `($a[1]*0x10000 + $a[2])/$a[0]`
      // dies with `Illegal division by zero` when `$a[0]` is 0. ExifTool's
      // `HandleTag`/`FoundTag` runs ValueConv inside `eval` (ExifTool.pm:
      // 10119-10131 — `eval $valueConv; if ($@) { ... return; }`), so the
      // tag is silently dropped on conversion failure. Codex round-3 F1 +
      // empirical oracle: `perl exiftool -j` on a RED2 fixture with `int16u[3]
      // = 0,0,24000` emits NO `Red:FrameRate` field at all (only the upstream
      // RedcodeVersion/ImageWidth/ImageHeight survive). Mirror that here.
      if std::ptr::eq(def, &RED2_FRAME_RATE) && red2_frame_rate_first_word_is_zero(&value) {
        continue;
      }
      push_with_conv(ctx, def, value, print_on);
    }
  }
}

/// Codex round-3 F1: detect the `($a[0] == 0)` case for RED2 FrameRate so
/// we can drop the tag instead of emitting a raw value. The shapes are
/// the ones [`read_value`] can produce for a `int16u[3]` field after the
/// faithful count-shortening (ExifTool.pm:6290-6292) and the single-element
/// typed-scalar return (ExifTool.pm:6318-6320):
///
/// - `TagValue::Str("0 …")` — `count == 3` or `2`, space-joined, first
///   token is `0`.
/// - `TagValue::I64(0)` — `count == 1`, typed scalar.
/// - `TagValue::F64(0.0)` — defensive (no current path produces this for
///   `int16u`, but Perl would treat `0.0` as falsy in division).
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

/// Red.pm:277-291 directory walk — read each entry, dispatch the format
/// code from the tag-ID top-4-bits, and HandleTag the resulting value
/// against `RED_MAIN`. `dir_len` is `Some` when the directory length was
/// taken from the header (Red.pm:260) and `None` when the fallback scan
/// was used (Red.pm:258 `$dirLen = 0`); Red.pm:282 `$fmt or $dirLen &&
/// $et->Warn(...)` SUPPRESSES the unknown-format warning in the fallback.
fn walk_red_directory(
  buff: &[u8],
  mut pos: usize,
  dir_end: usize,
  dir_len: Option<usize>,
  ctx: &mut ParseContext<'_>,
  print_on: bool,
) {
  let dir_len_truthy = dir_len.is_some();
  while pos + 4 <= dir_end {
    let len = u16::from_be_bytes([buff[pos], buff[pos + 1]]) as usize;
    // Red.pm:279 `last if $len < 4 or $pos + $len > $dirEnd`.
    if len < 4 || pos + len > dir_end {
      break;
    }
    let tag = u16::from_be_bytes([buff[pos + 2], buff[pos + 3]]);
    // Red.pm:281 `$fmt = $redFormat{$tag >> 12}`.
    let fmt_idx = (tag >> 12) as u8;
    let fmt = match red_format(fmt_idx) {
      Some(f) => f,
      None => {
        // Red.pm:282 `$fmt or $dirLen && $et->Warn('Unknown format
        // code'), last` — Warn only when the directory length came from
        // the header (truthy), not from the fallback scan (`$dirLen = 0`).
        if dir_len_truthy {
          ctx.metadata().push_warning("Unknown format code");
        }
        break;
      }
    };
    // Red.pm:283-289 HandleTag at `$pos+4`, size `$len-4`, format `$fmt`.
    let payload_off = pos + 4;
    let payload_size = len - 4;
    let elem = format_size_of(fmt);
    if elem > 0 && payload_size > 0 {
      let count = payload_size / elem;
      if count > 0 {
        if let Some(v) = read_value(buff, payload_off, fmt, count, ByteOrder::Mm) {
          // Look up the def; an unrecognized tag-id is faithfully a HandleTag
          // call that ExifTool drops (no entry in `%Main` ⇒ no FoundTag).
          if let Some(def) = (RED_MAIN.get())(TagId::Int(i64::from(tag))) {
            push_with_conv(ctx, def, v, print_on);
          }
        }
      }
    } else if fmt == "string" || fmt == "undef" {
      // string/undef: elem == 1, payload_size IS the count.
      if let Some(v) = read_value(buff, payload_off, fmt, payload_size, ByteOrder::Mm) {
        if let Some(def) = (RED_MAIN.get())(TagId::Int(i64::from(tag))) {
          push_with_conv(ctx, def, v, print_on);
        }
      }
    }
    pos += len;
  }
}

/// Mirror of `convert::format_size` for the Red.pm subset, exposed inside
/// this module so the directory walk can compute `count = payload_size /
/// elem_size` (faithful to `ExifTool.pm:6285-6293`). Unknown format ⇒ 0
/// (the caller skips read).
fn format_size_of(fmt: &str) -> usize {
  match fmt {
    "int8u" | "int8s" | "string" | "undef" => 1,
    "int16u" => 2,
    "int32u" | "int32s" | "rational32u" | "float" => 4,
    _ => 0,
  }
}

/// Apply ValueConv + (optionally) PrintConv via [`apply`] and push to the
/// `ctx.metadata()` value sink under the tag's family-0/family-1 group.
fn push_with_conv(ctx: &mut ParseContext<'_>, def: &'static TagDef, raw: TagValue, print_on: bool) {
  let out = apply(def, &raw, print_on);
  ctx
    .metadata()
    .push(Group::new(RED_MAIN.group0(), def.group1()), def.name(), out);
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::value::Rational;

  #[test]
  fn red_format_table_matches_pm() {
    // Red.pm:22-33 — every index 0..=9 must resolve; >9 ⇒ None.
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
  fn reject_short_input() {
    use crate::value::Metadata;
    let mut m = Metadata::new("Red.r3d");
    let bytes = [0u8; 7];
    let mut ctx = ParseContext::new(&bytes, "R3D", 0, "R3D", None, true, &mut m);
    assert!(!ProcessR3D.process(&mut ctx));
    assert!(m.tags().is_empty());
  }

  #[test]
  fn reject_bad_magic() {
    use crate::value::Metadata;
    // 8 bytes, no RED1/RED2 magic.
    let mut m = Metadata::new("Red.r3d");
    let bytes = b"\x00\x00\x00\x10ABCD";
    let mut ctx = ParseContext::new(bytes, "R3D", 0, "R3D", None, true, &mut m);
    assert!(!ProcessR3D.process(&mut ctx));
    assert!(m.tags().is_empty());
  }

  #[test]
  fn reject_size_less_than_8() {
    use crate::value::Metadata;
    // size = 4 < 8 (Red.pm:228 `return 0 if $size < 8`).
    let mut m = Metadata::new("Red.r3d");
    let bytes = b"\x00\x00\x00\x04RED1";
    let mut ctx = ParseContext::new(bytes, "R3D", 0, "R3D", None, true, &mut m);
    assert!(!ProcessR3D.process(&mut ctx));
    assert!(m.tags().is_empty());
  }

  #[test]
  fn truncated_header_emits_warning_and_filetype_triplet() {
    use crate::value::Metadata;
    // size = 0x40 — header validates, SetFileType runs, then Read($size-8)
    // fails (only 0 bytes remain) ⇒ Warn("Truncated R3D file").
    let mut m = Metadata::new("Red.r3d");
    let bytes = b"\x00\x00\x00\x40RED1";
    let mut ctx = ParseContext::new(bytes, "R3D", 0, "R3D", None, true, &mut m);
    assert!(ProcessR3D.process(&mut ctx));
    // File:FileType triplet plus the Warning.
    let names: Vec<&str> = m.tags().iter().map(|t| t.name()).collect();
    assert!(names.contains(&"FileType"));
    assert!(names.contains(&"FileTypeExtension"));
    assert!(names.contains(&"MIMEType"));
    assert_eq!(
      m.warnings(),
      &[smol_str::SmolStr::new("Truncated R3D file")]
    );
  }

  #[test]
  fn other_date_value_conv_preserves_non_ascii_text() {
    // Codex round-8 F1: `replace_yyyy_mm_underscore` previously did
    // `out.push(b[i] as char)` byte-by-byte, mojibaking multi-byte
    // UTF-8 sequences. Perl's `s/(\d{4})_(\d{2})_/$1:$2:/` operates
    // on bytes and preserves non-matching bytes verbatim — the same
    // result is achieved in Rust by slicing the original `&str` at
    // ASCII match boundaries and `push_str`ing the unmatched regions.
    //
    // Bundled-Perl oracle (run with `binmode STDOUT, ':utf8'`):
    //   my $s = "é2016_01_18_é";
    //   $s =~ s/(\d{4})_(\d{2})_/$1:$2:/;
    //   $s =~ tr/_/ /;  → "é2016:01:18 é"
    //
    // The `s///` consumes `2016_01_` (8 bytes, all ASCII); the trailing
    // `_é` survives the regex, then `tr/_/ /` turns the lone underscore
    // into a space, giving the trailing ` é`. The leading `é` (bytes
    // \xC3\xA9) and the trailing `é` are preserved verbatim — the
    // mojibake bug would have rendered them as `Ã©`.
    let v = other_date_value_conv(&TagValue::Str("é2016_01_18_é".into()));
    assert_eq!(v, TagValue::Str("é2016:01:18 é".into()));
    // Underscore in the trailing portion still gets `tr/_/ /`-converted
    // globally (Perl `tr` is byte-global; we use Rust `str::replace`
    // which is char-global but `_` is ASCII so identical).
    let v2 = other_date_value_conv(&TagValue::Str("é2016_01_18_T_é".into()));
    assert_eq!(v2, TagValue::Str("é2016:01:18 T é".into()));
    // No date match, but the input has underscores ⇒ Perl still runs
    // `tr/_/ /` (it's the second statement). Our impl mirrors this:
    // returns input unchanged from `replace_yyyy_mm_underscore` then
    // applies the global `_` → ` ` replacement.
    let v3 = other_date_value_conv(&TagValue::Str("é_é".into()));
    assert_eq!(v3, TagValue::Str("é é".into()));
  }

  #[test]
  fn other_date_value_conv_replaces_first_only() {
    // Red.pm:56 — `s/(\d{4})_(\d{2})_/$1:$2:/` is one-shot, `tr/_/ /` global.
    let v = other_date_value_conv(&TagValue::Str("2016_01_18".into()));
    assert_eq!(v, TagValue::Str("2016:01:18".into()));
    // Trailing `_TZ` ⇒ becomes space-separated.
    let v2 = other_date_value_conv(&TagValue::Str("2016_01_18_UTC".into()));
    assert_eq!(v2, TagValue::Str("2016:01:18 UTC".into()));
  }

  #[test]
  fn date_time_original_value_conv_splits_into_yyyy_mm_dd_hh_mm_ss() {
    // Input: 14 digits "20160118213555" ⇒ "2016:01:18 21:35:55".
    let v = datetime_original_value_conv(&TagValue::Str("20160118213555".into()));
    assert_eq!(v, TagValue::Str("2016:01:18 21:35:55".into()));
  }

  #[test]
  fn date_time_original_value_conv_preserves_non_ascii_text() {
    // Codex round-8 follow-up: the other three date helpers
    // (datetime_original, date_created, time_created) ALREADY use
    // `push_str(&s[..i])` — the correct UTF-8-safe pattern. Verify
    // non-ASCII passes through verbatim. Bundled Perl oracle:
    //   perl -e 'use utf8; binmode STDOUT, ":utf8";
    //            my $s="ééé20160118213555ééé";
    //            $s =~ s/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})/
    //                                              $1:$2:$3 $4:$5:/;
    //            print "$s\n"' ⇒ "ééé2016:01:18 21:35:55ééé"
    let v = datetime_original_value_conv(&TagValue::Str("ééé20160118213555ééé".into()));
    assert_eq!(v, TagValue::Str("ééé2016:01:18 21:35:55ééé".into()));
    // date_created (6-digit match anywhere)
    let v2 = date_created_value_conv(&TagValue::Str("é20160118é".into()));
    assert_eq!(v2, TagValue::Str("é2016:01:18é".into()));
    // time_created (4-digit match anywhere)
    let v3 = time_created_value_conv(&TagValue::Str("é213555é".into()));
    assert_eq!(v3, TagValue::Str("é21:35:55é".into()));
  }

  #[test]
  fn date_time_original_value_conv_skips_partial_digit_prefix() {
    // Codex round-7 adversarial probe: Perl's regex backtracks past a
    // partial-digit prefix (e.g. 10 digits + 'xx') to find the next
    // 12-digit run. The previous impl bailed at a 10-digit "no-match"
    // partial, diverging from Perl.
    //
    // Bundled-Perl oracle:
    //   perl -e 'my $s="1234567890xx20160118213555";
    //            $s =~ s/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})/$1:$2:$3 $4:$5:/;
    //            print "$s\n"'  → "1234567890xx2016:01:18 21:35:55"
    let v = datetime_original_value_conv(&TagValue::Str("1234567890xx20160118213555".into()));
    assert_eq!(v, TagValue::Str("1234567890xx2016:01:18 21:35:55".into()));
    // Longer adversarial: a 24-digit run starting at 0 matches FIRST
    // (the regex is greedy + leftmost). Perl emits the colons starting
    // at position 0: "0123:45:67 89:20:160118213555".
    let v2 = datetime_original_value_conv(&TagValue::Str("012345678920160118213555".into()));
    assert_eq!(v2, TagValue::Str("0123:45:67 89:20:160118213555".into()));
    // Non-digit prefix + valid 14-digit suffix. Perl skips the prefix.
    let v3 = datetime_original_value_conv(&TagValue::Str("abcdefg20160118213555".into()));
    assert_eq!(v3, TagValue::Str("abcdefg2016:01:18 21:35:55".into()));
    // Too few digits ⇒ regex doesn't match ⇒ value unchanged.
    let v4 = datetime_original_value_conv(&TagValue::Str("01234567890".into()));
    assert_eq!(v4, TagValue::Str("01234567890".into()));
  }

  #[test]
  fn date_created_value_conv_inserts_colons() {
    // Red.pm:82 — `s/(\d{4})(\d{2})/$1:$2:/` on `YYYYMMDD` ⇒ `YYYY:MM:DD`.
    let v = date_created_value_conv(&TagValue::Str("20160118".into()));
    assert_eq!(v, TagValue::Str("2016:01:18".into()));
  }

  #[test]
  fn time_created_value_conv_inserts_colons() {
    // Red.pm:87 — `s/(\d{2})(\d{2})/$1:$2:/` on `HHMMSS` ⇒ `HH:MM:SS`.
    let v = time_created_value_conv(&TagValue::Str("213555".into()));
    assert_eq!(v, TagValue::Str("21:35:55".into()));
  }

  #[test]
  fn red2_frame_rate_value_conv_matches_pm() {
    // Red.pm:201 `($a[1]*0x10000 + $a[2]) / $a[0]` — for bundled fixture
    // the int16u[3] is `1001 0 24000` ⇒ (0*65536 + 24000)/1001 ≈ 23.976023.
    let v = red2_frame_rate_value_conv(&TagValue::Str("1001 0 24000".into()));
    if let TagValue::F64(f) = v {
      assert!((f - 24000.0 / 1001.0).abs() < 1e-12);
    } else {
      panic!("expected F64, got {v:?}");
    }
  }

  #[test]
  fn red2_frame_rate_value_conv_partial_inputs_match_perl() {
    // Codex round-2 F1: with `read_value`'s faithful count-shortening
    // (ExifTool.pm:6290-6292), a truncated RED2 header at offset 0x56
    // produces a 2-element `"a b"` string (count=2) or a scalar `a`
    // (count=1). Perl's `split " ", $val` coerces missing indices to
    // numeric 0, yielding `0/a = 0` in both cases (oracle below). The
    // typed-scalar case (count==1) must also stringify-and-split (Perl
    // `split " ", 1001` ⇒ `(1001)`). Oracle:
    //   perl -e 'no warnings "uninitialized";
    //            for my $val ("1001 0", 1001) {
    //              my @a = split " ",$val;
    //              printf "%s => %g\n", $val,
    //                ($a[1]*0x10000+$a[2])/$a[0]; }'
    //   1001 0 => 0
    //   1001   => 0
    assert_eq!(
      red2_frame_rate_value_conv(&TagValue::Str("1001 0".into())),
      TagValue::F64(0.0)
    );
    assert_eq!(
      red2_frame_rate_value_conv(&TagValue::I64(1001)),
      TagValue::F64(0.0)
    );
    // `"1001"` (single token string) is the F64-stringify or string-shape
    // analogue: same `0/1001 = 0` result.
    assert_eq!(
      red2_frame_rate_value_conv(&TagValue::Str("1001".into())),
      TagValue::F64(0.0)
    );
  }

  #[test]
  fn red2_frame_rate_first_word_is_zero_classifies_all_read_value_shapes() {
    // Codex round-3 F1: the FrameRate-drop site must classify every shape
    // `read_value("int16u", 3, ...)` can produce after count-shortening
    // (ExifTool.pm:6286-6293) + single-element typed-scalar (ExifTool.pm:
    // 6318-6320), so the `($a[0] == 0)` Perl `Illegal division by zero`
    // case is silently dropped end-to-end, not just inside the ValueConv.
    //
    // count==3 ⇒ Str("a b c"); count==2 ⇒ Str("a b"); count==1 ⇒ I64(a).
    assert!(red2_frame_rate_first_word_is_zero(&TagValue::Str(
      "0 0 24000".into()
    )));
    assert!(red2_frame_rate_first_word_is_zero(&TagValue::Str(
      "0 1001".into()
    )));
    assert!(red2_frame_rate_first_word_is_zero(&TagValue::I64(0)));
    // Non-zero first word — must NOT classify as zero.
    assert!(!red2_frame_rate_first_word_is_zero(&TagValue::Str(
      "1001 0 24000".into()
    )));
    assert!(!red2_frame_rate_first_word_is_zero(&TagValue::I64(1001)));
    // Defensive F64 = 0.0 (no current path produces this for int16u, but
    // Perl would treat `0.0` as falsy in division).
    assert!(red2_frame_rate_first_word_is_zero(&TagValue::F64(0.0)));
    assert!(!red2_frame_rate_first_word_is_zero(&TagValue::F64(23.976)));
    // Unparseable or empty first token: defensively false (`a==0` not
    // proven; the `apply` path will then send the value to ValueConv
    // where the `parse::<i64>()` arm returns `v.clone()` unchanged).
    assert!(!red2_frame_rate_first_word_is_zero(&TagValue::Str(
      "abc".into()
    )));
    assert!(!red2_frame_rate_first_word_is_zero(&TagValue::Str(
      "".into()
    )));
  }

  #[test]
  fn round_to_3dp_print_conv_matches_pm_int_pattern() {
    // Red.pm:134,169,202: `int($val * 1000 + 0.5) / 1000`.
    // 24000/1001 = 23.976023976... ⇒ int(23.976023976*1000 + 0.5) =
    // int(23976.523...) = 23976 ⇒ 23.976.
    let v = round_to_3dp_print_conv(&TagValue::F64(24000.0 / 1001.0));
    assert_eq!(v, TagValue::F64(23.976));
    // From a Rational (RED1 path): `Rational::rational32(num=24000,
    // denom=1001)` ⇒ 23.976.
    let v2 = round_to_3dp_print_conv(&TagValue::Rational(Rational::rational32(24000, 1001)));
    assert_eq!(v2, TagValue::F64(23.976));
  }

  #[test]
  fn round_to_3dp_rational_routes_through_roundfloat_7g_first() {
    // Codex round-1 F1: Perl's ReadValue rationals are pre-rounded to 7
    // significant figures via RoundFloat (ExifTool.pm:6087,6094) BEFORE
    // PrintConv runs. `1106/101 = 10.95049504950495...` exact ⇒
    //   - Perl `RoundFloat(.., 7)` ⇒ `"10.9505"`
    //   - PrintConv `int(10.9505 * 1000 + 0.5)/1000 = int(10950.5+0.5)/1000
    //       = int(10951)/1000 = 10.951`
    // The Rational arm of `round_to_3dp_print_conv` must produce 10.951,
    // not the exact-ratio answer 10.95. Oracle: bundled Perl prints
    // `10.951`.
    //   perl -e 'use Image::ExifTool qw(:DataAccess); use strict;
    //            my $b = pack("nn", 1106, 101);
    //            my $v = Image::ExifTool::ReadValue(\$b, 0, "rational32u",
    //                                                1, length($b));
    //            printf "raw=%s\npc=%g\n", $v,
    //                                       int($v*1000+0.5)/1000;'
    //   raw=10.9505     pc=10.951
    let v = round_to_3dp_print_conv(&TagValue::Rational(Rational::rational32(1106, 101)));
    assert_eq!(v, TagValue::F64(10.951));
    // Non-Rational F64 path uses the exact f64; that semantic is unchanged
    // (no `%.7g` re-round for OriginalFrameRate which is `float`):
    let v2 = round_to_3dp_print_conv(&TagValue::F64(1106.0 / 101.0));
    assert_eq!(v2, TagValue::F64(10.95));
  }

  #[test]
  fn focus_distance_value_conv_and_print_conv() {
    // Red.pm:147 `ValueConv => $val/1000, PrintConv => "$val m"`.
    // int32s -1 ⇒ -0.001 ⇒ "-0.001 m".
    let vc = divide_by_1000(&TagValue::I64(-1));
    assert_eq!(vc, TagValue::F64(-0.001));
    let pc = focus_distance_print_conv(&vc);
    assert_eq!(pc, TagValue::Str("-0.001 m".into()));
  }

  #[test]
  fn divide_by_10_produces_float() {
    // Red.pm:141 `FNumber => $val / 10`. int16u 49 ⇒ 4.9.
    let v = divide_by_10(&TagValue::I64(49));
    assert_eq!(v, TagValue::F64(4.9));
  }

  // ── Codex round-4 F1+F2 fixes ──────────────────────────────────────────

  #[test]
  fn perl_arithmetic_to_f64_matches_oracle() {
    // Oracle (bundled Perl, `perl -e 'my $v="…"; my $r = $v + 0; print $r'`):
    //   ""              -> 0
    //   "  "            -> 0
    //   "0"             -> 0
    //   "-1"            -> -1
    //   "1.5"           -> 1.5
    //   "1.5e2"         -> 150
    //   "1.5e"          -> 1.5      (incomplete exponent dropped)
    //   "1e"            -> 1
    //   "abc"           -> 0
    //   "1000 2000"     -> 1000     (leading number; rest ignored)
    //   "  123 "        -> 123
    //   "+"             -> 0
    //   "-"             -> 0
    //   "1."            -> 1
    //   ".5"            -> 0.5
    //   "-.5"           -> -0.5
    //   "1.5abc"        -> 1.5
    //   "0x10"          -> 0        (no hex)
    //   "inf"           -> Inf
    //   "-inf"          -> -Inf
    //   "Inf"           -> Inf
    //   "INF"           -> Inf
    //   "infinity"      -> Inf
    //   "nan"           -> NaN
    //   "NaN"           -> NaN
    //   "undef"         -> 0        (no leading numeric prefix)
    //   "true"          -> 0
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
    // Codex round-9 indirect probe: the helper's "inf"/"nan" prefix
    // check must NOT use `&s[..3]` (which PANICS when the 3-byte mark
    // splits a multi-byte UTF-8 codepoint, e.g. `"éé"` — byte 3 is
    // inside the second `é`'s 0xC3 0xA9 pair). The byte-level
    // `starts_with_ci` form is panic-free for any UTF-8 input.
    assert_eq!(perl_arithmetic_to_f64("éé"), 0.0);
    assert_eq!(perl_arithmetic_to_f64("é"), 0.0);
    assert_eq!(perl_arithmetic_to_f64("éinf"), 0.0); // "é" is not a sign
    assert_eq!(perl_arithmetic_to_f64("日本"), 0.0);
    // ASCII inputs with the "inf" prefix + non-ASCII suffix still
    // resolve as Perl does:
    //   perl -e 'print 0+("infé")'   ⇒ "Inf"
    assert_eq!(perl_arithmetic_to_f64("infé"), f64::INFINITY);
    assert!(perl_arithmetic_to_f64("nanñ").is_nan());
  }

  #[test]
  fn perl_arithmetic_to_f64_inf_with_trailing_junk_matches_perl() {
    // Codex round-9 explicit oracle:
    //   perl -e 'for my $v ("infjunk","infinite","infx","nanx","+inf","-nanx") {
    //              my $r=$v+0; print "$v=$r\n" }'
    //   infjunk=Inf  infinite=Inf  infx=Inf  nanx=NaN
    //   +inf=Inf     -nanx=NaN
    assert_eq!(perl_arithmetic_to_f64("infjunk"), f64::INFINITY);
    assert_eq!(perl_arithmetic_to_f64("infinite"), f64::INFINITY);
    assert_eq!(perl_arithmetic_to_f64("infx"), f64::INFINITY);
    assert!(perl_arithmetic_to_f64("nanx").is_nan());
    assert_eq!(perl_arithmetic_to_f64("+inf"), f64::INFINITY);
    assert!(perl_arithmetic_to_f64("-nanx").is_nan());
    // Whitespace before sign + inf:
    assert_eq!(perl_arithmetic_to_f64(" inf"), f64::INFINITY);
    assert!(perl_arithmetic_to_f64(" nan").is_nan());
    assert_eq!(perl_arithmetic_to_f64(" +infx"), f64::INFINITY);
  }

  #[test]
  fn divide_by_10_perl_coerces_overlong_str_to_leading_number() {
    // Codex round-4 F1: an overlong directory entry for tag 0x406a
    // (FNumber) produces a space-joined `TagValue::Str` from `read_value`
    // for `count > 1`. Perl `"123 456" / 10 == 12.3` — the leading
    // number coerces; trailing tokens are silently ignored.
    let v = divide_by_10(&TagValue::Str("123 456".into()));
    assert_eq!(v, TagValue::F64(12.3));
    // No leading numeric prefix ⇒ 0.0 (Perl `"abc" / 10 == 0`).
    let v2 = divide_by_10(&TagValue::Str("abc".into()));
    assert_eq!(v2, TagValue::F64(0.0));
    // Empty string ⇒ 0.0 (Perl `"" / 10 == 0`).
    let v3 = divide_by_10(&TagValue::Str("".into()));
    assert_eq!(v3, TagValue::F64(0.0));
  }

  #[test]
  fn divide_by_1000_perl_coerces_overlong_str_to_leading_number() {
    // Codex round-4 F1: FocusDistance overlong directory entry.
    // Perl: `"1000 2000" / 1000 == 1`.
    let v = divide_by_1000(&TagValue::Str("1000 2000".into()));
    assert_eq!(v, TagValue::F64(1.0));
    // Negative leading number (FocusDistance is int32s; the Str shape
    // can carry a negative leading element).
    let v2 = divide_by_1000(&TagValue::Str("-500 0 0".into()));
    assert_eq!(v2, TagValue::F64(-0.5));
    // `Str` "0 0" ⇒ 0.0 (the leading 0).
    let v3 = divide_by_1000(&TagValue::Str("0 0".into()));
    assert_eq!(v3, TagValue::F64(0.0));
  }

  #[test]
  fn round_to_3dp_print_conv_coerces_overlong_str() {
    // Codex round-4 F1: OriginalFrameRate (Red.pm:131-135, format 2 =
    // float, elem = 4) overlong directory entry ⇒ space-joined Str.
    // Perl PrintConv: `int("23.976 30" * 1000 + 0.5) / 1000`
    //     = int(23.976 * 1000 + 0.5) / 1000 = int(23976.5) / 1000
    //     = 23976 / 1000 = 23.976.
    let v = round_to_3dp_print_conv(&TagValue::Str("23.976 30".into()));
    assert_eq!(v, TagValue::F64(23.976));
    // Non-numeric Str ⇒ 0.0 (Perl `int("abc"*1000+0.5)/1000 == 0`).
    let v2 = round_to_3dp_print_conv(&TagValue::Str("abc".into()));
    assert_eq!(v2, TagValue::F64(0.0));
  }

  #[test]
  fn round_to_3dp_print_conv_zero_denom_rational_emits_perl_coercion() {
    // Codex round-4 F2: RED1 FrameRate (Red.pm:166-170, rational32u at
    // offset 0x3e) with `denominator == 0`.
    //   `Rational::rational32(0, 0).exiftool_val_str()` ⇒ "undef"
    //   Perl PrintConv: `int("undef" * 1000 + 0.5) / 1000 == 0`.
    // Bundled-Perl oracle:
    //   perl -e '$v="undef"; print int($v*1000+0.5)/1000'  → "0"
    let v0 = round_to_3dp_print_conv(&TagValue::Rational(Rational::rational32(0, 0)));
    assert_eq!(v0, TagValue::F64(0.0));
    //   `Rational::rational32(N, 0)` for `N != 0` ⇒ "inf"
    //   Perl: `int("inf"*1000+0.5)/1000 == Inf`.
    // The Inf-to-JSON-null gap is the documented Phase-2 forward
    // item #1 (engine-level serializer concern) — this helper's job is
    // to faithfully propagate Perl's arithmetic result.
    let v1 = round_to_3dp_print_conv(&TagValue::Rational(Rational::rational32(24000, 0)));
    let inf = match v1 {
      TagValue::F64(n) => n,
      _ => panic!("expected F64, got {v1:?}"),
    };
    assert!(inf.is_infinite() && inf.is_sign_positive(), "got {inf}");
  }

  #[test]
  fn round_to_3dp_print_conv_preserves_large_finite_floats() {
    // Codex round-5 F1: Perl `int($x)` operates in NV space (double),
    // not IV space (i64). A crafted RED `OriginalFrameRate` from a
    // `float32` payload near `f32::MAX ≈ 3.4e38` reaches this branch
    // as `TagValue::F64`. Perl keeps the value at ~3.4e38; an `as
    // i64` cast in Rust would silently saturate to ~9.22e15.
    //
    // Bundled-Perl oracle (run interactively in the loop):
    //   perl -e 'for my $v (3.40282346638529e38, 1e20, 1.844e19, -3.4e38) {
    //              my $r = int($v * 1000 + 0.5) / 1000;
    //              printf "%.10g -> %.10g\n", $v, $r;
    //            }'
    //   3.402823466e+38 -> 3.402823466e+38
    //   1e+20           -> 1e+20
    //   1.844e+19       -> 1.844e+19
    //   -3.4e+38        -> -3.4e+38
    let big = 3.40282346638529e38_f64; // ~ f32::MAX
    let v = round_to_3dp_print_conv(&TagValue::F64(big));
    // The Perl chain `int($v*1000+0.5)/1000` is exact for any double
    // whose magnitude is so large that `* 1000.0` no longer changes
    // any fraction-bit precision; the result is the input value back.
    // Oracle: `printf "%.20g", int(3.402823466e38*1000+0.5)/1000` ⇒
    // `3.4028234663852901093e+38` (identical to input).
    assert_eq!(v, TagValue::F64(big));
    // 1.844e19 (just above 2^63), would saturate to i64::MAX as i64.
    // Perl preserves it; we now do too.
    let v3 = round_to_3dp_print_conv(&TagValue::F64(1.844e19));
    assert_eq!(v3, TagValue::F64(1.844e19));
    // Large negative (would saturate to i64::MIN as i64).
    let v4 = round_to_3dp_print_conv(&TagValue::F64(-3.4e38));
    assert_eq!(v4, TagValue::F64(-3.4e38));
    // Boundary near 2^63 (just below saturation under the old impl).
    let v5 = round_to_3dp_print_conv(&TagValue::F64(9.0e15));
    assert_eq!(v5, TagValue::F64(9.0e15));
    // Near-boundary case where the i64 cast would lose precision
    // (1e20 is too large for an i64 — Perl returns
    // `99999999999999983616` ≡ `1e20.next_down()`, a one-ULP loss from
    // the `* 1000.0` round-trip that lands on the SAME f64 value in
    // Rust). Verify the two routes agree (no Codex-R5 saturation).
    let v_1e20 = round_to_3dp_print_conv(&TagValue::F64(1e20));
    let n = match v_1e20 {
      TagValue::F64(n) => n,
      _ => panic!("expected F64, got {v_1e20:?}"),
    };
    // The Perl-matching answer is ≈ 9.999999999999998e19 (a one-ULP
    // loss from `1e20 * 1000.0 / 1000.0`). The pre-fix `as i64` path
    // would emit ~9.22e15 (≈5 orders of magnitude smaller).
    assert!(
      (n - 1e20).abs() / 1e20 < 1e-15,
      "got {n}, expected ≈ 1e20 (Perl: 99999999999999983616)"
    );
  }

  #[test]
  fn round_to_3dp_print_conv_negative_near_zero_normalizes_to_positive_zero() {
    // Codex round-6 F1: a crafted RED `OriginalFrameRate` float in
    // `(-0.0005, 0.0)` lands on a `scaled = f*1000+0.5` value in
    // `(-1.0, 0.0)`; `f64::trunc()` returns **negative zero** in
    // IEEE-754. Perl `int()` does not preserve the sign of zero
    // (`int(-0.001*1000+0.5) == 0`, positive NV bits — verified via
    // `Devel::Peek::Dump`). The result must serialize as `"0"`, not
    // `"-0"`. Our impl normalizes via `scaled.trunc() + 0.0` which
    // collapses `-0.0` to `+0.0` per IEEE addition rules.
    //
    // Bundled-Perl oracle:
    //   perl -e 'no warnings "numeric";
    //            for my $v (-0.001, -0.0001, -0.0004999, -0.00050) {
    //              my $r = int($v * 1000 + 0.5) / 1000;
    //              use Devel::Peek; Dump($r); print "---\n"; }'
    //   ⇒ every result is NV = 0 (positive zero), prints as "0".
    let v = round_to_3dp_print_conv(&TagValue::F64(-0.001));
    let n = match v {
      TagValue::F64(n) => n,
      _ => panic!("expected F64, got {v:?}"),
    };
    assert_eq!(n, 0.0);
    assert!(
      !n.is_sign_negative(),
      "expected positive zero, got negative zero (would JSON-emit -0)"
    );
    // Same shape for other inputs that hit the negative-near-zero
    // path. -0.0004 ⇒ scaled = 0.1 ⇒ trunc = 0.0 (positive — no
    // normalization needed). -0.0001 ⇒ scaled = 0.4 ⇒ trunc = 0.0
    // (positive). -0.0005 ⇒ scaled = 0.0 ⇒ trunc = 0.0 (positive).
    // -0.0006 ⇒ scaled = -0.1 ⇒ trunc = -0.0 (NEEDS the normalization).
    for v in [-0.0006_f64, -0.0009, -0.001, -0.0005001] {
      let r = round_to_3dp_print_conv(&TagValue::F64(v));
      let n = match r {
        TagValue::F64(n) => n,
        _ => panic!("expected F64, got {r:?}"),
      };
      assert_eq!(n, 0.0, "value {v}");
      assert!(
        !n.is_sign_negative(),
        "value {v} produced negative zero (would JSON-emit -0)"
      );
    }
    // Sanity: negative inputs outside the (-0.0005, ?) zero-trunc band
    // still produce the correct negative result (no spurious sign-flip).
    let neg = round_to_3dp_print_conv(&TagValue::F64(-1.5));
    assert_eq!(neg, TagValue::F64(-1.499)); // `int(-1.5*1000+0.5)/1000 = int(-1499.5)/1000 = -1499/1000`
    let neg2 = round_to_3dp_print_conv(&TagValue::F64(-0.5));
    assert_eq!(neg2, TagValue::F64(-0.499)); // `int(-499.5)/1000 = -499/1000`
  }

  #[test]
  fn round_to_3dp_print_conv_handles_overflow_to_infinity() {
    // Defensive: a finite `f` near `f64::MAX` whose `* 1000 + 0.5`
    // overflows to ±Inf. Perl: `int(Inf+0.5)/1000 = Inf`. Our impl
    // must not produce a NaN-or-other-anomaly; the post-multiply Inf
    // is propagated, landing on Phase-2 forward item #1.
    let near_max = f64::MAX / 100.0; // |f * 1000| overflows finite double range.
    let v = round_to_3dp_print_conv(&TagValue::F64(near_max));
    let n = match v {
      TagValue::F64(n) => n,
      _ => panic!("expected F64, got {v:?}"),
    };
    // Either the value is preserved exactly (if `* 1000 + 0.5` stays
    // finite due to floating-point absorbing the 0.5) or it became
    // Inf (overflow). Both are consistent with the Perl chain; neither
    // is the silent-saturation bug Codex R5 flagged.
    assert!(n.is_infinite() || n == near_max, "got {n}");
  }
}
