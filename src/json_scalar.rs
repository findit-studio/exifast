//! Shared ExifTool scalar JSON encoders — the byte-exact `EscapeJSON`
//! transliteration used by BOTH the `Metadata`→JSON serializer
//! ([`crate::serialize`]) and the direct [`crate::json_writer::JsonTagWriter`].
//!
//! This is a faithful transliteration of ExifTool's scalar encoder
//! `EscapeJSON` (`exiftool` lines 3800-3831, with the `%jsonChar` table at
//! line 250) and the `FormatJSON` ARRAY branch (`exiftool` 3843-3855).
//! Extracted verbatim from `serialize.rs` so the two output paths share ONE
//! source of truth for the number-vs-quoted-string gate, string escaping,
//! the binary placeholder, the rational repr, and list framing — guaranteeing
//! they are byte-identical. Building the string directly (no `serde_json`
//! round-trip) keeps it byte-exact with ExifTool and infallible — there is no
//! error path, so `Bytes`/`Rational` can never fail the document.

use crate::value::{Rational, TagValue, format_g, perl_nonfinite_str};

/// ExifTool's `%jsonChar` short escapes (`exiftool` line 250):
/// `"` → `\"`, `\` → `\\`, TAB → `\t`, LF → `\n`, CR → `\r`.
fn json_short_escape(c: char) -> Option<&'static str> {
  match c {
    '"' => Some("\\\""),
    '\\' => Some("\\\\"),
    '\t' => Some("\\t"),
    '\n' => Some("\\n"),
    '\r' => Some("\\r"),
    _ => None,
  }
}

/// Faithful transliteration of ExifTool `EscapeJSON`'s number gate
/// (`exiftool` line 3809):
/// `/^-?(\d|[1-9]\d{1,14})(\.\d{1,16})?(e[-+]?\d{1,3})?$/i`.
///
/// ExifTool emits a (stringly-typed) value as a bare JSON number iff its text
/// matches this regex; otherwise it is quoted. We transliterate the regex by
/// hand (the crate has no regex dependency) so numeric-looking string values
/// are emitted bare exactly as ExifTool does (e.g. an `Aperture` PrintConv of
/// `"3.5"` → bare `3.5`).
#[must_use]
pub fn is_json_number_literal(s: &str) -> bool {
  let b = s.as_bytes();
  let mut i = 0;
  // -?
  if i < b.len() && b[i] == b'-' {
    i += 1;
  }
  // (\d | [1-9]\d{1,14})  — a lone digit, OR 2..=15 digits with no leading 0
  let int_start = i;
  if i >= b.len() || !b[i].is_ascii_digit() {
    return false;
  }
  if b[i] == b'0' {
    // lone `0` only (the `\d` alternative); `[1-9]…` forbids leading zero.
    i += 1;
  } else {
    // [1-9]\d{1,14}  → 2..=15 digits total, or the single-digit `\d` form.
    i += 1;
    let mut extra = 0;
    while i < b.len() && b[i].is_ascii_digit() && extra < 14 {
      i += 1;
      extra += 1;
    }
    // total integer digits = 1 (single \d) or 2..=15; reject 16+.
    if i < b.len() && b[i].is_ascii_digit() {
      return false;
    }
  }
  debug_assert!(i > int_start);
  // (\.\d{1,16})?
  if i < b.len() && b[i] == b'.' {
    i += 1;
    let frac_start = i;
    let mut n = 0;
    while i < b.len() && b[i].is_ascii_digit() && n < 16 {
      i += 1;
      n += 1;
    }
    if i == frac_start || (i < b.len() && b[i].is_ascii_digit()) {
      return false; // need 1..=16 fraction digits
    }
  }
  // (e[-+]?\d{1,3})?  (case-insensitive `e`)
  if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
    i += 1;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
      i += 1;
    }
    let exp_start = i;
    let mut n = 0;
    while i < b.len() && b[i].is_ascii_digit() && n < 3 {
      i += 1;
      n += 1;
    }
    if i == exp_start || (i < b.len() && b[i].is_ascii_digit()) {
      return false; // need 1..=3 exponent digits
    }
  }
  i == b.len()
}

/// Quote and escape a string exactly as ExifTool `EscapeJSON` does for the
/// non-numeric path (`exiftool` lines 3816-3830, JSON branch):
/// short escapes for `" \ \t \n \r`, NULs deleted, other C0 controls and DEL
/// (`\x00-\x1f`, `\x7f`) as `\uXXXX` (upper-case hex). The input is already
/// valid UTF-8 (`String`), so `FixUTF8` is a no-op.
pub fn push_json_string(out: &mut String, s: &str) {
  out.push('"');
  for c in s.chars() {
    if let Some(esc) = json_short_escape(c) {
      out.push_str(esc);
    } else if c == '\0' {
      // ExifTool: `tr/\0//d` — NULs are removed entirely.
    } else if (c as u32) <= 0x1f || (c as u32) == 0x7f {
      // ExifTool: sprintf("\\u%.4X", ord $1)
      out.push_str(&format!("\\u{:04X}", c as u32));
    } else {
      out.push(c);
    }
  }
  out.push('"');
}

/// ExifTool's numeric value for a rational (ExifTool.pm `GetRational*`
/// lines 6081-6109): `num/denom` rounded to significant figures via the
/// shared [`crate::value::format_g`] (`%.{sig}g`, `$sig` = 7 for a
/// rational32 `ExifTool.pm:6087,6094`, 10 for a rational64
/// `ExifTool.pm:6101,6108`, carried on [`Rational::sig`]). A zero
/// denominator yields the bare word `inf` (numerator ≠ 0) or `undef`
/// (numerator == 0). Those words are not JSON numbers, so ExifTool's
/// `EscapeJSON` emits them as the quoted strings `"inf"` / `"undef"`.
///
/// Returns `(text, is_number)`: `is_number` is `false` for the `inf`/`undef`
/// words (→ quoted string) and `true` for a numeric token (→ bare number).
/// The text itself is [`Rational::exiftool_val_str`] — the single source of
/// truth shared with the PrintConv-hash lookup so a hash key (`$$conv{$val}`)
/// matches what the serializer prints.
fn rational_repr(r: &Rational) -> (String, bool) {
  let is_number = r.denominator() != 0;
  (r.exiftool_val_str(), is_number)
}

/// Append a `TagValue` as its faithful ExifTool JSON encoding.
///
/// Every variant is representable, so this is infallible — `Bytes` and
/// `Rational` can never fail the document (matching `exiftool -j`, which never
/// aborts a file because a tag is binary or rational).
pub fn push_value(out: &mut String, v: &TagValue) {
  match v {
    // ExifTool feeds the STRING form of every scalar through `EscapeJSON`'s
    // one number gate (`exiftool:3809`
    // `/^-?(\d|[1-9]\d{1,14})(\.\d{1,16})?(e[-+]?\d{1,3})?$/i`): bare iff it
    // matches, else the quoted-string branch (`exiftool:3830`
    // `'"' . $str . '"'`). A typed integer is no exception — Perl
    // stringifies it (`"$n"`) and runs the same gate, so a >15-digit
    // integer (`i64::MIN`/`MAX`, any 16+-digit value) is QUOTED, not bare.
    // Verified against the bundled Perl regex (see tests).
    TagValue::I64(n) => push_numeric_gated(out, &n.to_string()),
    // Same gate for an unsigned 64-bit integer: Perl stringifies (`"$n"`)
    // and runs the line-3809 number gate, so a u64 above `i64::MAX` (19-20
    // digits) is QUOTED — but with its EXACT decimal value, not the
    // saturated `i64::MAX`. Verified against the bundled Perl regex: u64::MAX
    // `18446744073709551615` → quoted exact (see tests).
    TagValue::U64(n) => push_numeric_gated(out, &n.to_string()),
    // Same gate for floats: ExifTool stringifies (`%.15g`-ish) then runs
    // line 3809. `format_g(_, 15)` fixed-notation can exceed the regex's
    // `\d{1,16}` fraction cap (e.g. `sprintf("%.15g",10/2134)` =
    // `0.00468603561387067`, 17 frac digits → Perl QUOTES it), so route
    // through the gate rather than assuming bare. Bundled-Perl verified.
    TagValue::F64(n) => {
      if n.is_finite() {
        push_numeric_gated(out, &format_g(*n, 15));
      } else {
        // ExifTool never emits a non-finite bare token; quote it. Codex R8
        // fix: use Perl's titlecase `Inf`/`-Inf`/`NaN` form (verified
        // 2026-05-20 via `perl -e 'print 1e308*1e308'`), NOT Rust's
        // lowercase `inf`/`-inf` from `f64::to_string`. `perl_nonfinite_str`
        // covers every non-finite f64 (NaN/+Inf/-Inf — IEEE-754 has no other
        // non-finite category), so the `None` arm is unreachable while the
        // outer `is_finite` gate holds. Fall back to Rust's default
        // stringification rather than emit a hard-to-debug empty string if
        // a future refactor ever routes a finite value into this branch
        // (would surface as visibly lowercase `inf`/`-inf` in the JSON,
        // failing the conformance gate loudly instead of silently emitting
        // `""`).
        match perl_nonfinite_str(*n) {
          Some(s) => push_json_string(out, s),
          None => push_json_string(out, &n.to_string()),
        }
      }
    }
    TagValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
    // ExifTool's value strings are stringly-typed: `EscapeJSON` emits them
    // bare when they look like a JSON number or `true`/`false`, else quoted.
    TagValue::Str(s) => {
      if is_json_number_literal(s) {
        out.push_str(s);
      } else if s.eq_ignore_ascii_case("true") {
        out.push_str("true");
      } else if s.eq_ignore_ascii_case("false") {
        out.push_str("false");
      } else {
        push_json_string(out, s);
      }
    }
    // ExifTool universal no-`-b` placeholder. Verified against the bundled
    // tool (see tests): `(Binary data <N> bytes, use -b option to extract)`
    // where N is the byte length. It is a plain string, never numeric.
    TagValue::Bytes(b) => {
      let placeholder = format!("(Binary data {} bytes, use -b option to extract)", b.len());
      push_json_string(out, &placeholder);
    }
    // ExifTool default rational = its numeric value (or "inf"/"undef").
    // The numeric token still passes through `EscapeJSON`'s gate
    // (`exiftool:3809`); `inf`/`undef` are non-numeric so the gate quotes
    // them anyway, matching `rational_repr`'s `is_number == false`.
    TagValue::Rational(r) => {
      let (text, _is_number) = rational_repr(r);
      push_numeric_gated(out, &text);
    }
    TagValue::List(items) => {
      // ExifTool `FormatJSON` ARRAY branch (`exiftool` 3843-3855):
      // `[`, comma-separated elements, `]` (no internal newlines).
      out.push('[');
      for (i, item) in items.iter().enumerate() {
        if i > 0 {
          out.push(',');
        }
        push_value(out, item);
      }
      out.push(']');
    }
  }
}

/// Emit an already-stringified numeric token exactly as ExifTool's
/// `EscapeJSON` would (`exiftool` lines 3808-3830): a bare token iff it passes
/// the number gate ([`is_json_number_literal`], the line-3809 regex), otherwise
/// the quoted-and-escaped string branch ([`push_json_string`],
/// `'"' . $str . '"'`). This is the single funnel every scalar's string form
/// goes through in ExifTool, so integers/floats/rationals are all faithful.
pub fn push_numeric_gated(out: &mut String, s: &str) {
  if is_json_number_literal(s) {
    out.push_str(s);
  } else {
    push_json_string(out, s);
  }
}
