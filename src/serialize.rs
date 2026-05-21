//! Serialize `Metadata` to the exact JSON shape of `exiftool -j -G1`.
//!
//! This is a faithful transliteration of ExifTool's JSON writer: the document
//! framing of `exiftool` (the `-j` `$fileHeader`/`$fileTrailer` and the
//! per-file/per-tag layout, `exiftool` lines 1647-1654, 2673-2680, 2946-2954,
//! 3088-3090) and the scalar encoder `EscapeJSON` (`exiftool` lines 3800-3831,
//! with the `%jsonChar` table at line 250). Building the string directly (no
//! `serde_json` round-trip) keeps it byte-exact with ExifTool and infallible —
//! there is no error path, so `Bytes`/`Rational` can never fail the document.

use crate::value::{Metadata, Rational, TagValue, format_g, perl_nonfinite_str};
use std::collections::HashSet;

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
fn is_json_number_literal(s: &str) -> bool {
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
fn push_json_string(out: &mut String, s: &str) {
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
fn push_value(out: &mut String, v: &TagValue) {
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
fn push_numeric_gated(out: &mut String, s: &str) {
  if is_json_number_literal(s) {
    out.push_str(s);
  } else {
    push_json_string(out, s);
  }
}

/// Serialize to the JSON string of `exiftool -j -G1`: the single-element array
/// `[{ … }]\n`, `SourceFile` first, then `"<Group1>:<Name>"` keys in
/// extraction order. Infallible — every `TagValue` (including `Bytes` and
/// `Rational`) has a faithful representation, so a document is never failed.
///
/// Duplicate-token suppression (`%noDups`, ExifTool `exiftool:2945-2952`):
/// the script's JSON branch computes `my $tok = $allGroup ? "$group:$tagName"
/// : $tagName;` then `next if $noDups{$tok}; $noDups{$tok} = 1;`. We always
/// run with `-G1` (`$allGroup` true), so `$tok` is `"<family1>:<name>"`. The
/// FIRST tag with a given token is emitted; every later tag resolving to the
/// SAME token is dropped entirely (no key, no value) — exactly `next if
/// $noDups{$tok}`. `SourceFile` is printed before the per-tag loop in
/// ExifTool and never enters `%noDups`, so it is emitted first as today.
///
/// Warnings are emitted as ExifTool's generated `Warning` tag. `Image::
/// ExifTool::Extra` defines `Warning => { Priority => 0, Groups =>
/// \%allGroupsExifTool … }` (`ExifTool.pm:1297`) and `%allGroupsExifTool =
/// ( 0 => 'ExifTool', 1 => 'ExifTool', 2 => 'ExifTool' )`
/// (`ExifTool.pm:1225`). With `-G1` (`$allGroup`) the JSON token is
/// `$group:$tagName` (`exiftool:2948`) ⇒ exactly `"ExifTool:Warning"`. It
/// joins the SAME `%noDups` set (`exiftool:2951`), so it is first-wins and a
/// pre-existing `ExifTool:Warning` token (unlikely) suppresses it. Default
/// `-j -G1` emits only the FIRST warning: `%noDups` is keyed solely by the
/// token (`exiftool:2948,2951`) and ExifTool's ` (N)` copy-suffix
/// suppression (`exiftool:2744`) drops the `Warning (1)`, `Warning (2)`, …
/// duplicates — matching `ExifTool.pm:1300`'s note ("Use the -a … to see all
/// warnings if more than one occurred"). The multi-warning `-a`/Duplicates
/// mode and the ` (N)` copy-suffix mechanic are NOT modelled here (the
/// golden harness uses default `-j -G1`), so only the first warning is
/// emitted, deferring those nuances.
#[must_use]
pub fn to_exiftool_json(m: &Metadata) -> String {
  // ExifTool framing: `$fileHeader = '['` (exiftool 1649); per file
  // `{\n  "SourceFile": …` (exiftool 2678) then `,\n  "tok": v` per tag
  // (exiftool 2953-2954, $ind = '  '); close `\n}` (exiftool 3090);
  // `$fileTrailer = "]\n"` (exiftool 1650).
  let mut out = String::new();
  out.push('[');
  out.push('{');
  out.push_str("\n  \"SourceFile\": ");
  push_json_string(&mut out, m.source_file());
  // ExifTool `%noDups` (exiftool:2950-2951 `next if $noDups{$tok};
  // $noDups{$tok} = 1;`): first occurrence of a "<family1>:<name>" token
  // wins; later same-token tags are skipped entirely (no key, no value).
  let mut seen: HashSet<String> = HashSet::new();
  for t in m.tags() {
    // exiftool:2947 `my $tok = $allGroup ? "$group:$tagName" : $tagName;`
    // (`-G1` => $allGroup true => "<family1>:<name>").
    let tok = format!("{}:{}", t.group().family1(), t.name());
    // exiftool:2950 `next if $noDups{$tok};` — first wins, drop the rest.
    if !seen.insert(tok.clone()) {
      continue;
    }
    out.push_str(",\n  ");
    push_json_string(&mut out, &tok);
    out.push_str(": ");
    push_value(&mut out, t.value());
  }
  // ExifTool's generated `Warning` tag: group1 = `ExifTool`
  // (`ExifTool.pm:1225,1297`) ⇒ `-G1` token `"ExifTool:Warning"`
  // (`exiftool:2948`). Joins the SAME `%noDups` set (`exiftool:2951`,
  // first-wins): a pre-existing `ExifTool:Warning` token suppresses this,
  // and only ONE is ever emitted. Default `-j -G1` shows just the FIRST
  // warning (the ` (N)` copy-suffix duplicates are dropped,
  // `exiftool:2744`; `-a`/Duplicates is not modelled — see fn doc), so we
  // emit `m.warnings()[0]` via the SAME escaped string path.
  if let Some(first) = m.warnings().first() {
    let tok = "ExifTool:Warning".to_string();
    if seen.insert(tok.clone()) {
      out.push_str(",\n  ");
      push_json_string(&mut out, &tok);
      out.push_str(": ");
      push_json_string(&mut out, first);
    }
  }
  // ExifTool's generated `Error` tag: defined in `Image::ExifTool::Extra`
  // (`ExifTool.pm:1288-1296`) with `Groups => \%allGroupsExifTool`
  // (`ExifTool.pm:1225`) — group1 `ExifTool`, exactly like `Warning`
  // (`ExifTool.pm:1297`). `sub Error` (`ExifTool.pm:5648`) is the plain
  // `$self->FoundTag('Error', $str)` on the read path (no DemoteErrors /
  // IgnoreMinorErrors options here). With `-G1` the JSON token is
  // `$group:$tagName` (`exiftool:2948`) ⇒ exactly `"ExifTool:Error"`. It
  // joins the SAME `%noDups` set (`exiftool:2951`) INDEPENDENTLY of the
  // Warning token (distinct tokens), first-wins; default `-j -G1` shows
  // only the FIRST error (the ` (N)` copy-suffix dups are dropped,
  // `exiftool:2744`; `-a`/Duplicates not modelled — see fn doc), so we
  // emit `m.errors()[0]` via the SAME EscapeJSON string path as Warning.
  if let Some(first) = m.errors().first() {
    let tok = "ExifTool:Error".to_string();
    if seen.insert(tok.clone()) {
      out.push_str(",\n  ");
      push_json_string(&mut out, &tok);
      out.push_str(": ");
      push_json_string(&mut out, first);
    }
  }
  out.push_str("\n}");
  out.push_str("]\n");
  out
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::value::{Group, Metadata, Rational, TagValue};

  #[test]
  fn shape_matches_exiftool_j_g1() {
    let mut m = Metadata::new("a.aac");
    m.push(
      Group::new("Audio", "AAC"),
      "SampleRate",
      TagValue::I64(44100),
    );
    m.push(
      Group::new("Audio", "AAC"),
      "AudioBitrate",
      TagValue::Str("128 kbps".into()),
    );
    let s = to_exiftool_json(&m);
    // Byte-exact with real `exiftool -j -G1` framing: `[{\n  "K": v,…\n}]\n`
    // (verified via `od -c` on the bundled tool's output).
    let expected = "[{\n  \"SourceFile\": \"a.aac\",\n  \"AAC:SampleRate\": 44100,\n  \"AAC:AudioBitrate\": \"128 kbps\"\n}]\n";
    assert_eq!(s, expected);
  }

  #[test]
  fn bytes_value_is_exiftool_binary_placeholder() {
    let mut m = Metadata::new("a.jpg");
    m.push(
      Group::new("EXIF", "IFD0"),
      "ThumbnailImage",
      TagValue::Bytes(vec![1, 2, 3]),
    );
    let s = to_exiftool_json(&m);
    // Exact ExifTool wording (bundled-tool verified, N = byte length).
    assert!(
      s.contains("\"IFD0:ThumbnailImage\": \"(Binary data 3 bytes, use -b option to extract)\""),
      "got: {s}"
    );
  }

  #[test]
  fn rational_value_is_numeric() {
    let mut m = Metadata::new("a.jpg");
    // 86/10 = 8.6 (e.g. FocalLength, a rational64); -n emits bare number.
    m.push(
      Group::new("EXIF", "IFD0"),
      "FocalLength",
      TagValue::Rational(Rational::rational64(86, 10)),
    );
    let s = to_exiftool_json(&m);
    assert!(s.contains("\"IFD0:FocalLength\": 8.6"), "got: {s}");
    assert!(
      !s.contains("\"8.6\""),
      "rational must be a bare number: {s}"
    );
  }

  #[test]
  fn rational_matches_exiftool_roundfloat_10g() {
    // ExposureTime 10/2134 is a rational64 (32/32). Bundled Perl
    // `Image::ExifTool::RoundFloat(10/2134,10)` => 0.004686035614
    // (= sprintf("%.10g", 10/2134)). Pin the byte-exact numeric token.
    let mut m = Metadata::new("a.jpg");
    m.push(
      Group::new("ExifIFD", "ExifIFD"),
      "ExposureTime",
      TagValue::Rational(Rational::rational64(10, 2134)),
    );
    let s = to_exiftool_json(&m);
    assert!(
      s.contains("\"ExifIFD:ExposureTime\": 0.004686035614"),
      "got: {s}"
    );
  }

  #[test]
  fn rational32_vs_rational64_width_is_byte_exact_vs_perl_roundfloat() {
    // FIX 3 (D10 r10): a rational carries ExifTool's `RoundFloat` width.
    // Verified against bundled Perl ExifTool:
    //   perl -Ilib -MImage::ExifTool -e \
    //     'print Image::ExifTool::RoundFloat(1/3,7),"\n",
    //            Image::ExifTool::RoundFloat(1/3,10),"\n",
    //            Image::ExifTool::RoundFloat(10/2134,7),"\n",
    //            Image::ExifTool::RoundFloat(10/2134,10),"\n"'
    //   => 0.3333333 / 0.3333333333 / 0.004686036 / 0.004686035614
    let mut m = Metadata::new("a.jpg");
    // rational32 (sig=7): GetRational32s/u, ExifTool.pm:6087,6094.
    m.push(
      Group::new("EXIF", "IFD0"),
      "R32Third",
      TagValue::Rational(Rational::rational32(1, 3)),
    );
    // rational64 (sig=10): GetRational64s/u, ExifTool.pm:6101,6108.
    m.push(
      Group::new("EXIF", "IFD0"),
      "R64Third",
      TagValue::Rational(Rational::rational64(1, 3)),
    );
    // A second non-terminating case (10/2134) at both widths.
    m.push(
      Group::new("EXIF", "IFD0"),
      "R32Exp",
      TagValue::Rational(Rational::rational32(10, 2134)),
    );
    m.push(
      Group::new("EXIF", "IFD0"),
      "R64Exp",
      TagValue::Rational(Rational::rational64(10, 2134)),
    );
    let s = to_exiftool_json(&m);
    // Byte-identical to the Perl RoundFloat outputs above.
    assert!(s.contains("\"IFD0:R32Third\": 0.3333333"), "got: {s}");
    assert!(s.contains("\"IFD0:R64Third\": 0.3333333333"), "got: {s}");
    assert!(s.contains("\"IFD0:R32Exp\": 0.004686036"), "got: {s}");
    assert!(s.contains("\"IFD0:R64Exp\": 0.004686035614"), "got: {s}");
    // The 7-sig form must NOT carry the 10-sig tail (true width separation).
    assert!(
      !s.contains("\"IFD0:R32Third\": 0.3333333333"),
      "rational32 must be 7 sig, got: {s}"
    );
  }

  #[test]
  fn rational_zero_denominator_is_undef_or_inf_string() {
    // ExifTool: 0/0 → "undef", n/0 (n!=0) → "inf", both as JSON strings
    // (bundled tool: Casio2.jpg DigitalZoomRatio = undef (0/0)).
    let mut m = Metadata::new("a.jpg");
    m.push(
      Group::new("ExifIFD", "ExifIFD"),
      "DigitalZoomRatio",
      TagValue::Rational(Rational::rational64(0, 0)),
    );
    m.push(
      Group::new("ExifIFD", "ExifIFD"),
      "Bad",
      TagValue::Rational(Rational::rational64(1, 0)),
    );
    let s = to_exiftool_json(&m);
    assert!(
      s.contains("\"ExifIFD:DigitalZoomRatio\": \"undef\""),
      "got: {s}"
    );
    assert!(s.contains("\"ExifIFD:Bad\": \"inf\""), "got: {s}");
  }

  #[test]
  fn list_containing_bytes_and_rational_serializes() {
    let mut m = Metadata::new("a.jpg");
    m.push(
      Group::new("EXIF", "IFD0"),
      "MixedList",
      TagValue::List(vec![
        TagValue::I64(1),
        TagValue::Bytes(vec![0_u8; 5]),
        TagValue::Rational(Rational::rational64(1, 2)),
      ]),
    );
    let s = to_exiftool_json(&m);
    // ExifTool FormatJSON ARRAY: `[1,"(Binary data 5 bytes…)",0.5]`.
    assert!(
      s.contains("\"IFD0:MixedList\": [1,\"(Binary data 5 bytes, use -b option to extract)\",0.5]"),
      "got: {s}"
    );
  }

  #[test]
  fn numeric_looking_string_is_emitted_bare() {
    // ExifTool EscapeJSON coerces numeric-looking strings to bare numbers
    // (e.g. Aperture PrintConv "3.5" → 3.5; bundled-tool verified).
    let mut m = Metadata::new("a.jpg");
    m.push(
      Group::new("EXIF", "ExifIFD"),
      "Aperture",
      TagValue::Str("3.5".into()),
    );
    m.push(
      Group::new("EXIF", "ExifIFD"),
      "ISO",
      TagValue::Str("100".into()),
    );
    m.push(
      Group::new("Composite", "Composite"),
      "Megapixels",
      TagValue::Str("6.4e-05".into()),
    );
    // Leading zero / 16+ digits do NOT match ExifTool's number gate.
    m.push(
      Group::new("File", "System"),
      "Version",
      TagValue::Str("01".into()),
    );
    let s = to_exiftool_json(&m);
    assert!(s.contains("\"ExifIFD:Aperture\": 3.5"), "got: {s}");
    assert!(s.contains("\"ExifIFD:ISO\": 100"), "got: {s}");
    assert!(s.contains("\"Composite:Megapixels\": 6.4e-05"), "got: {s}");
    assert!(
      s.contains("\"System:Version\": \"01\""),
      "leading zero stays string: {s}"
    );
  }

  #[test]
  fn boolean_string_true_false_coerced_like_exiftool() {
    let mut m = Metadata::new("a.jpg");
    m.push(Group::new("X", "X"), "A", TagValue::Str("true".into()));
    m.push(Group::new("X", "X"), "B", TagValue::Str("FALSE".into()));
    m.push(Group::new("X", "X"), "C", TagValue::Bool(true));
    let s = to_exiftool_json(&m);
    assert!(s.contains("\"X:A\": true"), "got: {s}");
    assert!(s.contains("\"X:B\": false"), "got: {s}");
    assert!(s.contains("\"X:C\": true"), "got: {s}");
  }

  #[test]
  fn string_escaping_matches_escapejson() {
    let mut m = Metadata::new("a.jpg");
    m.push(
      Group::new("X", "X"),
      "S",
      TagValue::Str("tab\there\"q\\b\nnl\u{1}\u{7f}\0z".into()),
    );
    let s = to_exiftool_json(&m);
    // " \ \t \n short-escaped; \x01 and DEL as \uXXXX; NUL removed.
    assert!(
      s.contains("\"X:S\": \"tab\\there\\\"q\\\\b\\nnl\\u0001\\u007Fz\""),
      "got: {s}"
    );
  }

  #[test]
  fn format_g_matches_perl_sprintf_10g() {
    // Cross-checked against bundled perl `sprintf("%.10g", …)`.
    assert_eq!(format_g(0.004686035614245549, 10), "0.004686035614");
    assert_eq!(format_g(300.0, 10), "300");
    assert_eq!(format_g(3.5, 10), "3.5");
    assert_eq!(format_g(1.0 / 3.0, 10), "0.3333333333");
    assert_eq!(format_g(1234567890123.0, 10), "1.23456789e+12");
    assert_eq!(format_g(1e-5, 10), "1e-05");
    assert_eq!(format_g(1e21, 10), "1e+21");
    assert_eq!(format_g(0.0, 10), "0");
    assert_eq!(format_g(-0.0, 10), "-0");
    assert_eq!(format_g(0.0001, 10), "0.0001");
    assert_eq!(format_g(9.999999999e-5, 10), "9.999999999e-05");
    assert_eq!(format_g(-7.25, 10), "-7.25");
  }

  #[test]
  fn is_json_number_literal_matches_exiftool_gate() {
    // Matches `/^-?(\d|[1-9]\d{1,14})(\.\d{1,16})?(e[-+]?\d{1,3})?$/i`.
    assert!(is_json_number_literal("0"));
    assert!(is_json_number_literal("-3"));
    assert!(is_json_number_literal("3.5"));
    assert!(is_json_number_literal("44100"));
    assert!(is_json_number_literal("6.4e-05"));
    assert!(is_json_number_literal("1E3"));
    assert!(is_json_number_literal("123456789012345")); // 15 digits ok
    assert!(!is_json_number_literal("01")); // leading zero
    assert!(!is_json_number_literal("1234567890123456")); // 16 digits
    assert!(!is_json_number_literal("")); // empty
    assert!(!is_json_number_literal("1.")); // no fraction digits
    assert!(!is_json_number_literal("1e")); // no exponent digits
    assert!(!is_json_number_literal("128 kbps"));
    assert!(!is_json_number_literal("+5")); // leading + not allowed
    assert!(!is_json_number_literal("1.2.3"));
  }

  #[test]
  fn i64_runs_through_exiftool_escapejson_number_gate() {
    // ExifTool `EscapeJSON` (exiftool:3808-3830) feeds the STRING form of
    // every scalar through the line-3809 gate
    //   /^-?(\d|[1-9]\d{1,14})(\.\d{1,16})?(e[-+]?\d{1,3})?$/i
    // bare iff it matches, else quoted (`'"' . $str . '"'`). A typed
    // integer is no exception. Each boundary below was validated against
    // the BUNDLED Perl regex via (env-var so leading `-` isn't a CLI flag):
    //   V=<value> perl -e '$s=$ENV{V};
    //     print(($s =~ /^-?(\d|[1-9]\d{1,14})(\.\d{1,16})?(e[-+]?\d{1,3})?$/i)
    //       ? "BARE":"QUOTED")'
    // Observed (commands run in /Users/user/Develop/findit-studio/exiftool):
    //   0                     => BARE
    //   1                     => BARE
    //   9                     => BARE
    //   42                    => BARE
    //   -1                    => BARE
    //   -42                   => BARE
    //   999999999999999  (15) => BARE
    //   -999999999999999 (15) => BARE
    //   1000000000000000 (16) => QUOTED
    //   1234567890123456 (16) => QUOTED
    //   9223372036854775807   => QUOTED   (i64::MAX, 19 digits)
    //   -9223372036854775808  => QUOTED   (i64::MIN, 19 digits)
    let mut m = Metadata::new("a.jpg");
    m.push(Group::new("X", "X"), "Zero", TagValue::I64(0));
    m.push(Group::new("X", "X"), "NegOne", TagValue::I64(-1));
    m.push(Group::new("X", "X"), "FortyTwo", TagValue::I64(42));
    m.push(
      Group::new("X", "X"),
      "D15",
      TagValue::I64(999_999_999_999_999),
    );
    m.push(
      Group::new("X", "X"),
      "D15Neg",
      TagValue::I64(-999_999_999_999_999),
    );
    m.push(
      Group::new("X", "X"),
      "D16",
      TagValue::I64(1_000_000_000_000_000),
    );
    m.push(
      Group::new("X", "X"),
      "D16b",
      TagValue::I64(1_234_567_890_123_456),
    );
    m.push(Group::new("X", "X"), "Max", TagValue::I64(i64::MAX));
    m.push(Group::new("X", "X"), "Min", TagValue::I64(i64::MIN));
    let s = to_exiftool_json(&m);
    // ≤15-digit integers: BARE (exactly as the Perl regex above).
    assert!(
      s.contains("\"X:Zero\": 0\n") || s.contains("\"X:Zero\": 0,"),
      "got: {s}"
    );
    assert!(s.contains("\"X:NegOne\": -1,"), "got: {s}");
    assert!(s.contains("\"X:FortyTwo\": 42,"), "got: {s}");
    assert!(
      s.contains("\"X:D15\": 999999999999999,"),
      "15-digit bare: {s}"
    );
    assert!(
      s.contains("\"X:D15Neg\": -999999999999999,"),
      "15-digit bare: {s}"
    );
    // 16+-digit / i64 extremes: QUOTED string (Perl QUOTED above).
    assert!(
      s.contains("\"X:D16\": \"1000000000000000\","),
      "16-digit quoted: {s}"
    );
    assert!(
      s.contains("\"X:D16b\": \"1234567890123456\","),
      "16-digit quoted: {s}"
    );
    assert!(
      s.contains("\"X:Max\": \"9223372036854775807\","),
      "i64::MAX quoted: {s}"
    );
    assert!(
      s.contains("\"X:Min\": \"-9223372036854775808\"\n"),
      "i64::MIN quoted: {s}"
    );
    // Sanity: no 16+-digit value ever leaked out as a bare number.
    assert!(!s.contains(": 1000000000000000"), "must be quoted: {s}");
    assert!(!s.contains(": 9223372036854775807"), "must be quoted: {s}");
    assert!(!s.contains(": -9223372036854775808"), "must be quoted: {s}");
  }

  #[test]
  #[cfg_attr(miri, ignore = "shells out to perl; Miri cannot spawn processes")]
  fn rust_i64_serializer_matches_bundled_perl_gate_exactly() {
    // Assert the Rust serializer's BARE/QUOTED decision == the bundled
    // Perl regex's, value-by-value. `perl_bare(s)` shells out to the SAME
    // regex from exiftool:3809 (env-var input so `-` is data, not a flag).
    fn perl_bare(s: &str) -> bool {
      let out = std::process::Command::new("perl")
        .arg("-e")
        .arg(
          "$s=$ENV{V}; print(($s =~ \
                     /^-?(\\d|[1-9]\\d{1,14})(\\.\\d{1,16})?(e[-+]?\\d{1,3})?$/i) \
                     ? 'BARE' : 'QUOTED')",
        )
        .env("V", s)
        .output()
        .expect("run bundled perl");
      assert!(out.status.success(), "perl failed for {s:?}");
      match String::from_utf8_lossy(&out.stdout).as_ref() {
        "BARE" => true,
        "QUOTED" => false,
        other => panic!("unexpected perl output {other:?} for {s:?}"),
      }
    }
    // 1 / 9-digit / 15-digit / 16-digit / 19-digit + i64::MIN.
    for n in [
      1_i64,
      999_999_999,
      999_999_999_999_999,
      1_000_000_000_000_000,
      9_223_372_036_854_775_807,
      i64::MIN,
    ] {
      let txt = n.to_string();
      let mut m = Metadata::new("a.jpg");
      m.push(Group::new("X", "X"), "V", TagValue::I64(n));
      let s = to_exiftool_json(&m);
      let rust_bare = s.contains(&format!("\"X:V\": {txt}\n"));
      let rust_quoted = s.contains(&format!("\"X:V\": \"{txt}\"\n"));
      assert!(rust_bare ^ rust_quoted, "exactly one form for {n}: {s}");
      assert_eq!(
        rust_bare,
        perl_bare(&txt),
        "Rust BARE/QUOTED must match bundled Perl gate for {n} ({txt})"
      );
    }
  }

  #[test]
  fn f64_and_rational_route_through_the_same_gate() {
    // ExifTool runs the ONE gate on the string form of EVERY scalar.
    // `format_g(_,15)` in fixed notation can exceed the regex's
    // `\d{1,16}` fraction cap: bundled Perl
    //   V=0.00468603561387067 perl -e '$s=$ENV{V}; print(($s =~
    //     /^-?(\d|[1-9]\d{1,14})(\.\d{1,16})?(e[-+]?\d{1,3})?$/i)
    //     ? "BARE":"QUOTED")'   => QUOTED   (17 fraction digits)
    // so a representable f64 (10.0/2134.0) is QUOTED, exactly as
    // ExifTool would. Ordinary floats stay bare.
    let mut m = Metadata::new("a.jpg");
    m.push(Group::new("X", "X"), "Plain", TagValue::F64(3.5));
    m.push(Group::new("X", "X"), "Long", TagValue::F64(10.0 / 2134.0));
    let s = to_exiftool_json(&m);
    assert!(s.contains("\"X:Plain\": 3.5,"), "ordinary float bare: {s}");
    assert!(
      s.contains("\"X:Long\": \"0.00468603561387067\""),
      "17-frac-digit %.15g float quoted like ExifTool: {s}"
    );
    // Rational numeric branch keeps passing the gate (sig 7/10 always do);
    // `inf`/`undef` are non-numeric so the gate quotes them (unchanged).
    let mut m2 = Metadata::new("a.jpg");
    m2.push(
      Group::new("X", "X"),
      "R",
      TagValue::Rational(Rational::rational64(86, 10)),
    );
    m2.push(
      Group::new("X", "X"),
      "Inf",
      TagValue::Rational(Rational::rational64(1, 0)),
    );
    let s2 = to_exiftool_json(&m2);
    assert!(
      s2.contains("\"X:R\": 8.6,"),
      "rational numeric still bare: {s2}"
    );
    assert!(s2.contains("\"X:Inf\": \"inf\""), "inf still quoted: {s2}");
  }

  #[test]
  fn duplicate_group1_name_token_is_suppressed_first_wins() {
    // FIX 1 (D10 r10): ExifTool `%noDups` (exiftool:2950-2951
    // `next if $noDups{$tok}; $noDups{$tok} = 1;`). With `-G1`,
    // $tok = "<family1>:<name>". Two tags both resolving to the token
    // `AAC:Channels` (different values, even different family0) => the
    // FIRST is emitted, the second is dropped ENTIRELY (no key/value).
    let mut m = Metadata::new("a.aac");
    m.push(Group::new("Audio", "AAC"), "Channels", TagValue::I64(2));
    m.push(Group::new("QuickTime", "AAC"), "Channels", TagValue::I64(6));
    let s = to_exiftool_json(&m);
    // Exactly ONE "AAC:Channels", carrying the FIRST tag's value (2).
    assert_eq!(
      s.matches("\"AAC:Channels\"").count(),
      1,
      "duplicate token must appear once: {s}"
    );
    assert!(s.contains("\"AAC:Channels\": 2"), "first wins: {s}");
    assert!(!s.contains("\"AAC:Channels\": 6"), "later dup dropped: {s}");
    // The dropped tag leaves no trailing comma/garbage: still valid JSON
    // and the framing closes cleanly right after the kept key.
    assert_eq!(
      s,
      "[{\n  \"SourceFile\": \"a.aac\",\n  \"AAC:Channels\": 2\n}]\n"
    );
  }

  #[test]
  fn distinct_tokens_are_all_kept() {
    // Different "<family1>:<name>" tokens are NOT deduped: same name but
    // different family1, and same family1 but different name, both stay.
    let mut m = Metadata::new("a.jpg");
    m.push(
      Group::new("EXIF", "IFD0"),
      "Make",
      TagValue::Str("Canon".into()),
    );
    m.push(
      Group::new("EXIF", "IFD1"),
      "Make",
      TagValue::Str("Nikon".into()),
    );
    m.push(
      Group::new("EXIF", "IFD0"),
      "Model",
      TagValue::Str("R5".into()),
    );
    let s = to_exiftool_json(&m);
    assert!(s.contains("\"IFD0:Make\": \"Canon\""), "got: {s}");
    assert!(s.contains("\"IFD1:Make\": \"Nikon\""), "got: {s}");
    assert!(s.contains("\"IFD0:Model\": \"R5\""), "got: {s}");
    // All three distinct tokens present (none deduped).
    assert_eq!(s.matches("\"IFD").count(), 3, "all distinct kept: {s}");
  }

  #[test]
  fn warnings_emitted_as_single_exiftool_warning_tag() {
    // ExifTool's generated `Warning` tag: `ExifTool.pm:1297`
    // `Warning => { Priority => 0, Groups => \%allGroupsExifTool … }`
    // and `:1225` `%allGroupsExifTool = ( 0 => 'ExifTool',
    // 1 => 'ExifTool', 2 => 'ExifTool' )`. With `-G1` the JSON token is
    // `$group:$tagName` (`exiftool:2948`) ⇒ `"ExifTool:Warning"`.
    // Default `-j -G1` shows only the FIRST warning (the ` (N)`
    // copy-suffix dups are dropped, `exiftool:2744`; `%noDups`
    // first-wins, `exiftool:2951`).
    let mut m = Metadata::new("a.jpg");
    m.push(
      Group::new("EXIF", "IFD0"),
      "Make",
      TagValue::Str("Canon".into()),
    );
    m.push_warning("w1");
    m.push_warning("w2");
    let s = to_exiftool_json(&m);
    // Exactly ONE "ExifTool:Warning", carrying the FIRST warning only.
    assert_eq!(
      s.matches("\"ExifTool:Warning\"").count(),
      1,
      "only the first warning is emitted: {s}"
    );
    assert!(
      s.contains("\"ExifTool:Warning\": \"w1\""),
      "first warning: {s}"
    );
    assert!(
      !s.contains("w2"),
      "later warning(s) dropped (default -j -G1): {s}"
    );
    // Other tags are unaffected.
    assert!(s.contains("\"IFD0:Make\": \"Canon\""), "got: {s}");
  }

  #[test]
  fn no_warnings_emits_no_warning_key() {
    let mut m = Metadata::new("a.jpg");
    m.push(
      Group::new("EXIF", "IFD0"),
      "Make",
      TagValue::Str("Canon".into()),
    );
    let s = to_exiftool_json(&m);
    assert!(!s.contains("Warning"), "no Warning key when none: {s}");
    // Framing still closes cleanly with only SourceFile + the one tag.
    assert_eq!(
      s,
      "[{\n  \"SourceFile\": \"a.jpg\",\n  \"IFD0:Make\": \"Canon\"\n}]\n"
    );
  }

  #[test]
  fn warning_is_json_escaped_via_the_same_string_path() {
    // The warning string goes through `push_json_string` (ExifTool
    // `EscapeJSON`): `"` `\` short-escaped, control chars `\uXXXX`,
    // NUL deleted — identical to every other string value.
    let mut m = Metadata::new("a.jpg");
    m.push_warning("bad \"q\\b\u{1}\0 file");
    let s = to_exiftool_json(&m);
    assert!(
      s.contains("\"ExifTool:Warning\": \"bad \\\"q\\\\b\\u0001 file\""),
      "warning must be EscapeJSON-escaped: {s}"
    );
  }

  #[test]
  fn warning_token_participates_in_nodups_first_wins() {
    // A tag that itself resolves to the token `ExifTool:Warning`
    // (group1 `ExifTool`, name `Warning`) is emitted first and, per
    // `%noDups` first-wins (`exiftool:2951`), suppresses the
    // `m.warnings()` emission entirely (only ONE `ExifTool:Warning`).
    let mut m = Metadata::new("a.jpg");
    m.push(
      Group::new("ExifTool", "ExifTool"),
      "Warning",
      TagValue::Str("from-tag".into()),
    );
    m.push_warning("from-warnings");
    let s = to_exiftool_json(&m);
    assert_eq!(
      s.matches("\"ExifTool:Warning\"").count(),
      1,
      "first-wins: exactly one ExifTool:Warning: {s}"
    );
    assert!(
      s.contains("\"ExifTool:Warning\": \"from-tag\""),
      "tag wins: {s}"
    );
    assert!(
      !s.contains("from-warnings"),
      "warnings list suppressed: {s}"
    );
  }
}
