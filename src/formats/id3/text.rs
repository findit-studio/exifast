//! Text-handling helpers ported from `ID3.pm`. Hosts:
//! - `convert_id3v1_text` — `ConvertID3v1Text` (ID3.pm:897-901).
//! - `print_genre` — `PrintGenre` (ID3.pm:1020-1037).
//! - `print_popularimeter` — POP/POPM PrintConv (ID3.pm:457 / :559).
//! - `make_tag_name` — `MakeTagName` (ID3.pm:884-891).
//! - `print_length` — TLEN PrintConv (`"$val s"`, ID3.pm:595).
//! - `value_length` — TLEN ValueConv (`$val / 1000`, ID3.pm:594).

// Golden-v2 Contract 3c (Phase C, slice w2c): panic-safety by construction —
// every raw `&[u8]` index/slice (from `str::as_bytes()`) is converted to a
// checked `.get()` form below. Each conversion is byte-identical: every read
// is inside a `while i < bytes.len()` / `i + N < bytes.len()` loop bound or a
// preceding `bytes.len() < N` length guard, so the `.get()` always yields the
// same byte and the comparison/parse result is unchanged. (`&str` range slices
// like `&s[a..b]` are not flagged by this lint and stay as-is.)
#![deny(clippy::indexing_slicing)]

use crate::{convert::ConvContext, formats::id3::genre, value::TagValue};
use smol_str::SmolStr;

/// Decode a raw byte string per `$$self{OPTIONS}{CharsetID3}`. Faithful
/// port of `ConvertID3v1Text` (ID3.pm:897-901):
///
/// ```perl
/// sub ConvertID3v1Text($$) {
///     my ($et, $val) = @_;
///     return $et->Decode($val, $et->Options('CharsetID3'));
/// }
/// ```
///
/// For the default `CharsetID3 => 'Latin'` (ExifTool.pm:1118) this is an
/// ISO-8859-1 → UTF-8 transliteration: each byte 0..=255 maps to the
/// Unicode code point of the same numeric value (the canonical Latin-1
/// transliteration; ExifTool::Charset uses the same table). Trailing
/// nulls are NOT stripped here — that's done by the binary-data caller
/// (`ProcessBinaryData` zero-pads `Format => 'string[N]'` results, and
/// our [`super::v1::process_id3v1`] strips trailing zeros BEFORE invoking
/// this function, matching the bundled-Perl observed behavior).
///
/// # Faithful coverage scope (flagged by Codex review R1 — accepted, see
/// `[[exifast-phase2-forward-items]]`)
///
/// Other `CharsetID3` values — `UTF8`, `Cyrillic`, `Latin2`, `Mac…`,
/// `Greek`, `Hebrew`, etc. (the full `Image::ExifTool::Charset` table) —
/// are NOT implemented in this read-only pathfinder. Production
/// `extract_info` ALWAYS constructs the default [`ConvContext::default`]
/// (no CLI options layer yet exposes `CharsetID3`), so the non-`Latin`
/// branch is unreachable from `extract_info`. Any caller that DOES
/// construct `ConvContext::new("UTF8")` or `with_charset_id3("Cyrillic")`
/// will get LOSSY UTF-8 decoding here — that is documented divergence
/// from bundled-Perl, not a silent bug. The D11 API contract states only
/// "the value reflects what `$$self{OPTIONS}{CharsetID3}` would carry"
/// — semantic equivalence with `Image::ExifTool::Decode` lands when the
/// engine ports `Image::ExifTool::Charset` (a separate infra concern; no
/// Phase-2 audio/video format requires non-`Latin` CharsetID3).
///
/// The `charset_id3` field on `ConvContext` is therefore a **forward-
/// compatible** declaration: future format ports CAN extend the decode
/// table here without re-designing the API.
#[must_use]
pub fn convert_id3v1_text(raw: &TagValue, ctx: &ConvContext) -> TagValue {
  // `TagValue::Str` is ALREADY-decoded UTF-8 in our port (the binary-data
  // emitter for ID3v1 `Format => 'string[N]'` produces `TagValue::Bytes`,
  // so any `Str` reaching here was produced by a later stage that already
  // owned a valid Rust `String`). Re-interpreting its UTF-8 bytes as
  // Latin-1 would corrupt multi-byte sequences (e.g. `"Café"` whose UTF-8
  // bytes `43 61 66 c3 a9` would decode to `"CafÃ©"`). Mirror Perl `Decode`'s
  // identity-on-already-decoded-string semantics by passing `Str` through.
  // Codex-converged Copilot review: only `TagValue::Bytes` carries the raw
  // ID3v1 octets that need charset transliteration.
  let bytes = match raw {
    TagValue::Bytes(b) => b.as_slice(),
    TagValue::Str(_) => return raw.clone(),
    other => return other.clone(),
  };
  match ctx.charset_id3() {
    "Latin" => {
      // ISO-8859-1 → UTF-8: each byte = Unicode code point. Allocates only
      // when a non-ASCII byte forces multi-byte UTF-8 (lossless either way).
      let mut s = String::with_capacity(bytes.len());
      for &b in bytes {
        s.push(b as char);
      }
      TagValue::Str(SmolStr::new(s))
    }
    _ => {
      // Non-default charsets unimplemented (see fn docs); lossy UTF-8 keeps
      // valid sequences exact. Tracked as a forward item.
      TagValue::Str(SmolStr::new(String::from_utf8_lossy(bytes)))
    }
  }
}

/// Faithful port of `PrintGenre` (ID3.pm:1020-1037). Resolves parenthesized
/// numeric refs `(N)` and slash-separated bare numbers to genre names from
/// [`super::genre::genre_name`], synthesizing `"Unknown ($n)"` for misses.
///
/// ```perl
/// while ($val =~ /\((\d+)\)/g) {                                  # :1025
///     $genre{$1} or $genre{$1} = "Unknown ($1)";
/// }
/// while ($val =~ /(?:^|\/)(\d+)(\/|$)/g) {                         # :1030
///     $genre{$1} or $genre{$1} = "Unknown ($1)";
/// }
/// $val =~ s/\((\d+)\)/\($genre{$1}\)/g;                            # :1033
/// $val =~ s/(^|\/)(\d+)(?=\/|$)/$1$genre{$2}/g;                    # :1034
/// $val =~ s/^\(([^)]+)\)\1?$/$1/; # clean up brackets/duplicates    # :1035
/// ```
///
/// The bundled test (`MP3.mp3` fixture) carries `TCO` value `"Testing"` —
/// no numeric pattern, so `print_genre` returns it unchanged. The full
/// transformation is exercised by inputs like `"(7)"` → `"Hip-Hop"` /
/// `"(7)Custom"` → `"(Hip-Hop)Custom"`.
#[must_use]
pub fn print_genre(raw: &TagValue) -> TagValue {
  let s = match raw {
    TagValue::Str(s) => s.to_string(),
    other => return other.clone(),
  };

  // R9-F2: preserve UTF-8 string slices instead of pushing per-byte
  // casts. The Perl regex substitutions operate on the DECODED string
  // (DecodeString returns UTF-8 in our port), so the surrounding non-
  // ASCII text must round-trip byte-identical. My previous
  // `out.push(bytes[i] as char)` corrupted UTF-8 by interpreting each
  // raw byte as a Unicode code point (e.g. `Café` → `CafÃ©`). The
  // ASCII anchors `(`, `)`, `/`, and ASCII digits are all single-byte
  // in UTF-8, so byte-level scanning is safe — but the in-between
  // bytes must be copied as slices to keep multi-byte UTF-8
  // sequences intact.

  // (1) ID3.pm:1033 — `s/\((\d+)\)/\($genre{$1}\)/g` (parenthesized number
  //     refs); a miss renders `"Unknown ($n)"`.
  let mut out = String::with_capacity(s.len());
  let bytes = s.as_bytes();
  let mut i = 0;
  let mut copy_from = 0;
  while i < bytes.len() {
    // `i < bytes.len()` ⇒ `.get(i)` is `Some`; the inner `.get(j)` scans are
    // `Some` exactly while `j < bytes.len()` (the `.get` returns `None` past
    // the end, replacing the explicit `j < bytes.len()` bound) — byte-
    // identical to the prior `bytes[i]` / `bytes[j]`.
    if bytes.get(i) == Some(&b'(') {
      // Try to parse `(<digits>)`.
      let start = i + 1;
      let mut j = start;
      while bytes.get(j).is_some_and(u8::is_ascii_digit) {
        j += 1;
      }
      if j > start && bytes.get(j) == Some(&b')') {
        // Flush the pending UTF-8 chunk before this `(`.
        out.push_str(&s[copy_from..i]);
        // R14-F3: Perl `%genre{$1}` uses the CAPTURED STRING as key.
        // `$genre{"007"}` is a miss (the table is keyed by integer-
        // stringified decimals like "7"). Only canonical decimals
        // (no leading zeros, except the lone "0") hit. Pass-through
        // via `lookup_genre_by_decimal_string` enforces that.
        let captured = &s[start..j];
        out.push('(');
        match lookup_genre_by_decimal_string(captured) {
          Some(name) => out.push_str(name),
          None => {
            out.push_str("Unknown (");
            out.push_str(captured);
            out.push(')');
          }
        }
        out.push(')');
        i = j + 1;
        copy_from = i;
        continue;
      }
    }
    i += 1;
  }
  // Final trailing UTF-8 chunk.
  out.push_str(&s[copy_from..]);

  // (2) ID3.pm:1034 — `s/(^|\/)(\d+)(?=\/|$)/$1$genre{$2}/g`: bare numeric
  //     tokens (start or after `/`) up to next `/` or end.
  let after_parens = out;
  let bytes2 = after_parens.as_bytes();
  let mut out2 = String::with_capacity(after_parens.len());
  let mut i = 0;
  let mut copy_from = 0;
  while i < bytes2.len() {
    // `i < bytes2.len()` ⇒ `.get(i)` is `Some`; `i == 0 || .get(i - 1) ==
    // Some(&b'/')` is byte-identical to `i == 0 || bytes2[i - 1] == b'/'`
    // (when `i > 0`, `i - 1 < len`). The inner `.get(k)` scan is `Some` exactly
    // while `k < bytes2.len()`. `.get(k) == Some(&b'/')` (else clause) covers
    // the `k < len && bytes2[k] == b'/'` case; `k == len` is the `None` side.
    let at_boundary = i == 0 || bytes2.get(i - 1) == Some(&b'/');
    if at_boundary && bytes2.get(i).is_some_and(u8::is_ascii_digit) {
      let start = i;
      let mut k = i;
      while bytes2.get(k).is_some_and(u8::is_ascii_digit) {
        k += 1;
      }
      let at_end = k == bytes2.len() || bytes2.get(k) == Some(&b'/');
      if at_end {
        // Flush the pending UTF-8 chunk.
        out2.push_str(&after_parens[copy_from..start]);
        let captured = &after_parens[start..k];
        // R14-F3: same `%genre{$2}` exact-key lookup — leading zeros
        // miss the table.
        match lookup_genre_by_decimal_string(captured) {
          Some(name) => out2.push_str(name),
          None => {
            out2.push_str("Unknown (");
            out2.push_str(captured);
            out2.push(')');
          }
        }
        i = k;
        copy_from = k;
        continue;
      }
      // Digits NOT followed by `/`/EOS — keep them verbatim; just
      // advance past them.
      i = k;
      continue;
    }
    i += 1;
  }
  // Final trailing UTF-8 chunk.
  out2.push_str(&after_parens[copy_from..]);

  // (3) ID3.pm:1035 — `s/^\(([^)]+)\)\1?$/$1/` — clean up by removing
  //     brackets when the value is exactly `(X)` or `(X)X`.
  let cleaned = clean_parens_duplicates(&out2);
  TagValue::Str(SmolStr::new(cleaned))
}

/// Faithful Perl `$genre{$captured}` lookup — only succeeds when
/// `captured` is the canonical decimal string for some genre number.
/// "007" misses (Perl `%genre{"007"}` is undef; the table is keyed by
/// integer-stringified decimals like `"7"`); "7" hits. The lone "0"
/// (genre 0 = Blues) is the only canonical input with a leading zero.
/// Codex R14-F3 regression.
fn lookup_genre_by_decimal_string(captured: &str) -> Option<&'static str> {
  // Reject any non-canonical decimal: leading zero on multi-digit
  // input, or non-digit chars (impossible here — the caller pre-
  // filters ASCII digits).
  if captured.is_empty() {
    return None;
  }
  let bytes = captured.as_bytes();
  // `.first()` is the checked form of `bytes[0]`; with `bytes.len() > 1` it is
  // always `Some` (byte-identical to the prior `bytes[0] == b'0'`).
  if bytes.len() > 1 && bytes.first() == Some(&b'0') {
    return None;
  }
  // Parse to i64; the table covers 0..=255 + a sparse upper range,
  // so any value out of i64 range is a miss.
  let n: i64 = captured.parse().ok()?;
  genre::genre_name(n)
}

/// Apply the Perl regex `s/^\(([^)]+)\)\1?$/$1/` (ID3.pm:1035): if the
/// whole string is `(X)` or `(X)X`, replace with `X`. Otherwise unchanged.
fn clean_parens_duplicates(s: &str) -> String {
  let b = s.as_bytes();
  // `.first()` is the checked form of `b[0]`; with `b.len() >= 2` it is always
  // `Some` (byte-identical to the prior `b[0] != b'('`). (`&s[1..close]` /
  // `&s[close + 1..]` below are `&str` range slices, not flagged.)
  if b.len() < 2 || b.first() != Some(&b'(') {
    return s.to_string();
  }
  // Find matching `)` — `[^)]+` so no nested parens, just one run.
  let close = match b.iter().position(|&c| c == b')') {
    Some(p) if p > 1 => p,
    _ => return s.to_string(),
  };
  let inner = &s[1..close];
  let tail = &s[close + 1..];
  if tail.is_empty() || tail == inner {
    inner.to_string()
  } else {
    s.to_string()
  }
}

/// Faithful port of POP/POPM PrintConv (ID3.pm:457 = :559):
///
/// ```perl
/// $val =~ s/^(.*?) (\d+) (\d+)$/$1 Rating=$2 Count=$3/s; $val
/// ```
///
/// The value emitted by the frame parser is `"$email $rating $cnt"`
/// (ID3.pm:1343). The PrintConv reshapes that into the canonical
/// human-readable form. If the regex misses (no two trailing decimal
/// fields), the value passes through unchanged (`$val` returned).
#[must_use]
pub fn print_popularimeter(raw: &TagValue) -> TagValue {
  let s = match raw {
    TagValue::Str(s) => s,
    other => return other.clone(),
  };
  // Regex: `^(.*?) (\d+) (\d+)$/s` — minimal-match `.*?` then space, digits,
  // space, digits, anchored. Implement directly: rfind last space, scan
  // digits, then rfind preceding space, scan digits, then everything before
  // is $1.
  let bytes = s.as_bytes();
  // Strip trailing digits → $3.
  let end3 = bytes.len();
  let mut start3 = end3;
  // Each `start*` walks down from `bytes.len()` and stays `> 0` when the read
  // happens, so `start* - 1 < bytes.len()` and `.get(start* - 1)` is always
  // `Some` (byte-identical to the prior `bytes[start* - 1]`); the `|| start*
  // == 0` short-circuit still guards the subtraction.
  while start3 > 0 && bytes.get(start3 - 1).is_some_and(u8::is_ascii_digit) {
    start3 -= 1;
  }
  if start3 == end3 || start3 == 0 || bytes.get(start3 - 1) != Some(&b' ') {
    return TagValue::Str(s.clone());
  }
  // Strip $2 digits. `end2` is the index of the ' ' before $3, i.e. the
  // upper bound for the $2 scan; `start2` walks backward over digits.
  let end2 = start3 - 1;
  let mut start2 = end2;
  while start2 > 0 && bytes.get(start2 - 1).is_some_and(u8::is_ascii_digit) {
    start2 -= 1;
  }
  if start2 == end2 || start2 == 0 || bytes.get(start2 - 1) != Some(&b' ') {
    return TagValue::Str(s.clone());
  }
  // $1 is the minimal-match prefix — everything BEFORE the space before $2.
  // $2 = bytes[start2..end2] (digits). $3 = bytes[start3..] (digits).
  let end1 = start2 - 1; // index of the ' ' before $2
  let dollar1 = &s[..end1];
  let dollar2 = &s[start2..end2];
  let dollar3 = &s[start3..];
  TagValue::Str(SmolStr::new(format!(
    "{dollar1} Rating={dollar2} Count={dollar3}"
  )))
}

/// Faithful port of `MakeTagName` (ID3.pm:884-891). Used to synthesize tag
/// names for user-defined TXXX/WXXX/PRIV/etc. tags. ExifTool's
/// `MakeTagName` (top-level, `Image::ExifTool::MakeTagName`) sanitizes
/// `[^-\w]` to `_` and ensures a non-empty result; the ID3 wrapper first
/// handles a couple of canonicalizations:
///
/// ```perl
/// my $name = shift;
/// return $userTagName{$name} if $userTagName{$name};   # ID3.pm:887 (ALBUMARTISTSORT, ASIN)
/// $name = ucfirst(lc $name) unless $name =~ /[a-z]/;   # :888 all-uppercase → MixedCase
/// $name =~ s/([a-z])[_ ]([a-z])/$1\U$2/g;              # :889 collapse space/underscore
/// return Image::ExifTool::MakeTagName($name);          # :890
/// ```
#[must_use]
pub fn make_tag_name(name: &str) -> String {
  // ID3.pm:887 — explicit overrides.
  match name {
    "ALBUMARTISTSORT" => return "AlbumArtistSort".to_string(),
    "ASIN" => return "ASIN".to_string(),
    _ => {}
  }
  // ID3.pm:888 — if string has NO lowercase letter, lowercase then capitalize first.
  let has_lower = name.chars().any(|c| c.is_ascii_lowercase());
  let mut s: String = if has_lower {
    name.to_string()
  } else {
    let lc = name.to_ascii_lowercase();
    let mut iter = lc.chars();
    match iter.next() {
      Some(c) => c.to_ascii_uppercase().to_string() + iter.as_str(),
      None => String::new(),
    }
  };
  // ID3.pm:889 — collapse `[a-z][_ ][a-z]` into `[a-z][A-Z]`.
  let bytes = s.as_bytes().to_vec();
  let mut out = String::with_capacity(bytes.len());
  let mut i = 0;
  while i < bytes.len() {
    // `i + 2 < bytes.len()` ⇒ all three reads are in range; in the `else`,
    // `i < bytes.len()` ⇒ `.get(i)` is `Some`. The `0` fallbacks are
    // unreachable (byte-identical to the prior `bytes[i]` / `bytes[i+1]` /
    // `bytes[i+2]`).
    if i + 2 < bytes.len()
      && bytes.get(i).is_some_and(u8::is_ascii_lowercase)
      && (bytes.get(i + 1) == Some(&b'_') || bytes.get(i + 1) == Some(&b' '))
      && bytes.get(i + 2).is_some_and(u8::is_ascii_lowercase)
    {
      out.push(bytes.get(i).copied().unwrap_or(0) as char);
      out.push((bytes.get(i + 2).copied().unwrap_or(0) as char).to_ascii_uppercase());
      i += 3;
    } else {
      out.push(bytes.get(i).copied().unwrap_or(0) as char);
      i += 1;
    }
  }
  s = out;
  // ID3.pm:890 → Image::ExifTool::MakeTagName (ExifTool.pm:6440-6448):
  //   $name =~ tr/-_a-zA-Z0-9//dc;   # REMOVE non-`[-_a-zA-Z0-9]` chars
  //   $name = ucfirst $name;          # capitalize first letter
  //   $name = "Tag$name" if length($name) < 2 or $name =~ /^[-0-9]/;
  // CRITICAL: `tr/.../.../dc` is COMPLEMENT-DELETE — it REMOVES disallowed
  // characters (does NOT replace them with `_`). E.g.
  //   MakeTagName("MusicBrainz Album Id") = "MusicBrainzAlbumId"  (spaces removed)
  //   MakeTagName("foo/bar")              = "foobar"              (/ removed)
  let mut sanitized = String::with_capacity(s.len());
  for c in s.chars() {
    if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
      sanitized.push(c);
    }
    // else: REMOVE (do not push) — faithful to Perl's `/dc` mode.
  }
  // ExifTool.pm:6444: `$name = ucfirst $name` — capitalize first letter.
  let mut sanitized = {
    let mut chars = sanitized.chars();
    match chars.next() {
      Some(c) => c.to_ascii_uppercase().to_string() + chars.as_str(),
      None => String::new(),
    }
  };
  // ExifTool.pm:6446: if length < 2 OR starts with `[-0-9]`, prepend "Tag".
  let needs_prefix = sanitized.len() < 2
    || sanitized
      .chars()
      .next()
      .is_some_and(|c| c == '-' || c.is_ascii_digit());
  if needs_prefix {
    sanitized = format!("Tag{sanitized}");
  }
  sanitized
}

/// Faithful port of `Image::ExifTool::XMP::ConvertXMPDate` (XMP.pm:3383-3394).
/// Used as the `ValueConv` of every v2.4 date/time frame
/// (TDEN/TDOR/TDRC/TDRL/TDTG, ID3.pm:705-709 via `%dateTimeConv`):
///
/// ```perl
/// sub ConvertXMPDate($;$) {
///     my ($val, $unsure) = @_;
///     if ($val =~ /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}:\d{2})(:\d{2})?\s*(\S*)$/) {
///         my $s = $5 || '';
///         $val = "$1:$2:$3 $4$s$6";   # XMP `2024-05-19T12:34:56` → EXIF `2024:05:19 12:34:56`
///     } elsif (not $unsure and $val =~ /^(\d{4})(-\d{2}){0,2}/) {
///         $val =~ tr/-/:/;            # year/year-mon/year-mon-day: replace `-` with `:`
///     }
///     return $val;
/// }
/// ```
///
/// The `$unsure` arg is omitted (false) by every ID3 caller; we drop it.
/// Pure string transform — no context dependency, so it's a plain `Func`.
#[must_use]
pub fn convert_xmp_date(raw: &TagValue) -> TagValue {
  let s = match raw {
    TagValue::Str(s) => s.to_string(),
    other => return other.clone(),
  };
  // Try the full datetime pattern first.
  if let Some(replaced) = try_xmp_datetime(&s) {
    return TagValue::Str(SmolStr::new(replaced));
  }
  // Otherwise: year / year-mon / year-mon-day → replace `-` with `:`.
  if let Some(replaced) = try_xmp_date_only(&s) {
    return TagValue::Str(SmolStr::new(replaced));
  }
  raw.clone()
}

fn try_xmp_datetime(s: &str) -> Option<String> {
  // /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}:\d{2})(:\d{2})?\s*(\S*)$/
  let bytes = s.as_bytes();
  if bytes.len() < 16 {
    return None;
  }
  // YYYY-MM-DD[T| ]HH:MM[:SS][TZ]. `bytes.len() >= 16` ⇒ every fixed read in
  // `0..16` is in range, so the `.get(..)?` always yields `Some` (the `?`
  // `None` recovery is the function's existing no-match path) — byte-identical
  // to the prior `&bytes[..4]` / `bytes[4]` etc.
  let year = std::str::from_utf8(bytes.get(..4)?).ok()?;
  if !year.bytes().all(|b| b.is_ascii_digit()) || bytes.get(4) != Some(&b'-') {
    return None;
  }
  let mon = std::str::from_utf8(bytes.get(5..7)?).ok()?;
  if !mon.bytes().all(|b| b.is_ascii_digit()) || bytes.get(7) != Some(&b'-') {
    return None;
  }
  let day = std::str::from_utf8(bytes.get(8..10)?).ok()?;
  if !day.bytes().all(|b| b.is_ascii_digit())
    || (bytes.get(10) != Some(&b'T') && bytes.get(10) != Some(&b' '))
  {
    return None;
  }
  let hhmm = std::str::from_utf8(bytes.get(11..16)?).ok()?;
  let hhmm_bytes = hhmm.as_bytes();
  if !hhmm_bytes.first().is_some_and(u8::is_ascii_digit)
    || !hhmm_bytes.get(1).is_some_and(u8::is_ascii_digit)
    || hhmm_bytes.get(2) != Some(&b':')
    || !hhmm_bytes.get(3).is_some_and(u8::is_ascii_digit)
    || !hhmm_bytes.get(4).is_some_and(u8::is_ascii_digit)
  {
    return None;
  }
  let mut pos = 16;
  let mut sec = String::new();
  // `pos + 3 <= bytes.len()` ⇒ `pos < bytes.len()`, so `.get(pos)` is `Some`
  // and `.get(pos + 1..pos + 3)` is `Some` — byte-identical.
  if pos + 3 <= bytes.len() && bytes.get(pos) == Some(&b':') {
    let tail = std::str::from_utf8(bytes.get(pos + 1..pos + 3)?).ok()?;
    if !tail.bytes().all(|b| b.is_ascii_digit()) {
      return None;
    }
    sec = format!(":{tail}");
    pos += 3;
  }
  // Skip whitespace then capture trailing tz (\S*$). `.get(pos)` is `Some`
  // exactly while `pos < bytes.len()` (replacing the explicit bound).
  while bytes.get(pos).is_some_and(u8::is_ascii_whitespace) {
    pos += 1;
  }
  let tz = if pos < bytes.len() {
    // `pos <= bytes.len()` always ⇒ `.get(pos..)` is `Some` (byte-identical).
    std::str::from_utf8(bytes.get(pos..)?).ok()?
  } else {
    ""
  };
  // Confirm tz has no whitespace (Perl `\S*$` is end-anchored).
  if tz.chars().any(char::is_whitespace) {
    return None;
  }
  Some(format!("{year}:{mon}:{day} {hhmm}{sec}{tz}"))
}

fn try_xmp_date_only(s: &str) -> Option<String> {
  // /^(\d{4})(-\d{2}){0,2}/  — year alone, or year-mon, or year-mon-day,
  // then DON'T care about the rest. Translate `-` → `:` over the matched
  // prefix only. Perl `tr/-/:/` operates on the entire `$val`, so any
  // hyphen in the value is converted.
  let bytes = s.as_bytes();
  if bytes.len() < 4 {
    return None;
  }
  // `bytes.len() >= 4` ⇒ `.get(..4)` is always `Some` (the `false` fallback is
  // unreachable) — byte-identical to the prior `bytes[..4]`.
  let year_ok = bytes
    .get(..4)
    .is_some_and(|b| b.iter().all(u8::is_ascii_digit));
  if !year_ok {
    return None;
  }
  // Optional `-MM` and `-DD`. `i + 3 <= bytes.len()` ⇒ the three reads are in
  // range; the `else if` `.get(i) == Some(&b'-')` covers `i < len && bytes[i]
  // == b'-'` (the `None` side is `i == len`) — byte-identical.
  let mut i = 4;
  let mut groups_ok = true;
  for _ in 0..2 {
    if i + 3 <= bytes.len()
      && bytes.get(i) == Some(&b'-')
      && bytes.get(i + 1).is_some_and(u8::is_ascii_digit)
      && bytes.get(i + 2).is_some_and(u8::is_ascii_digit)
    {
      i += 3;
    } else if bytes.get(i) == Some(&b'-') {
      // `-` without two digits ⇒ regex doesn't match (`{0,2}` allows 0
      // matches here, so prefix `^(\d{4})` alone matches, then no `-MM`).
      groups_ok = false;
      break;
    } else {
      // No more `-NN` groups; that's fine.
      break;
    }
  }
  let _ = groups_ok;
  // Perl `tr/-/:/` over the ENTIRE $val (not just the matched prefix).
  let replaced: String = s.chars().map(|c| if c == '-' { ':' } else { c }).collect();
  Some(replaced)
}

/// TLEN ValueConv (ID3.pm:594): `$val / 1000` — Length is stored in ms.
#[must_use]
pub fn value_length(raw: &TagValue) -> TagValue {
  match raw {
    TagValue::Str(s) => match s.parse::<f64>() {
      Ok(ms) => TagValue::F64(ms / 1000.0),
      Err(_) => raw.clone(),
    },
    TagValue::I64(ms) => TagValue::F64(*ms as f64 / 1000.0),
    TagValue::F64(ms) => TagValue::F64(ms / 1000.0),
    _ => raw.clone(),
  }
}

/// TLEN PrintConv (ID3.pm:595): `"$val s"` — bare seconds + " s".
#[must_use]
pub fn print_length(raw: &TagValue) -> TagValue {
  let txt = match raw {
    TagValue::F64(f) => crate::value::format_g(*f, 15),
    TagValue::I64(n) => n.to_string(),
    TagValue::Str(s) => s.to_string(),
    other => return other.clone(),
  };
  TagValue::Str(SmolStr::new(format!("{txt} s")))
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2c); the tests index fixed-layout data freely (an
// out-of-range index is a test-assertion failure, not a shipped panic), so the
// deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  #[test]
  fn convert_id3v1_text_latin1_to_utf8() {
    // 'Caf\xe9' (Latin-1) → 'Café' (UTF-8).
    let raw = TagValue::Bytes(vec![b'C', b'a', b'f', 0xe9]);
    let ctx = ConvContext::default();
    let out = convert_id3v1_text(&raw, &ctx);
    assert_eq!(out, TagValue::Str("Café".into()));
  }

  #[test]
  fn convert_id3v1_text_passes_through_when_already_str() {
    let raw = TagValue::Str("Hello".into());
    let ctx = ConvContext::default();
    let out = convert_id3v1_text(&raw, &ctx);
    assert_eq!(out, TagValue::Str("Hello".into()));
  }

  #[test]
  fn convert_id3v1_text_preserves_already_decoded_utf8_str() {
    // Copilot review regression: when input is already-decoded UTF-8
    // (e.g. produced by a later stage that owns a Rust `String`), the
    // function must NOT re-interpret its UTF-8 bytes as Latin-1. Prior
    // behavior cast each UTF-8 byte to `char`, mojibake-ing multi-byte
    // sequences (e.g. `"Café"` bytes `43 61 66 c3 a9` → `"CafÃ©"`).
    let raw = TagValue::Str("Café".into());
    let ctx = ConvContext::default();
    let out = convert_id3v1_text(&raw, &ctx);
    assert_eq!(out, TagValue::Str("Café".into()));
  }

  #[test]
  fn print_genre_parenthesized_number_to_name() {
    // ID3.pm:1033 — "(7)" → "(Hip-Hop)", then :1035 strips the brackets.
    assert_eq!(
      print_genre(&TagValue::Str("(7)".into())),
      TagValue::Str("Hip-Hop".into())
    );
    // "(7)" + "(13)" should expand both, no top-level wrap → "(Hip-Hop)(Pop)"
    // (no `^(X)$` match for :1035).
    assert_eq!(
      print_genre(&TagValue::Str("(7)(13)".into())),
      TagValue::Str("(Hip-Hop)(Pop)".into())
    );
  }

  #[test]
  fn print_genre_unknown_number_renders_unknown_n() {
    // 200 has no genre name → bundled Perl evaluates as:
    //   :1025 `$genre{200} = "Unknown (200)"`
    //   :1033 `s/\(200\)/\(Unknown (200)\)/` → "(Unknown (200))"
    //   :1035 `s/^\(([^)]+)\)\1?$/$1/` — [^)]+ stops at FIRST `)`, so the
    //     inner-`)` confuses the regex; no substitution → outer parens
    //     are NOT stripped. Oracle-verified vs bundled `perl -e ...`.
    assert_eq!(
      print_genre(&TagValue::Str("(200)".into())),
      TagValue::Str("(Unknown (200))".into())
    );
  }

  #[test]
  fn print_genre_preserves_utf8_in_surrounding_text() {
    // R9-F2 regression: bundled regex substitutions operate on the
    // DECODED UTF-8 string (post-DecodeString). Non-numeric text
    // surrounding the substitution targets must round-trip byte-
    // identical. Previously my port pushed `byte as char` per byte,
    // corrupting `Café` (bytes `43 61 66 c3 a9`) to `CafÃ©`.
    assert_eq!(
      print_genre(&TagValue::Str("Café".into())),
      TagValue::Str("Café".into())
    );
    // UTF-8 + parenthesized number ref: surrounding UTF-8 preserved.
    assert_eq!(
      print_genre(&TagValue::Str("(7)Café".into())),
      TagValue::Str("(Hip-Hop)Café".into())
    );
    // UTF-8 + slash-separated bare numeric: surrounding UTF-8 preserved.
    assert_eq!(
      print_genre(&TagValue::Str("7/Café".into())),
      TagValue::Str("Hip-Hop/Café".into())
    );
  }

  #[test]
  fn print_genre_plain_text_passes_through() {
    // ID3.pm:469-470: TCO/TCON value with no parens — "Testing" should
    // remain "Testing" (the synthetic fixture relies on this).
    assert_eq!(
      print_genre(&TagValue::Str("Testing".into())),
      TagValue::Str("Testing".into())
    );
  }

  #[test]
  fn print_genre_leading_zero_decimal_misses_table() {
    // R14-F3 regression: bundled `$genre{"007"}` is a miss (Perl hash
    // key "007" != integer-key 7). Faithful: `(007)` → `(Unknown (007))`
    // (the bracket-cleanup at ID3.pm:1035 doesn't fire because the
    // outer wrapper isn't a single ASCII bracketed-name). Same for
    // bare-numeric `007` after a `/`.
    assert_eq!(
      print_genre(&TagValue::Str("(007)".into())),
      TagValue::Str("(Unknown (007))".into())
    );
    // Slash-separated bare numeric `7/013` — `7` hits Hip-Hop,
    // `013` misses and becomes `Unknown (013)`.
    assert_eq!(
      print_genre(&TagValue::Str("7/013".into())),
      TagValue::Str("Hip-Hop/Unknown (013)".into())
    );
    // The lone "0" is the only canonical leading-zero input (genre
    // 0 = Blues).
    assert_eq!(
      print_genre(&TagValue::Str("(0)".into())),
      TagValue::Str("Blues".into())
    );
  }

  #[test]
  fn print_genre_id3v2_4_slash_separated_numbers() {
    // ID3.pm:1034 — v2.4 stores numbers separated by `/` (originally nulls
    // converted to `/` by DecodeString). "7/13" → "Hip-Hop/Pop".
    assert_eq!(
      print_genre(&TagValue::Str("7/13".into())),
      TagValue::Str("Hip-Hop/Pop".into())
    );
  }

  #[test]
  fn print_popularimeter_regex_substitution() {
    // ID3.pm:457: "email@x.com 5 100" → "email@x.com Rating=5 Count=100".
    assert_eq!(
      print_popularimeter(&TagValue::Str("email@x.com 5 100".into())),
      TagValue::Str("email@x.com Rating=5 Count=100".into())
    );
    // Empty email (still has the leading space).
    assert_eq!(
      print_popularimeter(&TagValue::Str(" 5 100".into())),
      TagValue::Str(" Rating=5 Count=100".into())
    );
    // Unmatched — no two trailing decimal fields → pass through.
    assert_eq!(
      print_popularimeter(&TagValue::Str("no-rating".into())),
      TagValue::Str("no-rating".into())
    );
  }

  #[test]
  fn make_tag_name_explicit_overrides() {
    assert_eq!(make_tag_name("ALBUMARTISTSORT"), "AlbumArtistSort");
    assert_eq!(make_tag_name("ASIN"), "ASIN");
  }

  #[test]
  fn make_tag_name_all_caps_to_mixedcase() {
    // "ALBUM" → "Album" (lc then ucfirst, no spaces to collapse).
    assert_eq!(make_tag_name("ALBUM"), "Album");
  }

  #[test]
  fn make_tag_name_collapses_space_or_underscore() {
    // "my comment" → ID3.pm:889 collapses `[a-z][_ ][a-z]` to `[a-z][A-Z]`
    // ⇒ "myComment".  "my_comment" → same collapse ⇒ "myComment".
    assert_eq!(make_tag_name("my comment"), "MyComment");
    assert_eq!(make_tag_name("my_comment"), "MyComment");
  }

  #[test]
  fn make_tag_name_strips_non_word_chars_faithfully() {
    // ExifTool.pm:6443 `tr/-_a-zA-Z0-9//dc` REMOVES non-`[-_a-zA-Z0-9]`
    // characters (does NOT replace them) — `/dc` = COMPLEMENT-DELETE.
    // After ucfirst: "name@host" → "Namehost".
    assert_eq!(make_tag_name("name@host"), "Namehost");
  }

  #[test]
  fn make_tag_name_musicbrainz_pattern_matches_bundled_perl() {
    // Oracle: `perl -MImage::ExifTool -e 'print
    //   Image::ExifTool::ID3::MakeTagName("MusicBrainz Album Id")'`
    // ⇒ `MusicBrainzAlbumId` (space-stripped, ucfirst-preserved).
    assert_eq!(make_tag_name("MusicBrainz Album Id"), "MusicBrainzAlbumId");
  }

  #[test]
  fn make_tag_name_short_input_gets_tag_prefix() {
    // ExifTool.pm:6446 — length < 2 OR starts with `[-0-9]` → prepend "Tag".
    assert_eq!(make_tag_name("X"), "TagX");
    assert_eq!(make_tag_name("1Album"), "Tag1Album");
  }

  #[test]
  fn value_and_print_length_match_perl() {
    // ID3.pm:594-595: TLEN = "$val s" after `/1000`.
    let raw = TagValue::Str("1234".into());
    let v = value_length(&raw);
    assert_eq!(v, TagValue::F64(1.234));
    assert_eq!(print_length(&v), TagValue::Str("1.234 s".into()));
  }
}
