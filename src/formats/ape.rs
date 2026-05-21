// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "ape")]
//! Faithful port of `Image::ExifTool::APE` (lib/Image/ExifTool/APE.pm).
//! PROCESS_PROC for the APE tag stream is the local [`ProcessApe`]; the two
//! header tables (`%OldHeader` ≤3.97, `%NewHeader` ≥3.98) use a minimal local
//! ProcessBinaryData subset (NOT engine-tier — promote to a shared engine
//! module only when a second consumer needs the same feature set, per the
//! D11 incremental-derivation discipline).
//!
//! The full algorithm is APE.pm:119-241 `ProcessAPE`, including the `%Main`
//! tag dictionary (string-keyed), dynamic `MakeTag`-style name munging
//! (APE.pm:102-112), and the `%Composite` Duration computation inline.
//!
//! **Phase F3 — lib-first migration.** This format follows the MOI pilot
//! (Phase E) and AAC/DV (Phase F1) pattern: a typed [`ApeMeta<'a>`] is
//! produced by the new [`crate::parser_new::FormatParser`] trait; the
//! legacy [`crate::parser::OldFormatParser`] entry point bridges through
//! [`crate::sink::MetadataTagWriter`] so CLI JSON output stays byte-exact
//! during the per-format crawl. The bridge keeps the ID3-chained
//! dispatch (`crate::formats::id3::process::process_id3_chained`) under
//! the `ParseContext`-backed legacy path because ID3 migration is a
//! parallel Phase F2 effort and owns the cross-format `SharedFlags`
//! plumbing for the audio-loop seam; APE READS `done_id3` from
//! [`crate::parser_new::SharedFlags`] (faithful APE.pm:169) and WRITES
//! `done_ape` after running (faithful APE.pm:131 / ID3.pm:1723). Phase G
//! retires the bridge.
//!
//! Deferrals (in-code documented, NOT half-built — also enumerated in the
//! spec at docs/superpowers/specs/2026-05-20-ape-port-design.md):
//! - Embedded ID3v1/v2 scan (APE.pm:124-127): IMPLEMENTED in Codex R2-F1
//!   via `crate::formats::id3::process::process_id3_chained` (faithful
//!   flattened model of the audio-loop recursion at ID3.pm:1582-1601).
//!   Pinned by `tests/fixtures/ape_id3_prefixed.ape`.
//! - specialTags `.` suffix collision (APE.pm:209): no real collision exists
//!   for the APE Main table.
//! - `footPos -= $$et{DoneID3}` (APE.pm:169): now tracked by
//!   `Metadata::done_id3()` (`Some(128)` when an ID3v1 trailer was
//!   detected; `Some(0)` for v2-only; `None` if ProcessID3 has not run).
//!   The plumbing of the trailer-size into the `plan_ape_trailer_only`
//!   foot-offset is a documented forward item — it matters only for a
//!   file with BOTH an ID3v1 trailer AND an APEv2 trailer; no such
//!   fixture is in scope. The R2-F1/F2 fixtures only carry ID3v2
//!   prefixes (no v1 trailer), so DoneID3 stays `Some(0)` and the
//!   `if $$et{DoneID3} > 1` branch is not exercised.
//! - Verbose VerboseDir/VerboseDump (APE.pm:184-189): no Verbose option in
//!   this engine.

use crate::{
  parser::ParseContext,
  parser_new::{FormatParser, MetaSinker, SharedFlags, TagWriter, parser_sealed},
  sink::MetadataTagWriter,
  tagtable::{PrintConv, TagDef, TagId, TagTable, ValueConv},
  value::{Group, TagValue},
};

// =============================================================================
// Family-0 group: APE
// =============================================================================

/// Family-0 group for ALL APE-module tags (faithful: APE.pm does NOT override
/// `GROUPS{0}` on `%Main`/`%OldHeader`/`%NewHeader`, so the default family-0
/// is the package name `APE`, ExifTool.pm:3822-3824). Confirmed via
/// `perl exiftool -G` on the real fixture: header tags emit as
/// `APE:CompressionLevel`, etc.
const APE_GROUP0: &str = "APE";

// =============================================================================
// ConvertDuration — PrintConv (ExifTool.pm:6866-6884)
// =============================================================================

/// Faithful port of `sub ConvertDuration` (ExifTool.pm:6866-6884). Used by
/// both APE Main `DURATION` (PrintConv) and the local Composite `Duration`
/// (PrintConv). Operates on the post-ValueConv numeric value.
///
/// IsFloat gate (ExifTool.pm `sub IsFloat`) rejects non-numeric values ⇒ they
/// pass through unchanged. Integer-valued strings/numbers DO satisfy IsFloat
/// (its regex accepts bare `\d+` with no fraction).
fn convert_duration(v: &TagValue) -> TagValue {
  // ExifTool.pm:6869 `return $time unless IsFloat($time);`
  let Some(time) = as_perl_float(v) else {
    return v.clone();
  };
  // ExifTool.pm:6870 `return '0 s' if $time == 0;`
  if time == 0.0 {
    return TagValue::Str("0 s".into());
  }
  // ExifTool.pm:6871 `my $sign = ($time > 0 ? '' : (($time = -$time), '-'));`
  let (sign, mut time) = if time > 0.0 { ("", time) } else { ("-", -time) };
  // ExifTool.pm:6872 `return sprintf("$sign%.2f s", $time) if $time < 30;`
  if time < 30.0 {
    return TagValue::Str(format!("{sign}{time:.2} s").into());
  }
  // ExifTool.pm:6873 `$time += 0.5;` (round to nearest second).
  time += 0.5;
  // ExifTool.pm:6874-6877:
  //   my $h = int($time / 3600);  $time -= $h * 3600;
  //   my $m = int($time / 60);    $time -= $m * 60;
  //
  // Codex r10 finding: Perl `int(f64)` truncates the FLOAT toward zero
  // but keeps the result as Perl NV (f64) when the value exceeds the IV
  // range. `$h -= $d*24` runs on the NV; `"$d days "` interpolation
  // stringifies the NV (`%.15g` for very large values, exact decimal for
  // those within IV range). Naively casting `time/3600.0 as i64`
  // saturates at i64::MAX (≈ 9.2e18) and produces a garbage h:m:s for
  // `time > i64::MAX * 3600` (≈ 3.3e22). Match Perl faithfully:
  //   - Keep h/m/s as f64 for the arithmetic.
  //   - Use `f64::trunc` for Perl's `int()` (truncate toward zero).
  //   - Format the days carve-out's `$d` via `perl_nv_str` (Perl NV
  //     stringify — exact decimal up to i64::MAX, else `%.15g`).
  let h_f = (time / 3600.0).trunc();
  time -= h_f * 3600.0;
  let m_f = (time / 60.0).trunc();
  time -= m_f * 60.0;
  let s_f = time.trunc();
  // ExifTool.pm:6878-6882 days carve-out (`$h > 24`).
  if h_f > 24.0 {
    let d_f = (h_f / 24.0).trunc();
    let h_remainder = h_f - d_f * 24.0;
    return TagValue::Str(
      format!(
        "{sign}{d} days {h}:{m}:{s}",
        d = perl_nv_str(d_f),
        h = perl_nv_str(h_remainder),
        m = perl_int_str_padded(m_f, 2),
        s = perl_int_str_padded(s_f, 2),
      )
      .into(),
    );
  }
  // ExifTool.pm:6883 final sprintf.
  TagValue::Str(
    format!(
      "{sign}{h}:{m}:{s}",
      h = perl_nv_str(h_f),
      m = perl_int_str_padded(m_f, 2),
      s = perl_int_str_padded(s_f, 2),
    )
    .into(),
  )
}

/// Left-pad `n` with leading zeros to `width` when the number is a
/// non-negative integer that fits in i64 (e.g. `5` → `"05"` at width 2).
/// For ConvertDuration's minutes/seconds (always in [0, 60)) this is the
/// in-range path; out-of-range values (impossible for m/s after
/// `time -= h*3600` etc., but defensive against synthetic input) fall
/// back to plain [`perl_nv_str`].
fn perl_int_str_padded(n: f64, width: usize) -> String {
  if n.is_finite() && (0.0..i64::MAX as f64).contains(&n) && n == n.trunc() {
    let iv = n as i64;
    format!("{iv:0width$}")
  } else {
    perl_nv_str(n)
  }
}

/// Perl default NV (number-value-in-string-context) stringification.
/// Equivalent to `sprintf("%.15g", $nv)` for finite values (Perl uses 15
/// significant figures by default). Special values are spelled `Inf` /
/// `-Inf` / `NaN`.
///
/// **Integer carve-out (Codex r11 finding).** Perl's `int()` returns
/// IV/UV-aware integers; stringification preserves the exact decimal as
/// long as the value fits Perl's UV (u64). Empirically against Perl 5:
///   - `int(1e19) ⇒ "10000000000000000000"` (decimal, > i64::MAX)
///   - `int(1.5e19) ⇒ "15000000000000000000"` (decimal)
///   - `int(u64::MAX as f64) ⇒ "18446744073709551615"` (decimal)
///   - `int(1.84467440737096e19) ⇒ "1.84467440737096e+19"` (above u64,
///     scientific)
///
/// We therefore preserve decimal for ANY integer-valued f64 that fits
/// either `i64` (signed range, negatives covered) OR `u64` (positive
/// range up to u64::MAX). Above that ⇒ `%.15g`.
fn perl_nv_str(n: f64) -> String {
  if n.is_nan() {
    return "NaN".to_string();
  }
  if n.is_infinite() {
    return if n.is_sign_negative() { "-Inf" } else { "Inf" }.to_string();
  }
  // Signed-integer carve-out: any integer-valued f64 in [i64::MIN, i64::MAX].
  // Codex r12 finding: `i64::MAX as f64` actually equals 2^63 (not 2^63-1)
  // because i64::MAX is not exactly representable in f64; the cast rounds
  // UP to the next representable f64 value. So `n = 9223372036854775808.0`
  // (exactly 2^63) passes the inclusive `(i64::MIN as f64..=i64::MAX as
  // f64).contains` check, but `n as i64` then saturates to i64::MAX
  // (9223372036854775807), losing exactly one. Perl uses the UV path here
  // and emits the full `9223372036854775808` decimal. Faithful fix: split
  // the signed/unsigned carve-outs at the exact f64 power-of-two boundary
  // 2^63 (signed: n < 2^63; unsigned: 2^63 <= n < 2^64).
  let two63 = (1u128 << 63) as f64; // exactly 9223372036854775808.0
  let two64 = (1u128 << 64) as f64; // exactly 18446744073709551616.0
  // Signed-integer carve-out: integer-valued f64 in [i64::MIN, 2^63),
  // EXCLUDING 2^63 because `n as i64` would saturate to i64::MAX = 2^63-1.
  if n == n.trunc() && n >= i64::MIN as f64 && n < two63 {
    let iv = n as i64;
    return iv.to_string();
  }
  // Unsigned-integer carve-out (Codex r11 + r12): positive integer-valued
  // f64 in [2^63, 2^64). `n as u64` saturates to u64::MAX for `n >= 2^64`,
  // so the strict upper bound is exactly `2^64`. The f64 values exactly
  // at 2^63 and just below 2^64 are both correctly representable as u64.
  if n == n.trunc() && n >= two63 && n < two64 {
    let uv = n as u64;
    return uv.to_string();
  }
  crate::value::format_g(n, 15)
}

/// Perl `IsFloat`-gated coercion (ExifTool.pm `sub IsFloat`):
/// regex `^[+-]?(?=\d|\.\d)\d*(\.\d*)?([Ee][+-]?\d+)?$`. Returns `Some(f64)`
/// if the value satisfies IsFloat (any Perl numeric scalar — integer or
/// float; bare digits, signed, dotted, exponent), else `None`. This is the
/// gate `ConvertDuration` uses (`return $time unless IsFloat($time);`).
///
/// Codex r9 finding: a non-finite f64 (Inf/-Inf/NaN) STRINGIFIES in Perl to
/// "Inf"/"-Inf"/"NaN" — neither of which the IsFloat regex accepts. So
/// passing `TagValue::F64(f64::INFINITY)` to `convert_duration` must MISS
/// the gate (Perl `return $time` short-circuit), keeping the value as-is.
/// We model that here by routing F64 through its `format_perl_string`
/// representation and only returning a coerced f64 when the resulting
/// string passes `is_perl_float` (i.e. finite values only).
fn as_perl_float(v: &TagValue) -> Option<f64> {
  match v {
    TagValue::I64(n) => Some(*n as f64),
    TagValue::F64(x) => {
      // Non-finite ⇒ stringifies to Inf/-Inf/NaN ⇒ IsFloat regex fails ⇒
      // gate miss. Finite ⇒ pass through.
      if x.is_finite() { Some(*x) } else { None }
    }
    TagValue::Str(s) => {
      if is_perl_float(s) {
        s.parse::<f64>().ok()
      } else {
        None
      }
    }
    _ => None,
  }
}

/// Hand-rolled faithful `sub IsFloat` regex
/// `^[+-]?(?=\d|\.\d)\d*(\.\d*)?([Ee][+-]?\d+)?$`. Implemented by hand to
/// keep this crate dependency-free (no `regex`).
fn is_perl_float(s: &str) -> bool {
  let b = s.as_bytes();
  let mut i = 0;
  // [+-]?
  if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
    i += 1;
  }
  // Lookahead: \d or .\d
  let la = match b.get(i) {
    Some(c) if c.is_ascii_digit() => true,
    Some(b'.') => matches!(b.get(i + 1), Some(c) if c.is_ascii_digit()),
    _ => false,
  };
  if !la {
    return false;
  }
  // \d*
  while i < b.len() && b[i].is_ascii_digit() {
    i += 1;
  }
  // (\.\d*)?
  if i < b.len() && b[i] == b'.' {
    i += 1;
    while i < b.len() && b[i].is_ascii_digit() {
      i += 1;
    }
  }
  // ([Ee][+-]?\d+)?
  if i < b.len() && (b[i] == b'E' || b[i] == b'e') {
    i += 1;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
      i += 1;
    }
    let exp_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
      i += 1;
    }
    if i == exp_start {
      return false;
    }
  }
  i == b.len()
}

// =============================================================================
// MakeTag — dynamic name munge (APE.pm:102-112)
// =============================================================================

/// Faithful port of `MakeTag` (APE.pm:102-112). Computes the in-table tag
/// name from a runtime APE tag KEY. The Perl logic, in order:
///
/// ```text
/// my $name = ucfirst(lc($tag));                          # lowercase, first char uppercased
/// $name =~ s/[^\w-]+(.?)/\U$1/sg;                        # collapse runs of [^\w-], uppercase next
/// $name =~ s/([a-z0-9])_([a-z])/$1\U$2/g;                # snake_case to camelCase
/// ```
///
/// Perl `\w` = `[A-Za-z0-9_]`. The hyphen `-` is preserved by the first
/// regex's negated class `[^\w-]`. The trailing empty `(.?)` allows a run at
/// end-of-string to consume nothing (deleting the run entirely).
fn make_tag(tag: &str) -> String {
  // ucfirst(lc($tag)) — entire string lowercased, then first char uppercased.
  // Empty input keeps `out` empty; we still flow into the AddTagToTable
  // post-processing below, which prepends "Tag" for length-<2 names.
  let mut chars = tag.chars();
  let first = chars.next();
  let mut out: String = match first {
    Some(c) => c.to_ascii_uppercase().to_string(),
    None => String::new(),
  };
  // (APE tag keys are ASCII in practice; uppercasing the ASCII first char
  // matches Perl `ucfirst` on a 7-bit-ASCII string. We `to_ascii_lowercase`
  // the rest below — APE.pm uses byte-level Perl `lc`/`uc` semantics, which
  // for ASCII input are byte-faithful.)
  for c in chars {
    out.push(c.to_ascii_lowercase());
  }
  // s/[^\w-]+(.?)/\U$1/sg
  let bytes = out.as_bytes();
  let mut out2 = String::with_capacity(out.len());
  let mut i = 0;
  while i < bytes.len() {
    let b = bytes[i];
    let is_word_or_dash = b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
    if is_word_or_dash {
      out2.push(b as char);
      i += 1;
    } else {
      // Consume the run of [^\w-].
      while i < bytes.len() {
        let bb = bytes[i];
        let kw = bb.is_ascii_alphanumeric() || bb == b'_' || bb == b'-';
        if kw {
          break;
        }
        i += 1;
      }
      // (.?) — optionally consume one more char (any) and uppercase it.
      if i < bytes.len() {
        let nxt = bytes[i] as char;
        out2.push(nxt.to_ascii_uppercase());
        i += 1;
      }
      // If end-of-string here, the empty (.?) matched ε — nothing appended.
    }
  }
  // s/([a-z0-9])_([a-z])/$1\U$2/g — snake_case to camelCase. Hand-rolled
  // to be FAITHFUL to Perl's `s///g` non-overlapping match semantics
  // (Codex r4 finding): after a successful match at position `j`, the
  // three matched bytes (`X_y`) are CONSUMED — the next search starts
  // AFTER them, and the previously-consumed `[a-z]` is NOT available as
  // left-context for a follow-on match. Earlier code treated the regex
  // as a lookbehind on `bs[j-1]`, which mis-handles `aa_b_c → AaB_c`
  // (greedy lookbehind gave the wrong `AaBC`).
  //
  // Match-driven walk: at each position j, check whether the THREE
  // bytes at j..j+3 form `[a-z0-9]_[a-z]`. If so, consume them and
  // emit `<bs[j]><uppercase(bs[j+2])>`. Else emit bs[j] and advance 1.
  let bs = out2.as_bytes();
  let mut out3 = String::with_capacity(out2.len());
  let mut j = 0;
  while j < bs.len() {
    if j + 2 < bs.len() {
      let a = bs[j];
      let u = bs[j + 1];
      let b = bs[j + 2];
      let a_ok = a.is_ascii_lowercase() || a.is_ascii_digit();
      if a_ok && u == b'_' && b.is_ascii_lowercase() {
        out3.push(a as char);
        out3.push(b.to_ascii_uppercase() as char);
        j += 3;
        continue;
      }
    }
    out3.push(bs[j] as char);
    j += 1;
  }
  // === ExifTool.pm:9243-9255 `AddTagToTable` post-processing ===========
  // MakeTag (APE.pm:102-112) calls AddTagToTable to register the new
  // tagInfo. AddTagToTable then applies further name normalisation
  // BEFORE the name reaches FoundTag and the metadata sink:
  //   9245: `$name =~ tr/-_a-zA-Z0-9//dc;` — strip illegal chars (keep
  //         only ASCII letters, digits, '-', '_'). For APE keys with
  //         e.g. '.' / ':' / ',' the chars that survived MakeTag's
  //         s/[^\w-]+(.?)/\U$1/sg are pruned here.
  //   9246: `$name = ucfirst $name;` — capitalize first letter. (Already
  //         applied by MakeTag's ucfirst, but if the s/// collapsed all
  //         leading non-word chars to nothing the result could start
  //         with a digit — ucfirst is a no-op on digit, but harmless.)
  //   9254: `$name = "Tag$name" if length($name) < 2 or $name !~ /^[A-Z]/i;`
  //         If the name is shorter than 2 chars OR doesn't start with
  //         an ASCII letter, prepend literal `Tag`. Empirically
  //         verified against bundled ExifTool 13.58 on single-char
  //         dynamic keys: "1" → "Tag1", "-" → "Tag-", "_" → "Tag_",
  //         "." → "Tag" (the dot is stripped by tr/// ⇒ empty ⇒ Tag).
  //
  // Codex r12 finding: the port previously stopped after MakeTag and
  // emitted the raw munged name, diverging from bundled Perl on these
  // single-char/single-non-word keys.
  let after_tr: String = out3
    .chars()
    .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
    .collect();
  // ucfirst (no-op when the string is empty or the first char isn't a
  // lowercase ASCII letter).
  let mut chars = after_tr.chars();
  let mut ucfirst_buf = String::with_capacity(after_tr.len());
  if let Some(c0) = chars.next() {
    ucfirst_buf.push(c0.to_ascii_uppercase());
    for c in chars {
      ucfirst_buf.push(c);
    }
  }
  // length < 2 OR doesn't start with [A-Za-z] ⇒ prepend "Tag".
  let starts_with_letter = ucfirst_buf
    .as_bytes()
    .first()
    .copied()
    .is_some_and(|b| b.is_ascii_alphabetic());
  if ucfirst_buf.chars().count() < 2 || !starts_with_letter {
    let mut prefixed = String::with_capacity(3 + ucfirst_buf.len());
    prefixed.push_str("Tag");
    prefixed.push_str(&ucfirst_buf);
    return prefixed;
  }
  ucfirst_buf
}

// =============================================================================
// APETAGEX size validity decoder (APE.pm:180-181)
// =============================================================================

/// Decode the APETAGEX header/footer 32-bit `size` field into a body-size
/// (post-`-32`) usize, returning `None` when the bit-31 guard fails.
///
/// Perl flow (APE.pm:180-181):
///
/// ```text
/// $size -= 32;                       # signed Perl arithmetic
/// if (($size & 0x80000000) == 0 ...) # high bit on the POST-subtract
///                                    # value ⇒ invalid
/// ```
///
/// The subtract is FIRST, then the bit-31 check. This matters for the
/// boundary `raw ∈ 0x80000000..=0x8000001f`: Perl's signed
/// `$size = raw - 32` wraps to a positive value in
/// `0x7fffffe0..=0x7fffffff`, passing the guard (Codex r14 finding).
/// Earlier code checked `raw & 0x80000000` before subtracting and
/// incorrectly rejected this range.
///
/// Implementation: `wrapping_sub` on `u32` mirrors Perl's two's-complement
/// signed arithmetic over the 32-bit window. The body-size cast to `usize`
/// is safe because `body_u32` has bit 31 unset ⇒ value fits in 31 bits.
///
/// Module-scope so unit tests can pin the exact mapping (Codex r15
/// finding: the process-level integration tests could not distinguish
/// "guard correctly accepts then short-read fails" from "guard
/// incorrectly rejects" on a small fixture).
fn decode_apetagex_body_size(size_raw: u32) -> Option<usize> {
  let body_u32 = size_raw.wrapping_sub(32);
  if (body_u32 & 0x8000_0000) != 0 {
    None
  } else {
    Some(body_u32 as usize)
  }
}

// =============================================================================
// Header tables — minimal local ProcessBinaryData subset
// =============================================================================

/// Width-and-offset rule, faithful to ExifTool.pm:9922 (`$entry =
/// int($index) * $increment + $varSize`, with `$increment =
/// $formatSize{$defaultFormat}`). Both APE header tables default
/// `FORMAT => 'int16u'`, so `index * 2`. No `var_*` formats in APE ⇒
/// `varSize == 0` ⇒ pure `index * 2`.
const APE_HEADER_INCREMENT: usize = 2;

/// One field of an APE binary-data header table.
struct ApeBinaryField {
  /// `$index` in `%OldHeader` / `%NewHeader` (the Perl hash key).
  index: u8,
  /// `$$tagInfo{Name}` — the resolved TagDef name to push.
  name: &'static str,
  /// Optional `$$tagInfo{Format}` override; `None` ⇒ table default (`int16u`).
  format_override: Option<ApeBinaryFormat>,
}

impl ApeBinaryField {
  /// `const fn` so the static tables can be built at compile time.
  const fn new(index: u8, name: &'static str, format_override: Option<ApeBinaryFormat>) -> Self {
    Self {
      index,
      name,
      format_override,
    }
  }
}

/// The two binary-data formats APE.pm uses. Newtype-style (D8): unit
/// variants only. Both little-endian (APE.pm:140 `SetByteOrder('II')`).
#[derive(Clone, Copy, derive_more::IsVariant)]
enum ApeBinaryFormat {
  Int16u,
  Int32u,
}

impl ApeBinaryFormat {
  const fn width(self) -> usize {
    match self {
      ApeBinaryFormat::Int16u => 2,
      ApeBinaryFormat::Int32u => 4,
    }
  }
}

// --- ValueConv funcs --------------------------------------------------------

/// APE.pm:51-53 `OldHeader::APEVersion` `ValueConv => '$val / 1000'`. Perl
/// `/` on integer scalars yields a float ⇒ produce f64 unconditionally.
fn ape_version_div_1000(v: &TagValue) -> TagValue {
  match v {
    TagValue::I64(n) => TagValue::F64((*n as f64) / 1000.0),
    TagValue::F64(x) => TagValue::F64(x / 1000.0),
    other => other.clone(),
  }
}

// --- Header TagDefs (D5 line-tagged) ----------------------------------------

// APE.pm:50-53
static APEVERSION: TagDef = TagDef::new(
  "APEVersion",
  "MAC",
  ValueConv::Func(ape_version_div_1000),
  PrintConv::None,
);
// APE.pm:54 / APE.pm:70
static COMPRESSION_LEVEL: TagDef =
  TagDef::new("CompressionLevel", "MAC", ValueConv::None, PrintConv::None);
// APE.pm:56 / APE.pm:76
static CHANNELS: TagDef = TagDef::new("Channels", "MAC", ValueConv::None, PrintConv::None);
// APE.pm:57 / APE.pm:77
// Phase F3: production typed-Meta path reads fields directly off `ApeHeader::{Old,New}`; the
// static defs survive only as the test-fixture reference for the binary-data extractor.
#[allow(dead_code)]
static SAMPLE_RATE: TagDef = TagDef::new("SampleRate", "MAC", ValueConv::None, PrintConv::None);
// APE.pm:60 / APE.pm:74
#[allow(dead_code)]
static TOTAL_FRAMES: TagDef = TagDef::new("TotalFrames", "MAC", ValueConv::None, PrintConv::None);
// APE.pm:61 / APE.pm:73
#[allow(dead_code)]
static FINAL_FRAME_BLOCKS: TagDef =
  TagDef::new("FinalFrameBlocks", "MAC", ValueConv::None, PrintConv::None);
// APE.pm:72
#[allow(dead_code)]
static BLOCKS_PER_FRAME: TagDef =
  TagDef::new("BlocksPerFrame", "MAC", ValueConv::None, PrintConv::None);
// APE.pm:75
#[allow(dead_code)]
static BITS_PER_SAMPLE: TagDef =
  TagDef::new("BitsPerSample", "MAC", ValueConv::None, PrintConv::None);

/// `%APE::OldHeader` (APE.pm:45-62). FORMAT=int16u, GROUPS{1}='MAC'.
/// Numerically-sorted indices (ExifTool.pm:9907 default `sort` order):
/// 0, 1, 3, 4, 10, 12. (Indices 2/6/8 are commented out in APE.pm; not ours.)
const OLD_HEADER: &[ApeBinaryField] = &[
  ApeBinaryField::new(0, "APEVersion", None), // APE.pm:50-53
  ApeBinaryField::new(1, "CompressionLevel", None), // APE.pm:54
  ApeBinaryField::new(3, "Channels", None),   // APE.pm:56
  ApeBinaryField::new(4, "SampleRate", Some(ApeBinaryFormat::Int32u)), // APE.pm:57
  ApeBinaryField::new(10, "TotalFrames", Some(ApeBinaryFormat::Int32u)), // APE.pm:60
  ApeBinaryField::new(12, "FinalFrameBlocks", Some(ApeBinaryFormat::Int32u)), // APE.pm:61
];

/// `%APE::NewHeader` (APE.pm:65-78). FORMAT=int16u, GROUPS{1}='MAC'.
/// Numerically-sorted indices: 0, 2, 4, 6, 8, 9, 10.
const NEW_HEADER: &[ApeBinaryField] = &[
  ApeBinaryField::new(0, "CompressionLevel", None), // APE.pm:70
  ApeBinaryField::new(2, "BlocksPerFrame", Some(ApeBinaryFormat::Int32u)), // APE.pm:72
  ApeBinaryField::new(4, "FinalFrameBlocks", Some(ApeBinaryFormat::Int32u)), // APE.pm:73
  ApeBinaryField::new(6, "TotalFrames", Some(ApeBinaryFormat::Int32u)), // APE.pm:74
  ApeBinaryField::new(8, "BitsPerSample", None),    // APE.pm:75
  ApeBinaryField::new(9, "Channels", None),         // APE.pm:76
  ApeBinaryField::new(10, "SampleRate", Some(ApeBinaryFormat::Int32u)), // APE.pm:77
];

/// Read an unsigned LE integer of width `width` (2 or 4) from `data[offset..]`.
/// Returns `None` if `offset + width > data.len()` — used to faithfully model
/// ExifTool.pm:9953 `last if $more <= 0` (silent stop on overrun).
fn read_le_uint(data: &[u8], offset: usize, width: usize) -> Option<u64> {
  let end = offset.checked_add(width)?;
  if end > data.len() {
    return None;
  }
  let bytes = &data[offset..end];
  Some(match width {
    2 => u16::from_le_bytes([bytes[0], bytes[1]]) as u64,
    4 => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
    // Unreachable for current APE tables; safe default so this fn never panics.
    _ => return None,
  })
}

/// Resolve a header field's static TagDef. APE header tags share the SAME
/// static TagDef set across OldHeader and NewHeader (Names overlap exactly),
/// so a single `match` suffices.
///
/// Phase F3 migration: the production header emission now reads directly
/// from the typed `ApeHeader` enum in `meta_from_plan`; this helper
/// remains for unit-test coverage of `process_ape_binary_data` (kept as
/// the binary-data extractor reference impl until Phase G).
#[allow(dead_code)] // Phase F3 — test-only after typed ApeMeta migration.
fn tag_def_for_header_field(name: &str) -> &'static TagDef {
  match name {
    "APEVersion" => &APEVERSION,
    "CompressionLevel" => &COMPRESSION_LEVEL,
    "Channels" => &CHANNELS,
    "SampleRate" => &SAMPLE_RATE,
    "TotalFrames" => &TOTAL_FRAMES,
    "FinalFrameBlocks" => &FINAL_FRAME_BLOCKS,
    "BlocksPerFrame" => &BLOCKS_PER_FRAME,
    "BitsPerSample" => &BITS_PER_SAMPLE,
    // Tables above are constants; an unknown name is a programming error.
    _ => unreachable!("APE header field {name} has no TagDef"),
  }
}

/// Minimal ProcessBinaryData subset for APE OldHeader/NewHeader (NOT
/// engine-tier; promote to `src/binary_data.rs` only when a second format
/// needs the same feature set). APE.pm's two header tables exercise just a
/// flat `FORMAT => 'int16u'` default + per-field `Format => 'int32u'`
/// overrides + `Name` + an optional `ValueConv`. No Mask, no relative tag
/// dispatch, no Condition.
///
/// Phase F3 migration: production now lifts via `extract_old_header` /
/// `extract_new_header` into the typed `ApeHeader` enum; this helper
/// remains for unit-test coverage of the binary-data extraction shape.
#[allow(dead_code)] // Phase F3 — test-only after typed ApeMeta migration.
fn process_ape_binary_data(
  data: &[u8],
  table: &'static [ApeBinaryField],
  into: &mut crate::value::Metadata,
  print_conv_enabled: bool,
) {
  for field in table {
    let offset = (field.index as usize) * APE_HEADER_INCREMENT;
    let format = field.format_override.unwrap_or(ApeBinaryFormat::Int16u);
    let Some(raw) = read_le_uint(data, offset, format.width()) else {
      // ExifTool.pm:9953 `last if $more <= 0`: subsequent (higher-index)
      // fields cannot possibly fit either — `break` is value-identical.
      break;
    };
    // ExifTool int formats up to int32u fit in i64 unchanged.
    let raw_val = TagValue::I64(raw as i64);
    let def = tag_def_for_header_field(field.name);
    let converted = crate::convert::apply(def, &raw_val, print_conv_enabled);
    into.push(Group::new(APE_GROUP0, def.group1()), def.name(), converted);
  }
}

// =============================================================================
// Perl boolean truthiness (Codex r10 finding for Composite RawConv guard)
// =============================================================================

/// Perl boolean context (`if ($val)`) for a `TagValue`. Faithful semantics
/// (verified empirically against Perl 5):
///   - `Str(s)`: TRUE iff `s` is non-empty AND not the exact literal `"0"`.
///     So `"0E0"`, `"0.0"`, `"00"`, `"+0"`, `" 0"`, `"0abc"` are all TRUE.
///   - `I64(n)`: TRUE iff `n != 0`.
///   - `F64(x)`: TRUE iff `x != 0.0` (NaN compares unequal to 0.0 in
///     IEEE, so NaN is reported as TRUE — faithful: Perl NaN is truthy).
///   - `Bool(b)`: TRUE iff `b` (direct Perl-bool mapping).
///   - `Bytes(b)`: TRUE iff `!b.is_empty()` AND `b != [b'0']`
///     (byte-faithful to the string rule).
///   - `Rational(n,d)`: TRUE iff `n != 0` (Perl scalar stringifies; 0/X
///     evaluates to "0" which is falsey).
///   - `List(_)`: list-context truthiness in Perl is the count, but here
///     `$val[N]` deref'd from `@val` returns a scalar; this can't be a
///     `List` realistically. Conservative: TRUE iff non-empty.
fn perl_boolean_truthy(v: &TagValue) -> bool {
  match v {
    TagValue::Str(s) => !s.is_empty() && s.as_str() != "0",
    TagValue::I64(n) => *n != 0,
    #[allow(clippy::float_cmp)]
    TagValue::F64(x) => *x != 0.0,
    TagValue::Bool(b) => *b,
    TagValue::Bytes(b) => !b.is_empty() && b.as_slice() != b"0",
    TagValue::Rational(r) => r.numerator() != 0,
    TagValue::List(l) => !l.is_empty(),
  }
}

// =============================================================================
// %APE::Main tag dictionary (APE.pm:21-42)
// =============================================================================

/// APE.pm:35-39 `DURATION` ValueConv:
///   `$val += 4294967296 if $val < 0 and $val >= -2147483648; $val * 1e-7`
///
/// Faithful: signed-i32 → unsigned wrap correction (when the on-disk DURATION
/// is read as a signed i32 and lands in the negative half, add 2^32 to
/// recover the unsigned interpretation), then scale by 1e-7. Output is f64.
///
/// **Perl numeric coercion is part of this ValueConv.** APE.pm runs `$val +=`
/// and `$val * 1e-7` directly on `$val`, which Perl coerces via its
/// leading-prefix numeric scan — accepting `"20000000"`, `"20000000\0"`,
/// `"  20000000"`, `"20000000.5"`, `"-1.0"`, etc. We replicate that here so
/// the same set of value shapes produces the same scaled f64 ExifTool would,
/// not just the exact-`i64` subset (Codex r1 finding 3).
fn ape_duration_value_conv(v: &TagValue) -> TagValue {
  // Step 1: coerce to f64 via the same Perl-numeric rule for every variant.
  let val_f64: f64 = match v {
    TagValue::I64(n) => *n as f64,
    TagValue::F64(x) => *x,
    TagValue::Str(s) => perl_numeric_coerce_f64(s),
    // Bytes/Bool/Rational/List: Perl-truthy coercion of these is
    // unrealistic for an APE DURATION tag value — bundled ExifTool would
    // never feed one in. Faithful: return the value unchanged (no panic,
    // no silent corruption).
    other => return other.clone(),
  };
  // Step 2: Perl `$val < 0 and $val >= -2147483648` numeric guard. This is
  // a NUMERIC comparison (not integer); a fractional negative in
  // [-2147483648, 0) DOES trigger the +2^32 wrap (faithful Perl semantics).
  // For non-finite f64 (Inf/-Inf/NaN), the comparison `$val < 0 and >= MIN`
  // is always FALSE (NaN ⇒ all comparisons false; ±Inf ⇒ `>= -2^31` false
  // for -Inf), so no wrap is applied — matching Perl semantics.
  let wrapped = if (-2_147_483_648.0_f64..0.0).contains(&val_f64) {
    val_f64 + 4_294_967_296.0_f64
  } else {
    val_f64
  };
  // Step 3: scale.
  let scaled = wrapped * 1e-7;
  // Codex r6 finding 2: Perl `0 + "Inf"` yields IEEE Inf; `Inf * 1e-7` is
  // still Inf. ExifTool stringifies these as `Inf`/`-Inf`/`NaN` and
  // EscapeJSON quotes them (they fail the numeric-literal regex). The
  // engine serializer DOES quote non-finite f64 (src/serialize.rs:159-
  // 165), but via Rust's `f64::to_string()` which produces lowercase
  // `inf`/`-inf` — Perl uses capitalised `Inf`/`-Inf`. So a bare
  // `TagValue::F64(non-finite)` would byte-diverge. We sidestep at the
  // format layer by emitting the Perl-stringified form as a
  // `TagValue::Str` directly. This is exactly what bundled Perl ExifTool
  // produces on inputs like `DURATION=Inf` / `DURATION=NaN`:
  // `"APE:Duration": "Inf"` (quoted, both with and without `-n`).
  if !scaled.is_finite() {
    let s = if scaled.is_nan() {
      "NaN"
    } else if scaled.is_sign_negative() {
      "-Inf"
    } else {
      "Inf"
    };
    return TagValue::Str(s.into());
  }
  TagValue::F64(scaled)
}

/// Perl numeric coercion (leading-prefix scan) returning `f64`. Faithful
/// to Perl's `0 + $str` rule for any APE tag value passed through a
/// numeric ValueConv:
///
/// Step 1 — skip optional ASCII whitespace.
/// Step 2a — match the special tokens `[+-]?(Inf(inity)?|NaN)`
/// case-insensitively FIRST (Perl numeric context accepts these; Codex r6
/// finding 2). A successful match returns `f64::INFINITY`,
/// `f64::NEG_INFINITY`, or `f64::NAN`.
/// Step 2b — otherwise match `[+-]?(\d+(\.\d*)?|\.\d+)([Ee][+-]?\d+)?`
/// greedily from the start.
/// Step 3 — if neither matches, return `0.0` (Perl `"abc" + 0 == 0`).
/// Step 4 — else parse the captured prefix as `f64`; overflow (e.g.
/// `1e309`) naturally yields `f64::INFINITY`, matching Perl.
///
/// This is local to APE because the engine's `convert::perl_numeric_coerce`
/// returns `u64` (BITMASK semantics); DURATION needs signed/float coercion.
/// (Engine-tier promotion is the right move once a second format consumer
/// arrives.)
fn perl_numeric_coerce_f64(s: &str) -> f64 {
  let bytes = s.as_bytes();
  let is_ws = |b: u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'\x0b' | b'\x0c');
  let mut i = 0;
  // 1. Leading ASCII whitespace.
  while i < bytes.len() && is_ws(bytes[i]) {
    i += 1;
  }
  // 2. Optional dual-sign parsing (Codex r7 finding). Perl's numeric
  // context accepts up to TWO sign characters with one whitespace block
  // between them, with NO whitespace permitted after the second sign.
  // Empirically verified against Perl 5:
  //   "+ 20000000"   → 20000000 (sign1, ws, no sign2, digits)
  //   "+-20000000"   → -20000000 (sign1, sign2 adjacent, digits)
  //   "--20000000"   → 20000000  (multiplicative: -×- = +)
  //   "-+Inf"        → -Inf
  //   "++Inf"        → Inf
  //   "+ +20"        → 20 (sign1 + ws + sign2 + digits)
  //   "+ +Inf"       → not tested but presumed Inf by same rule
  //   "+-20"         → -20 (sign1, sign2 adjacent)
  //   "+- 20"        → 0  (sign1 + sign2 + ws + digits — REJECTED:
  //                       ws not allowed after sign2)
  //   "-  -  20"     → 0  (same: sign2 followed by ws → reject)
  //   "+--20000000"  → 0  (three signs)
  //   "+- +20"       → not parseable per pattern
  //   "   20"        → 20 (no sign at all)
  // Algorithm: track effective sign = product of any signs seen.
  let mut neg = false;
  let mut sign_count = 0u8;
  // Sign 1.
  if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
    if bytes[i] == b'-' {
      neg = !neg;
    }
    i += 1;
    sign_count = 1;
    // Optional whitespace between sign 1 and sign 2 / digits.
    while i < bytes.len() && is_ws(bytes[i]) {
      i += 1;
    }
    // Sign 2 (no whitespace after this sign).
    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
      if bytes[i] == b'-' {
        neg = !neg;
      }
      i += 1;
      sign_count = 2;
    }
  }
  // After sign 2, if there's another sign character OR whitespace, Perl
  // rejects the whole prefix. (Empirically: "+--20" / "-+ 20" / "+- 20"
  // all return 0.)
  if sign_count == 2 && i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-' || is_ws(bytes[i]))
  {
    return 0.0;
  }
  // 3. Special tokens Inf/Infinity/NaN (Codex r6 + r7). Case-insensitive
  // ASCII; PREFIX scan — `"InfX" + 0` is still Inf.
  let starts_with_ci = |rest: &[u8], lit: &[u8]| -> bool {
    rest.len() >= lit.len()
      && rest[..lit.len()]
        .iter()
        .zip(lit.iter())
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
  };
  // Match "Infinity" first (longest), then "Inf", then "NaN".
  if starts_with_ci(&bytes[i..], b"Infinity") || starts_with_ci(&bytes[i..], b"Inf") {
    return if neg {
      f64::NEG_INFINITY
    } else {
      f64::INFINITY
    };
  }
  if starts_with_ci(&bytes[i..], b"NaN") {
    // Perl NaN has no sign distinction in stringification ("NaN" not
    // "-NaN"), so we ignore `neg` here.
    return f64::NAN;
  }
  // 4. Finite numeric prefix: `\d+(\.\d*)?` or `\.\d+`, optional exponent.
  // The sign characters were already consumed above; we now parse digits
  // only, manually wrapping the sign into the parsed value.
  let num_start = i;
  let digits_before_dot_start = i;
  while i < bytes.len() && bytes[i].is_ascii_digit() {
    i += 1;
  }
  let had_int_digits = i > digits_before_dot_start;
  if i < bytes.len() && bytes[i] == b'.' {
    i += 1;
    let frac_start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
      i += 1;
    }
    let had_frac_digits = i > frac_start;
    if !had_int_digits && !had_frac_digits {
      // Just a lone `.` with no digits ⇒ no numeric prefix.
      return 0.0;
    }
  } else if !had_int_digits {
    // No leading digits and no `.\d+` form ⇒ no numeric prefix.
    return 0.0;
  }
  // Optional exponent.
  let pre_exp = i;
  if i < bytes.len() && (bytes[i] == b'E' || bytes[i] == b'e') {
    i += 1;
    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
      i += 1;
    }
    let exp_digits_start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
      i += 1;
    }
    if i == exp_digits_start {
      // `E` with no following digits ⇒ Perl's prefix scan rejects the `E`
      // (the regex requires `\d+` after `[Ee][+-]?`), so the prefix
      // terminates BEFORE the `E`. Faithful: drop back to `pre_exp`.
      i = pre_exp;
    }
  }
  // Parse the matched numeric prefix as positive, then apply the sign.
  let mag = s[num_start..i].parse::<f64>().unwrap_or(0.0);
  if neg { -mag } else { mag }
}

// APE.pm:29
static MAIN_ALBUM: TagDef = TagDef::new("Album", "APE", ValueConv::None, PrintConv::None);
// APE.pm:30
static MAIN_ARTIST: TagDef = TagDef::new("Artist", "APE", ValueConv::None, PrintConv::None);
// APE.pm:31
static MAIN_GENRE: TagDef = TagDef::new("Genre", "APE", ValueConv::None, PrintConv::None);
// APE.pm:32
static MAIN_TITLE: TagDef = TagDef::new("Title", "APE", ValueConv::None, PrintConv::None);
// APE.pm:33
static MAIN_TRACK: TagDef = TagDef::new("Track", "APE", ValueConv::None, PrintConv::None);
// APE.pm:34
static MAIN_YEAR: TagDef = TagDef::new("Year", "APE", ValueConv::None, PrintConv::None);
// APE.pm:40 'Tool Version' => { Name => 'ToolVersion' }
static MAIN_TOOLVERSION: TagDef =
  TagDef::new("ToolVersion", "APE", ValueConv::None, PrintConv::None);
// APE.pm:41 'Tool Name' => { Name => 'ToolName' }
static MAIN_TOOLNAME: TagDef = TagDef::new("ToolName", "APE", ValueConv::None, PrintConv::None);
// APE.pm:35-39 DURATION ⇒ Duration (with ValueConv + PrintConv).
static MAIN_DURATION: TagDef = TagDef::new(
  "Duration",
  "APE",
  ValueConv::Func(ape_duration_value_conv),
  PrintConv::Func(convert_duration),
);

fn ape_main_get(id: TagId) -> Option<&'static TagDef> {
  // ExifTool indexes %Main by the runtime APE tag KEY (string).
  match id {
    TagId::Str("Album") => Some(&MAIN_ALBUM),
    TagId::Str("Artist") => Some(&MAIN_ARTIST),
    TagId::Str("Genre") => Some(&MAIN_GENRE),
    TagId::Str("Title") => Some(&MAIN_TITLE),
    TagId::Str("Track") => Some(&MAIN_TRACK),
    TagId::Str("Year") => Some(&MAIN_YEAR),
    TagId::Str("Tool Version") => Some(&MAIN_TOOLVERSION),
    TagId::Str("Tool Name") => Some(&MAIN_TOOLNAME),
    TagId::Str("DURATION") => Some(&MAIN_DURATION),
    _ => None,
  }
}

/// `%APE::Main` (APE.pm:21-42). String-keyed (TagId::Str) by the runtime APE
/// tag KEY. group0 = `APE`, group1 = `APE` (both default from the package).
pub static APE_MAIN: TagTable = TagTable::new(APE_GROUP0, ape_main_get);

// =============================================================================
// ProcessAPE driver (APE.pm:119-241)
// =============================================================================

/// APE parser (faithful `ProcessAPE`, APE.pm:119-241). Reads `ctx.data()`
/// as the file bytes (the engine passes the whole file; all Perl `$raf`
/// seeks become slice indexing).
#[derive(Debug, Clone, Copy)]
pub struct ProcessApe;

impl parser_sealed::Sealed for ProcessApe {}

/// Per-format parser context for APE (spec §6.4). Chained format ⇒ wraps
/// the input bytes alongside the cross-format
/// [`SharedFlags`](crate::parser_new::SharedFlags) state read for
/// `done_id3` (APE.pm:169) and written for `done_ape` (APE.pm:131 →
/// ID3.pm:1723). Leaves like AAC/DV/MOI take just `&'a [u8]`; APE chains
/// so it takes both.
///
/// D8 convention: no public fields, accessors only.
#[derive(Debug)]
pub struct ApeContext<'a> {
  data: &'a [u8],
  shared: &'a mut SharedFlags,
  /// Mirror of `Metadata::done_id3` from the legacy bridge. When `Some(n)`,
  /// the typed parser uses `n` as the trailer shift (APE.pm:169); when
  /// `None`, the typed parser interprets it as "ID3 has not run" and
  /// falls back to `shared.done_id3()` for the same purpose. The bridge
  /// in [`OldFormatParser::process`] populates this from
  /// `ctx.metadata().done_id3()` to thread the legacy v1-trailer-size
  /// state through; pure lib-callers leave it `None` and let the
  /// [`SharedFlags`] copy drive the shift.
  done_id3_legacy: Option<usize>,
  /// `true` when the typed parser should run ONLY the trailer-scan path
  /// (faithful APE.pm:118 `Just looks for APE trailer if FileType is
  /// already set`). The legacy bridge sets this to `true` when a prior
  /// parser already typed the file (e.g. MP3 calling APE for the trailer
  /// fallback via ID3.pm:1722-1727); the magic check + SetFileType +
  /// binary-header block (APE.pm:137-162) is skipped, only the
  /// APETAGEX-trailer block (APE.pm:165-237) runs.
  trailer_only: bool,
}

impl<'a> ApeContext<'a> {
  /// Construct the standard (full-parse) context. Used when APE is the
  /// detected file type and the typed parser owns the magic check +
  /// SetFileType + binary-header block + tag-stream walk.
  #[must_use]
  pub fn new(data: &'a [u8], shared: &'a mut SharedFlags) -> Self {
    Self {
      data,
      shared,
      done_id3_legacy: None,
      trailer_only: false,
    }
  }

  /// Construct a chained-parser trailer-only context. Used by MP3/MPC/
  /// WavPack chained dispatch (ID3.pm:1722-1727 → bundled ProcessAPE with
  /// `$$et{FileType}` already set ⇒ APE.pm:136 false ⇒ magic-and-header
  /// block skipped ⇒ trailer scan only).
  #[must_use]
  pub fn new_trailer_only(data: &'a [u8], shared: &'a mut SharedFlags) -> Self {
    Self {
      data,
      shared,
      done_id3_legacy: None,
      trailer_only: true,
    }
  }

  /// Input bytes.
  #[must_use]
  pub fn data(&self) -> &'a [u8] {
    self.data
  }

  /// Cross-format shared state.
  #[must_use]
  pub fn shared(&self) -> &SharedFlags {
    self.shared
  }

  /// Mutable cross-format shared state (the parser sets `done_ape` after
  /// running, faithful APE.pm:131).
  pub fn shared_mut(&mut self) -> &mut SharedFlags {
    self.shared
  }
}

/// Which MAC header table (if any) applies, and its body bytes.
/// Owned `Vec<u8>` so the borrow on `ctx.data()` is released before we
/// touch `ctx.metadata()`. `pub(crate)` to match
/// [`plan_ape_trailer_only`]'s return type (Codex r15 finding).
pub(crate) enum HeaderJob {
  None,
  Old(Vec<u8>),
  New(Vec<u8>),
}

/// The byte work the driver does in its read-only Phase 1. `Owned`
/// so we drop the `ctx.data()` borrow before mutating `ctx.metadata()`.
/// `pub(crate)` to match [`plan_ape_trailer_only`]'s return type;
/// fields stay private (D8 — no public fields, accessors only).
pub(crate) struct ApePlan {
  header_job: HeaderJob,
  /// `(group1, name, value)` tuples to push in order.
  pending: Vec<(&'static str, String, TagValue)>,
  /// Whether to emit `Warn('Bad APE trailer')`.
  warn_bad_trailer: bool,
}

#[allow(dead_code)] // Phase-1: no chained-parser consumer in-tree yet; Phase-2 will wire it.
impl ApePlan {
  /// The selected MAC header table (if any) and its body bytes.
  pub(crate) fn header_job(&self) -> &HeaderJob {
    &self.header_job
  }
  /// Pending tag pushes (g1, name, value), in extraction order. The
  /// chained-parser entry point [`ProcessApe::process_trailer_only`]
  /// consumes this directly.
  pub(crate) fn pending(&self) -> &[(&'static str, String, TagValue)] {
    &self.pending
  }
  /// Whether the post-loop `Warn('Bad APE trailer')` should fire.
  pub(crate) fn warn_bad_trailer(&self) -> bool {
    self.warn_bad_trailer
  }
}

// =============================================================================
// Typed Meta — `ApeMeta<'a>`
// =============================================================================

/// One emission of the MAC binary-data header (faithful APE.pm:146-162
/// dispatch over `%OldHeader` ≤3.97 vs `%NewHeader` ≥3.98). Variant fields
/// carry the resolved post-ValueConv values; emission order at sink time
/// follows the static [`OLD_HEADER`] / [`NEW_HEADER`] table arrays.
///
/// Family-1 group of every emitted tag is `MAC` (APE.pm:47/67); family-0
/// is `APE` (default-from-package, APE_GROUP0).
///
/// D8 — no public fields, accessors only.
#[derive(Debug, Clone)]
pub enum ApeHeader {
  /// `%APE::OldHeader` (APE.pm:45-62) — MAC version ≤ 3970.
  Old {
    /// APE.pm:50-53 `APEVersion = $val / 1000` (f64).
    ape_version: f64,
    /// APE.pm:54 `CompressionLevel` (raw int16u).
    compression_level: i64,
    /// APE.pm:56 `Channels` (raw int16u).
    channels: i64,
    /// APE.pm:57 `SampleRate` (raw int32u).
    sample_rate: i64,
    /// APE.pm:60 `TotalFrames` (raw int32u).
    total_frames: i64,
    /// APE.pm:61 `FinalFrameBlocks` (raw int32u).
    final_frame_blocks: i64,
    /// Number of fields read before short-read termination. `6` ⇒ full
    /// header; less ⇒ truncated body (ExifTool.pm:9953 `last if $more
    /// <= 0`). Used by [`ApeMeta::sink`] to know how many tags to emit.
    n_fields: u8,
  },
  /// `%APE::NewHeader` (APE.pm:65-78) — MAC version ≥ 3980.
  New {
    /// APE.pm:70 `CompressionLevel` (raw int16u).
    compression_level: i64,
    /// APE.pm:72 `BlocksPerFrame` (raw int32u).
    blocks_per_frame: i64,
    /// APE.pm:73 `FinalFrameBlocks` (raw int32u).
    final_frame_blocks: i64,
    /// APE.pm:74 `TotalFrames` (raw int32u).
    total_frames: i64,
    /// APE.pm:75 `BitsPerSample` (raw int16u).
    bits_per_sample: i64,
    /// APE.pm:76 `Channels` (raw int16u).
    channels: i64,
    /// APE.pm:77 `SampleRate` (raw int32u).
    sample_rate: i64,
    /// Number of fields read before short-read termination. `7` ⇒ full
    /// header; less ⇒ truncated body.
    n_fields: u8,
  },
}

/// One main-table emission — a wire-format `%APE::Main` (APE.pm:21-42)
/// tag OR a dynamic `MakeTag` (APE.pm:102-112) tag, with PrintConv/
/// ValueConv ALREADY APPLIED (the planning step calls
/// [`crate::convert::apply`] for static-def tags; dynamic tags emit
/// as-is). Family-1 group is `APE` (default from `%APE::Main` package);
/// family-0 is `APE` (APE_GROUP0).
///
/// `name` is an owned `String` because `MakeTag` produces a freshly-
/// allocated name (`ucfirst lc`, `s/.../.../`); static-def hits are
/// short-lived borrows we materialize to keep one Vec type.
///
/// D8 — no public fields, accessors only.
#[derive(Debug, Clone)]
pub struct ApeMainTag {
  name: String,
  value: TagValue,
}

impl ApeMainTag {
  /// Resolved tag name (post-MakeTag / static-table lookup).
  #[must_use]
  pub fn name(&self) -> &str {
    self.name.as_str()
  }

  /// Tag value (post-ValueConv / -PrintConv for static defs; raw
  /// `TagValue::Str` / `TagValue::Bytes` for dynamic MakeTag entries).
  #[must_use]
  pub fn value(&self) -> &TagValue {
    &self.value
  }
}

/// Typed APE metadata — the lib-first output of [`ProcessApe`].
///
/// Holds the MAC binary-data header tags (if any) plus the dynamic
/// `%APE::Main` tag-stream emissions (in extraction order, with
/// `MakeTag` name munging and ValueConv/PrintConv applied per the
/// `print_conv` mode the planner ran in). The `warn_bad_trailer` flag
/// mirrors APE.pm:238 `$i == $count or $et->Warn('Bad APE trailer');`.
///
/// **Composite Duration handling.** APE.pm:81-93 `%Composite::Duration`
/// can resolve ingredients from the APE tag stream itself OR from
/// cross-format injected tags (the `composite_lookup_resolves_via_
/// family0_apes_not_only_mac` test injects MAC tags from outside the
/// parser). The typed-Meta sink covers ONLY the intra-APE case (the
/// pre-computed `composite_duration` field below, populated by the
/// planner from the header + main pending tags). Cross-format composite
/// resolution remains in the legacy bridge (`emit_composite_duration_
/// if_present` reading from `Metadata::tags()`), faithful to ExifTool's
/// post-extraction `BuildCompositeTags` pass that's deferred to Phase G
/// in this engine.
///
/// **D8 — no public fields, accessors only.**
///
/// **Lifetimes.** `'a` is held for shape parity with formats that
/// borrow string slices from the input; APE's [`ApeMainTag::name`] is
/// owned (`MakeTag` allocates) and [`ApeMainTag::value`] is owned
/// (`TagValue` is by-value), so `'a` is effectively `'static`. The
/// parameter remains for future zero-copy work (Phase G).
#[derive(Debug, Clone)]
pub struct ApeMeta<'a> {
  header: Option<ApeHeader>,
  main_tags: Vec<ApeMainTag>,
  warn_bad_trailer: bool,
  /// Pre-computed intra-APE Composite:Duration emission (faithful
  /// `%APE::Composite::Duration` at APE.pm:83-92, applied only when
  /// the header + main-tag pending state contains all four Require
  /// ingredients). `None` ⇒ the bridge's `emit_composite_duration_if_
  /// present` may still emit one from cross-format injected tags;
  /// `Some(v)` ⇒ the intra-APE arithmetic produced a value (already
  /// PrintConv-converted at the planner's `print_conv` mode).
  composite_duration: Option<TagValue>,
  _phantom: core::marker::PhantomData<&'a ()>,
}

impl ApeMeta<'_> {
  /// MAC binary-data header tags (Old/New) if a MAC header was present.
  /// `None` when the input was APETAGEX-prefixed or trailer-only.
  #[must_use]
  pub fn header(&self) -> Option<&ApeHeader> {
    self.header.as_ref()
  }

  /// Dynamic `%APE::Main` tag-stream emissions, in extraction order.
  /// Always empty for a header-only input with no trailer; populated
  /// when an APETAGEX header/footer is parsed.
  #[must_use]
  pub fn main_tags(&self) -> &[ApeMainTag] {
    &self.main_tags
  }

  /// `true` iff the planner detected an invalid APETAGEX trailer
  /// (APE.pm:194 `$count = -1`) ⇒ APE.pm:238 `Warn('Bad APE trailer')`.
  #[must_use]
  pub fn warn_bad_trailer(&self) -> bool {
    self.warn_bad_trailer
  }

  /// Pre-computed intra-APE Composite:Duration value (post-PrintConv
  /// or post-ValueConv per the planner's `print_conv` mode). `None`
  /// when the intra-APE arithmetic did not produce a value (missing
  /// ingredients OR Perl-falsey `SampleRate`/`TotalFrames`).
  #[must_use]
  pub fn composite_duration(&self) -> Option<&TagValue> {
    self.composite_duration.as_ref()
  }

  // ---- Convenience lib-first accessors over `main_tags` ------------------

  /// `APE:Artist` (APE.pm:30) — the first-seen artist tag in the dynamic
  /// main-tag emissions. `None` if the wire format did not carry one.
  #[must_use]
  pub fn artist(&self) -> Option<&str> {
    self.find_str("Artist")
  }

  /// `APE:Album` (APE.pm:29).
  #[must_use]
  pub fn album(&self) -> Option<&str> {
    self.find_str("Album")
  }

  /// `APE:Title` (APE.pm:32).
  #[must_use]
  pub fn title(&self) -> Option<&str> {
    self.find_str("Title")
  }

  /// `APE:Genre` (APE.pm:31).
  #[must_use]
  pub fn genre(&self) -> Option<&str> {
    self.find_str("Genre")
  }

  /// `APE:Track` (APE.pm:33).
  #[must_use]
  pub fn track(&self) -> Option<&str> {
    self.find_str("Track")
  }

  /// `APE:Year` (APE.pm:34).
  #[must_use]
  pub fn year(&self) -> Option<&str> {
    self.find_str("Year")
  }

  fn find_str(&self, name: &str) -> Option<&str> {
    self.main_tags.iter().find_map(|t| {
      if t.name() == name {
        match t.value() {
          TagValue::Str(s) => Some(s.as_str()),
          _ => None,
        }
      } else {
        None
      }
    })
  }
}

// =============================================================================
// `ApeError` — Rust-level fatal modes (currently none)
// =============================================================================

/// Rust-level fatal modes for APE parsing. Currently empty — every bad
/// input produces `Ok(None)` (Perl `return 0`). Reserved for future I/O
/// wrappers if streaming readers are added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApeError {}

impl core::fmt::Display for ApeError {
  fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match *self {}
  }
}

impl std::error::Error for ApeError {}

impl FormatParser for ProcessApe {
  /// GAT: `ApeMeta<'a>`. APE's typed Meta already owns its resolved
  /// tag-name strings and `TagValue` payloads, so `'a` is phantom; the
  /// `'static`-producing planner widens to the caller's `'a` by covariance
  /// (Codex AF2).
  type Meta<'a> = ApeMeta<'a>;
  /// Chained format (spec §6.4): `&'a [u8]` + `&'a mut SharedFlags` for
  /// the `done_id3`/`done_ape` cross-recursion plumbing.
  type Context<'a> = ApeContext<'a>;
  type Error = ApeError;

  /// Run the APE planner and produce a typed [`ApeMeta`]. Returns:
  ///   * `Ok(Some(meta))` — APE header / trailer was detected and a
  ///     typed extraction is available;
  ///   * `Ok(None)` — neither a leading magic nor a trailing APETAGEX
  ///     footer was found (faithful APE.pm:137-138 / :172 `return 0/1`).
  ///   * `Err` — never today; reserved for future I/O wrappers.
  ///
  /// **Side effect — `done_ape`.** Faithful APE.pm:131
  /// `$$et{DoneAPE} = 1` runs unconditionally on entry, BEFORE any
  /// magic check. This sets `shared.set_done_ape(true)` to gate the
  /// MP3 → APE-trailer fallback at ID3.pm:1723-1726.
  fn parse<'a>(&self, ctx: Self::Context<'a>) -> Result<Option<Self::Meta<'a>>, Self::Error> {
    Ok(parse_borrowed(ctx))
  }
}

/// Lib-first direct entry: parse APE bytes (chained-context shape) into
/// a borrow-from-input [`ApeMeta`]. Returns `None` for short / non-magic
/// non-trailer inputs (faithful APE.pm:137-138 + :172 silent returns).
///
/// Sets `ctx.shared.done_ape = true` unconditionally before the magic
/// check (APE.pm:131 `$$et{DoneAPE} = 1`).
fn parse_borrowed(mut ctx: ApeContext<'_>) -> Option<ApeMeta<'static>> {
  // APE.pm:131 `$$et{DoneAPE} = 1` — runs IMMEDIATELY after the embedded
  // ID3 dispatch and BEFORE the magic check, so even a wrong-magic file
  // (we'd reject below) faithfully marks DoneAPE. Read by ID3.pm:1723
  // to gate the MP3 → APE trailer fallback.
  ctx.shared_mut().set_done_ape(true);
  // Thread `done_id3` for the APE.pm:169 trailer-shift. The legacy bridge
  // populates `done_id3_legacy` from `Metadata::done_id3()` (the existing
  // Phase-2 storage); pure lib-callers use `shared.done_id3()`. Prefer the
  // legacy mirror when present (the bridge knows the file-actual size); fall
  // back to `shared`.
  // `done_id3` here is the `usize` shift amount for APE.pm:169
  // (`$footPos -= $$et{DoneID3} if $$et{DoneID3} > 1`). `SharedFlags::done_id3()`
  // is now `Option<usize>` (None ⇒ not run); a not-run / ran-no-trailer state
  // maps to a 0 shift, which the `> 1` guard in the planner already enforces.
  let done_id3 = ctx
    .done_id3_legacy
    .or_else(|| ctx.shared.done_id3())
    .unwrap_or(0);
  // The planner runs with `print_conv_enabled = false` so the static-def
  // `convert::apply` step yields the post-ValueConv RAW scalars (for
  // `MAIN_DURATION`: the f64 from `ape_duration_value_conv`'s signed-i32
  // wrap + ×1e-7). The PrintConv (`ConvertDuration` →
  // `"0:05:00.300"`-style string) is applied at SINK TIME based on the
  // `print_conv` flag — faithful to ExifTool's
  // `$$self{OPTIONS}{PrintConv}` global toggle (ExifTool.pm:5710). Same
  // pattern as AAC/DV (Phase F1 leaves).
  let print_conv_planner_mode = false;
  let plan = if ctx.trailer_only {
    Some(plan_apetagex_trailer_only(
      ctx.data,
      print_conv_planner_mode,
      done_id3,
    ))
  } else {
    plan_ape(ctx.data, print_conv_planner_mode, done_id3)
  }?;
  Some(meta_from_plan(plan))
}

/// Chained-parser trailer-only typed entry with **decoupled lifetimes** —
/// `data` and `shared` borrow independently, and the returned
/// [`ApeMeta`] is owned (`'static`). Used by the typed MP3 / MPC / WavPack
/// wrappers (ID3.pm:1722-1727 `APE::ProcessAPE` trailer fallback) where
/// `shared` is a transient borrow that must not extend into the returned
/// Meta's lifetime (Codex BF1/CF1 + AF2).
///
/// Faithful to the private `parse_borrowed` trailer-only path: sets
/// `done_ape` (APE.pm:131) and threads `shared.done_id3()` for the
/// APE.pm:169 footer shift.
pub(crate) fn parse_trailer_only_owned(
  data: &[u8],
  shared: &mut SharedFlags,
) -> Option<ApeMeta<'static>> {
  // APE.pm:131 `$$et{DoneAPE} = 1` (unconditional, before any magic check).
  shared.set_done_ape(true);
  let done_id3 = shared.done_id3().unwrap_or(0);
  let plan = plan_apetagex_trailer_only(data, /* print_conv */ false, done_id3);
  Some(meta_from_plan(plan))
}

/// Full APE parse (header + trailer) with **decoupled lifetimes** — `data`
/// and `shared` borrow independently and the returned [`ApeMeta`] is owned
/// (`'static`). Used by the closed [`crate::parser_new::AnyParser`]
/// dispatch (Codex AF2) so the transient `shared` does not pin the
/// returned `AnyMeta<'a>` lifetime. Faithful to the private `parse_borrowed`
/// full path (APE.pm:121-172): sets `done_ape` and threads
/// `shared.done_id3()` for the APE.pm:169 footer shift.
pub(crate) fn parse_full_owned(data: &[u8], shared: &mut SharedFlags) -> Option<ApeMeta<'static>> {
  shared.set_done_ape(true);
  let done_id3 = shared.done_id3().unwrap_or(0);
  let plan = plan_ape(data, /* print_conv */ false, done_id3)?;
  Some(meta_from_plan(plan))
}

/// Lift a Phase-1 [`ApePlan`] into a typed [`ApeMeta`]. Translates the
/// `header_job` into [`ApeHeader::Old`] / [`ApeHeader::New`] (running
/// the same binary-data extraction the legacy path would have via
/// `process_ape_binary_data`), copies the pending main-tag pushes
/// verbatim into [`ApeMainTag`] entries, and runs the intra-APE
/// Composite:Duration arithmetic on the resolved fields.
fn meta_from_plan(plan: ApePlan) -> ApeMeta<'static> {
  // 1) Header extraction.
  let header = match &plan.header_job {
    HeaderJob::None => None,
    HeaderJob::Old(body) => Some(extract_old_header(body)),
    HeaderJob::New(body) => Some(extract_new_header(body)),
  };
  // 2) Main-table emissions. The plan's pending tuples already carry the
  // converted (`convert::apply`-applied) values for static-def hits and
  // raw `TagValue::Str/Bytes` for dynamic MakeTag entries.
  let main_tags: Vec<ApeMainTag> = plan
    .pending
    .into_iter()
    .map(|(_g1, name, value)| ApeMainTag { name, value })
    .collect();
  // 3) Intra-APE Composite:Duration. Resolve the 4 Require ingredients
  // against the header + main tags ALONE (not cross-format). Mirrors the
  // shared `emit_composite_duration_if_present` helper but reads from the
  // typed Meta. Cross-format ingredient injection remains in the legacy
  // bridge.
  let composite_duration = composite_duration_from_header_and_main(&header, &main_tags);
  ApeMeta {
    header,
    main_tags,
    warn_bad_trailer: plan.warn_bad_trailer,
    composite_duration,
    _phantom: core::marker::PhantomData,
  }
}

/// Run the [`OLD_HEADER`] binary-data extraction over a MAC OldHeader
/// payload. Faithful to `process_ape_binary_data` but lifts into typed
/// fields instead of pushing into `Metadata`.
fn extract_old_header(body: &[u8]) -> ApeHeader {
  // Defaults match the typed shape; n_fields tracks how many actually fit.
  let mut ape_version = 0.0_f64;
  let mut compression_level = 0_i64;
  let mut channels = 0_i64;
  let mut sample_rate = 0_i64;
  let mut total_frames = 0_i64;
  let mut final_frame_blocks = 0_i64;
  let mut n_fields = 0_u8;
  for field in OLD_HEADER {
    let offset = (field.index as usize) * APE_HEADER_INCREMENT;
    let format = field.format_override.unwrap_or(ApeBinaryFormat::Int16u);
    let Some(raw) = read_le_uint(body, offset, format.width()) else {
      // APE.pm `last if $more <= 0` — subsequent fields cannot fit either.
      break;
    };
    match field.name {
      "APEVersion" => ape_version = (raw as i64 as f64) / 1000.0,
      "CompressionLevel" => compression_level = raw as i64,
      "Channels" => channels = raw as i64,
      "SampleRate" => sample_rate = raw as i64,
      "TotalFrames" => total_frames = raw as i64,
      "FinalFrameBlocks" => final_frame_blocks = raw as i64,
      _ => unreachable!("OLD_HEADER field {} has no typed slot", field.name),
    }
    n_fields += 1;
  }
  ApeHeader::Old {
    ape_version,
    compression_level,
    channels,
    sample_rate,
    total_frames,
    final_frame_blocks,
    n_fields,
  }
}

/// Run the [`NEW_HEADER`] binary-data extraction over a MAC NewHeader
/// payload.
fn extract_new_header(body: &[u8]) -> ApeHeader {
  let mut compression_level = 0_i64;
  let mut blocks_per_frame = 0_i64;
  let mut final_frame_blocks = 0_i64;
  let mut total_frames = 0_i64;
  let mut bits_per_sample = 0_i64;
  let mut channels = 0_i64;
  let mut sample_rate = 0_i64;
  let mut n_fields = 0_u8;
  for field in NEW_HEADER {
    let offset = (field.index as usize) * APE_HEADER_INCREMENT;
    let format = field.format_override.unwrap_or(ApeBinaryFormat::Int16u);
    let Some(raw) = read_le_uint(body, offset, format.width()) else {
      break;
    };
    match field.name {
      "CompressionLevel" => compression_level = raw as i64,
      "BlocksPerFrame" => blocks_per_frame = raw as i64,
      "FinalFrameBlocks" => final_frame_blocks = raw as i64,
      "TotalFrames" => total_frames = raw as i64,
      "BitsPerSample" => bits_per_sample = raw as i64,
      "Channels" => channels = raw as i64,
      "SampleRate" => sample_rate = raw as i64,
      _ => unreachable!("NEW_HEADER field {} has no typed slot", field.name),
    }
    n_fields += 1;
  }
  ApeHeader::New {
    compression_level,
    blocks_per_frame,
    final_frame_blocks,
    total_frames,
    bits_per_sample,
    channels,
    sample_rate,
    n_fields,
  }
}

/// Intra-APE Composite:Duration resolution (faithful to
/// `%APE::Composite::Duration` at APE.pm:83-92). Reads the four Require
/// ingredients from the typed Meta's header + main tags (the lookup
/// rule: family-0 = `APE`, ALL families considered, last-wins per Codex
/// r5/r9 findings — but we only have intra-APE state here, so the
/// `MAC:` vs `APE:` family-1 distinction is irrelevant). Cross-format
/// injection remains in the legacy bridge's
/// [`emit_composite_duration_if_present`].
///
/// Returns the post-PrintConv `TagValue` (the planner always runs
/// `print_conv_enabled = true` for the static-def `convert::apply`
/// step; the sink translates back to raw f64 for `-n` mode if needed).
fn composite_duration_from_header_and_main(
  header: &Option<ApeHeader>,
  main_tags: &[ApeMainTag],
) -> Option<TagValue> {
  // Pull the four ingredients from header (preferred — the on-disk MAC
  // header is the canonical source) AND from main_tags (the wire format
  // can carry spaced keys like `Sample Rate` that MakeTag mangles to
  // `SampleRate` matching the Require). Last-wins (Codex r9 finding).
  let mut sample_rate: Option<(TagValue, f64)> = None;
  let mut total_frames: Option<(TagValue, f64)> = None;
  let mut blocks_per_frame: Option<(TagValue, f64)> = None;
  let mut final_frame_blocks: Option<(TagValue, f64)> = None;
  // First, lift from the header (chronologically earlier in extraction order).
  if let Some(h) = header {
    let (sr, tf, bpf, ffb) = match h {
      ApeHeader::Old {
        sample_rate: sr,
        total_frames: tf,
        n_fields,
        ..
      } => {
        // OldHeader has SampleRate (index 4) and TotalFrames (index 10).
        // BlocksPerFrame is not in OldHeader; final_frame_blocks (index
        // 12) IS, when n_fields ≥ 6. Composite needs all 4 ⇒ OldHeader
        // alone cannot satisfy unless the main-tag stream contributes
        // BlocksPerFrame.
        let sr = if *n_fields >= 4 { Some(*sr) } else { None };
        let tf = if *n_fields >= 5 { Some(*tf) } else { None };
        (sr, tf, None, None)
      }
      ApeHeader::New {
        sample_rate: sr,
        total_frames: tf,
        blocks_per_frame: bpf,
        final_frame_blocks: ffb,
        n_fields,
        ..
      } => {
        // NewHeader carries all 4. n_fields ordering: CompressionLevel(0),
        // BlocksPerFrame(1), FinalFrameBlocks(2), TotalFrames(3),
        // BitsPerSample(4), Channels(5), SampleRate(6).
        let bpf = if *n_fields >= 2 { Some(*bpf) } else { None };
        let ffb = if *n_fields >= 3 { Some(*ffb) } else { None };
        let tf = if *n_fields >= 4 { Some(*tf) } else { None };
        let sr = if *n_fields >= 7 { Some(*sr) } else { None };
        (sr, tf, bpf, ffb)
      }
    };
    if let Some(v) = sr {
      sample_rate = Some((TagValue::I64(v), v as f64));
    }
    if let Some(v) = tf {
      total_frames = Some((TagValue::I64(v), v as f64));
    }
    if let Some(v) = bpf {
      blocks_per_frame = Some((TagValue::I64(v), v as f64));
    }
    if let Some(v) = ffb {
      final_frame_blocks = Some((TagValue::I64(v), v as f64));
    }
  }
  // Then lift from the main-tag stream (later in extraction order
  // ⇒ overrides header values per Codex r9 last-wins). Reverse iteration
  // so we take the LAST occurrence per name.
  for t in main_tags.iter().rev() {
    let target = match t.name() {
      "SampleRate" => &mut sample_rate,
      "TotalFrames" => &mut total_frames,
      "BlocksPerFrame" => &mut blocks_per_frame,
      "FinalFrameBlocks" => &mut final_frame_blocks,
      _ => continue,
    };
    if target.is_some() {
      continue; // already filled by a later occurrence (we iterate reversed)
    }
    let raw = t.value().clone();
    let num = match &raw {
      TagValue::I64(n) => Some(*n as f64),
      TagValue::F64(x) => Some(*x),
      TagValue::Str(s) => Some(perl_numeric_coerce_f64(s)),
      _ => None,
    };
    if let Some(n) = num {
      *target = Some((raw, n));
    }
  }
  // Run the arithmetic only when ALL four ingredients resolve AND the
  // first two are Perl-truthy (APE.pm:90 guard).
  let (Some((sr_raw, sr)), Some((tf_raw, tf)), Some((_, bpf)), Some((_, ffb))) = (
    sample_rate,
    total_frames,
    blocks_per_frame,
    final_frame_blocks,
  ) else {
    return None;
  };
  if !perl_boolean_truthy(&sr_raw) || !perl_boolean_truthy(&tf_raw) {
    return None;
  }
  // APE.pm:90 arithmetic.
  let dur = ((tf - 1.0) * bpf + ffb) / sr;
  if !dur.is_finite() {
    let s = if dur.is_nan() {
      "NaN"
    } else if dur.is_sign_negative() {
      "-Inf"
    } else {
      "Inf"
    };
    return Some(TagValue::Str(s.into()));
  }
  // The sink decides PrintConv at emit time; we return the RAW f64. The
  // sink applies `convert_duration` when `print_conv = true`.
  Some(TagValue::F64(dur))
}

// =============================================================================
// `MetaSinker` — typed Meta → TagWriter
// =============================================================================

impl MetaSinker for ApeMeta<'_> {
  /// Emit APE tags into the writer in faithful APE.pm extraction order:
  /// (1) MAC binary-data header tags, (2) dynamic main-tag stream, (3)
  /// `Warning('Bad APE trailer')` if the planner detected an invalid
  /// trailer, (4) intra-APE `Composite:Duration` if the ingredients
  /// resolve.
  ///
  /// `print_conv = true` ⇒ PrintConv formatted strings (`-j` mode);
  /// `print_conv = false` ⇒ post-ValueConv raw scalars (`-n` mode).
  ///
  /// **Note on `print_conv` for main-tag stream.** The planner runs in
  /// `print_conv_enabled = true` (always) so the static-def tags
  /// (`DURATION` → `MAIN_DURATION`) get their PrintConv string applied
  /// up front. When the sink is called with `print_conv = false`, we
  /// re-derive the raw f64 form by reading the static def's ValueConv
  /// output. This dual-pass approach mirrors AAC/DV's pattern: PrintConv
  /// is a global engine toggle (ExifTool.pm:5710 `OPTIONS{PrintConv}`),
  /// not a writer choice.
  fn sink<W: TagWriter>(&self, print_conv: bool, out: &mut W) -> Result<(), W::Error> {
    // (1) MAC binary-data header.
    if let Some(header) = &self.header {
      sink_header(header, print_conv, out)?;
    }
    // (2) Main-tag stream.
    for t in &self.main_tags {
      sink_main_tag(t, print_conv, out)?;
    }
    // (3) Bad APE trailer warning (APE.pm:238).
    if self.warn_bad_trailer {
      out.write_warning("Bad APE trailer")?;
    }
    // (4) Intra-APE Composite:Duration emission. Cross-format composite
    // resolution remains in the legacy bridge — this sink covers the
    // header+main self-contained case.
    if let Some(comp) = &self.composite_duration {
      sink_composite_duration(comp, print_conv, out)?;
    }
    Ok(())
  }
}

fn sink_header<W: TagWriter>(
  header: &ApeHeader,
  print_conv: bool,
  out: &mut W,
) -> Result<(), W::Error> {
  // Faithful emission order = the static OLD_HEADER / NEW_HEADER arrays.
  // Family-1 group is `MAC` (APE.pm:47/67).
  const GROUP: &str = "MAC";
  match header {
    ApeHeader::Old {
      ape_version,
      compression_level,
      channels,
      sample_rate,
      total_frames,
      final_frame_blocks,
      n_fields,
    } => {
      let n = *n_fields as usize;
      let emits: &[(&str, EmitVal)] = &[
        ("APEVersion", EmitVal::F64(*ape_version)),
        ("CompressionLevel", EmitVal::I64(*compression_level)),
        ("Channels", EmitVal::I64(*channels)),
        ("SampleRate", EmitVal::I64(*sample_rate)),
        ("TotalFrames", EmitVal::I64(*total_frames)),
        ("FinalFrameBlocks", EmitVal::I64(*final_frame_blocks)),
      ];
      for (name, val) in emits.iter().take(n) {
        emit_with_print_conv(out, GROUP, name, val, print_conv)?;
      }
    }
    ApeHeader::New {
      compression_level,
      blocks_per_frame,
      final_frame_blocks,
      total_frames,
      bits_per_sample,
      channels,
      sample_rate,
      n_fields,
    } => {
      let n = *n_fields as usize;
      let emits: &[(&str, EmitVal)] = &[
        ("CompressionLevel", EmitVal::I64(*compression_level)),
        ("BlocksPerFrame", EmitVal::I64(*blocks_per_frame)),
        ("FinalFrameBlocks", EmitVal::I64(*final_frame_blocks)),
        ("TotalFrames", EmitVal::I64(*total_frames)),
        ("BitsPerSample", EmitVal::I64(*bits_per_sample)),
        ("Channels", EmitVal::I64(*channels)),
        ("SampleRate", EmitVal::I64(*sample_rate)),
      ];
      for (name, val) in emits.iter().take(n) {
        emit_with_print_conv(out, GROUP, name, val, print_conv)?;
      }
    }
  }
  Ok(())
}

/// Typed scalar emitted by `sink_header` — keyed by the header field's
/// VALUECONV output type. APE OldHeader `APEVersion` is the only F64
/// (after ValueConv `$val / 1000`); every other header field is raw I64.
enum EmitVal {
  I64(i64),
  F64(f64),
}

fn emit_with_print_conv<W: TagWriter>(
  out: &mut W,
  group: &str,
  name: &str,
  val: &EmitVal,
  _print_conv: bool,
) -> Result<(), W::Error> {
  // Header fields have `PrintConv::None` (APE.pm:50-78 — none of the
  // static defs set a PrintConv), so the `-j` and `-n` emission is
  // identical: emit the post-ValueConv scalar verbatim.
  match val {
    EmitVal::I64(n) => out.write_i64(group, name, *n),
    EmitVal::F64(x) => out.write_f64(group, name, *x),
  }
}

fn sink_main_tag<W: TagWriter>(
  t: &ApeMainTag,
  print_conv: bool,
  out: &mut W,
) -> Result<(), W::Error> {
  // The planner runs in `print_conv_enabled = false` ⇒ the value is the
  // POST-VALUECONV RAW scalar. For `print_conv = true` the sink applies
  // the static def's PrintConv on emit; for `print_conv = false` we emit
  // the raw scalar verbatim. Only `MAIN_DURATION` (APE.pm:35-39) has a
  // non-trivial PrintConv (`ConvertDuration`); the other main-table
  // static defs are `PrintConv::None` ⇒ `-j` and `-n` emit identically.
  // Dynamic `MakeTag` entries (no static def) emit as-is in both modes
  // (faithful: bundled Perl `tagInfo` has only `Name`, no PrintConv).
  if print_conv && t.name() == "Duration" {
    let printed = convert_duration(t.value());
    return emit_tag_value(out, "APE", t.name(), &printed);
  }
  emit_tag_value(out, "APE", t.name(), t.value())
}

fn emit_tag_value<W: TagWriter>(
  out: &mut W,
  group: &str,
  name: &str,
  v: &TagValue,
) -> Result<(), W::Error> {
  match v {
    TagValue::Str(s) => out.write_str(group, name, s.as_str()),
    TagValue::I64(n) => out.write_i64(group, name, *n),
    TagValue::F64(x) => out.write_f64(group, name, *x),
    TagValue::Bytes(b) => out.write_bytes(group, name, b.as_slice()),
    TagValue::Bool(b) => out.write_str(group, name, if *b { "true" } else { "false" }),
    TagValue::Rational(r) => {
      // Faithful Perl: rational tags stringify as `num/den` in default
      // context. APE Main has no Rational tags (verified against
      // APE.pm:21-42), so this is reserved for forward compatibility.
      out.write_fmt(group, name, |w| {
        write!(w, "{}/{}", r.numerator(), r.denominator())
      })
    }
    TagValue::List(_) => {
      // No APE Main tag emits List today. Reserved for forward compat.
      out.write_str(group, name, "<list>")
    }
  }
}

fn sink_composite_duration<W: TagWriter>(
  comp: &TagValue,
  print_conv: bool,
  out: &mut W,
) -> Result<(), W::Error> {
  const GROUP: &str = "Composite";
  // `composite_duration` is stored as RAW f64 (or Str for non-finite —
  // see `composite_duration_from_header_and_main`). The sink applies
  // ConvertDuration here when print_conv = true.
  match comp {
    TagValue::F64(dur) => {
      if print_conv {
        let converted = convert_duration(&TagValue::F64(*dur));
        match converted {
          TagValue::Str(s) => out.write_str(GROUP, "Duration", s.as_str()),
          TagValue::F64(x) => out.write_f64(GROUP, "Duration", x),
          other => emit_tag_value(out, GROUP, "Duration", &other),
        }
      } else {
        out.write_f64(GROUP, "Duration", *dur)
      }
    }
    // Non-finite stored as Str ("Inf"/"-Inf"/"NaN") — emit verbatim
    // (faithful: bundled Perl emits the quoted string in both -j and -n).
    other => emit_tag_value(out, GROUP, "Duration", other),
  }
}

// =============================================================================
// Legacy `OldFormatParser` bridge — preserves CLI byte-exact JSON
// =============================================================================

impl ProcessApe {
  /// Engine entry used by the closed [`crate::parser_new::AnyParser`]
  /// dispatch (`crate::parser::extract_info`). Runs the ID3 chained
  /// dispatch, then drives the typed [`FormatParser::parse`] +
  /// [`MetaSinker::sink`] path through a [`MetadataTagWriter`] so the
  /// serialized JSON stays byte-exact with bundled `perl exiftool`.
  ///
  /// Faithful order (APE.pm:119-241):
  ///   1. Embedded ID3 dispatch (APE.pm:124-127) via the existing
  ///      `process_id3_chained` helper — F2 ID3 migration owns this seam.
  ///   2. `set_done_ape` (APE.pm:131) — runs unconditionally on entry.
  ///   3. Magic check + SetFileType (APE.pm:137-141) iff the typed
  ///      planner produces a result.
  ///   4. Tag emission via `MetaSinker::sink` ⇒ `MetadataTagWriter`.
  ///   5. Cross-format Composite Duration resolution via the existing
  ///      `emit_composite_duration_if_present` (reads from
  ///      `Metadata::tags()` — covers cross-format injected ingredients
  ///      that the typed intra-APE meta cannot see). Phase G unifies
  ///      this when Composite is engine-tier.
  pub(crate) fn process(&self, ctx: &mut ParseContext<'_>) -> bool {
    // require Image::ExifTool::ID3; Image::ExifTool::ID3::ProcessID3(
    // $et, $dirInfo) and return 1; }`. The bundled audio-dispatch loop
    // INSIDE ProcessID3 (ID3.pm:1582-1601) recursively re-invokes
    // ProcessAPE for the MAC/APETAGEX body extraction when an ID3 prefix
    // is present, so a faithful flattened model runs BOTH the ID3 tag
    // extraction AND the APE MAC/APE-trailer extraction within a single
    // ProcessApe::process. The audio loop's recursive ProcessAPE skips
    // the embedded-ID3 check (DoneID3 set) but DOES call SetFileType
    // (APE.pm:141, "APE"), which then wins over the later
    // SetFileType('MP3') at ID3.pm:1604 via the FoundTag('FileType')
    // first-call-wins gate. Bundled `$hdrEnd` (ID3.pm:1505) marks the
    // file offset PAST the ID3v2 header; the audio loop's `Seek(
    // $hdrEnd, 0)` (ID3.pm:1590) is how the recursive ProcessAPE sees
    // `MAC `/`APETAGEX` at offset 0 of its slice. Verified vs bundled
    // `perl exiftool` on `tests/fixtures/ape_id3_prefixed.ape`
    // (FileType=APE, with both ID3v2_3:* and MAC:* + APE:* tags).
    let id3 = if ctx.metadata().done_id3().is_none() {
      crate::formats::id3::process::process_id3_chained(ctx)
    } else {
      crate::formats::id3::process::Id3ChainedResult::default()
    };
    let id3_found = id3.found();
    let hdr_end = id3.hdr_end_offset();

    // APE.pm:131 `$$et{DoneAPE} = 1` — runs immediately after the ID3
    // arm AND BEFORE the magic check, so even a wrong-magic file (one
    // we'd reject below) faithfully marks DoneAPE. Read by ID3.pm:1723
    // to gate the MP3→APE trailer fallback.
    ctx.metadata().set_done_ape();

    let print_conv_enabled = ctx.print_conv_enabled();

    // ----- Phase 1: planning (read-only over ctx.data()) -------------------
    // Slice past the ID3v2 header (bundled `$raf->Seek($hdrEnd, 0)` at
    // ID3.pm:1590). The recursive ProcessAPE inside the audio loop sees
    // `MAC `/`APETAGEX` at offset 0 of this slice. When `hdr_end == 0`
    // (no ID3 prefix), the slice IS `ctx.data()` unchanged.
    //
    // Codex R4 F1 fix: `hdr_end` may legitimately exceed `ctx.data().len()`
    // for a TRUNCATED v2.4-footer file. Bundled's `$raf->Seek(10, 1)` at
    // ID3.pm:1486 is unconditional — filesystems allow seeking past EOF, so
    // `$raf->Tell()` at :1504 yields `10 + size + 10` regardless of whether
    // the 10 footer bytes physically exist. Subsequent `$raf->Read` calls
    // in the audio loop just return short/empty (no crash). We model the
    // same byte-exact behavior with `get(hdr_end..).unwrap_or(&[])`: when
    // `hdr_end > data.len()`, the saturating-empty slice routes through
    // `plan_ape` → wrong-magic → ID3-only outcome (no panic).
    let ape_slice = ctx.data().get(hdr_end..).unwrap_or(&[]);
    // APE.pm:169 `$footPos -= $$et{DoneID3} if $$et{DoneID3} > 1` —
    // when ProcessID3 (above) found an ID3v1 trailer at EOF, walk PAST
    // it when scanning for the APETAGEX 32-byte trailer header. Codex R3
    // F2 fix: previously the footer scan used `data.len() - 32`
    // unconditionally, so files with both APEv2 + ID3v1 trailers at EOF
    // had the trailer header read from the wrong offset (32 bytes back
    // from EOF lands INSIDE the ID3v1 TAG block, not on `APETAGEX`).
    let done_id3 = ctx.metadata().done_id3().unwrap_or(0);
    // The planner runs in `print_conv_enabled = false` so the post-
    // ValueConv RAW scalars are carried through the typed Meta. The
    // sink applies PrintConv at emission time per `print_conv_enabled`
    // (the legacy bridge's `ctx.print_conv_enabled()` decides which
    // mode the sink runs in). This matches the AAC/DV pattern.
    let plan = match plan_ape(ape_slice, false, done_id3) {
      Some(p) => p,
      // APE.pm:137-138 — short or wrong-magic. Two faithful outcomes:
      //   (a) ID3 was found above ⇒ APE.pm:125-126 `ProcessID3 ... and
      //       return 1` semantics: return TRUE so the engine treats the
      //       file as ID3-only (audio-loop fallback at ID3.pm:1604 would
      //       set FileType='MP3' — we don't model the loop, but
      //       ID3-only is the bundled outcome).
      //   (b) ID3 was NOT found ⇒ return FALSE so the candidate loop
      //       tries the next type (faithful APE.pm:138 `return 0`).
      None => return id3_found,
    };

    // APE.pm:139 `$et->SetFileType();` — no-arg ⇒ detected ("APE").
    // Called after the file is validated, BEFORE pushing any tags
    // (faithful: SetFileType pushes File:* via FoundTag, ordered first).
    // Faithful to the bundled audio-loop recursion: the recursive
    // ProcessAPE invoked from ID3.pm:1582-1601 calls this same
    // SetFileType (APE.pm:141), engaging first-call-wins so the later
    // ID3.pm:1604 `SetFileType('MP3')` is a no-op.
    ctx.set_file_type(None, None, None);

    // ----- Phase 2: typed Meta → MetadataTagWriter sink --------------------
    // The plan-derived typed Meta carries the MAC header tags, the
    // dynamic main tags (with PrintConv-mode applied), the warn flag,
    // and the intra-APE Composite:Duration. The sink writes all of them
    // via `MetadataTagWriter` so the legacy `Metadata` accumulator stays
    // byte-exact during the migration.
    //
    // BUT: cross-format Composite:Duration resolution (the test
    // `composite_lookup_resolves_via_family0_apes_not_only_mac` injects
    // MAC tags from outside the parser) requires reading `Metadata::
    // tags()` AFTER the APE pushes — so we suppress the intra-APE
    // composite emission inside the typed sink here, and instead defer
    // to `emit_composite_duration_if_present` below which reads from
    // `Metadata::tags()` and covers both intra-APE and cross-format
    // ingredient sources.
    let mut meta = meta_from_plan(plan);
    meta.composite_duration = None; // suppress intra-APE sink; bridge runs below.
    {
      let mut bridge = MetadataTagWriter::with_family0(ctx.metadata(), APE_GROUP0);
      let _: Result<(), core::convert::Infallible> = meta.sink(print_conv_enabled, &mut bridge);
    }

    emit_composite_duration_if_present(ctx, print_conv_enabled);

    // Side effect — mirror DoneAPE into shared flags for any future
    // typed callers reading the cross-format state. (The legacy
    // `Metadata::set_done_ape()` is the path the engine actually reads
    // today; the SharedFlags mirror is groundwork for Phase G.)
    let _ = id3_found;
    true // APE.pm:240 `return 1;`.
  }
}

/// Faithful Composite::Duration emission (APE.pm:81-93). Looks up the four
/// Require ingredients on the metadata sink and pushes
/// `Composite:Duration` if both `SampleRate` and `TotalFrames` are
/// Perl-truthy. Shared by the regular [`ProcessApe::process`] entry
/// point AND the chained-parser [`ProcessApe::process_trailer_only`]
/// entry (Codex r16 finding) — both paths see the same composite
/// resolution rule.
///
/// Require resolution detail:
///   * ExifTool's `GroupMatches('APE', ...)` (ExifTool.pm:5207-5246)
///     checks ALL families of each candidate tag — family-0 = `APE`
///     (default-from-package on every APE-module tag) matches the
///     `APE:` prefix. Both header tags (group1=MAC, group0=APE) and
///     dynamic Main tags (group1=APE, group0=APE) qualify by name.
///   * Tolerates F64 and Str values (Codex r8): RawConv arithmetic
///     runs Perl numeric coercion on each ingredient. Coerce Str via
///     `perl_numeric_coerce_f64`.
///   * Duplicate-name override (Codex r9): when both MAC header and
///     wire tag carry the same canonical name, ExifTool's HandleTag/
///     DUPL_TAG renames the earlier value's key to `Name (1)` and
///     gives the bare key to the LATEST FoundTag call. Faithful match:
///     use `iter().rev()` (last-wins).
///   * Perl BOOLEAN truthiness (Codex r10): `($val[0] && $val[1])` runs
///     on the RAW VALUE scalar (not the coerced f64). Strings: TRUE iff
///     non-empty AND not exact `"0"` (`"0E0"`, `"0.0"`, etc. are TRUE).
///     Numeric: TRUE iff `!= 0`. NaN: TRUE (Perl NaN is truthy). We use
///     `perl_boolean_truthy` for this.
///   * Non-finite arithmetic (Codex r9): when any ingredient is
///     `Inf`/`-Inf`/`NaN`, `dur` is non-finite. Perl stringifies with
///     capital-I `Inf`/`-Inf`/`NaN` and EscapeJSON quotes the result;
///     Rust `f64::to_string()` would emit lowercase `inf`,
///     byte-diverging. We promote to Perl-cased `TagValue::Str` here.
fn emit_composite_duration_if_present(ctx: &mut ParseContext<'_>, print_conv_enabled: bool) {
  let (sample_rate, total_frames, blocks_per_frame, final_frame_blocks) = {
    let tags = ctx.metadata().tags();
    let lookup = |name: &str| -> Option<(TagValue, f64)> {
      tags
        .iter()
        .rev()
        .find(|t| t.group().family0() == APE_GROUP0 && t.name() == name)
        .and_then(|t| {
          let raw = t.value().clone();
          let num = match &raw {
            TagValue::I64(n) => Some(*n as f64),
            TagValue::F64(x) => Some(*x),
            TagValue::Str(s) => Some(perl_numeric_coerce_f64(s)),
            // Bytes / Bool / Rational / List: ExifTool's RawConv would
            // either error or coerce via Perl context that's irrelevant
            // for APE — none of the 4 ingredient kinds can realistically
            // be one of these. Skip cleanly (no Composite ⇒ undef tag).
            _ => None,
          }?;
          Some((raw, num))
        })
    };
    (
      lookup("SampleRate"),
      lookup("TotalFrames"),
      lookup("BlocksPerFrame"),
      lookup("FinalFrameBlocks"),
    )
  };
  if let (Some((sr_raw, sr)), Some((tf_raw, tf)), Some((_, bpf)), Some((_, ffb))) = (
    sample_rate,
    total_frames,
    blocks_per_frame,
    final_frame_blocks,
  ) {
    // APE.pm:90 `($val[0] && $val[1]) ? (($val[1]-1)*$val[2]+$val[3])/$val[0] : undef`.
    let sr_truthy = perl_boolean_truthy(&sr_raw);
    let tf_truthy = perl_boolean_truthy(&tf_raw);
    if sr_truthy && tf_truthy {
      // All computation in f64 from the start (no usize subtraction;
      // forward-item Phase-2 signed-arithmetic discipline).
      let dur = ((tf - 1.0) * bpf + ffb) / sr;
      let composite_val = if !dur.is_finite() {
        let s = if dur.is_nan() {
          "NaN"
        } else if dur.is_sign_negative() {
          "-Inf"
        } else {
          "Inf"
        };
        TagValue::Str(s.into())
      } else if print_conv_enabled {
        convert_duration(&TagValue::F64(dur))
      } else {
        TagValue::F64(dur)
      };
      ctx.metadata().push(
        Group::new("Composite", "Composite"),
        "Duration",
        composite_val,
      );
    }
  }
}

impl ProcessApe {
  /// Faithful APE.pm:118 docstring + APE.pm:136 `unless ($$et{FileType})`:
  /// invoked by a chained parser that has ALREADY typed the file (e.g.
  /// `ID3::ProcessID3` then `APE::ProcessAPE`, or `ProcessMP3` via the
  /// trailer fallback at ID3.pm:1722-1727). Skips the magic check +
  /// SetFileType and binary-header block (APE.pm:137-162) and runs ONLY
  /// the APETAGEX-trailer scan (APE.pm:165-237).
  ///
  /// Production consumer: the MP3 → APE-trailer fallback in
  /// `crate::formats::id3::process::ProcessMp3` (R2-F2).
  pub(crate) fn process_trailer_only(&self, ctx: &mut ParseContext<'_>) -> bool {
    // APE.pm:131 `$$et{DoneAPE} = 1` — runs unconditionally on entry to
    // ProcessAPE (whether the embedded-ID3 arm fired or not). The
    // trailer-only path IS reached via ID3.pm:1722-1727 from ProcessMP3
    // and (transitively) from the audio-loop recursion at
    // ID3.pm:1582-1601, both of which expect DoneAPE marked.
    ctx.metadata().set_done_ape();
    let print_conv_enabled = ctx.print_conv_enabled();
    // APE.pm:169 — when ProcessID3 (called earlier in the chain by
    // `ProcessMp3` at ID3.pm:1692) stored an ID3v1-trailer size in
    // `$$et{DoneID3}`, the APETAGEX 32-byte trailer header sits BEFORE
    // that block. The Codex R3 F2 fix threads the size in so the scan
    // walks the right offset (mirroring `$footPos -= $$et{DoneID3} if
    // $$et{DoneID3} > 1`).
    let done_id3 = ctx.metadata().done_id3().unwrap_or(0);
    // Planner runs in `print_conv_enabled = false` (raw scalars); sink
    // applies PrintConv at emit time per the bridge's mode.
    let plan = plan_apetagex_trailer_only(ctx.data(), false, done_id3);
    // Lift the plan into a typed Meta and sink through the
    // MetadataTagWriter migration bridge. `header_job` is always
    // `HeaderJob::None` on this path (the chained caller owns SetFileType
    // and any header tags); only main-tag stream + warn flag matters.
    // Intra-APE composite suppression matches `OldFormatParser::process`
    // — cross-format composite resolution runs once below.
    let mut meta = meta_from_plan(plan);
    meta.composite_duration = None;
    {
      let mut bridge = MetadataTagWriter::with_family0(ctx.metadata(), APE_GROUP0);
      let _: Result<(), core::convert::Infallible> = meta.sink(print_conv_enabled, &mut bridge);
    }
    // Composite Duration emission via the shared helper (Codex r16
    // finding): the trailer-only path MUST run Composite resolution
    // because the wire-format APE trailer can carry the four
    // ingredients directly (e.g. `Sample Rate=48000`, etc.). Bundled
    // ExifTool runs `BuildCompositeTags` over the per-file VALUE hash
    // at the end of ExtractInfo regardless of which parser provided
    // the ingredients; our single-parser engine has no separate
    // composite pass, so each parser emits its own composites at the
    // end of `process*`.
    emit_composite_duration_if_present(ctx, print_conv_enabled);
    true
  }
}

/// Push `(g1, name, value)` into `pending`, but if a prior entry has the
/// SAME `(g1, name)` already, REMOVE it first — then append the new one.
/// Faithful to ExifTool's HandleTag/DUPL_TAG rename semantics (Codex r12
/// finding): a wire-format duplicate KEY (same name) renames the OLD
/// VALUE's key to `Name (1)`, so the BARE-NAME key in the value hash is
/// always the LATEST FoundTag call. ExifTool's JSON `%noDups` then
/// suppresses any `Name (1)` token (it has a copy-suffix), so the
/// OBSERVABLE JSON is "only the latest". The simplest faithful
/// implementation in our push-order Metadata Vec is to drop the earlier
/// entry, leaving the latest as the only occurrence.
///
/// Cross-group duplicates (e.g. `MAC:SampleRate` and `APE:SampleRate`)
/// have DIFFERENT `family-1:Name` tokens and BOTH pass through %noDups;
/// this helper checks BOTH g1 and name, so cross-group dups are
/// preserved (faithful — see ape_dup_override fixture).
fn push_or_replace_last(
  pending: &mut Vec<(&'static str, String, TagValue)>,
  g1: &'static str,
  name: String,
  value: TagValue,
) {
  if let Some(pos) = pending
    .iter()
    .position(|(g, n, _)| *g == g1 && n.as_str() == name.as_str())
  {
    pending.remove(pos);
  }
  pending.push((g1, name, value));
}

/// Phase-1 planning: read `data`, return what we'll emit. `print_conv_enabled`
/// only affects the eventual `apply` calls (NOT this read-only scan), but is
/// threaded through because the tag-stream value type promotion (`DURATION`
/// from string → I64) is the same in both modes.
///
/// `already_typed` mirrors `if ($$et{FileType})` (APE.pm:136 negation): when
/// TRUE, the magic check + SetFileType + binary-header block (APE.pm:137-
/// 162) is skipped; only the APETAGEX-trailer block (APE.pm:165-237) runs.
/// This is APE.pm:118's documented "Just looks for APE trailer if FileType
/// is already set" — used in Perl when ProcessAPE is invoked AFTER another
/// parser already typed the file (e.g. MP3, MPC, WavPack chain-calling
/// ProcessAPE for the APE-trailer extraction). Today's engine dispatches
/// ONE parser per file, so `already_typed` is always `false` from the
/// real driver; the path is exercised via direct unit-test injection.
///
/// Returns `None` if APE.pm:137-138 short/non-magic guards reject. Note: a
/// successful return DOES NOT mean we read a footer — APE.pm:170/172
/// `return 1` paths produce an `ApePlan` with `pending == vec![]` and the
/// header_job's File:* tags only.
fn plan_ape(data: &[u8], print_conv_enabled: bool, done_id3: usize) -> Option<ApePlan> {
  plan_ape_inner(data, print_conv_enabled, false, done_id3)
}

/// Variant of [`plan_ape`] that mirrors APE.pm:136 `unless ($$et{FileType})`:
/// when invoked, skip the magic check + SetFileType + binary header block
/// (APE.pm:137-162) and run ONLY the APETAGEX-trailer scan (APE.pm:165-
/// 237). This is APE.pm:118's documented "Just looks for APE trailer if
/// FileType is already set" — used in Perl when ProcessAPE is invoked as
/// a follow-on by a parser that already typed the file (e.g. MP3/ID3,
/// MPC, WavPack chains).
///
/// `pub(crate)` so [`ProcessApe::process_trailer_only`] (this module) can
/// dispatch into the APE trailer extraction directly. Consumers (Codex r15
/// finding): the ID3 → APE-trailer fallback at ID3.pm:1722-1727
/// (`ProcessMp3` in `crate::formats::id3`), which routes void-context
/// through `ProcessApe::process_trailer_only`. Unit-tested via the same
/// seam.
///
/// Phase F3 migration: the production trailer-only path now calls
/// `plan_apetagex_trailer_only` directly (no `Option` wrap), which mirrors
/// the bundled-Perl semantic that the trailer-scan always returns a plan
/// (silent return on no-trailer = empty pending). This `Option`-wrapped
/// variant is retained for unit tests that pre-date Phase F3.
#[allow(dead_code)] // Phase F3 — test-only after typed ApeMeta migration.
pub(crate) fn plan_ape_trailer_only(
  data: &[u8],
  print_conv_enabled: bool,
  done_id3: usize,
) -> Option<ApePlan> {
  plan_ape_inner(data, print_conv_enabled, true, done_id3)
}

/// Trailer-only Phase-1 plan (APE.pm:165-237 — the `unless ($header)`
/// block). Used by the `already_typed = true` arm of [`plan_ape_inner`]:
/// the magic check + SetFileType + binary-header block (APE.pm:137-162)
/// is skipped because a prior parser already typed the file. We scan EOF
/// for an APETAGEX trailer; absent ⇒ silent (APE.pm:172 `return 1`,
/// `pending = []`); present-but-invalid-size ⇒ `Bad APE trailer` warn;
/// present-and-valid ⇒ tag-stream pass.
///
/// `done_id3` faithfully mirrors `$$et{DoneID3}` (APE.pm:169 `$footPos -=
/// $$et{DoneID3} if $$et{DoneID3} > 1`) — when ProcessID3 found an ID3v1
/// trailer at EOF and stored its size (128 from ID3.pm:1527; potentially
/// larger when an Enhanced TAG block precedes it, +227 from :1525), the
/// APETAGEX trailer sits BEFORE that block. The footer scan must walk
/// back PAST the ID3v1 trailer. The `> 1` guard matches bundled exactly
/// (`$$et{DoneID3} = 1` from :1436 means "ID3 ran, no v1 trailer" — no
/// shift; `> 1` means a real trailer size, do shift).
///
/// `header_job` is always [`HeaderJob::None`] (the chained-caller owns
/// the File:*/header tags).
fn plan_apetagex_trailer_only(data: &[u8], print_conv_enabled: bool, done_id3: usize) -> ApePlan {
  let mut plan = ApePlan {
    header_job: HeaderJob::None,
    pending: Vec::new(),
    warn_bad_trailer: false,
  };
  // APE.pm:167-169 `$footPos = -32; $footPos -= $$et{DoneID3} if
  // $$et{DoneID3} > 1` — bundled computes the byte-offset-from-EOF
  // where the 32-byte trailer header sits. `done_id3 > 1` mirrors Perl's
  // `> 1` (note: `$$et{DoneID3} = 1` from ID3.pm:1436 is the "ID3 ran,
  // no v1 trailer" sentinel — no shift in that case).
  let id3_shift = if done_id3 > 1 { done_id3 } else { 0 };
  // APE.pm:170 `$raf->Seek($footPos, 2) or return 1` — fails (silently,
  // no Warn) if the seek would go past start of file. Underflow guard:
  // returning `plan` with no pending = bundled's silent `return 1`.
  let trailer_off = match data.len().checked_sub(32 + id3_shift) {
    Some(off) => off,
    None => return plan,
  };
  // APE.pm:171 `$raf->Read($buff, 32) == 32 or return 1` — slice must
  // be 32 bytes; guaranteed by `data.len() >= 32 + id3_shift`.
  let footer = &data[trailer_off..trailer_off + 32];
  // APE.pm:172 `$buff =~ /^APETAGEX/ or return 1` — silent if absent.
  if !footer.starts_with(b"APETAGEX") {
    return plan;
  }
  let size_raw = u32::from_le_bytes([footer[12], footer[13], footer[14], footer[15]]);
  match decode_apetagex_body_size(size_raw) {
    None => {
      // APE.pm:194 `$count = -1` ⇒ Warn.
      plan.warn_bad_trailer = true;
    }
    Some(body_size) => match trailer_off.checked_sub(body_size) {
      None => plan.warn_bad_trailer = true, // seek-back would underflow
      Some(body_start) => {
        let body = &data[body_start..trailer_off];
        let count = u32::from_le_bytes([footer[16], footer[17], footer[18], footer[19]]) as usize;
        consume_apetagex_tag_stream(body, count, print_conv_enabled, &mut plan);
      }
    },
  }
  plan
}

fn plan_ape_inner(
  data: &[u8],
  print_conv_enabled: bool,
  already_typed: bool,
  done_id3: usize,
) -> Option<ApePlan> {
  // APE.pm:136 `unless ($$et{FileType})` — when the file is already typed
  // by a prior parser, the entire magic+header block (APE.pm:137-162) is
  // skipped; only the APETAGEX-trailer scan runs (APE.pm:118 docstring +
  // APE.pm:165 `unless ($header)`). We emit no File:* or MAC tags in
  // that mode — the prior parser owns those.
  if already_typed {
    return Some(plan_apetagex_trailer_only(
      data,
      print_conv_enabled,
      done_id3,
    ));
  }

  // APE.pm:137 `$raf->Read($buff, 32) == 32 or return 0;`
  if data.len() < 32 {
    return None;
  }
  // APE.pm:138 `$buff =~ /^(MAC |APETAGEX)/ or return 0;`
  let is_mac = data[..4] == *b"MAC ";
  let is_apetagex = data[..8] == *b"APETAGEX";
  if !is_mac && !is_apetagex {
    return None;
  }

  // header_at_start: 32 bytes at offset 0 ARE the APE header (the
  // header-path branch, APE.pm:142-144) versus reading the MAC header
  // (else branch, APE.pm:146-160).
  let header_at_start = is_apetagex;

  // ----- MAC header processing (APE.pm:146-160) --------------------------
  let header_job: HeaderJob = if is_mac {
    // APE.pm:147 `$vers = Get16u(\$buff, 4)` (LE).
    let vers = u16::from_le_bytes([data[4], data[5]]);
    if vers <= 3970 {
      // APE.pm:149-151: `$buff = substr($buff, 4)` ⇒ OldHeader payload
      // starts at byte 4 of the file (after the `MAC ` magic).
      //
      // Codex r4 finding: clone only the bytes the OldHeader can actually
      // read — index 12 int32u extends to byte 28 from the start of the
      // post-magic slice, so we need at most 28 bytes. Larger MAC files
      // (many KB) shouldn't pay a whole-file copy here.
      const OLD_HEADER_MAX_BYTES: usize = 28;
      let take = (data.len() - 4).min(OLD_HEADER_MAX_BYTES);
      HeaderJob::Old(data[4..4 + take].to_vec())
    } else {
      // APE.pm:153-159: $dlen=Get32u(8), $hlen=Get32u(12); if neither
      // has bit 31 set, the NewHeader body is at $dlen..$dlen+$hlen.
      let dlen = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
      let hlen = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
      let high_bit = 0x8000_0000usize;
      let mut job = HeaderJob::None;
      if (dlen & high_bit) == 0 && (hlen & high_bit) == 0 {
        // APE.pm:156 `$raf->Seek($dlen,0) and $raf->Read($buff,$hlen)
        // == $hlen` — only proceed if BOTH seek and read succeed.
        let end = dlen.saturating_add(hlen);
        if dlen <= data.len() && end <= data.len() {
          job = HeaderJob::New(data[dlen..end].to_vec());
        }
      }
      job
    }
  } else {
    HeaderJob::None
  };

  // ----- APE tag stream (APE.pm:165-238) ---------------------------------
  // Pick the 32-byte APE header that drives the tag-stream pass:
  // - header_at_start: bytes [0..32].
  // - else (MAC path): walk EOF for an APETAGEX footer.
  //
  // Three terminal states (Codex r1 finding 1):
  // - NoHeader: APE.pm:172 footer not found ⇒ silent `return 1` (no Warn).
  // - HeaderInvalid: APE.pm:181-194 size/seek/read failure ⇒ `$count = -1`
  //   ⇒ the for-loop runs zero iterations and APE.pm:238 emits
  //   `Warn('Bad APE trailer')`. Faithful: set warn_bad_trailer.
  // - HeaderAndBody: normal tag-stream walk; APE.pm:238 emits the warning
  //   only when the loop terminated early (n_consumed != count).
  enum HeaderState<'a> {
    NoHeader,
    HeaderInvalid,
    HeaderAndBody(&'a [u8], &'a [u8]),
  }
  // (see `decode_apetagex_body_size` at module scope — lifted from
  // `plan_ape` so the boundary semantics can be unit-tested directly,
  // Codex r15 finding.)
  let header_state: HeaderState<'_> = if header_at_start {
    let header = &data[..32];
    let size_raw = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
    match decode_apetagex_body_size(size_raw) {
      None => HeaderState::HeaderInvalid,
      Some(body_size) => {
        let end = 32usize.saturating_add(body_size);
        // APE.pm:183 `$raf->Read($buff, $size) == $size` — strictly equal,
        // so a short read (`end > data.len()`) also fails ⇒ `$count = -1`.
        if end <= data.len() {
          HeaderState::HeaderAndBody(header, &data[32..end])
        } else {
          HeaderState::HeaderInvalid
        }
      }
    }
  } else {
    // APE.pm:165-174 footer path. `done_id3 > 1` mirrors APE.pm:169
    // `$footPos -= $$et{DoneID3} if $$et{DoneID3} > 1` — when an ID3v1
    // trailer (128 bytes) lives at EOF, walk back PAST it to find the
    // APETAGEX 32-byte header. The earlier `data.len() >= 32` gate is
    // insufficient when shifting; we re-check via checked_sub to mirror
    // APE.pm:170 `Seek($footPos, 2) or return 1` (silent return on
    // underflow, NO Warn).
    let id3_shift = if done_id3 > 1 { done_id3 } else { 0 };
    let Some(trailer_off) = data.len().checked_sub(32 + id3_shift) else {
      // Silent: bundled `Seek(...) or return 1` — no Warn.
      return Some(ApePlan {
        header_job,
        pending: Vec::new(),
        warn_bad_trailer: false,
      });
    };
    let footer = &data[trailer_off..trailer_off + 32];
    if !footer.starts_with(b"APETAGEX") {
      // APE.pm:172 `$buff =~ /^APETAGEX/ or return 1` — no trailer, no Warn.
      HeaderState::NoHeader
    } else {
      let size_raw = u32::from_le_bytes([footer[12], footer[13], footer[14], footer[15]]);
      match decode_apetagex_body_size(size_raw) {
        None => HeaderState::HeaderInvalid,
        Some(body_size) => {
          // APE.pm:182 `$raf->Seek(-$size-32, 1)` — fails if it would go
          // past the start of file. Our `data` is the WHOLE file, so the
          // seek succeeds iff `trailer_off >= body_size`. The subsequent
          // `Read($buff, $size) == $size` then succeeds (the bytes exist
          // between body_start and trailer_off, which is `body_size`
          // bytes).
          match trailer_off.checked_sub(body_size) {
            Some(body_start) => HeaderState::HeaderAndBody(footer, &data[body_start..trailer_off]),
            None => HeaderState::HeaderInvalid,
          }
        }
      }
    }
  };

  // Initialize Warn flag based on the header state. APE.pm:194 sets
  // `$count = -1` then APE.pm:200 `for ($i=0; $i<$count; ++$i)` runs
  // zero iterations (signed `0 < -1` is false), and APE.pm:238 `$i ==
  // $count` is `0 == -1` ⇒ false ⇒ Warn. So HeaderInvalid ⇒ Warn.
  let mut plan = ApePlan {
    header_job,
    pending: Vec::new(),
    warn_bad_trailer: matches!(header_state, HeaderState::HeaderInvalid),
  };

  if let HeaderState::HeaderAndBody(header, body) = header_state {
    // APE.pm:178 `($version, $size, $count, $flags) = unpack('x8V4', $buff)`.
    let count = u32::from_le_bytes([header[16], header[17], header[18], header[19]]) as usize;
    consume_apetagex_tag_stream(body, count, print_conv_enabled, &mut plan);
  }

  Some(plan)
}

/// Faithful APE.pm:198-238 tag-stream loop. `body` is the APE-tag payload
/// (post-header, `$size` bytes long); `count` is the declared `$count`
/// from the header. Mutates `plan.pending` (the tag pushes, with
/// DUPL_TAG-rename semantics via `push_or_replace_last`) and sets
/// `plan.warn_bad_trailer = true` when the loop terminated early
/// (`$i != $count` on exit, APE.pm:238).
fn consume_apetagex_tag_stream(
  body: &[u8],
  count: usize,
  print_conv_enabled: bool,
  plan: &mut ApePlan,
) {
  let actual_size = body.len();
  let mut pos = 0usize;
  let mut n_consumed = 0usize;
  let mut i = 0usize;
  while i < count {
    // APE.pm:202 `last if $pos + 8 > $size`.
    if pos + 8 > actual_size {
      break;
    }
    // APE.pm:203 `Get32u(buff, pos)`.
    let tag_len =
      u32::from_le_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]]) as usize;
    // APE.pm:204 `Get32u(buff, pos+4)`.
    let tag_flags =
      u32::from_le_bytes([body[pos + 4], body[pos + 5], body[pos + 6], body[pos + 7]]);
    // APE.pm:205-206 NUL-terminated key starting at pos+8.
    let key_start = pos + 8;
    let Some(nul_off) = body[key_start..actual_size].iter().position(|&b| b == 0) else {
      // Perl regex /\G(.*?)\0/sg fails ⇒ `last`.
      break;
    };
    let key_bytes = &body[key_start..key_start + nul_off];
    // APE keys are ASCII per APE spec; lossy-utf8 the worst case so we
    // never panic. (Faithful: Perl strings carry raw bytes.)
    let key_str_owned = String::from_utf8_lossy(key_bytes).to_string();
    let key_str = key_str_owned.as_str();
    // APE.pm:209 `$tag .= '.' if $specialTags{$tag}` — DEFERRED.
    // APE.pm:210 `$pos = pos($buff);` ⇒ after the NUL.
    pos = key_start + nul_off + 1;
    // APE.pm:211 `last if $pos + $len > $size;`.
    if pos + tag_len > actual_size {
      break;
    }
    // APE.pm:212 `$val = substr($buff, $pos, $len);`.
    let val_bytes = &body[pos..pos + tag_len];
    // APE.pm:214 `if (($flags & 0x06) == 0x02) { ... binary ... }`.
    let is_binary = (tag_flags & 0x06) == 0x02;

    // Cover Art Desc carve-out (APE.pm:218-227). Faithful Perl flow:
    //   $buf2 =~ s/^([\x20-\x7e]*)\0//;   # ← always runs the s///
    //   if ($1) { ... emit "${tag} Desc" ... }
    //
    // The substitution is UNCONDITIONAL when the regex matches (a run
    // of 0+ ASCII-printable bytes followed by NUL): the value loses
    // that prefix. Only the Desc-tag emission is gated on Perl-truthy
    // `$1` (non-empty AND not literal "0"). Codex r2 finding 1: a
    // falsey description (empty or "0") MUST still be stripped from
    // the binary payload — earlier code skipped the strip in that
    // case, emitting a corrupted/oversized CoverArt payload.
    let (val_to_emit, cover_desc): (TagValue, Option<(String, String)>) = if is_binary {
      if key_str.starts_with("Cover Art") {
        // Find the regex anchor: longest leading run of bytes in
        // [0x20..0x7e] followed by NUL. The regex's `*` permits a
        // ZERO-length leading run (just `\0` at offset 0 matches with
        // $1 == "").
        let mut n_prefix = 0usize;
        while n_prefix < val_bytes.len() && (0x20..=0x7e).contains(&val_bytes[n_prefix]) {
          n_prefix += 1;
        }
        if n_prefix < val_bytes.len() && val_bytes[n_prefix] == 0 {
          // Regex matched: ALWAYS strip $&. The remainder is the
          // binary value the parent HandleTag receives.
          let desc = &val_bytes[..n_prefix];
          let desc_str = String::from_utf8_lossy(desc).to_string();
          let rest = &val_bytes[n_prefix + 1..];
          // APE.pm:221 `if ($1)` — Perl truthy: non-empty AND not "0".
          let truthy = !desc.is_empty() && desc_str != "0";
          if truthy {
            let desc_key = format!("{key_str} Desc");
            (TagValue::Bytes(rest.to_vec()), Some((desc_key, desc_str)))
          } else {
            // Falsey Desc ⇒ no Desc tag, but the strip still applied.
            (TagValue::Bytes(rest.to_vec()), None)
          }
        } else {
          // Regex did NOT match (no NUL after the printable run, or
          // a non-printable byte before any NUL). Perl `s///` leaves
          // $buf2 unchanged; we emit the full bytes as the value.
          (TagValue::Bytes(val_bytes.to_vec()), None)
        }
      } else {
        (TagValue::Bytes(val_bytes.to_vec()), None)
      }
    } else {
      // Non-binary: APE.pm passes `$val` (raw bytes) through HandleTag as
      // a STRING; ExifTool then runs ValueConv/PrintConv against that
      // string. `ape_duration_value_conv` accepts `Str` directly and
      // applies Perl numeric coercion (the +i32-wrap + ×1e-7), so we
      // can just emit the raw string for every non-binary tag — no
      // eager promotion to I64. (Codex r1 finding 3: a non-exact-i64
      // string like "20000000.5" or "20000000\0" must still scale; the
      // ValueConv now handles all such shapes.)
      let s = String::from_utf8_lossy(val_bytes).to_string();
      (TagValue::Str(s.into()), None)
    };

    // APE.pm:222-225 — emit Desc FIRST (APE.pm:225 HandleTag for Desc
    // is INSIDE the binary block, BEFORE the outer HandleTag at
    // APE.pm:229).
    if let Some((desc_key, desc_val)) = cover_desc {
      let desc_name = make_tag(&desc_key);
      push_or_replace_last(
        &mut plan.pending,
        "APE",
        desc_name,
        TagValue::Str(desc_val.into()),
      );
    }

    // APE.pm:213 `MakeTag($tag, $tagTablePtr) unless $$tagTablePtr{$tag}`.
    let static_def = (APE_MAIN.get())(TagId::Str(key_to_static_lookup(key_str)));
    let emitted_name: String = match static_def {
      Some(def) => def.name().to_string(),
      None => make_tag(key_str),
    };
    // Static def ⇒ run ValueConv/PrintConv; dynamic (MakeTag) tag emits
    // as-is (APE.pm:109 tagInfo has only `Name`).
    let converted = match static_def {
      Some(def) => crate::convert::apply(def, &val_to_emit, print_conv_enabled),
      None => val_to_emit,
    };
    push_or_replace_last(&mut plan.pending, "APE", emitted_name, converted);

    // APE.pm:236 `$pos += $len;`.
    pos += tag_len;
    n_consumed += 1;
    i += 1;
  }
  // APE.pm:238 `$i == $count or $et->Warn('Bad APE trailer');`.
  if n_consumed != count {
    plan.warn_bad_trailer = true;
  }
}

/// Map a runtime APE tag key to its STATIC `%Main` lookup key (`&'static
/// str` so it can feed `TagId::Str`). Returns `""` for any key that's NOT
/// in the static dictionary; `ape_main_get` has no `""` arm ⇒ guaranteed
/// miss ⇒ caller falls through to `make_tag`.
fn key_to_static_lookup(key: &str) -> &'static str {
  match key {
    "Album" => "Album",
    "Artist" => "Artist",
    "Genre" => "Genre",
    "Title" => "Title",
    "Track" => "Track",
    "Year" => "Year",
    "Tool Version" => "Tool Version",
    "Tool Name" => "Tool Name",
    "DURATION" => "DURATION",
    _ => "",
  }
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
  use super::*;

  // ExifTool.pm:6866-6884 sub ConvertDuration:
  //   return $time unless IsFloat($time);
  //   return '0 s' if $time == 0;
  //   $time < 30   ⇒ sprintf("%.2f s")
  //   else (after $time += 0.5):
  //     formed as $h:$m:$s, with "$d days " prefix if $h > 24.
  #[test]
  fn convert_duration_faithful_branches() {
    // Non-float (regex IsFloat fails) ⇒ identity passthrough.
    assert_eq!(
      convert_duration(&TagValue::Str("abc".into())),
      TagValue::Str("abc".into())
    );
    // Zero ⇒ "0 s".
    assert_eq!(
      convert_duration(&TagValue::F64(0.0)),
      TagValue::Str("0 s".into())
    );
    // < 30 ⇒ "%.2f s" with sign.
    assert_eq!(
      convert_duration(&TagValue::F64(2.639_229_024_943_311)),
      TagValue::Str("2.64 s".into())
    );
    assert_eq!(
      convert_duration(&TagValue::F64(-2.5)),
      TagValue::Str("-2.50 s".into())
    );
    // >= 30, < 1h ⇒ "0:00:30" style (after +0.5 rounding).
    assert_eq!(
      convert_duration(&TagValue::F64(30.0)),
      TagValue::Str("0:00:30".into())
    );
    assert_eq!(
      convert_duration(&TagValue::F64(125.4)),
      TagValue::Str("0:02:05".into())
    );
    // >= 1h, < 25h.
    assert_eq!(
      convert_duration(&TagValue::F64(3600.0)),
      TagValue::Str("1:00:00".into())
    );
    // > 24h ⇒ days carve-out.
    assert_eq!(
      convert_duration(&TagValue::F64(90061.0)),
      TagValue::Str("1 days 1:01:01".into())
    );
    // Negative >= 30 secs: sign carries through.
    assert_eq!(
      convert_duration(&TagValue::F64(-3661.0)),
      TagValue::Str("-1:01:01".into())
    );
    // I64 input: IsFloat regex accepts bare integer strings ⇒ promote to
    // f64 via as_perl_float, then process.
    assert_eq!(
      convert_duration(&TagValue::I64(45)),
      TagValue::Str("0:00:45".into())
    );
  }

  // APE.pm:102-112 sub MakeTag transliteration cross-check.
  // Examples verified by running the actual Perl regexes (see below).
  #[test]
  fn make_tag_faithful_to_perl() {
    assert_eq!(make_tag("Album"), "Album");
    assert_eq!(make_tag("Tool Version"), "ToolVersion");
    assert_eq!(make_tag("Tool Name"), "ToolName");
    assert_eq!(make_tag("Cover Art (Front)"), "CoverArtFront");
    // Desc carve-out tag (constructed as "<key> Desc" before make_tag).
    assert_eq!(make_tag("Cover Art (Front) Desc"), "CoverArtFrontDesc");
    assert_eq!(make_tag("Media Jukebox Date"), "MediaJukeboxDate");
    // Trailing punctuation: the s/// regex's (.?) at end-of-string matches
    // ε ⇒ the run is deleted.
    assert_eq!(make_tag("hello!"), "Hello");
    // Hyphen is preserved by [^\w-].
    assert_eq!(make_tag("Multi-Part Tag"), "Multi-partTag");
    // snake_case → camelCase via s/([a-z0-9])_([a-z])/$1\U$2/g.
    assert_eq!(make_tag("hello_world"), "HelloWorld");
    // Empty key ⇒ ExifTool.pm:9254 length<2 prepend "Tag" ⇒ "Tag".
    // (Verified against bundled ExifTool: an APE tag with empty key
    // emits `APE:Tag`.)
    assert_eq!(make_tag(""), "Tag");
  }

  // Codex r12 finding: AddTagToTable (ExifTool.pm:9243-9255) post-
  // processes the MakeTag-output name before storing it. Single-char
  // and stripped-to-empty keys trigger the `Tag` prefix via line 9254
  // `$name = "Tag$name" if length($name) < 2 or $name !~ /^[A-Z]/i`.
  // All cases verified against bundled ExifTool 13.58 on synthesized
  // APE wire keys (`/tmp/ape_dyn_keys.ape`).
  #[test]
  fn make_tag_add_tag_to_table_post_processing() {
    // Single digit, single hyphen, single underscore, single dot,
    // single lowercase letter — all len<2 OR not starting with [A-Za-z]
    // OR stripped-to-empty. Verified: Perl emits "Tag1", "Tag-",
    // "Tag_", "Tag", "TagA".
    assert_eq!(make_tag("1"), "Tag1");
    assert_eq!(make_tag("-"), "Tag-");
    assert_eq!(make_tag("_"), "Tag_");
    // `.` is non-word non-dash; MakeTag's s/// at EOS matches ε ⇒ name
    // becomes ""; AddTagToTable strips and prepends ⇒ "Tag".
    assert_eq!(make_tag("."), "Tag");
    // Single lowercase letter: MakeTag's ucfirst lc → "A"; length(1)<2
    // ⇒ prepend "Tag" ⇒ "TagA".
    assert_eq!(make_tag("a"), "TagA");
    // Two-char keys that survive intact are NOT prefixed.
    assert_eq!(make_tag("Ab"), "Ab");
    // Two-char key starting with digit: ucfirst lc leaves `1a`; AddTag
    // To Table line 9254 sees `len>=2` but `!~ /^[A-Z]/i` (digit) so
    // prepends `Tag` ⇒ `Tag1a` (the second `a` stays lowercase — no
    // case change beyond MakeTag's lc and the AddTagToTable ucfirst).
    assert_eq!(make_tag("1a"), "Tag1a");
    // MakeTag's s/// promotes the post-dot `b` ⇒ `AB`; AddTagToTable
    // sees `AB` ⇒ no Tag prefix (len>=2 AND starts with [A-Z]).
    assert_eq!(make_tag("a.b"), "AB");
    // --- Leading-underscore / leading-hyphen cases (Codex r13 follow-up,
    // empirically verified against bundled Perl ExifTool 13.58). The
    // AddTagToTable line 9254 condition `!~ /^[A-Z]/i` fires for ANY
    // first char that isn't an ASCII letter, INCLUDING `_` (which is a
    // valid `\w` char and survives tr///). So `_abc` (length 4, starts
    // with `_`) still gets the `Tag` prefix.
    assert_eq!(make_tag("_abc"), "Tag_abc");
    assert_eq!(make_tag("_a"), "Tag_a");
    assert_eq!(make_tag("_xyz"), "Tag_xyz");
    // ucfirst applies but only to the FIRST char; `_AB` → ucfirst lc →
    // `_ab` → tr keeps `_ab` → ucfirst is no-op on `_` → starts with
    // `_` ⇒ Tag prefix ⇒ `Tag_ab`.
    assert_eq!(make_tag("_AB"), "Tag_ab");
    // `_5` (length 2 but starts with `_`) ⇒ Tag prefix ⇒ `Tag_5`.
    assert_eq!(make_tag("_5"), "Tag_5");
    // Double underscore: `__abc` length 5, starts with `_` ⇒ Tag prefix.
    assert_eq!(make_tag("__abc"), "Tag__abc");
    // `_1a` ⇒ `Tag_1a` (starts with `_`).
    assert_eq!(make_tag("_1a"), "Tag_1a");
    // Leading hyphen behaves the same way (`-` is in tr's allow-list).
    assert_eq!(make_tag("-abc"), "Tag-abc");
    assert_eq!(make_tag("-a"), "Tag-a");
  }

  // Codex r4 finding: Perl `s///g` is NON-OVERLAPPING. After a match
  // consumes `X_y`, the next search starts AFTER the consumed `y` ⇒ the
  // previously-consumed `[a-z]` is NOT available as left-context for a
  // follow-on match. Earlier code used a lookbehind on `bs[j-1]`, which
  // would over-eagerly promote every `_<lower>` adjacent to a consumed
  // letter. All expected values below verified empirically with Perl:
  //
  //   $ perl -e 'sub mk { my $n=shift; $n=ucfirst(lc($n)); $n=~s/[^\w-]+(.?)/\U$1/sg; $n=~s/([a-z0-9])_([a-z])/$1\U$2/g; $n; }; for my $s (...) { print "$s -> ",mk($s),"\n"; }'
  //   aa_b_c            -> AaB_c
  //   foo_b_c_d         -> FooB_cD
  //   a_b_c             -> A_bC
  //   a_b_c_d           -> A_bC_d
  //   a_b_c_d_e         -> A_bC_dE
  //   aa_bb_cc          -> AaBbCc
  //   1_a_b_c           -> 1A_bC       (matched, then promoted; tag below adds the `Tag` prefix)
  //   hello_world_foo   -> HelloWorldFoo
  //
  // The pos-tracking bug surfaces wherever a `[a-z]` between two `_`
  // would have been consumed by the FIRST match, leaving the following
  // `_<lower>` past pos without an `[a-z0-9]` left-context for the
  // second match.
  #[test]
  fn make_tag_nonoverlapping_regex_substitution() {
    assert_eq!(make_tag("aa_b_c"), "AaB_c");
    assert_eq!(make_tag("foo_b_c_d"), "FooB_cD");
    assert_eq!(make_tag("a_b_c"), "A_bC");
    assert_eq!(make_tag("a_b_c_d"), "A_bC_d");
    assert_eq!(make_tag("a_b_c_d_e"), "A_bC_dE");
    assert_eq!(make_tag("aa_bb_cc"), "AaBbCc");
    // After AddTagToTable: starts with `1` (digit) ⇒ prepend "Tag".
    // Verified against bundled ExifTool 13.58: APE key `1_a_b_c` ⇒
    // `APE:Tag1A_bC`.
    assert_eq!(make_tag("1_a_b_c"), "Tag1A_bC");
    assert_eq!(make_tag("hello_world_foo"), "HelloWorldFoo");
  }

  // ProcessBinaryData byte-offset rule (ExifTool.pm:9922): offset =
  // index * sizeof(table default), NOT per-field-format. APE OldHeader /
  // NewHeader default int16u ⇒ offset = index * 2.
  #[test]
  fn new_header_extracts_expected_fields() {
    let mut hdr = [0u8; 24];
    // CompressionLevel = 3000 @ offset 0 (int16u LE).
    hdr[0..2].copy_from_slice(&3000u16.to_le_bytes());
    // BlocksPerFrame = 73728 @ offset 4 (int32u LE).
    hdr[4..8].copy_from_slice(&73728u32.to_le_bytes());
    // FinalFrameBlocks = 42662 @ offset 8 (int32u LE).
    hdr[8..12].copy_from_slice(&42662u32.to_le_bytes());
    // TotalFrames = 2 @ offset 12 (int32u LE).
    hdr[12..16].copy_from_slice(&2u32.to_le_bytes());
    // BitsPerSample = 16 @ offset 16 (int16u LE).
    hdr[16..18].copy_from_slice(&16u16.to_le_bytes());
    // Channels = 2 @ offset 18 (int16u LE).
    hdr[18..20].copy_from_slice(&2u16.to_le_bytes());
    // SampleRate = 44100 @ offset 20 (int32u LE).
    hdr[20..24].copy_from_slice(&44100u32.to_le_bytes());

    let mut m = crate::value::Metadata::new("x");
    process_ape_binary_data(&hdr, NEW_HEADER, &mut m, true);

    let by_name: std::collections::HashMap<&str, &TagValue> =
      m.tags().iter().map(|t| (t.name(), t.value())).collect();
    assert_eq!(by_name.get("CompressionLevel"), Some(&&TagValue::I64(3000)));
    assert_eq!(by_name.get("BlocksPerFrame"), Some(&&TagValue::I64(73728)));
    assert_eq!(
      by_name.get("FinalFrameBlocks"),
      Some(&&TagValue::I64(42662))
    );
    assert_eq!(by_name.get("TotalFrames"), Some(&&TagValue::I64(2)));
    assert_eq!(by_name.get("BitsPerSample"), Some(&&TagValue::I64(16)));
    assert_eq!(by_name.get("Channels"), Some(&&TagValue::I64(2)));
    assert_eq!(by_name.get("SampleRate"), Some(&&TagValue::I64(44100)));
    // Family-0 = APE (package default), family-1 = MAC (GROUPS{1}).
    for t in m.tags() {
      assert_eq!(t.group().family0(), "APE");
      assert_eq!(t.group().family1(), "MAC");
    }
  }

  // APE.pm:50-53 OldHeader index 0 = APEVersion with ValueConv '$val / 1000'.
  // Byte offset = 0 * 2 = 0 (int16u table default).
  #[test]
  fn old_header_apeversion_value_conv() {
    let mut hdr = [0u8; 28];
    hdr[0..2].copy_from_slice(&3970u16.to_le_bytes()); // APEVersion raw 3970 ⇒ 3.97
    hdr[2..4].copy_from_slice(&1000u16.to_le_bytes()); // CompressionLevel @ 2
    hdr[6..8].copy_from_slice(&2u16.to_le_bytes()); // Channels (index 3 ⇒ offset 6)
    hdr[8..12].copy_from_slice(&44100u32.to_le_bytes()); // SampleRate (index 4 ⇒ offset 8)
    let mut m = crate::value::Metadata::new("x");
    process_ape_binary_data(&hdr, OLD_HEADER, &mut m, true);
    let by_name: std::collections::HashMap<&str, &TagValue> =
      m.tags().iter().map(|t| (t.name(), t.value())).collect();
    // Raw 3970 / 1000 = 3.97 (f64).
    assert_eq!(by_name.get("APEVersion"), Some(&&TagValue::F64(3.97)));
    assert_eq!(by_name.get("CompressionLevel"), Some(&&TagValue::I64(1000)));
    assert_eq!(by_name.get("Channels"), Some(&&TagValue::I64(2)));
    assert_eq!(by_name.get("SampleRate"), Some(&&TagValue::I64(44100)));
  }

  // Codex r4 finding: the OldHeader-branch clone (HeaderJob::Old) must
  // only copy as many bytes as the OldHeader can actually read — index
  // 12 int32u extends to byte 28 from the start of the post-magic slice.
  // A large MAC-prefixed file must still parse correctly while the clone
  // stays bounded to 28 bytes.
  #[test]
  fn old_header_large_mac_file_no_whole_file_copy() {
    // 8 KiB synthetic OldHeader fixture: MAC magic + 28-byte OldHeader
    // body + arbitrary trailing junk. Faithful parse must succeed
    // identically regardless of trailing bytes.
    let mut data = vec![0u8; 8192];
    data[..4].copy_from_slice(b"MAC ");
    // OldHeader body starts at byte 4 of the file.
    data[4..6].copy_from_slice(&3970u16.to_le_bytes()); // APEVersion
    data[6..8].copy_from_slice(&2500u16.to_le_bytes()); // CompressionLevel
    data[10..12].copy_from_slice(&2u16.to_le_bytes()); // Channels (idx 3)
    data[12..16].copy_from_slice(&48000u32.to_le_bytes()); // SampleRate (idx 4)
    data[24..28].copy_from_slice(&500u32.to_le_bytes()); // TotalFrames (idx 10)
    data[28..32].copy_from_slice(&65536u32.to_le_bytes()); // FinalFrameBlocks (idx 12)
    // Fill the rest with non-zero junk that would corrupt header reads
    // if we mistakenly copied the WHOLE file and indexed past 28 bytes.
    for byte in data.iter_mut().skip(32) {
      *byte = 0xCC;
    }
    let mut m = crate::value::Metadata::new("x");
    let mut c = ParseContext::new(&data, "APE", 0, "APE", None, true, &mut m);
    assert!(ProcessApe.process(&mut c));
    let by_name: std::collections::HashMap<&str, &TagValue> = m
      .tags()
      .iter()
      .filter(|t| t.group().family1() == "MAC")
      .map(|t| (t.name(), t.value()))
      .collect();
    assert_eq!(by_name.get("APEVersion"), Some(&&TagValue::F64(3.97)));
    assert_eq!(by_name.get("CompressionLevel"), Some(&&TagValue::I64(2500)));
    assert_eq!(by_name.get("Channels"), Some(&&TagValue::I64(2)));
    assert_eq!(by_name.get("SampleRate"), Some(&&TagValue::I64(48000)));
    assert_eq!(by_name.get("TotalFrames"), Some(&&TagValue::I64(500)));
    assert_eq!(
      by_name.get("FinalFrameBlocks"),
      Some(&&TagValue::I64(65536))
    );
  }

  // ExifTool.pm:9953 `last if $more <= 0` — a field whose offset+width
  // exceeds the slice MUST silently stop (Perl bundled tool does not panic
  // or warn). Our iteration is ascending by index, so a `break` is
  // value-identical to Perl's `last`.
  #[test]
  fn binary_data_skips_overrun_no_panic() {
    let short = [0u8; 5];
    // < 6 ⇒ CompressionLevel @ offset 0 (2 bytes) OK; nothing else fits.
    let mut m = crate::value::Metadata::new("x");
    process_ape_binary_data(&short, NEW_HEADER, &mut m, true);
    assert_eq!(m.tags().len(), 1);
    assert_eq!(m.tags()[0].name(), "CompressionLevel");
  }

  // Static %Main lookup (APE.pm:29-42).
  #[test]
  fn ape_main_static_lookup() {
    let g = APE_MAIN.get();
    assert_eq!(g(TagId::Str("Album")).unwrap().name(), "Album");
    assert_eq!(g(TagId::Str("Tool Version")).unwrap().name(), "ToolVersion");
    assert_eq!(g(TagId::Str("Tool Name")).unwrap().name(), "ToolName");
    let dur = g(TagId::Str("DURATION")).unwrap();
    assert_eq!(dur.name(), "Duration");
    assert!(matches!(dur.value_conv(), ValueConv::Func(_)));
    assert!(matches!(dur.print_conv(), PrintConv::Func(_)));
    assert!(g(TagId::Str("Cover Art (Front)")).is_none());
    assert!(g(TagId::Int(0)).is_none());
    assert_eq!(APE_MAIN.group0(), "APE");
  }

  // APE.pm:35-39 DURATION ValueConv: signed-i32 wrap then ×1e-7. The
  // ValueConv accepts every shape Perl `+0` numeric coercion would accept
  // (Codex r1 finding 3 adversarial cases).
  #[test]
  fn duration_value_conv_signed_i32_wrap() {
    // --- I64 ---
    // Positive int32u stays positive.
    assert_eq!(
      ape_duration_value_conv(&TagValue::I64(20_000_000)),
      TagValue::F64(2.0)
    );
    // 0.
    assert_eq!(
      ape_duration_value_conv(&TagValue::I64(0)),
      TagValue::F64(0.0)
    );
    // -1 (signed-i32 of 0xFFFFFFFF) ⇒ -1 + 2^32 = 4294967295, ×1e-7.
    assert_eq!(
      ape_duration_value_conv(&TagValue::I64(-1)),
      TagValue::F64(4294967295.0 * 1e-7)
    );
    // i32 min boundary is INCLUDED in the wrap.
    assert_eq!(
      ape_duration_value_conv(&TagValue::I64(-2_147_483_648)),
      TagValue::F64(2_147_483_648.0 * 1e-7)
    );
    // Below i32 min: NOT corrected (faithful guard $val>=-2147483648).
    assert_eq!(
      ape_duration_value_conv(&TagValue::I64(-2_147_483_649)),
      TagValue::F64((-2_147_483_649_i64) as f64 * 1e-7)
    );
    // --- F64 (Codex r1 finding 3: the wrap MUST apply to floats too) ---
    assert_eq!(
      ape_duration_value_conv(&TagValue::F64(-1.0)),
      TagValue::F64(4294967295.0 * 1e-7)
    );
    assert_eq!(
      ape_duration_value_conv(&TagValue::F64(-0.5)),
      TagValue::F64(4_294_967_295.5_f64 * 1e-7)
    );
    // f64 below the i32 minimum: NOT corrected.
    assert_eq!(
      ape_duration_value_conv(&TagValue::F64(-3_000_000_000.0)),
      TagValue::F64(-3_000_000_000.0_f64 * 1e-7)
    );
    // --- Str (Perl numeric coercion is part of the ValueConv) ---
    // Plain integer string ⇒ same as I64.
    assert_eq!(
      ape_duration_value_conv(&TagValue::Str("20000000".into())),
      TagValue::F64(2.0)
    );
    // Trailing garbage (NUL, whitespace, letters) ⇒ Perl scans the
    // longest valid leading numeric prefix.
    assert_eq!(
      ape_duration_value_conv(&TagValue::Str("20000000\0".into())),
      TagValue::F64(2.0)
    );
    assert_eq!(
      ape_duration_value_conv(&TagValue::Str("  20000000".into())),
      TagValue::F64(2.0)
    );
    // Negative signed-decimal ⇒ wrap applies (faithful Perl numeric).
    assert_eq!(
      ape_duration_value_conv(&TagValue::Str("-1.0".into())),
      TagValue::F64(4294967295.0 * 1e-7)
    );
    // Fractional positive ⇒ no wrap.
    assert_eq!(
      ape_duration_value_conv(&TagValue::Str("20000000.5".into())),
      TagValue::F64(20_000_000.5_f64 * 1e-7)
    );
    // Garbage ⇒ Perl `+0` = 0.
    assert_eq!(
      ape_duration_value_conv(&TagValue::Str("abc".into())),
      TagValue::F64(0.0)
    );
    // Exponent.
    assert_eq!(
      ape_duration_value_conv(&TagValue::Str("2e7".into())),
      TagValue::F64(2.0)
    );
    // Sign + exponent.
    assert_eq!(
      ape_duration_value_conv(&TagValue::Str("-1e0".into())),
      TagValue::F64(4294967295.0 * 1e-7)
    );
  }

  // perl_numeric_coerce_f64 sanity vs Perl rules.
  #[test]
  fn perl_numeric_coerce_f64_faithful() {
    // Plain integer.
    assert_eq!(perl_numeric_coerce_f64("123"), 123.0);
    // Trailing garbage stops the prefix scan.
    assert_eq!(perl_numeric_coerce_f64("123\0extra"), 123.0);
    assert_eq!(perl_numeric_coerce_f64("123abc"), 123.0);
    // Leading whitespace skipped.
    assert_eq!(perl_numeric_coerce_f64("   42"), 42.0);
    assert_eq!(perl_numeric_coerce_f64("\t-5"), -5.0);
    // Sign + integer + fraction.
    assert_eq!(perl_numeric_coerce_f64("-1.5"), -1.5);
    assert_eq!(perl_numeric_coerce_f64("+1.0"), 1.0);
    // Lone dot before digits.
    assert_eq!(perl_numeric_coerce_f64(".5"), 0.5);
    // Exponent.
    assert_eq!(perl_numeric_coerce_f64("2e3"), 2000.0);
    assert_eq!(perl_numeric_coerce_f64("2.5E-2"), 0.025);
    // No numeric prefix ⇒ 0.
    assert_eq!(perl_numeric_coerce_f64("abc"), 0.0);
    assert_eq!(perl_numeric_coerce_f64(""), 0.0);
    assert_eq!(perl_numeric_coerce_f64("."), 0.0);
    // `E` with no digits ⇒ backtrack to before `E`.
    assert_eq!(perl_numeric_coerce_f64("123E"), 123.0);
    assert_eq!(perl_numeric_coerce_f64("123Eabc"), 123.0);
  }

  // The driver must reject short/non-APE inputs cleanly without pushing tags.
  #[test]
  fn rejects_short_and_non_ape_inputs() {
    let mut m = crate::value::Metadata::new("x");
    let too_short = [0u8; 31];
    let mut c = ParseContext::new(&too_short, "APE", 0, "APE", None, true, &mut m);
    assert!(!ProcessApe.process(&mut c));
    assert!(m.tags().is_empty());

    let mut m2 = crate::value::Metadata::new("x");
    let wrong_magic = [0xffu8; 32];
    let mut c2 = ParseContext::new(&wrong_magic, "APE", 0, "APE", None, true, &mut m2);
    assert!(!ProcessApe.process(&mut c2));
    assert!(m2.tags().is_empty());
  }

  // key_to_static_lookup must funnel non-static keys to the empty string
  // (guaranteed miss in ape_main_get) so the make_tag fallback engages.
  #[test]
  fn key_to_static_lookup_falls_through_for_dynamic_keys() {
    assert_eq!(key_to_static_lookup("Album"), "Album");
    assert_eq!(key_to_static_lookup("Tool Version"), "Tool Version");
    assert_eq!(key_to_static_lookup("DURATION"), "DURATION");
    // Dynamic keys ⇒ "".
    assert_eq!(key_to_static_lookup("Cover Art (Front)"), "");
    assert_eq!(key_to_static_lookup("Media Jukebox Date"), "");
    // Empty lookup never matches ape_main_get arms.
    assert!((APE_MAIN.get())(TagId::Str("")).is_none());
  }

  // APE.pm:181-194 + APE.pm:238 (Codex r1 finding 1): when the APETAGEX
  // header is FOUND but its declared size has the high bit set OR the
  // implied body can't fit in the file, Perl sets `$count = -1` and the
  // post-loop `$i == $count` check fails ⇒ `Warn('Bad APE trailer')`.
  #[test]
  fn invalid_apetagex_size_high_bit_emits_warn() {
    // 32-byte file: starts with APETAGEX (so header_at_start path);
    // size field (bytes 12..16, LE) has bit 31 set ⇒ HeaderInvalid.
    let mut data = [0u8; 32];
    data[..8].copy_from_slice(b"APETAGEX");
    // version, then size = 0x80000000.
    data[12..16].copy_from_slice(&0x8000_0000_u32.to_le_bytes());
    let mut m = crate::value::Metadata::new("x");
    let mut c = ParseContext::new(&data, "APE", 0, "APE", None, true, &mut m);
    assert!(ProcessApe.process(&mut c));
    // Bundled-ExifTool behaviour: File:* tags present + ExifTool:Warning.
    assert!(m.tags().iter().any(|t| t.name() == "FileType"));
    assert!(m.warnings().iter().any(|w| w.as_str() == "Bad APE trailer"));
  }

  // Footer present, declared body size exceeds available bytes ⇒
  // APE.pm:182 `$raf->Seek(-$size-32, 1) or $raf->Read(...) == $size`
  // fails ⇒ `$count = -1` ⇒ Warn fires.
  #[test]
  fn footer_too_large_body_emits_warn() {
    // 64-byte file: arbitrary 32 leading bytes (not MAC/APETAGEX-magic at
    // start, but starts with APETAGEX so the header-at-start path runs
    // — we want the footer path, so start with MAC and put APETAGEX at
    // the very end with body_size > 32).
    let mut data = vec![0u8; 64];
    data[..4].copy_from_slice(b"MAC ");
    // ver field at byte 4 — make vers > 3970 so NewHeader path runs but
    // bails out (dlen/hlen 0 ⇒ no body).
    data[4..6].copy_from_slice(&5000u16.to_le_bytes());
    // Footer at data[32..64]: APETAGEX with size_raw = 1024 (much larger
    // than the 32 bytes available before the footer).
    data[32..40].copy_from_slice(b"APETAGEX");
    data[32 + 12..32 + 16].copy_from_slice(&1024u32.to_le_bytes());
    let mut m = crate::value::Metadata::new("x");
    let mut c = ParseContext::new(&data, "APE", 0, "APE", None, true, &mut m);
    assert!(ProcessApe.process(&mut c));
    assert!(m.warnings().iter().any(|w| w.as_str() == "Bad APE trailer"));
  }

  // Codex r2 finding 2: APE.pm:180-181 `$size -= 32` is SIGNED Perl
  // arithmetic. `size_raw < 32` ⇒ $size becomes a negative IV. Perl's
  // bitwise `&` coerces negative IVs to UV (low 64 bits, two's-comp)
  // which always has bit 31 set ⇒ `($size & 0x80000000) == 0` is false
  // ⇒ `$count = -1` ⇒ `$i == $count` (0 == -1) ⇒ Warn fires. Our port
  // must trigger HeaderInvalid for `size_raw < 32` even when the
  // declared count is 0 (which would otherwise leave n_consumed ==
  // count == 0 and miss the warning).
  #[test]
  fn apetagex_size_below_32_emits_warn_even_count_zero() {
    // header_at_start path: APETAGEX magic, size_raw = 10 (< 32),
    // count = 0. Expect HeaderInvalid ⇒ Bad APE trailer warning.
    let mut data = [0u8; 32];
    data[..8].copy_from_slice(b"APETAGEX");
    data[12..16].copy_from_slice(&10u32.to_le_bytes()); // size_raw < 32
    data[16..20].copy_from_slice(&0u32.to_le_bytes()); // count = 0
    let mut m = crate::value::Metadata::new("x");
    let mut c = ParseContext::new(&data, "APE", 0, "APE", None, true, &mut m);
    assert!(ProcessApe.process(&mut c));
    assert!(
      m.warnings().iter().any(|w| w.as_str() == "Bad APE trailer"),
      "size_raw < 32 must trigger Bad APE trailer warning (APE.pm:180-181 signed arith)"
    );
  }

  // Same APE.pm:180-181 logic on the footer path. A MAC-prefix file with
  // a trailing APETAGEX whose size_raw < 32 must trigger HeaderInvalid.
  #[test]
  fn footer_size_below_32_emits_warn() {
    let mut data = vec![0u8; 64];
    data[..4].copy_from_slice(b"MAC ");
    data[4..6].copy_from_slice(&5000u16.to_le_bytes()); // NewHeader path
    // Footer at data[32..64] — APETAGEX with size_raw = 5.
    data[32..40].copy_from_slice(b"APETAGEX");
    data[32 + 12..32 + 16].copy_from_slice(&5u32.to_le_bytes());
    data[32 + 16..32 + 20].copy_from_slice(&0u32.to_le_bytes());
    let mut m = crate::value::Metadata::new("x");
    let mut c = ParseContext::new(&data, "APE", 0, "APE", None, true, &mut m);
    assert!(ProcessApe.process(&mut c));
    assert!(m.warnings().iter().any(|w| w.as_str() == "Bad APE trailer"));
  }

  // Codex r14 + r15: APE.pm subtracts 32 FIRST, then checks bit 31 on
  // the post-subtract value. Pin the EXACT mapping of the
  // `decode_apetagex_body_size` helper so a regression that re-applies
  // the bit-31 check to the RAW (pre-subtract) value is caught — the
  // earlier integration-level test was non-discriminating because both
  // the old (incorrect) and new (correct) implementations produce the
  // same `Bad APE trailer` warning on a small fixture (the accepted
  // body_size cannot fit in 32 bytes, so a short-read failure also
  // routes to HeaderInvalid). Boundary cases empirically verified
  // against Perl APE.pm:180-181 signed arithmetic.
  #[test]
  fn decode_apetagex_body_size_boundary_mapping() {
    // Accepted: post-subtract bit 31 unset.
    assert_eq!(decode_apetagex_body_size(32), Some(0));
    assert_eq!(decode_apetagex_body_size(33), Some(1));
    assert_eq!(decode_apetagex_body_size(0x7fff_ffff), Some(0x7fff_ffdf));
    // The R14-critical accepted range: bit 31 set on RAW, unset
    // post-subtract. Earlier code rejected these incorrectly.
    assert_eq!(decode_apetagex_body_size(0x8000_0000), Some(0x7fff_ffe0));
    assert_eq!(decode_apetagex_body_size(0x8000_0001), Some(0x7fff_ffe1));
    assert_eq!(decode_apetagex_body_size(0x8000_001f), Some(0x7fff_ffff));
    // Rejected: post-subtract bit 31 set.
    assert_eq!(decode_apetagex_body_size(0x8000_0020), None);
    assert_eq!(decode_apetagex_body_size(0x8000_0021), None);
    assert_eq!(decode_apetagex_body_size(0xffff_ffff), None);
    // Sub-32 values: post-subtract wraps negative ⇒ bit 31 set ⇒ rejected.
    assert_eq!(decode_apetagex_body_size(0), None);
    assert_eq!(decode_apetagex_body_size(1), None);
    assert_eq!(decode_apetagex_body_size(0x1f), None);
  }

  // Integration coverage: confirm the process path still emits
  // `Bad APE trailer` on a 32-byte fixture for both rejection paths
  // (bit-31 guard AND short-read), keeping the user-visible warning
  // semantics intact.
  #[test]
  fn apetagex_process_warns_on_invalid_sizes_small_fixture() {
    fn run(size_raw: u32) -> Vec<String> {
      let mut data = vec![0u8; 32];
      data[..8].copy_from_slice(b"APETAGEX");
      data[12..16].copy_from_slice(&size_raw.to_le_bytes());
      data[16..20].copy_from_slice(&0u32.to_le_bytes()); // count = 0
      let mut m = crate::value::Metadata::new("x");
      let mut c = ParseContext::new(&data, "APE", 0, "APE", None, true, &mut m);
      ProcessApe.process(&mut c);
      m.warnings()
        .iter()
        .map(|s| s.as_str().to_string())
        .collect()
    }
    // Bit-31-rejected raws.
    assert!(run(0x8000_0020).iter().any(|w| w == "Bad APE trailer"));
    assert!(run(0xffff_ffff).iter().any(|w| w == "Bad APE trailer"));
    // Bit-31-accepted but body unreadable in 32B fixture ⇒ HeaderInvalid
    // via short-read path.
    assert!(run(0x8000_0000).iter().any(|w| w == "Bad APE trailer"));
    assert!(run(0x8000_001f).iter().any(|w| w == "Bad APE trailer"));
    assert!(run(0x7fff_ffff).iter().any(|w| w == "Bad APE trailer"));
    // Sub-32 values.
    assert!(run(0x1f).iter().any(|w| w == "Bad APE trailer"));
    // Exact-32: body_size==0; count==0 ⇒ silent (APE.pm:172 path).
    let w32 = run(32);
    assert!(
      !w32.iter().any(|w| w == "Bad APE trailer"),
      "raw=32 (body_size=0, count=0) must NOT emit warning, got: {:?}",
      w32
    );
  }

  // Codex r2 finding 1: APE.pm:220 `s/^([\x20-\x7e]*)\0//` ALWAYS runs
  // its substitution when the regex matches; only the Desc-tag emission
  // is gated on `if ($1)` (Perl-truthy: non-empty AND not literal "0").
  //
  // - Truthy capture (e.g. "Foo\0...") ⇒ Desc tag emitted; binary value =
  //   bytes AFTER the NUL.
  // - Falsey capture (empty "\0..." or literal "0\0...") ⇒ NO Desc tag,
  //   but the strip still applies; binary value = bytes AFTER the NUL.
  // - Regex no-match (no NUL after printable run) ⇒ value unchanged.
  //
  // Build a minimal APETAGEX-at-start fixture carrying ONE binary tag
  // named "Cover Art (Front)" so the carve-out fires.
  fn build_single_tag_apetagex(key: &str, value: &[u8], flags: u32) -> Vec<u8> {
    // APE tag stream entry layout: 4B len (LE) | 4B flags (LE) |
    //   NUL-terminated key | value bytes.
    let key_bytes = key.as_bytes();
    let mut entry = Vec::new();
    entry.extend_from_slice(&(value.len() as u32).to_le_bytes());
    entry.extend_from_slice(&flags.to_le_bytes());
    entry.extend_from_slice(key_bytes);
    entry.push(0);
    entry.extend_from_slice(value);
    // 32-byte APETAGEX header: 8B magic + 4B ver + 4B size + 4B count +
    //   4B flags + 8B reserved.
    let body_size = entry.len();
    let total_size = body_size + 32; // includes the 32 header bytes.
    let mut data = Vec::new();
    data.extend_from_slice(b"APETAGEX"); // magic
    data.extend_from_slice(&2000u32.to_le_bytes()); // version
    data.extend_from_slice(&(total_size as u32).to_le_bytes()); // size
    data.extend_from_slice(&1u32.to_le_bytes()); // count = 1
    data.extend_from_slice(&0u32.to_le_bytes()); // flags
    data.extend_from_slice(&[0u8; 8]); // reserved
    debug_assert_eq!(data.len(), 32);
    data.extend_from_slice(&entry);
    data
  }

  #[test]
  fn cover_art_falsey_desc_strips_anyway() {
    // Empty Desc: value starts with NUL, then "BINARY".
    // - APE.pm:220 strips the leading "\0" ⇒ binary value = "BINARY".
    // - APE.pm:221 `if ($1)` is FALSE (empty $1 ≡ falsey) ⇒ NO Desc tag.
    let value = b"\0BINARY";
    // flags = 0x02 ⇒ binary tag (per APE.pm:214 `($flags & 0x06) == 0x02`).
    let data = build_single_tag_apetagex("Cover Art (Front)", value, 0x02);
    let mut m = crate::value::Metadata::new("x");
    let mut c = ParseContext::new(&data, "APE", 0, "APE", None, true, &mut m);
    assert!(ProcessApe.process(&mut c));
    // Locate the cover-art tag.
    let cover = m
      .tags()
      .iter()
      .find(|t| t.name() == "CoverArtFront")
      .expect("CoverArtFront tag");
    // Binary value MUST be "BINARY" (6 bytes), not "\0BINARY" (7 bytes).
    match cover.value() {
      TagValue::Bytes(b) => {
        assert_eq!(b.as_slice(), b"BINARY", "leading \\0 must be stripped");
        assert_eq!(b.len(), 6);
      }
      other => panic!("expected Bytes, got {other:?}"),
    }
    // NO Desc tag for an empty (falsey) description.
    assert!(
      !m.tags().iter().any(|t| t.name() == "CoverArtFrontDesc"),
      "empty Desc is falsey ⇒ no Desc tag"
    );
  }

  #[test]
  fn cover_art_literal_zero_desc_strips_no_desc_tag() {
    // Perl-falsey value: "0\0BINARY". $1 == "0" ⇒ falsey under Perl
    // boolean coercion ⇒ NO Desc tag. But strip still happens.
    let value = b"0\0BINARY";
    let data = build_single_tag_apetagex("Cover Art (Front)", value, 0x02);
    let mut m = crate::value::Metadata::new("x");
    let mut c = ParseContext::new(&data, "APE", 0, "APE", None, true, &mut m);
    assert!(ProcessApe.process(&mut c));
    let cover = m
      .tags()
      .iter()
      .find(|t| t.name() == "CoverArtFront")
      .expect("CoverArtFront tag");
    match cover.value() {
      TagValue::Bytes(b) => assert_eq!(b.as_slice(), b"BINARY"),
      other => panic!("expected Bytes, got {other:?}"),
    }
    assert!(!m.tags().iter().any(|t| t.name() == "CoverArtFrontDesc"));
  }

  #[test]
  fn cover_art_truthy_desc_strips_and_emits_desc_tag() {
    // Truthy Desc: "Foo\0BINARY". $1 = "Foo".
    let value = b"Foo\0BINARY";
    let data = build_single_tag_apetagex("Cover Art (Front)", value, 0x02);
    let mut m = crate::value::Metadata::new("x");
    let mut c = ParseContext::new(&data, "APE", 0, "APE", None, true, &mut m);
    assert!(ProcessApe.process(&mut c));
    let desc = m
      .tags()
      .iter()
      .find(|t| t.name() == "CoverArtFrontDesc")
      .expect("CoverArtFrontDesc tag");
    assert_eq!(desc.value(), &TagValue::Str("Foo".into()));
    let cover = m
      .tags()
      .iter()
      .find(|t| t.name() == "CoverArtFront")
      .expect("CoverArtFront tag");
    match cover.value() {
      TagValue::Bytes(b) => assert_eq!(b.as_slice(), b"BINARY"),
      other => panic!("expected Bytes, got {other:?}"),
    }
    // Desc tag MUST appear BEFORE the CoverArtFront tag (APE.pm:225
    // HandleTag is INSIDE the if-binary block BEFORE the outer
    // HandleTag at APE.pm:229).
    let desc_idx = m
      .tags()
      .iter()
      .position(|t| t.name() == "CoverArtFrontDesc");
    let cover_idx = m.tags().iter().position(|t| t.name() == "CoverArtFront");
    assert!(desc_idx < cover_idx);
  }

  // Codex r14 finding: APE.pm:118 docstring + APE.pm:136 `unless
  // ($$et{FileType})` — when ProcessAPE is called AFTER another parser
  // already typed the file, the magic check + SetFileType + binary-
  // header block (APE.pm:137-162) is skipped; only the APETAGEX-
  // trailer scan runs. Today's engine dispatches one parser per file,
  // so this path is unreachable from production code; we expose
  // `plan_ape_trailer_only` as a `#[cfg(test)]`-gated seam so the
  // behaviour is correctness-pinned for future chained-parser use
  // (ID3-then-APE on MP3, MPC-then-APE, WavPack-then-APE).
  #[test]
  fn trailer_only_plan_extracts_apetagex_without_magic_header() {
    // Build a payload that does NOT start with `MAC ` / `APETAGEX` — a
    // chained-parser scenario where some prior parser (e.g. MP3) read
    // the file's beginning and we follow up looking only at the trailer.
    // Place a real APETAGEX trailer at EOF with two tags.
    let mut data = Vec::new();
    // 64 bytes of "non-APE prefix" (would normally be MP3 frames etc.).
    data.extend_from_slice(&[0xff; 64]);
    // APETAGEX trailer at EOF.
    fn tag_entry(key: &str, value: &[u8]) -> Vec<u8> {
      let mut e = Vec::new();
      e.extend_from_slice(&(value.len() as u32).to_le_bytes());
      e.extend_from_slice(&0u32.to_le_bytes()); // flags
      e.extend_from_slice(key.as_bytes());
      e.push(0);
      e.extend_from_slice(value);
      e
    }
    let entries = {
      let mut e = Vec::new();
      e.extend_from_slice(&tag_entry("Title", b"Trailer-Only Title"));
      e.extend_from_slice(&tag_entry("Artist", b"Trailer-Only Artist"));
      e
    };
    let size = (entries.len() + 32) as u32;
    data.extend_from_slice(&entries);
    data.extend_from_slice(b"APETAGEX");
    data.extend_from_slice(&2000u32.to_le_bytes()); // version
    data.extend_from_slice(&size.to_le_bytes()); // size
    data.extend_from_slice(&2u32.to_le_bytes()); // count
    data.extend_from_slice(&0u32.to_le_bytes()); // flags
    data.extend_from_slice(&[0u8; 8]); // reserved
    // Run the trailer-only planner.
    let plan = plan_ape_trailer_only(&data, true, 0).expect("trailer-only plan returns Some");
    // header_job is None (the prior parser owns the File:*/header tags).
    assert!(matches!(plan.header_job, HeaderJob::None));
    // No 'Bad APE trailer' warning (the trailer is valid).
    assert!(!plan.warn_bad_trailer);
    // Two pending tags, in extraction order.
    assert_eq!(plan.pending.len(), 2);
    assert_eq!(plan.pending[0].1, "Title");
    assert_eq!(plan.pending[1].1, "Artist");
    // Values come from the wire (post-MakeTag, post-ValueConv ⇒ Str).
    match &plan.pending[0].2 {
      TagValue::Str(s) => assert_eq!(s.as_str(), "Trailer-Only Title"),
      other => panic!("expected Str(Title), got {:?}", other),
    }
  }

  // Trailer-only on a payload with NO APETAGEX trailer ⇒ silent (faithful
  // to APE.pm:172 `return 1` ⇒ no Warn, empty pending).
  #[test]
  fn trailer_only_plan_no_trailer_is_silent() {
    let data = vec![0u8; 100]; // arbitrary bytes, no APETAGEX
    let plan = plan_ape_trailer_only(&data, true, 0).expect("trailer-only plan returns Some");
    assert!(plan.pending.is_empty());
    assert!(!plan.warn_bad_trailer);
    assert!(matches!(plan.header_job, HeaderJob::None));
  }

  // Trailer-only on a payload shorter than 32 bytes ⇒ silent (faithful
  // to APE.pm:171 `$raf->Read($buff, 32) == 32 or return 1`).
  #[test]
  fn trailer_only_plan_short_data_is_silent() {
    let data = vec![0u8; 10];
    let plan = plan_ape_trailer_only(&data, true, 0).expect("trailer-only plan returns Some");
    assert!(plan.pending.is_empty());
    assert!(!plan.warn_bad_trailer);
  }

  // Codex r15 finding: pin the PRODUCTION ENTRY-POINT boundary of
  // `ProcessApe::process_trailer_only` (the chained-parser follow-on
  // method). Pre-populate metadata with a File:* triplet (simulating a
  // prior parser that already typed the file), then invoke
  // process_trailer_only and confirm the wire-format APE-tag-trailer is
  // extracted as expected, without touching File:* or emitting any
  // header tags.
  #[test]
  fn process_trailer_only_chained_parser_boundary() {
    use crate::value::Group;
    // Simulate a prior parser that ran SetFileType('MP3').
    let mut m = crate::value::Metadata::new("x");
    m.push(
      Group::new("File", "File"),
      "FileType",
      TagValue::Str("MP3".into()),
    );
    m.push(
      Group::new("File", "File"),
      "FileTypeExtension",
      TagValue::Str("mp3".into()),
    );
    m.push(
      Group::new("File", "File"),
      "MIMEType",
      TagValue::Str("audio/mpeg".into()),
    );

    // Build payload: 64 bytes of "MP3 frames" + APETAGEX trailer.
    let mut data = Vec::new();
    data.extend_from_slice(&[0xff; 64]);
    fn tag_entry(key: &str, value: &[u8]) -> Vec<u8> {
      let mut e = Vec::new();
      e.extend_from_slice(&(value.len() as u32).to_le_bytes());
      e.extend_from_slice(&0u32.to_le_bytes());
      e.extend_from_slice(key.as_bytes());
      e.push(0);
      e.extend_from_slice(value);
      e
    }
    let mut entries = Vec::new();
    entries.extend_from_slice(&tag_entry("Title", b"Chained Title"));
    entries.extend_from_slice(&tag_entry("Artist", b"Chained Artist"));
    let size = (entries.len() + 32) as u32;
    data.extend_from_slice(&entries);
    data.extend_from_slice(b"APETAGEX");
    data.extend_from_slice(&2000u32.to_le_bytes());
    data.extend_from_slice(&size.to_le_bytes());
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&[0u8; 8]);

    let n_before = m.tags().len();
    let mut c = ParseContext::new(&data, "MP3", 0, "MP3", None, true, &mut m);
    assert!(ProcessApe.process_trailer_only(&mut c));
    let tags = m.tags();
    // File:* preserved (the prior parser owns them).
    assert!(
      tags.iter().any(|t| t.name() == "FileType"
        && t.group().family1() == "File"
        && t.value() == &TagValue::Str("MP3".into())),
      "prior parser's File:FileType=MP3 must be untouched"
    );
    // Two new APE:* tags appended.
    let new_tags: Vec<_> = tags.iter().skip(n_before).collect();
    assert_eq!(new_tags.len(), 2, "exactly two trailer tags appended");
    assert_eq!(new_tags[0].name(), "Title");
    assert_eq!(new_tags[1].name(), "Artist");
    assert_eq!(new_tags[0].group().family1(), "APE");
    assert!(matches!(new_tags[0].value(), TagValue::Str(s) if s.as_str() == "Chained Title"));
    // No 'Bad APE trailer' warning.
    assert!(!m.warnings().iter().any(|w| w.as_str() == "Bad APE trailer"));
  }

  // Codex r16 finding: the trailer-only chained-parser path MUST also
  // run Composite Duration resolution. The wire-format APE trailer can
  // carry the four Require ingredients directly (e.g. via spaced keys
  // like `Sample Rate=48000`). Bundled ExifTool runs `BuildCompositeTags`
  // at the end of ExtractInfo regardless of which parser provided the
  // ingredients; our single-parser engine emits composites at the end
  // of `process*`. Pin that process_trailer_only invokes the shared
  // `emit_composite_duration_if_present` helper.
  #[test]
  fn process_trailer_only_emits_composite_when_ingredients_in_trailer() {
    use crate::value::Group;
    let mut m = crate::value::Metadata::new("x");
    // Simulate prior MP3 parser.
    m.push(
      Group::new("File", "File"),
      "FileType",
      TagValue::Str("MP3".into()),
    );

    fn tag_entry(key: &str, value: &[u8]) -> Vec<u8> {
      let mut e = Vec::new();
      e.extend_from_slice(&(value.len() as u32).to_le_bytes());
      e.extend_from_slice(&0u32.to_le_bytes()); // flags
      e.extend_from_slice(key.as_bytes());
      e.push(0);
      e.extend_from_slice(value);
      e
    }
    // Build the four Composite ingredients (with SPACES so MakeTag
    // produces CamelCase that matches the Require names).
    let mut entries = Vec::new();
    entries.extend_from_slice(&tag_entry("Sample Rate", b"48000"));
    entries.extend_from_slice(&tag_entry("Total Frames", b"10"));
    entries.extend_from_slice(&tag_entry("Blocks Per Frame", b"73728"));
    entries.extend_from_slice(&tag_entry("Final Frame Blocks", b"42662"));
    let size = (entries.len() + 32) as u32;
    let mut data = Vec::new();
    data.extend_from_slice(&[0xff; 64]); // MP3-frame stand-in
    data.extend_from_slice(&entries);
    data.extend_from_slice(b"APETAGEX");
    data.extend_from_slice(&2000u32.to_le_bytes());
    data.extend_from_slice(&size.to_le_bytes());
    data.extend_from_slice(&4u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&[0u8; 8]);

    let mut c = ParseContext::new(&data, "MP3", 0, "MP3", None, true, &mut m);
    assert!(ProcessApe.process_trailer_only(&mut c));
    // Composite:Duration MUST be present (14.71 s, as in the standalone
    // APE_spaced_composite fixture — same arithmetic, same PrintConv).
    let comp = m
      .tags()
      .iter()
      .find(|t| t.name() == "Duration" && t.group().family0() == "Composite")
      .expect("Composite:Duration from trailer-only chained call");
    match comp.value() {
      TagValue::Str(s) => assert_eq!(s.as_str(), "14.71 s"),
      other => panic!("expected Str composite, got {:?}", other),
    }
  }

  // APE.pm:172: `$buff =~ /^APETAGEX/ or return 1` — no trailer at EOF ⇒
  // silent return (no Warn). Faithful: a MAC-prefix file without a
  // trailing APETAGEX yields File:* + MAC tags but no Bad APE warning.
  #[test]
  fn no_footer_is_silent_no_warn() {
    // MAC header + NewHeader body fully zeroed; no APETAGEX trailer.
    let mut data = vec![0u8; 64];
    data[..4].copy_from_slice(b"MAC ");
    // Version 3990 (NewHeader). dlen=hlen=0 ⇒ NewHeader path bails out
    // (no body), still falls through to the footer scan — which then
    // finds NO APETAGEX at the end.
    data[4..6].copy_from_slice(&3990u16.to_le_bytes());
    let mut m = crate::value::Metadata::new("x");
    let mut c = ParseContext::new(&data, "APE", 0, "APE", None, true, &mut m);
    assert!(ProcessApe.process(&mut c));
    // File:* tags must exist.
    assert!(m.tags().iter().any(|t| t.name() == "FileType"));
    // NO 'Bad APE trailer' warning (faithful APE.pm:172 silent return).
    assert!(
      !m.warnings().iter().any(|w| w.as_str() == "Bad APE trailer"),
      "no-trailer path must be silent (APE.pm:172 `return 1`)"
    );
  }

  // Codex r5 finding: Composite Duration's `Require => 'APE:Name'`
  // resolves against ANY tag whose family-0 is `APE` (the GroupMatches
  // rule, ExifTool.pm:5207-5246). Earlier code hardcoded family-1=MAC,
  // which would miss a SampleRate tag emitted by the Main table (group1
  // would be APE, not MAC). Test by INJECTING a fake "SampleRate"
  // (group1=APE) via Metadata::push directly, then verifying the
  // composite lookup picks it up alongside MAC-sourced TotalFrames etc.
  //
  // NOTE: this is purely a robustness regression — the wire format
  // doesn't actually carry `SampleRate` as an APE key (APE keys are
  // user-facing names like Album/Artist/Year), so the only way to hit
  // this path is by adversarial / synthetic injection. But the resolved
  // FAITHFUL rule is family-0 match.
  #[test]
  fn composite_lookup_resolves_via_family0_apes_not_only_mac() {
    use crate::value::Group;
    let mut m = crate::value::Metadata::new("x");
    // File:FileType etc — pretend SetFileType already ran.
    m.push(
      Group::new("File", "File"),
      "FileType",
      TagValue::Str("APE".into()),
    );
    // Inject the 4 Composite ingredients with family-0=APE but
    // family-1=APE (NOT MAC). Faithful Perl Require would still pick
    // these up because GroupMatches('APE', ...) checks ALL families.
    m.push(
      Group::new(APE_GROUP0, "APE"),
      "SampleRate",
      TagValue::I64(48000),
    );
    m.push(
      Group::new(APE_GROUP0, "APE"),
      "TotalFrames",
      TagValue::I64(10),
    );
    m.push(
      Group::new(APE_GROUP0, "APE"),
      "BlocksPerFrame",
      TagValue::I64(73728),
    );
    m.push(
      Group::new(APE_GROUP0, "APE"),
      "FinalFrameBlocks",
      TagValue::I64(42662),
    );
    // Now feed a minimal APETAGEX-only-with-no-tags input to ProcessApe
    // so the composite block runs against the already-populated metadata.
    let mut data = vec![0u8; 32];
    data[..8].copy_from_slice(b"APETAGEX");
    data[12..16].copy_from_slice(&32u32.to_le_bytes()); // size == 32 ⇒ body_size==0
    data[16..20].copy_from_slice(&0u32.to_le_bytes()); // count == 0
    let mut c = ParseContext::new(&data, "APE", 0, "APE", None, true, &mut m);
    assert!(ProcessApe.process(&mut c));
    // Composite must be present — the family-0 lookup succeeded.
    let comp = m
      .tags()
      .iter()
      .find(|t| t.name() == "Duration" && t.group().family0() == "Composite")
      .expect("Composite:Duration must be emitted via family-0 lookup");
    // Verify it's a sensible duration value: ((10-1)*73728 + 42662)/48000
    // = (663552 + 42662) / 48000 = 706214 / 48000 ≈ 14.71 — which is
    // less than 30 seconds, so ConvertDuration uses the "%.2f s" form
    // (ExifTool.pm:6872), not the h:m:s form.
    if let TagValue::Str(s) = comp.value() {
      assert_eq!(s.as_str(), "14.71 s");
    } else {
      panic!("expected Str composite, got {:?}", comp.value());
    }
  }

  // Codex r8 finding: APE RawConv arithmetic runs Perl numeric coercion
  // on each Composite ingredient ⇒ Str values must be accepted. The
  // wire-format conformance fixture (APE_wire_composite_ingredients.ape)
  // proves Perl does NOT emit a Composite for such inputs because
  // MakeTag's `ucfirst lc` mangles the wire keys to `Samplerate`,
  // `Totalframes`, etc. — not matching the `APE:SampleRate` Require. To
  // exercise the Str-coercion code path itself we must inject tags with
  // the CANONICAL ingredient names via Metadata::push (bypassing
  // MakeTag); the lookup then finds them with Str values and Perl-coerces.
  #[test]
  fn composite_lookup_accepts_str_ingredients_perl_coerce() {
    use crate::value::Group;
    let mut m = crate::value::Metadata::new("x");
    m.push(
      Group::new("File", "File"),
      "FileType",
      TagValue::Str("APE".into()),
    );
    // String-valued ingredients — Perl numeric coercion via the lookup
    // closure must yield the same arithmetic as I64 variants.
    m.push(
      Group::new(APE_GROUP0, "APE"),
      "SampleRate",
      TagValue::Str("48000".into()),
    );
    m.push(
      Group::new(APE_GROUP0, "APE"),
      "TotalFrames",
      TagValue::Str("10".into()),
    );
    m.push(
      Group::new(APE_GROUP0, "APE"),
      "BlocksPerFrame",
      TagValue::Str("73728".into()),
    );
    m.push(
      Group::new(APE_GROUP0, "APE"),
      "FinalFrameBlocks",
      TagValue::Str("42662".into()),
    );
    // Drive ProcessApe with a minimal APETAGEX header carrying no tag-
    // stream entries so the composite block runs against pre-populated m.
    let mut data = vec![0u8; 32];
    data[..8].copy_from_slice(b"APETAGEX");
    data[12..16].copy_from_slice(&32u32.to_le_bytes());
    data[16..20].copy_from_slice(&0u32.to_le_bytes());
    let mut c = ParseContext::new(&data, "APE", 0, "APE", None, true, &mut m);
    assert!(ProcessApe.process(&mut c));
    // Same arithmetic as the I64-only test: (10-1)*73728+42662 = 706214;
    // /48000 = 14.71... ⇒ ConvertDuration's `%.2f s` form.
    let comp = m
      .tags()
      .iter()
      .find(|t| t.name() == "Duration" && t.group().family0() == "Composite")
      .expect("Composite:Duration from Str ingredients");
    match comp.value() {
      TagValue::Str(s) => assert_eq!(s.as_str(), "14.71 s"),
      other => panic!("expected Str composite, got {:?}", other),
    }
  }

  // Codex r10 finding: ConvertDuration must handle huge finite values
  // by keeping the arithmetic in f64 (NV-style) and stringifying the
  // out-of-IV components via Perl's default NV stringify (`%.15g`).
  // perl_nv_str / perl_int_str_padded are the helpers; tests below pin
  // the empirically-verified Perl behaviour.
  #[test]
  fn perl_nv_str_matches_perl_default_stringify() {
    // Finite integers in safe IV range ⇒ exact decimal (matches Perl
    // `print 1e10 . "\n"` ⇒ `10000000000`).
    assert_eq!(perl_nv_str(0.0), "0");
    assert_eq!(perl_nv_str(42.0), "42");
    assert_eq!(perl_nv_str(1.0e10), "10000000000");
    assert_eq!(perl_nv_str(1.0e15), "1000000000000000");
    // Negative integer in safe IV range.
    assert_eq!(perl_nv_str(-42.0), "-42");
    // Outside IV range ⇒ Perl `%.15g` (e.g. `1e25/24/3600` ≈ 1.157e+20).
    assert_eq!(perl_nv_str(1.0e25 / 24.0 / 3600.0), "1.15740740740741e+20");
    assert_eq!(perl_nv_str(1.0e25), "1e+25");
    // Fractional values use `%.15g`.
    assert_eq!(perl_nv_str(2.5), "2.5");
    // Special values.
    assert_eq!(perl_nv_str(f64::INFINITY), "Inf");
    assert_eq!(perl_nv_str(f64::NEG_INFINITY), "-Inf");
    assert_eq!(perl_nv_str(f64::NAN), "NaN");
    // Codex r11 finding: positive integer-valued f64 in
    // (i64::MAX, u64::MAX] must stringify as DECIMAL (Perl's UV path),
    // NOT scientific. Boundary cases empirically verified against
    // Perl 5:
    //   int(1e19) ⇒ "10000000000000000000"
    //   int(1.5e19) ⇒ "15000000000000000000"
    //   int(2^64-2048) ⇒ "18446744073709549568" (largest representable
    //     f64 below 2^64)
    //   int(2^64) ⇒ "1.84467440737096e+19" (next representable f64,
    //     scientific because > u64::MAX)
    assert_eq!(perl_nv_str(1.0e19), "10000000000000000000");
    assert_eq!(perl_nv_str(1.5e19), "15000000000000000000");
    // 2^64 - 2048 = 18446744073709549568 (representable in f64).
    assert_eq!(perl_nv_str(18446744073709549568.0), "18446744073709549568");
    // 2^64 (the f64 representation of u64::MAX+1) ⇒ scientific.
    // Note: `18446744073709551616.0_f64 == u64::MAX as f64` in Rust.
    let two64 = (1u128 << 64) as f64;
    assert_eq!(perl_nv_str(two64), "1.84467440737096e+19");
    // The duration helper's worst-case path: 8.64e23 → days = 1e19.
    // perl_nv_str(1e19) → "10000000000000000000" (decimal).
    let days_at_864e23 = (8.64e23_f64 / 3600.0 / 24.0).trunc();
    // Expected exact value (matches Perl `int(8.64e23/86400)`):
    assert_eq!(perl_nv_str(days_at_864e23), "10000000000000002048");
    // Codex r12 finding: `i64::MAX as f64` actually equals 2^63 because
    // i64::MAX (2^63 - 1) is not exactly representable in f64; the cast
    // rounds UP. So `n = 9223372036854775808.0` (exactly 2^63) must
    // stringify via the UV path as `"9223372036854775808"`, NOT via the
    // signed path's saturating `"9223372036854775807"`. Boundary
    // verified against Perl 5: `int(9223372036854775808.0) ⇒
    // "9223372036854775808"`. Largest representable f64 strictly below
    // 2^63 is `2^63 - 1024 = 9223372036854774784.0`.
    let two63 = (1u128 << 63) as f64;
    assert_eq!(perl_nv_str(two63), "9223372036854775808");
    // 2^63 - 1024 (representable as f64) goes via signed path.
    assert_eq!(perl_nv_str(9223372036854774784.0), "9223372036854774784");
  }

  #[test]
  fn perl_int_str_padded_in_range_pads_with_zeros() {
    // ConvertDuration's m/s values are always in [0, 60) when reached
    // via the normal path, so `%02d` zero-pads exactly.
    assert_eq!(perl_int_str_padded(0.0, 2), "00");
    assert_eq!(perl_int_str_padded(5.0, 2), "05");
    assert_eq!(perl_int_str_padded(59.0, 2), "59");
    // Boundary: i64::MAX as f64 is in-range — emits exact decimal padded
    // (though the value vastly exceeds width=2, format! just emits the
    // full number).
    assert_eq!(perl_int_str_padded(100.0, 2), "100");
    // Out-of-range or fractional ⇒ fall through to perl_nv_str.
    assert_eq!(perl_int_str_padded(f64::INFINITY, 2), "Inf");
    assert_eq!(perl_int_str_padded(1.5, 2), "1.5");
  }

  // Codex r11 finding: Perl boolean truthiness for `if ($val[0] &&
  // $val[1])` in the Composite Duration RawConv must use STRING-truthy
  // rules when the ingredient is a Str (e.g. wire-format `Sample Rate =
  // "0.0"` ⇒ Perl-truthy because the string is non-empty AND not
  // literal `"0"`), NOT a coerced-to-numeric-zero check. Empirically
  // verified against Perl 5 (see Bash transcript in the Codex r11 fix).
  #[test]
  fn composite_perl_boolean_truthiness_unit() {
    use crate::value::{Rational, TagValue};
    // String truthiness: non-empty AND not "0".
    assert!(!perl_boolean_truthy(&TagValue::Str("0".into())));
    assert!(!perl_boolean_truthy(&TagValue::Str("".into())));
    assert!(perl_boolean_truthy(&TagValue::Str("0.0".into())));
    assert!(perl_boolean_truthy(&TagValue::Str("0E0".into())));
    assert!(perl_boolean_truthy(&TagValue::Str("00".into())));
    assert!(perl_boolean_truthy(&TagValue::Str("+0".into())));
    assert!(perl_boolean_truthy(&TagValue::Str("-0".into())));
    assert!(perl_boolean_truthy(&TagValue::Str(" 0".into())));
    assert!(perl_boolean_truthy(&TagValue::Str("0abc".into())));
    assert!(perl_boolean_truthy(&TagValue::Str("hello".into())));
    // Numeric: false iff == 0.
    assert!(!perl_boolean_truthy(&TagValue::I64(0)));
    assert!(perl_boolean_truthy(&TagValue::I64(1)));
    assert!(perl_boolean_truthy(&TagValue::I64(-1)));
    #[allow(clippy::approx_constant)] // intentional 0.0 vs nonzero compare
    {
      assert!(!perl_boolean_truthy(&TagValue::F64(0.0)));
      assert!(!perl_boolean_truthy(&TagValue::F64(-0.0)));
      assert!(perl_boolean_truthy(&TagValue::F64(1.0)));
      assert!(perl_boolean_truthy(&TagValue::F64(-1.0)));
    }
    // NaN: TRUE (Perl semantics: NaN is truthy).
    assert!(perl_boolean_truthy(&TagValue::F64(f64::NAN)));
    // Inf: TRUE.
    assert!(perl_boolean_truthy(&TagValue::F64(f64::INFINITY)));
    // Bool: direct mapping.
    assert!(!perl_boolean_truthy(&TagValue::Bool(false)));
    assert!(perl_boolean_truthy(&TagValue::Bool(true)));
    // Bytes: byte-faithful to the string rule.
    assert!(!perl_boolean_truthy(&TagValue::Bytes(vec![])));
    assert!(!perl_boolean_truthy(&TagValue::Bytes(b"0".to_vec())));
    assert!(perl_boolean_truthy(&TagValue::Bytes(b"00".to_vec())));
    // Rational: numerator truthy.
    assert!(!perl_boolean_truthy(&TagValue::Rational(
      Rational::rational32(0, 1)
    )));
    assert!(perl_boolean_truthy(&TagValue::Rational(
      Rational::rational32(1, 1)
    )));
    // List: count truthy.
    assert!(!perl_boolean_truthy(&TagValue::List(vec![])));
    assert!(perl_boolean_truthy(&TagValue::List(vec![TagValue::I64(0)])));
  }

  // ConvertDuration on huge finite values must use the NV-arithmetic
  // path; the days carve-out's `$d` interpolates via perl_nv_str
  // (matches Perl empirically).
  #[test]
  fn convert_duration_huge_finite_matches_perl_nv_stringify() {
    // 1e25 seconds: `$h = int(1e25 / 3600) ≈ 2.78e+21`; `$d = int($h/24)
    // ≈ 1.157e+20`; remaining h = 0 (NV math: $h -= $d*24 → ~0 due to
    // precision); m, s = 0. Perl output: `1.15740740740741e+20 days 0:00:00`.
    assert_eq!(
      convert_duration(&TagValue::F64(1.0e25)),
      TagValue::Str("1.15740740740741e+20 days 0:00:00".into())
    );
    // 1e18 seconds: in-IV-range path, exact decimal.
    // h = 1e18/3600 = 277777777777777 days ≈ 11574074074074 days remainder
    // 1:46:56 (matches Perl: `11574074074074 days 1:46:56`).
    assert_eq!(
      convert_duration(&TagValue::F64(1.0e18)),
      TagValue::Str("11574074074074 days 1:46:56".into())
    );
    // 1e9 seconds: 11574 days 1:46:40.
    assert_eq!(
      convert_duration(&TagValue::F64(1.0e9)),
      TagValue::Str("11574 days 1:46:40".into())
    );
  }

  // -------------------------------------------------------------------------
  // Codex r6 finding 2: Perl numeric coercion accepts Inf/Infinity/NaN
  // tokens (case-insensitive, optional sign). The Rust port must recognize
  // these AND emit Perl-stringified form ("Inf"/"-Inf"/"NaN") through the
  // value-conv pipeline, not collapse them to 0.0/"0 s".
  // -------------------------------------------------------------------------
  #[test]
  fn perl_numeric_coerce_f64_recognizes_inf_nan() {
    // Cases empirically verified against Perl 5: `<token> + 0` =>
    //   Inf/Infinity/INF/inf       → +Inf
    //   +Inf                       → +Inf
    //   -Inf, -Infinity            → -Inf
    //   NaN/nan/NAN, ±NaN          → NaN (sign is implementation-defined)
    //   InfX, Infi, "Inf abc"      → +Inf (Perl prefix scan)
    //   1e309, -1e309              → ±Inf (overflow)
    //   "  Inf"                    → +Inf (leading whitespace OK)
    assert!(perl_numeric_coerce_f64("Inf").is_infinite());
    assert!(perl_numeric_coerce_f64("Inf").is_sign_positive());
    assert!(perl_numeric_coerce_f64("Infinity").is_infinite());
    assert!(perl_numeric_coerce_f64("INF").is_infinite());
    assert!(perl_numeric_coerce_f64("inf").is_infinite());
    assert!(perl_numeric_coerce_f64("iNf").is_infinite());
    assert!(perl_numeric_coerce_f64("+Inf").is_infinite());
    assert!(perl_numeric_coerce_f64("+Inf").is_sign_positive());
    let neg = perl_numeric_coerce_f64("-Inf");
    assert!(neg.is_infinite() && neg.is_sign_negative());
    let neg2 = perl_numeric_coerce_f64("-Infinity");
    assert!(neg2.is_infinite() && neg2.is_sign_negative());
    assert!(perl_numeric_coerce_f64("NaN").is_nan());
    assert!(perl_numeric_coerce_f64("nan").is_nan());
    assert!(perl_numeric_coerce_f64("NAN").is_nan());
    // Prefix scan: "InfX" / "Infi" / "Inf abc" — still Inf (Perl semantics).
    assert!(perl_numeric_coerce_f64("InfX").is_infinite());
    assert!(perl_numeric_coerce_f64("Infi").is_infinite());
    assert!(perl_numeric_coerce_f64("Inf abc").is_infinite());
    // Overflow: 1e309 parses to f64::INFINITY (matches Perl).
    assert!(perl_numeric_coerce_f64("1e309").is_infinite());
    assert!(perl_numeric_coerce_f64("-1e309").is_sign_negative());
    // Leading whitespace.
    assert!(perl_numeric_coerce_f64("  Inf").is_infinite());
    // Sanity: non-special tokens are unaffected by the new Inf/NaN path.
    assert_eq!(perl_numeric_coerce_f64("42"), 42.0);
    // Avoid `3.14` (clippy::approx_constant — too near std::f64::consts::PI).
    assert_eq!(perl_numeric_coerce_f64("2.5"), 2.5);
    assert_eq!(perl_numeric_coerce_f64("abc"), 0.0);
    assert_eq!(perl_numeric_coerce_f64(""), 0.0);
  }

  // Codex r7 finding: Perl's numeric-context prefix scanner accepts up to
  // TWO sign characters with optional whitespace BETWEEN them, with NO
  // whitespace allowed after the second sign. Effective sign = product of
  // signs (`+-` = -, `--` = +, `++` = +, `-+` = -). Empirically verified
  // against Perl 5.
  #[test]
  fn perl_numeric_coerce_f64_dual_sign_with_whitespace() {
    // ---- accepted shapes ----
    // single sign + whitespace + digits
    assert_eq!(perl_numeric_coerce_f64("+ 20000000"), 20_000_000.0);
    assert_eq!(perl_numeric_coerce_f64("-  20"), -20.0);
    assert_eq!(perl_numeric_coerce_f64("   20"), 20.0);
    // two adjacent signs + digits
    assert_eq!(perl_numeric_coerce_f64("+-20000000"), -20_000_000.0);
    assert_eq!(perl_numeric_coerce_f64("--20000000"), 20_000_000.0);
    assert_eq!(perl_numeric_coerce_f64("++20000000"), 20_000_000.0);
    assert_eq!(perl_numeric_coerce_f64("-+20"), -20.0);
    // single sign + ws + second sign + digits
    assert_eq!(perl_numeric_coerce_f64("+ +20"), 20.0);
    assert_eq!(perl_numeric_coerce_f64("- +20"), -20.0);
    assert_eq!(perl_numeric_coerce_f64("-  +20"), -20.0);
    assert_eq!(perl_numeric_coerce_f64("+ -20"), -20.0);
    // dual sign + Inf/NaN
    let inf = perl_numeric_coerce_f64("++Inf");
    assert!(inf.is_infinite() && inf.is_sign_positive());
    let neg_inf = perl_numeric_coerce_f64("-+Inf");
    assert!(neg_inf.is_infinite() && neg_inf.is_sign_negative());
    let inf_ws = perl_numeric_coerce_f64("+ Inf");
    assert!(inf_ws.is_infinite() && inf_ws.is_sign_positive());
    // " +nanx" → NaN (leading ws + sign + NaN prefix scan, "x" tail ignored)
    assert!(perl_numeric_coerce_f64(" +nanx").is_nan());
    // ---- rejected shapes (Perl returns 0) ----
    // Whitespace AFTER the second sign is forbidden (Perl behavior).
    assert_eq!(perl_numeric_coerce_f64("+- 20"), 0.0);
    assert_eq!(perl_numeric_coerce_f64("-- 20"), 0.0);
    assert_eq!(perl_numeric_coerce_f64("-+ 20"), 0.0);
    assert_eq!(perl_numeric_coerce_f64("++ 20"), 0.0);
    assert_eq!(perl_numeric_coerce_f64("-  -  20"), 0.0);
    // Three signs are rejected.
    assert_eq!(perl_numeric_coerce_f64("+--20000000"), 0.0);
    assert_eq!(perl_numeric_coerce_f64("++-Inf"), 0.0);
    assert_eq!(perl_numeric_coerce_f64("+ - 20"), 0.0);
    // Sign(s) alone with no digits.
    assert_eq!(perl_numeric_coerce_f64("+"), 0.0);
    assert_eq!(perl_numeric_coerce_f64("-"), 0.0);
  }

  // Codex r6 finding 2 (faithful fix): when DURATION="Inf" reaches
  // `ape_duration_value_conv`, the coercion yields f64::INFINITY; `Inf *
  // 1e-7 == Inf`. ExifTool's bundled Perl emits `"APE:Duration": "Inf"`
  // both with and without `-n` (empirically verified). The port mirrors
  // this by promoting non-finite coerced values to `TagValue::Str` of the
  // Perl-stringified form. The engine serializer DOES quote non-finite
  // f64 via Rust's `to_string()` which produces lowercase `inf`/`-inf`
  // (Perl uses `Inf`/`-Inf`) — promoting to Str here picks the
  // Perl-faithful casing, byte-exact against bundled output.
  #[test]
  fn ape_duration_value_conv_non_finite_emits_perl_string() {
    // Helper to compare against an expected stringified Perl-Inf/NaN form
    // without relying on the exact TagValue::Str inner type.
    fn expect_str(v: &TagValue, want: &str) {
      match v {
        TagValue::Str(s) => assert_eq!(s.as_str(), want, "wrong stringified form"),
        other => panic!("expected Str({want:?}), got {other:?}"),
      }
    }
    // String "Inf" → coerces to f64::INFINITY → wrapped→Inf → Inf*1e-7=Inf
    //   → emit Str("Inf").
    expect_str(
      &ape_duration_value_conv(&TagValue::Str("Inf".into())),
      "Inf",
    );
    expect_str(
      &ape_duration_value_conv(&TagValue::Str("Infinity".into())),
      "Inf",
    );
    // "-Inf" → -Inf*1e-7 = -Inf → emit Str("-Inf").
    expect_str(
      &ape_duration_value_conv(&TagValue::Str("-Inf".into())),
      "-Inf",
    );
    // "NaN" → NaN*1e-7 = NaN → emit Str("NaN").
    expect_str(
      &ape_duration_value_conv(&TagValue::Str("NaN".into())),
      "NaN",
    );
    // Pre-existing F64(Inf) input (could arise from a future caller) is
    // also normalized.
    expect_str(
      &ape_duration_value_conv(&TagValue::F64(f64::INFINITY)),
      "Inf",
    );
    expect_str(
      &ape_duration_value_conv(&TagValue::F64(f64::NEG_INFINITY)),
      "-Inf",
    );
    expect_str(&ape_duration_value_conv(&TagValue::F64(f64::NAN)), "NaN");
    // Overflow input ("1e309") → +Inf via coercion.
    expect_str(
      &ape_duration_value_conv(&TagValue::Str("1e309".into())),
      "Inf",
    );
  }

  // Codex r6 finding 2 (downstream): convert_duration receives the post-
  // ValueConv Str("Inf"); IsFloat regex fails on "Inf" ⇒ identity
  // passthrough. End-to-end JSON output remains the literal string "Inf".
  #[test]
  fn convert_duration_passes_non_finite_str_unchanged() {
    fn expect_str(v: &TagValue, want: &str) {
      match v {
        TagValue::Str(s) => assert_eq!(s.as_str(), want),
        other => panic!("expected Str({want:?}), got {other:?}"),
      }
    }
    expect_str(&convert_duration(&TagValue::Str("Inf".into())), "Inf");
    expect_str(&convert_duration(&TagValue::Str("-Inf".into())), "-Inf");
    expect_str(&convert_duration(&TagValue::Str("NaN".into())), "NaN");
  }

  // -------------------------------------------------------------------------
  // Codex r6 finding 1 (REFUTED — Codex claimed Perl's $1 persists from
  // the tag-key regex through the failed `s/^([\x20-\x7e]*)\0//` and
  // would cause `Cover Art Desc` emission with the tag-key as value).
  //
  // Empirical proof against bundled Perl ExifTool 13.58: a synthesized
  // `APETAGEX` fixture with `Cover Art (Front)` carrying raw JPEG bytes
  // (no printable\0 prefix) yields ONLY `APE:CoverArtFront` — NO
  // `CoverArtFrontDesc`. The root cause: between the `\G(.*?)\0` regex
  // (line 206) and the `s/^([\x20-\x7e]*)\0//` (line 220), Perl runs:
  //   - `MakeTag($tag, ...)` (line 214) — clobbers $1 inside MakeTag's
  //     scope but the call returns to APE.pm's scope where $1 is
  //     re-evaluated via the next regex.
  //   - `$tag =~ /^Cover Art/` (line 219) — a SUCCESSFUL no-capture
  //     match. Per Perl semantics, a successful m// without capture
  //     groups REPLACES $1 (it does not preserve previous match state).
  //     Empirically `$1` is `undef` immediately after this match.
  //   - The failed `s///` (line 220) then leaves $1 as `undef`.
  //   - `if ($1)` is therefore FALSE — no Desc emitted.
  //
  // The current port correctly mirrors this: when the regex fails
  // (no printable\0 in val_bytes), we go to the `n_prefix < len && byte == 0`
  // failure branch and emit no Desc. This test PINS that behavior.
  // -------------------------------------------------------------------------
  #[test]
  fn cover_art_no_marker_emits_no_desc_faithful_to_perl() {
    // Build a minimal APETAGEX-at-start fixture with a single
    // Cover Art (Front) binary tag whose payload starts directly with
    // non-printable bytes (JPEG header), so the regex never matches.
    let key = b"Cover Art (Front)";
    let payload: &[u8] = &[0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]; // JPEG SOI+APP0
    let tag_size = (payload.len() as u32).to_le_bytes();
    let tag_flags = 0x02u32.to_le_bytes(); // binary
    let mut tag_block = Vec::new();
    tag_block.extend_from_slice(&tag_size);
    tag_block.extend_from_slice(&tag_flags);
    tag_block.extend_from_slice(key);
    tag_block.push(0);
    tag_block.extend_from_slice(payload);
    let body_size = tag_block.len() as u32;
    let apetagex_size = body_size + 32;
    let mut data = Vec::new();
    data.extend_from_slice(b"APETAGEX");
    data.extend_from_slice(&2000u32.to_le_bytes()); // version
    data.extend_from_slice(&apetagex_size.to_le_bytes()); // size
    data.extend_from_slice(&1u32.to_le_bytes()); // count
    data.extend_from_slice(&0u32.to_le_bytes()); // flags
    data.extend_from_slice(&[0u8; 8]); // reserved
    data.extend_from_slice(&tag_block);
    let mut m = crate::value::Metadata::new("x");
    let mut c = ParseContext::new(&data, "APE", 0, "APE", None, true, &mut m);
    assert!(ProcessApe.process(&mut c));
    // Confirm CoverArtFront is emitted with the raw JPEG bytes intact.
    let cover = m
      .tags()
      .iter()
      .find(|t| t.name() == "CoverArtFront")
      .expect("CoverArtFront must be emitted");
    match cover.value() {
      TagValue::Bytes(b) => assert_eq!(b.as_slice(), payload),
      other => panic!("expected Bytes, got {other:?}"),
    }
    // Crucially: NO CoverArtFrontDesc emitted (refutes Codex r6 finding 1).
    let has_desc = m.tags().iter().any(|t| t.name() == "CoverArtFrontDesc");
    assert!(
      !has_desc,
      "no CoverArtFrontDesc must appear (faithful to bundled Perl ExifTool \
       13.58 on the same fixture: only APE:CoverArtFront is emitted, no Desc)"
    );
  }

  // ---------- Phase F3 — typed `ApeMeta` surface --------------------------

  /// Build a minimal valid APE input (NewHeader at offset 0 inside `MAC `
  /// magic + APETAGEX trailer with `Artist=Tester` + a single dynamic key).
  fn build_minimal_ape_input() -> Vec<u8> {
    let mut data = Vec::new();
    // MAC magic + NewHeader (version 3990).
    data.extend_from_slice(b"MAC ");
    data.extend_from_slice(&3990u16.to_le_bytes()); // version
    data.extend_from_slice(&0u16.to_le_bytes()); // padding
    data.extend_from_slice(&0u32.to_le_bytes()); // dlen = 0 (NewHeader body empty)
    data.extend_from_slice(&0u32.to_le_bytes()); // hlen = 0
    // Pad to >=32 bytes for the magic check.
    while data.len() < 32 {
      data.push(0);
    }
    // APETAGEX trailer at EOF with one tag.
    fn tag_entry(key: &str, value: &[u8]) -> Vec<u8> {
      let mut e = Vec::new();
      e.extend_from_slice(&(value.len() as u32).to_le_bytes());
      e.extend_from_slice(&0u32.to_le_bytes()); // flags
      e.extend_from_slice(key.as_bytes());
      e.push(0);
      e.extend_from_slice(value);
      e
    }
    let entries = tag_entry("Artist", b"Tester");
    let size = (entries.len() + 32) as u32;
    data.extend_from_slice(&entries);
    data.extend_from_slice(b"APETAGEX");
    data.extend_from_slice(&2000u32.to_le_bytes()); // version
    data.extend_from_slice(&size.to_le_bytes()); // size
    data.extend_from_slice(&1u32.to_le_bytes()); // count
    data.extend_from_slice(&0u32.to_le_bytes()); // flags
    data.extend_from_slice(&[0u8; 8]); // reserved
    data
  }

  #[test]
  fn typed_parse_returns_some_for_valid_ape_input() {
    let data = build_minimal_ape_input();
    let mut shared = SharedFlags::new();
    let meta =
      <ProcessApe as FormatParser>::parse(&ProcessApe, ApeContext::new(&data, &mut shared))
        .expect("ok")
        .expect("parsed");
    // Header is NewHeader (MAC vers >= 3980 ⇒ NewHeader table).
    assert!(matches!(meta.header(), Some(ApeHeader::New { .. })));
    // Main-tag stream carries the synthesized Artist.
    assert_eq!(meta.artist(), Some("Tester"));
    assert_eq!(meta.album(), None);
    assert!(!meta.warn_bad_trailer());
  }

  #[test]
  fn typed_parse_returns_none_for_short_input() {
    let data = vec![0u8; 5];
    let mut shared = SharedFlags::new();
    let r = <ProcessApe as FormatParser>::parse(&ProcessApe, ApeContext::new(&data, &mut shared))
      .expect("ok");
    assert!(r.is_none());
  }

  #[test]
  fn typed_parse_sets_done_ape() {
    // APE.pm:131 `$$et{DoneAPE} = 1` runs unconditionally on entry,
    // BEFORE the magic check ⇒ even a short/wrong-magic input marks
    // DoneAPE.
    let data = vec![0u8; 32];
    let mut shared = SharedFlags::new();
    let _ = <ProcessApe as FormatParser>::parse(&ProcessApe, ApeContext::new(&data, &mut shared));
    assert!(shared.done_ape(), "APE.pm:131 must mark DoneAPE on entry");
  }

  #[test]
  fn typed_parse_trailer_only_finds_apetagex_at_eof() {
    // Build a payload that does NOT start with `MAC `/`APETAGEX` but
    // carries a valid APETAGEX trailer at EOF — the chained-parser
    // scenario where a prior parser (e.g. MP3) already typed the file.
    let mut data = Vec::new();
    data.extend_from_slice(&[0xff; 64]); // non-APE prefix
    fn tag_entry(key: &str, value: &[u8]) -> Vec<u8> {
      let mut e = Vec::new();
      e.extend_from_slice(&(value.len() as u32).to_le_bytes());
      e.extend_from_slice(&0u32.to_le_bytes());
      e.extend_from_slice(key.as_bytes());
      e.push(0);
      e.extend_from_slice(value);
      e
    }
    let entries = tag_entry("Title", b"Trailer Title");
    let size = (entries.len() + 32) as u32;
    data.extend_from_slice(&entries);
    data.extend_from_slice(b"APETAGEX");
    data.extend_from_slice(&2000u32.to_le_bytes());
    data.extend_from_slice(&size.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&[0u8; 8]);
    let mut shared = SharedFlags::new();
    let meta = <ProcessApe as FormatParser>::parse(
      &ProcessApe,
      ApeContext::new_trailer_only(&data, &mut shared),
    )
    .expect("ok")
    .expect("trailer-only meta");
    // Trailer-only ⇒ no header.
    assert!(meta.header().is_none());
    // Wire tag extracted.
    assert_eq!(meta.title(), Some("Trailer Title"));
  }

  #[test]
  fn typed_sink_into_map_writer_emits_main_tags() {
    use crate::sink::{MapTagWriter, MapValue};
    let data = build_minimal_ape_input();
    let mut shared = SharedFlags::new();
    let meta =
      <ProcessApe as FormatParser>::parse(&ProcessApe, ApeContext::new(&data, &mut shared))
        .expect("ok")
        .expect("parsed");
    let mut w = MapTagWriter::new();
    meta.sink(true, &mut w).unwrap();
    // Family-1 key is "APE" for main-tag emissions in the writer's
    // single-string `group` model.
    assert_eq!(
      w.get("APE", "Artist").map(MapValue::as_str),
      Some("Tester".to_string())
    );
  }

  #[test]
  fn typed_meta_borrowed_round_trip_preserves_data() {
    // ApeMeta carries owned data (String names, by-value TagValues), so the
    // GAT `Meta<'a>` is phantom over `'a`. Confirm the typed parse preserves
    // data through the trait entry.
    let data = build_minimal_ape_input();
    let mut shared = SharedFlags::new();
    let meta =
      <ProcessApe as FormatParser>::parse(&ProcessApe, ApeContext::new(&data, &mut shared))
        .expect("ok")
        .expect("parsed");
    assert_eq!(meta.artist(), Some("Tester"));
  }

  #[test]
  fn ape_context_accessors_round_trip() {
    let bytes = [0u8; 4];
    let mut shared = SharedFlags::new();
    shared.set_done_id3(128);
    let mut ctx = ApeContext::new(&bytes, &mut shared);
    assert_eq!(ctx.data().len(), 4);
    assert_eq!(ctx.shared().done_id3(), Some(128));
    ctx.shared_mut().set_done_ape(true);
    assert!(ctx.shared().done_ape());
  }

  #[test]
  fn ape_meta_accessors_returning_dynamic_main_tags() {
    let data = build_minimal_ape_input();
    let mut shared = SharedFlags::new();
    let meta =
      <ProcessApe as FormatParser>::parse(&ProcessApe, ApeContext::new(&data, &mut shared))
        .expect("ok")
        .expect("parsed");
    let mains = meta.main_tags();
    assert!(!mains.is_empty(), "fixture has an Artist tag");
    assert!(mains.iter().any(|t| t.name() == "Artist"));
  }
}
