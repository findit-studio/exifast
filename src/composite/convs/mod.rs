//! The canonical ExifTool `ConvertDuration` (ExifTool.pm:6877-6895) and the
//! Perl number-stringification primitives the Composite engine and the
//! cross-format duration callers share.
//!
//! Before the Composite engine existed, three independent transliterations of
//! `ConvertDuration` lived in the tree (`datetime::convert_duration`,
//! `convert::write_convert_duration`, and an APE-local copy). The APE copy was
//! the most faithful — it keeps the `$h`/`$m`/`$s` and the days carve-out as
//! Perl NV (f64) scalars throughout and stringifies them with Perl's default
//! number-to-string rule (`perl_nv_str`), so it reproduces the extreme-input
//! goldens (`APE_u64_days`, `AIFF_huge_duration`, `APE_two63_boundary`) that an
//! `as i64` cast corrupts by saturating at `i64::MAX`. This module promotes
//! that faithful impl to the one canonical [`convert_duration`]; the former
//! entry points are now thin aliases over it (`convert::write_convert_duration`,
//! `datetime::convert_duration`) so the Real / MXF / MOI / M2TS / Flash callers
//! keep their signatures.

pub(crate) mod datetime;
pub(crate) mod gps;

#[cfg(feature = "alloc")]
use crate::value::TagValue;

/// `ConvertDuration($time)` (ExifTool.pm:6877-6895) — the canonical
/// transliteration.
///
/// ```text
/// return $time unless IsFloat($time);          # non-finite: stringify Inf/-Inf/NaN
/// return '0 s' if $time == 0;
/// my $sign = ($time > 0 ? '' : (($time = -$time), '-'));
/// return sprintf("$sign%.2f s", $time) if $time < 30;
/// $time += 0.5;                                 # round to nearest second
/// my $h = int($time / 3600); $time -= $h * 3600;
/// my $m = int($time / 60);   $time -= $m * 60;
/// if ($h > 24) { my $d = int($h / 24); $h -= $d * 24; $sign = "$sign$d days "; }
/// return sprintf("$sign%d:%.2d:%.2d", $h, $m, int($time));
/// ```
///
/// A NON-FINITE input fails Perl's `IsFloat` regex (its stringified form
/// `Inf`/`-Inf`/`NaN` is not a float literal), so `ConvertDuration` returns the
/// scalar unchanged and it stringifies to Perl's titlecase casing via
/// [`crate::value::perl_nonfinite_str`] — NOT Rust's lowercase `inf`.
///
/// `int()` is truncate-toward-zero on a Perl NV (f64): the magnitude is kept as
/// f64 through the modulo arithmetic and the days carve-out, and only the
/// already-reduced small remainders are formatted. The days count `$d` and the
/// post-carve hours `$h` are stringified with Perl's default NV rule
/// ([`perl_nv_str`]) — exact decimal up to `u64::MAX`, then `%.15g` — so a huge
/// finite duration prints the same bytes ExifTool does (`"…e+20 days 0:00:00"`,
/// `"10000000000000002048 days -32768:00:00"`).
#[must_use]
pub fn convert_duration(time: f64) -> String {
  // ExifTool.pm:6879 `return $time unless IsFloat($time)`. A non-finite f64 is
  // not IsFloat; Perl returns it unchanged and it stringifies with titlecase
  // `Inf`/`-Inf`/`NaN`.
  if !time.is_finite() {
    return crate::value::perl_nonfinite_str(time)
      .unwrap_or("NaN")
      .to_string();
  }
  // ExifTool.pm:6880 `return '0 s' if $time == 0`.
  if time == 0.0 {
    return "0 s".to_string();
  }
  // ExifTool.pm:6881 `$sign = ($time > 0 ? '' : (($time = -$time), '-'))`.
  let (sign, t) = if time > 0.0 { ("", time) } else { ("-", -time) };
  // ExifTool.pm:6882 `return sprintf("$sign%.2f s", $time) if $time < 30`.
  if t < 30.0 {
    return format!("{sign}{t:.2} s");
  }
  // ExifTool.pm:6883 `$time += 0.5` — round to nearest second.
  let mut rounded = t + 0.5;
  // ExifTool.pm:6884-6887 `$h = int($time/3600); $time -= $h*3600; ...`. Keep
  // h/m/s as f64 (Perl NV); `int()` ⇒ `f64::trunc` (truncate toward zero).
  let h_f = (rounded / 3600.0).trunc();
  rounded -= h_f * 3600.0;
  let m_f = (rounded / 60.0).trunc();
  rounded -= m_f * 60.0;
  let s_f = rounded.trunc(); // `int($time)` of the remaining seconds
  // ExifTool.pm:6888-6892 days carve-out (`$h > 24`).
  if h_f > 24.0 {
    let d_f = (h_f / 24.0).trunc();
    let h_remainder = h_f - d_f * 24.0;
    // `"$sign$d days "` then `sprintf("%d:%.2d:%.2d", $h, $m, int($time))`.
    // `$d` and the post-carve `$h` are Perl NV ⇒ `perl_nv_str`; `$m`/`$s` are
    // small (always in `0..60`) ⇒ zero-padded.
    return format!(
      "{sign}{d} days {h}:{m}:{s}",
      d = perl_nv_str(d_f),
      h = perl_nv_str(h_remainder),
      m = perl_int_str_padded(m_f, 2),
      s = perl_int_str_padded(s_f, 2),
    );
  }
  // ExifTool.pm:6893 final `sprintf("$sign%d:%.2d:%.2d", $h, $m, int($time))`.
  format!(
    "{sign}{h}:{m}:{s}",
    h = perl_nv_str(h_f),
    m = perl_int_str_padded(m_f, 2),
    s = perl_int_str_padded(s_f, 2),
  )
}

/// Perl default NV (number-in-string-context) stringification:
/// `sprintf("%.15g", $nv)` for finite values, with an exact-decimal carve-out
/// for any integer-valued f64 that fits Perl's signed (`i64`) or unsigned
/// (`u64`) integer range. Special values spell `Inf` / `-Inf` / `NaN`.
///
/// Empirically against Perl 5: `int(1e19) ⇒ "10000000000000000000"` (decimal,
/// above `i64::MAX`), `int(u64::MAX as f64) ⇒ "18446744073709551615"`, and
/// `int(1.84467440737096e19) ⇒ "1.84467440737096e+19"` (above `u64` ⇒
/// scientific). The signed/unsigned split is taken at the exact f64
/// power-of-two boundary `2^63`, because `i64::MAX as f64` rounds UP to `2^63`
/// (so `n as i64` would saturate to `2^63 - 1`, losing one).
#[must_use]
pub fn perl_nv_str(n: f64) -> String {
  if n.is_nan() {
    return "NaN".to_string();
  }
  if n.is_infinite() {
    return if n.is_sign_negative() { "-Inf" } else { "Inf" }.to_string();
  }
  let two63 = (1u128 << 63) as f64; // exactly 9223372036854775808.0
  let two64 = (1u128 << 64) as f64; // exactly 18446744073709551616.0
  // Signed-integer carve-out: integer-valued f64 in [i64::MIN, 2^63),
  // EXCLUDING 2^63 (`n as i64` would saturate to i64::MAX = 2^63 - 1).
  if n == n.trunc() && n >= i64::MIN as f64 && n < two63 {
    return (n as i64).to_string();
  }
  // Unsigned-integer carve-out: positive integer-valued f64 in [2^63, 2^64).
  if n == n.trunc() && n >= two63 && n < two64 {
    return (n as u64).to_string();
  }
  crate::value::format_g(n, 15)
}

/// Left-pad an integer-valued, in-`i64`-range, non-negative `n` to `width`
/// with leading zeros (`5` → `"05"` at width 2). Out-of-range / non-integer
/// values fall back to [`perl_nv_str`] (impossible for `ConvertDuration`'s
/// minutes/seconds, which are always in `0..60`, but kept faithful).
#[must_use]
pub fn perl_int_str_padded(n: f64, width: usize) -> String {
  if n.is_finite() && (0.0..i64::MAX as f64).contains(&n) && n == n.trunc() {
    let iv = n as i64;
    format!("{iv:0width$}")
  } else {
    perl_nv_str(n)
  }
}

/// The post-arithmetic `Composite:Duration` value as the sink should store it,
/// for the active conversion mode.
///
/// `raw` is the result of the def's RawConv/ValueConv arithmetic (the APE
/// `((tf-1)*bpf+ffb)/sr`, the FLAC/AIFF `frames/sr`). Under `-n`
/// ([`ConvMode::ValueConv`](crate::emit::ConvMode::ValueConv)) the sink stores
/// the raw scalar (a finite f64 as a bare number, a non-finite f64 as the
/// quoted Perl string). Under `-j`
/// ([`ConvMode::PrintConv`](crate::emit::ConvMode::PrintConv)) the PrintConv
/// `ConvertDuration($val)` runs — a finite value formats, a non-finite value
/// passes through `IsFloat`-unchanged to the same quoted Perl string. This is
/// the single place the three migrated formats agreed on (APE stored a
/// `Str("Inf")` for non-finite, FLAC/AIFF a bare f64 for finite).
#[cfg(feature = "alloc")]
#[must_use]
pub(crate) fn duration_value(raw: f64, mode: crate::emit::ConvMode) -> TagValue {
  if !raw.is_finite() {
    // Both modes emit the titlecase Perl string (quoted by EscapeJSON).
    return TagValue::Str(
      crate::value::perl_nonfinite_str(raw)
        .unwrap_or("NaN")
        .into(),
    );
  }
  match mode {
    crate::emit::ConvMode::PrintConv => TagValue::Str(convert_duration(raw).into()),
    crate::emit::ConvMode::ValueConv => TagValue::F64(raw),
  }
}

#[cfg(test)]
mod tests;
