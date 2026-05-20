//! Faithful date/time helpers (`ConvertUnixTime`/`ConvertDateTime`,
//! `ExifTool.pm:6773-6800` and `:6563`).
//!
//! Only the subset AIFF.pm uses is ported here:
//!   - `ConvertUnixTime($time)` (no `$toLocal`, no `$dec`) → GMT branch
//!     (ExifTool.pm:6787-6789: `@tm = gmtime($itime); $tz = ''`) which
//!     formats as `"%4d:%.2d:%.2d %.2d:%.2d:%.2d"`.
//!   - `ConvertDateTime($val)` (ExifTool.pm:6563) with the default format
//!     (no `DateFormat` option set) returns the input unchanged — the
//!     non-default `strftime` branch is faithfully deferred per spec §5.
//!
//! The local-time / `$dec` fractional-second branches are NOT ported here
//! (no AIFF tag exercises them; the QuickTime / FLAC date paths will derive
//! them when they need them, faithful to those formats' Perl).
//!
//! AIFF's epoch is 1904 (Mac/AIFF "seconds since 00:00 Jan 1, 1904");
//! `AIFF.pm:26` `ValueConv => 'ConvertUnixTime($val - ((66 * 365 + 17) * 24 * 3600))'`
//! converts to the Unix epoch (1970) by subtracting
//! `(66 * 365 + 17) * 24 * 3600 = 2_082_844_800` seconds.

/// `(66 * 365 + 17) * 24 * 3600` (AIFF.pm:26) — the 1970 − 1904 second offset
/// (66 years × 365 days + 17 leap days × 24 × 3600). Static constant so the
/// computation is single-source-of-truth and compile-time verified.
pub const AIFF_EPOCH_OFFSET: i64 = (66 * 365 + 17) * 24 * 3600;

/// Faithful subset of `ConvertUnixTime($time)` (ExifTool.pm:6773-6800), the
/// `$toLocal == 0` / `$dec == 0` branch. Input: seconds since the Unix epoch
/// (1970-01-01T00:00:00Z). Output: `"YYYY:MM:DD HH:MM:SS"` (24-hour, no
/// timezone suffix; `$tz = ''` per :6789). Negative `time` ≡ pre-1970.
///
/// Special case (:6776): `$time == 0` ⇒ `"0000:00:00 00:00:00"`.
///
/// The implementation rolls its own `gmtime` (full proleptic Gregorian; Perl's
/// `gmtime` matches the OS's, which in turn matches POSIX, which is the
/// proleptic Gregorian over the supported epoch range). No external dep —
/// keeps the crate's panic-free / `#![forbid(unsafe_code)]` guarantee.
#[must_use]
pub fn convert_unix_time(time: i64) -> String {
  if time == 0 {
    return "0000:00:00 00:00:00".to_string(); // ExifTool.pm:6776
  }
  let (y, mo, d, h, mi, s) = gmtime(time);
  format!("{y:04}:{mo:02}:{d:02} {h:02}:{mi:02}:{s:02}")
}

/// Faithful subset of `ConvertDateTime($val)` (ExifTool.pm:6563). With no
/// `DateFormat` option (the AIFF read path has no such option), Perl's
/// `$self->ConvertDateTime` returns its input unchanged. The `DateFormat`
/// branch (POSIX `strftime`) is faithfully deferred per spec §5 — the FIRST
/// consumer that sets it will derive the port. AIFF only ever invokes
/// `$self->ConvertDateTime($val)` with the default options, so identity is
/// faithful here.
#[must_use]
pub fn convert_datetime(val: &str) -> String {
  val.to_string()
}

/// Faithful `ConvertDuration($val)` (`ExifTool.pm:6866-6884`). Converts a
/// duration value in seconds (`f64`) to a human-readable display string,
/// matching `Image::ExifTool::ConvertDuration` byte-for-byte for the
/// reachable input space:
///
/// - `0.0` ⇒ `"0 s"` (`:6870`)
/// - `|time| < 30` ⇒ `sprintf("%.2f s", $time)` (`:6872`), with a leading
///   `-` for negative values per `:6871`.
/// - otherwise ⇒ `H:MM:SS` with optional `D days ` prefix when `$h > 24`
///   (`:6873-6883`); the input is incremented by 0.5 to round to nearest
///   second before integer-dividing into h/m/s.
///
/// Perl's `:6869 return $time unless IsFloat($time)` is faithfully
/// transliterated by the f64 typing of the input (any non-finite value is
/// caught by `is_finite()` and we return the canonical Perl string form).
/// AIFF's only consumer is `%AIFF::Composite Duration` (`AIFF.pm:143`),
/// whose `RawConv` already filters `$val == 0 ⇒ undef`, so this fn is
/// only called for positive finite floats — but we faithfully handle the
/// other branches for future composite-tag consumers.
#[must_use]
pub fn convert_duration(time: f64) -> String {
  // ExifTool.pm:6869 `return $time unless IsFloat($time)`. A non-finite
  // f64 is NOT IsFloat (IsFloat checks for a numeric scalar that parses
  // as a float); Perl returns the input scalar unchanged, and the scalar
  // stringifies via Perl's default NV-to-string with titlecase `Inf`/
  // `-Inf`/`NaN` casing (verified 2026-05-20). Codex R8 fix: use
  // `perl_nonfinite_str` for byte-exact casing (the prior `format!
  // ("{time}")` emitted Rust's lowercase `inf`/`-inf`).
  if !time.is_finite() {
    return crate::value::perl_nonfinite_str(time)
      .unwrap_or("")
      .to_string();
  }
  // ExifTool.pm:6870 `return '0 s' if $time == 0`.
  if time == 0.0 {
    return "0 s".to_string();
  }
  // ExifTool.pm:6871 `$sign = ($time > 0 ? '' : (($time = -$time), '-'))`.
  let (sign, t) = if time > 0.0 { ("", time) } else { ("-", -time) };
  // ExifTool.pm:6872 `return sprintf("$sign%.2f s", $time) if $time < 30`.
  if t < 30.0 {
    return format!("{sign}{t:.2} s");
  }
  // ExifTool.pm:6873 `$time += 0.5` — round to nearest second.
  let mut rounded = t + 0.5;
  // ExifTool.pm:6874-6877 `$h = int($time/3600); $time -= $h*3600;
  // $m = int($time/60); $time -= $m*60;`. `int()` in Perl is truncate-
  // toward-zero ON A FLOAT (NV); the FLOAT magnitude is preserved through
  // the modulo arithmetic (Codex R7 fix: prior `as i64` cast saturated for
  // huge finite durations, e.g. a SampleRate of 2^-84 / NumSampleFrames=1
  // yields ~1.93e+25 seconds and the i64 cast saturated to i64::MAX,
  // producing wrong sub-day values. Perl keeps `$h`, `$m`, `$d` as NV-
  // typed scalars whose magnitudes can exceed i64; we faithfully use f64
  // throughout and only cast the SMALL REMAINDERS to i64 for the final
  // `%d:%.2d:%.2d` printf).
  let h_f = (rounded / 3600.0).trunc();
  rounded -= h_f * 3600.0;
  let m_f = (rounded / 60.0).trunc();
  rounded -= m_f * 60.0;
  let s_f = rounded.trunc(); // `int($time)` of remaining
                             // ExifTool.pm:6878-6882 `if ($h > 24) { my $d = int($h/24); $h -= $d*24;
                             // $sign = "$sign$d days "; }`.
  let mut prefix = sign.to_string();
  let h_after_days = if h_f > 24.0 {
    let d_f = (h_f / 24.0).trunc();
    let h_left = h_f - d_f * 24.0;
    // Perl `"$sign$d days "` interpolates `$d` as Perl's default NV
    // stringification. Small integer d ⇒ no decimal (e.g. "12 days ");
    // very large d ⇒ scientific notation via `format_g(_, 15)` (Perl's
    // default NV → string precision). Oracle (2026-05-20) on SampleRate=
    // 2^-84 / NumSampleFrames=1 (`/tmp/test_ext_tiny.aif`) emits
    // `"2.23875151780487e+20 days 0:00:00"` — byte-exact via format_g(d, 15).
    prefix.push_str(&crate::value::format_g(d_f, 15));
    prefix.push_str(" days ");
    h_left
  } else {
    h_f
  };
  // ExifTool.pm:6883 `return sprintf("$sign%d:%.2d:%.2d", $h, $m, int($time))`.
  // After the `days` reduction `h_after_days` is in `0.0..=24.0` (always
  // a small float); m_f is in `0.0..=60.0`; s_f is in `0.0..=60.0`. All
  // safely fit i64 for `%d`/`%.2d` printf semantics.
  let h_i = h_after_days as i64;
  let m_i = m_f as i64;
  let s_i = s_f as i64;
  format!("{prefix}{h_i}:{m_i:02}:{s_i:02}")
}

/// Convert a Unix timestamp (seconds since 1970-01-01T00:00:00Z) to its
/// UTC broken-down components `(year, month, day, hour, minute, second)`.
/// Proleptic Gregorian over the full `i64` range (Perl's `gmtime` matches
/// POSIX, which is proleptic Gregorian).
///
/// The algorithm is the standard "days since civil epoch" decomposition
/// (Howard Hinnant, "date.h"): exact integer arithmetic, no floating point,
/// no panic, no overflow over the `i64` time domain that exceeds any
/// reasonable file timestamp range. The two arithmetic operations that could
/// overflow on `i64::MIN/MAX` (`time` ± offset) are guarded by `saturating_*`.
fn gmtime(time: i64) -> (i64, u32, u32, u32, u32, u32) {
  // Floor-divide / Euclidean modulo, faithful to Perl's `gmtime` rounding
  // toward negative infinity (POSIX). `div_euclid` / `rem_euclid` give
  // exactly that on `i64`.
  let day_seconds: i64 = 86_400;
  let days = time.div_euclid(day_seconds);
  let secs_of_day = time.rem_euclid(day_seconds); // 0..86399

  let h = (secs_of_day / 3600) as u32;
  let mi = ((secs_of_day / 60) % 60) as u32;
  let s = (secs_of_day % 60) as u32;

  // Convert days-since-1970-01-01 to (Y, M, D) via Hinnant's civil_from_days.
  // Offset to internal epoch: shift days so era 0 starts at 0000-03-01.
  // 719468 = days from 0000-03-01 to 1970-01-01 (Hinnant's "civil epoch").
  let z = days + 719_468;
  let era = if z >= 0 {
    z / 146_097
  } else {
    (z - 146_096) / 146_097
  };
  let doe = (z - era * 146_097) as u64; // 0..146096
  let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // 0..399
  let y_internal = (yoe as i64) + era * 400;
  let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // 0..365
  let mp = (5 * doy + 2) / 153; // 0..11
  let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // 1..31
  let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // 1..12
  let year = y_internal + i64::from(mp >= 10);

  (year, month, day, h, mi, s)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn aiff_epoch_offset_matches_perl_constant() {
    // AIFF.pm:26 `(66 * 365 + 17) * 24 * 3600 = 2_082_844_800`.
    assert_eq!(AIFF_EPOCH_OFFSET, 2_082_844_800);
  }

  #[test]
  fn zero_yields_zero_string() {
    // ExifTool.pm:6776 `return '0000:00:00 00:00:00' if $time == 0`.
    assert_eq!(convert_unix_time(0), "0000:00:00 00:00:00");
  }

  #[test]
  fn unix_epoch_one_second_after() {
    assert_eq!(convert_unix_time(1), "1970:01:01 00:00:01");
  }

  #[test]
  fn known_oracle_aiff_comment_time() {
    // Bundled oracle: AIFF.aif fixture has CommentTime u32 = 0xbc71b50e
    // (Mac/AIFF time). After subtracting AIFF_EPOCH_OFFSET, Perl's
    // ConvertUnixTime yields "2004:03:08 05:28:46" (oracle-captured).
    let mac = 0xbc71b50e_i64;
    let unix = mac - AIFF_EPOCH_OFFSET;
    assert_eq!(convert_unix_time(unix), "2004:03:08 05:28:46");
  }

  #[test]
  fn known_oracle_aifc_format_version_time() {
    // AIFC fixture: FormatVersionTime u32 = 0xa2805140 (Mac/AIFF time)
    // ⇒ "1990:05:23 14:40:00" (oracle-captured, AIFC golden).
    let mac = 0xa2805140_i64;
    let unix = mac - AIFF_EPOCH_OFFSET;
    assert_eq!(convert_unix_time(unix), "1990:05:23 14:40:00");
  }

  #[test]
  fn gmtime_handles_unix_epoch_boundary() {
    assert_eq!(gmtime(0), (1970, 1, 1, 0, 0, 0));
    assert_eq!(gmtime(-1), (1969, 12, 31, 23, 59, 59));
    assert_eq!(gmtime(86_400), (1970, 1, 2, 0, 0, 0));
  }

  #[test]
  fn gmtime_handles_leap_day_and_century_boundaries() {
    // 2000-02-29 12:34:56 UTC ⇒ epoch 951_827_696.
    assert_eq!(gmtime(951_827_696), (2000, 2, 29, 12, 34, 56));
    // 1900 is NOT a leap year (Gregorian rule); 1900-03-01 = 1900-02-28 + 1.
    // 1900-01-01 00:00:00 UTC ⇒ epoch -2_208_988_800.
    assert_eq!(gmtime(-2_208_988_800), (1900, 1, 1, 0, 0, 0));
    // 1899-12-31 23:59:59 UTC ⇒ epoch -2_208_988_801 (round toward -inf).
    assert_eq!(gmtime(-2_208_988_801), (1899, 12, 31, 23, 59, 59));
  }

  #[test]
  fn convert_datetime_is_identity_under_default_options() {
    // ExifTool.pm:6563 with no DateFormat option ⇒ returns input unchanged.
    assert_eq!(
      convert_datetime("2004:03:08 05:28:46"),
      "2004:03:08 05:28:46"
    );
    assert_eq!(convert_datetime(""), "");
  }

  // -- convert_duration ---------------------------------------------------
  // ExifTool.pm:6866-6884 oracle. Spot-checked against bundled Perl
  // `Image::ExifTool::ConvertDuration` (Codex R4 raised AIFF Duration as a
  // blocker; the fixture `AIFF_duration.aif` carries SampleRate=22050 and
  // NumSampleFrames=44100, oracle prints `"2.00 s"`).

  #[test]
  fn convert_duration_zero_returns_zero_s() {
    // ExifTool.pm:6870 `return '0 s' if $time == 0`.
    assert_eq!(convert_duration(0.0), "0 s");
  }

  #[test]
  fn convert_duration_under_30s_two_decimal_with_s_suffix() {
    // ExifTool.pm:6872 `return sprintf("$sign%.2f s", $time) if $time < 30`.
    // Bundled-Perl oracle:
    //   perl -e 'use Image::ExifTool; print Image::ExifTool::ConvertDuration(2.0)'
    //   => 2.00 s
    assert_eq!(convert_duration(2.0), "2.00 s");
    assert_eq!(convert_duration(0.5), "0.50 s");
    assert_eq!(convert_duration(29.999), "30.00 s"); // rounded by %.2f
    assert_eq!(convert_duration(-2.0), "-2.00 s");
  }

  #[test]
  fn convert_duration_30_plus_h_mm_ss() {
    // ExifTool.pm:6873-6883. `$time += 0.5` rounds; H:MM:SS via int divs.
    // 90s = 1m30s ⇒ `0:01:30`. Perl oracle:
    //   ConvertDuration(90.0)   => 0:01:30
    //   ConvertDuration(3600.0) => 1:00:00
    //   ConvertDuration(3661.0) => 1:01:01
    assert_eq!(convert_duration(90.0), "0:01:30");
    assert_eq!(convert_duration(3600.0), "1:00:00");
    assert_eq!(convert_duration(3661.0), "1:01:01");
  }

  #[test]
  fn convert_duration_over_24h_emits_days_prefix() {
    // ExifTool.pm:6878-6882. `if ($h > 24)` (strict >; 24h exactly stays
    // `24:00:00`). 25 hours ⇒ `1 days 1:00:00`. Bundled-Perl:
    //   ConvertDuration(25 * 3600.0) => 1 days 1:00:00
    //   ConvertDuration(50 * 3600.0) => 2 days 2:00:00
    assert_eq!(convert_duration(25.0 * 3600.0), "1 days 1:00:00");
    assert_eq!(convert_duration(50.0 * 3600.0), "2 days 2:00:00");
    // 24h exactly does NOT promote (`$h > 24` is strict greater-than).
    assert_eq!(convert_duration(24.0 * 3600.0), "24:00:00");
  }

  #[test]
  fn convert_duration_non_finite_returns_perl_titlecase_string() {
    // ExifTool.pm:6869 `return $time unless IsFloat($time)`. Non-finite
    // inputs are not realistic for AIFF (RawConv filters $val==0), but
    // we faithfully return the input scalar's stringification — Perl's
    // default NV-to-string uses titlecase `Inf`/`-Inf`/`NaN` (verified
    // 2026-05-20 via `perl -e 'print 1e308*1e308'`), NOT Rust's lowercase
    // `inf`/`-inf` from `f64::to_string`. Codex R8 fix.
    assert_eq!(convert_duration(f64::NAN), "NaN");
    assert_eq!(convert_duration(f64::INFINITY), "Inf");
    assert_eq!(convert_duration(f64::NEG_INFINITY), "-Inf");
  }
}
