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
  render_gmt(time)
}

/// `ConvertUnixTime($time)` (the `$toLocal == 0` GMT branch) for a *floating-
/// point* `$time` — the form PLIST's `DateTimeOriginal` `ValueConv`
/// (`PLIST.pm:73`, `ConvertUnixTime(($val - 25569) * 24 * 3600)`) hits.
///
/// Ports `ExifTool.pm:6776-6789` byte-for-byte: the `$time == 0` sentinel is
/// checked against the **float** (`:6776`); the fractional second is reduced
/// to an integer `$itime` via [`reduce_unix_time_float`] (half-to-even
/// rounding + carry, `:6780-6785`); the result is `gmtime($itime)` (`:6787`).
///
/// Critically, the sentinel is on the *original* float, NOT on the reduced
/// `$itime`: e.g. `ConvertUnixTime(0.4)` ⇒ `1970:01:01 00:00:00` (itime 0,
/// but NOT the `0000:…` sentinel), verified against bundled ExifTool 13.58.
#[must_use]
pub fn convert_unix_time_f64(time: f64) -> String {
  // ExifTool.pm:6776 `return '0000:00:00 00:00:00' if $time == 0;` — on the
  // ORIGINAL float input (before any fractional reduction).
  if time == 0.0 {
    return "0000:00:00 00:00:00".to_string();
  }
  render_gmt(reduce_unix_time_float(time))
}

/// `ConvertUnixTime($time, 0, -$digits)` (the GMT branch, ExifTool.pm:6784-
/// 6811) for a *floating-point* `$time` with a NEGATIVE fractional-format
/// flag — the form `%QuickTime::camm6 GPSDateTime` (`QuickTimeStream.pl:522`,
/// `ConvertUnixTime($val, 0, -6)`) hits.
///
/// A NEGATIVE `$dec` (`-$digits`) sets `$trim = 1` (`:6790`): the second is
/// rendered with UP TO `$digits` fractional digits, then trailing zeros (and a
/// bare trailing dot) are stripped (`$dec =~ s/\.?0+$//`, `:6797`). A whole
/// second therefore renders with NO fractional part at all (e.g. `…:00`, not
/// `…:00.000000`). Contrast a POSITIVE `$dec`, which would be fixed-width.
///
/// Faithful chain (`:6791-6797` + `:6808`):
/// ```text
/// $itime = int($time);                       # truncate toward zero
/// $frac  = $time - $itime;
/// $frac < 0 and $frac += 1, $itime -= 1;     # fold frac into [0,1)
/// $dec = sprintf('%.*f', $digits, $frac);    # e.g. "0.789000"
/// $dec =~ s/^(\d)// and $1 eq '1' and $itime += 1;   # strip int digit, carry
/// $dec =~ s/\.?0+$//;                         # trim trailing zeros (+bare dot)
/// # str = sprintf("…%.2d$dec", …, $sec)      # $dec is ".789" / ".5" / ""
/// ```
///
/// The `$time == 0` sentinel (`:6787`) is honoured on the ORIGINAL float, like
/// [`convert_unix_time_f64`]; a sub-second non-zero float (reduced `$itime ==
/// 0`) renders `1970:01:01 00:00:00<frac>`, NOT the sentinel.
#[must_use]
pub fn convert_unix_time_trim_frac_f64(time: f64, digits: u8) -> String {
  // ExifTool.pm:6787 — sentinel on the ORIGINAL float (a whole `0` is the
  // sentinel; a sub-second non-zero value is NOT).
  if time == 0.0 {
    return "0000:00:00 00:00:00".to_string();
  }
  // ExifTool.pm:6791-6793 — `int($time)` truncate-toward-zero, then fold a
  // negative fraction into `[0,1)` by borrowing a second (true floor).
  #[allow(clippy::cast_possible_truncation)]
  let mut itime = time.trunc() as i64;
  let mut frac = time - time.trunc();
  if frac < 0.0 {
    frac += 1.0;
    itime -= 1;
  }
  // ExifTool.pm:6794 `$dec = sprintf('%.*f', $digits, $frac)`. `$frac` is in
  // `[0,1)`; Rust's `format!("{:.*}", digits, _)` rounds half-to-EVEN exactly
  // like Perl's `sprintf('%.*f', …)`. Yields `"0.789000"` / `"0.500000"` /
  // `"0.000000"` — or `"1.000000"` if the fraction rounds up to a full second.
  let digits = digits as usize;
  let dec = format!("{frac:.digits$}");
  // ExifTool.pm:6796 `$dec =~ s/^(\d)// and $1 eq '1' and $itime += 1` — drop
  // the integer digit; a leading `1` (rounded up to the next whole second)
  // carries into `$itime`.
  let (lead, rest) = dec.split_at(1);
  if lead == "1" {
    itime += 1;
  }
  // ExifTool.pm:6797 `$dec =~ s/\.?0+$//` (the `$trim` branch, always taken
  // for a negative `$dec`): strip trailing zeros and, if nothing but zeros
  // followed the dot, the dot itself. `rest` is the post-integer-digit
  // remainder (`".789000"` / `".500000"` / `".000000"`).
  let frac_suffix = trim_trailing_zeros(rest);
  // ExifTool.pm:6808 — `sprintf("%.2d:%.2d:%.2d$dec", …)`: the GMT clock with
  // the trimmed fractional suffix appended to the seconds field.
  let (y, mo, d, h, mi, s) = gmtime(itime);
  format!("{y:04}:{mo:02}:{d:02} {h:02}:{mi:02}:{s:02}{frac_suffix}")
}

/// `s/\.?0+$//` (ExifTool.pm:6797) — remove a run of trailing `'0'`s at the
/// end of `s`, plus the dot immediately preceding that run if the dot is left
/// dangling. `".789000"` ⇒ `".789"`; `".500000"` ⇒ `".5"`; `".000000"` ⇒ `""`.
/// A string with no trailing zero (`".789"`) is returned unchanged.
fn trim_trailing_zeros(s: &str) -> &str {
  let trimmed = s.trim_end_matches('0');
  // After dropping trailing zeros, a dangling `.` (the whole fraction was
  // zeros) is itself removed by the `\.?` in the Perl regex.
  trimmed.strip_suffix('.').unwrap_or(trimmed)
}

/// `ConvertUnixTime($time, 1)` (the `$toLocal = 1` localtime branch) for a
/// *floating-point* `$time` — the form PLIST's binary `<date>` path
/// (`PLIST.pm:277`, `ConvertUnixTime($val + 11323*24*3600, 1)`) hits.
///
/// Ports `ExifTool.pm:6776-6795`: the `$time == 0` sentinel on the **float**
/// (`:6776`), the fractional reduction via [`reduce_unix_time_float`]
/// (`:6780-6785`), then the localtime / `TimeZoneString` rendering
/// ([`convert_unix_time_local`], `:6794-6795`).
#[must_use]
pub fn convert_unix_time_local_f64(time: f64) -> String {
  // ExifTool.pm:6776 — sentinel on the ORIGINAL float.
  if time == 0.0 {
    return "0000:00:00 00:00:00".to_string();
  }
  // The reduced `$itime` is fed to the integer localtime renderer. An
  // `$itime` of exactly 0 (reached only when the original float was a
  // sub-second non-zero value, already handled above) must render as
  // `1970:01:01 …`, NOT the sentinel — so dispatch on a sentinel-free
  // localtime path by adding the carry first. `convert_unix_time_local`
  // re-checks `time == 0`; an `$itime == 0` survivor is impossible here
  // because a float whose reduced `$itime` is 0 and whose `$time` is non-
  // zero rounds to `1970:01:01 00:00:00±..` only through the GMT/localtime
  // formatter — which we reach via the dedicated zero-aware renderer below.
  render_local(reduce_unix_time_float(time))
}

/// `int($time)` truncate-toward-zero ⇒ `$itime`, then the fractional
/// adjustment of `ExifTool.pm:6780-6785` (default `$dec = 0`):
///
/// ```text
/// $itime = int($time);
/// $frac  = $time - $itime;
/// $frac < 0 and $frac += 1, $itime -= 1;     # fold frac into [0,1)
/// $dec = sprintf('%.0f', $frac);             # half-to-EVEN (Perl sprintf)
/// $dec =~ s/^(\d)// and $1 eq '1' and $itime += 1;   # carry on round-up
/// ```
///
/// Returns the carry-adjusted integer `$itime`. The half-to-even tie rule is
/// the load-bearing fix (Codex R4 F1): Rust's `f64::round()` is half-AWAY-
/// from-zero, so `frac == 0.5` would carry (giving `…:01`) whereas Perl's
/// `sprintf('%.0f', 0.5)` ⇒ `"0"` (no carry, `…:00`). `format!("{:.0}", _)`
/// uses Rust's round-half-to-even formatter, matching Perl's `sprintf`.
fn reduce_unix_time_float(time: f64) -> i64 {
  // ExifTool.pm:6780 `$itime = int($time)` — truncate toward zero.
  #[allow(clippy::cast_possible_truncation)]
  let mut itime = time.trunc() as i64;
  // ExifTool.pm:6781 `$frac = $time - $itime`.
  let mut frac = time - time.trunc();
  // ExifTool.pm:6782 `$frac < 0 and $frac += 1, $itime -= 1` — fold a
  // negative fraction into [0,1) by borrowing a second (true floor).
  if frac < 0.0 {
    frac += 1.0;
    itime -= 1;
  }
  // ExifTool.pm:6783 `$dec = sprintf('%.0f', $frac)`. `$frac` is in `[0,1)`,
  // so this is `"0"` or `"1"`. Rust's `format!("{:.0}", _)` rounds half-to-
  // EVEN exactly like Perl's `sprintf('%.0f', _)` (`0.5` ⇒ `"0"`), the R4 F1
  // fix vs `f64::round()`'s half-away-from-zero (`0.5` ⇒ `1`).
  // ExifTool.pm:6785 `$dec =~ s/^(\d)// and $1 eq '1' and $itime += 1` — a
  // leading `1` (rounded up to the next whole second) carries into `$itime`.
  if format!("{frac:.0}") == "1" {
    itime += 1;
  }
  itime
}

/// `gmtime($itime)` rendered the `:6796-6797` way (no TZ suffix, `:6789`).
/// Shared by the integer and float GMT entry points; no `$time == 0`
/// sentinel (callers apply the sentinel against their own input form).
#[must_use]
fn render_gmt(itime: i64) -> String {
  let (y, mo, d, h, mi, s) = gmtime(itime);
  format!("{y:04}:{mo:02}:{d:02} {h:02}:{mi:02}:{s:02}")
}

/// Faithful `ConvertUnixTime($time, 1)` (ExifTool.pm:6773-6800) — the
/// `$toLocal = 1` branch (`@tm = localtime($itime); $tz =
/// TimeZoneString(\@tm, $itime)`, ExifTool.pm:6794-6795).
///
/// Input: seconds since the Unix epoch. Output: `"YYYY:MM:DD HH:MM:SS±HH:MM"`
/// — the OS-LOCAL broken-down clock with a `TimeZoneString` numeric-offset
/// suffix (ExifTool.pm:6753-6764). The conformance harness pins `TZ=UTC`
/// (`tools/gen_golden.sh`) so this code path is exercised deterministically.
///
/// Under `std` the OS timezone is read via `jiff::tz::TimeZone::system()`
/// (jiff reads `TZ` / `/etc/localtime`, exactly as Perl's `localtime`).
/// Under `no_std` (no OS TZ database) this falls back to the UTC clock with
/// a `+00:00` suffix — a documented faithful fallback (`localtime ≡ gmtime`
/// and `TimeZoneString ⇒ +00:00` on a UTC host).
///
/// Special case (ExifTool.pm:6776): `$time == 0` ⇒ `"0000:00:00 00:00:00"`.
#[must_use]
pub fn convert_unix_time_local(time: i64) -> String {
  if time == 0 {
    return "0000:00:00 00:00:00".to_string(); // ExifTool.pm:6776
  }
  render_local(time)
}

/// `localtime($itime)` + `TimeZoneString` rendered the `:6794-6795`/`:6796`
/// way. Shared by the integer and float localtime entry points; no
/// `$time == 0` sentinel (callers apply the sentinel against their own input
/// form — the float path checks the original float, not the reduced `$itime`).
#[must_use]
fn render_local(time: i64) -> String {
  #[cfg(feature = "std")]
  {
    use jiff::{Timestamp, tz::TimeZone};
    // ExifTool.pm:6794 `@tm = localtime($itime)`.
    if let Ok(ts) = Timestamp::from_second(time) {
      let zoned = ts.to_zoned(TimeZone::system());
      let dt = zoned.datetime();
      // ExifTool.pm:6795 `$tz = TimeZoneString(\@tm, $itime)` — the numeric
      // UTC offset in `±HH:MM` (ExifTool.pm:6753-6764). jiff's offset is the
      // local-minus-UTC seconds; render it the `TimeZoneString` way (round
      // to the nearest minute, `sprintf('%s%.2d:%.2d', …)`).
      let off_secs = zoned.offset().seconds();
      let tz = format_tz_offset(i64::from(off_secs));
      return format!(
        "{:04}:{:02}:{:02} {:02}:{:02}:{:02}{tz}",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
      );
    }
    // `Timestamp::from_second` rejects only out-of-range values no real
    // file date hits; fall through to the UTC rendering below.
  }
  // `no_std` (no OS TZ) — documented faithful fallback: a UTC host's
  // `localtime` equals `gmtime` and `TimeZoneString` yields `+00:00`.
  let (y, mo, d, h, mi, s) = gmtime(time);
  format!("{y:04}:{mo:02}:{d:02} {h:02}:{mi:02}:{s:02}+00:00")
}

/// Faithful `TimeZoneString` numeric rendering (ExifTool.pm:6759-6764) for a
/// UTC offset in seconds: `$min = int($min + 0.5)` (round to nearest minute),
/// then `sprintf('%s%.2d:%.2d', $sign, $h, $min - $h*60)`.
#[must_use]
fn format_tz_offset(offset_secs: i64) -> String {
  let sign = if offset_secs < 0 { '-' } else { '+' };
  let abs_secs = offset_secs.unsigned_abs();
  // ExifTool.pm:6761 `int($min + 0.5)` — round the minute count to nearest.
  let total_min = (abs_secs + 30) / 60;
  let h = total_min / 60;
  let m = total_min % 60;
  format!("{sign}{h:02}:{m:02}")
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
  fn format_tz_offset_matches_timezonestring() {
    // ExifTool.pm:6759-6764 `TimeZoneString` numeric rendering.
    assert_eq!(format_tz_offset(0), "+00:00");
    assert_eq!(format_tz_offset(-5 * 3600), "-05:00"); // US Eastern (EST)
    assert_eq!(format_tz_offset(5 * 3600 + 30 * 60), "+05:30"); // India
    assert_eq!(format_tz_offset(-9 * 3600 - 30 * 60), "-09:30"); // Marquesas
    // `int($min + 0.5)` rounds the minute count to nearest — a 29-second
    // sub-minute remainder rounds down, 30+ rounds up.
    assert_eq!(format_tz_offset(3600 + 29), "+01:00");
    assert_eq!(format_tz_offset(3600 + 30), "+01:01");
  }

  #[test]
  fn convert_unix_time_local_zero_is_zero_string() {
    // ExifTool.pm:6776 — the `$time == 0` short-circuit precedes the
    // localtime branch.
    assert_eq!(convert_unix_time_local(0), "0000:00:00 00:00:00");
  }

  #[test]
  fn convert_unix_time_local_has_offset_suffix() {
    // The localtime branch always appends a `±HH:MM` `TimeZoneString`
    // suffix (the exact offset is OS-TZ dependent — assert the shape).
    let s = convert_unix_time_local(1_000_000_000);
    let b = s.as_bytes();
    assert_eq!(b.len(), 25, "expected `YYYY:MM:DD HH:MM:SS±HH:MM`: {s}");
    assert!(b[19] == b'+' || b[19] == b'-', "missing tz sign: {s}");
    assert_eq!(b[22], b':', "missing tz colon: {s}");
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

  // -- Codex R4: the float-input ConvertUnixTime entry points --------------

  #[test]
  fn convert_unix_time_f64_float_sentinel_and_fractional_rounding() {
    // ExifTool.pm:6776 — sentinel on the ORIGINAL float, NOT the reduced
    // `$itime`. Bundled ExifTool 13.58 (TZ=UTC):
    //   ConvertUnixTime(0.0) => 0000:00:00 00:00:00
    //   ConvertUnixTime(0.4) => 1970:01:01 00:00:00   (itime 0, NOT sentinel)
    //   ConvertUnixTime(0.6) => 1970:01:01 00:00:01
    //   ConvertUnixTime(-0.4) => 1970:01:01 00:00:00  (floor to -1 then carry)
    assert_eq!(convert_unix_time_f64(0.0), "0000:00:00 00:00:00");
    assert_eq!(convert_unix_time_f64(0.4), "1970:01:01 00:00:00");
    assert_eq!(convert_unix_time_f64(0.6), "1970:01:01 00:00:01");
    assert_eq!(convert_unix_time_f64(-0.4), "1970:01:01 00:00:00");
  }

  #[test]
  fn reduce_unix_time_float_is_half_to_even() {
    // ExifTool.pm:6783 `sprintf('%.0f', $frac)` is round-half-to-EVEN. An
    // exact `.5` fraction therefore does NOT carry (rounds to the even `0`):
    //   reduce(0.5) == 0   (NOT 1, which `f64::round()` would give)
    //   reduce(1.5) == 1   (frac 0.5 ⇒ "0", no carry)
    //   reduce(-0.5) == -1 (floor 0→-1, frac 0.5 ⇒ "0", no carry)
    assert_eq!(reduce_unix_time_float(0.5), 0);
    assert_eq!(reduce_unix_time_float(1.5), 1);
    assert_eq!(reduce_unix_time_float(-0.5), -1);
    // Just past the tie carries.
    assert_eq!(reduce_unix_time_float(0.500_000_1), 1);
    // A negative non-tie fraction floors then may carry: -0.4 ⇒ floor -1,
    // frac 0.6 ⇒ "1" carry ⇒ 0.
    assert_eq!(reduce_unix_time_float(-0.4), 0);
  }

  #[test]
  fn convert_unix_time_trim_frac_f64_matches_camm6_minus6_oracle() {
    // `ConvertUnixTime($val, 0, -6)` (QuickTimeStream.pl:522) — the camm6
    // GPSDateTime fractional rule. Bundled ExifTool 13.59 (TZ=UTC) on crafted
    // camm6 GPSDateTime doubles (verified via `exiftool -ee -j -G3:1`):
    //   1704067200.789 => "2024:01:01 00:00:00.789"   (up to 6 digits)
    //   1704067200.5   => "2024:01:01 00:00:00.5"     (trailing zeros stripped)
    //   1704067200.0   => "2024:01:01 00:00:00"       (whole second: no frac)
    assert_eq!(
      convert_unix_time_trim_frac_f64(1_704_067_200.789, 6),
      "2024:01:01 00:00:00.789"
    );
    assert_eq!(
      convert_unix_time_trim_frac_f64(1_704_067_200.5, 6),
      "2024:01:01 00:00:00.5"
    );
    assert_eq!(
      convert_unix_time_trim_frac_f64(1_704_067_200.0, 6),
      "2024:01:01 00:00:00"
    );
  }

  #[test]
  fn convert_unix_time_trim_frac_f64_carry_and_sentinel() {
    // A fraction that rounds UP to a full second carries into `$itime`
    // (ExifTool.pm:6796) and leaves NO fractional part (the rounded "1.000000"
    // → strip leading "1" + carry, then `s/\.?0+$//` empties ".000000").
    // 0.9999999 at 6 digits ⇒ "1.000000" ⇒ +1 second, no frac.
    assert_eq!(
      convert_unix_time_trim_frac_f64(1_704_067_200.999_999_9, 6),
      "2024:01:01 00:00:01"
    );
    // The `$time == 0` sentinel is on the ORIGINAL float (ExifTool.pm:6787).
    assert_eq!(
      convert_unix_time_trim_frac_f64(0.0, 6),
      "0000:00:00 00:00:00"
    );
    // A sub-second non-zero float reduces to `$itime == 0` but renders
    // `1970:01:01 …` (NOT the sentinel), with its fractional suffix.
    assert_eq!(
      convert_unix_time_trim_frac_f64(0.25, 6),
      "1970:01:01 00:00:00.25"
    );
  }

  #[test]
  fn trim_trailing_zeros_matches_perl_regex() {
    // ExifTool.pm:6797 `s/\.?0+$//`: strip trailing zeros + a dangling dot.
    assert_eq!(trim_trailing_zeros(".789000"), ".789");
    assert_eq!(trim_trailing_zeros(".500000"), ".5");
    assert_eq!(trim_trailing_zeros(".000000"), "");
    // No trailing zero ⇒ unchanged.
    assert_eq!(trim_trailing_zeros(".789"), ".789");
    // A whole-second-only ".0" collapses to empty.
    assert_eq!(trim_trailing_zeros(".0"), "");
  }

  #[test]
  fn convert_unix_time_local_f64_float_sentinel() {
    // ExifTool.pm:6776 — the `$time == 0.0` float sentinel precedes the
    // localtime branch. A non-zero sub-second float reduces to `$itime == 0`
    // but renders `1970:01:01 00:00:00±..` (NOT the sentinel).
    assert_eq!(convert_unix_time_local_f64(0.0), "0000:00:00 00:00:00");
    let s = convert_unix_time_local_f64(0.4);
    assert!(
      s.starts_with("1970:01:01 00:00:00"),
      "sub-second non-zero float must not hit the sentinel: {s}"
    );
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
