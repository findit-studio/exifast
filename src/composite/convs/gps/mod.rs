//! The GPS coordinate / altitude PrintConv helpers the GPS Composite defs share
//! — a faithful transliteration of `Image::ExifTool::GPS::ToDMS` (GPS.pm:495)
//! and the `Composite:GPSAltitude` PrintConv (GPS.pm:419-431).
//!
//! Only the cases the *Composite* GPS tags reach are ported: `ToDMS` is always
//! invoked as `ToDMS($self, $val, 1, "N"|"E")` — `$doPrintConv eq '1'` with a
//! significant hemisphere `$ref` and the DEFAULT `CoordFormat` (exifast does not
//! expose the `-c`/`CoordFormat` option, so `$et->Options('CoordFormat')` is
//! always unset). That collapses `ToDMS` to: format string `%d deg %d' %.2f"`
//! plus the ` N`/` S`/` E`/` W` suffix, `$num == 3` (three captured specifiers),
//! and the D/M/S split with the ExifTool round-off carry. The XMP (`eq '2'`),
//! signed-unformatted (`eq '3'`), no-`$ref`, and custom-`CoordFormat` branches
//! are unreachable here and intentionally omitted.

use crate::value::format_g;

/// `Image::ExifTool::GPS::ToDMS($self, $val, 1, $ref)` (GPS.pm:495) for the
/// Composite-GPS case: `$doPrintConv eq '1'`, a significant hemisphere `ref`
/// (`'N'` for latitude, `'E'` for longitude), and the default `CoordFormat` —
/// i.e. `q{%d deg %d' %.2f"} . $refSuffix`, three format specifiers, the D/M/S
/// split, and the `>= 60` minutes/seconds carry. Produces e.g.
/// `48 deg 51' 29.34" N` (GPS.pm fmt `%d deg %d' %.2f"` then ` N`).
///
/// `ref_pos` is the cardinal letter for a NON-negative value; ExifTool flips it
/// to its opposite (`N`→`S`, `E`→`W`) and takes `abs($val)` when `val < 0`.
#[must_use]
pub(crate) fn to_dms(val: f64, ref_pos: char) -> String {
  // GPS.pm:505-514 `if ($ref) { if ($val < 0) { $val = -$val; $ref = {...} } ... }`.
  // (`length $val` is always true here — the Composite RawConv only reaches
  // PrintConv with a defined numeric `$val`; the empty-value short-circuit at
  // GPS.pm:499-503 cannot fire.)
  let (mag, hemi) = if val < 0.0 {
    (-val, opposite_hemisphere(ref_pos))
  } else {
    (val, ref_pos)
  };
  // GPS.pm:515 `$ref = " $ref"` (not the `eq '2'` XMP branch) — the suffix.
  // GPS.pm:526 default `$fmt = q{%d deg %d' %.2f"} . $ref` ⇒ three specifiers,
  // so `$num == 3` and we always take the full D/M/S split.

  // GPS.pm:548-558 the D/M/S split (`$num > 2`).
  let mut d = mag.trunc(); // `$c[0] = int($c[0])`
  let mut m = ((mag - d) * 60.0).trunc(); // `$c[1] = int(($val - $c[0]) * 60)`
  let s = (mag - d - m / 60.0) * 3600.0; // `$c[2] = ($val - $c[0] - $c[1]/60) * 3600`

  // GPS.pm:560-565 the round-off carry. `$c[-1]` is first FORMATTED to the
  // seconds spec (`sprintf('%.2f', $c[-1])`), then compared `>= 60` in Perl
  // NUMERIC context on that rounded string — so a seconds value that rounds UP
  // to 60.00 carries into the minutes (and on into the degrees).
  let mut s_rounded: f64 = format_seconds(s).parse().unwrap_or(s);
  if s_rounded >= 60.0 {
    s_rounded -= 60.0;
    m += 1.0;
    if m >= 60.0 {
      m -= 60.0;
      d += 1.0;
    }
  }

  // GPS.pm:568 `$rtnVal = sprintf($fmt, @c)` — `%d deg %d' %.2f" $ref`. `%d`
  // truncates toward zero (the D/M are already non-negative integers here);
  // `%.2f` re-formats the carried seconds.
  format!(
    "{d} deg {m}' {s}\" {hemi}",
    d = perl_int_d(d),
    m = perl_int_d(m),
    s = format_seconds(s_rounded),
  )
}

/// One `foreach (0,2)` candidate of the `Composite:GPSAltitude` PrintConv: the
/// altitude ingredient `$val[$_]` (as text — the single source for both the
/// `IsFloat($val[$_])` check and the `int($val[$_]*10)/10` numeric coercion)
/// paired with the ref-print `$prt[$_+1]`. Index 0 = the `GPS:GPSAltitude`/`Ref`
/// pair; index 2 = the `XMP:GPSAltitude`/`Ref` pair. The number is derived from
/// the `IsFloat`-normalized text (not carried separately) because `IsFloat`'s
/// `tr/,/./` mutates the scalar in place, so `int($val[$_]*10)` re-coerces the
/// translated value (`12,5` → `12.5`), exactly as a single mutated `$val[$_]`.
#[derive(Clone, Copy)]
pub(crate) struct AltCandidate<'a> {
  /// `$val[$_]` in string context (for `IsFloat($val[$_])` and the coercion).
  pub(crate) alt_text: Option<&'a str>,
  /// `$prt[$_+1]` (the ref-print, e.g. `"Above Sea Level"`).
  pub(crate) ref_print: Option<&'a str>,
}

/// `Composite:GPSAltitude` PrintConv (GPS.pm:419-431). `own_val` is the
/// composite's own `$val` (the ref-signed altitude — used by the fall-through);
/// `candidates` are the `(0,2)` ingredient pairs in order.
///
/// ```perl
/// foreach (0,2) {
///     next unless defined $val[$_] and IsFloat($val[$_]);
///     next unless defined $prt[$_+1] and $prt[$_+1] =~ /Sea/;
///     return((int($val[$_]*10)/10) . ' m ' . $prt[$_+1]);
/// }
/// $val = int($val * 10) / 10;
/// return(($val =~ s/^-// ? "$val m Below" : "$val m Above") . " Sea Level");
/// ```
///
/// The loop matches the FIRST candidate whose altitude is a float AND whose
/// ref-print contains `/Sea/` (the EXIF `GPSAltitudeRef` PrintConv strings —
/// `Above/Below Sea Level`, `Positive/Negative Sea Level` — and the XMP variant
/// — all contain "Sea"), yielding `(int($val*10)/10) m $prt`. Otherwise it
/// falls through to the unsigned form built from the composite's own `$val`
/// (`"$mag m Below/Above Sea Level"`, the sign giving Below vs Above).
#[must_use]
pub(crate) fn gps_altitude_print(own_val: f64, candidates: &[AltCandidate<'_>]) -> String {
  for cand in candidates {
    // `next unless defined $val[$_] and IsFloat($val[$_])`. `IsFloat` both
    // guards AND translates `,`→`.` in place; the later `int($val[$_]*10)`
    // coerces the NORMALIZED scalar, so coerce the normalized string.
    let Some(alt_text) = cand.alt_text else {
      continue;
    };
    let Some(alt_norm) = crate::convert::is_float_norm(alt_text) else {
      continue;
    };
    // `next unless defined $prt[$_+1] and $prt[$_+1] =~ /Sea/`.
    let Some(ref_print) = cand.ref_print else {
      continue;
    };
    if !ref_print.contains("Sea") {
      continue;
    }
    // `(int($val[$_]*10)/10) . ' m ' . $prt[$_+1]`.
    let alt = crate::convert::perl_str_to_f64(&alt_norm);
    let tenths = (alt * 10.0).trunc() / 10.0;
    return format!("{} m {ref_print}", format_g(tenths, 15));
  }
  // Fall-through (GPS.pm:427-430): `$val = int($val * 10) / 10; ($val =~ s/^-//
  // ? "$val m Below" : "$val m Above") . " Sea Level"`. The composite's own
  // `$val` is the ref-signed altitude; a leading `-` means Below.
  let tenths = (own_val * 10.0).trunc() / 10.0;
  let s = format_g(tenths, 15);
  match s.strip_prefix('-') {
    Some(mag) => format!("{mag} m Below Sea Level"),
    None => format!("{s} m Above Sea Level"),
  }
}

/// `{N => 'S', E => 'W'}->{$ref}` (GPS.pm:509). The Composite GPS PrintConv only
/// ever passes `'N'` (latitude) or `'E'` (longitude); any other letter is
/// returned unchanged (ExifTool would yield `undef`, unreachable here).
const fn opposite_hemisphere(c: char) -> char {
  match c {
    'N' => 'S',
    'E' => 'W',
    other => other,
  }
}

/// `sprintf('%.2f', $s)` — the seconds spec from the default `CoordFormat`.
/// Rust's `{:.2}` matches C/Perl `%.2f` (round-half-to-even is not observable at
/// the inputs GPS seconds reach; ExifTool uses the platform `sprintf`).
fn format_seconds(s: f64) -> String {
  format!("{s:.2}")
}

/// `sprintf('%d', $n)` of a non-negative integer-valued `f64` (the carried
/// degrees / minutes are always whole and `>= 0` here). `%d` truncates toward
/// zero; the values fit `i64`, so a direct cast is the faithful render.
fn perl_int_d(n: f64) -> String {
  // `%d` on a Perl NV truncates toward zero. D/M are always small non-negative
  // integers after the carry, so an `i64` cast reproduces ExifTool's bytes.
  (n.trunc() as i64).to_string()
}

#[cfg(test)]
mod tests;
