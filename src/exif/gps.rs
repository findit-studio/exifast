// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "gps")]
//! Faithful port of `Image::ExifTool::GPS` (`lib/Image/ExifTool/GPS.pm`).
//!
//! The GPS IFD is a standard Exif sub-IFD reached through the IFD0 tag
//! `GPSInfo` (0x8825 — `Exif.pm:2130-2141`). It is structurally IDENTICAL to
//! any other IFD: the Exif IFD walker ([`crate::exif::ifd`] + the walker in
//! [`crate::exif`]) decodes the entries; this module only supplies the GPS
//! tag table (`%Image::ExifTool::GPS::Main`, `GPS.pm:50-353`) plus the GPS
//! coordinate ValueConv/PrintConv (`ToDegrees`/`ToDMS`/`ConvertTimeStamp`/
//! `PrintTimeStamp`, `GPS.pm:455-601`).
//!
//! ## Coordinate conversion
//!
//! `GPSLatitude`/`GPSLongitude` are stored as 3 rationals (degrees, minutes,
//! seconds). ExifTool's `%coordConv` (`GPS.pm:16-20`):
//!
//! - **ValueConv** `ToDegrees($val)` — collapse D/M/S to decimal degrees.
//! - **PrintConv** `ToDMS($self, $val, 1)` — format as `D deg M' S"`.
//!
//! The N/S/E/W reference tags (`GPSLatitudeRef` etc.) sign the coordinate at
//! the COMPOSITE-tag layer (`GPS:GPSLatitude` itself is always the unsigned
//! magnitude; `Composite:GPSLatitude` applies the sign). Composite tags are
//! deferred crate-wide (`[[exifast-phase2-forward-items]]`), so the GPS IFD
//! port emits the unsigned `GPS:*` tags exactly as bundled does under `-j`.

// Golden-v2 Contract 3c (Phase C, slice w2d): panic-safety by construction —
// the `PrintTimeStamp` / `ExifDate` string scanners below index only behind a
// preceding length/position guard; each raw index/slice becomes a checked
// `.get()` form (the fallback is the guard-guaranteed value).
#![deny(clippy::indexing_slicing)]

use crate::exif::tables::Conv;

// The `--kind exif` generator's Step-A shadow of this table (`cargo xtask
// gen-tables --module GPS::Main --kind exif`): a strict subset of [`GPS_TAGS`]
// re-rendered into the same `GpsTag` rows, each resolved to the SAME
// [`GpsConv`] (a per-id differential parity test below is the gate). It is a
// CHILD module so its HANDPORTED `super::GPS_MEASURE_MODE` const reference (and
// the `super::Conv` / `super::GpsConv` imports) resolve against THIS module.
// [`lookup`] consults the hand table FIRST and falls back here; the shadow is a
// subset, so that fallback only ever AGREES.
#[path = "gps_generated.rs"]
mod generated;

// ===========================================================================
// GPS-specific PrintConv hashes (GPS.pm)
// ===========================================================================

/// `%printConvLatRef` PrintConv (`GPS.pm:22-34`) — `GPSLatitudeRef` /
/// `GPSDestLatitudeRef`. `N => 'North'`, `S => 'South'`.
const GPS_LAT_REF: &[(&str, &str)] = &[("N", "North"), ("S", "South")];

/// `%printConvLonRef` PrintConv (`GPS.pm:36-48`) — `GPSLongitudeRef` /
/// `GPSDestLongitudeRef`. `E => 'East'`, `W => 'West'`.
const GPS_LON_REF: &[(&str, &str)] = &[("E", "East"), ("W", "West")];

/// `GPSStatus` PrintConv (`GPS.pm:170-174`).
const GPS_STATUS: &[(&str, &str)] = &[("A", "Measurement Active"), ("V", "Measurement Void")];

/// `GPSMeasureMode` PrintConv (`GPS.pm:179-182`).
const GPS_MEASURE_MODE: &[(&str, &str)] = &[
  ("2", "2-Dimensional Measurement"),
  ("3", "3-Dimensional Measurement"),
];

/// `GPSSpeedRef` PrintConv (`GPS.pm:193-197`).
const GPS_SPEED_REF: &[(&str, &str)] = &[("K", "km/h"), ("M", "mph"), ("N", "knots")];

/// `GPSTrackRef` / `GPSImgDirectionRef` / `GPSDestBearingRef` PrintConv
/// (`GPS.pm:202-205` etc.) — `M`/`T`.
const GPS_DIRECTION_REF: &[(&str, &str)] = &[("M", "Magnetic North"), ("T", "True North")];

/// `GPSDestDistanceRef` PrintConv (`GPS.pm:284-288`).
const GPS_DEST_DISTANCE_REF: &[(&str, &str)] =
  &[("K", "Kilometers"), ("M", "Miles"), ("N", "Nautical Miles")];

/// `GPSDifferential` PrintConv (`GPS.pm:335-338`).
const GPS_DIFFERENTIAL: &[(i64, &str)] = &[(0, "No Correction"), (1, "Differential Corrected")];

/// `GPSAltitudeRef` PrintConv (`GPS.pm:107-112`).
const GPS_ALTITUDE_REF: &[(i64, &str)] = &[
  (0, "Above Sea Level"),
  (1, "Below Sea Level"),
  (2, "Positive Sea Level (sea-level ref)"),
  (3, "Negative Sea Level (sea-level ref)"),
];

// ===========================================================================
// GPS conversion descriptor — `GpsConv`
// ===========================================================================

/// The conversion ExifTool applies to one GPS tag. The plain Exif [`Conv`]
/// kinds (`None`, `IntLabel*`, `MetersSuffix`, `Version`) cover most GPS
/// tags; the GPS-specific ones get their own variants here.
///
/// D8: unit-or-newtype variants; `#[non_exhaustive]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GpsConv {
  /// A plain Exif conversion (no GPS-specific behaviour).
  Plain(Conv),
  /// `GPSVersionID` PrintConv — `$val =~ tr/ /./; $val` (`GPS.pm:61`):
  /// the space-joined int8u quadruple is rendered with `.` separators.
  VersionId,
  /// `%coordConv` — D/M/S rationals → decimal degrees (ValueConv
  /// `ToDegrees`), `D deg M' S"` (PrintConv `ToDMS`). `GPS.pm:16-20`.
  Coordinate,
  /// `GPSTimeStamp` — 3 rationals (H, M, S) → `ConvertTimeStamp` (ValueConv,
  /// `GPS.pm:133`) → `PrintTimeStamp` (PrintConv, `GPS.pm:135`).
  TimeStamp,
  /// `GPSDateStamp` — `undef[11]` → `ExifDate` (`GPS.pm:319`): a
  /// `YYYY:mm:dd` string, `\0`-stripped.
  DateStamp,
  /// String → label via a `(str, label)` slice (`GPSStatus` etc.).
  StrLabel(&'static [(&'static str, &'static str)]),
  /// `ConvertExifText` RawConv — `GPSProcessingMethod` / `GPSAreaInformation`
  /// (`GPS.pm:299`/305). An 8-byte charset-ID prefix (`ASCII`/`UNICODE`/`JIS`)
  /// is stripped and the payload decoded (`Exif.pm:5554-5601`).
  ExifText,
}

/// One GPS IFD tag descriptor — a row of `%Image::ExifTool::GPS::Main`.
#[derive(Debug, Clone, Copy)]
pub struct GpsTag {
  /// On-disk tag ID (`%GPS::Main` hash key).
  pub id: u16,
  /// Tag NAME (`Name => '…'`).
  pub name: &'static str,
  /// The conversion ExifTool applies.
  pub conv: GpsConv,
}

/// The ported `%Image::ExifTool::GPS::Main` (`GPS.pm:50-353`). The GPS IFD
/// has NO further SubDirectory tags, so this is a flat leaf table.
pub const GPS_TAGS: &[GpsTag] = &[
  GpsTag {
    id: 0x0000,
    name: "GPSVersionID",
    conv: GpsConv::VersionId,
  },
  GpsTag {
    id: 0x0001,
    name: "GPSLatitudeRef",
    conv: GpsConv::StrLabel(GPS_LAT_REF),
  },
  GpsTag {
    id: 0x0002,
    name: "GPSLatitude",
    conv: GpsConv::Coordinate,
  },
  GpsTag {
    id: 0x0003,
    name: "GPSLongitudeRef",
    conv: GpsConv::StrLabel(GPS_LON_REF),
  },
  GpsTag {
    id: 0x0004,
    name: "GPSLongitude",
    conv: GpsConv::Coordinate,
  },
  GpsTag {
    id: 0x0005,
    name: "GPSAltitudeRef",
    // No `PrintHex`; the `OTHER` sub returns `undef` on READ (it only maps the
    // WRITE/inverse path, GPS.pm:107-110), so a read miss takes the decimal
    // `Unknown (N)` fallback — `Conv::IntLabel`.
    conv: GpsConv::Plain(Conv::IntLabel(GPS_ALTITUDE_REF)),
  },
  GpsTag {
    id: 0x0006,
    name: "GPSAltitude",
    conv: GpsConv::Plain(Conv::MetersSuffix),
  },
  GpsTag {
    id: 0x0007,
    name: "GPSTimeStamp",
    conv: GpsConv::TimeStamp,
  },
  GpsTag {
    id: 0x0008,
    name: "GPSSatellites",
    conv: GpsConv::Plain(Conv::None),
  },
  GpsTag {
    id: 0x0009,
    name: "GPSStatus",
    conv: GpsConv::StrLabel(GPS_STATUS),
  },
  GpsTag {
    id: 0x000a,
    name: "GPSMeasureMode",
    conv: GpsConv::StrLabel(GPS_MEASURE_MODE),
  },
  GpsTag {
    id: 0x000b,
    name: "GPSDOP",
    conv: GpsConv::Plain(Conv::None),
  },
  GpsTag {
    id: 0x000c,
    name: "GPSSpeedRef",
    conv: GpsConv::StrLabel(GPS_SPEED_REF),
  },
  GpsTag {
    id: 0x000d,
    name: "GPSSpeed",
    conv: GpsConv::Plain(Conv::None),
  },
  GpsTag {
    id: 0x000e,
    name: "GPSTrackRef",
    conv: GpsConv::StrLabel(GPS_DIRECTION_REF),
  },
  GpsTag {
    id: 0x000f,
    name: "GPSTrack",
    conv: GpsConv::Plain(Conv::None),
  },
  GpsTag {
    id: 0x0010,
    name: "GPSImgDirectionRef",
    conv: GpsConv::StrLabel(GPS_DIRECTION_REF),
  },
  GpsTag {
    id: 0x0011,
    name: "GPSImgDirection",
    conv: GpsConv::Plain(Conv::None),
  },
  GpsTag {
    id: 0x0012,
    name: "GPSMapDatum",
    conv: GpsConv::Plain(Conv::None),
  },
  GpsTag {
    id: 0x0013,
    name: "GPSDestLatitudeRef",
    conv: GpsConv::StrLabel(GPS_LAT_REF),
  },
  GpsTag {
    id: 0x0014,
    name: "GPSDestLatitude",
    conv: GpsConv::Coordinate,
  },
  GpsTag {
    id: 0x0015,
    name: "GPSDestLongitudeRef",
    conv: GpsConv::StrLabel(GPS_LON_REF),
  },
  GpsTag {
    id: 0x0016,
    name: "GPSDestLongitude",
    conv: GpsConv::Coordinate,
  },
  GpsTag {
    id: 0x0017,
    name: "GPSDestBearingRef",
    conv: GpsConv::StrLabel(GPS_DIRECTION_REF),
  },
  GpsTag {
    id: 0x0018,
    name: "GPSDestBearing",
    conv: GpsConv::Plain(Conv::None),
  },
  GpsTag {
    id: 0x0019,
    name: "GPSDestDistanceRef",
    conv: GpsConv::StrLabel(GPS_DEST_DISTANCE_REF),
  },
  GpsTag {
    id: 0x001a,
    name: "GPSDestDistance",
    conv: GpsConv::Plain(Conv::None),
  },
  // GPSProcessingMethod / GPSAreaInformation use ConvertExifText (an 8-byte
  // charset-id prefix + payload — Exif.pm:5554-5601, GPS.pm:299/305).
  GpsTag {
    id: 0x001b,
    name: "GPSProcessingMethod",
    conv: GpsConv::ExifText,
  },
  GpsTag {
    id: 0x001c,
    name: "GPSAreaInformation",
    conv: GpsConv::ExifText,
  },
  GpsTag {
    id: 0x001d,
    name: "GPSDateStamp",
    conv: GpsConv::DateStamp,
  },
  GpsTag {
    id: 0x001e,
    name: "GPSDifferential",
    conv: GpsConv::Plain(Conv::IntLabel(GPS_DIFFERENTIAL)),
  },
  GpsTag {
    id: 0x001f,
    name: "GPSHPositioningError",
    conv: GpsConv::Plain(Conv::MetersSuffix),
  },
];

/// Resolve a GPS tag ID against [`GPS_TAGS`]. `None` for an unknown ID.
///
/// The hand [`GPS_TAGS`] is consulted FIRST; on a miss the `--kind exif`
/// generated shadow ([`generated::lookup`]) is the fallback. Step A's shadow is
/// a strict subset of the hand table, so this fallback is currently inert — the
/// wiring is in place for a future Step B that adds GPS tags beyond the hand set.
#[must_use]
pub fn lookup(id: u16) -> Option<&'static GpsTag> {
  GPS_TAGS
    .iter()
    .find(|t| t.id == id)
    .or_else(|| generated::lookup(id))
}

/// The READ-side `Format` override (`$$tagInfo{Format}`, `Exif.pm:6729`)
/// resolved against `%Image::ExifTool::GPS::Main`, the SAME tag table the GPS
/// leaf emits under. Like its `%Exif::Main` sibling
/// ([`crate::exif::tables::format_override`]) the override is applied to
/// `$formatStr`/`$format`/`$count` BEFORE `ReadValue` (`Exif.pm:6735-6744`):
/// the on-disk byte `$size` is preserved and `$count = int($size /
/// $formatSize[$format])`.
///
/// In the GPS table exactly ONE tag carries such an override: `GPSDateStamp`
/// (0x001d), `Format => 'undef'` (`GPS.pm:312`), with the Phil-Harvey comment
/// "(Casio EX-H20G uses "\0" instead of ":" as a separator)". Forcing `undef`
/// BEFORE `ReadValue` stops a `string`-on-disk `GPSDateStamp` (the table's
/// `Writable => 'string'`, `GPS.pm:311`) from being NUL-trimmed: the bytes
/// `2024\0 05\0 22\0` would otherwise truncate at the FIRST NUL to `2024`
/// (`ifd.rs:469-472`), collapsing the date to just the year. Read as `undef`
/// the interior NULs survive, the RawConv `$val=~s/\0+$//` (`GPS.pm:319`)
/// drops only the trailing run, and `ExifDate` (`GPS.pm:320`) re-separates the
/// 8 digits to `YYYY:MM:DD`.
///
/// NOTE the contrast with the GPS text tags `GPSProcessingMethod` (0x001b) /
/// `GPSAreaInformation` (0x001c): those carry `Writable => 'undef'` but NOT
/// `Format => 'undef'` (`GPS.pm:296/304`), so `$$tagInfo{Format}` is unset and
/// a `string`-on-disk GPS text tag IS NUL-trimmed by bundled ExifTool. The
/// override is keyed on `Format`, not `Writable`, so it applies to 0x001d only.
#[must_use]
pub const fn format_override(id: u16) -> Option<crate::exif::ifd::Format> {
  match id {
    0x001d => Some(crate::exif::ifd::Format::Undef),
    _ => None,
  }
}

/// Look up `code` in a `(str, label)` slice (`StrLabel` PrintConv).
#[must_use]
pub fn str_label_for(slice: &[(&'static str, &'static str)], code: &str) -> Option<&'static str> {
  slice.iter().find_map(|&(k, v)| (k == code).then_some(v))
}

// ===========================================================================
// GPS coordinate conversion — ToDegrees / ToDMS (GPS.pm:495-601)
// ===========================================================================

/// `ToDegrees($val)` (`GPS.pm:582-601`) — ValueConv for `%coordConv`.
/// Collapses up to three numbers (D, M, S) to decimal degrees:
/// `$deg = $d + (($m||0) + ($s||0)/60) / 60`.
///
/// We feed it the already-decoded D/M/S floats (the rationals' quotients);
/// `inf`/`undef` rationals are passed as `None` so the bundled `return ''`
/// guard (`GPS.pm:584`) maps to a `None` result.
#[must_use]
pub fn to_degrees(d: Option<f64>, m: Option<f64>, s: Option<f64>) -> Option<f64> {
  // `return '' if $val =~ /\b(inf|undef)\b/` — any non-finite component
  // aborts the conversion.
  let d = d?;
  if !d.is_finite() {
    return None;
  }
  let m = m.unwrap_or(0.0);
  let s = s.unwrap_or(0.0);
  if !m.is_finite() || !s.is_finite() {
    return None;
  }
  // `$deg = $d + (($m||0) + ($s||0)/60) / 60`
  Some(d + (m + s / 60.0) / 60.0)
}

/// `ToDMS($self, $val, 1)` (`GPS.pm:495-573`) — the PrintConv for
/// `%coordConv`, with `$doPrintConv == 1` and NO `$ref` argument (the
/// `GPS:GPSLatitude` tag itself; the Composite layer adds the N/S/E/W
/// suffix, which is deferred crate-wide).
///
/// With the default (empty) `CoordFormat` option the format is
/// `q{%d deg %d' %.2f"}` (`GPS.pm:524`) and `$num == 3`. The algorithm
/// (`GPS.pm:546-564`):
/// ```text
/// $val = abs($val);
/// $c[0] = int($val);
/// $c[1] = int(($val - $c[0]) * 60);
/// $c[2] = ($val - $c[0] - $c[1]/60) * 3600;
/// $c[2] = sprintf('%.2f', $c[2]);  # the last-coordinate format
/// if ($c[2] >= 60) { $c[2] -= 60; ++$c[1] >= 60 and $c[1] -= 60, ++$c[0] }
/// return sprintf(q{%d deg %d' %.2f"}, @c);
/// ```
#[must_use]
pub fn to_dms(val: f64) -> std::string::String {
  // No `$ref` ⇒ `$val = abs($val)` (GPS.pm:543). Note Perl does NOT
  // short-circuit a non-finite value: `length $val` is non-zero for the
  // string `"Inf"`/`"NaN"`, so the full DMS computation runs and propagates
  // `Inf`/`NaN` through `int`/`%d`/`%.2f` (e.g. `ToDMS(Inf)` →
  // `Inf deg NaN' NaN"`, `ToDMS(NaN)` → `NaN deg NaN' NaN"`). `abs(NaN)` is
  // NaN; `abs(-Inf)` is Inf.
  let val = val.abs();
  // `$num = 3` (no CoordFormat). `$c[0] = int($val)` — truncate toward 0.
  let mut c0 = val.trunc();
  // `$c[1] = ($val - $c[0]) * 60`, then `$c[1] = int($c[1])`.
  let mut c1 = ((val - c0) * 60.0).trunc();
  // `$c[2] = ($val - $c[0] - $c[1]/60) * 3600`.
  let c2_raw = (val - c0 - c1 / 60.0) * 3600.0;
  // `$c[-1] = sprintf($fmt[-1], $c[-1])` — the last coordinate is formatted
  // with `%.2f` BEFORE the round-off carry test (GPS.pm:558).
  let mut c2_str = perl_f2(c2_raw);
  // `if ($c[-1] >= 60)` — the carry test compares the FORMATTED string
  // numerically (Perl auto-stringifies; "60.00" >= 60 is true). A non-finite
  // `c2_str` ("NaN"/"Inf") parses back to NaN/Inf: `NaN >= 60` is false (no
  // carry, the degenerate path), matching Perl.
  if let Ok(c2_num) = c2_str.parse::<f64>()
    && c2_num >= 60.0
  {
    let carried = c2_num - 60.0;
    c2_str = perl_f2(carried);
    c1 += 1.0;
    if c1 >= 60.0 {
      c1 -= 60.0;
      c0 += 1.0;
    }
  }
  // `sprintf(q{%d deg %d' %.2f"}, @c)` — `%d` truncates the float to int.
  std::format!("{} deg {}' {}\"", perl_d(c0), perl_d(c1), c2_str)
}

/// Perl `sprintf("%d", $x)` of an (already integer-valued / truncated) `f64`.
/// For a finite value this is the truncated integer (`$x` here is always a
/// `.trunc()` result, so the cast is exact); for a non-finite value Perl prints
/// `Inf` / `-Inf` / `NaN` (titlecase) rather than Rust's lowercase `inf`/`nan`
/// or a saturating `as i64` cast (`Inf as i64` would be `i64::MAX`).
fn perl_d(x: f64) -> std::string::String {
  use std::string::ToString;
  match crate::value::perl_nonfinite_str(x) {
    Some(s) => s.to_string(),
    None => (x as i64).to_string(),
  }
}

/// Perl `sprintf("%.2f", $x)` of an `f64`. Finite values format identically to
/// Rust `{:.2}`; non-finite values print Perl's `Inf` / `-Inf` / `NaN`
/// (titlecase) instead of Rust's lowercase `inf` (NaN already matches).
fn perl_f2(x: f64) -> std::string::String {
  match crate::value::perl_nonfinite_str(x) {
    Some(s) => s.to_string(),
    None => std::format!("{x:.2}"),
  }
}

// ===========================================================================
// GPS timestamp conversion — ConvertTimeStamp / PrintTimeStamp (GPS.pm:455-487)
// ===========================================================================

/// `ConvertTimeStamp($val)` (`GPS.pm:459-475`) — the `GPSTimeStamp`
/// ValueConv. Input is the 3 rational quotients (H, M, S); output is the
/// EXIF-formatted `HH:MM:SS[.ffffffff]` string:
/// ```text
/// my ($h,$m,$s) = split ' ', $val;
/// my $f = (($h||0)*60 + ($m||0))*60 + ($s||0);
/// $h = int($f/3600); $f -= $h*3600;
/// $m = int($f/60);   $f -= $m*60;
/// my $ss = sprintf('%012.9f', $f);
/// if ($ss >= 60) { $ss = '00'; ++$m >= 60 and $m -= 60, ++$h }
/// else { $ss =~ s/\.?0+$//; }       # trim trailing zeros + decimal
/// return sprintf("%.2d:%.2d:%s", $h, $m, $ss);
/// ```
#[must_use]
pub fn convert_time_stamp(h: f64, m: f64, s: f64) -> std::string::String {
  use std::string::ToString;
  // Non-finite components are degenerate; Perl `split ' '` on an `inf`
  // string would still parse, but the on-disk GPSTimeStamp is always finite
  // rationals — defend by passing through a recognizable form.
  if !h.is_finite() || !m.is_finite() || !s.is_finite() {
    return std::format!("{h} {m} {s}");
  }
  // `$f = (($h||0)*60 + ($m||0))*60 + ($s||0)` — total seconds.
  let f_total = (h * 60.0 + m) * 60.0 + s;
  // `$h = int($f/3600); $f -= $h*3600;`
  let hh = (f_total / 3600.0).trunc();
  let f1 = f_total - hh * 3600.0;
  // `$m = int($f/60); $f -= $m*60;`
  let mm = (f1 / 60.0).trunc();
  let f2 = f1 - mm * 60.0;
  // `$ss = sprintf('%012.9f', $f)` — 12-wide, 9 fractional digits.
  let mut ss = std::format!("{f2:012.9}");
  let (mut hh, mut mm) = (hh, mm);
  // `if ($ss >= 60)` — numeric compare on the formatted string.
  if ss.parse::<f64>().is_ok_and(|n| n >= 60.0) {
    ss = "00".to_string();
    mm += 1.0;
    if mm >= 60.0 {
      mm -= 60.0;
      hh += 1.0;
    }
  } else {
    // `s/\.?0+$//` — trim trailing zeros, then a bare trailing `.`.
    let trimmed = ss.trim_end_matches('0');
    let trimmed = trimmed.strip_suffix('.').unwrap_or(trimmed);
    ss = trimmed.to_string();
  }
  // `sprintf("%.2d:%.2d:%s", $h, $m, $ss)`.
  std::format!("{:02}:{:02}:{}", hh as i64, mm as i64, ss)
}

/// `PrintTimeStamp($val)` (`GPS.pm:480-487`) — the `GPSTimeStamp` PrintConv:
/// ```text
/// return $val unless $val =~ s/:(\d{2}\.\d+)$//;
/// my $s = int($1 * 1000000 + 0.5) / 1000000;
/// $s = "0$s" if $s < 10;
/// return "${val}:$s";
/// ```
/// Rounds the seconds field to the nearest microsecond. If there is no
/// fractional-seconds part, the value is returned unchanged.
#[must_use]
pub fn print_time_stamp(val: &str) -> std::string::String {
  use std::string::ToString;
  // `$val =~ s/:(\d{2}\.\d+)$//` — the last `:SS.ffff` group.
  let Some(colon) = val.rfind(':') else {
    return val.to_string();
  };
  // `colon` is the byte index of an ASCII `:` (a char boundary) returned by
  // `rfind`, so `colon < val.len()`: `val.get(..colon)` / `val.get(colon+1..)`
  // are both `Some` — the checked, byte-identical form of `&val[..colon]` /
  // `&val[colon+1..]` (the `.unwrap_or(val)` / `.unwrap_or("")` fallbacks are
  // unreachable).
  let (head, sec_part) = (
    val.get(..colon).unwrap_or(val),
    val.get(colon + 1..).unwrap_or(""),
  );
  // The captured group must be exactly `\d{2}\.\d+`. The `[d0, d1, b'.', f0,
  // rest @ ..]` slice pattern requires ≥ 4 bytes (the old `len > 3` guard PLUS
  // the `\d+`'s ≥ 1 fractional digit `f0`) and binds them — the checked,
  // byte-identical form of `bytes[0]`/`bytes[1]`/`bytes[2]`/`bytes[3..]`.
  let is_ss_frac = matches!(
    sec_part.as_bytes(),
    [d0, d1, b'.', f0, rest @ ..]
      if d0.is_ascii_digit()
        && d1.is_ascii_digit()
        && f0.is_ascii_digit()
        && rest.iter().all(u8::is_ascii_digit)
  );
  if !is_ss_frac {
    return val.to_string();
  }
  let Ok(sec) = sec_part.parse::<f64>() else {
    return val.to_string();
  };
  // `int($1 * 1000000 + 0.5) / 1000000` — round to microsecond.
  let rounded = (sec * 1_000_000.0 + 0.5).trunc() / 1_000_000.0;
  // `$s = "0$s" if $s < 10` — Perl stringifies the float compactly.
  let mut s = compact_num(rounded);
  if rounded < 10.0 {
    s = std::format!("0{s}");
  }
  std::format!("{head}:{s}")
}

/// `ExifDate($val)` (`Exif.pm:6068-6076`) — the `GPSDateStamp` ValueConv.
///
/// Faithful transliteration of the two Perl statements:
/// ```text
/// $date =~ s/\0$//;                                       # strip ONE trailing NUL
/// $date =~ s/(\d{4})[^\d]*(\d{2})[^\d]*(\d{2})$/$1:$2:$3/; # END-ANCHORED subst
/// ```
/// The substitution is a SINGLE (non-`/g`) end-anchored match: it rewrites
/// ONLY the matched `YYYY…MM…DD`-shaped suffix to `YYYY:MM:DD`, preserves any
/// prefix BEFORE the match verbatim, and leaves the string UNCHANGED when no
/// such suffix exists. (This is NOT "take the last 8 digits": for
/// `"123456789"` Perl yields `"12345:67:89"` — the leftmost start that can
/// reach the end keeps the leading `1` as a prefix.)
#[must_use]
pub fn exif_date(val: &str) -> std::string::String {
  use std::string::ToString;
  // `$date =~ s/\0$//` — drop a single trailing NUL (the RawConv already
  // dropped any run; defend anyway). Perl `$` strips exactly one.
  let val = val.strip_suffix('\0').unwrap_or(val);
  // `s/(\d{4})[^\d]*(\d{2})[^\d]*(\d{2})$/$1:$2:$3/` — re-separate the
  // trailing date with colons. The bundled `GPSDateStamp` is already
  // `YYYY:MM:DD`, so the regex usually matches a no-op; the same transform
  // is faithful for the Casio EX-H20G `\0`-separated variant and the
  // `2003-10-22` / `20031022` / `2003/10/22` bad-format variants the Perl
  // comment lists.
  match reseparate_date(val) {
    Some(date) => date,
    None => val.to_string(),
  }
}

/// Hand-rolled equivalent of the end-anchored substitution
/// `s/(\d{4})[^\d]*(\d{2})[^\d]*(\d{2})$/$1:$2:$3/` (the `regex` crate is not
/// a dependency). Returns the rewritten string (prefix preserved + matched
/// suffix recoloned), or `None` when the pattern does not match at the end —
/// in which case the caller leaves the value UNCHANGED.
///
/// Reproduces Perl's leftmost-match-that-reaches-`$` semantics: scan the
/// start of `$1` left-to-right and take the FIRST position from which an
/// end-anchored match exists. Within a start attempt the two `[^\d]*` groups
/// are greedy — but since `[^\d]` and `\d` are disjoint, "skip the maximal
/// non-digit run, then require N digits" is deterministic (no intra-attempt
/// backtracking): if the digit/non-digit layout from this start cannot reach
/// the end, the start advances. `\d` is treated as ASCII `0-9` (GPSDateStamp
/// is ASCII per Exif §4.6.6; the bundled-Perl outputs match byte-for-byte on
/// the ASCII inputs). Byte indexing is UTF-8-safe here: an ASCII digit is a
/// single byte and always a char boundary, so the preserved prefix is valid
/// UTF-8.
fn reseparate_date(val: &str) -> Option<std::string::String> {
  let b = val.as_bytes();
  // `b.get(i).is_some_and(..)` folds the explicit `i < b.len()` bound into the
  // checked access — byte-identical to `i < b.len() && b[i].is_ascii_digit()`.
  let is_digit = |i: usize| b.get(i).is_some_and(u8::is_ascii_digit);
  // Maximal `[^\d]*` run starting at `i` (greedy; matches non-digit bytes).
  let skip_non_digits = |mut i: usize| {
    while b.get(i).is_some_and(|c| !c.is_ascii_digit()) {
      i += 1;
    }
    i
  };
  // Leftmost start `s` of the `\d{4}` group that yields an end-anchored match.
  for s in 0..b.len() {
    // `(\d{4})` — four digits at `s`.
    if !(is_digit(s) && is_digit(s + 1) && is_digit(s + 2) && is_digit(s + 3)) {
      continue;
    }
    // `[^\d]*` then `(\d{2})`.
    let p1 = skip_non_digits(s + 4);
    if !(is_digit(p1) && is_digit(p1 + 1)) {
      continue;
    }
    // `[^\d]*` then `(\d{2})` — and the second `\d{2}` must end the string.
    let p2 = skip_non_digits(p1 + 2);
    if is_digit(p2) && is_digit(p2 + 1) && p2 + 2 == b.len() {
      // Rewrite the matched span `[s, len)` to `$1:$2:$3`, preserving the
      // `[0, s)` prefix verbatim (Perl's substitution replaces only the
      // matched portion). Every span boundary here was just proven by the
      // `is_digit(..)` checks above (`s+4`/`p1+2`/`p2+2 <= b.len()`) and lands
      // on an ASCII-digit char boundary, so each `val.get(range)` is `Some` —
      // the checked, byte-identical form of the `&val[range]` reads (the `""`
      // fallbacks are unreachable).
      let mut out = std::string::String::with_capacity(s + 10);
      out.push_str(val.get(..s).unwrap_or(""));
      out.push_str(val.get(s..s + 4).unwrap_or("")); // $1 (year)
      out.push(':');
      out.push_str(val.get(p1..p1 + 2).unwrap_or("")); // $2 (month)
      out.push(':');
      out.push_str(val.get(p2..p2 + 2).unwrap_or("")); // $3 (day)
      return Some(out);
    }
  }
  None
}

/// Perl-compact float stringification — Perl's default `"$float"` drops a
/// trailing `.0` (an integer-valued float prints as `"5"`, not `"5.0"`).
fn compact_num(v: f64) -> std::string::String {
  use std::string::ToString;
  if v.is_finite() && v == v.trunc() {
    return std::format!("{}", v as i64);
  }
  v.to_string()
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2d); relaxed for the test module (test indexing is an
// assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  #[test]
  fn format_override_targets_datestamp_only() {
    use crate::exif::ifd::Format;
    // GPSDateStamp (0x001d) carries `Format => 'undef'` (GPS.pm:312).
    assert_eq!(format_override(0x001d), Some(Format::Undef));
    // GPS text tags carry only `Writable => 'undef'` (GPS.pm:296/304), NOT a
    // `Format` override — a string-on-disk value IS NUL-trimmed by bundled.
    assert_eq!(format_override(0x001b), None);
    assert_eq!(format_override(0x001c), None);
    // Unrelated GPS tags have no override.
    assert_eq!(format_override(0x0002), None);
  }

  #[test]
  fn lookup_finds_gps_tags() {
    assert_eq!(lookup(0x0002).map(|t| t.name), Some("GPSLatitude"));
    assert_eq!(lookup(0x0004).map(|t| t.name), Some("GPSLongitude"));
    assert_eq!(lookup(0x0007).map(|t| t.name), Some("GPSTimeStamp"));
    assert_eq!(lookup(0x001d).map(|t| t.name), Some("GPSDateStamp"));
    assert!(lookup(0xff00).is_none());
  }

  #[test]
  fn to_degrees_collapses_dms() {
    // 54° 59' 22.80" → 54.9896666...° (GPS.jpg fixture coordinate).
    let deg = to_degrees(Some(54.0), Some(59.0), Some(22.8)).unwrap();
    assert!((deg - 54.989_666_666_666_7).abs() < 1e-9, "got {deg}");
    // A None / non-finite component aborts.
    assert_eq!(to_degrees(Some(f64::INFINITY), Some(0.0), Some(0.0)), None);
  }

  #[test]
  fn to_dms_formats_coordinate() {
    // 54.9896666...° → `54 deg 59' 22.80"` (GPS.jpg fixture, -j output).
    let s = to_dms(54.989_666_666_666_7);
    assert_eq!(s, "54 deg 59' 22.80\"");
    // 1.91416666...° → `1 deg 54' 51.00"`.
    let s = to_dms(1.914_166_666_666_67);
    assert_eq!(s, "1 deg 54' 51.00\"");
  }

  #[test]
  fn to_dms_non_finite_matches_perl_inf_nan() {
    // Perl's `GPS::ToDMS` does NOT short-circuit a non-finite value: the full
    // DMS computation runs and propagates Inf/NaN through `int`/`%d`/`%.2f`,
    // which Perl prints TITLECASE. Oracle (bundled 13.59,
    // `GPS::ToDMS($et, $v, 1, "N")`):
    //   inf  → `Inf deg NaN' NaN"` ; nan → `NaN deg NaN' NaN"`.
    // `to_dms` formats only the magnitude (the ref letter is added by the
    // caller); `abs(-Inf)` = Inf, so -inf yields the same magnitude as inf.
    assert_eq!(to_dms(f64::INFINITY), "Inf deg NaN' NaN\"");
    assert_eq!(to_dms(f64::NEG_INFINITY), "Inf deg NaN' NaN\"");
    assert_eq!(to_dms(f64::NAN), "NaN deg NaN' NaN\"");
  }

  #[test]
  fn convert_time_stamp_faithful() {
    // 14h 58m 24s → "14:58:24" (GPS.jpg fixture GPSTimeStamp).
    let s = convert_time_stamp(14.0, 58.0, 24.0);
    assert_eq!(s, "14:58:24");
  }

  #[test]
  fn print_time_stamp_no_fraction_is_identity() {
    // "14:58:24" has no `:SS.ffff` group ⇒ returned unchanged.
    assert_eq!(print_time_stamp("14:58:24"), "14:58:24");
  }

  #[test]
  fn print_time_stamp_rounds_microseconds() {
    // "12:00:01.5000005" → seconds rounded to "01.500001".
    let s = print_time_stamp("12:00:01.5000005");
    assert_eq!(s, "12:00:01.500001");
  }

  #[test]
  fn exif_date_reseparates() {
    // Already-colon-separated → unchanged form (the subst is a no-op match).
    assert_eq!(exif_date("2002:06:20"), "2002:06:20");
    assert_eq!(exif_date("2024:01:15"), "2024:01:15");
    // NUL-separated (Casio EX-H20G uses "\0" instead of ":") → colon form.
    assert_eq!(exif_date("2002\0\u{0}06\0\u{0}20"), "2002:06:20");
    // The bad-format variants the Perl comment lists.
    assert_eq!(exif_date("20031022"), "2003:10:22");
    assert_eq!(exif_date("2003-10-22"), "2003:10:22");
    assert_eq!(exif_date("2003/10/22"), "2003:10:22");
    assert_eq!(exif_date("2003 10 22"), "2003:10:22");
    // Trailing NUL stripped (exactly one — Perl `$`).
    assert_eq!(exif_date("2002:06:20\0"), "2002:06:20");
  }

  #[test]
  fn exif_date_preserves_prefix_and_no_match() {
    // PREFIX preserved: the match is end-anchored, NOT "last 8 digits".
    // "blah " precedes an already-colon date ⇒ the no-op subst keeps it.
    assert_eq!(exif_date("blah 2024:01:15"), "blah 2024:01:15");
    // Leftmost start that reaches the end keeps the leading "1" as a prefix
    // (bundled `perl exiftool`: ExifDate("123456789") == "12345:67:89").
    assert_eq!(exif_date("123456789"), "12345:67:89");
    // Mixed prefix (bundled: "12 2024-01-15" → "12 2024:01:15").
    assert_eq!(exif_date("12 2024-01-15"), "12 2024:01:15");
    // The leftmost-`\d{4}` start that can reach the end skips earlier digit
    // runs blocked by interior digits (bundled: "0000aa1122bb3344" →
    // "0000aa1122:33:44").
    assert_eq!(exif_date("0000aa1122bb3344"), "0000aa1122:33:44");

    // NO MATCH at the end ⇒ value returned UNCHANGED.
    // Trailing space ⇒ the final `\d{2}$` cannot match ⇒ space KEPT.
    assert_eq!(exif_date("2024:01:15 "), "2024:01:15 ");
    // A trailing time defeats the end-anchor (last 2 chars "45" match $3 but
    // the `\d{4}…\d{2}…\d{2}$` shape cannot align) — bundled returns it
    // unchanged.
    assert_eq!(exif_date("2024:01:15 12:30:45"), "2024:01:15 12:30:45");
    // No digits at all ⇒ unchanged.
    assert_eq!(exif_date("justtext"), "justtext");
    // Trailing non-digits after a date ⇒ no end-anchored match ⇒ unchanged.
    assert_eq!(exif_date("20031022extra"), "20031022extra");
  }

  /// THE PARITY PROOF (table-codegen Step A): the `--kind exif` generated GPS
  /// shadow (`gps_generated.rs`) must reproduce EVERY hand [`GPS_TAGS`] row
  /// byte-identically — same NAME and same [`GpsConv`] (slice contents and all).
  #[test]
  fn generated_shadow_matches_hand_table() {
    for hand in GPS_TAGS {
      let shadow = generated::lookup(hand.id).unwrap_or_else(|| {
        panic!(
          "generated GPS shadow is MISSING hand id {:#06x} ({})",
          hand.id, hand.name
        )
      });
      assert_eq!(
        shadow.name, hand.name,
        "name mismatch at id {:#06x}: generated={:?} hand={:?}",
        hand.id, shadow.name, hand.name
      );
      assert_eq!(
        shadow.conv, hand.conv,
        "conv mismatch at id {:#06x} ({}): generated={:?} hand={:?}",
        hand.id, hand.name, shadow.conv, hand.conv
      );
    }
  }
}
