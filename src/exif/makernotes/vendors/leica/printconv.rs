// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Leica-specific PrintConv/ValueConv enum — covers the per-tag conversions in
//! the `%Image::ExifTool::Panasonic::Leica2`..`Leica9` MakerNote variant tables
//! (`Panasonic.pm:1604-2256`) plus the shared `%leicaLensTypes` lens lookup
//! (`Panasonic.pm:46-133`).
//!
//! Faithful 1:1 port against bundled ExifTool 13.59. Every variant is a named
//! arm with a `Panasonic.pm` citation, and the bundled label text is kept
//! verbatim. The big `%leicaLensTypes` lookup lives in [`lens_types`].

#![deny(clippy::indexing_slicing)]

use super::lens_types;
use crate::exif::ifd::RawValue;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

/// Per-tag conversion strategy for the Leica2..Leica9 IFD variant tables.
///
/// A Leica leaf renders the SAME way in both modes unless it carries a
/// `PrintConv` (the hash / `sprintf` rows): then `-j` applies the PrintConv and
/// `-n` keeps the ValueConv value. Where a row has a `ValueConv` (`LensType`,
/// the `/1e5` brightness rows, `FNumber`), that conversion applies in BOTH modes
/// — it is the value the PrintConv then formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeicaPrintConv {
  /// No conversion — emit the raw scalar/array (string/int/space-joined list).
  None,
  /// `Quality` (Leica2 0x300, `Panasonic.pm:1612`) — `1=>Fine, 2=>Basic`.
  Quality,
  /// `UserProfile` (Leica2 0x302, `Panasonic.pm:1617`) — int32u label hash.
  UserProfile2,
  /// `SerialNumber` (Leica2 0x303, `Panasonic.pm:1625`) — `sprintf("%.7d",$val)`.
  SerialNumber7,
  /// `WhiteBalance` (Leica2 0x304, `Panasonic.pm:1631`) — label hash with an
  /// `OTHER => \&WhiteBalanceConv` Kelvin fallback (`Panasonic.pm:2732`): a
  /// stored value `> 0x8000` renders `"<val-0x8000> Kelvin"`.
  WhiteBalance2,
  /// `LensType` (Leica2 0x310 / Subdir 0x3405 / Data1 0x0016, all
  /// `%leicaLensTypes`) — the `($val>>2)." ".($val&0x3)` ValueConv then the
  /// `%leicaLensTypes` lookup (with its leading-integer `OTHER` fallback).
  LensType,
  /// `sprintf("%.2f",$val)` on a (signed) rational — the
  /// `ExternalSensorBrightnessValue` / `MeasuredLV` rows whose value is the raw
  /// rational (Leica2 0x311/0x312, Leica6/Leica9 0x311/0x312).
  Sprintf2f,
  /// `ApproximateFNumber` (Leica2 0x313 / Subdir 0x3406, `Panasonic.pm:1650`) —
  /// `sprintf("%.1f",$val)` on a rational.
  Sprintf1f,
  /// `CameraTemperature` (Leica2 0x320 / Subdir 0x3402 / Leica6 …) — int32s,
  /// `"$val C"`.
  CameraTemperatureC,
  /// `UV-IRFilterCorrection` (Leica2 0x325, `Panasonic.pm:1668`) —
  /// `0=>'Not Active', 1=>'Active'`.
  UvIrFilterCorrection,
  /// `MeasuredLV` (Subdir 0x3407 / 0x3408, `Panasonic.pm`) — int32s,
  /// ValueConv `$val / 1e5` then `sprintf("%.2f",$val)`.
  Div1e5Sprintf2f,
  /// `Contrast` (Subdir 0x300a) — `0=>Low,1=>Medium Low,2=>Normal,
  /// 3=>Medium High,4=>High`.
  ContrastLevel,
  /// `Sharpening` (Subdir 0x300b) — `0=>Off,1=>Low,2=>Normal,3=>Medium High,
  /// 4=>High`.
  Sharpening,
  /// `Saturation` (Subdir 0x300d) — the Contrast hash plus
  /// `5=>'Black & White', 6=>'Vintage B&W'`.
  SaturationLevel,
  /// `WhiteBalance` (Subdir 0x3033) — the M9 white-balance hash.
  WhiteBalanceM9,
  /// `JPEGQuality` (Subdir 0x3034) — `94=>Basic, 97=>Fine`.
  JpegQuality,
  /// `JPEGSize` (Subdir 0x303a) — the M9 resolution hash.
  JpegSize,
  /// `LensTypeTrim` (Leica6 0x303, `Panasonic.pm:2150`) — string, ValueConv
  /// `$val=~s/ +$//` (trailing-space trim), no PrintConv.
  LensTypeTrim,
  /// `FirmwareVersion` (Leica6 0x320, `Panasonic.pm:2174`) — `$val=~tr/ /./`
  /// (spaces → dots) over the int8u[4] value.
  FirmwareVersionDots,
  /// `LensSerialNumber` (Leica6 0x321, `Panasonic.pm:2184`) —
  /// `sprintf("%.10d",$val)`.
  Sprintf10d,
  /// `ExposureMode` (Leica5 0x040d, `Panasonic.pm:2047`) — `Format =>
  /// 'int8u', Count => 4`, a PrintConv hash keyed by the space-joined int8u[4]
  /// string (`'0 0 0 0' => 'Program AE'`, …).
  ExposureMode5,
  /// `InternalSerialNumber` (Leica5 0x0500, `Panasonic.pm:2047`) — `undef`,
  /// PrintConv decodes the embedded date: a value matching
  /// `^(.{3})(\d{2})(\d{2})(\d{2})(\d{4})` renders `"($1) YYYY:$3:$4 no. $5"`
  /// (year = `$2 + ($2<70 ? 2000 : 1900)`); otherwise the raw `$val` passes
  /// through. `-n` keeps the raw `undef` bytes.
  InternalSerialNumber,
  /// `ISOSelected` (Leica9 0x359, `Panasonic.pm:2221`) — `0=>'Auto'`, with an
  /// `OTHER => sub{ return shift }` identity passthrough.
  IsoSelected,
  /// `FNumber` (Leica9 0x35a, `Panasonic.pm:2227`) — int32s, ValueConv
  /// `$val / 1000` then `sprintf("%.1f",$val)`.
  Div1000Sprintf1f,
}

impl LeicaPrintConv {
  /// Apply the conversion to a raw value, producing the rendered [`TagValue`]
  /// for the requested mode (`print_conv` = `-j` PrintConv, else `-n`
  /// ValueConv).
  #[must_use]
  pub fn apply(self, raw: &RawValue, print_conv: bool) -> TagValue {
    match self {
      LeicaPrintConv::None => raw_to_tag_value(raw),
      LeicaPrintConv::Quality => simple_label(raw, print_conv, |n| match n {
        1 => Some("Fine"),
        2 => Some("Basic"),
        _ => None,
      }),
      LeicaPrintConv::UserProfile2 => simple_label(raw, print_conv, |n| match n {
        1 => Some("User Profile 1"),
        2 => Some("User Profile 2"),
        3 => Some("User Profile 3"),
        4 => Some("User Profile 0 (Dynamic)"),
        _ => None,
      }),
      LeicaPrintConv::SerialNumber7 => {
        let Some(n) = first_i64(raw) else {
          return raw_to_tag_value(raw);
        };
        if !print_conv {
          return TagValue::I64(n);
        }
        TagValue::Str(SmolStr::from(sprintf_zero_pad(n, 7)))
      }
      LeicaPrintConv::WhiteBalance2 => {
        let Some(n) = first_i64(raw) else {
          return raw_to_tag_value(raw);
        };
        if !print_conv {
          return TagValue::I64(n);
        }
        // The hash (`Panasonic.pm:1633-1640`) first; then the `OTHER` Kelvin
        // fallback (`WhiteBalanceConv`, `Panasonic.pm:2732`): `$val > 0x8000`
        // ⇒ `"<val-0x8000> Kelvin"`. An unmatched value below 0x8000 returns
        // `undef` from `WhiteBalanceConv` ⇒ ExifTool's `PrintConv` falls back
        // to the raw value (the `Unknown (N)` form is for explicit hashes; an
        // OTHER that returns undef yields the raw `$val`).
        match n {
          0 => TagValue::Str("Auto or Manual".into()),
          1 => TagValue::Str("Daylight".into()),
          2 => TagValue::Str("Fluorescent".into()),
          3 => TagValue::Str("Tungsten".into()),
          4 => TagValue::Str("Flash".into()),
          10 => TagValue::Str("Cloudy".into()),
          11 => TagValue::Str("Shade".into()),
          _ if n > 0x8000 => TagValue::Str(SmolStr::from(std::format!("{} Kelvin", n - 0x8000))),
          // `WhiteBalanceConv` returns undef ⇒ raw `$val` passthrough.
          _ => TagValue::I64(n),
        }
      }
      LeicaPrintConv::LensType => lens_type(raw, print_conv),
      LeicaPrintConv::Sprintf2f => sprintf_rational(raw, print_conv, 2),
      LeicaPrintConv::Sprintf1f => sprintf_rational(raw, print_conv, 1),
      LeicaPrintConv::CameraTemperatureC => {
        let Some(n) = first_i64(raw) else {
          return raw_to_tag_value(raw);
        };
        if !print_conv {
          return TagValue::I64(n);
        }
        TagValue::Str(SmolStr::from(std::format!("{n} C")))
      }
      LeicaPrintConv::UvIrFilterCorrection => simple_label(raw, print_conv, |n| match n {
        0 => Some("Not Active"),
        1 => Some("Active"),
        _ => None,
      }),
      LeicaPrintConv::Div1e5Sprintf2f => {
        // int32s, ValueConv `$val / 1e5`, PrintConv `sprintf("%.2f",$val)`.
        let Some(n) = first_i64(raw) else {
          return raw_to_tag_value(raw);
        };
        let v = n as f64 / 1e5;
        if !print_conv {
          return TagValue::F64(v);
        }
        TagValue::Str(SmolStr::from(std::format!("{v:.2}")))
      }
      LeicaPrintConv::ContrastLevel => simple_label(raw, print_conv, contrast_label),
      LeicaPrintConv::Sharpening => simple_label(raw, print_conv, |n| match n {
        0 => Some("Off"),
        1 => Some("Low"),
        2 => Some("Normal"),
        3 => Some("Medium High"),
        4 => Some("High"),
        _ => None,
      }),
      LeicaPrintConv::SaturationLevel => simple_label(raw, print_conv, |n| match n {
        5 => Some("Black & White"),
        6 => Some("Vintage B&W"),
        other => contrast_label(other),
      }),
      LeicaPrintConv::WhiteBalanceM9 => simple_label(raw, print_conv, |n| match n {
        0 => Some("Auto"),
        1 => Some("Tungsten"),
        2 => Some("Fluorescent"),
        3 => Some("Daylight Fluorescent"),
        4 => Some("Daylight"),
        5 => Some("Flash"),
        6 => Some("Cloudy"),
        7 => Some("Shade"),
        8 => Some("Manual"),
        9 => Some("Kelvin"),
        _ => None,
      }),
      LeicaPrintConv::JpegQuality => simple_label(raw, print_conv, |n| match n {
        94 => Some("Basic"),
        97 => Some("Fine"),
        _ => None,
      }),
      LeicaPrintConv::JpegSize => simple_label(raw, print_conv, |n| match n {
        0 => Some("5216x3472"),
        1 => Some("3840x2592"),
        2 => Some("2592x1728"),
        3 => Some("1728x1152"),
        4 => Some("1280x864"),
        _ => None,
      }),
      LeicaPrintConv::LensTypeTrim => {
        // string, ValueConv `$val=~s/ +$//` (trim trailing spaces), no
        // PrintConv ⇒ identical under both modes.
        let s = text_value(raw);
        let Some(s) = s else {
          return raw_to_tag_value(raw);
        };
        TagValue::Str(SmolStr::from(s.trim_end_matches(' ')))
      }
      LeicaPrintConv::FirmwareVersionDots => {
        // int8u[4], PrintConv `$val=~tr/ /./` — the space-joined int8u array
        // with spaces turned into dots (e.g. `"1 2 3 4"` ⇒ `"1.2.3.4"`).
        // `-n` keeps the space-joined `$val`.
        let joined = match raw_to_tag_value(raw) {
          TagValue::Str(s) => s,
          TagValue::I64(n) => SmolStr::from(std::format!("{n}")),
          TagValue::U64(n) => SmolStr::from(std::format!("{n}")),
          other => return other,
        };
        if !print_conv {
          return TagValue::Str(joined);
        }
        TagValue::Str(SmolStr::from(joined.replace(' ', ".")))
      }
      LeicaPrintConv::Sprintf10d => {
        let Some(n) = first_i64(raw) else {
          return raw_to_tag_value(raw);
        };
        if !print_conv {
          return TagValue::I64(n);
        }
        TagValue::Str(SmolStr::from(sprintf_zero_pad(n, 10)))
      }
      LeicaPrintConv::ExposureMode5 => {
        // int8u[4] hash keyed by the space-joined value string. `-n` keeps the
        // space-joined raw; `-j` looks the string up, falling back to the raw
        // (Unknown form) on a miss.
        let key = match raw_to_tag_value(raw) {
          TagValue::Str(s) => s,
          other if !print_conv => return other,
          TagValue::I64(n) => SmolStr::from(std::format!("{n}")),
          TagValue::U64(n) => SmolStr::from(std::format!("{n}")),
          other => return other,
        };
        if !print_conv {
          return TagValue::Str(key);
        }
        let label = match key.as_str() {
          "0 0 0 0" => Some("Program AE"),
          "1 0 0 0" => Some("Aperture-priority AE"),
          "1 1 0 0" => Some("Aperture-priority AE (1)"),
          "2 0 0 0" => Some("Shutter speed priority AE"),
          "3 0 0 0" => Some("Manual"),
          _ => None,
        };
        match label {
          Some(l) => TagValue::Str(l.into()),
          None => TagValue::Str(SmolStr::from(std::format!("Unknown ({key})"))),
        }
      }
      LeicaPrintConv::InternalSerialNumber => {
        // `undef` ⇒ `raw` is `RawValue::Bytes`. `-n` keeps the raw value; `-j`
        // applies the date-decoding PrintConv on the ASCII text.
        if !print_conv {
          return raw_to_tag_value(raw);
        }
        let bytes = match raw {
          RawValue::Bytes(b) => b.as_slice(),
          RawValue::Text { raw: b, .. } => b.as_ref(),
          _ => return raw_to_tag_value(raw),
        };
        match decode_internal_serial(bytes) {
          Some(s) => TagValue::Str(SmolStr::from(s)),
          // No date match ⇒ the bundled `return $val` passthrough.
          None => raw_to_tag_value(raw),
        }
      }
      LeicaPrintConv::IsoSelected => {
        // int32s, `0=>'Auto'` with `OTHER => sub{ return shift }` (identity).
        let Some(n) = first_i64(raw) else {
          return raw_to_tag_value(raw);
        };
        if !print_conv {
          return TagValue::I64(n);
        }
        match n {
          0 => TagValue::Str("Auto".into()),
          // `OTHER` returns the value unchanged ⇒ the raw int.
          _ => TagValue::I64(n),
        }
      }
      LeicaPrintConv::Div1000Sprintf1f => {
        // int32s, ValueConv `$val / 1000`, PrintConv `sprintf("%.1f",$val)`.
        let Some(n) = first_i64(raw) else {
          return raw_to_tag_value(raw);
        };
        let v = n as f64 / 1000.0;
        if !print_conv {
          return TagValue::F64(v);
        }
        TagValue::Str(SmolStr::from(std::format!("{v:.1}")))
      }
    }
  }
}

/// Leica `LensType` (`Panasonic.pm:1644`) — the `($val>>2)." ".($val&0x3)`
/// ValueConv then the `%leicaLensTypes` lookup. The ValueConv splits the stored
/// int32u into `"<id> <bits>"`; the PrintConv tries the full `"id bits"` key,
/// then (the `%leicaLensTypes` `OTHER` closure, `Panasonic.pm:48-52`) strips
/// from the first space and re-looks-up the bare leading integer.
fn lens_type(raw: &RawValue, print_conv: bool) -> TagValue {
  let Some(n) = first_u64(raw) else {
    return raw_to_tag_value(raw);
  };
  let id = n >> 2;
  let bits = n & 0x3;
  // ValueConv `"<id> <bits>"` — the `-n` value.
  let value_conv = std::format!("{id} {bits}");
  if !print_conv {
    return TagValue::Str(SmolStr::from(value_conv));
  }
  // PrintConv: the full `"id bits"` key first, then the leading-integer
  // `OTHER` fallback (strip from the first space, look up the integer alone).
  if let Some(name) = lens_types::lookup_name(&value_conv) {
    return TagValue::Str(name);
  }
  let id_key = std::format!("{id}");
  if let Some(name) = lens_types::lookup_name(&id_key) {
    return TagValue::Str(name);
  }
  // No match anywhere ⇒ the `OTHER` returns `$$conv{$val}` which is undef ⇒
  // ExifTool keeps the ValueConv string as the rendered value.
  TagValue::Str(SmolStr::from(value_conv))
}

/// `0=>Low, 1=>Medium Low, 2=>Normal, 3=>Medium High, 4=>High` — the shared
/// Contrast/Saturation base hash (`Panasonic.pm:1779`/`1797`).
const fn contrast_label(n: i64) -> Option<&'static str> {
  match n {
    0 => Some("Low"),
    1 => Some("Medium Low"),
    2 => Some("Normal"),
    3 => Some("Medium High"),
    4 => Some("High"),
    _ => None,
  }
}

/// `sprintf("%.<prec>f", $val)` on the first rational. The ValueConv'd `$val` is
/// the rational's decimal; `-n` keeps the rational, `-j` formats it. An undef
/// (`0/0`) rational follows ExifTool's numeric formatting of `undef` → 0.
fn sprintf_rational(raw: &RawValue, print_conv: bool, prec: usize) -> TagValue {
  let Some(v) = first_f64(raw) else {
    return raw_to_tag_value(raw);
  };
  if !print_conv {
    return rational_first_value(raw);
  }
  match prec {
    1 => TagValue::Str(SmolStr::from(std::format!("{v:.1}"))),
    _ => TagValue::Str(SmolStr::from(std::format!("{v:.2}"))),
  }
}

/// Perl `sprintf("%.Nd", $val)` zero-padded decimal — preserves a leading `-`
/// then pads the magnitude to `width` digits.
fn sprintf_zero_pad(n: i64, width: usize) -> std::string::String {
  if n < 0 {
    let mag = n.unsigned_abs();
    std::format!("-{mag:0width$}")
  } else {
    let mag = n as u64;
    std::format!("{mag:0width$}")
  }
}

/// First scalar value as an unsigned `u64`.
fn first_u64(raw: &RawValue) -> Option<u64> {
  match raw {
    RawValue::U64(v) => v.first().copied(),
    RawValue::I64(v) => v.first().and_then(|&n| u64::try_from(n).ok()),
    _ => None,
  }
}

/// First scalar value as a signed `i64`.
fn first_i64(raw: &RawValue) -> Option<i64> {
  match raw {
    RawValue::I64(v) => v.first().copied(),
    RawValue::U64(v) => v.first().and_then(|&n| i64::try_from(n).ok()),
    _ => None,
  }
}

/// First scalar value as `f64` — handles rationals (for the rational tags).
fn first_f64(raw: &RawValue) -> Option<f64> {
  match raw {
    RawValue::F64(v) => v.first().copied(),
    RawValue::I64(v) => v.first().map(|&n| n as f64),
    RawValue::U64(v) => v.first().map(|&n| n as f64),
    RawValue::Rational(rs) => rs.first().map(|r| {
      let d = r.denominator();
      if d == 0 {
        0.0
      } else {
        r.numerator() as f64 / d as f64
      }
    }),
    _ => None,
  }
}

/// Render the first element as the `-n` ValueConv value of a single-value
/// rational tag.
fn rational_first_value(raw: &RawValue) -> TagValue {
  match raw {
    RawValue::Rational(rs) => match rs.first() {
      Some(r) => TagValue::Rational(*r),
      None => raw_to_tag_value(raw),
    },
    _ => raw_to_tag_value(raw),
  }
}

/// The display text of a `string` value, if any.
fn text_value(raw: &RawValue) -> Option<&str> {
  match raw {
    RawValue::Text { text: s, .. } => Some(s.as_str()),
    _ => None,
  }
}

/// Map a `u64` to the narrowest `TagValue` integer.
fn u64_tag(n: u64) -> TagValue {
  match i64::try_from(n) {
    Ok(n) => TagValue::I64(n),
    Err(_) => TagValue::U64(n),
  }
}

/// Generic int -> label PrintConv with a DECIMAL `Unknown (N)` fallback.
fn simple_label<F: Fn(i64) -> Option<&'static str>>(
  raw: &RawValue,
  print_conv: bool,
  f: F,
) -> TagValue {
  let Some(n) = first_i64(raw) else {
    return raw_to_tag_value(raw);
  };
  if !print_conv {
    return TagValue::I64(n);
  }
  match f(n) {
    Some(l) => TagValue::Str(l.into()),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({n})"))),
  }
}

/// `InternalSerialNumber` PrintConv (`Panasonic.pm:2049-2053`):
/// `^(.{3})(\d{2})(\d{2})(\d{2})(\d{4})` ⇒ `"($1) YYYY:$3:$4 no. $5"` with
/// `YYYY = $2 + ($2 < 70 ? 2000 : 1900)`. `None` ⇒ no match (the raw `$val`
/// passthrough). Operates on the raw `undef` bytes (ASCII); `.` in Perl matches
/// any byte (the value carries no newline), so a 3-byte prefix + 10 ASCII
/// digits is required.
fn decode_internal_serial(bytes: &[u8]) -> Option<std::string::String> {
  // Need 3 (prefix) + 2+2+2+4 = 13 bytes; the trailing 10 must be ASCII digits.
  let prefix = bytes.get(..3)?;
  let digits = bytes.get(3..13)?;
  if !digits.iter().all(u8::is_ascii_digit) {
    return None;
  }
  let yr2: i32 = std::str::from_utf8(digits.get(0..2)?).ok()?.parse().ok()?;
  let mm = std::str::from_utf8(digits.get(2..4)?).ok()?;
  let dd = std::str::from_utf8(digits.get(4..6)?).ok()?;
  let no = std::str::from_utf8(digits.get(6..10)?).ok()?;
  let yr = yr2 + if yr2 < 70 { 2000 } else { 1900 };
  let prefix = std::string::String::from_utf8_lossy(prefix);
  Some(std::format!("({prefix}) {yr}:{mm}:{dd} no. {no}"))
}

/// Render a raw value as a default [`TagValue`] (no conversion) — mirrors the
/// Sony/Pentax/Samsung helpers (single element ⇒ scalar; multi ⇒ space-joined
/// string; a multi-rational renders each element's ExifTool decimal).
pub(crate) fn raw_to_tag_value(raw: &RawValue) -> TagValue {
  use std::string::ToString;
  match raw {
    RawValue::I64(v) if let [n] = v.as_slice() => TagValue::I64(*n),
    RawValue::I64(v) => TagValue::Str(
      v.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(" ")
        .into(),
    ),
    RawValue::U64(v) if let [n] = v.as_slice() => u64_tag(*n),
    RawValue::U64(v) => TagValue::Str(
      v.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(" ")
        .into(),
    ),
    RawValue::F64(v) if let [n] = v.as_slice() => TagValue::F64(*n),
    RawValue::F64(v) => TagValue::Str(
      v.iter()
        .map(|f| f.to_string())
        .collect::<Vec<_>>()
        .join(" ")
        .into(),
    ),
    RawValue::Rational(rs) if let [r] = rs.as_slice() => TagValue::Rational(*r),
    RawValue::Rational(rs) => TagValue::Str(
      rs.iter()
        .map(|r| r.exiftool_val_str())
        .collect::<Vec<_>>()
        .join(" ")
        .into(),
    ),
    RawValue::Text { text: s, .. } => TagValue::Str(s.as_str().into()),
    RawValue::Bytes(b) => TagValue::Bytes(b.clone()),
  }
}
