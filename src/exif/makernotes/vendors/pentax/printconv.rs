// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Per-tag PrintConv / ValueConv for the ported `%Pentax::Main` leaf tags
//! (`Pentax.pm:859-3171`).
//!
//! Each [`PentaxPrintConv`] variant is the faithful 1:1 port of ONE tag's
//! `ValueConv`/`PrintConv` pair. `apply(raw, print_conv)` runs the ValueConv
//! (always) and, when `print_conv` is true, the PrintConv on top:
//!
//! - `print_conv = false` (`-n`) ⇒ the post-ValueConv value (`TagValue`).
//! - `print_conv = true` (`-j`) ⇒ the PrintConv rendering (usually a string;
//!   the JSON serializer's `EscapeJSON` number gate decides quoting, so a
//!   `sprintf("%.1f", …)` like FNumber's `"13.0"` serializes as the bare
//!   number `13.0`).
//!
//! The lens-type / model-ID / city lookups live in the sibling
//! [`super::lens_types`] / [`super::model_ids`] / [`super::cities`] modules;
//! the `LensType` decode (the `%Pentax::LensRec` `int8u[2]` at position 0,
//! reached via `0x003f LensRec`) is handled by the caller
//! ([`super::lens_rec_lens_type`]) because it reads two raw value bytes, not a
//! single scalar.

#![deny(clippy::indexing_slicing)]

use super::{cities, model_ids};
use crate::exif::ifd::RawValue;
use crate::value::{Rational, TagValue};
use smol_str::SmolStr;

/// The PrintConv/ValueConv strategy for one ported Pentax Main leaf tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PentaxPrintConv {
  /// No conv — the raw value passes straight through (the default ExifTool
  /// rendering: scalar as-is, multi-element as a space-joined string).
  None,
  /// `0x0005 PentaxModelID` — `PrintConv => \%pentaxModelID` (int32u key, with
  /// `PrintHex => 1` so an absent key renders `0xNNNN`).
  ModelId,
  /// `0x0023 HometownCity` / `0x0024 DestinationCity` — `\%pentaxCities`.
  City,
  /// `0x0006 Date` — `length==4 ? sprintf("%.4d:%.2d:%.2d", unpack("nC2")) :
  /// "Unknown (...)"` (no PrintConv).
  Date,
  /// `0x0007 Time` — `length>=3 ? sprintf("%.2d:%.2d:%.2d", unpack("C3")) :
  /// "Unknown (...)"` (no PrintConv).
  Time,
  /// `0x0027 DSPFirmwareVersion` / `0x0028 CPUFirmwareVersion` —
  /// `%pentaxFirmwareID`: ValueConv toggles all bits, formats
  /// `'%d %.2d %.2d %.2d'`; PrintConv replaces spaces with dots.
  FirmwareId,
  /// `0x0002 PreviewImageSize` — Count 2 int16u; ValueConv = the space-joined
  /// pair, PrintConv = `tr/ /x/` (e.g. `"640 480"` -> `"640x480"`).
  PreviewImageSize,
  /// `0x0000 PentaxVersion` — Count 4 int8u; ValueConv = the default
  /// space-joined run, PrintConv = `$val=~tr/ /./` (e.g. `"3 0 0 0"` ->
  /// `"3.0.0.0"`).
  Version,
  /// `0x0012 ExposureTime` — ValueConv `$val * 1e-5`; PrintConv `$val > 42949
  /// ? "Unknown (Bulb)" : PrintExposureTime($val)`.
  ExposureTime,
  /// `0x0013 FNumber` — ValueConv `$val / 10`; PrintConv `sprintf("%.1f")`.
  FNumber,
  /// `0x0040 SensitivityAdjust` — ValueConv `($val - 50) / 10`; PrintConv
  /// `$val ? sprintf("%+.1f") : 0`.
  SensitivityAdjust,
  /// `0x0047 CameraTemperature` — int8s; PrintConv `"$val C"`.
  CameraTemperature,
  /// `0x0209/0x020a/0x020b` AE/Flash metering segments — int8u[N];
  /// `%convertMeteringSegments`: each byte -> `n/a` (255), `0` (0), else
  /// `sprintf('%.1f', $_/8 - 6)`, space-joined.
  MeteringSegments,
  /// An int-keyed PrintConv hash (decimal `Unknown (N)` fallback). The
  /// `&[(key, label)]` slice is sorted for binary search.
  Hash(&'static [(i64, &'static str)]),
  /// An int-keyed PrintConv hash with a HEX `Unknown (0xNN)` fallback
  /// (`PrintHex => 1`).
  HashHex(&'static [(i64, &'static str)]),
}

impl PentaxPrintConv {
  /// Apply the conv to `raw`. `print_conv = false` ⇒ the post-ValueConv value;
  /// `true` ⇒ the PrintConv rendering.
  #[must_use]
  pub fn apply(self, raw: &RawValue, print_conv: bool) -> TagValue {
    match self {
      PentaxPrintConv::None => raw_to_tag_value(raw),
      PentaxPrintConv::ModelId => {
        let Some(n) = first_u64(raw) else {
          return raw_to_tag_value(raw);
        };
        if !print_conv {
          return u64_to_tag_value(n);
        }
        let id = u32::try_from(n).unwrap_or(u32::MAX);
        match model_ids::lookup_name(id) {
          Some(name) => TagValue::Str(name),
          // `PrintHex => 1` ⇒ a missing key renders the bare hex value.
          None => TagValue::Str(SmolStr::from(std::format!("0x{n:x}"))),
        }
      }
      PentaxPrintConv::City => {
        let Some(n) = first_i64(raw) else {
          return raw_to_tag_value(raw);
        };
        if !print_conv {
          return TagValue::I64(n);
        }
        let id = u16::try_from(n).unwrap_or(u16::MAX);
        match cities::lookup_name(id) {
          Some(name) => TagValue::Str(name),
          None => TagValue::Str(SmolStr::from(std::format!("Unknown ({n})"))),
        }
      }
      PentaxPrintConv::Date => date_value(raw),
      PentaxPrintConv::Time => time_value(raw),
      PentaxPrintConv::FirmwareId => firmware_value(raw, print_conv),
      PentaxPrintConv::PreviewImageSize => {
        // ValueConv: the default space-joined `"W H"` string; PrintConv:
        // `tr/ /x/` -> `"WxH"`.
        let joined = space_join(raw);
        if !print_conv {
          return TagValue::Str(SmolStr::from(joined));
        }
        TagValue::Str(SmolStr::from(joined.replace(' ', "x")))
      }
      PentaxPrintConv::Version => {
        // ValueConv: the default space-joined int8u[4] run; PrintConv:
        // `$val=~tr/ /./` -> dotted (e.g. `"3.0.0.0"`).
        let joined = space_join(raw);
        if !print_conv {
          return TagValue::Str(SmolStr::from(joined));
        }
        TagValue::Str(SmolStr::from(joined.replace(' ', ".")))
      }
      PentaxPrintConv::ExposureTime => {
        let Some(n) = first_u64(raw) else {
          return raw_to_tag_value(raw);
        };
        // ValueConv `$val * 1e-5`.
        let secs = n as f64 * 1e-5;
        if !print_conv {
          return TagValue::F64(secs);
        }
        // PrintConv: `$val > 42949 ? "Unknown (Bulb)" : PrintExposureTime($val)`
        // — note the threshold tests the POST-ValueConv `$val` (seconds).
        if secs > 42949.0 {
          return TagValue::Str(SmolStr::from("Unknown (Bulb)"));
        }
        TagValue::Str(SmolStr::from(print_exposure_time(secs)))
      }
      PentaxPrintConv::FNumber => {
        let Some(n) = first_u64(raw) else {
          return raw_to_tag_value(raw);
        };
        let f = n as f64 / 10.0;
        if !print_conv {
          return TagValue::F64(f);
        }
        // `sprintf("%.1f", $val)` — emit the literal one-decimal text; the JSON
        // serializer's number gate renders `"13.0"` as the bare number `13.0`.
        TagValue::Str(SmolStr::from(std::format!("{f:.1}")))
      }
      PentaxPrintConv::SensitivityAdjust => {
        let Some(n) = first_i64(raw) else {
          return raw_to_tag_value(raw);
        };
        let v = (n - 50) as f64 / 10.0;
        if !print_conv {
          return TagValue::F64(v);
        }
        // `$val ? sprintf("%+.1f", $val) : 0`.
        if v == 0.0 {
          return TagValue::I64(0);
        }
        TagValue::Str(SmolStr::from(std::format!("{v:+.1}")))
      }
      PentaxPrintConv::CameraTemperature => {
        let Some(n) = first_i64(raw) else {
          return raw_to_tag_value(raw);
        };
        if !print_conv {
          return TagValue::I64(n);
        }
        TagValue::Str(SmolStr::from(std::format!("{n} C")))
      }
      PentaxPrintConv::MeteringSegments => metering_segments(raw, print_conv),
      PentaxPrintConv::Hash(table) => hash_label(raw, print_conv, table, false),
      PentaxPrintConv::HashHex(table) => hash_label(raw, print_conv, table, true),
    }
  }
}

/// Binary-search a sorted `(key, label)` hash.
fn hash_get(table: &[(i64, &'static str)], key: i64) -> Option<&'static str> {
  match table.binary_search_by_key(&key, |&(k, _)| k) {
    Ok(i) => table.get(i).map(|&(_, v)| v),
    Err(_) => None,
  }
}

/// Int -> label PrintConv. `hex` selects the `Unknown (0xNN)` (PrintHex) vs
/// `Unknown (N)` decimal fallback. `-n` ⇒ the raw integer.
fn hash_label(
  raw: &RawValue,
  print_conv: bool,
  table: &[(i64, &'static str)],
  hex: bool,
) -> TagValue {
  let Some(n) = first_i64(raw) else {
    return raw_to_tag_value(raw);
  };
  if !print_conv {
    return TagValue::I64(n);
  }
  match hash_get(table, n) {
    Some(l) => TagValue::Str(SmolStr::from(l)),
    None if hex => TagValue::Str(SmolStr::from(std::format!("Unknown (0x{n:x})"))),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({n})"))),
  }
}

/// `0x0006 Date` — `length($val)==4 ? sprintf("%.4d:%.2d:%.2d", unpack("nC2",$val))`.
/// The value is `undef[4]`: a big-endian `int16u` year + two `int8u` (month,
/// day), regardless of EXIF byte order (`Pentax.pm:972`). No PrintConv.
fn date_value(raw: &RawValue) -> TagValue {
  if let Some(&[y0, y1, m, d]) = raw_bytes(raw) {
    let year = (u16::from(y0) << 8) | u16::from(y1);
    return TagValue::Str(SmolStr::from(std::format!("{year:04}:{m:02}:{d:02}")));
  }
  unknown_paren(raw)
}

/// `0x0007 Time` — `length($val)>=3 ? sprintf("%.2d:%.2d:%.2d", unpack("C3",$val))`.
/// `undef[3]`: three `int8u` (hour, minute, second). No PrintConv.
fn time_value(raw: &RawValue) -> TagValue {
  if let Some([h, m, s, ..]) = raw_bytes(raw) {
    return TagValue::Str(SmolStr::from(std::format!("{h:02}:{m:02}:{s:02}")));
  }
  unknown_paren(raw)
}

/// `%pentaxFirmwareID` (`Pentax.pm:767`) — ValueConv toggles all bits of the
/// 4 bytes and formats `'%d %.2d %.2d %.2d'`; PrintConv replaces spaces with
/// dots. A non-4-byte value passes through.
fn firmware_value(raw: &RawValue, print_conv: bool) -> TagValue {
  // ValueConv `return $val unless length($val) == 4` — a non-4-byte value passes
  // through; the slice pattern matches exactly the 4-byte case without indexing.
  let &[a0, a1, a2, a3] = raw_bytes(raw).unwrap_or(&[]) else {
    return raw_to_tag_value(raw);
  };
  let (x0, x1, x2, x3) = (a0 ^ 0xff, a1 ^ 0xff, a2 ^ 0xff, a3 ^ 0xff);
  let vc = std::format!("{x0} {x1:02} {x2:02} {x3:02}");
  if !print_conv {
    return TagValue::Str(SmolStr::from(vc));
  }
  TagValue::Str(SmolStr::from(vc.replace(' ', ".")))
}

/// `%convertMeteringSegments` (`Pentax.pm:581`) — int8u[N]; PrintConv maps each
/// byte: `255 -> "n/a"`, `0 -> "0"`, else `sprintf('%.1f', $_/8 - 6)`,
/// space-joined. `-n` ⇒ the raw space-joined bytes (the default int8u[N]
/// ValueConv).
fn metering_segments(raw: &RawValue, print_conv: bool) -> TagValue {
  if !print_conv {
    return TagValue::Str(SmolStr::from(space_join(raw)));
  }
  // `Format => 'int8u', Count => -1` ⇒ the value is a variable-length int8u run,
  // which the Walker materializes as `RawValue::Bytes` (undef-shaped block) or as
  // a `U64`/`I64` array; iterate the unified numeric view so all shapes render.
  let mut out = std::string::String::new();
  let push = |i: usize, n: u64, out: &mut std::string::String| {
    if i > 0 {
      out.push(' ');
    }
    if n == 255 {
      out.push_str("n/a");
    } else if n == 0 {
      out.push('0');
    } else {
      let lv = n as f64 / 8.0 - 6.0;
      out.push_str(&std::format!("{lv:.1}"));
    }
  };
  match raw {
    RawValue::Bytes(b) => {
      for (i, &n) in b.iter().enumerate() {
        push(i, u64::from(n), &mut out);
      }
    }
    RawValue::U64(v) => {
      for (i, &n) in v.iter().enumerate() {
        push(i, n, &mut out);
      }
    }
    RawValue::I64(v) => {
      for (i, &n) in v.iter().enumerate() {
        push(i, u64::try_from(n).unwrap_or(0), &mut out);
      }
    }
    _ => {}
  }
  TagValue::Str(SmolStr::from(out))
}

/// `Image::ExifTool::Exif::PrintExposureTime` (`Exif.pm:5701-5711`).
fn print_exposure_time(secs: f64) -> std::string::String {
  if !secs.is_finite() {
    return crate::value::format_g(secs, 15);
  }
  if secs < 0.250_01 && secs > 0.0 {
    let denom = (0.5 + 1.0 / secs).floor() as i64;
    return std::format!("1/{denom}");
  }
  let s = std::format!("{secs:.1}");
  match s.strip_suffix(".0") {
    Some(stripped) => stripped.to_string(),
    None => s,
  }
}

/// `"Unknown ($val)"` where `$val` is the default rendering of `raw`.
fn unknown_paren(raw: &RawValue) -> TagValue {
  TagValue::Str(SmolStr::from(std::format!("Unknown ({})", space_join(raw))))
}

/// The raw value's `undef`/`bytes` body, if it is a byte buffer.
fn raw_bytes(raw: &RawValue) -> Option<&[u8]> {
  match raw {
    RawValue::Bytes(b) => Some(b.as_slice()),
    RawValue::Text { raw, .. } => Some(raw),
    _ => None,
  }
}

/// The space-joined default rendering of a numeric `raw` (ExifTool's default
/// ValueConv for a multi-element value), or the bytes-as-decimal for a `Bytes`
/// undef value.
fn space_join(raw: &RawValue) -> std::string::String {
  use std::string::ToString;
  match raw {
    RawValue::U64(v) => v.iter().map(u64::to_string).collect::<Vec<_>>().join(" "),
    RawValue::I64(v) => v.iter().map(i64::to_string).collect::<Vec<_>>().join(" "),
    RawValue::Bytes(b) => b.iter().map(u8::to_string).collect::<Vec<_>>().join(" "),
    _ => match raw_to_tag_value(raw) {
      TagValue::Str(s) => s.to_string(),
      TagValue::I64(n) => n.to_string(),
      TagValue::U64(n) => n.to_string(),
      TagValue::F64(f) => crate::value::format_g(f, 15),
      _ => std::string::String::new(),
    },
  }
}

fn first_u64(raw: &RawValue) -> Option<u64> {
  match raw {
    RawValue::U64(v) => v.first().copied(),
    RawValue::I64(v) => v.first().and_then(|&n| u64::try_from(n).ok()),
    _ => None,
  }
}

fn first_i64(raw: &RawValue) -> Option<i64> {
  match raw {
    RawValue::I64(v) => v.first().copied(),
    RawValue::U64(v) => v.first().and_then(|&n| i64::try_from(n).ok()),
    _ => None,
  }
}

fn u64_to_tag_value(n: u64) -> TagValue {
  match i64::try_from(n) {
    Ok(v) => TagValue::I64(v),
    Err(_) => TagValue::U64(n),
  }
}

/// The DEFAULT ExifTool rendering of a raw value with no conv — a single scalar
/// stays a number; a multi-element value becomes a space-joined string.
pub(crate) fn raw_to_tag_value(raw: &RawValue) -> TagValue {
  use std::string::ToString;
  match raw {
    RawValue::I64(v) if let [n] = v.as_slice() => TagValue::I64(*n),
    RawValue::U64(v) if let [n] = v.as_slice() => u64_to_tag_value(*n),
    RawValue::F64(v) if let [n] = v.as_slice() => TagValue::F64(*n),
    RawValue::Rational(rs) if let [r] = rs.as_slice() => TagValue::Rational(*r),
    RawValue::Text { text, .. } => TagValue::Str(SmolStr::from(text.as_str())),
    RawValue::Bytes(b) => TagValue::Bytes(b.clone()),
    RawValue::I64(v) => TagValue::Str(SmolStr::from(
      v.iter().map(i64::to_string).collect::<Vec<_>>().join(" "),
    )),
    RawValue::U64(v) => TagValue::Str(SmolStr::from(
      v.iter().map(u64::to_string).collect::<Vec<_>>().join(" "),
    )),
    RawValue::F64(v) => TagValue::Str(SmolStr::from(
      v.iter()
        .map(|f| crate::value::format_g(*f, 15))
        .collect::<Vec<_>>()
        .join(" "),
    )),
    RawValue::Rational(rs) => TagValue::Str(SmolStr::from(
      rs.iter()
        .map(Rational::exiftool_val_str)
        .collect::<Vec<_>>()
        .join(" "),
    )),
  }
}

#[cfg(test)]
mod tests;
