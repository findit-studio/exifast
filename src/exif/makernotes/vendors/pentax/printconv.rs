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
///
/// `pub(crate)` so the Phase-2a binary SubDirectory decoders ([`super::subtables`])
/// can reuse the exact `PrintExposureTime` PrintConv for the AEInfo /
/// CameraSettings exposure-time leaves.
pub(crate) fn print_exposure_time(secs: f64) -> std::string::String {
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

// ---------------------------------------------------------------------------
// Phase-2a binary SubDirectory PrintConv tables (`%Pentax::CameraSettings`,
// `%Pentax::AEInfo`, `%Pentax::FlashInfo`). Each hash is sorted by key for
// binary search; each `*_BITS` table is the `DecodeBits` BITMASK label set.
// ---------------------------------------------------------------------------

/// `CameraSettings` `0 PictureMode2` (`Pentax.pm:3366-3386`).
pub(crate) const PICTURE_MODE2: &[(i64, &str)] = &[
  (0, "Scene Mode"),
  (1, "Auto PICT"),
  (2, "Program AE"),
  (3, "Green Mode"),
  (4, "Shutter Speed Priority"),
  (5, "Aperture Priority"),
  (6, "Program Tv Shift"),
  (7, "Program Av Shift"),
  (8, "Manual"),
  (9, "Bulb"),
  (10, "Aperture Priority, Off-Auto-Aperture"),
  (11, "Manual, Off-Auto-Aperture"),
  (12, "Bulb, Off-Auto-Aperture"),
  (13, "Shutter & Aperture Priority AE"),
  (15, "Sensitivity Priority AE"),
  (16, "Flash X-Sync Speed AE"),
];

/// `CameraSettings` `1.1 ProgramLine` (mask 0x03, `Pentax.pm:3391-3396`).
pub(crate) const PROGRAM_LINE: &[(i64, &str)] =
  &[(0, "Normal"), (1, "Hi Speed"), (2, "Depth"), (3, "MTF")];

/// `CameraSettings` `1.2 EVSteps` (mask 0x20, `Pentax.pm:3401-3404`).
pub(crate) const EV_STEPS: &[(i64, &str)] = &[(0, "1/2 EV Steps"), (1, "1/3 EV Steps")];

/// `CameraSettings` `1.3 E-DialInProgram` (mask 0x40, `Pentax.pm:3410-3413`).
pub(crate) const E_DIAL_IN_PROGRAM: &[(i64, &str)] = &[(0, "Tv or Av"), (1, "P Shift")];

/// `CameraSettings` `1.4 ApertureRingUse` (mask 0x80, `Pentax.pm:3419-3422`).
pub(crate) const APERTURE_RING_USE: &[(i64, &str)] = &[(0, "Prohibited"), (1, "Permitted")];

/// `CameraSettings` `2 FlashOptions` / `16 FlashOptions2` (mask 0xf0,
/// `Pentax.pm:3430-3440` / `:3657-3667` — identical label sets).
pub(crate) const FLASH_OPTIONS: &[(i64, &str)] = &[
  (0, "Normal"),
  (1, "Red-eye reduction"),
  (2, "Auto"),
  (3, "Auto, Red-eye reduction"),
  (5, "Wireless (Master)"),
  (6, "Wireless (Control)"),
  (8, "Slow-sync"),
  (9, "Slow-sync, Red-eye reduction"),
  (10, "Trailing-curtain Sync"),
];

/// `CameraSettings` `2.1 MeteringMode2` / `16.1 MeteringMode3` (mask 0x0f) and
/// `AEInfo` `13.1 AEMeteringMode2` — the shared `{ 0 => 'Multi-segment',
/// BITMASK => { 0 => 'Center-weighted average', 1 => 'Spot' } }` BITMASK
/// (`Pentax.pm:3446-3452`). The `0 => 'Multi-segment'` zero label is passed
/// separately to `bitmask0`.
pub(crate) const METERING_MODE_BITS: &[(u8, &str)] = &[(0, "Center-weighted average"), (1, "Spot")];

/// `CameraSettings` `3 AFPointMode` (mask 0xf0) — `{ 0 => 'Auto', BITMASK =>
/// { 0 => 'Select', 1 => 'Fixed Center' } }` (`Pentax.pm:3457-3464`).
pub(crate) const AF_POINT_MODE_BITS: &[(u8, &str)] = &[(0, "Select"), (1, "Fixed Center")];

/// `CameraSettings` `3.1 FocusMode2` (mask 0x0f, `Pentax.pm:3469-3474`).
pub(crate) const FOCUS_MODE2: &[(i64, &str)] =
  &[(0, "Manual"), (1, "AF-S"), (2, "AF-C"), (3, "AF-A")];

/// `CameraSettings` `4 AFPointSelected2` (int16u) — `{ 0 => 'Auto', BITMASK =>
/// { … } }` (`Pentax.pm:3479-3494`).
pub(crate) const AF_POINT_SELECTED2_BITS: &[(u8, &str)] = &[
  (0, "Upper-left"),
  (1, "Top"),
  (2, "Upper-right"),
  (3, "Left"),
  (4, "Mid-left"),
  (5, "Center"),
  (6, "Mid-right"),
  (7, "Right"),
  (8, "Lower-left"),
  (9, "Bottom"),
  (10, "Lower-right"),
];

/// `CameraSettings` `7 DriveMode2` — `{ 0 => 'Single-frame', BITMASK =>
/// { … } }` (`Pentax.pm:3504-3516`).
pub(crate) const DRIVE_MODE2_BITS: &[(u8, &str)] = &[
  (0, "Continuous"),
  (1, "Continuous (Lo)"),
  (2, "Self-timer (12 s)"),
  (3, "Self-timer (2 s)"),
  (4, "Remote Control (3 s delay)"),
  (5, "Remote Control"),
  (6, "Exposure Bracket"),
  (7, "Multiple Exposure"),
];

/// `CameraSettings` `8 ExposureBracketStepSize` (`Pentax.pm:3524-3533`). The
/// numeric-looking string labels (`"0.3"`) render as JSON numbers.
pub(crate) const EXPOSURE_BRACKET_STEP_SIZE: &[(i64, &str)] = &[
  (3, "0.3"),
  (4, "0.5"),
  (5, "0.7"),
  (8, "1.0"),
  (11, "1.3"),
  (12, "1.5"),
  (13, "1.7"),
  (16, "2.0"),
];

/// `CameraSettings` `9 BracketShotNumber` (PrintHex, `Pentax.pm:3538-3550`).
pub(crate) const BRACKET_SHOT_NUMBER: &[(i64, &str)] = &[
  (0x00, "n/a"),
  (0x02, "1 of 2"),
  (0x03, "1 of 3"),
  (0x05, "1 of 5"),
  (0x12, "2 of 2"),
  (0x13, "2 of 3"),
  (0x15, "2 of 5"),
  (0x23, "3 of 3"),
  (0x25, "3 of 5"),
  (0x35, "4 of 5"),
  (0x45, "5 of 5"),
];

/// `CameraSettings` `10 WhiteBalanceSet` (mask 0xf0, `Pentax.pm:3558-3574`).
pub(crate) const WHITE_BALANCE_SET: &[(i64, &str)] = &[
  (0, "Auto"),
  (1, "Daylight"),
  (2, "Shade"),
  (3, "Cloudy"),
  (4, "Daylight Fluorescent"),
  (5, "Day White Fluorescent"),
  (6, "White Fluorescent"),
  (7, "Tungsten"),
  (8, "Flash"),
  (9, "Manual"),
  (12, "Set Color Temperature 1"),
  (13, "Set Color Temperature 2"),
  (14, "Set Color Temperature 3"),
];

/// `{ 0 => 'Off', 1 => 'On' }` — `CameraSettings` `10.1 MultipleExposureSet`
/// (mask 0x0f, `Pentax.pm:3579-3582`).
pub(crate) const OFF_ON: &[(i64, &str)] = &[(0, "Off"), (1, "On")];

/// `CameraSettings` `13 RawAndJpgRecording` (K10D, PrintHex,
/// `Pentax.pm:3591-3608`).
pub(crate) const RAW_AND_JPG_RECORDING: &[(i64, &str)] = &[
  (0x01, "JPEG (Best)"),
  (0x04, "RAW (PEF, Best)"),
  (0x05, "RAW+JPEG (PEF, Best)"),
  (0x08, "RAW (DNG, Best)"),
  (0x09, "RAW+JPEG (DNG, Best)"),
  (0x21, "JPEG (Better)"),
  (0x24, "RAW (PEF, Better)"),
  (0x25, "RAW+JPEG (PEF, Better)"),
  (0x28, "RAW (DNG, Better)"),
  (0x29, "RAW+JPEG (DNG, Better)"),
  (0x41, "JPEG (Good)"),
  (0x44, "RAW (PEF, Good)"),
  (0x45, "RAW+JPEG (PEF, Good)"),
  (0x48, "RAW (DNG, Good)"),
  (0x49, "RAW+JPEG (DNG, Good)"),
];

/// `CameraSettings` `14.1 JpgRecordedPixels` (K10D, mask 0x03,
/// `Pentax.pm:3615-3619`).
pub(crate) const JPG_RECORDED_PIXELS: &[(i64, &str)] = &[(0, "10 MP"), (1, "6 MP"), (2, "2 MP")];

/// `{ 0 => 'No', 1 => 'Yes' }` (`%noYes`, `Pentax.pm:847`) — `CameraSettings`
/// `17.1 SRActive` (K10D, mask 0x80).
pub(crate) const NO_YES: &[(i64, &str)] = &[(0, "No"), (1, "Yes")];

/// `CameraSettings` `17.2 Rotation` (K10D, mask 0x60, `Pentax.pm:3698-3703`).
pub(crate) const ROTATION: &[(i64, &str)] = &[
  (0, "Horizontal (normal)"),
  (1, "Rotate 180"),
  (2, "Rotate 90 CW"),
  (3, "Rotate 270 CW"),
];

/// `CameraSettings` `17.3 ISOSetting` (K10D, mask 0x04, `Pentax.pm:3712-3715`).
pub(crate) const ISO_SETTING: &[(i64, &str)] = &[(0, "Manual"), (1, "Auto")];

/// `CameraSettings` `17.4 SensitivitySteps` (K10D, mask 0x02,
/// `Pentax.pm:3722-3725`).
pub(crate) const SENSITIVITY_STEPS: &[(i64, &str)] = &[(0, "1 EV Steps"), (1, "As EV Steps")];

/// `AEInfo` `6 AEProgramMode` (`Pentax.pm:3832-3866`).
pub(crate) const AE_PROGRAM_MODE: &[(i64, &str)] = &[
  (0, "M, P or TAv"),
  (1, "Av, B or X"),
  (2, "Tv"),
  (3, "Sv or Green Mode"),
  (8, "Hi-speed Program"),
  (11, "Hi-speed Program (P-Shift)"),
  (16, "DOF Program"),
  (19, "DOF Program (P-Shift)"),
  (24, "MTF Program"),
  (27, "MTF Program (P-Shift)"),
  (35, "Standard"),
  (43, "Portrait"),
  (51, "Landscape"),
  (59, "Macro"),
  (67, "Sport"),
  (75, "Night Scene Portrait"),
  (83, "No Flash"),
  (91, "Night Scene"),
  (99, "Surf & Snow"),
  (104, "Night Snap"),
  (107, "Text"),
  (115, "Sunset"),
  (123, "Kids"),
  (131, "Pet"),
  (139, "Candlelight"),
  (144, "SCN"),
  (147, "Museum"),
  (160, "Program"),
  (184, "Shallow DOF Program"),
  (216, "HDR"),
];

/// `AEInfo` `12 AEMeteringMode` — `{ 0 => 'Multi-segment', BITMASK =>
/// { 4 => 'Center-weighted average', 5 => 'Spot' } }` (`Pentax.pm:3932-3938`).
pub(crate) const AE_METERING_MODE_BITS: &[(u8, &str)] =
  &[(4, "Center-weighted average"), (5, "Spot")];

/// `FlashInfo` `0 FlashStatus` (PrintHex, `Pentax.pm:4587-4595`).
pub(crate) const FLASH_STATUS: &[(i64, &str)] = &[
  (0x00, "Off"),
  (0x01, "Off (1)"),
  (0x02, "External, Did not fire"),
  (0x06, "External, Fired"),
  (0x08, "Internal, Did not fire (0x08)"),
  (0x09, "Internal, Did not fire"),
  (0x0d, "Internal, Fired"),
];

/// `FlashInfo` `1 InternalFlashMode` (PrintHex, `Pentax.pm:4600-4622`).
pub(crate) const INTERNAL_FLASH_MODE: &[(i64, &str)] = &[
  (0x00, "n/a - Off-Auto-Aperture"),
  (0x86, "Fired, Wireless (Control)"),
  (0x95, "Fired, Wireless (Master)"),
  (0xc0, "Fired"),
  (0xc1, "Fired, Red-eye reduction"),
  (0xc2, "Fired, Auto"),
  (0xc3, "Fired, Auto, Red-eye reduction"),
  (
    0xc6,
    "Fired, Wireless (Control), Fired normally not as control",
  ),
  (0xc8, "Fired, Slow-sync"),
  (0xc9, "Fired, Slow-sync, Red-eye reduction"),
  (0xca, "Fired, Trailing-curtain Sync"),
  (0xf0, "Did not fire, Normal"),
  (0xf1, "Did not fire, Red-eye reduction"),
  (0xf2, "Did not fire, Auto"),
  (0xf3, "Did not fire, Auto, Red-eye reduction"),
  (0xf4, "Did not fire, (Unknown 0xf4)"),
  (0xf5, "Did not fire, Wireless (Master)"),
  (0xf6, "Did not fire, Wireless (Control)"),
  (0xf8, "Did not fire, Slow-sync"),
  (0xf9, "Did not fire, Slow-sync, Red-eye reduction"),
  (0xfa, "Did not fire, Trailing-curtain Sync"),
];

/// `FlashInfo` `2 ExternalFlashMode` (PrintHex, `Pentax.pm:4627-4639`).
pub(crate) const EXTERNAL_FLASH_MODE: &[(i64, &str)] = &[
  (0x00, "n/a - Off-Auto-Aperture"),
  (0x3f, "Off"),
  (0x40, "On, Auto"),
  (0xbf, "On, Flash Problem"),
  (0xc0, "On, Manual"),
  (0xc4, "On, P-TTL Auto"),
  (0xc5, "On, Contrast-control Sync"),
  (0xc6, "On, High-speed Sync"),
  (0xcc, "On, Wireless"),
  (0xcd, "On, Wireless, High-speed Sync"),
  (0xf0, "Not Connected"),
];

/// `FlashInfo` `25 ExternalFlashExposureComp` (`Pentax.pm:4683-4695`).
pub(crate) const EXTERNAL_FLASH_EXPOSURE_COMP: &[(i64, &str)] = &[
  (0, "n/a"),
  (144, "n/a (Manual Mode)"),
  (164, "-3.0"),
  (167, "-2.5"),
  (168, "-2.0"),
  (171, "-1.5"),
  (172, "-1.0"),
  (175, "-0.5"),
  (176, "0.0"),
  (179, "0.5"),
  (180, "1.0"),
];

/// `FlashInfo` `26 ExternalFlashBounce` (`Pentax.pm:4700-4704`).
pub(crate) const EXTERNAL_FLASH_BOUNCE: &[(i64, &str)] =
  &[(0, "n/a"), (16, "Direct"), (48, "Bounce")];

/// `%Pentax::LensData` `3 MinFocusDistance` (`Pentax.pm:4434-4467`) — the masked
/// (`Mask => 0xf8`) lens minimum-focus-distance code. The keys are the raw
/// masked value (`($val & 0xf8) >> 3`, 0-20); the labels are the verbatim range
/// strings. Sorted by key for binary search.
pub(crate) const MIN_FOCUS_DISTANCE: &[(i64, &str)] = &[
  (0, "0.13-0.19 m"),
  (1, "0.20-0.24 m"),
  (2, "0.25-0.28 m"),
  (3, "0.28-0.30 m"),
  (4, "0.35-0.38 m"),
  (5, "0.40-0.45 m"),
  (6, "0.49-0.50 m"),
  (7, "0.6 m"),
  (8, "0.7 m"),
  (9, "0.8-0.9 m"),
  (10, "1.0 m"),
  (11, "1.1-1.2 m"),
  (12, "1.4-1.5 m"),
  (13, "1.5 m"),
  (14, "2.0 m"),
  (15, "2.0-2.1 m"),
  (16, "2.1 m"),
  (17, "2.2-2.9 m"),
  (18, "3.0 m"),
  (19, "4-5 m"),
  (20, "5.6 m"),
];

#[cfg(test)]
mod tests;
