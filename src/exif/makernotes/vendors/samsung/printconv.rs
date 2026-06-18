// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Samsung-specific PrintConv/ValueConv enum — covers the per-tag conversions
//! in `%Image::ExifTool::Samsung::Type2` (`Samsung.pm:129-648`) plus the
//! `%Samsung::PictureWizard` binary sub-table (`Samsung.pm:650-705`).
//!
//! Faithful: every variant is a named arm with a `Samsung.pm` citation, and the
//! bundled label text is kept verbatim. The big lookup hashes
//! (`SamsungModelID` 0x0003 and `%samsungLensTypes` 0xa003) live in
//! [`super::model_ids`] / [`super::lens_types`].

#![deny(clippy::indexing_slicing)]

use super::lens_types;
use super::model_ids;
use crate::exif::ifd::RawValue;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

/// Per-tag conversion strategy for the Samsung Type2 IFD table + the
/// PictureWizard binary sub-table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SamsungPrintConv {
  /// No conversion — emit the raw scalar/array (string/int/space-joined list).
  None,
  /// `MakerNoteVersion` 0x0001 (`Samsung.pm:135-139`) — `Writable => 'undef'`,
  /// `Count => 4`. ExifTool renders the 4 undef bytes as the raw ASCII version
  /// string (`"0100"`), trailing-NUL-stripped (the `%Exif::Main`
  /// `ExifVersion` rendering); same under `-j` and `-n`.
  Version,
  /// `DeviceType` 0x0002 (`Samsung.pm:140-152`) — int32u, `PrintHex => 1`.
  DeviceType,
  /// `SamsungModelID` 0x0003 (`Samsung.pm:153-245`) — int32u lookup
  /// ([`model_ids`]), `PrintHex => 1`.
  SamsungModelId,
  /// `SmartAlbumColor` 0x0020 branch 1 (`Samsung.pm:256-264`) — the
  /// `$$valPt =~ /^\0{4}/` variant whose only PrintConv key is `'0 0' => 'n/a'`.
  SmartAlbumColor,
  /// `LocalLocationName` 0x0030 (`Samsung.pm:291-298`) — `Format => 'undef'`,
  /// `Writable => 'string'`, no PrintConv. The ValueConv rewrites the two
  /// embedded place names (Korean if in Korea), terminated at the first
  /// double-NUL and with each `\0`-then-spaces separator turned into a newline:
  /// `$val=~s/\0\0.*//; $val=~s/\0 */\n/g; $val`. With no PrintConv `-j` and
  /// `-n` render the SAME ValueConv string.
  LocalLocationName,
  /// `RawDataByteOrder` 0x0040 (`Samsung.pm:334-340`).
  RawDataByteOrder,
  /// `WhiteBalanceSetup` 0x0041 (`Samsung.pm:341-348`) — `0=>Auto, 1=>Manual`.
  WhiteBalanceSetup,
  /// `CameraTemperature` 0x0043 (`Samsung.pm:349-356`) — rational64s,
  /// `$val =~ /\d/ ? "$val C" : $val` (an undef `0/0` rational passes through
  /// as the bare word `undef`).
  CameraTemperature,
  /// `RawDataCFAPattern` 0x0050 (`Samsung.pm:361-368`).
  RawDataCfaPattern,
  /// `FaceDetect`/`FaceRecognition`/`SmartRange` — `0=>Off, 1=>On`
  /// (`Samsung.pm:384`/`391`/`445`).
  OffOn,
  /// `LensType` 0xa003 (`Samsung.pm:410-416`) — int16u lookup
  /// ([`lens_types`]).
  LensType,
  /// `ColorSpace` 0xa011 (`Samsung.pm:434-441`) — `0=>sRGB, 1=>Adobe RGB`.
  ColorSpace,
  /// `ExposureTime` 0xa018 (`Samsung.pm:455-462`) — rational64u, the
  /// `$val=~s/ .*//` first-value ValueConv then `PrintExposureTime`.
  ExposureTime,
  /// `FNumber` 0xa019 (`Samsung.pm:463-471`) — rational64u, first-value
  /// ValueConv then `sprintf("%.1f")`.
  FNumber,
  /// `FocalLengthIn35mmFormat` 0xa01a (`Samsung.pm:472-481`) — `Format =>
  /// 'int32u'`, ValueConv `$val / 10`, PrintConv `"$val mm"`.
  FocalLength35,
  /// `PictureWizardMode` (`%Samsung::PictureWizard` offset 0,
  /// `Samsung.pm:659-674`) — int16u label hash.
  PictureWizardMode,
  /// `PictureWizardSaturation`/`Sharpness`/`Contrast` (offsets 2/3/4,
  /// `Samsung.pm:680-704`) — ValueConv `$val - 4` (no PrintConv).
  PictureWizardMinus4,
}

impl SamsungPrintConv {
  /// Whether tag `id`'s value-`Condition` HOLDS for this entry — i.e. whether
  /// ExifTool's `GetTagInfo` would return the tag (so it is emitted). `false` ⇒
  /// the `Condition` fails ⇒ the tag is SUPPRESSED (no emission, no typed
  /// populate). `raw` is the decoded value (for the `$$valPt` byte test). Tags
  /// without a suppressible value-`Condition` return `true`.
  ///
  /// Mirrors the Panasonic `single_hash_condition_holds` shape (the established
  /// `$$valPt`-condition idiom in the shared-`Walker` emit path).
  ///
  /// The only Type2 row with such a Condition is:
  ///
  /// - `0xa002 SerialNumber` (`Samsung.pm:404-409`):
  ///   `Condition => '$$valPt =~ /^\w{5}/'` — emit ONLY when the first FIVE raw
  ///   value bytes are ASCII word characters `[A-Za-z0-9_]`. `\w` carries no
  ///   `/u`, so it is the ASCII word class; a non-ASCII (or NUL) byte in the
  ///   first five positions fails the test exactly as Perl's byte-string regex
  ///   does. The bytes are taken from
  ///   [`RawValue::val_bytes`](crate::exif::ifd::RawValue::val_bytes) — for the
  ///   `string`/`undef` shape this row always carries on a real body, that is the
  ///   on-disk `$$valPt` (NUL-trimmed). A NUL within the first five bytes shortens
  ///   the trimmed value below five and fails the gate, the same boolean
  ///   `$$valPt` yields (NUL is not `\w`).
  #[must_use]
  pub fn condition_holds(id: u16, raw: &RawValue) -> bool {
    match id {
      0xa002 => val_pt_matches_word5(raw),
      _ => true,
    }
  }

  /// Apply the conversion to a raw value, producing the rendered [`TagValue`]
  /// for the requested mode (`print_conv` = `-j` PrintConv, else `-n`
  /// ValueConv).
  #[must_use]
  pub fn apply(self, raw: &RawValue, print_conv: bool) -> TagValue {
    match self {
      SamsungPrintConv::None => raw_to_tag_value(raw),
      SamsungPrintConv::Version => {
        // `undef` bytes -> the raw ASCII version string, TRAILING-`\0`-stripped
        // (`Exif.pm:2241` `$val=~s/\0+$//`, anchored `$` — interior NULs kept).
        // Same value under both modes (no PrintConv/ValueConv distinction).
        let RawValue::Bytes(b) = raw else {
          return raw_to_tag_value(raw);
        };
        let end = b.iter().rposition(|&c| c != 0).map_or(0, |i| i + 1);
        let bytes = b.get(..end).unwrap_or(b.as_slice());
        TagValue::Str(SmolStr::from(std::string::String::from_utf8_lossy(bytes)))
      }
      SamsungPrintConv::DeviceType => hex_label(raw, print_conv, |n| match n {
        0x1000 => Some("Compact Digital Camera"),
        0x2000 => Some("High-end NX Camera"),
        0x3000 => Some("HXM Video Camera"),
        0x12000 => Some("Cell Phone"),
        0x300000 => Some("SMX Video Camera"),
        _ => None,
      }),
      SamsungPrintConv::SamsungModelId => {
        let Some(n) = first_u64(raw) else {
          return raw_to_tag_value(raw);
        };
        if !print_conv {
          return u64_tag(n);
        }
        let id = u32::try_from(n).unwrap_or(0);
        match model_ids::lookup_name(id) {
          Some(name) => TagValue::Str(name),
          // `PrintHex => 1` ⇒ an unmapped value renders as `Unknown (0xNN)`.
          None => TagValue::Str(SmolStr::from(std::format!("Unknown (0x{n:x})"))),
        }
      }
      SamsungPrintConv::SmartAlbumColor => {
        // Branch 1 (`$$valPt =~ /^\0{4}/`) PrintConv is the single key
        // `'0 0' => 'n/a'`; every other value passes through as the raw
        // `"a b"` string (branch 2's per-element color array is deferred — it
        // only applies to non-zero values, which are not the camera-indexing
        // case).
        let rendered = raw_to_tag_value(raw);
        if print_conv && matches!(&rendered, TagValue::Str(s) if s == "0 0") {
          TagValue::Str("n/a".into())
        } else {
          rendered
        }
      }
      SamsungPrintConv::LocalLocationName => {
        // `Format => 'undef'` ⇒ `raw` is the un-NUL-trimmed on-disk bytes
        // (`RawValue::Bytes`). Apply the bundled ValueConv on those bytes:
        //   `$val=~s/\0\0.*//;`  — drop from the FIRST double-NUL onward (the
        //                            two-name terminator; `.` is any byte but the
        //                            data carries no literal newline, so the
        //                            no-`/s` Perl default and a byte scan agree).
        //   `$val=~s/\0 */\n/g;`  — each NUL + zero-or-more SPACES → a newline.
        // No PrintConv ⇒ identical under both modes. A non-`Bytes` shape (never
        // produced for this `undef` row) falls back to the raw rendering.
        let RawValue::Bytes(b) = raw else {
          return raw_to_tag_value(raw);
        };
        TagValue::Str(SmolStr::from(local_location_name(b)))
      }
      SamsungPrintConv::RawDataByteOrder => simple_label(raw, print_conv, |n| match n {
        0 => Some("Little-endian (Intel, II)"),
        1 => Some("Big-endian (Motorola, MM)"),
        _ => None,
      }),
      SamsungPrintConv::WhiteBalanceSetup => simple_label(raw, print_conv, |n| match n {
        0 => Some("Auto"),
        1 => Some("Manual"),
        _ => None,
      }),
      SamsungPrintConv::CameraTemperature => {
        // rational64s. ValueConv is the identity (no `ValueConv` key); the
        // ValueConv'd `$val` is the rational's ExifTool string (a decimal, or
        // the bare word `undef` for `0/0`). PrintConv: append `" C"` only when
        // `$val` contains a digit, else pass the value through unchanged.
        let val_str = rational_val_string(raw);
        let Some(val_str) = val_str else {
          return raw_to_tag_value(raw);
        };
        if !print_conv {
          // `-n` is the ValueConv value: `undef` (no digit) stays the bare word
          // via `TagValue::Rational`; a real rational stays numeric.
          return raw_to_tag_value(raw);
        }
        if val_str.bytes().any(|b| b.is_ascii_digit()) {
          TagValue::Str(SmolStr::from(std::format!("{val_str} C")))
        } else {
          // No digit (e.g. `undef`) ⇒ `$val` passthrough — keep the numeric
          // shape so an `undef` rational still renders as the bare word.
          raw_to_tag_value(raw)
        }
      }
      SamsungPrintConv::RawDataCfaPattern => simple_label(raw, print_conv, |n| match n {
        0 => Some("Unchanged"),
        1 => Some("Swap"),
        65535 => Some("Roll"),
        _ => None,
      }),
      SamsungPrintConv::OffOn => simple_label(raw, print_conv, |n| match n {
        0 => Some("Off"),
        1 => Some("On"),
        _ => None,
      }),
      SamsungPrintConv::LensType => {
        let Some(n) = first_u64(raw) else {
          return raw_to_tag_value(raw);
        };
        if !print_conv {
          return u64_tag(n);
        }
        let id = u32::try_from(n).unwrap_or(0);
        match lens_types::lookup_name(id) {
          Some(name) => TagValue::Str(name),
          None => TagValue::Str(SmolStr::from(std::format!("Unknown ({n})"))),
        }
      }
      SamsungPrintConv::ColorSpace => simple_label(raw, print_conv, |n| match n {
        0 => Some("sRGB"),
        1 => Some("Adobe RGB"),
        _ => None,
      }),
      SamsungPrintConv::ExposureTime => {
        // rational64u. ValueConv `$val=~s/ .*//` keeps the first value (a single
        // rational is unaffected); the `-n` value is that rational's decimal.
        let Some(v) = first_f64(raw) else {
          return raw_to_tag_value(raw);
        };
        if !print_conv {
          return rational_first_value(raw);
        }
        TagValue::Str(SmolStr::from(print_exposure_time(v)))
      }
      SamsungPrintConv::FNumber => {
        let Some(v) = first_f64(raw) else {
          return raw_to_tag_value(raw);
        };
        if !print_conv {
          return rational_first_value(raw);
        }
        TagValue::Str(SmolStr::from(std::format!("{v:.1}")))
      }
      SamsungPrintConv::FocalLength35 => {
        // `Format => 'int32u'`, so `raw` is int32u; ValueConv `$val / 10`.
        let Some(n) = first_i64(raw) else {
          return raw_to_tag_value(raw);
        };
        let scaled = perl_div10(n);
        if !print_conv {
          return scaled_value(scaled);
        }
        TagValue::Str(SmolStr::from(std::format!("{} mm", fmt_num(scaled))))
      }
      SamsungPrintConv::PictureWizardMode => simple_label(raw, print_conv, |n| match n {
        0 => Some("Standard"),
        1 => Some("Vivid"),
        2 => Some("Portrait"),
        3 => Some("Landscape"),
        4 => Some("Forest"),
        5 => Some("Retro"),
        6 => Some("Cool"),
        7 => Some("Calm"),
        8 => Some("Classic"),
        9 => Some("Custom1"),
        10 => Some("Custom2"),
        11 => Some("Custom3"),
        255 => Some("n/a"),
        _ => None,
      }),
      SamsungPrintConv::PictureWizardMinus4 => {
        // ValueConv `$val - 4`; no PrintConv ⇒ both modes emit the shifted int.
        let Some(n) = first_i64(raw) else {
          return raw_to_tag_value(raw);
        };
        TagValue::I64(n - 4)
      }
    }
  }
}

/// `Image::ExifTool::Exif::PrintExposureTime` (`Exif.pm:5701-5711`).
fn print_exposure_time(secs: f64) -> std::string::String {
  if !secs.is_finite() {
    return fmt_num(secs);
  }
  if secs < 0.250_01 && secs > 0.0 {
    let inv = (0.5 + 1.0 / secs).floor();
    return std::format!("1/{}", inv as i64);
  }
  let s = std::format!("{secs:.1}");
  match s.strip_suffix(".0") {
    Some(t) => t.to_string(),
    None => s,
  }
}

/// Perl integer division by 10 toward zero (the `$val / 10` ValueConv on an
/// int32u value — exact for the integer inputs Samsung writes).
fn perl_div10(n: i64) -> f64 {
  n as f64 / 10.0
}

/// Render a `$val / 10` result for `-n`: an integral quotient stays an integer,
/// a fractional one a float (mirrors ExifTool's numeric `-n` value).
fn scaled_value(v: f64) -> TagValue {
  if v.fract() == 0.0 {
    TagValue::I64(v as i64)
  } else {
    TagValue::F64(v)
  }
}

/// Format a number the way ExifTool interpolates `"$val mm"` — an integral
/// value with no decimal point, else the shortest float.
fn fmt_num(v: f64) -> std::string::String {
  if v.fract() == 0.0 {
    std::format!("{}", v as i64)
  } else {
    let s = std::format!("{v}");
    s
  }
}

/// First scalar value as an unsigned `u64` (for the lookup PrintConvs).
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

/// The first rational's ExifTool value string (a decimal, or the bare word
/// `undef`/`inf` for a zero denominator) — for the `CameraTemperature`
/// `$val =~ /\d/` test. `None` when the value is not a rational.
fn rational_val_string(raw: &RawValue) -> Option<std::string::String> {
  match raw {
    RawValue::Rational(rs) => rs.first().map(|r| r.exiftool_val_str()),
    _ => None,
  }
}

/// Render the first element as the `-n` ValueConv value of a single-value
/// rational tag (`ExposureTime`/`FNumber` after the `$val=~s/ .*//` strip).
fn rational_first_value(raw: &RawValue) -> TagValue {
  match raw {
    RawValue::Rational(rs) => match rs.first() {
      Some(r) => TagValue::Rational(*r),
      None => raw_to_tag_value(raw),
    },
    _ => raw_to_tag_value(raw),
  }
}

/// Map a `u64` to the narrowest `TagValue` integer (mirrors the Sony helper:
/// an `i64`-representable value lands as `I64`, else `U64`).
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

/// Int -> label PrintConv with a HEX `Unknown (0xNN)` fallback (for the
/// `PrintHex => 1` rows).
fn hex_label<F: Fn(i64) -> Option<&'static str>>(
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
    None => TagValue::Str(SmolStr::from(std::format!("Unknown (0x{n:x})"))),
  }
}

/// `LocalLocationName` 0x0030 ValueConv (`Samsung.pm:296`) over the raw `undef`
/// bytes: `$val=~s/\0\0.*//; $val=~s/\0 */\n/g; $val`.
///
/// 1. Truncate at the FIRST double-NUL (`\0\0`) — the two-place-name terminator.
/// 2. Replace each `\0` + zero-or-more SPACE (0x20) run with a single `\n`.
///
/// Operates on bytes (the on-disk `undef` value), then lossy-decodes to UTF-8 —
/// the place names are Korean (or ASCII) text; the rare non-UTF-8 byte is
/// replaced, matching the walker's `string` rendering elsewhere.
fn local_location_name(b: &[u8]) -> std::string::String {
  // Step 1 — drop from the first `\0\0` onward.
  let head = match b.windows(2).position(|w| w == [0u8, 0u8]) {
    Some(i) => b.get(..i).unwrap_or(b),
    None => b,
  };
  // Step 2 — each NUL followed by zero-or-more spaces collapses to one newline.
  let mut out: Vec<u8> = Vec::with_capacity(head.len());
  let mut i = 0usize;
  while let Some(&c) = head.get(i) {
    if c == 0x00 {
      // Consume the NUL + any run of trailing spaces, emit one newline.
      i += 1;
      while head.get(i) == Some(&0x20) {
        i += 1;
      }
      out.push(b'\n');
    } else {
      out.push(c);
      i += 1;
    }
  }
  std::string::String::from_utf8_lossy(&out).into_owned()
}

/// Render a raw value as a default [`TagValue`] (no conversion) — mirrors the
/// Sony/Pentax helpers (single element ⇒ scalar; multi ⇒ space-joined string;
/// a multi-rational renders each element's ExifTool decimal).
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

/// `$$valPt =~ /^\w{5}/` (`Samsung.pm:406`) over the post-`ReadValue` `$val`
/// bytes: `true` when the value has at least five leading bytes, each an ASCII
/// word character `[A-Za-z0-9_]`. The bytes come from
/// [`RawValue::val_bytes`](crate::exif::ifd::RawValue::val_bytes) (the `Text`
/// shape's NUL-trimmed raw bytes for the `string`/`undef` SerialNumber row — the
/// faithful `$$valPt` for this test, see [`SamsungPrintConv::condition_holds`]).
fn val_pt_matches_word5(raw: &RawValue) -> bool {
  let bytes = raw.val_bytes();
  match bytes.get(..5) {
    Some(head) => head.iter().all(|&b| is_word_byte(b)),
    None => false,
  }
}

/// Perl `\w` (ASCII, no `/u`): `[A-Za-z0-9_]`.
const fn is_word_byte(b: u8) -> bool {
  b.is_ascii_alphanumeric() || b == b'_'
}

#[cfg(test)]
mod tests;
