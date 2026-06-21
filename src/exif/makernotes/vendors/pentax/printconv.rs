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
  /// `0x001d FocalLength` (the default non-Optio K10D variant,
  /// `Pentax.pm:1752-1764`) — int32u; ValueConv `$val / 100`; PrintConv
  /// `sprintf("%.1f mm", $val)`.
  FocalLength,
  /// `0x002d EffectiveLV` (the `$format eq "int16u"` variant,
  /// `Pentax.pm:1884-1893`) — `Format => 'int16s'` (re-read signed); ValueConv
  /// `$val / 1024`; PrintConv `sprintf("%.1f", $val)`.
  EffectiveLv,
  /// `0x0016 ExposureCompensation` (the `$count == 1` variant,
  /// `Pentax.pm:1593-1604`) — int16u; ValueConv `($val - 50) / 10`; PrintConv
  /// `$val ? sprintf("%+.1f", $val) : 0`.
  ExposureCompensation,
  /// `0x004d FlashExposureComp` (the `$count == 1` variant,
  /// `Pentax.pm:2182-2189`) — int32s; ValueConv `$val / 256`; PrintConv
  /// `$val ? sprintf("%+.1f", $val) : 0`.
  FlashExposureComp,
  /// `0x000c FlashMode` (`Pentax.pm:1131-1163`) — int16u `Count => -1`,
  /// `PrintHex => 1`. A 2-element ARRAY PrintConv: element 0 via the
  /// flash-mode hash, element 1 via the external-flash hash, joined with `"; "`
  /// (`ExifTool.pm:3697`). `-n` ⇒ the space-joined raw run.
  FlashMode,
  /// `0x0018 AutoBracketing` (`Pentax.pm:1626-1685`) — int16u `Count => -1`. A
  /// per-element ValueConv (`$val/3` for `$val<10`, …) then the bracket
  /// PrintConv `sub` (element 0 `sprintf('%.1f')` unless falsy/fraction;
  /// element 1 the extended-bracket label or `'No Extended Bracket'`), joined
  /// with `' EV, '`. `-n` ⇒ the space-joined post-ValueConv run.
  AutoBracketing,
  /// `0x0033 PictureMode` (`Pentax.pm:1922-2016`) — int8u `Count => 3`,
  /// `Relist => [[0,1], 2]` (join elements 0+1 with a space, keep element 2),
  /// then a 2-element ARRAY PrintConv joined with `"; "`. `-n` ⇒ the raw
  /// space-joined int8u[3] run (Relist runs only for the PrintConv side).
  PictureMode,
  /// `0x0034 DriveMode` (`Pentax.pm:2018-2062`) — int8u `Count => 4`, a
  /// 4-element ARRAY PrintConv (one hash per element) joined with `"; "`.
  /// `-n` ⇒ the raw space-joined int8u[4] run.
  DriveMode,
  /// `0x0032 ImageEditing` (`Pentax.pm:1904-1920`) — `Format => 'int8u',
  /// Count => 4`; a HASH PrintConv keyed on the SPACE-JOINED run (e.g.
  /// `"0 0 0 0" => 'None'`), decimal `Unknown (…)` fallback. `-n` ⇒ the
  /// space-joined run.
  StringKeyedHash(&'static [(&'static str, &'static str)]),
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
      PentaxPrintConv::FocalLength => {
        let Some(n) = first_u64(raw) else {
          return raw_to_tag_value(raw);
        };
        // ValueConv `$val / 100`.
        let v = n as f64 / 100.0;
        if !print_conv {
          return TagValue::F64(v);
        }
        // PrintConv `sprintf("%.1f mm", $val)`.
        TagValue::Str(SmolStr::from(std::format!("{v:.1} mm")))
      }
      PentaxPrintConv::EffectiveLv => {
        // `Format => 'int16s'` already re-read the on-disk bytes signed, so the
        // entry value is an `int16s`. ValueConv `$val / 1024`.
        let Some(n) = first_i64(raw) else {
          return raw_to_tag_value(raw);
        };
        let v = n as f64 / 1024.0;
        if !print_conv {
          return TagValue::F64(v);
        }
        // PrintConv `sprintf("%.1f", $val)`.
        TagValue::Str(SmolStr::from(std::format!("{v:.1}")))
      }
      PentaxPrintConv::ExposureCompensation => signed_div_ev(raw, print_conv, 50.0, 10.0),
      PentaxPrintConv::FlashExposureComp => signed_div_ev(raw, print_conv, 0.0, 256.0),
      PentaxPrintConv::FlashMode => flash_mode(raw, print_conv),
      PentaxPrintConv::AutoBracketing => auto_bracketing(raw, print_conv),
      PentaxPrintConv::PictureMode => picture_mode(raw, print_conv),
      PentaxPrintConv::DriveMode => drive_mode(raw, print_conv),
      PentaxPrintConv::StringKeyedHash(table) => string_keyed_hash(raw, print_conv, table),
    }
  }
}

/// `0x0023`-style numeric ARRAY view of `raw` (each element as `i64`), or `None`
/// for a non-numeric shape.
fn numeric_elems(raw: &RawValue) -> Option<std::vec::Vec<i64>> {
  match raw {
    RawValue::U64(v) => Some(v.iter().map(|&n| n as i64).collect()),
    RawValue::I64(v) => Some(v.clone()),
    RawValue::Bytes(b) => Some(b.iter().map(|&n| i64::from(n)).collect()),
    _ => None,
  }
}

/// The shared `($val - sub) / div` ValueConv with the `$val ? sprintf("%+.1f",
/// $val) : 0` PrintConv (`ExposureCompensation` 0x0016 = `(50, 10)`,
/// `FlashExposureComp` 0x004d = `(0, 256)`). `-n` ⇒ the post-ValueConv `f64`.
fn signed_div_ev(raw: &RawValue, print_conv: bool, sub: f64, div: f64) -> TagValue {
  let Some(n) = first_i64(raw) else {
    return raw_to_tag_value(raw);
  };
  let v = (n as f64 - sub) / div;
  if !print_conv {
    return TagValue::F64(v);
  }
  if v == 0.0 {
    return TagValue::I64(0);
  }
  TagValue::Str(SmolStr::from(std::format!("{v:+.1}")))
}

/// `0x000c FlashMode` (`Pentax.pm:1131-1163`) — `Count => -1`, `PrintHex => 1`,
/// a 2-element ARRAY PrintConv: element 0 via [`FLASH_MODE_0`], element 1 via
/// [`FLASH_MODE_1`], joined with `"; "`. A miss renders the `PrintHex`
/// `Unknown (0xNN)` fallback. `-n` ⇒ the space-joined raw run.
fn flash_mode(raw: &RawValue, print_conv: bool) -> TagValue {
  if !print_conv {
    return TagValue::Str(SmolStr::from(space_join(raw)));
  }
  let Some(elems) = numeric_elems(raw) else {
    return raw_to_tag_value(raw);
  };
  let tables: [&[(i64, &str)]; 2] = [FLASH_MODE_0, FLASH_MODE_1];
  let mut parts: std::vec::Vec<std::string::String> = std::vec::Vec::new();
  for (i, &n) in elems.iter().enumerate() {
    // The Perl ARRAY PrintConv runs each element through ITS positional hash;
    // an element past the 2-entry list falls through to the LAST hash
    // (`ExifTool.pm:3666`, `$conv = $$convList[-1]` when the index runs off the
    // end) — unreachable for the 2-element K10D record, but faithful.
    let table = *tables
      .get(i)
      .or_else(|| tables.last())
      .unwrap_or(&FLASH_MODE_0);
    match hash_get(table, n) {
      Some(l) => parts.push(l.to_string()),
      None => parts.push(std::format!("Unknown (0x{n:x})")),
    }
  }
  TagValue::Str(SmolStr::from(parts.join("; ")))
}

/// `0x0018 AutoBracketing` (`Pentax.pm:1626-1685`) — the per-element ValueConv
/// then the bracket PrintConv `sub`. `-n` ⇒ the space-joined post-ValueConv run.
fn auto_bracketing(raw: &RawValue, print_conv: bool) -> TagValue {
  let Some(elems) = numeric_elems(raw) else {
    return raw_to_tag_value(raw);
  };
  // ValueConv (applied to EACH element, `ExifTool.pm` ARRAY ValueConv):
  //   return $val / 3 if $val < 10;
  //   return $val - 9.5 if $val < 20;
  //   return ($val - 0x1000) . '/2' if $val & 0x1000;
  //   return ($val - 0x2000) . '/3' if $val & 0x2000;
  //   return $val;
  // Each converted element is a STRING (the `. '/2'` arms) or a number; keep the
  // string form so the `-n` join + the PrintConv `split(' ')` see the same shape.
  let conv = |val: i64| -> std::string::String {
    if val < 10 {
      crate::value::format_g(val as f64 / 3.0, 15)
    } else if val < 20 {
      crate::value::format_g(val as f64 - 9.5, 15)
    } else if val & 0x1000 != 0 {
      std::format!("{}/2", val - 0x1000)
    } else if val & 0x2000 != 0 {
      std::format!("{}/3", val - 0x2000)
    } else {
      val.to_string()
    }
  };
  let vc: std::vec::Vec<std::string::String> = elems.iter().map(|&n| conv(n)).collect();
  if !print_conv {
    return TagValue::Str(SmolStr::from(vc.join(" ")));
  }
  // PrintConv `sub` (`Pentax.pm:1654-1666`):
  //   my @v = split(' ', shift);
  //   $v[0] = sprintf('%.1f', $v[0]) if $v[0] and $v[0]!~m{/};
  //   if ($v[1]) { ...extended-bracket label... }
  //   elsif (defined $v[1]) { $v[1] = 'No Extended Bracket' }
  //   return join(' EV, ', @v);
  let mut v: std::vec::Vec<std::string::String> = vc;
  // `$v[0] = sprintf('%.1f', $v[0]) if $v[0] and $v[0]!~m{/}` — Perl numeric
  // truthiness: "0" / "0.0" / "" are FALSE; a "/"-bearing fraction is skipped.
  if let Some(first) = v.first_mut() {
    if perl_str_true(first) && !first.contains('/') {
      let f: f64 = first.parse().unwrap_or(0.0);
      *first = std::format!("{f:.1}");
    }
  }
  match v.get(1) {
    Some(second) if perl_str_true(second) => {
      // Extended bracket: `$t = $v[1] >> 8; sprintf('%s+%d', $s{$t}||"Unknown($t)",
      // $v[1] & 0xff)`. `$v[1]` is the post-ValueConv string; for an element >= 20
      // it is "<n>/2"/"<n>/3", but the extended-bracket arm only triggers for a
      // value with a numeric `$v[1]` (a second element), so parse the integer.
      let n: i64 = second
        .split('/')
        .next()
        .and_then(|t| t.parse().ok())
        .unwrap_or(0);
      let t = n >> 8;
      let label = match t {
        1 => "WB-BA",
        2 => "WB-GM",
        3 => "Saturation",
        4 => "Sharpness",
        5 => "Contrast",
        6 => "Hue",
        7 => "HighLowKey",
        _ => "",
      };
      let lo = n & 0xff;
      let s1 = if label.is_empty() {
        std::format!("Unknown({t})+{lo}")
      } else {
        std::format!("{label}+{lo}")
      };
      if let Some(slot) = v.get_mut(1) {
        *slot = s1;
      }
    }
    Some(_) => {
      // `elsif (defined $v[1])` — a present-but-falsy second element.
      if let Some(slot) = v.get_mut(1) {
        *slot = "No Extended Bracket".to_string();
      }
    }
    None => {}
  }
  TagValue::Str(SmolStr::from(v.join(" EV, ")))
}

/// Perl string truthiness for the AutoBracketing PrintConv: the empty string,
/// `"0"` and any all-zero numeric string (`"0.0"`, `"0.00"`, `"00"`) are FALSE;
/// everything else is TRUE.
fn perl_str_true(s: &str) -> bool {
  if s.is_empty() || s == "0" {
    return false;
  }
  // A numeric string that evaluates to 0 (e.g. "0.0") is also Perl-false.
  match s.parse::<f64>() {
    Ok(f) => f != 0.0,
    Err(_) => true,
  }
}

/// `0x0033 PictureMode` (`Pentax.pm:1922-2016`) — `Count => 3`,
/// `Relist => [[0,1], 2]`, a 2-element ARRAY PrintConv joined with `"; "`.
/// `-n` ⇒ the raw space-joined int8u[3] run (Relist is a PrintConv-side regroup).
fn picture_mode(raw: &RawValue, print_conv: bool) -> TagValue {
  if !print_conv {
    return TagValue::Str(SmolStr::from(space_join(raw)));
  }
  let Some(elems) = numeric_elems(raw) else {
    return raw_to_tag_value(raw);
  };
  // Relist `[[0,1], 2]`: group 0 = elements 0 and 1 space-joined; group 1 =
  // element 2 (`ExifTool.pm` Relist).
  let g0 = match (elems.first(), elems.get(1)) {
    (Some(a), Some(b)) => std::format!("{a} {b}"),
    (Some(a), None) => a.to_string(),
    _ => return raw_to_tag_value(raw),
  };
  // Group 0 via the string-keyed PICTURE_MODE hash; group 1 via the EV-step hash.
  let part0 = match str_hash_get(PICTURE_MODE, &g0) {
    Some(l) => l.to_string(),
    None => std::format!("Unknown ({g0})"),
  };
  let Some(&g1) = elems.get(2) else {
    // Only one Relist group present ⇒ just the first PrintConv element.
    return TagValue::Str(SmolStr::from(part0));
  };
  let part1 = match hash_get(PICTURE_MODE_EV_STEPS, g1) {
    Some(l) => l.to_string(),
    None => std::format!("Unknown ({g1})"),
  };
  TagValue::Str(SmolStr::from(std::format!("{part0}; {part1}")))
}

/// `0x0034 DriveMode` (`Pentax.pm:2018-2062`) — `Count => 4`, a 4-element ARRAY
/// PrintConv (one hash per element) joined with `"; "`. `-n` ⇒ the raw
/// space-joined int8u[4] run.
fn drive_mode(raw: &RawValue, print_conv: bool) -> TagValue {
  if !print_conv {
    return TagValue::Str(SmolStr::from(space_join(raw)));
  }
  let Some(elems) = numeric_elems(raw) else {
    return raw_to_tag_value(raw);
  };
  let tables: [&[(i64, &str)]; 4] = [DRIVE_MODE_0, DRIVE_MODE_1, DRIVE_MODE_2, DRIVE_MODE_3];
  let mut parts: std::vec::Vec<std::string::String> = std::vec::Vec::new();
  for (i, &n) in elems.iter().enumerate() {
    let table = *tables
      .get(i)
      .or_else(|| tables.last())
      .unwrap_or(&DRIVE_MODE_0);
    match hash_get(table, n) {
      Some(l) => parts.push(l.to_string()),
      None => parts.push(std::format!("Unknown ({n})")),
    }
  }
  TagValue::Str(SmolStr::from(parts.join("; ")))
}

/// A PrintConv HASH keyed on the SPACE-JOINED run (`0x0032 ImageEditing`,
/// `Pentax.pm:1904-1920`): the multi-element value's default rendering (the
/// `"0 0 0 0"` string) is the lookup key; a miss renders `Unknown (…)`. `-n` ⇒
/// the space-joined run.
fn string_keyed_hash(
  raw: &RawValue,
  print_conv: bool,
  table: &[(&'static str, &'static str)],
) -> TagValue {
  let joined = space_join(raw);
  if !print_conv {
    return TagValue::Str(SmolStr::from(joined));
  }
  match str_hash_get(table, &joined) {
    Some(l) => TagValue::Str(SmolStr::from(l)),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({joined})"))),
  }
}

/// Linear-search a `(string-key, label)` PrintConv hash (the keys are
/// space-joined run strings; the lists are short, so a linear scan is fine).
fn str_hash_get(table: &[(&'static str, &'static str)], key: &str) -> Option<&'static str> {
  table.iter().find(|&&(k, _)| k == key).map(|&(_, v)| v)
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

// ---------------------------------------------------------------------------
// `%Pentax::SRInfo` / `%Pentax::BatteryInfo` / `%Pentax::AFInfo` binary
// SubDirectory PrintConv tables (#173). Each int-keyed hash is sorted by key for
// binary search; each `*_BITS` table is the `DecodeBits` BITMASK label set.
// ---------------------------------------------------------------------------

/// `SRInfo` `0 SRResult` BITMASK (`Pentax.pm:3180-3185`) — `{ 0 => 'Not
/// stabilized', BITMASK => { 0 => 'Stabilized', 6 => 'Not ready' } }`. The
/// `0 => 'Not stabilized'` zero label is passed separately to `bitmask0`.
pub(crate) const SR_RESULT_BITS: &[(u8, &str)] = &[(0, "Stabilized"), (6, "Not ready")];

/// `SRInfo` `1 ShakeReduction` PrintConv (`Pentax.pm:3190-3203`). Sorted by key.
pub(crate) const SHAKE_REDUCTION: &[(i64, &str)] = &[
  (0, "Off"),
  (1, "On"),
  (4, "Off (4)"),
  (5, "On but Disabled"),
  (6, "On (Video)"),
  (7, "On (7)"),
  (15, "On (15)"),
  (39, "On (mode 2)"),
  (135, "On (135)"),
  (167, "On (mode 1)"),
];

/// `BatteryInfo` `0.1 PowerSource` PrintConv (the non-K-3III variant, mask 0x0f,
/// `Pentax.pm:4774-4779`). Sorted by key.
pub(crate) const POWER_SOURCE: &[(i64, &str)] = &[
  (1, "Camera Battery"),
  (2, "Body Battery"),
  (3, "Grip Battery"),
  (4, "External Power Supply"),
];

/// `BatteryInfo` `1.1 BodyBatteryState` PrintConv (the *istD/K100D/K200D/K10D/K20D
/// variant, mask 0xf0, `Pentax.pm:4810-4815`). Sorted by key.
pub(crate) const BODY_BATTERY_STATE_K10D: &[(i64, &str)] = &[
  (1, "Empty or Missing"),
  (2, "Almost Empty"),
  (3, "Running Low"),
  (4, "Full"),
];

/// `BatteryInfo` `1.2 GripBatteryState` PrintConv (the K10D/K20D variant, mask
/// 0x0f, `Pentax.pm:4836-4841`). Sorted by key.
pub(crate) const GRIP_BATTERY_STATE_K10D: &[(i64, &str)] = &[
  (1, "Empty or Missing"),
  (2, "Almost Empty"),
  (3, "Running Low"),
  (4, "Full"),
];

/// `AFInfo` `0x0b AFPointsInFocus` PrintConv (the non-K-1/3/70/KP/K-S1/S2
/// variant, `Pentax.pm:5077-5099`). Sorted by key.
pub(crate) const AF_POINTS_IN_FOCUS: &[(i64, &str)] = &[
  (0, "None"),
  (1, "Lower-left, Bottom"),
  (2, "Bottom"),
  (3, "Lower-right, Bottom"),
  (4, "Mid-left, Center"),
  (5, "Center (horizontal)"),
  (6, "Mid-right, Center"),
  (7, "Upper-left, Top"),
  (8, "Top"),
  (9, "Upper-right, Top"),
  (10, "Right"),
  (11, "Lower-left, Mid-left"),
  (12, "Upper-left, Mid-left"),
  (13, "Bottom, Center"),
  (14, "Top, Center"),
  (15, "Lower-right, Mid-right"),
  (16, "Upper-right, Mid-right"),
  (17, "Left"),
  (18, "Mid-left"),
  (19, "Center (vertical)"),
  (20, "Mid-right"),
];

/// `%Pentax::LensData` `0.2 MinAperture` PrintConv (`Pentax.pm:4407-4412`). The
/// numeric-looking string labels (`"22"`) render as JSON numbers. Sorted by key.
pub(crate) const LENS_MIN_APERTURE: &[(i64, &str)] = &[(0, "22"), (1, "32"), (2, "45"), (3, "16")];

/// `%Pentax::LensData` `0.1 AutoAperture` PrintConv (`Pentax.pm:4400`). Sorted
/// by key.
pub(crate) const AUTO_APERTURE: &[(i64, &str)] = &[(0, "On"), (1, "Off")];

/// `%Pentax::LensData` `3.1 FocusRangeIndex` PrintConv (`Pentax.pm:4472-4481`).
/// Sorted by key for binary search.
pub(crate) const FOCUS_RANGE_INDEX: &[(i64, &str)] = &[
  (0, "5"),
  (1, "4"),
  (2, "6 (far)"),
  (3, "7 (very far)"),
  (4, "2"),
  (5, "3"),
  (6, "1 (close)"),
  (7, "0 (very close)"),
];

// ---------------------------------------------------------------------------
// `%Pentax::Main` ARRAY / string-keyed PrintConv tables for the conditional /
// multi-element camera-indexing leaves (#173). The int-keyed positional element
// hashes for the ARRAY-PrintConv leaves live here (referenced by the helpers
// above); the simple int-keyed leaf hashes (FocusMode / AFPointSelected /
// RawDevelopmentProcess) live in `tags.rs` beside the other `Hash(...)` tables.
// ---------------------------------------------------------------------------

/// `0x000c FlashMode` element 0 PrintConv (`Pentax.pm:1136-1151`, `PrintHex`).
/// Sorted by key for binary search.
pub(crate) const FLASH_MODE_0: &[(i64, &str)] = &[
  (0x000, "Auto, Did not fire"),
  (0x001, "Off, Did not fire"),
  (0x002, "On, Did not fire"),
  (0x003, "Auto, Did not fire, Red-eye reduction"),
  (0x005, "On, Did not fire, Wireless (Master)"),
  (0x100, "Auto, Fired"),
  (0x102, "On, Fired"),
  (0x103, "Auto, Fired, Red-eye reduction"),
  (0x104, "On, Red-eye reduction"),
  (0x105, "On, Wireless (Master)"),
  (0x106, "On, Wireless (Control)"),
  (0x108, "On, Soft"),
  (0x109, "On, Slow-sync"),
  (0x10a, "On, Slow-sync, Red-eye reduction"),
  (0x10b, "On, Trailing-curtain Sync"),
];

/// `0x000c FlashMode` element 1 PrintConv — the AF-540FGZ external-flash hash
/// (`Pentax.pm:1152-1162`, `PrintHex`). Sorted by key for binary search.
pub(crate) const FLASH_MODE_1: &[(i64, &str)] = &[
  (0x000, "n/a - Off-Auto-Aperture"),
  (0x03f, "Internal"),
  (0x100, "External, Auto"),
  (0x23f, "External, Flash Problem"),
  (0x300, "External, Manual"),
  (0x304, "External, P-TTL Auto"),
  (0x305, "External, Contrast-control Sync"),
  (0x306, "External, High-speed Sync"),
  (0x30c, "External, Wireless"),
  (0x30d, "External, Wireless, High-speed Sync"),
];

/// `0x0033 PictureMode` element-0 PrintConv (`Pentax.pm:1928-2012`) — keyed on
/// the space-joined Relist group `"$v0 $v1"`. The full bundled hash (the K10D
/// fixture hits `"5 0" => 'Aperture Priority'`).
pub(crate) const PICTURE_MODE: &[(&str, &str)] = &[
  ("0 0", "Program"),
  ("0 1", "Hi-speed Program"),
  ("0 2", "DOF Program"),
  ("0 3", "MTF Program"),
  ("0 4", "Standard"),
  ("0 5", "Portrait"),
  ("0 6", "Landscape"),
  ("0 7", "Macro"),
  ("0 8", "Sport"),
  ("0 9", "Night Scene Portrait"),
  ("0 10", "No Flash"),
  ("0 11", "Night Scene"),
  ("0 12", "Surf & Snow"),
  ("0 13", "Text"),
  ("0 14", "Sunset"),
  ("0 15", "Kids"),
  ("0 16", "Pet"),
  ("0 17", "Candlelight"),
  ("0 18", "Museum"),
  ("0 19", "Food"),
  ("0 20", "Stage Lighting"),
  ("0 21", "Night Snap"),
  ("0 23", "Blue Sky"),
  ("0 24", "Sunset"),
  ("0 26", "Night Scene HDR"),
  ("0 27", "HDR"),
  ("0 28", "Quick Macro"),
  ("0 29", "Forest"),
  ("0 30", "Backlight Silhouette"),
  ("0 31", "Max. Aperture Priority"),
  ("0 32", "DOF"),
  ("1 4", "Auto PICT (Standard)"),
  ("1 5", "Auto PICT (Portrait)"),
  ("1 6", "Auto PICT (Landscape)"),
  ("1 7", "Auto PICT (Macro)"),
  ("1 8", "Auto PICT (Sport)"),
  ("2 0", "Program (HyP)"),
  ("2 1", "Hi-speed Program (HyP)"),
  ("2 2", "DOF Program (HyP)"),
  ("2 3", "MTF Program (HyP)"),
  ("2 22", "Shallow DOF (HyP)"),
  ("3 0", "Green Mode"),
  ("4 0", "Shutter Speed Priority"),
  ("4 2", "Shutter Speed Priority 2"),
  ("4 31", "Shutter Speed Priority 31"),
  ("5 0", "Aperture Priority"),
  ("5 2", "Aperture Priority 2"),
  ("5 31", "Aperture Priority 31"),
  ("6 0", "Program Tv Shift"),
  ("7 0", "Program Av Shift"),
  ("8 0", "Manual"),
  ("9 0", "Bulb"),
  ("10 0", "Aperture Priority, Off-Auto-Aperture"),
  ("11 0", "Manual, Off-Auto-Aperture"),
  ("12 0", "Bulb, Off-Auto-Aperture"),
  ("19 0", "Astrotracer"),
  ("13 0", "Shutter & Aperture Priority AE"),
  ("14 0", "Shutter Priority AE"),
  ("15 0", "Sensitivity Priority AE"),
  ("16 0", "Flash X-Sync Speed AE"),
  ("17 0", "Flash X-Sync Speed"),
  ("18 0", "Auto Program (Normal)"),
  ("18 1", "Auto Program (Hi-speed)"),
  ("18 2", "Auto Program (DOF)"),
  ("18 3", "Auto Program (MTF)"),
  ("18 22", "Auto Program (Shallow DOF)"),
  ("20 22", "Blur Control"),
  ("24 0", "Aperture Priority (Adv.Hyp)"),
  ("25 0", "Manual Exposure (Adv.Hyp)"),
  ("26 0", "Shutter and Aperture Priority (TAv)"),
  ("249 0", "Movie (TAv)"),
  ("250 0", "Movie (TAv, Auto Aperture)"),
  ("251 0", "Movie (Manual)"),
  ("252 0", "Movie (Manual, Auto Aperture)"),
  ("253 0", "Movie (Av)"),
  ("254 0", "Movie (Av, Auto Aperture)"),
  ("255 0", "Movie (P, Auto Aperture)"),
  ("255 4", "Video (4)"),
];

/// `0x0033 PictureMode` element-1 PrintConv — the EV-step hash
/// (`Pentax.pm:2013-2015`). Sorted by key for binary search.
pub(crate) const PICTURE_MODE_EV_STEPS: &[(i64, &str)] =
  &[(0, "1/2 EV steps"), (1, "1/3 EV steps")];

/// `0x0034 DriveMode` element 0 PrintConv (`Pentax.pm:2022-2031`). Sorted by key.
pub(crate) const DRIVE_MODE_0: &[(i64, &str)] = &[
  (0, "Single-frame"),
  (1, "Continuous"),
  (2, "Continuous (Lo)"),
  (3, "Burst"),
  (4, "Continuous (Medium)"),
  (5, "Continuous (Low)"),
  (255, "Video"),
];

/// `0x0034 DriveMode` element 1 PrintConv (`Pentax.pm:2032-2038`). Sorted by key.
pub(crate) const DRIVE_MODE_1: &[(i64, &str)] = &[
  (0, "No Timer"),
  (1, "Self-timer (12 s)"),
  (2, "Self-timer (2 s)"),
  (15, "Video"),
  (16, "Mirror Lock-up"),
  (255, "n/a"),
];

/// `0x0034 DriveMode` element 2 PrintConv (`Pentax.pm:2039-2043`). Sorted by key.
pub(crate) const DRIVE_MODE_2: &[(i64, &str)] = &[
  (0, "Shutter Button"),
  (1, "Remote Control (3 s delay)"),
  (2, "Remote Control"),
  (4, "Remote Continuous Shooting"),
];

/// `0x0034 DriveMode` element 3 PrintConv (`Pentax.pm:2044-2061`, `PrintHex` in
/// the table but rendered through the decimal `DecodeBits`-free hash — the keys
/// are listed as hex literals, looked up against the integer value). Sorted by
/// key for binary search.
pub(crate) const DRIVE_MODE_3: &[(i64, &str)] = &[
  (0x00, "Single Exposure"),
  (0x01, "Multiple Exposure"),
  (0x02, "Composite Average"),
  (0x03, "Composite Additive"),
  (0x04, "Composite Bright"),
  (0x08, "Interval Shooting"),
  (0x0a, "Interval Composite Average"),
  (0x0b, "Interval Composite Additive"),
  (0x0c, "Interval Composite Bright"),
  (0x0f, "Interval Movie"),
  (0x10, "HDR"),
  (0x20, "HDR Strong 1"),
  (0x30, "HDR Strong 2"),
  (0x40, "HDR Strong 3"),
  (0x50, "HDR Manual"),
  (0xe0, "HDR Auto"),
  (0xff, "Video"),
];

/// `0x0032 ImageEditing` PrintConv (`Pentax.pm:1909-1919`) — keyed on the
/// space-joined int8u[4] run.
pub(crate) const IMAGE_EDITING: &[(&str, &str)] = &[
  ("0 0", "None"),
  ("0 0 0 0", "None"),
  ("0 0 0 4", "Digital Filter"),
  ("1 0 0 0", "Resized"),
  ("2 0 0 0", "Cropped"),
  ("4 0 0 0", "Digital Filter 4"),
  ("6 0 0 0", "Digital Filter 6"),
  ("8 0 0 0", "Red-eye Correction"),
  ("16 0 0 0", "Frame Synthesis?"),
];

/// `0x006c HighLowKeyAdj` PrintConv (`Pentax.pm:2378-2386`) — int16s `Count =>
/// 2`, keyed on the space-joined `"adj 0"` pair. The integer labels render as
/// bare JSON numbers via the `EscapeJSON` number gate (`"0 0" => 0`, etc.).
pub(crate) const HIGH_LOW_KEY_ADJ: &[(&str, &str)] = &[
  ("-4 0", "-4"),
  ("-3 0", "-3"),
  ("-2 0", "-2"),
  ("-1 0", "-1"),
  ("0 0", "0"),
  ("1 0", "1"),
  ("2 0", "2"),
  ("3 0", "3"),
  ("4 0", "4"),
];

#[cfg(test)]
mod tests;
