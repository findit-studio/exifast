// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Shared helpers for the older Sony plain-`ProcessBinaryData` Main-IFD
//! SubDirectories the A33-class (SLT / DSLR-A4xx-A5xx / NEX) bodies dispatch:
//! [`super::camerainfo3`] (`CameraInfo3`), [`super::moreinfo`] (`MoreInfo` ->
//! `MoreSettings`/`FaceInfo`/`MoreInfo0201`/`MoreInfo0401`),
//! [`super::camerasettings3`] (`CameraSettings3`) and [`super::extrainfo3`]
//! (`ExtraInfo3`).
//!
//! These tables are NOT enciphered (unlike the `Tag9xxx` series); the verbatim
//! on-disk block bytes are read directly. Each per-field read follows the
//! `ProcessBinaryData` per-field-availability contract
//! ([[exifast-processbinarydata-per-field]]): a leaf is emitted IFF its byte
//! range is in the block AND its model `Condition` holds.

use crate::value::TagValue;
use smol_str::SmolStr;

/// One emitted leaf from an older Sony SubDirectory — the resolved `Name`,
/// rendered value and ExifTool `Priority => N`. Shared by all four `subtables`
/// modules so the [`crate::exif`] dispatch can iterate a single emission type.
pub struct SubEmission {
  /// `Name => '…'` from the bundled table.
  pub name: &'static str,
  /// The rendered value (`-j` PrintConv result, or `-n` raw `$val`).
  pub value: TagValue,
  /// The ExifTool `Priority => N` for this leaf (the table-level `PRIORITY`,
  /// overridden by an explicit per-leaf `Priority`). `0` means this leaf NEVER
  /// overrides an existing duplicate of the same `(doc, family1, name)`
  /// (`ExifTool.pm:9544-9560`) — e.g. the `PRIORITY => 0` `CameraSettings3`
  /// `Quality` must NOT override the higher-priority Main-IFD `0x0102` `Quality`
  /// (`RAW + JPEG/HEIF`).
  pub priority: u8,
}

impl SubEmission {
  /// A `Priority => 1` (default) leaf. The dispatch / parse functions overwrite
  /// `priority` for the `PRIORITY => 0` tables.
  #[must_use]
  pub fn new(name: &'static str, value: TagValue) -> Self {
    Self {
      name,
      value,
      priority: 1,
    }
  }
}

/// Read a little-endian `int16u` at byte `off` of the block (`None` if the
/// 2-byte range is out of bounds).
#[must_use]
pub fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
  match buf.get(off..off + 2) {
    Some(&[a, b]) => Some(u16::from_le_bytes([a, b])),
    _ => None,
  }
}

/// Read a little-endian `int16s` at byte `off` of the block.
#[must_use]
pub fn read_i16(buf: &[u8], off: usize) -> Option<i16> {
  match buf.get(off..off + 2) {
    Some(&[a, b]) => Some(i16::from_le_bytes([a, b])),
    _ => None,
  }
}

/// Read a little-endian `int32u` at byte `off` of the block.
#[must_use]
pub fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
  match buf.get(off..off + 4) {
    Some(&[a, b, c, d]) => Some(u32::from_le_bytes([a, b, c, d])),
    _ => None,
  }
}

/// `%afStatusInfo` rendered value (`Minolta.pm:647-660`): `int16s` where
/// `0 => 'In Focus'`, `-32768 => 'Out of Focus'`, else
/// `Front Focus ($val)` (`$val < 0`) / `Back Focus (+$val)`. `-n` is the raw
/// signed integer.
#[must_use]
pub fn af_status_value(v: i16, print_conv: bool) -> TagValue {
  if !print_conv {
    return TagValue::I64(i64::from(v));
  }
  let s = match v {
    0 => "In Focus".to_string(),
    -32768 => "Out of Focus".to_string(),
    n if n < 0 => std::format!("Front Focus ({n})"),
    n => std::format!("Back Focus (+{n})"),
  };
  TagValue::Str(SmolStr::new(s))
}

/// `int8s` `'$val > 0 ? "+$val" : $val'` PrintConv (the `ContrastSetting` /
/// `SaturationSetting` / `SharpnessSetting` / `ColorCompensationFilterSet`
/// signed-setting form). `-n` is the raw signed integer.
#[must_use]
pub fn signed_setting_value(v: i8, print_conv: bool) -> TagValue {
  if !print_conv {
    return TagValue::I64(i64::from(v));
  }
  let s = if v > 0 {
    std::format!("+{v}")
  } else {
    std::format!("{v}")
  };
  TagValue::Str(SmolStr::new(s))
}

/// `'$val ? sprintf("%+.1f",$val) : 0'` — the `ExposureCompensationSet` /
/// `FlashExposureCompSet` form (`ValueConv => '($val - 128) / 24'`). A zero
/// value renders the integer `0`; a non-zero value renders `%+.1f`. `-n` keeps
/// the float ValueConv result.
#[must_use]
pub fn exposure_comp_value(raw: u8, print_conv: bool) -> TagValue {
  let val = (f64::from(raw) - 128.0) / 24.0;
  if !print_conv {
    return TagValue::F64(val);
  }
  if val == 0.0 {
    TagValue::I64(0)
  } else {
    TagValue::Str(SmolStr::new(std::format!("{val:+.1}")))
  }
}

/// `'$val / 8'` `int16s` exposure-comp form (`ExposureCompensation2` /
/// `FlashExposureCompSet2`): `$val ? sprintf("%+.1f",$val) : 0`. `-n` keeps the
/// float.
#[must_use]
pub fn exposure_comp2_value(raw: i16, print_conv: bool) -> TagValue {
  let val = f64::from(raw) / 8.0;
  if !print_conv {
    return TagValue::F64(val);
  }
  if val == 0.0 {
    TagValue::I64(0)
  } else {
    TagValue::Str(SmolStr::new(std::format!("{val:+.1}")))
  }
}

/// Render a hash-PrintConv leaf with the bundled `PrintHex => 1` flag honoured.
/// A hit renders the label; a miss renders `"Unknown (0x%x)"` (`-j`) or the raw
/// integer (`-n`) per `ExifTool.pm:3603-3622`.
#[must_use]
pub fn hash_hex_value(raw: u32, hit: Option<&'static str>, print_conv: bool) -> TagValue {
  match (print_conv, hit) {
    (true, Some(s)) => TagValue::Str(SmolStr::new(s)),
    (true, None) => TagValue::Str(SmolStr::new(std::format!("Unknown (0x{raw:x})"))),
    (false, _) => TagValue::I64(i64::from(raw)),
  }
}

/// `$$self{Model} =~ /^(SLT-|DSLR-A(560|580))\b/` — the 15-point-AF body class
/// (`CameraInfo3` 15-point branch, `MoreSettings`/`CameraSettings3`/
/// `ExtraInfo3` "other / SLT" branches).
#[must_use]
pub fn model_is_slt_15pt(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  word_boundary_after(m, "SLT-")
    || word_boundary_after(m, "DSLR-A560")
    || word_boundary_after(m, "DSLR-A580")
}

/// `$$self{Model} =~ /^SLT-/`.
#[must_use]
pub fn model_is_slt(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.starts_with("SLT-"))
}

/// `$$self{Model} =~ /^DSLR-A(450|500|550)\b/` — the 9-point-AF DSLR class.
#[must_use]
pub fn model_is_a4xx_9pt(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  word_boundary_after(m, "DSLR-A450")
    || word_boundary_after(m, "DSLR-A500")
    || word_boundary_after(m, "DSLR-A550")
}

/// `$$self{Model} =~ /^NEX-(3|5|5C)/` (a prefix match, not a `\b` boundary —
/// the Perl alternation matches `NEX-3`, `NEX-5`, `NEX-5C`).
#[must_use]
pub fn model_is_nex355c(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  m.starts_with("NEX-3") || m.starts_with("NEX-5")
}

/// `$$self{Model} =~ /^NEX-/`.
#[must_use]
pub fn model_is_nex(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.starts_with("NEX-"))
}

/// `$$self{Model} =~ /^DSLR-/`.
#[must_use]
pub fn model_is_dslr(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.starts_with("DSLR-"))
}

/// `$$self{Model} =~ /^(NEX-(3|5|5C|C3|VG10|VG10E))\b/` — the ExtraInfo3 NEX
/// exclusion class (`BatteryVoltage1`/`BatteryVoltage2`/`ImageStabilization`
/// are NOT valid for these bodies).
#[must_use]
pub fn model_is_nex_battery_excl(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  for tail in [
    "NEX-3",
    "NEX-5",
    "NEX-5C",
    "NEX-C3",
    "NEX-VG10",
    "NEX-VG10E",
  ] {
    if word_boundary_after(m, tail) {
      return true;
    }
  }
  false
}

/// True when `m` starts with `prefix` AND a Perl `\b` word-boundary holds at the
/// position right after `prefix`, reproducing `/^prefix\b/`.
///
/// A `\b` boundary exists between two adjacent positions iff EXACTLY ONE is a
/// word char (`[A-Za-z0-9_]`). The boundary here is between the LAST char of
/// `prefix` and the NEXT char of `m` (or end-of-string). So a prefix ending in a
/// word char (e.g. `DSLR-A560`) needs the next char to be a non-word char / end,
/// whereas a prefix ending in a NON-word char (e.g. `SLT-`) needs the next char
/// to be a word char (the `-`→`A` transition in `SLT-A33`).
fn word_boundary_after(m: &str, prefix: &str) -> bool {
  let Some(rest) = m.strip_prefix(prefix) else {
    return false;
  };
  let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
  // The char immediately before the boundary = the last char of `prefix`.
  let before_is_word = prefix.chars().next_back().is_some_and(is_word);
  // The char immediately after the boundary = the first char of `rest` (a
  // non-word "char" at end-of-string).
  let after_is_word = rest.chars().next().is_some_and(is_word);
  before_is_word != after_is_word
}

/// `%whiteBalanceSetting` PrintConv (`Sony.pm` — the `PrintHex => 1` WB table
/// shared by `MoreSettings` 0x0d / `CameraSettings3` 0x16).
#[must_use]
pub fn white_balance_setting(v: u32) -> Option<&'static str> {
  Some(match v {
    0x10 => "Auto (-3)",
    0x11 => "Auto (-2)",
    0x12 => "Auto (-1)",
    0x13 => "Auto (0)",
    0x14 => "Auto (+1)",
    0x15 => "Auto (+2)",
    0x16 => "Auto (+3)",
    0x20 => "Daylight (-3)",
    0x21 => "Daylight (-2)",
    0x22 => "Daylight (-1)",
    0x23 => "Daylight (0)",
    0x24 => "Daylight (+1)",
    0x25 => "Daylight (+2)",
    0x26 => "Daylight (+3)",
    0x30 => "Shade (-3)",
    0x31 => "Shade (-2)",
    0x32 => "Shade (-1)",
    0x33 => "Shade (0)",
    0x34 => "Shade (+1)",
    0x35 => "Shade (+2)",
    0x36 => "Shade (+3)",
    0x40 => "Cloudy (-3)",
    0x41 => "Cloudy (-2)",
    0x42 => "Cloudy (-1)",
    0x43 => "Cloudy (0)",
    0x44 => "Cloudy (+1)",
    0x45 => "Cloudy (+2)",
    0x46 => "Cloudy (+3)",
    0x50 => "Tungsten (-3)",
    0x51 => "Tungsten (-2)",
    0x52 => "Tungsten (-1)",
    0x53 => "Tungsten (0)",
    0x54 => "Tungsten (+1)",
    0x55 => "Tungsten (+2)",
    0x56 => "Tungsten (+3)",
    0x60 => "Fluorescent (-3)",
    0x61 => "Fluorescent (-2)",
    0x62 => "Fluorescent (-1)",
    0x63 => "Fluorescent (0)",
    0x64 => "Fluorescent (+1)",
    0x65 => "Fluorescent (+2)",
    0x66 => "Fluorescent (+3)",
    0x70 => "Flash (-3)",
    0x71 => "Flash (-2)",
    0x72 => "Flash (-1)",
    0x73 => "Flash (0)",
    0x74 => "Flash (+1)",
    0x75 => "Flash (+2)",
    0x76 => "Flash (+3)",
    0xa3 => "Custom",
    0xf3 => "Color Temperature/Color Filter",
    _ => return None,
  })
}

/// `%sonyExposureProgram2` PrintConv (`Sony.pm`) — `MoreSettings` 0x02 /
/// `CameraSettings3` 0x05 `ExposureProgram`.
#[must_use]
pub fn exposure_program2(v: u32) -> Option<&'static str> {
  Some(match v {
    1 => "Program AE",
    2 => "Aperture-priority AE",
    3 => "Shutter speed priority AE",
    4 => "Manual",
    5 => "Cont. Priority AE",
    16 => "Auto",
    17 => "Auto (no flash)",
    18 => "Auto+",
    49 => "Portrait",
    50 => "Landscape",
    51 => "Macro",
    52 => "Sports",
    53 => "Sunset",
    54 => "Night view",
    55 => "Night view/portrait",
    56 => "Handheld Night Shot",
    57 => "3D Sweep Panorama",
    64 => "Auto 2",
    65 => "Auto 2 (no flash)",
    80 => "Sweep Panorama",
    96 => "Anti Motion Blur",
    128 => "Toy Camera",
    129 => "Pop Color",
    130 => "Posterization",
    131 => "Posterization B/W",
    132 => "Retro Photo",
    133 => "High-key",
    134 => "Partial Color Red",
    135 => "Partial Color Green",
    136 => "Partial Color Blue",
    137 => "Partial Color Yellow",
    138 => "High Contrast Monochrome",
    _ => return None,
  })
}

/// `%sonyDriveMode` shared `DriveMode2`/`DriveModeSetting`/`DriveMode` body
/// PrintConv (`PrintHex => 1`; `MoreSettings` 0x01 / `CameraSettings3`
/// 0x04). The extended `0xd1..0xd6` continuous variants only appear in the
/// `CameraSettings3` 0x34 `DriveMode` table; pass `extended = true` there.
#[must_use]
pub fn drive_mode(v: u32, extended: bool) -> Option<&'static str> {
  Some(match v {
    0x10 => "Single Frame",
    0x21 => "Continuous High",
    0x22 => "Continuous Low",
    0x30 => "Speed Priority Continuous",
    0x51 => "Self-timer 10 sec",
    0x52 => "Self-timer 2 sec, Mirror Lock-up",
    0x71 => "Continuous Bracketing 0.3 EV",
    0x75 => "Continuous Bracketing 0.7 EV",
    0x91 => "White Balance Bracketing Low",
    0x92 => "White Balance Bracketing High",
    0xc0 => "Remote Commander",
    0xd1 if extended => "Continuous - HDR",
    0xd2 if extended => "Continuous - Multi Frame NR",
    0xd3 if extended => "Continuous - Handheld Night Shot",
    0xd4 if extended => "Continuous - Anti Motion Blur",
    0xd5 if extended => "Continuous - Sweep Panorama",
    0xd6 if extended => "Continuous - 3D Sweep Panorama",
    _ => return None,
  })
}
