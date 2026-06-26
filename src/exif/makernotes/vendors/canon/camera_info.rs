// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Canon per-model `CameraInfo` sub-tables (`Canon.pm:3158-6002`).
//!
//! The `%Canon::Main` tag `0x0d` (`Canon.pm:1308-1494`) is a model-conditional
//! list of `Canon::CameraInfo<Model>` SubDirectories. This module ports the
//! EOS 5D table (`%Canon::CameraInfo5D`, `Canon.pm:3777-3964`, selected by
//! `$$self{Model} =~ /EOS 5D$/`). The newer bodies (`CameraInfo7D`, …) have a
//! firmware-dependent `Hook`/`varSize` offset shift and are deferred.
//!
//! `CameraInfo5D` is `FORMAT => 'int8s'`, `FIRST_ENTRY => 0`, `PRIORITY => 0`,
//! so a tag at position `p` is at byte offset `p` (one `int8s` per unit) and
//! EVERY leaf is `Priority => 0` — a duplicate of an earlier higher-or-equal
//! leaf (the `CanonShotInfo`/`CanonFocalLength`/`CanonCameraSettings` values,
//! walked first) NEVER overrides it (`ExifTool.pm:9544-9560`). The dispatch
//! site emits each pair with `tag_priority == 0` for exactly that reason.
//!
//! D8: pure decoder (no public struct fields); returns the `(Name, TagValue)`
//! emission pairs the dispatch site wraps in the `Canon` family-1 group.

#![deny(clippy::indexing_slicing)]

use super::camera_settings::canon_ev;
use super::lens_types;
use super::printconv::picture_style_label;
use super::shot_info::white_balance_label;
use crate::datetime::convert_unix_time;
use crate::exif::ifd::ByteOrder;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::string::String;
use std::vec::Vec;

/// `true` when `model` selects `%Canon::CameraInfo5D` via the `0x0d`
/// conditional list (`Canon.pm:1342`, `$$self{Model} =~ /EOS 5D$/` — anchored,
/// so the original 5D only, NOT "5D Mark II/III").
#[must_use]
pub fn model_is_camera_info_5d(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.trim_end().ends_with("EOS 5D"))
}

/// Decode the `Canon::CameraInfo` block for the parent `model`. Only the EOS 5D
/// variant is ported; any other model yields nothing (deferred). `print_conv`
/// selects the PrintConv vs ValueConv view.
#[must_use]
pub fn parse(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
) -> Vec<(SmolStr, TagValue)> {
  if model_is_camera_info_5d(model) {
    camera_info_5d(data, order, print_conv)
  } else {
    Vec::new()
  }
}

/// `%Canon::CameraInfo5D` (`Canon.pm:3777-3964`).
fn camera_info_5d(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));

  // 0x03 FNumber (int8u, RawConv drop-0, exp((val-8)/16*ln2), PrintConv %.2g).
  if let Some(raw) = i8u(data, 0x03)
    && raw != 0
  {
    let vc = ((raw as f64 - 8.0) / 16.0 * std::f64::consts::LN_2).exp();
    push("FNumber", value_or_print(print_conv, vc, format_g2(vc)));
  }
  // 0x04 ExposureTime (int8u, RawConv drop-0, exp(4*ln2*(1-CanonEv(val-24)))).
  if let Some(raw) = i8u(data, 0x04)
    && raw != 0
  {
    let vc = (4.0 * std::f64::consts::LN_2 * (1.0 - canon_ev(raw - 24))).exp();
    push(
      "ExposureTime",
      value_or_print(print_conv, vc, print_exposure_time(vc)),
    );
  }
  // 0x06 ISO (int8u, 100*exp((val/8-9)*ln2), PrintConv %.0f).
  if let Some(raw) = i8u(data, 0x06) {
    let vc = 100.0 * ((raw as f64 / 8.0 - 9.0) * std::f64::consts::LN_2).exp();
    push(
      "ISO",
      value_or_print(print_conv, vc, std::format!("{vc:.0}")),
    );
  }
  // 0x0c LensType (int16uRev, RawConv drop-0, %canonLensTypes).
  if let Some(v) = u16_rev(data, 0x0c, order)
    && v != 0
  {
    push("LensType", lens_type_value(v, print_conv));
  }
  // 0x17 CameraTemperature (int8u, val-128, "$val C").
  if let Some(raw) = i8u(data, 0x17) {
    let c = raw - 128;
    push(
      "CameraTemperature",
      if print_conv {
        TagValue::Str(SmolStr::from(std::format!("{c} C")))
      } else {
        TagValue::I64(c)
      },
    );
  }
  // 0x27 CameraOrientation (int8s, PrintConv).
  if let Some(v) = i8s(data, 0x27) {
    push(
      "CameraOrientation",
      enum8(v, print_conv, camera_orientation_label),
    );
  }
  // 0x28 FocalLength (int16uRev, RawConv drop-0, "$val mm").
  if let Some(v) = u16_rev(data, 0x28, order)
    && v != 0
  {
    push("FocalLength", mm_value(v, print_conv));
  }
  // 0x38 AFPointsInFocus5D (int16uRev, BITMASK).
  if let Some(v) = u16_rev(data, 0x38, order) {
    push(
      "AFPointsInFocus5D",
      if print_conv {
        TagValue::Str(SmolStr::from(af_points_in_focus_5d(v)))
      } else {
        TagValue::I64(v)
      },
    );
  }
  // 0x54 WhiteBalance (int16u, %canonWhiteBalance).
  if let Some(v) = u16(data, 0x54, order) {
    push(
      "WhiteBalance",
      if print_conv {
        hash16(v, white_balance_label(v))
      } else {
        TagValue::I64(v)
      },
    );
  }
  // 0x58 ColorTemperature (int16u, plain).
  if let Some(v) = u16(data, 0x58, order) {
    push("ColorTemperature", TagValue::I64(v));
  }
  // 0x6c PictureStyle (int8u, PrintHex, %pictureStyles).
  if let Some(v) = i8u(data, 0x6c) {
    push("PictureStyle", picture_style_value(v, print_conv));
  }
  // 0x93 MinFocalLength, 0x95 MaxFocalLength (int16uRev, "$val mm").
  if let Some(v) = u16_rev(data, 0x93, order) {
    push("MinFocalLength", mm_value(v, print_conv));
  }
  if let Some(v) = u16_rev(data, 0x95, order) {
    push("MaxFocalLength", mm_value(v, print_conv));
  }
  // 0x97 LensType (int16uRev, %canonLensTypes).
  if let Some(v) = u16_rev(data, 0x97, order) {
    push("LensType", lens_type_value(v, print_conv));
  }
  // 0xa4 FirmwareRevision (string[8]); 0xac ShortOwnerName (string[16]).
  if let Some(s) = read_string(data, 0xa4, 8) {
    push("FirmwareRevision", TagValue::Str(SmolStr::from(s)));
  }
  if let Some(s) = read_string(data, 0xac, 16) {
    push("ShortOwnerName", TagValue::Str(SmolStr::from(s)));
  }
  // 0xcc DirectoryIndex (int32u, plain).
  if let Some(v) = u32(data, 0xcc, order) {
    push("DirectoryIndex", TagValue::I64(v));
  }
  // 0xd0 FileIndex (int16u, ValueConv $val+1).
  if let Some(v) = u16(data, 0xd0, order) {
    push("FileIndex", TagValue::I64(v + 1));
  }
  // 0xe8..0x10b — plain int8s style scalars (no PrintConv).
  for &(off, name) in STYLE_SCALARS_5D {
    if let Some(v) = i8s(data, off) {
      push(name, TagValue::I64(v));
    }
  }
  // 0xff FilterEffectMonochrome, 0x108 ToningEffectMonochrome (int8s, PrintConv).
  if let Some(v) = i8s(data, 0xff) {
    push(
      "FilterEffectMonochrome",
      enum8(v, print_conv, filter_effect_label),
    );
  }
  if let Some(v) = i8s(data, 0x108) {
    push(
      "ToningEffectMonochrome",
      enum8(v, print_conv, toning_effect_label),
    );
  }
  // 0x10c/0x10e/0x110 UserDef{1,2,3}PictureStyle (int16u, %userDefStyles).
  for &(off, name) in &[
    (0x10c, "UserDef1PictureStyle"),
    (0x10e, "UserDef2PictureStyle"),
    (0x110, "UserDef3PictureStyle"),
  ] {
    if let Some(v) = u16(data, off, order) {
      push(name, user_def_style_value(v, print_conv));
    }
  }
  // 0x11c TimeStamp (int32u, RawConv drop-0, ConvertUnixTime ⇒ same in -j/-n).
  if let Some(v) = u32(data, 0x11c, order)
    && v != 0
  {
    push(
      "TimeStamp",
      TagValue::Str(SmolStr::from(convert_unix_time(v))),
    );
  }
  out
}

/// The plain `int8s` per-style scalars (`Contrast`/`Sharpness`/`Saturation`/
/// `ColorTone` × the style set, `Canon.pm:3877-3933`). No PrintConv.
const STYLE_SCALARS_5D: &[(usize, &str)] = &[
  (0xe8, "ContrastStandard"),
  (0xe9, "ContrastPortrait"),
  (0xea, "ContrastLandscape"),
  (0xeb, "ContrastNeutral"),
  (0xec, "ContrastFaithful"),
  (0xed, "ContrastMonochrome"),
  (0xee, "ContrastUserDef1"),
  (0xef, "ContrastUserDef2"),
  (0xf0, "ContrastUserDef3"),
  (0xf1, "SharpnessStandard"),
  (0xf2, "SharpnessPortrait"),
  (0xf3, "SharpnessLandscape"),
  (0xf4, "SharpnessNeutral"),
  (0xf5, "SharpnessFaithful"),
  (0xf6, "SharpnessMonochrome"),
  (0xf7, "SharpnessUserDef1"),
  (0xf8, "SharpnessUserDef2"),
  (0xf9, "SharpnessUserDef3"),
  (0xfa, "SaturationStandard"),
  (0xfb, "SaturationPortrait"),
  (0xfc, "SaturationLandscape"),
  (0xfd, "SaturationNeutral"),
  (0xfe, "SaturationFaithful"),
  (0x100, "SaturationUserDef1"),
  (0x101, "SaturationUserDef2"),
  (0x102, "SaturationUserDef3"),
  (0x103, "ColorToneStandard"),
  (0x104, "ColorTonePortrait"),
  (0x105, "ColorToneLandscape"),
  (0x106, "ColorToneNeutral"),
  (0x107, "ColorToneFaithful"),
  (0x109, "ColorToneUserDef1"),
  (0x10a, "ColorToneUserDef2"),
  (0x10b, "ColorToneUserDef3"),
];

/// `CameraOrientation` PrintConv (`Canon.pm:3800-3804`).
fn camera_orientation_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Horizontal (normal)",
    1 => "Rotate 90 CW",
    2 => "Rotate 270 CW",
    _ => return None,
  })
}

/// `FilterEffectMonochrome` PrintConv (`Canon.pm:3902-3910`).
fn filter_effect_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "None",
    1 => "Yellow",
    2 => "Orange",
    3 => "Red",
    4 => "Green",
    _ => return None,
  })
}

/// `ToningEffectMonochrome` PrintConv (`Canon.pm:3921-3929`).
fn toning_effect_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "None",
    1 => "Sepia",
    2 => "Blue",
    3 => "Purple",
    4 => "Green",
    _ => return None,
  })
}

/// `%userDefStyles` (`Canon.pm:1149-1165`).
fn user_def_style_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0x41 => "PC 1",
    0x42 => "PC 2",
    0x43 => "PC 3",
    0x81 => "Standard",
    0x82 => "Portrait",
    0x83 => "Landscape",
    0x84 => "Neutral",
    0x85 => "Faithful",
    0x86 => "Monochrome",
    0x87 => "Auto",
    _ => return None,
  })
}

/// `AFPointsInFocus5D` (`Canon.pm:3807-3830`) — `0 => '(none)'`, else a
/// `BITMASK` joined with `", "` (DecodeBits: a set bit `n` renders its label or
/// `"[n]"`).
fn af_points_in_focus_5d(v: i64) -> String {
  if v == 0 {
    return String::from("(none)");
  }
  const LABELS: &[&str] = &[
    "Center",
    "Top",
    "Bottom",
    "Upper-left",
    "Upper-right",
    "Lower-left",
    "Lower-right",
    "Left",
    "Right",
    "AI Servo1",
    "AI Servo2",
    "AI Servo3",
    "AI Servo4",
    "AI Servo5",
    "AI Servo6",
  ];
  let mut parts: Vec<String> = Vec::new();
  for bit in 0..32u32 {
    if v & (1i64 << bit) != 0 {
      match LABELS.get(bit as usize) {
        Some(l) => parts.push(String::from(*l)),
        None => parts.push(std::format!("[{bit}]")),
      }
    }
  }
  parts.join(", ")
}

/// Render a `%canonLensTypes` PrintConv (`PrintInt`): the resolved name, or
/// `Unknown (N)`; raw int under `-n`.
fn lens_type_value(v: i64, print_conv: bool) -> TagValue {
  if print_conv {
    match u16::try_from(v).ok().and_then(lens_types::lookup_name) {
      Some(name) => TagValue::Str(name),
      None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
    }
  } else {
    TagValue::I64(v)
  }
}

/// Render `%pictureStyles` (`PrintHex`): the label, or `Unknown (0xNN)`.
fn picture_style_value(v: i64, print_conv: bool) -> TagValue {
  if print_conv {
    match picture_style_label(v) {
      Some(l) => TagValue::Str(SmolStr::new_static(l)),
      None => TagValue::Str(SmolStr::from(std::format!("Unknown (0x{v:x})"))),
    }
  } else {
    TagValue::I64(v)
  }
}

/// Render `%userDefStyles` (`PrintHex` on `UserDef1` only — irrelevant once a
/// label resolves): the label, or `Unknown (0xNN)`.
fn user_def_style_value(v: i64, print_conv: bool) -> TagValue {
  if print_conv {
    match user_def_style_label(v) {
      Some(l) => TagValue::Str(SmolStr::new_static(l)),
      None => TagValue::Str(SmolStr::from(std::format!("Unknown (0x{v:x})"))),
    }
  } else {
    TagValue::I64(v)
  }
}

/// Render a `"$val mm"` focal-length leaf; raw int under `-n`.
fn mm_value(v: i64, print_conv: bool) -> TagValue {
  if print_conv {
    TagValue::Str(SmolStr::from(std::format!("{v} mm")))
  } else {
    TagValue::I64(v)
  }
}

/// Render an `int8s` enum PrintConv (label or `Unknown (N)`); raw under `-n`.
fn enum8(v: i64, print_conv: bool, label: fn(i64) -> Option<&'static str>) -> TagValue {
  if print_conv {
    hash16(v, label(v))
  } else {
    TagValue::I64(v)
  }
}

/// A hash PrintConv result: the label, or `Unknown (N)`.
fn hash16(v: i64, label: Option<&'static str>) -> TagValue {
  match label {
    Some(l) => TagValue::Str(SmolStr::new_static(l)),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
  }
}

/// Choose the `-j` print text or the `-n` ValueConv number (whole-vs-fractional).
fn value_or_print(print_conv: bool, vc: f64, print: String) -> TagValue {
  if print_conv {
    TagValue::Str(SmolStr::from(print))
  } else if vc.fract() == 0.0 && vc.is_finite() {
    TagValue::I64(vc as i64)
  } else {
    TagValue::F64(vc)
  }
}

/// `sprintf("%.2g", $val)` — ExifTool's FNumber PrintConv.
fn format_g2(v: f64) -> String {
  crate::value::format_g(v, 2)
}

/// `Image::ExifTool::Exif::PrintExposureTime` (`Exif.pm`).
fn print_exposure_time(secs: f64) -> String {
  if secs > 0.0 && secs < 0.25001 {
    return std::format!("1/{}", (0.5 + 1.0 / secs) as i64);
  }
  let s = std::format!("{secs:.1}");
  String::from(s.strip_suffix(".0").unwrap_or(&s))
}

// ─── byte readers (FORMAT int8s ⇒ byte offset == word position) ──────────────

/// Read one signed 8-bit byte at `off`.
fn i8s(data: &[u8], off: usize) -> Option<i64> {
  data.get(off).map(|&b| b as i8 as i64)
}

/// Read one unsigned 8-bit byte at `off`.
fn i8u(data: &[u8], off: usize) -> Option<i64> {
  data.get(off).map(|&b| b as i64)
}

/// Read an unsigned 16-bit word at byte `off` in the file's byte order.
fn u16(data: &[u8], off: usize, order: ByteOrder) -> Option<i64> {
  let arr: [u8; 2] = data.get(off..off + 2)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u16::from_le_bytes(arr),
    ByteOrder::Big => u16::from_be_bytes(arr),
  } as i64)
}

/// Read an `int16uRev` word at byte `off` — the 16-bit value is stored with the
/// REVERSED byte order (big-endian for a little-endian file, `Canon.pm:3789`).
fn u16_rev(data: &[u8], off: usize, order: ByteOrder) -> Option<i64> {
  let arr: [u8; 2] = data.get(off..off + 2)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u16::from_be_bytes(arr),
    ByteOrder::Big => u16::from_le_bytes(arr),
  } as i64)
}

/// Read an unsigned 32-bit word at byte `off` in the file's byte order.
fn u32(data: &[u8], off: usize, order: ByteOrder) -> Option<i64> {
  let arr: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u32::from_le_bytes(arr),
    ByteOrder::Big => u32::from_be_bytes(arr),
  } as i64)
}

/// Read a `string[len]` at byte `off`: the bytes up to the first NUL, decoded
/// as Latin-1/ASCII (the owner name is ASCII). `None` if the field is past the
/// end of `data`.
fn read_string(data: &[u8], off: usize, len: usize) -> Option<String> {
  let bytes = data.get(off..off + len)?;
  let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
  let slice = bytes.get(..end)?;
  Some(slice.iter().map(|&b| b as char).collect())
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  /// Build a CameraInfo5D blob with the named bytes set (the rest zero).
  fn blob() -> Vec<u8> {
    let mut b = vec![0u8; 0x120];
    b[0x06] = 88; // ISO raw
    b[0x27] = 0; // CameraOrientation
    // AFPointsInFocus5D int16uRev: bytes "00 01" ⇒ BE ⇒ 1.
    b[0x38] = 0x00;
    b[0x39] = 0x01;
    b[0x58] = 0x50; // ColorTemperature LE 0x1450 = 5200
    b[0x59] = 0x14;
    b[0x6c] = 0x81; // PictureStyle 0x81
    b[0xa4..0xac].copy_from_slice(b"1.1.1.2\0");
    b[0xac..0xbc].copy_from_slice(b"Julian Tolchard\0");
    b[0xd0] = 0x93; // FileIndex LE 0x0593 = 1427 ⇒ +1 = 1428
    b[0xd1] = 0x05;
    b[0xf1] = 3; // SharpnessStandard
    b[0x10c] = 0x81; // UserDef1PictureStyle 0x0081
    // TimeStamp int32u LE 1370690080 = 0x51B31220.
    b[0x11c..0x120].copy_from_slice(&1_370_690_080u32.to_le_bytes());
    b
  }

  #[test]
  fn camera_info_5d_print_values() {
    let data = blob();
    let em = parse(&data, ByteOrder::Little, true, Some("Canon EOS 5D"));
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Horizontal (normal)".into()))
    );
    assert_eq!(
      find("AFPointsInFocus5D"),
      Some(TagValue::Str("Center".into()))
    );
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("PictureStyle"), Some(TagValue::Str("Standard".into())));
    assert_eq!(
      find("FirmwareRevision"),
      Some(TagValue::Str("1.1.1.2".into()))
    );
    assert_eq!(
      find("ShortOwnerName"),
      Some(TagValue::Str("Julian Tolchard".into()))
    );
    assert_eq!(find("FileIndex"), Some(TagValue::I64(1428)));
    assert_eq!(find("SharpnessStandard"), Some(TagValue::I64(3)));
    assert_eq!(
      find("UserDef1PictureStyle"),
      Some(TagValue::Str("Standard".into()))
    );
    assert_eq!(
      find("TimeStamp"),
      Some(TagValue::Str("2013:06:08 11:14:40".into()))
    );
  }

  #[test]
  fn camera_info_5d_numeric_iso() {
    let data = blob();
    let em = parse(&data, ByteOrder::Little, false, Some("Canon EOS 5D"));
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::I64(400)));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(1428)));
  }

  #[test]
  fn dispatch_anchored() {
    assert!(model_is_camera_info_5d(Some("Canon EOS 5D")));
    assert!(!model_is_camera_info_5d(Some("Canon EOS 5D Mark II")));
    assert!(!model_is_camera_info_5d(Some("Canon EOS 7D")));
    // A non-5D model yields nothing.
    assert!(parse(&[0u8; 0x120], ByteOrder::Little, true, Some("Canon EOS 7D")).is_empty());
  }
}
