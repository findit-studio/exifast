// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Canon per-model `CameraInfo` sub-tables (`Canon.pm:3158-6002`).
//!
//! The `%Canon::Main` tag `0x0d` (`Canon.pm:1308-1494`) is a model-conditional
//! list of `Canon::CameraInfo<Model>` SubDirectories. This module ports the
//! EOS 5D table (`%Canon::CameraInfo5D`, `Canon.pm:3777-3964`, selected by
//! `$$self{Model} =~ /EOS 5D$/`) and the EOS 7D table (`%Canon::CameraInfo7D`,
//! `Canon.pm:4342-4489`, selected by `$$self{Model} =~ /EOS 7D$/`).
//!
//! `CameraInfo7D` is `FORMAT => 'int8u'`, `PRIORITY => 0`, with a
//! firmware-dependent `Hook`/`varSize` offset shift (`Canon.pm:4347-4402`): the
//! `0x00 FirmwareVersionLookAhead` RawConv probes the version string at 0x1a8
//! (`CanonFirm = 1`) then 0x1ac (`CanonFirm = 2`); the `0x1e` `Hook`
//! (`$varSize += ($$self{CanonFirm} ? -4 : 0x10000) if $$self{CanonFirm} < 2`)
//! shifts every leaf at/after 0x1e accordingly. Its `0x327 PictureStyleInfo`
//! `IS_SUBDIR` points at the nested `%Canon::PSInfo` table (`Canon.pm:6018`,
//! `PRIORITY => 0`), emitted in the same `Canon` group.
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
  } else if model_is_camera_info_7d(model) {
    camera_info_7d(data, order, print_conv)
  } else {
    Vec::new()
  }
}

/// `true` when `model` selects `%Canon::CameraInfo7D` via the `0x0d`
/// conditional list (`Canon.pm:4338`, `$$self{Model} =~ /EOS 7D$/` — anchored,
/// so the original 7D only, NOT "7D Mark II").
#[must_use]
pub fn model_is_camera_info_7d(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.trim_end().ends_with("EOS 7D"))
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

/// `%Canon::CameraInfo7D` (`Canon.pm:4342-4489`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`. The `0x1e` `Hook` shifts every leaf at/after 0x1e by
/// `varSize` (firmware-version dependent); the `0x327 PictureStyleInfo`
/// `IS_SUBDIR` walks the nested `%Canon::PSInfo` table.
fn camera_info_7d(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));

  // 0x00 FirmwareVersionLookAhead (`Canon.pm:4354-4368`): probe the firmware
  // string position to set CanonFirm, which drives the 0x1e `Hook` shift.
  let canon_firm = canon_firm_7d(data);
  // 0x1e `Hook`: `$varSize += ($$self{CanonFirm} ? -4 : 0x10000) if
  // $$self{CanonFirm} < 2` — applied to EVERY leaf at byte offset >= 0x1e.
  let var_size: i64 = if canon_firm < 2 {
    if canon_firm != 0 { -4 } else { 0x1_0000 }
  } else {
    0
  };
  // Map a table offset to its actual byte offset (the `Hook` shift fires at
  // 0x1e). `None` when the shifted offset is not representable (CanonFirm == 0
  // pushes every later leaf out of range — ExifTool emits nothing for them).
  let at = |off: usize| -> Option<usize> {
    let a: i64 = if off >= 0x1e {
      off as i64 + var_size
    } else {
      off as i64
    };
    usize::try_from(a).ok()
  };

  // 0x03 FNumber / 0x04 ExposureTime / 0x06 ISO (`%ciFNumber`/`%ciExposureTime`/
  // `%ciISO`, int8u). FNumber/ExposureTime collide with the walked-first
  // `ShotInfo` (`Priority => 0` ⇒ suppressed); ISO is the lone non-colliding leaf.
  if let Some(off) = at(0x03)
    && let Some(raw) = i8u(data, off)
    && raw != 0
  {
    let vc = ((raw as f64 - 8.0) / 16.0 * std::f64::consts::LN_2).exp();
    push("FNumber", value_or_print(print_conv, vc, format_g2(vc)));
  }
  if let Some(off) = at(0x04)
    && let Some(raw) = i8u(data, off)
    && raw != 0
  {
    let vc = (4.0 * std::f64::consts::LN_2 * (1.0 - canon_ev(raw - 24))).exp();
    push(
      "ExposureTime",
      value_or_print(print_conv, vc, print_exposure_time(vc)),
    );
  }
  if let Some(off) = at(0x06)
    && let Some(raw) = i8u(data, off)
  {
    let vc = 100.0 * ((raw as f64 / 8.0 - 9.0) * std::f64::consts::LN_2).exp();
    push(
      "ISO",
      value_or_print(print_conv, vc, std::format!("{vc:.0}")),
    );
  }
  // 0x07 HighlightTonePriority (int8u, %offOn).
  if let Some(off) = at(0x07)
    && let Some(v) = i8u(data, off)
  {
    push("HighlightTonePriority", enum8(v, print_conv, off_on_label));
  }
  // 0x08 MeasuredEV2 / 0x09 MeasuredEV (int8u, RawConv drop-0, `$val/8-6`,
  // NO PrintConv ⇒ a bare JSON number in both views).
  if let Some(off) = at(0x08)
    && let Some(raw) = i8u(data, off)
    && raw != 0
  {
    push("MeasuredEV2", ev_value(raw as f64 / 8.0 - 6.0));
  }
  if let Some(off) = at(0x09)
    && let Some(raw) = i8u(data, off)
    && raw != 0
  {
    push("MeasuredEV", ev_value(raw as f64 / 8.0 - 6.0));
  }
  // 0x15 FlashMeteringMode (int8u, PrintConv hash).
  if let Some(off) = at(0x15)
    && let Some(v) = i8u(data, off)
  {
    push(
      "FlashMeteringMode",
      enum8(v, print_conv, flash_metering_mode_label),
    );
  }
  // 0x19 CameraTemperature (`%ciCameraTemperature`, int8u, `$val-128`, "$val C").
  if let Some(off) = at(0x19)
    && let Some(raw) = i8u(data, off)
  {
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
  // 0x1e FocalLength (`%ciFocalLength`, int16uRev, RawConv drop-0, "$val mm")
  // — the `Hook` leaf itself (read at the shifted offset).
  if let Some(off) = at(0x1e)
    && let Some(v) = u16_rev(data, off, order)
    && v != 0
  {
    push("FocalLength", mm_value(v, print_conv));
  }
  // 0x35 CameraOrientation (int8u, PrintConv).
  if let Some(off) = at(0x35)
    && let Some(v) = i8u(data, off)
  {
    push(
      "CameraOrientation",
      enum8(v, print_conv, camera_orientation_label),
    );
  }
  // 0x54 FocusDistanceUpper / 0x56 FocusDistanceLower (`%focusDistanceByteSwap`,
  // int16uRev, `$val/100`, ">655.345 ? inf : '$val m'"). Collide with the
  // higher-priority `FileInfo` leaves (walked later ⇒ they win).
  if let Some(off) = at(0x54)
    && let Some(raw) = u16_rev(data, off, order)
  {
    push("FocusDistanceUpper", focus_distance_value(raw, print_conv));
  }
  if let Some(off) = at(0x56)
    && let Some(raw) = u16_rev(data, off, order)
  {
    push("FocusDistanceLower", focus_distance_value(raw, print_conv));
  }
  // 0x77 WhiteBalance (int16u, %canonWhiteBalance).
  if let Some(off) = at(0x77)
    && let Some(v) = u16(data, off, order)
  {
    push(
      "WhiteBalance",
      if print_conv {
        hash16(v, white_balance_label(v))
      } else {
        TagValue::I64(v)
      },
    );
  }
  // 0x7b ColorTemperature (int16u, plain).
  if let Some(off) = at(0x7b)
    && let Some(v) = u16(data, off, order)
  {
    push("ColorTemperature", TagValue::I64(v));
  }
  // 0xaf CameraPictureStyle (int8u, PrintHex, model-specific hash).
  if let Some(off) = at(0xaf)
    && let Some(v) = i8u(data, off)
  {
    push(
      "CameraPictureStyle",
      camera_picture_style_value(v, print_conv),
    );
  }
  // 0xc9 HighISONoiseReduction (int8u, PrintConv hash).
  if let Some(off) = at(0xc9)
    && let Some(v) = i8u(data, off)
  {
    push(
      "HighISONoiseReduction",
      enum8(v, print_conv, high_iso_nr_label),
    );
  }
  // 0x112 LensType (int16uRev, %canonLensTypes).
  if let Some(off) = at(0x112)
    && let Some(v) = u16_rev(data, off, order)
  {
    push("LensType", lens_type_value(v, print_conv));
  }
  // 0x114 MinFocalLength / 0x116 MaxFocalLength (int16uRev, "$val mm").
  if let Some(off) = at(0x114)
    && let Some(v) = u16_rev(data, off, order)
  {
    push("MinFocalLength", mm_value(v, print_conv));
  }
  if let Some(off) = at(0x116)
    && let Some(v) = u16_rev(data, off, order)
  {
    push("MaxFocalLength", mm_value(v, print_conv));
  }
  // 0x1ac FirmwareVersion (string[6], RawConv `/^\d+\.\d+\.\d+\s*$/`).
  if let Some(off) = at(0x1ac)
    && let Some(s) = read_string(data, off, 6)
    && is_firmware_version(&s)
  {
    push("FirmwareVersion", TagValue::Str(SmolStr::from(s)));
  }
  // 0x1eb FileIndex (int32u, ValueConv `$val + 1`).
  if let Some(off) = at(0x1eb)
    && let Some(v) = u32(data, off, order)
  {
    push("FileIndex", TagValue::I64(v + 1));
  }
  // 0x1f7 DirectoryIndex (int32u, ValueConv `$val - 1`).
  if let Some(off) = at(0x1f7)
    && let Some(v) = u32(data, off, order)
  {
    push("DirectoryIndex", TagValue::I64(v - 1));
  }
  // 0x327 PictureStyleInfo (`IS_SUBDIR` ⇒ `%Canon::PSInfo`, FIRST_ENTRY 0,
  // PRIORITY 0). The SubDirectory starts at the shifted 0x327.
  if let Some(ps_start) = at(0x327) {
    ps_info(data, ps_start, order, print_conv, &mut push);
  }
  out
}

/// `%Canon::CameraInfo7D` `0x00 FirmwareVersionLookAhead` RawConv
/// (`Canon.pm:4359-4366`): `CanonFirm = 1` if a `D.D.D` version prefix sits at
/// 0x1a8, else `2` if at 0x1ac, else `0` (ExifTool warns then the `Hook` shifts
/// every later leaf out of range).
fn canon_firm_7d(data: &[u8]) -> u8 {
  if firmware_prefix_at(data, 0x1a8) {
    1
  } else if firmware_prefix_at(data, 0x1ac) {
    2
  } else {
    0
  }
}

/// `substr($val, $off, 6) =~ /^\d+\.\d+\.\d+/` — a `D.D.D` version prefix in the
/// 6-byte window at `off`.
fn firmware_prefix_at(data: &[u8], off: usize) -> bool {
  data
    .get(off..off + 6)
    .is_some_and(|b| version_prefix_len(b).is_some())
}

/// `/^\d+\.\d+\.\d+\s*$/` — the `0x1ac FirmwareVersion` RawConv (`Canon.pm:4469`):
/// a full `D.D.D` version, optionally trailing whitespace, NOTHING else.
fn is_firmware_version(s: &str) -> bool {
  match version_prefix_len(s.as_bytes()) {
    Some(n) => s.as_bytes().get(n..).is_some_and(|t| {
      t.iter()
        .all(|&c| c == b' ' || c == b'\t' || c == b'\r' || c == b'\n')
    }),
    None => false,
  }
}

/// Length of a leading `\d+\.\d+\.\d+` (digits, dot, digits, dot, digits), or
/// `None` if the bytes do not start with one.
fn version_prefix_len(b: &[u8]) -> Option<usize> {
  let mut i = 0usize;
  let digits = |i: &mut usize| -> bool {
    let start = *i;
    while b.get(*i).is_some_and(u8::is_ascii_digit) {
      *i += 1;
    }
    *i > start
  };
  if !digits(&mut i) {
    return None;
  }
  if b.get(i) != Some(&b'.') {
    return None;
  }
  i += 1;
  if !digits(&mut i) {
    return None;
  }
  if b.get(i) != Some(&b'.') {
    return None;
  }
  i += 1;
  if !digits(&mut i) {
    return None;
  }
  Some(i)
}

/// `%Canon::PSInfo` (`Canon.pm:6018-6175`). FORMAT int32s, FIRST_ENTRY 0,
/// PRIORITY 0. The `Unknown => 1` rows (the per-style FilterEffect/ToningEffect
/// for Standard..Faithful, and Saturation/ColorTone Monochrome) are suppressed.
fn ps_info<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  start: usize,
  order: ByteOrder,
  print_conv: bool,
  push: &mut F,
) {
  // The plain int32s scalars (`%psConv`: 0xdeadbeef ⇒ "n/a", else passthrough).
  for &(off, name) in PS_SCALARS {
    if let Some(v) = i32s(data, start + off, order) {
      push(name, ps_scalar_value(v, print_conv));
    }
  }
  // FilterEffect/ToningEffect (Monochrome + the three UserDefs) — explicit
  // PrintConv hashes (with 0xdeadbeef ⇒ "n/a").
  for &(off, name, toning) in PS_EFFECTS {
    if let Some(v) = i32s(data, start + off, order) {
      let label = if toning {
        ps_toning_effect_label(v)
      } else {
        ps_filter_effect_label(v)
      };
      push(name, ps_effect_value(v, print_conv, label));
    }
  }
  // UserDef{1,2,3}PictureStyle (int16u, %userDefStyles). PSInfo's entries carry
  // NO `PrintHex` (`Canon.pm:6152-6169`), so an unresolved value renders the
  // DECIMAL `Unknown (N)` fallback (unlike the `CameraInfo5D` UserDef1 leaf).
  for &(off, name) in &[
    (0xd8usize, "UserDef1PictureStyle"),
    (0xda, "UserDef2PictureStyle"),
    (0xdc, "UserDef3PictureStyle"),
  ] {
    if let Some(v) = u16(data, start + off, order) {
      let value = if print_conv {
        match user_def_style_label(v) {
          Some(l) => TagValue::Str(SmolStr::new_static(l)),
          None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
        }
      } else {
        TagValue::I64(v)
      };
      push(name, value);
    }
  }
}

/// The plain `%psInfo` scalars emitted for the 7D (`Canon.pm:6025-6130`, minus
/// the `Unknown => 1` FilterEffect/ToningEffect Standard..Faithful + Saturation/
/// ColorTone Monochrome rows).
const PS_SCALARS: &[(usize, &str)] = &[
  (0x00, "ContrastStandard"),
  (0x04, "SharpnessStandard"),
  (0x08, "SaturationStandard"),
  (0x0c, "ColorToneStandard"),
  (0x18, "ContrastPortrait"),
  (0x1c, "SharpnessPortrait"),
  (0x20, "SaturationPortrait"),
  (0x24, "ColorTonePortrait"),
  (0x30, "ContrastLandscape"),
  (0x34, "SharpnessLandscape"),
  (0x38, "SaturationLandscape"),
  (0x3c, "ColorToneLandscape"),
  (0x48, "ContrastNeutral"),
  (0x4c, "SharpnessNeutral"),
  (0x50, "SaturationNeutral"),
  (0x54, "ColorToneNeutral"),
  (0x60, "ContrastFaithful"),
  (0x64, "SharpnessFaithful"),
  (0x68, "SaturationFaithful"),
  (0x6c, "ColorToneFaithful"),
  (0x78, "ContrastMonochrome"),
  (0x7c, "SharpnessMonochrome"),
  (0x90, "ContrastUserDef1"),
  (0x94, "SharpnessUserDef1"),
  (0x98, "SaturationUserDef1"),
  (0x9c, "ColorToneUserDef1"),
  (0xa8, "ContrastUserDef2"),
  (0xac, "SharpnessUserDef2"),
  (0xb0, "SaturationUserDef2"),
  (0xb4, "ColorToneUserDef2"),
  (0xc0, "ContrastUserDef3"),
  (0xc4, "SharpnessUserDef3"),
  (0xc8, "SaturationUserDef3"),
  (0xcc, "ColorToneUserDef3"),
];

/// The FilterEffect/ToningEffect PSInfo entries that carry an explicit PrintConv
/// (`Canon.pm:6059-6149`): `(offset, name, is_toning)`.
const PS_EFFECTS: &[(usize, &str, bool)] = &[
  (0x88, "FilterEffectMonochrome", false),
  (0x8c, "ToningEffectMonochrome", true),
  (0xa0, "FilterEffectUserDef1", false),
  (0xa4, "ToningEffectUserDef1", true),
  (0xb8, "FilterEffectUserDef2", false),
  (0xbc, "ToningEffectUserDef2", true),
  (0xd0, "FilterEffectUserDef3", false),
  (0xd4, "ToningEffectUserDef3", true),
];

/// `%offOn` (`Canon.pm:1218`).
fn off_on_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    1 => "On",
    _ => return None,
  })
}

/// `FlashMeteringMode` PrintConv (`Canon.pm:4392-4398`).
fn flash_metering_mode_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "E-TTL",
    3 => "TTL",
    4 => "External Auto",
    5 => "External Manual",
    6 => "Off",
    _ => return None,
  })
}

/// `HighISONoiseReduction` PrintConv (`Canon.pm:4447-4452`).
fn high_iso_nr_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Standard",
    1 => "Low",
    2 => "Strong",
    3 => "Off",
    _ => return None,
  })
}

/// `CameraPictureStyle` (`Canon.pm:4431-4443`, `PrintHex`): the label, or
/// `Unknown (0xNN)`.
fn camera_picture_style_value(v: i64, print_conv: bool) -> TagValue {
  if !print_conv {
    return TagValue::I64(v);
  }
  let label = match v {
    0x21 => "User Defined 1",
    0x22 => "User Defined 2",
    0x23 => "User Defined 3",
    0x81 => "Standard",
    0x82 => "Portrait",
    0x83 => "Landscape",
    0x84 => "Neutral",
    0x85 => "Faithful",
    0x86 => "Monochrome",
    _ => return TagValue::Str(SmolStr::from(std::format!("Unknown (0x{v:x})"))),
  };
  TagValue::Str(SmolStr::new_static(label))
}

/// `%focusDistanceByteSwap` (`Canon.pm:1200-1208`): `$val/100`, then
/// `$val > 655.345 ? "inf" : "$val m"`.
fn focus_distance_value(raw: i64, print_conv: bool) -> TagValue {
  let v = raw as f64 / 100.0;
  if print_conv {
    if v > 655.345 {
      TagValue::Str(SmolStr::new_static("inf"))
    } else {
      TagValue::Str(SmolStr::from(std::format!("{v} m")))
    }
  } else if v.fract() == 0.0 {
    TagValue::I64(v as i64)
  } else {
    TagValue::F64(v)
  }
}

/// `%psConv` (`Canon.pm:1168-1171`): `-559038737` (0xdeadbeef) ⇒ "n/a", else
/// the raw int passes through (`OTHER => sub { shift }`). `PrintHex` never fires
/// (the `OTHER` catch-all returns the value unchanged).
fn ps_scalar_value(v: i64, print_conv: bool) -> TagValue {
  if print_conv && v == -559_038_737 {
    TagValue::Str(SmolStr::new_static("n/a"))
  } else {
    TagValue::I64(v)
  }
}

/// `FilterEffect`/`ToningEffect` PSInfo PrintConv: the label (with `0xdeadbeef
/// ⇒ "n/a"`), or the `PrintHex` `Unknown (0xNN)` fallback; raw int under `-n`.
fn ps_effect_value(v: i64, print_conv: bool, label: Option<&'static str>) -> TagValue {
  if !print_conv {
    return TagValue::I64(v);
  }
  match label {
    Some(l) => TagValue::Str(SmolStr::new_static(l)),
    None if v == -559_038_737 => TagValue::Str(SmolStr::new_static("n/a")),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown (0x{v:x})"))),
  }
}

/// PSInfo `FilterEffect*` PrintConv (`Canon.pm:6083-6091`).
fn ps_filter_effect_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "None",
    1 => "Yellow",
    2 => "Orange",
    3 => "Red",
    4 => "Green",
    _ => return None,
  })
}

/// PSInfo `ToningEffect*` PrintConv (`Canon.pm:6093-6101`).
fn ps_toning_effect_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "None",
    1 => "Sepia",
    2 => "Blue",
    3 => "Purple",
    4 => "Green",
    _ => return None,
  })
}

/// `MeasuredEV`/`MeasuredEV2` (`$val/8-6`, no PrintConv): a bare number —
/// integral values collapse to `I64` (so `-j`/`-n` agree, e.g. `4` not `4.0`).
fn ev_value(v: f64) -> TagValue {
  if v.fract() == 0.0 {
    TagValue::I64(v as i64)
  } else {
    TagValue::F64(v)
  }
}

/// Read one signed 32-bit word at byte `off` in the file's byte order.
fn i32s(data: &[u8], off: usize, order: ByteOrder) -> Option<i64> {
  let arr: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => i32::from_le_bytes(arr),
    ByteOrder::Big => i32::from_be_bytes(arr),
  } as i64)
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
    assert!(model_is_camera_info_7d(Some("Canon EOS 7D")));
    assert!(!model_is_camera_info_7d(Some("Canon EOS 7D Mark II")));
    assert!(!model_is_camera_info_7d(Some("Canon EOS 5D")));
    // A model handled by neither table yields nothing.
    assert!(
      parse(
        &[0u8; 0x120],
        ByteOrder::Little,
        true,
        Some("Canon EOS 60D")
      )
      .is_empty()
    );
  }
}
