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
use super::canon_custom::word_bounded;
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

/// `true` when `model` selects `%Canon::CameraInfo6D` (`Canon.pm:1357`,
/// `$$self{Model} =~ /EOS 6D$/` — anchored, so the original 6D only, NOT
/// "6D Mark II").
#[must_use]
pub fn model_is_camera_info_6d(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.trim_end().ends_with("EOS 6D"))
}

/// Decode the `Canon::CameraInfo` block for the parent `model` via the `0x0d`
/// model-conditional list (`Canon.pm:1308-1494`), evaluated in ExifTool's order.
/// Ported variants: 5D / 7D and the xxxD DSLR batch (40D / 50D / 450D / 500D /
/// 550D / 1000D); any other model yields nothing (deferred). `print_conv`
/// selects the PrintConv vs ValueConv view; `canon_lens_type` is the pre-scanned
/// `$$self{LensType}` (the CameraSettings DataMember) that gates the
/// `MacroMagnification` leaf (`%ciMacroMagnification`, `Canon.pm:3124-3133`).
#[must_use]
pub fn parse(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
  canon_lens_type: Option<u16>,
) -> Vec<(SmolStr, TagValue)> {
  if model_is_camera_info_5d(model) {
    camera_info_5d(data, order, print_conv)
  } else if model_is_camera_info_6d(model) {
    camera_info_6d(data, order, print_conv)
  } else if model_is_camera_info_7d(model) {
    camera_info_7d(data, order, print_conv)
  } else if model_is_camera_info_40d(model) {
    camera_info_40d(data, order, print_conv, canon_lens_type)
  } else if model_is_camera_info_50d(model) {
    camera_info_50d(data, order, print_conv)
  } else if model_is_camera_info_60d(model) {
    camera_info_60d(data, order, print_conv, model)
  } else if model_is_camera_info_70d(model) {
    camera_info_70d(data, order, print_conv)
  } else if model_is_camera_info_450d(model) {
    camera_info_450d(data, order, print_conv, canon_lens_type)
  } else if model_is_camera_info_500d(model) {
    camera_info_500d(data, order, print_conv)
  } else if model_is_camera_info_550d(model) {
    camera_info_550d(data, order, print_conv)
  } else if model_is_camera_info_600d(model) {
    camera_info_600d(data, order, print_conv)
  } else if model_is_camera_info_1000d(model) {
    camera_info_1000d(data, order, print_conv, canon_lens_type)
  } else {
    Vec::new()
  }
}

/// `true` when `model` selects `%Canon::CameraInfo40D` (`Canon.pm:1366`,
/// `$$self{Model} =~ /EOS 40D$/`).
#[must_use]
pub fn model_is_camera_info_40d(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.trim_end().ends_with("EOS 40D"))
}

/// `true` when `model` selects `%Canon::CameraInfo50D` (`Canon.pm:1371`,
/// `$$self{Model} =~ /EOS 50D$/`).
#[must_use]
pub fn model_is_camera_info_50d(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.trim_end().ends_with("EOS 50D"))
}

/// `true` when `model` selects `%Canon::CameraInfo60D` — either the 60D proper
/// (`Canon.pm:1377`, `$$self{Model} =~ /EOS 60D$/`) or the 1200D alias
/// (`Canon.pm:1442`, `/\b(1200D|REBEL T5|Kiss X70)\b/`), which share the table.
#[must_use]
pub fn model_is_camera_info_60d(model: Option<&str>) -> bool {
  model_is_60d_proper(model) || model_is_1200d(model)
}

/// The 60D proper (`/EOS 60D$/`) — gates the 60D-only rows of `%CameraInfo60D`.
fn model_is_60d_proper(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.trim_end().ends_with("EOS 60D"))
}

/// The 1200D alias (`/\b(1200D|REBEL T5|Kiss X70)\b/`) — gates the 1200D-only
/// rows of `%CameraInfo60D`.
fn model_is_1200d(model: Option<&str>) -> bool {
  model.is_some_and(|m| {
    word_bounded(m, "1200D") || word_bounded(m, "REBEL T5") || word_bounded(m, "Kiss X70")
  })
}

/// `true` when `model` selects `%Canon::CameraInfo70D` (`Canon.pm:1382`,
/// `$$self{Model} =~ /EOS 70D$/`).
#[must_use]
pub fn model_is_camera_info_70d(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.trim_end().ends_with("EOS 70D"))
}

/// `true` when `model` selects `%Canon::CameraInfo600D` — the 600D
/// (`Canon.pm:1407`, `/\b(600D|REBEL T3i|Kiss X5)\b/`) or the 1100D alias
/// (`Canon.pm:1437`, `/\b(1100D|REBEL T3|Kiss X50)\b/`); both share the table
/// with identical rows (no per-model `Condition`s).
#[must_use]
pub fn model_is_camera_info_600d(model: Option<&str>) -> bool {
  model.is_some_and(|m| {
    word_bounded(m, "600D")
      || word_bounded(m, "REBEL T3i")
      || word_bounded(m, "Kiss X5")
      || word_bounded(m, "1100D")
      || word_bounded(m, "REBEL T3")
      || word_bounded(m, "Kiss X50")
  })
}

/// `true` when `model` selects `%Canon::CameraInfo450D` (`Canon.pm:1391`,
/// `$$self{Model} =~ /\b(450D|REBEL XSi|Kiss X2)\b/`).
#[must_use]
pub fn model_is_camera_info_450d(model: Option<&str>) -> bool {
  model.is_some_and(|m| {
    word_bounded(m, "450D") || word_bounded(m, "REBEL XSi") || word_bounded(m, "Kiss X2")
  })
}

/// `true` when `model` selects `%Canon::CameraInfo500D` (`Canon.pm:1396`,
/// `$$self{Model} =~ /\b(500D|REBEL T1i|Kiss X3)\b/`).
#[must_use]
pub fn model_is_camera_info_500d(model: Option<&str>) -> bool {
  model.is_some_and(|m| {
    word_bounded(m, "500D") || word_bounded(m, "REBEL T1i") || word_bounded(m, "Kiss X3")
  })
}

/// `true` when `model` selects `%Canon::CameraInfo550D` (`Canon.pm:1401`,
/// `$$self{Model} =~ /\b(550D|REBEL T2i|Kiss X4)\b/`).
#[must_use]
pub fn model_is_camera_info_550d(model: Option<&str>) -> bool {
  model.is_some_and(|m| {
    word_bounded(m, "550D") || word_bounded(m, "REBEL T2i") || word_bounded(m, "Kiss X4")
  })
}

/// `true` when `model` selects `%Canon::CameraInfo1000D` (`Canon.pm:1431`,
/// `$$self{Model} =~ /\b(1000D|REBEL XS|Kiss F)\b/`).
#[must_use]
pub fn model_is_camera_info_1000d(model: Option<&str>) -> bool {
  model.is_some_and(|m| {
    word_bounded(m, "1000D") || word_bounded(m, "REBEL XS") || word_bounded(m, "Kiss F")
  })
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

/// `%Canon::CameraInfo6D` (`Canon.pm:4261-4339`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`, no firmware `Hook`. Carries `WhiteBalance` (0xc2) and a
/// PictureStyle leaf; `FirmwareVersion` (0x256) has NO `RawConv` guard. The
/// `0x3c6 PictureStyleInfo` `IS_SUBDIR` walks the nested `%Canon::PSInfo2` table
/// (the 60D-group variant with the extra `*Auto` style block).
fn camera_info_6d(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_exposure_triple(data, print_conv, &mut push);
  emit_camera_temperature(data, 0x1b, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x23,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x83, print_conv, &mut push);
  emit_focus_distance(
    data,
    0x92,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0x94,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_white_balance(data, 0xc2, order, print_conv, &mut push);
  emit_color_temperature(data, 0xc6, order, &mut push);
  emit_picture_style(data, 0xfa, print_conv, &mut push);
  emit_lens_type(data, 0x161, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x163,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0x165,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_firmware_version(data, 0x256, false, &mut push);
  emit_file_index(data, 0x2aa, order, &mut push);
  emit_directory_index(data, 0x2b6, order, true, &mut push);
  ps_info2(data, 0x3c6, order, print_conv, &mut push);
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

/// `%Canon::CameraInfo40D` (`Canon.pm:4492-4581`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`, NO firmware `Hook` (every leaf at its nominal offset). The
/// `0x25b PictureStyleInfo` `IS_SUBDIR` walks the nested `%Canon::PSInfo` table.
fn camera_info_40d(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  canon_lens_type: Option<u16>,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_exposure_triple(data, print_conv, &mut push);
  emit_flash_metering_mode(data, 0x15, print_conv, &mut push);
  emit_camera_temperature(data, 0x18, print_conv, &mut push);
  emit_macro_magnification(data, 0x1b, canon_lens_type, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x1d,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x30, print_conv, &mut push);
  emit_focus_distance(
    data,
    0x43,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0x45,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_white_balance(data, 0x6f, order, print_conv, &mut push);
  emit_color_temperature(data, 0x73, order, &mut push);
  emit_lens_type(data, 0xd6, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0xd8,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0xda,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_firmware_version(data, 0xff, false, &mut push);
  emit_file_index(data, 0x133, order, &mut push);
  emit_directory_index(data, 0x13f, order, true, &mut push);
  ps_info(data, 0x25b, order, print_conv, &mut push);
  emit_string_leaf(data, 0x92b, 64, "LensModel", &mut push);
  out
}

/// `%Canon::CameraInfo50D` (`Canon.pm:4584-4715`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`. The `0x00 FirmwareVersionLookAhead` sets `CanonFirm` (probing
/// the version string at 0x15a then 0x15e); the `0xee` `Hook`
/// (`$varSize += ($$self{CanonFirm} ? -4 : 0x10000) if $$self{CanonFirm} < 2`)
/// shifts every leaf AFTER 0xee. `0x2d7 PictureStyleInfo` walks `%Canon::PSInfo`.
fn camera_info_50d(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  let canon_firm = canon_firm_50d(data);
  let var_size: i64 = if canon_firm < 2 {
    if canon_firm != 0 { -4 } else { 0x1_0000 }
  } else {
    0
  };
  // The `0xee` Hook fires AFTER its own entry's value is read (ExifTool.pm:9957
  // computes the offset, :10049 runs the Hook, :10076 reads at the PRE-Hook
  // offset), so MaxFocalLength (0xee) is read UNSHIFTED and only leaves STRICTLY
  // after 0xee take the `varSize` shift. `None` ⇒ the shifted offset is out of
  // range (CanonFirm == 0 pushes every later leaf out — ExifTool emits nothing).
  let at = |off: usize| -> Option<usize> {
    let a: i64 = if off > 0xee {
      off as i64 + var_size
    } else {
      off as i64
    };
    usize::try_from(a).ok()
  };
  emit_exposure_triple(data, print_conv, &mut push);
  emit_highlight_tone_priority(data, 0x07, print_conv, &mut push);
  emit_flash_metering_mode(data, 0x15, print_conv, &mut push);
  emit_camera_temperature(data, 0x19, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x1e,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x31, print_conv, &mut push);
  emit_focus_distance(
    data,
    0x50,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0x52,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_white_balance(data, 0x6f, order, print_conv, &mut push);
  emit_color_temperature(data, 0x73, order, &mut push);
  emit_picture_style(data, 0xa7, print_conv, &mut push);
  emit_high_iso_nr(data, 0xbd, print_conv, &mut push);
  emit_auto_lighting_optimizer(data, 0xbf, print_conv, &mut push);
  emit_lens_type(data, 0xea, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0xec,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0xee,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  if let Some(off) = at(0x15e) {
    emit_firmware_version(data, off, false, &mut push);
  }
  if let Some(off) = at(0x19b) {
    emit_file_index(data, off, order, &mut push);
  }
  if let Some(off) = at(0x1a7) {
    emit_directory_index(data, off, order, true, &mut push);
  }
  if let Some(ps_start) = at(0x2d7) {
    ps_info(data, ps_start, order, print_conv, &mut push);
  }
  out
}

/// `%Canon::CameraInfo50D` `0x00 FirmwareVersionLookAhead` RawConv
/// (`Canon.pm:4601-4609`): `CanonFirm = 1` if a `D.D.D` version prefix sits at
/// 0x15a, else `2` if at 0x15e, else `0` (ExifTool warns then the `Hook` shifts
/// every later leaf out of range).
fn canon_firm_50d(data: &[u8]) -> u8 {
  if firmware_prefix_at(data, 0x15a) {
    1
  } else if firmware_prefix_at(data, 0x15e) {
    2
  } else {
    0
  }
}

/// `%Canon::CameraInfo60D` (`Canon.pm:4719-4815`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`, no firmware `Hook`. Shared by the 60D and 1200D (`Canon.pm`
/// `0x0d` aliases both onto this table) — several rows carry per-model
/// `Condition`s: the `CameraOrientation` lives at 0x36 (60D) vs 0x3a (1200D), and
/// `FocusDistance*`/`ColorTemperature`/`FileIndex`/`DirectoryIndex` are 60D-only.
/// The `PictureStyleInfo` `IS_SUBDIR` (`%PSInfo2`) is at 0x2f9 (1200D) / 0x321
/// (60D).
fn camera_info_60d(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  let is_60d = model_is_60d_proper(model);
  let is_1200d = model_is_1200d(model);
  emit_exposure_triple(data, print_conv, &mut push);
  emit_camera_temperature(data, 0x19, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x1e,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  if is_60d {
    emit_camera_orientation(data, 0x36, print_conv, &mut push);
  }
  if is_1200d {
    emit_camera_orientation(data, 0x3a, print_conv, &mut push);
  }
  if is_60d {
    emit_focus_distance(
      data,
      0x55,
      "FocusDistanceUpper",
      order,
      print_conv,
      &mut push,
    );
    emit_focus_distance(
      data,
      0x57,
      "FocusDistanceLower",
      order,
      print_conv,
      &mut push,
    );
    emit_color_temperature(data, 0x7d, order, &mut push);
  }
  emit_lens_type(data, 0xe8, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0xea,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0xec,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_firmware_version(data, 0x199, false, &mut push);
  if is_60d {
    emit_file_index(data, 0x1d9, order, &mut push);
    emit_directory_index(data, 0x1e5, order, true, &mut push);
  }
  if is_1200d {
    ps_info2(data, 0x2f9, order, print_conv, &mut push);
  }
  if is_60d {
    ps_info2(data, 0x321, order, print_conv, &mut push);
  }
  out
}

/// `%Canon::CameraInfo70D` (`Canon.pm:4908-4975`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`, no firmware `Hook`. Like the 6D but with NO `WhiteBalance`
/// leaf; `FirmwareVersion` (0x25e) has NO `RawConv` guard. The `0x3cf
/// PictureStyleInfo` `IS_SUBDIR` walks `%PSInfo2`.
fn camera_info_70d(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_exposure_triple(data, print_conv, &mut push);
  emit_camera_temperature(data, 0x1b, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x23,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x84, print_conv, &mut push);
  emit_focus_distance(
    data,
    0x93,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0x95,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_color_temperature(data, 0xc7, order, &mut push);
  emit_lens_type(data, 0x166, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x168,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0x16a,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_firmware_version(data, 0x25e, false, &mut push);
  emit_file_index(data, 0x2b3, order, &mut push);
  emit_directory_index(data, 0x2bf, order, true, &mut push);
  ps_info2(data, 0x3cf, order, print_conv, &mut push);
  out
}

/// `%Canon::CameraInfo450D` (`Canon.pm:5042-5130`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`, no firmware `Hook`. Carries `OwnerName` (string[32]) and a
/// PLAIN `DirectoryIndex` (no `$val-1`); `0x263 PictureStyleInfo` walks `%PSInfo`.
fn camera_info_450d(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  canon_lens_type: Option<u16>,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_exposure_triple(data, print_conv, &mut push);
  emit_flash_metering_mode(data, 0x15, print_conv, &mut push);
  emit_camera_temperature(data, 0x18, print_conv, &mut push);
  emit_macro_magnification(data, 0x1b, canon_lens_type, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x1d,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x30, print_conv, &mut push);
  emit_focus_distance(
    data,
    0x43,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0x45,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_white_balance(data, 0x6f, order, print_conv, &mut push);
  emit_color_temperature(data, 0x73, order, &mut push);
  emit_lens_type(data, 0xde, order, print_conv, &mut push);
  emit_firmware_version(data, 0x107, false, &mut push);
  emit_string_leaf(data, 0x10f, 32, "OwnerName", &mut push);
  emit_directory_index(data, 0x133, order, false, &mut push);
  emit_file_index(data, 0x13f, order, &mut push);
  ps_info(data, 0x263, order, print_conv, &mut push);
  emit_string_leaf(data, 0x933, 64, "LensModel", &mut push);
  out
}

/// `%Canon::CameraInfo500D` (`Canon.pm:5133-5243`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`, no firmware `Hook`. `FirmwareVersion` carries the
/// `/^\d+\.\d+\.\d+\s*$/` RawConv guard; `0x30b PictureStyleInfo` walks `%PSInfo`.
fn camera_info_500d(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_exposure_triple(data, print_conv, &mut push);
  emit_highlight_tone_priority(data, 0x07, print_conv, &mut push);
  emit_flash_metering_mode(data, 0x15, print_conv, &mut push);
  emit_camera_temperature(data, 0x19, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x1e,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x31, print_conv, &mut push);
  emit_focus_distance(
    data,
    0x50,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0x52,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_white_balance(data, 0x73, order, print_conv, &mut push);
  emit_color_temperature(data, 0x77, order, &mut push);
  emit_picture_style(data, 0xab, print_conv, &mut push);
  emit_high_iso_nr(data, 0xbc, print_conv, &mut push);
  emit_auto_lighting_optimizer(data, 0xbe, print_conv, &mut push);
  emit_lens_type(data, 0xf6, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0xf8,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0xfa,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_firmware_version(data, 0x190, true, &mut push);
  emit_file_index(data, 0x1d3, order, &mut push);
  emit_directory_index(data, 0x1df, order, true, &mut push);
  ps_info(data, 0x30b, order, print_conv, &mut push);
  out
}

/// `%Canon::CameraInfo550D` (`Canon.pm:5247-5340`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`, no firmware `Hook`. Like the 500D but with NO
/// HighISONoiseReduction/AutoLightingOptimizer; `0x31c PictureStyleInfo` walks
/// `%PSInfo`.
fn camera_info_550d(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_exposure_triple(data, print_conv, &mut push);
  emit_highlight_tone_priority(data, 0x07, print_conv, &mut push);
  emit_flash_metering_mode(data, 0x15, print_conv, &mut push);
  emit_camera_temperature(data, 0x19, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x1e,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x35, print_conv, &mut push);
  emit_focus_distance(
    data,
    0x54,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0x56,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_white_balance(data, 0x78, order, print_conv, &mut push);
  emit_color_temperature(data, 0x7c, order, &mut push);
  emit_picture_style(data, 0xb0, print_conv, &mut push);
  emit_lens_type(data, 0xff, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x101,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0x103,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_firmware_version(data, 0x1a4, true, &mut push);
  emit_file_index(data, 0x1e4, order, &mut push);
  emit_directory_index(data, 0x1f0, order, true, &mut push);
  ps_info(data, 0x31c, order, print_conv, &mut push);
  out
}

/// `%Canon::CameraInfo600D` (`Canon.pm:5343-5436`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`, no firmware `Hook`. Shared by the 600D and 1100D with every
/// row unconditional. Carries `HighlightTonePriority`/`FlashMeteringMode`/
/// `WhiteBalance`/`PictureStyle`; `FirmwareVersion` (0x19b) has the
/// `/^\d+\.\d+\.\d+\s*$/` RawConv guard. `0x2fb PictureStyleInfo` walks `%PSInfo2`.
fn camera_info_600d(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_exposure_triple(data, print_conv, &mut push);
  emit_highlight_tone_priority(data, 0x07, print_conv, &mut push);
  emit_flash_metering_mode(data, 0x15, print_conv, &mut push);
  emit_camera_temperature(data, 0x19, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x1e,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x38, print_conv, &mut push);
  emit_focus_distance(
    data,
    0x57,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0x59,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_white_balance(data, 0x7b, order, print_conv, &mut push);
  emit_color_temperature(data, 0x7f, order, &mut push);
  emit_picture_style(data, 0xb3, print_conv, &mut push);
  emit_lens_type(data, 0xea, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0xec,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0xee,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_firmware_version(data, 0x19b, true, &mut push);
  emit_file_index(data, 0x1db, order, &mut push);
  emit_directory_index(data, 0x1e7, order, true, &mut push);
  ps_info2(data, 0x2fb, order, print_conv, &mut push);
  out
}

/// `%Canon::CameraInfo1000D` (`Canon.pm:5623-5707`). `FORMAT => 'int8u'`,
/// `PRIORITY => 0`, no firmware `Hook`. Carries `FlashModel` (`Mask => 0x7f`,
/// `%flashModel`), `MacroMagnification` (LensType==124), and a PLAIN
/// `DirectoryIndex` (no `$val-1`); `0x267 PictureStyleInfo` walks `%PSInfo`.
fn camera_info_1000d(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  canon_lens_type: Option<u16>,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));
  emit_exposure_triple(data, print_conv, &mut push);
  emit_flash_model(data, 0x13, print_conv, &mut push);
  emit_flash_metering_mode(data, 0x15, print_conv, &mut push);
  emit_camera_temperature(data, 0x18, print_conv, &mut push);
  emit_macro_magnification(data, 0x1b, canon_lens_type, print_conv, &mut push);
  emit_focal_mm(
    data,
    0x1d,
    "FocalLength",
    true,
    order,
    print_conv,
    &mut push,
  );
  emit_camera_orientation(data, 0x30, print_conv, &mut push);
  emit_focus_distance(
    data,
    0x43,
    "FocusDistanceUpper",
    order,
    print_conv,
    &mut push,
  );
  emit_focus_distance(
    data,
    0x45,
    "FocusDistanceLower",
    order,
    print_conv,
    &mut push,
  );
  emit_white_balance(data, 0x6f, order, print_conv, &mut push);
  emit_color_temperature(data, 0x73, order, &mut push);
  emit_lens_type(data, 0xe2, order, print_conv, &mut push);
  emit_focal_mm(
    data,
    0xe4,
    "MinFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_focal_mm(
    data,
    0xe6,
    "MaxFocalLength",
    false,
    order,
    print_conv,
    &mut push,
  );
  emit_firmware_version(data, 0x10b, false, &mut push);
  emit_directory_index(data, 0x137, order, false, &mut push);
  emit_file_index(data, 0x143, order, &mut push);
  ps_info(data, 0x267, order, print_conv, &mut push);
  emit_string_leaf(data, 0x937, 64, "LensModel", &mut push);
  out
}

// ─── shared per-field emitters for the int8u xxxD `CameraInfo` tables ─────────
// Each reads at the byte offset the caller already resolved (applying any
// firmware `Hook` shift) and pushes the rendered leaf, reusing the same value
// renderers as the 5D/7D tables. Faithful to the shared `%ci*` common defs
// (`Canon.pm:3086-3153`) and the inline rows of each per-model table.

/// `%ciFNumber` (0x03) / `%ciExposureTime` (0x04) / `%ciISO` (0x06) — the int8u
/// exposure triple shared by every xxxD `CameraInfo` table at fixed offsets
/// (`Canon.pm:3087-3115`). FNumber/ExposureTime drop a zero raw; ISO does not.
fn emit_exposure_triple<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  print_conv: bool,
  push: &mut F,
) {
  if let Some(raw) = i8u(data, 0x03)
    && raw != 0
  {
    let vc = ((raw as f64 - 8.0) / 16.0 * std::f64::consts::LN_2).exp();
    push("FNumber", value_or_print(print_conv, vc, format_g2(vc)));
  }
  if let Some(raw) = i8u(data, 0x04)
    && raw != 0
  {
    let vc = (4.0 * std::f64::consts::LN_2 * (1.0 - canon_ev(raw - 24))).exp();
    push(
      "ExposureTime",
      value_or_print(print_conv, vc, print_exposure_time(vc)),
    );
  }
  if let Some(raw) = i8u(data, 0x06) {
    let vc = 100.0 * ((raw as f64 / 8.0 - 9.0) * std::f64::consts::LN_2).exp();
    push(
      "ISO",
      value_or_print(print_conv, vc, std::format!("{vc:.0}")),
    );
  }
}

/// `%ciCameraTemperature` (`Canon.pm:3116`, int8u, `$val-128`, "$val C").
fn emit_camera_temperature<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(raw) = i8u(data, off) {
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
}

/// `%ciMacroMagnification` (`Canon.pm:3124-3133`): gated on the pre-scanned
/// `$$self{LensType} == 124` (the MP-E 65mm Macro), `exp((75-$val)*ln2*3/40)`,
/// PrintConv `%.1fx`.
fn emit_macro_magnification<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  canon_lens_type: Option<u16>,
  print_conv: bool,
  push: &mut F,
) {
  if canon_lens_type != Some(124) {
    return;
  }
  if let Some(raw) = i8u(data, off) {
    let vc = ((75.0 - raw as f64) * std::f64::consts::LN_2 * 3.0 / 40.0).exp();
    let value = if print_conv {
      TagValue::Str(SmolStr::from(std::format!("{vc:.1}x")))
    } else if vc.fract() == 0.0 && vc.is_finite() {
      TagValue::I64(vc as i64)
    } else {
      TagValue::F64(vc)
    };
    push("MacroMagnification", value);
  }
}

/// `%ciFocalLength`/`%ciMinFocal`/`%ciMaxFocal` (`Canon.pm:3134-3153`, int16uRev,
/// "$val mm"). `drop_zero` mirrors `%ciFocalLength`'s `RawConv => '$val ? $val :
/// undef'` (Min/Max focal carry no such drop).
fn emit_focal_mm<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  name: &'static str,
  drop_zero: bool,
  order: ByteOrder,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(v) = u16_rev(data, off, order) {
    if drop_zero && v == 0 {
      return;
    }
    push(name, mm_value(v, print_conv));
  }
}

/// `CameraOrientation` (int8u, `%camera_orientation_label`).
fn emit_camera_orientation<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(v) = i8u(data, off) {
    push(
      "CameraOrientation",
      enum8(v, print_conv, camera_orientation_label),
    );
  }
}

/// `FocusDistanceUpper`/`FocusDistanceLower` (`%focusDistanceByteSwap`, int16uRev,
/// `$val/100`, `>655.345 ? inf : '$val m'`).
fn emit_focus_distance<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  name: &'static str,
  order: ByteOrder,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(raw) = u16_rev(data, off, order) {
    push(name, focus_distance_value(raw, print_conv));
  }
}

/// `WhiteBalance` (int16u, `%canonWhiteBalance`).
fn emit_white_balance<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  order: ByteOrder,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(v) = u16(data, off, order) {
    push(
      "WhiteBalance",
      if print_conv {
        hash16(v, white_balance_label(v))
      } else {
        TagValue::I64(v)
      },
    );
  }
}

/// `ColorTemperature` (int16u, plain integer).
fn emit_color_temperature<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  order: ByteOrder,
  push: &mut F,
) {
  if let Some(v) = u16(data, off, order) {
    push("ColorTemperature", TagValue::I64(v));
  }
}

/// `LensType` (int16uRev, `%canonLensTypes`, `PrintInt`).
fn emit_lens_type<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  order: ByteOrder,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(v) = u16_rev(data, off, order) {
    push("LensType", lens_type_value(v, print_conv));
  }
}

/// `PictureStyle` (int8u, `PrintHex`, `%pictureStyles`).
fn emit_picture_style<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(v) = i8u(data, off) {
    push("PictureStyle", picture_style_value(v, print_conv));
  }
}

/// `HighlightTonePriority` (int8u, `%offOn`).
fn emit_highlight_tone_priority<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(v) = i8u(data, off) {
    push("HighlightTonePriority", enum8(v, print_conv, off_on_label));
  }
}

/// `HighISONoiseReduction` (int8u, `Canon.pm:4663-4669`).
fn emit_high_iso_nr<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(v) = i8u(data, off) {
    push(
      "HighISONoiseReduction",
      enum8(v, print_conv, high_iso_nr_label),
    );
  }
}

/// `AutoLightingOptimizer` (int8u, `Canon.pm:4672-4678`).
fn emit_auto_lighting_optimizer<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(v) = i8u(data, off) {
    push(
      "AutoLightingOptimizer",
      enum8(v, print_conv, auto_lighting_optimizer_label),
    );
  }
}

/// `FirmwareVersion` (string[6]). `validate` mirrors the `RawConv =>
/// '$val=~/^\d+\.\d+\.\d+\s*$/ ? $val : undef'` carried by the 500D/550D rows
/// (`Canon.pm:5224`/`:5320`); the 40D/50D/450D/1000D rows have no such guard.
fn emit_firmware_version<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  validate: bool,
  push: &mut F,
) {
  if let Some(s) = read_string(data, off, 6) {
    if validate && !is_firmware_version(&s) {
      return;
    }
    push("FirmwareVersion", TagValue::Str(SmolStr::from(s)));
  }
}

/// A plain `string[len]` leaf (`OwnerName`/`LensModel`).
fn emit_string_leaf<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  len: usize,
  name: &'static str,
  push: &mut F,
) {
  if let Some(s) = read_string(data, off, len) {
    push(name, TagValue::Str(SmolStr::from(s)));
  }
}

/// `FileIndex` (int32u, ValueConv `$val + 1`).
fn emit_file_index<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  order: ByteOrder,
  push: &mut F,
) {
  if let Some(v) = u32(data, off, order) {
    push("FileIndex", TagValue::I64(v + 1));
  }
}

/// `DirectoryIndex` (int32u). `minus_one` applies the `ValueConv => '$val - 1'`
/// carried by the 40D/50D/500D/550D rows; the 450D/1000D rows emit the raw value.
fn emit_directory_index<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  order: ByteOrder,
  minus_one: bool,
  push: &mut F,
) {
  if let Some(v) = u32(data, off, order) {
    let value = if minus_one { v - 1 } else { v };
    push("DirectoryIndex", TagValue::I64(value));
  }
}

/// `FlashMeteringMode` (int8u, `Canon.pm:4503-4512`).
fn emit_flash_metering_mode<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(v) = i8u(data, off) {
    push(
      "FlashMeteringMode",
      enum8(v, print_conv, flash_metering_mode_label),
    );
  }
}

/// `AutoLightingOptimizer` PrintConv (`Canon.pm:4672-4678`) — the same labels as
/// `HighISONoiseReduction`, kept distinct to mirror the source table structure.
fn auto_lighting_optimizer_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Standard",
    1 => "Low",
    2 => "Strong",
    3 => "Off",
    _ => return None,
  })
}

/// `FlashModel` (`Canon.pm:5634`, `Mask => 0x7f`, `%flashModel`). The mask has no
/// `BitShift`, so the value is `raw & 0x7f`; a hash miss renders the DECIMAL
/// `Unknown (N)` (the row carries no `PrintHex`).
fn emit_flash_model<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  off: usize,
  print_conv: bool,
  push: &mut F,
) {
  if let Some(raw) = i8u(data, off) {
    let v = raw & 0x7f;
    let value = if print_conv {
      match flash_model_label(v) {
        Some(l) => TagValue::Str(SmolStr::new_static(l)),
        None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
      }
    } else {
      TagValue::I64(v)
    };
    push("FlashModel", value);
  }
}

/// `%flashModel` (`Canon.pm:1029-1049`).
fn flash_model_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "n/a",
    4 => "Speedlite 540EZ",
    5 => "Speedlite 380EX",
    6 => "Speedlite 550EX",
    8 => "Speedlite ST-E2",
    9 => "Speedlite MR-14EX",
    12 => "Speedlite 580EX",
    13 => "Speedlite 430EX",
    17 => "Speedlite 580EX II",
    18 => "Speedlite 430EX II",
    22 => "Speedlite 600EX-RT",
    23 => "Speedlite 600EX II-RT",
    24 => "Speedlite 90EX",
    25 => "Speedlite 430EX III-RT",
    31 => "Speedlite EL-1 ver2",
    33 => "Speedlite EL-5",
    34 => "Speedlite EL-10",
    _ => return None,
  })
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

/// `%Canon::PSInfo2` (`Canon.pm:6178-6356`) — the 60D-group nested subdir
/// (5DmkIII / 60D / 600D / 1100D etc.). Identical to `%PSInfo` but with an extra
/// `*Auto` picture-style block inserted at 0x90 (Contrast/Sharpness/Saturation/
/// ColorTone + Filter/ToningEffectAuto), which shifts the three UserDef blocks
/// +0x18 and moves the int16u `UserDef{1,2,3}PictureStyle` leaves to
/// 0xf0/0xf2/0xf4. Same `%psInfo` suppression of the `Unknown => 1` rows.
fn ps_info2<F: FnMut(&'static str, TagValue)>(
  data: &[u8],
  start: usize,
  order: ByteOrder,
  print_conv: bool,
  push: &mut F,
) {
  // The plain int32s scalars (`%psConv`: 0xdeadbeef ⇒ "n/a", else passthrough).
  for &(off, name) in PS_SCALARS2 {
    if let Some(v) = i32s(data, start + off, order) {
      push(name, ps_scalar_value(v, print_conv));
    }
  }
  // FilterEffect/ToningEffect (Monochrome + Auto + the three UserDefs) —
  // explicit PrintConv hashes (with 0xdeadbeef ⇒ "n/a").
  for &(off, name, toning) in PS_EFFECTS2 {
    if let Some(v) = i32s(data, start + off, order) {
      let label = if toning {
        ps_toning_effect_label(v)
      } else {
        ps_filter_effect_label(v)
      };
      push(name, ps_effect_value(v, print_conv, label));
    }
  }
  // UserDef{1,2,3}PictureStyle (int16u, %userDefStyles). As with `%PSInfo`, the
  // entries carry NO `PrintHex` (`Canon.pm:6336-6353`), so an unresolved value
  // renders the DECIMAL `Unknown (N)` fallback.
  for &(off, name) in &[
    (0xf0usize, "UserDef1PictureStyle"),
    (0xf2, "UserDef2PictureStyle"),
    (0xf4, "UserDef3PictureStyle"),
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

/// `%Canon::PSInfo2` plain int32s scalars (`Canon.pm:6185-6314`, minus the
/// `Unknown => 1` rows). Differs from `PS_SCALARS` by the `*Auto` block at
/// 0x90-0x9c and the +0x18 shift of every UserDef scalar.
const PS_SCALARS2: &[(usize, &str)] = &[
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
  (0x90, "ContrastAuto"),
  (0x94, "SharpnessAuto"),
  (0x98, "SaturationAuto"),
  (0x9c, "ColorToneAuto"),
  (0xa8, "ContrastUserDef1"),
  (0xac, "SharpnessUserDef1"),
  (0xb0, "SaturationUserDef1"),
  (0xb4, "ColorToneUserDef1"),
  (0xc0, "ContrastUserDef2"),
  (0xc4, "SharpnessUserDef2"),
  (0xc8, "SaturationUserDef2"),
  (0xcc, "ColorToneUserDef2"),
  (0xd8, "ContrastUserDef3"),
  (0xdc, "SharpnessUserDef3"),
  (0xe0, "SaturationUserDef3"),
  (0xe4, "ColorToneUserDef3"),
];

/// The `%Canon::PSInfo2` FilterEffect/ToningEffect entries with an explicit
/// PrintConv (`Canon.pm:6219-6333`): `(offset, name, is_toning)`. Adds the
/// `*Auto` pair (0xa0/0xa4) and shifts the UserDef pairs +0x18 vs `PS_EFFECTS`.
const PS_EFFECTS2: &[(usize, &str, bool)] = &[
  (0x88, "FilterEffectMonochrome", false),
  (0x8c, "ToningEffectMonochrome", true),
  (0xa0, "FilterEffectAuto", false),
  (0xa4, "ToningEffectAuto", true),
  (0xb8, "FilterEffectUserDef1", false),
  (0xbc, "ToningEffectUserDef1", true),
  (0xd0, "FilterEffectUserDef2", false),
  (0xd4, "ToningEffectUserDef2", true),
  (0xe8, "FilterEffectUserDef3", false),
  (0xec, "ToningEffectUserDef3", true),
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
    let em = parse(&data, ByteOrder::Little, true, Some("Canon EOS 5D"), None);
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
    let em = parse(&data, ByteOrder::Little, false, Some("Canon EOS 5D"), None);
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
    // A model handled by neither table yields nothing (5D Mark II is not yet
    // ported; the 60D/etc. are now handled, so a still-unported model is used).
    assert!(
      parse(
        &[0u8; 0x120],
        ByteOrder::Little,
        true,
        Some("Canon EOS 5D Mark II"),
        None
      )
      .is_empty()
    );
  }

  #[test]
  fn dispatch_anchored_40d_50d() {
    assert!(model_is_camera_info_40d(Some("Canon EOS 40D")));
    assert!(!model_is_camera_info_40d(Some("Canon EOS 400D")));
    assert!(model_is_camera_info_50d(Some("Canon EOS 50D")));
    assert!(!model_is_camera_info_50d(Some("Canon EOS 500D")));
    assert!(!model_is_camera_info_50d(Some("Canon EOS 5D")));
  }

  /// `%Canon::CameraInfo40D` (no firmware `Hook`) print values + the
  /// `MacroMagnification` LensType gate + the `PSInfo` subdir.
  #[test]
  fn camera_info_40d_fields() {
    let mut b = vec![0u8; 0x980];
    b[0x06] = 88; // ISO 400
    b[0x18] = 148; // CameraTemperature 20 C
    b[0x1b] = 75; // MacroMagnification raw (1.0x when LensType == 124)
    b[0x1d] = 0x00;
    b[0x1e] = 0x32; // FocalLength int16uRev = 50
    b[0x30] = 1; // CameraOrientation Rotate 90 CW
    b[0x73] = 0x50;
    b[0x74] = 0x14; // ColorTemperature 5200
    b[0xd8] = 0x00;
    b[0xd9] = 0x0a; // MinFocalLength 10
    b[0xda] = 0x00;
    b[0xdb] = 0xc8; // MaxFocalLength 200
    b[0xff..0x105].copy_from_slice(b"1.0.3\0"); // FirmwareVersion string[6]
    b[0x133..0x137].copy_from_slice(&100u32.to_le_bytes()); // FileIndex + 1 = 101
    b[0x13f..0x143].copy_from_slice(&100u32.to_le_bytes()); // DirectoryIndex - 1 = 99
    b[0x92b..0x934].copy_from_slice(b"EF24-70mm"); // LensModel string[64]
    let em = parse(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon EOS 40D"),
      Some(124),
    );
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("20 C".into()))
    );
    assert_eq!(
      find("MacroMagnification"),
      Some(TagValue::Str("1.0x".into()))
    );
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Rotate 90 CW".into()))
    );
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("10 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("200 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("1.0.3".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(101)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(99)));
    assert_eq!(find("LensModel"), Some(TagValue::Str("EF24-70mm".into())));
    // MacroMagnification is gated on the pre-scanned LensType == 124.
    let em2 = parse(&b, ByteOrder::Little, true, Some("Canon EOS 40D"), Some(50));
    assert!(em2.iter().all(|(k, _)| k != "MacroMagnification"));
    // -n view: ISO / FileIndex render as bare integers.
    let emn = parse(&b, ByteOrder::Little, false, Some("Canon EOS 40D"), None);
    let findn = |n: &str| emn.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(findn("ISO"), Some(TagValue::I64(400)));
    assert_eq!(findn("FileIndex"), Some(TagValue::I64(101)));
  }

  /// Per-field availability: a blob that ends before the later leaves emits the
  /// in-range tags only (each leaf gated on `buf.get(off..off+size)`).
  #[test]
  fn camera_info_40d_truncated_per_field() {
    let mut b = vec![0u8; 0x80];
    b[0x06] = 88; // ISO 400 (in range)
    let em = parse(&b, ByteOrder::Little, true, Some("Canon EOS 40D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert!(find("FirmwareVersion").is_none());
    assert!(find("FileIndex").is_none());
    assert!(find("LensModel").is_none());
    assert!(find("MinFocalLength").is_none());
  }

  /// `%Canon::CameraInfo50D` firmware-1 (`CanonFirm == 1`): the `0xee` `Hook`
  /// shifts every leaf AFTER 0xee by `-4`; the Hook entry (MaxFocalLength) and
  /// the earlier leaves stay at their nominal offsets.
  #[test]
  fn camera_info_50d_firmware1_shift() {
    let mut b = vec![0u8; 0x3c0];
    b[0x06] = 88; // ISO 400
    b[0x07] = 1; // HighlightTonePriority On
    b[0x19] = 148; // CameraTemperature 20 C
    b[0x1e] = 0x00;
    b[0x1f] = 0x32; // FocalLength 50
    b[0xa7] = 0x81; // PictureStyle 0x81 Standard
    b[0xbd] = 2; // HighISONoiseReduction Strong
    b[0xbf] = 1; // AutoLightingOptimizer Low
    b[0xee] = 0x00;
    b[0xef] = 0x64; // MaxFocalLength 100 (Hook entry — read UNSHIFTED)
    b[0x15a..0x160].copy_from_slice(b"2.6.1\0"); // version prefix at 0x15a ⇒ CanonFirm 1
    b[0x197..0x19b].copy_from_slice(&200u32.to_le_bytes()); // FileIndex @ 0x19b-4
    b[0x1a3..0x1a7].copy_from_slice(&200u32.to_le_bytes()); // DirectoryIndex @ 0x1a7-4
    let em = parse(&b, ByteOrder::Little, true, Some("Canon EOS 50D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(
      find("HighlightTonePriority"),
      Some(TagValue::Str("On".into()))
    );
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("20 C".into()))
    );
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(find("PictureStyle"), Some(TagValue::Str("Standard".into())));
    assert_eq!(
      find("HighISONoiseReduction"),
      Some(TagValue::Str("Strong".into()))
    );
    assert_eq!(
      find("AutoLightingOptimizer"),
      Some(TagValue::Str("Low".into()))
    );
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("100 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("2.6.1".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(201)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(199)));
  }

  /// `%Canon::CameraInfo50D` firmware-2 (`CanonFirm == 2`): no `varSize` shift —
  /// the post-Hook leaves stay at their nominal offsets.
  #[test]
  fn camera_info_50d_firmware2_no_shift() {
    let mut b = vec![0u8; 0x3c0];
    b[0xee] = 0x00;
    b[0xef] = 0x64; // MaxFocalLength 100
    b[0x15e..0x164].copy_from_slice(b"1.0.3\0"); // version prefix at 0x15e ⇒ CanonFirm 2
    b[0x19b..0x19f].copy_from_slice(&200u32.to_le_bytes()); // FileIndex @ 0x19b
    b[0x1a7..0x1ab].copy_from_slice(&200u32.to_le_bytes()); // DirectoryIndex @ 0x1a7
    let em = parse(&b, ByteOrder::Little, true, Some("Canon EOS 50D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("100 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("1.0.3".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(201)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(199)));
  }

  #[test]
  fn dispatch_word_bounded_450d_500d_550d() {
    assert!(model_is_camera_info_450d(Some("Canon EOS 450D")));
    assert!(model_is_camera_info_450d(Some("Canon EOS REBEL XSi")));
    assert!(model_is_camera_info_450d(Some("Canon EOS Kiss X2")));
    assert!(model_is_camera_info_500d(Some("Canon EOS 500D")));
    assert!(model_is_camera_info_500d(Some("Canon EOS REBEL T1i")));
    assert!(model_is_camera_info_550d(Some("Canon EOS 550D")));
    assert!(model_is_camera_info_550d(Some("Canon EOS Kiss X4")));
    // `\bREBEL XS\b` (a 1000D) must NOT match the 450D `REBEL XSi` token.
    assert!(!model_is_camera_info_450d(Some("Canon EOS REBEL XS")));
    // No cross-matching between the three.
    assert!(!model_is_camera_info_450d(Some("Canon EOS 500D")));
    assert!(!model_is_camera_info_550d(Some("Canon EOS 450D")));
  }

  /// `%Canon::CameraInfo450D`: OwnerName + the PLAIN DirectoryIndex (no `$val-1`,
  /// unlike 40D/50D/500D/550D) + the LensType MacroMagnification gate.
  #[test]
  fn camera_info_450d_fields() {
    let mut b = vec![0u8; 0x980];
    b[0x06] = 88; // ISO 400
    b[0x18] = 148; // CameraTemperature 20 C
    b[0x1d] = 0x00;
    b[0x1e] = 0x32; // FocalLength 50
    b[0x107..0x10d].copy_from_slice(b"1.2.4\0"); // FirmwareVersion (no RawConv guard)
    b[0x10f..0x117].copy_from_slice(b"Jane Doe"); // OwnerName string[32]
    b[0x133..0x137].copy_from_slice(&200u32.to_le_bytes()); // DirectoryIndex PLAIN = 200
    b[0x13f..0x143].copy_from_slice(&200u32.to_le_bytes()); // FileIndex + 1 = 201
    b[0x933..0x93e].copy_from_slice(b"EF-S18-55mm"); // LensModel
    let em = parse(&b, ByteOrder::Little, true, Some("Canon EOS 450D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("20 C".into()))
    );
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("1.2.4".into())));
    assert_eq!(find("OwnerName"), Some(TagValue::Str("Jane Doe".into())));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(200))); // PLAIN, no -1
    assert_eq!(find("FileIndex"), Some(TagValue::I64(201)));
    assert_eq!(find("LensModel"), Some(TagValue::Str("EF-S18-55mm".into())));
  }

  /// `%Canon::CameraInfo500D`: HighlightTonePriority/PictureStyle/HighISO/ALO +
  /// the `/^\d+\.\d+\.\d+\s*$/` FirmwareVersion RawConv guard.
  #[test]
  fn camera_info_500d_fields() {
    let mut b = vec![0u8; 0x400];
    b[0x06] = 88; // ISO 400
    b[0x07] = 1; // HighlightTonePriority On
    b[0x19] = 148; // CameraTemperature 20 C
    b[0x1e] = 0x00;
    b[0x1f] = 0x32; // FocalLength 50
    b[0xab] = 0x81; // PictureStyle Standard
    b[0xbc] = 2; // HighISONoiseReduction Strong
    b[0xbe] = 1; // AutoLightingOptimizer Low
    b[0xf8] = 0x00;
    b[0xf9] = 0x0a; // MinFocalLength 10
    b[0xfa] = 0x00;
    b[0xfb] = 0xc8; // MaxFocalLength 200
    b[0x190..0x196].copy_from_slice(b"1.1.1\0"); // FirmwareVersion (valid)
    b[0x1d3..0x1d7].copy_from_slice(&200u32.to_le_bytes()); // FileIndex 201
    b[0x1df..0x1e3].copy_from_slice(&200u32.to_le_bytes()); // DirectoryIndex 199
    let em = parse(&b, ByteOrder::Little, true, Some("Canon EOS 500D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(
      find("HighlightTonePriority"),
      Some(TagValue::Str("On".into()))
    );
    assert_eq!(find("PictureStyle"), Some(TagValue::Str("Standard".into())));
    assert_eq!(
      find("HighISONoiseReduction"),
      Some(TagValue::Str("Strong".into()))
    );
    assert_eq!(
      find("AutoLightingOptimizer"),
      Some(TagValue::Str("Low".into()))
    );
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("10 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("200 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("1.1.1".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(201)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(199)));
    // The RawConv drops a non-version FirmwareVersion string.
    b[0x190..0x196].copy_from_slice(b"BADVER");
    let em2 = parse(&b, ByteOrder::Little, true, Some("Canon EOS 500D"), None);
    assert!(em2.iter().all(|(k, _)| k != "FirmwareVersion"));
  }

  /// `%Canon::CameraInfo550D`: like 500D but with NO HighISONoiseReduction /
  /// AutoLightingOptimizer rows (different offsets throughout).
  #[test]
  fn camera_info_550d_fields() {
    let mut b = vec![0u8; 0x410];
    b[0x06] = 88; // ISO 400
    b[0x07] = 1; // HighlightTonePriority On
    b[0x19] = 148; // CameraTemperature 20 C
    b[0x1e] = 0x00;
    b[0x1f] = 0x32; // FocalLength 50
    b[0x35] = 1; // CameraOrientation Rotate 90 CW
    b[0xb0] = 0x81; // PictureStyle Standard
    b[0x101] = 0x00;
    b[0x102] = 0x0a; // MinFocalLength 10
    b[0x103] = 0x00;
    b[0x104] = 0xc8; // MaxFocalLength 200
    b[0x1a4..0x1aa].copy_from_slice(b"2.0.0\0"); // FirmwareVersion (valid)
    b[0x1e4..0x1e8].copy_from_slice(&200u32.to_le_bytes()); // FileIndex 201
    b[0x1f0..0x1f4].copy_from_slice(&200u32.to_le_bytes()); // DirectoryIndex 199
    let em = parse(&b, ByteOrder::Little, true, Some("Canon EOS 550D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(
      find("HighlightTonePriority"),
      Some(TagValue::Str("On".into()))
    );
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Rotate 90 CW".into()))
    );
    assert_eq!(find("PictureStyle"), Some(TagValue::Str("Standard".into())));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("10 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("200 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("2.0.0".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(201)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(199)));
    // 550D has no HighISONoiseReduction / AutoLightingOptimizer rows.
    assert!(em.iter().all(|(k, _)| k != "HighISONoiseReduction"));
    assert!(em.iter().all(|(k, _)| k != "AutoLightingOptimizer"));
  }

  #[test]
  fn dispatch_word_bounded_1000d() {
    assert!(model_is_camera_info_1000d(Some("Canon EOS 1000D")));
    assert!(model_is_camera_info_1000d(Some("Canon EOS REBEL XS")));
    assert!(model_is_camera_info_1000d(Some("Canon EOS Kiss F")));
    // `REBEL XS` (1000D) is distinct from `REBEL XSi` (450D).
    assert!(!model_is_camera_info_1000d(Some("Canon EOS REBEL XSi")));
    assert!(!model_is_camera_info_450d(Some("Canon EOS REBEL XS")));
  }

  /// `%Canon::CameraInfo1000D`: FlashModel (Mask 0x7f drops the high bit) +
  /// MacroMagnification + a PLAIN DirectoryIndex.
  #[test]
  fn camera_info_1000d_fields() {
    let mut b = vec![0u8; 0x980];
    b[0x06] = 88; // ISO 400
    b[0x13] = 0x91; // FlashModel: 0x91 & 0x7f = 0x11 (17) ⇒ Speedlite 580EX II
    b[0x18] = 148; // CameraTemperature 20 C
    b[0x1b] = 75; // MacroMagnification raw (1.0x when LensType == 124)
    b[0x1d] = 0x00;
    b[0x1e] = 0x32; // FocalLength 50
    b[0xe4] = 0x00;
    b[0xe5] = 0x0a; // MinFocalLength 10
    b[0xe6] = 0x00;
    b[0xe7] = 0xc8; // MaxFocalLength 200
    b[0x10b..0x111].copy_from_slice(b"1.0.7\0"); // FirmwareVersion
    b[0x137..0x13b].copy_from_slice(&200u32.to_le_bytes()); // DirectoryIndex PLAIN = 200
    b[0x143..0x147].copy_from_slice(&200u32.to_le_bytes()); // FileIndex + 1 = 201
    b[0x937..0x943].copy_from_slice(b"EF-S55-250mm"); // LensModel
    let em = parse(
      &b,
      ByteOrder::Little,
      true,
      Some("Canon EOS 1000D"),
      Some(124),
    );
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(
      find("FlashModel"),
      Some(TagValue::Str("Speedlite 580EX II".into()))
    );
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("20 C".into()))
    );
    assert_eq!(
      find("MacroMagnification"),
      Some(TagValue::Str("1.0x".into()))
    );
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("10 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("200 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("1.0.7".into())));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(200))); // PLAIN, no -1
    assert_eq!(find("FileIndex"), Some(TagValue::I64(201)));
    assert_eq!(
      find("LensModel"),
      Some(TagValue::Str("EF-S55-250mm".into()))
    );
    // -n view: FlashModel renders the masked raw integer.
    let emn = parse(&b, ByteOrder::Little, false, Some("Canon EOS 1000D"), None);
    let findn = |n: &str| emn.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(findn("FlashModel"), Some(TagValue::I64(17)));
    // A FlashModel value absent from %flashModel ⇒ decimal "Unknown (N)".
    b[0x13] = 0x7f; // 127 (not in the hash)
    let em2 = parse(&b, ByteOrder::Little, true, Some("Canon EOS 1000D"), None);
    assert_eq!(
      em2
        .iter()
        .find(|(k, _)| k == "FlashModel")
        .map(|(_, v)| v.clone()),
      Some(TagValue::Str("Unknown (127)".into()))
    );
  }

  #[test]
  fn dispatch_anchored_6d() {
    assert!(model_is_camera_info_6d(Some("Canon EOS 6D")));
    assert!(!model_is_camera_info_6d(Some("Canon EOS 6D Mark II")));
    // /EOS 6D$/ must NOT match the 60D (which ends "60D", not "6D").
    assert!(!model_is_camera_info_6d(Some("Canon EOS 60D")));
  }

  /// `%Canon::PSInfo2` descent: the inserted `*Auto` block at 0x90/0xa0 and the
  /// +0x18-shifted UserDef blocks + the 0xf0 `UserDef1PictureStyle` leaf.
  #[test]
  fn ps_info2_auto_block() {
    let mut b = vec![0u8; 0x100];
    b[0x00..0x04].copy_from_slice(&5i32.to_le_bytes()); // ContrastStandard
    b[0x04..0x08].copy_from_slice(&(-559_038_737i32).to_le_bytes()); // Sharpness n/a
    b[0x90..0x94].copy_from_slice(&7i32.to_le_bytes()); // ContrastAuto (PSInfo2 only)
    b[0xa0..0xa4].copy_from_slice(&1i32.to_le_bytes()); // FilterEffectAuto -> Yellow
    b[0xa8..0xac].copy_from_slice(&9i32.to_le_bytes()); // ContrastUserDef1 (shifted +0x18)
    b[0xe4..0xe8].copy_from_slice(&3i32.to_le_bytes()); // ColorToneUserDef3
    b[0xf0..0xf2].copy_from_slice(&0x82u16.to_le_bytes()); // UserDef1PictureStyle -> Portrait
    let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
    let mut push = |n: &'static str, v: TagValue| out.push((SmolStr::new_static(n), v));
    ps_info2(&b, 0, ByteOrder::Little, true, &mut push);
    let find = |n: &str| out.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ContrastStandard"), Some(TagValue::I64(5)));
    assert_eq!(find("SharpnessStandard"), Some(TagValue::Str("n/a".into())));
    assert_eq!(find("ContrastAuto"), Some(TagValue::I64(7)));
    assert_eq!(
      find("FilterEffectAuto"),
      Some(TagValue::Str("Yellow".into()))
    );
    assert_eq!(find("ContrastUserDef1"), Some(TagValue::I64(9)));
    assert_eq!(find("ColorToneUserDef3"), Some(TagValue::I64(3)));
    assert_eq!(
      find("UserDef1PictureStyle"),
      Some(TagValue::Str("Portrait".into()))
    );
    // 0x9c is the Auto block's ColorTone slot in PSInfo2 (it is ColorToneUserDef1
    // in plain PSInfo) — confirm the PSInfo2 mapping is used.
    assert_eq!(find("ColorToneAuto"), Some(TagValue::I64(0)));
  }

  /// `%Canon::CameraInfo6D` print values + the nested `%PSInfo2` subdir.
  #[test]
  fn camera_info_6d_fields() {
    let mut b = vec![0u8; 0x4c0];
    b[0x06] = 88; // ISO 400
    b[0x1b] = 148; // CameraTemperature 20 C
    b[0x23] = 0x00;
    b[0x24] = 0x32; // FocalLength int16uRev = 50
    b[0x83] = 1; // CameraOrientation Rotate 90 CW
    b[0x92] = 0x01;
    b[0x93] = 0xf4; // FocusDistanceUpper 500 -> 5 m
    b[0x94] = 0x01;
    b[0x95] = 0x2c; // FocusDistanceLower 300 -> 3 m
    b[0xc2] = 0x02; // WhiteBalance raw 2 (checked in -n)
    b[0xc6] = 0x50;
    b[0xc7] = 0x14; // ColorTemperature 5200
    b[0xfa] = 0x81; // PictureStyle Standard
    b[0x161] = 0x00;
    b[0x162] = 0x01; // LensType int16uRev = 1 (checked in -n)
    b[0x163] = 0x00;
    b[0x164] = 0x0a; // MinFocalLength 10
    b[0x165] = 0x00;
    b[0x166] = 0xc8; // MaxFocalLength 200
    b[0x256..0x25c].copy_from_slice(b"1.1.6\0"); // FirmwareVersion (no guard)
    b[0x2aa..0x2ae].copy_from_slice(&200u32.to_le_bytes()); // FileIndex + 1 = 201
    b[0x2b6..0x2ba].copy_from_slice(&200u32.to_le_bytes()); // DirectoryIndex - 1 = 199
    // nested PSInfo2 at 0x3c6:
    b[0x3c6..0x3ca].copy_from_slice(&3i32.to_le_bytes()); // ContrastStandard
    b[0x456..0x45a].copy_from_slice(&2i32.to_le_bytes()); // ContrastAuto (0x3c6+0x90)
    b[0x466..0x46a].copy_from_slice(&1i32.to_le_bytes()); // FilterEffectAuto (0x3c6+0xa0)
    b[0x4b6..0x4b8].copy_from_slice(&0x81u16.to_le_bytes()); // UserDef1PictureStyle (0x3c6+0xf0)
    let em = parse(&b, ByteOrder::Little, true, Some("Canon EOS 6D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("20 C".into()))
    );
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Rotate 90 CW".into()))
    );
    assert_eq!(
      find("FocusDistanceUpper"),
      Some(TagValue::Str("5 m".into()))
    );
    assert_eq!(
      find("FocusDistanceLower"),
      Some(TagValue::Str("3 m".into()))
    );
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("PictureStyle"), Some(TagValue::Str("Standard".into())));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("10 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("200 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("1.1.6".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(201)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(199)));
    // nested PSInfo2 tags:
    assert_eq!(find("ContrastStandard"), Some(TagValue::I64(3)));
    assert_eq!(find("ContrastAuto"), Some(TagValue::I64(2)));
    assert_eq!(
      find("FilterEffectAuto"),
      Some(TagValue::Str("Yellow".into()))
    );
    assert_eq!(
      find("UserDef1PictureStyle"),
      Some(TagValue::Str("Standard".into()))
    );
    // -n view: WhiteBalance / LensType render as bare masked integers.
    let emn = parse(&b, ByteOrder::Little, false, Some("Canon EOS 6D"), None);
    let findn = |n: &str| emn.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(findn("WhiteBalance"), Some(TagValue::I64(2)));
    assert_eq!(findn("LensType"), Some(TagValue::I64(1)));
  }

  #[test]
  fn dispatch_60d_1200d() {
    assert!(model_is_camera_info_60d(Some("Canon EOS 60D")));
    assert!(model_is_camera_info_60d(Some("Canon EOS 1200D")));
    assert!(model_is_camera_info_60d(Some("Canon EOS REBEL T5")));
    assert!(model_is_camera_info_60d(Some("Canon EOS Kiss X70")));
    // REBEL T5 (1200D) is distinct from REBEL T5i (700D).
    assert!(!model_is_camera_info_60d(Some("Canon EOS REBEL T5i")));
    // /EOS 60D$/ must NOT match the 6D.
    assert!(!model_is_camera_info_60d(Some("Canon EOS 6D")));
    // per-model discriminators used inside the table:
    assert!(model_is_60d_proper(Some("Canon EOS 60D")));
    assert!(!model_is_60d_proper(Some("Canon EOS 1200D")));
    assert!(model_is_1200d(Some("Canon EOS 1200D")));
    assert!(!model_is_1200d(Some("Canon EOS 60D")));
  }

  /// `%Canon::CameraInfo60D` shared 60D/1200D table: the per-model
  /// `CameraOrientation` offset (0x36 vs 0x3a), the 60D-only FocusDistance/
  /// ColorTemperature/File/Dir rows, and the `%PSInfo2` subdir at 0x321 (60D) vs
  /// 0x2f9 (1200D).
  #[test]
  fn camera_info_60d_and_1200d_alias() {
    let mut b = vec![0u8; 0x420];
    b[0x06] = 88; // ISO 400
    b[0x19] = 148; // CameraTemperature 20 C
    b[0x1e] = 0x00;
    b[0x1f] = 0x32; // FocalLength 50
    b[0x36] = 2; // CameraOrientation 60D -> Rotate 270 CW
    b[0x3a] = 1; // CameraOrientation 1200D -> Rotate 90 CW
    b[0x55] = 0x01;
    b[0x56] = 0xf4; // FocusDistanceUpper 500 -> 5 m (60D only)
    b[0x57] = 0x01;
    b[0x58] = 0x2c; // FocusDistanceLower 300 -> 3 m (60D only)
    b[0x7d] = 0x50;
    b[0x7e] = 0x14; // ColorTemperature 5200 (60D only)
    b[0xe8] = 0x00;
    b[0xe9] = 0x01; // LensType int16uRev = 1 (-n)
    b[0xea] = 0x00;
    b[0xeb] = 0x0a; // MinFocalLength 10
    b[0xec] = 0x00;
    b[0xed] = 0xc8; // MaxFocalLength 200
    b[0x199..0x19f].copy_from_slice(b"2.8.1\0"); // FirmwareVersion (no guard, both)
    b[0x1d9..0x1dd].copy_from_slice(&100u32.to_le_bytes()); // FileIndex + 1 = 101 (60D only)
    b[0x1e5..0x1e9].copy_from_slice(&100u32.to_le_bytes()); // DirectoryIndex - 1 = 99 (60D only)
    b[0x2f9..0x2fd].copy_from_slice(&5i32.to_le_bytes()); // PSInfo2(1200D) ContrastStandard
    b[0x321..0x325].copy_from_slice(&3i32.to_le_bytes()); // PSInfo2(60D) ContrastStandard

    // 60D proper:
    let em = parse(&b, ByteOrder::Little, true, Some("Canon EOS 60D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Rotate 270 CW".into()))
    );
    assert_eq!(
      find("FocusDistanceUpper"),
      Some(TagValue::Str("5 m".into()))
    );
    assert_eq!(
      find("FocusDistanceLower"),
      Some(TagValue::Str("3 m".into()))
    );
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("2.8.1".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(101)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(99)));
    assert_eq!(find("ContrastStandard"), Some(TagValue::I64(3))); // from 0x321

    // 1200D alias:
    let em2 = parse(&b, ByteOrder::Little, true, Some("Canon EOS 1200D"), None);
    let find2 = |n: &str| em2.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(
      find2("CameraOrientation"),
      Some(TagValue::Str("Rotate 90 CW".into())) // 0x3a
    );
    assert_eq!(
      find2("FirmwareVersion"),
      Some(TagValue::Str("2.8.1".into()))
    );
    assert_eq!(find2("ContrastStandard"), Some(TagValue::I64(5))); // from 0x2f9
    // 60D-only rows are absent for the 1200D.
    assert!(find2("FocusDistanceUpper").is_none());
    assert!(find2("FocusDistanceLower").is_none());
    assert!(find2("ColorTemperature").is_none());
    assert!(find2("FileIndex").is_none());
    assert!(find2("DirectoryIndex").is_none());
  }

  #[test]
  fn dispatch_anchored_70d() {
    assert!(model_is_camera_info_70d(Some("Canon EOS 70D")));
    assert!(!model_is_camera_info_70d(Some("Canon EOS 7D")));
    // /EOS 70D$/ must NOT match the 700D.
    assert!(!model_is_camera_info_70d(Some("Canon EOS 700D")));
  }

  /// `%Canon::CameraInfo70D` print values + the nested `%PSInfo2` subdir; the
  /// table carries NO `WhiteBalance` leaf.
  #[test]
  fn camera_info_70d_fields() {
    let mut b = vec![0u8; 0x4d0];
    b[0x06] = 88; // ISO 400
    b[0x1b] = 148; // CameraTemperature 20 C
    b[0x23] = 0x00;
    b[0x24] = 0x32; // FocalLength 50
    b[0x84] = 1; // CameraOrientation Rotate 90 CW
    b[0x93] = 0x01;
    b[0x94] = 0xf4; // FocusDistanceUpper 500 -> 5 m
    b[0x95] = 0x01;
    b[0x96] = 0x2c; // FocusDistanceLower 300 -> 3 m
    b[0xc7] = 0x50;
    b[0xc8] = 0x14; // ColorTemperature 5200
    b[0x166] = 0x00;
    b[0x167] = 0x01; // LensType int16uRev = 1 (-n)
    b[0x168] = 0x00;
    b[0x169] = 0x0a; // MinFocalLength 10
    b[0x16a] = 0x00;
    b[0x16b] = 0xc8; // MaxFocalLength 200
    b[0x25e..0x264].copy_from_slice(b"6.1.2\0"); // FirmwareVersion (no guard)
    b[0x2b3..0x2b7].copy_from_slice(&100u32.to_le_bytes()); // FileIndex + 1 = 101
    b[0x2bf..0x2c3].copy_from_slice(&100u32.to_le_bytes()); // DirectoryIndex - 1 = 99
    b[0x3cf..0x3d3].copy_from_slice(&4i32.to_le_bytes()); // PSInfo2 ContrastStandard
    b[0x45f..0x463].copy_from_slice(&2i32.to_le_bytes()); // PSInfo2 ContrastAuto (0x3cf+0x90)
    b[0x4bf..0x4c1].copy_from_slice(&0x86u16.to_le_bytes()); // UserDef1PictureStyle (0x3cf+0xf0)
    let em = parse(&b, ByteOrder::Little, true, Some("Canon EOS 70D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ISO"), Some(TagValue::Str("400".into())));
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("20 C".into()))
    );
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Rotate 90 CW".into()))
    );
    assert_eq!(
      find("FocusDistanceUpper"),
      Some(TagValue::Str("5 m".into()))
    );
    assert_eq!(
      find("FocusDistanceLower"),
      Some(TagValue::Str("3 m".into()))
    );
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("10 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("200 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("6.1.2".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(101)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(99)));
    assert_eq!(find("ContrastStandard"), Some(TagValue::I64(4)));
    assert_eq!(find("ContrastAuto"), Some(TagValue::I64(2)));
    assert_eq!(
      find("UserDef1PictureStyle"),
      Some(TagValue::Str("Monochrome".into()))
    );
    // The 70D table has no WhiteBalance row.
    assert!(find("WhiteBalance").is_none());
    // -n view: LensType renders the bare integer.
    let emn = parse(&b, ByteOrder::Little, false, Some("Canon EOS 70D"), None);
    assert_eq!(
      emn
        .iter()
        .find(|(k, _)| k == "LensType")
        .map(|(_, v)| v.clone()),
      Some(TagValue::I64(1))
    );
  }

  #[test]
  fn dispatch_600d_1100d() {
    assert!(model_is_camera_info_600d(Some("Canon EOS 600D")));
    assert!(model_is_camera_info_600d(Some("Canon EOS REBEL T3i")));
    assert!(model_is_camera_info_600d(Some("Canon EOS Kiss X5")));
    assert!(model_is_camera_info_600d(Some("Canon EOS 1100D")));
    assert!(model_is_camera_info_600d(Some("Canon EOS REBEL T3")));
    assert!(model_is_camera_info_600d(Some("Canon EOS Kiss X50")));
    // REBEL T3 (1100D) vs REBEL T3i (600D): the T3i token must not leak into the
    // T5 (1200D) family, and Kiss X6i (650D) must not match.
    assert!(!model_is_camera_info_600d(Some("Canon EOS REBEL T5")));
    assert!(!model_is_camera_info_600d(Some("Canon EOS Kiss X6i")));
  }

  /// `%Canon::CameraInfo600D` shared 600D/1100D table (all rows unconditional):
  /// print values, the `FirmwareVersion` RawConv guard, and the `%PSInfo2` subdir.
  #[test]
  fn camera_info_600d_fields() {
    let mut b = vec![0u8; 0x400];
    b[0x06] = 88; // ISO 400
    b[0x07] = 1; // HighlightTonePriority On
    b[0x15] = 0; // FlashMeteringMode E-TTL
    b[0x19] = 148; // CameraTemperature 20 C
    b[0x1e] = 0x00;
    b[0x1f] = 0x32; // FocalLength 50
    b[0x38] = 2; // CameraOrientation Rotate 270 CW
    b[0x57] = 0x01;
    b[0x58] = 0xf4; // FocusDistanceUpper 500 -> 5 m
    b[0x59] = 0x01;
    b[0x5a] = 0x2c; // FocusDistanceLower 300 -> 3 m
    b[0x7b] = 0x02; // WhiteBalance raw 2 (-n)
    b[0x7f] = 0x50;
    b[0x80] = 0x14; // ColorTemperature 5200
    b[0xb3] = 0x81; // PictureStyle Standard
    b[0xea] = 0x00;
    b[0xeb] = 0x01; // LensType int16uRev = 1 (-n)
    b[0xec] = 0x00;
    b[0xed] = 0x0a; // MinFocalLength 10
    b[0xee] = 0x00;
    b[0xef] = 0xc8; // MaxFocalLength 200
    b[0x19b..0x1a1].copy_from_slice(b"1.0.2\0"); // FirmwareVersion (valid, guarded)
    b[0x1db..0x1df].copy_from_slice(&100u32.to_le_bytes()); // FileIndex + 1 = 101
    b[0x1e7..0x1eb].copy_from_slice(&100u32.to_le_bytes()); // DirectoryIndex - 1 = 99
    b[0x2fb..0x2ff].copy_from_slice(&6i32.to_le_bytes()); // PSInfo2 ContrastStandard
    b[0x39b..0x39f].copy_from_slice(&1i32.to_le_bytes()); // PSInfo2 FilterEffectAuto (0x2fb+0xa0)
    b[0x3eb..0x3ed].copy_from_slice(&0x83u16.to_le_bytes()); // UserDef1PictureStyle (0x2fb+0xf0)
    let em = parse(&b, ByteOrder::Little, true, Some("Canon EOS 600D"), None);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(
      find("HighlightTonePriority"),
      Some(TagValue::Str("On".into()))
    );
    assert_eq!(
      find("FlashMeteringMode"),
      Some(TagValue::Str("E-TTL".into()))
    );
    assert_eq!(
      find("CameraTemperature"),
      Some(TagValue::Str("20 C".into()))
    );
    assert_eq!(find("FocalLength"), Some(TagValue::Str("50 mm".into())));
    assert_eq!(
      find("CameraOrientation"),
      Some(TagValue::Str("Rotate 270 CW".into()))
    );
    assert_eq!(
      find("FocusDistanceUpper"),
      Some(TagValue::Str("5 m".into()))
    );
    assert_eq!(
      find("FocusDistanceLower"),
      Some(TagValue::Str("3 m".into()))
    );
    assert_eq!(find("ColorTemperature"), Some(TagValue::I64(5200)));
    assert_eq!(find("PictureStyle"), Some(TagValue::Str("Standard".into())));
    assert_eq!(find("MinFocalLength"), Some(TagValue::Str("10 mm".into())));
    assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("200 mm".into())));
    assert_eq!(find("FirmwareVersion"), Some(TagValue::Str("1.0.2".into())));
    assert_eq!(find("FileIndex"), Some(TagValue::I64(101)));
    assert_eq!(find("DirectoryIndex"), Some(TagValue::I64(99)));
    assert_eq!(find("ContrastStandard"), Some(TagValue::I64(6)));
    assert_eq!(
      find("FilterEffectAuto"),
      Some(TagValue::Str("Yellow".into()))
    );
    assert_eq!(
      find("UserDef1PictureStyle"),
      Some(TagValue::Str("Landscape".into()))
    );
    // 1100D alias yields the identical table.
    let em2 = parse(&b, ByteOrder::Little, true, Some("Canon EOS 1100D"), None);
    let find2 = |n: &str| em2.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(
      find2("FirmwareVersion"),
      Some(TagValue::Str("1.0.2".into()))
    );
    assert_eq!(find2("ContrastStandard"), Some(TagValue::I64(6)));
    // The RawConv guard drops a non-version FirmwareVersion string.
    b[0x19b..0x1a1].copy_from_slice(b"BADVER");
    let em3 = parse(&b, ByteOrder::Little, true, Some("Canon EOS 600D"), None);
    assert!(em3.iter().all(|(k, _)| k != "FirmwareVersion"));
    // -n view: WhiteBalance / LensType render as bare integers.
    let emn = parse(&b, ByteOrder::Little, false, Some("Canon EOS 600D"), None);
    let findn = |n: &str| emn.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(findn("WhiteBalance"), Some(TagValue::I64(2)));
    assert_eq!(findn("LensType"), Some(TagValue::I64(1)));
  }
}
