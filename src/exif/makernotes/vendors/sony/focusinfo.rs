// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::FocusInfo` (`Sony.pm:3195-3382`) — the `0x0020`
//! Main-table SubDirectory dispatched (over `MoreInfo`) when `$count == 19154 ||
//! 19148` (`Sony.pm:753-760`), a plain (un-enciphered) `ProcessBinaryData` block
//! of camera settings + focus information for the A200/A230/A290/A300/A330/A350/
//! A380/A390/A700/A850/A900.
//!
//! `ByteOrder => 'LittleEndian'`, default `int8u` format, `PRIORITY => 0` — so
//! every leaf here is a `Priority => 0` duplicate (a higher-priority Main-IFD or
//! `CameraInfo2` leaf of the same name is NOT overridden), and where a settings
//! leaf is ALSO in the later `CameraSettings` block (`0x0114`) this earlier copy
//! wins the priority-0 first-wins tie.
//!
//! Per the `ProcessBinaryData` per-field-availability contract each tag is
//! emitted IFF its byte range is in the block AND its model `Condition` holds
//! ([[exifast-processbinarydata-per-field]]).

use crate::value::TagValue;

use super::subtables::{
  SubEmission, creative_style, drive_mode_a200, dro_mode, exposure_program, hash_hex_value,
};

/// `DriveMode2` (0x0e) variant-1 PrintConv (`Sony.pm:3204-3216`) — A230, A290,
/// A330, A380, A390 (`$$self{Model} =~ /^DSLR-A(230|290|330|380|390)$/`).
fn drive_mode2_a23x(v: u32) -> Option<&'static str> {
  Some(match v {
    0x01 => "Single Frame",
    0x02 => "Continuous High",
    0x04 => "Self-timer 10 sec",
    0x05 => "Self-timer 2 sec, Mirror Lock-up",
    0x07 => "Continuous Bracketing",
    0x0a => "Remote Commander",
    0x0b => "Continuous Self-timer",
    _ => return None,
  })
}

/// `Rotation` (0x10) PrintConv (`Sony.pm:3239-3246`) — note `1`/`2` are INVERTED
/// vs the `CameraSettings` 0x3f `Rotation`.
fn rotation(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Horizontal (normal)",
    1 => "Rotate 270 CW",
    2 => "Rotate 90 CW",
    _ => return None,
  })
}

/// `WhiteBalanceBracketing` (0x2c) / `DynamicRangeOptimizerBracket` (0x2e)
/// PrintConv (`0 => Off`, `1 => Low`, `2 => High`).
fn bracket_off_low_high(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    1 => "Low",
    2 => "High",
    _ => return None,
  })
}

/// `ImageStabilizationSetting` (0x14) PrintConv (`0 => Off`, `1 => On`).
fn image_stabilization(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    1 => "On",
    _ => return None,
  })
}

/// Is `model` an A230/A290/A330/A380/A390 (`$`-anchored EXACT) — the `DriveMode2`
/// variant-1 set.
fn model_is_a23x(model: Option<&str>) -> bool {
  matches!(
    model,
    Some("DSLR-A230" | "DSLR-A290" | "DSLR-A330" | "DSLR-A380" | "DSLR-A390")
  )
}

/// Push a simple `int8u` hash-PrintConv leaf at `off`.
fn push_hash(
  buf: &[u8],
  off: usize,
  name: &'static str,
  hit: impl Fn(u8) -> Option<&'static str>,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  if let Some(&raw) = buf.get(off) {
    out.push(SubEmission::new(
      name,
      super::hash_print_value(raw, hit(raw), print_conv),
    ));
  }
}

/// Push a plain `int8u` leaf (no PrintConv) at `off`.
fn push_plain(buf: &[u8], off: usize, name: &'static str, out: &mut Vec<SubEmission>) {
  if let Some(&raw) = buf.get(off) {
    out.push(SubEmission::new(name, TagValue::I64(i64::from(raw))));
  }
}

/// `ISOSetting` (0x6d) / `ISO` (0x6f) value (`Sony.pm:3311-3325`): ValueConv
/// `$val ? exp(($val/8-6)*log(2))*100 : $val`, PrintConv `$val ? sprintf("%.0f")
/// : "Auto"`. `-n` is the bare ValueConv float (a whole result renders without a
/// trailing `.0`); `-j` is the rounded integer / `"Auto"`.
fn iso_value(raw: u8, print_conv: bool) -> TagValue {
  if raw == 0 {
    return if print_conv {
      TagValue::Str("Auto".into())
    } else {
      TagValue::I64(0)
    };
  }
  let vc = ((f64::from(raw) / 8.0 - 6.0) * core::f64::consts::LN_2).exp() * 100.0;
  if print_conv {
    TagValue::I64((vc + 0.5) as i64)
  } else {
    TagValue::F64(vc)
  }
}

/// Walk the `FocusInfo` block and emit the settings/focus leaves (`Priority =>
/// 0`, set by the caller).
///
/// `buf` is the verbatim (un-enciphered) `0x0020` block; `model` is
/// `$$self{Model}`; `print_conv` selects `-j` vs `-n`.
#[must_use]
pub fn parse_focus_info(buf: &[u8], model: Option<&str>, print_conv: bool) -> Vec<SubEmission> {
  let mut out = std::vec::Vec::new();

  // 0x0e DriveMode2 — PrintHex; variant-1 for A230/A290/A330/A380/A390, else
  // variant-2 (Sony.pm:3203-3237).
  if let Some(&raw) = buf.get(0x0e) {
    let hit = if model_is_a23x(model) {
      drive_mode2_a23x(u32::from(raw))
    } else {
      drive_mode_a200(u32::from(raw))
    };
    out.push(SubEmission::new(
      "DriveMode2",
      hash_hex_value(u32::from(raw), hit, print_conv),
    ));
  }

  push_hash(buf, 0x10, "Rotation", rotation, print_conv, &mut out);
  push_hash(
    buf,
    0x14,
    "ImageStabilizationSetting",
    image_stabilization,
    print_conv,
    &mut out,
  );
  push_hash(
    buf,
    0x15,
    "DynamicRangeOptimizerMode",
    dro_mode,
    print_conv,
    &mut out,
  );

  push_plain(buf, 0x2b, "BracketShotNumber", &mut out);
  push_hash(
    buf,
    0x2c,
    "WhiteBalanceBracketing",
    bracket_off_low_high,
    print_conv,
    &mut out,
  );
  push_plain(buf, 0x2d, "BracketShotNumber2", &mut out);
  push_hash(
    buf,
    0x2e,
    "DynamicRangeOptimizerBracket",
    bracket_off_low_high,
    print_conv,
    &mut out,
  );
  push_plain(buf, 0x2f, "ExposureBracketShotNumber", &mut out);

  push_hash(
    buf,
    0x3f,
    "ExposureProgram",
    exposure_program,
    print_conv,
    &mut out,
  );
  push_hash(
    buf,
    0x41,
    "CreativeStyle",
    creative_style,
    print_conv,
    &mut out,
  );

  // 0x6d ISOSetting / 0x6f ISO — exp ValueConv (Sony.pm:3311-3325).
  if let Some(&raw) = buf.get(0x6d) {
    out.push(SubEmission::new("ISOSetting", iso_value(raw, print_conv)));
  }
  if let Some(&raw) = buf.get(0x6f) {
    out.push(SubEmission::new("ISO", iso_value(raw, print_conv)));
  }

  // 0x77 DynamicRangeOptimizerMode (a 2nd copy at a different offset) / 0x79
  // DynamicRangeOptimizerLevel (Sony.pm:3326-3340).
  push_hash(
    buf,
    0x77,
    "DynamicRangeOptimizerMode",
    dro_mode,
    print_conv,
    &mut out,
  );
  push_plain(buf, 0x79, "DynamicRangeOptimizerLevel", &mut out);

  // 0x09bb FocusPosition — `int8u`, `Condition => $$self{Model} =~
  // /^DSLR-A(200|230|290|300|330|350|380|390|700|850|900)$/` (Sony.pm:3345-3350).
  // 128 = infinity (drives Composite:FocusDistance).
  if model_has_focus_position(model) {
    push_plain(buf, 0x09bb, "FocusPosition", &mut out);
  }

  // 0x1110 TiffMeteringImage — `undef[9600]`, ValueConv `return undef unless
  // length $val >= 9600; \ "Binary data 7404 bytes"` (Sony.pm:3352-3380). The
  // scalar-ref renders to the fixed placeholder in BOTH modes.
  if buf.len() >= 0x1110 + 9600 {
    out.push(SubEmission::new(
      "TiffMeteringImage",
      TagValue::Str("(Binary data 7404 bytes, use -b option to extract)".into()),
    ));
  }

  out
}

/// `Condition => $$self{Model} =~ /^DSLR-A(200|230|290|300|330|350|380|390|700|
/// 850|900)$/` for `FocusPosition` (`Sony.pm:3347`).
fn model_has_focus_position(model: Option<&str>) -> bool {
  matches!(
    model,
    Some(
      "DSLR-A200"
        | "DSLR-A230"
        | "DSLR-A290"
        | "DSLR-A300"
        | "DSLR-A330"
        | "DSLR-A350"
        | "DSLR-A380"
        | "DSLR-A390"
        | "DSLR-A700"
        | "DSLR-A850"
        | "DSLR-A900"
    )
  )
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
#[path = "focusinfo_tests.rs"]
mod tests;
