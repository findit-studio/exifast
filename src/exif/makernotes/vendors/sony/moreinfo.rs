// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::MoreInfo` (`Sony.pm:3382-3456`) — the `0x0020`
//! Main-table SubDirectory dispatched (over `FocusInfo`) when `$count` is NOT
//! `19154`/`19148` (`Sony.pm:44-63`). Unlike the other older sub-tables, its
//! `PROCESS_PROC` is the bespoke `ProcessMoreInfo` (`Sony.pm:11247-11360`): an
//! INDEX directory, not a flat `ProcessBinaryData` block.
//!
//! ## `ProcessMoreInfo` index layout
//! `[ num:int16u ][ len:int16u ][ num × (tagID:int16u, offset:int16u) ]`. Each
//! index entry points at a block whose size is the gap to the next-higher
//! offset (sorted), clamped to `len`. The four ported blocks dispatch to plain
//! `ProcessBinaryData` sub-tables whose offsets are RELATIVE to the block start:
//! `MoreSettings` (0x0001), `FaceInfo` (0x0002), `MoreInfo0201` (0x0201) and
//! `MoreInfo0401` (0x0401).
//!
//! Per the `ProcessBinaryData` per-field contract each leaf is emitted IFF its
//! byte range is in its block AND its model `Condition` holds
//! ([[exifast-processbinarydata-per-field]]). The truncation/corruption guards
//! (`dirLen < 4`, `dirLen < 4 + num*4`, `num > 50`) match `ProcessMoreInfo`.

use crate::exif::tables::{print_exposure_time, print_fnumber};
use crate::value::TagValue;
use smol_str::SmolStr;

use super::subtables::{
  SubEmission, drive_mode, exposure_comp_value, exposure_comp2_value, exposure_program2,
  hash_hex_value, model_is_a4xx_exact, model_is_a4xx_prefix, model_is_nex355c, read_i16, read_u16,
  read_u32, signed_setting_value, white_balance_setting,
};

/// Walk the `MoreInfo` index directory and emit the leaves of the four ported
/// blocks.
///
/// `buf` is the verbatim `0x0020` block (`DirStart = 0`, `DirLen = buf.len()`).
/// `model` is `$$self{Model}`; `print_conv` selects `-j` vs `-n`.
#[must_use]
pub fn parse_more_info(buf: &[u8], model: Option<&str>, print_conv: bool) -> Vec<SubEmission> {
  let mut out = std::vec::Vec::new();
  // `ProcessMoreInfo`: `return if $dirLen < 4`.
  let Some(num) = read_u16(buf, 0) else {
    return out;
  };
  let num = usize::from(num);
  let Some(len_hdr) = read_u16(buf, 2) else {
    return out;
  };
  let dir_len = buf.len();
  // `$dirLen < 4 + $num*4` ⇒ truncated; `$num > 50` ⇒ corrupted.
  if dir_len < 4 + num * 4 || num > 50 {
    return out;
  }
  let mut len = usize::from(len_hdr);
  if len > dir_len {
    len = dir_len;
  }

  // Read the index, then derive each block's size from the sorted offsets.
  let mut index: std::vec::Vec<(u16, usize)> = std::vec::Vec::with_capacity(num);
  for i in 0..num {
    let entry = 4 + i * 4;
    let Some(tag) = read_u16(buf, entry) else {
      return out;
    };
    let Some(off) = read_u16(buf, entry + 2) else {
      return out;
    };
    let off = usize::from(off);
    index.push((tag, off));
    if off > len && off <= dir_len {
      len = dir_len;
    }
  }
  // Block size = gap to the next-higher sorted offset, clamped to `len`.
  let mut sorted: std::vec::Vec<usize> = index.iter().map(|&(_, off)| off).collect();
  sorted.sort_unstable();
  sorted.push(0xffff);
  let mut block_size: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
  for pair in sorted.windows(2) {
    let &[off, next] = pair else { continue };
    let mut size = next.saturating_sub(off);
    if size > len.saturating_sub(off) {
      size = len.saturating_sub(off);
    }
    block_size.entry(off).or_insert(size);
  }

  // Dispatch each index entry to its block sub-table. `MoreSettings` /
  // `MoreInfo0201` / `MoreInfo0401` are `PRIORITY => 0`; `FaceInfo` has no
  // `PRIORITY` (default 1). The priority is applied to each block's freshly
  // pushed leaves so a later `CameraSettings3` duplicate (also `PRIORITY => 0`)
  // resolves last-wins, while a higher-priority Main leaf still wins.
  for &(tag_id, off) in &index {
    if off > dir_len {
      continue; // ignore bad offsets
    }
    let size = block_size.get(&off).copied().unwrap_or(0);
    let Some(block) = buf.get(off..off + size) else {
      continue;
    };
    let start = out.len();
    let block_priority = match tag_id {
      0x0001 => {
        parse_more_settings(block, model, print_conv, &mut out);
        0
      }
      // FaceInfo vs FaceInfoA is the `$`-anchored EXACT selector
      // (`Sony.pm:3398`/`3402`): `FaceInfoA` only for a model EQUAL to
      // DSLR-A450/A500/A550, else this non-A4xx `FaceInfo` — so a suffixed body
      // still parses FaceInfo. This is NOT the `\b` `model_is_a4xx_9pt` (the
      // ExtraInfo3 0x0014 / CameraInfo3 9-point-AF condition).
      0x0002 if !model_is_a4xx_exact(model) => {
        parse_face_info(block, print_conv, &mut out);
        1
      }
      // 0x0107 TiffMeteringImage — the 7200-byte (3×40×30 int16u) AE-metering
      // block, ValueConv `\ "Binary data 7404 bytes"` (Sony.pm:3413-3437). The
      // scalar-ref renders to the fixed `(Binary data 7404 bytes, …)`
      // placeholder (`exiftool:3984-3986`) in BOTH `-j` and `-n`, emitted only
      // when `length $val >= 7200`.
      0x0107 if block.len() >= 7200 => {
        out.push(SubEmission::new(
          "TiffMeteringImage",
          TagValue::Str("(Binary data 7404 bytes, use -b option to extract)".into()),
        ));
        1
      }
      0x0201 => {
        parse_more_info0201(block, model, print_conv, &mut out);
        0
      }
      0x0401 => {
        parse_more_info0401(block, model, print_conv, &mut out);
        0
      }
      _ => continue,
    };
    if let Some(fresh) = out.get_mut(start..) {
      for e in fresh {
        e.priority = block_priority;
      }
    }
  }
  out
}

/// `%Sony::MoreSettings` (`Sony.pm:3528-4006`) — the bulk of the older-body
/// settings. This ports the "other models" (`!~ NEX-(3|5|5C)|DSLR-A4xx`)
/// branches the A33 needs plus the shared leaves; the A4xx/NEX-only overlapping
/// offsets stay deferred.
fn parse_more_settings(
  buf: &[u8],
  model: Option<&str>,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  // Two A4xx anchor flavors live in this table: 0x13/0x15 are `$`-anchored EXACT
  // (`/^DSLR-(A450|A500|A550)$/`), while every overlapping-offset `other` leaf
  // (0x1e..0x86) is the no-anchor PREFIX (`/^DSLR-(A450|A500|A550)/`). A single
  // `\b` bool is wrong in OPPOSITE directions for a suffixed A4xx string, so
  // split them.
  let a4xx_exact = model_is_a4xx_exact(model);
  let a4xx_prefix = model_is_a4xx_prefix(model);
  let nex355c = model_is_nex355c(model);
  // `!~ /^NEX-(3|5|5C)|DSLR-(A450|A500|A550)/` — the prefix-A4xx + NEX-3/5/5C
  // exclusion shared by the 0x1e..0x86 overlapping leaves.
  let other = !a4xx_prefix && !nex355c;

  // 0x01 DriveMode2 — PrintHex, %sonyDriveMode (Sony.pm:3534).
  push_hash_hex(
    buf,
    0x01,
    "DriveMode2",
    |v| drive_mode(v, false),
    print_conv,
    out,
  );
  // 0x02 ExposureProgram — %sonyExposureProgram2 (Sony.pm:3550).
  push_hash(
    buf,
    0x02,
    "ExposureProgram",
    |v| exposure_program2(u32::from(v)),
    print_conv,
    out,
  );
  push_hash(buf, 0x03, "MeteringMode", metering_mode, print_conv, out);
  push_hash(
    buf,
    0x04,
    "DynamicRangeOptimizerSetting",
    dro_setting,
    print_conv,
    out,
  );
  push_plain(buf, 0x05, "DynamicRangeOptimizerLevel", out);
  push_hash(buf, 0x06, "ColorSpace", color_space, print_conv, out);
  push_hash(
    buf,
    0x07,
    "CreativeStyleSetting",
    creative_style_setting,
    print_conv,
    out,
  );
  push_signed(buf, 0x08, "ContrastSetting", print_conv, out);
  push_signed(buf, 0x09, "SaturationSetting", print_conv, out);
  push_signed(buf, 0x0a, "SharpnessSetting", print_conv, out);
  // 0x0d WhiteBalanceSetting — PrintHex, %whiteBalanceSetting (Sony.pm:3606).
  push_hash_hex(
    buf,
    0x0d,
    "WhiteBalanceSetting",
    white_balance_setting,
    print_conv,
    out,
  );
  // 0x0e ColorTemperatureSetting — `$val*100`, "$val K" (Sony.pm:3614).
  push_color_temp(buf, 0x0e, out, print_conv);
  push_signed(buf, 0x0f, "ColorCompensationFilterSet", print_conv, out);
  push_hash(buf, 0x10, "FlashMode", flash_mode, print_conv, out);
  push_hash(
    buf,
    0x11,
    "LongExposureNoiseReduction",
    long_exposure_nr,
    print_conv,
    out,
  );
  push_hash(
    buf,
    0x12,
    "HighISONoiseReduction",
    high_iso_nr,
    print_conv,
    out,
  );
  // 0x13 FocusMode — `!~ /^DSLR-(A450|A500|A550)$/` ($-anchored EXACT,
  // Sony.pm:3662).
  if !a4xx_exact {
    push_hash(
      buf,
      0x13,
      "FocusMode",
      focus_mode_morsettings,
      print_conv,
      out,
    );
  }
  // 0x15 MultiFrameNoiseReduction — `!~ /^DSLR-(A450|A500|A550)$/` ($-anchored
  // EXACT, Sony.pm:3673).
  if !a4xx_exact {
    push_hash(
      buf,
      0x15,
      "MultiFrameNoiseReduction",
      multi_frame_nr,
      print_conv,
      out,
    );
  }
  push_hash(buf, 0x16, "HDRSetting", hdr_setting, print_conv, out);
  push_hash(buf, 0x17, "HDRLevel", hdr_level, print_conv, out);
  push_hash(buf, 0x18, "ViewingMode", viewing_mode, print_conv, out);
  push_hash(buf, 0x19, "FaceDetection", face_detection, print_conv, out);
  // 0x1a CustomWB_RBLevels — int16uRev[2] (Sony.pm:3697).
  push_custom_wb_rb(buf, 0x1a, out);

  // The overlapping exposure offsets — the A33 (other) branches.
  if other {
    // 0x1e ExposureCompensationSet (Sony.pm:3717).
    push_exposure_comp(buf, 0x1e, "ExposureCompensationSet", print_conv, out);
    // 0x1f FlashExposureCompSet (Sony.pm:3728).
    push_exposure_comp(buf, 0x1f, "FlashExposureCompSet", print_conv, out);
    // 0x20 LiveViewAFMethod — `!~ NEX-(3|5|5C)` (Sony.pm:3744).
    push_hash(
      buf,
      0x20,
      "LiveViewAFMethod",
      live_view_af_method,
      print_conv,
      out,
    );
    // 0x25 ISO — variant 2, `!~ /^DSLR-(A450|A500|A550)/` (no-anchor PREFIX,
    // Sony.pm:3843).
    push_iso(buf, 0x25, out, print_conv);
    // 0x26 FNumber — "other models" fallback after the A4xx-prefix / NEX-prefix
    // variants (Sony.pm:3870).
    push_fnumber(buf, 0x26, "FNumber", print_conv, out);
    // 0x27 ExposureTime — `!~ NEX-(3|5|5C)|DSLR-A4xx` (Sony.pm:3819).
    push_exposure_time(buf, 0x27, "ExposureTime", print_conv, out);
    // 0x29 FocalLength2 — `!~ NEX-(3|5|5C)` (Sony.pm:3851).
    push_focal_length2(buf, 0x29, out, print_conv);
    // 0x2a ExposureCompensation2 — int16s `!~ NEX-(3|5|5C)` (Sony.pm:3868).
    push_exposure_comp2(buf, 0x2a, "ExposureCompensation2", print_conv, out);
    // 0x2c FlashExposureCompSet2 — int16s "other models" (Sony.pm:3902).
    push_exposure_comp2(buf, 0x2c, "FlashExposureCompSet2", print_conv, out);
    // 0x2e Orientation2 — `!~ DSLR-A4xx` (Sony.pm:3919).
    push_hash(buf, 0x2e, "Orientation2", orientation2, print_conv, out);
    // 0x2f FocusPosition2 — `!~ NEX-(3|5|5C)|DSLR-A4xx` (Sony.pm:3930).
    push_plain(buf, 0x2f, "FocusPosition2", out);
    // 0x30 FlashAction — `!~ NEX-(3|5|5C)|DSLR-A4xx` (Sony.pm:3936).
    push_hash(buf, 0x30, "FlashAction", flash_action, print_conv, out);
    // 0x32 FocusMode2 — `!~ NEX-(3|5|5C)|DSLR-A4xx` (Sony.pm:3947).
    push_hash(buf, 0x32, "FocusMode2", focus_mode2, print_conv, out);
    // 0x7c FlashActionExternal — `!~ NEX-(3|5|5C)|DSLR-A4xx` (Sony.pm:3974).
    push_hash(
      buf,
      0x7c,
      "FlashActionExternal",
      flash_action_external,
      print_conv,
      out,
    );
    // 0x86 FlashStatus — `!~ NEX-(3|5|5C)|DSLR-A4xx` (Sony.pm:3997).
    push_hash(buf, 0x86, "FlashStatus", flash_status, print_conv, out);
  }
}

/// `%Sony::FaceInfo` (`Sony.pm:4062-4122`) — the non-A4xx `FaceInfo` variant the
/// A33-class dispatches (`MoreInfo` 0x0002 when
/// `Model !~ /^DSLR-(A450|A500|A550)$/`; the A4xx `FaceInfoA` is deferred).
///
/// `FORMAT => 'int16u'` ⇒ the `ProcessBinaryData` increment is 2, so a table key
/// `K` addresses BYTE `K*2` (`ExifTool.pm:9933`). 0x00 `FacesDetected` is
/// `int16s` with `RawConv => '$$self{FacesDetected} = ($val == -1 ? 0 : $val);
/// $val'` — the emitted value is the original `$val` (`-1 => 'n/a'` in `-j`),
/// while the per-face DataMember gate folds `-1` to `0`. Keys
/// 0x01/0x06/0x0b/0x10/0x15/0x1a/0x1f/0x24 are `Face1..8Position` (`int16u[4]`),
/// each emitted IFF `FacesDetected >= N` AND its full 8-byte range is in-block
/// ([[exifast-processbinarydata-per-field]]).
fn parse_face_info(buf: &[u8], print_conv: bool, out: &mut Vec<SubEmission>) {
  // 0x00 FacesDetected — int16s at byte 0 (key 0x00 × 2).
  let Some(raw) = read_i16(buf, 0x00) else {
    return;
  };
  let value = if print_conv && raw == -1 {
    TagValue::Str("n/a".into())
  } else {
    TagValue::I64(i64::from(raw))
  };
  out.push(SubEmission {
    priority: 1,
    name: "FacesDetected",
    value,
  });

  // DataMember gate for the per-face rows: `($val == -1 ? 0 : $val)`.
  let faces = if raw == -1 { 0 } else { raw };

  // Face1..8Position — `int16u[4]` at byte (key × 2), gated by
  // `FacesDetected >= N`. `%faceInfo` has no PrintConv, so `-j` and `-n` render
  // the same re-ordered/scaled string.
  const FACES: [(i16, &str, usize); 8] = [
    (1, "Face1Position", 0x01),
    (2, "Face2Position", 0x06),
    (3, "Face3Position", 0x0b),
    (4, "Face4Position", 0x10),
    (5, "Face5Position", 0x15),
    (6, "Face6Position", 0x1a),
    (7, "Face7Position", 0x1f),
    (8, "Face8Position", 0x24),
  ];
  for (n, name, key) in FACES {
    if faces < n {
      continue;
    }
    if let Some(value) = face_position_value(buf, key * 2) {
      out.push(SubEmission {
        priority: 1,
        name,
        value,
      });
    }
  }
}

/// `%faceInfo` (`Sony.pm:4056-4061`) — read the `int16u[4]` rectangle at `byte`
/// (LE), then `ValueConv => 'my @v=split(" ",$val); $_*=15 foreach @v;
/// "$v[1] $v[0] $v[3] $v[2]"'`: scale each ×15 and re-order to top, left,
/// height, width. `None` when the full 8-byte range is not in-block.
fn face_position_value(buf: &[u8], byte: usize) -> Option<TagValue> {
  let v0 = u32::from(read_u16(buf, byte)?);
  let v1 = u32::from(read_u16(buf, byte + 2)?);
  let v2 = u32::from(read_u16(buf, byte + 4)?);
  let v3 = u32::from(read_u16(buf, byte + 6)?);
  let (top, left, height, width) = (v1 * 15, v0 * 15, v3 * 15, v2 * 15);
  Some(TagValue::Str(SmolStr::new(std::format!(
    "{top} {left} {height} {width}"
  ))))
}

/// `%Sony::MoreInfo0201` (`Sony.pm:3457-3496`) — ImageCount (0x011b) +
/// ShutterCount (0x0125), int32u `& 0x00ffffff`,
/// `!~ /^DSLR-A(450|500|550)$/` ($-anchored EXACT).
fn parse_more_info0201(
  buf: &[u8],
  model: Option<&str>,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  // `Condition => '$$self{Model} !~ /^DSLR-A(450|500|550)$/'` ($-anchored EXACT,
  // Sony.pm:3477/3484) — NOT the `\b` boundary, so a hyphen/space-suffixed A4xx
  // body still emits ImageCount/ShutterCount. The exact A4xx bodies instead
  // carry 0x014a ShutterCount (deferred — not the A33 path).
  if model_is_a4xx_exact(model) {
    return;
  }
  let _ = print_conv;
  if let Some(v) = read_u32(buf, 0x011b) {
    out.push(SubEmission {
      priority: 1,
      name: "ImageCount",
      value: TagValue::I64(i64::from(v & 0x00ff_ffff)),
    });
  }
  if let Some(v) = read_u32(buf, 0x0125) {
    out.push(SubEmission {
      priority: 1,
      name: "ShutterCount",
      value: TagValue::I64(i64::from(v & 0x00ff_ffff)),
    });
  }
}

/// `%Sony::MoreInfo0401` (`Sony.pm:3498-3527`) — ShotNumberSincePowerUp
/// (0x044e), int32u `& 0x00ffffff`, `!~ NEX-(3|5)`.
fn parse_more_info0401(
  buf: &[u8],
  model: Option<&str>,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  let _ = print_conv;
  // `Condition => '$$self{Model} !~ /^NEX-(3|5)$/'` — a `$`-anchored exact
  // match (NEX-3 / NEX-5 only, NOT NEX-5C).
  if model.is_some_and(|m| m == "NEX-3" || m == "NEX-5") {
    return;
  }
  if let Some(v) = read_u32(buf, 0x044e) {
    out.push(SubEmission {
      priority: 1,
      name: "ShotNumberSincePowerUp",
      value: TagValue::I64(i64::from(v & 0x00ff_ffff)),
    });
  }
}

// ---- shared MoreSettings PrintConv hashes ----

fn metering_mode(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "Multi-segment",
    2 => "Center-weighted average",
    3 => "Spot",
    _ => return None,
  })
}

fn dro_setting(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "Off",
    16 => "On (Auto)",
    17 => "On (Manual)",
    _ => return None,
  })
}

fn color_space(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "sRGB",
    2 => "Adobe RGB",
    _ => return None,
  })
}

fn creative_style_setting(v: u8) -> Option<&'static str> {
  Some(match v {
    16 => "Standard",
    32 => "Vivid",
    64 => "Portrait",
    80 => "Landscape",
    96 => "B&W",
    160 => "Sunset",
    _ => return None,
  })
}

fn flash_mode(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "Flash Off",
    16 => "Autoflash",
    17 => "Fill-flash",
    18 => "Slow Sync",
    19 => "Rear Sync",
    20 => "Wireless",
    _ => return None,
  })
}

fn long_exposure_nr(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "Off",
    16 => "On",
    _ => return None,
  })
}

fn high_iso_nr(v: u8) -> Option<&'static str> {
  Some(match v {
    16 => "Low",
    17 => "High",
    19 => "Auto",
    _ => return None,
  })
}

/// `FocusMode` (MoreSettings 0x13) PrintConv (`Sony.pm:3652-3658`).
fn focus_mode_morsettings(v: u8) -> Option<&'static str> {
  Some(match v {
    17 => "AF-S",
    18 => "AF-C",
    19 => "AF-A",
    32 => "Manual",
    48 => "DMF",
    _ => return None,
  })
}

fn multi_frame_nr(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "n/a",
    1 => "Off",
    16 => "On",
    255 => "None",
    _ => return None,
  })
}

fn hdr_setting(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "Off",
    16 => "On (Auto)",
    17 => "On (Manual)",
    _ => return None,
  })
}

fn hdr_level(v: u8) -> Option<&'static str> {
  Some(match v {
    33 => "1 EV",
    34 => "1.5 EV",
    35 => "2 EV",
    36 => "2.5 EV",
    37 => "3 EV",
    38 => "3.5 EV",
    39 => "4 EV",
    40 => "5 EV",
    41 => "6 EV",
    _ => return None,
  })
}

fn viewing_mode(v: u8) -> Option<&'static str> {
  Some(match v {
    16 => "ViewFinder",
    33 => "Focus Check Live View",
    34 => "Quick AF Live View",
    _ => return None,
  })
}

fn face_detection(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "Off",
    16 => "On",
    _ => return None,
  })
}

fn live_view_af_method(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "n/a",
    1 => "Phase-detect AF",
    2 => "Contrast AF",
    _ => return None,
  })
}

fn orientation2(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "Horizontal (normal)",
    2 => "Rotate 180",
    6 => "Rotate 90 CW",
    8 => "Rotate 270 CW",
    _ => return None,
  })
}

fn flash_action(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Did not fire",
    1 => "Fired",
    _ => return None,
  })
}

fn focus_mode2(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "AF",
    1 => "MF",
    _ => return None,
  })
}

/// `FlashActionExternal` (MoreSettings 0x7c) PrintConv (`Sony.pm:3984-3989`).
fn flash_action_external(v: u8) -> Option<&'static str> {
  Some(match v {
    136 => "Did not fire",
    167 => "Fired",
    182 => "Fired, HSS",
    _ => return None,
  })
}

/// `FlashStatus` (MoreSettings 0x86) PrintConv (`Sony.pm:4000-4005`).
fn flash_status(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "None",
    1 => "Built-in",
    2 => "External",
    _ => return None,
  })
}

// ---- push helpers ----

fn push_hash(
  buf: &[u8],
  off: usize,
  name: &'static str,
  hit: impl Fn(u8) -> Option<&'static str>,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  if let Some(&raw) = buf.get(off) {
    out.push(SubEmission {
      priority: 1,
      name,
      value: super::hash_print_value(raw, hit(raw), print_conv),
    });
  }
}

fn push_hash_hex(
  buf: &[u8],
  off: usize,
  name: &'static str,
  hit: impl Fn(u32) -> Option<&'static str>,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  if let Some(&raw) = buf.get(off) {
    out.push(SubEmission {
      priority: 1,
      name,
      value: hash_hex_value(u32::from(raw), hit(u32::from(raw)), print_conv),
    });
  }
}

fn push_plain(buf: &[u8], off: usize, name: &'static str, out: &mut Vec<SubEmission>) {
  if let Some(&raw) = buf.get(off) {
    out.push(SubEmission {
      priority: 1,
      name,
      value: TagValue::I64(i64::from(raw)),
    });
  }
}

fn push_signed(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  if let Some(&raw) = buf.get(off) {
    out.push(SubEmission {
      priority: 1,
      name,
      value: signed_setting_value(raw as i8, print_conv),
    });
  }
}

fn push_exposure_comp(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  if let Some(&raw) = buf.get(off) {
    out.push(SubEmission {
      priority: 1,
      name,
      value: exposure_comp_value(raw, print_conv),
    });
  }
}

fn push_exposure_comp2(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  if let Some(raw) = read_i16(buf, off) {
    out.push(SubEmission {
      priority: 1,
      name,
      value: exposure_comp2_value(raw, print_conv),
    });
  }
}

fn push_color_temp(buf: &[u8], off: usize, out: &mut Vec<SubEmission>, print_conv: bool) {
  if let Some(&raw) = buf.get(off) {
    let k = u32::from(raw) * 100;
    out.push(SubEmission {
      priority: 1,
      name: "ColorTemperatureSetting",
      value: if print_conv {
        TagValue::Str(SmolStr::new(std::format!("{k} K")))
      } else {
        TagValue::I64(i64::from(k))
      },
    });
  }
}

/// `CustomWB_RBLevels` — int16uRev[2] (big-endian pair, space-joined). `-n` is
/// the same string (no ValueConv).
fn push_custom_wb_rb(buf: &[u8], off: usize, out: &mut Vec<SubEmission>) {
  if let Some(&[a0, a1, b0, b1]) = buf.get(off..off + 4) {
    let a = u16::from_be_bytes([a0, a1]);
    let b = u16::from_be_bytes([b0, b1]);
    out.push(SubEmission {
      priority: 1,
      name: "CustomWB_RBLevels",
      value: TagValue::Str(SmolStr::new(std::format!("{a} {b}"))),
    });
  }
}

/// ISO (`$val ? exp(($val/8-6)*ln2)*100 : $val`, `$val ? %.0f : "Auto"`).
fn push_iso(buf: &[u8], off: usize, out: &mut Vec<SubEmission>, print_conv: bool) {
  if let Some(&raw) = buf.get(off) {
    out.push(SubEmission {
      priority: 1,
      name: "ISO",
      value: iso_value(raw, print_conv),
    });
  }
}

fn iso_value(raw: u8, print_conv: bool) -> TagValue {
  let vc = if raw != 0 {
    (((f64::from(raw) / 8.0 - 6.0) * core::f64::consts::LN_2).exp()) * 100.0
  } else {
    0.0
  };
  if !print_conv {
    return if raw != 0 {
      crate::value::whole_f64_to_tag_value(vc)
    } else {
      TagValue::I64(0)
    };
  }
  if raw != 0 {
    TagValue::I64(libm_round(vc))
  } else {
    TagValue::Str("Auto".into())
  }
}

/// `sprintf("%.0f",$val)` — round-half-to-even is NOT Perl's behaviour; Perl's
/// `sprintf %.0f` rounds half away from zero. For the positive ISO values here
/// (always > 0) this is `floor(v + 0.5)`.
fn libm_round(v: f64) -> i64 {
  (v + 0.5).floor() as i64
}

/// FNumber (`2**(($val/8 - 1)/2)`, PrintFNumber).
fn push_fnumber(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  if let Some(&raw) = buf.get(off) {
    let fnum = 2f64.powf((f64::from(raw) / 8.0 - 1.0) / 2.0);
    out.push(SubEmission {
      priority: 1,
      name,
      value: if print_conv {
        TagValue::Str(print_fnumber(fnum).into())
      } else {
        crate::value::whole_f64_to_tag_value(fnum)
      },
    });
  }
}

/// ExposureTime (`$val ? 2**(6 - $val/8) : 0`, `$val ? PrintExposureTime : "Bulb"`).
fn push_exposure_time(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  if let Some(&raw) = buf.get(off) {
    let secs = if raw != 0 {
      2f64.powf(6.0 - f64::from(raw) / 8.0)
    } else {
      0.0
    };
    out.push(SubEmission {
      priority: 1,
      name,
      value: if print_conv {
        if raw != 0 {
          TagValue::Str(print_exposure_time(secs).into())
        } else {
          TagValue::Str("Bulb".into())
        }
      } else {
        crate::value::whole_f64_to_tag_value(secs)
      },
    });
  }
}

/// FocalLength2 (`10 * 2**(($val-28)/16)`, `sprintf("%.1f mm",$val)`).
fn push_focal_length2(buf: &[u8], off: usize, out: &mut Vec<SubEmission>, print_conv: bool) {
  if let Some(&raw) = buf.get(off) {
    let mm = 10.0 * 2f64.powf((f64::from(raw) - 28.0) / 16.0);
    out.push(SubEmission {
      priority: 1,
      name: "FocalLength2",
      value: if print_conv {
        TagValue::Str(SmolStr::new(std::format!("{mm:.1} mm")))
      } else {
        crate::value::whole_f64_to_tag_value(mm)
      },
    });
  }
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is relaxed for the test
// module, which indexes fixed-layout byte buffers directly (an out-of-range
// index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
#[path = "moreinfo_tests.rs"]
mod tests;
