// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Canon `ColorData` raw-color-processing sub-tables (`Canon.pm:7436-8976`).
//!
//! The `%Canon::Main` tag `0x4001` (`Canon.pm:1973-2048`) is a COUNT-selected
//! list of `Canon::ColorData<N>` SubDirectories — the `$count` (number of
//! `int16u` words) keys the variant. This module ports every defined variant,
//! `ColorData1..12`; the trailing `ColorDataUnknown` fallback is deferred (an
//! unmatched count yields nothing).
//!
//! Each table is `FORMAT => 'int16s'`, `FIRST_ENTRY => 0`, so a tag at word
//! position `p` is at byte offset `2 * p`. The shared shape is a run of
//! `WB_RGGBLevels<X>` (`int16s[4]`) + `ColorTemp<X>` (`int16s`) pairs followed
//! by black-/white-level leaves; the interleaved `*Unknown*` pairs and the
//! `ColorCalib` (`Unknown => 1`) SubDirectories are skipped. Several variants
//! gate later leaves on `$$self{ColorDataVersion}` (word `0x00`). The
//! `RawMeasuredRGGB`/`MeasuredRGGBData` `int32u[4]` leaves apply `SwapWords`
//! (`Canon.pm:10311` — swap the two 16-bit halves of each word). `ColorData5`
//! is the outlier: its WB pairs live in a nested `ColorCoefs`/`ColorCoefs2`
//! block at word `0x47` (`Canon.pm:7775-7884`; the `-4` variant uses an
//! 8-word stride with the temperature at `+7`).
//!
//! D8: pure decoder (no public struct fields); returns the `(Name, TagValue)`
//! emission pairs the dispatch site wraps in the `Canon` family-1 group.

#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::ByteOrder;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::string::String;
use std::vec::Vec;

/// Decode the `Canon::ColorData` block (`Canon.pm:1973-2048`), dispatching on
/// the `int16u` word count (`data.len() / 2`) to the matching `ColorData<N>`
/// variant. A count outside the ported variants yields nothing (the
/// `ColorDataUnknown` fallback is deferred).
#[must_use]
pub fn parse(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let count = data.len() / 2;
  if count == 582 {
    color_data_1(data, order)
  } else if count == 653 {
    color_data_2(data, order)
  } else if count == 796 {
    color_data_3(data, order, print_conv)
  } else if matches!(
    count,
    692 | 674 | 702 | 1227 | 1250 | 1251 | 1337 | 1338 | 1346
  ) {
    color_data_4(data, order, print_conv)
  } else if matches!(count, 1273 | 1275) {
    color_data_6(data, order, print_conv)
  } else if matches!(count, 1312 | 1313 | 1316 | 1506) {
    color_data_7(data, order, print_conv)
  } else if matches!(count, 1560 | 1592 | 1353 | 1602) {
    color_data_8(data, order, print_conv)
  } else if matches!(count, 1816 | 1820 | 1824) {
    color_data_9(data, order, print_conv)
  } else {
    Vec::new()
  }
}

/// `%Canon::ColorData9` (`Canon.pm:8186-8330`, `$count` in `1816|1820|1824`) —
/// EOS M50 / R / RP / 250D / 90D … The WB_RGGBLevels*/ColorTemp* pairs are
/// inline at non-contiguous word offsets (interleaved with `Unknown` pairs);
/// the per-channel black + normal/specular white + linearity-margin levels are
/// far down the block. `FORMAT => 'int16s'`, `FIRST_ENTRY => 0`. The CanonEOSR
/// CTMD (type-8) carries this variant (`ColorDataVersion == 17`).
fn color_data_9(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  // 0x00 ColorDataVersion (DataMember + PrintConv).
  if let Some(v) = read_i16(data, 0, order) {
    out.push((
      "ColorDataVersion".into(),
      if print_conv {
        let label = match v {
          16 => Some("16 (M50)"),
          17 => Some("17 (R)"),
          18 => Some("18 (RP/250D)"),
          19 => Some("19 (90D/850D/M6mkII/M200)"),
          _ => None,
        };
        match label {
          Some(l) => TagValue::Str(SmolStr::new_static(l)),
          None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
        }
      } else {
        TagValue::I64(v)
      },
    ));
  }
  // WB_RGGBLevels<X> (int16s[4]) + ColorTemp<X> (int16s) pairs (`Canon.pm`
  // 0x47..0xaa, skipping the `Unknown` 0x56..0x87 / 0xab.. runs).
  const WB_PAIRS_9: &[(usize, &str, &str)] = &[
    (0x47, "WB_RGGBLevelsAsShot", "ColorTempAsShot"),
    (0x4c, "WB_RGGBLevelsAuto", "ColorTempAuto"),
    (0x51, "WB_RGGBLevelsMeasured", "ColorTempMeasured"),
    (0x88, "WB_RGGBLevelsDaylight", "ColorTempDaylight"),
    (0x8d, "WB_RGGBLevelsShade", "ColorTempShade"),
    (0x92, "WB_RGGBLevelsCloudy", "ColorTempCloudy"),
    (0x97, "WB_RGGBLevelsTungsten", "ColorTempTungsten"),
    (0x9c, "WB_RGGBLevelsFluorescent", "ColorTempFluorescent"),
    (0xa1, "WB_RGGBLevelsKelvin", "ColorTempKelvin"),
    (0xa6, "WB_RGGBLevelsFlash", "ColorTempFlash"),
  ];
  push_wb_pairs(&mut out, data, order, WB_PAIRS_9);
  // 0x149 PerChannelBlackLevel (int16u[4]).
  push_u16_quad(&mut out, data, order, 0x149, "PerChannelBlackLevel");
  // 0x31c NormalWhiteLevel (int16u, RawConv `$val || undef` ⇒ drop a zero).
  if let Some(v) = read_u16(data, 0x31c, order)
    && v != 0
  {
    out.push(("NormalWhiteLevel".into(), TagValue::I64(v)));
  }
  // 0x31d SpecularWhiteLevel (int16u).
  if let Some(v) = read_u16(data, 0x31d, order) {
    out.push(("SpecularWhiteLevel".into(), TagValue::I64(v)));
  }
  // 0x31e LinearityUpperMargin (int16u).
  if let Some(v) = read_u16(data, 0x31e, order) {
    out.push(("LinearityUpperMargin".into(), TagValue::I64(v)));
  }
  out
}

/// `%Canon::ColorData3` (`Canon.pm:7557-7646`).
fn color_data_3(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  // 0x00 ColorDataVersion (PrintConv { 1 => '1 (1DmkIIN/5D/30D/400D)' }).
  if let Some(v) = read_i16(data, 0, order) {
    out.push((
      "ColorDataVersion".into(),
      if print_conv {
        match v {
          1 => TagValue::Str(SmolStr::new_static("1 (1DmkIIN/5D/30D/400D)")),
          n => TagValue::Str(SmolStr::from(std::format!("Unknown ({n})"))),
        }
      } else {
        TagValue::I64(v)
      },
    ));
  }
  // WB_RGGBLevels<X> (int16s[4]) + ColorTemp<X> (int16s) pairs (Canon.pm:7574-7602).
  const WB_PAIRS_3: &[(usize, &str, &str)] = &[
    (0x3f, "WB_RGGBLevelsAsShot", "ColorTempAsShot"),
    (0x44, "WB_RGGBLevelsAuto", "ColorTempAuto"),
    (0x49, "WB_RGGBLevelsMeasured", "ColorTempMeasured"),
    (0x4e, "WB_RGGBLevelsDaylight", "ColorTempDaylight"),
    (0x53, "WB_RGGBLevelsShade", "ColorTempShade"),
    (0x58, "WB_RGGBLevelsCloudy", "ColorTempCloudy"),
    (0x5d, "WB_RGGBLevelsTungsten", "ColorTempTungsten"),
    (0x62, "WB_RGGBLevelsFluorescent", "ColorTempFluorescent"),
    (0x67, "WB_RGGBLevelsKelvin", "ColorTempKelvin"),
    (0x6c, "WB_RGGBLevelsFlash", "ColorTempFlash"),
    (0x71, "WB_RGGBLevelsPC1", "ColorTempPC1"),
    (0x76, "WB_RGGBLevelsPC2", "ColorTempPC2"),
    (0x7b, "WB_RGGBLevelsPC3", "ColorTempPC3"),
    (0x80, "WB_RGGBLevelsCustom", "ColorTempCustom"),
  ];
  push_wb_pairs(&mut out, data, order, WB_PAIRS_3);
  // 0xc4 PerChannelBlackLevel (int16u[4]).
  push_u16_quad(&mut out, data, order, 0xc4, "PerChannelBlackLevel");
  // 0x248 FlashOutput, 0x249 FlashBatteryLevel, 0x24a ColorTempFlashData.
  push_flash_output(&mut out, data, order, 0x248, print_conv);
  push_flash_battery(&mut out, data, order, 0x249, print_conv);
  push_color_temp_flash_data(&mut out, data, order, 0x24a);
  // 0x287 MeasuredRGGBData (int32u[4], SwapWords).
  push_swapped_u32_quad(&mut out, data, order, 0x287, "MeasuredRGGBData");
  out
}

/// `%Canon::ColorData4` (`Canon.pm:7648-7772`) + its nested `ColorCoefs`
/// (`Canon.pm:7774-7830`, anchored at word `0x3f`).
fn color_data_4(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  // 0x00 ColorDataVersion (DataMember + PrintConv).
  let version = read_i16(data, 0, order);
  if let Some(v) = version {
    out.push((
      "ColorDataVersion".into(),
      if print_conv {
        let label = match v {
          2 => Some("2 (1DmkIII)"),
          3 => Some("3 (40D)"),
          4 => Some("4 (1DSmkIII)"),
          5 => Some("5 (450D/1000D)"),
          6 => Some("6 (50D/5DmkII)"),
          7 => Some("7 (500D/550D/7D/1DmkIV)"),
          9 => Some("9 (60D/1100D)"),
          _ => None,
        };
        match label {
          Some(l) => TagValue::Str(SmolStr::new_static(l)),
          None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
        }
      } else {
        TagValue::I64(v)
      },
    ));
  }
  // ColorCoefs nested block at word 0x3f — WB_RGGBLevels<X>/ColorTemp<X> at
  // absolute word offset `0x3f + relative` (Canon.pm:7774-7830, the NAMED
  // entries only; the `Unknown` ones are skipped).
  const WB_PAIRS_4: &[(usize, &str, &str)] = &[
    (0x3f, "WB_RGGBLevelsAsShot", "ColorTempAsShot"),
    (0x44, "WB_RGGBLevelsAuto", "ColorTempAuto"),
    (0x49, "WB_RGGBLevelsMeasured", "ColorTempMeasured"),
    (0x53, "WB_RGGBLevelsDaylight", "ColorTempDaylight"),
    (0x58, "WB_RGGBLevelsShade", "ColorTempShade"),
    (0x5d, "WB_RGGBLevelsCloudy", "ColorTempCloudy"),
    (0x62, "WB_RGGBLevelsTungsten", "ColorTempTungsten"),
    (0x67, "WB_RGGBLevelsFluorescent", "ColorTempFluorescent"),
    (0x6c, "WB_RGGBLevelsKelvin", "ColorTempKelvin"),
    (0x71, "WB_RGGBLevelsFlash", "ColorTempFlash"),
  ];
  push_wb_pairs(&mut out, data, order, WB_PAIRS_4);
  // 0x0e7 AverageBlackLevel (int16u[4]).
  push_u16_quad(&mut out, data, order, 0x0e7, "AverageBlackLevel");
  // 0x26b FlashOutput, 0x26c FlashBatteryLevel.
  push_flash_output(&mut out, data, order, 0x26b, print_conv);
  push_flash_battery(&mut out, data, order, 0x26c, print_conv);
  // 0x280 RawMeasuredRGGB (int32u[4], SwapWords).
  push_swapped_u32_quad(&mut out, data, order, 0x280, "RawMeasuredRGGB");
  // Version-conditional white-level leaves (Canon.pm:7710-7771).
  let ver = version.unwrap_or(0);
  let v45 = ver == 4 || ver == 5;
  let v67 = ver == 6 || ver == 7;
  let v9 = ver == 9;
  if v45 {
    push_u16_quad(&mut out, data, order, 0x2b4, "PerChannelBlackLevel");
    push_white_level(&mut out, data, order, 0x2b8, "NormalWhiteLevel", true);
    push_white_level(&mut out, data, order, 0x2b9, "SpecularWhiteLevel", false);
    push_white_level(&mut out, data, order, 0x2ba, "LinearityUpperMargin", false);
  }
  if v67 {
    push_u16_quad(&mut out, data, order, 0x2cb, "PerChannelBlackLevel");
    push_white_level(&mut out, data, order, 0x2cf, "NormalWhiteLevel", true);
    push_white_level(&mut out, data, order, 0x2d0, "SpecularWhiteLevel", false);
    push_white_level(&mut out, data, order, 0x2d1, "LinearityUpperMargin", false);
  }
  if v9 {
    push_u16_quad(&mut out, data, order, 0x2cf, "PerChannelBlackLevel");
    push_white_level(&mut out, data, order, 0x2d3, "NormalWhiteLevel", true);
    push_white_level(&mut out, data, order, 0x2d4, "SpecularWhiteLevel", false);
    push_white_level(&mut out, data, order, 0x2d5, "LinearityUpperMargin", false);
  }
  out
}

/// `%Canon::ColorData1` (`Canon.pm:7437-7473`, `$count == 582`) — EOS 20D / 350D.
/// There is no `ColorDataVersion` (word `0x00` is the record byte-size); the ten
/// `WB_RGGBLevels<X>`/`ColorTemp<X>` pairs run contiguously from word `0x19`.
/// `ColorCalib` (`0x4b`, `Unknown`) is skipped.
fn color_data_1(data: &[u8], order: ByteOrder) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  const WB_PAIRS_1: &[(usize, &str, &str)] = &[
    (0x19, "WB_RGGBLevelsAsShot", "ColorTempAsShot"),
    (0x1e, "WB_RGGBLevelsAuto", "ColorTempAuto"),
    (0x23, "WB_RGGBLevelsDaylight", "ColorTempDaylight"),
    (0x28, "WB_RGGBLevelsShade", "ColorTempShade"),
    (0x2d, "WB_RGGBLevelsCloudy", "ColorTempCloudy"),
    (0x32, "WB_RGGBLevelsTungsten", "ColorTempTungsten"),
    (0x37, "WB_RGGBLevelsFluorescent", "ColorTempFluorescent"),
    (0x3c, "WB_RGGBLevelsFlash", "ColorTempFlash"),
    (0x41, "WB_RGGBLevelsCustom1", "ColorTempCustom1"),
    (0x46, "WB_RGGBLevelsCustom2", "ColorTempCustom2"),
  ];
  push_wb_pairs(&mut out, data, order, WB_PAIRS_1);
  out
}

/// `%Canon::ColorData2` (`Canon.pm:7476-7555`, `$count == 653`) — 1DmkII /
/// 1DSmkII. The named pairs are `Auto` (`0x18`), `AsShot` (`0x22`), then the
/// daylight…flash set with `Kelvin`, plus `PC1..PC3`; the interleaved
/// `*Unknown*` pairs are skipped. `RawMeasuredRGGB` (`0x26a`, `int32u[4]`,
/// `SwapWords`) trails; `ColorCalib` (`0xa4`, `Unknown`) is skipped.
fn color_data_2(data: &[u8], order: ByteOrder) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  const WB_PAIRS_2: &[(usize, &str, &str)] = &[
    (0x18, "WB_RGGBLevelsAuto", "ColorTempAuto"),
    (0x22, "WB_RGGBLevelsAsShot", "ColorTempAsShot"),
    (0x27, "WB_RGGBLevelsDaylight", "ColorTempDaylight"),
    (0x2c, "WB_RGGBLevelsShade", "ColorTempShade"),
    (0x31, "WB_RGGBLevelsCloudy", "ColorTempCloudy"),
    (0x36, "WB_RGGBLevelsTungsten", "ColorTempTungsten"),
    (0x3b, "WB_RGGBLevelsFluorescent", "ColorTempFluorescent"),
    (0x40, "WB_RGGBLevelsKelvin", "ColorTempKelvin"),
    (0x45, "WB_RGGBLevelsFlash", "ColorTempFlash"),
    (0x90, "WB_RGGBLevelsPC1", "ColorTempPC1"),
    (0x95, "WB_RGGBLevelsPC2", "ColorTempPC2"),
    (0x9a, "WB_RGGBLevelsPC3", "ColorTempPC3"),
  ];
  push_wb_pairs(&mut out, data, order, WB_PAIRS_2);
  push_swapped_u32_quad(&mut out, data, order, 0x26a, "RawMeasuredRGGB");
  out
}

/// `%Canon::ColorData6` (`Canon.pm:8016-8099`, `$count` in `1273|1275`) — EOS
/// 600D / 1200D. Ten named WB pairs (the `Measured` slot is present; the
/// `*Unknown*` runs are skipped) then `AverageBlackLevel`, `RawMeasuredRGGB`
/// (`SwapWords`), `PerChannelBlackLevel` and the three white-level leaves.
fn color_data_6(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  color_data_version(
    &mut out,
    data,
    order,
    print_conv,
    &[(10, "10 (600D/1200D)")],
  );
  const WB_PAIRS_6: &[(usize, &str, &str)] = &[
    (0x3f, "WB_RGGBLevelsAsShot", "ColorTempAsShot"),
    (0x44, "WB_RGGBLevelsAuto", "ColorTempAuto"),
    (0x49, "WB_RGGBLevelsMeasured", "ColorTempMeasured"),
    (0x67, "WB_RGGBLevelsDaylight", "ColorTempDaylight"),
    (0x6c, "WB_RGGBLevelsShade", "ColorTempShade"),
    (0x71, "WB_RGGBLevelsCloudy", "ColorTempCloudy"),
    (0x76, "WB_RGGBLevelsTungsten", "ColorTempTungsten"),
    (0x7b, "WB_RGGBLevelsFluorescent", "ColorTempFluorescent"),
    (0x80, "WB_RGGBLevelsKelvin", "ColorTempKelvin"),
    (0x85, "WB_RGGBLevelsFlash", "ColorTempFlash"),
  ];
  push_wb_pairs(&mut out, data, order, WB_PAIRS_6);
  push_u16_quad(&mut out, data, order, 0x0fb, "AverageBlackLevel");
  push_swapped_u32_quad(&mut out, data, order, 0x194, "RawMeasuredRGGB");
  push_u16_quad(&mut out, data, order, 0x1df, "PerChannelBlackLevel");
  push_white_level(&mut out, data, order, 0x1e3, "NormalWhiteLevel", true);
  push_white_level(&mut out, data, order, 0x1e4, "SpecularWhiteLevel", false);
  push_white_level(&mut out, data, order, 0x1e5, "LinearityUpperMargin", false);
  out
}

/// `%Canon::ColorData7` (`Canon.pm:8102-8262`, `$count` in `1312|1313|1316|1506`)
/// — 1DX / 5DmkIII / 6D / 7DmkII / 70D / 100D / 650D / 700D / M / M2 …. Ten named
/// WB pairs, `AverageBlackLevel`, `FlashOutput`/`FlashBatteryLevel` (same convs
/// as ColorData3), then a `ColorDataVersion`-keyed (10 vs 11) block of
/// `RawMeasuredRGGB` (`SwapWords`) + `PerChannelBlackLevel` + the white levels.
fn color_data_7(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let version = color_data_version(
    &mut out,
    data,
    order,
    print_conv,
    &[
      (10, "10 (1DX/5DmkIII/6D/70D/100D/650D/700D/M/M2)"),
      (11, "11 (7DmkII/750D/760D/8000D)"),
    ],
  );
  const WB_PAIRS_7: &[(usize, &str, &str)] = &[
    (0x3f, "WB_RGGBLevelsAsShot", "ColorTempAsShot"),
    (0x44, "WB_RGGBLevelsAuto", "ColorTempAuto"),
    (0x49, "WB_RGGBLevelsMeasured", "ColorTempMeasured"),
    (0x80, "WB_RGGBLevelsDaylight", "ColorTempDaylight"),
    (0x85, "WB_RGGBLevelsShade", "ColorTempShade"),
    (0x8a, "WB_RGGBLevelsCloudy", "ColorTempCloudy"),
    (0x8f, "WB_RGGBLevelsTungsten", "ColorTempTungsten"),
    (0x94, "WB_RGGBLevelsFluorescent", "ColorTempFluorescent"),
    (0x99, "WB_RGGBLevelsKelvin", "ColorTempKelvin"),
    (0x9e, "WB_RGGBLevelsFlash", "ColorTempFlash"),
  ];
  push_wb_pairs(&mut out, data, order, WB_PAIRS_7);
  push_u16_quad(&mut out, data, order, 0x114, "AverageBlackLevel");
  push_flash_output(&mut out, data, order, 0x198, print_conv);
  push_flash_battery(&mut out, data, order, 0x199, print_conv);
  match version {
    Some(10) => {
      push_swapped_u32_quad(&mut out, data, order, 0x1ad, "RawMeasuredRGGB");
      push_u16_quad(&mut out, data, order, 0x1f8, "PerChannelBlackLevel");
      push_white_level(&mut out, data, order, 0x1fc, "NormalWhiteLevel", true);
      push_white_level(&mut out, data, order, 0x1fd, "SpecularWhiteLevel", false);
      push_white_level(&mut out, data, order, 0x1fe, "LinearityUpperMargin", false);
    }
    Some(11) => {
      push_swapped_u32_quad(&mut out, data, order, 0x26b, "RawMeasuredRGGB");
      push_u16_quad(&mut out, data, order, 0x2d8, "PerChannelBlackLevel");
      push_white_level(&mut out, data, order, 0x2dc, "NormalWhiteLevel", true);
      push_white_level(&mut out, data, order, 0x2dd, "SpecularWhiteLevel", false);
      push_white_level(&mut out, data, order, 0x2de, "LinearityUpperMargin", false);
    }
    _ => {}
  }
  out
}

/// `%Canon::ColorData8` (`Canon.pm:8265-8426`, `$count` in `1560|1592|1353|1602`)
/// — 1DXmkII / 5DS / 5DSR / 5DmkIV / 80D / 1300D …. Ten named WB pairs and
/// `AverageBlackLevel`, then a `ColorDataVersion`-keyed white-level block: `== 14`
/// (1300D) at `0x22c` vs `< 14 || == 15` at `0x30a`. No `RawMeasuredRGGB`/flash.
fn color_data_8(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let version = color_data_version(
    &mut out,
    data,
    order,
    print_conv,
    &[
      (12, "12 (1DXmkII/5DS/5DSR)"),
      (13, "13 (80D/5DmkIV)"),
      (14, "14 (1300D/2000D/4000D)"),
      (15, "15 (6DmkII/77D/200D/800D,9000D)"),
    ],
  );
  const WB_PAIRS_8: &[(usize, &str, &str)] = &[
    (0x3f, "WB_RGGBLevelsAsShot", "ColorTempAsShot"),
    (0x44, "WB_RGGBLevelsAuto", "ColorTempAuto"),
    (0x49, "WB_RGGBLevelsMeasured", "ColorTempMeasured"),
    (0x85, "WB_RGGBLevelsDaylight", "ColorTempDaylight"),
    (0x8a, "WB_RGGBLevelsShade", "ColorTempShade"),
    (0x8f, "WB_RGGBLevelsCloudy", "ColorTempCloudy"),
    (0x94, "WB_RGGBLevelsTungsten", "ColorTempTungsten"),
    (0x99, "WB_RGGBLevelsFluorescent", "ColorTempFluorescent"),
    (0x9e, "WB_RGGBLevelsKelvin", "ColorTempKelvin"),
    (0xa3, "WB_RGGBLevelsFlash", "ColorTempFlash"),
  ];
  push_wb_pairs(&mut out, data, order, WB_PAIRS_8);
  push_u16_quad(&mut out, data, order, 0x146, "AverageBlackLevel");
  let ver = version.unwrap_or(0);
  if ver == 14 {
    push_u16_quad(&mut out, data, order, 0x22c, "PerChannelBlackLevel");
    push_white_level(&mut out, data, order, 0x230, "NormalWhiteLevel", true);
    push_white_level(&mut out, data, order, 0x231, "SpecularWhiteLevel", false);
    push_white_level(&mut out, data, order, 0x232, "LinearityUpperMargin", false);
  }
  if ver < 14 || ver == 15 {
    push_u16_quad(&mut out, data, order, 0x30a, "PerChannelBlackLevel");
    push_white_level(&mut out, data, order, 0x30e, "NormalWhiteLevel", true);
    push_white_level(&mut out, data, order, 0x30f, "SpecularWhiteLevel", false);
    push_white_level(&mut out, data, order, 0x310, "LinearityUpperMargin", false);
  }
  out
}

/// Emit `ColorDataVersion` (word `0x00`, `int16s`) and return the raw version
/// for the variants whose later leaves are `$$self{ColorDataVersion}`-keyed.
/// With `print_conv`, a `labels` hit renders as the descriptive string and a
/// miss as ExifTool's default `"Unknown (N)"`.
fn color_data_version(
  out: &mut Vec<(SmolStr, TagValue)>,
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  labels: &[(i64, &'static str)],
) -> Option<i64> {
  let v = read_i16(data, 0, order)?;
  let value = if print_conv {
    match labels.iter().find(|(k, _)| *k == v) {
      Some((_, label)) => TagValue::Str(SmolStr::new_static(label)),
      None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
    }
  } else {
    TagValue::I64(v)
  };
  out.push(("ColorDataVersion".into(), value));
  Some(v)
}

/// Push the `WB_RGGBLevels<X>` (`int16s[4]`) + `ColorTemp<X>` (`int16s`) pairs.
fn push_wb_pairs(
  out: &mut Vec<(SmolStr, TagValue)>,
  data: &[u8],
  order: ByteOrder,
  pairs: &[(usize, &'static str, &'static str)],
) {
  for &(off, wb_name, temp_name) in pairs {
    if let Some(quad) = read_i16x4(data, off, order) {
      out.push((
        SmolStr::new_static(wb_name),
        TagValue::Str(SmolStr::from(join_i64(&quad))),
      ));
    }
    if let Some(t) = read_i16(data, off + 4, order) {
      out.push((SmolStr::new_static(temp_name), TagValue::I64(t)));
    }
  }
}

/// Push an `int16u[4]` quad (space-joined) at word `off` if in range.
fn push_u16_quad(
  out: &mut Vec<(SmolStr, TagValue)>,
  data: &[u8],
  order: ByteOrder,
  off: usize,
  name: &'static str,
) {
  if let Some(quad) = read_u16x4(data, off, order) {
    out.push((
      SmolStr::new_static(name),
      TagValue::Str(SmolStr::from(join_i64(&quad))),
    ));
  }
}

/// Push an `int16u` white-level leaf; `raw_conv_drop_zero` applies the
/// `RawConv => '$val || undef'` (skip a zero — `NormalWhiteLevel`).
fn push_white_level(
  out: &mut Vec<(SmolStr, TagValue)>,
  data: &[u8],
  order: ByteOrder,
  off: usize,
  name: &'static str,
  raw_conv_drop_zero: bool,
) {
  if let Some(v) = read_u16(data, off, order)
    && !(raw_conv_drop_zero && v == 0)
  {
    out.push((SmolStr::new_static(name), TagValue::I64(v)));
  }
}

/// `FlashOutput` (`Canon.pm:7615-7621`/`:7689-7695`). ValueConv
/// `$val >= 255 ? 255 : exp(($val-200)/16*log(2))`; PrintConv
/// `$val == 255 ? "Strobe or Misfire" : sprintf("%.0f%%", $val*100)`.
fn push_flash_output(
  out: &mut Vec<(SmolStr, TagValue)>,
  data: &[u8],
  order: ByteOrder,
  off: usize,
  print_conv: bool,
) {
  if let Some(raw) = read_i16(data, off, order) {
    let vc = if raw >= 255 {
      255.0
    } else {
      ((raw as f64 - 200.0) / 16.0 * std::f64::consts::LN_2).exp()
    };
    let value = if print_conv {
      if vc == 255.0 {
        TagValue::Str(SmolStr::new_static("Strobe or Misfire"))
      } else {
        TagValue::Str(SmolStr::from(std::format!("{:.0}%", vc * 100.0)))
      }
    } else {
      num_value(vc)
    };
    out.push(("FlashOutput".into(), value));
  }
}

/// `FlashBatteryLevel` (`Canon.pm:7622-7628`/`:7696-7701`). No ValueConv;
/// PrintConv `$val ? sprintf("%.2fV", $val*5/186) : "n/a"`.
fn push_flash_battery(
  out: &mut Vec<(SmolStr, TagValue)>,
  data: &[u8],
  order: ByteOrder,
  off: usize,
  print_conv: bool,
) {
  if let Some(raw) = read_i16(data, off, order) {
    let value = if print_conv {
      if raw != 0 {
        TagValue::Str(SmolStr::from(std::format!(
          "{:.2}V",
          raw as f64 * 5.0 / 186.0
        )))
      } else {
        TagValue::Str(SmolStr::new_static("n/a"))
      }
    } else {
      TagValue::I64(raw)
    };
    out.push(("FlashBatteryLevel".into(), value));
  }
}

/// `ColorTempFlashData` (`Canon.pm:7629-7634`, ColorData3 only). RawConv
/// `($val < 2000 or $val > 12000) ? undef : $val` (no PrintConv).
fn push_color_temp_flash_data(
  out: &mut Vec<(SmolStr, TagValue)>,
  data: &[u8],
  order: ByteOrder,
  off: usize,
) {
  if let Some(v) = read_i16(data, off, order)
    && (2000..=12000).contains(&v)
  {
    out.push(("ColorTempFlashData".into(), TagValue::I64(v)));
  }
}

/// Push an `int32u[4]` leaf with `SwapWords` applied (`Canon.pm:10311`).
fn push_swapped_u32_quad(
  out: &mut Vec<(SmolStr, TagValue)>,
  data: &[u8],
  order: ByteOrder,
  off: usize,
  name: &'static str,
) {
  let mut quad = [0u32; 4];
  for (i, slot) in quad.iter_mut().enumerate() {
    match read_u32(data, off + i * 2, order) {
      // `SwapWords`: `(($_ >> 16) | ($_ << 16)) & 0xffffffff` — swap the two
      // 16-bit halves, i.e. a 16-bit rotate of the `u32` (`Canon.pm:10314`).
      Some(v) => *slot = v.rotate_left(16),
      None => return, // a missing word ⇒ ExifTool's ReadValue returns undef
    }
  }
  let joined = quad
    .iter()
    .map(|w| w.to_string())
    .collect::<Vec<_>>()
    .join(" ");
  out.push((
    SmolStr::new_static(name),
    TagValue::Str(SmolStr::from(joined)),
  ));
}

/// Read one signed 16-bit word at word `position` (byte offset `2*position`).
fn read_i16(data: &[u8], position: usize, order: ByteOrder) -> Option<i64> {
  let off = 2 * position;
  let arr: [u8; 2] = data.get(off..off + 2)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => i16::from_le_bytes(arr),
    ByteOrder::Big => i16::from_be_bytes(arr),
  } as i64)
}

/// Read one unsigned 16-bit word at word `position` (byte offset `2*position`).
fn read_u16(data: &[u8], position: usize, order: ByteOrder) -> Option<i64> {
  let off = 2 * position;
  let arr: [u8; 2] = data.get(off..off + 2)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u16::from_le_bytes(arr),
    ByteOrder::Big => u16::from_be_bytes(arr),
  } as i64)
}

/// Read one unsigned 32-bit word at word `position` (byte offset `2*position`,
/// `int16s`-table units) — the four bytes form the file-order `u32`.
fn read_u32(data: &[u8], position: usize, order: ByteOrder) -> Option<u32> {
  let off = 2 * position;
  let arr: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u32::from_le_bytes(arr),
    ByteOrder::Big => u32::from_be_bytes(arr),
  })
}

/// Read four consecutive signed 16-bit words at word `position`.
fn read_i16x4(data: &[u8], position: usize, order: ByteOrder) -> Option<[i64; 4]> {
  let mut quad = [0i64; 4];
  for (i, slot) in quad.iter_mut().enumerate() {
    *slot = read_i16(data, position + i, order)?;
  }
  Some(quad)
}

/// Read four consecutive unsigned 16-bit words at word `position`.
fn read_u16x4(data: &[u8], position: usize, order: ByteOrder) -> Option<[i64; 4]> {
  let mut quad = [0i64; 4];
  for (i, slot) in quad.iter_mut().enumerate() {
    *slot = read_u16(data, position + i, order)?;
  }
  Some(quad)
}

/// Render a four-element int array as ExifTool's default space-joined string.
fn join_i64(words: &[i64]) -> String {
  use std::fmt::Write;
  let mut s = String::new();
  for (i, w) in words.iter().enumerate() {
    if i != 0 {
      s.push(' ');
    }
    let _ = write!(s, "{w}");
  }
  s
}

/// ExifTool's whole-vs-fractional number formatting for a ValueConv float.
fn num_value(v: f64) -> TagValue {
  if v.fract() == 0.0 && v.is_finite() {
    TagValue::I64(v as i64)
  } else {
    TagValue::F64(v)
  }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  fn put_i16(buf: &mut [u8], word: usize, v: i16) {
    let b = v.to_le_bytes();
    buf[word * 2] = b[0];
    buf[word * 2 + 1] = b[1];
  }
  fn put_u16(buf: &mut [u8], word: usize, v: u16) {
    let b = v.to_le_bytes();
    buf[word * 2] = b[0];
    buf[word * 2 + 1] = b[1];
  }

  #[test]
  fn color_data_3_decodes_named_leaves() {
    let mut buf = vec![0u8; 796 * 2];
    put_i16(&mut buf, 0x00, 1); // ColorDataVersion
    for (i, v) in [2158i16, 1024, 1024, 1382].iter().enumerate() {
      put_i16(&mut buf, 0x3f + i, *v); // WB_RGGBLevelsAsShot
    }
    put_i16(&mut buf, 0x43, 5786); // ColorTempAsShot
    for (i, v) in [128u16, 128, 128, 128].iter().enumerate() {
      put_u16(&mut buf, 0xc4 + i, *v); // PerChannelBlackLevel
    }
    put_i16(&mut buf, 0x248, 0); // FlashOutput raw 0
    put_i16(&mut buf, 0x249, 0); // FlashBatteryLevel raw 0
    let em = parse(&buf, ByteOrder::Little, true);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(
      find("ColorDataVersion"),
      Some(TagValue::Str("1 (1DmkIIN/5D/30D/400D)".into()))
    );
    assert_eq!(
      find("WB_RGGBLevelsAsShot"),
      Some(TagValue::Str("2158 1024 1024 1382".into()))
    );
    assert_eq!(find("ColorTempAsShot"), Some(TagValue::I64(5786)));
    assert_eq!(
      find("PerChannelBlackLevel"),
      Some(TagValue::Str("128 128 128 128".into()))
    );
    assert_eq!(find("FlashOutput"), Some(TagValue::Str("0%".into())));
    assert_eq!(find("FlashBatteryLevel"), Some(TagValue::Str("n/a".into())));
    // `-n` ColorDataVersion is the bare int; FlashOutput is the ValueConv float.
    let emn = parse(&buf, ByteOrder::Little, false);
    let findn = |n: &str| emn.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(findn("ColorDataVersion"), Some(TagValue::I64(1)));
    assert!(matches!(findn("FlashOutput"), Some(TagValue::F64(_))));
  }

  #[test]
  fn color_data_4_version_7_white_levels() {
    let mut buf = vec![0u8; 1337 * 2];
    put_i16(&mut buf, 0x00, 7); // ColorDataVersion 7
    for (i, v) in [2166i16, 1024, 1024, 1524].iter().enumerate() {
      put_i16(&mut buf, 0x3f + i, *v); // WB_RGGBLevelsAsShot (ColorCoefs)
    }
    put_u16(&mut buf, 0x2cf, 16383); // NormalWhiteLevel (ver 6/7)
    put_u16(&mut buf, 0x2d0, 11222); // SpecularWhiteLevel
    put_u16(&mut buf, 0x2d1, 10000); // LinearityUpperMargin
    let em = parse(&buf, ByteOrder::Little, false);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("ColorDataVersion"), Some(TagValue::I64(7)));
    assert_eq!(
      find("WB_RGGBLevelsAsShot"),
      Some(TagValue::Str("2166 1024 1024 1524".into()))
    );
    assert_eq!(find("NormalWhiteLevel"), Some(TagValue::I64(16383)));
    assert_eq!(find("SpecularWhiteLevel"), Some(TagValue::I64(11222)));
    assert_eq!(find("LinearityUpperMargin"), Some(TagValue::I64(10000)));
  }

  #[test]
  fn swap_words_matches_oracle() {
    // MeasuredRGGBData raw word 0x33DD0000 ⇒ SwapWords ⇒ 0x000033DD = 13277.
    let mut buf = vec![0u8; 796 * 2];
    let raw: u32 = 0x33DD_0000;
    let b = raw.to_le_bytes();
    let base = 0x287 * 2;
    buf[base..base + 4].copy_from_slice(&b);
    let em = parse(&buf, ByteOrder::Little, false);
    let v = em
      .iter()
      .find(|(k, _)| k == "MeasuredRGGBData")
      .map(|(_, v)| v.clone());
    assert_eq!(v, Some(TagValue::Str("13277 0 0 0".into())));
  }

  fn put_u32(buf: &mut [u8], word: usize, v: u32) {
    let b = v.to_le_bytes();
    buf[word * 2..word * 2 + 4].copy_from_slice(&b);
  }
  fn find_in<'a>(em: &'a [(SmolStr, TagValue)], n: &str) -> Option<&'a TagValue> {
    em.iter().find(|(k, _)| k == n).map(|(_, v)| v)
  }

  #[test]
  fn color_data_1_wb_pairs_no_version() {
    let mut buf = vec![0u8; 582 * 2];
    for (i, v) in [2000i16, 1024, 1024, 1500].iter().enumerate() {
      put_i16(&mut buf, 0x19 + i, *v); // WB_RGGBLevelsAsShot
    }
    put_i16(&mut buf, 0x1d, 5200); // ColorTempAsShot
    for (i, v) in [2100i16, 1024, 1024, 1400].iter().enumerate() {
      put_i16(&mut buf, 0x46 + i, *v); // WB_RGGBLevelsCustom2
    }
    put_i16(&mut buf, 0x4a, 6000); // ColorTempCustom2
    let em = parse(&buf, ByteOrder::Little, true);
    assert_eq!(
      find_in(&em, "WB_RGGBLevelsAsShot"),
      Some(&TagValue::Str("2000 1024 1024 1500".into()))
    );
    assert_eq!(find_in(&em, "ColorTempAsShot"), Some(&TagValue::I64(5200)));
    assert_eq!(
      find_in(&em, "WB_RGGBLevelsCustom2"),
      Some(&TagValue::Str("2100 1024 1024 1400".into()))
    );
    assert_eq!(find_in(&em, "ColorTempCustom2"), Some(&TagValue::I64(6000)));
    // ColorData1 has no ColorDataVersion (word 0x00 is the record size).
    assert_eq!(find_in(&em, "ColorDataVersion"), None);
  }

  #[test]
  fn color_data_2_auto_first_and_raw_measured() {
    let mut buf = vec![0u8; 653 * 2];
    for (i, v) in [2048i16, 1024, 1024, 1600].iter().enumerate() {
      put_i16(&mut buf, 0x18 + i, *v); // WB_RGGBLevelsAuto (first named pair)
    }
    put_i16(&mut buf, 0x1c, 5000); // ColorTempAuto
    for (i, v) in [2222i16, 1024, 1024, 1333].iter().enumerate() {
      put_i16(&mut buf, 0x22 + i, *v); // WB_RGGBLevelsAsShot
    }
    put_i16(&mut buf, 0x26, 5600); // ColorTempAsShot
    put_u32(&mut buf, 0x26a, 0x1234_0000); // RawMeasuredRGGB (SwapWords ⇒ 0x1234)
    let em = parse(&buf, ByteOrder::Little, false);
    assert_eq!(
      find_in(&em, "WB_RGGBLevelsAuto"),
      Some(&TagValue::Str("2048 1024 1024 1600".into()))
    );
    assert_eq!(find_in(&em, "ColorTempAuto"), Some(&TagValue::I64(5000)));
    assert_eq!(
      find_in(&em, "WB_RGGBLevelsAsShot"),
      Some(&TagValue::Str("2222 1024 1024 1333".into()))
    );
    assert_eq!(
      find_in(&em, "RawMeasuredRGGB"),
      Some(&TagValue::Str("4660 0 0 0".into()))
    );
    // The interleaved Unknown pair at word 0x1d must not be emitted.
    assert_eq!(find_in(&em, "WB_RGGBLevelsUnknown"), None);
    assert_eq!(find_in(&em, "ColorDataVersion"), None);
  }

  #[test]
  fn color_data_6_version_and_white_levels() {
    let mut buf = vec![0u8; 1273 * 2];
    put_i16(&mut buf, 0x00, 10); // ColorDataVersion
    for (i, v) in [2100i16, 1024, 1024, 1500].iter().enumerate() {
      put_i16(&mut buf, 0x3f + i, *v); // WB_RGGBLevelsAsShot
    }
    put_i16(&mut buf, 0x43, 5500); // ColorTempAsShot
    put_u16(&mut buf, 0x1e3, 16383); // NormalWhiteLevel
    put_u16(&mut buf, 0x1e4, 13000); // SpecularWhiteLevel
    put_u16(&mut buf, 0x1e5, 12000); // LinearityUpperMargin
    let em = parse(&buf, ByteOrder::Little, true);
    assert_eq!(
      find_in(&em, "ColorDataVersion"),
      Some(&TagValue::Str("10 (600D/1200D)".into()))
    );
    assert_eq!(
      find_in(&em, "WB_RGGBLevelsAsShot"),
      Some(&TagValue::Str("2100 1024 1024 1500".into()))
    );
    assert_eq!(find_in(&em, "ColorTempAsShot"), Some(&TagValue::I64(5500)));
    assert_eq!(
      find_in(&em, "NormalWhiteLevel"),
      Some(&TagValue::I64(16383))
    );
    assert_eq!(
      find_in(&em, "SpecularWhiteLevel"),
      Some(&TagValue::I64(13000))
    );
    assert_eq!(
      find_in(&em, "LinearityUpperMargin"),
      Some(&TagValue::I64(12000))
    );
  }

  #[test]
  fn color_data_7_version_10_block_gates_off_v11() {
    let mut buf = vec![0u8; 1312 * 2];
    put_i16(&mut buf, 0x00, 10);
    for (i, v) in [2050i16, 1024, 1024, 1480].iter().enumerate() {
      put_i16(&mut buf, 0x3f + i, *v); // WB_RGGBLevelsAsShot
    }
    put_i16(&mut buf, 0x43, 5300);
    for (i, v) in [2222i16, 1024, 1024, 1444].iter().enumerate() {
      put_i16(&mut buf, 0x80 + i, *v); // WB_RGGBLevelsDaylight (note the 0x4e..0x7f gap)
    }
    put_i16(&mut buf, 0x84, 5200); // ColorTempDaylight
    put_i16(&mut buf, 0x199, 0); // FlashBatteryLevel raw 0 ⇒ "n/a"
    put_u16(&mut buf, 0x1fc, 15000); // NormalWhiteLevel (ver 10)
    put_u16(&mut buf, 0x1fe, 13000); // LinearityUpperMargin (ver 10)
    put_u16(&mut buf, 0x2dc, 9999); // ver-11 NormalWhiteLevel sentinel (must be ignored)
    let em = parse(&buf, ByteOrder::Little, true);
    assert_eq!(
      find_in(&em, "ColorDataVersion"),
      Some(&TagValue::Str(
        "10 (1DX/5DmkIII/6D/70D/100D/650D/700D/M/M2)".into()
      ))
    );
    assert_eq!(
      find_in(&em, "WB_RGGBLevelsAsShot"),
      Some(&TagValue::Str("2050 1024 1024 1480".into()))
    );
    assert_eq!(
      find_in(&em, "WB_RGGBLevelsDaylight"),
      Some(&TagValue::Str("2222 1024 1024 1444".into()))
    );
    assert_eq!(
      find_in(&em, "ColorTempDaylight"),
      Some(&TagValue::I64(5200))
    );
    assert_eq!(
      find_in(&em, "FlashBatteryLevel"),
      Some(&TagValue::Str("n/a".into()))
    );
    assert_eq!(
      find_in(&em, "NormalWhiteLevel"),
      Some(&TagValue::I64(15000))
    );
    assert_eq!(
      find_in(&em, "LinearityUpperMargin"),
      Some(&TagValue::I64(13000))
    );
  }

  #[test]
  fn color_data_7_version_11_block() {
    let mut buf = vec![0u8; 1316 * 2];
    put_i16(&mut buf, 0x00, 11);
    put_u32(&mut buf, 0x26b, 0x0064_0000); // RawMeasuredRGGB (SwapWords ⇒ 100)
    put_u16(&mut buf, 0x2dc, 8000); // NormalWhiteLevel (ver 11)
    put_u16(&mut buf, 0x1fc, 1); // ver-10 NormalWhiteLevel sentinel (must be ignored)
    let em = parse(&buf, ByteOrder::Little, true);
    assert_eq!(
      find_in(&em, "ColorDataVersion"),
      Some(&TagValue::Str("11 (7DmkII/750D/760D/8000D)".into()))
    );
    assert_eq!(
      find_in(&em, "RawMeasuredRGGB"),
      Some(&TagValue::Str("100 0 0 0".into()))
    );
    assert_eq!(find_in(&em, "NormalWhiteLevel"), Some(&TagValue::I64(8000)));
  }

  #[test]
  fn color_data_8_version_12_uses_late_block() {
    let mut buf = vec![0u8; 1560 * 2];
    put_i16(&mut buf, 0x00, 12);
    for (i, v) in [2080i16, 1024, 1024, 1460].iter().enumerate() {
      put_i16(&mut buf, 0x3f + i, *v); // WB_RGGBLevelsAsShot
    }
    put_i16(&mut buf, 0x43, 5350);
    put_u16(&mut buf, 0x30e, 15500); // NormalWhiteLevel (ver < 14)
    put_u16(&mut buf, 0x230, 1); // ver-14 NormalWhiteLevel sentinel (must be ignored)
    let em = parse(&buf, ByteOrder::Little, true);
    assert_eq!(
      find_in(&em, "ColorDataVersion"),
      Some(&TagValue::Str("12 (1DXmkII/5DS/5DSR)".into()))
    );
    assert_eq!(
      find_in(&em, "WB_RGGBLevelsAsShot"),
      Some(&TagValue::Str("2080 1024 1024 1460".into()))
    );
    assert_eq!(
      find_in(&em, "NormalWhiteLevel"),
      Some(&TagValue::I64(15500))
    );
  }

  #[test]
  fn color_data_8_version_14_uses_1300d_block() {
    let mut buf = vec![0u8; 1353 * 2];
    put_i16(&mut buf, 0x00, 14);
    for (i, v) in [128u16, 129, 130, 131].iter().enumerate() {
      put_u16(&mut buf, 0x22c + i, *v); // PerChannelBlackLevel (ver 14)
    }
    put_u16(&mut buf, 0x230, 16000); // NormalWhiteLevel (ver 14)
    put_u16(&mut buf, 0x30e, 2); // ver-(<14||15) NormalWhiteLevel sentinel (must be ignored)
    let em = parse(&buf, ByteOrder::Little, false);
    assert_eq!(find_in(&em, "ColorDataVersion"), Some(&TagValue::I64(14)));
    assert_eq!(
      find_in(&em, "PerChannelBlackLevel"),
      Some(&TagValue::Str("128 129 130 131".into()))
    );
    assert_eq!(
      find_in(&em, "NormalWhiteLevel"),
      Some(&TagValue::I64(16000))
    );
  }
}
