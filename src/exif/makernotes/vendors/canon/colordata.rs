// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Canon `ColorData` raw-color-processing sub-tables (`Canon.pm:7436-8976`).
//!
//! The `%Canon::Main` tag `0x4001` (`Canon.pm:1973-2048`) is a COUNT-selected
//! list of `Canon::ColorData<N>` SubDirectories — the `$count` (number of
//! `int16u` words) keys the variant. This module ports the two variants the
//! real EOS-5D / EOS-7D CR2 fixtures dispatch:
//!
//! - `ColorData3` (`Canon.pm:7557-7646`, `$count == 796`) — 1DmkIIN/5D/30D/400D.
//!   WB_RGGBLevels*/ColorTemp* are inline at word offsets `0x3f..0x84`.
//! - `ColorData4` (`Canon.pm:7648-7772`, `$count` in
//!   `692|674|702|1227|1250|1251|1337|1338|1346`) — many bodies incl. the 7D.
//!   The WB_RGGBLevels*/ColorTemp* live in a nested `ColorCoefs` block at word
//!   `0x3f` (`Canon.pm:7774-7830`); several white-level leaves are
//!   `ColorDataVersion`-conditional.
//!
//! All tables are `FORMAT => 'int16s'`, `FIRST_ENTRY => 0`, so a tag at word
//! position `p` is at byte offset `2 * p`. `ColorCalib` (`Unknown => 1`) is
//! skipped. The `RawMeasuredRGGB`/`MeasuredRGGBData` `int32u[4]` leaves apply
//! `SwapWords` (`Canon.pm:10311` — swap the two 16-bit halves of each word).
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
  if count == 796 {
    color_data_3(data, order, print_conv)
  } else if matches!(
    count,
    692 | 674 | 702 | 1227 | 1250 | 1251 | 1337 | 1338 | 1346
  ) {
    color_data_4(data, order, print_conv)
  } else {
    Vec::new()
  }
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
}
