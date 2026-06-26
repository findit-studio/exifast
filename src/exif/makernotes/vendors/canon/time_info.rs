// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Canon::TimeInfo` (`Canon.pm:6635-6702`) — `Canon::Main` tag `0x35`.
//!
//! `FORMAT => 'int32s'`, `FIRST_ENTRY => 1` (index 0 is the 16-byte size), so a
//! tag at index `i` lives at byte offset `i * 4`: TimeZone (1) @ 4,
//! TimeZoneCity (2) @ 8, DaylightSavings (3) @ 12.
//!
//! D8: pure decoder — returns the `(Name, TagValue)` emission pairs the
//! dispatch site wraps in the `Canon` family-1 group.

#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::ByteOrder;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::string::String;
use std::vec::Vec;

/// Decode `%Canon::TimeInfo` from the 16-byte `0x35` blob.
#[must_use]
pub fn parse(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  // 1) TimeZone @ byte 4 (int32s, `TimeZoneString($val)`).
  if let Some(v) = i32s(data, 4, order) {
    out.push((
      SmolStr::new_static("TimeZone"),
      if print_conv {
        TagValue::Str(SmolStr::from(time_zone_string(v)))
      } else {
        TagValue::I64(v)
      },
    ));
  }
  // 2) TimeZoneCity @ byte 8 (int32s, PrintConv hash).
  if let Some(v) = i32s(data, 8, order) {
    out.push((
      SmolStr::new_static("TimeZoneCity"),
      hash(v, print_conv, time_zone_city_label),
    ));
  }
  // 3) DaylightSavings @ byte 12 (int32s, `{0 => 'Off', 60 => 'On'}`).
  if let Some(v) = i32s(data, 12, order) {
    out.push((
      SmolStr::new_static("DaylightSavings"),
      hash(v, print_conv, daylight_savings_label),
    ));
  }
  out
}

/// `Image::ExifTool::TimeZoneString($min)` (`ExifTool.pm:6750-6762`) for a
/// minute offset: `±HH:MM`.
fn time_zone_string(min: i64) -> String {
  let sign = if min < 0 { '-' } else { '+' };
  let min = min.abs();
  let h = min / 60;
  let m = min - h * 60;
  std::format!("{sign}{h:02}:{m:02}")
}

/// `TimeZoneCity` PrintConv (`Canon.pm:6654-6693`).
fn time_zone_city_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "n/a",
    1 => "Chatham Islands",
    2 => "Wellington",
    3 => "Solomon Islands",
    4 => "Sydney",
    5 => "Adelaide",
    6 => "Tokyo",
    7 => "Hong Kong",
    8 => "Bangkok",
    9 => "Yangon",
    10 => "Dhaka",
    11 => "Kathmandu",
    12 => "Delhi",
    13 => "Karachi",
    14 => "Kabul",
    15 => "Dubai",
    16 => "Tehran",
    17 => "Moscow",
    18 => "Cairo",
    19 => "Paris",
    20 => "London",
    21 => "Azores",
    22 => "Fernando de Noronha",
    23 => "Sao Paulo",
    24 => "Newfoundland",
    25 => "Santiago",
    26 => "Caracas",
    27 => "New York",
    28 => "Chicago",
    29 => "Denver",
    30 => "Los Angeles",
    31 => "Anchorage",
    32 => "Honolulu",
    33 => "Samoa",
    32766 => "(not set)",
    _ => return None,
  })
}

/// `DaylightSavings` PrintConv (`Canon.pm:6697-6700`).
fn daylight_savings_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    60 => "On",
    _ => return None,
  })
}

/// Render a hash PrintConv: the label, or `Unknown (N)`; raw int under `-n`.
fn hash(v: i64, print_conv: bool, label: fn(i64) -> Option<&'static str>) -> TagValue {
  if !print_conv {
    return TagValue::I64(v);
  }
  match label(v) {
    Some(l) => TagValue::Str(SmolStr::new_static(l)),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
  }
}

/// Read one signed 32-bit word at byte `off`.
fn i32s(data: &[u8], off: usize, order: ByteOrder) -> Option<i64> {
  let arr: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => i32::from_le_bytes(arr),
    ByteOrder::Big => i32::from_be_bytes(arr),
  } as i64)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  #[test]
  fn time_info_7d() {
    // [size=16][TimeZone=60][TimeZoneCity=19][DaylightSavings=0]
    let mut b = vec![0u8; 16];
    b[0] = 16;
    b[4] = 60;
    b[8] = 19;
    let em = parse(&b, ByteOrder::Little, true);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("TimeZone"), Some(TagValue::Str("+01:00".into())));
    assert_eq!(find("TimeZoneCity"), Some(TagValue::Str("Paris".into())));
    assert_eq!(find("DaylightSavings"), Some(TagValue::Str("Off".into())));

    let em = parse(&b, ByteOrder::Little, false);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("TimeZone"), Some(TagValue::I64(60)));
    assert_eq!(find("TimeZoneCity"), Some(TagValue::I64(19)));
  }

  #[test]
  fn time_zone_string_negative() {
    assert_eq!(time_zone_string(-300), "-05:00");
    assert_eq!(time_zone_string(0), "+00:00");
    assert_eq!(time_zone_string(330), "+05:30");
  }
}
