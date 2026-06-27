// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::AFInfo` (`Sony.pm:9453-9748`) — the `0x940e`
//! Main-table SubDirectory dispatched when `$$self{Model} =~ /^(SLT-|HV|ILCA-)/`
//! (`Sony.pm:2094-2097`). An ENCIPHERED `ProcessBinaryData` block
//! (`PROCESS_PROC => \&ProcessEnciphered`); the central dispatch deciphers it
//! (once, or twice under `DoubleCipher`) BEFORE this parser runs, so the parser
//! receives the already-deciphered bytes (exactly like [`super::tag940e`]).
//!
//! `FORMAT => 'int8u'`, `PRIORITY => 0`, so the table keys are byte offsets and
//! EVERY leaf is `Priority => 0` — it never overrides an earlier same-name
//! duplicate (e.g. a `CameraInfo3`/`Tag9416` `FocusMode`/`ExposureProgram`).
//! `0x02 AFType` is a `DataMember` (`1 => 15-point`, `2 => 19-point`,
//! `3 => 79-point`) read first; it (and `$$self{Model} =~ /^ILCA-/`) selects two
//! mutually-exclusive decoding paths:
//!  - SLT / HV (AFType 1/2, model `!~ /^ILCA-/`): the `%afPoint15`/`%afPoint19`
//!    AFPoint trio, `AFStatus15`/`AFStatus19` (`int16s[18]`/`[30]`), the
//!    int32u `AFPointsUsed` bitmask, `AFMicroAdj` and `ExposureProgram`.
//!  - ILCA (AFType 3, model `=~ /^ILCA-/`): the `%afPoints79_940e` AFPoint trio,
//!    the `int8u[10]` `%afPoints79` `AFPointsUsed` bitmask, `AFStatus79`
//!    (`int16s[95]`), `AFMicroAdj` and `ExposureProgram`.
//!
//! Per the `ProcessBinaryData` per-field-availability contract a leaf is emitted
//! IFF its byte range is in the block ([[exifast-processbinarydata-per-field]])
//! AND its `AFType`/model `Condition` holds.

use crate::value::TagValue;
use smol_str::SmolStr;

use super::subtables::{SubEmission, af_status_value, read_i16, read_u32};

/// `AFType` (0x02) PrintConv (`Sony.pm:9482-9487`); `0` (n.a.) is unmapped.
fn af_type(v: u8) -> Option<&'static str> {
  Some(match v {
    1 => "15-point",
    2 => "19-point",
    3 => "79-point",
    _ => return None,
  })
}

/// `%afPoint15` (`Sony.pm:557-575`) — the 15-point AF sensor list.
fn af_point15(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Upper-left",
    1 => "Left",
    2 => "Lower-left",
    3 => "Far Left",
    4 => "Top (horizontal)",
    5 => "Near Right",
    6 => "Center (horizontal)",
    7 => "Near Left",
    8 => "Bottom (horizontal)",
    9 => "Top (vertical)",
    10 => "Center (vertical)",
    11 => "Bottom (vertical)",
    12 => "Far Right",
    13 => "Upper-right",
    14 => "Right",
    15 => "Lower-right",
    16 => "Upper-middle",
    17 => "Lower-middle",
    _ => return None,
  })
}

/// `%afPoint19` (`Sony.pm:580-611`) — the 19-point AF sensor list.
fn af_point19(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Upper Far Left",
    1 => "Upper-left (horizontal)",
    2 => "Far Left (horizontal)",
    3 => "Left (horizontal)",
    4 => "Lower Far Left",
    5 => "Lower-left (horizontal)",
    6 => "Upper-left (vertical)",
    7 => "Left (vertical)",
    8 => "Lower-left (vertical)",
    9 => "Far Left (vertical)",
    10 => "Top (horizontal)",
    11 => "Near Right",
    12 => "Center (horizontal)",
    13 => "Near Left",
    14 => "Bottom (horizontal)",
    15 => "Top (vertical)",
    16 => "Upper-middle",
    17 => "Center (vertical)",
    18 => "Lower-middle",
    19 => "Bottom (vertical)",
    20 => "Upper Far Right",
    21 => "Upper-right (horizontal)",
    22 => "Far Right (horizontal)",
    23 => "Right (horizontal)",
    24 => "Lower Far Right",
    25 => "Lower-right (horizontal)",
    26 => "Far Right (vertical)",
    27 => "Upper-right (vertical)",
    28 => "Right (vertical)",
    29 => "Lower-right (vertical)",
    _ => return None,
  })
}

/// `%afPoints79_940e` (`Sony.pm:628-646`) — the 0-94 AFPoint numbering used by
/// the ILCA `0x37`/`0x38`/`0x39` AFInfo rows.
fn af_points79_940e(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "B4",
    1 => "C4",
    2 => "D4",
    3 => "E4",
    4 => "F4",
    5 => "G4",
    6 => "H4",
    7 => "B3",
    8 => "C3",
    9 => "D3",
    10 => "E3",
    11 => "F3",
    12 => "G3",
    13 => "H3",
    14 => "B2",
    15 => "C2",
    16 => "D2",
    17 => "E2",
    18 => "F2",
    19 => "G2",
    20 => "H2",
    21 => "C1",
    22 => "D1",
    23 => "E1",
    24 => "F1",
    25 => "G1",
    26 => "A7 Vertical",
    27 => "A6 Vertical",
    28 => "A5 Vertical",
    29 => "C7 Vertical",
    30 => "C6 Vertical",
    31 => "C5 Vertical",
    32 => "E7 Vertical",
    33 => "E6 Center Vertical",
    34 => "E5 Vertical",
    35 => "G7 Vertical",
    36 => "G6 Vertical",
    37 => "G5 Vertical",
    38 => "I7 Vertical",
    39 => "I6 Vertical",
    40 => "I5 Vertical",
    41 => "A7",
    42 => "B7",
    43 => "C7",
    44 => "D7",
    45 => "E7",
    46 => "F7",
    47 => "G7",
    48 => "H7",
    49 => "I7",
    50 => "A6",
    51 => "B6",
    52 => "C6",
    53 => "D6",
    54 => "E6 Center",
    55 => "F6",
    56 => "G6",
    57 => "H6",
    58 => "I6",
    59 => "A5",
    60 => "B5",
    61 => "C5",
    62 => "D5",
    63 => "E5",
    64 => "F5",
    65 => "G5",
    66 => "H5",
    67 => "I5",
    68 => "C11",
    69 => "D11",
    70 => "E11",
    71 => "F11",
    72 => "G11",
    73 => "B10",
    74 => "C10",
    75 => "D10",
    76 => "E10",
    77 => "F10",
    78 => "G10",
    79 => "H10",
    80 => "B9",
    81 => "C9",
    82 => "D9",
    83 => "E9",
    84 => "F9",
    85 => "G9",
    86 => "H9",
    87 => "B8",
    88 => "C8",
    89 => "D8",
    90 => "E8",
    91 => "F8",
    92 => "G8",
    93 => "H8",
    94 => "E6 Center F2.8",
    _ => return None,
  })
}

/// SLT `AFAreaMode` (0x0a) PrintConv (`Sony.pm:9557-9562`).
fn af_area_mode_slt(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Wide",
    1 => "Spot",
    2 => "Local",
    3 => "Zone",
    _ => return None,
  })
}

/// ILCA `AFAreaMode` (0x3a) PrintConv (`Sony.pm:9710-9716`).
fn af_area_mode_ilca(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Wide",
    1 => "Center",
    2 => "Flexible Spot",
    3 => "Zone",
    4 => "Expanded Flexible Spot",
    _ => return None,
  })
}

/// SLT `FocusMode` (0x0b) PrintConv (`Sony.pm:9570-9577`) — note `7 => AF-D`.
fn focus_mode_slt(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Manual",
    2 => "AF-S",
    3 => "AF-C",
    4 => "AF-A",
    6 => "DMF",
    7 => "AF-D",
    _ => return None,
  })
}

/// ILCA `FocusMode` (0x05) PrintConv (`Sony.pm:9661-9668`).
fn focus_mode_ilca(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Manual",
    2 => "AF-S",
    3 => "AF-C",
    4 => "AF-A",
    6 => "DMF",
    _ => return None,
  })
}

/// `%afPoints79` (`Sony.pm:615-625`) — the 79-point grid label (keys 0..=78);
/// the ILCA `AFPointsUsed` (0x10) `int8u[10]` BITMASK lookup.
fn af_points79(n: u32) -> Option<&'static str> {
  Some(match n {
    0 => "A5",
    1 => "A6",
    2 => "A7",
    3 => "B2",
    4 => "B3",
    5 => "B4",
    6 => "B5",
    7 => "B6",
    8 => "B7",
    9 => "B8",
    10 => "B9",
    11 => "B10",
    12 => "C1",
    13 => "C2",
    14 => "C3",
    15 => "C4",
    16 => "C5",
    17 => "C6",
    18 => "C7",
    19 => "C8",
    20 => "C9",
    21 => "C10",
    22 => "C11",
    23 => "D1",
    24 => "D2",
    25 => "D3",
    26 => "D4",
    27 => "D5",
    28 => "D6",
    29 => "D7",
    30 => "D8",
    31 => "D9",
    32 => "D10",
    33 => "D11",
    34 => "E1",
    35 => "E2",
    36 => "E3",
    37 => "E4",
    38 => "E5",
    39 => "E6",
    40 => "E7",
    41 => "E8",
    42 => "E9",
    43 => "E10",
    44 => "E11",
    45 => "F1",
    46 => "F2",
    47 => "F3",
    48 => "F4",
    49 => "F5",
    50 => "F6",
    51 => "F7",
    52 => "F8",
    53 => "F9",
    54 => "F10",
    55 => "F11",
    56 => "G1",
    57 => "G2",
    58 => "G3",
    59 => "G4",
    60 => "G5",
    61 => "G6",
    62 => "G7",
    63 => "G8",
    64 => "G9",
    65 => "G10",
    66 => "G11",
    67 => "H2",
    68 => "H3",
    69 => "H4",
    70 => "H5",
    71 => "H6",
    72 => "H7",
    73 => "H8",
    74 => "H9",
    75 => "H10",
    76 => "I5",
    77 => "I6",
    78 => "I7",
    _ => return None,
  })
}

/// SLT `AFPointsUsed` (0x16e) int32u BITMASK lookup (`Sony.pm:9605-9624`).
fn af_points_used_slt_bit(n: u32) -> Option<&'static str> {
  Some(match n {
    0 => "Center",
    1 => "Top",
    2 => "Upper-right",
    3 => "Right",
    4 => "Lower-right",
    5 => "Bottom",
    6 => "Lower-left",
    7 => "Left",
    8 => "Upper-left",
    9 => "Far Right",
    10 => "Far Left",
    11 => "Upper-middle",
    12 => "Near Right",
    13 => "Lower-middle",
    14 => "Near Left",
    15 => "Upper Far Right",
    16 => "Lower Far Right",
    17 => "Lower Far Left",
    18 => "Upper Far Left",
    _ => return None,
  })
}

/// The 18 `AFStatus15` `int16s` leaf names (`%Sony::AFStatus15`,
/// `Sony.pm:9802-9819`).
const AF_STATUS15_NAMES: [&str; 18] = [
  "AFStatusUpper-left",
  "AFStatusLeft",
  "AFStatusLower-left",
  "AFStatusFarLeft",
  "AFStatusTopHorizontal",
  "AFStatusNearRight",
  "AFStatusCenterHorizontal",
  "AFStatusNearLeft",
  "AFStatusBottomHorizontal",
  "AFStatusTopVertical",
  "AFStatusCenterVertical",
  "AFStatusBottomVertical",
  "AFStatusFarRight",
  "AFStatusUpper-right",
  "AFStatusRight",
  "AFStatusLower-right",
  "AFStatusUpper-middle",
  "AFStatusLower-middle",
];

/// The 30 `AFStatus19` `int16s` leaf names (`%Sony::AFStatus19`,
/// `Sony.pm:9827-9856`).
const AF_STATUS19_NAMES: [&str; 30] = [
  "AFStatusUpperFarLeft",
  "AFStatusUpper-leftHorizontal",
  "AFStatusFarLeftHorizontal",
  "AFStatusLeftHorizontal",
  "AFStatusLowerFarLeft",
  "AFStatusLower-leftHorizontal",
  "AFStatusUpper-leftVertical",
  "AFStatusLeftVertical",
  "AFStatusLower-leftVertical",
  "AFStatusFarLeftVertical",
  "AFStatusTopHorizontal",
  "AFStatusNearRight",
  "AFStatusCenterHorizontal",
  "AFStatusNearLeft",
  "AFStatusBottomHorizontal",
  "AFStatusTopVertical",
  "AFStatusUpper-middle",
  "AFStatusCenterVertical",
  "AFStatusLower-middle",
  "AFStatusBottomVertical",
  "AFStatusUpperFarRight",
  "AFStatusUpper-rightHorizontal",
  "AFStatusFarRightHorizontal",
  "AFStatusRightHorizontal",
  "AFStatusLowerFarRight",
  "AFStatusLower-rightHorizontal",
  "AFStatusFarRightVertical",
  "AFStatusUpper-rightVertical",
  "AFStatusRightVertical",
  "AFStatusLower-rightVertical",
];

/// The 95 `AFStatus79` `int16s` leaf names (`%Sony::AFStatus79`,
/// `Sony.pm:9876-9975`).
const AF_STATUS79_NAMES: [&str; 95] = [
  "AFStatus_00_B4",
  "AFStatus_01_C4",
  "AFStatus_02_D4",
  "AFStatus_03_E4",
  "AFStatus_04_F4",
  "AFStatus_05_G4",
  "AFStatus_06_H4",
  "AFStatus_07_B3",
  "AFStatus_08_C3",
  "AFStatus_09_D3",
  "AFStatus_10_E3",
  "AFStatus_11_F3",
  "AFStatus_12_G3",
  "AFStatus_13_H3",
  "AFStatus_14_B2",
  "AFStatus_15_C2",
  "AFStatus_16_D2",
  "AFStatus_17_E2",
  "AFStatus_18_F2",
  "AFStatus_19_G2",
  "AFStatus_20_H2",
  "AFStatus_21_C1",
  "AFStatus_22_D1",
  "AFStatus_23_E1",
  "AFStatus_24_F1",
  "AFStatus_25_G1",
  "AFStatus_26_A7_Vertical",
  "AFStatus_27_A6_Vertical",
  "AFStatus_28_A5_Vertical",
  "AFStatus_29_C7_Vertical",
  "AFStatus_30_C6_Vertical",
  "AFStatus_31_C5_Vertical",
  "AFStatus_32_E7_Vertical",
  "AFStatus_33_E6_Center_Vertical",
  "AFStatus_34_E5_Vertical",
  "AFStatus_35_G7_Vertical",
  "AFStatus_36_G6_Vertical",
  "AFStatus_37_G5_Vertical",
  "AFStatus_38_I7_Vertical",
  "AFStatus_39_I6_Vertical",
  "AFStatus_40_I5_Vertical",
  "AFStatus_41_A7",
  "AFStatus_42_B7",
  "AFStatus_43_C7",
  "AFStatus_44_D7",
  "AFStatus_45_E7",
  "AFStatus_46_F7",
  "AFStatus_47_G7",
  "AFStatus_48_H7",
  "AFStatus_49_I7",
  "AFStatus_50_A6",
  "AFStatus_51_B6",
  "AFStatus_52_C6",
  "AFStatus_53_D6",
  "AFStatus_54_E6_Center",
  "AFStatus_55_F6",
  "AFStatus_56_G6",
  "AFStatus_57_H6",
  "AFStatus_58_I6",
  "AFStatus_59_A5",
  "AFStatus_60_B5",
  "AFStatus_61_C5",
  "AFStatus_62_D5",
  "AFStatus_63_E5",
  "AFStatus_64_F5",
  "AFStatus_65_G5",
  "AFStatus_66_H5",
  "AFStatus_67_I5",
  "AFStatus_68_C11",
  "AFStatus_69_D11",
  "AFStatus_70_E11",
  "AFStatus_71_F11",
  "AFStatus_72_G11",
  "AFStatus_73_B10",
  "AFStatus_74_C10",
  "AFStatus_75_D10",
  "AFStatus_76_E10",
  "AFStatus_77_F10",
  "AFStatus_78_G10",
  "AFStatus_79_H10",
  "AFStatus_80_B9",
  "AFStatus_81_C9",
  "AFStatus_82_D9",
  "AFStatus_83_E9",
  "AFStatus_84_F9",
  "AFStatus_85_G9",
  "AFStatus_86_H9",
  "AFStatus_87_B8",
  "AFStatus_88_C8",
  "AFStatus_89_D8",
  "AFStatus_90_E8",
  "AFStatus_91_F8",
  "AFStatus_92_G8",
  "AFStatus_93_H8",
  "AFStatus_94_E6_Center_F2-8",
];

/// `$$self{Model} =~ /^ILCA-/`.
fn model_is_ilca(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.starts_with("ILCA-"))
}

/// A `Priority => 0` (`PRIORITY => 0` table default) AFInfo leaf.
fn leaf(name: &'static str, value: TagValue) -> SubEmission {
  SubEmission {
    name,
    value,
    priority: 0,
  }
}

/// Push an `int8u` hash-PrintConv leaf at byte `off` (`-j` label / `Unknown
/// (N)`, `-n` raw int).
fn push_hash(
  buf: &[u8],
  off: usize,
  name: &'static str,
  hit: impl Fn(u8) -> Option<&'static str>,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  if let Some(&raw) = buf.get(off) {
    out.push(leaf(
      name,
      super::hash_print_value(raw, hit(raw), print_conv),
    ));
  }
}

/// Push an `int16s` (`%afStatusInfo`) leaf at byte `off`.
fn push_af_status(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  if let Some(v) = read_i16(buf, off) {
    out.push(leaf(name, af_status_value(v, print_conv)));
  }
}

/// Push an `int8s` `AFMicroAdj` leaf at byte `off` (`Format => 'int8s'`, no
/// PrintConv / ValueConv ⇒ the signed integer in both `-j` and `-n`).
fn push_af_micro_adj(buf: &[u8], off: usize, out: &mut Vec<SubEmission>) {
  if let Some(&raw) = buf.get(off) {
    out.push(leaf("AFMicroAdj", TagValue::I64(i64::from(raw as i8))));
  }
}

/// Push the `int16s[N]` `%afStatusInfo` grid `names` starting at byte `start`.
fn push_af_status_grid(
  buf: &[u8],
  start: usize,
  names: &[&'static str],
  print_conv: bool,
  out: &mut Vec<SubEmission>,
) {
  for (i, name) in names.iter().enumerate() {
    push_af_status(buf, start + i * 2, name, print_conv, out);
  }
}

/// DecodeBits over a set of words: bit `i` of word `w` ⇒ bit number
/// `i + bits_per_word * w` ⇒ `lookup(n)` (or `[n]` when absent), joined `", "`;
/// no set bit ⇒ `"(none)"` (`ExifTool.pm` DecodeBits).
fn decode_bits(
  words: &[u32],
  bits_per_word: u32,
  lookup: impl Fn(u32) -> Option<&'static str>,
) -> SmolStr {
  let mut bit_list: Vec<String> = std::vec::Vec::new();
  for (w, &word) in words.iter().enumerate() {
    for i in 0..bits_per_word {
      if word & (1u32 << i) != 0 {
        let n = i + bits_per_word * w as u32;
        match lookup(n) {
          Some(label) => bit_list.push(label.to_string()),
          None => bit_list.push(std::format!("[{n}]")),
        }
      }
    }
  }
  if bit_list.is_empty() {
    return SmolStr::new("(none)");
  }
  SmolStr::new(bit_list.join(", "))
}

/// Walk the (already-deciphered) `AFInfo` block and emit its `Priority => 0`
/// leaves.
///
/// `buf` is the deciphered `0x940e` block; `model` is `$$self{Model}` (selects
/// the SLT vs ILCA path); `print_conv` selects `-j` vs `-n`.
#[must_use]
pub fn parse_af_info(buf: &[u8], model: Option<&str>, print_conv: bool) -> Vec<SubEmission> {
  let mut out = std::vec::Vec::new();
  let ilca = model_is_ilca(model);

  // 0x02 AFType (DataMember) — emitted unconditionally; gates the AFType-keyed
  // rows below.
  let af_type_raw = buf.get(0x02).copied();
  if let Some(raw) = af_type_raw {
    out.push(leaf(
      "AFType",
      super::hash_print_value(raw, af_type(raw), print_conv),
    ));
  }

  if !ilca {
    // ---- SLT / HV path (model !~ /^ILCA-/) ----
    // 0x04 AFStatusActiveSensor — int16s.
    push_af_status(buf, 0x04, "AFStatusActiveSensor", print_conv, &mut out);

    // 0x07/0x08/0x09 the AFPoint trio (AFType 1 ⇒ %afPoint15, 2 ⇒ %afPoint19).
    match af_type_raw {
      Some(1) => {
        push_hash(buf, 0x07, "AFPoint", af_point15, print_conv, &mut out);
        // 0x08 adds `255 => '(none)'`.
        push_hash(
          buf,
          0x08,
          "AFPointInFocus",
          |v| {
            if v == 255 {
              Some("(none)")
            } else {
              af_point15(v)
            }
          },
          print_conv,
          &mut out,
        );
        // 0x09 adds `30 => '(out of focus)'`.
        push_hash(
          buf,
          0x09,
          "AFPointAtShutterRelease",
          |v| {
            if v == 30 {
              Some("(out of focus)")
            } else {
              af_point15(v)
            }
          },
          print_conv,
          &mut out,
        );
      }
      Some(2) => {
        push_hash(buf, 0x07, "AFPoint", af_point19, print_conv, &mut out);
        push_hash(
          buf,
          0x08,
          "AFPointInFocus",
          |v| {
            if v == 255 {
              Some("(none)")
            } else {
              af_point19(v)
            }
          },
          print_conv,
          &mut out,
        );
        push_hash(
          buf,
          0x09,
          "AFPointAtShutterRelease",
          |v| {
            if v == 30 {
              Some("(out of focus)")
            } else {
              af_point19(v)
            }
          },
          print_conv,
          &mut out,
        );
      }
      _ => {}
    }

    // 0x0a AFAreaMode / 0x0b FocusMode.
    push_hash(
      buf,
      0x0a,
      "AFAreaMode",
      af_area_mode_slt,
      print_conv,
      &mut out,
    );
    push_hash(buf, 0x0b, "FocusMode", focus_mode_slt, print_conv, &mut out);

    // 0x11 AFStatus15 (AFType 1, int16s[18]) / AFStatus19 (AFType 2, int16s[30]).
    match af_type_raw {
      Some(1) => push_af_status_grid(buf, 0x11, &AF_STATUS15_NAMES, print_conv, &mut out),
      Some(2) => push_af_status_grid(buf, 0x11, &AF_STATUS19_NAMES, print_conv, &mut out),
      _ => {}
    }

    // 0x16e AFPointsUsed — int32u BITMASK (default 32-bit single word).
    if let Some(v) = read_u32(buf, 0x16e) {
      let value = if print_conv {
        TagValue::Str(decode_bits(&[v], 32, af_points_used_slt_bit))
      } else {
        TagValue::I64(i64::from(v))
      };
      out.push(leaf("AFPointsUsed", value));
    }

    // 0x17d AFMicroAdj — int8s.
    push_af_micro_adj(buf, 0x17d, &mut out);

    // 0x17e ExposureProgram — %sonyExposureProgram3.
    push_hash(
      buf,
      0x17e,
      "ExposureProgram",
      super::print_exposure_program3,
      print_conv,
      &mut out,
    );
  } else {
    // ---- ILCA path (model =~ /^ILCA-/, AFType 3) ----
    // 0x05 FocusMode.
    push_hash(
      buf,
      0x05,
      "FocusMode",
      focus_mode_ilca,
      print_conv,
      &mut out,
    );

    // 0x10 AFPointsUsed — int8u[10] BITMASK (%afPoints79, BitsPerWord 8).
    if let Some(words) = buf.get(0x10..0x10 + 10) {
      let value = if print_conv {
        let words: Vec<u32> = words.iter().map(|&b| u32::from(b)).collect();
        TagValue::Str(decode_bits(&words, 8, af_points79))
      } else {
        // `-n` renders the default space-joined int8u list.
        let parts: Vec<String> = words.iter().map(|&b| std::format!("{b}")).collect();
        TagValue::Str(SmolStr::new(parts.join(" ")))
      };
      out.push(leaf("AFPointsUsed", value));
    }

    // 0x37/0x38/0x39 the AFPoint trio (AFType 3 ⇒ %afPoints79_940e).
    if af_type_raw == Some(3) {
      push_hash(
        buf,
        0x37,
        "AFPoint",
        |v| {
          if v == 255 {
            Some("(none)")
          } else {
            af_points79_940e(v)
          }
        },
        print_conv,
        &mut out,
      );
      push_hash(
        buf,
        0x38,
        "AFPointInFocus",
        |v| {
          if v == 255 {
            Some("(none)")
          } else {
            af_points79_940e(v)
          }
        },
        print_conv,
        &mut out,
      );
      push_hash(
        buf,
        0x39,
        "AFPointAtShutterRelease",
        |v| {
          if v == 95 {
            Some("(none)")
          } else {
            af_points79_940e(v)
          }
        },
        print_conv,
        &mut out,
      );
    }

    // 0x3a AFAreaMode / 0x3b AFStatusActiveSensor.
    push_hash(
      buf,
      0x3a,
      "AFAreaMode",
      af_area_mode_ilca,
      print_conv,
      &mut out,
    );
    push_af_status(buf, 0x3b, "AFStatusActiveSensor", print_conv, &mut out);

    // 0x43 ExposureProgram.
    push_hash(
      buf,
      0x43,
      "ExposureProgram",
      super::print_exposure_program3,
      print_conv,
      &mut out,
    );

    // 0x50 AFMicroAdj — int8s.
    push_af_micro_adj(buf, 0x50, &mut out);

    // 0x7d AFStatus79 (AFType 3, int16s[95]).
    if af_type_raw == Some(3) {
      push_af_status_grid(buf, 0x7d, &AF_STATUS79_NAMES, print_conv, &mut out);
    }
  }

  out
}

#[cfg(test)]
// The module-level `#![deny(clippy::indexing_slicing)]` is relaxed for the test
// module, which indexes fixed-layout byte buffers directly (an out-of-range
// index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
#[path = "afinfo_tests.rs"]
mod tests;
