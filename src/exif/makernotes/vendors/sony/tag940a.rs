// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::Tag940a` (`Sony.pm:9292-9345`) — the enciphered
//! `Tag940a` `ProcessBinaryData` block (`AFPointsSelected`).
//!
//! The `0x940a` Main-table row is a conditional-ARRAY SubDirectory dispatcher
//! (`Sony.pm:2067-2074`): the `Tag940a` table is selected when `$$self{Model}
//! =~ /^(SLT-|HV)/` (otherwise `Sony_0x940a`, `%unknownCipherData`). The block
//! is enciphered (`PROCESS_PROC => \&ProcessEnciphered`, `Sony.pm:9293`) so the
//! dispatcher [`process_enciphered`](super::decipher::process_enciphered)s it
//! (once, or twice for a double-enciphered body) and hands this table the
//! DECIPHERED bytes; `FORMAT => 'int8u'` + `FIRST_ENTRY => 0`
//! (`Sony.pm:9296,9298`). NOTES: "These tags are currently extracted for SLT
//! models only."
//!
//! Per the `ProcessBinaryData` contract each tag is emitted IFF its byte range
//! is in the deciphered block ([[exifast-processbinarydata-per-field]]). The
//! ILME-FX3 is not an SLT/HV body, so ExifTool dispatches its `0x940a` as
//! `Sony_0x940a` and this table is never selected for it.

use crate::value::TagValue;

/// One emitted `Tag940a` leaf — the resolved tag name and rendered value.
pub struct Tag940aEmission {
  /// `Name => '…'` from the bundled table.
  pub name: &'static str,
  /// The rendered value (`-j` PrintConv result, or `-n` raw `$val`).
  pub value: TagValue,
}

/// `true` when `$$self{Model} =~ /^(SLT-|HV)/` selects the `Tag940a` variant
/// (`Sony.pm:2069`). Tested against the parent `$$self{Model}`.
#[must_use]
pub fn selects_tag940a(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.starts_with("SLT-") || m.starts_with("HV"))
}

/// Walk the DECIPHERED `Tag940a` block and emit `AFPointsSelected`.
///
/// `buf` is the DECIPHERED `0x940a` block — the dispatcher already confirmed the
/// variant gate ([`selects_tag940a`]) and ran
/// [`process_enciphered`](super::decipher::process_enciphered). `print_conv`
/// selects `-j` (PrintConv) vs `-n` (raw `$val`).
#[must_use]
pub fn parse_tag940a(buf: &[u8], print_conv: bool) -> Vec<Tag940aEmission> {
  let mut out = std::vec::Vec::new();

  // 0x04 AFPointsSelected — int32u (Sony.pm:9303-9342). PrintConv is a literal
  // hash with a BITMASK fallback (`ExifTool.pm:3614-3618`): a literal hit wins,
  // otherwise the value decodes via DecodeBits (32-bit, no BitsPerWord).
  if let Some(&[a, b, c, d]) = buf.get(0x04..0x08) {
    let val = u32::from_le_bytes([a, b, c, d]);
    out.push(Tag940aEmission {
      name: "AFPointsSelected",
      value: af_points_selected_value(val, print_conv),
    });
  }

  out
}

/// `AFPointsSelected` rendered value (`Sony.pm:9304-9341`). `-n` keeps the raw
/// `int32u` (no ValueConv). In `-j`: the literal hash is checked first
/// (`ExifTool.pm:3616`); on a miss the value renders via `DecodeBits`
/// (`ExifTool.pm:3617-3618`, `ExifTool.pm:6385-6407`) over the 0..32 bit labels
/// — a labelled bit renders its name, an unlabelled set bit renders `"[n]"`,
/// joined with `", "`. (`0` hits the literal `'(none)'`, so the empty-bitlist
/// `"(none)"` DecodeBits case is unreachable here.)
fn af_points_selected_value(val: u32, print_conv: bool) -> TagValue {
  if !print_conv {
    return TagValue::I64(i64::from(val));
  }
  if let Some(label) = af_points_selected_literal(val) {
    return TagValue::Str(label.into());
  }
  let mut bits: Vec<String> = std::vec::Vec::new();
  for i in 0..32u32 {
    if val & (1u32 << i) != 0 {
      match af_points_selected_bit(i) {
        Some(label) => bits.push(label.to_string()),
        None => bits.push(std::format!("[{i}]")),
      }
    }
  }
  if bits.is_empty() {
    return TagValue::Str("(none)".into());
  }
  TagValue::Str(bits.join(", ").into())
}

/// `AFPointsSelected` literal-value PrintConv keys (`Sony.pm:9310-9316`).
fn af_points_selected_literal(v: u32) -> Option<&'static str> {
  Some(match v {
    0 => "(none)",
    0x0000_7801 => "Center Zone",
    0x0001_821c => "Right Zone",
    0x0006_05c0 => "Left Zone",
    0x0003_ffff => "(all LA-EA4)",
    0x7fff_ffff => "(all)",
    0xffff_ffff => "n/a",
    _ => return None,
  })
}

/// `AFPointsSelected` BITMASK bit labels (`Sony.pm:9319-9339`).
fn af_points_selected_bit(n: u32) -> Option<&'static str> {
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

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is relaxed for the test
// module, which indexes fixed-layout byte buffers directly (an out-of-range
// index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
#[path = "tag940a_tests.rs"]
mod tests;
