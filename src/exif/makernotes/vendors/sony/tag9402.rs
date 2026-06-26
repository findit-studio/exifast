// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::Tag9402` (`Sony.pm:8685-8789`) — the enciphered
//! `Tag9402` `ProcessBinaryData` block (AF / ISO / temperature info for the
//! non-SLT/HV/ILCA bodies, incl. the ILME-FX3).
//!
//! The `0x9402` Main-table row is a conditional-ARRAY SubDirectory dispatcher
//! (`Sony.pm:1935-1974`): the `Tag9402` table is selected when the body is NOT
//! SLT/HV/ILCA *and* the (still-enciphered) first value byte is neither `0x05`
//! nor `0xff` (`Sony.pm:1969`). The FX3 (`ILME-FX3`) passes the model gate and
//! its enciphered first byte is `0xd3` (deciphering to `0x22`), so it takes the
//! `Tag9402` branch. The block is enciphered (`PROCESS_PROC =>
//! \&ProcessEnciphered`, `Sony.pm:8686`) so the dispatcher
//! [`process_enciphered`](super::decipher::process_enciphered)s it and hands this
//! table the DECIPHERED bytes; `FORMAT => 'int8u'` + `FIRST_ENTRY => 0`
//! (`Sony.pm:8689,8691`).
//!
//! `ProcessEnciphered` honours the file-global `$$self{DoubleCipher}` flag
//! (`Sony.pm:11553-11556`): on a file the ExifTool 9.04-9.10 write bug
//! double-enciphered — latched when the 0x9400 first byte ∈ {0x5e,0xe7,0x04}
//! ([`super::tag9400::detects_double_cipher`], `Sony.pm:1847`) — EVERY 0x94xx
//! block (not just this one) is deciphered TWICE. That second pass is applied
//! CENTRALLY by [`process_enciphered`](super::decipher::process_enciphered), so
//! this table always receives correctly-deciphered bytes.
//!
//! Per the `ProcessBinaryData` contract each tag is emitted IFF its byte range
//! is in the deciphered block ([[exifast-processbinarydata-per-field]]). Only
//! the camera-metadata leaves the FX3 activation golden needs are ported here.

use crate::value::TagValue;

/// One emitted `Tag9402` leaf — the resolved tag name and rendered value.
pub struct Tag9402Emission {
  /// `Name => '…'` from the bundled table.
  pub name: &'static str,
  /// The rendered value (`-j` PrintConv result, or `-n` raw `$val`).
  pub value: TagValue,
}

/// 0x0017 `AFAreaMode` PrintConv hash (`Sony.pm:8722-8738`).
fn print_af_area_mode(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Multi",
    1 => "Center",
    2 => "Spot",
    3 => "Flexible Spot",
    10 => "Selective (for Miniature effect)",
    11 => "Zone",
    12 => "Expanded Flexible Spot",
    13 => "Custom AF Area",
    14 => "Tracking",
    15 => "Face Tracking",
    20 => "Animal Eye Tracking",
    21 => "Human Eye Tracking",
    255 => "Manual",
    _ => return None,
  })
}

/// Walk the DECIPHERED `Tag9402` block and emit the camera-metadata leaves the
/// FX3 activation golden needs.
///
/// `buf` is the DECIPHERED `0x9402` block — the dispatcher already confirmed the
/// variant gate ([`selects_tag9402`]) on the raw bytes and ran
/// [`process_enciphered`](super::decipher::process_enciphered), which applies the
/// SECOND `Decipher` pass (`Sony.pm:11553-11556`) when the file-global
/// `$$self{DoubleCipher}` flag is set (latched from the 0x9400 walk,
/// [`super::tag9400::detects_double_cipher`]). So a double-enciphered body is
/// already fully deciphered here, not once-deciphered garbage. `print_conv`
/// selects `-j` (PrintConv) vs `-n` (raw `$val`).
#[must_use]
pub fn parse_tag9402(buf: &[u8], print_conv: bool) -> Vec<Tag9402Emission> {
  let mut out = std::vec::Vec::new();

  // 0x0002 TempTest1 — DataMember, `RawConv` keeps it `undef` unless `Unknown`
  // >= 2 (Sony.pm:8695-8700), so it is never emitted; it only gates 0x0004.
  let temp_test1 = buf.get(0x02).copied();

  // 0x0004 AmbientTemperature — int8s, `Condition => '$$self{TempTest1} == 255'`,
  // `PrintConv => '"$val C"'` (Sony.pm:8701-8708). `$val` is the SIGNED byte.
  if temp_test1 == Some(255)
    && let Some(&raw) = buf.get(0x04)
  {
    let signed = i64::from(raw as i8);
    let value = if print_conv {
      TagValue::Str(std::format!("{signed} C").into())
    } else {
      TagValue::I64(signed)
    };
    out.push(Tag9402Emission {
      name: "AmbientTemperature",
      value,
    });
  }

  // 0x0016 FocusMode — int8u, `Mask => 0x7f` (Sony.pm:8709-8720). After the Mask
  // `$val` is the masked byte, so a hash miss renders `"Unknown ($masked)"`.
  if let Some(&raw) = buf.get(0x16) {
    let masked = raw & 0x7f;
    let value = super::hash_print_value(masked, print_focus_mode(masked), print_conv);
    out.push(Tag9402Emission {
      name: "FocusMode",
      value,
    });
  }

  // 0x0017 AFAreaMode — int8u hash (Sony.pm:8721-8739).
  if let Some(&raw) = buf.get(0x17) {
    let value = super::hash_print_value(raw, print_af_area_mode(raw), print_conv);
    out.push(Tag9402Emission {
      name: "AFAreaMode",
      value,
    });
  }

  // 0x002d FocusPosition2 — int8u, `Condition => '$$self{Model} !~ /^(DSC-|
  // Stellar)/'` (Sony.pm:8782-8786). The FX3 is not a DSC-/Stellar body, so the
  // caller (which only reaches an `ILME-`/`ILCE-`/… body) always satisfies it.
  if let Some(&raw) = buf.get(0x2d) {
    out.push(Tag9402Emission {
      name: "FocusPosition2",
      value: TagValue::I64(i64::from(raw)),
    });
  }

  out
}

/// 0x0016 `FocusMode` PrintConv hash (`Sony.pm:8712-8719`).
fn print_focus_mode(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Manual",
    2 => "AF-S",
    3 => "AF-C",
    4 => "AF-A",
    6 => "DMF",
    _ => return None,
  })
}

/// `true` when the on-disk (enciphered) `0x9402` value selects the `Tag9402`
/// variant (`Sony.pm:1969`): the body is NOT SLT/HV/ILCA *and* the enciphered
/// first byte is neither `0x05` nor `0xff`. Tested against the RAW on-disk bytes
/// (the Perl `$$valPt` is pre-decipher) and the parent `$$self{Model}`.
#[must_use]
pub fn selects_tag9402(raw: &[u8], model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  if m.starts_with("SLT-") || m.starts_with("HV") || m.starts_with("ILCA-") {
    return false;
  }
  !matches!(raw.first(), Some(0x05 | 0xff))
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is relaxed for the test
// module, which indexes fixed-layout byte buffers directly (an out-of-range
// index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
#[path = "tag9402_tests.rs"]
mod tests;
