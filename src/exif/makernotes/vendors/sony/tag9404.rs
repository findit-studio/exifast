// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::Tag9404a`/`Tag9404b`/`Tag9404c`
//! (`Sony.pm:8821-8876`) — the enciphered `Tag9404` `ProcessBinaryData` blocks
//! (ExposureProgram / IntelligentAuto / LensZoomPosition / FocusPosition2).
//!
//! The `0x9404` Main-table row is a conditional-ARRAY SubDirectory dispatcher
//! (`Sony.pm:1990-2008`) selected by the (still-enciphered) first and fourth
//! value bytes:
//!
//! - `Tag9404a` — `$$valPt =~ /^[\x40\x7d]..\x01/` (first byte `0x40`/`0x7d`
//!   = deciphered 4/5, fourth byte `0x01`).
//! - `Tag9404b` — `$$valPt =~ /^[\xe7\xea\xcd\x8a\x70]..\x08/` (first byte
//!   = deciphered 9/12/13/15/16, fourth byte `0x08` = deciphered 2).
//! - `Tag9404c` — `$$valPt =~ /^\xb6..\x01/` (first byte = deciphered 17,
//!   fourth byte `0x01`).
//! - else `Sony_0x9404` (`%unknownCipherData`) — emits nothing.
//!
//! Each regex has two `.` wildcards at value bytes 1 and 2; with NO `/s` flag a
//! `.` matches any byte EXCEPT newline (`0x0a`), so a block with `0x0a` at byte
//! 1 or 2 fails the gate and falls through to `Sony_0x9404` (emits nothing).
//!
//! The variant gate is tested on the RAW on-disk (pre-decipher) bytes (the
//! Perl `$$valPt` is pre-decipher); the dispatcher then
//! [`process_enciphered`](super::decipher::process_enciphered)s the block (once,
//! or twice for a double-enciphered body) and hands the per-variant parser the
//! DECIPHERED bytes. `FORMAT => 'int8u'` + `FIRST_ENTRY => 0`.
//!
//! Per the `ProcessBinaryData` contract each tag is emitted IFF its byte range
//! is in the deciphered block ([[exifast-processbinarydata-per-field]]) AND its
//! per-leaf model `Condition` holds. The real ILME-FX3's `0x9404` matches none
//! of the three variant gates (ExifTool dispatches it as `Sony_0x9404`), so this
//! module emits nothing for the FX3.

use crate::value::TagValue;

/// One emitted `Tag9404` leaf — the resolved tag name and rendered value.
pub struct Tag9404Emission {
  /// `Name => '…'` from the bundled table.
  pub name: &'static str,
  /// The rendered value (`-j` PrintConv result, or `-n` raw `$val`).
  pub value: TagValue,
}

/// Read a little-endian `int16u` at byte `off` of the deciphered block.
fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
  match buf.get(off..off.checked_add(2)?) {
    Some(&[a, b]) => Some(u16::from_le_bytes([a, b])),
    _ => None,
  }
}

/// `IntelligentAuto` PrintConv hash (`Sony.pm:8830`/`8850`/`8875`):
/// `{ 0 => 'Off', 1 => 'On' }`. `None` for an unmapped value (the hash-PrintConv
/// miss renders `"Unknown ($val)"` in `-j` via [`super::hash_print_value`]).
fn print_intelligent_auto(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    1 => "On",
    _ => return None,
  })
}

/// `LensZoomPosition` rendered value — `int16u`, `PrintConv =>
/// 'sprintf("%.0f%%",$val/10.24)'` (`Sony.pm:8835`/`8855`). `-n` keeps the raw
/// `int16u` (no ValueConv on this row).
fn lens_zoom_position_value(raw: u16, print_conv: bool) -> TagValue {
  if print_conv {
    TagValue::Str(std::format!("{:.0}%", f64::from(raw) / 10.24).into())
  } else {
    TagValue::I64(i64::from(raw))
  }
}

/// `$$self{Model} =~ /^SLT-/` — the `Tag9404a` `LensZoomPosition` exclusion
/// (`Sony.pm:8834`: the leaf is valid only when the model is NOT an SLT body).
/// A `None` model does NOT match (`undef !~ /…/` is true), so the leaf is valid.
fn model_is_slt(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.starts_with("SLT-"))
}

/// `$$self{Model} =~ /^(SLT-|HV|ILCA-)/` — the `Tag9404b` phase-detect body
/// class (`Sony.pm:8854`/`8861`): `LensZoomPosition` is excluded for these
/// bodies, `FocusPosition2` is valid only for them.
fn model_is_slt_hv_ilca(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.starts_with("SLT-") || m.starts_with("HV") || m.starts_with("ILCA-"))
}

/// Perl `.` WITHOUT the `/s` flag (`Sony.pm:1993`/`1998`/`2003` carry no `/s`):
/// the byte at `off` must EXIST and must not be the newline `0x0a` — a `.`
/// matches any single character except `\n`.
fn dot_no_newline(raw: &[u8], off: usize) -> bool {
  matches!(raw.get(off), Some(&b) if b != b'\n')
}

/// `true` when the on-disk (enciphered) `0x9404` value selects `Tag9404a`
/// (`Sony.pm:1993`, `/^[\x40\x7d]..\x01/`): first byte `0x40`/`0x7d`, bytes 1+2
/// non-newline (`.` without `/s`), fourth byte `0x01`. Tested against the RAW
/// on-disk bytes (the Perl `$$valPt` is pre-decipher).
#[must_use]
pub fn selects_tag9404a(raw: &[u8]) -> bool {
  matches!(raw.first(), Some(0x40 | 0x7d))
    && dot_no_newline(raw, 1)
    && dot_no_newline(raw, 2)
    && raw.get(3) == Some(&0x01)
}

/// `true` when the on-disk (enciphered) `0x9404` value selects `Tag9404b`
/// (`Sony.pm:1998`, `/^[\xe7\xea\xcd\x8a\x70]..\x08/`): first byte
/// `0xe7`/`0xea`/`0xcd`/`0x8a`/`0x70`, bytes 1+2 non-newline (`.` without `/s`),
/// fourth byte `0x08`. Tested against the RAW on-disk bytes.
#[must_use]
pub fn selects_tag9404b(raw: &[u8]) -> bool {
  matches!(raw.first(), Some(0xe7 | 0xea | 0xcd | 0x8a | 0x70))
    && dot_no_newline(raw, 1)
    && dot_no_newline(raw, 2)
    && raw.get(3) == Some(&0x08)
}

/// `true` when the on-disk (enciphered) `0x9404` value selects `Tag9404c`
/// (`Sony.pm:2003`, `/^\xb6..\x01/`): first byte `0xb6`, bytes 1+2 non-newline
/// (`.` without `/s`), fourth byte `0x01`. Tested against the RAW on-disk bytes.
#[must_use]
pub fn selects_tag9404c(raw: &[u8]) -> bool {
  raw.first() == Some(&0xb6)
    && dot_no_newline(raw, 1)
    && dot_no_newline(raw, 2)
    && raw.get(3) == Some(&0x01)
}

/// Walk the DECIPHERED `Tag9404a` block (`Sony.pm:8821-8838`).
#[must_use]
pub fn parse_tag9404a(buf: &[u8], model: Option<&str>, print_conv: bool) -> Vec<Tag9404Emission> {
  let mut out = std::vec::Vec::new();

  // 0x000b ExposureProgram — int8u, %sonyExposureProgram3 (Sony.pm:8829).
  if let Some(&raw) = buf.get(0x0b) {
    out.push(Tag9404Emission {
      name: "ExposureProgram",
      value: super::hash_print_value(raw, super::print_exposure_program3(raw), print_conv),
    });
  }

  // 0x000d IntelligentAuto — int8u hash (Sony.pm:8830).
  if let Some(&raw) = buf.get(0x0d) {
    out.push(Tag9404Emission {
      name: "IntelligentAuto",
      value: super::hash_print_value(raw, print_intelligent_auto(raw), print_conv),
    });
  }

  // 0x0019 LensZoomPosition — int16u, `Condition => '$$self{Model} !~ /^SLT-/'`
  // (Sony.pm:8831-8837).
  if !model_is_slt(model)
    && let Some(raw) = read_u16(buf, 0x19)
  {
    out.push(Tag9404Emission {
      name: "LensZoomPosition",
      value: lens_zoom_position_value(raw, print_conv),
    });
  }

  out
}

/// Walk the DECIPHERED `Tag9404b` block (`Sony.pm:8841-8863`).
#[must_use]
pub fn parse_tag9404b(buf: &[u8], model: Option<&str>, print_conv: bool) -> Vec<Tag9404Emission> {
  let mut out = std::vec::Vec::new();

  // 0x000c ExposureProgram — int8u, %sonyExposureProgram3 (Sony.pm:8849).
  if let Some(&raw) = buf.get(0x0c) {
    out.push(Tag9404Emission {
      name: "ExposureProgram",
      value: super::hash_print_value(raw, super::print_exposure_program3(raw), print_conv),
    });
  }

  // 0x000e IntelligentAuto — int8u hash (Sony.pm:8850).
  if let Some(&raw) = buf.get(0x0e) {
    out.push(Tag9404Emission {
      name: "IntelligentAuto",
      value: super::hash_print_value(raw, print_intelligent_auto(raw), print_conv),
    });
  }

  // 0x001e LensZoomPosition — int16u, `Condition => '$$self{Model} !~
  // /^(SLT-|HV|ILCA-)/'` (Sony.pm:8851-8857).
  if !model_is_slt_hv_ilca(model)
    && let Some(raw) = read_u16(buf, 0x1e)
  {
    out.push(Tag9404Emission {
      name: "LensZoomPosition",
      value: lens_zoom_position_value(raw, print_conv),
    });
  }

  // 0x0020 FocusPosition2 — int8u, `Condition => '$$self{Model} =~
  // /^(SLT-|HV|ILCA-)/'` (Sony.pm:8858-8862). No PrintConv ⇒ raw in both modes.
  if model_is_slt_hv_ilca(model)
    && let Some(&raw) = buf.get(0x20)
  {
    out.push(Tag9404Emission {
      name: "FocusPosition2",
      value: TagValue::I64(i64::from(raw)),
    });
  }

  out
}

/// Walk the DECIPHERED `Tag9404c` block (`Sony.pm:8866-8876`).
#[must_use]
pub fn parse_tag9404c(buf: &[u8], print_conv: bool) -> Vec<Tag9404Emission> {
  let mut out = std::vec::Vec::new();

  // 0x000b ExposureProgram — int8u, %sonyExposureProgram3 (Sony.pm:8874).
  if let Some(&raw) = buf.get(0x0b) {
    out.push(Tag9404Emission {
      name: "ExposureProgram",
      value: super::hash_print_value(raw, super::print_exposure_program3(raw), print_conv),
    });
  }

  // 0x000d IntelligentAuto — int8u hash (Sony.pm:8875).
  if let Some(&raw) = buf.get(0x0d) {
    out.push(Tag9404Emission {
      name: "IntelligentAuto",
      value: super::hash_print_value(raw, print_intelligent_auto(raw), print_conv),
    });
  }

  out
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is relaxed for the test
// module, which indexes fixed-layout byte buffers directly (an out-of-range
// index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
#[path = "tag9404_tests.rs"]
mod tests;
