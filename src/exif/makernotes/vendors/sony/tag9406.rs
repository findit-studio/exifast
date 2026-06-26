// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::Tag9406` (`Sony.pm:9199-9246`) — the enciphered
//! `Tag9406` `ProcessBinaryData` block (battery temperature / level info for
//! most SLT/ILCA and NEX/ILCE bodies, incl. the ILME-FX3).
//!
//! The `0x9406` Main-table row is a conditional-ARRAY SubDirectory dispatcher
//! (`Sony.pm:2038-2054`): the `Tag9406` table is selected when the
//! (still-enciphered) first value byte is `0x01`/`0x08`/`0x1b` AND the third
//! value byte is `0x08`/`0x1b` (`Condition => '$$valPt =~ /^[\x01\x08\x1b].[\x08\x1b]/s'`,
//! `Sony.pm:2044`). The FX3 enciphered prefix is `1b 50 08` (deciphering to
//! `03 9b 02`), so it matches the `Tag9406` branch (NOT the `Tag9406b` `0x40`
//! variant). The block is enciphered (`PROCESS_PROC => \&ProcessEnciphered`,
//! `Sony.pm:9201`) so it is [`super::decipher::deciphered_block`]ed before this
//! table reads it; `FORMAT => 'int8u'` + `FIRST_ENTRY => 0`
//! (`Sony.pm:9204,9206`).
//!
//! Per the `ProcessBinaryData` contract each tag is emitted IFF its byte range
//! is in the deciphered block ([[exifast-processbinarydata-per-field]]). Only
//! the camera-metadata leaves the FX3 activation golden needs are ported here
//! (`BatteryTemperature`, `BatteryLevel`); the grip-battery leaves
//! `BatteryLevelGrip1`/`BatteryLevelGrip2` carry `RawConv` undef-guards
//! (`Sony.pm:9223,9239` — only valid when non-zero / not 0|255) that drop them
//! for the FX3 (both are 0), matching the golden.

use super::decipher::deciphered_block;
use crate::value::TagValue;

/// One emitted `Tag9406` leaf — the resolved tag name and rendered value.
pub struct Tag9406Emission {
  /// `Name => '…'` from the bundled table.
  pub name: &'static str,
  /// The rendered value (`-j` PrintConv result, or `-n` raw `$val`).
  pub value: TagValue,
}

/// Walk the DECIPHERED `Tag9406` block and emit the battery leaves the FX3
/// activation golden needs.
///
/// `src` is the on-disk (enciphered) `0x9406` value bytes; the caller has
/// already confirmed the variant gate ([`selects_tag9406`]). `print_conv`
/// selects `-j` (PrintConv) vs `-n` (raw `$val`).
#[must_use]
pub fn parse_tag9406(src: &[u8], print_conv: bool) -> Vec<Tag9406Emission> {
  let buf = deciphered_block(src, 0, src.len());
  let mut out = std::vec::Vec::new();

  // 0x0005 BatteryTemperature — int8u, `ValueConv => '($val - 32) / 1.8'` (to
  // Celsius), `PrintConv => 'sprintf("%.1f C",$val)'` (Sony.pm:9213-9219).
  if let Some(&raw) = buf.get(0x05) {
    let celsius = (f64::from(raw) - 32.0) / 1.8;
    let value = if print_conv {
      TagValue::Str(std::format!("{celsius:.1} C").into())
    } else {
      TagValue::F64(celsius)
    };
    out.push(Tag9406Emission {
      name: "BatteryTemperature",
      value,
    });
  }

  // 0x0006 BatteryLevelGrip1 — int8u, `RawConv => '$val ? $val : undef'` (only
  // valid when non-zero), `PrintConv => '"$val%"'` (Sony.pm:9221-9226).
  if let Some(&raw) = buf.get(0x06)
    && raw != 0
  {
    let value = if print_conv {
      TagValue::Str(std::format!("{raw}%").into())
    } else {
      TagValue::I64(i64::from(raw))
    };
    out.push(Tag9406Emission {
      name: "BatteryLevelGrip1",
      value,
    });
  }

  // 0x0007 BatteryLevel — int8u, `PrintConv => '"$val%"'` (Sony.pm:9228-9232).
  if let Some(&raw) = buf.get(0x07) {
    let value = if print_conv {
      TagValue::Str(std::format!("{raw}%").into())
    } else {
      TagValue::I64(i64::from(raw))
    };
    out.push(Tag9406Emission {
      name: "BatteryLevel",
      value,
    });
  }

  // 0x0008 BatteryLevelGrip2 — int8u, `Condition => '$$self{Model} !~
  // /^(ILCE-(7|7R)|Lusso)$/'`, `RawConv => '($val and $val != 255) ? $val :
  // undef'` (Sony.pm:9236-9242). The FX3 is not an ILCE-7/7R/Lusso body, so the
  // Condition holds; the RawConv drops 0 and 255.
  if let Some(&raw) = buf.get(0x08)
    && raw != 0
    && raw != 255
  {
    let value = if print_conv {
      TagValue::Str(std::format!("{raw}%").into())
    } else {
      TagValue::I64(i64::from(raw))
    };
    out.push(Tag9406Emission {
      name: "BatteryLevelGrip2",
      value,
    });
  }

  out
}

/// `true` when the on-disk (enciphered) `0x9406` value selects the `Tag9406`
/// variant (`Sony.pm:2044`): `$$valPt =~ /^[\x01\x08\x1b].[\x08\x1b]/s` — the
/// enciphered first byte is `0x01`/`0x08`/`0x1b` AND the third byte is
/// `0x08`/`0x1b`. Tested against the RAW on-disk bytes (the Perl `$$valPt` is
/// pre-decipher).
#[must_use]
pub fn selects_tag9406(raw: &[u8]) -> bool {
  matches!(raw.first(), Some(0x01 | 0x08 | 0x1b)) && matches!(raw.get(2), Some(0x08 | 0x1b))
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is relaxed for the test
// module, which indexes fixed-layout byte buffers directly (an out-of-range
// index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
#[path = "tag9406_tests.rs"]
mod tests;
