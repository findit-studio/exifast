// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::Tag9403` (`Sony.pm:8792-8818`) — the enciphered
//! `Tag9403` `ProcessBinaryData` block (camera/sensor temperature).
//!
//! The `0x9403` Main-table row is an UNCONDITIONAL SubDirectory
//! (`Sony.pm:1975-1978`): every body that writes `0x9403` routes here. The
//! block is enciphered (`PROCESS_PROC => \&ProcessEnciphered`, `Sony.pm:8793`)
//! so the dispatcher
//! [`process_enciphered`](super::decipher::process_enciphered)s it (once, or
//! twice for a double-enciphered body) and hands this table the DECIPHERED
//! bytes; `FORMAT => 'int8u'` + `FIRST_ENTRY => 0` (`Sony.pm:8796,8798`).
//!
//! Per the `ProcessBinaryData` contract each tag is emitted IFF its byte range
//! is in the deciphered block ([[exifast-processbinarydata-per-field]]). The
//! `0x04` `TempTest2` DataMember is `Hidden => 1` with a `RawConv` that returns
//! `undef` unless `Unknown >= 2` (`Sony.pm:8804-8807`), so it is NEVER emitted;
//! it only gates `0x05` `CameraTemperature`. The real ILME-FX3 writes a 4-byte
//! `0x9403` block (offsets `0..3`), so NEITHER field is in range and the table
//! emits nothing — matching ExifTool's empty `Tag9403` directory for the FX3.

use crate::value::TagValue;

/// One emitted `Tag9403` leaf — the resolved tag name and rendered value.
pub struct Tag9403Emission {
  /// `Name => '…'` from the bundled table.
  pub name: &'static str,
  /// The rendered value (`-j` PrintConv result, or `-n` raw `$val`).
  pub value: TagValue,
}

/// Walk the DECIPHERED `Tag9403` block and emit `CameraTemperature`.
///
/// `buf` is the DECIPHERED `0x9403` block — the dispatcher already ran
/// [`process_enciphered`](super::decipher::process_enciphered) (twice for a
/// double-enciphered body). `print_conv` selects `-j` (PrintConv) vs `-n` (raw
/// `$val`).
#[must_use]
pub fn parse_tag9403(buf: &[u8], print_conv: bool) -> Vec<Tag9403Emission> {
  let mut out = std::vec::Vec::new();

  // 0x04 TempTest2 — int8u DataMember, `Hidden => 1` + `RawConv` keeps it
  // `undef` unless `Unknown >= 2` (Sony.pm:8801-8808), so it is never emitted;
  // its int8u value only gates 0x05.
  let temp_test2 = buf.get(0x04).copied();

  // 0x05 CameraTemperature — int8s, `Condition => '$$self{TempTest2} and
  // $$self{TempTest2} < 100'` (Sony.pm:8809-8815): emitted only when TempTest2
  // is non-zero AND < 100. `PrintConv => '"$val C"'`; `$val` is the SIGNED byte.
  if let Some(tt2) = temp_test2
    && tt2 != 0
    && tt2 < 100
    && let Some(&raw) = buf.get(0x05)
  {
    let signed = i64::from(raw as i8);
    let value = if print_conv {
      TagValue::Str(std::format!("{signed} C").into())
    } else {
      TagValue::I64(signed)
    };
    out.push(Tag9403Emission {
      name: "CameraTemperature",
      value,
    });
  }

  out
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is relaxed for the test
// module, which indexes fixed-layout byte buffers directly (an out-of-range
// index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
#[path = "tag9403_tests.rs"]
mod tests;
