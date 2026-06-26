// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::Tag202a` (`Sony.pm:7407-7450`) — the (un-enciphered)
//! `Tag202a` `ProcessBinaryData` block: the FocalPlaneAFPointsUsed grid, first
//! seen for the ILCE-6300 and written by newer bodies incl. the ILME-FX3.
//!
//! The `0x202a` Main-table row is a SubDirectory dispatcher gated on
//! `Condition => '$$valPt =~ /^\x01/'` (`Sony.pm:1575`) — the first value byte
//! must be `0x01`. This block is NOT enciphered (a plain `%binaryDataAttrs`
//! table, `Sony.pm:7408`); `FORMAT => 'int8u'`, `FIRST_ENTRY => 0`,
//! `DATAMEMBER => [0x01]` (`Sony.pm:7410-7411`).
//!
//! `0x01 FocalPlaneAFPointsUsed` (int8u, `DataMember => 'Locations'`,
//! `RawConv => '$$self{Locations} = $val'`) is the count of AF-point locations
//! that follow; the per-location leaves (`FocalPlaneAFPointArea`,
//! `FocalPlaneAFPointLocation1..15`) are each `Condition => '$$self{Locations}
//! >= N'` (`Sony.pm:7430-7449`). The FX3 fixture has `Locations = 0`, so ONLY
//! `FocalPlaneAFPointsUsed` is emitted; the location leaves are gated out
//! ([[exifast-processbinarydata-per-field]]). The per-location int16u[2] leaves
//! are not ported (no real-device golden needs them); a non-zero-Locations body
//! simply omits them here.

use crate::value::TagValue;

/// One emitted `Tag202a` leaf — the resolved tag name and rendered value.
pub struct Tag202aEmission {
  /// `Name => '…'` from the bundled table.
  pub name: &'static str,
  /// The rendered value (`-j` PrintConv result, or `-n` raw `$val`).
  pub value: TagValue,
}

/// Walk the `Tag202a` block and emit `FocalPlaneAFPointsUsed`.
///
/// `buf` is the on-disk `0x202a` value bytes (NOT enciphered). The caller has
/// already confirmed the `0x01` first-byte gate ([`selects_tag202a`]).
/// `print_conv` is irrelevant here (no PrintConv on the ported leaf) but kept
/// for call-site symmetry with the other Sony sub-block parsers.
#[must_use]
pub fn parse_tag202a(buf: &[u8], _print_conv: bool) -> Vec<Tag202aEmission> {
  let mut out = std::vec::Vec::new();

  // 0x01 FocalPlaneAFPointsUsed — int8u (Sony.pm:7424-7429). No PrintConv: the
  // raw count is emitted in both `-j` and `-n`.
  if let Some(&raw) = buf.get(0x01) {
    out.push(Tag202aEmission {
      name: "FocalPlaneAFPointsUsed",
      value: TagValue::I64(i64::from(raw)),
    });
  }

  out
}

/// `true` when the `0x202a` value selects the `Tag202a` SubDirectory
/// (`Sony.pm:1575`): the first value byte is `0x01`.
#[must_use]
pub fn selects_tag202a(buf: &[u8]) -> bool {
  matches!(buf.first(), Some(0x01))
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is relaxed for the test
// module, which indexes fixed-layout byte buffers directly (an out-of-range
// index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
#[path = "tag202a_tests.rs"]
mod tests;
