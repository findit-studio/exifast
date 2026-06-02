// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Canon::SensorInfo` (`Canon.pm:7411-7434`).
//!
//! Binary-data sub-table — `FORMAT => 'int16s'`, `FIRST_ENTRY => 1`,
//! `GROUPS => { 0 => 'MakerNotes', 2 => 'Image' }`. Reached via the
//! `Canon::Main` tag `0xe0` SubDirectory (`Canon.pm:1967-1973`) AND the
//! `CanonRaw::Main` tag `0x1031` SubDirectory (`CanonRaw.pm:149-153`).
//!
//! Named positions (`Canon.pm:7417-7433`): position 1 `SensorWidth`,
//! 2 `SensorHeight`, 5 `SensorLeftBorder`, 6 `SensorTopBorder`,
//! 7 `SensorRightBorder`, 8 `SensorBottomBorder`, 9 `BlackMaskLeftBorder`,
//! 10 `BlackMaskTopBorder`, 11 `BlackMaskRightBorder`,
//! 12 `BlackMaskBottomBorder`. Positions 0/3/4 (and any beyond 12) are
//! unnamed (no `tagInfo`), so bundled's `next unless defined $tagInfo`
//! emits nothing for them. None of these positions has a `PrintConv`, so the
//! `-j` and `-n` views are identical (the bare signed int).
//!
//! D8: this is a pure decoder (no public struct fields); it returns the
//! `(Name, TagValue)` emission pairs the dispatch site wraps in the
//! `Canon` family-1 group.

// Golden-v2 Contract 3c (Phase C, slice w2d): panic-safety by construction —
// every raw index/slice below is dominated by a preceding length/count guard
// and converted to a checked `.get()` form (re-asserts the parent `exif`
// deny over the makernotes subtree's slice-D/E `#![allow]` shim).
#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::ByteOrder;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

/// One named `SensorInfo` word position (`FORMAT => 'int16s'`).
struct SensorTag {
  /// The word position — byte offset `2 * position` from the blob start
  /// (ExifTool `ProcessBinaryData` indexes by `position * formatSize`; the
  /// `FIRST_ENTRY => 1` only suppresses position 0, it does NOT shift the
  /// offset, `Canon.pm:7414`).
  position: usize,
  /// `Name => '…'` (`Canon.pm:7417-7433`).
  name: &'static str,
}

/// The named `Canon::SensorInfo` positions (`Canon.pm:7417-7433`). No
/// `PrintConv` on any of them ⇒ each emits the bare signed int.
const SENSOR_TAGS: &[SensorTag] = &[
  SensorTag {
    position: 1,
    name: "SensorWidth",
  },
  SensorTag {
    position: 2,
    name: "SensorHeight",
  },
  SensorTag {
    position: 5,
    name: "SensorLeftBorder",
  },
  SensorTag {
    position: 6,
    name: "SensorTopBorder",
  },
  SensorTag {
    position: 7,
    name: "SensorRightBorder",
  },
  SensorTag {
    position: 8,
    name: "SensorBottomBorder",
  },
  SensorTag {
    position: 9,
    name: "BlackMaskLeftBorder",
  },
  SensorTag {
    position: 10,
    name: "BlackMaskTopBorder",
  },
  SensorTag {
    position: 11,
    name: "BlackMaskRightBorder",
  },
  SensorTag {
    position: 12,
    name: "BlackMaskBottomBorder",
  },
];

/// Decode the `Canon::SensorInfo` binary block (`Canon.pm:7411-7434`) into
/// the `(Name, TagValue)` emission pairs. `print_conv` is accepted for a
/// uniform sub-table signature; there is NO `PrintConv` here, so the result
/// is identical in `-j` and `-n` (the bare signed int per named position).
/// A position whose word is past the end of `data` is simply skipped
/// (bundled's `ReadValue` returns undef beyond the block).
#[must_use]
pub fn parse(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let _ = print_conv; // no PrintConv in this table
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  for t in SENSOR_TAGS {
    if let Some(raw) = read_i16(data, t.position, order) {
      out.push((SmolStr::new_static(t.name), TagValue::I64(raw)));
    }
  }
  out
}

/// Read one signed 16-bit word at word `position` (byte offset `2*position`).
fn read_i16(data: &[u8], position: usize, order: ByteOrder) -> Option<i64> {
  let off = 2 * position;
  // `get(off..off+2)` yields exactly 2 bytes, so `try_into()` to `[u8; 2]`
  // always succeeds — the checked, byte-identical form of `[b[0], b[1]]`.
  let arr: [u8; 2] = data.get(off..off + 2)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => i16::from_le_bytes(arr),
    ByteOrder::Big => i16::from_be_bytes(arr),
  } as i64)
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2d); the test fixtures index fixed-layout buffers freely
// (an out-of-range index is a test-assertion failure, not a shipped panic), so
// the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  /// The real `CanonRaw.crw` / `MakerNotes_Canon.jpg` SensorInfo block
  /// (int16s words, position 0 = byte-length 34). Oracle (`perl exiftool
  /// -G1 -j`): SensorWidth 3152, SensorHeight 2068, SensorLeftBorder 72,
  /// SensorTopBorder 16, SensorRightBorder 3143, SensorBottomBorder 2063,
  /// BlackMaskLeftBorder 24, BlackMaskTopBorder 224, BlackMaskRightBorder 40,
  /// BlackMaskBottomBorder 1856.
  fn build(words: &[i16], order: ByteOrder) -> Vec<u8> {
    let mut v = Vec::new();
    for w in words {
      match order {
        ByteOrder::Little => v.extend_from_slice(&w.to_le_bytes()),
        ByteOrder::Big => v.extend_from_slice(&w.to_be_bytes()),
      }
    }
    v
  }

  #[test]
  fn decodes_300d_sensor_block() {
    // word[0]=34 (length), [1]=3152, [2]=2068, [3]=1, [4]=1, [5]=72, [6]=16,
    // [7]=3143, [8]=2063, [9]=24, [10]=224, [11]=40, [12]=1856.
    let words = [
      34i16, 3152, 2068, 1, 1, 72, 16, 3143, 2063, 24, 224, 40, 1856, 0, 0, 0, 0,
    ];
    let data = build(&words, ByteOrder::Little);
    let em = parse(&data, ByteOrder::Little, true);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("SensorWidth"), Some(TagValue::I64(3152)));
    assert_eq!(find("SensorHeight"), Some(TagValue::I64(2068)));
    assert_eq!(find("SensorLeftBorder"), Some(TagValue::I64(72)));
    assert_eq!(find("SensorTopBorder"), Some(TagValue::I64(16)));
    assert_eq!(find("SensorRightBorder"), Some(TagValue::I64(3143)));
    assert_eq!(find("SensorBottomBorder"), Some(TagValue::I64(2063)));
    assert_eq!(find("BlackMaskLeftBorder"), Some(TagValue::I64(24)));
    assert_eq!(find("BlackMaskTopBorder"), Some(TagValue::I64(224)));
    assert_eq!(find("BlackMaskRightBorder"), Some(TagValue::I64(40)));
    assert_eq!(find("BlackMaskBottomBorder"), Some(TagValue::I64(1856)));
    // Positions 0/3/4 are unnamed → no emission.
    assert_eq!(em.len(), 10);
    // `-n` is identical (no PrintConv).
    let em_n = parse(&data, ByteOrder::Little, false);
    assert_eq!(em, em_n);
  }

  #[test]
  fn big_endian_round_trip() {
    let words = [34i16, 100, 200, 0, 0, 5, 6, 7, 8, 9, 10, 11, 12];
    let data = build(&words, ByteOrder::Big);
    let em = parse(&data, ByteOrder::Big, true);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("SensorWidth"), Some(TagValue::I64(100)));
    assert_eq!(find("BlackMaskBottomBorder"), Some(TagValue::I64(12)));
  }

  #[test]
  fn truncated_block_skips_missing_positions() {
    // Only enough for position 0,1,2 (6 bytes).
    let words = [34i16, 3152, 2068];
    let data = build(&words, ByteOrder::Little);
    let em = parse(&data, ByteOrder::Little, true);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(find("SensorWidth"), Some(TagValue::I64(3152)));
    assert_eq!(find("SensorHeight"), Some(TagValue::I64(2068)));
    // Beyond position 2 → nothing.
    assert!(find("SensorLeftBorder").is_none());
    assert_eq!(em.len(), 2);
  }
}
