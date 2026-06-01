// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Canon::ColorBalance` (`Canon.pm:7268-7293`).
//!
//! Binary-data sub-table — `FORMAT => 'int16s'`, `FIRST_ENTRY => 0`,
//! `GROUPS => { 0 => 'MakerNotes', 2 => 'Camera' }`, `NOTES => 'These tags
//! are used by the 10D and 300D.'`. Reached via the `Canon::Main` tag `0xa9`
//! SubDirectory (`Canon.pm:1907-1912`) AND the `CanonRaw::Main` tag `0x10a9`
//! SubDirectory (`CanonRaw.pm:203-207`).
//!
//! Each named position is a `Format => 'int16s[4]'` quad (red, green1,
//! green2, blue, ref 2) rendered as ExifTool's default space-joined string
//! (e.g. `"1740 832 831 931"`). Positions (`Canon.pm:7275-7292`):
//!
//! | pos | tag |
//! |-----|-----|
//! | 1   | `WB_RGGBLevelsAuto` |
//! | 5   | `WB_RGGBLevelsDaylight` |
//! | 9   | `WB_RGGBLevelsShade` |
//! | 13  | `WB_RGGBLevelsCloudy` |
//! | 17  | `WB_RGGBLevelsTungsten` |
//! | 21  | `WB_RGGBLevelsFluorescent` |
//! | 25  | `WB_RGGBLevelsFlash` |
//! | 29  | `WB_RGGBLevelsCustom` (model ≠ D60) / `BlackLevels` (D60) |
//! | 33  | `WB_RGGBLevelsKelvin` |
//! | 37  | `WB_RGGBBlackLevels` |
//!
//! Position 29 is a CONDITIONAL list (`Canon.pm:7282-7290`): for a body whose
//! `$$self{Model}` is NOT an `EOS D60` the name is `WB_RGGBLevelsCustom`; for
//! a D60 it is `BlackLevels` (the D60 stores black levels there, ref IB).
//! There is NO `PrintConv` on any position, so the `-j` and `-n` views are
//! identical (the space-joined signed list).
//!
//! D8: pure decoder (no public struct fields); returns the `(Name,
//! TagValue)` emission pairs the dispatch site wraps in the `Canon`
//! family-1 group.

use crate::exif::ifd::ByteOrder;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::string::String;
use std::vec::Vec;

/// One named `ColorBalance` position — an `int16s[4]` quad whose `Name` may
/// depend on the body `Model` (position 29 only).
struct ColorBalanceTag {
  /// Word position — byte offset `2 * position` (`FIRST_ENTRY => 0` ⇒ no
  /// offset shift; `Canon.pm:7272`).
  position: usize,
  /// `Name => '…'` for a non-D60 body (the common case).
  name: &'static str,
  /// `Name` override for an `EOS D60` body (only set for position 29, where
  /// the D60 stores `BlackLevels` instead of `WB_RGGBLevelsCustom`,
  /// `Canon.pm:7282-7290`). `None` ⇒ `name` is used unconditionally.
  d60_name: Option<&'static str>,
}

/// The named `Canon::ColorBalance` positions (`Canon.pm:7275-7292`). Each is
/// an `int16s[4]` quad; no `PrintConv`.
const COLOR_BALANCE_TAGS: &[ColorBalanceTag] = &[
  ColorBalanceTag {
    position: 1,
    name: "WB_RGGBLevelsAuto",
    d60_name: None,
  },
  ColorBalanceTag {
    position: 5,
    name: "WB_RGGBLevelsDaylight",
    d60_name: None,
  },
  ColorBalanceTag {
    position: 9,
    name: "WB_RGGBLevelsShade",
    d60_name: None,
  },
  ColorBalanceTag {
    position: 13,
    name: "WB_RGGBLevelsCloudy",
    d60_name: None,
  },
  ColorBalanceTag {
    position: 17,
    name: "WB_RGGBLevelsTungsten",
    d60_name: None,
  },
  ColorBalanceTag {
    position: 21,
    name: "WB_RGGBLevelsFluorescent",
    d60_name: None,
  },
  ColorBalanceTag {
    position: 25,
    name: "WB_RGGBLevelsFlash",
    d60_name: None,
  },
  // Position 29: conditional list (`Canon.pm:7282-7290`).
  ColorBalanceTag {
    position: 29,
    name: "WB_RGGBLevelsCustom",
    d60_name: Some("BlackLevels"),
  },
  ColorBalanceTag {
    position: 33,
    name: "WB_RGGBLevelsKelvin",
    d60_name: None,
  },
  ColorBalanceTag {
    position: 37,
    name: "WB_RGGBBlackLevels",
    d60_name: None,
  },
];

/// `true` when `model` matches the bundled `EOS D60\b` regex
/// (`Canon.pm:7285`) — i.e. an exact `EOS D60` word boundary (so `EOS D60`
/// and `Canon EOS D60` match, `EOS D600`/`EOS D6000` do NOT). Used only to
/// pick the position-29 name.
fn model_is_eos_d60(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  // `/EOS D60\b/`: find "EOS D60" then require a non-word char (or end) after.
  let needle = "EOS D60";
  let bytes = m.as_bytes();
  let nb = needle.as_bytes();
  let mut i = 0;
  while i + nb.len() <= bytes.len() {
    if &bytes[i..i + nb.len()] == nb {
      // `\b` after position: next char must be a non-word char or end-of-string.
      match bytes.get(i + nb.len()) {
        None => return true,
        Some(&c) => {
          let is_word = c.is_ascii_alphanumeric() || c == b'_';
          if !is_word {
            return true;
          }
        }
      }
    }
    i += 1;
  }
  false
}

/// Decode the `Canon::ColorBalance` binary block (`Canon.pm:7268-7293`) into
/// the `(Name, TagValue)` emission pairs. Each named position is an
/// `int16s[4]` quad rendered space-joined; `model` only selects the
/// position-29 name (`WB_RGGBLevelsCustom` vs the D60 `BlackLevels`).
///
/// There is no `PrintConv`, so `print_conv` does not change the result (the
/// `-j` and `-n` views are identical, accepted only for the uniform
/// sub-table signature). A quad whose four words are not all present is
/// skipped (bundled's `ReadValue` returns undef past the block).
#[must_use]
pub fn parse(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
) -> Vec<(SmolStr, TagValue)> {
  let _ = print_conv; // no PrintConv in this table
  let is_d60 = model_is_eos_d60(model);
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  for t in COLOR_BALANCE_TAGS {
    if let Some(quad) = read_i16x4(data, t.position, order) {
      let name = if is_d60 {
        t.d60_name.unwrap_or(t.name)
      } else {
        t.name
      };
      out.push((
        SmolStr::new_static(name),
        TagValue::Str(SmolStr::from(join_i16(&quad))),
      ));
    }
  }
  out
}

/// Read four consecutive signed 16-bit words starting at word `position`
/// (`Format => 'int16s[4]'`, byte offset `2*position`). Returns `None` if
/// any of the four words is past the end of `data`.
fn read_i16x4(data: &[u8], position: usize, order: ByteOrder) -> Option<[i16; 4]> {
  let mut quad = [0i16; 4];
  for (i, slot) in quad.iter_mut().enumerate() {
    let off = 2 * (position + i);
    let b = data.get(off..off + 2)?;
    let arr = [b[0], b[1]];
    *slot = match order {
      ByteOrder::Little => i16::from_le_bytes(arr),
      ByteOrder::Big => i16::from_be_bytes(arr),
    };
  }
  Some(quad)
}

/// Render an `int16s[4]` quad as ExifTool's default space-joined string
/// (e.g. `"1740 832 831 931"`).
fn join_i16(words: &[i16]) -> String {
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

#[cfg(test)]
mod tests {
  use super::*;

  /// Build a ColorBalance blob from int16s words (little-endian).
  fn build(words: &[i16]) -> Vec<u8> {
    let mut v = Vec::new();
    for w in words {
      v.extend_from_slice(&w.to_le_bytes());
    }
    v
  }

  /// The real `CanonRaw.crw` / `MakerNotes_Canon.jpg` ColorBalance block
  /// (int16s, position 0 = byte-length 82). Oracle (`perl exiftool -G1 -j`
  /// on `CanonRaw.crw`).
  const CRW_WORDS: &[i16] = &[
    82, // pos 0 (length, unnamed)
    1740, 832, 831, 931, // 1 Auto
    1722, 832, 831, 989, // 5 Daylight
    2035, 832, 831, 839, // 9 Shade
    1878, 832, 831, 903, // 13 Cloudy
    1228, 913, 912, 1668, // 17 Tungsten
    1506, 842, 841, 1381, // 21 Fluorescent
    1964, 832, 831, 877, // 25 Flash
    1722, 832, 831, 989, // 29 Custom (300D ⇒ WB_RGGBLevelsCustom)
    1722, 832, 831, 988, // 33 Kelvin
    125, 124, 125, 124, // 37 WB_RGGBBlackLevels
  ];

  #[test]
  fn decodes_300d_color_balance() {
    let data = build(CRW_WORDS);
    let em = parse(
      &data,
      ByteOrder::Little,
      true,
      Some("Canon EOS DIGITAL REBEL"),
    );
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(
      find("WB_RGGBLevelsAuto"),
      Some(TagValue::Str("1740 832 831 931".into()))
    );
    assert_eq!(
      find("WB_RGGBLevelsDaylight"),
      Some(TagValue::Str("1722 832 831 989".into()))
    );
    assert_eq!(
      find("WB_RGGBLevelsShade"),
      Some(TagValue::Str("2035 832 831 839".into()))
    );
    assert_eq!(
      find("WB_RGGBLevelsTungsten"),
      Some(TagValue::Str("1228 913 912 1668".into()))
    );
    assert_eq!(
      find("WB_RGGBLevelsFlash"),
      Some(TagValue::Str("1964 832 831 877".into()))
    );
    // Non-D60 ⇒ position 29 is WB_RGGBLevelsCustom (NOT BlackLevels).
    assert_eq!(
      find("WB_RGGBLevelsCustom"),
      Some(TagValue::Str("1722 832 831 989".into()))
    );
    assert!(find("BlackLevels").is_none());
    assert_eq!(
      find("WB_RGGBLevelsKelvin"),
      Some(TagValue::Str("1722 832 831 988".into()))
    );
    assert_eq!(
      find("WB_RGGBBlackLevels"),
      Some(TagValue::Str("125 124 125 124".into()))
    );
    // 10 named positions present.
    assert_eq!(em.len(), 10);
    // `-n` is identical (no PrintConv).
    let em_n = parse(
      &data,
      ByteOrder::Little,
      false,
      Some("Canon EOS DIGITAL REBEL"),
    );
    assert_eq!(em, em_n);
  }

  #[test]
  fn d60_position_29_is_black_levels() {
    let data = build(CRW_WORDS);
    let em = parse(&data, ByteOrder::Little, true, Some("Canon EOS D60"));
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    // D60 ⇒ position 29 is BlackLevels, NOT WB_RGGBLevelsCustom.
    assert_eq!(
      find("BlackLevels"),
      Some(TagValue::Str("1722 832 831 989".into()))
    );
    assert!(find("WB_RGGBLevelsCustom").is_none());
    // The other positions are unchanged.
    assert_eq!(
      find("WB_RGGBLevelsAuto"),
      Some(TagValue::Str("1740 832 831 931".into()))
    );
  }

  #[test]
  fn eos_d60_regex_word_boundary() {
    // `/EOS D60\b/`: word boundary semantics.
    assert!(model_is_eos_d60(Some("EOS D60")));
    assert!(model_is_eos_d60(Some("Canon EOS D60")));
    assert!(model_is_eos_d60(Some("Canon EOS D60 ")));
    // D600 / D6000 do NOT match (no word boundary after "D60").
    assert!(!model_is_eos_d60(Some("Canon EOS D600")));
    assert!(!model_is_eos_d60(Some("Canon EOS D6000")));
    // 300D / DIGITAL REBEL do not match.
    assert!(!model_is_eos_d60(Some("Canon EOS DIGITAL REBEL")));
    assert!(!model_is_eos_d60(Some("Canon EOS 300D")));
    assert!(!model_is_eos_d60(None));
  }

  #[test]
  fn truncated_block_skips_incomplete_quads() {
    // Only enough for position 0..4 (5 words = pos 0 + the Auto quad at 1..4).
    let data = build(&[82, 1740, 832, 831, 931]);
    let em = parse(
      &data,
      ByteOrder::Little,
      true,
      Some("Canon EOS DIGITAL REBEL"),
    );
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(
      find("WB_RGGBLevelsAuto"),
      Some(TagValue::Str("1740 832 831 931".into()))
    );
    // Daylight quad (pos 5..8) would need words up to index 8 → absent.
    assert!(find("WB_RGGBLevelsDaylight").is_none());
    assert_eq!(em.len(), 1);
  }
}
