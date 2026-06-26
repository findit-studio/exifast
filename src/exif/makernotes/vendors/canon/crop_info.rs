// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Canon::CropInfo` (`Canon.pm:7165-7174`, `Canon::Main` tag `0x98`) and
//! `%Canon::AspectInfo` (`Canon.pm:7177-7200`, tag `0x9a`).
//!
//! CropInfo is `FORMAT => 'int16u'`, FIRST_ENTRY 0 (CropLeftMargin/RightMargin/
//! TopMargin/BottomMargin at bytes 0/2/4/6). AspectInfo is `FORMAT => 'int32u'`,
//! FIRST_ENTRY 0 (AspectRatio @ 0, then CroppedImageWidth/Height/Left/Top at
//! bytes 4/8/12/16). Each emits only the in-range leaves (per-field
//! availability).
//!
//! D8: pure decoders — return the `(Name, TagValue)` emission pairs the dispatch
//! site wraps in the `Canon` family-1 group.

#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::ByteOrder;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

/// Decode `%Canon::CropInfo` from the int16u `0x98` blob.
#[must_use]
pub fn parse_crop(data: &[u8], order: ByteOrder, _print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  for &(off, name) in &[
    (0usize, "CropLeftMargin"),
    (2, "CropRightMargin"),
    (4, "CropTopMargin"),
    (6, "CropBottomMargin"),
  ] {
    if let Some(v) = u16(data, off, order) {
      out.push((SmolStr::new_static(name), TagValue::I64(v)));
    }
  }
  out
}

/// Decode `%Canon::AspectInfo` from the int32u `0x9a` blob.
#[must_use]
pub fn parse_aspect(data: &[u8], order: ByteOrder, print_conv: bool) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  // 0) AspectRatio @ 0 (int32u, PrintConv hash).
  if let Some(v) = u32(data, 0, order) {
    out.push((
      SmolStr::new_static("AspectRatio"),
      if print_conv {
        match aspect_ratio_label(v) {
          Some(l) => TagValue::Str(SmolStr::new_static(l)),
          None => TagValue::Str(SmolStr::from(std::format!("Unknown ({v})"))),
        }
      } else {
        TagValue::I64(v)
      },
    ));
  }
  // 1..4) CroppedImageWidth/Height/Left/Top (int32u, plain).
  for &(off, name) in &[
    (4usize, "CroppedImageWidth"),
    (8, "CroppedImageHeight"),
    (12, "CroppedImageLeft"),
    (16, "CroppedImageTop"),
  ] {
    if let Some(v) = u32(data, off, order) {
      out.push((SmolStr::new_static(name), TagValue::I64(v)));
    }
  }
  out
}

/// `AspectRatio` PrintConv (`Canon.pm:7184-7193`).
fn aspect_ratio_label(v: i64) -> Option<&'static str> {
  Some(match v {
    0 => "3:2",
    1 => "1:1",
    2 => "4:3",
    7 => "16:9",
    8 => "4:5",
    12 => "3:2 (APS-H crop)",
    13 => "3:2 (APS-C crop)",
    258 => "4:3 crop",
    _ => return None,
  })
}

/// Read an unsigned 16-bit word at byte `off`.
fn u16(data: &[u8], off: usize, order: ByteOrder) -> Option<i64> {
  let arr: [u8; 2] = data.get(off..off + 2)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u16::from_le_bytes(arr),
    ByteOrder::Big => u16::from_be_bytes(arr),
  } as i64)
}

/// Read an unsigned 32-bit word at byte `off`.
fn u32(data: &[u8], off: usize, order: ByteOrder) -> Option<i64> {
  let arr: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
  Some(match order {
    ByteOrder::Little => u32::from_le_bytes(arr),
    ByteOrder::Big => u32::from_be_bytes(arr),
  } as i64)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  #[test]
  fn crop_info_zeros() {
    let b = [0u8; 8];
    let em = parse_crop(&b, ByteOrder::Little, true);
    assert_eq!(em.len(), 4);
    assert_eq!(
      em[0],
      (SmolStr::new_static("CropLeftMargin"), TagValue::I64(0))
    );
  }

  #[test]
  fn aspect_info_unknown_ratio() {
    // AspectRatio=256, CroppedImageWidth=2592, CroppedImageHeight=1728.
    let mut b = vec![0u8; 20];
    b[0..4].copy_from_slice(&256u32.to_le_bytes());
    b[4..8].copy_from_slice(&2592u32.to_le_bytes());
    b[8..12].copy_from_slice(&1728u32.to_le_bytes());
    let em = parse_aspect(&b, ByteOrder::Little, true);
    let find = |n: &str| em.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(
      find("AspectRatio"),
      Some(TagValue::Str("Unknown (256)".into()))
    );
    assert_eq!(find("CroppedImageWidth"), Some(TagValue::I64(2592)));
    assert_eq!(find("CroppedImageHeight"), Some(TagValue::I64(1728)));
  }
}
