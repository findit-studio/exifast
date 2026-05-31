// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Canon::AFInfo` (`Canon.pm:6432-6499`) and
//! `%Image::ExifTool::Canon::AFInfo2` (`Canon.pm:6503-6603`).
//!
//! Both use `PROCESS_PROC => \&ProcessSerialData` (`Canon.pm:10516-
//! 10598`): a SEQUENTIAL reader. Each numbered index consumes
//! `FormatSize(format) * count` bytes from the running `$pos`, where
//! `count` may be an expression over PRIOR decoded values (`%val`) and
//! the block `$size`. The default `FORMAT => 'int16u'` (size 2). Some
//! arrays are `int16s[$val{N}]` (signed). Processing STOPS (`last`) when
//! a tag's array count can't be evaluated, when `$pos + $len > $size`, or
//! when `GetTagInfo` returns nothing (the EOS branch of the conditional-
//! list positions — serial sync would break otherwise).
//!
//! ## AFInfo (older; tag 0x12) — index → name
//!
//! | Idx | Name | Format | Cite |
//! |-----|------|--------|------|
//! | 0 | NumAFPoints | int16u | `Canon.pm:6446` |
//! | 1 | ValidAFPoints | int16u | `Canon.pm:6449` |
//! | 2 | CanonImageWidth | int16u | `Canon.pm:6453` |
//! | 3 | CanonImageHeight | int16u | `Canon.pm:6457` |
//! | 4 | AFImageWidth | int16u | `Canon.pm:6461` |
//! | 5 | AFImageHeight | int16u | `Canon.pm:6465` |
//! | 6 | AFAreaWidth | int16u | `Canon.pm:6466` |
//! | 7 | AFAreaHeight | int16u | `Canon.pm:6467` |
//! | 8 | AFAreaXPositions | int16s[$val{0}] | `Canon.pm:6468-6471` |
//! | 9 | AFAreaYPositions | int16s[$val{0}] | `Canon.pm:6472-6475` |
//! | 10 | AFPointsInFocus | int16s[int(($val{0}+15)/16)] | `Canon.pm:6476-6480` |
//! | 11 | (cond) PrimaryAFPoint / 8-word unknown — non-EOS only | `Canon.pm:6481-6498` |
//! | 12 | PrimaryAFPoint | int16u | `Canon.pm:6499` |
//!
//! For EOS bodies, index 11's conditional list has NO matching branch
//! (both are `Model !~ /EOS/`), so `GetTagInfo` returns undef → `last`.
//! Indices 11/12 are not emitted (matches the EOS 300D fixture).
//!
//! For NON-EOS bodies, index 11 keys on `$$self{AFInfoCount}` (the 0x12
//! SubDirectory element count = blob word count, `Canon.pm:1601`):
//!   - `AFInfoCount != 36` (or unset) → index 11 IS `PrimaryAFPoint`
//!     (int16u scalar).
//!   - `AFInfoCount == 36` → index 11 is the 8-word `Canon_AFInfo_0x000b`
//!     `int16u[8]` Unknown filler (consumed, not emitted), then index 12
//!     `PrimaryAFPoint` (some PowerShot 9-point systems put PrimaryAFPoint
//!     after 8 unknown values). Both layouts ported.
//!
//! ## AFInfo2 (newer; tag 0x26, and tag 0x3c as AFInfo3) — index → name
//!
//! The same `Canon::AFInfo2` table is also used for `Canon::Main` tag
//! `0x3c` (`AFInfo3`, G1XmkII; `Canon.pm:1764-1770`), which sets the
//! `$$self{AFInfo3}` DataMember — see [`parse_af_info3`]. (Bundled does
//! NOT route tag 0x32 here; `Canon.pm:1748` only documents 0x32 as an
//! unrelated WB record.)
//!
//! | Idx | Name | Format | Cite |
//! |-----|------|--------|------|
//! | 0 | AFInfoSize (Unknown) | int16u | `Canon.pm:6513` |
//! | 1 | AFAreaMode (PrintConv) | int16u | `Canon.pm:6517-6542` |
//! | 2 | NumAFPoints | int16u | `Canon.pm:6543-6546` |
//! | 3 | ValidAFPoints | int16u | `Canon.pm:6547` |
//! | 4 | CanonImageWidth | int16u | `Canon.pm:6551` |
//! | 5 | CanonImageHeight | int16u | `Canon.pm:6555` |
//! | 6 | AFImageWidth | int16u | `Canon.pm:6559` |
//! | 7 | AFImageHeight | int16u | `Canon.pm:6563` |
//! | 8 | AFAreaWidths | int16s[$val{2}] | `Canon.pm:6564-6567` |
//! | 9 | AFAreaHeights | int16s[$val{2}] | `Canon.pm:6568-6571` |
//! | 10 | AFAreaXPositions | int16s[$val{2}] | `Canon.pm:6572-6575` |
//! | 11 | AFAreaYPositions | int16s[$val{2}] | `Canon.pm:6576-6579` |
//! | 12 | AFPointsInFocus | int16s[int(($val{2}+15)/16)] | `Canon.pm:6580-6584` |
//! | 13 | (cond) AFPointsSelected (EOS) / `Canon_AFInfo2_0x000d` filler (non-EOS, Unknown) | `Canon.pm:6585-6597` |
//! | 14 | PrimaryAFPoint — `Model !~ /EOS/ and not $$self{AFInfo3}` | `Canon.pm:6598-6602` |
//!
//! ## Scope (issue #86 part 2)
//!
//! Ports NumAFPoints, ValidAFPoints, CanonImageWidth/Height,
//! AFImageWidth/Height, AFAreaWidth(s)/Height(s), AFAreaXPositions,
//! AFAreaYPositions, AFPointsInFocus (DecodeBits), PrimaryAFPoint (non-
//! EOS), AFAreaMode (AFInfo2). The `Unknown`-flagged scalars (AFInfoSize,
//! the `Canon_AFInfo2_0x000d` filler) are consumed for serial sync but
//! NOT emitted (bundled hides them without `-u`). AFPointsSelected (EOS,
//! AFInfo2 index 13) is emitted (DecodeBits, like AFPointsInFocus).

use crate::convert::decode_bits;
use crate::exif::ifd::ByteOrder;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

/// Decoded Canon AFInfo / AFInfo2 — the camera-indexing-relevant typed
/// surface (shared shape for both record versions). D8 accessor-only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CanonAFInfo {
  /// `true` when decoded from the newer AFInfo2 record (Main tag 0x26, or
  /// AFInfo3 = Main tag 0x3c), `false` for the older AFInfo (tag 0x12).
  is_v2: bool,
  /// AFAreaMode label — AFInfo2 only (`Canon.pm:6517-6542`).
  af_area_mode: Option<SmolStr>,
  /// NumAFPoints — total AF point count for the body.
  num_af_points: Option<u16>,
  /// ValidAFPoints — points valid in the following arrays.
  valid_af_points: Option<u16>,
  /// CanonImageWidth (pixels).
  canon_image_width: Option<u16>,
  /// CanonImageHeight (pixels).
  canon_image_height: Option<u16>,
  /// AFImageWidth — image size in AF coordinates.
  af_image_width: Option<u16>,
  /// AFImageHeight — image size in AF coordinates.
  af_image_height: Option<u16>,
  /// AFAreaXPositions (signed, AF-coordinate space, 0,0 = centre).
  af_area_x_positions: Vec<i16>,
  /// AFAreaYPositions (signed).
  af_area_y_positions: Vec<i16>,
  /// PrimaryAFPoint — non-EOS bodies only.
  primary_af_point: Option<u16>,
}

impl CanonAFInfo {
  /// Empty placeholder.
  #[must_use]
  #[inline]
  pub fn new() -> Self {
    Self::default()
  }

  /// `true` when no field decoded.
  #[must_use]
  #[inline]
  pub fn is_empty(&self) -> bool {
    *self == Self::default()
  }

  /// `true` for the AFInfo2 record, `false` for the older AFInfo.
  #[must_use]
  #[inline(always)]
  pub const fn is_v2(&self) -> bool {
    self.is_v2
  }

  /// AFAreaMode label (AFInfo2 only).
  #[must_use]
  #[inline]
  pub fn af_area_mode(&self) -> Option<&str> {
    self.af_area_mode.as_deref()
  }

  /// Total AF point count.
  #[must_use]
  #[inline(always)]
  pub const fn num_af_points(&self) -> Option<u16> {
    self.num_af_points
  }

  /// Valid AF point count.
  #[must_use]
  #[inline(always)]
  pub const fn valid_af_points(&self) -> Option<u16> {
    self.valid_af_points
  }

  /// CanonImageWidth in pixels.
  #[must_use]
  #[inline(always)]
  pub const fn canon_image_width(&self) -> Option<u16> {
    self.canon_image_width
  }

  /// CanonImageHeight in pixels.
  #[must_use]
  #[inline(always)]
  pub const fn canon_image_height(&self) -> Option<u16> {
    self.canon_image_height
  }

  /// AFImageWidth.
  #[must_use]
  #[inline(always)]
  pub const fn af_image_width(&self) -> Option<u16> {
    self.af_image_width
  }

  /// AFImageHeight.
  #[must_use]
  #[inline(always)]
  pub const fn af_image_height(&self) -> Option<u16> {
    self.af_image_height
  }

  /// AFAreaXPositions (signed AF-coordinate values).
  #[must_use]
  #[inline]
  pub fn af_area_x_positions(&self) -> &[i16] {
    &self.af_area_x_positions
  }

  /// AFAreaYPositions (signed AF-coordinate values).
  #[must_use]
  #[inline]
  pub fn af_area_y_positions(&self) -> &[i16] {
    &self.af_area_y_positions
  }

  /// PrimaryAFPoint (non-EOS bodies only).
  #[must_use]
  #[inline(always)]
  pub const fn primary_af_point(&self) -> Option<u16> {
    self.primary_af_point
  }
}

/// AFAreaMode PrintConv (`Canon.pm:6519-6541`) — AFInfo2 index 1.
fn af_area_mode_label(val: i64) -> Option<&'static str> {
  Some(match val {
    0 => "Off (Manual Focus)",
    1 => "AF Point Expansion (surround)",
    2 => "Single-point AF",
    4 => "Auto",
    5 => "Face Detect AF",
    6 => "Face + Tracking",
    7 => "Zone AF",
    8 => "AF Point Expansion (4 point)",
    9 => "Spot AF",
    10 => "AF Point Expansion (8 point)",
    11 => "Flexizone Multi (49 point)",
    12 => "Flexizone Multi (9 point)",
    13 => "Flexizone Single",
    14 => "Large Zone AF",
    16 => "Large Zone AF (vertical)",
    17 => "Large Zone AF (horizontal)",
    19 => "Flexible Zone AF 1",
    20 => "Flexible Zone AF 2",
    21 => "Flexible Zone AF 3",
    22 => "Whole Area AF",
    _ => return None,
  })
}

/// `$$self{Model} =~ /EOS/` (the AFInfo/AFInfo2 conditional-list gate).
fn is_eos(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.contains("EOS"))
}

/// One field's read format inside the serial stream.
#[derive(Clone, Copy)]
enum Fmt {
  /// `int16u` scalar.
  U16,
  /// `int16s[count]` array. `count` is resolved from prior `%val`.
  S16Array(ArrayCount),
}

/// How a `int16s[...]` count is computed from earlier decoded scalars.
#[derive(Clone, Copy)]
enum ArrayCount {
  /// `$val{idx}` — the prior NumAFPoints value at the given index.
  NumPoints,
  /// `int(($val{idx}+15)/16)` — the AFPointsInFocus / AFPointsSelected
  /// bit-word count.
  BitWords,
}

/// Read one `int16u` word at byte `off`.
fn read_u16(data: &[u8], off: usize, order: ByteOrder) -> Option<u16> {
  let b = data.get(off..off + 2)?;
  let arr = [b[0], b[1]];
  Some(match order {
    ByteOrder::Little => u16::from_le_bytes(arr),
    ByteOrder::Big => u16::from_be_bytes(arr),
  })
}

/// Read one `int16s` word at byte `off`.
fn read_i16(data: &[u8], off: usize, order: ByteOrder) -> Option<i16> {
  let b = data.get(off..off + 2)?;
  let arr = [b[0], b[1]];
  Some(match order {
    ByteOrder::Little => i16::from_le_bytes(arr),
    ByteOrder::Big => i16::from_be_bytes(arr),
  })
}

/// Join signed words with a single space, like bundled `-j` array
/// rendering (`"1014 608 0 0 0 -608 -1014"`).
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

/// `DecodeBits($val, undef, 16)` over a slice of int16s words rendered as
/// the space-joined string bundled would pass.
fn decode_bits_16(words: &[i16]) -> String {
  decode_bits(&join_i16(words), None, 16)
}

/// Parse the older `Canon::AFInfo` record (tag 0x12).
#[must_use]
pub fn parse_af_info(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
) -> (CanonAFInfo, Vec<(SmolStr, TagValue)>) {
  parse_serial(data, order, print_conv, model, false, false)
}

/// Parse the newer `Canon::AFInfo2` record (tag 0x26).
#[must_use]
pub fn parse_af_info2(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
) -> (CanonAFInfo, Vec<(SmolStr, TagValue)>) {
  parse_serial(data, order, print_conv, model, true, false)
}

/// Parse the `Canon::AFInfo3` record (tag 0x3c, G1XmkII), which bundled
/// processes with the SAME `Canon::AFInfo2` table but with
/// `$$self{AFInfo3} = 1` set (`Canon.pm:1764-1770`). The only behavioural
/// difference vs [`parse_af_info2`] is index 14 `PrimaryAFPoint`, whose
/// `Condition` is `$$self{Model} !~ /EOS/ and not $$self{AFInfo3}`
/// (`Canon.pm:6602`): with `AFInfo3` set the condition is FALSE even for a
/// non-EOS body, so `GetTagInfo` returns undef and serial processing stops
/// before PrimaryAFPoint (verified against bundled `exiftool 13.59` on a
/// crafted G1XmkII 0x3c record).
#[must_use]
pub fn parse_af_info3(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
) -> (CanonAFInfo, Vec<(SmolStr, TagValue)>) {
  parse_serial(data, order, print_conv, model, true, true)
}

/// Field descriptor: `(name, format, emit)`.
struct Field {
  name: &'static str,
  fmt: Fmt,
  emit: bool,
}

/// Shared `ProcessSerialData` walk for AFInfo (v1) and AFInfo2 (v2).
///
/// `af_info3` mirrors the `$$self{AFInfo3}` DataMember (set to 1 by the
/// `Canon::Main` 0x3c dispatch, `Canon.pm:1766`). It only affects the
/// AFInfo2 index-14 `PrimaryAFPoint` `Condition`
/// (`$$self{Model} !~ /EOS/ and not $$self{AFInfo3}`, `Canon.pm:6602`):
/// when set, the non-EOS PrimaryAFPoint is suppressed.
fn parse_serial(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
  v2: bool,
  af_info3: bool,
) -> (CanonAFInfo, Vec<(SmolStr, TagValue)>) {
  let mut typed = CanonAFInfo {
    is_v2: v2,
    ..CanonAFInfo::default()
  };
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  let size = data.len();
  if size < 2 {
    return (typed, out);
  }

  // The NumAFPoints index differs: 0 for AFInfo, 2 for AFInfo2.
  let num_idx = if v2 { 2usize } else { 0usize };

  // Build the field list up to (but excluding) the conditional-list
  // position; the conditional handling is done inline afterward because it
  // depends on the EOS model gate.
  let fields: &[Field] = if v2 {
    &[
      Field {
        name: "AFInfoSize",
        fmt: Fmt::U16,
        emit: false,
      }, // 0 (Unknown)
      Field {
        name: "AFAreaMode",
        fmt: Fmt::U16,
        emit: true,
      }, // 1
      Field {
        name: "NumAFPoints",
        fmt: Fmt::U16,
        emit: true,
      }, // 2
      Field {
        name: "ValidAFPoints",
        fmt: Fmt::U16,
        emit: true,
      }, // 3
      Field {
        name: "CanonImageWidth",
        fmt: Fmt::U16,
        emit: true,
      }, // 4
      Field {
        name: "CanonImageHeight",
        fmt: Fmt::U16,
        emit: true,
      }, // 5
      Field {
        name: "AFImageWidth",
        fmt: Fmt::U16,
        emit: true,
      }, // 6
      Field {
        name: "AFImageHeight",
        fmt: Fmt::U16,
        emit: true,
      }, // 7
      Field {
        name: "AFAreaWidths",
        fmt: Fmt::S16Array(ArrayCount::NumPoints),
        emit: true,
      }, // 8
      Field {
        name: "AFAreaHeights",
        fmt: Fmt::S16Array(ArrayCount::NumPoints),
        emit: true,
      }, // 9
      Field {
        name: "AFAreaXPositions",
        fmt: Fmt::S16Array(ArrayCount::NumPoints),
        emit: true,
      }, // 10
      Field {
        name: "AFAreaYPositions",
        fmt: Fmt::S16Array(ArrayCount::NumPoints),
        emit: true,
      }, // 11
      Field {
        name: "AFPointsInFocus",
        fmt: Fmt::S16Array(ArrayCount::BitWords),
        emit: true,
      }, // 12
    ]
  } else {
    &[
      Field {
        name: "NumAFPoints",
        fmt: Fmt::U16,
        emit: true,
      }, // 0
      Field {
        name: "ValidAFPoints",
        fmt: Fmt::U16,
        emit: true,
      }, // 1
      Field {
        name: "CanonImageWidth",
        fmt: Fmt::U16,
        emit: true,
      }, // 2
      Field {
        name: "CanonImageHeight",
        fmt: Fmt::U16,
        emit: true,
      }, // 3
      Field {
        name: "AFImageWidth",
        fmt: Fmt::U16,
        emit: true,
      }, // 4
      Field {
        name: "AFImageHeight",
        fmt: Fmt::U16,
        emit: true,
      }, // 5
      Field {
        name: "AFAreaWidth",
        fmt: Fmt::U16,
        emit: true,
      }, // 6
      Field {
        name: "AFAreaHeight",
        fmt: Fmt::U16,
        emit: true,
      }, // 7
      Field {
        name: "AFAreaXPositions",
        fmt: Fmt::S16Array(ArrayCount::NumPoints),
        emit: true,
      }, // 8
      Field {
        name: "AFAreaYPositions",
        fmt: Fmt::S16Array(ArrayCount::NumPoints),
        emit: true,
      }, // 9
      Field {
        name: "AFPointsInFocus",
        fmt: Fmt::S16Array(ArrayCount::BitWords),
        emit: true,
      }, // 10
    ]
  };

  let mut pos = 0usize; // byte cursor into `data`.
  // `%val` holds the prior NumAFPoints scalar (the only one any count
  // expression references). Keyed by the BUNDLED index.
  let mut num_points_val: Option<i64> = None;

  let push_scalar = |out: &mut Vec<(SmolStr, TagValue)>, name: &'static str, v: TagValue| {
    out.push((SmolStr::new_static(name), v));
  };

  // Walk the fixed-prefix fields. `last` (break) on any short read so the
  // record stays in sync (matches ProcessSerialData's `last`).
  let mut stopped = false;
  for (idx, f) in fields.iter().enumerate() {
    match f.fmt {
      Fmt::U16 => {
        // `last if $pos + $len > $size`.
        if pos + 2 > size {
          stopped = true;
          break;
        }
        let Some(raw) = read_u16(data, pos, order) else {
          stopped = true;
          break;
        };
        pos += 2;
        if idx == num_idx {
          num_points_val = Some(i64::from(raw));
        }
        store_scalar(&mut typed, f.name, raw, v2);
        if f.emit {
          let value = if print_conv && f.name == "AFAreaMode" {
            let label = af_area_mode_label(i64::from(raw));
            if let Some(l) = label {
              typed.af_area_mode = Some(SmolStr::new_static(l));
            }
            match label {
              Some(l) => TagValue::Str(SmolStr::new_static(l)),
              None => TagValue::Str(SmolStr::from(std::format!("Unknown ({raw})"))),
            }
          } else {
            TagValue::I64(i64::from(raw))
          };
          push_scalar(&mut out, f.name, value);
        }
      }
      Fmt::S16Array(count_kind) => {
        let count = match resolve_count(count_kind, num_points_val) {
          Some(c) => c,
          None => {
            stopped = true;
            break;
          }
        };
        let len = count * 2;
        if pos + len > size {
          stopped = true;
          break;
        }
        let mut words: Vec<i16> = Vec::with_capacity(count);
        for w in 0..count {
          let Some(v) = read_i16(data, pos + w * 2, order) else {
            stopped = true;
            break;
          };
          words.push(v);
        }
        if words.len() != count {
          stopped = true;
          break;
        }
        pos += len;
        store_array(&mut typed, f.name, &words);
        if f.emit && count > 0 {
          let value = render_array(f.name, &words, print_conv);
          push_scalar(&mut out, f.name, value);
        }
      }
    }
  }

  if stopped {
    return (typed, out);
  }

  // AFInfo2 index 13 for EOS bodies is `AFPointsSelected` (DecodeBits,
  // like AFPointsInFocus) — `Canon.pm:6585-6591`. Emit it, then serial
  // processing stops for EOS (index 14 PrimaryAFPoint is non-EOS only).
  if v2 && is_eos(model) {
    if let Some(np) = num_points_val {
      let bitwords = ((np + 15) / 16).max(0) as usize;
      let len = bitwords * 2;
      if bitwords > 0 && pos + len <= size {
        let mut words: Vec<i16> = Vec::with_capacity(bitwords);
        for w in 0..bitwords {
          if let Some(v) = read_i16(data, pos + w * 2, order) {
            words.push(v);
          }
        }
        if words.len() == bitwords {
          let value = render_array("AFPointsSelected", &words, print_conv);
          push_scalar(&mut out, "AFPointsSelected", value);
        }
      }
    }
    return (typed, out);
  }

  // Conditional-list position + trailing PrimaryAFPoint. For EOS bodies
  // these are skipped (the conditional list has no matching branch, so
  // ProcessSerialData stops). For non-EOS bodies we emit PrimaryAFPoint.
  if !is_eos(model) {
    if v2 {
      // AFInfo2 index 13 conditional: non-EOS falls to the unknown filler
      // `Canon_AFInfo2_0x000d` (int16s[bitwords+1], Unknown → consumed,
      // not emitted). Then index 14 PrimaryAFPoint, `Condition =>
      // '$$self{Model} !~ /EOS/ and not $$self{AFInfo3}'` (`Canon.pm:6602`):
      // emitted for a non-EOS body UNLESS this is an AFInfo3 (0x3c) record,
      // in which case `$$self{AFInfo3}` is 1 so `GetTagInfo` returns undef
      // and serial processing stops (no PrimaryAFPoint).
      if !af_info3 && let Some(np) = num_points_val {
        let bitwords = ((np + 15) / 16).max(0) as usize;
        let filler = bitwords + 1;
        let len = filler * 2;
        if pos + len <= size {
          pos += len;
          if let Some(raw) = read_u16(data, pos, order) {
            typed.primary_af_point = Some(raw);
            push_scalar(&mut out, "PrimaryAFPoint", TagValue::I64(i64::from(raw)));
          }
        }
      }
    } else {
      // AFInfo index 11 conditional (non-EOS), `Canon.pm:6482-6498`:
      //   - branch 1 `PrimaryAFPoint`: `Model !~ /EOS/ and (not AFInfoCount
      //     or AFInfoCount != 36)` — an int16u scalar AT index 11.
      //   - branch 2 `Canon_AFInfo_0x000b`: `Model !~ /EOS/`, `int16u[8]`,
      //     `Unknown => 1` — consumed for serial sync, NOT emitted; THEN
      //     index 12 `PrimaryAFPoint` (int16u scalar) follows.
      // `$$self{AFInfoCount}` is the IFD entry element count for the 0x12
      // SubDirectory (`Canon.pm:1601` `Condition => '$$self{AFInfoCount} =
      // $count'`); for an int16u record that is `byte_len / 2`, i.e. the
      // total word count of THIS blob. So `AFInfoCount == 36` ⇔ a 72-byte
      // record. (Oracled against bundled `exiftool 13.59` ProcessSerialData:
      // count 36 → 8-word filler then PrimaryAFPoint at index 12; count ≠ 36
      // → PrimaryAFPoint at index 11.)
      let af_info_count = size / 2;
      if af_info_count == 36 {
        // Branch 2: skip the 8-word `int16u[8]` Unknown filler (index 11),
        // then read `PrimaryAFPoint` (index 12).
        let filler_len = 8 * 2;
        if pos + filler_len <= size {
          pos += filler_len;
          if pos + 2 <= size
            && let Some(raw) = read_u16(data, pos, order)
          {
            typed.primary_af_point = Some(raw);
            push_scalar(&mut out, "PrimaryAFPoint", TagValue::I64(i64::from(raw)));
          }
        }
      } else if pos + 2 <= size
        && let Some(raw) = read_u16(data, pos, order)
      {
        // Branch 1: PrimaryAFPoint directly at index 11.
        typed.primary_af_point = Some(raw);
        push_scalar(&mut out, "PrimaryAFPoint", TagValue::I64(i64::from(raw)));
      }
    }
  }

  (typed, out)
}

/// Resolve an `int16s[...]` element count from prior values.
fn resolve_count(kind: ArrayCount, num_points: Option<i64>) -> Option<usize> {
  let np = num_points?;
  if np < 0 {
    return Some(0);
  }
  Some(match kind {
    ArrayCount::NumPoints => np as usize,
    // `int(($val{N}+15)/16)`.
    ArrayCount::BitWords => ((np + 15) / 16) as usize,
  })
}

/// Store a scalar into the typed struct (by bundled name).
fn store_scalar(typed: &mut CanonAFInfo, name: &str, raw: u16, _v2: bool) {
  match name {
    "NumAFPoints" => typed.num_af_points = Some(raw),
    "ValidAFPoints" => typed.valid_af_points = Some(raw),
    "CanonImageWidth" => typed.canon_image_width = Some(raw),
    "CanonImageHeight" => typed.canon_image_height = Some(raw),
    "AFImageWidth" => typed.af_image_width = Some(raw),
    "AFImageHeight" => typed.af_image_height = Some(raw),
    _ => {}
  }
}

/// Store an array into the typed struct (by bundled name).
fn store_array(typed: &mut CanonAFInfo, name: &str, words: &[i16]) {
  match name {
    "AFAreaXPositions" => typed.af_area_x_positions = words.to_vec(),
    "AFAreaYPositions" => typed.af_area_y_positions = words.to_vec(),
    _ => {}
  }
}

/// Render an array field: AFPointsInFocus / AFPointsSelected use
/// `DecodeBits`; everything else is the space-joined signed list.
fn render_array(name: &str, words: &[i16], print_conv: bool) -> TagValue {
  if (name == "AFPointsInFocus" || name == "AFPointsSelected") && print_conv {
    // DecodeBits PrintConv (`Canon.pm:6480`/:6584) over the raw value.
    TagValue::Str(SmolStr::from(decode_bits_16(words)))
  } else if let [single] = words {
    // ExifTool emits a SINGLE-element list as the bare scalar (a number), not a
    // space-joined string — e.g. AFPointsInFocus with NumAFPoints ≤ 16 has one
    // `int16s` word, so `-n` is the integer `0`, not `"0"`. (DecodeBits in `-j`
    // is handled above; the raw `-n` value of a 1-word array is the scalar.)
    TagValue::I64(i64::from(*single))
  } else {
    // Multiple values ⇒ ExifTool's default space-joined string.
    TagValue::Str(SmolStr::from(join_i16(words)))
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::exif::ifd::ByteOrder;

  fn blob(words: &[i16]) -> Vec<u8> {
    let mut data = Vec::with_capacity(words.len() * 2);
    for &w in words {
      data.extend_from_slice(&w.to_le_bytes());
    }
    data
  }

  fn find(emissions: &[(SmolStr, TagValue)], name: &str) -> Option<TagValue> {
    emissions
      .iter()
      .find(|(n, _)| n == name)
      .map(|(_, v)| v.clone())
  }

  /// Real-input parity: the EOS 300D fixture AFInfo record (older, tag
  /// 0x12). 24 int16u words. EOS → serial stops before PrimaryAFPoint.
  #[test]
  fn eos_300d_af_info_matches_oracle() {
    let words: [i16; 24] = [
      7, 7, 3072, 2048, 3072, 2048, 151, 151, // scalars 0-7
      1014, 608, 0, 0, 0, -608, -1014, // AFAreaXPositions[7]
      0, 0, -506, 0, 506, 0, 0,  // AFAreaYPositions[7]
      0,  // AFPointsInFocus[1] = 0 → "(none)"
      -1, // trailing (would be index 11/12 — EOS stops, not consumed)
    ];
    let data = blob(&words);
    let model = Some("EOS Digital Rebel / 300D / Kiss Digital");
    let (typed, em) = parse_af_info(&data, ByteOrder::Little, true, model);

    assert_eq!(find(&em, "NumAFPoints"), Some(TagValue::I64(7)));
    assert_eq!(typed.num_af_points(), Some(7));
    assert_eq!(find(&em, "ValidAFPoints"), Some(TagValue::I64(7)));
    assert_eq!(find(&em, "CanonImageWidth"), Some(TagValue::I64(3072)));
    assert_eq!(find(&em, "CanonImageHeight"), Some(TagValue::I64(2048)));
    assert_eq!(find(&em, "AFImageWidth"), Some(TagValue::I64(3072)));
    assert_eq!(find(&em, "AFImageHeight"), Some(TagValue::I64(2048)));
    assert_eq!(find(&em, "AFAreaWidth"), Some(TagValue::I64(151)));
    assert_eq!(find(&em, "AFAreaHeight"), Some(TagValue::I64(151)));
    assert_eq!(
      find(&em, "AFAreaXPositions"),
      Some(TagValue::Str("1014 608 0 0 0 -608 -1014".into()))
    );
    assert_eq!(
      typed.af_area_x_positions(),
      &[1014, 608, 0, 0, 0, -608, -1014]
    );
    assert_eq!(
      find(&em, "AFAreaYPositions"),
      Some(TagValue::Str("0 0 -506 0 506 0 0".into()))
    );
    assert_eq!(typed.af_area_y_positions(), &[0, 0, -506, 0, 506, 0, 0]);
    // AFPointsInFocus = 0 → DecodeBits → "(none)".
    assert_eq!(
      find(&em, "AFPointsInFocus"),
      Some(TagValue::Str("(none)".into()))
    );
    // EOS → no PrimaryAFPoint emitted.
    assert_eq!(find(&em, "PrimaryAFPoint"), None);
    assert_eq!(typed.primary_af_point(), None);
    assert!(!typed.is_v2());
  }

  /// Non-EOS AFInfo with `AFInfoCount == 36` (a 72-byte / 36-word record):
  /// index 11 is the `Canon_AFInfo_0x000b` `int16u[8]` Unknown filler
  /// (consumed, NOT emitted), then index 12 `PrimaryAFPoint`. Oracled
  /// against bundled `exiftool 13.59` ProcessSerialData (NumAFPoints=9,
  /// bitwords=1): the 8 filler words are skipped and PrimaryAFPoint=7 is
  /// read from index 12.
  #[test]
  fn powershot_af_info_count36_skips_filler_then_primary() {
    // 8 scalars + 9 X + 9 Y + 1 AFPointsInFocus + 8 filler + 1 Primary = 36.
    let words: [i16; 36] = [
      9, 9, 4000, 3000, 4000, 3000, 100, 100, // scalars 0-7
      -400, -300, -200, -100, 0, 100, 200, 300, 400, // AFAreaXPositions[9]
      -200, -150, -100, -50, 0, 50, 100, 150, 200, // AFAreaYPositions[9]
      5,   // AFPointsInFocus[1] = 5 → "0,2"
      11, 12, 13, 14, 15, 16, 17, 18, // Canon_AFInfo_0x000b[8] (Unknown)
      7,  // index 12 PrimaryAFPoint
    ];
    assert_eq!(words.len(), 36);
    let data = blob(&words);
    let model = Some("Canon PowerShot S5 IS");
    let (typed, em) = parse_af_info(&data, ByteOrder::Little, true, model);

    assert_eq!(find(&em, "NumAFPoints"), Some(TagValue::I64(9)));
    assert_eq!(
      find(&em, "AFPointsInFocus"),
      Some(TagValue::Str("0,2".into()))
    );
    // The 8-word filler is Unknown → not emitted.
    assert_eq!(find(&em, "Canon_AFInfo_0x000b"), None);
    // PrimaryAFPoint is read from index 12 (value 7), NOT the first filler
    // word (11).
    assert_eq!(find(&em, "PrimaryAFPoint"), Some(TagValue::I64(7)));
    assert_eq!(typed.primary_af_point(), Some(7));
  }

  /// The SAME non-EOS arrays but a NON-36 count (28 words) take the
  /// PrimaryAFPoint-at-index-11 branch (no filler). Confirms the count
  /// gate flips behaviour. Oracled: PrimaryAFPoint=7 read at index 11.
  #[test]
  fn powershot_af_info_count_not_36_primary_at_index_11() {
    // 8 scalars + 9 X + 9 Y + 1 AFPointsInFocus + 1 Primary = 28 (!= 36).
    let words: [i16; 28] = [
      9, 9, 4000, 3000, 4000, 3000, 100, 100, // scalars 0-7
      -400, -300, -200, -100, 0, 100, 200, 300, 400, // X[9]
      -200, -150, -100, -50, 0, 50, 100, 150, 200, // Y[9]
      5,   // AFPointsInFocus[1]
      7,   // index 11 PrimaryAFPoint (non-36 branch)
    ];
    assert_eq!(words.len(), 28);
    let data = blob(&words);
    let (typed, em) = parse_af_info(
      &data,
      ByteOrder::Little,
      true,
      Some("Canon PowerShot S5 IS"),
    );
    assert_eq!(find(&em, "PrimaryAFPoint"), Some(TagValue::I64(7)));
    assert_eq!(typed.primary_af_point(), Some(7));
  }

  /// Non-EOS (PowerShot) AFInfo: PrimaryAFPoint IS emitted at index 11.
  #[test]
  fn powershot_af_info_emits_primary_af_point() {
    // NumAFPoints=1 → 1 X, 1 Y, 1 bit-word, then PrimaryAFPoint.
    let words: [i16; 12] = [
      1, 1, 2048, 1536, 2048, 1536, 100, 100, // scalars 0-7
      50,  // AFAreaXPositions[1]
      60,  // AFAreaYPositions[1]
      0,   // AFPointsInFocus[1]
      3,   // index 11 PrimaryAFPoint (non-EOS branch)
    ];
    let data = blob(&words);
    let (typed, em) = parse_af_info(&data, ByteOrder::Little, true, Some("PowerShot A95"));
    assert_eq!(find(&em, "NumAFPoints"), Some(TagValue::I64(1)));
    assert_eq!(find(&em, "PrimaryAFPoint"), Some(TagValue::I64(3)));
    assert_eq!(typed.primary_af_point(), Some(3));
  }

  /// AFInfo3 (tag 0x3c) shares the AFInfo2 table but sets `$$self{AFInfo3}`,
  /// which makes the index-14 `PrimaryAFPoint` `Condition`
  /// (`$$self{Model} !~ /EOS/ and not $$self{AFInfo3}`, `Canon.pm:6602`)
  /// FALSE even for a non-EOS body. So [`parse_af_info2`] emits
  /// PrimaryAFPoint for a non-EOS G1XmkII-like record but [`parse_af_info3`]
  /// does NOT (oracled against bundled `exiftool 13.59`).
  #[test]
  fn af_info3_suppresses_primary_af_point_vs_af_info2() {
    // NumAFPoints=9 (bitwords=1): 9 widths/heights/X/Y, 1 AFPointsInFocus,
    // then the index-13 filler[bitwords+1=2], then index-14 PrimaryAFPoint=3.
    let mut words: Vec<i16> = vec![96, 2, 9, 9, 4000, 3000, 4000, 3000];
    words.extend(std::iter::repeat_n(50, 9)); // AFAreaWidths[9]
    words.extend(std::iter::repeat_n(60, 9)); // AFAreaHeights[9]
    words.extend([-400, -300, -200, -100, 0, 100, 200, 300, 400]); // X[9]
    words.extend([-200, -150, -100, -50, 0, 50, 100, 150, 200]); // Y[9]
    words.push(5); // AFPointsInFocus[1]
    words.extend([7, 0]); // Canon_AFInfo2_0x000d[2] filler
    words.push(3); // index-14 PrimaryAFPoint candidate
    let data = blob(&words);
    let model = Some("Canon PowerShot G1 X Mark II");

    // AFInfo2 (0x26): non-EOS → PrimaryAFPoint IS emitted.
    let (typed2, em2) = parse_af_info2(&data, ByteOrder::Little, true, model);
    assert_eq!(find(&em2, "PrimaryAFPoint"), Some(TagValue::I64(3)));
    assert_eq!(typed2.primary_af_point(), Some(3));

    // AFInfo3 (0x3c): same bytes, but the AFInfo3 flag suppresses it.
    let (typed3, em3) = parse_af_info3(&data, ByteOrder::Little, true, model);
    assert_eq!(find(&em3, "PrimaryAFPoint"), None);
    assert_eq!(typed3.primary_af_point(), None);
    // Everything else still decodes identically (the only difference is index 14).
    assert_eq!(find(&em3, "NumAFPoints"), Some(TagValue::I64(9)));
    assert_eq!(
      find(&em3, "AFAreaMode"),
      Some(TagValue::Str("Single-point AF".into()))
    );
    assert_eq!(
      find(&em3, "AFPointsInFocus"),
      Some(TagValue::Str("0,2".into()))
    );
    assert!(typed3.is_v2());
  }

  /// AFInfo2 (newer) record with AFAreaMode PrintConv + NumAFPoints at
  /// index 2 driving the arrays.
  #[test]
  fn af_info2_eos_decodes_area_mode_and_arrays() {
    // idx0 AFInfoSize=20, idx1 AFAreaMode=2 (Single-point AF),
    // idx2 NumAFPoints=2, idx3 ValidAFPoints=2, idx4..7 image dims,
    // idx8 AFAreaWidths[2], idx9 AFAreaHeights[2], idx10 X[2], idx11 Y[2],
    // idx12 AFPointsInFocus[1].
    let words: [i16; 18] = [
      20, 2, 2, 2, 5184, 3456, 5184, 3456, // 0-7
      100, 110, // AFAreaWidths[2]
      120, 130, // AFAreaHeights[2]
      -200, 200, // AFAreaXPositions[2]
      -50, 50, // AFAreaYPositions[2]
      0,  // AFPointsInFocus[1]
      0,  // padding
    ];
    let data = blob(&words);
    let (typed, em) = parse_af_info2(&data, ByteOrder::Little, true, Some("EOS 7D Mark II"));
    assert!(typed.is_v2());
    // AFInfoSize is Unknown → not emitted.
    assert_eq!(find(&em, "AFInfoSize"), None);
    assert_eq!(
      find(&em, "AFAreaMode"),
      Some(TagValue::Str("Single-point AF".into()))
    );
    assert_eq!(typed.af_area_mode(), Some("Single-point AF"));
    assert_eq!(find(&em, "NumAFPoints"), Some(TagValue::I64(2)));
    assert_eq!(
      find(&em, "AFAreaXPositions"),
      Some(TagValue::Str("-200 200".into()))
    );
    assert_eq!(
      find(&em, "AFAreaYPositions"),
      Some(TagValue::Str("-50 50".into()))
    );
    assert_eq!(typed.af_area_x_positions(), &[-200, 200]);
    // EOS → no PrimaryAFPoint.
    assert_eq!(find(&em, "PrimaryAFPoint"), None);
  }

  /// AFPointsInFocus DecodeBits with bits set: word value 5 (bits 0+2) →
  /// "0,2".
  #[test]
  fn af_points_in_focus_decode_bits() {
    let words: [i16; 12] = [
      1, 1, 100, 100, 100, 100, 10, 10, // scalars
      0,  // X[1]
      0,  // Y[1]
      5,  // AFPointsInFocus[1] = 5 → bits 0,2
      0,  // PrimaryAFPoint (won't reach for EOS)
    ];
    let data = blob(&words);
    let (_typed, em) = parse_af_info(&data, ByteOrder::Little, true, Some("EOS 5D"));
    assert_eq!(
      find(&em, "AFPointsInFocus"),
      Some(TagValue::Str("0,2".into()))
    );
  }

  /// Truncated record: serial processing stops cleanly at the short read,
  /// emitting only what was fully decoded.
  #[test]
  fn truncated_record_stops_in_sync() {
    // Only 4 words present: NumAFPoints, ValidAFPoints, CanonImageWidth,
    // then truncated before CanonImageHeight.
    let words: [i16; 3] = [7, 7, 3072];
    let data = blob(&words);
    let (typed, em) = parse_af_info(&data, ByteOrder::Little, true, Some("EOS 5D"));
    assert_eq!(find(&em, "NumAFPoints"), Some(TagValue::I64(7)));
    assert_eq!(find(&em, "CanonImageWidth"), Some(TagValue::I64(3072)));
    // CanonImageHeight not present.
    assert_eq!(find(&em, "CanonImageHeight"), None);
    assert!(typed.af_area_x_positions().is_empty());
  }

  /// `print_conv = false`: AFAreaMode stays an int, arrays stay joined.
  #[test]
  fn print_conv_off_keeps_numeric() {
    let words: [i16; 19] = [
      20, 2, 2, 2, 100, 100, 100, 100, 1, 1, 1, 1, -1, 1, -1, 1, 0, 0, 0,
    ];
    let data = blob(&words);
    let (_typed, em) = parse_af_info2(&data, ByteOrder::Little, false, Some("EOS 7D"));
    assert_eq!(find(&em, "AFAreaMode"), Some(TagValue::I64(2)));
  }

  #[test]
  fn short_blob_yields_empty() {
    let (typed, em) = parse_af_info(&[0], ByteOrder::Little, true, None);
    assert!(typed.is_empty());
    assert!(em.is_empty());
  }
}
