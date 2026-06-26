// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Konica-Minolta RAW (`MRW`) meta-information — `%MinoltaRaw::Main` + the PRD /
//! WBG / RIF `ProcessBinaryData` sub-blocks (`MinoltaRaw.pm`).
//!
//! Reached on a Sony ARW through the `%Sony::SR2Private` `MRWInfo` leaf (0x7250,
//! `Sony.pm:10506-10512`, `Condition => '$$valPt !~ /^\0\0\0\0/'`): its value is
//! an `\0MRI`-headed MRW block walked by `ProcessMRW` (`MinoltaRaw.pm:392-495`).
//! The block is a header (`\0MR[MI]` + a 4-byte total length) followed by
//! `\0XXX`-tagged segments (`\0PRD` raw picture dimensions, `\0WBG` white-balance
//! gains, `\0RIF` requested image format, plus the deferred `\0TTW` TIFF block and
//! `\0CSA` padding). Each handled segment is a `ProcessBinaryData` table; a leaf
//! is emitted IFF its byte range is in the segment AND its model `Condition`
//! holds ([[exifast-processbinarydata-per-field]]).
//!
//! The leaves ride the SHARED `ResolvedConv::Exif` render path (like the
//! [`super::sr2`] tables): every leaf is an [`ExifTag`] carrying a [`Conv`], and
//! [`process_mrw`] returns [`MrwLeaf`]s the [`crate::exif`] walker wraps into
//! `MinoltaRaw:*` entries. The three MinoltaRaw-specific PrintConvs — `WBMode`
//! ([`convert_wb_mode`]), `ISOSetting` ([`iso_setting_print`]) and the
//! A200/A700 `ColorTemperature` (`$val*100` then `$val ? $val : "Auto"`) — are
//! rendered through the [`Conv::MinoltaWbMode`] / [`Conv::MinoltaIsoSetting`] /
//! [`Conv::MinoltaColorTemperature`] arms of `emit_exif_value`.
//!
//! MEMORY-SAFE: the header / segment lengths are validated against the block
//! before each read; every field read is bounds-checked through `get`.
//!
//! DEFERRED MinoltaRaw blocks (not reached by the A200 — `MinoltaRaw.pm`): the
//! `\0TTW` embedded-TIFF SubDirectory (`MinoltaTTW`); the `\0PRD`/`\0WBG`/`\0RIF`
//! Minolta-only leaves whose `Condition` excludes a `Make =~ /^SONY/` body —
//! `RIF` `ColorMode` (offset 7), the `WB_RBLevels*` array (offsets 8-44, gated on
//! `DSLR-A100` or the `MRW`-file `MinoltaPRD` DataMember), `ColorFilter`/
//! `ZoneMatching`/`ColorTemperature` (offsets 56/58/60, Minolta make) and the
//! `DSLR-A100`-only `ColorTemperature`/`ColorFilter`/`RawDataLength` (76/77/80).

#[cfg(feature = "alloc")]
use crate::exif::ifd::RawValue;
use crate::exif::tables::{Conv, ExifTag};

// ===========================================================================
// `%MinoltaRaw::PRD` (`MinoltaRaw.pm:55-110`) — raw picture dimensions.
// ===========================================================================
static PRD_FIRMWARE_ID: ExifTag = ExifTag::new(0x00, "FirmwareID", Conv::None);
static PRD_SENSOR_HEIGHT: ExifTag = ExifTag::new(0x08, "SensorHeight", Conv::None);
static PRD_SENSOR_WIDTH: ExifTag = ExifTag::new(0x0a, "SensorWidth", Conv::None);
static PRD_IMAGE_HEIGHT: ExifTag = ExifTag::new(0x0c, "ImageHeight", Conv::None);
static PRD_IMAGE_WIDTH: ExifTag = ExifTag::new(0x0e, "ImageWidth", Conv::None);
static PRD_RAW_DEPTH: ExifTag = ExifTag::new(0x10, "RawDepth", Conv::None);
static PRD_BIT_DEPTH: ExifTag = ExifTag::new(0x11, "BitDepth", Conv::None);
/// `82 => 'Padded', 89 => 'Linear'` (`MinoltaRaw.pm:96-99`).
static PRD_STORAGE_METHOD: ExifTag = ExifTag::new(
  0x12,
  "StorageMethod",
  Conv::IntLabel(&[(82, "Padded"), (89, "Linear")]),
);
/// `1 => 'RGGB', 4 => 'GBRG'` (`MinoltaRaw.pm:104-108`); a miss (e.g. the Sony
/// A850's `0`) renders `Unknown (N)`.
static PRD_BAYER_PATTERN: ExifTag = ExifTag::new(
  0x17,
  "BayerPattern",
  Conv::IntLabel(&[(1, "RGGB"), (4, "GBRG")]),
);

// ===========================================================================
// `%MinoltaRaw::WBG` (`MinoltaRaw.pm:112-137`) — white-balance gains.
// ===========================================================================
static WBG_SCALE: ExifTag = ExifTag::new(0x00, "WBScale", Conv::None);
/// `Condition => '$$self{Model} =~ /DiMAGE A200\b/'` (`MinoltaRaw.pm:126`).
static WBG_GBRG_LEVELS: ExifTag = ExifTag::new(0x04, "WB_GBRGLevels", Conv::None);
/// The `other models` default arm (`MinoltaRaw.pm:131-135`).
static WBG_RGGB_LEVELS: ExifTag = ExifTag::new(0x04, "WB_RGGBLevels", Conv::None);

// ===========================================================================
// `%MinoltaRaw::RIF` (`MinoltaRaw.pm:139-346`) — requested image format.
// ===========================================================================
static RIF_SATURATION: ExifTag = ExifTag::new(0x01, "Saturation", Conv::None);
static RIF_CONTRAST: ExifTag = ExifTag::new(0x02, "Contrast", Conv::None);
static RIF_SHARPNESS: ExifTag = ExifTag::new(0x03, "Sharpness", Conv::None);
/// `Image::ExifTool::MinoltaRaw::ConvertWBMode($val)` (`MinoltaRaw.pm:161`).
static RIF_WB_MODE: ExifTag = ExifTag::new(0x04, "WBMode", Conv::MinoltaWbMode);
/// `0 => 'None', 1 => 'Portrait', 2 => 'Text', 3 => 'Night Portrait',
/// 4 => 'Sunset', 5 => 'Sports'` (`MinoltaRaw.pm:165-174`); the Sony ARW values
/// (7/128/129/160) are HASH misses → `Unknown (N)`.
static RIF_PROGRAM_MODE: ExifTag = ExifTag::new(
  0x05,
  "ProgramMode",
  Conv::IntLabel(&[
    (0, "None"),
    (1, "Portrait"),
    (2, "Text"),
    (3, "Night Portrait"),
    (4, "Sunset"),
    (5, "Sports"),
  ]),
);
/// `RawConv => '$val == 255 ? undef : $val'` (applied in [`parse_rif`]) then the
/// HASH+`OTHER` PrintConv (`MinoltaRaw.pm:177-200`, [`iso_setting_print`]).
static RIF_ISO_SETTING: ExifTag = ExifTag::new(0x06, "ISOSetting", Conv::MinoltaIsoSetting);
static RIF_BW_FILTER: ExifTag = ExifTag::new(0x39, "BWFilter", Conv::None);
static RIF_HUE: ExifTag = ExifTag::new(0x3b, "Hue", Conv::None);
/// `Condition => '$$self{Make} =~ /^SONY/'` (`MinoltaRaw.pm:300-310`):
/// `0 => 'ISO Setting Used', 1 => 'High Key', 2 => 'Low Key'`.
static RIF_ZONE_MATCHING_SONY: ExifTag = ExifTag::new(
  0x4a,
  "ZoneMatching",
  Conv::IntLabel(&[(0, "ISO Setting Used"), (1, "High Key"), (2, "Low Key")]),
);
/// `Condition => '$$self{Model} =~ /^DSLR-A(200|700)$/'` (`MinoltaRaw.pm:325-333`):
/// `ValueConv => '$val * 100'`, `PrintConv => '$val ? $val : "Auto"'`.
static RIF_COLOR_TEMPERATURE_A200: ExifTag =
  ExifTag::new(0x4e, "ColorTemperature", Conv::MinoltaColorTemperature);
/// `Condition => '$$self{Model} =~ /^DSLR-A(200|700)$/'` (`MinoltaRaw.pm:334-338`).
static RIF_COLOR_FILTER_A200: ExifTag = ExifTag::new(0x4f, "ColorFilter", Conv::None);

/// One emitted `MinoltaRaw:*` leaf — the static [`ExifTag`] (its `Name` + the
/// `Conv` rendered through `emit_exif_value`) and the decoded [`RawValue`]. The
/// [`crate::exif`] walker wraps each into a `ResolvedConv::Exif` entry under the
/// `IfdKind::MinoltaRaw` family-1 group.
#[cfg(feature = "alloc")]
pub struct MrwLeaf {
  /// The leaf descriptor (`Name` + `Conv`).
  pub tag: &'static ExifTag,
  /// The decoded value (pre-conversion `$val`).
  pub value: RawValue,
}

/// `ProcessMRW` (`MinoltaRaw.pm:392-495`) — walk the `\0MR[MI]`-headed MRW block
/// in `buf` and emit the A200-class `MinoltaRaw:*` leaves.
///
/// `make`/`model` are the parent IFD0 `Make`/`Model` the `RIF`/`WBG` model
/// `Condition`s read. A block that fails the `^\0MR[MI]` header check (the FX3's
/// non-MRW 0x7250 data, an A33's zero block) emits NOTHING — exactly as
/// `ProcessMRW`'s `$data =~ /^\0MR([MI])/ or return 0` (`MinoltaRaw.pm:410`).
#[cfg(feature = "alloc")]
#[must_use]
pub fn process_mrw(buf: &[u8], make: Option<&str>, model: Option<&str>) -> std::vec::Vec<MrwLeaf> {
  let mut out = std::vec::Vec::new();
  // `$data =~ /^\0MR([MI])/` — `\0MRI` (little-endian, MRWInfo in ARW), `\0MRM`
  // (big-endian, standalone MRW). `SetByteOrder($1 . $1)` (`MinoltaRaw.pm:412`).
  let le = match buf {
    [0, b'M', b'R', b'I', ..] => true,
    [0, b'M', b'R', b'M', ..] => false,
    _ => return out,
  };
  // `$offset = Get32u(\$data, 4) + $pos` with `$pos = 8` (after the header read,
  // `MinoltaRaw.pm:419-420`). The segment loop runs `while ($pos < $offset)`.
  let Some(total) = rd_u32(buf, 4, le) else {
    return out;
  };
  let end = (total as usize).saturating_add(8).min(buf.len());
  let mut pos = 8usize;
  while pos < end {
    // `$raf->Read($data,8) == 8` — the 8-byte segment header (`\0XXX` + int32u
    // length, `MinoltaRaw.pm:425-428`).
    let Some(seg_pos) = pos.checked_add(8) else {
      break;
    };
    let Some(header) = buf.get(pos..seg_pos) else {
      break;
    };
    let Some(len) = rd_u32(buf, pos.wrapping_add(4), le) else {
      break;
    };
    let Some(data_end) = seg_pos.checked_add(len as usize) else {
      break;
    };
    let Some(seg) = buf.get(seg_pos..data_end) else {
      break;
    };
    match header {
      [0, b'P', b'R', b'D', ..] => parse_prd(seg, le, &mut out),
      [0, b'W', b'B', b'G', ..] => parse_wbg(seg, le, model, &mut out),
      [0, b'R', b'I', b'F', ..] => parse_rif(seg, le, make, model, &mut out),
      // `\0TTW` (embedded TIFF) and `\0CSA` (padding) are deferred / skipped
      // (`MinoltaRaw.pm:31-52`, the `else { skip }` arm `:472-475`).
      _ => {}
    }
    pos = data_end;
  }
  out
}

/// `%MinoltaRaw::PRD` (`MinoltaRaw.pm:55-110`).
#[cfg(feature = "alloc")]
fn parse_prd(seg: &[u8], le: bool, out: &mut std::vec::Vec<MrwLeaf>) {
  if let Some(b) = seg.get(0..8) {
    out.push(MrwLeaf {
      tag: &PRD_FIRMWARE_ID,
      value: string_value(b),
    });
  }
  push_u16(seg, 0x08, le, &PRD_SENSOR_HEIGHT, out);
  push_u16(seg, 0x0a, le, &PRD_SENSOR_WIDTH, out);
  push_u16(seg, 0x0c, le, &PRD_IMAGE_HEIGHT, out);
  push_u16(seg, 0x0e, le, &PRD_IMAGE_WIDTH, out);
  push_u8(seg, 0x10, &PRD_RAW_DEPTH, out);
  push_u8(seg, 0x11, &PRD_BIT_DEPTH, out);
  push_u8(seg, 0x12, &PRD_STORAGE_METHOD, out);
  push_u8(seg, 0x17, &PRD_BAYER_PATTERN, out);
}

/// `%MinoltaRaw::WBG` (`MinoltaRaw.pm:112-137`).
#[cfg(feature = "alloc")]
fn parse_wbg(seg: &[u8], le: bool, model: Option<&str>, out: &mut std::vec::Vec<MrwLeaf>) {
  // 0: `WBScale` `int8u[4]`.
  if let Some(b) = seg.get(0..4) {
    out.push(MrwLeaf {
      tag: &WBG_SCALE,
      value: RawValue::U64(b.iter().map(|&x| u64::from(x)).collect()),
    });
  }
  // 4: `int16u[4]` — `WB_GBRGLevels` for `DiMAGE A200`, else `WB_RGGBLevels`.
  if let Some(arr) = rd_u16_array(seg, 0x04, 4, le) {
    let tag = if model.is_some_and(model_is_dimage_a200) {
      &WBG_GBRG_LEVELS
    } else {
      &WBG_RGGB_LEVELS
    };
    out.push(MrwLeaf {
      tag,
      value: RawValue::U64(arr),
    });
  }
}

/// `%MinoltaRaw::RIF` (`MinoltaRaw.pm:139-346`). The A200 is a `Make =~ /^SONY/`,
/// `Model =~ /^DSLR-A200$/` body; the Minolta-only / A100-only leaves are gated
/// off (and the `WB_RBLevels*` array stays deferred — see the module note).
#[cfg(feature = "alloc")]
fn parse_rif(
  seg: &[u8],
  _le: bool,
  make: Option<&str>,
  model: Option<&str>,
  out: &mut std::vec::Vec<MrwLeaf>,
) {
  // `$$self{Make} =~ /^SONY/`.
  let is_sony = make.is_some_and(|m| m.starts_with("SONY"));
  // `$$self{Model} =~ /^DSLR-A(200|700)$/` (the exact `$` anchor).
  let is_a200_a700 = model.is_some_and(|m| m == "DSLR-A200" || m == "DSLR-A700");

  push_i8(seg, 0x01, &RIF_SATURATION, out);
  push_i8(seg, 0x02, &RIF_CONTRAST, out);
  push_i8(seg, 0x03, &RIF_SHARPNESS, out);
  push_u8(seg, 0x04, &RIF_WB_MODE, out);
  push_u8(seg, 0x05, &RIF_PROGRAM_MODE, out);
  // 6: `ISOSetting` — `RawConv => '$val == 255 ? undef : $val'`.
  if let Some(&v) = seg.get(0x06)
    && v != 255
  {
    out.push(leaf_u8(&RIF_ISO_SETTING, v));
  }
  // 7 ColorMode / 8-44 WB_RBLevels* / 56 ColorFilter / 58 ZoneMatching / 60
  // ColorTemperature: Minolta-make / A100 / MinoltaPRD only — deferred for the
  // SONY A200 (module note).
  push_u8(seg, 0x39, &RIF_BW_FILTER, out);
  push_i8(seg, 0x3b, &RIF_HUE, out);
  // 74: `ZoneMatching` — `$$self{Make} =~ /^SONY/`.
  if is_sony {
    push_u8(seg, 0x4a, &RIF_ZONE_MATCHING_SONY, out);
  }
  // 78/79: `ColorTemperature`/`ColorFilter` — `Model =~ /^DSLR-A(200|700)$/`.
  if is_a200_a700 {
    push_u8(seg, 0x4e, &RIF_COLOR_TEMPERATURE_A200, out);
    push_u8(seg, 0x4f, &RIF_COLOR_FILTER_A200, out);
  }
}

/// `ConvertWBMode($val)` (`MinoltaRaw.pm:348-371`): the low nibble selects the
/// WB name (else `Unknown ($lo)`); a high nibble in `6..=12` appends ` (hi-8)`.
#[cfg(feature = "alloc")]
#[must_use]
pub fn convert_wb_mode(val: u64) -> std::string::String {
  let lo = val & 0x0f;
  let name = match lo {
    0 => "Auto",
    1 => "Daylight",
    2 => "Cloudy",
    3 => "Tungsten",
    4 => "Flash/Fluorescent",
    5 => "Fluorescent",
    6 => "Shade",
    7 => "User 1",
    8 => "User 2",
    9 => "User 3",
    10 => "Temperature",
    _ => "",
  };
  let mut s = if name.is_empty() {
    std::format!("Unknown ({lo})")
  } else {
    name.to_string()
  };
  let hi = val >> 4;
  if (6..=12).contains(&hi) {
    s.push_str(&std::format!(" ({})", hi as i64 - 8));
  }
  s
}

/// The rendered `ISOSetting` PrintConv (`MinoltaRaw.pm:179-200`) — either a HASH
/// label or the `OTHER` integer `int(2 ** (($val-48)/8) * 100 + 0.5)`.
#[cfg(feature = "alloc")]
pub enum IsoPrint {
  /// A HASH label (`0 => 'Auto'`, `174 => '80 (Zone Matching Low)'`, …).
  Str(&'static str),
  /// The `OTHER`-computed (or HASH-int) sensitivity.
  Int(i64),
}

/// `ISOSetting` PrintConv (`MinoltaRaw.pm:179-200`): the explicit HASH entries,
/// else `int(2 ** (($val-48)/8) * 100 + 0.5)` (Perl `int` truncates toward zero;
/// the argument is non-negative here).
#[cfg(feature = "alloc")]
#[must_use]
pub fn iso_setting_print(val: u64) -> IsoPrint {
  match val {
    0 => IsoPrint::Str("Auto"),
    48 => IsoPrint::Int(100),
    56 => IsoPrint::Int(200),
    64 => IsoPrint::Int(400),
    72 => IsoPrint::Int(800),
    80 => IsoPrint::Int(1600),
    174 => IsoPrint::Str("80 (Zone Matching Low)"),
    184 => IsoPrint::Str("200 (Zone Matching High)"),
    _ => {
      #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
      let computed = (2f64.powf((val as f64 - 48.0) / 8.0) * 100.0 + 0.5).trunc() as i64;
      IsoPrint::Int(computed)
    }
  }
}

/// `$$self{Model} =~ /DiMAGE A200\b/` — the substring with a trailing Perl `\b`
/// (a word/non-word transition after the `0`).
#[cfg(feature = "alloc")]
fn model_is_dimage_a200(model: &str) -> bool {
  let needle = "DiMAGE A200";
  let bytes = model.as_bytes();
  let nlen = needle.len();
  bytes.windows(nlen).enumerate().any(|(i, w)| {
    w == needle.as_bytes() && {
      // `\b` after the match: end-of-string, or a non-word char follows the
      // word char `0`.
      match bytes.get(i + nlen) {
        None => true,
        Some(&c) => !(c.is_ascii_alphanumeric() || c == b'_'),
      }
    }
  })
}

// ---- bounded readers + leaf constructors --------------------------------

/// `string[N]` — read `b`, trim from the first NUL (`ExifTool.pm:6301`).
#[cfg(feature = "alloc")]
fn string_value(b: &[u8]) -> RawValue {
  let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
  let trimmed = b.get(..end).unwrap_or(b);
  RawValue::Text {
    text: std::string::String::from_utf8_lossy(trimmed).into_owned(),
    raw: trimmed.to_vec().into_boxed_slice(),
  }
}

#[cfg(feature = "alloc")]
fn leaf_u8(tag: &'static ExifTag, v: u8) -> MrwLeaf {
  MrwLeaf {
    tag,
    value: RawValue::U64(std::vec![u64::from(v)]),
  }
}

#[cfg(feature = "alloc")]
fn push_u8(seg: &[u8], off: usize, tag: &'static ExifTag, out: &mut std::vec::Vec<MrwLeaf>) {
  if let Some(&v) = seg.get(off) {
    out.push(leaf_u8(tag, v));
  }
}

#[cfg(feature = "alloc")]
fn push_i8(seg: &[u8], off: usize, tag: &'static ExifTag, out: &mut std::vec::Vec<MrwLeaf>) {
  if let Some(&v) = seg.get(off) {
    out.push(MrwLeaf {
      tag,
      value: RawValue::I64(std::vec![i64::from(v as i8)]),
    });
  }
}

#[cfg(feature = "alloc")]
fn push_u16(
  seg: &[u8],
  off: usize,
  le: bool,
  tag: &'static ExifTag,
  out: &mut std::vec::Vec<MrwLeaf>,
) {
  if let Some(v) = rd_u16(seg, off, le) {
    out.push(MrwLeaf {
      tag,
      value: RawValue::U64(std::vec![u64::from(v)]),
    });
  }
}

/// Read a byte-order-aware `int16u` at `off`.
fn rd_u16(buf: &[u8], off: usize, le: bool) -> Option<u16> {
  match buf.get(off..off.checked_add(2)?) {
    Some(&[a, b]) => Some(if le {
      u16::from_le_bytes([a, b])
    } else {
      u16::from_be_bytes([a, b])
    }),
    _ => None,
  }
}

/// Read a byte-order-aware `int32u` at `off`.
fn rd_u32(buf: &[u8], off: usize, le: bool) -> Option<u32> {
  match buf.get(off..off.checked_add(4)?) {
    Some(&[a, b, c, d]) => Some(if le {
      u32::from_le_bytes([a, b, c, d])
    } else {
      u32::from_be_bytes([a, b, c, d])
    }),
    _ => None,
  }
}

/// Read `count` byte-order-aware `int16u` values at `off` (all-or-nothing — a
/// short tail emits no array, matching `ReadValue`'s exact-count read).
#[cfg(feature = "alloc")]
fn rd_u16_array(buf: &[u8], off: usize, count: usize, le: bool) -> Option<std::vec::Vec<u64>> {
  let mut v = std::vec::Vec::with_capacity(count);
  for i in 0..count {
    let pos = off.checked_add(i.checked_mul(2)?)?;
    v.push(u64::from(rd_u16(buf, pos, le)?));
  }
  Some(v)
}

#[cfg(test)]
#[path = "minoltaraw_tests.rs"]
mod tests;
