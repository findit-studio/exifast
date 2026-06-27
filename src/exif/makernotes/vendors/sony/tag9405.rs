// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Sony::Tag9405a` (`Sony.pm:8879-8956`) and
//! `%Image::ExifTool::Sony::Tag9405b` (`Sony.pm:8959-9197`) — the two enciphered
//! `Tag9405` `ProcessBinaryData` color/lens blocks (lens-mount/-type,
//! distortion / vignetting / chromatic-aberration correction parameters, and —
//! for `Tag9405b` — ISO / exposure / aperture / CreativeStyle).
//!
//! ## Variant dispatch
//!
//! The `0x9405` Main-table row is a conditional-ARRAY SubDirectory dispatcher
//! (`Sony.pm:2024-2040`) selected by the (still-enciphered) FIRST value byte:
//!
//! - `Tag9405a` — `$$valPt =~ /^[\x1b\x40\x7d]/` (valid for SLT, NEX,
//!   ILCE-3000/3500 and several DSC models, `Sony.pm:8884`).
//! - `Tag9405b` — `$$valPt =~ /^[\x3a\xb3\x7e\x9a\x25\xe1\x76\x8b]/` (valid for
//!   the DSC-HX/RX, ILCE-7/9/5000/6000 and ILCA families, `Sony.pm:8965-8970`).
//! - else `Sony_0x9405` (`%unknownCipherData`) — emits nothing.
//!
//! The variant gate is tested on the RAW on-disk (pre-decipher) bytes (the Perl
//! `$$valPt` is pre-decipher); the dispatcher then
//! [`process_enciphered`](super::decipher::process_enciphered)s the block (once,
//! or twice for a double-enciphered body) and hands the per-variant parser the
//! DECIPHERED bytes. Both tables are `FORMAT => 'int8u'` + `FIRST_ENTRY => 0` +
//! `PRIORITY => 0` (`Sony.pm:8880-8887`, `8960-8964`).
//!
//! ## Per-field availability + the `LensMount` DataMember
//!
//! Per the `ProcessBinaryData` contract each tag is emitted IFF its byte range
//! is in the deciphered block ([[exifast-processbinarydata-per-field]]) AND its
//! per-leaf model `Condition` holds; leaves are emitted in ascending offset
//! order (ExifTool processes `ProcessBinaryData` keys numerically).
//!
//! The `DataMember` `LensMount` (`Tag9405a` 0x0604, `Tag9405b` 0x005e) is read
//! first because `LensType2`/`LensType` gate on it. Its `RawConv` sets the
//! DataMember to the RAW byte UNCONDITIONALLY, then a `$$self{Model} =~
//! /^(DSC-|Stellar)/ ? undef : $val` (a / `/^DSC-/` for `Tag9405b`) decides
//! whether the `LensMount` TAG itself is emitted — so a DSC body still latches
//! the DataMember (driving `LensType2`/`LensType`) but suppresses the
//! `LensMount` leaf (`Sony.pm:8919-8929`, `9075-9085`).

use super::{amount_lens_types, lens_types};
use crate::exif::tables::print_exposure_time;
use crate::value::{TagValue, format_g, whole_f64_to_tag_value};
use smol_str::SmolStr;

/// One emitted `Tag9405a`/`Tag9405b` leaf — the resolved tag name and rendered
/// value.
pub struct Tag9405Emission {
  /// `Name => '…'` from the bundled table.
  pub name: &'static str,
  /// The rendered value (`-j` PrintConv result, or `-n` raw `$val`/ValueConv).
  pub value: TagValue,
}

/// Read a little-endian `int16u` at byte `off` of the deciphered block.
fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
  match buf.get(off..off.checked_add(2)?) {
    Some(&[a, b]) => Some(u16::from_le_bytes([a, b])),
    _ => None,
  }
}

/// Read a little-endian `int32u` at byte `off` of the deciphered block.
fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
  match buf.get(off..off.checked_add(4)?) {
    Some(&[a, b, c, d]) => Some(u32::from_le_bytes([a, b, c, d])),
    _ => None,
  }
}

// --- variant gates (tested on the RAW on-disk first byte) --------------------

/// `true` when the on-disk (enciphered) `0x9405` value selects `Tag9405a`
/// (`Sony.pm:2027`, `/^[\x1b\x40\x7d]/`): first byte `0x1b`/`0x40`/`0x7d`.
/// Tested against the RAW on-disk bytes (the Perl `$$valPt` is pre-decipher).
#[must_use]
pub fn selects_tag9405a(raw: &[u8]) -> bool {
  matches!(raw.first(), Some(0x1b | 0x40 | 0x7d))
}

/// `true` when the on-disk (enciphered) `0x9405` value selects `Tag9405b`
/// (`Sony.pm:2032`, `/^[\x3a\xb3\x7e\x9a\x25\xe1\x76\x8b]/`): first byte in that
/// 8-value set. Tested against the RAW on-disk bytes.
#[must_use]
pub fn selects_tag9405b(raw: &[u8]) -> bool {
  matches!(
    raw.first(),
    Some(0x3a | 0xb3 | 0x7e | 0x9a | 0x25 | 0xe1 | 0x76 | 0x8b)
  )
}

// --- model `Condition` predicates --------------------------------------------

/// `$$self{Model} =~ /^(DSC-|Stellar)/` — the `Tag9405a` exclusion class
/// (`Sony.pm:8902` etc.): a `None` model does NOT match.
fn model_is_dsc_or_stellar(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.starts_with("DSC-") || m.starts_with("Stellar"))
}

/// `$$self{Model} =~ /^DSC-/` — the `Tag9405b` exclusion class (`Sony.pm:9046`
/// etc.).
fn model_is_dsc(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.starts_with("DSC-"))
}

/// `$$self{Model} =~ /^(DSC-|ZV-)/` — the `Tag9405b` `SonyFNumber` exclusion
/// (`Sony.pm:9011`).
fn model_is_dsc_or_zv(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.starts_with("DSC-") || m.starts_with("ZV-"))
}

/// `model` starts with any `stem`, then a Perl `\b` word boundary (the next
/// char is NOT `[A-Za-z0-9_]`, or end-of-string). Used for the `…\b`-anchored
/// `VignettingCorrParams`/`ChromaticAberrationCorrParams` conditions, where a
/// bare `ILCE-7` must NOT swallow `ILCE-7M2`/`ILCE-7RM2`/…
fn starts_with_word_boundary(model: Option<&str>, stems: &[&str]) -> bool {
  let Some(m) = model else { return false };
  stems.iter().any(|stem| {
    m.strip_prefix(stem).is_some_and(|rest| {
      rest
        .chars()
        .next()
        .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'))
    })
  })
}

/// `model` starts with any `stem` (a plain Perl `/^(…)/` prefix alternation,
/// NO trailing `\b`). An optional `A?` suffix in the Perl source is reproduced
/// by listing the base stem (the `A?` matches empty in a prefix context).
fn starts_with_any(model: Option<&str>, stems: &[&str]) -> bool {
  let Some(m) = model else { return false };
  stems.iter().any(|stem| m.starts_with(stem))
}

/// `Sony.pm:8893`/`9041` `\b`-anchored set (also the `Tag9405b` 0x034a
/// `VignettingCorrParams` / 0x037c `ChromaticAberrationCorrParams` condition):
/// `/^(ILCA-(68|77M2)|ILCE-(5000|5100|6000|7|7R|7S|QX1)|Lusso)\b/`.
fn model_set_a_mount_early(model: Option<&str>) -> bool {
  starts_with_word_boundary(
    model,
    &[
      "ILCA-68",
      "ILCA-77M2",
      "ILCE-5000",
      "ILCE-5100",
      "ILCE-6000",
      "ILCE-7",
      "ILCE-7R",
      "ILCE-7S",
      "ILCE-QX1",
      "Lusso",
    ],
  )
}

/// `Sony.pm:9120`/`9210` set (0x0368 `VignettingCorrParams` / 0x039c
/// `ChromaticAberrationCorrParams`): `/^(ILCE-(6300|7RM2|7SM2))/`.
fn model_set_6300_7rm2_7sm2(model: Option<&str>) -> bool {
  starts_with_any(model, &["ILCE-6300", "ILCE-7RM2", "ILCE-7SM2"])
}

/// `Sony.pm:9090` 0x0342 `LensZoomPosition` EXCLUSION set (the leaf emits when
/// the model does NOT match):
/// `/^(ILCA-|ILCE-(7RM2|7M3|7RM3A?|7RM4A?|7SM2|6100|6300|6400|6500|6600|7C|9|9M2)|`
/// `DSC-(HX80|HX90V|HX99|RX0|RX10M2|RX10M3|RX10M4|RX100M4|RX100M5|RX100M5A|`
/// `RX100M6|RX100M7|WX500)|ZV-)/`.
fn model_lzp_0x0342_excluded(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  if m.starts_with("ILCA-") || m.starts_with("ZV-") {
    return true;
  }
  starts_with_any(
    model,
    &[
      "ILCE-7RM2",
      "ILCE-7M3",
      "ILCE-7RM3",
      "ILCE-7RM4",
      "ILCE-7SM2",
      "ILCE-6100",
      "ILCE-6300",
      "ILCE-6400",
      "ILCE-6500",
      "ILCE-6600",
      "ILCE-7C",
      "ILCE-9",
      "ILCE-9M2",
      "DSC-HX80",
      "DSC-HX90V",
      "DSC-HX99",
      "DSC-RX0",
      "DSC-RX10M2",
      "DSC-RX10M3",
      "DSC-RX10M4",
      "DSC-RX100M4",
      "DSC-RX100M5",
      "DSC-RX100M5A",
      "DSC-RX100M6",
      "DSC-RX100M7",
      "DSC-WX500",
    ],
  )
}

/// `Sony.pm:9100` 0x034e `LensZoomPosition` set:
/// `/^(DSC-(RX100M5|RX100M5A|RX100M6|RX100M7|RX10M4|HX99)|`
/// `ILCE-(6100|6400|6600|7C|7M3|7RM3A?|7RM4A?|9M2)|ZV-E10)/`.
fn model_lzp_0x034e(model: Option<&str>) -> bool {
  starts_with_any(
    model,
    &[
      "DSC-RX100M5",
      "DSC-RX100M6",
      "DSC-RX100M7",
      "DSC-RX10M4",
      "DSC-HX99",
      "ILCE-6100",
      "ILCE-6400",
      "ILCE-6600",
      "ILCE-7C",
      "ILCE-7M3",
      "ILCE-7RM3",
      "ILCE-7RM4",
      "ILCE-9M2",
      "ZV-E10",
    ],
  )
}

/// `Sony.pm:9110` 0x035a `LensZoomPosition` set:
/// `/^(ILCE-(7RM2|7SM2)|DSC-(HX80|HX90V|RX10M2|RX10M3|RX100M4|WX500))/`.
fn model_lzp_0x035a(model: Option<&str>) -> bool {
  starts_with_any(
    model,
    &[
      "ILCE-7RM2",
      "ILCE-7SM2",
      "DSC-HX80",
      "DSC-HX90V",
      "DSC-RX10M2",
      "DSC-RX10M3",
      "DSC-RX100M4",
      "DSC-WX500",
    ],
  )
}

/// `Sony.pm:9115` 0x035c `VignettingCorrParams` set:
/// `/^(ILCA-99M2|ILCE-(6100|6400|6500|6600|7C|7M3|7RM3A?|7RM4A?|9|9M2)|ZV-E10)/`.
fn model_vcp_0x035c(model: Option<&str>) -> bool {
  starts_with_any(
    model,
    &[
      "ILCA-99M2",
      "ILCE-6100",
      "ILCE-6400",
      "ILCE-6500",
      "ILCE-6600",
      "ILCE-7C",
      "ILCE-7M3",
      "ILCE-7RM3",
      "ILCE-7RM4",
      "ILCE-9",
      "ILCE-9M2",
      "ZV-E10",
    ],
  )
}

/// `Sony.pm:9220` 0x03b8 `ChromaticAberrationCorrParams` set:
/// `/^(ILCE-(6100|6400|6600|7C|7M3|7RM3A?|7RM4A?|9|9M2)|ZV-E10)/`.
fn model_cacp_0x03b8(model: Option<&str>) -> bool {
  starts_with_any(
    model,
    &[
      "ILCE-6100",
      "ILCE-6400",
      "ILCE-6600",
      "ILCE-7C",
      "ILCE-7M3",
      "ILCE-7RM3",
      "ILCE-7RM4",
      "ILCE-9",
      "ILCE-9M2",
      "ZV-E10",
    ],
  )
}

// --- PrintConv hashes --------------------------------------------------------

/// `{ 0 => 'No', 1 => 'Yes' }` — `DistortionCorrParamsPresent`
/// (`Sony.pm:8889`/`9046`).
fn print_no_yes(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "No",
    1 => "Yes",
    _ => return None,
  })
}

/// `{ 0 => 'None', 1 => 'Applied' }` — `DistortionCorrection`
/// (`Sony.pm:8895`/`9052`).
fn print_distortion_correction(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "None",
    1 => "Applied",
    _ => return None,
  })
}

/// `{ 0 => 'Unknown', 1 => 'APS-C', 2 => 'Full-frame' }` — `LensFormat`
/// (`Sony.pm:8908`/`9062`).
fn print_lens_format(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Unknown",
    1 => "APS-C",
    2 => "Full-frame",
    _ => return None,
  })
}

/// `{ 0 => 'Unknown', 1 => 'A-mount', 2 => 'E-mount' }` — `LensMount`
/// (`Sony.pm:8923`/`9079`).
fn print_lens_mount(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Unknown",
    1 => "A-mount",
    2 => "E-mount",
    _ => return None,
  })
}

/// `{ 0 => 'Off', 1 => 'Low', 2 => 'Normal', 3 => 'High' }` —
/// `HighISONoiseReduction` (`Sony.pm:9023-9028`).
fn print_high_iso_nr(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    1 => "Low",
    2 => "Normal",
    3 => "High",
    _ => return None,
  })
}

/// `{ 0 => 'Off', 1 => 'On' }` — `LongExposureNoiseReduction`
/// (`Sony.pm:9031-9034`).
fn print_long_exposure_nr(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    1 => "On",
    _ => return None,
  })
}

/// `%pictureEffect2010` PrintConv hash — `PictureEffect2` (`Sony.pm:6500-6520`,
/// referenced at `Sony.pm:9036`).
fn print_picture_effect2(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Off",
    1 => "Toy Camera",
    2 => "Pop Color",
    3 => "Posterization",
    4 => "Retro Photo",
    5 => "Soft High Key",
    6 => "Partial Color",
    7 => "High Contrast Monochrome",
    8 => "Soft Focus",
    9 => "HDR Painting",
    10 => "Rich-tone Monochrome",
    11 => "Miniature",
    12 => "Water Color",
    13 => "Illustration",
    _ => return None,
  })
}

/// `Tag9405b` 0x004a `CreativeStyle` PrintConv hash (`Sony.pm:9038-9057`).
/// Distinct from the `Tag9416` 0x0037 map (no `19 => FL2` / `20 => FL3`).
fn print_creative_style_b(v: u8) -> Option<&'static str> {
  Some(match v {
    0 => "Standard",
    1 => "Vivid",
    2 => "Neutral",
    3 => "Portrait",
    4 => "Landscape",
    5 => "B&W",
    6 => "Clear",
    7 => "Deep",
    8 => "Light",
    9 => "Sunset",
    10 => "Night View/Portrait",
    11 => "Autumn Leaves",
    13 => "Sepia",
    15 => "FL",
    16 => "VV2",
    17 => "IN",
    18 => "SH",
    255 => "Off",
    _ => return None,
  })
}

// --- value pushers -----------------------------------------------------------

/// An `int8u` row whose PrintConv is a lookup hash. A hash MISS renders
/// `"Unknown ($val)"` in `-j` / the raw `$val` in `-n` ([`super::hash_print_value`]).
fn push_u8_hash(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  hash: impl Fn(u8) -> Option<&'static str>,
  out: &mut std::vec::Vec<Tag9405Emission>,
) {
  let Some(&raw) = buf.get(off) else { return };
  out.push(Tag9405Emission {
    name,
    value: super::hash_print_value(raw, hash(raw), print_conv),
  });
}

/// A raw `int16u` row with no ValueConv/PrintConv (`SonyImageWidthMax`/
/// `SonyImageHeightMax`, `Sony.pm:9019-9020`): the raw integer in both modes.
fn push_u16_raw(
  buf: &[u8],
  off: usize,
  name: &'static str,
  out: &mut std::vec::Vec<Tag9405Emission>,
) {
  if let Some(raw) = read_u16(buf, off) {
    out.push(Tag9405Emission {
      name,
      value: TagValue::I64(i64::from(raw)),
    });
  }
}

/// `SonyISO`/`BaseISO` — int16u, `ValueConv => '100 * 2**(16 - $val/256)'`,
/// `PrintConv => 'sprintf("%.0f",$val)'` (`Sony.pm:8961-8978`).
fn push_sony_iso(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut std::vec::Vec<Tag9405Emission>,
) {
  let Some(raw) = read_u16(buf, off) else {
    return;
  };
  let iso = 100.0 * 2f64.powf(16.0 - f64::from(raw) / 256.0);
  let value = if print_conv {
    TagValue::Str(std::format!("{iso:.0}").into())
  } else {
    whole_f64_to_tag_value(iso)
  };
  out.push(Tag9405Emission { name, value });
}

/// `%gain2010` `StopsAboveBaseISO` — int16u, `ValueConv => '16 - $val/256'`,
/// `PrintConv => '$val ? sprintf("%.1f",$val) : $val'` (`Sony.pm:6274-6286`).
fn push_gain2010(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut std::vec::Vec<Tag9405Emission>,
) {
  let Some(raw) = read_u16(buf, off) else {
    return;
  };
  let stops = 16.0 - f64::from(raw) / 256.0;
  let value = if print_conv && stops != 0.0 {
    // `$val ? sprintf("%.1f",$val) : $val` — a ValueConv of exactly 0 prints the
    // bare ValueConv result (integer `0`); otherwise "%.1f".
    TagValue::Str(std::format!("{stops:.1}").into())
  } else {
    whole_f64_to_tag_value(stops)
  };
  out.push(Tag9405Emission { name, value });
}

/// `SonyExposureTime2` — int16u, `ValueConv => '$val ? 2 ** (16 - $val/256) : 0'`,
/// `PrintConv => '$val ? PrintExposureTime($val) : "Bulb"'` (`Sony.pm:8983-8989`).
fn push_sony_exposure_time2(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut std::vec::Vec<Tag9405Emission>,
) {
  let Some(raw) = read_u16(buf, off) else {
    return;
  };
  let secs = if raw != 0 {
    2f64.powf(16.0 - f64::from(raw) / 256.0)
  } else {
    0.0
  };
  let value = if print_conv {
    if raw != 0 {
      TagValue::Str(print_exposure_time(secs).into())
    } else {
      TagValue::Str("Bulb".into())
    }
  } else {
    whole_f64_to_tag_value(secs)
  };
  out.push(Tag9405Emission { name, value });
}

/// `ExposureTime` — `rational32u` (num/den `int16u` pair), no ValueConv;
/// `PrintConv => '$val ? PrintExposureTime($val) : "Bulb"'` (`Sony.pm:8990-8995`).
/// `GetRational32u`: a 0 denominator yields the literal `'inf'` (num != 0) or
/// `'undef'` (num == 0); `PrintExposureTime` passes both non-numeric strings
/// through. Neither case drops the tag.
fn push_exposure_time_rational(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut std::vec::Vec<Tag9405Emission>,
) {
  let (Some(num), Some(den)) = (
    read_u16(buf, off),
    off.checked_add(2).and_then(|o| read_u16(buf, o)),
  ) else {
    return;
  };
  if den == 0 {
    let literal = if num != 0 { "inf" } else { "undef" };
    out.push(Tag9405Emission {
      name,
      value: TagValue::Str(literal.into()),
    });
    return;
  }
  let secs = round_float(f64::from(num) / f64::from(den), 7);
  let value = if print_conv {
    if secs != 0.0 {
      TagValue::Str(print_exposure_time(secs).into())
    } else {
      TagValue::Str("Bulb".into())
    }
  } else {
    whole_f64_to_tag_value(secs)
  };
  out.push(Tag9405Emission { name, value });
}

/// `SonyFNumber`/`SonyMaxApertureValue` — int16u, `ValueConv => '2 ** (($val/256
/// - 16) / 2)'`, `PrintConv => 'sprintf("%.1f",$val)'` (`Sony.pm:8996-9018`).
fn push_aperture(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut std::vec::Vec<Tag9405Emission>,
) {
  let Some(raw) = read_u16(buf, off) else {
    return;
  };
  let val = 2f64.powf((f64::from(raw) / 256.0 - 16.0) / 2.0);
  let value = if print_conv {
    TagValue::Str(std::format!("{val:.1}").into())
  } else {
    whole_f64_to_tag_value(val)
  };
  out.push(Tag9405Emission { name, value });
}

/// `%sequenceImageNumber` `SequenceImageNumber` — int32u, `ValueConv =>
/// '$val + 1'` (`Sony.pm:6180-6187`). Same value in `-j`/`-n`.
fn push_sequence_image_number(
  buf: &[u8],
  off: usize,
  name: &'static str,
  out: &mut std::vec::Vec<Tag9405Emission>,
) {
  if let Some(raw) = read_u32_le(buf, off) {
    out.push(Tag9405Emission {
      name,
      value: TagValue::I64(i64::from(raw) + 1),
    });
  }
}

/// `Sharpness` — int8s, `PrintConv => '$val > 0 ? "+$val" : $val'`
/// (`Sony.pm:9039-9044`). `-n` keeps the raw `int8s`; `-j` prefixes `+` for a
/// positive value.
fn push_sharpness(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut std::vec::Vec<Tag9405Emission>,
) {
  let Some(&raw) = buf.get(off) else { return };
  let v = i64::from(i8::from_le_bytes([raw]));
  let value = if print_conv && v > 0 {
    TagValue::Str(std::format!("+{v}").into())
  } else {
    TagValue::I64(v)
  };
  out.push(Tag9405Emission { name, value });
}

/// `LensZoomPosition` — int16u, `PrintConv => 'sprintf("%.0f%%",$val/10.24)'`
/// (`Sony.pm:9092` etc.). `-n` keeps the raw int16u (no ValueConv).
fn push_lens_zoom_position(
  buf: &[u8],
  off: usize,
  name: &'static str,
  print_conv: bool,
  out: &mut std::vec::Vec<Tag9405Emission>,
) {
  let Some(raw) = read_u16(buf, off) else {
    return;
  };
  let value = if print_conv {
    TagValue::Str(std::format!("{:.0}%", f64::from(raw) / 10.24).into())
  } else {
    TagValue::I64(i64::from(raw))
  };
  out.push(Tag9405Emission { name, value });
}

/// An `int16s[count]` array row — space-joined for BOTH `-j` and `-n` (no
/// PrintConv; ExifTool joins a multi-element value with spaces). Emitted IFF the
/// whole `count`-element span is in range.
fn push_i16_array(
  buf: &[u8],
  off: usize,
  count: usize,
  name: &'static str,
  out: &mut std::vec::Vec<Tag9405Emission>,
) {
  let Some(end) = count.checked_mul(2).and_then(|n| off.checked_add(n)) else {
    return;
  };
  let Some(span) = buf.get(off..end) else {
    return;
  };
  let mut joined = std::string::String::new();
  for (i, pair) in span.chunks_exact(2).enumerate() {
    use core::fmt::Write;
    if i > 0 {
      joined.push(' ');
    }
    let v = match pair {
      &[lo, hi] => i16::from_le_bytes([lo, hi]),
      _ => continue,
    };
    let _ = write!(joined, "{v}");
  }
  out.push(Tag9405Emission {
    name,
    value: TagValue::Str(joined.into()),
  });
}

/// A `LensType2` (E-mount, `%sonyLensTypes2`) or `LensType` (A-mount,
/// `%sonyLensTypes`) row — int16u, `gated` by the caller on the `LensMount`
/// DataMember (`$$self{LensMount} == 2` / `== 1`). A hash MISS renders
/// `"Unknown ($val)"` (`-j`) / the raw int16u (`-n`); `PrintInt => 1` is a
/// `BuildTagLookup`-only doc flag, not a runtime directive.
fn push_lens_type(
  buf: &[u8],
  off: usize,
  name: &'static str,
  gated: bool,
  lookup: impl Fn(u32) -> Option<SmolStr>,
  print_conv: bool,
  out: &mut std::vec::Vec<Tag9405Emission>,
) {
  if !gated {
    return;
  }
  let Some(raw) = read_u16(buf, off) else {
    return;
  };
  let value = if print_conv {
    match lookup(u32::from(raw)) {
      Some(label) => TagValue::Str(label),
      None => TagValue::Str(SmolStr::from(std::format!("Unknown ({raw})"))),
    }
  } else {
    TagValue::I64(i64::from(raw))
  };
  out.push(Tag9405Emission { name, value });
}

/// `RoundFloat($val, $sig)` (`ExifTool.pm`) — round to `sig` SIGNIFICANT digits
/// via the `%.*g` round-trip.
fn round_float(val: f64, sig: usize) -> f64 {
  format_g(val, sig).parse::<f64>().unwrap_or(val)
}

// --- parsers -----------------------------------------------------------------

/// Walk the DECIPHERED `Tag9405a` block (`Sony.pm:8879-8956`).
///
/// `buf` is the DECIPHERED `0x9405` block (the dispatcher already ran
/// [`process_enciphered`](super::decipher::process_enciphered) — once, or twice
/// for a double-enciphered body). `model` drives the per-leaf model `Condition`s;
/// `print_conv` selects `-j` (PrintConv) vs `-n` (raw `$val`/ValueConv).
#[must_use]
pub fn parse_tag9405a(buf: &[u8], model: Option<&str>, print_conv: bool) -> Vec<Tag9405Emission> {
  let mut out = std::vec::Vec::new();
  let not_dsc = !model_is_dsc_or_stellar(model);

  // 0x0600 DistortionCorrParamsPresent — Condition Model !~ /^(DSC-|Stellar)/.
  if not_dsc {
    push_u8_hash(
      buf,
      0x0600,
      "DistortionCorrParamsPresent",
      print_conv,
      print_no_yes,
      &mut out,
    );
  }
  // 0x0601 DistortionCorrection.
  push_u8_hash(
    buf,
    0x0601,
    "DistortionCorrection",
    print_conv,
    print_distortion_correction,
    &mut out,
  );
  // 0x0603 LensFormat — Condition Model !~ /^(DSC-|Stellar)/.
  if not_dsc {
    push_u8_hash(
      buf,
      0x0603,
      "LensFormat",
      print_conv,
      print_lens_format,
      &mut out,
    );
  }
  // 0x0604 LensMount — DataMember (raw, always latched), tag emitted iff
  // Model !~ /^(DSC-|Stellar)/.
  let lens_mount = buf.get(0x0604).copied();
  if not_dsc {
    push_u8_hash(
      buf,
      0x0604,
      "LensMount",
      print_conv,
      print_lens_mount,
      &mut out,
    );
  }
  // 0x0605 LensType2 — Condition LensMount == 2 (E-mount, %sonyLensTypes2).
  push_lens_type(
    buf,
    0x0605,
    "LensType2",
    lens_mount == Some(2),
    lens_types::lookup_name,
    print_conv,
    &mut out,
  );
  // 0x0608 LensType — Condition LensMount == 1 (A-mount, %sonyLensTypes).
  push_lens_type(
    buf,
    0x0608,
    "LensType",
    lens_mount == Some(1),
    amount_lens_types::lookup_name,
    print_conv,
    &mut out,
  );
  // 0x064a VignettingCorrParams int16s[16] — Condition Model !~ /^(DSC-|Stellar)/.
  if not_dsc {
    push_i16_array(buf, 0x064a, 16, "VignettingCorrParams", &mut out);
  }
  // 0x066a ChromaticAberrationCorrParams int16s[32] — same Condition.
  if not_dsc {
    push_i16_array(buf, 0x066a, 32, "ChromaticAberrationCorrParams", &mut out);
  }
  // 0x06ca DistortionCorrParams int16s[16] — same Condition.
  if not_dsc {
    push_i16_array(buf, 0x06ca, 16, "DistortionCorrParams", &mut out);
  }

  out
}

/// Walk the DECIPHERED `Tag9405b` block (`Sony.pm:8959-9197`).
///
/// `buf` is the DECIPHERED `0x9405` block; `model` drives the (large) set of
/// per-leaf model `Condition`s; `print_conv` selects `-j`/`-n`.
#[must_use]
pub fn parse_tag9405b(buf: &[u8], model: Option<&str>, print_conv: bool) -> Vec<Tag9405Emission> {
  let mut out = std::vec::Vec::new();
  let not_dsc = !model_is_dsc(model);

  // 0x0004 SonyISO / 0x0006 BaseISO.
  push_sony_iso(buf, 0x0004, "SonyISO", print_conv, &mut out);
  push_sony_iso(buf, 0x0006, "BaseISO", print_conv, &mut out);
  // 0x000a StopsAboveBaseISO (%gain2010).
  push_gain2010(buf, 0x000a, "StopsAboveBaseISO", print_conv, &mut out);
  // 0x000e SonyExposureTime2 / 0x0010 ExposureTime (rational32u).
  push_sony_exposure_time2(buf, 0x000e, "SonyExposureTime2", print_conv, &mut out);
  push_exposure_time_rational(buf, 0x0010, "ExposureTime", print_conv, &mut out);
  // 0x0014 SonyFNumber — Condition Model !~ /^(DSC-|ZV-)/.
  if !model_is_dsc_or_zv(model) {
    push_aperture(buf, 0x0014, "SonyFNumber", print_conv, &mut out);
  }
  // 0x0016 SonyMaxApertureValue.
  push_aperture(buf, 0x0016, "SonyMaxApertureValue", print_conv, &mut out);
  // 0x0024 SequenceImageNumber (%sequenceImageNumber, int32u + 1).
  push_sequence_image_number(buf, 0x0024, "SequenceImageNumber", &mut out);
  // 0x0034 ReleaseMode2 (%releaseMode2).
  push_u8_hash(
    buf,
    0x0034,
    "ReleaseMode2",
    print_conv,
    super::release_mode2_print,
    &mut out,
  );
  // 0x003e SonyImageWidthMax / 0x0040 SonyImageHeightMax (raw int16u).
  push_u16_raw(buf, 0x003e, "SonyImageWidthMax", &mut out);
  push_u16_raw(buf, 0x0040, "SonyImageHeightMax", &mut out);
  // 0x0042 HighISONoiseReduction / 0x0044 LongExposureNoiseReduction.
  push_u8_hash(
    buf,
    0x0042,
    "HighISONoiseReduction",
    print_conv,
    print_high_iso_nr,
    &mut out,
  );
  push_u8_hash(
    buf,
    0x0044,
    "LongExposureNoiseReduction",
    print_conv,
    print_long_exposure_nr,
    &mut out,
  );
  // 0x0046 PictureEffect2 (%pictureEffect2010).
  push_u8_hash(
    buf,
    0x0046,
    "PictureEffect2",
    print_conv,
    print_picture_effect2,
    &mut out,
  );
  // 0x0048 ExposureProgram (%exposureProgram2010 == %sonyExposureProgram3).
  push_u8_hash(
    buf,
    0x0048,
    "ExposureProgram",
    print_conv,
    super::print_exposure_program3,
    &mut out,
  );
  // 0x004a CreativeStyle.
  push_u8_hash(
    buf,
    0x004a,
    "CreativeStyle",
    print_conv,
    print_creative_style_b,
    &mut out,
  );
  // 0x0052 Sharpness (int8s).
  push_sharpness(buf, 0x0052, "Sharpness", print_conv, &mut out);
  // 0x005a DistortionCorrParamsPresent — Condition Model !~ /^DSC-/.
  if not_dsc {
    push_u8_hash(
      buf,
      0x005a,
      "DistortionCorrParamsPresent",
      print_conv,
      print_no_yes,
      &mut out,
    );
  }
  // 0x005b DistortionCorrection.
  push_u8_hash(
    buf,
    0x005b,
    "DistortionCorrection",
    print_conv,
    print_distortion_correction,
    &mut out,
  );
  // 0x005d LensFormat — Condition Model !~ /^DSC-/.
  if not_dsc {
    push_u8_hash(
      buf,
      0x005d,
      "LensFormat",
      print_conv,
      print_lens_format,
      &mut out,
    );
  }
  // 0x005e LensMount — DataMember (raw, always latched), tag emitted iff
  // Model !~ /^DSC-/.
  let lens_mount = buf.get(0x005e).copied();
  if not_dsc {
    push_u8_hash(
      buf,
      0x005e,
      "LensMount",
      print_conv,
      print_lens_mount,
      &mut out,
    );
  }
  // 0x0060 LensType2 (E-mount) / 0x0062 LensType (A-mount).
  push_lens_type(
    buf,
    0x0060,
    "LensType2",
    lens_mount == Some(2),
    lens_types::lookup_name,
    print_conv,
    &mut out,
  );
  push_lens_type(
    buf,
    0x0062,
    "LensType",
    lens_mount == Some(1),
    amount_lens_types::lookup_name,
    print_conv,
    &mut out,
  );
  // 0x0064 DistortionCorrParams int16s[16] — Condition Model !~ /^DSC-/.
  if not_dsc {
    push_i16_array(buf, 0x0064, 16, "DistortionCorrParams", &mut out);
  }

  // The model-conditional LensZoomPosition / VignettingCorrParams /
  // ChromaticAberrationCorrParams rows (ascending offset order, mutually
  // exclusive per model).
  // 0x0342 LensZoomPosition — Condition Model !~ /^(big exclusion set)/.
  if !model_lzp_0x0342_excluded(model) {
    push_lens_zoom_position(buf, 0x0342, "LensZoomPosition", print_conv, &mut out);
  }
  // 0x034a VignettingCorrParams int16s[16] — A-mount/early-E set (\b).
  if model_set_a_mount_early(model) {
    push_i16_array(buf, 0x034a, 16, "VignettingCorrParams", &mut out);
  }
  // 0x034e LensZoomPosition.
  if model_lzp_0x034e(model) {
    push_lens_zoom_position(buf, 0x034e, "LensZoomPosition", print_conv, &mut out);
  }
  // 0x0350 VignettingCorrParams int16s[16] — ILCE-7M2.
  if starts_with_any(model, &["ILCE-7M2"]) {
    push_i16_array(buf, 0x0350, 16, "VignettingCorrParams", &mut out);
  }
  // 0x035a LensZoomPosition.
  if model_lzp_0x035a(model) {
    push_lens_zoom_position(buf, 0x035a, "LensZoomPosition", print_conv, &mut out);
  }
  // 0x035c VignettingCorrParams int16s[16].
  if model_vcp_0x035c(model) {
    push_i16_array(buf, 0x035c, 16, "VignettingCorrParams", &mut out);
  }
  // 0x0368 VignettingCorrParams int16s[16] — ILCE-6300/7RM2/7SM2.
  if model_set_6300_7rm2_7sm2(model) {
    push_i16_array(buf, 0x0368, 16, "VignettingCorrParams", &mut out);
  }
  // 0x037c ChromaticAberrationCorrParams int16s[32] — A-mount/early-E set (\b).
  if model_set_a_mount_early(model) {
    push_i16_array(buf, 0x037c, 32, "ChromaticAberrationCorrParams", &mut out);
  }
  // 0x0384 ChromaticAberrationCorrParams int16s[32] — ILCE-7M2.
  if starts_with_any(model, &["ILCE-7M2"]) {
    push_i16_array(buf, 0x0384, 32, "ChromaticAberrationCorrParams", &mut out);
  }
  // 0x039c ChromaticAberrationCorrParams int16s[32] — ILCE-6300/7RM2/7SM2.
  if model_set_6300_7rm2_7sm2(model) {
    push_i16_array(buf, 0x039c, 32, "ChromaticAberrationCorrParams", &mut out);
  }
  // 0x03b0 ChromaticAberrationCorrParams int16s[32] — ILCA-99M2/ILCE-6500.
  if starts_with_any(model, &["ILCA-99M2", "ILCE-6500"]) {
    push_i16_array(buf, 0x03b0, 32, "ChromaticAberrationCorrParams", &mut out);
  }
  // 0x03b8 ChromaticAberrationCorrParams int16s[32].
  if model_cacp_0x03b8(model) {
    push_i16_array(buf, 0x03b8, 32, "ChromaticAberrationCorrParams", &mut out);
  }

  out
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is relaxed for the test
// module, which indexes fixed-layout byte buffers directly (an out-of-range
// index is a test-assertion failure, not a shipped panic).
#[allow(clippy::indexing_slicing)]
#[path = "tag9405_tests.rs"]
mod tests;
