// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Canon-specific PrintConv enum — covers the per-tag PrintConv hashes
//! and inline sprintf expressions in `Canon.pm` for Main + CameraSettings
//! + FileInfo + FocalLength.

use super::lens_types;
use super::model_ids;
use crate::exif::ifd::RawValue;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::string::String;
use std::vec::Vec;

/// Per-tag PrintConv strategy for the Canon Main IFD table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CanonPrintConv {
  /// No PrintConv — emit raw.
  None,
  /// `FileNumber` (`Canon.pm:1264`) — `s/(\d+)(\d{4})/$1-$2/` so
  /// `1181861` ⇒ `"118-1861"`.
  FileNumberDash,
  /// `SerialNumber` (`Canon.pm:1282-1306`) — conditional LIST on Model:
  /// `$$self{Model} =~ /EOS D30\b/` ⇒ `sprintf("%.4x%.5d",$val>>16,
  /// $val&0xffff)` (`Canon.pm:1286-1288`); `$$self{Model} =~ /EOS-1D/` ⇒
  /// `sprintf("%.6u",$val)` (`Canon.pm:1295-1297`); else `sprintf("%.10u",
  /// $val)` (`Canon.pm:1302-1304`). The parent body `$$self{Model}` is
  /// threaded in via [`CanonPrintConv::apply`]'s `model` argument.
  SerialNumber,
  /// `SerialNumberFormat` (`Canon.pm:1619-1622`) — int32u, PrintHex with
  /// `0x90000000 => 'Format 1', 0xa0000000 => 'Format 2'`.
  SerialNumberFormat,
  /// `SuperMacro` (`Canon.pm:1628-1632`) — `{0=>'Off',1=>'On (1)',2=>'On (2)'}`.
  SuperMacro,
  /// `DateStampMode` (`Canon.pm:1638-1642`) — `{0=>'Off',1=>'Date',2=>'Date & Time'}`.
  DateStampMode,
  /// `FirmwareRevision` (`Canon.pm:1658-1664`) — formatted hex.
  FirmwareRevision,
  /// `CanonModelID` (`Canon.pm:1583-1589`) — `int32u`, PrintHex, lookup
  /// against `%canonModelID`.
  ModelId,
  /// `ImageUniqueID` (`Canon.pm:1727-1733`) — undef[16], `unpack("H*")`.
  HexEncoded,
  /// `ColorSpace` (`Canon.pm:1943-1947`) — `{1=>'sRGB',2=>'Adobe RGB',
  /// 65535=>'n/a'}`. NOTE: Canon's `0xffff` maps to `'n/a'`, NOT the
  /// EXIF 0xa001 `'Uncalibrated'` convention.
  ColorSpace,
  /// `PictureStyleUserDef` (0x4008, `Canon.pm:2066-2073`) +
  /// `PictureStylePC` (0x4009, `Canon.pm:2074-2081`) — `int16u`,
  /// `Count => 3`, `PrintHex => 1`, array PrintConv
  /// `[\%pictureStyles,\%pictureStyles,\%pictureStyles]`. Each of the 3
  /// elements is converted through `%pictureStyles`
  /// (`Canon.pm:1119-1148`); unknown → `Unknown (0xNN)` (PrintHex). The
  /// converted elements are joined with `"; "` for PrintConv
  /// (`ExifTool.pm:3697`).
  PictureStyle,
  /// Canon `LensType` (`Canon.pm:2500-2509`) — `int16u`, PrintConv via
  /// `%canonLensTypes`.
  LensType,
}

impl CanonPrintConv {
  /// Apply the PrintConv to a raw value. `model` is the parent body's
  /// `$$self{Model}` (from IFD0), needed for the model-conditional
  /// `SerialNumber` list (`Canon.pm:1282-1306`); all other arms ignore it.
  #[must_use]
  pub fn apply(self, raw: &RawValue, print_conv: bool, model: Option<&str>) -> TagValue {
    match self {
      CanonPrintConv::None => raw_to_tag_value(raw),
      CanonPrintConv::FileNumberDash => {
        let Some(n) = first_u64(raw) else {
          return raw_to_tag_value(raw);
        };
        if print_conv {
          TagValue::Str(file_number_dash(n).into())
        } else {
          TagValue::U64(n)
        }
      }
      CanonPrintConv::SerialNumber => {
        let Some(n) = first_u64(raw) else {
          return raw_to_tag_value(raw);
        };
        if print_conv {
          // Conditional list (`Canon.pm:1282-1306`): match the parent
          // body `$$self{Model}` against each `Condition` in order.
          let s = if model.is_some_and(model_matches_eos_d30) {
            // `Canon.pm:1286-1288` — `EOS D30\b`:
            // `sprintf("%.4x%.5d", $val>>16, $val&0xffff)`.
            std::format!("{:04x}{:05}", n >> 16, n & 0xffff)
          } else if model.is_some_and(|m| m.contains("EOS-1D")) {
            // `Canon.pm:1295-1297` — `EOS-1D`: `sprintf("%.6u", $val)`.
            std::format!("{n:06}")
          } else {
            // `Canon.pm:1302-1304` — default: `sprintf("%.10u", $val)`.
            std::format!("{n:010}")
          };
          TagValue::Str(SmolStr::from(s))
        } else {
          TagValue::U64(n)
        }
      }
      CanonPrintConv::SerialNumberFormat => {
        let Some(n) = first_u64(raw) else {
          return raw_to_tag_value(raw);
        };
        if print_conv {
          let label = match n {
            0x9000_0000 => "Format 1",
            0xa000_0000 => "Format 2",
            _ => return TagValue::Str(SmolStr::from(std::format!("Unknown ({n})"))),
          };
          TagValue::Str(label.into())
        } else {
          TagValue::U64(n)
        }
      }
      CanonPrintConv::SuperMacro => simple_label(raw, print_conv, |n| match n {
        0 => Some("Off"),
        1 => Some("On (1)"),
        2 => Some("On (2)"),
        _ => None,
      }),
      CanonPrintConv::DateStampMode => simple_label(raw, print_conv, |n| match n {
        0 => Some("Off"),
        1 => Some("Date"),
        2 => Some("Date & Time"),
        _ => None,
      }),
      CanonPrintConv::FirmwareRevision => {
        let Some(n) = first_u64(raw) else {
          return raw_to_tag_value(raw);
        };
        if print_conv {
          TagValue::Str(firmware_revision_text(n).into())
        } else {
          TagValue::U64(n)
        }
      }
      CanonPrintConv::ModelId => {
        let Some(n) = first_u64(raw) else {
          return raw_to_tag_value(raw);
        };
        if print_conv {
          match model_ids::lookup_name(n as u32) {
            Some(name) => TagValue::Str(name),
            None => TagValue::Str(SmolStr::from(std::format!("Unknown ({n:#010x})"))),
          }
        } else {
          // -n: bare integer.
          TagValue::U64(n)
        }
      }
      CanonPrintConv::HexEncoded => {
        let bytes = match raw {
          RawValue::Bytes(b) => b,
          RawValue::U64(v) => {
            // Should NOT happen for undef but defensive.
            let bytes: Vec<u8> = v.iter().map(|&n| n as u8).collect();
            return TagValue::Str(SmolStr::from(hex_encode(&bytes)));
          }
          _ => return raw_to_tag_value(raw),
        };
        TagValue::Str(SmolStr::from(hex_encode(bytes)))
      }
      CanonPrintConv::ColorSpace => simple_label(raw, print_conv, |n| match n {
        // `Canon.pm:1943-1947` — Canon's ColorSpace map. 65535 ⇒ 'n/a'
        // (NOT the EXIF 0xa001 'Uncalibrated').
        1 => Some("sRGB"),
        2 => Some("Adobe RGB"),
        65535 => Some("n/a"),
        _ => None,
      }),
      CanonPrintConv::PictureStyle => picture_style_array(raw, print_conv),
      CanonPrintConv::LensType => {
        let Some(n) = first_u64(raw) else {
          return raw_to_tag_value(raw);
        };
        if print_conv {
          let id = u16::try_from(n).unwrap_or(0);
          match lens_types::lookup_name(id) {
            Some(name) => TagValue::Str(name),
            None => TagValue::Str(SmolStr::from(std::format!("Unknown ({n})"))),
          }
        } else {
          TagValue::U64(n)
        }
      }
    }
  }
}

/// `$$self{Model} =~ /EOS 5D/` (`Canon.pm:1837`). UNANCHORED substring
/// match — NOT a word boundary (unlike [`model_matches_eos_d30`]) and NOT
/// the `\b5D$` end-anchor used by the FocalLength `Condition`
/// ([`super::focal_length`]). So "EOS 5D", "EOS 5D Mark II/III/IV",
/// "EOS 5DS", "EOS 5DS R" ALL match (each contains the literal `EOS 5D`),
/// which is what gates Canon Main tag `0x96` onto the `SerialInfo`
/// SubDirectory rather than `InternalSerialNumber` (`Canon.pm:1834-1846`).
pub(super) fn model_matches_eos_5d(model: &str) -> bool {
  model.contains("EOS 5D")
}

/// `$$self{Model} =~ /EOS D30\b/` (`Canon.pm:1286`). `\b` is a word
/// boundary, so "EOS D30" must be followed by a non-word char (`[^A-Za-z0-9_]`)
/// or end-of-string — it must NOT match "EOS D300", "EOS D30s", etc.
fn model_matches_eos_d30(model: &str) -> bool {
  let needle = "EOS D30";
  let mut search = model;
  while let Some(idx) = search.find(needle) {
    // The char immediately after the match must be a word boundary.
    let after = &search[idx + needle.len()..];
    let boundary = after
      .chars()
      .next()
      .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
    if boundary {
      return true;
    }
    // Advance past this occurrence and keep scanning.
    search = &search[idx + needle.len()..];
  }
  false
}

/// `"118-1861"` from `1181861` — bundled `s/(\d+)(\d{4})/$1-$2/`.
fn file_number_dash(n: u64) -> String {
  let s = std::format!("{n}");
  if s.len() > 4 {
    let split = s.len() - 4;
    std::format!("{}-{}", &s[..split], &s[split..])
  } else {
    s
  }
}

/// `FirmwareRevision` print: bundled at `Canon.pm:1658-1664` —
/// `sprintf("%.8x", $val)` then split into prefix + groups.
fn firmware_revision_text(val: u64) -> String {
  let rev = std::format!("{:08x}", val);
  // Pattern: ^(.)(.)(..)0?(.+)(..)$
  let bytes = rev.as_bytes();
  if bytes.len() < 6 {
    return rev;
  }
  let rel = bytes[0] as char;
  let v1 = bytes[1] as char;
  let v2 = core::str::from_utf8(&bytes[2..4]).unwrap_or("--");
  // 0?(.+)(..) — strip optional leading 0 from the r1 group
  let mid = core::str::from_utf8(&bytes[4..bytes.len() - 2]).unwrap_or("--");
  let r1 = mid.strip_prefix('0').unwrap_or(mid);
  let r2 = core::str::from_utf8(&bytes[bytes.len() - 2..]).unwrap_or("--");
  let prefix = match rel {
    'a' => "Alpha ",
    'b' => "Beta ",
    '0' => "",
    _ => return std::format!("Unknown({rel}) {v1}.{v2} rev {r1}.{r2}"),
  };
  std::format!("{prefix}{v1}.{v2} rev {r1}.{r2}")
}

/// `%pictureStyles` (`Canon.pm:1119-1148`) — base picture-style codes.
/// Returns the label for a known code, else `None` (the caller renders the
/// `PrintHex` `Unknown (0xNN)` fallback). Faithful key→label port:
///
/// ```text
/// 0x00 => 'None'              0x06 => 'CM Set 1'    0x42 => 'PC 2'
/// 0x01 => 'Standard'         0x07 => 'CM Set 2'    0x43 => 'PC 3'
/// 0x02 => 'Portrait'         0x21 => 'User Def. 1' 0x81 => 'Standard'
/// 0x03 => 'High Saturation'  0x22 => 'User Def. 2' 0x82 => 'Portrait'
/// 0x04 => 'Adobe RGB'        0x23 => 'User Def. 3' 0x83 => 'Landscape'
/// 0x05 => 'Low Saturation'   0x41 => 'PC 1'        0x84 => 'Neutral'
/// 0x85 => 'Faithful'  0x86 => 'Monochrome'  0x87 => 'Auto'
/// 0x88 => 'Fine Detail'  0xff => 'n/a'  0xffff => 'n/a'
/// ```
fn picture_style_label(n: i64) -> Option<&'static str> {
  match n {
    0x00 => Some("None"),
    0x01 => Some("Standard"),
    0x02 => Some("Portrait"),
    0x03 => Some("High Saturation"),
    0x04 => Some("Adobe RGB"),
    0x05 => Some("Low Saturation"),
    0x06 => Some("CM Set 1"),
    0x07 => Some("CM Set 2"),
    0x21 => Some("User Def. 1"),
    0x22 => Some("User Def. 2"),
    0x23 => Some("User Def. 3"),
    0x41 => Some("PC 1"),
    0x42 => Some("PC 2"),
    0x43 => Some("PC 3"),
    0x81 => Some("Standard"),
    0x82 => Some("Portrait"),
    0x83 => Some("Landscape"),
    0x84 => Some("Neutral"),
    0x85 => Some("Faithful"),
    0x86 => Some("Monochrome"),
    0x87 => Some("Auto"),
    0x88 => Some("Fine Detail"),
    0xff => Some("n/a"),
    0xffff => Some("n/a"),
    _ => None,
  }
}

/// Array PrintConv for `PictureStyleUserDef` / `PictureStylePC`
/// (`Canon.pm:2066-2081`). `Count => 3`, `PrintHex => 1`, PrintConv
/// `[\%pictureStyles,\%pictureStyles,\%pictureStyles]`.
///
/// ExifTool array-PrintConv semantics (`ExifTool.pm:3550-3697`): split the
/// value into elements, convert element i through hash i (all three are
/// `%pictureStyles` here), then join. For `PrintConv` the join separator
/// is `"; "` (`ExifTool.pm:3697`); each unknown element renders the
/// `PrintHex` `Unknown (0xNN)` fallback (`ExifTool.pm:3628-3634`). For the
/// `-n` (ValueConv) path no conversion runs and the raw ints are joined
/// with `" "` (matching [`raw_to_tag_value`]).
fn picture_style_array(raw: &RawValue, print_conv: bool) -> TagValue {
  let elems: Vec<i64> = match raw {
    RawValue::U64(v) => v.iter().map(|&n| n as i64).collect(),
    RawValue::I64(v) => v.clone(),
    _ => return raw_to_tag_value(raw),
  };
  if !print_conv {
    // `-n`: bare ints joined with a space (same as `raw_to_tag_value`).
    return raw_to_tag_value(raw);
  }
  use std::string::ToString;
  let parts: Vec<String> = elems
    .iter()
    .map(|&n| match picture_style_label(n) {
      Some(label) => label.to_string(),
      // PrintHex => 1 ⇒ `Unknown (0xNN)` (`ExifTool.pm:3631`).
      None => std::format!("Unknown (0x{n:x})"),
    })
    .collect();
  TagValue::Str(SmolStr::from(parts.join("; ")))
}

/// Hex-encode bytes (lowercase, no separators).
fn hex_encode(bytes: &[u8]) -> String {
  use std::fmt::Write;
  let mut out = String::with_capacity(bytes.len() * 2);
  for &b in bytes {
    write!(&mut out, "{b:02x}").ok();
  }
  out
}

/// First scalar `u64` from a raw value — common for int* tags.
fn first_u64(raw: &RawValue) -> Option<u64> {
  match raw {
    RawValue::U64(v) => v.first().copied(),
    RawValue::I64(v) => v.first().and_then(|&n| u64::try_from(n).ok()),
    _ => None,
  }
}

/// First scalar `i64` from a raw value.
fn first_i64(raw: &RawValue) -> Option<i64> {
  match raw {
    RawValue::I64(v) => v.first().copied(),
    RawValue::U64(v) => v.first().and_then(|&n| i64::try_from(n).ok()),
    _ => None,
  }
}

/// Generic int → label PrintConv. `print_conv=false` returns the raw int.
fn simple_label<F: Fn(i64) -> Option<&'static str>>(
  raw: &RawValue,
  print_conv: bool,
  f: F,
) -> TagValue {
  let Some(n) = first_i64(raw) else {
    return raw_to_tag_value(raw);
  };
  if print_conv {
    match f(n) {
      Some(label) => TagValue::Str(label.into()),
      None => TagValue::Str(SmolStr::from(std::format!("Unknown ({n})"))),
    }
  } else {
    TagValue::I64(n)
  }
}

/// Render a raw value as a default [`TagValue`] (no PrintConv).
pub(crate) fn raw_to_tag_value(raw: &RawValue) -> TagValue {
  use std::string::ToString;
  match raw {
    RawValue::I64(v) if v.len() == 1 => TagValue::I64(v[0]),
    RawValue::I64(v) => TagValue::Str(
      v.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(" ")
        .into(),
    ),
    RawValue::U64(v) if v.len() == 1 => match i64::try_from(v[0]) {
      Ok(n) => TagValue::I64(n),
      Err(_) => TagValue::U64(v[0]),
    },
    RawValue::U64(v) => TagValue::Str(
      v.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(" ")
        .into(),
    ),
    RawValue::F64(v) if v.len() == 1 => TagValue::F64(v[0]),
    RawValue::F64(v) => TagValue::Str(
      v.iter()
        .map(|f| f.to_string())
        .collect::<Vec<_>>()
        .join(" ")
        .into(),
    ),
    RawValue::Rational(rs) if rs.len() == 1 => TagValue::Rational(rs[0]),
    RawValue::Rational(rs) => TagValue::Str(
      rs.iter()
        .map(|r| std::format!("{}/{}", r.numerator(), r.denominator()))
        .collect::<Vec<_>>()
        .join(" ")
        .into(),
    ),
    RawValue::Text(s) => TagValue::Str(s.as_str().into()),
    RawValue::Bytes(b) => TagValue::Bytes(b.clone()),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn file_number_dash_inserts_separator() {
    assert_eq!(file_number_dash(1181861), "118-1861");
    assert_eq!(file_number_dash(11234), "1-1234");
    assert_eq!(file_number_dash(123), "123"); // short — unchanged.
  }

  #[test]
  fn serial_number_pads_to_10_digits() {
    // Default branch (`Canon.pm:1304`, `sprintf("%.10u")`) — no model.
    let raw = RawValue::U64(vec![560018150]);
    let v = CanonPrintConv::SerialNumber.apply(&raw, true, None);
    assert_eq!(v, TagValue::Str("0560018150".into()));
  }

  /// `EOS-1D` branch (`Canon.pm:1295-1297`): `sprintf("%.6u", $val)`.
  /// Raw 500292 ⇒ "500292" (already 6 digits, no padding).
  #[test]
  fn serial_number_eos_1d_six_digits() {
    let raw = RawValue::U64(vec![500292]);
    let v = CanonPrintConv::SerialNumber.apply(&raw, true, Some("Canon EOS-1D Mark IV"));
    assert_eq!(v, TagValue::Str("500292".into()));
    // A short value zero-pads to 6.
    let raw2 = RawValue::U64(vec![42]);
    let v2 = CanonPrintConv::SerialNumber.apply(&raw2, true, Some("Canon EOS-1Ds Mark II"));
    assert_eq!(v2, TagValue::Str("000042".into()));
  }

  /// `EOS D30` branch (`Canon.pm:1286-1288`):
  /// `sprintf("%.4x%.5d", $val>>16, $val&0xffff)`.
  #[test]
  fn serial_number_eos_d30_hex_dec_form() {
    // 0x00ab_0001 ⇒ hi=0x00ab ⇒ "00ab", lo=1 ⇒ "00001" ⇒ "00ab00001".
    let raw = RawValue::U64(vec![0x00ab_0001]);
    let v = CanonPrintConv::SerialNumber.apply(&raw, true, Some("Canon EOS D30"));
    assert_eq!(v, TagValue::Str("00ab00001".into()));
  }

  /// `/EOS D30\b/` must NOT match "EOS D300" (word boundary) — it falls
  /// through to the default `%.10u` branch.
  #[test]
  fn serial_number_eos_d300_not_d30() {
    let raw = RawValue::U64(vec![560018150]);
    let v = CanonPrintConv::SerialNumber.apply(&raw, true, Some("Canon EOS D300"));
    assert_eq!(v, TagValue::Str("0560018150".into()));
  }

  /// `-n` (value-conv) mode emits the bare integer regardless of model.
  #[test]
  fn serial_number_value_conv_bare_int() {
    let raw = RawValue::U64(vec![500292]);
    let v = CanonPrintConv::SerialNumber.apply(&raw, false, Some("Canon EOS-1D Mark IV"));
    assert_eq!(v, TagValue::U64(500292));
  }

  #[test]
  fn serial_number_format_resolves_known_labels() {
    let raw = RawValue::U64(vec![0x9000_0000]);
    assert_eq!(
      CanonPrintConv::SerialNumberFormat.apply(&raw, true, None),
      TagValue::Str("Format 1".into())
    );
  }

  #[test]
  fn model_id_resolves_against_canonmodelid() {
    // 0x80000189 → "EOS Digital Rebel XT / 350D / Kiss Digital N"
    let raw = RawValue::U64(vec![0x80000189]);
    let v = CanonPrintConv::ModelId.apply(&raw, true, None);
    assert_eq!(
      v,
      TagValue::Str("EOS Digital Rebel XT / 350D / Kiss Digital N".into())
    );
  }

  #[test]
  fn lens_type_resolves_against_canonlenstypes() {
    let raw = RawValue::U64(vec![1]);
    let v = CanonPrintConv::LensType.apply(&raw, true, None);
    assert_eq!(v, TagValue::Str("Canon EF 50mm f/1.8".into()));
  }

  #[test]
  fn unknown_label_renders_unknown_n() {
    let raw = RawValue::U64(vec![99]);
    let v = CanonPrintConv::SuperMacro.apply(&raw, true, None);
    assert_eq!(v, TagValue::Str("Unknown (99)".into()));
  }

  #[test]
  fn print_conv_off_emits_raw_int() {
    let raw = RawValue::U64(vec![1]);
    let v = CanonPrintConv::LensType.apply(&raw, false, None);
    assert_eq!(v, TagValue::U64(1));
  }

  #[test]
  fn hex_encoded_undef_array() {
    let raw = RawValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef]);
    let v = CanonPrintConv::HexEncoded.apply(&raw, true, None);
    assert_eq!(v, TagValue::Str("deadbeef".into()));
  }

  #[test]
  fn model_matches_eos_d30_word_boundary() {
    assert!(model_matches_eos_d30("Canon EOS D30"));
    assert!(model_matches_eos_d30("Canon EOS D30 ")); // trailing space = boundary
    assert!(!model_matches_eos_d30("Canon EOS D300"));
    assert!(!model_matches_eos_d30("Canon EOS D30s"));
    assert!(!model_matches_eos_d30("Canon EOS 5D"));
  }

  /// `/EOS 5D/` (`Canon.pm:1837`) — UNANCHORED substring. The whole
  /// 5D family matches (base + Mark II/III/IV + 5DS / 5DS R); non-5D
  /// bodies do not.
  #[test]
  fn model_matches_eos_5d_is_unanchored_substring() {
    assert!(model_matches_eos_5d("Canon EOS 5D"));
    assert!(model_matches_eos_5d("Canon EOS 5D Mark II"));
    assert!(model_matches_eos_5d("Canon EOS 5D Mark III"));
    assert!(model_matches_eos_5d("Canon EOS 5D Mark IV"));
    assert!(model_matches_eos_5d("Canon EOS 5DS"));
    assert!(model_matches_eos_5d("Canon EOS 5DS R"));
    // Not the 5D family.
    assert!(!model_matches_eos_5d("Canon EOS 6D"));
    assert!(!model_matches_eos_5d("Canon EOS 50D"));
    assert!(!model_matches_eos_5d("Canon EOS-1D Mark IV"));
    assert!(!model_matches_eos_5d("Canon EOS D30"));
  }

  /// `Canon.pm:1943-1947` — Canon ColorSpace 65535 ⇒ 'n/a' (NOT the EXIF
  /// 0xa001 'Uncalibrated'). Also covers 1/2 and -n raw.
  #[test]
  fn color_space_maps_canon_values() {
    let srgb = RawValue::U64(vec![1]);
    assert_eq!(
      CanonPrintConv::ColorSpace.apply(&srgb, true, None),
      TagValue::Str("sRGB".into())
    );
    let adobe = RawValue::U64(vec![2]);
    assert_eq!(
      CanonPrintConv::ColorSpace.apply(&adobe, true, None),
      TagValue::Str("Adobe RGB".into())
    );
    // 65535 ⇒ 'n/a' (the gap that was previously 'Uncalibrated').
    let na = RawValue::U64(vec![65535]);
    assert_eq!(
      CanonPrintConv::ColorSpace.apply(&na, true, None),
      TagValue::Str("n/a".into())
    );
    // -n (value-conv) ⇒ bare raw int 65535.
    assert_eq!(
      CanonPrintConv::ColorSpace.apply(&na, false, None),
      TagValue::I64(65535)
    );
  }

  /// `Canon.pm:2066-2081` — PictureStyleUserDef/PC, `Count => 3`,
  /// `PrintHex => 1`, array PrintConv `[\%pictureStyles x3]`. Known codes
  /// resolve via `%pictureStyles`; converted elements join with `"; "`
  /// (`ExifTool.pm:3697`).
  #[test]
  fn picture_style_array_known_values() {
    // 0x81/0x82/0x83 ⇒ Standard/Portrait/Landscape.
    let raw = RawValue::U64(vec![0x81, 0x82, 0x83]);
    let v = CanonPrintConv::PictureStyle.apply(&raw, true, None);
    assert_eq!(v, TagValue::Str("Standard; Portrait; Landscape".into()));
    // Lower ColorMatrix range + User Def + None.
    let raw2 = RawValue::U64(vec![0x00, 0x21, 0x41]);
    let v2 = CanonPrintConv::PictureStyle.apply(&raw2, true, None);
    assert_eq!(v2, TagValue::Str("None; User Def. 1; PC 1".into()));
  }

  /// Unknown style codes use the `PrintHex` `Unknown (0xNN)` fallback
  /// (`ExifTool.pm:3628-3631`), mixed with known labels.
  #[test]
  fn picture_style_array_unknown_uses_print_hex() {
    let raw = RawValue::U64(vec![0x84, 0x99, 0xab]);
    let v = CanonPrintConv::PictureStyle.apply(&raw, true, None);
    assert_eq!(
      v,
      TagValue::Str("Neutral; Unknown (0x99); Unknown (0xab)".into())
    );
  }

  /// `-n` (value-conv) emits the bare ints joined by a space — no
  /// `%pictureStyles` conversion, matching `raw_to_tag_value`.
  #[test]
  fn picture_style_array_value_conv_raw_ints() {
    let raw = RawValue::U64(vec![0x81, 0x99, 0x88]);
    let v = CanonPrintConv::PictureStyle.apply(&raw, false, None);
    // 0x81=129, 0x99=153, 0x88=136.
    assert_eq!(v, TagValue::Str("129 153 136".into()));
  }

  #[test]
  fn firmware_revision_text_decodes_release_v_r() {
    // Canon.pm:1658 — sprintf("%.8x", $val) ⇒ regex
    // `^(.)(.)(..)0?(.+)(..)$`. For 0x01001000 ⇒ "01001000":
    //   rel='0', v1='1', v2='00', 0?=empty, r1='10', r2='00'.
    // With '0' ⇒ '' prefix: "1.00 rev 10.00".
    let text = firmware_revision_text(0x01001000);
    assert_eq!(text, "1.00 rev 10.00");
  }
}
