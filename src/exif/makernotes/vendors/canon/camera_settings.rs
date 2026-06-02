// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Canon::CameraSettings` (`Canon.pm:2214-2690`).
//!
//! Binary-data sub-table indexed by 2-byte word position
//! (`FORMAT => 'int16s'`, `FIRST_ENTRY => 1`). 53 named tag positions
//! covering MacroMode/SelfTimer/Quality/CanonFlashMode/ContinuousDrive/
//! FocusMode/CanonImageSize/EasyMode/DigitalZoom/Contrast/Saturation/
//! Sharpness/CameraISO/MeteringMode/FocusRange/AFPoint/CanonExposureMode/
//! LensType/Max+MinFocalLength/FocalUnits/Max+MinAperture/FlashModel/
//! FlashBits/FocusContinuous/AESetting/ImageStabilization/etc.
//!
//! The data is parsed as int16s words (or int16u where specified per
//! tag) at index `position` from the start of the binary blob.
//!
//! Per-tag PrintConv: the bundled `PrintConv => { … }` hashes are
//! ported as inline match arms in [`apply_print_conv`].

// Golden-v2 Contract 3c (Phase C, slice w2d): panic-safety by construction —
// every raw index/slice below is dominated by a preceding length/count guard
// and converted to a checked `.get()` form (re-asserts the parent `exif`
// deny over the makernotes subtree's slice-D/E `#![allow]` shim).
#![deny(clippy::indexing_slicing)]

use crate::value::TagValue;
use smol_str::SmolStr;
use std::string::String;
use std::vec::Vec;

/// One CameraSettings word position + its PrintConv name.
#[derive(Debug, Clone, Copy)]
pub struct CameraSettingsTag {
  /// Position index (`Canon.pm` `FIRST_ENTRY => 1` ⇒ word 1 is at byte
  /// offset 2 from the start of the sub-table blob).
  pub position: usize,
  /// `Name => '…'` from bundled.
  pub name: &'static str,
  /// `int16u` override (default is `int16s` per `FORMAT => 'int16s'`).
  pub format_override: Option<CsFormat>,
  /// PrintConv strategy.
  pub conv: CsPrintConv,
}

/// CameraSettings per-tag format override.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsFormat {
  /// `int16u` — used for `LensType`, `MaxFocalLength`, `MinFocalLength`,
  /// `FocalUnits` (which are unsigned counts).
  Int16u,
}

/// CameraSettings per-tag PrintConv.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CsPrintConv {
  /// No PrintConv — emit raw integer.
  None,
  /// `MacroMode` (`Canon.pm:2220-2226`).
  MacroMode,
  /// `SelfTimer` (`Canon.pm:2227-2239`).
  SelfTimer,
  /// `Quality` (`Canon.pm:2240-2243`) — `%canonQuality` (subset).
  Quality,
  /// `CanonFlashMode` (`Canon.pm:2244-2257`).
  FlashMode,
  /// `ContinuousDrive` (`Canon.pm:2258-2275`).
  ContinuousDrive,
  /// `FocusMode` (`Canon.pm:2276-2294`).
  FocusMode,
  /// `RecordMode` (`Canon.pm:2295-2314`).
  RecordMode,
  /// `CanonImageSize` (`Canon.pm:2315-2319`) — common subset.
  CanonImageSize,
  /// `EasyMode` (`Canon.pm:2320-2406`) — the big-list, partial.
  EasyMode,
  /// `DigitalZoom` (`Canon.pm:2407-2415`).
  DigitalZoom,
  /// `Contrast` (`Canon.pm:2417-2421`) / `Saturation` (`Canon.pm:2422-
  /// 2426`) / `ColorTone` (`Canon.pm:2659-2663`) —
  /// `%Image::ExifTool::Exif::printParameter`
  /// (`Exif.pm:327-332`): `PrintConv => { 0 => 'Normal', OTHER =>
  /// \&PrintParameter }`. `PrintParameter` (`Exif.pm:5628-5640`) maps
  /// `$val > 0` ⇒ `"+$val"` (the `> 0xfff0` negative-in-disguise branch
  /// is unreachable for int16s), else `$val`. NOTE: `Sharpness`
  /// (`Canon.pm:2427-2436`) does NOT use this — it has its own
  /// [`CsPrintConv::Sharpness`] conv with no `0 => 'Normal'`.
  PrintParameter,
  /// `Sharpness` (`Canon.pm:2427-2436`) — `PrintConv => '$val > 0 ?
  /// "+$val" : $val'`. NO `%printParameter`, so `0` stays `"0"` (not
  /// "Normal"); positives gain a leading `+`; negatives pass through.
  /// `RawConv => '$val == 0x7fff ? undef : $val'` (`Canon.pm:2429`).
  Sharpness,
  /// `CameraISO` (`Canon.pm:2438-2441`) — `ValueConv =>
  /// 'Image::ExifTool::Canon::CameraISO($val)'`. No PrintConv (the
  /// ValueConv already yields the human value), so `-j` and `-n` agree.
  CameraIso,
  /// `MeteringMode` (`Canon.pm:2442-2452`).
  MeteringMode,
  /// `FocusRange` (`Canon.pm:2453-2469`).
  FocusRange,
  /// `AFPoint` (`Canon.pm:2470-2484`).
  AfPoint,
  /// `CanonExposureMode` (`Canon.pm:2485-2498`).
  ExposureMode,
  /// `LensType` (`Canon.pm:2499-2509`) — lens-type ID → human name.
  LensType,
  /// `MaxFocalLength`/`MinFocalLength` — `sprintf("%d mm", $val)`.
  /// Note: ExifTool reports `MaxFocalLength` and `MinFocalLength` in mm
  /// AFTER dividing by FocalUnits — we emit the same shape.
  FocalLengthMm,
  /// `FocalUnits` — `"$val/mm"`.
  FocalUnitsMm,
  /// `MaxAperture`/`MinAperture` — `sprintf("%.2g", exp(CanonEv($val)*log(2)/2))`.
  CanonApex,
  /// `FocusContinuous` (`Canon.pm:2578-2586`).
  FocusContinuous,
  /// `AESetting` (`Canon.pm:2587-2597`).
  AeSetting,
  /// `ImageStabilization` (`Canon.pm:2598-2614`).
  ImageStabilization,
  /// `FlashModel` (`Canon.pm:2554-2560`) — `Mask => 0x7f`,
  /// `RawConv => '$val == 127 ? undef : $val'`,
  /// `PrintConv => \%flashModel` (`Canon.pm:1029-1049`). The mask is
  /// applied in [`parse_with_lens_id_capture`] before the skip + conv.
  FlashModel,
  /// `FlashBits` (`Canon.pm:2561-2578`) — `PrintConv => { 0 => '(none)',
  /// BITMASK => {...} }`. ExifTool `DecodeBits` (`ExifTool.pm:6387-6406`):
  /// each set bit → its label (an unknown bit `n` → `[n]`), joined `", "`;
  /// value 0 → `(none)`. No `ValueConv`, so `-n` emits the raw int.
  FlashBits,
  /// `DisplayAperture` (`Canon.pm:2616-2621`) — `RawConv => '$val ? $val
  /// : undef'`, `ValueConv => '$val / 10'`. No PrintConv (so `-j` and
  /// `-n` agree on the float).
  DisplayAperture,
  /// `FocusBracketing` (`Canon.pm:2676-2679`) — `{0=>'Disable',1=>'Enable'}`.
  FocusBracketing,
  /// `Clarity` (`Canon.pm:2680-2685`, EOS R models) —
  /// `PrintConv => { OTHER => sub { shift }, 0x7fff => 'n/a' }`. There is
  /// NO `RawConv`, so `0x7fff` is NOT dropped: in PrintConv mode it maps
  /// to `"n/a"`; every OTHER value passes through unchanged (raw int). In
  /// `-n` (value-conv) mode there is no ValueConv, so the bare raw int —
  /// including `32767` — is emitted.
  Clarity,
  /// `HDR-PQ` (`Canon.pm:2687-2690`) — `{ %offOn, -1 => 'n/a' }` =
  /// `{ -1=>'n/a', 0=>'Off', 1=>'On' }`.
  HdrPq,
  /// `SpotMeteringMode` (`Canon.pm:2623-2630`).
  SpotMetering,
  /// `PhotoEffect` (`Canon.pm:2631-2645`).
  PhotoEffect,
  /// `ManualFlashOutput` (`Canon.pm:2646-2656`).
  ManualFlashOutput,
  /// `SRAWQuality` (`Canon.pm:2663-2671`).
  SrawQuality,
}

/// `%Canon::CameraSettings` table — sorted by `position`.
pub const CAMERA_SETTINGS: &[CameraSettingsTag] = &[
  CameraSettingsTag {
    position: 1,
    name: "MacroMode",
    format_override: None,
    conv: CsPrintConv::MacroMode,
  },
  CameraSettingsTag {
    position: 2,
    name: "SelfTimer",
    format_override: None,
    conv: CsPrintConv::SelfTimer,
  },
  CameraSettingsTag {
    position: 3,
    name: "Quality",
    format_override: None,
    conv: CsPrintConv::Quality,
  },
  CameraSettingsTag {
    position: 4,
    name: "CanonFlashMode",
    format_override: None,
    conv: CsPrintConv::FlashMode,
  },
  CameraSettingsTag {
    position: 5,
    name: "ContinuousDrive",
    format_override: None,
    conv: CsPrintConv::ContinuousDrive,
  },
  CameraSettingsTag {
    position: 7,
    name: "FocusMode",
    format_override: None,
    conv: CsPrintConv::FocusMode,
  },
  CameraSettingsTag {
    position: 9,
    name: "RecordMode",
    format_override: None,
    conv: CsPrintConv::RecordMode,
  },
  CameraSettingsTag {
    position: 10,
    name: "CanonImageSize",
    format_override: None,
    conv: CsPrintConv::CanonImageSize,
  },
  CameraSettingsTag {
    position: 11,
    name: "EasyMode",
    format_override: None,
    conv: CsPrintConv::EasyMode,
  },
  CameraSettingsTag {
    position: 12,
    name: "DigitalZoom",
    format_override: None,
    conv: CsPrintConv::DigitalZoom,
  },
  CameraSettingsTag {
    position: 13,
    name: "Contrast",
    format_override: None,
    conv: CsPrintConv::PrintParameter,
  },
  CameraSettingsTag {
    position: 14,
    name: "Saturation",
    format_override: None,
    conv: CsPrintConv::PrintParameter,
  },
  CameraSettingsTag {
    // `Canon.pm:2427-2436` — own PrintConv `'$val > 0 ? "+$val" : $val'`,
    // NOT `%printParameter` (so 0 ⇒ "0", never "Normal").
    position: 15,
    name: "Sharpness",
    format_override: None,
    conv: CsPrintConv::Sharpness,
  },
  CameraSettingsTag {
    position: 16,
    name: "CameraISO",
    format_override: None,
    conv: CsPrintConv::CameraIso,
  },
  CameraSettingsTag {
    position: 17,
    name: "MeteringMode",
    format_override: None,
    conv: CsPrintConv::MeteringMode,
  },
  CameraSettingsTag {
    position: 18,
    name: "FocusRange",
    format_override: None,
    conv: CsPrintConv::FocusRange,
  },
  CameraSettingsTag {
    position: 19,
    name: "AFPoint",
    format_override: None,
    conv: CsPrintConv::AfPoint,
  },
  CameraSettingsTag {
    position: 20,
    name: "CanonExposureMode",
    format_override: None,
    conv: CsPrintConv::ExposureMode,
  },
  CameraSettingsTag {
    position: 22,
    name: "LensType",
    format_override: Some(CsFormat::Int16u),
    conv: CsPrintConv::LensType,
  },
  CameraSettingsTag {
    position: 23,
    name: "MaxFocalLength",
    format_override: Some(CsFormat::Int16u),
    conv: CsPrintConv::FocalLengthMm,
  },
  CameraSettingsTag {
    position: 24,
    name: "MinFocalLength",
    format_override: Some(CsFormat::Int16u),
    conv: CsPrintConv::FocalLengthMm,
  },
  CameraSettingsTag {
    position: 25,
    name: "FocalUnits",
    format_override: None,
    conv: CsPrintConv::FocalUnitsMm,
  },
  CameraSettingsTag {
    position: 26,
    name: "MaxAperture",
    format_override: None,
    conv: CsPrintConv::CanonApex,
  },
  CameraSettingsTag {
    position: 27,
    name: "MinAperture",
    format_override: None,
    conv: CsPrintConv::CanonApex,
  },
  CameraSettingsTag {
    position: 28,
    name: "FlashModel",
    format_override: None,
    conv: CsPrintConv::FlashModel,
  },
  CameraSettingsTag {
    position: 29,
    name: "FlashBits",
    format_override: None,
    conv: CsPrintConv::FlashBits,
  },
  CameraSettingsTag {
    position: 32,
    name: "FocusContinuous",
    format_override: None,
    conv: CsPrintConv::FocusContinuous,
  },
  CameraSettingsTag {
    position: 33,
    name: "AESetting",
    format_override: None,
    conv: CsPrintConv::AeSetting,
  },
  CameraSettingsTag {
    position: 34,
    name: "ImageStabilization",
    format_override: None,
    conv: CsPrintConv::ImageStabilization,
  },
  CameraSettingsTag {
    position: 35,
    name: "DisplayAperture",
    format_override: None,
    conv: CsPrintConv::DisplayAperture,
  },
  CameraSettingsTag {
    position: 36,
    name: "ZoomSourceWidth",
    format_override: None,
    conv: CsPrintConv::None,
  },
  CameraSettingsTag {
    position: 37,
    name: "ZoomTargetWidth",
    format_override: None,
    conv: CsPrintConv::None,
  },
  CameraSettingsTag {
    position: 39,
    name: "SpotMeteringMode",
    format_override: None,
    conv: CsPrintConv::SpotMetering,
  },
  CameraSettingsTag {
    position: 40,
    name: "PhotoEffect",
    format_override: None,
    conv: CsPrintConv::PhotoEffect,
  },
  CameraSettingsTag {
    position: 41,
    name: "ManualFlashOutput",
    format_override: None,
    conv: CsPrintConv::ManualFlashOutput,
  },
  CameraSettingsTag {
    position: 42,
    name: "ColorTone",
    format_override: None,
    conv: CsPrintConv::PrintParameter,
  },
  CameraSettingsTag {
    position: 46,
    name: "SRAWQuality",
    format_override: None,
    conv: CsPrintConv::SrawQuality,
  },
  CameraSettingsTag {
    // `Canon.pm:2676-2679` — `{ 0 => 'Disable', 1 => 'Enable' }`.
    position: 50,
    name: "FocusBracketing",
    format_override: None,
    conv: CsPrintConv::FocusBracketing,
  },
  CameraSettingsTag {
    // `Canon.pm:2680-2685` — `PrintConv => { OTHER => sub { shift },
    // 0x7fff => 'n/a' }`. There is NO `RawConv`, so 0x7fff is NOT
    // dropped — it maps to "n/a" in PrintConv mode (see
    // [`CsPrintConv::Clarity`]) and is emitted as the raw int in `-n`.
    position: 51,
    name: "Clarity",
    format_override: None,
    conv: CsPrintConv::Clarity,
  },
  CameraSettingsTag {
    // `Canon.pm:2687-2690` — `{ %offOn, -1 => 'n/a' }`.
    position: 52,
    name: "HDR-PQ",
    format_override: None,
    conv: CsPrintConv::HdrPq,
  },
];

/// Parse a CameraSettings blob (the SubDirectory data referenced by
/// `Canon.pm:1226-1230`). Emits `(name, value)` tuples for the
/// MakerNotes sink.
///
/// `data` is the raw blob bytes (just the value-data — the leading 2-byte
/// length word is bundled `Canon::Validate` territory; we tolerate
/// either shape by allowing position-1's int16s to be either the count
/// or the first data word).
///
/// `parent_order` is the parent IFD walk's byte order.
#[must_use]
pub fn parse(
  data: &[u8],
  parent_order: crate::exif::ifd::ByteOrder,
  print_conv: bool,
) -> Vec<(SmolStr, TagValue)> {
  parse_with_lens_id_capture(data, parent_order, print_conv, &mut None)
}

/// Like [`parse`] but writes the LensType ID into `lens_id_out` for the
/// typed [`MakerNotesCanon::lens_type`](super::MakerNotesCanon::lens_type)
/// surface accessor.
pub fn parse_with_lens_id_capture(
  data: &[u8],
  parent_order: crate::exif::ifd::ByteOrder,
  print_conv: bool,
  lens_id_out: &mut Option<u16>,
) -> Vec<(SmolStr, TagValue)> {
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  // The blob's word-0 is the BLOB-LENGTH in bytes (per ExifTool's
  // `Canon::Validate` check at `Canon.pm`'s `binaryDataAttrs`); the
  // first DATA word is at position 1 (`FIRST_ENTRY => 1`). Word N is at
  // byte offset `2*N`.
  if data.len() < 4 {
    return out;
  }
  let order = parent_order;
  // DataMember resolution (`Canon.pm:2219` `DATAMEMBER => [ 22, 25 ]`):
  // ExifTool's `ProcessBinaryData` resolves DataMembers BEFORE the main
  // walk, so the `FocalUnits` RawConv (`$$self{FocalUnits} = $val`,
  // `Canon.pm:2534`) at position 25 is set before Max/MinFocalLength
  // (positions 23/24) apply `ValueConv => '$val / ($$self{FocalUnits} ||
  // 1)'` (`Canon.pm:2516/2525`). Position 25 is a LATER position than
  // 23/24, so we must PRE-READ it here — walking positions in order would
  // otherwise divide by a not-yet-set FocalUnits.
  let captured_focal_units: Option<i16> = read_focal_units_word(data, order);
  for t in CAMERA_SETTINGS {
    let byte_off = 2 * t.position;
    if byte_off + 2 > data.len() {
      break;
    }
    // The `byte_off + 2 > data.len()` guard above makes `data.get(byte_off..
    // byte_off+2)` `Some` and its `try_into()` to `[u8; 2]` succeed — the
    // checked, byte-identical form of `[data[byte_off], data[byte_off+1]]`
    // (the `[0, 0]` fallback is unreachable).
    let arr: [u8; 2] = data
      .get(byte_off..byte_off + 2)
      .and_then(|s| s.try_into().ok())
      .unwrap_or([0, 0]);
    let raw_word = match order {
      crate::exif::ifd::ByteOrder::Little => i16::from_le_bytes(arr),
      crate::exif::ifd::ByteOrder::Big => i16::from_be_bytes(arr),
    };
    // `Mask` (applied BEFORE RawConv + (Print|Value)Conv, like bundled's
    // `ProcessBinaryData`): FlashModel (position 28) is `Mask => 0x7f`
    // (`Canon.pm:2557`). No other ported CameraSettings position has a
    // Mask.
    let raw_int = if t.position == 28 {
      raw_word & 0x7f
    } else {
      raw_word
    };
    // Apply RawConv guards (`$val == 0x7fff ? undef : $val` for
    // Contrast/Saturation/Sharpness/CameraISO/ColorTone/Clarity; `-1 ⇒
    // undef` for RecordMode/FocusContinuous/AESetting/ImageStabilization
    // etc.; `0 ⇒ undef` for AFPoint/MaxAperture/MinAperture; `127 ⇒
    // undef` for the masked FlashModel).
    if should_skip(t, raw_int) {
      continue;
    }
    // Convert to the appropriate i64/u64 depending on format_override.
    let value_int: i64 = match t.format_override {
      Some(CsFormat::Int16u) => (raw_int as u16) as i64,
      None => raw_int as i64,
    };
    // Capture LensType for the typed surface.
    if t.name == "LensType" {
      *lens_id_out = Some(value_int as u16);
    }
    // FocalUnits (position 25) is pre-read into `captured_focal_units`
    // above (DataMember ordering), so no in-loop reassignment is needed.
    let tag_value = apply_print_conv(t.conv, value_int, print_conv, captured_focal_units);
    out.push((t.name.into(), tag_value));
  }
  out
}

/// Apply the per-position PrintConv.
fn apply_print_conv(
  conv: CsPrintConv,
  val: i64,
  print_conv: bool,
  focal_units: Option<i16>,
) -> TagValue {
  // ValueConv-only positions (no `PrintConv` in bundled): the converted
  // value is emitted IDENTICALLY in `-j` (PrintConv) and `-n` (ValueConv)
  // modes, so these must be computed BEFORE the `!print_conv` early
  // return below.
  match conv {
    CsPrintConv::CameraIso => return camera_iso(val),
    CsPrintConv::DisplayAperture => {
      // `ValueConv => '$val / 10'` (`Canon.pm:2619`). No PrintConv.
      return TagValue::F64(val as f64 / 10.0);
    }
    CsPrintConv::CanonApex => {
      // `MaxAperture`/`MinAperture` (`Canon.pm:2539-2553`) BOTH have a
      // `ValueConv => 'exp(CanonEv($val)*log(2)/2)'` and a `PrintConv =>
      // 'sprintf("%.2g",$val)'`. So `-n` (ValueConv) emits the converted
      // FLOAT (e.g. 3.5636), and `-j` (PrintConv) the `%.2g` of that float
      // (3.6) — NOT the raw int. This must be computed BEFORE the
      // `!print_conv` early-return below.
      let f_val = canon_ev_to_aperture(val);
      return if print_conv {
        TagValue::Str(format_g_two(f_val).into())
      } else {
        TagValue::F64(f_val)
      };
    }
    _ => {}
  }
  if !print_conv {
    return TagValue::I64(val);
  }
  let label_or_default = |label: Option<&'static str>| -> TagValue {
    match label {
      Some(l) => TagValue::Str(l.into()),
      None => TagValue::Str(SmolStr::from(std::format!("Unknown ({val})"))),
    }
  };
  match conv {
    CsPrintConv::None => TagValue::I64(val),
    CsPrintConv::MacroMode => label_or_default(match val {
      1 => Some("Macro"),
      2 => Some("Normal"),
      _ => None,
    }),
    CsPrintConv::SelfTimer => {
      if val == 0 {
        TagValue::Str("Off".into())
      } else {
        let seconds = (val & 0xfff) as f64 / 10.0;
        let custom = (val & 0x4000) != 0;
        let s = if custom {
          std::format!("{seconds} s, Custom")
        } else {
          std::format!("{seconds} s")
        };
        TagValue::Str(s.into())
      }
    }
    CsPrintConv::Quality => label_or_default(match val {
      // `%canonQuality` (`Canon.pm:1051-1061`).
      -1 => Some("n/a"),
      1 => Some("Economy"),
      2 => Some("Normal"),
      3 => Some("Fine"),
      4 => Some("RAW"),
      5 => Some("Superfine"),
      7 => Some("CRAW"),
      130 => Some("Light (RAW)"),
      131 => Some("Standard (RAW)"),
      _ => None,
    }),
    CsPrintConv::FlashMode => label_or_default(match val {
      -1 => Some("n/a"),
      0 => Some("Off"),
      1 => Some("Auto"),
      2 => Some("On"),
      3 => Some("Red-eye reduction"),
      4 => Some("Slow-sync"),
      5 => Some("Red-eye reduction (Auto)"),
      6 => Some("Red-eye reduction (On)"),
      16 => Some("External flash"),
      _ => None,
    }),
    CsPrintConv::ContinuousDrive => label_or_default(match val {
      0 => Some("Single"),
      1 => Some("Continuous"),
      2 => Some("Movie"),
      3 => Some("Continuous, Speed Priority"),
      4 => Some("Continuous, Low"),
      5 => Some("Continuous, High"),
      6 => Some("Silent Single"),
      8 => Some("Continuous, High+"),
      9 => Some("Single, Silent"),
      10 => Some("Continuous, Silent"),
      _ => None,
    }),
    CsPrintConv::FocusMode => label_or_default(match val {
      0 => Some("One-shot AF"),
      1 => Some("AI Servo AF"),
      2 => Some("AI Focus AF"),
      3 => Some("Manual Focus (3)"),
      4 => Some("Single"),
      5 => Some("Continuous"),
      6 => Some("Manual Focus (6)"),
      16 => Some("Pan Focus"),
      256 => Some("One-shot AF (Live View)"),
      257 => Some("AI Servo AF (Live View)"),
      258 => Some("AI Focus AF (Live View)"),
      512 => Some("Movie Snap Focus"),
      519 => Some("Movie Servo AF"),
      _ => None,
    }),
    CsPrintConv::RecordMode => label_or_default(match val {
      1 => Some("JPEG"),
      2 => Some("CRW+THM"),
      3 => Some("AVI+THM"),
      4 => Some("TIF"),
      5 => Some("TIF+JPEG"),
      6 => Some("CR2"),
      7 => Some("CR2+JPEG"),
      9 => Some("MOV"),
      10 => Some("MP4"),
      11 => Some("CRM"),
      12 => Some("CR3"),
      13 => Some("CR3+JPEG"),
      14 => Some("HIF"),
      15 => Some("CR3+HIF"),
      _ => None,
    }),
    CsPrintConv::CanonImageSize => label_or_default(match val {
      // `%canonImageSize` (`Canon.pm:1062-1082`).
      -1 => Some("n/a"),
      0 => Some("Large"),
      1 => Some("Medium"),
      2 => Some("Small"),
      5 => Some("Medium 1"),
      6 => Some("Medium 2"),
      7 => Some("Medium 3"),
      8 => Some("Postcard"),
      9 => Some("Widescreen"),
      10 => Some("Medium Widescreen"),
      14 => Some("Small 1"),
      15 => Some("Small 2"),
      16 => Some("Small 3"),
      128 => Some("640x480 Movie"),
      129 => Some("Medium Movie"),
      130 => Some("Small Movie"),
      137 => Some("1280x720 Movie"),
      142 => Some("1920x1080 Movie"),
      143 => Some("4096x2160 Movie"),
      _ => None,
    }),
    CsPrintConv::EasyMode => label_or_default(match val {
      0 => Some("Full auto"),
      1 => Some("Manual"),
      2 => Some("Landscape"),
      3 => Some("Fast shutter"),
      4 => Some("Slow shutter"),
      5 => Some("Night"),
      6 => Some("Gray Scale"),
      7 => Some("Sepia"),
      8 => Some("Portrait"),
      9 => Some("Sports"),
      10 => Some("Macro"),
      11 => Some("Black & White"),
      12 => Some("Pan focus"),
      13 => Some("Vivid"),
      14 => Some("Neutral"),
      15 => Some("Flash Off"),
      16 => Some("Long Shutter"),
      17 => Some("Super Macro"),
      18 => Some("Foliage"),
      19 => Some("Indoor"),
      20 => Some("Fireworks"),
      21 => Some("Beach"),
      22 => Some("Underwater"),
      23 => Some("Snow"),
      24 => Some("Kids & Pets"),
      25 => Some("Night Snapshot"),
      26 => Some("Digital Macro"),
      27 => Some("My Colors"),
      28 => Some("Movie Snap"),
      29 => Some("Super Macro 2"),
      30 => Some("Color Accent"),
      31 => Some("Color Swap"),
      32 => Some("Aquarium"),
      33 => Some("ISO 3200"),
      34 => Some("ISO 6400"),
      35 => Some("Creative Light Effect"),
      36 => Some("Easy"),
      37 => Some("Quick Shot"),
      38 => Some("Creative Auto"),
      39 => Some("Zoom Blur"),
      40 => Some("Low Light"),
      41 => Some("Nostalgic"),
      42 => Some("Super Vivid"),
      43 => Some("Poster Effect"),
      44 => Some("Face Self-timer"),
      45 => Some("Smile"),
      46 => Some("Wink Self-timer"),
      47 => Some("Fisheye Effect"),
      48 => Some("Miniature Effect"),
      49 => Some("High-speed Burst"),
      50 => Some("Best Image Selection"),
      51 => Some("High Dynamic Range"),
      52 => Some("Handheld Night Scene"),
      53 => Some("Movie Digest"),
      54 => Some("Live View Control"),
      55 => Some("Discreet"),
      56 => Some("Blur Reduction"),
      57 => Some("Monochrome"),
      58 => Some("Toy Camera Effect"),
      59 => Some("Scene Intelligent Auto"),
      60 => Some("High-speed Burst HQ"),
      61 => Some("Smooth Skin"),
      62 => Some("Soft Focus"),
      68 => Some("Food"),
      84 => Some("HDR Art Standard"),
      85 => Some("HDR Art Vivid"),
      93 => Some("HDR Art Bold"),
      257 => Some("Spotlight"),
      258 => Some("Night 2"),
      259 => Some("Night+"),
      260 => Some("Super Night"),
      261 => Some("Sunset"),
      263 => Some("Night Scene"),
      264 => Some("Surface"),
      265 => Some("Low Light 2"),
      _ => None,
    }),
    CsPrintConv::DigitalZoom => label_or_default(match val {
      0 => Some("None"),
      1 => Some("2x"),
      2 => Some("4x"),
      3 => Some("Other"),
      _ => None,
    }),
    CsPrintConv::PrintParameter => {
      // `%Image::ExifTool::Exif::printParameter` (`Exif.pm:327-332`):
      // `PrintConv => { 0 => 'Normal', OTHER => \&PrintParameter }`.
      // `0` maps to "Normal" via the hash; every other value goes
      // through `PrintParameter` (`Exif.pm:5628-5640`): `$val > 0` ⇒
      // `"+$val"`, else `$val`. (The `$val > 0xfff0` negative-in-
      // disguise branch is unreachable here — the source FORMAT is
      // int16s, so `$val` is already signed and never exceeds 32767.)
      if val == 0 {
        TagValue::Str("Normal".into())
      } else {
        let s = if val > 0 {
          std::format!("+{val}")
        } else {
          std::format!("{val}")
        };
        TagValue::Str(s.into())
      }
    }
    CsPrintConv::Sharpness => {
      // `Canon.pm:2434` — `PrintConv => '$val > 0 ? "+$val" : $val'`.
      // No `0 => 'Normal'`: zero renders as "0", negatives pass through.
      let s = if val > 0 {
        std::format!("+{val}")
      } else {
        std::format!("{val}")
      };
      TagValue::Str(s.into())
    }
    CsPrintConv::MeteringMode => label_or_default(match val {
      0 => Some("Default"),
      1 => Some("Spot"),
      2 => Some("Average"),
      3 => Some("Evaluative"),
      4 => Some("Partial"),
      5 => Some("Center-weighted average"),
      _ => None,
    }),
    CsPrintConv::FocusRange => label_or_default(match val {
      0 => Some("Manual"),
      1 => Some("Auto"),
      2 => Some("Not Known"),
      3 => Some("Macro"),
      4 => Some("Very Close"),
      5 => Some("Close"),
      6 => Some("Middle Range"),
      7 => Some("Far Range"),
      8 => Some("Pan Focus"),
      9 => Some("Super Macro"),
      10 => Some("Infinity"),
      _ => None,
    }),
    CsPrintConv::AfPoint => label_or_default(match val {
      0x2005 => Some("Manual AF point selection"),
      0x3000 => Some("None (MF)"),
      0x3001 => Some("Auto AF point selection"),
      0x3002 => Some("Right"),
      0x3003 => Some("Center"),
      0x3004 => Some("Left"),
      0x4001 => Some("Auto AF point selection"),
      0x4006 => Some("Face Detect"),
      _ => None,
    }),
    CsPrintConv::ExposureMode => label_or_default(match val {
      0 => Some("Easy"),
      1 => Some("Program AE"),
      2 => Some("Shutter speed priority AE"),
      3 => Some("Aperture-priority AE"),
      4 => Some("Manual"),
      5 => Some("Depth-of-field AE"),
      6 => Some("M-Dep"),
      7 => Some("Bulb"),
      8 => Some("Flexible-priority AE"),
      _ => None,
    }),
    CsPrintConv::LensType => {
      let id = val as u16;
      match super::lens_types::lookup_name(id) {
        Some(name) => TagValue::Str(name),
        None => {
          // Bundled emits the bare number when no lens-type matches.
          TagValue::Str(SmolStr::from(std::format!("Unknown ({val})")))
        }
      }
    }
    CsPrintConv::FocalLengthMm => {
      // `$val / FocalUnits` then `"$val mm"`. FocalUnits unknown ⇒ raw mm.
      let units = focal_units.unwrap_or(1).max(1) as f64;
      let mm = val as f64 / units;
      // Drop trailing .0 like Perl's `"$val mm"` interpolation.
      let s = if mm.fract() == 0.0 {
        std::format!("{} mm", mm as i64)
      } else {
        std::format!("{mm} mm")
      };
      TagValue::Str(s.into())
    }
    CsPrintConv::FocalUnitsMm => TagValue::Str(SmolStr::from(std::format!("{val}/mm"))),
    // `CsPrintConv::CanonApex` is handled in the ValueConv-aware block above
    // (it has a ValueConv that applies in BOTH `-j` and `-n`), so it cannot
    // reach this PrintConv-only match — fall through to the catch-all.
    CsPrintConv::FocusContinuous => label_or_default(match val {
      0 => Some("Single"),
      1 => Some("Continuous"),
      8 => Some("Manual"),
      _ => None,
    }),
    CsPrintConv::AeSetting => label_or_default(match val {
      0 => Some("Normal AE"),
      1 => Some("Exposure Compensation"),
      2 => Some("AE Lock"),
      3 => Some("AE Lock + Exposure Comp."),
      4 => Some("No AE"),
      _ => None,
    }),
    CsPrintConv::ImageStabilization => label_or_default(match val {
      0 => Some("Off"),
      1 => Some("On"),
      2 => Some("Shoot Only"),
      3 => Some("Panning"),
      4 => Some("Dynamic"),
      256 => Some("Off (2)"),
      257 => Some("On (2)"),
      258 => Some("Shoot Only (2)"),
      259 => Some("Panning (2)"),
      260 => Some("Dynamic (2)"),
      _ => None,
    }),
    CsPrintConv::FlashModel => {
      // `%flashModel` (`Canon.pm:1029-1049`). The 0x7f mask + the
      // `$val == 127 ? undef` RawConv are applied before this arm (see
      // `should_skip` + the mask in the parse loop).
      label_or_default(match val {
        0 => Some("n/a"),
        4 => Some("Speedlite 540EZ"),
        5 => Some("Speedlite 380EX"),
        6 => Some("Speedlite 550EX"),
        8 => Some("Speedlite ST-E2"),
        9 => Some("Speedlite MR-14EX"),
        12 => Some("Speedlite 580EX"),
        13 => Some("Speedlite 430EX"),
        17 => Some("Speedlite 580EX II"),
        18 => Some("Speedlite 430EX II"),
        22 => Some("Speedlite 600EX-RT"),
        23 => Some("Speedlite 600EX II-RT"),
        24 => Some("Speedlite 90EX"),
        25 => Some("Speedlite 430EX III-RT"),
        31 => Some("Speedlite EL-1 ver2"),
        33 => Some("Speedlite EL-5"),
        34 => Some("Speedlite EL-10"),
        _ => None,
      })
    }
    CsPrintConv::FlashBits => {
      // `Canon.pm:2561-2578`: scalar `0 => '(none)'` + `BITMASK`. ExifTool
      // `DecodeBits` (`ExifTool.pm:6387-6406`) renders each set bit as its
      // label (an unknown bit `n` → `[n]`), joined `", "`. Reached only in
      // `-j`; the `!print_conv` guard above already returned the raw int for
      // `-n` (FlashBits has no `ValueConv`).
      if val == 0 {
        return TagValue::Str("(none)".into());
      }
      let bit_label = |bit: u32| -> Option<&'static str> {
        match bit {
          0 => Some("Manual"),
          1 => Some("TTL"),
          2 => Some("A-TTL"),
          3 => Some("E-TTL"),
          4 => Some("FP sync enabled"),
          7 => Some("2nd-curtain sync used"),
          11 => Some("FP sync used"),
          13 => Some("Built-in"),
          14 => Some("External"),
          _ => None,
        }
      };
      let mut out = std::string::String::new();
      for bit in 0..16u32 {
        if ((val >> bit) & 1) != 0 {
          if !out.is_empty() {
            out.push_str(", ");
          }
          match bit_label(bit) {
            Some(l) => out.push_str(l),
            None => out.push_str(&std::format!("[{bit}]")),
          }
        }
      }
      TagValue::Str(SmolStr::from(out))
    }
    // CameraIso + DisplayAperture + CanonApex have a ValueConv and are
    // handled in the pre-`print_conv` match at the top of this fn (they
    // return early in BOTH modes).
    CsPrintConv::CameraIso | CsPrintConv::DisplayAperture | CsPrintConv::CanonApex => {
      unreachable!()
    }
    CsPrintConv::FocusBracketing => label_or_default(match val {
      0 => Some("Disable"),
      1 => Some("Enable"),
      _ => None,
    }),
    CsPrintConv::Clarity => {
      // `Canon.pm:2682-2684` — `{ OTHER => sub { shift }, 0x7fff =>
      // 'n/a' }`. PrintConv mode: 0x7fff (read as int16s ⇒ 32767) ⇒
      // "n/a"; every OTHER value passes through unchanged (raw int).
      // (`-n` mode is handled by the early return above — no ValueConv,
      // so the raw int incl. 32767 is emitted.)
      if val == 0x7fff {
        TagValue::Str("n/a".into())
      } else {
        TagValue::I64(val)
      }
    }
    CsPrintConv::HdrPq => label_or_default(match val {
      -1 => Some("n/a"),
      0 => Some("Off"),
      1 => Some("On"),
      _ => None,
    }),
    CsPrintConv::SpotMetering => label_or_default(match val {
      0 => Some("Center"),
      1 => Some("AF Point"),
      _ => None,
    }),
    CsPrintConv::PhotoEffect => label_or_default(match val {
      0 => Some("Off"),
      1 => Some("Vivid"),
      2 => Some("Neutral"),
      3 => Some("Smooth"),
      4 => Some("Sepia"),
      5 => Some("B&W"),
      6 => Some("Custom"),
      100 => Some("My Color Data"),
      _ => None,
    }),
    CsPrintConv::ManualFlashOutput => label_or_default(match val {
      0 => Some("n/a"),
      0x500 => Some("Full"),
      0x502 => Some("Medium"),
      0x504 => Some("Low"),
      0x7fff => Some("n/a"),
      _ => None,
    }),
    CsPrintConv::SrawQuality => label_or_default(match val {
      0 => Some("n/a"),
      1 => Some("sRAW1 (mRAW)"),
      2 => Some("sRAW2 (sRAW)"),
      _ => None,
    }),
  }
}

/// `Image::ExifTool::Canon::CameraISO` (`Canon.pm:10466-10493`), forward
/// direction (`$inv` false). Used as the `ValueConv` for CameraSettings
/// position 16 (`Canon.pm:2440`); there is no PrintConv, so the result is
/// emitted identically in `-j` and `-n`.
///
/// ```text
/// my %isoLookup = (0=>'n/a',14=>'Auto High',15=>'Auto',
///                  16=>50,17=>100,18=>200,19=>400,20=>800);
/// elsif ($val != 0x7fff) {
///     if ($val & 0x4000) { $rtnVal = $val & 0x3fff; }
///     else { $rtnVal = $isoLookup{$val} || "Unknown ($val)"; }
/// }
/// ```
///
/// `0x7fff` returns undef in bundled — but the table's
/// `RawConv => '$val == 0x7fff ? undef : $val'` (`Canon.pm:2439`) already
/// drops the tag (see `should_skip`), so this fn never sees `0x7fff` in
/// practice; we still guard it to mirror the sub exactly (returning the
/// raw word, which the caller would otherwise never reach).
fn camera_iso(val: i64) -> TagValue {
  // The encoded word is read as int16s; mask to 16 bits for the bit
  // tests (mirrors Perl's unsigned bitwise ops on the stored value).
  let v = (val as u16) as i64;
  if v == 0x7fff {
    return TagValue::I64(val);
  }
  if v & 0x4000 != 0 {
    // Direct numeric ISO form.
    return TagValue::I64(v & 0x3fff);
  }
  match v {
    0 => TagValue::Str("n/a".into()),
    14 => TagValue::Str("Auto High".into()),
    15 => TagValue::Str("Auto".into()),
    16 => TagValue::I64(50),
    17 => TagValue::I64(100),
    18 => TagValue::I64(200),
    19 => TagValue::I64(400),
    20 => TagValue::I64(800),
    other => TagValue::Str(SmolStr::from(std::format!("Unknown ({other})"))),
  }
}

/// `Canon::CanonEv` — APEX-encoded aperture: a piecewise `val/32` style
/// mapping. For typical positive values from CameraSettings tag 26/27,
/// the value comes in as an APEX-style integer; `exp(CanonEv*ln(2)/2)`
/// converts to an f-number.
fn canon_ev_to_aperture(val: i64) -> f64 {
  // Canon.pm:9943-9962 `sub CanonEv`: the value comes already in
  // APEX-32 encoding (val/32 = APEX), so apex = val/32. Then
  // `f = 2 ** (apex / 2)`. For val=0, apex=0 ⇒ f=1.0.
  // For Canon.jpg's MaxAperture=4 (which we see as the LE int16s 4),
  // bundled emits "4" — which means the encoding here is ALREADY in
  // the f-number scale, NOT APEX-32. The Canon CanonEv subroutine
  // does THE-OTHER-WAY conversion (APEX -> integer EV), but the read
  // path uses `exp(CanonEv*log(2)/2)`. Let me check oracle.
  //
  // Oracle on Canon.jpg: MaxAperture = 4, MinAperture = 27. These are
  // raw int16s WITHOUT APEX encoding. Direct ValueConv applied:
  //   exp(CanonEv(4)*log(2)/2)
  // CanonEv(4): 4 < 32 ⇒ frac=4, so APEX = (4/32) = 0.125 -- no, look
  // at the actual sub:
  //   if ($val < 8) { return $val; }
  //   elsif ($val < 16) { return ($val+3*8)/8; }
  //   ... etc.
  // For $val=4: returns 4 (which is APEX value 4). So
  //   exp(4*log(2)/2) = 2^2 = 4.0. ✓
  // For $val=27: 27 is in [16,24) branch? Let me read more carefully.
  //
  // Actually Canon.pm `sub CanonEv` ($val):
  //   my $sign;
  //   if ($val < 0) { ... return -CanonEv(-$val) }
  //   my $frac = $val & 0x1f;
  //   $val -= $frac;      # now integer multiple of 32
  //   ...
  //   return $val / 32 + (something with frac)
  //
  // So the encoded value IS apex*32 + frac. For $val=4, $frac=4, then
  // $val -= 4 = 0. Returns 0/32 + frac-stuff = small fraction near 0.
  // exp(0.something * log(2)/2) ~ 1, not 4.
  //
  // I'm misreading the Perl. Let me just implement the literal mapping.
  canon_ev(val).exp_f_number()
}

/// Apex-to-aperture wrapper.
trait ApexFNumber {
  fn exp_f_number(self) -> f64;
}

impl ApexFNumber for f64 {
  fn exp_f_number(self) -> f64 {
    // bundled: `exp(CanonEv($val)*log(2)/2)` = `2 ** (CanonEv($val)/2)`.
    (self / 2.0).exp2()
  }
}

/// Canon.pm:9943-9962 `sub CanonEv`. Converts the int16s encoded value
/// to an APEX float. Shared with [`super::shot_info`] (AEBBracketValue
/// uses `CanonEv($val)` then `PrintFraction`).
pub(super) fn canon_ev(val: i64) -> f64 {
  if val < 0 {
    return -canon_ev(-val);
  }
  // The Perl encoding: low 5 bits are the fractional part (out of 32),
  // upper bits are the integer APEX value.
  //
  // ```
  // my $frac = $val & 0x1f;
  // $val -= $frac;        # now integer-multiple of 0x20
  // if ($frac == 0xc) { $val += 32/3 }
  // elsif ($frac == 0x14) { $val += 64/3 }
  // else { $val += $frac * 32/24 }   # wait, that's not right either
  // ```
  //
  // Actual code (Canon.pm:9943-9962):
  // sub CanonEv($) {
  //   my $val = shift;
  //   my $sign;
  //   if ($val < 0) { $val = -$val; $sign = -1; } else { $sign = 1; }
  //   my $frac = $val & 0x1f;
  //   $val -= $frac;
  //   if ($frac == 0x0c) { $frac = 32 / 3; }
  //   elsif ($frac == 0x14) { $frac = 64 / 3; }
  //   return $sign * ($val + $frac) / 32;
  // }
  //
  // So for $val=4: $frac=4, $val=0. Neither 0x0c nor 0x14, so $frac=4.
  // Return = (0 + 4) / 32 = 0.125. Then exp(0.125 * log(2)/2) =
  // 2^(0.0625) ≈ 1.044. That's not 4.0.
  //
  // I think bundled's CanonEv encodes a STOP not a literal f-number.
  // The raw int16s in CameraSettings for MaxAperture comes encoded as
  // APEX*32. For MaxAperture=4 (oracle), the encoded value would be 64
  // (which is APEX-2), and exp(2 * log(2)/2) = 2^1 = 2.0. Still not 4.
  //
  // Wait — APEX aperture: f = 2^(APEX/2). For f=4, APEX=4. So encoded =
  // 4*32 = 128. CanonEv(128) = (128 + 0) / 32 = 4. exp(4*log(2)/2) =
  // 2^2 = 4. ✓
  //
  // So in Canon.jpg the raw int16s value at position 26 is 128, NOT 4!
  // The user-visible oracle of "MaxAperture = 4" comes after the
  // CanonEv ValueConv applied.
  //
  // OK — implementing the literal Perl:
  let frac = val & 0x1f;
  let intp = val - frac;
  let frac_f = match frac {
    0x0c => 32.0 / 3.0,
    0x14 => 64.0 / 3.0,
    other => other as f64,
  };
  (intp as f64 + frac_f) / 32.0
}

/// Perl `sprintf("%.2g", val)` formatting (~2 significant figures).
fn format_g_two(v: f64) -> String {
  if !v.is_finite() {
    return std::format!("{v}");
  }
  // Perl %.2g: 2 significant figures.
  let s = std::format!("{:.*e}", 1, v); // 2 sig figs = 1 decimal in scientific.
  // Convert scientific to plain when small absolute exponent.
  let abs = v.abs();
  if abs == 0.0 {
    return "0".to_string();
  }
  if (0.0001..1e5).contains(&abs) {
    // Print plain. Two sig figs.
    let exp = abs.log10().floor() as i32;
    let decimals = (1 - exp).max(0) as usize;
    let formatted = std::format!("{:.*}", decimals, v);
    // Strip trailing zeros and trailing '.'
    let trimmed = formatted.trim_end_matches('0').trim_end_matches('.');
    if trimmed.is_empty() || trimmed == "-" {
      return "0".to_string();
    }
    return trimmed.to_string();
  }
  s
}

/// Pre-read the `FocalUnits` DataMember (position 25, `Canon.pm:2530-
/// 2537`) from the blob so it is available when Max/MinFocalLength
/// (positions 23/24) apply `$val / ($$self{FocalUnits} || 1)`. ExifTool
/// resolves `DATAMEMBER => [ 22, 25 ]` (`Canon.pm:2219`) before the main
/// walk; this mirrors that for the in-order walk. Returns the raw int16s
/// word (the `|| 1` falsy handling lives in the `FocalLengthMm` conv via
/// `.max(1)`), or `None` if the blob doesn't reach position 25.
fn read_focal_units_word(data: &[u8], order: crate::exif::ifd::ByteOrder) -> Option<i16> {
  let byte_off = 2 * 25;
  // `data.get(byte_off..byte_off+2)?` folds the `byte_off + 2 > data.len()`
  // guard into the read and its `try_into()` to `[u8; 2]` always succeeds — the
  // checked, byte-identical form of `[data[byte_off], data[byte_off+1]]`.
  let arr: [u8; 2] = data.get(byte_off..byte_off + 2)?.try_into().ok()?;
  Some(match order {
    crate::exif::ifd::ByteOrder::Little => i16::from_le_bytes(arr),
    crate::exif::ifd::ByteOrder::Big => i16::from_be_bytes(arr),
  })
}

/// Per-tag `RawConv` guards: which raw int values mean "skip the tag"
/// (the bundled `RawConv => '$val == X ? undef : $val'` lines).
fn should_skip(t: &CameraSettingsTag, raw_int: i16) -> bool {
  // Guards harvested from Canon.pm:
  match t.position {
    // Contrast(13)/Saturation(14)/Sharpness(15)/CameraISO(16)/ColorTone(42):
    // `RawConv => '$val == 0x7fff ? undef : $val'` (`Canon.pm:2419/2424/
    // 2429/2439/2661`). NOTE: Clarity (51) is NOT here — it has NO RawConv
    // (`Canon.pm:2680-2685`), so 0x7fff is kept and mapped to "n/a" by its
    // PrintConv.
    13 | 14 | 15 | 16 | 42 => raw_int == 0x7fff,
    // RecordMode/FocusContinuous/AESetting/ImageStabilization/PhotoEffect
    // /SpotMeteringMode/SRAWQuality: -1 → undef
    9 | 32 | 33 | 34 | 39 | 40 | 46 => raw_int == -1,
    // AFPoint: 0 → undef
    19 => raw_int == 0,
    // LensType: `RawConv => '$val ? $$self{LensType} = $val : undef'`
    // (`Canon.pm:2503`) — value 0 (no lens info) is dropped AND the LensType
    // data member is left unset. `should_skip` runs BEFORE the lens_id capture
    // below, so a 0 LensType emits nothing and is NOT captured — faithful.
    22 => raw_int == 0,
    // MaxAperture/MinAperture: !($val > 0) → undef (we still process 0 to
    // emit "1" for the CameraSettings absolute zero case — bundled emits
    // nothing in that case so we DO skip).
    26 | 27 => raw_int <= 0,
    // FlashModel: 127 → undef (Canon.pm:2557).
    28 => raw_int == 127,
    // DisplayAperture: 0 → undef (Canon.pm:2617).
    35 => raw_int == 0,
    _ => false,
  }
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2d); the test fixtures index fixed-layout buffers freely
// (an out-of-range index is a test-assertion failure, not a shipped panic), so
// the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;
  use crate::exif::ifd::ByteOrder;

  /// Build a synthetic CameraSettings blob with a single value at the
  /// given position.
  fn one_position(pos: usize, val: i16, order: ByteOrder) -> Vec<u8> {
    // 2-byte length word + (pos+1)*2 bytes of data positions.
    // Position 0 holds the blob length per `binaryDataAttrs`; we write 0.
    let total = (pos + 1) * 2 + 2;
    let mut data = std::vec![0u8; total];
    let val_bytes = match order {
      ByteOrder::Little => val.to_le_bytes(),
      ByteOrder::Big => val.to_be_bytes(),
    };
    data[2 * pos..2 * pos + 2].copy_from_slice(&val_bytes);
    data
  }

  /// LensType `RawConv => '$val ? $$self{LensType} = $val : undef'`
  /// (`Canon.pm:2503`): a 0 LensType word is dropped (no tag emitted) AND is
  /// NOT captured as a lens id (the data member is left unset).
  #[test]
  fn lens_type_zero_dropped_and_not_captured() {
    let data = one_position(22, 0, ByteOrder::Little);
    let mut lens_id = None;
    let out = parse_with_lens_id_capture(&data, ByteOrder::Little, true, &mut lens_id);
    assert!(
      !out.iter().any(|(n, _)| n == "LensType"),
      "LensType 0 must be dropped (Canon.pm:2503 RawConv), got {:?}",
      out
    );
    assert_eq!(
      lens_id, None,
      "LensType 0 must NOT be captured as a lens id"
    );
  }

  /// A nonzero LensType IS emitted and captured as the lens id.
  #[test]
  fn lens_type_nonzero_emitted_and_captured() {
    let data = one_position(22, 125, ByteOrder::Little);
    let mut lens_id = None;
    let out = parse_with_lens_id_capture(&data, ByteOrder::Little, true, &mut lens_id);
    assert!(out.iter().any(|(n, _)| n == "LensType"));
    assert_eq!(lens_id, Some(125));
  }

  /// FlashBits (`Canon.pm:2561-2578`): scalar `0 => '(none)'` + BITMASK
  /// (set bits → labels joined ", "; unknown bit n → "[n]"); `-n` = raw int.
  #[test]
  fn flash_bits_bitmask_render() {
    let fb = |val: i16, print_conv: bool| -> TagValue {
      let data = one_position(29, val, ByteOrder::Little);
      let out = parse_with_lens_id_capture(&data, ByteOrder::Little, print_conv, &mut None);
      out
        .into_iter()
        .find(|(n, _)| n == "FlashBits")
        .map(|(_, v)| v)
        .expect("FlashBits emitted")
    };
    assert_eq!(fb(0, true), TagValue::Str("(none)".into()));
    assert_eq!(fb(0, false), TagValue::I64(0)); // -n: raw int
    // bits 0 (Manual) + 3 (E-TTL) = 0x09
    assert_eq!(fb(0x09, true), TagValue::Str("Manual, E-TTL".into()));
    // bit 14 (External) = 0x4000
    assert_eq!(fb(0x4000, true), TagValue::Str("External".into()));
    // bit 5 is not in the BITMASK → "[5]"
    assert_eq!(fb(0x20, true), TagValue::Str("[5]".into()));
  }

  #[test]
  fn parse_lens_type_emits_lens_name() {
    let data = one_position(22, 1, ByteOrder::Little);
    let mut lens_id = None;
    let emissions = parse_with_lens_id_capture(&data, ByteOrder::Little, true, &mut lens_id);
    assert_eq!(lens_id, Some(1));
    assert!(
      emissions
        .iter()
        .any(|(name, _)| name.as_str() == "LensType")
    );
    let v = emissions
      .iter()
      .find(|(n, _)| n == "LensType")
      .map(|(_, v)| v.clone())
      .unwrap();
    assert_eq!(v, TagValue::Str("Canon EF 50mm f/1.8".into()));
  }

  #[test]
  fn parse_focal_length_uses_focal_units() {
    // MaxFocalLength=55, MinFocalLength=18, FocalUnits=1
    let mut data = std::vec![0u8; 60];
    let order = ByteOrder::Little;
    data[2 * 23..2 * 23 + 2].copy_from_slice(&(55u16).to_le_bytes());
    data[2 * 24..2 * 24 + 2].copy_from_slice(&(18u16).to_le_bytes());
    data[2 * 25..2 * 25 + 2].copy_from_slice(&(1i16).to_le_bytes());
    let emissions = parse(&data, order, true);
    let max = emissions
      .iter()
      .find(|(n, _)| n == "MaxFocalLength")
      .map(|(_, v)| v.clone())
      .unwrap();
    let min = emissions
      .iter()
      .find(|(n, _)| n == "MinFocalLength")
      .map(|(_, v)| v.clone())
      .unwrap();
    assert_eq!(max, TagValue::Str("55 mm".into()));
    assert_eq!(min, TagValue::Str("18 mm".into()));
  }

  /// DataMember ordering (`Canon.pm:2219` `DATAMEMBER => [ 22, 25 ]`):
  /// FocalUnits (position 25) is a LATER position than Max/MinFocalLength
  /// (23/24), but must still scale them. Raw Max=550, Min=180,
  /// FocalUnits=10 ⇒ 55 mm / 18 mm.
  #[test]
  fn focal_length_divided_by_later_focal_units() {
    let mut data = std::vec![0u8; 60];
    let order = ByteOrder::Little;
    data[2 * 23..2 * 23 + 2].copy_from_slice(&(550u16).to_le_bytes());
    data[2 * 24..2 * 24 + 2].copy_from_slice(&(180u16).to_le_bytes());
    data[2 * 25..2 * 25 + 2].copy_from_slice(&(10i16).to_le_bytes());
    let emissions = parse(&data, order, true);
    let max = emissions
      .iter()
      .find(|(n, _)| n == "MaxFocalLength")
      .map(|(_, v)| v.clone())
      .unwrap();
    let min = emissions
      .iter()
      .find(|(n, _)| n == "MinFocalLength")
      .map(|(_, v)| v.clone())
      .unwrap();
    assert_eq!(max, TagValue::Str("55 mm".into()));
    assert_eq!(min, TagValue::Str("18 mm".into()));
    // FocalUnits itself emits "10/mm".
    assert!(
      emissions
        .iter()
        .any(|(n, v)| n == "FocalUnits" && *v == TagValue::Str("10/mm".into()))
    );
  }

  #[test]
  fn macro_mode_normal_label() {
    let data = one_position(1, 2, ByteOrder::Little);
    let v = parse(&data, ByteOrder::Little, true);
    assert!(
      v.iter()
        .any(|(name, val)| name == "MacroMode" && *val == TagValue::Str("Normal".into()))
    );
  }

  #[test]
  fn focus_mode_manual_focus_label() {
    let data = one_position(7, 3, ByteOrder::Little);
    let v = parse(&data, ByteOrder::Little, true);
    assert!(
      v.iter()
        .any(|(name, val)| name == "FocusMode" && *val == TagValue::Str("Manual Focus (3)".into()))
    );
  }

  #[test]
  fn raw_conv_skips_0x7fff_for_contrast() {
    // Contrast at position 13 with 0x7fff → undef.
    let data = one_position(13, 0x7fff_u16 as i16, ByteOrder::Little);
    let v = parse(&data, ByteOrder::Little, true);
    assert!(!v.iter().any(|(name, _)| name == "Contrast"));
  }

  #[test]
  fn print_conv_off_emits_raw() {
    let data = one_position(22, 1, ByteOrder::Little);
    let v = parse(&data, ByteOrder::Little, false);
    assert!(
      v.iter()
        .any(|(name, val)| name == "LensType" && *val == TagValue::I64(1))
    );
  }

  #[test]
  fn max_aperture_apex_to_fnumber() {
    // Canon.jpg: MaxAperture int16s = 128 ⇒ APEX 4 ⇒ f/4.0
    let data = one_position(26, 128, ByteOrder::Little);
    let v = parse(&data, ByteOrder::Little, true);
    let max_ap = v
      .iter()
      .find(|(n, _)| n == "MaxAperture")
      .map(|(_, val)| val.clone())
      .unwrap();
    // Either "4" or "4.0" depending on format_g_two rounding.
    match max_ap {
      TagValue::Str(s) => {
        assert!(
          s.starts_with("4") && (s == "4" || s == "4.0"),
          "MaxAperture = {s:?} (expected ~4)"
        );
      }
      other => panic!("expected Str, got {other:?}"),
    }
  }

  /// `Canon::CameraISO` (`Canon.pm:10466-10493`) lookup-table forms.
  #[test]
  fn camera_iso_lookup_forms() {
    assert_eq!(camera_iso(0), TagValue::Str("n/a".into()));
    assert_eq!(camera_iso(14), TagValue::Str("Auto High".into()));
    assert_eq!(camera_iso(15), TagValue::Str("Auto".into()));
    assert_eq!(camera_iso(16), TagValue::I64(50));
    assert_eq!(camera_iso(17), TagValue::I64(100));
    assert_eq!(camera_iso(18), TagValue::I64(200));
    assert_eq!(camera_iso(19), TagValue::I64(400));
    assert_eq!(camera_iso(20), TagValue::I64(800));
    // Out-of-table small value ⇒ "Unknown (N)".
    assert_eq!(camera_iso(13), TagValue::Str("Unknown (13)".into()));
  }

  /// The `0x4000`-flagged "direct numeric ISO" form: `$val & 0x3fff`.
  #[test]
  fn camera_iso_direct_numeric_form() {
    // 0x4000 | 100 ⇒ ISO 100.
    assert_eq!(camera_iso(0x4000 | 100), TagValue::I64(100));
    // 0x4000 | 1600 ⇒ ISO 1600.
    assert_eq!(camera_iso(0x4000 | 1600), TagValue::I64(1600));
  }

  /// CameraISO emits the SAME value in `-n` (value-conv) mode as `-j` —
  /// bundled has a ValueConv but no PrintConv at position 16.
  #[test]
  fn camera_iso_value_conv_matches_print_conv() {
    let data = one_position(16, 17, ByteOrder::Little); // 17 ⇒ ISO 100
    let pc = parse(&data, ByteOrder::Little, true);
    let vc = parse(&data, ByteOrder::Little, false);
    let find = |v: &[(SmolStr, TagValue)]| {
      v.iter()
        .find(|(n, _)| n == "CameraISO")
        .map(|(_, x)| x.clone())
    };
    assert_eq!(find(&pc), Some(TagValue::I64(100)));
    assert_eq!(find(&vc), Some(TagValue::I64(100)));
  }

  /// The `0x7fff` RawConv guard (`Canon.pm:2439`) drops CameraISO entirely.
  #[test]
  fn camera_iso_raw_conv_skips_0x7fff() {
    let data = one_position(16, 0x7fff_u16 as i16, ByteOrder::Little);
    let v = parse(&data, ByteOrder::Little, true);
    assert!(!v.iter().any(|(n, _)| n == "CameraISO"));
  }

  /// `printParameter` maps 0 ⇒ "Normal" (`Exif.pm:329`); positives get a
  /// leading '+'; negatives pass through. Applies to Contrast(13),
  /// Saturation(14), ColorTone(42) — NOT Sharpness.
  #[test]
  fn print_parameter_zero_is_normal() {
    let data = one_position(13, 0, ByteOrder::Little); // Contrast = 0
    let v = parse(&data, ByteOrder::Little, true);
    assert!(
      v.iter()
        .any(|(n, val)| n == "Contrast" && *val == TagValue::Str("Normal".into()))
    );
    let data_pos = one_position(14, 2, ByteOrder::Little); // Saturation = +2
    let vp = parse(&data_pos, ByteOrder::Little, true);
    assert!(
      vp.iter()
        .any(|(n, val)| n == "Saturation" && *val == TagValue::Str("+2".into()))
    );
    // ColorTone(42) uses printParameter too: 0 ⇒ "Normal".
    let data_ct = one_position(42, 0, ByteOrder::Little);
    let vct = parse(&data_ct, ByteOrder::Little, true);
    assert!(
      vct
        .iter()
        .any(|(n, val)| n == "ColorTone" && *val == TagValue::Str("Normal".into()))
    );
  }

  /// `Sharpness` (`Canon.pm:2434`) — own conv `'$val > 0 ? "+$val" :
  /// $val'`, NO `%printParameter`: 0 ⇒ "0" (NOT "Normal"), 3 ⇒ "+3",
  /// -2 ⇒ "-2".
  #[test]
  fn sharpness_has_own_conv_not_print_parameter() {
    let d0 = one_position(15, 0, ByteOrder::Little);
    let v0 = parse(&d0, ByteOrder::Little, true);
    assert!(
      v0.iter()
        .any(|(n, val)| n == "Sharpness" && *val == TagValue::Str("0".into())),
      "Sharpness 0 must be \"0\", never \"Normal\""
    );
    let d3 = one_position(15, 3, ByteOrder::Little);
    let v3 = parse(&d3, ByteOrder::Little, true);
    assert!(
      v3.iter()
        .any(|(n, val)| n == "Sharpness" && *val == TagValue::Str("+3".into()))
    );
    let dn = one_position(15, -2, ByteOrder::Little);
    let vn = parse(&dn, ByteOrder::Little, true);
    assert!(
      vn.iter()
        .any(|(n, val)| n == "Sharpness" && *val == TagValue::Str("-2".into()))
    );
    // 0x7fff RawConv (`Canon.pm:2429`) still drops Sharpness.
    let ds = one_position(15, 0x7fff_u16 as i16, ByteOrder::Little);
    let vs = parse(&ds, ByteOrder::Little, true);
    assert!(!vs.iter().any(|(n, _)| n == "Sharpness"));
  }

  /// `%canonQuality` text fix: 130 ⇒ "Light (RAW)", 131 ⇒ "Standard (RAW)".
  #[test]
  fn quality_raw_variant_labels() {
    let d130 = one_position(3, 130, ByteOrder::Little);
    let v130 = parse(&d130, ByteOrder::Little, true);
    assert!(
      v130
        .iter()
        .any(|(n, val)| n == "Quality" && *val == TagValue::Str("Light (RAW)".into()))
    );
    let d131 = one_position(3, 131, ByteOrder::Little);
    let v131 = parse(&d131, ByteOrder::Little, true);
    assert!(
      v131
        .iter()
        .any(|(n, val)| n == "Quality" && *val == TagValue::Str("Standard (RAW)".into()))
    );
  }

  /// `%canonImageSize` new keys: 137/142/143 movies + -1 ⇒ "n/a".
  #[test]
  fn canon_image_size_movie_keys() {
    for (raw, want) in [
      (137i16, "1280x720 Movie"),
      (142, "1920x1080 Movie"),
      (143, "4096x2160 Movie"),
      (-1, "n/a"),
    ] {
      let d = one_position(10, raw, ByteOrder::Little);
      let v = parse(&d, ByteOrder::Little, true);
      assert!(
        v.iter()
          .any(|(n, val)| n == "CanonImageSize" && *val == TagValue::Str(want.into())),
        "CanonImageSize {raw} should be {want:?}"
      );
    }
  }

  /// FlashModel: `Mask => 0x7f` applied, then `%flashModel` lookup. A raw
  /// word with bit 7 set still maps via its low 7 bits.
  #[test]
  fn flash_model_mask_and_lookup() {
    // 0x8000 | 12 ⇒ mask 0x7f ⇒ 12 ⇒ "Speedlite 580EX".
    let d = one_position(28, 0x8000_u16 as i16 | 12, ByteOrder::Little);
    let v = parse(&d, ByteOrder::Little, true);
    assert!(
      v.iter()
        .any(|(n, val)| n == "FlashModel" && *val == TagValue::Str("Speedlite 580EX".into()))
    );
  }

  /// FlashModel: masked value 127 ⇒ undef (`Canon.pm:2558`) ⇒ skipped.
  #[test]
  fn flash_model_127_skipped() {
    // 0x80 | 0x7f ⇒ mask ⇒ 127 ⇒ undef.
    let d = one_position(28, 0xff_i16, ByteOrder::Little);
    let v = parse(&d, ByteOrder::Little, true);
    assert!(!v.iter().any(|(n, _)| n == "FlashModel"));
  }

  /// DisplayAperture: `ValueConv => '$val / 10'`, no PrintConv (so both
  /// modes agree on the float), and 0 ⇒ undef (skipped).
  #[test]
  fn display_aperture_value_conv() {
    let d = one_position(35, 35, ByteOrder::Little); // 35/10 = 3.5
    let pc = parse(&d, ByteOrder::Little, true);
    let vc = parse(&d, ByteOrder::Little, false);
    assert!(
      pc.iter()
        .any(|(n, val)| n == "DisplayAperture" && *val == TagValue::F64(3.5))
    );
    assert!(
      vc.iter()
        .any(|(n, val)| n == "DisplayAperture" && *val == TagValue::F64(3.5))
    );
    // 0 ⇒ undef.
    let d0 = one_position(35, 0, ByteOrder::Little);
    let v0 = parse(&d0, ByteOrder::Little, true);
    assert!(!v0.iter().any(|(n, _)| n == "DisplayAperture"));
  }

  /// Positions 50/51/52: FocusBracketing / Clarity / HDR-PQ.
  #[test]
  fn focus_bracketing_clarity_hdrpq() {
    let d50 = one_position(50, 1, ByteOrder::Little);
    let v50 = parse(&d50, ByteOrder::Little, true);
    assert!(
      v50
        .iter()
        .any(|(n, val)| n == "FocusBracketing" && *val == TagValue::Str("Enable".into()))
    );
    // Clarity: raw int passthrough (OTHER => sub { shift }).
    let d51 = one_position(51, 7, ByteOrder::Little);
    let v51 = parse(&d51, ByteOrder::Little, true);
    assert!(
      v51
        .iter()
        .any(|(n, val)| n == "Clarity" && *val == TagValue::I64(7))
    );
    // Clarity 0x7fff ⇒ "n/a" in PrintConv mode — NOT dropped (Clarity has
    // NO RawConv, `Canon.pm:2680-2685`).
    let d51n = one_position(51, 0x7fff_u16 as i16, ByteOrder::Little);
    let v51n = parse(&d51n, ByteOrder::Little, true);
    assert!(
      v51n
        .iter()
        .any(|(n, val)| n == "Clarity" && *val == TagValue::Str("n/a".into())),
      "Clarity 0x7fff must map to \"n/a\", not be skipped"
    );
    // In `-n` (value-conv) mode there is no ValueConv, so the raw int
    // 32767 is emitted.
    let v51v = parse(&d51n, ByteOrder::Little, false);
    assert!(
      v51v
        .iter()
        .any(|(n, val)| n == "Clarity" && *val == TagValue::I64(32767))
    );
    // HDR-PQ: -1 ⇒ "n/a", 1 ⇒ "On".
    let d52 = one_position(52, -1, ByteOrder::Little);
    let v52 = parse(&d52, ByteOrder::Little, true);
    assert!(
      v52
        .iter()
        .any(|(n, val)| n == "HDR-PQ" && *val == TagValue::Str("n/a".into()))
    );
  }
}
