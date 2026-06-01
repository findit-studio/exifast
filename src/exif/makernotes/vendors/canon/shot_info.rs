// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `%Image::ExifTool::Canon::ShotInfo` (`Canon.pm:2772-3051`).
//!
//! Binary-data sub-table — `FORMAT => 'int16s'`, `FIRST_ENTRY => 1`,
//! `DATAMEMBER => [ 19 ]`. Words are signed 16-bit by default; positions
//! 19/20 override to `int16u` (`Canon.pm:2939`/`:2950`).
//!
//! ## Scope (camera-indexing-relevant subset, issue #86 part 1)
//!
//! Ported positions (the full bundled table, minus the all-`# comment`
//! reserved positions 11/25 and the `int16u` ContinuousDrive blanks):
//!
//! | Pos | Name | Cite |
//! |-----|------|------|
//! | 1 | AutoISO (`exp(v/32*ln2)*100`, `%.0f`) | `Canon.pm:2779-2786` |
//! | 2 | BaseISO (RawConv drop-0, `*100/32`, `%.0f`) | `Canon.pm:2787-2795` |
//! | 3 | MeasuredEV (`v/32+5`, `%.2f`) | `Canon.pm:2796-2809` |
//! | 4 | TargetAperture (RawConv `>0`, aperture conv, `%.2g`) | `Canon.pm:2810-2817` |
//! | 5 | TargetExposureTime (RawConv, `exp(-CanonEv*ln2)`, `PrintExposureTime`) | `Canon.pm:2818-2827` |
//! | 6 | ExposureCompensation (`CanonEv`→`PrintFraction`) | `Canon.pm:2828-2834` |
//! | 7 | WhiteBalance (`%canonWhiteBalance`) | `Canon.pm:2835-2839` |
//! | 8 | SlowShutter (PrintConv hash) | `Canon.pm:2840-2849` |
//! | 9 | SequenceNumber | `Canon.pm:2850-2854` |
//! | 10 | OpticalZoomCode (`v==8?"n/a":v`) | `Canon.pm:2855-2864` |
//! | 12 | CameraTemperature (EOS-only condition) | `Canon.pm:2866-2877` |
//! | 13 | FlashGuideNumber | `Canon.pm:2878-2883` |
//! | 14 | AFPointsInFocus (PrintHex hash, RawConv drop-0) | `Canon.pm:2885-2902` |
//! | 15 | FlashExposureComp (`CanonEv`→`PrintFraction`) | `Canon.pm:2903-2910` |
//! | 16 | AutoExposureBracketing | `Canon.pm:2911-2920` |
//! | 17 | AEBBracketValue (`CanonEv`→`PrintFraction`) | `Canon.pm:2921-2927` |
//! | 18 | ControlMode | `Canon.pm:2928-2936` |
//! | 19 | FocusDistanceUpper (int16u) | `Canon.pm:2937-2947` |
//! | 20 | FocusDistanceLower (int16u, cond) | `Canon.pm:2948-2956` |
//! | 21 | FNumber (RawConv drop-0, aperture conv, `%.2g`) | `Canon.pm:2957-2966` |
//! | 22 | ExposureTime (model-conditional list, `PrintExposureTime`) | `Canon.pm:2967-2997` |
//! | 23 | MeasuredEV2 | `Canon.pm:2998-3004` |
//! | 24 | BulbDuration | `Canon.pm:3005-3009` |
//! | 26 | CameraType (PrintConv hash) | `Canon.pm:3012-3022` |
//! | 27 | AutoRotate (RawConv `>=0`, PrintConv hash) | `Canon.pm:3023-3033` |
//! | 28 | NDFilter | `Canon.pm:3034-3037` |
//! | 29 | SelfTimer2 (RawConv `>=0`, `v/10`) | `Canon.pm:3038-3043` |
//! | 33 | FlashOutput (PowerShot condition) | `Canon.pm:3044-3051` |
//!
//! `ContinuousShootingSpeed` (named in the umbrella issue) does NOT exist
//! in `%Canon::ShotInfo` in the bundled module — it lives in the
//! per-model `CameraInfoXXX` tables (deferred, #85). No-op here.
//!
//! ## Faithfulness notes
//!
//! - **Position 14 AFPointsInFocus has NO `Condition`** in bundled 13.59
//!   (`Canon.pm:2885-2902`) — it is emitted for ALL models (including EOS),
//!   gated only by `RawConv => '$val==0 ? undef : $val'`. (The EOS body ALSO
//!   gets a same-named tag from `Canon::AFInfo`/`AFInfo2`; ExifTool keeps both
//!   because they live in different sub-tables. This port mirrors that — see
//!   the `af_points_in_focus_*` tests.)
//! - **Position 22 ExposureTime** is a Perl conditional list
//!   (`Canon.pm:2967-2997`): the FIRST branch matches bodies whose
//!   `$$self{Model} =~ /\b(20D|350D|REBEL XT|Kiss Digital N)\b/` and uses
//!   `ValueConv => 'exp(-CanonEv*log2)*1000/32'`; the default branch uses
//!   `'exp(-CanonEv*log2)'` (identical to TargetExposureTime). Both share
//!   `PrintConv => PrintExposureTime` and `RawConv => '($val or
//!   $$self{FILE_TYPE} eq "CRW") ? $val : undef'`. The container
//!   `$$self{FILE_TYPE}` IS threaded through ([`parse`]'s `file_type`), so the
//!   CRW-allows-0 clause is a faithful transcription: a raw-0 ExposureTime is
//!   kept only when `file_type == Some("CRW")` (`"0 is valid in a CRW image
//!   (=1s, D60 sample)"`) and dropped for every non-CRW container
//!   (JPG/CR2/TIFF/MOV). Because the port has no CIFF/CRW parser, every
//!   reachable container is non-CRW today, so the emitted output is unchanged;
//!   only the gate is now spelled faithfully.
//!
//! ## ValueConv that needs `CanonEv` / the aperture conv
//!
//! Positions 4/21 reuse the `exp(CanonEv($val)*log(2)/2)` aperture mapping
//! (`= 2 ** (CanonEv/2)`) shared with [`super::camera_settings`]; positions
//! 5/22 use `exp(-CanonEv($val)*log(2))` (`= 2 ** -CanonEv`); positions
//! 6/15/17 use `CanonEv($val)` then `PrintFraction`. `CanonEv` is the APEX
//! decoder shared with [`super::camera_settings`].

use super::camera_settings::canon_ev;
use crate::exif::ifd::ByteOrder;
use crate::exif::tables::{print_exposure_time, print_fraction};
use crate::value::{TagValue, format_g};
use smol_str::SmolStr;
use std::vec::Vec;

/// Decoded `Canon::ShotInfo` — the camera-indexing-relevant typed
/// surface. D8: no public fields; accessor-only.
///
/// Stored values are the POST-ValueConv numeric values (e.g.
/// `focus_distance_upper_m` is metres, not the raw `int16u`). PrintConv
/// strings (e.g. WhiteBalance label) are stored as [`SmolStr`].
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct CanonShotInfo {
  /// Position 1 — AutoISO; `exp(v/32*ln2)*100` (`Canon.pm:2779-2786`).
  auto_iso: Option<f64>,
  /// Position 2 — BaseISO; `exp(v/32*ln2)*100/32`, RawConv drops 0
  /// (`Canon.pm:2787-2795`).
  base_iso: Option<f64>,
  /// Position 3 — MeasuredEV; `v/32+5` (`Canon.pm:2796-2809`).
  measured_ev: Option<f64>,
  /// Position 4 — TargetAperture (f-number); RawConv drops `<= 0`
  /// (`Canon.pm:2810-2817`).
  target_aperture: Option<f64>,
  /// Position 5 — TargetExposureTime in seconds; RawConv gate
  /// (`Canon.pm:2818-2827`).
  target_exposure_time: Option<f64>,
  /// Position 6 — ExposureCompensation in EV (`CanonEv`)
  /// (`Canon.pm:2828-2834`).
  exposure_compensation: Option<f64>,
  /// Position 7 — `%canonWhiteBalance` label (`Canon.pm:2835-2839`).
  white_balance: Option<SmolStr>,
  /// Position 8 — SlowShutter label (`Canon.pm:2840-2849`).
  slow_shutter: Option<SmolStr>,
  /// Position 9 — shot number in a continuous burst (`Canon.pm:2850`).
  sequence_number: Option<i64>,
  /// Position 10 — OpticalZoomCode raw (`Canon.pm:2855-2864`).
  optical_zoom_code: Option<i64>,
  /// Position 12 — `int16s - 128` degrees C, EOS-only, RawConv drops 0
  /// (`Canon.pm:2865-2876`).
  camera_temperature_c: Option<i64>,
  /// Position 13 — `int16s / 32`; RawConv drops `-1` (`Canon.pm:2877`).
  flash_guide_number: Option<f64>,
  /// Position 14 — AFPointsInFocus label (PrintHex hash); RawConv drops 0
  /// (`Canon.pm:2885-2902`).
  af_points_in_focus: Option<SmolStr>,
  /// Position 15 — FlashExposureComp in EV (`CanonEv`) (`Canon.pm:2903`).
  flash_exposure_comp: Option<f64>,
  /// Position 16 — AutoExposureBracketing label (`Canon.pm:2911`).
  auto_exposure_bracketing: Option<SmolStr>,
  /// Position 18 — ControlMode label (`Canon.pm:2927-2935`).
  control_mode: Option<SmolStr>,
  /// Position 19 — `int16u / 100` metres; `inf` when `> 655.345`
  /// (`Canon.pm:2936-2946`). The DataMember that gates position 20.
  focus_distance_upper_m: Option<f64>,
  /// Position 20 — `int16u / 100` metres; only when position 19 nonzero
  /// (`Canon.pm:2947-2955`).
  focus_distance_lower_m: Option<f64>,
  /// Position 21 — FNumber (f-number); RawConv drops 0 (`Canon.pm:2957`).
  f_number: Option<f64>,
  /// Position 22 — ExposureTime in seconds (model-conditional list); RawConv
  /// gate (`Canon.pm:2967-2997`).
  exposure_time: Option<f64>,
  /// Position 23 — `int16s / 8 - 6`; RawConv drops 0 (`Canon.pm:2997`).
  measured_ev2: Option<f64>,
  /// Position 24 — `int16s / 10` seconds (`Canon.pm:3004-3008`).
  bulb_duration: Option<f64>,
  /// Position 26 — CameraType label (`Canon.pm:3012-3022`).
  camera_type: Option<SmolStr>,
  /// Position 27 — AutoRotate label; RawConv drops `< 0`
  /// (`Canon.pm:3023-3033`).
  auto_rotate: Option<SmolStr>,
  /// Position 28 — NDFilter label (`Canon.pm:3034-3037`).
  nd_filter: Option<SmolStr>,
  /// Position 29 — SelfTimer2 seconds; RawConv drops `< 0`, `v/10`
  /// (`Canon.pm:3038-3043`).
  self_timer2: Option<f64>,
  /// Position 33 — PowerShot flash output 0-500; RawConv keeps only
  /// PowerShot/IXUS/IXY bodies or nonzero (`Canon.pm:3043-3050`).
  flash_output: Option<i64>,
}

impl CanonShotInfo {
  /// Empty placeholder (every field `None`).
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {
      auto_iso: None,
      base_iso: None,
      measured_ev: None,
      target_aperture: None,
      target_exposure_time: None,
      exposure_compensation: None,
      white_balance: None,
      slow_shutter: None,
      sequence_number: None,
      optical_zoom_code: None,
      camera_temperature_c: None,
      flash_guide_number: None,
      af_points_in_focus: None,
      flash_exposure_comp: None,
      auto_exposure_bracketing: None,
      control_mode: None,
      focus_distance_upper_m: None,
      focus_distance_lower_m: None,
      f_number: None,
      exposure_time: None,
      measured_ev2: None,
      bulb_duration: None,
      camera_type: None,
      auto_rotate: None,
      nd_filter: None,
      self_timer2: None,
      flash_output: None,
    }
  }

  /// `true` when no field decoded.
  #[must_use]
  #[inline]
  pub fn is_empty(&self) -> bool {
    *self == Self::new()
  }

  /// AutoISO — `BaseISO * AutoISO / 100` is the actual ISO (position 1).
  #[must_use]
  #[inline(always)]
  pub const fn auto_iso(&self) -> Option<f64> {
    self.auto_iso
  }

  /// BaseISO (position 2).
  #[must_use]
  #[inline(always)]
  pub const fn base_iso(&self) -> Option<f64> {
    self.base_iso
  }

  /// MeasuredEV — Canon's MeasuredLV (position 3).
  #[must_use]
  #[inline(always)]
  pub const fn measured_ev(&self) -> Option<f64> {
    self.measured_ev
  }

  /// TargetAperture as an f-number (position 4).
  #[must_use]
  #[inline(always)]
  pub const fn target_aperture(&self) -> Option<f64> {
    self.target_aperture
  }

  /// TargetExposureTime in seconds (position 5).
  #[must_use]
  #[inline(always)]
  pub const fn target_exposure_time(&self) -> Option<f64> {
    self.target_exposure_time
  }

  /// ExposureCompensation in EV (position 6).
  #[must_use]
  #[inline(always)]
  pub const fn exposure_compensation(&self) -> Option<f64> {
    self.exposure_compensation
  }

  /// WhiteBalance label (position 7).
  #[must_use]
  #[inline]
  pub fn white_balance(&self) -> Option<&str> {
    self.white_balance.as_deref()
  }

  /// SlowShutter label (position 8).
  #[must_use]
  #[inline]
  pub fn slow_shutter(&self) -> Option<&str> {
    self.slow_shutter.as_deref()
  }

  /// OpticalZoomCode raw value (position 10).
  #[must_use]
  #[inline(always)]
  pub const fn optical_zoom_code(&self) -> Option<i64> {
    self.optical_zoom_code
  }

  /// SequenceNumber — shot number in continuous burst (position 9).
  #[must_use]
  #[inline(always)]
  pub const fn sequence_number(&self) -> Option<i64> {
    self.sequence_number
  }

  /// CameraTemperature in degrees C (position 12, EOS-only).
  #[must_use]
  #[inline(always)]
  pub const fn camera_temperature_c(&self) -> Option<i64> {
    self.camera_temperature_c
  }

  /// FlashGuideNumber (position 13).
  #[must_use]
  #[inline(always)]
  pub const fn flash_guide_number(&self) -> Option<f64> {
    self.flash_guide_number
  }

  /// AFPointsInFocus label (position 14, PrintHex hash).
  #[must_use]
  #[inline]
  pub fn af_points_in_focus(&self) -> Option<&str> {
    self.af_points_in_focus.as_deref()
  }

  /// FlashExposureComp in EV (position 15).
  #[must_use]
  #[inline(always)]
  pub const fn flash_exposure_comp(&self) -> Option<f64> {
    self.flash_exposure_comp
  }

  /// AutoExposureBracketing label (position 16).
  #[must_use]
  #[inline]
  pub fn auto_exposure_bracketing(&self) -> Option<&str> {
    self.auto_exposure_bracketing.as_deref()
  }

  /// ControlMode label (position 18).
  #[must_use]
  #[inline]
  pub fn control_mode(&self) -> Option<&str> {
    self.control_mode.as_deref()
  }

  /// FocusDistanceUpper in metres (position 19). `f64::INFINITY` encodes
  /// the bundled `"inf"` (raw `> 655.345`).
  #[must_use]
  #[inline(always)]
  pub const fn focus_distance_upper_m(&self) -> Option<f64> {
    self.focus_distance_upper_m
  }

  /// FocusDistanceLower in metres (position 20).
  #[must_use]
  #[inline(always)]
  pub const fn focus_distance_lower_m(&self) -> Option<f64> {
    self.focus_distance_lower_m
  }

  /// FNumber as an f-number (position 21).
  #[must_use]
  #[inline(always)]
  pub const fn f_number(&self) -> Option<f64> {
    self.f_number
  }

  /// ExposureTime in seconds (position 22, model-conditional list).
  #[must_use]
  #[inline(always)]
  pub const fn exposure_time(&self) -> Option<f64> {
    self.exposure_time
  }

  /// MeasuredEV2 (position 23).
  #[must_use]
  #[inline(always)]
  pub const fn measured_ev2(&self) -> Option<f64> {
    self.measured_ev2
  }

  /// BulbDuration in seconds (position 24).
  #[must_use]
  #[inline(always)]
  pub const fn bulb_duration(&self) -> Option<f64> {
    self.bulb_duration
  }

  /// CameraType label (position 26).
  #[must_use]
  #[inline]
  pub fn camera_type(&self) -> Option<&str> {
    self.camera_type.as_deref()
  }

  /// AutoRotate label (position 27).
  #[must_use]
  #[inline]
  pub fn auto_rotate(&self) -> Option<&str> {
    self.auto_rotate.as_deref()
  }

  /// NDFilter label (position 28).
  #[must_use]
  #[inline]
  pub fn nd_filter(&self) -> Option<&str> {
    self.nd_filter.as_deref()
  }

  /// SelfTimer2 in seconds (position 29).
  #[must_use]
  #[inline(always)]
  pub const fn self_timer2(&self) -> Option<f64> {
    self.self_timer2
  }

  /// FlashOutput (position 33, PowerShot-only).
  #[must_use]
  #[inline(always)]
  pub const fn flash_output(&self) -> Option<i64> {
    self.flash_output
  }
}

/// `%canonWhiteBalance` (`Canon.pm:1082-1113`).
fn white_balance_label(val: i64) -> Option<&'static str> {
  Some(match val {
    0 => "Auto",
    1 => "Daylight",
    2 => "Cloudy",
    3 => "Tungsten",
    4 => "Fluorescent",
    5 => "Flash",
    6 => "Custom",
    7 => "Black & White",
    8 => "Shade",
    9 => "Manual Temperature (Kelvin)",
    10 => "PC Set1",
    11 => "PC Set2",
    12 => "PC Set3",
    14 => "Daylight Fluorescent",
    15 => "Custom 1",
    16 => "Custom 2",
    17 => "Underwater",
    18 => "Custom 3",
    19 => "Custom 4",
    20 => "PC Set4",
    21 => "PC Set5",
    23 => "Auto (ambience priority)",
    _ => return None,
  })
}

/// AutoExposureBracketing PrintConv (`Canon.pm:2912-2918`).
fn aeb_label(val: i64) -> Option<&'static str> {
  Some(match val {
    -1 => "On",
    0 => "Off",
    1 => "On (shot 1)",
    2 => "On (shot 2)",
    3 => "On (shot 3)",
    _ => return None,
  })
}

/// ControlMode PrintConv (`Canon.pm:2929-2934`).
fn control_mode_label(val: i64) -> Option<&'static str> {
  Some(match val {
    0 => "n/a",
    1 => "Camera Local Control",
    3 => "Computer Remote Control",
    _ => return None,
  })
}

/// NDFilter PrintConv (`Canon.pm:3036`).
fn nd_filter_label(val: i64) -> Option<&'static str> {
  Some(match val {
    -1 => "n/a",
    0 => "Off",
    1 => "On",
    _ => return None,
  })
}

/// SlowShutter PrintConv (`Canon.pm:2842-2848`).
fn slow_shutter_label(val: i64) -> Option<&'static str> {
  Some(match val {
    -1 => "n/a",
    0 => "Off",
    1 => "Night Scene",
    2 => "On",
    3 => "None",
    _ => return None,
  })
}

/// AFPointsInFocus PrintConv (`Canon.pm:2892-2901`). `Flags => 'PrintHex'`
/// (`Canon.pm:2889`): the unmatched fallback renders `Unknown (0xNN)` with
/// lowercase hex (`ExifTool.pm:3628-3634`), NOT `Unknown (decimal)`.
fn af_points_in_focus_label(val: i64) -> Option<&'static str> {
  Some(match val {
    0x3000 => "None (MF)",
    0x3001 => "Right",
    0x3002 => "Center",
    0x3003 => "Center+Right",
    0x3004 => "Left",
    0x3005 => "Left+Right",
    0x3006 => "Left+Center",
    0x3007 => "All",
    _ => return None,
  })
}

/// CameraType PrintConv (`Canon.pm:3015-3021`).
fn camera_type_label(val: i64) -> Option<&'static str> {
  Some(match val {
    0 => "n/a",
    248 => "EOS High-end",
    250 => "Compact",
    252 => "EOS Mid-range",
    255 => "DV Camera",
    _ => return None,
  })
}

/// AutoRotate PrintConv (`Canon.pm:3026-3032`). The `-1 => 'n/a'` entry is
/// unreachable because `RawConv => '$val >= 0 ? $val : undef'`
/// (`Canon.pm:3025`) drops negatives before PrintConv; kept for fidelity.
fn auto_rotate_label(val: i64) -> Option<&'static str> {
  Some(match val {
    -1 => "n/a",
    0 => "None",
    1 => "Rotate 90 CW",
    2 => "Rotate 180",
    3 => "Rotate 270 CW",
    _ => return None,
  })
}

/// `exp(CanonEv($val)*log(2)/2)` — the APEX→f-number aperture conv shared
/// by TargetAperture (pos 4) and FNumber (pos 21), and identical to
/// CameraSettings Max/MinAperture (`Canon.pm:2813`/`:2962`). Equivalent to
/// `2 ** (CanonEv($val)/2)`.
fn aperture_from_apex(raw: i64) -> f64 {
  (canon_ev(raw) / 2.0).exp2()
}

/// `exp(-CanonEv($val)*log(2))` — the APEX→seconds exposure-time conv used
/// by TargetExposureTime (pos 5) and the DEFAULT ExposureTime branch (pos
/// 22; `Canon.pm:2823`/`:2992`). Equivalent to `2 ** -CanonEv($val)`.
fn exposure_time_from_apex(raw: i64) -> f64 {
  (-canon_ev(raw)).exp2()
}

/// `sprintf("%.2g", $val)` — reuses the shared faithful `%g` formatter.
fn format_g_two(v: f64) -> String {
  format_g(v, 2)
}

/// `Image::ExifTool::Canon::PrintFocusDistance`-equivalent inline
/// (`Canon.pm:2944`): `$val > 655.345 ? "inf" : "$val m"` where
/// `$val = raw / 100`.
fn focus_distance_print(metres: f64) -> SmolStr {
  if metres > 655.345 {
    SmolStr::new_static("inf")
  } else {
    SmolStr::from(format_distance_m(metres))
  }
}

/// `"$val m"` with Perl's bare-number stringification (no forced
/// decimals — `5.46` stays `5.46`, `100` stays `100`).
fn format_distance_m(metres: f64) -> std::string::String {
  if metres.fract() == 0.0 {
    std::format!("{} m", metres as i64)
  } else {
    std::format!("{metres} m")
  }
}

/// Read one signed 16-bit word at word `position` (byte offset
/// `2*position`). Default `FORMAT => 'int16s'`.
fn read_i16(data: &[u8], position: usize, order: ByteOrder) -> Option<i64> {
  let off = 2 * position;
  let b = data.get(off..off + 2)?;
  let arr = [b[0], b[1]];
  Some(match order {
    ByteOrder::Little => i16::from_le_bytes(arr),
    ByteOrder::Big => i16::from_be_bytes(arr),
  } as i64)
}

/// Read one unsigned 16-bit word (the position 19/20 `Format =>
/// 'int16u'` overrides).
fn read_u16(data: &[u8], position: usize, order: ByteOrder) -> Option<i64> {
  let off = 2 * position;
  let b = data.get(off..off + 2)?;
  let arr = [b[0], b[1]];
  Some(match order {
    ByteOrder::Little => u16::from_le_bytes(arr),
    ByteOrder::Big => u16::from_be_bytes(arr),
  } as i64)
}

/// `$$self{Model} =~ /EOS/ and $$self{Model} !~ /EOS-1DS?$/`
/// (`Canon.pm:2867`) — the CameraTemperature gate.
fn camera_temperature_model_ok(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  if !m.contains("EOS") {
    return false;
  }
  // `!~ /EOS-1DS?$/` — exclude bodies whose name ENDS in "EOS-1D" or
  // "EOS-1DS". The bundled model-name strings are like "EOS-1D" /
  // "EOS-1DS"; the trailing-anchor excludes exactly those two.
  !(m.ends_with("EOS-1D") || m.ends_with("EOS-1DS"))
}

/// `$$self{Model} =~ /(PowerShot|IXUS|IXY)/` (`Canon.pm:3046`). Also the
/// TargetExposureTime RawConv body (`Canon.pm:2822`) accepts EOS too.
fn is_powershot(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.contains("PowerShot") || m.contains("IXUS") || m.contains("IXY"))
}

/// `$$self{Model} =~ /(EOS|PowerShot|IXUS|IXY)/` — the TargetExposureTime
/// RawConv model clause (`Canon.pm:2822`): a raw of 0 is kept only for
/// these families (otherwise a 0 ⇒ undef).
fn is_eos_or_powershot(model: Option<&str>) -> bool {
  model.is_some_and(|m| {
    m.contains("EOS") || m.contains("PowerShot") || m.contains("IXUS") || m.contains("IXY")
  })
}

/// `$$self{Model} =~ /\b(20D|350D|REBEL XT|Kiss Digital N)\b/` — the
/// position-22 ExposureTime conditional-list FIRST branch
/// (`Canon.pm:2972`). These bodies encode ExposureTime as
/// `exp(-CanonEv*log2)*1000/32` instead of the default `exp(-CanonEv*log2)`.
/// `\b` is a word boundary; the resolved `%canonModelID` names contain these
/// tokens delimited by spaces/slashes (e.g. `"EOS 20D"`,
/// `"EOS Digital Rebel XT / 350D / Kiss Digital N"`).
fn is_20d_350d_family(model: Option<&str>) -> bool {
  let Some(m) = model else { return false };
  ["20D", "350D", "REBEL XT", "Kiss Digital N"]
    .iter()
    .any(|tok| matches_word(m, tok))
}

/// Faithful-enough `\b<token>\b` test for the model-name tokens above. A
/// Perl `\b` boundary sits between a word char (`[A-Za-z0-9_]`) and a
/// non-word char (or string edge). We require each match position to have a
/// non-word char (or edge) on both sides — sufficient for these tokens,
/// which are themselves word-char-bounded.
fn matches_word(haystack: &str, token: &str) -> bool {
  let hb = haystack.as_bytes();
  let tb = token.as_bytes();
  let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
  let mut start = 0usize;
  while let Some(rel) = haystack[start..].find(token) {
    let i = start + rel;
    let before_ok = i == 0 || !is_word(hb[i - 1]);
    let end = i + tb.len();
    let after_ok = end >= hb.len() || !is_word(hb[end]);
    if before_ok && after_ok {
      return true;
    }
    start = i + 1;
  }
  false
}

/// Parse a ShotInfo blob into a typed [`CanonShotInfo`] + the
/// `(name, value)` emissions (faithful to bundled's `-j` shape).
///
/// `model` is the resolved Canon model NAME (from `%canonModelID`) — the
/// bundled Conditions key on `$$self{Model}`, and the resolved name is
/// the faithful stand-in (e.g. `"EOS 20D"`).
///
/// `file_type` is the container's detected `$$self{FILE_TYPE}` (`Some("CRW")`
/// for a CIFF/CRW raw, `Some("JPEG")`/`Some("CR2")`/… otherwise, `None` when
/// unknown). It is read ONLY by position 22's RawConv (`Canon.pm:2977`/`:2990`):
/// a raw-0 ExposureTime is kept when the container is a CRW (`"0 is valid in a
/// CRW image (=1s, D60 sample)"`).
#[must_use]
pub fn parse(
  data: &[u8],
  order: ByteOrder,
  print_conv: bool,
  model: Option<&str>,
  file_type: Option<&str>,
) -> (CanonShotInfo, Vec<(SmolStr, TagValue)>) {
  let mut typed = CanonShotInfo::new();
  let mut out: Vec<(SmolStr, TagValue)> = Vec::new();
  if data.len() < 4 {
    return (typed, out);
  }

  let mut push = |name: &'static str, v: TagValue| out.push((SmolStr::new_static(name), v));

  let labelled = |label: Option<&'static str>, raw: i64| -> TagValue {
    match label {
      Some(l) => TagValue::Str(SmolStr::new_static(l)),
      None => TagValue::Str(SmolStr::from(std::format!("Unknown ({raw})"))),
    }
  };

  // Position 1 — AutoISO. `exp($val/32*log(2))*100`, PrintConv `%.0f`.
  // No RawConv (raw 0 ⇒ ValueConv 100).
  if let Some(raw) = read_i16(data, 1, order) {
    let v = (raw as f64 / 32.0 * std::f64::consts::LN_2).exp() * 100.0;
    typed.auto_iso = Some(v);
    push(
      "AutoISO",
      if print_conv {
        TagValue::Str(SmolStr::from(std::format!("{v:.0}")))
      } else {
        num_value(v)
      },
    );
  }

  // Position 2 — BaseISO. RawConv `$val ? $val : undef` (drop 0); ValueConv
  // `exp($val/32*log(2))*100/32`, PrintConv `%.0f`.
  if let Some(raw) = read_i16(data, 2, order)
    && raw != 0
  {
    let v = (raw as f64 / 32.0 * std::f64::consts::LN_2).exp() * 100.0 / 32.0;
    typed.base_iso = Some(v);
    push(
      "BaseISO",
      if print_conv {
        TagValue::Str(SmolStr::from(std::format!("{v:.0}")))
      } else {
        num_value(v)
      },
    );
  }

  // Position 3 — MeasuredEV. ValueConv `$val/32+5`, PrintConv `%.2f`.
  // No RawConv (raw 0 ⇒ 5).
  if let Some(raw) = read_i16(data, 3, order) {
    let v = raw as f64 / 32.0 + 5.0;
    typed.measured_ev = Some(v);
    push(
      "MeasuredEV",
      if print_conv {
        TagValue::Str(SmolStr::from(std::format!("{v:.2}")))
      } else {
        num_value(v)
      },
    );
  }

  // Position 4 — TargetAperture. RawConv `$val > 0 ? $val : undef`;
  // ValueConv `exp(CanonEv($val)*log(2)/2)`, PrintConv `%.2g`.
  if let Some(raw) = read_i16(data, 4, order)
    && raw > 0
  {
    let v = aperture_from_apex(raw);
    typed.target_aperture = Some(v);
    push(
      "TargetAperture",
      if print_conv {
        TagValue::Str(SmolStr::from(format_g_two(v)))
      } else {
        num_value(v)
      },
    );
  }

  // Position 5 — TargetExposureTime. RawConv drops `<= -1000`, and 0 unless
  // an EOS/PowerShot/IXUS/IXY body (`Canon.pm:2822`); ValueConv
  // `exp(-CanonEv($val)*log(2))`, PrintConv `PrintExposureTime`.
  if let Some(raw) = read_i16(data, 5, order)
    && raw > -1000
    && (raw != 0 || is_eos_or_powershot(model))
  {
    let v = exposure_time_from_apex(raw);
    typed.target_exposure_time = Some(v);
    push(
      "TargetExposureTime",
      if print_conv {
        TagValue::Str(SmolStr::from(print_exposure_time(v)))
      } else {
        num_value(v)
      },
    );
  }

  // Position 6 — ExposureCompensation. ValueConv `CanonEv($val)`, PrintConv
  // `PrintFraction` (same shape as AEBBracketValue). No RawConv.
  if let Some(raw) = read_i16(data, 6, order) {
    let ev = canon_ev(raw);
    push(
      "ExposureCompensation",
      if print_conv {
        TagValue::Str(SmolStr::from(print_fraction(ev)))
      } else {
        num_value(ev)
      },
    );
    typed.exposure_compensation = Some(ev);
  }

  // Position 7 — WhiteBalance.
  if let Some(raw) = read_i16(data, 7, order) {
    let label = white_balance_label(raw);
    if let Some(l) = label {
      typed.white_balance = Some(SmolStr::new_static(l));
    }
    push(
      "WhiteBalance",
      if print_conv {
        labelled(label, raw)
      } else {
        TagValue::I64(raw)
      },
    );
  }

  // Position 8 — SlowShutter (PrintConv hash; no RawConv/ValueConv).
  if let Some(raw) = read_i16(data, 8, order) {
    let label = slow_shutter_label(raw);
    if let Some(l) = label {
      typed.slow_shutter = Some(SmolStr::new_static(l));
    }
    push(
      "SlowShutter",
      if print_conv {
        labelled(label, raw)
      } else {
        TagValue::I64(raw)
      },
    );
  }

  // Position 9 — SequenceNumber (no conv).
  if let Some(raw) = read_i16(data, 9, order) {
    typed.sequence_number = Some(raw);
    push("SequenceNumber", TagValue::I64(raw));
  }

  // Position 10 — OpticalZoomCode. No ValueConv; PrintConv
  // `$val == 8 ? "n/a" : $val` (`Canon.pm:2862`).
  if let Some(raw) = read_i16(data, 10, order) {
    typed.optical_zoom_code = Some(raw);
    push(
      "OpticalZoomCode",
      if print_conv && raw == 8 {
        TagValue::Str(SmolStr::new_static("n/a"))
      } else {
        TagValue::I64(raw)
      },
    );
  }

  // Position 12 — CameraTemperature (EOS-only; RawConv drops 0).
  if camera_temperature_model_ok(model)
    && let Some(raw) = read_i16(data, 12, order)
    && raw != 0
  {
    let c = raw - 128;
    typed.camera_temperature_c = Some(c);
    push(
      "CameraTemperature",
      if print_conv {
        TagValue::Str(SmolStr::from(std::format!("{c} C")))
      } else {
        TagValue::I64(c)
      },
    );
  }

  // Position 13 — FlashGuideNumber (RawConv drops -1; ValueConv /32).
  if let Some(raw) = read_i16(data, 13, order)
    && raw != -1
  {
    let v = raw as f64 / 32.0;
    typed.flash_guide_number = Some(v);
    push("FlashGuideNumber", num_value(v));
  }

  // Position 14 — AFPointsInFocus. RawConv `$val==0 ? undef : $val`;
  // `Flags => 'PrintHex'` (unmatched ⇒ `Unknown (0xNN)`, lowercase hex).
  // NO model Condition in bundled 13.59 — emitted for EOS too (the EOS body
  // ALSO gets a same-named tag from Canon::AFInfo, kept separately).
  if let Some(raw) = read_i16(data, 14, order)
    && raw != 0
  {
    let label = af_points_in_focus_label(raw);
    if let Some(l) = label {
      typed.af_points_in_focus = Some(SmolStr::new_static(l));
    }
    push(
      "AFPointsInFocus",
      if print_conv {
        match label {
          Some(l) => TagValue::Str(SmolStr::new_static(l)),
          // PrintHex fallback: `sprintf('Unknown (0x%x)', $val)`.
          None => TagValue::Str(SmolStr::from(std::format!("Unknown (0x{raw:x})"))),
        }
      } else {
        TagValue::I64(raw)
      },
    );
  }

  // Position 15 — FlashExposureComp. ValueConv `CanonEv($val)`, PrintConv
  // `PrintFraction` (same shape as ExposureCompensation/AEBBracketValue).
  if let Some(raw) = read_i16(data, 15, order) {
    let ev = canon_ev(raw);
    push(
      "FlashExposureComp",
      if print_conv {
        TagValue::Str(SmolStr::from(print_fraction(ev)))
      } else {
        num_value(ev)
      },
    );
    typed.flash_exposure_comp = Some(ev);
  }

  // Position 16 — AutoExposureBracketing.
  if let Some(raw) = read_i16(data, 16, order) {
    let label = aeb_label(raw);
    if let Some(l) = label {
      typed.auto_exposure_bracketing = Some(SmolStr::new_static(l));
    }
    push(
      "AutoExposureBracketing",
      if print_conv {
        labelled(label, raw)
      } else {
        TagValue::I64(raw)
      },
    );
  }

  // Position 17 — AEBBracketValue (CanonEv → PrintFraction).
  if let Some(raw) = read_i16(data, 17, order) {
    let ev = canon_ev(raw);
    push(
      "AEBBracketValue",
      if print_conv {
        TagValue::Str(SmolStr::from(print_fraction(ev)))
      } else {
        // -n: ValueConv result (CanonEv), the bare APEX value.
        num_value(ev)
      },
    );
  }

  // Position 18 — ControlMode.
  if let Some(raw) = read_i16(data, 18, order) {
    let label = control_mode_label(raw);
    if let Some(l) = label {
      typed.control_mode = Some(SmolStr::new_static(l));
    }
    push(
      "ControlMode",
      if print_conv {
        labelled(label, raw)
      } else {
        TagValue::I64(raw)
      },
    );
  }

  // Position 19 — FocusDistanceUpper (int16u; RawConv `$val || undef`).
  // Sets the DataMember that gates position 20.
  let mut focus_upper_nonzero = false;
  if let Some(raw) = read_u16(data, 19, order)
    && raw != 0
  {
    focus_upper_nonzero = true;
    let metres = raw as f64 / 100.0;
    // Encode "inf" as f64::INFINITY in the typed surface.
    typed.focus_distance_upper_m = Some(if metres > 655.345 {
      f64::INFINITY
    } else {
      metres
    });
    push(
      "FocusDistanceUpper",
      if print_conv {
        TagValue::Str(focus_distance_print(metres))
      } else {
        num_value(metres)
      },
    );
  }

  // Position 20 — FocusDistanceLower (int16u; Condition FocusDistanceUpper).
  if focus_upper_nonzero && let Some(raw) = read_u16(data, 20, order) {
    let metres = raw as f64 / 100.0;
    typed.focus_distance_lower_m = Some(if metres > 655.345 {
      f64::INFINITY
    } else {
      metres
    });
    push(
      "FocusDistanceLower",
      if print_conv {
        TagValue::Str(focus_distance_print(metres))
      } else {
        num_value(metres)
      },
    );
  }

  // Position 21 — FNumber. RawConv `$val ? $val : undef` (drop 0); ValueConv
  // `exp(CanonEv($val)*log(2)/2)`, PrintConv `%.2g` (same as TargetAperture).
  if let Some(raw) = read_i16(data, 21, order)
    && raw != 0
  {
    let v = aperture_from_apex(raw);
    typed.f_number = Some(v);
    push(
      "FNumber",
      if print_conv {
        TagValue::Str(SmolStr::from(format_g_two(v)))
      } else {
        num_value(v)
      },
    );
  }

  // Position 22 — ExposureTime (model-conditional list, `Canon.pm:2967-
  // 2997`). RawConv `($val or $$self{FILE_TYPE} eq "CRW") ? $val : undef`:
  // emit unless `$val == 0` AND the container is not a CRW (`"0 is valid in a
  // CRW image (=1s, D60 sample)"`, `Canon.pm:2974-2976`). Both the FIRST
  // branch (20D/350D/REBEL XT/Kiss Digital N, ValueConv
  // `exp(-CanonEv($val)*log(2))*1000/32`) and the default branch
  // (`exp(-CanonEv($val)*log(2))`) carry the SAME RawConv, so the single
  // `raw != 0 || file_type == Some("CRW")` gate covers both. Both PrintConv
  // `PrintExposureTime`.
  if let Some(raw) = read_i16(data, 22, order)
    && (raw != 0 || file_type == Some("CRW"))
  {
    let v = if is_20d_350d_family(model) {
      exposure_time_from_apex(raw) * 1000.0 / 32.0
    } else {
      exposure_time_from_apex(raw)
    };
    typed.exposure_time = Some(v);
    push(
      "ExposureTime",
      if print_conv {
        TagValue::Str(SmolStr::from(print_exposure_time(v)))
      } else {
        num_value(v)
      },
    );
  }

  // Position 23 — MeasuredEV2 (RawConv drops 0; ValueConv /8 - 6).
  if let Some(raw) = read_i16(data, 23, order)
    && raw != 0
  {
    let v = raw as f64 / 8.0 - 6.0;
    typed.measured_ev2 = Some(v);
    push("MeasuredEV2", num_value(v));
  }

  // Position 24 — BulbDuration (ValueConv /10).
  if let Some(raw) = read_i16(data, 24, order) {
    let v = raw as f64 / 10.0;
    typed.bulb_duration = Some(v);
    push("BulbDuration", num_value(v));
  }

  // Position 26 — CameraType (PrintConv hash; no RawConv/ValueConv).
  if let Some(raw) = read_i16(data, 26, order) {
    let label = camera_type_label(raw);
    if let Some(l) = label {
      typed.camera_type = Some(SmolStr::new_static(l));
    }
    push(
      "CameraType",
      if print_conv {
        labelled(label, raw)
      } else {
        TagValue::I64(raw)
      },
    );
  }

  // Position 27 — AutoRotate. RawConv `$val >= 0 ? $val : undef` (drop
  // negatives), PrintConv hash.
  if let Some(raw) = read_i16(data, 27, order)
    && raw >= 0
  {
    let label = auto_rotate_label(raw);
    if let Some(l) = label {
      typed.auto_rotate = Some(SmolStr::new_static(l));
    }
    push(
      "AutoRotate",
      if print_conv {
        labelled(label, raw)
      } else {
        TagValue::I64(raw)
      },
    );
  }

  // Position 28 — NDFilter.
  if let Some(raw) = read_i16(data, 28, order) {
    let label = nd_filter_label(raw);
    if let Some(l) = label {
      typed.nd_filter = Some(SmolStr::new_static(l));
    }
    push(
      "NDFilter",
      if print_conv {
        labelled(label, raw)
      } else {
        TagValue::I64(raw)
      },
    );
  }

  // Position 29 — SelfTimer2. RawConv `$val >= 0 ? $val : undef`; ValueConv
  // `$val / 10`. No PrintConv (the ValueConv number is the print value).
  if let Some(raw) = read_i16(data, 29, order)
    && raw >= 0
  {
    let v = raw as f64 / 10.0;
    typed.self_timer2 = Some(v);
    push("SelfTimer2", num_value(v));
  }

  // Position 33 — FlashOutput (RawConv: PowerShot OR nonzero).
  if let Some(raw) = read_i16(data, 33, order)
    && (is_powershot(model) || raw != 0)
  {
    typed.flash_output = Some(raw);
    push("FlashOutput", TagValue::I64(raw));
  }

  (typed, out)
}

/// Emit a float value as an integer when it is whole (Perl stringifies
/// `4.0` as `4`), else as `F64`.
fn num_value(v: f64) -> TagValue {
  if v.fract() == 0.0 && v.is_finite() {
    TagValue::I64(v as i64)
  } else {
    TagValue::F64(v)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::exif::ifd::ByteOrder;

  /// Build a synthetic ShotInfo blob (`words.len()` int16 words, LE),
  /// with word 0 set to the blob size.
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

  /// Real-input parity: the EOS 300D fixture's ShotInfo words decoded by
  /// the oracle (`Canon.pm` `-j`). Verifies the high-value positions.
  #[test]
  fn eos_300d_fixture_words_match_oracle() {
    // 33 words from the fixture (Canon.pm verbose dump, little-endian).
    let words: [i16; 33] = [
      66, 0, 160, -200, 244, -32768, 0, 0, 3, 0, 8, 8, 0, 0, 0, 0, 0, 0, 1, -1, 546, 244, -224, 38,
      40, 0, 252, 0, -1, 0, 0, 0, 0,
    ];
    let data = blob(&words);
    let model = Some("EOS Digital Rebel / 300D / Kiss Digital");
    let (typed, em) = parse(&data, ByteOrder::Little, true, model, None);

    // --- Newly-ported positions (oracled vs ExifTool 13.59 Perl) ---
    // pos1 AutoISO raw=0 → exp(0)*100 = 100 → "100".
    assert_eq!(find(&em, "AutoISO"), Some(TagValue::Str("100".into())));
    assert_eq!(typed.auto_iso(), Some(100.0));
    // pos2 BaseISO raw=160 → exp(5*ln2)*100/32 = 100 → "100".
    assert_eq!(find(&em, "BaseISO"), Some(TagValue::Str("100".into())));
    // pos3 MeasuredEV raw=-200 → -200/32+5 = -1.25 → "-1.25".
    assert_eq!(find(&em, "MeasuredEV"), Some(TagValue::Str("-1.25".into())));
    // pos4 TargetAperture raw=244 → "14".
    assert_eq!(
      find(&em, "TargetAperture"),
      Some(TagValue::Str("14".into()))
    );
    // pos5 TargetExposureTime raw=-32768 → RawConv (<= -1000) drops it.
    assert_eq!(find(&em, "TargetExposureTime"), None);
    assert_eq!(typed.target_exposure_time(), None);
    // pos6 ExposureCompensation raw=0 → CanonEv(0)=0 → PrintFraction "0".
    assert_eq!(
      find(&em, "ExposureCompensation"),
      Some(TagValue::Str("0".into()))
    );
    // pos8 SlowShutter raw=3 → "None".
    assert_eq!(find(&em, "SlowShutter"), Some(TagValue::Str("None".into())));
    // pos10 OpticalZoomCode raw=8 → "n/a".
    assert_eq!(
      find(&em, "OpticalZoomCode"),
      Some(TagValue::Str("n/a".into()))
    );
    // pos14 AFPointsInFocus raw=0 → RawConv drops it.
    assert_eq!(find(&em, "AFPointsInFocus"), None);
    // pos15 FlashExposureComp raw=0 → "0".
    assert_eq!(
      find(&em, "FlashExposureComp"),
      Some(TagValue::Str("0".into()))
    );
    // pos21 FNumber raw=244 → "14".
    assert_eq!(find(&em, "FNumber"), Some(TagValue::Str("14".into())));
    // pos22 ExposureTime raw=-224, model=300D (NOT 350D) → default branch
    // exp(-CanonEv(-224)*ln2) = 128 → "128".
    assert_eq!(find(&em, "ExposureTime"), Some(TagValue::Str("128".into())));
    // pos26 CameraType raw=252 → "EOS Mid-range".
    assert_eq!(
      find(&em, "CameraType"),
      Some(TagValue::Str("EOS Mid-range".into()))
    );
    assert_eq!(typed.camera_type(), Some("EOS Mid-range"));
    // pos27 AutoRotate raw=0 → "None".
    assert_eq!(find(&em, "AutoRotate"), Some(TagValue::Str("None".into())));
    // pos29 SelfTimer2 raw=0 → 0/10 = 0.
    assert_eq!(find(&em, "SelfTimer2"), Some(TagValue::I64(0)));

    // --- Previously-ported positions (unchanged) ---
    // WhiteBalance = 0 → "Auto".
    assert_eq!(
      find(&em, "WhiteBalance"),
      Some(TagValue::Str("Auto".into()))
    );
    assert_eq!(typed.white_balance(), Some("Auto"));
    // SequenceNumber = 0.
    assert_eq!(find(&em, "SequenceNumber"), Some(TagValue::I64(0)));
    // CameraTemperature = 0 → RawConv drops it.
    assert_eq!(find(&em, "CameraTemperature"), None);
    assert_eq!(typed.camera_temperature_c(), None);
    // FlashGuideNumber = 0 → 0/32 = 0.
    assert_eq!(find(&em, "FlashGuideNumber"), Some(TagValue::I64(0)));
    // AutoExposureBracketing = 0 → "Off".
    assert_eq!(
      find(&em, "AutoExposureBracketing"),
      Some(TagValue::Str("Off".into()))
    );
    // AEBBracketValue = 0 → CanonEv(0)=0 → PrintFraction(0) = "0".
    assert_eq!(
      find(&em, "AEBBracketValue"),
      Some(TagValue::Str("0".into()))
    );
    // ControlMode = 1 → "Camera Local Control".
    assert_eq!(
      find(&em, "ControlMode"),
      Some(TagValue::Str("Camera Local Control".into()))
    );
    // FocusDistanceUpper = 65535 (int16u) → 655.35 → "inf".
    assert_eq!(
      find(&em, "FocusDistanceUpper"),
      Some(TagValue::Str("inf".into()))
    );
    assert_eq!(typed.focus_distance_upper_m(), Some(f64::INFINITY));
    // FocusDistanceLower = 546 → 5.46 → "5.46 m".
    assert_eq!(
      find(&em, "FocusDistanceLower"),
      Some(TagValue::Str("5.46 m".into()))
    );
    assert_eq!(typed.focus_distance_lower_m(), Some(5.46));
    // MeasuredEV2 = 38 → 38/8 - 6 = -1.25.
    assert_eq!(find(&em, "MeasuredEV2"), Some(TagValue::F64(-1.25)));
    // BulbDuration = 40 → 4.
    assert_eq!(find(&em, "BulbDuration"), Some(TagValue::I64(4)));
    // NDFilter = -1 → "n/a".
    assert_eq!(find(&em, "NDFilter"), Some(TagValue::Str("n/a".into())));
    // FlashOutput at word 33 is OUT OF RANGE (33 words, idx 0-32) → absent.
    assert_eq!(find(&em, "FlashOutput"), None);
  }

  /// AEBBracketValue: `CanonEv($val)` → `PrintFraction`. Verified against
  /// the Perl oracle (`Canon::CanonEv` + `Exif::PrintFraction`):
  /// raw 16 → "+1/2", raw 12 → "+1/3", raw 32 → "+1", raw -32 → "-1".
  #[test]
  fn aeb_bracket_value_canon_ev_print_fraction() {
    let cases = [(16i16, "+1/2"), (12, "+1/3"), (32, "+1"), (-32, "-1")];
    for (raw, want) in cases {
      let mut words = [0i16; 18];
      words[17] = raw;
      let data = blob(&words);
      let (_t, em) = parse(&data, ByteOrder::Little, true, None, None);
      assert_eq!(
        find(&em, "AEBBracketValue"),
        Some(TagValue::Str(want.into())),
        "AEBBracketValue raw={raw}"
      );
    }
  }

  /// The int16u read at position 19 must NOT sign-extend (65535 ≠ -1).
  #[test]
  fn focus_distance_upper_is_unsigned() {
    let mut words = [0i16; 21];
    words[19] = -1; // bytes 0xffff → as int16u = 65535.
    words[20] = 546;
    let data = blob(&words);
    let (typed, em) = parse(&data, ByteOrder::Little, true, None, None);
    assert_eq!(
      find(&em, "FocusDistanceUpper"),
      Some(TagValue::Str("inf".into()))
    );
    assert_eq!(typed.focus_distance_upper_m(), Some(f64::INFINITY));
    // Lower emitted because upper was nonzero.
    assert_eq!(
      find(&em, "FocusDistanceLower"),
      Some(TagValue::Str("5.46 m".into()))
    );
  }

  /// Position 20 is skipped when position 19 (FocusDistanceUpper) is 0.
  #[test]
  fn focus_distance_lower_gated_on_upper() {
    let mut words = [0i16; 21];
    words[19] = 0; // upper = 0 → RawConv undef.
    words[20] = 546;
    let data = blob(&words);
    let (_typed, em) = parse(&data, ByteOrder::Little, true, None, None);
    assert_eq!(find(&em, "FocusDistanceUpper"), None);
    assert_eq!(find(&em, "FocusDistanceLower"), None);
  }

  /// CameraTemperature emits for an EOS body (nonzero raw) and is dropped
  /// for the excluded `EOS-1D`/`EOS-1DS`.
  #[test]
  fn camera_temperature_eos_condition() {
    let mut words = [0i16; 13];
    words[12] = 150; // 150 - 128 = 22 C.
    let data = blob(&words);

    // EOS 5D → emitted.
    let (typed, em) = parse(&data, ByteOrder::Little, true, Some("EOS 5D"), None);
    assert_eq!(
      find(&em, "CameraTemperature"),
      Some(TagValue::Str("22 C".into()))
    );
    assert_eq!(typed.camera_temperature_c(), Some(22));

    // EOS-1D → excluded by `!~ /EOS-1DS?$/`.
    let (typed2, em2) = parse(&data, ByteOrder::Little, true, Some("EOS-1D"), None);
    assert_eq!(find(&em2, "CameraTemperature"), None);
    assert_eq!(typed2.camera_temperature_c(), None);

    // Non-EOS (PowerShot) → excluded.
    let (_t3, em3) = parse(
      &data,
      ByteOrder::Little,
      true,
      Some("PowerShot A570 IS"),
      None,
    );
    assert_eq!(find(&em3, "CameraTemperature"), None);
  }

  /// FlashOutput keeps a 0 value for PowerShot bodies but drops it for
  /// EOS bodies (RawConv `PowerShot|IXUS|IXY OR $val`).
  #[test]
  fn flash_output_powershot_condition() {
    let mut words = [0i16; 34];
    words[33] = 0;
    let data = blob(&words);
    // PowerShot → 0 kept.
    let (typed, em) = parse(
      &data,
      ByteOrder::Little,
      true,
      Some("PowerShot A570 IS"),
      None,
    );
    assert_eq!(find(&em, "FlashOutput"), Some(TagValue::I64(0)));
    assert_eq!(typed.flash_output(), Some(0));
    // EOS with 0 → dropped.
    let (_t2, em2) = parse(&data, ByteOrder::Little, true, Some("EOS 5D"), None);
    assert_eq!(find(&em2, "FlashOutput"), None);
    // EOS with nonzero → kept.
    words[33] = 200;
    let data2 = blob(&words);
    let (_t3, em3) = parse(&data2, ByteOrder::Little, true, Some("EOS 5D"), None);
    assert_eq!(find(&em3, "FlashOutput"), Some(TagValue::I64(200)));
  }

  /// `print_conv = false` keeps raw/ValueConv numerics (no labels).
  #[test]
  fn print_conv_off_keeps_numeric() {
    let mut words = [0i16; 29];
    words[7] = 1; // WhiteBalance = Daylight.
    words[28] = 1; // NDFilter = On.
    let data = blob(&words);
    let (_typed, em) = parse(&data, ByteOrder::Little, false, None, None);
    assert_eq!(find(&em, "WhiteBalance"), Some(TagValue::I64(1)));
    assert_eq!(find(&em, "NDFilter"), Some(TagValue::I64(1)));
  }

  #[test]
  fn short_blob_yields_empty() {
    let (typed, em) = parse(&[0, 0], ByteOrder::Little, true, None, None);
    assert!(typed.is_empty());
    assert!(em.is_empty());
  }

  /// AutoISO (pos 1) / BaseISO (pos 2): `exp(v/32*ln2)*100[/32]` then
  /// `%.0f`. Oracled (Perl): AutoISO raw 96→"800", 200→"7611" (-n
  /// 7610.925536); BaseISO raw 200→"238", raw 0 dropped.
  #[test]
  fn auto_and_base_iso_convs() {
    // -j: rounded strings.
    let mut words = [0i16; 3];
    words[1] = 96; // AutoISO
    words[2] = 200; // BaseISO
    let data = blob(&words);
    let (typed, em) = parse(&data, ByteOrder::Little, true, None, None);
    // -j: Perl `%.0f` rounds the (799.999…) float to "800".
    assert_eq!(find(&em, "AutoISO"), Some(TagValue::Str("800".into())));
    assert_eq!(find(&em, "BaseISO"), Some(TagValue::Str("238".into())));
    // The stored f64 carries the exact IEEE value (matching Perl's NV; the
    // %.0f / %.15g rounding to 800 happens at print/serialize time).
    let auto_iso_96 = (96.0_f64 / 32.0 * std::f64::consts::LN_2).exp() * 100.0;
    assert_eq!(typed.auto_iso(), Some(auto_iso_96));

    // -n: post-ValueConv numbers (whole→I64, fractional→F64).
    words[1] = 200;
    let data2 = blob(&words);
    let (_t, em2) = parse(&data2, ByteOrder::Little, false, None, None);
    let auto_iso_200 = (200.0_f64 / 32.0 * std::f64::consts::LN_2).exp() * 100.0;
    assert_eq!(find(&em2, "AutoISO"), Some(TagValue::F64(auto_iso_200)));

    // BaseISO RawConv drops 0; AutoISO has no RawConv (raw 0 → 100).
    let mut z = [0i16; 3];
    z[1] = 0;
    z[2] = 0;
    let dataz = blob(&z);
    let (_tz, emz) = parse(&dataz, ByteOrder::Little, true, None, None);
    assert_eq!(find(&emz, "AutoISO"), Some(TagValue::Str("100".into())));
    assert_eq!(find(&emz, "BaseISO"), None);
  }

  /// MeasuredEV (pos 3): `v/32+5`, `%.2f`. Oracled: raw 32→"6.00",
  /// raw 0→"5.00" (no RawConv).
  #[test]
  fn measured_ev_conv() {
    let mut words = [0i16; 4];
    words[3] = 32;
    let data = blob(&words);
    let (typed, em) = parse(&data, ByteOrder::Little, true, None, None);
    assert_eq!(find(&em, "MeasuredEV"), Some(TagValue::Str("6.00".into())));
    assert_eq!(typed.measured_ev(), Some(6.0));
    // raw 0 → 5.00 (not dropped).
    let z = [0i16; 4];
    let (_t, emz) = parse(&blob(&z), ByteOrder::Little, true, None, None);
    assert_eq!(find(&emz, "MeasuredEV"), Some(TagValue::Str("5.00".into())));
    // -n: 6 (whole).
    let (_t2, emn) = parse(&data, ByteOrder::Little, false, None, None);
    assert_eq!(find(&emn, "MeasuredEV"), Some(TagValue::I64(6)));
  }

  /// TargetAperture (pos 4) / FNumber (pos 21): aperture conv + `%.2g`.
  /// Oracled: raw 160→"5.7" (-n 5.656854249), raw 192→"8", raw 96→"2.8".
  /// RawConv: TargetAperture drops `<= 0`, FNumber drops `0`.
  #[test]
  fn target_aperture_and_fnumber_convs() {
    let mut words = [0i16; 22];
    words[4] = 160; // TargetAperture
    words[21] = 96; // FNumber
    let data = blob(&words);
    let (typed, em) = parse(&data, ByteOrder::Little, true, None, None);
    assert_eq!(
      find(&em, "TargetAperture"),
      Some(TagValue::Str("5.7".into()))
    );
    assert_eq!(find(&em, "FNumber"), Some(TagValue::Str("2.8".into())));
    // Exact IEEE value of `2 ** (CanonEv(160)/2)` (CanonEv(160) = 5).
    let aperture_160 = (5.0_f64 / 2.0).exp2();
    assert_eq!(typed.target_aperture(), Some(aperture_160));

    // -n: ValueConv float.
    let (_t, emn) = parse(&data, ByteOrder::Little, false, None, None);
    assert_eq!(
      find(&emn, "TargetAperture"),
      Some(TagValue::F64(aperture_160))
    );

    // RawConv gates: TargetAperture raw 0 dropped, FNumber raw 0 dropped.
    let z = [0i16; 22];
    let (_tz, emz) = parse(&blob(&z), ByteOrder::Little, true, None, None);
    assert_eq!(find(&emz, "TargetAperture"), None);
    assert_eq!(find(&emz, "FNumber"), None);
    // TargetAperture raw -32 (<=0) dropped too.
    let mut neg = [0i16; 22];
    neg[4] = -32;
    let (_tn, emneg) = parse(&blob(&neg), ByteOrder::Little, true, None, None);
    assert_eq!(find(&emneg, "TargetAperture"), None);
  }

  /// TargetExposureTime (pos 5): RawConv drops `<= -1000`, and 0 unless
  /// EOS/PowerShot/IXUS/IXY. ValueConv `exp(-CanonEv*ln2)` →
  /// PrintExposureTime. Oracled: raw 160→"1/32", raw 96→"1/8".
  #[test]
  fn target_exposure_time_conv_and_gate() {
    let mut words = [0i16; 6];
    words[5] = 160;
    let data = blob(&words);
    let (typed, em) = parse(&data, ByteOrder::Little, true, Some("EOS 5D"), None);
    assert_eq!(
      find(&em, "TargetExposureTime"),
      Some(TagValue::Str("1/32".into()))
    );
    assert_eq!(typed.target_exposure_time(), Some(0.03125));
    // -n: 0.03125.
    let (_t, emn) = parse(&data, ByteOrder::Little, false, Some("EOS 5D"), None);
    assert_eq!(
      find(&emn, "TargetExposureTime"),
      Some(TagValue::F64(0.03125))
    );

    // raw <= -1000 → dropped regardless of model.
    let mut bad = [0i16; 6];
    bad[5] = -32768i16; // -32768 < -1000.
    let (_tb, emb) = parse(&blob(&bad), ByteOrder::Little, true, Some("EOS 5D"), None);
    assert_eq!(find(&emb, "TargetExposureTime"), None);

    // raw 0: kept for EOS/PowerShot (→ exp(0)=1s → "1"), dropped otherwise.
    let z = [0i16; 6];
    let (_tz, emz) = parse(&blob(&z), ByteOrder::Little, true, Some("EOS 5D"), None);
    assert_eq!(
      find(&emz, "TargetExposureTime"),
      Some(TagValue::Str("1".into()))
    );
    let (_tu, emu) = parse(
      &blob(&z),
      ByteOrder::Little,
      true,
      Some("Some Webcam"),
      None,
    );
    assert_eq!(find(&emu, "TargetExposureTime"), None);
  }

  /// ExposureCompensation (pos 6) / FlashExposureComp (pos 15): `CanonEv`
  /// then `PrintFraction`. Oracled: raw 16→"+1/2", -16→"-1/2", 64→"+2".
  #[test]
  fn exposure_comp_and_flash_exposure_comp() {
    let mut words = [0i16; 16];
    words[6] = 16; // ExposureCompensation
    words[15] = -16; // FlashExposureComp
    let data = blob(&words);
    let (typed, em) = parse(&data, ByteOrder::Little, true, None, None);
    assert_eq!(
      find(&em, "ExposureCompensation"),
      Some(TagValue::Str("+1/2".into()))
    );
    assert_eq!(
      find(&em, "FlashExposureComp"),
      Some(TagValue::Str("-1/2".into()))
    );
    assert_eq!(typed.exposure_compensation(), Some(0.5));
    assert_eq!(typed.flash_exposure_comp(), Some(-0.5));
    // -n: bare CanonEv values.
    let (_t, emn) = parse(&data, ByteOrder::Little, false, None, None);
    assert_eq!(find(&emn, "ExposureCompensation"), Some(TagValue::F64(0.5)));
  }

  /// SlowShutter (pos 8) PrintConv hash + unknown fallback `Unknown (n)`.
  #[test]
  fn slow_shutter_hash() {
    for (raw, want) in [(0i16, "Off"), (1, "Night Scene"), (2, "On"), (3, "None")] {
      let mut words = [0i16; 9];
      words[8] = raw;
      let (_t, em) = parse(&blob(&words), ByteOrder::Little, true, None, None);
      assert_eq!(find(&em, "SlowShutter"), Some(TagValue::Str(want.into())));
    }
    // unknown → "Unknown (9)".
    let mut words = [0i16; 9];
    words[8] = 9;
    let (_t, em) = parse(&blob(&words), ByteOrder::Little, true, None, None);
    assert_eq!(
      find(&em, "SlowShutter"),
      Some(TagValue::Str("Unknown (9)".into()))
    );
  }

  /// OpticalZoomCode (pos 10): PrintConv `v==8?"n/a":v`; -n always int.
  #[test]
  fn optical_zoom_code() {
    let mut words = [0i16; 11];
    words[10] = 8;
    let (_t, em) = parse(&blob(&words), ByteOrder::Little, true, None, None);
    assert_eq!(
      find(&em, "OpticalZoomCode"),
      Some(TagValue::Str("n/a".into()))
    );
    // raw 3 → 3 (int even in -j).
    words[10] = 3;
    let (_t2, em2) = parse(&blob(&words), ByteOrder::Little, true, None, None);
    assert_eq!(find(&em2, "OpticalZoomCode"), Some(TagValue::I64(3)));
    // -n raw 8 → 8.
    words[10] = 8;
    let (_t3, em3) = parse(&blob(&words), ByteOrder::Little, false, None, None);
    assert_eq!(find(&em3, "OpticalZoomCode"), Some(TagValue::I64(8)));
  }

  /// AFPointsInFocus (pos 14, PrintHex): RawConv drops 0; matched key →
  /// label; unmatched → `Unknown (0xNN)` lowercase hex. NO model gate
  /// (emits for EOS too). Oracled: 0x3002→"Center", 0x1234→"Unknown
  /// (0x1234)".
  #[test]
  fn af_points_in_focus_print_hex() {
    let mut words = [0i16; 15];
    words[14] = 0x3002u16 as i16; // "Center"
    let (typed, em) = parse(&blob(&words), ByteOrder::Little, true, Some("EOS 5D"), None);
    assert_eq!(
      find(&em, "AFPointsInFocus"),
      Some(TagValue::Str("Center".into()))
    );
    assert_eq!(typed.af_points_in_focus(), Some("Center"));
    // unmatched → "Unknown (0x1234)".
    words[14] = 0x1234;
    let (_t, em2) = parse(&blob(&words), ByteOrder::Little, true, Some("EOS 5D"), None);
    assert_eq!(
      find(&em2, "AFPointsInFocus"),
      Some(TagValue::Str("Unknown (0x1234)".into()))
    );
    // RawConv drops 0.
    words[14] = 0;
    let (_t2, em3) = parse(&blob(&words), ByteOrder::Little, true, Some("EOS 5D"), None);
    assert_eq!(find(&em3, "AFPointsInFocus"), None);
    // -n: raw decimal int (0x3002 = 12290).
    words[14] = 0x3002u16 as i16;
    let (_t3, em4) = parse(
      &blob(&words),
      ByteOrder::Little,
      false,
      Some("EOS 5D"),
      None,
    );
    assert_eq!(find(&em4, "AFPointsInFocus"), Some(TagValue::I64(12290)));
  }

  /// ExposureTime (pos 22) model-conditional list. 20D/350D/REBEL XT/Kiss
  /// Digital N → `exp(-CanonEv*ln2)*1000/32`; others → `exp(-CanonEv*ln2)`.
  /// Oracled raw 96: 20D branch → 3.90625 → "3.9"; default → 0.125 → "1/8".
  #[test]
  fn exposure_time_model_conditional() {
    let mut words = [0i16; 23];
    words[22] = 96;
    let data = blob(&words);

    // 20D branch.
    let (typed, em) = parse(&data, ByteOrder::Little, true, Some("EOS 20D"), None);
    assert_eq!(find(&em, "ExposureTime"), Some(TagValue::Str("3.9".into())));
    assert_eq!(typed.exposure_time(), Some(3.90625));
    // Kiss Digital N branch (word-boundary token match).
    let (_tk, emk) = parse(
      &data,
      ByteOrder::Little,
      true,
      Some("EOS Digital Rebel XT / 350D / Kiss Digital N"),
      None,
    );
    assert_eq!(
      find(&emk, "ExposureTime"),
      Some(TagValue::Str("3.9".into()))
    );

    // Default branch (5D is NOT in the 20D family).
    let (_td, emd) = parse(&data, ByteOrder::Little, true, Some("EOS 5D"), None);
    assert_eq!(
      find(&emd, "ExposureTime"),
      Some(TagValue::Str("1/8".into()))
    );
    // A "350D" substring inside a larger word must NOT match (\b). The
    // resolved names always delimit the token, so e.g. "X350DZ" stays
    // default — guards the word-boundary helper.
    let (_tx, emx) = parse(
      &data,
      ByteOrder::Little,
      true,
      Some("PowerShot X350DZ"),
      None,
    );
    assert_eq!(
      find(&emx, "ExposureTime"),
      Some(TagValue::Str("1/8".into()))
    );

    // RawConv drops a raw-0 for a non-CRW container (`file_type = None`):
    // `($val or FILE_TYPE eq "CRW")` is false.
    let z = [0i16; 23];
    let (_tz, emz) = parse(&blob(&z), ByteOrder::Little, true, Some("EOS 20D"), None);
    assert_eq!(find(&emz, "ExposureTime"), None);
  }

  /// Position-22 ExposureTime RawConv `($val or $$self{FILE_TYPE} eq "CRW") ?
  /// $val : undef` (`Canon.pm:2977`/`:2990`, BOTH branches): a raw-0
  /// ExposureTime is EMITTED for a CRW container ("0 is valid in a CRW image
  /// (=1s, D60 sample)") and DROPPED for every non-CRW container.
  ///
  /// Oracled against bundled 13.59 (`perl exiftool`): `CanonEv(0) = 0`, so the
  /// DEFAULT branch ValueConv `exp(-CanonEv(0)*log(2)) = 1` → PrintExposureTime
  /// "1"; the 20D branch ValueConv `…*1000/32 = 31.25` → PrintExposureTime
  /// "31.2".
  #[test]
  fn exposure_time_pos22_crw_keeps_raw_zero() {
    let z = [0i16; 23]; // pos-22 raw = 0.

    // --- CRW container: raw-0 IS emitted (the `FILE_TYPE eq "CRW"` clause). ---
    // Default branch (5D is not in the 20D family): exp(0) = 1.
    let (typed_d, em_d) = parse(
      &blob(&z),
      ByteOrder::Little,
      true,
      Some("EOS 5D"),
      Some("CRW"),
    );
    assert_eq!(find(&em_d, "ExposureTime"), Some(TagValue::Str("1".into())));
    assert_eq!(typed_d.exposure_time(), Some(1.0));
    // -n (ValueConv numeric): 1.0 is whole → I64(1).
    let (_td_n, em_d_n) = parse(
      &blob(&z),
      ByteOrder::Little,
      false,
      Some("EOS 5D"),
      Some("CRW"),
    );
    assert_eq!(find(&em_d_n, "ExposureTime"), Some(TagValue::I64(1)));

    // 20D branch: exp(0)*1000/32 = 31.25 → PrintExposureTime "31.2".
    let (typed_2, em_2) = parse(
      &blob(&z),
      ByteOrder::Little,
      true,
      Some("EOS 20D"),
      Some("CRW"),
    );
    assert_eq!(
      find(&em_2, "ExposureTime"),
      Some(TagValue::Str("31.2".into()))
    );
    assert_eq!(typed_2.exposure_time(), Some(31.25));
    // -n: 31.25 is fractional → F64(31.25).
    let (_t2_n, em_2_n) = parse(
      &blob(&z),
      ByteOrder::Little,
      false,
      Some("EOS 20D"),
      Some("CRW"),
    );
    assert_eq!(find(&em_2_n, "ExposureTime"), Some(TagValue::F64(31.25)));

    // --- Non-CRW containers: raw-0 is DROPPED (both branches, -j and -n). ---
    for ft in [Some("CR2"), Some("JPEG"), Some("TIFF"), None] {
      for model in [Some("EOS 5D"), Some("EOS 20D")] {
        for pc in [true, false] {
          let (_t, em) = parse(&blob(&z), ByteOrder::Little, pc, model, ft);
          assert_eq!(
            find(&em, "ExposureTime"),
            None,
            "raw-0 ExposureTime must be dropped for file_type={ft:?} model={model:?} pc={pc}"
          );
        }
      }
    }

    // A NONZERO raw is unaffected by file_type (CRW vs non-CRW identical).
    let mut nz = [0i16; 23];
    nz[22] = 96; // default branch → "1/8".
    let (_tc, em_crw) = parse(
      &blob(&nz),
      ByteOrder::Little,
      true,
      Some("EOS 5D"),
      Some("CRW"),
    );
    let (_tj, em_jpg) = parse(
      &blob(&nz),
      ByteOrder::Little,
      true,
      Some("EOS 5D"),
      Some("JPEG"),
    );
    assert_eq!(
      find(&em_crw, "ExposureTime"),
      Some(TagValue::Str("1/8".into()))
    );
    assert_eq!(find(&em_crw, "ExposureTime"), find(&em_jpg, "ExposureTime"));
  }

  /// CameraType (pos 26) hash + AutoRotate (pos 27) hash with RawConv
  /// `>= 0` dropping negatives. SelfTimer2 (pos 29) `v/10`, drops `< 0`.
  #[test]
  fn camera_type_auto_rotate_self_timer2() {
    let mut words = [0i16; 30];
    words[26] = 250; // CameraType → "Compact"
    words[27] = 2; // AutoRotate → "Rotate 180"
    words[29] = 20; // SelfTimer2 → 2.0
    let data = blob(&words);
    let (typed, em) = parse(&data, ByteOrder::Little, true, None, None);
    assert_eq!(
      find(&em, "CameraType"),
      Some(TagValue::Str("Compact".into()))
    );
    assert_eq!(
      find(&em, "AutoRotate"),
      Some(TagValue::Str("Rotate 180".into()))
    );
    // 20/10 = 2.0 is whole → emitted as I64(2) (Perl prints "2").
    assert_eq!(find(&em, "SelfTimer2"), Some(TagValue::I64(2)));
    assert_eq!(typed.self_timer2(), Some(2.0));

    // AutoRotate RawConv drops negatives (so the -1 "n/a" label is
    // unreachable); SelfTimer2 drops negatives too.
    let mut neg = [0i16; 30];
    neg[27] = -1;
    neg[29] = -5;
    let (_tn, emn) = parse(&blob(&neg), ByteOrder::Little, true, None, None);
    assert_eq!(find(&emn, "AutoRotate"), None);
    assert_eq!(find(&emn, "SelfTimer2"), None);

    // CameraType unknown → "Unknown (7)".
    let mut u = [0i16; 30];
    u[26] = 7;
    let (_tu, emu) = parse(&blob(&u), ByteOrder::Little, true, None, None);
    assert_eq!(
      find(&emu, "CameraType"),
      Some(TagValue::Str("Unknown (7)".into()))
    );
  }
}
