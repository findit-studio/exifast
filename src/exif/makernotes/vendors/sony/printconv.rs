// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Sony-specific PrintConv enum — covers the per-tag PrintConv hashes
//! and inline sprintf expressions in `%Image::ExifTool::Sony::Main`
//! (`Sony.pm:707-2711`), plus the shared Minolta lookups
//! (`%minoltaSceneMode`, `%minoltaTeleconverters`) the Main hash references.
//!
//! Faithful: every variant is a named arm with a `Sony.pm` (or `Minolta.pm`)
//! citation. Bundled-PrintConv values are kept in the exact text bundled
//! emits.

#![deny(clippy::indexing_slicing)]

use super::amount_lens_types;
use super::model_ids;
use crate::exif::ifd::RawValue;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

/// Per-tag PrintConv strategy for the Sony Main IFD table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SonyPrintConv {
  /// No PrintConv — emit raw scalar/array.
  None,
  /// `Quality` 0x0102 (`Sony.pm:770-786`).
  Quality,
  /// `WhiteBalance` 0x0115 (`Sony.pm:836-853`) — PrintHex.
  WhiteBalance,
  /// `MultiBurstMode` 0x1000 (`Sony.pm:880-887`) — `0=>'Off',1=>'On'`.
  OnOff,
  /// `ElectronicFrontCurtainShutter` 0x201a (`Sony.pm:1232-1239`) —
  /// `0=>'Off',1=>'On'`.
  OffOn,
  /// `Contrast`/`Saturation`/`Sharpness`/`Brightness` (`Sony.pm:954-977`)
  /// and `Shadows`/`Highlights`/`Fade`/`SharpnessRange`/`Clarity`
  /// (`Sony.pm:1687-1716`) — `$val > 0 ? "+$val" : $val`.
  PlusOrInt,
  /// `LongExposureNoiseReduction` 0x2008 (`Sony.pm:978-990`) — PrintHex.
  LongExposureNr,
  /// `HighISONoiseReduction` 0x2009 (`Sony.pm:991-1003`).
  HighIsoNr,
  /// `MultiFrameNoiseReduction` 0x200b (`Sony.pm:1032-1041`).
  MultiFrameNr,
  /// `PictureEffect` 0x200e (`Sony.pm:1044-1085`).
  PictureEffect,
  /// `SoftSkinEffect` 0x200f (`Sony.pm:1086-1099`).
  SoftSkinEffect,
  /// `VignettingCorrection`/`LateralChromaticAberration`/
  /// `DistortionCorrectionSetting` (`Sony.pm:1174-1200`) —
  /// `0=>'Off',2=>'Auto',0xffffffff=>'n/a'`.
  OffAutoNa,
  /// `AutoPortraitFramed` 0x2016 (`Sony.pm:1211-1216`) — `0=>'No',1=>'Yes'`.
  NoYes,
  /// `FlashAction` 0x2017 (`Sony.pm:1218-1228`).
  FlashAction,
  /// `FocusMode` 0x201b (`Sony.pm:1240-1255`) — SLT/ILCE int8u mapping.
  FocusMode2,
  /// `AFTracking` 0x2021 (`Sony.pm:1471-1480`).
  AfTracking,
  /// `MultiFrameNREffect` 0x2023 (`Sony.pm:1508-1515`).
  MultiFrameNrEffect,
  /// `VariableLowPassFilter` 0x2028 (`Sony.pm:1545-1556`) — int16u[2]
  /// string-keyed.
  VariableLowPassFilter,
  /// `RAWFileType` 0x2029 (`Sony.pm:1557-1567`).
  RawFileType,
  /// `PrioritySetInAWB` 0x202b (`Sony.pm:1578-1586`).
  PrioritySetInAwb,
  /// `MeteringMode2` 0x202c (`Sony.pm:1587-1599`) — int16u PrintHex.
  MeteringMode2,
  /// `ExposureStandardAdjustment` 0x202d (`Sony.pm:1600-1605`) —
  /// rational64s `$val ? sprintf("%+.1f",$val) : 0`.
  ExposureStandardAdjustment,
  /// `Quality` 0x202e (`Sony.pm:1606-1642`) — int16u[2] string-keyed.
  Quality2,
  /// `JPEG-HEIFSwitch` 0x2039 (`Sony.pm:1728-1736`).
  JpegHeifSwitch,
  /// `StepCropShooting` 0x205c (`Sony.pm:1758-1767`).
  StepCropShooting,
  /// `FileFormat` 0xb000 (`Sony.pm:2119-2148`) — int8u[4] string-keyed.
  FileFormat,
  /// `Rating` 0x2002 (`Sony.pm:949-952`) — int32u (0-5 stars or 4294967295).
  Rating,
  /// `SonyModelID` 0xb001 (`Sony.pm:2149-2270`) — lookup against
  /// `%sonyModelID` ([`model_ids`]).
  ModelId,
  /// Sony Main `LensType` 0xb027 (`Sony.pm:2364-2372`) — lookup against the
  /// A-mount (Minolta-backed) `%sonyLensTypes` ([`amount_lens_types`]), NOT
  /// the E-mount `%sonyLensTypes2` ([`super::lens_types`]). E-mount lenses are
  /// written as `65535` ⇒ `"E-Mount, T-Mount, Other Lens or no lens"`
  /// (`Sony.pm:2368`, `Minolta.pm:545`).
  LensType,
  /// `CreativeStyle` 0xb020 (`Sony.pm:2271-2303`) — string label map with
  /// `OTHER => sub { shift }` passthrough.
  CreativeStyle,
  /// `ColorTemperature` 0xb021 (`Sony.pm:2304-2309`) — `0 => "Auto"`,
  /// `0xffffffff => "n/a"`.
  ColorTemperature,
  /// `Macro` 0xb040 (`Sony.pm:2424-2434`).
  Macro,
  /// `FocusMode` 0xb042 (`Sony.pm:2476-2495`) — older DSC mapping.
  FocusMode,
  /// `FocusMode` 0xb04e (`Sony.pm:2634-2648`) — HX9V-generation mapping.
  FocusMode3,
  /// `AFAreaMode` 0xb043 first branch (`Sony.pm:2496-2515`) — older models.
  AfAreaMode,
  /// `AFIlluminator` 0xb044 (`Sony.pm:2533-2542`).
  AfIlluminator,
  /// `JPEGQuality` 0xb047 (`Sony.pm:2545-2555`).
  JpegQuality,
  /// `FlashLevel` 0xb048 (`Sony.pm:2556-2582`) — int16s mapping.
  FlashLevel,
  /// `ReleaseMode` 0xb049 (`Sony.pm:2583-2595`).
  ReleaseMode,
  /// `SequenceNumber` 0xb04a (`Sony.pm:2596-2606`) — `0=>'Single'`,
  /// `65535=>'n/a'`, `OTHER` passthrough.
  SequenceNumber,
  /// `Anti-Blur` 0xb04b (`Sony.pm:2607-2617`).
  AntiBlur,
  /// `IntelligentAuto` 0xb052 (`Sony.pm:2675-2683`).
  IntelligentAuto,
  /// `ZoneMatching` 0xb024 (`Sony.pm:2322-2330`).
  ZoneMatching,
  /// `DynamicRangeOptimizer` 0xb025 (`Sony.pm:2331-2354`).
  DynamicRangeOptimizer,
  /// `DynamicRangeOptimizer` 0xb04f (`Sony.pm:2649-2659`) — DSC mapping.
  DynamicRangeOptimizer2,
  /// `HighISONoiseReduction2` 0xb050 (`Sony.pm:2660-2673`).
  HighIsoNr2,
  /// `ExposureMode` 0xb041 (`Sony.pm:2435-2475`).
  ExposureMode,
  /// `ImageStabilization` 0xb026 (`Sony.pm:2355-2363`) —
  /// `0=>'Off',1=>'On',0xffffffff=>'n/a'`.
  ImageStabilizationNa,
  /// `WhiteBalance` 0xb054 (`Sony.pm:2685-2710`) — int16u EXIF-aligned.
  WhiteBalance2,
  /// `FullImageSize` 0xb02b / `PreviewImageSize` 0xb02c
  /// (`Sony.pm:2405-2422`). Values are stored **height-first**;
  /// `ValueConv => 'join(" ", reverse split(" ", $val))'` reverses them to
  /// `"width height"`, and `PrintConv => '$val =~ tr/ /x/; $val'` then turns
  /// the spaces into `x` → `"widthxheight"`. So `-n` (ValueConv) emits the
  /// reversed `"width height"` and `-j` (PrintConv) emits `"widthxheight"`
  /// (no spaces).
  ImageSizeHxV,
  /// `Teleconverter` 0x0105 (`Sony.pm:792-797`) — PrintHex
  /// `%Minolta::minoltaTeleconverters` (`Minolta.pm:555-567`).
  Teleconverter,
  /// `SceneMode` 0xb023 (`Sony.pm:2316-2321`) — `%minoltaSceneMode`
  /// (`Minolta.pm:618-644`).
  SceneMode,
  /// `HDR` 0x200a (`Sony.pm:1004-1031`). `Format => 'int16u'`, `Count => 2`,
  /// `PrintHex => 1`, positional `PrintConv => [{…},{…}]`: position 0 (HDR
  /// setting, A550 hash) and position 1 (HDR result, A580 hash) use distinct
  /// hashes, joined with `"; "` (`ExifTool.pm:3697`); each unmatched element
  /// renders the PrintHex `Unknown (0xNN)` fallback. `-n` (no ValueConv) →
  /// the space-joined int16u pair.
  Hdr,
  /// `WBShiftAB_GM_Precise` 0x2026 (`Sony.pm:1521-1530`). int32s[2];
  /// `PrintConv => 'my @v=split(" ",$val); $_/=1000 foreach @v;
  /// sprintf("%.2f %.2f",$v[0],$v[1])'` — divide each by 1000 and format to
  /// 2 decimals. No ValueConv, so `-n` is the raw space-joined int pair.
  WbShiftAbGmPrecise,
  /// `PixelShiftInfo` 0x202f (`Sony.pm:1643-1677`). `Writable => 'undef'`
  /// (6 bytes); `RawConv` decodes GroupID (int32u) + ShotNumber into
  /// `"GGGGGGGG b c 0xN"` (always, incl. `-n`); `PrintConv => { '00000000
  /// 0 0 0x0' => 'n/a', OTHER => sub }` rewrites the decoded string into
  /// `"Group …, Shot b/c (0xN)"` (and `"Shot 0/N" → "Composed N-shot"`).
  PixelShiftInfo,
  /// `FocusFrameSize` 0x2037 (`Sony.pm:1717-1727`). `Format => 'int16u'`,
  /// `Count => 3`; `PrintConv => 'my @a = split " ", $val; return $a[2] ?
  /// sprintf("%3dx%3d", $a[0], $a[1]) : "n/a"'` — `"WxH"` (each field width
  /// 3, space-padded) when the 3rd value is truthy, else `"n/a"`. `-n` → the
  /// space-joined int16u triple.
  FocusFrameSize,
  /// `ColorMode` 0xb029 (`Sony.pm:2385-2390`) — int32u; `PrintConv =>
  /// \%Minolta::sonyColorMode` (`Minolta.pm`).
  ColorMode,
  /// `SerialNumber` 0x2031 (`Sony.pm:1678-1685`). `Writable => 'string'`;
  /// `ValueConv => '$val=~s/(\d{2})(\d{2})(\d{2})(\d{2})/$4$3$2$1/;
  /// $val=~s/^0//; $val'` (reverse the four 2-digit groups of an 8-digit
  /// string, then strip a single leading zero); `PrintConv =>
  /// 'sprintf("%.8d",$val)'` (zero-pad the ValueConv result back to 8
  /// digits).
  SerialNumber2031,
  /// `AFAreaModeSetting` 0x201c (`Sony.pm:1256-1306`) — conditional ARRAY,
  /// per-`$$self{Model}` `int8u` PrintConv hash. Three branches:
  /// SLT/HV (`Sony.pm:1265-1273`), NEX/ILCE/ILME/ZV/some-DSC
  /// (`Sony.pm:1276-1290`), ILCA (`Sony.pm:1293-1304`). The NEX/ILCE branch
  /// and the ILCA branch each set a DataMember (`AFAreaILCE`/`AFAreaILCA`)
  /// that 0x201e reads — captured in [`super::body`]/the walk before
  /// 0x201e is dispatched. No matching branch ⇒ no conv (raw `int8u`).
  AfAreaModeSetting,
  /// `AFPointSelected` 0x201e (`Sony.pm:1321-1421`) — conditional ARRAY,
  /// per-`$$self{Model}`/`AFAreaILCx`-DataMember `int8u` PrintConv. Six
  /// branches; some use `%afPoints79`/`%afPoints99M2` (`Sony.pm:615-664`)
  /// and a `ValueConv => '$val - 1'` (the ILCA-68/77M2 branch) or an
  /// `OTHER => sub { shift }` passthrough (the ILCA-99M2 branch). No
  /// matching branch ⇒ no conv (raw `int8u`).
  AfPointSelected,
  /// `AFPointsUsed` 0x2020 (`Sony.pm:1426-1468`) — conditional ARRAY,
  /// per-`$$self{Model}` BITMASK (DecodeBits, `BitsPerWord => 8`). Branch 1
  /// (non-ILCA/DSC/ZV, `Sony.pm:1428-1456`) uses a 19-entry bit table;
  /// branch 2 (ILCA-68/77M2, `Sony.pm:1458-1467`) uses `%afPoints79` as the
  /// bit table. No matching branch ⇒ no conv (raw `int8u` list).
  AfPointsUsed,
  /// `FocalPlaneAFPointsUsed` 0x2022 (`Sony.pm:1487-1507`) — conditional
  /// ARRAY, per-`$$self{Model}` BITMASK with an EMPTY `{ }` lookup
  /// (`Sony.pm:1495,1505`): DecodeBits with no labels emits `[n]` per set
  /// bit (and `(none)` when no bit is set). Two branches:
  /// ILCE-5100/6000/7M2 and ILCE-7RM2. No matching branch ⇒ no conv.
  FocalPlaneAfPointsUsed,
  /// `LensSpec` 0xb02a (`Sony.pm:2391-2404`). `Format => 'undef'`,
  /// `Count => 8`. `ValueConv => \&ConvLensSpec` (`Sony.pm:11138-11146`)
  /// unpacks the 8 bytes into a LensInfo-like `"flags1 sf lf sa la flags2"`
  /// string; `PrintConv => \&PrintLensSpec` (`Sony.pm:11165-11213`) renders
  /// `"DT 18-55mm F3.5-5.6 SAM"`-style strings using the `@lensFeatures`
  /// bit table. `-n` is the ValueConv string, `-j` is PrintLensSpec.
  LensSpec,
}

impl SonyPrintConv {
  /// Apply the PrintConv to a raw value, threading the body `$$self{Model}`
  /// (from IFD0) and the `AFAreaILCx` DataMember (set by 0x201c, read by
  /// 0x201e) needed for the conditional-ARRAY AF tags.
  ///
  /// `model` is `$$self{Model}`; `af_area` is the `AFAreaILCE`/`AFAreaILCA`
  /// DataMember value captured from 0x201c earlier in the same IFD walk
  /// (`None` if 0x201c was absent or didn't set it). Non-model-conditional
  /// convs ignore both and delegate to [`apply`](Self::apply).
  ///
  /// Returns `None` for the four conditional-ARRAY AF tags
  /// (`0x201c`/`0x201e`/`0x2020`/`0x2022`) when NO `Condition` branch matches
  /// this body. Each of these rows is a fully-conditional `[ {Condition=>…},
  /// … ]` with no unconditional catch-all branch, so ExifTool's `GetTagInfo`
  /// finds no tag info and the entry is ABSENT from default output
  /// (`Sony.pm:1256-1306,1321-1421,1426-1468,1487-1507`). The caller
  /// ([`super::parse_in_tiff`]) drops the emission on `None`. Every other
  /// variant (and a matched AF branch) returns `Some(value)`.
  #[must_use]
  pub fn apply_with_context(
    self,
    raw: &RawValue,
    print_conv: bool,
    model: Option<&str>,
    af_area: Option<i64>,
  ) -> Option<TagValue> {
    match self {
      SonyPrintConv::AfAreaModeSetting => af_area_mode_setting(raw, print_conv, model),
      SonyPrintConv::AfPointSelected => af_point_selected(raw, print_conv, model, af_area),
      SonyPrintConv::AfPointsUsed => af_points_used(raw, print_conv, model),
      SonyPrintConv::FocalPlaneAfPointsUsed => focal_plane_af_points_used(raw, print_conv, model),
      _ => Some(self.apply(raw, print_conv)),
    }
  }

  /// Whether `0x201c`'s `RawConv` sets the `AFAreaILCE`/`AFAreaILCA`
  /// DataMember for this `$$self{Model}` (`Sony.pm:1278-1279,1295-1296`).
  /// The `RawConv => '$$self{AFAreaILCx} = $val'` is present ONLY on the
  /// NEX/ILCE branch (branch 2, `Sony.pm:1276`) and the ILCA branch (branch
  /// 3, `Sony.pm:1293`); the SLT/HV branch (branch 1) and a no-match body
  /// set nothing.
  #[must_use]
  pub fn af_area_sets_data_member(model: Option<&str>) -> bool {
    let m = model.unwrap_or("");
    // SLT/HV (branch 1) takes precedence in the Condition chain and has no
    // RawConv, so it does NOT set a DataMember.
    if model_is_slt_hv(m) {
      return false;
    }
    model_is_nex_ilce_set(m) || model_is_ilca(m)
  }

  /// Apply the PrintConv to a raw value.
  #[must_use]
  pub fn apply(self, raw: &RawValue, print_conv: bool) -> TagValue {
    match self {
      SonyPrintConv::None => raw_to_tag_value(raw),
      SonyPrintConv::Quality => simple_label(raw, print_conv, |n| match n {
        0 => Some("RAW"),
        1 => Some("Super Fine"),
        2 => Some("Fine"),
        3 => Some("Standard"),
        4 => Some("Economy"),
        5 => Some("Extra Fine"),
        6 => Some("RAW + JPEG/HEIF"),
        7 => Some("Compressed RAW"),
        8 => Some("Compressed RAW + JPEG"),
        9 => Some("Light"),
        0xffff_ffff => Some("n/a"),
        _ => None,
      }),
      SonyPrintConv::WhiteBalance => hex_label(raw, print_conv, |n| match n {
        0x00 => Some("Auto"),
        0x01 => Some("Color Temperature/Color Filter"),
        0x10 => Some("Daylight"),
        0x20 => Some("Cloudy"),
        0x30 => Some("Shade"),
        0x40 => Some("Tungsten"),
        0x50 => Some("Flash"),
        0x60 => Some("Fluorescent"),
        0x70 => Some("Custom"),
        0x80 => Some("Underwater"),
        _ => None,
      }),
      SonyPrintConv::OnOff => simple_label(raw, print_conv, |n| match n {
        0 => Some("Off"),
        1 => Some("On"),
        _ => None,
      }),
      SonyPrintConv::OffOn => simple_label(raw, print_conv, |n| match n {
        0 => Some("Off"),
        1 => Some("On"),
        _ => None,
      }),
      SonyPrintConv::PlusOrInt => {
        let Some(n) = first_i64(raw) else {
          return raw_to_tag_value(raw);
        };
        if print_conv {
          let s = if n > 0 {
            std::format!("+{n}")
          } else {
            std::format!("{n}")
          };
          TagValue::Str(s.into())
        } else {
          TagValue::I64(n)
        }
      }
      SonyPrintConv::LongExposureNr => hex_label(raw, print_conv, |n| match n {
        0 => Some("Off"),
        1 => Some("On (unused)"),
        0x10001 => Some("On (dark subtracted)"),
        0xffff_0000 => Some("Off (65535)"),
        0xffff_0001 => Some("On (65535)"),
        0xffff_ffff => Some("n/a"),
        _ => None,
      }),
      SonyPrintConv::HighIsoNr => simple_label(raw, print_conv, |n| match n {
        0 => Some("Off"),
        1 => Some("Low"),
        2 => Some("Normal"),
        3 => Some("High"),
        256 => Some("Auto"),
        65535 => Some("n/a"),
        _ => None,
      }),
      SonyPrintConv::MultiFrameNr => simple_label(raw, print_conv, |n| match n {
        0 => Some("Off"),
        1 => Some("On"),
        255 => Some("n/a"),
        _ => None,
      }),
      SonyPrintConv::PictureEffect => simple_label(raw, print_conv, |n| match n {
        0 => Some("Off"),
        1 => Some("Toy Camera"),
        2 => Some("Pop Color"),
        3 => Some("Posterization"),
        4 => Some("Posterization B/W"),
        5 => Some("Retro Photo"),
        6 => Some("Soft High Key"),
        7 => Some("Partial Color (red)"),
        8 => Some("Partial Color (green)"),
        9 => Some("Partial Color (blue)"),
        10 => Some("Partial Color (yellow)"),
        13 => Some("High Contrast Monochrome"),
        16 => Some("Toy Camera (normal)"),
        17 => Some("Toy Camera (cool)"),
        18 => Some("Toy Camera (warm)"),
        19 => Some("Toy Camera (green)"),
        20 => Some("Toy Camera (magenta)"),
        32 => Some("Soft Focus (low)"),
        33 => Some("Soft Focus"),
        34 => Some("Soft Focus (high)"),
        48 => Some("Miniature (auto)"),
        49 => Some("Miniature (top)"),
        50 => Some("Miniature (middle horizontal)"),
        51 => Some("Miniature (bottom)"),
        52 => Some("Miniature (left)"),
        53 => Some("Miniature (middle vertical)"),
        54 => Some("Miniature (right)"),
        64 => Some("HDR Painting (low)"),
        65 => Some("HDR Painting"),
        66 => Some("HDR Painting (high)"),
        80 => Some("Rich-tone Monochrome"),
        97 => Some("Water Color"),
        98 => Some("Water Color 2"),
        112 => Some("Illustration (low)"),
        113 => Some("Illustration"),
        114 => Some("Illustration (high)"),
        _ => None,
      }),
      SonyPrintConv::SoftSkinEffect => simple_label(raw, print_conv, |n| match n {
        0 => Some("Off"),
        1 => Some("Low"),
        2 => Some("Mid"),
        3 => Some("High"),
        0xffff_ffff => Some("n/a"),
        _ => None,
      }),
      SonyPrintConv::OffAutoNa => simple_label(raw, print_conv, |n| match n {
        0 => Some("Off"),
        2 => Some("Auto"),
        0xffff_ffff => Some("n/a"),
        _ => None,
      }),
      SonyPrintConv::NoYes => simple_label(raw, print_conv, |n| match n {
        0 => Some("No"),
        1 => Some("Yes"),
        _ => None,
      }),
      SonyPrintConv::FlashAction => simple_label(raw, print_conv, |n| match n {
        0 => Some("Did not fire"),
        1 => Some("Flash Fired"),
        2 => Some("External Flash Fired"),
        3 => Some("Wireless Controlled Flash Fired"),
        _ => None,
      }),
      SonyPrintConv::FocusMode2 => simple_label(raw, print_conv, |n| match n {
        0 => Some("Manual"),
        2 => Some("AF-S"),
        3 => Some("AF-C"),
        4 => Some("AF-A"),
        6 => Some("DMF"),
        7 => Some("AF-D"),
        _ => None,
      }),
      SonyPrintConv::AfTracking => simple_label(raw, print_conv, |n| match n {
        0 => Some("Off"),
        1 => Some("Face tracking"),
        2 => Some("Lock On AF"),
        _ => None,
      }),
      SonyPrintConv::MultiFrameNrEffect => simple_label(raw, print_conv, |n| match n {
        0 => Some("Normal"),
        1 => Some("High"),
        _ => None,
      }),
      SonyPrintConv::VariableLowPassFilter => pair_label(raw, print_conv, |a, b| match (a, b) {
        (0, 0) => Some("n/a"),
        (1, 0) => Some("Off"),
        (1, 1) => Some("Standard"),
        (1, 2) => Some("High"),
        (65535, 65535) => Some("n/a"),
        _ => None,
      }),
      SonyPrintConv::RawFileType => simple_label(raw, print_conv, |n| match n {
        0 => Some("Compressed RAW"),
        1 => Some("Uncompressed RAW"),
        2 => Some("Lossless Compressed RAW"),
        3 => Some("Compressed RAW 2"),
        65535 => Some("n/a"),
        _ => None,
      }),
      SonyPrintConv::PrioritySetInAwb => simple_label(raw, print_conv, |n| match n {
        0 => Some("Standard"),
        1 => Some("Ambience"),
        2 => Some("White"),
        _ => None,
      }),
      SonyPrintConv::MeteringMode2 => hex_label(raw, print_conv, |n| match n {
        0x100 => Some("Multi-segment"),
        0x200 => Some("Center-weighted average"),
        0x301 => Some("Spot (Standard)"),
        0x302 => Some("Spot (Large)"),
        0x400 => Some("Average"),
        0x500 => Some("Highlight"),
        _ => None,
      }),
      SonyPrintConv::ExposureStandardAdjustment => {
        // rational64s: `$val ? sprintf("%+.1f",$val) : 0`.
        let Some(v) = first_f64(raw) else {
          return raw_to_tag_value(raw);
        };
        if !print_conv {
          return raw_to_tag_value(raw);
        }
        if v == 0.0 {
          TagValue::I64(0)
        } else {
          TagValue::Str(SmolStr::from(std::format!("{v:+.1}")))
        }
      }
      SonyPrintConv::Quality2 => pair_label(raw, print_conv, quality2_label),
      SonyPrintConv::JpegHeifSwitch => simple_label(raw, print_conv, |n| match n {
        0 => Some("JPEG"),
        1 => Some("HEIF"),
        65535 => Some("n/a"),
        _ => None,
      }),
      SonyPrintConv::StepCropShooting => simple_label(raw, print_conv, |n| match n {
        0 => Some("35mm (Off)"),
        1 => Some("50mm"),
        2 => Some("70mm"),
        _ => None,
      }),
      SonyPrintConv::FileFormat => file_format_label(raw, print_conv),
      SonyPrintConv::Rating => {
        let Some(n) = first_u64(raw) else {
          return raw_to_tag_value(raw);
        };
        if print_conv && n == 0xffff_ffff {
          TagValue::Str("n/a".into())
        } else {
          TagValue::U64(n)
        }
      }
      SonyPrintConv::ModelId => {
        let Some(n) = first_u64(raw) else {
          return raw_to_tag_value(raw);
        };
        if print_conv {
          let id = u16::try_from(n).unwrap_or(0);
          match model_ids::lookup_name(id) {
            Some(name) => TagValue::Str(name),
            None => TagValue::Str(SmolStr::from(std::format!("Unknown ({n})"))),
          }
        } else {
          TagValue::U64(n)
        }
      }
      SonyPrintConv::LensType => {
        let Some(n) = first_u64(raw) else {
          return raw_to_tag_value(raw);
        };
        if print_conv {
          // 0xb027 resolves against the A-mount `%sonyLensTypes`
          // (`Sony.pm:2370`), NOT the E-mount `%sonyLensTypes2`.
          let id = u32::try_from(n).unwrap_or(0);
          match amount_lens_types::lookup_name(id) {
            Some(name) => TagValue::Str(name),
            None => TagValue::Str(SmolStr::from(std::format!("Unknown ({n})"))),
          }
        } else {
          TagValue::U64(n)
        }
      }
      SonyPrintConv::CreativeStyle => {
        // String label map (`Sony.pm:2278-2302`) with `OTHER => sub { shift }`
        // passthrough — Sony writes these as English codes regardless of UI
        // language. Map the known short codes; pass anything else through.
        let s = match raw {
          RawValue::Text(s) => s.as_str(),
          _ => return raw_to_tag_value(raw),
        };
        if !print_conv {
          return TagValue::Str(s.into());
        }
        let label = match s {
          "None" => "None",
          "AdobeRGB" => "Adobe RGB",
          "Real" => "Real",
          "Standard" => "Standard",
          "Vivid" => "Vivid",
          "Portrait" => "Portrait",
          "Landscape" => "Landscape",
          "Sunset" => "Sunset",
          "Nightview" => "Night View/Portrait",
          "BW" => "B&W",
          "Neutral" => "Neutral",
          "Clear" => "Clear",
          "Deep" => "Deep",
          "Light" => "Light",
          "Autumnleaves" => "Autumn Leaves",
          "Sepia" => "Sepia",
          "VV2" => "Vivid 2",
          "FL" => "FL",
          "IN" => "IN",
          "SH" => "SH",
          other => other, // OTHER => sub { shift }
        };
        TagValue::Str(label.into())
      }
      SonyPrintConv::ColorTemperature => {
        // `$val ? ($val==0xffffffff ? "n/a" : $val) : "Auto"`.
        let Some(n) = first_u64(raw) else {
          return raw_to_tag_value(raw);
        };
        if print_conv {
          if n == 0 {
            TagValue::Str("Auto".into())
          } else if n == 0xffff_ffff {
            TagValue::Str("n/a".into())
          } else {
            TagValue::U64(n)
          }
        } else {
          TagValue::U64(n)
        }
      }
      SonyPrintConv::Macro => simple_label(raw, print_conv, |n| match n {
        0 => Some("Off"),
        1 => Some("On"),
        2 => Some("Close Focus"),
        65535 => Some("n/a"),
        _ => None,
      }),
      SonyPrintConv::FocusMode => simple_label(raw, print_conv, |n| match n {
        1 => Some("AF-S"),
        2 => Some("AF-C"),
        4 => Some("Permanent-AF"),
        65535 => Some("n/a"),
        _ => None,
      }),
      SonyPrintConv::FocusMode3 => simple_label(raw, print_conv, |n| match n {
        0 => Some("Manual"),
        2 => Some("AF-S"),
        3 => Some("AF-C"),
        5 => Some("Semi-manual"),
        6 => Some("DMF"),
        _ => None,
      }),
      SonyPrintConv::AfAreaMode => simple_label(raw, print_conv, |n| match n {
        0 => Some("Default"),
        1 => Some("Multi"),
        2 => Some("Center"),
        3 => Some("Spot"),
        4 => Some("Flexible Spot"),
        6 => Some("Touch"),
        14 => Some("Tracking"),
        15 => Some("Face Tracking"),
        65535 => Some("n/a"),
        _ => None,
      }),
      SonyPrintConv::AfIlluminator => simple_label(raw, print_conv, |n| match n {
        0 => Some("Off"),
        1 => Some("Auto"),
        65535 => Some("n/a"),
        _ => None,
      }),
      SonyPrintConv::JpegQuality => simple_label(raw, print_conv, |n| match n {
        0 => Some("Standard"),
        1 => Some("Fine"),
        2 => Some("Extra Fine"),
        65535 => Some("n/a"),
        _ => None,
      }),
      SonyPrintConv::FlashLevel => simple_label(raw, print_conv, |n| match n {
        -32768 => Some("Low"),
        -9 => Some("-9/3"),
        -8 => Some("-8/3"),
        -7 => Some("-7/3"),
        -6 => Some("-6/3"),
        -5 => Some("-5/3"),
        -4 => Some("-4/3"),
        -3 => Some("-3/3"),
        -2 => Some("-2/3"),
        -1 => Some("-1/3"),
        0 => Some("Normal"),
        1 => Some("+1/3"),
        2 => Some("+2/3"),
        3 => Some("+3/3"),
        4 => Some("+4/3"),
        5 => Some("+5/3"),
        6 => Some("+6/3"),
        9 => Some("+9/3"),
        128 => Some("n/a"),
        32767 => Some("High"),
        _ => None,
      }),
      SonyPrintConv::ReleaseMode => simple_label(raw, print_conv, |n| match n {
        0 => Some("Normal"),
        2 => Some("Continuous"),
        5 => Some("Exposure Bracketing"),
        6 => Some("White Balance Bracketing"),
        8 => Some("DRO Bracketing"),
        65535 => Some("n/a"),
        _ => None,
      }),
      SonyPrintConv::SequenceNumber => {
        // `0 => 'Single'`, `65535 => 'n/a'`, `OTHER => sub { shift }`.
        let Some(n) = first_i64(raw) else {
          return raw_to_tag_value(raw);
        };
        if !print_conv {
          return TagValue::I64(n);
        }
        match n {
          0 => TagValue::Str("Single".into()),
          65535 => TagValue::Str("n/a".into()),
          other => TagValue::Str(SmolStr::from(std::format!("{other}"))),
        }
      }
      SonyPrintConv::AntiBlur => simple_label(raw, print_conv, |n| match n {
        0 => Some("Off"),
        1 => Some("On (Continuous)"),
        2 => Some("On (Shooting)"),
        65535 => Some("n/a"),
        _ => None,
      }),
      SonyPrintConv::IntelligentAuto => simple_label(raw, print_conv, |n| match n {
        0 => Some("Off"),
        1 => Some("On"),
        2 => Some("Advanced"),
        _ => None,
      }),
      SonyPrintConv::ZoneMatching => simple_label(raw, print_conv, |n| match n {
        0 => Some("ISO Setting Used"),
        1 => Some("High Key"),
        2 => Some("Low Key"),
        _ => None,
      }),
      SonyPrintConv::DynamicRangeOptimizer => simple_label(raw, print_conv, |n| match n {
        0 => Some("Off"),
        1 => Some("Standard"),
        2 => Some("Advanced Auto"),
        3 => Some("Auto"),
        8 => Some("Advanced Lv1"),
        9 => Some("Advanced Lv2"),
        10 => Some("Advanced Lv3"),
        11 => Some("Advanced Lv4"),
        12 => Some("Advanced Lv5"),
        16 => Some("Lv1"),
        17 => Some("Lv2"),
        18 => Some("Lv3"),
        19 => Some("Lv4"),
        20 => Some("Lv5"),
        21 => Some("Lv6"),
        22 => Some("Lv7"),
        23 => Some("Lv8"),
        _ => None,
      }),
      SonyPrintConv::DynamicRangeOptimizer2 => simple_label(raw, print_conv, |n| match n {
        0 => Some("Off"),
        1 => Some("Standard"),
        2 => Some("Plus"),
        _ => None,
      }),
      SonyPrintConv::HighIsoNr2 => simple_label(raw, print_conv, |n| match n {
        0 => Some("Normal"),
        1 => Some("High"),
        2 => Some("Low"),
        3 => Some("Off"),
        65535 => Some("n/a"),
        _ => None,
      }),
      SonyPrintConv::ExposureMode => simple_label(raw, print_conv, |n| match n {
        0 => Some("Program AE"),
        1 => Some("Portrait"),
        2 => Some("Beach"),
        3 => Some("Sports"),
        4 => Some("Snow"),
        5 => Some("Landscape"),
        6 => Some("Auto"),
        7 => Some("Aperture-priority AE"),
        8 => Some("Shutter speed priority AE"),
        9 => Some("Night Scene / Twilight"),
        10 => Some("Hi-Speed Shutter"),
        11 => Some("Twilight Portrait"),
        12 => Some("Soft Snap/Portrait"),
        13 => Some("Fireworks"),
        14 => Some("Smile Shutter"),
        15 => Some("Manual"),
        18 => Some("High Sensitivity"),
        19 => Some("Macro"),
        20 => Some("Advanced Sports Shooting"),
        29 => Some("Underwater"),
        33 => Some("Food"),
        34 => Some("Sweep Panorama"),
        35 => Some("Handheld Night Shot"),
        36 => Some("Anti Motion Blur"),
        37 => Some("Pet"),
        38 => Some("Backlight Correction HDR"),
        39 => Some("Superior Auto"),
        40 => Some("Background Defocus"),
        41 => Some("Soft Skin"),
        42 => Some("3D Image"),
        65535 => Some("n/a"),
        _ => None,
      }),
      SonyPrintConv::ImageStabilizationNa => simple_label(raw, print_conv, |n| match n {
        0 => Some("Off"),
        1 => Some("On"),
        0xffff_ffff => Some("n/a"),
        _ => None,
      }),
      SonyPrintConv::WhiteBalance2 => simple_label(raw, print_conv, |n| match n {
        0 => Some("Auto"),
        4 => Some("Custom"),
        5 => Some("Daylight"),
        6 => Some("Cloudy"),
        7 => Some("Cool White Fluorescent"),
        8 => Some("Day White Fluorescent"),
        9 => Some("Daylight Fluorescent"),
        10 => Some("Incandescent2"),
        11 => Some("Warm White Fluorescent"),
        14 => Some("Incandescent"),
        15 => Some("Flash"),
        17 => Some("Underwater 1 (Blue Water)"),
        18 => Some("Underwater 2 (Green Water)"),
        19 => Some("Underwater Auto"),
        _ => None,
      }),
      SonyPrintConv::ImageSizeHxV => image_size_hxv(raw, print_conv),
      SonyPrintConv::Teleconverter => hex_label(raw, print_conv, |n| match n {
        0x00 => Some("None"),
        0x04 => Some("Minolta/Sony AF 1.4x APO (D) (0x04)"),
        0x05 => Some("Minolta/Sony AF 2x APO (D) (0x05)"),
        0x48 => Some("Minolta/Sony AF 2x APO (D)"),
        0x50 => Some("Minolta AF 2x APO II"),
        0x60 => Some("Minolta AF 2x APO"),
        0x88 => Some("Minolta/Sony AF 1.4x APO (D)"),
        0x90 => Some("Minolta AF 1.4x APO II"),
        0xa0 => Some("Minolta AF 1.4x APO"),
        _ => None,
      }),
      SonyPrintConv::SerialNumber2031 => serial_number_2031(raw, print_conv),
      // The four conditional-ARRAY AF tags need `$$self{Model}` (and 0x201e
      // also the `AFAreaILCx` DataMember) — without that context no
      // `Condition` branch can be selected. ExifTool then SUPPRESSES the tag
      // (no catch-all branch ⇒ `GetTagInfo` finds nothing); the real dispatch
      // is `apply_with_context`, which signals that as `None`. This
      // context-free `apply` cannot drop a tag (it returns `TagValue`), so it
      // falls back to the raw value — but `parse_in_tiff` always routes these
      // four through `apply_with_context`, so the suppression IS observed.
      SonyPrintConv::AfAreaModeSetting => {
        af_area_mode_setting(raw, print_conv, None).unwrap_or_else(|| raw_to_tag_value(raw))
      }
      SonyPrintConv::AfPointSelected => {
        af_point_selected(raw, print_conv, None, None).unwrap_or_else(|| raw_to_tag_value(raw))
      }
      SonyPrintConv::AfPointsUsed => {
        af_points_used(raw, print_conv, None).unwrap_or_else(|| raw_to_tag_value(raw))
      }
      SonyPrintConv::FocalPlaneAfPointsUsed => {
        focal_plane_af_points_used(raw, print_conv, None).unwrap_or_else(|| raw_to_tag_value(raw))
      }
      SonyPrintConv::LensSpec => lens_spec(raw, print_conv),
      SonyPrintConv::Hdr => hdr(raw, print_conv),
      SonyPrintConv::WbShiftAbGmPrecise => wb_shift_ab_gm_precise(raw, print_conv),
      SonyPrintConv::PixelShiftInfo => pixel_shift_info(raw, print_conv),
      SonyPrintConv::FocusFrameSize => focus_frame_size(raw, print_conv),
      SonyPrintConv::ColorMode => simple_label(raw, print_conv, color_mode_label),
      SonyPrintConv::SceneMode => simple_label(raw, print_conv, |n| match n {
        0 => Some("Standard"),
        1 => Some("Portrait"),
        2 => Some("Text"),
        3 => Some("Night Scene"),
        4 => Some("Sunset"),
        5 => Some("Sports"),
        6 => Some("Landscape"),
        7 => Some("Night Portrait"),
        8 => Some("Macro"),
        9 => Some("Super Macro"),
        16 => Some("Auto"),
        17 => Some("Night View/Portrait"),
        18 => Some("Sweep Panorama"),
        19 => Some("Handheld Night Shot"),
        20 => Some("Anti Motion Blur"),
        21 => Some("Cont. Priority AE"),
        22 => Some("Auto+"),
        23 => Some("3D Sweep Panorama"),
        24 => Some("Superior Auto"),
        25 => Some("High Sensitivity"),
        26 => Some("Fireworks"),
        27 => Some("Food"),
        28 => Some("Pet"),
        33 => Some("HDR"),
        0xffff => Some("n/a"),
        _ => None,
      }),
    }
  }
}

/// `0x202e Quality` int16u[2] string-keyed lookup (`Sony.pm:1610-1641`).
fn quality2_label(a: i64, b: i64) -> Option<&'static str> {
  match (a, b) {
    (0, 0) => Some("n/a"),
    (0, 1) => Some("Standard"),
    (0, 2) => Some("Fine"),
    (0, 3) => Some("Extra Fine"),
    (0, 4) => Some("Light"),
    (1, 0) => Some("RAW"),
    (1, 1) => Some("RAW + Standard"),
    (1, 2) => Some("RAW + Fine"),
    (1, 3) => Some("RAW + Extra Fine"),
    (1, 4) => Some("RAW + Light"),
    (2, 0) => Some("S-size RAW"),
    (2, 1) => Some("S-size RAW + Standard"),
    (2, 2) => Some("S-size RAW + Fine"),
    (2, 3) => Some("S-size RAW + Extra Fine"),
    (2, 4) => Some("S-size RAW + Light"),
    (3, 0) => Some("M-size RAW"),
    (3, 1) => Some("M-size RAW + Standard"),
    (3, 2) => Some("M-size RAW + Fine"),
    (3, 3) => Some("M-size RAW + Extra Fine"),
    (3, 4) => Some("M-size RAW + Light"),
    (4, 0) => Some("Compressed RAW"),
    (4, 1) => Some("Compressed RAW + Standard"),
    (4, 2) => Some("Compressed RAW + Fine"),
    (4, 3) => Some("Compressed RAW + Extra Fine"),
    (4, 4) => Some("Compressed RAW + Light"),
    (5, 0) => Some("Compressed (HQ) RAW"),
    (5, 1) => Some("Compressed (HQ) RAW + Standard"),
    (5, 2) => Some("Compressed (HQ) RAW + Fine"),
    (5, 3) => Some("Compressed (HQ) RAW + Extra Fine"),
    (5, 4) => Some("Compressed (HQ) RAW + Light"),
    _ => None,
  }
}

/// `0xb000 FileFormat` int8u[4] string-keyed lookup (`Sony.pm:2129-2147`).
/// The key is the space-joined decimal of the 4 bytes (e.g. `"0 0 0 2"`).
fn file_format_label(raw: &RawValue, print_conv: bool) -> TagValue {
  let key = match raw {
    RawValue::U64(v) => v
      .iter()
      .map(std::string::ToString::to_string)
      .collect::<Vec<_>>()
      .join(" "),
    RawValue::I64(v) => v
      .iter()
      .map(std::string::ToString::to_string)
      .collect::<Vec<_>>()
      .join(" "),
    _ => return raw_to_tag_value(raw),
  };
  if !print_conv {
    return TagValue::Str(key.into());
  }
  let label = match key.as_str() {
    "0 0 0 2" => "JPEG",
    "1 0 0 0" => "SR2",
    "2 0 0 0" => "ARW 1.0",
    "3 0 0 0" => "ARW 2.0",
    "3 1 0 0" => "ARW 2.1",
    "3 2 0 0" => "ARW 2.2",
    "3 3 0 0" => "ARW 2.3",
    "3 3 1 0" => "ARW 2.3.1",
    "3 3 2 0" => "ARW 2.3.2",
    "3 3 3 0" => "ARW 2.3.3",
    "3 3 5 0" => "ARW 2.3.5",
    "4 0 0 0" => "ARW 4.0",
    "4 0 1 0" => "ARW 4.0.1",
    "5 0 0 0" => "ARW 5.0",
    "5 0 1 0" => "ARW 5.0.1",
    "6 0 0 0" => "ARW 6.0",
    _ => return TagValue::Str(SmolStr::from(std::format!("Unknown ({key})"))),
  };
  TagValue::Str(label.into())
}

/// `0x2031 SerialNumber` (`Sony.pm:1681-1683`).
///
/// `ValueConv => '$val=~s/(\d{2})(\d{2})(\d{2})(\d{2})/$4$3$2$1/; $val=~s/^0//;
/// $val'` — reverse the four 2-digit groups of the FIRST run of 8 digits in
/// the raw string, then strip a single leading `0`. The `-n` output is this
/// ValueConv string. `PrintConv => 'sprintf("%.8d",$val)'` zero-pads the
/// (numeric) ValueConv result back to 8 digits for the `-j` output.
fn serial_number_2031(raw: &RawValue, print_conv: bool) -> TagValue {
  // Source `$val` is the raw `string`-tag text (NUL-trimmed, as ExifTool
  // stores the string value).
  let src: String = match raw {
    RawValue::Text(s) => s.as_str().to_string(),
    RawValue::Bytes(b) => {
      let end = b.iter().position(|&x| x == 0).unwrap_or(b.len());
      // `end <= b.len()` by construction, so `.get(..end)` is `Some` — the
      // checked slice is byte-identical to `&b[..end]`.
      b.get(..end)
        .and_then(|s| core::str::from_utf8(s).ok())
        .unwrap_or("")
        .to_string()
    }
    _ => return raw_to_tag_value(raw),
  };
  // `s/(\d{2})(\d{2})(\d{2})(\d{2})/$4$3$2$1/` — leftmost run of EXACTLY 8
  // consecutive ASCII digits, pairs reversed in place. Perl's `\d{2}{4}`
  // matches 8 digits starting at the first position where 8 digits run; we
  // scan for the first index with 8 digit bytes.
  let bytes = src.as_bytes();
  let mut value = src.clone();
  if bytes.len() >= 8 {
    // `i` ranges over `0..=bytes.len()-8`, so `i + 8 <= bytes.len()` and
    // `.get(i..i+8)` is always `Some` — byte-identical to `bytes[i..i+8]`.
    if let Some(start) = (0..=bytes.len() - 8).find(|&i| {
      bytes
        .get(i..i + 8)
        .is_some_and(|w| w.iter().all(u8::is_ascii_digit))
    }) {
      let d = &src[start..start + 8];
      // $4$3$2$1 — swap the four 2-char groups.
      let reordered = std::format!("{}{}{}{}", &d[6..8], &d[4..6], &d[2..4], &d[0..2]);
      value = std::format!("{}{}{}", &src[..start], reordered, &src[start + 8..]);
    }
  }
  // `s/^0//` — strip a single leading zero.
  let value = value.strip_prefix('0').map_or(value.as_str(), |v| v);
  if !print_conv {
    return TagValue::Str(SmolStr::from(value));
  }
  // `sprintf("%.8d",$val)` — parse the ValueConv string as an integer and
  // zero-pad to a minimum field width of 8. ExifTool's Perl coerces the
  // string to a number (non-numeric → 0); replicate with a parse fallback.
  let n: i64 = value.parse().unwrap_or(0);
  TagValue::Str(SmolStr::from(std::format!("{n:08}")))
}

// ===========================================================================
// Conditional-ARRAY AF tags (0x201c / 0x201e / 0x2020 / 0x2022)
//
// These rows are `0xNN => [ {Condition=>…,PrintConv=>…}, … ]` in
// `%Sony::Main`: ExifTool walks the branches in order and applies the FIRST
// whose `Condition` (a `$$self{Model}` / `$$self{AFAreaILCx}` predicate)
// holds. No matching branch ⇒ the tag has NO PrintConv there ⇒ the raw value
// renders (DecodeBits/lookup never run). The matchers below port each Perl
// regex byte-for-byte (no regex dependency — mirrors the Canon/Panasonic
// `model_matches_*` hand-rolled style).
// ===========================================================================

/// `$$self{Model} =~ /^(SLT-|HV)/` (`Sony.pm:1265,1328`).
fn model_is_slt_hv(model: &str) -> bool {
  model.starts_with("SLT-") || model.starts_with("HV")
}

/// The DSC bodies that, from 2018, use the NEX/ILCE AFAreaMode hashes:
/// `RX10M4|RX100M6|RX100M7|RX100M5A|HX95|HX99|RX0M2|RX1RM3` (`Sony.pm:1276`).
/// Matched as `^DSC-(…)` (a prefix match — the alternation is unanchored at
/// its tail, so e.g. `DSC-RX100M6xx` would match, mirroring the Perl regex).
fn model_dsc_new(model: &str) -> bool {
  let Some(rest) = model.strip_prefix("DSC-") else {
    return false;
  };
  const TAILS: &[&str] = &[
    "RX10M4", "RX100M6", "RX100M7", "RX100M5A", "HX95", "HX99", "RX0M2", "RX1RM3",
  ];
  TAILS.iter().any(|t| rest.starts_with(t))
}

/// 0x201c branch 2 / 0x201d / 0x201e branch-1-clause-2 Model set:
/// `^(NEX-|ILCE-|ILME-|ZV-|DSC-(RX10M4|…|RX1RM3))` (`Sony.pm:1276,1313`).
fn model_is_nex_ilce_set(model: &str) -> bool {
  model.starts_with("NEX-")
    || model.starts_with("ILCE-")
    || model.starts_with("ILME-")
    || model.starts_with("ZV-")
    || model_dsc_new(model)
}

/// `$$self{Model} =~ /^ILCA-/` (`Sony.pm:1293`).
fn model_is_ilca(model: &str) -> bool {
  model.starts_with("ILCA-")
}

// ===========================================================================
// Single-HASH `Condition` suppression (the same faithfulness class as the
// four conditional-ARRAY AF tags above, but for `0xNN => { Condition=>…, … }`
// rows). ExifTool's `GetTagInfo` evaluates the single `Condition`; if it does
// NOT hold, no tag info is returned and the entry is ABSENT from default
// output. The conditional-ARRAY rows fold the Condition INTO the per-branch
// PrintConv selection (handled in `apply_with_context`); these single-HASH
// rows keep the Condition SEPARATE from the conv, so the predicate below
// gates the emission independently — `super::parse_in_tiff` skips the
// emission when it returns `false`.
//
// Only rows whose `Condition` can FAIL for a real body are listed: a
// `$$self{Model}` regex (matched against the threaded IFD0 Model) or a
// `$format` test (matched against the entry's on-disk TIFF format name). The
// `$$self{MetaVersion}`/`$$self{TagB042}` rows (0xb042/0xb043/0xb04e) gate on
// DataMembers that only the DEFERRED `ShotInfo` (0x3000) sub-table sets, so
// they are documented deferrals in the Condition oracle, not gated here.
// ===========================================================================

/// Every `%Sony::Main` tag id whose `Condition`-driven suppression the parse
/// path models — i.e. the "condition-aware" set the
/// `tests/sony_main_condition.rs` oracle requires. Two mechanisms feed it:
///
/// - the four conditional-ARRAY AF tags (0x201c/0x201e/0x2020/0x2022), whose
///   per-branch `Condition` is folded into the conv selection in
///   [`SonyPrintConv::apply_with_context`] (a no-branch-match returns `None`
///   ⇒ the caller drops the emission), and
/// - the single-HASH `Condition` rows handled by
///   [`single_hash_condition_holds`] (0x201b/0x201d/0x2021/0x205c/0xb050 and
///   the `$format`-gated 0x1000/0x1001/0x1002).
///
/// The oracle asserts this set covers every bundled Conditioned LEAF row that
/// can be suppressed (catch-all ARRAYs never suppress; SubDirectory rows are
/// deferred), so a future faithful bump can't silently regress one back to a
/// raw emission.
pub const CONDITION_GATED_IDS: &[u16] = &[
  // conditional-ARRAY AF tags (apply_with_context → None on no match)
  0x201c, 0x201e, 0x2020, 0x2022,
  // single-HASH Condition rows (single_hash_condition_holds)
  0x1000, 0x1001, 0x1002, 0x201b, 0x201d, 0x2021, 0x205c, 0xb050,
];

/// Whether tag `id`'s single-HASH `Condition` HOLDS for this body — i.e.
/// whether ExifTool's `GetTagInfo` would return the tag (so it is emitted).
/// `false` ⇒ the `Condition` fails ⇒ the tag is SUPPRESSED (absent), matching
/// ExifTool's default output. `model` is the threaded IFD0 `$$self{Model}`;
/// `format` is the entry's on-disk TIFF format name (`$format`).
///
/// Tags WITHOUT a suppressible single-HASH `Condition` return `true`
/// (always emitted) — the four conditional-ARRAY AF tags are NOT handled here
/// (their suppression is the `apply_with_context`-returns-`None` path).
#[must_use]
pub fn single_hash_condition_holds(id: u16, format: &str, model: Option<&str>) -> bool {
  let m = model.unwrap_or("");
  match id {
    // 0x201b FocusMode / 0x2021 AFTracking (`Sony.pm:1244,1473`):
    // `($$self{Model} !~ /^DSC-/) or ($$self{Model} =~
    //  /^DSC-(RX10M4|RX100M6|RX100M7|RX100M5A|HX95|HX99|RX0M2|RX1RM3)/)`.
    0x201b | 0x2021 => !m.starts_with("DSC-") || model_dsc_new(m),
    // 0x201d FlexibleSpotPosition (`Sony.pm:1313`):
    // `$$self{Model} =~ /^(NEX-|ILCE-|ILME-|ZV-|DSC-(RX10M4|…|RX1RM3))/`.
    0x201d => model_is_nex_ilce_set(m),
    // 0x205c StepCropShooting (`Sony.pm:1761`):
    // `$$self{Model} =~ /^(DSC-RX1RM3)\b/`.
    0x205c => model_matches_dsc_rx1rm3_wb(m),
    // 0xb050 HighISONoiseReduction2 (`Sony.pm:2662`):
    // `$$self{Model} =~ /^(DSC-|Stellar)/`.
    0xb050 => m.starts_with("DSC-") || m.starts_with("Stellar"),
    // 0x1000 MultiBurstMode (`Sony.pm:882`): `$format eq "undef"`.
    0x1000 => format == "undef",
    // 0x1001 MultiBurstImageWidth / 0x1002 MultiBurstImageHeight
    // (`Sony.pm:890,895`): `$format eq "int16u"`.
    0x1001 | 0x1002 => format == "int16u",
    // Everything else: no suppressible single-HASH Condition ⇒ always emit.
    _ => true,
  }
}

// ===========================================================================
// RawConv undef-drop (sentinel suppression). In ExifTool a tag's `RawConv`
// runs during value extraction AFTER `GetTagInfo`/Condition has selected the
// tag; if it returns `undef` the value is NOT stored ⇒ the tag is ABSENT from
// output (`ExifTool.pm` `ConvertValue`/`GetValue`). Several `%Sony::Main`
// rows use `RawConv => '$val == 65535 ? undef : $val'` (and 0xb048 a
// model-conditional `-1` drop) to suppress a sentinel raw value while still
// keeping `65535 => 'n/a'` (etc.) in the PrintConv for the rare body that
// writes the sentinel WITHOUT the RawConv. The parse path otherwise always
// emits `def.conv.apply(...)`, so without this gate a sentinel raw would leak
// as a bogus converted value. `super::parse_in_tiff` skips the emission when
// [`rawconv_drops`] returns `true`.
//
// EXCLUDED (not drops): the DataMember-capture RawConvs (0x201c
// `$$self{AFAreaILCx}=$val`), the binary-passthrough RawConv (0x2001
// PreviewImage `return \$val …`), and the always-return RawConvs (0x202f
// PixelShiftInfo sprintf, 0xb000 FileFormat `return $val`). None of those
// drop a normal scalar value.
// ===========================================================================

/// Every `%Sony::Main` LEAF tag id whose `RawConv` can return `undef` to DROP
/// a sentinel raw value — the "rawconv-drop" set the
/// `tests/sony_main_rawconv.rs` oracle requires. All are
/// `$val == 65535 ? undef : $val` (`Sony.pm`) except 0xb048, whose drop is
/// `($val == -1 and $$self{Model} =~ /DSLR-A100\b/) ? undef : $val`
/// (`Sony.pm:2559`) — a model-conditional `-1` drop. The exact raw-value
/// predicate is in [`rawconv_drops`].
pub const RAWCONV_DROP_IDS: &[u16] = &[
  0xb040, // Macro                 (Sony.pm:2427)
  0xb041, // ExposureMode          (Sony.pm:2438)
  0xb042, // FocusMode             (Sony.pm:2478)
  0xb043, // AFAreaMode            (Sony.pm:2498)
  0xb044, // AFIlluminator         (Sony.pm:2535)
  0xb047, // JPEGQuality           (Sony.pm:2547)
  0xb048, // FlashLevel (A100, -1) (Sony.pm:2559)
  0xb049, // ReleaseMode           (Sony.pm:2585)
  0xb04a, // SequenceNumber        (Sony.pm:2598)
  0xb04b, // Anti-Blur             (Sony.pm:2609)
];

/// Whether tag `id`'s `RawConv` DROPS this raw value (returns `undef`) ⇒ the
/// tag is SUPPRESSED (absent from output). `model` is the threaded IFD0
/// `$$self{Model}` (only 0xb048's drop reads it). Tags without a
/// sentinel-drop RawConv return `false` (always emitted).
///
/// The drop tests the RAW value (pre-ValueConv/PrintConv), exactly as
/// ExifTool's `RawConv` does.
#[must_use]
pub fn rawconv_drops(id: u16, raw: &RawValue, model: Option<&str>) -> bool {
  match id {
    // `$val == 65535 ? undef : $val` (`Sony.pm:2427,2438,2478,2498,2535,
    // 2547,2585,2598,2609`) — these are all `Writable => 'int16u'`, so the
    // sentinel is the unsigned 65535.
    0xb040 | 0xb041 | 0xb042 | 0xb043 | 0xb044 | 0xb047 | 0xb049 | 0xb04a | 0xb04b => {
      first_u64(raw) == Some(65535)
    }
    // 0xb048 FlashLevel (`Sony.pm:2559`): `($val == -1 and $$self{Model} =~
    // /DSLR-A100\b/) ? undef : $val`. `Writable => 'int16s'`, so the drop is
    // the signed `-1` AND only on the DSLR-A100 body.
    0xb048 => first_i64(raw) == Some(-1) && model.is_some_and(model_is_dslr_a100),
    _ => false,
  }
}

/// `$$self{Model} =~ /DSLR-A100\b/` (`Sony.pm:2559`) — an UNANCHORED match
/// (no leading `^`) with a trailing `\b` word boundary: `DSLR-A100` may occur
/// anywhere in the Model and must be followed by a non-word character
/// (`[^A-Za-z0-9_]`) or end-of-string (so `DSLR-A100` matches but a
/// hypothetical `DSLR-A100X` would NOT).
fn model_is_dslr_a100(model: &str) -> bool {
  let bytes = model.as_bytes();
  let needle = b"DSLR-A100";
  if bytes.len() < needle.len() {
    return false;
  }
  (0..=bytes.len() - needle.len()).any(|i| {
    // `i + needle.len() <= bytes.len()` over this range, so `.get(..)` is
    // `Some` — byte-identical to `&bytes[i..i + needle.len()] == needle`.
    bytes.get(i..i + needle.len()) == Some(&needle[..])
      && match bytes.get(i + needle.len()) {
        None => true,
        Some(&c) => !(c.is_ascii_alphanumeric() || c == b'_'),
      }
  })
}

/// `$$self{Model} =~ /^(DSC-RX1RM3)\b/` (`Sony.pm:1761`). The trailing `\b`
/// is a word boundary: `DSC-RX1RM3` must be followed by a non-word character
/// (`[^A-Za-z0-9_]`) or end-of-string — so `DSC-RX1RM3` matches but a
/// hypothetical `DSC-RX1RM3X` would NOT.
fn model_matches_dsc_rx1rm3_wb(model: &str) -> bool {
  let Some(rest) = model.strip_prefix("DSC-RX1RM3") else {
    return false;
  };
  // `\b` after the alphanumeric `3`: the next char must NOT be a word char.
  match rest.chars().next() {
    None => true,
    Some(c) => !(c.is_ascii_alphanumeric() || c == '_'),
  }
}

/// `0x201c AFAreaModeSetting` (`Sony.pm:1256-1306`). Three per-Model `int8u`
/// PrintConv branches, ALL gated by a `Condition` (no unconditional catch-all
/// branch); first matching `Condition` wins. No match ⇒ `None` ⇒ the caller
/// SUPPRESSES the tag (ExifTool's `GetTagInfo` finds no tag info, so the entry
/// is absent from default output — e.g. `Model=DSC-RX100`).
///
/// Note the DataMember set by branches 2/3 (`AFAreaILCE`/`AFAreaILCA`) is
/// captured by the caller during the IFD walk (see [`super::parse_in_tiff`]),
/// not here — this fn only renders the displayed value.
fn af_area_mode_setting(raw: &RawValue, print_conv: bool, model: Option<&str>) -> Option<TagValue> {
  let m = model.unwrap_or("");
  if model_is_slt_hv(m) {
    // Branch 1 — SLT/HV (`Sony.pm:1268-1273`).
    Some(simple_label(raw, print_conv, |n| match n {
      0 => Some("Wide"),
      4 => Some("Local"),
      8 => Some("Zone"),
      9 => Some("Spot"),
      _ => None,
    }))
  } else if model_is_nex_ilce_set(m) {
    // Branch 2 — NEX/ILCE/ILME/ZV/some-DSC (`Sony.pm:1281-1290`).
    Some(simple_label(raw, print_conv, |n| match n {
      0 => Some("Wide"),
      1 => Some("Center"),
      3 => Some("Flexible Spot"),
      4 => Some("Flexible Spot (LA-EA4)"),
      9 => Some("Center (LA-EA4)"),
      11 => Some("Zone"),
      12 => Some("Expanded Flexible Spot"),
      13 => Some("Custom AF Area"),
      _ => None,
    }))
  } else if model_is_ilca(m) {
    // Branch 3 — ILCA (`Sony.pm:1298-1304`).
    Some(simple_label(raw, print_conv, |n| match n {
      0 => Some("Wide"),
      4 => Some("Flexible Spot"),
      8 => Some("Zone"),
      9 => Some("Center"),
      12 => Some("Expanded Flexible Spot"),
      _ => None,
    }))
  } else {
    // No `Condition` matched ⇒ no tag info ⇒ SUPPRESS (absent from output).
    None
  }
}

/// `0x201e AFPointSelected` (`Sony.pm:1321-1421`). Five per-Model/DataMember
/// branches, ALL gated by a `Condition` (no unconditional catch-all); first
/// matching `Condition` wins. `af_area` is the `AFAreaILCx` DataMember from
/// 0x201c. No match ⇒ `None` ⇒ the caller SUPPRESSES the tag (e.g. an ILCA
/// body whose `AFAreaILCA` DataMember was never set, or a non-RX DSC).
fn af_point_selected(
  raw: &RawValue,
  print_conv: bool,
  model: Option<&str>,
  af_area: Option<i64>,
) -> Option<TagValue> {
  let m = model.unwrap_or("");
  // Branch 1 (`Sony.pm:1326-1355`): SLT/HV, OR ILCE/ILME with AFAreaILCE == 4.
  let branch1 = model_is_slt_hv(m)
    || ((m.starts_with("ILCE-") || m.starts_with("ILME-")) && af_area == Some(4));
  if branch1 {
    return Some(simple_label(raw, print_conv, |n| match n {
      0 => Some("Auto"),
      1 => Some("Center"),
      2 => Some("Top"),
      3 => Some("Upper-right"),
      4 => Some("Right"),
      5 => Some("Lower-right"),
      6 => Some("Bottom"),
      7 => Some("Lower-left"),
      8 => Some("Left"),
      9 => Some("Upper-left"),
      10 => Some("Far Right"),
      11 => Some("Far Left"),
      12 => Some("Upper-middle"),
      13 => Some("Near Right"),
      14 => Some("Lower-middle"),
      15 => Some("Near Left"),
      16 => Some("Upper Far Right"),
      17 => Some("Lower Far Right"),
      18 => Some("Lower Far Left"),
      19 => Some("Upper Far Left"),
      _ => None,
    }));
  }
  // Branch 2 (`Sony.pm:1357-1368`): ILCA-(68|77M2) and AFAreaILCA != 8.
  // `ValueConv => '$val - 1'` then PrintConv keyed on the shifted value:
  // `{ -1 => 'Auto', %afPoints79, 39 => 'E6 (Center)' }`.
  if model_is_ilca_68_77m2(m) && af_area.is_some_and(|a| a != 8) {
    let Some(n) = first_i64(raw) else {
      return Some(raw_to_tag_value(raw));
    };
    let shifted = n - 1; // ValueConv (applies in both -n and -j).
    if !print_conv {
      return Some(TagValue::I64(shifted));
    }
    let label = match shifted {
      -1 => Some("Auto"),
      39 => Some("E6 (Center)"), // overrides %afPoints79's "E6"
      other => af_points79(other),
    };
    return Some(match label {
      Some(l) => TagValue::Str(l.into()),
      None => TagValue::Str(SmolStr::from(std::format!("Unknown ({shifted})"))),
    });
  }
  // Branch 3 (`Sony.pm:1370-1381`): ILCA-99M2 and AFAreaILCA != 8.
  // `{ 0 => 'Auto', %afPoints99M2, 162 => 'E6 (162, Center)', OTHER => sub }`.
  if m.starts_with("ILCA-99M2") && af_area.is_some_and(|a| a != 8) {
    let Some(n) = first_i64(raw) else {
      return Some(raw_to_tag_value(raw));
    };
    if !print_conv {
      return Some(TagValue::I64(n));
    }
    let label = match n {
      0 => Some("Auto"),
      162 => Some("E6 (162, Center)"), // overrides %afPoints99M2's "E6 (162)"
      other => af_points99m2(other),
    };
    return Some(match label {
      Some(l) => TagValue::Str(l.into()),
      // OTHER => sub { shift } — pass other values straight through.
      None => TagValue::I64(n),
    });
  }
  // Branch 4 (`Sony.pm:1383-1401`): ILCA-* and AFAreaILCA == 8 (Zone).
  if model_is_ilca(m) && af_area == Some(8) {
    return Some(simple_label(raw, print_conv, |n| match n {
      0 => Some("n/a"),
      1 => Some("Top Left Zone"),
      2 => Some("Top Zone"),
      3 => Some("Top Right Zone"),
      4 => Some("Left Zone"),
      5 => Some("Center Zone"),
      6 => Some("Right Zone"),
      7 => Some("Bottom Left Zone"),
      8 => Some("Bottom Zone"),
      9 => Some("Bottom Right Zone"),
      _ => None,
    }));
  }
  // Branch 5 (`Sony.pm:1402-1420`): NEX/ILCE/ILME/ZV/DSC-RX (Zone).
  if model_is_nex_ilce_zv_dscrx(m) {
    return Some(simple_label(raw, print_conv, |n| match n {
      0 => Some("n/a"),
      1 => Some("Center Zone"),
      2 => Some("Top Zone"),
      3 => Some("Right Zone"),
      4 => Some("Left Zone"),
      5 => Some("Bottom Zone"),
      6 => Some("Bottom Right Zone"),
      7 => Some("Bottom Left Zone"),
      8 => Some("Top Left Zone"),
      9 => Some("Top Right Zone"),
      _ => None,
    }));
  }
  // No `Condition` matched ⇒ no tag info ⇒ SUPPRESS (absent from output).
  None
}

/// `$$self{Model} =~ /^ILCA-(68|77M2)/` (`Sony.pm:1358,1459`).
fn model_is_ilca_68_77m2(model: &str) -> bool {
  model.starts_with("ILCA-68") || model.starts_with("ILCA-77M2")
}

/// 0x201e branch-5 Model set: `^(NEX-|ILCE-|ILME-|ZV-|DSC-RX)` (`Sony.pm:1406`).
fn model_is_nex_ilce_zv_dscrx(model: &str) -> bool {
  model.starts_with("NEX-")
    || model.starts_with("ILCE-")
    || model.starts_with("ILME-")
    || model.starts_with("ZV-")
    || model.starts_with("DSC-RX")
}

/// `0x2020 AFPointsUsed` (`Sony.pm:1426-1468`). Two per-Model BITMASK
/// branches (`BitsPerWord => 8`), BOTH gated by a `Condition` (no
/// unconditional catch-all); first matching `Condition` wins. No match ⇒
/// `None` ⇒ the caller SUPPRESSES the tag (e.g. `Model=DSC-…`/`ZV-…`/`ILCA-`
/// other than 68/77M2).
fn af_points_used(raw: &RawValue, print_conv: bool, model: Option<&str>) -> Option<TagValue> {
  let m = model.unwrap_or("");
  // Branch 1 (`Sony.pm:1428`): NOT /^(ILCA-|DSC-|ZV-)/.
  if !(model_is_ilca(m) || m.starts_with("DSC-") || m.starts_with("ZV-")) {
    return Some(decode_bits(raw, print_conv, af_points_used_bit));
  }
  // Branch 2 (`Sony.pm:1459`): /^ILCA-(68|77M2)/ → %afPoints79 bit table.
  if model_is_ilca_68_77m2(m) {
    return Some(decode_bits(raw, print_conv, af_points79));
  }
  // No `Condition` matched ⇒ no tag info ⇒ SUPPRESS (absent from output).
  None
}

/// 0x2020 branch-1 BITMASK lookup (`Sony.pm:1435-1454`).
fn af_points_used_bit(n: i64) -> Option<&'static str> {
  Some(match n {
    0 => "Center",
    1 => "Top",
    2 => "Upper-right",
    3 => "Right",
    4 => "Lower-right",
    5 => "Bottom",
    6 => "Lower-left",
    7 => "Left",
    8 => "Upper-left",
    9 => "Far Right",
    10 => "Far Left",
    11 => "Upper-middle",
    12 => "Near Right",
    13 => "Lower-middle",
    14 => "Near Left",
    15 => "Upper Far Right",
    16 => "Lower Far Right",
    17 => "Lower Far Left",
    18 => "Upper Far Left",
    _ => return None,
  })
}

/// `0x2022 FocalPlaneAFPointsUsed` (`Sony.pm:1487-1507`). Two per-Model
/// branches, each with an EMPTY `BITMASK => { }` (`Sony.pm:1495,1505`), so
/// DecodeBits emits `[n]` for every set bit. BOTH branches are gated by a
/// `Condition` (no unconditional catch-all); first matching `Condition` wins.
/// No match ⇒ `None` ⇒ the caller SUPPRESSES the tag (e.g. `Model=ILCE-9`,
/// which writes neither variant).
fn focal_plane_af_points_used(
  raw: &RawValue,
  print_conv: bool,
  model: Option<&str>,
) -> Option<TagValue> {
  let m = model.unwrap_or("");
  // Branch 1 (`Sony.pm:1489`): /^(ILCE-(5100|6000|7M2))/.
  let branch1 =
    m.starts_with("ILCE-5100") || m.starts_with("ILCE-6000") || m.starts_with("ILCE-7M2");
  // Branch 2 (`Sony.pm:1499`): /^ILCE-7RM2/.
  if branch1 || m.starts_with("ILCE-7RM2") {
    // Empty lookup ⇒ every set bit renders as `[n]`.
    return Some(decode_bits(raw, print_conv, |_| None));
  }
  // No `Condition` matched ⇒ no tag info ⇒ SUPPRESS (absent from output).
  None
}

/// `DecodeBits` (`ExifTool.pm:6385-6407`) with `BitsPerWord => 8`. The value
/// is the space-joined `int8u` list (ExifTool's default ValueConv for an
/// `int8u[N]` tag); bit `i` of word `w` is bit number `i + 8*w`. With a
/// lookup, each set bit renders its label (or `[n]` when absent) and labels
/// join with `", "`; no set bit ⇒ `"(none)"`.
///
/// `-n` (no PrintConv) renders the raw space-joined `int8u` list (no
/// ValueConv on these rows beyond the implicit int8u join).
fn decode_bits<F: Fn(i64) -> Option<&'static str>>(
  raw: &RawValue,
  print_conv: bool,
  lookup: F,
) -> TagValue {
  // Gather the int8u words.
  let words: Vec<i64> = match raw {
    RawValue::U64(v) => v.iter().map(|&n| n as i64).collect(),
    RawValue::I64(v) => v.clone(),
    RawValue::Bytes(b) => b.iter().map(|&n| n as i64).collect(),
    _ => return raw_to_tag_value(raw),
  };
  if !print_conv {
    // `-n`: the raw space-joined int list (matches `raw_to_tag_value`).
    return raw_to_tag_value(raw);
  }
  let mut bit_list: Vec<String> = Vec::new();
  for (w, &word) in words.iter().enumerate() {
    // `$val & (1 << $i)` for i in 0..8 (BitsPerWord). Mask to the low 8 bits
    // since the source is int8u (a wider value can't occur for int8u[N]).
    for i in 0..8u32 {
      if word & (1i64 << i) != 0 {
        let n = i as i64 + (w as i64) * 8;
        match lookup(n) {
          Some(label) => bit_list.push(label.to_string()),
          None => bit_list.push(std::format!("[{n}]")),
        }
      }
    }
  }
  if bit_list.is_empty() {
    return TagValue::Str("(none)".into());
  }
  TagValue::Str(SmolStr::from(bit_list.join(", ")))
}

/// `%afPoints79` (`Sony.pm:615-625`) — the shared 79-point AF grid label
/// table (keys 0..=78). Used by 0x201e branch 2 and 0x2020 branch 2.
fn af_points79(n: i64) -> Option<&'static str> {
  Some(match n {
    0 => "A5",
    1 => "A6",
    2 => "A7",
    3 => "B2",
    4 => "B3",
    5 => "B4",
    6 => "B5",
    7 => "B6",
    8 => "B7",
    9 => "B8",
    10 => "B9",
    11 => "B10",
    12 => "C1",
    13 => "C2",
    14 => "C3",
    15 => "C4",
    16 => "C5",
    17 => "C6",
    18 => "C7",
    19 => "C8",
    20 => "C9",
    21 => "C10",
    22 => "C11",
    23 => "D1",
    24 => "D2",
    25 => "D3",
    26 => "D4",
    27 => "D5",
    28 => "D6",
    29 => "D7",
    30 => "D8",
    31 => "D9",
    32 => "D10",
    33 => "D11",
    34 => "E1",
    35 => "E2",
    36 => "E3",
    37 => "E4",
    38 => "E5",
    39 => "E6",
    40 => "E7",
    41 => "E8",
    42 => "E9",
    43 => "E10",
    44 => "E11",
    45 => "F1",
    46 => "F2",
    47 => "F3",
    48 => "F4",
    49 => "F5",
    50 => "F6",
    51 => "F7",
    52 => "F8",
    53 => "F9",
    54 => "F10",
    55 => "F11",
    56 => "G1",
    57 => "G2",
    58 => "G3",
    59 => "G4",
    60 => "G5",
    61 => "G6",
    62 => "G7",
    63 => "G8",
    64 => "G9",
    65 => "G10",
    66 => "G11",
    67 => "H2",
    68 => "H3",
    69 => "H4",
    70 => "H5",
    71 => "H6",
    72 => "H7",
    73 => "H8",
    74 => "H9",
    75 => "H10",
    76 => "I5",
    77 => "I6",
    78 => "I7",
    _ => return None,
  })
}

/// `%afPoints99M2` (`Sony.pm:654-664`) — the ILCA-99M2 selectable AF-point
/// label table (sparse keys 93..=231). Used by 0x201e branch 3.
fn af_points99m2(n: i64) -> Option<&'static str> {
  Some(match n {
    93 => "A5 (93)",
    94 => "A6 (94)",
    95 => "A7 (95)",
    106 => "B2 (106)",
    107 => "B3 (107)",
    108 => "B4 (108)",
    110 => "B5 (110)",
    111 => "B6 (111)",
    112 => "B7 (112)",
    114 => "B8 (114)",
    115 => "B9 (115)",
    116 => "B10 (116)",
    122 => "C1 (122)",
    123 => "C2 (123)",
    124 => "C3 (124)",
    125 => "C4 (125)",
    127 => "C5 (127)",
    128 => "C6 (128)",
    129 => "C7 (129)",
    131 => "C8 (131)",
    132 => "C9 (132)",
    133 => "C10 (133)",
    134 => "C11 (134)",
    139 => "D1 (139)",
    140 => "D2 (140)",
    141 => "D3 (141)",
    142 => "D4 (142)",
    144 => "D5 (144)",
    145 => "D6 (145)",
    146 => "D7 (146)",
    148 => "D8 (148)",
    149 => "D9 (149)",
    150 => "D10 (150)",
    151 => "D11 (151)",
    156 => "E1 (156)",
    157 => "E2 (157)",
    158 => "E3 (158)",
    159 => "E4 (159)",
    161 => "E5 (161)",
    162 => "E6 (162)",
    163 => "E7 (163)",
    165 => "E8 (165)",
    166 => "E9 (166)",
    167 => "E10 (167)",
    168 => "E11 (168)",
    173 => "F1 (173)",
    174 => "F2 (174)",
    175 => "F3 (175)",
    176 => "F4 (176)",
    178 => "F5 (178)",
    179 => "F6 (179)",
    180 => "F7 (180)",
    182 => "F8 (182)",
    183 => "F9 (183)",
    184 => "F10 (184)",
    185 => "F11 (185)",
    190 => "G1 (190)",
    191 => "G2 (191)",
    192 => "G3 (192)",
    193 => "G4 (193)",
    195 => "G5 (195)",
    196 => "G6 (196)",
    197 => "G7 (197)",
    199 => "G8 (199)",
    200 => "G9 (200)",
    201 => "G10 (201)",
    202 => "G11 (202)",
    208 => "H2 (208)",
    209 => "H3 (209)",
    210 => "H4 (210)",
    212 => "H5 (212)",
    213 => "H6 (213)",
    214 => "H7 (214)",
    216 => "H8 (216)",
    217 => "H9 (217)",
    218 => "H10 (218)",
    229 => "I5 (229)",
    230 => "I6 (230)",
    231 => "I7 (231)",
    _ => return None,
  })
}

/// `ConvLensSpec` + `PrintLensSpec` for `0xb02a LensSpec`
/// (`Sony.pm:2391-2404`, `:11138-11146`, `:11165-11213`).
///
/// `Format => 'undef'`, `Count => 8` ⇒ the raw value is 8 bytes. ConvLensSpec
/// (`Sony.pm:11140-11146`):
///   `unpack("H2H4H4H2H2H2",$val)` → `[flags1, sf, lf, sa, la, flags2]` hex
///   strings; `$a[1]+=0; $a[2]+=0` strips the focal-length leading zeros;
///   for the two aperture fields a hex digit `a-f` is converted (`"b0" → 110`)
///   then `/= 10`. The ValueConv string is `join ' ', @a` (the `-n` value).
/// PrintLensSpec (`Sony.pm:11179-11213`) renders the LensInfo + feature tags.
fn lens_spec(raw: &RawValue, print_conv: bool) -> TagValue {
  // The 8 raw `undef` bytes.
  let bytes: Vec<u8> = match raw {
    RawValue::Bytes(b) => b.clone(),
    // `int8u` storage path (a defensive fallback — bundled is `undef`).
    RawValue::U64(v) => v.iter().map(|&n| n as u8).collect(),
    RawValue::I64(v) => v.iter().map(|&n| n as u8).collect(),
    _ => return raw_to_tag_value(raw),
  };
  // `return \$val unless length($val) == 8;` — non-8-byte ⇒ ValueConv returns
  // a scalar ref (left unconverted); render the raw bytes unchanged. The
  // exact-length slice pattern below is byte-identical to the `len != 8`
  // guard + `bytes[0..7]` indexing.
  let [b0, b1, b2, b3, b4, b5, b6, b7] = *bytes.as_slice() else {
    return raw_to_tag_value(raw);
  };
  // unpack("H2H4H4H2H2H2") — each field is the lowercase HEX STRING of its
  // bytes (a0 = byte0; a1 = bytes1-2; a2 = bytes3-4; a3 = byte5; a4 = byte6;
  // a5 = byte7). The `H4` focal-length strings and `H2` aperture strings are
  // then numerically coerced as DECIMAL (NOT hex), per `Sony.pm:11143-11145`:
  //   `$a[1] += 0; $a[2] += 0;` (e.g. "0018" → 18, "0055" → 55), and
  //   `s/([a-f])/hex($1)/e; $_ /= 10;` for the apertures (e.g. "35" → 3.5,
  //   "b0" → "110" → 11). Flags `a0`/`a5` stay as their 2-char hex strings.
  let a0 = std::format!("{b0:02x}");
  let sf = h4_to_decimal(b1, b2); // a1
  let lf = h4_to_decimal(b3, b4); // a2
  let sa = h2_aperture(b5); // a3
  let la = h2_aperture(b6); // a4
  let a5 = std::format!("{b7:02x}");
  // ValueConv string `join ' ', @a` (the `-n` value).
  let value_str = std::format!("{a0} {sf} {lf} {} {} {a5}", fmt_f(sa), fmt_f(la),);
  if !print_conv {
    return TagValue::Str(SmolStr::from(value_str));
  }
  TagValue::Str(SmolStr::from(print_lens_spec(&value_str)))
}

/// Perl numeric coercion of a string (`$str + 0` / `$str / 10` etc.): take the
/// LEADING numeric prefix and ignore any trailing non-numeric characters;
/// an empty or non-leading-numeric string coerces to `0.0` (Perl `"f"+0 == 0`,
/// `"15f"+0 == 15`, `"012a"+0 == 12`). The arithmetic ops in `ConvLensSpec`
/// (`$a[1] += 0`, `$a[3] /= 10`, `Sony.pm:11143-11145`) all trigger this
/// coercion, so `f64::parse()` on the WHOLE string is WRONG: `"ff"` after the
/// single `s/([a-f])/.../e` becomes `"15f"`, which Rust `parse()` rejects (→ 0)
/// but Perl coerces to 15. The numeric prefix follows Perl's grammar: optional
/// leading whitespace, optional sign, then `digits[.digits]` or `.digits`,
/// with an optional `e[+-]digits` exponent (longest valid prefix; stops at the
/// first char that would break the numeric token).
fn perl_num(s: &str) -> f64 {
  let bytes = s.as_bytes();
  let mut i = 0;
  // `bytes.get(i).is_some_and(pred)` is byte-identical to the prior
  // `i < n && bytes[i] <pred>`: out of range ⇒ `None` ⇒ `false` (same as the
  // failed `i < n`), in range ⇒ the predicate on `bytes[i]`.
  // Optional leading whitespace (Perl skips it before the number).
  while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
    i += 1;
  }
  let start = i;
  // Optional sign.
  if bytes.get(i).is_some_and(|&b| b == b'+' || b == b'-') {
    i += 1;
  }
  let mut saw_digit = false;
  // Integer part.
  while bytes.get(i).is_some_and(u8::is_ascii_digit) {
    i += 1;
    saw_digit = true;
  }
  // Fractional part: a single `.` followed by optional digits.
  if bytes.get(i).is_some_and(|&b| b == b'.') {
    i += 1;
    while bytes.get(i).is_some_and(u8::is_ascii_digit) {
      i += 1;
      saw_digit = true;
    }
  }
  if !saw_digit {
    return 0.0;
  }
  // Optional exponent `e`/`E` [+/-] digits — only consumed if at least one
  // exponent digit follows (otherwise the `e` is trailing non-numeric).
  if bytes.get(i).is_some_and(|&b| b == b'e' || b == b'E') {
    let mut j = i + 1;
    if bytes.get(j).is_some_and(|&b| b == b'+' || b == b'-') {
      j += 1;
    }
    let exp_start = j;
    while bytes.get(j).is_some_and(u8::is_ascii_digit) {
      j += 1;
    }
    if j > exp_start {
      i = j;
    }
  }
  s[start..i].parse().unwrap_or(0.0)
}

/// `H4` focal length: the two bytes' 4-char hex STRING coerced as DECIMAL
/// (`$a[1] += 0`, `Sony.pm:11143`). e.g. bytes (0x00,0x18) → "0018" → 18.
/// NOTE: the `s/([a-f])/hex/e` substitution is applied only to `@a[3,4]`
/// (apertures), NOT the focal lengths, so a hex letter in the focal string is
/// left in place and `+ 0` coerces only the leading numeric run — e.g.
/// "012a" → 12, "00ff" → 0. We use [`perl_num`] (not `parse()`, which would
/// reject "012a" → 0) to mirror that coercion. Returns the integer focal
/// length (the field never carries a fractional value).
fn h4_to_decimal(b1: u8, b2: u8) -> u32 {
  let s = std::format!("{b1:02x}{b2:02x}");
  perl_num(&s) as u32
}

/// `H2` aperture byte → f-number: the 2-char hex STRING with each `a-f` digit
/// replaced by its decimal value (`s/([a-f])/hex($1)/e`, single substitution,
/// no `/g`), then `/= 10` (`Sony.pm:11144-11145`). The `/= 10` triggers Perl
/// numeric coercion, so the post-substitution string is read via [`perl_num`]
/// (leading numeric prefix, trailing non-numeric ignored) NOT `f64::parse()`:
/// "35" → 3.5, "b0" → "110" → 11.0, "a1" → "101" → 10.1, and crucially
/// "ff" → (sub first `f`) → "15f" → coerce 15 → 1.5 (parse() would yield 0.0).
fn h2_aperture(b: u8) -> f64 {
  let s = std::format!("{b:02x}");
  // Perl `s///` (no /g) substitutes only the FIRST `a-f` letter. Capturing the
  // byte via `find` (instead of `position` + re-indexing `s.as_bytes()[idx]`)
  // is byte-identical and avoids the raw index.
  let replaced = match s
    .bytes()
    .enumerate()
    .find(|&(_, c)| (b'a'..=b'f').contains(&c))
  {
    Some((idx, letter)) => {
      let val = (letter - b'a' + 10) as u32; // hex('a')..hex('f') = 10..15
      std::format!("{}{}{}", &s[..idx], val, &s[idx + 1..])
    }
    None => s,
  };
  perl_num(&replaced) / 10.0
}

/// Format a ValueConv focal-aperture number the way Perl stringifies it:
/// integers print without a trailing `.0`, fractions keep their decimals
/// (e.g. `3.5`, `5.6`, `11`, `10.1`).
fn fmt_f(v: f64) -> std::string::String {
  if v.fract() == 0.0 {
    std::format!("{}", v as i64)
  } else {
    std::format!("{v}")
  }
}

/// One `@lensFeatures` row (`Sony.pm:11165-11178`): `(mask, &[(bits, name),
/// …], is_prefix)`. The masked `hex($flags1 . $flags2)` bits select the name
/// (or `Unknown(%.4x)`); `is_prefix` places the name before vs after the
/// LensInfo body.
type LensFeature = (u32, &'static [(u32, &'static str)], bool);

/// `@lensFeatures` (`Sony.pm:11165-11178`), in the order features are
/// appended to the LensSpec string. The mask/bits are applied to
/// `hex($flags1 . $flags2)` (high byte = byte0, low byte = byte7).
const LENS_FEATURES: &[LensFeature] = &[
  (0x4000, &[(0x4000, "PZ")], true),
  (
    0x0300,
    &[(0x0100, "DT"), (0x0200, "FE"), (0x0300, "E")],
    true,
  ),
  (
    0x00e0,
    &[
      (0x0020, "STF"),
      (0x0040, "Reflex"),
      (0x0060, "Macro"),
      (0x0080, "Fisheye"),
    ],
    false,
  ),
  (0x000c, &[(0x0004, "ZA"), (0x0008, "G")], false),
  (0x0003, &[(0x0001, "SSM"), (0x0002, "SAM")], false),
  (0x8000, &[(0x8000, "OSS")], false),
  (0x2000, &[(0x2000, "LE")], false),
  (0x0800, &[(0x0800, "II")], false),
];

/// `PrintLensSpec` (`Sony.pm:11179-11213`). Renders the ValueConv string
/// (`"flags1 sf lf sa la flags2"`) into a LensInfo + feature-tag string like
/// `"DT 18-55mm F3.5-5.6 SAM"`.
fn print_lens_spec(val: &str) -> std::string::String {
  let a: Vec<&str> = val.split(' ').collect();
  // 0=flags1, 1=short focal, 2=long focal, 3=max aperture@short, 4=@long,
  // 5=flags2.
  let mut rtn: Option<std::string::String> = None;
  let mut f1 = "";
  let mut f2 = "";
  // Slice patterns replace the `a.len() == 2` / `>= 6` guards + `a[i]`
  // indexing — byte-identical (each pattern matches the same length class and
  // binds the same elements).
  if let [g1, g2] = *a.as_slice() {
    // LensSpecFeatures patch: ($f1,$f2)=@a; $rtnVal=''.
    f1 = g1;
    f2 = g2;
    rtn = Some(std::string::String::new());
  } else if let [g1, sf_s, lf_s, sa_s, la_s, g2, ..] = *a.as_slice() {
    f1 = g1;
    f2 = g2;
    let sf: f64 = sf_s.parse().unwrap_or(0.0);
    let lf: f64 = lf_s.parse().unwrap_or(0.0);
    let sa: f64 = sa_s.parse().unwrap_or(0.0);
    let la: f64 = la_s.parse().unwrap_or(0.0);
    // Crude validation (`Sony.pm:11192`): sf!=0 && sa!=0 && (lf==0||lf>=sf) &&
    // (la==0||la>=sa).
    if sf != 0.0 && sa != 0.0 && (lf == 0.0 || lf >= sf) && (la == 0.0 || la >= sa) {
      // Zoom: append `-lf` / `-la` ranges.
      let sf_s = if lf != sf && lf != 0.0 {
        std::format!("{}-{}", fmt_f(sf), fmt_f(lf))
      } else {
        fmt_f(sf)
      };
      let sa_s = if sa != la && la != 0.0 {
        std::format!("{}-{}", fmt_f(sa), fmt_f(la))
      } else {
        fmt_f(sa)
      };
      rtn = Some(std::format!("{sf_s}mm F{sa_s}"));
    }
  }
  if let Some(mut rtn_val) = rtn {
    // hex($f1 . $f2) — concatenate the two hex strings, parse as hex.
    let flags = u32::from_str_radix(&std::format!("{f1}{f2}"), 16).unwrap_or(0);
    for (mask, names, is_prefix) in LENS_FEATURES {
      let bits = mask & flags;
      // `next unless $bits or $$feature[1]{$bits};` — skip when no masked
      // bits AND no explicit name for 0.
      let name_for_bits = names.iter().find(|(b, _)| *b == bits).map(|(_, n)| *n);
      if bits == 0 && name_for_bits.is_none() {
        continue;
      }
      // `$str = $$feature[1]{$bits} || sprintf('Unknown(%.4x)',$bits)`.
      let str_owned;
      let s: &str = match name_for_bits {
        Some(n) => n,
        None => {
          str_owned = std::format!("Unknown({bits:04x})");
          &str_owned
        }
      };
      // Prefix vs suffix; an empty rtn_val just becomes the feature string.
      rtn_val = if rtn_val.is_empty() {
        s.to_string()
      } else if *is_prefix {
        std::format!("{s} {rtn_val}")
      } else {
        std::format!("{rtn_val} {s}")
      };
    }
    rtn_val
  } else {
    std::format!("Unknown ({val})")
  }
}

/// `FullImageSize` 0xb02b / `PreviewImageSize` 0xb02c
/// (`Sony.pm:2405-2422`). The int32u[2] is stored **height-first**;
/// `ValueConv => 'join(" ", reverse split(" ", $val))'` reverses the
/// space-split list (turning the stored `"H W"` into `"W H"`), and
/// `PrintConv => '$val =~ tr/ /x/; $val'` substitutes every space in that
/// reversed value with `x` (→ `"WxH"`). So `-n` (ValueConv) is the reversed
/// `"width height"` and `-j` (PrintConv) is `"widthxheight"`. We faithfully
/// `reverse` the WHOLE list (not just a 2-swap) to match `reverse split`.
fn image_size_hxv(raw: &RawValue, print_conv: bool) -> TagValue {
  use std::string::ToString;
  let parts: Vec<String> = match raw {
    RawValue::U64(v) => v.iter().rev().map(ToString::to_string).collect(),
    RawValue::I64(v) => v.iter().rev().map(ToString::to_string).collect(),
    _ => return raw_to_tag_value(raw),
  };
  // `tr/ /x/` for PrintConv joins with 'x'; ValueConv keeps the space.
  let sep = if print_conv { "x" } else { " " };
  TagValue::Str(SmolStr::from(parts.join(sep)))
}

/// `HDR` 0x200a positional-array PrintConv (`Sony.pm:1004-1031`).
///
/// `Format => 'int16u'`, `Count => 2`, `PrintHex => 1`,
/// `PrintConv => [{A550-hash},{A580-hash}]`. ExifTool array-PrintConv
/// semantics (`ExifTool.pm:3550-3697`): element `i` converts through
/// `convList[i]` (here position 0 → the HDR-setting hash, position 1 → the
/// HDR-result hash), then the converted elements join with `"; "`. An
/// element absent from its hash uses the `PrintHex` `Unknown (0xNN)`
/// fallback (`ExifTool.pm:3628-3634`; no OTHER/BITMASK on either hash).
/// `-n` (no ValueConv) emits the space-joined raw int16u pair.
fn hdr(raw: &RawValue, print_conv: bool) -> TagValue {
  let vals: Vec<i64> = match raw {
    RawValue::U64(v) => v.iter().map(|&n| n as i64).collect(),
    RawValue::I64(v) => v.clone(),
    _ => return raw_to_tag_value(raw),
  };
  if !print_conv {
    // `-n`: bare ints joined with a space (same as `raw_to_tag_value`).
    return raw_to_tag_value(raw);
  }
  use std::string::ToString;
  let parts: Vec<String> = vals
    .iter()
    .enumerate()
    .map(|(i, &n)| {
      let label = match i {
        // Position 0 — HDR setting (A550 hash, `Sony.pm:1012-1024`).
        0 => match n {
          0x0 => Some("Off"),
          0x01 => Some("Auto"),
          0x10 => Some("1.0 EV"),
          0x11 => Some("1.5 EV"),
          0x12 => Some("2.0 EV"),
          0x13 => Some("2.5 EV"),
          0x14 => Some("3.0 EV"),
          0x15 => Some("3.5 EV"),
          0x16 => Some("4.0 EV"),
          0x17 => Some("4.5 EV"),
          0x18 => Some("5.0 EV"),
          0x19 => Some("5.5 EV"),
          0x1a => Some("6.0 EV"),
          _ => None,
        },
        // Position 1 — HDR result (A580 hash, `Sony.pm:1026-1030`).
        _ => match n {
          0 => Some("Uncorrected image"),
          1 => Some("HDR image (good)"),
          2 => Some("HDR image (fail 1)"),
          3 => Some("HDR image (fail 2)"),
          _ => None,
        },
      };
      match label {
        Some(l) => l.to_string(),
        // PrintHex => 1 ⇒ `Unknown (0xNN)` (`ExifTool.pm:3631`).
        None => std::format!("Unknown (0x{n:x})"),
      }
    })
    .collect();
  TagValue::Str(SmolStr::from(parts.join("; ")))
}

/// `WBShiftAB_GM_Precise` 0x2026 (`Sony.pm:1521-1530`). int32s[2];
/// `PrintConv => 'my @v=split(" ",$val); $_/=1000 foreach @v;
/// sprintf("%.2f %.2f",$v[0],$v[1])'`. No ValueConv ⇒ `-n` is the raw
/// space-joined pair; `-j` divides each by 1000 and formats to 2 decimals.
/// `sprintf("%.2f",$v[0])` coerces an absent element to 0 (→ `"0.00"`).
fn wb_shift_ab_gm_precise(raw: &RawValue, print_conv: bool) -> TagValue {
  let vals: Vec<i64> = match raw {
    RawValue::I64(v) => v.clone(),
    RawValue::U64(v) => v.iter().map(|&n| n as i64).collect(),
    _ => return raw_to_tag_value(raw),
  };
  if !print_conv {
    // `-n`: no ValueConv, so the raw int pair joined with a space.
    return raw_to_tag_value(raw);
  }
  // sprintf("%.2f %.2f",$v[0],$v[1]) — missing elements coerce to 0.
  let v0 = vals.first().copied().unwrap_or(0) as f64 / 1000.0;
  let v1 = vals.get(1).copied().unwrap_or(0) as f64 / 1000.0;
  TagValue::Str(SmolStr::from(std::format!("{v0:.2} {v1:.2}")))
}

/// `PixelShiftInfo` 0x202f (`Sony.pm:1643-1677`). `Writable => 'undef'`
/// (6 bytes). `RawConv` (applies in BOTH modes, before PrintConv) reads a
/// little-/big-endian int32u GroupID at offset 0 plus two int8u at 4/5, and
/// formats `sprintf("%.2d%.2d%.2d%.2d %d %d 0x%x", ($a>>17)&0x1f,
/// ($a>>12)&0x1f, ($a>>6)&0x3f, $a&0x3f, $b, $c, $a>>22)`. The `-n` output
/// is that RawConv string; the `-j` PrintConv maps `'00000000 0 0 0x0' =>
/// 'n/a'`, else the OTHER sub rewrites `"GG b c 0xN" → "Group GG, Shot b/c
/// (0xN)"` then `"Shot 0+/0*N" → "Composed N-shot"`.
fn pixel_shift_info(raw: &RawValue, print_conv: bool) -> TagValue {
  // Source is the 6-byte `undef` blob. `Get32u`/`Get8u` read with the IFD
  // byte order; the body walker has already materialised the bytes, so we
  // read the raw `undef` bytes here. ExifTool's Get32u uses the parent IFD
  // order — the body walker captures the value bytes verbatim, so a 6-byte
  // `RawValue::Bytes` is the faithful input.
  let bytes: Vec<u8> = match raw {
    RawValue::Bytes(b) => b.clone(),
    _ => return raw_to_tag_value(raw),
  };
  // The `len >= 6` guard makes `first_chunk::<4>()` / `get(4)` / `get(5)`
  // all `Some`; the checked reads are byte-identical to the prior indexing.
  let (Some(a4), Some(&b), Some(&c)) = (bytes.first_chunk::<4>(), bytes.get(4), bytes.get(5))
  else {
    return raw_to_tag_value(raw);
  };
  // ExifTool `Get32u(\$val,0)` defaults to the current byte order. The
  // GroupID is documented as int32u; the body materialises `undef` bytes in
  // file order, so read little-endian to match the on-disk layout ExifTool
  // sees after honouring the IFD order (Sony MakerNotes are little-endian).
  let a = u32::from_le_bytes(*a4);
  let raw_str = std::format!(
    "{:02}{:02}{:02}{:02} {} {} 0x{:x}",
    (a >> 17) & 0x1f,
    (a >> 12) & 0x1f,
    (a >> 6) & 0x3f,
    a & 0x3f,
    b,
    c,
    a >> 22
  );
  if !print_conv {
    return TagValue::Str(SmolStr::from(raw_str));
  }
  if raw_str == "00000000 0 0 0x0" {
    return TagValue::Str("n/a".into());
  }
  // OTHER sub (forward, `$inv` false): rewrite "G b c W" → "Group G, Shot
  // b/c (W)"; if no match, return undef (→ raw passes through unchanged).
  match pixel_shift_other(&raw_str) {
    Some(s) => TagValue::Str(SmolStr::from(s)),
    None => TagValue::Str(SmolStr::from(raw_str)),
  }
}

/// 0x202f PrintConv `OTHER` sub forward direction (`Sony.pm:1667-1675`):
/// `$val =~ s{(\d+) (\d+) (\d+) (\w+)}{Group $1, Shot $2/$3 ($4)} or return
/// undef; $val =~ s{Shot 0+/0*(\d+)\b}{Composed $1-shot}i;`.
fn pixel_shift_other(val: &str) -> Option<String> {
  // The RawConv output is always exactly "GROUP B C 0xW" (4 ws-separated
  // tokens: digits, digits, digits, word). Parse those four tokens.
  let toks: Vec<&str> = val.split(' ').collect();
  // `[g, b, c, w]` matches exactly four tokens — byte-identical to the prior
  // `toks.len() != 4` guard + `toks[0..3]` indexing, without raw indexing.
  let [g, b, c, w] = toks.as_slice() else {
    return None;
  };
  // `(\d+) (\d+) (\d+) (\w+)` — first three are digit runs, last is \w+.
  if !g.bytes().all(|x| x.is_ascii_digit())
    || !b.bytes().all(|x| x.is_ascii_digit())
    || !c.bytes().all(|x| x.is_ascii_digit())
    || w.is_empty()
    || !w.bytes().all(|x| x.is_ascii_alphanumeric() || x == b'_')
  {
    return None;
  }
  // s{Shot 0+/0*(\d+)\b}{Composed $1-shot}i — the "Shot $2/$3" we just
  // built becomes "Composed $3-shot" iff $2 is all zeros (`0+`) and $3 has
  // any leading zeros stripped (`0*`). Mirror against the parsed b/c.
  let b_all_zero = b.bytes().all(|x| x == b'0');
  if b_all_zero {
    // `0*(\d+)` — strip leading zeros from $3 (the regex `\d+` keeps ≥1
    // digit, so an all-zero $3 collapses to "0").
    let c_stripped = c.trim_start_matches('0');
    let c_stripped = if c_stripped.is_empty() {
      "0"
    } else {
      c_stripped
    };
    Some(std::format!("Group {g}, Composed {c_stripped}-shot ({w})"))
  } else {
    Some(std::format!("Group {g}, Shot {b}/{c} ({w})"))
  }
}

/// `FocusFrameSize` 0x2037 (`Sony.pm:1717-1727`). `Format => 'int16u'`,
/// `Count => 3`; `PrintConv => 'my @a = split " ", $val; return $a[2] ?
/// sprintf("%3dx%3d", $a[0], $a[1]) : "n/a"'`. `-n` (no ValueConv) emits
/// the space-joined int16u triple.
fn focus_frame_size(raw: &RawValue, print_conv: bool) -> TagValue {
  let vals: Vec<i64> = match raw {
    RawValue::U64(v) => v.iter().map(|&n| n as i64).collect(),
    RawValue::I64(v) => v.clone(),
    _ => return raw_to_tag_value(raw),
  };
  if !print_conv {
    return raw_to_tag_value(raw);
  }
  // `$a[2] ? … : 'n/a'` — Perl truthiness: the 3rd element (index 2) must be
  // present and non-zero. A missing index is undef ⇒ falsy ⇒ "n/a".
  let third = vals.get(2).copied().unwrap_or(0);
  if third == 0 {
    return TagValue::Str("n/a".into());
  }
  // sprintf("%3dx%3d", $a[0], $a[1]) — width-3, space-padded, 'x' separator.
  let a0 = vals.first().copied().unwrap_or(0);
  let a1 = vals.get(1).copied().unwrap_or(0);
  TagValue::Str(SmolStr::from(std::format!("{a0:3}x{a1:3}")))
}

/// `%Image::ExifTool::Minolta::sonyColorMode` (`Minolta.pm`) — the
/// `0xb029 ColorMode` lookup (`Sony.pm:2389`).
fn color_mode_label(n: i64) -> Option<&'static str> {
  match n {
    0 => Some("Standard"),
    1 => Some("Vivid"),
    2 => Some("Portrait"),
    3 => Some("Landscape"),
    4 => Some("Sunset"),
    5 => Some("Night View/Portrait"),
    6 => Some("B&W"),
    7 => Some("Adobe RGB"),
    12 => Some("Neutral"),
    13 => Some("Clear"),
    14 => Some("Deep"),
    15 => Some("Light"),
    16 => Some("Autumn Leaves"),
    17 => Some("Sepia"),
    18 => Some("FL"),
    19 => Some("Vivid 2"),
    20 => Some("IN"),
    21 => Some("SH"),
    22 => Some("FL2"),
    23 => Some("FL3"),
    100 => Some("Neutral"),
    101 => Some("Clear"),
    102 => Some("Deep"),
    103 => Some("Light"),
    104 => Some("Night View"),
    105 => Some("Autumn Leaves"),
    255 => Some("Off"),
    4_294_967_295 => Some("n/a"),
    _ => None,
  }
}

/// First scalar `u64`.
fn first_u64(raw: &RawValue) -> Option<u64> {
  match raw {
    RawValue::U64(v) => v.first().copied(),
    RawValue::I64(v) => v.first().and_then(|&n| u64::try_from(n).ok()),
    _ => None,
  }
}

/// First scalar `i64`.
fn first_i64(raw: &RawValue) -> Option<i64> {
  match raw {
    RawValue::I64(v) => v.first().copied(),
    RawValue::U64(v) => v.first().and_then(|&n| i64::try_from(n).ok()),
    _ => None,
  }
}

/// First scalar value as `f64` — handles rationals (for rational64s tags).
fn first_f64(raw: &RawValue) -> Option<f64> {
  match raw {
    RawValue::F64(v) => v.first().copied(),
    RawValue::I64(v) => v.first().map(|&n| n as f64),
    RawValue::U64(v) => v.first().map(|&n| n as f64),
    RawValue::Rational(rs) => rs.first().map(|r| {
      let d = r.denominator();
      if d == 0 {
        0.0
      } else {
        r.numerator() as f64 / d as f64
      }
    }),
    _ => None,
  }
}

/// First two scalar values (for int16u[2]/int16s[2] string-keyed PrintConvs).
fn first_pair(raw: &RawValue) -> Option<(i64, i64)> {
  // `[a, b, ..]` matches len ≥ 2 and binds the first two — byte-identical to
  // the `if v.len() >= 2 => (v[0], v[1])` index pair, without raw indexing.
  match raw {
    RawValue::I64(v) if let [a, b, ..] = v.as_slice() => Some((*a, *b)),
    RawValue::U64(v) if let [a, b, ..] = v.as_slice() => {
      Some((i64::try_from(*a).ok()?, i64::try_from(*b).ok()?))
    }
    _ => None,
  }
}

/// Generic int → label PrintConv (decimal `Unknown (N)` fallback).
fn simple_label<F: Fn(i64) -> Option<&'static str>>(
  raw: &RawValue,
  print_conv: bool,
  f: F,
) -> TagValue {
  let Some(n) = first_i64(raw) else {
    return raw_to_tag_value(raw);
  };
  if !print_conv {
    return TagValue::I64(n);
  }
  match f(n) {
    Some(l) => TagValue::Str(l.into()),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({n})"))),
  }
}

/// Int → label PrintConv with a HEX `Unknown (0xNN)` fallback (for tags
/// bundled marks `PrintHex => 1`).
fn hex_label<F: Fn(i64) -> Option<&'static str>>(
  raw: &RawValue,
  print_conv: bool,
  f: F,
) -> TagValue {
  let Some(n) = first_i64(raw) else {
    return raw_to_tag_value(raw);
  };
  if !print_conv {
    return TagValue::I64(n);
  }
  match f(n) {
    Some(l) => TagValue::Str(l.into()),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown (0x{n:x})"))),
  }
}

/// Two-int → label PrintConv for `int16u[2]` string-keyed hashes. When the
/// value isn't a 2-element list, falls back to the default rendering; when
/// `print_conv` is off, emits the raw `"a b"` string (bundled's ValueConv).
fn pair_label<F: Fn(i64, i64) -> Option<&'static str>>(
  raw: &RawValue,
  print_conv: bool,
  f: F,
) -> TagValue {
  let Some((a, b)) = first_pair(raw) else {
    return raw_to_tag_value(raw);
  };
  if !print_conv {
    return TagValue::Str(SmolStr::from(std::format!("{a} {b}")));
  }
  match f(a, b) {
    Some(l) => TagValue::Str(l.into()),
    None => TagValue::Str(SmolStr::from(std::format!("{a} {b}"))),
  }
}

/// Render a raw value as a default [`TagValue`] (no PrintConv) — mirrors
/// the Apple/Canon/Panasonic helpers.
pub(crate) fn raw_to_tag_value(raw: &RawValue) -> TagValue {
  use std::string::ToString;
  // Single-element arms use a slice pattern (`[x]`) instead of `v[0]` behind
  // an `if v.len() == 1` guard — byte-identical (the pattern matches exactly
  // when there is one element) and free of raw indexing.
  match raw {
    RawValue::I64(v) if let [n] = v.as_slice() => TagValue::I64(*n),
    RawValue::I64(v) => TagValue::Str(
      v.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(" ")
        .into(),
    ),
    RawValue::U64(v) if let [n] = v.as_slice() => match i64::try_from(*n) {
      Ok(n) => TagValue::I64(n),
      Err(_) => TagValue::U64(*n),
    },
    RawValue::U64(v) => TagValue::Str(
      v.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(" ")
        .into(),
    ),
    RawValue::F64(v) if let [n] = v.as_slice() => TagValue::F64(*n),
    RawValue::F64(v) => TagValue::Str(
      v.iter()
        .map(|f| f.to_string())
        .collect::<Vec<_>>()
        .join(" ")
        .into(),
    ),
    RawValue::Rational(rs) if let [r] = rs.as_slice() => TagValue::Rational(*r),
    // Multi-element rational with NO conv: ExifTool's default ValueConv
    // renders EACH rational to its `RoundFloat(n/d, sig)` DECIMAL
    // (`ExifTool.pm:6107-6119`) and space-joins them (e.g. `[1/2, 3/4] → "0.5
    // 0.75"`), NOT the raw `num/den`. Mirrors the Panasonic helper.
    RawValue::Rational(rs) => TagValue::Str(
      rs.iter()
        .map(|r| r.exiftool_val_str())
        .collect::<Vec<_>>()
        .join(" ")
        .into(),
    ),
    RawValue::Text(s) => TagValue::Str(s.as_str().into()),
    RawValue::Bytes(b) => TagValue::Bytes(b.clone()),
  }
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C S2); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  #[test]
  fn quality_fine_label() {
    let raw = RawValue::U64(vec![2]);
    assert_eq!(
      SonyPrintConv::Quality.apply(&raw, true),
      TagValue::Str("Fine".into())
    );
  }

  #[test]
  fn white_balance_hex_auto() {
    let raw = RawValue::U64(vec![0]);
    assert_eq!(
      SonyPrintConv::WhiteBalance.apply(&raw, true),
      TagValue::Str("Auto".into())
    );
  }

  #[test]
  fn picture_effect_pop_color() {
    let raw = RawValue::U64(vec![2]);
    assert_eq!(
      SonyPrintConv::PictureEffect.apply(&raw, true),
      TagValue::Str("Pop Color".into())
    );
  }

  #[test]
  fn model_id_resolves_against_sony_model_ids() {
    let raw = RawValue::U64(vec![358]);
    assert_eq!(
      SonyPrintConv::ModelId.apply(&raw, true),
      TagValue::Str("ILCE-9".into())
    );
  }

  /// 0xb027 LensType resolves against the A-mount (Minolta-backed)
  /// `%sonyLensTypes` (`Sony.pm:2370`), NOT the E-mount `%sonyLensTypes2`.
  /// A real Minolta-table ID renders its A-mount name; the E-mount sentinel
  /// 65535 renders `"E-Mount, T-Mount, Other Lens or no lens"`
  /// (`Minolta.pm:545`). An E-mount lens ID (e.g. 32785, an `%sonyLensTypes2`
  /// key) is NOT present here, so it falls through to `Unknown (N)` — E-mount
  /// lenses are written as 65535 at 0xb027 (`Sony.pm:2368`).
  #[test]
  fn lens_type_b027_resolves_against_amount_table() {
    // Minolta-table ID 0 → A-mount name (NOT the E-mount "Unknown E-mount
    // lens or other lens" that %sonyLensTypes2 has at id 0).
    let id0 = RawValue::U64(vec![0]);
    assert_eq!(
      SonyPrintConv::LensType.apply(&id0, true),
      TagValue::Str("Minolta AF 28-85mm F3.5-4.5 New".into())
    );
    // E-mount sentinel.
    let sentinel = RawValue::U64(vec![65535]);
    assert_eq!(
      SonyPrintConv::LensType.apply(&sentinel, true),
      TagValue::Str("E-Mount, T-Mount, Other Lens or no lens".into())
    );
    // An E-mount lens ID is not an A-mount key → Unknown (N).
    let emount_id = RawValue::U64(vec![32785]);
    assert_eq!(
      SonyPrintConv::LensType.apply(&emount_id, true),
      TagValue::Str("Unknown (32785)".into())
    );
    // -n yields the bare raw int regardless.
    assert_eq!(SonyPrintConv::LensType.apply(&id0, false), TagValue::U64(0));
  }

  #[test]
  fn long_exposure_nr_dark_subtracted() {
    let raw = RawValue::U64(vec![0x10001]);
    assert_eq!(
      SonyPrintConv::LongExposureNr.apply(&raw, true),
      TagValue::Str("On (dark subtracted)".into())
    );
  }

  #[test]
  fn plus_or_int_positive_renders_plus() {
    let raw = RawValue::I64(vec![2]);
    assert_eq!(
      SonyPrintConv::PlusOrInt.apply(&raw, true),
      TagValue::Str("+2".into())
    );
  }

  #[test]
  fn print_conv_off_emits_raw_int() {
    let raw = RawValue::U64(vec![2]);
    assert_eq!(SonyPrintConv::Quality.apply(&raw, false), TagValue::I64(2));
  }

  /// 0x2028 VariableLowPassFilter int16u[2] string key (`Sony.pm:1549-1554`).
  #[test]
  fn variable_low_pass_filter_pair() {
    let raw = RawValue::U64(vec![1, 1]);
    assert_eq!(
      SonyPrintConv::VariableLowPassFilter.apply(&raw, true),
      TagValue::Str("Standard".into())
    );
    let na = RawValue::U64(vec![0, 0]);
    assert_eq!(
      SonyPrintConv::VariableLowPassFilter.apply(&na, true),
      TagValue::Str("n/a".into())
    );
  }

  /// 0x202e Quality int16u[2] string key (`Sony.pm:1606-1642`).
  #[test]
  fn quality2_raw_plus_fine() {
    let raw = RawValue::U64(vec![1, 2]);
    assert_eq!(
      SonyPrintConv::Quality2.apply(&raw, true),
      TagValue::Str("RAW + Fine".into())
    );
  }

  /// 0x202b PrioritySetInAWB (`Sony.pm:1581-1584`).
  #[test]
  fn priority_set_in_awb_white() {
    let raw = RawValue::U64(vec![2]);
    assert_eq!(
      SonyPrintConv::PrioritySetInAwb.apply(&raw, true),
      TagValue::Str("White".into())
    );
  }

  /// 0x202c MeteringMode2 PrintHex (`Sony.pm:1592`).
  #[test]
  fn metering_mode2_multi_segment() {
    let raw = RawValue::U64(vec![0x100]);
    assert_eq!(
      SonyPrintConv::MeteringMode2.apply(&raw, true),
      TagValue::Str("Multi-segment".into())
    );
  }

  /// 0xb000 FileFormat int8u[4] (`Sony.pm:2133`).
  #[test]
  fn file_format_arw_20() {
    let raw = RawValue::U64(vec![3, 0, 0, 0]);
    assert_eq!(
      SonyPrintConv::FileFormat.apply(&raw, true),
      TagValue::Str("ARW 2.0".into())
    );
  }

  /// 0xb023 SceneMode via %minoltaSceneMode (`Minolta.pm:631`).
  #[test]
  fn scene_mode_sweep_panorama() {
    let raw = RawValue::U64(vec![18]);
    assert_eq!(
      SonyPrintConv::SceneMode.apply(&raw, true),
      TagValue::Str("Sweep Panorama".into())
    );
  }

  /// 0xb040 Macro — '2' is "Close Focus" (`Sony.pm:2431`), NOT the Minolta
  /// "Magnifying Glass" label (a regression caught in the prior version).
  #[test]
  fn macro_close_focus() {
    let raw = RawValue::U64(vec![2]);
    assert_eq!(
      SonyPrintConv::Macro.apply(&raw, true),
      TagValue::Str("Close Focus".into())
    );
  }

  /// 0xb042 FocusMode older-DSC mapping (`Sony.pm:2490-2491`).
  #[test]
  fn focus_mode_b042_af_s() {
    let raw = RawValue::U64(vec![1]);
    assert_eq!(
      SonyPrintConv::FocusMode.apply(&raw, true),
      TagValue::Str("AF-S".into())
    );
  }

  /// 0xb043 AFAreaMode older-models mapping (`Sony.pm:2506`).
  #[test]
  fn af_area_mode_b043_default() {
    let raw = RawValue::U64(vec![0]);
    assert_eq!(
      SonyPrintConv::AfAreaMode.apply(&raw, true),
      TagValue::Str("Default".into())
    );
  }

  /// 0x0105 Teleconverter via %minoltaTeleconverters PrintHex
  /// (`Minolta.pm:559`).
  #[test]
  fn teleconverter_2x() {
    let raw = RawValue::U64(vec![0x48]);
    assert_eq!(
      SonyPrintConv::Teleconverter.apply(&raw, true),
      TagValue::Str("Minolta/Sony AF 2x APO (D)".into())
    );
  }

  /// 0x2031 SerialNumber (`Sony.pm:1681-1683`). ValueConv reverses the four
  /// 2-digit groups + strips ONE leading zero (the `-n` value); PrintConv
  /// zero-pads the result back to 8 digits (the `-j` value). Oracle values
  /// computed from the bundled Perl ValueConv/PrintConv expressions.
  #[test]
  fn serial_number_2031_reverses_and_pads() {
    // raw "12345678" → reverse pairs → "78563412" (no leading 0 to strip).
    let raw = RawValue::Text("12345678".into());
    assert_eq!(
      SonyPrintConv::SerialNumber2031.apply(&raw, false),
      TagValue::Str("78563412".into()),
      "-n = ValueConv (reversed pairs)"
    );
    assert_eq!(
      SonyPrintConv::SerialNumber2031.apply(&raw, true),
      TagValue::Str("78563412".into()),
      "-j = sprintf %.8d of the ValueConv"
    );
  }

  /// 0x2031 with a leading zero AFTER the pair-reversal: raw "00010203"
  /// → reverse → "03020100" → strip one leading 0 → "3020100" (`-n`);
  /// `sprintf("%.8d")` re-pads → "03020100" (`-j`).
  #[test]
  fn serial_number_2031_strips_leading_zero_then_repads() {
    let raw = RawValue::Text("00010203".into());
    assert_eq!(
      SonyPrintConv::SerialNumber2031.apply(&raw, false),
      TagValue::Str("3020100".into()),
      "-n strips the single leading zero from the reversed value"
    );
    assert_eq!(
      SonyPrintConv::SerialNumber2031.apply(&raw, true),
      TagValue::Str("03020100".into()),
      "-j zero-pads back to 8 digits"
    );
  }

  /// 0x200a HDR positional-array PrintConv (`Sony.pm:1004-1031`). Position 0
  /// uses the A550 HDR-setting hash, position 1 the A580 result hash; joined
  /// with `"; "`; PrintHex `Unknown (0xNN)` per element. Oracle values from
  /// the bundled hashes via ExifTool's array-PrintConv loop.
  #[test]
  fn hdr_positional_array() {
    // 0x10 → "1.0 EV" (pos 0), 0 → "Uncorrected image" (pos 1).
    let raw = RawValue::U64(vec![0x10, 0]);
    assert_eq!(
      SonyPrintConv::Hdr.apply(&raw, true),
      TagValue::Str("1.0 EV; Uncorrected image".into())
    );
    // 1 → "Auto", 1 → "HDR image (good)".
    let raw2 = RawValue::U64(vec![1, 1]);
    assert_eq!(
      SonyPrintConv::Hdr.apply(&raw2, true),
      TagValue::Str("Auto; HDR image (good)".into())
    );
    // 0x1a → "6.0 EV", 3 → "HDR image (fail 2)".
    let raw3 = RawValue::U64(vec![0x1a, 3]);
    assert_eq!(
      SonyPrintConv::Hdr.apply(&raw3, true),
      TagValue::Str("6.0 EV; HDR image (fail 2)".into())
    );
    // Unknown pos0 + unknown pos1 → PrintHex Unknown (0xNN) each.
    let raw4 = RawValue::U64(vec![0x63, 5]);
    assert_eq!(
      SonyPrintConv::Hdr.apply(&raw4, true),
      TagValue::Str("Unknown (0x63); Unknown (0x5)".into())
    );
    // -n: no ValueConv → space-joined raw int pair.
    assert_eq!(
      SonyPrintConv::Hdr.apply(&raw, false),
      TagValue::Str("16 0".into())
    );
  }

  /// 0x2026 WBShiftAB_GM_Precise (`Sony.pm:1521-1530`). int32s[2]; PrintConv
  /// divides each by 1000 then `sprintf("%.2f %.2f")`. No ValueConv ⇒ `-n`
  /// is the raw space-joined pair. Oracle from the bundled expression.
  #[test]
  fn wb_shift_ab_gm_precise_two_decimals() {
    let raw = RawValue::I64(vec![500, 250]);
    assert_eq!(
      SonyPrintConv::WbShiftAbGmPrecise.apply(&raw, true),
      TagValue::Str("0.50 0.25".into())
    );
    let neg = RawValue::I64(vec![-500, 1000]);
    assert_eq!(
      SonyPrintConv::WbShiftAbGmPrecise.apply(&neg, true),
      TagValue::Str("-0.50 1.00".into())
    );
    // -n: raw signed pair joined with a space.
    assert_eq!(
      SonyPrintConv::WbShiftAbGmPrecise.apply(&raw, false),
      TagValue::Str("500 250".into())
    );
  }

  /// 0x202f PixelShiftInfo (`Sony.pm:1643-1677`). RawConv decodes the 6-byte
  /// `undef` into `"GG b c 0xN"` (both modes); PrintConv maps the all-zero
  /// string to "n/a", else the OTHER sub rewrites it. Oracle from the
  /// bundled RawConv + OTHER expressions.
  #[test]
  fn pixel_shift_info_decodes() {
    // All-zero → RawConv "00000000 0 0 0x0", PrintConv → "n/a".
    let zero = RawValue::Bytes(vec![0, 0, 0, 0, 0, 0]);
    assert_eq!(
      SonyPrintConv::PixelShiftInfo.apply(&zero, false),
      TagValue::Str("00000000 0 0 0x0".into()),
      "-n = RawConv string"
    );
    assert_eq!(
      SonyPrintConv::PixelShiftInfo.apply(&zero, true),
      TagValue::Str("n/a".into()),
      "-j: all-zero → n/a"
    );
    // GroupID bytes 0x1234 (LE), shot (1 4): RawConv "00010852 1 4 0x0",
    // PrintConv OTHER → "Group 00010852, Shot 1/4 (0x0)".
    let src = RawValue::Bytes(vec![0x34, 0x12, 0, 0, 1, 4]);
    assert_eq!(
      SonyPrintConv::PixelShiftInfo.apply(&src, false),
      TagValue::Str("00010852 1 4 0x0".into())
    );
    assert_eq!(
      SonyPrintConv::PixelShiftInfo.apply(&src, true),
      TagValue::Str("Group 00010852, Shot 1/4 (0x0)".into())
    );
    // Combined 4-shot: shot (0 4) → "Composed 4-shot".
    let combined = RawValue::Bytes(vec![0, 0, 0, 0, 0, 4]);
    assert_eq!(
      SonyPrintConv::PixelShiftInfo.apply(&combined, true),
      TagValue::Str("Group 00000000, Composed 4-shot (0x0)".into())
    );
  }

  /// 0x2037 FocusFrameSize (`Sony.pm:1717-1727`). `$a[2] ? sprintf("%3dx%3d",
  /// $a[0],$a[1]) : 'n/a'`. Oracle from the bundled expression.
  #[test]
  fn focus_frame_size_sprintf_or_na() {
    // 3rd value truthy → "%3dx%3d" (width-3 space-padded).
    let raw = RawValue::U64(vec![640, 480, 257]);
    assert_eq!(
      SonyPrintConv::FocusFrameSize.apply(&raw, true),
      TagValue::Str("640x480".into())
    );
    // small dims get space-padded to width 3.
    let small = RawValue::U64(vec![16, 9, 1]);
    assert_eq!(
      SonyPrintConv::FocusFrameSize.apply(&small, true),
      TagValue::Str(" 16x  9".into())
    );
    // 3rd value 0 → "n/a".
    let na = RawValue::U64(vec![0, 0, 0]);
    assert_eq!(
      SonyPrintConv::FocusFrameSize.apply(&na, true),
      TagValue::Str("n/a".into())
    );
    // -n: space-joined triple.
    assert_eq!(
      SonyPrintConv::FocusFrameSize.apply(&raw, false),
      TagValue::Str("640 480 257".into())
    );
  }

  /// 0xb029 ColorMode via `%Minolta::sonyColorMode` (`Sony.pm:2389`).
  #[test]
  fn color_mode_lookup() {
    let raw = RawValue::U64(vec![16]);
    assert_eq!(
      SonyPrintConv::ColorMode.apply(&raw, true),
      TagValue::Str("Autumn Leaves".into())
    );
    // n/a sentinel 0xffffffff.
    let na = RawValue::U64(vec![4_294_967_295]);
    assert_eq!(
      SonyPrintConv::ColorMode.apply(&na, true),
      TagValue::Str("n/a".into())
    );
    // -n: bare int.
    assert_eq!(
      SonyPrintConv::ColorMode.apply(&raw, false),
      TagValue::I64(16)
    );
  }

  /// 0xb02b FullImageSize / 0xb02c PreviewImageSize (`Sony.pm:2405-2422`).
  /// Values are stored **height-first**; `ValueConv` reverses to
  /// `"width height"` and `PrintConv` substitutes spaces with `x`. For a
  /// 6000x4000 capture the on-disk int32u[2] is `[4000, 6000]` (H, W):
  /// `-n` → `"6000 4000"`, `-j` → `"6000x4000"`. Oracle from the bundled
  /// ValueConv/PrintConv expressions (`Sony.pm:2410-2412`).
  #[test]
  fn image_size_hxv_reverses_then_formats() {
    // Stored height-first: [H=4000, W=6000].
    let raw = RawValue::U64(vec![4000, 6000]);
    assert_eq!(
      SonyPrintConv::ImageSizeHxV.apply(&raw, false),
      TagValue::Str("6000 4000".into()),
      "-n = ValueConv reverses to \"width height\""
    );
    assert_eq!(
      SonyPrintConv::ImageSizeHxV.apply(&raw, true),
      TagValue::Str("6000x4000".into()),
      "-j = PrintConv tr/ /x/ → \"widthxheight\""
    );
    // I64 storage path behaves identically.
    let raw_i = RawValue::I64(vec![1080, 1920]);
    assert_eq!(
      SonyPrintConv::ImageSizeHxV.apply(&raw_i, false),
      TagValue::Str("1920 1080".into())
    );
    assert_eq!(
      SonyPrintConv::ImageSizeHxV.apply(&raw_i, true),
      TagValue::Str("1920x1080".into())
    );
  }

  /// 0x2031 from NUL-padded bytes (string tag storage): "00000001" reverses
  /// to "01000000", strips one leading 0 → "1000000" (`-n`); sprintf →
  /// "01000000" (`-j`).
  #[test]
  fn serial_number_2031_from_bytes() {
    let raw = RawValue::Bytes(b"00000001\0\0".to_vec());
    assert_eq!(
      SonyPrintConv::SerialNumber2031.apply(&raw, false),
      TagValue::Str("1000000".into())
    );
    assert_eq!(
      SonyPrintConv::SerialNumber2031.apply(&raw, true),
      TagValue::Str("01000000".into())
    );
  }

  // ===================================================================
  // Conditional-ARRAY AF tags + LensSpec (Phase-3 common-tag gaps).
  // Oracle values are from the BUNDLED 13.59 Sony.pm conversions, driven
  // through ExifTool's own conditional dispatch + ConvertValue/DecodeBits
  // (a per-tag Perl harness setting `$$self{Model}` / `$$self{AFAreaILCx}`).
  // ===================================================================

  /// 0x201c AFAreaModeSetting per-Model PrintConv (`Sony.pm:1256-1306`).
  /// Branch 1 SLT/HV, branch 2 NEX/ILCE, branch 3 ILCA; no-match ⇒ `None`
  /// (tag SUPPRESSED — all three branches are conditional, no catch-all).
  /// Negative oracle: `Model=DSC-RX100` and an absent Model both yield no
  /// branch (verified via ExifTool's `GetTagInfo` against the local bundle).
  #[test]
  fn af_area_mode_setting_per_model() {
    let r = |n: i64| RawValue::U64(vec![n as u64]);
    // SLT branch: 8 → "Zone".
    assert_eq!(
      SonyPrintConv::AfAreaModeSetting.apply_with_context(&r(8), true, Some("SLT-A99V"), None),
      Some(TagValue::Str("Zone".into()))
    );
    // ILCE branch: 11 → "Zone" (task's named rep).
    assert_eq!(
      SonyPrintConv::AfAreaModeSetting.apply_with_context(&r(11), true, Some("ILCE-7M3"), None),
      Some(TagValue::Str("Zone".into()))
    );
    // ILCE 13 → "Custom AF Area" (NC, ILCE-9M3/1M2).
    assert_eq!(
      SonyPrintConv::AfAreaModeSetting.apply_with_context(&r(13), true, Some("ILCE-7M3"), None),
      Some(TagValue::Str("Custom AF Area".into()))
    );
    // ILCA branch: 4 → "Flexible Spot" (DIFFERENT from SLT's "Local").
    assert_eq!(
      SonyPrintConv::AfAreaModeSetting.apply_with_context(&r(4), true, Some("ILCA-77M2"), None),
      Some(TagValue::Str("Flexible Spot".into()))
    );
    // SLT 4 → "Local" (proves per-model dispatch, not a shared hash).
    assert_eq!(
      SonyPrintConv::AfAreaModeSetting.apply_with_context(&r(4), true, Some("SLT-A99V"), None),
      Some(TagValue::Str("Local".into()))
    );
    // New-DSC body in branch 2: DSC-RX100M6 raw 11 → "Zone".
    assert_eq!(
      SonyPrintConv::AfAreaModeSetting.apply_with_context(&r(11), true, Some("DSC-RX100M6"), None),
      Some(TagValue::Str("Zone".into()))
    );
    // NEGATIVE oracle — old DSC (not in the new-DSC list) matches NO branch
    // ⇒ SUPPRESSED (`Model=DSC-RX100`: ExifTool emits no tag).
    assert_eq!(
      SonyPrintConv::AfAreaModeSetting.apply_with_context(&r(11), true, Some("DSC-RX100"), None),
      None
    );
    // NEGATIVE oracle — absent Model matches no branch ⇒ SUPPRESSED.
    assert_eq!(
      SonyPrintConv::AfAreaModeSetting.apply_with_context(&r(11), true, None, None),
      None
    );
    // -n is the bare raw int when a branch DOES match (suppression is
    // independent of print_conv — it's branch selection, not the conv).
    assert_eq!(
      SonyPrintConv::AfAreaModeSetting.apply_with_context(&r(8), false, Some("SLT-A99V"), None),
      Some(TagValue::I64(8))
    );
  }

  /// 0x201e AFPointSelected per-Model/DataMember PrintConv
  /// (`Sony.pm:1321-1421`). Five branches incl. a `ValueConv => '$val-1'`
  /// (ILCA-68/77M2) and an `OTHER => sub` passthrough (ILCA-99M2). All five
  /// are conditional (no catch-all) ⇒ no-match returns `None` (SUPPRESSED).
  #[test]
  fn af_point_selected_per_model_and_datamember() {
    let r = |n: i64| RawValue::U64(vec![n as u64]);
    // Branch 1 (SLT/HV): 1 → "Center".
    assert_eq!(
      SonyPrintConv::AfPointSelected.apply_with_context(&r(1), true, Some("SLT-A99V"), None),
      Some(TagValue::Str("Center".into()))
    );
    // Branch 1 via ILCE + AFAreaILCE==4: 5 → "Lower-right".
    assert_eq!(
      SonyPrintConv::AfPointSelected.apply_with_context(&r(5), true, Some("ILCE-7RM2"), Some(4)),
      Some(TagValue::Str("Lower-right".into()))
    );
    // Same body, AFAreaILCE==3 → falls to branch 5 (NEX/ILCE Zone): 5 →
    // "Bottom Zone" (DIFFERENT label, proving the DataMember gate).
    assert_eq!(
      SonyPrintConv::AfPointSelected.apply_with_context(&r(5), true, Some("ILCE-7RM2"), Some(3)),
      Some(TagValue::Str("Bottom Zone".into()))
    );
    // Branch 2 (ILCA-77M2, ILCA!=8): ValueConv `$val-1`. raw 35 → -j "E1",
    // -n 34.
    assert_eq!(
      SonyPrintConv::AfPointSelected.apply_with_context(&r(35), true, Some("ILCA-77M2"), Some(4)),
      Some(TagValue::Str("E1".into()))
    );
    assert_eq!(
      SonyPrintConv::AfPointSelected.apply_with_context(&r(35), false, Some("ILCA-77M2"), Some(4)),
      Some(TagValue::I64(34))
    );
    // raw 40 → 39 → "E6 (Center)" override of %afPoints79's "E6".
    assert_eq!(
      SonyPrintConv::AfPointSelected.apply_with_context(&r(40), true, Some("ILCA-77M2"), Some(4)),
      Some(TagValue::Str("E6 (Center)".into()))
    );
    // raw 0 → -1 → "Auto".
    assert_eq!(
      SonyPrintConv::AfPointSelected.apply_with_context(&r(0), true, Some("ILCA-77M2"), Some(4)),
      Some(TagValue::Str("Auto".into()))
    );
    // Branch 3 (ILCA-99M2, ILCA!=8): 162 → "E6 (162, Center)".
    assert_eq!(
      SonyPrintConv::AfPointSelected.apply_with_context(&r(162), true, Some("ILCA-99M2"), Some(5)),
      Some(TagValue::Str("E6 (162, Center)".into()))
    );
    assert_eq!(
      SonyPrintConv::AfPointSelected.apply_with_context(&r(93), true, Some("ILCA-99M2"), Some(5)),
      Some(TagValue::Str("A5 (93)".into()))
    );
    // OTHER => sub { shift } passthrough: an unmapped value renders raw.
    assert_eq!(
      SonyPrintConv::AfPointSelected.apply_with_context(&r(500), true, Some("ILCA-99M2"), Some(5)),
      Some(TagValue::I64(500))
    );
    // Branch 4 (ILCA, ILCA==8 Zone): 5 → "Center Zone".
    assert_eq!(
      SonyPrintConv::AfPointSelected.apply_with_context(&r(5), true, Some("ILCA-77M2"), Some(8)),
      Some(TagValue::Str("Center Zone".into()))
    );
    // Branch 5 (NEX): 1 → "Center Zone".
    assert_eq!(
      SonyPrintConv::AfPointSelected.apply_with_context(&r(1), true, Some("NEX-6"), None),
      Some(TagValue::Str("Center Zone".into()))
    );
    // NEGATIVE oracle — an ILCA body whose `AFAreaILCA` DataMember was never
    // set (af_area=None): branches 2/3/4 all require `defined $$self{AFAreaILCA}`
    // and branch 5 excludes ILCA, so NO branch matches ⇒ SUPPRESSED
    // (`Model=ILCA-77M2`, AFAreaILCA undef → ExifTool emits no tag).
    assert_eq!(
      SonyPrintConv::AfPointSelected.apply_with_context(&r(1), true, Some("ILCA-77M2"), None),
      None
    );
    // NEGATIVE oracle — a non-RX DSC matches no branch ⇒ SUPPRESSED.
    assert_eq!(
      SonyPrintConv::AfPointSelected.apply_with_context(&r(1), true, Some("DSC-W800"), None),
      None
    );
    // NEGATIVE oracle — absent Model ⇒ no branch ⇒ SUPPRESSED.
    assert_eq!(
      SonyPrintConv::AfPointSelected.apply_with_context(&r(1), true, None, None),
      None
    );
  }

  /// 0x2020 AFPointsUsed per-Model BITMASK (`Sony.pm:1426-1468`). DecodeBits
  /// with `BitsPerWord => 8`; bit `i` of word `w` ⇒ bit `i+8w`. Both branches
  /// are conditional (no catch-all) ⇒ no-match returns `None` (SUPPRESSED).
  #[test]
  fn af_points_used_bitmask() {
    // Branch 1 (SLT): single word 1 → bit0 → "Center".
    assert_eq!(
      SonyPrintConv::AfPointsUsed.apply_with_context(
        &RawValue::U64(vec![1]),
        true,
        Some("SLT-A99V"),
        None
      ),
      Some(TagValue::Str("Center".into()))
    );
    // 5 → bit0+bit2 → "Center, Upper-right" (joined ", ").
    assert_eq!(
      SonyPrintConv::AfPointsUsed.apply_with_context(
        &RawValue::U64(vec![5]),
        true,
        Some("SLT-A99V"),
        None
      ),
      Some(TagValue::Str("Center, Upper-right".into()))
    );
    // Word boundary: [0, 2] → word1 bit1 → bit9 → "Far Right".
    assert_eq!(
      SonyPrintConv::AfPointsUsed.apply_with_context(
        &RawValue::U64(vec![0, 2]),
        true,
        Some("SLT-A99V"),
        None
      ),
      Some(TagValue::Str("Far Right".into()))
    );
    // All-zero 10-word list → "(none)".
    assert_eq!(
      SonyPrintConv::AfPointsUsed.apply_with_context(
        &RawValue::U64(vec![0; 10]),
        true,
        Some("SLT-A99V"),
        None
      ),
      Some(TagValue::Str("(none)".into()))
    );
    // Single 0 (count-1) → "(none)" too: ExifTool's `0 => '(none)'` hash key
    // short-circuits before DecodeBits, and DecodeBits of all-zero is also
    // "(none)" — both paths agree (`Sony.pm:1434`, `ExifTool.pm:6405`).
    assert_eq!(
      SonyPrintConv::AfPointsUsed.apply_with_context(
        &RawValue::U64(vec![0]),
        true,
        Some("SLT-A99V"),
        None
      ),
      Some(TagValue::Str("(none)".into()))
    );
    // Branch 2 (ILCA-77M2) uses %afPoints79: bit0 → "A5"; [0,0,2] → bit17 →
    // "C6".
    assert_eq!(
      SonyPrintConv::AfPointsUsed.apply_with_context(
        &RawValue::U64(vec![1]),
        true,
        Some("ILCA-77M2"),
        None
      ),
      Some(TagValue::Str("A5".into()))
    );
    assert_eq!(
      SonyPrintConv::AfPointsUsed.apply_with_context(
        &RawValue::U64(vec![0, 0, 2]),
        true,
        Some("ILCA-77M2"),
        None
      ),
      Some(TagValue::Str("C6".into()))
    );
    // NEGATIVE oracle — DSC/ZV bodies match no branch ⇒ SUPPRESSED
    // (`Model=DSC-RX100`/`ZV-…`/`ILCA-` other than 68/77M2: ExifTool emits
    // no tag).
    assert_eq!(
      SonyPrintConv::AfPointsUsed.apply_with_context(
        &RawValue::U64(vec![1]),
        true,
        Some("DSC-RX100"),
        None
      ),
      None
    );
    assert_eq!(
      SonyPrintConv::AfPointsUsed.apply_with_context(
        &RawValue::U64(vec![1]),
        true,
        Some("ZV-1"),
        None
      ),
      None
    );
    assert_eq!(
      SonyPrintConv::AfPointsUsed.apply_with_context(
        &RawValue::U64(vec![1]),
        true,
        Some("ILCA-99M2"),
        None
      ),
      None
    );
    // -n: raw space-joined list when a branch DOES match.
    assert_eq!(
      SonyPrintConv::AfPointsUsed.apply_with_context(
        &RawValue::U64(vec![0, 2]),
        false,
        Some("SLT-A99V"),
        None
      ),
      Some(TagValue::Str("0 2".into()))
    );
  }

  /// 0x2022 FocalPlaneAFPointsUsed per-Model BITMASK with an EMPTY `{ }`
  /// lookup (`Sony.pm:1487-1507`): each set bit renders `[n]`, none ⇒
  /// "(none)". Both branches are conditional (no catch-all) ⇒ no-match
  /// returns `None` (SUPPRESSED).
  #[test]
  fn focal_plane_af_points_used_bitmask_empty() {
    // Branch 1 (ILCE-6000): 1 → "[0]".
    assert_eq!(
      SonyPrintConv::FocalPlaneAfPointsUsed.apply_with_context(
        &RawValue::U64(vec![1]),
        true,
        Some("ILCE-6000"),
        None
      ),
      Some(TagValue::Str("[0]".into()))
    );
    // 5 → "[0], [2]".
    assert_eq!(
      SonyPrintConv::FocalPlaneAfPointsUsed.apply_with_context(
        &RawValue::U64(vec![5]),
        true,
        Some("ILCE-6000"),
        None
      ),
      Some(TagValue::Str("[0], [2]".into()))
    );
    // [0,2] → bit9 → "[9]".
    assert_eq!(
      SonyPrintConv::FocalPlaneAfPointsUsed.apply_with_context(
        &RawValue::U64(vec![0, 2]),
        true,
        Some("ILCE-6000"),
        None
      ),
      Some(TagValue::Str("[9]".into()))
    );
    // Branch 2 (ILCE-7RM2): 128 → bit7 → "[7]".
    assert_eq!(
      SonyPrintConv::FocalPlaneAfPointsUsed.apply_with_context(
        &RawValue::U64(vec![128]),
        true,
        Some("ILCE-7RM2"),
        None
      ),
      Some(TagValue::Str("[7]".into()))
    );
    // All-zero → "(none)".
    assert_eq!(
      SonyPrintConv::FocalPlaneAfPointsUsed.apply_with_context(
        &RawValue::U64(vec![0; 10]),
        true,
        Some("ILCE-7M2"),
        None
      ),
      Some(TagValue::Str("(none)".into()))
    );
    // NEGATIVE oracle — a body that writes neither variant matches no branch
    // ⇒ SUPPRESSED (`Model=ILCE-9`: ExifTool emits no tag).
    assert_eq!(
      SonyPrintConv::FocalPlaneAfPointsUsed.apply_with_context(
        &RawValue::U64(vec![1]),
        true,
        Some("ILCE-9"),
        None
      ),
      None
    );
  }

  /// 0xb02a LensSpec ConvLensSpec (`Sony.pm:11138-11146`) + PrintLensSpec
  /// (`Sony.pm:11179-11213`). The 8 `undef` bytes unpack to
  /// `"flags1 sf lf sa la flags2"` (`-n`) and render `"DT 18-55mm F3.5-5.6
  /// SAM"`-style strings (`-j`). Oracle bytes/strings from the bundled subs.
  #[test]
  fn lens_spec_conv_and_print() {
    // DT 18-55mm F3.5-5.6 SAM (`hex("01"."02")`=0x0102 → DT|SAM).
    let b = RawValue::Bytes(vec![0x01, 0x00, 0x18, 0x00, 0x55, 0x35, 0x56, 0x02]);
    assert_eq!(
      SonyPrintConv::LensSpec.apply(&b, false),
      TagValue::Str("01 18 55 3.5 5.6 02".into()),
      "-n = ConvLensSpec value string"
    );
    assert_eq!(
      SonyPrintConv::LensSpec.apply(&b, true),
      TagValue::Str("DT 18-55mm F3.5-5.6 SAM".into()),
      "-j = PrintLensSpec"
    );
    // FE 24-70mm F2.8 (constant aperture; 0x0200 → FE prefix).
    let fe = RawValue::Bytes(vec![0x02, 0x00, 0x24, 0x00, 0x70, 0x28, 0x28, 0x00]);
    assert_eq!(
      SonyPrintConv::LensSpec.apply(&fe, true),
      TagValue::Str("FE 24-70mm F2.8".into())
    );
    // OSS + an unmatched feature-bit group → "Unknown(0003)" suffix
    // (`hex("80"."03")`=0x8003: 0x8000 OSS, 0x0003 not in SSM/SAM hash).
    let oss = RawValue::Bytes(vec![0x80, 0x00, 0x32, 0x00, 0x32, 0x18, 0x18, 0x03]);
    assert_eq!(
      SonyPrintConv::LensSpec.apply(&oss, true),
      TagValue::Str("32mm F1.8 Unknown(0003) OSS".into())
    );
    // Fixed F11 (byte 0xb0 → "110" → 11.0).
    let f11 = RawValue::Bytes(vec![0x00, 0x00, 0x64, 0x00, 0x00, 0xb0, 0x00, 0x00]);
    assert_eq!(
      SonyPrintConv::LensSpec.apply(&f11, false),
      TagValue::Str("00 64 0 11 0 00".into())
    );
    assert_eq!(
      SonyPrintConv::LensSpec.apply(&f11, true),
      TagValue::Str("64mm F11".into())
    );
    // ZA + SSM suffixes (`hex("00"."05")`=0x0005 → ZA(0x0004)|SSM(0x0001)).
    let za = RawValue::Bytes(vec![0x00, 0x00, 0x55, 0x00, 0x00, 0x14, 0x00, 0x05]);
    assert_eq!(
      SonyPrintConv::LensSpec.apply(&za, true),
      TagValue::Str("55mm F1.4 ZA SSM".into())
    );
    // Macro feature group (0x0060) suffix.
    let mac = RawValue::Bytes(vec![0x00, 0x00, 0x32, 0x00, 0x00, 0x28, 0x00, 0x60]);
    assert_eq!(
      SonyPrintConv::LensSpec.apply(&mac, true),
      TagValue::Str("32mm F2.8 Macro".into())
    );
    // Aperture byte 0xff → Perl numeric coercion (NOT f64::parse).
    // Bundled (ReadValue + ConvLensSpec + PrintLensSpec, ExifTool 13.59):
    //   raw `00 00 50 00 00 ff ff 00` → ValueConv "00 50 0 1.5 1.5 00",
    //   PrintLensSpec "50mm F1.5". The 0xff byte hex-string "ff" → s/([a-f])/
    //   hex/e (first `f`) → "15f" → `/10` coerces "15f" to 15 → 1.5
    //   (`f64::parse("15f")` would Err → 0.0 → the old F0.0 / Unknown bug).
    let ff = RawValue::Bytes(vec![0x00, 0x00, 0x50, 0x00, 0x00, 0xff, 0xff, 0x00]);
    assert_eq!(
      SonyPrintConv::LensSpec.apply(&ff, false),
      TagValue::Str("00 50 0 1.5 1.5 00".into()),
      "-n: 0xff aperture coerces \"15f\"→15 →/10 = 1.5"
    );
    assert_eq!(
      SonyPrintConv::LensSpec.apply(&ff, true),
      TagValue::Str("50mm F1.5".into()),
      "-j: full 00 00 50 00 00 ff ff 00 → 50mm F1.5"
    );
    // Focal-length H4 coercion sibling case (`$a[1] += 0`, NO s///e on focal).
    // Bundled: raw `00 01 2a 00 00 35 00 00` → ValueConv "00 12 0 3.5 0 00",
    //   PrintLensSpec "12mm F3.5". Short-focal bytes 0x01,0x2a → "012a"
    //   → Perl `+0` = 12 (leading numeric run, stops at `a`); `f64::parse`/
    //   `u32::parse("012a")` would Err → 0 → sf==0 → "Unknown (...)".
    let focal_af = RawValue::Bytes(vec![0x00, 0x01, 0x2a, 0x00, 0x00, 0x35, 0x00, 0x00]);
    assert_eq!(
      SonyPrintConv::LensSpec.apply(&focal_af, false),
      TagValue::Str("00 12 0 3.5 0 00".into()),
      "-n: focal \"012a\" coerces to 12"
    );
    assert_eq!(
      SonyPrintConv::LensSpec.apply(&focal_af, true),
      TagValue::Str("12mm F3.5".into()),
      "-j: focal-length leading-numeric coercion"
    );
    // Invalid (all-zero) → "Unknown (...)" of the ValueConv string.
    let zero = RawValue::Bytes(vec![0u8; 8]);
    assert_eq!(
      SonyPrintConv::LensSpec.apply(&zero, true),
      TagValue::Str("Unknown (00 0 0 0 0 00)".into())
    );
    // Wrong length (ConvLensSpec returns \$val unconverted) → raw bytes.
    let short = RawValue::Bytes(vec![0x01, 0x02, 0x03]);
    assert_eq!(
      SonyPrintConv::LensSpec.apply(&short, true),
      TagValue::Bytes(vec![0x01, 0x02, 0x03])
    );
  }

  #[test]
  fn perl_num_matches_perl_coercion() {
    // Oracle values from bundled Perl `$str + 0` (ExifTool 13.59 perl):
    //   "15f"→15, "12."→12, "12.5x"→12.5, "1e3z"→1000, "+7a"→7, ".5b"→0.5,
    //   "12.3.4"→12.3, "00ff"→0, "012a"→12, "-3q"→-3, "abc"→0, ""→0, "  9z"→9.
    let cases: &[(&str, f64)] = &[
      ("15f", 15.0),
      ("12.", 12.0),
      ("12.5x", 12.5),
      ("1e3z", 1000.0),
      ("+7a", 7.0),
      (".5b", 0.5),
      ("12.3.4", 12.3),
      ("00ff", 0.0),
      ("012a", 12.0),
      ("-3q", -3.0),
      ("abc", 0.0),
      ("", 0.0),
      ("  9z", 9.0),
      // Clean strings still parse normally.
      ("35", 35.0),
      ("110", 110.0),
      ("0055", 55.0),
    ];
    for &(s, want) in cases {
      assert_eq!(perl_num(s), want, "perl_num({s:?})");
    }
  }
}
