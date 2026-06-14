// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Per-tag PrintConv / ValueConv for the Nikon MakerNotes tables — a small
//! enum over the `PrintConv => { … }` hashes and inline expressions in
//! `Image::ExifTool::Nikon` (`Nikon.pm`). The IFD walker calls
//! [`NikonConv::apply`] at emit time with the decoded raw value.
//!
//! The `%Image::ExifTool::Nikon::Main` table sets a table-level
//! `PRINT_CONV => \&FormatString` (`Nikon.pm:1784`), which title-cases the
//! all-caps string values Nikon cameras write (e.g. `FINE` → `Fine`,
//! `SPEEDLIGHT` → `Speedlight`). A tag with NO own `PrintConv` and a string
//! value falls through to that table default — modelled here by
//! [`NikonConv::FormatString`]. Tags with their own `PrintConv` (LensType,
//! FlashMode, …) or `PrintConv => undef` (SerialNumber) bypass it.

#![deny(clippy::indexing_slicing)]

use super::body::ParsedValue;
use crate::exif::ifd::ByteOrder;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::string::String;

/// One Nikon tag's conversion strategy. Enum-newtype/unit-only (D8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NikonConv {
  /// No own PrintConv — the value falls through the table-level
  /// `PRINT_CONV => \&FormatString` (`Nikon.pm:1784`) when it is a string
  /// (title-cases all-caps Nikon strings); a non-string value renders via the
  /// default `ReadValue` join. This is the dominant Nikon::Main string tag.
  FormatString,
  /// No PrintConv AND no table-default (the tag set `PrintConv => undef` to
  /// disable the inherited `FormatString`, e.g. `SerialNumber` 0x001d) — emit
  /// the raw decoded value verbatim.
  Raw,
  /// `MakerNoteVersion` (0x0001) — `ValueConv` converts a binary 4-byte value
  /// to the digit string, then `PrintConv` `s/^(\d{2})/$1./;s/^0//` inserts a
  /// dot after the first two digits and strips a leading zero
  /// (`Nikon.pm:1786-1797`). E.g. `"0210"` → `"2.10"` (a numeric-shaped string
  /// the JSON writer emits as the bare number `2.10`).
  MakerNoteVersion,
  /// `ISO` (0x0002) — `int16u[2]`, `PrintConv` `s/^0 //;s/^1 (\d+)/Hi $1/`
  /// (`Nikon.pm:1804-1819`). The first word is `1` for the "Hi ISO" modes;
  /// otherwise the leading `0 ` is stripped. The tag's `RawConv => '$val eq
  /// "\0\0\0\0" ? undef : $val'` (`Nikon.pm:1806`) is effectively DEAD: by
  /// RawConv time `$val` is the decoded `int16u[2]` string (e.g. `"0 0"`),
  /// never the raw 4-NUL byte string, so the `eq` never matches and the
  /// all-zero LO-ISO value IS emitted (`Nikon.jpg` → `Nikon:ISO` `0`,
  /// oracle-confirmed). NOT a drop.
  Iso,
  /// The three-byte signed-fraction ValueConv `unpack("c3"); $c ? $a*($b/$c)
  /// : 0`, then `Exif::PrintFraction` (`+N` / `+N/2` / `+N/3` / `%+.3g`).
  /// Used by `ProgramShift` (0x000d), `ExposureTuning` (0x001c).
  SignedFractionPrintFraction,
  /// `ExposureDifference` (0x000e) — the same `c3` ValueConv, but the
  /// PrintConv is `$val ? sprintf("%+.1f",$val) : 0` (`Nikon.pm:1859`), NOT
  /// `PrintFraction`. e.g. `-4.9167` → `"-4.9"`.
  ExposureDifference,
  /// As [`Self::SignedFractionPrintFraction`] but the `PrintConv` is the
  /// `PrintFraction`-as-`"+N/M"` flash-comp form (0x0012 `FlashExposureComp`,
  /// 0x0017 `ExternalFlashExposureComp`). ExifTool shares the same
  /// `PrintFraction` here — kept distinct only for documentation.
  FlashExposureComp,
  /// `FlashExposureBracketValue` (0x0018) / `ExposureBracketValue` (0x0019) —
  /// the same `c3` ValueConv, `PrintConv => sprintf("%.1f", $val)`
  /// (`Nikon.pm:1955`). 0x0019 is a plain `rational64s` instead.
  BracketFloat1,
  /// `ISOSetting` (0x0013) — `int16u[2]`, `PrintConv => s/^0 //`
  /// (`Nikon.pm:1907`). The first word is always stripped.
  IsoSetting,
  /// `LensType` (0x0083) — a `DecodeBits` BITMASK with post-processing:
  /// `0 → "AF"`, then the bit labels with comma-stripping and the E/1/FT-1
  /// reordering (`Nikon.pm:2052-2070`).
  LensType,
  /// `Lens` (0x0084) — `rational64u[4]` rendered by `Exif::PrintLensInfo`
  /// (`"18-70mm f/3.5-4.5"`, `Nikon.pm:2089`).
  Lens,
  /// `FlashMode` (0x0087) — `int8u` hash (`Nikon.pm:2099-2110`).
  FlashMode,
  /// `ShootingMode` (0x0089) — the `Single-Frame` prefix logic + a
  /// `DecodeBits` BITMASK (`Nikon.pm:2160-2189`). Bit 5's label is
  /// model-dependent (D70 = "Unused LE-NR Slowdown", else "Auto ISO").
  ShootingMode,
  /// `LensFStops` (0x008b) — `c3` `ValueConv` then `PrintConv => sprintf("%.2f",
  /// $val)` (`Nikon.pm:2196`).
  LensFStops,
  /// `NEFCompression` (0x0093) — `%nefCompression` hash (`Nikon.pm:2913`).
  NefCompression,
  /// `ColorSpace` (0x001e) — `{1=>'sRGB',2=>'Adobe RGB',4=>'BT.2100'}`
  /// (`Nikon.pm:2010`).
  ColorSpace,
  /// `ShutterCount` (0x00a7) — `$val == 4294965247 ? "n/a" : $val`
  /// (`Nikon.pm:2980`).
  ShutterCount,
  /// `ExposureBracketValue` (0x0019) — `rational64s`, `PrintConv =>
  /// PrintFraction` unless the value is `undef` → `"n/a"` (`Nikon.pm:1960`).
  ExposureBracketRational,
  /// `SensorPixelSize` (0x009a) — `rational64u[2]`, `PrintConv =>
  /// '$val=~s/ / x /;"$val um"'` (`Nikon.pm:2868`) → `"7.8 x 7.8 um"`.
  SensorPixelSize,
  /// `ImageAuthentication` (0x0020) / `%offOn` — `{0=>'Off',1=>'On'}`.
  OffOn,
  /// `ActiveD-Lighting` (0x0022, `Nikon.pm:1998`).
  ActiveDLighting,
  /// `VignetteControl` (0x002a, `Nikon.pm:2032`).
  VignetteControl,
  /// `ShutterMode` (0x0034, `Nikon.pm:2042`).
  ShutterMode,
  /// `ImageSizeRAW` (0x003e, `Nikon.pm:2042`) — `{1=>'Large',2=>'Medium',
  /// 3=>'Small'}`.
  ImageSizeRaw,
  /// `JPGCompression` (0x0044, `Nikon.pm:2168-2175`) — `{1=>'Size Priority',
  /// 3=>'Optimal Quality'}`, with a `RawConv => '($val) ? $val : undef'`
  /// (`:2170`) that drops `0` (raw files) ⇒ the tag is NOT emitted.
  JpgCompression,
  /// `DateStampMode` (0x009d, `Nikon.pm:2925`).
  DateStampMode,
  /// `HighISONoiseReduction` (0x00b1, `Nikon.pm:3066`).
  HighIsoNr,
  /// `%Nikon::AFInfo` position 0 `AFAreaMode` (`Nikon.pm:2117`).
  AfAreaMode,
  /// `%Nikon::AFInfo` position 1 `AFPoint` (`Nikon.pm:2128`).
  AfPoint,
  /// `%Nikon::AFInfo` position 2 `AFPointsInFocus` (`%afPoints11`,
  /// `Nikon.pm:2152`) — a `0 => '(none)'` / `0x7ff => 'All 11 Points'` hash
  /// with a `DecodeBits` BITMASK fallback.
  AfPointsInFocus,
  /// `CropHiSpeed` (0x001b, `%cropHiSpeed`, `Nikon.pm:1974`) — `int16u[7]`; the
  /// `OTHER` sub maps element 0 via the crop-mode hash and formats the full
  /// record as `"<mode> (<W>x<H> cropped to <W>x<H> at pixel <X>,<Y>)"`.
  CropHiSpeed,
  /// `RetouchHistory` (0x009e, `Nikon.pm:2935`) — `int16u[10]`; ValueConv
  /// trims trailing ` 0` groups, the ARRAY PrintConv maps each element via
  /// `%retouchValues` and joins with `"; "` (`ExifTool.pm:3696`).
  RetouchHistory,
  /// `PowerUpTime` (0x00b6, `Nikon.pm:3071`) — `undef`; RawConv unpacks a
  /// 16-bit year (`v`/`n` by byte order) + 5 bytes (M/D/h/m/s) into
  /// `"YYYY:MM:DD HH:MM:SS"`; the PrintConv `ConvertDateTime` is identity.
  PowerUpTime,
  /// `NEFBitDepth` (0x0e22, `Nikon.pm:3280`) — `int16u[4]`; a space-joined
  /// PrintConv hash (`'8 8 8 0' => '8 x 3'`, …) keyed on the whole record.
  NefBitDepth,
  /// `%Nikon::LensData00/01` aperture members (`AFAperture`,
  /// `MaxApertureAtMinFocal`, `MaxApertureAtMaxFocal`, `EffectiveMaxAperture`)
  /// — `%nikonApertureConversions` (`Nikon.pm:5441`): `ValueConv =>
  /// '2**($val/24)'`, `PrintConv => sprintf("%.1f",$val)`.
  LensDataAperture,
  /// `%Nikon::LensData00/01` focal-length members (`FocalLength`,
  /// `MinFocalLength`, `MaxFocalLength`) — `%nikonFocalConversions`
  /// (`Nikon.pm:5448`): `ValueConv => '5 * 2**($val/24)'`, `PrintConv =>
  /// sprintf("%.1f mm",$val)`.
  LensDataFocal,
  /// `%Nikon::LensData01` `LensFStops` (0x0c) — `ValueConv => '$val / 12'`,
  /// `PrintConv => sprintf("%.2f", $val)` (`Nikon.pm:5552`). DISTINCT from the
  /// 0x008b `LensFStops` ([`Self::LensFStops`], a `c3` ValueConv).
  LensDataFStops,
  /// `%Nikon::LensData01` `ExitPupilPosition` (0x04) — `ValueConv => '$val ?
  /// 2048 / $val : $val'`, `PrintConv => sprintf("%.1f mm",$val)`
  /// (`Nikon.pm:5512`).
  ExitPupilPosition,
  /// `%Nikon::LensData01` `FocusPosition` (0x08) — `PrintConv =>
  /// sprintf("0x%02x", $val)` (`Nikon.pm:5524`), no ValueConv.
  FocusPosition,
  /// `%Nikon::LensData01` `FocusDistance` (0x09) — `ValueConv => '0.01 *
  /// 10**($val/40)'` (metres), `PrintConv => '$val ? sprintf("%.2f m",$val) :
  /// "inf"'` (`Nikon.pm:5538`).
  FocusDistance,
  /// `%Nikon::LensData0800` `LensID` (0x30, `int16u`, `Nikon.pm:5819-5875`) —
  /// the Nikkor-Z lens-name PrintConv hash. The raw value is the LensID
  /// integer; an unmapped value renders `Unknown (N)`. `-n` emits the integer.
  LensId,
  /// `%Nikon::LensData0800` `LensFirmwareVersion` (0x34, `int16u`,
  /// `Nikon.pm:5876-5886`) — the V.R.M PrintConv: `version=int($val/256)`,
  /// `release=int(($val-256*version)/16)`, `modification=$val-(256*version+
  /// 16*release)`, then `sprintf("%.0f.%.0f.%.0f", version, release,
  /// modification)`. No ValueConv (`-n` emits the raw integer).
  LensFirmwareZ,
  /// `%Nikon::LensData0800` `MaxAperture` (0x36) / `FNumber` (0x38) (`int16u`,
  /// `Nikon.pm:5887-5906`) — `ValueConv => '2**($val/384-1)'`, `PrintConv =>
  /// sprintf("%.1f",$val)`. `-n` emits the post-ValueConv float.
  LensApertureZ,
  /// `%Nikon::LensData0800` `FocalLength` (0x3c, `int16u`, `Nikon.pm:5907-
  /// 5914`) — NO ValueConv; `PrintConv => '"$val mm"'`. `-n` emits the raw
  /// integer.
  FocalLengthZ,
  /// `%Nikon::LensData0800` `FocusDistance` (0x4e, `int16u`, `Nikon.pm:5922-
  /// 5932`) — `RawConv => '$val = $val/256'` (the 1st byte is the fractional
  /// component), `ValueConv => '2**(($val-80)/12)'` (metres), then a nested
  /// PrintConv that picks the decimal precision from the magnitude. The "Inf"
  /// branch keys on `$$self{FocusStepsFromInfinity}`, which is `Unknown => 1`
  /// and therefore NEVER set in default mode (`next if Unknown`), so it is
  /// unreachable here. `-n` emits the post-ValueConv metres float.
  FocusDistanceZ,
  /// `%Nikon::LensData0800` `LensMountType` (0x5f, `int8u`, `Mask => 0x01`,
  /// `Nikon.pm:5953-5961`) — `{0=>'Z-mount',1=>'F-mount'}`. The Mask is applied
  /// by the caller BEFORE this PrintConv; the raw value here is already masked
  /// to 0/1. `-n` emits the masked integer.
  LensMountType,
  /// `%Nikon::FlashInfo0100` `FlashSource` (offset 4, `Nikon.pm:10824`) —
  /// `{0=>'None',1=>'External',2=>'Internal'}`.
  FlashSource,
  /// `%Nikon::FlashInfo0100` `FlashControlMode` / `FlashGroupAControlMode` /
  /// `FlashGroupBControlMode` (`Nikon.pm:829-838`, the shared `%flashControlMode`
  /// hash) — `{0=>'Off',1=>'iTTL-BL',…,7=>'Repeating Flash'}`. The `Mask` is
  /// applied by the caller; the raw value here is already masked.
  FlashControlMode,
  /// `%Nikon::FlashInfo0100` `ExternalFlashFlags` (offset 8, `Nikon.pm:10838`) —
  /// `PrintConv => { 0 => '(none)', BITMASK => { 0=>'Fired', 2=>'Bounce Flash',
  /// 4=>'Wide Flash Adapter', 5=>'Dome Diffuser' } }`. The `0` key short-circuits
  /// `(none)`; otherwise the `DecodeBits` walk (the same path `LensType` uses) —
  /// an unlisted set bit renders `[n]`. `-n` emits the raw int8u.
  ExternalFlashFlags,
  /// `%Nikon::FlashInfo0100` `FlashGNDistance` (offset 14, `Nikon.pm:792-815`,
  /// the `%flashGNDistance` hash) — `{0=>'0',1=>'0.1 m',…,255=>'n/a'}`. Key `0`
  /// maps to the bare string `"0"`; an unlisted value renders `Unknown (N)` —
  /// the standard ExifTool HASH-PrintConv miss fallback (`ExifTool.pm:3632`,
  /// no `BITMASK`/`OTHER`/`PrintHex` on this hash), via the shared `hash_conv`.
  /// `-n` emits the raw int8u.
  FlashGnDistance,
  /// `%Nikon::FlashInfo0100` `FlashOutput` / `FlashGroupAOutput` /
  /// `FlashGroupBOutput` (the `Manual`-arm of the offset-10/17/18 conditional,
  /// `Nikon.pm:10864`) — `ValueConv => '2 ** (-$val/6)'`, `PrintConv =>
  /// '$val>0.99 ? "Full" : sprintf("%.0f%%",$val*100)'`. `-n` emits the
  /// post-ValueConv float.
  FlashOutput,
  /// `%Nikon::FlashInfo0100` `FlashCompensation` (the non-Manual arm of offset
  /// 10, `Nikon.pm:10872-10879`) — `int8s`, `ValueConv => '-$val/6'`, `PrintConv
  /// => Image::ExifTool::Exif::PrintFraction`. `-n` emits the post-ValueConv
  /// float.
  FlashCompensation,
  /// `%Nikon::FlashInfo0100` `FlashGroupACompensation` / `FlashGroupBCompensation`
  /// (the non-Manual arm of offset 17/18, `Nikon.pm:10934-10939`) — `int8s`,
  /// `ValueConv => '-$val/6'`, `PrintConv => '$val ? sprintf("%+.1f",$val) : 0'`
  /// (NOT PrintFraction — a `%+.1f` render, and exactly 0 renders the integer
  /// `0`). `-n` emits the post-ValueConv float.
  FlashGroupCompensation,
  /// `%Nikon::FlashInfo0100` `FlashFocalLength` (offset 11, `Nikon.pm:10882`) —
  /// `RawConv => '$val ? $val : undef'` (a raw `0` ⇒ the tag is NOT emitted),
  /// `PrintConv => '"$val mm"'`. `-n` emits the raw int8u.
  FlashFocalLength,
  /// `%Nikon::FlashInfo0100` `RepeatingFlashRate` (offset 12, `Nikon.pm:10889`) —
  /// `RawConv => '$val ? $val : undef'` (0 ⇒ drop), `PrintConv => '"$val Hz"'`.
  /// `-n` emits the raw int8u.
  RepeatingFlashRate,
  /// `%Nikon::ShotInfo` `VibrationReduction` 0x75 (`Nikon.pm:6037`, the `0207`
  /// D200 arm) — `int8u`, `{0=>'Off',1=>'On (1)',2=>'On (2)',3=>'On (3)'}`. A
  /// miss renders `Unknown (N)` (no PrintHex on this hash). `-n` emits the raw
  /// int8u.
  ShotInfoVibrationReduction0207,
  /// `%Nikon::ShotInfo` `VibrationReduction` 0x1ae (`Nikon.pm:6075`, the `0205`
  /// D50 arm) — `int8u`, `PrintHex => 1`, `{0x00=>'n/a',0x0c=>'Off',
  /// 0x0f=>'On'}`. With `PrintHex` an unmapped value renders `Unknown (0xNN)`
  /// (`ExifTool.pm:3632` uses the hex `$val` when `PrintHex`). `-n` emits the
  /// raw int8u.
  ShotInfoVibrationReduction0205,
}

impl NikonConv {
  /// Apply this conversion to the decoded value, returning the converted
  /// [`TagValue`] — or `None` when a `RawConv => … : undef` drops the value
  /// (the tag is then NOT emitted, matching ExifTool: a RawConv that returns
  /// `undef` suppresses the tag). Of the ported Nikon::Main tags, only
  /// `JPGCompression` (0x0044, `RawConv => '($val) ? $val : undef'`,
  /// `Nikon.pm:2170`) has a RawConv that actually fires — it drops the
  /// raw-file `0`, so this conv returns `None` for raw `0`. Every other conv
  /// returns `Some(_)`. (The ISO 0x0002 `$val eq "\0\0\0\0"` RawConv looks
  /// similar but is DEAD — see [`Self::Iso`] — so ISO never drops.) The leaf
  /// walker SKIPS a `None` (does not push), the same way the Canon binary
  /// tables drop their `RawConv … undef` positions.
  ///
  /// `print_conv = false` (`-n`) emits the post-ValueConv raw scalar;
  /// `print_conv = true` (the `-j` default) renders the human string.
  /// `model` threads the parent IFD0 `Model` for the few model-conditional
  /// PrintConv branches (`ShootingMode` bit 5). `order` is the byte order in
  /// effect for the MakerNote IFD (`GetByteOrder()`) — needed by the few
  /// RawConvs that unpack multi-byte fields from `undef` data (`PowerUpTime`).
  #[must_use]
  pub fn apply(
    self,
    raw: &ParsedValue,
    print_conv: bool,
    model: Option<&str>,
    order: ByteOrder,
  ) -> Option<TagValue> {
    Some(match self {
      // `RawConv => '($val) ? $val : undef'` (`Nikon.pm:2170`): a raw `0`
      // (the raw-file marker) is `undef` ⇒ the tag is NOT emitted.
      NikonConv::JpgCompression => return jpg_compression_conv(raw, print_conv),
      NikonConv::Raw => raw.to_default_tag_value(),
      NikonConv::FormatString => {
        // ValueConv is identity; the table-default PrintConv title-cases a
        // string value. `-n` mode emits the un-title-cased string.
        match raw.as_text() {
          Some(s) if print_conv => TagValue::Str(SmolStr::new(format_string(s))),
          Some(s) => TagValue::Str(SmolStr::new(s)),
          None => raw.to_default_tag_value(),
        }
      }
      NikonConv::MakerNoteVersion => {
        let s = maker_note_version_value(raw);
        if print_conv {
          TagValue::Str(SmolStr::new(maker_note_version_print(&s)))
        } else {
          TagValue::Str(SmolStr::new(s))
        }
      }
      NikonConv::Iso => iso_conv(raw, print_conv),
      NikonConv::IsoSetting => iso_setting_conv(raw, print_conv),
      NikonConv::SignedFractionPrintFraction | NikonConv::FlashExposureComp => {
        let Some(v) = raw.signed_fraction_c3() else {
          return Some(raw.to_default_tag_value());
        };
        if print_conv {
          TagValue::Str(SmolStr::new(print_fraction(v)))
        } else {
          value_conv_number(v)
        }
      }
      NikonConv::ExposureDifference => {
        let Some(v) = raw.signed_fraction_c3() else {
          return Some(raw.to_default_tag_value());
        };
        if print_conv {
          // `$val ? sprintf("%+.1f",$val) : 0`.
          if v == 0.0 {
            TagValue::I64(0)
          } else {
            TagValue::Str(SmolStr::new(std::format!("{v:+.1}")))
          }
        } else {
          value_conv_number(v)
        }
      }
      NikonConv::BracketFloat1 => bracket_float1(raw, print_conv),
      NikonConv::LensType => lens_type_conv(raw, print_conv),
      NikonConv::Lens => lens_conv(raw, print_conv),
      NikonConv::FlashMode => hash_conv(raw, print_conv, flash_mode_label),
      NikonConv::ShootingMode => shooting_mode_conv(raw, print_conv, model),
      NikonConv::LensFStops => {
        let Some(v) = raw.signed_fraction_c3() else {
          return Some(raw.to_default_tag_value());
        };
        if print_conv {
          TagValue::Str(SmolStr::new(std::format!("{v:.2}")))
        } else {
          value_conv_number(v)
        }
      }
      NikonConv::NefCompression => hash_conv(raw, print_conv, nef_compression_label),
      NikonConv::ColorSpace => hash_conv(raw, print_conv, color_space_label),
      NikonConv::ShutterCount => {
        let Some(n) = raw.first_i64() else {
          return Some(raw.to_default_tag_value());
        };
        if print_conv && n == 4_294_965_247 {
          TagValue::Str(SmolStr::new("n/a"))
        } else {
          TagValue::I64(n)
        }
      }
      NikonConv::ExposureBracketRational => {
        // `rational64s`; PrintConv `$val !~ /undef/ ? PrintFraction : "n/a"`.
        // The decoded `$val` is the single rational's decimal scalar; an
        // `undef` (0/0) rational renders the bare word `undef` → "n/a".
        let Some(joined) = raw.rational_join_decimal() else {
          return Some(raw.to_default_tag_value());
        };
        if print_conv {
          if joined.contains("undef") {
            TagValue::Str(SmolStr::new("n/a"))
          } else {
            let v: f64 = joined.parse().unwrap_or(0.0);
            TagValue::Str(SmolStr::new(print_fraction(v)))
          }
        } else {
          TagValue::Str(SmolStr::new(joined))
        }
      }
      NikonConv::SensorPixelSize => {
        let Some(joined) = raw.rational_join_decimal() else {
          return Some(raw.to_default_tag_value());
        };
        if print_conv {
          // s/ / x / then append " um".
          TagValue::Str(SmolStr::new(std::format!(
            "{} um",
            joined.replace(' ', " x ")
          )))
        } else {
          TagValue::Str(SmolStr::new(joined))
        }
      }
      NikonConv::OffOn => hash_conv(raw, print_conv, off_on_label),
      NikonConv::ActiveDLighting => hash_conv(raw, print_conv, active_d_lighting_label),
      NikonConv::VignetteControl => hash_conv(raw, print_conv, vignette_control_label),
      NikonConv::ShutterMode => hash_conv(raw, print_conv, shutter_mode_label),
      NikonConv::ImageSizeRaw => hash_conv(raw, print_conv, image_size_raw_label),
      NikonConv::DateStampMode => hash_conv(raw, print_conv, date_stamp_mode_label),
      NikonConv::HighIsoNr => hash_conv(raw, print_conv, high_iso_nr_label),
      NikonConv::AfAreaMode => hash_conv(raw, print_conv, af_area_mode_label),
      NikonConv::AfPoint => hash_conv(raw, print_conv, af_point_label),
      NikonConv::AfPointsInFocus => af_points_in_focus_conv(raw, print_conv),
      NikonConv::CropHiSpeed => crop_hi_speed_conv(raw, print_conv),
      NikonConv::RetouchHistory => retouch_history_conv(raw, print_conv),
      NikonConv::PowerUpTime => power_up_time_conv(raw, print_conv, order),
      NikonConv::NefBitDepth => nef_bit_depth_conv(raw, print_conv),
      NikonConv::LensDataAperture => {
        // `2**($val/24)`; PrintConv `sprintf("%.1f",$val)`.
        let Some(n) = raw.first_i64() else {
          return Some(raw.to_default_tag_value());
        };
        let v = 2f64.powf(n as f64 / 24.0);
        if print_conv {
          TagValue::Str(SmolStr::new(std::format!("{v:.1}")))
        } else {
          TagValue::F64(v)
        }
      }
      NikonConv::LensDataFocal => {
        // `5 * 2**($val/24)`; PrintConv `sprintf("%.1f mm",$val)`.
        let Some(n) = raw.first_i64() else {
          return Some(raw.to_default_tag_value());
        };
        let v = 5.0 * 2f64.powf(n as f64 / 24.0);
        if print_conv {
          TagValue::Str(SmolStr::new(std::format!("{v:.1} mm")))
        } else {
          TagValue::F64(v)
        }
      }
      NikonConv::LensDataFStops => {
        // `$val / 12`; PrintConv `sprintf("%.2f", $val)`.
        let Some(n) = raw.first_i64() else {
          return Some(raw.to_default_tag_value());
        };
        let v = n as f64 / 12.0;
        if print_conv {
          TagValue::Str(SmolStr::new(std::format!("{v:.2}")))
        } else {
          value_conv_number(v)
        }
      }
      NikonConv::ExitPupilPosition => {
        // `$val ? 2048 / $val : $val`; PrintConv `sprintf("%.1f mm",$val)`.
        let Some(n) = raw.first_i64() else {
          return Some(raw.to_default_tag_value());
        };
        let v = if n != 0 { 2048.0 / n as f64 } else { 0.0 };
        if print_conv {
          TagValue::Str(SmolStr::new(std::format!("{v:.1} mm")))
        } else {
          value_conv_number(v)
        }
      }
      NikonConv::FocusPosition => {
        // No ValueConv; PrintConv `sprintf("0x%02x", $val)`.
        let Some(n) = raw.first_i64() else {
          return Some(raw.to_default_tag_value());
        };
        if print_conv {
          TagValue::Str(SmolStr::new(std::format!("0x{n:02x}")))
        } else {
          TagValue::I64(n)
        }
      }
      NikonConv::FocusDistance => {
        // `0.01 * 10**($val/40)` (metres); PrintConv `$val ? sprintf("%.2f
        // m",$val) : "inf"`. The ValueConv-then-PrintConv `$val` is the
        // post-ValueConv metres; a raw `0` ⇒ ValueConv `0.01` (non-zero) ⇒ NOT
        // "inf" — "inf" only when the ValueConv result is zero, which never
        // happens (`0.01 * 10**x > 0`). Faithful: a zero ValueConv would print
        // "inf", but it is unreachable on this conversion.
        let Some(n) = raw.first_i64() else {
          return Some(raw.to_default_tag_value());
        };
        let v = 0.01 * 10f64.powf(n as f64 / 40.0);
        if print_conv {
          if v == 0.0 {
            TagValue::Str(SmolStr::new("inf"))
          } else {
            TagValue::Str(SmolStr::new(std::format!("{v:.2} m")))
          }
        } else {
          value_conv_number(v)
        }
      }
      NikonConv::LensId => {
        // `int16u` hash (`Nikon.pm:5825-5874`); unmapped → `Unknown (N)`.
        let Some(n) = raw.first_i64() else {
          return Some(raw.to_default_tag_value());
        };
        if print_conv {
          match lens_id_z_label(n) {
            Some(s) => TagValue::Str(SmolStr::new(s)),
            None => TagValue::Str(SmolStr::new(std::format!("Unknown ({n})"))),
          }
        } else {
          TagValue::I64(n)
        }
      }
      NikonConv::LensFirmwareZ => {
        // No ValueConv; PrintConv decomposes the int16u into V.R.M
        // (`Nikon.pm:5880-5885`). `-n` emits the raw integer.
        let Some(n) = raw.first_i64() else {
          return Some(raw.to_default_tag_value());
        };
        if print_conv {
          // int() truncates toward zero (the values are non-negative int16u).
          let version = n / 256;
          let release = (n - 256 * version) / 16;
          let modification = n - (256 * version + 16 * release);
          TagValue::Str(SmolStr::new(std::format!(
            "{version}.{release}.{modification}"
          )))
        } else {
          TagValue::I64(n)
        }
      }
      NikonConv::LensApertureZ => {
        // `2**($val/384-1)`; PrintConv `sprintf("%.1f",$val)`
        // (`Nikon.pm:5892-5894`).
        let Some(n) = raw.first_i64() else {
          return Some(raw.to_default_tag_value());
        };
        let v = 2f64.powf(n as f64 / 384.0 - 1.0);
        if print_conv {
          TagValue::Str(SmolStr::new(std::format!("{v:.1}")))
        } else {
          TagValue::F64(v)
        }
      }
      NikonConv::FocalLengthZ => {
        // No ValueConv; PrintConv `"$val mm"` (`Nikon.pm:5912`). `-n` emits the
        // raw integer.
        let Some(n) = raw.first_i64() else {
          return Some(raw.to_default_tag_value());
        };
        if print_conv {
          TagValue::Str(SmolStr::new(std::format!("{n} mm")))
        } else {
          TagValue::I64(n)
        }
      }
      NikonConv::FocusDistanceZ => return Some(focus_distance_z_conv(raw, print_conv)),
      NikonConv::LensMountType => {
        // `{0=>'Z-mount',1=>'F-mount'}` (`Nikon.pm:5957-5960`); the Mask 0x01 is
        // applied by the caller, so `$val` here is already 0/1. An unmapped
        // value (impossible after the mask) renders `Unknown (N)`.
        let Some(n) = raw.first_i64() else {
          return Some(raw.to_default_tag_value());
        };
        if print_conv {
          match n {
            0 => TagValue::Str(SmolStr::new("Z-mount")),
            1 => TagValue::Str(SmolStr::new("F-mount")),
            _ => TagValue::Str(SmolStr::new(std::format!("Unknown ({n})"))),
          }
        } else {
          TagValue::I64(n)
        }
      }
      NikonConv::FlashSource => hash_conv(raw, print_conv, flash_source_label),
      NikonConv::FlashControlMode => hash_conv(raw, print_conv, flash_control_mode_label),
      NikonConv::ExternalFlashFlags => external_flash_flags_conv(raw, print_conv),
      NikonConv::FlashGnDistance => hash_conv(raw, print_conv, flash_gn_distance_label),
      NikonConv::FlashOutput => {
        // `ValueConv => '2 ** (-$val/6)'`; PrintConv `$val>0.99 ? "Full" :
        // sprintf("%.0f%%",$val*100)`.
        let Some(n) = raw.first_i64() else {
          return Some(raw.to_default_tag_value());
        };
        let v = 2f64.powf(-(n as f64) / 6.0);
        if print_conv {
          if v > 0.99 {
            TagValue::Str(SmolStr::new("Full"))
          } else {
            TagValue::Str(SmolStr::new(std::format!("{}%", flash_pct(v * 100.0))))
          }
        } else {
          TagValue::F64(v)
        }
      }
      NikonConv::FlashCompensation => {
        // `int8s`, `ValueConv => '-$val/6'`, PrintConv PrintFraction.
        let Some(n) = raw.first_i64() else {
          return Some(raw.to_default_tag_value());
        };
        let v = -(n as f64) / 6.0;
        if print_conv {
          TagValue::Str(SmolStr::new(print_fraction(v)))
        } else {
          value_conv_number(v)
        }
      }
      NikonConv::FlashGroupCompensation => {
        // `int8s`, `ValueConv => '-$val/6'`, PrintConv `$val ?
        // sprintf("%+.1f",$val) : 0` (the integer 0 for an exact-zero value).
        let Some(n) = raw.first_i64() else {
          return Some(raw.to_default_tag_value());
        };
        let v = -(n as f64) / 6.0;
        if print_conv {
          if v == 0.0 {
            TagValue::I64(0)
          } else {
            TagValue::Str(SmolStr::new(std::format!("{v:+.1}")))
          }
        } else {
          value_conv_number(v)
        }
      }
      NikonConv::FlashFocalLength => {
        // `RawConv => '$val ? $val : undef'` (0 ⇒ drop), PrintConv `"$val mm"`.
        let Some(n) = raw.first_i64() else {
          return Some(raw.to_default_tag_value());
        };
        if n == 0 {
          return None;
        }
        if print_conv {
          TagValue::Str(SmolStr::new(std::format!("{n} mm")))
        } else {
          TagValue::I64(n)
        }
      }
      NikonConv::RepeatingFlashRate => {
        // `RawConv => '$val ? $val : undef'` (0 ⇒ drop), PrintConv `"$val Hz"`.
        let Some(n) = raw.first_i64() else {
          return Some(raw.to_default_tag_value());
        };
        if n == 0 {
          return None;
        }
        if print_conv {
          TagValue::Str(SmolStr::new(std::format!("{n} Hz")))
        } else {
          TagValue::I64(n)
        }
      }
      NikonConv::ShotInfoVibrationReduction0207 => {
        hash_conv(raw, print_conv, shot_info_vr_0207_label)
      }
      NikonConv::ShotInfoVibrationReduction0205 => {
        // `PrintHex => 1`: a hash MISS renders the hex `$val` (`Unknown (0xNN)`),
        // not the decimal (`ExifTool.pm:3632`). `-n` emits the raw int8u.
        let Some(n) = raw.first_i64() else {
          return Some(raw.to_default_tag_value());
        };
        if print_conv {
          match shot_info_vr_0205_label(n) {
            Some(s) => TagValue::Str(SmolStr::new(s)),
            None => TagValue::Str(SmolStr::new(std::format!("Unknown (0x{n:x})"))),
          }
        } else {
          TagValue::I64(n)
        }
      }
    })
  }
}

/// `%Nikon::LensData0800` `FocusDistance` (0x4e) ValueConv + PrintConv
/// (`Nikon.pm:5922-5932`). The decoded `$val` is the raw `int16u`; RawConv
/// `$val = $val/256` (the 1st byte is the fractional part), ValueConv
/// `2**(($val-80)/12)` (metres). The PrintConv selects the decimal precision by
/// magnitude:
///
/// ```text
/// $val < 100 ? $val < 10 ? $val < 1 ? $val < 0.35 ? "%.4f m" : "%.3f m"
///                                                  : "%.2f m"
///                                   : "%.1f m"
///                        : "%.0f m"
/// ```
///
/// The leading `(defined $$self{FocusStepsFromInfinity} and … eq 0) ? "Inf"`
/// branch keys on a `Unknown => 1` DataMember, which is never set in default
/// mode (`next if $$tagInfo{Unknown}`), so it is unreachable and omitted.
/// `-n` emits the post-ValueConv metres float.
fn focus_distance_z_conv(raw: &ParsedValue, print_conv: bool) -> TagValue {
  let Some(n) = raw.first_i64() else {
    return raw.to_default_tag_value();
  };
  // RawConv `$val = $val/256` then ValueConv `2**(($val-80)/12)`.
  let raw_div = n as f64 / 256.0;
  let v = 2f64.powf((raw_div - 80.0) / 12.0);
  if !print_conv {
    return value_conv_number(v);
  }
  let s = if v < 100.0 {
    if v < 10.0 {
      if v < 1.0 {
        if v < 0.35 {
          std::format!("{v:.4} m")
        } else {
          std::format!("{v:.3} m")
        }
      } else {
        std::format!("{v:.2} m")
      }
    } else {
      std::format!("{v:.1} m")
    }
  } else {
    std::format!("{v:.0} m")
  };
  TagValue::Str(SmolStr::new(s))
}

/// `%Nikon::LensData0800` `LensID` (0x30) PrintConv hash (`Nikon.pm:5825-5874`)
/// — the Nikkor-Z lens-name table. A non-zero LensID denotes a native Z lens;
/// `0` / an unlisted value falls through to `Unknown (N)` at the call site. The
/// keys are NOT contiguous (the two 327xx entries are the TC-1.4x teleconverter
/// combinations).
fn lens_id_z_label(n: i64) -> Option<&'static str> {
  Some(match n {
    1 => "Nikkor Z 24-70mm f/4 S",
    2 => "Nikkor Z 14-30mm f/4 S",
    4 => "Nikkor Z 35mm f/1.8 S",
    8 => "Nikkor Z 58mm f/0.95 S Noct",
    9 => "Nikkor Z 50mm f/1.8 S",
    11 => "Nikkor Z DX 16-50mm f/3.5-6.3 VR",
    12 => "Nikkor Z DX 50-250mm f/4.5-6.3 VR",
    13 => "Nikkor Z 24-70mm f/2.8 S",
    14 => "Nikkor Z 85mm f/1.8 S",
    15 => "Nikkor Z 24mm f/1.8 S",
    16 => "Nikkor Z 70-200mm f/2.8 VR S",
    17 => "Nikkor Z 20mm f/1.8 S",
    18 => "Nikkor Z 24-200mm f/4-6.3 VR",
    21 => "Nikkor Z 50mm f/1.2 S",
    22 => "Nikkor Z 24-50mm f/4-6.3",
    23 => "Nikkor Z 14-24mm f/2.8 S",
    24 => "Nikkor Z MC 105mm f/2.8 VR S",
    25 => "Nikkor Z 40mm f/2",
    26 => "Nikkor Z DX 18-140mm f/3.5-6.3 VR",
    27 => "Nikkor Z MC 50mm f/2.8",
    28 => "Nikkor Z 100-400mm f/4.5-5.6 VR S",
    29 => "Nikkor Z 28mm f/2.8",
    30 => "Nikkor Z 400mm f/2.8 TC VR S",
    31 => "Nikkor Z 24-120mm f/4 S",
    32 => "Nikkor Z 800mm f/6.3 VR S",
    35 => "Nikkor Z 28-75mm f/2.8",
    36 => "Nikkor Z 400mm f/4.5 VR S",
    37 => "Nikkor Z 600mm f/4 TC VR S",
    38 => "Nikkor Z 85mm f/1.2 S",
    39 => "Nikkor Z 17-28mm f/2.8",
    40 => "Nikkor Z 26mm f/2.8",
    41 => "Nikkor Z DX 12-28mm f/3.5-5.6 PZ VR",
    42 => "Nikkor Z 180-600mm f/5.6-6.3 VR",
    43 => "Nikkor Z DX 24mm f/1.7",
    44 => "Nikkor Z 70-180mm f/2.8",
    45 => "Nikkor Z 600mm f/6.3 VR S",
    46 => "Nikkor Z 135mm f/1.8 S Plena",
    47 => "Nikkor Z 35mm f/1.2 S",
    48 => "Nikkor Z 28-400mm f/4-8 VR",
    49 => "Nikkor Z 28-135mm f/4 PZ",
    50 => "Nikkor Z 24-70mm f/2.8 S II",
    51 => "Nikkor Z 35mm f/1.4",
    52 => "Nikkor Z 50mm f/1.4",
    54 => "Nikkor Z 70-200mm f/2.8 VR S II",
    57 => "Nikkor Z 24-105mm f/4-7.1",
    2305 => "Laowa FFII 10mm F2.8 C&D Dreamer",
    32768 => "Nikkor Z 400mm f/2.8 TC VR S TC-1.4x",
    32769 => "Nikkor Z 600mm f/4 TC VR S TC-1.4x",
    _ => return None,
  })
}

/// `%afPoints11` (`Nikon.pm:2152`) PrintConv: `0 => '(none)'`,
/// `0x7ff => 'All 11 Points'`, else a `DecodeBits` BITMASK over the 11 AF
/// points. ExifTool checks the direct hash key FIRST, then falls to BITMASK
/// (`ExifTool.pm:3603-3624`).
fn af_points_in_focus_conv(raw: &ParsedValue, print_conv: bool) -> TagValue {
  let Some(n) = raw.first_i64() else {
    return raw.to_default_tag_value();
  };
  if !print_conv {
    return TagValue::I64(n);
  }
  match n {
    0 => TagValue::Str(SmolStr::new("(none)")),
    0x7ff => TagValue::Str(SmolStr::new("All 11 Points")),
    _ => TagValue::Str(SmolStr::new(crate::convert::decode_bits(
      &n.to_string(),
      Some(AF_POINTS11_BITS),
      32,
    ))),
  }
}

/// `CropHiSpeed` (0x001b, `%cropHiSpeed`, `Nikon.pm:1974`). The decoded `$val`
/// is the space-joined `int16u[7]` string. The `OTHER` sub: with exactly 7
/// elements, map element 0 via the crop-mode hash (else `Unknown (N)`) and
/// format `"<mode> (<a1>x<a2> cropped to <a3>x<a4> at pixel <a5>,<a6>)"`; any
/// other count renders `Unknown ($val)`. `-n` emits the raw joined string.
fn crop_hi_speed_conv(raw: &ParsedValue, print_conv: bool) -> TagValue {
  let Some(val) = raw.int_list_val_string() else {
    return raw.to_default_tag_value();
  };
  if !print_conv {
    return TagValue::Str(SmolStr::new(val));
  }
  let a: Vec<&str> = val.split(' ').collect();
  if a.len() != 7 {
    return TagValue::Str(SmolStr::new(std::format!("Unknown ({val})")));
  }
  let mode = a
    .first()
    .and_then(|s| s.parse::<i64>().ok())
    .and_then(crop_hi_speed_label)
    .map_or_else(
      || std::format!("Unknown ({})", a.first().copied().unwrap_or("")),
      std::string::ToString::to_string,
    );
  TagValue::Str(SmolStr::new(std::format!(
    "{mode} ({}x{} cropped to {}x{} at pixel {},{})",
    a.get(1).copied().unwrap_or(""),
    a.get(2).copied().unwrap_or(""),
    a.get(3).copied().unwrap_or(""),
    a.get(4).copied().unwrap_or(""),
    a.get(5).copied().unwrap_or(""),
    a.get(6).copied().unwrap_or(""),
  )))
}

/// `RetouchHistory` (0x009e, `Nikon.pm:2935`). ValueConv `$val=~s/( 0)+$//`
/// trims trailing ` 0` groups from the space-joined `int16u[10]` string; the
/// ARRAY PrintConv maps each remaining element via `%retouchValues` (unmapped
/// → `Unknown (N)`) and joins with `"; "` (`ExifTool.pm:3696`). `-n` emits the
/// post-ValueConv (trimmed) raw string.
fn retouch_history_conv(raw: &ParsedValue, print_conv: bool) -> TagValue {
  let Some(val) = raw.int_list_val_string() else {
    return raw.to_default_tag_value();
  };
  // s/( 0)+$// — strip trailing " 0" groups.
  let mut trimmed = val.as_str();
  while let Some(head) = trimmed.strip_suffix(" 0") {
    trimmed = head;
  }
  if !print_conv {
    return TagValue::Str(SmolStr::new(trimmed));
  }
  let mut out = String::new();
  for (i, tok) in trimmed.split(' ').enumerate() {
    if i > 0 {
      out.push_str("; ");
    }
    match tok.parse::<i64>().ok().and_then(retouch_value_label) {
      Some(s) => out.push_str(s),
      None => out.push_str(&std::format!("Unknown ({tok})")),
    }
  }
  TagValue::Str(SmolStr::new(out))
}

/// `PowerUpTime` (0x00b6, `Nikon.pm:3071`). RawConv: a value shorter than 7
/// bytes passes through verbatim; otherwise unpack a 16-bit year (`v`/`n` per
/// byte order) + 5 bytes (month/day/hour/min/sec) → `"YYYY:MM:DD HH:MM:SS"`.
/// The PrintConv `$self->ConvertDateTime($val)` is identity (no DateFormat).
fn power_up_time_conv(raw: &ParsedValue, print_conv: bool, order: ByteOrder) -> TagValue {
  let _ = print_conv; // ConvertDateTime is identity ⇒ value is the same string.
  let bytes = raw.undef_or_text_bytes();
  if bytes.len() < 7 {
    return raw.to_default_tag_value();
  }
  let (y0, y1) = (bytes.first().copied(), bytes.get(1).copied());
  let (Some(y0), Some(y1)) = (y0, y1) else {
    return raw.to_default_tag_value();
  };
  let year = match order {
    ByteOrder::Little => u16::from_le_bytes([y0, y1]),
    ByteOrder::Big => u16::from_be_bytes([y0, y1]),
  };
  let month = bytes.get(2).copied().unwrap_or(0);
  let day = bytes.get(3).copied().unwrap_or(0);
  let hour = bytes.get(4).copied().unwrap_or(0);
  let min = bytes.get(5).copied().unwrap_or(0);
  let sec = bytes.get(6).copied().unwrap_or(0);
  TagValue::Str(SmolStr::new(std::format!(
    "{year:04}:{month:02}:{day:02} {hour:02}:{min:02}:{sec:02}"
  )))
}

/// `NEFBitDepth` (0x0e22, `Nikon.pm:3280`) — `int16u[4]`, a PrintConv hash
/// keyed on the whole space-joined record (`'8 8 8 0' => '8 x 3'`, …); an
/// unmapped record renders `Unknown ($val)`. `-n` emits the raw joined string.
fn nef_bit_depth_conv(raw: &ParsedValue, print_conv: bool) -> TagValue {
  let Some(val) = raw.int_list_val_string() else {
    return raw.to_default_tag_value();
  };
  if !print_conv {
    return TagValue::Str(SmolStr::new(val));
  }
  let label = match val.as_str() {
    "0 0 0 0" => "n/a (JPEG)",
    "8 8 8 0" => "8 x 3",
    "16 16 16 0" => "16 x 3",
    "12 0 0 0" => "12",
    "14 0 0 0" => "14",
    other => return TagValue::Str(SmolStr::new(std::format!("Unknown ({other})"))),
  };
  TagValue::Str(SmolStr::new(label))
}

/// `%cropHiSpeed` (`Nikon.pm:1974`) crop-mode labels (element 0).
fn crop_hi_speed_label(n: i64) -> Option<&'static str> {
  Some(match n {
    0 => "Off",
    1 => "1.3x Crop",
    2 => "DX Crop",
    3 => "5:4 Crop",
    4 => "3:2 Crop",
    6 => "16:9 Crop",
    8 => "2.7x Crop",
    9 => "DX Movie 16:9 Crop",
    10 => "1.3x Movie Crop",
    11 => "FX Uncropped",
    12 => "DX Uncropped",
    13 => "2.8x Movie Crop",
    14 => "1.4x Movie Crop",
    15 => "1.5x Movie Crop",
    17 => "FX 1:1 Crop",
    18 => "DX 1:1 Crop",
    _ => return None,
  })
}

/// `%retouchValues` (`Nikon.pm`) — the in-camera retouch-effect labels.
fn retouch_value_label(n: i64) -> Option<&'static str> {
  Some(match n {
    0 => "None",
    3 => "B & W",
    4 => "Sepia",
    5 => "Trim",
    6 => "Small Picture",
    7 => "D-Lighting",
    8 => "Red Eye",
    9 => "Cyanotype",
    10 => "Sky Light",
    11 => "Warm Tone",
    12 => "Color Custom",
    13 => "Image Overlay",
    14 => "Red Intensifier",
    15 => "Green Intensifier",
    16 => "Blue Intensifier",
    17 => "Cross Screen",
    18 => "Quick Retouch",
    19 => "NEF Processing",
    23 => "Distortion Control",
    25 => "Fisheye",
    26 => "Straighten",
    29 => "Perspective Control",
    30 => "Color Outline",
    31 => "Soft Filter",
    32 => "Resize",
    33 => "Miniature Effect",
    34 => "Skin Softening",
    35 => "Selected Frame",
    37 => "Color Sketch",
    38 => "Selective Color",
    39 => "Glamour",
    40 => "Drawing",
    44 => "Pop",
    45 => "Toy Camera Effect 1",
    46 => "Toy Camera Effect 2",
    47 => "Cross Process (red)",
    48 => "Cross Process (blue)",
    49 => "Cross Process (green)",
    50 => "Cross Process (yellow)",
    51 => "Super Vivid",
    52 => "High-contrast Monochrome",
    53 => "High Key",
    54 => "Low Key",
    _ => return None,
  })
}

/// `-n`/ValueConv numeric: emit an integer if the fraction is integral, else
/// a float (mirrors Perl's dualvar — a `0` ValueConv emits `0`, `-4.9` emits
/// the float). The JSON writer then renders the bare number.
fn value_conv_number(v: f64) -> TagValue {
  if v == 0.0 {
    TagValue::I64(0)
  } else if v.fract() == 0.0 && v.abs() < 1e15 {
    TagValue::I64(v as i64)
  } else {
    TagValue::F64(v)
  }
}

/// `Image::ExifTool::Exif::PrintFraction($val)` (`Exif.pm`) — the faithful
/// transliteration:
///
/// ```perl
/// $val *= 1.00001;                       # avoid round-off errors
/// if (not $val)                  { '0' }
/// elsif (int($val)/$val > 0.999) { sprintf("%+d", int($val)) }
/// elsif (int($val*2)/($val*2) > 0.999) { sprintf("%+d/2", int($val*2)) }
/// elsif (int($val*3)/($val*3) > 0.999) { sprintf("%+d/3", int($val*3)) }
/// else                           { sprintf("%+.3g", $val) }
/// ```
///
/// e.g. `-5/3 ≈ -1.6667` → `"-5/3"`, `-4.9` → `"-4.9"` (the `%+.3g` arm).
fn print_fraction(v: f64) -> String {
  let val = v * 1.000_01;
  // `not $val` is Perl-falsy for 0 (and the un-multiplied 0 stays 0).
  if val == 0.0 {
    return "0".to_string();
  }
  // int() truncates toward zero (Perl `int`).
  let trunc = val.trunc();
  if trunc / val > 0.999 {
    return std::format!("{:+}", trunc as i64);
  }
  let v2 = val * 2.0;
  if v2.trunc() / v2 > 0.999 {
    return std::format!("{:+}/2", v2.trunc() as i64);
  }
  let v3 = val * 3.0;
  if v3.trunc() / v3 > 0.999 {
    return std::format!("{:+}/3", v3.trunc() as i64);
  }
  // sprintf("%+.3g", $val) — 3 significant figures with a forced sign.
  format_g_signed(val, 3)
}

/// `sprintf("%+.{prec}g", val)` — the `%g` form with a forced leading sign.
/// Reuses the shared `%g` renderer (`crate::value::format_g`) and prepends
/// `+` for non-negative values (the renderer already emits `-` for negatives).
fn format_g_signed(val: f64, prec: usize) -> String {
  let body = crate::value::format_g(val, prec);
  if body.starts_with('-') {
    body
  } else {
    std::format!("+{body}")
  }
}

/// `MakerNoteVersion` ValueConv (`Nikon.pm:1791`):
/// `$_=$val; /^[\x00-\x09]/ and $_=join("",unpack("CCCC",$_)); $_`.
/// A value whose first byte is in `0x00..=0x09` is BINARY — render each of
/// the 4 bytes as a decimal digit string; otherwise the value is already the
/// ASCII digit string (e.g. `"0210"`).
fn maker_note_version_value(raw: &ParsedValue) -> String {
  let bytes = raw.undef_or_text_bytes();
  match bytes.first() {
    Some(&b) if b <= 0x09 => {
      // join("", unpack("CCCC")) — the 4 bytes as concatenated decimals.
      let mut s = String::new();
      for &byte in bytes.iter().take(4) {
        s.push_str(&byte.to_string());
      }
      s
    }
    _ => String::from_utf8_lossy(&bytes).into_owned(),
  }
}

/// `MakerNoteVersion` PrintConv (`Nikon.pm:1793`):
/// `$_=$val;s/^(\d{2})/$1\./;s/^0//;$_` — a dot after the first two digits,
/// then strip a leading zero.
fn maker_note_version_print(val: &str) -> String {
  // s/^(\d{2})/$1./  — only if the first two chars are digits.
  let mut s = String::from(val);
  let first_two_digits = s.as_bytes().first().is_some_and(u8::is_ascii_digit)
    && s.as_bytes().get(1).is_some_and(u8::is_ascii_digit);
  if first_two_digits {
    // Insert a '.' after index 2.
    let (head, tail) = s.split_at(2);
    s = std::format!("{head}.{tail}");
  }
  // s/^0//
  if let Some(rest) = s.strip_prefix('0') {
    s = rest.to_string();
  }
  s
}

/// `ISO` (0x0002) ValueConv + PrintConv. The decoded `int16u[2]` is rendered
/// by `ReadValue` as `"A B"`; `PrintConv` `s/^0 //;s/^1 (\d+)/Hi $1/`
/// (`Nikon.pm:1817`).
fn iso_conv(raw: &ParsedValue, print_conv: bool) -> TagValue {
  let two = raw.first_two_u64();
  let Some((a, b)) = two else {
    return raw.to_default_tag_value();
  };
  if print_conv {
    if a == 1 {
      TagValue::Str(SmolStr::new(std::format!("Hi {b}")))
    } else {
      // s/^0 // — strip a leading "0 "; the remaining value is the ISO.
      // (For a == 0 this is just `b`; ExifTool emits the bare second word.)
      if a == 0 {
        TagValue::I64(b as i64)
      } else {
        TagValue::Str(SmolStr::new(std::format!("{a} {b}")))
      }
    }
  } else {
    // -n: the raw "A B" string.
    TagValue::Str(SmolStr::new(std::format!("{a} {b}")))
  }
}

/// `JPGCompression` (0x0044, `Nikon.pm:2168-2175`) — `RawConv => '($val) ?
/// $val : undef'` (`:2170`) drops a raw `0` (the raw-file marker) ⇒ tag NOT
/// emitted; otherwise the `{1 => 'Size Priority', 3 => 'Optimal Quality'}`
/// PrintConv hash (an unmapped value renders `Unknown (N)`, the ExifTool
/// default). `-n` emits the raw integer.
fn jpg_compression_conv(raw: &ParsedValue, print_conv: bool) -> Option<TagValue> {
  let Some(n) = raw.first_i64() else {
    return Some(raw.to_default_tag_value());
  };
  if n == 0 {
    return None;
  }
  Some(if print_conv {
    match jpg_compression_label(n) {
      Some(s) => TagValue::Str(SmolStr::new(s)),
      None => TagValue::Str(SmolStr::new(std::format!("Unknown ({n})"))),
    }
  } else {
    TagValue::I64(n)
  })
}

/// `ISOSetting` (0x0013) — `int16u[2]`, `PrintConv => s/^0 //` (`Nikon.pm:1907`).
fn iso_setting_conv(raw: &ParsedValue, print_conv: bool) -> TagValue {
  let two = raw.first_two_u64();
  let Some((a, b)) = two else {
    return raw.to_default_tag_value();
  };
  if print_conv {
    if a == 0 {
      TagValue::I64(b as i64)
    } else {
      TagValue::Str(SmolStr::new(std::format!("{a} {b}")))
    }
  } else {
    TagValue::Str(SmolStr::new(std::format!("{a} {b}")))
  }
}

/// `FlashExposureBracketValue` (0x0018) — `c3` ValueConv + `sprintf("%.1f")`.
/// `ExposureBracketValue` (0x0019) is a `rational64s`, `PrintConv`
/// `PrintFraction` unless undef → "n/a". This helper handles the `c3` form;
/// the rational form is routed through [`NikonConv::Raw`]'s default render
/// when it is a rational (0x0019 has its own arm only when needed).
fn bracket_float1(raw: &ParsedValue, print_conv: bool) -> TagValue {
  let Some(v) = raw.signed_fraction_c3() else {
    return raw.to_default_tag_value();
  };
  if print_conv {
    TagValue::Str(SmolStr::new(std::format!("{v:.1}")))
  } else {
    value_conv_number(v)
  }
}

/// `LensType` (0x0083) `PrintConv` (`Nikon.pm:2052-2070`).
fn lens_type_conv(raw: &ParsedValue, print_conv: bool) -> TagValue {
  let Some(n) = raw.first_i64() else {
    return raw.to_default_tag_value();
  };
  if !print_conv {
    return TagValue::I64(n);
  }
  if n == 0 {
    return TagValue::Str(SmolStr::new("AF"));
  }
  // DecodeBits($val, { 0=>MF,1=>D,2=>G,3=>VR,4=>1,5=>FT-1,6=>E,7=>AF-P }).
  let decoded = crate::convert::decode_bits(&n.to_string(), Some(LENS_TYPE_BITS), 32);
  TagValue::Str(SmolStr::new(lens_type_postprocess(&decoded)))
}

/// The Perl post-processing on the `DecodeBits` output (`Nikon.pm:2061-2068`):
///
/// ```perl
/// s/,//g; s/\bD G\b/G/;
/// s/ E\b// and s/^(G )?/E /;   # put "E" at the start instead of "G"
/// s/ 1// and $_ = "1 $_";      # put "1" at start
/// s/FT-1 // and $_ .= ' FT-1'; # put "FT-1" at end
/// ```
///
/// `DecodeBits` joins set bits with `", "`, so the input is e.g. `"D, G, E"`.
/// A direct transliteration of each substitution (the `and` chains the next
/// substitution only when the previous one matched, exactly like Perl).
fn lens_type_postprocess(decoded: &str) -> String {
  // s/,//g — remove EVERY comma (turning ", " joiners into a single space).
  let mut s: String = decoded.replace(',', "");
  // s/\bD G\b/G/ — the first "D G" (word-bounded) collapses to "G".
  if let Some(pos) = find_bounded(&s, "D G") {
    let end = pos + "D G".len();
    s = std::format!(
      "{}G{}",
      s.get(..pos).unwrap_or(""),
      s.get(end..).unwrap_or("")
    );
  }
  // s/ E\b// and s/^(G )?/E / — remove the first " E" (word-bounded), and only
  // if it matched, replace a leading "G " (optional) with "E ".
  if let Some(e_at) = find_bounded(&s, " E") {
    let end = e_at + " E".len();
    s = std::format!(
      "{}{}",
      s.get(..e_at).unwrap_or(""),
      s.get(end..).unwrap_or("")
    );
    // s/^(G )?/E /
    if let Some(rest) = s.strip_prefix("G ") {
      s = std::format!("E {rest}");
    } else {
      s = std::format!("E {s}");
    }
  }
  // s/ 1// and $_ = "1 $_" — remove the first " 1", and if it matched prepend "1 ".
  if let Some(one_at) = find_bounded(&s, " 1") {
    let end = one_at + " 1".len();
    s = std::format!(
      "{}{}",
      s.get(..one_at).unwrap_or(""),
      s.get(end..).unwrap_or("")
    );
    s = std::format!("1 {s}");
  }
  // s/FT-1 // and $_ .= ' FT-1' — remove the first "FT-1 ", and if it matched
  // append " FT-1".
  if let Some(ft_at) = s.find("FT-1 ") {
    let end = ft_at + "FT-1 ".len();
    s = std::format!(
      "{}{}",
      s.get(..ft_at).unwrap_or(""),
      s.get(end..).unwrap_or("")
    );
    s.push_str(" FT-1");
  }
  s
}

/// Find `needle` in `haystack` with a trailing `\b` word boundary — the byte
/// AFTER the match must be a non-word char (or end). Used for the `\b`-anchored
/// `LensType` substitutions; `needle`'s own start is space-anchored by the
/// callers (each pattern begins with a space or a known word), so only the
/// trailing boundary needs checking here.
fn find_bounded(haystack: &str, needle: &str) -> Option<usize> {
  let bytes = haystack.as_bytes();
  let mut from = 0;
  while let Some(rel) = haystack.get(from..).and_then(|s| s.find(needle)) {
    let pos = from + rel;
    let end = pos + needle.len();
    let after_is_word = bytes
      .get(end)
      .is_some_and(|&b| b.is_ascii_alphanumeric() || b == b'_');
    if !after_is_word {
      return Some(pos);
    }
    from = end;
  }
  None
}

/// `Lens` (0x0084) `PrintConv => Exif::PrintLensInfo` (`Exif.pm`).
fn lens_conv(raw: &ParsedValue, print_conv: bool) -> TagValue {
  // The decoded value is `rational64u[4]`; `ReadValue` joins as decimal
  // scalars (`exiftool_val_str`). For `-n` we emit that join verbatim.
  let joined = raw.rational_join_decimal();
  let Some(joined) = joined else {
    return raw.to_default_tag_value();
  };
  if print_conv {
    TagValue::Str(SmolStr::new(print_lens_info(&joined)))
  } else {
    TagValue::Str(SmolStr::new(joined))
  }
}

/// `Image::ExifTool::Exif::PrintLensInfo($val)` (`Exif.pm`): from the
/// space-joined 4-value `"short long apShort apLong"`, build
/// `"short-longmm f/apShort-apLong"`, collapsing equal endpoints and
/// rendering `inf`/`undef` as `?`.
fn print_lens_info(val: &str) -> String {
  let vals: Vec<&str> = val.split(' ').filter(|s| !s.is_empty()).collect();
  let [v0, v1, v2, v3] = vals.as_slice() else {
    return val.to_string();
  };
  // Each must be a float / "inf" / "undef" (→ "?").
  let norm = |s: &str| -> Option<String> {
    if s == "inf" || s == "undef" {
      Some("?".to_string())
    } else if is_float(s) {
      Some(s.to_string())
    } else {
      None
    }
  };
  let (Some(s0), Some(s1), Some(s2), Some(s3)) = (norm(v0), norm(v1), norm(v2), norm(v3)) else {
    return val.to_string();
  };
  let mut out = s0.clone();
  // .= "-$vals[1]" if $vals[1] and $vals[1] ne $vals[0]
  if !is_zeroish(&s1) && s1 != s0 {
    out.push('-');
    out.push_str(&s1);
  }
  out.push_str("mm f/");
  out.push_str(&s2);
  if !is_zeroish(&s3) && s3 != s2 {
    out.push('-');
    out.push_str(&s3);
  }
  out
}

/// `$vals[N] and …` is falsy in Perl for `"0"`/`"0.0"`/empty — treat a
/// zero-valued endpoint as "absent" so the dash is dropped.
fn is_zeroish(s: &str) -> bool {
  s.parse::<f64>().map(|v| v == 0.0).unwrap_or(false)
}

/// `ShootingMode` (0x0089) `PrintConv` (`Nikon.pm:2160-2189`).
fn shooting_mode_conv(raw: &ParsedValue, print_conv: bool, model: Option<&str>) -> TagValue {
  let Some(n) = raw.first_i64() else {
    return raw.to_default_tag_value();
  };
  if !print_conv {
    return TagValue::I64(n);
  }
  // unless ($val & 0x87) { return 'Single-Frame' unless $val; $_ = 'Single-Frame, '; }
  let mut prefix = String::new();
  if n & 0x87 == 0 {
    if n == 0 {
      return TagValue::Str(SmolStr::new("Single-Frame"));
    }
    prefix.push_str("Single-Frame, ");
  }
  // Bit 5's label is model-dependent.
  let bit5 = if model.is_some_and(model_is_d70) {
    "Unused LE-NR Slowdown"
  } else {
    "Auto ISO"
  };
  let bits: [(u8, &str); 10] = [
    (0, "Continuous"),
    (1, "Delay"),
    (2, "PC Control"),
    (3, "Self-timer"),
    (4, "Exposure Bracketing"),
    (5, bit5),
    (6, "White-Balance Bracketing"),
    (7, "IR Control"),
    (8, "D-Lighting Bracketing"),
    (11, "Pre-capture"),
  ];
  let decoded = crate::convert::decode_bits(&n.to_string(), Some(&bits), 32);
  TagValue::Str(SmolStr::new(std::format!("{prefix}{decoded}")))
}

/// `$$self{Model}=~/D70\b/` (`Nikon.pm:2180`) — matches "NIKON D70" and
/// "NIKON D70s"? No: `\b` after "D70" — "D70s" has no word boundary between
/// "70" and "s", so `/D70\b/` matches "D70" but NOT "D70s". Mirror that.
fn model_is_d70(model: &str) -> bool {
  // Find "D70" occurrences and require a word boundary (non-word char or end)
  // immediately after.
  let bytes = model.as_bytes();
  let mut i = 0;
  while let Some(pos) = model.get(i..).and_then(|s| s.find("D70")) {
    let end = i + pos + 3;
    let after_is_word = bytes
      .get(end)
      .is_some_and(|&b| b.is_ascii_alphanumeric() || b == b'_');
    if !after_is_word {
      return true;
    }
    i = end;
  }
  false
}

/// Generic single-integer hash PrintConv: look up `n` in `label`; a miss
/// renders `Unknown (n)` (`ExifTool.pm:3622`).
fn hash_conv(
  raw: &ParsedValue,
  print_conv: bool,
  label: fn(i64) -> Option<&'static str>,
) -> TagValue {
  let Some(n) = raw.first_i64() else {
    return raw.to_default_tag_value();
  };
  if print_conv {
    match label(n) {
      Some(s) => TagValue::Str(SmolStr::new(s)),
      None => TagValue::Str(SmolStr::new(std::format!("Unknown ({n})"))),
    }
  } else {
    TagValue::I64(n)
  }
}

fn flash_mode_label(n: i64) -> Option<&'static str> {
  Some(match n {
    0 => "Did Not Fire",
    1 => "Fired, Manual",
    3 => "Not Ready",
    7 => "Fired, External",
    8 => "Fired, Commander Mode",
    9 => "Fired, TTL Mode",
    18 => "LED Light",
    _ => return None,
  })
}

fn nef_compression_label(n: i64) -> Option<&'static str> {
  Some(match n {
    1 => "Lossy (type 1)",
    2 => "Uncompressed",
    3 => "Lossless",
    4 => "Lossy (type 2)",
    5 => "Striped packed 12 bits",
    6 => "Uncompressed (reduced to 12 bit)",
    7 => "Unpacked 12 bits",
    8 => "Small",
    9 => "Packed 12 bits",
    10 => "Packed 14 bits",
    13 => "High Efficiency",
    14 => "High Efficiency*",
    _ => return None,
  })
}

fn color_space_label(n: i64) -> Option<&'static str> {
  Some(match n {
    1 => "sRGB",
    2 => "Adobe RGB",
    4 => "BT.2100",
    _ => return None,
  })
}

fn off_on_label(n: i64) -> Option<&'static str> {
  Some(match n {
    0 => "Off",
    1 => "On",
    _ => return None,
  })
}

fn active_d_lighting_label(n: i64) -> Option<&'static str> {
  Some(match n {
    0 => "Off",
    1 => "Low",
    3 => "Normal",
    5 => "High",
    7 => "Extra High",
    8 => "Extra High 1",
    9 => "Extra High 2",
    10 => "Extra High 3",
    11 => "Extra High 4",
    0xffff => "Auto",
    _ => return None,
  })
}

fn vignette_control_label(n: i64) -> Option<&'static str> {
  Some(match n {
    0 => "Off",
    1 => "Low",
    3 => "Normal",
    5 => "High",
    _ => return None,
  })
}

fn shutter_mode_label(n: i64) -> Option<&'static str> {
  Some(match n {
    0 => "Mechanical",
    16 => "Electronic",
    48 => "Electronic Front Curtain",
    64 => "Electronic (Movie)",
    80 => "Auto (Mechanical)",
    81 => "Auto (Electronic Front Curtain)",
    96 => "Electronic (High Speed)",
    _ => return None,
  })
}

fn image_size_raw_label(n: i64) -> Option<&'static str> {
  Some(match n {
    1 => "Large",
    2 => "Medium",
    3 => "Small",
    _ => return None,
  })
}

fn jpg_compression_label(n: i64) -> Option<&'static str> {
  Some(match n {
    1 => "Size Priority",
    3 => "Optimal Quality",
    _ => return None,
  })
}

fn date_stamp_mode_label(n: i64) -> Option<&'static str> {
  Some(match n {
    0 => "Off",
    1 => "Date & Time",
    2 => "Date",
    3 => "Date Counter",
    _ => return None,
  })
}

fn high_iso_nr_label(n: i64) -> Option<&'static str> {
  Some(match n {
    0 => "Off",
    1 => "Minimal",
    2 => "Low",
    3 => "Medium Low",
    4 => "Normal",
    5 => "Medium High",
    6 => "High",
    _ => return None,
  })
}

/// `%Nikon::AFInfo` position 0 `AFAreaMode` (`Nikon.pm:2117-2126`).
fn af_area_mode_label(n: i64) -> Option<&'static str> {
  Some(match n {
    0 => "Single Area",
    1 => "Dynamic Area",
    2 => "Dynamic Area (closest subject)",
    3 => "Group Dynamic",
    4 => "Single Area (wide)",
    5 => "Dynamic Area (wide)",
    _ => return None,
  })
}

/// `%Nikon::AFInfo` position 1 `AFPoint` (`Nikon.pm:2128-2150`).
fn af_point_label(n: i64) -> Option<&'static str> {
  Some(match n {
    0 => "Center",
    1 => "Top",
    2 => "Bottom",
    3 => "Mid-left",
    4 => "Mid-right",
    5 => "Upper-left",
    6 => "Upper-right",
    7 => "Lower-left",
    8 => "Lower-right",
    9 => "Far Left",
    10 => "Far Right",
    _ => return None,
  })
}

/// `%Nikon::FlashInfo0100` `FlashSource` (offset 4, `Nikon.pm:10826-10828`).
fn flash_source_label(n: i64) -> Option<&'static str> {
  Some(match n {
    0 => "None",
    1 => "External",
    2 => "Internal",
    _ => return None,
  })
}

/// `%flashControlMode` (`Nikon.pm:829-838`) — the shared
/// `FlashControlMode`/`FlashGroupAControlMode`/`FlashGroupBControlMode` hash.
fn flash_control_mode_label(n: i64) -> Option<&'static str> {
  Some(match n {
    0x00 => "Off",
    0x01 => "iTTL-BL",
    0x02 => "iTTL",
    0x03 => "Auto Aperture",
    0x04 => "Automatic",
    0x05 => "GN (distance priority)",
    0x06 => "Manual",
    0x07 => "Repeating Flash",
    _ => return None,
  })
}

/// `ExternalFlashFlags` (offset 8, `Nikon.pm:10829-10843`) — `PrintConv =>
/// { 0 => '(none)', BITMASK => {…} }`. ExifTool tries the direct hash key
/// FIRST (`0 => '(none)'`), then the `DecodeBits` BITMASK (the same
/// `0 → "(none)"` / set-bit-label / `[n]` path `LensType` 0x0083 uses); an
/// unlisted set bit renders `[n]`. The lone direct key is `0`, which the empty
/// DecodeBits already renders `"(none)"`, so the BITMASK path subsumes it.
/// `-n` emits the raw int8u.
fn external_flash_flags_conv(raw: &ParsedValue, print_conv: bool) -> TagValue {
  let Some(n) = raw.first_i64() else {
    return raw.to_default_tag_value();
  };
  if !print_conv {
    return TagValue::I64(n);
  }
  TagValue::Str(SmolStr::new(crate::convert::decode_bits(
    &n.to_string(),
    Some(EXTERNAL_FLASH_FLAGS_BITS),
    8,
  )))
}

/// `%flashGNDistance` labels (`Nikon.pm:792-815`). Key `0` is the bare string
/// `"0"` (NOT a metre value); `255` is `"n/a"`.
fn flash_gn_distance_label(n: i64) -> Option<&'static str> {
  Some(match n {
    0 => "0",
    1 => "0.1 m",
    2 => "0.2 m",
    3 => "0.3 m",
    4 => "0.4 m",
    5 => "0.5 m",
    6 => "0.6 m",
    7 => "0.7 m",
    8 => "0.8 m",
    9 => "0.9 m",
    10 => "1.0 m",
    11 => "1.1 m",
    12 => "1.3 m",
    13 => "1.4 m",
    14 => "1.6 m",
    15 => "1.8 m",
    16 => "2.0 m",
    17 => "2.2 m",
    18 => "2.5 m",
    19 => "2.8 m",
    20 => "3.2 m",
    21 => "3.6 m",
    22 => "4.0 m",
    23 => "4.5 m",
    24 => "5.0 m",
    25 => "5.6 m",
    26 => "6.3 m",
    27 => "7.1 m",
    28 => "8.0 m",
    29 => "9.0 m",
    30 => "10.0 m",
    31 => "11.0 m",
    32 => "13.0 m",
    33 => "14.0 m",
    34 => "16.0 m",
    35 => "18.0 m",
    36 => "20.0 m",
    255 => "n/a",
    _ => return None,
  })
}

/// `%Nikon::ShotInfo` `VibrationReduction` 0x75 (`Nikon.pm:6037-6048`, the
/// `0207` D200 arm). A miss → `Unknown (N)` (no PrintHex on this hash).
fn shot_info_vr_0207_label(n: i64) -> Option<&'static str> {
  Some(match n {
    0 => "Off",
    1 => "On (1)",
    2 => "On (2)",
    3 => "On (3)",
    _ => return None,
  })
}

/// `%Nikon::ShotInfo` `VibrationReduction` 0x1ae (`Nikon.pm:6071-6078`, the
/// `0205` D50 arm, `PrintHex => 1`). The caller renders a miss as the hex
/// `Unknown (0xNN)`.
fn shot_info_vr_0205_label(n: i64) -> Option<&'static str> {
  Some(match n {
    0x00 => "n/a",
    0x0c => "Off",
    0x0f => "On",
    _ => return None,
  })
}

/// `sprintf("%.0f", v)` for the `FlashOutput` percent — `{:.0}` rounds
/// half-to-even like glibc `printf` (the `Manual`-arm of offset 10/17/18; never
/// reached by the bundled DSLR fixtures, which take the `FlashCompensation`
/// arm).
fn flash_pct(v: f64) -> String {
  std::format!("{v:.0}")
}

/// `%afPoints11` BITMASK labels (`Nikon.pm:2152`). Sorted by bit.
const AF_POINTS11_BITS: &[(u8, &str)] = &[
  (0, "Center"),
  (1, "Top"),
  (2, "Bottom"),
  (3, "Mid-left"),
  (4, "Mid-right"),
  (5, "Upper-left"),
  (6, "Upper-right"),
  (7, "Lower-left"),
  (8, "Lower-right"),
  (9, "Far Left"),
  (10, "Far Right"),
];

/// `Nikon::FormatString` (`Nikon.pm:14172-14199`): title-case Nikon's all-caps
/// string values. Trailing whitespace is removed, then in WORDS CONTAINING A
/// VOWEL all letters after the first are lower-cased; the `AF`/`RAW` words are
/// patched back to upper-case.
///
/// (The `LimitLongValues` branch caps very long unknown strings; none of the
/// Nikon::Main string tags reach that limit, so it is omitted — a string over
/// the default `LimitLongValues` would only appear on an unported tag.)
pub fn format_string(input: &str) -> String {
  // s/\s+$// — strip trailing whitespace (Perl \s).
  let trimmed = input.trim_end_matches(is_perl_space);
  // Only change case if the string contains an upper-case vowel (Perl's
  // /[AEIOUY]/ tests the raw string, which is all-caps for the inputs that
  // need conversion).
  if !trimmed
    .bytes()
    .any(|b| matches!(b, b'A' | b'E' | b'I' | b'O' | b'U' | b'Y'))
  {
    return trimmed.to_string();
  }
  // Two passes mirror the two Perl substitutions:
  //   1. s/\b([AEIOUY])([A-Z]+)/$1\L$2/g  (vowel-initial words)
  //   2. s/\b([A-Z])([A-Z]*[AEIOUY][A-Z]*)/$1\L$2/g  (any word with a vowel)
  // Both lower-case all but the first letter of words that contain a vowel.
  // The combined effect: for every maximal run of ASCII letters that contains
  // a vowel, keep the first letter and lower-case the rest. Then patch
  // "Af" → "AF" and "Raw" → "RAW".
  let mut out = String::with_capacity(trimmed.len());
  let bytes = trimmed.as_bytes();
  let mut i = 0;
  while i < bytes.len() {
    let Some(&b) = bytes.get(i) else { break };
    if b.is_ascii_alphabetic() {
      // Collect the maximal letter run.
      let start = i;
      while bytes.get(i).is_some_and(u8::is_ascii_alphabetic) {
        i += 1;
      }
      let word = trimmed.get(start..i).unwrap_or("");
      let has_vowel = word.bytes().any(|c| {
        matches!(
          c.to_ascii_uppercase(),
          b'A' | b'E' | b'I' | b'O' | b'U' | b'Y'
        )
      });
      if has_vowel {
        // Keep the first char, lower-case the rest.
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
          out.push(first);
          for c in chars {
            out.extend(c.to_lowercase());
          }
        }
      } else {
        out.push_str(word);
      }
    } else {
      out.push(b as char);
      i += 1;
    }
  }
  // s/\bAf\b/AF/ and s/\bRaw\b/RAW/ — applied as whole-word patches.
  patch_word(&mut out, "Af", "AF");
  patch_word(&mut out, "Raw", "RAW");
  out
}

/// Replace every `\bFROM\b` occurrence with `TO` — Perl `s/\bFROM\b/TO/`.
/// A `\b` is a transition between a word char (`[A-Za-z0-9_]`) and a
/// non-word char (or string edge); so `"Af-C"` matches `\bAf\b` (the hyphen
/// is a non-word boundary) and becomes `"AF-C"`.
fn patch_word(s: &mut String, from: &str, to: &str) {
  if from.is_empty() || !s.contains(from) {
    return;
  }
  let bytes = s.as_bytes();
  let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
  let mut out = String::with_capacity(s.len());
  let mut i = 0;
  while i < s.len() {
    if let Some(slice) = s.get(i..i + from.len())
      && slice == from
    {
      let before_is_word = i
        .checked_sub(1)
        .and_then(|p| bytes.get(p))
        .is_some_and(|&b| is_word(b));
      let after_is_word = bytes.get(i + from.len()).is_some_and(|&b| is_word(b));
      if !before_is_word && !after_is_word {
        out.push_str(to);
        i += from.len();
        continue;
      }
    }
    // Copy one char (UTF-8 safe).
    let ch = s.get(i..).and_then(|t| t.chars().next());
    if let Some(c) = ch {
      out.push(c);
      i += c.len_utf8();
    } else {
      break;
    }
  }
  *s = out;
}

/// Perl `\s` whitespace test (space, tab, newline, CR, form-feed, vertical tab).
fn is_perl_space(c: char) -> bool {
  matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{0c}' | '\u{0b}')
}

fn is_float(s: &str) -> bool {
  s.parse::<f64>().is_ok()
}

/// `LensType` BITMASK labels (`Nikon.pm:2053-2061`). Sorted by bit for the
/// `DecodeBits` walk.
const LENS_TYPE_BITS: &[(u8, &str)] = &[
  (0, "MF"),
  (1, "D"),
  (2, "G"),
  (3, "VR"),
  (4, "1"),
  (5, "FT-1"),
  (6, "E"),
  (7, "AF-P"),
];

/// `ExternalFlashFlags` BITMASK labels (`Nikon.pm:10840-10843`). Sorted by bit
/// for the `DecodeBits` walk; bits 1/3/6/7 are unlisted ⇒ render `[n]`.
const EXTERNAL_FLASH_FLAGS_BITS: &[(u8, &str)] = &[
  (0, "Fired"),
  (2, "Bounce Flash"),
  (4, "Wide Flash Adapter"),
  (5, "Dome Diffuser"),
];

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;
  use crate::exif::ifd::RawValue;

  fn undef(bytes: &[u8]) -> ParsedValue {
    ParsedValue::new(RawValue::Bytes(bytes.to_vec()))
  }
  fn u8v(n: u64) -> ParsedValue {
    ParsedValue::new(RawValue::U64(vec![n]))
  }

  /// `Nikon::FormatString` title-casing matches the bundled oracle
  /// (verified via `perl -e '… Image::ExifTool::Nikon::FormatString(…)'`).
  #[test]
  fn format_string_matches_oracle() {
    assert_eq!(format_string("FINE"), "Fine");
    assert_eq!(format_string("NORMAL"), "Normal");
    assert_eq!(format_string("AUTO"), "Auto");
    assert_eq!(format_string("RAW"), "RAW"); // patched back
    assert_eq!(format_string("COLOR"), "Color");
    assert_eq!(format_string("AF-C"), "AF-C"); // "AF" patched, no vowel-run change
    assert_eq!(format_string("SPEEDLIGHT"), "Speedlight");
    assert_eq!(format_string("CUSTOM"), "Custom");
    assert_eq!(format_string("ENHANCED"), "Enhanced");
    assert_eq!(format_string("Med.H"), "Med.H");
    assert_eq!(format_string("CS"), "CS"); // no vowel ⇒ unchanged
    assert_eq!(format_string("FPNR"), "FPNR"); // no vowel ⇒ unchanged
    assert_eq!(format_string("Preset0"), "Preset0");
    assert_eq!(format_string("NORMAL  "), "Normal"); // trailing ws stripped
    assert_eq!(format_string("No= 20025585"), "No= 20025585");
  }

  /// `LensType` (0x0083) DecodeBits + post-processing — oracle-cited
  /// (`perl … DecodeBits(...)` traced in the PR notes).
  #[test]
  fn lens_type_print_conv() {
    // 0 → "AF".
    assert_eq!(
      lens_type_conv(&u8v(0), true),
      TagValue::Str(SmolStr::new("AF"))
    );
    // 0x06 → "D, G" → "G".
    assert_eq!(
      lens_type_conv(&u8v(0x06), true),
      TagValue::Str(SmolStr::new("G"))
    );
    // 0x02 → "D".
    assert_eq!(
      lens_type_conv(&u8v(0x02), true),
      TagValue::Str(SmolStr::new("D"))
    );
    // 0x46 → "D, G, E" → "E G".
    assert_eq!(
      lens_type_conv(&u8v(0x46), true),
      TagValue::Str(SmolStr::new("E G"))
    );
    // 0x86 → "D, G, AF-P" → "G AF-P".
    assert_eq!(
      lens_type_conv(&u8v(0x86), true),
      TagValue::Str(SmolStr::new("G AF-P"))
    );
    // 0x16 → "D, G, 1" → "1 G".
    assert_eq!(
      lens_type_conv(&u8v(0x16), true),
      TagValue::Str(SmolStr::new("1 G"))
    );
    // 0x26 → "D, G, FT-1" → "G FT-1".
    assert_eq!(
      lens_type_conv(&u8v(0x26), true),
      TagValue::Str(SmolStr::new("G FT-1"))
    );
    // 0x08 → "VR".
    assert_eq!(
      lens_type_conv(&u8v(0x08), true),
      TagValue::Str(SmolStr::new("VR"))
    );
    // -n: the raw integer.
    assert_eq!(lens_type_conv(&u8v(0x06), false), TagValue::I64(6));
  }

  /// `Lens` (0x0084) → `Exif::PrintLensInfo` (`"18-70mm f/3.5-4.5"`).
  #[test]
  fn lens_print_lens_info() {
    assert_eq!(print_lens_info("18 70 3.5 4.5"), "18-70mm f/3.5-4.5");
    // Prime lens (equal endpoints collapse): "50 50 1.8 1.8" → "50mm f/1.8".
    assert_eq!(print_lens_info("50 50 1.8 1.8"), "50mm f/1.8");
    // A non-4-value string passes through unchanged.
    assert_eq!(print_lens_info("18 70 3.5"), "18 70 3.5");
  }

  /// `MakerNoteVersion` (0x0001) — `"0210"` → `"2.10"`, `"0100"` → `"1.00"`.
  #[test]
  fn maker_note_version_print_conv() {
    // ASCII digit string (the common DSLR form).
    let v = ParsedValue::new(RawValue::Bytes(b"0210".to_vec()));
    assert_eq!(
      NikonConv::MakerNoteVersion.apply(&v, true, None, ByteOrder::Big),
      Some(TagValue::Str(SmolStr::new("2.10")))
    );
    let v = ParsedValue::new(RawValue::Bytes(b"0100".to_vec()));
    assert_eq!(
      NikonConv::MakerNoteVersion.apply(&v, true, None, ByteOrder::Big),
      Some(TagValue::Str(SmolStr::new("1.00")))
    );
    // -n: the post-ValueConv "0210".
    let v = ParsedValue::new(RawValue::Bytes(b"0210".to_vec()));
    assert_eq!(
      NikonConv::MakerNoteVersion.apply(&v, false, None, ByteOrder::Big),
      Some(TagValue::Str(SmolStr::new("0210")))
    );
    // Binary form (first byte ≤ 0x09): "\x00\x01\x00\x00" → "0100" → "1.00".
    let v = undef(&[0x00, 0x01, 0x00, 0x00]);
    assert_eq!(
      NikonConv::MakerNoteVersion.apply(&v, true, None, ByteOrder::Big),
      Some(TagValue::Str(SmolStr::new("1.00")))
    );
  }

  /// `FlashGNDistance` (`%flashGNDistance`) is a plain HASH PrintConv: key 0 →
  /// the bare `"0"`, listed bytes render their metre label, 255 → `"n/a"`, and
  /// an UNLISTED valid byte (37-254) renders ExifTool's HASH-miss fallback
  /// `Unknown (N)` (`ExifTool.pm:3632` — no `BITMASK`/`OTHER`/`PrintHex`), NOT
  /// the raw number. `-n` (print_conv false) emits the raw int8u.
  #[test]
  fn flash_gn_distance_hash_miss_is_unknown() {
    let c = |n: u64, pc: bool| NikonConv::FlashGnDistance.apply(&u8v(n), pc, None, ByteOrder::Big);
    let s = |t: &str| Some(TagValue::Str(SmolStr::new(t)));
    assert_eq!(c(0, true), s("0")); // key 0 → bare "0"
    assert_eq!(c(10, true), s("1.0 m"));
    assert_eq!(c(36, true), s("20.0 m")); // last listed metre value
    assert_eq!(c(255, true), s("n/a"));
    // Unlisted valid byte ⇒ the standard hash-miss "Unknown (N)" (was: raw N).
    assert_eq!(c(37, true), s("Unknown (37)"));
    assert_eq!(c(200, true), s("Unknown (200)"));
    // -n value mode emits the raw int.
    assert_eq!(c(37, false), Some(TagValue::I64(37)));
  }

  /// `ShootingMode` (0x0089) — value 0 → "Single-Frame"; the DecodeBits path.
  #[test]
  fn shooting_mode_print_conv() {
    // 0 → "Single-Frame".
    assert_eq!(
      shooting_mode_conv(&u8v(0), true, None),
      TagValue::Str(SmolStr::new("Single-Frame"))
    );
    // bit 0 set (Continuous), no 0x87 bits beyond → "Continuous".
    assert_eq!(
      shooting_mode_conv(&u8v(0x01), true, None),
      TagValue::Str(SmolStr::new("Continuous"))
    );
    // bit 1 (Delay) only: 0x02 & 0x87 = 0x02 (bit1 ∈ 0x87) so NO prefix; the
    // DecodeBits yields "Delay".
    assert_eq!(
      shooting_mode_conv(&u8v(0x02), true, None),
      TagValue::Str(SmolStr::new("Delay"))
    );
  }

  /// `AFPointsInFocus` (`%afPoints11`) — `0 → "(none)"`, bit 0 → "Center".
  #[test]
  fn af_points_in_focus_conv_oracle() {
    assert_eq!(
      af_points_in_focus_conv(&ParsedValue::new(RawValue::U64(vec![0])), true),
      TagValue::Str(SmolStr::new("(none)"))
    );
    assert_eq!(
      af_points_in_focus_conv(&ParsedValue::new(RawValue::U64(vec![1])), true),
      TagValue::Str(SmolStr::new("Center"))
    );
    assert_eq!(
      af_points_in_focus_conv(&ParsedValue::new(RawValue::U64(vec![0x7ff])), true),
      TagValue::Str(SmolStr::new("All 11 Points"))
    );
  }

  /// `SensorPixelSize` (0x009a) → `"7.8 x 7.8 um"`.
  #[test]
  fn sensor_pixel_size_conv() {
    use crate::value::Rational;
    let v = ParsedValue::new(RawValue::Rational(vec![
      Rational::rational64(78, 10),
      Rational::rational64(78, 10),
    ]));
    assert_eq!(
      NikonConv::SensorPixelSize.apply(&v, true, None, ByteOrder::Big),
      Some(TagValue::Str(SmolStr::new("7.8 x 7.8 um")))
    );
  }

  /// `JPGCompression` (0x0044) — `RawConv => '($val) ? $val : undef'`: a raw
  /// `0` (the raw-file marker) is `undef` ⇒ `apply` returns `None` (the tag is
  /// then NOT emitted), in BOTH `-j` and `-n` modes; a non-zero value renders
  /// via the `{1 => 'Size Priority', 3 => 'Optimal Quality'}` hash (`-j`) /
  /// the raw integer (`-n`). Oracle: a Nikon file with 0x0044 == 0 has no
  /// `Nikon:JPGCompression` tag.
  #[test]
  fn nikon_jpgcompression_zero_suppressed() {
    // Raw 0 ⇒ dropped (None) under both -j and -n.
    let zero = ParsedValue::new(RawValue::U64(vec![0]));
    assert_eq!(
      NikonConv::JpgCompression.apply(&zero, true, None, ByteOrder::Big),
      None
    );
    assert_eq!(
      NikonConv::JpgCompression.apply(&zero, false, None, ByteOrder::Big),
      None
    );
    // Raw 1 ⇒ "Size Priority" (-j) / 1 (-n).
    let one = ParsedValue::new(RawValue::U64(vec![1]));
    assert_eq!(
      NikonConv::JpgCompression.apply(&one, true, None, ByteOrder::Big),
      Some(TagValue::Str(SmolStr::new("Size Priority")))
    );
    assert_eq!(
      NikonConv::JpgCompression.apply(&one, false, None, ByteOrder::Big),
      Some(TagValue::I64(1))
    );
    // Raw 3 ⇒ "Optimal Quality" (-j) / 3 (-n).
    let three = ParsedValue::new(RawValue::U64(vec![3]));
    assert_eq!(
      NikonConv::JpgCompression.apply(&three, true, None, ByteOrder::Big),
      Some(TagValue::Str(SmolStr::new("Optimal Quality")))
    );
    assert_eq!(
      NikonConv::JpgCompression.apply(&three, false, None, ByteOrder::Big),
      Some(TagValue::I64(3))
    );
    // An unmapped non-zero value renders the ExifTool `Unknown (N)` default.
    let five = ParsedValue::new(RawValue::U64(vec![5]));
    assert_eq!(
      NikonConv::JpgCompression.apply(&five, true, None, ByteOrder::Big),
      Some(TagValue::Str(SmolStr::new("Unknown (5)")))
    );
  }

  /// `ISO` (0x0002) — the `$val eq "\0\0\0\0"` RawConv is DEAD (by RawConv
  /// time `$val` is the `int16u[2]` string `"0 0"`, never the raw NUL bytes),
  /// so an all-zero ISO is NOT dropped: `apply` returns `Some` and the `-j`
  /// PrintConv `s/^0 //` yields `0`. Oracle: `Nikon.jpg` emits `Nikon:ISO` 0
  /// (`int16u[2]` value `00 00 00 00`).
  #[test]
  fn nikon_iso_all_zero_emitted_not_dropped() {
    let zero2 = ParsedValue::new(RawValue::U64(vec![0, 0]));
    assert_eq!(
      NikonConv::Iso.apply(&zero2, true, None, ByteOrder::Big),
      Some(TagValue::I64(0))
    );
    // -n: the raw "0 0" string.
    assert_eq!(
      NikonConv::Iso.apply(&zero2, false, None, ByteOrder::Big),
      Some(TagValue::Str(SmolStr::new("0 0")))
    );
  }

  /// `model_is_d70` matches "NIKON D70" but NOT "NIKON D70s" (the `/D70\b/`).
  #[test]
  fn model_d70_word_boundary() {
    assert!(model_is_d70("NIKON D70"));
    assert!(!model_is_d70("NIKON D70s"));
    assert!(!model_is_d70("NIKON D2Hs"));
  }

  /// `CropHiSpeed` (0x001b) — the `%cropHiSpeed` `OTHER` sub maps element 0 and
  /// formats the full 7-int16u record. Oracle (Perl `%cropHiSpeed` OTHER):
  /// `2 6048 4032 4500 3000 774 516` →
  /// `"DX Crop (6048x4032 cropped to 4500x3000 at pixel 774,516)"`.
  #[test]
  fn crop_hi_speed_other_format() {
    let v = ParsedValue::new(RawValue::U64(vec![2, 6048, 4032, 4500, 3000, 774, 516]));
    assert_eq!(
      NikonConv::CropHiSpeed.apply(&v, true, None, ByteOrder::Big),
      Some(TagValue::Str(SmolStr::new(
        "DX Crop (6048x4032 cropped to 4500x3000 at pixel 774,516)"
      )))
    );
    // A non-7 count renders `Unknown ($val)`.
    let bad = ParsedValue::new(RawValue::U64(vec![0, 0, 0]));
    assert_eq!(
      NikonConv::CropHiSpeed.apply(&bad, true, None, ByteOrder::Big),
      Some(TagValue::Str(SmolStr::new("Unknown (0 0 0)")))
    );
    // `-n` emits the raw joined string.
    assert_eq!(
      NikonConv::CropHiSpeed.apply(&v, false, None, ByteOrder::Big),
      Some(TagValue::Str(SmolStr::new("2 6048 4032 4500 3000 774 516")))
    );
  }

  /// `RetouchHistory` (0x009e) — ValueConv trims trailing ` 0` groups, the
  /// ARRAY PrintConv maps each remaining element via `%retouchValues` and joins
  /// with `"; "`. Oracle (Perl): `7 8 0 0 0 0 0 0 0 0` ValueConv → `7 8` →
  /// PrintConv → `"D-Lighting; Red Eye"`. A bare `0` → `"None"`.
  #[test]
  fn retouch_history_array_print_conv() {
    let v = ParsedValue::new(RawValue::U64(vec![7, 8, 0, 0, 0, 0, 0, 0, 0, 0]));
    assert_eq!(
      NikonConv::RetouchHistory.apply(&v, true, None, ByteOrder::Big),
      Some(TagValue::Str(SmolStr::new("D-Lighting; Red Eye")))
    );
    // `-n` emits the post-ValueConv (trimmed) raw string.
    assert_eq!(
      NikonConv::RetouchHistory.apply(&v, false, None, ByteOrder::Big),
      Some(TagValue::Str(SmolStr::new("7 8")))
    );
    // All-zero (a single 0 remains after trimming) → "None".
    let none = ParsedValue::new(RawValue::U64(vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    assert_eq!(
      NikonConv::RetouchHistory.apply(&none, true, None, ByteOrder::Big),
      Some(TagValue::Str(SmolStr::new("None")))
    );
    // An unmapped code → `Unknown (N)`.
    let unk = ParsedValue::new(RawValue::U64(vec![99, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    assert_eq!(
      NikonConv::RetouchHistory.apply(&unk, true, None, ByteOrder::Big),
      Some(TagValue::Str(SmolStr::new("Unknown (99)")))
    );
  }

  /// `PowerUpTime` (0x00b6) — RawConv unpacks a 16-bit year (per byte order) +
  /// 5 bytes M/D/h/m/s; the PrintConv `ConvertDateTime` is identity. Big-endian
  /// year 2008 (`0x07d8`): `07 d8 05 1e 0c 22 38` → `"2008:05:30 12:34:56"`.
  #[test]
  fn power_up_time_big_endian_decode() {
    let be = ParsedValue::new(RawValue::Bytes(vec![
      0x07, 0xd8, 0x05, 0x1e, 0x0c, 0x22, 0x38,
    ]));
    assert_eq!(
      NikonConv::PowerUpTime.apply(&be, true, None, ByteOrder::Big),
      Some(TagValue::Str(SmolStr::new("2008:05:30 12:34:56")))
    );
    // Little-endian: the year bytes swap (`d8 07` → 2008).
    let le = ParsedValue::new(RawValue::Bytes(vec![
      0xd8, 0x07, 0x05, 0x1e, 0x0c, 0x22, 0x38,
    ]));
    assert_eq!(
      NikonConv::PowerUpTime.apply(&le, true, None, ByteOrder::Little),
      Some(TagValue::Str(SmolStr::new("2008:05:30 12:34:56")))
    );
    // A value shorter than 7 bytes passes through verbatim (the RawConv guard).
    let short = ParsedValue::new(RawValue::Bytes(vec![0x07, 0xd8]));
    assert!(matches!(
      NikonConv::PowerUpTime.apply(&short, true, None, ByteOrder::Big),
      Some(TagValue::Bytes(_))
    ));
  }

  /// `NEFBitDepth` (0x0e22) — a space-joined PrintConv hash. Oracle: `8 8 8 0`
  /// → `"8 x 3"`; `0 0 0 0` → `"n/a (JPEG)"`; an unmapped record → `Unknown`.
  #[test]
  fn nef_bit_depth_hash() {
    let v = ParsedValue::new(RawValue::U64(vec![8, 8, 8, 0]));
    assert_eq!(
      NikonConv::NefBitDepth.apply(&v, true, None, ByteOrder::Big),
      Some(TagValue::Str(SmolStr::new("8 x 3")))
    );
    let jpeg = ParsedValue::new(RawValue::U64(vec![0, 0, 0, 0]));
    assert_eq!(
      NikonConv::NefBitDepth.apply(&jpeg, true, None, ByteOrder::Big),
      Some(TagValue::Str(SmolStr::new("n/a (JPEG)")))
    );
    let unk = ParsedValue::new(RawValue::U64(vec![10, 0, 0, 0]));
    assert_eq!(
      NikonConv::NefBitDepth.apply(&unk, true, None, ByteOrder::Big),
      Some(TagValue::Str(SmolStr::new("Unknown (10 0 0 0)")))
    );
  }

  /// `SilentPhotography` (0x00bf) — `%offOn`. `0` → `"Off"`, `1` → `"On"`.
  #[test]
  fn silent_photography_off_on() {
    let off = ParsedValue::new(RawValue::U64(vec![0]));
    let on = ParsedValue::new(RawValue::U64(vec![1]));
    assert_eq!(
      NikonConv::OffOn.apply(&off, true, None, ByteOrder::Big),
      Some(TagValue::Str(SmolStr::new("Off")))
    );
    assert_eq!(
      NikonConv::OffOn.apply(&on, true, None, ByteOrder::Big),
      Some(TagValue::Str(SmolStr::new("On")))
    );
  }
}
