// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Panasonic-specific PrintConv enum — covers the per-tag PrintConv hashes
//! and a few inline expressions in `%Image::ExifTool::Panasonic::Main`
//! (`Panasonic.pm:265-1601`). Faithful 1:1 against bundled 13.59.
//!
//! Every variant is a named arm with a citation. Bundled-PrintConv hashes
//! are reproduced key-for-key; the rendered label text is byte-identical to
//! what bundled emits.

#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::RawValue;
use crate::value::{TagValue, format_g};
use smol_str::SmolStr;
use std::string::String;
use std::vec::Vec;

/// Every `%Panasonic::Main` tag id whose `Condition`-driven suppression the
/// parse path models — the "condition-aware" set the
/// `tests/panasonic_main_condition.rs` oracle requires. All three are
/// single-HASH `$format`/`$$valPt` rows handled by
/// [`PanasonicPrintConv::single_hash_condition_holds`]; the model-conditional
/// ARRAY rows 0x000f/0x002c each have an unconditional catch-all branch (so
/// they NEVER suppress — the branch selection lives in
/// `af_area_mode_for_model`/`contrast_mode_for_model`) and are not listed.
pub const CONDITION_GATED_IDS: &[u16] = &[0xc4, 0xc5, 0xe4];

/// Every `%Panasonic::Main` LEAF tag id whose `RawConv` can return `undef` to
/// DROP a sentinel raw value — the "rawconv-drop" set the
/// `tests/panasonic_main_rawconv.rs` oracle requires. Two mechanisms feed it:
///
/// - 0x86 ManometerPressure (`$val==65535 ? undef`) and 0xd1 ISO
///   (`$val > 0xfffffff0 ? undef`) — gated by
///   [`PanasonicPrintConv::rawconv_drops`] (the exact predicate + `.pm` cites
///   are there).
/// - 0xc5 / 0xe4 LensTypeModel (`return undef unless $val`, i.e. a zero-value
///   drop) — gated by
///   [`PanasonicPrintConv::apply_lens_type_model`] (folded into the byte-swap
///   conv, which returns `None` on a zero raw).
///
/// The `%Panasonic::Main` rows with a non-dropping RawConv are EXCLUDED:
/// there are none beyond these (no DataMember-capture or binary-passthrough
/// RawConv in the Panasonic Main table).
pub const RAWCONV_DROP_IDS: &[u16] = &[0x86, 0xc5, 0xd1, 0xe4];

/// Per-tag PrintConv strategy for the Panasonic Main IFD table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PanasonicPrintConv {
  /// No PrintConv — emit raw scalar.
  None,
  /// `ImageQuality` (`Panasonic.pm:270-285`).
  ImageQuality,
  /// `FirmwareVersion` (`Panasonic.pm:286-302`) — undef[4]; if any byte is
  /// in `\0-\x2f` then `join(" ",unpack("C*"))`, then PrintConv `tr/ /./`.
  FirmwareVersion,
  /// `WhiteBalance` (`Panasonic.pm:303-322`).
  WhiteBalance,
  /// `FocusMode` (`Panasonic.pm:323-335`).
  FocusMode,
  /// `AFAreaMode` (`Panasonic.pm:347-382`) — "other models" (last,
  /// unconditional) branch; the PrintConv keys on the space-joined int8u
  /// pair. Selected for every Model EXCEPT `DMC-FZ10` (and for an absent
  /// Model, since `undef =~ /DMC-FZ10\b/` is false).
  AfAreaMode,
  /// `AFAreaMode` 0x0f FZ10 branch (`Panasonic.pm:338-346`) —
  /// `Condition => '$$self{Model} =~ /DMC-FZ10\b/'`. Only `'0 1'`/`'0 16'`
  /// are defined; selected solely for the DMC-FZ10.
  AfAreaModeFz10,
  /// `ImageStabilization` (`Panasonic.pm:383-399`).
  ImageStabilization,
  /// `MacroMode` (`Panasonic.pm:400-409`).
  MacroMode,
  /// `ShootingMode` — uses the shared `%shootingMode` (`Panasonic.pm:181-263`).
  ShootingMode,
  /// `SceneMode` (`Panasonic.pm:1532-1540`) — `{0=>'Off', %shootingMode}`.
  SceneMode,
  /// `Audio` (`Panasonic.pm:416-424`).
  Audio,
  /// `WhiteBalanceBias` (`Panasonic.pm:431-439`) — int16s/3 then
  /// `Exif::PrintFraction`.
  WhiteBalanceBias,
  /// `FlashBias` (`Panasonic.pm:440-448`) — same as `WhiteBalanceBias`.
  FlashBias,
  /// `InternalSerialNumber` (`Panasonic.pm:449-463`).
  InternalSerialNumber,
  /// `PanasonicExifVersion`/`MakerNoteVersion` (`Panasonic.pm:464-467`,
  /// `:1528-1531`) — undef passthrough (ASCII).
  PanasonicExifVersion,
  /// `VideoFrameRate` (`Panasonic.pm:468-476`) — `0=>'n/a'`, else passthrough.
  VideoFrameRate,
  /// `ColorEffect` (`Panasonic.pm:477-490`).
  ColorEffect,
  /// `TimeSincePowerOn` (`Panasonic.pm:491-528`).
  TimeSincePowerOn,
  /// `BurstMode` (`Panasonic.pm:530-544`).
  BurstMode,
  /// `ContrastMode` 0x2c — the FIRST (PrintHex) branch
  /// (`Panasonic.pm:550-583`). `Condition`: Model NOT in
  /// `/^DMC-(FX10|G1|L1|L10|LC80|GF\d+|G2|TZ10|ZS7)$/` AND NOT `/^DC-/`
  /// (so also the branch for an absent Model). `Flags => 'PrintHex'`.
  ContrastMode,
  /// `ContrastMode` 0x2c GF/G2 branch (`Panasonic.pm:585-657`) —
  /// `Condition => '$$self{Model} =~ /^DMC-(GF\d+|G2)$/'` (G2/GF1/GF2/GF3/
  /// GF5/GF6). Plain (non-PrintHex) int16u hash.
  ContrastModeGfG2,
  /// `ContrastMode` 0x2c TZ10/ZS7 branch (`Panasonic.pm:658-668`) —
  /// `Condition => '$$self{Model} =~ /^DMC-(TZ10|ZS7)$/'`. Plain int16u
  /// hash.
  ContrastModeTz10Zs7,
  /// `NoiseReduction` (`Panasonic.pm:661-679`).
  NoiseReduction,
  /// `SelfTimer` (`Panasonic.pm:680-694`).
  SelfTimer,
  /// `Rotation` (`Panasonic.pm:695-704`).
  Rotation,
  /// `AFAssistLamp` (`Panasonic.pm:705-716`).
  AfAssistLamp,
  /// `ColorMode` (`Panasonic.pm:717-726`).
  ColorMode,
  /// `BabyAge`/`BabyAge2` (`Panasonic.pm:727-733`, `:1580-1586`) —
  /// `"9999:99:99 00:00:00" => "(not set)"`, else passthrough.
  BabyAge,
  /// `OpticalZoomMode` (`Panasonic.pm:734-741`).
  OpticalZoomMode,
  /// `ConversionLens` (`Panasonic.pm:742-751`).
  ConversionLens,
  /// `TravelDay` (`Panasonic.pm:752-757`) — `65535 ? "n/a" : $val`.
  TravelDay,
  /// `BatteryLevel` (`Panasonic.pm:760-772`).
  BatteryLevel,
  /// `Contrast`/`Saturation`/`Sharpness` — `Exif::printParameter`.
  PrintParameter,
  /// `WorldTimeLocation` (`Panasonic.pm:779-786`).
  WorldTimeLocation,
  /// `TextStamp` (`Panasonic.pm:787-792` etc.) — `{1=>'Off',2=>'On'}`.
  TextStamp,
  /// `ProgramISO` (`Panasonic.pm:793-802`).
  ProgramIso,
  /// `FilmMode` (`Panasonic.pm:831-849`).
  FilmMode,
  /// `JPEGQuality` (`Panasonic.pm:850-860`).
  JpegQuality,
  /// `BracketSettings` (`Panasonic.pm:865-877`).
  BracketSettings,
  /// `FlashCurtain` (`Panasonic.pm:890-898`).
  FlashCurtain,
  /// `LongExposureNoiseReduction` (`Panasonic.pm:899-906`) — `{1=>Off,2=>On}`.
  LongExposureNoiseReduction,
  /// `Transform` (`Panasonic.pm:970-983`, `:1587-1600`) — int16s pair hash.
  Transform,
  /// `IntelligentExposure` (`Panasonic.pm:987-997`).
  IntelligentExposure,
  /// `LensFirmwareVersion` (`Panasonic.pm:999-1006`) — int8u[4]; tr/ /./.
  LensFirmwareVersion,
  /// `FlashWarning` (`Panasonic.pm:1013-1017`).
  FlashWarning,
  /// `IntelligentResolution` (`Panasonic.pm:1073-1085`).
  IntelligentResolution,
  /// `IntelligentD-Range` (`Panasonic.pm:1099-1108`).
  IntelligentDRange,
  /// `ManometerPressure` (`Panasonic.pm:1127-1135`) — int16u/10, "%.1f kPa".
  ManometerPressure,
  /// `PhotoStyle` (`Panasonic.pm:1136-1155`).
  PhotoStyle,
  /// `AccelerometerZ`/`X`/`Y` (`Panasonic.pm:1170-1187`) — int16s passthrough.
  AccelerometerSint,
  /// `CameraOrientation` (`Panasonic.pm:1188-1199`).
  CameraOrientation,
  /// `RollAngle` (`Panasonic.pm:1200-1207`) — int16s/10, no PrintConv.
  RollAngle,
  /// `PitchAngle` (`Panasonic.pm:1208-1215`) — `-$val/10`, no PrintConv.
  PitchAngle,
  /// `SweepPanoramaDirection` (`Panasonic.pm:1222-1232`).
  SweepPanoramaDirection,
  /// `TimerRecording` (`Panasonic.pm:1237-1246`).
  TimerRecording,
  /// `HDR` (`Panasonic.pm:1251-1263`).
  Hdr,
  /// `ShutterType` (`Panasonic.pm:1264-1272`).
  ShutterType,
  /// `MonochromeFilterEffect` (`Panasonic.pm:1324-1328`).
  MonochromeFilterEffect,
  /// `VideoBurstResolution` (`Panasonic.pm:1343-1347`).
  VideoBurstResolution,
  /// `MultiExposure` (`Panasonic.pm:1348-1352`).
  MultiExposure,
  /// `VideoBurstMode` (`Panasonic.pm:1358-1374`) — int32u, PrintHex hash.
  VideoBurstMode,
  /// `DiffractionCorrection` (`Panasonic.pm:1375-1379`).
  DiffractionCorrection,
  /// `VideoPreburst` (`Panasonic.pm:1397-1401`).
  VideoPreburst,
  /// `SensorType` (`Panasonic.pm:1402-1409`).
  SensorType,
  /// `MonochromeGrainEffect` (`Panasonic.pm:1434-1443`) — Off/Low/Standard/High.
  OffLowStdHigh,
  /// `AFSubjectDetection` (`Panasonic.pm:1477-1496`).
  AfSubjectDetection,
  /// `HighlightWarning` (`Panasonic.pm:1541-1545`).
  HighlightWarning,
  /// Shared `{0=>'Off',1=>'On'}` — ClearRetouch (`:1110-1114`),
  /// ShadingCompensation (`:1156-1163`), TouchAE (`:1319-1323`),
  /// RedEyeRemoval (`:1353-1357`), HybridLogGamma (`:1444-1448`),
  /// DynamicRangeBoost (`:1497-1501`).
  OffOn,
  /// Shared `{1=>'No',2=>'Yes'}` — LongExposureNRUsed (`:1386-1390`),
  /// DarkFocusEnvironment (`:1546-1550`).
  NoYes12,
  /// `LensType` 0x51 / `LensSerialNumber` 0x52 / `AccessoryType` 0x53 /
  /// `AccessorySerialNumber` 0x54 (`Panasonic.pm:944-969`) — `Writable =>
  /// 'string'`, `ValueConv => '$val=~s/ +$//; $val'` (strip TRAILING spaces
  /// only). Applies in both `-n` and `-j` (no PrintConv). NUL termination is
  /// already handled by the string reader.
  TrimTrailingSpaces,
  /// `LensTypeModel` 0xc5 / 0xe4 (`Panasonic.pm:1417-1428`, `:1461-1472`) —
  /// `Writable => 'int16u'`. A `RawConv` of `return undef unless $val;`
  /// (drops a zero value → the tag is ABSENT) followed by a byte-swap
  /// `ValueConv => '$_=sprintf("%.4x",$val); s/(..)(..)/$2 $1/; $_'` that
  /// renders the int16u as two space-separated hex byte-pairs, low byte
  /// first: `0x1234 → "34 12"`. No PrintConv, so `-n` and `-j` are identical.
  /// The undef-drop is observed by [`super::parse_in_tiff`] (which calls
  /// [`apply_lens_type_model`](Self::apply_lens_type_model)); the
  /// Olympus-Composite-`LensID` cross-table that combines this with
  /// `LensTypeMake` (`Panasonic.pm:1410-1411`) is deferred — only the DIRECT
  /// tag conversion is implemented here.
  LensTypeModel,
  /// `AFPointPosition` 0x4d (`Panasonic.pm:916-935`) — `Writable =>
  /// 'rational64u'`, `Count => 2`. The rational pair decodes (default
  /// ValueConv) to a space-joined DECIMAL string `$val` (each rational
  /// rendered via `RoundFloat(n/d, 10)`, e.g. `128/256 → "0.5"`), which is
  /// the `-n` output. The `PrintConv` then keys off that decimal `$val`:
  /// `'none'` if `$val eq '16777216 16777216'` (the raw 16777216/1 sentinel),
  /// `'n/a'` if `$val =~ /^4194303\.9/` (the 4294967295/1024 sentinel →
  /// `"4194303.999"`), else `sprintf("%.2g %.2g", split ' ', $val)`.
  AfPointPosition,
  /// `AFAreaSize` 0x4d-sibling 0xde (`Panasonic.pm:1453-1460`) — `Writable =>
  /// 'rational64u'`, `Count => 2`. Same decimal-pair ValueConv `$val` (the
  /// `-n` output). `PrintConv => '$val =~ /^4194303\.9/ ? "n/a" : $val'`:
  /// `'n/a'` for the 4294967295/1024 manual-focus sentinel, else the decimal
  /// pair verbatim.
  AfAreaSize,
  /// `FilterEffect` 0xa1 (`Panasonic.pm:1274-1304`) — `Writable =>
  /// 'rational64u'` but `Format => 'int32u'`, so `ProcessExif` re-reads the 8
  /// on-disk bytes as int32u[2] (the [`super::body`] walker applies this via
  /// the modelled `FormatOverride`). The PrintConv is a plain (non-PrintHex)
  /// hash keyed on the space-joined int32u pair (`"0 1" => 'Expressive'`, …);
  /// a HASH-miss renders the decimal `Unknown (a b)`. `-n` emits the raw int
  /// pair string.
  FilterEffect,
  /// `PostFocusMerging` 0xbf (`Panasonic.pm:1391-1396`) — `Format => 'int32u',
  /// Count => 2`. Plain hash with the single key `"0 0" => 'Post Focus Auto
  /// Merging or None'`; HASH-miss ⇒ decimal `Unknown (a b)`. `-n` emits the
  /// int pair string.
  PostFocusMerging,
  /// `TimeStamp` 0xaf (`Panasonic.pm:1335-1342`) — `Writable => 'string'`,
  /// `PrintConv => '$self->ConvertDateTime($val)'`. With ExifTool's DEFAULT
  /// options (no `DateFormat`, no `GlobalTimeShift`) `ConvertDateTime` returns
  /// its input UNCHANGED (`ExifTool.pm:6574` — both the `$shift` and `$fmt`
  /// branches are skipped), so `-j` equals the raw string (= `-n`). Routed
  /// through the shared [`crate::datetime::convert_datetime`] port (identity
  /// under default options); the `DateFormat`/`GlobalTimeShift` reformatting is
  /// faithfully deferred there per spec §5, consistent with every other port.
  TimeStamp,
}

impl PanasonicPrintConv {
  /// Select the model-conditional `0x0f AFAreaMode` branch
  /// (`Panasonic.pm:336-382`). ExifTool's conditional-list semantics: the
  /// first branch whose `Condition` is true wins; the FZ10 branch requires
  /// `$$self{Model} =~ /DMC-FZ10\b/`, otherwise the unconditional
  /// "other models" branch applies (also for an absent Model, since
  /// `undef =~ /DMC-FZ10/` is false).
  #[must_use]
  pub fn af_area_mode_for_model(model: Option<&str>) -> Self {
    if model.is_some_and(model_is_fz10) {
      PanasonicPrintConv::AfAreaModeFz10
    } else {
      PanasonicPrintConv::AfAreaMode
    }
  }

  /// Select the model-conditional `0x2c ContrastMode` branch
  /// (`Panasonic.pm:549-660`) in ExifTool's declared order:
  ///
  /// 1. PrintHex branch — `$$self{Model} !~
  ///    /^DMC-(FX10|G1|L1|L10|LC80|GF\d+|G2|TZ10|ZS7)$/ and !~ /^DC-/`
  ///    (also the branch for an absent Model — both negated matches hold for
  ///    `undef`/empty).
  /// 2. GF/G2 branch — `=~ /^DMC-(GF\d+|G2)$/`.
  /// 3. TZ10/ZS7 branch — `=~ /^DMC-(TZ10|ZS7)$/`.
  /// 4. Fallback (no `Condition`, no `PrintConv`) — RAW value
  ///    ([`PanasonicPrintConv::None`]), for `DMC-(FX10|G1|L1|L10|LC80)` and
  ///    every `DC-` body that isn't GF/G2/TZ10/ZS7.
  #[must_use]
  pub fn contrast_mode_for_model(model: Option<&str>) -> Self {
    let m = model.unwrap_or("");
    if contrast_mode_branch1(m) {
      PanasonicPrintConv::ContrastMode
    } else if model_is_gf_g2(m) {
      PanasonicPrintConv::ContrastModeGfG2
    } else if model_is_tz10_zs7(m) {
      PanasonicPrintConv::ContrastModeTz10Zs7
    } else {
      // Last (unconditional) branch has no PrintConv ⇒ raw value.
      PanasonicPrintConv::None
    }
  }

  /// `LensTypeModel` 0xc5 / 0xe4 (`Panasonic.pm:1417-1428`, `:1461-1472`)
  /// with the bundled `RawConv`'s undef-drop honoured: returns `None` when
  /// the raw int16u is `0` (`RawConv => 'return undef unless $val;'` ⇒ the
  /// tag is suppressed from output), else `Some` of the byte-swap
  /// `ValueConv` string (`0x1234 → "34 12"`). [`super::parse_in_tiff`] uses
  /// this for 0xc5/0xe4 so a zero value yields NO emission (matching
  /// ExifTool); the plain [`apply`](Self::apply) path can't drop a tag and
  /// renders the (rare) zero as `"00 00"`.
  #[must_use]
  pub fn apply_lens_type_model(raw: &RawValue, print_conv: bool) -> Option<TagValue> {
    lens_type_model(raw, print_conv)
  }

  /// Whether tag `id`'s single-HASH `Condition` HOLDS for this entry — i.e.
  /// whether ExifTool's `GetTagInfo` would return the tag (so it is emitted).
  /// `false` ⇒ the `Condition` fails ⇒ the tag is SUPPRESSED (absent from
  /// default output). `format` is the entry's on-disk TIFF format name
  /// (`$format`); `raw` is the decoded value (for the `$$valPt` test on
  /// 0xc4). Tags without a suppressible single-HASH `Condition` return `true`.
  ///
  /// These three rows share tag ids that are REUSED with other formats on
  /// other Panasonic/Leica bodies; the `$format eq "int16u"` guard is how
  /// ExifTool picks the LensType meaning (vs the reused tag), so a non-int16u
  /// entry must be suppressed here, not rendered.
  #[must_use]
  pub fn single_hash_condition_holds(id: u16, format: &str, raw: &RawValue) -> bool {
    match id {
      // 0xc4 LensTypeMake (`Panasonic.pm:1414`):
      // `$format eq "int16u" and $$valPt ne "\xff\xff"`. The `$$valPt` test
      // drops the int16u value 65535 (`0xffff`) — "ignore make 65535 for now".
      0xc4 => format == "int16u" && first_u64(raw) != Some(0xffff),
      // 0xc5 / 0xe4 LensTypeModel (`Panasonic.pm:1419,1463`):
      // `$format eq "int16u"`.
      0xc5 | 0xe4 => format == "int16u",
      // Everything else: no suppressible single-HASH Condition ⇒ always emit.
      _ => true,
    }
  }

  /// Apply the PrintConv to a raw value.
  #[must_use]
  pub fn apply(self, raw: &RawValue, print_conv: bool) -> TagValue {
    match self {
      PanasonicPrintConv::None => raw_to_tag_value(raw),
      PanasonicPrintConv::ImageQuality => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:275-283
        1 => Some("TIFF"),
        2 => Some("High"),
        3 => Some("Normal"),
        6 => Some("Very High"),
        7 => Some("RAW"),
        9 => Some("Motion Picture"),
        11 => Some("Full HD Movie"),
        12 => Some("4k Movie"),
        _ => None,
      }),
      PanasonicPrintConv::FirmwareVersion => firmware_version(raw, print_conv),
      PanasonicPrintConv::LensFirmwareVersion => lens_firmware_version(raw, print_conv),
      PanasonicPrintConv::WhiteBalance => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:307-320
        1 => Some("Auto"),
        2 => Some("Daylight"),
        3 => Some("Cloudy"),
        4 => Some("Incandescent"),
        5 => Some("Manual"),
        8 => Some("Flash"),
        10 => Some("Black & White"),
        11 => Some("Manual 2"),
        12 => Some("Shade"),
        13 => Some("Kelvin"),
        14 => Some("Manual 3"),
        15 => Some("Manual 4"),
        19 => Some("Auto (cool)"),
        _ => None,
      }),
      PanasonicPrintConv::FocusMode => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:327-333
        1 => Some("Auto"),
        2 => Some("Manual"),
        4 => Some("Auto, Focus button"),
        5 => Some("Auto, Continuous"),
        6 => Some("AF-S"),
        7 => Some("AF-C"),
        8 => Some("AF-F"),
        _ => None,
      }),
      PanasonicPrintConv::AfAreaMode => af_area_mode(raw, print_conv),
      PanasonicPrintConv::AfAreaModeFz10 => af_area_mode_fz10(raw, print_conv),
      PanasonicPrintConv::ImageStabilization => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:387-397
        2 => Some("On, Optical"),
        3 => Some("Off"),
        4 => Some("On, Mode 2"),
        5 => Some("On, Optical Panning"),
        6 => Some("On, Body-only"),
        7 => Some("On, Body-only Panning"),
        9 => Some("Dual IS"),
        10 => Some("Dual IS Panning"),
        11 => Some("Dual2 IS"),
        12 => Some("Dual2 IS Panning"),
        _ => None,
      }),
      PanasonicPrintConv::MacroMode => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:404-407
        1 => Some("On"),
        2 => Some("Off"),
        0x101 => Some("Tele-Macro"),
        0x201 => Some("Macro Zoom"),
        _ => None,
      }),
      PanasonicPrintConv::ShootingMode => simple_label(raw, print_conv, shooting_mode_label),
      PanasonicPrintConv::SceneMode => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:1537 — `0 => 'Off'`, then `%shootingMode`.
        0 => Some("Off"),
        _ => shooting_mode_label(n),
      }),
      PanasonicPrintConv::Audio => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:420-422
        1 => Some("Yes"),
        2 => Some("No"),
        3 => Some("Stereo"),
        _ => None,
      }),
      PanasonicPrintConv::WhiteBalanceBias => fraction_third(raw, print_conv),
      PanasonicPrintConv::FlashBias => fraction_third(raw, print_conv),
      PanasonicPrintConv::InternalSerialNumber => internal_serial_number(raw, print_conv),
      PanasonicPrintConv::PanasonicExifVersion => panasonic_exif_version(raw),
      PanasonicPrintConv::VideoFrameRate => video_frame_rate(raw, print_conv),
      PanasonicPrintConv::ColorEffect => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:482-488
        1 => Some("Off"),
        2 => Some("Warm"),
        3 => Some("Cool"),
        4 => Some("Black & White"),
        5 => Some("Sepia"),
        6 => Some("Happy"),
        8 => Some("Vivid"),
        _ => None,
      }),
      PanasonicPrintConv::TimeSincePowerOn => time_since_power_on(raw, print_conv),
      PanasonicPrintConv::BurstMode => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:535-542
        0 => Some("Off"),
        1 => Some("On"),
        2 => Some("Auto Exposure Bracketing (AEB)"),
        3 => Some("Focus Bracketing"),
        4 => Some("Unlimited"),
        8 => Some("White Balance Bracketing"),
        17 => Some("On (with flash)"),
        18 => Some("Aperture Bracketing"),
        _ => None,
      }),
      PanasonicPrintConv::ContrastMode => contrast_mode(raw, print_conv),
      PanasonicPrintConv::ContrastModeGfG2 => contrast_mode_gf_g2(raw, print_conv),
      PanasonicPrintConv::ContrastModeTz10Zs7 => contrast_mode_tz10_zs7(raw, print_conv),
      PanasonicPrintConv::NoiseReduction => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:666-677
        0 => Some("Standard"),
        1 => Some("Low (-1)"),
        2 => Some("High (+1)"),
        3 => Some("Lowest (-2)"),
        4 => Some("Highest (+2)"),
        5 => Some("+5"),
        6 => Some("+6"),
        65531 => Some("-5"),
        65532 => Some("-4"),
        65533 => Some("-3"),
        65534 => Some("-2"),
        65535 => Some("-1"),
        _ => None,
      }),
      PanasonicPrintConv::SelfTimer => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:684-691
        0 => Some("Off (0)"),
        1 => Some("Off"),
        2 => Some("10 s"),
        3 => Some("2 s"),
        4 => Some("10 s / 3 pictures"),
        258 => Some("2 s after shutter pressed"),
        266 => Some("10 s after shutter pressed"),
        778 => Some("3 photos after 10 s"),
        _ => None,
      }),
      PanasonicPrintConv::Rotation => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:699-702
        1 => Some("Horizontal (normal)"),
        3 => Some("Rotate 180"),
        6 => Some("Rotate 90 CW"),
        8 => Some("Rotate 270 CW"),
        _ => None,
      }),
      PanasonicPrintConv::AfAssistLamp => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:709-712
        1 => Some("Fired"),
        2 => Some("Enabled but Not Used"),
        3 => Some("Disabled but Required"),
        4 => Some("Disabled and Not Required"),
        _ => None,
      }),
      PanasonicPrintConv::ColorMode => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:721-723
        0 => Some("Normal"),
        1 => Some("Natural"),
        2 => Some("Vivid"),
        _ => None,
      }),
      PanasonicPrintConv::BabyAge => baby_age(raw, print_conv),
      PanasonicPrintConv::OpticalZoomMode => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:738-739
        1 => Some("Standard"),
        2 => Some("Extended"),
        _ => None,
      }),
      PanasonicPrintConv::ConversionLens => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:746-749
        1 => Some("Off"),
        2 => Some("Wide"),
        3 => Some("Telephoto"),
        4 => Some("Macro"),
        _ => None,
      }),
      PanasonicPrintConv::TravelDay => {
        // Panasonic.pm:755 — `$val == 65535 ? "n/a" : $val`.
        let Some(n) = first_i64(raw) else {
          return raw_to_tag_value(raw);
        };
        if print_conv && n == 65535 {
          TagValue::Str("n/a".into())
        } else {
          TagValue::I64(n)
        }
      }
      PanasonicPrintConv::BatteryLevel => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:764-770
        1 => Some("Full"),
        2 => Some("Medium"),
        3 => Some("Low"),
        4 => Some("Near Empty"),
        7 => Some("Near Full"),
        8 => Some("Medium Low"),
        256 => Some("n/a"),
        _ => None,
      }),
      PanasonicPrintConv::PrintParameter => print_parameter(raw, print_conv),
      PanasonicPrintConv::WorldTimeLocation => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:783-784
        1 => Some("Home"),
        2 => Some("Destination"),
        _ => None,
      }),
      PanasonicPrintConv::TextStamp => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:791 — `{ 1 => 'Off', 2 => 'On' }`.
        1 => Some("Off"),
        2 => Some("On"),
        _ => None,
      }),
      PanasonicPrintConv::ProgramIso => {
        // Panasonic.pm:796-800. OTHER passes int through; 65534/65535/-1 mapped.
        let Some(n) = first_i64(raw) else {
          return raw_to_tag_value(raw);
        };
        if !print_conv {
          return TagValue::I64(n);
        }
        match n {
          65534 => TagValue::Str("Intelligent ISO".into()),
          65535 | -1 => TagValue::Str("n/a".into()),
          _ => TagValue::I64(n),
        }
      }
      PanasonicPrintConv::FilmMode => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:835-846
        0 => Some("n/a"),
        1 => Some("Standard (color)"),
        2 => Some("Dynamic (color)"),
        3 => Some("Nature (color)"),
        4 => Some("Smooth (color)"),
        5 => Some("Standard (B&W)"),
        6 => Some("Dynamic (B&W)"),
        7 => Some("Smooth (B&W)"),
        10 => Some("Nostalgic"),
        11 => Some("Vibrant"),
        _ => None,
      }),
      PanasonicPrintConv::JpegQuality => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:854-858
        0 => Some("n/a (Movie)"),
        2 => Some("High"),
        3 => Some("Standard"),
        6 => Some("Very High"),
        255 => Some("n/a (RAW only)"),
        _ => None,
      }),
      PanasonicPrintConv::BracketSettings => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:869-875
        0 => Some("No Bracket"),
        1 => Some("3 Images, Sequence 0/-/+"),
        2 => Some("3 Images, Sequence -/0/+"),
        3 => Some("5 Images, Sequence 0/-/+"),
        4 => Some("5 Images, Sequence -/0/+"),
        5 => Some("7 Images, Sequence 0/-/+"),
        6 => Some("7 Images, Sequence -/0/+"),
        _ => None,
      }),
      PanasonicPrintConv::FlashCurtain => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:894-896
        0 => Some("n/a"),
        1 => Some("1st"),
        2 => Some("2nd"),
        _ => None,
      }),
      PanasonicPrintConv::LongExposureNoiseReduction => {
        simple_label(raw, print_conv, |n| match n {
          // Panasonic.pm:903-904
          1 => Some("Off"),
          2 => Some("On"),
          _ => None,
        })
      }
      PanasonicPrintConv::Transform => transform(raw, print_conv),
      PanasonicPrintConv::IntelligentExposure => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:992-995
        0 => Some("Off"),
        1 => Some("Low"),
        2 => Some("Standard"),
        3 => Some("High"),
        _ => None,
      }),
      PanasonicPrintConv::FlashWarning => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:1016
        0 => Some("No"),
        1 => Some("Yes (flash required but disabled)"),
        _ => None,
      }),
      PanasonicPrintConv::IntelligentResolution => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:1077-1083
        0 => Some("Off"),
        1 => Some("Low"),
        2 => Some("Standard"),
        3 => Some("High"),
        4 => Some("Extended"),
        _ => None,
      }),
      PanasonicPrintConv::IntelligentDRange => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:1103-1106
        0 => Some("Off"),
        1 => Some("Low"),
        2 => Some("Standard"),
        3 => Some("High"),
        _ => None,
      }),
      PanasonicPrintConv::ManometerPressure => manometer_pressure(raw, print_conv),
      PanasonicPrintConv::PhotoStyle => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:1140-1153
        0 => Some("Auto"),
        1 => Some("Standard or Custom"),
        2 => Some("Vivid"),
        3 => Some("Natural"),
        4 => Some("Monochrome"),
        5 => Some("Scenery"),
        6 => Some("Portrait"),
        8 => Some("Cinelike D"),
        9 => Some("Cinelike V"),
        11 => Some("L. Monochrome"),
        12 => Some("Like709"),
        15 => Some("L. Monochrome D"),
        17 => Some("V-Log"),
        18 => Some("Cinelike D2"),
        _ => None,
      }),
      PanasonicPrintConv::AccelerometerSint => {
        // Panasonic.pm:1170-1187 — int16s passthrough.
        let Some(n) = first_i64(raw) else {
          return raw_to_tag_value(raw);
        };
        TagValue::I64(n)
      }
      PanasonicPrintConv::CameraOrientation => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:1192-1197
        0 => Some("Normal"),
        1 => Some("Rotate CW"),
        2 => Some("Rotate 180"),
        3 => Some("Rotate CCW"),
        4 => Some("Tilt Upwards"),
        5 => Some("Tilt Downwards"),
        _ => None,
      }),
      PanasonicPrintConv::RollAngle => scaled_tenths(raw, print_conv, false),
      PanasonicPrintConv::PitchAngle => scaled_tenths(raw, print_conv, true),
      PanasonicPrintConv::SweepPanoramaDirection => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:1226-1230
        0 => Some("Off"),
        1 => Some("Left to Right"),
        2 => Some("Right to Left"),
        3 => Some("Top to Bottom"),
        4 => Some("Bottom to Top"),
        _ => None,
      }),
      PanasonicPrintConv::TimerRecording => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:1241-1244
        0 => Some("Off"),
        1 => Some("Time Lapse"),
        2 => Some("Stop-motion Animation"),
        3 => Some("Focus Bracketing"),
        _ => None,
      }),
      PanasonicPrintConv::Hdr => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:1255-1261
        0 => Some("Off"),
        100 => Some("1 EV"),
        200 => Some("2 EV"),
        300 => Some("3 EV"),
        32868 => Some("1 EV (Auto)"),
        32968 => Some("2 EV (Auto)"),
        33068 => Some("3 EV (Auto)"),
        _ => None,
      }),
      PanasonicPrintConv::ShutterType => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:1268-1270
        0 => Some("Mechanical"),
        1 => Some("Electronic"),
        2 => Some("Hybrid"),
        _ => None,
      }),
      PanasonicPrintConv::MonochromeFilterEffect => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:1327 — `{ 0 => 'Off', 1 => 'Yellow', 2 => 'Orange', 3 => 'Red', 4 => 'Green' }`.
        0 => Some("Off"),
        1 => Some("Yellow"),
        2 => Some("Orange"),
        3 => Some("Red"),
        4 => Some("Green"),
        _ => None,
      }),
      PanasonicPrintConv::VideoBurstResolution => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:1346 — `{ 1 => 'Off or 4K', 4 => '6K' }`.
        1 => Some("Off or 4K"),
        4 => Some("6K"),
        _ => None,
      }),
      PanasonicPrintConv::MultiExposure => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:1351 — `{ 0 => 'n/a', 1 => 'Off', 2 => 'On' }`.
        0 => Some("n/a"),
        1 => Some("Off"),
        2 => Some("On"),
        _ => None,
      }),
      PanasonicPrintConv::VideoBurstMode => video_burst_mode(raw, print_conv),
      PanasonicPrintConv::DiffractionCorrection => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:1378 — `{ 0 => 'Off', 1 => 'Auto' }`.
        0 => Some("Off"),
        1 => Some("Auto"),
        _ => None,
      }),
      PanasonicPrintConv::VideoPreburst => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:1400 — `{ 0 => 'No', 1 => '4K or 6K' }`.
        0 => Some("No"),
        1 => Some("4K or 6K"),
        _ => None,
      }),
      PanasonicPrintConv::SensorType => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:1406-1407
        0 => Some("Multi-aspect"),
        1 => Some("Standard"),
        _ => None,
      }),
      PanasonicPrintConv::OffLowStdHigh => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:1438-1441
        0 => Some("Off"),
        1 => Some("Low"),
        2 => Some("Standard"),
        3 => Some("High"),
        _ => None,
      }),
      PanasonicPrintConv::AfSubjectDetection => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:1481-1494
        0 => Some("n/a"),
        1 => Some("Human Eye/Face/Body"),
        2 => Some("Animal"),
        3 => Some("Human Eye/Face"),
        4 => Some("Animal Body"),
        5 => Some("Animal Eye/Body"),
        6 => Some("Car"),
        7 => Some("Motorcycle"),
        8 => Some("Car (main part priority)"),
        9 => Some("Motorcycle (helmet priority)"),
        10 => Some("Train"),
        11 => Some("Train (main part priority)"),
        12 => Some("Airplane"),
        13 => Some("Airplane (nose priority)"),
        _ => None,
      }),
      PanasonicPrintConv::HighlightWarning => simple_label(raw, print_conv, |n| match n {
        // Panasonic.pm:1544 — `{ 0 => 'Disabled', 1 => 'No', 2 => 'Yes' }`.
        0 => Some("Disabled"),
        1 => Some("No"),
        2 => Some("Yes"),
        _ => None,
      }),
      PanasonicPrintConv::OffOn => simple_label(raw, print_conv, |n| match n {
        // Shared `{ 0 => 'Off', 1 => 'On' }`.
        0 => Some("Off"),
        1 => Some("On"),
        _ => None,
      }),
      PanasonicPrintConv::NoYes12 => simple_label(raw, print_conv, |n| match n {
        // Shared `{ 1 => 'No', 2 => 'Yes' }`.
        1 => Some("No"),
        2 => Some("Yes"),
        _ => None,
      }),
      PanasonicPrintConv::TrimTrailingSpaces => trim_trailing_spaces(raw),
      // The undef-drop (zero ⇒ tag absent) is a RawConv side-effect that the
      // context-free `apply` can't perform (it returns `TagValue`), so it
      // renders the byte-swap unconditionally; `parse_in_tiff` routes 0xc5/
      // 0xe4 through `apply_lens_type_model` to honour the drop.
      PanasonicPrintConv::LensTypeModel => {
        lens_type_model(raw, print_conv).unwrap_or_else(|| raw_to_tag_value(raw))
      }
      PanasonicPrintConv::AfPointPosition => af_point_position(raw, print_conv),
      PanasonicPrintConv::AfAreaSize => af_area_size(raw, print_conv),
      PanasonicPrintConv::FilterEffect => int_pair_label(raw, print_conv, |key| match key {
        // Panasonic.pm:1280-1302 — int32u[2] pair keys, verbatim.
        "0 0" => Some("Off"),
        "0 1" => Some("Expressive"),
        "0 2" => Some("Retro"),
        "0 4" => Some("High Key"),
        "0 8" => Some("Sepia"),
        "0 16" => Some("High Dynamic"),
        "0 32" => Some("Miniature Effect"),
        "0 256" => Some("Low Key"),
        "0 512" => Some("Toy Effect"),
        "0 1024" => Some("Dynamic Monochrome"),
        "0 2048" => Some("Soft Focus"),
        "0 4096" => Some("Impressive Art"),
        "0 8192" => Some("Cross Process"),
        "0 16384" => Some("One Point Color"),
        "0 32768" => Some("Star Filter"),
        "0 524288" => Some("Old Days"),
        "0 1048576" => Some("Sunshine"),
        "0 2097152" => Some("Bleach Bypass"),
        "0 4194304" => Some("Toy Pop"),
        "0 8388608" => Some("Fantasy"),
        "0 33554432" => Some("Monochrome"),
        "0 67108864" => Some("Rough Monochrome"),
        "0 134217728" => Some("Silky Monochrome"),
        _ => None,
      }),
      PanasonicPrintConv::PostFocusMerging => int_pair_label(raw, print_conv, |key| match key {
        // Panasonic.pm:1395 — single key.
        "0 0" => Some("Post Focus Auto Merging or None"),
        _ => None,
      }),
      PanasonicPrintConv::TimeStamp => time_stamp(raw, print_conv),
    }
  }

  /// Whether tag `id`'s `RawConv` DROPS this raw value (returns `undef`) ⇒ the
  /// tag is SUPPRESSED (absent from output). In ExifTool a tag's `RawConv`
  /// runs during value extraction; an `undef` return means the value is not
  /// stored. Covers `%Panasonic::Main`'s two sentinel-drop scalar rows:
  ///
  /// - 0x86 ManometerPressure (`Panasonic.pm:1130`): `$val==65535 ? undef :
  ///   $val` — `Writable => 'int16u'`, drops the unsigned 65535.
  /// - 0xd1 ISO (`Panasonic.pm:1431`): `$val > 0xfffffff0 ? undef : $val` —
  ///   `Writable => 'int32u'`, drops any raw int32u greater than 0xfffffff0
  ///   (i.e. 0xfffffff1..=0xffffffff).
  ///
  /// The 0xc5/0xe4 LensTypeModel `return undef unless $val` drop
  /// (`Panasonic.pm:1421,1465`) is handled separately by
  /// [`apply_lens_type_model`](Self::apply_lens_type_model) (it is folded into
  /// the byte-swap conv), so it is NOT repeated here — but both ids are listed
  /// in [`RAWCONV_DROP_IDS`] for the completeness oracle. The drop tests the
  /// RAW value (pre-ValueConv/PrintConv), exactly as ExifTool's `RawConv`.
  /// Tags without a sentinel-drop RawConv return `false` (always emitted).
  #[must_use]
  pub fn rawconv_drops(id: u16, raw: &RawValue) -> bool {
    match id {
      // 0x86 ManometerPressure (`Panasonic.pm:1130`): `$val==65535 ? undef`.
      0x86 => first_u64(raw) == Some(65535),
      // 0xd1 ISO (`Panasonic.pm:1431`): `$val > 0xfffffff0 ? undef`.
      0xd1 => first_u64(raw).is_some_and(|v| v > 0xffff_fff0),
      _ => false,
    }
  }
}

// ----- model-conditional branch predicates (`$$self{Model}` regexes) -----
//
// Hand-rolled to match the bundled Perl regexes byte-for-byte (no regex
// dependency — mirrors Canon's `model_matches_*` style).

/// `$$self{Model} =~ /DMC-FZ10\b/` (`Panasonic.pm:340`). Unanchored substring
/// "DMC-FZ10" followed by a word boundary, so `DMC-FZ10` matches but
/// `DMC-FZ100` does NOT (the trailing digit is a word char → no `\b`).
fn model_is_fz10(model: &str) -> bool {
  let needle = "DMC-FZ10";
  let bytes = model.as_bytes();
  let mut from = 0;
  while let Some(rel) = model[from..].find(needle) {
    let end = from + rel + needle.len();
    // `\b` after the match: end-of-string, or the next byte is a non-word
    // char (Perl `\w` = `[A-Za-z0-9_]`).
    let boundary = match bytes.get(end) {
      None => true,
      Some(&c) => !(c.is_ascii_alphanumeric() || c == b'_'),
    };
    if boundary {
      return true;
    }
    from = from + rel + 1;
  }
  false
}

/// `$$self{Model} =~ /^DMC-(GF\d+|G2)$/` (`Panasonic.pm:586`).
fn model_is_gf_g2(model: &str) -> bool {
  if let Some(rest) = model.strip_prefix("DMC-") {
    if rest == "G2" {
      return true;
    }
    if let Some(digits) = rest.strip_prefix("GF") {
      return !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());
    }
  }
  false
}

/// `$$self{Model} =~ /^DMC-(TZ10|ZS7)$/` (`Panasonic.pm:659`).
fn model_is_tz10_zs7(model: &str) -> bool {
  model == "DMC-TZ10" || model == "DMC-ZS7"
}

/// 0x2c ContrastMode branch-1 (PrintHex) `Condition` (`Panasonic.pm:552-556`):
/// `$$self{Model} !~ /^DMC-(FX10|G1|L1|L10|LC80|GF\d+|G2|TZ10|ZS7)$/ and
/// $$self{Model} !~ /^DC-/`.
fn contrast_mode_branch1(model: &str) -> bool {
  !contrast_mode_excluded(model) && !model.starts_with("DC-")
}

/// `$$self{Model} =~ /^DMC-(FX10|G1|L1|L10|LC80|GF\d+|G2|TZ10|ZS7)$/` — the
/// set excluded from branch 1.
fn contrast_mode_excluded(model: &str) -> bool {
  let Some(rest) = model.strip_prefix("DMC-") else {
    return false;
  };
  match rest {
    "FX10" | "G1" | "L1" | "L10" | "LC80" | "G2" | "TZ10" | "ZS7" => true,
    _ => {
      // `GF\d+` — "GF" then one-or-more digits, anchored to end.
      if let Some(digits) = rest.strip_prefix("GF") {
        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
      } else {
        false
      }
    }
  }
}

/// `%shootingMode` (`Panasonic.pm:181-263`) — used by both ShootingMode
/// (0x1f) and SceneMode (0x8001, with an extra `0 => 'Off'`).
fn shooting_mode_label(n: i64) -> Option<&'static str> {
  match n {
    1 => Some("Normal"),
    2 => Some("Portrait"),
    3 => Some("Scenery"),
    4 => Some("Sports"),
    5 => Some("Night Portrait"),
    6 => Some("Program"),
    7 => Some("Aperture Priority"),
    8 => Some("Shutter Priority"),
    9 => Some("Macro"),
    10 => Some("Spot"),
    11 => Some("Manual"),
    12 => Some("Movie Preview"),
    13 => Some("Panning"),
    14 => Some("Simple"),
    15 => Some("Color Effects"),
    16 => Some("Self Portrait"),
    17 => Some("Economy"),
    18 => Some("Fireworks"),
    19 => Some("Party"),
    20 => Some("Snow"),
    21 => Some("Night Scenery"),
    22 => Some("Food"),
    23 => Some("Baby"),
    24 => Some("Soft Skin"),
    25 => Some("Candlelight"),
    26 => Some("Starry Night"),
    27 => Some("High Sensitivity"),
    28 => Some("Panorama Assist"),
    29 => Some("Underwater"),
    30 => Some("Beach"),
    31 => Some("Aerial Photo"),
    32 => Some("Sunset"),
    33 => Some("Pet"),
    34 => Some("Intelligent ISO"),
    35 => Some("Clipboard"),
    36 => Some("High Speed Continuous Shooting"),
    37 => Some("Intelligent Auto"),
    39 => Some("Multi-aspect"),
    41 => Some("Transform"),
    42 => Some("Flash Burst"),
    43 => Some("Pin Hole"),
    44 => Some("Film Grain"),
    45 => Some("My Color"),
    46 => Some("Photo Frame"),
    48 => Some("Movie"),
    51 => Some("HDR"),
    52 => Some("Peripheral Defocus"),
    55 => Some("Handheld Night Shot"),
    57 => Some("3D"),
    59 => Some("Creative Control"),
    60 => Some("Intelligent Auto Plus"),
    62 => Some("Panorama"),
    63 => Some("Glass Through"),
    64 => Some("HDR"),
    66 => Some("Digital Filter"),
    67 => Some("Clear Portrait"),
    68 => Some("Silky Skin"),
    69 => Some("Backlit Softness"),
    70 => Some("Clear in Backlight"),
    71 => Some("Relaxing Tone"),
    72 => Some("Sweet Child's Face"),
    73 => Some("Distinct Scenery"),
    74 => Some("Bright Blue Sky"),
    75 => Some("Romantic Sunset Glow"),
    76 => Some("Vivid Sunset Glow"),
    77 => Some("Glistening Water"),
    78 => Some("Clear Nightscape"),
    79 => Some("Cool Night Sky"),
    80 => Some("Warm Glowing Nightscape"),
    81 => Some("Artistic Nightscape"),
    82 => Some("Glittering Illuminations"),
    83 => Some("Clear Night Portrait"),
    84 => Some("Soft Image of a Flower"),
    85 => Some("Appetizing Food"),
    86 => Some("Cute Dessert"),
    87 => Some("Freeze Animal Motion"),
    88 => Some("Clear Sports Shot"),
    89 => Some("Monochrome"),
    90 => Some("Creative Control"),
    92 => Some("Handheld Night Shot"),
    _ => None,
  }
}

/// `FirmwareVersion` (`Panasonic.pm:294,300`). `ValueConv` joins bytes with
/// spaces when any byte is ≤ 0x2f (binary form), else passes the ASCII
/// through; `PrintConv` is `$val =~ tr/ /./` (spaces → dots).
fn firmware_version(raw: &RawValue, print_conv: bool) -> TagValue {
  use std::format;
  use std::string::ToString;
  let bytes = match raw {
    RawValue::Bytes(b) => b.clone(),
    RawValue::Text { text: s, .. } => s.as_bytes().to_vec(),
    RawValue::U64(v) => v.iter().map(|&n| n as u8).collect(),
    _ => return raw_to_tag_value(raw),
  };
  if bytes.is_empty() {
    return TagValue::Str(SmolStr::new(""));
  }
  let any_lo = bytes.iter().any(|&b| b <= 0x2f);
  let value_str = if any_lo {
    bytes
      .iter()
      .map(|b| b.to_string())
      .collect::<Vec<_>>()
      .join(" ")
  } else {
    match core::str::from_utf8(&bytes) {
      Ok(s) => s.to_string(),
      Err(_) => format!("(binary {} bytes)", bytes.len()),
    }
  };
  let out = if print_conv {
    value_str.replace(' ', ".")
  } else {
    value_str
  };
  TagValue::Str(SmolStr::from(out))
}

/// `LensFirmwareVersion` (`Panasonic.pm:999-1006`). `Format => 'int8u'`,
/// `Count => 4`; `PrintConv => '$val=~tr/ /./'` (the ValueConv is implicit
/// from int8u[4] → the space-joined "a b c d"). With PrintConv the spaces
/// become dots ("a.b.c.d"); the `-n` value is the space-joined string.
fn lens_firmware_version(raw: &RawValue, print_conv: bool) -> TagValue {
  use std::string::ToString;
  // int8u[4] arrives as U64 vec; the default ValueConv space-joins ints.
  let value_str = match raw {
    RawValue::U64(v) => v
      .iter()
      .map(|n| n.to_string())
      .collect::<Vec<_>>()
      .join(" "),
    RawValue::I64(v) => v
      .iter()
      .map(|n| n.to_string())
      .collect::<Vec<_>>()
      .join(" "),
    RawValue::Bytes(b) => b
      .iter()
      .map(|n| n.to_string())
      .collect::<Vec<_>>()
      .join(" "),
    _ => return raw_to_tag_value(raw),
  };
  let out = if print_conv {
    value_str.replace(' ', ".")
  } else {
    value_str
  };
  TagValue::Str(SmolStr::from(out))
}

/// `AFAreaMode` "other models" branch (`Panasonic.pm:352-380`). The int8u
/// pair is rendered as the space-joined string, then looked up in the hash.
fn af_area_mode(raw: &RawValue, print_conv: bool) -> TagValue {
  let key = int_vec_joined(raw);
  let Some(key) = key else {
    return raw_to_tag_value(raw);
  };
  if !print_conv {
    return TagValue::Str(SmolStr::from(key));
  }
  let label = match key.as_str() {
    "0 1" => Some("9-area"),
    "0 16" => Some("3-area (high speed)"),
    "0 23" => Some("23-area"),
    "0 49" => Some("49-area"),
    "0 225" => Some("225-area"),
    "1 0" => Some("Spot Focusing"),
    "1 1" => Some("5-area"),
    "16" => Some("Normal?"),
    "16 0" => Some("1-area"),
    "16 16" => Some("1-area (high speed)"),
    "16 32" => Some("1-area +"),
    "16 225" => Some("225-area 2"),
    "17 0" => Some("Full Area"),
    "32 0" => Some("Tracking"),
    "32 1" => Some("3-area (left)?"),
    "32 2" => Some("3-area (center)?"),
    "32 3" => Some("3-area (right)?"),
    "32 16" => Some("Zone"),
    "32 18" => Some("Zone (horizontal/vertical)"),
    "64 0" => Some("Face Detect"),
    "64 1" => Some("Face Detect (animal detect on)"),
    "64 2" => Some("Face Detect (animal detect off)"),
    "128 0" => Some("Pinpoint focus"),
    "240 0" => Some("Tracking"),
    _ => None,
  };
  match label {
    Some(l) => TagValue::Str(l.into()),
    // ExifTool HASH-miss (no OTHER/BITMASK/PrintHex) → "Unknown ($val)"
    // (`ExifTool.pm:3633`); `$val` is the space-joined pair.
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({key})"))),
  }
}

/// `AFAreaMode` 0x0f FZ10 branch (`Panasonic.pm:338-346`). Only `'0 1'` /
/// `'0 16'` are defined; everything else is the HASH-miss `Unknown ($val)`.
fn af_area_mode_fz10(raw: &RawValue, print_conv: bool) -> TagValue {
  let Some(key) = int_vec_joined(raw) else {
    return raw_to_tag_value(raw);
  };
  if !print_conv {
    return TagValue::Str(SmolStr::from(key));
  }
  let label = match key.as_str() {
    "0 1" => Some("Spot Mode On"),
    "0 16" => Some("Spot Mode Off"),
    _ => None,
  };
  match label {
    Some(l) => TagValue::Str(l.into()),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({key})"))),
  }
}

/// `Transform`/`Transform` (`Panasonic.pm:976-982`, `:1593-1599`). int16s
/// pair, rendered as the space-joined string then looked up.
fn transform(raw: &RawValue, print_conv: bool) -> TagValue {
  let Some(key) = int_vec_joined(raw) else {
    return raw_to_tag_value(raw);
  };
  if !print_conv {
    return TagValue::Str(SmolStr::from(key));
  }
  let label = match key.as_str() {
    "-3 2" => Some("Slim High"),
    "-1 1" => Some("Slim Low"),
    "0 0" => Some("Off"),
    "1 1" => Some("Stretch Low"),
    "3 2" => Some("Stretch High"),
    _ => None,
  };
  match label {
    Some(l) => TagValue::Str(l.into()),
    // ExifTool HASH-miss → "Unknown ($val)" (`ExifTool.pm:3633`).
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({key})"))),
  }
}

/// `VideoBurstMode` (`Panasonic.pm:1358-1374`). int32u, `PrintHex => 1`
/// (`Panasonic.pm:1361`), so an unmatched value renders the PrintHex HASH-miss
/// fallback `sprintf('Unknown (0x%x)',$val)` (`ExifTool.pm:3628-3631`).
fn video_burst_mode(raw: &RawValue, print_conv: bool) -> TagValue {
  let Some(n) = first_i64(raw) else {
    return raw_to_tag_value(raw);
  };
  if !print_conv {
    return TagValue::I64(n);
  }
  let label = match n {
    0x01 => Some("Off"),
    0x04 => Some("Post Focus"),
    0x18 => Some("4K Burst"),
    0x28 => Some("4K Burst (Start/Stop)"),
    0x48 => Some("4K Pre-burst"),
    0x108 => Some("Loop Recording"),
    0x810 => Some("6K Burst"),
    0x820 => Some("6K Burst (Start/Stop)"),
    0x408 => Some("Focus Stacking"),
    0x1001 => Some("High Resolution Mode"),
    _ => None,
  };
  match label {
    Some(l) => TagValue::Str(l.into()),
    // PrintHex HASH-miss ⇒ `Unknown (0x%x)` (`ExifTool.pm:3628-3631`).
    None => TagValue::Str(SmolStr::from(std::format!("Unknown (0x{n:x})"))),
  }
}

/// `ManometerPressure` (`Panasonic.pm:1130-1133`). `RawConv` drops 65535,
/// `ValueConv => '$val/10'`, `PrintConv => 'sprintf("%.1f kPa",$val)'`.
fn manometer_pressure(raw: &RawValue, print_conv: bool) -> TagValue {
  let Some(n) = first_i64(raw) else {
    return raw_to_tag_value(raw);
  };
  // RawConv `$val==65535 ? undef` (`Panasonic.pm:1130`) ⇒ the tag is dropped.
  // The parse path (`super::parse_in_tiff`) suppresses 65535 BEFORE calling
  // this conv (via `PanasonicPrintConv::rawconv_drops`), so a 65535 never
  // reaches here in normal output. This guard is the fallback for a direct
  // `apply` call (which returns a `TagValue` and cannot drop): emit the raw
  // sentinel unchanged rather than the bogus `"6553.5 kPa"`.
  if n == 65535 {
    return TagValue::I64(n);
  }
  let v = n as f64 / 10.0;
  if print_conv {
    TagValue::Str(SmolStr::from(std::format!("{v:.1} kPa")))
  } else {
    TagValue::F64(v)
  }
}

/// `Contrast`/`Saturation`/`Sharpness`/`Clarity`/`NoiseReductionStrength`
/// — `%Image::ExifTool::Exif::printParameter` (`Exif.pm:327-332`):
/// `PrintConv => { 0 => 'Normal', OTHER => \&PrintParameter }`. The OTHER
/// sub (`Exif.pm:5628-5640`): if `$val > 0` then (`$val > 0xfff0` ?
/// `$val - 0x10000` : `"+$val"`); else return `$val`. These tags are
/// `Format => 'int16s'`, so the value is already signed (`> 0xfff0` cannot
/// occur); 0 → "Normal", positive → "+N", negative → "N".
fn print_parameter(raw: &RawValue, print_conv: bool) -> TagValue {
  let Some(n) = first_i64(raw) else {
    return raw_to_tag_value(raw);
  };
  if !print_conv {
    return TagValue::I64(n);
  }
  if n == 0 {
    return TagValue::Str("Normal".into());
  }
  let s = if n > 0 {
    std::format!("+{n}")
  } else {
    std::format!("{n}")
  };
  TagValue::Str(s.into())
}

/// `BabyAge`/`BabyAge2` (`Panasonic.pm:731`, `:1584`). string;
/// `"9999:99:99 00:00:00" => "(not set)"`, else passthrough.
fn baby_age(raw: &RawValue, print_conv: bool) -> TagValue {
  let s = match raw {
    RawValue::Text { text: s, .. } => s.as_str().to_string(),
    RawValue::Bytes(b) => {
      let end = b.iter().position(|&x| x == 0).unwrap_or(b.len());
      // `end <= b.len()`, so `.get(..end)` is `Some` — byte-identical.
      b.get(..end)
        .and_then(|s| core::str::from_utf8(s).ok())
        .unwrap_or("")
        .to_string()
    }
    _ => return raw_to_tag_value(raw),
  };
  if print_conv && s == "9999:99:99 00:00:00" {
    TagValue::Str("(not set)".into())
  } else {
    TagValue::Str(SmolStr::from(s))
  }
}

/// `TimeStamp` 0xaf (`Panasonic.pm:1335-1342`). `Writable => 'string'`,
/// `PrintConv => '$self->ConvertDateTime($val)'`. The string reader already
/// NUL-trims; `-n` (no PrintConv) emits it verbatim, `-j` routes it through
/// the shared `ConvertDateTime` port (identity under default options).
fn time_stamp(raw: &RawValue, print_conv: bool) -> TagValue {
  let s = match raw {
    RawValue::Text { text: s, .. } => s.as_str().to_string(),
    RawValue::Bytes(b) => {
      let end = b.iter().position(|&x| x == 0).unwrap_or(b.len());
      // `end <= b.len()`, so `.get(..end)` is `Some` — byte-identical.
      b.get(..end)
        .and_then(|s| core::str::from_utf8(s).ok())
        .unwrap_or("")
        .to_string()
    }
    _ => return raw_to_tag_value(raw),
  };
  if print_conv {
    TagValue::Str(SmolStr::from(crate::datetime::convert_datetime(&s)))
  } else {
    TagValue::Str(SmolStr::from(s))
  }
}

/// `WhiteBalanceBias`/`FlashBias` — int16s/3, then `Exif::PrintFraction`.
fn fraction_third(raw: &RawValue, print_conv: bool) -> TagValue {
  let Some(n) = first_i64(raw) else {
    return raw_to_tag_value(raw);
  };
  let v = n as f64 / 3.0;
  if !print_conv {
    return TagValue::F64(v);
  }
  // Exif::PrintFraction: 0 if |val|<1.5e-6, else +N.NNN / -N.NNN trimmed.
  if v.abs() < 1e-6 {
    TagValue::Str("0".into())
  } else if (v.fract()).abs() < 1e-6 {
    let s = if v > 0.0 {
      std::format!("+{}", v as i64)
    } else {
      std::format!("{}", v as i64)
    };
    TagValue::Str(s.into())
  } else {
    let s = if v > 0.0 {
      std::format!("+{v}")
    } else {
      std::format!("{v}")
    };
    TagValue::Str(s.into())
  }
}

/// `RollAngle`/`PitchAngle` (`Panasonic.pm:1205`, `:1213`). int16s;
/// `ValueConv => '$val/10'` (RollAngle) or `'-$val/10'` (PitchAngle). NO
/// PrintConv — the value IS the output.
fn scaled_tenths(raw: &RawValue, print_conv: bool, negate: bool) -> TagValue {
  let Some(n) = first_i64(raw) else {
    return raw_to_tag_value(raw);
  };
  let mut v = n as f64 / 10.0;
  if negate {
    v = -v;
  }
  // No PrintConv: ExifTool renders the number directly in both modes.
  let _ = print_conv;
  TagValue::F64(v)
}

/// `InternalSerialNumber` (`Panasonic.pm:457-461`). PrintConv decodes the
/// `^([A-Z][0-9A-Z]{2})(\d{2})(\d{2})(\d{2})(\d{4})` shape into
/// `"($1) $yr:$3:$4 no. $5"`.
fn internal_serial_number(raw: &RawValue, print_conv: bool) -> TagValue {
  let bytes = match raw {
    RawValue::Bytes(b) => b.clone(),
    RawValue::Text { text: s, .. } => s.as_bytes().to_vec(),
    _ => return raw_to_tag_value(raw),
  };
  let mut end = bytes.len();
  // `end > 0` ⇒ `end - 1 < len`, so `.get(end-1)` is `Some`; `.get(..end)` is
  // `Some` for `end <= len` — both byte-identical to the prior indexing.
  while end > 0 && bytes.get(end - 1).is_some_and(|&b| b == 0 || b == b' ') {
    end -= 1;
  }
  let raw_str = bytes
    .get(..end)
    .and_then(|s| core::str::from_utf8(s).ok())
    .map(|s| s.to_string())
    .unwrap_or_default();
  if !print_conv {
    return TagValue::Str(SmolStr::from(raw_str));
  }
  match parse_internal_sn(&raw_str) {
    Some(decoded) => TagValue::Str(SmolStr::from(decoded)),
    None => TagValue::Str(SmolStr::from(raw_str)),
  }
}

/// Parse `S000407190102` → `"(S00) 2004:07:19 no. 0102"`
/// (`Panasonic.pm:458`).
fn parse_internal_sn(s: &str) -> Option<String> {
  let bytes = s.as_bytes();
  // The `len < 13` guard makes every `.get(..)` below `Some`; the checked
  // forms are byte-identical to `bytes[0]` / `bytes[1..3]` / `bytes[3..13]`.
  if bytes.len() < 13 {
    return None;
  }
  if !bytes.first().is_some_and(u8::is_ascii_uppercase) {
    return None;
  }
  for &b in bytes.get(1..3).unwrap_or_default() {
    if !(b.is_ascii_uppercase() || b.is_ascii_digit()) {
      return None;
    }
  }
  for &b in bytes.get(3..13).unwrap_or_default() {
    if !b.is_ascii_digit() {
      return None;
    }
  }
  let g1 = &s[..3];
  let yy: u32 = s[3..5].parse().ok()?;
  let yr = if yy < 70 { 2000 + yy } else { 1900 + yy };
  let mm = &s[5..7];
  let dd = &s[7..9];
  let counter = &s[9..13];
  Some(std::format!("({g1}) {yr}:{mm}:{dd} no. {counter}"))
}

/// `PanasonicExifVersion`/`MakerNoteVersion` — undef, ASCII passthrough.
fn panasonic_exif_version(raw: &RawValue) -> TagValue {
  match raw {
    RawValue::Bytes(b) => {
      if let Ok(s) = core::str::from_utf8(b) {
        TagValue::Str(s.into())
      } else {
        TagValue::Bytes(b.clone())
      }
    }
    RawValue::Text { text: s, .. } => TagValue::Str(s.as_str().into()),
    _ => raw_to_tag_value(raw),
  }
}

/// `VideoFrameRate` (`Panasonic.pm:472-475`). `0 => 'n/a'`, OTHER passes
/// through.
fn video_frame_rate(raw: &RawValue, print_conv: bool) -> TagValue {
  let Some(n) = first_i64(raw) else {
    return raw_to_tag_value(raw);
  };
  if print_conv && n == 0 {
    TagValue::Str("n/a".into())
  } else {
    TagValue::I64(n)
  }
}

/// `TimeSincePowerOn` (`Panasonic.pm:498-518`). ValueConv `$val/100` then
/// the printf-loop into `[DD days ]HH:MM:SS.ss`.
fn time_since_power_on(raw: &RawValue, print_conv: bool) -> TagValue {
  let Some(n) = first_i64(raw) else {
    return raw_to_tag_value(raw);
  };
  let val = n as f64 / 100.0;
  if !print_conv {
    return TagValue::F64(val);
  }
  let mut rem = val;
  let mut prefix = String::new();
  if rem >= 24.0 * 3600.0 {
    let d = (rem / (24.0 * 3600.0)).floor() as i64;
    prefix = std::format!("{d} days ");
    rem -= d as f64 * 24.0 * 3600.0;
  }
  let h = (rem / 3600.0).floor() as i64;
  rem -= h as f64 * 3600.0;
  let m = (rem / 60.0).floor() as i64;
  rem -= m as f64 * 60.0;
  let mut ss_str = std::format!("{rem:05.2}");
  let ss_value: f64 = ss_str.parse().unwrap_or(rem);
  let (final_h, final_m, final_ss) = if ss_value >= 60.0 {
    ss_str = "00.00".into();
    let mut new_m = m + 1;
    let mut new_h = h;
    if new_m >= 60 {
      new_m -= 60;
      new_h += 1;
    }
    (new_h, new_m, ss_str)
  } else {
    (h, m, ss_str)
  };
  TagValue::Str(SmolStr::from(std::format!(
    "{prefix}{final_h:02}:{final_m:02}:{final_ss}"
  )))
}

/// `ContrastMode` (`Panasonic.pm:564-583`) — `PrintHex` first branch.
fn contrast_mode(raw: &RawValue, print_conv: bool) -> TagValue {
  let Some(n) = first_i64(raw) else {
    return raw_to_tag_value(raw);
  };
  if !print_conv {
    return TagValue::I64(n);
  }
  let label = match n {
    0x00 => Some("Normal"),
    0x01 => Some("Low"),
    0x02 => Some("High"),
    0x05 => Some("Normal 2"),
    0x06 => Some("Medium Low"),
    0x07 => Some("Medium High"),
    0x0d => Some("High Dynamic"),
    0x18 => Some("Dynamic Range (film-like)"),
    0x2e => Some("Match Filter Effects Toy"),
    0x37 => Some("Match Photo Style L. Monochrome"),
    0x100 => Some("Low"),
    0x110 => Some("Normal"),
    0x120 => Some("High"),
    _ => None,
  };
  match label {
    Some(l) => TagValue::Str(l.into()),
    // HASH-miss on a `Flags => 'PrintHex'` tag (`Panasonic.pm:557`) ⇒
    // `sprintf('Unknown (0x%x)',$val)` (`ExifTool.pm:3628-3631`), NOT a bare
    // `0xNN` and NOT the decimal `Unknown ($val)`.
    None => TagValue::Str(SmolStr::from(std::format!("Unknown (0x{n:x})"))),
  }
}

/// `ContrastMode` 0x2c GF/G2 branch (`Panasonic.pm:585-657`) — the int16u
/// hash used by the G2, GF1, GF2, GF3, GF5 and GF6. Plain hash (NOT
/// PrintHex), so an unmatched value renders the decimal `Unknown (N)`.
fn contrast_mode_gf_g2(raw: &RawValue, print_conv: bool) -> TagValue {
  let Some(n) = first_i64(raw) else {
    return raw_to_tag_value(raw);
  };
  if !print_conv {
    return TagValue::I64(n);
  }
  let label = match n {
    0 => Some("-2"),
    1 => Some("-1"),
    2 => Some("Normal"),
    3 => Some("+1"),
    4 => Some("+2"),
    5 => Some("Normal 2"),
    7 => Some("Nature (Color Film)"),
    9 => Some("Expressive"),
    12 => Some("Smooth (Color Film) or Pure (My Color)"),
    17 => Some("Dynamic (B&W Film)"),
    22 => Some("Smooth (B&W Film)"),
    25 => Some("High Dynamic"),
    26 => Some("Retro"),
    27 => Some("Dynamic (Color Film)"),
    28 => Some("Low Key"),
    29 => Some("Toy Effect"),
    32 => Some("Vibrant (Color Film) or Expressive (My Color)"),
    33 => Some("Elegant (My Color)"),
    37 => Some("Nostalgic (Color Film)"),
    41 => Some("Dynamic Art (My Color)"),
    42 => Some("Retro (My Color)"),
    45 => Some("Cinema"),
    47 => Some("Dynamic Mono"),
    50 => Some("Impressive Art"),
    51 => Some("Cross Process"),
    100 => Some("High Dynamic 2"),
    101 => Some("Retro 2"),
    102 => Some("High Key 2"),
    103 => Some("Low Key 2"),
    104 => Some("Toy Effect 2"),
    107 => Some("Expressive 2"),
    112 => Some("Sepia"),
    117 => Some("Miniature"),
    122 => Some("Dynamic Monochrome"),
    127 => Some("Old Days"),
    132 => Some("Dynamic Monochrome 2"),
    135 => Some("Impressive Art 2"),
    136 => Some("Cross Process 2"),
    137 => Some("Toy Pop"),
    138 => Some("Fantasy"),
    256 => Some("Normal 3"),
    272 => Some("Standard"),
    288 => Some("High"),
    _ => None,
  };
  match label {
    Some(l) => TagValue::Str(l.into()),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({n})"))),
  }
}

/// `ContrastMode` 0x2c TZ10/ZS7 branch (`Panasonic.pm:658-668`) — the int16u
/// hash used by the TZ10 and ZS7. Plain hash → decimal `Unknown (N)` miss.
fn contrast_mode_tz10_zs7(raw: &RawValue, print_conv: bool) -> TagValue {
  let Some(n) = first_i64(raw) else {
    return raw_to_tag_value(raw);
  };
  if !print_conv {
    return TagValue::I64(n);
  }
  let label = match n {
    0 => Some("Normal"),
    1 => Some("-2"),
    2 => Some("+2"),
    5 => Some("-1"),
    6 => Some("+1"),
    _ => None,
  };
  match label {
    Some(l) => TagValue::Str(l.into()),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({n})"))),
  }
}

/// Generic int → label PrintConv. Unmatched values render as
/// `Unknown (N)` — ExifTool's `PrintConv` hash default for a non-PrintHex
/// table.
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

/// Plain (non-PrintHex) hash PrintConv keyed on the space-joined int vector
/// `$val` (e.g. an int32u[2] pair `"0 1"`). `-n` (print_conv off) emits the
/// raw joined string (the default ValueConv); a HASH-miss renders the decimal
/// `Unknown ($val)` (`ExifTool.pm:3633`). Used by the `Format => 'int32u'`
/// reinterpret tags 0xa1 FilterEffect / 0xbf PostFocusMerging, whose
/// [`super::body`] walker already produces the int32u pair.
fn int_pair_label<F: Fn(&str) -> Option<&'static str>>(
  raw: &RawValue,
  print_conv: bool,
  f: F,
) -> TagValue {
  let Some(key) = int_vec_joined(raw) else {
    return raw_to_tag_value(raw);
  };
  if !print_conv {
    return TagValue::Str(SmolStr::from(key));
  }
  match f(&key) {
    Some(l) => TagValue::Str(l.into()),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({key})"))),
  }
}

/// Join an int vector (`U64`/`I64`) into the space-separated string ExifTool
/// uses as a multi-value PrintConv key (e.g. `"0 1"`).
fn int_vec_joined(raw: &RawValue) -> Option<String> {
  use std::string::ToString;
  match raw {
    RawValue::U64(v) if !v.is_empty() => Some(
      v.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(" "),
    ),
    RawValue::I64(v) if !v.is_empty() => Some(
      v.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(" "),
    ),
    _ => None,
  }
}

/// First scalar i64.
fn first_i64(raw: &RawValue) -> Option<i64> {
  match raw {
    RawValue::I64(v) => v.first().copied(),
    RawValue::U64(v) => v.first().and_then(|&n| i64::try_from(n).ok()),
    _ => None,
  }
}

/// First element as `u64` — used by the 0xc4 `$$valPt ne "\xff\xff"` gate
/// (the int16u value 65535) in
/// [`single_hash_condition_holds`](PanasonicPrintConv::single_hash_condition_holds).
fn first_u64(raw: &RawValue) -> Option<u64> {
  match raw {
    RawValue::U64(v) => v.first().copied(),
    RawValue::I64(v) => v.first().and_then(|&n| u64::try_from(n).ok()),
    _ => None,
  }
}

/// `LensType`/`LensSerialNumber`/`AccessoryType`/`AccessorySerialNumber`
/// (`Panasonic.pm:947,953,959,965`) — `ValueConv => '$val=~s/ +$//; $val'`
/// strips a run of TRAILING ASCII spaces (only `' '`, not other whitespace),
/// applied in both `-n` and `-j`. The string reader already NUL-trims, so we
/// trim trailing spaces here to match. A non-string raw falls back to the
/// default rendering.
fn trim_trailing_spaces(raw: &RawValue) -> TagValue {
  let s = match raw {
    RawValue::Text { text: s, .. } => s.as_str(),
    RawValue::Bytes(b) => match core::str::from_utf8(b) {
      Ok(t) => t.trim_end_matches('\0'),
      Err(_) => return raw_to_tag_value(raw),
    },
    _ => return raw_to_tag_value(raw),
  };
  // `s/ +$//` — trailing ASCII spaces only (NOT tabs/newlines).
  TagValue::Str(SmolStr::from(s.trim_end_matches(' ')))
}

/// `LensTypeModel` 0xc5 / 0xe4 (`Panasonic.pm:1421-1427`, `:1465-1471`).
///
/// `RawConv => q{ return undef unless $val; require …Olympus; return $val; }`
/// — a zero value drops the tag (returns `None`); the `require Olympus` is a
/// module-load side-effect (to register the Composite `LensID`, which is
/// deferred) and does not alter `$val`. `ValueConv => '$_=sprintf("%.4x",
/// $val); s/(..)(..)/$2 $1/; $_'` formats the int16u as a 4-digit lowercase
/// hex string then swaps the two byte-pairs with a space (low byte first):
/// `0x1234 → "1234" → "34 12"`. There is no PrintConv, so `-n` and `-j` emit
/// the same string. (Hex has only digits/`a-f`, so `tr`-style case is moot.)
fn lens_type_model(raw: &RawValue, print_conv: bool) -> Option<TagValue> {
  let _ = print_conv; // no PrintConv — identical in -n and -j.
  let n = first_i64(raw)?;
  // `return undef unless $val;` — zero (or unreadable) ⇒ tag dropped.
  if n == 0 {
    return None;
  }
  // `sprintf("%.4x",$val)` — minimum 4 hex digits (int16u ⇒ exactly 4); a
  // wider value (can't occur for int16u) would keep all its digits, and the
  // single `s/(..)(..)/$2 $1/` (no /g) swaps only the FIRST two byte-pairs,
  // matching Perl.
  let hex = std::format!("{:04x}", n as u64);
  // `{:04x}` always yields ≥ 4 bytes, so `first_chunk::<4>()` is `Some` and
  // the binding is byte-identical to `hex.as_bytes()[0..3]`; the `else` is
  // unreachable (kept only to stay panic-free).
  let Some(&[b0, b1, b2, b3]) = hex.as_bytes().first_chunk::<4>() else {
    return Some(TagValue::Str(SmolStr::from(hex)));
  };
  // Swap the first two 2-char groups: "abcd…" → "cd ab…".
  let swapped = std::format!(
    "{}{} {}{}{}",
    b2 as char,
    b3 as char,
    b0 as char,
    b1 as char,
    &hex[4..],
  );
  Some(TagValue::Str(SmolStr::from(swapped)))
}

/// The default ValueConv `$val` text for a rational tag: each rational
/// rendered via ExifTool's `RoundFloat(n/d, sig)` decimal
/// ([`crate::value::Rational::exiftool_val_str`]) and space-joined — exactly
/// the scalar string ExifTool's `ProcessExif` stores for a rational value
/// (`ExifTool.pm` `GetRational64u/64s` 6107-6119), and the string a PrintConv
/// sees in `$val`. `128/256 → "0.5"`; the pair `[128/256, 128/256] → "0.5
/// 0.5"`. Returns `None` for a non-rational raw (caller falls back).
fn rational_val_str(raw: &RawValue) -> Option<String> {
  match raw {
    RawValue::Rational(rs) if !rs.is_empty() => Some(
      rs.iter()
        .map(|r| r.exiftool_val_str())
        .collect::<Vec<_>>()
        .join(" "),
    ),
    _ => None,
  }
}

/// `AFPointPosition` 0x4d (`Panasonic.pm:916-935`). `Writable =>
/// 'rational64u'`, `Count => 2`. The default ValueConv renders the rational
/// pair to a space-joined decimal `$val` (the `-n` output); the `PrintConv`
/// then maps the sentinels and `%.2g`-formats the pair:
///
/// ```text
/// return 'none' if $val eq '16777216 16777216';
/// return 'n/a'  if $val =~ /^4194303\.9/;
/// my @a = split ' ', $val;
/// sprintf("%.2g %.2g", @a);
/// ```
fn af_point_position(raw: &RawValue, print_conv: bool) -> TagValue {
  let Some(val) = rational_val_str(raw) else {
    return raw_to_tag_value(raw);
  };
  if !print_conv {
    // No PrintConv ⇒ the ValueConv decimal pair (`-n`).
    return TagValue::Str(SmolStr::from(val));
  }
  // `return 'none' if $val eq '16777216 16777216';` (the 16777216/1 sentinel).
  if val == "16777216 16777216" {
    return TagValue::Str("none".into());
  }
  // `return 'n/a' if $val =~ /^4194303\.9/;` (the 4294967295/1024 sentinel
  // → "4194303.999"). Matches any `$val` that STARTS with `4194303.9`.
  if val.starts_with("4194303.9") {
    return TagValue::Str("n/a".into());
  }
  // `sprintf("%.2g %.2g", split ' ', $val)` — re-render each whitespace-split
  // token at 2 sig figs. `split ' '` (single-space) collapses runs of
  // whitespace and ignores leading whitespace, matching Perl's awk-mode split.
  let formatted = val
    .split_whitespace()
    .map(|tok| format_g(tok.parse::<f64>().unwrap_or(0.0), 2))
    .collect::<Vec<_>>()
    .join(" ");
  TagValue::Str(SmolStr::from(formatted))
}

/// `AFAreaSize` 0xde (`Panasonic.pm:1453-1460`). `Writable => 'rational64u'`,
/// `Count => 2`. Same decimal-pair ValueConv `$val` (the `-n` output);
/// `PrintConv => '$val =~ /^4194303\.9/ ? "n/a" : $val'` — `"n/a"` for the
/// 4294967295/1024 manual-focus sentinel, else the decimal pair verbatim.
fn af_area_size(raw: &RawValue, print_conv: bool) -> TagValue {
  let Some(val) = rational_val_str(raw) else {
    return raw_to_tag_value(raw);
  };
  if print_conv && val.starts_with("4194303.9") {
    return TagValue::Str("n/a".into());
  }
  TagValue::Str(SmolStr::from(val))
}

/// Render a raw value as a default [`TagValue`] (no PrintConv) — mirrors
/// the Apple/Canon helpers.
pub(crate) fn raw_to_tag_value(raw: &RawValue) -> TagValue {
  use std::string::ToString;
  // Single-element arms use a slice pattern (`[x]`) instead of `v[0]` behind
  // an `if v.len() == 1` guard — byte-identical and free of raw indexing.
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
    // A multi-element rational with NO conv: ExifTool's default ValueConv
    // renders EACH rational to its `RoundFloat(n/d, sig)` DECIMAL
    // (`ExifTool.pm:6107-6119`) and space-joins them — e.g. the pair
    // `[128/256, 128/256] → "0.5 0.5"`, NOT `"128/256 128/256"`. Joining the
    // raw `num/den` (the prior behaviour) diverged from bundled for any
    // rational[N] tag without a conv. Match ExifTool by joining the decimal
    // string of each element.
    RawValue::Rational(rs) => TagValue::Str(
      rs.iter()
        .map(|r| r.exiftool_val_str())
        .collect::<Vec<_>>()
        .join(" ")
        .into(),
    ),
    RawValue::Text { text: s, .. } => TagValue::Str(s.as_str().into()),
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
  fn image_quality_known_label() {
    let raw = RawValue::U64(vec![2]);
    assert_eq!(
      PanasonicPrintConv::ImageQuality.apply(&raw, true),
      TagValue::Str("High".into())
    );
  }

  #[test]
  fn image_quality_unknown_label() {
    let raw = RawValue::U64(vec![99]);
    assert_eq!(
      PanasonicPrintConv::ImageQuality.apply(&raw, true),
      TagValue::Str("Unknown (99)".into())
    );
  }

  #[test]
  fn firmware_version_binary_to_dotted() {
    let raw = RawValue::Bytes(std::vec![0, 1, 0, 8]);
    assert_eq!(
      PanasonicPrintConv::FirmwareVersion.apply(&raw, true),
      TagValue::Str("0.1.0.8".into())
    );
  }

  #[test]
  fn af_area_mode_9_area() {
    // int8u[2] = [0,1] → "0 1" → "9-area".
    let raw = RawValue::U64(std::vec![0, 1]);
    assert_eq!(
      PanasonicPrintConv::AfAreaMode.apply(&raw, true),
      TagValue::Str("9-area".into())
    );
    // -n: the raw joined string.
    assert_eq!(
      PanasonicPrintConv::AfAreaMode.apply(&raw, false),
      TagValue::Str("0 1".into())
    );
  }

  /// 0x51-0x54 string `ValueConv => '$val=~s/ +$//; $val'` — strip trailing
  /// ASCII spaces in BOTH modes (`Panasonic.pm:947`). Leading/interior
  /// spaces are preserved; only trailing spaces go.
  #[test]
  fn trim_trailing_spaces_strips_only_trailing() {
    let raw = RawValue::Text {
      text: "LUMIX G 14/F2.5   ".into(),
      raw: b"LUMIX G 14/F2.5   "[..].into(),
    };
    assert_eq!(
      PanasonicPrintConv::TrimTrailingSpaces.apply(&raw, true),
      TagValue::Str("LUMIX G 14/F2.5".into())
    );
    // Same in -n (it's a ValueConv, not a PrintConv).
    assert_eq!(
      PanasonicPrintConv::TrimTrailingSpaces.apply(&raw, false),
      TagValue::Str("LUMIX G 14/F2.5".into())
    );
    // Interior spaces kept; no trailing → unchanged.
    let raw2 = RawValue::Text {
      text: "A B C".into(),
      raw: b"A B C"[..].into(),
    };
    assert_eq!(
      PanasonicPrintConv::TrimTrailingSpaces.apply(&raw2, true),
      TagValue::Str("A B C".into())
    );
    // NUL-padded bytes: reader-style NUL trim then space trim.
    let raw3 = RawValue::Bytes(b"ABC \0\0".to_vec());
    assert_eq!(
      PanasonicPrintConv::TrimTrailingSpaces.apply(&raw3, true),
      TagValue::Str("ABC".into())
    );
  }

  /// 0xc5 / 0xe4 LensTypeModel byte-swap ValueConv (`Panasonic.pm:1426,1470`):
  /// `$_=sprintf("%.4x",$val); s/(..)(..)/$2 $1/` ⇒ `0x1234 → "34 12"`. No
  /// PrintConv ⇒ identical in `-n` and `-j`. Oracle values cross-checked
  /// against the bundled Perl expression.
  #[test]
  fn lens_type_model_byte_swap() {
    let raw = RawValue::U64(vec![0x1234]);
    assert_eq!(
      PanasonicPrintConv::LensTypeModel.apply(&raw, true),
      TagValue::Str("34 12".into())
    );
    // Same in -n (it's a ValueConv, not a PrintConv).
    assert_eq!(
      PanasonicPrintConv::LensTypeModel.apply(&raw, false),
      TagValue::Str("34 12".into())
    );
    // `0x0102 → "02 01"`; a low byte-pair keeps its leading zero (`%.4x`).
    assert_eq!(
      PanasonicPrintConv::LensTypeModel.apply(&RawValue::U64(vec![0x0102]), true),
      TagValue::Str("02 01".into())
    );
    // `0x0001 → "01 00"` (leading zeros preserved by the 4-digit format).
    assert_eq!(
      PanasonicPrintConv::LensTypeModel.apply(&RawValue::U64(vec![1]), true),
      TagValue::Str("01 00".into())
    );
    // `0xabcd → "cd ab"`.
    assert_eq!(
      PanasonicPrintConv::LensTypeModel.apply(&RawValue::U64(vec![0xabcd]), true),
      TagValue::Str("cd ab".into())
    );
  }

  /// 0xc5 / 0xe4 RawConv `return undef unless $val;` (`Panasonic.pm:1422,1466`)
  /// — a zero value DROPS the tag. `apply_lens_type_model` (the path
  /// `parse_in_tiff` uses) returns `None` for zero and `Some` otherwise.
  #[test]
  fn lens_type_model_zero_is_undef_dropped() {
    assert_eq!(
      PanasonicPrintConv::apply_lens_type_model(&RawValue::U64(vec![0]), true),
      None,
      "zero ⇒ RawConv undef-drop ⇒ tag suppressed"
    );
    assert_eq!(
      PanasonicPrintConv::apply_lens_type_model(&RawValue::U64(vec![0x1234]), true),
      Some(TagValue::Str("34 12".into())),
      "non-zero ⇒ byte-swap value"
    );
  }

  /// 0x4d AFPointPosition (`Panasonic.pm:916-935`). rational64u[2]. The real
  /// `Panasonic.rw2` sample stores `128/256 128/256` → decimal `"0.5 0.5"`,
  /// which ExifTool emits in BOTH `-n` AND `-j` (`%.2g` of 0.5 is `0.5`).
  /// Oracle values cross-checked by driving the bundled PrintConv.
  #[test]
  fn af_point_position_decimal_and_sentinels() {
    use crate::value::Rational;
    // Real sample: 128/256 128/256 → "0.5 0.5" in both modes.
    let real = RawValue::Rational(vec![
      Rational::rational64(128, 256),
      Rational::rational64(128, 256),
    ]);
    assert_eq!(
      PanasonicPrintConv::AfPointPosition.apply(&real, true),
      TagValue::Str("0.5 0.5".into()),
      "-j: %.2g of the decimal pair"
    );
    assert_eq!(
      PanasonicPrintConv::AfPointPosition.apply(&real, false),
      TagValue::Str("0.5 0.5".into()),
      "-n: the ValueConv decimal pair"
    );
    // `none` sentinel: 16777216/1 16777216/1 → decimal "16777216 16777216".
    let none = RawValue::Rational(vec![
      Rational::rational64(16_777_216, 1),
      Rational::rational64(16_777_216, 1),
    ]);
    assert_eq!(
      PanasonicPrintConv::AfPointPosition.apply(&none, true),
      TagValue::Str("none".into())
    );
    // -n keeps the raw decimal pair (no PrintConv).
    assert_eq!(
      PanasonicPrintConv::AfPointPosition.apply(&none, false),
      TagValue::Str("16777216 16777216".into())
    );
    // `n/a` sentinel: 4294967295/1024 → decimal "4194303.999" (starts 4194303.9).
    let na = RawValue::Rational(vec![
      Rational::rational64(4_294_967_295, 1024),
      Rational::rational64(4_294_967_295, 1024),
    ]);
    assert_eq!(
      PanasonicPrintConv::AfPointPosition.apply(&na, true),
      TagValue::Str("n/a".into())
    );
    // A non-round pair: %.2g rounds (e.g. 0.123456 → 0.12).
    let frac = RawValue::Rational(vec![
      Rational::rational64(123_456, 1_000_000),
      Rational::rational64(654_321, 1_000_000),
    ]);
    assert_eq!(
      PanasonicPrintConv::AfPointPosition.apply(&frac, true),
      TagValue::Str("0.12 0.65".into())
    );
    assert_eq!(
      PanasonicPrintConv::AfPointPosition.apply(&frac, false),
      TagValue::Str("0.123456 0.654321".into())
    );
  }

  /// 0xde AFAreaSize (`Panasonic.pm:1453-1460`). rational64u[2]; decimal-pair
  /// ValueConv (`-n`), PrintConv `/^4194303\.9/ ? "n/a" : $val` (so `-j`
  /// differs from `-n` ONLY for the manual-focus sentinel).
  #[test]
  fn af_area_size_decimal_and_na() {
    use crate::value::Rational;
    // A normal relative pair → decimal verbatim in both modes.
    let rel = RawValue::Rational(vec![Rational::rational64(1, 4), Rational::rational64(3, 4)]);
    assert_eq!(
      PanasonicPrintConv::AfAreaSize.apply(&rel, true),
      TagValue::Str("0.25 0.75".into())
    );
    assert_eq!(
      PanasonicPrintConv::AfAreaSize.apply(&rel, false),
      TagValue::Str("0.25 0.75".into())
    );
    // `n/a` sentinel: 4294967295/1024 → "4194303.999" (manual focus).
    let na = RawValue::Rational(vec![
      Rational::rational64(4_294_967_295, 1024),
      Rational::rational64(4_294_967_295, 1024),
    ]);
    assert_eq!(
      PanasonicPrintConv::AfAreaSize.apply(&na, true),
      TagValue::Str("n/a".into())
    );
    // -n keeps the raw decimal pair even for the sentinel (no PrintConv).
    assert_eq!(
      PanasonicPrintConv::AfAreaSize.apply(&na, false),
      TagValue::Str("4194303.999 4194303.999".into())
    );
  }

  /// 0xa1 FilterEffect (`Panasonic.pm:1274-1304`). `Format => 'int32u'` makes
  /// the value an int32u[2] pair; the plain (non-PrintHex) hash keys on the
  /// space-joined pair, HASH-miss ⇒ decimal `Unknown (a b)`. `-n` emits the
  /// raw int pair. Oracle values cross-checked against the bundled hash.
  #[test]
  fn filter_effect_int32u_pair_labels() {
    // int32u[2] arrives as a U64 vec (the body's Format=int32u read).
    let expressive = RawValue::U64(vec![0, 1]);
    assert_eq!(
      PanasonicPrintConv::FilterEffect.apply(&expressive, true),
      TagValue::Str("Expressive".into())
    );
    // -n: the raw int pair string.
    assert_eq!(
      PanasonicPrintConv::FilterEffect.apply(&expressive, false),
      TagValue::Str("0 1".into())
    );
    assert_eq!(
      PanasonicPrintConv::FilterEffect.apply(&RawValue::U64(vec![0, 0]), true),
      TagValue::Str("Off".into())
    );
    assert_eq!(
      PanasonicPrintConv::FilterEffect.apply(&RawValue::U64(vec![0, 134_217_728]), true),
      TagValue::Str("Silky Monochrome".into())
    );
    // Regression guard for the bundled-hash transcription (Panasonic.pm:
    // 1280-1302): these keys were previously assigned the WRONG labels and
    // slipped past the presence-only oracle. Pin the exact bundled mapping.
    for (key, want) in [
      (4u64, "High Key"),
      (8, "Sepia"),
      (32, "Miniature Effect"),
      (256, "Low Key"),
      (512, "Toy Effect"),
      (2048, "Soft Focus"),
      (4096, "Impressive Art"),
      (8192, "Cross Process"),
      (32768, "Star Filter"),
      (524_288, "Old Days"),
      (2_097_152, "Bleach Bypass"),
      (4_194_304, "Toy Pop"),
      (8_388_608, "Fantasy"),
      (33_554_432, "Monochrome"),
      (67_108_864, "Rough Monochrome"),
    ] {
      assert_eq!(
        PanasonicPrintConv::FilterEffect.apply(&RawValue::U64(vec![0, key]), true),
        TagValue::Str(want.into()),
        "0xa1 FilterEffect key `0 {key}` should be {want:?}",
      );
    }
    // HASH-miss ⇒ decimal `Unknown (0 99)` (plain hash, not PrintHex).
    assert_eq!(
      PanasonicPrintConv::FilterEffect.apply(&RawValue::U64(vec![0, 99]), true),
      TagValue::Str("Unknown (0 99)".into())
    );
  }

  /// 0xbf PostFocusMerging (`Panasonic.pm:1391-1396`). int32u[2]; single key.
  #[test]
  fn post_focus_merging_labels() {
    assert_eq!(
      PanasonicPrintConv::PostFocusMerging.apply(&RawValue::U64(vec![0, 0]), true),
      TagValue::Str("Post Focus Auto Merging or None".into())
    );
    assert_eq!(
      PanasonicPrintConv::PostFocusMerging.apply(&RawValue::U64(vec![0, 0]), false),
      TagValue::Str("0 0".into())
    );
    assert_eq!(
      PanasonicPrintConv::PostFocusMerging.apply(&RawValue::U64(vec![0, 1]), true),
      TagValue::Str("Unknown (0 1)".into())
    );
  }

  /// 0xaf TimeStamp (`Panasonic.pm:1335-1342`). `ConvertDateTime` under
  /// default options is identity, so `-n` and `-j` both emit the raw string
  /// (NUL-trimmed). Cross-checked: bundled `ConvertDateTime("2021:05:30
  /// 12:34:56")` returns the input unchanged.
  #[test]
  fn time_stamp_convert_datetime_identity() {
    let raw = RawValue::Text {
      text: "2021:05:30 12:34:56".into(),
      raw: b"2021:05:30 12:34:56"[..].into(),
    };
    assert_eq!(
      PanasonicPrintConv::TimeStamp.apply(&raw, true),
      TagValue::Str("2021:05:30 12:34:56".into())
    );
    assert_eq!(
      PanasonicPrintConv::TimeStamp.apply(&raw, false),
      TagValue::Str("2021:05:30 12:34:56".into())
    );
    // NUL-padded bytes ⇒ reader-style NUL trim.
    let raw2 = RawValue::Bytes(b"2021:05:30 12:34:56\0\0".to_vec());
    assert_eq!(
      PanasonicPrintConv::TimeStamp.apply(&raw2, true),
      TagValue::Str("2021:05:30 12:34:56".into())
    );
  }

  /// The bare-rational (no-conv) path renders a multi-element rational as the
  /// space-joined DECIMAL of each element (`ExifTool.pm:6107-6119`), NOT the
  /// raw `num/den`. Pins the `raw_to_tag_value` fix.
  #[test]
  fn bare_multi_rational_renders_decimal_not_fraction() {
    use crate::value::Rational;
    let pair = RawValue::Rational(vec![
      Rational::rational64(128, 256),
      Rational::rational64(3, 4),
    ]);
    assert_eq!(
      raw_to_tag_value(&pair),
      TagValue::Str("0.5 0.75".into()),
      "decimal join, not \"128/256 3/4\""
    );
    // A single rational stays a Rational (serializes to its decimal scalar).
    let single = RawValue::Rational(vec![Rational::rational64(1, 2)]);
    assert_eq!(
      raw_to_tag_value(&single),
      TagValue::Rational(Rational::rational64(1, 2))
    );
  }

  #[test]
  fn internal_serial_number_decodes_structured_form() {
    let raw = RawValue::Bytes(b"S000407190102".to_vec());
    assert_eq!(
      PanasonicPrintConv::InternalSerialNumber.apply(&raw, true),
      TagValue::Str("(S00) 2004:07:19 no. 0102".into())
    );
  }

  #[test]
  fn time_since_power_on_renders_hhmmss() {
    let raw = RawValue::U64(vec![696]);
    assert_eq!(
      PanasonicPrintConv::TimeSincePowerOn.apply(&raw, true),
      TagValue::Str("00:00:06.96".into())
    );
  }

  #[test]
  fn shooting_mode_program_label() {
    let raw = RawValue::U64(vec![6]);
    assert_eq!(
      PanasonicPrintConv::ShootingMode.apply(&raw, true),
      TagValue::Str("Program".into())
    );
  }

  #[test]
  fn scene_mode_off_label() {
    let raw = RawValue::U64(vec![0]);
    assert_eq!(
      PanasonicPrintConv::SceneMode.apply(&raw, true),
      TagValue::Str("Off".into())
    );
  }

  #[test]
  fn fraction_third_zero() {
    let raw = RawValue::I64(vec![0]);
    assert_eq!(
      PanasonicPrintConv::WhiteBalanceBias.apply(&raw, true),
      TagValue::Str("0".into())
    );
  }

  #[test]
  fn lens_firmware_version_dotted() {
    let raw = RawValue::U64(std::vec![0, 1, 2, 3]);
    assert_eq!(
      PanasonicPrintConv::LensFirmwareVersion.apply(&raw, true),
      TagValue::Str("0.1.2.3".into())
    );
  }

  #[test]
  fn flash_warning_labels() {
    assert_eq!(
      PanasonicPrintConv::FlashWarning.apply(&RawValue::U64(vec![0]), true),
      TagValue::Str("No".into())
    );
    assert_eq!(
      PanasonicPrintConv::FlashWarning.apply(&RawValue::U64(vec![1]), true),
      TagValue::Str("Yes (flash required but disabled)".into())
    );
  }

  /// `/DMC-FZ10\b/` — matches DMC-FZ10 (and with a trailing non-word char),
  /// NOT DMC-FZ100 (trailing digit is a word char ⇒ no `\b`).
  #[test]
  fn model_fz10_word_boundary() {
    assert!(model_is_fz10("DMC-FZ10"));
    assert!(model_is_fz10("DMC-FZ10 "));
    assert!(!model_is_fz10("DMC-FZ100"));
    assert!(!model_is_fz10("DMC-FZ1000"));
    assert!(!model_is_fz10("DMC-FZ8"));
  }

  /// `/^DMC-(GF\d+|G2)$/` — anchored; GF needs ≥1 digit.
  #[test]
  fn model_gf_g2_anchored() {
    assert!(model_is_gf_g2("DMC-GF1"));
    assert!(model_is_gf_g2("DMC-GF6"));
    assert!(model_is_gf_g2("DMC-G2"));
    assert!(!model_is_gf_g2("DMC-GF")); // no digit
    assert!(!model_is_gf_g2("DMC-G1")); // G1 is not in this set
    assert!(!model_is_gf_g2("DMC-GF1X")); // trailing junk (anchored $)
    assert!(!model_is_gf_g2("XDMC-GF1")); // leading junk (anchored ^)
  }

  /// 0x2c branch-1 condition (`Model !~ excluded and !~ /^DC-/`). Empty
  /// (undef) Model selects branch 1; the excluded set + DC- bodies do not.
  #[test]
  fn contrast_mode_branch1_selection() {
    assert!(contrast_mode_branch1("")); // undef ⇒ branch 1
    assert!(contrast_mode_branch1("DMC-FZ8"));
    assert!(contrast_mode_branch1("DMC-LX100"));
    assert!(!contrast_mode_branch1("DMC-G1"));
    assert!(!contrast_mode_branch1("DMC-GF1"));
    assert!(!contrast_mode_branch1("DMC-TZ10"));
    assert!(!contrast_mode_branch1("DC-GH6"));
    assert!(!contrast_mode_branch1("DC-G9M2"));
  }

  /// The branch selector returns the right conv variant per Model.
  #[test]
  fn contrast_mode_for_model_branch_variants() {
    assert_eq!(
      PanasonicPrintConv::contrast_mode_for_model(Some("DMC-FZ8")),
      PanasonicPrintConv::ContrastMode
    );
    assert_eq!(
      PanasonicPrintConv::contrast_mode_for_model(None),
      PanasonicPrintConv::ContrastMode
    );
    assert_eq!(
      PanasonicPrintConv::contrast_mode_for_model(Some("DMC-GF1")),
      PanasonicPrintConv::ContrastModeGfG2
    );
    assert_eq!(
      PanasonicPrintConv::contrast_mode_for_model(Some("DMC-TZ10")),
      PanasonicPrintConv::ContrastModeTz10Zs7
    );
    // Excluded-from-branch-1, not GF/G2/TZ10/ZS7 ⇒ raw (None).
    assert_eq!(
      PanasonicPrintConv::contrast_mode_for_model(Some("DMC-G1")),
      PanasonicPrintConv::None
    );
    assert_eq!(
      PanasonicPrintConv::contrast_mode_for_model(Some("DC-GH6")),
      PanasonicPrintConv::None
    );
  }

  /// FZ10 0x0f branch: matched keys + HASH-miss `Unknown ($val)`.
  #[test]
  fn af_area_mode_fz10_labels_and_miss() {
    assert_eq!(
      PanasonicPrintConv::AfAreaModeFz10.apply(&RawValue::U64(vec![0, 1]), true),
      TagValue::Str("Spot Mode On".into())
    );
    assert_eq!(
      PanasonicPrintConv::AfAreaModeFz10.apply(&RawValue::U64(vec![0, 16]), true),
      TagValue::Str("Spot Mode Off".into())
    );
    // Unmatched pair → "Unknown ($val)" (`ExifTool.pm:3633`), NOT raw key.
    assert_eq!(
      PanasonicPrintConv::AfAreaModeFz10.apply(&RawValue::U64(vec![32, 0]), true),
      TagValue::Str("Unknown (32 0)".into())
    );
  }

  /// AFAreaMode "other models" HASH-miss is `Unknown ($val)` too (fixed from
  /// the prior raw-key fallthrough; `ExifTool.pm:3633`).
  #[test]
  fn af_area_mode_other_models_miss_is_unknown() {
    assert_eq!(
      PanasonicPrintConv::AfAreaMode.apply(&RawValue::U64(vec![99, 99]), true),
      TagValue::Str("Unknown (99 99)".into())
    );
  }

  /// 0x2c GF/G2 branch labels + decimal `Unknown (N)` miss.
  #[test]
  fn contrast_mode_gf_g2_labels() {
    assert_eq!(
      PanasonicPrintConv::ContrastModeGfG2.apply(&RawValue::U64(vec![32]), true),
      TagValue::Str("Vibrant (Color Film) or Expressive (My Color)".into())
    );
    assert_eq!(
      PanasonicPrintConv::ContrastModeGfG2.apply(&RawValue::U64(vec![999]), true),
      TagValue::Str("Unknown (999)".into())
    );
  }

  /// 0x2c TZ10/ZS7 branch labels.
  #[test]
  fn contrast_mode_tz10_zs7_labels() {
    assert_eq!(
      PanasonicPrintConv::ContrastModeTz10Zs7.apply(&RawValue::U64(vec![6]), true),
      TagValue::Str("+1".into())
    );
  }
}
