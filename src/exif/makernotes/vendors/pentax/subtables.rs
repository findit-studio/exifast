// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Pentax binary `ProcessBinaryData` SubDirectory tables — Phase 2a (#262).
//!
//! Three `%Pentax::Main` `SubDirectory` rows whose K10D variant the
//! `Pentax.jpg` (K10D) fixture exercises:
//!
//! - `%Pentax::CameraSettings` (`0x0205`, `Pentax.pm:3361-3768`) —
//!   `ProcessBinaryData` / `BigEndian`. The K10D variant is selected by the
//!   Main-row `Condition => '$count < 25'` (`Pentax.pm:2788`).
//! - `%Pentax::AEInfo` (`0x0206`, `Pentax.pm:3778-3990`) — `ProcessBinaryData`.
//!   The K10D variant is selected by `Condition => '$count <= 25 and
//!   $count != 21'` (`Pentax.pm:2804`).
//! - `%Pentax::FlashInfo` (`0x0208`, `Pentax.pm:4580-4708`) —
//!   `ProcessBinaryData`. The K10D variant is selected by `Condition =>
//!   '$count == 27'` (`Pentax.pm:2855`).
//!
//! ## The `$count`-gated variant scope-fence (the load-bearing correctness point)
//!
//! Each of these Main rows is a Perl LIST of `SubDirectory` alternatives keyed
//! on `$count` (the IFD entry's element count). Only the K10D variant is ported;
//! [`emit_camera_settings`] / [`emit_aeinfo`] / [`emit_flashinfo`] re-check the
//! exact `$count` `Condition` BEFORE decoding, so a non-K10D record size (e.g.
//! the K-01 `CameraSettings` `$count == 25`, the K-r `AEInfo` `$count == 21`,
//! the Q `FlashInfo` `$count != 27`) falls through to its deferred
//! `*Unknown`/`AEInfo2`/`AEInfo3` variant and emits NOTHING — never a bogus
//! decode through the wrong layout. `$count` is the IFD entry COUNT
//! (`value_size / on_disk_format.byte_size()`), computed by the caller.
//!
//! ## The K10D-offset-13+ model gate (`%Pentax::CameraSettings`)
//!
//! Many `CameraSettings` leaves carry `Condition => '$$self{Model} =~
//! /(K10D|GX10)\b/'` (`Pentax.pm:3586`…): they are valid ONLY for the K10D /
//! Samsung GX10 body. [`emit_camera_settings`] takes the parent `$$self{Model}`
//! (threaded through the isolated Pentax walk after the Phase-1 `FixBase` fix)
//! and emits those leaves only when it matches, mirroring ExifTool's per-tag
//! `Condition`. The base leaves (offsets 0-10, `ISOFloor` at 6) are emitted for
//! every `$count < 25` body.
//!
//! ## Formats and conversions
//!
//! `%binaryDataAttrs` declares no `FORMAT`, so the default ProcessBinaryData
//! element format is `int8u` (`FIRST_ENTRY => 0`). A leaf with an explicit
//! `Format => 'int16u'` / `'int8s'` overrides one element. A `Mask => 0xNN`
//! leaf reads `($val & mask) >> bitShift` where `bitShift` is the mask's
//! trailing-zero-bit count (`ExifTool.pm:5916-5919` / `:10078-10079`). The
//! exp/log `ValueConv`s (`PentaxEv`, the AE formulas) are inlined as pure Rust
//! `f64` math; the `PrintExposureTime` PrintConv reuses the Phase-1 helper.

#![deny(clippy::indexing_slicing)]

use crate::value::TagValue;
use smol_str::SmolStr;

use super::super::VendorEmission;
use super::printconv;

/// `Image::ExifTool::Pentax::PentaxEv` (`Pentax.pm:6822-6835`).
///
/// ```text
/// if ($val & 0x01) {
///     my $sign = $val < 0 ? -1 : 1;
///     my $frac = ($val * $sign) & 0x07;
///     if    ($frac == 0x03) { $val += $sign * ( 8 / 3 - $frac) }
///     elsif ($frac == 0x05) { $val += $sign * (16 / 3 - $frac) }
/// }
/// return $val / 8;
/// ```
///
/// `$val` reaches here as an integer (a binary-data byte, or `64 - $val` /
/// `$val - 68` etc.). The `& 0x01` / `& 0x07` Perl bit-ops force integer
/// (UV/IV) context; the fractional adjustment then produces an `f64`.
#[must_use]
pub(crate) fn pentax_ev(val: i64) -> f64 {
  let mut v = val as f64;
  if val & 0x01 != 0 {
    let sign = if val < 0 { -1.0 } else { 1.0 };
    // `($val * $sign) & 0x07` — the magnitude's low 3 bits (val*sign >= 0).
    let frac = ((val * if val < 0 { -1 } else { 1 }) & 0x07) as f64;
    if frac == 3.0 {
      v += sign * (8.0 / 3.0 - frac);
    } else if frac == 5.0 {
      v += sign * (16.0 / 3.0 - frac);
    }
  }
  v / 8.0
}

/// `$val == 255 ? "n/a" : $val` style integer-or-`-n` value.
#[inline]
fn int_value(n: i64) -> TagValue {
  TagValue::I64(n)
}

/// A `$val ? sprintf("%+.1f", $val) : 0` PrintConv (the shared
/// `BaseExposureCompensation` / `FlashExposureCompSet` rendering): the signed
/// one-decimal string, or the integer `0` when the value is exactly zero.
fn signed_ev_print(v: f64) -> TagValue {
  if v == 0.0 {
    TagValue::I64(0)
  } else {
    TagValue::Str(SmolStr::from(std::format!("{v:+.1}")))
  }
}

/// `sprintf("%.1f", $val)` → a one-decimal string (rendered as a JSON number by
/// the serializer's `EscapeJSON` gate, e.g. `"12.7"` → `12.7`).
fn fixed1_print(v: f64) -> TagValue {
  TagValue::Str(SmolStr::from(std::format!("{v:.1}")))
}

/// Push a leaf emission (never `Unknown`).
#[inline]
fn push(out: &mut std::vec::Vec<VendorEmission>, name: &'static str, value: TagValue) {
  out.push(VendorEmission::new(SmolStr::new_static(name), value, false));
}

/// `true` when the parent body `$$self{Model}` matches `/(K10D|GX10)\b/`
/// (`Pentax.pm:3586`…) — the model gate for the `CameraSettings`-offset-13+
/// leaves. `\b` is a word boundary; the model strings are `"PENTAX K10D"` /
/// `"PENTAX GX10"` (or the bare body name), so a suffix match with a trailing
/// word boundary is faithful.
fn is_k10d_or_gx10(model: Option<&str>) -> bool {
  let Some(m) = model else {
    return false;
  };
  // `/(K10D|GX10)\b/` — find the token followed by a non-word char or end.
  for needle in ["K10D", "GX10"] {
    let mut from = 0;
    while let Some(rel) = m.get(from..).and_then(|s| s.find(needle)) {
      let start = from + rel;
      let end = start + needle.len();
      let after_ok = m
        .get(end..)
        .and_then(|s| s.chars().next())
        .is_none_or(|c| !is_word_char(c));
      if after_ok {
        return true;
      }
      from = end;
    }
  }
  false
}

/// Perl `\w` — `[A-Za-z0-9_]` (the ASCII word class; the model names are ASCII).
#[inline]
const fn is_word_char(c: char) -> bool {
  c.is_ascii_alphanumeric() || c == '_'
}

/// Decode `%Pentax::CameraSettings` (`0x0205`) for the K10D `$count < 25`
/// variant (`Pentax.pm:3361-3768`). `block` is the verbatim on-disk record
/// span; `count` is the IFD entry COUNT (the `$count` `Condition` reads);
/// `model` is the parent `$$self{Model}`; `print_conv` selects `-j`/`-n`.
///
/// A `count >= 25` entry (the K-01 `CameraSettingsUnknown` variant) emits
/// NOTHING (the scope-fence). Each leaf is bounds-checked: an offset past the
/// (possibly truncated) block is skipped, matching `ProcessBinaryData`'s
/// `last if $entry >= $size`.
pub(crate) fn emit_camera_settings(
  block: &[u8],
  count: usize,
  model: Option<&str>,
  print_conv: bool,
  out: &mut std::vec::Vec<VendorEmission>,
) {
  // `Condition => '$count < 25'` (`Pentax.pm:2788`) — the K10D variant gate.
  if count >= 25 {
    return;
  }
  let k10d = is_k10d_or_gx10(model);
  let b = |i: usize| block.get(i).copied();

  // 0: PictureMode2 (int8u) — direct hash.
  if let Some(v) = b(0) {
    push(
      out,
      "PictureMode2",
      hash(print_conv, i64::from(v), printconv::PICTURE_MODE2),
    );
  }
  // 1: bitfields.
  if let Some(v) = b(1) {
    let v = i64::from(v);
    push(
      out,
      "ProgramLine",
      hash(print_conv, mask(v, 0x03), printconv::PROGRAM_LINE),
    );
    push(
      out,
      "EVSteps",
      hash(print_conv, mask(v, 0x20), printconv::EV_STEPS),
    );
    push(
      out,
      "E-DialInProgram",
      hash(print_conv, mask(v, 0x40), printconv::E_DIAL_IN_PROGRAM),
    );
    push(
      out,
      "ApertureRingUse",
      hash(print_conv, mask(v, 0x80), printconv::APERTURE_RING_USE),
    );
  }
  // 2: FlashOptions (mask 0xf0) + MeteringMode2 (mask 0x0f, BITMASK).
  if let Some(v) = b(2) {
    let v = i64::from(v);
    push(
      out,
      "FlashOptions",
      hash(print_conv, mask(v, 0xf0), printconv::FLASH_OPTIONS),
    );
    push(
      out,
      "MeteringMode2",
      bitmask0(
        print_conv,
        mask(v, 0x0f),
        "Multi-segment",
        printconv::METERING_MODE_BITS,
      ),
    );
  }
  // 3: AFPointMode (mask 0xf0, BITMASK) + FocusMode2 (mask 0x0f).
  if let Some(v) = b(3) {
    let v = i64::from(v);
    push(
      out,
      "AFPointMode",
      bitmask0(
        print_conv,
        mask(v, 0xf0),
        "Auto",
        printconv::AF_POINT_MODE_BITS,
      ),
    );
    push(
      out,
      "FocusMode2",
      hash(print_conv, mask(v, 0x0f), printconv::FOCUS_MODE2),
    );
  }
  // 4: AFPointSelected2 (int16u, BITMASK). Big-endian (the table ByteOrder).
  if let (Some(hi), Some(lo)) = (b(4), b(5)) {
    let v = (i64::from(hi) << 8) | i64::from(lo);
    push(
      out,
      "AFPointSelected2",
      bitmask0(print_conv, v, "Auto", printconv::AF_POINT_SELECTED2_BITS),
    );
  }
  // 6: ISOFloor — int(100*exp(PentaxEv($val-32)*ln2)+0.5).
  if let Some(v) = b(6) {
    push(out, "ISOFloor", iso_from_ev(i64::from(v)));
  }
  // 7: DriveMode2 (BITMASK).
  if let Some(v) = b(7) {
    push(
      out,
      "DriveMode2",
      bitmask0(
        print_conv,
        i64::from(v),
        "Single-frame",
        printconv::DRIVE_MODE2_BITS,
      ),
    );
  }
  // 8: ExposureBracketStepSize.
  if let Some(v) = b(8) {
    push(
      out,
      "ExposureBracketStepSize",
      hash(
        print_conv,
        i64::from(v),
        printconv::EXPOSURE_BRACKET_STEP_SIZE,
      ),
    );
  }
  // 9: BracketShotNumber (PrintHex).
  if let Some(v) = b(9) {
    push(
      out,
      "BracketShotNumber",
      hash_hex(print_conv, i64::from(v), printconv::BRACKET_SHOT_NUMBER),
    );
  }
  // 10: WhiteBalanceSet (mask 0xf0) + MultipleExposureSet (mask 0x0f).
  if let Some(v) = b(10) {
    let v = i64::from(v);
    push(
      out,
      "WhiteBalanceSet",
      hash(print_conv, mask(v, 0xf0), printconv::WHITE_BALANCE_SET),
    );
    push(
      out,
      "MultipleExposureSet",
      hash(print_conv, mask(v, 0x0f), printconv::OFF_ON),
    );
  }

  if !k10d {
    return;
  }
  // ---- K10D / GX10-only leaves (offsets 13-21) ----
  // 13: RawAndJpgRecording (PrintHex).
  if let Some(v) = b(13) {
    push(
      out,
      "RawAndJpgRecording",
      hash_hex(print_conv, i64::from(v), printconv::RAW_AND_JPG_RECORDING),
    );
  }
  // 14.1: JpgRecordedPixels (mask 0x03).
  if let Some(v) = b(14) {
    push(
      out,
      "JpgRecordedPixels",
      hash(
        print_conv,
        mask(i64::from(v), 0x03),
        printconv::JPG_RECORDED_PIXELS,
      ),
    );
  }
  // 16: FlashOptions2 (mask 0xf0) + MeteringMode3 (mask 0x0f, BITMASK).
  if let Some(v) = b(16) {
    let v = i64::from(v);
    push(
      out,
      "FlashOptions2",
      hash(print_conv, mask(v, 0xf0), printconv::FLASH_OPTIONS),
    );
    push(
      out,
      "MeteringMode3",
      bitmask0(
        print_conv,
        mask(v, 0x0f),
        "Multi-segment",
        printconv::METERING_MODE_BITS,
      ),
    );
  }
  // 17: SRActive (0x80) + Rotation (0x60) + ISOSetting (0x04) + SensitivitySteps (0x02).
  if let Some(v) = b(17) {
    let v = i64::from(v);
    push(
      out,
      "SRActive",
      hash(print_conv, mask(v, 0x80), printconv::NO_YES),
    );
    push(
      out,
      "Rotation",
      hash(print_conv, mask(v, 0x60), printconv::ROTATION),
    );
    push(
      out,
      "ISOSetting",
      hash(print_conv, mask(v, 0x04), printconv::ISO_SETTING),
    );
    push(
      out,
      "SensitivitySteps",
      hash(print_conv, mask(v, 0x02), printconv::SENSITIVITY_STEPS),
    );
  }
  // 18: TvExposureTimeSetting — exp(-PentaxEv($val-68)*ln2); PrintExposureTime.
  if let Some(v) = b(18) {
    let secs = (-pentax_ev(i64::from(v) - 68) * std::f64::consts::LN_2).exp();
    push(
      out,
      "TvExposureTimeSetting",
      if print_conv {
        TagValue::Str(SmolStr::from(printconv::print_exposure_time(secs)))
      } else {
        TagValue::F64(secs)
      },
    );
  }
  // 19: AvApertureSetting — exp(PentaxEv($val-68)*ln2/2); sprintf("%.1f").
  if let Some(v) = b(19) {
    let f = (pentax_ev(i64::from(v) - 68) * std::f64::consts::LN_2 / 2.0).exp();
    push(
      out,
      "AvApertureSetting",
      if print_conv {
        fixed1_print(f)
      } else {
        TagValue::F64(f)
      },
    );
  }
  // 20: SvISOSetting — int(100*exp(PentaxEv($val-32)*ln2)+0.5) (no PrintConv).
  if let Some(v) = b(20) {
    push(out, "SvISOSetting", iso_from_ev(i64::from(v)));
  }
  // 21: BaseExposureCompensation — PentaxEv(64-$val); $val ? %+.1f : 0.
  if let Some(v) = b(21) {
    let ev = pentax_ev(64 - i64::from(v));
    push(
      out,
      "BaseExposureCompensation",
      if print_conv {
        signed_ev_print(ev)
      } else {
        TagValue::F64(ev)
      },
    );
  }
}

/// `int(100*exp(PentaxEv($val-32)*log(2))+0.5)` — the shared `ISOFloor` /
/// `SvISOSetting` ValueConv (`Pentax.pm:3499`/`:3756`). `int(... + 0.5)` rounds
/// toward zero after adding 0.5, so the result is an integer for both `-j` and
/// `-n` (there is no PrintConv).
fn iso_from_ev(raw: i64) -> TagValue {
  let f = 100.0 * (pentax_ev(raw - 32) * std::f64::consts::LN_2).exp() + 0.5;
  // Perl `int()` truncates toward zero; the value is always positive here.
  int_value(f.trunc() as i64)
}

/// Decode `%Pentax::AEInfo` (`0x0206`) for the `$count <= 25 and $count != 21`
/// variant (`Pentax.pm:3778-3990`) — the K10D `Pentax.jpg` (16 bytes) and the
/// K-x `Pentax.avi` (24 bytes) both select it.
///
/// `AEFlags` (offset 7) carries `Hook => '$size > 20 and $varSize += 1'`
/// (`Pentax.pm:3871`): for a record whose BYTE SIZE is larger than 20 every
/// subsequent leaf reads one byte later, so offsets 8-14 are emitted at
/// `offset + shift` where `shift = (block.len() > 20) as usize`. `block.len()`
/// is the re-sliced SubDirectory byte span — ExifTool's `$size` (the data-block
/// byte size, `value_size`), NOT `$count`: the two diverge when a non-`undef`
/// on-disk format coerces a record through the implicit-`undef` SubDirectory path
/// (count <= 20 yet byte size > 20). The K10D record is 16 bytes ⇒ `shift == 0`;
/// the K-x is 24 ⇒ `shift == 1`.
///
/// `AEFlags` itself is `RawConv => '$$self{OPTIONS}{Unknown} ? $val : undef'`
/// (`Pentax.pm:3876`) — it emits nothing without `-U`, so it is not ported.
/// `AEWhiteBalance` / `AEMeteringMode2` (offset 13) are gated `$$self{AEInfoSize}
/// == 24` (`Pentax.pm:3942`/`:3959`) — a deferred size-24-only pair that the K-x
/// (24 bytes) DOES carry; this Phase-2a port emits only the size-independent
/// leaves, so they (and the size-24 `LevelIndicator` at offset 21) are deferred
/// to the `-x` list, never mis-emitted.
pub(crate) fn emit_aeinfo(
  block: &[u8],
  count: usize,
  print_conv: bool,
  out: &mut std::vec::Vec<VendorEmission>,
) {
  // `Condition => '$count <= 25 and $count != 21'` (`Pentax.pm:2804`). The
  // `$$self{AEInfoSize} = $count` assignment is an always-true side effect; for
  // the ported K10D layout AEInfoSize == count == 16 (no offset shift, no
  // size-24 leaves). A `$count > 25` / `== 21` / `== 48|64` / `== 34` record is
  // a deferred variant ⇒ emit nothing.
  if count > 25 || count == 21 {
    return;
  }
  // `AEFlags` (offset 7) `Hook => '$size > 20 and $varSize += 1'`
  // (`Pentax.pm:3871`): for a record whose BYTE SIZE is LARGER than 20 (e.g. the
  // K-x AVI's 24-byte AEInfo), every leaf AFTER offset 7 reads one byte LATER. So
  // offsets 0-7 are fixed; offsets 8-14 are `+shift`. The Hook keys on ExifTool's
  // `$size` (the SubDirectory data-block BYTE size) — the re-sliced `block.len()`
  // here — NOT `$count`: the two coincide for an `undef` record but DIVERGE when a
  // wider-than-`int8u` on-disk format coerces a record through the implicit-`undef`
  // SubDirectory path (count <= 20 yet byte size > 20), which would otherwise pass
  // the count-based variant gate yet read offsets 8+ one byte early. The K10D
  // `Pentax.jpg` record is 16 bytes ⇒ `shift == 0`; the K-x AVI is 24 ⇒ `shift == 1`.
  let shift = usize::from(block.len() > 20);
  let b = |i: usize| block.get(i).copied();

  // 0: AEExposureTime — 24*exp(-($val-32)*ln2/8); PrintExposureTime.
  if let Some(v) = b(0) {
    let secs = 24.0 * (-(f64::from(v) - 32.0) * std::f64::consts::LN_2 / 8.0).exp();
    push(out, "AEExposureTime", expo_value(secs, print_conv));
  }
  // 1: AEAperture — exp(($val-68)*ln2/16); sprintf("%.1f").
  if let Some(v) = b(1) {
    let f = aperture_from_raw(i64::from(v));
    push(
      out,
      "AEAperture",
      if print_conv {
        fixed1_print(f)
      } else {
        TagValue::F64(f)
      },
    );
  }
  // 2: AE_ISO — 100*exp(($val-32)*ln2/8); int($val+0.5).
  if let Some(v) = b(2) {
    let f = 100.0 * ((f64::from(v) - 32.0) * std::f64::consts::LN_2 / 8.0).exp();
    push(
      out,
      "AE_ISO",
      if print_conv {
        TagValue::I64((f + 0.5).trunc() as i64)
      } else {
        TagValue::F64(f)
      },
    );
  }
  // 3: AEXv — ($val-64)/8 (no PrintConv).
  if let Some(v) = b(3) {
    push(out, "AEXv", TagValue::F64((f64::from(v) - 64.0) / 8.0));
  }
  // 4: AEBXv — int8s; $val / 8 (no PrintConv).
  if let Some(v) = b(4) {
    push(out, "AEBXv", TagValue::F64(f64::from(v as i8) / 8.0));
  }
  // 5: AEMinExposureTime — 24*exp(-($val-32)*ln2/8); PrintExposureTime.
  if let Some(v) = b(5) {
    let secs = 24.0 * (-(f64::from(v) - 32.0) * std::f64::consts::LN_2 / 8.0).exp();
    push(out, "AEMinExposureTime", expo_value(secs, print_conv));
  }
  // 6: AEProgramMode — direct hash.
  if let Some(v) = b(6) {
    push(
      out,
      "AEProgramMode",
      hash(print_conv, i64::from(v), printconv::AE_PROGRAM_MODE),
    );
  }
  // 7: AEFlags — RawConv drops it without -U (not ported).
  // 8 (+shift): AEApertureSteps — $val == 255 ? "n/a" : $val.
  if let Some(v) = b(8 + shift) {
    let n = i64::from(v);
    push(
      out,
      "AEApertureSteps",
      if print_conv && n == 255 {
        TagValue::Str(SmolStr::from("n/a"))
      } else {
        int_value(n)
      },
    );
  }
  // 9 (+shift): AEMaxAperture — exp(($val-68)*ln2/16); sprintf("%.1f").
  if let Some(v) = b(9 + shift) {
    let f = aperture_from_raw(i64::from(v));
    push(
      out,
      "AEMaxAperture",
      if print_conv {
        fixed1_print(f)
      } else {
        TagValue::F64(f)
      },
    );
  }
  // 10 (+shift): AEMaxAperture2 — exp(($val-68)*ln2/16); sprintf("%.1f").
  if let Some(v) = b(10 + shift) {
    let f = aperture_from_raw(i64::from(v));
    push(
      out,
      "AEMaxAperture2",
      if print_conv {
        fixed1_print(f)
      } else {
        TagValue::F64(f)
      },
    );
  }
  // 11 (+shift): AEMinAperture — exp(($val-68)*ln2/16); sprintf("%.0f").
  if let Some(v) = b(11 + shift) {
    let f = aperture_from_raw(i64::from(v));
    push(
      out,
      "AEMinAperture",
      if print_conv {
        TagValue::Str(SmolStr::from(std::format!("{f:.0}")))
      } else {
        TagValue::F64(f)
      },
    );
  }
  // 12 (+shift): AEMeteringMode — direct hash + BITMASK.
  if let Some(v) = b(12 + shift) {
    push(
      out,
      "AEMeteringMode",
      bitmask0(
        print_conv,
        i64::from(v),
        "Multi-segment",
        printconv::AE_METERING_MODE_BITS,
      ),
    );
  }
  // 14 (+shift): FlashExposureCompSet — int8s; PentaxEv($val); $val ? %+.1f : 0.
  if let Some(v) = b(14 + shift) {
    let ev = pentax_ev(i64::from(v as i8));
    push(
      out,
      "FlashExposureCompSet",
      if print_conv {
        signed_ev_print(ev)
      } else {
        TagValue::F64(ev)
      },
    );
  }
}

/// `exp(($val-68)*log(2)/16)` — the shared AEInfo aperture ValueConv
/// (`Pentax.pm:3795`…).
#[inline]
fn aperture_from_raw(raw: i64) -> f64 {
  ((raw as f64 - 68.0) * std::f64::consts::LN_2 / 16.0).exp()
}

/// The shared `AEExposureTime` / `AEMinExposureTime` value: `-n` ⇒ the seconds
/// `f64`; `-j` ⇒ `PrintExposureTime`.
#[inline]
fn expo_value(secs: f64, print_conv: bool) -> TagValue {
  if print_conv {
    TagValue::Str(SmolStr::from(printconv::print_exposure_time(secs)))
  } else {
    TagValue::F64(secs)
  }
}

/// Decode `%Pentax::FlashInfo` (`0x0208`) for the K10D `$count == 27` variant
/// (`Pentax.pm:4580-4708`). A `count != 27` entry (the `FlashInfoUnknown`
/// variant) emits NOTHING (the scope-fence).
pub(crate) fn emit_flashinfo(
  block: &[u8],
  count: usize,
  print_conv: bool,
  out: &mut std::vec::Vec<VendorEmission>,
) {
  // `Condition => '$count == 27'` (`Pentax.pm:2855`) — the K10D variant gate.
  if count != 27 {
    return;
  }
  let b = |i: usize| block.get(i).copied();

  // 0: FlashStatus (PrintHex).
  if let Some(v) = b(0) {
    push(
      out,
      "FlashStatus",
      hash_hex(print_conv, i64::from(v), printconv::FLASH_STATUS),
    );
  }
  // 1: InternalFlashMode (PrintHex).
  if let Some(v) = b(1) {
    push(
      out,
      "InternalFlashMode",
      hash_hex(print_conv, i64::from(v), printconv::INTERNAL_FLASH_MODE),
    );
  }
  // 2: ExternalFlashMode (PrintHex).
  if let Some(v) = b(2) {
    push(
      out,
      "ExternalFlashMode",
      hash_hex(print_conv, i64::from(v), printconv::EXTERNAL_FLASH_MODE),
    );
  }
  // 3: InternalFlashStrength (no conv).
  if let Some(v) = b(3) {
    push(out, "InternalFlashStrength", int_value(i64::from(v)));
  }
  // 4-7: TTL_DA_AUp / ADown / BUp / BDown (no conv).
  for (i, name) in [
    (4, "TTL_DA_AUp"),
    (5, "TTL_DA_ADown"),
    (6, "TTL_DA_BUp"),
    (7, "TTL_DA_BDown"),
  ] {
    if let Some(v) = b(i) {
      push(out, name, int_value(i64::from(v)));
    }
  }
  // 24.1: ExternalFlashGuideNumber (mask 0x1f) — exp ValueConv; int or "n/a".
  if let Some(v) = b(24) {
    let raw = mask(i64::from(v), 0x1f);
    let gn = external_flash_guide_number(raw);
    push(
      out,
      "ExternalFlashGuideNumber",
      if print_conv {
        if gn == 0.0 {
          TagValue::Str(SmolStr::from("n/a"))
        } else {
          // `int($val + 0.5)`.
          int_value((gn + 0.5).trunc() as i64)
        }
      } else {
        TagValue::F64(gn)
      },
    );
  }
  // 25: ExternalFlashExposureComp (hash).
  if let Some(v) = b(25) {
    push(
      out,
      "ExternalFlashExposureComp",
      hash(
        print_conv,
        i64::from(v),
        printconv::EXTERNAL_FLASH_EXPOSURE_COMP,
      ),
    );
  }
  // 26: ExternalFlashBounce (hash).
  if let Some(v) = b(26) {
    push(
      out,
      "ExternalFlashBounce",
      hash(print_conv, i64::from(v), printconv::EXTERNAL_FLASH_BOUNCE),
    );
  }
}

/// `ExternalFlashGuideNumber` ValueConv (`Pentax.pm:4653-4657`):
///
/// ```text
/// return 0 unless $val;
/// $val = -3 if $val == 29;   # -3 is stored as 0x1d
/// return 2**($val/16 + 4);
/// ```
fn external_flash_guide_number(raw: i64) -> f64 {
  if raw == 0 {
    return 0.0;
  }
  let v = if raw == 29 { -3.0 } else { raw as f64 };
  2.0_f64.powf(v / 16.0 + 4.0)
}

/// `($val & mask) >> bitShift`, `bitShift` = the mask's trailing-zero-bit count
/// (`ExifTool.pm:5916-5919`, `:10079`).
#[inline]
fn mask(val: i64, mask: i64) -> i64 {
  (val & mask) >> mask.trailing_zeros()
}

/// A direct-key PrintConv hash with a decimal `Unknown (N)` fallback. `-n` ⇒
/// the raw integer. Faithful to `ExifTool.pm:3603-3624` (direct key, then
/// `Unknown ($val)`); a hash value that looks numeric (`"0.3"`) is rendered as a
/// JSON number by the serializer's `EscapeJSON` gate.
fn hash(print_conv: bool, n: i64, table: &[(i64, &'static str)]) -> TagValue {
  if !print_conv {
    return TagValue::I64(n);
  }
  match get(table, n) {
    Some(l) => TagValue::Str(SmolStr::from(l)),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({n})"))),
  }
}

/// As [`hash`] but with the `PrintHex => 1` hex fallback `Unknown (0xNN)`
/// (`ExifTool.pm:3617-3620`).
fn hash_hex(print_conv: bool, n: i64, table: &[(i64, &'static str)]) -> TagValue {
  if !print_conv {
    return TagValue::I64(n);
  }
  match get(table, n) {
    Some(l) => TagValue::Str(SmolStr::from(l)),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown (0x{n:x})"))),
  }
}

/// A `{ 0 => zero_label, BITMASK => { …bits… } }` PrintConv
/// (`ExifTool.pm:3603-3624`): the explicit direct `0` key wins (so a zero value
/// renders `zero_label`), otherwise the `DecodeBits` BITMASK walk over the SAME
/// masked value (the Perl `else` after the BITMASK branch skips OTHER/Unknown).
/// `-n` ⇒ the raw integer. None of these Pentax tables list a NON-zero direct
/// key, so a non-zero value always takes the `DecodeBits` path.
fn bitmask0(
  print_conv: bool,
  n: i64,
  zero_label: &'static str,
  bits: &[(u8, &'static str)],
) -> TagValue {
  if !print_conv {
    return TagValue::I64(n);
  }
  if n == 0 {
    return TagValue::Str(SmolStr::new_static(zero_label));
  }
  // `DecodeBits($val, \%bits, 32)` — the default `BitsPerWord` is 32.
  TagValue::Str(SmolStr::from(crate::convert::decode_bits(
    &n.to_string(),
    Some(bits),
    32,
  )))
}

/// Binary-search a sorted `(key, label)` hash.
fn get(table: &[(i64, &'static str)], key: i64) -> Option<&'static str> {
  match table.binary_search_by_key(&key, |&(k, _)| k) {
    Ok(i) => table.get(i).map(|&(_, v)| v),
    Err(_) => None,
  }
}

#[cfg(test)]
mod tests;
