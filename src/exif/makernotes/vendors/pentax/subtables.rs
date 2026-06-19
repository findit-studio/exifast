// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Pentax binary `ProcessBinaryData` SubDirectory tables — Phase 2a/2b/2c (#262).
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
//! - `%Pentax::LensInfo2` (`0x0207`, `Pentax.pm:4240-4271`) —
//!   `ProcessBinaryData` / `BigEndian` (Phase 2b). Selected by the Main-row
//!   `Condition => '$count != 90 and $count != 91 and $count != 80 and
//!   $count != 128 and $count != 168'` (`Pentax.pm:2847`). Its offset-4
//!   `LensData` `undef[17]` is a NESTED `%Pentax::LensData` SubDirectory
//!   (`Pentax.pm:4385-4577`); [`emit_lens_info`] slices that 17-byte span and
//!   emits the five non-`%lensCode` lens-detail leaves (LensFStops,
//!   MinFocusDistance, LensFocalLength, NominalMaxAperture, NominalMinAperture).
//!   The LensInfo2-offset-0 `LensType` is NOT re-emitted (Phase 1's `0x003f
//!   LensRec` owns it).
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

/// Decode the nested `%Pentax::LensData` (`Pentax.pm:4385-4577`) leaves from a
/// `%Pentax::LensInfo2` (`0x0207`) record for the K10D variant
/// (`Pentax.pm:4240-4271`). `block` is the verbatim on-disk `LensInfo2` record
/// (`LensType` `int8u[4]` at offset 0, then `LensData` `undef[17]` at offset 4);
/// `count` is the IFD entry COUNT (the value the `0x0207` SubDirectory-list
/// `Condition` selects on); `model` is the parent `$$self{Model}`.
///
/// ## Scope-fence (the load-bearing correctness point)
///
/// The Main-row `Condition => '$count != 90 and $count != 91 and $count != 80
/// and $count != 128 and $count != 168'` (`Pentax.pm:2847`) selects `LensInfo2`.
/// A `count` in `{90,91,80,128,168}` is a DIFFERENT model's `LensInfo3` (645D),
/// `LensInfo4` (K-r/K-5/K-5II), `LensInfo5` (K-01/K-30/…) or the Ricoh GR III
/// layout — those are deferred, so this emitter emits NOTHING for such a record
/// (never a bogus decode through the K10D `LensData` offsets). The *ist /
/// Samsung GX-1 old-`LensInfo` (`Pentax.pm:2825-2833`, table `LensInfo`) is a
/// distinct earlier layout also deferred; ExifTool tests it FIRST — before the
/// `$count` condition — via a Model+byte-20 regex, so this emitter mirrors that
/// order with the old-`LensInfo` gate at the top of the body, which returns zero
/// emissions for an *ist / GX-1[LS] (or an old-format K100D/K110D) record. The
/// K10D (which fails that regex) falls through to the `$count` test and decodes.
///
/// ## `LensType` is NOT re-emitted
///
/// `LensInfo2` offset 0-3 is `LensType` (`Pentax.pm:4245`), but Phase 1 already
/// emits `LensType` via the `0x003f LensRec` SubDirectory. This emitter reads
/// ONLY the offset-4 `LensData` slice, so `LensType` stays owned by `0x003f`
/// (byte-identical) and is never doubled.
///
/// ## Nested-slice approach
///
/// `LensData` is `Format => 'undef[17]'` at LensInfo2 offset 4
/// (`Pentax.pm:4267-4270`), i.e. the 17-byte span `block[4..21]`. The five
/// leaves are read at offsets RELATIVE to that slice start, mirroring the
/// fixed-block-slice pattern of [`emit_camera_settings`] / [`emit_aeinfo`] —
/// each read is bounds-checked, so a truncated record skips the out-of-range
/// leaves (no panic), matching `ProcessBinaryData`'s `last if $entry >= $size`.
pub(crate) fn emit_lens_info(
  block: &[u8],
  count: usize,
  model: Option<&str>,
  print_conv: bool,
  out: &mut std::vec::Vec<VendorEmission>,
) {
  // The old-`LensInfo` (`%Pentax::LensInfo`) variant gate, which ExifTool tests
  // FIRST — BEFORE the `LensInfo2` `$count` condition (`Pentax.pm:2825-2833`):
  //
  //   Condition => q{
  //       $$self{Model}=~/(\*ist|GX-1[LS])/ or
  //      ($$self{Model}=~/(K100D|K110D)/ and $$valPt=~/^.{20}(\xff|\0\0)/s)
  //   }
  //
  // The `*ist` series and the Samsung `GX-1[LS]` ALWAYS use the old format; the
  // `K100D`/`K110D`/`K100D Super` use it only when byte 20 of the record is `0xff`
  // or bytes 20..22 are `00 00` (the old-vs-new marker). The old `%Pentax::LensInfo`
  // table (`LensData` at offset 3, a distinct earlier layout) is DEFERRED, so —
  // mirroring ExifTool's ordered variant list — when this condition matches we emit
  // NOTHING here (the scope-fence) rather than misdecoding through the offset-4
  // `LensInfo2` `LensData`. `$$valPt` is the verbatim record (`block`); the
  // `/^.{20}.../s` regex simply fails to match on a record shorter than 21/22 bytes
  // (byte 20/21 absent ⇒ NOT old-format), so a short block falls through to the
  // `$count` test below — hence the bounds-checked `block.get` reads.
  if let Some(m) = model {
    let ist_or_gx1 = m.contains("*ist") || m.contains("GX-1L") || m.contains("GX-1S");
    let k100_k110_old = (m.contains("K100D") || m.contains("K110D"))
      && (block.get(20) == Some(&0xff)
        || (block.get(20) == Some(&0x00) && block.get(21) == Some(&0x00)));
    if ist_or_gx1 || k100_k110_old {
      return;
    }
  }
  // The K10D `LensInfo2` variant gate (`Pentax.pm:2847`): a `$count` in
  // `{90,91,80,128,168}` is a deferred `LensInfo3`/`4`/`5`/Ricoh-GR-III layout ⇒
  // emit nothing.
  if matches!(count, 90 | 91 | 80 | 128 | 168) {
    return;
  }
  // `LensData` = `Format => 'undef[17]'` at LensInfo2 offset 4 — the 17-byte span
  // `block[4..21]`. A record too short for the full slice falls back to whatever
  // tail begins at offset 4 (ExifTool extracts a SHORT `undef` value when fewer
  // bytes remain, then `ProcessBinaryData` reads each leaf with `last if $entry
  // >= $size`); a record shorter than offset 4 itself yields `&[]` ⇒ no leaf
  // emits. Every per-leaf read below is additionally bounds-checked.
  let lens_data: &[u8] = block.get(4..21).or_else(|| block.get(4..)).unwrap_or(&[]);
  let b = |i: usize| lens_data.get(i).copied();

  // 0.3: LensFStops — `Mask => 0x70` (>>4); `Condition => 'not $$self{NewLensData}'`
  // (`Pentax.pm:4415-4421`). The K10D `LensInfo2` uses the OLD 17-byte `LensData`
  // (the `NewLensData = 1` flag is set only by the size-18 `LensInfo4` path,
  // `Pentax.pm:4340-4344`), so `NewLensData` is structurally FALSE here and the
  // leaf emits. `ValueConv => '5 + ($val ^ 0x07) / 2'`; there is NO PrintConv, so
  // BOTH `-j` and `-n` emit the raw ValueConv `f64` — the serializer's number gate
  // renders an integral float without a trailing `.0` (`6.0` → `6`, matching
  // ExifTool's JSON number formatting), while a fractional value keeps its
  // decimals (`8.5`). (Contrast NominalMax/MinAperture below, which DO carry an
  // `sprintf` PrintConv and so emit a formatted STRING under `-j`.)
  if let Some(v) = b(0) {
    let raw = mask(i64::from(v), 0x70);
    let f = 5.0 + ((raw ^ 0x07) as f64) / 2.0;
    push(out, "LensFStops", TagValue::F64(f));
  }
  // 0.1: AutoAperture — `Mask => 0x01`; `Condition => 'not $$self{NewLensData}'`
  // (`Pentax.pm:4395-4400`). The K10D uses the OLD 17-byte `LensData`
  // (`NewLensData` structurally false here), so the leaf emits. Direct hash
  // `{ 0 => 'On', 1 => 'Off' }`.
  if let Some(v) = b(0) {
    let raw = mask(i64::from(v), 0x01);
    push(
      out,
      "AutoAperture",
      hash(print_conv, raw, printconv::AUTO_APERTURE),
    );
  }
  // 0.2: MinAperture — `Mask => 0x06` (>>1); `Condition => 'not $$self{NewLensData}'`
  // (`Pentax.pm:4402-4412`). Direct hash (`{ 0 => 22, 1 => 32, 2 => 45, 3 => 16 }`,
  // numeric-string labels render as JSON numbers).
  if let Some(v) = b(0) {
    let raw = mask(i64::from(v), 0x06);
    push(
      out,
      "MinAperture",
      hash(print_conv, raw, printconv::LENS_MIN_APERTURE),
    );
  }
  // 3: MinFocusDistance — `Mask => 0xf8` (>>3); PrintConv HASH (the masked code →
  // a range string), `-n` ⇒ the raw masked value (`Pentax.pm:4434-4467`).
  if let Some(v) = b(3) {
    let raw = mask(i64::from(v), 0xf8);
    push(
      out,
      "MinFocusDistance",
      hash(print_conv, raw, printconv::MIN_FOCUS_DISTANCE),
    );
  }
  // 3.1: FocusRangeIndex — `Mask => 0x07`; direct hash (`Pentax.pm:4469-4482`).
  if let Some(v) = b(3) {
    let raw = mask(i64::from(v), 0x07);
    push(
      out,
      "FocusRangeIndex",
      hash(print_conv, raw, printconv::FOCUS_RANGE_INDEX),
    );
  }
  // 9: LensFocalLength — `Condition => '$$self{Model} !~ /645Z/'`
  // (`Pentax.pm:4475-4486`); the K10D is not a 645Z, so the leaf emits.
  // `ValueConv => '10*($val>>2) * 4**(($val&0x03)-2)'`; PrintConv
  // `sprintf("%.1f mm", $val)`. `-n` ⇒ the raw ValueConv f64.
  if let Some(v) = b(9) {
    if model.is_none_or(|m| !m.contains("645Z")) {
      let raw = i64::from(v);
      let f = 10.0 * ((raw >> 2) as f64) * 4.0_f64.powi(((raw & 0x03) - 2) as i32);
      // `%Pentax::LensData` `LensFocalLength` (pos 9) is `Priority => 0`
      // (`Pentax.pm:4506`): a duplicate never overrides an earlier same-`(doc,
      // family1, name)` tag (`ExifTool.pm:9544-9560`).
      out.push(VendorEmission::new_with_priority(
        SmolStr::new_static("LensFocalLength"),
        if print_conv {
          TagValue::Str(SmolStr::from(std::format!("{f:.1} mm")))
        } else {
          TagValue::F64(f)
        },
        false,
        0,
      ));
    }
  }
  // 10: NominalMaxAperture — `Mask => 0xf0` (>>4); `ValueConv => '2**($val/4)'`;
  // PrintConv `sprintf("%.1f", $val)` (`Pentax.pm:4516-4521`).
  if let Some(v) = b(10) {
    let raw = mask(i64::from(v), 0xf0);
    let f = 2.0_f64.powf(raw as f64 / 4.0);
    push(
      out,
      "NominalMaxAperture",
      if print_conv {
        fixed1_print(f)
      } else {
        TagValue::F64(f)
      },
    );
  }
  // 10.1: NominalMinAperture — `Mask => 0x0f`; `ValueConv => '2**(($val+10)/4)'`;
  // PrintConv `sprintf("%.0f", $val)` (`Pentax.pm:4523-4529`).
  if let Some(v) = b(10) {
    let raw = mask(i64::from(v), 0x0f);
    let f = 2.0_f64.powf((raw as f64 + 10.0) / 4.0);
    push(
      out,
      "NominalMinAperture",
      if print_conv {
        TagValue::Str(SmolStr::from(std::format!("{f:.0}")))
      } else {
        TagValue::F64(f)
      },
    );
  }
  // 14.1: MaxAperture — `Mask => 0x7f`; `RawConv => '$val > 1 ? $val : undef'`;
  // `ValueConv => '2**(($val-1)/32)'`; PrintConv `sprintf("%.1f", $val)`
  // (`Pentax.pm:4557-4567`). `Condition => '$$self{Model} ne "K-5"'`
  // (`Pentax.pm:4559`) — the gate is `ne` against the BARE literal `"K-5"`, an
  // EXACT-string compare (NOT a `=~ /K-5/` regex). `$$self{Model}` is the full
  // IFD0 Model (e.g. `"PENTAX K10D"`, `"PENTAX K-5"`) — never the bare `"K-5"`
  // (contrast `Pentax.pm:5148` which keys on the full `"PENTAX K-3 II"`), so a
  // real PENTAX K-5 body (model `"PENTAX K-5"`) STILL passes `ne "K-5"` and
  // emits; the suppression fires only for a model that is exactly `"K-5"`. A
  // faithful 1:1 port must replicate this exact-equality quirk — a substring /
  // regex match here would wrongly suppress the real `"PENTAX K-5"`. The K10D
  // `LensData` is the OLD 17-byte layout (no `NewLensDataHook` +1 shift, which
  // fires only for `NewLensData`), so MaxAperture sits at `LensData` byte 14.
  // The `RawConv` drops a raw value <= 1 (a sentinel meaning "n/a") — then
  // NOTHING is emitted for this leaf.
  if let Some(v) = b(14) {
    let raw = mask(i64::from(v), 0x7f);
    // `raw > 1` is the `RawConv` "n/a" drop; `model != Some("K-5")` is the
    // `Condition => '$$self{Model} ne "K-5"'` exact-equality gate. Both must
    // hold for the single emission.
    if raw > 1 && model != Some("K-5") {
      let f = 2.0_f64.powf((raw as f64 - 1.0) / 32.0);
      push(
        out,
        "MaxAperture",
        if print_conv {
          fixed1_print(f)
        } else {
          TagValue::F64(f)
        },
      );
    }
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

/// Read a BigEndian `int32u` at byte offset `at` in `block`, or `None` when the
/// 4-byte field is out of range. `%Pentax::CameraInfo` is read in the inherited
/// MakerNote (BigEndian) order — confirmed by `exiftool -v3` (the `0x0215`
/// BinaryData directory is "Big-endian" for both the K10D `Pentax.jpg` and the
/// K-x `Pentax.avi`, even though the AVI's other Pentax binary directories are
/// LittleEndian) — matching the hardcoded-BigEndian reads in the sibling
/// `CameraSettings`/`AEInfo` decoders.
#[inline]
fn be_u32(block: &[u8], at: usize) -> Option<u32> {
  let end = at.checked_add(4)?;
  match block.get(at..end) {
    Some(&[a, b, c, d]) => Some(u32::from_be_bytes([a, b, c, d])),
    _ => None,
  }
}

/// `%Pentax::CameraInfo` `1 ManufactureDate` ValueConv (`Pentax.pm:4735-4740`):
///
/// ```text
/// $val =~ /^(\d{4})(\d{2})(\d{2})$/ and return "$1:$2:$3";
/// # Optio A10 and A20 leave "200" off the year
/// $val =~ /^(\d)(\d{2})(\d{2})$/ and return "200$1:$2:$3";
/// return "Unknown ($val)";
/// ```
///
/// `$val` is the int32u rendered as a decimal string (no leading zeros), so the
/// `^...$`-anchored regexes match a bare 8-digit (`YYYYMMDD`) or 5-digit
/// (Optio `YMMDD`, year "200" stripped) value. There is NO PrintConv, so the
/// ValueConv result is emitted for BOTH `-j` and `-n`.
fn manufacture_date(raw: u32) -> SmolStr {
  let s = raw.to_string();
  let digits: &[u8] = s.as_bytes();
  // `/^(\d{4})(\d{2})(\d{2})$/` — exactly 8 digits ⇒ `YYYY:MM:DD`.
  if digits.len() == 8 {
    if let (Some(y), Some(m), Some(d)) = (s.get(0..4), s.get(4..6), s.get(6..8)) {
      return SmolStr::from(std::format!("{y}:{m}:{d}"));
    }
  }
  // `/^(\d)(\d{2})(\d{2})$/` — exactly 5 digits ⇒ `200Y:MM:DD`.
  if digits.len() == 5 {
    if let (Some(y), Some(m), Some(d)) = (s.get(0..1), s.get(1..3), s.get(3..5)) {
      return SmolStr::from(std::format!("200{y}:{m}:{d}"));
    }
  }
  SmolStr::from(std::format!("Unknown ({s})"))
}

/// Decode `%Pentax::CameraInfo` (`0x0215`, `Pentax.pm:4717-4754`) — a fixed
/// `int32u` (`FORMAT => 'int32u'`) binary record read in BigEndian order. The
/// Main row (`Pentax.pm:2940`) is UNCONDITIONAL (no `Condition` / `$count` gate,
/// no model variant), so — unlike the `$count`-gated `CameraSettings`/`AEInfo`/
/// `LensInfo2`/`FlashInfo` decoders — there is no scope-fence; every Pentax body
/// reaches it.
///
/// Emits ONLY the three serviceable-data scalars: offset 1 (byte 4)
/// `ManufactureDate`, offset 2 (byte 8) `ProductionCode` (`int32u[2]`, two
/// space-joined int32u → `tr/ /./`), offset 4 (byte 16) `InternalSerialNumber`.
///
/// ## `PentaxModelID` (offset 0) is NOT re-emitted
///
/// `CameraInfo` offset 0 (byte 0) is `PentaxModelID` (`Pentax.pm:4721-4727`), but
/// Phase 1 already emits it from the `0x0005` Main leaf (byte-identical `'K10D'`
/// for `Pentax.jpg`). This emitter SKIPS offset 0 entirely so `PentaxModelID`
/// stays a single entry owned by `0x0005` (the same discipline as the Phase-2b
/// `LensType` guardrail, where `0x003f` owns the leaf and `0x0207` does not
/// double it).
///
/// ## Bounds-checking
///
/// Each int32u read is bounds-checked ([`be_u32`] returns `None` past the block
/// end): a short / truncated `CameraInfo` emits only the in-range scalars and
/// never panics, matching `ProcessBinaryData` reading whatever the record holds
/// (`last if $entry >= $size`). `ProductionCode` (`int32u[2]`) needs BOTH 4-byte
/// elements present, so a record reaching byte 8 but not byte 16 emits no
/// `ProductionCode`.
pub(crate) fn emit_camera_info(
  block: &[u8],
  print_conv: bool,
  out: &mut std::vec::Vec<VendorEmission>,
) {
  // offset 0 (byte 0): PentaxModelID — NOT emitted (owned by the 0x0005 leaf).

  // offset 1 (byte 4): ManufactureDate (int32u). ValueConv only (no PrintConv) ⇒
  // the same value for -j and -n.
  if let Some(v) = be_u32(block, 4) {
    push(out, "ManufactureDate", TagValue::Str(manufacture_date(v)));
  }
  // offset 2 (byte 8): ProductionCode (int32u[2]) — the default multi-element
  // ValueConv space-joins the two int32u, then `tr/ /./` (`Pentax.pm:4748`). The
  // PrintConv (`Pentax.pm:4750`) appends " (camera has been serviced)" when the
  // value starts with "8."; otherwise it is the bare dotted string (rendered as a
  // JSON number by the serializer's number gate, e.g. "2.1" → 2.1). Both int32u
  // elements must be present (byte 8 and byte 12).
  if let (Some(a), Some(b)) = (be_u32(block, 8), be_u32(block, 12)) {
    let dotted = std::format!("{a}.{b}");
    let value = if print_conv && dotted.starts_with("8.") {
      std::format!("{dotted} (camera has been serviced)")
    } else {
      dotted
    };
    push(out, "ProductionCode", TagValue::Str(SmolStr::from(value)));
  }
  // offset 4 (byte 16): InternalSerialNumber (int32u) — no conv (direct). The
  // int32u value is emitted as an integer for both -j and -n.
  if let Some(v) = be_u32(block, 16) {
    push(out, "InternalSerialNumber", int_value(i64::from(v)));
  }
}

/// Decode `%Pentax::SRInfo` (`0x005c`) for the `$count == 4` variant
/// (`Pentax.pm:3172-3228`). A `count != 4` entry (the 2-byte K-3 `SRInfo2`
/// variant) emits NOTHING (the scope-fence). `block` is the verbatim 4-byte
/// on-disk record; `count` is the IFD entry COUNT; `print_conv` selects `-j`/`-n`.
pub(crate) fn emit_sr_info(
  block: &[u8],
  count: usize,
  print_conv: bool,
  out: &mut std::vec::Vec<VendorEmission>,
) {
  // `Condition => '$count == 4'` (`Pentax.pm:2260`) — the SRInfo (vs SRInfo2)
  // variant gate.
  if count != 4 {
    return;
  }
  let b = |i: usize| block.get(i).copied();

  // 0: SRResult — `{ 0 => 'Not stabilized', BITMASK => { 0 => 'Stabilized',
  // 6 => 'Not ready' } }`.
  if let Some(v) = b(0) {
    push(
      out,
      "SRResult",
      bitmask0(
        print_conv,
        i64::from(v),
        "Not stabilized",
        printconv::SR_RESULT_BITS,
      ),
    );
  }
  // 1: ShakeReduction — direct hash.
  if let Some(v) = b(1) {
    push(
      out,
      "ShakeReduction",
      hash(print_conv, i64::from(v), printconv::SHAKE_REDUCTION),
    );
  }
  // 2: SRHalfPressTime — `$val / 60`; PrintConv `sprintf("%.2f s", $val) .
  // ($val > 254.5/60 ? " or longer" : "")`.
  if let Some(v) = b(2) {
    let secs = f64::from(v) / 60.0;
    push(
      out,
      "SRHalfPressTime",
      if print_conv {
        let mut t = std::format!("{secs:.2} s");
        if secs > 254.5 / 60.0 {
          t.push_str(" or longer");
        }
        TagValue::Str(SmolStr::from(t))
      } else {
        TagValue::F64(secs)
      },
    );
  }
  // 3: SRFocalLength — `$val & 0x01 ? $val * 4 : $val / 2`; PrintConv `"$val mm"`.
  if let Some(v) = b(3) {
    let n = i64::from(v);
    let fl = if n & 0x01 != 0 {
      (n * 4) as f64
    } else {
      n as f64 / 2.0
    };
    push(
      out,
      "SRFocalLength",
      if print_conv {
        TagValue::Str(SmolStr::from(std::format!(
          "{} mm",
          crate::value::format_g(fl, 15)
        )))
      } else {
        TagValue::F64(fl)
      },
    );
  }
}

/// `sprintf("%d (%.1fV, %d%%)", $val, $val*8.18/186, ($val-empty)*100/range)` —
/// the shared K10D `BodyBatteryADNoLoad` / `BodyBatteryADLoad` PrintConv
/// (`Pentax.pm:4854`/`:4898`, differing only in the empty/range constants).
/// `int(...)` truncates toward zero for the `%d` percent field.
fn battery_ad_print(val: i64, empty: f64, range: f64) -> SmolStr {
  let volts = val as f64 * 8.18 / 186.0;
  let pct = ((val as f64 - empty) * 100.0 / range).trunc() as i64;
  SmolStr::from(std::format!("{val} ({volts:.1}V, {pct}%)"))
}

/// Decode `%Pentax::BatteryInfo` (`0x0216`, `Pentax.pm:4757-4989`) — a BigEndian
/// `ProcessBinaryData` record. The Main `0x0216` row is UNCONDITIONAL (no
/// `$count` gate), but EVERY leaf is `$$self{Model}`-gated and several offsets
/// hold an ENTIRELY DIFFERENT tag/format per model (offset 2 is the K10D-family
/// `BodyBatteryADNoLoad` int8u byte but the K-x/K-5/K-r/K-3 etc.
/// `BodyBatteryVoltage1` int16u; offset 4 likewise `GripBatteryADNoLoad` vs
/// `BodyBatteryVoltage2`; the K-3 Mark III re-lays the whole record). So each
/// leaf is emitted ONLY for the exact `$$self{Model}` regex its ExifTool
/// variant carries; any other model emits NOTHING at that offset — never the
/// K10D byte-layout reinterpreted as a foreign model's int16u voltage (the
/// scope-fence). The non-K10D-fixtured voltage/percent variants are DEFERRED
/// (see the #173 follow-up issue).
///
/// `block` is the verbatim on-disk record; `model` is the parent
/// `$$self{Model}`; `print_conv` selects `-j`/`-n`. The K10D `BatteryInfo` is 6
/// bytes (offsets 0-5); the K-3III/K-5/K-r-only offsets 6/8/16/17/18 are out of
/// range AND model-gated out, so they never emit. The default element format is
/// `int8u`; the K10D leaves are all single bytes.
pub(crate) fn emit_battery_info(
  block: &[u8],
  model: Option<&str>,
  print_conv: bool,
  out: &mut std::vec::Vec<VendorEmission>,
) {
  // The exact `$$self{Model}` regexes from the BatteryInfo table, per offset.
  let is_k3iii = is_k3_mark_iii(model);
  let body_state_k10d = is_body_state_k10d(model); // offset 1.1 variant A
  let grip_state_k10d = is_grip_state_k10d(model); // offset 1.2
  let body_ad_pc = is_body_ad_printconv(model); // offset 2/3 PrintConv variant (A)
  let body_ad_noload_raw = is_body_ad_noload_raw(model); // offset 2 raw variant (B)
  let body_ad_load_raw = is_body_ad_load_raw(model); // offset 3 raw variant (B)
  let grip_ad_noload = is_grip_ad_noload(model); // offset 4
  let grip_ad_load = is_grip_ad_load(model); // offset 5
  let b = |i: usize| block.get(i).copied();

  // 0.1: PowerSource (mask 0x0f) — `Condition => '$$self{Model} !~ /K-3 Mark
  // III/'` (`Pentax.pm:4767-4779`). The K-3III variant (a DIFFERENT 3-entry
  // hash) + the K-3III-only `0.2 PowerAvailable` are DEFERRED ⇒ for a K-3III the
  // leaf emits nothing here.
  if !is_k3iii {
    if let Some(v) = b(0) {
      push(
        out,
        "PowerSource",
        hash(
          print_conv,
          mask(i64::from(v), 0x0f),
          printconv::POWER_SOURCE,
        ),
      );
    }
  }
  // 1.1: BodyBatteryState (mask 0xf0) — variant A
  // `/(\*ist|K100D|K200D|K10D|GX10|K20D|GX20|GX-1[LS]?)\b/` (the 4-entry hash,
  // `Pentax.pm:4806-4815`); the K10D matches this FIRST arm. Variant B (the
  // 5-entry 'Close to Full' hash for most other models) is DEFERRED, so a
  // model matching only variant B emits nothing here (never variant A's labels).
  if body_state_k10d {
    if let Some(v) = b(1) {
      push(
        out,
        "BodyBatteryState",
        hash(
          print_conv,
          mask(i64::from(v), 0xf0),
          printconv::BODY_BATTERY_STATE_K10D,
        ),
      );
    }
  }
  // 1.2: GripBatteryState (mask 0x0f) — `/(K10D|GX10|K20D|GX20)\b/` only
  // (`Pentax.pm:4833`).
  if grip_state_k10d {
    if let Some(v) = b(1) {
      push(
        out,
        "GripBatteryState",
        hash(
          print_conv,
          mask(i64::from(v), 0x0f),
          printconv::GRIP_BATTERY_STATE_K10D,
        ),
      );
    }
  }
  // 2: BodyBatteryADNoLoad — variant A `/(K10D|GX10|K20D|GX20)\b/` (the int8u
  // byte WITH the `%d (%.1fV, %d%%)` PrintConv, `Pentax.pm:4848-4856`); variant
  // B `/(\*ist|K100D|K200D|GX-1[LS]?)\b/` (the same byte, NO PrintConv ⇒ raw).
  // For any OTHER model offset 2 is `BodyBatteryVoltage1` (int16u, `$val/100`)
  // or the K-3III `BodyBatteryState` — a DIFFERENT tag/format, DEFERRED ⇒ emit
  // nothing here (never the byte mis-read).
  if let Some(v) = b(2) {
    let n = i64::from(v);
    if body_ad_pc {
      push(
        out,
        "BodyBatteryADNoLoad",
        if print_conv {
          TagValue::Str(battery_ad_print(n, 155.0, 35.0))
        } else {
          int_value(n)
        },
      );
    } else if body_ad_noload_raw {
      push(out, "BodyBatteryADNoLoad", int_value(n));
    }
  }
  // 3: BodyBatteryADLoad — variant A `/(K10D|GX10|K20D|GX20)\b/` (PrintConv,
  // `Pentax.pm:4893-4899`); variant B `/(\*ist|K100D|K200D)\b/` (raw). Other
  // models: `BodyBatteryPercent` (K-3III) or nothing — DEFERRED.
  if let Some(v) = b(3) {
    let n = i64::from(v);
    if body_ad_pc {
      push(
        out,
        "BodyBatteryADLoad",
        if print_conv {
          TagValue::Str(battery_ad_print(n, 152.0, 34.0))
        } else {
          int_value(n)
        },
      );
    } else if body_ad_load_raw {
      push(out, "BodyBatteryADLoad", int_value(n));
    }
  }
  // 4: GripBatteryADNoLoad — `/(\*ist|K10D|GX10|K20D|GX20|GX-1[LS]?)\b/` (no
  // PrintConv ⇒ raw int, `Pentax.pm:4913-4916`). Other models: `BodyBatteryVoltage2`
  // (int16u) / `BodyBatteryVoltage` (K-3III int32u) — DEFERRED.
  if grip_ad_noload {
    if let Some(v) = b(4) {
      push(out, "GripBatteryADNoLoad", int_value(i64::from(v)));
    }
  }
  // 5: GripBatteryADLoad — `/(\*ist|K10D|GX10|K20D|GX20)\b/` (no PrintConv,
  // `Pentax.pm:4936-4940`).
  if grip_ad_load {
    if let Some(v) = b(5) {
      push(out, "GripBatteryADLoad", int_value(i64::from(v)));
    }
  }
}

/// `true` when `model` matches `/K-3 Mark III/` (a plain substring — ExifTool's
/// regex has no anchor/`\b`) — the gate that DESELECTS every non-K-3III
/// BatteryInfo variant and SELECTS the deferred K-3III re-layout.
fn is_k3_mark_iii(model: Option<&str>) -> bool {
  model.is_some_and(|m| m.contains("K-3 Mark III"))
}

/// `true` for the BatteryInfo `1.1 BodyBatteryState` variant A
/// `/(\*ist|K100D|K200D|K10D|GX10|K20D|GX20|GX-1[LS]?)\b/` (`Pentax.pm:4807`).
fn is_body_state_k10d(model: Option<&str>) -> bool {
  model_matches_any(
    model,
    &[
      "*ist", "K100D", "K200D", "K10D", "GX10", "K20D", "GX20", "GX-1L", "GX-1S", "GX-1",
    ],
  )
}

/// `true` for the BatteryInfo `1.2 GripBatteryState` / `2`/`3`
/// `BodyBatteryAD*` PrintConv variant model regex `/(K10D|GX10|K20D|GX20)\b/`
/// (`Pentax.pm:4833`/`:4850`/`:4895`).
fn is_grip_state_k10d(model: Option<&str>) -> bool {
  model_matches_any(model, &["K10D", "GX10", "K20D", "GX20"])
}

/// `true` for the BatteryInfo `2`/`3` `BodyBatteryADNoLoad`/`ADLoad` PrintConv
/// variant (A) `/(K10D|GX10|K20D|GX20)\b/`.
fn is_body_ad_printconv(model: Option<&str>) -> bool {
  model_matches_any(model, &["K10D", "GX10", "K20D", "GX20"])
}

/// `true` for the BatteryInfo `2 BodyBatteryADNoLoad` raw variant (B)
/// `/(\*ist|K100D|K200D|GX-1[LS]?)\b/` (`Pentax.pm:4860`).
fn is_body_ad_noload_raw(model: Option<&str>) -> bool {
  model_matches_any(model, &["*ist", "K100D", "K200D", "GX-1L", "GX-1S", "GX-1"])
}

/// `true` for the BatteryInfo `3 BodyBatteryADLoad` raw variant (B)
/// `/(\*ist|K100D|K200D)\b/` (`Pentax.pm:4904`).
fn is_body_ad_load_raw(model: Option<&str>) -> bool {
  model_matches_any(model, &["*ist", "K100D", "K200D"])
}

/// `true` for the BatteryInfo `4 GripBatteryADNoLoad`
/// `/(\*ist|K10D|GX10|K20D|GX20|GX-1[LS]?)\b/` (`Pentax.pm:4915`).
fn is_grip_ad_noload(model: Option<&str>) -> bool {
  model_matches_any(
    model,
    &[
      "*ist", "K10D", "GX10", "K20D", "GX20", "GX-1L", "GX-1S", "GX-1",
    ],
  )
}

/// `true` for the BatteryInfo `5 GripBatteryADLoad`
/// `/(\*ist|K10D|GX10|K20D|GX20)\b/` (`Pentax.pm:4938`).
fn is_grip_ad_load(model: Option<&str>) -> bool {
  model_matches_any(model, &["*ist", "K10D", "GX10", "K20D", "GX20"])
}

/// `true` when `model` contains any of `needles` followed by a `\b` word
/// boundary (Perl `\b` after the token; the model strings are ASCII). The `*ist`
/// token has no trailing word char in practice, so a plain substring suffices
/// for it; for the alphanumeric body tokens the trailing-boundary check avoids a
/// false `K10D` match inside e.g. `K10DX` (no such model exists, but faithful).
fn model_matches_any(model: Option<&str>, needles: &[&str]) -> bool {
  let Some(m) = model else {
    return false;
  };
  for &needle in needles {
    let mut from = 0;
    while let Some(rel) = m.get(from..).and_then(|sub| sub.find(needle)) {
      let start = from + rel;
      let end = start + needle.len();
      let boundary_ok = m
        .get(end..)
        .and_then(|sub| sub.chars().next())
        .is_none_or(|c| !is_word_char(c));
      if boundary_ok {
        return true;
      }
      from = end;
    }
  }
  false
}

/// Read a BigEndian `int16u` at byte offset `at` in `block`, or `None` past the
/// end. `%Pentax::AFInfo` declares `ByteOrder => 'BigEndian'`
/// (`Pentax.pm:2987`).
#[inline]
fn be_i16(block: &[u8], at: usize) -> Option<i16> {
  let end = at.checked_add(2)?;
  match block.get(at..end) {
    Some(&[a, b]) => Some(i16::from_be_bytes([a, b])),
    _ => None,
  }
}

/// Decode `%Pentax::AFInfo` (`0x021f`, `Pentax.pm:4992-...`) — a BigEndian
/// `ProcessBinaryData` record. The Main `0x021f` row is UNCONDITIONAL, but the
/// `0x0b AFPointsInFocus` leaf is `$$self{Model}`-gated. Emits AFPredictor
/// (int16s @ 4), AFDefocus (int8u @ 6), AFIntegrationTime (@ 7) and — only for
/// the `/(K-(1|3|70|S1|S2)|KP)\b/`-EXCLUDING models — AFPointsInFocus (@ 11).
/// The two `Unknown => 1` AFPointsUnknown1/2 (int16u @ 0/2) are suppressed
/// without `-U`; the K-3III-only leaves (offsets 0x14+) are model-gated out.
/// `model` is the parent `$$self{Model}`.
pub(crate) fn emit_af_info(
  block: &[u8],
  model: Option<&str>,
  print_conv: bool,
  out: &mut std::vec::Vec<VendorEmission>,
) {
  let b = |i: usize| block.get(i).copied();

  // 0x00 AFPointsUnknown1 / 0x02 AFPointsUnknown2 — `Unknown => 1` (suppressed).
  // 0x04: AFPredictor — int16s (BigEndian), no conv.
  if let Some(n) = be_i16(block, 4) {
    push(out, "AFPredictor", int_value(i64::from(n)));
  }
  // 0x06: AFDefocus — int8u, no conv.
  if let Some(v) = b(6) {
    push(out, "AFDefocus", int_value(i64::from(v)));
  }
  // 0x07: AFIntegrationTime — `$val * 2`; PrintConv `"$val ms"`.
  if let Some(v) = b(7) {
    let n = i64::from(v) * 2;
    push(
      out,
      "AFIntegrationTime",
      if print_conv {
        TagValue::Str(SmolStr::from(std::format!("{n} ms")))
      } else {
        int_value(n)
      },
    );
  }
  // 0x0b: AFPointsInFocus — `Condition => '$$self{Model} !~ /(K-(1|3|70|S1|S2)|KP)\b/'`
  // (`Pentax.pm:5070`). The K-1/K-3/K-70/KP/K-S1/S2 models have NO `0x0b`
  // definition that matches ⇒ ExifTool emits nothing there; the K10D matches the
  // EXCLUDING gate, so it emits the 21-entry hash. Suppressing for the excluded
  // models avoids flattening this hash onto a record that has no such tag.
  if !is_af_points_in_focus_excluded(model) {
    if let Some(v) = b(11) {
      push(
        out,
        "AFPointsInFocus",
        hash(print_conv, i64::from(v), printconv::AF_POINTS_IN_FOCUS),
      );
    }
  }
}

/// `true` when `model` matches the AFPointsInFocus EXCLUSION regex
/// `/(K-(1|3|70|S1|S2)|KP)\b/` (`Pentax.pm:5070`) — i.e. the K-1, K-3, K-70,
/// K-S1, K-S2 or KP, for which the `0x0b AFPointsInFocus` leaf is NOT defined.
/// `K-3` here also matches `K-3 II` / `K-3 Mark III` via the `\b` after `K-3`
/// (a space is a non-word char), exactly as the Perl regex does.
fn is_af_points_in_focus_excluded(model: Option<&str>) -> bool {
  model_matches_any(model, &["K-1", "K-3", "K-70", "K-S1", "K-S2", "KP"])
}

/// Decode `%Pentax::ColorInfo` (`0x0222`, `Pentax.pm:5258-5270`) — a
/// `ProcessBinaryData` record with `FORMAT => 'int8s'`. UNCONDITIONAL. Emits the
/// two white-balance-shift leaves WBShiftAB (@ 16) and WBShiftGM (@ 17), both
/// signed bytes with no conv.
pub(crate) fn emit_color_info(
  block: &[u8],
  _print_conv: bool,
  out: &mut std::vec::Vec<VendorEmission>,
) {
  // FORMAT => 'int8s' — read each leaf as a signed byte.
  if let Some(v) = block.get(16) {
    push(out, "WBShiftAB", int_value(i64::from(*v as i8)));
  }
  if let Some(v) = block.get(17) {
    push(out, "WBShiftGM", int_value(i64::from(*v as i8)));
  }
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
