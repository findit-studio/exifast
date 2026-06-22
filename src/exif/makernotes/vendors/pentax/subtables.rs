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

use crate::exif::ifd::ByteOrder;
use crate::value::TagValue;
use smol_str::SmolStr;

use super::super::VendorEmission;
use super::printconv;

/// Read an `int16u` at byte offset `at` in `order` byte order, or `None` past the
/// end. Pentax binary sub-tables that declare no explicit `ByteOrder` inherit the
/// parent MakerNote IFD order (the KS-2 parent is Little-endian); the few that
/// declare `ByteOrder => 'BigEndian'` (`CameraSettings`/`BatteryInfo`/`AFInfo`)
/// pass [`ByteOrder::Big`] regardless of the parent.
#[inline]
fn read_u16(block: &[u8], at: usize, order: ByteOrder) -> Option<u16> {
  let end = at.checked_add(2)?;
  match block.get(at..end) {
    Some(&[a, b]) => Some(match order {
      ByteOrder::Little => u16::from_le_bytes([a, b]),
      ByteOrder::Big => u16::from_be_bytes([a, b]),
    }),
    _ => None,
  }
}

/// Read an `int32u` at byte offset `at` in `order` byte order, or `None` past the
/// end.
#[inline]
fn read_u32(block: &[u8], at: usize, order: ByteOrder) -> Option<u32> {
  let end = at.checked_add(4)?;
  match block.get(at..end) {
    Some(&[a, b, c, d]) => Some(match order {
      ByteOrder::Little => u32::from_le_bytes([a, b, c, d]),
      ByteOrder::Big => u32::from_be_bytes([a, b, c, d]),
    }),
    _ => None,
  }
}

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
  emit_lens_data_leaves(lens_data, model, print_conv, out);
}

/// Decode the nested `%Pentax::LensData` (`Pentax.pm:4385-4577`) leaves from a
/// 17-byte `LensData` slice. Shared by [`emit_lens_info`] (`%Pentax::LensInfo2`,
/// `LensData` at offset 4) and [`emit_lens_info5`] (`%Pentax::LensInfo5`,
/// `LensData` at offset 15) — the nested table is identical, only the parent
/// offset differs. The K10D / K-S2 records use the OLD 17-byte `LensData`
/// (`NewLensData` structurally false). Each leaf read is bounds-checked.
fn emit_lens_data_leaves(
  lens_data: &[u8],
  model: Option<&str>,
  print_conv: bool,
  out: &mut std::vec::Vec<VendorEmission>,
) {
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
/// `int32u` (`FORMAT => 'int32u'`) binary record. The `0x0215` Main row declares
/// NO explicit `ByteOrder`, so the record inherits the parent MakerNote IFD order
/// (`order`): BigEndian for the K10D `Pentax.jpg` / K-x `Pentax.avi` (big-endian
/// bodies), but **LittleEndian** for the K-S2 `JPEG_pentax_ks2.jpg` (a
/// little-endian body — `exiftool -v3` shows the `0x0215` BinaryData directory as
/// "Little-endian" there). Reading it BigEndian-hardcoded would mis-decode every
/// scalar for a little-endian body; `order` is threaded from the walked IFD. The
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
/// Each int32u read is bounds-checked ([`read_u32`] returns `None` past the block
/// end): a short / truncated `CameraInfo` emits only the in-range scalars and
/// never panics, matching `ProcessBinaryData` reading whatever the record holds
/// (`last if $entry >= $size`). `ProductionCode` (`int32u[2]`) needs BOTH 4-byte
/// elements present, so a record reaching byte 8 but not byte 16 emits no
/// `ProductionCode`.
pub(crate) fn emit_camera_info(
  block: &[u8],
  order: ByteOrder,
  print_conv: bool,
  out: &mut std::vec::Vec<VendorEmission>,
) {
  // offset 0 (byte 0): PentaxModelID — NOT emitted (owned by the 0x0005 leaf).

  // offset 1 (byte 4): ManufactureDate (int32u). ValueConv only (no PrintConv) ⇒
  // the same value for -j and -n.
  if let Some(v) = read_u32(block, 4, order) {
    push(out, "ManufactureDate", TagValue::Str(manufacture_date(v)));
  }
  // offset 2 (byte 8): ProductionCode (int32u[2]) — the default multi-element
  // ValueConv space-joins the two int32u, then `tr/ /./` (`Pentax.pm:4748`). The
  // PrintConv (`Pentax.pm:4750`) appends " (camera has been serviced)" when the
  // value starts with "8."; otherwise it is the bare dotted string (rendered as a
  // JSON number by the serializer's number gate, e.g. "2.1" → 2.1). Both int32u
  // elements must be present (byte 8 and byte 12).
  if let (Some(a), Some(b)) = (read_u32(block, 8, order), read_u32(block, 12, order)) {
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
  if let Some(v) = read_u32(block, 16, order) {
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
  // offset 1.1 variant B — `$$self{Model} !~ /(K110D|K2000|K-m|K-3 Mark III)\b/`
  // (`Pentax.pm:4817-4827`), the 5-entry 'Close to Full' hash. Tried only when
  // variant A fails (ExifTool's ordered Condition list): the K-S2 fails A and
  // matches B ⇒ value 5 → 'Full'.
  let body_state_other = !body_state_k10d && is_body_state_other(model);
  let grip_state_k10d = is_grip_state_k10d(model); // offset 1.2
  let body_ad_pc = is_body_ad_printconv(model); // offset 2/3 PrintConv variant (A)
  let body_ad_noload_raw = is_body_ad_noload_raw(model); // offset 2 raw variant (B)
  let body_ad_load_raw = is_body_ad_load_raw(model); // offset 3 raw variant (B)
  // offset 2/4 `BodyBatteryVoltage1`/`Voltage2` (int16u, `$val/100`, `%.2f V`) —
  // `/(645D|645Z|K-(1|01|3|5|7|30|50|70|500|r|x|S[12])|KP)\b/ and !~ /III/`
  // (`Pentax.pm:4864`/`:4919`). The K-S2 matches (`K-S2`); these replace the
  // int8u A/D byte reads at the SAME offsets for a voltage-reporting body.
  let body_voltage = is_body_voltage(model);
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
  } else if body_state_other {
    // 1.1 variant B (the 5-entry 'Close to Full' hash). The K-S2 falls here.
    if let Some(v) = b(1) {
      push(
        out,
        "BodyBatteryState",
        hash(
          print_conv,
          mask(i64::from(v), 0xf0),
          printconv::BODY_BATTERY_STATE_OTHER,
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
  if body_voltage {
    // offset 2 `BodyBatteryVoltage1` (int16u, BigEndian — the table's declared
    // order) → `$val / 100`; PrintConv `sprintf("%.2f V", $val)`.
    if let Some(v) = read_u16(block, 2, ByteOrder::Big) {
      push(
        out,
        "BodyBatteryVoltage1",
        battery_voltage(i64::from(v), print_conv),
      );
    }
  } else if let Some(v) = b(2) {
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
  if body_voltage {
    // offset 4 `BodyBatteryVoltage2` (int16u, BigEndian) → `$val / 100`;
    // PrintConv `sprintf("%.2f V", $val)`.
    if let Some(v) = read_u16(block, 4, ByteOrder::Big) {
      push(
        out,
        "BodyBatteryVoltage2",
        battery_voltage(i64::from(v), print_conv),
      );
    }
  } else if grip_ad_noload {
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
/// regex has no anchor/`\b`). The gate that DESELECTS every non-K-3III
/// `BatteryInfo` variant, and the `0x022b` LevelInfo SubDirectory selector
/// (`Pentax.pm:3046`) that routes a K-3III body to `%LevelInfoK3III`
/// ([`emit_level_info_k3iii`]) instead of the K-5-style `%LevelInfo`.
pub(crate) fn is_k3_mark_iii(model: Option<&str>) -> bool {
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

/// `true` for the BatteryInfo `1.1 BodyBatteryState` variant B —
/// `$$self{Model} !~ /(K110D|K2000|K-m|K-3 Mark III)\b/` (`Pentax.pm:4818`), the
/// 5-entry 'Close to Full' hash for "most other models". A NEGATIVE gate: it
/// matches every model EXCEPT those four. The caller already excludes variant A
/// (tried first), so this fires for the K-S2 / K-5 / K-r / etc.
fn is_body_state_other(model: Option<&str>) -> bool {
  !model_matches_any(model, &["K110D", "K2000", "K-m", "K-3 Mark III"])
}

/// `true` for the BatteryInfo `2`/`4` `BodyBatteryVoltage1`/`Voltage2`
/// `/(645D|645Z|K-(1|01|3|5|7|30|50|70|500|r|x|S[12])|KP)\b/ and !~ /III/`
/// (`Pentax.pm:4864`/`:4919`). The K-S2 matches via `K-S2`.
fn is_body_voltage(model: Option<&str>) -> bool {
  let Some(m) = model else {
    return false;
  };
  // The `and $$self{Model} !~ /III/` clause excludes the K-3 Mark III.
  if m.contains("III") {
    return false;
  }
  model_matches_any(
    model,
    &[
      "645D", "645Z", "K-1", "K-01", "K-3", "K-5", "K-7", "K-30", "K-50", "K-70", "K-500", "K-r",
      "K-x", "K-S1", "K-S2", "KP",
    ],
  )
}

/// `BodyBatteryVoltage1`/`Voltage2` value: `$val / 100`; PrintConv
/// `sprintf("%.2f V", $val)` (`Pentax.pm:4866-4869`). `-n` ⇒ the post-ValueConv
/// volts `f64`.
fn battery_voltage(raw: i64, print_conv: bool) -> TagValue {
  let v = raw as f64 / 100.0;
  if print_conv {
    TagValue::Str(SmolStr::from(std::format!("{v:.2} V")))
  } else {
    TagValue::F64(v)
  }
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

/// Decode `%Pentax::AEInfo3` (`0x0206`, `Pentax.pm:4118-4183`) for the
/// `$count == 48 or $count == 64` variant (`Pentax.pm:2812-2815`) — the
/// auto-exposure record for the K-1mkII / K-3 / K-30 / K-50 / **K-S2 (K-S1,K-S2
/// via RawDevelopmentProcess 15)** / K-70 / K-500 / KP. The K-S2 record is 48
/// bytes (`$count == 48`). `%binaryDataAttrs` declares no `FORMAT` ⇒ default
/// `int8u`, `FIRST_ENTRY 0`; the row declares no explicit `ByteOrder` ⇒ inherits
/// the parent MakerNote IFD order (Little-endian for the K-S2), but every AEInfo3
/// leaf is a single `int8u` byte, so the order is immaterial here.
///
/// A `count` outside `{48, 64}` is a deferred AEInfo / AEInfo2 / AEInfoUnknown
/// variant ⇒ emit NOTHING (the scope-fence). The leaves sit at element offsets
/// 16-31 (`AEExposureTime`, `AEAperture`, `AE_ISO`, then `AEMaxAperture`,
/// `AEMaxAperture2`, `AEMinAperture`, `AEMinExposureTime` at 28-31).
pub(crate) fn emit_aeinfo3(
  block: &[u8],
  count: usize,
  print_conv: bool,
  out: &mut std::vec::Vec<VendorEmission>,
) {
  if count != 48 && count != 64 {
    return;
  }
  let b = |i: usize| block.get(i).copied();
  // 16: AEExposureTime — 24*exp(-($val-32)*ln2/8); PrintExposureTime.
  if let Some(v) = b(16) {
    let secs = 24.0 * (-(f64::from(v) - 32.0) * std::f64::consts::LN_2 / 8.0).exp();
    push(out, "AEExposureTime", expo_value(secs, print_conv));
  }
  // 17: AEAperture — exp(($val-68)*ln2/16); sprintf("%.1f").
  if let Some(v) = b(17) {
    push(
      out,
      "AEAperture",
      aperture_value(i64::from(v), print_conv, 1),
    );
  }
  // 18: AE_ISO — 100*exp(($val-32)*ln2/8); int($val+0.5).
  if let Some(v) = b(18) {
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
  // 28: AEMaxAperture — exp(($val-68)*ln2/16); sprintf("%.1f").
  if let Some(v) = b(28) {
    push(
      out,
      "AEMaxAperture",
      aperture_value(i64::from(v), print_conv, 1),
    );
  }
  // 29: AEMaxAperture2 — exp(($val-68)*ln2/16); sprintf("%.1f").
  if let Some(v) = b(29) {
    push(
      out,
      "AEMaxAperture2",
      aperture_value(i64::from(v), print_conv, 1),
    );
  }
  // 30: AEMinAperture — exp(($val-68)*ln2/16); sprintf("%.0f").
  if let Some(v) = b(30) {
    push(
      out,
      "AEMinAperture",
      aperture_value(i64::from(v), print_conv, 0),
    );
  }
  // 31: AEMinExposureTime — 24*exp(-($val-32)*ln2/8); PrintExposureTime.
  if let Some(v) = b(31) {
    let secs = 24.0 * (-(f64::from(v) - 32.0) * std::f64::consts::LN_2 / 8.0).exp();
    push(out, "AEMinExposureTime", expo_value(secs, print_conv));
  }
}

/// The shared `AEInfo*` aperture value: `exp(($val-68)*ln2/16)` then
/// `sprintf("%.Nf", $val)` (`prec` = 1 for most, 0 for `AEMinAperture`). `-n` ⇒
/// the post-ValueConv `f64`.
fn aperture_value(raw: i64, print_conv: bool, prec: usize) -> TagValue {
  let f = aperture_from_raw(raw);
  if !print_conv {
    return TagValue::F64(f);
  }
  TagValue::Str(SmolStr::from(match prec {
    0 => std::format!("{f:.0}"),
    _ => std::format!("{f:.1}"),
  }))
}

/// Decode the nested `%Pentax::LensData` leaves from a `%Pentax::LensInfo5`
/// record (`0x0207`, `Pentax.pm:4349-4382`) — the lens-info layout for the K-01
/// and newer (K-30/K-50/K-500/K-3/K-3II/**K-S1/K-S2**/K-70/KP). Selected by the
/// `0x0207` SubDirectory-list `Condition => '$count == 80 or $count == 128'`
/// (`Pentax.pm:2847`); the K-S2 record is 128 bytes.
///
/// `LensInfo5` differs from `LensInfo2` ONLY in where the nested `LensData`
/// `undef[17]` SubDirectory sits: offset **15** (`Pentax.pm:4377`) vs `LensInfo2`'s
/// offset 4. The nested `%Pentax::LensData` table is identical, so this slices
/// `block[15..32]` and runs the SAME leaf decode as [`emit_lens_info`] (the K-S2
/// uses the OLD 17-byte `LensData`; `NewLensData` is set only by the size-18
/// `LensInfo4` path, so it is structurally false here). Offset-1 `LensType` is NOT
/// re-emitted — Phase 1's `0x003f LensRec` owns it.
pub(crate) fn emit_lens_info5(
  block: &[u8],
  count: usize,
  model: Option<&str>,
  print_conv: bool,
  out: &mut std::vec::Vec<VendorEmission>,
) {
  if count != 80 && count != 128 {
    return;
  }
  // `LensData` = `undef[17]` at LensInfo5 offset 15 — `block[15..32]`.
  let lens_data: &[u8] = block.get(15..32).or_else(|| block.get(15..)).unwrap_or(&[]);
  emit_lens_data_leaves(lens_data, model, print_conv, out);
}

/// Decode the K-1mkII/K-3/K-30/.../K-S2/K-70/KP `%Pentax::KelvinWB`
/// (`0x0221`, `Pentax.pm:5233-5255`) — `FORMAT => 'int16u'`, so element offset N
/// = byte 2N. The row declares no `ByteOrder` ⇒ inherits the parent IFD `order`
/// (Little-endian for the K-S2). Each leaf is `%kelvinWB`: `int16u[4]` with
/// ValueConv `(53190-a0) a1 (a2/8192) (a3/8192)` (`Pentax.pm`); there is no
/// PrintConv, so the ValueConv string is emitted for BOTH `-j` and `-n`. Entries
/// at element offsets 1, 5, 9, …, 65 (`KelvinWB_Daylight`, then `KelvinWB_01`
/// … `KelvinWB_16`).
pub(crate) fn emit_kelvin_wb(
  block: &[u8],
  order: ByteOrder,
  out: &mut std::vec::Vec<VendorEmission>,
) {
  // (name, element-offset). Element offset N is byte 2N (FORMAT int16u).
  const ENTRIES: &[(&str, usize)] = &[
    ("KelvinWB_Daylight", 1),
    ("KelvinWB_01", 5),
    ("KelvinWB_02", 9),
    ("KelvinWB_03", 13),
    ("KelvinWB_04", 17),
    ("KelvinWB_05", 21),
    ("KelvinWB_06", 25),
    ("KelvinWB_07", 29),
    ("KelvinWB_08", 33),
    ("KelvinWB_09", 37),
    ("KelvinWB_10", 41),
    ("KelvinWB_11", 45),
    ("KelvinWB_12", 49),
    ("KelvinWB_13", 53),
    ("KelvinWB_14", 57),
    ("KelvinWB_15", 61),
    ("KelvinWB_16", 65),
  ];
  for &(name, elem) in ENTRIES {
    let byte = elem * 2;
    // int16u[4] — four consecutive int16u in the parent order.
    let (Some(a0), Some(a1), Some(a2), Some(a3)) = (
      read_u16(block, byte, order),
      read_u16(block, byte + 2, order),
      read_u16(block, byte + 4, order),
      read_u16(block, byte + 6, order),
    ) else {
      continue;
    };
    // ValueConv `(53190 - a0) . ' ' . a1 . ' ' . (a2/8192) . ' ' . (a3/8192)`.
    let v0 = 53190i64 - i64::from(a0);
    let g2 = crate::value::format_g(f64::from(a2) / 8192.0, 15);
    let g3 = crate::value::format_g(f64::from(a3) / 8192.0, 15);
    push(
      out,
      name,
      TagValue::Str(SmolStr::from(std::format!("{v0} {a1} {g2} {g3}"))),
    );
  }
}

/// Decode `%Pentax::TimeInfo` (`0x006b`, `Pentax.pm:3305-3336`) — the world-time
/// settings (`FORMAT` default `int8u`; inherits the parent IFD order, but all
/// leaves are single bytes / masks). Emits WorldTimeLocation (mask 0x01),
/// HometownDST (0x02), DestinationDST (0x04), HometownCity (byte 2), DestinationCity
/// (byte 3).
pub(crate) fn emit_time_info(
  block: &[u8],
  print_conv: bool,
  out: &mut std::vec::Vec<VendorEmission>,
) {
  let b = |i: usize| block.get(i).copied();
  if let Some(v) = b(0) {
    let v = i64::from(v);
    push(
      out,
      "WorldTimeLocation",
      hash(print_conv, mask(v, 0x01), printconv::WORLD_TIME_LOCATION),
    );
    push(
      out,
      "HometownDST",
      hash(print_conv, mask(v, 0x02), printconv::NO_YES),
    );
    push(
      out,
      "DestinationDST",
      hash(print_conv, mask(v, 0x04), printconv::NO_YES),
    );
  }
  if let Some(v) = b(2) {
    push(out, "HometownCity", city(print_conv, i64::from(v)));
  }
  if let Some(v) = b(3) {
    push(out, "DestinationCity", city(print_conv, i64::from(v)));
  }
}

/// A `\%pentaxCities` PrintConv leaf (`HometownCity` / `DestinationCity`): the
/// city name for `-j`, the raw index for `-n`, with the `Unknown (N)` fallback
/// for an absent key.
fn city(print_conv: bool, n: i64) -> TagValue {
  if !print_conv {
    return TagValue::I64(n);
  }
  match u16::try_from(n).ok().and_then(super::cities::lookup_name) {
    Some(name) => TagValue::Str(name),
    None => TagValue::Str(SmolStr::from(std::format!("Unknown ({n})"))),
  }
}

/// Decode `%Pentax::LensCorr` (`0x007d`, `Pentax.pm:3339-3358`) — the lens
/// distortion / aberration correction flags (`FORMAT` default `int8u`). Emits
/// DistortionCorrection (@0), ChromaticAberrationCorrection (@1),
/// PeripheralIlluminationCorr (@2), DiffractionCorrection (@3, `{0=>Off,16=>On}`).
pub(crate) fn emit_lens_corr(
  block: &[u8],
  print_conv: bool,
  out: &mut std::vec::Vec<VendorEmission>,
) {
  let b = |i: usize| block.get(i).copied();
  if let Some(v) = b(0) {
    push(
      out,
      "DistortionCorrection",
      hash(print_conv, i64::from(v), printconv::OFF_ON),
    );
  }
  if let Some(v) = b(1) {
    push(
      out,
      "ChromaticAberrationCorrection",
      hash(print_conv, i64::from(v), printconv::OFF_ON),
    );
  }
  if let Some(v) = b(2) {
    push(
      out,
      "PeripheralIlluminationCorr",
      hash(print_conv, i64::from(v), printconv::OFF_ON),
    );
  }
  if let Some(v) = b(3) {
    push(
      out,
      "DiffractionCorrection",
      hash(print_conv, i64::from(v), printconv::DIFFRACTION_CORRECTION),
    );
  }
}

/// Decode `%Pentax::FaceInfo` (`0x0060`, `Pentax.pm:2293-2297` Main row /
/// `:3264-3280` table) — `FORMAT` default `int8u`. Emits FacesDetected (@0) and
/// FacePosition (@2, `int8u[2]`, space-joined). The Main `0x0060` row carries NO
/// `Condition` (it is a single `{...}`, not a model-variant ARRAY), so EVERY body
/// — the K-3 Mark III included — routes 0x0060 through this `%FaceInfo` table;
/// this emitter is therefore UNCONDITIONAL, matching ExifTool. The K-3III's
/// distinct `%FaceInfoK3III` re-layout is a SEPARATE Main tag id (`0x040b`,
/// `Pentax.pm:3154-3158`), NOT a 0x0060 variant; that tag is not yet ported (a
/// deferred follow-up). Adding a model gate here would WRONGLY suppress FaceInfo
/// for a K-3III body.
pub(crate) fn emit_face_info(block: &[u8], out: &mut std::vec::Vec<VendorEmission>) {
  if let Some(v) = block.first() {
    push(out, "FacesDetected", int_value(i64::from(*v)));
  }
  // 2: FacePosition — int8u[2], the default space-joined pair.
  if let (Some(&x), Some(&y)) = (block.get(2), block.get(3)) {
    push(
      out,
      "FacePosition",
      TagValue::Str(SmolStr::from(std::format!("{x} {y}"))),
    );
  }
}

/// Decode `%Pentax::AWBInfo` (`0x0068`, `Pentax.pm:3283-3302`) — the automatic
/// white-balance settings (`FORMAT` default `int8u`). Emits
/// WhiteBalanceAutoAdjustment (@0, `{0=>Off,1=>On}`) and TungstenAWB (@1,
/// `{0=>'Subtle Correction',1=>'Strong Correction'}`, present only for the K-5 and
/// later — a byte-1 record).
pub(crate) fn emit_awb_info(
  block: &[u8],
  print_conv: bool,
  out: &mut std::vec::Vec<VendorEmission>,
) {
  if let Some(v) = block.first() {
    push(
      out,
      "WhiteBalanceAutoAdjustment",
      hash(print_conv, i64::from(*v), printconv::OFF_ON),
    );
  }
  if let Some(v) = block.get(1) {
    push(
      out,
      "TungstenAWB",
      hash(print_conv, i64::from(*v), printconv::TUNGSTEN_AWB),
    );
  }
}

/// Decode `%Pentax::EVStepInfo` (`0x0224`, `Pentax.pm:5273-5294`) — `FORMAT`
/// default `int8u`. Emits EVSteps (@0, `{0=>'1/2 EV Steps',1=>'1/3 EV Steps'}`),
/// SensitivitySteps (@1, `{0=>'1 EV Steps',1=>'As EV Steps'}`) and LiveView (@3,
/// `{0=>Off,1=>On}`).
pub(crate) fn emit_evstep_info(
  block: &[u8],
  print_conv: bool,
  out: &mut std::vec::Vec<VendorEmission>,
) {
  let b = |i: usize| block.get(i).copied();
  if let Some(v) = b(0) {
    push(
      out,
      "EVSteps",
      hash(print_conv, i64::from(v), printconv::EV_STEPS_INFO),
    );
  }
  if let Some(v) = b(1) {
    push(
      out,
      "SensitivitySteps",
      hash(print_conv, i64::from(v), printconv::SENSITIVITY_STEPS_INFO),
    );
  }
  if let Some(v) = b(3) {
    push(
      out,
      "LiveView",
      hash(print_conv, i64::from(v), printconv::OFF_ON),
    );
  }
}

/// Decode `%Pentax::LevelInfo` (`0x022b`, `Pentax.pm:5701-5769`) — the electronic
/// level info, `FORMAT => 'int8s'` (every leaf is a SIGNED byte). This is the
/// K-5-style (non-K-3III) variant: the `0x022b` Main row is VARIANT-SELECTED on
/// `$$self{Model}` (`Pentax.pm:3044-3051`) — a `/K-3 Mark III/` body reads the
/// distinct `%LevelInfoK3III` re-layout ([`emit_level_info_k3iii`]), every OTHER
/// body reads THIS table. The dispatcher applies that model gate, so this emitter
/// runs only for non-K-3III bodies (the K-S2 / K-1 / K-3 / KP / K-70 / K-5 II
/// fixtures). Emits LevelOrientation (mask 0x0f), CompositionAdjust (mask 0xf0),
/// RollAngle (@1, -$val/2), PitchAngle (@2, -$val/2), CompositionAdjustX (@5,
/// -$val), CompositionAdjustY (@6, -$val), CompositionAdjustRotation (@7, -$val/2).
pub(crate) fn emit_level_info(
  block: &[u8],
  print_conv: bool,
  out: &mut std::vec::Vec<VendorEmission>,
) {
  // int8s — each byte read SIGNED. The mask leaves apply the mask to the raw
  // (unsigned-interpreted) byte; for byte 0 the masks 0x0f / 0xf0 select nibbles.
  let raw = |i: usize| block.get(i).map(|&b| i64::from(b as i8));
  let raw_u = |i: usize| block.get(i).copied().map(i64::from);
  // 0: LevelOrientation (mask 0x0f). The mask reads the unsigned byte's low nibble.
  if let Some(v) = raw_u(0) {
    push(
      out,
      "LevelOrientation",
      hash(print_conv, mask(v, 0x0f), printconv::LEVEL_ORIENTATION),
    );
    push(
      out,
      "CompositionAdjust",
      hash(print_conv, mask(v, 0xf0), printconv::COMPOSITION_ADJUST),
    );
  }
  // 1: RollAngle — ValueConv -$val/2 (no PrintConv ⇒ same for -j/-n).
  if let Some(v) = raw(1) {
    push(out, "RollAngle", angle_half(v));
  }
  // 2: PitchAngle — ValueConv -$val/2.
  if let Some(v) = raw(2) {
    push(out, "PitchAngle", angle_half(v));
  }
  // 5: CompositionAdjustX — ValueConv -$val.
  if let Some(v) = raw(5) {
    push(out, "CompositionAdjustX", neg_int(v));
  }
  // 6: CompositionAdjustY — ValueConv -$val.
  if let Some(v) = raw(6) {
    push(out, "CompositionAdjustY", neg_int(v));
  }
  // 7: CompositionAdjustRotation — ValueConv -$val/2.
  if let Some(v) = raw(7) {
    push(out, "CompositionAdjustRotation", angle_half(v));
  }
}

/// Decode `%Pentax::LevelInfoK3III` (`0x022b`, `Pentax.pm:5771-5801`) — the
/// K-3-Mark-III electronic-level re-layout, `FORMAT => 'int8s'`. The `0x022b`
/// Main row selects THIS table when `$$self{Model} =~ /K-3 Mark III/`
/// (`Pentax.pm:3044-3047`), in preference to the K-5-style [`emit_level_info`];
/// the dispatcher applies the same model gate. `Format`-overridden leaves:
/// CameraOrientation (`int8s` @ 1, PrintConv hash), RollAngle (`int16s` @ 3,
/// -$val/2) and PitchAngle (`int16s` @ 5, -$val/2). The two `int16s` leaves carry
/// no per-table `ByteOrder`, so they inherit the parent MakerNote IFD `order`
/// (threaded as `order`) — exactly as the rest of `%Pentax::Main` does. No active
/// fixture is a K-3 Mark III, so this path is unexercised by the goldens, but it
/// keeps the variant SELECTION faithful (a K-3III record would otherwise mis-decode
/// through the K-5 layout). No PrintConv on the angles ⇒ identical for `-j`/`-n`.
pub(crate) fn emit_level_info_k3iii(
  block: &[u8],
  order: ByteOrder,
  print_conv: bool,
  out: &mut std::vec::Vec<VendorEmission>,
) {
  // 1: CameraOrientation (int8s) — direct PrintConv hash.
  if let Some(&b) = block.get(1) {
    push(
      out,
      "CameraOrientation",
      hash(
        print_conv,
        i64::from(b as i8),
        printconv::CAMERA_ORIENTATION_K3III,
      ),
    );
  }
  // 3: RollAngle — Format `int16s`, ValueConv -$val/2 (inherits the parent order).
  if let Some(v) = read_u16(block, 3, order) {
    push(out, "RollAngle", angle_half(i64::from(v as i16)));
  }
  // 5: PitchAngle — Format `int16s`, ValueConv -$val/2.
  if let Some(v) = read_u16(block, 5, order) {
    push(out, "PitchAngle", angle_half(i64::from(v as i16)));
  }
}

/// `-$val / 2` ValueConv (RollAngle / PitchAngle / CompositionAdjustRotation), no
/// PrintConv ⇒ emitted for both modes. The serializer's number gate renders an
/// integral `f64` without a trailing `.0`.
fn angle_half(raw: i64) -> TagValue {
  TagValue::F64(-(raw as f64) / 2.0)
}

/// `-$val` ValueConv (CompositionAdjustX/Y), no PrintConv. The negated signed
/// byte is an integer.
fn neg_int(raw: i64) -> TagValue {
  TagValue::I64(-raw)
}

/// Decode `%Pentax::CAFPointInfo` (`0x0238`, `Pentax.pm:5202-5230`) — the
/// contrast-detect AF-point info (`FORMAT` default `int8u`, `FIRST_ENTRY 0`).
/// Emits NumCAFPoints (@1, `($val>>4)*($val&0x0f)`), CAFGridSize (@1.1,
/// `(val>>4) (val&0x0f)` → `tr/ /x/`), and CAFPointsInFocus (@2) / CAFPointsSelected
/// (@2.1), each a `DecodeAFPoints` over an `int8u[int((NumCAFPoints+3)/4)]` slice
/// — for a record with `NumCAFPoints == 0` the slice is empty and `DecodeAFPoints`
/// returns `'(none)'`.
pub(crate) fn emit_caf_point_info(
  block: &[u8],
  print_conv: bool,
  out: &mut std::vec::Vec<VendorEmission>,
) {
  let Some(v1) = block.get(1).copied().map(i64::from) else {
    return;
  };
  // 1: NumCAFPoints — RawConv stores `($val & 0x0f) * ($val >> 4)`; ValueConv
  // `($val >> 4) * ($val & 0x0f)` (same product). No PrintConv.
  let num = (v1 >> 4) * (v1 & 0x0f);
  push(out, "NumCAFPoints", int_value(num));
  // 1.1: CAFGridSize — ValueConv `(val>>4) " " (val&0x0f)`; PrintConv `tr/ /x/`.
  let grid = std::format!("{} {}", v1 >> 4, v1 & 0x0f);
  push(
    out,
    "CAFGridSize",
    if print_conv {
      TagValue::Str(SmolStr::from(grid.replace(' ', "x")))
    } else {
      TagValue::Str(SmolStr::from(grid))
    },
  );
  // 2 / 2.1: CAFPointsInFocus / CAFPointsSelected — `int8u[int((num+3)/4)]` then
  // `DecodeAFPoints`. The slice starts at byte 2. For `-n` ExifTool emits the raw
  // space-joined run (empty when `num == 0`).
  let n_bytes = ((num.max(0) as usize) + 3) / 4;
  let slice: &[u8] = block.get(2..2 + n_bytes).unwrap_or(&[]);
  for (name, bit_val) in [("CAFPointsInFocus", 0x02u8), ("CAFPointsSelected", 0x03u8)] {
    if print_conv {
      push(
        out,
        name,
        TagValue::Str(SmolStr::from(decode_af_points(slice, num, 2, bit_val))),
      );
    } else {
      // `-n`: the default space-joined int8u run.
      let joined = slice
        .iter()
        .map(u8::to_string)
        .collect::<std::vec::Vec<_>>()
        .join(" ");
      push(out, name, TagValue::Str(SmolStr::from(joined)));
    }
  }
}

/// `Image::ExifTool::Pentax::DecodeAFPoints` (`Pentax.pm:6730-6754`): walk `num`
/// AF points packed `bits`-per-point across `bytes`, listing the 1-based index of
/// each point whose `bits`-wide field (high bits first) equals `bit_val`. An
/// EMPTY byte slice returns `'(none)'`; otherwise a comma-joined index list (also
/// `'(none)'`-displayed by the join when empty? — no, ExifTool joins to `''`, but
/// the empty-slice early-return covers the K-S2's `num == 0`).
fn decode_af_points(bytes: &[u8], num: i64, bits: u32, bit_val: u8) -> std::string::String {
  let Some(&first) = bytes.first() else {
    return "(none)".to_string();
  };
  let shift0 = 8i32 - bits as i32;
  let mut i: i64 = 1;
  let mut idx = 0usize;
  let mut byte = i64::from(first);
  let mut shift = shift0;
  let mask_bits = (1i64 << bits) - 1;
  let mut bit_list: std::vec::Vec<std::string::String> = std::vec::Vec::new();
  loop {
    if ((byte >> shift) & mask_bits) == i64::from(bit_val) {
      bit_list.push(i.to_string());
    }
    i += 1;
    if i > num {
      break;
    }
    shift -= bits as i32;
    if shift < 0 {
      idx += 1;
      let Some(&nb) = bytes.get(idx) else {
        break;
      };
      byte = i64::from(nb);
      shift += 8;
    }
  }
  bit_list.join(",")
}

/// Decode `%Pentax::FilterInfo` (`0x022a`, `Pentax.pm:5660-5698`) — the digital
/// filter info. The `0x022a` Main row is VARIANT-SELECTED on `$$self{Make}`
/// (`Pentax.pm:3030-3043`): a RICOH body (`Make =~ /^RICOH/`) reads the table
/// **LittleEndian**, every OTHER body reads it **BigEndian**. The forced order is
/// NOT the parent IFD order — so the byte order is determined HERE from the
/// threaded `make`, not from `resolved_subdir_order`. The K-S2 / K-1 / K-3 / KP /
/// K-70 fixtures all report `Make => "RICOH IMAGING COMPANY, LTD."` ⇒ the
/// LittleEndian variant; the K-5 II reports `Make => "PENTAX"` ⇒ the BigEndian
/// variant. (For every fixture both leaves are 0, so the order is value-invisible,
/// but the SELECTION must still be faithful — a non-zero record would byte-swap.)
/// Emits SourceDirectoryIndex (`int16u` @ byte 0) and SourceFileIndex (`int16u` @
/// byte 2); the 20 `DigitalFilterNN` blobs are deferred. `%FilterInfo` declares
/// `FORMAT => 'int8u'` (`Pentax.pm:5663`), so a `ProcessBinaryData` row key is a
/// BYTE offset (`key × sizeof(FORMAT) = key × 1`): `SourceDirectoryIndex` (key 0)
/// at byte 0 and `SourceFileIndex` (key 2) at byte 2 — NOT an `int16u`-element
/// index (which would put it at byte 4). The per-row `Format => 'int16u'`
/// (`Pentax.pm:5672`/`:5676`) sets only how many bytes are READ at that offset,
/// not the offset's stride.
pub(crate) fn emit_filter_info(
  block: &[u8],
  make: Option<&str>,
  out: &mut std::vec::Vec<VendorEmission>,
) {
  // `Make =~ /^RICOH/` ⇒ LittleEndian; otherwise BigEndian (`Pentax.pm:3032-3041`).
  let order = if is_ricoh_make(make) {
    ByteOrder::Little
  } else {
    ByteOrder::Big
  };
  // `FORMAT => 'int8u'` ⇒ row key = byte offset: SourceDirectoryIndex (key 0) at
  // byte 0, SourceFileIndex (key 2) at byte 2. Each is read as an `int16u`.
  if let Some(v) = read_u16(block, 0, order) {
    push(out, "SourceDirectoryIndex", int_value(i64::from(v)));
  }
  if let Some(v) = read_u16(block, 2, order) {
    push(out, "SourceFileIndex", int_value(i64::from(v)));
  }
}

/// `true` when `make` matches Perl `/^RICOH/` (a `^`-anchored, NON-`\b` prefix —
/// `$$self{Make} =~ /^RICOH/`, `Pentax.pm:3032`). The Make strings are ASCII;
/// `"RICOH IMAGING COMPANY, LTD."` matches, `"PENTAX"` / `"PENTAX Corporation"`
/// do not.
fn is_ricoh_make(make: Option<&str>) -> bool {
  make.is_some_and(|m| m.starts_with("RICOH"))
}

/// Decode `%Pentax::SRInfo2` (`0x005c`, `Pentax.pm:3231-3261`) for the
/// `$count == 2` variant — the shake-reduction info for the K-3 and newer
/// (K-3/K-S1/**K-S2**/K-70/…), selected when the `0x005c` record is NOT 4 bytes
/// (the `%Pentax::SRInfo` variant, `Pentax.pm:2258-2262`). Emits ShakeReduction
/// (@1, the K-3 `#forum5425` hash); the offset-0 `SRResult` is `Unknown => 1`
/// (an empty BITMASK) and is suppressed without `-U`.
pub(crate) fn emit_sr_info2(
  block: &[u8],
  count: usize,
  print_conv: bool,
  out: &mut std::vec::Vec<VendorEmission>,
) {
  // `$count == 4` is the OLD `%Pentax::SRInfo` (handled by `emit_sr_info`); this
  // SRInfo2 variant is the fall-through (any other count, in practice 2).
  if count == 4 {
    return;
  }
  if let Some(v) = block.get(1) {
    push(
      out,
      "ShakeReduction",
      hash(print_conv, i64::from(*v), printconv::SHAKE_REDUCTION2),
    );
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
