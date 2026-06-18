// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Unit tests for the Samsung Type2 PrintConv/ValueConv arms.

use super::*;
use crate::value::Rational;

#[test]
fn device_type_high_end_nx() {
  let raw = RawValue::U64(std::vec![0x2000]);
  assert_eq!(
    SamsungPrintConv::DeviceType.apply(&raw, true),
    TagValue::Str("High-end NX Camera".into())
  );
  assert_eq!(
    SamsungPrintConv::DeviceType.apply(&raw, false),
    TagValue::I64(0x2000)
  );
}

#[test]
fn samsung_model_id_various_models_hex_unknown() {
  // 0x5001038 is a mapped "Various Models" key.
  let raw = RawValue::U64(std::vec![0x5001038]);
  assert_eq!(
    SamsungPrintConv::SamsungModelId.apply(&raw, true),
    TagValue::Str("Various Models (0x5001038)".into())
  );
  assert_eq!(
    SamsungPrintConv::SamsungModelId.apply(&raw, false),
    TagValue::I64(0x5001038)
  );
  // An unmapped value renders as the PrintHex `Unknown (0xNN)`.
  let raw2 = RawValue::U64(std::vec![0xdead]);
  assert_eq!(
    SamsungPrintConv::SamsungModelId.apply(&raw2, true),
    TagValue::Str("Unknown (0xdead)".into())
  );
}

#[test]
fn lens_type_nx_45mm() {
  let raw = RawValue::U64(std::vec![10]);
  assert_eq!(
    SamsungPrintConv::LensType.apply(&raw, true),
    TagValue::Str("Samsung NX 45mm F1.8".into())
  );
  assert_eq!(
    SamsungPrintConv::LensType.apply(&raw, false),
    TagValue::I64(10)
  );
}

#[test]
fn smart_album_color_zero_is_na() {
  let raw = RawValue::U64(std::vec![0, 0]);
  assert_eq!(
    SamsungPrintConv::SmartAlbumColor.apply(&raw, true),
    TagValue::Str("n/a".into())
  );
  assert_eq!(
    SamsungPrintConv::SmartAlbumColor.apply(&raw, false),
    TagValue::Str("0 0".into())
  );
}

#[test]
fn camera_temperature_undef_passthrough() {
  // 0/0 rational ⇒ the bare word `undef`, no digit ⇒ `$val` passthrough (both
  // modes render the undef rational).
  let raw = RawValue::Rational(std::vec![Rational::rational64(0, 0)]);
  let pc = SamsungPrintConv::CameraTemperature.apply(&raw, true);
  let nc = SamsungPrintConv::CameraTemperature.apply(&raw, false);
  assert_eq!(pc, TagValue::Rational(Rational::rational64(0, 0)));
  assert_eq!(nc, TagValue::Rational(Rational::rational64(0, 0)));
}

#[test]
fn camera_temperature_real_value_gets_c_suffix() {
  // 2/10 = 0.2 ⇒ "0.2 C" in print-conv, the rational in value-conv.
  let raw = RawValue::Rational(std::vec![Rational::rational64(2, 10)]);
  assert_eq!(
    SamsungPrintConv::CameraTemperature.apply(&raw, true),
    TagValue::Str("0.2 C".into())
  );
  assert_eq!(
    SamsungPrintConv::CameraTemperature.apply(&raw, false),
    TagValue::Rational(Rational::rational64(2, 10))
  );
}

#[test]
fn exposure_time_print_exposure_time() {
  // 1/160 ⇒ "1/160"; value-conv keeps the rational (0.00625).
  let raw = RawValue::Rational(std::vec![Rational::rational64(1, 160)]);
  assert_eq!(
    SamsungPrintConv::ExposureTime.apply(&raw, true),
    TagValue::Str("1/160".into())
  );
  assert_eq!(
    SamsungPrintConv::ExposureTime.apply(&raw, false),
    TagValue::Rational(Rational::rational64(1, 160))
  );
}

#[test]
fn fnumber_one_decimal() {
  let raw = RawValue::Rational(std::vec![Rational::rational64(89, 10)]);
  assert_eq!(
    SamsungPrintConv::FNumber.apply(&raw, true),
    TagValue::Str("8.9".into())
  );
  assert_eq!(
    SamsungPrintConv::FNumber.apply(&raw, false),
    TagValue::Rational(Rational::rational64(89, 10))
  );
}

#[test]
fn focal_length_35_div10_mm() {
  // int32u 690 ⇒ ValueConv /10 = 69 ⇒ "69 mm"; value-conv 69.
  let raw = RawValue::U64(std::vec![690]);
  assert_eq!(
    SamsungPrintConv::FocalLength35.apply(&raw, true),
    TagValue::Str("69 mm".into())
  );
  assert_eq!(
    SamsungPrintConv::FocalLength35.apply(&raw, false),
    TagValue::I64(69)
  );
}

#[test]
fn picture_wizard_mode_standard() {
  let raw = RawValue::U64(std::vec![0]);
  assert_eq!(
    SamsungPrintConv::PictureWizardMode.apply(&raw, true),
    TagValue::Str("Standard".into())
  );
}

#[test]
fn picture_wizard_minus4() {
  // raw 0 ⇒ ValueConv $val - 4 = -4 (both modes; no PrintConv).
  let raw = RawValue::U64(std::vec![0]);
  assert_eq!(
    SamsungPrintConv::PictureWizardMinus4.apply(&raw, true),
    TagValue::I64(-4)
  );
  assert_eq!(
    SamsungPrintConv::PictureWizardMinus4.apply(&raw, false),
    TagValue::I64(-4)
  );
}

#[test]
fn maker_note_version_renders_ascii() {
  // undef[4] "0100" ⇒ the ASCII string, trailing-NUL-stripped (same both modes).
  let raw = RawValue::Bytes(std::vec![0x30, 0x31, 0x30, 0x30]);
  assert_eq!(
    SamsungPrintConv::Version.apply(&raw, true),
    TagValue::Str("0100".into())
  );
  assert_eq!(
    SamsungPrintConv::Version.apply(&raw, false),
    TagValue::Str("0100".into())
  );
  // Trailing NULs stripped; an interior NUL kept.
  let raw2 = RawValue::Bytes(std::vec![0x30, 0x31, 0x00, 0x00]);
  assert_eq!(
    SamsungPrintConv::Version.apply(&raw2, true),
    TagValue::Str("01".into())
  );
}

/// `LocalLocationName` 0x0030 ValueConv (`Samsung.pm:296`):
/// `$val=~s/\0\0.*//; $val=~s/\0 */\n/g; $val`. The on-disk `Format => 'undef'`
/// value arrives as `RawValue::Bytes`; two place names are separated by a
/// NUL+space and terminated by a double-NUL. No PrintConv ⇒ identical in both modes.
#[test]
fn local_location_name_nul_separated() {
  // "Seoul" \0 " " "Gangnam" \0\0 "trailing-junk".
  let raw = RawValue::Bytes(b"Seoul\0 Gangnam\0\0trailing-junk".to_vec());
  // Truncate at the first \0\0 ⇒ "Seoul\0 Gangnam"; then \0+spaces ⇒ newline.
  assert_eq!(
    SamsungPrintConv::LocalLocationName.apply(&raw, true),
    TagValue::Str("Seoul\nGangnam".into())
  );
  assert_eq!(
    SamsungPrintConv::LocalLocationName.apply(&raw, false),
    TagValue::Str("Seoul\nGangnam".into()),
    "no PrintConv ⇒ -j and -n render the same ValueConv string"
  );
}

/// The separator is `\0` followed by ZERO-or-more spaces, so a bare `\0`
/// (no trailing space) also collapses to a single newline, and a run of spaces
/// after the NUL is absorbed into that one newline.
#[test]
fn local_location_name_nul_without_space_and_space_run() {
  // "A" \0 "B"  — NUL with no space.
  let bare = RawValue::Bytes(b"A\0B".to_vec());
  assert_eq!(
    SamsungPrintConv::LocalLocationName.apply(&bare, true),
    TagValue::Str("A\nB".into())
  );
  // "A" \0 "   " "B" — NUL + three spaces collapse to ONE newline (greedy ` *`).
  let run = RawValue::Bytes(b"A\0   B".to_vec());
  assert_eq!(
    SamsungPrintConv::LocalLocationName.apply(&run, true),
    TagValue::Str("A\nB".into())
  );
}

/// With NO double-NUL terminator the whole (separator-rewritten) value is kept —
/// the `s/\0\0.*//` is a no-op when there is no `\0\0`.
#[test]
fn local_location_name_no_double_nul_keeps_all() {
  let raw = RawValue::Bytes(b"OnlyOne\0 Place".to_vec());
  assert_eq!(
    SamsungPrintConv::LocalLocationName.apply(&raw, true),
    TagValue::Str("OnlyOne\nPlace".into())
  );
}

// ---------------------------------------------------------------------------
// 0xa002 SerialNumber value-`Condition` gate (`$$valPt =~ /^\w{5}/`,
// `Samsung.pm:404-409`). `condition_holds(0xa002, raw)` is TRUE only when the
// first five raw value bytes are ASCII word chars `[A-Za-z0-9_]`.
// ---------------------------------------------------------------------------

/// A `string` SerialNumber whose first five bytes are word chars PASSES.
/// `RawValue::Text.raw` is the NUL-trimmed on-disk `$$valPt`.
#[test]
fn serial_condition_passes_on_word5() {
  let raw = RawValue::Text {
    text: std::string::String::from("AB12C"),
    raw: Box::from(&b"AB12C"[..]),
  };
  assert!(SamsungPrintConv::condition_holds(0xa002, &raw));
  // A longer serial (e.g. 10 chars) also passes — only the first five matter.
  let long = RawValue::Text {
    text: std::string::String::from("0560018150"),
    raw: Box::from(&b"0560018150"[..]),
  };
  assert!(SamsungPrintConv::condition_holds(0xa002, &long));
}

/// The NX500 fixture value: `0x30` (`'0'`) then NULs ⇒ NUL-trimmed `$$valPt` is
/// `"0"` (one word char, then nothing) ⇒ fewer than five leading word chars ⇒
/// the Condition FAILS (bundled emits no `Samsung:SerialNumber` for NX500).
#[test]
fn serial_condition_fails_on_nx500_value() {
  // On-disk `string[30]` = "0" + 29 NULs; `RawValue::Text.raw` is the trimmed "0".
  let raw = RawValue::Text {
    text: std::string::String::from("0"),
    raw: Box::from(&b"0"[..]),
  };
  assert!(!SamsungPrintConv::condition_holds(0xa002, &raw));
}

/// A NUL within the first five bytes fails: the `Text` shape NUL-trims to the
/// pre-NUL run, which is then shorter than five word chars (NUL is not `\w`, so
/// `$$valPt` would fail the same way).
#[test]
fn serial_condition_fails_on_embedded_nul() {
  let raw = RawValue::Text {
    text: std::string::String::from("AB"),
    raw: Box::from(&b"AB"[..]), // bytes were "AB\0CDE" on disk; ReadValue trims at \0
  };
  assert!(!SamsungPrintConv::condition_holds(0xa002, &raw));
  // An UNDEF-shaped value carrying a NUL in the first five bytes also fails
  // (`val_bytes` returns the bytes verbatim; positions 0..5 are not all `\w`).
  let undef = RawValue::Bytes(b"AB CDEF".to_vec());
  assert!(!SamsungPrintConv::condition_holds(0xa002, &undef));
}

/// A non-word ASCII char (`!`) in the first five bytes fails.
#[test]
fn serial_condition_fails_on_non_word_byte() {
  let raw = RawValue::Bytes(b"AB!CDEF".to_vec());
  assert!(!SamsungPrintConv::condition_holds(0xa002, &raw));
}

/// Underscore is a `\w` character; five leading underscores pass.
#[test]
fn serial_condition_underscore_is_word() {
  let raw = RawValue::Text {
    text: std::string::String::from("_____X"),
    raw: Box::from(&b"_____X"[..]),
  };
  assert!(SamsungPrintConv::condition_holds(0xa002, &raw));
}

/// A value shorter than five bytes cannot match `/^\w{5}/`.
#[test]
fn serial_condition_fails_on_short_value() {
  let raw = RawValue::Text {
    text: std::string::String::from("AB12"),
    raw: Box::from(&b"AB12"[..]),
  };
  assert!(!SamsungPrintConv::condition_holds(0xa002, &raw));
}

/// Every OTHER Samsung tag has no suppressible value-Condition ⇒ always TRUE,
/// even for a value that would fail the SerialNumber test.
#[test]
fn condition_holds_true_for_non_serial_tags() {
  let bad = RawValue::Bytes(b"!!".to_vec());
  for id in [0x0001u16, 0x0002, 0x0030, 0xa001, 0xa003, 0xa005, 0xa01a] {
    assert!(
      SamsungPrintConv::condition_holds(id, &bad),
      "tag {id:#x} has no value-Condition and must always hold"
    );
  }
}
