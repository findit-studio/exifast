//! Byte-exact tests for `PrintExposureTime` / `PrintFNumber` against the Perl
//! originals (Exif.pm:5701 / 5715), pinned to the bundled-ExifTool 13.59 output
//! the regenerated stills carry.

use super::*;

#[test]
fn print_exposure_time_fraction_branch() {
  // `0 < secs < 0.25001` ⇒ `1/int(0.5 + 1/secs)`. NikonD2Hs ShutterSpeed 0.008.
  assert_eq!(print_exposure_time(0.008), "1/125");
  // ExifGPS 1/724 ≈ 0.001381 ⇒ int(0.5 + 724.0) = 724.
  assert_eq!(print_exposure_time(1.0 / 724.0), "1/724");
  // Pentax 1/100 = 0.01 ⇒ int(0.5 + 100) = 100.
  assert_eq!(print_exposure_time(0.01), "1/100");
  // Exactly at the 0.25001 boundary stays in the fraction branch (`< 0.25001`).
  assert_eq!(print_exposure_time(0.25), "1/4");
}

#[test]
fn print_exposure_time_decimal_branch_strips_trailing_zero() {
  // `secs >= 0.25001` ⇒ `sprintf("%.1f")` with a trailing `.0` stripped.
  assert_eq!(print_exposure_time(2.0), "2"); // "2.0" → "2"
  assert_eq!(print_exposure_time(0.5), "0.5"); // 0.5 >= 0.25001 ⇒ decimal
  assert_eq!(print_exposure_time(1.3), "1.3");
  assert_eq!(print_exposure_time(30.0), "30"); // "30.0" → "30"
}

#[test]
fn print_exposure_time_zero_and_nonfinite_pass_through() {
  // `secs == 0` is NOT `> 0` ⇒ decimal branch: `sprintf("%.1f", 0)` = "0.0" → "0".
  assert_eq!(print_exposure_time(0.0), "0");
  // Non-finite fails IsFloat ⇒ returned unchanged (Perl spelling).
  assert_eq!(print_exposure_time(f64::INFINITY), "Inf");
  assert_eq!(print_exposure_time(f64::NEG_INFINITY), "-Inf");
  assert_eq!(print_exposure_time(f64::NAN), "NaN");
}

#[test]
fn print_fnumber_one_and_two_decimal_branches() {
  // `val >= 1` ⇒ `%.1f` (NO trailing-zero strip): Aperture 4.0 / 13.0 / 1.0.
  assert_eq!(print_fnumber(4.0), "4.0");
  assert_eq!(print_fnumber(13.0), "13.0");
  assert_eq!(print_fnumber(1.0), "1.0");
  assert_eq!(print_fnumber(2.8), "2.8");
  // `0 < val < 1` ⇒ `%.2f`: ExifGPS Aperture 0.64.
  assert_eq!(print_fnumber(0.64), "0.64");
  assert_eq!(print_fnumber(0.95), "0.95");
}

#[test]
fn print_fnumber_nonpositive_and_nonfinite_pass_through() {
  // `val <= 0` is NOT `> 0` ⇒ pass through as the Perl NV stringification.
  assert_eq!(print_fnumber(0.0), "0");
  // Non-finite ⇒ Perl spelling.
  assert_eq!(print_fnumber(f64::INFINITY), "Inf");
  assert_eq!(print_fnumber(f64::NAN), "NaN");
}

#[test]
fn print_exposure_time_scalar_passes_non_float_strings_through() {
  use crate::value::TagValue;
  // A genuinely-numeric operand (a `TagValue::F64`/`I64`/`U64`) IsFloat-passes
  // ⇒ the normal `1/N` / decimal shaping (byte-identical to the f64 helper).
  assert_eq!(
    print_exposure_time_scalar(&TagValue::F64(0.008)),
    "1/125",
    "a finite f64 operand formats"
  );
  assert_eq!(print_exposure_time_scalar(&TagValue::F64(2.0)), "2");
  assert_eq!(print_exposure_time_scalar(&TagValue::U64(30)), "30");
  // A float-SHAPED string operand is IsFloat (and `,`→`.` translated) ⇒ format.
  assert_eq!(
    print_exposure_time_scalar(&TagValue::Str("0.00138106793200498".into())),
    "1/724",
    "a float-shaped string formats (ExifGPS ShutterSpeedValue path)"
  );
  // A NON-float string operand (a zero-denominator/undef rational's ValueConv
  // string, or any non-IsFloat text) PASSES THROUGH UNCHANGED — Exif.pm:5704
  // `return $secs unless IsFloat($secs)`. The prior `coerce_numeric` path turned
  // these into `0` (a fabricated `Composite:ShutterSpeed`); now they are kept.
  assert_eq!(
    print_exposure_time_scalar(&TagValue::Str("undef".into())),
    "undef",
    "a zero-denominator rational's `undef` passes through (NOT coerced to 0)"
  );
  assert_eq!(
    print_exposure_time_scalar(&TagValue::Str("inf".into())),
    "inf"
  );
  assert_eq!(
    print_exposure_time_scalar(&TagValue::Str("n/a".into())),
    "n/a"
  );
  // A non-finite f64 operand stringifies to a Perl spelling that fails IsFloat
  // ⇒ passthrough (the `print_exposure_time` non-finite arm, reached via the
  // scalar gate's `is_finite` rejection).
  assert_eq!(
    print_exposure_time_scalar(&TagValue::F64(f64::INFINITY)),
    "Inf"
  );
}

#[test]
fn print_exposure_time_scalar_formats_every_isfloat_value() {
  // `PrintExposureTime` has NO positivity passthrough (unlike `PrintFNumber`):
  // it `return $secs unless IsFloat`, then ALWAYS formats an `IsFloat` value
  // (`%.1f` with `.0` stripped, or `1/N` for `0 < secs < 0.25001`). So a
  // NON-positive `IsFloat` STRING is FORMATTED, not returned verbatim. Pinned
  // to bundled `Image::ExifTool::Exif::PrintExposureTime` (2026-06-20).
  use crate::value::TagValue;
  let cases = [
    ("0.0", "0"),   // sprintf("%.1f",0)="0.0" → strip → "0"
    ("+0", "0"),    // IsFloat dot-branch (no comma normalize) → 0.0 → "0"
    ("0E0", "0"),   // exponent zero → 0.0 → "0"
    ("-0.0", "-0"), // sprintf("%.1f",-0)="-0.0" → strip → "-0"
    ("0,0", "0"),   // comma normalized to "0.0", value 0.0 → "0"
    ("5,6", "5.6"), // comma normalized to "5.6", >=0.25001 → "%.1f" → "5.6"
    ("-1.5", "-1.5"),
    ("4.0", "4"),    // "4.0" → strip → "4"
    ("0.25", "1/4"), // 0 < 0.25 < 0.25001 ⇒ fraction
    ("0.3", "0.3"),
  ];
  for (input, want) in cases {
    assert_eq!(
      print_exposure_time_scalar(&TagValue::Str(input.into())),
      want,
      "PrintExposureTime({input:?}) must match bundled Perl"
    );
  }
  // A non-`IsFloat` string short-circuits verbatim (`return $secs unless …`).
  assert_eq!(
    print_exposure_time_scalar(&TagValue::Str("undef".into())),
    "undef"
  );
  // Numeric operands: 0 / negative format via `%.1f` (the same gate, no
  // verbatim arm) — `0` → "0", `-1` → "-1".
  assert_eq!(print_exposure_time_scalar(&TagValue::I64(0)), "0");
  assert_eq!(print_exposure_time_scalar(&TagValue::F64(-1.5)), "-1.5");
}

#[test]
fn print_fnumber_scalar_passes_non_float_strings_through() {
  use crate::value::TagValue;
  // Numeric / float-shaped operands format via PrintFNumber.
  assert_eq!(print_fnumber_scalar(&TagValue::F64(4.0)), "4.0");
  assert_eq!(print_fnumber_scalar(&TagValue::U64(13)), "13.0");
  assert_eq!(print_fnumber_scalar(&TagValue::Str("0.64".into())), "0.64");
  // A NON-float string passes through unchanged — Exif.pm:5719 returns `$val`
  // when `IsFloat($val) and $val > 0` is false.
  assert_eq!(
    print_fnumber_scalar(&TagValue::Str("undef".into())),
    "undef",
    "a zero-denominator rational's `undef` passes through (NOT coerced to 0)"
  );
  assert_eq!(print_fnumber_scalar(&TagValue::Str("inf".into())), "inf");
  // A non-positive numeric operand also passes through (PrintFNumber gate is
  // `$val > 0`): `0` renders as the Perl NV `"0"`, not `"0.0"`.
  assert_eq!(print_fnumber_scalar(&TagValue::F64(0.0)), "0");
}

#[test]
fn print_fnumber_scalar_nonpositive_isfloat_string_returns_verbatim() {
  // `PrintFNumber` formats ONLY when `IsFloat($val) and $val > 0`; otherwise it
  // `return $val` — the `tr/,/./`-mutated scalar VERBATIM, NOT a numeric
  // canonicalization. So a reachable allow-listed `exif:FNumber="0.0"` (XMP
  // keeps the operand as `Str("0.0")`) renders "0.0" UNCHANGED, not "0". Pinned
  // to bundled `Image::ExifTool::Exif::PrintFNumber` (2026-06-20).
  use crate::value::TagValue;
  let verbatim = [
    ("0.0", "0.0"),   // not > 0 ⇒ `return $val` (original, no normalize)
    ("+0", "+0"),     // dot-branch IsFloat, value 0.0 ⇒ verbatim original
    ("0E0", "0E0"),   // exponent zero, value 0.0 ⇒ verbatim original
    ("-0.0", "-0.0"), // -0.0 is NOT > 0 ⇒ verbatim
    ("-1.5", "-1.5"), // negative ⇒ verbatim
  ];
  for (input, want) in verbatim {
    assert_eq!(
      print_fnumber_scalar(&TagValue::Str(input.into())),
      want,
      "PrintFNumber({input:?}) returns the operand verbatim (gate `$val > 0` failed)"
    );
  }
  // A comma operand fails `> 0` but is returned in IsFloat's `,`→`.`-NORMALIZED
  // form (`tr/,/./` mutated the scalar before the `else` return): "0,0" → "0.0".
  assert_eq!(
    print_fnumber_scalar(&TagValue::Str("0,0".into())),
    "0.0",
    "a non-positive comma operand returns the `,`→`.`-normalized string, not \"0\""
  );
  // A POSITIVE float-shaped string still formats (the gate's `and $val > 0`
  // branch): "4.0" → "4.0" (`%.1f`), and the comma "5,6" → "5.6".
  assert_eq!(print_fnumber_scalar(&TagValue::Str("4.0".into())), "4.0");
  assert_eq!(print_fnumber_scalar(&TagValue::Str("5,6".into())), "5.6");
  // A non-`IsFloat` string passes through unchanged.
  assert_eq!(
    print_fnumber_scalar(&TagValue::Str("undef".into())),
    "undef"
  );
  // A negative numeric operand: `-1` → the Perl NV "-1" (the `else` arm formats
  // the value, since `Number` has no source string).
  assert_eq!(print_fnumber_scalar(&TagValue::F64(-1.0)), "-1");
}

#[test]
fn print_megapixels_magnitude_keyed_precision() {
  // `>= 1` ⇒ 1 decimal: DJI_Matrice30T 1280*1024/1e6 = 1.31072 ⇒ "1.3".
  assert_eq!(print_megapixels(1.31072), "1.3");
  // `0.001 <= val < 1` ⇒ 3 decimals: HEIC 1280*720/1e6 = 0.9216 ⇒ "0.922";
  // AVIF 1204*800/1e6 = 0.9632 ⇒ "0.963"; ExifGPS 120*80/1e6 = 0.0096 ⇒ "0.010".
  assert_eq!(print_megapixels(0.9216), "0.922");
  assert_eq!(print_megapixels(0.9632), "0.963");
  assert_eq!(print_megapixels(0.0096), "0.010");
  // `< 0.001` ⇒ 6 decimals: NikonD2Hs 8*8/1e6 = 6.4e-5 ⇒ "0.000064".
  assert_eq!(print_megapixels(6.4e-5), "0.000064");
  // Exact boundaries: 1.0 ⇒ 1 dp; 0.001 ⇒ 3 dp.
  assert_eq!(print_megapixels(1.0), "1.0");
  assert_eq!(print_megapixels(0.001), "0.001");
}
