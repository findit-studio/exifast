//! Unit tests for the canonical [`convert_duration`] and its Perl
//! number-stringification primitives — including the extreme-input cases the
//! migrated APE/AIFF goldens pin (huge-days carve-out, `2^63` boundary,
//! non-finite passthrough).

use super::*;

#[test]
fn convert_duration_zero_and_sub_30() {
  assert_eq!(convert_duration(0.0), "0 s");
  assert_eq!(convert_duration(2.63922902494331), "2.64 s");
  assert_eq!(convert_duration(14.7127916666667), "14.71 s");
  assert_eq!(convert_duration(-2.5), "-2.50 s");
}

#[test]
fn convert_duration_hms_and_rounding() {
  // FLAC_duration: 240000/8000 = 30 → "0:00:30".
  assert_eq!(convert_duration(30.0), "0:00:30");
  // AIFF_duration: 44100/22050 = 2 → "2.00 s" (< 30, the `%.2f s` path).
  assert_eq!(convert_duration(2.0), "2.00 s");
  assert_eq!(convert_duration(5400.0), "1:30:00");
  // +0.5 rounding to the nearest second.
  assert_eq!(convert_duration(59.6), "0:01:00");
}

#[test]
fn convert_duration_days_carve_out_faithful() {
  // AIFF_huge_duration golden: a huge finite duration prints `$d` via `%.15g`.
  assert_eq!(
    convert_duration(1.93428131138341e25),
    "2.23875151780487e+20 days 0:00:00"
  );
  // APE_huge_composite golden.
  assert_eq!(
    convert_duration(9.99999999999999e29),
    "1.15740740740741e+25 days 0:00:00"
  );
}

#[test]
fn convert_duration_non_finite_titlecase() {
  assert_eq!(convert_duration(f64::INFINITY), "Inf");
  assert_eq!(convert_duration(f64::NEG_INFINITY), "-Inf");
  assert_eq!(convert_duration(f64::NAN), "NaN");
}

#[test]
fn perl_nv_str_matches_perl_default_stringify() {
  // Finite integers in safe IV range ⇒ exact decimal (matches Perl
  // `print 1e10 . "\n"` ⇒ `10000000000`).
  assert_eq!(perl_nv_str(0.0), "0");
  assert_eq!(perl_nv_str(42.0), "42");
  assert_eq!(perl_nv_str(1.0e10), "10000000000");
  assert_eq!(perl_nv_str(1.0e15), "1000000000000000");
  // Negative integer in safe IV range.
  assert_eq!(perl_nv_str(-42.0), "-42");
  assert_eq!(perl_nv_str(-32768.0), "-32768");
  // Outside IV range ⇒ Perl `%.15g` (e.g. `1e25/24/3600` ≈ 1.157e+20).
  assert_eq!(perl_nv_str(1.0e25 / 24.0 / 3600.0), "1.15740740740741e+20");
  assert_eq!(perl_nv_str(1.0e25), "1e+25");
  // Fractional values use `%.15g`.
  assert_eq!(perl_nv_str(2.5), "2.5");
  // Special values.
  assert_eq!(perl_nv_str(f64::INFINITY), "Inf");
  assert_eq!(perl_nv_str(f64::NEG_INFINITY), "-Inf");
  assert_eq!(perl_nv_str(f64::NAN), "NaN");
  // Positive integer-valued f64 in (i64::MAX, u64::MAX] ⇒ DECIMAL (Perl's UV
  // path), NOT scientific. Boundaries empirically verified against Perl 5:
  //   int(1e19) ⇒ "10000000000000000000"
  //   int(1.5e19) ⇒ "15000000000000000000"
  //   int(2^64-2048) ⇒ "18446744073709549568" (largest f64 below 2^64)
  //   int(2^64) ⇒ "1.84467440737096e+19" (scientific, > u64::MAX)
  assert_eq!(perl_nv_str(1.0e19), "10000000000000000000");
  assert_eq!(perl_nv_str(1.5e19), "15000000000000000000");
  assert_eq!(perl_nv_str(18446744073709549568.0), "18446744073709549568");
  let two64 = (1u128 << 64) as f64;
  assert_eq!(perl_nv_str(two64), "1.84467440737096e+19");
  // The duration helper's worst-case path: 8.64e23 → days = 1e19.
  let days_at_864e23 = (8.64e23_f64 / 3600.0 / 24.0).trunc();
  assert_eq!(perl_nv_str(days_at_864e23), "10000000000000002048");
  // `i64::MAX as f64` rounds UP to 2^63; exactly-2^63 must go via the UV path
  // (`"9223372036854775808"`), NOT the saturating signed `"…807"`.
  let two63 = (1u128 << 63) as f64;
  assert_eq!(perl_nv_str(two63), "9223372036854775808");
  // 2^63 - 1024 (representable as f64) goes via the signed path.
  assert_eq!(perl_nv_str(9223372036854774784.0), "9223372036854774784");
}

#[test]
fn perl_int_str_padded_in_range_pads_with_zeros() {
  // ConvertDuration's m/s values are always in [0, 60) ⇒ `%02d` zero-pads.
  assert_eq!(perl_int_str_padded(0.0, 2), "00");
  assert_eq!(perl_int_str_padded(5.0, 2), "05");
  assert_eq!(perl_int_str_padded(59.0, 2), "59");
  // In-range but wider than `width` ⇒ the full number.
  assert_eq!(perl_int_str_padded(100.0, 2), "100");
  // Out-of-range or fractional ⇒ fall through to perl_nv_str.
  assert_eq!(perl_int_str_padded(f64::INFINITY, 2), "Inf");
  assert_eq!(perl_int_str_padded(1.5, 2), "1.5");
}

#[cfg(feature = "alloc")]
#[test]
fn duration_value_modes() {
  use crate::emit::ConvMode;
  use crate::value::TagValue;
  assert_eq!(
    duration_value(30.0, ConvMode::PrintConv),
    TagValue::Str("0:00:30".into())
  );
  assert_eq!(
    duration_value(30.0, ConvMode::ValueConv),
    TagValue::F64(30.0)
  );
  assert_eq!(
    duration_value(f64::INFINITY, ConvMode::PrintConv),
    TagValue::Str("Inf".into())
  );
  assert_eq!(
    duration_value(f64::INFINITY, ConvMode::ValueConv),
    TagValue::Str("Inf".into())
  );
}
