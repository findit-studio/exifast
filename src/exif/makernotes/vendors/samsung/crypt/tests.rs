// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! `Image::ExifTool::Samsung::Crypt` port tests — REAL-input vectors captured
//! from bundled ExifTool 13.59 decrypting `tests/fixtures/SamsungNX500.srw`
//! (the `0xa020 EncryptionKey` = `305 72 737 456 282 307 519 724 13 505 193`).
//! Each `(raw, format, salts) -> decrypted` triple is the exact RawConv input
//! and output bundled produces — the proof the cipher port is byte-faithful.

use super::{Salt, crypt};
use crate::exif::ifd::Format;

/// The NX500 `0xa020 EncryptionKey` (int32u[11]).
const KEY: &[i64] = &[305, 72, 737, 456, 282, 307, 519, 724, 13, 505, 193];

#[test]
fn wb_rggb_levels_uncorrected_0xa021() {
  // SALT "-0", int32u[4].
  let raw = [6881, 4168, 4833, 9064];
  let got = crypt(&raw, KEY, Format::Int32u, &[Salt::neg(0)]).unwrap();
  assert_eq!(got, "6576 4096 4096 8608");
}

#[test]
fn wb_rggb_levels_auto_0xa022() {
  // SALT -4, int32u[4].
  let raw = [6858, 4403, 4615, 9332];
  let got = crypt(&raw, KEY, Format::Int32u, &[Salt::neg(4)]).unwrap();
  assert_eq!(got, "6576 4096 4096 8608");
}

#[test]
fn wb_rggb_levels_illuminator1_0xa023() {
  let raw = [5293, 4601, 4289, 10113];
  let got = crypt(&raw, KEY, Format::Int32u, &[Salt::neg(8)]).unwrap();
  assert_eq!(got, "5280 4096 4096 9808");
}

#[test]
fn wb_rggb_levels_illuminator2_0xa024() {
  let raw = [7384, 4833, 4552, 6250];
  let got = crypt(&raw, KEY, Format::Int32u, &[Salt::neg(1)]).unwrap();
  assert_eq!(got, "7312 4096 4096 5968");
}

#[test]
fn wb_rggb_levels_black_0xa028() {
  // int32s[4], SALT "-0". Raw on-disk are signed.
  let raw = [433, 200, 865, 584];
  let got = crypt(&raw, KEY, Format::Int32s, &[Salt::neg(0)]).unwrap();
  assert_eq!(got, "128 128 128 128");
}

#[test]
fn color_matrix_0xa030() {
  // int32s[9], SALT 0 (positive sign).
  let raw = [131, -192, -797, -498, 30, -321, -517, -818, 335];
  let got = crypt(&raw, KEY, Format::Int32s, &[Salt::pos(0)]).unwrap();
  assert_eq!(got, "436 -120 -60 -42 312 -14 2 -94 348");
}

#[test]
fn color_matrix_srgb_0xa031() {
  let raw = [73, -174, -757, -484, 46, -351, -511, -824, 335];
  let got = crypt(&raw, KEY, Format::Int32s, &[Salt::pos(0)]).unwrap();
  assert_eq!(got, "378 -102 -20 -28 328 -44 8 -100 348");
}

#[test]
fn color_matrix_adobe_rgb_0xa032() {
  let raw = [-61, -36, -761, -482, 38, -345, -511, -796, 307];
  let got = crypt(&raw, KEY, Format::Int32s, &[Salt::pos(0)]).unwrap();
  assert_eq!(got, "244 36 -24 -26 320 -38 8 -72 320");
}

#[test]
fn cbcr_matrix_default_0xa033() {
  // int32s[4], SALT 0.
  let raw = [-49, -72, -737, -200];
  let got = crypt(&raw, KEY, Format::Int32s, &[Salt::pos(0)]).unwrap();
  assert_eq!(got, "256 0 0 256");
}

#[test]
fn cbcr_matrix_0xa034() {
  // Same raw bytes as CbCrMatrixDefault but SALT 4 (different phase) ⇒ different output.
  let raw = [-49, -72, -737, -200];
  let got = crypt(&raw, KEY, Format::Int32s, &[Salt::pos(4)]).unwrap();
  assert_eq!(got, "233 235 -218 524");
}

#[test]
fn cbcr_gain_default_0xa035() {
  // int32u[2], SALT "-0".
  let raw = [4096, 4096];
  let got = crypt(&raw, KEY, Format::Int32u, &[Salt::neg(0)]).unwrap();
  assert_eq!(got, "3791 4024");
}

#[test]
fn cbcr_gain_0xa036() {
  // Same raw as CbCrGainDefault but SALT -2 ⇒ different output.
  let raw = [4096, 4096];
  let got = crypt(&raw, KEY, Format::Int32u, &[Salt::neg(2)]).unwrap();
  assert_eq!(got, "3359 3640");
}

#[test]
fn tone_curve_srgb_default_0xa040() {
  // int32u[23], TWO salts (0,"-0"): a[0]=11 is the array length (skipped); the
  // first 11 entries (X coords) use salt 0 (+sign), the next 11 (Y coords) use
  // salt "-0" (-sign). The on-disk negative deltas appear as large int32u.
  let raw = [
    11, 4294966991, 4294967240, 4294966591, 4294966904, 4294967142, 4294967245, 4294967289, 300,
    2035, 2567, 3902, 305, 79, 751, 484, 334, 397, 659, 914, 243, 750, 448,
  ];
  let got = crypt(&raw, KEY, Format::Int32u, &[Salt::pos(0), Salt::neg(0)]).unwrap();
  assert_eq!(
    got,
    "11 0 16 32 64 128 256 512 1024 2048 3072 4095 0 7 14 28 52 90 140 190 230 245 255"
  );
}

#[test]
fn empty_key_returns_none() {
  // $key or return undef — no EncryptionKey captured ⇒ no decryption.
  let raw = [6881, 4168, 4833, 9064];
  assert!(crypt(&raw, &[], Format::Int32u, &[Salt::neg(0)]).is_none());
}

#[test]
fn non_int_format_returns_none() {
  // return undef unless $formatMinMax{$format}.
  let raw = [1, 2];
  assert!(crypt(&raw, KEY, Format::Rational64u, &[Salt::pos(0)]).is_none());
}
