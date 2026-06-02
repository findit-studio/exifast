// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! DJI-specific PrintConv enum — covers the inline PrintConv hashes and
//! the shared `%convFloat2` table in `%Image::ExifTool::DJI::Main`
//! (`DJI.pm:53-72`).
//!
//! Faithful: `%convFloat2` is `PrintConv => 'sprintf("%+.2f", $val)'`
//! (`DJI.pm:47-50`) — a signed-2-decimal printf applied to every
//! Pitch/Yaw/Roll/CameraPitch/CameraYaw/CameraRoll/Speed{X,Y,Z} value.
//!
//! Bundled DJI Main currently emits NO PrintConv lookup tables — every
//! tag is either a string passthrough (`Make`) or a float-with-sign
//! (`%convFloat2`). The enum still uses the same shape as the Phase 3
//! vendors so future expansions (DJI thermal hashes etc.) can land
//! cleanly here.

#![deny(clippy::indexing_slicing)]

use crate::exif::ifd::RawValue;
use crate::value::TagValue;
use smol_str::SmolStr;
use std::vec::Vec;

/// Per-tag PrintConv strategy for the DJI Main IFD table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DjiPrintConv {
  /// No PrintConv — emit raw scalar / string.
  None,
  /// `%convFloat2` (`DJI.pm:47-50`) — `sprintf("%+.2f", $val)`. Applied to
  /// SpeedX/SpeedY/SpeedZ/Pitch/Yaw/Roll/CameraPitch/CameraYaw/CameraRoll.
  Float2Signed,
}

impl DjiPrintConv {
  /// Apply the PrintConv to a raw value. When `print_conv` is `false`
  /// the bundled value-conv (raw scalar) is returned.
  #[must_use]
  pub fn apply(self, raw: &RawValue, print_conv: bool) -> TagValue {
    match self {
      DjiPrintConv::None => raw_to_tag_value(raw),
      DjiPrintConv::Float2Signed => float2_signed(raw, print_conv),
    }
  }
}

/// `sprintf("%+.2f", $val)` (`DJI.pm:48`). Renders signed 2-decimal float
/// with explicit `+` for positive values (`-0.00` for negatives).
fn float2_signed(raw: &RawValue, print_conv: bool) -> TagValue {
  let Some(v) = first_f64(raw) else {
    return raw_to_tag_value(raw);
  };
  if !print_conv {
    return TagValue::F64(v);
  }
  // Perl's `%+.2f` always emits an explicit sign on positive numbers
  // and on zero. `format!("{:+.2}", 0.0_f64)` matches that ("+0.00").
  TagValue::Str(SmolStr::from(std::format!("{v:+.2}")))
}

/// Extract the first f64 scalar from a [`RawValue`] (works for `F64`,
/// `I64`, `U64`, and `Rational`).
fn first_f64(raw: &RawValue) -> Option<f64> {
  match raw {
    RawValue::F64(v) => v.first().copied(),
    RawValue::I64(v) => v.first().map(|&n| n as f64),
    RawValue::U64(v) => v.first().map(|&n| n as f64),
    RawValue::Rational(r) => r.first().map(|r| {
      let n = r.numerator();
      let d = r.denominator();
      if d == 0 { 0.0 } else { n as f64 / d as f64 }
    }),
    _ => None,
  }
}

/// Render a raw value as a default [`TagValue`] (no PrintConv) — mirrors
/// the Apple/Canon/Panasonic helpers.
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
    RawValue::Rational(rs) => TagValue::Str(
      rs.iter()
        .map(|r| std::format!("{}/{}", r.numerator(), r.denominator()))
        .collect::<Vec<_>>()
        .join(" ")
        .into(),
    ),
    RawValue::Text(s) => {
      // ASCII strings often end in NUL/spaces from TIFF padding; trim
      // to match Perl's bundled output.
      let trimmed = s.trim_end_matches(['\0', ' ']);
      TagValue::Str(trimmed.into())
    }
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
  fn float2_signed_positive() {
    let raw = RawValue::F64(std::vec![12.345]);
    assert_eq!(
      DjiPrintConv::Float2Signed.apply(&raw, true),
      TagValue::Str("+12.35".into())
    );
  }

  #[test]
  fn float2_signed_negative() {
    let raw = RawValue::F64(std::vec![-7.50]);
    assert_eq!(
      DjiPrintConv::Float2Signed.apply(&raw, true),
      TagValue::Str("-7.50".into())
    );
  }

  #[test]
  fn float2_signed_zero_gets_plus_sign() {
    // Perl `%+.2f` of 0.0 ⇒ "+0.00" (explicit positive sign).
    let raw = RawValue::F64(std::vec![0.0]);
    assert_eq!(
      DjiPrintConv::Float2Signed.apply(&raw, true),
      TagValue::Str("+0.00".into())
    );
  }

  #[test]
  fn float2_signed_value_conv_passes_through_raw() {
    let raw = RawValue::F64(std::vec![3.5]);
    assert_eq!(
      DjiPrintConv::Float2Signed.apply(&raw, false),
      TagValue::F64(3.5)
    );
  }

  #[test]
  fn none_string_strip_trailing_padding() {
    let raw = RawValue::Text("DJI\0\0".into());
    assert_eq!(
      DjiPrintConv::None.apply(&raw, true),
      TagValue::Str("DJI".into())
    );
  }
}
