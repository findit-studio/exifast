// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! The single faithful **default** (no-PrintConv) `RawValue` → [`TagValue`]
//! renderer for the tag-table archetype (golden pattern L3b — `render_value`).
//!
//! This consolidates the rational→decimal / multi-rational space-join / scalar
//! passthrough logic that was duplicated between two emitters:
//!
//! - [`super::emit_raw`] — the EXIF `Conv::None` default path (`exif/mod.rs`);
//! - the Apple MakerNote "no PrintConv" default rendering (formerly the
//!   per-vendor `apple::body::ParsedValue::to_default_tag_value`, deleted with
//!   the oracle in #243 phase 5; the isolated decode path now renders through
//!   this same `render_value`).
//!
//! Both render an un-converted `$val` the same way ExifTool's `ReadValue`
//! does (`ExifTool.pm:6275-6321`): a multi-element value is space-joined
//! (`ExifTool.pm:6319`), a single element is the bare scalar. A rational is
//! stringified via [`Rational::exiftool_val_str`](crate::value::Rational::exiftool_val_str)
//! (`RoundFloat(n/d, sig)`), so a single rational becomes a
//! [`TagValue::Rational`] (its serializer emits the same ExifTool-rounded
//! number) and a multi-rational becomes the space-joined decimal string
//! (e.g. Apple `AccelerationVector` → `"-0.01 0.02 -0.7"`).
//!
//! Gated on `feature = "alloc"` to match the surrounding EXIF emission code:
//! a [`TagValue`] carries owned `SmolStr`/`Vec` data.

#![cfg(feature = "alloc")]
// Golden-v2 Contract 3c (Phase C, slice w2d): panic-safety by construction —
// the single-element `v[0]` reads below are each dominated by a `v.len() == 1`
// match guard, so the checked `.first()` form recovers the same scalar.
#![deny(clippy::indexing_slicing)]

use crate::emit::ConvMode;
use crate::exif::ifd::RawValue;
use crate::value::TagValue;

/// Render a decoded [`RawValue`] to its **default** (no-PrintConv/ValueConv)
/// [`TagValue`] — the faithful `ReadValue` stringification ExifTool applies
/// when a tag has no conversion hash (`Conv::None`):
///
/// - a single integer / float → the bare scalar
///   ([`TagValue::I64`] / [`TagValue::U64`] / [`TagValue::F64`]);
/// - a single rational → [`TagValue::Rational`] (the serializer renders its
///   `RoundFloat(n/d, sig)` decimal — `value.rs`);
/// - a multi-element value → the space-joined string
///   (`ExifTool.pm:6319` joins an array with spaces); a multi-rational joins
///   each element's [`exiftool_val_str`](crate::value::Rational::exiftool_val_str)
///   DECIMAL (NOT `n/d` fractions);
/// - a `string` → [`TagValue::Str`]; raw bytes → [`TagValue::Bytes`].
///
/// `mode` is accepted for signature uniformity with the conversion-bearing
/// emitters, but the **default** renderer does not branch on it: a tag with
/// no PrintConv/ValueConv renders byte-identically under `-j` and `-n`
/// (`Conv::None` has no human-readable vs raw distinction).
#[must_use]
pub(crate) fn render_value(raw: &RawValue, mode: ConvMode) -> TagValue {
  // The default renderer is mode-agnostic (a `Conv::None` tag has no PrintConv
  // vs ValueConv split); bind `mode` to document that and keep the signature
  // uniform with the conversion-bearing paths.
  let _ = mode;
  // The single-element arms below use an `if let [x] = v.as_slice()` guard
  // rather than `len()==1` + `v[0]`: the binding `x` IS the sole element, so
  // the read is checked by the slice pattern and stays byte-identical (no panic
  // site, no fallback value).
  match raw {
    // ---- integers ---------------------------------------------------------
    RawValue::I64(v) if let [x] = v.as_slice() => TagValue::I64(*x),
    RawValue::I64(v) => TagValue::Str(join_signed(v).into()),
    RawValue::U64(v) if let [x] = v.as_slice() => match i64::try_from(*x) {
      Ok(n) => TagValue::I64(n),
      // Above `i64::MAX` — keep the exact unsigned value (no saturation).
      Err(_) => TagValue::U64(*x),
    },
    RawValue::U64(v) => TagValue::Str(join_unsigned(v).into()),
    // ---- floats -----------------------------------------------------------
    RawValue::F64(v) if let [x] = v.as_slice() => TagValue::F64(*x),
    RawValue::F64(v) => TagValue::Str(join_floats(v).into()),
    // ---- rationals --------------------------------------------------------
    // A single rational keeps its `Rational` shape (its serializer renders the
    // ExifTool-rounded decimal). A multi-rational space-joins each element's
    // `exiftool_val_str` DECIMAL (e.g. AccelerationVector → "-0.01 0.02 -0.7";
    // `Apple.pm:62`, `rational64s` Count 3, no PrintConv), NOT `n/d` fractions.
    RawValue::Rational(rs) if let [r] = rs.as_slice() => TagValue::Rational(*r),
    RawValue::Rational(rs) => TagValue::Str(
      rs.iter()
        .map(crate::value::Rational::exiftool_val_str)
        .collect::<std::vec::Vec<_>>()
        .join(" ")
        .into(),
    ),
    // ---- string / bytes ---------------------------------------------------
    RawValue::Text { text, .. } => TagValue::Str(text.as_str().into()),
    RawValue::Bytes(b) => TagValue::Bytes(b.clone()),
  }
}

/// Space-join signed integers (the multi-element `ReadValue` array join,
/// `ExifTool.pm:6319`).
fn join_signed(v: &[i64]) -> std::string::String {
  v.iter()
    .map(i64::to_string)
    .collect::<std::vec::Vec<_>>()
    .join(" ")
}

/// Space-join unsigned integers.
fn join_unsigned(v: &[u64]) -> std::string::String {
  v.iter()
    .map(u64::to_string)
    .collect::<std::vec::Vec<_>>()
    .join(" ")
}

/// Space-join floats. (`to_string` matches the Apple `to_default_tag_value`
/// multi-float join this consolidates — multi-float EXIF tags do not occur on
/// the bundled camera fixtures, so the join spelling is exercised only by the
/// Apple archetype.)
fn join_floats(v: &[f64]) -> std::string::String {
  v.iter()
    .map(f64::to_string)
    .collect::<std::vec::Vec<_>>()
    .join(" ")
}

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2d); the test assertions index fixed-shape values freely
// (an out-of-range index is a test failure, not a shipped panic), so the deny
// is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;
  use crate::value::Rational;

  /// A single rational keeps its `Rational` shape — the serializer renders the
  /// `RoundFloat(n/d, sig)` decimal (so `1/2` → `0.5`, not the `n/d` fraction).
  #[test]
  fn render_single_rational_is_rational_value() {
    let v = render_value(
      &RawValue::Rational(std::vec![Rational::rational64(1, 2)]),
      ConvMode::PrintConv,
    );
    assert_eq!(v, TagValue::Rational(Rational::rational64(1, 2)));
  }

  /// A multi-rational space-joins each element's `exiftool_val_str` DECIMAL
  /// (`-1/100` → `-0.01`, `2/100` → `0.02`), NOT `n/d` fractions — the
  /// AccelerationVector shape (`Apple.pm:62`).
  #[test]
  fn render_multi_rational_is_space_joined_decimals() {
    let v = render_value(
      &RawValue::Rational(std::vec![
        Rational::rational64(-1, 100),
        Rational::rational64(2, 100),
      ]),
      ConvMode::PrintConv,
    );
    assert_eq!(v, TagValue::Str("-0.01 0.02".into()));
    // Mode does not change the no-conv default rendering.
    assert_eq!(
      v,
      render_value(
        &RawValue::Rational(std::vec![
          Rational::rational64(-1, 100),
          Rational::rational64(2, 100),
        ]),
        ConvMode::ValueConv,
      )
    );
  }

  /// A single integer passes through as the bare scalar.
  #[test]
  fn render_single_int_passthrough() {
    assert_eq!(
      render_value(&RawValue::U64(std::vec![72]), ConvMode::PrintConv),
      TagValue::I64(72)
    );
    assert_eq!(
      render_value(&RawValue::I64(std::vec![-5]), ConvMode::ValueConv),
      TagValue::I64(-5)
    );
    // A `u64` above `i64::MAX` keeps its exact unsigned value.
    assert_eq!(
      render_value(&RawValue::U64(std::vec![u64::MAX]), ConvMode::PrintConv),
      TagValue::U64(u64::MAX)
    );
  }

  /// A multi-element integer array space-joins.
  #[test]
  fn render_multi_int_is_space_joined() {
    assert_eq!(
      render_value(&RawValue::U64(std::vec![8, 8, 8]), ConvMode::PrintConv),
      TagValue::Str("8 8 8".into())
    );
  }

  /// A `string` passes through as `Str`; raw bytes as `Bytes`.
  #[test]
  fn render_string_and_bytes_passthrough() {
    assert_eq!(
      render_value(
        &RawValue::Text {
          text: "Canon".to_string(),
          raw: b"Canon"[..].into(),
        },
        ConvMode::PrintConv
      ),
      TagValue::Str("Canon".into())
    );
    assert_eq!(
      render_value(&RawValue::Bytes(std::vec![1, 2, 3]), ConvMode::PrintConv),
      TagValue::Bytes(std::vec![1, 2, 3])
    );
  }
}
