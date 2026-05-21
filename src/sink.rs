// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Tag-writer implementors. Each downstream consumer (JSON, in-memory
//! collector, validation harness) brings its own [`crate::parser_new::TagWriter`]
//! impl.
//!
//! [`MapTagWriter`] is the in-memory reference implementor (tests + generic
//! library callers).
//!
//! **History (task #124).** This module once held a `Metadata`-bridge
//! tag-writer adapter that translated a typed `Meta` emission into the
//! push-style [`crate::value::Metadata`] sink the JSON serializer rendered.
//! That bridge — and the `Metadata` push-bag on the OUTPUT path — were
//! removed once the direct [`crate::json_writer::JsonTagWriter`] (which
//! reproduces the same byte-exact `exiftool -j -G1` JSON) became the
//! engine's `$$et` value sink. Each format's engine entry
//! (`ProcessXxx::process`) now drives [`crate::parser_new::MetaSinker::sink`]
//! straight into the `JsonTagWriter` carried by
//! [`crate::parser::ParseContext`].

use crate::parser_new::TagWriter;
use core::{convert::Infallible, fmt, fmt::Write as _};

use std::{
  collections::BTreeMap,
  string::{String, ToString},
  vec::Vec,
};

/// Owned `(Group, Name)` key — used by [`MapTagWriter`] to index emitted
/// tags. Kept as `(String, String)` rather than `(&'static str, &'static
/// str)` so the writer is usable with dynamically-derived group/name pairs
/// (e.g., from a user-supplied tag table).
type MapKey = (String, String);

/// Owned tag value as emitted by a [`TagWriter`]. Mirrors the input
/// methods of the trait — the writer eagerly serializes each call into the
/// stored variant.
#[derive(Debug, Clone, PartialEq)]
pub enum MapValue {
  /// A `write_str` / `write_fmt` value (both produce textual output).
  Str(String),
  /// A `write_u64` value.
  U64(u64),
  /// A `write_i64` value.
  I64(i64),
  /// A `write_f64` value.
  F64(f64),
  /// A `write_bytes` value.
  Bytes(Vec<u8>),
}

impl MapValue {
  /// Returns the textual representation of the value — `Str` and
  /// `write_fmt` outputs return their string verbatim; numeric variants
  /// produce a `Display`-style rendering. Used by tests; library callers
  /// typically match on the variant directly.
  #[must_use]
  pub fn as_str(&self) -> String {
    match self {
      MapValue::Str(s) => s.clone(),
      MapValue::U64(n) => n.to_string(),
      MapValue::I64(n) => n.to_string(),
      MapValue::F64(n) => {
        let mut s = String::new();
        // `{}` on `f64` matches `Display` — `3.5_f64.to_string()` →
        // `"3.5"`. Adequate for the test path; canonical JSON formatting
        // lives in the future JSON sink.
        let _ = write!(&mut s, "{n}");
        s
      }
      MapValue::Bytes(b) => {
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
          let _ = write!(&mut s, "{byte:02x}");
        }
        s
      }
    }
  }
}

/// In-memory tag collector — primarily for tests and library callers that
/// want a generic key/value view without the JSON pipeline.
///
/// D8 convention: no public fields; accessors only. The internal storage
/// is a `BTreeMap` so the test assertions can do exact `get(group, name)`
/// lookups without depending on insertion order. (Library callers who
/// need insertion order should use a different sink — see [`tracked`
/// FU-7](../docs/tracking.md).)
#[derive(Debug, Default, Clone)]
pub struct MapTagWriter {
  /// `(Group, Name) -> Value` map. `BTreeMap` for deterministic iteration
  /// in tests.
  tags: BTreeMap<MapKey, MapValue>,
  /// `write_warning` accumulator. Preserves call order.
  warnings: Vec<String>,
  /// `write_error` accumulator. Preserves call order.
  errors: Vec<String>,
}

impl MapTagWriter {
  /// Construct an empty writer.
  #[must_use]
  pub fn new() -> Self {
    Self::default()
  }

  /// Number of distinct `(group, name)` tags plus warnings plus errors
  /// emitted so far.
  #[must_use]
  pub fn len(&self) -> usize {
    self.tags.len() + self.warnings.len() + self.errors.len()
  }

  /// True if no tags / warnings / errors have been emitted.
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.tags.is_empty() && self.warnings.is_empty() && self.errors.is_empty()
  }

  /// Look up an emitted tag by `(group, name)`. Returns `None` if the
  /// pair was never written.
  #[must_use]
  pub fn get(&self, group: &str, name: &str) -> Option<&MapValue> {
    self.tags.get(&(group.to_string(), name.to_string()))
  }

  /// Iterate all emitted `(group, name) -> value` triples in
  /// `BTreeMap` order (lexicographic on `(group, name)`).
  pub fn iter(&self) -> impl Iterator<Item = (&str, &str, &MapValue)> {
    self
      .tags
      .iter()
      .map(|((g, n), v)| (g.as_str(), n.as_str(), v))
  }

  /// All warnings emitted via [`TagWriter::write_warning`], in call order.
  #[must_use]
  pub fn warnings(&self) -> &[String] {
    &self.warnings
  }

  /// All errors emitted via [`TagWriter::write_error`], in call order.
  #[must_use]
  pub fn errors(&self) -> &[String] {
    &self.errors
  }
}

impl TagWriter for MapTagWriter {
  /// `MapTagWriter` cannot fail — every insertion is an in-memory
  /// `BTreeMap` write or a `Vec::push`. Using [`Infallible`] lets the
  /// caller's `?` operator compile-eliminate the error branch entirely.
  type Error = Infallible;

  fn write_str(&mut self, group: &str, name: &str, value: &str) -> Result<(), Infallible> {
    self.tags.insert(
      (group.to_string(), name.to_string()),
      MapValue::Str(value.to_string()),
    );
    Ok(())
  }

  fn write_u64(&mut self, group: &str, name: &str, value: u64) -> Result<(), Infallible> {
    self
      .tags
      .insert((group.to_string(), name.to_string()), MapValue::U64(value));
    Ok(())
  }

  fn write_i64(&mut self, group: &str, name: &str, value: i64) -> Result<(), Infallible> {
    self
      .tags
      .insert((group.to_string(), name.to_string()), MapValue::I64(value));
    Ok(())
  }

  fn write_f64(&mut self, group: &str, name: &str, value: f64) -> Result<(), Infallible> {
    self
      .tags
      .insert((group.to_string(), name.to_string()), MapValue::F64(value));
    Ok(())
  }

  fn write_bytes(&mut self, group: &str, name: &str, value: &[u8]) -> Result<(), Infallible> {
    self.tags.insert(
      (group.to_string(), name.to_string()),
      MapValue::Bytes(value.to_vec()),
    );
    Ok(())
  }

  fn write_fmt(
    &mut self,
    group: &str,
    name: &str,
    f: impl FnOnce(&mut dyn fmt::Write) -> fmt::Result,
  ) -> Result<(), Infallible> {
    // `write_fmt` is documented as the no-alloc workhorse — the
    // `MapTagWriter` accumulator does allocate (it has to, to store the
    // result), but consumers receiving the produced `&mut dyn fmt::Write`
    // see only the streaming-format interface. The single allocation
    // happens here, in the implementor — not at the Meta call site.
    let mut s = String::new();
    f(&mut s).expect("MapTagWriter::write_fmt: in-memory String write cannot fail");
    self
      .tags
      .insert((group.to_string(), name.to_string()), MapValue::Str(s));
    Ok(())
  }

  fn write_warning(&mut self, text: &str) -> Result<(), Infallible> {
    self.warnings.push(text.to_string());
    Ok(())
  }

  fn write_error(&mut self, text: &str) -> Result<(), Infallible> {
    self.errors.push(text.to_string());
    Ok(())
  }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn new_is_empty() {
    let w = MapTagWriter::new();
    assert!(w.is_empty());
    assert_eq!(w.len(), 0);
    assert!(w.warnings().is_empty());
    assert!(w.errors().is_empty());
  }

  #[test]
  fn last_write_wins_per_key() {
    // BTreeMap insert replaces — verifies the documented behavior of
    // duplicate (group, name) keys (last-write-wins; useful for tests
    // building up Meta in stages).
    let mut w = MapTagWriter::new();
    w.write_str("G", "N", "first").unwrap();
    w.write_str("G", "N", "second").unwrap();
    assert_eq!(
      w.get("G", "N").map(MapValue::as_str),
      Some("second".to_string())
    );
    assert_eq!(w.len(), 1);
  }

  #[test]
  fn numeric_variants_round_trip() {
    let mut w = MapTagWriter::new();
    w.write_u64("G", "U", 100).unwrap();
    w.write_i64("G", "I", -100).unwrap();
    w.write_f64("G", "F", 1.5).unwrap();
    assert_eq!(w.get("G", "U"), Some(&MapValue::U64(100)));
    assert_eq!(w.get("G", "I"), Some(&MapValue::I64(-100)));
    assert_eq!(w.get("G", "F"), Some(&MapValue::F64(1.5)));
  }

  #[test]
  fn bytes_variant_round_trips_and_renders_hex() {
    let mut w = MapTagWriter::new();
    w.write_bytes("G", "B", &[0xde, 0xad, 0xbe, 0xef]).unwrap();
    assert_eq!(
      w.get("G", "B"),
      Some(&MapValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef]))
    );
    assert_eq!(
      w.get("G", "B").map(MapValue::as_str),
      Some("deadbeef".to_string())
    );
  }

  #[test]
  fn write_fmt_streams_into_string() {
    let mut w = MapTagWriter::new();
    w.write_fmt("G", "Fmt", |f| write!(f, "{:04}:{:02}:{:02}", 2026, 5, 21))
      .unwrap();
    assert_eq!(
      w.get("G", "Fmt").map(MapValue::as_str),
      Some("2026:05:21".to_string())
    );
  }

  #[test]
  fn warnings_and_errors_preserve_order() {
    let mut w = MapTagWriter::new();
    w.write_warning("w1").unwrap();
    w.write_warning("w2").unwrap();
    w.write_error("e1").unwrap();
    assert_eq!(w.warnings(), &["w1".to_string(), "w2".to_string()]);
    assert_eq!(w.errors(), &["e1".to_string()]);
  }

  #[test]
  fn iter_visits_all_tags() {
    let mut w = MapTagWriter::new();
    w.write_str("A", "Name1", "v1").unwrap();
    w.write_str("B", "Name2", "v2").unwrap();
    let collected: Vec<_> = w.iter().collect();
    assert_eq!(collected.len(), 2);
    // BTreeMap orders by key: ("A","Name1") < ("B","Name2").
    assert_eq!(collected[0].0, "A");
    assert_eq!(collected[1].0, "B");
  }

  /// `write_str_list` on the default `MapTagWriter` falls through to the
  /// trait's default impl (per-element `write_str`). The BTreeMap's
  /// last-write-wins means only the final element is observable; this is
  /// the documented behavior for non-list-aware sinks.
  #[test]
  fn map_tag_writer_write_str_list_uses_default_impl_last_write_wins() {
    let mut w = MapTagWriter::new();
    w.write_str_list("G", "N", &["a", "b", "c"]).unwrap();
    assert_eq!(w.get("G", "N").map(MapValue::as_str), Some("c".to_string()));
  }
}
