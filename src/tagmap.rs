// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! [`TagMap`] — the single inline tag-collection sink for the typed-Meta
//! rendering path.
//!
//! It replaces the deleted `TagWriter`/`MetaSinker` trait pair and the
//! `JsonTagWriter`/`MapTagWriter` collector structs: each typed `Meta`'s
//! `serialize_tags(print_conv, &mut TagMap)` inherent method emits its
//! `(Group1, Name, value)` triples here, and [`TagMap`] folds them into an
//! ordered `(("<Group1>:<Name>"), TagValue)` list with the faithful `%noDups`
//! first-wins dedup (`exiftool:2950-2951`) plus the `Warning`/`Error`
//! accumulators. The two consumers drain it:
//!
//! - [`crate::parser::extract_info`] (the `json` engine entry) serializes each
//!   stored [`TagValue`] into a `serde_json::Map` document.
//! - [`crate::Rendered`]'s `Serialize` impl (the `serde` `-j`/`-n` wrapper)
//!   emits each stored [`TagValue`] through any `serde::Serializer`'s map.
//!
//! ## Why a `(key, TagValue)` list and not a `serde_json::Map`
//!
//! [`TagMap`] is `alloc`-gated (NOT `json`-gated) so the `serde`-only
//! [`crate::Rendered`] wrapper — available with just `--features serde` — can
//! use it without pulling `serde_json`. The `serde_json::Map` shaping lives in
//! the `json`-gated [`crate::parser::extract_info`] consumer. Object KEY ORDER
//! and scalar TOKEN style are NOT load-bearing (the value-semantic
//! [`crate::jsondiff`] gate makes them irrelevant); only the SET of entries +
//! the first-wins dedup matter. The list preserves first-occurrence order for
//! determinism.
//!
//! ## No family-0
//!
//! Only the family-1 group reaches the `-G1` JSON key (`exiftool:2948`), so the
//! `group` argument every emitter passes IS the family-1 group and goes
//! straight into the key. The legacy `JsonTagWriter`'s family-0 override
//! existed only for the engine's read-back Composite-ingredient lookup
//! (APE.pm:84-87) — in the typed path the Composite is computed at PARSE time
//! from the structured sub-Metas, so no family-0 is needed at serialize time.
//!
//! Gated on `feature = "alloc"`: it stores owned strings + [`TagValue`].

#![cfg(feature = "alloc")]

use crate::value::TagValue;
use core::convert::Infallible;
use smol_str::SmolStr;
use std::{
  string::{String, ToString},
  vec::Vec,
};

/// The inline tag-collection sink a typed `Meta` emits its tags into. `%noDups`
/// first-wins on the `"<Group1>:<Name>"` key (`exiftool:2950-2951`): a later
/// emission of an already-present key is dropped. Warnings/errors accumulate in
/// call order; the document surfaces only the FIRST of each
/// (`ExifTool.pm:1288-1297`).
///
/// Private to the crate (constructed by [`crate::Rendered`]'s `Serialize` and
/// [`crate::parser::extract_info`]). NOT a public API surface.
pub(crate) struct TagMap {
  /// `("<Group1>:<Name>", value)` in first-occurrence order, first-wins.
  entries: Vec<(SmolStr, TagValue)>,
  warnings: Vec<String>,
  errors: Vec<String>,
}

impl TagMap {
  /// An empty sink.
  pub(crate) fn new() -> Self {
    Self {
      entries: Vec::new(),
      warnings: Vec::new(),
      errors: Vec::new(),
    }
  }

  /// Insert `value` under the `"<group>:<name>"` key with faithful `FoundTag`
  /// LAST-wins (a later emission of the same key REPLACES the earlier value in
  /// place, preserving first-occurrence POSITION — ExifTool.pm:9437-9519). This
  /// is the net of the legacy `JsonTagWriter`'s push-stage last-wins (on the
  /// full `(family0, family1, name)` identity) folded with the render-stage
  /// `%noDups` first-wins (on the `family1:name` token): in the typed path the
  /// key IS `family1:name` and every typed sink emits at most one family-0 per
  /// `family1:name`, so a repeated `family1:name` is ALWAYS the same-identity
  /// duplicate FoundTag would replace (e.g. AIFF duplicate `NAME` chunks →
  /// `AIFF:Name` keeps the LAST value, `AIFF_dup_name.aif`; multi-COMM →
  /// last COMM). No typed sink emits two DIFFERENT family-0 under one
  /// `family1:name`, so the render-stage first-wins never applies here.
  fn insert(&mut self, group: &str, name: &str, value: TagValue) {
    let key = SmolStr::new(std::format!("{group}:{name}"));
    if let Some(slot) = self.entries.iter_mut().find(|(k, _)| *k == key) {
      slot.1 = value; // last-wins, in place (keeps first-occurrence position)
      return;
    }
    self.entries.push((key, value));
  }

  // The `write_*` surface returns `Result<(), Infallible>` so the typed
  // `Meta::serialize_tags` bodies keep their `?`-propagation and `Ok(())`
  // unchanged from the old `MetaSinker::sink<W: TagWriter>` impls (a pure
  // signature swap, not a body rewrite). `Infallible` lets the compiler
  // eliminate the error branch.

  /// Emit a `&str` value.
  pub(crate) fn write_str(
    &mut self,
    group: &str,
    name: &str,
    value: &str,
  ) -> Result<(), Infallible> {
    self.insert(group, name, TagValue::Str(value.into()));
    Ok(())
  }

  /// Emit a `u64` value (EXACT — no saturation to `i64::MAX`).
  pub(crate) fn write_u64(
    &mut self,
    group: &str,
    name: &str,
    value: u64,
  ) -> Result<(), Infallible> {
    self.insert(group, name, TagValue::U64(value));
    Ok(())
  }

  /// Emit an `i64` value.
  pub(crate) fn write_i64(
    &mut self,
    group: &str,
    name: &str,
    value: i64,
  ) -> Result<(), Infallible> {
    self.insert(group, name, TagValue::I64(value));
    Ok(())
  }

  /// Emit an `f64` value.
  pub(crate) fn write_f64(
    &mut self,
    group: &str,
    name: &str,
    value: f64,
  ) -> Result<(), Infallible> {
    self.insert(group, name, TagValue::F64(value));
    Ok(())
  }

  /// Emit raw bytes (rendered as the no-`-b` binary placeholder by
  /// `TagValue::Bytes`'s `Serialize`).
  pub(crate) fn write_bytes(
    &mut self,
    group: &str,
    name: &str,
    value: &[u8],
  ) -> Result<(), Infallible> {
    self.insert(group, name, TagValue::Bytes(value.to_vec()));
    Ok(())
  }

  /// Format directly into a `String`, then emit as a `&str` value. The
  /// no-alloc workhorse on the old sink; the typed store holds an owned value,
  /// so the single allocation happens here.
  pub(crate) fn write_fmt(
    &mut self,
    group: &str,
    name: &str,
    f: impl FnOnce(&mut dyn core::fmt::Write) -> core::fmt::Result,
  ) -> Result<(), Infallible> {
    let mut s = String::new();
    let _ = f(&mut s); // in-memory String write cannot fail
    self.insert(group, name, TagValue::Str(s.into()));
    Ok(())
  }

  /// Emit a list of `&str` values for one key as a single `TagValue::List`
  /// (Vorbis ARTIST/PERFORMER/CONTACT coalesce, Vorbis.pm:85/86/94; faithful
  /// `FoundTag` promote-and-push, ExifTool.pm:9505-9520). First-wins on the
  /// key like every other emission. Each typed sink passes ALL values for the
  /// key in one call, so no cross-call coalescing is needed.
  pub(crate) fn write_str_list(
    &mut self,
    group: &str,
    name: &str,
    values: &[&str],
  ) -> Result<(), Infallible> {
    let items: Vec<TagValue> = values.iter().map(|v| TagValue::Str((*v).into())).collect();
    self.insert(group, name, TagValue::List(items));
    Ok(())
  }

  /// Emit a pre-built [`TagValue`] verbatim. Used by formats whose typed
  /// `Meta` already produces a finished value tree — e.g. XMP's
  /// structured (`-struct`) output, where a nested
  /// [`TagValue::Map`]/[`TagValue::List`] is assembled by the parser's
  /// own struct-rebuild pass (`RestoreStruct`, XMPStruct.pl:708).
  pub(crate) fn write_value(
    &mut self,
    group: &str,
    name: &str,
    value: TagValue,
  ) -> Result<(), Infallible> {
    self.insert(group, name, value);
    Ok(())
  }

  /// Record a `Warning` in occurrence order (`$self->Warn`, ExifTool.pm:1297).
  pub(crate) fn write_warning(&mut self, text: &str) -> Result<(), Infallible> {
    self.warnings.push(text.to_string());
    Ok(())
  }

  /// Record an `Error` in occurrence order (`$self->Error`, ExifTool.pm:5648).
  pub(crate) fn write_error(&mut self, text: &str) -> Result<(), Infallible> {
    self.errors.push(text.to_string());
    Ok(())
  }

  /// The collected format-tag entries (`"<Group1>:<Name>"`, value) in
  /// first-occurrence order (first-wins already applied). Slice view of the
  /// backing `Vec` (§3: never expose `&Vec<T>`).
  #[inline(always)]
  pub(crate) const fn entries(&self) -> &[(SmolStr, TagValue)] {
    self.entries.as_slice()
  }

  /// The FIRST recorded warning, if any (`ExifTool:Warning` under default `-j`).
  #[inline(always)]
  pub(crate) fn first_warning(&self) -> Option<&str> {
    self.warnings.first().map(String::as_str)
  }

  /// The FIRST recorded error, if any (`ExifTool:Error`).
  #[inline(always)]
  pub(crate) fn first_error(&self) -> Option<&str> {
    self.errors.first().map(String::as_str)
  }

  /// All recorded warnings in call order (test-only read-back).
  #[cfg(test)]
  pub(crate) fn warnings(&self) -> &[String] {
    &self.warnings
  }

  /// All recorded errors in call order (test-only read-back).
  #[cfg(test)]
  pub(crate) fn errors(&self) -> &[String] {
    &self.errors
  }

  /// Look up an emitted tag's [`TagValue`] by `(group, name)` — the
  /// `"<group>:<name>"` key (test-only read-back, mirrors the retired
  /// `MapTagWriter::get`). `None` if never emitted.
  #[cfg(test)]
  pub(crate) fn get(&self, group: &str, name: &str) -> Option<&TagValue> {
    let key = std::format!("{group}:{name}");
    self
      .entries
      .iter()
      .find(|(k, _)| k.as_str() == key)
      .map(|(_, v)| v)
  }

  /// `true` if no tags / warnings / errors were emitted (test-only).
  #[cfg(test)]
  pub(crate) fn is_empty(&self) -> bool {
    self.entries.is_empty() && self.warnings.is_empty() && self.errors.is_empty()
  }

  /// Render an emitted tag's value to its textual form — the test-only
  /// analogue of the retired `MapTagWriter`'s `MapValue::as_str` (`Str`
  /// verbatim; integers via `Display`; `F64` via `Display`; `Bytes` as lower
  /// hex). Lets the migrated format unit tests assert string-equality without
  /// rebuilding each `TagValue` literal. `None` if the key was never emitted.
  #[cfg(test)]
  pub(crate) fn get_str(&self, group: &str, name: &str) -> Option<String> {
    use core::fmt::Write as _;
    self.get(group, name).map(|v| match v {
      TagValue::Str(s) => s.to_string(),
      TagValue::U64(n) => n.to_string(),
      TagValue::I64(n) => n.to_string(),
      TagValue::F64(x) => {
        let mut s = String::new();
        let _ = write!(&mut s, "{x}");
        s
      }
      TagValue::Bool(b) => b.to_string(),
      TagValue::Bytes(b) => {
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
          let _ = write!(&mut s, "{byte:02x}");
        }
        s
      }
      TagValue::Rational(r) => {
        let mut s = String::new();
        let _ = write!(&mut s, "{}/{}", r.numerator(), r.denominator());
        s
      }
      TagValue::List(_) | TagValue::Map(_) => std::format!("{v:?}"),
    })
  }
}
