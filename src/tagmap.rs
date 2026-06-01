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
  collections::HashMap,
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
///
/// ## Storage (Golden-v2 P1 — O(1) dedup, key built once at serialize)
///
/// Entries are stored as the `(family1, name, value)` TRIPLE in
/// first-occurrence order, with a side index `HashMap<(family1, name) → idx>`
/// for O(1) last-wins dedup. The previous design keyed dedup on a per-insert
/// `format!("{group}:{name}")` `SmolStr` and resolved duplicates via an O(n)
/// linear scan (O(n²) over a walk); this builds NO `"g:n"` string at insert
/// time — the two short `SmolStr`s (`family1`, `name`, both usually inline so
/// the clone is a memcpy, not a heap alloc) ARE the key. The combined
/// `"<family1>:<name>"` JSON key is materialized ONCE per surviving entry at
/// serialization (the two consumers — [`crate::parser::extract_info`] and
/// [`crate::Rendered`] — build it from [`entries`](Self::entries)), not per
/// emission. Net per-insert: one `HashMap` probe + (on a new key) two inline
/// `SmolStr` clones, vs the old heap `format!` + a growing linear scan.
pub(crate) struct TagMap {
  /// `(family1, name, value)` in first-occurrence order; the latest value for a
  /// repeated `(family1, name)` replaces in place (faithful `FoundTag`
  /// last-wins, keeping first-occurrence POSITION — `ExifTool.pm:9437-9519`).
  entries: Vec<(SmolStr, SmolStr, TagValue)>,
  /// `(family1, name) → index into `entries`` for O(1) dedup. The key clones
  /// the two short `SmolStr`s (inline for ≤23 bytes — no heap), so the dedup
  /// probe never builds the `"g:n"` string the old design allocated per insert.
  index: HashMap<(SmolStr, SmolStr), usize>,
  warnings: Vec<String>,
  errors: Vec<String>,
}

impl TagMap {
  /// An empty sink.
  pub(crate) fn new() -> Self {
    Self {
      entries: Vec::new(),
      index: HashMap::new(),
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
    // O(1) dedup on the `(family1, name)` PAIR — no `"g:n"` string is built here
    // (it is materialized once per surviving entry at serialization). The probe
    // key clones the two `SmolStr`s; tag groups + names are short identifiers
    // (`"EXIF"`/`"IFD0"`/`"Canon"`, `"MakerNoteVersion"` — all ≤23 bytes), so
    // `SmolStr::new` stores them INLINE (a memcpy, NO heap allocation). On a
    // MISS the freshly-built key is moved straight into the index + entries (no
    // re-clone); on a HIT the latest value replaces in place, keeping
    // first-occurrence POSITION (faithful `FoundTag` last-wins).
    let key = (SmolStr::new(group), SmolStr::new(name));
    if let Some(&idx) = self.index.get(&key) {
      self.entries[idx].2 = value;
      return;
    }
    let idx = self.entries.len();
    self.entries.push((key.0.clone(), key.1.clone(), value));
    self.index.insert(key, idx);
  }

  // The `write_*` surface returns `Result<(), Infallible>` so the typed
  // `Meta::serialize_tags` bodies keep their `?`-propagation and `Ok(())`
  // unchanged from the old `MetaSinker::sink<W: TagWriter>` impls (a pure
  // signature swap, not a body rewrite). `Infallible` lets the compiler
  // eliminate the error branch.

  // `write_str` / `write_u64` / `write_i64` / `write_f64` / `write_fmt`: with
  // EXIF's `File:ExifByteOrder` folded into `ExifMeta::tags()` (the LAST
  // production `write_str` caller — it now emits an `EmittedTag` carrying a
  // pre-built `TagValue::Str` through the golden engine), NO lib-build caller
  // remains for ANY of these per-type writers — every production tag now flows
  // through `write_value` (carrying a pre-built [`TagValue`]). Their only
  // surviving callers are test code: the `#[cfg(test)]` `ExifSink for TagMap`
  // impl ([`crate::exif`]) and the ID3v1 differential test in
  // `formats::id3::process`. Gated `#[cfg(all(test, feature = "alloc"))]` to
  // match those callers exactly (mirrors the same-reason gate on the
  // `ExifSink for TagMap` test impl) so the lib build carries no dead code.

  /// Emit a `&str` value.
  #[cfg(all(test, feature = "alloc"))]
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
  #[cfg(all(test, feature = "alloc"))]
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
  #[cfg(all(test, feature = "alloc"))]
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
  #[cfg(all(test, feature = "alloc"))]
  pub(crate) fn write_f64(
    &mut self,
    group: &str,
    name: &str,
    value: f64,
  ) -> Result<(), Infallible> {
    self.insert(group, name, TagValue::F64(value));
    Ok(())
  }

  /// Format directly into a `String`, then emit as a `&str` value. The
  /// no-alloc workhorse on the old sink; the typed store holds an owned value,
  /// so the single allocation happens here.
  #[cfg(all(test, feature = "alloc"))]
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

  /// Emit a pre-built [`TagValue`] directly (no per-type conversion). The
  /// MakerNotes typed-vendor parsers ([`crate::exif::makernotes::vendors`])
  /// produce already-typed values (the per-tag PrintConv has run), so
  /// `write_value` is the right sink for them.
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

  /// The collected format-tag entries `(family1, name, value)` in
  /// first-occurrence order (last-wins dedup already applied). The consumer
  /// builds the `"<family1>:<name>"` JSON key ONCE per entry here (not per
  /// emission). Slice view of the backing `Vec` (§3: never expose `&Vec<T>`).
  #[inline(always)]
  pub(crate) const fn entries(&self) -> &[(SmolStr, SmolStr, TagValue)] {
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

  /// Look up an emitted tag's [`TagValue`] by `(family1, name)` (test-only
  /// read-back, mirrors the retired `MapTagWriter::get`). `None` if never
  /// emitted. Uses the O(1) dedup index.
  #[cfg(test)]
  pub(crate) fn get(&self, group: &str, name: &str) -> Option<&TagValue> {
    let key = (SmolStr::new(group), SmolStr::new(name));
    self.index.get(&key).map(|&idx| &self.entries[idx].2)
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
      TagValue::List(_) => std::format!("{v:?}"),
    })
  }
}
