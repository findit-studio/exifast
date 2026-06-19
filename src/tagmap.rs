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

/// The pseudo-tag names whose duplicate-handling is FIRST-wins (priority-0)
/// rather than the default last-wins. `Warning` and `Error` are defined in
/// `Image::ExifTool::Extra` with `Priority => 0` (ExifTool.pm:1290/1299), and
/// every other place a `Warning`/`Error` tag is produced (e.g. the Matroska
/// `StdTag` SimpleTag table, `PRIORITY => 0`, Matroska.pm:752) is likewise
/// priority-0. ExifTool's duplicate handler never lets a priority-0 tag
/// override an existing same-`family1:name` tag (ExifTool.pm:9544-9560 — the
/// new value is shunted to a numbered `Warning (n)` key) and the default
/// (`%noDups`) output keeps the FIRST-extracted one by file order
/// (ExifTool.pm:5404-5417). See [`TagMap::insert`].
///
/// This is the NAME fallback for the general per-tag priority threaded through
/// [`TagMap::insert`]: even when a `Warning`/`Error` reaches the sink with the
/// default `priority == 1` (its producers do not yet thread a `Priority => 0`),
/// the insert forces its EFFECTIVE priority to `0` so the faithful first-wins is
/// preserved. A producer MAY also pass `priority == 0` explicitly; both routes
/// agree.
#[inline]
fn is_priority_zero_pseudo_tag(name: &str) -> bool {
  name == "Warning" || name == "Error"
}

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
  /// `(doc, family1, name, priority, value)` in first-occurrence order. A
  /// repeated `(doc, family1, name)` overrides the stored `(priority, value)`
  /// in place IFF the NEW duplicate's effective priority is non-zero AND `>=`
  /// the stored priority (ExifTool's general duplicate rule,
  /// `ExifTool.pm:9544-9560`); first-occurrence POSITION is always kept
  /// (`ExifTool.pm:9437-9519`). For an ordinary tag (priority `1`) this is the
  /// faithful last-wins; a `Priority => 0` duplicate (e.g. `Warning`/`Error`)
  /// never overrides. The leading `doc` is the family-3 sub-document index (`0`
  /// = Main); it widens the dedup identity so a sub-document tag (`Doc<N>`)
  /// never collides with the same `family1:name` in another document. The
  /// stored `priority` is the SURVIVING entry's priority, so a later same-key
  /// duplicate is compared against the value that currently occupies the slot.
  entries: Vec<(u32, SmolStr, SmolStr, u8, TagValue)>,
  /// `(doc, family1, name) → index into `entries`` for O(1) dedup. The key
  /// clones the two short `SmolStr`s (inline for ≤23 bytes — no heap), so the
  /// dedup probe never builds the `"g:n"` string the old design allocated per
  /// insert. The leading `doc` keeps per-sub-document tags distinct.
  index: HashMap<(u32, SmolStr, SmolStr), usize>,
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
  /// last COMM).
  ///
  /// **General `Priority => N` duplicate rule (`ExifTool.pm:9544-9560`).** Each
  /// tag carries a `priority` (default `1`); a producer marks a `Priority => 0`
  /// tag by passing `0`. The effective priority is forced to `0` for the
  /// `Warning`/`Error` pseudo-tags (the [`is_priority_zero_pseudo_tag`] name
  /// fallback) so they stay first-wins even when their producer still passes the
  /// default `1`. On a key HIT the NEW duplicate REPLACES the stored
  /// `(priority, value)` IFF `(effective_priority != 0) && (effective_priority
  /// >= stored_priority)` — ExifTool forces a stored tag's priority to at least
  /// `1` (`ExifTool.pm:9553`), so a `Priority => 0` duplicate can never override
  /// (`0 >= 1` is false → the new value is shunted to a numbered key) and the
  /// render `%noDups` then keeps the FIRST-extracted by file order
  /// (`ExifTool.pm:5404-5417`). First-occurrence POSITION is always preserved.
  ///
  /// For an ordinary tag (priority `1` vs stored `1`) this reduces to the
  /// faithful last-wins (`1 >= 1` ⇒ replace), unchanged from before per-tag
  /// priority existed. The documented colliding case is the pseudo-tags
  /// `Warning` / `Error` (`Priority => 0`, ExifTool.pm:1290/1299; a Matroska
  /// SimpleTag `StdTag` table is `PRIORITY => 0`, Matroska.pm:752): both are
  /// effective-priority-0, so a HIT is a NO-OP (the first-extracted value
  /// stays), and ExifTool.pm:9542 spells it out: "never override a Warning tag".
  /// The group-scoped diagnostic and the real same-group `Warning`/`Error`
  /// therefore both ride the in-stream `tags()` path so their FoundTag order is
  /// faithful (the survivor is whichever the walk reached FIRST). Pinned by the
  /// `Matroska_warning_collision*.mkv` goldens.
  fn insert(&mut self, doc: u32, group: &str, name: &str, priority: u8, value: TagValue) {
    // O(1) dedup on the `(doc, family1, name)` TRIPLE — no `"g:n"` string is
    // built here (it is materialized once per surviving entry at serialization).
    // The probe key clones the two `SmolStr`s; tag groups + names are short
    // identifiers (`"EXIF"`/`"IFD0"`/`"Canon"`, `"MakerNoteVersion"` — all ≤23
    // bytes), so `SmolStr::new` stores them INLINE (a memcpy, NO heap
    // allocation). On a MISS the freshly-built key is moved straight into the
    // index + entries (no re-clone); on a HIT the latest value replaces in
    // place, keeping first-occurrence POSITION (faithful `FoundTag` last-wins) —
    // EXCEPT for the priority-0 `Warning`/`Error` pseudo-tags, where a HIT keeps
    // the FIRST-extracted value (see the doc comment). The leading `doc` keeps a
    // sub-document tag (`Doc<N>`) distinct from the same `family1:name` in
    // another document; the `Warning`/`Error` first-wins exception stays keyed
    // on `name` only (doc-agnostic — correct, it never overrides regardless).
    // The `Warning`/`Error` name fallback forces effective priority to `0` even
    // when the producer passed the default `1`, preserving their first-wins.
    let effective_priority = if is_priority_zero_pseudo_tag(name) {
      0
    } else {
      priority
    };
    let key = (doc, SmolStr::new(group), SmolStr::new(name));
    if let Some(&idx) = self.index.get(&key) {
      // ExifTool's general rule: a NEW duplicate overrides the stored entry IFF
      // its effective priority is non-zero AND `>=` the stored (`>= 1`) priority
      // (`ExifTool.pm:9544-9560`). A `Priority => 0` duplicate never overrides.
      let stored_priority = self.entries[idx].3;
      if effective_priority != 0 && effective_priority >= stored_priority {
        self.entries[idx].3 = effective_priority;
        self.entries[idx].4 = value;
      }
      return;
    }
    let idx = self.entries.len();
    self.entries.push((
      key.0,
      key.1.clone(),
      key.2.clone(),
      effective_priority,
      value,
    ));
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
    self.insert(0, group, name, 1, TagValue::Str(value.into()));
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
    self.insert(0, group, name, 1, TagValue::U64(value));
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
    self.insert(0, group, name, 1, TagValue::I64(value));
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
    self.insert(0, group, name, 1, TagValue::F64(value));
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
    self.insert(0, group, name, 1, TagValue::Str(s.into()));
    Ok(())
  }

  /// Emit a pre-built [`TagValue`] directly (no per-type conversion). The
  /// MakerNotes typed-vendor parsers ([`crate::exif::makernotes::vendors`])
  /// produce already-typed values (the per-tag PrintConv has run), so
  /// `write_value` is the right sink for them. XMP also routes through it: its
  /// typed `Meta` already produces a finished value tree — a nested
  /// [`TagValue::Map`]/[`TagValue::List`] assembled by the parser's own
  /// struct-rebuild pass (`RestoreStruct`, XMPStruct.pl:708).
  pub(crate) fn write_value(
    &mut self,
    group: &str,
    name: &str,
    value: TagValue,
  ) -> Result<(), Infallible> {
    // The non-`-ee` value path: Main document (`doc == 0`), ExifTool's default
    // duplicate `Priority => 1` (`ExifTool.pm:9553`).
    self.insert(0, group, name, 1, value);
    Ok(())
  }

  /// Emit a pre-built [`TagValue`] under a specific family-3 sub-document
  /// (`doc==0` is Main) with an explicit ExifTool `Priority => N`. The doc
  /// widens the dedup identity so a per-sample (`Doc<N>`) tag never collides
  /// with the same `family1:name` in another document — the doc-aware entry
  /// point for the emission engine + the timed-metadata (`-ee`) walkers. The
  /// `priority` threads the tag's `Priority => N` into the general
  /// duplicate-override rule (`ExifTool.pm:9544-9560`); ordinary tags pass `1`.
  pub(crate) fn write_value_doc(
    &mut self,
    doc: u32,
    group: &str,
    name: &str,
    priority: u8,
    value: TagValue,
  ) -> Result<(), Infallible> {
    self.insert(doc, group, name, priority, value);
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

  /// The collected format-tag entries `(doc, family1, name, priority, value)`
  /// in first-occurrence order (the priority-aware dedup already applied). The
  /// consumer builds the JSON key ONCE per entry here via
  /// [`crate::serialize_key::group_key`] (not per emission) — `-G1` collapses
  /// the leading `doc`, `-G3` renders it as a `Doc<N>:` prefix; the `priority`
  /// is dedup bookkeeping the consumers ignore. Slice view of the backing `Vec`
  /// (§3: never expose `&Vec<T>`).
  #[inline(always)]
  pub(crate) const fn entries(&self) -> &[(u32, SmolStr, SmolStr, u8, TagValue)] {
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
    let key = (0u32, SmolStr::new(group), SmolStr::new(name));
    self.index.get(&key).map(|&idx| &self.entries[idx].4)
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

#[cfg(all(test, feature = "alloc"))]
mod tests {
  use super::*;

  #[test]
  fn tagmap_dedup_is_doc_aware() {
    let mut m = TagMap::new();
    m.write_value_doc(1, "QuickTime", "GPSLatitude", 1, TagValue::F64(47.0))
      .unwrap();
    m.write_value_doc(2, "QuickTime", "GPSLatitude", 1, TagValue::F64(-33.0))
      .unwrap();
    m.write_value_doc(0, "QuickTime", "TimeScale", 1, TagValue::U64(600))
      .unwrap();
    m.write_value_doc(0, "QuickTime", "TimeScale", 1, TagValue::U64(1000))
      .unwrap();
    assert_eq!(m.entries().len(), 3);
    let doc2 = m.entries().iter().filter(|(d, _, _, _, _)| *d == 2).count();
    assert_eq!(doc2, 1);
  }

  /// The general ExifTool `Priority => N` duplicate rule
  /// (`ExifTool.pm:9544-9560`): a NEW duplicate of an already-present
  /// `(doc, family1, name)` overrides the stored value IFF its priority is
  /// non-zero AND `>=` the stored one.
  #[test]
  fn tagmap_priority_dedup_general_rule() {
    // (a) Higher priority OVERRIDES the lower (2 >= 1, non-zero) ⇒ last wins.
    let mut m = TagMap::new();
    m.insert(0, "G", "P", 1, TagValue::U64(1));
    m.insert(0, "G", "P", 2, TagValue::U64(2));
    assert_eq!(m.get("G", "P"), Some(&TagValue::U64(2)));

    // (a') ...and the SURVIVING priority is the higher one, so a later
    // priority-1 duplicate can NOT override it (1 >= 2 is false).
    m.insert(0, "G", "P", 1, TagValue::U64(3));
    assert_eq!(m.get("G", "P"), Some(&TagValue::U64(2)));

    // (b) A priority-0 duplicate NEVER overrides (0 != 0 is false) ⇒ first wins.
    let mut m = TagMap::new();
    m.insert(0, "G", "Q", 1, TagValue::U64(10));
    m.insert(0, "G", "Q", 0, TagValue::U64(99));
    assert_eq!(m.get("G", "Q"), Some(&TagValue::U64(10)));

    // (b') Two priority-0 entries: neither overrides (`0 != 0` is false), so the
    // first-extracted wins — the `Warning`/`Error` collision case.
    let mut m = TagMap::new();
    m.insert(0, "G", "R", 0, TagValue::U64(1));
    m.insert(0, "G", "R", 0, TagValue::U64(2));
    assert_eq!(m.get("G", "R"), Some(&TagValue::U64(1)));

    // (c) Two ordinary priority-1 entries ⇒ faithful last-wins (1 >= 1).
    let mut m = TagMap::new();
    m.insert(0, "G", "S", 1, TagValue::U64(1));
    m.insert(0, "G", "S", 1, TagValue::U64(2));
    assert_eq!(m.get("G", "S"), Some(&TagValue::U64(2)));

    // (d) The `Warning`/`Error` NAME fallback: a producer passing the default
    // priority `1` still gets effective-priority-0 first-wins.
    let mut m = TagMap::new();
    m.insert(0, "G", "Warning", 1, TagValue::Str("first".into()));
    m.insert(0, "G", "Warning", 1, TagValue::Str("second".into()));
    assert_eq!(m.get("G", "Warning"), Some(&TagValue::Str("first".into())));

    // First-occurrence POSITION is always preserved across overrides.
    let mut m = TagMap::new();
    m.insert(0, "G", "A", 1, TagValue::U64(1));
    m.insert(0, "G", "B", 1, TagValue::U64(1));
    m.insert(0, "G", "A", 2, TagValue::U64(9)); // overrides A in place
    let names: std::vec::Vec<&str> = m
      .entries()
      .iter()
      .map(|(_, _, n, _, _)| n.as_str())
      .collect();
    assert_eq!(names, ["A", "B"]);
  }
}
