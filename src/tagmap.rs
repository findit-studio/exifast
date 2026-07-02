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
//! ## Family-0 is carried, but only the family-1 group reaches the JSON key
//!
//! Only the family-1 group reaches the `-G1` JSON key (`exiftool:2948`), so the
//! `group` argument every emitter passes IS the family-1 group and goes
//! straight into the key. Each entry ALSO carries its family-0 group as
//! METADATA (NOT part of the dedup key — the key stays
//! `(doc, doc_subpath, family1, name)`), so the family-0 carry is behavior-
//! preserving for the JSON/dedup path. Family-0 is read ONLY by the Composite
//! engine's `CompositeSink::resolve`, which needs it to match a family-0-
//! qualified ingredient (`Sony:GPSLatitude` resolves the entry whose family-0
//! is `Sony`, Sony.pm:10929) — the same lookup ExifTool's `GroupMatches` does
//! and the [`iter_tags`](crate::format_parser::AnyMeta::iter_tags) `Tag`-`Vec`
//! path already does (its full [`Group`](crate::value::Group) carries family-0).
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

/// A tag's EFFECTIVE `Priority => N` for the duplicate-override decision: the
/// producer's `priority`, forced to `0` for the `Warning`/`Error` pseudo-tags
/// (the [`is_priority_zero_pseudo_tag`] name fallback) so they stay first-wins
/// even when their producer still passes the default `1`. This is the SINGLE
/// definition both tag sinks compute through — [`TagMap::insert`] (the JSON /
/// golden path) and
/// [`collect_deduped_tags`](crate::format_parser::AnyMeta::collect_deduped_tags)
/// (the `iter_tags` / Composite `Tag`-`Vec` path) — so they cannot diverge on
/// what "effective priority" means (`ExifTool.pm:9553` forces an explicit-less
/// tag to `1`; `Warning`/`Error` are `Priority => 0`, ExifTool.pm:1290/1299).
#[inline]
pub(crate) fn effective_priority(name: &str, priority: u8) -> u8 {
  if is_priority_zero_pseudo_tag(name) {
    0
  } else {
    priority
  }
}

/// ExifTool's general duplicate-override decision (`ExifTool.pm:9544-9560`): a
/// NEW same-`(doc, family1, name)` duplicate REPLACES the stored survivor
/// (value + family-0 + priority travel together) IFF its effective priority is
/// non-zero AND `>=` the stored survivor's. A `Priority => 0` duplicate (e.g.
/// `Warning`/`Error`, or a `VP8`/`VP8L` `ImageWidth` that must not override a
/// `VP8X` canvas) can therefore never override — `%noDups` then keeps the
/// FIRST-extracted by file order (`ExifTool.pm:5404-5417`), i.e. first-wins.
/// For an ordinary tag (`1 >= 1`) this is the faithful last-wins.
///
/// The SINGLE override predicate both sinks call so they cannot diverge:
/// [`TagMap::insert`] (the JSON / golden path) and
/// [`collect_deduped_tags`](crate::format_parser::AnyMeta::collect_deduped_tags)
/// (the `iter_tags` / Composite `Tag`-`Vec` path). Both `new` and `stored` MUST
/// already be EFFECTIVE priorities ([`effective_priority`]).
#[inline]
pub(crate) fn dedup_override(new_effective: u8, stored_effective: u8) -> bool {
  new_effective != 0 && new_effective >= stored_effective
}

/// Whether a NEW [`EmittedTag`](crate::emit::EmittedTag) `new` overrides the
/// `stored` survivor occupying a `(family1, name)` slot, by ExifTool's general
/// duplicate rule — the SAME decision [`TagMap::insert`] and
/// [`collect_deduped_tags`](crate::format_parser::AnyMeta::collect_deduped_tags)
/// reach, expressed once over two `EmittedTag`s so the timed-metadata per-`Doc`
/// scratch collapses (the QuickTime `mebx`/Sony-rtmd/Canon-CTMD/camm/GoPro
/// within-sample folds) cannot hard-code a divergent predicate. It composes the
/// SHARED [`effective_priority`] (forcing `Warning`/`Error` to `0` by NAME, even
/// when their producer passed the default `1`) and [`dedup_override`], computing
/// each side's effective priority from the tag that currently occupies it — the
/// stored slot ALWAYS holds the running winner, so recomputing its effective
/// priority from its `(name, priority)` is identical to carrying it alongside
/// (exactly as `TagMap` stores the surviving entry's effective priority). A
/// `Priority => 0` row (a re-dispatched `Canon::ShotInfo` `FNumber`, or a
/// `Warning`/`Error`) therefore never overrides ⇒ first-wins; an ordinary
/// `Priority => 1` duplicate last-wins (`1 >= 1`).
#[cfg(feature = "alloc")]
#[inline]
pub(crate) fn emitted_dedup_override(
  new: &crate::emit::EmittedTag,
  stored: &crate::emit::EmittedTag,
) -> bool {
  dedup_override(
    effective_priority(new.tag().name(), new.priority()),
    effective_priority(stored.tag().name(), stored.priority()),
  )
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
  /// `(doc, doc_subpath, family1, name, priority, value, family0, seq)` in
  /// first-occurrence order. A repeated `(doc, doc_subpath, family1, name)`
  /// overrides the stored `(priority, value)` in place IFF the NEW duplicate's
  /// effective priority is non-zero AND `>=` the stored priority (ExifTool's
  /// general duplicate rule, `ExifTool.pm:9544-9560`); first-occurrence POSITION
  /// is always kept (`ExifTool.pm:9437-9519`). For an ordinary tag (priority
  /// `1`) this is the faithful last-wins; a `Priority => 0` duplicate (e.g.
  /// `Warning`/`Error`) never overrides. The leading `(doc, doc_subpath)` is the
  /// family-3 sub-document identity (`doc == 0` = Main; `doc_subpath` is the
  /// pre-rendered dash-joined tail beyond the first level — `""`, `"-1"`,
  /// `"-1-1"`, …); it widens the dedup identity so a sub-document tag (`Doc<N>`,
  /// `Doc<N>-<M>`, `Doc<N>-<M>-<P>`) never collides with the same `family1:name`
  /// in another document, INCLUDING a deep JUMBF nest (`Doc1-1-1`) vs a
  /// shallower one (`Doc1-1`). The stored `priority` is the SURVIVING entry's
  /// priority, so a later same-key duplicate is compared against the value that
  /// currently occupies the slot.
  ///
  /// `family0` is carried as METADATA — it is NOT part of the dedup key (the
  /// key stays `(doc, doc_subpath, family1, name)`, exactly as before), so adding it
  /// is BEHAVIOR-PRESERVING: which duplicates collapse, and which value/position
  /// survives, are unchanged. It exists ONLY so the Composite engine can resolve
  /// a family-0-qualified input (`Sony:GPSLatitude` matches the entry whose
  /// family-0 is `Sony` — Sony.pm:10929) the same way the
  /// [`iter_tags`](crate::format_parser::AnyMeta::iter_tags) `Tag`-`Vec` path
  /// does (where the full [`Group`](crate::value::Group) carries it). Appended
  /// LAST so the existing positional dedup fields keep their indices. The
  /// SURVIVING entry's `family0` is the WINNER's: a same-key duplicate that wins
  /// the last-wins override replaces `(priority, value)` AND `family0` together
  /// (so the family0 tracks the value that survived dedup), exactly as the
  /// `Tag`-`Vec` sink REPLACES the whole tag (`*slot = tag`). This keeps the two
  /// sinks' family-0-qualified Composite resolution identical even when a
  /// duplicate shares the rendered `family1:name` but carries a DIFFERENT
  /// family-0 (the video track-scoped Sony/QuickTime/GoPro case). A priority-0
  /// `Warning`/`Error` duplicate never wins, so its slot keeps the first
  /// (surviving) family0 — also consistent.
  ///
  /// The trailing `seq` is the entry's WALK SEQUENCE: the value of
  /// [`next_seq`](Self::next_seq) at the [`insert`](Self::insert) that FIRST
  /// created this slot. It is assigned ONCE and never re-stamped — a later
  /// same-key duplicate that wins the last-wins override updates
  /// `(priority, value, family0)` but leaves `seq`, so `seq` increases strictly
  /// with first-occurrence POSITION. It exists so the bare-name Composite
  /// resolver can break an equal-effective-priority tie by walk order
  /// (`FoundTag`, ExifTool.pm:9564); today it reads the MIN `seq` among equals,
  /// which — because `seq` == position order — is exactly the first-inserted =
  /// first-emitted entry, i.e. BYTE-IDENTICAL to the pre-`seq` first-among-equals
  /// tiebreak and consistent with the `Vec<(Tag, u8)>` sink's positional index.
  /// #474 PR 2 flips the resolver to MAX `seq` for the faithful last-walked
  /// tiebreak, and re-stamps on a winning replace at that point.
  entries: Vec<(u32, SmolStr, SmolStr, SmolStr, u8, TagValue, SmolStr, u32)>,
  /// `(doc, doc_subpath, family1, name) → index into `entries`` for O(1) dedup.
  /// The key clones the short `SmolStr`s (inline for ≤23 bytes — no heap), so
  /// the dedup probe never builds the `"g:n"` string the old design allocated
  /// per insert. The leading `(doc, doc_subpath)` keeps per-sub-document tags
  /// distinct — INCLUDING a deep JUMBF nest (`Doc1-1-1`) vs a shallower one
  /// (`Doc1-1`), which the pre-rendered `doc_subpath` tail (`"-1-1"` vs `"-1"`)
  /// distinguishes.
  index: HashMap<(u32, SmolStr, SmolStr, SmolStr), usize>,
  warnings: Vec<String>,
  errors: Vec<String>,
  /// Monotonic walk-sequence counter: the `seq` stamped on the NEXT
  /// [`insert`](Self::insert), incremented once per `insert` call (so a slot's
  /// `seq` reflects its insertion order in the emission walk). See the `entries`
  /// `seq` field doc — it is the walk-order axis the bare-name Composite resolver
  /// uses to break equal-priority ties (min-`seq` today = first-emitted).
  next_seq: u32,
}

impl TagMap {
  /// An empty sink.
  pub(crate) fn new() -> Self {
    Self {
      entries: Vec::new(),
      index: HashMap::new(),
      warnings: Vec::new(),
      errors: Vec::new(),
      next_seq: 0,
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
  // The dedup identity (`doc`, `doc_subpath`, `group`/family1, `name`) + the
  // `priority`/`value` payload + the carried `family0` metadata are all distinct
  // per-tag inputs; bundling them into a struct would obscure the call sites.
  #[allow(clippy::too_many_arguments)]
  fn insert(
    &mut self,
    doc: u32,
    doc_subpath: &str,
    group: &str,
    name: &str,
    priority: u8,
    value: TagValue,
    family0: &str,
  ) {
    // O(1) dedup on the `(doc, doc_subpath, family1, name)` key — no `"g:n"`
    // string is built here (it is materialized once per surviving entry at
    // serialization). The probe key clones the short `SmolStr`s (`doc_subpath`
    // empty for almost every tag; tag groups + names are short identifiers —
    // `"EXIF"`/`"IFD0"`/`"Canon"`, `"MakerNoteVersion"` — all ≤23 bytes), so
    // `SmolStr::new` stores them INLINE (a memcpy, NO heap allocation). On a
    // MISS the freshly-built key is moved straight into the index + entries (no
    // re-clone); on a HIT the latest value replaces in place, keeping
    // first-occurrence POSITION (faithful `FoundTag` last-wins) — EXCEPT for the
    // priority-0 `Warning`/`Error` pseudo-tags, where a HIT keeps the
    // FIRST-extracted value (see the doc comment). The leading `(doc,
    // doc_subpath)` keeps a sub-document tag (`Doc<N>` / `Doc<N>-<M>` /
    // `Doc<N>-<M>-<P>`) distinct from the same `family1:name` in another
    // document — including a deep JUMBF nest (`Doc1-1-1`) vs a shallower one
    // (`Doc1-1`); the `Warning`/`Error` first-wins exception stays keyed on
    // `name` only (doc-agnostic — correct, it never overrides regardless). The
    // `Warning`/`Error` name fallback forces effective priority to `0` even when
    // the producer passed the default `1`, preserving their first-wins.
    let effective_priority = effective_priority(name, priority);
    // The walk-sequence stamp for THIS insertion (insertion order in the
    // emission walk). Consumed once per `insert` call — even a losing duplicate
    // (a no-op) advances the counter, so gaps are harmless: only the RELATIVE
    // order of surviving `seq`s matters to the resolver. `saturating_add` avoids
    // a debug overflow panic on a pathological tag count (well beyond the DoS
    // budget) while staying monotonic non-decreasing.
    let seq = self.next_seq;
    self.next_seq = self.next_seq.saturating_add(1);
    let key = (
      doc,
      SmolStr::new(doc_subpath),
      SmolStr::new(group),
      SmolStr::new(name),
    );
    if let Some(&idx) = self.index.get(&key) {
      // ExifTool's general rule, via the SHARED [`dedup_override`] predicate the
      // `Tag`-`Vec` sink (`collect_deduped_tags`) also calls: a NEW duplicate
      // overrides the stored entry IFF its effective priority is non-zero AND
      // `>=` the stored (`>= 1`) priority (`ExifTool.pm:9544-9560`). A
      // `Priority => 0` duplicate never overrides. When the duplicate WINS,
      // `(priority, value)` AND `family0` all travel together — the surviving
      // entry's family0 is the WINNER's, exactly as the `Tag`-`Vec` sink
      // REPLACES the whole tag (`*slot = tag`), so both sinks agree on a
      // family-0-qualified Composite match (`Sony:GPSLatitude`) under the same
      // input order. (Carrying only `(priority, value)` and leaving the
      // first-occurrence family0 would diverge whenever a duplicate has the same
      // rendered `family1:name` but a DIFFERENT family-0 — reachable on the video
      // path where track-scoped emitters share a `Track<N>` family-1 across Sony/
      // QuickTime/GoPro family-0.) When the duplicate LOSES (priority-0
      // `Warning`/`Error`, or a `VP8`/`VP8L` `ImageWidth` behind a `VP8X`
      // canvas), nothing is touched — the first family0 stays with the first
      // (surviving) value, also consistent.
      let stored_priority = self.entries[idx].4;
      if dedup_override(effective_priority, stored_priority) {
        self.entries[idx].4 = effective_priority;
        self.entries[idx].5 = value;
        self.entries[idx].6 = SmolStr::new(family0);
        // NOTE (#474 PR 1/2): `seq` is deliberately NOT re-stamped on a winning
        // replace, so an entry keeps its FIRST-insertion `seq` for its whole
        // life. That makes `seq` strictly increase with first-occurrence POSITION
        // (a later same-key duplicate never reorders `seq`), which is exactly
        // what keeps the bare-name resolver's MIN-`seq` tiebreak byte-identical to
        // the pre-`seq` first-among-equals — AND keeps it consistent with the
        // `Vec<(Tag, u8)>` sink, whose positional index is its `seq`. PR 2 flips
        // the resolver to MAX-`seq` for the faithful last-walked `FoundTag`
        // tiebreak (ExifTool.pm:9564) and, AT THAT POINT, re-stamps here so the
        // surviving `seq` tracks the last-walked contributor.
      }
      return;
    }
    let idx = self.entries.len();
    self.entries.push((
      key.0,
      key.1.clone(),
      key.2.clone(),
      key.3.clone(),
      effective_priority,
      value,
      SmolStr::new(family0),
      seq,
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
    self.insert(0, "", group, name, 1, TagValue::Str(value.into()), group);
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
    self.insert(0, "", group, name, 1, TagValue::U64(value), group);
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
    self.insert(0, "", group, name, 1, TagValue::I64(value), group);
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
    self.insert(0, "", group, name, 1, TagValue::F64(value), group);
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
    self.insert(0, "", group, name, 1, TagValue::Str(s.into()), group);
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
    // duplicate `Priority => 1` (`ExifTool.pm:9553`). The two callers are the
    // group-scoped `<group>:Warning`/`<group>:Error` diagnostic tags
    // (`diagnostics.rs`), where ExifTool's `SET_GROUP1` IS the family-1 group;
    // family-0 is not meaningful for the Composite resolver here, so it mirrors
    // `group` (the Composite engine never resolves a `Warning`/`Error` input).
    self.insert(0, "", group, name, 1, value, group);
    Ok(())
  }

  /// Emit a pre-built [`TagValue`] under a specific family-3 sub-document
  /// (`doc==0` is Main) with an explicit ExifTool `Priority => N`. The doc
  /// widens the dedup identity so a per-sample (`Doc<N>`) tag never collides
  /// with the same `family1:name` in another document — the doc-aware entry
  /// point for the emission engine + the timed-metadata (`-ee`) walkers. The
  /// `priority` threads the tag's `Priority => N` into the general
  /// duplicate-override rule (`ExifTool.pm:9544-9560`); ordinary tags pass `1`.
  // The doc-aware dedup key + value + priority + the carried family-0 are
  // distinct per-tag inputs (see [`Self::insert`]); a struct would obscure the
  // `run_emission` / timed-walker call sites.
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn write_value_doc(
    &mut self,
    doc: u32,
    doc_subpath: &str,
    group: &str,
    name: &str,
    priority: u8,
    value: TagValue,
    family0: &str,
  ) -> Result<(), Infallible> {
    self.insert(doc, doc_subpath, group, name, priority, value, family0);
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

  /// The collected format-tag entries
  /// `(doc, doc_subpath, family1, name, priority, value, family0, seq)` in
  /// first-occurrence order (the priority-aware dedup already applied). The
  /// consumer builds the JSON key ONCE per entry here via
  /// [`crate::serialize_key::group_key`] (not per emission) — `-G1` collapses
  /// the leading `(doc, doc_subpath)`, `-G3` renders it as a `Doc<N>…:` prefix;
  /// the `priority`, `family0` and `seq` are dedup / Composite-resolution
  /// bookkeeping the JSON consumers ignore. Slice view of the backing `Vec`
  /// (§3: never expose `&Vec<T>`).
  #[inline(always)]
  pub(crate) const fn entries(
    &self,
  ) -> &[(u32, SmolStr, SmolStr, SmolStr, u8, TagValue, SmolStr, u32)] {
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
    let key = (
      0u32,
      SmolStr::default(),
      SmolStr::new(group),
      SmolStr::new(name),
    );
    self.index.get(&key).map(|&idx| &self.entries[idx].5)
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
      TagValue::Str(s) | TagValue::JsonStr(s) => s.to_string(),
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
    m.write_value_doc(
      1,
      "",
      "QuickTime",
      "GPSLatitude",
      1,
      TagValue::F64(47.0),
      "QuickTime",
    )
    .unwrap();
    m.write_value_doc(
      2,
      "",
      "QuickTime",
      "GPSLatitude",
      1,
      TagValue::F64(-33.0),
      "QuickTime",
    )
    .unwrap();
    m.write_value_doc(
      0,
      "",
      "QuickTime",
      "TimeScale",
      1,
      TagValue::U64(600),
      "QuickTime",
    )
    .unwrap();
    m.write_value_doc(
      0,
      "",
      "QuickTime",
      "TimeScale",
      1,
      TagValue::U64(1000),
      "QuickTime",
    )
    .unwrap();
    assert_eq!(m.entries().len(), 3);
    let doc2 = m
      .entries()
      .iter()
      .filter(|(d, _, _, _, _, _, _, _)| *d == 2)
      .count();
    assert_eq!(doc2, 1);
  }

  /// The dedup identity carries the FULL `doc_subpath` tail, so two distinct
  /// JUMBF nested superbox contents (`Doc1-1` vs `Doc1-1-1`, Jpeg2000.pm:786
  /// `DOC_NUM = join '-', @jumd_level`) NEVER collide — a 2-level `(doc,
  /// doc_sub)` key would collapse both onto `Doc1-1` and last-wins one away.
  #[test]
  fn tagmap_dedup_distinguishes_n_level_subpath() {
    let mut m = TagMap::new();
    m.write_value_doc(
      1,
      "-1",
      "JUMBF",
      "JUMDLabel",
      1,
      TagValue::Str("two".into()),
      "JUMBF",
    )
    .unwrap();
    m.write_value_doc(
      1,
      "-1-1",
      "JUMBF",
      "JUMDLabel",
      1,
      TagValue::Str("three".into()),
      "JUMBF",
    )
    .unwrap();
    // Distinct sub-paths ⇒ two SEPARATE entries (no collision / no data loss).
    assert_eq!(m.entries().len(), 2);
    // A SAME `(doc, doc_subpath, family1, name)` IS deduped (last-wins).
    m.write_value_doc(
      1,
      "-1-1",
      "JUMBF",
      "JUMDLabel",
      1,
      TagValue::Str("three-again".into()),
      "JUMBF",
    )
    .unwrap();
    assert_eq!(m.entries().len(), 2);
    let deep = m
      .entries()
      .iter()
      .find(|(d, sub, _, _, _, _, _, _)| *d == 1 && sub.as_str() == "-1-1")
      .expect("the Doc1-1-1 entry survives");
    assert_eq!(deep.5, TagValue::Str("three-again".into()));
  }

  /// The general ExifTool `Priority => N` duplicate rule
  /// (`ExifTool.pm:9544-9560`): a NEW duplicate of an already-present
  /// `(doc, family1, name)` overrides the stored value IFF its priority is
  /// non-zero AND `>=` the stored one.
  #[test]
  fn tagmap_priority_dedup_general_rule() {
    // (a) Higher priority OVERRIDES the lower (2 >= 1, non-zero) ⇒ last wins.
    let mut m = TagMap::new();
    m.insert(0, "", "G", "P", 1, TagValue::U64(1), "G");
    m.insert(0, "", "G", "P", 2, TagValue::U64(2), "G");
    assert_eq!(m.get("G", "P"), Some(&TagValue::U64(2)));

    // (a') ...and the SURVIVING priority is the higher one, so a later
    // priority-1 duplicate can NOT override it (1 >= 2 is false).
    m.insert(0, "", "G", "P", 1, TagValue::U64(3), "G");
    assert_eq!(m.get("G", "P"), Some(&TagValue::U64(2)));

    // (b) A priority-0 duplicate NEVER overrides (0 != 0 is false) ⇒ first wins.
    let mut m = TagMap::new();
    m.insert(0, "", "G", "Q", 1, TagValue::U64(10), "G");
    m.insert(0, "", "G", "Q", 0, TagValue::U64(99), "G");
    assert_eq!(m.get("G", "Q"), Some(&TagValue::U64(10)));

    // (b') Two priority-0 entries: neither overrides (`0 != 0` is false), so the
    // first-extracted wins — the `Warning`/`Error` collision case.
    let mut m = TagMap::new();
    m.insert(0, "", "G", "R", 0, TagValue::U64(1), "G");
    m.insert(0, "", "G", "R", 0, TagValue::U64(2), "G");
    assert_eq!(m.get("G", "R"), Some(&TagValue::U64(1)));

    // (c) Two ordinary priority-1 entries ⇒ faithful last-wins (1 >= 1).
    let mut m = TagMap::new();
    m.insert(0, "", "G", "S", 1, TagValue::U64(1), "G");
    m.insert(0, "", "G", "S", 1, TagValue::U64(2), "G");
    assert_eq!(m.get("G", "S"), Some(&TagValue::U64(2)));

    // (d) The `Warning`/`Error` NAME fallback: a producer passing the default
    // priority `1` still gets effective-priority-0 first-wins.
    let mut m = TagMap::new();
    m.insert(0, "", "G", "Warning", 1, TagValue::Str("first".into()), "G");
    m.insert(
      0,
      "",
      "G",
      "Warning",
      1,
      TagValue::Str("second".into()),
      "G",
    );
    assert_eq!(m.get("G", "Warning"), Some(&TagValue::Str("first".into())));

    // First-occurrence POSITION is always preserved across overrides.
    let mut m = TagMap::new();
    m.insert(0, "", "G", "A", 1, TagValue::U64(1), "G");
    m.insert(0, "", "G", "B", 1, TagValue::U64(1), "G");
    m.insert(0, "", "G", "A", 2, TagValue::U64(9), "G"); // overrides A in place
    let names: std::vec::Vec<&str> = m
      .entries()
      .iter()
      .map(|(_, _, _, n, _, _, _, _)| n.as_str())
      .collect();
    assert_eq!(names, ["A", "B"]);
  }

  /// On a same-key duplicate that WINS the override, the stored `family0` is
  /// REPLACED with the winner's — it tracks the value/priority that survived
  /// dedup, exactly as the `Tag`-`Vec` sink replaces the whole tag. This is the
  /// #133 two-sink-parity invariant: a duplicate sharing `(doc, family1, name)`
  /// but carrying a DIFFERENT family-0 (the video track-scoped Sony/QuickTime/
  /// GoPro case) must leave the survivor's family-0 = the winner's, so a
  /// family-0-qualified Composite (`Sony:GPSLatitude`) resolves identically
  /// across both sinks.
  #[test]
  fn override_carries_the_winners_family0() {
    // (a) The winner's family-0 travels with the winning value. `GoPro` first,
    // `Sony` wins last (priority 1 >= 1) ⇒ stored family-0 is now `Sony`.
    let mut m = TagMap::new();
    m.insert(
      1,
      "",
      "Track1",
      "GPSLatitude",
      1,
      TagValue::F64(11.0),
      "GoPro",
    );
    m.insert(
      1,
      "",
      "Track1",
      "GPSLatitude",
      1,
      TagValue::F64(47.6),
      "Sony",
    );
    let e = &m.entries()[0];
    assert_eq!(e.5, TagValue::F64(47.6), "winner's value survives");
    assert_eq!(e.6.as_str(), "Sony", "winner's family-0 travels with it");

    // (a') A higher-priority winner likewise carries its family-0.
    let mut m = TagMap::new();
    m.insert(0, "", "G", "P", 1, TagValue::U64(1), "First");
    m.insert(0, "", "G", "P", 2, TagValue::U64(2), "Second");
    assert_eq!(m.entries()[0].6.as_str(), "Second");

    // (b) A LOSING duplicate leaves the stored family-0 untouched (it stays with
    // the surviving FIRST value). Priority-0 `Warning`/`Error` never override.
    let mut m = TagMap::new();
    m.insert(0, "", "G", "Warning", 1, TagValue::Str("a".into()), "First");
    m.insert(
      0,
      "",
      "G",
      "Warning",
      1,
      TagValue::Str("b".into()),
      "Second",
    );
    let e = &m.entries()[0];
    assert_eq!(e.5, TagValue::Str("a".into()), "first Warning survives");
    assert_eq!(
      e.6.as_str(),
      "First",
      "the loser does NOT touch the survivor's family-0"
    );

    // (b') A lower-priority duplicate that loses (1 >= 2 is false) likewise
    // leaves the winner's family-0 in place.
    let mut m = TagMap::new();
    m.insert(0, "", "G", "P", 2, TagValue::U64(2), "Winner");
    m.insert(0, "", "G", "P", 1, TagValue::U64(9), "Loser");
    assert_eq!(m.entries()[0].6.as_str(), "Winner");
  }

  /// The [`emitted_dedup_override`] helper the timed-metadata per-`Doc` scratch
  /// collapses (`mebx`/Sony-rtmd/Canon-CTMD/camm/GoPro within-sample folds) call
  /// reproduces the SAME decision [`TagMap::insert`] reaches, proven here for the
  /// Canon-CTMD priority-0 class: a `new` row overrides the `stored` survivor IFF
  /// the shared rule says so. A raw `tag.priority() != 0 && tag.priority() >=
  /// slot.priority()` predicate would MISS the `Warning`/`Error` NAME ⇒
  /// effective-priority-0 fallback; routing through [`effective_priority`] makes
  /// a `Warning`/`Error` carrying the default priority `1` first-win regardless.
  #[test]
  fn emitted_dedup_override_matches_the_shared_rule() {
    use crate::emit::EmittedTag;
    use crate::value::Group;
    let tag = |name: &str, prio: u8| {
      EmittedTag::new_with_priority(
        Group::new("Canon", "Track1"),
        name.into(),
        TagValue::F64(1.0),
        false,
        prio,
      )
    };

    // (1) The CTMD case: a re-dispatched `ShotInfo` `FNumber` (`Priority => 0`)
    // does NOT override this sample's earlier `ExposureInfo` `FNumber`
    // (`Priority => 1`) — the survivor the existing CTMD fixtures show.
    let exposure_fnumber = tag("FNumber", 1);
    let shotinfo_fnumber = tag("FNumber", 0);
    assert!(
      !emitted_dedup_override(&shotinfo_fnumber, &exposure_fnumber),
      "a Priority=>0 ShotInfo FNumber must NOT override the Priority=>1 ExposureInfo FNumber"
    );

    // (2) The edge the old raw-`priority()` check MISSED: a CTMD scratch
    // `Warning` reaches the fold with the DEFAULT priority `1`, but its NAME
    // forces effective-priority-0 ⇒ it must NOT override (first-wins), matching
    // the final sinks. The old `1 != 0 && 1 >= 1` predicate would WRONGLY have
    // let it override.
    let warning_first = tag("Warning", 1);
    let warning_second = tag("Warning", 1);
    assert!(
      !emitted_dedup_override(&warning_second, &warning_first),
      "a later Warning (effective-priority-0 by name) must first-win, not override"
    );
    // Same for `Error`.
    let error_first = tag("Error", 1);
    let error_second = tag("Error", 1);
    assert!(!emitted_dedup_override(&error_second, &error_first));

    // (3) An ordinary `Priority => 1` duplicate last-wins (`1 >= 1`).
    let gps_first = tag("GPSLatitude", 1);
    let gps_second = tag("GPSLatitude", 1);
    assert!(
      emitted_dedup_override(&gps_second, &gps_first),
      "an ordinary Priority=>1 duplicate last-wins"
    );

    // (4) A higher-priority duplicate overrides; the survivor's (recomputed)
    // effective priority then blocks a later lower-priority one — the same
    // running-winner behaviour `TagMap::insert` shows (it stores the winner's
    // effective priority; this helper recomputes it from the slot's tag).
    let stored_p2 = tag("ISO", 2);
    let new_p1 = tag("ISO", 1);
    assert!(
      !emitted_dedup_override(&new_p1, &stored_p2),
      "a Priority=>1 duplicate must NOT override a stored Priority=>2 survivor"
    );
  }

  /// #474 PR 1 — the per-entry walk-`seq`. It is a monotonic insertion counter
  /// stamped ONCE at an entry's first insertion and NEVER re-stamped, so it
  /// tracks first-occurrence order (this is what keeps the bare-name Composite
  /// resolver's MIN-`seq` tiebreak byte-identical to the pre-`seq` first-among-
  /// equals). Reading `entries()[i].7` — the private `seq` slot — from the test
  /// module (same crate) is fine.
  #[test]
  fn walk_seq_is_the_first_insertion_order_and_not_restamped() {
    let seq_of = |m: &TagMap, name: &str| -> u32 {
      m.entries()
        .iter()
        .find(|e| e.3.as_str() == name)
        .expect("entry present")
        .7
    };

    // (a) Distinct keys get strictly increasing `seq`s in insertion order.
    let mut m = TagMap::new();
    m.insert(0, "", "G", "A", 1, TagValue::U64(1), "G");
    m.insert(0, "", "G", "B", 1, TagValue::U64(2), "G");
    m.insert(0, "", "G", "C", 1, TagValue::U64(3), "G");
    let seqs: std::vec::Vec<u32> = m.entries().iter().map(|e| e.7).collect();
    assert_eq!(seqs, [0, 1, 2], "seq is the monotonic insertion order");

    // (b) A last-wins REPLACE (ordinary priority `1 >= 1`) updates the value but
    // KEEPS the slot's FIRST-insertion `seq` (NOT re-stamped) — the keep-first
    // invariant that guarantees min-seq ≡ first-emitted. The counter still
    // advanced (the next new key gets `seq == 4`, not `3`).
    m.insert(0, "", "G", "A", 1, TagValue::U64(99), "G"); // wins, replaces A's value
    assert_eq!(seq_of(&m, "A"), 0, "winning replace keeps the FIRST seq");
    assert_eq!(
      m.get("G", "A"),
      Some(&TagValue::U64(99)),
      "value is last-wins-replaced"
    );
    m.insert(0, "", "G", "D", 1, TagValue::U64(4), "G");
    assert_eq!(
      seq_of(&m, "D"),
      4,
      "the insert counter advanced past the replace"
    );

    // (c) A priority-0 `Warning`/`Error` duplicate LOSES (first-wins) and its
    // slot likewise keeps its first `seq` (nothing is touched).
    let mut m = TagMap::new();
    m.insert(0, "", "G", "Warning", 1, TagValue::Str("first".into()), "G");
    let first_warn_seq = seq_of(&m, "Warning");
    m.insert(
      0,
      "",
      "G",
      "Warning",
      1,
      TagValue::Str("second".into()),
      "G",
    ); // loses
    assert_eq!(
      seq_of(&m, "Warning"),
      first_warn_seq,
      "a losing Warning duplicate leaves the first seq untouched"
    );
    assert_eq!(m.get("G", "Warning"), Some(&TagValue::Str("first".into())));
  }
}
