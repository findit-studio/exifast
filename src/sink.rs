// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Tag-writer implementors. Each downstream consumer (JSON, in-memory
//! collector, validation harness) brings its own [`crate::parser_new::TagWriter`]
//! impl.
//!
//! Phase D shipped exactly one reference implementor — [`MapTagWriter`] — to
//! exercise the trait shape and prove the dataflow Meta → TagWriter compiles
//! end-to-end. Phase E adds [`MetadataTagWriter`] — the migration bridge
//! adapter that translates a typed `Meta` emission back into the push-style
//! [`crate::value::Metadata`] sink used by the legacy
//! [`crate::parser::OldFormatParser`] dispatch. This bridge is what lets
//! the CLI JSON output remain byte-exact while individual formats migrate
//! one PR at a time across Phases E–F. Retired in Phase G when the JSON
//! emitter consumes [`AnyMeta`](crate::parser_new::AnyMeta) directly.

use crate::{
  parser_new::TagWriter,
  value::{Group, Metadata, TagValue},
};
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
// `MetadataTagWriter` — Phase E–F migration bridge
// ===========================================================================

/// Bridge [`TagWriter`] that emits into the push-style [`Metadata`] sink.
///
/// This is the **Phase E–F migration bridge**: the legacy
/// [`crate::parser::OldFormatParser`] dispatch (`parser_for(file_type) ->
/// &dyn OldFormatParser`) reads `&mut Metadata` and pushes string-keyed
/// tags into it; the new typed-Meta API ([`crate::parser_new::MetaSinker`])
/// emits typed scalars into a [`TagWriter`]. As each format migrates from
/// the old to the new design, its `OldFormatParser` impl uses this adapter
/// to translate the new `Meta`'s `MetaSinker::sink` call back into pushes
/// on the existing `Metadata`. The CLI JSON serializer (which still reads
/// `Metadata`) stays byte-exact end-to-end during the per-format crawl.
///
/// **Retired in Phase G** once the JSON emitter consumes
/// [`AnyMeta`](crate::parser_new::AnyMeta) directly via a JSON-native
/// `TagWriter`; the old `OldFormatParser` dispatch is removed at the same
/// time.
///
/// **Group mapping** (the `group` argument of every `write_*` call):
///
/// - The string is taken as **both** family-0 AND family-1 of the pushed
///   tag's [`Group`]. Spec §6.2 (TagWriter) leaves the dual-family encoding
///   open; for the formats migrating through Phases E–F the two families
///   are identical (e.g. MOI emits under family-0/-1 = "MOI"; ID3 emits
///   under family-1 = "ID3v2_3"/"ID3v2_4" etc. with family-0 also matching;
///   File:* is pushed by `ctx.set_file_type` outside this writer's path).
///   Formats that need a family-0 ≠ family-1 split will encode the family-1
///   directly in their `group` argument (since family-1 is what `-G1`
///   emits and the serializer's `%noDups` key is keyed by family-1).
/// - The MOI pilot exercises the `family-0 == family-1` case end-to-end.
///   Future formats will revisit this if they observe a divergent need;
///   the bridge is internal to the migration.
///
/// **Listable tags** — [`Metadata::push_listable`]: the bridge does NOT
/// expose a listable variant in the current Phase E. List-emitting formats
/// (OGG Vorbis comments, ID3 multi-frame, etc.) are Phase F4–F5 migrations
/// and will be handled there; MOI emits only scalars.
///
/// D8 convention: no public fields; constructor takes the `&mut Metadata`.
pub struct MetadataTagWriter<'meta> {
  meta: &'meta mut Metadata,
  /// Optional family-0 override (per spec §6.2 group-mapping rationale).
  /// When `Some(f0)`, every `write_*` call pushes a tag with
  /// `family-0 = f0` and `family-1 = group` (the writer-side argument).
  /// When `None` (default), `family-0 = family-1 = group` — the original
  /// MOI/AAC/DV pattern.
  ///
  /// **Use case (Phase F3 / APE):** APE has TWO emission group-1 values
  /// (`"APE"` for the main-tag stream, `"MAC"` for the binary-data
  /// header), and a SINGLE family-0 (`"APE"` — APE.pm has no explicit
  /// `GROUPS{0}` so all tags default to family-0 = package name `APE`).
  /// The composite lookup at APE.pm:84-87 keys on family-0 = `"APE:"`
  /// so MAC tags MUST land at family-0 = `"APE"` to be discovered.
  family0_override: Option<&'static str>,
}

impl<'meta> MetadataTagWriter<'meta> {
  /// Construct an adapter that pushes into `meta` for every `write_*` call.
  pub fn new(meta: &'meta mut Metadata) -> Self {
    Self {
      meta,
      family0_override: None,
    }
  }

  /// Construct an adapter that overrides family-0 for every push. The
  /// writer-side `group` argument becomes family-1 only; family-0 is
  /// pinned to `family0`. See the type-level docs for the use case (APE
  /// MAC vs APE main-tag split).
  pub fn with_family0(meta: &'meta mut Metadata, family0: &'static str) -> Self {
    Self {
      meta,
      family0_override: Some(family0),
    }
  }

  /// Build a [`Group`] from the writer-side single-string `group` argument.
  /// When `family0_override` is `Some(f0)`, family-0 = `f0` and
  /// family-1 = `group`; otherwise family-0 = family-1 = `group`.
  fn group(&self, group: &str) -> Group {
    match self.family0_override {
      Some(f0) => Group::new(f0, group),
      None => Group::new(group, group),
    }
  }
}

impl TagWriter for MetadataTagWriter<'_> {
  /// Bridge writes never fail — every `write_*` call is a `Metadata::push`
  /// (or a `push_warning`/`push_error`), all of which are infallible. Using
  /// [`Infallible`] lets a typed `Meta`'s `?`-propagating `MetaSinker::sink`
  /// chain compile-eliminate the error branch.
  type Error = Infallible;

  fn write_str(&mut self, group: &str, name: &str, value: &str) -> Result<(), Infallible> {
    self.meta.push(
      self.group(group),
      name.to_string(),
      TagValue::Str(value.into()),
    );
    Ok(())
  }

  fn write_u64(&mut self, group: &str, name: &str, value: u64) -> Result<(), Infallible> {
    // The push-style `Metadata` stores integers as `TagValue::I64`. Most
    // typed-Meta `u64` emissions fit cleanly (`as i64`) — sizes/durations
    // are well below 2^63. We saturate to `i64::MAX` defensively; in the
    // Phase E MOI pilot the values are u32-derived, never overflowing.
    let n = i64::try_from(value).unwrap_or(i64::MAX);
    self
      .meta
      .push(self.group(group), name.to_string(), TagValue::I64(n));
    Ok(())
  }

  fn write_i64(&mut self, group: &str, name: &str, value: i64) -> Result<(), Infallible> {
    self
      .meta
      .push(self.group(group), name.to_string(), TagValue::I64(value));
    Ok(())
  }

  fn write_f64(&mut self, group: &str, name: &str, value: f64) -> Result<(), Infallible> {
    self
      .meta
      .push(self.group(group), name.to_string(), TagValue::F64(value));
    Ok(())
  }

  fn write_bytes(&mut self, group: &str, name: &str, value: &[u8]) -> Result<(), Infallible> {
    self.meta.push(
      self.group(group),
      name.to_string(),
      TagValue::Bytes(value.to_vec()),
    );
    Ok(())
  }

  fn write_fmt(
    &mut self,
    group: &str,
    name: &str,
    f: impl FnOnce(&mut dyn fmt::Write) -> fmt::Result,
  ) -> Result<(), Infallible> {
    // `write_fmt` is the no-alloc workhorse on the TagWriter side; the
    // bridge must materialize the formatted text because `Metadata` stores
    // strings as owned `TagValue::Str`. The single allocation happens
    // here — the caller (`MetaSinker::sink`) sees only a streaming-format
    // interface.
    let mut s = String::new();
    f(&mut s).expect("MetadataTagWriter::write_fmt: in-memory String write cannot fail");
    self
      .meta
      .push(self.group(group), name.to_string(), TagValue::Str(s.into()));
    Ok(())
  }

  fn write_warning(&mut self, text: &str) -> Result<(), Infallible> {
    // Faithful: `Metadata::push_warning` mirrors ExifTool's `$self->Warn`
    // accumulator (the serializer surfaces the first as `ExifTool:Warning`
    // under `-j -G1`, ExifTool.pm:1297).
    self.meta.push_warning(text.to_string());
    Ok(())
  }

  fn write_error(&mut self, text: &str) -> Result<(), Infallible> {
    // Faithful: `Metadata::push_error` mirrors `$self->Error`
    // (ExifTool.pm:5648), surfaced as `ExifTool:Error`.
    self.meta.push_error(text.to_string());
    Ok(())
  }

  /// Override the default `write_str_list` to route through
  /// [`Metadata::push_listable`], preserving the first-occurrence-position
  /// list-coalesce semantics that the CLI JSON serializer expects
  /// (faithful to ExifTool.pm:9505-9520 `FoundTag` promote-and-push).
  ///
  /// This unblocks the OGG/FLAC bridges from calling `push_listable`
  /// directly inside their `OldFormatParser::process` impls — the typed
  /// [`MetaSinker::sink`](crate::parser_new::MetaSinker) path can now emit
  /// list values via `write_str_list` and the bridge translates them
  /// faithfully. Added in Phase G (per F3-FLAC / F4-OGG integration notes).
  fn write_str_list(&mut self, group: &str, name: &str, values: &[&str]) -> Result<(), Infallible> {
    for v in values {
      self.meta.push_listable(
        self.group(group),
        name.to_string(),
        TagValue::Str((*v).into()),
      );
    }
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

  // -------------------------------------------------------------------------
  // MetadataTagWriter tests
  // -------------------------------------------------------------------------

  /// Helper: locate a pushed tag by `(family1, name)` (`-G1` token).
  fn find<'a>(meta: &'a Metadata, group: &str, name: &str) -> Option<&'a TagValue> {
    meta
      .tags()
      .iter()
      .find(|t| t.group().family1() == group && t.name() == name)
      .map(|t| t.value())
  }

  #[test]
  fn metadata_writer_pushes_str_through_to_metadata() {
    let mut meta = Metadata::new("x.moi");
    {
      let mut w = MetadataTagWriter::new(&mut meta);
      w.write_str("MOI", "MOIVersion", "V6").unwrap();
    }
    assert_eq!(
      find(&meta, "MOI", "MOIVersion"),
      Some(&TagValue::Str("V6".into()))
    );
  }

  #[test]
  fn metadata_writer_pushes_u64_as_i64() {
    // The push-style Metadata stores integers as I64; the bridge maps u64
    // ⇒ I64 with saturation. For values ≤ i64::MAX this is exact.
    let mut meta = Metadata::new("x.moi");
    {
      let mut w = MetadataTagWriter::new(&mut meta);
      w.write_u64("MOI", "VideoBitrate", 8_500_000).unwrap();
    }
    assert_eq!(
      find(&meta, "MOI", "VideoBitrate"),
      Some(&TagValue::I64(8_500_000))
    );
  }

  #[test]
  fn metadata_writer_u64_saturates_on_overflow() {
    // u64 values above i64::MAX saturate to i64::MAX. Not reachable from
    // any real-world MOI extraction; defensive coverage of the cast path.
    let mut meta = Metadata::new("x.moi");
    {
      let mut w = MetadataTagWriter::new(&mut meta);
      w.write_u64("MOI", "Huge", u64::MAX).unwrap();
    }
    assert_eq!(find(&meta, "MOI", "Huge"), Some(&TagValue::I64(i64::MAX)));
  }

  #[test]
  fn metadata_writer_pushes_f64() {
    let mut meta = Metadata::new("x.moi");
    {
      let mut w = MetadataTagWriter::new(&mut meta);
      w.write_f64("MOI", "Duration", 8.16).unwrap();
    }
    assert_eq!(find(&meta, "MOI", "Duration"), Some(&TagValue::F64(8.16)));
  }

  #[test]
  fn metadata_writer_pushes_bytes() {
    let mut meta = Metadata::new("x.moi");
    {
      let mut w = MetadataTagWriter::new(&mut meta);
      w.write_bytes("MOI", "Cover", &[1, 2, 3]).unwrap();
    }
    assert_eq!(
      find(&meta, "MOI", "Cover"),
      Some(&TagValue::Bytes(vec![1, 2, 3]))
    );
  }

  #[test]
  fn metadata_writer_write_fmt_materializes_string() {
    let mut meta = Metadata::new("x.moi");
    {
      let mut w = MetadataTagWriter::new(&mut meta);
      w.write_fmt("MOI", "DateTimeOriginal", |f| {
        write!(
          f,
          "{:04}:{:02}:{:02} {:02}:{:02}:{:06.3}",
          2011, 5, 15, 17, 58, 48.0
        )
      })
      .unwrap();
    }
    assert_eq!(
      find(&meta, "MOI", "DateTimeOriginal"),
      Some(&TagValue::Str("2011:05:15 17:58:48.000".into()))
    );
  }

  #[test]
  fn metadata_writer_routes_warnings_and_errors() {
    let mut meta = Metadata::new("x.moi");
    {
      let mut w = MetadataTagWriter::new(&mut meta);
      w.write_warning("minor — malformed tag").unwrap();
      w.write_error("fatal — header rejected").unwrap();
    }
    assert_eq!(meta.warnings(), &["minor — malformed tag".to_string()]);
    assert_eq!(meta.errors(), &["fatal — header rejected".to_string()]);
  }

  #[test]
  fn metadata_writer_uses_group_as_both_family0_and_family1() {
    let mut meta = Metadata::new("x.moi");
    {
      let mut w = MetadataTagWriter::new(&mut meta);
      w.write_str("MOI", "T", "v").unwrap();
    }
    let tag = meta
      .tags()
      .iter()
      .find(|t| t.name() == "T")
      .expect("pushed tag missing");
    assert_eq!(tag.group().family0(), "MOI");
    assert_eq!(tag.group().family1(), "MOI");
  }

  /// `write_str_list` routes through `Metadata::push_listable` on the
  /// bridge sink, coalescing repeats into a single first-occurrence-position
  /// `TagValue::List`. Faithful to ExifTool's `FoundTag` list-coalesce
  /// (ExifTool.pm:9505-9520).
  #[test]
  fn metadata_writer_write_str_list_coalesces_via_push_listable() {
    let mut meta = Metadata::new("x.ogg");
    {
      let mut w = MetadataTagWriter::new(&mut meta);
      w.write_str_list("Vorbis", "Artist", &["Alice", "Bob", "Carol"])
        .unwrap();
    }
    let tag = meta
      .tags()
      .iter()
      .find(|t| t.name() == "Artist")
      .expect("Artist tag missing");
    // Single tag with a 3-element list, not 3 separate scalar pushes.
    match tag.value() {
      crate::value::TagValue::List(items) => {
        assert_eq!(items.len(), 3);
        assert!(matches!(&items[0], crate::value::TagValue::Str(s) if s == "Alice"));
        assert!(matches!(&items[1], crate::value::TagValue::Str(s) if s == "Bob"));
        assert!(matches!(&items[2], crate::value::TagValue::Str(s) if s == "Carol"));
      }
      other => panic!("expected TagValue::List, got {other:?}"),
    }
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
