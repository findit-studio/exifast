// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! [`JsonTagWriter`] — a [`TagWriter`] that buffers a typed `Meta`'s
//! [`MetaSinker::sink`] emission stream as a `Vec<Tag>`, then renders the
//! `exiftool -j -G1` JSON via standard `serde_json`.
//!
//! It is the engine's `$$et` value sink: the CLI JSON path is `Meta` →
//! [`crate::parser_new::MetaSinker::sink`] → `JsonTagWriter` →
//! [`JsonTagWriter::finish`]. The COLLECTION surface (`push`, `sink`,
//! `records`, the `$$et` flags) is serde-free (`alloc`); the terminal
//! [`finish`](JsonTagWriter::finish) render is `json`-gated and delegates to
//! [`crate::serialize::render_document`] (the single document renderer shared
//! with [`crate::serialize::to_exiftool_json`]).
//!
//! ## Value-equivalence contract
//!
//! The rendered JSON is VALUE-equivalent (not token- or key-order-exact) to
//! bundled `perl exiftool -j -G1`, which the value-semantic
//! [`crate::jsondiff`] conformance gate verifies. Scalar VALUES come from the
//! [`TagValue`] `Serialize` impl (standard `serde_json` scalars; binary
//! placeholder; titlecase non-finite string; ExifTool-rounded rational value).
//! Specifically:
//!
//! 1. **`write_*` → `TagValue` mapping.** `write_u64` → `U64` (the EXACT
//!    unsigned value — no saturation to `i64::MAX`), `write_i64` → `I64`,
//!    `write_f64` → `F64`, `write_str`/`write_fmt` → `Str`, `write_bytes` →
//!    `Bytes`. `write_str_list` coalesces via the
//!    [`crate::value::Metadata::push_listable`] promote-and-push rule
//!    (`ExifTool.pm:9505-9520`).
//! 2. **Push-level dedup / last-write-wins.** Same `(family0, family1, name)`
//!    identity replace-in-place as [`crate::value::Metadata::push`] (faithful
//!    `FoundTag`, `ExifTool.pm:9437-9519`): the LATEST scalar `write_*` for a
//!    key wins.
//! 3. **Document framing + `%noDups` first-wins + Warning/Error.**
//!    [`finish`](JsonTagWriter::finish) delegates to
//!    [`crate::serialize::render_document`]: the array-of-one-object,
//!    `SourceFile` first, the `"<Group1>:<Name>"` keys, the `%noDups`
//!    first-wins token dedup (`exiftool:2950-2951`), and the generated
//!    `ExifTool:Warning` / `ExifTool:Error` tags (`ExifTool.pm:1225,
//!    1288-1297`; only the first of each). Object key ORDER and scalar TOKEN
//!    style are NOT reproduced — the value-semantic gate makes them irrelevant.
//!
//! ## Group mapping
//!
//! The writer-side `group`
//! argument is taken as BOTH family-0 and family-1 by default, or — when
//! constructed via [`JsonTagWriter::with_family0`] — family-0 is pinned and
//! `group` is family-1. Only family-1 reaches the JSON token (`exiftool:2948`
//! `-G1`), but family-0 still participates in the push-level dedup identity
//! (so two tags differing only in family-0 are distinct at the push stage,
//! exactly as `Metadata::push` treats them).
//!
//! ## Modes
//!
//! `print_conv` is supplied to [`MetaSinker::sink`], not stored on the writer:
//! the Meta itself chooses `write_str`(PrintConv) vs `write_u64`/`write_f64`
//! (raw ValueConv) per the flag. `JsonTagWriter` is mode-agnostic — it
//! faithfully renders whatever scalars the Meta emits, so the same writer
//! serves both `-j` and `-n` (`exiftool` PrintConv toggle, `ExifTool.pm:5710`).

use crate::parser_new::TagWriter;
use crate::value::{Group, Tag, TagValue};
use core::{convert::Infallible, fmt};
use smol_str::SmolStr;
use std::{string::String, vec::Vec};

/// A [`TagWriter`] that emits bundled-`exiftool -j -G1` JSON directly from a
/// typed `Meta`'s emission stream — see the module docs for the byte-exact
/// contract it honours.
///
/// Usage: construct with the `SourceFile` path, drive
/// [`MetaSinker::sink`](crate::parser_new::MetaSinker::sink) into it (in the
/// desired `-j`/`-n` mode), then call [`JsonTagWriter::finish`] for the JSON
/// string. The writer is infallible ([`Infallible`] error), so a
/// `?`-propagating sink chain compile-eliminates the error branch.
///
/// D8 convention: no public fields; constructors + accessors only.
pub struct JsonTagWriter {
  source_file: String,
  /// Buffered tags in first-occurrence order (mirrors the retired push-style
  /// `Metadata`'s `Vec<Tag>` ordering, which the `%noDups` pass then walks).
  /// Stored as [`crate::value::Tag`] — the SAME element type the retired
  /// `Metadata` used — so the engine read-back surface ([`Self::tags`] /
  /// [`Self::records`]) is a 1:1 replacement for `Metadata::tags()`.
  records: Vec<Tag>,
  /// Warning accumulator, in call order (`ExifTool.pm:1297`; the first is
  /// surfaced as `ExifTool:Warning` under `-j -G1`).
  warnings: Vec<String>,
  /// Error accumulator, in call order (`ExifTool.pm:1288-1296`; the first is
  /// surfaced as `ExifTool:Error`).
  errors: Vec<String>,
  /// Optional family-0 override: when `Some(f0)`, family-0 = `f0` and
  /// family-1 = the writer-side `group`; when `None`, family-0 = family-1 =
  /// `group`. Mutable at runtime via [`JsonTagWriter::set_family0_override`]
  /// so the engine's APE entry can pin family-0 = `"APE"` for the duration of
  /// the APE `MetaSinker::sink` call (the MAC/main split, APE.pm:84-87) while
  /// leaving the surrounding `File:*` / chained-ID3 emissions on the default
  /// `group == family-0 == family-1` mapping — a single writer-level seam in
  /// place of any per-sink family-0 wrapper.
  family0_override: Option<&'static str>,
  /// Faithful `$$et{DoneID3}` flag (ID3.pm:1435-1436, APE.pm:124, etc.) for
  /// the ENGINE path (`crate::parser::extract_info` -> `process(ctx)`), which
  /// carries cross-format state on this `$$et` value sink. `None` => ProcessID3
  /// has not run on this `$self`; `Some(n)` => run, with `n` the ID3v1-trailer
  /// size (ID3.pm:1527) read by APE.pm:169 to walk PAST the trailer. Moved here
  /// verbatim from the retired `crate::value::Metadata::done_id3` so the engine
  /// `process` chain (ID3 -> APE/MPC/WV/etc.) keeps its `$self`-scoped flag.
  /// (The TYPED `parse`/`parse_bytes` path uses `SharedFlags` instead — these
  /// are two parallel ExifTool-`$$et` mirrors, unchanged by this migration.)
  done_id3: Option<usize>,
  /// Faithful `$$et{DoneAPE}` flag (APE.pm:131, ID3.pm:1723) for the engine
  /// path. Set by `ProcessAPE` immediately after the ID3 check; read by
  /// ID3.pm:1723 to gate the MP3->APE trailer fallback. Moved verbatim from
  /// the retired `Metadata::done_ape`.
  done_ape: bool,
}

impl JsonTagWriter {
  /// Construct a writer for the given `SourceFile` path. Family-0 = family-1 =
  /// the writer-side `group` argument (the default MOI/AAC/DV pattern).
  #[must_use]
  pub fn new(source_file: impl Into<String>) -> Self {
    Self {
      source_file: source_file.into(),
      records: Vec::new(),
      warnings: Vec::new(),
      errors: Vec::new(),
      family0_override: None,
      done_id3: None,
      done_ape: false,
    }
  }

  /// Construct a writer that pins family-0 to `family0` for every emission
  /// (the writer-side `group` becomes family-1 only). Used by APE's MAC vs
  /// main-tag family-0 split.
  #[must_use]
  pub fn with_family0(source_file: impl Into<String>, family0: &'static str) -> Self {
    Self {
      source_file: source_file.into(),
      records: Vec::new(),
      warnings: Vec::new(),
      errors: Vec::new(),
      family0_override: Some(family0),
      done_id3: None,
      done_ape: false,
    }
  }

  /// The `SourceFile` path this writer was constructed with.
  #[must_use]
  pub fn source_file(&self) -> &str {
    &self.source_file
  }

  /// Build a [`Group`] from the writer-side single-string `group` argument,
  /// honouring the optional family-0 override.
  fn group(&self, group: &str) -> Group {
    match self.family0_override {
      Some(f0) => Group::new(f0, group),
      None => Group::new(group, group),
    }
  }

  // -------------------------------------------------------------------------
  // Engine `$$et` value-sink surface — read-back + state. These methods make
  // `JsonTagWriter` a drop-in for the retired `crate::value::Metadata` push-bag
  // on the ENGINE path (`crate::parser::extract_info` -> `process(ctx)`): the
  // `ParseContext` carries `&mut JsonTagWriter` and the format `process`
  // entries push File:* + sink their typed Meta + read tags back (Composite
  // ingredient lookup, SetFileType first-call-wins) directly here.
  // -------------------------------------------------------------------------

  /// Set (or clear) the runtime family-0 override. The engine's APE entry
  /// pins family-0 = `"APE"` for the duration of its `MetaSinker::sink` call
  /// (the MAC-header vs main-tag split keyed by family-0 = `APE:`,
  /// APE.pm:84-87) then clears it, so the surrounding `File:*` and chained-ID3
  /// emissions keep the default `group == family-0 == family-1` mapping. This
  /// is a single writer-level seam (in place of any per-sink family-0
  /// wrapper) now that a single writer is shared across the whole `process`.
  pub fn set_family0_override(&mut self, family0: Option<&'static str>) {
    self.family0_override = family0;
  }

  /// `$$et{DoneID3}` — `None` until `ProcessID3` runs on this engine `$self`;
  /// `Some(n)` once run, with `n` the ID3v1-trailer size. Faithful read of
  /// the retired `Metadata::done_id3` (ID3.pm:1435, APE.pm:124/169).
  #[must_use]
  pub fn done_id3(&self) -> Option<usize> {
    self.done_id3
  }

  /// Set `$$et{DoneID3} = trailer_size` (ID3.pm:1436/1527). Mirrors the
  /// retired `Metadata::set_done_id3`.
  pub fn set_done_id3(&mut self, trailer_size: usize) {
    self.done_id3 = Some(trailer_size);
  }

  /// `$$et{DoneAPE}` (APE.pm:131, ID3.pm:1723). Faithful read of the retired
  /// `Metadata::done_ape`.
  #[must_use]
  pub fn done_ape(&self) -> bool {
    self.done_ape
  }

  /// Set `$$et{DoneAPE} = 1` (APE.pm:131). Mirrors the retired
  /// `Metadata::set_done_ape`.
  pub fn set_done_ape(&mut self) {
    self.done_ape = true;
  }

  /// Is `File:FileType` (family-1 `File`) already buffered? Faithful to
  /// ExifTool's per-file `$$self{FileType}` first-call-wins marker
  /// (ExifTool.pm:9681/9701). Read by `ParseContext::set_file_type` before
  /// pushing the `File:*` triplet. Verbatim port of the retired
  /// `Metadata::has_file_type`.
  #[must_use]
  pub fn has_file_type(&self) -> bool {
    self
      .records
      .iter()
      .any(|t| t.group().family1() == "File" && t.name() == "FileType")
  }

  /// Existence query for `(group, name)` (family-0 AND family-1 + name).
  /// Verbatim port of the retired `Metadata::has_tag` — used by
  /// format-specific duplicate-handling paths.
  #[must_use]
  pub fn has_tag(&self, group: &Group, name: &str) -> bool {
    self
      .records
      .iter()
      .any(|t| t.group() == group && t.name() == name)
  }

  /// Push (FoundTag) a tag in first-occurrence order, or overwrite an existing
  /// same-`(group, name)` tag's value in place (last-write-wins). Verbatim
  /// port of the retired `Metadata::push` (ExifTool.pm:9437-9519). The
  /// `group` carries BOTH families explicitly — the engine's `set_file_type`,
  /// the Composite emission, and the chained-ID3 push helpers call this
  /// exactly as they called `Metadata::push`.
  pub fn push(&mut self, group: Group, name: impl Into<SmolStr>, value: TagValue) {
    let name = name.into();
    if let Some(tag) = self
      .records
      .iter_mut()
      .find(|t| t.group() == &group && t.name() == name.as_str())
    {
      tag.set_value(value);
    } else {
      self.records.push(Tag::new(group, name, value));
    }
  }

  /// Push `value` under `(group, name)` with `List`-coalesce semantics
  /// (promote scalar -> 1-elem list, extend list, else append scalar).
  /// Verbatim port of the retired `Metadata::push_listable`
  /// (ExifTool.pm:9505-9520). The engine's chained-ID3 / Vorbis push helpers
  /// call this exactly as they called `Metadata::push_listable`.
  pub fn push_listable(&mut self, group: Group, name: impl Into<SmolStr>, value: TagValue) {
    let name = name.into();
    if let Some(tag) = self
      .records
      .iter_mut()
      .find(|t| t.group() == &group && t.name() == name.as_str())
    {
      let placeholder = TagValue::List(Vec::new());
      let new_val = match core::mem::replace(tag.value_mut(), placeholder) {
        TagValue::List(mut items) => {
          items.push(value);
          TagValue::List(items)
        }
        scalar => TagValue::List(std::vec![scalar, value]),
      };
      tag.set_value(new_val);
    } else {
      self.records.push(Tag::new(group, name, value));
    }
  }

  /// Replace the value of the existing `(group, name)` tag in place;
  /// returns `true` if found (else no-op `false`). Verbatim port of the
  /// retired `Metadata::set_tag_value` (the `OverrideFileType` path,
  /// ExifTool.pm:9717-9724).
  pub fn set_tag_value(&mut self, group: &Group, name: &str, value: TagValue) -> bool {
    match self
      .records
      .iter_mut()
      .find(|t| t.group() == group && t.name() == name)
    {
      Some(tag) => {
        tag.set_value(value);
        true
      }
      None => false,
    }
  }

  /// Record a non-fatal warning, in occurrence order (`$self->Warn`,
  /// ExifTool.pm:1297). Verbatim port of the retired `Metadata::push_warning`.
  /// (Identical to the [`TagWriter::write_warning`] impl, exposed under the
  /// `Metadata`-style name so the engine `process` chain migrates 1:1.)
  pub fn push_warning(&mut self, warning: impl Into<String>) {
    self.warnings.push(warning.into());
  }

  /// Record an error, in occurrence order (`$self->Error`, ExifTool.pm:5648).
  /// Verbatim port of the retired `Metadata::push_error`.
  pub fn push_error(&mut self, error: impl Into<String>) {
    self.errors.push(error.into());
  }

  /// The buffered tags, in first-occurrence order. The 1:1 read analogue of
  /// the retired `Metadata::tags()` (same [`crate::value::Tag`] element type,
  /// same ordering the `%noDups` pass walks). The engine's Composite
  /// ingredient lookup (APE.pm:81-93, scanning family-0 = `APE:`) and the ID3
  /// stage-and-replay lift (a scratch `JsonTagWriter` collects the legacy
  /// engine's emission, then [`crate::formats::id3`] reads it back) iterate
  /// this.
  #[must_use]
  pub fn tags(&self) -> &[Tag] {
    &self.records
  }

  /// Iterate the buffered tags in first-occurrence order as
  /// `(&Group, &str name, &TagValue)` triples — a destructured convenience
  /// over [`Self::tags`] for the `.rev()` Composite ingredient scan and the
  /// orchestration-tag lift.
  pub fn records(&self) -> impl DoubleEndedIterator<Item = (&Group, &str, &TagValue)> {
    self
      .records
      .iter()
      .map(|t| (t.group(), t.name(), t.value()))
  }

  /// Accumulated warnings, in call order (`$self->Warn`). Read by the ID3
  /// stage-and-replay lift off its scratch writer; the public output document
  /// surfaces only the FIRST via [`Self::finish`]. Faithful read analogue of
  /// the retired `Metadata::warnings`.
  #[must_use]
  pub fn warnings(&self) -> &[String] {
    &self.warnings
  }

  /// Accumulated errors, in call order (`$self->Error`). Faithful read
  /// analogue of the retired `Metadata::errors`.
  #[must_use]
  pub fn errors(&self) -> &[String] {
    &self.errors
  }

  /// Emit the buffered records as the `exiftool -j -G1` JSON document
  /// (VALUE-equivalent to bundled, via standard `serde_json`). Consumes the
  /// writer.
  ///
  /// Delegates to [`crate::serialize::render_document`] — the SINGLE document
  /// renderer shared with [`crate::serialize::to_exiftool_json`] — so both
  /// output paths agree. It owns the array-of-one-object framing, `SourceFile`
  /// first, the `"<Group1>:<Name>"` keys, the generated `ExifTool:Warning` /
  /// `ExifTool:Error` tags (`ExifTool.pm:1225,1288-1297`), and the `%noDups`
  /// first-wins token dedup (`exiftool:2950-2951`). Object key ORDER and scalar
  /// TOKEN style are NOT reproduced — the value-semantic conformance gate makes
  /// them irrelevant.
  ///
  /// `json`-gated: rendering goes through `serde_json` (the `json` feature). The
  /// collection surface (`push`/`sink`/`records`) stays available under `alloc`
  /// for the serde-free engine tier; only the final render needs `json`.
  #[cfg(feature = "json")]
  #[must_use]
  pub fn finish(self) -> String {
    crate::serialize::render_document(
      &self.source_file,
      &self.records,
      &self.warnings,
      &self.errors,
    )
  }
}

impl TagWriter for JsonTagWriter {
  /// Buffering into in-memory `Vec`s cannot fail; using [`Infallible`] lets a
  /// typed `Meta`'s `?`-propagating [`MetaSinker::sink`](crate::parser_new::MetaSinker::sink)
  /// chain compile-eliminate the error branch.
  type Error = Infallible;

  fn write_str(&mut self, group: &str, name: &str, value: &str) -> Result<(), Infallible> {
    let g = self.group(group);
    self.push(g, name, TagValue::Str(value.into()));
    Ok(())
  }

  fn write_u64(&mut self, group: &str, name: &str, value: u64) -> Result<(), Infallible> {
    // Store the u64 EXACTLY as `TagValue::U64` (Codex A-R4-1). The prior
    // `i64::try_from(value).unwrap_or(i64::MAX)` silently corrupted any value
    // above `i64::MAX` (e.g. an APE u64 day-count, a large file size) into
    // `9223372036854775807`. Perl is untyped: it stringifies the integer and
    // runs the one `EscapeJSON` number gate (`exiftool:3809`), so the full
    // decimal — quoted because it exceeds 15 digits, exactly as `i64::MAX`
    // would be — renders byte-identical to bundled but with the TRUE value.
    let g = self.group(group);
    self.push(g, name, TagValue::U64(value));
    Ok(())
  }

  fn write_i64(&mut self, group: &str, name: &str, value: i64) -> Result<(), Infallible> {
    let g = self.group(group);
    self.push(g, name, TagValue::I64(value));
    Ok(())
  }

  fn write_f64(&mut self, group: &str, name: &str, value: f64) -> Result<(), Infallible> {
    let g = self.group(group);
    self.push(g, name, TagValue::F64(value));
    Ok(())
  }

  fn write_bytes(&mut self, group: &str, name: &str, value: &[u8]) -> Result<(), Infallible> {
    let g = self.group(group);
    self.push(g, name, TagValue::Bytes(value.to_vec()));
    Ok(())
  }

  fn write_fmt(
    &mut self,
    group: &str,
    name: &str,
    f: impl FnOnce(&mut dyn fmt::Write) -> fmt::Result,
  ) -> Result<(), Infallible> {
    // `write_fmt` is the no-alloc workhorse on the sink side; we must
    // materialize because the buffered record stores an owned `TagValue::Str`
    // — the single allocation happens here, exactly like the bridge.
    let mut s = String::new();
    f(&mut s).expect("JsonTagWriter::write_fmt: in-memory String write cannot fail");
    let g = self.group(group);
    self.push(g, name, TagValue::Str(s.into()));
    Ok(())
  }

  fn write_warning(&mut self, text: &str) -> Result<(), Infallible> {
    self.warnings.push(text.into());
    Ok(())
  }

  fn write_error(&mut self, text: &str) -> Result<(), Infallible> {
    self.errors.push(text.into());
    Ok(())
  }

  /// Override the default per-element `write_str` to coalesce into a single
  /// first-occurrence-position list value, via
  /// [`crate::value::Metadata::push_listable`] semantics (faithful
  /// `FoundTag` promote-and-push, `ExifTool.pm:9505-9520`).
  fn write_str_list(&mut self, group: &str, name: &str, values: &[&str]) -> Result<(), Infallible> {
    for v in values {
      let g = self.group(group);
      self.push_listable(g, name, TagValue::Str((*v).into()));
    }
    Ok(())
  }
}

impl fmt::Debug for JsonTagWriter {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("JsonTagWriter")
      .field("source_file", &self.source_file)
      .field("records", &self.records.len())
      .field("warnings", &self.warnings.len())
      .field("errors", &self.errors.len())
      .finish()
  }
}

// ===========================================================================
// Tests
// ===========================================================================

// This module is the writer-vs-serialize byte-exactness parity suite: EVERY
// test asserts `JsonTagWriter::finish` == `to_exiftool_json(&Metadata)`, so
// the whole module depends on `crate::serialize` (gated on `feature = "json"`,
// which `std` does NOT imply). Gate it on `json` so a `--features std,id3`
// test build — where `json_writer` itself compiles (alloc-gated) but
// `serialize`/`jsondiff` do not — still BUILDS its non-json tests (Codex
// A-R4-2). The same gating pattern the `bitstream` test module already uses
// for its `to_exiftool_json` cases.
#[cfg(all(test, feature = "json"))]
mod tests {
  use super::*;
  use crate::serialize::to_exiftool_json;
  use crate::value::{Metadata, Rational};

  /// Helper: build a `Metadata` from the SAME (family0, family1, name, value)
  /// records and assert `JsonTagWriter::finish` is byte-identical to
  /// `to_exiftool_json` over that Metadata. This is the core byte-exactness
  /// contract — the writer is a faithful re-composition of bridge+serialize.
  fn assert_matches_serialize(source: &str, push: impl Fn(&mut Metadata, &mut JsonTagWriter)) {
    let mut m = Metadata::new(source);
    let mut w = JsonTagWriter::new(source);
    push(&mut m, &mut w);
    let via_serialize = to_exiftool_json(&m);
    let via_writer = w.finish();
    assert_eq!(
      via_writer, via_serialize,
      "JsonTagWriter must be byte-identical to to_exiftool_json"
    );
  }

  #[test]
  fn empty_doc_matches_serialize() {
    assert_matches_serialize("a.aac", |_m, _w| {});
  }

  #[test]
  fn scalars_match_serialize_and_bridge_mapping() {
    assert_matches_serialize("a.aac", |m, w| {
      // write_str → Str
      m.push(
        Group::new("AAC", "AAC"),
        "ProfileType",
        TagValue::Str("Low Complexity".into()),
      );
      w.write_str("AAC", "ProfileType", "Low Complexity").unwrap();
      // write_u64 → I64
      m.push(Group::new("AAC", "AAC"), "SampleRate", TagValue::I64(44100));
      w.write_u64("AAC", "SampleRate", 44100).unwrap();
      // write_i64 → I64
      m.push(Group::new("X", "X"), "Neg", TagValue::I64(-7));
      w.write_i64("X", "Neg", -7).unwrap();
      // write_f64 → F64
      m.push(Group::new("X", "X"), "Dur", TagValue::F64(8.16));
      w.write_f64("X", "Dur", 8.16).unwrap();
      // write_bytes → Bytes
      m.push(
        Group::new("EXIF", "IFD0"),
        "Thumb",
        TagValue::Bytes(std::vec![1, 2, 3]),
      );
      w.write_bytes("IFD0", "Thumb", &[1, 2, 3]).unwrap();
    });
  }

  #[test]
  fn write_u64_preserves_exact_value_above_i64_max() {
    // Codex A-R4-1 regression: a u64 ABOVE i64::MAX must round-trip its FULL
    // value, NOT saturate to i64::MAX (`9223372036854775807`). The writer and
    // the serialize oracle agree (both store U64, both render via serde).
    assert_matches_serialize("a.aac", |m, w| {
      for (name, v) in [
        ("Max", u64::MAX),
        ("AboveI64Max", (i64::MAX as u64) + 1),
        ("Round", 10_000_000_000_000_000_000_u64),
      ] {
        m.push(Group::new("X", "X"), name, TagValue::U64(v));
        w.write_u64("X", name, v).unwrap();
      }
    });
    // Value-semantic: the FULL exact value renders (serde emits the u64 as a
    // bare number), NOT the truncated i64::MAX.
    let mut w = JsonTagWriter::new("a.aac");
    w.write_u64("X", "Max", u64::MAX).unwrap();
    let out = w.finish();
    crate::jsondiff::json_equivalent(
      &out,
      r#"[{"SourceFile":"a.aac","X:Max":18446744073709551615}]"#,
    )
    .expect("u64::MAX exact value");
    assert!(
      !out.contains("9223372036854775807"),
      "u64::MAX must NOT saturate to i64::MAX, got: {out}"
    );
  }

  #[test]
  fn write_fmt_materializes_like_bridge() {
    assert_matches_serialize("a.moi", |m, w| {
      m.push(
        Group::new("MOI", "MOI"),
        "DateTimeOriginal",
        TagValue::Str("2011:05:15 17:58:48.000".into()),
      );
      w.write_fmt("MOI", "DateTimeOriginal", |f| {
        write!(
          f,
          "{:04}:{:02}:{:02} {:02}:{:02}:{:06.3}",
          2011, 5, 15, 17, 58, 48.0
        )
      })
      .unwrap();
    });
  }

  #[test]
  fn last_write_wins_for_same_key() {
    // FoundTag last-wins (ExifTool.pm:9437-9519) at the push stage.
    assert_matches_serialize("dup.aif", |m, w| {
      m.push(
        Group::new("AIFF", "AIFF"),
        "Name",
        TagValue::Str("First".into()),
      );
      m.push(
        Group::new("AIFF", "AIFF"),
        "Name",
        TagValue::Str("Second".into()),
      );
      w.write_str("AIFF", "Name", "First").unwrap();
      w.write_str("AIFF", "Name", "Second").unwrap();
    });
  }

  #[test]
  fn nodups_first_wins_on_family1_token() {
    // Two records with SAME family1:name but DIFFERENT family0 → distinct at
    // the push stage, then `%noDups` first-wins on the family1 token drops the
    // second (exiftool:2950-2951). Push both into one writer via the internal
    // scalar path with explicit groups (the public API uses one family0 per
    // writer, so the two-family0 case is exercised at the buffer level).
    let mut m = Metadata::new("a.aac");
    m.push(Group::new("Audio", "AAC"), "Channels", TagValue::I64(2));
    m.push(Group::new("QuickTime", "AAC"), "Channels", TagValue::I64(6));
    let mut wr = JsonTagWriter::new("a.aac");
    wr.push(Group::new("Audio", "AAC"), "Channels", TagValue::I64(2));
    wr.push(Group::new("QuickTime", "AAC"), "Channels", TagValue::I64(6));
    assert_eq!(wr.finish(), to_exiftool_json(&m));
  }

  #[test]
  fn write_str_list_coalesces_like_serialize() {
    assert_matches_serialize("a.ogg", |m, w| {
      m.push_listable(
        Group::new("Vorbis", "Vorbis"),
        "Artist",
        TagValue::Str("Alice".into()),
      );
      m.push_listable(
        Group::new("Vorbis", "Vorbis"),
        "Artist",
        TagValue::Str("Bob".into()),
      );
      m.push_listable(
        Group::new("Vorbis", "Vorbis"),
        "Artist",
        TagValue::Str("Carol".into()),
      );
      w.write_str_list("Vorbis", "Artist", &["Alice", "Bob", "Carol"])
        .unwrap();
    });
  }

  #[test]
  fn interleaved_list_keeps_first_occurrence_position() {
    // R1-F2 semantics: a List tag accumulates at its FIRST-occurrence
    // position even when unrelated tags interleave (write_str_list per repeat,
    // faithful to the Vorbis comment walker).
    assert_matches_serialize("a.ogg", |m, w| {
      m.push_listable(
        Group::new("Vorbis", "Vorbis"),
        "Artist",
        TagValue::Str("Alice".into()),
      );
      m.push(
        Group::new("Vorbis", "Vorbis"),
        "Title",
        TagValue::Str("Song".into()),
      );
      m.push_listable(
        Group::new("Vorbis", "Vorbis"),
        "Artist",
        TagValue::Str("Bob".into()),
      );
      m.push(
        Group::new("Vorbis", "Vorbis"),
        "Comment",
        TagValue::Str("Foo".into()),
      );
      w.write_str_list("Vorbis", "Artist", &["Alice"]).unwrap();
      w.write_str("Vorbis", "Title", "Song").unwrap();
      w.write_str_list("Vorbis", "Artist", &["Bob"]).unwrap();
      w.write_str("Vorbis", "Comment", "Foo").unwrap();
    });
  }

  #[test]
  fn warnings_and_errors_match_serialize() {
    assert_matches_serialize("a.jpg", |m, w| {
      m.push(
        Group::new("EXIF", "IFD0"),
        "Make",
        TagValue::Str("Canon".into()),
      );
      m.push_warning("w1");
      m.push_warning("w2");
      m.push_error("e1");
      w.write_str("IFD0", "Make", "Canon").unwrap();
      w.write_warning("w1").unwrap();
      w.write_warning("w2").unwrap();
      w.write_error("e1").unwrap();
    });
  }

  #[test]
  fn string_escaping_matches_serialize() {
    assert_matches_serialize("a.jpg", |m, w| {
      let s = "tab\there\"q\\b\nnl\u{1}\u{7f}\0z";
      m.push(Group::new("X", "X"), "S", TagValue::Str(s.into()));
      w.write_str("X", "S", s).unwrap();
    });
  }

  #[test]
  fn numeric_looking_strings_match_serialize() {
    assert_matches_serialize("a.jpg", |m, w| {
      for (n, v) in [
        ("Aperture", "3.5"),
        ("ISO", "100"),
        ("Mp", "6.4e-05"),
        ("Ver", "01"),
        ("B", "true"),
        ("C", "FALSE"),
      ] {
        m.push(Group::new("X", "X"), n, TagValue::Str(v.into()));
        w.write_str("X", n, v).unwrap();
      }
    });
  }

  #[test]
  fn float_and_inf_match_serialize() {
    assert_matches_serialize("a.jpg", |m, w| {
      m.push(Group::new("X", "X"), "Plain", TagValue::F64(3.5));
      m.push(Group::new("X", "X"), "Long", TagValue::F64(10.0 / 2134.0));
      m.push(Group::new("X", "X"), "Inf", TagValue::F64(f64::INFINITY));
      m.push(
        Group::new("X", "X"),
        "NegInf",
        TagValue::F64(f64::NEG_INFINITY),
      );
      m.push(Group::new("X", "X"), "Nan", TagValue::F64(f64::NAN));
      w.write_f64("X", "Plain", 3.5).unwrap();
      w.write_f64("X", "Long", 10.0 / 2134.0).unwrap();
      w.write_f64("X", "Inf", f64::INFINITY).unwrap();
      w.write_f64("X", "NegInf", f64::NEG_INFINITY).unwrap();
      w.write_f64("X", "Nan", f64::NAN).unwrap();
    });
  }

  #[test]
  fn list_with_bytes_and_rational_matches_serialize() {
    // Lists can only reach the writer via write_str_list (all-str), so cover
    // the mixed-list serializer path through push_listable parity directly on
    // the writer's internal buffer (the bridge has no mixed-list emission).
    let mut m = Metadata::new("a.jpg");
    m.push(
      Group::new("EXIF", "IFD0"),
      "MixedList",
      TagValue::List(std::vec![
        TagValue::I64(1),
        TagValue::Bytes(std::vec![0u8; 5]),
        TagValue::Rational(Rational::rational64(1, 2)),
      ]),
    );
    let mut w = JsonTagWriter::new("a.jpg");
    w.push(
      Group::new("EXIF", "IFD0"),
      "MixedList",
      TagValue::List(std::vec![
        TagValue::I64(1),
        TagValue::Bytes(std::vec![0u8; 5]),
        TagValue::Rational(Rational::rational64(1, 2)),
      ]),
    );
    assert_eq!(w.finish(), to_exiftool_json(&m));
  }

  #[test]
  fn with_family0_routes_family1_to_token() {
    // APE MAC/main split: family0 pinned, group arg is family1.
    let mut m = Metadata::new("a.ape");
    m.push(
      Group::new("APE", "MAC"),
      "Version",
      TagValue::Str("3.99".into()),
    );
    let mut w = JsonTagWriter::with_family0("a.ape", "APE");
    w.write_str("MAC", "Version", "3.99").unwrap();
    assert_eq!(w.finish(), to_exiftool_json(&m));
  }
}
