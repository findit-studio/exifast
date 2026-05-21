//! PARITY CHECKPOINT for the sink-layer removal.
//!
//! Proves that an independently-assembled **typed serde document** — the
//! orchestration tags lifted off [`exifast::parser::extract_info`] PLUS the
//! format tags from `serde_json::to_value(&`[`exifast::Rendered`]`)` — is, for
//! EVERY active conformance fixture in BOTH `-j` (PrintConv) and `-n` (numeric)
//! modes, value-equivalent to the engine document [`extract_info`] produces AND
//! the committed bundled-ExifTool golden.
//!
//! After the sink layer was deleted, `extract_info` IS the typed-serde path
//! (`detect → parse → serde-render`), so the "vs `extract_info`" arm is now a
//! self-consistency check (the document assembled via the public
//! [`exifast::Rendered`] serde wrapper matches the engine's own serde render);
//! the "vs golden" arm remains the load-bearing conformance check. Kept as a
//! standalone harness because it exercises the public `Rendered` serde view +
//! the `parse_bytes`-style candidate loop independently of the engine entry.
//!
//! ## What the typed serde document is
//!
//! `extract_info` detects the file type, runs the parse (yielding a complete
//! typed `AnyMeta` incl. chains), emits the orchestration tags
//! (`ExifTool:ExifToolVersion`, `SourceFile`, the `File:*` triplet), and
//! serde-renders the whole thing. This harness assembles an EQUIVALENT document
//! by:
//!
//!   1. Lifting the orchestration tags (`ExifTool:*` + `File:*`) and the
//!      warnings/errors (incl. the post-loop finalization `Error`) off the
//!      engine document ([`extract_info`], itself §4-conformant) — these are
//!      the engine's responsibility, OUTSIDE the per-format typed Meta.
//!   2. Serde-rendering the typed `AnyMeta` for the FORMAT tags via
//!      `serde_json::to_value(&Rendered::new(&meta, print_conv))` — the public
//!      typed serde view.
//!   3. Merging into the single `[{ … }]` document with `%noDups` first-wins
//!      (orchestration keys are inserted first, so they win over any
//!      coincident typed key — though typed Metas never emit `File:*`).
//!
//! ## Excluded fixture
//!
//! `AIFF_id3.aif` is NOT one of the 121 active conformance fixtures: the AIFF
//! `ID3 ` SubDirectory dispatch (AIFF.pm:202) is a deliberate Phase-2 forward
//! item that the ENGINE path also does not implement (the `ID3 ` chunk is
//! recognized then silently skipped — see the `#[ignore]`-d
//! `aiff_id3_chunk_subdirectory_dispatch_deferred_conformance` test). The
//! typed path matches the engine path there (both lack ID3); both diverge only
//! from the golden. It is therefore excluded from this 121-fixture checkpoint,
//! exactly as it is excluded from `conformance.rs`.
//!
//! Gated on `feature = "json"`: imports the `json`-gated `jsondiff` +
//! `serde_json` rendering of `Rendered`.
#![cfg(feature = "json")]

use exifast::filetype::detection_candidates;
use exifast::format_parser::{Rendered, SharedFlags, any_parser_for};
use exifast::jsondiff::json_equivalent;
use exifast::parser::extract_info;

/// Fixtures excluded from the active conformance set — known
/// formally-accept-deferred residuals (NOT silent metadata losses;
/// see docs/tracking.md and the per-fixture `#[ignore]` conformance
/// tests).
///
/// - `AIFF_id3.aif` — AIFF ID3-chunk SubDirectory (forward item in both
///   the engine and typed paths; see module docs).
/// - `FLAC.ogg` — Ogg-FLAC transport (R3 F2 fallback; the `\x7fFLAC`
///   packet handler `numFlac` accumulator + FLAC sub-stream re-dispatch
///   is not yet ported). The METADATA_BLOCK_PICTURE half of R3 F2 IS
///   fixed (see `tests/conformance.rs::ogg_metadata_block_picture_conformance`).
const NOT_ACTIVE: &[&str] = &["AIFF_id3.aif", "FLAC.ogg"];

/// Every `tests/fixtures/<f>` that has both `tests/golden/<f>.json` and
/// `tests/golden/<f>.n.json`, MINUS the [`NOT_ACTIVE`] formally-accept-
/// deferred residuals — i.e. the active conformance fixtures.
fn active_fixtures() -> Vec<String> {
  let root = env!("CARGO_MANIFEST_DIR");
  let mut out = Vec::new();
  for entry in std::fs::read_dir(format!("{root}/tests/fixtures")).expect("read fixtures dir") {
    let entry = entry.expect("dir entry");
    if !entry.file_type().expect("file type").is_file() {
      continue;
    }
    let name = entry.file_name().to_string_lossy().into_owned();
    if NOT_ACTIVE.contains(&name.as_str()) {
      continue;
    }
    let j = format!("{root}/tests/golden/{name}.json");
    let n = format!("{root}/tests/golden/{name}.n.json");
    if std::path::Path::new(&j).is_file() && std::path::Path::new(&n).is_file() {
      out.push(name);
    }
  }
  out.sort();
  out
}

/// Resolve the typed parser the SAME way `extract_info` does — walk the
/// detection candidates in `ExtractInfo` loop order; the first whose
/// `any_parser_for` is `Some` AND whose `parse_any` returns `Ok(Some(meta))`
/// wins. Returns `None` when no typed parser accepts (rejected/finalization-
/// only fixtures — e.g. `bad.ogg`, where the golden's tags come from
/// finalization, not a Meta). Mirrors `parse_bytes`' candidate loop.
fn typed_parse<'a>(fixture: &str, data: &'a [u8]) -> Option<exifast::AnyMeta<'a>> {
  let ext = exifast::filetype::file_ext_for_name(fixture);
  let ext_ref = ext.as_deref();
  let mut shared = SharedFlags::new();
  for cand in detection_candidates(fixture, data) {
    let ft = cand.file_type();
    let Some(parser) = any_parser_for(ft) else {
      continue;
    };
    match parser.parse_any(data, &mut shared, ext_ref) {
      Ok(Some(meta)) => return Some(meta),
      Ok(None) => shared = SharedFlags::new(),
      Err(_) => shared = SharedFlags::new(),
    }
  }
  None
}

/// Build the typed SERDE document for `fixture` in the given mode: lift the
/// orchestration tags + warnings/errors off the engine writer, serde-render
/// the typed `AnyMeta` for the format tags, and merge into the `[{ … }]`
/// document with `%noDups` first-wins. Returns the JSON string.
fn typed_serde_document(fixture: &str, data: &[u8], print_on: bool) -> String {
  use serde_json::{Map, Value};

  let mut obj: Map<String, Value> = Map::new();
  obj.insert("SourceFile".into(), Value::String(fixture.to_string()));

  // (1) Orchestration tags (`ExifTool:*` + `File:*`) + warnings/errors lifted
  // off the authoritative engine writer. These are the engine's
  // responsibility OUTSIDE the typed Meta in BOTH designs. We lift them as
  // rendered JSON values by round-tripping the engine's own document and
  // copying only the orchestration/diagnostic keys — this keeps their exact
  // rendered form (e.g. `ExifTool:ExifToolVersion` as the bare number 13.58).
  let engine_doc = extract_info(fixture, data, print_on);
  let engine_parsed: Value = serde_json::from_str(&engine_doc).expect("engine doc is valid JSON");
  let engine_obj = engine_parsed[0]
    .as_object()
    .expect("engine doc is a single-object array");
  for (key, value) in engine_obj {
    if key == "SourceFile" {
      continue; // already inserted first
    }
    let is_orchestration = key.starts_with("ExifTool:")
      || key.starts_with("File:")
      || key == "ExifTool:Warning"
      || key == "ExifTool:Error";
    if is_orchestration && !obj.contains_key(key) {
      obj.insert(key.clone(), value.clone());
    }
  }

  // (2) Format tags via the typed SERDE path — `serde_json::to_value` over the
  // `Rendered` wrapper (the actual Stage-2 output mechanism).
  if let Some(meta) = typed_parse(fixture, data) {
    let rendered = serde_json::to_value(Rendered::new(&meta, print_on))
      .expect("Rendered serialization is infallible");
    if let Value::Object(format_map) = rendered {
      for (key, value) in format_map {
        // `%noDups` first-wins: orchestration keys (inserted above) win.
        obj.entry(key).or_insert(value);
      }
    }
  }

  Value::Array(vec![Value::Object(obj)]).to_string()
}

#[test]
fn typed_serde_path_equals_writer_path_and_golden_all_145() {
  // 121 → 124 after F2 (Codex adversarial): added MPC + WavPack chain
  // fixtures (mpc_with_id3v2_prefix.mpc, mpc_with_apev2_trailer.mpc,
  // wavpack_with_apev2_trailer.wv). These exercise the ID3-prefix /
  // APE-trailer chains the previous typed dispatch silently dropped.
  // 124 → 125 after R3 F1 (Codex adversarial): added
  // `ogg_id3_prefixed.ogg` to exercise the OGG ID3-prefix chain.
  // 125 → 126 after R3 F2 (Codex adversarial): added `Opus.opus` (the
  // bundled t/images fixture) to exercise the `METADATA_BLOCK_PICTURE`
  // Vorbis-comment SubDirectory hop into `%FLAC::Picture` (FLAC.pm:84-
  // 134). The other R3 F2 fixture (`FLAC.ogg`, Ogg-FLAC transport) is
  // formally accept-deferred — see `NOT_ACTIVE`.
  // 126 → 127 after FORMATS.md row 23 lib/matroska: added `Matroska.mkv`
  // (bundled t/images fixture, 507 bytes) to exercise the EBML walker +
  // tag-table dispatch ported in `src/formats/matroska.rs`.
  // 127 → 131 after PR #31 Round-1 findings (F1, F2, F3, F5): added
  // `Matroska_simpletag.mkv`, `Matroska_unknown_segment.mkv`,
  // `Matroska_cluster_skip.mkv`, `Matroska_attachment.mkv` — synthetic
  // adversarial fixtures exercising SimpleTag/StdTag mapping,
  // unknown-size Segment, default Cluster-stop, and binary-placeholder
  // emission (see `tests/conformance.rs::matroska_*_conformance`).
  // 131 → 133 after PR #31 Round-2 finding (DateUTC subsecond loss):
  // added `Matroska_subsecond_date.mkv` (positive raw_ns with non-zero
  // nanosecond remainder) and `Matroska_negative_subsecond_date.mkv`
  // (pre-2001 raw_ns < 0 exercising both the EBML 8-byte signed-decode
  // f64 promotion loss and the $frac < 0 correction branch). Both
  // verify the new `convert_matroska_date` faithful transliteration of
  // `Matroska.pm:1184-1198` + `ExifTool.pm:6773-6800` fractional branch.
  // 136 → 137 after PR #31 R4 finding F1 (Codex adversarial): added
  // `Matroska_chapters.mkv` exercising ChapterTimeStart/ChapterTimeEnd
  // (Matroska.pm:580-592 unsigned-ns → /1e9 → ConvertDuration), the
  // ChapterDisplay (ID 0) traversal fix, and the `Chapter<n>` family-1
  // group attribution (Matroska.pm:1117-1119 chapterNum counter).
  // 137 → 138 after PR #31 R4 finding F2 (Codex adversarial): added
  // `Matroska_track_targeted_tag.mkv` exercising the
  // TagTrackUID → Track<N> group override (Matroska.pm:1207-1216
  // %trackNum map populated from TrackUID inside TrackEntry, looked up
  // at TagTrackUID time to switch SET_GROUP1 for the enclosing Tag).
  // 138 → 139 after PR #31 R5 finding (Codex adversarial): added
  // `Matroska_simpletag_duplicates.mkv` exercising last-wins overwrite
  // semantics on SimpleTag children (Matroska.pm:1226 `$$struct{$tagName}
  // = $val` is plain Perl hash assignment) AND TagDefault absorbed-not-
  // emitted (Matroska.pm:1224-1226 routes ALL leaves into struct when
  // active; Matroska.pm:929 explicitly drops TagDefault at flush).
  // 139 → 141 after the Real (RM/RA) port (FORMATS.md row 19): added
  // the bundled `Real.rm` (chunk-walk + RJMD footer + ID3v1) and
  // `Real.ra` (RealAudio V4 codec table) fixtures.
  // 128 → 130 after Codex R1 F2 (PR #33): added 2 adversarial Real
  // fixtures pinning the ID3v1-trailer fidelity gap (empty Title
  // preserved as `""`; sparse Genre byte 192 preserved verbatim).
  // 130 → 132 after Codex R1 F1 (PR #33): added 2 adversarial Real
  // fixtures pinning the MIME-override branch (1-stream audio MIME
  // ⇒ override fires; 2 populated streams ⇒ no override). The 2
  // empty-MIME F1 variants (1empty, 2_empty_audio) live in fixtures/
  // for unit tests only — bundled emits a Perl-interpreter-level
  // `Condition FileInfoLen2: Use of uninitialized value` warning that
  // this Rust port does not (and should not) replicate, so they
  // cannot be value-equivalent at the JSON surface.
  let root = env!("CARGO_MANIFEST_DIR");
  let fixtures = active_fixtures();
  assert_eq!(
    fixtures.len(),
    145,
    "expected exactly the 145 active conformance fixtures, found {}: {:?}",
    fixtures.len(),
    fixtures
  );

  let mut failures: Vec<String> = Vec::new();

  for fixture in &fixtures {
    let data = std::fs::read(format!("{root}/tests/fixtures/{fixture}"))
      .unwrap_or_else(|e| panic!("read fixture {fixture}: {e}"));
    let golden_j = std::fs::read_to_string(format!("{root}/tests/golden/{fixture}.json"))
      .unwrap_or_else(|e| panic!("read golden {fixture}.json: {e}"));
    let golden_n = std::fs::read_to_string(format!("{root}/tests/golden/{fixture}.n.json"))
      .unwrap_or_else(|e| panic!("read golden {fixture}.n.json: {e}"));

    for (mode, print_on, golden) in [("j", true, &golden_j), ("n", false, &golden_n)] {
      let typed = typed_serde_document(fixture, &data, print_on);
      let writer = extract_info(fixture, &data, print_on);

      // typed serde == writer path.
      if let Err(e) = json_equivalent(&typed, &writer) {
        failures.push(format!(
          "[{mode}] {fixture}: typed-serde != writer-path: {}\n  typed:  {typed}\n  writer: {writer}",
          e.message()
        ));
      }
      // typed serde == golden.
      if let Err(e) = json_equivalent(&typed, golden) {
        failures.push(format!(
          "[{mode}] {fixture}: typed-serde != golden: {}\n  typed:  {typed}\n  golden: {golden}",
          e.message()
        ));
      }
    }
  }

  assert!(
    failures.is_empty(),
    "STAGE-1 PARITY CHECKPOINT failed for {} case(s):\n{}",
    failures.len(),
    failures.join("\n")
  );

  eprintln!(
    "=== STAGE-1 PARITY CHECKPOINT: typed-serde == writer == golden for all {} fixtures, both -j and -n ===",
    fixtures.len()
  );
}
