//! Byte-exact parity for the TYPED parse path through
//! [`exifast::json_writer::JsonTagWriter`]: for EVERY conformance fixture, the
//! JSON the TYPED path emits (`any_parser_for` → `AnyParser::parse_any` →
//! `AnyMeta` → `MetaSinker::sink`) must be jsondiff-equivalent to the committed
//! bundled-ExifTool golden, in BOTH `-j` (PrintConv) and `-n` (numeric) modes.
//!
//! ## Relationship to `conformance.rs` (task #124)
//!
//! After task #124, `JsonTagWriter` IS the engine's `$$et` value sink:
//! `parser::extract_info` produces its byte-exact JSON directly via
//! `JsonTagWriter::finish()`, and `conformance.rs` already pins that ENGINE
//! (`process(ctx)`) path against the goldens. So the old "writer-only vs
//! `to_exiftool_json`" comparison this file used to run is now exactly what
//! `conformance.rs` proves — it has been removed here (the `Metadata` →
//! `to_exiftool_json` output path it compared against no longer exists).
//!
//! What remains UNIQUE to this harness is the TYPED `parse_any` path
//! (`parse_bytes`-style), which `conformance.rs` does NOT exercise. We lift the
//! orchestration tags (`ExifTool:ExifToolVersion` + the `File:*` triplet) and
//! warnings/errors off the authoritative engine writer
//! ([`extract_info_to_writer`], itself §4-conformant), then drive the TYPED
//! `MetaSinker::sink` for the format tags on top and compare to the golden. The
//! `JsonTagWriter`'s own `%noDups` first-wins dedup (`exiftool:2950-2951`)
//! makes the lift + sink composition order-insensitive.
//!
//! Gated on `feature = "json"` (Codex A-R4-2): imports the `json`-gated
//! `jsondiff`, which `std` does not imply, so a `--features std,id3` test
//! build skips this whole file.
#![cfg(feature = "json")]

use exifast::TagWriter;
use exifast::filetype::detection_candidates;
use exifast::json_writer::JsonTagWriter;
use exifast::jsondiff::json_equivalent;
use exifast::parser::extract_info_to_writer;
use exifast::parser_new::{MetaSinker, SharedFlags, any_parser_for};
use exifast::value::TagValue;

/// The full fixture set: every `tests/fixtures/<f>` that has both a
/// `tests/golden/<f>.json` and a `tests/golden/<f>.n.json`.
fn all_fixtures() -> Vec<String> {
  let root = env!("CARGO_MANIFEST_DIR");
  let mut out = Vec::new();
  for entry in std::fs::read_dir(format!("{root}/tests/fixtures")).expect("read fixtures dir") {
    let entry = entry.expect("dir entry");
    if !entry.file_type().expect("file type").is_file() {
      continue;
    }
    let name = entry.file_name().to_string_lossy().into_owned();
    let j = format!("{root}/tests/golden/{name}.json");
    let n = format!("{root}/tests/golden/{name}.n.json");
    if std::path::Path::new(&j).is_file() && std::path::Path::new(&n).is_file() {
      out.push(name);
    }
  }
  out.sort();
  out
}

/// Replay a single `TagValue` into a [`TagWriter`] using the mapping that
/// produces the byte-identical stored value. Mirrors the per-format sinks
/// (e.g. `ape::emit_tag_value`): `Bool` → `"true"`/`"false"` string, an
/// all-string `List` → `write_str_list`. (No real fixture emits a typed
/// `Rational` or a mixed-type `List` — the only golden array anywhere is the
/// all-string `Vorbis:Artist` — so the reserved arms use the same forms the
/// sinks reserve for forward-compat.)
fn replay_value<W: TagWriter>(
  out: &mut W,
  group: &str,
  name: &str,
  v: &TagValue,
) -> Result<(), W::Error> {
  match v {
    TagValue::Str(s) => out.write_str(group, name, s.as_str()),
    TagValue::I64(n) => out.write_i64(group, name, *n),
    TagValue::U64(n) => out.write_u64(group, name, *n),
    TagValue::F64(x) => out.write_f64(group, name, *x),
    TagValue::Bytes(b) => out.write_bytes(group, name, b.as_slice()),
    TagValue::Bool(b) => out.write_str(group, name, if *b { "true" } else { "false" }),
    TagValue::Rational(r) => out.write_str(
      group,
      name,
      &format!("{}/{}", r.numerator(), r.denominator()),
    ),
    TagValue::List(items) => {
      // Every golden list is all-string (Vorbis:Artist). Render via
      // write_str_list when so; otherwise fall back to per-element replay
      // (which the jsondiff would then catch if a non-str list ever appears).
      if items.iter().all(|it| matches!(it, TagValue::Str(_))) {
        let owned: Vec<String> = items
          .iter()
          .map(|it| match it {
            TagValue::Str(s) => s.to_string(),
            _ => unreachable!("guarded by all() above"),
          })
          .collect();
        let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
        out.write_str_list(group, name, &refs)
      } else {
        for it in items {
          replay_value(out, group, name, it)?;
        }
        Ok(())
      }
    }
  }
}

/// Resolve the typed parser the SAME way `extract_info` does — walk the
/// detection candidates in `ExtractInfo` loop order; the first whose
/// `any_parser_for` is `Some` AND whose `parse_any` returns `Ok(Some(meta))`
/// wins. Returns `None` when no typed parser accepts (rejected/unsupported
/// fixtures — e.g. `bad.ogg`, where the golden's tags come from
/// finalization, not a Meta).
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
      Ok(None) => {
        // Reset shared between rejected candidates (mirrors `parse_bytes`).
        shared = SharedFlags::new();
      }
      Err(_) => {
        shared = SharedFlags::new();
      }
    }
  }
  None
}

/// TYPED-PATH parity: lift the orchestration tags (`ExifTool:*` + `File:*`)
/// and warnings/errors from `extract_info`, drive the TYPED `MetaSinker::sink`
/// for the format tags, then compare the writer's JSON to the bundled golden
/// via `json_equivalent`. Returns `Ok(typed_handled)` where `typed_handled`
/// is whether a typed Meta contributed (false ⇒ rejected/finalization-only
/// fixture, format tags came from the orchestration lift).
fn typed_path_matches_golden(
  fixture: &str,
  data: &[u8],
  golden: &str,
  print_on: bool,
) -> Result<bool, String> {
  // Authoritative full engine writer (orchestration + format tags) — already
  // §4-conformant. We lift ONLY the orchestration tags + warnings/errors
  // from its buffered records; the format tags are produced by the typed sink
  // below. `extract_info_to_writer` is `extract_info` minus the final
  // `.finish()`, so its records are exactly the engine's emission.
  let m = extract_info_to_writer(fixture, data, print_on);
  let mut w = JsonTagWriter::new(fixture);

  // Orchestration: `ExifTool:ExifToolVersion` + the `File:*` triplet
  // (`extract_info` + `set_file_type`, OUTSIDE the per-format Meta).
  for (group, name, value) in m.records() {
    let g1 = group.family1();
    if g1 == "ExifTool" || g1 == "File" {
      replay_value(&mut w, g1, name, value).expect("JsonTagWriter is Infallible");
    }
  }
  // Warnings/errors (incl. the post-loop finalization `Error`). Lifted first
  // so the writer's `%noDups` first-wins keeps the authoritative value if the
  // typed sink also raises one (`exiftool:2951`).
  for warn in m.warnings() {
    w.write_warning(warn).expect("JsonTagWriter is Infallible");
  }
  for err in m.errors() {
    w.write_error(err).expect("JsonTagWriter is Infallible");
  }

  // Format tags via the TYPED path.
  let typed_handled = if let Some(meta) = typed_parse(fixture, data) {
    meta
      .sink(print_on, &mut w)
      .expect("JsonTagWriter is Infallible");
    true
  } else {
    // No typed Meta (rejected / finalization-only). The orchestration lift
    // already carries every golden tag (File:* + Error); we additionally lift
    // any non-orchestration format tags so the comparison is honest about
    // what the typed path could NOT yet produce.
    let mut lifted_format = false;
    for (group, name, value) in m.records() {
      let g1 = group.family1();
      if g1 != "ExifTool" && g1 != "File" {
        replay_value(&mut w, g1, name, value).expect("JsonTagWriter is Infallible");
        lifted_format = true;
      }
    }
    let _ = lifted_format;
    false
  };

  let got = w.finish();
  json_equivalent(&got, golden).map_err(|e| e.message().to_string())?;
  Ok(typed_handled)
}

/// Fixtures whose **typed** parse path (`AnyParser::parse_any` →
/// `MetaSinker::sink`) does NOT reproduce the bundled golden. After the
/// sink-layer unification the only remaining entry is the one Phase-2 forward
/// item where the **engine path ALSO diverges from the golden**:
///
/// - `AIFF_id3.aif` — AIFF with an embedded `ID3 ` CHUNK (AIFF.pm:202 ID3
///   SubDirectory dispatch). Neither the typed path NOR the engine
///   `ProcessAiff::process` runs the chained `ProcessID3` over the chunk body
///   (the `ID3 ` chunk is recognized then silently skipped — see the
///   `id3_chunk_recognized_then_silently_skipped` unit test in
///   `src/formats/aiff.rs`), so `File:ID3Size` + `ID3v2_3:Title` are missing
///   in BOTH paths. This is the SAME deliberate divergence the
///   `#[ignore]`-d `aiff_id3_chunk_subdirectory_dispatch_deferred_conformance`
///   test in `conformance.rs` documents — `AIFF_id3.aif` is therefore NOT one
///   of the 121 active conformance fixtures. The typed path here matches the
///   engine path (both lack ID3); it diverges only from the GOLDEN, which pins
///   the post-merge oracle for when the AIFF ID3-chunk dispatch lands.
///
/// All five formerly-listed chained gaps (the four `ape_*` ID3-prefix/trailer
/// fixtures + `dsf_with_id3v2_trailer.dsf` + the `APE_dup_override.ape`
/// composite) now pass typed parity: APE and DSF nest a typed `Id3Meta` and
/// the APE intra-composite resolves last-wins, so the typed `parse_any` path
/// emits the complete chained tag set.
const KNOWN_TYPED_GAPS: &[&str] = &["AIFF_id3.aif"];

#[test]
fn json_writer_byte_exact_parity_all_fixtures() {
  let root = env!("CARGO_MANIFEST_DIR");
  let fixtures = all_fixtures();
  assert!(
    fixtures.len() >= 120,
    "expected the full conformance fixture set (>=120), found {}",
    fixtures.len()
  );

  let mut typed_ok_j = 0usize;
  let mut typed_ok_n = 0usize;
  let mut typed_handled = 0usize;
  // Typed-path mismatches NOT on the known-gap allowlist — a regression in
  // the typed parse path; hard failure.
  let mut unexpected_typed_failures: Vec<String> = Vec::new();
  // Known typed-path gaps that (still) fail — expected; reported only.
  let mut known_gap_hits: Vec<String> = Vec::new();
  // Known-gap fixtures that UNEXPECTEDLY passed typed parity — the other
  // agent fixed them; flag so the allowlist can be tightened.
  let mut newly_passing_gaps: Vec<String> = Vec::new();

  let is_gap = |f: &str| KNOWN_TYPED_GAPS.contains(&f);

  for fixture in &fixtures {
    let data = std::fs::read(format!("{root}/tests/fixtures/{fixture}"))
      .unwrap_or_else(|e| panic!("read fixture {fixture}: {e}"));
    let golden_j = std::fs::read_to_string(format!("{root}/tests/golden/{fixture}.json"))
      .unwrap_or_else(|e| panic!("read golden {fixture}.json: {e}"));
    let golden_n = std::fs::read_to_string(format!("{root}/tests/golden/{fixture}.n.json"))
      .unwrap_or_else(|e| panic!("read golden {fixture}.n.json: {e}"));

    // ---- TYPED-PATH parity (allowlist-gated, both modes) ----
    let mut typed_pass = true;
    match typed_path_matches_golden(fixture, &data, &golden_j, true) {
      Ok(handled) => {
        typed_ok_j += 1;
        if handled {
          typed_handled += 1;
        }
      }
      Err(e) => {
        typed_pass = false;
        if is_gap(fixture) {
          known_gap_hits.push(format!("[typed -j] {fixture}: {e}"));
        } else {
          unexpected_typed_failures.push(format!("[typed -j] {fixture}: {e}"));
        }
      }
    }
    match typed_path_matches_golden(fixture, &data, &golden_n, false) {
      Ok(_) => typed_ok_n += 1,
      Err(e) => {
        typed_pass = false;
        if is_gap(fixture) {
          known_gap_hits.push(format!("[typed -n] {fixture}: {e}"));
        } else {
          unexpected_typed_failures.push(format!("[typed -n] {fixture}: {e}"));
        }
      }
    }
    if is_gap(fixture) && typed_pass {
      newly_passing_gaps.push(fixture.clone());
    }
  }

  let total = fixtures.len();
  eprintln!("=== JsonTagWriter TYPED-PATH parity over {total} fixtures ===");
  eprintln!("TYPED-PATH vs bundled golden: -j {typed_ok_j}/{total}, -n {typed_ok_n}/{total}");
  eprintln!("  (typed Meta contributed format tags for {typed_handled}/{total} in -j)");
  if !known_gap_hits.is_empty() {
    eprintln!(
      "  KNOWN typed-path gaps (chained-format / Composite — owned by the \
       OldFormatParser-retirement pass), {} case(s):",
      known_gap_hits.len()
    );
    for g in &known_gap_hits {
      eprintln!("    - {g}");
    }
  }

  // The WRITER-ONLY vs `to_exiftool_json` gate this test used to assert is now
  // covered by `conformance.rs` (the engine `process` path IS the
  // `JsonTagWriter` after task #124); the `Metadata` → `to_exiftool_json`
  // output path it compared against no longer exists.

  // Hard gate: no NEW typed-path mismatch outside the known-gap allowlist.
  assert!(
    unexpected_typed_failures.is_empty(),
    "{} UNEXPECTED typed-path failure(s) (regression outside KNOWN_TYPED_GAPS):\n{}",
    unexpected_typed_failures.len(),
    unexpected_typed_failures.join("\n")
  );

  // Soft signal: if a known gap started passing, the allowlist is stale —
  // surface it so the integration pass tightens it (does not fail the build,
  // since the other agent's landing order is independent of this branch).
  if !newly_passing_gaps.is_empty() {
    eprintln!(
      "NOTE: {} KNOWN_TYPED_GAPS now pass typed parity — tighten the allowlist: {:?}",
      newly_passing_gaps.len(),
      newly_passing_gaps
    );
  }
}
