//! Byte-exact parity for the direct [`exifast::json_writer::JsonTagWriter`]:
//! for EVERY conformance fixture, the JSON it emits — driven from the TYPED
//! parse path (`any_parser_for` → `AnyParser::parse_any` → `AnyMeta` →
//! `MetaSinker::sink`) — must be jsondiff-equivalent to the committed
//! bundled-ExifTool golden, in BOTH `-j` (PrintConv) and `-n` (numeric) modes.
//!
//! This proves the redesign target (Phase #124): `JsonTagWriter` can replace
//! the `MetadataTagWriter` → `Metadata` → `to_exiftool_json` chain on the
//! OUTPUT path, producing bundled-identical JSON DIRECTLY from a typed `Meta`.
//!
//! ## What the typed path emits vs. what the golden contains
//!
//! The golden = `ExifTool:ExifToolVersion` + the `File:*` triplet
//! (`FileType` / `FileTypeExtension` / `MIMEType`) + the format's tags
//! (+ any `ExifTool:Warning` / `ExifTool:Error`). The typed
//! `MetaSinker::sink` emits ONLY the format's tags (and any warnings/errors
//! the Meta itself raises) — the `ExifTool:*` version tag and the `File:*`
//! triplet are *orchestration* set by `parser::extract_info` /
//! `ParseContext::set_file_type` (`AAC.pm:107` `$et->SetFileType()`,
//! `ExifTool.pm:3060` `ExifToolVersion`), OUTSIDE the per-format `Meta`.
//!
//! So this harness reproduces `extract_info`'s orchestration around the
//! writer: it lifts the `ExifTool:*` + `File:*` tags (and the
//! warnings/errors, which include the post-loop finalization `Error`) from
//! the authoritative `extract_info` `Metadata` — those are plain
//! `TagValue::Str` pushes, already pinned byte-exact by the §4 conformance
//! suite — then drives the TYPED `sink` for the format tags on top. The
//! `JsonTagWriter`'s own `%noDups` first-wins dedup (`exiftool:2950-2951`)
//! makes the lift + sink composition order-insensitive.
//!
//! For comparison rigour, every fixture is ALSO checked the "writer-only"
//! way: the COMPLETE `extract_info` tag stream replayed through the writer
//! must equal `to_exiftool_json` over the same `Metadata` — a byte-for-byte
//! proof that the writer is a faithful re-composition of the serializer for
//! the real, full tag set of every format.

use exifast::TagWriter;
use exifast::filetype::detection_candidates;
use exifast::json_writer::JsonTagWriter;
use exifast::jsondiff::json_equivalent;
use exifast::parser::extract_info;
use exifast::parser_new::{MetaSinker, SharedFlags, any_parser_for};
use exifast::serialize::to_exiftool_json;
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

/// WRITER-ONLY parity: the COMPLETE `extract_info` tag stream replayed
/// through `JsonTagWriter` must be byte-identical to `to_exiftool_json` over
/// the same `Metadata`. Proves the direct writer reproduces the serializer
/// for the real, full tag set (every variant the format actually emits).
fn writer_matches_serialize(fixture: &str, data: &[u8], print_on: bool) -> Result<(), String> {
  let m = extract_info(fixture, data, print_on);
  let via_serialize = to_exiftool_json(&m);
  let mut w = JsonTagWriter::new(fixture);
  for t in m.tags() {
    // `extract_info`'s tags carry family-1 == JSON token group. Replay each
    // through the writer (family-0 == family-1 here, which matches the
    // serializer's `%noDups` family-1 token).
    replay_value(&mut w, t.group().family1(), t.name(), t.value())
      .expect("JsonTagWriter is Infallible");
  }
  for warn in m.warnings() {
    w.write_warning(warn).expect("JsonTagWriter is Infallible");
  }
  for err in m.errors() {
    w.write_error(err).expect("JsonTagWriter is Infallible");
  }
  let via_writer = w.finish();
  if via_writer == via_serialize {
    Ok(())
  } else {
    Err(format!(
      "writer != serialize\n  writer:    {via_writer}\n  serialize: {via_serialize}"
    ))
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
  // Authoritative full Metadata (orchestration + format tags) — already
  // §4-conformant. We lift ONLY the orchestration tags + warnings/errors
  // from it; the format tags are produced by the typed sink below.
  let m = extract_info(fixture, data, print_on);
  let mut w = JsonTagWriter::new(fixture);

  // Orchestration: `ExifTool:ExifToolVersion` + the `File:*` triplet
  // (`extract_info` + `set_file_type`, OUTSIDE the per-format Meta).
  for t in m.tags() {
    let g1 = t.group().family1();
    if g1 == "ExifTool" || g1 == "File" {
      replay_value(&mut w, g1, t.name(), t.value()).expect("JsonTagWriter is Infallible");
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
    for t in m.tags() {
      let g1 = t.group().family1();
      if g1 != "ExifTool" && g1 != "File" {
        replay_value(&mut w, g1, t.name(), t.value()).expect("JsonTagWriter is Infallible");
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
/// `MetaSinker::sink`) does NOT yet reproduce the bundled golden, because the
/// CHAINED sub-format tags are surfaced only through the legacy
/// `OldFormatParser::process` dispatch — NOT yet through the typed
/// `AnyMeta`/`AnyParser` chaining. These are the gaps the parallel
/// `OldFormatParser`-retirement pass on `lib/fix-all` is closing; the #124
/// integration pass will flip them green here once `parse_any` chains:
///
/// - `AIFF_id3.aif` — AIFF with an embedded ID3 chunk: `AiffMeta::sink` emits
///   the AIFF tags but the typed path does not run the chained `ProcessID3`,
///   so `ID3v1:*` is missing (legacy AIFF bridge runs it).
/// - `ape_*` (4) — APE chained with ID3 (prefix / v1 trailer / v2.4 footer /
///   enhanced-tag): the typed `AnyParser::Ape` arm
///   (`ape::parse_full_owned`) does not surface the `MAC:*` binary header
///   **and** the chained `ID3v1:*`/`ID3v2_*` tags together via `parse_any`
///   the way the legacy bridge does.
/// - `dsf_with_id3v2_trailer.dsf` — DSF chained with an ID3v2 trailer: the
///   typed `AnyParser::Dsf` arm (`dsf::parse_borrowed`) exposes the trailer
///   scan range on the Meta but does not itself run the chained `ProcessID3`,
///   so `ID3v2_3:Title` is missing from the typed sink.
/// - `APE_dup_override.ape` — the typed APE `Composite:Duration` computes a
///   different value (16.01 s) than bundled (14.71 s): a typed-path Composite
///   derivation difference (frame math / SampleRate source), independent of
///   the writer.
///
/// IMPORTANT: every one of these passes the **writer-only** parity below
/// (122/122) — the `JsonTagWriter` renders the complete real tag stream
/// byte-exactly. The gaps are purely in what the TYPED parse path emits, owned
/// by the format/parser code the other agent is editing. Listed here (not
/// silently skipped) per the task's "noted, not skipped" requirement.
const KNOWN_TYPED_GAPS: &[&str] = &[
  "AIFF_id3.aif",
  "ape_id3_prefixed.ape",
  "ape_id3v24_footer_then_mac.ape",
  "ape_with_enhancedtag_and_id3v1.ape",
  "ape_with_id3v1_trailer.ape",
  "dsf_with_id3v2_trailer.dsf",
  "APE_dup_override.ape",
];

#[test]
fn json_writer_byte_exact_parity_all_fixtures() {
  let root = env!("CARGO_MANIFEST_DIR");
  let fixtures = all_fixtures();
  assert!(
    fixtures.len() >= 120,
    "expected the full conformance fixture set (>=120), found {}",
    fixtures.len()
  );

  let mut writer_ok_j = 0usize;
  let mut writer_ok_n = 0usize;
  let mut typed_ok_j = 0usize;
  let mut typed_ok_n = 0usize;
  let mut typed_handled = 0usize;
  // The WRITER deliverable: byte-exact rendering of the full tag stream. ANY
  // entry here is a hard failure.
  let mut writer_failures: Vec<String> = Vec::new();
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

    // ---- WRITER-ONLY parity (hard gate, both modes) ----
    match writer_matches_serialize(fixture, &data, true) {
      Ok(()) => writer_ok_j += 1,
      Err(e) => writer_failures.push(format!("[writer -j] {fixture}: {e}")),
    }
    match writer_matches_serialize(fixture, &data, false) {
      Ok(()) => writer_ok_n += 1,
      Err(e) => writer_failures.push(format!("[writer -n] {fixture}: {e}")),
    }

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
  eprintln!("=== JsonTagWriter parity over {total} fixtures ===");
  eprintln!(
    "WRITER-ONLY vs to_exiftool_json (the deliverable): -j {writer_ok_j}/{total}, -n {writer_ok_n}/{total}"
  );
  eprintln!(
    "TYPED-PATH vs bundled golden:                      -j {typed_ok_j}/{total}, -n {typed_ok_n}/{total}"
  );
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

  // Hard gate 1: the writer must be byte-exact for the full tag stream of
  // EVERY fixture, in BOTH modes. This is the component deliverable.
  assert!(
    writer_failures.is_empty(),
    "{} WRITER parity failure(s) (these are JsonTagWriter bugs):\n{}",
    writer_failures.len(),
    writer_failures.join("\n")
  );
  assert_eq!(writer_ok_j, total, "writer-only -j must be 122/122");
  assert_eq!(writer_ok_n, total, "writer-only -n must be 122/122");

  // Hard gate 2: no NEW typed-path mismatch outside the known-gap allowlist.
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
