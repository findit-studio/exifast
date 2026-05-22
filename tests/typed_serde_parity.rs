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
//! ## Excluded fixtures
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
//! `flash_xmp_livexml.flv` is similarly excluded: Flash.pm:243-246 dispatches
//! the `liveXML` AMF key through `Image::ExifTool::XMP::Main` (FORMATS.md row
//! 15 XMP infra, 6693 LOC, Phase-3+). Both the engine and typed paths surface
//! the deferral as `ExifTool:Warning: "XMP SubDirectory dispatch deferred
//! (Phase-3+)"`; the bundled golden additionally carries `XMP-*:*` tags we
//! cannot synthesize without the XMP parser. Pinned by the `#[ignore]`-d
//! `flash_xmp_livexml_subdirectory_deferred_conformance` test. Codex PR #32 R6.
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
/// - `flash_xmp_livexml.flv` — Codex PR #32 R6: Flash.pm:243-246
///   dispatches the `liveXML` AMF key through `Image::ExifTool::XMP::Main`
///   (FORMATS.md row 15 XMP infra, 6693 LOC, Phase-3+). Bundled emits
///   `XMP-*:*` tags via XMP::ProcessXMP; exifast surfaces the deferral as
///   `ExifTool:Warning: "XMP SubDirectory dispatch deferred (Phase-3+)"`
///   so the gap is visible (see `src/formats/flash.rs::
///   is_xmp_subdirectory_dispatch`). Pinned by
///   `tests/conformance.rs::flash_xmp_livexml_subdirectory_deferred_conformance`
///   (#[ignore]d).
const NOT_ACTIVE: &[&str] = &["AIFF_id3.aif", "FLAC.ogg", "flash_xmp_livexml.flv"];

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
fn typed_serde_path_equals_writer_path_and_golden_all_186() {
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
  // 132 → 133 after Codex R2 (PR #33): added 1 adversarial Real fixture
  // (`real_synth_embedded_nul_mime.rm`) pinning the bundled first-NUL
  // truncation (ReadValue at ExifTool.pm:6300 + Real.pm:643) on
  // `Format => 'string[$val{10}]'` StreamMimeType. Without the fix,
  // an embedded NUL leaks through both `Real-MDPR:StreamMimeType` AND
  // the single-stream `File:MIMEType` override.
  // 146 → 149 after the PR #33 Copilot RAM/RPM fix: added 3 Metafile
  // fixtures (`real_synth_ram_pnm.ram`, `real_synth_rpm_pnm.rpm`,
  // `real_synth_metafile_http_accept.ram`) pinning the Real.pm:533-555
  // Metafile branch — the RAM-vs-RPM extension discrimination, the
  // `^[a-z]{3,4}://` URL/text split, and the `http`-line acceptance gate.
  // 126 → 127 after wave-a-flash: added `Flash.flv` (FORMATS.md row 18,
  // bundled FLV fixture with audio/video bit-stream + AMF onMetaData).
  // 127 → 135 after Codex R1 Flash F1/F2 fixes: added 8 synthetic FLVs
  // exercising AMF strict-array heterogeneous emission (strings/bools/
  // dates/mixed) + per-AMF-type truncation warning paths (double/string/
  // date/array).
  // 135 → 136 after Codex R2/F3 fix: added `flash_f3_unsupported.flv`
  // — bundled emits `Flash:Duration` + the `AMF AMF3data record not
  // yet supported` warning; the prior `ReadResult::Truncated`
  // discriminant collision let the top-level walker silently pop the
  // unsupported diagnostic.
  // 136 → 137 after Codex R2/F2 fix: added `flash_f2_nested_array.flv`
  // — bundled emits `OuterArr: [[1,2],99]` (nested strict-array
  // preserved as nested JSON list); prior shape returned
  // `AmfValue::StrictArray` from `read_value` without consuming the
  // nested array's count+payload, leaving the cursor mid-array.
  // 137 → 139 after Codex R2/F1 verification pin: added
  // `flash_f1_double_first.flv` and `flash_f1_struct_first.flv` —
  // bundled WALKS PAST a non-string scalar at rec=0 and walks the
  // children of a struct at rec=0 inline (Flash.pm:442's
  // `unless ($isStruct{$type})` SKIPS the gate for any struct; the
  // `else` arm at lines 448-452 is verbose-only for non-string
  // non-struct rec=0 — NO `last`). The original Codex R2/F1 framing
  // suggested bundled rejects in both cases, but empirical bundled
  // output contradicts. Current Rust walker already matches bundled;
  // these fixtures PIN the walk-past behaviour so a future
  // regression would fail conformance.
  // 139 → 140 after Codex R3/F1: added `flash_amf_scalars.flv`
  // (onMetaData mixed-array carrying five AMF scalar shapes —
  // null/undef/unsupported emit `""`, reference emits the u16 numeric
  // value, control double emits 7.5 — per Flash.pm:403-409).
  // 140 → 141 after Codex R3/F2: added `flash_array_with_empties.flv`
  // (strict-array `[null, undef, ref(3), double(4)]` emits
  // `["","",3,4]` per Flash.pm:417-422 `push @vals, $v unless
  // $isStruct{$t}`).
  // 141 → 142 after Codex R3/F3: added `flash_top_strict_array.flv`
  // (top-level 0x0a between onMetaData and a mixed-array — bundled
  // walks past the lone strict-array per Flash.pm:410-426 reached
  // from the outer record loop, then emits the mixed-array's
  // `goodKey: 7.5`).
  // 142 → 143 after Codex R4/F2 fix: added
  // `flash_f4_nested_array_prefix.flv` (nested strict-array recursion
  // MUST carry the per-index prefix per Flash.pm:415-418's
  // `$$dirInfo{StructName} = $structName . $i if defined $structName`
  // applied BEFORE recursive ProcessMeta — prior shape passed the outer
  // struct_name unchanged into the nested array walk, collapsing
  // `outerArr[1][0].name` and `outerArr[0][0].name` to the same
  // `OuterArr0Name` tag under first-wins).
  // 143 → 144 after Codex R4/F1 fix: added
  // `flash_f4_array_abort_sibling.flv` (struct walker MUST abort on a
  // failed child array — bundled Flash.pm:382-386's `last Record unless
  // defined $t and defined $v` aborts the entire struct walk, dropping
  // the sibling AFTER the failed array; prior shape unconditionally
  // continued and emitted the sibling).
  // 144 → 145 after Codex R5 verification pin (FALSE POSITIVE): added
  // `flash_f5_array_struct_abort.flv` — bundled does NOT abort the
  // strict-array element loop when a STRUCT element's child is
  // unsupported. Flash.pm:340's `$val = ''` (struct branch dummy) keeps
  // `$val` DEFINED across the inner pair-loop's `last Record`, so the
  // inner ProcessMeta returns `(0x03, '')` (not `(undef, undef)`); the
  // outer array loop's line 420 `last Record unless defined $v` does
  // NOT fire — cursor desync continues at i+1 and bundled emits the
  // misparsed array value `[1.25e-308]` (the next bytes happen to read
  // as a double). Current Rust walker already matches bundled; this
  // fixture PINS the struct-element-failure-does-NOT-propagate-abort
  // behaviour so a future regression would fail conformance.
  // 145 → 146 after Codex R7: added `flash_nested_livexml.flv`. The R6
  // XMP-deferral gate `(Meta && raw_key == "liveXML")` was too broad —
  // it dropped a NESTED `foo.liveXML` with the XMP-deferral warning,
  // even though bundled emits the nested case as a plain auto-add
  // scalar `Flash:FooLiveXML`. Fix narrows the gate to
  // `struct_name.is_empty()` (the TOP-LEVEL un-prefixed case — the
  // only shape that reaches the Meta `liveXML` SubDirectory in
  // bundled). The original top-level fixture (`flash_xmp_livexml.flv`)
  // stays `#[ignore]`-d in `NOT_ACTIVE` (R6 accept-deferral).
  // 146 → 148 after Codex R8: added `flash_empty_key_livexml.flv` AND
  // `flash_toplevel_array_objects.flv`. R7's `is_empty()` gate collapsed
  // Perl's `undef $structName` (top-level / no struct in effect) with
  // a DEFINED empty string `Some("")` (e.g. child under an empty-key
  // parent), and Flash.pm:380 + Flash.pm:418 gate on `defined`, not on
  // length-zero. Two adversarial branches uncovered:
  //   * R8/F1 — `flash_empty_key_livexml.flv`: an empty-key object
  //     containing `liveXML` MUST emit `Flash:LiveXML` (the prefix
  //     branch's `"" . ucfirst("liveXML") = "LiveXML"` auto-adds via
  //     resolve_emit MISS), NOT trigger the XMP-deferral. Pre-R8 the
  //     empty `struct_name` collapsed to the top-level branch and the
  //     value was silently dropped.
  //   * R8/F2 — `flash_toplevel_array_objects.flv`: a top-level
  //     strict-array containing object elements. Bundled does NOT
  //     append the array index per Flash.pm:418's `if defined
  //     $structName` (undef at top level → no append) — bundled emits
  //     `Flash:Name` last-wins (collision intentional). Pre-R8 the
  //     `format!("{struct_name}{i}")` site appended `0`/`1` even when
  //     `struct_name` was the empty/None sentinel, manufacturing
  //     `Flash:0Name`/`Flash:1Name` tags bundled never emits.
  //   Fix changes the walker's `struct_name: &str` to
  //   `Option<&str>` throughout, distinguishing Perl undef (`None`)
  //   from defined empty (`Some("")`), and gates BOTH the
  //   XMP-deferral check AND the array-index append on the `defined`
  //   condition. See `src/formats/flash.rs::is_xmp_subdirectory_dispatch`
  //   and `walk_pairs` doc comments.
  // 148 → 149 after Codex R9/F1: added
  // `flash_keyed_array_truncated_count.flv`. Pre-R9
  // `collect_array_items` returned silent `None` when `*pos + 4 >
  // data.len()` at the strict-array count read; the keyed-value caller
  // dropped bundled's `"Truncated AMF record 0xa"` (Flash.pm:455).
  // Fix introduces `ArrayOutcome::TruncatedCount` so the keyed-value
  // caller (`walk_array` from `walk_pairs`) can push the bundled-
  // faithful warning while the top-level caller stays silent under
  // bundled's $val-from-prior-records rule.
  // 149 → 151 after Codex R9/F2: added
  // `flash_typed_object_truncated_name.flv` (top-level) and
  // `flash_array_typed_object_truncated_name.flv` (nested-in-array).
  // Pre-R9 `skip_struct_intro` returned silent `bool` for typed-object
  // (0x10) name-payload overrun; both top-level and nested-in-array
  // call sites dropped bundled's `"Truncated typedObject record"`
  // (Flash.pm:353). Fix splits the typed-object name parsing into a
  // dedicated `consume_struct_intro` helper that returns an
  // `IntroOutcome` enum and pushes the exact bundled warning text on
  // the payload-overrun path (NOT on the length-truncation path —
  // bundled's $val='' from line 340 keeps that silent).
  // 151 → 153 after Codex R10: added
  // `flash_array_typed_object_truncated_length.flv` and
  // `flash_array_mixed_array_truncated_top_index.flv`. R9/F2 introduced
  // silent `IntroOutcome::Truncated` returns for 0x10 name-LENGTH /
  // 0x08 top-index, but the strict-array element caller
  // (`collect_array_items`) wrapped every `Truncated` with a
  // `"Truncated AMF record 0xa"` push — converting bundled's silent
  // paths into user-visible warnings at the array frame. Fix: enrich
  // `IntroOutcome::Truncated` with `IntroTruncReason` and route the
  // silent reasons to abort-without-push; the typedObject-name-overrun
  // path stays at helper-pushes-warning + caller-no-push (was
  // helper-pushes + caller-also-pushes pre-R10).
  // — rebased onto main post-#33: the counts above are each
  //   branch's own running history; the merged total reconciles
  //   to 149 (main after #31 Matroska + #33 Real) + 27 (lib/flash) = 176.
  // 176 → 178 after Codex R11: added `flash_array_struct_intro_trunc_continues.flv`
  // (R11/F1 — a struct-introducer truncation on a NON-LAST strict-array
  // element must NOT abort the element loop early: bundled's `$val=''`
  // dummy keeps the inner ProcessMeta's return DEFINED, so the loop
  // continues and a later EOF raises `Truncated AMF record 0xa`) and
  // `flash_amf_date_zero_sentinel.flv` (R11/F2 — an AMF date of 0
  // milliseconds must format as ExifTool's `0000:00:00 00:00:00`
  // zero-time sentinel + AMF tz suffix, NOT `1970:01:01 00:00:00...`).
  // 178 → 180 after Codex R12: added `flash_duration_strict_array.flv`
  // (R12/F1 — a known Flash tag with a PrintConv, AMF-encoded as a
  // strict-array, must apply the tag PrintConv per element: `duration`
  // → `["1.50 s","0:01:01"]` under `-j`, raw `[1.5,61]` under `-n`) and
  // `flash_amf_date_pre1000.flv` (R12/F2 — a pre-1000 AMF date must
  // space-pad the year per ExifTool's `sprintf %4d`: Unix second
  // -30641760000 → `" 999:01:01 00:00:00.000000+00:00"`, NOT a
  // zero-padded `"0999:..."`).
  // 180 → 183 after Codex R13: added `flash_duration_nested_array.flv`
  // (R13/F1 — a NESTED strict-array element of a known-PrintConv tag
  // stays raw: `duration` → `[[1.5,61]]`, not `[["1.50 s","0:01:01"]]`),
  // `flash_audio_encoding_reserved.flv` (R13/F2 — a hash-PrintConv MISS
  // renders `Unknown (9)` under -j, raw `9` under -n), and
  // `flash_audio_tail_truncated.flv` (R13/F3 — an audio packet whose
  // declared payload is truncated after the first config byte still
  // emits all four audio tags with no warning).
  // 183 → 184 after Codex R14: added `flash_duration_mixed_nested.flv`
  // (R14/F1 — the owning tag conversion is applied ONCE PER TOP-LEVEL
  // element: `duration` = `[1.5, [2,3], 61]` → `["1.50 s",[2,3],"0:01:01"]`
  // under -j and `[1.5,[2,3],61]` under -n — scalars convert, the nested
  // arrayref passes through raw with no recursive descent). The arithmetic
  // *datarate / FrameRate nested-arrayref case is NOT fixtured: bundled
  // coerces the arrayref to a non-deterministic memory address (no stable
  // golden); covered by the `collect_array_items_mul_1000_*` unit test.
  // 184 → 185 after Codex R15: added `flash_creationdate_strict_array.flv`
  // (R15/F1 — the owning tag STRING ValueConv `$val=~s/\s+$//` is applied
  // per top-level array element: `creationdate` = `["A   ","B\t "]` →
  // `["A","B"]` under BOTH -j and -n. The nested-arrayref string stays raw,
  // covered by the `collect_array_items_trim_ws_*` unit test).
  // 185 → 186 after Codex R16: added `flash_r16_nested_struct_abort.flv`
  // (R16/F1 — a STRUCT-VALUED child whose object body starts with an
  // unsupported AMF3 marker (`00 00 11`) must NOT abort the PARENT pair
  // walk: Flash.pm:340's `$val=''` struct dummy keeps the child's
  // ProcessMeta return `(0x03, '')` defined, so the outer line 386
  // check passes and line 387 `next if $isStruct{$t}` continues — the
  // parent sibling `after=9` IS emitted. Pre-fix the Rust struct-child
  // branch propagated `WalkOutcome::Abort`, silently dropping
  // `Flash:After`).
  // 186 → 187 after Codex R17: added
  // `flash_r17_struct_child_trunc_intro.flv` (R17/F1 — a struct-valued
  // child whose `0x08` mixed-array introducer is itself truncated
  // (`08 00 05`, a 4-byte top-index needs 4 bytes) must NOT enter the
  // child pair loop: Flash.pm:342's `last if $pos+4>$dirLen` exits the
  // struct branch BEFORE the `for(;;)` loop, returning `(0x08,'')`.
  // The parent `obj` object loop then surfaces `Truncated object
  // record` FIRST, the grandparent mixedArray `Truncated mixedArray
  // record` SECOND. Pre-fix the Rust struct-child branch always called
  // `walk_pairs` even for a truncated introducer, pushing `Truncated
  // mixedArray record` first and inverting the warning order / JSON
  // first-wins result).
  // 187 → 188 after Codex R18/F1: added `flash_amf_bad_utf8.flv`
  // (an onMetaData mixed-array whose AMF string (0x02), long-string
  // (0x0c) and XML (0x0f) values each carry the invalid-UTF-8 run
  // `41 ff 42`). Bundled keeps the raw bytes and applies
  // `XMP::FixUTF8` at JSON emit (exiftool:3822 → XMP.pm:2948-2972),
  // rendering `Flash:BadStr/BadLong/BadXml = "A?B"` in both -j and -n.
  // Pre-fix the string-like AMF arms decoded via
  // `String::from_utf8_lossy`, materializing U+FFFD and failing the
  // jsondiff gate; the fix routes every payload-derived AMF string
  // through `crate::convert::fix_utf8` (the faithful FixUTF8
  // transliteration).
  // 188 → 190 after Codex R19/F1: added `flash_amf_string_conv.flv`
  // (scalar) and `flash_amf_string_conv_array.flv` (strict-array). Bundled
  // `GetValue` (ExifTool.pm:3519-3656) applies a tag's ValueConv/PrintConv
  // to `$val` whether AMF carried it as a number (0x00) or a numeric string
  // (0x02/0x0c/0x0f) — Perl numeric coercion turns `"65.8"` into 65.8 inside
  // an arithmetic ValueConv. Pre-fix the AMF-string arm only trimmed
  // `creationdate` and stored the raw string, so numeric fields encoded as
  // AMF strings skipped their conversion (`audiodatarate "65.8"` → bundled
  // `"65.8 kbps"`/`65800`; the port emitted the unconverted `"65.8"`). Fix
  // (`emit_resolved` + `emit_entry` + `collect_array_items` +
  // `flash_list_item_with_pc`): `mul_1000` strings are Perl-coerced and
  // numified to a double (then ConvertBitrate/RoundInt apply); the
  // no-ValueConv-with-PrintConv tags (duration/starttime ConvertDuration,
  // framerate RoundMilli) apply their PrintConv to the string at `-j` emit
  // (ConvertDuration honours the `IsFloat` guard incl. comma-decimal;
  // RoundMilli uses raw arithmetic coercion). The coercion rule
  // (leading-numeric-prefix → number via `convert::perl_str_to_f64`, else 0)
  // is pinned against the bundled oracle in BOTH `-j` and `-n`. The strict-
  // array path mirrors the same per-top-level-element conversion.
  // 190 → 192 after Codex R20/F1: added `flash_amf_nonfinite_inf.flv`
  // (all four numeric fields = `inf`) and `flash_amf_nonfinite_nan.flv`
  // (`NaN`/`Inf`/`-inf`/`nan`). Perl's `Perl_my_atof` coerces the IEEE
  // non-finite spellings (`inf`/`nan`/`infinity`/`1.#INF`, any case + sign)
  // to `±Inf`/`NaN`; the `$val * 1000` ValueConv then carries the non-finite
  // into `ConvertBitrate`/`int($val+0.5)` (audio/video/total) — all of which
  // `IsFloat`-reject it and pass through, stringifying to Perl's titlecase
  // `Inf`/`-Inf`/`NaN` in BOTH `-j` and `-n`. `framerate` (no ValueConv) keeps
  // its raw AMF string under `-n` (lowercase `inf`/`nan` as authored) and runs
  // `int($val*1000+0.5)/1000` under `-j` (→ titlecase). Pre-fix
  // `perl_str_to_f64` returned `0.0` for every non-finite spelling (the
  // ValueConv tags became `0`/`0 bps`) and `ConvertBitrate`/`ConvertDuration`
  // emitted Rust's lowercase `inf`/`-inf`. Both pinned here vs the bundled
  // oracle.
  let root = env!("CARGO_MANIFEST_DIR");
  let fixtures = active_fixtures();
  assert_eq!(
    fixtures.len(),
    192,
    "expected exactly the 192 active conformance fixtures, found {}: {:?}",
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
