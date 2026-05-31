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

use exifast::{
  filetype::detection_candidates,
  format_parser::{Rendered, SharedFlags, any_parser_for},
  jsondiff::json_equivalent,
  parser::extract_info,
};

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
/// - `Exif_makernote.tif` — the Exif port captures the MakerNote (0x927c)
///   raw bytes but DEFERS vendor parsing to the MakerNotes wave; bundled
///   `perl exiftool` emits an `ExifTool:Warning` (or MakerNotes:* tags for
///   a recognized vendor) the exifast Exif port does not. 4-surface
///   accept-defer (see `tests/conformance.rs::
///   exif_makernote_subdirectory_deferred_conformance`, the
///   `SubDirKind::MakerNote` code comment, and docs/tracking.md).
const NOT_ACTIVE: &[&str] = &[
  "AIFF_id3.aif",
  "FLAC.ogg",
  "flash_xmp_livexml.flv",
  "Exif_makernote.tif",
];

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
    // `cand.header_skip()` threads the unknown-leading-header byte count for
    // the terminal JPEG/TIFF candidate (`0` for ordinary candidates) — same
    // dispatch the engine's `extract_info` runs.
    match parser.parse_any(
      data,
      &mut shared,
      ext_ref,
      cand.header_skip(),
      Some(cand.parent_type()),
    ) {
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
fn typed_serde_path_equals_writer_path_and_golden_all_267() {
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
  // 149 → 150 after the QuickTime port Sub-Port 1 (the box/atom walker +
  // core structural atoms): added the synthetic `QuickTime_sp1.mov`
  // fixture exercising `ftyp` + `moov`(`mvhd` + 2 `trak`s) + `mdat`. The
  // real bundled `QuickTime.mov`/`QuickTime.m4a` fixtures land in a later
  // sub-port (see `docs/tracking.md`).
  // 150 → 153 after PR #38 Codex R1 findings F2/F4/F5: added three
  // synthetic adversarial QuickTime fixtures verified vs bundled —
  // `QuickTime_v1tkhd.mov` (version-1 tkhd ImageWidth/Height at offsets
  // 88/92, F2), `QuickTime_moov_order.mov` (trak-before-mvhd ⇒ final-
  // TimeScale durationInfo, F4-refuted), `QuickTime_nested_size0.mov`
  // (contained size-0 terminator drops the trailing trak, F5).
  // 153 → 158 after PR #38 Codex R2 findings F1/F2/F3/F4: added five
  // synthetic adversarial QuickTime fixtures verified vs bundled —
  // `QuickTime_zerodate.mov` (raw-0 mvhd/tkhd/mdhd dates ⇒ "0000:00:00
  // 00:00:00" sentinel, not dropped, R2/F1), `QuickTime_m4a.mov` +
  // `QuickTime_m4v.mov` (ftyp-derived MIME audio/mp4 + video/x-m4v carried
  // through finalization, R2/F2), `QuickTime_zerotimescale.mov` (TimeScale=0
  // ⇒ Duration/TrackDuration emit the bare raw value, R2/F3),
  // `QuickTime_maclang.mov` (Macintosh MediaLanguageCode 12 ⇒ ttLang
  // PrintConv "ar", -n raw 12, R2/F4).
  // 158 → 160 after PR #38 Codex R3 findings F1/F2: added two synthetic
  // adversarial QuickTime fixtures verified vs bundled —
  // `QuickTime_matrixfrac.mov` (a FRACTIONAL mvhd MatrixStructure exercising
  // GetFixed32s' 5-dp rounding + Perl `%.15g` ⇒ "2e-05 0 0 0 2e-05 0 0 0
  // 1.220703125e-09", R3/F1) and `QuickTime_multimoov.mov` (TWO top-level
  // moovs; the second's mvhd overwrites the GLOBAL TimeScale to 300, so the
  // first track's TrackDuration converts as 1200/300 = 4 against the FINAL
  // TimeScale, R3/F2).
  // 160 → 162 after PR #38 Codex R4 findings F1/F2: added two synthetic
  // adversarial QuickTime fixtures verified vs bundled —
  // `QuickTime_size0_moov.mov` (ftyp + a TOP-LEVEL size-0 `moov` whose `mvhd`
  // payload is NOT decoded — ExifTool prints "extends to end of file" and
  // STOPS, QuickTime.pm:10044-10056 — so ONLY the ftyp tags survive, R4/F1)
  // and `QuickTime_multimoov_tracks.mov` (TWO top-level moovs each with one
  // `trak`; ExifTool's `$track` counter is a `my` local of each moov's
  // ProcessMOV call so it RESETS per moov ⇒ BOTH are `Track1`, and the second
  // collapses on the family-1 collision in default JSON — no `Track2`, R4/F2).
  // 162 → 164 after PR #38 Codex R5 findings F1/F2: added two synthetic
  // adversarial QuickTime fixtures verified vs bundled —
  // `QuickTime_multimoov_tracksdistinct.mov` (TWO top-level moovs both numbering
  // their lone `trak` as `Track1` but carrying DISTINCT tags — moov1 a bare
  // `tkhd` with TrackID, moov2 a bare `mdhd`/`hdlr` with MediaTimeScale/
  // MediaDuration/HandlerType; ExifTool's `%noDups` first-wins is per rendered
  // tag KEY not per group, so BOTH sets of `Track1:*` tags survive, R5/F1) and
  // `QuickTime_size0_mdat_first.mov` (a file whose VERY FIRST top-level atom is
  // `size == 0, type = mdat`; the first-atom gate keys on the 4-byte type
  // regardless of size ⇒ FileType MOV + MediaDataSize/Offset then `last`,
  // QuickTime.pm:9984/10044-10056, R5/F2).
  // 164 → 167 after PR #38 Codex R6 findings F1/F2: added three synthetic
  // adversarial QuickTime fixtures verified vs bundled —
  // `QuickTime_multimoov_movdur.mov` (TWO top-level moovs; moov1's `mvhd` has
  // Duration=3000 under TimeScale=600, moov2's SHORT `mvhd` carries only
  // TimeScale=300 with NO Duration ⇒ movie `Duration` = 3000/300 = "10.00 s" —
  // the `%durationInfo` ValueConv runs at OUTPUT against the FINAL global
  // TimeScale and an absent field in the later `mvhd` does NOT erase the
  // earlier count, R6/F1), `QuickTime_trunc_ftyp.mov` (a 12-byte file whose
  // first `ftyp` declares size 100; the format is gated on the 4-byte `$tag`
  // alone ⇒ accepted, FileType MP4 default + a `Truncated 'ftyp' data`
  // warning, R6/F2) and `QuickTime_overrun_mdat.mov` (a 12-byte file whose
  // first `mdat` declares size 100 ⇒ FileType MOV + MediaDataSize=92 +
  // MediaDataOffset=8 from the DECLARED size + a `Truncated 'mdat' data at
  // offset 0x0` warning, R6/F2).
  // 167 → 171 after PR #38 Codex R7 findings F1/F2: added four synthetic
  // adversarial QuickTime fixtures verified vs bundled —
  // `QuickTime_dupmdhd.mov` (a `moov/trak/mdia` with a FULL `mdhd`
  // TimeScale=600/Duration=1200 followed by a SHORT `mdhd` carrying only
  // TimeScale=300 ⇒ `Track1:MediaDuration = "2.00 s"` is NOT erased by the
  // later absent Duration while `MediaTimeScale = 300` is last-wins, R7/F1),
  // `QuickTime_nested_trunc_mvhd.mov` (a truncated `mvhd` inside `moov` ⇒
  // `ExifTool:Warning = "Truncated 'mvhd' data (missing 88 bytes)"` — a
  // contained `TruncatedAtom` now surfaces the warning instead of breaking
  // silently, R7/F2), `QuickTime_nested_trunc_tkhd.mov` (a truncated `tkhd`
  // inside `moov/trak` ⇒ `Track1:Warning`, the warning attaches to the
  // current family-1 group, R7/F2) and `QuickTime_nested_trunc_mdhd.mov` (a
  // truncated `mdhd` three levels deep in `moov/trak/mdia` ⇒ `Track1:Warning`,
  // R7/F2).
  // 171 → 175 after PR #38 Codex R8 findings F1/F2: added four synthetic
  // adversarial QuickTime fixtures verified vs bundled, pinning the
  // first-atom size/header malformation class-sweep —
  // `QuickTime_invalid_size.mov` (an 8-byte `00000004 ftyp`: a `size < 8`
  // first atom ⇒ FileType MOV + `ExifTool:Warning = "Invalid atom size"`,
  // R8/F1), `QuickTime_trunc_ext_hdr.mov` (a 12-byte `size==1 ftyp` whose
  // 8-byte extended-size header is truncated ⇒ FileType MOV + `Truncated atom
  // header`, R8/F1), `QuickTime_short_ftyp.mov` (an 8-byte `size==8 ftyp`
  // whose RAW 32-bit size is `< 12` ⇒ `else { SetFileType() }` ⇒ MOV, not the
  // MP4 default, R8/F1) and `QuickTime_ext_ftyp.mov` (an extended-size `ftyp`
  // with the `isom` brand: the `$size >= 12` gate sees the RAW 32-bit
  // `size == 1` so it FAILS ⇒ MOV, even though the brand alone would resolve
  // to MP4, R8/F1). R8/F2 — a lowercase `pict` first atom is now a recognized
  // MOV magic atom (`is_known_top_level` += `pict`, −`meta`) — is pinned by
  // the `lowercase_pict_first_atom_accepted_as_mov` /
  // `meta_first_atom_is_rejected` unit tests (a `pict` conformance fixture
  // would force the SP2-scope `Binary` `PreviewPICT` payload tag).
  // 175 → 178 after PR #38 Codex R9 findings F1/F2: added three synthetic
  // adversarial QuickTime fixtures verified vs bundled —
  // `QuickTime_ftyp_first_qt.mov` (a `ftyp` `isom` major + `qt  ` in the FIRST
  // compatible-brand slot ⇒ FileType MP4: the `^.{8}(.{4})+(qt  )` regex needs
  // a NON-first compatible-brand slot, so a first-slot `qt  ` does not
  // override the MP4 default, R9/F1), `QuickTime_nested_invalid_mvhd.mov` (a
  // `moov` containing an `mvhd` with declared `size == 4` ⇒ `ExifTool:Warning
  // = "Invalid atom size"`: a contained `Malformed` header now surfaces the
  // bundled `$warnStr` instead of `walk_atoms` breaking silently, R9/F2) and
  // `QuickTime_nested_invalid_tkhd.mov` (a `tkhd` with invalid `size == 4`
  // inside `moov/trak` ⇒ `Track1:Warning = "Invalid atom size"`, R9/F2).
  // 178 → 179 after PR #38 Codex R10 finding F1: added the synthetic
  // adversarial QuickTime fixture `QuickTime_m4a_isom_override.mov` (an `ftyp`
  // `isom` MAJOR brand + a lone `soun`-handler track and NO `vide` handler ⇒
  // bundled ExifTool's post-walk `OverrideFileType('M4A','audio/mp4')` flips
  // the MP4-resolved type to `File:FileType=M4A` / `File:FileTypeExtension=m4a`
  // / `File:MIMEType=audio/mp4` while `QuickTime:MajorBrand` keeps the `isom`
  // PrintConv — the audio-only `.m4a` real-world-file case,
  // QuickTime.pm:10619-10624, verified vs bundled 13.58, R10/F1). R10/F2 — the
  // mvhd/tkhd/mdhd Hooks widen on a TRUTHY version (not strictly `== 1`) — is
  // crafted-input-only (v2+ atoms are undefined by the MP4 spec), so it adds
  // NO fixture; the existing v0/v1 fixtures stay byte-exact green.
  // 179 → 180 after PR #38 Codex R11 finding F1: added the QuickTime fixture
  // `QuickTime_useext_glv.glv` — the BYTE-IDENTICAL twin of
  // `QuickTime_m4a_isom_override.mov` but named `.glv`. The `%useExt` rule
  // (QuickTime.pm:240 `( GLV => 'MP4' )`, applied at QuickTime.pm:10006-10007)
  // promotes the ftyp-derived MP4 to GLV BEFORE the post-walk MP4→M4A override
  // (gated on `FileType eq 'MP4'`), so the same audio-only bytes yield
  // `File:FileType=GLV` / `File:FileTypeExtension=glv` / `File:MIMEType=video/mp4`
  // as `.glv` vs `M4A` as `.mov` (verified vs bundled 13.58, R11/F1). The
  // `%useExt` table has exactly this one entry, so no other fixture is needed.
  // 180 → 182 after PR #38 Codex R12 finding F1 [REAL-INPUT]: added two
  // synthetic adversarial QuickTime fixtures verified vs bundled, pinning the
  // default `LargeFileSupport => 1` (ExifTool.pm:1167) 64-bit extended-size
  // handling — `QuickTime_mdat64_moov.mov` (`ftyp` + a `size == 1` 64-bit
  // `mdat` that FITS + a trailing `moov`; the walker skips the 64-bit `mdat`
  // by its declared size and REACHES the trailing `moov` ⇒ full
  // Duration/TimeScale/dates/MatrixStructure/NextTrackID — the real >2GB-video
  // shape, QuickTime.pm:10062-10074) and `QuickTime_mdat64_large.mov` (a
  // `size == 1` `mdat` declaring 0x80000010, i.e. `lo > 0x7fffffff` — PARSED,
  // not rejected: MediaDataSize=2147483648 from the DECLARED 64-bit size +
  // `Truncated 'mdat' data at offset 0x14`, NOT the dead `LargeFileSupport not
  // enabled` branch the port emitted before the fix, R12/F1).
  // — after FORMATS.md row 24 lib/mxf: added `MXF.mxf` (bundled
  // t/images fixture, 7510 bytes) exercising the KLV walker + BER length
  // decoder + Primer local-id→UL map + local-set walker + the MXF-specific
  // value decoders + `Track<N>` group attribution ported in
  // `src/formats/mxf.rs`.
  // after Codex R1/F1: added `MXF_MultiDescriptor.mxf` (synthetic,
  // 2426 bytes) — a multi-essence MXF whose audio descriptors are reachable
  // ONLY through the hidden `MultipleDescriptor.FileDescriptors` /
  // `SourcePackage.PackageTracks` StrongReference edges, exercising the
  // complete structural-edge subset of `TAG_TABLE`.
  // after Codex R2/F1: added `MXF_BomBE.mxf` + `MXF_BomLE.mxf`
  // (each MXF.mxf with its UTF-16 `ApplicationName`/`TrackName` values
  // rewritten to carry a `FE FF` / `FF FE` byte-order mark, byte-length
  // preserved) — pinning `Charset.pm:203-206` BOM handling in the UTF-16
  // decoder: a BE BOM is stripped (not preserved as U+FEFF) and a LE BOM is
  // stripped AND the remainder decoded little-endian (not garbled).
  // after Codex R3/F1: added `MXF_DupDurationFF.mxf` (synthetic, two
  // same-InstanceUID `TimecodeComponent` sets — earlier valid `Duration`,
  // later all-`0xff`) — pinning that MXF.pm:98's `%duration` RawConv-`undef`
  // drop is a NON-entry (ExifTool.pm:9493 + MXF.pm:2666 `next unless $key`),
  // so the dropped value never participates in the reverse-order duplicate
  // pass and the earlier valid `Duration` survives.
  // after Codex R4/F1: added `MXF_Utf16EmbeddedNul.mxf` (`MXF.mxf`
  // with the UTF-16 `ApplicationName` `ExifTool` rewritten to `E\0ifTool` —
  // an in-band NUL followed by non-zero stale text) — pinning that
  // `Charset.pm:326`'s `Recompose` runs `s/\0.*//s` and TRUNCATES the UTF-8
  // output at the first NUL, so the oracle emits `"E"` (not `"EifTool"`).
  // ----- PR #36 / FORMATS.md rows 13-14 (Exif+GPS) ----------------------
  // The chronology below is from the lib/exif-gps branch (forked before
  // Flash/MXF/QuickTime landed in main, so its `139 → 149` collapses Real's
  // multi-step chain into one recap). The post-recap `149 → ...` lines
  // document the Exif/JPEG fixture additions; the active-count assertion
  // below was recomputed post-rebase to the actual fixture-count total
  // (main's Flash/MXF/QuickTime fixtures PLUS the Exif/JPEG additions).
  // 149 → 151 after FORMATS.md rows 13-14 lib/exif-gps: added the two
  // synthetic standalone-TIFF fixtures `Exif.tif` (IFD0 + ExifIFD + IFD1
  // chain — the camera-tag IFD machinery) and `ExifGPS.tif` (IFD0 + GPS
  // sub-IFD — the GPS coordinate ValueConv). The MakerNote-bearing
  // `Exif_makernote.tif` is formally accept-deferred — see `NOT_ACTIVE`.
  // 151 → 155 after PR #36 Codex R1 (F1/F2/F3): four adversarial
  // standalone-TIFFs — `Exif_badoffset_low.tif` (out-of-line value
  // offset < 8 ⇒ `Suspicious … offset` warning + tag dropped),
  // `Exif_badoffset_eof.tif` (offset + size past EOF ⇒ `Error reading
  // value …` warning + tag dropped), `Exif_truncated_ifd.tif` (IFD0
  // declares more entries than the file holds ⇒ `Bad IFD0 directory`
  // and the whole directory aborts), `Exif_focallength35.tif`
  // (FocalLengthIn35mmFormat 0xa405 — the no-decimal `"$val mm"`
  // PrintConv, distinct from FocalLength 0x920a's `sprintf("%.1f mm")`).
  // 155 → 161 after PR #36 Codex R2 (F1/F2/F3): six adversarial
  // standalone-TIFFs — `Exif_badformat_entry0.tif` (entry-0 bad format
  // code ⇒ `Bad format (99) for IFD0 entry 0` + directory abort),
  // `Exif_illegal_ifd0_size.tif` / `Exif_illegal_subifd_size.tif`
  // (`$bytesFromEnd` ∈ {1,3} ⇒ `Illegal … directory size (n entries)`
  // + abort, at IFD0 and a GPS sub-IFD), `Exif_gps_baddir.tif` (GPS
  // pointer past EOF ⇒ `Bad GPS directory`), `Exif_gps_badoffset.tif` /
  // `Exif_gps_eofoverrun.tif` (GPS-IFD warning tag names resolved
  // against `%GPS::Main` — 0x0002 = GPSLatitude, not InteropVersion).
  // 161 → 163 after PR #36 Codex R3 (F1/F2): two adversarial standalone-
  // TIFFs — `Exif_badformat_ifd1.tif` (entry-0 bad format in IFD0 with a
  // valid IFD1 next-IFD pointer ⇒ the `return 0` abort suppresses IFD1
  // too — no `IFD1:*` tags), `Exif_gps_proctext.tif`
  // (GPSProcessingMethod/GPSAreaInformation with the `ASCII\0\0\0` charset
  // prefix ⇒ `ConvertExifText` strips the prefix and decodes the text).
  // 163 → 164 after PR #36 Codex R4 (F1): one adversarial standalone-TIFF —
  // `Exif_gps_unicode.tif` (big-endian TIFF carrying UTF-16LE `UNICODE\0`
  // GPSProcessingMethod with NO BOM + GPSAreaInformation with an LE BOM ⇒
  // `ConvertExifText`'s `Decode(...,'UTF16','Unknown')` seeds the order from
  // `GetByteOrder()` then flips on the Charset.pm distribution heuristic, so
  // both decode to ASCII text rather than mojibake).
  // 164 → 167 after PR #36 Codex R5 (F1): three adversarial standalone-TIFFs
  // exercising ExifIFD `UserComment` (0x9286), which is `Format => 'undef'` +
  // `RawConv => ConvertExifText` (Exif.pm:2497-2507) — the SAME RawConv the
  // GPS text tags use, but in the ExifIFD and WITHOUT the `gps` feature.
  // `Exif_usercomment_ascii.tif` (`ASCII\0\0\0` prefix ⇒ "Hello World", was
  // wrongly `Conv::None` ⇒ binary placeholder), `Exif_usercomment_unicode.tif`
  // (MM TIFF, `UNICODE\0` + UTF-16LE no-BOM ⇒ heuristic flip ⇒ "MANUAL"),
  // `Exif_usercomment_bom.tif` (MM TIFF, `UNICODE\0` + LE BOM ⇒ BOM pins LE
  // order ⇒ "Tokyo"). The `ConvertExifText` impl moved out of the gps-only
  // module into `exif::exiftext` (feature = "exif") so UserComment decodes
  // without `gps`.
  // 167 → 169 after PR #36 Codex R6 (F1): two adversarial standalone-TIFFs —
  // `Exif_usercomment_string.tif` / `Exif_usercomment_int8u.tif` — an ExifIFD
  // UserComment (0x9286) whose ON-DISK format code is `string` (2) / `int8u`
  // (1), the documented mis-writers (Exif.pm:2499). ExifTool's `Format =>
  // 'undef'` (Exif.pm:2500) is a READ-side override applied BEFORE `ReadValue`
  // (Exif.pm:6729-6744): it forces the value through `undef` so the on-disk
  // bytes are not NUL-trimmed, then `ConvertExifText` strips the 8-byte
  // `ASCII\0\0\0` prefix ⇒ "Hello World". Without it the `string` decode
  // truncates at the first NUL to "ASCII". The fix adds `tables::
  // format_override` (the `$$tagInfo{Format}` lookup) applied in the IFD
  // walker before `read_value`, keyed on `Format` (UserComment) not `Writable`
  // (GPS text tags carry only `Writable => 'undef'`, so a `string`-on-disk GPS
  // text tag IS NUL-trimmed by bundled — the contrast pins the scoping).
  // 169 → 170 after PR #36 Codex R7 (F1): one adversarial standalone-TIFF —
  // `Exif_gps_datestamp.tif` — a GPS sub-IFD GPSDateStamp (0x001d) whose
  // ON-DISK format is `string` (2) but whose bytes use `\0` separators
  // (`2024\0 05\0 22\0`, the Casio EX-H20G variant, GPS.pm:312). The GPS table
  // sets `Format => 'undef'` (GPS.pm:312), a READ-side override (Exif.pm:6729-
  // 6744) that forces the undef re-read so the interior NULs survive ⇒ the
  // RawConv strips only the trailing run and `ExifDate` re-separates to
  // "2024:05:22". The R6 fix gated the override off for ALL GPS entries; R7
  // resolves it per-table (`gps::format_override(0x001d)` → `Format::Undef`),
  // honoring 0x001d while keeping the GPS text tags 0x001b/0x001c (only
  // `Writable => 'undef'`, no `Format`) NUL-trimmed exactly as bundled does.
  // 170 → 171 after PR #36 Codex R8 (F1): one adversarial standalone-TIFF —
  // `Exif_gps_wrongfmt.tif` — an IFD0 GPSInfo pointer (0x8825) mis-encoded as
  // `string[4]` instead of an integer. GPSInfo carries `Flags => 'SubIFD'`
  // (Exif.pm:2134), so the offset-integrality check (Exif.pm:6747) warns
  // `Wrong format (string) for IFD0 0x8825 GPSInfo` and `next`-skips the entry
  // in default mode — the GPS sub-IFD is NOT walked. Pins the fix for a
  // silently-swallowed pointer (the would-be GPS IFD at the encoded offset is
  // never reached, so no GPS:* leaks); IFD0:Orientation still emits.
  // 171 → 172 after PR #36 Codex R9 (F1): one adversarial standalone-TIFF —
  // `Exif_gps_int32s.tif` — an IFD0 GPSInfo pointer (0x8825) encoded as
  // `int32s` (format 9, a SIGNED integer) with a POSITIVE offset. `%intFormat`
  // (Exif.pm:125-136) lists `int32s => 9`, so the signed format passes the
  // offset-integrality gate (Exif.pm:6747) WITHOUT a warning and the pointer
  // is used as `Start => '$val'` — the GPS sub-IFD IS walked. Pins the fix for
  // the SubIFD-pointer extraction accepting `RawValue::I64` (not only `U64`);
  // bundled emits `GPS:GPSVersionID` = "2.3.0.0".
  // 172 → 173 after PR #36 Codex R10 (F1): one synthetic standalone-TIFF —
  // `Exif_multipage.tif` — a three-deep next-IFD chain IFD0 -> IFD1 -> IFD2.
  // ExifTool's `Multi` trailing-directory scan (Exif.pm:7202-7232) is a
  // `for (;;)` loop that re-reads `Get32u($dataPt, $dirEnd)` and increments
  // the directory number after each trailing IFD (`DirName .= $ifdNum + 1`,
  // Exif.pm:7215-7216). The R10 bug stopped the walker after IFD1 because
  // `walk_one_ifd` returned the next pointer only for `IfdKind::Ifd0`; the
  // fix follows the chain for `IfdKind::Ifd0 | IfdKind::Trailing(_)` and
  // numbers each trailing IFD (`Trailing(n)` → family-1 group `IFDn`), so
  // bundled's `IFD2:Compression` / `IFD2:Software` / `IFD2:Orientation` are
  // emitted.
  // 173 → 174 after PR #36 Codex R11 (F1): one synthetic standalone-TIFF —
  // `Exif_manyifd.tif` — a 66-deep next-IFD chain IFD0 -> ... -> IFD65.
  // ExifTool's `Multi` trailing-directory scan is an UNCAPPED `for (;;)`
  // loop (Exif.pm:7211). The R11 bug capped `walk_ifd_chain` at `0..MAX_IFDS`
  // (64) — counting IFD0, so IFD64/IFD65 were silently dropped from a valid
  // multipage TIFF. The fix removes the fixed cap (the seen-offset reprocess
  // guard keeps the `loop {}` finite) and widens `IfdKind::Trailing` to `u16`
  // so `IFDn` numbers past 64; bundled's `IFD64:Software` / `IFD65:Software`
  // are emitted.
  // 174 → 175 after PR #36 Codex R12 (F1): one synthetic standalone-TIFF —
  // `Exif_ifd65536.tif` — a 65537-deep next-IFD chain IFD0 -> ... -> IFD65536.
  // ExifTool numbers each trailing IFD with plain Perl arithmetic
  // `DirName .= $ifdNum + 1` (Exif.pm:7215-7216) — uncapped. The R12/F1 bug
  // stored the trailing-IFD number in a `u16` advanced with `saturating_add`,
  // so past IFD65535 it pinned at 65535 and mislabeled IFD65536 as IFD65535
  // (overwriting the real IFD65535 tags). The fix widens `IfdKind::Trailing`
  // to `u32` with an unsaturating `+ 1` and a 13-byte `IfdName` buffer, so
  // bundled's distinct `IFD65535:Software` / `IFD65536:Software` are emitted.
  // 175 → 176 after PR #36 Codex R12 (F2): one synthetic standalone-TIFF —
  // `Exif_gps_after_interop.tif` — IFD0's GPSInfo (0x8825) and ExifIFD's
  // InteropOffset (0xa005) BOTH point at one shared sub-IFD. ExifTool's
  // `%PROCESSED` reprocess guard (ExifTool.pm:9050-9061) is gated on
  // `$$dirInfo{DirLen}` being non-zero; IFD-pointer SubDirectories carry
  // `DirLen => 0`, so the guard never fires and ExifTool reprocesses the
  // shared offset as GPS (the Windows Phone 7.5 O/S bug, ExifTool.pm:9059).
  // The R12/F2 bug rejected any previously seen IFD offset, dropping all
  // GPS tags. The fix tracks each seen offset WITH its owning `IfdKind` and
  // allows the GPS-after-InteropIFD reprocess; the shared dir carries only
  // GPS IDs absent from `%InteropIFD` (GPSVersionID/GPSSatellites/
  // GPSMapDatum) so bundled's `GPS:*` tags emit with no Interop/Composite
  // golden noise.
  // 176 → 177 after PR #36 Codex R13 (F1): one synthetic standalone-TIFF —
  // `Exif_gps_shared_pointer.tif` — IFD0's ExifOffset (0x8769) AND GPSInfo
  // (0x8825) BOTH point at one shared sub-IFD. This is the GENERAL form of
  // the R12/F2 pointer-collision: ExifTool's `%PROCESSED` guard is gated on
  // a non-zero `DirLen` (ExifTool.pm:9052) and a standalone TIFF's
  // IFD-pointer SubDirectories carry `DirLen 0` (Exif.pm:7020-7026 resets
  // `$size` for an out-of-buffer subdirectory start), so the guard is
  // SKIPPED for EVERY IFD-pointer subdirectory — ExifTool reprocesses any
  // shared offset, not just GPS-after-InteropIFD. The R12/F2 carve-out
  // admitted only GPS-after-InteropIFD, so the GPS pass over an
  // ExifIFD-owned offset returned `None` and every GPS tag was dropped. The
  // re-modelled guard records only chain IFDs (IFD0/Trailing) in the
  // seen-offset loop breaker and reprocesses IFD-pointer subdirectory
  // revisits, rejecting only a true ancestor cycle (active recursion path).
  // Bundled emits `ExifIFD:Orientation` AND `GPS:GPSVersionID`, no warning.
  // 177 → 178 after PR #36 Codex R14 (F1): one adversarial standalone-TIFF —
  // `Exif_eofoverrun_chain.tif` — IFD0 entry 1 is an out-of-line value
  // (Software) whose `offset + size` runs past EOF, with a VALID entry 2
  // (Orientation) AFTER it AND a non-zero next-IFD pointer to a structurally
  // valid IFD1. A standalone TIFF carries a RAF (`DoProcessTIFF` sets
  // `RAF => $raf`, ExifTool.pm:8717; `ProcessExif` reads it, Exif.pm:6289),
  // so the out-of-line read takes the `if ($raf)` path (Exif.pm:6552); the
  // past-EOF `$raf->Read` fails (Exif.pm:6593) ⇒ `Error reading value for
  // IFD0 entry 1, ID 0x0131 Software` (Exif.pm:6594) ⇒ `return 0 unless
  // $inMakerNotes or $htmlDump or $truncOK` (Exif.pm:6602) — the WHOLE
  // directory aborts BEFORE the line-7202 trailing-IFD scan. The R14/F1 bug
  // recorded the warning but returned `true` (continue), so `IFD0:Orientation`
  // and the IFD1:* tags leaked. The fix returns `false` (abort) from
  // `walk_entry` on the EOF read-failure branch; the MakerNotes/truncOK
  // exemption never applies (this walker defers MakerNote parsing and emits
  // no TruncateOK tag). Bundled emits ONLY `IFD0:Make` + the warning.
  // 178 → 179 after PR #36 Codex R15 (F1): one standalone-TIFF —
  // `Exif_trailing_space.tif` — whose IFD0 Make/Model/Software/Artist and
  // ExifIFD SubSecTime* fields are space-padded; bundled trims the trailing
  // whitespace (`RawConv s/\s+$//`) / trailing spaces (`ValueConv s/ +$//`) in
  // both -j and -n, so the port must too (else duplicate camera/software
  // facets). Exif.pm:585/599/906/925 + 2543/2552/2560.
  // 179 → 180 after PR #36 Codex R16 (F1): the REAL camera-JPEG fixture
  // `ExifGPS.jpg` (bundled `t/images/GPS.jpg`) — the JPEG container front-end
  // (`src/exif/jpeg.rs`) walks the markers, dispatches the `APP1` `Exif\0\0`
  // segment to ProcessTIFF → ProcessExif (ExifTool.pm:7736-7783), and the
  // typed `ExifMeta` carries the full IFD0/ExifIFD/GPS/IFD1 set. This is the
  // first real-input (non-synthetic) Exif fixture and the core product
  // capability (camera photos read their Make/Model/DateTime/GPS).
  // 180 → 182 after PR #36 Codex R17: two JPEG-container fixtures.
  //  - `JPEG_malformed_app1_exif.jpg` (R17/F1) — a valid JPEG whose `APP1`
  //    `Exif\0\0` block is NOT a valid TIFF; bundled `ProcessJPEG`
  //    `SetFileType`s it `JPEG` (ExifTool.pm:7304) regardless of the Exif arm
  //    and `Warn`s `Malformed APP1 EXIF segment` (ExifTool.pm:7783). The JPEG
  //    container is ACCEPTED — never mis-rejected into a finalization error.
  //  - `JPEG_two_app1_exif.jpg` (R17/F2) — a JPEG with two INDEPENDENT `APP1`
  //    Exif blocks (each a self-contained `Exif\0\0II\x2a\0` TIFF); the marker
  //    walk continues after the first (ExifTool.pm:7821 `next`) so both
  //    contribute tags (`IFD0:Make` from block 1, `IFD0:Model` from block 2).
  // 182 → 183 after PR #36 Codex R18 (F2): `JPEG_unknown_header.jpg` — a
  // valid JPEG behind a 4-byte unknown leading header. The file-type
  // detector's terminal JPEG candidate carries a non-zero `header_skip`
  // (`ExifTool.pm:3026-3034`); the Exif dispatch slices `bytes` at that offset
  // and rebases the embedded Exif `Base` by it. Pre-fix the candidate was
  // detected then mis-rejected into a finalization error.
  // 265 → 266 after PR #68 (TIFF standalone container): `Exif_pagecount.tif`
  // — a two-page TIFF whose IFDs carry `SubfileType` (0x00fe) values (IFD0=0
  // full-resolution, IFD1=2 single page of multi-page) that trip the bundled
  // `MultiPage` flag and the synthesized `File:PageCount` (ExifTool.pm:
  // 8756-8757). Pins the PageCount `RawConv` tracker + the standalone-TIFF
  // emit gate; embedded TIFF blocks (PNG `eXIf`, JPEG `APP1`) suppress the
  // emit (`TIFF_TYPE == 'TIFF'`).
  // 266 → 267 after #162 Codex R1 (TIFF subtype PageCount gate):
  // `Exif_pagecount.dng` — the SAME multi-page bytes under a TIFF-rooted SUBTYPE
  // extension. Bundled detects `FileType = DNG`, `TIFF_TYPE = DNG`, so it emits
  // NO `File:PageCount` (ExifTool.pm:8767) while still extracting every IFD tag.
  // Pins the standalone-TIFF arm gating PageCount on the candidate `Parent`
  // (not a hard-coded `true`).
  let root = env!("CARGO_MANIFEST_DIR");
  let fixtures = active_fixtures();
  assert_eq!(
    fixtures.len(),
    267,
    "expected exactly the 267 active conformance fixtures, found {}: {:?}",
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
