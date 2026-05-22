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
fn typed_serde_path_equals_writer_path_and_golden_all_180() {
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
  // 149 → 154 after the XMP infra port: added XMP / XMP4 / XMP6 / XMP7 /
  // XMP8 standalone-`.xmp` sidecar fixtures (RDF/XML walker, `%nsURI`
  // namespace taming, camera-critical exif/tiff/photoshop/aux tag tables,
  // struct rebuild, lang-alt). Five further XMP fixtures (PLUS, XMP2,
  // XMP3, XMP5, XMP9) exercising the `plus`/`mwg-*` namespace tables, full
  // `rdf:nodeID` blank-node resolution, and list-of-lang-alt rebuild are
  // deferred — see `docs/tracking.md` and the `#[ignore]`'d
  // `xmp_unported_namespace_printconv_deferred` accept-defer test.
  // 154 → 159 after Codex R1 (PR #37): added 5 adversarial XMP fixtures
  // pinning the four fixes — `XMP_bom_utf8.xmp` + `XMP_bom_utf16le.xmp`
  // (F1: BOM-prefixed recognition reaches the decoder), `XMP_gps.xmp`
  // (F2: `%latConv`/`%longConv` ToDegrees ValueConv + ToDMS PrintConv for
  // GPSLatitude/Longitude + Dest variants — `-j` DMS, `-n` decimal degrees),
  // `XMP_hashmiss.xmp` (F3: string-keyed PrintConv hash, `"05"`/`"99"`/`"Z"`
  // misses ⇒ `Unknown ($val)`, no integer coercion), and `XMP_langalt.xmp`
  // (F4: `StandardLangCase` + `GetLangInfo` underscore handling —
  // `en-us-x-private`→`-en-US-x-private`, `zh-Hant-CN`→`-zh-hant-cn`,
  // `de_DE`→`-de-de`, `es-419`→`-es-419`).
  // 159 → 160 after Codex R2 F1 (PR #37): added `XMP_gps_carry.xmp` pinning the
  // GPS ToDMS seconds round-off carry (GPS.pm:559-561) — the carry subtracts
  // 60 from the ROUNDED `sprintf('%.2f', $c[-1])` value, not the original
  // unrounded seconds, so `12.9999999999N` → `13 deg 0' 0.00" N` (not the
  // negative-zero `-0.00"`). Four boundary cardinals: N/W degree-carry, a
  // signed-decimal Dest S sign-flip carry, and a minute-only E carry
  // (`0.0166666666` → `0 deg 1' 0.00" E`, no degree increment).
  // 160 → 162 after Codex R3 F1 (PR #37): added 2 adversarial XMP fixtures
  // pinning the `rdf:datatype="base64"` decoded-payload binary/text SPLIT
  // (XMP.pm:3646-3647: `$val = $$val unless length $$val > 100 or
  // $$val =~ /[\0-\x08\x0b\x0e-\x1f]/`). `XMP_base64_ctrl.xmp` — single
  // control bytes: NUL/vtab/0x0e ⇒ `(Binary data 1 bytes, …)`, while FF
  // (0x0c) / tab+LF+CR / "hello" ⇒ TEXT (the `\0x0c` Perl token is `\0` +
  // literal `x0c`, NOT `\x0c`, so 0x0c stays text — verified vs bundled
  // 13.58). `XMP_base64_binary.xmp` — a `<=100`-byte non-UTF-8 JPEG header
  // (`FF D8 FF E0`) ⇒ lossy text `"????"` (FixUTF8 at JSON time), a
  // `>100`-byte printable payload ⇒ binary by length, and a `>100`-byte
  // non-UTF-8 PNG-like blob ⇒ binary. Before the fix `decode_base64_text`
  // coerced every payload through `String::from_utf8`, so the NUL became a
  // text string and the non-UTF-8 image bytes failed and stayed base64.
  // 162 → 163 after Codex R4 F1 (PR #37): added 1 adversarial XMP fixture
  // pinning `DecodeBase64`'s truncate-and-decode semantics (XMP.pm:2981) —
  // `XMP_base64_malformed.xmp`: trailing junk `aGVsbG8=#junk` → "hello",
  // VT-truncate `aGVs<VT>bG8=` → "hel", unpadded `aGVsbG8` → "hello". Before
  // the fix the decoder returned `None` on the first invalid byte and the
  // caller fell back to the literal undecoded base64 text.
  // 163 → 164 after Codex R5 F1 (PR #37): added 1 adversarial XMP fixture
  // pinning the base64 decode-BEFORE-unescape order. Perl runs
  // `DecodeBase64($val)` on the still-escaped value (XMP.pm:3645) and only
  // THEN un-escapes (XMP.pm:3655-3669). `XMP_base64_escaped.xmp`:
  // `aGVs&#x62;G8=` → "hel" (the `&` truncates DecodeBase64; un-escaping
  // `&#x62;`→`b` first would wrongly yield "hello"), and `YSZhbXA7Yg==` →
  // "a&b" (decodes to `a&amp;b`, un-escaped post-decode). Before the fix the
  // value was un-escaped BEFORE the base64 decode.
  // 164 → 165 after Codex R6 F1 (PR #37): added 1 adversarial XMP fixture
  // pinning namespace-NORMALIZED structural-attribute lookup. `FoundXMP`
  // reads `rdf:datatype`/`et:encoding` (XMP.pm:3644) and `xml:lang`
  // (XMP.pm:3497) from the `%attrs` HASH, whose keys are prefix-translated
  // by the attribute loop (XMP.pm:3976). `XMP_ncprefix.xmp` declares the
  // RDF namespace under a noncanonical `r:` prefix: `r:datatype="base64"`
  // ⇒ `aGVsbG8=` decodes to "hello" and `/9j/4A==` to a binary JPEG header
  // ("????"), exactly as a canonical `rdf:datatype` does (Canonical=world).
  // Before the fix the lookup scanned the RAW attribute text for a literal
  // `rdf:datatype`, missed it, and emitted the undecoded base64. The
  // `rdf:resource` fallback (XMP.pm:4186) is the OPPOSITE — ExifTool matches
  // the RAW `$attrs` string with a literal `\brdf:`, so a noncanonical
  // `r:resource` does NOT trigger it: Link stays "" (verified vs bundled).
  // 165 → 167 after Codex R7 (PR #37): added 2 adversarial XMP fixtures.
  // `XMP_rdf_resource_spaced.xmp` (F1) pins the empty-value fallback's
  // LITERAL raw-regex match (XMP.pm:4185-4186 `\brdf:(?:value|resource)=`
  // / `\brdf:about=` — NO `\s*` around `=`): `rdf:resource = "…"` written
  // with spaces does NOT match, so `Link`/`ValSpaced` stay "" while the
  // tight `LinkTight`/`ValTight` keep their values. `XMP_et_encoding.xmp`
  // (F2) pins shorthand-attr DELETE semantics (XMP.pm:4133): `et:encoding`
  // is a non-ignored shorthand attr — extracted as its own tag
  // (`PayloadEncoding`) AND deleted from `%attrs`, so it does NOT drive the
  // parent decode (`Payload` stays raw `aGVsbG8=`); the un-deleted
  // `rdf:datatype` still decodes its parent (`d29ybGQ=` → "world").
  // 167 → 168 after Codex R8 F1 (PR #37): added `XMP_li_cap.xmp` pinning
  // the `rdf:li` 1000-item cap (XMP.pm:3991-3999). The fixture has 1001
  // `<rdf:li>` keywords; ExifTool's default read path (no
  // `IgnoreMinorErrors` — `exifast` has no such option) extracts exactly
  // the first 1000 (`Subject` = [kw1..kw1000]) and raises the minor
  // warning `[Minor] Extracted only 1000 dc:subject items. Ignore minor
  // errors to extract all` (`Warn(..., 2)` ⇒ literal `[Minor] ` prefix,
  // ExifTool.pm:5619), then `last`s out of the element loop. Before the
  // fix the Rust `rdf:li` branch extracted every item with no cap and no
  // warning. (R8/F2 — SVG/XML/PLIST inputs now rejected by the XMP parser
  // — adds no fixture: it is covered by the `xmp_svg_*` conformance test
  // and the `parse_inner_accepts_only_*` unit test, and a rejected input
  // produces no golden.)
  // 168 → 169 after Codex R9 F2 (PR #37): added `XMP_numentity.xmp` pinning
  // `UnescapeChar`'s `pack('C0U')` numeric-entity semantics (XMP.pm:2919-2936
  // + the downstream `FixUTF8`, XMP.pm:2943-2972). Out-of-range / surrogate
  // numeric refs are encoded as malformed loose-UTF-8 and then mapped to ONE
  // `?` per bad byte (`A&#x100000000;B` → "A???????B", `S&#xD800;E` → "S???E",
  // `over&#x110000;flow` → "over????flow"), while `&#x100;` → `Ā` and the
  // class-sweep literals `&#X41;` (uppercase X) / `&#x+41;` (sign breaks
  // `\w+`) stay verbatim. Before the fix the overflow/surrogate path bailed to
  // `None` and left the literal entity text. (R9/F1 — leading-whitespace
  // recognition anchoring — adds no fixture: a leading-whitespace `<rdf:RDF`/
  // `<?xml` finalizes to TXT in ExifTool, a deferred FileType with no golden;
  // it is covered by the `xmp_leading_whitespace_recognition_anchoring`
  // conformance test and the `parse_inner_*` unit tests.)
  // 169 → 171 after Codex R10 (PR #37): added 2 adversarial XMP fixtures
  // pinning the UTF text-encoding decode paths (the class sweep). ExifTool
  // transcodes via `unpack` + `pack('C0U*')` (each 16/32-bit unit decoded
  // INDEPENDENTLY) then `FixUTF8` (XMP.pm:2943-2972 / 4467-4498 / 4571-4587),
  // mangling non-ASCII the port previously kept verbatim. `XMP_double_utf8.xmp`
  // (F1) — a UTF-8-BOM + `<?xpacket begin=` sidecar (the `$double` capture,
  // XMP.pm:4351): the body `é` (U+00E9) is decode-UTF8'd then byte-truncated
  // (`pack('C*', unpack('C0U*'))`, XMP.pm:4476-4480) to `0xE9` → `?`, with the
  // `XMP is double UTF-encoded` warning (XMP.pm:4494). `XMP_utf16le_nonbmp.xmp`
  // (F2) — a UTF-16LE sidecar whose `dc:title = A😀B`: the surrogate PAIR is
  // two `unpack('v*')` units → `pack('C0U*')` 6 loose-UTF-8 bytes
  // (`ed a0 bd ed b8 80`) → `FixUTF8` → `A??????B` (no warning — the BOM marker
  // validates, XMP.pm:4567). Before the fix the port `String::from_utf16_lossy`
  // combined the pair into the real scalar (`A😀B`) and skipped the `$double`
  // branch entirely. The class sweep also fixed the plain-UTF-8 path (a
  // malformed byte now → `?`, not `from_utf8_lossy`'s U+FFFD) — covered by the
  // `parse_inner_encoding_paths_end_to_end` / `decode_paths_*` unit tests.
  // 171 -> 174 after Codex R11 (PR #37): added 3 adversarial XMP fixtures.
  // `XMP_nikon_nxd.xmp` (F1) pins the namespace-driven `OverrideFileType`
  // (XMP.pm:3915-3916): an `xmlns` URI beginning `http://ns.nikon.com/
  // BASIC_PARAM` is a Nikon NX-D settings sidecar, so ExifTool calls
  // `OverrideFileType('NXD','application/x-nikon-nxd')` and finalizes
  // `File:FileType=NXD` / `File:FileTypeExtension=nxd` (the `-n` form keeps
  // the uppercase `NXD`) / `File:MIMEType=application/x-nikon-nxd` (the
  // EXPLICIT MIME, since `NXD` has no `%mimeType` entry) instead of generic
  // XMP. Before the fix the port indexed it as `XMP` + `application/rdf+xml`.
  // `XMP_nikon_nxd_ext.nxd` (F1 class-sweep) pins the `OverrideFileType`
  // GUARD `$fileType ne $$self{VALUE}{FileType}` (ExifTool.pm:9715): the SAME
  // content under a `.nxd` extension already has `SetFileType` resolve `NXD`
  // (the `NXD => XMP` sub-type-by-ext promotion, ExifTool.pm:9686-9690), so
  // `NXD ne NXD` is FALSE ⇒ the override is a NO-OP and the base MIME
  // `application/rdf+xml` stands (NOT the explicit `application/x-nikon-nxd`).
  // `XMP_base64_x0c.xmp` (F2) pins the base64 binary-guard TYPO (XMP.pm:3647
  // `... or $$val =~ /[\0-\x08\x0b\0x0c\x0e-\x1f]/`): `\0x0c` parses as
  // `\0` + the LITERAL bytes `x`/`0`/`c`, so a short base64 payload decoding
  // to `cat`/`x`/`0`/`c` is a binary placeholder, while a payload without
  // control/`x`/`0`/`c` bytes stays text (`dog` decodes to "dog", `9` to 9 --
  // only the digit `0` is special, not all digits). Before the fix the port
  // omitted the literal `x`/`0`/`c` bytes and emitted `cat`/`x`/`0`/`c` as
  // text. (The all-control-range coverage stays in `XMP_base64_ctrl.xmp`.)
  // 174 -> 175 after Codex R12 (PR #37): added `XMP_rational_plus.xmp`
  // pinning the numeric-parsing leniency class. `ConvertRational`
  // (XMP.pm:3402) gates the value with `^(-?\d+)/(-?\d+)$` — an OPTIONAL
  // `-` (never `+`) per side — so a `+N/D` rational is NOT converted; the
  // looser Rust `i64::parse` accepted the `+`. The fixture's
  // `exif:ExposureBiasValue=+1/3` therefore stays `+1/3` in `-n`, and the
  // un-gated `PrintFraction` (Exif.pm:5520, no `IsFloat`) coerces it the
  // Perl way (`"+1/3" + 0 == 1`) to `+1` in `-j` (verified vs bundled
  // 13.58). The class-sweep companions: `exif:FocalLength=+50/1` exercises
  // the raw-`sprintf("%.1f mm",$val)` `FocalMm` PrintConv (`-n` `+50/1`,
  // `-j` `50.0 mm`); `exif:ApertureValue=+2/1` the un-gated
  // `sqrt(2)**$val` APEX `ValueConv` coercing `+2/1`->`2` (`-n` `2`,
  // `-j` `2.0` via `sprintf("%.1f",$val)`); and `exif:BrightnessValue=-1/3`
  // is the control — a valid `-`-signed rational still converts to
  // `-0.333333333333333` in both modes. Before the fix the port converted
  // `+1/3` to a `0.333...` quotient and the `f64::parse`-based converters
  // (stricter than Perl coercion — they reject `+1/3`/`+50/1`) left the
  // un-converted `+`-rationals verbatim in `-j`.
  // 175 -> 180 after Codex R14 F1 (PR #37): added 5 real-input value-parity
  // XMP fixtures pinning the `exif:ColorSpace` / `aux:LensInfo` /
  // `aux:ApproximateFocusDistance` conversions that the table previously
  // declared raw/identity. `XMP_colorspace.xmp` (`exif:ColorSpace`) pins the
  // `'$val == 0xffffffff ? 0xffff : $val'` ValueConv (XMP.pm:2003) — a
  // written `4294967295` collapses to `65535` (`-n`) and PrintConv-maps to
  // `Uncalibrated` (`-j`); before the fix the missing ValueConv left
  // `4294967295` raw, a PrintConv hash miss => `Unknown (4294967295)`.
  // `XMP_lensinfo.xmp` + `XMP_lensinfo_prime.xmp` (`aux:LensInfo`) pin
  // `\&ConvertRationalList` (XMP.pm:2600 / 3418) + `\&Exif::PrintLensInfo`
  // (XMP.pm:2615 / Exif.pm:5800): `24/1 70/1 28/10 40/10` -> `24 70 2.8 4`
  // (`-n`) -> `24-70mm f/2.8-4` (`-j`); the prime `50/1 0/1 14/10 14/10` ->
  // `50 0 1.4 1.4` -> `50mm f/1.4` exercises `PrintLensInfo`'s Perl-truthy
  // `if $vals[1]` guard dropping the `"0"` upper focal (Exif.pm:5814).
  // `XMP_aux_focusdist.xmp` + `XMP_aux_focusdist_inf.xmp`
  // (`aux:ApproximateFocusDistance`) pin the `4294967295 => 'infinity'`
  // PrintConv hash whose `OTHER => sub` (XMP.pm:2634-2638) returns the value
  // UNCHANGED on a read-direction miss: a `rational` Writable so
  // `ConvertRational` runs first — `53/10` -> `5.3` (a hash miss, OTHER
  // passes it through) and `4294967295/1` -> `4294967295` keys the
  // `infinity` row.
  let root = env!("CARGO_MANIFEST_DIR");
  let fixtures = active_fixtures();
  assert_eq!(
    fixtures.len(),
    180,
    "expected exactly the 180 active conformance fixtures, found {}: {:?}",
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
