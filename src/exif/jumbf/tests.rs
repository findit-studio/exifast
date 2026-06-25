// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Unit tests for the JUMBF / C2PA box-structure reader ([`super`]).

use super::*;
use crate::emit::{ConvMode, EmitOptions, Taggable};
use crate::value::TagValue;

// ── box-stream builders (mirror tools/gen_jumbf_fixtures.py) ─────────────────

/// A JUMBF box: 4-byte BE length (INCLUDING the 8-byte header) + 4-byte type +
/// payload.
fn box_bytes(typ: &[u8; 4], payload: &[u8]) -> Vec<u8> {
  let mut v = Vec::with_capacity(8 + payload.len());
  v.extend_from_slice(&((8 + payload.len()) as u32).to_be_bytes());
  v.extend_from_slice(typ);
  v.extend_from_slice(payload);
  v
}

/// The JSON content type-UUID: ASCII `json` then `00110010800000aa00389b71`.
fn json_uuid() -> Vec<u8> {
  let mut v = b"json".to_vec();
  v.extend_from_slice(&[
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71,
  ]);
  v
}

/// The raw JPEG-image type-UUID `6579d6fbdba2446bb2ac1b82feeb89d1`
/// (`Jpeg2000.pm:756`, a NON-ASCII first group).
fn jpeg_uuid() -> [u8; 16] {
  [
    0x65, 0x79, 0xd6, 0xfb, 0xdb, 0xa2, 0x44, 0x6b, 0xb2, 0xac, 0x1b, 0x82, 0xfe, 0xeb, 0x89, 0xd1,
  ]
}

/// A `jumd` description-box CONTENT (the payload after the box header): 16-byte
/// type-UUID + 1-byte toggles + optional NUL-terminated label + optional 4-byte
/// id + optional 32-byte signature.
fn jumd_content(uuid: &[u8], toggles: u8, label: Option<&str>, id: Option<u32>) -> Vec<u8> {
  let mut v = Vec::new();
  v.extend_from_slice(uuid);
  v.push(toggles);
  if toggles & 0x02 != 0 {
    v.extend_from_slice(label.unwrap().as_bytes());
    v.push(0);
  }
  if toggles & 0x04 != 0 {
    v.extend_from_slice(&id.unwrap().to_be_bytes());
  }
  if toggles & 0x08 != 0 {
    v.extend_from_slice(&[0u8; 32]);
  }
  v
}

/// Render a `JumbfMeta` to a `(family1, name, value)` list for the conv mode.
fn render(meta: &JumbfMeta, print_conv: bool) -> Vec<(String, String, TagValue)> {
  let mode = ConvMode::from_print_conv(print_conv);
  meta
    .tags(EmitOptions::g1(mode, false))
    .map(|t| {
      (
        t.tag().group_ref().family1().to_string(),
        t.tag().name().to_string(),
        t.tag().value_ref().clone(),
      )
    })
    .collect()
}

/// Render to `(family1, name, value, doc, doc_subpath)` — the Doc<N>-axis tests
/// need the sub-document path the `(family1,name,value)` view drops. The
/// `doc_subpath` is the pre-rendered dash-joined tail (`""`, `"-1"`, `"-1-1"`).
fn render_doc(meta: &JumbfMeta, print_conv: bool) -> Vec<(String, String, TagValue, u32, String)> {
  let mode = ConvMode::from_print_conv(print_conv);
  meta
    .tags(EmitOptions::g1(mode, false))
    .map(|t| {
      let g = t.tag().group_ref();
      (
        g.family1().to_string(),
        t.tag().name().to_string(),
        t.tag().value_ref().clone(),
        g.doc(),
        g.doc_subpath().to_string(),
      )
    })
    .collect()
}

/// The `(family1, name, value)` of a named tag, or panic.
fn find<'a>(list: &'a [(String, String, TagValue)], name: &str) -> &'a (String, String, TagValue) {
  list
    .iter()
    .find(|(_, n, _)| n == name)
    .unwrap_or_else(|| panic!("missing tag {name}: {list:?}"))
}

fn has(list: &[(String, String, TagValue)], name: &str) -> bool {
  list.iter().any(|(_, n, _)| n == name)
}

// ── Part A/C: the structure-only jumb -> jumd(label) case ────────────────────

#[test]
fn jumb_jumd_label_json_uuid() {
  // jumb -> jumd(JSON uuid, toggles 0x03 = Requestable+Label, label "c2pa.test").
  let jumd = jumd_content(&json_uuid(), 0x03, Some("c2pa.test"), None);
  let jumb = box_bytes(b"jumb", &box_bytes(b"jumd", &jumd));
  let meta = process(&jumb);

  // -j (PrintConv): JUMDType splits + ASCII-detects the (json) prefix.
  let pj = render(&meta, true);
  let (g, _, v) = find(&pj, "JUMDType");
  assert_eq!(g, GROUP_JUMBF);
  assert_eq!(
    v,
    &TagValue::Str("(json)-0011-0010-800000aa00389b71".into())
  );
  let (_, _, lv) = find(&pj, "JUMDLabel");
  assert_eq!(lv, &TagValue::Str("c2pa.test".into()));
  // JUMDToggles is Unknown=>1 ⇒ suppressed from the default tag stream's value
  // (it is still YIELDED with the unknown flag; run_emission drops it). The
  // `tags()` stream itself carries it, so assert its unknown flag is set.
  let mode = ConvMode::from_print_conv(true);
  let toggles = meta
    .tags(EmitOptions::g1(mode, false))
    .find(|t| t.tag().name() == "JUMDToggles")
    .expect("JUMDToggles present in the stream");
  assert!(toggles.unknown(), "JUMDToggles must carry Unknown=>1");

  // -n (ValueConv): JUMDType is the raw lowercase hex (no PrintConv split).
  let nj = render(&meta, false);
  let (_, _, nv) = find(&nj, "JUMDType");
  assert_eq!(
    nv,
    &TagValue::Str("6a736f6e00110010800000aa00389b71".into())
  );
}

// ── Part D: the raw-uuid jumd + bfdb + bidb case ─────────────────────────────

#[test]
fn jumd_raw_uuid_bfdb_bidb() {
  // jumb -> jumd(raw JPEG uuid, no label) + bfdb("image/jpeg") + bidb(16 bytes).
  let jumd = jumd_content(&jpeg_uuid(), 0x00, None, None);
  let mut bfdb = vec![0u8]; // toggle byte (dropped by the ValueConv)
  bfdb.extend_from_slice(b"image/jpeg\0");
  let bidb = b"\xff\xd8\xff\xe0FAKEJPEGDATA".to_vec(); // 16 bytes
  assert_eq!(bidb.len(), 16);
  let mut inner = box_bytes(b"jumd", &jumd);
  inner.extend_from_slice(&box_bytes(b"bfdb", &bfdb));
  inner.extend_from_slice(&box_bytes(b"bidb", &bidb));
  let jumb = box_bytes(b"jumb", &inner);
  let meta = process(&jumb);

  let pj = render(&meta, true);
  // The raw UUID's first group is non-ASCII ⇒ NO parens, raw hex 8-4-4-16.
  let (tg, _, tv) = find(&pj, "JUMDType");
  assert_eq!(tg, GROUP_JUMBF);
  assert_eq!(
    tv,
    &TagValue::Str("6579d6fb-dba2-446b-b2ac1b82feeb89d1".into())
  );
  // bfdb/bidb emit under the Jpeg2000 group, NOT JUMBF.
  let (bg, _, bv) = find(&pj, "BinaryDataType");
  assert_eq!(bg, GROUP_JPEG2000);
  assert_eq!(bv, &TagValue::Str("image/jpeg".into()));
  let (dg, _, dv) = find(&pj, "BinaryData");
  assert_eq!(dg, GROUP_JPEG2000);
  assert_eq!(
    dv,
    &TagValue::Str("(Binary data 16 bytes, use -b option to extract)".into())
  );
}

// ── Part C: the JUMBFLabel rename of bfdb/c2sh ───────────────────────────────

#[test]
fn jumbf_label_renames_content_tags() {
  // jumb -> jumd(label "c2pa.assertions") + bfdb + c2sh.
  let jumd = jumd_content(&json_uuid(), 0x03, Some("c2pa.assertions"), None);
  let mut bfdb = vec![0u8];
  bfdb.extend_from_slice(b"application/octet-stream\0");
  let c2sh = vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe];
  let mut inner = box_bytes(b"jumd", &jumd);
  inner.extend_from_slice(&box_bytes(b"bfdb", &bfdb));
  inner.extend_from_slice(&box_bytes(b"c2sh", &c2sh));
  let jumb = box_bytes(b"jumb", &inner);
  let meta = process(&jumb);

  let pj = render(&meta, true);
  // bfdb -> <Label>Type, c2sh -> <Label>Salt; both keep the Jpeg2000 group.
  let (tg, _, tv) = find(&pj, "C2PAAssertionsType");
  assert_eq!(tg, GROUP_JPEG2000);
  assert_eq!(tv, &TagValue::Str("application/octet-stream".into()));
  let (sg, _, sv) = find(&pj, "C2PAAssertionsSalt");
  assert_eq!(sg, GROUP_JPEG2000);
  assert_eq!(sv, &TagValue::Str("deadbeefcafe".into()));
  // The un-renamed default names must NOT appear.
  assert!(!has(&pj, "BinaryDataType"));
  assert!(!has(&pj, "C2PASaltHash"));
}

// ── Part B: the Doc<N> sub-document axis ─────────────────────────────────────

#[test]
fn single_jumb_opens_doc1() {
  let jumd = jumd_content(&json_uuid(), 0x03, Some("c2pa.test"), None);
  let jumb = box_bytes(b"jumb", &box_bytes(b"jumd", &jumd));
  let meta = process(&jumb);
  // -G1 collapses the doc axis to the bare family1:name, but the doc ordinal is
  // carried (1) for the -G3 render.
  let dj = render_doc(&meta, true);
  for (_, name, _, doc, doc_subpath) in &dj {
    assert_eq!(*doc, 1, "tag {name} should be Doc1");
    assert_eq!(doc_subpath, "", "tag {name} is top-level, no sub-doc");
  }
}

#[test]
fn sibling_jumbs_open_doc1_then_doc2() {
  // caBX -> [jumb(jumd lbl=a) , jumb(jumd lbl=b)] — two top-level superboxes.
  let jumd_a = jumd_content(&json_uuid(), 0x03, Some("aaa"), None);
  let jumd_b = jumd_content(&json_uuid(), 0x03, Some("bbb"), None);
  let mut stream = box_bytes(b"jumb", &box_bytes(b"jumd", &jumd_a));
  stream.extend_from_slice(&box_bytes(b"jumb", &box_bytes(b"jumd", &jumd_b)));
  let meta = process(&stream);
  let dj = render_doc(&meta, true);
  // The first superbox's JUMDLabel is "aaa" @ Doc1; the second @ Doc2.
  let a = dj
    .iter()
    .find(|(_, n, v, _, _)| n == "JUMDLabel" && *v == TagValue::Str("aaa".into()));
  let b = dj
    .iter()
    .find(|(_, n, v, _, _)| n == "JUMDLabel" && *v == TagValue::Str("bbb".into()));
  assert_eq!(a.expect("aaa label").3, 1, "first superbox is Doc1");
  assert_eq!(b.expect("bbb label").3, 2, "second superbox is Doc2");
}

#[test]
fn nested_jumb_opens_doc1_dash1() {
  // jumb -> jumb -> jumd: the inner superbox is the two-level Doc1-1.
  let jumd = jumd_content(&json_uuid(), 0x03, Some("inner"), None);
  let inner = box_bytes(b"jumb", &box_bytes(b"jumd", &jumd));
  let outer = box_bytes(b"jumb", &inner);
  let meta = process(&outer);
  let dj = render_doc(&meta, true);
  let label = dj
    .iter()
    .find(|(_, n, _, _, _)| n == "JUMDLabel")
    .expect("inner label");
  assert_eq!(label.3, 1, "outer superbox is Doc1");
  assert_eq!(label.4, "-1", "inner superbox is the two-level Doc1-1");
}

#[test]
fn three_level_nesting_opens_doc1_1_1() {
  // jumb -> jumb -> jumb -> jumd + bfdb + bidb: the deepest superbox is the
  // three-level Doc1-1-1 (`DOC_NUM = join '-', @jumd_level`, Jpeg2000.pm:786).
  // Ground-truthed against bundled 13.59 (`-G3 -j` ⇒ `Doc1-1-1:JUMDLabel` etc.).
  let jumd = jumd_content(&json_uuid(), 0x03, Some("inner"), None);
  let mut bfdb = vec![0u8];
  bfdb.extend_from_slice(b"image/jpeg\0");
  let bidb = b"\xff\xd8\xff\xe0FAKEJPEGDATA".to_vec(); // 16 bytes
  let mut inner = box_bytes(b"jumd", &jumd);
  inner.extend_from_slice(&box_bytes(b"bfdb", &bfdb));
  inner.extend_from_slice(&box_bytes(b"bidb", &bidb));
  let lvl3 = box_bytes(b"jumb", &inner);
  let lvl2 = box_bytes(b"jumb", &lvl3);
  let lvl1 = box_bytes(b"jumb", &lvl2);
  let meta = process(&lvl1);
  let dj = render_doc(&meta, true);
  // EVERY tag of the innermost superbox carries the full Doc1-1-1 path.
  assert!(!dj.is_empty(), "the deep nest must emit tags");
  for (_, name, _, doc, doc_subpath) in &dj {
    assert_eq!(*doc, 1, "tag {name} is under Doc1…");
    assert_eq!(
      doc_subpath, "-1-1",
      "tag {name} is the three-level Doc1-1-1"
    );
  }
  // The bfdb/bidb content emit (renamed by the "inner" label) AND the JUMD tags
  // are all present at the same deep path.
  assert!(has(&render(&meta, true), "JUMDLabel"));
  assert!(has(&render(&meta, true), "InnerType")); // bfdb -> <Label>Type
  assert!(has(&render(&meta, true), "InnerData")); // bidb -> <Label>Data
}

#[test]
fn three_distinct_nested_contents_do_not_collide() {
  // jumb(one) -> jumb(two) -> jumb(three), each with its OWN jumd(label) + bfdb,
  // so each level produces a DISTINCT bfdb under Doc1 / Doc1-1 / Doc1-1-1. The
  // full N-level dedup key must keep all three (no last-wins collision). Ground-
  // truthed vs bundled 13.59 (`-G3 -j` ⇒ Doc1:OneType / Doc1-1:TwoType /
  // Doc1-1-1:ThreeType).
  fn jumb_with_content(label: &str, mime: &str, inner: &[u8]) -> Vec<u8> {
    let jumd = jumd_content(&json_uuid(), 0x03, Some(label), None);
    let mut bfdb = vec![0u8];
    bfdb.extend_from_slice(mime.as_bytes());
    bfdb.push(0);
    let mut body = box_bytes(b"jumd", &jumd);
    body.extend_from_slice(&box_bytes(b"bfdb", &bfdb));
    body.extend_from_slice(inner);
    box_bytes(b"jumb", &body)
  }
  let g3 = jumb_with_content("three", "image/three", &[]);
  let g2 = jumb_with_content("two", "image/two", &g3);
  let g1 = jumb_with_content("one", "image/one", &g2);
  let meta = process(&g1);
  let dj = render_doc(&meta, true);

  // The three renamed bfdb tags live at three DISTINCT doc paths — no collision.
  let find_type = |name: &str| -> &(String, String, TagValue, u32, String) {
    dj.iter()
      .find(|(_, n, _, _, _)| n == name)
      .unwrap_or_else(|| panic!("missing {name}: {dj:?}"))
  };
  let one = find_type("OneType");
  let two = find_type("TwoType");
  let three = find_type("ThreeType");
  assert_eq!((one.3, one.4.as_str()), (1, ""), "OneType @ Doc1");
  assert_eq!((two.3, two.4.as_str()), (1, "-1"), "TwoType @ Doc1-1");
  assert_eq!(
    (three.3, three.4.as_str()),
    (1, "-1-1"),
    "ThreeType @ Doc1-1-1"
  );
  // Each carries its own MIME value (proof the distinct contents survive).
  assert_eq!(one.2, TagValue::Str("image/one".into()));
  assert_eq!(two.2, TagValue::Str("image/two".into()));
  assert_eq!(three.2, TagValue::Str("image/three".into()));
}

// ── label sanitization (tables::sanitize_label) ──────────────────────────────

#[test]
fn sanitize_label_matches_perl() {
  // Ground-truthed against the exact Perl pipeline (`Jpeg2000.pm:824-831`).
  assert_eq!(
    tables::sanitize_label("c2pa.test").as_deref(),
    Some("C2PATest")
  );
  assert_eq!(
    tables::sanitize_label("c2pa.assertions").as_deref(),
    Some("C2PAAssertions")
  );
  assert_eq!(tables::sanitize_label("a__b").as_deref(), Some("A_b"));
  assert_eq!(tables::sanitize_label(".a.b.c").as_deref(), Some("ABC"));
  // `_x`: '_' is legal so step 1 does not fire; length 2 ⇒ no `Tag` prefix at
  // stage 1 (the stage-2 `AddTagToTable` Tag-prefix is applied to label+suffix,
  // not the bare label).
  assert_eq!(tables::sanitize_label("_x").as_deref(), Some("_x"));
  // `X`: ucfirst -> `X`, length 1 < 2 ⇒ `TagX` (stage-1 length rule).
  assert_eq!(tables::sanitize_label("X").as_deref(), Some("TagX"));
  // Empty label ⇒ no JUMBFLabel.
  assert_eq!(tables::sanitize_label(""), None);
}

#[test]
fn make_renamed_tag_name_applies_tag_prefix() {
  // c2pa.test -> C2PATest -> C2PATestType (starts with a letter, kept).
  assert_eq!(
    tables::make_renamed_tag_name("C2PATest", "Type"),
    "C2PATestType"
  );
  // _x -> _xType: does NOT start with a letter ⇒ Tag-prefixed (ExifTool.pm:6488).
  assert_eq!(tables::make_renamed_tag_name("_x", "Type"), "Tag_xType");
}

// ── render_type / render_toggles ─────────────────────────────────────────────

#[test]
fn render_type_ascii_and_raw() {
  // ASCII-printable first group ⇒ (text)-…; PrintConv only.
  assert_eq!(
    render_type("6a736f6e00110010800000aa00389b71", true),
    "(json)-0011-0010-800000aa00389b71"
  );
  // Non-ASCII first group ⇒ raw hex 8-4-4-16.
  assert_eq!(
    render_type("6579d6fbdba2446bb2ac1b82feeb89d1", true),
    "6579d6fb-dba2-446b-b2ac1b82feeb89d1"
  );
  // ValueConv (-n) is always the raw hex, no split.
  assert_eq!(
    render_type("6a736f6e00110010800000aa00389b71", false),
    "6a736f6e00110010800000aa00389b71"
  );
  // A non-32-digit string renders verbatim.
  assert_eq!(render_type("abcd", true), "abcd");
}

#[test]
fn render_toggles_bitmask() {
  assert_eq!(render_toggles(0x03), "Requestable, Label"); // bits 0+1
  assert_eq!(render_toggles(0x0f), "Requestable, Label, ID, Signature");
  assert_eq!(render_toggles(0x00), "(none)");
  // An unmapped high bit renders [n].
  assert_eq!(render_toggles(0x10), "[4]");
}

// ── Part A: per-field bounds + truncation ────────────────────────────────────

#[test]
fn truncated_jumd_warns_and_stops() {
  // A jumd shorter than the 17-byte minimum.
  let short = box_bytes(b"jumd", &[0u8; 10]);
  let jumb = box_bytes(b"jumb", &short);
  let meta = process(&jumb);
  assert!(meta.warnings().contains(&JumbfWarning::TruncatedJumd));
  // No JUMDType emitted from the truncated box.
  let pj = render(&meta, true);
  assert!(!has(&pj, "JUMDType"));
}

#[test]
fn missing_label_terminator_warns() {
  // Label toggle set but NO NUL terminator in the remaining bytes.
  let mut content = jpeg_uuid().to_vec();
  content.push(0x02); // toggles: Label
  content.extend_from_slice(b"no-nul-here"); // no terminating NUL
  let jumb = box_bytes(b"jumb", &box_bytes(b"jumd", &content));
  let meta = process(&jumb);
  assert!(
    meta
      .warnings()
      .contains(&JumbfWarning::MissingLabelTerminator)
  );
}

#[test]
fn missing_id_warns() {
  // ID toggle set but no 4 bytes remain.
  let mut content = jpeg_uuid().to_vec();
  content.push(0x04); // toggles: ID
  content.extend_from_slice(&[0x00, 0x01]); // only 2 bytes
  let jumb = box_bytes(b"jumb", &box_bytes(b"jumd", &content));
  let meta = process(&jumb);
  assert!(meta.warnings().contains(&JumbfWarning::MissingId));
}

#[test]
fn id_and_signature_emit() {
  // toggles 0x0c = ID + Signature.
  let mut content = jpeg_uuid().to_vec();
  content.push(0x0c);
  content.extend_from_slice(&0xdead_beefu32.to_be_bytes());
  content.extend_from_slice(&[0xab; 32]);
  let jumb = box_bytes(b"jumb", &box_bytes(b"jumd", &content));
  let meta = process(&jumb);
  let pj = render(&meta, true);
  let (_, _, idv) = find(&pj, "JUMDID");
  assert_eq!(idv, &TagValue::U64(0xdead_beef));
  let (_, _, sv) = find(&pj, "JUMDSignature");
  assert_eq!(sv, &TagValue::Str(SmolStr::from("ab".repeat(32))));
}

#[test]
fn empty_or_unrecognized_cabx_is_empty() {
  // Empty payload ⇒ nothing decoded, no warning (the walk ends cleanly at the
  // exact end; bundled likewise emits no `caBX` tags and no warning).
  assert!(process(&[]).is_empty());
  // An unrecognized top-level box is SKIPPED with no warning — the walk advances
  // past it and ends cleanly (oracle-verified: bundled emits no warning for a
  // `zzzz` box). A 12-byte box (8 header + 4 payload) consumes the whole stream.
  let unk = box_bytes(b"zzzz", &[1, 2, 3, 4]);
  assert!(process(&unk).is_empty());
}

// ── Part A: the generic box-structure truncation / invalid-length warnings ───
// (`ProcessJpeg2000Box`, `Jpeg2000.pm:1349-1356`). Each case is a VALID jumb
// (emitting JUMDType/JUMDLabel — partial progress) followed by a malformed box;
// the exact warning string + the partial-progress tags are ground-truthed
// against bundled ExifTool 13.59 (`perl exiftool -G1 -j`).

/// A valid `jumb -> jumd(json uuid, label "c2pa.test")` prefix that emits tags
/// BEFORE any trailing malformed box — so each truncation test also asserts the
/// faithful partial progress (the valid box's tags survive).
fn valid_prefix() -> Vec<u8> {
  let jumd = jumd_content(&json_uuid(), 0x03, Some("c2pa.test"), None);
  box_bytes(b"jumb", &box_bytes(b"jumd", &jumd))
}

/// A trailing malformed box's warning fires AND the preceding valid box's tags
/// still emit (the ExifTool walk emits valid boxes then warns once on the
/// malformed one).
fn assert_partial_progress(meta: &JumbfMeta) {
  let pj = render(meta, true);
  assert!(
    has(&pj, "JUMDType") && has(&pj, "JUMDLabel"),
    "the valid box parsed before the malformed one must still emit: {pj:?}"
  );
}

#[test]
fn partial_box_header_warns_truncated() {
  // (a) A short tail (< 8 bytes) after a valid box — the header cannot be read.
  // Bundled: "Truncated JPEG 2000 box" + the valid box's tags.
  let mut data = valid_prefix();
  data.extend_from_slice(&[0x00, 0x00, 0x00, 0x05, b'a']); // 5-byte tail
  let meta = process(&data);
  assert!(meta.warnings().contains(&JumbfWarning::BoxTruncated));
  assert_partial_progress(&meta);
}

#[test]
fn extended_size_truncated_header_warns_truncated() {
  // (b) A box with boxLen==1 (extended size) but fewer than 8 size bytes follow.
  // Bundled: "Truncated JPEG 2000 box".
  let mut data = valid_prefix();
  data.extend_from_slice(&1u32.to_be_bytes()); // boxLen == 1 (extended)
  data.extend_from_slice(b"jumb");
  data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // only 4 of the 8 size bytes
  let meta = process(&data);
  assert!(meta.warnings().contains(&JumbfWarning::BoxTruncated));
  assert_partial_progress(&meta);
}

#[test]
fn box_len_below_header_warns_invalid_length() {
  // (c) A readable 8-byte header whose declared boxLen is in 1..8 (so boxLen -
  // hdrLen < 0), with trailing pad so the next-header check does NOT fire first.
  // Bundled: "Invalid JPEG 2000 box length" (NOT "Truncated" — a header that IS
  // readable but nonsensical, vs a header too short to read).
  for bad_len in [2u32, 4, 7] {
    let mut data = valid_prefix();
    data.extend_from_slice(&bad_len.to_be_bytes());
    data.extend_from_slice(b"jumb");
    data.extend_from_slice(&[0u8; 16]); // pad past the header
    let meta = process(&data);
    assert!(
      meta.warnings().contains(&JumbfWarning::InvalidBoxLength),
      "boxLen {bad_len} (< hdrLen) must warn InvalidBoxLength, got {:?}",
      meta.warnings()
    );
    assert!(
      !meta.warnings().contains(&JumbfWarning::BoxTruncated),
      "boxLen {bad_len} is Invalid, not Truncated"
    );
    assert_partial_progress(&meta);
  }
}

#[test]
fn claimed_payload_beyond_buffer_warns_truncated() {
  // (d) A box claiming a payload far past the buffer end. Bundled: "Truncated
  // JPEG 2000 box".
  let mut data = valid_prefix();
  data.extend_from_slice(&0x1000u32.to_be_bytes()); // boxLen claims 0x1000 bytes
  data.extend_from_slice(b"jumb");
  data.extend_from_slice(&box_bytes(b"jumd", &[0u8; 8])); // only a few real bytes
  let meta = process(&data);
  assert!(meta.warnings().contains(&JumbfWarning::BoxTruncated));
  assert_partial_progress(&meta);
}

#[test]
fn extended_size_over_4gb_warns() {
  // (e) An extended-size (boxLen==1) box with a non-zero HIGH word ⇒ a > 4 GB
  // box ExifTool refuses. Bundled: "Can't currently handle JPEG 2000 boxes
  // > 4 GB".
  let mut data = valid_prefix();
  data.extend_from_slice(&1u32.to_be_bytes()); // boxLen == 1 (extended)
  data.extend_from_slice(b"jumb");
  data.extend_from_slice(&1u32.to_be_bytes()); // high word != 0
  data.extend_from_slice(&0u32.to_be_bytes()); // low word
  let meta = process(&data);
  assert!(meta.warnings().contains(&JumbfWarning::Over4Gb));
  assert_partial_progress(&meta);
}

#[test]
fn oversized_top_level_box_warns_truncated() {
  // An oversized 0xffffffff boxLen + the `jumb` type, no payload. The 8-byte
  // header IS readable, so boxLen - hdrLen is a huge value whose payload overruns
  // the buffer ⇒ "Truncated JPEG 2000 box" (ground-truthed vs bundled 13.59 — it
  // is NOT silently dropped).
  let mut bad = 0xffff_ffffu32.to_be_bytes().to_vec();
  bad.extend_from_slice(b"jumb");
  let meta = process(&bad);
  assert!(!meta.is_empty(), "an oversized box must raise a warning");
  assert!(meta.warnings().contains(&JumbfWarning::BoxTruncated));
}

#[test]
fn exact_buffer_end_is_clean() {
  // A buffer consumed EXACTLY by a valid box ends with NO warning (`$err = ''
  // unless $pos == $dirEnd`, Jpeg2000.pm:1080) — only a NON-exact short tail is
  // truncated. The valid prefix's box consumes the whole stream.
  let meta = process(&valid_prefix());
  assert!(
    meta.warnings().is_empty(),
    "an exactly-consumed buffer is clean: {:?}",
    meta.warnings()
  );
  assert_partial_progress(&meta);
}

#[test]
fn depth_budget_caps_recursion() {
  // Nest MAX_BOX_DEPTH+2 jumb boxes; the walker must NOT recurse past the cap
  // and must raise TooDeep instead of overflowing the stack.
  let jumd = jumd_content(&json_uuid(), 0x03, Some("deep"), None);
  let mut payload = box_bytes(b"jumd", &jumd);
  for _ in 0..(MAX_BOX_DEPTH + 2) {
    payload = box_bytes(b"jumb", &payload);
  }
  let meta = process(&payload);
  assert!(meta.warnings().contains(&JumbfWarning::TooDeep));
}

#[test]
fn jumd_private_data_recursion_is_depth_bounded() {
  // A crafted `jumd` whose trailing-private region (`Jpeg2000.pm:844-859`) is
  // ITSELF another `jumd` box — whose private region is another `jumd`, … — must
  // be bounded by the SAME depth budget as `jumb`/`asoc` nesting. Without it the
  // private-data walk reset the recursion depth to 0 each level, so this chain
  // would recurse `process_jumd → walk → process_jumd` until the stack blows.
  // ExifTool re-enters the full `ProcessJpeg2000Box` walker for this private
  // region (`Jpeg2000::Main` PROCESS_PROC, `Jpeg2000.pm:127-130`/`:855`), so a
  // `jumd`-in-private IS a real recursion level — the cap is the only bound.
  //
  // Build the innermost as a bare valid `jumd` content (no private region), then
  // wrap MAX_BOX_DEPTH+4 levels, each a `jumd` whose content is `uuid + toggle 0
  // + box("jumd", child)` so its private region (>= 8 bytes) is the child box.
  let mut content = jumd_content(&jpeg_uuid(), 0x00, None, None); // 17 bytes, no private
  for _ in 0..(MAX_BOX_DEPTH + 4) {
    let child_box = box_bytes(b"jumd", &content);
    // The parent jumd's content: 16-byte UUID + toggle 0x00 (no label/id/sig),
    // then the child `jumd` BOX as the trailing-private region.
    let mut parent = jpeg_uuid().to_vec();
    parent.push(0x00);
    parent.extend_from_slice(&child_box);
    content = parent;
  }
  // Top-level `jumb` so the chain begins inside a superbox (the real entry).
  let cabx = box_bytes(b"jumb", &box_bytes(b"jumd", &content));
  // The mere fact `process` RETURNS (no stack overflow) is the primary assertion;
  // the depth budget must have fired exactly once it ran out of headroom.
  let meta = process(&cabx);
  assert!(
    meta.warnings().contains(&JumbfWarning::TooDeep),
    "the jumd-private recursion must hit the depth budget (TooDeep), got {:?}",
    meta.warnings()
  );
}

#[test]
fn box_len_zero_runs_to_end() {
  // A boxLen==0 jumb runs to the end of the caBX payload (Jpeg2000.pm:1117).
  let jumd = jumd_content(&json_uuid(), 0x03, Some("toend"), None);
  let inner = box_bytes(b"jumd", &jumd);
  let mut jumb = Vec::new();
  jumb.extend_from_slice(&0u32.to_be_bytes()); // boxLen == 0 (to end)
  jumb.extend_from_slice(b"jumb");
  jumb.extend_from_slice(&inner);
  let meta = process(&jumb);
  let pj = render(&meta, true);
  assert!(has(&pj, "JUMDLabel"));
}

// ── Phase 2: the `json` content decoder (`JSON::Main` / `ProcessJSON`) ────────

/// Build a `jumb -> jumd(label) + json{doc}` caBX box stream and decode it.
fn json_box_meta(doc: &[u8]) -> JumbfMeta {
  let jumd = jumd_content(&json_uuid(), 0x03, Some("c2pa.test"), None);
  let inner = [box_bytes(b"jumd", &jumd), box_bytes(b"json", doc)].concat();
  process(&box_bytes(b"jumb", &inner))
}

#[test]
fn json_flattens_top_level_object_keys() {
  // Each top-level key becomes one JSON:<legalized-key> tag; group is JSON.
  let meta = json_box_meta(br#"{"claim_generator":"exifast/1.0","format":"image/png"}"#);
  let pj = render(&meta, true);
  let (g, _, v) = find(&pj, "Claim_generator");
  assert_eq!(g, GROUP_JSON);
  assert_eq!(v, &TagValue::Str("exifast/1.0".into()));
  let (g2, _, v2) = find(&pj, "Format");
  assert_eq!(g2, GROUP_JSON);
  assert_eq!(v2, &TagValue::Str("image/png".into()));
}

#[test]
fn json_scalar_types_render_through_the_gate() {
  // number -> raw lexeme Str (gate renders bare); true/false -> Bool; null ->
  // the "null" Str (MissingTagValue default, gate quotes it); a >15-digit
  // integer stays a Str (gate quotes it).
  let meta = json_box_meta(
    br#"{"version":2,"score":0.95,"validated":true,"revoked":false,"signature":null,"serial":1234567890123456789}"#,
  );
  let pj = render(&meta, true);
  assert_eq!(find(&pj, "Version").2, TagValue::Str("2".into()));
  assert_eq!(find(&pj, "Score").2, TagValue::Str("0.95".into()));
  assert_eq!(find(&pj, "Validated").2, TagValue::Bool(true));
  assert_eq!(find(&pj, "Revoked").2, TagValue::Bool(false));
  assert_eq!(find(&pj, "Signature").2, TagValue::Str("null".into()));
  assert_eq!(
    find(&pj, "Serial").2,
    TagValue::Str("1234567890123456789".into())
  );
}

#[test]
fn json_nested_object_is_a_struct_map_with_raw_inner_keys() {
  // Under -struct, a nested object emits as ONE tag whose value is a Map with
  // the RAW inner keys (NOT legalized).
  let meta = json_box_meta(br#"{"thumbnail":{"format":"image/jpeg","2key":7}}"#);
  let pj = render(&meta, true);
  let (g, _, v) = find(&pj, "Thumbnail");
  assert_eq!(g, GROUP_JSON);
  assert_eq!(
    v,
    &TagValue::Map(vec![
      ("format".into(), TagValue::Str("image/jpeg".into())),
      ("2key".into(), TagValue::Str("7".into())),
    ])
  );
}

#[test]
fn json_arrays_of_scalars_and_objects() {
  // An array stays a List; an array of objects is a List of Maps.
  let meta = json_box_meta(br#"{"ingredients":["a","b"],"assertions":[{"label":"x"}]}"#);
  let pj = render(&meta, true);
  assert_eq!(
    find(&pj, "Ingredients").2,
    TagValue::List(vec![TagValue::Str("a".into()), TagValue::Str("b".into())])
  );
  assert_eq!(
    find(&pj, "Assertions").2,
    TagValue::List(vec![TagValue::Map(vec![(
      "label".into(),
      TagValue::Str("x".into())
    )])])
  );
}

#[test]
fn json_empty_array_emits_no_tag_but_empty_object_does() {
  // A top-level EMPTY array emits nothing (ProcessTag iterates @$val = []);
  // an empty object emits one tag (FoundTag(Struct=>1) -> {}).
  let meta = json_box_meta(br#"{"empty_arr":[],"empty_obj":{},"kept":1}"#);
  let pj = render(&meta, true);
  assert!(!has(&pj, "Empty_arr"), "empty array must emit no tag");
  assert_eq!(find(&pj, "Empty_obj").2, TagValue::Map(vec![]));
  assert_eq!(find(&pj, "Kept").2, TagValue::Str("1".into()));
}

#[test]
fn json_top_level_key_legalization() {
  // tr/:/_/, the ^c2pa->C2PA hack, MakeTagName (delete-illegal/ucfirst/Tag-
  // prefix), and AddTagToTable's leading-letter Tag prefix.
  let meta =
    json_box_meta(br#"{"hello world":1,"with.dot":2,"123num":3,"c2pa.manifest":4,"_x":5,"a":6}"#);
  let pj = render(&meta, true);
  assert!(has(&pj, "Helloworld"));
  assert!(has(&pj, "Withdot"));
  assert!(has(&pj, "Tag123num"));
  assert!(has(&pj, "C2PAmanifest"));
  assert!(has(&pj, "Tag_x"));
  assert!(has(&pj, "TagA"));
}

#[test]
fn json_string_escapes_are_unescaped() {
  // \uHHHH -> the code point; \t\n\r\b\f -> the control char; \" \\ -> the
  // literal char; and a raw multi-byte UTF-8 sequence (é = 0xC3 0xA9) passes
  // through repaired.
  let mut doc = br#"{"esc":"a\tb\n\"q\"\\"#.to_vec();
  doc.extend_from_slice(&[0xC3, 0xA9]); // a literal U+00E9 in the source bytes
  doc.extend_from_slice(br#""}"#);
  let meta = json_box_meta(&doc);
  let pj = render(&meta, true);
  assert_eq!(
    find(&pj, "Esc").2,
    TagValue::Str("a\tb\n\"q\"\\\u{00e9}".into())
  );
}

#[test]
fn json_tags_ride_the_doc_axis() {
  // The JSON tags carry this box's Doc<N> (Doc1 here — first top-level jumb).
  let meta = json_box_meta(br#"{"key":1}"#);
  let doc = render_doc(&meta, true);
  let k = doc
    .iter()
    .find(|(_, n, ..)| n == "Key")
    .expect("JSON:Key present");
  assert_eq!(k.0, GROUP_JSON);
  assert_eq!(k.3, 1, "JSON tag must ride Doc1");
  assert_eq!(k.4, "", "top-level jumb is a plain Doc1 (no sub-path)");
}

#[test]
fn json_non_object_document_is_unrecognized_box() {
  // A bare-scalar document -> ProcessJSON returns 0 -> the JUMBF walker raises
  // `Unrecognized <Name> box` (the renamed JUMBFLabel — c2pa.test -> C2PATest).
  let meta = json_box_meta(br#"42"#);
  assert!(
    render(&meta, true).iter().all(|(g, ..)| g != GROUP_JSON),
    "a non-object json doc emits no JSON tags"
  );
  assert!(
    meta
      .warnings()
      .iter()
      .any(|w| w.message() == "Unrecognized C2PATest box"),
    "expected the Unrecognized box warning, got {:?}",
    meta.warnings()
  );
}

#[test]
fn json_deeply_nested_is_depth_bounded_not_a_panic() {
  // A pathologically deep document must not overflow the stack: it parses to a
  // failure at the budget and surfaces the Unrecognized-box warning (no panic).
  let depth = super::json::tests_max_depth() + 50;
  let mut doc = Vec::new();
  for _ in 0..depth {
    doc.extend_from_slice(br#"{"a":"#);
  }
  doc.extend_from_slice(b"1");
  doc.extend(std::iter::repeat_n(b'}', depth));
  let meta = json_box_meta(&doc);
  // Must not panic; either no JSON tags or a warning — the point is termination.
  assert!(render(&meta, true).iter().all(|(g, ..)| g != GROUP_JSON) || !meta.warnings().is_empty());
}

#[test]
fn json_truncated_document_does_not_panic() {
  // A truncated object (no closing brace / value) must fail gracefully.
  for doc in [
    &b"{"[..],
    &b"{\"k\":"[..],
    &b"{\"k\":\"unterminated"[..],
    &b"[1,2"[..],
    &b"{\"k\":1,"[..],
  ] {
    let meta = json_box_meta(doc);
    // No panic; a malformed doc yields the Unrecognized-box warning.
    let _ = render(&meta, true);
    assert!(
      !meta.warnings().is_empty(),
      "truncated json {doc:?} should warn"
    );
  }
}

// ── Phase 2: the `Import::ReadJSON` SourceFile-keyed array database ───────────
// (Import.pm:285-303 + the ProcessJSON sorted-key flatten loop, JSON.pm:161-168.
//  Each top-level array OBJECT is keyed by its `SourceFile`; a later same-key
//  object overwrites; the surviving objects flatten in SORTED key order, the
//  auto-default `'*'` SourceFile skipped. All oracle-verified vs bundled 13.59.)

#[test]
fn json_array_distinct_sourcefiles_keep_both_objects() {
  // [{SourceFile:a,x:1},{SourceFile:b,y:2}] -> two DISTINCT database keys, so
  // BOTH objects survive: JSON:TagX (from a.jpg) and JSON:TagY (from b.jpg).
  // NO data loss — the pre-fix `last_object` collapse dropped TagX entirely.
  let meta = json_box_meta(br#"[{"SourceFile":"a.jpg","x":1},{"SourceFile":"b.jpg","y":2}]"#);
  let pj = render(&meta, true);
  assert_eq!(find(&pj, "TagX").2, TagValue::Str("1".into()));
  assert_eq!(find(&pj, "TagY").2, TagValue::Str("2".into()));
  // Both objects carry an explicit SourceFile (≠ '*'), so each flattens to a
  // JSON:SourceFile entry, emitted in sorted-key order [a.jpg, b.jpg]. The
  // unit `tags()` stream is pre-dedup; the downstream TagMap last-wins keeps the
  // LAST value (b.jpg), matching bundled. Assert the emitted SEQUENCE so both
  // the sorted order and the last-wins value are pinned.
  let sources: Vec<&TagValue> = pj
    .iter()
    .filter(|(g, n, _)| g == GROUP_JSON && n == "SourceFile")
    .map(|(_, _, v)| v)
    .collect();
  assert_eq!(
    sources,
    vec![
      &TagValue::Str("a.jpg".into()),
      &TagValue::Str("b.jpg".into())
    ],
    "explicit SourceFiles flatten in sorted-key order; TagMap then last-wins b.jpg"
  );
}

#[test]
fn json_array_no_sourcefile_collapses_to_last() {
  // [{x:1},{y:2}] -> neither has a SourceFile, so both default to '*' and
  // collide; the LAST object overwrites -> only JSON:TagY survives (TagX gone).
  // The auto-default '*' SourceFile is skipped, so no JSON:SourceFile.
  let meta = json_box_meta(br#"[{"x":1},{"y":2}]"#);
  let pj = render(&meta, true);
  assert!(
    !has(&pj, "TagX"),
    "the '*'-keyed first object is overwritten"
  );
  assert_eq!(find(&pj, "TagY").2, TagValue::Str("2".into()));
  assert!(
    !has(&pj, "SourceFile"),
    "the auto-default '*' SourceFile is skipped (JSON.pm:165)"
  );
}

#[test]
fn json_array_sourcefile_keys_iterate_sorted() {
  // [{SourceFile:b,y:2},{SourceFile:a,x:1}] -> sorted key order visits a.jpg
  // BEFORE b.jpg regardless of document order, so TagX (a.jpg) flattens first.
  // (Verifies `sort keys %database`, JSON.pm:161.)
  let meta = json_box_meta(br#"[{"SourceFile":"b.jpg","y":2},{"SourceFile":"a.jpg","x":1}]"#);
  let pj = render(&meta, true);
  let names: Vec<&str> = pj
    .iter()
    .filter(|(g, ..)| g == GROUP_JSON)
    .map(|(_, n, _)| n.as_str())
    .collect();
  let x = names.iter().position(|n| *n == "TagX");
  let y = names.iter().position(|n| *n == "TagY");
  assert!(
    x.is_some() && y.is_some(),
    "both objects survive: {names:?}"
  );
  assert!(
    x < y,
    "a.jpg sorts before b.jpg, so TagX precedes TagY: {names:?}"
  );
}

#[test]
fn json_array_same_sourcefile_overwrites() {
  // [{SourceFile:a,x:1},{SourceFile:a,y:2}] -> same database key 'a.jpg', so
  // the second object OVERWRITES the first: TagX gone, only TagY (+ the
  // explicit SourceFile a.jpg, which is ≠ '*' so it flattens).
  let meta = json_box_meta(br#"[{"SourceFile":"a.jpg","x":1},{"SourceFile":"a.jpg","y":2}]"#);
  let pj = render(&meta, true);
  assert!(!has(&pj, "TagX"), "same-key object is overwritten");
  assert_eq!(find(&pj, "TagY").2, TagValue::Str("2".into()));
  assert_eq!(find(&pj, "SourceFile").2, TagValue::Str("a.jpg".into()));
}

#[test]
fn json_array_of_scalars_is_unrecognized() {
  // [1,2,3] -> no HASH element -> $found stays false -> ReadJSON errors ->
  // ProcessJSON returns 0 -> the Unrecognized-box warning, no JSON tags.
  let meta = json_box_meta(br#"[1,2,3]"#);
  assert!(
    render(&meta, true).iter().all(|(g, ..)| g != GROUP_JSON),
    "a scalar-only array emits no JSON tags"
  );
  assert!(
    meta
      .warnings()
      .iter()
      .any(|w| w.message() == "Unrecognized C2PATest box"),
    "expected the Unrecognized-box warning, got {:?}",
    meta.warnings()
  );
}

#[test]
fn json_array_mixed_scalar_and_object_keeps_the_object() {
  // [1,{x:5}] -> the scalar 1 is skipped (next unless ref eq HASH); the object
  // defaults to '*' -> JSON:TagX=5.
  let meta = json_box_meta(br#"[1,{"x":5}]"#);
  let pj = render(&meta, true);
  assert_eq!(find(&pj, "TagX").2, TagValue::Str("5".into()));
}

#[test]
fn json_single_object_explicit_sourcefile_flattens_it() {
  // A single (non-array) object with an EXPLICIT SourceFile (≠ '*') flattens it
  // to JSON:SourceFile (ReadJSON wraps {…} as [{…}]; the value is not '*').
  let meta = json_box_meta(br#"{"SourceFile":"z.jpg","x":1}"#);
  let pj = render(&meta, true);
  assert_eq!(find(&pj, "SourceFile").2, TagValue::Str("z.jpg".into()));
  assert_eq!(find(&pj, "TagX").2, TagValue::Str("1".into()));
}

#[test]
fn json_single_object_star_and_case_insensitive_sourcefile_are_dropped() {
  // An explicit '*' SourceFile is skipped (JSON.pm:165).
  let star = json_box_meta(br#"{"SourceFile":"*","x":1}"#);
  let star_pj = render(&star, true);
  assert!(!has(&star_pj, "SourceFile"), "explicit '*' is skipped");
  assert_eq!(find(&star_pj, "TagX").2, TagValue::Str("1".into()));
  // A case-insensitive `sourcefile` key (no exact SourceFile) is RENAMED to
  // SourceFile and its original key REMOVED, so it does NOT flatten at all.
  let ci = json_box_meta(br#"{"sourcefile":"q.jpg","x":1}"#);
  let ci_pj = render(&ci, true);
  assert!(
    !has(&ci_pj, "SourceFile") && !has(&ci_pj, "Sourcefile"),
    "a renamed case-insensitive sourcefile key flattens to nothing: {ci_pj:?}"
  );
  assert_eq!(find(&ci_pj, "TagX").2, TagValue::Str("1".into()));
}

// ── Phase 2: `Import::ReadJSON` base64 string decoding (Import.pm:227-229) ────

#[test]
fn json_base64_text_value_is_decoded() {
  // 'base64:SGk=' (len 11, %4==3) decodes to "Hi" (oracle: JSON:TagV "Hi").
  let meta = json_box_meta(br#"{"v":"base64:SGk="}"#);
  let pj = render(&meta, true);
  assert_eq!(find(&pj, "TagV").2, TagValue::Str("Hi".into()));
  // A longer body: 'base64:SGVsbG8=' (len 15, %4==3) -> "Hello".
  let meta2 = json_box_meta(br#"{"v":"base64:SGVsbG8="}"#);
  assert_eq!(
    find(&render(&meta2, true), "TagV").2,
    TagValue::Str("Hello".into())
  );
}

#[test]
fn json_base64_binary_value_renders_as_question_marks() {
  // 'base64:/v0=' (len 11, %4==3) decodes to the bytes FE FD (invalid UTF-8);
  // bundled's JSON FixUTF8 renders them as "??" (0x3F 0x3F), top-level AND in a
  // nested struct (oracle-verified both paths).
  let meta = json_box_meta(br#"{"v":"base64:/v0="}"#);
  assert_eq!(
    find(&render(&meta, true), "TagV").2,
    TagValue::Str("??".into())
  );
  let nested = json_box_meta(br#"{"outer":{"v":"base64:/v0="}}"#);
  assert_eq!(
    find(&render(&nested, true), "Outer").2,
    TagValue::Map(vec![("v".into(), TagValue::Str("??".into()))])
  );
}

#[test]
fn json_base64_non_matching_length_stays_literal() {
  // The length rule `% 4 == 3` is on the WHOLE string. 'base64:QQ=' has length
  // 10 (%4==2) -> does NOT decode -> the literal string passes through.
  let meta = json_box_meta(br#"{"v":"base64:QQ="}"#);
  assert_eq!(
    find(&render(&meta, true), "TagV").2,
    TagValue::Str("base64:QQ=".into())
  );
  // The length rule passes (`base64:a@bc` = 11, %4==3) but the '@' breaks the
  // `[A-Za-z0-9+/]*={0,2}` body form -> NOT decoded, the literal passes through.
  let meta2 = json_box_meta(br#"{"v":"base64:a@bc"}"#);
  assert_eq!(
    find(&render(&meta2, true), "TagV").2,
    TagValue::Str("base64:a@bc".into())
  );
}

// ── Phase 2: the SourceFile database key is the RAW (pre-FixUTF8) bytes ───────
// (Import.pm:301 keys %database on the raw decoded SourceFile scalar — base64-
//  decoded, but BEFORE FixUTF8, which is an OUTPUT concern). Early normalization
//  would collapse two DISTINCT raw keys that share a FixUTF8 rendering and drop
//  an object. All oracle-verified vs bundled ExifTool 13.59.

#[test]
fn json_array_sourcefile_raw_byte_keys_do_not_collide() {
  // [{SourceFile:'base64:/v0=',x:1},{SourceFile:'??',y:2}]: the first object's
  // SourceFile base64-decodes to the RAW bytes FE FD; the second's is the
  // literal ASCII '??' = 3F 3F. These are DISTINCT raw database keys, so BOTH
  // objects survive (the pre-fix early-FixUTF8 turned FE FD into '??' too, so
  // the keys collided and TagX was LOST). Ground-truthed vs bundled 13.59
  // (`-G1 -j -struct` ⇒ both JSON:TagX=1 AND JSON:TagY=2).
  let meta = json_box_meta(br#"[{"SourceFile":"base64:/v0=","x":1},{"SourceFile":"??","y":2}]"#);
  let pj = render(&meta, true);
  assert_eq!(find(&pj, "TagX").2, TagValue::Str("1".into()));
  assert_eq!(find(&pj, "TagY").2, TagValue::Str("2".into()));
  // Sorted RAW-key order: 3F 3F (the '??' object, with TagY) sorts BEFORE FE FD
  // (the FE-FD object, with TagX) — 0x3F < 0xFE. Both SourceFile values render
  // '??' at output (FE FD and 3F 3F both FixUTF8 to '??'). Assert the emitted
  // JSON sequence pins the raw-byte sort order (TagY before TagX).
  let names: Vec<&str> = pj
    .iter()
    .filter(|(g, ..)| g == GROUP_JSON)
    .map(|(_, n, _)| n.as_str())
    .collect();
  let y = names.iter().position(|n| *n == "TagY");
  let x = names.iter().position(|n| *n == "TagX");
  assert!(
    y < x,
    "raw key 3F 3F (TagY) sorts before FE FD (TagX): {names:?}"
  );
  // Each surviving object flattens its explicit SourceFile, both rendering '??'
  // (the FE-FD object's via FixUTF8 at flatten, the literal object's verbatim).
  let sources: Vec<&TagValue> = pj
    .iter()
    .filter(|(g, n, _)| g == GROUP_JSON && n == "SourceFile")
    .map(|(_, _, v)| v)
    .collect();
  assert_eq!(
    sources,
    vec![&TagValue::Str("??".into()), &TagValue::Str("??".into())],
    "both objects' SourceFile values render '??' after FixUTF8"
  );
}

#[test]
fn json_array_base64_and_literal_decoding_to_same_bytes_collide() {
  // The KEY is the base64-DECODED bytes, so a base64 value that decodes to the
  // SAME bytes as a literal value DOES collide. 'base64:Pz8=' decodes to 3F 3F
  // = the literal '??', so both objects key on 3F 3F -> the LAST (y) overwrites
  // the first (x). Ground-truthed vs bundled 13.59 (`-G1 -j` ⇒ only JSON:TagY=2
  // + JSON:SourceFile '??'; TagX gone). Proves the key is the DECODED raw bytes,
  // not the `base64:` lexeme.
  let meta = json_box_meta(br#"[{"SourceFile":"base64:Pz8=","x":1},{"SourceFile":"??","y":2}]"#);
  let pj = render(&meta, true);
  assert!(
    !has(&pj, "TagX"),
    "base64:Pz8= decodes to 3F 3F = '??', colliding with the literal -> TagX overwritten"
  );
  assert_eq!(find(&pj, "TagY").2, TagValue::Str("2".into()));
  assert_eq!(find(&pj, "SourceFile").2, TagValue::Str("??".into()));
}

#[test]
fn json_array_duplicate_tag_across_sorted_raw_keys_last_wins() {
  // Two objects with DISTINCT raw SourceFile keys (FE FD via base64, vs the
  // literal 'a.jpg') BOTH emit a `dup` tag. They flatten in sorted raw-key
  // order — 'a.jpg' (61 2E...) sorts BEFORE FE FD — so `dup`=first then `dup`=
  // second in the stream; the downstream TagMap last-wins keeps the LAST (the
  // FE-FD object's value). Pins both the raw-byte sort order AND the last-wins
  // across sorted raw keys (oracle: bundled 13.59 prints the FE-FD object's
  // `dup` last, so `-j` last-wins keeps "fromfefd").
  let meta = json_box_meta(
    br#"[{"SourceFile":"base64:/v0=","dup":"fromfefd"},{"SourceFile":"a.jpg","dup":"froma"}]"#,
  );
  let pj = render(&meta, true);
  let dups: Vec<&TagValue> = pj
    .iter()
    .filter(|(g, n, _)| g == GROUP_JSON && n == "Dup")
    .map(|(_, _, v)| v)
    .collect();
  // 'a.jpg' (0x61...) sorts before FE FD, so the sequence is [froma, fromfefd].
  assert_eq!(
    dups,
    vec![
      &TagValue::Str("froma".into()),
      &TagValue::Str("fromfefd".into())
    ],
    "duplicate `dup` flattens in sorted raw-key order [a.jpg, FE FD]; TagMap then last-wins fromfefd"
  );
}

// ── Phase 2: `\uHHHH` surrogate / BMP escape decoding (Import.pm:224) ─────────

/// Wrap a `\u`-escape body (the bytes BETWEEN the value quotes) into a json doc
/// `{"v":"<body>"}`. Built byte-wise so a literal backslash-u stays a JSON
/// escape (not a Rust one).
fn json_uesc_doc(body: &[u8]) -> Vec<u8> {
  [br#"{"v":""#.as_slice(), body, br#""}"#.as_slice()].concat()
}

#[test]
fn json_unicode_escapes_match_to_utf8_then_fixutf8() {
  // The `\uHHHH` escape bodies are spelled as explicit ASCII bytes so they
  // stay JSON escapes (a Rust `\u` literal would be interpreted at compile).
  // `é` = the 6 bytes below.
  let bmp = json_box_meta(&json_uesc_doc(b"\\u00e9"));
  // A BMP escape é -> the proper UTF-8 for é (C3 A9).
  assert_eq!(
    find(&render(&bmp, true), "TagV").2,
    TagValue::Str("\u{00e9}".into())
  );
  // `😀` (what a JSON encoder emits for 😀) is NOT combined into
  // U+1F600: ExifTool encodes each surrogate half independently (ToUTF8 -> two
  // 3-byte WTF-8 sequences = 6 invalid bytes), then FixUTF8 renders them as six
  // '?' (oracle-verified vs bundled 13.59).
  let pair = json_box_meta(&json_uesc_doc(b"\\uD83D\\uDE00"));
  assert_eq!(
    find(&render(&pair, true), "TagV").2,
    TagValue::Str("??????".into())
  );
  // A LONE surrogate `\uD83D` -> one 3-byte WTF-8 sequence -> three '?'.
  let lone = json_box_meta(&json_uesc_doc(b"\\uD83D"));
  assert_eq!(
    find(&render(&lone, true), "TagV").2,
    TagValue::Str("???".into())
  );
}

#[test]
fn json_unicode_escape_then_single_char_escape_ordering() {
  // ExifTool runs the \uHHHH substitution BEFORE the \(.) one, both global:
  // `\` becomes a literal backslash in pass 1, which pass 2 then pairs
  // with the following 'n' -> a NEWLINE (0x0A). (Import.pm:224 then :225;
  // oracle-verified vs bundled 13.59: `\n` -> the single byte 0x0A.)
  let meta = json_box_meta(&json_uesc_doc(b"\\u005cn"));
  assert_eq!(
    find(&render(&meta, true), "TagV").2,
    TagValue::Str("\n".into())
  );
}
