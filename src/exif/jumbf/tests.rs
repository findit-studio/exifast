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
