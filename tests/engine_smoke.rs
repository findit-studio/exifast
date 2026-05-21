//! End-to-end engine smoke: build Metadata via the public API, run a value
//! through the conversion runtime, serialize, and confirm our own jsondiff
//! treats the output as equivalent to itself. No format parser involved.
//!
//! Gated on `feature = "json"` (Codex A-R4-2): imports the `json`-gated
//! `serialize` + `jsondiff`, which `std` does not imply.
#![cfg(feature = "json")]
use exifast::{
  Group, Metadata, TagValue,
  convert::apply,
  jsondiff::json_equivalent,
  serialize::to_exiftool_json,
  tagtable::{PrintConv, TagDef, ValueConv},
};

static FILETYPE: TagDef = TagDef::new("FileType", "System", ValueConv::None, PrintConv::None);

#[test]
fn engine_pipeline_round_trips() {
  let v = apply(&FILETYPE, &TagValue::Str("AAC".into()), true);
  let mut m = Metadata::new("x.aac");
  m.push(Group::new("File", "System"), "FileType", v);

  let json = to_exiftool_json(&m);
  // serde emits standard scalars (no space after `:`); value-equivalent to the
  // expected document.
  assert!(
    json_equivalent(&json, r#"[{"SourceFile":"x.aac","System:FileType":"AAC"}]"#).is_ok(),
    "got: {json}"
  );
  // Our diff harness must consider identical output equivalent.
  assert!(json_equivalent(&json, &json).is_ok());
}
