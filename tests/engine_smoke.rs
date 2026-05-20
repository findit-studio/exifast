//! End-to-end engine smoke: build Metadata via the public API, run a value
//! through the conversion runtime, serialize, and confirm our own jsondiff
//! treats the output as equivalent to itself. No format parser involved.
use exifast::{
  convert::apply,
  jsondiff::json_equivalent,
  serialize::to_exiftool_json,
  tagtable::{PrintConv, TagDef, ValueConv},
  Group, Metadata, TagValue,
};

static FILETYPE: TagDef = TagDef::new("FileType", "System", ValueConv::None, PrintConv::None);

#[test]
fn engine_pipeline_round_trips() {
  let v = apply(&FILETYPE, &TagValue::Str("AAC".into()), true);
  let mut m = Metadata::new("x.aac");
  m.push(Group::new("File", "System"), "FileType", v);

  let json = to_exiftool_json(&m);
  assert!(json.contains("\"System:FileType\": \"AAC\""));
  // Our diff harness must consider identical output equivalent.
  assert!(json_equivalent(&json, &json).is_ok());
}
