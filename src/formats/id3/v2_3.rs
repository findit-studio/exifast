//! Faithful port of `%Image::ExifTool::ID3::v2_3` (ID3.pm:673-690) —
//! v2.3-only frames plus the `%id3v2_common` inclusion. 10-byte frame
//! header (`a4Nn`); length is a normal big-endian 32-bit integer.

// Golden-v2 Contract 3c (Phase C, slice w2c): panic-safety by construction.
// This module is a tag-table definition (no runtime buffer indexing); the deny
// is the file-level panic-safety contract for the slice.
#![deny(clippy::indexing_slicing)]

use crate::{
  formats::id3::v2_common::common_v2_3,
  tagtable::{PrintConv, TagDef, TagId, TagTable, ValueConv},
};

/// xtask-GENERATED `%ID3::v2_3` table (`cargo xtask gen-tables --kind tagdef
/// --module ID3::v2_3`) — DRIFT-GUARD ONLY (no wire). v2.3 frames emit through
/// the hand [`v2_3_get`] lookup (`%id3v2_common` + the v2.3-only frames) +
/// `text::make_tag_name` / SubDirectory routing; the generated `get` is a
/// parallel copy with no caller — `#[allow(dead_code)]`. The committed table
/// exists solely so `tests/xtask_check.rs` fails if a future ExifTool version
/// shifts `%v2_3`. (The hand layer is a SUPERSET — it also routes the
/// SubDirectory `GEOB`/`PRIV`/`SYLT` + `XOLY` frames `-listx` omits/flattens.)
#[path = "v2_3_generated.rs"]
#[allow(dead_code)]
mod generated;

// v2.3-only frames (ID3.pm:681-690).
static IPLS: TagDef = TagDef::new(
  "InvolvedPeople",
  "ID3v2_3",
  ValueConv::None,
  PrintConv::None,
);
static TDAT: TagDef = TagDef::new("Date", "ID3v2_3", ValueConv::None, PrintConv::None);
static TIME: TagDef = TagDef::new("Time", "ID3v2_3", ValueConv::None, PrintConv::None);
static TORY: TagDef = TagDef::new(
  "OriginalReleaseYear",
  "ID3v2_3",
  ValueConv::None,
  PrintConv::None,
);
static TRDA: TagDef = TagDef::new(
  "RecordingDates",
  "ID3v2_3",
  ValueConv::None,
  PrintConv::None,
);
static TSIZ: TagDef = TagDef::new("Size", "ID3v2_3", ValueConv::None, PrintConv::None);
static TYER: TagDef = TagDef::new("Year", "ID3v2_3", ValueConv::None, PrintConv::None);

fn v2_3_get(id: TagId) -> Option<&'static TagDef> {
  // common table first (faithful Perl `%id3v2_common` is included before the
  // v2.3-only entries in `%v2_3`, but those keys are unique so order is
  // immaterial for correctness — only for tidy lookup).
  if let Some(def) = common_v2_3(id) {
    return Some(def);
  }
  match id {
    TagId::Str("IPLS") => Some(&IPLS),
    TagId::Str("TDAT") => Some(&TDAT),
    TagId::Str("TIME") => Some(&TIME),
    TagId::Str("TORY") => Some(&TORY),
    TagId::Str("TRDA") => Some(&TRDA),
    TagId::Str("TSIZ") => Some(&TSIZ),
    TagId::Str("TYER") => Some(&TYER),
    _ => None,
  }
}

/// `%Image::ExifTool::ID3::v2_3` (ID3.pm:673).
pub static ID3V2_3_MAIN: TagTable = TagTable::new("ID3", v2_3_get);

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2c); the tests index fixed-layout data freely (an
// out-of-range index is a test-assertion failure, not a shipped panic), so the
// deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  #[test]
  fn v2_3_specific_and_common_resolve() {
    let g = ID3V2_3_MAIN.get();
    // Common.
    assert_eq!(g(TagId::Str("TIT2")).unwrap().name(), "Title");
    assert_eq!(g(TagId::Str("TIT2")).unwrap().group1(), "ID3v2_3");
    // v2.3-only.
    assert_eq!(g(TagId::Str("TYER")).unwrap().name(), "Year");
    assert_eq!(g(TagId::Str("TYER")).unwrap().group1(), "ID3v2_3");
    assert_eq!(g(TagId::Str("IPLS")).unwrap().name(), "InvolvedPeople");
    assert!(g(TagId::Str("TDRC")).is_none()); // v2.4-only
  }
}
