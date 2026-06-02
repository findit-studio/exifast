//! Faithful port of `%Image::ExifTool::ID3::v2_4` (ID3.pm:693-718) —
//! v2.4-only frames plus the `%id3v2_common` inclusion. 10-byte frame
//! header (`a4Nn`); length is a "sync-safe" 28-bit integer
//! (`UnSyncSafe`), but ProcessID3v2 has an iTunes-bug heuristic that
//! falls back to a normal int32 if sync-safe doesn't match the next ID.

// Golden-v2 Contract 3c (Phase C, slice w2c): panic-safety by construction.
// This module is a tag-table definition (no runtime buffer indexing); the deny
// is the file-level panic-safety contract for the slice.
#![deny(clippy::indexing_slicing)]

use crate::{
  formats::id3::{text::convert_xmp_date, v2_common::common_v2_4},
  tagtable::{PrintConv, TagDef, TagId, TagTable, ValueConv},
};

// v2.4-only frames (ID3.pm:702-717).
static RVA2: TagDef = TagDef::new(
  "RelativeVolumeAdjustment",
  "ID3v2_4",
  ValueConv::None,
  PrintConv::None,
);
// ID3.pm:66-69, 705-709 — every v2.4 date/time frame has `%dateTimeConv`:
//   ValueConv => 'require Image::ExifTool::XMP;
//                 Image::ExifTool::XMP::ConvertXMPDate($val)'
//   PrintConv => '$self->ConvertDateTime($val)'
// The ValueConv reformats `2024-05-19T12:34:56` → `2024:05:19 12:34:56`
// (XMP → EXIF date separators). The PrintConv is `ConvertDateTime` which
// w/o a `DateFormat` option returns its input unchanged — pass-through
// (D11 forward item: when an options layer adds DateFormat support,
// promote to `PrintConv::FuncCtx`; today the no-options default produces
// the same output as no PrintConv).
static TDEN: TagDef = TagDef::new(
  "EncodingTime",
  "ID3v2_4",
  ValueConv::Func(convert_xmp_date),
  PrintConv::None,
);
static TDOR: TagDef = TagDef::new(
  "OriginalReleaseTime",
  "ID3v2_4",
  ValueConv::Func(convert_xmp_date),
  PrintConv::None,
);
static TDRC: TagDef = TagDef::new(
  "RecordingTime",
  "ID3v2_4",
  ValueConv::Func(convert_xmp_date),
  PrintConv::None,
);
static TDRL: TagDef = TagDef::new(
  "ReleaseTime",
  "ID3v2_4",
  ValueConv::Func(convert_xmp_date),
  PrintConv::None,
);
static TDTG: TagDef = TagDef::new(
  "TaggingTime",
  "ID3v2_4",
  ValueConv::Func(convert_xmp_date),
  PrintConv::None,
);
static TIPL: TagDef = TagDef::new(
  "InvolvedPeople",
  "ID3v2_4",
  ValueConv::None,
  PrintConv::None,
);
static TMCL: TagDef = TagDef::new(
  "MusicianCredits",
  "ID3v2_4",
  ValueConv::None,
  PrintConv::None,
);
static TMOO: TagDef = TagDef::new("Mood", "ID3v2_4", ValueConv::None, PrintConv::None);
static TPRO: TagDef = TagDef::new(
  "ProducedNotice",
  "ID3v2_4",
  ValueConv::None,
  PrintConv::None,
);
static TSOA: TagDef = TagDef::new(
  "AlbumSortOrder",
  "ID3v2_4",
  ValueConv::None,
  PrintConv::None,
);
static TSOP: TagDef = TagDef::new(
  "PerformerSortOrder",
  "ID3v2_4",
  ValueConv::None,
  PrintConv::None,
);
static TSOT: TagDef = TagDef::new(
  "TitleSortOrder",
  "ID3v2_4",
  ValueConv::None,
  PrintConv::None,
);
static TSST: TagDef = TagDef::new("SetSubtitle", "ID3v2_4", ValueConv::None, PrintConv::None);

fn v2_4_get(id: TagId) -> Option<&'static TagDef> {
  if let Some(def) = common_v2_4(id) {
    return Some(def);
  }
  match id {
    TagId::Str("RVA2") => Some(&RVA2),
    TagId::Str("TDEN") => Some(&TDEN),
    TagId::Str("TDOR") => Some(&TDOR),
    TagId::Str("TDRC") => Some(&TDRC),
    TagId::Str("TDRL") => Some(&TDRL),
    TagId::Str("TDTG") => Some(&TDTG),
    TagId::Str("TIPL") => Some(&TIPL),
    TagId::Str("TMCL") => Some(&TMCL),
    TagId::Str("TMOO") => Some(&TMOO),
    TagId::Str("TPRO") => Some(&TPRO),
    TagId::Str("TSOA") => Some(&TSOA),
    TagId::Str("TSOP") => Some(&TSOP),
    TagId::Str("TSOT") => Some(&TSOT),
    TagId::Str("TSST") => Some(&TSST),
    _ => None,
  }
}

/// `%Image::ExifTool::ID3::v2_4` (ID3.pm:693).
pub static ID3V2_4_MAIN: TagTable = TagTable::new("ID3", v2_4_get);

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2c); the tests index fixed-layout data freely (an
// out-of-range index is a test-assertion failure, not a shipped panic), so the
// deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  #[test]
  fn v2_4_specific_and_common_resolve() {
    let g = ID3V2_4_MAIN.get();
    assert_eq!(g(TagId::Str("TIT2")).unwrap().name(), "Title");
    assert_eq!(g(TagId::Str("TIT2")).unwrap().group1(), "ID3v2_4");
    assert_eq!(g(TagId::Str("TDRC")).unwrap().name(), "RecordingTime");
    assert_eq!(
      g(TagId::Str("RVA2")).unwrap().name(),
      "RelativeVolumeAdjustment"
    );
    assert!(g(TagId::Str("TYER")).is_none()); // v2.3-only
  }
}
