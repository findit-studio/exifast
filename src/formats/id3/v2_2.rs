//! Faithful port of `%Image::ExifTool::ID3::v2_2` (ID3.pm:428-524).
//! ID3v2.2 (the iTunes 5.0 variant). 6-byte frame header (`a3Cn`).
//!
//! Group convention (ID3.pm:430): family-1 `"ID3v2_2"`, family-0 `"ID3"`.

// Golden-v2 Contract 3c (Phase C, slice w2c): panic-safety by construction.
// This module is a tag-table definition (no runtime buffer indexing); the deny
// is the file-level panic-safety contract for the slice.
#![deny(clippy::indexing_slicing)]

use crate::{
  formats::id3::{picture_type::PICTURE_TYPE_HASH, text},
  tagtable::{PrintConv, PrintConvHash, PrintValue, TagDef, TagId, TagTable, ValueConv},
};

// Every TagDef in this module shares family-0 "ID3" / family-1 "ID3v2_2".

macro_rules! text_tag {
  ($name:expr) => {
    TagDef::new($name, "ID3v2_2", ValueConv::None, PrintConv::None)
  };
}

// --- text/URL/etc. frames (most have only a Name) ---

static CNT: TagDef = text_tag!("PlayCounter");
static COM: TagDef = text_tag!("Comment");
static IPL: TagDef = text_tag!("InvolvedPeople");
static PIC: TagDef = text_tag!("Picture");
static PIC_1: TagDef = text_tag!("PictureFormat");
static PIC_2: TagDef = TagDef::new(
  "PictureType",
  "ID3v2_2",
  ValueConv::None,
  PrintConv::Hash(PICTURE_TYPE_HASH),
);
static PIC_3: TagDef = text_tag!("PictureDescription");
static POP: TagDef = TagDef::new(
  "Popularimeter",
  "ID3v2_2",
  ValueConv::None,
  PrintConv::Func(text::print_popularimeter),
);
static SLT: TagDef = text_tag!("SynLyrics");
static TAL: TagDef = text_tag!("Album");
static TBP: TagDef = text_tag!("BeatsPerMinute");
static TCM: TagDef = text_tag!("Composer");
static TCO: TagDef = TagDef::new(
  "Genre",
  "ID3v2_2",
  ValueConv::None,
  PrintConv::Func(text::print_genre),
);
static TCP: TagDef = TagDef::new(
  "Compilation",
  "ID3v2_2",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("0", PrintValue::Str("No")),
    ("1", PrintValue::Str("Yes")),
  ])),
);
static TCR: TagDef = text_tag!("Copyright");
static TDA: TagDef = text_tag!("Date");
static TDY: TagDef = text_tag!("PlaylistDelay");
static TEN: TagDef = text_tag!("EncodedBy");
static TFT: TagDef = text_tag!("FileType");
static TIM: TagDef = text_tag!("Time");
static TKE: TagDef = text_tag!("InitialKey");
static TLA: TagDef = text_tag!("Language");
static TLE: TagDef = text_tag!("Length");
static TMT: TagDef = text_tag!("Media");
static TOA: TagDef = text_tag!("OriginalArtist");
static TOF: TagDef = text_tag!("OriginalFileName");
static TOL: TagDef = text_tag!("OriginalLyricist");
static TOR: TagDef = text_tag!("OriginalReleaseYear");
static TOT: TagDef = text_tag!("OriginalAlbum");
static TP1: TagDef = text_tag!("Artist");
static TP2: TagDef = text_tag!("Band");
static TP3: TagDef = text_tag!("Conductor");
static TP4: TagDef = text_tag!("InterpretedBy");
static TPA: TagDef = text_tag!("PartOfSet");
static TPB: TagDef = text_tag!("Publisher");
static TRC: TagDef = text_tag!("ISRC");
static TRD: TagDef = text_tag!("RecordingDates");
static TRK: TagDef = text_tag!("Track");
static TSI: TagDef = text_tag!("Size");
static TSS: TagDef = text_tag!("EncoderSettings");
static TT1: TagDef = text_tag!("Grouping");
static TT2: TagDef = text_tag!("Title");
static TT3: TagDef = text_tag!("Subtitle");
static TXT: TagDef = text_tag!("Lyricist");
static TXX: TagDef = text_tag!("UserDefinedText");
static TYE: TagDef = text_tag!("Year");
static ULT: TagDef = text_tag!("Lyrics");
static WAF: TagDef = text_tag!("FileURL");
static WAR: TagDef = text_tag!("ArtistURL");
static WAS: TagDef = text_tag!("SourceURL");
static WCM: TagDef = text_tag!("CommercialURL");
static WCP: TagDef = text_tag!("CopyrightURL");
static WPB: TagDef = text_tag!("PublisherURL");
static WXX: TagDef = text_tag!("UserDefinedURL");
// ID3.pm:513-524 iTunes 10.5 extras + non-standard.
static RVA: TagDef = text_tag!("RelativeVolumeAdjustment");
static TST: TagDef = text_tag!("TitleSortOrder");
static TSA: TagDef = text_tag!("AlbumSortOrder");
static TSP: TagDef = text_tag!("PerformerSortOrder");
static TS2: TagDef = text_tag!("AlbumArtistSortOrder");
static TSC: TagDef = text_tag!("ComposerSortOrder");
static ITU: TagDef = text_tag!("iTunesU");
static PCS: TagDef = text_tag!("Podcast");
static GP1: TagDef = text_tag!("Grouping");
static MVN: TagDef = text_tag!("MovementName");
static MVI: TagDef = text_tag!("MovementNumber");

fn v2_2_get(id: TagId) -> Option<&'static TagDef> {
  match id {
    TagId::Str("CNT") => Some(&CNT),
    TagId::Str("COM") => Some(&COM),
    TagId::Str("IPL") => Some(&IPL),
    TagId::Str("PIC") => Some(&PIC),
    TagId::Str("PIC-1") => Some(&PIC_1),
    TagId::Str("PIC-2") => Some(&PIC_2),
    TagId::Str("PIC-3") => Some(&PIC_3),
    TagId::Str("POP") => Some(&POP),
    TagId::Str("SLT") => Some(&SLT),
    TagId::Str("TAL") => Some(&TAL),
    TagId::Str("TBP") => Some(&TBP),
    TagId::Str("TCM") => Some(&TCM),
    TagId::Str("TCO") => Some(&TCO),
    TagId::Str("TCP") => Some(&TCP),
    TagId::Str("TCR") => Some(&TCR),
    TagId::Str("TDA") => Some(&TDA),
    TagId::Str("TDY") => Some(&TDY),
    TagId::Str("TEN") => Some(&TEN),
    TagId::Str("TFT") => Some(&TFT),
    TagId::Str("TIM") => Some(&TIM),
    TagId::Str("TKE") => Some(&TKE),
    TagId::Str("TLA") => Some(&TLA),
    TagId::Str("TLE") => Some(&TLE),
    TagId::Str("TMT") => Some(&TMT),
    TagId::Str("TOA") => Some(&TOA),
    TagId::Str("TOF") => Some(&TOF),
    TagId::Str("TOL") => Some(&TOL),
    TagId::Str("TOR") => Some(&TOR),
    TagId::Str("TOT") => Some(&TOT),
    TagId::Str("TP1") => Some(&TP1),
    TagId::Str("TP2") => Some(&TP2),
    TagId::Str("TP3") => Some(&TP3),
    TagId::Str("TP4") => Some(&TP4),
    TagId::Str("TPA") => Some(&TPA),
    TagId::Str("TPB") => Some(&TPB),
    TagId::Str("TRC") => Some(&TRC),
    TagId::Str("TRD") => Some(&TRD),
    TagId::Str("TRK") => Some(&TRK),
    TagId::Str("TSI") => Some(&TSI),
    TagId::Str("TSS") => Some(&TSS),
    TagId::Str("TT1") => Some(&TT1),
    TagId::Str("TT2") => Some(&TT2),
    TagId::Str("TT3") => Some(&TT3),
    TagId::Str("TXT") => Some(&TXT),
    TagId::Str("TXX") => Some(&TXX),
    TagId::Str("TYE") => Some(&TYE),
    TagId::Str("ULT") => Some(&ULT),
    TagId::Str("WAF") => Some(&WAF),
    TagId::Str("WAR") => Some(&WAR),
    TagId::Str("WAS") => Some(&WAS),
    TagId::Str("WCM") => Some(&WCM),
    TagId::Str("WCP") => Some(&WCP),
    TagId::Str("WPB") => Some(&WPB),
    TagId::Str("WXX") => Some(&WXX),
    TagId::Str("RVA") => Some(&RVA),
    TagId::Str("TST") => Some(&TST),
    TagId::Str("TSA") => Some(&TSA),
    TagId::Str("TSP") => Some(&TSP),
    TagId::Str("TS2") => Some(&TS2),
    TagId::Str("TSC") => Some(&TSC),
    TagId::Str("ITU") => Some(&ITU),
    TagId::Str("PCS") => Some(&PCS),
    TagId::Str("GP1") => Some(&GP1),
    TagId::Str("MVN") => Some(&MVN),
    TagId::Str("MVI") => Some(&MVI),
    _ => None,
  }
}

/// `%Image::ExifTool::ID3::v2_2` (ID3.pm:428).
pub static ID3V2_2_MAIN: TagTable = TagTable::new("ID3", v2_2_get);

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2c); the tests index fixed-layout data freely (an
// out-of-range index is a test-assertion failure, not a shipped panic), so the
// deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;

  #[test]
  fn v2_2_dispatch_spot_checks() {
    let g = ID3V2_2_MAIN.get();
    assert_eq!(g(TagId::Str("TT2")).unwrap().name(), "Title");
    assert_eq!(g(TagId::Str("TP1")).unwrap().name(), "Artist");
    assert_eq!(g(TagId::Str("TCO")).unwrap().name(), "Genre");
    assert_eq!(g(TagId::Str("PIC")).unwrap().name(), "Picture");
    assert_eq!(g(TagId::Str("PIC-1")).unwrap().name(), "PictureFormat");
    assert_eq!(g(TagId::Str("PIC-2")).unwrap().name(), "PictureType");
    assert_eq!(g(TagId::Str("PIC-3")).unwrap().name(), "PictureDescription");
    assert!(g(TagId::Str("XXX")).is_none());
    // Numeric ids never match this string-keyed table.
    assert!(g(TagId::Int(0x42)).is_none());
    assert_eq!(ID3V2_2_MAIN.group0(), "ID3");
  }
}
