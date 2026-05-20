//! Faithful port of `%Image::ExifTool::ID3::v1` (ID3.pm:335-378). The
//! ID3v1 trailer is a fixed 128-byte block at the end of the file
//! beginning with the 3-byte literal `"TAG"`. Each row is a binary-table
//! entry (`PROCESS_PROC => ProcessBinaryData`, ID3.pm:336).
//!
//! Group convention (ID3.pm:337): family-1 `"ID3v1"`, family-0 `"ID3"`
//! (the parent `%Image::ExifTool::ID3::Main` table's group, ID3.pm:78).

use crate::{
  convert::{ConvContext, apply_ctx},
  formats::id3::text::convert_id3v1_text,
  tagtable::{PrintConv, PrintConvHash, PrintValue, TagDef, TagId, TagTable, ValueConv},
  value::{Group, Metadata, TagValue},
};
use smol_str::SmolStr;

// PrintConv for the Genre byte. Built by mapping every numbered entry in
// `super::genre::genre_name` to a `PrintValue::Str`. ID3v1 numeric range is
// 0..=255 but the table is sparse (192..=254 absent → `Unknown ($n)`).
// We seed the *defined* entries via a static slice; the rest fall to
// `Unknown ($val)` per the engine's hash-PrintConv fallback.
const GENRE_ENTRIES: &[(&str, PrintValue)] = &[
  ("0", PrintValue::Str("Blues")),
  ("1", PrintValue::Str("Classic Rock")),
  ("2", PrintValue::Str("Country")),
  ("3", PrintValue::Str("Dance")),
  ("4", PrintValue::Str("Disco")),
  ("5", PrintValue::Str("Funk")),
  ("6", PrintValue::Str("Grunge")),
  ("7", PrintValue::Str("Hip-Hop")),
  ("8", PrintValue::Str("Jazz")),
  ("9", PrintValue::Str("Metal")),
  ("10", PrintValue::Str("New Age")),
  ("11", PrintValue::Str("Oldies")),
  ("12", PrintValue::Str("Other")),
  ("13", PrintValue::Str("Pop")),
  ("14", PrintValue::Str("R&B")),
  ("15", PrintValue::Str("Rap")),
  ("16", PrintValue::Str("Reggae")),
  ("17", PrintValue::Str("Rock")),
  ("18", PrintValue::Str("Techno")),
  ("19", PrintValue::Str("Industrial")),
  ("20", PrintValue::Str("Alternative")),
  ("21", PrintValue::Str("Ska")),
  ("22", PrintValue::Str("Death Metal")),
  ("23", PrintValue::Str("Pranks")),
  ("24", PrintValue::Str("Soundtrack")),
  ("25", PrintValue::Str("Euro-Techno")),
  ("26", PrintValue::Str("Ambient")),
  ("27", PrintValue::Str("Trip-Hop")),
  ("28", PrintValue::Str("Vocal")),
  ("29", PrintValue::Str("Jazz+Funk")),
  ("30", PrintValue::Str("Fusion")),
  ("31", PrintValue::Str("Trance")),
  ("32", PrintValue::Str("Classical")),
  ("33", PrintValue::Str("Instrumental")),
  ("34", PrintValue::Str("Acid")),
  ("35", PrintValue::Str("House")),
  ("36", PrintValue::Str("Game")),
  ("37", PrintValue::Str("Sound Clip")),
  ("38", PrintValue::Str("Gospel")),
  ("39", PrintValue::Str("Noise")),
  ("40", PrintValue::Str("Alt. Rock")),
  ("41", PrintValue::Str("Bass")),
  ("42", PrintValue::Str("Soul")),
  ("43", PrintValue::Str("Punk")),
  ("44", PrintValue::Str("Space")),
  ("45", PrintValue::Str("Meditative")),
  ("46", PrintValue::Str("Instrumental Pop")),
  ("47", PrintValue::Str("Instrumental Rock")),
  ("48", PrintValue::Str("Ethnic")),
  ("49", PrintValue::Str("Gothic")),
  ("50", PrintValue::Str("Darkwave")),
  ("51", PrintValue::Str("Techno-Industrial")),
  ("52", PrintValue::Str("Electronic")),
  ("53", PrintValue::Str("Pop-Folk")),
  ("54", PrintValue::Str("Eurodance")),
  ("55", PrintValue::Str("Dream")),
  ("56", PrintValue::Str("Southern Rock")),
  ("57", PrintValue::Str("Comedy")),
  ("58", PrintValue::Str("Cult")),
  ("59", PrintValue::Str("Gangsta Rap")),
  ("60", PrintValue::Str("Top 40")),
  ("61", PrintValue::Str("Christian Rap")),
  ("62", PrintValue::Str("Pop/Funk")),
  ("63", PrintValue::Str("Jungle")),
  ("64", PrintValue::Str("Native American")),
  ("65", PrintValue::Str("Cabaret")),
  ("66", PrintValue::Str("New Wave")),
  ("67", PrintValue::Str("Psychedelic")),
  ("68", PrintValue::Str("Rave")),
  ("69", PrintValue::Str("Showtunes")),
  ("70", PrintValue::Str("Trailer")),
  ("71", PrintValue::Str("Lo-Fi")),
  ("72", PrintValue::Str("Tribal")),
  ("73", PrintValue::Str("Acid Punk")),
  ("74", PrintValue::Str("Acid Jazz")),
  ("75", PrintValue::Str("Polka")),
  ("76", PrintValue::Str("Retro")),
  ("77", PrintValue::Str("Musical")),
  ("78", PrintValue::Str("Rock & Roll")),
  ("79", PrintValue::Str("Hard Rock")),
  ("80", PrintValue::Str("Folk")),
  ("81", PrintValue::Str("Folk-Rock")),
  ("82", PrintValue::Str("National Folk")),
  ("83", PrintValue::Str("Swing")),
  ("84", PrintValue::Str("Fast-Fusion")),
  ("85", PrintValue::Str("Bebop")),
  ("86", PrintValue::Str("Latin")),
  ("87", PrintValue::Str("Revival")),
  ("88", PrintValue::Str("Celtic")),
  ("89", PrintValue::Str("Bluegrass")),
  ("90", PrintValue::Str("Avantgarde")),
  ("91", PrintValue::Str("Gothic Rock")),
  ("92", PrintValue::Str("Progressive Rock")),
  ("93", PrintValue::Str("Psychedelic Rock")),
  ("94", PrintValue::Str("Symphonic Rock")),
  ("95", PrintValue::Str("Slow Rock")),
  ("96", PrintValue::Str("Big Band")),
  ("97", PrintValue::Str("Chorus")),
  ("98", PrintValue::Str("Easy Listening")),
  ("99", PrintValue::Str("Acoustic")),
  ("100", PrintValue::Str("Humour")),
  ("101", PrintValue::Str("Speech")),
  ("102", PrintValue::Str("Chanson")),
  ("103", PrintValue::Str("Opera")),
  ("104", PrintValue::Str("Chamber Music")),
  ("105", PrintValue::Str("Sonata")),
  ("106", PrintValue::Str("Symphony")),
  ("107", PrintValue::Str("Booty Bass")),
  ("108", PrintValue::Str("Primus")),
  ("109", PrintValue::Str("Porn Groove")),
  ("110", PrintValue::Str("Satire")),
  ("111", PrintValue::Str("Slow Jam")),
  ("112", PrintValue::Str("Club")),
  ("113", PrintValue::Str("Tango")),
  ("114", PrintValue::Str("Samba")),
  ("115", PrintValue::Str("Folklore")),
  ("116", PrintValue::Str("Ballad")),
  ("117", PrintValue::Str("Power Ballad")),
  ("118", PrintValue::Str("Rhythmic Soul")),
  ("119", PrintValue::Str("Freestyle")),
  ("120", PrintValue::Str("Duet")),
  ("121", PrintValue::Str("Punk Rock")),
  ("122", PrintValue::Str("Drum Solo")),
  ("123", PrintValue::Str("A Cappella")),
  ("124", PrintValue::Str("Euro-House")),
  ("125", PrintValue::Str("Dance Hall")),
  ("126", PrintValue::Str("Goa")),
  ("127", PrintValue::Str("Drum & Bass")),
  ("128", PrintValue::Str("Club-House")),
  ("129", PrintValue::Str("Hardcore")),
  ("130", PrintValue::Str("Terror")),
  ("131", PrintValue::Str("Indie")),
  ("132", PrintValue::Str("BritPop")),
  ("133", PrintValue::Str("Afro-Punk")),
  ("134", PrintValue::Str("Polsk Punk")),
  ("135", PrintValue::Str("Beat")),
  ("136", PrintValue::Str("Christian Gangsta Rap")),
  ("137", PrintValue::Str("Heavy Metal")),
  ("138", PrintValue::Str("Black Metal")),
  ("139", PrintValue::Str("Crossover")),
  ("140", PrintValue::Str("Contemporary Christian")),
  ("141", PrintValue::Str("Christian Rock")),
  ("142", PrintValue::Str("Merengue")),
  ("143", PrintValue::Str("Salsa")),
  ("144", PrintValue::Str("Thrash Metal")),
  ("145", PrintValue::Str("Anime")),
  ("146", PrintValue::Str("JPop")),
  ("147", PrintValue::Str("Synthpop")),
  ("148", PrintValue::Str("Abstract")),
  ("149", PrintValue::Str("Art Rock")),
  ("150", PrintValue::Str("Baroque")),
  ("151", PrintValue::Str("Bhangra")),
  ("152", PrintValue::Str("Big Beat")),
  ("153", PrintValue::Str("Breakbeat")),
  ("154", PrintValue::Str("Chillout")),
  ("155", PrintValue::Str("Downtempo")),
  ("156", PrintValue::Str("Dub")),
  ("157", PrintValue::Str("EBM")),
  ("158", PrintValue::Str("Eclectic")),
  ("159", PrintValue::Str("Electro")),
  ("160", PrintValue::Str("Electroclash")),
  ("161", PrintValue::Str("Emo")),
  ("162", PrintValue::Str("Experimental")),
  ("163", PrintValue::Str("Garage")),
  ("164", PrintValue::Str("Global")),
  ("165", PrintValue::Str("IDM")),
  ("166", PrintValue::Str("Illbient")),
  ("167", PrintValue::Str("Industro-Goth")),
  ("168", PrintValue::Str("Jam Band")),
  ("169", PrintValue::Str("Krautrock")),
  ("170", PrintValue::Str("Leftfield")),
  ("171", PrintValue::Str("Lounge")),
  ("172", PrintValue::Str("Math Rock")),
  ("173", PrintValue::Str("New Romantic")),
  ("174", PrintValue::Str("Nu-Breakz")),
  ("175", PrintValue::Str("Post-Punk")),
  ("176", PrintValue::Str("Post-Rock")),
  ("177", PrintValue::Str("Psytrance")),
  ("178", PrintValue::Str("Shoegaze")),
  ("179", PrintValue::Str("Space Rock")),
  ("180", PrintValue::Str("Trop Rock")),
  ("181", PrintValue::Str("World Music")),
  ("182", PrintValue::Str("Neoclassical")),
  ("183", PrintValue::Str("Audiobook")),
  ("184", PrintValue::Str("Audio Theatre")),
  ("185", PrintValue::Str("Neue Deutsche Welle")),
  ("186", PrintValue::Str("Podcast")),
  ("187", PrintValue::Str("Indie Rock")),
  ("188", PrintValue::Str("G-Funk")),
  ("189", PrintValue::Str("Dubstep")),
  ("190", PrintValue::Str("Garage Rock")),
  ("191", PrintValue::Str("Psybient")),
  ("255", PrintValue::Str("None")),
];

// Static TagDefs for the 7 v1 fields (ID3.pm:339-377). The "key" is the
// binary offset within the 128-byte TAG block.
static TITLE: TagDef = TagDef::new(
  "Title",
  "ID3v1",
  ValueConv::FuncCtx(convert_id3v1_text),
  PrintConv::None,
);
static ARTIST: TagDef = TagDef::new(
  "Artist",
  "ID3v1",
  ValueConv::FuncCtx(convert_id3v1_text),
  PrintConv::None,
);
static ALBUM: TagDef = TagDef::new(
  "Album",
  "ID3v1",
  ValueConv::FuncCtx(convert_id3v1_text),
  PrintConv::None,
);
// ID3.pm:355-359 — Year is `Format => 'string[4]'`, no ValueConv (raw
// 4-char year, possibly all-spaces if missing).
static YEAR: TagDef = TagDef::new("Year", "ID3v1", ValueConv::None, PrintConv::None);
static COMMENT: TagDef = TagDef::new(
  "Comment",
  "ID3v1",
  ValueConv::FuncCtx(convert_id3v1_text),
  PrintConv::None,
);
// ID3.pm:365-370 — Track lives at offset 125 (int8u[2]) as the LAST 2
// bytes of the v1.0 Comment field; `RawConv => '($val =~ s/^0 // and $val)
// ? $val : undef'`. ProcessID3v1 emits this only when the leading byte at
// offset 125 is 0 AND the byte at 126 is non-zero (RawConv idiom: `$val`
// is the two-byte unpacked `int8u[2]` joined by space — e.g. "0 3").
// Faithful gate: see [`process_id3v1`].
static TRACK: TagDef = TagDef::new("Track", "ID3v1", ValueConv::None, PrintConv::None);
static GENRE: TagDef = TagDef::new(
  "Genre",
  "ID3v1",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(GENRE_ENTRIES)),
);

fn v1_get(id: TagId) -> Option<&'static TagDef> {
  match id {
    TagId::Int(3) => Some(&TITLE),
    TagId::Int(33) => Some(&ARTIST),
    TagId::Int(63) => Some(&ALBUM),
    TagId::Int(93) => Some(&YEAR),
    TagId::Int(97) => Some(&COMMENT),
    TagId::Int(125) => Some(&TRACK),
    TagId::Int(127) => Some(&GENRE),
    _ => None,
  }
}

/// `%Image::ExifTool::ID3::v1` (ID3.pm:335-378). family-0 group `"ID3"`
/// (`%Image::ExifTool::ID3::Main` parent, ID3.pm:78).
pub static ID3V1_MAIN: TagTable = TagTable::new("ID3", v1_get);

/// Truncate a fixed-width Latin-1 string field at the FIRST embedded NUL.
/// Faithful to ExifTool's `ReadValue` (ExifTool.pm:6296-6300) for
/// `$format eq 'string'`:
///
/// ```perl
/// $vals[0] = substr($$dataPt, $offset, $count * $len);
/// $vals[0] =~ s/\0.*//s if $format eq 'string';
/// ```
///
/// CRITICAL: bundled Perl uses `s/\0.*//s` (truncate at FIRST NUL, including
/// the NUL itself and everything after) — NOT trailing-NUL-strip. For a
/// v1.1 fixture where byte 125==0 and byte 126==track-number, the Comment
/// field at offset 97..127 contains `Comment\x00…\x00 0 <track>`; bundled
/// emits `"Comment"` (truncated at the first internal NUL) AND a separate
/// `Track` tag (from offset 125-126). Pinned by R2 regression
/// `process_id3v1_v1_1_comment_truncates_at_first_null`.
fn truncate_at_first_null(b: &[u8]) -> &[u8] {
  match b.iter().position(|&c| c == 0) {
    Some(p) => &b[..p],
    None => b,
  }
}

/// `ProcessBinaryData` over the 128-byte ID3v1 TAG block. Faithful
/// transliteration of the ProcessID3 ID3v1 path (ID3.pm:1612-1617):
///
/// ```perl
/// SetByteOrder('MM');
/// $tagTablePtr = GetTagTable('Image::ExifTool::ID3::v1');
/// $et->ProcessDirectory(\%id3Trailer, $tagTablePtr);
/// ```
///
/// `data` must be exactly 128 bytes and begin with `b"TAG"` (the magic;
/// the caller's `ProcessID3` matches `^TAG`, ID3.pm:1511).
pub fn process_id3v1(data: &[u8], meta: &mut Metadata, print_conv_on: bool, ctx: &ConvContext) {
  // Caller (`ProcessID3`, ID3.pm:1511) guarantees a 128-byte TAG block.
  // Validate panic-free: any other shape is a faithful no-op (Perl
  // ProcessBinaryData over a too-short block would emit no tags).
  if data.len() != 128 || !data.starts_with(b"TAG") {
    return;
  }
  // Title (3..33), Artist (33..63), Album (63..93), Year (93..97),
  // Comment (97..127), Genre (127). Track is the last 2 bytes of Comment
  // when byte 125 == 0 AND byte 126 != 0.
  // ID3.pm:338 `PRIORITY => 0`: ID3v1 tags may be overwritten by ID3v2;
  // but ID3v2 is pushed BEFORE ID3v1 in ProcessID3 (header processed
  // first, then trailer), so the order is correct for our push-based
  // serializer.

  let push_text = |off: usize, len: usize, def: &'static TagDef, meta: &mut Metadata| {
    let raw = &data[off..off + len];
    let raw = truncate_at_first_null(raw);
    if raw.is_empty() {
      // Bundled-Perl: an all-null field emits an empty string. Observed
      // on the synthetic v1.0 file; mirror it.
      let out = apply_ctx(def, &TagValue::Bytes(Vec::new()), print_conv_on, ctx);
      meta.push(
        Group::new(ID3V1_MAIN.group0(), def.group1()),
        def.name(),
        out,
      );
      return;
    }
    let out = apply_ctx(def, &TagValue::Bytes(raw.to_vec()), print_conv_on, ctx);
    meta.push(
      Group::new(ID3V1_MAIN.group0(), def.group1()),
      def.name(),
      out,
    );
  };

  // Title.
  push_text(3, 30, &TITLE, meta);
  // Artist.
  push_text(33, 30, &ARTIST, meta);
  // Album.
  push_text(63, 30, &ALBUM, meta);
  // Year (string[4], no ConvertID3v1Text). Bundled `ReadValue` for
  // `Format => 'string[N]'` (ExifTool.pm:6299-6300) truncates at the
  // FIRST embedded NUL (`s/\0.*//s`). Codex R3-F2 caught my prior path
  // which kept post-NUL bytes — fixed by routing Year through
  // `truncate_at_first_null` then Latin-1 decoding the prefix.
  {
    let raw = truncate_at_first_null(&data[93..97]);
    let s: String = raw.iter().map(|&b| b as char).collect();
    // Year may parse as numeric (e.g. "2003"); ExifTool keeps it as a
    // string per its `Format => 'string[4]'`, but the serializer's
    // number gate re-promotes pure-digit strings to JSON numbers — match
    // bundled output by emitting the string literal here.
    meta.push(
      Group::new(ID3V1_MAIN.group0(), YEAR.group1()),
      YEAR.name(),
      TagValue::Str(SmolStr::new(s)),
    );
  }
  // Comment + Track (ID3v1.1).
  {
    let raw_comment = &data[97..127];
    // ID3v1.1 Track lives at the last 2 bytes of the v1.0 Comment field
    // (ID3.pm:365-370): `Format => 'int8u[2]', RawConv => '($val =~ s/^0
    //  // and $val) ? $val : undef'`. ExifTool's ProcessBinaryData
    // independently emits BOTH Comment (offset 97, full 30 bytes) AND
    // Track (offset 125, 2 bytes) — they overlap; the Track RawConv
    // succeeds iff data[125]==0 && data[126]!=0 (i.e. the v1.1 layout).
    let comment_bytes = truncate_at_first_null(raw_comment);
    let out = apply_ctx(
      &COMMENT,
      &TagValue::Bytes(comment_bytes.to_vec()),
      print_conv_on,
      ctx,
    );
    meta.push(
      Group::new(ID3V1_MAIN.group0(), COMMENT.group1()),
      COMMENT.name(),
      out,
    );
    // Track: RawConv `$val =~ s/^0 //` — succeeds iff $val[0]==0 byte
    // (interp'd as ASCII '0' after `unpack` to int8u joined w/ space?).
    // Re-read ID3.pm:367 `Format => 'int8u[2]'` — Perl's int8u[2] unpack
    // yields TWO integers; ExifTool then joins them with a SPACE for the
    // raw `$val` string (`PrintConv`'s `$val =~ s/^0 //`). So the raw
    // val is e.g. `"0 3"` for track 3 in v1.1. The RawConv strips the
    // leading `"0 "` and returns the remaining string `"3"`; if the
    // first byte is NOT 0, the regex misses and returns undef → no tag.
    if data[125] == 0 && data[126] != 0 {
      let track_n = data[126] as i64;
      meta.push(
        Group::new(ID3V1_MAIN.group0(), TRACK.group1()),
        TRACK.name(),
        TagValue::I64(track_n),
      );
    }
  }
  // Genre.
  {
    let g = data[127] as i64;
    // Faithful: ProcessBinaryData pushes the raw integer; PrintConv looks
    // it up in `%genre` (our PrintConvHash). For `255 => 'None'` and
    // sparse misses (192..=254) the hash fallback yields `"Unknown ($n)"`.
    // We DO NOT pre-check `genre::genre_name` — the PrintConvHash already
    // implements ExifTool's lookup faithfully (the static GENRE_ENTRIES table
    // above mirrors every numbered row in `genre.rs`).
    let out = apply_ctx(&GENRE, &TagValue::I64(g), print_conv_on, ctx);
    meta.push(
      Group::new(ID3V1_MAIN.group0(), GENRE.group1()),
      GENRE.name(),
      out,
    );
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn make_tag_block(
    title: &str,
    artist: &str,
    album: &str,
    year: &str,
    comment: &str,
    track: Option<u8>,
    genre: u8,
  ) -> Vec<u8> {
    let mut b = Vec::with_capacity(128);
    b.extend_from_slice(b"TAG");
    let pad = |s: &str, n: usize| {
      let mut v: Vec<u8> = s.bytes().collect();
      v.resize(n, 0);
      v
    };
    b.extend_from_slice(&pad(title, 30));
    b.extend_from_slice(&pad(artist, 30));
    b.extend_from_slice(&pad(album, 30));
    // Year as 4 ASCII chars (no null trim).
    let mut yb = [b' '; 4];
    for (i, ch) in year.bytes().take(4).enumerate() {
      yb[i] = ch;
    }
    b.extend_from_slice(&yb);
    // Comment + maybe Track (v1.1 layout).
    match track {
      Some(t) => {
        let mut c = pad(comment, 28);
        c.push(0); // byte 125 = 0 (v1.1 sentinel)
        c.push(t); // byte 126 = track
        b.extend_from_slice(&c);
      }
      None => {
        let c = pad(comment, 30);
        b.extend_from_slice(&c);
      }
    }
    b.push(genre);
    assert_eq!(b.len(), 128);
    b
  }

  #[test]
  fn process_id3v1_emits_expected_tags() {
    let data = make_tag_block(
      "Title", "Artist", "Album", "2003", "Comment", None, 7, /* Hip-Hop */
    );
    let mut m = Metadata::new("x.mp3");
    let ctx = ConvContext::default();
    process_id3v1(&data, &mut m, true, &ctx);
    let names: Vec<(&str, &str, TagValue)> = m
      .tags()
      .iter()
      .map(|t| (t.group().family1(), t.name(), t.value().clone()))
      .collect();
    assert_eq!(
      names,
      vec![
        ("ID3v1", "Title", TagValue::Str("Title".into())),
        ("ID3v1", "Artist", TagValue::Str("Artist".into())),
        ("ID3v1", "Album", TagValue::Str("Album".into())),
        ("ID3v1", "Year", TagValue::Str("2003".into())),
        ("ID3v1", "Comment", TagValue::Str("Comment".into())),
        ("ID3v1", "Genre", TagValue::Str("Hip-Hop".into())),
      ]
    );
  }

  #[test]
  fn process_id3v1_track_emitted_when_v1_1_layout() {
    let data = make_tag_block(
      "T",
      "A",
      "Al",
      "2003",
      "Cmt",
      Some(5), /* track */
      7,       /* Hip-Hop */
    );
    let mut m = Metadata::new("x.mp3");
    let ctx = ConvContext::default();
    process_id3v1(&data, &mut m, true, &ctx);
    let track = m.tags().iter().find(|t| t.name() == "Track");
    assert!(track.is_some(), "v1.1 Track must be emitted");
    assert_eq!(track.unwrap().value(), &TagValue::I64(5));
  }

  #[test]
  fn process_id3v1_minus_n_emits_genre_as_byte() {
    // PrintConv off → raw byte value (i64 7) instead of "Hip-Hop".
    let data = make_tag_block("T", "A", "Al", "2003", "Cmt", None, 7);
    let mut m = Metadata::new("x.mp3");
    let ctx = ConvContext::default();
    process_id3v1(&data, &mut m, false, &ctx);
    let g = m.tags().iter().find(|t| t.name() == "Genre").unwrap();
    assert_eq!(g.value(), &TagValue::I64(7));
  }

  #[test]
  fn process_id3v1_unknown_genre_byte_yields_unknown_fallback() {
    // Genre 200 is sparse — ExifTool hash lookup misses → "Unknown (200)".
    let data = make_tag_block("T", "A", "Al", "2003", "Cmt", None, 200);
    let mut m = Metadata::new("x.mp3");
    let ctx = ConvContext::default();
    process_id3v1(&data, &mut m, true, &ctx);
    let g = m.tags().iter().find(|t| t.name() == "Genre").unwrap();
    assert_eq!(g.value(), &TagValue::Str("Unknown (200)".into()));
  }

  #[test]
  fn process_id3v1_year_truncates_at_first_null() {
    // R3-F2: bundled `ReadValue` for `Format => 'string[N]'` (ExifTool.pm:
    // 6299-6300) truncates at the FIRST embedded NUL. A fixture where
    // Year bytes are `"20\0X"` must emit Year `"20"` (NOT `"20X"`).
    let mut block = make_tag_block("T", "A", "Al", "    ", "Cmt", None, 7);
    // Patch Year (offset 93-96) to `"20\0X"`.
    block[93] = b'2';
    block[94] = b'0';
    block[95] = 0;
    block[96] = b'X';
    let mut m = Metadata::new("x.mp3");
    let ctx = ConvContext::default();
    process_id3v1(&block, &mut m, true, &ctx);
    let year = m.tags().iter().find(|t| t.name() == "Year").unwrap();
    assert_eq!(year.value(), &TagValue::Str("20".into()));
  }

  #[test]
  fn process_id3v1_v1_1_comment_truncates_at_first_null() {
    // R2 regression: bundled `ReadValue` (ExifTool.pm:6299-6300) does
    // `$val =~ s/\0.*//s` for `Format => 'string'` — truncates at the
    // FIRST embedded NUL. ID3v1.1's Comment field is `string[30]` and
    // overlaps Track at offset 125-126; for a v1.1 fixture the layout
    // is `<comment>\0…<sentinel-0><track>`, so bundled emits the
    // pre-NUL comment AND the separate Track tag. My previous
    // `trim_trailing_nulls` kept the embedded NUL + track byte in the
    // comment value — that was a Codex R2-F2 bug.
    let data = make_tag_block("T", "A", "Al", "2003", "Cmt", Some(7), 7);
    // Comment field bytes (offset 97..127):
    // "Cmt" + 25 nulls + "\0\x07" (Track sentinel + track 7)
    // After R2 fix: comment value = "Cmt" (truncated at first NUL).
    let mut m = Metadata::new("x.mp3");
    let ctx = ConvContext::default();
    process_id3v1(&data, &mut m, true, &ctx);
    let cmt = m.tags().iter().find(|t| t.name() == "Comment").unwrap();
    assert_eq!(cmt.value(), &TagValue::Str("Cmt".into()));
    let tr = m.tags().iter().find(|t| t.name() == "Track").unwrap();
    assert_eq!(tr.value(), &TagValue::I64(7));
  }

  #[test]
  fn process_id3v1_non_128_byte_block_is_no_op() {
    let mut m = Metadata::new("x.mp3");
    let ctx = ConvContext::default();
    // <128 bytes: silently no-op (real callers gate by file length).
    process_id3v1(b"TAG\x00", &mut m, true, &ctx);
    assert!(m.tags().is_empty());
  }
}
