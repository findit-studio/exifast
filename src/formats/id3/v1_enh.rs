// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Faithful port of `%Image::ExifTool::ID3::v1_Enh` (ID3.pm:380-425). The
//! ID3v1 "Enhanced TAG" trailer is a 227-byte block that PRECEDES the
//! standard 128-byte ID3v1 TAG, magic `TAG+` (matched by Perl regex `^TAG+`
//! — i.e. `TAG` followed by one-or-more `G`s; the inline-detection in
//! `ID3.pm:1523` is `eBuff =~ /^TAG+/`, which the literal `TAG` prefix
//! satisfies).
//!
//! Group convention (ID3.pm:383): family-1 `"ID3v1_Enh"`, family-0 `"ID3"`
//! (inherited from `%ID3::Main` like ID3v1).
//!
//! F4 (Codex adversarial): the pre-fix engine detected the Enhanced TAG
//! (to size `DoneID3` correctly so APE.pm:169's footer scan walks past it)
//! but never PARSED the buffer — bundled emits 7 fields here, so the
//! `ape_with_enhancedtag_and_id3v1` golden had them hand-trimmed. This
//! module closes that hole; the only Enhanced-TAG tag still deferred is
//! `Composite:DateTimeOriginal`, which lives in the Composite engine and
//! is part of the broader accepted-deferral set.

use crate::{
  convert::{ConvContext, apply_ctx},
  formats::id3::text::convert_id3v1_text,
  tagtable::{PrintConv, PrintConvHash, PrintValue, TagDef, TagId, TagTable, ValueConv},
  value::{Group, Metadata, TagValue},
};
use smol_str::SmolStr;

// ID3.pm:402-411 — `Speed` PrintConv map.
const SPEED_ENTRIES: &[(&str, PrintValue)] = &[
  ("1", PrintValue::Str("Slow")),
  ("2", PrintValue::Str("Medium")),
  ("3", PrintValue::Str("Fast")),
  ("4", PrintValue::Str("Hardcore")),
];

// Static TagDefs for the 7 v1_Enh fields (ID3.pm:386-424). The "key" is
// the binary offset within the 227-byte TAG+ block.
static TITLE2: TagDef = TagDef::new(
  "Title2",
  "ID3v1_Enh",
  ValueConv::FuncCtx(convert_id3v1_text),
  PrintConv::None,
);
static ARTIST2: TagDef = TagDef::new(
  "Artist2",
  "ID3v1_Enh",
  ValueConv::FuncCtx(convert_id3v1_text),
  PrintConv::None,
);
static ALBUM2: TagDef = TagDef::new(
  "Album2",
  "ID3v1_Enh",
  ValueConv::FuncCtx(convert_id3v1_text),
  PrintConv::None,
);
// ID3.pm:402-411 — Speed is int8u with a 4-entry PrintConv. ValueConv-off
// emits the raw byte (1..=4); PrintConv-on emits "Slow"/"Medium"/"Fast"/
// "Hardcore" (an unmapped byte falls through to `Unknown ($n)` via the
// hash-PrintConv contract).
static SPEED: TagDef = TagDef::new(
  "Speed",
  "ID3v1_Enh",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(SPEED_ENTRIES)),
);
// ID3.pm:412-416 — Genre here is a STRING (`Format => 'string[30]'`), NOT
// a byte. The %genre lookup of ID3v1 does NOT apply.
static GENRE: TagDef = TagDef::new(
  "Genre",
  "ID3v1_Enh",
  ValueConv::FuncCtx(convert_id3v1_text),
  PrintConv::None,
);
// ID3.pm:417-420 — StartTime `string[6]`, no ValueConv.
static START_TIME: TagDef = TagDef::new("StartTime", "ID3v1_Enh", ValueConv::None, PrintConv::None);
// ID3.pm:421-424 — EndTime `string[6]`, no ValueConv.
static END_TIME: TagDef = TagDef::new("EndTime", "ID3v1_Enh", ValueConv::None, PrintConv::None);

fn v1_enh_get(id: TagId) -> Option<&'static TagDef> {
  match id {
    TagId::Int(4) => Some(&TITLE2),
    TagId::Int(64) => Some(&ARTIST2),
    TagId::Int(124) => Some(&ALBUM2),
    TagId::Int(184) => Some(&SPEED),
    TagId::Int(185) => Some(&GENRE),
    TagId::Int(215) => Some(&START_TIME),
    TagId::Int(221) => Some(&END_TIME),
    _ => None,
  }
}

/// `%Image::ExifTool::ID3::v1_Enh` (ID3.pm:380-425). family-0 group `"ID3"`
/// (inherited from `%ID3::Main`, ID3.pm:78).
pub static ID3V1_ENH_MAIN: TagTable = TagTable::new("ID3", v1_enh_get);

/// Truncate a fixed-width Latin-1 string field at the FIRST embedded NUL.
/// Faithful to ExifTool's `ReadValue` (ExifTool.pm:6296-6300) for
/// `$format eq 'string'`:
/// ```perl
/// $vals[0] =~ s/\0.*//s if $format eq 'string';
/// ```
/// (Duplicates the same helper from `id3::v1` — kept private here to avoid
/// reaching across modules; the two callers are independent.)
fn truncate_at_first_null(b: &[u8]) -> &[u8] {
  match b.iter().position(|&c| c == 0) {
    Some(p) => &b[..p],
    None => b,
  }
}

/// `ProcessBinaryData` over the 227-byte Enhanced TAG (`TAG+`) block.
/// Faithful transliteration of the ProcessID3 Enhanced-TAG dispatch
/// (ID3.pm:1618-1626):
///
/// ```perl
/// if ($id3Trailer{EnhancedTAG}) {
///     $et->VPrint(0, "ID3v1 Enhanced TAG:\n");
///     $tagTablePtr = GetTagTable('Image::ExifTool::ID3::v1_Enh');
///     $id3Trailer{DataPt} = $id3Trailer{EnhancedTAG};
///     $id3Trailer{DataPos} -= 227;
///     $id3Trailer{DirLen} = 227;
///     $et->ProcessDirectory(\%id3Trailer, $tagTablePtr);
/// }
/// ```
///
/// `data` MUST be exactly 227 bytes and begin with `b"TAG"` (the caller's
/// `ProcessID3` detects via `eBuff =~ /^TAG+/`, ID3.pm:1523).
pub fn process_id3v1_enh(data: &[u8], meta: &mut Metadata, print_conv_on: bool, ctx: &ConvContext) {
  // Caller (`ProcessID3`, ID3.pm:1523) guarantees a 227-byte TAG+ block.
  // Validate panic-free: any other shape is a faithful no-op (Perl
  // ProcessBinaryData over a too-short block would emit no tags).
  if data.len() != 227 || !data.starts_with(b"TAG") {
    return;
  }

  // Push a `Format => 'string[N]'` field through `truncate_at_first_null` +
  // `ConvertID3v1Text` (via the static `def`'s ValueConv). Faithful to the
  // ProcessBinaryData lift for `Format => 'string'` (ExifTool.pm:6299-6300:
  // `$vals[0] =~ s/\0.*//s if $format eq 'string';`).
  let push_text = |off: usize, len: usize, def: &'static TagDef, meta: &mut Metadata| {
    let raw = &data[off..off + len];
    let raw = truncate_at_first_null(raw);
    if raw.is_empty() {
      // Empty (all-NUL) field: bundled-Perl still emits the tag with an
      // empty string. Mirror that (consistent with `process_id3v1`).
      let out = apply_ctx(def, &TagValue::Bytes(Vec::new()), print_conv_on, ctx);
      meta.push(
        Group::new(ID3V1_ENH_MAIN.group0(), def.group1()),
        def.name(),
        out,
      );
      return;
    }
    let out = apply_ctx(def, &TagValue::Bytes(raw.to_vec()), print_conv_on, ctx);
    meta.push(
      Group::new(ID3V1_ENH_MAIN.group0(), def.group1()),
      def.name(),
      out,
    );
  };

  // ID3.pm:386-401 — Title2 (4..64), Artist2 (64..124), Album2 (124..184).
  push_text(4, 60, &TITLE2, meta);
  push_text(64, 60, &ARTIST2, meta);
  push_text(124, 60, &ALBUM2, meta);

  // ID3.pm:402-411 — Speed (184, int8u). PrintConv maps 1..=4 → labels;
  // ProcessBinaryData pushes the raw integer and the per-field PrintConv
  // resolves at apply-time. An unmapped byte (e.g. 0 or 5..=255) renders
  // as `Unknown ($n)` via the `PrintConvHash` fallback (same contract as
  // ID3v1's Genre byte).
  {
    let b = data[184] as i64;
    let out = apply_ctx(&SPEED, &TagValue::I64(b), print_conv_on, ctx);
    meta.push(
      Group::new(ID3V1_ENH_MAIN.group0(), SPEED.group1()),
      SPEED.name(),
      out,
    );
  }

  // ID3.pm:412-416 — Genre (185..215, string[30]) — UNLIKE ID3v1's Genre
  // (which is a byte), this is a STRING field.
  push_text(185, 30, &GENRE, meta);

  // ID3.pm:417-420 — StartTime (215..221, string[6]) — no ValueConv.
  // Year-style emission keeps the raw 6-char prefix (with trailing space
  // or NUL truncation), matching bundled (`"00:00 "` style).
  {
    let raw = truncate_at_first_null(&data[215..221]);
    let s: String = raw.iter().map(|&b| b as char).collect();
    meta.push(
      Group::new(ID3V1_ENH_MAIN.group0(), START_TIME.group1()),
      START_TIME.name(),
      TagValue::Str(SmolStr::new(s)),
    );
  }
  // ID3.pm:421-424 — EndTime (221..227, string[6]).
  {
    let raw = truncate_at_first_null(&data[221..227]);
    let s: String = raw.iter().map(|&b| b as char).collect();
    meta.push(
      Group::new(ID3V1_ENH_MAIN.group0(), END_TIME.group1()),
      END_TIME.name(),
      TagValue::Str(SmolStr::new(s)),
    );
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn make_enh_block(
    title2: &str,
    artist2: &str,
    album2: &str,
    speed: u8,
    genre: &str,
    start_time: &str,
    end_time: &str,
  ) -> Vec<u8> {
    let mut b = Vec::with_capacity(227);
    b.extend_from_slice(b"TAG+");
    let pad = |s: &str, n: usize| {
      let mut v: Vec<u8> = s.bytes().collect();
      v.resize(n, 0);
      v
    };
    b.extend_from_slice(&pad(title2, 60));
    b.extend_from_slice(&pad(artist2, 60));
    b.extend_from_slice(&pad(album2, 60));
    b.push(speed);
    b.extend_from_slice(&pad(genre, 30));
    b.extend_from_slice(&pad(start_time, 6));
    b.extend_from_slice(&pad(end_time, 6));
    assert_eq!(b.len(), 227);
    b
  }

  #[test]
  fn process_enh_emits_seven_fields_print_conv_on() {
    let block = make_enh_block(
      "EnhancedTitle",
      "EnhancedArtist",
      "EnhancedAlbum",
      2, /* Medium */
      "Rock",
      "00:00 ",
      "03:45 ",
    );
    let mut m = Metadata::new("x.mp3");
    let ctx = ConvContext::default();
    process_id3v1_enh(&block, &mut m, true, &ctx);
    let names: Vec<(&str, &str)> = m
      .tags_slice()
      .iter()
      .map(|t| (t.name(), t.group_ref().family1()))
      .collect();
    assert_eq!(
      names,
      vec![
        ("Title2", "ID3v1_Enh"),
        ("Artist2", "ID3v1_Enh"),
        ("Album2", "ID3v1_Enh"),
        ("Speed", "ID3v1_Enh"),
        ("Genre", "ID3v1_Enh"),
        ("StartTime", "ID3v1_Enh"),
        ("EndTime", "ID3v1_Enh"),
      ]
    );
    let speed = m.tags_slice().iter().find(|t| t.name() == "Speed").unwrap();
    assert_eq!(speed.value_ref(), &TagValue::Str("Medium".into()));
  }

  #[test]
  fn process_enh_speed_minus_n_is_raw_byte() {
    let block = make_enh_block("T", "A", "Al", 2, "Rock", "00:00 ", "03:45 ");
    let mut m = Metadata::new("x.mp3");
    let ctx = ConvContext::default();
    process_id3v1_enh(&block, &mut m, false, &ctx);
    let speed = m.tags_slice().iter().find(|t| t.name() == "Speed").unwrap();
    assert_eq!(speed.value_ref(), &TagValue::I64(2));
  }

  #[test]
  fn process_enh_non_227_block_is_no_op() {
    let mut m = Metadata::new("x.mp3");
    let ctx = ConvContext::default();
    process_id3v1_enh(b"TAG+\x00\x00", &mut m, true, &ctx);
    assert!(m.tags_slice().is_empty());
  }
}
