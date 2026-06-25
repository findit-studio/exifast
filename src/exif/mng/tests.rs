// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Unit tests for the MNG/JNG sub-table reader ([`super`]).

use super::*;
use crate::emit::{ConvMode, EmitOptions, Taggable};
use crate::value::TagValue;

/// Render a `MngMeta` to a `(name, value)` list for the given conv mode.
fn render(meta: &MngMeta, print_conv: bool) -> Vec<(String, TagValue)> {
  let mode = ConvMode::from_print_conv(print_conv);
  meta
    .tags(EmitOptions::g1(mode, false))
    .map(|t| (t.tag().name().to_string(), t.tag().value_ref().clone()))
    .collect()
}

/// Render a `MngMeta` to a `(family1, name, value)` list — the trailer-group
/// tests need the family-1 group (`MNG` vs `Trailer`), which [`render`] drops.
fn render_g1(meta: &MngMeta, print_conv: bool) -> Vec<(String, String, TagValue)> {
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

/// A leaf with the given name, asserting it is present with the given string value.
fn assert_str(list: &[(String, TagValue)], name: &str, want: &str) {
  let got = list
    .iter()
    .find(|(n, _)| n == name)
    .unwrap_or_else(|| panic!("missing leaf {name}: {list:?}"));
  assert_eq!(
    got.1,
    TagValue::Str(want.into()),
    "leaf {name} value mismatch"
  );
}

/// A leaf asserting a u64 value.
fn assert_u64(list: &[(String, TagValue)], name: &str, want: u64) {
  let got = list
    .iter()
    .find(|(n, _)| n == name)
    .unwrap_or_else(|| panic!("missing leaf {name}: {list:?}"));
  assert_eq!(got.1, TagValue::U64(want), "leaf {name} value mismatch");
}

#[test]
fn mhdr_full_with_simplicity_profile() {
  // MHDR FORMAT int32u: 7 int32u (28 bytes). SimplicityProfile @ index 6 →
  // sprintf 0x%.8x (-j) / raw (-n).
  let mut m = MngMeta::new();
  let mut body = Vec::new();
  for v in [100u32, 200, 30, 5, 10, 0, 1] {
    body.extend_from_slice(&v.to_be_bytes());
  }
  assert!(m.process_chunk(b"MHDR", &body, false));
  let pj = render(&m, true);
  assert_u64(&pj, "ImageWidth", 100);
  assert_u64(&pj, "ImageHeight", 200);
  assert_u64(&pj, "TicksPerSecond", 30);
  assert_str(&pj, "SimplicityProfile", "0x00000001");
  // -n: SimplicityProfile is the raw int.
  let pn = render(&m, false);
  assert_u64(&pn, "SimplicityProfile", 1);
}

#[test]
fn mhdr_truncated_per_field_availability() {
  // A 12-byte MHDR (3 int32u): only ImageWidth/Height/TicksPerSecond fit.
  let mut m = MngMeta::new();
  let mut body = Vec::new();
  for v in [50u32, 60, 24] {
    body.extend_from_slice(&v.to_be_bytes());
  }
  assert!(m.process_chunk(b"MHDR", &body, false));
  let pj = render(&m, true);
  assert_eq!(pj.len(), 3, "only 3 leaves fit: {pj:?}");
  assert_u64(&pj, "ImageWidth", 50);
  assert_u64(&pj, "TicksPerSecond", 24);
  assert!(
    pj.iter().all(|(n, _)| n != "SimplicityProfile"),
    "SimplicityProfile must be omitted"
  );
}

#[test]
fn jhdr_color_type_and_compression_print_conv() {
  // JHDR (int8u default, W/H int32u): ColorType 10 → "Color", Compression 8 →
  // "Huffman-coded baseline JPEG".
  let mut m = MngMeta::new();
  let mut body = Vec::new();
  body.extend_from_slice(&320u32.to_be_bytes());
  body.extend_from_slice(&240u32.to_be_bytes());
  body.extend_from_slice(&[10, 8, 8, 0, 8, 8, 0, 0]);
  assert!(m.process_chunk(b"JHDR", &body, false));
  let pj = render(&m, true);
  assert_u64(&pj, "ImageWidth", 320);
  assert_str(&pj, "ColorType", "Color");
  assert_str(&pj, "Compression", "Huffman-coded baseline JPEG");
  assert_str(&pj, "Interlace", "Sequential");
  // -n: raw ints.
  let pn = render(&m, false);
  assert_u64(&pn, "ColorType", 10);
  assert_u64(&pn, "Compression", 8);
}

#[test]
fn binary_chunk_emits_placeholder() {
  // DBYK (Binary => 1) → "(Binary data N bytes, …)" from the LENGTH.
  let mut m = MngMeta::new();
  assert!(m.process_chunk(b"DBYK", b"keyword data", false));
  let pj = render(&m, true);
  assert_str(
    &pj,
    "DropByKeyword",
    "(Binary data 12 bytes, use -b option to extract)",
  );
  // A 0-byte SAVE still renders the placeholder.
  let mut m2 = MngMeta::new();
  assert!(m2.process_chunk(b"SAVE", b"", false));
  assert_str(
    &render(&m2, true),
    "SaveObjects",
    "(Binary data 0 bytes, use -b option to extract)",
  );
}

#[test]
fn inline_valueconv_disc_drop_seek() {
  // DISC: join unpack n* ; DROP: 4-char split ; SEEK: NUL-strip.
  let mut m = MngMeta::new();
  assert!(m.process_chunk(b"DISC", &[0, 1, 0, 2, 0, 3], false));
  assert!(m.process_chunk(b"DROP", b"BACKMHDR", false));
  assert!(m.process_chunk(b"SEEK", b"point1\x00garbage", false));
  let pj = render(&m, true);
  assert_str(&pj, "DiscardObjects", "1 2 3");
  assert_str(&pj, "DropChunks", "BACK MHDR");
  assert_str(&pj, "SeekPoint", "point1");
  // ValueConvs apply identically in -n.
  let pn = render(&m, false);
  assert_str(&pn, "DiscardObjects", "1 2 3");
  assert_str(&pn, "SeekPoint", "point1");
}

#[test]
fn magn_xmethod_uses_shared_magmethod() {
  // MAGN XMethod @4 + YMethod @17 both use %magMethod.
  let mut m = MngMeta::new();
  let mut body = Vec::new();
  body.extend_from_slice(&1u16.to_be_bytes()); // FirstObjectID
  body.extend_from_slice(&5u16.to_be_bytes()); // LastObjectID
  body.push(2); // XMethod
  for v in [2u16, 2, 1, 1, 1, 1] {
    body.extend_from_slice(&v.to_be_bytes());
  }
  body.push(3); // YMethod
  assert_eq!(body.len(), 18);
  assert!(m.process_chunk(b"MAGN", &body, false));
  let pj = render(&m, true);
  assert_str(&pj, "XMethod", "Linear Interpolation");
  assert_str(&pj, "YMethod", "Closest Pixel");
}

#[test]
fn array_leaf_space_joins() {
  // DEFI XYLocation int32u[2] + ClippingBoundary int32u[4].
  let mut m = MngMeta::new();
  let mut body = Vec::new();
  body.extend_from_slice(&7u16.to_be_bytes()); // ObjectID
  body.push(1); // DoNotShow
  body.push(0); // ConcreteFlag
  body.extend_from_slice(&10u32.to_be_bytes());
  body.extend_from_slice(&20u32.to_be_bytes());
  for v in [0u32, 100, 0, 200] {
    body.extend_from_slice(&v.to_be_bytes());
  }
  assert!(m.process_chunk(b"DEFI", &body, false));
  let pj = render(&m, true);
  assert_str(&pj, "XYLocation", "10 20");
  assert_str(&pj, "ClippingBoundary", "0 100 0 200");
}

#[test]
fn unknown_chunk_returns_false() {
  let mut m = MngMeta::new();
  assert!(!m.process_chunk(b"FOOO", b"data", false));
  assert!(render(&m, true).is_empty());
}

#[test]
fn phyg_routes_to_caller_not_here() {
  // pHYg is `Phys`: process_chunk recognizes it (returns true) but emits no
  // MNG leaf — the caller routes it to the shared PNG pHYs decoder.
  let mut m = MngMeta::new();
  assert!(m.process_chunk(b"pHYg", &[0, 0, 0, 1, 0, 0, 0, 1, 1], false));
  assert!(render(&m, true).is_empty(), "pHYg emits nothing in MngMeta");
}

#[test]
fn printconv_miss_renders_raw_int() {
  // BASI ColorType with an out-of-table value (99) → raw int (HASH-PrintConv
  // miss). Build a 10-byte BASI: W,H int32u, BitDepth, ColorType=99.
  let mut m = MngMeta::new();
  let mut body = Vec::new();
  body.extend_from_slice(&8u32.to_be_bytes());
  body.extend_from_slice(&8u32.to_be_bytes());
  body.push(8); // BitDepth
  body.push(99); // ColorType (not in table)
  assert!(m.process_chunk(b"BASI", &body, false));
  let pj = render(&m, true);
  assert_u64(&pj, "ColorType", 99);
}

/// Finding 3: a count-0 (unsized) `string` leaf must require its first byte to
/// be in range (`byte_off < data.len()`), NOT merely `data.get(byte_off..)`
/// (which yields `Some(&[])` at the boundary → a spurious empty `SnapshotName`).
/// eXPi has `SnapshotID` (int16u @0) + `SnapshotName` (unsized string @2), so:
///   len 0/1 → NEITHER fits (SnapshotID needs 2 bytes); len 2 → SnapshotID only
///   (SnapshotName's offset 2 == len ⇒ OMITTED, not empty); len 3 → both.
/// Oracle-verified vs bundled 13.59 (`-G1 -j`).
#[test]
fn expi_unsized_string_per_field_availability() {
  // len 0: no leaves.
  let mut m0 = MngMeta::new();
  assert!(m0.process_chunk(b"eXPi", b"", false));
  assert!(render(&m0, true).is_empty(), "len 0 ⇒ no leaves");

  // len 1: SnapshotID (int16u) does not fit; SnapshotName offset 2 > len.
  let mut m1 = MngMeta::new();
  assert!(m1.process_chunk(b"eXPi", b"\x00", false));
  assert!(render(&m1, true).is_empty(), "len 1 ⇒ no leaves");

  // len 2: SnapshotID fits (= 5); SnapshotName offset 2 == len ⇒ OMITTED.
  let mut m2 = MngMeta::new();
  assert!(m2.process_chunk(b"eXPi", &[0x00, 0x05], false));
  let pj2 = render(&m2, true);
  assert_u64(&pj2, "SnapshotID", 5);
  assert!(
    pj2.iter().all(|(n, _)| n != "SnapshotName"),
    "SnapshotName must be omitted at len 2 (offset == len), not empty: {pj2:?}"
  );

  // len 3: SnapshotID = 5, SnapshotName = "A".
  let mut m3 = MngMeta::new();
  assert!(m3.process_chunk(b"eXPi", &[0x00, 0x05, b'A'], false));
  let pj3 = render(&m3, true);
  assert_u64(&pj3, "SnapshotID", 5);
  assert_str(&pj3, "SnapshotName", "A");
}

/// Finding 2: a post-`MEND`/`IEND` TRAILER MNG chunk emits its leaves under
/// family-1 `Trailer`, NOT `MNG` (`PNG.pm:1484` `SET_GROUP1 = 'Trailer'`). The
/// `in_trailer` flag is threaded into `process_chunk`. A trailing leaf coexists
/// with a same-named main leaf (distinct `(family1, name)` dedup keys), so the
/// trailer does NOT overwrite the main. Oracle-verified vs bundled 13.59.
#[test]
fn post_end_chunk_emits_under_trailer_group() {
  let mut m = MngMeta::new();
  // MAIN MHDR (in_trailer = false): SimplicityProfile = 0x00000001.
  let mut main = Vec::new();
  for v in [100u32, 200, 30, 0, 0, 0, 1] {
    main.extend_from_slice(&v.to_be_bytes());
  }
  assert!(m.process_chunk(b"MHDR", &main, false));
  // TRAILER MHDR (in_trailer = true): SimplicityProfile = 0x0000000b.
  let mut trailer = Vec::new();
  for v in [100u32, 200, 30, 0, 0, 0, 0x0b] {
    trailer.extend_from_slice(&v.to_be_bytes());
  }
  assert!(m.process_chunk(b"MHDR", &trailer, true));
  // TRAILER BACK (in_trailer = true): BackgroundColor (int16u[3]) @0 = "1 2 3".
  let mut back = Vec::new();
  for v in [1u16, 2, 3] {
    back.extend_from_slice(&v.to_be_bytes());
  }
  assert!(m.process_chunk(b"BACK", &back, true));

  let g1 = render_g1(&m, true);
  // Main MHDR → MNG:SimplicityProfile = 0x00000001 (NOT overwritten).
  assert!(
    g1.iter().any(|(grp, n, v)| grp == "MNG"
      && n == "SimplicityProfile"
      && *v == TagValue::Str("0x00000001".into())),
    "main MNG:SimplicityProfile must stay 0x00000001: {g1:?}"
  );
  // Trailer MHDR → Trailer:SimplicityProfile = 0x0000000b.
  assert!(
    g1.iter().any(|(grp, n, v)| grp == "Trailer"
      && n == "SimplicityProfile"
      && *v == TagValue::Str("0x0000000b".into())),
    "trailer Trailer:SimplicityProfile must be 0x0000000b: {g1:?}"
  );
  // Trailer BACK → Trailer:BackgroundColor = "1 2 3".
  assert!(
    g1.iter().any(|(grp, n, v)| grp == "Trailer"
      && n == "BackgroundColor"
      && *v == TagValue::Str("1 2 3".into())),
    "trailer Trailer:BackgroundColor must be \"1 2 3\": {g1:?}"
  );
  // The main MHDR leaves are NOT under Trailer.
  assert!(
    g1.iter()
      .any(|(grp, n, _)| grp == "MNG" && n == "ImageWidth"),
    "main ImageWidth stays under MNG: {g1:?}"
  );
  // -n: the raw SimplicityProfile ints carry the same group split.
  let g1n = render_g1(&m, false);
  assert!(
    g1n
      .iter()
      .any(|(grp, n, v)| grp == "MNG" && n == "SimplicityProfile" && *v == TagValue::U64(1)),
    "raw main = 1: {g1n:?}"
  );
  assert!(
    g1n
      .iter()
      .any(|(grp, n, v)| grp == "Trailer" && n == "SimplicityProfile" && *v == TagValue::U64(11)),
    "raw trailer = 11: {g1n:?}"
  );
}
