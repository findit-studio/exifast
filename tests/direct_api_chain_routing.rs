//! R4 F2 direct-API regression — the public `parse_<fmt>` lib APIs must
//! route through their respective `parse_full_chained` path so the embedded
//! ID3 / APE chains run (Codex adversarial finding R4 F2).
//!
//! Before the fix, each of the affected public APIs called the bare
//! body-only `parse_borrowed` / `parse_full_owned`, producing an
//! `Option<Meta>` with `id3` / `ape` sub-Metas always `None` — even for
//! buffers where the engine's `AnyParser::*` arm successfully nests them.
//! That was silent metadata loss outside the conformance route.
//!
//! Tests below exercise the lib-direct path (`exifast::parse_<fmt>`) for
//! each format that chains, and assert the nested sub-Metas surface.

#![cfg(feature = "std")]

use std::fs;
use std::path::Path;

fn fixture(name: &str) -> Vec<u8> {
  let p = Path::new(env!("CARGO_MANIFEST_DIR"))
    .join("tests/fixtures")
    .join(name);
  fs::read(&p).unwrap_or_else(|e| panic!("read fixture {}: {e}", p.display()))
}

/// `exifast::parse_ogg` on `ogg_id3_prefixed.ogg` must surface BOTH the
/// ID3-prefix sub-Meta (TIT2 = "IDPrefixTitle") AND the Vorbis tags.
/// Pre-fix the bare `parse_inner` rejected the buffer on `OggS != bytes[0]`,
/// returning `success = false` and zero ID3.
#[test]
#[cfg(all(feature = "ogg", feature = "id3"))]
fn parse_ogg_direct_routes_through_full_chained_for_id3_prefix() {
  let bytes = fixture("ogg_id3_prefixed.ogg");
  let meta = exifast::parse_ogg(&bytes, /* print_conv */ true)
    .expect("parse_ogg returns Ok")
    .expect("parse_ogg returns Some");

  // ID3 prefix detected and nested. The golden carries `File:ID3Size: 34`
  // and `ID3v2_3:Title: "IDPrefixTitle"`.
  let id3 = meta.id3_ref().expect("id3 sub-Meta present");
  assert_eq!(id3.id3_size(), 34, "File:ID3Size matches golden");
  assert_eq!(
    id3.title().unwrap_or(""),
    "IDPrefixTitle",
    "ID3v2 TIT2 title surfaces"
  );

  // Vorbis comments still parsed (the OGG body lives at bytes[34..]).
  // The golden lists Vorbis:Vendor / Vorbis:Artist / Vorbis:Album / …
  let comments = meta.comments();
  assert!(
    !comments.is_empty(),
    "Vorbis comment block surfaces alongside ID3 prefix"
  );
  let names: Vec<&str> = comments
    .iter()
    .map(|c| match c {
      exifast::formats::ogg::Comment::Scalar(s) => s.name(),
      exifast::formats::ogg::Comment::List(l) => l.name(),
      exifast::formats::ogg::Comment::Binary(b) => b.name(),
      // `Comment` is `#[non_exhaustive]`; reserved for future variants.
      _ => "",
    })
    .collect();
  assert!(
    names.iter().any(|n| *n == "Artist"),
    "Vorbis:Artist present (got names: {names:?})"
  );
}

/// `exifast::parse_ape` on `ape_id3_prefixed.ape` must surface the nested
/// ID3 sub-Meta (TIT2 = "TestTitle") AND the APE body's Artist tag.
/// Pre-fix `parse_ape` called `parse_full_owned` which skipped the ID3
/// chain entirely.
#[test]
#[cfg(all(feature = "ape", feature = "id3"))]
fn parse_ape_direct_routes_through_full_chained_for_id3_prefix() {
  let bytes = fixture("ape_id3_prefixed.ape");
  let mut shared = exifast::SharedFlags::new();
  let meta = exifast::parse_ape(&bytes, &mut shared)
    .expect("parse_ape returns Ok")
    .expect("parse_ape returns Some");

  // Golden: `File:ID3Size: 30`, `ID3v2_3:Title: "TestTitle"`.
  let id3 = meta.id3_ref().expect("id3 sub-Meta present");
  assert_eq!(id3.id3_size(), 30, "File:ID3Size matches golden");
  assert_eq!(
    id3.title().unwrap_or(""),
    "TestTitle",
    "ID3v2 TIT2 title surfaces"
  );

  // APE body still extracted — golden lists `APE:Artist: "Tester"`.
  assert_eq!(
    meta.artist().unwrap_or(""),
    "Tester",
    "APE:Artist surfaces alongside ID3 prefix"
  );
}

/// `exifast::parse_mpc` on `mpc_with_id3v2_prefix.mpc` must surface the
/// nested ID3 sub-Meta (TIT2 = "MpcId3v2Title") AND the MPC SV7 fields.
/// Pre-fix `parse_mpc` called the bare `parse_borrowed` which dropped
/// the ID3 prefix.
#[test]
#[cfg(all(feature = "mpc", feature = "id3"))]
fn parse_mpc_direct_routes_through_full_chained_for_id3_prefix() {
  let bytes = fixture("mpc_with_id3v2_prefix.mpc");
  let meta = exifast::parse_mpc(&bytes)
    .expect("parse_mpc returns Ok")
    .expect("parse_mpc returns Some");

  // Golden: `File:ID3Size: 34`, `ID3v2_3:Title: "MpcId3v2Title"`.
  let id3 = meta.id3_ref().expect("id3 sub-Meta present");
  assert_eq!(id3.id3_size(), 34, "File:ID3Size matches golden");
  assert_eq!(
    id3.title().unwrap_or(""),
    "MpcId3v2Title",
    "ID3v2 TIT2 title surfaces"
  );

  // MPC body still extracted — version 7 (SV7).
  assert_eq!(meta.version(), 7, "MPC SV7 version surfaces");
}

/// `exifast::parse_mpc` on `mpc_with_apev2_trailer.mpc` must surface the
/// nested APE sub-Meta (Artist = "MpcApeArtist") alongside the MPC SV7
/// fields. Pre-fix the bare `parse_borrowed` dropped the trailer.
#[test]
#[cfg(all(feature = "mpc", feature = "ape"))]
fn parse_mpc_direct_routes_through_full_chained_for_ape_trailer() {
  let bytes = fixture("mpc_with_apev2_trailer.mpc");
  let meta = exifast::parse_mpc(&bytes)
    .expect("parse_mpc returns Ok")
    .expect("parse_mpc returns Some");

  // Golden: `APE:Artist: "MpcApeArtist"`.
  let ape = meta.ape_ref().expect("ape sub-Meta present");
  assert_eq!(
    ape.artist().unwrap_or(""),
    "MpcApeArtist",
    "APE:Artist surfaces via MPC trailer chain"
  );
  assert_eq!(meta.version(), 7, "MPC SV7 version still surfaces");
}

/// `exifast::parse_wavpack` on `wavpack_with_apev2_trailer.wv` must
/// surface the nested APE sub-Meta (Artist = "WvApeArtist") alongside
/// the WavPack body fields. Pre-fix the bare `parse_borrowed` dropped
/// the trailer.
#[test]
#[cfg(all(feature = "wavpack", feature = "ape"))]
fn parse_wavpack_direct_routes_through_full_chained_for_ape_trailer() {
  let bytes = fixture("wavpack_with_apev2_trailer.wv");
  let meta = exifast::parse_wavpack(&bytes)
    .expect("parse_wavpack returns Ok")
    .expect("parse_wavpack returns Some");

  // Golden: `APE:Artist: "WvApeArtist"`.
  let ape = meta.ape_ref().expect("ape sub-Meta present");
  assert_eq!(
    ape.artist().unwrap_or(""),
    "WvApeArtist",
    "APE:Artist surfaces via WavPack trailer chain"
  );
  // WavPack body still extracted (sample rate from the golden).
  assert_eq!(
    meta.sample_rate_hz(),
    Some(48000),
    "WavPack SampleRate surfaces"
  );
}
