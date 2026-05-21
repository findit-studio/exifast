//! R4 F2 + R5 direct-API regression — every public parse surface
//! (crate-root `parse_<fmt>`, module-level `formats::<fmt>::parse_borrowed`,
//! AND `FormatParser::parse` trait impls) must route through the format's
//! `parse_full_chained` helper so the embedded ID3 / APE chains run
//! (Codex adversarial findings R4 F2 + R5).
//!
//! Before R4, the crate-root `parse_<fmt>` accessors called the bare
//! body-only `parse_borrowed` / `parse_full_owned`. R4 fixed those.
//! Before R5, the module-level `formats::<fmt>::parse_borrowed` and the
//! `FormatParser::parse` trait impls on `ProcessXxx` still bypassed the
//! chain — silent metadata loss for lib-first callers using the typed
//! `FormatParser` surface OR the module-level public entry. R5 lifts
//! the chain into ALL public surfaces.
//!
//! Tests below exercise each of the three surfaces for the chain-capable
//! formats (ape, mpc, wavpack, ogg) and assert the nested sub-Metas surface.

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

// ===========================================================================
// R5 — module-level `formats::<fmt>::parse_borrowed` regression tests
// ===========================================================================

/// `exifast::formats::ape` did not have a public `parse_borrowed` —
/// the module-level public surface for APE is the trait impl. Skip the
/// module-level assertion (no symbol to call). The trait-level test below
/// covers it.

/// `exifast::formats::mpc::parse_borrowed` must route through
/// `parse_full_chained` for the ID3-prefix case (R5).
#[test]
#[cfg(all(feature = "mpc", feature = "id3"))]
fn module_parse_borrowed_mpc_routes_chain_for_id3_prefix() {
  let bytes = fixture("mpc_with_id3v2_prefix.mpc");
  let meta = exifast::formats::mpc::parse_borrowed(&bytes)
    .expect("parse_borrowed returns Ok")
    .expect("parse_borrowed returns Some");
  let id3 = meta
    .id3_ref()
    .expect("id3 sub-Meta present via module-level entry");
  assert_eq!(id3.id3_size(), 34, "File:ID3Size matches golden");
  assert_eq!(
    id3.title().unwrap_or(""),
    "MpcId3v2Title",
    "ID3v2 TIT2 title surfaces via module-level entry"
  );
  assert_eq!(meta.version(), 7, "MPC SV7 version surfaces");
}

/// `exifast::formats::mpc::parse_borrowed` must route through
/// `parse_full_chained` for the APE-trailer case (R5).
#[test]
#[cfg(all(feature = "mpc", feature = "ape"))]
fn module_parse_borrowed_mpc_routes_chain_for_ape_trailer() {
  let bytes = fixture("mpc_with_apev2_trailer.mpc");
  let meta = exifast::formats::mpc::parse_borrowed(&bytes)
    .expect("parse_borrowed returns Ok")
    .expect("parse_borrowed returns Some");
  let ape = meta
    .ape_ref()
    .expect("ape sub-Meta present via module-level entry");
  assert_eq!(
    ape.artist().unwrap_or(""),
    "MpcApeArtist",
    "APE:Artist surfaces via module-level MPC trailer chain"
  );
  assert_eq!(meta.version(), 7, "MPC SV7 version still surfaces");
}

/// `exifast::formats::wavpack::parse_borrowed` must route through
/// `parse_full_chained` for the APE-trailer case (R5).
#[test]
#[cfg(all(feature = "wavpack", feature = "ape"))]
fn module_parse_borrowed_wavpack_routes_chain_for_ape_trailer() {
  let bytes = fixture("wavpack_with_apev2_trailer.wv");
  let meta = exifast::formats::wavpack::parse_borrowed(&bytes)
    .expect("parse_borrowed returns Ok")
    .expect("parse_borrowed returns Some");
  let ape = meta
    .ape_ref()
    .expect("ape sub-Meta present via module-level entry");
  assert_eq!(
    ape.artist().unwrap_or(""),
    "WvApeArtist",
    "APE:Artist surfaces via module-level WavPack trailer chain"
  );
  assert_eq!(
    meta.sample_rate_hz(),
    Some(48000),
    "WavPack SampleRate surfaces"
  );
}

/// `exifast::formats::ogg::parse_borrowed` must route through
/// `parse_full_chained` for the ID3-prefix case (R5). Pre-R5 the
/// module-level entry already routed through the chain (R4 percolated)
/// — this test pins that contract against future regressions.
#[test]
#[cfg(all(feature = "ogg", feature = "id3"))]
fn module_parse_borrowed_ogg_routes_chain_for_id3_prefix() {
  let bytes = fixture("ogg_id3_prefixed.ogg");
  let meta = exifast::formats::ogg::parse_borrowed(&bytes, /* print_conv */ true)
    .expect("parse_borrowed returns Ok")
    .expect("parse_borrowed returns Some");
  let id3 = meta
    .id3_ref()
    .expect("id3 sub-Meta present via module-level entry");
  assert_eq!(id3.id3_size(), 34, "File:ID3Size matches golden");
  assert_eq!(
    id3.title().unwrap_or(""),
    "IDPrefixTitle",
    "ID3v2 TIT2 title surfaces via module-level entry"
  );
}

// ===========================================================================
// R5 — `FormatParser::parse` trait-impl regression tests
// ===========================================================================
//
// Each test constructs the per-format Context (chained: `(data, &mut shared)`;
// leaf: bare `&data`) and dispatches through the `parser_new::FormatParser`
// trait. Pre-R5 every trait impl bypassed the chain — even for buffers where
// the engine `AnyParser::*` arm successfully nests the sub-Meta.

use exifast::format_parser::FormatParser;

/// `<ProcessApe as FormatParser>::parse(ctx)` with a full-parse Context
/// must surface the ID3 prefix on `ape_id3_prefixed.ape` (R5).
#[test]
#[cfg(all(feature = "ape", feature = "id3"))]
fn trait_parse_ape_routes_chain_for_id3_prefix() {
  use exifast::formats::ape::{Context, ProcessApe};
  let bytes = fixture("ape_id3_prefixed.ape");
  let mut shared = exifast::SharedFlags::new();
  let ctx = Context::new(&bytes, &mut shared);
  let meta = <ProcessApe as FormatParser>::parse(&ProcessApe, ctx)
    .expect("trait parse returns Ok")
    .expect("trait parse returns Some");
  let id3 = meta
    .id3_ref()
    .expect("id3 sub-Meta present via trait surface");
  assert_eq!(id3.id3_size(), 30, "File:ID3Size matches golden");
  assert_eq!(
    id3.title().unwrap_or(""),
    "TestTitle",
    "ID3v2 TIT2 title surfaces via trait surface"
  );
  assert_eq!(
    meta.artist().unwrap_or(""),
    "Tester",
    "APE:Artist surfaces alongside ID3 prefix"
  );
}

/// `<ProcessApe as FormatParser>::parse(ctx)` with a trailer-only
/// Context must NOT run the ID3 chain (faithful APE.pm:118 — bundled
/// `APE::ProcessAPE` from a `$$et{FileType}`-already-set parent skips
/// the embedded ID3 dispatch). Trailer-only stays body-only.
#[test]
#[cfg(all(feature = "ape", feature = "id3"))]
fn trait_parse_ape_trailer_only_skips_id3_chain() {
  use exifast::formats::ape::{Context, ProcessApe};
  // ID3-prefixed APE — the prefix would be detected if we ran the chain.
  let bytes = fixture("ape_id3_prefixed.ape");
  let mut shared = exifast::SharedFlags::new();
  let ctx = Context::new_trailer_only(&bytes, &mut shared);
  let result =
    <ProcessApe as FormatParser>::parse(&ProcessApe, ctx).expect("trait parse returns Ok");
  // Trailer-only: no full-buffer ID3 detection — the chain MUST stay
  // skipped (the bundled gate at APE.pm:118 is honored).
  if let Some(meta) = result {
    assert!(
      meta.id3_ref().is_none(),
      "trailer-only Context must not nest an ID3 sub-Meta"
    );
  }
}

/// `<ProcessMpc as FormatParser>::parse(ctx)` must surface the ID3
/// prefix on `mpc_with_id3v2_prefix.mpc` (R5).
#[test]
#[cfg(all(feature = "mpc", feature = "id3"))]
fn trait_parse_mpc_routes_chain_for_id3_prefix() {
  use exifast::formats::mpc::{Context, ProcessMpc};
  let bytes = fixture("mpc_with_id3v2_prefix.mpc");
  let mut shared = exifast::SharedFlags::new();
  let ctx = Context::new(&bytes, &mut shared);
  let meta = <ProcessMpc as FormatParser>::parse(&ProcessMpc, ctx)
    .expect("trait parse returns Ok")
    .expect("trait parse returns Some");
  let id3 = meta
    .id3_ref()
    .expect("id3 sub-Meta present via trait surface");
  assert_eq!(id3.id3_size(), 34, "File:ID3Size matches golden");
  assert_eq!(
    id3.title().unwrap_or(""),
    "MpcId3v2Title",
    "ID3v2 TIT2 title surfaces via trait surface"
  );
  assert_eq!(meta.version(), 7, "MPC SV7 version surfaces");
}

/// `<ProcessMpc as FormatParser>::parse(ctx)` must surface the APE
/// trailer on `mpc_with_apev2_trailer.mpc` (R5).
#[test]
#[cfg(all(feature = "mpc", feature = "ape"))]
fn trait_parse_mpc_routes_chain_for_ape_trailer() {
  use exifast::formats::mpc::{Context, ProcessMpc};
  let bytes = fixture("mpc_with_apev2_trailer.mpc");
  let mut shared = exifast::SharedFlags::new();
  let ctx = Context::new(&bytes, &mut shared);
  let meta = <ProcessMpc as FormatParser>::parse(&ProcessMpc, ctx)
    .expect("trait parse returns Ok")
    .expect("trait parse returns Some");
  let ape = meta
    .ape_ref()
    .expect("ape sub-Meta present via trait surface");
  assert_eq!(
    ape.artist().unwrap_or(""),
    "MpcApeArtist",
    "APE:Artist surfaces via trait MPC trailer chain"
  );
  assert_eq!(meta.version(), 7, "MPC SV7 version surfaces");
}

/// `<ProcessWv as FormatParser>::parse(ctx)` must surface the APE
/// trailer on `wavpack_with_apev2_trailer.wv` (R5).
#[test]
#[cfg(all(feature = "wavpack", feature = "ape"))]
fn trait_parse_wavpack_routes_chain_for_ape_trailer() {
  use exifast::formats::wavpack::{Context, ProcessWv};
  let bytes = fixture("wavpack_with_apev2_trailer.wv");
  let mut shared = exifast::SharedFlags::new();
  let ctx = Context::new(&bytes, &mut shared);
  let meta = <ProcessWv as FormatParser>::parse(&ProcessWv, ctx)
    .expect("trait parse returns Ok")
    .expect("trait parse returns Some");
  let ape = meta
    .ape_ref()
    .expect("ape sub-Meta present via trait surface");
  assert_eq!(
    ape.artist().unwrap_or(""),
    "WvApeArtist",
    "APE:Artist surfaces via trait WavPack trailer chain"
  );
  assert_eq!(
    meta.sample_rate_hz(),
    Some(48000),
    "WavPack SampleRate surfaces"
  );
}

/// `<ProcessOgg as FormatParser>::parse(&bytes)` must surface the ID3
/// prefix on `ogg_id3_prefixed.ogg` (R5). Pre-R5 the trait impl called
/// `parse_inner` directly which requires `OggS` at byte 0 — an
/// ID3v2-prefixed buffer would return `success=false` and silently
/// drop both the ID3 tags and the Vorbis body.
#[test]
#[cfg(all(feature = "ogg", feature = "id3"))]
fn trait_parse_ogg_routes_chain_for_id3_prefix() {
  use exifast::formats::ogg::ProcessOgg;
  let bytes = fixture("ogg_id3_prefixed.ogg");
  let meta = <ProcessOgg as FormatParser>::parse(&ProcessOgg, &bytes)
    .expect("trait parse returns Ok")
    .expect("trait parse returns Some");
  let id3 = meta
    .id3_ref()
    .expect("id3 sub-Meta present via trait surface");
  assert_eq!(id3.id3_size(), 34, "File:ID3Size matches golden");
  assert_eq!(
    id3.title().unwrap_or(""),
    "IDPrefixTitle",
    "ID3v2 TIT2 title surfaces via trait surface"
  );
  // Vorbis comments still parsed (the OGG body lives at bytes[34..]).
  assert!(
    !meta.comments().is_empty(),
    "Vorbis comment block surfaces alongside ID3 prefix"
  );
}
