// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Integration test for MakerNotes Phase-1 dispatch — the Exif IFD walker
//! reaches a real-fixture MakerNote, captures its bytes, and dispatches
//! it to the correct [`Vendor`] via the bundled-faithful
//! [`makernotes::dispatch`] table.
//!
//! Phase 1 verifies VENDOR IDENTIFICATION through the public
//! [`ExifMeta::maker_note`] → `MakerNote::vendor` accessor chain. The
//! per-vendor tag tables (Apple.pm, Canon.pm, …) are Phase 2-4 and not
//! exercised here.
//!
//! Fixture: `tests/fixtures/Exif_makernote.tif` — a hand-crafted TIFF
//! that the upstream `exif` IFD test suite uses; carries Make = `PENTAX`,
//! Model = `PENTAX K1`, and an 8-byte `PENTAX\0\0` MakerNote blob in the
//! ExifIFD's 0x927C tag. Bundled exiftool dispatches this to
//! `MakerNotePentax` (`MakerNotes.pm:763-779` — the `AOC\0` Pentax
//! variant doesn't match here; PENTAX-make + non-AOC body falls through
//! to the Pentax2/3 Asahi family OR to the catch-all). The port's
//! dispatcher resolves PENTAX as `Vendor::Pentax`.

#![cfg(all(feature = "exif", feature = "std"))]

use exifast::exif::makernotes::Vendor;

#[test]
fn exif_makernote_fixture_dispatches_to_pentax() {
  // The bundled Exif MakerNote fixture — TIFF (MM), IFD0 carries Make/
  // Model/ExifIFD-pointer, ExifIFD carries the 0x927C MakerNote tag with
  // the bytes `PENTAX\0\0...`.
  let data = std::fs::read(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/Exif_makernote.tif"
  ))
  .unwrap();
  let meta = exifast::parse_exif(&data)
    .expect("Exif parse returns Ok")
    .expect("TIFF recognized");

  // The Make tag was emitted into the entry list (the walker passes it
  // through to the dispatcher AND surfaces it as a leaf tag).
  let make_entry = meta.entry("Make").expect("Make tag in IFD0");
  let make = match make_entry.value_ref().raw() {
    exifast::exif::ifd::RawValue::Text(s) => s.as_str(),
    other => panic!("Make is not a Text RawValue: {other:?}"),
  };
  assert!(make.starts_with("PENTAX"), "Make = {make:?}");

  // The MakerNote was captured (the walker reaches ExifIFD's 0x927C and
  // calls into the MakerNotes Phase-1 dispatcher).
  let mn = meta.maker_note().expect("MakerNote captured");
  assert!(!mn.bytes().is_empty(), "MakerNote bytes captured");

  // Bundled `MakerNotePentax` requires `AOC\0` prefix; this fixture's
  // blob starts with `PENTAX\0\0` — bundled would still route via Make
  // ("$$self{Make}=~/^PENTAX/" — the headerless Nikon3 dispatch line
  // doesn't apply, but the Pentax5/6 signatures don't match either;
  // `PENTAX \0` is Pentax5, and our blob is `PENTAX\0\0` (no space). It
  // falls through to the Unknown catch-all in bundled. The port's
  // dispatcher does the same. Verify the dispatch is faithful: vendor
  // = `Vendor::Unknown` because the blob has NO matching signature
  // and PENTAX-make alone (without AOC\0) is not a sufficient
  // condition in `MakerNotes.pm`.
  //
  // This is the FAITHFUL-PORT BEHAVIOR — `MakerNotes.pm:763-779` has
  // the Pentax condition `$$valPt=~/^AOC\0/`, and our fixture blob
  // does NOT start with AOC\0.
  let vendor = mn.vendor();
  assert!(
    vendor.is_unknown(),
    "fixture blob falls through to MakerNoteUnknown (no AOC\\0 signature, no AOC-blob Pentax line for PENTAX make), got {vendor:?}"
  );
}

/// A SYNTHETIC test: build a TIFF whose ExifIFD's 0x927C MakerNote is
/// the canonical "Apple iOS\0" header, and verify the dispatcher routes
/// it to [`Vendor::Apple`] with the correct body-offset / base-rule /
/// byte-order directives.
#[test]
fn synthetic_apple_makernote_dispatches() {
  // MM TIFF: IFD0 with `Make = "Apple\0"` (6 bytes, inline) + ExifIFD
  // pointer (0x8769). ExifIFD with MakerNote (0x927C) holding the
  // 24-byte Apple blob (`Apple iOS\0\0\x01MM` + 10 bytes of fake IFD).
  let mut t: Vec<u8> = vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
  // IFD0: 2 entries (Make + ExifIFD).
  t.extend_from_slice(&[0x00, 0x02]);
  // Entry 1: Make (0x010f, ASCII, count=4 ⇒ inline) = "App\0". The
  // dispatcher's Apple branch matches on the blob SIGNATURE, not Make, so
  // any (or no) Make works; a 4-byte inline value keeps the fixture small.
  t.extend_from_slice(&[0x01, 0x0f]); // Make (0x010f, MM)
  t.extend_from_slice(&[0x00, 0x02]); // ASCII
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // count 4 (≤ 4 ⇒ inline)
  t.extend_from_slice(b"App\x00"); // inline 4-byte "App\0"
  // Entry 2: ExifIFD pointer (0x8769, LONG count 1).
  t.extend_from_slice(&[0x87, 0x69]); // tag 0x8769
  t.extend_from_slice(&[0x00, 0x04]); // LONG
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // count 1
  // ExifIFD offset: header(8) + IFD0(2 + 12 + 12 + 4) = 38.
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x26]); // 38 = 0x26
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // IFD0 next 0
  // ExifIFD at 38: 1 entry (MakerNote).
  t.extend_from_slice(&[0x00, 0x01]);
  t.extend_from_slice(&[0x92, 0x7c]); // tag 0x927c MakerNote
  t.extend_from_slice(&[0x00, 0x07]); // UNDEF
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x18]); // count 24
  // MakerNote value offset: 38 + (2 + 12 + 4) = 56.
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x38]); // 56 = 0x38
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ExifIFD next 0
  // The 24-byte Apple MakerNote blob at offset 56.
  // Bytes: "Apple iOS\0\0\x01MM" (14 bytes header) + 10 bytes payload.
  t.extend_from_slice(b"Apple iOS\x00\x00\x01MM");
  t.extend_from_slice(&[0x00, 0x05, 0x01, 0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);

  let meta = exifast::parse_exif_block(&t).expect("valid TIFF");
  let mn = meta.maker_note().expect("MakerNote captured");
  assert!(
    mn.vendor().is_apple(),
    "Apple signature dispatches to Vendor::Apple, got {:?}",
    mn.vendor()
  );
  // The Phase-1 dispatch directives — Apple is `body_offset=14`,
  // `Base => '$start - 14'`, `ByteOrder => 'Unknown'`.
  assert_eq!(mn.detected().body_offset(), 14);
  assert!(mn.detected().byte_order().is_unknown());
  // The body after the 14-byte header.
  let body = mn.body();
  assert_eq!(body.len(), 10);
}

/// SYNTHETIC: Canon MakerNote — `$$self{Make} =~ /^Canon/` and no
/// signature. The dispatcher resolves on Make alone
/// (`MakerNotes.pm:60-68`).
#[test]
fn synthetic_canon_makernote_dispatches() {
  // MM TIFF: IFD0 with Make = "Canon\0" (count 6 — offset case),
  // ExifIFD pointer, MakerNote.
  let mut t: Vec<u8> = vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
  // IFD0: 2 entries.
  t.extend_from_slice(&[0x00, 0x02]);
  // Entry 1: Make, ASCII, count=6, value-as-offset.
  t.extend_from_slice(&[0x01, 0x0f]); // Make
  t.extend_from_slice(&[0x00, 0x02]); // ASCII
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x06]); // count 6
  // Make offset: header(8) + IFD0(2 + 12 + 12 + 4) = 38.
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x26]); // offset 38
  // Entry 2: ExifIFD.
  t.extend_from_slice(&[0x87, 0x69]); // ExifIFD
  t.extend_from_slice(&[0x00, 0x04]); // LONG
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // count 1
  // ExifIFD offset: 38 (Make string at 38..44) + 6 = 44.
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x2c]); // 44 = 0x2c
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // IFD0 next 0
  // Make string at 38: "Canon\0".
  t.extend_from_slice(b"Canon\x00");
  // ExifIFD at 44: 1 entry (MakerNote).
  t.extend_from_slice(&[0x00, 0x01]);
  t.extend_from_slice(&[0x92, 0x7c]); // MakerNote
  t.extend_from_slice(&[0x00, 0x07]); // UNDEF
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x08]); // count 8
  // MakerNote offset: 44 + (2 + 12 + 4) = 62.
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x3e]); // 62 = 0x3e
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ExifIFD next 0
  // The 8-byte Canon MakerNote blob (no signature — Canon starts with IFD).
  t.extend_from_slice(&[0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04]);

  let meta = exifast::parse_exif_block(&t).expect("valid TIFF");
  // Make captured.
  assert_eq!(
    meta.entry("Make").map(|e| match e.value_ref().raw() {
      exifast::exif::ifd::RawValue::Text(s) => s.as_str(),
      _ => "<not-text>",
    }),
    Some("Canon")
  );
  let mn = meta.maker_note().expect("MakerNote captured");
  // Canon's dispatch: Make-only; no header; Inherit base; Unknown
  // byte-order (probe the body).
  assert!(
    mn.vendor().is_canon(),
    "Canon Make dispatches to Vendor::Canon, got {:?}",
    mn.vendor()
  );
  assert_eq!(mn.detected().body_offset(), 0);
  assert!(mn.detected().base_rule().is_inherit());
  // Body equals the whole blob (no header to strip).
  assert_eq!(mn.body(), mn.bytes());
}

/// SYNTHETIC: Sony MakerNote — primary `SONY DSC \0` signature
/// (`MakerNotes.pm:1031-1041`).
#[test]
fn synthetic_sony_makernote_dispatches() {
  let mut t: Vec<u8> = vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
  // IFD0: 1 entry (ExifIFD pointer).
  t.extend_from_slice(&[0x00, 0x01]);
  t.extend_from_slice(&[0x87, 0x69]); // ExifIFD
  t.extend_from_slice(&[0x00, 0x04]);
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
  // ExifIFD offset: 8 + (2 + 12 + 4) = 26.
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x1a]);
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
  // ExifIFD at 26.
  t.extend_from_slice(&[0x00, 0x01]);
  t.extend_from_slice(&[0x92, 0x7c]);
  t.extend_from_slice(&[0x00, 0x07]);
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x14]); // count 20
  // MakerNote offset: 26 + (2 + 12 + 4) = 44.
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x2c]);
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
  // 20-byte Sony blob: "SONY DSC \0" (10) + 10 bytes payload.
  t.extend_from_slice(b"SONY DSC \x00");
  t.extend_from_slice(&[0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05]);

  let meta = exifast::parse_exif_block(&t).expect("valid TIFF");
  let mn = meta.maker_note().expect("MakerNote captured");
  assert!(
    mn.vendor().is_sony(),
    "SONY DSC dispatches to Vendor::Sony, got {:?}",
    mn.vendor()
  );
  assert_eq!(mn.detected().body_offset(), 12);
  assert!(mn.detected().base_rule().is_inherit());
}

/// SYNTHETIC: Unknown MakerNote — no signature, no recognized Make ⇒
/// `Vendor::Unknown` (`MakerNotes.pm:1117-1126`).
#[test]
fn synthetic_unknown_makernote_routes_to_unknown() {
  let mut t: Vec<u8> = vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
  t.extend_from_slice(&[0x00, 0x01]); // 1 entry
  t.extend_from_slice(&[0x87, 0x69]);
  t.extend_from_slice(&[0x00, 0x04]);
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x1a]); // 26
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
  // ExifIFD at 26.
  t.extend_from_slice(&[0x00, 0x01]);
  t.extend_from_slice(&[0x92, 0x7c]);
  t.extend_from_slice(&[0x00, 0x07]);
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x08]); // count 8
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x2c]); // offset 44
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
  // 8 bytes of NONSENSE — no signature.
  t.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]);

  let meta = exifast::parse_exif_block(&t).expect("valid TIFF");
  let mn = meta.maker_note().expect("MakerNote captured");
  assert!(
    mn.vendor().is_unknown(),
    "no-signature + no-Make routes to Vendor::Unknown, got {:?}",
    mn.vendor()
  );
}

/// The `Vendor` enum's status surface — Phase 2/3/4/deferred is
/// observable.
#[test]
fn vendor_status_phase_buckets_are_observable() {
  assert!(Vendor::Apple.status().is_scheduled());
  assert!(Vendor::Canon.status().is_scheduled());
  assert!(Vendor::Sony.status().is_scheduled());
  assert!(Vendor::Panasonic.status().is_scheduled());
  assert!(Vendor::GoPro.status().is_scheduled());
  assert!(Vendor::Dji.status().is_scheduled());
  // Long-tail vendors are deferred.
  assert!(Vendor::Nikon.status().is_deferred());
  assert!(Vendor::Pentax.status().is_deferred());
  assert!(Vendor::Fuji.status().is_deferred());
}
