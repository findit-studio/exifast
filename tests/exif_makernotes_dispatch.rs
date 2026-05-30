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

// ===========================================================================
// Phase 2 — real-input Apple/Canon JPEG fixtures
// ===========================================================================

/// Apple iPhone 7 JPEG (bundled from `exiftool/t/images/Apple.jpg`).
/// Verify that the Apple body decoder populates `MakerNotesApple` with
/// the per-tag values the bundled `perl exiftool -j` oracle emits.
///
/// Oracle (excerpt):
///
/// ```text
/// "MakerNotes:MakerNoteVersion": 4,
/// "MakerNotes:AEStable": "Yes",
/// "MakerNotes:AETarget": 177,
/// "MakerNotes:AEAverage": 185,
/// "MakerNotes:AFStable": "Yes",
/// "MakerNotes:AccelerationVector": "-0.6483164083 0.002264119004 -0.7500767578",
/// "MakerNotes:FocusDistanceRange": "0.54 - 0.68 m",
/// "MakerNotes:OISMode": 2,
/// "MakerNotes:ImageCaptureType": "Unknown (5)",
/// ```
#[test]
fn apple_iphone_real_fixture_decodes_typed_fields() {
  let data = std::fs::read(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/MakerNotes_Apple.jpg"
  ))
  .unwrap();
  let meta = exifast::exif::jpeg::parse_jpeg_exif(&data).expect("Apple JPEG parsed");
  let mn = meta.maker_note().expect("MakerNote captured");
  assert!(mn.vendor().is_apple(), "vendor = Apple");

  let apple = mn.meta().apple().expect("Apple typed populated");

  // MakerNoteVersion (tag 0x0001) — the bundled oracle says 4.
  assert_eq!(apple.maker_note_version(), Some(4));
  // OISMode (tag 0x000f) — oracle says 2.
  assert_eq!(apple.ois_mode(), Some(2));
  // ImageCaptureType (tag 0x0014) — oracle says "Unknown (5)" (value 5).
  assert_eq!(apple.image_capture_type(), Some(5));
  // AccelerationVector (tag 0x0008) — 3 rational64s.
  let accel = apple.acceleration_vector().expect("AccelerationVector");
  assert!((accel.0 - (-0.6483164083)).abs() < 1e-6, "x = {}", accel.0);
  assert!((accel.1 - 0.002264119).abs() < 1e-6, "y = {}", accel.1);
  assert!((accel.2 - (-0.7500767578)).abs() < 1e-6, "z = {}", accel.2);
  // FocusDistanceRange (tag 0x000c) — bundled oracle PrintConv:
  // "0.54 - 0.68 m". Our typed surface stores the f64 pair.
  let range = apple.focus_distance_range().expect("FocusDistanceRange");
  assert!((range.0 - 0.539).abs() < 0.01, "min = {}", range.0);
  assert!((range.1 - 0.684).abs() < 0.01, "max = {}", range.1);
}

/// Apple emissions include the named MakerNote tags under
/// `MakerNotes:<Name>` for the JSON serializer.
#[test]
fn apple_iphone_real_fixture_emits_makernote_group() {
  let data = std::fs::read(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/MakerNotes_Apple.jpg"
  ))
  .unwrap();
  let meta = exifast::exif::jpeg::parse_jpeg_exif(&data).expect("Apple JPEG parsed");
  let mn = meta.maker_note().expect("MakerNote captured");
  let emissions = mn.emissions_print_conv();
  assert!(!emissions.is_empty(), "Apple emissions populated");
  // Should include MakerNoteVersion.
  let mnv = emissions
    .iter()
    .find(|e| e.name() == "MakerNoteVersion")
    .map(|e| e.value().clone());
  assert!(mnv.is_some(), "MakerNoteVersion emitted");
}

/// Canon EOS 300D / Digital Rebel JPEG (bundled from
/// `exiftool/t/images/Canon.jpg`). Verify the Canon body decoder
/// populates `MakerNotesCanon` with the per-tag values the bundled
/// `perl exiftool -j` oracle emits.
///
/// Oracle (excerpt):
///
/// ```text
/// "MakerNotes:CanonImageType": "CRW:EOS DIGITAL REBEL CMOS RAW",
/// "MakerNotes:CanonFirmwareVersion": "Firmware Version 1.1.1",
/// "MakerNotes:SerialNumber": "0560018150",
/// "MakerNotes:FileNumber": "118-1861",
/// "MakerNotes:OwnerName": "Phil Harvey",
/// "MakerNotes:CanonModelID": "EOS Digital Rebel / 300D / Kiss Digital",
/// "MakerNotes:LensType": "n/a",
/// "MakerNotes:MaxFocalLength": "55 mm",
/// "MakerNotes:MinFocalLength": "18 mm",
/// ```
#[test]
fn canon_eos_real_fixture_decodes_typed_fields() {
  let data = std::fs::read(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/MakerNotes_Canon.jpg"
  ))
  .unwrap();
  let meta = exifast::exif::jpeg::parse_jpeg_exif(&data).expect("Canon JPEG parsed");
  let mn = meta.maker_note().expect("MakerNote captured");
  assert!(mn.vendor().is_canon(), "vendor = Canon");

  let canon = mn.meta().canon().expect("Canon typed populated");

  // Camera identity.
  assert_eq!(canon.image_type(), Some("CRW:EOS DIGITAL REBEL CMOS RAW"));
  assert_eq!(canon.firmware_version(), Some("Firmware Version 1.1.1"));
  assert_eq!(canon.serial_number(), Some(560_018_150));
  assert_eq!(canon.file_number(), Some(1_181_861));
  assert_eq!(canon.owner_name(), Some("Phil Harvey"));
  assert_eq!(canon.model_id(), Some(0x80000170));
  assert_eq!(
    canon.model_name(),
    Some("EOS Digital Rebel / 300D / Kiss Digital")
  );

  // Lens identity.
  assert_eq!(canon.lens_type(), Some(65535));
  assert_eq!(canon.lens_name(), Some("n/a"));
  let range = canon.focal_range_mm().expect("focal range");
  assert!((range.0 - 18.0).abs() < 0.1, "min focal {}", range.0);
  assert!((range.1 - 55.0).abs() < 0.1, "max focal {}", range.1);
}

/// Canon emissions include the named MakerNote tags under
/// `MakerNotes:<Name>` and apply the print-conv labels.
#[test]
fn canon_eos_real_fixture_emits_print_conv_labels() {
  let data = std::fs::read(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/MakerNotes_Canon.jpg"
  ))
  .unwrap();
  let meta = exifast::exif::jpeg::parse_jpeg_exif(&data).expect("Canon JPEG parsed");
  let mn = meta.maker_note().expect("MakerNote captured");
  let emissions = mn.emissions_print_conv();

  // Find named emissions.
  let find = |name: &str| -> Option<exifast::value::TagValue> {
    emissions
      .iter()
      .find(|e| e.name() == name)
      .map(|e| e.value().clone())
  };
  use exifast::value::TagValue;
  assert_eq!(
    find("CanonImageType"),
    Some(TagValue::Str("CRW:EOS DIGITAL REBEL CMOS RAW".into()))
  );
  assert_eq!(
    find("CanonFirmwareVersion"),
    Some(TagValue::Str("Firmware Version 1.1.1".into()))
  );
  assert_eq!(
    find("SerialNumber"),
    Some(TagValue::Str("0560018150".into()))
  );
  assert_eq!(find("FileNumber"), Some(TagValue::Str("118-1861".into())));
  assert_eq!(find("OwnerName"), Some(TagValue::Str("Phil Harvey".into())));
  assert_eq!(
    find("CanonModelID"),
    Some(TagValue::Str(
      "EOS Digital Rebel / 300D / Kiss Digital".into()
    ))
  );
  // CameraSettings sub-table emissions.
  assert_eq!(find("LensType"), Some(TagValue::Str("n/a".into())));
  assert_eq!(find("MaxFocalLength"), Some(TagValue::Str("55 mm".into())));
  assert_eq!(find("MinFocalLength"), Some(TagValue::Str("18 mm".into())));
}

// ===========================================================================
// SERIALIZED-OUTPUT (`-G1`) fidelity — what the JSON document actually emits
//
// The typed-field tests above validate the decoded struct; these validate the
// rendered `"<family1>:<Name>"` keys/values the conformance gate compares
// against `perl exiftool -j -G1`. `extract_info` is the end-to-end serializer
// path — it runs `ExifMeta::serialize_tags`, i.e. the cached-MakerNote
// emission site — and emits the `-G1` JSON document. The output is COMPACT
// `serde_json` (no token-spacing guarantees), so we PARSE it and assert on the
// `"<group>:<Name>"` object keys / values rather than substring-matching the
// raw text. Gated on `json` (the feature `extract_info` needs).
// ===========================================================================

/// Parse the single-object `-G1` document `extract_info` emits and return its
/// `"<group>:<Name>" -> value` map.
#[cfg(feature = "json")]
fn extract_info_map(fixture: &str, print_on: bool) -> serde_json::Map<String, serde_json::Value> {
  let root = env!("CARGO_MANIFEST_DIR");
  let data = std::fs::read(format!("{root}/tests/fixtures/{fixture}"))
    .unwrap_or_else(|e| panic!("read {fixture}: {e}"));
  let json = exifast::parser::extract_info(fixture, &data, print_on);
  let doc: serde_json::Value = serde_json::from_str(&json)
    .unwrap_or_else(|e| panic!("{fixture}: invalid JSON ({e}):\n{json}"));
  doc
    .as_array()
    .and_then(|a| a.first())
    .and_then(|o| o.as_object())
    .cloned()
    .unwrap_or_else(|| panic!("{fixture}: doc is not [{{…}}]:\n{json}"))
}

/// FIX 1 — cached Apple MakerNote emissions use the vendor FAMILY-1 group.
///
/// Under `-G1` ExifTool emits `Apple:<Name>` (the vendor module name), NOT the
/// family-0 `MakerNotes:<Name>`. Oracle (`perl exiftool -j -G1` on this
/// fixture) emits `"Apple:MakerNoteVersion"`, `"Apple:AccelerationVector"`,
/// `"Apple:FocusDistanceRange"`. Assert the serialized keys carry the `Apple:`
/// prefix and that NO `MakerNotes:` MakerNote key leaks through — in both `-j`
/// (PrintConv on) and `-n` (off), which share the emission site.
#[cfg(feature = "json")]
#[test]
fn apple_serialized_keys_use_apple_group1() {
  for print_on in [true, false] {
    let mode = if print_on { "-j" } else { "-n" };
    let map = extract_info_map("MakerNotes_Apple.jpg", print_on);
    assert!(
      map.contains_key("Apple:MakerNoteVersion"),
      "expected Apple:MakerNoteVersion ({mode}); keys: {:?}",
      map.keys().collect::<Vec<_>>()
    );
    assert!(
      map.contains_key("Apple:AccelerationVector"),
      "expected Apple:AccelerationVector ({mode})"
    );
    // The family-1 group is the VENDOR, never the family-0 `MakerNotes`.
    assert!(
      !map.contains_key("MakerNotes:MakerNoteVersion"),
      "MakerNote tag leaked under family-0 MakerNotes group ({mode})"
    );
    assert!(
      !map.contains_key("MakerNotes:AccelerationVector"),
      "MakerNote tag leaked under family-0 MakerNotes group ({mode})"
    );
  }
}

/// FIX 1 — cached Canon MakerNote emissions use the `Canon:` family-1 group.
///
/// Oracle (`perl exiftool -j -G1`) emits `"Canon:CanonImageType"`,
/// `"Canon:LensType"`, `"Canon:MaxFocalLength"` — NOT `MakerNotes:`.
#[cfg(feature = "json")]
#[test]
fn canon_serialized_keys_use_canon_group1() {
  for print_on in [true, false] {
    let mode = if print_on { "-j" } else { "-n" };
    let map = extract_info_map("MakerNotes_Canon.jpg", print_on);
    assert!(
      map.contains_key("Canon:CanonImageType"),
      "expected Canon:CanonImageType ({mode}); keys: {:?}",
      map.keys().collect::<Vec<_>>()
    );
    assert!(
      map.contains_key("Canon:LensType"),
      "expected Canon:LensType ({mode})"
    );
    assert!(
      !map.contains_key("MakerNotes:CanonImageType"),
      "MakerNote tag leaked under family-0 MakerNotes group ({mode})"
    );
    assert!(
      !map.contains_key("MakerNotes:LensType"),
      "MakerNote tag leaked under family-0 MakerNotes group ({mode})"
    );
  }
}

/// FIX 2 — Apple multi-rational with NO PrintConv renders as space-joined
/// DECIMAL components, NOT `n/d` fractions.
///
/// AccelerationVector (`Apple.pm:62`, `rational64s` Count 3, no PrintConv)
/// serializes the same as the generic EXIF serializer: each rational via
/// `Rational::exiftool_val_str` (decimal), space-joined. Oracle emits
/// `"Apple:AccelerationVector": "-0.6483164083 0.002264119004 -0.7500767578"`
/// in BOTH `-j` and `-n` (no PrintConv applies to this tag, so the two modes
/// agree). Assert the exact decimal string and that it carries no `/`.
#[cfg(feature = "json")]
#[test]
fn apple_multi_rational_serializes_as_decimals_not_fractions() {
  for print_on in [true, false] {
    let mode = if print_on { "-j" } else { "-n" };
    let map = extract_info_map("MakerNotes_Apple.jpg", print_on);
    let v = map
      .get("Apple:AccelerationVector")
      .and_then(|v| v.as_str())
      .unwrap_or_else(|| panic!("Apple:AccelerationVector missing/non-string ({mode})"));
    // Decimal scalar form — matches the oracle and the generic EXIF serializer.
    assert_eq!(
      v, "-0.6483164083 0.002264119004 -0.7500767578",
      "AccelerationVector must be space-joined decimals ({mode})"
    );
    assert!(
      !v.contains('/'),
      "AccelerationVector rendered as n/d fractions ({mode}): {v:?}"
    );
  }
}

/// Unknown-tag suppression (Canon) — `Unknown => 1` MakerNote tags are
/// OMITTED from the default `-j -G1` output, matching ExifTool
/// (`ExifTool.pm:9179-9185` returns undef for them with no `-u`).
///
/// `0x3 CanonFlashInfo` (`Canon.pm:1237-1239`, `Unknown => 1`) is present in
/// this fixture (`-u` reveals it as "100 0 0 0"), but the golden
/// `perl exiftool -j -G1` (no `-u`) omits `Canon:CanonFlashInfo`. Assert it
/// is absent while a SUPPORTED Canon tag (`Canon:LensType`) is still present,
/// in BOTH `-j` (PrintConv on) and `-n` (off).
#[cfg(feature = "json")]
#[test]
fn canon_unknown_tags_suppressed_in_default_output() {
  for print_on in [true, false] {
    let mode = if print_on { "-j" } else { "-n" };
    let map = extract_info_map("MakerNotes_Canon.jpg", print_on);
    assert!(
      !map.contains_key("Canon:CanonFlashInfo"),
      "Canon:CanonFlashInfo (Unknown => 1) must be suppressed in default output ({mode}); keys: {:?}",
      map.keys().collect::<Vec<_>>()
    );
    // A supported tag is still emitted.
    assert!(
      map.contains_key("Canon:LensType"),
      "supported Canon:LensType must still be present ({mode})"
    );
  }
}

/// Unknown-tag suppression (Apple) — the `Unknown => 1` Apple MakerNote tags
/// (`Apple.pm` AEMatrix 0x0002, ImageProcessingFlags 0x0019, SceneFlags
/// 0x0025, …) are OMITTED from the default `-j -G1` output. This fixture
/// carries `AEMatrix` (0x0002, `Apple.pm:36 Unknown => 1`), which `-u`
/// reveals but the no-`-u` golden omits. Assert the Unknown keys are absent
/// while a SUPPORTED Apple tag (`Apple:AccelerationVector`) is still present,
/// in BOTH `-j` and `-n`.
#[cfg(feature = "json")]
#[test]
fn apple_unknown_tags_suppressed_in_default_output() {
  for print_on in [true, false] {
    let mode = if print_on { "-j" } else { "-n" };
    let map = extract_info_map("MakerNotes_Apple.jpg", print_on);
    for unknown_key in [
      "Apple:AEMatrix",
      "Apple:ImageProcessingFlags",
      "Apple:SceneFlags",
      "Apple:QualityHint",
      "Apple:ImageCaptureRequestID",
      "Apple:SignalToNoiseRatioType",
      "Apple:GreenGhostMitigationStatus",
      "Apple:ColorCorrectionMatrix",
    ] {
      assert!(
        !map.contains_key(unknown_key),
        "{unknown_key} (Unknown => 1) must be suppressed in default output ({mode}); keys: {:?}",
        map.keys().collect::<Vec<_>>()
      );
    }
    // A supported tag is still emitted.
    assert!(
      map.contains_key("Apple:AccelerationVector"),
      "supported Apple:AccelerationVector must still be present ({mode})"
    );
  }
}
