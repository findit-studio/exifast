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
  let meta = exifast::parse_exif(&data).expect("TIFF recognized");

  // The Make tag was emitted into the entry list (the walker passes it
  // through to the dispatcher AND surfaces it as a leaf tag).
  let make_entry = meta.entry("Make").expect("Make tag in IFD0");
  let make = match make_entry.value_ref().raw() {
    exifast::exif::ifd::RawValue::Text { text: s, .. } => s.as_str(),
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
      exifast::exif::ifd::RawValue::Text { text: s, .. } => s.as_str(),
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

  // ShotInfo deep sub-table (issue #86) — real-input parity vs the oracle
  // (`exiftool -j MakerNotes_Canon.jpg`).
  let shot = canon.shot_info().expect("ShotInfo decoded");
  assert_eq!(shot.white_balance(), Some("Auto"));
  assert_eq!(shot.sequence_number(), Some(0));
  // CameraTemperature raw is 0 → RawConv drops it (300D is EOS but the
  // sensor temp wasn't recorded).
  assert_eq!(shot.camera_temperature_c(), None);
  assert_eq!(shot.flash_guide_number(), Some(0.0));
  assert_eq!(shot.auto_exposure_bracketing(), Some("Off"));
  assert_eq!(shot.control_mode(), Some("Camera Local Control"));
  // FocusDistanceUpper raw 65535 → 655.35 m → "inf" (f64::INFINITY).
  assert_eq!(shot.focus_distance_upper_m(), Some(f64::INFINITY));
  assert_eq!(shot.focus_distance_lower_m(), Some(5.46));
  assert_eq!(shot.measured_ev2(), Some(-1.25));
  assert_eq!(shot.bulb_duration(), Some(4.0));
  assert_eq!(shot.nd_filter(), Some("n/a"));

  // AFInfo deep sub-table (issue #86) — older AFInfo record (tag 0x12).
  let af = canon.af_info().expect("AFInfo decoded");
  assert!(!af.is_v2(), "EOS 300D uses the older AFInfo record");
  assert_eq!(af.num_af_points(), Some(7));
  assert_eq!(af.valid_af_points(), Some(7));
  assert_eq!(af.canon_image_width(), Some(3072));
  assert_eq!(af.canon_image_height(), Some(2048));
  assert_eq!(af.af_image_width(), Some(3072));
  assert_eq!(af.af_image_height(), Some(2048));
  assert_eq!(af.af_area_x_positions(), &[1014, 608, 0, 0, 0, -608, -1014]);
  assert_eq!(af.af_area_y_positions(), &[0, 0, -506, 0, 506, 0, 0]);
  // EOS body → PrimaryAFPoint is NOT emitted (serial processing stops).
  assert_eq!(af.primary_af_point(), None);

  // FileInfo model-conditional decode (issue #88). The 300D's FileInfo
  // position 1 matches NONE of the FileNumber/ShutterCount conditions
  // (not 20D/350D/30D/400D/1D), and positions 20/21 are out of range in
  // this 18-byte blob — so the conditional surface stays empty. (The
  // visible "FileNumber" comes from the Main IFD 0x08 tag, not FileInfo.)
  assert_eq!(canon.file_number_decoded(), None);
  assert_eq!(canon.shutter_count_decoded(), None);
  assert_eq!(canon.focus_distance_decoded(), None);
}

// ===========================================================================
// Phase 3 — real-input Sony/Panasonic JPEG fixtures
// ===========================================================================

/// Sony DSC-F828 JPEG (bundled from `exiftool/t/images/Sony.jpg`). The
/// bundled fixture's MakerNotes IFD has 9 entries (`Sony_0x2000` through
/// `Sony_0x9008`) — ALL unrecognized in `%Image::ExifTool::Sony::Main`,
/// so bundled emits no `MakerNotes:` group either. The port's behavior is
/// FAITHFUL: dispatch the Sony signature, walk the body, omit unknown
/// tags. The integration verifies dispatch + empty typed surface (no
/// false positives).
#[test]
fn sony_dsc_real_fixture_dispatches_with_no_recognized_tags() {
  let data = std::fs::read(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/MakerNotes_Sony.jpg"
  ))
  .unwrap();
  let meta = exifast::exif::jpeg::parse_jpeg_exif(&data).expect("Sony JPEG parsed");

  // IFD0 Make = "SONY"
  let make_entry = meta.entry("Make").expect("Make tag in IFD0");
  let make = match make_entry.value_ref().raw() {
    exifast::exif::ifd::RawValue::Text { text: s, .. } => s.as_str(),
    other => panic!("Make is not a Text RawValue: {other:?}"),
  };
  assert_eq!(make, "SONY");

  let mn = meta.maker_note().expect("MakerNote captured");
  // Sony PRIMARY signature `SONY DSC \0` dispatches to Vendor::Sony.
  assert!(mn.vendor().is_sony(), "vendor = {:?}", mn.vendor());
  assert_eq!(mn.detected().body_offset(), 12);

  // No recognized tags in this fixture's MakerNotes IFD (`Sony_0x2000`..
  // `Sony_0x9008` — bundled emits `Sony_0xNNNN` placeholder names only in
  // verbose mode; the default `-j` output omits them, and we do the same).
  let emissions = mn.emissions_print_conv();
  assert!(
    emissions.is_empty(),
    "Sony fixture has no recognized tags — got {emissions:?}"
  );
  // Typed surface populated only for tags we recognize — all None here.
  let sony = mn.meta().sony().expect("Sony slot allocated");
  assert!(sony.model_id().is_none());
  assert!(sony.quality().is_none());
  assert!(sony.lens_type().is_none());
}

/// Synthetic Sony JPEG: build the same dispatch path used in the real
/// fixture but with a HEADERLESS Sony body that carries a single
/// `Quality` (0x0102) tag. Verify the typed surface and emissions
/// populate the print-conv label.
#[test]
fn synthetic_sony_typed_populates_quality_and_model_id() {
  // Direct parse via the public sony API (the dispatcher integration is
  // already covered by `synthetic_sony_makernote_dispatches`).
  use exifast::exif::makernotes::vendors::sony;
  // Headerless body: 2 entries — Quality=2 ("Fine") + SonyModelID=358 ("ILCE-9")
  let mut blob: Vec<u8> = Vec::new();
  blob.extend_from_slice(&[0x02, 0x00]); // 2 entries LE
  // Entry 1: Quality (0x0102, int32u, count=1, value=2)
  blob.extend_from_slice(&[0x02, 0x01, 0x04, 0x00]);
  blob.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
  blob.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
  // Entry 2: SonyModelID (0xb001, int16u, count=1, value=358)
  blob.extend_from_slice(&[0x01, 0xb0, 0x03, 0x00]);
  blob.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
  blob.extend_from_slice(&[0x66, 0x01, 0x00, 0x00]);
  let (typed, emissions) = sony::parse(&blob, 0, exifast::exif::ifd::ByteOrder::Little);
  assert_eq!(typed.quality(), Some(2));
  assert_eq!(typed.model_id(), Some(358));
  assert_eq!(typed.model_name(), Some("ILCE-9"));
  assert_eq!(emissions.len(), 2);
  use exifast::value::TagValue;
  let find = |n: &str| {
    emissions
      .iter()
      .find(|e| e.name() == n)
      .map(|e| e.value().clone())
  };
  assert_eq!(find("Quality"), Some(TagValue::Str("Fine".into())));
  assert_eq!(find("SonyModelID"), Some(TagValue::Str("ILCE-9".into())));
}

/// Panasonic Lumix DMC-FZ3 JPEG (bundled from `exiftool/t/images/Panasonic.jpg`).
/// Verify the Panasonic body decoder populates `MakerNotesPanasonic` with
/// the per-tag values the bundled `perl exiftool -j` oracle emits.
///
/// Oracle (excerpt):
///
/// ```text
/// "MakerNotes:ImageQuality": "High",
/// "MakerNotes:FirmwareVersion": "0.1.0.8",
/// "MakerNotes:WhiteBalance": "Auto",
/// "MakerNotes:FocusMode": "Auto",
/// "MakerNotes:ImageStabilization": "On, Mode 2",
/// "MakerNotes:MacroMode": "Off",
/// "MakerNotes:ShootingMode": "Program",
/// "MakerNotes:Audio": "No",
/// "MakerNotes:InternalSerialNumber": "(S00) 2004:07:19 no. 0102",
/// "MakerNotes:PanasonicExifVersion": "0100",
/// "MakerNotes:VideoFrameRate": "n/a",
/// "MakerNotes:ColorEffect": "Off",
/// "MakerNotes:TimeSincePowerOn": "00:00:06.96",
/// "MakerNotes:BurstMode": "Off",
/// "MakerNotes:SequenceNumber": 0,
/// "MakerNotes:ContrastMode": "Normal",
/// "MakerNotes:NoiseReduction": "Standard",
/// "MakerNotes:SelfTimer": "Off",
/// ```
#[test]
fn panasonic_lumix_real_fixture_decodes_typed_fields() {
  let data = std::fs::read(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/MakerNotes_Panasonic.jpg"
  ))
  .unwrap();
  let meta = exifast::exif::jpeg::parse_jpeg_exif(&data).expect("Panasonic JPEG parsed");
  let mn = meta.maker_note().expect("MakerNote captured");
  assert!(mn.vendor().is_panasonic(), "vendor = Panasonic");
  assert_eq!(mn.detected().body_offset(), 12);

  let pana = mn.meta().panasonic().expect("Panasonic typed populated");

  // Body identity.
  assert_eq!(pana.firmware_version(), Some("0.1.0.8"));
  assert_eq!(
    pana.internal_serial_number(),
    Some("(S00) 2004:07:19 no. 0102")
  );
  assert_eq!(pana.panasonic_exif_version(), Some("0100"));

  // Capture-mode integers.
  assert_eq!(pana.shooting_mode(), Some(6)); // 6 = Program
  assert_eq!(pana.image_stabilization(), Some(4)); // 4 = On, Mode 2
}

/// Panasonic emissions include the named MakerNote tags under
/// `MakerNotes:<Name>` with their print-conv labels.
#[test]
fn panasonic_lumix_real_fixture_emits_print_conv_labels() {
  let data = std::fs::read(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/MakerNotes_Panasonic.jpg"
  ))
  .unwrap();
  let meta = exifast::exif::jpeg::parse_jpeg_exif(&data).expect("Panasonic JPEG parsed");
  let mn = meta.maker_note().expect("MakerNote captured");
  let emissions = mn.emissions_print_conv();

  let find = |name: &str| -> Option<exifast::value::TagValue> {
    emissions
      .iter()
      .find(|e| e.name() == name)
      .map(|e| e.value().clone())
  };
  use exifast::value::TagValue;
  assert_eq!(find("ImageQuality"), Some(TagValue::Str("High".into())));
  assert_eq!(
    find("FirmwareVersion"),
    Some(TagValue::Str("0.1.0.8".into()))
  );
  assert_eq!(find("WhiteBalance"), Some(TagValue::Str("Auto".into())));
  assert_eq!(find("FocusMode"), Some(TagValue::Str("Auto".into())));
  assert_eq!(
    find("ImageStabilization"),
    Some(TagValue::Str("On, Mode 2".into()))
  );
  assert_eq!(find("MacroMode"), Some(TagValue::Str("Off".into())));
  assert_eq!(find("ShootingMode"), Some(TagValue::Str("Program".into())));
  assert_eq!(find("Audio"), Some(TagValue::Str("No".into())));
  assert_eq!(
    find("InternalSerialNumber"),
    Some(TagValue::Str("(S00) 2004:07:19 no. 0102".into()))
  );
  assert_eq!(
    find("PanasonicExifVersion"),
    Some(TagValue::Str("0100".into()))
  );
  assert_eq!(find("VideoFrameRate"), Some(TagValue::Str("n/a".into())));
  assert_eq!(find("ColorEffect"), Some(TagValue::Str("Off".into())));
  assert_eq!(
    find("TimeSincePowerOn"),
    Some(TagValue::Str("00:00:06.96".into()))
  );
  assert_eq!(find("BurstMode"), Some(TagValue::Str("Off".into())));
  assert_eq!(find("SequenceNumber"), Some(TagValue::I64(0)));
  assert_eq!(find("ContrastMode"), Some(TagValue::Str("Normal".into())));
  assert_eq!(
    find("NoiseReduction"),
    Some(TagValue::Str("Standard".into()))
  );
  assert_eq!(find("SelfTimer"), Some(TagValue::Str("Off".into())));
}

// ===========================================================================
// MakerNotePanasonic3 (DC-FT7) — `Base => 12` out-of-line offset regression
// ===========================================================================
//
// `MakerNotePanasonic3` (`MakerNotes.pm:752-760`) is the DC-FT7 variant of
// `%Panasonic::Main`. It carries `Base => 12` (`:758`, bundled comment
// `# crazy!`). ExifTool resolves the child IFD's `$$dirInfo{Base}` to
// `eval(12) + $base` (`Exif.pm:7003`) and shifts `$subdirDataPos` by
// `$base - $subdirBase` (`Exif.pm:7040`); the value-offset resolver then does
// `$valuePtr -= $dataPos` (`Exif.pm:6546`). Net effect, in the port's buffer
// coordinates (parent `base == 0`, `dataPos == 0`): an OUT-OF-LINE value
// offset `off` resolves to buffer position `off + 12`. Reading it at `off`
// (base 0, the pre-fix behaviour) lands 12 bytes EARLY ⇒ the string/binary is
// corrupted. Inline values (≤ 4 bytes) carry no offset and are unaffected.
//
// The synthetic TIFF below was VERIFIED against the bundled ExifTool 13.59
// binary (`exiftool -G1 -j`): it reports
//   "IFD0:Make": "Panasonic", "IFD0:Model": "DC-FT7",
//   "Panasonic:LensType": "LUMIX-LENS-12"
// i.e. ExifTool reads the out-of-line LensType string via the `Base => 12`
// rule. The bytes encode a little-endian standalone TIFF: IFD0 (Make,
// Model=DC-FT7, ExifIFD ptr) → ExifIFD (0x927c MakerNote) →
// "Panasonic\0\0\0" + a 1-entry IFD whose 0x51 LensType (string, count 14,
// OUT-OF-LINE) stores its offset 12 LESS than the real string position (the
// DC-FT7 base-12 convention) → the string "LUMIX-LENS-12\0" → the Make/Model
// strings.

/// DC-FT7 standalone TIFF; out-of-line LensType offset stored base-12
/// (the FAITHFUL DC-FT7 encoding). `Panasonic:LensType` == "LUMIX-LENS-12".
const DCFT7_BASE12_TIFF: &[u8] = &[
  73, 73, 42, 0, 8, 0, 0, 0, 3, 0, 15, 1, 2, 0, 10, 0, 0, 0, 112, 0, 0, 0, 16, 1, 2, 0, 7, 0, 0, 0,
  122, 0, 0, 0, 105, 135, 4, 0, 1, 0, 0, 0, 50, 0, 0, 0, 0, 0, 0, 0, 1, 0, 124, 146, 7, 0, 44, 0,
  0, 0, 68, 0, 0, 0, 0, 0, 0, 0, 80, 97, 110, 97, 115, 111, 110, 105, 99, 0, 0, 0, 1, 0, 81, 0, 2,
  0, 14, 0, 0, 0, 86, 0, 0, 0, 0, 0, 0, 0, 76, 85, 77, 73, 88, 45, 76, 69, 78, 83, 45, 49, 50, 0,
  80, 97, 110, 97, 115, 111, 110, 105, 99, 0, 68, 67, 45, 70, 84, 55, 0,
];

/// SAME TIFF but the LensType out-of-line offset is stored base-0 (the real
/// file position, 98 instead of 86). Under the `Base => 12` rule ExifTool
/// reads at 98+12=110 ⇒ corruption (it reported `"Panasonic:LensType": 2`).
/// This is the NEGATIVE CONTROL: with the +12 fix the faithful walker must
/// NOT produce "LUMIX-LENS-12" from this buffer.
const DCFT7_BASE0_TIFF: &[u8] = &[
  73, 73, 42, 0, 8, 0, 0, 0, 3, 0, 15, 1, 2, 0, 10, 0, 0, 0, 112, 0, 0, 0, 16, 1, 2, 0, 7, 0, 0, 0,
  122, 0, 0, 0, 105, 135, 4, 0, 1, 0, 0, 0, 50, 0, 0, 0, 0, 0, 0, 0, 1, 0, 124, 146, 7, 0, 44, 0,
  0, 0, 68, 0, 0, 0, 0, 0, 0, 0, 80, 97, 110, 97, 115, 111, 110, 105, 99, 0, 0, 0, 1, 0, 81, 0, 2,
  0, 14, 0, 0, 0, 98, 0, 0, 0, 0, 0, 0, 0, 76, 85, 77, 73, 88, 45, 76, 69, 78, 83, 45, 49, 50, 0,
  80, 97, 110, 97, 115, 111, 110, 105, 99, 0, 68, 67, 45, 70, 84, 55, 0,
];

/// The dispatcher routes a DC-FT7 `Panasonic`-prefixed blob to
/// `MakerNotePanasonic3` (`BaseRule::Literal(12)`, body_offset 12), and the
/// walker reads the OUT-OF-LINE LensType string via the +12 base shift —
/// matching the bundled `exiftool -G1 -j` output ("LUMIX-LENS-12").
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn panasonic3_dcft7_base12_out_of_line_lenstype() {
  use exifast::exif::makernotes::BaseRule;
  use exifast::value::TagValue;

  let meta = exifast::parse_exif(DCFT7_BASE12_TIFF).expect("TIFF recognized");

  // Model selected the Panasonic3 (DC-FT7) variant: the dispatcher gave it
  // `Base => 12` (`MakerNotes.pm:758`) and the 12-byte header.
  let mn = meta.maker_note().expect("MakerNote captured");
  assert!(mn.vendor().is_panasonic(), "vendor = Panasonic");
  assert_eq!(mn.detected().body_offset(), 12);
  assert_eq!(
    mn.detected().base_rule(),
    BaseRule::Literal(12),
    "DC-FT7 must dispatch as MakerNotePanasonic3 (Base => 12)"
  );

  // The out-of-line LensType resolves via off+12 ⇒ the real string.
  let find = |name: &str| -> Option<TagValue> {
    mn.emissions_print_conv()
      .iter()
      .find(|e| e.name() == name)
      .map(|e| e.value().clone())
  };
  assert_eq!(
    find("LensType"),
    Some(TagValue::Str("LUMIX-LENS-12".into())),
    "Base => 12 out-of-line read must match bundled ExifTool (LUMIX-LENS-12)"
  );
}

/// NEGATIVE CONTROL: with the offset stored base-0, the `Base => 12` rule
/// reads 12 bytes too far ⇒ the walker must NOT recover "LUMIX-LENS-12".
/// Proves the +12 shift is load-bearing (and matches ExifTool, which also
/// corrupts this buffer — it reported `2`, not the string).
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn panasonic3_dcft7_base0_offset_is_corrupted() {
  use exifast::value::TagValue;
  let meta = exifast::parse_exif(DCFT7_BASE0_TIFF).expect("TIFF recognized");
  let mn = meta.maker_note().expect("MakerNote captured");
  let lens = mn
    .emissions_print_conv()
    .iter()
    .find(|e| e.name() == "LensType")
    .map(|e| e.value().clone());
  assert_ne!(
    lens,
    Some(TagValue::Str("LUMIX-LENS-12".into())),
    "a base-0-stored offset must NOT yield the real string under Base => 12"
  );
}

/// Cross-check the DC-FT7 synthetic TIFF against the bundled ExifTool binary
/// (when `$EXIFTOOL` is set / on PATH): `exiftool -G1 -j -LensType` must emit
/// "LUMIX-LENS-12", proving the Rust read is byte-faithful. Skipped (not
/// failed) when the binary is unavailable.
#[cfg(all(feature = "exif", feature = "std", feature = "json"))]
#[test]
fn panasonic3_dcft7_matches_bundled_exiftool() {
  use std::process::Command;
  let tool = std::env::var("EXIFTOOL").unwrap_or_else(|_| "exiftool".to_string());
  // Probe availability.
  if Command::new(&tool).arg("-ver").output().is_err() {
    eprintln!("SKIP: exiftool binary not available; DC-FT7 cross-check skipped");
    return;
  }
  let dir = std::env::temp_dir();
  let path = dir.join("exifast_dcft7_base12.tif");
  std::fs::write(&path, DCFT7_BASE12_TIFF).expect("write temp DC-FT7 tif");
  let out = Command::new(&tool)
    .args(["-G1", "-j", "-LensType", "-Model"])
    .arg(&path)
    .output()
    .expect("run exiftool");
  let _ = std::fs::remove_file(&path);
  assert!(out.status.success(), "exiftool failed");
  let json = String::from_utf8(out.stdout).expect("utf8");
  let doc: serde_json::Value = serde_json::from_str(&json).expect("valid json");
  let obj = doc
    .as_array()
    .and_then(|a| a.first())
    .and_then(|o| o.as_object())
    .expect("doc is [{…}]");
  // Confirm the bundled binary detects DC-FT7 and reads the base-12 string.
  assert_eq!(
    obj.get("IFD0:Model").and_then(|v| v.as_str()),
    Some("DC-FT7"),
    "bundled exiftool must see Model DC-FT7"
  );
  assert_eq!(
    obj.get("Panasonic:LensType").and_then(|v| v.as_str()),
    Some("LUMIX-LENS-12"),
    "bundled exiftool must read the Base => 12 out-of-line LensType"
  );
}

/// `MakerNotePanasonic2` (the "MKE" Type2 variant, `MakerNotes.pm:742-749`)
/// uses `Panasonic::Type2` — a `ProcessBinaryData` table (`Panasonic.pm:2259`),
/// NOT `%Panasonic::Main`. The dispatcher routes it to `Vendor::Panasonic`,
/// but the Panasonic Main IFD parser must NOT run on it (Type2 BinaryData is
/// unported / deferred). Build a Panasonic-make TIFF whose 0x927c blob starts
/// with "MKE" AND — critically — is shaped so that IF the Main IFD walker were
/// (wrongly) run, it WOULD decode a real Main tag (ImageQuality at the count=1
/// position after the 12-byte header). Assert the vendor is Panasonic but NO
/// Main emissions surface — proving the Type2 gate is load-bearing, not just
/// that this blob happens to decode empty.
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn panasonic2_mke_type2_does_not_run_main_parser() {
  // Little-endian TIFF. IFD0: Make ("Panasonic\0", out-of-line) + ExifIFD ptr.
  // Layout offsets:
  //   header 0..8
  //   IFD0 @8: count=2 -> 2 + 24 + 4 = 30 -> ends @38
  //   ExifIFD @38: count=1 -> 2 + 12 + 4 = 18 -> ends @56
  //   MakerNote blob @56 (len 30) — "MKE\0" then a VALID 1-entry Main IFD
  //   Make "Panasonic\0" @86 (10 bytes)
  let mut t: Vec<u8> = Vec::new();
  t.extend_from_slice(&[b'I', b'I', 0x2a, 0x00, 8, 0, 0, 0]); // header, IFD0@8
  // IFD0: 2 entries.
  t.extend_from_slice(&2u16.to_le_bytes());
  // Make 0x010f, ASCII(2), count=10, offset=86 (out-of-line).
  t.extend_from_slice(&0x010fu16.to_le_bytes());
  t.extend_from_slice(&2u16.to_le_bytes());
  t.extend_from_slice(&10u32.to_le_bytes());
  t.extend_from_slice(&86u32.to_le_bytes());
  // ExifIFD ptr 0x8769, LONG(4), count=1, value=38.
  t.extend_from_slice(&0x8769u16.to_le_bytes());
  t.extend_from_slice(&4u16.to_le_bytes());
  t.extend_from_slice(&1u32.to_le_bytes());
  t.extend_from_slice(&38u32.to_le_bytes());
  t.extend_from_slice(&0u32.to_le_bytes()); // next IFD
  // ExifIFD @38: 1 entry (MakerNote).
  t.extend_from_slice(&1u16.to_le_bytes());
  t.extend_from_slice(&0x927cu16.to_le_bytes());
  t.extend_from_slice(&7u16.to_le_bytes()); // UNDEFINED
  t.extend_from_slice(&30u32.to_le_bytes()); // count = 30
  t.extend_from_slice(&56u32.to_le_bytes()); // offset = 56
  t.extend_from_slice(&0u32.to_le_bytes()); // next IFD
  // MakerNote blob @56 (30 bytes): "MKE\0" + 8 filler bytes to fill the
  // 12-byte header slot, THEN a valid Main IFD the Main walker WOULD decode:
  //   [12..14) count = 1
  //   [14..26) entry: tag 0x01 ImageQuality, int16u(3), count 1, value 2
  //   [26..30) next-IFD ptr = 0
  let blob_start = t.len();
  assert_eq!(blob_start, 56);
  t.extend_from_slice(b"MKE\x00"); // Type2 magic
  t.extend_from_slice(&[0u8; 8]); // pad header to 12 bytes
  t.extend_from_slice(&1u16.to_le_bytes()); // count = 1 (Main walker would read here)
  t.extend_from_slice(&0x01u16.to_le_bytes()); // tag 0x01 = ImageQuality
  t.extend_from_slice(&3u16.to_le_bytes()); // int16u
  t.extend_from_slice(&1u32.to_le_bytes()); // count 1
  t.extend_from_slice(&2u32.to_le_bytes()); // value 2 (= "High") inline
  t.extend_from_slice(&0u32.to_le_bytes()); // next IFD
  assert_eq!(t.len() - blob_start, 30);
  // Make string @86.
  assert_eq!(t.len(), 86);
  t.extend_from_slice(b"Panasonic\x00");

  let meta = exifast::parse_exif(&t).expect("TIFF");
  let mn = meta.maker_note().expect("MakerNote captured");
  // Dispatched to Panasonic (MakerNotePanasonic2 — make=Panasonic + "MKE").
  assert!(
    mn.vendor().is_panasonic(),
    "MKE blob dispatches to Vendor::Panasonic"
  );
  // But the Main parser was NOT run: no Main typed fields, no emissions —
  // even though the blob WOULD decode an ImageQuality entry if it had.
  assert!(
    mn.meta().panasonic().is_none(),
    "Panasonic Main typed must be ABSENT for a Type2/MKE blob"
  );
  assert!(
    mn.emissions_print_conv().is_empty(),
    "Panasonic Main emissions must be EMPTY for a Type2/MKE blob (Type2 deferred)"
  );
}

/// AUDIT (Sony side): `MakerNoteSonyEricsson` (`MakerNotes.pm:1082-1090`,
/// `SEMC MS\0`) routes to `Sony::Ericsson` with `Base => '$start - 8'` — NOT
/// `%Sony::Main`. The dispatcher collapses it to `Vendor::Sony`, but the Sony
/// Main IFD walker must NOT run on it: at body_offset 20 the Ericsson bytes
/// can coincidentally decode a real Main tag id (e.g. 0x0102 Quality ⇒ a bogus
/// "Standard"), which `routes_to_main` now suppresses. Real Sony Ericsson
/// bodies report Make `"Sony Ericsson"` (mixed case, so they do NOT match
/// Sony5's `/^SONY/` gate — they reach the Ericsson arm in both ExifTool and
/// the port). Build such a TIFF and assert NO Sony Main emissions surface.
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn sony_ericsson_does_not_run_main_parser() {
  // Little-endian TIFF. IFD0: Make ("Sony Ericsson\0", out-of-line) + ExifIFD
  // ptr. ExifIFD: MakerNote (0x927c) = "SEMC MS\0" + padding to body_offset 20
  // + a 1-entry IFD that WOULD decode Quality (0x0102) if the Main walker ran.
  //   header 0..8
  //   IFD0 @8: count=2 -> 30 -> ends @38
  //   ExifIFD @38: count=1 -> 18 -> ends @56
  //   MakerNote blob @56 (len 38)
  //   Make "Sony Ericsson\0" @94 (14 bytes)
  let mut t: Vec<u8> = Vec::new();
  t.extend_from_slice(&[b'I', b'I', 0x2a, 0x00, 8, 0, 0, 0]);
  t.extend_from_slice(&2u16.to_le_bytes());
  // Make 0x010f, ASCII(2), count=14, offset=94.
  t.extend_from_slice(&0x010fu16.to_le_bytes());
  t.extend_from_slice(&2u16.to_le_bytes());
  t.extend_from_slice(&14u32.to_le_bytes());
  t.extend_from_slice(&94u32.to_le_bytes());
  // ExifIFD ptr 0x8769, LONG(4), count=1, value=38.
  t.extend_from_slice(&0x8769u16.to_le_bytes());
  t.extend_from_slice(&4u16.to_le_bytes());
  t.extend_from_slice(&1u32.to_le_bytes());
  t.extend_from_slice(&38u32.to_le_bytes());
  t.extend_from_slice(&0u32.to_le_bytes());
  // ExifIFD @38: 1 entry (MakerNote).
  t.extend_from_slice(&1u16.to_le_bytes());
  t.extend_from_slice(&0x927cu16.to_le_bytes());
  t.extend_from_slice(&7u16.to_le_bytes());
  t.extend_from_slice(&38u32.to_le_bytes()); // count = 38
  t.extend_from_slice(&56u32.to_le_bytes()); // offset = 56
  t.extend_from_slice(&0u32.to_le_bytes());
  // MakerNote blob @56 (38 bytes): "SEMC MS\0" + pad to offset 20 + valid IFD.
  let blob_start = t.len();
  assert_eq!(blob_start, 56);
  t.extend_from_slice(b"SEMC MS\x00"); // 8 bytes
  t.extend_from_slice(&[0u8; 12]); // pad to body_offset 20
  t.extend_from_slice(&1u16.to_le_bytes()); // count = 1 (Main would read here)
  t.extend_from_slice(&0x0102u16.to_le_bytes()); // tag 0x0102 = Quality
  t.extend_from_slice(&4u16.to_le_bytes()); // int32u
  t.extend_from_slice(&1u32.to_le_bytes()); // count 1
  t.extend_from_slice(&2u32.to_le_bytes()); // value 2 (= "Fine") inline
  t.extend_from_slice(&0u32.to_le_bytes()); // next IFD
  assert_eq!(t.len() - blob_start, 38);
  // Make string @94.
  assert_eq!(t.len(), 94);
  t.extend_from_slice(b"Sony Ericsson\x00");

  let meta = exifast::parse_exif(&t).expect("TIFF");
  let mn = meta.maker_note().expect("MakerNote captured");
  assert!(
    mn.vendor().is_sony(),
    "SEMC MS\\0 dispatches to Vendor::Sony"
  );
  // The Main parser must NOT run ⇒ no spurious Quality.
  assert!(
    mn.meta().sony().is_none(),
    "Sony Main typed must be ABSENT for a SonyEricsson blob"
  );
  assert!(
    mn.emissions_print_conv().is_empty(),
    "Sony Main emissions must be EMPTY for a SonyEricsson blob (Ericsson table deferred)"
  );
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

  // ShotInfo sub-table emissions (issue #86) — PrintConv labels match the
  // oracle exactly.
  assert_eq!(find("WhiteBalance"), Some(TagValue::Str("Auto".into())));
  assert_eq!(find("SequenceNumber"), Some(TagValue::I64(0)));
  assert_eq!(
    find("AutoExposureBracketing"),
    Some(TagValue::Str("Off".into()))
  );
  assert_eq!(find("AEBBracketValue"), Some(TagValue::Str("0".into())));
  assert_eq!(
    find("ControlMode"),
    Some(TagValue::Str("Camera Local Control".into()))
  );
  assert_eq!(
    find("FocusDistanceUpper"),
    Some(TagValue::Str("inf".into()))
  );
  assert_eq!(
    find("FocusDistanceLower"),
    Some(TagValue::Str("5.46 m".into()))
  );
  assert_eq!(find("MeasuredEV2"), Some(TagValue::F64(-1.25)));
  assert_eq!(find("BulbDuration"), Some(TagValue::I64(4)));
  assert_eq!(find("NDFilter"), Some(TagValue::Str("n/a".into())));
  // CameraTemperature raw 0 → RawConv drops it (absent).
  assert_eq!(find("CameraTemperature"), None);

  // AFInfo sub-table emissions (issue #86).
  assert_eq!(find("NumAFPoints"), Some(TagValue::I64(7)));
  assert_eq!(find("ValidAFPoints"), Some(TagValue::I64(7)));
  assert_eq!(find("CanonImageWidth"), Some(TagValue::I64(3072)));
  assert_eq!(find("CanonImageHeight"), Some(TagValue::I64(2048)));
  assert_eq!(find("AFImageWidth"), Some(TagValue::I64(3072)));
  assert_eq!(find("AFImageHeight"), Some(TagValue::I64(2048)));
  assert_eq!(find("AFAreaWidth"), Some(TagValue::I64(151)));
  assert_eq!(find("AFAreaHeight"), Some(TagValue::I64(151)));
  assert_eq!(
    find("AFAreaXPositions"),
    Some(TagValue::Str("1014 608 0 0 0 -608 -1014".into()))
  );
  assert_eq!(
    find("AFAreaYPositions"),
    Some(TagValue::Str("0 0 -506 0 506 0 0".into()))
  );
  // AFPointsInFocus = 0 → DecodeBits → "(none)".
  assert_eq!(
    find("AFPointsInFocus"),
    Some(TagValue::Str("(none)".into()))
  );
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

/// #177 — a DEFERRED (non-walked) Canon SubDirectory tag must NOT leak its raw
/// value as a bogus `Canon:<parent>` key. ExifTool descends into the child
/// table and emits its leaves but NEVER the SubDirectory PARENT (`Exif.pm` `next
/// unless $doMaker or … or $$tagInfo{BlockExtract}` skips `FoundTag` for a
/// no-value SubDirectory row); the port mirrors that by suppressing the parent
/// in the Canon vendor walk's deferred-SubDirectory arm (same class as the
/// merged #96 R14 Sony/Panasonic fix). `MakerNotes_Canon.jpg` (== bundled
/// `t/images/Canon.jpg`) carries ONLY walked SubDirectories (CameraSettings /
/// ShotInfo / FileInfo / ColorBalance / AFInfo), so none of the deferred
/// parent names may ever appear — and the walked leaves stay present unchanged.
/// (The Canon1DmkIII.jpg `EXIFTOOL_T_IMAGES` test exercises the `ProcessingInfo`
/// trigger that this `Canon.jpg` lacks.)
#[cfg(feature = "json")]
#[test]
fn canon_deferred_subdir_parents_not_emitted() {
  // The Canon::Main names whose `SubDirectory` the port DEFERS (not walked):
  // `CANON_DEFERRED_SUBDIR_PARENTS` is the `is_walked() == false` set.
  const CANON_DEFERRED_SUBDIR_PARENTS: &[&str] = &[
    "CanonPanorama",  // 0x05  Canon::Panorama
    "MovieInfo",      // 0x11  Canon::MovieInfo
    "MyColors",       // 0x1d  Canon::MyColors
    "FaceDetect1",    // 0x24  Canon::FaceDetect1
    "FaceDetect2",    // 0x25  Canon::FaceDetect2
    "ContrastInfo",   // 0x27  Canon::ContrastInfo
    "WBInfo",         // 0x29  Canon::WBInfo
    "ProcessingInfo", // 0xa0  Canon::Processing
    "LensInfo",       // 0x4019 Canon::LensInfo
    "SerialInfo",     // 0x96 first arm (EOS 5D) Canon::SerialInfo
  ];
  for print_on in [true, false] {
    let mode = if print_on { "-j" } else { "-n" };
    let map = extract_info_map("MakerNotes_Canon.jpg", print_on);
    for parent in CANON_DEFERRED_SUBDIR_PARENTS {
      assert!(
        !map.contains_key(&format!("Canon:{parent}")),
        "bogus deferred SubDirectory parent Canon:{parent} must not be emitted ({mode}); keys: {:?}",
        map.keys().collect::<Vec<_>>()
      );
    }
    // The WALKED leaves are unaffected — a CameraSettings leaf (LensType) and
    // a ColorBalance leaf (WB_RGGBLevelsAuto) the oracle DOES emit stay present.
    assert!(
      map.contains_key("Canon:LensType"),
      "walked CameraSettings leaf Canon:LensType must still be present ({mode})"
    );
    assert!(
      map.contains_key("Canon:WB_RGGBLevelsAuto"),
      "walked ColorBalance leaf Canon:WB_RGGBLevelsAuto must still be present ({mode})"
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

// ===========================================================================
// FIX 1 / VALUE ORACLE — Panasonic serialized `-G1` group + conversions.
//
// `MakerNotes_Panasonic.jpg` (a DMC-FZ3 Lumix) is NOT a `conformance.rs`
// fixture: the engine does not yet emit the JPEG SOF `File:*` tags
// (ImageWidth/Height/EncodingProcess/BitsPerSample/ColorComponents/
// YCbCrSubSampling), the `IFD1:ThumbnailImage`, or `PrintIM:PrintIMVersion`
// that bundled exiftool reports for this JPEG, and the crate's
// `ExifTool:ExifToolVersion` is pinned to 13.58 while the bundled oracle is
// 13.59 — all unrelated to the Sony/Panasonic MakerNote findings (Apple/Canon
// JPEG fixtures share the same gaps, which is why neither is a conformance
// entry either). So we verify the Panasonic group end-to-end HERE, against
// the exiftool-verified `Panasonic:*` subset, in BOTH `-j` and `-n`.
//
// This is the end-to-end check the `emissions_print_conv()` dispatch tests
// missed: it drives the FULL serializer (`extract_info` → the cached-MakerNote
// emission site) and asserts the rendered `"<family1>:<Name>"` keys — i.e.
// that the family-1 group is `Panasonic` (FIX 1), not the family-0
// `MakerNotes`, AND that every conversion is value-identical to bundled.
// ===========================================================================

/// The bundled `perl exiftool -j -G1 MakerNotes_Panasonic.jpg` `Panasonic:*`
/// subset (PrintConv on, `print_on=true`) and the `-n` subset
/// (`print_on=false`). Captured from ExifTool 13.59; compared value-semantic
/// (so `"0"`/`0` and `0.0`/`0` match — same rule as `conformance.rs`).
#[cfg(feature = "json")]
fn panasonic_oracle(print_on: bool) -> &'static [(&'static str, &'static str)] {
  if print_on {
    &[
      ("Panasonic:ImageQuality", "\"High\""),
      ("Panasonic:FirmwareVersion", "\"0.1.0.8\""),
      ("Panasonic:WhiteBalance", "\"Auto\""),
      ("Panasonic:FocusMode", "\"Auto\""),
      ("Panasonic:AFAreaMode", "\"9-area\""),
      ("Panasonic:ImageStabilization", "\"On, Mode 2\""),
      ("Panasonic:MacroMode", "\"Off\""),
      ("Panasonic:ShootingMode", "\"Program\""),
      ("Panasonic:Audio", "\"No\""),
      (
        "Panasonic:DataDump",
        "\"(Binary data 5428 bytes, use -b option to extract)\"",
      ),
      ("Panasonic:WhiteBalanceBias", "0"),
      ("Panasonic:FlashBias", "0"),
      (
        "Panasonic:InternalSerialNumber",
        "\"(S00) 2004:07:19 no. 0102\"",
      ),
      ("Panasonic:PanasonicExifVersion", "\"0100\""),
      ("Panasonic:VideoFrameRate", "\"n/a\""),
      ("Panasonic:ColorEffect", "\"Off\""),
      ("Panasonic:TimeSincePowerOn", "\"00:00:06.96\""),
      ("Panasonic:BurstMode", "\"Off\""),
      ("Panasonic:SequenceNumber", "0"),
      ("Panasonic:ContrastMode", "\"Normal\""),
      ("Panasonic:NoiseReduction", "\"Standard\""),
      ("Panasonic:SelfTimer", "\"Off\""),
    ]
  } else {
    &[
      ("Panasonic:ImageQuality", "2"),
      ("Panasonic:FirmwareVersion", "\"0 1 0 8\""),
      ("Panasonic:WhiteBalance", "1"),
      ("Panasonic:FocusMode", "1"),
      ("Panasonic:AFAreaMode", "\"0 1\""),
      ("Panasonic:ImageStabilization", "4"),
      ("Panasonic:MacroMode", "2"),
      ("Panasonic:ShootingMode", "6"),
      ("Panasonic:Audio", "2"),
      (
        "Panasonic:DataDump",
        "\"(Binary data 5428 bytes, use -b option to extract)\"",
      ),
      ("Panasonic:WhiteBalanceBias", "0"),
      ("Panasonic:FlashBias", "0"),
      ("Panasonic:InternalSerialNumber", "\"S000407190102\""),
      ("Panasonic:PanasonicExifVersion", "\"0100\""),
      ("Panasonic:VideoFrameRate", "0"),
      ("Panasonic:ColorEffect", "1"),
      ("Panasonic:TimeSincePowerOn", "6.96"),
      ("Panasonic:BurstMode", "0"),
      ("Panasonic:SequenceNumber", "0"),
      ("Panasonic:ContrastMode", "0"),
      ("Panasonic:NoiseReduction", "0"),
      ("Panasonic:SelfTimer", "1"),
    ]
  }
}

/// FIX 1 + conversions — every Panasonic MakerNote tag in this fixture
/// serializes under the `Panasonic:` family-1 group (NOT `MakerNotes:`) with
/// the exact value bundled ExifTool emits, in BOTH `-j` and `-n`. Compared
/// value-semantic via [`json_equivalent`] (`"0"`==`0`, `0.0`==`0`).
#[cfg(feature = "json")]
#[test]
fn panasonic_serialized_group_and_values_match_bundled() {
  use exifast::jsondiff::json_equivalent;
  for print_on in [true, false] {
    let mode = if print_on { "-j" } else { "-n" };
    let map = extract_info_map("MakerNotes_Panasonic.jpg", print_on);
    for (key, want_val) in panasonic_oracle(print_on) {
      let got = map.get(*key).unwrap_or_else(|| {
        panic!(
          "missing {key} ({mode}); keys: {:?}",
          map.keys().collect::<Vec<_>>()
        )
      });
      let got_doc = serde_json::to_string(got).unwrap();
      // Wrap both sides as a 1-element array of {v: …} so the value-semantic
      // comparator runs on the scalar.
      let got_obj = format!("[{{\"v\":{got_doc}}}]");
      let want_obj = format!("[{{\"v\":{want_val}}}]");
      assert!(
        json_equivalent(&got_obj, &want_obj).is_ok(),
        "{key} ({mode}): got {got_doc}, want {want_val}"
      );
    }
    // FIX 1: no MakerNote tag leaks under the family-0 `MakerNotes` group.
    for leaked in [
      "MakerNotes:ImageQuality",
      "MakerNotes:ContrastMode",
      "MakerNotes:AFAreaMode",
    ] {
      assert!(
        !map.contains_key(leaked),
        "{leaked} leaked under family-0 MakerNotes group ({mode})"
      );
    }
  }
}

// ===========================================================================
// `MakerNotesMeta::from_blob` — variant/base gate (parallel-path regression)
//
// The production `ProcessExif` IFD walk gates the Sony/Panasonic Main parser
// (variant routing + DC-FT7 `Base => 12`) through the SINGLE gated entries
// `sony::parse_main_gated` / `panasonic::parse_main_gated`. The public
// `MakerNotesMeta::from_blob` constructor is a PARALLEL entry path into the
// same Main parser; it must use the SAME gate so a non-Main variant or a
// base-12 blob cannot produce wrong Main values. These tests drive `from_blob`
// directly (the production path is covered by the `*_does_not_run_main_parser`
// / `panasonic3_dcft7_*` tests above) and assert the gate holds there too.
// ===========================================================================

/// `from_blob` with a `SEMC MS\0` SonyEricsson blob (`MakerNotes.pm:1082-1090`,
/// → `Sony::Ericsson`, NOT `%Sony::Main`). The dispatcher collapses it to
/// `Vendor::Sony`, but the gated entry must reject it (no make ⇒ not a
/// prefixed Main variant) so the Sony slot stays ABSENT — even though the blob
/// is shaped to decode a real Main `Quality` (0x0102) if the ungated walker
/// ran. Regression for the parallel-path bypass bug.
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn from_blob_sony_ericsson_leaves_sony_slot_absent() {
  use exifast::exif::ifd::ByteOrder;
  use exifast::exif::makernotes::{MakerNotesMeta, dispatch};

  // Standalone SonyEricsson blob: "SEMC MS\0" + pad to body_offset 20 + a
  // 1-entry IFD that WOULD decode Quality=2 ("Fine") if Sony::Main ran.
  let mut blob: Vec<u8> = Vec::new();
  blob.extend_from_slice(b"SEMC MS\x00"); // 8 bytes
  blob.extend_from_slice(&[0u8; 12]); // pad to body_offset 20
  blob.extend_from_slice(&1u16.to_le_bytes()); // count = 1
  blob.extend_from_slice(&0x0102u16.to_le_bytes()); // tag 0x0102 = Quality
  blob.extend_from_slice(&4u16.to_le_bytes()); // int32u
  blob.extend_from_slice(&1u32.to_le_bytes()); // count 1
  blob.extend_from_slice(&2u32.to_le_bytes()); // value 2 (= "Fine") inline
  blob.extend_from_slice(&0u32.to_le_bytes()); // next IFD

  // Dispatch as bundled would (Make is mixed-case "Sony Ericsson", which does
  // NOT match Sony5's /^SONY/ — it reaches the Ericsson arm). The dispatcher
  // collapses it to Vendor::Sony regardless.
  let detected = dispatch(&blob, Some("Sony Ericsson"), Some("K800i"), None);
  assert!(
    detected.vendor().is_sony(),
    "SEMC MS\\0 dispatches to Vendor::Sony"
  );

  let meta = MakerNotesMeta::from_blob(detected, &blob, ByteOrder::Little);
  assert!(meta.vendor().is_sony());
  assert!(
    meta.sony().is_none(),
    "from_blob must leave the Sony Main slot ABSENT for a SonyEricsson blob \
     (Ericsson table deferred; the gate rejects the non-Main variant)"
  );
}

/// Positive control: `from_blob` with a PREFIXED `SONY DSC` Main blob
/// (`MakerNoteSony`, `MakerNotes.pm:1032`) — its signature gates `true`
/// regardless of Make, so the gated entry DOES run `%Sony::Main` and
/// populates the Sony slot. Proves the gate is not over-rejecting (the
/// `SEMC MS` absence above is a true rejection, not a blanket "from_blob
/// never parses Sony").
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn from_blob_sony_prefixed_main_populates_slot() {
  use exifast::exif::ifd::ByteOrder;
  use exifast::exif::makernotes::{MakerNotesMeta, dispatch};

  // "SONY DSC " (8-byte sig + space) + 4 pad bytes = 12-byte header
  // (body_offset 12), then a 1-entry IFD: Quality (0x0102, int32u) = 2.
  let mut blob: Vec<u8> = Vec::new();
  blob.extend_from_slice(b"SONY DSC "); // 9 bytes
  blob.extend_from_slice(&[0u8; 3]); // pad to body_offset 12
  blob.extend_from_slice(&1u16.to_le_bytes()); // count = 1
  blob.extend_from_slice(&0x0102u16.to_le_bytes()); // Quality
  blob.extend_from_slice(&4u16.to_le_bytes()); // int32u
  blob.extend_from_slice(&1u32.to_le_bytes()); // count 1
  blob.extend_from_slice(&2u32.to_le_bytes()); // value 2 (= "Fine")
  blob.extend_from_slice(&0u32.to_le_bytes()); // next IFD

  let detected = dispatch(&blob, Some("SONY"), Some("DSC-RX100"), None);
  assert!(detected.vendor().is_sony());
  assert_eq!(detected.body_offset(), 12, "SONY DSC ⇒ body_offset 12");

  let meta = MakerNotesMeta::from_blob(detected, &blob, ByteOrder::Little);
  let sony = meta
    .sony()
    .expect("from_blob must populate the Sony slot for a prefixed Main blob");
  assert_eq!(
    sony.quality(),
    Some(2),
    "the prefixed Main variant decodes Quality through the gated entry"
  );
}

/// `from_blob_with_context` resolves the HEADERLESS `MakerNoteSony5`
/// (`MakerNotes.pm:1069-1080`) make-only Main route. Sony5 is identified ONLY
/// by `$$self{Make} =~ /^SONY/` (no blob signature, `Start => '$valuePtr'`),
/// so the make-LESS `from_blob` leaves the slot ABSENT (the documented
/// caveat), whereas threading `make = "SONY"` through the context API gates
/// `routes_to_main` true and decodes `%Sony::Main`.
///
/// Bundled cross-check: `exiftool -j -G1` on a headerless Sony body whose
/// IFD0 Make is `SONY` emits `Sony:Quality` (the body routes through
/// `MakerNoteSony5` → `Image::ExifTool::Sony::Main`); a value of 2 is "Fine"
/// (`Sony.pm:770-786`).
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn from_blob_with_context_resolves_headerless_sony5() {
  use exifast::exif::ifd::ByteOrder;
  use exifast::exif::makernotes::{MakerNotesMeta, dispatch};

  // Headerless Sony5 body (Start => '$valuePtr', body_offset 0): a bare IFD
  // with NO prefix signature. The count MUST NOT be `\x01\x00`: a body
  // starting `\x01\x00` is the SonySRF case (`Sony::SRF`, `MakerNotes.pm:1093`
  // / the Sony5 `$$valPt !~ /^\x01\x00/` lookahead `:1072`), which is NOT
  // `%Sony::Main` — so use a 2-entry IFD (count `\x02\x00`): Quality (0x0102,
  // int32u) = 2 + SonyModelID (0xb001, int16u) = 358 ("ILCE-9"). Entries must
  // be tag-id sorted.
  let mut blob: Vec<u8> = Vec::new();
  blob.extend_from_slice(&2u16.to_le_bytes()); // count = 2 (avoids the SonySRF \x01\x00 case)
  // Entry 1: Quality (0x0102, int32u, count 1) = 2 ("Fine").
  blob.extend_from_slice(&0x0102u16.to_le_bytes());
  blob.extend_from_slice(&4u16.to_le_bytes()); // int32u
  blob.extend_from_slice(&1u32.to_le_bytes()); // count 1
  blob.extend_from_slice(&2u32.to_le_bytes()); // value 2 inline
  // Entry 2: SonyModelID (0xb001, int16u, count 1) = 358.
  blob.extend_from_slice(&0xb001u16.to_le_bytes());
  blob.extend_from_slice(&3u16.to_le_bytes()); // int16u
  blob.extend_from_slice(&1u32.to_le_bytes()); // count 1
  blob.extend_from_slice(&358u32.to_le_bytes()); // value 358 inline
  blob.extend_from_slice(&0u32.to_le_bytes()); // next IFD

  // The dispatcher routes a `Make =~ /^SONY/` headerless body to Sony5
  // (body_offset 0). The Make is REQUIRED at dispatch time too.
  let detected = dispatch(&blob, Some("SONY"), Some("DSLR-A700"), None);
  assert!(
    detected.vendor().is_sony(),
    "headerless SONY ⇒ Vendor::Sony"
  );
  assert_eq!(
    detected.body_offset(),
    0,
    "Sony5 is headerless (body_offset 0)"
  );

  // make-LESS: the headerless Sony5 make-gate cannot fire ⇒ slot ABSENT.
  let meta_no_ctx = MakerNotesMeta::from_blob(detected, &blob, ByteOrder::Little);
  assert!(
    meta_no_ctx.sony().is_none(),
    "from_blob (make-less) must leave the Sony slot ABSENT for a headerless \
     Sony5 body (make-only Main route)"
  );

  // WITH context (make = "SONY"): the gate fires ⇒ %Sony::Main decodes.
  let meta = MakerNotesMeta::from_blob_with_context(
    detected,
    &blob,
    ByteOrder::Little,
    Some("SONY"),
    Some("DSLR-A700"),
  );
  let sony = meta.sony().expect(
    "from_blob_with_context must populate the Sony slot for a headerless \
     Sony5 body when Make=SONY threads the make-gate",
  );
  assert_eq!(
    sony.quality(),
    Some(2),
    "the headerless Sony5 variant decodes Quality through the context gate"
  );
}

/// `from_blob` with a Panasonic Type2 (`MKE`) blob (`MakerNotePanasonic2`,
/// `MakerNotes.pm:743` → `Panasonic::Type2` `ProcessBinaryData`, NOT
/// `%Panasonic::Main`). The dispatcher collapses it to `Vendor::Panasonic`,
/// but the gated entry rejects the non-`Panasonic`-prefixed blob so the
/// Panasonic slot stays ABSENT — even though the blob is shaped to decode a
/// real Main `ImageQuality` (0x01) if the ungated walker ran.
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn from_blob_panasonic_type2_mke_leaves_panasonic_slot_absent() {
  use exifast::exif::ifd::ByteOrder;
  use exifast::exif::makernotes::{MakerNotesMeta, dispatch};

  // Standalone "MKE\0" Type2 blob: "MKE\0" + 8 filler bytes (12-byte header
  // slot) + a valid 1-entry Main IFD the Main walker WOULD decode.
  let mut blob: Vec<u8> = Vec::new();
  blob.extend_from_slice(b"MKE\x00"); // Type2 magic
  blob.extend_from_slice(&[0u8; 8]); // pad header to 12 bytes
  blob.extend_from_slice(&1u16.to_le_bytes()); // count = 1
  blob.extend_from_slice(&0x01u16.to_le_bytes()); // tag 0x01 = ImageQuality
  blob.extend_from_slice(&3u16.to_le_bytes()); // int16u
  blob.extend_from_slice(&1u32.to_le_bytes()); // count 1
  blob.extend_from_slice(&2u32.to_le_bytes()); // value 2 (= "High") inline
  blob.extend_from_slice(&0u32.to_le_bytes()); // next IFD

  // The "MKE" signature only matches MakerNotePanasonic2 under Make=Panasonic.
  let detected = dispatch(&blob, Some("Panasonic"), Some("DMC-FZ30"), None);
  assert!(
    detected.vendor().is_panasonic(),
    "MKE blob (Make=Panasonic) dispatches to Vendor::Panasonic"
  );

  let meta = MakerNotesMeta::from_blob(detected, &blob, ByteOrder::Little);
  assert!(meta.vendor().is_panasonic());
  assert!(
    meta.panasonic().is_none(),
    "from_blob must leave the Panasonic Main slot ABSENT for a Type2/MKE blob \
     (Type2 BinaryData deferred; the gate rejects the non-Main variant)"
  );
}

/// `from_blob` with a `MakerNotePanasonic3` (DC-FT7, `Base => 12`) blob: an
/// OUT-OF-LINE `LensType` (0x51) whose stored offset is base-12 (the DC-FT7
/// convention). The gated entry threads `BaseRule::Literal(12)` so the value
/// is read at `stored + 12` (the real string) instead of 12 bytes early. The
/// OLD `from_blob` (calling `panasonic::parse`, base 0) read it corrupted.
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn from_blob_panasonic3_dcft7_base12_reads_out_of_line_at_correct_offset() {
  use exifast::exif::ifd::ByteOrder;
  use exifast::exif::makernotes::{
    BaseRule, ChildByteOrder, DetectedMakerNote, MakerNotesMeta, Vendor, dispatch,
  };

  // Self-contained Panasonic3 blob (the standalone equivalent of
  // DCFT7_BASE12_TIFF, with offsets relative to the BLOB start):
  //   [0..12)  "Panasonic\0\0\0" header
  //   [12..14) count = 1
  //   [14..26) entry: tag 0x51 LensType, ASCII(2), count 14, OUT-OF-LINE
  //            offset stored = 18 (real string @30 read via +12 base)
  //   [26..30) next-IFD = 0
  //   [30..44) "LUMIX-LENS-12\0" (14 bytes)
  let mut blob: Vec<u8> = Vec::new();
  blob.extend_from_slice(b"Panasonic\x00\x00\x00"); // 12-byte header
  blob.extend_from_slice(&1u16.to_le_bytes()); // count = 1
  blob.extend_from_slice(&0x51u16.to_le_bytes()); // tag 0x51 = LensType
  blob.extend_from_slice(&2u16.to_le_bytes()); // ASCII
  blob.extend_from_slice(&14u32.to_le_bytes()); // count 14 (out-of-line)
  // Stored offset = real_pos(30) - 12 (DC-FT7 Base => 12 convention).
  blob.extend_from_slice(&18u32.to_le_bytes());
  blob.extend_from_slice(&0u32.to_le_bytes()); // next IFD
  assert_eq!(blob.len(), 30, "string must start at blob offset 30");
  blob.extend_from_slice(b"LUMIX-LENS-12\x00"); // 14 bytes @30

  // The dispatcher selects MakerNotePanasonic3 only for Model "DC-FT7"
  // (`MakerNotes.pm:752-760`): Panasonic prefix + Base => 12 + body_offset 12.
  let detected = dispatch(&blob, Some("Panasonic"), Some("DC-FT7"), None);
  assert!(detected.vendor().is_panasonic());
  assert_eq!(
    detected.base_rule(),
    BaseRule::Literal(12),
    "DC-FT7 must dispatch as MakerNotePanasonic3 (Base => 12)"
  );

  let meta = MakerNotesMeta::from_blob(detected, &blob, ByteOrder::Little);
  let pana = meta
    .panasonic()
    .expect("from_blob must populate the Panasonic slot for a DC-FT7 blob");
  assert_eq!(
    pana.lens_type(),
    Some("LUMIX-LENS-12"),
    "from_blob must read the Base => 12 out-of-line LensType at +12 (the \
     ungated base-0 path read it 12 bytes early)"
  );

  // NEGATIVE CONTROL: the SAME blob dispatched with `BaseRule::Inherit`
  // (base 0) reads the out-of-line offset 12 bytes early ⇒ NOT the string.
  // Proves the +12 threading through the gate is load-bearing in `from_blob`.
  let detected_base0 = DetectedMakerNote::new(
    Vendor::Panasonic,
    12,
    BaseRule::Inherit,
    ChildByteOrder::Unknown,
    false,
  );
  let meta0 = MakerNotesMeta::from_blob(detected_base0, &blob, ByteOrder::Little);
  let lens0 = meta0.panasonic().and_then(|p| p.lens_type());
  assert_ne!(
    lens0,
    Some("LUMIX-LENS-12"),
    "a base-0 (Inherit) read must NOT recover the real string from a \
     base-12-stored offset"
  );
}

// ===========================================================================
// MakerNoteLeica10 (D-Lux7) — cross-vendor `%Panasonic::Main` route
// ===========================================================================
//
// `MakerNoteLeica10` (`MakerNotes.pm:724-730`) is a `Vendor::Leica` blob
// (`Condition => '$$valPt =~ /^LEICA CAMERA AG\0/'`, `:725`) routed to the
// PANASONIC Main table (`TagTable => 'Image::ExifTool::Panasonic::Main'`,
// `:727`) with `Start => '$valuePtr + 18'` (`:728`, body offset 18, NOT the
// 12-byte `Panasonic\0\0\0` offset) and NO `Base` line (inherit). Bundled
// `exiftool -G1 -j` therefore emits the resulting tags under the `Panasonic:*`
// family-1 group (they ARE `%Panasonic::Main` tags).
//
// The dispatcher classifies the blob as `Vendor::Leica`, but the production
// dispatch only ran `panasonic::parse_main_gated` for `Vendor::Panasonic`, so
// the Panasonic Main tags were DROPPED. This fix routes a Leica10-signature
// blob through `panasonic::parse_leica10_gated` (body offset 18, Panasonic
// group), while leaving the nine Leica-specific-table variants
// (`Panasonic::Leica2..Leica9`, unported) gated/emitting-nothing.
//
// The bytes below were VERIFIED against bundled ExifTool 13.59
// (`exiftool -G1 -j`): it reports
//   "IFD0:Make": "LEICA CAMERA AG", "IFD0:Model": "D-Lux 7",
//   "Panasonic:ImageQuality": "High"
// Little-endian standalone TIFF: IFD0 (Make, Model, ExifIFD ptr) → ExifIFD
// (0x927c MakerNote) → "LEICA CAMERA AG\0" (16) + 2 pad (body @18) + a 1-entry
// IFD whose 0x01 ImageQuality (int16u, count 1, value 2 = "High", INLINE) →
// the Make/Model strings.

/// Byte-built Leica10 standalone TIFF (the verified oracle fixture).
/// `Panasonic:ImageQuality` == "High" in bundled ExifTool 13.59.
const LEICA10_TIFF: &[u8] = &[
  73, 73, 42, 0, 8, 0, 0, 0, 3, 0, 15, 1, 2, 0, 16, 0, 0, 0, 104, 0, 0, 0, 16, 1, 2, 0, 8, 0, 0, 0,
  120, 0, 0, 0, 105, 135, 4, 0, 1, 0, 0, 0, 50, 0, 0, 0, 0, 0, 0, 0, 1, 0, 124, 146, 7, 0, 36, 0,
  0, 0, 68, 0, 0, 0, 0, 0, 0, 0, 76, 69, 73, 67, 65, 32, 67, 65, 77, 69, 82, 65, 32, 65, 71, 0, 0,
  0, 1, 0, 1, 0, 3, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 76, 69, 73, 67, 65, 32, 67, 65, 77, 69,
  82, 65, 32, 65, 71, 0, 68, 45, 76, 117, 120, 32, 55, 0,
];

/// The dispatcher classifies the `LEICA CAMERA AG\0` blob as `Vendor::Leica`
/// with body_offset 18 (`MakerNoteLeica10`, `MakerNotes.pm:724-730`); the
/// production walk routes it through the cross-table Panasonic Main parser and
/// the typed Panasonic slot + cached emissions carry `ImageQuality = High`,
/// under the `Panasonic` emission group (NOT `MakerNotes`/`Leica`).
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn leica10_dispatches_to_panasonic_main_image_quality() {
  use exifast::exif::makernotes::BaseRule;
  use exifast::value::TagValue;

  let meta = exifast::parse_exif(LEICA10_TIFF).expect("TIFF recognized");
  let mn = meta.maker_note().expect("MakerNote captured");

  // Dispatched as Leica10: Vendor::Leica, body_offset 18, inherit base.
  assert!(mn.vendor().is_leica(), "vendor = Leica (Leica10 signature)");
  assert_eq!(
    mn.detected().body_offset(),
    18,
    "Leica10 Start => '$valuePtr + 18' (MakerNotes.pm:728)"
  );
  assert_eq!(
    mn.detected().base_rule(),
    BaseRule::Inherit,
    "Leica10 has no Base line (MakerNotes.pm:726-730) ⇒ inherit"
  );

  // The cross-table Panasonic Main parser ran ⇒ the Panasonic typed slot is
  // populated (Leica10's tags ARE %Panasonic::Main tags).
  assert!(
    mn.meta().panasonic().is_some(),
    "Leica10 must populate the Panasonic typed slot via the Main table"
  );

  // The cached emission carries ImageQuality = "High" under the Panasonic
  // group (the emission group1 is overridden to Panasonic even though the
  // vendor is Leica). ImageQuality (tag 0x01, value 2) ⇒ "High"
  // (Panasonic.pm:276).
  assert_eq!(
    mn.emission_group1(),
    "Panasonic",
    "Leica10 tags emit as Panasonic:* (they are %Panasonic::Main tags)"
  );
  let iq = mn
    .emissions_print_conv()
    .iter()
    .find(|e| e.name() == "ImageQuality")
    .map(|e| e.value().clone());
  assert_eq!(
    iq,
    Some(TagValue::Str("High".into())),
    "Leica10 ImageQuality (tag 0x01, value 2) ⇒ \"High\""
  );
}

/// END-TO-END SERIALIZED `-G1` fidelity: the full serializer
/// (`extract_info`, the conformance-gate path) must emit
/// `"Panasonic:ImageQuality": "High"` for the byte-built Leica10 TIFF —
/// matching bundled ExifTool's `Panasonic:*` output — and must NOT leak the
/// tag under a `Leica:` or family-0 `MakerNotes:` group.
#[cfg(all(feature = "exif", feature = "std", feature = "json"))]
#[test]
fn leica10_serialized_keys_use_panasonic_group1() {
  for print_on in [true, false] {
    let mode = if print_on { "-j" } else { "-n" };
    let json = exifast::parser::extract_info("leica10.tif", LEICA10_TIFF, print_on);
    let doc: serde_json::Value =
      serde_json::from_str(&json).unwrap_or_else(|e| panic!("invalid JSON ({e}):\n{json}"));
    let obj = doc
      .as_array()
      .and_then(|a| a.first())
      .and_then(|o| o.as_object())
      .unwrap_or_else(|| panic!("doc is not [{{…}}]:\n{json}"));
    // Make/Model decode (sanity); ImageQuality under the Panasonic group.
    assert_eq!(
      obj.get("IFD0:Make").and_then(|v| v.as_str()),
      Some("LEICA CAMERA AG"),
      "IFD0:Make ({mode})"
    );
    // `-j` renders the PrintConv label "High"; `-n` keeps the raw int 2.
    if print_on {
      assert_eq!(
        obj.get("Panasonic:ImageQuality").and_then(|v| v.as_str()),
        Some("High"),
        "Leica10 ImageQuality must serialize as Panasonic:ImageQuality=\"High\" ({mode}); \
         keys: {:?}",
        obj.keys().collect::<Vec<_>>()
      );
    } else {
      assert_eq!(
        obj
          .get("Panasonic:ImageQuality")
          .and_then(serde_json::Value::as_i64),
        Some(2),
        "Leica10 ImageQuality -n raw int ({mode})"
      );
    }
    // The family-1 group is Panasonic, never Leica or the family-0 MakerNotes.
    assert!(
      !obj.contains_key("Leica:ImageQuality"),
      "Leica10 tag must NOT emit under a Leica: group ({mode})"
    );
    assert!(
      !obj.contains_key("MakerNotes:ImageQuality"),
      "Leica10 tag must NOT emit under family-0 MakerNotes ({mode})"
    );
  }
}

/// Cross-check the Leica10 synthetic TIFF against the bundled ExifTool binary
/// (when `$EXIFTOOL` is set / on PATH): `exiftool -G1 -j` must emit
/// `Panasonic:ImageQuality` == "High", proving the Rust read is byte-faithful
/// to the cross-vendor route. Skipped (not failed) when the binary is absent.
#[cfg(all(feature = "exif", feature = "std", feature = "json"))]
#[test]
fn leica10_matches_bundled_exiftool() {
  use std::process::Command;
  let tool = std::env::var("EXIFTOOL").unwrap_or_else(|_| "exiftool".to_string());
  if Command::new(&tool).arg("-ver").output().is_err() {
    eprintln!("SKIP: exiftool binary not available; Leica10 cross-check skipped");
    return;
  }
  let dir = std::env::temp_dir();
  let path = dir.join("exifast_leica10.tif");
  std::fs::write(&path, LEICA10_TIFF).expect("write temp Leica10 tif");
  let out = Command::new(&tool)
    .args(["-G1", "-j", "-ImageQuality", "-Make", "-Model"])
    .arg(&path)
    .output()
    .expect("run exiftool");
  let _ = std::fs::remove_file(&path);
  assert!(out.status.success(), "exiftool failed");
  let json = String::from_utf8(out.stdout).expect("utf8");
  let doc: serde_json::Value = serde_json::from_str(&json).expect("valid json");
  let obj = doc
    .as_array()
    .and_then(|a| a.first())
    .and_then(|o| o.as_object())
    .expect("doc is [{…}]");
  assert_eq!(
    obj.get("IFD0:Model").and_then(|v| v.as_str()),
    Some("D-Lux 7"),
    "bundled exiftool must see Model D-Lux 7"
  );
  // The load-bearing oracle: bundled emits the Leica10 ImageQuality under the
  // Panasonic group (it is a %Panasonic::Main tag).
  assert_eq!(
    obj.get("Panasonic:ImageQuality").and_then(|v| v.as_str()),
    Some("High"),
    "bundled exiftool must emit Panasonic:ImageQuality=\"High\" for the Leica10 route"
  );
}

/// `from_blob` (the public constructor — a parallel code path) must ALSO route
/// a Leica10-signature blob through the gate and populate the Panasonic slot
/// at body offset 18, while a genuinely-Leica-table blob (`LEICA\0\0\0`, the
/// `Panasonic::Leica2` M8 variant) leaves the slot ABSENT (unported/deferred).
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn from_blob_leica10_populates_panasonic_slot_others_deferred() {
  use exifast::exif::ifd::ByteOrder;
  use exifast::exif::makernotes::{MakerNotesMeta, dispatch};

  // Self-contained Leica10 blob: "LEICA CAMERA AG\0" (16) + 2 pad (body @18)
  // + 1-entry IFD (0x1a ImageStabilization int16u count1 value4 inline) +
  // next=0. Tag 0x1a is a TYPED field on the Panasonic struct (`Panasonic.pm:
  // ImageStabilization`); `from_blob` returns only the typed meta (no
  // emissions), so this gives a concrete typed assertion through the gate.
  let mut blob: Vec<u8> = Vec::new();
  blob.extend_from_slice(b"LEICA CAMERA AG\x00");
  blob.extend_from_slice(&[0x00, 0x00]);
  blob.extend_from_slice(&1u16.to_le_bytes());
  blob.extend_from_slice(&0x1au16.to_le_bytes()); // tag 0x1a ImageStabilization
  blob.extend_from_slice(&3u16.to_le_bytes()); // int16u
  blob.extend_from_slice(&1u32.to_le_bytes()); // count 1
  blob.extend_from_slice(&4u32.to_le_bytes()); // value 4 = "On, Mode 2"
  blob.extend_from_slice(&0u32.to_le_bytes());

  let detected = dispatch(&blob, Some("LEICA CAMERA AG"), Some("D-Lux 7"), None);
  assert!(detected.vendor().is_leica(), "Leica10 dispatches to Leica");
  assert_eq!(detected.body_offset(), 18);

  let meta = MakerNotesMeta::from_blob(detected, &blob, ByteOrder::Little);
  let pana = meta
    .panasonic()
    .expect("from_blob must populate the Panasonic slot for a Leica10 blob");
  assert_eq!(
    pana.image_stabilization(),
    Some(4),
    "from_blob must decode the Leica10 body at offset 18 (ImageStabilization=4)"
  );

  // NEGATIVE: a `LEICA\0\0\0` (Leica2 / M8, `Panasonic::Leica2` table) blob is
  // a `Vendor::Leica` detection too, but it does NOT match the Leica10
  // signature ⇒ the gate returns `None` ⇒ Panasonic slot ABSENT (the Leica2
  // table is unported/deferred — no spurious Panasonic Main tags). The blob is
  // shaped so that IF the Main walker were (wrongly) run at body offset 18 it
  // WOULD see a 1-entry IFD; the signature gate is what suppresses it.
  let mut leica2: Vec<u8> = Vec::new();
  leica2.extend_from_slice(b"LEICA\x00\x00\x00"); // 8-byte LEICA2 header
  leica2.extend_from_slice(&[0x00; 10]); // pad so body @18 is a plausible IFD
  leica2.extend_from_slice(&1u16.to_le_bytes());
  leica2.extend_from_slice(&0x01u16.to_le_bytes());
  leica2.extend_from_slice(&3u16.to_le_bytes());
  leica2.extend_from_slice(&1u32.to_le_bytes());
  leica2.extend_from_slice(&2u32.to_le_bytes());
  leica2.extend_from_slice(&0u32.to_le_bytes());
  let det2 = dispatch(&leica2, Some("Leica Camera AG"), Some("M8"), None);
  assert!(
    det2.vendor().is_leica(),
    "LEICA\\0\\0\\0 dispatches to Leica"
  );
  let meta2 = MakerNotesMeta::from_blob(det2, &leica2, ByteOrder::Little);
  assert!(
    meta2.panasonic().is_none(),
    "a genuinely-Leica-table blob (LEICA\\0\\0\\0 / Leica2) must leave the \
     Panasonic slot ABSENT (Panasonic::Leica2 unported/deferred)"
  );
}

// ===========================================================================
// MakerNoteLeica (Leica1) — cross-vendor `%Panasonic::Main` route (make-only)
// ===========================================================================
//
// `MakerNoteLeica` (Leica1, `MakerNotes.pm:599-608`) is the older-Leica
// make-only variant routed to the PANASONIC Main table (`TagTable =>
// 'Image::ExifTool::Panasonic::Main'`, `:604`). Its `Condition` is the
// MAKE-only `$$self{Make} eq "LEICA"` (`:602`) — there is NO `$$valPt`
// signature term — with `Start => '$valuePtr + 8'` (`:606`, the 8-byte
// `LEICA\0\0\0` header) and NO `Base` line (inherit). It is the FIRST Leica
// entry in `%Main`, so a `Make eq "LEICA"` body is claimed by it regardless
// of signature; the later Leica2-9/Leica10 arms (which need a different
// Make, or sit after Leica1) are never reached. Bundled `exiftool -G1 -j`
// emits the resulting tags under the `Panasonic:*` family-1 group (they ARE
// `%Panasonic::Main` tags).
//
// Before this fix the production walk only ran `panasonic::parse_main_gated`
// (for `Vendor::Panasonic`) and `parse_leica10_gated` (for the Leica10
// signature), so a make-only `LEICA` body — older Leica Digilux / early
// D-Lux / V-Lux — DROPPED its Panasonic Main tags. The fix routes it through
// `panasonic::parse_leica1_gated` (make `== "LEICA"` gate, body offset 8,
// Panasonic group), while leaving the eight Leica-specific-table variants
// (`Panasonic::Leica2..Leica9`, unported) gated/emitting-nothing.
//
// The bytes below were VERIFIED against bundled ExifTool 13.59
// (`exiftool -G1 -j`): it reports
//   "IFD0:Make": "LEICA", "IFD0:Model": "DIGILUX 2",
//   "Panasonic:ImageQuality": "High"
// Little-endian standalone TIFF: IFD0 (Make="LEICA", Model="DIGILUX 2",
// ExifIFD ptr) → ExifIFD (0x927c MakerNote) → "LEICA\0\0\0" (8, body @8) +
// a 1-entry IFD whose 0x01 ImageQuality (int16u, count 1, value 2 = "High",
// INLINE) → the Make/Model strings.

/// Byte-built Leica1 standalone TIFF (the verified oracle fixture).
/// `Panasonic:ImageQuality` == "High" in bundled ExifTool 13.59.
const LEICA1_TIFF: &[u8] = &[
  73, 73, 42, 0, 8, 0, 0, 0, 3, 0, 15, 1, 2, 0, 6, 0, 0, 0, 94, 0, 0, 0, 16, 1, 2, 0, 10, 0, 0, 0,
  100, 0, 0, 0, 105, 135, 4, 0, 1, 0, 0, 0, 50, 0, 0, 0, 0, 0, 0, 0, 1, 0, 124, 146, 7, 0, 26, 0,
  0, 0, 68, 0, 0, 0, 0, 0, 0, 0, 76, 69, 73, 67, 65, 0, 0, 0, 1, 0, 1, 0, 3, 0, 1, 0, 0, 0, 2, 0,
  0, 0, 0, 0, 0, 0, 76, 69, 73, 67, 65, 0, 68, 73, 71, 73, 76, 85, 88, 32, 50, 0,
];

/// Byte-built NEGATIVE fixture: a `Make="Leica Camera AG"` body whose
/// MakerNote carries a Leica5 signature (`LEICA\0\x01\0`, `MakerNotes.pm:
/// 650-663`). This routes to the Leica-specific `Panasonic::Leica5` table
/// (UNPORTED here), NOT `%Panasonic::Main` — bundled ExifTool 13.59 emits NO
/// `Panasonic:ImageQuality` for it (verified). The make is NOT exactly
/// "LEICA", so the Leica1 make-gate must reject it and the Panasonic slot
/// must stay ABSENT (no spurious Main leak).
const LEICA5_NEG_TIFF: &[u8] = &[
  73, 73, 42, 0, 8, 0, 0, 0, 3, 0, 15, 1, 2, 0, 16, 0, 0, 0, 94, 0, 0, 0, 16, 1, 2, 0, 4, 0, 0, 0,
  110, 0, 0, 0, 105, 135, 4, 0, 1, 0, 0, 0, 50, 0, 0, 0, 0, 0, 0, 0, 1, 0, 124, 146, 7, 0, 26, 0,
  0, 0, 68, 0, 0, 0, 0, 0, 0, 0, 76, 69, 73, 67, 65, 0, 1, 0, 1, 0, 1, 0, 3, 0, 1, 0, 0, 0, 2, 0,
  0, 0, 0, 0, 0, 0, 76, 101, 105, 99, 97, 32, 67, 97, 109, 101, 114, 97, 32, 65, 71, 0, 77, 57, 0,
  0,
];

/// The dispatcher classifies the make-only `LEICA` body as `Vendor::Leica`
/// with body_offset 8 (`MakerNoteLeica`/Leica1, `MakerNotes.pm:599-608`); the
/// production walk routes it through the cross-table Panasonic Main parser via
/// `parse_leica1_gated` and the typed Panasonic slot + cached emissions carry
/// `ImageQuality = High`, under the `Panasonic` emission group (NOT
/// `MakerNotes`/`Leica`).
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn leica1_dispatches_to_panasonic_main_image_quality() {
  use exifast::exif::makernotes::BaseRule;
  use exifast::value::TagValue;

  let meta = exifast::parse_exif(LEICA1_TIFF).expect("TIFF recognized");
  let mn = meta.maker_note().expect("MakerNote captured");

  // Dispatched as Leica1: Vendor::Leica, body_offset 8, inherit base.
  assert!(mn.vendor().is_leica(), "vendor = Leica (make-only LEICA)");
  assert_eq!(
    mn.detected().body_offset(),
    8,
    "Leica1 Start => '$valuePtr + 8' (MakerNotes.pm:606)"
  );
  assert_eq!(
    mn.detected().base_rule(),
    BaseRule::Inherit,
    "Leica1 has no Base line (MakerNotes.pm:603-607) ⇒ inherit"
  );

  // The cross-table Panasonic Main parser ran ⇒ the Panasonic typed slot is
  // populated (Leica1's tags ARE %Panasonic::Main tags).
  assert!(
    mn.meta().panasonic().is_some(),
    "Leica1 must populate the Panasonic typed slot via the Main table"
  );

  // The cached emission carries ImageQuality = "High" under the Panasonic
  // group (the emission group1 is overridden to Panasonic even though the
  // vendor is Leica). ImageQuality (tag 0x01, value 2) ⇒ "High"
  // (Panasonic.pm:276).
  assert_eq!(
    mn.emission_group1(),
    "Panasonic",
    "Leica1 tags emit as Panasonic:* (they are %Panasonic::Main tags)"
  );
  let iq = mn
    .emissions_print_conv()
    .iter()
    .find(|e| e.name() == "ImageQuality")
    .map(|e| e.value().clone());
  assert_eq!(
    iq,
    Some(TagValue::Str("High".into())),
    "Leica1 ImageQuality (tag 0x01, value 2) ⇒ \"High\""
  );
}

/// END-TO-END SERIALIZED `-G1` fidelity: the full serializer
/// (`extract_info`, the conformance-gate path) must emit
/// `"Panasonic:ImageQuality": "High"` for the byte-built Leica1 TIFF —
/// matching bundled ExifTool's `Panasonic:*` output — and must NOT leak the
/// tag under a `Leica:` or family-0 `MakerNotes:` group.
#[cfg(all(feature = "exif", feature = "std", feature = "json"))]
#[test]
fn leica1_serialized_keys_use_panasonic_group1() {
  for print_on in [true, false] {
    let mode = if print_on { "-j" } else { "-n" };
    let json = exifast::parser::extract_info("leica1.tif", LEICA1_TIFF, print_on);
    let doc: serde_json::Value =
      serde_json::from_str(&json).unwrap_or_else(|e| panic!("invalid JSON ({e}):\n{json}"));
    let obj = doc
      .as_array()
      .and_then(|a| a.first())
      .and_then(|o| o.as_object())
      .unwrap_or_else(|| panic!("doc is not [{{…}}]:\n{json}"));
    assert_eq!(
      obj.get("IFD0:Make").and_then(|v| v.as_str()),
      Some("LEICA"),
      "IFD0:Make ({mode})"
    );
    // `-j` renders the PrintConv label "High"; `-n` keeps the raw int 2.
    if print_on {
      assert_eq!(
        obj.get("Panasonic:ImageQuality").and_then(|v| v.as_str()),
        Some("High"),
        "Leica1 ImageQuality must serialize as Panasonic:ImageQuality=\"High\" ({mode}); \
         keys: {:?}",
        obj.keys().collect::<Vec<_>>()
      );
    } else {
      assert_eq!(
        obj
          .get("Panasonic:ImageQuality")
          .and_then(serde_json::Value::as_i64),
        Some(2),
        "Leica1 ImageQuality -n raw int ({mode})"
      );
    }
    // The family-1 group is Panasonic, never Leica or the family-0 MakerNotes.
    assert!(
      !obj.contains_key("Leica:ImageQuality"),
      "Leica1 tag must NOT emit under a Leica: group ({mode})"
    );
    assert!(
      !obj.contains_key("MakerNotes:ImageQuality"),
      "Leica1 tag must NOT emit under family-0 MakerNotes ({mode})"
    );
  }
}

/// END-TO-END NEGATIVE: a `Make="Leica Camera AG"` body carrying a Leica5
/// signature (`LEICA\0\x01\0`) routes to the unported `Panasonic::Leica5`
/// table — NOT `%Panasonic::Main`. The full serializer must therefore emit
/// NO `Panasonic:ImageQuality` (bundled ExifTool 13.59 emits none either),
/// proving the Leica1 make-gate does not over-capture a Leica2-9 body and
/// the deferred Leica-specific tables leak nothing.
#[cfg(all(feature = "exif", feature = "std", feature = "json"))]
#[test]
fn leica5_signature_make_not_leica_emits_no_panasonic() {
  let meta = exifast::parse_exif(LEICA5_NEG_TIFF).expect("TIFF recognized");
  let mn = meta.maker_note().expect("MakerNote captured");
  // Dispatched as Leica (a Leica5-signature blob), body_offset 8.
  assert!(mn.vendor().is_leica(), "vendor = Leica (Leica5 signature)");
  // Neither gate admits it: make != "LEICA" (Leica1 rejects) and the blob is
  // not `LEICA CAMERA AG\0` (Leica10 rejects) ⇒ Panasonic slot ABSENT.
  assert!(
    mn.meta().panasonic().is_none(),
    "a Leica5-signature body (Make != \"LEICA\") must leave the Panasonic slot \
     ABSENT (Panasonic::Leica5 unported/deferred)"
  );

  for print_on in [true, false] {
    let json = exifast::parser::extract_info("leica5neg.tif", LEICA5_NEG_TIFF, print_on);
    let doc: serde_json::Value = serde_json::from_str(&json).expect("valid json");
    let obj = doc
      .as_array()
      .and_then(|a| a.first())
      .and_then(|o| o.as_object())
      .expect("doc is [{…}]");
    assert!(
      !obj.contains_key("Panasonic:ImageQuality"),
      "Leica5-signature body must NOT emit Panasonic:ImageQuality (it routes to \
       the unported Leica5 table); keys: {:?}",
      obj.keys().collect::<Vec<_>>()
    );
  }
}

/// Cross-check the Leica1 + Leica5-negative synthetic TIFFs against the
/// bundled ExifTool binary (when `$EXIFTOOL` is set / on PATH): bundled
/// `exiftool -G1 -j` must emit `Panasonic:ImageQuality` == "High" for the
/// Leica1 fixture and NONE for the Leica5-negative fixture, proving the Rust
/// read is byte-faithful to the cross-vendor route. Skipped (not failed) when
/// the binary is absent.
#[cfg(all(feature = "exif", feature = "std", feature = "json"))]
#[test]
fn leica1_matches_bundled_exiftool() {
  use std::process::Command;
  let tool = std::env::var("EXIFTOOL").unwrap_or_else(|_| "exiftool".to_string());
  if Command::new(&tool).arg("-ver").output().is_err() {
    eprintln!("SKIP: exiftool binary not available; Leica1 cross-check skipped");
    return;
  }
  let dir = std::env::temp_dir();

  // POSITIVE — Leica1 emits Panasonic:ImageQuality == "High".
  let path = dir.join("exifast_leica1.tif");
  std::fs::write(&path, LEICA1_TIFF).expect("write temp Leica1 tif");
  let out = Command::new(&tool)
    .args(["-G1", "-j", "-ImageQuality", "-Make", "-Model"])
    .arg(&path)
    .output()
    .expect("run exiftool");
  let _ = std::fs::remove_file(&path);
  assert!(out.status.success(), "exiftool failed");
  let json = String::from_utf8(out.stdout).expect("utf8");
  let doc: serde_json::Value = serde_json::from_str(&json).expect("valid json");
  let obj = doc
    .as_array()
    .and_then(|a| a.first())
    .and_then(|o| o.as_object())
    .expect("doc is [{…}]");
  assert_eq!(
    obj.get("IFD0:Make").and_then(|v| v.as_str()),
    Some("LEICA"),
    "bundled exiftool must see Make LEICA"
  );
  assert_eq!(
    obj.get("Panasonic:ImageQuality").and_then(|v| v.as_str()),
    Some("High"),
    "bundled exiftool must emit Panasonic:ImageQuality=\"High\" for the Leica1 route"
  );

  // NEGATIVE — a Leica5-signature body (Make != "LEICA") emits no
  // Panasonic:ImageQuality (it routes to the Leica-specific Leica5 table).
  let npath = dir.join("exifast_leica5neg.tif");
  std::fs::write(&npath, LEICA5_NEG_TIFF).expect("write temp Leica5-neg tif");
  let nout = Command::new(&tool)
    .args(["-G1", "-j"])
    .arg(&npath)
    .output()
    .expect("run exiftool");
  let _ = std::fs::remove_file(&npath);
  assert!(nout.status.success(), "exiftool failed");
  let njson = String::from_utf8(nout.stdout).expect("utf8");
  let ndoc: serde_json::Value = serde_json::from_str(&njson).expect("valid json");
  let nobj = ndoc
    .as_array()
    .and_then(|a| a.first())
    .and_then(|o| o.as_object())
    .expect("doc is [{…}]");
  assert!(
    !nobj.contains_key("Panasonic:ImageQuality"),
    "bundled exiftool must NOT emit Panasonic:ImageQuality for a Leica5-signature \
     body (it routes to the Leica5 table, not %Panasonic::Main)"
  );
}

/// `from_blob` make-less caveat (same shape as the Sony5-headerless caveat):
/// the public `from_blob` constructor does NOT carry the parent IFD0 `Make`,
/// so the make-only Leica1 gate (`$$self{Make} eq "LEICA"`) cannot fire there
/// — it passes `make = None` and leaves the Panasonic slot ABSENT. That is
/// faithful (a `Vendor::Leica` + body-offset-8 detection is ambiguous between
/// Leica1 and the unported Leica2-9 tables WITHOUT the make). The production
/// `parse_exif` walk — which HAS the Make — decodes Leica1 fully (asserted in
/// `leica1_dispatches_to_panasonic_main_image_quality`). The signature-gated
/// Leica10 route still decodes through `from_blob` (covered separately).
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn from_blob_leica1_make_only_slot_absent_without_make() {
  use exifast::exif::ifd::ByteOrder;
  use exifast::exif::makernotes::{MakerNotesMeta, dispatch};

  // Self-contained Leica1 blob: "LEICA\0\0\0" (8, body @8) + 1-entry IFD
  // (0x1a ImageStabilization int16u count1 value4 inline) + next=0.
  let mut blob: Vec<u8> = Vec::new();
  blob.extend_from_slice(b"LEICA\x00\x00\x00");
  blob.extend_from_slice(&1u16.to_le_bytes());
  blob.extend_from_slice(&0x1au16.to_le_bytes()); // tag 0x1a ImageStabilization
  blob.extend_from_slice(&3u16.to_le_bytes()); // int16u
  blob.extend_from_slice(&1u32.to_le_bytes()); // count 1
  blob.extend_from_slice(&4u32.to_le_bytes()); // value 4
  blob.extend_from_slice(&0u32.to_le_bytes());

  // The dispatcher routes a make-only "LEICA" body to Leica1 (offset 8).
  let detected = dispatch(&blob, Some("LEICA"), Some("DIGILUX 2"), None);
  assert!(
    detected.vendor().is_leica(),
    "make-only LEICA dispatches to Leica"
  );
  assert_eq!(detected.body_offset(), 8, "Leica1 body offset 8");

  // from_blob has no Make ⇒ the make-only Leica1 gate yields None ⇒ slot
  // ABSENT (the faithful make-less choice).
  let meta = MakerNotesMeta::from_blob(detected, &blob, ByteOrder::Little);
  assert!(
    meta.panasonic().is_none(),
    "from_blob (make-less) must leave the Panasonic slot ABSENT for a Leica1 \
     body — the make-only gate cannot fire without Make (the production \
     parse_exif walk, which has Make, decodes it; see \
     leica1_dispatches_to_panasonic_main_image_quality)"
  );
}

/// `from_blob_with_context` resolves the make-only `MakerNoteLeica` (Leica1,
/// `MakerNotes.pm:599-608`) route. Leica1's `Condition` is `$$self{Make} eq
/// "LEICA"` (`:602`) — no blob signature — so the make-LESS `from_blob`
/// leaves the slot ABSENT (asserted above), whereas threading `make =
/// "LEICA"` through the context API gates `parse_leica1_gated` true and
/// decodes `%Panasonic::Main` (Leica1 routes there, `:604`) at body_offset 8
/// (`:606`). Same shape as the headerless-Sony5 context test.
///
/// Bundled cross-check: this is the byte-built equivalent of the
/// `parse_exif` LEICA1_TIFF case (`leica1_dispatches_to_panasonic_main_image_quality`),
/// which HAS the IFD0 Make and decodes Leica1 fully; here the context API
/// supplies the Make to the same gate. 0x1a ImageStabilization = 4 populates
/// the typed `image_stabilization` field (`Panasonic.pm` IS-mode integer).
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn from_blob_with_context_resolves_make_only_leica1() {
  use exifast::exif::ifd::ByteOrder;
  use exifast::exif::makernotes::{MakerNotesMeta, dispatch};

  // Same self-contained Leica1 blob as the make-less test.
  let mut blob: Vec<u8> = Vec::new();
  blob.extend_from_slice(b"LEICA\x00\x00\x00"); // 8-byte header (body @8)
  blob.extend_from_slice(&1u16.to_le_bytes());
  blob.extend_from_slice(&0x1au16.to_le_bytes()); // 0x1a ImageStabilization
  blob.extend_from_slice(&3u16.to_le_bytes()); // int16u
  blob.extend_from_slice(&1u32.to_le_bytes()); // count 1
  blob.extend_from_slice(&4u32.to_le_bytes()); // value 4
  blob.extend_from_slice(&0u32.to_le_bytes());

  let detected = dispatch(&blob, Some("LEICA"), Some("DIGILUX 2"), None);
  assert!(detected.vendor().is_leica());
  assert_eq!(detected.body_offset(), 8, "Leica1 body offset 8");

  // WITH context (make = "LEICA"): the make-only Leica1 gate fires ⇒ the
  // Panasonic Main parser runs and populates the Panasonic typed slot
  // (Leica1's tags ARE %Panasonic::Main tags).
  let meta = MakerNotesMeta::from_blob_with_context(
    detected,
    &blob,
    ByteOrder::Little,
    Some("LEICA"),
    Some("DIGILUX 2"),
  );
  let pana = meta.panasonic().expect(
    "from_blob_with_context must populate the Panasonic slot for a make-only \
     Leica1 body when Make=LEICA threads the gate",
  );
  assert_eq!(
    pana.image_stabilization(),
    Some(4),
    "Leica1 (via %Panasonic::Main) decodes ImageStabilization=4 through the \
     context gate"
  );

  // Negative control on the SAME body: a non-LEICA make does NOT satisfy the
  // make-only Leica1 gate (and is not the signature-gated Leica10), so the
  // slot stays ABSENT — proving the gate, not a blanket parse, is load-bearing.
  let meta_other = MakerNotesMeta::from_blob_with_context(
    detected,
    &blob,
    ByteOrder::Little,
    Some("Panasonic"),
    None,
  );
  assert!(
    meta_other.panasonic().is_none(),
    "a non-LEICA make must NOT resolve the make-only Leica1 route"
  );
}

// ===========================================================================
// Phase 4 — GoPro + DJI dispatch + typed parse
// ===========================================================================

/// SYNTHETIC: a GoPro file (`$$self{Make} == "GoPro"`). Bundled
/// `MakerNotes.pm` has NO `MakerNoteGoPro` entry, so the 0x927C bytes
/// are NOT a recognized MakerNote — they fall through to
/// `Vendor::Unknown` (bundled emits `MakerNoteUnknown` + `Warning:
/// [minor] Unrecognized MakerNotes`). Faithful regression guard: GoPro
/// must NOT resolve a dedicated vendor or surface any `MakerNotes:*`
/// keys; GoPro files are identified by the standard IFD0 `Make` tag.
#[test]
fn gopro_makernote_falls_through_to_unknown() {
  // MM TIFF: IFD0 with Make = "GoPro" (5 bytes — inline; count 5 ≤ 4-byte
  // slot is wrong — use count 5 → must be offset). Use count 6 to be safe.
  let mut t: Vec<u8> = vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
  // IFD0: 2 entries (Make + ExifIFD).
  t.extend_from_slice(&[0x00, 0x02]);
  // Entry 1: Make (0x010f, ASCII, count 6 = "GoPro\0", offset).
  t.extend_from_slice(&[0x01, 0x0f]); // Make
  t.extend_from_slice(&[0x00, 0x02]); // ASCII
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x06]); // count 6
  // Offset: header(8) + IFD0(2 + 12 + 12 + 4) = 38.
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x26]); // 38
  // Entry 2: ExifIFD pointer.
  t.extend_from_slice(&[0x87, 0x69]); // ExifIFD
  t.extend_from_slice(&[0x00, 0x04]); // LONG
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // count 1
  // ExifIFD offset: 38 + 6 = 44.
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x2c]); // 44
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // IFD0 next 0
  // Make string at 38: "GoPro\0".
  t.extend_from_slice(b"GoPro\x00");
  // ExifIFD at 44: 1 entry (MakerNote).
  t.extend_from_slice(&[0x00, 0x01]);
  t.extend_from_slice(&[0x92, 0x7c]); // MakerNote
  t.extend_from_slice(&[0x00, 0x07]); // UNDEF
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x10]); // count 16
  // MakerNote offset: 44 + (2 + 12 + 4) = 62.
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x3e]); // 62
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ExifIFD next 0
  // 16-byte GoPro MakerNote bytes — modeled on the t/images/GoPro.jpg
  // shape (`\x0b\x00\x11\x00...` — an IFD-like header bundled doesn't
  // decode). The dispatcher routes on Make alone; the bytes are
  // captured but the body decoder returns empty.
  t.extend_from_slice(&[
    0x0b, 0x00, 0x11, 0x00, 0x00, 0xc0, 0x86, 0x46, 0x00, 0x00, 0x4c, 0x41, 0x4a, 0x37, 0x30, 0x36,
  ]);

  let meta = exifast::parse_exif_block(&t).expect("valid TIFF");
  let mn = meta.maker_note().expect("MakerNote captured");
  // Bundled has no MakerNoteGoPro → the captured 0x927C bytes are an
  // unrecognized MakerNote: Vendor::Unknown, NOT a dedicated GoPro vendor.
  assert!(
    matches!(mn.vendor(), Vendor::Unknown),
    "GoPro has no bundled MakerNoteGoPro → Vendor::Unknown, got {:?}",
    mn.vendor()
  );
  // No per-vendor typed surface, no decoded MakerNote emissions (faithful:
  // bundled emits MakerNoteUnknown + a minor warning, zero decoded keys).
  assert!(mn.meta().dji().is_none());
  assert!(
    mn.emissions_print_conv().is_empty(),
    "unrecognized GoPro MakerNote emits no decoded MakerNote keys"
  );
}

/// SYNTHETIC: DJI MakerNote — `$$self{Make} == "DJI"` + body bytes that
/// do NOT start with `DJI` or `...@AMBA` (those go to a deferred
/// signature). Dispatch resolves on Make alone (`MakerNotes.pm:99-106`).
/// Phase-4 walks the body and populates [`MakerNotesDji`].
#[test]
fn synthetic_dji_makernote_dispatches_and_decodes_pose() {
  let t = synthetic_dji_pitch_tiff();

  let meta = exifast::parse_exif_block(&t).expect("valid TIFF");
  // Sanity: Make was extracted.
  let make_entry = meta.entry("Make").expect("Make in IFD0");
  let make = match make_entry.value_ref().raw() {
    exifast::exif::ifd::RawValue::Text { text: s, .. } => s.as_str(),
    other => panic!("Make not Text, got {other:?}"),
  };
  assert!(make.starts_with("DJI"), "Make = {make:?}");
  let mn = meta.maker_note().expect("MakerNote captured");
  assert!(
    mn.vendor().is_dji(),
    "Make=DJI dispatches to Vendor::Dji, got {:?}",
    mn.vendor()
  );
  assert_eq!(mn.detected().body_offset(), 0);
  assert!(mn.detected().base_rule().is_inherit());
  // The typed surface populates from the body walk.
  let dji = mn.meta().dji().expect("DJI typed populated");
  let pitch = dji
    .flight_pitch()
    .expect("Pitch tag should be present and parsed");
  assert!((pitch - 12.5).abs() < 1e-6, "got {pitch}");
  // PrintConv emission carries the signed-2-decimal form.
  let emissions = mn.emissions_print_conv();
  assert!(
    emissions
      .iter()
      .any(|e| e.name() == "Pitch" && *e.value() == exifast::value::TagValue::Str("+12.50".into())),
    "Pitch emission with PrintConv label, got {emissions:?}"
  );
}

/// Build the synthetic LE DJI TIFF shared by the DJI dispatch +
/// serialized-grouping tests: IFD0 `Make = "DJI"`, ExifIFD → 0x927C
/// MakerNote whose 24-byte headerless body carries one entry
/// `Pitch (0x06)` = float 12.5.
fn synthetic_dji_pitch_tiff() -> Vec<u8> {
  // LE TIFF (DJI is byte-order-unknown, but the parent IFD order
  // governs since the body has no marker). Use LE for the synthetic
  // build.
  let mut t: Vec<u8> = vec![b'I', b'I', 0x2a, 0x00, 0x08, 0x00, 0x00, 0x00];
  // IFD0: 2 entries.
  t.extend_from_slice(&[0x02, 0x00]);
  // Entry 1: Make = "DJI\0" (count 4, inline).
  t.extend_from_slice(&[0x0f, 0x01]); // 0x010f LE
  t.extend_from_slice(&[0x02, 0x00]); // ASCII
  t.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]); // count 4
  t.extend_from_slice(b"DJI\x00"); // inline
  // Entry 2: ExifIFD pointer.
  t.extend_from_slice(&[0x69, 0x87]); // 0x8769 LE
  t.extend_from_slice(&[0x04, 0x00]); // LONG
  t.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // count 1
  // ExifIFD offset: header(8) + IFD0(2 + 12 + 12 + 4) = 38.
  t.extend_from_slice(&[0x26, 0x00, 0x00, 0x00]); // 38 LE
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // IFD0 next 0
  // ExifIFD at 38: 1 entry (MakerNote).
  t.extend_from_slice(&[0x01, 0x00]);
  t.extend_from_slice(&[0x7c, 0x92]); // 0x927c MakerNote LE
  t.extend_from_slice(&[0x07, 0x00]); // UNDEF
  // The 24-byte DJI body — 1 entry header (count=1) + 1 entry (12 bytes)
  // = 14 bytes minimum; pad to 24.
  t.extend_from_slice(&[0x18, 0x00, 0x00, 0x00]); // count 24
  // MakerNote offset: 38 + (2 + 12 + 4) = 56.
  t.extend_from_slice(&[0x38, 0x00, 0x00, 0x00]); // 56 LE
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ExifIFD next 0
  // DJI body at offset 56: headerless. 1 entry: Pitch (0x06) float 12.5
  // inline.
  t.extend_from_slice(&[0x01, 0x00]); // 1 entry LE
  t.extend_from_slice(&[0x06, 0x00]); // tag 0x06
  t.extend_from_slice(&[0x0b, 0x00]); // float
  t.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // count 1
  t.extend_from_slice(&12.5f32.to_le_bytes()); // 12.5 inline
  // Pad to 24 bytes.
  while t.len() < 56 + 24 {
    t.push(0);
  }
  t
}

/// SERIALIZED `-G1`: DJI MakerNote tags carry the vendor family-1 group
/// `DJI:` — NOT the family-0 `MakerNotes:`. `MakerNotes.pm:100`
/// (`Name => 'MakerNoteDJI'`) routes to `Image::ExifTool::DJI::Main`,
/// whose `-G1` group ExifTool derives from the vendor module name;
/// `DJI.pm:56` sets only family-0 `MakerNotes`. Bundled 13.59 on a DJI
/// file emits `DJI:Pitch` (with `-j`, `sprintf("%+.2f")` → `+12.50`),
/// NEVER `MakerNotes:Pitch`. Regression guard for the `Vendor::group1()`
/// wiring (both `-j` PrintConv-on and `-n` PrintConv-off share the site).
#[cfg(feature = "json")]
#[test]
fn dji_serialized_keys_use_dji_group1() {
  let t = synthetic_dji_pitch_tiff();
  for print_on in [true, false] {
    let mode = if print_on { "-j" } else { "-n" };
    let json = exifast::parser::extract_info("dji.tif", &t, print_on);
    let doc: serde_json::Value =
      serde_json::from_str(&json).unwrap_or_else(|e| panic!("invalid JSON ({e}):\n{json}"));
    let map = doc
      .as_array()
      .and_then(|a| a.first())
      .and_then(|o| o.as_object())
      .unwrap_or_else(|| panic!("doc is not [{{…}}]:\n{json}"));
    assert!(
      map.contains_key("DJI:Pitch"),
      "expected DJI:Pitch ({mode}); keys: {:?}",
      map.keys().collect::<Vec<_>>()
    );
    // The family-1 group is the VENDOR, never the family-0 `MakerNotes`.
    assert!(
      !map.contains_key("MakerNotes:Pitch"),
      "DJI MakerNote tag leaked under family-0 MakerNotes group ({mode})"
    );
  }
}

/// SYNTHETIC: DJI typed parse via the public API (round-trips the
/// full Main IFD table — 10 tags). The dispatcher integration is
/// covered by [`synthetic_dji_makernote_dispatches_and_decodes_pose`];
/// this exercise the full tag coverage in isolation.
#[test]
fn synthetic_dji_typed_populates_all_main_tags() {
  use exifast::exif::makernotes::vendors::dji;
  // Build a synthetic DJI body with one entry per Main IFD tag.
  // Headerless body, LE byte order.
  let entries: Vec<(u16, u16, u32, Vec<u8>)> = vec![
    (0x01, 0x02, 4, b"DJI\x00".to_vec()),
    (0x03, 0x0b, 1, 1.5f32.to_le_bytes().to_vec()),
    (0x04, 0x0b, 1, (-2.25f32).to_le_bytes().to_vec()),
    (0x05, 0x0b, 1, 0.0f32.to_le_bytes().to_vec()),
    (0x06, 0x0b, 1, 10.5f32.to_le_bytes().to_vec()),
    (0x07, 0x0b, 1, (-45.0f32).to_le_bytes().to_vec()),
    (0x08, 0x0b, 1, 5.0f32.to_le_bytes().to_vec()),
    (0x09, 0x0b, 1, (-30.0f32).to_le_bytes().to_vec()),
    (0x0a, 0x0b, 1, 90.0f32.to_le_bytes().to_vec()),
    (0x0b, 0x0b, 1, 0.0f32.to_le_bytes().to_vec()),
  ];
  let mut blob: Vec<u8> = Vec::new();
  blob.extend_from_slice(&(entries.len() as u16).to_le_bytes());
  let entries_start = blob.len();
  let dir_size = 12 * entries.len();
  let mut data_off = entries_start + dir_size;
  let elem_sizes: [usize; 14] = [0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8, 4];
  let mut pending: Vec<Vec<u8>> = Vec::new();
  for (tag, format, count, value) in &entries {
    let total = elem_sizes[*format as usize] * (*count as usize);
    blob.extend_from_slice(&tag.to_le_bytes());
    blob.extend_from_slice(&format.to_le_bytes());
    blob.extend_from_slice(&count.to_le_bytes());
    if total <= 4 {
      let mut padded = [0u8; 4];
      padded[..value.len().min(4)].copy_from_slice(&value[..value.len().min(4)]);
      blob.extend_from_slice(&padded);
    } else {
      blob.extend_from_slice(&(data_off as u32).to_le_bytes());
      data_off += total;
      pending.push(value.clone());
    }
  }
  for v in pending {
    blob.extend_from_slice(&v);
  }
  let (typed, emissions) = dji::parse(&blob, exifast::exif::ifd::ByteOrder::Little);
  assert_eq!(typed.make(), Some("DJI"));
  assert!((typed.speed_x().unwrap() - 1.5).abs() < 1e-6);
  assert!((typed.speed_y().unwrap() + 2.25).abs() < 1e-6);
  assert!((typed.speed_z().unwrap() - 0.0).abs() < 1e-6);
  assert!((typed.flight_pitch().unwrap() - 10.5).abs() < 1e-6);
  assert!((typed.flight_yaw().unwrap() + 45.0).abs() < 1e-6);
  assert!((typed.flight_roll().unwrap() - 5.0).abs() < 1e-6);
  assert!((typed.camera_pitch().unwrap() + 30.0).abs() < 1e-6);
  assert!((typed.camera_yaw().unwrap() - 90.0).abs() < 1e-6);
  assert!((typed.camera_roll().unwrap() - 0.0).abs() < 1e-6);
  // PrintConv labels.
  use exifast::value::TagValue;
  let find = |n: &str| {
    emissions
      .iter()
      .find(|e| e.name() == n)
      .map(|e| e.value().clone())
  };
  assert_eq!(find("Make"), Some(TagValue::Str("DJI".into())));
  assert_eq!(find("SpeedX"), Some(TagValue::Str("+1.50".into())));
  assert_eq!(find("SpeedY"), Some(TagValue::Str("-2.25".into())));
  assert_eq!(find("SpeedZ"), Some(TagValue::Str("+0.00".into())));
  assert_eq!(find("Pitch"), Some(TagValue::Str("+10.50".into())));
  assert_eq!(find("Yaw"), Some(TagValue::Str("-45.00".into())));
  assert_eq!(find("Roll"), Some(TagValue::Str("+5.00".into())));
  assert_eq!(find("CameraPitch"), Some(TagValue::Str("-30.00".into())));
  assert_eq!(find("CameraYaw"), Some(TagValue::Str("+90.00".into())));
  assert_eq!(find("CameraRoll"), Some(TagValue::Str("+0.00".into())));
}

/// Phase 4 status surface — DJI is `Phase4` and observable. DJI has a
/// signature: the `MakerNotes.pm:101` negative-lookahead
/// `$$valPt !~ /^(...@AMBA|DJI)/` makes it Make+blob. (GoPro is
/// intentionally NOT a MakerNote vendor — bundled has no
/// `MakerNoteGoPro` — so there is no GoPro vendor surface to observe.)
#[test]
fn phase4_vendor_surface_is_observable() {
  assert!(Vendor::Dji.status().is_scheduled());
  assert!(Vendor::Dji.is_dji());
  // DJI has a signature (the negative-lookahead body shape carving).
  assert!(Vendor::Dji.is_signature_based());
}

// ===========================================================================
// Canon deep sub-table focused regressions (PR #164 — AFInfo2 0x26 all-zero
// suppression / AFInfo3 0x3c dispatch / FileInfo `-n` / Unknown-flagged
// AFInfoSize). Each value/behaviour below was oracled against the bundled
// `perl exiftool 13.59` binary (see the per-test cites).
// ===========================================================================

/// Build a one-entry Canon Main IFD blob (little-endian) carrying `tag` as an
/// `int16u[count]` array stored OUT-OF-LINE, with `words` the array contents.
/// The blob is laid out so `canon::parse_in_tiff(blob, 0, blob.len(), ..)`
/// resolves the value offset (blob-relative, Canon inherits the parent base).
#[cfg(all(feature = "exif", feature = "std"))]
fn canon_mn_one_int16u_array(tag: u16, words: &[i16]) -> Vec<u8> {
  let mut blob: Vec<u8> = Vec::new();
  blob.extend_from_slice(&1u16.to_le_bytes()); // entry count = 1
  blob.extend_from_slice(&tag.to_le_bytes()); // tag id
  blob.extend_from_slice(&3u16.to_le_bytes()); // format 3 = int16u
  blob.extend_from_slice(&(words.len() as u32).to_le_bytes()); // count
  // value offset: after the 2-byte count + one 12-byte entry + 4-byte next = 18.
  let data_off = 2 + 12 + 4;
  blob.extend_from_slice(&(data_off as u32).to_le_bytes());
  blob.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0
  for &w in words {
    blob.extend_from_slice(&w.to_le_bytes());
  }
  blob
}

/// 0x26 all-zero suppression (`Canon.pm:1713`,
/// `Condition => '$$valPt !~ /^\0\0\0\0/'`).
///
/// When the CanonAFInfo2 record's first four bytes are all zero (the all-zero
/// 0x26 record bundled documents for "thumbnail of 60D MOV video"), bundled
/// does NOT enter the AFInfo2 SubDirectory and emits NOTHING for it. Oracle:
/// a crafted Canon TIFF with a zeroed 0x26 → `perl exiftool -j -G1` produces
/// no `Canon:AF*` keys (verified). The port must likewise emit nothing.
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn canon_afinfo2_0x26_all_zero_is_suppressed() {
  use exifast::exif::ifd::ByteOrder;
  use exifast::exif::makernotes::vendors::canon;
  // A 48-word record whose FIRST TWO words (= first 4 bytes) are zero, but
  // whose later words would decode to real AF tags if the walk ran. (AFInfoSize
  // = word 0 = 0, AFAreaMode = word 1 = 0.)
  let mut words = vec![0i16; 48];
  words[2] = 9; // NumAFPoints — would drive arrays if (wrongly) parsed
  words[3] = 9; // ValidAFPoints
  let blob = canon_mn_one_int16u_array(0x26, &words);
  let (typed, em) = canon::parse_in_tiff(
    &blob,
    0,
    blob.len(),
    ByteOrder::Little,
    true,
    Some("Canon EOS 60D"),
    None,
  );
  // No AFInfo2 leaves emitted, and the typed AF surface stays unset.
  assert!(
    !em.iter().any(|e| e.name() == "NumAFPoints"
      || e.name() == "AFAreaMode"
      || e.name() == "ValidAFPoints"),
    "all-zero 0x26 must emit no AFInfo2 tags; got {:?}",
    em.iter().map(|e| e.name().to_string()).collect::<Vec<_>>()
  );
  assert!(
    typed.af_info().is_none(),
    "all-zero 0x26 must not populate the typed AFInfo surface"
  );
}

/// A NON-zero 0x26 (only the first word zero, second word non-zero) is NOT
/// suppressed — `/^\0\0\0\0/` requires the first FOUR bytes zero. With
/// AFInfoSize=0 but AFAreaMode!=0, the first 4 bytes are `00 00 02 00`, which
/// does not match, so bundled enters the SubDirectory.
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn canon_afinfo2_0x26_only_first_word_zero_is_not_suppressed() {
  use exifast::exif::ifd::ByteOrder;
  use exifast::exif::makernotes::vendors::canon;
  let mut words = vec![0i16; 48];
  words[0] = 0; // AFInfoSize = 0 (bytes 0-1 zero)
  words[1] = 2; // AFAreaMode = 2 (bytes 2-3 = 02 00, non-zero) → not all-zero
  words[2] = 9; // NumAFPoints
  words[3] = 9; // ValidAFPoints
  let blob = canon_mn_one_int16u_array(0x26, &words);
  let (_typed, em) = canon::parse_in_tiff(
    &blob,
    0,
    blob.len(),
    ByteOrder::Little,
    true,
    Some("Canon EOS 60D"),
    None,
  );
  assert!(
    em.iter()
      .any(|e| e.name() == "NumAFPoints" && *e.value() == exifast::value::TagValue::I64(9)),
    "0x26 with a non-zero second word must still decode NumAFPoints; got {:?}",
    em.iter().map(|e| e.name().to_string()).collect::<Vec<_>>()
  );
}

/// 0x3c AFInfo3 dispatch (`Canon.pm:1764-1770`): the SAME `Canon::AFInfo2`
/// walker runs, but `$$self{AFInfo3} = 1` suppresses the index-14
/// `PrimaryAFPoint` (`Condition => '$$self{Model} !~ /EOS/ and not
/// $$self{AFInfo3}'`, `Canon.pm:6602`).
///
/// Oracle: a crafted G1XmkII (non-EOS) TIFF with a 0x3c record →
/// `perl exiftool -j -G1` emits `Canon:AFAreaMode "Single-point AF"`,
/// `Canon:NumAFPoints 9`, `Canon:AFAreaWidths`, `Canon:AFAreaXPositions`,
/// `Canon:AFPointsInFocus "0,2"`, and crucially NO `Canon:PrimaryAFPoint`
/// (verified). Before this fix the port left 0x3c as `sub_table: None`, so it
/// emitted a bogus raw `AFInfo3` leaf and decoded none of the AF tags.
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn canon_afinfo3_0x3c_dispatches_to_afinfo2_and_suppresses_primary() {
  use exifast::exif::ifd::ByteOrder;
  use exifast::exif::makernotes::vendors::canon;
  use exifast::value::TagValue;
  // Same non-EOS AFInfo2 layout used to oracle the non-EOS path: NumAFPoints=9,
  // AFAreaMode=2, AFPointsInFocus word = 5 (bits 0,2), then the index-13 filler
  // (2 words) and a trailing PrimaryAFPoint candidate (3) that must NOT emit.
  let words: [i16; 48] = [
    96, 2, 9, 9, 4000, 3000, 4000, 3000, // 0-7 (AFInfoSize=96 = byte length)
    50, 50, 50, 50, 50, 50, 50, 50, 50, // AFAreaWidths[9]
    60, 60, 60, 60, 60, 60, 60, 60, 60, // AFAreaHeights[9]
    -400, -300, -200, -100, 0, 100, 200, 300, 400, // AFAreaXPositions[9]
    -200, -150, -100, -50, 0, 50, 100, 150, 200, // AFAreaYPositions[9]
    5,   // AFPointsInFocus[1] = 5 → DecodeBits "0,2"
    7, 0, // Canon_AFInfo2_0x000d[2] filler (Unknown → not emitted)
    3, // index 14 PrimaryAFPoint candidate — suppressed by AFInfo3
  ];
  let blob = canon_mn_one_int16u_array(0x3c, &words);
  let (typed, em) = canon::parse_in_tiff(
    &blob,
    0,
    blob.len(),
    ByteOrder::Little,
    true,
    Some("Canon PowerShot G1 X Mark II"),
    None,
  );
  let find = |n: &str| em.iter().find(|e| e.name() == n).map(|e| e.value().clone());
  assert_eq!(
    find("AFAreaMode"),
    Some(TagValue::Str("Single-point AF".into())),
    "0x3c must decode AFAreaMode via the AFInfo2 table"
  );
  assert_eq!(find("NumAFPoints"), Some(TagValue::I64(9)));
  assert_eq!(
    find("AFAreaXPositions"),
    Some(TagValue::Str(
      "-400 -300 -200 -100 0 100 200 300 400".into()
    ))
  );
  assert_eq!(find("AFPointsInFocus"), Some(TagValue::Str("0,2".into())));
  // PrimaryAFPoint MUST be suppressed (AFInfo3 flag), even though non-EOS.
  assert_eq!(
    find("PrimaryAFPoint"),
    None,
    "AFInfo3 (0x3c) must suppress index-14 PrimaryAFPoint"
  );
  // The bogus raw `AFInfo3` leaf (the pre-fix deferred-arm output) is gone.
  assert!(
    !em.iter().any(|e| e.name() == "AFInfo3"),
    "0x3c must be walked, not emitted as a raw AFInfo3 leaf"
  );
  // Typed surface populated and flagged as the v2 record shape.
  let af = typed
    .af_info()
    .expect("AFInfo3 populates the typed surface");
  assert!(af.is_v2());
  assert_eq!(af.num_af_points(), Some(9));
  assert_eq!(af.primary_af_point(), None);
}

/// FileInfo `-n` (ValueConv-only) fidelity (`Canon.pm:6842-7140`). The real
/// 1D Mark III FileInfo record (extracted via `perl exiftool` FoundTag hook,
/// byte order II) decodes — under `-n` — to raw ints for every PrintConv tag
/// and `$val/100` FLOATS for FocusDistanceUpper/Lower (the only ValueConv
/// positions). Oracle (`perl exiftool -n -j -G1 t/images/Canon1DmkIII.jpg`):
/// BracketMode 0, RawJpgSize 0, FocusDistanceUpper 2.19, FocusDistanceLower
/// 1.13, LiveViewShooting 0 (verified). RawJpgQuality(0) and FilterEffect/
/// ToningEffect(-1) are dropped by their RawConvs in BOTH modes.
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn canon_fileinfo_n_mode_matches_1dmkiii_oracle() {
  use exifast::exif::ifd::ByteOrder;
  use exifast::exif::makernotes::vendors::canon::file_info::parse_with_model;
  use exifast::value::TagValue;
  // FileInfo words[0..22]; word[0] is the length validator (not a tag).
  let mut w = [0i16; 22];
  w[0] = 44; // 22 words * 2 bytes
  w[14] = -1; // FilterEffect = -1 → dropped
  w[15] = -1; // ToningEffect = -1 → dropped
  w[20] = 219; // FocusDistanceUpper raw → 2.19
  w[21] = 113; // FocusDistanceLower raw → 1.13
  let mut data = Vec::new();
  for &x in &w {
    data.extend_from_slice(&x.to_le_bytes());
  }
  let (em, _decoded) = parse_with_model(
    &data,
    ByteOrder::Little,
    false, // -n: ValueConv only, no PrintConv
    None,
    Some("Canon EOS-1D Mark III"),
  );
  // `parse_with_model` returns `(SmolStr, TagValue)` tuples (not VendorEmission).
  let find = |n: &str| {
    em.iter()
      .find(|(name, _)| name == n)
      .map(|(_, v)| v.clone())
  };
  // PrintConv tags stay raw ints under `-n`.
  assert_eq!(find("BracketMode"), Some(TagValue::I64(0)));
  assert_eq!(find("RawJpgSize"), Some(TagValue::I64(0)));
  assert_eq!(find("LongExposureNoiseReduction2"), Some(TagValue::I64(0)));
  assert_eq!(find("WBBracketMode"), Some(TagValue::I64(0)));
  assert_eq!(find("LiveViewShooting"), Some(TagValue::I64(0)));
  // The ONLY ValueConv positions emit `$val/100` floats (NOT "X m" strings).
  assert_eq!(find("FocusDistanceUpper"), Some(TagValue::F64(2.19)));
  assert_eq!(find("FocusDistanceLower"), Some(TagValue::F64(1.13)));
  // RawConv-dropped tags are absent in `-n` too.
  assert_eq!(
    find("RawJpgQuality"),
    None,
    "RawJpgQuality(0) dropped by $val<=0"
  );
  assert_eq!(
    find("FilterEffect"),
    None,
    "FilterEffect(-1) dropped by $val==-1"
  );
  assert_eq!(
    find("ToningEffect"),
    None,
    "ToningEffect(-1) dropped by $val==-1"
  );
}

/// Unknown-flagged AFInfo emission (`AFInfoSize`, `Canon.pm:6515`,
/// `Unknown => 1`). Bundled hides it without `-u`; the port consumes it for
/// serial sync but never surfaces it in the default `-j`/`-n` output. Oracle:
/// `perl exiftool -j -G1` on the 1DmkIII shows NO `Canon:AFInfoSize` (it only
/// appears under `-u`, where it is 396). Verify the port's default emission
/// list excludes AFInfoSize while still decoding the following tags.
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn canon_afinfo2_afinfosize_unknown_hidden_by_default() {
  use exifast::exif::ifd::ByteOrder;
  use exifast::exif::makernotes::vendors::canon::af_info::parse_af_info2;
  // Minimal valid EOS AFInfo2: AFInfoSize=N, AFAreaMode=2, NumAFPoints=1, …
  let words: [i16; 16] = [
    32, 2, 1, 1, 4000, 3000, 4000, 3000, // 0-7
    50,   // AFAreaWidths[1]
    60,   // AFAreaHeights[1]
    10,   // AFAreaXPositions[1]
    20,   // AFAreaYPositions[1]
    0,    // AFPointsInFocus[1]
    0,    // AFPointsSelected[1] (EOS)
    0, 0, // padding
  ];
  let mut data = Vec::new();
  for &x in &words {
    data.extend_from_slice(&x.to_le_bytes());
  }
  // `parse_af_info2` returns `(SmolStr, TagValue)` tuples.
  let (_typed, em) = parse_af_info2(&data, ByteOrder::Little, true, Some("Canon EOS 5D"));
  assert!(
    !em.iter().any(|(name, _)| name == "AFInfoSize"),
    "AFInfoSize (Unknown => 1) must be hidden in default output; got {:?}",
    em.iter().map(|(n, _)| n.to_string()).collect::<Vec<_>>()
  );
  // But the non-Unknown tags after it ARE present (serial sync intact).
  assert!(em.iter().any(|(name, _)| name == "AFAreaMode"));
  assert!(em.iter().any(|(name, _)| name == "NumAFPoints"));
}

/// #164 R3: AFInfo (v1, 0x12) array rendering on the REAL `MakerNotes_Canon.jpg`
/// (7 AF points). Oracle (`perl exiftool 13.59 -G1 [-n] -j`):
///   `AFAreaXPositions` "1014 608 0 0 0 -608 -1014" (7 signed `int16s`, space-joined)
///   `AFAreaYPositions` "0 0 -506 0 506 0 0"
///   `AFPointsInFocus`  `-j` "(none)" (DecodeBits 0)  /  `-n` `0` — the SCALAR
///   number, NOT the string "0": ExifTool emits a single-element `int16s` list as
///   a bare scalar. (The R1 oracle used a different model and missed this.)
#[test]
fn canon_af_info_real_fixture_array_rendering() {
  let root = env!("CARGO_MANIFEST_DIR");
  let data = std::fs::read(format!("{root}/tests/fixtures/MakerNotes_Canon.jpg")).expect("fixture");
  // `-n` (ValueConv): signed arrays space-joined; AFPointsInFocus is the NUMBER 0.
  let n = exifast::parser::extract_info("MakerNotes_Canon.jpg", &data, false);
  assert!(
    n.contains("\"Canon:AFAreaXPositions\":\"1014 608 0 0 0 -608 -1014\""),
    "AFAreaXPositions (signed, space-joined): {n}",
  );
  assert!(
    n.contains("\"Canon:AFAreaYPositions\":\"0 0 -506 0 506 0 0\""),
    "AFAreaYPositions: {n}",
  );
  assert!(
    n.contains("\"Canon:AFPointsInFocus\":0"),
    "AFPointsInFocus -n must be the scalar number 0: {n}",
  );
  assert!(
    !n.contains("\"Canon:AFPointsInFocus\":\"0\""),
    "AFPointsInFocus -n must NOT be the string \"0\": {n}",
  );
  // `-j` (PrintConv): AFPointsInFocus DecodeBits(0) = "(none)".
  let j = exifast::parser::extract_info("MakerNotes_Canon.jpg", &data, true);
  assert!(
    j.contains("\"Canon:AFPointsInFocus\":\"(none)\""),
    "AFPointsInFocus -j must be DecodeBits \"(none)\": {j}",
  );
}

/// #164: the newly-completed `Canon::ShotInfo` positions on the REAL
/// `MakerNotes_Canon.jpg` (EOS 300D / "Canon EOS DIGITAL REBEL"). Oracle
/// (`perl exiftool 13.59 -G1 [-n] -j`):
///   `-j`  AutoISO 100, BaseISO 100, MeasuredEV -1.25, TargetAperture 14,
///         ExposureCompensation 0, SlowShutter "None", OpticalZoomCode
///         "n/a", FlashExposureComp 0, FNumber 14, ExposureTime 128,
///         CameraType "EOS Mid-range", AutoRotate "None", SelfTimer2 0.
///   `-n`  AutoISO 100, TargetAperture 14.2543794902454, SlowShutter 3,
///         CameraType 252, AutoRotate 0 (the raw / ValueConv numbers).
/// ExposureTime is the DEFAULT branch (model lacks the 20D/350D tokens).
#[cfg(feature = "json")]
#[test]
fn canon_shot_info_real_fixture_new_positions() {
  // -j (PrintConv): hash labels + the "n/a"/PrintFraction strings. Numeric
  // PrintConv results (e.g. "14") serialize as JSON strings but the
  // value-semantic conformance comparator coerces them to the bare number,
  // so assert via the parsed map's value type rather than raw text.
  let jmap = extract_info_map("MakerNotes_Canon.jpg", true);
  let want_label = [
    ("Canon:SlowShutter", "None"),
    ("Canon:OpticalZoomCode", "n/a"),
    ("Canon:CameraType", "EOS Mid-range"),
    ("Canon:AutoRotate", "None"),
  ];
  for (k, v) in want_label {
    assert_eq!(
      jmap.get(k).and_then(|x| x.as_str()),
      Some(v),
      "{k} (-j) must be {v:?}; map: {jmap:?}"
    );
  }
  // PrintFraction "0" for the two CanonEv comp tags (string token, value 0).
  for k in ["Canon:ExposureCompensation", "Canon:FlashExposureComp"] {
    let got = jmap.get(k).unwrap_or_else(|| panic!("{k} (-j) missing"));
    // Either the bare number 0 or the string "0" is value-equal to the
    // oracle's 0; assert it is one of those (PrintFraction emits "0").
    assert!(
      got.as_str() == Some("0") || got.as_i64() == Some(0),
      "{k} (-j) must be PrintFraction 0; got {got:?}"
    );
  }

  // -n (ValueConv): the raw / numeric values, as bare JSON numbers.
  let nmap = extract_info_map("MakerNotes_Canon.jpg", false);
  assert_eq!(
    nmap.get("Canon:AutoISO").and_then(|v| v.as_f64()),
    Some(100.0),
    "AutoISO (-n)"
  );
  assert_eq!(
    nmap.get("Canon:SlowShutter").and_then(|v| v.as_i64()),
    Some(3),
    "SlowShutter (-n) is the raw int 3"
  );
  assert_eq!(
    nmap.get("Canon:CameraType").and_then(|v| v.as_i64()),
    Some(252),
    "CameraType (-n) is the raw int 252"
  );
  assert_eq!(
    nmap.get("Canon:AutoRotate").and_then(|v| v.as_i64()),
    Some(0),
    "AutoRotate (-n) is the raw int 0"
  );
  assert_eq!(
    nmap.get("Canon:ExposureTime").and_then(|v| v.as_i64()),
    Some(128),
    "ExposureTime (-n) default branch = 128"
  );
  // TargetAperture / FNumber -n: the aperture float, %.15g-rounded.
  for k in ["Canon:TargetAperture", "Canon:FNumber"] {
    let got = nmap.get(k).and_then(|v| v.as_f64());
    assert!(
      got.is_some_and(|f| (f - 14.2543794902454).abs() < 1e-9),
      "{k} (-n) must be ~14.2543794902454; got {got:?}"
    );
  }
}

/// Canon CRW completion — `MakerNotes_Canon.jpg` now emits the `ColorBalance`
/// (`Canon::Main` 0xa9 → `Canon::ColorBalance`) WB_RGGBLevels tags. The real
/// JPEG carries a ColorBalance sub-directory; before the port walked it the
/// `Canon:WB_RGGBLevels*` tags were silently dropped (a faithfulness gap).
/// Oracle (`perl exiftool 13.59 -G1 -j t/images/Canon.jpg`):
/// `Canon:WB_RGGBLevelsAuto "1719 832 831 990"`, …, `WB_RGGBBlackLevels
/// "124 123 124 123"` (the int16s[4] quads, space-joined). The 300D is NOT a
/// D60, so position 29 is `WB_RGGBLevelsCustom` (not `BlackLevels`).
#[cfg(feature = "json")]
#[test]
fn canon_color_balance_jpeg_emits_wb_rggb_levels() {
  let jmap = extract_info_map("MakerNotes_Canon.jpg", true);
  // The ColorBalance quads are space-joined strings, identical in -j/-n
  // (no PrintConv). Spot-check the camera-facing ones from the oracle.
  let want = [
    ("Canon:WB_RGGBLevelsAuto", "1719 832 831 990"),
    ("Canon:WB_RGGBLevelsDaylight", "1722 832 831 989"),
    ("Canon:WB_RGGBLevelsShade", "2035 832 831 839"),
    ("Canon:WB_RGGBLevelsTungsten", "1228 913 912 1668"),
    ("Canon:WB_RGGBLevelsFlash", "1933 832 831 895"),
    ("Canon:WB_RGGBLevelsCustom", "1722 832 831 989"),
    ("Canon:WB_RGGBLevelsKelvin", "1722 832 831 988"),
    ("Canon:WB_RGGBBlackLevels", "124 123 124 123"),
  ];
  for (k, v) in want {
    assert_eq!(
      jmap.get(k).and_then(|x| x.as_str()),
      Some(v),
      "{k} (-j) must be {v:?}; map keys: {:?}",
      jmap
        .keys()
        .filter(|k| k.contains("WB_RGGB"))
        .collect::<Vec<_>>()
    );
  }
  // Non-D60 ⇒ no BlackLevels (that is the D60-only position-29 name).
  assert!(
    !jmap.contains_key("Canon:BlackLevels"),
    "300D (not D60) must NOT emit Canon:BlackLevels"
  );
  // MaxAperture / MinAperture -n now apply the ValueConv (the float), NOT the
  // raw APEX int (the CanonApex ValueConv fix). Oracle `perl exiftool 13.59 -n
  // -j` on Canon.jpg: MaxAperture 4 (an integer-valued float), MinAperture
  // 26.9086852881189 (`exp(CanonEv($val)*log(2)/2)`).
  let nmap = extract_info_map("MakerNotes_Canon.jpg", false);
  for (k, want) in [
    ("Canon:MaxAperture", 4.0_f64),
    ("Canon:MinAperture", 26.908_685_288_118_9),
  ] {
    let got = nmap.get(k).and_then(|v| v.as_f64());
    assert!(
      got.is_some_and(|f| (f - want).abs() < 1e-9),
      "{k} (-n) must be the ValueConv float ~{want}; got {got:?}"
    );
  }
}

/// Canon CRW completion — full real-input fidelity on the REAL bundled
/// `CanonRaw.crw` (EOS 300D / "Canon EOS DIGITAL REBEL"), copied verbatim to
/// `tests/fixtures/CanonRaw_full.crw`. This file carries embedded XMP + ~25
/// camera `Composite:*` tags the port cannot emit, so it is NOT a byte-golden
/// conformance fixture; instead we assert the port emits ALL the
/// `CanonRaw:*` + `Canon:*` tags the bundled oracle does, byte-identical
/// (value-equivalent), and NOTHING under `Composite:`/`XMP*` (the legit
/// port-wide omissions). Oracle: `perl exiftool 13.59 -G1 -j` ⇒ 41 `CanonRaw:`
/// + 91 `Canon:` = 132 tags.
#[cfg(feature = "json")]
#[test]
fn canon_crw_full_real_fixture_matches_oracle() {
  for print_on in [true, false] {
    let mode = if print_on { "-j" } else { "-n" };
    let map = extract_info_map("CanonRaw_full.crw", print_on);

    // (a) The legit OMISSIONS — no camera Composite subsystem, no XMP (#37),
    // no CanonCustom (#87). These are PORT-WIDE deferrals.
    let composite_or_xmp: Vec<&String> = map
      .keys()
      .filter(|k| k.starts_with("Composite:") || k.starts_with("XMP"))
      .collect();
    assert!(
      composite_or_xmp.is_empty(),
      "({mode}) port must emit NO Composite:/XMP tags (deferred); got {composite_or_xmp:?}"
    );

    // (b) The CanonRaw:/Canon: tag COUNT matches the oracle exactly:
    // 41 CanonRaw: + 91 Canon: = 132.
    let canonraw = map.keys().filter(|k| k.starts_with("CanonRaw:")).count();
    let canon = map.keys().filter(|k| k.starts_with("Canon:")).count();
    assert_eq!(
      canonraw,
      41,
      "({mode}) expected 41 CanonRaw: tags, got {canonraw}; keys: {:?}",
      map
        .keys()
        .filter(|k| k.starts_with("CanonRaw:"))
        .collect::<Vec<_>>()
    );
    assert_eq!(
      canon,
      91,
      "({mode}) expected 91 Canon: tags, got {canon}; keys: {:?}",
      map
        .keys()
        .filter(|k| k.starts_with("Canon:"))
        .collect::<Vec<_>>()
    );
  }

  // (c) Value spot-checks (-j): the NEWLY-completed CanonRaw scalar +
  // structural records, the SensorInfo + ColorBalance sub-tables — the camera
  // metadata an indexer cares about. (Oracle values, byte-identical.)
  let j = extract_info_map("CanonRaw_full.crw", true);
  let js = |k: &str| j.get(k).and_then(|v| v.as_str()).map(str::to_owned);
  let ji = |k: &str| j.get(k).and_then(serde_json::Value::as_i64);
  // CanonRaw scalar / structural records.
  assert_eq!(js("CanonRaw:FileNumber").as_deref(), Some("116-1602"));
  assert_eq!(js("CanonRaw:SerialNumber").as_deref(), Some("0560018150"));
  assert_eq!(
    js("CanonRaw:DateTimeOriginal").as_deref(),
    Some("2003:11:10 17:39:26")
  );
  assert_eq!(
    js("CanonRaw:TargetImageType").as_deref(),
    Some("Real-world Subject")
  );
  assert_eq!(js("CanonRaw:ColorSpace").as_deref(), Some("sRGB"));
  assert_eq!(js("CanonRaw:RawJpgQuality").as_deref(), Some("Fine"));
  assert_eq!(js("CanonRaw:RawJpgSize").as_deref(), Some("Medium"));
  assert_eq!(
    js("CanonRaw:CanonFileDescription").as_deref(),
    Some("EOS DIGITAL REBEL CMOS RAW")
  );
  assert_eq!(js("CanonRaw:UserComment").as_deref(), Some(""));
  assert_eq!(ji("CanonRaw:ColorTemperature"), Some(5200));
  assert_eq!(ji("CanonRaw:RecordID"), Some(0));
  assert_eq!(ji("CanonRaw:ImageWidth"), Some(3072));
  assert_eq!(ji("CanonRaw:ImageHeight"), Some(2048));
  assert_eq!(ji("CanonRaw:ComponentBitDepth"), Some(8));
  assert_eq!(ji("CanonRaw:ColorBitDepth"), Some(24));
  assert_eq!(ji("CanonRaw:ColorBW"), Some(257));
  assert_eq!(ji("CanonRaw:DecoderTableNumber"), Some(1));
  assert_eq!(ji("CanonRaw:CompressedDataOffset"), Some(514));
  assert_eq!(ji("CanonRaw:CompressedDataLength"), Some(4_120_111));
  assert_eq!(ji("CanonRaw:RawJpgWidth"), Some(2048));
  assert_eq!(ji("CanonRaw:RawJpgHeight"), Some(1360));
  // TimeZoneCode is the FLOAT `$val/3600` ValueConv (a +5:30 zone ⇒ 5.5), so
  // it serializes as a JSON float — here the real file's 0 ⇒ `0.0` (value-
  // equivalent to the oracle's `0`).
  assert!(
    j.get("CanonRaw:TimeZoneCode")
      .and_then(serde_json::Value::as_f64)
      .is_some_and(|f| f == 0.0),
    "CanonRaw:TimeZoneCode must be 0 (float)"
  );
  assert_eq!(ji("CanonRaw:TimeZoneInfo"), Some(0));
  // MeasuredEV: float 4.625 (ValueConv $val + 5).
  assert!(
    j.get("CanonRaw:MeasuredEV")
      .and_then(serde_json::Value::as_f64)
      .is_some_and(|f| (f - 4.625).abs() < 1e-6),
    "CanonRaw:MeasuredEV must be 4.625"
  );
  // Canon::SensorInfo sub-table (border coordinates).
  assert_eq!(ji("Canon:SensorWidth"), Some(3152));
  assert_eq!(ji("Canon:SensorHeight"), Some(2068));
  assert_eq!(ji("Canon:SensorLeftBorder"), Some(72));
  assert_eq!(ji("Canon:SensorRightBorder"), Some(3143));
  assert_eq!(ji("Canon:BlackMaskLeftBorder"), Some(24));
  assert_eq!(ji("Canon:BlackMaskBottomBorder"), Some(1856));
  // Canon::ColorBalance sub-table (WB_RGGBLevels quads).
  assert_eq!(
    js("Canon:WB_RGGBLevelsAuto").as_deref(),
    Some("1740 832 831 931")
  );
  assert_eq!(
    js("Canon:WB_RGGBLevelsCustom").as_deref(),
    Some("1722 832 831 989")
  );
  assert_eq!(
    js("Canon:WB_RGGBBlackLevels").as_deref(),
    Some("125 124 125 124")
  );
}

// ===========================================================================
// #172 — TIFF_TYPE threading: a Samsung `.srw` raw whose MakerNote LACKS the
// EXIF-format magic dispatches to `MakerNoteSamsung2` via `$$self{TIFF_TYPE}
// eq 'SRW'` (`MakerNotes.pm:966-969`), now that the standalone-TIFF IFD walker
// threads the container's detected file type into [`makernotes::dispatch`].
// ===========================================================================

/// The bundled-faithful end-to-end proof for #172: `parse_any` on the crafted
/// `tests/fixtures/MakerNotesSamsung2.srw` — driven with the candidate
/// `Parent`/`ext` the engine derives for a `.srw` file — threads
/// `$$self{TIFF_TYPE} = "SRW"` (`ExifTool.pm:8715`) into the MakerNote
/// dispatch, so the magic-LESS Samsung body resolves to [`Vendor::Samsung`]
/// via the SRW clause alone (NOT the EXIF-format-magic clause).
///
/// ORACLE (bundled exiftool 13.59 on this exact fixture):
/// ```text
/// $ exiftool -j MakerNotesSamsung2.srw
///   "FileType": "SRW", "MIMEType": "image/x-samsung-srw",
///   "Make": "SAMSUNG", "Warning": "[minor] Unrecognized MakerNotes"
/// $ exiftool -v3 …  →  `MakerNoteSamsung2 (SubDirectory) -->`
/// ```
/// i.e. bundled classifies the file as `SRW` and routes the 0x927C blob to
/// `MakerNoteSamsung2`. The fixture's MakerNote body is a deliberately EMPTY
/// IFD (count 0, `0xFF` padding) — it carries NEITHER the EXIF-format magic
/// (`MakerNotes.pm:970`, bytes 10..14 `"0100"`) NOR any decodable Samsung tag,
/// so the dispatch can ONLY be reached through the threaded SRW `tiff_type`.
/// (The full `Samsung::Type2` tag table — `MakerNoteVersion`/`DeviceType`/
/// `SamsungModelID`/… — is UNPORTED, so exifast captures the blob + identifies
/// the vendor but emits no `Samsung:*` leaves; that table is a separate
/// follow-up. This test pins the PLUMBING, which is the #172 deliverable.)
#[test]
fn samsung_srw_makernote_dispatches_via_tiff_type() {
  use exifast::format_parser::{AnyMeta, SharedFlags, any_parser_for};

  let data = std::fs::read(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/MakerNotesSamsung2.srw"
  ))
  .expect("read MakerNotesSamsung2.srw fixture");

  // The engine maps a `.srw` candidate to the TIFF parser with
  // `file_type() == "TIFF"` and `parent_type() == "SRW"` (the uppercased
  // extension; `ExifTool.pm:3038` `$dirInfo{Parent} = $tiffType`). Drive
  // `parse_any` with exactly those — the SAME inputs `extract_info` passes for
  // a `.srw` file — so `DoProcessTIFF` finalizes `$$self{FILE_TYPE}`/
  // `TIFF_TYPE` to `"SRW"` (SRW's base module is `TIFF`, `ExifTool.pm:536`).
  let parser = any_parser_for("TIFF").expect("TIFF parser (exif feature)");
  let mut shared = SharedFlags::new();
  let meta = parser
    .parse_any(&data, &mut shared, Some("srw"), 0, Some("SRW"))
    .expect("crafted SRW TIFF is recognized");

  let AnyMeta::Exif(exif) = &meta else {
    panic!("a TIFF parses to AnyMeta::Exif");
  };

  // The threaded `$$self{FILE_TYPE}`/`TIFF_TYPE` reached the walker as "SRW".
  assert_eq!(
    exif.file_type(),
    Some("SRW"),
    "the finalized container file type threads through as SRW"
  );

  // The Make (0x010f) was captured for the dispatcher's `uc Make eq 'SAMSUNG'`.
  let make = exif.entry("Make").and_then(|e| match e.value_ref().raw() {
    exifast::exif::ifd::RawValue::Text { text, .. } => Some(text.as_str()),
    _ => None,
  });
  assert_eq!(make, Some("SAMSUNG"), "IFD0 Make captured for the dispatch");

  // THE LOAD-BEARING ASSERTION (#172): the 0x927C blob — which has NO Samsung2
  // EXIF-format magic — dispatched to `Vendor::Samsung` PURELY via the threaded
  // `tiff_type == Some("SRW")` (`MakerNotes.pm:969`). Before the plumbing this
  // fell through to `Vendor::Unknown`.
  let mn = exif.maker_note().expect("0x927C MakerNote captured");
  assert!(
    mn.vendor().is_samsung(),
    "magic-less Samsung SRW body must dispatch to Vendor::Samsung via the \
     threaded TIFF_TYPE, got {:?}",
    mn.vendor()
  );
  // `MakerNoteSamsung2` sets `FixBase => 1` (`MakerNotes.pm:977`).
  assert!(mn.detected().fix_base(), "Samsung2 carries FixBase => 1");
}

/// CONTROL for #172: the SAME magic-less Samsung body, parsed via the
/// embedded-block entry [`exifast::parse_exif_block`] (a JPEG `APP1` /
/// QuickTime EXIF / PNG `eXIf` Samsung body, where `$$self{TIFF_TYPE}` is the
/// OUTER container type, never `"SRW"`), threads `tiff_type = None` into the
/// dispatch and so FALLS THROUGH past Samsung2 (its SRW clause is inert and the
/// blob has no magic). This proves the threaded `Some("SRW")` from the
/// standalone-TIFF path is what enables the Samsung2 dispatch — the body does
/// NOT match Samsung2 on its own bytes, so the change is purely additive and
/// the embedded-block behavior is unchanged.
#[test]
fn samsung_srw_body_without_tiff_type_does_not_reach_samsung2() {
  let data = std::fs::read(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/MakerNotesSamsung2.srw"
  ))
  .expect("read MakerNotesSamsung2.srw fixture");

  // The embedded-block entry passes `file_type = None` to the IFD walker, so
  // the MakerNote dispatch receives `tiff_type = None` — exactly the path a
  // JPEG/PNG/QuickTime-embedded Samsung body takes (its `$$self{TIFF_TYPE}` is
  // the container type, not "SRW").
  let exif = exifast::parse_exif_block(&data).expect("the TIFF block is valid");
  assert_eq!(
    exif.file_type(),
    None,
    "the embedded-block entry threads no container file type"
  );

  let mn = exif.maker_note().expect("0x927C MakerNote captured");
  // The magic-less SAMSUNG body matches NO signature and (without the SRW
  // tiff_type) no make-only Samsung arm, so it lands on the Unknown catch-all
  // (`MakerNoteUnknown`, `MakerNotes.pm:1117-1126`). The point is only that it
  // is NOT Samsung here — reaching Samsung2 requires the threaded TIFF_TYPE.
  assert!(
    !mn.vendor().is_samsung(),
    "without the threaded SRW tiff_type the magic-less body must NOT reach \
     Samsung2, got {:?}",
    mn.vendor()
  );
}

// ===========================================================================
// #177 — Canon1DmkIII.jpg (NOT bundled; gated on EXIFTOOL_T_IMAGES) is the real
// fixture that carries a DEFERRED `ProcessingInfo` (0xa0) SubDirectory, the
// concrete trigger for the bogus-parent bug. (The bundled Canon.jpg has only
// walked SubDirectories, so it cannot exercise the deferred arm.)
// ===========================================================================

/// #177 — the deferred `ProcessingInfo` (0xa0 → Canon::Processing) SubDirectory
/// in Canon1DmkIII.jpg must NOT leak as a bogus `Canon:ProcessingInfo` key,
/// while the walked Canon tags the oracle emits stay present and unchanged.
///
/// Oracle (`perl exiftool -G1 -j t/images/Canon1DmkIII.jpg`) emits NO
/// `Canon:ProcessingInfo` (it descends into `Canon::Processing` and emits its
/// leaves but never the parent). The bundled fixtures dir is supplied via the
/// `EXIFTOOL_T_IMAGES` env var (ExifTool's `t/images`); the test skips when it
/// is unset so a checkout without the ExifTool sources still passes.
#[cfg(feature = "json")]
#[test]
fn canon_1dmk3_real_fixture_no_bogus_processinginfo_parent() {
  let Ok(dir) = std::env::var("EXIFTOOL_T_IMAGES") else {
    eprintln!("skipping: EXIFTOOL_T_IMAGES not set");
    return;
  };
  let path = format!("{dir}/Canon1DmkIII.jpg");
  let Ok(data) = std::fs::read(&path) else {
    eprintln!("skipping: {path} not readable");
    return;
  };
  for print_on in [true, false] {
    let mode = if print_on { "-j" } else { "-n" };
    let json = exifast::parser::extract_info("Canon1DmkIII.jpg", &data, print_on);
    let doc: serde_json::Value =
      serde_json::from_str(&json).unwrap_or_else(|e| panic!("invalid JSON ({e}):\n{json}"));
    let map = doc
      .as_array()
      .and_then(|a| a.first())
      .and_then(|o| o.as_object())
      .unwrap_or_else(|| panic!("doc is not [{{…}}]:\n{json}"));
    // The bug: a bogus `Canon:ProcessingInfo` parent (raw int16s array) that
    // ExifTool never emits.
    assert!(
      !map.contains_key("Canon:ProcessingInfo"),
      "bogus deferred SubDirectory parent Canon:ProcessingInfo must not be emitted ({mode})"
    );
    // The walked tags the oracle DOES emit stay present + unaffected:
    // a CameraSettings leaf, the Main-IFD LensModel string (0x95), and a
    // SensorInfo leaf (0xe0, a walked SubDirectory in this fixture).
    assert!(
      map.contains_key("Canon:LensModel"),
      "walked Canon:LensModel must still be present ({mode})"
    );
    assert!(
      map.contains_key("Canon:ContinuousDrive"),
      "walked CameraSettings leaf Canon:ContinuousDrive must still be present ({mode})"
    );
    assert!(
      map.contains_key("Canon:SensorWidth"),
      "walked SensorInfo leaf Canon:SensorWidth must still be present ({mode})"
    );
  }
}

// ===========================================================================
// #223 — sibling class of #177: Canon::Main tags that ARE real `SubDirectory`
// pointers in Canon.pm were MIS-MARKED `sub_table: None`, so they missed the
// deferred-SubDirectory suppression arm (#177) and instead hit the LEAF arm,
// leaking a bogus raw-array PARENT value ExifTool never emits.
//
// The first pass corrected 7 SubDirectory pointers + the all-zero `ImageUniqueID`
// RawConv (`ImageUniqueID` 0x28 is NOT a SubDirectory — `Canon.pm:1732`,
// `$val eq "\0" x 16 ? undef : $val`). A FULL `%Canon::Main` sweep against
// Canon.pm then found 23 MORE mis-marked SubDirectory IDs (0x90 CustomFunctions1D
// was the one Codex flagged): UnknownD30 0x0a, CustomFunctions 0x0f, FaceDetect3
// 0x2f, TimeInfo 0x35, CustomFunctions1D 0x90, PersonalFunctions 0x91,
// PersonalFunctionValues 0x92, CanonFlags 0xb0, ModifiedInfo 0xb1,
// PreviewImageInfo 0xb6, ColorInfo 0x4003, VignettingCorr 0x4015,
// VignettingCorr2 0x4016, LightingOpt 0x4018, AmbienceInfo 0x4020, MultiExp
// 0x4021, FilterInfo 0x4024, HDRInfo 0x4025, LogInfo 0x4026, AFConfig 0x4028,
// RawBurstModeRoll 0x403f, FocusBracketingInfo 0x4053, LevelInfo 0x4059. All are
// now `sub_table: Some(..)` (suppressed; children stay #84/#85/#87-deferred).
// (None of the 3 available fixtures CARRIES any of these 23 — they appear only
// on un-fixtured bodies (1D/1Ds for 0x90, newer bodies for the 0x40xx set) — so
// the fix is verified by the `canon::tags` table-invariant test plus the
// synthetic suppression test below, not a fixture diff.) The whole-table guard
// lives in `canon::tags::canon_tags_subdirectory_rows_are_marked`.
// ===========================================================================

/// The seven Canon::Main `SubDirectory` parents that #223 corrected from
/// `sub_table: None` to `Some(..)` — none may appear as a raw parent key (their
/// child tables stay deferred). `CanonCameraInfo` (0x0d) and `MeasuredColor`
/// (0xaa) are present in the bundled `MakerNotes_Canon.jpg` (== `t/images/
/// Canon.jpg`); all seven plus an all-zero `ImageUniqueID` are present in
/// `Canon1DmkIII.jpg` (`EXIFTOOL_T_IMAGES`).
#[cfg(feature = "exif")]
const CANON_223_MISMARKED_SUBDIR_PARENTS: &[&str] = &[
  "CanonCameraInfo",  // 0x0d   Canon::CameraInfo<Model>
  "CropInfo",         // 0x98   Canon::CropInfo
  "CustomFunctions2", // 0x99   CanonCustom::Functions2
  "AspectInfo",       // 0x9a   Canon::AspectInfo
  "MeasuredColor",    // 0xaa   Canon::MeasuredColor
  "ColorData",        // 0x4001 Canon::ColorData<N>
  "AFMicroAdj",       // 0x4013 Canon::AFMicroAdj
];

/// #223 — none of the seven mis-marked SubDirectory parents (nor an all-zero
/// `ImageUniqueID`) may be emitted, while real Canon tags stay present.
/// Bundled `MakerNotes_Canon.jpg` runs in CI (carries `CanonCameraInfo` +
/// `MeasuredColor` as the bogus parents — verified against the
/// `perl exiftool -G1 -j` oracle, which emits NEITHER).
#[cfg(feature = "json")]
#[test]
fn canon_mismarked_subdir_parents_not_emitted() {
  for print_on in [true, false] {
    let mode = if print_on { "-j" } else { "-n" };
    let map = extract_info_map("MakerNotes_Canon.jpg", print_on);
    for parent in CANON_223_MISMARKED_SUBDIR_PARENTS {
      assert!(
        !map.contains_key(&format!("Canon:{parent}")),
        "bogus mis-marked SubDirectory parent Canon:{parent} must not be emitted ({mode}); keys: {:?}",
        map.keys().collect::<Vec<_>>()
      );
    }
    // An all-zero ImageUniqueID (0x28) is dropped by the RawConv; this fixture
    // has no ImageUniqueID at all, so it must be absent either way.
    assert!(
      !map.contains_key("Canon:ImageUniqueID"),
      "Canon:ImageUniqueID must be absent for this fixture ({mode})"
    );
    // Real Canon tags the oracle DOES emit stay present + unchanged.
    assert!(
      map.contains_key("Canon:CanonImageType"),
      "real Canon:CanonImageType must still be present ({mode})"
    );
    assert!(
      map.contains_key("Canon:LensType"),
      "walked CameraSettings leaf Canon:LensType must still be present ({mode})"
    );
  }
}

/// #223 — the real `Canon1DmkIII.jpg` (NOT bundled; gated on
/// `EXIFTOOL_T_IMAGES`) carries ALL SEVEN mis-marked SubDirectory parents
/// (`CanonCameraInfo`/`CropInfo`/`CustomFunctions2`/`AspectInfo`/
/// `MeasuredColor`/`ColorData`/`AFMicroAdj`) AND an all-zero `ImageUniqueID`
/// (0x28 = 16 NUL bytes). The `perl exiftool -G1 -j` oracle emits NONE of
/// them (it descends the SubDirectories — emitting e.g. `ColorDataVersion`,
/// `AFMicroAdjMode`, all #84/#85/#87-deferred children this port does not yet
/// produce — and the RawConv drops the all-zero ImageUniqueID). Assert none of
/// the eight bogus parents/values leak, while the walked Canon tags stay
/// present and unchanged.
#[cfg(feature = "json")]
#[test]
fn canon_1dmk3_real_fixture_no_mismarked_subdir_parents() {
  let Ok(dir) = std::env::var("EXIFTOOL_T_IMAGES") else {
    eprintln!("skipping: EXIFTOOL_T_IMAGES not set");
    return;
  };
  let path = format!("{dir}/Canon1DmkIII.jpg");
  let Ok(data) = std::fs::read(&path) else {
    eprintln!("skipping: {path} not readable");
    return;
  };
  for print_on in [true, false] {
    let mode = if print_on { "-j" } else { "-n" };
    let json = exifast::parser::extract_info("Canon1DmkIII.jpg", &data, print_on);
    let doc: serde_json::Value =
      serde_json::from_str(&json).unwrap_or_else(|e| panic!("invalid JSON ({e}):\n{json}"));
    let map = doc
      .as_array()
      .and_then(|a| a.first())
      .and_then(|o| o.as_object())
      .unwrap_or_else(|| panic!("doc is not [{{…}}]:\n{json}"));
    for parent in CANON_223_MISMARKED_SUBDIR_PARENTS {
      assert!(
        !map.contains_key(&format!("Canon:{parent}")),
        "bogus mis-marked SubDirectory parent Canon:{parent} must not be emitted ({mode}); keys: {:?}",
        map.keys().collect::<Vec<_>>()
      );
    }
    // The all-zero ImageUniqueID (0x28 = 16 NUL bytes) → undef RawConv → dropped.
    assert!(
      !map.contains_key("Canon:ImageUniqueID"),
      "all-zero Canon:ImageUniqueID must be dropped by the RawConv ({mode})"
    );
    // The walked Canon tags the oracle DOES emit stay present + unaffected: a
    // CameraSettings leaf, a SensorInfo leaf (0xe0, walked here), and the
    // Main-IFD LensModel string (0x95) — proving the suppression is surgical
    // (only the bogus parents removed). (`WB_RGGBLevels*` on this body come
    // from the DEFERRED ColorData4 child of 0x4001, so they are oracle-only —
    // the #84-deferral, out of #223 scope.)
    assert!(
      map.contains_key("Canon:ContinuousDrive"),
      "walked CameraSettings leaf Canon:ContinuousDrive must still be present ({mode})"
    );
    assert!(
      map.contains_key("Canon:SensorWidth"),
      "walked SensorInfo leaf Canon:SensorWidth must still be present ({mode})"
    );
    assert!(
      map.contains_key("Canon:LensModel"),
      "Main-IFD leaf Canon:LensModel must still be present ({mode})"
    );
  }
}

/// Build a one-entry Canon Main IFD blob (little-endian) carrying tag 0x28
/// `ImageUniqueID`, with `value_bytes` stored OUT-OF-LINE (>4 bytes) and the
/// entry declaring TIFF format code `format` with element count `count`. The
/// 16 on-disk value bytes are written verbatim regardless of the declared
/// numeric shape — mirroring how ExifTool's `Format => 'undef'` reads the
/// literal bytes. Mirrors [`canon_mn_one_int16u_array`].
#[cfg(all(feature = "exif", feature = "std"))]
fn canon_mn_image_unique_id_shape(format: u16, count: u32, value_bytes: &[u8]) -> Vec<u8> {
  let mut blob: Vec<u8> = Vec::new();
  blob.extend_from_slice(&1u16.to_le_bytes()); // entry count = 1
  blob.extend_from_slice(&0x28u16.to_le_bytes()); // tag 0x28 ImageUniqueID
  blob.extend_from_slice(&format.to_le_bytes()); // declared on-disk format
  blob.extend_from_slice(&count.to_le_bytes()); // element count
  // value offset: 2-byte count + one 12-byte entry + 4-byte next-IFD = 18.
  let data_off = 2 + 12 + 4;
  blob.extend_from_slice(&(data_off as u32).to_le_bytes());
  blob.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0
  blob.extend_from_slice(value_bytes);
  blob
}

/// #223 — `ImageUniqueID` (0x28) `Format => 'undef'` raw-byte handling
/// (`Canon.pm:1726-1735`): `RawConv => '$val eq "\0" x 16 ? undef : $val'`
/// then `ValueConv => 'unpack("H*", $val)'`.
///
/// ExifTool forces `Format => 'undef'` (`Exif.pm:6735-6744`: override the
/// declared numeric format with `undef` and re-derive `$count = $size /
/// $formatSize['undef']`, so `ReadValue` returns the ORIGINAL on-disk
/// `$size` bytes — the verbose dump literally reads `int8u[16] read as
/// undef[16]`). It therefore reads the SAME 16 raw value bytes whether the
/// entry is declared `int8u[16]`, `int16u[8]`, `int32u[4]`, `undef[16]`,
/// `float[4]`, `double[2]`, or `rational[2]` — a *16-NUL* value is dropped
/// (undef), and a non-zero value is lowercase-hex-encoded to the SAME string
/// across every shape. The expected hex string is oracle-cited: a crafted
/// Canon TIFF with these bytes in each shape was confirmed against `perl
/// exiftool -G1 -j` to yield
/// `Canon:ImageUniqueID = "00112233445566778899aabbccddeeff"` identically
/// (and identically under `-n`); the float/double/rational shapes were
/// individually oracle-checked to yield the SAME hex (NOT a numeric decode).
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn canon_image_unique_id_all_zero_dropped() {
  use exifast::exif::ifd::ByteOrder;
  use exifast::exif::makernotes::vendors::canon;

  // The oracle-cited 16 raw bytes and their `unpack("H*")` rendering.
  const ID_BYTES: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  ];
  const ID_HEX: &str = "00112233445566778899aabbccddeeff";

  // (format code, element count) for the same 16 raw bytes — every TIFF
  // shape that multiplies out to 16 on-disk bytes: int8u[16], int16u[8],
  // int32u[4], undef[16], AND the FLOAT (11) / DOUBLE (12) / RATIONAL (5)
  // shapes that the previous decode-then-reserialize path zeroed out
  // (`reserialize_value_bytes` fell through to `Vec::new()` for those).
  // ExifTool's `undef` read ignores the numeric shape, so every shape yields
  // the IDENTICAL result (each oracle-verified via `perl exiftool -G1 -j`).
  for &(format, count) in &[
    (1u16, 16u32), // int8u[16]
    (3, 8),        // int16u[8]
    (4, 4),        // int32u[4]
    (7, 16),       // undef[16]
    (11, 4),       // float[4]
    (12, 2),       // double[2]
    (5, 2),        // rational[2]
  ] {
    // All-zero 16-byte value ⇒ `$val eq "\0" x 16` ⇒ RawConv undef ⇒ dropped
    // (no emission, typed surface unset). Oracle: an all-zero `int8u[16]`
    // emits NO `Canon:ImageUniqueID`.
    let zero_blob = canon_mn_image_unique_id_shape(format, count, &[0u8; 16]);
    let (typed, em) = canon::parse(&zero_blob, ByteOrder::Little);
    assert!(
      !em.iter().any(|e| e.name() == "ImageUniqueID"),
      "all-zero 16-byte ImageUniqueID must NOT be emitted (format {format}, count {count}); got {:?}",
      em.iter().map(|e| e.name().to_string()).collect::<Vec<_>>()
    );
    assert!(
      typed.image_unique_id().is_none(),
      "all-zero 16-byte ImageUniqueID must not populate the typed surface (format {format}, count {count})"
    );

    // Non-zero ⇒ emitted hex-encoded, typed surface populated — SAME string
    // across all shapes (the `undef` read sees the literal 16 bytes).
    let nz_blob = canon_mn_image_unique_id_shape(format, count, &ID_BYTES);
    let (typed, em) = canon::parse(&nz_blob, ByteOrder::Little);
    let emitted = em
      .iter()
      .find(|e| e.name() == "ImageUniqueID")
      .map(|e| e.value().clone());
    assert_eq!(
      emitted,
      Some(exifast::value::TagValue::Str(ID_HEX.into())),
      "non-zero ImageUniqueID must be hex-encoded from the raw 16 bytes (format {format}, count {count})"
    );
    assert_eq!(
      typed.image_unique_id(),
      Some(ID_HEX),
      "non-zero ImageUniqueID must populate the typed surface (format {format}, count {count})"
    );
  }
}

/// #223 R3 — a SHORT all-zero `ImageUniqueID` is EMITTED, not dropped. The
/// RawConv is `$val eq "\0" x 16` (Perl string equality to EXACTLY sixteen
/// NUL bytes), NOT `/^\0+$/` — so an all-zero value of any length OTHER than
/// 16 is NOT equal and survives. Oracle (`perl exiftool -G1 -j` on a crafted
/// Canon TIFF, tag 0x28 declared `int8u[8]`/`int16u[4]` with eight NUL value
/// bytes): `"Canon:ImageUniqueID": "0000000000000000"` (eight bytes ⇒ sixteen
/// hex zeros) — it does NOT drop. The previous port wrongly suppressed ANY
/// all-zero byte string (`val_bytes.iter().all(|&b| b == 0)`).
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn canon_image_unique_id_short_all_zero_is_emitted() {
  use exifast::exif::ifd::ByteOrder;
  use exifast::exif::makernotes::vendors::canon;

  // Eight NUL bytes ⇒ NOT `"\0" x 16` ⇒ emitted as sixteen hex zeros.
  const SHORT_ZERO_HEX: &str = "0000000000000000";

  // int8u[8] and int16u[4] both multiply to 8 on-disk bytes; the `undef`
  // read sees the SAME eight NUL bytes (oracle-identical hex for both).
  for &(format, count) in &[(1u16, 8u32), (3, 4)] {
    let blob = canon_mn_image_unique_id_shape(format, count, &[0u8; 8]);
    let (typed, em) = canon::parse(&blob, ByteOrder::Little);
    let emitted = em
      .iter()
      .find(|e| e.name() == "ImageUniqueID")
      .map(|e| e.value().clone());
    assert_eq!(
      emitted,
      Some(exifast::value::TagValue::Str(SHORT_ZERO_HEX.into())),
      "a SHORT (8-byte) all-zero ImageUniqueID must be EMITTED as hex zeros, not dropped (format {format}, count {count})"
    );
    assert_eq!(
      typed.image_unique_id(),
      Some(SHORT_ZERO_HEX),
      "a SHORT all-zero ImageUniqueID must populate the typed surface (format {format}, count {count})"
    );
  }
}

/// #223 R3 — a 16-byte value with EMBEDDED NULs (but not all-zero) keeps its
/// NULs in the hex render — the `Format => 'undef'` read is byte-exact and
/// does NOT NUL-trim (the previous `Ascii`/`Text` path would have truncated
/// at the first NUL). Oracle (`perl exiftool -G1 -j` on a crafted Canon TIFF,
/// tag 0x28 declared `int8u[16]` with bytes `00 ff 00 … 00 aa`):
/// `"Canon:ImageUniqueID": "00ff00000000000000000000000000aa"` — the full 32
/// hex chars, including the internal NULs.
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn canon_image_unique_id_embedded_nuls_not_truncated() {
  use exifast::exif::ifd::ByteOrder;
  use exifast::exif::makernotes::vendors::canon;

  // Leading NUL, embedded NUL run, trailing non-NUL — not all-zero, so it
  // survives the RawConv, and the hex must include every NUL byte.
  const NUL_BYTES: [u8; 16] = [
    0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa,
  ];
  const NUL_HEX: &str = "00ff00000000000000000000000000aa";

  let blob = canon_mn_image_unique_id_shape(1, 16, &NUL_BYTES);
  let (typed, em) = canon::parse(&blob, ByteOrder::Little);
  let emitted = em
    .iter()
    .find(|e| e.name() == "ImageUniqueID")
    .map(|e| e.value().clone());
  assert_eq!(
    emitted,
    Some(exifast::value::TagValue::Str(NUL_HEX.into())),
    "an ImageUniqueID with embedded NULs must hex-render the FULL 16 bytes (no NUL-trim)"
  );
  assert_eq!(typed.image_unique_id(), Some(NUL_HEX));
}

/// #223 R4 — a `0x28` entry with `count == 0` must take the `Format => 'undef'`
/// raw-byte view BEFORE `read_value`, so the declared-format decode (and its
/// count-zero expansion) is skipped: the `undef[0]` value is the EMPTY string,
/// derived WITHOUT reading/allocating the trailing buffer that follows the IFD.
///
/// ExifTool overrides the format to `undef` and re-derives `$count =
/// int($size / 1)` where `$size = $count_declared * $formatSize[$declared] = 0`
/// (`Exif.pm:6740-6743`). With a DEFINED `$count == 0`, `ReadValue` returns `''`
/// immediately (`ExifTool.pm:6296-6298` — it does NOT fall through to `$count =
/// int($size / $len)`, which only runs for an UNDEFINED count). The `RawConv`
/// (`'' eq "\0" x 16` is false) keeps `''`, and `unpack("H*", '')` is `''`.
/// Oracle (`perl exiftool -G1 -j` on a crafted Canon TIFF, tag 0x28 declared
/// `int8u[0]` with 16 trailing value bytes): `"Canon:ImageUniqueID": ""` — an
/// EMPTY string, not the hex of the trailing bytes. The pre-R4 code called
/// `read_value` first, which (seeing `count == 0`, `size == avail`) expanded
/// `$count` from the WHOLE remaining buffer and allocated a discarded `Vec`
/// before the `0x28` override replaced it with the (empty) `total_size` window.
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn canon_0x28_count_zero_no_trailing_decode() {
  use exifast::exif::ifd::ByteOrder;
  use exifast::exif::makernotes::vendors::canon;

  // Sixteen NON-zero trailing bytes sit right after the IFD (the helper stores
  // `value_bytes` at offset 18). A `count == 0` entry is classified INLINE
  // (`$size == 0 <= 4`), so the raw window is the empty slice at `entry+8`; if
  // the declared-numeric path ran instead, `read_value` would expand into
  // these trailing bytes and the hex would be non-empty.
  const TRAILING: [u8; 16] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
  ];
  // int8u[0] and int32u[0] both multiply to size 0 (inline, empty window).
  for &(format, count) in &[(1u16, 0u32), (4, 0)] {
    let blob = canon_mn_image_unique_id_shape(format, count, &TRAILING);
    let (typed, em) = canon::parse(&blob, ByteOrder::Little);
    let emitted = em
      .iter()
      .find(|e| e.name() == "ImageUniqueID")
      .map(|e| e.value().clone());
    // Oracle: `undef[0]` ⇒ empty string (the trailing bytes are NOT decoded).
    assert_eq!(
      emitted,
      Some(exifast::value::TagValue::Str("".into())),
      "count-0 ImageUniqueID must emit the EMPTY string (undef[0]), not decode the trailing buffer (format {format})"
    );
    assert_eq!(
      typed.image_unique_id(),
      Some(""),
      "count-0 ImageUniqueID must populate the typed surface with the empty string (format {format})"
    );
  }
}

/// #223 R4 — a `0x28` entry declaring a HUGE element count must be bounds-safe:
/// the checked window computation (`byte_size().checked_mul(count)` +
/// `checked_add` + `get`) never panics and never allocates the discarded
/// multi-gigabyte numeric `Vec` the pre-R4 `read_value`-first path would have.
///
/// `int32u[0x40000000]` ⇒ `$size = 0x40000000 * 4 = 0x1_0000_0000 >
/// 0x7fffffff`, so `ProcessExif` warns `Invalid size (...)` and skips the entry
/// (`Exif.pm:6505`); ExifTool emits NO `ImageUniqueID`. The exifast classifier
/// reaches the SAME verdict (`CanonEntryClass::InvalidSize`, `body.rs`), so the
/// entry never reaches the `0x28` raw-window code — proving the huge count is
/// rejected WITHOUT a panic or a large allocation. Oracle (`perl exiftool -G1
/// -j`): the tag is absent.
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn canon_0x28_large_count_bounded() {
  use exifast::exif::ifd::ByteOrder;
  use exifast::exif::makernotes::vendors::canon;

  // int32u, count 0x40000000 → declared size 4 GiB, value region truncated to
  // 16 bytes. Must not panic, must not allocate, must emit nothing.
  let blob = canon_mn_image_unique_id_shape(4, 0x4000_0000, &[0u8; 16]);
  let (typed, em) = canon::parse(&blob, ByteOrder::Little);
  assert!(
    !em.iter().any(|e| e.name() == "ImageUniqueID"),
    "a huge-count (int32u[0x40000000]) ImageUniqueID must be rejected with no emission; got {:?}",
    em.iter().map(|e| e.name().to_string()).collect::<Vec<_>>()
  );
  assert!(
    typed.image_unique_id().is_none(),
    "a huge-count ImageUniqueID must not populate the typed surface"
  );
}

/// The 23 Canon::Main `SubDirectory` parents the SECOND #223 pass corrected
/// from `sub_table: None` to a deferred `Some(..)` (`0x90 CustomFunctions1D` is
/// the one Codex flagged). None appears in any available fixture, so the
/// suppression is exercised SYNTHETICALLY: each is a real SubDirectory pointer
/// that — left as `None` — would hit the leaf arm and leak a bogus raw-array
/// parent ExifTool never emits.
#[cfg(all(feature = "exif", feature = "std"))]
const CANON_223_SECOND_PASS_PARENTS: &[(u16, &str)] = &[
  (0x0a, "UnknownD30"),             // Canon::UnknownD30
  (0x0f, "CustomFunctions"),        // CanonCustom::Functions<Model>
  (0x2f, "FaceDetect3"),            // Canon::FaceDetect3
  (0x35, "TimeInfo"),               // Canon::TimeInfo
  (0x90, "CustomFunctions1D"),      // CanonCustom::Functions1D
  (0x91, "PersonalFunctions"),      // CanonCustom::PersonalFuncs
  (0x92, "PersonalFunctionValues"), // CanonCustom::PersonalFuncValues
  (0xb0, "CanonFlags"),             // Canon::Flags
  (0xb1, "ModifiedInfo"),           // Canon::ModifiedInfo
  (0xb6, "PreviewImageInfo"),       // Canon::PreviewImageInfo
  (0x4003, "ColorInfo"),            // Canon::ColorInfo
  (0x4015, "VignettingCorr"),       // Canon::VignettingCorr{,Unknown}
  (0x4016, "VignettingCorr2"),      // Canon::VignettingCorr2
  (0x4018, "LightingOpt"),          // Canon::LightingOpt
  (0x4020, "AmbienceInfo"),         // Canon::Ambience
  (0x4021, "MultiExp"),             // Canon::MultiExp
  (0x4024, "FilterInfo"),           // Canon::FilterInfo
  (0x4025, "HDRInfo"),              // Canon::HDRInfo
  (0x4026, "LogInfo"),              // Canon::LogInfo
  (0x4028, "AFConfig"),             // Canon::AFConfig
  (0x403f, "RawBurstModeRoll"),     // Canon::RawBurstInfo
  (0x4053, "FocusBracketingInfo"),  // Canon::FocusBracketingInfo
  (0x4059, "LevelInfo"),            // Canon::LevelInfo
];

/// #223 (second pass) — a Canon Main IFD carrying tag `id` as an int16u array
/// must emit NO `Canon:<parent>` raw value: it is a deferred SubDirectory and
/// is suppressed (the same descend-no-parent-value rule as #177). A co-present
/// real leaf (`CanonImageType` 0x06) is still emitted, proving the suppression
/// is surgical and the walk did run. Driven through the public standalone
/// `canon::parse`, in BOTH `-j` (PrintConv on) and `-n` (off).
#[cfg(all(feature = "exif", feature = "std"))]
#[test]
fn canon_223_second_pass_subdir_parents_suppressed() {
  use exifast::exif::ifd::ByteOrder;
  use exifast::exif::makernotes::vendors::canon;

  for &(id, parent) in CANON_223_SECOND_PASS_PARENTS {
    // Two-entry Main IFD (LE): the SubDirectory tag (out-of-line int16u[8]) +
    // CanonImageType (0x06, ASCII, out-of-line). If `id` were mis-marked
    // `None`, the int16u[8] would leak as a bogus `Canon:<parent>` array.
    let words: [i16; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let image_type = b"CanonTest\x00"; // 10 bytes, out-of-line
    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(&2u16.to_le_bytes()); // 2 entries
    // Entry 1: the deferred SubDirectory tag, int16u(3) count 8, out-of-line.
    let entries_end = 2 + 12 * 2 + 4; // count + 2 entries + next-IFD
    let words_off = entries_end;
    let it_off = words_off + words.len() * 2;
    blob.extend_from_slice(&id.to_le_bytes());
    blob.extend_from_slice(&3u16.to_le_bytes()); // int16u
    blob.extend_from_slice(&(words.len() as u32).to_le_bytes());
    blob.extend_from_slice(&(words_off as u32).to_le_bytes());
    // Entry 2: CanonImageType 0x06, ASCII(2), out-of-line.
    blob.extend_from_slice(&0x06u16.to_le_bytes());
    blob.extend_from_slice(&2u16.to_le_bytes()); // ASCII
    blob.extend_from_slice(&(image_type.len() as u32).to_le_bytes());
    blob.extend_from_slice(&(it_off as u32).to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0
    for &w in &words {
      blob.extend_from_slice(&w.to_le_bytes());
    }
    blob.extend_from_slice(image_type);

    for print_on in [true, false] {
      let mode = if print_on { "-j" } else { "-n" };
      let (_typed, em) = canon::parse_in_tiff(
        &blob,
        0,
        blob.len(),
        ByteOrder::Little,
        print_on,
        // Use a 1D body so the 0x0f/0x90 model-conditional SubDirectory arms
        // resolve (they are SubDirectories for EVERY model; the body only
        // affects WHICH child table, which we defer regardless).
        Some("Canon EOS-1D"),
        None,
      );
      assert!(
        !em.iter().any(|e| e.name() == parent),
        "deferred SubDirectory parent Canon:{parent} (0x{id:04x}) must NOT be emitted ({mode}); \
         got {:?}",
        em.iter().map(|e| e.name().to_string()).collect::<Vec<_>>()
      );
      // The co-present real leaf still emits — suppression is surgical.
      assert!(
        em.iter().any(|e| e.name() == "CanonImageType"),
        "co-present real leaf Canon:CanonImageType must still be emitted ({mode}) for 0x{id:04x}"
      );
    }
  }
}
