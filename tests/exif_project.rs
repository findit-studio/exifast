// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Integration test for the domain-projection layer (golden pattern L2):
//! [`Project::project`] mapping a parsed [`ExifMeta`] onto the normalized
//! cross-format [`MediaMetadata`].
//!
//! The projection is ADDITIVE over tag emission — it reads an already-parsed
//! `ExifMeta` (here via the JPEG/TIFF Exif front-ends) and surfaces the
//! camera / lens / GPS / capture domains a media indexer wants regardless of
//! container. These tests pin the real-fixture mappings:
//!
//! - `MakerNotes_Canon.jpg` — IFD0 `Make`/`Model` + the Canon MakerNote's
//!   typed lens/model identity (the standard EXIF IFD carries no `LensModel`
//!   for this body, so the lens domain comes from the MakerNote merge).
//! - `ExifGPS.tif` — a clean GPS sub-IFD (decimal-degree lat/long + altitude).

#![cfg(all(feature = "exif", feature = "std"))]

use exifast::metadata::Project;

/// A Canon JPEG projects a populated camera domain (`make`/`model`) AND a
/// lens domain — the latter sourced from the Canon MakerNote merge, since
/// this body writes no standard `LensModel` EXIF tag.
#[test]
fn exif_project_populates_camera_and_lens() {
  let data = std::fs::read(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/MakerNotes_Canon.jpg"
  ))
  .unwrap();
  let meta = exifast::exif::jpeg::parse_jpeg_exif(&data).expect("Canon JPEG parsed");

  let projected = meta.project();

  // Camera identity from IFD0 Make/Model.
  let camera = projected.camera().expect("camera domain populated");
  assert_eq!(camera.make(), Some("Canon"));
  let model = camera.model().expect("model present");
  assert!(model.starts_with("Canon EOS"), "model = {model:?}");
  // The Canon MakerNote carries the user-facing body serial; the standard
  // IFD has no SerialNumber tag for this fixture, so this comes from the
  // MakerNote merge.
  assert_eq!(camera.serial(), Some("560018150"));

  // Lens identity — present ONLY because the Canon MakerNote `lens_name`
  // ("n/a", the resolved %canonLensTypes label) merges in; IFD0/ExifIFD
  // carry no LensModel here.
  let lens = projected.lens().expect("lens domain populated");
  assert_eq!(lens.model(), Some("n/a"));
  // FocalLength comes from the ExifIFD rational (34/1 mm); the MakerNote
  // focal RANGE (18-55) only fills it if the IFD value is absent.
  assert_eq!(lens.focal_length_mm(), Some(34.0));
  // FNumber (14/1) is the capture aperture proxy.
  assert_eq!(lens.aperture(), Some(14.0));

  // Capture settings from the ExifIFD.
  let capture = projected.capture().expect("capture domain populated");
  assert_eq!(capture.exposure_time_s(), Some(4.0));
  assert_eq!(capture.iso(), Some(100));
  assert_eq!(capture.f_number(), Some(14.0));
}

/// A GPS-bearing TIFF (Apple iPhone 12) projects decimal-degree
/// latitude/longitude + altitude through the GPS sub-IFD ValueConv.
#[cfg(feature = "gps")]
#[test]
fn exif_project_populates_gps() {
  let data = std::fs::read(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/ExifGPS.tif"
  ))
  .unwrap();
  let meta = exifast::exif::parse_exif_block(&data).expect("GPS TIFF parsed");

  let projected = meta.project();
  let gps = projected.gps().expect("gps domain populated");

  // 48°51'29.34" N  → +48.858_15
  let lat = gps.latitude().expect("latitude");
  assert!((lat - 48.858_15).abs() < 1e-4, "lat = {lat}");
  // 2°20'56.16" E   → +2.349_0
  let lon = gps.longitude().expect("longitude");
  assert!((lon - 2.349_0).abs() < 1e-4, "lon = {lon}");
  // GPSAltitude 35.00 m, ref 0 (above sea) → +35.0
  let alt = gps.altitude_m().expect("altitude");
  assert!((alt - 35.0).abs() < 1e-6, "alt = {alt}");

  // This GPS-only TIFF also carries IFD0 Make/Model.
  let camera = projected.camera().expect("camera domain populated");
  assert_eq!(camera.make(), Some("Apple"));
  assert_eq!(camera.model(), Some("iPhone 12"));
}

/// EXIF identity strings are commonly space-padded; the projection must
/// surface the TRIMMED value (bundled trims Make/Model/Software via
/// `RawConv => '$val =~ s/\s+$//'`, Exif.pm:585/599/906). The fixture
/// `Exif_trailing_space.tif` carries Make `"Canon   "`, Model `"EOS R5\t "`,
/// Software `"FW v2.0 "` — the domain must report them without the padding.
#[test]
fn exif_project_trims_padded_identity_strings() {
  let data = std::fs::read(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/Exif_trailing_space.tif"
  ))
  .unwrap();
  let meta = exifast::exif::parse_exif_block(&data).expect("TIFF parsed");
  let projected = meta.project();
  let camera = projected.camera().expect("camera domain populated");
  assert_eq!(camera.make(), Some("Canon"));
  assert_eq!(camera.model(), Some("EOS R5"));
  assert_eq!(camera.software(), Some("FW v2.0"));
}

/// A still's EXIF `Orientation` projects onto the `MediaInfo::orientation`
/// domain field (#324) — the single normalized orientation a consumer reads
/// to orient a decoded-frame thumbnail. `Pentax.jpg`'s IFD0 `Orientation` is
/// `8` ("Rotate 270 CW" — see its `-n` golden), so the projected orientation
/// is 270° CW, un-mirrored.
#[test]
fn exif_project_populates_orientation() {
  let data = std::fs::read(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/Pentax.jpg"
  ))
  .unwrap();
  let meta = exifast::exif::jpeg::parse_jpeg_exif(&data).expect("Pentax JPEG parsed");
  let projected = meta.project();
  let orientation = projected
    .media()
    .orientation()
    .expect("orientation projected from EXIF 0x0112");
  assert_eq!(orientation.exif_value(), 8);
  assert_eq!(orientation.rotation_degrees(), 270);
  assert!(!orientation.mirrored());
}

/// Build a little-endian TIFF: IFD0 carries `Make` and `next-IFD -> IFD1`;
/// IFD1 (the thumbnail) carries an `Orientation` (SHORT) and ends the chain.
/// `ifd0_orientation = Some(v)` adds an `Orientation` SHORT to IFD0 as well.
/// Used to pin that `MediaInfo::orientation` is sourced from the PRIMARY image
/// (IFD0) only — a thumbnail's IFD1 `Orientation` must NOT populate it.
fn tiff_orientation_in_ifd1(ifd1_orientation: u16, ifd0_orientation: Option<u16>) -> Vec<u8> {
  let make = b"M\0"; // "M" NUL-terminated
  let ifd0_start: u32 = 8;
  let n0: u16 = if ifd0_orientation.is_some() { 2 } else { 1 };
  // IFD0 layout: count(2) + n0*12 entries + next-IFD ptr(4), then the Make value.
  let ifd0_val_off = ifd0_start + 2 + u32::from(n0) * 12 + 4;
  let ifd1_off = ifd0_val_off + make.len() as u32; // IFD1 sits right after Make.

  let mut t = Vec::new();
  t.extend_from_slice(b"II");
  t.extend_from_slice(&0x002a_u16.to_le_bytes());
  t.extend_from_slice(&ifd0_start.to_le_bytes());

  // ---- IFD0 ----
  t.extend_from_slice(&n0.to_le_bytes());
  // IFD entries are sorted by tag id; Orientation (0x0112) > Make (0x010f),
  // so Make comes first when both are present.
  t.extend_from_slice(&0x010f_u16.to_le_bytes()); // Make
  t.extend_from_slice(&0x0002_u16.to_le_bytes()); // ASCII
  t.extend_from_slice(&(make.len() as u32).to_le_bytes());
  t.extend_from_slice(&ifd0_val_off.to_le_bytes());
  if let Some(v) = ifd0_orientation {
    t.extend_from_slice(&0x0112_u16.to_le_bytes()); // Orientation
    t.extend_from_slice(&0x0003_u16.to_le_bytes()); // SHORT
    t.extend_from_slice(&1u32.to_le_bytes()); // count 1
    // Inline SHORT value (2 bytes) in the low half of the 4-byte value field.
    t.extend_from_slice(&v.to_le_bytes());
    t.extend_from_slice(&0u16.to_le_bytes()); // pad to 4 bytes
  }
  t.extend_from_slice(&ifd1_off.to_le_bytes()); // next IFD -> IFD1
  t.extend_from_slice(make); // Make value

  // ---- IFD1 (thumbnail) ----
  let n1: u16 = 1;
  t.extend_from_slice(&n1.to_le_bytes());
  t.extend_from_slice(&0x0112_u16.to_le_bytes()); // Orientation
  t.extend_from_slice(&0x0003_u16.to_le_bytes()); // SHORT
  t.extend_from_slice(&1u32.to_le_bytes()); // count 1
  t.extend_from_slice(&ifd1_orientation.to_le_bytes()); // inline SHORT
  t.extend_from_slice(&0u16.to_le_bytes()); // pad to 4 bytes
  t.extend_from_slice(&0u32.to_le_bytes()); // no further IFD
  t
}

/// Regression (#324, Codex finding 2): `Orientation` must be resolved from the
/// PRIMARY image's IFD0 ONLY. A TIFF whose IFD0 has NO `Orientation` but whose
/// IFD1 (thumbnail) DOES must project `MediaInfo::orientation() == None` — the
/// thumbnail's orientation must not leak into the primary frame's.
#[test]
fn exif_project_orientation_ignores_thumbnail_ifd1() {
  // IFD1 says "Rotate 90 CW" (6); IFD0 has none.
  let data = tiff_orientation_in_ifd1(6, None);
  let meta = exifast::exif::parse_exif_block(&data).expect("TIFF parsed");

  // Sanity: the IFD1 Orientation IS present among the emitted entries (so the
  // None below is genuinely the IFD0-only filter, not a parse miss).
  assert!(
    meta
      .entries()
      .iter()
      .any(|e| e.tag_id() == 0x0112 && format!("{}", e.group()) == "IFD1"),
    "expected an IFD1 Orientation entry in the parse"
  );
  assert!(
    !meta
      .entries()
      .iter()
      .any(|e| e.tag_id() == 0x0112 && format!("{}", e.group()) == "IFD0"),
    "IFD0 must carry no Orientation in this fixture"
  );

  let projected = meta.project();
  assert!(
    projected.media().orientation().is_none(),
    "a thumbnail (IFD1) Orientation must not populate the primary MediaInfo::orientation"
  );
}

/// Counterpart: when IFD0 DOES carry an `Orientation`, it is the one projected
/// — even if IFD1 carries a different value (the IFD0-only resolution picks
/// the primary, never the thumbnail).
#[test]
fn exif_project_orientation_prefers_ifd0_over_thumbnail() {
  // IFD0 = "Rotate 180" (3); IFD1 = "Rotate 90 CW" (6) — IFD0 must win.
  let data = tiff_orientation_in_ifd1(6, Some(3));
  let meta = exifast::exif::parse_exif_block(&data).expect("TIFF parsed");
  let projected = meta.project();
  let orientation = projected
    .media()
    .orientation()
    .expect("IFD0 Orientation projects");
  assert_eq!(
    orientation.exif_value(),
    3,
    "the IFD0 value (3), not IFD1's (6)"
  );
  assert_eq!(orientation.rotation_degrees(), 180);
  assert!(!orientation.mirrored());
}
