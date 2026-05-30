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
