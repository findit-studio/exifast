//! Smoke test: a standalone TIFF dispatches through `parse_bytes` to the
//! `AnyMeta::Exif` arm, and the public `parse_exif`/`parse_exif_block`
//! entries return a typed `ExifMeta`. Covers the crate-root public API
//! surface (`parse_exif`, `parse_exif_block`, `ExifMeta::entry`) that the
//! golden conformance tests — which go through `extract_info` — do not
//! exercise directly.
#![cfg(all(feature = "exif", feature = "std"))]
use exifast::AnyMeta;

#[test]
fn standalone_tiff_dispatches_to_exif_arm() {
  let data = std::fs::read(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/Exif.tif"
  ))
  .unwrap();
  let meta = exifast::parse_bytes(&data)
    .unwrap()
    .expect("TIFF recognized");
  assert!(matches!(meta, AnyMeta::Exif(_)), "got {meta:?}");
  // The reusable entry returns the same typed ExifMeta.
  let block = exifast::parse_exif_block(&data).expect("parse_exif_block");
  assert_eq!(block.entry("Make").map(|e| e.name()), Some("Make"));
  // The direct `parse_exif` accessor too.
  let direct = exifast::parse_exif(&data).unwrap().expect("parse_exif");
  assert!(direct.entry("LensModel").is_some());
}
