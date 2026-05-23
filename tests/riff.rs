//! Integration tests for the RIFF / AVI parser (FORMATS.md row 26). Covers
//! the synthetic + bundled fixtures end-to-end through the engine entry
//! [`extract_info`].

#![cfg(all(feature = "json", feature = "riff"))]

use exifast::parser::extract_info;

#[test]
fn bundled_riff_avi_extracts_camera_metadata() {
  // Bundled `lib/Image/ExifTool/t/images/RIFF.avi` — a 1262-byte Motion JPEG
  // Canon AVI fixture from 2003. Carries the most-common AVI tag surface:
  // hdrl/avih (FrameRate / FrameCount / dimensions), strl/strh (StreamType /
  // codec / VideoFrameRate / VideoFrameCount), strl/strf for both vids
  // (BMP-V3 header) and auds (AudioFormat / Encoding=PCM), LIST_INFO
  // (`ISFT` = "CanonMVI01"), IDIT (DateTimeOriginal). We test the engine
  // path which exercises the file-type detection → parser registry hop.
  let root = env!("CARGO_MANIFEST_DIR");
  let data = std::fs::read(format!("{root}/tests/fixtures/RIFF.avi")).expect("read RIFF.avi");
  let got = extract_info("RIFF.avi", &data, /* print_on */ true);
  // The doc must mention the AVI file type + MIME + camera identity tags.
  assert!(
    got.contains("\"File:FileType\":\"AVI\""),
    "missing AVI file type:\n{got}"
  );
  assert!(
    got.contains("\"File:MIMEType\":\"video/x-msvideo\""),
    "missing AVI MIME:\n{got}"
  );
  assert!(
    got.contains("\"RIFF:Software\":\"CanonMVI01\""),
    "missing ISFT software:\n{got}"
  );
  assert!(
    got.contains("\"RIFF:DateTimeOriginal\":\"2003:03:10 15:04:43\""),
    "missing IDIT date:\n{got}"
  );
  assert!(
    got.contains("\"RIFF:VideoCodec\":\"mjpg\""),
    "missing video codec:\n{got}"
  );
  assert!(
    got.contains("\"RIFF:Encoding\":\"Microsoft PCM\""),
    "missing PCM encoding label:\n{got}"
  );
  assert!(
    got.contains("\"RIFF:StreamType\":\"Video\""),
    "missing StreamType PrintConv:\n{got}"
  );
  // BMP-strf hop.
  assert!(
    got.contains("\"File:BMPVersion\":\"Windows V3\""),
    "missing BMPVersion:\n{got}"
  );
  assert!(
    got.contains("\"File:Compression\":\"MJPG\""),
    "missing BMP FourCC compression:\n{got}"
  );
}

#[test]
fn bundled_riff_avi_n_mode_emits_raw_values() {
  // `-n` mode strips PrintConv: Encoding → 1, StreamType → "vids",
  // BMPVersion → 40.
  let root = env!("CARGO_MANIFEST_DIR");
  let data = std::fs::read(format!("{root}/tests/fixtures/RIFF.avi")).expect("read RIFF.avi");
  let got = extract_info("RIFF.avi", &data, /* print_on */ false);
  assert!(
    got.contains("\"RIFF:Encoding\":1"),
    "raw PCM encoding code:\n{got}"
  );
  assert!(
    got.contains("\"RIFF:StreamType\":\"vids\""),
    "raw StreamType FourCC:\n{got}"
  );
  assert!(
    got.contains("\"File:BMPVersion\":40"),
    "raw BMPVersion:\n{got}"
  );
}

#[test]
fn media_metadata_projection_from_riff() {
  // The `from_riff` projection should populate MediaInfo with width / height /
  // created / duration (FrameCount/FrameRate) and CameraInfo.software from
  // INFO/ISFT.
  use exifast::AnyMeta;
  use exifast::filetype::detection_candidates;
  use exifast::format_parser::{SharedFlags, any_parser_for};
  use exifast::metadata::MediaMetadata;

  let root = env!("CARGO_MANIFEST_DIR");
  let data = std::fs::read(format!("{root}/tests/fixtures/RIFF.avi")).expect("read RIFF.avi");
  let candidates = detection_candidates("RIFF.avi", &data);
  let mut shared = SharedFlags::new();
  let mut riff_meta = None;
  for cand in candidates {
    if let Some(p) = any_parser_for(cand.file_type())
      && let Ok(Some(meta)) = p.parse_any(&data, &mut shared, Some("avi"), 0, None)
    {
      if let AnyMeta::Riff(rm) = meta {
        riff_meta = Some(rm);
      }
      break;
    }
  }
  let riff = riff_meta.expect("RIFF.avi parsed as AnyMeta::Riff");

  let projected = MediaMetadata::from_riff(&riff);
  assert_eq!(projected.media().width(), Some(320));
  assert_eq!(projected.media().height(), Some(240));
  assert_eq!(projected.media().created(), Some("2003:03:10 15:04:43"));
  // RIFF.avi has video + audio streams.
  assert!(projected.media().has_video());
  assert!(projected.media().has_audio());
  // Software from INFO/ISFT.
  let camera = projected.camera().expect("CameraInfo populated by ISFT");
  assert_eq!(camera.software(), Some("CanonMVI01"));
}
