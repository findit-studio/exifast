//! QuickTime Sub-Port 3 conformance — embedded timed-metadata GPS.
//!
//! `Image::ExifTool::QuickTime::Stream` (QuickTimeStream.pl) extracts per-frame
//! GPS / sensor telemetry from a video's metadata tracks. ExifTool only
//! surfaces these tags under the `ExtractEmbedded` (`-ee`) option, so the
//! standard `tools/gen_golden.sh` conformance harness — which never passes
//! `-ee` — does NOT exercise them. This dedicated harness instead:
//!
//!   1. parses each SP3 fixture with [`exifast::parse_quicktime`];
//!   2. reads the matching `<fixture>.ee.json` golden — the bundled-ExifTool
//!      `-ee` output, captured by the same `-j -G1 -struct -api
//!      QuickTimeUTC=1` flags as `gen_golden.sh` PLUS `-ee`;
//!   3. asserts the typed [`exifast::metadata::QuickTimeStreamMeta`] decodes
//!      the same GPS / accelerometer / `mebx` values the oracle reports.
//!
//! The `.ee.json` goldens carry NO `.json` / `.n.json` companion, so the
//! `tests/conformance.rs` and `tests/typed_serde_parity.rs` auto-discovery
//! (which requires BOTH standard goldens) naturally skips these fixtures —
//! the SP3 timed-metadata tags never pollute the non-`-ee` conformance set.
#![cfg(all(feature = "quicktime", feature = "json"))]

use exifast::parse_quicktime;

/// Load `tests/golden/<name>.ee.json` and return the first (only) document.
fn ee_golden(name: &str) -> serde_json::Map<String, serde_json::Value> {
  let root = env!("CARGO_MANIFEST_DIR");
  let raw = std::fs::read_to_string(format!("{root}/tests/golden/{name}.ee.json"))
    .unwrap_or_else(|e| panic!("read golden {name}.ee.json: {e}"));
  let v: serde_json::Value = serde_json::from_str(&raw).expect("golden is valid JSON");
  v.as_array()
    .and_then(|a| a.first())
    .and_then(|d| d.as_object())
    .cloned()
    .expect("golden document object")
}

/// Read a fixture into memory.
fn fixture(name: &str) -> Vec<u8> {
  let root = env!("CARGO_MANIFEST_DIR");
  std::fs::read(format!("{root}/tests/fixtures/{name}"))
    .unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
}

/// Pull a golden value as `f64` (accepts a JSON number or a numeric string).
fn golden_f64(g: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<f64> {
  match g.get(key)? {
    serde_json::Value::Number(n) => n.as_f64(),
    serde_json::Value::String(s) => s.parse().ok(),
    _ => None,
  }
}

#[test]
fn quicktime_mebx_timed_metadata_decodes_keys_table() {
  // QuickTimeStream.pl `Process_mebx` (2644-2680) + `SaveMetaKeys` (876-962):
  // an Apple `mebx` metadata track. The fixture's `keys` table maps local-id
  // 1 → TagID `GPSCoordinates` (int32u); the single timed sample carries the
  // value 123456. Bundled `-ee` ⇒ `Track1:GPSCoordinates = 123456`.
  let data = fixture("QuickTime_mebx_gps.mov");
  let golden = ee_golden("QuickTime_mebx_gps.mov");
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  let stream = meta.stream();
  assert!(!stream.is_empty(), "mebx timed metadata must be decoded");
  // The keys-table mebx pair.
  let pairs = stream.mebx_samples();
  assert_eq!(pairs.len(), 1, "one mebx key/value pair");
  assert_eq!(pairs[0].name(), "GPSCoordinates");
  assert_eq!(pairs[0].value(), "123456");
  // Value-equivalent to the bundled oracle's Track1:GPSCoordinates.
  let want = golden
    .get("Track1:GPSCoordinates")
    .expect("golden GPSCoordinates")
    .to_string();
  assert!(
    want.contains("123456"),
    "oracle GPSCoordinates {want} vs decoded 123456"
  );
}

#[test]
fn quicktime_kenwood_gps_box_decodes_le_records() {
  // QuickTimeStream.pl `ParseTag` `GPS ` (2557-2580): a moov-level Kenwood
  // `GPS ` box of 36-byte little-endian records. The fixture has two fixes;
  // the bundled `-ee -j` output collapses sub-documents and reports the FIRST
  // fix under `QuickTime:GPS*`.
  let data = fixture("QuickTime_gps_kenwood.mov");
  let golden = ee_golden("QuickTime_gps_kenwood.mov");
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  let stream = meta.stream();
  assert_eq!(stream.gps_samples().len(), 2, "two Kenwood GPS records");
  let first = stream.first_fix().expect("a GPS fix");
  // The oracle's QuickTime:GPSLatitude is a DMS PrintConv string; the typed
  // layer keeps post-ValueConv decimal degrees. Cross-check the decimal
  // matches the DMS: 4737.705 DDDMM.MMMM ⇒ 47.6284...
  let lat = first.latitude().expect("latitude");
  let lon = first.longitude().expect("longitude");
  assert!((lat - 47.628_416_666_666_67).abs() < 1e-6, "lat {lat}");
  // first record's longitude is West ⇒ negative.
  assert!((lon + 122.165_016_666_666_67).abs() < 1e-6, "lon {lon}");
  // GPSSpeed is a bare number in the golden — exact match.
  assert_eq!(first.speed_kph(), golden_f64(&golden, "QuickTime:GPSSpeed"));
  // The oracle's DMS string carries 'N' for the (positive) latitude.
  let dms_lat = golden
    .get("QuickTime:GPSLatitude")
    .and_then(|v| v.as_str())
    .expect("golden GPSLatitude");
  assert!(dms_lat.ends_with('N'), "first fix is North: {dms_lat}");
  let dms_lon = golden
    .get("QuickTime:GPSLongitude")
    .and_then(|v| v.as_str())
    .expect("golden GPSLongitude");
  assert!(dms_lon.ends_with('W'), "first fix is West: {dms_lon}");
}

#[test]
fn quicktime_gps0_dudubell_decodes_binary_records() {
  // QuickTimeStream.pl `Process_gps0` (2715-2763): a top-level DuDuBell /
  // VSYS `gps0` box of 32-byte little-endian binary GPS records.
  let data = fixture("QuickTime_gps0.mov");
  let golden = ee_golden("QuickTime_gps0.mov");
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  let stream = meta.stream();
  assert_eq!(stream.gps_samples().len(), 2, "two gps0 records");
  let first = stream.first_fix().expect("a GPS fix");
  // Altitude / speed / track are bare numbers / "N m" in the golden.
  // QuickTime:GPSAltitude golden is "123 m"; the typed value is 123.0.
  assert_eq!(first.altitude_m(), Some(123.0));
  assert_eq!(first.speed_kph(), golden_f64(&golden, "QuickTime:GPSSpeed"));
  // GPSTrack golden: the int8u byte 0x1c (30) doubled ⇒ 60.
  assert_eq!(first.track(), golden_f64(&golden, "QuickTime:GPSTrack"));
  // GPSDateTime is built from the record's embedded date bytes — exact.
  assert_eq!(
    first.date_time(),
    golden.get("QuickTime:GPSDateTime").and_then(|v| v.as_str())
  );
  // lat/lon decimal cross-check against the DMS golden hemisphere.
  let lat = first.latitude().expect("lat");
  assert!((lat - 47.628_421_666_666_67).abs() < 1e-6, "lat {lat}");
}

#[test]
fn quicktime_gsen_dudubell_decodes_accelerometer() {
  // QuickTimeStream.pl `Process_gsen` (2769-2789): a top-level DuDuBell
  // `gsen` box of 3-byte int8s accelerometer triples (scaled by 1/16).
  let data = fixture("QuickTime_gsen.mov");
  let golden = ee_golden("QuickTime_gsen.mov");
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  let stream = meta.stream();
  assert_eq!(stream.gps_samples().len(), 2, "two gsen records");
  // First record: 16/16, -32/16, 48/16 ⇒ "1 -2 3" — exact match to the
  // oracle's QuickTime:Accelerometer.
  assert_eq!(stream.gps_samples()[0].accelerometer(), Some("1 -2 3"));
  let want = golden
    .get("QuickTime:Accelerometer")
    .and_then(|v| v.as_str())
    .expect("golden Accelerometer");
  assert_eq!(want, "1 -2 3", "oracle accelerometer");
}

#[test]
fn quicktime_stream_empty_for_plain_video() {
  // A QuickTime file with no timed-metadata track ⇒ empty stream meta and no
  // embedded-Exif deferral (the existing SP1 fixture has neither).
  let data = fixture("QuickTime_sp1.mov");
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  assert!(
    meta.stream().is_empty(),
    "plain video has no timed metadata"
  );
  assert!(
    !meta.embedded_exif_deferred(),
    "plain video has no embedded Exif"
  );
}

#[test]
fn quicktime_media_metadata_projects_first_gps_fix() {
  // The normalized MediaMetadata projection fills GpsLocation from the FIRST
  // embedded timed-metadata GPS fix (SP3).
  let data = fixture("QuickTime_gps0.mov");
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  let md = meta.media_metadata();
  let gps = md.gps().expect("GpsLocation projected from timed metadata");
  let lat = gps.latitude().expect("latitude");
  assert!((lat - 47.628_421_666_666_67).abs() < 1e-6, "lat {lat}");
  assert_eq!(gps.altitude_m(), Some(123.0));
  assert!(gps.timestamp().is_some(), "GPSDateTime projected");
}

#[test]
fn quicktime_freegps_brute_force_scan_finds_block_in_mdat() {
  // SP3.5 — ProcessFreeGPS + ScanMediaData (QuickTimeStream.pl:1637-2484,
  // :3679-3789). Synthetic mov file with an `mdat` that contains a Type-6
  // (Akaso) freeGPS block. The brute-force scanner must locate the block
  // and dispatch into `decode_type6_akaso`, producing one GPS sample
  // accessible via `Meta::stream`.
  let data = build_mov_with_freegps_in_mdat();
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  let stream = meta.stream();
  assert_eq!(
    stream.gps_samples().len(),
    1,
    "freeGPS scan must locate and decode the embedded block"
  );
  let s = &stream.gps_samples()[0];
  // Type 6 lat 4737.7053 ⇒ ConvertLatLon ⇒ 47.628.
  assert!((s.latitude().unwrap() - 47.628_421).abs() < 1e-3);
  assert!(s.longitude().unwrap() < -120.0);
}

/// Build a minimal but valid `.mov` containing:
///   - an 8-byte ftyp atom
///   - a minimal moov+mvhd (no timed-metadata tracks)
///   - an `mdat` payload containing a Type-6 freeGPS block
fn build_mov_with_freegps_in_mdat() -> Vec<u8> {
  // ftyp atom: 'qt  '.
  let mut ftyp = 16u32.to_be_bytes().to_vec();
  ftyp.extend_from_slice(b"ftyp");
  ftyp.extend_from_slice(b"qt  ");
  ftyp.extend_from_slice(&0u32.to_be_bytes());
  // mvhd (v0, 108 bytes): version+flags + 7 × int32 zero + 1 dword timescale=1000 + ...
  let mut mvhd = Vec::new();
  mvhd.extend_from_slice(&[0u8; 4]); // version+flags
  mvhd.extend_from_slice(&[0u8; 8]); // create+modify date
  mvhd.extend_from_slice(&1000u32.to_be_bytes()); // timescale
  mvhd.extend_from_slice(&1000u32.to_be_bytes()); // duration (1s)
  mvhd.extend_from_slice(&[0u8; 80]); // rest
  let mut moov = (mvhd.len() as u32 + 16).to_be_bytes().to_vec();
  moov.extend_from_slice(b"moov");
  let mut mvhd_atom = (mvhd.len() as u32 + 8).to_be_bytes().to_vec();
  mvhd_atom.extend_from_slice(b"mvhd");
  mvhd_atom.extend_from_slice(&mvhd);
  moov.extend_from_slice(&mvhd_atom);
  // Build the freeGPS block (Type 6, 256-byte block — alignment per the
  // ExifTool scanner's `\0..\0` size pattern).
  let mut block = vec![0u8; 0x100];
  block[0..4].copy_from_slice(&0x0100u32.to_be_bytes());
  block[4..12].copy_from_slice(b"freeGPS ");
  block[60] = b'A';
  block[68] = b'N';
  block[76] = b'W';
  block[0x30..0x34].copy_from_slice(&14u32.to_le_bytes()); // hr
  block[0x34..0x38].copy_from_slice(&30u32.to_le_bytes()); // min
  block[0x38..0x3c].copy_from_slice(&45u32.to_le_bytes()); // sec
  block[0x58..0x5c].copy_from_slice(&2024u32.to_le_bytes()); // yr
  block[0x5c..0x60].copy_from_slice(&7u32.to_le_bytes()); // mon
  block[0x60..0x64].copy_from_slice(&15u32.to_le_bytes()); // day
  block[0x40..0x44].copy_from_slice(&4737.7053f32.to_le_bytes()); // lat
  block[0x48..0x4c].copy_from_slice(&12209.901f32.to_le_bytes()); // lon
  // mdat payload = 64 bytes pad + block + 64 bytes pad.
  let mut mdat_payload = vec![0u8; 64];
  mdat_payload.extend_from_slice(&block);
  mdat_payload.extend_from_slice(&[0u8; 64]);
  let mut mdat = (mdat_payload.len() as u32 + 8).to_be_bytes().to_vec();
  mdat.extend_from_slice(b"mdat");
  mdat.extend_from_slice(&mdat_payload);
  let mut out = ftyp;
  out.extend_from_slice(&moov);
  out.extend_from_slice(&mdat);
  out
}

// ===========================================================================
// SP4 — GoPro GPMF
// ===========================================================================

#[test]
fn quicktime_gopro_gpmf_in_mdat_brute_force_dispatch() {
  // SP4 — the brute-force `mdat` scan locates a GoPro `GP\x06\0\0` record;
  // its DEVC payload feeds the GPMF KLV walker. The synthetic record
  // carries enough tags to populate the typed GoPro identity + a single
  // GPS5 fix.
  let data = build_mov_with_gpro6_in_mdat();
  let meta = exifast::parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  let gp = meta.gopro();
  assert!(
    !gp.is_empty(),
    "the brute-force scan must populate the GoPro meta"
  );
  assert_eq!(gp.device_name(), Some("Camera"));
  assert_eq!(gp.model(), Some("HERO6 Black"));
  assert_eq!(gp.camera_serial_number(), Some("C3221324657219"));
  assert_eq!(gp.firmware_version(), Some("HD6.01.01.51.00"));
  let samples = gp.gps_samples();
  assert_eq!(samples.len(), 1, "one GPS5 row");
  let s = &samples[0];
  assert!((s.latitude().unwrap() - 4.2).abs() < 1e-6);
  assert!((s.longitude().unwrap() + 10.5).abs() < 1e-6);
}

#[test]
fn quicktime_gopro_gpmf_projects_camera_and_gps_into_media_metadata() {
  // The MediaMetadata projection picks up CameraInfo (make=GoPro,
  // model=HERO6 Black, serial, software) and GpsLocation (first fix).
  let data = build_mov_with_gpro6_in_mdat();
  let meta = exifast::parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  let md = meta.media_metadata();
  let cam = md.camera().expect("GoPro CameraInfo projected");
  assert_eq!(cam.make(), Some("GoPro"));
  assert_eq!(cam.model(), Some("HERO6 Black"));
  assert_eq!(cam.serial(), Some("C3221324657219"));
  assert_eq!(cam.software(), Some("HD6.01.01.51.00"));
  let gps = md.gps().expect("GpsLocation projected from GPS5");
  assert!((gps.latitude().unwrap() - 4.2).abs() < 1e-6);
  assert!((gps.longitude().unwrap() + 10.5).abs() < 1e-6);
}

#[test]
fn quicktime_gopro_gpmf_in_udta_atom() {
  // SP4 — a moov/udta/GPMF atom (the path of QuickTime.pm:2132-2135).
  // Build a movie with a moov-level GPMF atom carrying a DEVC record.
  let data = build_mov_with_gpmf_in_udta();
  let meta = exifast::parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  let gp = meta.gopro();
  assert_eq!(gp.device_name(), Some("Hero"));
  assert_eq!(gp.firmware_version(), Some("HD6.01.01.51.00"));
}

/// Real-fixture conformance stub for GoPro GPMF.
///
/// Bundled exiftool has no GoPro `.mp4` fixture (only `t/images/GoPro.jpg`,
/// an APP6 still photo); the synthetic-buffer unit tests carry the
/// algorithmic coverage. When a small GoPro `.mp4` fixture lands (per
/// follow-up issue #127), unignore this test and add the round-trip
/// assertions against `perl /Users/user/Develop/findit-studio/exiftool/
/// exiftool -j -G -ee <fixture>`.
#[test]
#[ignore = "needs real GoPro .mp4 fixture; see #127"]
fn gopro_real_fixture_conformance() {
  // Placeholder: load fixture, parse via exifast, golden-compare per-tag.
}

/// Build a minimal but valid `.mov` whose `mdat` contains one GoPro
/// `GP\x06\0\0` record. The contained payload is a DEVC GPMF container
/// holding DVNM/MINF/CASN/FMWR + a one-row GPS5 with default scaling.
fn build_mov_with_gpro6_in_mdat() -> Vec<u8> {
  // ftyp atom: 'qt  '.
  let mut ftyp = 16u32.to_be_bytes().to_vec();
  ftyp.extend_from_slice(b"ftyp");
  ftyp.extend_from_slice(b"qt  ");
  ftyp.extend_from_slice(&0u32.to_be_bytes());
  // mvhd (v0, 108 bytes): version+flags + 7 × int32 zero + 1 dword timescale=1000 + ...
  let mut mvhd = Vec::new();
  mvhd.extend_from_slice(&[0u8; 4]);
  mvhd.extend_from_slice(&[0u8; 8]);
  mvhd.extend_from_slice(&1000u32.to_be_bytes());
  mvhd.extend_from_slice(&1000u32.to_be_bytes());
  mvhd.extend_from_slice(&[0u8; 80]);
  let mut moov = (mvhd.len() as u32 + 16).to_be_bytes().to_vec();
  moov.extend_from_slice(b"moov");
  let mut mvhd_atom = (mvhd.len() as u32 + 8).to_be_bytes().to_vec();
  mvhd_atom.extend_from_slice(b"mvhd");
  mvhd_atom.extend_from_slice(&mvhd);
  moov.extend_from_slice(&mvhd_atom);
  // Build the GPMF DEVC container.
  let mut inner = Vec::new();
  inner.extend_from_slice(&klv(b"DVNM", 0x63, 6, 1, b"Camera"));
  inner.extend_from_slice(&klv(b"MINF", 0x63, 11, 1, b"HERO6 Black"));
  inner.extend_from_slice(&klv(b"CASN", 0x63, 14, 1, b"C3221324657219"));
  inner.extend_from_slice(&klv(b"FMWR", 0x63, 15, 1, b"HD6.01.01.51.00"));
  // One GPS5 row with default scaling — lat/lon as int32s.
  let mut gps5_payload = Vec::new();
  gps5_payload.extend_from_slice(&42_000_000i32.to_be_bytes()); // 4.2°
  gps5_payload.extend_from_slice(&(-105_000_000i32).to_be_bytes()); // -10.5°
  gps5_payload.extend_from_slice(&1_500_000i32.to_be_bytes()); // alt 1500 m
  gps5_payload.extend_from_slice(&12_000i32.to_be_bytes()); // spd 12 m/s
  gps5_payload.extend_from_slice(&1_500i32.to_be_bytes()); // spd3d 15 m/s
  inner.extend_from_slice(&klv(b"GPS5", 0x6c, 20, 1, &gps5_payload));
  let devc = klv(b"DEVC", 0, 1, inner.len() as u16, &inner);
  // GP\x06\0\0 record header.
  let mut gp6 = Vec::with_capacity(16);
  gp6.extend_from_slice(b"GP\x06\0"); // tag
  gp6.extend_from_slice(&(devc.len() as u32).to_be_bytes()); // size BE
  gp6.extend_from_slice(&[0u8; 8]); // 8 reserved
  let mut gp6_record = gp6;
  gp6_record.extend_from_slice(&devc);
  // mdat payload = 64 bytes pad + record + 64 bytes pad.
  let mut mdat_payload = vec![0u8; 64];
  mdat_payload.extend_from_slice(&gp6_record);
  mdat_payload.extend_from_slice(&[0u8; 64]);
  let mut mdat = (mdat_payload.len() as u32 + 8).to_be_bytes().to_vec();
  mdat.extend_from_slice(b"mdat");
  mdat.extend_from_slice(&mdat_payload);
  let mut out = ftyp;
  out.extend_from_slice(&moov);
  out.extend_from_slice(&mdat);
  out
}

/// Build a minimal but valid `.mov` whose moov/udta carries a `GPMF` atom
/// with a one-DVNM-record DEVC payload.
fn build_mov_with_gpmf_in_udta() -> Vec<u8> {
  // ftyp atom: 'qt  '.
  let mut ftyp = 16u32.to_be_bytes().to_vec();
  ftyp.extend_from_slice(b"ftyp");
  ftyp.extend_from_slice(b"qt  ");
  ftyp.extend_from_slice(&0u32.to_be_bytes());
  let mut mvhd = Vec::new();
  mvhd.extend_from_slice(&[0u8; 4]);
  mvhd.extend_from_slice(&[0u8; 8]);
  mvhd.extend_from_slice(&1000u32.to_be_bytes());
  mvhd.extend_from_slice(&1000u32.to_be_bytes());
  mvhd.extend_from_slice(&[0u8; 80]);
  let mut mvhd_atom = (mvhd.len() as u32 + 8).to_be_bytes().to_vec();
  mvhd_atom.extend_from_slice(b"mvhd");
  mvhd_atom.extend_from_slice(&mvhd);
  // Build a minimal GPMF payload (DEVC{DVNM,FMWR}).
  let mut inner = Vec::new();
  inner.extend_from_slice(&klv(b"DVNM", 0x63, 4, 1, b"Hero"));
  inner.extend_from_slice(&klv(b"FMWR", 0x63, 15, 1, b"HD6.01.01.51.00"));
  let devc = klv(b"DEVC", 0, 1, inner.len() as u16, &inner);
  let mut gpmf_atom = ((devc.len() as u32) + 8).to_be_bytes().to_vec();
  gpmf_atom.extend_from_slice(b"GPMF");
  gpmf_atom.extend_from_slice(&devc);
  let mut udta_body = Vec::new();
  udta_body.extend_from_slice(&gpmf_atom);
  let mut udta = ((udta_body.len() as u32) + 8).to_be_bytes().to_vec();
  udta.extend_from_slice(b"udta");
  udta.extend_from_slice(&udta_body);
  let mut moov_body = Vec::new();
  moov_body.extend_from_slice(&mvhd_atom);
  moov_body.extend_from_slice(&udta);
  let mut moov = ((moov_body.len() as u32) + 8).to_be_bytes().to_vec();
  moov.extend_from_slice(b"moov");
  moov.extend_from_slice(&moov_body);
  let mut out = ftyp;
  out.extend_from_slice(&moov);
  out
}

/// Build one GPMF KLV record header + payload, padded to 4-byte boundary.
fn klv(tag: &[u8; 4], fmt: u8, sample_size: u8, count: u16, payload: &[u8]) -> Vec<u8> {
  let mut out = Vec::new();
  out.extend_from_slice(tag);
  out.push(fmt);
  out.push(sample_size);
  out.extend_from_slice(&count.to_be_bytes());
  out.extend_from_slice(payload);
  while out.len() % 4 != 0 {
    out.push(0);
  }
  out
}
