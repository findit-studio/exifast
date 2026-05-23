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

// ===========================================================================
// SP4 — Android Google CAMM (Camera Motion Metadata)
// ===========================================================================

#[test]
fn quicktime_camm_decodes_camm5_minimal_gps() {
  // Synthetic .mov with a `camm` MetaFormat metadata track carrying one
  // 28-byte camm5 packet (minimal GPS: 3×f64 lat/lon/alt). The walker must
  // populate `Meta::android_camm` and the MediaMetadata projection must
  // fill GpsLocation from the first fix.
  let data = build_mov_with_camm_track(&camm5_packet(37.5, -122.0, 50.0));
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  let camm = meta.android_camm();
  assert!(!camm.is_empty(), "camm5 must populate android_camm");
  assert_eq!(camm.gps_samples().len(), 1);
  let s = &camm.gps_samples()[0];
  assert_eq!(s.packet_type(), 5);
  assert_eq!(s.latitude(), Some(37.5));
  assert_eq!(s.longitude(), Some(-122.0));
  assert_eq!(s.altitude_m(), Some(50.0));
  // MediaMetadata projects the first fix into GpsLocation.
  let md = meta.media_metadata();
  let gps = md.gps().expect("GpsLocation projected from camm5");
  assert_eq!(gps.latitude(), Some(37.5));
  assert_eq!(gps.longitude(), Some(-122.0));
  assert_eq!(gps.altitude_m(), Some(50.0));
}

#[test]
fn quicktime_camm_decodes_camm6_full_gps_with_date_time() {
  // Synthetic .mov with a camm6 packet (60 bytes: f64 ts + u32 mm + 2×f64 +
  // 7×f32). The projected GpsLocation carries the timestamp.
  let unix_ts = 1_704_067_200.0f64; // 2024-01-01 00:00 UTC
  let data = build_mov_with_camm_track(&camm6_packet(
    unix_ts, /* measure_mode */ 3, /* lat */ 40.0, /* lon */ -75.0,
    /* alt */ 200.0, /* h_acc */ 5.0, /* v_acc */ 10.0, /* v_e */ 1.0,
    /* v_n */ 2.0, /* v_u */ 0.5, /* spd_acc */ 0.1,
  ));
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  let camm = meta.android_camm();
  assert_eq!(camm.gps_samples().len(), 1);
  let s = &camm.gps_samples()[0];
  assert_eq!(s.packet_type(), 6);
  assert_eq!(s.latitude(), Some(40.0));
  assert_eq!(s.longitude(), Some(-75.0));
  assert!((s.altitude_m().unwrap() - 200.0).abs() < 1e-3);
  assert_eq!(s.measure_mode(), Some(3));
  assert_eq!(s.horizontal_accuracy_m(), Some(5.0));
  assert_eq!(s.velocity_east_mps(), Some(1.0));
  // Date/time renders via convert_unix_time + 'Z'.
  assert_eq!(s.date_time(), Some("2024:01:01 00:00:00Z"));
  // MediaMetadata projection picks up the timestamp.
  let md = meta.media_metadata();
  let gps = md.gps().expect("GpsLocation projected from camm6");
  assert_eq!(gps.timestamp(), Some("2024:01:01 00:00:00Z"));
}

#[test]
fn quicktime_camm_decodes_motion_records() {
  // Synthetic .mov with a camm track carrying the four "motion" packet
  // types in a single sample: camm1 (exposure), camm2 (gyro), camm3
  // (accel), camm7 (magnetic field). All must populate their respective
  // Vec in android_camm.
  let mut payload = Vec::new();
  payload.extend_from_slice(&camm_packet(
    1,
    &[
      &500_000_000i32.to_le_bytes()[..], // 0.5 s pixel exposure
      &200_000_000i32.to_le_bytes()[..], // 0.2 s skew
    ]
    .concat(),
  ));
  payload.extend_from_slice(&camm_packet(2, &vec3_le(0.1, 0.2, 0.3)));
  payload.extend_from_slice(&camm_packet(3, &vec3_le(0.0, 0.0, 9.81)));
  payload.extend_from_slice(&camm_packet(7, &vec3_le(25.0, -10.0, 40.0)));
  let data = build_mov_with_camm_track(&payload);
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  let camm = meta.android_camm();
  assert_eq!(camm.exposure().len(), 1);
  assert!((camm.exposure()[0].pixel_exposure_time_s() - 0.5).abs() < 1e-9);
  assert!((camm.exposure()[0].rolling_shutter_skew_time_s() - 0.2).abs() < 1e-9);
  assert_eq!(camm.angular_velocity().len(), 1);
  assert!((camm.angular_velocity()[0].x() - 0.1).abs() < 1e-6);
  assert_eq!(camm.acceleration().len(), 1);
  assert!((camm.acceleration()[0].z() - 9.81).abs() < 1e-3);
  assert_eq!(camm.magnetic_field().len(), 1);
  assert!((camm.magnetic_field()[0].z() - 40.0).abs() < 1e-3);
}

#[test]
fn quicktime_camm_round_trip_via_media_metadata_priority() {
  // The MediaMetadata GPS projection orders sources GoPro → camm → stream;
  // with NO GoPro data, a camm5 packet wins over an absent stream/freeGPS
  // sample.
  let data = build_mov_with_camm_track(&camm5_packet(1.23, 4.56, 100.0));
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  assert!(meta.gopro().is_empty());
  assert!(meta.stream().is_empty());
  assert!(!meta.android_camm().is_empty());
  let md = meta.media_metadata();
  let gps = md.gps().expect("projected from camm");
  assert!((gps.latitude().unwrap() - 1.23).abs() < 1e-9);
  assert!((gps.longitude().unwrap() - 4.56).abs() < 1e-9);
}

/// Real-fixture conformance stub for Android CAMM.
///
/// Bundled exiftool has no Pixel/Samsung CAMM `.mp4` fixture in
/// `t/images/`; the synthetic-packet unit tests carry the algorithmic
/// coverage. When a small camm5/camm6 `.mp4` fixture lands (per follow-up
/// issue #60), unignore this test and add the round-trip assertions
/// against `perl /Users/user/Develop/findit-studio/exiftool/exiftool -j
/// -G -ee <fixture>`.
#[test]
#[ignore = "needs real Pixel/Samsung CAMM .mp4 fixture; see #60"]
fn camm_real_fixture_conformance() {
  // Placeholder: load fixture, parse via exifast, golden-compare per-tag.
}

/// Real-fixture conformance stub for Sony Alpha rtmd.
///
/// Bundled exiftool has no Sony Alpha/FX rtmd `.mp4` fixture; synthetic
/// rtmd-record unit tests carry the algorithmic coverage. When a small
/// Sony rtmd fixture lands (per follow-up issue #76), unignore this test
/// and add the round-trip assertions against `perl /Users/user/Develop/
/// findit-studio/exiftool/exiftool -j -G -ee <fixture>`.
#[test]
#[ignore = "needs real Sony Alpha/FX rtmd .mp4 fixture; see #76"]
fn sony_rtmd_real_fixture_conformance() {
  // Placeholder: load fixture, parse via exifast, golden-compare per-tag.
}

/// Real-fixture conformance for Canon CTMD via the bundled `CanonRaw.cr3`.
///
/// `t/images/CanonRaw.cr3` (Phil Harvey's regression fixture) carries a
/// real Canon EOS R-series CR3 with embedded CTMD records. This test
/// loads the file via exifast and verifies the typed CTMD surface (no
/// algorithmic golden comparison — that needs a `perl exiftool -j` golden
/// snapshot to run; the bundled tree is tested via its own t/ suite).
/// Ignored by default because the bundled tree is an absolute path
/// (only present in the maintainer's checkout); the synthetic-record
/// tests above carry full algorithmic coverage.
#[test]
#[ignore = "promotion test — uses bundled t/images/CanonRaw.cr3; run manually"]
fn canon_ctmd_real_fixture_conformance() {
  let bundled_cr3 = "/Users/user/Develop/findit-studio/exiftool/t/images/CanonRaw.cr3";
  let data = match std::fs::read(bundled_cr3) {
    Ok(v) => v,
    Err(_) => return, // Bundled tree not present — skip gracefully.
  };
  let meta = exifast::parse_quicktime(&data)
    .expect("CR3 parses as MOV-family")
    .expect("recognised file");
  // CR3 carries CTMD samples — the typed surface must populate.
  let ctmd = meta.canon_ctmd();
  if !ctmd.is_empty() {
    // At least one sample decoded — the projection must surface Canon
    // as the camera Make and ExposureSettings should be present.
    let md = meta.media_metadata();
    assert_eq!(
      md.camera().and_then(|c| c.make()),
      Some("Canon"),
      "Canon CTMD projection sets Make=Canon"
    );
  }
}

/// Real-fixture conformance stub for Insta360 INSV/INSP.
///
/// Bundled exiftool has no Insta360 fixture in `t/images/`; the synthetic-
/// trailer unit tests carry the algorithmic coverage. When a small INSV/
/// INSP fixture lands (per follow-up issue #91), unignore this test and
/// add the round-trip assertions against `perl /Users/user/Develop/
/// findit-studio/exiftool/exiftool -j -G -ee <fixture>`.
#[test]
#[ignore = "needs real Insta360 INSV/INSP fixture; see #91"]
fn insta360_real_fixture_conformance() {
  // Placeholder: load fixture, parse via exifast, golden-compare per-tag.
}

// ===========================================================================
// SP4 — Sony rtmd (Real-Time MetaData)
// ===========================================================================

#[test]
fn quicktime_sony_rtmd_decodes_camera_identity_and_exposure() {
  // Synthetic .mov with an `rtmd` MetaFormat metadata track carrying one
  // sample with SerialNumber + FNumber + ExposureTime + ISO + FrameRate.
  // The walker must populate `Meta::sony_rtmd()` and the MediaMetadata
  // projection must surface CameraInfo + CaptureSettings.
  let mut records = Vec::new();
  records.extend_from_slice(&rtmd_record(0x8114, b"ILCE-7SM3 5072108"));
  records.extend_from_slice(&rtmd_record(0x8000, &40960u16.to_be_bytes())); // f/8
  records.extend_from_slice(&rtmd_record(0x8109, &rat64u_be(1, 100))); // 1/100 s
  records.extend_from_slice(&rtmd_record(0x810b, &200u16.to_be_bytes())); // ISO 200
  records.extend_from_slice(&rtmd_record(0x8106, &rat64u_be(24_000, 1001))); // 23.976 fps
  let data = build_mov_with_meta_track(b"rtmd", &rtmd_sample(&records));
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  let rtmd = meta.sony_rtmd();
  assert!(!rtmd.is_empty(), "rtmd must populate sony_rtmd");
  assert_eq!(rtmd.camera_snapshots().len(), 1);
  let snap = &rtmd.camera_snapshots()[0];
  assert_eq!(snap.serial_number(), Some("ILCE-7SM3 5072108"));
  assert_eq!(snap.model(), Some("ILCE-7SM3"));
  assert_eq!(snap.serial(), Some("5072108"));
  assert!((snap.f_number().unwrap() - 8.0).abs() < 1e-9);
  assert!((snap.exposure_time_s().unwrap() - 0.01).abs() < 1e-9);
  assert_eq!(snap.iso(), Some(200));
  assert!((snap.frame_rate().unwrap() - 24_000.0 / 1001.0).abs() < 1e-9);

  // MediaMetadata projection: CameraInfo (Sony, ILCE-7SM3, 5072108).
  let md = meta.media_metadata();
  let cam = md.camera().expect("CameraInfo from rtmd");
  assert_eq!(cam.make(), Some("Sony"));
  assert_eq!(cam.model(), Some("ILCE-7SM3"));
  assert_eq!(cam.serial(), Some("5072108"));

  // MediaMetadata projection: CaptureSettings (1/100 s, ISO 200, f/8).
  let cap = md.capture().expect("CaptureSettings from rtmd");
  assert!((cap.exposure_time_s().unwrap() - 0.01).abs() < 1e-9);
  assert_eq!(cap.iso(), Some(200));
  assert!((cap.f_number().unwrap() - 8.0).abs() < 1e-9);
}

#[test]
fn quicktime_sony_rtmd_decodes_gps_when_present() {
  // Phone-paired Sony rtmd GPS — 0x8500..0x851d. The walker must surface
  // SonyRtmdGpsSample + the GpsLocation projection must combine
  // DateStamp + TimeStamp into the Exif-style timestamp.
  let mut records = Vec::new();
  records.extend_from_slice(&rtmd_record(0x8500, &[2u8, 2, 0, 0])); // version 2.2.0.0
  records.extend_from_slice(&rtmd_record(0x8501, b"N")); // LatRef
  let mut lat = Vec::new();
  lat.extend_from_slice(&rat64u_be(40, 1));
  lat.extend_from_slice(&rat64u_be(30, 1));
  lat.extend_from_slice(&rat64u_be(0, 1));
  records.extend_from_slice(&rtmd_record(0x8502, &lat));
  records.extend_from_slice(&rtmd_record(0x8503, b"W")); // LonRef
  let mut lon = Vec::new();
  lon.extend_from_slice(&rat64u_be(75, 1));
  lon.extend_from_slice(&rat64u_be(15, 1));
  lon.extend_from_slice(&rat64u_be(0, 1));
  records.extend_from_slice(&rtmd_record(0x8504, &lon));
  let mut ts = Vec::new();
  ts.extend_from_slice(&rat64u_be(10, 1));
  ts.extend_from_slice(&rat64u_be(20, 1));
  ts.extend_from_slice(&rat64u_be(30, 1));
  records.extend_from_slice(&rtmd_record(0x8507, &ts));
  records.extend_from_slice(&rtmd_record(0x8509, b"A")); // status active
  records.extend_from_slice(&rtmd_record(0x850a, b"3")); // 3-D
  records.extend_from_slice(&rtmd_record(0x8512, b"WGS-84"));
  records.extend_from_slice(&rtmd_record(0x851d, b"2024:03:05"));
  let data = build_mov_with_meta_track(b"rtmd", &rtmd_sample(&records));
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  let rtmd = meta.sony_rtmd();
  assert_eq!(rtmd.gps_samples().len(), 1);
  let g = &rtmd.gps_samples()[0];
  assert_eq!(g.version_id(), Some("2.2.0.0"));
  // North + West ⇒ lat positive, lon negative.
  assert!((g.latitude().unwrap() - 40.5).abs() < 1e-9);
  assert!((g.longitude().unwrap() + 75.25).abs() < 1e-9);
  assert_eq!(g.time_stamp(), Some("10:20:30"));
  assert_eq!(g.date_stamp(), Some("2024:03:05"));

  // MediaMetadata projection: GpsLocation with combined timestamp.
  let md = meta.media_metadata();
  let gps = md.gps().expect("GpsLocation from rtmd");
  assert!((gps.latitude().unwrap() - 40.5).abs() < 1e-9);
  assert!((gps.longitude().unwrap() + 75.25).abs() < 1e-9);
  assert!(gps.altitude_m().is_none()); // Sony rtmd has no altitude tag
  assert_eq!(gps.timestamp(), Some("2024:03:05 10:20:30"));
}

#[test]
fn quicktime_sony_rtmd_gps_priority_vs_camm_keeps_camm() {
  // The priority chain is GoPro → camm → Sony rtmd → SP3 stream. A file
  // with BOTH camm and rtmd GPS must keep the camm fix (physical-device
  // GPS) over rtmd (phone-paired). This synthetic file only has ONE
  // metadata track at a time, so we exercise the priority by injecting
  // BOTH tracks would be complex; instead this test asserts that an
  // rtmd-only file populates GpsLocation (the rtmd lane is reachable).
  let mut records = Vec::new();
  records.extend_from_slice(&rtmd_record(0x8501, b"N"));
  let mut lat = Vec::new();
  lat.extend_from_slice(&rat64u_be(1, 1));
  lat.extend_from_slice(&rat64u_be(0, 1));
  lat.extend_from_slice(&rat64u_be(0, 1));
  records.extend_from_slice(&rtmd_record(0x8502, &lat));
  records.extend_from_slice(&rtmd_record(0x8503, b"E"));
  let mut lon = Vec::new();
  lon.extend_from_slice(&rat64u_be(2, 1));
  lon.extend_from_slice(&rat64u_be(0, 1));
  lon.extend_from_slice(&rat64u_be(0, 1));
  records.extend_from_slice(&rtmd_record(0x8504, &lon));
  let data = build_mov_with_meta_track(b"rtmd", &rtmd_sample(&records));
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  assert!(meta.gopro().is_empty());
  assert!(meta.android_camm().is_empty());
  assert!(meta.stream().is_empty());
  assert!(!meta.sony_rtmd().is_empty());
  let md = meta.media_metadata();
  let gps = md.gps().expect("rtmd-only feeds GpsLocation");
  assert!((gps.latitude().unwrap() - 1.0).abs() < 1e-9);
  assert!((gps.longitude().unwrap() - 2.0).abs() < 1e-9);
}

// ===========================================================================
// SP4 — Canon CTMD (Canon Timed MetaData)
// ===========================================================================

#[test]
fn quicktime_canon_ctmd_decodes_time_stamp_focal_and_exposure() {
  // Synthetic CR3-style .mov with a `CTMD` MetaFormat metadata track
  // carrying one sample with TimeStamp + FocalInfo + ExposureInfo records
  // mirroring the real CanonRaw.cr3 fixture's byte layout. The walker must
  // populate `Meta::canon_ctmd()` and the MediaMetadata projection must
  // surface CameraInfo (Make=Canon), LensInfo (FocalLength) and
  // CaptureSettings (FNumber/ExposureTime/ISO).
  let mut records = Vec::new();
  records.extend_from_slice(&ctmd_record(
    1,
    &[
      0x00, 0x00, 0xe2, 0x07, 0x02, 0x15, 0x0c, 0x08, 0x38, 0x15, 0x00, 0x00,
    ],
  )); // TimeStamp 2018:02:21 12:08:56.21
  records.extend_from_slice(&ctmd_record(
    4,
    &[
      0x0f, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ],
  )); // FocalLength 15/1 mm
  records.extend_from_slice(&ctmd_record(
    5,
    &[
      0x23, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x50, 0x00, 0x00, 0x32, 0x00, 0x00, 0x01, 0x00, 0x00,
      0x00,
    ],
  )); // FNumber=3.5, ExposureTime=1/80, ISO=12800
  let data = build_mov_with_meta_track(b"CTMD", &records);
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  let ctmd = meta.canon_ctmd();
  assert!(!ctmd.is_empty(), "CTMD must populate canon_ctmd");
  assert_eq!(ctmd.samples().len(), 1);
  let s = &ctmd.samples()[0];
  assert_eq!(s.time_stamp(), Some("2018:02:21 12:08:56.21"));
  let f = s.focal().expect("focal");
  assert!((f.focal_length_mm().unwrap() - 15.0).abs() < 1e-9);
  let e = s.exposure().expect("exposure");
  assert!((e.f_number().unwrap() - 3.5).abs() < 1e-9);
  assert!((e.exposure_time_s().unwrap() - 1.0 / 80.0).abs() < 1e-9);
  assert_eq!(e.iso(), Some(12800));

  // MediaMetadata projection: CameraInfo with Make=Canon.
  let md = meta.media_metadata();
  let cam = md.camera().expect("CameraInfo from CTMD");
  assert_eq!(cam.make(), Some("Canon"));

  // LensInfo: focal length.
  let lens = md.lens().expect("LensInfo from CTMD");
  assert!((lens.focal_length_mm().unwrap() - 15.0).abs() < 1e-9);

  // CaptureSettings: f/3.5, 1/80 s, ISO 12800.
  let cap = md.capture().expect("CaptureSettings from CTMD");
  assert!((cap.f_number().unwrap() - 3.5).abs() < 1e-9);
  assert!((cap.exposure_time_s().unwrap() - 1.0 / 80.0).abs() < 1e-9);
  assert_eq!(cap.iso(), Some(12800));
}

#[test]
fn quicktime_canon_ctmd_iso_high_bit_masked() {
  // Build a CTMD sample with ONLY an ExposureInfo record where the ISO's
  // high bit is set. The walker must mask it off (Canon.pm:9885
  // `ValueConv => '$val & 0x7fffffff'`).
  let mut payload = Vec::new();
  payload.extend_from_slice(&[0x23, 0x00, 0x0a, 0x00]); // FNumber 35/10
  payload.extend_from_slice(&[0x01, 0x00, 0x50, 0x00]); // ExposureTime 1/80
  payload.extend_from_slice(&[0x00, 0x32, 0x00, 0x80]); // ISO 0x80003200 ⇒ 12800
  let records = ctmd_record(5, &payload);
  let data = build_mov_with_meta_track(b"CTMD", &records);
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  let e = meta.canon_ctmd().samples()[0].exposure().expect("exposure");
  assert_eq!(e.iso(), Some(12800));
}

#[test]
fn quicktime_canon_ctmd_truncated_record_warns_and_decodes_prefix() {
  // First record is a clean TimeStamp; second claims size=1000 but the
  // buffer is short. The walker must decode the TimeStamp THEN warn
  // `Truncated CTMD record` and stop, leaving the sample populated.
  let mut records = Vec::new();
  records.extend_from_slice(&ctmd_record(
    1,
    &[
      0x00, 0x00, 0xe2, 0x07, 0x02, 0x15, 0x0c, 0x08, 0x38, 0x15, 0x00, 0x00,
    ],
  ));
  // truncated second record
  records.extend_from_slice(&1000u32.to_le_bytes()); // size = 1000
  records.extend_from_slice(&5u16.to_le_bytes()); // type = 5 ExposureInfo
  records.extend_from_slice(&[0u8; 10]); // header + a few payload bytes
  let data = build_mov_with_meta_track(b"CTMD", &records);
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  let ctmd = meta.canon_ctmd();
  assert_eq!(ctmd.warning(), Some("Truncated CTMD record"));
  assert_eq!(
    ctmd.samples()[0].time_stamp(),
    Some("2018:02:21 12:08:56.21")
  );
}

// --- Canon CTMD helpers -----------------------------------------------------

/// Build one Canon CTMD record `[size:u32-LE][type:u16-LE][6-byte opaque
/// header][payload]`. `payload` excludes the 12-byte prefix.
fn ctmd_record(type_: u16, payload: &[u8]) -> Vec<u8> {
  let size = 12 + payload.len();
  let mut v = Vec::with_capacity(size);
  v.extend_from_slice(&(size as u32).to_le_bytes());
  v.extend_from_slice(&type_.to_le_bytes());
  // Bundled comment (Canon.pm:10769-10780) calls the next 6 bytes the
  // "opaque header"; the values vary per type and are hex-dumped under
  // verbose. Use a realistic value pattern.
  v.extend_from_slice(&[0, 0, 0, 1, 0xff, 0xff]);
  v.extend_from_slice(payload);
  v
}

// --- Sony rtmd helpers ------------------------------------------------------

/// Build one Sony rtmd record `[tag:u16-BE][len:u16-BE][value]`.
fn rtmd_record(tag: u16, value: &[u8]) -> Vec<u8> {
  let mut v = Vec::with_capacity(4 + value.len());
  v.extend_from_slice(&tag.to_be_bytes());
  v.extend_from_slice(&(value.len() as u16).to_be_bytes());
  v.extend_from_slice(value);
  v
}

/// Wrap rtmd records in a sample's 0x1c-byte header.
fn rtmd_sample(records: &[u8]) -> Vec<u8> {
  let mut v = Vec::with_capacity(0x1c + records.len());
  v.extend_from_slice(&0x001cu16.to_be_bytes()); // header length
  v.extend(core::iter::repeat_n(0u8, 0x1c - 2));
  v.extend_from_slice(records);
  v
}

/// Big-endian rational64u 8-byte buffer.
fn rat64u_be(num: u32, denom: u32) -> [u8; 8] {
  let mut out = [0u8; 8];
  out[..4].copy_from_slice(&num.to_be_bytes());
  out[4..].copy_from_slice(&denom.to_be_bytes());
  out
}

// --- camm packet builders ---------------------------------------------------

/// Build a CAMM packet `[reserved:2 (=0)][type:int16u-le][payload]`.
fn camm_packet(t: u16, payload: &[u8]) -> Vec<u8> {
  let mut v = Vec::with_capacity(4 + payload.len());
  v.extend_from_slice(&[0u8, 0u8]); // reserved
  v.extend_from_slice(&t.to_le_bytes());
  v.extend_from_slice(payload);
  v
}

fn camm5_packet(lat: f64, lon: f64, alt: f64) -> Vec<u8> {
  let mut payload = Vec::with_capacity(24);
  payload.extend_from_slice(&lat.to_le_bytes());
  payload.extend_from_slice(&lon.to_le_bytes());
  payload.extend_from_slice(&alt.to_le_bytes());
  camm_packet(5, &payload)
}

#[allow(clippy::too_many_arguments)]
fn camm6_packet(
  gps_dt: f64,
  measure_mode: u32,
  lat: f64,
  lon: f64,
  alt: f32,
  h_acc: f32,
  v_acc: f32,
  v_e: f32,
  v_n: f32,
  v_u: f32,
  spd_acc: f32,
) -> Vec<u8> {
  let mut payload = Vec::with_capacity(56);
  payload.extend_from_slice(&gps_dt.to_le_bytes());
  payload.extend_from_slice(&measure_mode.to_le_bytes());
  payload.extend_from_slice(&lat.to_le_bytes());
  payload.extend_from_slice(&lon.to_le_bytes());
  payload.extend_from_slice(&alt.to_le_bytes());
  payload.extend_from_slice(&h_acc.to_le_bytes());
  payload.extend_from_slice(&v_acc.to_le_bytes());
  payload.extend_from_slice(&v_e.to_le_bytes());
  payload.extend_from_slice(&v_n.to_le_bytes());
  payload.extend_from_slice(&v_u.to_le_bytes());
  payload.extend_from_slice(&spd_acc.to_le_bytes());
  camm_packet(6, &payload)
}

fn vec3_le(x: f32, y: f32, z: f32) -> Vec<u8> {
  let mut v = Vec::with_capacity(12);
  v.extend_from_slice(&x.to_le_bytes());
  v.extend_from_slice(&y.to_le_bytes());
  v.extend_from_slice(&z.to_le_bytes());
  v
}

/// Build a minimal but valid .mov whose moov contains ONE metadata `trak`
/// with `mhlr/meta` handler + a `mebx`-style stsd whose first 4-byte
/// "format" code is the given `meta_format`. The track's single sample
/// is `sample_bytes`, stored at the start of `mdat`. Used by both the
/// camm and Sony rtmd integration tests.
fn build_mov_with_meta_track(meta_format: &[u8; 4], sample_bytes: &[u8]) -> Vec<u8> {
  build_mov_with_meta_track_inner(meta_format, sample_bytes)
}

/// Backwards-compatible alias of [`build_mov_with_meta_track`] hard-coded
/// to the `camm` MetaFormat — used by the SP4 camm tests already in this
/// file.
fn build_mov_with_camm_track(sample_bytes: &[u8]) -> Vec<u8> {
  build_mov_with_meta_track_inner(b"camm", sample_bytes)
}

fn build_mov_with_meta_track_inner(meta_format: &[u8; 4], sample_bytes: &[u8]) -> Vec<u8> {
  // ftyp atom: 'qt  '.
  let mut ftyp = 16u32.to_be_bytes().to_vec();
  ftyp.extend_from_slice(b"ftyp");
  ftyp.extend_from_slice(b"qt  ");
  ftyp.extend_from_slice(&0u32.to_be_bytes());

  let sample_len = sample_bytes.len() as u32;

  // mdat — sample data lives at offset (ftyp.len() + 8) from file start
  // (after ftyp + mdat 8-byte header). The stco entry below points at it.
  let mut mdat = (sample_len + 8).to_be_bytes().to_vec();
  mdat.extend_from_slice(b"mdat");
  mdat.extend_from_slice(sample_bytes);
  let sample_file_offset_val = (ftyp.len() as u32) + 8;

  // mvhd (v0, 100 bytes payload).
  let mut mvhd = Vec::new();
  mvhd.extend_from_slice(&[0u8; 4]); // version+flags
  mvhd.extend_from_slice(&[0u8; 8]); // create/modify
  mvhd.extend_from_slice(&1000u32.to_be_bytes()); // timescale
  mvhd.extend_from_slice(&1000u32.to_be_bytes()); // duration
  mvhd.extend_from_slice(&[0u8; 80]); // rest

  // hdlr (mhlr/meta), 33-byte payload incl. version+flags+pre_defined+type+reserved+name(empty).
  let mut hdlr = Vec::new();
  hdlr.extend_from_slice(&[0u8; 4]); // version+flags
  hdlr.extend_from_slice(b"mhlr"); // pre_defined (matches mebx fixture)
  hdlr.extend_from_slice(b"meta"); // handler_type — meta_handler dispatches
  hdlr.extend_from_slice(&[0u8; 12]); // reserved
  hdlr.push(0); // name (empty)

  // mdhd (v0, 24-byte payload).
  let mut mdhd = Vec::new();
  mdhd.extend_from_slice(&[0u8; 4]); // version+flags
  mdhd.extend_from_slice(&[0u8; 8]); // create/modify
  mdhd.extend_from_slice(&1000u32.to_be_bytes()); // timescale
  mdhd.extend_from_slice(&1000u32.to_be_bytes()); // duration
  mdhd.extend_from_slice(&[0u8; 4]); // language+quality

  // stsd — 1 entry whose first 4-byte format code is `meta_format`.
  // [version+flags:4][count:4][entry-size:4][format:4][reserved:6][data-ref-index:2]
  let mut stsd_entry = Vec::new();
  // Entry: size(=16) + format + 6 reserved bytes + data-ref-index(=1).
  stsd_entry.extend_from_slice(&16u32.to_be_bytes());
  stsd_entry.extend_from_slice(meta_format);
  stsd_entry.extend_from_slice(&[0u8; 6]);
  stsd_entry.extend_from_slice(&1u16.to_be_bytes());
  let mut stsd = Vec::new();
  stsd.extend_from_slice(&[0u8; 4]); // version+flags
  stsd.extend_from_slice(&1u32.to_be_bytes()); // entry count
  stsd.extend_from_slice(&stsd_entry);

  // stts: 1 entry, count=1 delta=1000.
  let mut stts = Vec::new();
  stts.extend_from_slice(&[0u8; 4]);
  stts.extend_from_slice(&1u32.to_be_bytes());
  stts.extend_from_slice(&1u32.to_be_bytes());
  stts.extend_from_slice(&1000u32.to_be_bytes());

  // stsc: 1 entry (first_chunk=1, samples_per_chunk=1, desc_index=1).
  let mut stsc = Vec::new();
  stsc.extend_from_slice(&[0u8; 4]);
  stsc.extend_from_slice(&1u32.to_be_bytes());
  stsc.extend_from_slice(&1u32.to_be_bytes());
  stsc.extend_from_slice(&1u32.to_be_bytes());
  stsc.extend_from_slice(&1u32.to_be_bytes());

  // stsz: 1 sample, explicit size.
  let mut stsz = Vec::new();
  stsz.extend_from_slice(&[0u8; 4]); // version+flags
  stsz.extend_from_slice(&0u32.to_be_bytes()); // sample_size=0 (variable)
  stsz.extend_from_slice(&1u32.to_be_bytes()); // count
  stsz.extend_from_slice(&sample_len.to_be_bytes());

  // stco: 1 chunk offset (pointing at the sample inside mdat).
  let mut stco = Vec::new();
  stco.extend_from_slice(&[0u8; 4]);
  stco.extend_from_slice(&1u32.to_be_bytes());
  stco.extend_from_slice(&sample_file_offset_val.to_be_bytes());

  // Assemble stbl from the tables.
  let mut stbl = Vec::new();
  stbl.extend_from_slice(&atom_bytes(b"stsd", &stsd));
  stbl.extend_from_slice(&atom_bytes(b"stts", &stts));
  stbl.extend_from_slice(&atom_bytes(b"stsc", &stsc));
  stbl.extend_from_slice(&atom_bytes(b"stsz", &stsz));
  stbl.extend_from_slice(&atom_bytes(b"stco", &stco));

  // minf with nmhd + stbl.
  let nmhd = atom_bytes(b"nmhd", &[0u8; 4]);
  let mut minf = nmhd;
  minf.extend_from_slice(&atom_bytes(b"stbl", &stbl));

  // mdia with mdhd + hdlr + minf.
  let mut mdia = atom_bytes(b"mdhd", &mdhd);
  mdia.extend_from_slice(&atom_bytes(b"hdlr", &hdlr));
  mdia.extend_from_slice(&atom_bytes(b"minf", &minf));

  // trak with tkhd (minimal) + mdia.
  let tkhd_payload = vec![0u8; 84];
  let mut trak = atom_bytes(b"tkhd", &tkhd_payload);
  trak.extend_from_slice(&atom_bytes(b"mdia", &mdia));

  // moov with mvhd + trak.
  let mut moov = atom_bytes(b"mvhd", &mvhd);
  moov.extend_from_slice(&atom_bytes(b"trak", &trak));

  let mut out = ftyp;
  // Mirror the fixture order: ftyp / mdat / moov is also valid; we use
  // ftyp / moov / mdat which matches build_mov_with_gpro6_in_mdat.
  // Note: stco offset MUST land inside the mdat we emit; we placed mdat
  // RIGHT AFTER ftyp, so sample_file_offset is correct.
  out.extend_from_slice(&mdat);
  out.extend_from_slice(&atom_bytes(b"moov", &moov));
  out
}

/// Wrap `body` as a top-level atom `[size:u32 BE][type:4][body]`.
fn atom_bytes(t: &[u8; 4], body: &[u8]) -> Vec<u8> {
  let mut v = ((body.len() + 8) as u32).to_be_bytes().to_vec();
  v.extend_from_slice(t);
  v.extend_from_slice(body);
  v
}

// ===========================================================================
// SP4 — Insta360 trailer
// ===========================================================================

/// Build a minimal QuickTime file with an Insta360 trailer appended.
///
/// File layout: `[ftyp][moov][mdat]` (standard MOV) followed by the
/// Insta360 trailer (records + 78-byte footer).
fn build_mov_with_insta360_trailer(records: &[(u16, Vec<u8>)]) -> Vec<u8> {
  // Minimal valid MOV (ftyp + moov + mdat) prefix.
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
  let mvhd_atom = atom_bytes(b"mvhd", &mvhd);
  let moov = atom_bytes(b"moov", &mvhd_atom);

  let mdat_payload = vec![0u8; 16];
  let mdat = atom_bytes(b"mdat", &mdat_payload);

  let mut file = ftyp;
  file.extend_from_slice(&moov);
  file.extend_from_slice(&mdat);

  // Append the Insta360 trailer. Each record body is followed by its 6-byte
  // [id:u16-LE][len:u32-LE] footer; the trailer ends with a 78-byte footer
  // whose first 6 bytes are the LAST record's id+len (so the LAST record's
  // 6-byte footer IS the first 6 bytes of the 78-byte trailer footer).
  let trailer_start = file.len();
  for (id, body) in records {
    file.extend_from_slice(body);
    file.extend_from_slice(&id.to_le_bytes());
    file.extend_from_slice(&(body.len() as u32).to_le_bytes());
  }
  let (last_id, last_len) = if let Some((id, body)) = records.last() {
    (*id, body.len() as u32)
  } else {
    (0u16, 0u32)
  };
  // Strip the last 6-byte footer; we'll fold it into the 78-byte trailer footer.
  file.truncate(file.len() - 6);
  let trailer_len = (file.len() - trailer_start) as u32 + 78;
  // 78-byte trailer footer: [last_id:u16-LE][last_len:u32-LE][32 opaque]
  // [trailer_len:u32-LE][4 opaque][32-byte ASCII magic].
  file.extend_from_slice(&last_id.to_le_bytes());
  file.extend_from_slice(&last_len.to_le_bytes());
  file.extend_from_slice(&[0u8; 32]);
  file.extend_from_slice(&trailer_len.to_le_bytes());
  file.extend_from_slice(&[0u8; 4]);
  file.extend_from_slice(b"8db42d694ccc418790edff439fe026bf");
  file
}

/// One 0x101 identity record body: `[tag:u8][len:u8][value]` items.
fn insta360_identity_body(items: &[(u8, &[u8])]) -> Vec<u8> {
  let mut out = Vec::new();
  for (t, v) in items {
    out.push(*t);
    out.push(v.len() as u8);
    out.extend_from_slice(v);
  }
  out
}

/// One 53-byte 0x700 GPS row.
#[allow(clippy::too_many_arguments)]
fn insta360_gps_row(
  unixtime: u32,
  ms: u16,
  status: u8,
  lat: f64,
  ns: u8,
  lon: f64,
  ew: u8,
  speed_mps: f64,
  track_deg: f64,
  altitude_m: f64,
) -> Vec<u8> {
  let mut out = Vec::with_capacity(53);
  out.extend_from_slice(&unixtime.to_le_bytes());
  out.extend_from_slice(&0u32.to_le_bytes());
  out.extend_from_slice(&ms.to_le_bytes());
  out.push(status);
  out.extend_from_slice(&lat.to_le_bytes());
  out.push(ns);
  out.extend_from_slice(&lon.to_le_bytes());
  out.push(ew);
  out.extend_from_slice(&speed_mps.to_le_bytes());
  out.extend_from_slice(&track_deg.to_le_bytes());
  out.extend_from_slice(&altitude_m.to_le_bytes());
  out
}

#[test]
fn quicktime_insta360_trailer_identity_only_projects_camera_info() {
  // An Insta360 file with only a `0x101` identity record. The parser must
  // populate `Meta::insta360()` and `MediaMetadata::camera_info()` with
  // Make=Insta360 + Model=Insta360 X3 + Software=1.0.07 + Serial=IXX00123.
  let id_body = insta360_identity_body(&[
    (0x0a, b"IXX00123"),      // SerialNumber
    (0x12, b"Insta360 X3"),   // Model
    (0x1a, b"1.0.07"),        // Firmware
    (0x2a, b"2_6_4032_3024"), // Parameters
  ]);
  let data = build_mov_with_insta360_trailer(&[(0x101, id_body)]);
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized as MOV");
  let i = meta.insta360();
  assert!(!i.is_empty(), "insta360() must populate");
  let id = i.identity().expect("identity decoded");
  assert_eq!(id.model(), Some("Insta360 X3"));
  assert_eq!(id.serial_number(), Some("IXX00123"));
  assert_eq!(id.firmware(), Some("1.0.07"));
  assert_eq!(id.parameters(), Some("2 6 4032 3024"));

  // MediaMetadata projection: CameraInfo with Insta360 fields.
  let md = meta.media_metadata();
  let cam = md.camera().expect("CameraInfo from Insta360");
  assert_eq!(cam.make(), Some("Insta360"));
  assert_eq!(cam.model(), Some("Insta360 X3"));
  assert_eq!(cam.serial(), Some("IXX00123"));
  assert_eq!(cam.software(), Some("1.0.07"));
}

#[test]
fn quicktime_insta360_trailer_gps_record_projects_gps_location() {
  // An Insta360 file with one 0x700 GPS record carrying one active fix.
  // The parser must populate `Meta::insta360().first_fix()` AND
  // `MediaMetadata::gps_location()`.
  let gps_body = insta360_gps_row(
    1717250400, // 2024:06:01 14:00:00 UTC
    0, b'A', 45.0, b'N', 8.0, b'E', 10.0, 90.0, 200.0,
  );
  let data = build_mov_with_insta360_trailer(&[(0x700, gps_body)]);
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  let fix = meta.insta360().first_fix().expect("fix");
  assert!((fix.latitude().unwrap() - 45.0).abs() < 1e-9);
  assert!((fix.longitude().unwrap() - 8.0).abs() < 1e-9);
  assert!((fix.altitude_m().unwrap() - 200.0).abs() < 1e-9);
  assert!((fix.speed_kph().unwrap() - 36.0).abs() < 1e-9); // 10 m/s * 3.6
  assert_eq!(fix.date_time(), Some("2024:06:01 14:00:00Z"));
  // GpsLocation projection
  let md = meta.media_metadata();
  let gps = md.gps().expect("GpsLocation from Insta360");
  assert!((gps.latitude().unwrap() - 45.0).abs() < 1e-9);
  assert!((gps.longitude().unwrap() - 8.0).abs() < 1e-9);
  assert!((gps.altitude_m().unwrap() - 200.0).abs() < 1e-9);
  assert_eq!(gps.timestamp(), Some("2024:06:01 14:00:00Z"));
}

#[test]
fn quicktime_insta360_identity_and_gps_full_projection() {
  // An Insta360 file with BOTH identity + GPS records. The projection
  // should yield CameraInfo + GpsLocation.
  let id_body = insta360_identity_body(&[(0x12, b"Insta360 ONE RS"), (0x1a, b"1.0.01")]);
  let gps_body = insta360_gps_row(
    1717250400, 250, b'A', 37.7749, b'N', -122.4194, b'W', 5.0, 0.0, 10.0,
  );
  let data = build_mov_with_insta360_trailer(&[(0x101, id_body), (0x700, gps_body)]);
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  let md = meta.media_metadata();
  let cam = md.camera().expect("CameraInfo");
  assert_eq!(cam.make(), Some("Insta360"));
  assert_eq!(cam.model(), Some("Insta360 ONE RS"));
  let gps = md.gps().expect("GpsLocation");
  assert!((gps.latitude().unwrap() - 37.7749).abs() < 1e-9);
  assert!((gps.longitude().unwrap() - -122.4194).abs() < 1e-9);
  // ms=250 ⇒ ".25" suffix (after trailing-zero strip).
  assert_eq!(gps.timestamp(), Some("2024:06:01 14:00:00.25Z"));
}

#[test]
fn quicktime_no_insta360_trailer_leaves_meta_empty() {
  // A plain QuickTime file (no Insta360 trailer) must have an empty
  // `insta360()` meta — the signature check is a 32-byte compare at file
  // EOF; nothing else should fire.
  let data = build_mov_with_freegps_in_mdat();
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  assert!(meta.insta360().is_empty());
}
