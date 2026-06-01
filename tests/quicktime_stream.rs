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
fn quicktime_mebx_float_array_value_reads_all_elements() {
  // REGRESSION (mebx float-array): `Process_mebx` (QuickTimeStream.pl:2668)
  // calls `ReadValue($dataPt, $pos+8, $$info{Format}, undef, $len-8)` — a
  // `count == undef` read. ExifTool.pm:6296-6330 then sets
  // `$count = int($size/$len)` and space-joins ALL elements
  // (`join(' ', @vals) if @vals > 1`). So a `float[4]` value
  // (`%qtFmt` code 72 — "float[4] x,y,width,height") decodes to FOUR floats,
  // NOT just the first. The earlier `read_meta_value` decoded only `[0..4]`
  // (the first element) — this fixture pins the full-array behavior.
  //
  // Crafted fixture: one `mebx` track whose `keys` table maps local-id 1 →
  // TagID `TestMatrix` with `dtyp` namespace-0 `qtFmt` code 72 (float); the
  // single timed sample carries the big-endian `float[4]`
  // `[1.0, 2.5, -3.0, 4.25]`. Oracle (`perl exiftool -ee`,
  // `QuickTime_mebx_float.mov.ee.json`) ⇒ `Track1:TestMatrix = "1 2.5 -3 4.25"`.
  let data = fixture("QuickTime_mebx_float.mov");
  let golden = ee_golden("QuickTime_mebx_float.mov");
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  let stream = meta.stream();
  let pairs = stream.mebx_samples();
  assert_eq!(pairs.len(), 1, "one mebx key/value pair");
  assert_eq!(pairs[0].name(), "TestMatrix");
  // The FULL float[4] array, space-joined (each element via `%.15g`).
  assert_eq!(
    pairs[0].value(),
    "1 2.5 -3 4.25",
    "all four float elements must be decoded and space-joined"
  );
  // Byte-for-byte equal to the bundled oracle's Track1:TestMatrix.
  let want = golden
    .get("Track1:TestMatrix")
    .and_then(|v| v.as_str())
    .expect("golden TestMatrix");
  assert_eq!(pairs[0].value(), want, "oracle parity for the float array");
}

#[test]
fn quicktime_mebx_keys_table_name_resolution_and_value_conv() {
  // REGRESSION (mebx key resolution + per-key ValueConv): `Process_mebx`
  // (QuickTimeStream.pl:2657-2669) resolves each TagID through the
  // `%QuickTime::Keys` table (the `mebx` SubDirectory's TagTable,
  // QuickTimeStream.pl:177). This fixture has TWO keys in one sample:
  //   * `scene-illuminance` — a `%QuickTime::Keys` entry (QuickTime.pm:6840)
  //     ⇒ Name `SceneIlluminance`, ValueConv `unpack("N",$val)`; the raw
  //     undef bytes `00 00 04 D2` ⇒ `1234`.
  //   * `test.foo-bar` — NOT in `%QuickTime::Keys` ⇒ the dynamic-add path
  //     (QuickTimeStream.pl:2663-2664) camel-cases it to `TestFooBar`; the
  //     value is the raw (undef) string `hi`.
  // Oracle (`perl exiftool -ee`, `QuickTime_mebx_keys.mov.ee.json`) ⇒
  //   Track1:SceneIlluminance = 1234, Track1:TestFooBar = "hi".
  let data = fixture("QuickTime_mebx_keys.mov");
  let golden = ee_golden("QuickTime_mebx_keys.mov");
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
  let pairs = meta.stream().mebx_samples();
  assert_eq!(pairs.len(), 2, "two mebx key/value pairs");

  // Keys-table lookup + ValueConv unpack("N",..).
  assert_eq!(pairs[0].name(), "SceneIlluminance");
  assert_eq!(pairs[0].value(), "1234");
  let want_illum = golden
    .get("Track1:SceneIlluminance")
    .expect("golden SceneIlluminance")
    .to_string();
  assert_eq!(want_illum, "1234", "oracle SceneIlluminance");

  // Dynamic-add camel-case of an unknown reverse-DNS TagID.
  assert_eq!(pairs[1].name(), "TestFooBar");
  assert_eq!(pairs[1].value(), "hi");
  let want_foo = golden
    .get("Track1:TestFooBar")
    .and_then(|v| v.as_str())
    .expect("golden TestFooBar");
  assert_eq!(pairs[1].value(), want_foo, "oracle TestFooBar");
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
