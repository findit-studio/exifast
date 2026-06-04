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

use exifast::{AnyMeta, ConvMode, parse_bytes, parse_quicktime};

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
  let meta = parse_quicktime(&data).expect("recognized");
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
  let meta = parse_quicktime(&data).expect("recognized");
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
  let meta = parse_quicktime(&data).expect("recognized");
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
fn quicktime_mebx_live_photo_info_unpacks_le_blob() {
  // `live-photo-info` (QuickTime.pm:6789-6791) is a `%QuickTime::Keys` entry
  // whose ValueConv is `join " ",unpack "VfVVf6c4lCCcclf4Vvv",$val` — a fixed
  // 80-byte LITTLE-ENDIAN blob unpacked into 27 scalars and space-joined. The
  // bundled comment concedes the `f`/`l` codes are native-endian and the
  // goldens are generated on a little-endian machine, so the port decodes LE.
  //
  // Crafted fixture: one `mebx` track whose `keys` table maps local-id 1 →
  // TagID `live-photo-info` (undef format — the raw bytes feed the unpack); the
  // single timed sample carries the 80-byte LE value
  //   V=1 f=1.5 V=2 V=3 f6=[.25 .5 .75 1 1.25 1.5] c4=[1 -2 3 -4] l=-1000
  //   C=200 C=250 c=-5 c=7 l=123456 f4=[2.5 -3.5 4 .125] V=99 v=1000 v=65535.
  // Oracle (`perl exiftool -ee`, `QuickTime_mebx_livephoto.mov.ee.json`) ⇒
  //   Track1:LivePhotoInfo = "1 1.5 2 3 0.25 0.5 0.75 1 1.25 1.5 1 -2 3 -4
  //   -1000 200 250 -5 7 123456 2.5 -3.5 4 0.125 99 1000 65535".
  let data = fixture("QuickTime_mebx_livephoto.mov");
  let golden = ee_golden("QuickTime_mebx_livephoto.mov");
  let meta = parse_quicktime(&data).expect("recognized");
  let pairs = meta.stream().mebx_samples();
  assert_eq!(pairs.len(), 1, "one mebx key/value pair");
  assert_eq!(pairs[0].name(), "LivePhotoInfo");
  // Byte-for-byte equal to the bundled oracle's Track1:LivePhotoInfo (the 27
  // space-joined scalars; floats via Perl's default `%.15g`).
  let want = golden
    .get("Track1:LivePhotoInfo")
    .and_then(|v| v.as_str())
    .expect("golden LivePhotoInfo");
  assert_eq!(
    pairs[0].value(),
    want,
    "oracle parity for the unpacked live-photo-info blob"
  );
}

#[cfg(feature = "plist")]
#[test]
fn quicktime_mebx_smartstyle_info_decodes_embedded_plist() {
  // `smartstyle-info` (QuickTime.pm:6847-6852) is a `%QuickTime::Keys`
  // SubDirectory entry whose value is a binary PLIST, processed through
  // `Image::ExifTool::PLIST::Main` / `PLIST::ProcessBinaryPLIST`. So a `mebx`
  // `smartstyle-info` sample's value bytes ARE a `bplist00` blob; ExifTool
  // emits the resulting PLIST tags (camel-cased keys, family-0 group `PLIST`).
  //
  // Crafted fixture: one `mebx` track whose `keys` table maps local-id 1 →
  // TagID `smartstyle-info`; the single timed sample carries a binary plist
  // `{ styleIntensity = 80, styleName = "Vivid" }`. Oracle (`perl exiftool
  // -ee -G1:0`, `QuickTime_mebx_smartstyle.mov.ee.json`) ⇒
  //   Track1:PLIST StyleIntensity = 80, Track1:PLIST StyleName = "Vivid"
  // (family-0 `PLIST`, family-1 re-scoped to the enclosing `Track1`).
  //
  // exifast wires the value through `PLIST::parse_borrowed` and stores the
  // decoded PLIST tags (preserving the typed value + the PLIST family-0 group)
  // in `QuickTimeStreamMeta::plist_subdir_tags`.
  let data = fixture("QuickTime_mebx_smartstyle.mov");
  let golden = ee_golden("QuickTime_mebx_smartstyle.mov");
  let meta = parse_quicktime(&data).expect("recognized");
  // The embedded PLIST is NOT a scalar `mebx` pair (the SubDirectory replaces
  // the scalar) — it lands in the nested-PLIST tag list.
  assert!(
    meta.stream().mebx_samples().is_empty(),
    "smartstyle-info is a SubDirectory, not a scalar mebx pair"
  );
  let tags = meta.stream().plist_subdir_tags();
  assert_eq!(tags.len(), 2, "two PLIST tags from the embedded bplist");

  // The decoded PLIST tags carry the PLIST table's family-0 group, the
  // camel-cased PLIST key name, and the TYPED value (int / string) — faithful
  // to the standalone PLIST emission (`PLIST:StyleIntensity` = 80, etc.).
  let intensity = &tags[0];
  assert_eq!(intensity.group_ref().family0(), "PLIST");
  assert_eq!(intensity.name(), "StyleIntensity");
  let style_name = &tags[1];
  assert_eq!(style_name.group_ref().family0(), "PLIST");
  assert_eq!(style_name.name(), "StyleName");

  // Value-equivalent to the bundled oracle's Track1:StyleIntensity (80, a bare
  // JSON number) and Track1:StyleName ("Vivid").
  let want_intensity = golden
    .get("Track1:StyleIntensity")
    .expect("golden StyleIntensity");
  assert_eq!(want_intensity.as_i64(), Some(80), "oracle StyleIntensity");
  // The typed value preserves the integer type the oracle emits as a bare
  // number (NOT a stringified "80").
  match intensity.value_ref() {
    exifast::value::TagValue::I64(n) => assert_eq!(*n, 80),
    other => panic!("StyleIntensity should be a typed integer, got {other:?}"),
  }
  let want_name = golden
    .get("Track1:StyleName")
    .and_then(|v| v.as_str())
    .expect("golden StyleName");
  assert_eq!(want_name, "Vivid", "oracle StyleName");
  match style_name.value_ref() {
    exifast::value::TagValue::Str(s) => assert_eq!(s.as_str(), "Vivid"),
    other => panic!("StyleName should be a typed string, got {other:?}"),
  }
}

#[test]
fn quicktime_mebx_detected_face_decodes_nested_atom_tree() {
  // `detected-face` (QuickTime.pm:6808-6811) is a `%QuickTime::Keys`
  // SubDirectory entry naming `QuickTime::FaceInfo` (`PROCESS_PROC =>
  // ProcessMOV`). So a `mebx` `detected-face` sample's value bytes are a NESTED
  // MOV atom tree: `crec` (→ `FaceRec`, also `ProcessMOV`) → `cits` (→
  // `%QuickTime::Keys` with `ProcessProc => Process_mebx`). The `cits` content
  // is itself a `mebx` record stream decoded against the SAME `keys` map,
  // resolving the four leaf keys (QuickTime.pm:6816-6828):
  //   detected-face.bounds     (dtyp 80, float[8]) -> DetectedFaceBounds
  //     PrintConv `int($_*1e6+.5)/1e6` per element (round to 6 dp).
  //   detected-face.face-id    (dtyp 77, int32u)   -> DetectedFaceID
  //   detected-face.roll-angle (dtyp 23, float)    -> DetectedFaceRollAngle
  //   detected-face.yaw-angle  (dtyp 23, float)    -> DetectedFaceYawAngle
  //
  // Crafted fixture: one `mebx` track whose `keys` table maps local-id 1 ->
  // `detected-face` (undef) and local-ids 2..5 -> the four leaf keys; the single
  // timed sample carries TWO `crec` faces. The port re-enters its box walker on
  // the sample value (FaceInfo -> FaceRec -> cits) and decodes BOTH faces into
  // flat `mebx` samples (8 = 2 faces x 4 keys). ExifTool's flat `-G1` last-wins
  // TagMap keeps only the SECOND face's values; the per-document `-G3:1` oracle
  // shows BOTH and matches the port's full list.
  //
  // Face 1 bounds exercise the positive round (0.123456789 -> 0.123457); face 2
  // (the last-wins golden) exercises the NEGATIVE round direction — Perl int()
  // truncates toward zero after +.5, so -2.3456785 -> -2.345678 (round-half-up
  // toward +inf, NOT away-from-zero -2.345679).
  let data = fixture("QuickTime_mebx_detface.mov");
  let golden = ee_golden("QuickTime_mebx_detface.mov");
  let meta = parse_quicktime(&data).expect("recognized");
  let stream = meta.stream();

  // `detected-face` is a SubDirectory: its scalar form is NEVER emitted (the
  // pre-fix branch wrongly stored the raw nested-atom bytes as a `FaceInfo`
  // scalar). The leaf keys land as flat `mebx` samples.
  let pairs = stream.mebx_samples();
  assert!(
    pairs.iter().all(|p| p.name() != "FaceInfo"),
    "the detected-face parent must NOT be emitted as a scalar"
  );
  assert_eq!(pairs.len(), 8, "two faces x four leaf keys");

  // Face 1 (QuickTime.pm:6816-6828 order: bounds, face-id, roll, yaw).
  assert_eq!(pairs[0].name(), "DetectedFaceBounds");
  assert_eq!(
    pairs[0].value(),
    "0.1 0.2 0.3 0.4 0.123457 0.5 0.6 0.7",
    "face 1 bounds rounded to 6 dp (0.123456789 -> 0.123457)"
  );
  assert_eq!(pairs[1].name(), "DetectedFaceID");
  assert_eq!(pairs[1].value(), "1001");
  assert_eq!(pairs[2].name(), "DetectedFaceRollAngle");
  assert_eq!(pairs[2].value(), "12.5");
  assert_eq!(pairs[3].name(), "DetectedFaceYawAngle");
  assert_eq!(pairs[3].value(), "-7.25");

  // Face 2 — the SampleTime/SampleDuration thread through to every leaf.
  assert_eq!(pairs[4].name(), "DetectedFaceBounds");
  assert_eq!(
    pairs[4].value(),
    "0.765432 -2.345678 0.33 0.44 0.55 0.66 0.77 0.88",
    "face 2 bounds — negative round-half-up toward +inf (-2.3456785 -> -2.345678)"
  );
  assert_eq!(pairs[5].name(), "DetectedFaceID");
  assert_eq!(pairs[5].value(), "1002");
  assert_eq!(pairs[6].name(), "DetectedFaceRollAngle");
  assert_eq!(
    pairs[6].value(),
    "-3",
    "roll-angle has no PrintConv (unrounded)"
  );
  assert_eq!(pairs[7].name(), "DetectedFaceYawAngle");
  assert_eq!(pairs[7].value(), "45");

  // Every leaf carries the enclosing sample's time/duration.
  for p in pairs {
    assert_eq!(p.sample_time(), Some(0.0));
    assert_eq!(p.sample_duration(), Some(1.0));
  }

  // Byte-for-byte equal to the bundled oracle's flat `-G1` last-wins values
  // (the SECOND face — ExifTool's TagMap overwrites the first).
  let want_bounds = golden
    .get("Track1:DetectedFaceBounds")
    .and_then(|v| v.as_str())
    .expect("golden DetectedFaceBounds");
  assert_eq!(
    pairs[4].value(),
    want_bounds,
    "oracle parity for the rounded face bounds"
  );
  assert_eq!(
    golden.get("Track1:DetectedFaceID").and_then(|v| v.as_i64()),
    Some(1002),
    "oracle DetectedFaceID"
  );
  assert_eq!(
    golden
      .get("Track1:DetectedFaceRollAngle")
      .and_then(|v| v.as_i64()),
    Some(-3),
    "oracle DetectedFaceRollAngle"
  );
  assert_eq!(
    golden
      .get("Track1:DetectedFaceYawAngle")
      .and_then(|v| v.as_i64()),
    Some(45),
    "oracle DetectedFaceYawAngle"
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
  let meta = parse_quicktime(&data).expect("recognized");
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
  let meta = parse_quicktime(&data).expect("recognized");
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
  let meta = parse_quicktime(&data).expect("recognized");
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
  let meta = parse_quicktime(&data).expect("recognized");
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
  let meta = parse_quicktime(&data).expect("recognized");
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
  let meta = parse_quicktime(&data).expect("recognized");
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

#[test]
fn quicktime_moov_gps_box_decodes_block_outside_mdat() {
  // Codex R3 — the `moov`-level Novatek `gps ` box (the EMPTY-HandlerType box,
  // `%eeBox{''}{'gps '} = 'moov'`, QuickTime.pm:523-533) is an offset TABLE
  // whose `(start, size)` pairs point at `freeGPS ` blocks ANYWHERE in the
  // file — `ParseTag` reads each block and runs ProcessSamples
  // (QuickTimeStream.pl:2544-2556). This fixture is the XGODY 12" 4K Dashcam
  // shape: a single Type-6 `freeGPS ` block lives OUTSIDE `mdat` (between
  // `ftyp` and `moov`), reachable ONLY via the offset table. Oracle (`-ee`):
  //   GPSLatitude 47 deg 37' 42.30" N, GPSLongitude 122 deg 9' 54.08" W,
  //   GPSDateTime 2024:07:15 14:30:45Z.
  let data = fixture("QuickTime_moov_gps.mov");
  let golden = ee_golden("QuickTime_moov_gps.mov");
  let meta = parse_quicktime(&data).expect("recognized");
  let stream = meta.stream();
  assert_eq!(
    stream.gps_samples().len(),
    1,
    "the moov-level gps ' offset table must decode the out-of-mdat block"
  );
  let s = &stream.gps_samples()[0];
  // Type-6 stores lat/lon as f32 (block-relative); 4737.7053 DDDMM.MMMM ⇒
  // 47.6284..., 12209.901 (West) ⇒ -122.1650... — cross-checking the oracle's
  // DMS PrintConv string (`47 deg 37' 42.30" N`, `122 deg 9' 54.08" W`). The
  // f32 round-trip widens the tolerance, exactly as the brute-force-scan test.
  let lat = s.latitude().expect("latitude");
  let lon = s.longitude().expect("longitude");
  assert!((lat - 47.628_421).abs() < 1e-3, "lat {lat}");
  assert!((lon + 122.165_016).abs() < 1e-3, "lon {lon}");
  let dms_lat = golden
    .get("QuickTime:GPSLatitude")
    .and_then(|v| v.as_str())
    .expect("golden GPSLatitude");
  assert!(dms_lat.ends_with('N'), "fix is North: {dms_lat}");
  let dms_lon = golden
    .get("QuickTime:GPSLongitude")
    .and_then(|v| v.as_str())
    .expect("golden GPSLongitude");
  assert!(dms_lon.ends_with('W'), "fix is West: {dms_lon}");
  // The block carries its OWN date (Type-6 parses yr/mon/day + hr/min/sec), so
  // GPSDateTime matches the oracle exactly — independent of any SampleTime.
  assert_eq!(
    s.date_time(),
    golden.get("QuickTime:GPSDateTime").and_then(|v| v.as_str()),
    "GPSDateTime matches the oracle"
  );
}

#[test]
fn quicktime_frea_kodak_tags_decode_with_oracle_parity() {
  // Part A — the top-level `frea` atom → `Image::ExifTool::Kodak::frea`
  // (QuickTime.pm:610-613 ⇒ Kodak.pm:2977-2990). The fixture's `frea` carries
  // `tima` (Duration 3725s), `'ver '` (KodakVersion "3.01.054"), `thma`
  // (ThumbnailImage 40B) and `scra` (PreviewImage 60B). Bundled `-ee -G1` ⇒
  // the four tags under family-0 `MakerNotes`, family-1 `Kodak`.
  let data = fixture("QuickTime_frea_rexing17b.mov");
  let golden = ee_golden("QuickTime_frea_rexing17b.mov");
  let meta = parse_quicktime(&data).expect("recognized");

  // Typed accessor: the decoded `frea` values.
  let frea = meta.quicktime().kodak_frea();
  assert!(!frea.is_empty(), "frea atom must be decoded");
  assert_eq!(frea.duration_secs(), Some(3725), "tima raw int32u seconds");
  assert_eq!(frea.version(), Some("3.01.054"), "KodakVersion string");
  assert_eq!(frea.thumbnail_len(), Some(40), "thma payload byte count");
  assert_eq!(frea.preview_len(), Some(60), "scra payload byte count");

  // Rendered tag stream (the golden `Meta::tags()` path): the four tags emit
  // under family-0 `MakerNotes`, family-1 `Kodak`, with the bundled-parity
  // PrintConv values.
  let any = parse_bytes(&data).expect("recognized");
  assert!(matches!(any, AnyMeta::QuickTime(_)), "got {any:?}");
  let tags: Vec<exifast::Tag> = any.iter_tags(ConvMode::PrintConv).collect();
  let kodak: std::collections::HashMap<&str, &exifast::Tag> = tags
    .iter()
    .filter(|t| t.group_ref().family0() == "MakerNotes" && t.group_ref().family1() == "Kodak")
    .map(|t| (t.name(), t))
    .collect();
  assert_eq!(kodak.len(), 4, "exactly the four Kodak frea tags");
  for (name, want_key) in [
    ("Duration", "Kodak:Duration"),
    ("KodakVersion", "Kodak:KodakVersion"),
    ("ThumbnailImage", "Kodak:ThumbnailImage"),
    ("PreviewImage", "Kodak:PreviewImage"),
  ] {
    let tag = kodak
      .get(name)
      .unwrap_or_else(|| panic!("Kodak:{name} emitted"));
    // Every frea PrintConv value is a `TagValue::Str` (Duration ⇒ ConvertDuration
    // string, KodakVersion ⇒ raw string, thma/scra ⇒ binary placeholder).
    let got = match tag.value_ref() {
      exifast::TagValue::Str(s) => s.as_str(),
      other => panic!("Kodak:{name} expected a string value, got {other:?}"),
    };
    let want = golden
      .get(want_key)
      .and_then(|v| v.as_str())
      .unwrap_or_else(|| panic!("golden {want_key}"));
    assert_eq!(got, want, "Kodak:{name} oracle parity ({got} vs {want})");
  }
}

#[test]
fn quicktime_frea_rexing_type17b_scales_gps_via_kodak_version() {
  // Part B — the `frea`-atom KodakVersion ("3.01.054") is threaded into the
  // `mdat` freeGPS scan; the Type-17 block then takes the 17b Rexing V1-4k
  // scaling (QuickTimeStream.pl:2323-2327): `(lat-187.982162849635)/3` /
  // `(lon-2199.19873715495)/2`, decimal degrees, `W` ref negating the lon.
  // Bundled `-ee` ⇒ GPSLatitude 33.6697742486894, GPSLongitude
  // -112.096920485025 (verified vs ExifTool 13.59).
  let data = fixture("QuickTime_frea_rexing17b.mov");
  let meta = parse_quicktime(&data).expect("recognized");
  let fix = meta
    .stream()
    .first_fix()
    .expect("17b GPS fix from the mdat freeGPS scan");
  let lat = fix.latitude().expect("lat");
  let lon = fix.longitude().expect("lon");
  assert!(
    (lat - 33.669_774_248_689_4).abs() < 1e-6,
    "17b lat {lat} (want 33.6697742486894)"
  );
  assert!(
    (lon - -112.096_920_485_025).abs() < 1e-6,
    "17b lon {lon} (want -112.096920485025)"
  );
  assert!(
    (fix.speed_kph().expect("spd") - 92.6).abs() < 1e-3,
    "17b speed 92.6 km/h (knotsToKph, NOT divided)"
  );
  assert_eq!(fix.track(), Some(90.0), "17b track");
  assert_eq!(fix.date_time(), Some("2024:02:22 14:34:40Z"));
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
  // mdat payload = 64 bytes pad + block + padding past 0x8000.
  // ExifTool bails a sub-0x8000 FINAL chunk WITHOUT decoding (`last if
  // length $buff < $gpsBlockSize`, QuickTimeStream.pl:3750), so the block must
  // be found in a full 0x8000-byte chunk — pad the `mdat` accordingly (this
  // matches a real dashcam, whose first freeGPS block sits in an early full
  // chunk; a sub-0x8000 mdat yields NO GPS, oracle-verified).
  let mut mdat_payload = vec![0u8; 64];
  mdat_payload.extend_from_slice(&block);
  mdat_payload.extend_from_slice(&vec![0u8; 0x9000]);
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
  let meta = exifast::parse_quicktime(&data).expect("recognized");
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
  let meta = exifast::parse_quicktime(&data).expect("recognized");
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
fn quicktime_gopro_gpmf_emits_gopro_group_tags_speed_in_kph() {
  // SP4 — the golden `Meta::tags()` path emits the GoPro GPMF tags under
  // family-0/family-1 `GoPro` (the `%GoPro::GPMF`/`GPS5` tables,
  // GoPro.pm:67-69/489-490). The GPS5 fix is summarized (first row); the
  // identity scalars are one-per-file. KEY: `GPSSpeed`/`GPSSpeed3D` apply the
  // ValueConv `$val * 3.6` (m/s → km/h, GoPro.pm:504-513) on emission — the
  // fixture stores 12 m/s / 15 m/s, so the emitted tags are 43.2 / 54.0 km/h.
  let data = build_mov_with_gpro6_in_mdat();
  let any = parse_bytes(&data).expect("recognized");
  assert!(matches!(any, AnyMeta::QuickTime(_)), "got {any:?}");
  let tags: Vec<exifast::Tag> = any.iter_tags(ConvMode::PrintConv).collect();
  let gp: std::collections::HashMap<&str, &exifast::Tag> = tags
    .iter()
    .filter(|t| t.group_ref().family0() == "GoPro" && t.group_ref().family1() == "GoPro")
    .map(|t| (t.name(), t))
    .collect();
  // Identity strings.
  let want_str = |name: &str| match gp.get(name).map(|t| t.value_ref()) {
    Some(exifast::TagValue::Str(s)) => s.as_str().to_string(),
    other => panic!("GoPro:{name} expected a string, got {other:?}"),
  };
  assert_eq!(want_str("DeviceName"), "Camera");
  assert_eq!(want_str("Model"), "HERO6 Black");
  assert_eq!(want_str("CameraSerialNumber"), "C3221324657219");
  assert_eq!(want_str("FirmwareVersion"), "HD6.01.01.51.00");
  // GPS fix: decimal lat/lon (DMS PrintConv deferred, like the SP3 stream),
  // metres altitude, and km/h speeds.
  let want_f64 = |name: &str| match gp.get(name).map(|t| t.value_ref()) {
    Some(&exifast::TagValue::F64(v)) => v,
    other => panic!("GoPro:{name} expected an f64, got {other:?}"),
  };
  assert!((want_f64("GPSLatitude") - 4.2).abs() < 1e-6);
  assert!((want_f64("GPSLongitude") + 10.5).abs() < 1e-6);
  assert!((want_f64("GPSAltitude") - 1500.0).abs() < 1e-6);
  // 12 m/s × 3.6 = 43.2 km/h; 15 m/s × 3.6 = 54.0 km/h.
  assert!(
    (want_f64("GPSSpeed") - 43.2).abs() < 1e-6,
    "GPSSpeed must be km/h"
  );
  assert!(
    (want_f64("GPSSpeed3D") - 54.0).abs() < 1e-6,
    "GPSSpeed3D must be km/h"
  );
}

#[test]
fn quicktime_gopro_gpmf_in_udta_atom() {
  // SP4 — a moov/udta/GPMF atom (the path of QuickTime.pm:2132-2135).
  // Build a movie with a moov-level GPMF atom carrying a DEVC record.
  let data = build_mov_with_gpmf_in_udta();
  let meta = exifast::parse_quicktime(&data).expect("recognized");
  let gp = meta.gopro();
  assert_eq!(gp.device_name(), Some("Hero"));
  assert_eq!(gp.firmware_version(), Some("HD6.01.01.51.00"));
}

#[test]
fn quicktime_gopro_karma_glpi_kbat_decode_and_emit() {
  // R5 — a Karma-drone GPMF (moov/udta/GPMF) carrying TYPE+SCAL+GLPI (GPSPos)
  // and TYPE+SCAL+KBAT (BatteryStatus) in separate STRMs, plus a SYST
  // calibration. Asserts: (1) the typed GLPI/KBAT collections decode; (2) the
  // golden `tags()` path emits the Karma tags under family-0/1 `GoPro`;
  // (3) the GLPI GPS fix projects into MediaMetadata (no GPS5/GPS9 present).
  let data = build_mov_with_karma_gpmf_in_udta();
  let meta = exifast::parse_quicktime(&data).expect("recognized");
  let gp = meta.gopro();
  // Typed GLPI sample.
  let g = gp.glpi_samples().first().expect("one GLPI sample");
  assert!((g.latitude().unwrap() - 4.2).abs() < 1e-6);
  assert!((g.longitude().unwrap() + 10.5).abs() < 1e-6);
  assert!((g.altitude_m().unwrap() - 1500.0).abs() < 1e-6);
  assert!((g.track_deg().unwrap() - 180.0).abs() < 1e-6);
  // Typed KBAT record.
  let k = gp.kbat_records().first().expect("one KBAT record");
  assert!((k.current_a().unwrap() - 1.5).abs() < 1e-4);
  assert!((k.level_pct().unwrap() - 95.0).abs() < 1e-4);
  assert!((k.voltage1_v().unwrap() - 4.0).abs() < 1e-4);

  // Golden emission — GoPro:GoPro family tags.
  let any = parse_bytes(&data).expect("recognized");
  let tags: Vec<exifast::Tag> = any.iter_tags(ConvMode::PrintConv).collect();
  let gpm: std::collections::HashMap<&str, &exifast::Tag> = tags
    .iter()
    .filter(|t| t.group_ref().family0() == "GoPro" && t.group_ref().family1() == "GoPro")
    .map(|t| (t.name(), t))
    .collect();
  let want_f64 = |name: &str| match gpm.get(name).map(|t| t.value_ref()) {
    Some(&exifast::TagValue::F64(v)) => v,
    other => panic!("GoPro:{name} expected an f64, got {other:?}"),
  };
  let want_str = |name: &str| match gpm.get(name).map(|t| t.value_ref()) {
    Some(exifast::TagValue::Str(s)) => s.as_str().to_string(),
    other => panic!("GoPro:{name} expected a string, got {other:?}"),
  };
  // GLPI lat/lon/alt: DMS / `"$val m"` PrintConv deferred (raw F64), the
  // accepted GPS5/GPS9/GLPI deferral.
  assert!((want_f64("GPSLatitude") - 4.2).abs() < 1e-6);
  assert!((want_f64("GPSLongitude") + 10.5).abs() < 1e-6);
  assert!((want_f64("GPSAltitude") - 1500.0).abs() < 1e-6);
  // R6-C: GLPI speeds DO apply `'"$val m/s"'` in PrintConv mode (stay m/s —
  // GLPI has no *3.6 km/h ValueConv). GPSTrack (col 8) has no PrintConv (raw).
  assert_eq!(want_str("GPSSpeedX"), "1.5 m/s");
  assert!((want_f64("GPSTrack") - 180.0).abs() < 1e-6);
  // R6-C: KBAT unit-suffix PrintConvs apply in PrintConv mode.
  assert_eq!(want_str("BatteryCurrent"), "1.5 A");
  assert_eq!(want_str("BatteryVoltage1"), "4 V");
  assert_eq!(want_str("BatteryLevel"), "95 %");
  // R6-C: BatteryTime PrintConv `ConvertDuration(int($val + 0.5))` — 36000 s →
  // "10:00:00".
  assert_eq!(want_str("BatteryTime"), "10:00:00");
  // R6-B: SystemTime is a default tag emitted by `-ee` — the post-SCAL 2-column
  // join of the FIRST (single-row) SYST record (first-wins). The fixture's
  // first SYST is (sys=0, unix_ms=1551484800000) → "0 1551484800".
  assert_eq!(want_str("SystemTime"), "0 1551484800");
  // GPSDateTime: with the SYST calibration the systime 5.0 interpolates to a
  // whole-number epoch ⇒ the faithful ExifTool all-zero quirk literal.
  match gpm.get("GPSDateTime").map(|t| t.value_ref()) {
    Some(exifast::TagValue::Str(s)) => assert_eq!(s.as_str(), "0000:00:00 00:00:00"),
    other => panic!("GPSDateTime expected a string, got {other:?}"),
  }

  // GLPI GPS projects into MediaMetadata (no GPS5/GPS9 present).
  let md = meta.media_metadata();
  let gps = md.gps().expect("GLPI fix projected into GpsLocation");
  assert!((gps.latitude().unwrap() - 4.2).abs() < 1e-6);
  assert!((gps.longitude().unwrap() + 10.5).abs() < 1e-6);
  assert!((gps.altitude_m().unwrap() - 1500.0).abs() < 1e-6);
  // The all-zero GPSDateTime quirk is NOT used as the projection timestamp
  // (usable_glpi_time filters the `0000:` sentinel).
  assert_eq!(gps.timestamp(), None);
  // CameraInfo still projects (DVNM → model fallback).
  let cam = md.camera().expect("GoPro CameraInfo");
  assert_eq!(cam.make(), Some("GoPro"));
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
/// holding DVNM/MINF/CASN/FMWR + the canonical SCAL vector + a one-row GPS5
/// (GPS5 kept last so the GoPro.pm:884 last-in-container SCAL guard fires).
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
  // The canonical SCAL vector ahead of GPS5 (GoPro.pm:218). ExifTool scales
  // GPS5 only when a SCAL record was seen AND GPS5 is the LAST record in its
  // container (GoPro.pm:884 `if $scal and $tag ne 'SCAL' and
  // $pos+$size+3>=$dirEnd`); a real GoPro STRM always begins with SCAL, so
  // emit it here with GPS5 kept last. SCAL = [1e7, 1e7, 1000, 1000, 100].
  let scal_payload: Vec<u8> = [10_000_000u32, 10_000_000, 1_000, 1_000, 100]
    .iter()
    .flat_map(|v| v.to_be_bytes())
    .collect();
  inner.extend_from_slice(&klv(b"SCAL", 0x4c, 4, 5, &scal_payload));
  // One GPS5 row — raw int32s; SCAL above divides them to 4.2° / -10.5° /
  // 1500 m / 12 m/s / 15 m/s. GPS5 is the LAST record so scaling fires.
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

/// Wrap a GPMF KLV body in one `STRM` container.
fn strm(body: &[u8]) -> Vec<u8> {
  klv(b"STRM", 0, 1, body.len() as u16, body)
}

/// Build a minimal `.mov` whose moov/udta carries a `GPMF` atom holding a
/// Karma-drone DEVC: DVNM + two single-row SYST calibration STRMs + a GLPI
/// (`GPSPos`) STRM + a KBAT (`BatteryStatus`) STRM. The TYPE/SCAL records use
/// the canonical Karma layouts (GoPro.pm:200-201 / 267-268); the values mirror
/// the PR oracle pinned against `perl exiftool` 13.59.
fn build_mov_with_karma_gpmf_in_udta() -> Vec<u8> {
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

  // ── SYST calibration STRMs (TYPE=JJ, SCAL=1000000 1000) ──────────────
  let syst_type = klv(b"TYPE", 0x63, 2, 1, &[0x4a, 0x4a]); // 'JJ'
  let syst_scal_p: Vec<u8> = [1_000_000u32, 1000]
    .iter()
    .flat_map(|v| v.to_be_bytes())
    .collect();
  let syst_scal = klv(b"SCAL", 0x4c, 4, 2, &syst_scal_p);
  let mk_syst_strm = |sys: u64, unix_ms: u64| {
    let mut r = Vec::new();
    r.extend_from_slice(&sys.to_be_bytes());
    r.extend_from_slice(&unix_ms.to_be_bytes());
    let syst = klv(b"SYST", 0x3f, 16, 1, &r);
    let mut b = Vec::new();
    b.extend_from_slice(&syst_type);
    b.extend_from_slice(&syst_scal);
    b.extend_from_slice(&syst);
    strm(&b)
  };

  // ── GLPI STRM (TYPE=LllllsssS, SCAL per GoPro.pm:201) ────────────────
  let glpi_type = klv(
    b"TYPE",
    0x63,
    9,
    1,
    &[0x4c, 0x6c, 0x6c, 0x6c, 0x6c, 0x73, 0x73, 0x73, 0x53],
  );
  let glpi_scal_p: Vec<u8> = [
    1000u32, 10_000_000, 10_000_000, 1000, 1000, 100, 100, 100, 100,
  ]
  .iter()
  .flat_map(|v| v.to_be_bytes())
  .collect();
  let glpi_scal = klv(b"SCAL", 0x4c, 4, 9, &glpi_scal_p);
  let mut glpi_row = Vec::new();
  glpi_row.extend_from_slice(&5000u32.to_be_bytes()); // systime →5.0
  glpi_row.extend_from_slice(&42_000_000i32.to_be_bytes()); // lat →4.2
  glpi_row.extend_from_slice(&(-105_000_000i32).to_be_bytes()); // lon →-10.5
  glpi_row.extend_from_slice(&1_500_000i32.to_be_bytes()); // alt →1500
  glpi_row.extend_from_slice(&2000i32.to_be_bytes()); // unk4 (dropped)
  glpi_row.extend_from_slice(&150i16.to_be_bytes()); // spdX →1.5
  glpi_row.extend_from_slice(&250i16.to_be_bytes()); // spdY →2.5
  glpi_row.extend_from_slice(&(-100i16).to_be_bytes()); // spdZ →-1.0
  glpi_row.extend_from_slice(&18000u16.to_be_bytes()); // track →180
  let mut glpi_body = Vec::new();
  glpi_body.extend_from_slice(&glpi_type);
  glpi_body.extend_from_slice(&glpi_scal);
  glpi_body.extend_from_slice(&klv(b"GLPI", 0x3f, 28, 1, &glpi_row));
  let glpi_strm = strm(&glpi_body);

  // ── KBAT STRM (TYPE=lLlsSSSSSSSBBBb, SCAL per GoPro.pm:268) ───────────
  let kbat_type = klv(
    b"TYPE",
    0x63,
    15,
    1,
    &[
      0x6c, 0x4c, 0x6c, 0x73, 0x53, 0x53, 0x53, 0x53, 0x53, 0x53, 0x53, 0x42, 0x42, 0x42, 0x62,
    ],
  );
  // 0.01f32 / 0.016_666_668f32 = the exact f32 round-trips of ExifTool's
  // 0.00999999977648258 / 0.0166666675359011 SCAL factors (GoPro.pm:268).
  let ks = [
    1000.0f32,
    1000.0,
    0.01,
    100.0,
    1000.0,
    1000.0,
    1000.0,
    1000.0,
    0.016_666_668,
    1.0,
    1.0,
    1.0,
    1.0,
    1.0,
    1.0,
  ];
  let kbat_scal_p: Vec<u8> = ks.iter().flat_map(|v| v.to_be_bytes()).collect();
  let kbat_scal = klv(b"SCAL", 0x66, 4, 15, &kbat_scal_p);
  let mut kbat_row = Vec::new();
  kbat_row.extend_from_slice(&1500i32.to_be_bytes()); // current →1.5
  kbat_row.extend_from_slice(&2000u32.to_be_bytes()); // capacity →2
  kbat_row.extend_from_slice(&100i32.to_be_bytes()); // unk2 (dropped)
  kbat_row.extend_from_slice(&3500i16.to_be_bytes()); // temp →35
  kbat_row.extend_from_slice(&4000u16.to_be_bytes()); // V1 →4
  kbat_row.extend_from_slice(&4100u16.to_be_bytes()); // V2 →4.1
  kbat_row.extend_from_slice(&4200u16.to_be_bytes()); // V3 →4.2
  kbat_row.extend_from_slice(&4300u16.to_be_bytes()); // V4 →4.3
  kbat_row.extend_from_slice(&600u16.to_be_bytes()); // time →10s scaled→36000s? (0.0166→36000)
  kbat_row.extend_from_slice(&88u16.to_be_bytes()); // unk9 (dropped)
  kbat_row.extend_from_slice(&7u16.to_be_bytes()); // unk10 (dropped)
  kbat_row.push(11); // unk11 (dropped)
  kbat_row.push(12); // unk12 (dropped)
  kbat_row.push(13); // unk13 (dropped)
  kbat_row.extend_from_slice(&95i8.to_be_bytes()); // level →95
  let mut kbat_body = Vec::new();
  kbat_body.extend_from_slice(&kbat_type);
  kbat_body.extend_from_slice(&kbat_scal);
  kbat_body.extend_from_slice(&klv(b"KBAT", 0x3f, 32, 1, &kbat_row));
  let kbat_strm = strm(&kbat_body);

  // ── DEVC container ───────────────────────────────────────────────────
  let mut devc_body = Vec::new();
  devc_body.extend_from_slice(&klv(b"DVNM", 0x63, 5, 1, b"Karma"));
  devc_body.extend_from_slice(&mk_syst_strm(0, 1_551_484_800_000));
  devc_body.extend_from_slice(&mk_syst_strm(10_000_000, 1_551_484_810_000));
  devc_body.extend_from_slice(&glpi_strm);
  devc_body.extend_from_slice(&kbat_strm);
  let devc = klv(b"DEVC", 0, 1, devc_body.len() as u16, &devc_body);

  let mut gpmf_atom = ((devc.len() as u32) + 8).to_be_bytes().to_vec();
  gpmf_atom.extend_from_slice(b"GPMF");
  gpmf_atom.extend_from_slice(&devc);
  let mut udta = ((gpmf_atom.len() as u32) + 8).to_be_bytes().to_vec();
  udta.extend_from_slice(b"udta");
  udta.extend_from_slice(&gpmf_atom);
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

// ===========================================================================
// SP4 — R12-A: the FULL default-visible %GoPro::GPMF tag set (sensor streams +
// scalar settings + calibrations). Per-tag values oracle-pinned vs
// `perl exiftool 13.59 -ee` (see also the byte-exact end-to-end conformance
// fixture QuickTime_gopro_gpmf.mov in tests/conformance.rs).
// ===========================================================================

/// Build a `.mov` whose `moov/udta/GPMF` carries a DEVC with sensor STRMs
/// (`Binary` ACCL), a `SHUT` exposure stream, a standalone `STMP`, a `TMPC`
/// scalar, and a plain-multi `MAGN`. The moov/udta/GPMF path is processed
/// WITHOUT `-ee` (it is a moov atom), so the full emission path is exercised.
fn build_mov_with_sensor_gpmf_in_udta() -> Vec<u8> {
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

  // ACCL STRM: SCAL=418 (s int16s), 2 rows ⇒ "2 3 -0.5 1 2 4" (14 chars).
  let accl_strm = {
    let scal = klv(b"SCAL", 0x73, 2, 1, &418i16.to_be_bytes());
    let mut data = Vec::new();
    let rows: [(i16, i16, i16); 2] = [(836, 1254, -209), (418, 836, 1672)];
    for &(x, y, z) in &rows {
      data.extend_from_slice(&x.to_be_bytes());
      data.extend_from_slice(&y.to_be_bytes());
      data.extend_from_slice(&z.to_be_bytes());
    }
    let mut b = Vec::new();
    b.extend_from_slice(&scal);
    b.extend_from_slice(&klv(b"ACCL", 0x73, 6, 2, &data));
    strm(&b)
  };
  // SHUT exposure stream: floats 0.005, 0.008 ⇒ PrintConv "1/200 1/125".
  let shut_strm = {
    let mut data = Vec::new();
    data.extend_from_slice(&0.005f32.to_be_bytes());
    data.extend_from_slice(&0.008f32.to_be_bytes());
    strm(&klv(b"SHUT", 0x66, 4, 2, &data))
  };
  // Standalone STMP (TimeStamp, J int64u, /1e6).
  let stmp_strm = strm(&klv(b"STMP", 0x4a, 8, 1, &12_345_678u64.to_be_bytes()));
  // MAGN plain multi (scaled /100): single row (10,20,30) ⇒ "0.1 0.2 0.3".
  let magn_strm = {
    let scal = klv(b"SCAL", 0x73, 2, 1, &100i16.to_be_bytes());
    let mut data = Vec::new();
    for v in [10i16, 20, 30] {
      data.extend_from_slice(&v.to_be_bytes());
    }
    let mut b = Vec::new();
    b.extend_from_slice(&scal);
    b.extend_from_slice(&klv(b"MAGN", 0x73, 6, 1, &data));
    strm(&b)
  };

  let mut devc_body = Vec::new();
  devc_body.extend_from_slice(&klv(b"DVNM", 0x63, 6, 1, b"Camera"));
  devc_body.extend_from_slice(&klv(b"TMPC", 0x66, 4, 1, &42.5f32.to_be_bytes()));
  devc_body.extend_from_slice(&accl_strm);
  devc_body.extend_from_slice(&shut_strm);
  devc_body.extend_from_slice(&stmp_strm);
  devc_body.extend_from_slice(&magn_strm);
  let devc = klv(b"DEVC", 0, 1, devc_body.len() as u16, &devc_body);

  let mut gpmf_atom = ((devc.len() as u32) + 8).to_be_bytes().to_vec();
  gpmf_atom.extend_from_slice(b"GPMF");
  gpmf_atom.extend_from_slice(&devc);
  let mut udta = ((gpmf_atom.len() as u32) + 8).to_be_bytes().to_vec();
  udta.extend_from_slice(b"udta");
  udta.extend_from_slice(&gpmf_atom);
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

#[test]
fn quicktime_gopro_sensor_streams_emit_binary_and_scaled_values() {
  // R12-A — sensor streams + scalar conv families through the golden `tags()`
  // path. Oracle (`perl exiftool 13.59 -ee`):
  //   Accelerometer = "(Binary data 14 bytes, use -b option to extract)" (both)
  //   ExposureTimes = "1/200 1/125" (PrintConv) / raw float list (ValueConv)
  //   TimeStamp = 12.345678; CameraTemperature = "42.5 C" / 42.5;
  //   Magnetometer = "0.1 0.2 0.3".
  let data = build_mov_with_sensor_gpmf_in_udta();
  let any = parse_bytes(&data).expect("recognized");

  let collect = |mode| -> std::collections::HashMap<String, exifast::TagValue> {
    any
      .iter_tags(mode)
      .filter(|t| t.group_ref().family0() == "GoPro")
      .map(|t| (t.name().to_string(), t.value_ref().clone()))
      .collect()
  };
  let pc = collect(ConvMode::PrintConv);
  let nc = collect(ConvMode::ValueConv);
  let s = |m: &std::collections::HashMap<String, exifast::TagValue>, k: &str| match m.get(k) {
    Some(exifast::TagValue::Str(v)) => v.as_str().to_string(),
    other => panic!("GoPro:{k} expected Str, got {other:?}"),
  };

  // `Binary => 1` placeholder in BOTH modes, N = 14 (the scaled "2 3 -0.5 1 2 4").
  assert_eq!(
    s(&pc, "Accelerometer"),
    "(Binary data 14 bytes, use -b option to extract)"
  );
  assert_eq!(
    s(&nc, "Accelerometer"),
    "(Binary data 14 bytes, use -b option to extract)"
  );
  // SHUT: PrintExposureTime per element in `-j`; raw float list in `-n`.
  assert_eq!(s(&pc, "ExposureTimes"), "1/200 1/125");
  assert!(
    s(&nc, "ExposureTimes").starts_with("0.0049999"),
    "ValueConv ExposureTimes is the raw float list: {}",
    s(&nc, "ExposureTimes")
  );
  // STMP `/1e6` (folded at decode): same in both modes.
  match pc.get("TimeStamp") {
    Some(&exifast::TagValue::F64(v)) => assert!((v - 12.345678).abs() < 1e-9),
    other => panic!("TimeStamp {other:?}"),
  }
  // TMPC `"$val C"` in `-j`, raw F64 in `-n`.
  assert_eq!(s(&pc, "CameraTemperature"), "42.5 C");
  match nc.get("CameraTemperature") {
    Some(&exifast::TagValue::F64(v)) => assert!((v - 42.5).abs() < 1e-9),
    other => panic!("CameraTemperature -n {other:?}"),
  }
  // MAGN plain multi (scaled), same in both modes.
  assert_eq!(s(&pc, "Magnetometer"), "0.1 0.2 0.3");
  assert_eq!(s(&nc, "Magnetometer"), "0.1 0.2 0.3");
}

#[test]
fn quicktime_gopro_multirow_binary_complex_emits_placeholder_per_row() {
  // R12-A — a MULTI-ROW complex-`?` `Binary => 1` tag (CSEN, TYPE=LffffffLLLL,
  // no SCAL). ExifTool's `\$val` is `\@rows`, so it emits a JSON ARRAY with ONE
  // `(Binary data N bytes…)` per row, each N = that row's value-string length.
  // Oracle (`perl exiftool 13.59 -ee`): two rows ⇒
  // ["(Binary data 110 bytes, use -b option to extract)", <same>] (each raw row
  // = "1000 0.100000001490116 … 10 20 30 40", 110 chars).
  let data = build_mov_with_csen_two_rows_in_udta();
  let any = parse_bytes(&data).expect("recognized");
  let tag = any
    .iter_tags(ConvMode::PrintConv)
    .find(|t| t.group_ref().family0() == "GoPro" && t.name() == "CoyoteSense")
    .expect("CoyoteSense emitted");
  match tag.value_ref() {
    exifast::TagValue::List(items) => {
      assert_eq!(items.len(), 2, "one placeholder per row");
      for it in items {
        match it {
          exifast::TagValue::Str(s) => {
            assert_eq!(
              s.as_str(),
              "(Binary data 110 bytes, use -b option to extract)"
            );
          }
          other => panic!("row placeholder expected Str, got {other:?}"),
        }
      }
    }
    other => panic!("multi-row Binary CSEN expected a List, got {other:?}"),
  }
}

/// Build a `moov/udta/GPMF` `.mov` with a 2-row CSEN (`Binary` + complex `?`,
/// TYPE=LffffffLLLL, no SCAL) for the multi-row-Binary placeholder test.
fn build_mov_with_csen_two_rows_in_udta() -> Vec<u8> {
  let csen_type = klv(b"TYPE", 0x63, 11, 1, b"LffffffLLLL");
  let csen_row = || {
    let mut r = 1000u32.to_be_bytes().to_vec();
    for f in [0.1f32, 0.2, 0.3, 0.4, 0.5, 0.6] {
      r.extend_from_slice(&f.to_be_bytes());
    }
    for v in [10u32, 20, 30, 40] {
      r.extend_from_slice(&v.to_be_bytes());
    }
    r
  };
  let mut rows = csen_row();
  rows.extend_from_slice(&csen_row());
  let mut body = Vec::new();
  body.extend_from_slice(&csen_type);
  body.extend_from_slice(&klv(b"CSEN", 0x3f, 44, 2, &rows));
  let csen_strm = strm(&body);

  let mut devc_body = Vec::new();
  devc_body.extend_from_slice(&klv(b"DVNM", 0x63, 6, 1, b"Camera"));
  devc_body.extend_from_slice(&csen_strm);
  let devc = klv(b"DEVC", 0, 1, devc_body.len() as u16, &devc_body);

  let mut mvhd = vec![0u8; 4];
  mvhd.extend_from_slice(&[0u8; 8]);
  mvhd.extend_from_slice(&1000u32.to_be_bytes());
  mvhd.extend_from_slice(&1000u32.to_be_bytes());
  mvhd.extend_from_slice(&[0u8; 80]);
  let moov = mov_atom(
    b"moov",
    &[
      mov_atom(b"mvhd", &mvhd),
      mov_atom(b"udta", &mov_atom(b"GPMF", &devc)),
    ]
    .concat(),
  );
  let ftyp = mov_atom(b"ftyp", &{
    let mut b = b"qt  ".to_vec();
    b.extend_from_slice(&0u32.to_be_bytes());
    b
  });
  let mut out = ftyp;
  out.extend_from_slice(&moov);
  out
}

#[test]
fn quicktime_gopro_multirow_addunits_emits_array_with_units() {
  // R12-A — a MULTI-ROW `%addUnits` complex-`?` tag (SIMU, TYPE=Lsssssssss,
  // SCAL all 1000, SIUN=s,g,g,g,rad/s×3,T,T,T). ExifTool runs `AddUnits` per row
  // (`$val = \@rows`): `-j` ⇒ a JSON array of per-row unit-interleaved strings,
  // `-n` ⇒ a JSON array of bare per-row scaled strings (oracle-verified vs
  // `perl exiftool 13.59 -ee`).
  let data = build_mov_with_simu_two_rows_in_udta();
  let any = parse_bytes(&data).expect("recognized");
  let get = |mode| -> exifast::TagValue {
    any
      .iter_tags(mode)
      .find(|t| t.group_ref().family0() == "GoPro" && t.name() == "ScaledIMU")
      .map(|t| t.value_ref().clone())
      .expect("ScaledIMU emitted")
  };
  let want_list = |v: exifast::TagValue, expect: &str| match v {
    exifast::TagValue::List(items) => {
      assert_eq!(items.len(), 2, "one entry per row");
      for it in &items {
        match it {
          exifast::TagValue::Str(s) => assert_eq!(s.as_str(), expect),
          other => panic!("row expected Str, got {other:?}"),
        }
      }
    }
    other => panic!("multi-row SIMU expected a List, got {other:?}"),
  };
  want_list(
    get(ConvMode::PrintConv),
    "1 s 0.1 g 0.2 g 0.3 g 0.4 rad/s 0.5 rad/s 0.6 rad/s 0.7 T 0.8 T 0.9 T",
  );
  want_list(
    get(ConvMode::ValueConv),
    "1 0.1 0.2 0.3 0.4 0.5 0.6 0.7 0.8 0.9",
  );
}

/// Build a `moov/udta/GPMF` `.mov` with a 2-row SIMU (`%addUnits` complex `?`,
/// TYPE=Lsssssssss, SCAL all 1000, SIUN=s,g,g,g,rad/s,rad/s,rad/s,T,T,T) for the
/// multi-row AddUnits test.
fn build_mov_with_simu_two_rows_in_udta() -> Vec<u8> {
  let units: [&[u8]; 10] = [
    b"s", b"g", b"g", b"g", b"rad/s", b"rad/s", b"rad/s", b"T", b"T", b"T",
  ];
  let unit_payload: Vec<u8> = units
    .iter()
    .flat_map(|u| {
      let mut c = u.to_vec();
      c.resize(5, 0);
      c
    })
    .collect();
  let siun = klv(b"SIUN", 0x63, 5, 10, &unit_payload);
  let simu_type = klv(b"TYPE", 0x63, 10, 1, b"Lsssssssss");
  let scal_p: Vec<u8> = core::iter::repeat_n(1000u32, 10)
    .flat_map(u32::to_be_bytes)
    .collect();
  let simu_scal = klv(b"SCAL", 0x4c, 4, 10, &scal_p);
  let row = || {
    let mut r = 1000u32.to_be_bytes().to_vec();
    for v in [100i16, 200, 300, 400, 500, 600, 700, 800, 900] {
      r.extend_from_slice(&v.to_be_bytes());
    }
    r
  };
  let mut rows = row();
  rows.extend_from_slice(&row());
  let mut body = Vec::new();
  body.extend_from_slice(&siun);
  body.extend_from_slice(&simu_type);
  body.extend_from_slice(&simu_scal);
  body.extend_from_slice(&klv(b"SIMU", 0x3f, 22, 2, &rows));
  let simu_strm = strm(&body);

  let mut devc_body = Vec::new();
  devc_body.extend_from_slice(&klv(b"DVNM", 0x63, 6, 1, b"Camera"));
  devc_body.extend_from_slice(&simu_strm);
  let devc = klv(b"DEVC", 0, 1, devc_body.len() as u16, &devc_body);
  let mut mvhd = vec![0u8; 4];
  mvhd.extend_from_slice(&[0u8; 8]);
  mvhd.extend_from_slice(&1000u32.to_be_bytes());
  mvhd.extend_from_slice(&1000u32.to_be_bytes());
  mvhd.extend_from_slice(&[0u8; 80]);
  let moov = mov_atom(
    b"moov",
    &[
      mov_atom(b"mvhd", &mvhd),
      mov_atom(b"udta", &mov_atom(b"GPMF", &devc)),
    ]
    .concat(),
  );
  let ftyp = mov_atom(b"ftyp", &{
    let mut b = b"qt  ".to_vec();
    b.extend_from_slice(&0u32.to_be_bytes());
    b
  });
  let mut out = ftyp;
  out.extend_from_slice(&moov);
  out
}

/// Build a `.mov` with a `gpmd` metadata TRACK whose single sample has SIZE 0
/// (stsz sz-table entry = 0), plus an `mdat` containing a buried GoPro
/// `GP\x06\0\0` record. ExifTool reads the size-0 `gpmd` sample, enters
/// `ProcessGoPro` (sets `FoundEmbedded`), and so SUPPRESSES the brute-force
/// `mdat` scan — the buried GP6 is NOT extracted. (R12-B.)
fn build_mov_with_empty_gpmd_sample_and_buried_gp6() -> Vec<u8> {
  let ftyp = mov_atom(b"ftyp", &{
    let mut b = b"qt  ".to_vec();
    b.extend_from_slice(&0u32.to_be_bytes());
    b
  });

  // ── the buried GP6 record in mdat (a DEVC{DVNM} — would emit if scanned) ──
  let gp6_devc = {
    let inner = klv(b"DVNM", 0x63, 8, 1, b"BuriedGP");
    klv(b"DEVC", 0, 1, inner.len() as u16, &inner)
  };
  let mut gp6 = b"GP\x06\0".to_vec();
  gp6.extend_from_slice(&(gp6_devc.len() as u32).to_be_bytes());
  gp6.extend_from_slice(&[0u8; 8]);
  gp6.extend_from_slice(&gp6_devc);
  let mut mdat_payload = vec![0u8; 64];
  mdat_payload.extend_from_slice(&gp6);
  mdat_payload.extend_from_slice(&[0u8; 64]);

  let mvhd = mov_full(b"mvhd", &{
    let mut b = vec![0u8; 8];
    b.extend_from_slice(&1000u32.to_be_bytes());
    b.extend_from_slice(&0u32.to_be_bytes());
    b.extend_from_slice(&[0u8; 80]);
    b
  });
  // mdhd (timescale 1000).
  let mdhd = mov_full(b"mdhd", &{
    let mut b = vec![0u8; 8];
    b.extend_from_slice(&1000u32.to_be_bytes());
    b.extend_from_slice(&0u32.to_be_bytes());
    b.extend_from_slice(&[0u8; 4]);
    b
  });
  // hdlr HandlerType='meta' (the walker reads byte 8 of the body).
  let hdlr = mov_full(b"hdlr", &{
    let mut b = vec![0u8; 4];
    b.extend_from_slice(b"meta");
    b.extend_from_slice(&[0u8; 12]);
    b
  });
  // stsd, one entry, MetaFormat='gpmd'.
  let stsd = {
    let entry = {
      let body = {
        let mut bd = vec![0u8; 6];
        bd.extend_from_slice(&1u16.to_be_bytes());
        bd
      };
      let mut e = ((body.len() as u32) + 8).to_be_bytes().to_vec();
      e.extend_from_slice(b"gpmd");
      e.extend_from_slice(&body);
      e
    };
    let mut b = vec![0u8; 4];
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&entry);
    mov_atom(b"stsd", &b)
  };
  // stsz: sz=0 table, num=1, the one entry = 0 (the empty sample).
  let stsz = {
    let mut b = vec![0u8; 4];
    b.extend_from_slice(&0u32.to_be_bytes());
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&0u32.to_be_bytes());
    mov_atom(b"stsz", &b)
  };
  let stsc = {
    let mut b = vec![0u8; 4];
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&1u32.to_be_bytes());
    mov_atom(b"stsc", &b)
  };
  let stco = {
    let mut b = vec![0u8; 4];
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&0u32.to_be_bytes()); // patched below
    mov_atom(b"stco", &b)
  };
  let mut stbl_body = Vec::new();
  stbl_body.extend_from_slice(&stsd);
  stbl_body.extend_from_slice(&stsz);
  stbl_body.extend_from_slice(&stsc);
  stbl_body.extend_from_slice(&stco);
  let stbl = mov_atom(b"stbl", &stbl_body);
  let minf = mov_atom(b"minf", &stbl);
  let mut mdia_body = Vec::new();
  mdia_body.extend_from_slice(&mdhd);
  mdia_body.extend_from_slice(&hdlr);
  mdia_body.extend_from_slice(&minf);
  let trak = mov_atom(b"trak", &mov_atom(b"mdia", &mdia_body));

  let mut moov_body = Vec::new();
  moov_body.extend_from_slice(&mvhd);
  moov_body.extend_from_slice(&trak);
  let moov = mov_atom(b"moov", &moov_body);
  let mdat = mov_atom(b"mdat", &mdat_payload);

  let mut out = Vec::new();
  out.extend_from_slice(&ftyp);
  out.extend_from_slice(&moov);
  let mdat_payload_start = (out.len() + 8) as u32;
  out.extend_from_slice(&mdat);
  patch_stco_offset(&mut out, mdat_payload_start);
  out
}

/// `[size:4][type:4][body]`.
fn mov_atom(typ: &[u8; 4], body: &[u8]) -> Vec<u8> {
  let mut a = ((body.len() as u32) + 8).to_be_bytes().to_vec();
  a.extend_from_slice(typ);
  a.extend_from_slice(body);
  a
}

/// A FullBox: `[size:4][type:4][version+flags:4][body]`.
fn mov_full(typ: &[u8; 4], body: &[u8]) -> Vec<u8> {
  let mut b = vec![0u8; 4];
  b.extend_from_slice(body);
  mov_atom(typ, &b)
}

/// Patch the (single) `stco` chunk offset in an assembled `.mov` to `offset`.
fn patch_stco_offset(out: &mut [u8], offset: u32) {
  if let Some(pos) = out.windows(4).position(|w| w == b"stco") {
    // stco layout after the 'stco' tag: [ver+flags:4][count:4][entry:4].
    let entry = pos + 4 + 4 + 4;
    if let Some(slot) = out.get_mut(entry..entry + 4) {
      slot.copy_from_slice(&offset.to_be_bytes());
    }
  }
}

#[test]
fn quicktime_empty_gpmd_sample_suppresses_mdat_scan() {
  // R12-B — an EMPTY (size-0) `gpmd` GoPro sample must still set `FoundEmbedded`
  // on `ProcessGoPro` ENTRY (GoPro.pm:822), so the brute-force `mdat` scan is
  // SUPPRESSED (QuickTimeStream.pl:3689) and the buried GP6 `DVNM=BuriedGP`
  // record is NOT extracted. Pre-fix, the port skipped the empty sample, left
  // `FoundEmbedded` false, ran the scan, and emitted the buried record's tags.
  let data = build_mov_with_empty_gpmd_sample_and_buried_gp6();
  let meta = parse_quicktime(&data).expect("recognized");
  let gp = meta.gopro();
  assert_eq!(
    gp.device_name(),
    None,
    "the buried GP6 record must NOT be scanned (empty gpmd set FoundEmbedded)"
  );
  assert!(
    gp.is_empty(),
    "no GoPro tags: the empty sample yielded none and the scan was suppressed"
  );
}

#[test]
fn quicktime_buried_gp6_is_scanned_without_a_gpmd_track() {
  // Control for R12-B: the SAME buried GP6 record, but with NO gpmd track to
  // set `FoundEmbedded` — here the brute-force `mdat` scan DOES run and extracts
  // the record (proving the suppression above is caused by the empty sample,
  // not by the GP6 being unreachable).
  let data = build_mov_with_buried_gp6_no_track();
  let meta = parse_quicktime(&data).expect("recognized");
  assert_eq!(
    meta.gopro().device_name(),
    Some("BuriedGP"),
    "without a gpmd track the buried GP6 is scanned and extracted"
  );
}

/// The R12-B control fixture: the buried GP6 record in `mdat` with a plain
/// (non-metadata) `moov` — no `gpmd` track, so the scan is not suppressed.
fn build_mov_with_buried_gp6_no_track() -> Vec<u8> {
  let ftyp = mov_atom(b"ftyp", &{
    let mut b = b"qt  ".to_vec();
    b.extend_from_slice(&0u32.to_be_bytes());
    b
  });
  let mut mvhd = vec![0u8; 4];
  mvhd.extend_from_slice(&[0u8; 8]);
  mvhd.extend_from_slice(&1000u32.to_be_bytes());
  mvhd.extend_from_slice(&0u32.to_be_bytes());
  mvhd.extend_from_slice(&[0u8; 80]);
  let moov = mov_atom(b"moov", &mov_atom(b"mvhd", &mvhd));
  let gp6_devc = {
    let inner = klv(b"DVNM", 0x63, 8, 1, b"BuriedGP");
    klv(b"DEVC", 0, 1, inner.len() as u16, &inner)
  };
  let mut gp6 = b"GP\x06\0".to_vec();
  gp6.extend_from_slice(&(gp6_devc.len() as u32).to_be_bytes());
  gp6.extend_from_slice(&[0u8; 8]);
  gp6.extend_from_slice(&gp6_devc);
  let mut mdat_payload = vec![0u8; 64];
  mdat_payload.extend_from_slice(&gp6);
  mdat_payload.extend_from_slice(&[0u8; 64]);
  let mut out = ftyp;
  out.extend_from_slice(&moov);
  out.extend_from_slice(&mov_atom(b"mdat", &mdat_payload));
  out
}

/// **SP2** — the normalized [`exifast::metadata::MediaMetadata`] projection of
/// the `udta` / Keys camera atoms. The synthetic `QuickTime_sp2.mov` carries a
/// `moov/udta` (Make=`Apple`, Model=`iPhone 15 Pro`, SoftwareVersion=`17.2.1`,
/// ContentCreateDate, `©xyz` GPS) AND a `moov/meta` Keys/ItemList (Make=`Apple
/// Computer`, Model=`iPhone 15 Pro Max`, Software=`17.3`, CreationDate,
/// `location.ISO6709`). The domain prefers Keys over UserData (ExifTool's
/// ItemList-over-UserData rule), so `CameraInfo` reflects the Keys identity, the
/// capture date is the Keys `creationdate`, and `GpsLocation` is the Keys
/// `location.ISO6709` (Paris: 48.8584, 2.2945, 35 m).
#[test]
fn quicktime_sp2_projects_camera_capture_date_and_gps() {
  let data = fixture("QuickTime_sp2.mov");
  let meta = parse_quicktime(&data).expect("recognized");

  // ── typed SP2 layer (both UserData and Keys decoded) ───────────────
  let qt = meta.quicktime();
  assert_eq!(qt.user_data().make(), Some("Apple"));
  assert_eq!(qt.user_data().model(), Some("iPhone 15 Pro"));
  assert_eq!(qt.user_data().software(), Some("17.2.1"));
  assert_eq!(
    qt.user_data().content_create_date(),
    Some("2024:01:02 03:04:05+00:00")
  );
  assert_eq!(qt.keys().make(), Some("Apple Computer"));
  assert_eq!(qt.keys().model(), Some("iPhone 15 Pro Max"));
  assert_eq!(qt.keys().software(), Some("17.3"));
  assert_eq!(qt.keys().creation_date(), Some("2024:06:07 08:09:10+00:00"));
  // The `moov/meta` HandlerType (mdta).
  assert_eq!(qt.meta_handler_type(), Some("mdta"));

  // ── normalized domain projection (Keys preferred over UserData) ────
  let md = meta.media_metadata();
  let cam = md.camera().expect("SP2 populates CameraInfo");
  assert_eq!(cam.make(), Some("Apple Computer"));
  assert_eq!(cam.model(), Some("iPhone 15 Pro Max"));
  assert_eq!(cam.software(), Some("17.3"));
  // Capture date = the Keys `creationdate` (overrides the mvhd CreateDate).
  assert_eq!(md.media().created(), Some("2024:06:07 08:09:10+00:00"));
  // GPS = the Keys `location.ISO6709` (Paris).
  let gps = md.gps().expect("SP2 populates GpsLocation");
  assert!(
    (gps.latitude().expect("lat") - 48.8584).abs() < 1e-9,
    "lat {:?}",
    gps.latitude()
  );
  assert!(
    (gps.longitude().expect("lon") - 2.2945).abs() < 1e-9,
    "lon {:?}",
    gps.longitude()
  );
  assert!(
    (gps.altitude_m().expect("alt") - 35.0).abs() < 1e-9,
    "alt {:?}",
    gps.altitude_m()
  );
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
  let meta = parse_quicktime(&data).expect("recognized");
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
  let meta = parse_quicktime(&data).expect("recognized");
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
  let meta = parse_quicktime(&data).expect("recognized");
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
  let meta = parse_quicktime(&data).expect("recognized");
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
/// against the bundled `exiftool -j -G -ee <fixture>`.
#[test]
#[ignore = "needs real Pixel/Samsung CAMM .mp4 fixture; see #60"]
fn camm_real_fixture_conformance() {
  // Placeholder: load fixture, parse via exifast, golden-compare per-tag.
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
/// "format" code is `camm`. The track's single sample is `sample_bytes`,
/// stored at the start of `mdat`.
fn build_mov_with_camm_track(sample_bytes: &[u8]) -> Vec<u8> {
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

  // stsd — 1 entry whose first 4-byte format code is `camm`.
  // [version+flags:4][count:4][entry-size:4][format:4][reserved:6][data-ref-index:2]
  let mut stsd_entry = Vec::new();
  // Entry: size(=16)+format=camm+6 reserved bytes+data-ref-index(=1).
  stsd_entry.extend_from_slice(&16u32.to_be_bytes());
  stsd_entry.extend_from_slice(b"camm");
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
// `ParseOptions { extract_embedded }` THREADING — the render-time `-ee` flag
// reaches the typed Meta's `serialize_tags` → `EmitOptions`.
//
// The BEHAVIORAL difference (the four timed-metadata blocks gated on the flag)
// lands in a LATER emission-gating task; these tests pin only the threading:
// the flag compiles + flows end-to-end through both public render seams
// (`extract_info_with_options` and `Rendered::new_with_options`), and — because
// the emitters don't yet consult it — `false` vs `true` render IDENTICALLY
// today (which is also the default-off byte-identical regression guard).
// ===========================================================================

/// `extract_info_with_options` threads `ParseOptions { extract_embedded }` into
/// the document render. Until the emission-gating task consults the flag, `-ee`
/// off and on render the SAME JSON document (the flag merely reaches emission).
#[test]
fn extract_info_with_options_threads_extract_embedded() {
  use exifast::ParseOptions;
  use exifast::parser::extract_info_with_options;

  let data = fixture("QuickTime_gps0.mov");

  let off = extract_info_with_options("QuickTime_gps0.mov", &data, true, ParseOptions::default());
  let on = extract_info_with_options(
    "QuickTime_gps0.mov",
    &data,
    true,
    ParseOptions::default().with_extract_embedded(true),
  );

  // Sanity: the default-off render equals the legacy `extract_info` exactly
  // (the regression guard — default `extract_embedded = false` keeps output
  // byte-identical to the hard-coded baseline).
  assert_eq!(
    off,
    exifast::parser::extract_info("QuickTime_gps0.mov", &data, true),
    "default ParseOptions must match the legacy extract_info byte-for-byte"
  );
  // The flag flows through, but the emitters don't gate on it yet ⇒ identical.
  assert_eq!(
    off, on,
    "threading-only: -ee gating lands in the emission task, so off == on today"
  );
}

/// `Rendered::new_with_options` carries `extract_embedded` into the serde
/// `Serialize` path (the same `serialize_tags` seam). Threading-only: off == on
/// until the emission-gating task.
#[test]
fn rendered_new_with_options_threads_extract_embedded() {
  use exifast::Rendered;

  let data = fixture("QuickTime_gps0.mov");
  let meta = parse_bytes(&data).expect("recognized");

  let base = Rendered::new(&meta, true);
  assert!(!base.extract_embedded(), "Rendered::new defaults -ee off");

  let on = Rendered::new_with_options(&meta, true, true);
  assert!(on.extract_embedded(), "new_with_options carries -ee on");

  let off_json = serde_json::to_value(Rendered::new(&meta, true)).expect("serialize off");
  let on_json = serde_json::to_value(on).expect("serialize on");
  assert_eq!(
    off_json, on_json,
    "threading-only: -ee gating lands in the emission task, so off == on today"
  );
}

/// PLACEHOLDER for the emission-gating task: once the four timed-metadata
/// blocks honor `extract_embedded`, `-ee` ON must emit the per-sample
/// `QuickTime:GPS*` tags from the `.ee.json` golden that `-ee` OFF suppresses
/// (replacing them with the `[minor] ExtractEmbedded` warning). Ignored until
/// that task wires the gate.
#[test]
#[ignore = "behavioral gating lands in the emission task"]
fn extract_embedded_on_emits_timed_gps_tags() {
  use exifast::ParseOptions;
  use exifast::parser::extract_info_with_options;

  let data = fixture("QuickTime_gps0.mov");
  let on = extract_info_with_options(
    "QuickTime_gps0.mov",
    &data,
    true,
    ParseOptions::default().with_extract_embedded(true),
  );
  let doc: serde_json::Value = serde_json::from_str(&on).expect("valid JSON");
  let obj = doc
    .as_array()
    .and_then(|a| a.first())
    .and_then(|d| d.as_object())
    .expect("document object");
  assert!(
    obj.contains_key("QuickTime:GPSLatitude"),
    "-ee on must emit the per-sample timed GPS tags"
  );
}
