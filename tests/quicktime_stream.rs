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
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
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
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
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
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
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

#[test]
fn quicktime_frea_kodak_tags_decode_with_oracle_parity() {
  // Part A — the top-level `frea` atom → `Image::ExifTool::Kodak::frea`
  // (QuickTime.pm:610-613 ⇒ Kodak.pm:2977-2990). The fixture's `frea` carries
  // `tima` (Duration 3725s), `'ver '` (KodakVersion "3.01.054"), `thma`
  // (ThumbnailImage 40B) and `scra` (PreviewImage 60B). Bundled `-ee -G1` ⇒
  // the four tags under family-0 `MakerNotes`, family-1 `Kodak`.
  let data = fixture("QuickTime_frea_rexing17b.mov");
  let golden = ee_golden("QuickTime_frea_rexing17b.mov");
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");

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
  let any = parse_bytes(&data).expect("parse ok").expect("recognized");
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
  let meta = parse_quicktime(&data)
    .expect("parse ok")
    .expect("recognized");
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
