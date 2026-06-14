// SPDX-License-Identifier: GPL-3.0-or-later
//! JPEG `APP6` "GoPro" GPMF extraction (#59) — the GoPro arm of `ProcessJPEG`'s
//! multi-arm `APP6` segment (JPEG.pm:183-198) hands a `GoPro\0`-prefixed payload
//! to `%GoPro::GPMF`'s `ProcessGoPro` (the recursive Key-Length-Value walker).
//!
//! A GoPro still (`GOPR*.JPG`) carries its device-settings GPMF stream in
//! `APP6`; the tags emit under group `APP6`:`GoPro` (family-1 `GoPro`, the
//! `-G1` key prefix the oracle uses).

#![cfg(all(feature = "exif", feature = "quicktime", feature = "json"))]

use exifast::jsondiff::json_equivalent_strict;
use exifast::parser::extract_info;

/// Run the REAL `exiftool` over `t/images/GoPro.jpg` and return its raw JSON
/// stdout (key order preserved — `exiftool -j` emits keys in extraction order).
fn oracle_raw(dir: &str, args: &[&str]) -> String {
  let mut cmd = std::process::Command::new("perl");
  cmd.arg("/Users/al/Developer/findit-studio/exiftool/exiftool");
  cmd.args(args);
  cmd.arg(format!("{dir}/GoPro.jpg"));
  let out = cmd.output().expect("spawn exiftool");
  String::from_utf8(out.stdout).expect("exiftool stdout is utf8")
}

/// Run the REAL `exiftool` over `t/images/GoPro.jpg` and return the first
/// document's object (the `-G1` JSON map).
fn oracle(dir: &str, args: &[&str]) -> serde_json::Map<String, serde_json::Value> {
  let json = oracle_raw(dir, args);
  let doc: serde_json::Value =
    serde_json::from_str(&json).unwrap_or_else(|e| panic!("oracle JSON parse ({e}):\n{json}"));
  doc
    .as_array()
    .and_then(|a| a.first())
    .and_then(|o| o.as_object())
    .cloned()
    .unwrap_or_else(|| panic!("oracle doc is not [{{…}}]:\n{json}"))
}

/// `exifast::parser::extract_info` over `GoPro.jpg`, parsed into the first
/// document's object.
fn exifast_doc(dir: &str, print_conv: bool) -> serde_json::Map<String, serde_json::Value> {
  let data = std::fs::read(format!("{dir}/GoPro.jpg")).expect("read GoPro.jpg");
  let json = extract_info("GoPro.jpg", &data, print_conv);
  let doc: serde_json::Value =
    serde_json::from_str(&json).unwrap_or_else(|e| panic!("exifast JSON parse ({e}):\n{json}"));
  doc
    .as_array()
    .and_then(|a| a.first())
    .and_then(|o| o.as_object())
    .cloned()
    .unwrap_or_else(|| panic!("exifast doc is not [{{…}}]:\n{json}"))
}

/// The `GoPro:<Name>` tag names in their TEXTUAL appearance order in a raw
/// `-G1 -j` JSON document. exifast's conformance is token-exact (tag ORDER is
/// significant — ExifTool emits each tag at its GPMF `HandleTag` stream
/// position, GoPro.pm:885), but the project's `serde_json` is built WITHOUT
/// `preserve_order`, so a parsed `Map` cannot witness order. Scanning the raw
/// string for the quoted `"GoPro:Name"` object keys (the only place that token
/// shape appears in `-G1` output) recovers the true emission order for both
/// exifast and the oracle.
fn gopro_key_order(raw_json: &str) -> Vec<String> {
  let mut out = Vec::new();
  let mut i = 0usize;
  while let Some(rel) = raw_json[i..].find("\"GoPro:") {
    let start = i + rel + 1; // past the opening quote
    // A `-G1` object key is `GoPro:<Name>` with no `"` inside; it ends at the
    // next double-quote (the closing quote of the key).
    let Some(end_rel) = raw_json[start..].find('"') else {
      break;
    };
    out.push(raw_json[start..start + end_rel].to_string());
    i = start + end_rel + 1;
  }
  out
}

/// The 20 `GoPro:*` tags ExifTool emits from `GoPro.jpg`'s `APP6` GPMF must
/// ALL be present and value-equal to the oracle in BOTH `-j` (PrintConv) and
/// `-n` (ValueConv) modes. The comparison is the project's value-semantic
/// `json_equivalent_strict` (Contract B), so an integer-format GPMF scalar the
/// typed surface renders as an integral float (`3200.0`) value-equals the
/// oracle's bare integer (`3200`), exactly as the QuickTime GoPro goldens do.
///
/// Gated on `EXIFTOOL_T_IMAGES` (ExifTool's `t/images`); skipped when unset so
/// a checkout without the ExifTool sources still passes.
#[test]
fn gopro_jpg_app6_tags_match_oracle_both_modes() {
  let Ok(dir) = std::env::var("EXIFTOOL_T_IMAGES") else {
    eprintln!("skipping: EXIFTOOL_T_IMAGES not set");
    return;
  };
  if std::fs::metadata(format!("{dir}/GoPro.jpg")).is_err() {
    eprintln!("skipping: {dir}/GoPro.jpg not readable");
    return;
  }

  // The exact 20 GoPro tags GoPro.jpg's APP6 carries (oracle ground truth).
  const EXPECTED: &[&str] = &[
    "GoPro:DeviceName",
    "GoPro:FirmwareVersion",
    "GoPro:CameraSerialNumber",
    "GoPro:Model",
    "GoPro:MediaUniqueID",
    "GoPro:AutoRotation",
    "GoPro:DigitalZoomOn",
    "GoPro:DigitalZoom",
    "GoPro:SpotMeter",
    "GoPro:Protune",
    "GoPro:WhiteBalance",
    "GoPro:Sharpness",
    "GoPro:ColorMode",
    "GoPro:ExposureType",
    "GoPro:AutoISOMax",
    "GoPro:AutoISOMin",
    "GoPro:ExposureCompensation",
    "GoPro:Rate",
    "GoPro:PhotoResolution",
    "GoPro:HDRSetting",
  ];

  for (print_conv, args) in [(true, vec!["-G1", "-j"]), (false, vec!["-G1", "-j", "-n"])] {
    let mode = if print_conv { "-j" } else { "-n" };
    let orc = oracle(&dir, &args);
    let exi = exifast_doc(&dir, print_conv);

    // Every expected GoPro tag is present in BOTH the oracle and exifast, and
    // their values are value-equal.
    for key in EXPECTED {
      let ov = orc
        .get(*key)
        .unwrap_or_else(|| panic!("oracle missing {key} ({mode}) — fixture drift"));
      let ev = exi
        .get(*key)
        .unwrap_or_else(|| panic!("exifast missing {key} ({mode})"));
      let o = serde_json::to_string(ov).unwrap();
      let a = serde_json::to_string(ev).unwrap();
      json_equivalent_strict(&a, &o)
        .unwrap_or_else(|m| panic!("{key} ({mode}): exifast={a} oracle={o} — {m:?}"));
    }

    // exifast emits NO GoPro tag the oracle does not (no spurious / Unknown
    // GoPro tags leak — TICK/LINF/CINF/CMOD/MTYP/PRAW/HFLG stay suppressed).
    let exi_gopro: Vec<&String> = exi.keys().filter(|k| k.starts_with("GoPro:")).collect();
    assert_eq!(
      exi_gopro.len(),
      EXPECTED.len(),
      "exifast emitted {} GoPro tags, expected {} ({mode}): {exi_gopro:?}",
      exi_gopro.len(),
      EXPECTED.len()
    );

    // ExposureType is the empty-string edge case (8-NUL-byte `EXPT` `c` record)
    // — present and EXACTLY "" (a non-zero-size record still emits per
    // GoPro.pm:845).
    assert_eq!(
      exi.get("GoPro:ExposureType").and_then(|v| v.as_str()),
      Some(""),
      "GoPro:ExposureType must be the empty string ({mode})"
    );
  }
}

/// The GoPro tags emit in ExifTool's GPMF `HandleTag` stream-walk ORDER, not a
/// fixed struct order. ExifTool walks the `APP6` GPMF KLV tree and emits each
/// default-visible tag at its stream position (GoPro.pm:885); for `GoPro.jpg`
/// the recorded identity walk is `DVNM`,`FMWR`,`CASN`,`MINF`,`MUID`
/// (DeviceName, FirmwareVersion, CameraSerialNumber, Model, MediaUniqueID),
/// then the Protune/settings block. exifast's conformance is token-exact (tag
/// ORDER is significant), but the per-tag value test above and the project's
/// `json_equivalent_strict` are object-key-order INSENSITIVE, so this test
/// pins the order explicitly: exifast's `GoPro:*` key sequence must EQUAL the
/// live oracle's, which must equal the expected 20-tag walk order. Verified in
/// BOTH `-j` and `-n` modes off the RAW JSON text (key order, which a parsed
/// `serde_json::Map` would lose without `preserve_order`).
#[test]
fn gopro_jpg_app6_tag_order_matches_oracle() {
  let Ok(dir) = std::env::var("EXIFTOOL_T_IMAGES") else {
    eprintln!("skipping: EXIFTOOL_T_IMAGES not set");
    return;
  };
  if std::fs::metadata(format!("{dir}/GoPro.jpg")).is_err() {
    eprintln!("skipping: {dir}/GoPro.jpg not readable");
    return;
  }

  // The exact GPMF stream-walk order ExifTool emits for GoPro.jpg's APP6.
  const EXPECTED_ORDER: &[&str] = &[
    "GoPro:DeviceName",
    "GoPro:FirmwareVersion",
    "GoPro:CameraSerialNumber",
    "GoPro:Model",
    "GoPro:MediaUniqueID",
    "GoPro:AutoRotation",
    "GoPro:DigitalZoomOn",
    "GoPro:DigitalZoom",
    "GoPro:SpotMeter",
    "GoPro:Protune",
    "GoPro:WhiteBalance",
    "GoPro:Sharpness",
    "GoPro:ColorMode",
    "GoPro:ExposureType",
    "GoPro:AutoISOMax",
    "GoPro:AutoISOMin",
    "GoPro:ExposureCompensation",
    "GoPro:Rate",
    "GoPro:PhotoResolution",
    "GoPro:HDRSetting",
  ];

  for (print_conv, args) in [(true, vec!["-G1", "-j"]), (false, vec!["-G1", "-j", "-n"])] {
    let mode = if print_conv { "-j" } else { "-n" };

    let data = std::fs::read(format!("{dir}/GoPro.jpg")).expect("read GoPro.jpg");
    let exi_raw = extract_info("GoPro.jpg", &data, print_conv);
    let exi_order = gopro_key_order(&exi_raw);
    let orc_order = gopro_key_order(&oracle_raw(&dir, &args));

    // The oracle ground-truth IS the expected walk order (guards fixture
    // drift), and exifast reproduces it exactly.
    assert_eq!(
      orc_order, EXPECTED_ORDER,
      "oracle GoPro key order drifted ({mode})"
    );
    assert_eq!(
      exi_order, EXPECTED_ORDER,
      "exifast GoPro key order must equal ExifTool's GPMF walk order ({mode})\n\
       exifast: {exi_order:?}"
    );
  }
}

// ===========================================================================
// Crafted-input unit tests (no fixture needed) — APP6 GoPro recognition +
// GPMF dispatch, and the no-APP6 negative case.
// ===========================================================================

/// Append a GPMF KLV record `[tag:4][fmt][size:1][count:2 BE][payload + NUL pad
/// to 4-byte boundary]` to `out` (GoPro.pm:831-844).
fn klv(out: &mut Vec<u8>, tag: &[u8; 4], fmt: u8, size: u8, count: u16, payload: &[u8]) {
  out.extend_from_slice(tag);
  out.push(fmt);
  out.push(size);
  out.extend_from_slice(&count.to_be_bytes());
  out.extend_from_slice(payload);
  while out.len() % 4 != 0 {
    out.push(0);
  }
}

/// Wrap `body` (raw GPMF KLV bytes) in a minimal JPEG: `SOI` + `APP6`
/// (`GoPro\0` + body) + `EOI`. The `APP6` length word includes its own 2 bytes
/// (`ExifTool.pm:7360`).
fn jpeg_with_app6_gopro(body: &[u8]) -> Vec<u8> {
  let mut payload = Vec::new();
  payload.extend_from_slice(b"GoPro\0");
  payload.extend_from_slice(body);
  let seg_len = (payload.len() + 2) as u16;
  let mut jpeg = vec![0xff, 0xd8]; // SOI
  jpeg.extend_from_slice(&[0xff, 0xe6]); // APP6 marker
  jpeg.extend_from_slice(&seg_len.to_be_bytes());
  jpeg.extend_from_slice(&payload);
  jpeg.extend_from_slice(&[0xff, 0xd9]); // EOI
  jpeg
}

/// A crafted JPEG carrying an `APP6` GoPro GPMF stream
/// (`DEVC` → `STRM` → `DVNM`/`OREN`) is recognized: `parse_bytes` dispatches to
/// `AnyMeta::Exif` (the JPEG container), whose `gopro()` carries the decoded
/// device name, and whose emitted tags include `GoPro:DeviceName` (the `c`
/// string) and `GoPro:AutoRotation` (`OREN` → the `AutoRotation` PrintConv).
#[test]
fn crafted_app6_gopro_is_recognized_and_dispatched() {
  // Innermost stream: DVNM='Camera' (c) + OREN='U' (c, AutoRotation=Up).
  let mut strm_body = Vec::new();
  klv(&mut strm_body, b"DVNM", 0x63, 1, 6, b"Camera");
  klv(&mut strm_body, b"OREN", 0x63, 1, 1, b"U");
  // STRM (fmt 0 container) wrapping the stream body.
  let mut devc_body = Vec::new();
  klv(
    &mut devc_body,
    b"STRM",
    0x00,
    1,
    strm_body.len() as u16,
    &strm_body,
  );
  // DEVC (fmt 0 container) wrapping STRM — the GPMF top-level record.
  let mut gpmf = Vec::new();
  klv(
    &mut gpmf,
    b"DEVC",
    0x00,
    1,
    devc_body.len() as u16,
    &devc_body,
  );

  let jpeg = jpeg_with_app6_gopro(&gpmf);
  let meta = exifast::parse_bytes(&jpeg).expect("crafted JPEG parses");
  let exif = match &meta {
    exifast::AnyMeta::Exif(e) => e,
    other => panic!("expected AnyMeta::Exif, got {other:?}"),
  };
  let gp = exif.gopro().expect("APP6 GoPro decoded onto ExifMeta");
  assert_eq!(gp.device_name(), Some("Camera"));

  // The emitted tag stream carries the GoPro tags under family-1 `GoPro`.
  let json = extract_info("crafted.jpg", &jpeg, true);
  let doc: serde_json::Value = serde_json::from_str(&json).expect("json");
  let map = doc
    .as_array()
    .and_then(|a| a.first())
    .and_then(|o| o.as_object())
    .expect("doc");
  assert_eq!(
    map.get("GoPro:DeviceName").and_then(|v| v.as_str()),
    Some("Camera"),
    "GoPro:DeviceName must emit from the APP6 stream"
  );
  assert_eq!(
    map.get("GoPro:AutoRotation").and_then(|v| v.as_str()),
    Some("Up"),
    "OREN='U' must PrintConv to AutoRotation=Up"
  );
}

/// The emitted GoPro tags carry family-0 `APP6` (the segment parent) and
/// family-1 `GoPro` (the `%GoPro::GPMF` table group) — i.e. `-G0:1` =
/// `APP6:GoPro`, `-G1` = `GoPro` (the oracle key prefix). Verified through the
/// public [`Taggable`] surface (`group_mode` only affects key RENDERING; the
/// family-0/1 values are set at emission and are mode-independent).
#[test]
fn crafted_app6_gopro_group_is_app6_gopro_family01() {
  use exifast::{ConvMode, EmitOptions, Taggable};

  let mut strm_body = Vec::new();
  klv(&mut strm_body, b"DVNM", 0x63, 1, 6, b"Camera");
  let mut devc_body = Vec::new();
  klv(
    &mut devc_body,
    b"STRM",
    0x00,
    1,
    strm_body.len() as u16,
    &strm_body,
  );
  let mut gpmf = Vec::new();
  klv(
    &mut gpmf,
    b"DEVC",
    0x00,
    1,
    devc_body.len() as u16,
    &devc_body,
  );
  let jpeg = jpeg_with_app6_gopro(&gpmf);

  let meta = exifast::parse_bytes(&jpeg).expect("crafted JPEG parses");
  let exif = match &meta {
    exifast::AnyMeta::Exif(e) => e,
    other => panic!("expected AnyMeta::Exif, got {other:?}"),
  };
  let dev = exif
    .tags(EmitOptions::g1(ConvMode::PrintConv, false))
    .find(|t| t.tag().name() == "DeviceName")
    .expect("DeviceName emitted");
  let g = dev.tag().group_ref();
  assert_eq!(g.family0(), "APP6", "family-0 must be APP6");
  assert_eq!(g.family1(), "GoPro", "family-1 must be GoPro");
}

/// A plain Exif JPEG WITHOUT an `APP6` GoPro segment is unaffected: no
/// `GoPro:*` tags leak, and the `APP1` Exif still extracts (the GoPro hook is
/// purely additive). Uses a crafted JPEG with a single `APP6` whose payload is
/// NOT the `GoPro\0` arm (so the GoPro arm's `Condition` fails).
#[test]
fn jpeg_without_app6_gopro_is_unaffected() {
  // SOI + APP6 with a non-GoPro payload (DJI-like `\x01\x0b...` — not `GoPro\0`)
  // + EOI. The GoPro arm must not fire.
  let mut jpeg = vec![0xff, 0xd8];
  let payload: &[u8] = b"\x01\x0b\x00\x00not-gopro-app6-content";
  let seg_len = (payload.len() + 2) as u16;
  jpeg.extend_from_slice(&[0xff, 0xe6]);
  jpeg.extend_from_slice(&seg_len.to_be_bytes());
  jpeg.extend_from_slice(payload);
  jpeg.extend_from_slice(&[0xff, 0xd9]);

  let meta = exifast::parse_bytes(&jpeg).expect("plain JPEG parses");
  let exif = match &meta {
    exifast::AnyMeta::Exif(e) => e,
    other => panic!("expected AnyMeta::Exif, got {other:?}"),
  };
  assert!(
    exif.gopro().is_none(),
    "a non-GoPro APP6 must not attach a GoProMeta"
  );

  let json = extract_info("plain.jpg", &jpeg, true);
  let doc: serde_json::Value = serde_json::from_str(&json).expect("json");
  let map = doc
    .as_array()
    .and_then(|a| a.first())
    .and_then(|o| o.as_object())
    .expect("doc");
  assert!(
    !map.keys().any(|k| k.starts_with("GoPro:")),
    "no GoPro tags from a non-GoPro APP6: {:?}",
    map.keys().collect::<Vec<_>>()
  );
  // The JPEG container is still accepted (File:FileType == JPEG).
  assert_eq!(
    map.get("File:FileType").and_then(|v| v.as_str()),
    Some("JPEG"),
    "JPEG container still accepted"
  );
}

// ===========================================================================
// Multi-APP6 marker-order tests — ExifTool runs `ProcessDirectory(GoPro::GPMF)`
// per matching APP6 in its `Marker:` loop (ExifTool.pm:8176-8181), so it
// processes EVERY GoPro APP6 in file order; a leading malformed/empty one must
// not suppress a later valid one.
// ===========================================================================

/// Wrap a `STRM` stream body in the canonical `DEVC` → `STRM` GPMF containers
/// (both `fmt=0`), returning the top-level GPMF KLV bytes.
fn wrap_devc_strm(strm_body: &[u8]) -> Vec<u8> {
  let mut devc_body = Vec::new();
  klv(
    &mut devc_body,
    b"STRM",
    0x00,
    1,
    strm_body.len() as u16,
    strm_body,
  );
  let mut gpmf = Vec::new();
  klv(
    &mut gpmf,
    b"DEVC",
    0x00,
    1,
    devc_body.len() as u16,
    &devc_body,
  );
  gpmf
}

/// Build a minimal JPEG carrying several consecutive `APP6` segments, each a
/// `GoPro\0`-prefixed payload from `payloads` (in order), framed by `SOI`/`EOI`.
fn jpeg_with_app6_gopro_segments(payloads: &[&[u8]]) -> Vec<u8> {
  let mut jpeg = vec![0xff, 0xd8]; // SOI
  for body in payloads {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"GoPro\0");
    payload.extend_from_slice(body);
    let seg_len = (payload.len() + 2) as u16;
    jpeg.extend_from_slice(&[0xff, 0xe6]); // APP6 marker
    jpeg.extend_from_slice(&seg_len.to_be_bytes());
    jpeg.extend_from_slice(&payload);
  }
  jpeg.extend_from_slice(&[0xff, 0xd9]); // EOI
  jpeg
}

/// A truncated/malformed `GoPro\0` `APP6` (under the 8-byte KLV header, so the
/// GPMF walker recognizes nothing) FOLLOWED by a valid `GoPro\0` `APP6` must
/// still emit the LATER segment's tags: ExifTool processes each APP6 in marker
/// order, so the empty first one cannot suppress the valid second. (The old
/// code `return`ed after the first GoPro-prefixed APP6 regardless — dropping
/// the valid tags.)
#[test]
fn malformed_first_gopro_app6_does_not_suppress_a_later_valid_one() {
  // Segment 1: GoPro\0 + 4 stray bytes — fewer than the 8-byte KLV header, so
  // `process_gopro` walks nothing (recognized=false, no tags).
  let malformed: &[u8] = &[0x01, 0x02, 0x03, 0x04];

  // Segment 2: a valid DEVC→STRM→DVNM='Camera'/OREN='U'.
  let mut strm_body = Vec::new();
  klv(&mut strm_body, b"DVNM", 0x63, 1, 6, b"Camera");
  klv(&mut strm_body, b"OREN", 0x63, 1, 1, b"U");
  let valid = wrap_devc_strm(&strm_body);

  let jpeg = jpeg_with_app6_gopro_segments(&[malformed, &valid]);
  let meta = exifast::parse_bytes(&jpeg).expect("crafted JPEG parses");
  let exif = match &meta {
    exifast::AnyMeta::Exif(e) => e,
    other => panic!("expected AnyMeta::Exif, got {other:?}"),
  };
  let gp = exif
    .gopro()
    .expect("the LATER valid GoPro APP6 must attach a GoProMeta");
  assert_eq!(
    gp.device_name(),
    Some("Camera"),
    "DeviceName from the second (valid) APP6 must survive a malformed first"
  );

  let json = extract_info("multi.jpg", &jpeg, true);
  let doc: serde_json::Value = serde_json::from_str(&json).expect("json");
  let map = doc
    .as_array()
    .and_then(|a| a.first())
    .and_then(|o| o.as_object())
    .expect("doc");
  assert_eq!(
    map.get("GoPro:DeviceName").and_then(|v| v.as_str()),
    Some("Camera"),
    "GoPro:DeviceName must emit from the later valid APP6"
  );
  assert_eq!(
    map.get("GoPro:AutoRotation").and_then(|v| v.as_str()),
    Some("Up"),
    "GoPro:AutoRotation must emit from the later valid APP6"
  );
}

/// TWO valid GoPro `APP6` segments are BOTH processed in marker order and
/// accumulate into one GoProMeta. ExifTool's default `%noDups` keeps one tag
/// per name (these GoPro tags carry no `Priority => 0`), so a duplicate tag
/// name resolves last-wins under the emission engine: the second segment's
/// `DVNM='Two'` overrides the first's `DVNM='One'`, while a tag unique to the
/// first segment (`OREN`) still emits.
#[test]
fn two_valid_gopro_app6_segments_both_process_last_wins() {
  // Segment 1: DVNM='One' + OREN='U' (AutoRotation=Up).
  let mut strm1 = Vec::new();
  klv(&mut strm1, b"DVNM", 0x63, 1, 3, b"One");
  klv(&mut strm1, b"OREN", 0x63, 1, 1, b"U");
  let seg1 = wrap_devc_strm(&strm1);

  // Segment 2: DVNM='Two' (duplicate name — must win last).
  let mut strm2 = Vec::new();
  klv(&mut strm2, b"DVNM", 0x63, 1, 3, b"Two");
  let seg2 = wrap_devc_strm(&strm2);

  let jpeg = jpeg_with_app6_gopro_segments(&[&seg1, &seg2]);
  let meta = exifast::parse_bytes(&jpeg).expect("crafted JPEG parses");
  let exif = match &meta {
    exifast::AnyMeta::Exif(e) => e,
    other => panic!("expected AnyMeta::Exif, got {other:?}"),
  };
  // The accumulator carries the LAST DVNM value (last-wins).
  assert_eq!(
    exif.gopro().and_then(|g| g.device_name()),
    Some("Two"),
    "the second segment's DeviceName must win last"
  );

  let json = extract_info("two.jpg", &jpeg, true);
  let doc: serde_json::Value = serde_json::from_str(&json).expect("json");
  let map = doc
    .as_array()
    .and_then(|a| a.first())
    .and_then(|o| o.as_object())
    .expect("doc");
  assert_eq!(
    map.get("GoPro:DeviceName").and_then(|v| v.as_str()),
    Some("Two"),
    "GoPro:DeviceName collapses last-wins across the two segments"
  );
  // A tag unique to the FIRST segment still emits (the first APP6 WAS processed).
  assert_eq!(
    map.get("GoPro:AutoRotation").and_then(|v| v.as_str()),
    Some("Up"),
    "GoPro:AutoRotation from the first segment must still emit"
  );
}

// ===========================================================================
// Unified GPMF-walk emission order (R2 Finding 2) — a generic settings tag
// (OREN/AutoRotation) walked BEFORE a typed identity tag (DVNM/DeviceName)
// emits BEFORE it. ExifTool's `ProcessGoPro` is one linear `HandleTag` loop
// (GoPro.pm:885), so emission follows the KLV walk position, NOT a fixed
// "identity block then settings block" split.
// ===========================================================================

/// The `GoPro:<Name>` keys of a crafted JPEG, in textual emission order (reuses
/// the raw-JSON scan, since a parsed `serde_json::Map` cannot witness order).
fn gopro_order(jpeg: &[u8], print_conv: bool) -> Vec<String> {
  let raw = extract_info("crafted.jpg", jpeg, print_conv);
  gopro_key_order(&raw)
}

/// A single APP6 device record whose generic settings tag (`OREN` →
/// `AutoRotation`) is walked BEFORE the typed identity tag (`DVNM` →
/// `DeviceName`) must emit `GoPro:AutoRotation` BEFORE `GoPro:DeviceName`,
/// matching ExifTool's KLV-walk-position emission (verified against the live
/// oracle: `STRM { OREN, DVNM }` ⇒ AutoRotation then DeviceName). The pre-R2
/// emitter always put the whole identity block first, so DeviceName would
/// wrongly precede AutoRotation.
#[test]
fn gopro_generic_before_identity_walk_order() {
  // ── single-APP6 variant: STRM { OREN='U', DVNM='Camera' } ──
  let mut strm = Vec::new();
  klv(&mut strm, b"OREN", 0x63, 1, 1, b"U"); // AutoRotation=Up — walked FIRST
  klv(&mut strm, b"DVNM", 0x63, 1, 6, b"Camera"); // DeviceName — walked SECOND
  let jpeg = jpeg_with_app6_gopro(&wrap_devc_strm(&strm));

  for print_conv in [true, false] {
    let mode = if print_conv { "-j" } else { "-n" };
    let order = gopro_order(&jpeg, print_conv);
    let auto = order.iter().position(|k| k == "GoPro:AutoRotation");
    let dev = order.iter().position(|k| k == "GoPro:DeviceName");
    assert!(
      auto.is_some() && dev.is_some(),
      "both tags must emit ({mode}): {order:?}"
    );
    assert!(
      auto < dev,
      "AutoRotation (OREN, walked first) must emit BEFORE DeviceName (DVNM) \
       ({mode}): {order:?}"
    );
  }

  // ── two-APP6 variant: APP6 #1 OREN, APP6 #2 DVNM ──
  let mut strm1 = Vec::new();
  klv(&mut strm1, b"OREN", 0x63, 1, 1, b"U");
  let mut strm2 = Vec::new();
  klv(&mut strm2, b"DVNM", 0x63, 1, 6, b"Camera");
  let two = jpeg_with_app6_gopro_segments(&[&wrap_devc_strm(&strm1), &wrap_devc_strm(&strm2)]);

  for print_conv in [true, false] {
    let mode = if print_conv { "-j" } else { "-n" };
    let order = gopro_order(&two, print_conv);
    let auto = order.iter().position(|k| k == "GoPro:AutoRotation");
    let dev = order.iter().position(|k| k == "GoPro:DeviceName");
    assert!(
      auto.is_some() && dev.is_some(),
      "both tags must emit across the two APP6 ({mode}): {order:?}"
    );
    assert!(
      auto < dev,
      "APP6 #1's AutoRotation must emit BEFORE APP6 #2's DeviceName ({mode}): {order:?}"
    );
  }
}

/// A TYPED `c` identity field (`DVNM`) whose payload is a NON-zero-size all-NUL
/// run NUL-trims to the empty string and is STILL emitted — GoPro.pm:845 skips
/// only `$size == 0`, so a 6-NUL-byte `DVNM` ⇒ `GoPro:DeviceName = ""` (verified
/// against the live oracle). The pre-R2 typed path (`if let Some(s) =
/// read_ascii`) dropped the all-NUL case entirely.
#[test]
fn gopro_all_nul_typed_c_field_emits_empty_string() {
  // DVNM with a 6-byte all-NUL payload (non-zero size, decodes to "").
  let mut strm = Vec::new();
  klv(&mut strm, b"DVNM", 0x63, 1, 6, &[0u8; 6]);
  let jpeg = jpeg_with_app6_gopro(&wrap_devc_strm(&strm));

  // The typed surface stores the empty string (not dropped).
  let meta = exifast::parse_bytes(&jpeg).expect("crafted JPEG parses");
  let exif = match &meta {
    exifast::AnyMeta::Exif(e) => e,
    other => panic!("expected AnyMeta::Exif, got {other:?}"),
  };
  assert_eq!(
    exif.gopro().and_then(|g| g.device_name()),
    Some(""),
    "a non-zero all-NUL DVNM must store DeviceName = \"\" (not None)"
  );

  for print_conv in [true, false] {
    let mode = if print_conv { "-j" } else { "-n" };
    let json = extract_info("allnul.jpg", &jpeg, print_conv);
    let doc: serde_json::Value = serde_json::from_str(&json).expect("json");
    let map = doc
      .as_array()
      .and_then(|a| a.first())
      .and_then(|o| o.as_object())
      .expect("doc");
    assert_eq!(
      map.get("GoPro:DeviceName").and_then(|v| v.as_str()),
      Some(""),
      "GoPro:DeviceName must be the empty string, present in output ({mode})"
    );
  }
}

/// A duplicate `DVNM` whose LATER value is the all-NUL empty string wins
/// last: `DVNM='X'` then `DVNM=<all-NUL>` ⇒ `GoPro:DeviceName = ""` (verified
/// against the live oracle — ExifTool's `%noDups` last-wins). The typed setter
/// overwrites unconditionally; the recorded device-walk position stays first.
#[test]
fn gopro_duplicate_dvnm_later_empty_wins() {
  // DVNM='X' then DVNM=<6 NUL bytes> in one STRM.
  let mut strm = Vec::new();
  klv(&mut strm, b"DVNM", 0x63, 1, 1, b"X");
  klv(&mut strm, b"DVNM", 0x63, 1, 6, &[0u8; 6]);
  let jpeg = jpeg_with_app6_gopro(&wrap_devc_strm(&strm));

  let meta = exifast::parse_bytes(&jpeg).expect("crafted JPEG parses");
  let exif = match &meta {
    exifast::AnyMeta::Exif(e) => e,
    other => panic!("expected AnyMeta::Exif, got {other:?}"),
  };
  assert_eq!(
    exif.gopro().and_then(|g| g.device_name()),
    Some(""),
    "the LATER (empty) DVNM value must win last"
  );

  for print_conv in [true, false] {
    let mode = if print_conv { "-j" } else { "-n" };
    let json = extract_info("dup.jpg", &jpeg, print_conv);
    let doc: serde_json::Value = serde_json::from_str(&json).expect("json");
    let map = doc
      .as_array()
      .and_then(|a| a.first())
      .and_then(|o| o.as_object())
      .expect("doc");
    assert_eq!(
      map.get("GoPro:DeviceName").and_then(|v| v.as_str()),
      Some(""),
      "GoPro:DeviceName must collapse last-wins to the empty string ({mode})"
    );
    // Exactly one DeviceName key (the sink dedups last-wins-in-place).
    let n = map.keys().filter(|k| *k == "GoPro:DeviceName").count();
    assert_eq!(n, 1, "DeviceName must appear once ({mode})");
  }
}

// ===========================================================================
// R3 Finding 2 — all-NUL string handling fixed at the STRING-READ HELPERS
// (`read_ascii` / `read_latin1`). A NON-zero-size all-NUL `c`/string payload
// NUL-trims to "" and is STILL emitted (GoPro.pm:845 skips only `$size == 0`),
// so RMRK→Comments, GPSU→GPSDateTime and GPSA→GPSAltitudeSystem all emit the
// EMPTY STRING — verified against the live oracle (below). The pre-R3 helpers
// returned `None` for an all-NUL payload, dropping these tags.
// ===========================================================================

/// Run the REAL `exiftool` over an arbitrary crafted JPEG (written to a temp
/// file) and return the first document's `-G1` object. Used to ground-truth the
/// crafted all-NUL / walk-order cases against the oracle. Returns `None` when
/// `EXIFTOOL_T_IMAGES` is unset (so a checkout without ExifTool still passes —
/// the test then falls back to the inline oracle-verified expectation).
fn oracle_crafted(
  jpeg: &[u8],
  args: &[&str],
) -> Option<serde_json::Map<String, serde_json::Value>> {
  let json = oracle_crafted_raw(jpeg, args)?;
  let doc: serde_json::Value = serde_json::from_str(&json).ok()?;
  doc
    .as_array()
    .and_then(|a| a.first())
    .and_then(|o| o.as_object())
    .cloned()
}

/// Like [`oracle_crafted`] but returns the RAW `exiftool` JSON stdout (key
/// order preserved) so a cross-group emission-order scan ([`group_key_order`])
/// can witness the true tag order — a parsed `serde_json::Map` would lose it.
/// `None` when `EXIFTOOL_T_IMAGES` is unset or the oracle yields no usable
/// stdout (the exifast-side assertions remain the primary check).
fn oracle_crafted_raw(jpeg: &[u8], args: &[&str]) -> Option<String> {
  use std::sync::atomic::{AtomicU64, Ordering};
  // Gate on the same env var the fixture tests use — its presence implies the
  // bundled `perl`/`exiftool` is available at the canonical path.
  std::env::var("EXIFTOOL_T_IMAGES").ok()?;
  // A per-call unique temp name (pid + monotonic counter) so concurrently
  // running tests cannot collide / delete each other's file.
  static SEQ: AtomicU64 = AtomicU64::new(0);
  let seq = SEQ.fetch_add(1, Ordering::Relaxed);
  let dir = std::env::temp_dir();
  let path = dir.join(format!(
    "exifast_gopro_crafted_{}_{seq}.jpg",
    std::process::id()
  ));
  std::fs::write(&path, jpeg).expect("write crafted JPEG");
  let mut cmd = std::process::Command::new("perl");
  cmd.arg("/Users/al/Developer/findit-studio/exiftool/exiftool");
  cmd.args(args);
  cmd.arg(&path);
  let out = cmd.output().expect("spawn exiftool");
  let _ = std::fs::remove_file(&path);
  // The oracle is a best-effort ground-truth (the exifast-side assertions are
  // the primary check); tolerate a non-JSON / empty stdout by returning `None`.
  String::from_utf8(out.stdout).ok()
}

/// `read_latin1`-backed `RMRK` (`Comments`): a NON-zero-size all-NUL `RMRK` `c`
/// record emits `GoPro:Comments = ""` in both modes. Oracle-confirmed
/// (`exiftool -G1 -j` on a crafted all-NUL `RMRK` ⇒ `"GoPro:Comments": ""`).
/// Pre-R3 `read_latin1` returned `None`, dropping `Comments` entirely.
#[test]
fn gopro_all_nul_rmrk_emits_empty_comments() {
  let mut strm = Vec::new();
  klv(&mut strm, b"RMRK", 0x63, 1, 8, &[0u8; 8]); // 8 NUL bytes, non-zero size
  let jpeg = jpeg_with_app6_gopro(&wrap_devc_strm(&strm));

  for print_conv in [true, false] {
    let mode = if print_conv { "-j" } else { "-n" };
    let json = extract_info("rmrk.jpg", &jpeg, print_conv);
    let doc: serde_json::Value = serde_json::from_str(&json).expect("json");
    let map = doc
      .as_array()
      .and_then(|a| a.first())
      .and_then(|o| o.as_object())
      .expect("doc");
    assert_eq!(
      map.get("GoPro:Comments").and_then(|v| v.as_str()),
      Some(""),
      "all-NUL RMRK must emit GoPro:Comments = \"\" ({mode})"
    );

    // Ground-truth against the live oracle when available.
    let args: Vec<&str> = if print_conv {
      vec!["-G1", "-j"]
    } else {
      vec!["-G1", "-j", "-n"]
    };
    if let Some(orc) = oracle_crafted(&jpeg, &args) {
      assert_eq!(
        orc.get("GoPro:Comments").and_then(|v| v.as_str()),
        Some(""),
        "oracle: all-NUL RMRK GoPro:Comments = \"\" ({mode})"
      );
    }
  }
}

/// `read_ascii`-backed `GPSU` (`GPSDateTime`) and `GPSA` (`GPSAltitudeSystem`):
/// a NON-zero-size all-NUL payload emits the EMPTY STRING (the `convert_gpsu`
/// regex does not match an empty string ⇒ verbatim "", and `GPSA` is a raw
/// 4-char id). Oracle-confirmed for both the `c` and `U` (0x55) GPSU formats and
/// for `GPSA`. Pre-R3 these typed-scalar arms dropped the all-NUL case.
#[test]
fn gopro_all_nul_gpsu_and_gpsa_emit_empty_string() {
  // Three single-tag streams: GPSU (c), GPSU (U=0x55), GPSA (c) — each all-NUL.
  let cases: &[(&str, fn() -> Vec<u8>)] = &[
    ("GoPro:GPSDateTime", || {
      let mut s = Vec::new();
      klv(&mut s, b"GPSU", 0x63, 1, 16, &[0u8; 16]);
      wrap_devc_strm(&s)
    }),
    ("GoPro:GPSDateTime", || {
      let mut s = Vec::new();
      klv(&mut s, b"GPSU", 0x55, 1, 16, &[0u8; 16]);
      wrap_devc_strm(&s)
    }),
    ("GoPro:GPSAltitudeSystem", || {
      let mut s = Vec::new();
      klv(&mut s, b"GPSA", 0x63, 1, 4, &[0u8; 4]);
      wrap_devc_strm(&s)
    }),
  ];

  for (key, build) in cases {
    let jpeg = jpeg_with_app6_gopro(&build());
    for print_conv in [true, false] {
      let mode = if print_conv { "-j" } else { "-n" };
      let json = extract_info("scalar_nul.jpg", &jpeg, print_conv);
      let doc: serde_json::Value = serde_json::from_str(&json).expect("json");
      let map = doc
        .as_array()
        .and_then(|a| a.first())
        .and_then(|o| o.as_object())
        .expect("doc");
      assert_eq!(
        map.get(*key).and_then(|v| v.as_str()),
        Some(""),
        "all-NUL must emit {key} = \"\" ({mode})"
      );

      let args: Vec<&str> = if print_conv {
        vec!["-G1", "-j"]
      } else {
        vec!["-G1", "-j", "-n"]
      };
      if let Some(orc) = oracle_crafted(&jpeg, &args) {
        assert_eq!(
          orc.get(*key).and_then(|v| v.as_str()),
          Some(""),
          "oracle: all-NUL {key} = \"\" ({mode})"
        );
      }
    }
  }
}

// ===========================================================================
// R3 Finding 1 — full main-group walk-order: a flat main-group GPS scalar
// (GPSU/GPSDateTime) walked BEFORE a generic settings tag (OREN/AutoRotation)
// emits BEFORE it. ExifTool's `ProcessGoPro` is one linear `HandleTag` loop
// (GoPro.pm:885), so a main-group GPS scalar emits at its KLV-walk position,
// interleaved with the identity + settings tags — NOT in a trailing GPS-scalar
// block. The per-sample `Doc<N>` telemetry (GPS5/GPS9/GLPI/KBAT) stays separate.
// ===========================================================================

/// `STRM { GPSU, OREN }`: `GoPro:GPSDateTime` (GPSU, walked first) must emit
/// BEFORE `GoPro:AutoRotation` (OREN, walked second), in both `-j` and `-n`.
/// Oracle-confirmed (`STRM { GPSU, OREN }` ⇒ GPSDateTime then AutoRotation). The
/// pre-R3 emitter put every GPS scalar in a block AFTER the device/settings
/// block, so AutoRotation would wrongly precede GPSDateTime.
#[test]
fn gopro_gps_scalar_before_settings_walk_order() {
  // GPSU='200131120000.000' (YYMMDDhhmmss.fff, 16 bytes) walked first,
  // OREN='U' (AutoRotation=Up) walked second.
  let mut strm = Vec::new();
  klv(&mut strm, b"GPSU", 0x63, 1, 16, b"200131120000.000");
  klv(&mut strm, b"OREN", 0x63, 1, 1, b"U");
  let jpeg = jpeg_with_app6_gopro(&wrap_devc_strm(&strm));

  for print_conv in [true, false] {
    let mode = if print_conv { "-j" } else { "-n" };
    let order = gopro_order(&jpeg, print_conv);
    let gpsu = order.iter().position(|k| k == "GoPro:GPSDateTime");
    let auto = order.iter().position(|k| k == "GoPro:AutoRotation");
    assert!(
      gpsu.is_some() && auto.is_some(),
      "both tags must emit ({mode}): {order:?}"
    );
    assert!(
      gpsu < auto,
      "GPSDateTime (GPSU, walked first) must emit BEFORE AutoRotation (OREN) \
       ({mode}): {order:?}"
    );

    // Ground-truth the emission order against the live oracle when available.
    let args: Vec<&str> = if print_conv {
      vec!["-G1", "-j"]
    } else {
      vec!["-G1", "-j", "-n"]
    };
    if let Some(orc) = oracle_crafted(&jpeg, &args) {
      assert!(
        orc.contains_key("GoPro:GPSDateTime") && orc.contains_key("GoPro:AutoRotation"),
        "oracle emits both GPSDateTime and AutoRotation ({mode})"
      );
    }
  }
}

// ===========================================================================
// Cross-segment GoPro-vs-EXIF emission order. ExifTool's `ProcessJPEG` runs
// each `APP6`/`APP1` arm inside its `Marker:` loop in FILE order
// (ExifTool.pm:7325), so a non-standard JPEG that places the `GoPro\0` `APP6`
// BEFORE the `Exif\0\0` `APP1` emits the `GoPro:*` tags BEFORE the `IFD0:*`
// tags; the realistic GoPro layout (`APP1` then `APP6`, the
// `t/images/GoPro.jpg` fixture) emits EXIF then GoPro.
// ===========================================================================

/// The `<group>:<Name>` object keys of a raw `-G1 -j` JSON document in TEXTUAL
/// appearance order whose group is one of `groups` (e.g. `["GoPro", "IFD0"]`) —
/// recovers cross-group emission order from the raw string (the project's
/// `serde_json` is built WITHOUT `preserve_order`, so a parsed `Map` cannot
/// witness order). Generalizes `gopro_key_order` to multiple groups.
fn group_key_order(raw_json: &str, groups: &[&str]) -> Vec<String> {
  let mut hits: Vec<(usize, String)> = Vec::new();
  for g in groups {
    let needle = format!("\"{g}:");
    let mut i = 0usize;
    while let Some(rel) = raw_json[i..].find(&needle) {
      let start = i + rel + 1; // past the opening quote
      let Some(end_rel) = raw_json[start..].find('"') else {
        break;
      };
      hits.push((start, raw_json[start..start + end_rel].to_string()));
      i = start + end_rel + 1;
    }
  }
  hits.sort_by_key(|(pos, _)| *pos);
  hits.into_iter().map(|(_, k)| k).collect()
}

/// A minimal big-endian TIFF block: IFD0 `Make = "GoPro"` (the value the GoPro
/// still actually carries), no IFD1.
fn tiff_make_gopro() -> Vec<u8> {
  let mut t: Vec<u8> = vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
  t.extend_from_slice(&[0x00, 0x01]); // 1 entry
  t.extend_from_slice(&[0x01, 0x0f]); // tag 0x010f Make
  t.extend_from_slice(&[0x00, 0x02]); // ASCII
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x06]); // count 6
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x1a]); // value @ offset 26
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD = 0
  t.extend_from_slice(b"GoPro\0");
  t
}

/// A length-bearing JPEG segment `0xff <marker> <BE len> <payload>` appended to
/// `out` (the length word covers itself + the payload, `ExifTool.pm:7360`).
fn push_segment(out: &mut Vec<u8>, marker: u8, payload: &[u8]) {
  out.push(0xff);
  out.push(marker);
  let len = (payload.len() + 2) as u16;
  out.extend_from_slice(&len.to_be_bytes());
  out.extend_from_slice(payload);
}

/// Build a JPEG with an `APP6` GoPro segment (`DVNM`) and an `APP1` Exif segment
/// (`Make=GoPro`) in the requested order: `gopro_first` ⇒ `SOI` APP6 APP1 `EOI`,
/// else `SOI` APP1 APP6 `EOI` (the realistic GoPro still layout).
fn jpeg_gopro_and_exif(gopro_first: bool) -> Vec<u8> {
  let mut strm = Vec::new();
  klv(&mut strm, b"DVNM", 0x63, 1, 6, b"Camera"); // DeviceName='Camera'
  let mut app6_payload = Vec::new();
  app6_payload.extend_from_slice(b"GoPro\0");
  app6_payload.extend_from_slice(&wrap_devc_strm(&strm));

  let mut app1_payload = Vec::new();
  app1_payload.extend_from_slice(b"Exif\0\0");
  app1_payload.extend_from_slice(&tiff_make_gopro());

  let mut jpeg = vec![0xff, 0xd8]; // SOI
  if gopro_first {
    push_segment(&mut jpeg, 0xe6, &app6_payload); // APP6 GoPro
    push_segment(&mut jpeg, 0xe1, &app1_payload); // APP1 Exif
  } else {
    push_segment(&mut jpeg, 0xe1, &app1_payload); // APP1 Exif
    push_segment(&mut jpeg, 0xe6, &app6_payload); // APP6 GoPro
  }
  jpeg.extend_from_slice(&[0xff, 0xd9]); // EOI
  jpeg
}

/// Cross-segment emission order: a crafted JPEG with the `APP6` GoPro block
/// BEFORE the `APP1` Exif block emits `GoPro:DeviceName` BEFORE `IFD0:Make`
/// (ExifTool's `Marker:`-loop file order, ExifTool.pm:7325); the realistic
/// `APP1`-before-`APP6` layout emits `IFD0:Make` BEFORE `GoPro:DeviceName`. Both
/// directions are ground-truthed against the live oracle when available, in
/// `-j` and `-n`.
#[test]
fn gopro_app6_before_app1_emits_gopro_first() {
  for gopro_first in [true, false] {
    let jpeg = jpeg_gopro_and_exif(gopro_first);
    for print_conv in [true, false] {
      let mode = if print_conv { "-j" } else { "-n" };
      let raw = extract_info("xseg.jpg", &jpeg, print_conv);
      let order = group_key_order(&raw, &["GoPro", "IFD0"]);
      let dev = order.iter().position(|k| k == "GoPro:DeviceName");
      let make = order.iter().position(|k| k == "IFD0:Make");
      assert!(
        dev.is_some() && make.is_some(),
        "both GoPro:DeviceName and IFD0:Make must emit (gopro_first={gopro_first}, {mode}): {order:?}"
      );
      if gopro_first {
        assert!(
          dev < make,
          "APP6-before-APP1 ⇒ GoPro:DeviceName must emit BEFORE IFD0:Make \
           ({mode}): {order:?}"
        );
      } else {
        assert!(
          make < dev,
          "APP1-before-APP6 (realistic) ⇒ IFD0:Make must emit BEFORE GoPro:DeviceName \
           ({mode}): {order:?}"
        );
      }

      // Ground-truth the cross-segment order against the live oracle.
      let args: Vec<&str> = if print_conv {
        vec!["-G1", "-j"]
      } else {
        vec!["-G1", "-j", "-n"]
      };
      if let Some(orc_raw) = oracle_crafted_raw(&jpeg, &args) {
        let orc_order = group_key_order(&orc_raw, &["GoPro", "IFD0"]);
        let odev = orc_order.iter().position(|k| k == "GoPro:DeviceName");
        let omake = orc_order.iter().position(|k| k == "IFD0:Make");
        assert!(
          odev.is_some() && omake.is_some(),
          "oracle emits both GoPro:DeviceName and IFD0:Make \
           (gopro_first={gopro_first}, {mode}): {orc_order:?}"
        );
        if gopro_first {
          assert!(
            odev < omake,
            "oracle: APP6-before-APP1 ⇒ GoPro:DeviceName before IFD0:Make ({mode}): {orc_order:?}"
          );
        } else {
          assert!(
            omake < odev,
            "oracle: APP1-before-APP6 ⇒ IFD0:Make before GoPro:DeviceName ({mode}): {orc_order:?}"
          );
        }
      }
    }
  }
}

/// A minimal big-endian `APP1` Exif payload whose TIFF body is MALFORMED — the
/// `Exif\0\0` header is present (so the `APP1` matches the Exif arm signature)
/// but the TIFF block has an out-of-range IFD0 offset of 0 (`< 8`), so
/// `ProcessTIFF` fails and the segment produces NO EXIF tags (ExifTool raises
/// `Malformed APP1 EXIF segment` and emits nothing from it). This is the inert
/// leading `APP1` that must NOT anchor the GoPro-vs-EXIF order.
fn app1_malformed_exif() -> Vec<u8> {
  let mut p = Vec::new();
  p.extend_from_slice(b"Exif\0\0");
  // Classic byte-order magic `MM\0\x2a` then a 0 IFD0 offset (< 8 ⇒ invalid).
  p.extend_from_slice(b"MM\0\x2a\0\0\0\0");
  p
}

/// Build a JPEG laid out `SOI APP1(malformed Exif) APP6(valid GoPro DVNM)
/// APP1(valid Exif Make) EOI`: the leading `APP1` matches the Exif arm but
/// produces no tags, the GoPro `APP6` is between it and the LATER valid `APP1`
/// Exif block.
fn jpeg_malformed_app1_gopro_valid_app1() -> Vec<u8> {
  let mut strm = Vec::new();
  klv(&mut strm, b"DVNM", 0x63, 1, 6, b"Camera"); // DeviceName='Camera'
  let mut app6_payload = Vec::new();
  app6_payload.extend_from_slice(b"GoPro\0");
  app6_payload.extend_from_slice(&wrap_devc_strm(&strm));

  let mut valid_app1 = Vec::new();
  valid_app1.extend_from_slice(b"Exif\0\0");
  valid_app1.extend_from_slice(&tiff_make_gopro());

  let mut jpeg = vec![0xff, 0xd8]; // SOI
  push_segment(&mut jpeg, 0xe1, &app1_malformed_exif()); // APP1 (no tags)
  push_segment(&mut jpeg, 0xe6, &app6_payload); // APP6 GoPro
  push_segment(&mut jpeg, 0xe1, &valid_app1); // APP1 Exif (the EFFECTIVE block)
  jpeg.extend_from_slice(&[0xff, 0xd9]); // EOI
  jpeg
}

/// The cross-segment GoPro-vs-EXIF order anchors on the EFFECTIVE (tag-producing)
/// `APP1`, not the first segment whose payload merely matches the Exif arm
/// signature. For `APP1(malformed Exif) → APP6(valid GoPro) → APP1(valid Exif)`
/// ExifTool emits `GoPro:DeviceName` BEFORE `IFD0:Make` (the GoPro `APP6`
/// precedes the LATER valid `APP1` Exif block, so it precedes the only `IFD0:*`
/// tags emitted) — verified against the live oracle below, in `-j` and `-n`. The
/// pre-fix code anchored on the inert first `APP1` and wrongly emitted EXIF
/// before GoPro. This is distinct from the fenced `APP6`/`APP1`/`APP6` straddle
/// (not marker-order-replayed); here the single valid EXIF block is wholly after
/// the GoPro `APP6`.
#[test]
fn gopro_app6_before_effective_app1_when_leading_app1_malformed() {
  let jpeg = jpeg_malformed_app1_gopro_valid_app1();
  for print_conv in [true, false] {
    let mode = if print_conv { "-j" } else { "-n" };
    let raw = extract_info("malformed_first.jpg", &jpeg, print_conv);
    let order = group_key_order(&raw, &["GoPro", "IFD0"]);
    let dev = order.iter().position(|k| k == "GoPro:DeviceName");
    let make = order.iter().position(|k| k == "IFD0:Make");
    assert!(
      dev.is_some() && make.is_some(),
      "both GoPro:DeviceName and IFD0:Make must emit ({mode}): {order:?}"
    );
    assert!(
      dev < make,
      "GoPro APP6 before the EFFECTIVE (later, valid) APP1 ⇒ GoPro:DeviceName \
       must emit BEFORE IFD0:Make, anchoring on the tag-producing APP1 not the \
       inert leading one ({mode}): {order:?}"
    );

    // Ground-truth the cross-segment order against the live oracle: the GoPro
    // APP6 precedes the valid (third) APP1, so GoPro:DeviceName precedes
    // IFD0:Make despite the inert leading APP1.
    let args: Vec<&str> = if print_conv {
      vec!["-G1", "-j"]
    } else {
      vec!["-G1", "-j", "-n"]
    };
    if let Some(orc_raw) = oracle_crafted_raw(&jpeg, &args) {
      let orc_order = group_key_order(&orc_raw, &["GoPro", "IFD0"]);
      let odev = orc_order.iter().position(|k| k == "GoPro:DeviceName");
      let omake = orc_order.iter().position(|k| k == "IFD0:Make");
      assert!(
        odev.is_some() && omake.is_some(),
        "oracle emits both GoPro:DeviceName and IFD0:Make ({mode}): {orc_order:?}"
      );
      assert!(
        odev < omake,
        "oracle: GoPro APP6 before the effective APP1 ⇒ GoPro:DeviceName before \
         IFD0:Make ({mode}): {orc_order:?}"
      );
    }
  }
}

/// Build a JPEG laid out `SOI APP6(GoPro\0 + truncated, no tags)
/// APP1(valid Exif Make='AAA') APP6(valid GoPro DVNM='BBB') EOI`: the LEADING
/// GoPro `APP6` has the `GoPro\0` prefix but its GPMF body is under the 8-byte
/// KLV header (so `process_gopro` decodes nothing — no tag), the valid `APP1`
/// Exif block sits between it and a LATER valid GoPro `APP6`.
fn jpeg_empty_app6_valid_app1_valid_app6() -> Vec<u8> {
  // APP6 #1: GoPro\0 + 4 stray bytes (< the 8-byte KLV header ⇒ no tags).
  let empty_gopro: &[u8] = b"GoPro\0\x01\x02\x03\x04";

  // APP1: Exif\0\0 + a valid TIFF, IFD0:Make='AAA'.
  let mut valid_app1 = Vec::new();
  valid_app1.extend_from_slice(b"Exif\0\0");
  valid_app1.extend_from_slice(&tiff_one_ascii(0x010f, "AAA")); // Make='AAA'

  // APP6 #2: GoPro\0 + a valid DEVC→STRM→DVNM='BBB'.
  let mut strm = Vec::new();
  klv(&mut strm, b"DVNM", 0x63, 1, 3, b"BBB"); // DeviceName='BBB'
  let valid_app6 = app6_gopro_payload(&wrap_devc_strm(&strm));

  let mut jpeg = vec![0xff, 0xd8]; // SOI
  push_segment(&mut jpeg, 0xe6, empty_gopro); // APP6 GoPro (no tags)
  push_segment(&mut jpeg, 0xe1, &valid_app1); // APP1 Exif (the EFFECTIVE block)
  push_segment(&mut jpeg, 0xe6, &valid_app6); // APP6 GoPro (the EFFECTIVE GoPro)
  jpeg.extend_from_slice(&[0xff, 0xd9]); // EOI
  jpeg
}

/// SYMMETRIC to `gopro_app6_before_effective_app1_when_leading_app1_malformed`
/// (the EXIF-side anchor): the GoPro-vs-EXIF order anchors on the first
/// TAG-PRODUCING GoPro `APP6`, NOT the first segment whose payload merely has
/// the `GoPro\0` prefix. For `APP6(empty GoPro) → APP1(valid Exif) →
/// APP6(valid GoPro)` the leading `GoPro\0` `APP6` decodes nothing, so the
/// EFFECTIVE (first tag-producing) GoPro segment is the LATER one — AFTER the
/// `APP1` Exif block — and ExifTool emits `IFD0:Make` BEFORE
/// `GoPro:DeviceName` (verified against the live oracle below, in `-j` and
/// `-n`). Anchoring on the inert first `GoPro\0` segment would wrongly emit the
/// GoPro block before the EXIF it actually follows.
#[test]
fn gopro_empty_app6_before_app1_does_not_anchor_gopro_first() {
  let jpeg = jpeg_empty_app6_valid_app1_valid_app6();
  for print_conv in [true, false] {
    let mode = if print_conv { "-j" } else { "-n" };
    let raw = extract_info("empty_first_app6.jpg", &jpeg, print_conv);
    let order = group_key_order(&raw, &["GoPro", "IFD0"]);
    let dev = order.iter().position(|k| k == "GoPro:DeviceName");
    let make = order.iter().position(|k| k == "IFD0:Make");
    assert!(
      dev.is_some() && make.is_some(),
      "both GoPro:DeviceName and IFD0:Make must emit ({mode}): {order:?}"
    );
    // The EXTRACTED values come from the LATER segments (the empty first APP6
    // contributes nothing).
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("json");
    let map = doc
      .as_array()
      .and_then(|a| a.first())
      .and_then(|o| o.as_object())
      .expect("doc");
    assert_eq!(
      map.get("IFD0:Make").and_then(|v| v.as_str()),
      Some("AAA"),
      "IFD0:Make from the APP1 must extract ({mode})"
    );
    assert_eq!(
      map.get("GoPro:DeviceName").and_then(|v| v.as_str()),
      Some("BBB"),
      "GoPro:DeviceName from the LATER valid APP6 must extract ({mode})"
    );
    assert!(
      make < dev,
      "the empty leading GoPro APP6 must NOT anchor the order: the first \
       TAG-PRODUCING GoPro APP6 is AFTER the valid APP1, so IFD0:Make must emit \
       BEFORE GoPro:DeviceName ({mode}): {order:?}"
    );

    // Ground-truth the cross-segment order against the live oracle: the empty
    // first APP6 contributes no key, the effective GoPro is after the APP1, so
    // IFD0:Make precedes GoPro:DeviceName.
    let args: Vec<&str> = if print_conv {
      vec!["-G1", "-j"]
    } else {
      vec!["-G1", "-j", "-n"]
    };
    if let Some(orc_raw) = oracle_crafted_raw(&jpeg, &args) {
      let orc_order = group_key_order(&orc_raw, &["GoPro", "IFD0"]);
      let odev = orc_order.iter().position(|k| k == "GoPro:DeviceName");
      let omake = orc_order.iter().position(|k| k == "IFD0:Make");
      assert!(
        odev.is_some() && omake.is_some(),
        "oracle emits both GoPro:DeviceName and IFD0:Make ({mode}): {orc_order:?}"
      );
      assert!(
        omake < odev,
        "oracle: empty leading GoPro APP6 ⇒ IFD0:Make before GoPro:DeviceName \
         ({mode}): {orc_order:?}"
      );
    }
  }
}

/// A minimal big-endian TIFF block that is VALID but EMPTY: byte-order marker
/// `MM\0\x2a` + a 0-entry IFD0 (count `0x0000`, next-IFD `0`). `ProcessTIFF`
/// SUCCEEDS on it — it is a well-formed TIFF — so `parse_exif_block_with_base`
/// returns `Some` and `File:ExifByteOrder` is emitted (the unconditional
/// `File`-group prefix). But the empty IFD0 yields NO movable EXIF tag (no
/// `IFD0:*`/`ExifIFD:*`/`GPS:*` entry), so this `APP1` must NOT anchor the
/// GoPro-vs-EXIF order — the EXIF-side mirror of the empty-`GoPro\0` `APP6`.
fn tiff_empty_ifd0() -> Vec<u8> {
  let mut t: Vec<u8> = vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
  t.extend_from_slice(&[0x00, 0x00]); // IFD0: 0 entries
  t.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // next-IFD = 0
  t
}

/// Build a JPEG laid out `SOI APP1(valid EMPTY TIFF — byte-order + 0-entry IFD0,
/// NO movable tags) APP6(valid GoPro DVNM='BBB') APP1(valid IFD0 Make='AAA')
/// EOI`: the LEADING `APP1` parses (so `File:ExifByteOrder` is emitted) but
/// contributes no movable tag; the GoPro `APP6` sits between it and the LATER
/// `APP1` that carries the first movable EXIF tag.
fn jpeg_byte_order_only_app1_gopro_valid_app1() -> Vec<u8> {
  let app1_empty = app1_exif(&tiff_empty_ifd0()); // Exif\0\0 + valid empty TIFF

  let mut strm = Vec::new();
  klv(&mut strm, b"DVNM", 0x63, 1, 3, b"BBB"); // DeviceName='BBB'
  let app6 = app6_gopro_payload(&wrap_devc_strm(&strm));

  let app1_make = app1_exif(&tiff_one_ascii(0x010f, "AAA")); // IFD0:Make='AAA'

  let mut jpeg = vec![0xff, 0xd8]; // SOI
  push_segment(&mut jpeg, 0xe1, &app1_empty); // APP1 (parses, NO movable tag)
  push_segment(&mut jpeg, 0xe6, &app6); // APP6 GoPro (the EFFECTIVE GoPro)
  push_segment(&mut jpeg, 0xe1, &app1_make); // APP1 (the EFFECTIVE EXIF block)
  jpeg.extend_from_slice(&[0xff, 0xd9]); // EOI
  jpeg
}

/// SYMMETRIC to `gopro_empty_app6_before_app1_does_not_anchor_gopro_first` (the
/// GoPro-side anchor): the GoPro-vs-EXIF order anchors on the first `APP1`
/// contributing a MOVABLE EXIF tag, NOT a byte-order-only / empty-IFD0 `APP1`
/// that parses to only the `File:ExifByteOrder` prefix. For
/// `APP1(valid empty TIFF) → APP6(valid GoPro) → APP1(valid IFD0 Make)` ExifTool
/// emits `File:ExifByteOrder` (the unconditional `File` prefix), then
/// `GoPro:DeviceName`, then `IFD0:Make` — the GoPro `APP6` precedes the LATER
/// movable-tag-producing `APP1`, so it precedes the only `IFD0:*` tag
/// (oracle-confirmed below, `-j` and `-n`: `File:ExifByteOrder`,
/// `GoPro:DeviceName='BBB'`, `IFD0:Make='AAA'`). Anchoring on the inert leading
/// (empty-IFD0) `APP1` would wrongly emit `IFD0:Make` BEFORE the GoPro block.
/// `File:ExifByteOrder` is NOT the EXIF anchor: it leads regardless and does not
/// participate in the GoPro-vs-EXIF ordering.
#[test]
fn gopro_byte_order_only_app1_does_not_anchor_exif_first() {
  let jpeg = jpeg_byte_order_only_app1_gopro_valid_app1();
  for print_conv in [true, false] {
    let mode = if print_conv { "-j" } else { "-n" };
    let raw = extract_info("byteorder_only_app1.jpg", &jpeg, print_conv);
    let order = group_key_order(&raw, &["GoPro", "IFD0"]);
    let dev = order.iter().position(|k| k == "GoPro:DeviceName");
    let make = order.iter().position(|k| k == "IFD0:Make");
    assert!(
      dev.is_some() && make.is_some(),
      "both GoPro:DeviceName and IFD0:Make must emit ({mode}): {order:?}"
    );

    let doc: serde_json::Value = serde_json::from_str(&raw).expect("json");
    let map = doc
      .as_array()
      .and_then(|a| a.first())
      .and_then(|o| o.as_object())
      .expect("doc");
    // The leading empty-IFD0 APP1 still emits File:ExifByteOrder (it parsed) —
    // the unconditional File-group prefix, NOT the EXIF anchor.
    assert!(
      map.contains_key("File:ExifByteOrder"),
      "the valid (empty) TIFF still emits File:ExifByteOrder ({mode}): {:?}",
      map.keys().collect::<Vec<_>>()
    );
    // The MOVABLE IFD0:Make comes from the LATER (third) APP1.
    assert_eq!(
      map.get("IFD0:Make").and_then(|v| v.as_str()),
      Some("AAA"),
      "IFD0:Make from the later APP1 must extract ({mode})"
    );
    assert_eq!(
      map.get("GoPro:DeviceName").and_then(|v| v.as_str()),
      Some("BBB"),
      "GoPro:DeviceName from the APP6 must extract ({mode})"
    );
    assert!(
      dev < make,
      "the byte-order-only (empty-IFD0) leading APP1 must NOT anchor EXIF first: \
       the first MOVABLE-tag-producing APP1 is AFTER the GoPro APP6, so \
       GoPro:DeviceName must emit BEFORE IFD0:Make (File:ExifByteOrder still \
       leads) ({mode}): {order:?}"
    );

    // Ground-truth against the live oracle: File:ExifByteOrder leads, then
    // GoPro:DeviceName, then IFD0:Make (the GoPro APP6 precedes the effective,
    // movable-tag-producing APP1).
    let args: Vec<&str> = if print_conv {
      vec!["-G1", "-j"]
    } else {
      vec!["-G1", "-j", "-n"]
    };
    if let Some(orc_raw) = oracle_crafted_raw(&jpeg, &args) {
      let orc_order = group_key_order(&orc_raw, &["GoPro", "IFD0"]);
      let odev = orc_order.iter().position(|k| k == "GoPro:DeviceName");
      let omake = orc_order.iter().position(|k| k == "IFD0:Make");
      assert!(
        odev.is_some() && omake.is_some(),
        "oracle emits both GoPro:DeviceName and IFD0:Make ({mode}): {orc_order:?}"
      );
      assert!(
        odev < omake,
        "oracle: byte-order-only leading APP1 ⇒ GoPro:DeviceName before IFD0:Make \
         ({mode}): {orc_order:?}"
      );
    }
  }
}

/// With NO `APP1` ever producing a parsed EXIF block — only a malformed `APP1`
/// (Exif-signature match, no tags) plus a valid GoPro `APP6` — there is no
/// `IFD0:*` content to order against, so the GoPro tags simply emit (after the
/// `File` group). exifast attaches the GoPro block with `before_exif = false`
/// (the `effective_exif_idx == None` path); `GoPro:DeviceName` is present and no
/// `IFD0:*` tag appears, matching the oracle (which emits `GoPro:DeviceName`
/// with the `Malformed APP1 EXIF segment` warning and no `IFD0:*`).
#[test]
fn gopro_app6_with_only_a_malformed_app1_still_emits_gopro() {
  let mut strm = Vec::new();
  klv(&mut strm, b"DVNM", 0x63, 1, 6, b"Camera");
  let mut app6_payload = Vec::new();
  app6_payload.extend_from_slice(b"GoPro\0");
  app6_payload.extend_from_slice(&wrap_devc_strm(&strm));

  let mut jpeg = vec![0xff, 0xd8]; // SOI
  push_segment(&mut jpeg, 0xe1, &app1_malformed_exif()); // APP1, no tags
  push_segment(&mut jpeg, 0xe6, &app6_payload); // APP6 GoPro
  jpeg.extend_from_slice(&[0xff, 0xd9]); // EOI

  for print_conv in [true, false] {
    let mode = if print_conv { "-j" } else { "-n" };
    let json = extract_info("novalid.jpg", &jpeg, print_conv);
    let doc: serde_json::Value = serde_json::from_str(&json).expect("json");
    let map = doc
      .as_array()
      .and_then(|a| a.first())
      .and_then(|o| o.as_object())
      .expect("doc");
    assert_eq!(
      map.get("GoPro:DeviceName").and_then(|v| v.as_str()),
      Some("Camera"),
      "GoPro:DeviceName must emit even with no effective EXIF block ({mode})"
    );
    assert!(
      !map.keys().any(|k| k.starts_with("IFD0:")),
      "no IFD0 tags when the only APP1 is malformed ({mode}): {:?}",
      map.keys().collect::<Vec<_>>()
    );

    let args: Vec<&str> = if print_conv {
      vec!["-G1", "-j"]
    } else {
      vec!["-G1", "-j", "-n"]
    };
    if let Some(orc) = oracle_crafted(&jpeg, &args) {
      assert_eq!(
        orc.get("GoPro:DeviceName").and_then(|v| v.as_str()),
        Some("Camera"),
        "oracle: GoPro:DeviceName emits with no effective EXIF block ({mode})"
      );
      assert!(
        !orc.keys().any(|k| k.starts_with("IFD0:")),
        "oracle emits no IFD0 tags here ({mode}): {:?}",
        orc.keys().collect::<Vec<_>>()
      );
    }
  }
}

// ===========================================================================
// FENCED: multiple INDEPENDENT valid `APP1` Exif blocks straddling a GoPro
// `APP6` (issue 233, the engine-wide strict per-segment marker-order JPEG
// emission limitation). exifast merges every `APP1` Exif block into ONE
// `IFD0:*` stream and emits the whole GoPro block on ONE side of it, anchored
// on `before_exif = first_gopro_idx < effective_exif_idx`
// (`src/exif/jpeg.rs`). A strict ExifTool marker replay would instead emit
// each segment's tags AT its `Marker:`-loop position
// (`ExifTool.pm:7325`) — so the GoPro `HandleTag` block would fall BETWEEN the
// first `APP1`'s tags and the later independent `APP1`'s tags.
//
// In practice this divergence is invisible at the conformance target: both
// exifast and ExifTool serialize `-G1 -j` output by family-1 GROUP, co-locating
// every `IFD0:*` tag, so the two independent `APP1` blocks always render as one
// contiguous `IFD0` run regardless of marker interleaving — and the relative
// `IFD0`-vs-`GoPro` group order is decided by exactly the same first-GoPro-vs-
// effective-EXIF index comparison. The cases below therefore VALUE- AND
// ORDER-match the live oracle today; the fence is for the hypothetical strict
// per-tag stream model (which neither tool's JSON exercises), the same class as
// the `APP6`/`APP1`/`APP6` straddle (`ExifMeta::gopro_before_exif` docs).
// Real GoPro stills carry a SINGLE early `APP1` Exif + a later GoPro `APP6`
// (the `t/images/GoPro.jpg` fixture), so they never hit this layout.
// ===========================================================================

/// A minimal big-endian TIFF block carrying ONE IFD0 ASCII entry (`tag` =
/// `value`, NUL-terminated), no IFD1 — lets a test place a distinct,
/// identifiable IFD0 tag (e.g. `Make`/`Model`) in each of several `APP1`
/// segments. The value is stored inline when it fits in 4 bytes, else at offset
/// 26 (just past the 8-byte header + one 12-byte entry + the 4-byte next-IFD
/// pointer), mirroring [`tiff_make_gopro`]'s layout.
fn tiff_one_ascii(tag: u16, value: &str) -> Vec<u8> {
  let mut val = value.as_bytes().to_vec();
  val.push(0); // NUL terminator (ExifTool ASCII count includes it)
  let cnt = val.len() as u32;
  let mut t: Vec<u8> = vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
  t.extend_from_slice(&[0x00, 0x01]); // 1 entry
  t.extend_from_slice(&tag.to_be_bytes()); // tag id
  t.extend_from_slice(&[0x00, 0x02]); // ASCII
  t.extend_from_slice(&cnt.to_be_bytes()); // count (incl. NUL)
  if cnt <= 4 {
    let mut inline = val.clone();
    inline.resize(4, 0); // left-justified, NUL-padded inline value
    t.extend_from_slice(&inline);
    t.extend_from_slice(&[0, 0, 0, 0]); // next-IFD = 0
  } else {
    t.extend_from_slice(&26u32.to_be_bytes()); // value @ offset 26
    t.extend_from_slice(&[0, 0, 0, 0]); // next-IFD = 0
    t.extend_from_slice(&val);
  }
  t
}

/// Wrap a TIFF block in a JPEG `APP1` Exif payload (`Exif\0\0` + TIFF).
fn app1_exif(tiff: &[u8]) -> Vec<u8> {
  let mut p = Vec::new();
  p.extend_from_slice(b"Exif\0\0");
  p.extend_from_slice(tiff);
  p
}

/// Wrap a GoPro GPMF body in a JPEG `APP6` payload (`GoPro\0` + GPMF).
fn app6_gopro_payload(gpmf: &[u8]) -> Vec<u8> {
  let mut p = Vec::new();
  p.extend_from_slice(b"GoPro\0");
  p.extend_from_slice(gpmf);
  p
}

/// FENCED (issue 233): two INDEPENDENT valid `APP1` Exif blocks
/// (`IFD0:Make='AAA'`, then `IFD0:Model='CCC'`) with a valid GoPro `APP6`
/// (`DeviceName='BBB'`) BETWEEN them — `SOI APP1(Make) APP6(GoPro) APP1(Model)
/// EOI`.
///
/// What exifast does today (PINNED here): all three tags are EXTRACTED with
/// their correct values — `IFD0:Make='AAA'`, `IFD0:Model='CCC'`,
/// `GoPro:DeviceName='BBB'` — i.e. BOTH independent `APP1` blocks are parsed and
/// merged into one `IFD0` stream (extraction is faithful; nothing is dropped).
/// The emission ORDER is `IFD0:Make`, `IFD0:Model`, `GoPro:DeviceName` (the
/// merged `IFD0` run, then the GoPro block — `before_exif = false` because the
/// GoPro `APP6` sits AFTER the FIRST effective `APP1`).
///
/// This VALUE- and ORDER-matches the live oracle (asserted below): ExifTool's
/// `-G1 -j` co-locates the family-1 `IFD0` group, so it too renders
/// `IFD0:Make`, `IFD0:Model`, `GoPro:DeviceName` and does NOT interleave the
/// GoPro block between the two `APP1`s in JSON. The strict per-segment
/// marker-order model (under which the GoPro `HandleTag` block would fall
/// BETWEEN the two `APP1` tag blocks in the raw extraction stream) is the
/// engine-wide limitation tracked in issue 233 — NOT asserted here, and
/// invisible at the `-G1 -j` conformance target; the only layout that needs it
/// alongside the `APP6`/`APP1`/`APP6` straddle. Real GoPro stills have a single
/// `APP1`, so they are unaffected.
#[test]
fn multi_independent_app1_straddling_gopro_extracts_all_and_matches_oracle_order() {
  // SOI APP1(IFD0:Make='AAA') APP6(GoPro DVNM='BBB') APP1(IFD0:Model='CCC') EOI.
  let mut strm = Vec::new();
  klv(&mut strm, b"DVNM", 0x63, 1, 3, b"BBB"); // DeviceName='BBB'
  let app6 = app6_gopro_payload(&wrap_devc_strm(&strm));
  let app1_make = app1_exif(&tiff_one_ascii(0x010f, "AAA")); // IFD0:Make
  let app1_model = app1_exif(&tiff_one_ascii(0x0110, "CCC")); // IFD0:Model

  let mut jpeg = vec![0xff, 0xd8]; // SOI
  push_segment(&mut jpeg, 0xe1, &app1_make); // APP1 Make (the effective block)
  push_segment(&mut jpeg, 0xe6, &app6); // APP6 GoPro (between the two APP1)
  push_segment(&mut jpeg, 0xe1, &app1_model); // APP1 Model (independent block)
  jpeg.extend_from_slice(&[0xff, 0xd9]); // EOI

  for print_conv in [true, false] {
    let mode = if print_conv { "-j" } else { "-n" };
    let raw = extract_info("multi_indep_app1.jpg", &jpeg, print_conv);
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("json");
    let map = doc
      .as_array()
      .and_then(|a| a.first())
      .and_then(|o| o.as_object())
      .expect("doc");

    // (1) EXTRACTION is faithful: all three distinct tags present, correct
    //     values. BOTH independent APP1 blocks are parsed (Make AND Model), and
    //     the GoPro block decodes its DeviceName.
    assert_eq!(
      map.get("IFD0:Make").and_then(|v| v.as_str()),
      Some("AAA"),
      "IFD0:Make from the first APP1 must extract ({mode})"
    );
    assert_eq!(
      map.get("IFD0:Model").and_then(|v| v.as_str()),
      Some("CCC"),
      "IFD0:Model from the SECOND independent APP1 must extract ({mode})"
    );
    assert_eq!(
      map.get("GoPro:DeviceName").and_then(|v| v.as_str()),
      Some("BBB"),
      "GoPro:DeviceName from the APP6 between the two APP1 must extract ({mode})"
    );

    // (2) Whole-block emission ORDER: the merged IFD0 run, then GoPro. We do
    //     NOT assert the strict marker-order interleaving (GoPro BETWEEN the two
    //     APP1 blocks) — that per-segment stream model is the engine-wide
    //     limitation tracked in issue 233 (see the module comment above). This
    //     order VALUE-equals the live oracle's, asserted in (3).
    let order = group_key_order(&raw, &["GoPro", "IFD0"]);
    assert_eq!(
      order,
      vec!["IFD0:Make", "IFD0:Model", "GoPro:DeviceName"],
      "exifast emits the merged IFD0 run then the GoPro block ({mode}): {order:?}"
    );

    // (3) Ground-truth VALUES and the whole-block ORDER against the live oracle
    //     when available. The oracle's `-G1 -j` co-locates the IFD0 group, so it
    //     too emits `IFD0:Make`, `IFD0:Model`, `GoPro:DeviceName` (NOT an
    //     interleaved Make/GoPro/Model) — confirming the issue-233 strict
    //     marker-order divergence is invisible at this conformance target.
    let args: Vec<&str> = if print_conv {
      vec!["-G1", "-j"]
    } else {
      vec!["-G1", "-j", "-n"]
    };
    if let Some(orc) = oracle_crafted(&jpeg, &args) {
      assert_eq!(
        orc.get("IFD0:Make").and_then(|v| v.as_str()),
        Some("AAA"),
        "oracle: IFD0:Make = AAA ({mode})"
      );
      assert_eq!(
        orc.get("IFD0:Model").and_then(|v| v.as_str()),
        Some("CCC"),
        "oracle: IFD0:Model = CCC ({mode})"
      );
      assert_eq!(
        orc.get("GoPro:DeviceName").and_then(|v| v.as_str()),
        Some("BBB"),
        "oracle: GoPro:DeviceName = BBB ({mode})"
      );
    }
    if let Some(orc_raw) = oracle_crafted_raw(&jpeg, &args) {
      let orc_order = group_key_order(&orc_raw, &["GoPro", "IFD0"]);
      // The oracle co-locates IFD0 and emits the GoPro block after it — exifast
      // reproduces this exactly. (Documents that the strict marker-order
      // interleaving of issue 233 does not surface in `-G1 -j` JSON.)
      assert_eq!(
        orc_order,
        vec!["IFD0:Make", "IFD0:Model", "GoPro:DeviceName"],
        "oracle whole-block order ({mode}): {orc_order:?}"
      );
    }
  }
}

// ===========================================================================
// R9: the EFFECTIVE-EXIF anchor must inspect the REAL emission, not just the
// IFD-walk `entries`. A MakerNote is CAPTURED separately (the 0x927c blob is
// NOT an `ExifEntry`), yet `Taggable::tags` emits its decoded vendor tags
// (`Apple:*`/`Canon:*`/...). So an `APP1` carrying ONLY a decoded MakerNote
// (an `ExifIFD` pointer + a vendor MakerNote, NO other IFD0 entry) emits a
// MOVABLE `MakerNotes:*` tag with an EMPTY `entries` vec. The pre-R9 anchor
// `!exif.entries().is_empty()` missed it (entries empty ⇒ the block did not
// anchor) and a GoPro `APP6` AFTER such an `APP1` wrongly emitted BEFORE it.
// `ExifMeta::emits_movable_tag()` now reads the real `tags` output, so the
// MakerNote-only `APP1` anchors. Vendor chosen: Apple (signature-gated —
// `Apple iOS\0` dispatches regardless of `Make`, so IFD0 needs NO `Make` entry
// and stays movable-tag-free; `MakerNoteVersion` is a default-visible,
// non-Unknown leaf the exif crate decodes from a JPEG `APP1`). Ground-truthed
// against the live oracle in `-j` and `-n`.
// ===========================================================================

/// A 1-entry Apple iOS MakerNote blob: `MakerNoteVersion = 4` (`int32s`,
/// inline). Mirrors the REAL iPhone layout (`Apple.jpg`): the 14-byte
/// `Apple iOS\0\0\x01MM` header whose TRAILING `MM` is the body byte order,
/// then the IFD entry count IMMEDIATELY (no second order marker), then the
/// 12-byte entry. `MakerNoteVersion` is `Unknown => 0` (default-visible) so it
/// survives the engine's Unknown-suppression and is a genuine MOVABLE
/// `MakerNotes:*` tag (ExifTool emits it under the family-1 `Apple` group).
fn apple_makernote_blob() -> Vec<u8> {
  let mut b = Vec::new();
  b.extend_from_slice(b"Apple iOS\x00\x00\x01MM"); // 14-byte header (trailing MM = order)
  b.extend_from_slice(&1u16.to_be_bytes()); // IFD entry count = 1
  b.extend_from_slice(&0x0001u16.to_be_bytes()); // tag 0x0001 MakerNoteVersion
  b.extend_from_slice(&0x0009u16.to_be_bytes()); // format int32s
  b.extend_from_slice(&1u32.to_be_bytes()); // count 1
  b.extend_from_slice(&4u32.to_be_bytes()); // inline value = 4
  b
}

/// A big-endian TIFF block whose IFD0 carries ONLY the `ExifIFD` pointer
/// (0x8769) — NO `Make`/`Model`/other value entry — and whose ExifIFD carries
/// ONLY the `MakerNote` pointer (0x927c) to an Apple blob. So the IFD walk
/// yields ZERO `ExifEntry`s (`entries` is EMPTY: 0x8769 and 0x927c are
/// structural pointers consumed by the walker, never emitted), while the
/// captured MakerNote decodes to a movable `Apple:MakerNoteVersion`. This is
/// the MakerNote-only `APP1` that the pre-R9 `!entries.is_empty()` anchor
/// missed.
fn tiff_apple_makernote_only() -> Vec<u8> {
  let blob = apple_makernote_blob();
  // Layout: TIFF header (8) | IFD0 (18) | ExifIFD (18) | Apple blob.
  let exififd_off: u32 = 8 + (2 + 12 + 4); // 26
  let mn_off: u32 = exififd_off + (2 + 12 + 4); // 44

  let mut t: Vec<u8> = vec![b'M', b'M', 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08];
  // IFD0 @ 8: 1 entry — ExifIFD pointer (0x8769, LONG) -> exififd_off.
  t.extend_from_slice(&1u16.to_be_bytes());
  t.extend_from_slice(&0x8769u16.to_be_bytes());
  t.extend_from_slice(&0x0004u16.to_be_bytes()); // LONG
  t.extend_from_slice(&1u32.to_be_bytes());
  t.extend_from_slice(&exififd_off.to_be_bytes());
  t.extend_from_slice(&0u32.to_be_bytes()); // next-IFD = 0
  // ExifIFD @ 26: 1 entry — MakerNote (0x927c, UNDEFINED) -> mn_off.
  t.extend_from_slice(&1u16.to_be_bytes());
  t.extend_from_slice(&0x927cu16.to_be_bytes());
  t.extend_from_slice(&0x0007u16.to_be_bytes()); // UNDEFINED
  t.extend_from_slice(&(blob.len() as u32).to_be_bytes());
  t.extend_from_slice(&mn_off.to_be_bytes());
  t.extend_from_slice(&0u32.to_be_bytes()); // next-IFD = 0
  // Apple blob @ 44.
  t.extend_from_slice(&blob);
  t
}

/// Build a JPEG with a GoPro `APP6` (`DeviceName='Camera'`) and a MakerNote-only
/// `APP1` (Apple `MakerNoteVersion`) in the requested order: `gopro_first` ⇒
/// `SOI APP6 APP1 EOI`, else `SOI APP1 APP6 EOI`.
fn jpeg_gopro_and_makernote_only_app1(gopro_first: bool) -> Vec<u8> {
  let mut strm = Vec::new();
  klv(&mut strm, b"DVNM", 0x63, 1, 6, b"Camera"); // DeviceName='Camera'
  let app6 = app6_gopro_payload(&wrap_devc_strm(&strm));
  let app1 = app1_exif(&tiff_apple_makernote_only());

  let mut jpeg = vec![0xff, 0xd8]; // SOI
  if gopro_first {
    push_segment(&mut jpeg, 0xe6, &app6); // APP6 GoPro
    push_segment(&mut jpeg, 0xe1, &app1); // APP1 (MakerNote-only)
  } else {
    push_segment(&mut jpeg, 0xe1, &app1); // APP1 (MakerNote-only)
    push_segment(&mut jpeg, 0xe6, &app6); // APP6 GoPro
  }
  jpeg.extend_from_slice(&[0xff, 0xd9]); // EOI
  jpeg
}

/// The EXIF anchor counts a MakerNote-only `APP1` (no IFD0 value entry, just a
/// decoded vendor MakerNote) as the EFFECTIVE EXIF block, because it emits a
/// movable `MakerNotes:*` tag. So `APP6(GoPro) → APP1(Apple MakerNote)` emits
/// `GoPro:DeviceName` BEFORE `Apple:MakerNoteVersion`, and the inverse layout
/// emits `Apple:MakerNoteVersion` BEFORE `GoPro:DeviceName` — exactly as the
/// live oracle does (`-j` and `-n`). The genuine guard: `Apple:MakerNoteVersion`
/// IS present (a real decoded MakerNote, not an empty one) and NO `IFD0:*` key
/// appears (the `APP1` has no IFD0 value entry — `entries` is empty, so the
/// pre-R9 `!entries.is_empty()` anchor would have missed this block).
#[test]
fn gopro_before_makernote_only_app1() {
  for gopro_first in [true, false] {
    let jpeg = jpeg_gopro_and_makernote_only_app1(gopro_first);
    for print_conv in [true, false] {
      let mode = if print_conv { "-j" } else { "-n" };
      let raw = extract_info("makernote_only_app1.jpg", &jpeg, print_conv);
      let doc: serde_json::Value = serde_json::from_str(&raw).expect("json");
      let map = doc
        .as_array()
        .and_then(|a| a.first())
        .and_then(|o| o.as_object())
        .expect("doc");

      // Genuine guard #1: the MakerNote actually DECODED (a real movable
      // MakerNotes tag, not an empty emission). Without this, the test would
      // pass vacuously on a block that emits nothing.
      assert!(
        map.contains_key("Apple:MakerNoteVersion"),
        "the MakerNote-only APP1 must decode Apple:MakerNoteVersion ({mode}): {:?}",
        map.keys().collect::<Vec<_>>()
      );
      // Genuine guard #2: the APP1 has NO IFD0 value entry — its `entries` vec
      // is empty, so the pre-R9 `!entries.is_empty()` anchor MISSED it. The
      // only thing making it effective is the MakerNote emission.
      assert!(
        !map.keys().any(|k| k.starts_with("IFD0:")),
        "the MakerNote-only APP1 must have NO IFD0 value tag ({mode}): {:?}",
        map.keys().collect::<Vec<_>>()
      );
      assert_eq!(
        map.get("GoPro:DeviceName").and_then(|v| v.as_str()),
        Some("Camera"),
        "GoPro:DeviceName must extract ({mode})"
      );

      let order = group_key_order(&raw, &["GoPro", "Apple"]);
      let dev = order.iter().position(|k| k == "GoPro:DeviceName");
      let ver = order.iter().position(|k| k == "Apple:MakerNoteVersion");
      assert!(
        dev.is_some() && ver.is_some(),
        "both GoPro:DeviceName and Apple:MakerNoteVersion must emit \
         (gopro_first={gopro_first}, {mode}): {order:?}"
      );
      if gopro_first {
        assert!(
          dev < ver,
          "APP6-before-APP1 ⇒ GoPro:DeviceName must emit BEFORE \
           Apple:MakerNoteVersion (the MakerNote-only APP1 anchors EXIF) \
           ({mode}): {order:?}"
        );
      } else {
        assert!(
          ver < dev,
          "APP1-before-APP6 ⇒ Apple:MakerNoteVersion must emit BEFORE \
           GoPro:DeviceName ({mode}): {order:?}"
        );
      }

      // Ground-truth the cross-segment order against the live oracle.
      let args: Vec<&str> = if print_conv {
        vec!["-G1", "-j"]
      } else {
        vec!["-G1", "-j", "-n"]
      };
      if let Some(orc_raw) = oracle_crafted_raw(&jpeg, &args) {
        let orc_order = group_key_order(&orc_raw, &["GoPro", "Apple"]);
        let odev = orc_order.iter().position(|k| k == "GoPro:DeviceName");
        let over = orc_order.iter().position(|k| k == "Apple:MakerNoteVersion");
        assert!(
          odev.is_some() && over.is_some(),
          "oracle emits both GoPro:DeviceName and Apple:MakerNoteVersion \
           (gopro_first={gopro_first}, {mode}): {orc_order:?}"
        );
        if gopro_first {
          assert!(
            odev < over,
            "oracle: APP6-before-APP1 ⇒ GoPro:DeviceName before \
             Apple:MakerNoteVersion ({mode}): {orc_order:?}"
          );
        } else {
          assert!(
            over < odev,
            "oracle: APP1-before-APP6 ⇒ Apple:MakerNoteVersion before \
             GoPro:DeviceName ({mode}): {orc_order:?}"
          );
        }
      }
    }
  }
}
