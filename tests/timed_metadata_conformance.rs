//! Byte-exact `-ee` timed-metadata conformance — the crux integration.
//!
//! ExifTool surfaces a video's per-sample GPS / sensor telemetry only under
//! `-ee` (`ExtractEmbedded`). exifast emits the same stream through the shared
//! [`emit_timed_samples`](exifast internal) emitter, gated on
//! [`ParseOptions::with_extract_embedded`]. This suite renders the full
//! document at `-ee -j -G1` (the doc axis collapsed, first-fix-wins) and at
//! `-ee -j -G3` (every fix as its own `Doc<N>` row) and compares it
//! TOKEN-EXACTLY ([`json_equivalent_strict`]) to the committed bundled-ExifTool
//! `.ee.json` (`-ee -j -G1`) / `.ee.g3.json` (`-ee -j -G3:1`) goldens.
//!
//! The lat/lon `GPS::ToDMS` PrintConv (`"47 deg 37' 42.32\" N"`), the altitude
//! `" m"`-suffix PrintConv, and the per-source speed/track/measure-mode columns
//! are all applied here at `-j`; `-n` would emit the raw post-ValueConv scalars
//! (covered by the in-crate unit tests).
//!
//! ## Structurally-absent fields (noted gaps)
//!
//! Two structural (NON-GPS) track fields are not modeled by the typed layer and
//! are EXCLUDED from the comparison (the GPS lat/lon/alt/datetime/measure-mode/
//! accuracy/velocity columns — the camera-metadata payload — MUST still match
//! exactly):
//!
//! - `Track<N>:MetaFormat` — the `stsd` sample-description 4-char format code
//!   (`"camm"`/`"mebx"`). The structural QuickTime trak parse does not capture
//!   the sample-description format, so this tag is absent for BOTH camm and
//!   mebx. (Adding it is a structural-parse feature, not part of the timed-GPS
//!   emission.)
//! - `Track<N>:SampleTime` / `Track<N>:SampleDuration` for **camm** — the typed
//!   [`CammGpsSample`] carries no `ProcessSamples` sample-table timing, so these
//!   cannot be reproduced. (The **mebx** sample DOES carry timing, so its
//!   `SampleTime`/`SampleDuration` ARE emitted and compared.)
#![cfg(all(feature = "quicktime", feature = "json"))]

use exifast::ParseOptions;
use exifast::jsondiff::json_equivalent_strict;
use exifast::parser::extract_info_with_options;

/// Read a fixture into memory.
fn fixture(name: &str) -> Vec<u8> {
  let root = env!("CARGO_MANIFEST_DIR");
  std::fs::read(format!("{root}/tests/fixtures/{name}"))
    .unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
}

/// Read a golden into a string.
fn golden(name: &str) -> String {
  let root = env!("CARGO_MANIFEST_DIR");
  std::fs::read_to_string(format!("{root}/tests/golden/{name}"))
    .unwrap_or_else(|e| panic!("read golden {name}: {e}"))
}

/// Render `fixture` at `-ee -j` in the given group mode and compare TOKEN-EXACT
/// to `golden_name`. `g3 = true` ⇒ `-G3:1` (`Doc<N>:` prefixes); `false` ⇒
/// `-G1` (doc axis collapsed).
fn check_ee(fixture_name: &str, golden_name: &str, g3: bool) {
  let data = fixture(fixture_name);
  let opts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(g3);
  let got = extract_info_with_options(fixture_name, &data, true, opts);
  let want = golden(golden_name);
  if let Err(e) = json_equivalent_strict(&got, &want) {
    panic!(
      "{fixture_name} ({}) vs {golden_name}: {}\n--- got ---\n{got}\n--- want ---\n{want}",
      if g3 { "-G3" } else { "-G1" },
      e.message()
    );
  }
}

/// Strip a set of keys from every object in a `-j -G1`/`-G3` document so a
/// structurally-absent field (one exifast cannot yet produce) does not fail the
/// otherwise byte-exact comparison. The keys are matched against the FULL JSON
/// key (`<group>:<name>` or `Doc<N>:<group>:<name>`) by their `:<name>` tail.
fn drop_keys(doc: &str, name_tails: &[&str]) -> String {
  let mut v: serde_json::Value = serde_json::from_str(doc).expect("valid JSON document");
  if let Some(arr) = v.as_array_mut() {
    for el in arr {
      if let Some(obj) = el.as_object_mut() {
        obj.retain(|k, _| {
          !name_tails
            .iter()
            .any(|t| k == t || k.ends_with(&format!(":{t}")))
        });
      }
    }
  }
  serde_json::to_string(&v).expect("re-serialize document")
}

/// Like [`check_ee`] but compares with `excluded` name-tails removed from BOTH
/// sides (the structurally-absent `SampleTime`/`SampleDuration` for camm).
fn check_ee_excluding(fixture_name: &str, golden_name: &str, g3: bool, excluded: &[&str]) {
  let data = fixture(fixture_name);
  let opts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(g3);
  let got = drop_keys(
    &extract_info_with_options(fixture_name, &data, true, opts),
    excluded,
  );
  let want = drop_keys(&golden(golden_name), excluded);
  if let Err(e) = json_equivalent_strict(&got, &want) {
    panic!(
      "{fixture_name} ({}) vs {golden_name} [excluding {excluded:?}]: {}\n\
       --- got ---\n{got}\n--- want ---\n{want}",
      if g3 { "-G3" } else { "-G1" },
      e.message()
    );
  }
}

// ── QuickTime: sources (SP3 stream / freeGPS — moov-level, family1 QuickTime) ─

#[test]
fn gps0_ee_byte_exact() {
  check_ee("QuickTime_gps0.mov", "QuickTime_gps0.mov.ee.json", false);
  check_ee("QuickTime_gps0.mov", "QuickTime_gps0.mov.ee.g3.json", true);
}

#[test]
fn gps_kenwood_ee_byte_exact() {
  check_ee(
    "QuickTime_gps_kenwood.mov",
    "QuickTime_gps_kenwood.mov.ee.json",
    false,
  );
  check_ee(
    "QuickTime_gps_kenwood.mov",
    "QuickTime_gps_kenwood.mov.ee.g3.json",
    true,
  );
}

#[test]
fn moov_gps_ee_byte_exact() {
  check_ee(
    "QuickTime_moov_gps.mov",
    "QuickTime_moov_gps.mov.ee.json",
    false,
  );
  check_ee(
    "QuickTime_moov_gps.mov",
    "QuickTime_moov_gps.mov.ee.g3.json",
    true,
  );
}

#[test]
fn frea_rexing17b_ee_byte_exact() {
  check_ee(
    "QuickTime_frea_rexing17b.mov",
    "QuickTime_frea_rexing17b.mov.ee.json",
    false,
  );
  check_ee(
    "QuickTime_frea_rexing17b.mov",
    "QuickTime_frea_rexing17b.mov.ee.g3.json",
    true,
  );
}

// ── Track<N>: camm (Android CAMM — per-sample Track<N>, via track_index) ─────
// SampleTime / SampleDuration are structurally absent (no sample-table timing
// on the typed CammGpsSample) and excluded; the GPS columns must match.

#[test]
fn camm_ee_byte_exact_gps_columns() {
  // Excluded: the structural `MetaFormat` (stsd code, not captured) + the
  // sample-table `SampleTime`/`SampleDuration` (no typed CammGpsSample timing).
  let excl = ["SampleTime", "SampleDuration", "MetaFormat"];
  check_ee_excluding(
    "QuickTime_camm.mov",
    "QuickTime_camm.mov.ee.json",
    false,
    &excl,
  );
  check_ee_excluding(
    "QuickTime_camm.mov",
    "QuickTime_camm.mov.ee.g3.json",
    true,
    &excl,
  );
}

// ── Track<N>: mebx (Apple metadata keys — per-sample Track<N>, with timing) ──
// SampleTime / SampleDuration ARE emitted (the mebx sample carries timing); only
// the structural `MetaFormat` (stsd code) is an unmodeled gap.

#[test]
fn mebx_gps_ee_byte_exact_except_metaformat() {
  let excl = ["MetaFormat"];
  check_ee_excluding(
    "QuickTime_mebx_gps.mov",
    "QuickTime_mebx_gps.mov.ee.json",
    false,
    &excl,
  );
  check_ee_excluding(
    "QuickTime_mebx_gps.mov",
    "QuickTime_mebx_gps.mov.ee.g3.json",
    true,
    &excl,
  );
}
