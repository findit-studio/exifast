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
//! One structural (NON-GPS) track field is not modeled by the typed layer and
//! is EXCLUDED from the comparison (the GPS lat/lon/alt/datetime/measure-mode/
//! accuracy/velocity columns — the camera-metadata payload — MUST still match
//! exactly):
//!
//! - `Track<N>:MetaFormat` — the `stsd` sample-description 4-char format code
//!   (`"camm"`/`"mebx"`). The structural QuickTime trak parse does not capture
//!   the sample-description format, so this tag is absent for BOTH camm and
//!   mebx. (Adding it is a structural-parse feature, not part of the timed-GPS
//!   emission — issue #212.)
//!
//! `Track<N>:SampleTime` / `Track<N>:SampleDuration` — the `ProcessSamples`
//! sample-table timing emitted ahead of each decoded sample's payload — ARE now
//! emitted and compared byte-exact for BOTH **camm** and **mebx** (each timed
//! sample carries its `SampleTime`/`SampleDuration` off the `stts`/`stsz` tables,
//! threaded onto the camm GPS / motion / warning records of that sample).
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

/// Render `fixture` at the DEFAULT `-j` (NO `-ee`, `-G1`) and compare
/// TOKEN-EXACT to `golden_name` with `excluded` name-tails dropped from BOTH
/// sides. This is the faithful no-`ee` path: ExifTool emits the `[minor]
/// ExtractEmbedded` warning where an embedded timed-metadata stream exists, but
/// surfaces NO per-sample GPS without `-ee`. The `excluded` tails cover the
/// structural `MetaFormat` gap (the `stsd` 4-char code is not captured by the
/// structural trak parse — same gap as the `-ee` tests).
fn check_noee_excluding(fixture_name: &str, golden_name: &str, excluded: &[&str]) {
  let data = fixture(fixture_name);
  // The default: `-ee` OFF. `extract_info` already defaults `extract_embedded`
  // to false; spell it out via the options entry for symmetry with `check_ee`.
  let opts = ParseOptions::default().with_extract_embedded(false);
  let got = drop_keys(
    &extract_info_with_options(fixture_name, &data, true, opts),
    excluded,
  );
  let want = drop_keys(&golden(golden_name), excluded);
  if let Err(e) = json_equivalent_strict(&got, &want) {
    panic!(
      "{fixture_name} (no-ee) vs {golden_name} [excluding {excluded:?}]: {}\n\
       --- got ---\n{got}\n--- want ---\n{want}",
      e.message()
    );
  }
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

// ── QuickTime: gsen (DuDuBell/VSYS accelerometer — top-level box, family1
// QuickTime) ─────────────────────────────────────────────────────────────────
// `Process_gsen` (QuickTimeStream.pl:2769-2789) opens a `Doc<N>` per 3-byte
// record (`++DOC_COUNT`) and `HandleTag`s ONLY `Accelerometer => "@acc"` — these
// records carry NO coordinate pair, so the per-sample emit MUST NOT be gated on
// `has_coordinates`. The oracle: `-G1` collapses both records to one
// `QuickTime:Accelerometer "1 -2 3"` (first-wins); `-G3:1` keeps
// `Doc1:…Accelerometer "1 -2 3"` / `Doc2:…Accelerometer "0.5 -0.5 0"`.
#[test]
fn gsen_ee_byte_exact() {
  check_ee("QuickTime_gsen.mov", "QuickTime_gsen.mov.ee.json", false);
  check_ee("QuickTime_gsen.mov", "QuickTime_gsen.mov.ee.g3.json", true);
}

// ── Track<N>: camm (Android CAMM — per-sample Track<N>, via track_index) ─────
// SampleTime / SampleDuration ARE emitted (one per camm SAMPLE, off the
// sample-table timing threaded onto each sample's records) and compared; only
// the structural `MetaFormat` (stsd 4cc, #212) is excluded.

#[test]
fn camm_ee_byte_exact_gps_columns() {
  // Excluded: only the structural `MetaFormat` (stsd code, not captured). The
  // sample-table `SampleTime`/`SampleDuration` ARE emitted (the camm sample
  // carries the timing) and compared byte-exact.
  let excl = ["MetaFormat"];
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

// A MOTION-only camm fixture (NO GPS packets): one camm2 AngularVelocity, one
// camm3 Acceleration, one camm7 MagneticField, and one camm1
// PixelExposureTime/RollingShutterSkewTime — each its OWN timed sample, so
// `ProcessSamples` opens one `Doc<N>` per sample. Pins that the camm MOTION
// telemetry (camm1-4/7) `ProcessCAMM` decodes — which the GPS-only emitter once
// dropped — now surfaces under `-ee`: the vec3 tags are the three floats space-joined
// (`"@a"` / `%.15g`, mode-invariant), and the camm1 exposure carries its
// `sprintf("%.4g ms", $val*1000)` PrintConv at `-j` (raw seconds at `-n`). The
// `-ee -G3` oracle is `Doc1:Track1:AngularVelocity` / `Doc2:Track1:Acceleration`
// / `Doc3:Track1:MagneticField` / `Doc4:Track1:{PixelExposureTime,
// RollingShutterSkewTime}`; `-G1` collapses each to its single `Track1:` row.
// camm0's `AngleAxis` is NOT emitted (type 0 is absent from `%size`, so
// `ProcessCAMM` `last`s — verified separately). SampleTime/SampleDuration ARE
// emitted (one per camm SAMPLE, ahead of that sample's motion payload) and
// compared; only the structural `MetaFormat` is excluded.
#[test]
fn camm_motion_ee_byte_exact() {
  let excl = ["MetaFormat"];
  check_ee_excluding(
    "QuickTime_camm_motion.mov",
    "QuickTime_camm_motion.mov.ee.json",
    false,
    &excl,
  );
  check_ee_excluding(
    "QuickTime_camm_motion.mov",
    "QuickTime_camm_motion.mov.ee.g3.json",
    true,
    &excl,
  );
}

// The motion-only fixture at no-`ee`: camm is a `meta`-handler `trak`, so it is
// fully `-ee`-gated — the only surfaced tag is the `Track1:Warning` ([minor]
// ExtractEmbedded), NOT any motion record. Pins that the new motion emission is
// `-ee`-only (same gate as the GPS camm), so a no-`ee` parse leaks nothing.
#[test]
fn camm_motion_noee_warning_byte_exact_except_metaformat() {
  check_noee_excluding(
    "QuickTime_camm_motion.mov",
    "QuickTime_camm_motion.mov.json",
    &["MetaFormat"],
  );
}

// A MULTI-PACKET single-sample camm fixture: the FIRST timed sample holds TWO
// camm5 GPS packets (10/20/30 then 40/50/60); the SECOND sample one camm5
// (11/21/31). ExifTool fires `FoundSomething` ONCE per timed SAMPLE then
// `HandleTag`s every packet of that sample under the SAME `DOC_NUM`
// (QuickTimeStream.pl:1523/3493-3504), so both packets of sample 1 share Doc1.
// Pins the two-rule `-ee -G1` collapse: WITHIN Doc1 a duplicate `GPSLatitude`
// REPLACES (last-wins, ExifTool.pm:9564) ⇒ 40/50/60 survives (NOT the first
// 10/20/30 a pure first-wins collapse would keep); ACROSS docs the FIRST doc
// wins ⇒ Doc2's 11/21/31 is DROPPED at `-G1`. At `-ee -G3` Doc1 = 40/50/60 (the
// flat TagMap sink is last-wins in place) and Doc2 = 11/21/31. SampleTime/
// SampleDuration ARE emitted: ONE per camm SAMPLE (Doc1 carries the first
// sample's timing once, even though it has two packets) and compared; only the
// structural `MetaFormat` is excluded.
#[test]
fn camm_multipkt_within_doc_last_wins_byte_exact() {
  let excl = ["MetaFormat"];
  check_ee_excluding(
    "QuickTime_camm_multipkt.mov",
    "QuickTime_camm_multipkt.mov.ee.json",
    false,
    &excl,
  );
  check_ee_excluding(
    "QuickTime_camm_multipkt.mov",
    "QuickTime_camm_multipkt.mov.ee.g3.json",
    true,
    &excl,
  );
}

// A MIXED warning+GPS-on-ONE-track camm fixture: sample 0 is a camm0 (Unknown
// record type 0) raising a `Track1:Warning` INSIDE `ProcessCAMM`
// (QuickTimeStream.pl:3495); sample 1 is a camm5 GPS fix. Both ride Track1 but
// carry DIFFERENT sample-table SampleTimes (Doc1 "0 s", Doc2 "1.00 s" — the
// shared `stts` delta=1000 gives each sample its own start). `Meta::tags`
// emits the camm warning BEFORE the camm GPS, so the warning's `Track1:SampleTime`
// is enqueued first and the GPS's later. `FoundSomething` emits SampleTime/
// SampleDuration per SAMPLE in sample order (QuickTimeStream.pl:967-972) before
// the ProcessCAMM dispatch, and JSON `%noDups` is FIRST-wins (exiftool:2952-2953),
// so at `-ee -G1` ExifTool keeps SAMPLE 0's `Track1:SampleTime "0 s"` (NOT
// sample 1's "1.00 s"). This pins that exifast routes the warning sample's
// SampleTime/SampleDuration through the SAME first-seen timing gate the camm
// GPS/motion emitters use: the warning emits first, so ITS timing wins and the
// later GPS `Track1:SampleTime` is gated out. (Pre-fix the warning path pushed
// its timing UNGATED, so the later GPS SampleTime overwrote it in the last-wins
// `TagMap` sink — `-G1` wrongly showed "1.00 s".) At `-ee -G3:1` there is NO
// gate: Doc1 keeps "0 s"+Warning and Doc2 keeps "1.00 s"+GPS. Only the
// structural `MetaFormat` is excluded.
#[test]
fn camm_warn_gps_mixed_track_sample_time_first_wins_byte_exact() {
  let excl = ["MetaFormat"];
  check_ee_excluding(
    "QuickTime_camm_warn_gps.mov",
    "QuickTime_camm_warn_gps.mov.ee.json",
    false,
    &excl,
  );
  check_ee_excluding(
    "QuickTime_camm_warn_gps.mov",
    "QuickTime_camm_warn_gps.mov.ee.g3.json",
    true,
    &excl,
  );
}

// A REVERSE-ORDER GPS-then-warning camm fixture (the MIRROR of camm_warn_gps):
// sample 0 is a camm5 GPS fix (Doc1 "0 s"), sample 1 is a camm0 Unknown-record
// warning (Doc2 "1.00 s"), both on Track1. ExifTool processes camm samples
// SEQUENTIALLY and JSON `%noDups` is FIRST-wins, so at `-ee -G1` it keeps
// SAMPLE 0's `Track1:SampleTime "0 s"` — the GPS sample's — NOT the later
// warning's "1.00 s". This is the REVERSE of exifast's emitter-KIND order:
// `Meta::tags` drains the camm WARNING records (with their "1.00 s" timing)
// BEFORE the GPS records, so the OLD per-kind first-wins gate wrongly recorded
// the warning sample's "1.00 s" first and `-G1` showed "1.00 s". The structural
// fix precomputes, per Track<N>, the SampleTime/SampleDuration of the
// MINIMUM-doc camm sample across ALL kinds (here the GPS sample, Doc1) and emits
// only THAT at `-G1`. At `-ee -G3:1` each doc keeps its own timing. Only the
// structural `MetaFormat` (stsd 4cc, #212) is excluded.
#[test]
fn camm_gps_warn_reverse_order_min_doc_sample_time_byte_exact() {
  let excl = ["MetaFormat"];
  check_ee_excluding(
    "QuickTime_camm_gps_warn.mov",
    "QuickTime_camm_gps_warn.mov.ee.json",
    false,
    &excl,
  );
  check_ee_excluding(
    "QuickTime_camm_gps_warn.mov",
    "QuickTime_camm_gps_warn.mov.ee.g3.json",
    true,
    &excl,
  );
}

// A REVERSE-ORDER motion-then-GPS camm fixture: sample 0 is a camm2
// AngularVelocity MOTION packet (Doc1 "0 s"), sample 1 is a camm5 GPS fix (Doc2
// "1.00 s"), both on Track1. ExifTool keeps SAMPLE 0's `Track1:SampleTime "0 s"`
// (the MOTION sample's) at `-ee -G1` — the minimum-doc camm sample regardless of
// packet kind. This is the REVERSE of exifast's emitter-KIND order: `Meta::tags`
// drains the camm GPS records (with their "1.00 s" timing) BEFORE the motion
// records, so the OLD per-kind first-wins gate wrongly recorded the GPS sample's
// "1.00 s" first and `-G1` showed "1.00 s". The structural min-doc precompute
// picks the motion sample (Doc1, "0 s") for `Track1:SampleTime`. At `-ee -G3:1`
// each doc keeps its own (Doc1 = "0 s"+AngularVelocity, Doc2 = "1.00 s"+GPS).
// Only the structural `MetaFormat` is excluded.
#[test]
fn camm_motion_gps_reverse_order_min_doc_sample_time_byte_exact() {
  let excl = ["MetaFormat"];
  check_ee_excluding(
    "QuickTime_camm_motion_gps.mov",
    "QuickTime_camm_motion_gps.mov.ee.json",
    false,
    &excl,
  );
  check_ee_excluding(
    "QuickTime_camm_motion_gps.mov",
    "QuickTime_camm_motion_gps.mov.ee.g3.json",
    true,
    &excl,
  );
}

// A camm0 (type-0 first packet) fixture — the DISPATCH-but-warn case. Type 0
// matches the camm0 `Condition` `/^..\0\0/s` (QuickTimeStream.pl:255), so
// `GetTagInfo` returns the camm0 tagInfo → `FoundSomething` emits
// SampleTime/SampleDuration (Doc1) → `ProcessCAMM` runs, but type 0 is NOT in its
// `%size` table, so the walk `$et->Warn("Unknown camm record type 0"), last`s
// (:3495). The `-ee -G3:1` oracle is `Doc1:Track1:SampleTime "0 s"`,
// `SampleDuration "1.00 s"`, then `Warning "Unknown camm record type 0"`. This
// REGRESSION-pins that the new first-packet dispatch gate STILL dispatches a
// type-0 first packet (camm0 Condition matches) — the gate rejects only types
// OUTSIDE 0..7 (or a sample too short to read the +2 type). Only the structural
// `MetaFormat` (stsd 4cc, #212) is excluded.
#[test]
fn camm0_unknown_record_dispatches_and_warns_byte_exact() {
  let excl = ["MetaFormat"];
  check_ee_excluding(
    "QuickTime_camm0.mov",
    "QuickTime_camm0.mov.ee.json",
    false,
    &excl,
  );
  check_ee_excluding(
    "QuickTime_camm0.mov",
    "QuickTime_camm0.mov.ee.g3.json",
    true,
    &excl,
  );
}

// A camm_trunc (recognized first packet, TRUNCATED) fixture — the dispatch-but-
// truncate case. A camm5 first packet matches the camm5 `Condition`
// `/^..\x05\0/s` → `FoundSomething` (Doc1) → `ProcessCAMM`, whose `$pos + $size >
// $end and $et->Warn("Truncated camm record 5"), last`s because the 28-byte
// record overruns the 20-byte sample (:3496). The `-ee -G3:1` oracle is
// `Doc1:Track1:SampleTime`, `SampleDuration`, then `Warning "Truncated camm
// record 5"`. REGRESSION-pins that a recognized first packet that then truncates
// STILL dispatches + warns (the gate is on the FIRST packet matching a Condition,
// not on the decode succeeding). Only the structural `MetaFormat` is excluded.
#[test]
fn camm_trunc_recognized_first_packet_dispatches_and_warns_byte_exact() {
  let excl = ["MetaFormat"];
  check_ee_excluding(
    "QuickTime_camm_trunc.mov",
    "QuickTime_camm_trunc.mov.ee.json",
    false,
    &excl,
  );
  check_ee_excluding(
    "QuickTime_camm_trunc.mov",
    "QuickTime_camm_trunc.mov.ee.g3.json",
    true,
    &excl,
  );
}

// A BAD-FIRST-PACKET-TYPE camm fixture (first packet type = 8, OUTSIDE 0..7) —
// the DISPATCH-GATE case. The `camm` MetaFormat dispatches through `GetTagInfo`,
// which evaluates the camm0..camm7 `Condition`s `$$valPt =~ /^..\x0N\0/s`
// (N=0..7, QuickTimeStream.pl:251-309) against the sample bytes. A first packet
// whose int16u-LE type (byte +2) is 8 matches NO camm<N> `Condition` → `GetTagInfo`
// returns undef → `FoundSomething` is NOT called (no `Doc<N>`, no
// SampleTime/SampleDuration) and `ProcessCAMM` is NEVER dispatched (no `Unknown
// camm record type 8` warning — that fires only AFTER a Condition matched the
// FIRST packet). The buffer does not start with `X`, so the text-camm fallback
// (:1540) is skipped too. The bundled `-ee -G1`/`-G3:1` oracle emits NOTHING for
// this sample (ends at `Track1:MetaFormat`). Pins exifast's dispatch gate: a
// first-packet type outside 0..7 emits no doc, no SampleTime, no warning, and must
// NOT run `process_camm`. RED before the fix (exifast unconditionally opened a doc
// + warned `Unknown camm record type 8`); GREEN after. Only the structural
// `MetaFormat` (stsd 4cc) is excluded.
#[test]
fn camm_badtype_first_packet_out_of_range_emits_nothing_byte_exact() {
  let excl = ["MetaFormat"];
  check_ee_excluding(
    "QuickTime_camm_badtype.mov",
    "QuickTime_camm_badtype.mov.ee.json",
    false,
    &excl,
  );
  check_ee_excluding(
    "QuickTime_camm_badtype.mov",
    "QuickTime_camm_badtype.mov.ee.g3.json",
    true,
    &excl,
  );
}

// A RECOGNIZED-EMPTY-PAYLOAD camm fixture (a camm5 4-byte header, NO payload) —
// the TIMING-ONLY-MARKER case. The camm5 first packet matches the camm5
// `Condition` `/^..\x05\0/s` (the 4-byte header satisfies it) → `FoundSomething`
// emits SampleTime/SampleDuration (:1523), THEN `ProcessCAMM` runs but its
// `while ($pos + 4 < $end)` loop is `0 + 4 < 4` = FALSE → the body never
// iterates: NO packet decoded, NO `Unknown`/`Truncated` warning. The bundled
// `-ee -G3:1` oracle is `Doc1:Track1:SampleTime "0 s"` + `Doc1:Track1:SampleDuration
// "1.00 s"` (NO GPS payload, NO Warning); at `-ee -G1` the same as
// `Track1:SampleTime`/`SampleDuration`. Pins exifast's timing-only marker: a
// recognized first-packet camm sample that decodes to NO stored record STILL
// records per-sample timing so it participates in the `-G1` cross-kind min-doc
// timing AND emits its own `Doc<N>` SampleTime/SampleDuration at `-G3`. RED
// before the fix (exifast decoded nothing → stored no marker → missed the
// timing); GREEN after. Only the structural `MetaFormat` is excluded.
#[test]
fn camm_emptypayload_recognized_first_packet_emits_timing_only_byte_exact() {
  let excl = ["MetaFormat"];
  check_ee_excluding(
    "QuickTime_camm_emptypayload.mov",
    "QuickTime_camm_emptypayload.mov.ee.json",
    false,
    &excl,
  );
  check_ee_excluding(
    "QuickTime_camm_emptypayload.mov",
    "QuickTime_camm_emptypayload.mov.ee.g3.json",
    true,
    &excl,
  );
}

// A DUPLICATE-WARNING camm fixture — the `-ee -G3` timing-vs-dedup ORDERING case.
// TWO warning-only camm0 samples carry the SAME warning string: sample 0 at
// SampleTime "0 s" (Doc1), sample 1 at SampleTime "1.00 s" (Doc2) — both
// `ProcessCAMM` walks `$et->Warn("Unknown camm record type 0"), last` (:3495).
// `FoundSomething` emits `SampleTime`/`SampleDuration` per SAMPLE BEFORE the
// `ProcessCAMM` dispatch (:1518-1523), so EACH sample's `Doc<N>` timing exists;
// but the SECOND identical `Warn` is WAS_WARNED-deduped (`ExifTool.pm sub Warn`),
// so only Doc1 carries the `Warning` TAG — and the surviving tag gains the
// ` [x2]` occurrence-count suffix (`ExifTool.pm:3196-3203`, keyed on the message
// string in `$$self{VALUE}` regardless of group). The `-ee -G3:1` oracle is
// therefore `Doc1:Track1:SampleTime "0 s"` + `SampleDuration` + `Warning
// "Unknown camm record type 0 [x2]"`, then `Doc2:Track1:SampleTime "1.00 s"` +
// `SampleDuration` but NO `Doc2:…Warning`. At `-ee -G1` it collapses to one
// `Track1:SampleTime "0 s"` (the min-doc sample) + one `Track1:Warning
// "Unknown camm record type 0 [x2]"`. Pins that exifast emits the second warning
// sample's `-G3` `Doc<N>` timing EVEN WHEN its `Warning` text is deduped. RED
// before the fix (the message-dedup `continue` skipped the whole second sample,
// losing its `Doc2:Track1:SampleTime`/`SampleDuration`, AND no `[x2]` count
// suffix); GREEN after. Only the structural `MetaFormat` (stsd 4cc) is excluded.
#[test]
fn camm_dup_warn_g3_timing_before_message_dedup_byte_exact() {
  let excl = ["MetaFormat"];
  check_ee_excluding(
    "QuickTime_camm_dup_warn.mov",
    "QuickTime_camm_dup_warn.mov.ee.json",
    false,
    &excl,
  );
  check_ee_excluding(
    "QuickTime_camm_dup_warn.mov",
    "QuickTime_camm_dup_warn.mov.ee.g3.json",
    true,
    &excl,
  );
}

// The bad-type + empty-payload fixtures at no-`ee`: camm is a `meta`-handler
// `trak`, so the per-sample dispatch is `-ee`-only. The no-`ee` path emits the
// standard `[minor] ExtractEmbedded` warning (mdat sample data is present) and
// NO per-sample record — the same shape as the other camm fixtures. Only the
// structural `MetaFormat` (stsd 4cc) is excluded.
#[test]
fn camm_badtype_emptypayload_noee_warning_byte_exact_except_metaformat() {
  check_noee_excluding(
    "QuickTime_camm_badtype.mov",
    "QuickTime_camm_badtype.mov.json",
    &["MetaFormat"],
  );
  check_noee_excluding(
    "QuickTime_camm_emptypayload.mov",
    "QuickTime_camm_emptypayload.mov.json",
    &["MetaFormat"],
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

// A `mebx` timed sample whose `keys` table resolves MORE THAN ONE record per
// sample (`QuickTime_mebx_keys.mov`: SceneIlluminance + TestFooBar) pins that
// every record of ONE timed sample shares ONE `Doc<N>`. ExifTool calls
// `FoundSomething` ONCE per timed sample (ProcessSamples:1517 → one `++DOC_COUNT`),
// then `Process_mebx` `HandleTag`s ALL records of that sample under the SAME
// `DOC_NUM` (Process_mebx never bumps the doc itself — QuickTimeStream.pl:2644).
// So the `-ee -G3` oracle is `Doc1:Track1:SceneIlluminance` + `Doc1:Track1:TestFooBar`
// (NOT Doc1/Doc2), with a single `Doc1:Track1:SampleTime`/`SampleDuration`. The
// single-key `mebx_gps` fixture above could not catch a per-record doc bump.
#[test]
fn mebx_keys_ee_byte_exact_except_metaformat() {
  let excl = ["MetaFormat"];
  check_ee_excluding(
    "QuickTime_mebx_keys.mov",
    "QuickTime_mebx_keys.mov.ee.json",
    false,
    &excl,
  );
  check_ee_excluding(
    "QuickTime_mebx_keys.mov",
    "QuickTime_mebx_keys.mov.ee.g3.json",
    true,
    &excl,
  );
}

// A `detected-face` `mebx` sample expands to FOUR leaf records
// (DetectedFaceBounds/ID/RollAngle/YawAngle) via the nested `crec`/`cits` MOV
// tree (QuickTime.pm:6808-6828) — all decoded by ONE `Process_mebx` invocation
// for ONE timed sample, so the `-ee -G3` oracle keeps ALL FOUR under `Doc1`
// (one SampleTime). This is the strongest per-timed-sample-doc pin: a per-record
// bump would scatter the four face leaves across Doc1..Doc4.
#[test]
fn mebx_detface_ee_byte_exact_except_metaformat() {
  let excl = ["MetaFormat"];
  check_ee_excluding(
    "QuickTime_mebx_detface.mov",
    "QuickTime_mebx_detface.mov.ee.json",
    false,
    &excl,
  );
  check_ee_excluding(
    "QuickTime_mebx_detface.mov",
    "QuickTime_mebx_detface.mov.ee.g3.json",
    true,
    &excl,
  );
}

// ── No-`ee` faithfulness: the `[minor] ExtractEmbedded` warning ──────────────
//
// Without `-ee`, ExifTool's Handler-box RawConv (QuickTime.pm:8407-8411) raises
// `[minor] The ExtractEmbedded option may find more tags in the media data` —
// scoped to the family-1 group of the FIRST `trak` whose handler type is an
// `%eeBox` member (`meta`/`text`/`sbtl`/`data`/`camm`/`ctbx`; `vide` excluded)
// — and emits NO per-sample GPS. Both `mebx` and `camm` tracks carry the `meta`
// handler, so the oracle shows `Track1:Warning` (between `HandlerClass` and
// `HandlerType`) and no GPS columns. exifast reproduces the warning; the
// structural `MetaFormat` (stsd 4-char code) remains the only unmodeled gap, so
// it is excluded from the comparison (same gap as the `-ee` tests above).

#[test]
fn mebx_gps_noee_warning_byte_exact_except_metaformat() {
  check_noee_excluding(
    "QuickTime_mebx_gps.mov",
    "QuickTime_mebx_gps.mov.json",
    &["MetaFormat"],
  );
}

// The multi-record `mebx` fixtures carry the SAME no-`ee` shape as `mebx_gps`:
// the `meta`-handler `Track1:Warning` and NO per-sample payload (the records
// surface only under `-ee`). Pins that the per-timed-sample doc change does not
// leak any record into the no-`ee` path.
#[test]
fn mebx_keys_noee_warning_byte_exact_except_metaformat() {
  check_noee_excluding(
    "QuickTime_mebx_keys.mov",
    "QuickTime_mebx_keys.mov.json",
    &["MetaFormat"],
  );
}

#[test]
fn mebx_detface_noee_warning_byte_exact_except_metaformat() {
  check_noee_excluding(
    "QuickTime_mebx_detface.mov",
    "QuickTime_mebx_detface.mov.json",
    &["MetaFormat"],
  );
}

#[test]
fn camm_noee_warning_byte_exact_except_metaformat() {
  check_noee_excluding(
    "QuickTime_camm.mov",
    "QuickTime_camm.mov.json",
    &["MetaFormat"],
  );
}

// ── No-`ee` faithfulness: the top-level magic boxes (gps0/gsen/3gf) ──────────
//
// gps0/gsen/3gf are TOP-LEVEL magic boxes ExifTool's `Process_gps0`/`Process_gsen`
// /`Process_3gf` decode during `ProcessMOV` REGARDLESS of `-ee` (QuickTime.pm
// `%QuickTime::Main` `gps0`/`gsen`/`3gf ` SubDirectories, not gated on
// ExtractEmbedded). When such a box holds more than one record ExifTool emits the
// FIRST fix + raises the DOCUMENT-level `[minor] The ExtractEmbedded option may
// find more tags in the media data` (a file-level `ExifTool:Warning`, NOT a
// `Track<N>:Warning` — these boxes are not `trak`s with an `%eeBox` handler).
// exifast reproduces both: the first gps0 fix surfaces at no-`ee` under
// `QuickTime:` plus the file-level warning; the `-ee`-only sources stay gated.

#[test]
fn gps0_noee_first_fix_and_file_warning_byte_exact() {
  // No `MetaFormat` gap: gps0 is a top-level box, not a `trak` sample-description.
  check_noee_excluding("QuickTime_gps0.mov", "QuickTime_gps0.mov.json", &[]);
}

// `QuickTime_gps0_oor0.mov` — the crafted adversarial gps0: PHYSICAL record 0 is
// OUT-OF-RANGE (`lat = 90000.0` ⇒ `abs($lat) > 9000`), record 1 is the VALID
// 33°N/151°E fix. `Process_gps0` (QuickTimeStream.pl:2742-2747) bumps
// `++DOC_COUNT` for record 0 BEFORE the `next if abs($lat) > 9000` skip, and the
// no-`ee` `$dirLen = $recLen` truncation (2738) stops the loop at physical record
// 0. So this fixture pins the three divergence modes the per-PHYSICAL-record fix
// must reproduce (each oracle-pinned against the bundled ExifTool 13.59):
//   - no-`ee`: ONLY the file-level `ExifTool:Warning` (the byte-length truncation
//     still fires) and NO GPS — record 0 is rejected, the loop never reaches
//     record 1.
//   - `-ee -G3`: the valid record-1 fix at `Doc2:` (record 0 consumed Doc1 even
//     though skipped — `++DOC_COUNT` ran before the skip).
//   - `-ee -G1`: the valid record-1 fix collapsed to `QuickTime:` (first-PRESENT
//     wins; record 0 produced no row).
// No `MetaFormat` gap (top-level box).
#[test]
fn gps0_oor_record0_noee_warning_only_byte_exact() {
  check_noee_excluding(
    "QuickTime_gps0_oor0.mov",
    "QuickTime_gps0_oor0.mov.json",
    &[],
  );
}

#[test]
fn gps0_oor_record0_ee_doc2_byte_exact() {
  // -ee -G1: valid record-1 fix collapsed flat (QuickTime:…).
  check_ee(
    "QuickTime_gps0_oor0.mov",
    "QuickTime_gps0_oor0.mov.ee.json",
    false,
  );
  // -ee -G3: valid record-1 fix at Doc2 (record 0 consumed Doc1).
  check_ee(
    "QuickTime_gps0_oor0.mov",
    "QuickTime_gps0_oor0.mov.ee.g3.json",
    true,
  );
}

// gsen is the accelerometer-only analogue: two 3-byte records, so `dirLen (6) >
// recLen (3)` truncates to the FIRST record + raises the file-level
// `ExtractEmbedded` warning at no-`ee`. The oracle (`-j -G1`):
// `ExifTool:Warning` + `QuickTime:Accelerometer "1 -2 3"` (first record only),
// NO `Doc<N>` axis. No `MetaFormat` gap (top-level box).
#[test]
fn gsen_noee_first_record_and_file_warning_byte_exact() {
  check_noee_excluding("QuickTime_gsen.mov", "QuickTime_gsen.mov.json", &[]);
}

// moov-level / scan / Kenwood GPS sources surface NO no-`ee` warning and NO
// no-`ee` GPS (their decoders run only under `ProcessSamples`/`ScanMediaData`,
// QuickTimeStream.pl:2544-2580/3689 — fully `-ee` gated, and no `eeBox` track
// handler is present). exifast already matches; the byte-exact no-`ee` check is
// the standard `.json`/`.n.json` active-conformance pair (see
// `tests/typed_serde_parity.rs`). A redundant assertion here keeps the no-`ee`
// truth co-located with the timed-metadata suite.
#[test]
fn moov_gps_kenwood_frea_noee_no_warning_no_gps() {
  for (fix, gold) in [
    ("QuickTime_moov_gps.mov", "QuickTime_moov_gps.mov.json"),
    (
      "QuickTime_gps_kenwood.mov",
      "QuickTime_gps_kenwood.mov.json",
    ),
    (
      "QuickTime_frea_rexing17b.mov",
      "QuickTime_frea_rexing17b.mov.json",
    ),
  ] {
    check_noee_excluding(fix, gold, &[]);
  }
}

// ── Cross-struct / multi-track GLOBAL `$$et{DOC_COUNT}` (issue #214) ──────────
//
// The single-source fixtures above cannot reach the case where MORE THAN ONE
// timed-metadata source / track contributes to ONE file: ExifTool numbers every
// embedded sample off ONE running `$$et{DOC_COUNT}` shared across ALL sources in
// WALK order (a trak's samples get their `Doc<N>` as that trak is processed;
// magic boxes inline; the freeGPS `mdat` scan last). exifast keeps the per-source
// timed samples in SEPARATE structs (`QuickTimeStreamMeta` for `mebx`/the SP3
// magic boxes, `CammMeta` for `camm`), so the global ordinal must be threaded
// through a single shared counter; the `-ee -G3:1` `Doc<N>` numbers below pin
// that. The `-ee -G1` checks pin the GROUP-AWARE collapse — distinct family-1
// `Track<N>` rows of the SAME tag name must BOTH survive (a name-only `%noDups`
// collapse would drop the later track's value).

// `QuickTime_camm_2track.mov` — two `camm` `trak`s (Track1: 2 fixes, Track2: 1).
// The GLOBAL doc counter spans the tracks: `-ee -G3` ⇒ `Doc1:Track1` /
// `Doc2:Track1` / `Doc3:Track2` (Track2's fix continues the ordinal, NOT a
// colliding `Doc1`). `-ee -G1` ⇒ BOTH `Track1:GPSLatitude` and
// `Track2:GPSLatitude` survive (group-aware first-wins collapse). `SampleTime`/
// `SampleDuration` ARE emitted per camm SAMPLE (each `Doc<N>` carries its own
// timing) and compared; only `MetaFormat` (the `stsd` 4-char code) is excluded.
#[test]
fn camm_2track_ee_global_doc_byte_exact() {
  let excl = ["MetaFormat"];
  check_ee_excluding(
    "QuickTime_camm_2track.mov",
    "QuickTime_camm_2track.mov.ee.json",
    false,
    &excl,
  );
  check_ee_excluding(
    "QuickTime_camm_2track.mov",
    "QuickTime_camm_2track.mov.ee.g3.json",
    true,
    &excl,
  );
}

// `QuickTime_mebx_camm.mov` — a `mebx` `trak` (Track1) FOLLOWED by a `camm`
// `trak` (Track2: 2 fixes). The crux cross-STRUCT pin: the `mebx` sample opens
// `Doc1` (in `QuickTimeStreamMeta`), and the two camm fixes CONTINUE the same
// global ordinal as `Doc2`/`Doc3` (in `CammMeta`) — proving the counter is shared
// across the two structs IN WALK ORDER (mebx trak walked before camm trak). At
// `-ee -G1` the mebx and camm tags occupy distinct `Track1`/`Track2` groups and
// all survive. `SampleTime`/`SampleDuration` are emitted for BOTH the mebx and
// the camm samples (each carries its sample-table timing) and compared; only the
// structural `MetaFormat` is excluded.
#[test]
fn mebx_camm_ee_cross_struct_global_doc_byte_exact() {
  let excl = ["MetaFormat"];
  check_ee_excluding(
    "QuickTime_mebx_camm.mov",
    "QuickTime_mebx_camm.mov.ee.json",
    false,
    &excl,
  );
  check_ee_excluding(
    "QuickTime_mebx_camm.mov",
    "QuickTime_mebx_camm.mov.ee.g3.json",
    true,
    &excl,
  );
}

// `QuickTime_mebx_2track.mov` — two `mebx` `trak`s emitting the SAME key name
// (`SceneIlluminance`). `-ee -G3` ⇒ `Doc1:Track1:SceneIlluminance` (1234) /
// `Doc2:Track2:SceneIlluminance` (5678) — the global doc spans the two tracks.
// `-ee -G1` ⇒ BOTH `Track1:SceneIlluminance` AND `Track2:SceneIlluminance`
// survive: a name-only collapse would drop Track2's value, so this is the
// strongest pin that the mebx `-G1` `%noDups` collapse is GROUP-AWARE
// (`(family1, name)`-keyed). Only the structural `MetaFormat` is excluded; the
// mebx `SampleTime`/`SampleDuration` ARE emitted and compared.
#[test]
fn mebx_2track_ee_global_doc_and_group_aware_collapse_byte_exact() {
  let excl = ["MetaFormat"];
  check_ee_excluding(
    "QuickTime_mebx_2track.mov",
    "QuickTime_mebx_2track.mov.ee.json",
    false,
    &excl,
  );
  check_ee_excluding(
    "QuickTime_mebx_2track.mov",
    "QuickTime_mebx_2track.mov.ee.g3.json",
    true,
    &excl,
  );
}

// The cross-struct / multi-track fixtures carry the SAME no-`ee` shape as the
// single-source `mebx`/`camm` fixtures: a `meta`-handler `Track1:Warning` and NO
// per-sample payload (the records surface only under `-ee`). Pins that the
// global-doc threading does not leak any record into the no-`ee` path.
#[test]
fn cross_struct_noee_warning_byte_exact_except_metaformat() {
  for (fix, gold) in [
    (
      "QuickTime_camm_2track.mov",
      "QuickTime_camm_2track.mov.json",
    ),
    ("QuickTime_mebx_camm.mov", "QuickTime_mebx_camm.mov.json"),
    (
      "QuickTime_mebx_2track.mov",
      "QuickTime_mebx_2track.mov.json",
    ),
  ] {
    check_noee_excluding(fix, gold, &["MetaFormat"]);
  }
}
