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
//! ## Full structural coverage (no excluded tags)
//!
//! Every emitted tag — including the structural `Track<N>:MetaFormat` — is now
//! compared byte-exact; NOTHING is excluded.
//!
//! - `Track<N>:MetaFormat` — the `stsd` sample-description 4-char format code
//!   (`"rtmd"`/`"camm"`/`"mebx"`). The structural QuickTime trak parse now
//!   descends `mdia/minf/stbl/stsd` and pulls the format 4cc onto the
//!   `MediaTrack`; the emission surfaces it at the family-1 `Track<N>` level
//!   (right after `HandlerType`), gated on the `meta` handler — exactly
//!   ExifTool's `MetaSampleDesc` `MetaFormat` (QuickTime.pm:7393, `Condition =>
//!   '$$self{HandlerType} eq "meta"'`). Implemented subsystem-wide in R13;
//!   resolves issue #212.
//!
//! `Track<N>:SampleTime` / `Track<N>:SampleDuration` — the `ProcessSamples`
//! sample-table timing emitted ahead of each decoded sample's payload — are also
//! compared byte-exact for BOTH **camm** and **mebx** (each timed sample carries
//! its `SampleTime`/`SampleDuration` off the `stts`/`stsz` tables, threaded onto
//! the camm GPS / motion / warning records of that sample).
#![cfg(all(feature = "quicktime", feature = "json"))]

use exifast::ParseOptions;
use exifast::jsondiff::json_equivalent_strict;
use exifast::parser::extract_info_with_options;

/// No exclusions — every key (including `Track<N>:MetaFormat`, now emitted) is
/// compared byte-exact. Retained as a named constant so the `*_excluding` call
/// sites read clearly after the `MetaFormat` gap was closed (R13).
const NO_EXCL: &[&str] = &[];

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
// sample-table timing threaded onto each sample's records) and compared; every
// tag (incl. `Track<N>:MetaFormat`, the stsd 4cc, #212) is compared byte-exact.

#[test]
fn camm_ee_byte_exact_gps_columns() {
  // Every tag — incl. the structural `Track<N>:MetaFormat` (the stsd 4cc, #212)
  // and the sample-table `SampleTime`/`SampleDuration` — is emitted and compared
  // byte-exact.
  check_ee_excluding(
    "QuickTime_camm.mov",
    "QuickTime_camm.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_camm.mov",
    "QuickTime_camm.mov.ee.g3.json",
    true,
    NO_EXCL,
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
// compared; every emitted tag (incl. `Track<N>:MetaFormat`) is compared byte-exact.
#[test]
fn camm_motion_ee_byte_exact() {
  check_ee_excluding(
    "QuickTime_camm_motion.mov",
    "QuickTime_camm_motion.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_camm_motion.mov",
    "QuickTime_camm_motion.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

// The motion-only fixture at no-`ee`: camm is a `meta`-handler `trak`, so it is
// fully `-ee`-gated — the only surfaced tag is the `Track1:Warning` ([minor]
// ExtractEmbedded), NOT any motion record. Pins that the new motion emission is
// `-ee`-only (same gate as the GPS camm), so a no-`ee` parse leaks nothing.
#[test]
fn camm_motion_noee_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_camm_motion.mov",
    "QuickTime_camm_motion.mov.json",
    NO_EXCL,
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
// sample's timing once, even though it has two packets) and compared; every tag
// (incl. `Track<N>:MetaFormat`) is compared byte-exact.
#[test]
fn camm_multipkt_within_doc_last_wins_byte_exact() {
  check_ee_excluding(
    "QuickTime_camm_multipkt.mov",
    "QuickTime_camm_multipkt.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_camm_multipkt.mov",
    "QuickTime_camm_multipkt.mov.ee.g3.json",
    true,
    NO_EXCL,
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
// gate: Doc1 keeps "0 s"+Warning and Doc2 keeps "1.00 s"+GPS. Every tag (incl.
// `Track<N>:MetaFormat`) is compared byte-exact.
#[test]
fn camm_warn_gps_mixed_track_sample_time_first_wins_byte_exact() {
  check_ee_excluding(
    "QuickTime_camm_warn_gps.mov",
    "QuickTime_camm_warn_gps.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_camm_warn_gps.mov",
    "QuickTime_camm_warn_gps.mov.ee.g3.json",
    true,
    NO_EXCL,
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
// structural `Track<N>:MetaFormat` (the stsd 4cc) is now compared byte-exact.
#[test]
fn camm_gps_warn_reverse_order_min_doc_sample_time_byte_exact() {
  check_ee_excluding(
    "QuickTime_camm_gps_warn.mov",
    "QuickTime_camm_gps_warn.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_camm_gps_warn.mov",
    "QuickTime_camm_gps_warn.mov.ee.g3.json",
    true,
    NO_EXCL,
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
// every emitted tag (incl. `Track<N>:MetaFormat`) is compared byte-exact.
#[test]
fn camm_motion_gps_reverse_order_min_doc_sample_time_byte_exact() {
  check_ee_excluding(
    "QuickTime_camm_motion_gps.mov",
    "QuickTime_camm_motion_gps.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_camm_motion_gps.mov",
    "QuickTime_camm_motion_gps.mov.ee.g3.json",
    true,
    NO_EXCL,
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
// `Track<N>:MetaFormat` (the stsd 4cc) is now compared byte-exact.
#[test]
fn camm0_unknown_record_dispatches_and_warns_byte_exact() {
  check_ee_excluding(
    "QuickTime_camm0.mov",
    "QuickTime_camm0.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_camm0.mov",
    "QuickTime_camm0.mov.ee.g3.json",
    true,
    NO_EXCL,
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
// not on the decode succeeding). every emitted tag (incl. `Track<N>:MetaFormat`) is compared byte-exact.
#[test]
fn camm_trunc_recognized_first_packet_dispatches_and_warns_byte_exact() {
  check_ee_excluding(
    "QuickTime_camm_trunc.mov",
    "QuickTime_camm_trunc.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_camm_trunc.mov",
    "QuickTime_camm_trunc.mov.ee.g3.json",
    true,
    NO_EXCL,
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
// `Track<N>:MetaFormat` (the stsd 4cc) is now compared byte-exact.
#[test]
fn camm_badtype_first_packet_out_of_range_emits_nothing_byte_exact() {
  check_ee_excluding(
    "QuickTime_camm_badtype.mov",
    "QuickTime_camm_badtype.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_camm_badtype.mov",
    "QuickTime_camm_badtype.mov.ee.g3.json",
    true,
    NO_EXCL,
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
// timing); GREEN after. every emitted tag (incl. `Track<N>:MetaFormat`) is compared byte-exact.
#[test]
fn camm_emptypayload_recognized_first_packet_emits_timing_only_byte_exact() {
  check_ee_excluding(
    "QuickTime_camm_emptypayload.mov",
    "QuickTime_camm_emptypayload.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_camm_emptypayload.mov",
    "QuickTime_camm_emptypayload.mov.ee.g3.json",
    true,
    NO_EXCL,
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
// suffix); GREEN after. every emitted tag (incl. `Track<N>:MetaFormat`) is compared byte-exact.
#[test]
fn camm_dup_warn_g3_timing_before_message_dedup_byte_exact() {
  check_ee_excluding(
    "QuickTime_camm_dup_warn.mov",
    "QuickTime_camm_dup_warn.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_camm_dup_warn.mov",
    "QuickTime_camm_dup_warn.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

// The bad-type + empty-payload fixtures at no-`ee`: camm is a `meta`-handler
// `trak`, so the per-sample dispatch is `-ee`-only. The no-`ee` path emits the
// standard `[minor] ExtractEmbedded` warning (mdat sample data is present) and
// NO per-sample record — the same shape as the other camm fixtures. Only the
// structural `Track<N>:MetaFormat` (the stsd 4cc) is now compared byte-exact.
#[test]
fn camm_badtype_emptypayload_noee_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_camm_badtype.mov",
    "QuickTime_camm_badtype.mov.json",
    NO_EXCL,
  );
  check_noee_excluding(
    "QuickTime_camm_emptypayload.mov",
    "QuickTime_camm_emptypayload.mov.json",
    NO_EXCL,
  );
}

// ── Track<N>: mebx (Apple metadata keys — per-sample Track<N>, with timing) ──
// SampleTime / SampleDuration ARE emitted (the mebx sample carries timing), and
// the structural `Track<N>:MetaFormat` (stsd `mebx` 4cc) is now emitted +
// compared too — every tag is byte-exact.

#[test]
fn mebx_gps_ee_byte_exact() {
  check_ee_excluding(
    "QuickTime_mebx_gps.mov",
    "QuickTime_mebx_gps.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_mebx_gps.mov",
    "QuickTime_mebx_gps.mov.ee.g3.json",
    true,
    NO_EXCL,
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
fn mebx_keys_ee_byte_exact() {
  check_ee_excluding(
    "QuickTime_mebx_keys.mov",
    "QuickTime_mebx_keys.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_mebx_keys.mov",
    "QuickTime_mebx_keys.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

// A `detected-face` `mebx` sample expands to FOUR leaf records
// (DetectedFaceBounds/ID/RollAngle/YawAngle) via the nested `crec`/`cits` MOV
// tree (QuickTime.pm:6808-6828) — all decoded by ONE `Process_mebx` invocation
// for ONE timed sample, so the `-ee -G3` oracle keeps ALL FOUR under `Doc1`
// (one SampleTime). This is the strongest per-timed-sample-doc pin: a per-record
// bump would scatter the four face leaves across Doc1..Doc4.
#[test]
fn mebx_detface_ee_byte_exact() {
  check_ee_excluding(
    "QuickTime_mebx_detface.mov",
    "QuickTime_mebx_detface.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_mebx_detface.mov",
    "QuickTime_mebx_detface.mov.ee.g3.json",
    true,
    NO_EXCL,
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
// `HandlerType`) and no GPS columns. exifast reproduces the warning AND the
// structural `Track<N>:MetaFormat` (stsd 4-char code), so every tag is compared
// byte-exact (no exclusion — same as the `-ee` tests above).

#[test]
fn mebx_gps_noee_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_mebx_gps.mov",
    "QuickTime_mebx_gps.mov.json",
    NO_EXCL,
  );
}

// The multi-record `mebx` fixtures carry the SAME no-`ee` shape as `mebx_gps`:
// the `meta`-handler `Track1:Warning` and NO per-sample payload (the records
// surface only under `-ee`). Pins that the per-timed-sample doc change does not
// leak any record into the no-`ee` path.
#[test]
fn mebx_keys_noee_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_mebx_keys.mov",
    "QuickTime_mebx_keys.mov.json",
    NO_EXCL,
  );
}

#[test]
fn mebx_detface_noee_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_mebx_detface.mov",
    "QuickTime_mebx_detface.mov.json",
    NO_EXCL,
  );
}

// ── Track<N>: Sony rtmd (Sony Alpha/FX "Real-Time MetaData" — per-sample
// Track<N>, camera + GPS, with timing) ───────────────────────────────────────
// `Process_rtmd` (Sony.pm:11569-11602) decodes one timed sample per `rtmd`
// sample, each its own `Doc<N>` under the enclosing `Track<N>`. The fixture
// carries 2 samples: Doc1 = camera + a full `0x85xx` GPS fix (ISO 800), Doc2 =
// camera-only (ISO 1600). The `-ee -G3:1` oracle keeps both as
// `Doc1:Track1:*` / `Doc2:Track1:*`; `-ee -G1` collapses to the first-wins
// `Track1:*` row per name (Doc1's camera scalars + its GPS family win; Doc2's
// differing ISO is dropped). The camera scalars carry their Sony.pm PrintConvs
// at `-j` (FNumber `PrintFNumber`, FrameRate `%.2f`, ExposureTime
// `PrintExposureTime`, MasterGainAdjustment `%.2f dB`, WhiteBalance the
// `0xe303` map → `Unknown (0)`); the GPS family carries the GPS.pm ref/status/
// measure-mode PrintConvs + `GPS::ToDMS` lat/lon. SampleTime/SampleDuration ARE
// emitted (the rtmd sample carries the sample-table timing); only the
// structural `Track<N>:MetaFormat` (the stsd rtmd 4cc) is now compared byte-exact.

#[test]
fn sony_rtmd_ee_byte_exact() {
  check_ee_excluding(
    "QuickTime_sony_rtmd.mov",
    "QuickTime_sony_rtmd.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_sony_rtmd.mov",
    "QuickTime_sony_rtmd.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

// End-to-end `-ee -G1 -n` (ValueConv) check for the rational64u FrameRate /
// ExposureTime and the fractional GPSTimeStamp.
// The conformance `.ee.*` goldens are `-j` only, so this pins the `-n` path
// the harness never reaches. Oracle (bundled ExifTool 13.59
// `-ee -j -G1 -n QuickTime_sony_rtmd.mov`): `Track1:FrameRate 29.97002997`
// (the rational `%g` form, NOT the 15-digit f64 `29.97002997002997`) and
// `Track1:ExposureTime 0.01666666667`; and for the fractsec fixture
// `Track1:GPSTimeStamp "01:02:03.123456789"` (the full 9-digit ValueConv form,
// unrounded at `-n`).
#[test]
fn sony_rtmd_ee_n_rational64u_and_gps_timestamp_match_bundled() {
  // FrameRate / ExposureTime `-n` on the base fixture.
  let data = fixture("QuickTime_sony_rtmd.mov");
  let opts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(false);
  let got = extract_info_with_options("QuickTime_sony_rtmd.mov", &data, false, opts);
  let v: serde_json::Value = serde_json::from_str(&got).expect("valid JSON");
  let obj = v.as_array().and_then(|a| a.first()).expect("one object");
  // Rational renders as a bare JSON NUMBER equal to the bundled `%.10g` value.
  assert_eq!(
    obj.get("Track1:FrameRate"),
    Some(&serde_json::json!(29.97002997)),
    "FrameRate -n must be the rational %g value, not the 15-digit f64"
  );
  assert_eq!(
    obj.get("Track1:ExposureTime"),
    Some(&serde_json::json!(0.01666666667)),
  );

  // GPSTimeStamp `-n` on the fractional fixture: the full unrounded string.
  let fdata = fixture("QuickTime_sony_rtmd_fractsec.mov");
  let fopts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(false);
  let fgot = extract_info_with_options("QuickTime_sony_rtmd_fractsec.mov", &fdata, false, fopts);
  let fv: serde_json::Value = serde_json::from_str(&fgot).expect("valid JSON");
  let fobj = fv.as_array().and_then(|a| a.first()).expect("one object");
  assert_eq!(
    fobj.get("Track1:GPSTimeStamp"),
    Some(&serde_json::json!("01:02:03.123456789")),
    "GPSTimeStamp -n must be the unrounded 9-digit ConvertTimeStamp form"
  );

  // GPSLatitude/GPSLongitude `-n` on the non-decimal-denominator COORDINATE
  // fixture: each D/M/S `rational64u` is `GetRational64u`-rounded (RoundFloat
  // 10) BEFORE `GPS::ToDegrees` sums `D + M/60 + S/3600`. Seconds = 1/3 (lat)
  // and 2/3 (lon) must round to `0.3333333333`/`0.6666666667` first, so the
  // `-n` coordinate is the bundled value, not a raw 15-digit f64 divide.
  let cdata = fixture("QuickTime_sony_rtmd_coordround.mov");
  let copts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(false);
  let cgot = extract_info_with_options("QuickTime_sony_rtmd_coordround.mov", &cdata, false, copts);
  let cv: serde_json::Value = serde_json::from_str(&cgot).expect("valid JSON");
  let cobj = cv.as_array().and_then(|a| a.first()).expect("one object");
  assert_eq!(
    cobj.get("Track1:GPSLatitude"),
    Some(&serde_json::json!(47.6167592592592)),
    "GPSLatitude -n must round each rational64u component to 10 sig-figs before ToDegrees"
  );
  assert_eq!(
    cobj.get("Track1:GPSLongitude"),
    Some(&serde_json::json!(122.150185185185)),
  );
}

// The Sony rtmd fixture at no-`ee`: `rtmd` is a `meta`-handler `trak`, so the
// per-sample camera/GPS emission is fully `-ee`-gated. The no-`ee` path emits
// the standard `Track1:Warning` ([minor] ExtractEmbedded) and NO per-sample
// record — the same shape as the `mebx`/`camm` fixtures. Only the structural
// `Track<N>:MetaFormat` (the stsd rtmd 4cc) is now compared byte-exact.
#[test]
fn sony_rtmd_noee_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_sony_rtmd.mov",
    "QuickTime_sony_rtmd.mov.json",
    NO_EXCL,
  );
}

// The Sony rtmd FRACTIONAL-seconds GPSTimeStamp fixture. The
// `0x8507` GPSTimeStamp encodes S = 3.123456789 (rational 3123456789/1e9), so
// `ConvertTimeStamp` (the `-n`/ValueConv form) yields `01:02:03.123456789` and
// `PrintTimeStamp` (the `-j`/PrintConv) ROUNDS to microseconds:
// `01:02:03.123457`. The `.ee.json`/`.ee.g3.json` goldens are `-j`, so they pin
// the 6-digit-rounded form — exifast must match byte-exact. Only the structural
// `Track<N>:MetaFormat` (the stsd rtmd 4cc) is now compared byte-exact.
#[test]
fn sony_rtmd_fractsec_ee_byte_exact() {
  check_ee_excluding(
    "QuickTime_sony_rtmd_fractsec.mov",
    "QuickTime_sony_rtmd_fractsec.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_sony_rtmd_fractsec.mov",
    "QuickTime_sony_rtmd_fractsec.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

#[test]
fn sony_rtmd_fractsec_noee_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_sony_rtmd_fractsec.mov",
    "QuickTime_sony_rtmd_fractsec.mov.json",
    NO_EXCL,
  );
}

// The Sony rtmd SHORT-SAMPLE timing-Doc fixture. Sample 0 is a
// single byte (`< 2`), which `Process_rtmd` `return 0`s SILENTLY — but
// `ProcessSamples` already opened `Doc1` and emitted its SampleTime/
// SampleDuration, so the timing row must survive. The normal sample 1 becomes
// `Doc2`. So `-ee -G3:1` shows `Doc1:Track1:SampleTime/SampleDuration` (timing
// only) then the full `Doc2:Track1:…`; `-ee -G1` collapses with the Doc1 timing
// winning (first-wins). exifast pushes an empty sample for the `< 2`-byte case
// so the dispatcher stamps that timing-only doc. every tag (incl. `Track<N>:MetaFormat`) is compared byte-exact.
#[test]
fn sony_rtmd_shortsample_ee_byte_exact() {
  check_ee_excluding(
    "QuickTime_sony_rtmd_shortsample.mov",
    "QuickTime_sony_rtmd_shortsample.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_sony_rtmd_shortsample.mov",
    "QuickTime_sony_rtmd_shortsample.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

#[test]
fn sony_rtmd_shortsample_noee_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_sony_rtmd_shortsample.mov",
    "QuickTime_sony_rtmd_shortsample.mov.json",
    NO_EXCL,
  );
}

// The Sony rtmd ZERO-DENOMINATOR FrameRate/ExposureTime fixture.
// `0x8106 FrameRate` (`sprintf("%.2f",$val)`) and `0x8109
// ExposureTime` (`PrintExposureTime`) read `rational64u`; a zero denominator
// makes `GetRational64u` yield the WORD `"undef"` (0/0) or `"inf"` (n/0).
// Sample 0 = 0/0 → `-j` FrameRate `0.00` (numified) + ExposureTime `"undef"`;
// sample 1 = n/0 → `-j` FrameRate `"Inf"` + ExposureTime `"inf"`. The `-G3:1`
// golden carries both Docs; `-G1` first-wins keeps Doc1. The earlier-NaN bug
// is gone (the `-j` path no longer formats a non-finite quotient). Only the
// structural `Track<N>:MetaFormat` (the stsd rtmd 4cc) is now compared byte-exact.
#[test]
fn sony_rtmd_zerodenom_ee_byte_exact() {
  check_ee_excluding(
    "QuickTime_sony_rtmd_zerodenom.mov",
    "QuickTime_sony_rtmd_zerodenom.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_sony_rtmd_zerodenom.mov",
    "QuickTime_sony_rtmd_zerodenom.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

#[test]
fn sony_rtmd_zerodenom_noee_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_sony_rtmd_zerodenom.mov",
    "QuickTime_sony_rtmd_zerodenom.mov.json",
    NO_EXCL,
  );
}

// The Sony rtmd NON-DECIMAL-DENOMINATOR GPSTimeStamp fixture.
// `0x8507` seconds = 1496725904/123456789 (= 12.1234799327…); ExifTool
// `GetRational64u`-rounds each H/M/S component to 10 sig-figs BEFORE
// `ConvertTimeStamp`, so the `-n`/ValueConv value is `12:00:12.12347993` (NOT
// the 11-digit raw quotient) and `PrintTimeStamp` rounds it to `12:00:12.12348`
// at `-j`. The `.ee.*` goldens are `-j`, pinning the 5-digit-rounded form; the
// `-n` value is pinned separately below. every tag (incl. `Track<N>:MetaFormat`) is compared byte-exact.
#[test]
fn sony_rtmd_gpsts_round_ee_byte_exact() {
  check_ee_excluding(
    "QuickTime_sony_rtmd_gpsts_round.mov",
    "QuickTime_sony_rtmd_gpsts_round.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_sony_rtmd_gpsts_round.mov",
    "QuickTime_sony_rtmd_gpsts_round.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

#[test]
fn sony_rtmd_gpsts_round_noee_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_sony_rtmd_gpsts_round.mov",
    "QuickTime_sony_rtmd_gpsts_round.mov.json",
    NO_EXCL,
  );
}

// The Sony rtmd NON-DECIMAL-DENOMINATOR GPS COORDINATE fixture.
// `0x8502 GPSLatitude` / `0x8504 GPSLongitude` each read three `rational64u`
// (D,M,S) THROUGH `GetRational64u` (RoundFloat-10 per component) BEFORE
// `GPS::ToDegrees` sums `D + M/60 + S/3600`. Seconds = 1/3 (lat) / 2/3 (lon)
// round to `0.3333333333`/`0.6666666667` first, so the `-j`/`GPS::ToDMS`
// PrintConv renders `47 deg 37' 0.33"` / `122 deg 9' 0.67"` (the `-n` decimal
// is pinned in `sony_rtmd_ee_n_rational64u_and_gps_timestamp_match_bundled`).
// The `.ee.*` goldens are `-j`; exifast must match byte-exact. Only the
// structural `Track<N>:MetaFormat` (the stsd rtmd 4cc) is now compared byte-exact.
#[test]
fn sony_rtmd_coordround_ee_byte_exact() {
  check_ee_excluding(
    "QuickTime_sony_rtmd_coordround.mov",
    "QuickTime_sony_rtmd_coordround.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_sony_rtmd_coordround.mov",
    "QuickTime_sony_rtmd_coordround.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

#[test]
fn sony_rtmd_coordround_noee_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_sony_rtmd_coordround.mov",
    "QuickTime_sony_rtmd_coordround.mov.json",
    NO_EXCL,
  );
}

// The Sony rtmd ZERO-DENOMINATOR GPS COORDINATE fixture. The `0x8502
// GPSLatitude` seconds = 423/0 renders the WORD `"inf"` via `GetRational64u`,
// and `GPS::ToDegrees` (GPS.pm:585) `return ''` yields the EMPTY STRING `""` (a
// DEFINED value) for any `\b(inf|undef)\b` component. exifast now emits that
// `""` BYTE-EXACT (a present `SonyRtmdCoord::Empty` → `Str("")` at both `-j`/
// `-n`), so `GPSLatitude` is NO LONGER excluded — only the structural
// `MetaFormat` (stsd 4cc) remains. The surviving GPSLongitude (a normal
// 122/9/54 fix) also matches, proving the inf component renders ONLY its own
// coordinate empty, not the whole GPS record.
#[test]
fn sony_rtmd_coordzero_ee_byte_exact() {
  check_ee_excluding(
    "QuickTime_sony_rtmd_coordzero.mov",
    "QuickTime_sony_rtmd_coordzero.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_sony_rtmd_coordzero.mov",
    "QuickTime_sony_rtmd_coordzero.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

#[test]
fn sony_rtmd_coordzero_noee_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_sony_rtmd_coordzero.mov",
    "QuickTime_sony_rtmd_coordzero.mov.json",
    NO_EXCL,
  );
}

// The Sony rtmd NON-FINITE (n/0) GPSTimeStamp fixture. The `0x8507` seconds =
// 423/0 renders the WORD `"inf"` via `GetRational64u`; unlike `GPS::ToDegrees`
// (which guards inf/undef), `GPS::ConvertTimeStamp` has NO such guard, so its
// arithmetic + string interpolation emit the CONSTANT bogus string
// `"Inf:NaN:000000000NaN"` (the same for an inf in ANY H/M/S position).
// exifast now emits that constant verbatim BYTE-EXACT (at both `-j`/`-n`), so
// `GPSTimeStamp` (like every tag, incl. `Track<N>:MetaFormat`) is compared
// byte-exact. The valid GPSLatitude/GPSLongitude (a normal 47/37/42.3 + 122/9/54
// fix) also match, proving the inf SECONDS poisons ONLY the timestamp.
#[test]
fn sony_rtmd_gpsts_inf_ee_byte_exact() {
  check_ee_excluding(
    "QuickTime_sony_rtmd_gpsts_inf.mov",
    "QuickTime_sony_rtmd_gpsts_inf.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_sony_rtmd_gpsts_inf.mov",
    "QuickTime_sony_rtmd_gpsts_inf.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

#[test]
fn sony_rtmd_gpsts_inf_noee_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_sony_rtmd_gpsts_inf.mov",
    "QuickTime_sony_rtmd_gpsts_inf.mov.json",
    NO_EXCL,
  );
}

// The Sony rtmd PARTIAL-GPS fixture. `0x8502 GPSLatitude` /
// `0x8504 GPSLongitude` / `0x8507 GPSTimeStamp` are `Format => 'rational64u'`
// with NO Count, so `ReadValue` derives the component count from the RECORD
// SIZE: a 1-component (8-byte) or 2-component (16-byte) record is valid and
// `GPS::ToDegrees`/`ConvertTimeStamp` default the missing minute/second to 0.
// The fixture's 8-byte GPSLatitude (`"12/1"` → `12`), 16-byte GPSLongitude
// (`"122/1 30/1"` → `122.5`) and 8-byte GPSTimeStamp (`"12/1"` → `12:00:00`)
// MUST decode byte-exact (the old `< 24` guard dropped them). EVERYTHING is
// byte-exact; every emitted tag (incl. `Track<N>:MetaFormat`) is compared byte-exact.
#[test]
fn sony_rtmd_partialgps_ee_byte_exact() {
  check_ee_excluding(
    "QuickTime_sony_rtmd_partialgps.mov",
    "QuickTime_sony_rtmd_partialgps.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_sony_rtmd_partialgps.mov",
    "QuickTime_sony_rtmd_partialgps.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

#[test]
fn sony_rtmd_partialgps_noee_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_sony_rtmd_partialgps.mov",
    "QuickTime_sony_rtmd_partialgps.mov.json",
    NO_EXCL,
  );
}

// The Sony rtmd NON-FINITE-BY-POSITION fixture. A PRESENT
// GPSLatitude/GPSLongitude record always yields a DEFINED tag — the decimal
// (all-finite) OR `""` (`GPS::ToDegrees` GPS.pm:585, for ANY inf/undef
// component in ANY D/M/S position); a GPSTimeStamp with an inf component (ANY
// H/M/S position) emits the CONSTANT `"Inf:NaN:000000000NaN"`. Three Docs sweep
// the positions: Doc1 (lat inf@D, lon undef@M, time inf@H), Doc2 (lat inf@M,
// lon inf@S, time inf@M), Doc3 (a VALID coord pair + time inf@S). Under `-G1`
// Doc1's EMPTY GPSLatitude/GPSLongitude `""` WIN over Doc3's valid DMS (bundled
// first-extracted-wins); under `-G3:1` each Doc keeps its own. exifast emits all
// of these BYTE-EXACT — every emitted tag (incl. `Track<N>:MetaFormat`) is compared byte-exact.
#[test]
fn sony_rtmd_nonfinite_ee_byte_exact() {
  check_ee_excluding(
    "QuickTime_sony_rtmd_nonfinite.mov",
    "QuickTime_sony_rtmd_nonfinite.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_sony_rtmd_nonfinite.mov",
    "QuickTime_sony_rtmd_nonfinite.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

#[test]
fn sony_rtmd_nonfinite_noee_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_sony_rtmd_nonfinite.mov",
    "QuickTime_sony_rtmd_nonfinite.mov.json",
    NO_EXCL,
  );
}

// `-ee -G3:1 -n` (ValueConv) for the NON-FINITE-BY-POSITION fixture — the
// `.ee.*` `-j` goldens render the `ToDMS` PrintConv, so this pins the raw
// post-ValueConv scalars per Doc/position: every Empty coordinate (inf/undef in
// ANY of D/M/S) is the empty string `""`, every inf-component timestamp (ANY of
// H/M/S) is the constant `"Inf:NaN:000000000NaN"`, and Doc3's VALID coordinate
// pair surfaces its `-n` decimals (47.628…/122.165) — proving the Empty/bogus
// values never poison a real fix. Oracle: bundled ExifTool 13.59.
#[test]
fn sony_rtmd_nonfinite_n_by_position_match_bundled() {
  let data = fixture("QuickTime_sony_rtmd_nonfinite.mov");
  let opts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(true);
  let got = extract_info_with_options("QuickTime_sony_rtmd_nonfinite.mov", &data, false, opts);
  let v: serde_json::Value = serde_json::from_str(&got).expect("valid JSON");
  let obj = v.as_array().and_then(|a| a.first()).expect("one object");
  let empty = serde_json::json!("");
  let bogus = serde_json::json!("Inf:NaN:000000000NaN");
  // Doc1: lat inf@D, lon undef@M, time inf@H.
  assert_eq!(
    obj.get("Doc1:Track1:GPSLatitude"),
    Some(&empty),
    "inf@D lat"
  );
  assert_eq!(
    obj.get("Doc1:Track1:GPSLongitude"),
    Some(&empty),
    "undef@M lon"
  );
  assert_eq!(
    obj.get("Doc1:Track1:GPSTimeStamp"),
    Some(&bogus),
    "inf@H ts"
  );
  // Doc2: lat inf@M, lon inf@S, time inf@M.
  assert_eq!(
    obj.get("Doc2:Track1:GPSLatitude"),
    Some(&empty),
    "inf@M lat"
  );
  assert_eq!(
    obj.get("Doc2:Track1:GPSLongitude"),
    Some(&empty),
    "inf@S lon"
  );
  assert_eq!(
    obj.get("Doc2:Track1:GPSTimeStamp"),
    Some(&bogus),
    "inf@M ts"
  );
  // Doc3: a VALID coordinate pair (-n decimals) + time inf@S.
  assert_eq!(
    obj.get("Doc3:Track1:GPSLatitude"),
    Some(&serde_json::json!(47.6284166666667)),
    "Doc3 valid latitude -n decimal"
  );
  assert_eq!(
    obj.get("Doc3:Track1:GPSLongitude"),
    Some(&serde_json::json!(122.165)),
    "Doc3 valid longitude -n decimal"
  );
  assert_eq!(
    obj.get("Doc3:Track1:GPSTimeStamp"),
    Some(&bogus),
    "inf@S ts"
  );
}

// End-to-end `-ee -G1 -n` (ValueConv) for the partial GPS rationals — the
// `.ee.*` `-j` goldens render the `ToDMS` PrintConv, so this pins the raw
// post-ValueConv scalars: an 8-byte `"12/1"` GPSLatitude → `12`, a 16-byte
// `"122/1 30/1"` GPSLongitude → `122.5`, an 8-byte `"12/1"` GPSTimeStamp →
// `"12:00:00"`. Oracle: bundled ExifTool 13.59.
#[test]
fn sony_rtmd_partialgps_n_match_bundled() {
  let data = fixture("QuickTime_sony_rtmd_partialgps.mov");
  let opts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(false);
  let got = extract_info_with_options("QuickTime_sony_rtmd_partialgps.mov", &data, false, opts);
  let v: serde_json::Value = serde_json::from_str(&got).expect("valid JSON");
  let obj = v.as_array().and_then(|a| a.first()).expect("one object");
  assert_eq!(
    obj.get("Track1:GPSLatitude"),
    Some(&serde_json::json!(12.0)),
    "a 1-component (8-byte) GPSLatitude decodes its degrees, defaulting M/S to 0"
  );
  assert_eq!(
    obj.get("Track1:GPSLongitude"),
    Some(&serde_json::json!(122.5)),
    "a 2-component (16-byte) GPSLongitude decodes D + M/60, defaulting S to 0"
  );
  assert_eq!(
    obj.get("Track1:GPSTimeStamp"),
    Some(&serde_json::json!("12:00:00")),
    "a 1-component (8-byte) GPSTimeStamp decodes its hours, defaulting M/S to 0"
  );
}

// The Sony rtmd DEFINED-EMPTY-STRING fixture. A `string` record
// of length >= 1 that truncates to empty (a LEADING NUL) is a DEFINED EMPTY
// value bundled EMITS the tag for (only a zero-length record is omitted). The
// PrintConv render of an empty value (verified vs bundled ExifTool 13.59):
// SerialNumber / GPSMapDatum / GPSDateStamp (no hash PrintConv) → `""` at `-j`
// AND `-n`; GPSLatitudeRef / GPSLongitudeRef / GPSStatus / GPSMeasureMode (a
// bare inline hash PrintConv with NO `OTHER`) → the DEFAULT hash-miss
// `"Unknown ()"` at `-j`, `""` at `-n`. Two samples prove the `-G1` first-wins
// collapse with an EMPTY first-Doc value (sample 0 = empty, sample 1 = normal
// → Doc1's empty values win the collapse; the `-G3:1` golden shows Doc1 empty +
// Doc2 normal). EVERYTHING is byte-exact; only the structural `MetaFormat`
// (stsd rtmd 4cc) is excluded.
#[test]
fn sony_rtmd_emptystr_ee_byte_exact() {
  check_ee_excluding(
    "QuickTime_sony_rtmd_emptystr.mov",
    "QuickTime_sony_rtmd_emptystr.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_sony_rtmd_emptystr.mov",
    "QuickTime_sony_rtmd_emptystr.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

#[test]
fn sony_rtmd_emptystr_noee_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_sony_rtmd_emptystr.mov",
    "QuickTime_sony_rtmd_emptystr.mov.json",
    NO_EXCL,
  );
}

// End-to-end `-ee -G1 -n` (ValueConv) for the defined-empty strings — the
// `.ee.*` `-j` goldens render the GPS-ref/status/measure-mode PrintConv as
// `"Unknown ()"`, so this pins the RAW empty scalars: every empty string tag
// (SerialNumber + the GPS refs/status/measure-mode/map-datum/date-stamp)
// renders `""` at `-n`. Oracle: bundled ExifTool 13.59.
#[test]
fn sony_rtmd_emptystr_n_match_bundled() {
  let data = fixture("QuickTime_sony_rtmd_emptystr.mov");
  let opts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(false);
  let got = extract_info_with_options("QuickTime_sony_rtmd_emptystr.mov", &data, false, opts);
  let v: serde_json::Value = serde_json::from_str(&got).expect("valid JSON");
  let obj = v.as_array().and_then(|a| a.first()).expect("one object");
  // Under `-G1` the EMPTY first-Doc (sample 0) values win the collapse.
  for name in [
    "Track1:SerialNumber",
    "Track1:GPSLatitudeRef",
    "Track1:GPSLongitudeRef",
    "Track1:GPSStatus",
    "Track1:GPSMeasureMode",
    "Track1:GPSMapDatum",
    "Track1:GPSDateStamp",
  ] {
    assert_eq!(
      obj.get(name),
      Some(&serde_json::json!("")),
      "{name} -n must be the defined empty string (present, not omitted)"
    );
  }
}

// The Sony rtmd INVALID-UTF8 string fixture. A `string` record whose
// pre-NUL bytes are NOT valid UTF-8 is STILL a DEFINED tag: bundled `ReadValue`
// does not validate UTF-8 and `exiftool` FixUTF8's the value at JSON output
// (exiftool:3822) — one ASCII `?` per malformed byte (XMP.pm:2949-2972) — in BOTH
// -j and -n. exifast's old `from_utf8(...).ok()?` dropped the tag entirely; the
// fix routes decode_string through the engine's faithful fix_utf8. One sample
// with a single 0xff in: SerialNumber (raw → "A?B"), GPSMapDatum (raw → "WG?S"),
// GPSLatitudeRef + GPSStatus (inline-hash PrintConv miss → "Unknown (?)" at -j).
// Byte-exact vs bundled ExifTool 13.59.
#[test]
fn sony_rtmd_badutf8_ee_byte_exact() {
  check_ee_excluding(
    "QuickTime_sony_rtmd_badutf8.mov",
    "QuickTime_sony_rtmd_badutf8.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_sony_rtmd_badutf8.mov",
    "QuickTime_sony_rtmd_badutf8.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

#[test]
fn sony_rtmd_badutf8_noee_byte_exact() {
  check_noee_excluding(
    "QuickTime_sony_rtmd_badutf8.mov",
    "QuickTime_sony_rtmd_badutf8.mov.json",
    NO_EXCL,
  );
}

// End-to-end `-ee -G1 -n` (ValueConv) — the `.ee.*` `-j` goldens render the GPS
// ref/status PrintConv as "Unknown (?)", so this pins the RAW FixUTF8 scalars:
// each malformed string emits one ASCII `?` per bad byte ("A?B" / "?" / "WG?S"),
// PRESENT (never the dropped tag of the old `from_utf8(...).ok()?`). Oracle:
// bundled ExifTool 13.59.
#[test]
fn sony_rtmd_badutf8_n_match_bundled() {
  let data = fixture("QuickTime_sony_rtmd_badutf8.mov");
  let opts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(false);
  let got = extract_info_with_options("QuickTime_sony_rtmd_badutf8.mov", &data, false, opts);
  let v: serde_json::Value = serde_json::from_str(&got).expect("valid JSON");
  let obj = v.as_array().and_then(|a| a.first()).expect("one object");
  for (name, want) in [
    ("Track1:SerialNumber", "A?B"),
    ("Track1:GPSLatitudeRef", "?"),
    ("Track1:GPSStatus", "?"),
    ("Track1:GPSMapDatum", "WG?S"),
  ] {
    assert_eq!(
      obj.get(name),
      Some(&serde_json::json!(want)),
      "{name} -n must be the FixUTF8 raw value (present, one `?` per bad byte)"
    );
  }
}

// End-to-end `-ee -G1 -n` (ValueConv) checks the `.ee.*` `-j` goldens cannot
// reach: the zero-denominator FrameRate/ExposureTime words and the
// rounded non-decimal GPSTimeStamp. Oracle: bundled ExifTool 13.59.
#[test]
fn sony_rtmd_zerodenom_and_gpsts_round_n_match_bundled() {
  // Zero-denominator FrameRate/ExposureTime `-n` (both Docs via -G3:1).
  let zdata = fixture("QuickTime_sony_rtmd_zerodenom.mov");
  let zopts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(true);
  let zgot = extract_info_with_options("QuickTime_sony_rtmd_zerodenom.mov", &zdata, false, zopts);
  let zv: serde_json::Value = serde_json::from_str(&zgot).expect("valid JSON");
  let zobj = zv.as_array().and_then(|a| a.first()).expect("one object");
  // 0/0 (Doc1) → "undef"; n/0 (Doc2) → "inf" — JSON strings at `-n`.
  assert_eq!(
    zobj.get("Doc1:Track1:FrameRate"),
    Some(&serde_json::json!("undef")),
    "0/0 FrameRate -n is the rational `undef` word, never NaN"
  );
  assert_eq!(
    zobj.get("Doc1:Track1:ExposureTime"),
    Some(&serde_json::json!("undef")),
  );
  assert_eq!(
    zobj.get("Doc2:Track1:FrameRate"),
    Some(&serde_json::json!("inf")),
  );
  assert_eq!(
    zobj.get("Doc2:Track1:ExposureTime"),
    Some(&serde_json::json!("inf")),
  );

  // Non-decimal-denominator GPSTimeStamp `-n` (the rounded 8-digit form).
  let gdata = fixture("QuickTime_sony_rtmd_gpsts_round.mov");
  let gopts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(false);
  let ggot = extract_info_with_options("QuickTime_sony_rtmd_gpsts_round.mov", &gdata, false, gopts);
  let gv: serde_json::Value = serde_json::from_str(&ggot).expect("valid JSON");
  let gobj = gv.as_array().and_then(|a| a.first()).expect("one object");
  assert_eq!(
    gobj.get("Track1:GPSTimeStamp"),
    Some(&serde_json::json!("12:00:12.12347993")),
    "GPSTimeStamp -n must round each rational64u to 10 sig-figs before ConvertTimeStamp"
  );

  // Zero-denominator GPS COORDINATE empty `-n`: the `0x8502` latitude seconds =
  // 423/0 renders `"inf"`, so `GPS::ToDegrees` (GPS.pm:585) `return ''` yields
  // the EMPTY STRING `""` (a DEFINED value). exifast emits `GPSLatitude` as
  // `""` at `-n` (a present `SonyRtmdCoord::Empty`), BYTE-EXACT with bundled;
  // the sibling GPSLongitude (a normal fix) surfaces its `-n` decimal. This
  // pins that an inf component renders ONLY its own coordinate empty, never a
  // bogus Inf/NaN and never the whole GPS record.
  let czdata = fixture("QuickTime_sony_rtmd_coordzero.mov");
  let czopts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(false);
  let czgot =
    extract_info_with_options("QuickTime_sony_rtmd_coordzero.mov", &czdata, false, czopts);
  let czv: serde_json::Value = serde_json::from_str(&czgot).expect("valid JSON");
  let czobj = czv.as_array().and_then(|a| a.first()).expect("one object");
  assert_eq!(
    czobj.get("Track1:GPSLatitude"),
    Some(&serde_json::json!("")),
    "an inf (zero-denominator) latitude component renders the empty string at -n"
  );
  assert_eq!(
    czobj.get("Track1:GPSLongitude"),
    Some(&serde_json::json!(122.165)),
    "the sibling longitude (a normal fix) is unaffected by the empty latitude"
  );

  // Non-finite (n/0) GPSTimeStamp `-n`: the `0x8507` seconds = 423/0 renders
  // `"inf"`, which `GPS::ConvertTimeStamp` (no inf/undef guard) numifies into
  // the CONSTANT bogus string `"Inf:NaN:000000000NaN"`. exifast emits that
  // constant verbatim at `-n`, BYTE-EXACT with bundled. The valid
  // GPSLatitude/GPSLongitude (a normal 47/37/42.3 + 122/9/54 fix) surface their
  // `-n` decimals. This pins that an inf seconds poisons ONLY the timestamp.
  // (Contrast a `0/0` `undef` component, which `($x||0)` numifies to 0.)
  let gidata = fixture("QuickTime_sony_rtmd_gpsts_inf.mov");
  let giopts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(false);
  let gigot =
    extract_info_with_options("QuickTime_sony_rtmd_gpsts_inf.mov", &gidata, false, giopts);
  let giv: serde_json::Value = serde_json::from_str(&gigot).expect("valid JSON");
  let giobj = giv.as_array().and_then(|a| a.first()).expect("one object");
  assert_eq!(
    giobj.get("Track1:GPSTimeStamp"),
    Some(&serde_json::json!("Inf:NaN:000000000NaN")),
    "an inf (zero-denominator) seconds component emits the constant bogus ConvertTimeStamp string"
  );
  assert_eq!(
    giobj.get("Track1:GPSLatitude"),
    Some(&serde_json::json!(47.6284166666667)),
    "the valid latitude is unaffected by the bogus timestamp"
  );
  assert_eq!(
    giobj.get("Track1:GPSLongitude"),
    Some(&serde_json::json!(122.165)),
    "the valid longitude is unaffected by the bogus timestamp"
  );
}

// The Sony rtmd NON-FINAL ZERO-LENGTH TLV fixture.
// `Process_rtmd`'s walker (`while $pos+4 < $end`) processes a NON-FINAL
// zero-length record (`Size => 0`): `HandleTag(Size => 0)` is reached and
// `ReadValue` returns `''` (ExifTool.pm:6297) — a DEFINED value (the R9 "0-byte
// → absent" decision was WRONG for non-final records). SerialNumber(0x8114),
// GPSLatitudeRef(0x8501), GPSTimeStamp(0x8507) and GPSLatitude(0x8502) are each
// zero-length and NON-FINAL (followed by further records). Bundled emits
// SerialNumber `""`, GPSLatitudeRef `"Unknown ()"`@-j/`""`@-n, GPSTimeStamp
// `"00:00:00"`, GPSLatitude `""`; the surviving GPSLongitude (a normal 122/9/54
// fix) + the LongitudeRef/status/datum/datestamp + the full camera record set
// ALL stay byte-exact, proving a zero-length record renders ONLY its own tag
// empty. EVERYTHING is byte-exact; every emitted tag (incl. `Track<N>:MetaFormat`) is compared byte-exact.
#[test]
fn sony_rtmd_zerolen_ee_byte_exact() {
  check_ee_excluding(
    "QuickTime_sony_rtmd_zerolen.mov",
    "QuickTime_sony_rtmd_zerolen.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_sony_rtmd_zerolen.mov",
    "QuickTime_sony_rtmd_zerolen.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

#[test]
fn sony_rtmd_zerolen_noee_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_sony_rtmd_zerolen.mov",
    "QuickTime_sony_rtmd_zerolen.mov.json",
    NO_EXCL,
  );
}

// End-to-end `-ee -G1 -n` (ValueConv) for the zero-length records — the
// `.ee.*` `-j` goldens render the ref/timestamp PrintConvs, so this pins the raw
// post-ValueConv scalars for the defined-empty values: the zero-length
// SerialNumber / GPSLatitudeRef / GPSLatitude are the empty string `""`, the
// zero-length GPSTimeStamp is `"00:00:00"`, and the surviving GPSLongitude is a
// real `-n` decimal — proving the present-empty values never poison the real
// fix. Oracle: bundled ExifTool 13.59.
#[test]
fn sony_rtmd_zerolen_n_match_bundled() {
  let data = fixture("QuickTime_sony_rtmd_zerolen.mov");
  let opts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(false);
  let got = extract_info_with_options("QuickTime_sony_rtmd_zerolen.mov", &data, false, opts);
  let v: serde_json::Value = serde_json::from_str(&got).expect("valid JSON");
  let obj = v.as_array().and_then(|a| a.first()).expect("one object");
  let empty = serde_json::json!("");
  assert_eq!(
    obj.get("Track1:SerialNumber"),
    Some(&empty),
    "a NON-FINAL zero-length SerialNumber is a defined empty string"
  );
  assert_eq!(
    obj.get("Track1:GPSLatitudeRef"),
    Some(&empty),
    "a NON-FINAL zero-length GPSLatitudeRef is the empty string at -n"
  );
  assert_eq!(
    obj.get("Track1:GPSLatitude"),
    Some(&empty),
    "a NON-FINAL zero-length GPSLatitude renders the GPS::ToDegrees empty string"
  );
  assert_eq!(
    obj.get("Track1:GPSTimeStamp"),
    Some(&serde_json::json!("00:00:00")),
    "a NON-FINAL zero-length GPSTimeStamp is ConvertTimeStamp('') = 00:00:00"
  );
  assert_eq!(
    obj.get("Track1:GPSLongitude"),
    Some(&serde_json::json!(122.165)),
    "the surviving longitude fix is unaffected by the zero-length siblings"
  );
}

// ── PRESENT-but-sub-width NUMERIC conformance ───────
//
// `QuickTime_sony_rtmd_shortnum.mov` makes EACH numeric record (FNumber 0x8000,
// FrameRate 0x8106, ExposureTime 0x8109, MasterGainAdjustment 0x810a, ISO
// 0x810b, ElectricalExtenderMagnification 0x810c) sub-width AND NON-FINAL in
// sample 0 (Doc1) — the walker (`while $pos+4 < $end`) processes each, and
// `ReadValue` returns `''` → each tag's ValueConv numifies a DEFINED value.
// Bundled emits (verified vs ExifTool 13.59):
//   FNumber 256.0 (`2^(8-0/8192)`)   FrameRate 0.00 (`sprintf("%.2f",'')`)
//   ExposureTime "" (PrintExposureTime('') passes through)
//   MasterGainAdjustment "0.00 dB" (`''/100=0`)   ISO ""   EEM ""  (raw '')
// Sample 1 (Doc2) is the FULL VALID camera + GPS set (proves valid numerics stay
// byte-exact under the SAME emission). Under `-G1` Doc1's empty-read numerics WIN
// (first-extracted); under `-G3:1` each Doc keeps its own. EVERYTHING is
// byte-exact — NO numeric-tag exclusions; only the structural `MetaFormat` is
// excluded (the whole point of the fix).
#[test]
fn sony_rtmd_shortnum_ee_byte_exact() {
  check_ee_excluding(
    "QuickTime_sony_rtmd_shortnum.mov",
    "QuickTime_sony_rtmd_shortnum.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_sony_rtmd_shortnum.mov",
    "QuickTime_sony_rtmd_shortnum.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

#[test]
fn sony_rtmd_shortnum_noee_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_sony_rtmd_shortnum.mov",
    "QuickTime_sony_rtmd_shortnum.mov.json",
    NO_EXCL,
  );
}

#[test]
fn sony_rtmd_multistsd_ee_byte_exact() {
  // A 2-entry `stsd` `[rtmd, camm]` whose `stsc` points the chunk at description
  // index 1 (the rtmd decoy). ExifTool's `MetaFormat` is LAST-WINS across stsd
  // entries (`ProcessSampleDesc` per-entry `$$self{MetaFormat} = $val`) and it
  // dispatches every sample on that single last-wins format while DISCARDING the
  // `stsc` description index (QuickTimeStream.pl:1378). So the track resolves to
  // `camm` (NOT the desc-1 rtmd) and the sample decodes as camm — pinning
  // last-wins + the no-desc-index-routing behavior, `MetaFormat = "camm"`
  // compared byte-exact (no exclusion).
  check_ee_excluding(
    "QuickTime_sony_rtmd_multistsd.mov",
    "QuickTime_sony_rtmd_multistsd.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_sony_rtmd_multistsd.mov",
    "QuickTime_sony_rtmd_multistsd.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

#[test]
fn sony_rtmd_multistsd_noee_byte_exact() {
  check_noee_excluding(
    "QuickTime_sony_rtmd_multistsd.mov",
    "QuickTime_sony_rtmd_multistsd.mov.json",
    NO_EXCL,
  );
}

#[test]
fn sony_rtmd_multistsd8_ee_byte_exact() {
  // Like `multistsd` but the active LAST stsd entry is an UNDERSIZED 8-byte
  // `camm` (`[size=8][camm]`, no reserved/dref/children). ExifTool stops the
  // stsd loop only at `$size < 8` (QuickTime.pm:9642), so the 8-byte entry STILL
  // sets last-wins MetaFormat = "camm" and drives the camm decoder — pinning the
  // `size >= 8` (not `>= 16`) guard in walk_stsd / decode_stsd_meta_format.
  check_ee_excluding(
    "QuickTime_sony_rtmd_multistsd8.mov",
    "QuickTime_sony_rtmd_multistsd8.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_sony_rtmd_multistsd8.mov",
    "QuickTime_sony_rtmd_multistsd8.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

#[test]
fn sony_rtmd_multistsd8_noee_byte_exact() {
  check_noee_excluding(
    "QuickTime_sony_rtmd_multistsd8.mov",
    "QuickTime_sony_rtmd_multistsd8.mov.json",
    NO_EXCL,
  );
}

// End-to-end `-ee -G1 -n` (ValueConv) for the sub-width numerics — the `.ee.*`
// `-j` goldens render the PrintConvs, so this pins the raw post-ValueConv scalars
// of the empty-read values: FNumber `256` (the `2^(8-0/8192)` F64, no PrintConv),
// MasterGainAdjustment `0` (the `''/100` F64), and FrameRate / ExposureTime / ISO
// / ElectricalExtenderMagnification the EMPTY STRING `""` (the raw `''` / the `-n`
// rational `''`). Under `-G1` Doc1's empty-read values win the first-extracted
// collapse. Oracle: bundled ExifTool 13.59 (`-ee -G1 -n`).
#[test]
fn sony_rtmd_shortnum_n_match_bundled() {
  let data = fixture("QuickTime_sony_rtmd_shortnum.mov");
  let opts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(false);
  let got = extract_info_with_options("QuickTime_sony_rtmd_shortnum.mov", &data, false, opts);
  let v: serde_json::Value = serde_json::from_str(&got).expect("valid JSON");
  let obj = v.as_array().and_then(|a| a.first()).expect("one object");
  // FNumber / MasterGainAdjustment empty-read: a bare NUMBER (the ValueConv-of-
  // `''`: `2^(8-''/8192)=256`, `''/100=0`). Compare by NUMERIC VALUE — bundled's
  // integer-valued NV writer emits `256`/`0` while the typed `F64` serializer
  // emits `256.0`/`0.0`; `json_equivalent_strict` treats them equal (both parse
  // to the same f64). The KEY assertion is that the tag is PRESENT and numeric
  // (NOT dropped, NOT the `""` of a degenerate string).
  let num = |key: &str| -> f64 {
    obj
      .get(key)
      .and_then(serde_json::Value::as_f64)
      .unwrap_or_else(|| panic!("{key} is a bare number, not {:?}", obj.get(key)))
  };
  assert!(
    (num("Track1:FNumber") - 256.0).abs() < 1e-9,
    "a sub-width FNumber renders the ValueConv-of-'' = 256 at -n"
  );
  assert!(
    num("Track1:MasterGainAdjustment").abs() < 1e-9,
    "a sub-width MasterGainAdjustment renders the ValueConv-of-'' = 0 at -n"
  );
  // FrameRate / ExposureTime / ISO / EEM empty-read: the EMPTY STRING `""` (the
  // raw ValueConv `''` / the `-n` rational `''` / the no-conv raw `''`).
  let empty = serde_json::json!("");
  for key in [
    "Track1:FrameRate",
    "Track1:ExposureTime",
    "Track1:ISO",
    "Track1:ElectricalExtenderMagnification",
  ] {
    assert_eq!(
      obj.get(key),
      Some(&empty),
      "a sub-width {key} renders the raw '' empty string at -n (present, not dropped)"
    );
  }
  // SerialNumber survives (the sub-width numerics render ONLY their own tag
  // degenerate; the walker continued through every one).
  assert_eq!(
    obj.get("Track1:SerialNumber"),
    Some(&serde_json::json!("ILCE-7SM3 5072108")),
    "the surviving SerialNumber proves the walker stepped past every sub-width numeric"
  );
}

// ── DEGENERATE WhiteBalance + DateTime ─────────────────
//
// A PRESENT-but-degenerate `0xe303 WhiteBalance` / `0xe304 DateTime` record is
// walker-processed (NON-FINAL) and emits a DEFINED value — NOT a dropped tag.
// Sample 0 (Doc1) carries a zero-length WhiteBalance (`ReadValue '' → -j
// "Unknown ()" / -n ""`) + a 4-byte DateTime (`unpack` partial → `"2024:03:
// ::"`); a valid ISO + SerialNumber follow so both stay NON-FINAL. Sample 1
// (Doc2) is the full valid camera set (WhiteBalance raw 0 → `"Unknown (0)"`,
// full DateTime). EVERYTHING is byte-exact — NO WhiteBalance/DateTime
// exclusions, AND (R13) `Track<N>:MetaFormat = rtmd` is now emitted + compared,
// so NOTHING is excluded. Verified byte-exact vs bundled ExifTool 13.59.
#[test]
fn sony_rtmd_wbdt_ee_byte_exact() {
  check_ee(
    "QuickTime_sony_rtmd_wbdt.mov",
    "QuickTime_sony_rtmd_wbdt.mov.ee.json",
    false,
  );
  check_ee(
    "QuickTime_sony_rtmd_wbdt.mov",
    "QuickTime_sony_rtmd_wbdt.mov.ee.g3.json",
    true,
  );
}

#[test]
fn sony_rtmd_wbdt_noee_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_sony_rtmd_wbdt.mov",
    "QuickTime_sony_rtmd_wbdt.mov.json",
    NO_EXCL,
  );
}

// End-to-end `-ee -G3:1 -n` (ValueConv) for the degenerate WhiteBalance /
// DateTime — the `.ee.*` `-j` goldens render the PrintConvs, so this pins the
// raw post-ValueConv `-n` scalars per Doc: the zero-length WhiteBalance is the
// EMPTY STRING `""` (raw `''`, NOT the `-j` `"Unknown ()"`), the 4-byte DateTime
// is the SAME partial `"2024:03: ::"` (ConvertDateTime passes a malformed value
// through, so `-n` == `-j`), and Doc2's valid WhiteBalance raw 0 is the bare
// number `0`. Oracle: bundled ExifTool 13.59 (`-ee -G3:1 -n`).
#[test]
fn sony_rtmd_wbdt_n_match_bundled() {
  let data = fixture("QuickTime_sony_rtmd_wbdt.mov");
  let opts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(true);
  let got = extract_info_with_options("QuickTime_sony_rtmd_wbdt.mov", &data, false, opts);
  let v: serde_json::Value = serde_json::from_str(&got).expect("valid JSON");
  let obj = v.as_array().and_then(|a| a.first()).expect("one object");
  // Doc1: degenerate. Zero-length WhiteBalance → raw `''` empty string at `-n`.
  assert_eq!(
    obj.get("Doc1:Track1:WhiteBalance"),
    Some(&serde_json::json!("")),
    "a zero-length WhiteBalance renders the raw '' empty string at -n (present, not dropped)"
  );
  // 4-byte DateTime → the partial BCD string (identical at -j / -n).
  assert_eq!(
    obj.get("Doc1:Track1:DateTime"),
    Some(&serde_json::json!("2024:03: ::")),
    "a 4-byte DateTime renders its partial unpack output at -n"
  );
  // Doc2: a valid WhiteBalance raw 0 → the bare number 0 at -n.
  assert_eq!(
    obj
      .get("Doc2:Track1:WhiteBalance")
      .and_then(serde_json::Value::as_f64),
    Some(0.0),
    "a valid WhiteBalance raw 0 renders the bare numeric key at -n"
  );
  // Doc2: the full valid DateTime survives.
  assert_eq!(
    obj.get("Doc2:Track1:DateTime"),
    Some(&serde_json::json!("2024:01:07 11:19:15")),
  );
  // The track-level `MetaFormat` (R13) is the `stsd` 4cc, emitted once at the
  // `Track<N>` level (NOT under `Doc<N>`) — verify both presence + position.
  assert_eq!(
    obj.get("Track1:MetaFormat"),
    Some(&serde_json::json!("rtmd")),
    "MetaFormat is emitted at the family-1 Track level"
  );
  assert!(
    obj.get("Doc1:Track1:MetaFormat").is_none() && obj.get("Doc2:Track1:MetaFormat").is_none(),
    "MetaFormat is track-level only, never under a Doc<N>"
  );
}

#[test]
fn camm_noee_warning_byte_exact() {
  check_noee_excluding("QuickTime_camm.mov", "QuickTime_camm.mov.json", NO_EXCL);
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
// timing) and compared; every tag (incl. `Track<N>:MetaFormat`, the stsd 4-char code) is compared byte-exact.
#[test]
fn camm_2track_ee_global_doc_byte_exact() {
  check_ee_excluding(
    "QuickTime_camm_2track.mov",
    "QuickTime_camm_2track.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_camm_2track.mov",
    "QuickTime_camm_2track.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

// `QuickTime_mebx_camm.mov` — a `mebx` `trak` (Track1) FOLLOWED by a `camm`
// `trak` (Track2: 2 fixes). The crux cross-STRUCT pin: the `mebx` sample opens
// `Doc1` (in `QuickTimeStreamMeta`), and the two camm fixes CONTINUE the same
// global ordinal as `Doc2`/`Doc3` (in `CammMeta`) — proving the counter is shared
// across the two structs IN WALK ORDER (mebx trak walked before camm trak). At
// `-ee -G1` the mebx and camm tags occupy distinct `Track1`/`Track2` groups and
// all survive. `SampleTime`/`SampleDuration` are emitted for BOTH the mebx and
// the camm samples (each carries its sample-table timing) and compared; every
// tag (incl. `Track<N>:MetaFormat`) is compared byte-exact.
#[test]
fn mebx_camm_ee_cross_struct_global_doc_byte_exact() {
  check_ee_excluding(
    "QuickTime_mebx_camm.mov",
    "QuickTime_mebx_camm.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_mebx_camm.mov",
    "QuickTime_mebx_camm.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

// `QuickTime_mebx_2track.mov` — two `mebx` `trak`s emitting the SAME key name
// (`SceneIlluminance`). `-ee -G3` ⇒ `Doc1:Track1:SceneIlluminance` (1234) /
// `Doc2:Track2:SceneIlluminance` (5678) — the global doc spans the two tracks.
// `-ee -G1` ⇒ BOTH `Track1:SceneIlluminance` AND `Track2:SceneIlluminance`
// survive: a name-only collapse would drop Track2's value, so this is the
// strongest pin that the mebx `-G1` `%noDups` collapse is GROUP-AWARE
// (`(family1, name)`-keyed). Every tag (incl. `Track<N>:MetaFormat`) is compared
// byte-exact; the mebx `SampleTime`/`SampleDuration` ARE emitted and compared.
#[test]
fn mebx_2track_ee_global_doc_and_group_aware_collapse_byte_exact() {
  check_ee_excluding(
    "QuickTime_mebx_2track.mov",
    "QuickTime_mebx_2track.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_mebx_2track.mov",
    "QuickTime_mebx_2track.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

// The cross-struct / multi-track fixtures carry the SAME no-`ee` shape as the
// single-source `mebx`/`camm` fixtures: a `meta`-handler `Track1:Warning` and NO
// per-sample payload (the records surface only under `-ee`). Pins that the
// global-doc threading does not leak any record into the no-`ee` path.
#[test]
fn cross_struct_noee_warning_byte_exact() {
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
    check_noee_excluding(fix, gold, NO_EXCL);
  }
}
