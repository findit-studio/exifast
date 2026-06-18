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

// ── Track<N>: Canon CTMD (Canon Timed MetaData — per-sample Track<N>) ────────
// `Image::ExifTool::Canon::ProcessCTMD` (Canon.pm:10758-10804) decodes ONE
// timed sample per `CTMD` sample-table entry; `ProcessSamples` opens a `Doc<N>`
// per sample and `HandleTag`s every record under it. NOTE (oracle-verified):
// although `%Canon::CTMD` declares `GROUPS => { 1 => 'Canon' }`, the timed-
// metadata machinery re-scopes the family-1 group to the trak's `Track<N>`
// (oracle `Doc1:Track1:TimeStamp`, NOT `Canon:…`) — same as `rtmd`/`mebx`.
// Per sample (Canon.pm record order): SampleTime / SampleDuration / TimeStamp
// (type 1) / FocalLength (type 4) / FNumber + ExposureTime + ISO (type 5). The
// `-G1` collapse keeps Doc1's values (ISO 12800); `-G3:1` shows both docs
// (Doc2 ISO 6400). FocalLength/ExposureTime store the f64 quotient, so `-n`
// renders the bare quotient (15 / 0.0125), `-j` the `%.1f mm` / PrintExposureTime
// shaping. Only the structural `Track<N>:MetaFormat` (the stsd `CTMD` 4cc) plus
// the camera scalars are compared — everything is byte-exact with NO exclusion.

#[test]
fn canon_ctmd_ee_byte_exact() {
  check_ee_excluding(
    "QuickTime_canon_ctmd.mov",
    "QuickTime_canon_ctmd.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_canon_ctmd.mov",
    "QuickTime_canon_ctmd.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

// The Canon CTMD fixture at no-`ee`: `CTMD` is a `meta`-handler `trak`, so the
// per-sample TimeStamp/Focal/Exposure emission is fully `-ee`-gated. The no-`ee`
// path emits the standard `Track1:Warning` ([minor] ExtractEmbedded) + the
// structural `Track<N>:MetaFormat` and NO per-sample record — the same shape as
// the `rtmd`/`mebx`/`camm` fixtures. Byte-exact with NO exclusion.
#[test]
fn canon_ctmd_noee_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_canon_ctmd.mov",
    "QuickTime_canon_ctmd.mov.json",
    NO_EXCL,
  );
}

// End-to-end `-ee -G3:1 -n` (ValueConv) for the Canon CTMD camera scalars — the
// `.ee.*` `-j` goldens render the PrintConvs, so this pins the raw post-ValueConv
// `-n` scalars per Doc. Canon CTMD stores the f64 QUOTIENT (not a Rational like
// Sony rtmd), so at `-n`: FocalLength is the bare quotient `15` (NOT `"15.0 mm"`),
// FNumber `3.5`, ExposureTime the bare quotient `0.0125` (NOT `"1/80"`), ISO the
// integer `12800` (Doc1) / `6400` (Doc2); TimeStamp is the SAME Date/Time string
// (ConvertDateTime passes it through, so `-n` == `-j`). Oracle: bundled ExifTool
// 13.59 (`-ee -G3:1 -n QuickTime_canon_ctmd.mov`).
#[test]
fn canon_ctmd_n_match_bundled() {
  let data = fixture("QuickTime_canon_ctmd.mov");
  let opts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(true);
  let got = extract_info_with_options("QuickTime_canon_ctmd.mov", &data, false, opts);
  let v: serde_json::Value = serde_json::from_str(&got).expect("valid JSON");
  let obj = v.as_array().and_then(|a| a.first()).expect("one object");
  // Doc1: FocalLength is the bare f64 quotient at -n (not the `%.1f mm` string).
  assert_eq!(
    obj
      .get("Doc1:Track1:FocalLength")
      .and_then(serde_json::Value::as_f64),
    Some(15.0),
    "FocalLength -n must be the raw quotient (f64), not the `%.1f mm` PrintConv string"
  );
  // FNumber renders the bare number in both modes (PrintFNumber numifies).
  assert_eq!(
    obj
      .get("Doc1:Track1:FNumber")
      .and_then(serde_json::Value::as_f64),
    Some(3.5),
  );
  // ExposureTime is the raw quotient seconds at -n (1/80 = 0.0125), not "1/80".
  assert_eq!(
    obj
      .get("Doc1:Track1:ExposureTime")
      .and_then(serde_json::Value::as_f64),
    Some(0.0125),
    "ExposureTime -n must be the raw quotient seconds, not the PrintExposureTime string"
  );
  // ISO is the plain integer; Doc1 = 12800.
  assert_eq!(
    obj
      .get("Doc1:Track1:ISO")
      .and_then(serde_json::Value::as_u64),
    Some(12800),
  );
  // TimeStamp passes through ConvertDateTime unchanged → identical at -n / -j.
  assert_eq!(
    obj.get("Doc1:Track1:TimeStamp"),
    Some(&serde_json::json!("2018:02:21 12:08:56.21")),
  );
  // Doc2 keeps its own ISO under -G3:1 (the across-doc value the -G1 collapse drops).
  assert_eq!(
    obj
      .get("Doc2:Track1:ISO")
      .and_then(serde_json::Value::as_u64),
    Some(6400),
  );
  // The track-level `MetaFormat` is the `stsd` 4cc, emitted once at the
  // `Track<N>` level (NOT under `Doc<N>`).
  assert_eq!(
    obj.get("Track1:MetaFormat"),
    Some(&serde_json::json!("CTMD")),
    "MetaFormat is emitted at the family-1 Track level"
  );
  assert!(
    obj.get("Doc1:Track1:MetaFormat").is_none() && obj.get("Doc2:Track1:MetaFormat").is_none(),
    "MetaFormat is track-level only, never under a Doc<N>"
  );
}

// ── Canon CTMD: FIX #3 rational32u `-n` %.7g precision ──────────────────────
//
// `FocalLength` / `FNumber` / `ExposureTime` are `rational32u`, so the bundled
// `GetRational32u` (ExifTool.pm:6094) renders `RoundFloat(n/d, 7)` = `%.7g`, NOT
// a 15-digit f64. This fixture uses non-terminating quotients (FocalLength 10/3,
// FNumber 1/3, ExposureTime 1/3): the `.ee.*` `-j` goldens pin the PrintConvs
// (`3.3 mm` / `0.33` / `0.3`, byte-exact); the `-n` test below pins the raw
// `%.7g` ValueConv (`3.333333` / `0.3333333` / `0.3333333`) — the precision a
// stored f64 quotient would lose (it would emit `3.3333333333333335`).
#[test]
fn canon_ctmd_rational_ee_byte_exact() {
  check_ee_excluding(
    "QuickTime_canon_ctmd_rational.mov",
    "QuickTime_canon_ctmd_rational.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_canon_ctmd_rational.mov",
    "QuickTime_canon_ctmd_rational.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

#[test]
fn canon_ctmd_rational_n_precision_match_bundled() {
  let data = fixture("QuickTime_canon_ctmd_rational.mov");
  let opts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(true);
  // `-n` (ValueConv): the raw `rational32u` rendered as ExifTool's `%.7g`.
  let got = extract_info_with_options("QuickTime_canon_ctmd_rational.mov", &data, false, opts);
  let v: serde_json::Value = serde_json::from_str(&got).expect("valid JSON");
  let obj = v.as_array().and_then(|a| a.first()).expect("one object");
  // The byte-exact `-n` tokens bundled emits (oracle: `-ee -G3:1 -n`). A stored
  // f64 quotient would instead serialize the 15-/17-digit IEEE value.
  for (key, want) in [
    ("Doc1:Track1:FocalLength", "3.333333"),
    ("Doc1:Track1:FNumber", "0.3333333"),
    ("Doc1:Track1:ExposureTime", "0.3333333"),
  ] {
    let got_num = obj.get(key).expect("tag present");
    // Serialize the JSON value back to its token to compare the EXACT digits.
    assert_eq!(
      serde_json::to_string(got_num).unwrap(),
      want,
      "{key} -n must be the GetRational32u %.7g token, not a 15-digit f64"
    );
  }
}

// Canon CTMD duplicate type-4/type-5 within one sample: bundled
// `HandleTag`s every record, so a repeated FocalInfo/ExposureInfo is a same-Doc
// duplicate tag and the LATER value wins (ExifTool.pm:9437-9519). The fixture
// writes 15.0 mm then 24.0 mm (type 4) and F3.5/1-80/ISO12800 then
// F8.0/1-250/ISO6400 (type 5) in ONE sample; bundled (and exifast) keep the
// SECOND of each. Pins the `set_focal`/`set_exposure` last-wins fix.
#[test]
fn canon_ctmd_dup_last_wins_byte_exact() {
  check_ee_excluding(
    "QuickTime_canon_ctmd_dup.mov",
    "QuickTime_canon_ctmd_dup.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_canon_ctmd_dup.mov",
    "QuickTime_canon_ctmd_dup.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

// ── Canon CTMD: FIX #2 ProcessCTMD `Doc<N>:Track<N>:Warning` ─────────────────
//
// `ProcessCTMD` raises three walk-abort warnings, each surfaced under the
// raising sample's `Doc<N>`/`Track<N>` (the camm `Warning` channel): `Short CTMD
// record` (size<12), `Truncated CTMD record` (pos+size>dirLen, the preceding
// TimeStamp still emits), and the MINOR `[minor] Error parsing Canon CTMD data`
// (trailing-byte residue, `Warn(...,1)`). Each fixture isolates one warning;
// byte-exact at both `-G1` (`.ee.json`) and `-G3:1` (`.ee.g3.json`).
#[test]
fn canon_ctmd_warning_short_byte_exact() {
  check_ee_excluding(
    "QuickTime_canon_ctmd_warn_short.mov",
    "QuickTime_canon_ctmd_warn_short.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_canon_ctmd_warn_short.mov",
    "QuickTime_canon_ctmd_warn_short.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

#[test]
fn canon_ctmd_warning_truncated_byte_exact() {
  check_ee_excluding(
    "QuickTime_canon_ctmd_warn_trunc.mov",
    "QuickTime_canon_ctmd_warn_trunc.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_canon_ctmd_warn_trunc.mov",
    "QuickTime_canon_ctmd_warn_trunc.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

#[test]
fn canon_ctmd_warning_residue_minor_byte_exact() {
  check_ee_excluding(
    "QuickTime_canon_ctmd_warn_residue.mov",
    "QuickTime_canon_ctmd_warn_residue.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_canon_ctmd_warn_residue.mov",
    "QuickTime_canon_ctmd_warn_residue.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

// ── Canon CTMD: FIX #4 short TimeStamp partial unpack + RawConv warning ──────
//
// The type-1 `TimeStamp` `RawConv` ALWAYS runs `unpack('x2vCCCCCC')` +
// `sprintf`, so a SHORT payload yields a PARTIAL string (not a dropped tag) plus
// a RawConv-context warning. This fixture's two samples cover both arms: a len-4
// payload → `2018:00:00 00:00:00.00` + `RawConv TimeStamp: Missing argument in
// sprintf`; a len-0 payload → NO TimeStamp (the `x2` skip croaks) + `RawConv
// TimeStamp: 'x' outside of string in unpack`. Byte-exact at both group modes;
// the per-length strings 0..=12 are additionally pinned in the parser unit test.
#[test]
fn canon_ctmd_short_timestamp_byte_exact() {
  check_ee_excluding(
    "QuickTime_canon_ctmd_shortts.mov",
    "QuickTime_canon_ctmd_shortts.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_canon_ctmd_shortts.mov",
    "QuickTime_canon_ctmd_shortts.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

// Canon CTMD `ExifInfo7/8/9` re-dispatch (#82 — types 7/8/9 ProcessExifInfo,
// Canon.pm:9818-9853 / 10730-10754). A type-7 record whose ProcessExifInfo
// payload carries TWO `[len][tag][TIFF]` entries: a `0x8769` ExifIFD (a full
// TIFF with ExposureTime 1/80 + ISO 400) and a `0x927c` MakerNoteCanon (a full
// TIFF whose IFD0 is the Canon MakerNote, CanonFirmwareVersion). Bundled
// re-dispatches each embedded TIFF via `ProcessTIFF` under the sample's open
// `Doc<N>`/`Track<N>` scope; the recovered tags re-stamp to:
//   - `EXIF:ExifIFD:ExposureTime` / `:ISO` (the 0x8769 EXIF tags — family-1
//     `ExifIFD`, distinct from the CTMD type-5 `Track<N>:ExposureTime`/`:ISO`),
//   - `File:Track<N>:ExifByteOrder` (the 0x8769 ProcessTIFF byte-order marker),
//   - `MakerNotes:Track<N>:CanonFirmwareVersion` (the 0x927c MakerNote tag).
// Every group + value is oracle-verified vs bundled 13.59 (`-ee -G3:1:0`).
// Byte-exact at both group modes, NO exclusion.
#[test]
fn canon_ctmd_exifinfo_redispatch_byte_exact() {
  check_ee_excluding(
    "QuickTime_canon_ctmd_exifinfo.mov",
    "QuickTime_canon_ctmd_exifinfo.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_canon_ctmd_exifinfo.mov",
    "QuickTime_canon_ctmd_exifinfo.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

// End-to-end `-ee -G3:1 -n` (ValueConv) for the Canon CTMD ExifInfo re-dispatch:
// the `.ee.*` goldens render the PrintConvs, so this pins the raw post-ValueConv
// `-n` tokens of the re-dispatched EXIF tags per Doc. At `-n` the 0x8769 EXIF
// ExposureTime is the raw quotient seconds (1/80 = 0.0125, NOT "1/80"), ISO the
// plain integer (Doc1 400 / Doc2 200), ExifByteOrder the bare `II` marker, and
// the 0x927c CanonFirmwareVersion the same string (ConvertString passthrough).
// Oracle: bundled ExifTool 13.59 (`-ee -G3:1 -n`).
#[test]
fn canon_ctmd_exifinfo_n_match_bundled() {
  let data = fixture("QuickTime_canon_ctmd_exifinfo.mov");
  let opts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(true);
  let got = extract_info_with_options("QuickTime_canon_ctmd_exifinfo.mov", &data, false, opts);
  let v: serde_json::Value = serde_json::from_str(&got).expect("valid JSON");
  let obj = v.as_array().and_then(|a| a.first()).expect("one object");
  // The 0x8769 EXIF re-dispatch under `EXIF:ExifIFD`, per-Doc.
  for (key, want) in [
    ("Doc1:ExifIFD:ExposureTime", serde_json::json!(0.0125)),
    ("Doc1:ExifIFD:ISO", serde_json::json!(400)),
    ("Doc2:ExifIFD:ExposureTime", serde_json::json!(0.0125)),
    ("Doc2:ExifIFD:ISO", serde_json::json!(200)),
    // ExifByteOrder re-scopes to `File:Track<N>`, bare `II` at -n.
    ("Doc1:Track1:ExifByteOrder", serde_json::json!("II")),
    // The 0x927c MakerNote re-dispatch under `MakerNotes:Track<N>`.
    (
      "Doc1:Track1:CanonFirmwareVersion",
      serde_json::json!("Firmware Version 1.0.0"),
    ),
  ] {
    assert_eq!(obj.get(key), Some(&want), "{key} -n token mismatch");
  }
}

// Canon CTMD `ExifInfo` 0x8769 re-dispatch with a NESTED EXIF sub-IFD.
// The 0x8769 ProcessExifInfo TIFF's IFD0 carries ExposureTime + ISO AND a 0xa005
// InteropOffset → a nested InteropIFD with InteropIndex (0x0001 "R98"). When
// bundled re-dispatches the 0x8769 TIFF via `Exif::Main` (Canon.pm:9838-9843),
// it names the top-level directory `ExifIFD` (so IFD0's direct tags group
// `EXIF:ExifIFD`) but PRESERVES the DirName of the nested sub-IFD (Exif.pm:416 +
// 2720-2729 SET_GROUP1 `InteropIFD`). So the re-stamp keeps nested groups intact:
//   - `EXIF:ExifIFD:ExposureTime` / `:ISO`           (top-level IFD0 → ExifIFD),
//   - `EXIF:InteropIFD:InteropIndex`                 (nested 0xa005 → InteropIFD,
//     NOT collapsed to ExifIFD),
//   - `File:Track<N>:ExifByteOrder`                  (the ProcessTIFF marker).
// Oracle-verified vs bundled 13.59 (`-ee -G3:1` and `-ee -G1`). Byte-exact at
// both group modes, NO exclusion.
#[test]
fn canon_ctmd_exifinfo_nested_subifd_byte_exact() {
  check_ee_excluding(
    "QuickTime_canon_ctmd_exifinfo_nested.mov",
    "QuickTime_canon_ctmd_exifinfo_nested.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_canon_ctmd_exifinfo_nested.mov",
    "QuickTime_canon_ctmd_exifinfo_nested.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

// `-ee -G3:1 -n` (ValueConv) for the nested-sub-IFD re-dispatch: pins the raw
// post-ValueConv `-n` tokens. The nested InteropIFD's `InteropIndex` stays under
// `EXIF:InteropIFD` (raw token "R98", NOT the DCF PrintConv label, NOT under
// ExifIFD); the top-level IFD0 tags stay under `EXIF:ExifIFD`. Oracle: bundled
// ExifTool 13.59 (`-ee -G3:1 -n`).
#[test]
fn canon_ctmd_exifinfo_nested_n_match_bundled() {
  let data = fixture("QuickTime_canon_ctmd_exifinfo_nested.mov");
  let opts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(true);
  let got = extract_info_with_options(
    "QuickTime_canon_ctmd_exifinfo_nested.mov",
    &data,
    false,
    opts,
  );
  let v: serde_json::Value = serde_json::from_str(&got).expect("valid JSON");
  let obj = v.as_array().and_then(|a| a.first()).expect("one object");
  for (key, want) in [
    ("Doc1:ExifIFD:ExposureTime", serde_json::json!(0.0125)),
    ("Doc1:ExifIFD:ISO", serde_json::json!(400)),
    // The nested InteropIFD keeps its DirName (NOT collapsed to ExifIFD).
    ("Doc1:InteropIFD:InteropIndex", serde_json::json!("R98")),
    ("Doc1:Track1:ExifByteOrder", serde_json::json!("II")),
  ] {
    assert_eq!(obj.get(key), Some(&want), "{key} -n token mismatch");
  }
  // The nested sub-IFD tag MUST NOT appear under ExifIFD (the collapse bug).
  assert_eq!(
    obj.get("Doc1:ExifIFD:InteropIndex"),
    None,
    "InteropIndex must not collapse to ExifIFD"
  );
}

// ── Canon CTMD: 0x8769 Model hand-off to a 0x927c model-conditional tag ──────
//
// `ProcessExifInfo` processes a sample's ExifInfo entries IN ORDER
// (Canon.pm:10739-10751): a 0x8769 (ExifIFD) entry's IFD0 Model sets
// `$$self{Model}`, and a LATER 0x927c (MakerNoteCanon) entry's `Canon::Main`
// decode keys its MODEL-CONDITIONAL sub-tables on it. `$$self{Model}` is
// OBJECT-level state — STICKY across records AND across samples. The fixture's
// two samples prove both halves (oracle-verified vs bundled 13.59):
//   Doc1: 0x8769(Model="Canon EOS R5") THEN 0x927c(ShotInfo CameraTemperature
//         raw=158). The handed-off EOS Model passes the CameraTemperature
//         Condition (`$$self{Model} =~ /EOS/ and !~ /EOS-1DS?$/`, Canon.pm:2868),
//         so `Doc1:Track1:CameraTemperature` = 158-128 = "30 C". WITHOUT the
//         hand-off (the emitter passing None) the tag would be ABSENT.
//   Doc2: 0x927c-only(ShotInfo CameraTemperature raw=200). No 0x8769 in this
//         sample, but `$$self{Model}` STAYS "Canon EOS R5" from Doc1, so
//         `Doc2:Track1:CameraTemperature` = 200-128 = "72 C" — the cross-sample
//         stickiness. (AutoISO=100 is model-AGNOSTIC: present in both as the
//         control proving the ShotInfo array itself decoded.)
// Byte-exact at both `-G1` (`.ee.json`) and `-G3:1` (`.ee.g3.json`), NO exclusion.
#[test]
fn canon_ctmd_exifinfo_model_handoff_byte_exact() {
  check_ee_excluding(
    "QuickTime_canon_ctmd_exifinfo_model.mov",
    "QuickTime_canon_ctmd_exifinfo_model.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_canon_ctmd_exifinfo_model.mov",
    "QuickTime_canon_ctmd_exifinfo_model.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

// The model hand-off at `-ee -G3:1` (PrintConv) and `-ee -G1 -n` (ValueConv),
// asserting the model-CONDITIONAL `CameraTemperature` tags directly: Doc1 gets
// it from the in-sample 0x8769 Model, Doc2 from the STICKY cross-sample
// `$$self{Model}`. WITHOUT the hand-off the emitter would pass `None`, the
// Condition (`$$self{Model} =~ /EOS/`) would fail, and BOTH CameraTemperature
// tags would be absent — so these assertions pin that bundled decodes them USING
// the handed-off Model and exifast matches. Oracle: bundled ExifTool 13.59.
#[test]
fn canon_ctmd_exifinfo_model_handoff_camera_temperature_present() {
  let data = fixture("QuickTime_canon_ctmd_exifinfo_model.mov");
  // `-ee -G3:1` PrintConv: per-Doc CameraTemperature with the `"$val C"` PrintConv.
  let opts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(true);
  let got = extract_info_with_options("QuickTime_canon_ctmd_exifinfo_model.mov", &data, true, opts);
  let v: serde_json::Value = serde_json::from_str(&got).expect("valid JSON");
  let obj = v.as_array().and_then(|a| a.first()).expect("one object");
  for (key, want) in [
    // Doc1: from the in-sample 0x8769 Model "Canon EOS R5" (158-128 = 30).
    ("Doc1:Track1:CameraTemperature", serde_json::json!("30 C")),
    ("Doc1:ExifIFD:Model", serde_json::json!("Canon EOS R5")),
    // Doc2: NO 0x8769 here, but $$self{Model} is sticky ⇒ 200-128 = 72.
    ("Doc2:Track1:CameraTemperature", serde_json::json!("72 C")),
  ] {
    assert_eq!(obj.get(key), Some(&want), "{key} (PrintConv) mismatch");
  }

  // `-ee -G1 -n` ValueConv: at G1 the two Docs collapse first-wins onto Doc1's
  // raw CameraTemperature (30, the post-ValueConv `$val - 128` integer).
  let nopts = ParseOptions::default().with_extract_embedded(true);
  let ngot = extract_info_with_options(
    "QuickTime_canon_ctmd_exifinfo_model.mov",
    &data,
    false,
    nopts,
  );
  let nv: serde_json::Value = serde_json::from_str(&ngot).expect("valid JSON");
  let nobj = nv.as_array().and_then(|a| a.first()).expect("one object");
  assert_eq!(
    nobj.get("Track1:CameraTemperature"),
    Some(&serde_json::json!(30)),
    "the -n CameraTemperature is the raw post-ValueConv integer keyed on the handed-off Model"
  );
}

// ── Canon CTMD: duplicate IFD0 Model in one 0x8769 — last-wins ──
//
// A hostile 0x8769 (ExifIFD) whose IFD0 carries TWO Model tags — a non-EOS
// "Canon PowerShot S100" FIRST, then "Canon EOS R5" — followed by a 0x927c
// (MakerNoteCanon) ShotInfo CameraTemperature (raw=158). Exif.pm:599's RawConv
// `$$self{Model} = $val` runs EACH time a Model tag is handled, so the LATER
// (EOS) Model is in `$$self{Model}` when the 0x927c re-dispatches (LAST-wins).
// The EOS Model passes the CameraTemperature Condition (`$$self{Model} =~ /EOS/`,
// Canon.pm:2868) ⇒ `Doc1:Track1:CameraTemperature` = 158-128 = "30 C", and the
// emitted `Doc1:ExifIFD:Model` is ALSO last-wins ("Canon EOS R5"). Under the
// pre-R6 FIRST-wins capture the non-EOS PowerShot would win, the Condition would
// FAIL, and CameraTemperature would be ABSENT — so this fixture is a direct
// last-vs-first discriminator. Byte-exact at both `-G1` and `-G3:1`, NO exclusion.
#[test]
fn canon_ctmd_exifinfo_dup_model_last_wins_byte_exact() {
  check_ee_excluding(
    "QuickTime_canon_ctmd_exifinfo_dupmodel.mov",
    "QuickTime_canon_ctmd_exifinfo_dupmodel.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_canon_ctmd_exifinfo_dupmodel.mov",
    "QuickTime_canon_ctmd_exifinfo_dupmodel.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

// The duplicate-Model last-wins asserted directly: the model-CONDITIONAL
// `CameraTemperature` is present ONLY because the LAST (EOS) Model won. WITHOUT
// last-wins (the pre-R6 first-wins keeping the non-EOS PowerShot) the Condition
// would fail and the tag would be absent — so this pins that exifast hands off
// the LAST IFD0 Model, matching bundled 13.59.
#[test]
fn canon_ctmd_exifinfo_dup_model_camera_temperature_present() {
  let data = fixture("QuickTime_canon_ctmd_exifinfo_dupmodel.mov");
  let opts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(true);
  let got = extract_info_with_options(
    "QuickTime_canon_ctmd_exifinfo_dupmodel.mov",
    &data,
    true,
    opts,
  );
  let v: serde_json::Value = serde_json::from_str(&got).expect("valid JSON");
  let obj = v.as_array().and_then(|a| a.first()).expect("one object");
  for (key, want) in [
    ("Doc1:Track1:CameraTemperature", serde_json::json!("30 C")),
    ("Doc1:ExifIFD:Model", serde_json::json!("Canon EOS R5")),
  ] {
    assert_eq!(obj.get(key), Some(&want), "{key} (PrintConv) mismatch");
  }
}

// ── Canon CTMD: embedded ExifInfo TIFF diagnostics ───────────────────────────
//
// The CTMD type-7/8/9 re-dispatch parses each embedded TIFF (Canon.pm:10745-
// 10751); a MALFORMED one (valid header + bad IFD0 offset) raises a normal EXIF
// `Bad $dir directory` warning UNDER the active Doc/Track scope. Two one-sample
// fixtures isolate each re-dispatch tag — the warning rides the SAME
// `Doc<N>:Track<N>:Warning` channel (priority-0 first-wins) as the ProcessCTMD
// walk-abort warnings:
//   badexif — a 0x8769 (ExifIFD) block ⇒ `Track1:ExifByteOrder` STILL emits
//             (the header parsed) AND a NON-minor `Bad ExifIFD directory`.
//   badmn   — a 0x927c (MakerNoteCanon) block ⇒ NO ExifByteOrder (the MakerNote
//             re-dispatch never surfaces it) and the MINOR `[minor] Bad
//             MakerNotes directory` ($inMakerNotes ⇒ minor). The TimeStamp ahead
//             of each bad block still decodes.
// Byte-exact at both `-G1` (`.ee.json`) and `-G3:1` (`.ee.g3.json`), NO exclusion.
#[test]
fn canon_ctmd_bad_embedded_exif_diagnostics_byte_exact() {
  check_ee_excluding(
    "QuickTime_canon_ctmd_badexif.mov",
    "QuickTime_canon_ctmd_badexif.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_canon_ctmd_badexif.mov",
    "QuickTime_canon_ctmd_badexif.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

#[test]
fn canon_ctmd_bad_embedded_makernote_diagnostics_byte_exact() {
  check_ee_excluding(
    "QuickTime_canon_ctmd_badmn.mov",
    "QuickTime_canon_ctmd_badmn.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_canon_ctmd_badmn.mov",
    "QuickTime_canon_ctmd_badmn.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

// End-to-end `-ee -G3:1 -n` (ValueConv): the warning string renders identically
// at `-n` (it carries no conv), so the bad-block `Doc1:Track1:Warning` token is
// the SAME as `-j`, while the 0x8769 `Doc1:Track1:ExifByteOrder` drops to the
// bare `II` marker. Oracle: bundled ExifTool 13.59 (`-ee -G3:1 -n`).
#[test]
fn canon_ctmd_bad_embedded_n_match_bundled() {
  // badexif: ExifByteOrder bare `II` + the non-minor warning.
  let edata = fixture("QuickTime_canon_ctmd_badexif.mov");
  let eopts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(true);
  let egot = extract_info_with_options("QuickTime_canon_ctmd_badexif.mov", &edata, false, eopts);
  let ev: serde_json::Value = serde_json::from_str(&egot).expect("valid JSON");
  let eobj = ev.as_array().and_then(|a| a.first()).expect("one object");
  assert_eq!(
    eobj.get("Doc1:Track1:ExifByteOrder"),
    Some(&serde_json::json!("II")),
    "0x8769 ExifByteOrder is the bare `II` marker at -n"
  );
  assert_eq!(
    eobj.get("Doc1:Track1:Warning"),
    Some(&serde_json::json!("Bad ExifIFD directory")),
    "0x8769 bad IFD0 raises the non-minor `Bad ExifIFD directory` warning"
  );

  // badmn: the MINOR warning (`[minor] ` prefix preserved at -n), no ExifByteOrder.
  let mdata = fixture("QuickTime_canon_ctmd_badmn.mov");
  let mopts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(true);
  let mgot = extract_info_with_options("QuickTime_canon_ctmd_badmn.mov", &mdata, false, mopts);
  let mv: serde_json::Value = serde_json::from_str(&mgot).expect("valid JSON");
  let mobj = mv.as_array().and_then(|a| a.first()).expect("one object");
  assert_eq!(
    mobj.get("Doc1:Track1:Warning"),
    Some(&serde_json::json!("[minor] Bad MakerNotes directory")),
    "0x927c bad IFD0 raises the MINOR `[minor] Bad MakerNotes directory` warning"
  );
  assert!(
    mobj.get("Doc1:Track1:ExifByteOrder").is_none(),
    "the 0x927c MakerNote re-dispatch never surfaces ExifByteOrder"
  );
}

// Canon CTMD 0x927c re-dispatch routes through `Canon::Main` — NOT the generic
// Exif walker. A type-7 carries a 0x927c (MakerNoteCanon) block
// whose READABLE IFD0 holds a CanonFirmwareVersion AND a bogus 0x8769
// (ExifIFD-style) pointer. `%Canon::Main` has no 0x8769 key (Canon's MakerNote
// carries no ExifIFD pointer; its sub-tables are ProcessBinaryData, not
// ProcessExif IFD sub-dirs), so bundled NEVER follows it: the block decodes
// (`Doc1:Track1:CanonFirmwareVersion = "FW1.0.0"`) and NO `Bad ExifIFD
// directory` warning is raised. Using the generic Exif walker for the 0x927c
// diagnostics would emit that spurious nested warning. Byte-exact at both group
// modes (the goldens carry NO `Warning` for this Doc), NO exclusion.
#[test]
fn canon_ctmd_makernote_nested_exif_pointer_not_followed_byte_exact() {
  check_ee_excluding(
    "QuickTime_canon_ctmd_badmn_nested.mov",
    "QuickTime_canon_ctmd_badmn_nested.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_canon_ctmd_badmn_nested.mov",
    "QuickTime_canon_ctmd_badmn_nested.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

// ── Canon CTMD: 0x927c PER-ENTRY value-offset warnings ──────────
//
// A READABLE 0x927c (MakerNoteCanon) IFD0 whose Canon tag has a bad OUT-OF-LINE
// value pointer raises a per-entry value-offset warning under `$inMakerNotes`
// (ProcessTIFF → ProcessExif-under-`Canon::Main`, in-memory ⇒ no RAF). Two
// one-sample fixtures isolate each (oracle-verified vs bundled 13.59):
//   badmnval  — value pointer far past EOF ⇒ the no-RAF `Bad offset for $dir
//               $tagStr` (Exif.pm:6660), `$dir` re-mapped to `MakerNotes`,
//               `$tagStr` the `%Canon::Main` name, MINOR (`$inMakerNotes`):
//               `Doc1:Track1:Warning = "[minor] Bad offset for MakerNotes
//               CanonFirmwareVersion"`.
//   badmnsusp — value pointer IN bounds but overlapping the directory ⇒ the
//               `Suspicious $dir offset for $tagStr` (Exif.pm:6675), MINOR:
//               `"[minor] Suspicious MakerNotes offset for CanonFirmwareVersion"`.
// The IFD0 directory itself parses, so NO `Bad MakerNotes directory`; the warning
// rides the SAME priority-0 first-wins `Doc<N>:Track<N>:Warning` channel as the
// ProcessCTMD/ExifInfo diagnostics, after the clean `TimeStamp`. The generic Exif
// walker would emit the wrong `Error reading value` text (its RAF/non-MakerNotes
// model) and abort — this pins the in-memory `$inMakerNotes` path. Byte-exact at
// both group modes, NO exclusion.
#[test]
fn canon_ctmd_makernote_bad_value_offset_byte_exact() {
  check_ee_excluding(
    "QuickTime_canon_ctmd_badmnval.mov",
    "QuickTime_canon_ctmd_badmnval.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_canon_ctmd_badmnval.mov",
    "QuickTime_canon_ctmd_badmnval.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

// The `badmnsusp` value pointer is IN bounds (it merely OVERLAPS the directory),
// so bundled's `$inMakerNotes` path `next`-SKIPS the entry (Exif.pm:6672-6678)
// and emits NO `CanonFirmwareVersion`. The shared Canon body walker
// (`walk_canon_in_tiff`) now ALSO `next`-skips a suspect-offset entry (
// `value_ptr < 8` OR a value range overlapping the IFD directory), so the
// spurious `Track<N>:CanonFirmwareVersion` is gone and this is FULLY byte-exact
// — NO exclusion. The `Suspicious MakerNotes offset` Warning still rides the
// diagnostic channel (asserted by `canon_ctmd_makernote_value_offset_warning_text`).
#[test]
fn canon_ctmd_makernote_suspicious_value_offset_byte_exact() {
  check_ee_excluding(
    "QuickTime_canon_ctmd_badmnsusp.mov",
    "QuickTime_canon_ctmd_badmnsusp.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_canon_ctmd_badmnsusp.mov",
    "QuickTime_canon_ctmd_badmnsusp.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

// The 0x927c value-offset warnings assert directly at `-ee -G3:1` (PrintConv):
// the exact bundled `Doc1:Track1:Warning` text, AND that the `Bad offset` /
// `Suspicious offset` case is MINOR (`[minor]` prefix). The clean `TimeStamp`
// still decodes (the warning rides alongside, not an abort). Oracle: bundled 13.59.
#[test]
fn canon_ctmd_makernote_value_offset_warning_text() {
  for (fix, want) in [
    (
      "QuickTime_canon_ctmd_badmnval.mov",
      "[minor] Bad offset for MakerNotes CanonFirmwareVersion",
    ),
    (
      "QuickTime_canon_ctmd_badmnsusp.mov",
      "[minor] Suspicious MakerNotes offset for CanonFirmwareVersion",
    ),
  ] {
    let data = fixture(fix);
    let opts = ParseOptions::default()
      .with_extract_embedded(true)
      .with_group3(true);
    let got = extract_info_with_options(fix, &data, true, opts);
    let v: serde_json::Value = serde_json::from_str(&got).expect("valid JSON");
    let obj = v.as_array().and_then(|a| a.first()).expect("one object");
    assert_eq!(
      obj.get("Doc1:Track1:Warning"),
      Some(&serde_json::json!(want)),
      "{fix}: 0x927c per-entry value-offset Warning text mismatch"
    );
    assert_eq!(
      obj.get("Doc1:Track1:TimeStamp"),
      Some(&serde_json::json!("2018:02:21 12:08:56.21")),
      "{fix}: the clean TimeStamp still decodes alongside the value-offset Warning"
    );
  }
}

// ── Canon CTMD: IFD-tail + per-entry validation crafted edges ─────
//
// The CTMD re-dispatch's IFD-validation reproduces `ProcessExif`'s
// directory-shape gate (`Exif.pm:6343-6400`) AND per-entry checks
// (`Exif.pm:6454-6679`) BYTE-EXACTLY, with the emission SKIP and the diagnostic
// WARNING driven by ONE shared predicate ([`body::classify_canon_directory`] /
// [`body::classify_canon_entry`] for `0x927c`; the no-RAF generic walker for
// `0x8769`) — they can NEVER disagree (the R8 bug was a `dir_end + 4 <=
// data_len` diagnostic gate that suppressed the warning while the emission still
// skipped). Each fixture isolates one shape; byte-exact at BOTH group modes
// (`.ee.json` `-G1` and `.ee.g3.json` `-G3:1`), NO exclusion. Oracle: bundled
// ExifTool 13.59.

// R8 PROPER: a `0x927c` IFD ending EXACTLY at the block boundary (`$bytesFromEnd
// == 0`) AND a `2`-byte-tail variant (`$bytesFromEnd == 2`) — both LEGAL tails,
// so the directory is walked and the suspect (directory-overlapping) value
// offset is reached ⇒ `[minor] Suspicious MakerNotes offset for
// CanonFirmwareVersion` (the warning NOW fires alongside the emission skip).
#[test]
fn canon_ctmd_makernote_suspicious_offset_block_boundary_tail_byte_exact() {
  for fix in [
    "QuickTime_canon_ctmd_badmnsusp_tail0.mov",
    "QuickTime_canon_ctmd_badmnsusp_tail2.mov",
  ] {
    check_ee_excluding(fix, &format!("{fix}.ee.json"), false, NO_EXCL);
    check_ee_excluding(fix, &format!("{fix}.ee.g3.json"), true, NO_EXCL);
  }
}

// Illegal `1`-/`3`-byte IFD tails (`$bytesFromEnd` ∈ {1,3}) ⇒ the directory
// ABORTS with `Illegal MakerNotes directory size (1 entries)` (`Exif.pm:6397`) —
// NON-minor (the Perl `$et->Warn` carries no minor arg even under
// `$inMakerNotes`), no entry read. Pins both the abort (emission) and the
// NON-minor level (the prior force-minor was wrong).
#[test]
fn canon_ctmd_makernote_illegal_directory_tail_byte_exact() {
  for fix in [
    "QuickTime_canon_ctmd_badmn_tail1.mov",
    "QuickTime_canon_ctmd_badmn_tail3.mov",
  ] {
    check_ee_excluding(fix, &format!("{fix}.ee.json"), false, NO_EXCL);
    check_ee_excluding(fix, &format!("{fix}.ee.g3.json"), true, NO_EXCL);
  }
}

// Bad NONZERO format code (`Exif.pm:6463-6477`): on entry 0 ⇒ `[minor] Bad
// format (99) for MakerNotes entry 0` + ABORT (no value); on entry 1 (after a
// VALID entry 0) ⇒ CanonFirmwareVersion STILL emits AND `[minor] Bad format (99)
// for MakerNotes entry 1` (`next`-skip, NOT abort). The `Bad format` warning was
// previously absent from the `0x927c` diagnostic walk entirely.
#[test]
fn canon_ctmd_makernote_bad_format_byte_exact() {
  for fix in [
    "QuickTime_canon_ctmd_badmnfmt0.mov",
    "QuickTime_canon_ctmd_badmnfmt1.mov",
  ] {
    check_ee_excluding(fix, &format!("{fix}.ee.json"), false, NO_EXCL);
    check_ee_excluding(fix, &format!("{fix}.ee.g3.json"), true, NO_EXCL);
  }
}

// Count overflow (`$size > 0x7fffffff`, `Exif.pm:6505`) ⇒ `[minor] Invalid size
// (4294967296) for MakerNotes tag 0x0007 CanonFirmwareVersion` — the FIRST
// `$size > 4` test, reported as `Invalid size` (with the `TagName` form), NOT as
// `Bad offset`. (The prior hand-walk mis-reported it as `Bad offset`.)
#[test]
fn canon_ctmd_makernote_invalid_size_byte_exact() {
  check_ee_excluding(
    "QuickTime_canon_ctmd_badmnsize.mov",
    "QuickTime_canon_ctmd_badmnsize.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_canon_ctmd_badmnsize.mov",
    "QuickTime_canon_ctmd_badmnsize.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

// `0x8769` ExifIFD no-RAF re-dispatch: an OUT-OF-BOUNDS Make (entry 0) then a
// VALID inline Software (entry 1). Bundled re-frames `$dataPt` to the embedded
// block with NO RAF, so the OOB value warns `Bad offset for ExifIFD Make`
// (NON-minor, `$inMakerNotes = 0`) + `$bad = 1` and CONTINUES ⇒ the LATER
// Software STILL decodes (`Doc1:ExifIFD:Software`). A RAF-modeled walk would
// `Error reading value` + ABORT, dropping Software AND mis-naming the warning —
// this pins the faithful no-RAF branch (both the text and the survival of the
// later entry).
#[test]
fn canon_ctmd_exififd_no_raf_bad_offset_continues_byte_exact() {
  check_ee_excluding(
    "QuickTime_canon_ctmd_badexifval.mov",
    "QuickTime_canon_ctmd_badexifval.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_canon_ctmd_badexifval.mov",
    "QuickTime_canon_ctmd_badexifval.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

// `$warnCount > 10` directory abort (`Exif.pm:6455-6456`). An IFD0
// with a VALID entry 0, 12 BAD-format entries (entries 1..12), then a VALID
// later entry: ExifTool counts entries 1..11 (11 warnings) and at entry 12
// `$warnCount > 10` fires ⇒ `Too many warnings -- $dir parsing aborted` +
// `return 0`, so the LATER valid entry is SUPPRESSED. The abort warning is the
// 12th distinct one (deduped behind the first `Bad format … entry 1` — first-
// wins), so the surviving `Warning` is `Bad format (255) for <dir> entry 1` and
// the OBSERVABLE effect is the dropped later entry. Two re-dispatch tables:
//   warnmany_mn   — `0x927c` MakerNoteCanon (Canon emission + diagnostic walks,
//                   `$inMakerNotes = 1` ⇒ `[minor]`): CanonFirmwareVersion emits,
//                   OwnerName (entry 13) suppressed.
//   warnmany_exif — `0x8769` ExifIFD (the shared generic Walker,
//                   `$inMakerNotes = 0`): ExposureTime emits, ISO suppressed.
#[test]
fn canon_ctmd_too_many_warnings_directory_abort_byte_exact() {
  for fix in [
    "QuickTime_canon_ctmd_warnmany_mn.mov",
    "QuickTime_canon_ctmd_warnmany_exif.mov",
  ] {
    check_ee_excluding(fix, &std::format!("{fix}.ee.json"), false, NO_EXCL);
    check_ee_excluding(fix, &std::format!("{fix}.ee.g3.json"), true, NO_EXCL);
  }
}

// R9-2: `ProcessExif` has NO zero-entry or maximum-count directory gate
// (`Exif.pm:6343-6400`). Two ends:
//   badmn_zero_tail1/3 — a `0x927c` IFD0 with ZERO entries and a `1`/`3`-byte
//     tail ⇒ the NON-minor `Illegal MakerNotes directory size (0 entries)`
//     (`Exif.pm:6397`) + abort. (The retired `num_entries == 0` reject would
//     have dropped this warning.)
//   mn_manyentries — a `0x927c` IFD0 with 1100 (> 1024) VALID in-bounds entries
//     ⇒ bundled WALKS them all (the first decodes `CanonFirmwareVersion`), NO
//     warning. (The retired `MAX_SANE_ENTRIES = 1024` ceiling dropped the whole
//     directory.)
#[test]
fn canon_ctmd_makernote_zero_and_large_directory_byte_exact() {
  for fix in [
    "QuickTime_canon_ctmd_badmn_zero_tail1.mov",
    "QuickTime_canon_ctmd_badmn_zero_tail3.mov",
    "QuickTime_canon_ctmd_mn_manyentries.mov",
  ] {
    check_ee_excluding(fix, &std::format!("{fix}.ee.json"), false, NO_EXCL);
    check_ee_excluding(fix, &std::format!("{fix}.ee.g3.json"), true, NO_EXCL);
  }
}

// Canon CTMD partial-duplicate type-5 ExposureInfo merges PER FIELD (Codex
// R3-2). ONE sample: a FULL type-5 (FNumber 3.5 / ExposureTime 1/80 / ISO
// 12800), then an 8-byte type-5 (FNumber 8.0 + ExposureTime 1/250, no ISO),
// then a 4-byte type-5 (FNumber 5.6 only). Bundled HandleTags each record;
// ProcessBinaryData emits only the fields that fit the payload and resolves
// duplicates per tag NAME (Canon.pm:9874-9887; ExifTool.pm:9514-9565), so the
// merged sample is FNumber 5.6 (LAST record), ExposureTime 1/250 (the 8-byte
// record — the 4-byte one omitted it), ISO 12800 (the FULL record — neither
// partial carried it). A partial record must NOT clobber the sibling fields.
// Byte-exact at both group modes, NO exclusion.
#[test]
fn canon_ctmd_partial_duplicate_exposure_byte_exact() {
  check_ee_excluding(
    "QuickTime_canon_ctmd_partialdup.mov",
    "QuickTime_canon_ctmd_partialdup.mov.ee.json",
    false,
    NO_EXCL,
  );
  check_ee_excluding(
    "QuickTime_canon_ctmd_partialdup.mov",
    "QuickTime_canon_ctmd_partialdup.mov.ee.g3.json",
    true,
    NO_EXCL,
  );
}

// End-to-end `-ee -G3:1 -n` (ValueConv) for the partial-duplicate ExposureInfo:
// the per-field merge holds at `-n` too — FNumber 5.6 (raw F64), ExposureTime
// the raw quotient seconds (1/250 = 0.004, NOT "1/250"), ISO the plain integer
// 12800. Oracle: bundled ExifTool 13.59 (`-ee -G3:1 -n`).
#[test]
fn canon_ctmd_partial_duplicate_exposure_n_match_bundled() {
  let data = fixture("QuickTime_canon_ctmd_partialdup.mov");
  let opts = ParseOptions::default()
    .with_extract_embedded(true)
    .with_group3(true);
  let got = extract_info_with_options("QuickTime_canon_ctmd_partialdup.mov", &data, false, opts);
  let v: serde_json::Value = serde_json::from_str(&got).expect("valid JSON");
  let obj = v.as_array().and_then(|a| a.first()).expect("one object");
  for (key, want) in [
    ("Doc1:Track1:FNumber", serde_json::json!(5.6)),
    ("Doc1:Track1:ExposureTime", serde_json::json!(0.004)),
    ("Doc1:Track1:ISO", serde_json::json!(12800)),
  ] {
    assert_eq!(obj.get(key), Some(&want), "{key} -n token mismatch");
  }
}

// All the new CTMD fixtures at no-`ee`: `CTMD` is a `meta`-handler `trak`, so
// the per-sample emission (incl. the ProcessCTMD warnings + the ExifInfo
// re-dispatch) is fully `-ee`-gated. The no-`ee` path emits only the standard
// `[minor] ExtractEmbedded` `Track1:Warning` + the structural
// `Track1:MetaFormat`. Byte-exact, NO exclusion.
#[test]
fn canon_ctmd_variants_noee_byte_exact() {
  for fix in [
    "QuickTime_canon_ctmd_rational.mov",
    "QuickTime_canon_ctmd_warn_short.mov",
    "QuickTime_canon_ctmd_warn_trunc.mov",
    "QuickTime_canon_ctmd_warn_residue.mov",
    "QuickTime_canon_ctmd_shortts.mov",
    "QuickTime_canon_ctmd_exifinfo.mov",
    "QuickTime_canon_ctmd_exifinfo_model.mov",
    "QuickTime_canon_ctmd_badexif.mov",
    "QuickTime_canon_ctmd_badmn.mov",
    "QuickTime_canon_ctmd_badmn_nested.mov",
    "QuickTime_canon_ctmd_partialdup.mov",
    "QuickTime_canon_ctmd_warnmany_mn.mov",
    "QuickTime_canon_ctmd_warnmany_exif.mov",
    "QuickTime_canon_ctmd_badmn_zero_tail1.mov",
    "QuickTime_canon_ctmd_badmn_zero_tail3.mov",
    "QuickTime_canon_ctmd_mn_manyentries.mov",
  ] {
    check_noee_excluding(fix, &std::format!("{fix}.json"), NO_EXCL);
  }
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

// ── Insta360 INSV/INSP file-end trailer (ProcessInsta360) ───────────────────
// A crafted minimal MP4 carrying an Insta360 trailer with EVERY surfaced record
// type (identity 0x101 + accelerometer 0x300 [a 56-byte doubles row + a 20-byte
// int16 row] + videotimestamp 0x600 [2 rows] + exposure 0x400 [2 rows] + GPS
// 0x700 [2 'A' fixes + 1 void 'V']). The walker steps last-record-first, and a
// SINGLE global `DOC_NUM` `++`s per surfaced timed row across ALL types — so
// GPS=Doc1/Doc2, exposure=Doc3/Doc4, videotime=Doc5/Doc6, accel=Doc7/Doc8 —
// while the identity record (walked LAST, file-first) does NOT increment it and
// rides the sticky Doc8.
//
// The `-ee -G3` oracle (`QuickTime_insta360.mp4.ee.g3.json`) is each row under
// its own `Doc<N>:Insta360:*`; the `-ee -G1` oracle (`…ee.json`) is the two-rule
// `%noDups` collapse over the doc-ORDERED UNION of all record types — the
// strongest pin being the cross-TYPE `TimeCode` collision (exposure Doc3=1.000 /
// Doc4=2.000 AND accel Doc7=2.000 / Doc8=1.000) resolving to the single LOWEST-doc
// `TimeCode: 1.000` (Doc3), and `Accelerometer`/`AngularVelocity` keeping the
// lower-doc accel20 row (Doc7). The unique identity names always survive at `-G1`.
#[test]
fn insta360_ee_byte_exact_all_record_types() {
  check_ee(
    "QuickTime_insta360.mp4",
    "QuickTime_insta360.mp4.ee.json",
    false,
  );
  check_ee(
    "QuickTime_insta360.mp4",
    "QuickTime_insta360.mp4.ee.g3.json",
    true,
  );
}

// At no-`ee`: `ProcessInsta360` runs only under `ExtractEmbedded`, so NO trailer
// record surfaces — but `ProcessMOV` STILL raises the always-on `[minor] Insta360
// trailer at offset 0x8c (442 bytes)` warning (QuickTime.pm:10600) on reaching the
// trailer, present in EVERY mode. Pins that the trailer emission is `-ee`-gated for
// records yet the positional warning is unconditional.
#[test]
fn insta360_noee_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_insta360.mp4",
    "QuickTime_insta360.mp4.json",
    NO_EXCL,
  );
}

// A trailer whose declared `trailerLen` (1582) EXCEEDS the file size (582 bytes)
// — the QuickTimeStream.pl:3277 bad-size branch. `ProcessInsta360` raises "Bad
// Insta360 trailer size" internally, but `ProcessMOV`'s POSITIONAL trailer
// warning (QuickTime.pm:10600) fires FIRST whenever a trailer is identified, and
// ExifTool's priority-0 first-wins keeps it — so the ONLY `-j` warning is the
// positional one, with the WRAPPED (negative→unsigned) offset
// `0xfffffffffffffc18` (= 582 − 1582 = −1000 as u64) and the declared 1582-byte
// size. No trailer records surface (the walk decodes nothing past the bad-size
// check). Pins that exifast emits the wrapped-offset positional warning, NOT
// "Bad Insta360 trailer size". Byte-exact at no-`-ee` (G1) and at `-ee` (G1+G3),
// all of which carry only the positional warning.
#[test]
fn insta360_badtrailer_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_insta360_badtrailer.mp4",
    "QuickTime_insta360_badtrailer.mp4.json",
    NO_EXCL,
  );
  check_ee(
    "QuickTime_insta360_badtrailer.mp4",
    "QuickTime_insta360_badtrailer.mp4.ee.json",
    false,
  );
  check_ee(
    "QuickTime_insta360_badtrailer.mp4",
    "QuickTime_insta360_badtrailer.mp4.ee.g3.json",
    true,
  );
}

// A trailer-bearing QuickTime file SHORTER than the 78-byte `ProcessInsta360`
// footer: a recognized `ftyp` + ONLY the 40-byte EOF-40 `IdentifyTrailers`
// locator (`[trailerLen:u32][4 opaque][32-byte magic]`), 64 bytes total.
// ExifTool's EOF-40 locator (QuickTime.pm:9897-9926) still IDENTIFIES the
// trailer — emitting the positional `[minor] … trailer at offset 0x18 (40
// bytes)` warning and bounding the box walk to the trailer start (so only
// `ftyp` decodes, no `moov`) — but `ProcessInsta360`'s `Seek(-78)` fails on the
// <78-byte file so NO records decode. Pins that exifast identifies via the
// 40-byte locator (NOT the 78-byte footer): without that, a 40..77-byte trailer
// would be missed, losing the warning and leaving the box/freeGPS scans to
// consume trailer bytes. Byte-exact at no-`-ee` (G1) and `-ee` (G1+G3).
#[test]
fn insta360_shorttrailer_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_insta360_shorttrailer.mp4",
    "QuickTime_insta360_shorttrailer.mp4.json",
    NO_EXCL,
  );
  check_ee(
    "QuickTime_insta360_shorttrailer.mp4",
    "QuickTime_insta360_shorttrailer.mp4.ee.json",
    false,
  );
  check_ee(
    "QuickTime_insta360_shorttrailer.mp4",
    "QuickTime_insta360_shorttrailer.mp4.ee.g3.json",
    true,
  );
}

// A valid trailer carrying NON-MULTIPLE fixed-stride records — the
// QuickTimeStream.pl:3355-3357 `if ($len % $dlen and $id != 0x700)` branch. The
// trailer holds a 0x400 exposure record of 17 bytes (one 16-byte row + 1
// trailing byte) and a 0x600 videotimestamp record of 9 bytes (one 8-byte row +
// 1 trailing byte) alongside a VALID 0x700 GPS fix + 0x101 identity. A
// fixed-stride record whose post-cap length is NOT a multiple of its stride
// (0x300/0x400/0x600; 0x700 EXEMPT) decodes ZERO rows in bundled (the `elsif`
// decode is skipped) and raises only `Unexpected Insta360 record 0x%x length` —
// a `Trailer`/`Insta360` `Warning` (priority-0 first-wins), NOT
// `ExifTool:Warning`. So the `-ee` oracle surfaces the GPS fix (Doc1) + identity
// (sticky Doc1) + the FIRST such warning (0x600, walked first → collapses the
// later 0x400 one) and NO ExposureTime / VideoTimeStamp / TimeCode rows. Pins
// (1) the non-multiple records emit no rows and (2) the warning is group-scoped
// `Insta360:Warning` riding the sticky `Doc<N>` (`Doc1` at `-G3`). At no-`ee`,
// only the positional `ExifTool:Warning` (records decode only under `-ee`).
// Byte-exact at no-`ee` (G1) and `-ee` (G1+G3).
#[test]
fn insta360_badstride_non_multiple_records_emit_no_rows_byte_exact() {
  check_noee_excluding(
    "QuickTime_insta360_badstride.mp4",
    "QuickTime_insta360_badstride.mp4.json",
    NO_EXCL,
  );
  check_ee(
    "QuickTime_insta360_badstride.mp4",
    "QuickTime_insta360_badstride.mp4.ee.json",
    false,
  );
  check_ee(
    "QuickTime_insta360_badstride.mp4",
    "QuickTime_insta360_badstride.mp4.ee.g3.json",
    true,
  );
}

// A 0x300 accelerometer record with a SHORT 10-byte body — a length that is a
// multiple of NEITHER 20 nor 56 — FOLLOWED by a 0x700 GPS fix + 0x101 identity.
// Pins the QuickTimeStream.pl:3327-3346 else-branch stride probe semantics (R8):
// that probe is `$raf->Read($buff, 20)` against the RAF (the FILE), NOT the
// record's own body, so it reads PAST the short body into the following
// footer/record bytes and SUCCEEDS whenever ≥ 20 bytes remain to EOF. Because
// records follow the 0x300 here, the probe succeeds → picks a stride (20/56) →
// the 10-byte record's `len % stride != 0` raises `Unexpected Insta360 record
// 0x300 length` (a `Trailer`/`Insta360` `Warning`, priority-0 first-wins, riding
// the sticky `Doc1` the GPS fix left) and decodes ZERO accel rows — it is NOT
// silently skipped. (A PRIOR fix wrongly skipped a sub-19-byte body silently;
// the genuine `$dlen == 0` silent skip happens ONLY when that `Read(20)` FAILS,
// i.e. fewer than 20 bytes remain to EOF, which a 0x300 followed by more records
// can never trigger.) The GPS 'A' fix (Doc1) + the identity (sticky Main) still
// extract. At no-`ee`: only the positional `ExifTool:Warning` (records decode
// only under `-ee`). Byte-exact at no-`ee` (G1) and `-ee` (G1+G3).
#[test]
fn insta360_short300_read20_reads_past_body_warns_byte_exact() {
  check_noee_excluding(
    "QuickTime_insta360_short300.mp4",
    "QuickTime_insta360_short300.mp4.json",
    NO_EXCL,
  );
  check_ee(
    "QuickTime_insta360_short300.mp4",
    "QuickTime_insta360_short300.mp4.ee.json",
    false,
  );
  check_ee(
    "QuickTime_insta360_short300.mp4",
    "QuickTime_insta360_short300.mp4.ee.g3.json",
    true,
  );
}

// The SAME valid Insta360 trailer followed by an (empty) LigoGPS trailer, so the
// Insta360 trailer is NOT the final block. ExifTool's `IdentifyTrailers`
// (QuickTime.pm:9897-9926) is a BACKWARD linked-list walk: it reads 40 bytes at
// EOF, recognizes the LigoGPS signature (`&&&&` + a BE u32 length), steps PAST
// the 8-byte LigoGPS block, re-reads, and now recognizes the Insta360 signature
// — so the non-last Insta360 trailer is STILL found and fully decoded. The
// EARLIEST (Insta360) trailer is the linked-list head, so `ProcessMOV` bounds
// its box walk to the Insta360 start and warns the Insta360 positional `[minor]
// Insta360 trailer at offset 0x8c (442 bytes)`. exifast does not extract LigoGPS
// (and an empty one has nothing to extract), so the output is byte-IDENTICAL to
// the standalone `QuickTime_insta360.mp4` fixture: full Insta360 metadata + the
// positional warning + NO LigoGPS tags. Byte-exact at no-`ee` (G1) and `-ee`
// (G1+G3). Pins the linked-list trailer discovery (without it, a non-last
// Insta360 trailer is MISSED — losing the metadata + warning + the box bound).
#[test]
fn insta360_chained_trailer_byte_exact() {
  check_noee_excluding(
    "QuickTime_insta360_chained.mp4",
    "QuickTime_insta360_chained.mp4.json",
    NO_EXCL,
  );
  check_ee(
    "QuickTime_insta360_chained.mp4",
    "QuickTime_insta360_chained.mp4.ee.json",
    false,
  );
  check_ee(
    "QuickTime_insta360_chained.mp4",
    "QuickTime_insta360_chained.mp4.ee.g3.json",
    true,
  );
}

// A `moov` whose DECLARED size SPANS into the Insta360 trailer (but stays within
// the file). ExifTool's `ProcessMOV` walks top-level atoms by their DECLARED
// size (QuickTime.pm:10597-10602): the over-large `moov` is read in full (mvhd +
// the first trailer bytes), and walking that buffer the trailer's first record
// bytes parse as a contained atom `(size=0x0a0d4958, tag='SE12')` whose huge
// size overruns the buffer ⇒ `Truncated 'SE12' data at offset 0x8c` (the unknown
// atom's skip path, :10590). After the moov the cursor is PAST the trailer
// start, so the trailer-processing loop SKIPS it (`next if $lastPos >
// $$trailer[1]`, :10656) — NO Insta360 metadata is extracted. The positional
// `[minor] Insta360 trailer …` warning is also emitted but suppressed under `-j`
// by the earlier `Truncated 'SE12'` warning (priority-0 first-wins). Pins FIX 2:
// the in-loop trailer stop + extraction gate REPLACED the old pre-bound box view
// (which truncated the spanning moov at the trailer start, mis-warning
// `Truncated 'moov'` and still extracting). Byte-exact at no-`ee` (G1) and `-ee`
// (G1+G3) — all three goldens carry exactly the `Truncated 'SE12'` warning + the
// mvhd-derived QuickTime tags + no Insta360 tags.
#[test]
fn insta360_atomspan_trailer_byte_exact() {
  check_noee_excluding(
    "QuickTime_insta360_atomspan.mp4",
    "QuickTime_insta360_atomspan.mp4.json",
    NO_EXCL,
  );
  check_ee(
    "QuickTime_insta360_atomspan.mp4",
    "QuickTime_insta360_atomspan.mp4.ee.json",
    false,
  );
  check_ee(
    "QuickTime_insta360_atomspan.mp4",
    "QuickTime_insta360_atomspan.mp4.ee.g3.json",
    true,
  );
}

// The REAL Sony FX3 `.mp4` rtmd metadata track (#76). Unlike the synthetic
// `.mov` fixtures (a hand-built minimal `moov`), this is a genuine `ILME-FX3`
// clip: a full `moov` — video (Track1) + audio (Track2) + `rtmd` timed-metadata
// (Track3) — whose `mdat` precedes the `moov` and whose rtmd `stsz` is a
// FIXED-size table (`sample-size = 11264`, `count = 24`, body exactly 12 bytes).
// The rtmd track is a `meta`-handler `trak` (`stsd` 4cc `rtmd`); sample 1
// carries the FX3 camera scalars (FNumber/FrameRate/ExposureTime/
// MasterGainAdjustment/ISO/ElectricalExtenderMagnification/SerialNumber/
// WhiteBalance/DateTime) plus the `PitchRollYaw`/`Accelerometer` IMU arrays. No
// GPS on this clip. ExifTool collapses the duplicate samples to ONE record at
// `-ee -G1`.
//
// Every Sony `rtmd` payload tag — FNumber … Accelerometer, plus the structural
// `Track3:MetaFormat` (the stsd rtmd 4cc) and the sample-table `Track3:
// SampleTime`/`SampleDuration` — is compared BYTE-EXACT. The decode is enabled
// by the `parse_stsz` precedence fix (the Perl `length > 12` guard gates
// `stz2`, NOT `stsz`; the 12-byte fixed-size rtmd `stsz` must still expand to
// `($sz) x $num`).
//
// EXCLUDED ([`FX3_STRUCT_EXCL`]) are the GENERAL-QuickTime container tags this
// Sony-rtmd port does not target — the `vide`/`soun` `stsd` sample-description
// fields (BitDepth/Compressor*/GraphicsMode/OpColor/SourceImage*/XResolution/
// YResolution/VideoFrameRate, Audio*/Balance), the per-`trak`
// HandlerDescription/TrackProperty, the `tref` `ContentDescribes`, and the
// `mvhd`-region `TimeZone`. They are absent from the synthetic `.mov` goldens
// (minimal `moov`) and are a deferred structural-decode item, NOT an rtmd gap.
// The `-ee` run ALSO excludes `Track3:Warning` "Error reading meta data [x22]":
// that is `ProcessSamples`' GENERIC short-read diagnostic
// (QuickTimeStream.pl:1438 `$et->Warn("Error reading $type data")`) for the 22
// rtmd samples whose fixed-size offsets run past EOF — a per-track read-error
// channel exifast does not yet model (it skips a past-EOF sample). The no-`ee`
// `Track3:Warning` "[minor] The ExtractEmbedded option may find more tags…"
// already matches byte-exact, so the no-`ee` test does NOT exclude it.
const FX3_STRUCT_EXCL: &[&str] = &[
  "TimeZone",
  "BitDepth",
  "CompressorID",
  "CompressorName",
  "GraphicsMode",
  "OpColor",
  "SourceImageWidth",
  "SourceImageHeight",
  "XResolution",
  "YResolution",
  "VideoFrameRate",
  "AudioFormat",
  "AudioChannels",
  "AudioBitsPerSample",
  "AudioSampleRate",
  "Balance",
  "HandlerDescription",
  "TrackProperty",
  "ContentDescribes",
];

/// `FX3_STRUCT_EXCL` plus `Track3:Warning` — the `-ee` short-read diagnostic
/// (`Error reading meta data [x22]`) for the past-EOF rtmd samples, a per-track
/// read-error channel exifast does not yet model.
const FX3_EE_EXCL: &[&str] = &[
  "TimeZone",
  "BitDepth",
  "CompressorID",
  "CompressorName",
  "GraphicsMode",
  "OpColor",
  "SourceImageWidth",
  "SourceImageHeight",
  "XResolution",
  "YResolution",
  "VideoFrameRate",
  "AudioFormat",
  "AudioChannels",
  "AudioBitsPerSample",
  "AudioSampleRate",
  "Balance",
  "HandlerDescription",
  "TrackProperty",
  "ContentDescribes",
  "Warning",
];

#[test]
fn sony_fx3_rtmd_mp4_ee_byte_exact() {
  // `-ee -G1`: the duplicate full samples (the rtmd chunk offset `0x24` is read
  // by BOTH chunk-1 sample 1 AND chunk-2 sample 13 — `stsc` = 12 samples/chunk,
  // 2 chunks) collapse to ONE record. Every rtmd payload tag is byte-exact.
  check_ee_excluding(
    "QuickTime_sony_fx3_rtmd.mp4",
    "QuickTime_sony_fx3_rtmd.mp4.ee.json",
    false,
    FX3_EE_EXCL,
  );
  // The `-ee -G3:1` Doc-axis golden is NOT asserted: it depends on the same
  // unmodeled partial/past-EOF sample handling as `Track3:Warning`. The fixed-
  // size rtmd `stsz` (24 samples × 11264 B all from offset `0x24`) lays samples
  // back-to-back, so samples 2 and 14 PARTIAL-read the file tail (2239 B of the
  // trailing `moov`) and samples 3-12 / 15-24 read 0 B past EOF. ExifTool opens
  // a `Doc<N>` for every sample that read ≥1 byte and emits its timing-only
  // `SampleTime`/`SampleDuration` (golden Docs: 1 full, 2 timing-only, 3 full,
  // 4 timing-only). exifast SKIPS a past-EOF/partial sample wholesale
  // (`data.get(start..start+size)` → `None` → `continue` in `process_samples`),
  // so it opens only the 2 FULL-read docs and numbers them 1/2 — a different
  // Doc multiset the name-tail exclusion cannot reconcile. Modeling the
  // ExifTool clamp-and-parse (partial read → warn `Error reading meta data`,
  // open a timing-only doc, parse the clamped bytes) is the deferred per-track
  // read-error feature noted on `FX3_EE_EXCL`'s `Warning`; the `-G1` record
  // above is the byte-exact rtmd proof.
}

#[test]
fn sony_fx3_rtmd_mp4_noee_warning_byte_exact() {
  check_noee_excluding(
    "QuickTime_sony_fx3_rtmd.mp4",
    "QuickTime_sony_fx3_rtmd.mp4.json",
    FX3_STRUCT_EXCL,
  );
}
