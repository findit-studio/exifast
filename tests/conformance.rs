//! §4 conformance: `exifast::extract_info` output must be VALUE-EQUIVALENT to
//! the bundled-ExifTool golden for every ported fixture, for both the default
//! (`-j -G1 -struct`) and `-n` snapshots. The gate is the value-semantic
//! [`json_equivalent`] (`src/jsondiff.rs`): object key ORDER is insensitive,
//! the key MULTISET must match, array order IS significant, and scalars compare
//! by VALUE — `1 == 1.0`, `"123" == 123`, `3.4e+38 == 3.4e38`. We deliberately
//! do NOT compare scalar TOKENS or key order: the serializer uses standard
//! `serde_json` formatting, and a different valid spelling of the same value is
//! not a regression (same principle as "JSON key order doesn't matter"). One
//! case per ported format — add a `#[test]` per format as it lands (FORMATS.md
//! order).
//!
//! Gated on `feature = "json"`: the suite imports the `json`-gated `jsondiff`,
//! and `std` does NOT imply `json`, so a `--features std,id3` test build must
//! skip this whole file (the lib still builds; this is a json-output
//! conformance check).
#![cfg(feature = "json")]
use exifast::{jsondiff::json_equivalent, parser::extract_info};

/// Assert exifast's output for `fixture` is VALUE-EQUIVALENT to the committed
/// bundled-ExifTool golden `golden` via [`json_equivalent`]. `print_on` =
/// ExifTool PrintConv (`false` ⇒ `-n`).
///
/// Value-semantic (not raw byte) comparison is correct here because the
/// serializer emits STANDARD `serde_json` scalars and does not chase ExifTool's
/// `sprintf` token style; a value-equal-but-differently-spelled scalar (or a
/// reordered object key) is the same JSON value, not a regression. A genuine
/// value or structure difference — a wrong number, a missing/extra key, a
/// different array order — still fails (do NOT weaken the goldens to mask one).
fn check(fixture: &str, golden: &str, print_on: bool) {
  let root = env!("CARGO_MANIFEST_DIR");
  let data = std::fs::read(format!("{root}/tests/fixtures/{fixture}"))
    .unwrap_or_else(|e| panic!("read fixture {fixture}: {e}"));
  let want = std::fs::read_to_string(format!("{root}/tests/golden/{golden}"))
    .unwrap_or_else(|e| panic!("read golden {golden}: {e}"));
  let got = extract_info(fixture, &data, print_on);
  if let Err(e) = json_equivalent(&got, &want) {
    panic!(
      "{fixture} vs {golden}: value mismatch: {}\n--- got ---\n{got}\n\
       --- want ---\n{want}",
      e.message()
    );
  }
}

#[test]
fn aac_conformance() {
  check("AAC.aac", "AAC.aac.json", true);
  check("AAC.aac", "AAC.aac.n.json", false);
}

#[test]
fn quicktime_sp1_conformance() {
  // QuickTime port Sub-Port 1 (the box/atom walker + core structural
  // atoms). `tests/fixtures/QuickTime_sp1.mov` is a SYNTHETIC minimal
  // `.mov` exercising exactly the atoms SP1 implements: `ftyp` +
  // `moov`(`mvhd` + 2 `trak`s, each `tkhd`/`mdia`(`mdhd`/`hdlr`)) +
  // `mdat`. The real bundled `QuickTime.mov`/`QuickTime.m4a` fixtures
  // land in a later sub-port (SP1 cannot reach byte-exact parity on
  // them — most of their tags belong to SP2-SP4).
  //
  // PR #38 Codex R1/F1: the goldens are now the FULL UNSTRIPPED bundled
  // `perl exiftool -j -G1 -struct -api QuickTimeUTC=1` output — every tag
  // ExifTool emits for the ftyp/mvhd/tkhd/mdhd/mdat atoms SP1 implements
  // (MajorBrand/MinorVersion/CompatibleBrands, PreferredRate/Volume,
  // MatrixStructure, the Preview/Poster/Selection/Current time tags,
  // NextTrackID, MediaDataSize/Offset, TrackCreate/ModifyDate, TrackLayer/
  // Volume, MediaCreate/ModifyDate, …). Only the STANDARD `System:*` /
  // `Composite:*` exclusions remain (composite synthesis is deferred per
  // `[[exifast-phase2-forward-items]]`, the same uniform exclusion every
  // other format golden applies). No per-tag stripping.
  check("QuickTime_sp1.mov", "QuickTime_sp1.mov.json", true);
  check("QuickTime_sp1.mov", "QuickTime_sp1.mov.n.json", false);
}

#[test]
fn quicktime_v1_tkhd_conformance() {
  // PR #38 Codex R1/F2: a SYNTHETIC `.mov` with a VERSION-1 tkhd. The v1
  // Hook widens only the three time/duration fields (create/modify/duration,
  // +12 bytes), so ImageWidth/ImageHeight (int32u table indices 19/20) sit
  // at byte offsets 88/92 — NOT 96/100. Verified vs bundled ExifTool:
  // ImageWidth=1280, ImageHeight=720. Without the F2 fix the decoder read
  // garbage from 96/100.
  check("QuickTime_v1tkhd.mov", "QuickTime_v1tkhd.mov.json", true);
  check("QuickTime_v1tkhd.mov", "QuickTime_v1tkhd.mov.n.json", false);
}

#[test]
fn quicktime_moov_order_conformance() {
  // PR #38 Codex R1/F4 (REFUTED): a SYNTHETIC `.mov` whose `trak` precedes
  // `mvhd` inside `moov`. The `TrackDuration` durationInfo is a ValueConv
  // applied at OUTPUT time using the FINAL movie TimeScale — so the trak's
  // TrackDuration is `18000/600 = 30 s` even though the trak is parsed
  // before mvhd (verified vs bundled). Pins the final-TimeScale semantics
  // against the Codex-suggested (incorrect) parse-order threading.
  check(
    "QuickTime_moov_order.mov",
    "QuickTime_moov_order.mov.json",
    true,
  );
  check(
    "QuickTime_moov_order.mov",
    "QuickTime_moov_order.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_nested_size0_conformance() {
  // PR #38 Codex R1/F5: a SYNTHETIC `.mov` whose `moov` contains a size-0
  // `free` atom (a CONTAINED zero-size = terminator, QuickTime.pm:10036-
  // 10043) BEFORE a `trak`. Bundled ExifTool stops the contained walk at the
  // terminator, so the trailing `trak` is DROPPED (no `Track1:*` tags). A
  // top-level size-0 still extends to EOF (the `mdat`-size path). Pins the
  // top-level-vs-contained size-0 distinction.
  check(
    "QuickTime_nested_size0.mov",
    "QuickTime_nested_size0.mov.json",
    true,
  );
  check(
    "QuickTime_nested_size0.mov",
    "QuickTime_nested_size0.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_zerodate_conformance() {
  // PR #38 Codex R2/F1: a SYNTHETIC `.mov` whose mvhd/tkhd/mdhd carry RAW-ZERO
  // CreateDate/ModifyDate/Track*Date/Media*Date. The timeInfo RawConv only
  // `undef`s a zero date under `StrictDate` (QuickTime.pm:265, unimplemented +
  // off in the gen-golden config); otherwise the ValueConv
  // `ConvertUnixTime(0, …)` emits the zero sentinel "0000:00:00 00:00:00"
  // (ExifTool.pm:6776). Verified vs bundled — the zero dates are EMITTED, not
  // dropped. Without the fix the typed layer silently omitted them.
  check(
    "QuickTime_zerodate.mov",
    "QuickTime_zerodate.mov.json",
    true,
  );
  check(
    "QuickTime_zerodate.mov",
    "QuickTime_zerodate.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_m4a_conformance() {
  // PR #38 Codex R2/F2: a SYNTHETIC `.mov` with an `M4A ` major brand. The
  // QuickTime parser derives `File:FileType=M4A` AND `File:MIMEType=audio/mp4`
  // from `ftyp` (QuickTime.pm:10008 `SetFileType($ft, $mimeLookup{$ft})`).
  // M4A is ABSENT from the generic `%mimeType` table, so the engine must carry
  // the parser-supplied MIME through finalization. Verified vs bundled —
  // MIMEType=audio/mp4 (not the base MOV `video/quicktime`).
  check("QuickTime_m4a.mov", "QuickTime_m4a.mov.json", true);
  check("QuickTime_m4a.mov", "QuickTime_m4a.mov.n.json", false);
}

#[test]
fn quicktime_m4a_isom_override_conformance() {
  // PR #38 Codex R10/F1: a SYNTHETIC `.mov` with an `isom` MAJOR brand whose
  // brands resolve to MP4, plus a single `soun`-handler track and NO `vide`
  // handler. ExifTool runs a post-walk override (QuickTime.pm:10619-10624):
  // when the resolved type is MP4 AND `save_ftyp` (the major brand) matches
  // `^(iso|dash|mp42)` AND a `soun` handler exists AND no `vide` handler
  // exists, `OverrideFileType('M4A','audio/mp4')` flips the type. So this
  // audio-only `.m4a` is `File:FileType=M4A` / `File:FileTypeExtension=m4a` /
  // `File:MIMEType=audio/mp4`, while `QuickTime:MajorBrand` keeps the `isom`
  // PrintConv ("MP4 Base Media v1 …"). Verified vs bundled ExifTool 13.58 —
  // this is the ubiquitous real-world M4A audio-file fidelity case.
  check(
    "QuickTime_m4a_isom_override.mov",
    "QuickTime_m4a_isom_override.mov.json",
    true,
  );
  check(
    "QuickTime_m4a_isom_override.mov",
    "QuickTime_m4a_isom_override.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_m4v_conformance() {
  // PR #38 Codex R2/F2: a SYNTHETIC `.mov` with an `M4V ` major brand ⇒
  // `File:FileType=M4V`, `File:MIMEType=video/x-m4v` (QuickTime.pm:10008 +
  // %mimeLookup). M4V is absent from the generic `%mimeType` table; the
  // ftyp-derived MIME is carried through finalization (verified vs bundled).
  check("QuickTime_m4v.mov", "QuickTime_m4v.mov.json", true);
  check("QuickTime_m4v.mov", "QuickTime_m4v.mov.n.json", false);
}

#[test]
fn quicktime_zerotimescale_conformance() {
  // PR #38 Codex R2/F3: a SYNTHETIC `.mov` with movie TimeScale=0 and
  // Duration=1200. The durationInfo PrintConv gates on TimeScale TRUTHINESS
  // (`$$self{TimeScale} ? ConvertDuration($val) : $val`, QuickTime.pm:315) —
  // a zero TimeScale is falsy, so Duration emits the BARE raw value 1200 (not
  // a ConvertDuration string). Likewise the Preview/Poster/etc. movie-scale
  // durations emit their raw 0. Verified vs bundled.
  check(
    "QuickTime_zerotimescale.mov",
    "QuickTime_zerotimescale.mov.json",
    true,
  );
  check(
    "QuickTime_zerotimescale.mov",
    "QuickTime_zerotimescale.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_maclang_conformance() {
  // PR #38 Codex R2/F4: a SYNTHETIC `.mov` whose mdhd MediaLanguageCode is a
  // MACINTOSH numeric code (12, < 0x400). The ValueConv keeps the bare number
  // (QuickTime.pm:7280); the PrintConv maps numeric values through
  // `$ttLang{Macintosh}` (Font.pm:92-117) ⇒ 12 → "ar", with an
  // `Unknown ($val)` fallback (QuickTime.pm:7281-7285). Verified vs bundled —
  // `-j` "ar", `-n` raw 12. Without the fix `-j` leaked the raw number.
  check("QuickTime_maclang.mov", "QuickTime_maclang.mov.json", true);
  check(
    "QuickTime_maclang.mov",
    "QuickTime_maclang.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_matrixfrac_conformance() {
  // PR #38 Codex R3/F1: a SYNTHETIC `.mov` whose mvhd MatrixStructure carries
  // raw 1 in the a/d/w slots. The `Format => 'fixed32s[9]'` reads each entry
  // through GetFixed32s (ExifTool.pm:6121-6127) which divides by 0x10000 then
  // ROUNDS to 5 decimal places: 1/65536 = 1.52587890625e-05 → 2e-05. The
  // ValueConv then applies `$_ /= 0x4000` to the right column (entry 8: that
  // rounded 2e-05 / 0x4000 = 1.220703125e-09). Perl interpolates each into
  // `"@a"` via `%.15g`. Verified vs bundled —
  // `MatrixStructure: "2e-05 0 0 0 2e-05 0 0 0 1.220703125e-09"`. Without the
  // GetFixed32s rounding + `%.15g` formatting, the port emitted the full Rust
  // float `0.0000152587890625 …`.
  check(
    "QuickTime_matrixfrac.mov",
    "QuickTime_matrixfrac.mov.json",
    true,
  );
  check(
    "QuickTime_matrixfrac.mov",
    "QuickTime_matrixfrac.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_multimoov_conformance() {
  // PR #38 Codex R3/F2: a SYNTHETIC `.mov` with TWO top-level `moov` atoms.
  // The first carries the track (tkhd Duration=1200) under mvhd TimeScale=600;
  // a SECOND top-level moov overwrites the GLOBAL movie TimeScale to 300. The
  // `mvhd` TimeScale RawConv (`$$self{TimeScale} = $val`, QuickTime.pm:1384)
  // is a single global slot, last-wins; the TrackDuration durationInfo
  // ValueConv runs at OUTPUT against that FINAL value ⇒ 1200/300 = 4. Verified
  // vs bundled — `Track1:TrackDuration = 4`. Without learning every mvhd's
  // TimeScale BEFORE converting any TrackDuration the port emitted 1200/600 =
  // 2.
  check(
    "QuickTime_multimoov.mov",
    "QuickTime_multimoov.mov.json",
    true,
  );
  check(
    "QuickTime_multimoov.mov",
    "QuickTime_multimoov.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_size0_moov_conformance() {
  // PR #38 Codex R4/F1: a SYNTHETIC `.mov` = ftyp + a TOP-LEVEL size-0 `moov`
  // containing a real `mvhd`. For a top-level size-0 atom ExifTool prints
  // "extends to end of file", records the synthetic `$tag-size`/`$tag-offset`
  // tags ONLY if they exist (just `mdat`), then `last` — STOPS the walk WITHOUT
  // processing the payload (QuickTime.pm:10044-10056). So the size-0 `moov`'s
  // `mvhd` is NEVER decoded; verified vs bundled — ONLY the ftyp tags survive
  // (no CreateDate/TimeScale/Duration/tracks). Previously the size-0 atom was
  // treated as a normal extends-to-EOF Atom and the `mvhd` payload was decoded.
  check(
    "QuickTime_size0_moov.mov",
    "QuickTime_size0_moov.mov.json",
    true,
  );
  check(
    "QuickTime_size0_moov.mov",
    "QuickTime_size0_moov.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_multimoov_tracks_conformance() {
  // PR #38 Codex R4/F2: a SYNTHETIC `.mov` with TWO top-level `moov` atoms,
  // each holding ONE (byte-identical) `trak`. ExifTool's `$track` counter is a
  // `my` local of EACH moov's `ProcessMOV` invocation (QuickTime.pm:9944),
  // `++`-incremented per `trak` (QuickTime.pm:10354) — so it RESETS to 1 per
  // moov and BOTH traks become `Track1` (NOT `Track1` + `Track2`). In default
  // JSON the second `Track1` collapses on the family-1 collision; verified vs
  // bundled — a single `Track1` group, NO `Track2`. Previously the tracks were
  // flattened into one Vec and numbered with a GLOBAL `enumerate()+1`, wrongly
  // yielding `Track1` + `Track2`.
  check(
    "QuickTime_multimoov_tracks.mov",
    "QuickTime_multimoov_tracks.mov.json",
    true,
  );
  check(
    "QuickTime_multimoov_tracks.mov",
    "QuickTime_multimoov_tracks.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_multimoov_tracksdistinct_conformance() {
  // PR #38 Codex R5/F1: a SYNTHETIC `.mov` with TWO top-level `moov` atoms,
  // BOTH numbering their lone `trak` as `Track1`, but carrying DISTINCT tags:
  // moov1's `Track1` comes from a bare `tkhd` (TrackID=7, TrackDuration,
  // TrackLayer/Volume, MatrixStructure, ImageWidth/Height, …) while moov2's
  // `Track1` comes from a bare `mdia`(`mdhd`/`hdlr`) (MediaTimeScale=90000,
  // MediaDuration, MediaLanguageCode, HandlerType, …). ExifTool's `%noDups`
  // first-wins collision is per rendered tag KEY (`(family-1 group, tag name)`),
  // NOT per group: verified vs bundled — the single `Track1` group carries BOTH
  // moov1's TrackID and moov2's MediaTimeScale/MediaDuration/HandlerType. The
  // R4/F2 serializer wrongly `continue`d the ENTIRE later same-group track,
  // dropping every Media* tag. (TrackDuration = 1200/300 = 4 — the FINAL global
  // TimeScale=300 from moov2's mvhd, last-wins, R3/F2.)
  check(
    "QuickTime_multimoov_tracksdistinct.mov",
    "QuickTime_multimoov_tracksdistinct.mov.json",
    true,
  );
  check(
    "QuickTime_multimoov_tracksdistinct.mov",
    "QuickTime_multimoov_tracksdistinct.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_size0_mdat_first_conformance() {
  // PR #38 Codex R5/F2: a SYNTHETIC `.mov` whose VERY FIRST top-level atom is
  // `size == 0, type = mdat` (extends to EOF). ExifTool's first-atom recognition
  // gate (QuickTime.pm:9984 `$$tagTablePtr{$tag} or return 0`) keys on the
  // 4-byte `$tag` REGARDLESS of size, so `mdat` is recognized → FileType MOV;
  // the per-atom loop then treats the size-0 `mdat` as extends-to-EOF, records
  // the synthetic `mdat-size`/`mdat-offset` (QuickTime.pm:10044-10056), and
  // `last`. Verified vs bundled — FileType MOV + MediaDataSize=32 (40-byte file,
  // 8-byte header) + MediaDataOffset=8, nothing else. The port previously
  // rejected the file at the first-atom gate (which accepted only
  // `HeaderOutcome::Atom`, not a top-level size-0 `ExtendsToEof`) and returned
  // `Ok(None)`, losing the QuickTime result entirely.
  check(
    "QuickTime_size0_mdat_first.mov",
    "QuickTime_size0_mdat_first.mov.json",
    true,
  );
  check(
    "QuickTime_size0_mdat_first.mov",
    "QuickTime_size0_mdat_first.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_multimoov_movdur_conformance() {
  // PR #38 Codex R6/F1: a SYNTHETIC `.mov` with TWO top-level `moov` atoms.
  // moov1's `mvhd` has TimeScale=600 + Duration=3000; moov2's `mvhd` is a
  // SHORT 16-byte header carrying only version/create/modify/TimeScale=300 —
  // NO Duration field. The movie `Duration` is a `%durationInfo` tag whose
  // ValueConv `$val / $$self{TimeScale}` runs at OUTPUT against the FINAL
  // global movie TimeScale (last-wins, 300) — and an absent Duration in the
  // later short `mvhd` must NOT erase moov1's found count. Verified vs
  // bundled: `QuickTime:Duration = "10.00 s"` (3000 / 300), with
  // MovieHeaderVersion/CreateDate/ModifyDate/TimeScale from moov2 (last-wins
  // for the fields it DOES carry). The port previously converted Duration at
  // `mvhd` decode against the SAME mvhd's TimeScale and let the short moov2
  // overwrite the field with `None`.
  check(
    "QuickTime_multimoov_movdur.mov",
    "QuickTime_multimoov_movdur.mov.json",
    true,
  );
  check(
    "QuickTime_multimoov_movdur.mov",
    "QuickTime_multimoov_movdur.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_trunc_ftyp_conformance() {
  // PR #38 Codex R6/F2: a 12-byte file whose first atom is `ftyp` with a
  // DECLARED size of 100 — the header is intact but the brand payload
  // overruns EOF. ExifTool gates the format on the 4-byte `$tag` ALONE
  // (QuickTime.pm:9984), so the file IS QuickTime: `$tag eq 'ftyp' and $size
  // >= 12` runs, the short brand read fails, `$fileType` stays undef and
  // defaults to MP4 (QuickTime.pm:10004), then the `Truncated 'ftyp' data`
  // warning stops the walk. Verified vs bundled: FileType=MP4 +
  // `ExifTool:Warning = "Truncated 'ftyp' data (missing 92 bytes)"`, no
  // `QuickTime:*` tags. The port previously rejected the file outright (the
  // payload-bounds check returned `None` at the first-atom gate).
  check(
    "QuickTime_trunc_ftyp.mov",
    "QuickTime_trunc_ftyp.mov.json",
    true,
  );
  check(
    "QuickTime_trunc_ftyp.mov",
    "QuickTime_trunc_ftyp.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_overrun_mdat_conformance() {
  // PR #38 Codex R6/F2: a 12-byte file whose first atom is `mdat` with a
  // DECLARED size of 100. ExifTool records the synthetic `mdat-size` /
  // `mdat-offset` from the DECLARED size BEFORE the short payload read
  // (QuickTime.pm:10156-10158); `mdat` is `Unknown` so `GetTagInfo` returns
  // undef and the seek-past `else` branch fires `Truncated 'mdat' data at
  // offset 0x0` (QuickTime.pm:10590). Verified vs bundled: FileType=MOV +
  // MediaDataSize=92 + MediaDataOffset=8 + the truncation warning. The port
  // previously rejected the file at the first-atom gate.
  check(
    "QuickTime_overrun_mdat.mov",
    "QuickTime_overrun_mdat.mov.json",
    true,
  );
  check(
    "QuickTime_overrun_mdat.mov",
    "QuickTime_overrun_mdat.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_dupmdhd_conformance() {
  // PR #38 Codex R7/F1: a SYNTHETIC `.mov` whose `moov/trak/mdia` holds TWO
  // `mdhd` atoms — a FULL mdhd (TimeScale=600, Duration=1200) followed by a
  // SHORT 16-byte mdhd carrying only version/create/modify/TimeScale=300, NO
  // Duration field. `MediaDuration`/`MediaTimeScale` are per-track binary-data
  // fields; bundled ExifTool never erases an earlier FoundTag when a later
  // field is absent. Verified vs bundled: `Track1:MediaDuration = "2.00 s"`
  // (the FULL mdhd's 1200/600, NOT erased) + `Track1:MediaTimeScale = 300`
  // (the short mdhd's, last-wins for the field it DOES carry). The port
  // previously passed the short mdhd's absent Duration `None` into
  // `set_media_duration_seconds`, clearing the earlier 2.00 s.
  check("QuickTime_dupmdhd.mov", "QuickTime_dupmdhd.mov.json", true);
  check(
    "QuickTime_dupmdhd.mov",
    "QuickTime_dupmdhd.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_nested_trunc_mvhd_conformance() {
  // PR #38 Codex R7/F2: a SYNTHETIC `.mov` with a truncated `mvhd` CONTAINED
  // inside `moov` — the mvhd header is intact but its declared 92-byte payload
  // overruns EOF (only 4 bytes present). `walk_atoms` must surface the same
  // `Truncated '...' data` warning the top-level loop emits. Verified vs
  // bundled: `ExifTool:Warning = "Truncated 'mvhd' data (missing 88 bytes)"`.
  // The port's `walk_atoms` previously broke silently on a contained
  // `TruncatedAtom` outcome.
  check(
    "QuickTime_nested_trunc_mvhd.mov",
    "QuickTime_nested_trunc_mvhd.mov.json",
    true,
  );
  check(
    "QuickTime_nested_trunc_mvhd.mov",
    "QuickTime_nested_trunc_mvhd.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_nested_trunc_tkhd_conformance() {
  // PR #38 Codex R7/F2: a truncated `tkhd` inside `moov/trak` (declared
  // 90-byte payload, 4 bytes present). ExifTool attaches the truncation
  // warning to the CURRENT family-1 group, so it surfaces as `Track1:Warning`
  // (NOT the document-level `ExifTool:Warning`). Verified vs bundled:
  // `Track1:Warning = "Truncated 'tkhd' data (missing 86 bytes)"`.
  check(
    "QuickTime_nested_trunc_tkhd.mov",
    "QuickTime_nested_trunc_tkhd.mov.json",
    true,
  );
  check(
    "QuickTime_nested_trunc_tkhd.mov",
    "QuickTime_nested_trunc_tkhd.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_nested_trunc_mdhd_conformance() {
  // PR #38 Codex R7/F2: a truncated `mdhd` nested THREE levels deep inside
  // `moov/trak/mdia` (declared 40-byte payload, 4 bytes present). The
  // recursive `walk_atoms` surfaces the warning into the enclosing track's
  // family-1 group. Verified vs bundled:
  // `Track1:Warning = "Truncated 'mdhd' data (missing 36 bytes)"`.
  check(
    "QuickTime_nested_trunc_mdhd.mov",
    "QuickTime_nested_trunc_mdhd.mov.json",
    true,
  );
  check(
    "QuickTime_nested_trunc_mdhd.mov",
    "QuickTime_nested_trunc_mdhd.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_invalid_size_conformance() {
  // PR #38 Codex R8/F1: an 8-byte file `00000004 66747970` — the first atom's
  // 4-byte type `ftyp` is a recognized magic atom but its declared `size == 4`
  // is structurally invalid (`< 8`). ExifTool gates the format on the 4-byte
  // `$tag` ALONE (QuickTime.pm:9984) and `SetFileType`s ⇒ MOV BEFORE the
  // per-atom loop's `$size < 8` check sets `$warnStr = 'Invalid atom size'`
  // and `last`s (QuickTime.pm:10058). Verified vs bundled: FileType MOV +
  // `ExifTool:Warning = "Invalid atom size"`. The port previously rejected
  // the file outright — `read_atom_header` returned `None` for `size < 8` and
  // `parse_inner` turned that into `Ok(None)`, losing the QuickTime result.
  check(
    "QuickTime_invalid_size.mov",
    "QuickTime_invalid_size.mov.json",
    true,
  );
  check(
    "QuickTime_invalid_size.mov",
    "QuickTime_invalid_size.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_trunc_ext_hdr_conformance() {
  // PR #38 Codex R8/F1: a 12-byte file whose first atom is `size == 1 ftyp`
  // but whose 8-byte extended-size header is truncated (only 4 of 8 bytes).
  // QuickTime.pm:10059 `$raf->Read($buff,8) == 8 or $warnStr = 'Truncated
  // atom header', last` — but the 8-byte tag/size header was already read and
  // `SetFileType` already ran. Verified vs bundled: FileType MOV +
  // `ExifTool:Warning = "Truncated atom header"`. The port previously
  // returned `Ok(None)` (the truncated-extended-header path returned `None`).
  check(
    "QuickTime_trunc_ext_hdr.mov",
    "QuickTime_trunc_ext_hdr.mov.json",
    true,
  );
  check(
    "QuickTime_trunc_ext_hdr.mov",
    "QuickTime_trunc_ext_hdr.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_short_ftyp_conformance() {
  // PR #38 Codex R8/F1: an 8-byte file `00000008 66747970` — a `ftyp` first
  // atom whose RAW 32-bit `size` is `8`, i.e. `< 12`. ExifTool's file-type
  // branch `if ($tag eq 'ftyp' and $size >= 12)` FAILS (the brand path needs
  // `$size >= 12`) so it takes `else { SetFileType() }` ⇒ MOV
  // (QuickTime.pm:9986/10012). Verified vs bundled: FileType MOV. The port
  // previously defaulted a short `ftyp` to MP4 (it keyed the brand path on a
  // readable >=4-byte payload rather than the RAW 32-bit size >= 12).
  check(
    "QuickTime_short_ftyp.mov",
    "QuickTime_short_ftyp.mov.json",
    true,
  );
  check(
    "QuickTime_short_ftyp.mov",
    "QuickTime_short_ftyp.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_ext_ftyp_conformance() {
  // PR #38 Codex R8/F1: a 24-byte file whose first atom is an EXTENDED-size
  // `ftyp` (`size32 == 1`, 64-bit size 24) with the `isom` major brand.
  // ExifTool's `$size >= 12` ftyp gate sees the RAW 32-bit `$size == 1` (the
  // 64-bit decode happens later, INSIDE the per-atom loop), so it FAILS ⇒
  // `else { SetFileType() }` ⇒ MOV — even though the `isom` brand would
  // otherwise resolve to MP4. The brand is still decoded from the (valid)
  // extended-size atom walk. Verified vs bundled: FileType MOV +
  // `QuickTime:MajorBrand = "MP4 Base Media v1 [IS0 14496-12:2003]"` +
  // `QuickTime:MinorVersion = "0.0.0"`. The port previously resolved the
  // file type from the normalized payload brand and wrongly yielded MP4.
  check(
    "QuickTime_ext_ftyp.mov",
    "QuickTime_ext_ftyp.mov.json",
    true,
  );
  check(
    "QuickTime_ext_ftyp.mov",
    "QuickTime_ext_ftyp.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_ftyp_first_qt_conformance() {
  // PR #38 Codex R9/F1: a `ftyp` whose major brand is `isom`, minor version 0,
  // and FIRST compatible brand is `qt  `. ExifTool's compatible-brand regex
  // `/^.{8}(.{4})+(qt  )/s` (QuickTime.pm:10000) skips the major brand + minor
  // version via `^.{8}`, then `(.{4})+` requires ONE OR MORE 4-byte slots
  // BEFORE the matched brand — so a `qt  ` in the FIRST compatible-brand slot
  // (buffer offset 8) can NOT trigger the match. `$fileType` stays undef ⇒
  // `$fileType or $fileType = 'MP4'` (QuickTime.pm:10004). Verified vs bundled:
  // FileType MP4 (not MOV). The port previously scanned every slot from offset
  // 8 and returned MOV on the first `qt  ` it saw.
  check(
    "QuickTime_ftyp_first_qt.mov",
    "QuickTime_ftyp_first_qt.mov.json",
    true,
  );
  check(
    "QuickTime_ftyp_first_qt.mov",
    "QuickTime_ftyp_first_qt.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_nested_invalid_mvhd_conformance() {
  // PR #38 Codex R9/F2: a `moov` containing an `mvhd` whose declared
  // `size == 4` is structurally invalid (`< 8`). ExifTool runs the same
  // `ProcessMOV` per-atom `for(;;)` loop on the contained `moov` directory
  // (QuickTime.pm:10035-10075), so the `size < 8` check sets `$warnStr =
  // 'Invalid atom size'` and `last`s; the warning is emitted at the
  // directory's exit. Verified vs bundled: `ExifTool:Warning = "Invalid atom
  // size"`. The port's `walk_atoms` previously treated a contained
  // `HeaderOutcome::Malformed` like a size-0 terminator — a SILENT break.
  check(
    "QuickTime_nested_invalid_mvhd.mov",
    "QuickTime_nested_invalid_mvhd.mov.json",
    true,
  );
  check(
    "QuickTime_nested_invalid_mvhd.mov",
    "QuickTime_nested_invalid_mvhd.mov.n.json",
    false,
  );
}

#[test]
fn quicktime_nested_invalid_tkhd_conformance() {
  // PR #38 Codex R9/F2: a `tkhd` with an invalid declared `size == 4` inside
  // `moov/trak`. ExifTool attaches the `Invalid atom size` warning to the
  // CURRENT family-1 group — the `trak`'s `Track#` — so it surfaces as
  // `Track1:Warning`, NOT the document-level `ExifTool:Warning`. Verified vs
  // bundled: `Track1:Warning = "Invalid atom size"`.
  check(
    "QuickTime_nested_invalid_tkhd.mov",
    "QuickTime_nested_invalid_tkhd.mov.json",
    true,
  );
  check(
    "QuickTime_nested_invalid_tkhd.mov",
    "QuickTime_nested_invalid_tkhd.mov.n.json",
    false,
  );
}

#[test]
fn matroska_conformance() {
  // FORMATS.md row 23. `tests/fixtures/Matroska.mkv` is the bundled
  // `lib/Image/ExifTool/t/images/Matroska.mkv` (507 bytes, video+audio
  // tracks with `DocType="matroska"`). Goldens are bundled
  // `perl exiftool -j -G1:1 -api struct=1` output with `System:*` and
  // `Composite:*` stripped uniformly (matching every other format
  // conformance — composite-tag system is deferred per
  // `[[exifast-phase2-forward-items]]`).
  check("Matroska.mkv", "Matroska.mkv.json", true);
  check("Matroska.mkv", "Matroska.mkv.n.json", false);
}

#[test]
fn matroska_simpletag_conformance() {
  // PR #31 R1 finding F1 — Tags → SimpleTag → TagName/TagString
  // mapping via `Image::ExifTool::Matroska::StdTag` (Matroska.pm:750-
  // 891). Synthetic fixture: EBMLHeader + Segment[Info + Tracks +
  // Tags[Tag[SimpleTag(TITLE, "Hello World"), SimpleTag(ARTIST, "Test
  // Artist"), SimpleTag(DATE_RELEASED, "2010-01-15")]]]. Exercises the
  // StdTag canonical-name lookup (TITLE→Title, ARTIST→Artist,
  // DATE_RELEASED→DateReleased + dateInfo separator conversion).
  // Goldens captured with `perl exiftool -j -G1:1 -api struct=1
  // -x System:all -x Composite:all`.
  check(
    "Matroska_simpletag.mkv",
    "Matroska_simpletag.mkv.json",
    true,
  );
  check(
    "Matroska_simpletag.mkv",
    "Matroska_simpletag.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_unknown_segment_conformance() {
  // PR #31 R1 finding F2 — unknown-size master element handling
  // (Matroska.pm:1073-1085, 1114). Synthetic fixture: EBMLHeader +
  // Segment(size = unknown-8-byte-VINT)[Info + Tracks]. Without F2
  // the walker breaks on the unknown-size VINT after EBMLHeader and
  // emits ONLY File:* + EBMLHeader children (losing Info + Tracks).
  // With F2 the walker descends the unknown-size Segment using the
  // parent's end (here EOF) as the effective bound, faithful to
  // Matroska.pm:1073 `$size = 1e20` for unknown-size masters.
  check(
    "Matroska_unknown_segment.mkv",
    "Matroska_unknown_segment.mkv.json",
    true,
  );
  check(
    "Matroska_unknown_segment.mkv",
    "Matroska_unknown_segment.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_cluster_skip_conformance() {
  // PR #31 R1 finding F3 — Cluster default-skip (Matroska.pm:1096-
  // 1105). Synthetic fixture: EBMLHeader + Segment[Info + Cluster
  // (with Timecode + SimpleBlock body) + Tags]. Bundled DEFAULT
  // behavior is to `last` the walker at the first Cluster (no
  // `-v`/`-U > 1`/`-ee`), so Tags AFTER Cluster MUST NOT be emitted —
  // matches our `Kind::SkipBody` → `break` semantics. Verifies we
  // emit Info:* but neither walk into Cluster's body (SimpleBlock
  // would emit nothing anyway since it's NoSave) nor pick up the
  // Tags AFTER Cluster.
  check(
    "Matroska_cluster_skip.mkv",
    "Matroska_cluster_skip.mkv.json",
    true,
  );
  check(
    "Matroska_cluster_skip.mkv",
    "Matroska_cluster_skip.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_negative_subsecond_date_conformance() {
  // PR #31 R2 finding companion fixture — pre-2001 DateUTC (signed
  // nanoseconds < 0) exercises BOTH (a) the EBML 8-byte signed-decode
  // f64-promotion loss (`Matroska.pm:1184-1191` — Perl's `$val * 256 +
  // $byte` accumulator promotes IV→NV at ~2^64 magnitude, so the
  // post-subtract `$val` is OFF FROM THE EXACT INTEGER by ~256), and
  // (b) the fractional-second `$frac < 0 → frac += 1, $itime -= 1`
  // correction branch in `ExifTool.pm:6782`.
  //
  // Synthetic fixture: raw_ns = -1_500_000_000 (1.5 s before Matroska
  // epoch). Bundled-Perl emits "2000:12:31 23:59:58.499999762Z" — the
  // `.499999762` (not `.5`) is Perl's deliberate decode loss; our
  // `convert_matroska_date` replays it via `(raw_ns as u64) as f64 -
  // 2^64` for byte-exact match.
  check(
    "Matroska_negative_subsecond_date.mkv",
    "Matroska_negative_subsecond_date.mkv.json",
    true,
  );
  check(
    "Matroska_negative_subsecond_date.mkv",
    "Matroska_negative_subsecond_date.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_subsecond_date_conformance() {
  // PR #31 R2 finding — `Value::Date` rendering used `as i64` casting on
  // `secs_unix` (f64), silently dropping the subsecond component that
  // Perl's `ConvertUnixTime($t, undef, -9) . 'Z'` preserves
  // (ExifTool.pm:6773-6800 fractional branch + `dec=-9` trim). The
  // bundled Matroska.mkv fixture's DateTimeOriginal carries integer
  // nanoseconds (`2010:02:03 21:17:48Z` — no fractional), so the
  // original conformance didn't catch the loss.
  //
  // Synthetic fixture: minimal EBMLHeader + Segment[Info[TimecodeScale,
  // MuxingApp, WritingApp, DateUTC = 286_658_268_123_456_789]] →
  // post-Matroska-offset `$t = 1264965468.123456789` → bundled-Perl
  // emits `"2010:01:31 19:17:48.123456717Z"` (the `.717` instead of
  // `.789` is the inherent f64 precision loss of Perl's `$val / 1e9`,
  // which our `convert_matroska_date` faithfully transliterates).
  //
  // Goldens captured with `EXIFTOOL=...exiftool tools/gen_golden.sh
  // Matroska_subsecond_date.mkv` — UNTRIMMED; the synthetic body is so
  // minimal there are no System:* / Composite:* tags emitted by Perl
  // for this fixture (gen_golden.sh strips fs-dependent System fields).
  check(
    "Matroska_subsecond_date.mkv",
    "Matroska_subsecond_date.mkv.json",
    true,
  );
  check(
    "Matroska_subsecond_date.mkv",
    "Matroska_subsecond_date.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_attachment_conformance() {
  // PR #31 R1 finding F5 — Binary elements (Matroska.pm:552
  // `AttachedFileData`, 695 `TagBinary`). Synthetic fixture:
  // EBMLHeader + Segment[Info + Tracks + Attachments[AttachedFile
  // (Name=cover.jpg, MIME=image/jpeg, UID=deadbeef, Data=32B)]].
  // Bundled emits AttachedFileData as
  // `"(Binary data 32 bytes, use -b option to extract)"` (identical
  // string for both `-j` and `-n` — TagValue::Bytes serialization in
  // `src/value.rs:711-716`). With pre-F5 `Kind::Skip` the binary
  // payload was silently dropped.
  check(
    "Matroska_attachment.mkv",
    "Matroska_attachment.mkv.json",
    true,
  );
  check(
    "Matroska_attachment.mkv",
    "Matroska_attachment.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_duration_before_scale_conformance() {
  // PR #31 R3 finding — Duration ValueConv (Matroska.pm:170-171)
  // `'$$self{TimecodeScale} ? $val * $$self{TimecodeScale} / 1e9 :
  // $val / 1000'`. ValueConv/PrintConv are deferred to output time
  // and read `$$self{TimecodeScale}` LAZILY (verified empirically
  // against bundled-Perl 13.58 — for files where Duration precedes
  // TimecodeScale, bundled still applies the FINAL TimecodeScale).
  //
  // Synthetic fixture: minimal EBMLHeader + Segment[Info[MuxingApp,
  // WritingApp, Duration=60000.0 raw_float, TimecodeScale=1_000_000
  // (1 ms)]] — Duration appears BEFORE TimecodeScale in the EBML
  // walk. Bundled emits `"Info:Duration": "0:01:00"` because the
  // LAST `$$self{TimecodeScale}` (1 ms) is used at output-time
  // ValueConv ⇒ `60000 * 1e6 / 1e9 = 60.0 s = "0:01:00"`. This
  // pins the order-independence semantic so a future walk-time
  // ValueConv refactor that misread Perl's deferred-eval semantics
  // would regress.
  check(
    "Matroska_duration_before_scale.mkv",
    "Matroska_duration_before_scale.mkv.json",
    true,
  );
  check(
    "Matroska_duration_before_scale.mkv",
    "Matroska_duration_before_scale.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_duration_no_scale_conformance() {
  // PR #31 R3 — Duration FALSY branch (NO TimecodeScale in the file).
  // ValueConv: `$$self{TimecodeScale} ? ... : $val / 1000` — when
  // TimecodeScale is absent, `$$self{TimecodeScale}` is `undef` ⇒
  // FALSY ⇒ fallback fires ⇒ `60000 / 1000 = 60`. PrintConv ALSO
  // gates on the same ternary ⇒ bare numeric (NOT
  // `ConvertDuration($val)`), so `-j` and `-n` BOTH emit `60`.
  //
  // Synthetic fixture: minimal EBMLHeader + Segment[Info[MuxingApp,
  // WritingApp, Duration=60000.0]] (no TimecodeScale element at all).
  check(
    "Matroska_duration_no_scale.mkv",
    "Matroska_duration_no_scale.mkv.json",
    true,
  );
  check(
    "Matroska_duration_no_scale.mkv",
    "Matroska_duration_no_scale.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_track_targeted_tag_conformance() {
  // PR #31 R4 finding F2 — Track-targeted SimpleTag misattribution
  // (Matroska.pm:1207-1216). Bundled records every `TrackUID` inside a
  // TrackEntry into `%trackNum{$val} = $$et{SET_GROUP1}` (raw bytes →
  // Track<N>); when `TagTrackUID` is later read inside `Tags/Tag/
  // Targets`, the matching raw bytes look up the mapped `Track<N>` and
  // OVERRIDE SET_GROUP1 for the duration of the enclosing `Tag` master.
  // SimpleTag children then emit under `Track<N>` instead of the
  // default file-level group.
  //
  // Synthetic fixture: TrackEntry[TrackNumber=1, TrackUID=01020304,
  // TrackType=Video] + Tags[Tag[Targets[TagTrackUID=01020304],
  // SimpleTag[TagName="TITLE", TagString="Track Title"]]]. Bundled
  // emits `Track1:TagTrackUID: "01020304"` AND `Track1:Title: "Track
  // Title"` (NOT `Matroska:TagTrackUID` / `Matroska:Title`, which is
  // what the pre-fix walker emitted).
  //
  // Lock-depth semantics: the `Tag` master's index in `Walker.ends` is
  // used as the reset trigger, faithful to Perl's
  // `$trackIndent = substr($$et{INDENT}, 0, -2)` one-level-up reset
  // (Matroska.pm:1215). Multiple sibling Tags in the same Tags section
  // can each re-set/reset independently.
  check(
    "Matroska_track_targeted_tag.mkv",
    "Matroska_track_targeted_tag.mkv.json",
    true,
  );
  check(
    "Matroska_track_targeted_tag.mkv",
    "Matroska_track_targeted_tag.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_simpletag_duplicates_conformance() {
  // PR #31 R5 finding — SimpleTag accumulator semantics. Matroska.pm:1224-
  // 1226 is `if ($$tagInfo{NoSave} or $struct) { ... $$struct{$tagName} =
  // $val if $struct; }` — i.e. plain Perl hash assignment, which is
  // OVERWRITE semantics. Two divergences from the pre-R5 Rust port:
  //   (1) The accumulator was first-wins on TagName/TagString/TagBinary —
  //       Perl is last-wins (a second-occurrence `$$struct{TagString}` would
  //       silently overwrite the first).
  //   (2) Only TagBinary/TagName/TagString routed into the struct; other
  //       leaves inside SimpleTag (e.g. `TagDefault` 0x484, `Format =>
  //       'unsigned'`, Matroska.pm:690) fell through `Kind::Unsigned` →
  //       `push_entry` → emitted as a TOP-LEVEL `Tags:TagDefault` tag.
  //       Bundled NEVER emits such children (HandleStruct, Matroska.pm:
  //       897-948, only reads TagName/TagString/TagBinary/TagLanguage — the
  //       absorbed TagDefault is silently dropped at flush time per the
  //       explicit "not currently handling TagDefault attribute" comment
  //       at Matroska.pm:929).
  //
  // Synthetic fixture: a single Tag block with TWO SimpleTags:
  //   #1: TagName="TITLE", TagString="First", TagString="Last",
  //       TagDefault=1 → bundled emits `Matroska:Title: "Last"`.
  //   #2: TagName="ARTIST", TagString="Original Artist",
  //       TagName="REPLACED_ARTIST", TagDefault=0 → bundled emits
  //       `Matroska:ReplacedArtist: "Original Artist"` (the LAST TagName
  //       binds the canonical lookup key; `REPLACED_ARTIST` is NOT in
  //       StdTag so `synthesize_tag_name` kicks in: lowercase →
  //       `replaced_artist`, ucfirst → `Replaced_artist`, then `_a` → `A`
  //       per `s/_([a-z])/\U$1/g` ⇒ `ReplacedArtist`).
  //
  // Neither golden contains `Matroska:TagDefault` (or any TagDefault
  // emission anywhere) — the pre-R5 Rust would have emitted both as
  // top-level tags.
  check(
    "Matroska_simpletag_duplicates.mkv",
    "Matroska_simpletag_duplicates.mkv.json",
    true,
  );
  check(
    "Matroska_simpletag_duplicates.mkv",
    "Matroska_simpletag_duplicates.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_chapters_conformance() {
  // PR #31 R4 finding F1 — ChapterTimeStart (0x11) + ChapterTimeEnd (0x12)
  // were `Kind::Skip` (silent drop). Bundled extracts both as
  // `Format => 'unsigned'`, `ValueConv => '$val / 1e9'`,
  // `PrintConv => 'ConvertDuration($val)'` (Matroska.pm:580-592). Group
  // attribution: each ChapterAtom (Matroska.pm:1117-1118) bumps a 1-based
  // counter and SET_GROUP1 → `Chapter<n>`, so a fixture with one
  // ChapterAtom emits `Chapter1:ChapterTimeStart`, etc.
  //
  // Two ancillary fixes wrapped into this finding:
  //   (a) The walker's ID-validity guard previously rejected ID 0
  //       (`id_v.value() <= 0` ⇒ `< 0`, faithful to Matroska.pm:1068
  //       `$tag >= 0`). ChapterDisplay's ID IS 0 (Matroska.pm:615), so
  //       any chapter content (including ChapterString) was being
  //       dropped.
  //   (b) The new `Kind::ChapterTimeNs` carries raw u64 ns through to
  //       output-time `ValueConv` + `ConvertDuration` (faithful to the
  //       deferred-eval semantics the rest of the Matroska module uses).
  //
  // Synthetic fixture: EBMLHeader + Segment[Info(TimecodeScale=1ms,
  // MuxingApp, WritingApp) + Chapters[EditionEntry[ChapterAtom[
  // ChapterTimeStart=60s in ns, ChapterTimeEnd=120s in ns, ChapterDisplay
  // [ChapterString="Intro"]]]]]. Bundled `-j` emits
  // `Chapter1:ChapterTimeStart: "0:01:00"`, ChapterTimeEnd: "0:02:00",
  // ChapterString: "Intro". Bundled `-n` emits the bare numeric seconds.
  check("Matroska_chapters.mkv", "Matroska_chapters.mkv.json", true);
  check(
    "Matroska_chapters.mkv",
    "Matroska_chapters.mkv.n.json",
    false,
  );
}

#[test]
fn matroska_duration_zero_scale_conformance() {
  // PR #31 R3 finding — the ACTUAL pre-fix bug. ValueConv:
  // `$$self{TimecodeScale} ? $val * $$self{TimecodeScale} / 1e9 :
  // $val / 1000` — PERL TRUTHINESS, so `$$self{TimecodeScale} = 0`
  // is FALSY (NOT just `undef`). Pre-R3-fix Rust code matched
  // `Some(ts) => raw * ts / 1e9` unconditionally, so `Some(0)`
  // took the WRONG branch ⇒ `60000 * 0 / 1e9 = 0`. Post-fix
  // adds an explicit `ts != 0` guard ⇒ both `None` AND `Some(0)`
  // fall through to `$val / 1000` ⇒ `60.0`. PrintConv mirrors
  // the same truthiness ⇒ bare numeric.
  //
  // Synthetic fixture: minimal EBMLHeader + Segment[Info[MuxingApp,
  // WritingApp, TimecodeScale=0, Duration=60000.0]] — TimecodeScale
  // explicitly stored as 0 (1-byte unsigned).
  check(
    "Matroska_duration_zero_scale.mkv",
    "Matroska_duration_zero_scale.mkv.json",
    true,
  );
  check(
    "Matroska_duration_zero_scale.mkv",
    "Matroska_duration_zero_scale.mkv.n.json",
    false,
  );
}

#[test]
fn wavpack_conformance() {
  // FORMATS.md row 6. Native `wvpk....` 32-byte header (no RIFF wrapper,
  // no ID3, no APE) ⇒ ProcessWV runs the WavPack::Main ProcessBinaryData
  // step (5 masked sub-tags) and the post-PBD `ProcessRIFF`/`ProcessAPE`
  // calls (WavPack.pm:97-102) emit nothing — see the orchestrator-scoped
  // deferral note in `src/formats/wavpack.rs`. Goldens captured from
  // bundled `perl exiftool`.
  check("WavPack.wv", "WavPack.wv.json", true);
  check("WavPack.wv", "WavPack.wv.n.json", false);
}

#[test]
fn wavpack_adversarial_conformance() {
  // Flags = 0xFFFFFFFF: every mask saturates ⇒ exercises the off-end of
  // every PrintConv hash (SampleRate index 15 = 'Custom' is the only
  // non-numeric entry; BytesPerSample raw=3 ⇒ +1 = 4 = the largest
  // ValueConv output). Pins that the byte-order (MM) and the mask /
  // shift derivation stay faithful even with every bit set.
  check(
    "WavPack_adversarial.wv",
    "WavPack_adversarial.wv.json",
    true,
  );
  check(
    "WavPack_adversarial.wv",
    "WavPack_adversarial.wv.n.json",
    false,
  );
}

#[test]
fn dsf_conformance() {
  // FORMATS.md row 7. Faithful DSF.pm port (1:1 of ExifTool 13.58
  // lib/Image/ExifTool/DSF.pm:55-99). The fixture is a synthesized minimal
  // valid DSF (no bundled `t/images/DSF.dsf`); see plan §3.1 for layout.
  check("DSF.dsf", "DSF.dsf.json", true);
  check("DSF.dsf", "DSF.dsf.n.json", false);
}

#[test]
fn dsf_short_fmt_warning_conformance() {
  // Pins DSF.pm:71-72 Warn + `return 1`: a DSF whose `fmtLen` violates the
  // `>12 && <1000` guard (here `fmtLen=8`) still emits File:* via
  // `SetFileType` (DSF.pm:64 runs BEFORE the guard, DSF.pm:67) plus the
  // ExifTool:Warning, and NO fmt-chunk payload tags.
  check("DSF_short.dsf", "DSF_short.dsf.json", true);
  check("DSF_short.dsf", "DSF_short.dsf.n.json", false);
}

#[test]
fn dv_conformance() {
  // FORMATS.md row 11. `tests/fixtures/DV.dv` is the bundled
  // `lib/Image/ExifTool/t/images/DV.dv` (4400 bytes, PAL 25Mbps 4:2:0,
  // 16:9 aspect, interlaced, 32 kHz audio). Goldens are bundled `perl
  // exiftool -j -G1 -struct` output with `System:*` and `Composite:*`
  // stripped uniformly (matching every other format conformance — the
  // composite-tag system is engine infrastructure outside DV.pm's
  // scope, deferred per `[[exifast-phase2-forward-items]]`).
  check("DV.dv", "DV.dv.json", true);
  check("DV.dv", "DV.dv.n.json", false);
}

#[test]
fn real_rm_conformance() {
  // FORMATS.md row 19. `tests/fixtures/Real.rm` is the bundled
  // `lib/Image/ExifTool/t/images/Real.rm` (1915 bytes). Exercises the
  // RealMedia chunk walk (PROP / MDPR×2 / CONT), the RJMD footer
  // metadata block, and the 128-byte ID3v1 trailer. The golden is bundled
  // `perl exiftool -j -G1 -struct` output with `System:*` + `Composite:*`
  // stripped uniformly (composite-tag synthesis is engine infrastructure
  // outside Real.pm's scope — deferred per `[[exifast-phase2-forward-items]]`;
  // bundled emits one Composite:DateTimeOriginal=2003 lifted from the
  // ID3v1:Year frame).
  check("Real.rm", "Real.rm.json", true);
  check("Real.rm", "Real.rm.n.json", false);
}

#[test]
fn real_ra_conformance() {
  // FORMATS.md row 19. `tests/fixtures/Real.ra` is the bundled
  // `lib/Image/ExifTool/t/images/Real.ra` (130 bytes, RealAudio V4).
  // Exercises the `.ra\xfd` magic, the V4 codec table (AudioBytes /
  // BytesPerMinute / AudioFrameSize / SampleRate / BitsPerSample /
  // Channels / Title / Copyright; the file has no Artist or Comment).
  // Goldens captured the same way as RM.
  check("Real.ra", "Real.ra.json", true);
  check("Real.ra", "Real.ra.n.json", false);
}

#[test]
fn real_synth_1audio_conformance() {
  // Codex R1 F1 adversarial — pinpoints the bundled `File:MIMEType`
  // override (Real.pm:653-657) for a 1-stream RM whose sole MDPR
  // carries `audio/x-pn-realaudio`. Bundled OVERRIDES the table-derived
  // `application/vnd.rn-realmedia` with the stream MIME (exactly the
  // override case that fires); this Rust port must agree.
  // Synthesized fixture (RMF header + PROP + 1 MDPR + DATA terminator);
  // goldens captured with `-x Composite:all`.
  check("real_synth_1audio.rm", "real_synth_1audio.rm.json", true);
  check("real_synth_1audio.rm", "real_synth_1audio.rm.n.json", false);
}

#[test]
fn real_synth_2_audio_audio_conformance() {
  // Codex R1 F1 adversarial — 2-stream RM with BOTH MIMEs populated
  // (`audio/x-pn-realaudio` each). Bundled @mimeTypes has 2 entries, so
  // the `@mimeTypes == 1` gate (Real.pm:654) fails ⇒ NO override; the
  // table-derived `application/vnd.rn-realmedia` is kept. Pins the
  // count-mismatch arm of the override branch.
  check(
    "real_synth_2_audio_audio.rm",
    "real_synth_2_audio_audio.rm.json",
    true,
  );
  check(
    "real_synth_2_audio_audio.rm",
    "real_synth_2_audio_audio.rm.n.json",
    false,
  );
}

#[test]
fn real_synth_id3v1_empty_title_conformance() {
  // Codex R1 F2 adversarial — RM + RJMD footer + ID3v1 trailer whose
  // Title slot is ALL NULL (faithful bundled `"ID3v1:Title": ""`). The
  // previous PrintConv-staged lift dropped the empty Title via
  // `nonempty()` (process.rs `stuff_id3v1_field`) and Real's
  // `emit_id3v1` skipped the tag entirely — silent metadata loss. The
  // direct-block parser
  // [`crate::formats::id3::v1::parse_id3v1_typed`] preserves
  // `Some("")` so the empty Title round-trips through `-j` and `-n`.
  check(
    "real_synth_id3v1_empty_title.rm",
    "real_synth_id3v1_empty_title.rm.json",
    true,
  );
  check(
    "real_synth_id3v1_empty_title.rm",
    "real_synth_id3v1_empty_title.rm.n.json",
    false,
  );
}

#[test]
fn real_synth_embedded_nul_mime_conformance() {
  // Codex R2 adversarial — RM whose 1 MDPR carries a StreamMimeType with
  // an EMBEDDED NUL byte (`audio/x\0pn-realaudio`). Bundled Real.pm:643
  // runs `$mime =~ s/\0.*//s` (first-NUL truncation) before pushing to
  // `@mimeTypes`, and the `Format => 'string[$val{10}]'` read at Real.pm:
  // 132-136 already truncates via ReadValue's `s/\0.*//s` at
  // ExifTool.pm:6300, so BOTH `Real-MDPR:StreamMimeType` AND
  // `File:MIMEType` (via the single-stream override at Real.pm:653-657)
  // emit the truncated `audio/x` form. Pre-fix the Rust port used
  // `strip_trailing_nuls`, which preserved the embedded NUL and leaked it
  // through both surfaces.
  check(
    "real_synth_embedded_nul_mime.rm",
    "real_synth_embedded_nul_mime.rm.json",
    true,
  );
  check(
    "real_synth_embedded_nul_mime.rm",
    "real_synth_embedded_nul_mime.rm.n.json",
    false,
  );
}

#[test]
fn real_synth_id3v1_sparse_genre_conformance() {
  // Codex R1 F2 adversarial — RM + RJMD footer + ID3v1 trailer whose
  // Genre byte is 192 (SPARSE — outside the GENRE_ENTRIES named-genre
  // table, between 191 `Psybient` and 255 `None`). Bundled emits
  // `"ID3v1:Genre": "Unknown (192)"` in `-j` mode and the raw int
  // `"ID3v1:Genre": 192` in `-n` mode. The previous PrintConv-staged
  // lift rendered `"Unknown (192)"` via the `%genre` hash fallback,
  // then the back-resolver (`id3v1_genre_byte_for_name`) failed to map
  // that string back to byte 192 — `v1.genre = None`, `v1.genre_name = None`,
  // and Real's `emit_id3v1` SKIPPED the Genre tag entirely. The
  // direct-block parser preserves the raw byte so both `-j` (rendered)
  // and `-n` (bare int) emit faithfully.
  check(
    "real_synth_id3v1_sparse_genre.rm",
    "real_synth_id3v1_sparse_genre.rm.json",
    true,
  );
  check(
    "real_synth_id3v1_sparse_genre.rm",
    "real_synth_id3v1_sparse_genre.rm.n.json",
    false,
  );
}

#[test]
fn real_synth_ram_pnm_conformance() {
  // PR #33 Copilot finding — the RAM/RPM Metafile branch (Real.pm:533-555).
  // `tests/fixtures/real_synth_ram_pnm.ram` is a synthetic RAM playlist:
  // a `pnm://` URL line, an `rtsp://` URL line, and a plain text line.
  // Exercises (1) the `RealKind::Ram` default when the extension is not
  // `RPM` (Real.pm:535-536), (2) the `^[a-z]{3,4}://` URL-vs-text split
  // (Real.pm:552 — `Real:URL` / `Real:Text`), and (3) the last-wins
  // duplicate-tag semantics: TWO `url` lines ⇒ bundled JSON keeps the
  // FINAL line (`rtsp://…/feature.rm`) as `Real:URL`. Goldens captured
  // with bundled `perl exiftool 13.58 -j -G1 -struct` (`-n` variant
  // identical — the `Real::Metafile` table has no PrintConv).
  check(
    "real_synth_ram_pnm.ram",
    "real_synth_ram_pnm.ram.json",
    true,
  );
  check(
    "real_synth_ram_pnm.ram",
    "real_synth_ram_pnm.ram.n.json",
    false,
  );
}

#[test]
fn real_synth_rpm_pnm_conformance() {
  // PR #33 Copilot finding — RAM-vs-RPM is decided ONLY by the file
  // extension (Real.pm:535-536 `$$et{FILE_EXT} eq 'RPM'`). Same kind of
  // `pnm://`-headed metafile as `real_synth_ram_pnm.ram`, but the `.rpm`
  // extension flips the typed `RealKind` to `Rpm` ⇒ `File:FileType=RPM`
  // and the RPM MIME `audio/x-pn-realaudio-plugin`. Pins that the `ext`
  // channel is threaded through `AnyParser::Real` → `parse_with_ext` →
  // `parse_metafile` (the pre-fix stub discarded `ext` and always
  // returned `RealKind::Ram`).
  check(
    "real_synth_rpm_pnm.rpm",
    "real_synth_rpm_pnm.rpm.json",
    true,
  );
  check(
    "real_synth_rpm_pnm.rpm",
    "real_synth_rpm_pnm.rpm.n.json",
    false,
  );
}

#[test]
fn real_synth_metafile_http_accept_conformance() {
  // PR #33 Copilot finding — the `http`-line acceptance gate (Real.pm:546:
  // `return 0 if $buff =~ /^http/ and $buff !~ /\.(ra|rm|rv|rmvb|smil)$/i`).
  // `real_synth_metafile_http_accept.ram`'s first non-empty line is
  // `http://…/promo.ra` — the `.ra` suffix SATISFIES the gate, so bundled
  // ACCEPTS the file as RAM. (The rejection half of the gate — an
  // `http://` line WITHOUT a Real media suffix ⇒ `return 0` ⇒ the file
  // falls through to `TXT` — is pinned by the `parse_metafile_http_*`
  // unit tests in `src/formats/real.rs`: exifast has no `Text`-module
  // parser, so a rejected metafile cannot be a conformance fixture.)
  check(
    "real_synth_metafile_http_accept.ram",
    "real_synth_metafile_http_accept.ram.json",
    true,
  );
  check(
    "real_synth_metafile_http_accept.ram",
    "real_synth_metafile_http_accept.ram.n.json",
    false,
  );
}

#[test]
fn dv_unknown_profile_conformance() {
  // Adversarial: 480-byte synthetic with the primary `\x1f\x07\0\x3f`
  // magic and `stype=0x1f` at offset 451 — never present in
  // `@dvProfiles`, so DV.pm:188 hits the `Warn("Unrecognized DV
  // profile")` branch. Faithful bundled-Perl output: `ExifTool:Warning`
  // tag + `File:*` triplet only, no `DV:*` tags. Goldens captured with
  // `-x Composite:all`.
  check("dv_unknown_profile.dv", "dv_unknown_profile.dv.json", true);
  check(
    "dv_unknown_profile.dv",
    "dv_unknown_profile.dv.n.json",
    false,
  );
}

#[test]
fn ogg_conformance() {
  // FORMATS.md row 9 (Ogg + Vorbis-comments): a real Ogg-Vorbis fixture
  // from the bundled-ExifTool corpus. The committed golden is bundled
  // `perl exiftool -j -G1 -struct ... -x Composite:all`:
  // `Composite:Duration` is the only hand-trim (Composite engine is on
  // the accepted-deferral list — see `docs/tracking.md` → "Residual
  // (still in accepted-deferral list)"). Every emitted tag —
  // including the `Vorbis:VorbisVersion` / `Vorbis:AudioChannels` /
  // `Vorbis:SampleRate` / `Vorbis:NominalBitrate` identification fields
  // ported in R2 F-OGG-TRIM — is value-equivalent to bundled Perl in both
  // PrintConv-on (default) and `-n` modes.
  check("Vorbis.ogg", "Vorbis.ogg.json", true);
  check("Vorbis.ogg", "Vorbis.ogg.n.json", false);
}

#[test]
fn malformed_ogg_error_conformance() {
  // Adversarial: a 16-byte file starting with `OggS` magic but truncated
  // before the page-header is even 27 bytes long. `.ogg` is a known
  // type ⇒ `ProcessOGG` runs, returns 0 (no valid page completed) ⇒
  // `'File format error'` (ExifTool.pm:3093). Pins that the OGG parser
  // does not "accept" without finalising a stream — symmetric with the
  // AAC `bad.aac` / `aac_profile3.aac` adversarial pattern.
  check("bad.ogg", "bad.ogg.json", true);
  check("bad.ogg", "bad.ogg.n.json", false);
}

#[test]
fn ogg_truncated_error_conformance() {
  // R1 regression pin: a 27-byte file with valid `OggS` magic but exactly
  // ONE byte short of the page-header minimum read. Bundled `Ogg.pm:94`
  // requires `$raf->Read($buff, 28) == 28` — at 27 bytes the read returns
  // 27, the `== 28` fails, the loop never enters, `$success` stays 0 ⇒
  // post-loop `'File format error'` (ExifTool.pm:3093). Pins that
  // `ProcessOgg` does NOT call `SetFileType` on a 27-byte OggS prefix
  // (the Codex round-1 F1 finding).
  check("ogg_truncated.ogg", "ogg_truncated.ogg.json", true);
  check("ogg_truncated.ogg", "ogg_truncated.ogg.n.json", false);
}

#[test]
fn ogg_vorbis_trailing_garbage_conformance() {
  // R2 regression pin (Codex round-2 [medium] disposition: finding rejected
  // as misframed — see commit message + `src/formats/ogg.rs::process_vorbis_comments`).
  //
  // Fixture: a complete two-page Ogg-Vorbis file whose comment packet is
  // `\x03vorbis` + vendor("test") + count=0 + `\x01\x02\x03` (3 trailing
  // garbage bytes) + framing-bit. Reaches `process_vorbis_comments` with
  // exactly that block.
  //
  // The Codex round-2 finding claimed bundled ExifTool emits
  // `ExifTool:Warning => 'Format error in Vorbis comments'` on this input.
  // EMPIRICAL EVIDENCE (this committed golden, captured from bundled
  // `perl exiftool`): NO `ExifTool:Warning` is emitted — only the Vorbis
  // identification fields (`VorbisVersion`/`AudioChannels`/`SampleRate`/
  // `NominalBitrate` — R2 F-OGG-TRIM port) plus `Vorbis:Vendor`.
  //
  // The reason (Vorbis.pm:157-210): `ProcessComments` reads the vendor in
  // the FIRST loop iteration (line 175 else-branch), sets `$num =
  // (pos+4 < end) ? Get32u(at count) : 0` (line 184; reads as 0 in the
  // trailing case since the count field contents are `\0\0\0\0`), then
  // unconditionally hits `$num-- or return 1` (line 205) at the end of the
  // iteration. With `$num == 0`, `$num--` returns the original 0 (falsy),
  // so `return 1` fires IMMEDIATELY — BEFORE the next iteration can run
  // `last if pos+4 > end` (line 168) that would otherwise fall through to
  // the warning at line 208. Perl therefore returns success without ever
  // reaching the warning line, and any bytes after the comment count
  // (whether 0, 3, or more) are silently ignored.
  //
  // This conformance test pins that exifast's `process_vorbis_comments`
  // matches the silent-accept behaviour. Adding a `pos != end` check
  // here (as the rejected finding proposed) would emit a warning on an
  // input Perl accepts cleanly — UNFAITHFUL by D5 and would break this
  // golden. The negative pin is the regression guard.
  check(
    "ogg_vorbis_trailing_garbage.ogg",
    "ogg_vorbis_trailing_garbage.ogg.json",
    true,
  );
  check(
    "ogg_vorbis_trailing_garbage.ogg",
    "ogg_vorbis_trailing_garbage.ogg.n.json",
    false,
  );
}

#[test]
fn ogg_vorbis_interleaved_list_conformance() {
  // R1-F2 regression pin: an Ogg-Vorbis comment block with INTERLEAVED
  // `List => 1` and non-List keys: vendor + ARTIST=Alice, TITLE=Song,
  // ARTIST=Bob, COMMENT=Foo. Bundled `perl exiftool` emits
  // `Vorbis:Artist = ["Alice","Bob"]` at the FIRST-occurrence position
  // (before Title, before Comment) — faithful FoundTag semantics
  // (ExifTool.pm:9505-9520). A previous implementation accumulated list
  // values in a HashMap and flushed alphabetically at end-of-parse, which
  // happened to coincide with bundled output for ARTIST-only fixtures
  // (alphabetical-of-one) but reordered interleaved comments. The fix
  // marks ARTIST/PERFORMER/CONTACT TagDefs with `.with_list(true)` and
  // routes them through `Metadata::push_listable` at encounter time —
  // identical seam to FLAC's Vorbis-comment path (`flac.rs:888-895`).
  //
  // R2 F-OGG-TRIM: identification-header tags (`Vorbis:VorbisVersion`,
  // `:AudioChannels`, `:SampleRate`) are now PORTED and present in the
  // golden — the R1-F2 deferral was reversed when the round-2 review
  // showed it forced new hand-trims that the 1:1 bar disallows.
  check(
    "ogg_vorbis_interleaved_list.ogg",
    "ogg_vorbis_interleaved_list.ogg.json",
    true,
  );
  check(
    "ogg_vorbis_interleaved_list.ogg",
    "ogg_vorbis_interleaved_list.ogg.n.json",
    false,
  );
}

#[test]
fn mp3_conformance() {
  // ID3-free MPEG-1 Layer III audio frame at 128 kbps / 44.1 kHz / Joint
  // Stereo (a single 417-byte frame: 4-byte header 0xfffb904c + 413 zero
  // bytes of audio payload). The bundled `perl exiftool -j -G1 -struct`
  // emits an additional `"Composite:Duration": "0.03 s (approx)"` (and
  // `0.0260625` under `-n`); both goldens here EXCLUDE that key because
  // composite tags are not yet ported (`%MPEG::Composite`, MPEG.pm:385-
  // 432 — a forward item tracked in the module header). The capture
  // suppresses it via `--Composite:Duration`.
  check("MP3.mp3", "MP3.mp3.json", true);
  check("MP3.mp3", "MP3.mp3.n.json", false);
}

#[test]
fn vbr_xing_lame_mp3_conformance() {
  // Synthesized 504-byte VBR Xing+LAME MP3. Pins the MPEG.pm:501-578 tail:
  // `%MPEG::Xing` (VBRFrames=1000, VBRBytes=200_000, VBRScale=78, Encoder=
  // "LAME3.99r", LameVBRQuality=2, LameQuality=2) and `%MPEG::Lame`
  // (LameMethod=4→"VBR (new/mtrh)", LameLowPassFilter=160→"16 kHz",
  // LameBitrate=128→"128 kbps", LameStereoMode=3→"Joint Stereo"). The
  // bundled `perl exiftool -j -G1 -struct` also emits `Composite:
  // AudioBitrate` (61.2 kbps under -j, 61250 under -n); both goldens
  // EXCLUDE that key (Composite tags are not yet ported — `%MPEG::
  // Composite` forward item) just as `mp3_conformance` excludes
  // `Composite:Duration`. The capture suppresses it via
  // `--Composite:AudioBitrate`.
  check("VBR.mp3", "VBR.mp3.json", true);
  check("VBR.mp3", "VBR.mp3.n.json", false);
}

#[test]
fn vbr_no_vbrscale_mp3_conformance() {
  // F2 (Codex R2): Xing+LAME MP3 with flags = 0x13 — VBRFrames | VBRBytes |
  // LAME, deliberately OMITTING the VBRScale flag bit (0x08). MPEG.pm:510
  // declares `my $vbrScale;` (undef); MPEG.pm:528-533 only assigns it when
  // `$flags & 0x08`. The LAME-quality calculation at MPEG.pm:563-565 then
  // evaluates `undef <= 100` in numeric context — Perl promotes undef to 0
  // with a runtime warning, so the calc runs unconditionally on the encoder
  // version: `int((100 - 0) / 10) = 10` (LameVBRQuality) and `(100 - 0) %
  // 10 = 0` (LameQuality). Bundled `perl exiftool -j -G1 -struct` confirms:
  // `LameVBRQuality=10, LameQuality=0` (with three "Use of uninitialized
  // value $vbrScale ..." warnings to STDERR). Pins the undef-as-zero
  // semantics — without the `vbr_scale.unwrap_or(0)` fallback in
  // `parse_xing_lame`'s LAME-quality arm (MPEG.pm:563-565), exifast omits
  // both LAME quality tags and this assertion fails.
  check("VBR_no_vbrscale.mp3", "VBR_no_vbrscale.mp3.json", true);
  check("VBR_no_vbrscale.mp3", "VBR_no_vbrscale.mp3.n.json", false);
}

#[test]
fn mus_layer2_conformance() {
  // Codex R3: 5-byte MUS fixture (`\xff\xfd\x90\x4c\x00`) = MPEG-1 Layer II
  // sync at 160 kbps / 44.1 kHz / Joint Stereo. Bundled `ID3::ProcessMP3`
  // dispatches `.mus` files through `ParseMPEGAudio($et, \$buff, $mp3)`
  // with `$mp3 = ($ext eq 'MUS') ? 0 : 1` (ID3.pm:1715-1717), so the
  // Layer-III-only check at MPEG.pm:485 is BYPASSED for `.mus` ⇒ Layer II
  // is accepted. Bundled `perl exiftool -j -G1 -struct
  // --System:all --Composite:all` emits `MPEG:AudioLayer=2`. exifast's
  // `ProcessMp3::process` must thread the caller `$mp3` flag through (NOT
  // recompute it from `ctx.file_type()=="MP3"`); without that, the Layer
  // III gate falsely rejects this fixture. Pins ID3.pm:1715-1717 +
  // MPEG.pm:485 caller-flag semantics.
  check("MUS_layer2.mus", "MUS_layer2.mus.json", true);
  check("MUS_layer2.mus", "MUS_layer2.mus.n.json", false);
}

#[test]
fn junk_past_8k_mp3_conformance() {
  // F1 (Codex R1): 8200 bytes of pseudo-random non-`\xff` filler followed
  // by a valid Layer III header at offset 8200. Bundled ExifTool's
  // `ID3::ProcessMP3` (ID3.pm:1704) reads only the first 8192 bytes; the
  // header at offset 8200 is outside the scan window, so the audio-frame
  // sync scan finds nothing ⇒ `ParseMPEGAudio` returns 0 ⇒ post-loop
  // `File format error` (ExifTool.pm:3093). exifast's bounded-scan
  // wrapper (`ProcessMp3::process` → ID3.pm:1684-1729) must match.
  // Without the bound, the unbounded scan would latch onto the sync byte
  // at offset 8200 and falsely accept ⇒ this test would fail.
  check("JunkPast8k.mp3", "JunkPast8k.mp3.json", true);
  check("JunkPast8k.mp3", "JunkPast8k.mp3.n.json", false);
}

#[test]
fn malformed_mp3_error_conformance() {
  // `.mp3` extension + 144 bytes that all fail the audio-frame header
  // validation (either sync-bit reject or bad bitrate). `MP3` is a known
  // type ⇒ post-loop ExifTool:Error finalizes as `File format error`
  // (ExifTool.pm:3093). Pins that `parse_mpeg_audio` returns false on
  // pure garbage AND that no File:* tags slip through (no SetFileType
  // was called).
  check("bad.mp3", "bad.mp3.json", true);
  check("bad.mp3", "bad.mp3.n.json", false);
}

#[test]
fn ogg_vorbis_specialkeys_conformance() {
  // R3 regression pin (Codex round-3 [medium] dispositions F1+F2).
  //
  // F1: `%specialTags` (ExifTool.pm:1228-1236) had been partially ported
  // as a 16-key stub including 3 keys NOT in Perl (`PARENT`, `DID_TAG_ID`,
  // `ID3`) and missing 15 that ARE in Perl (incl. `NAMESPACE`, `AVOID`,
  // `IS_OFFSET`, `LANG_INFO`, `TAG_PREFIX`, `PREFERRED`, `SHORT_NAME`,
  // `TABLE_DESC`, `IS_SUBDIR`, `EXTRACT_UNKNOWN`, `PRINT_CONV`,
  // `SRC_TABLE`, `SET_GROUP1`, `PERMANENT`, `INIT_TABLE`). For each
  // comment KEY in that set, `Vorbis.pm:180` appends `_` to the
  // synthesised tag name (so `NAMESPACE=x` ⇒ `Vorbis:Namespace_`).
  // Fixed by porting the full 28-key hash; this fixture pins seven of
  // them (`NAMESPACE`, `AVOID`, `IS_OFFSET`, `LANG_INFO`, `TAG_PREFIX`,
  // `PREFERRED`, `NOTES`) byte-exact against the bundled golden.
  //
  // F2: `underscore_camelcase` (port of Perl `s/([a-z0-9])_([a-z])/$1\U$2/g`,
  // Vorbis.pm:193) had walked positions in the ORIGINAL input string and
  // tested `bytes[i-1]` for lowercase against pre-replacement state, so
  // multi-underscore chains like `TRACK_A_B` (after ucfirst+lc =>
  // `Track_a_b`) produced `TrackAB` instead of Perl's `TrackA_b`.
  // Perl `s///g` advances `pos()` past the END of each replacement and
  // continues from there in the mutated string — so after `a_b` becomes
  // `aB`, the next character checked is the now-uppercase `B`, which
  // does NOT satisfy `[a-z0-9]` and the trailing `_b` is preserved.
  // Fixed by switching to cursor-over-MUTATED-output semantics; this
  // fixture pins `TRACK_A_B => TrackA_b`, `A_B_C_D_E => A_bC_dE`,
  // `KEY_A_LONG_NAME => KeyA_longName`, `FOO_BAR_X_Y => FooBarX_y`
  // byte-exact against the bundled golden.
  //
  // Fixture layout (323 bytes, synthetic Ogg-Vorbis, CRC-valid):
  //   - BOS page (header_type=0x02, seq=0): `\x01vorbis` identification
  //     packet (vendor`=` placeholder; channels=2, sample_rate=44100,
  //     nominal_bitrate=128000, blocksize0/1=0xB8, framing=1).
  //   - Page (header_type=0x00, seq=1): `\x03vorbis` comment packet
  //     with vendor="test vendor" + 11 KEY=VALUE comments + framing=1.
  // R2 F-OGG-TRIM: identification-binary fields (VorbisVersion /
  // AudioChannels / SampleRate / NominalBitrate) are now PORTED and
  // present in the golden — only `Composite:Duration` is hand-trimmed
  // (accepted-deferral; see `docs/tracking.md`).
  check(
    "synthetic_vorbis_specialkeys.ogg",
    "synthetic_vorbis_specialkeys.ogg.json",
    true,
  );
  check(
    "synthetic_vorbis_specialkeys.ogg",
    "synthetic_vorbis_specialkeys.ogg.n.json",
    false,
  );
}

#[test]
fn ogg_id3_prefixed_conformance() {
  // R3 F1 regression pin (Codex round-3 [high] disposition).
  //
  // Fixture: a real Ogg-Vorbis stream with a 34-byte ID3v2.3 PREFIX
  // (10-byte header + a TIT2 frame containing "IDPrefixTitle") in front
  // of the `OggS` page. Bundled `ProcessOGG` (Ogg.pm:79-83) runs
  // `ID3::ProcessID3` BEFORE the OGG container walk; the audio-format
  // loop (ID3.pm:1582-1601) then seeks past `$hdrEnd` and re-dispatches
  // OGG on the post-ID3 body. Net emission: `File:ID3Size`, every Vorbis
  // tag, plus the ID3v2 frame tags.
  //
  // Pre-fix the engine's `AnyParser::Ogg` arm stripped the ID3v2 prefix
  // to reparse `bytes[hdr_end..]` but never emitted the ID3 directory —
  // silent metadata loss (`File:ID3Size` + `ID3v2_3:Title` both dropped).
  // R3 F1 fix: nest typed `Id3Meta` into `ogg::Meta::id3` via
  // `ogg::parse_full_chained`, same pattern as APE/FLAC/DSF
  // (`ape::parse_full_chained`, `flac::parse_inner`, etc.).
  //
  // Golden: bundled `perl exiftool -j -G1 -struct ... --Composite:Duration`
  // (Composite engine is on the accepted-deferral list — see Vorbis.ogg).
  // Every other emitted tag is value-equivalent to bundled in both modes.
  check("ogg_id3_prefixed.ogg", "ogg_id3_prefixed.ogg.json", true);
  check("ogg_id3_prefixed.ogg", "ogg_id3_prefixed.ogg.n.json", false);
}

#[test]
fn ogg_metadata_block_picture_conformance() {
  // R3 F2 regression pin (Codex round-3 [high] disposition).
  //
  // Fixture: the bundled `Opus.opus` corpus file (exiftool/t/images/Opus.opus)
  // — a real Ogg-Opus stream carrying a `METADATA_BLOCK_PICTURE` Vorbis
  // comment (a base64-encoded payload with the FLAC METADATA_BLOCK type-6
  // on-wire structure: PictureType=3 "Front Cover", MIME=image/png,
  // Description="cover pic", 16x16 1bpp, 85 bytes of PNG data).
  //
  // Vorbis.pm:122-134 defines the `METADATA_BLOCK_PICTURE` SubDirectory
  // hop: the base64 RawConv decodes the value, then ProcessDirectory
  // dispatches it through `%Image::ExifTool::FLAC::Picture` (FLAC.pm:84-
  // 134). Bundled emits each Picture sub-field (`FLAC:PictureType`,
  // `:PictureMIMEType`, `:PictureDescription`, `:PictureWidth`,
  // `:PictureHeight`, `:PictureBitsPerPixel`, `:PictureIndexedColors`,
  // `:PictureLength`, `:Picture`).
  //
  // Pre-fix exifast's `metadata_block_picture_valueconv` only base64-
  // decoded the value into a single `Vorbis:Picture` Bytes blob, losing
  // every sub-field. Silent metadata loss caught by Codex round 3.
  //
  // Fix: a comments-level intercept in `process_vorbis_comments` decodes
  // the base64 then parses the result via `flac::parse_flac_picture`
  // (made `pub(crate)`); the parsed `Picture` is cloned into an owned
  // `OggPicture` accumulated on `ogg::Meta::pictures`. The typed
  // `serialize_tags` sink emits each Picture under the `FLAC` family-1
  // group with the same shape FLAC's `sink_picture` uses.
  check("Opus.opus", "Opus.opus.json", true);
  check("Opus.opus", "Opus.opus.n.json", false);
}

#[test]
#[ignore = "Ogg-FLAC transport (Ogg.pm:176-179, 190-195): \\x7fFLAC packet → \
  ProcessFLAC on substr(buff,9). FORMALLY ACCEPT-DEFERRED — see docs/tracking.md \
  (R3 F2 fallback). The METADATA_BLOCK_PICTURE half of R3 F2 IS fixed (see \
  ogg_metadata_block_picture_conformance)."]
fn ogg_flac_transport_deferred() {
  // R3 F2 FALLBACK (formally accept-deferred per task spec). Bundled
  // `FLAC.ogg` extracts `FLAC:BlockSizeMin/Max`, `FLAC:FrameSizeMin/Max`,
  // `FLAC:SampleRate`, `FLAC:Channels`, `FLAC:BitsPerSample`,
  // `FLAC:TotalSamples`, `FLAC:MD5Signature`, `Vorbis:Vendor`.
  //
  // exifast's current OGG parser emits only the orchestration triplet
  // (`File:FileType`, `:FileTypeExtension`, `:MIMEType`) for this
  // fixture; the `\x7fFLAC` packet hits `PacketKind::Flac` which is
  // a silent no-op (`process_packet` returns `PacketOutcome::FlacDeferred`).
  //
  // Implementation cost: porting the bundled `numFlac` accumulator
  // (Ogg.pm:123-126, 176-179, 190-195) — track the FLAC header packet
  // count, accumulate packets across pages, and after all are read run
  // `ProcessFLAC` on the assembled `substr(buff, 9)` buffer (which
  // begins with `fLaC` magic — see hex dump of FLAC.ogg). Then nest a
  // `flac::Meta` into `ogg::Meta`, which forces a self-referential
  // shape (the flac::Meta borrows from the buffer that's owned by the
  // ogg::Meta).
  //
  // Per-user contract: this is FORMALLY ACCEPT-DEFERRED, NOT silent.
  // `#[ignore]` keeps the test off the default run but committed; the
  // golden is committed for the eventual port; `docs/tracking.md`
  // records the residual; this comment + the
  // `PacketKind::Flac => PacketOutcome::FlacDeferred` arm in
  // `src/formats/ogg.rs::process_packet` document it in code too.
  //
  // Run manually to verify the gap closes when the port lands:
  //   `cargo test --ignored ogg_flac_transport_deferred`
  check("FLAC.ogg", "FLAC.ogg.json", true);
  check("FLAC.ogg", "FLAC.ogg.n.json", false);
}

#[test]
fn ogg_opus_synthetic_conformance() {
  // A synthetic minimal Ogg-Opus stream (BOS page wrapping `OpusHead` +
  // EOS page wrapping `OpusTags` with vendor + 2 KEY=VALUE comments —
  // built in `examples/gen_synthetic_opus.rs`). Avoids the real
  // `Opus.opus` corpus fixture's `METADATA_BLOCK_PICTURE` (now COVERED
  // by `ogg_metadata_block_picture_conformance` — R3 F2 fix).
  // Exercises `OverrideFileType('OPUS')`
  // (Ogg.pm:50) firing on the `OpusHead` packet, the `OpusTags`
  // Vorbis-comments delegation (Opus.pm:32), AND the `Opus::Header`
  // binary table (Opus.pm:36-51, R2 F-OGG-TRIM port) emitting
  // `Opus:OpusVersion`/`AudioChannels`/`SampleRate`/`OutputGain` byte-
  // exact against the bundled golden.
  check(
    "synthetic_opus_minimal.opus",
    "synthetic_opus_minimal.opus.json",
    true,
  );
  check(
    "synthetic_opus_minimal.opus",
    "synthetic_opus_minimal.opus.n.json",
    false,
  );
}

#[test]
fn audible_aa_conformance() {
  // FORMATS.md row 10. Bundled fixture
  // `exiftool/t/images/Audible.aa`; goldens captured from `LC_ALL=C
  // TZ=UTC perl exiftool -j -G1 -struct -api QuickTimeUTC=1 ...`. Both
  // snapshots asserted (the PrintConv vs `-n` diff is only on
  // `File:FileTypeExtension` here: `aa` vs `AA`).
  check("Audible.aa", "Audible.aa.json", true);
  check("Audible.aa", "Audible.aa.n.json", false);
}

#[test]
fn audible_chapters_aa_conformance() {
  // Adversarial synthesized fixture: minimal valid AA exercising the
  // type-6 ChapterCount path (Audible.pm:221-225, absent from the
  // bundled Audible.aa fixture) AND `UnescapeHTML` (Audible.pm:261)
  // via a dictionary value `"A &amp; B"` ⇒ `"A & B"`. Goldens captured
  // from bundled `perl exiftool` exactly as for Audible.aa.
  check("Audible_chapters.aa", "Audible_chapters.aa.json", true);
  check("Audible_chapters.aa", "Audible_chapters.aa.n.json", false);
}

#[test]
fn audible_eof_aa_conformance() {
  // Adversarial: TOC has a type-6 entry whose offset is past EOF (the
  // 0xFFFFFFFF sentinel). The faithful Perl behavior (Audible.pm:222
  // inline `next if length < 4 or $raf->Read($buff, 4) != 4`) is to
  // silently skip the chunk — no Warn — and CONTINUE the TOC walk so
  // the subsequent valid type-2 dictionary still emits its tags. Pins
  // Codex R1 finding #1's fix: there is NO "Chunk 6 seek error" warning
  // for an in-memory/file backing where Seek succeeds but Read fails.
  check("Audible_eof.aa", "Audible_eof.aa.json", true);
  check("Audible_eof.aa", "Audible_eof.aa.n.json", false);
}

#[test]
fn audible_warn_aa_conformance() {
  // Adversarial: malformed AA whose first chunk-2 dictionary has
  // `num > 0x200` ⇒ Audible.pm:240 `Warn('Bad dictionary count'),
  // next`, and a second chunk-6 still emits a valid ChapterCount.
  // Bundled golden has `ExifTool:Warning` PLUS `Audible:ChapterCount`,
  // proving the loop continues past the Warn (Codex R1 finding #3).
  // The warning's position within the JSON object is not significant
  // under jsondiff's order-insensitive comparison (per the
  // [[exifast-phase2-forward-items]] "Warning JSON ordering" entry —
  // non-blocking until a format requires position-faithful warning
  // ordering at the byte level; tracked for the engine-level fix when
  // the gap becomes visible at the byte-exact bar).
  check("Audible_warn.aa", "Audible_warn.aa.json", true);
  check("Audible_warn.aa", "Audible_warn.aa.n.json", false);
}

#[test]
fn audible_badutf_aa_conformance() {
  // Adversarial: chunk-2 dictionary value contains a raw 0xFF byte
  // (`A\xffB`). Bundled Perl ExifTool's pipeline:
  //   bytes "A\xffB" → UnescapeHTML (no-op, no `&`) →
  //   Decode($_, 'UTF8') (no-op, from==to==UTF8) →
  //   HandleTag(Author, "A\xffB") →
  //   JSON serialize → FixUTF8 (replaces 0xff with '?') →
  //   "A?B"
  // Pins Codex R4 finding's fix: invalid input bytes flow through to
  // FixUTF8 (now applied at the parser boundary in this AA port, until
  // the engine grows a serializer-tier FixUTF8 — tracked in
  // [[exifast-phase2-forward-items]] "engine-wide FixUTF8 at JSON
  // serialization"). Rust's `String::from_utf8_lossy` (U+FFFD =
  // EF BF BD) would diverge — this confirms the byte-oriented
  // `fix_utf8(&unescape_html_bytes(...))` pipeline matches bundled
  // ExifTool exactly.
  check("Audible_badutf.aa", "Audible_badutf.aa.json", true);
  check("Audible_badutf.aa", "Audible_badutf.aa.n.json", false);
}

#[test]
fn audible_surrogate_aa_conformance() {
  // Adversarial: chunk-2 dictionary value `"X&#xD800;Y"`. Bundled Perl:
  //   bytes "X&#xD800;Y" → UnescapeHTML →
  //     pack('C0U', 0xD800) → "X\xed\xa0\x80Y" (invalid 3-byte surrogate
  //     encoding) →
  //   Decode($_, 'UTF8') (no-op) →
  //   HandleTag → JSON serialize → FixUTF8 (each of \xed \xa0 \x80
  //   replaced with '?') →
  //   "X???Y"
  // Pins Codex R4 finding's fix for the surrogate / out-of-range numeric
  // entity sub-case. Rust `char::from_u32(0xD800)` returns None (would
  // leave the entity literal as `&#xD800;`); the byte-oriented port
  // emits Perl's invalid 3-byte sequence via `pack_c0u`, which `fix_utf8`
  // then replaces with three `?`.
  check("Audible_surrogate.aa", "Audible_surrogate.aa.json", true);
  check("Audible_surrogate.aa", "Audible_surrogate.aa.n.json", false);
}

#[test]
fn audible_dup_aa_conformance() {
  // R5: two `author` entries in chunk-2 dictionary. Bundled Perl
  // `FoundTag` (ExifTool.pm:9504-9577) promotes the first entry to
  // `Author (1)` and writes the second at base `Author`; the `%noDups`
  // JSON serializer (exiftool:2744-2752) drops `(1)` so the final
  // output is `Audible:Author = "SECOND"`. Pin: replace-in-place
  // (`push_dict_last_wins`) keeps the first slot's position but
  // updates its value, exactly matching bundled output byte-for-byte.
  check("Audible_dup.aa", "Audible_dup.aa.json", true);
  check("Audible_dup.aa", "Audible_dup.aa.n.json", false);
}

#[test]
fn audible_bigent_aa_conformance() {
  // R5: chunk-2 dictionary value `"&#x100000000;"` — a numeric entity
  // whose body exceeds u32. Bundled Perl: `hex("100000000")` →
  // `0x100000000` → `pack('C0U', 0x100000000)` →
  // 7-byte invalid UTF-8 (`fe 84 80 80 80 80 80`) → `FixUTF8` ⇒ 7 `?`.
  // The previous u32-only `resolve_html_entity_codepoint` left the
  // entity literal; the new u64 path mirrors Perl byte-for-byte.
  check("Audible_bigent.aa", "Audible_bigent.aa.json", true);
  check("Audible_bigent.aa", "Audible_bigent.aa.n.json", false);
}

#[test]
fn audible_dupchap_aa_conformance() {
  // R6: two type-6 ChapterCount chunks in TOC (counts 1, then 2).
  // Bundled Perl `FoundTag` last-wins (ExifTool.pm:9504-9577) +
  // `%noDups` serializer filter ⇒ `Audible:ChapterCount` = 2. The
  // previous chunk-tag path used plain `push` instead of the AA dict's
  // last-wins helper, leaving Rust to emit ChapterCount = 1 (first
  // wins via `%noDups`). Routing every AA `HandleTag` equivalent
  // through `push_dict_last_wins` covers chunk-6 and chunk-11 the
  // same way as the dict path.
  check("Audible_dupchap.aa", "Audible_dupchap.aa.json", true);
  check("Audible_dupchap.aa", "Audible_dupchap.aa.n.json", false);
}

#[test]
fn audible_under_aa_conformance() {
  // R6: dict tag `__foo` exercises Perl `AddTagToTable` (ExifTool.pm:
  // 9217-9266) final name normalization: after MakeTagName +
  // `s/_(.)/\U$1/g` produces `_foo`, AddTagToTable's `length($name) <
  // 2 or $name !~ /^[A-Z]/i` rule prepends `Tag` because `_foo`'s
  // first char is not a letter. Bundled Perl emits `Audible:Tag_foo`;
  // the Rust port previously stopped after `s/_(.)/\U$1/g` and
  // emitted `Audible:_foo`.
  check("Audible_under.aa", "Audible_under.aa.json", true);
  check("Audible_under.aa", "Audible_under.aa.n.json", false);
}

#[test]
fn audible_dictcover_aa_conformance() {
  // R6: dictionary tag `_cover_art` (Audible.pm:43-47, `Binary => 1`)
  // takes the static-table branch but its raw value is binary — the
  // engine's universal `TagValue::Bytes` serializer emits
  // `(Binary data N bytes, use -b option to extract)`. The previous
  // dict-path treatment converted every static value to `TagValue::
  // Str(fix_utf8(unescape_html_bytes(...)))`, which dropped the
  // binary semantics and (worse) reshaped the byte length via
  // fix_utf8's invalid-byte replacement. Bundled Perl emits
  // `(Binary data 5 bytes, ...)` for the 5-byte value `"ABCDE"`.
  check("Audible_dictcover.aa", "Audible_dictcover.aa.json", true);
  check("Audible_dictcover.aa", "Audible_dictcover.aa.n.json", false);
}

#[test]
fn audible_reserved_aa_conformance() {
  // R7: dict tags `GROUPS` and `FORMAT` are in Perl `%specialTags`
  // (ExifTool.pm:1229-1236, table-internal hash keys). When the dict
  // loop hits one, Perl's `unless ($$tagTablePtr{$tag})` branch sees
  // a defined hashref (the table's actual GROUPS) and SKIPS
  // AddTagToTable; HandleTag then calls GetTagInfo which warns and
  // returns empty for special tags, so FoundTag is NEVER reached and
  // the tag is dropped. Bundled Perl emits ONLY `Audible:Title`; the
  // previous Rust port emitted `Audible:GROUPS` and `Audible:FORMAT`
  // too via the dynamic-name fallthrough.
  check("Audible_reserved.aa", "Audible_reserved.aa.json", true);
  check("Audible_reserved.aa", "Audible_reserved.aa.n.json", false);
}

#[test]
fn audible_ftype_aa_conformance() {
  // R7: dict entries `file_type` and `FileType` both resolve to
  // dynamic name `FileType` (after MakeTagName + `s/_(.)/\U$1/g` +
  // AddTagToTable). The engine's `SetFileType` (Audible.pm:207)
  // already pushed `File:FileType=AA` with `Priority => 2`
  // (ExifTool.pm:1437); Perl FoundTag (ExifTool.pm:9533-9574) sees
  // PRIORITY{FileType}=2 vs the AA push's default $priority=1, takes
  // the else branch (`$tag = $nextTag`) and stores the FIRST AA push
  // at `FileType (1)`, the SECOND at `FileType (2)`. The JSON noDups
  // dedup (exiftool:2951) keys by `<family1>:<name>` and picks the
  // first occurrence, so bundled Perl emits
  // `Audible:FileType = "FIRST"`. The R5 last-wins helper would have
  // emitted `SECOND`; R7 fix: when the AA dynamic-tag name collides
  // with an engine-pre-pushed bare name in a different group, treat
  // AA duplicates as FIRST-wins (mirroring Perl's no-promotion arm).
  check("Audible_ftype.aa", "Audible_ftype.aa.json", true);
  check("Audible_ftype.aa", "Audible_ftype.aa.n.json", false);
}

#[test]
fn audible_ftypeext_aa_conformance() {
  // R8 negative case: dict entries `file_type_extension=FIRST` and
  // `FileTypeExtension=SECOND` both resolve to dynamic name
  // `FileTypeExtension`. Unlike `FileType` (Priority 2), bundled
  // Perl's `File:FileTypeExtension` uses the DEFAULT Priority 1
  // (ExifTool.pm:1444+ has no `Priority =>` line), so FoundTag's
  // promote arm fires symmetrically and emits the LAST value:
  // `Audible:FileTypeExtension = "SECOND"`. The R7 fix was over-
  // broad (treated every cross-group same-name collision as first-
  // wins); R8 narrows the helper to the single Priority-2 name
  // `FileType`, restoring last-wins for the symmetric case.
  check("Audible_ftypeext.aa", "Audible_ftypeext.aa.json", true);
  check("Audible_ftypeext.aa", "Audible_ftypeext.aa.n.json", false);
}

#[test]
fn audible_etver_aa_conformance() {
  // R8 negative case: dict entries `exif_tool_version=FIRST` and
  // `ExifToolVersion=SECOND` both resolve to dynamic name
  // `ExifToolVersion`. The engine pre-emits
  // `ExifTool:ExifToolVersion` with default Priority 1 (no `Priority
  // =>` line, ExifTool.pm:1451+), so FoundTag's promote arm fires
  // and bundled Perl emits `Audible:ExifToolVersion = "SECOND"`.
  // Confirms the narrowed R8 check: cross-group `ExifToolVersion`
  // does NOT trigger first-wins.
  check("Audible_etver.aa", "Audible_etver.aa.json", true);
  check("Audible_etver.aa", "Audible_etver.aa.n.json", false);
}

#[test]
fn unsupported_bz2_conformance() {
  check("Unsupported.bz2", "Unsupported.bz2.json", true);
  check("Unsupported.bz2", "Unsupported.bz2.n.json", false);
}

// ExifTool's post-loop `ExifTool:Error` finalization (ExifTool.pm:3080-3128):
// when nothing is finalized, invalid inputs must be distinguishable. Goldens
// are bundled `perl exiftool -j -G1 -struct` (and `-n`) output; the default
// and `-n` snapshots are byte-identical for every case (the Error string has
// no PrintConv) but BOTH are asserted, mirroring the format conformance.

#[test]
fn empty_file_error_conformance() {
  // 0-byte file ⇒ `$self->Error('File is empty')` (ExifTool.pm:3086).
  check("Empty.dat", "Empty.dat.json", true);
  check("Empty.dat", "Empty.dat.n.json", false);
}

#[test]
fn unknown_type_error_conformance() {
  // 8 non-magic bytes, unrecognized extension ⇒ buff < 16, no known type
  // ⇒ 'Unknown file type' (ExifTool.pm:3095).
  check("mystery.xyz", "mystery.xyz.json", true);
  check("mystery.xyz", "mystery.xyz.n.json", false);
}

#[test]
fn malformed_aac_error_conformance() {
  // `\xff\xf1\xf0…` passes the AAC %magicNumber gate but `ProcessAAC`
  // rejects (sampling-freq index > 12, AAC.pm:103); `.aac` is a known
  // type ⇒ 'File format error' (ExifTool.pm:3093).
  check("bad.aac", "bad.aac.json", true);
  check("bad.aac", "bad.aac.n.json", false);
}

#[test]
fn aac_reserved_profile_error_conformance() {
  // Adversarial: ff f1 c0 00 00 00 00 — byte2=0xC0. Passes the AAC
  // %magicNumber gate; ProcessAAC's faithful >>16/>>12 checks (AAC.pm:
  // 102-103) don't trip, but $len < 7 (AAC.pm:105) ⇒ reject ⇒ '.aac'
  // known type ⇒ 'File format error' (ExifTool.pm:3093). Pins that the
  // faithful shift offsets are NOT to be "corrected" to >>14/>>10:
  // exifast must match bundled ExifTool byte-exact here.
  check("aac_profile3.aac", "aac_profile3.aac.json", true);
  check("aac_profile3.aac", "aac_profile3.aac.n.json", false);
}

#[test]
fn ape_conformance() {
  // Real fixture from exiftool/t/images/APE.ape: NewHeader (version 3990)
  // + APETAGEX v2 footer with 14 tags including Cover Art (front).
  check("APE.ape", "APE.ape.json", true);
  check("APE.ape", "APE.ape.n.json", false);
}

#[test]
fn ape_old_header_conformance() {
  // Adversarial synthesized fixture: OldHeader (version <= 3970) with no
  // APETAGEX trailer. Exercises the APE.pm:149-151 OldHeader branch +
  // APE.pm:170 `return 1` (no-trailer) path.
  check("APE_old.ape", "APE_old.ape.json", true);
  check("APE_old.ape", "APE_old.ape.n.json", false);
}

#[test]
fn ape_apetagex_only_conformance() {
  // Adversarial synthesized fixture (Codex r5 finding): starts directly
  // with APETAGEX (no MAC header). Exercises the APE.pm:142-144
  // header_at_start path with the Composite Duration Require failing
  // cleanly (no MAC ingredients ⇒ no Composite tag). Also covers the
  // dynamic MakeTag path ('My Custom Tag' → 'MyCustomTag') alongside a
  // static-dictionary tag ('Title' → 'Title').
  check("APE_apetagex.ape", "APE_apetagex.ape.json", true);
  check("APE_apetagex.ape", "APE_apetagex.ape.n.json", false);
}

#[test]
fn ape_wire_composite_ingredients_conformance() {
  // Adversarial wire-format fixture (Codex r8 follow-up). Carries four
  // APE tag-stream entries whose KEYS spell the four Composite Duration
  // ingredient names exactly: 'SampleRate', 'TotalFrames',
  // 'BlocksPerFrame', 'FinalFrameBlocks'. Bundled ExifTool 13.58
  // confirms NO `Composite:Duration` is emitted — because APE.pm:105
  // `MakeTag` runs `ucfirst lc` on the wire key first, producing
  // `Samplerate` (lowercase 'r'), `Totalframes` (lowercase 'f'), etc.
  // The Composite Require key `APE:SampleRate` (capital 'R') does NOT
  // match `Samplerate`, so no Composite tag fires. Pins this faithful
  // case-mangling behavior: a future regression that preserved camelCase
  // in MakeTag would WRONGLY emit a Composite here.
  check(
    "APE_wire_composite_ingredients.ape",
    "APE_wire_composite_ingredients.ape.json",
    true,
  );
  check(
    "APE_wire_composite_ingredients.ape",
    "APE_wire_composite_ingredients.ape.n.json",
    false,
  );
}

#[test]
fn ape_spaced_composite_conformance() {
  // Adversarial wire-format fixture (Codex r9 finding): four APE tag
  // entries whose KEYS contain SPACES — `Sample Rate`, `Total Frames`,
  // `Blocks Per Frame`, `Final Frame Blocks`. APE.pm:107 `MakeTag`
  // applies `s/[^\w-]+(.?)/\U$1/sg` AFTER `ucfirst lc`: `Sample Rate` →
  // ucfirst lc `Sample rate` → s/// at the space (non-word, then
  // uppercase the next char) → `SampleRate`. The Composite Require key
  // `APE:SampleRate` MATCHES, so Composite:Duration IS emitted
  // (`14.71 s`). Pins the family-0 + Str-coercion composite lookup
  // path end-to-end.
  check(
    "APE_spaced_composite.ape",
    "APE_spaced_composite.ape.json",
    true,
  );
  check(
    "APE_spaced_composite.ape",
    "APE_spaced_composite.ape.n.json",
    false,
  );
}

#[test]
fn ape_dup_override_conformance() {
  // Adversarial wire-format fixture (Codex r9 finding): MAC NewHeader
  // emits `SampleRate=44100`, then the APETAGEX footer emits a
  // `Sample Rate=48000` (which MakeTag normalises to `SampleRate`). Both
  // tags appear as `MAC:SampleRate` and `APE:SampleRate`; the Composite
  // Duration MUST use the LATEST value (48000, the wire-format override),
  // matching ExifTool's HandleTag/DUPL_TAG semantics (the bare-name key
  // is given to the most recent FoundTag call). Faithful Duration =
  // ((10-1)*73728+42662)/48000 = 14.71 s (NOT 16.01 s from 44100). Pins
  // the `iter().rev().find` last-wins behaviour in the composite lookup.
  check("APE_dup_override.ape", "APE_dup_override.ape.json", true);
  check("APE_dup_override.ape", "APE_dup_override.ape.n.json", false);
}

#[test]
fn ape_nonfinite_composite_conformance() {
  // Adversarial wire-format fixture (Codex r9 finding): one ingredient
  // (`Total Frames`) has value `"Inf"` (a string Perl coerces to IEEE
  // infinity). The composite arithmetic `(Inf-1)*73728+42662 = Inf;
  // /48000 = Inf`. ExifTool emits `APE:TotalFrames: "Inf"` (string,
  // because Inf fails IsFloat) and `Composite:Duration: "Inf"`. Pins:
  // (a) perl_numeric_coerce_f64 recognises "Inf"; (b) the composite
  // arithmetic in f64 propagates non-finite cleanly; (c) the composite
  // emit promotes non-finite f64 to Perl-cased `TagValue::Str("Inf")`
  // — Rust's f64::to_string() would emit lowercase `inf` and
  // byte-diverge.
  check(
    "APE_nonfinite_composite.ape",
    "APE_nonfinite_composite.ape.json",
    true,
  );
  check(
    "APE_nonfinite_composite.ape",
    "APE_nonfinite_composite.ape.n.json",
    false,
  );
}

#[test]
fn ape_huge_composite_conformance() {
  // Adversarial wire-format fixture (Codex r10 finding): four APE tag
  // entries where the Composite Duration arithmetic produces a value
  // beyond `i64::MAX` seconds (`1e15 * 1e15 / 1` ≈ 1e30 s). The previous
  // Rust port cast `(time / 3600.0) as i64` — saturating to `i64::MAX`
  // and emitting a corrupt h:m:s. Bundled Perl ExifTool 13.58 emits the
  // hours count via Perl's NV stringification (`%.15g`) which yields
  // `1.15740740740741e+25 days 0:00:00`. Pins the f64-throughout
  // ConvertDuration days-carve-out and the perl_nv_str helper.
  check(
    "APE_huge_composite.ape",
    "APE_huge_composite.ape.json",
    true,
  );
  check(
    "APE_huge_composite.ape",
    "APE_huge_composite.ape.n.json",
    false,
  );
}

#[test]
fn ape_repeated_keys_conformance() {
  // Adversarial wire-format fixture (Codex r13 follow-up): same APE
  // wire key emitted TWICE. Two `Title` entries (`First Title`,
  // `Second Title`) and two `Sample Rate` entries (`44100`, `48000`).
  // ExifTool HandleTag/FoundTag DUPL_TAG semantics give the bare key
  // to the LAST FoundTag call (renaming earlier ones to `Name (1)`,
  // `Name (2)`, …); default `-G1 -j` JSON suppresses the renamed
  // duplicates. Bundled Perl 13.58 emits ONLY the second value for
  // each key: `APE:Title="Second Title"`, `APE:SampleRate=48000`.
  check("APE_repeated.ape", "APE_repeated.ape.json", true);
  check("APE_repeated.ape", "APE_repeated.ape.n.json", false);
}

#[test]
fn ape_dynamic_edge_keys_conformance() {
  // Adversarial wire-format fixture (Codex r13 finding): four edge
  // dynamic APE tag keys exercising AddTagToTable (ExifTool.pm:9243-9255)
  // name normalization post-processing that MakeTag invokes:
  //   `1abc` → `Tag1abc` (prepend "Tag" because doesn't start with letter)
  //   `_abc` → `Tag_abc` (prepend "Tag" because doesn't start with letter)
  //   `a`    → `TagA` (prepend "Tag" because length<2; ucfirst → A)
  //   `\xe9` → `Tag` (non-ASCII byte stripped by tr/-_a-zA-Z0-9//dc ⇒
  //                   empty ⇒ length<2 ⇒ prepend "Tag")
  // Verified against bundled Perl 13.58. Pins make_tag's
  // AddTagToTable-equivalent post-processing.
  check(
    "APE_dynamic_edge_keys.ape",
    "APE_dynamic_edge_keys.ape.json",
    true,
  );
  check(
    "APE_dynamic_edge_keys.ape",
    "APE_dynamic_edge_keys.ape.n.json",
    false,
  );
}

#[test]
fn ape_two63_boundary_composite_conformance() {
  // Adversarial wire-format fixture (Codex r12 finding): `Sample Rate=1`,
  // `Total Frames=9223372036854775808` (= 2^63), `Blocks Per Frame=86400`,
  // `Final Frame Blocks=0`. Composite arithmetic:
  //   `(2^63 - 1) * 86400 / 1 ≈ 7.97e23` seconds → days = `2^63` exactly.
  // This pins the exact f64 boundary `i64::MAX as f64 == 2^63` (because
  // i64::MAX = 2^63-1 isn't representable in f64; the cast rounds UP).
  // Earlier `perl_nv_str` treated `n as i64` on `n=2^63` and saturated
  // to `i64::MAX = 2^63-1`, losing one. Bundled Perl 13.58 uses its UV
  // path and emits `"9223372036854775808 days 0:00:00"`. The fix splits
  // signed/unsigned carve-outs at the exact f64 power-of-two boundary.
  check(
    "APE_two63_boundary.ape",
    "APE_two63_boundary.ape.json",
    true,
  );
  check(
    "APE_two63_boundary.ape",
    "APE_two63_boundary.ape.n.json",
    false,
  );
}

#[test]
fn ape_u64_days_composite_conformance() {
  // Adversarial wire-format fixture (Codex r11 finding): four APE tag
  // entries chosen so the Composite Duration arithmetic produces a days
  // count strictly above `i64::MAX` (≈ 9.22e18) but at-or-below
  // `u64::MAX` (≈ 1.84e19). Perl preserves DECIMAL stringification in
  // that range via its UV (u64) integer path. Earlier `perl_nv_str` only
  // handled the signed `i64` range and emitted scientific notation
  // here, byte-diverging from bundled Perl. Empirically against bundled
  // Perl 13.58: composite duration `8.64e+23` seconds (≈ 1e19 days)
  // stringifies as `"10000000000000002048 days -32768:00:00"` — note
  // the `-32768` negative-hours residue is itself a faithful Perl quirk
  // caused by f64 precision loss in `$h -= $d * 24` and `%02d` integer
  // formatting (verified against bundled Perl). Pins the u64-range
  // integer carve-out in `perl_nv_str`.
  check("APE_u64_days.ape", "APE_u64_days.ape.json", true);
  check("APE_u64_days.ape", "APE_u64_days.ape.n.json", false);
}

#[test]
fn all_zero_file_error_conformance() {
  // 32 `\0` ⇒ buff ≥ 16 and all-same ⇒ the all-same-byte insight;
  // whole file is `\0` ⇒ 'Entire file is binary zeros'
  // (ExifTool.pm:3111,3115).
  check("allzero.dat", "allzero.dat.json", true);
  check("allzero.dat", "allzero.dat.n.json", false);
}

#[test]
fn raw_unsupported_error_conformance() {
  // 8 `\0` named `RAW.raw` ⇒ buff < 16 ⇒ the not-all-same arm; the
  // scalar `GetFileType("RAW.raw")` returns `"RAW"` (the multi row
  // `%fileTypeLookup{RAW}`) ⇒ Perl `$fileType eq 'RAW'` branch fires
  // ⇒ 'Unsupported RAW file type' (ExifTool.pm:3091-3092). Goldens
  // are bundled `perl exiftool` output.
  check("RAW.raw", "RAW.raw.json", true);
  check("RAW.raw", "RAW.raw.n.json", false);
}

#[test]
fn mpc_conformance() {
  // Pure SV7 MPC happy path (32-byte MP+ header, no ID3 leading / APE
  // trailer / ID3v1 — those are deferred to PRs #6 (ID3), the APE PR).
  // Synthesized from APE.mpc[263..295], the embedded MP+ frame in
  // exiftool/t/images/APE.mpc; oracle = bundled `perl exiftool` output.
  // MPC.pm:97-106 (SV7 ProcessDirectory) + MPC.pm:98 SetByteOrder('II')
  // (first end-to-end exerciser of bitstream::BitOrder::Ii).
  check("MPC.mpc", "MPC.mpc.json", true);
  check("MPC.mpc", "MPC.mpc.n.json", false);
}

#[test]
fn mpc_sv8_warn_conformance() {
  // MPC.pm:107-109 Warn path: a valid MP+ magic with version != 0x07 still
  // calls SetFileType (MPC.pm:94, before the version dispatch) then emits
  // `ExifTool:Warning = 'Audio info currently not extracted from this
  // version MPC file'`. Goldens captured from bundled `perl exiftool`.
  // Adversarial — pins that the version-dispatch branch is taken AFTER
  // SetFileType (the inverted ordering would emit just the Warning with no
  // File:* tags, which would diverge from bundled ExifTool byte-exact).
  check("sv8.mpc", "sv8.mpc.json", true);
  check("sv8.mpc", "sv8.mpc.n.json", false);
}

#[test]
fn mpc_with_id3v2_prefix_conformance() {
  // F2 (Codex adversarial) regression pin: MPC.pm:84-87 ID3-prefix
  // dispatch. Pre-fix the `AnyParser::Mpc` arm called the bare
  // `parse_borrowed` (header-only) and DROPPED the ID3 chain — so an
  // ID3-prefixed MPC silently lost `File:ID3Size` + every `ID3v2_*:*`
  // frame tag. `parse_full_chained` now nests a typed `Id3Meta` on
  // `mpc::Meta` (same pattern APE/DSF/FLAC use) and emits it.
  //
  // Fixture (66 bytes): ID3v2.3 with TIT2="MpcId3v2Title" (34 bytes) +
  // 32-byte MP+ SV7 header copied from MPC.mpc. Bundled emits the full
  // chain incl. `ID3v2_3:Title="MpcId3v2Title"`. Goldens captured from
  // bundled `perl exiftool` via tools/gen_golden.sh (untrimmed).
  check(
    "mpc_with_id3v2_prefix.mpc",
    "mpc_with_id3v2_prefix.mpc.json",
    true,
  );
  check(
    "mpc_with_id3v2_prefix.mpc",
    "mpc_with_id3v2_prefix.mpc.n.json",
    false,
  );
}

#[test]
fn mpc_with_apev2_trailer_conformance() {
  // F2 (Codex adversarial) regression pin: MPC.pm:111-113 APE-trailer
  // dispatch. Pre-fix the `AnyParser::Mpc` arm dropped the APE chain
  // (`parse_borrowed` is header-only) — so an APE-trailer-on-MPC fixture
  // silently lost every `APE:*` tag. `parse_full_chained` now runs
  // `ape::parse_trailer_only_owned` on the post-header buffer and nests
  // the resulting `ape::Meta`.
  //
  // Fixture (91 bytes): 32-byte MP+ SV7 header + APEv2 trailer carrying
  // `APE:Artist="MpcApeArtist"` (59-byte body + 32-byte footer).
  // Goldens captured from bundled `perl exiftool` via
  // tools/gen_golden.sh (untrimmed).
  check(
    "mpc_with_apev2_trailer.mpc",
    "mpc_with_apev2_trailer.mpc.json",
    true,
  );
  check(
    "mpc_with_apev2_trailer.mpc",
    "mpc_with_apev2_trailer.mpc.n.json",
    false,
  );
}

#[test]
fn wavpack_with_apev2_trailer_conformance() {
  // F2 (Codex adversarial) regression pin: WavPack.pm:100-103 APE-
  // trailer dispatch (`APE::ProcessAPE` after the wvpk-header
  // extraction). Pre-fix the `AnyParser::Wv` arm dropped the chain.
  // `parse_full_chained` now runs `ProcessID3` (recursion-guarded) +
  // `parse_trailer_only_owned` and nests both typed sub-Metas on
  // `wavpack::Meta`.
  //
  // Fixture (90 bytes): 32-byte wvpk header (copied from WavPack.wv) +
  // APEv2 trailer carrying `APE:Artist="WvApeArtist"`. The WV header
  // emits `File:BytesPerSample`/`AudioType`/`Compression`/`DataFormat`/
  // `SampleRate`; the APE trailer adds `APE:Artist`. Goldens captured
  // from bundled `perl exiftool` via tools/gen_golden.sh (untrimmed).
  check(
    "wavpack_with_apev2_trailer.wv",
    "wavpack_with_apev2_trailer.wv.json",
    true,
  );
  check(
    "wavpack_with_apev2_trailer.wv",
    "wavpack_with_apev2_trailer.wv.n.json",
    false,
  );
}

#[test]
fn red_r3d_conformance() {
  // FORMATS.md row 12: Image::ExifTool::Red. Bundled fixture
  // `tests/fixtures/Red.r3d` is the real `t/images/Red.r3d` (1160 bytes,
  // RED2 + ~50 directory entries). Goldens are bundled `perl exiftool`
  // output stripped of the 5 `Composite:*` lines (composite synthesis is
  // engine-level, NOT in Red.pm — see Red::ProcessR3D module docs).
  check("Red.r3d", "Red.r3d.json", true);
  check("Red.r3d", "Red.r3d.n.json", false);
}

#[test]
fn red_bad_magic_error_conformance() {
  // 8 bytes, magic gate `\0\0..RED(1|2)` fails. `.r3d` is a known type but
  // no parser accepted ⇒ post-loop 'File format error' (ExifTool.pm:3093).
  check("red_bad_magic.r3d", "red_bad_magic.r3d.json", true);
  check("red_bad_magic.r3d", "red_bad_magic.r3d.n.json", false);
}

#[test]
fn red_short_size_error_conformance() {
  // 8 bytes, magic OK, `$size = 4 < 8` ⇒ ProcessR3D returns 0 (Red.pm:228).
  // No parser accepted ⇒ 'File format error'.
  check("red_short.r3d", "red_short.r3d.json", true);
  check("red_short.r3d", "red_short.r3d.n.json", false);
}

#[test]
fn red_truncated_header_conformance() {
  // 8 bytes, magic OK, `$size = 0x40 > 8` but the `Read($size-8)` of the
  // remaining header bytes fails ⇒ SetFileType triplet is emitted then
  // `$et->Warn("Truncated R3D file")` (Red.pm:236). Bundled output:
  // ExifToolVersion, Warning, File:{FileType, FileTypeExtension, MIMEType}.
  check(
    "red_truncated_header.r3d",
    "red_truncated_header.r3d.json",
    true,
  );
  check(
    "red_truncated_header.r3d",
    "red_truncated_header.r3d.n.json",
    false,
  );
}

// FORMATS.md row 2 — ID3 pathfinder + MP3 completion. Each fixture is a
// synthetic ID3v2.x or ID3v1 file (no MPEG audio frame body — MPEG.pm is
// row 17, out-of-PR-scope; APE.pm row 5 likewise). The bundled-Perl
// oracle JSON is captured by hand from `perl exiftool -j -G1 -struct …`.

#[test]
fn id3v2_2_conformance() {
  // Synthetic ID3v2.2 file: TT2/TP1/TCO/TCM/COM/PIC frames; no Composite
  // triggers (no Year). Exercises ProcessID3 + ProcessID3v2 (6-byte
  // frame header path) + PIC sub-attribute emission (PIC-1/-2/-3 +
  // binary Picture).
  check("ID3v2_2.mp3", "ID3v2_2.mp3.json", true);
  check("ID3v2_2.mp3", "ID3v2_2.mp3.n.json", false);
}

#[test]
fn id3v1_conformance() {
  // 128-byte ID3v1 TAG trailer + 256 leading null bytes. Year set to
  // `\0\0\0\0` ⇒ ID3v1:Year="" ⇒ Composite:DateTimeOriginal NOT emitted
  // (Perl ValueConv `return undef unless $val[1]`, ID3.pm:853). Exercises
  // ProcessID3 ID3v1 trailer detection + ProcessID3v1 (binary table).
  check("ID3v1.mp3", "ID3v1.mp3.json", true);
  check("ID3v1.mp3", "ID3v1.mp3.n.json", false);
}

#[test]
fn id3v2_3_conformance() {
  // Synthetic ID3v2.3 file: TIT2/TPE1/TALB/TCON/COMM/APIC frames. v2.3
  // uses 10-byte frame headers (a4 N n) and standard int32 sizes.
  check("ID3v2_3.mp3", "ID3v2_3.mp3.json", true);
  check("ID3v2_3.mp3", "ID3v2_3.mp3.n.json", false);
}

#[test]
fn id3v2_4_conformance() {
  // Synthetic ID3v2.4 file: TIT2/TPE1 with sync-safe sizes. Exercises
  // ProcessID3v2 v2.4 sync-safe length detection (the no-iTunes-bug
  // path where sync-safe size IS valid).
  check("ID3v2_4.mp3", "ID3v2_4.mp3.json", true);
  check("ID3v2_4.mp3", "ID3v2_4.mp3.n.json", false);
}

#[test]
fn id3v2_3_extended_header_conformance() {
  // R4-F1 regression — pins the FAITHFUL bundled-Perl behavior:
  //   ID3.pm:1481 `$hBuff = substr($hBuff, $len)` strips EXACTLY $len
  //   bytes from the buffer, where $len is the writer's ext-header
  //   length-field value. Canonical real-world ID3v2.3 writers store
  //   $len = total_ext_header_size INCLUDING the 4-byte length field
  //   (verified against bundled `perl exiftool` on this fixture).
  //   Naively "fixing" the strip to `$len + 4` would diverge from
  //   bundled — Codex review R4 misread the ID3 spec on this point.
  //
  // The fixture is a v2.3 file with ext-header value=10 (full ext
  // size) + TIT2 frame. Bundled emits ID3v2_3:Title="ExtHdr".
  check("ID3v2_3_exthdr.mp3", "ID3v2_3_exthdr.mp3.json", true);
  check("ID3v2_3_exthdr.mp3", "ID3v2_3_exthdr.mp3.n.json", false);
}

#[test]
fn id3v2_corrupt_with_valid_id3v1_trailer_conformance() {
  // R3-F1 regression: a file with a corrupt ID3v2 header (here `ID3v5`,
  // unsupported) BUT a valid ID3v1 trailer at the end. Bundled ID3.pm
  // `last`s out of the v2 header loop (ID3.pm:1454-1465) AND CONTINUES
  // to the ID3v1 trailer scan at ID3.pm:1510-1517 — the trailer tags
  // must still be emitted. Previously my port early-returned on the
  // v5 Warn and dropped all ID3v1 tags. Pinned by this conformance:
  // `Warning="Unsupported ID3 version: 2.5.0"` + full ID3v1:* tag set.
  check("ID3v2_v5_with_v1.mp3", "ID3v2_v5_with_v1.mp3.json", true);
  check("ID3v2_v5_with_v1.mp3", "ID3v2_v5_with_v1.mp3.n.json", false);
}

#[test]
fn id3v2_4_big_frame_conformance() {
  // R2 regression — v2.4 single frame with sync-safe size > 127 followed
  // by EOF (no terminator). Bundled `ProcessID3v2` (ID3.pm:1143-1152)
  // emits `[minor] Missing ID3 terminating frame` Warn AND extracts the
  // 200-byte title. Previously my port defaulted to RAW int32 in the
  // sync-safe-above-127 branch and dropped the frame. Pinned by this
  // conformance fixture: 200 'A's + the bundled Warn.
  check("ID3v2_4_big.mp3", "ID3v2_4_big.mp3.json", true);
  check("ID3v2_4_big.mp3", "ID3v2_4_big.mp3.n.json", false);
}

#[test]
fn id3v5_unsupported_conformance() {
  // ID3 magic + version 5.0 ⇒ ExifTool emits Warn "Unsupported ID3
  // version: 2.5.0" (ID3.pm:1460). $rtnVal=1 was set at ID3.pm:1453
  // BEFORE the version check, so SetFileType('MP3') + ID3Size=0 still
  // run in the post-loop rtnVal-truthy block (ID3.pm:1580-1611).
  check("ID3v5_unsupported.mp3", "ID3v5_unsupported.mp3.json", true);
  check(
    "ID3v5_unsupported.mp3",
    "ID3v5_unsupported.mp3.n.json",
    false,
  );
}

#[test]
fn id3_with_mpeg_audio_conformance() {
  // R1-F1 regression pin: ID3v2 header + MPEG Layer-III audio frames in
  // the same MP3 file. Bundled `ProcessMP3` (ID3.pm:1684-1727) emits
  // BOTH `ID3v2_*:Title` AND `MPEG:*` audio tags via the recursive
  // @audioFormats dance (ID3.pm:1580-1602, recursive ProcessID3 returns
  // 0 due to DoneID3 flag ⇒ unless-rtnVal branch ID3.pm:1696-1719 runs
  // ParseMPEGAudio on the post-ID3 buffer). Fixture is a hand-crafted
  // 57-byte MP3 with a 25-byte ID3v2.3 header containing TIT2="Test"
  // followed by a single MPEG-1 Layer-III frame.
  check(
    "ID3v2_with_mpeg_audio.mp3",
    "ID3v2_with_mpeg_audio.mp3.json",
    true,
  );
  check(
    "ID3v2_with_mpeg_audio.mp3",
    "ID3v2_with_mpeg_audio.mp3.n.json",
    false,
  );
}

#[test]
fn mp3_with_large_id3v2_artwork_conformance() {
  // Codex R5 high-severity regression pin: an MP3 with a large ID3v2.3
  // header (9261-byte body, containing a 9216-byte APIC artwork JPEG)
  // followed by a valid MPEG-1 Layer-III frame. The post-ID3 audio frame
  // sits at offset 9271 (> 8192) — beyond the 8192-byte `$scanLen`
  // window from offset 0.
  //
  // Bundled `ProcessMP3` (ID3.pm:1684-1729) handles this via the audio
  // loop at ID3.pm:1580-1601: ProcessID3 finds the ID3v2 prefix, sets
  // `$rtnVal=1` and `$$et{DoneID3}=1`, then the foreach @audioFormats
  // loop does `$raf->Seek($hdrEnd, 0)` (ID3.pm:1590) BEFORE invoking the
  // recursive ProcessMP3, which then reads a FRESH 8192-byte buffer from
  // the post-ID3 file position. Without that seek-then-read, the audio
  // frame is silently missed.
  //
  // Pre-fix: exifast scanned `data[..8192]` from offset 0 — the post-ID3
  // audio frame at offset 9271 was NEVER reached, so `MPEG:*` tags
  // were silently dropped. Post-fix: id3/process.rs threads `hdr_end`
  // through to mpeg::ProcessMp3.process_with_start_offset, mirroring
  // bundled's `Seek($hdrEnd, 0)` + `Read($buff, $scanLen)` pair byte-
  // for-byte.
  //
  // Goldens captured via bundled Perl ExifTool 13.58 with
  // `-x System:all -x Composite:all` (same exclusions as
  // `id3_with_mpeg_audio_conformance` — Composite:Duration is engine-
  // deferred per the FLAC-id3-prefix precedent).
  check(
    "mp3_with_large_id3v2_artwork.mp3",
    "mp3_with_large_id3v2_artwork.mp3.json",
    true,
  );
  check(
    "mp3_with_large_id3v2_artwork.mp3",
    "mp3_with_large_id3v2_artwork.mp3.n.json",
    false,
  );
}

#[test]
fn flac_conformance() {
  // FLAC.pm:239-280 + Vorbis.pm:157-210. The fixture's metadata blocks
  // contain a StreamInfo (block 0) AND a VorbisComment (block 4) with
  // vendor + 6 user comments (REPLAYGAIN_*, Title, Copyright). Goldens
  // are captured from bundled Perl ExifTool 13.58.
  check("FLAC.flac", "FLAC.flac.json", true);
  check("FLAC.flac", "FLAC.flac.n.json", false);
}

#[test]
fn bad_flac_conformance() {
  // Adversarial: `fLaC` + 4-byte StreamInfo header claiming 1 MiB payload
  // (truncated). FLAC.pm:263 sets $err=1, :278 emits 'Format error in
  // FLAC file' warning; :279 still returns 1 (SetFileType already fired
  // at :255). Goldens captured by hand from bundled Perl ExifTool
  // (gen_golden.sh can't handle ExifTool exit 1 — see [[exifast-phase2-
  // forward-items]]).
  check("bad_flac.flac", "bad_flac.flac.json", true);
  check("bad_flac.flac", "bad_flac.flac.n.json", false);
}

#[test]
fn flac_multi_artist_conformance() {
  // R1-F2 regression pin: Vorbis.pm:85 `ARTIST => { List => 1 }`. Fixture
  // is a synthetic FLAC with StreamInfo + VorbisComment containing two
  // ARTIST entries. Bundled ExifTool emits `"Vorbis:Artist": ["Alice",
  // "Bob"]` (JSON array); exifast must coalesce same-(group, name)
  // repeats via `push_listable` (ExifTool.pm:9520).
  check(
    "FLAC_multi_artist.flac",
    "FLAC_multi_artist.flac.json",
    true,
  );
  check(
    "FLAC_multi_artist.flac",
    "FLAC_multi_artist.flac.n.json",
    false,
  );
}

#[test]
fn red2_framerate_div_by_zero_conformance() {
  // Codex round-3 F1 regression: RED2 `int16u[3]` at offset 0x56 is
  // `(0, 0, 24000)` — the first word (`$a[0]`) is zero. Perl ValueConv
  // `($a[1]*0x10000 + $a[2])/$a[0]` dies with `Illegal division by zero`
  // inside `GetValue`'s eval (ExifTool.pm:3652-3655); the resulting
  // `$value = undef` drops the `Red:FrameRate` tag from output. Bundled
  // `perl exiftool -j -G` on this fixture emits RedcodeVersion / ImageWidth
  // / ImageHeight (extracted before FrameRate) but no `Red:FrameRate` —
  // empirically verified.
  check(
    "red2_framerate_div_by_zero.r3d",
    "red2_framerate_div_by_zero.r3d.json",
    true,
  );
  check(
    "red2_framerate_div_by_zero.r3d",
    "red2_framerate_div_by_zero.r3d.n.json",
    false,
  );
}

#[test]
fn flac_id3_prefix_conformance() {
  // R1-F1 regression pin: FLAC.pm:244-247 ID3-prefix dispatch. Fixture is
  // a real FLAC body prefixed with a (10-byte, no-extended-header) empty
  // ID3v2 tag. Bundled ExifTool runs `ID3::ProcessID3` first (emits
  // `File:ID3Size = 10` + any ID3v2 frames) then extracts the FLAC body.
  //
  // F1 fix (Codex adversarial): `flac::parse_inner` now invokes the typed
  // `parse_id3_with_hdr_end` (same nesting pattern APE/DSF use) and the
  // sink emits the chained ID3 sub-Meta BEFORE the FLAC body tags. The
  // golden is regenerated UNTRIMMED from bundled — `File:ID3Size = 10`
  // is committed (the previous hand-trim is removed).
  check("FLAC_id3_prefix.flac", "FLAC_id3_prefix.flac.json", true);
  check("FLAC_id3_prefix.flac", "FLAC_id3_prefix.flac.n.json", false);
}

#[test]
fn flac_picture_conformance() {
  // R1-F3 regression pin: FLAC.pm:51-54 Picture block (subdir to
  // %FLAC::Picture). Fixture is a synthetic FLAC carrying a Picture
  // block with PictureType + MIME + Description + Width/Height/
  // BitsPerPixel/IndexedColors + raw PNG bytes. exifast must emit
  // ALL ported sub-fields byte-equivalent to bundled `perl exiftool -j`.
  check("FLAC_picture.flac", "FLAC_picture.flac.json", true);
  check("FLAC_picture.flac", "FLAC_picture.flac.n.json", false);
}

#[test]
fn flac_coverart_conformance() {
  // R1-F3 regression pin: Vorbis.pm:97-105 `COVERART => { Binary => 1,
  // ValueConv => DecodeBase64 }`. Fixture is a FLAC with a VorbisComment
  // block containing COVERART (base64 of raw image bytes) +
  // COVERARTMIME=image/jpeg + TITLE. Bundled `perl exiftool -j` emits
  // `"Vorbis:CoverArt": "(Binary data 27 bytes, use -b option to
  // extract)"` after decoding. exifast must match byte-equivalent.
  check("FLAC_coverart.flac", "FLAC_coverart.flac.json", true);
  check("FLAC_coverart.flac", "FLAC_coverart.flac.n.json", false);
}

#[test]
fn flac_metadata_block_picture_conformance() {
  // R1-F3 regression pin: Vorbis.pm:122-135
  // `METADATA_BLOCK_PICTURE => { RawConv => DecodeBase64, SubDirectory =>
  // FLAC::Picture }`. Bundled ExifTool's ProcessDirectory recursion guard
  // (ExifTool.pm:9056-9059) fires here invariably ("Picture pointer
  // references previous VorbisComment directory") — verified via `perl
  // exiftool -j -G1` on a synthetic fixture (2026-05-20). The Picture
  // sub-fields are NOT emitted; only the warning is. exifast mirrors
  // that faithful disposition exactly.
  check("FLAC_mbpicture.flac", "FLAC_mbpicture.flac.json", true);
  check("FLAC_mbpicture.flac", "FLAC_mbpicture.flac.n.json", false);
}

#[test]
fn flac_id3v24_footer_conformance() {
  // R2-F1 regression pin: ID3.pm:1484-1487 — `if ($flags & 0x10) { $raf->
  // Seek(10, 1); }` skips the optional v2.4 footer (10 bytes) AFTER the
  // header + synchsafe-size payload. Fixture is a real FLAC body prefixed
  // with an ID3v2.4 header (flags=0x10, size=0) immediately followed by a
  // 10-byte `3DI` footer and the `fLaC` magic. Bundled ExifTool runs
  // `ID3::ProcessID3` (emits `File:ID3Size = 10`), then extracts the FLAC
  // body.
  //
  // F1 fix (Codex adversarial): the typed FLAC parser nests the ID3 sub-
  // Meta via `parse_id3_with_hdr_end` (which honours the v2.4 footer flag
  // in its hdr_end calculation, matching ID3.pm:1484-1487). The golden
  // is regenerated UNTRIMMED — `File:ID3Size = 10` is committed.
  check(
    "FLAC_id3v24_footer.flac",
    "FLAC_id3v24_footer.flac.json",
    true,
  );
  check(
    "FLAC_id3v24_footer.flac",
    "FLAC_id3v24_footer.flac.n.json",
    false,
  );
}

#[test]
fn id3v2_short_header_conformance() {
  // ID3 magic + only 2 bytes total (5 bytes of header). ID3.pm:1454
  // `$raf->Read($hBuff,7)==7 or $et->Warn('Short ID3 header'), last`.
  // Same rtnVal-was-already-1 pattern: File:* + ID3Size=0 still emitted.
  check("ID3v2_short.mp3", "ID3v2_short.mp3.json", true);
  check("ID3v2_short.mp3", "ID3v2_short.mp3.n.json", false);
}

#[test]
fn id3v2_truncated_data_conformance() {
  // ID3 magic + declared size 100 but only 3 body bytes. ID3.pm:1464
  // Warn "Truncated ID3 data".
  check("ID3v2_truncated.mp3", "ID3v2_truncated.mp3.json", true);
  check("ID3v2_truncated.mp3", "ID3v2_truncated.mp3.n.json", false);
}

#[test]
fn no_ext_layer2_mpeg_conformance() {
  // R8-F1 regression. A dotless file whose contents start with the valid
  // MPEG Layer-II frame sync `ff fd 90 4c`. Bundled `ProcessMP3`
  // (ID3.pm:1684-1728) invokes `ParseMPEGAudio` with `$mp3 = 1` because
  // `$ext ne 'MUS'` (ID3.pm:1715-1717); the Layer-III gate at
  // MPEG.pm:485 then rejects this sync (`0x040000 != 0x020000`).
  // Without the .mp3 extension MPEG.pm:488 `return 0 unless $ext eq
  // 'MP3'` bails immediately, so the candidate loop continues and the
  // post-loop emits `Unknown file type`. Previously my port used the
  // same `ext_is_mp3` boolean for both the 8192-byte scan window AND
  // the Layer-III gate — for a non-MP3-ext dispatch path it skipped
  // the Layer-III check and would have accepted this Layer-II header.
  // Pinned: `Error="Unknown file type"`, no `File:*` tags.
  check(
    "no_ext_layer2_mpeg.bin",
    "no_ext_layer2_mpeg.bin.json",
    true,
  );
  check(
    "no_ext_layer2_mpeg.bin",
    "no_ext_layer2_mpeg.bin.n.json",
    false,
  );
}

#[test]
fn red2_short_first_block_conformance() {
  // Codex round-2 F2 regression: RED2 declared `$size = 0x40` (< 0x44),
  // file has trailing bytes past the declared first block. Pre-fix this
  // port would read `rdi/rda/rdx` from offsets 0x40..0x42 of the FULL
  // file (outside `$buff`), compute a nonsense directory position, and
  // enter fallback scanning. Faithful Perl (Red.pm:251-252) bounds `$buff`
  // to `$size` first, then checks `length($buff) < 0x44` and warns
  // "Truncated R3D file" — RedcodeVersion still flows from the prior
  // RED2 subtable extraction (Red.pm:175-206 read at offset 0x07).
  check(
    "red2_short_first_block.r3d",
    "red2_short_first_block.r3d.json",
    true,
  );
  check(
    "red2_short_first_block.r3d",
    "red2_short_first_block.r3d.n.json",
    false,
  );
}

#[test]
fn flac_picture_truncated_conformance() {
  // R2-F3 regression pin: FLAC.pm:131 `Picture => undef[$val{7}]` ⇒
  // ExifTool.pm:6290-6298 `ReadValue` clamps `count` to the remaining
  // bytes (`$count = int($size / $len)`) and emits the partial blob.
  // Fixture declares PictureLength=8 but supplies only 4 payload bytes;
  // bundled emits `Picture` as `(Binary data 4 bytes, use -b option to
  // extract)` (the clamped count) and still emits every preceding sub-
  // field of the Picture block. exifast must match byte-equivalent.
  check(
    "FLAC_picture_truncated.flac",
    "FLAC_picture_truncated.flac.json",
    true,
  );
  check(
    "FLAC_picture_truncated.flac",
    "FLAC_picture_truncated.flac.n.json",
    false,
  );
}

#[test]
fn id3v2_3_with_v2_4_frame_conformance() {
  // R8-F2 regression (v2.3 → v2.4 fallback). A v2.3 file containing
  // a v2.4-only frame (`TMOO` = Mood). Bundled ID3.pm:833-836
  // `%otherTable` maps v2.3 ↔ v2.4; ID3.pm:1166-1172: when the per-
  // frame `GetTagInfo` misses in the current-version table, the alt
  // table is consulted, and on a hit a minor `Warn("Frame '${id}' is
  // not valid for this ID3 version", 1)` is emitted + the tag IS still
  // extracted under the alt table's `TagDef` (whose `group1()` is
  // `ID3v2_4`). TMOO chosen because it is NOT a Composite source
  // (Composite tag derivation is out-of-PR-scope, row 17 +); pins
  // the fallback emission without depending on out-of-scope Composite
  // machinery. Pinned: `Warning="[minor] Frame 'TMOO' is not valid
  // for this ID3 version"` + `ID3v2_4:Mood="Happy"`.
  check(
    "ID3v2_3_with_v2_4_frame.mp3",
    "ID3v2_3_with_v2_4_frame.mp3.json",
    true,
  );
  check(
    "ID3v2_3_with_v2_4_frame.mp3",
    "ID3v2_3_with_v2_4_frame.mp3.n.json",
    false,
  );
}

#[test]
fn flac_duration_conformance() {
  // R2-F2 regression pin: FLAC.pm:137-149 `%FLAC::Composite` Duration =
  // `($val[0] and $val[1]) ? $val[1] / $val[0] : undef` (TotalSamples /
  // SampleRate) with `PrintConv => 'ConvertDuration($val)'`. Fixture is
  // a synthetic FLAC with TotalSamples=240000 and SampleRate=8000 ⇒
  // duration=30.0 s; bundled emits `"Composite:Duration": "0:00:30"`
  // (default, formatted by ConvertDuration / `sprintf("%d:%.2d:%.2d")`
  // ExifTool.pm:6883) and `"Composite:Duration": 30` under `-n` (raw
  // numeric).
  check("FLAC_duration.flac", "FLAC_duration.flac.json", true);
  check("FLAC_duration.flac", "FLAC_duration.flac.n.json", false);
}

#[test]
fn id3v2_4_with_v2_3_frame_conformance() {
  // R8-F2 regression (v2.4 → v2.3 fallback). A v2.4 file containing
  // a v2.3-only frame (`TSIZ` = Size). Symmetric to the above; bundled
  // emits the same minor Warn but the tag goes under `ID3v2_3:Size`
  // (the alt table's group1). TSIZ chosen because it is NOT a
  // Composite source (Year/Date/Time WOULD trigger
  // Composite:DateTimeOriginal). Pinned: `Warning="[minor] Frame
  // 'TSIZ' is not valid for this ID3 version"` + `ID3v2_3:Size=12345`.
  check(
    "ID3v2_4_with_v2_3_frame.mp3",
    "ID3v2_4_with_v2_3_frame.mp3.json",
    true,
  );
  check(
    "ID3v2_4_with_v2_3_frame.mp3",
    "ID3v2_4_with_v2_3_frame.mp3.n.json",
    false,
  );
}

#[test]
fn id3v2_3_invalid_apic_conformance() {
  // R8-F3 regression (APIC Latin). A v2.3 file with a malformed APIC
  // frame: MIME + 0 + picType + description WITHOUT the description's
  // trailing `\0` terminator. Bundled ID3.pm:1321 regex
  // `.(.*?)\0(.)(.*?)\0` does NOT match (final `\0` absent), ID3.pm:
  // 1324 `... or $et->Warn("Invalid $id frame"), next` fires.
  // Previously my port treated the entire remaining buffer as the
  // description and emitted empty image bytes; now the picture frame
  // is skipped entirely. Pinned: `Warning="Invalid APIC frame"` + NO
  // `APIC*` tags.
  check(
    "ID3v2_3_invalid_APIC.mp3",
    "ID3v2_3_invalid_APIC.mp3.json",
    true,
  );
  check(
    "ID3v2_3_invalid_APIC.mp3",
    "ID3v2_3_invalid_APIC.mp3.n.json",
    false,
  );
}

#[test]
fn id3v2_3_invalid_apic_utf16_conformance() {
  // R8-F3 regression (APIC UTF-16). The UTF-16 branch of the bundled
  // regex (ID3.pm:1319 `.(.*?)\0(.)((?:..)*?)\0\0`) requires a word-
  // aligned `\0\0` description terminator; fixture omits it ⇒ same
  // `Invalid APIC frame` Warn + skip semantics.
  check(
    "ID3v2_3_invalid_APIC_utf16.mp3",
    "ID3v2_3_invalid_APIC_utf16.mp3.json",
    true,
  );
  check(
    "ID3v2_3_invalid_APIC_utf16.mp3",
    "ID3v2_3_invalid_APIC_utf16.mp3.n.json",
    false,
  );
}

#[test]
fn id3v2_2_invalid_pic_conformance() {
  // R8-F3 regression (PIC v2.2). The 3-byte image-format + 1-byte
  // picType + description-without-`\0`. Bundled ID3.pm:1321 PIC regex
  // `.(...)(.)(.*?)\0` requires the trailing `\0`; absent ⇒
  // `Warn("Invalid PIC frame")` + frame skipped. Pinned to confirm
  // the v2.2 path uses the `Invalid PIC frame` wording (NOT APIC).
  check(
    "ID3v2_2_invalid_PIC.mp3",
    "ID3v2_2_invalid_PIC.mp3.json",
    true,
  );
  check(
    "ID3v2_2_invalid_PIC.mp3",
    "ID3v2_2_invalid_PIC.mp3.n.json",
    false,
  );
}

#[test]
fn aiff_conformance() {
  // Synthesized AIFF fixture: FORM <sz> AIFF + COMT (1 comment) + COMM
  // (SampleRate=0 keeps Composite Duration's `Require` from firing) +
  // NAME + AUTH + (c) + ANNO + APPL. Exercises every %AIFF::Main scalar
  // tag, %AIFF::Common ProcessBinaryData, %AIFF::Comment ProcessComment,
  // and the AIFF time-epoch ConvertUnixTime path.
  check("AIFF.aif", "AIFF.aif.json", true);
  check("AIFF.aif", "AIFF.aif.n.json", false);
}

#[test]
fn aiff_duplicate_name_chunk_last_wins_conformance() {
  // Codex R11 regression: an AIFF with TWO `NAME` chunks. Perl's FoundTag
  // (`ExifTool.pm:9437-9519`) detects the duplicate and, when both
  // values share the default priority of 1, MOVES the OLD value to a
  // `"Name (1)"` copy-key slot and stores the NEW value under the
  // canonical `"Name"` key. The JSON serializer (`exiftool:2744`) then
  // suppresses any `\(\d+\)` copy-keys via `next if $tag =~ /^(.*?) ?\(/
  // and defined $$info{$1}`. Net effect: LAST chunk's value wins.
  //
  // The prior `Metadata::push` was unconditional-append + first-wins
  // serializer dedup ⇒ FIRST chunk's value won, diverging from Perl.
  // Post-fix: `push` is now replace-in-place for any existing same
  // `group + name` key, faithful to FoundTag's priority-≥-old branch.
  // Oracle (bundled `perl exiftool`, captured 2026-05-20) on a
  // synthesized two-NAME-chunk AIFF (`"First Name"` then `"Second
  // Name"`): emits `"AIFF:Name": "Second Name"`.
  check("AIFF_dup_name.aif", "AIFF_dup_name.aif.json", true);
  check("AIFF_dup_name.aif", "AIFF_dup_name.aif.n.json", false);
}

#[test]
#[ignore = "Phase-2 defer: ID3 SubDirectory dispatch lives in parallel PR #6 (ID3 port). See module-doc of src/formats/aiff.rs and the `ID3 ` branch of process_aiff. This fixture pins the POST-merge oracle output (File:ID3Size + ID3v2_3:Title) so when ID3 lands the test will auto-pass; today it documents the deliberate divergence."]
fn aiff_id3_chunk_subdirectory_dispatch_deferred_conformance() {
  // Codex R12 regression: an AIFF containing an `ID3 ` chunk carrying a
  // minimal ID3v2.3 frame (TIT2 = "Test Title"). Bundled `perl exiftool`
  // (oracle captured 2026-05-20) emits `File:ID3Size` AND `ID3v2_3:Title`
  // via AIFF.pm:69-75's `SubDirectory => { TagTable => 'Image::ExifTool::
  // ID3::Main', ProcessProc => &ProcessID3 }`. exifast's `ID3 ` chunk
  // handler currently silent-skips the body (Phase-2 defer, see module
  // doc of `src/formats/aiff.rs`), so this conformance check would FAIL
  // until the parallel ID3 PR (#6) integrates `ProcessID3`. The fixture
  // and golden are committed NOW so the deferral is empirically
  // documented; the `#[ignore]` attribute holds the test out of the
  // default suite. Remove the `#[ignore]` once ID3 lands and exifast
  // becomes byte-exact here.
  check("AIFF_id3.aif", "AIFF_id3.aif.json", true);
  check("AIFF_id3.aif", "AIFF_id3.aif.n.json", false);
}

#[test]
fn aiff_duration_composite_conformance() {
  // Codex R4 oracle: an AIFF with nonzero SampleRate AND NumSampleFrames
  // MUST emit `Composite:Duration`. Bundled Perl `Image::ExifTool::AIFF
  // ::Composite::Duration` formula: `NumSampleFrames / SampleRate`,
  // PrintConv via `ConvertDuration` (ExifTool.pm:6866). Fixture has
  // SampleRate=22050, NumSampleFrames=44100 ⇒ 2.0 s. Default ⇒
  // `"2.00 s"` (sprintf %.2f); `-n` ⇒ bare `2` (the raw f64 stringified
  // by the EscapeJSON gate; `format_g(2.0,15) == "2"`).
  check("AIFF_duration.aif", "AIFF_duration.aif.json", true);
  check("AIFF_duration.aif", "AIFF_duration.aif.n.json", false);
}

#[test]
fn aiff_duration_float_sample_rate_conformance() {
  // Codex R6 regression: AIFF SampleRate is 80-bit extended (AIFF.pm:91);
  // `get_extended` returns `TagValue::F64` for non-integer rates and
  // `TagValue::I64` for the common integer case. The prior I64-only match
  // in `emit_composite_duration` silently dropped Duration whenever the
  // rate was non-integer (e.g. NTSC pull-down 44056.94 Hz). This fixture
  // pins SampleRate=22050.5 with NumSampleFrames=44101 ⇒ exactly 2.0 s,
  // forcing the f64 branch through `tag_as_f64` and verifying that the
  // `(Some(sr), Some(nf))` destructure now succeeds. Default ⇒ `"2.00 s"`
  // (sprintf %.2f); `-n` ⇒ bare `2` (format_g(2.0,15) == "2").
  check(
    "AIFF_duration_float.aif",
    "AIFF_duration_float.aif.json",
    true,
  );
  check(
    "AIFF_duration_float.aif",
    "AIFF_duration_float.aif.n.json",
    false,
  );
}

#[test]
fn aifc_noninteger_sample_rate_conformance() {
  // Codex R6 regression (AIFC variant): non-integer 80-bit extended rate
  // 44056.94 Hz (the canonical NTSC pull-down rate 44100 * 1000/1001).
  // Exercises the F64 path of `tag_as_f64` for both the SampleRate tag
  // serialization (`AIFF:SampleRate` ⇒ 44056.94) AND the Composite
  // Duration numerator (NumSampleFrames=44057 / 44056.94 ≈ 1.0000013...).
  // Default ⇒ `"1.00 s"` (sprintf %.2f truncates); `-n` ⇒ raw f64
  // `1.00000136187397` (format_g 15-digit roundtrip preserves precision).
  check(
    "AIFC_noninteger_rate.aifc",
    "AIFC_noninteger_rate.aifc.json",
    true,
  );
  check(
    "AIFC_noninteger_rate.aifc",
    "AIFC_noninteger_rate.aifc.n.json",
    false,
  );
}

#[test]
fn aiff_extended_integer_overflow_conformance() {
  // Codex R7 regression: 80-bit extended `403e8000000000000001` decodes to
  // the EXACT integer 2^63 + 1 = 9223372036854775809, which overflows i64.
  // Perl's `GetExtended` preserves the exact integer (Perl scalars keep
  // UV/IV when arithmetic permits), and the EscapeJSON gate quotes any >15
  // digit integer text — so bundled ExifTool emits `AIFF:SampleRate` as
  // the QUOTED string `"9223372036854775809"`. Prior `(sig as f64) as i64`
  // rounded the significand to 2^63 (lossy at the 53-bit mantissa boundary)
  // and then saturated the cast to i64::MAX, storing 9223372036854775807.
  // Post-fix `get_extended` uses integer arithmetic on the bit pattern to
  // detect the exact integer value and emits `TagValue::Str("9223372036854775809")`
  // for the >i64::MAX magnitude — the serializer's `is_json_number_literal`
  // gate then quotes it (16+ digits exceeds the `\d{1,15}` cap), byte-exact
  // to Perl. The Composite:Duration with NumSampleFrames=1000 is the
  // same 1000 / 9223372036854775809.0 ≈ 1.0842021724855e-16 in both
  // languages (the f64 division uses the IEEE-754 rounded denominator).
  check(
    "AIFF_ext_int_overflow.aif",
    "AIFF_ext_int_overflow.aif.json",
    true,
  );
  check(
    "AIFF_ext_int_overflow.aif",
    "AIFF_ext_int_overflow.aif.n.json",
    false,
  );
}

#[test]
fn aiff_extended_integer_negative_overflow_conformance() {
  // Codex R7 follow-up: 80-bit extended `c03e8000000000000001` decodes
  // to -(2^63 + 1) = -9223372036854775809, whose magnitude exceeds i64::MIN.
  // Perl's `GetExtended` forces NV here (`-1 * UV` cannot stay UV when
  // UV > i64::MAX), so the scalar becomes NV stringified as `%.15g` ⇒
  // `-9.22337203685478e+18`. Oracle (bundled `perl exiftool`, captured
  // 2026-05-20): `"AIFF:SampleRate": -9.22337203685478e+18` (BARE numeric,
  // not a quoted string — `%.15g` form is < 15 digits with the exponent).
  // The prior `int_or_str` symmetric branch emitted
  // `TagValue::Str("-9223372036854775809")` (exact-decimal quoted), which
  // diverged from the oracle. Post-fix: negatives > 2^63 magnitude route
  // through `TagValue::F64(- mag as f64)`, matching Perl's NV path.
  check(
    "AIFF_ext_int_neg_overflow.aif",
    "AIFF_ext_int_neg_overflow.aif.json",
    true,
  );
  check(
    "AIFF_ext_int_neg_overflow.aif",
    "AIFF_ext_int_neg_overflow.aif.n.json",
    false,
  );
}

#[test]
fn aiff_huge_duration_conformance() {
  // Codex R7 regression: SampleRate extended `3fab8000000000000000` decodes
  // to 2^-84 = 5.16987882845642e-26 (a very small non-integer). With
  // NumSampleFrames=1, Composite:Duration = 1 / 2^-84 = 2^84 ≈
  // 1.93428131138341e+25 seconds. Prior `convert_duration` cast `h/m/s`
  // through `f64::trunc as i64` and SATURATED at i64::MAX for the huge h
  // value, producing wrong sub-day numbers. Perl keeps h/m/d as NV (f64)
  // scalars through the modulo arithmetic, only casting the SMALL
  // REMAINDERS to integer at the final `%d:%.2d:%.2d` printf. Oracle
  // (2026-05-20): default PrintConv ⇒ `"2.23875151780487e+20 days 0:00:00"`
  // (the days count `$d` interpolated via Perl's default NV stringification,
  // byte-exact to `format_g(d, 15)` in scientific notation); `-n` ⇒ raw
  // f64 `1.93428131138341e+25` (format_g(_, 15) roundtrip).
  check(
    "AIFF_huge_duration.aif",
    "AIFF_huge_duration.aif.json",
    true,
  );
  check(
    "AIFF_huge_duration.aif",
    "AIFF_huge_duration.aif.n.json",
    false,
  );
}

#[test]
fn aiff_negative_zero_significand_extended_conformance() {
  // Codex R8 regression: an AIFF SampleRate extended with `sig == 0` but
  // a NON-zero biased exponent and the negative sign bit set
  // (`80010000000000000000`). Mathematically the value is `-1 * 0 *
  // 2^-16445 = 0`. Perl evaluates `$sign * $sig * (2 ** $exp)` and the
  // NV multiplication by 0 yields exactly 0 (the sign bit is dropped by
  // the multiplication itself, NOT preserved as -0). The prior
  // `get_extended` guard was `sig == 0 && biased == 0`, so this
  // adversarial input flowed through the f64 reconstruction `0.0`
  // followed by `-0.0 = -val` ⇒ `TagValue::F64(-0.0)`, and the
  // serializer's `format_g(-0.0, 15)` emitted bare `-0` — diverging
  // from the oracle's bare `0`. Post-fix: `sig == 0` (any biased)
  // short-circuits to `TagValue::I64(0)`, byte-exact.
  check("AIFF_neg_zero_sig.aif", "AIFF_neg_zero_sig.aif.json", true);
  check(
    "AIFF_neg_zero_sig.aif",
    "AIFF_neg_zero_sig.aif.n.json",
    false,
  );
}

#[test]
fn aiff_zero_significand_max_exponent_nan_conformance() {
  // Codex R9 regression: an AIFF SampleRate extended with `sig == 0` AND
  // `biased == 0x7FFF` (the infinity exponent slot, `0x7fff0000000000000000`).
  // Mathematically `0 * 2 ** 16321 = 0 * Inf = NaN` per IEEE-754. Perl's
  // NV multiplication `$sig * (2 ** $exp)` with `$sig = 0` and `$exp = 16321`
  // yields NaN, which Perl stringifies as titlecase `NaN`. The R8 fix
  // `sig == 0 ⇒ I64(0)` was too broad — it returned bare 0 here, diverging
  // from oracle's `"NaN"`. Post-fix: the short-circuit fires only when
  // `biased != 0x7FFF`; the infinity-exponent + zero-sig case falls
  // through to the f64 path where `0.0 * 2^16321 = NaN` is propagated
  // via `perl_nonfinite_str`. Oracle (2026-05-20) confirms both
  // SampleRate and Composite:Duration emit quoted `"NaN"` (the
  // ConvertDuration `unless IsFloat` branch on a NaN also returns NaN).
  check(
    "AIFF_zero_sig_max_exp.aif",
    "AIFF_zero_sig_max_exp.aif.json",
    true,
  );
  check(
    "AIFF_zero_sig_max_exp.aif",
    "AIFF_zero_sig_max_exp.aif.n.json",
    false,
  );
}

#[test]
fn aiff_infinity_sample_rate_conformance() {
  // Codex R8 regression: an AIFF SampleRate extended with the maximum
  // biased exponent (`7fff8000000000000000`). The 80-bit-extended-to-f64
  // reconstruction overflows to `f64::INFINITY`. Perl's NV scalar for
  // infinity stringifies as titlecase `Inf` (verified 2026-05-20 via
  // `perl -e 'print 1e308*1e308'` ⇒ `Inf`). Prior `serialize.rs` non-
  // finite branch called `f64::to_string` which emits lowercase `inf` —
  // diverging from the oracle. Post-fix: `perl_nonfinite_str` produces
  // titlecase `Inf`/`-Inf`/`NaN`, byte-exact to Perl. The
  // Composite:Duration falls through as `1000.0 / inf = 0.0` ⇒ default
  // PrintConv `"0 s"` (the `time == 0.0` branch of ConvertDuration),
  // `-n` ⇒ bare `0`.
  check(
    "AIFF_inf_sample_rate.aif",
    "AIFF_inf_sample_rate.aif.json",
    true,
  );
  check(
    "AIFF_inf_sample_rate.aif",
    "AIFF_inf_sample_rate.aif.n.json",
    false,
  );
}

#[test]
fn aiff_exp53_integer_fits_i64_routes_via_nv_conformance() {
  // Codex R10 regression: SampleRate extended `40730000000000000001`
  // (biased=0x4073=16499, exp=53, sig=1). Mathematically `1 * 2^53 =
  // 9007199254740992` is an EXACT integer that fits i64. The prior
  // `exp >= 0` integer-detection path emitted `TagValue::Str
  // ("9007199254740992")` (16 digits ⇒ EscapeJSON quote), but Perl's
  // `$sig * (2 ** $exp)`:
  // - `2 ** 53` is NV (Devel::Peek-verified)
  // - `UV(1) * NV(2^53)`: when the NV factor != 1, Perl's multiplication
  //   PROMOTES to NV; the result is NV(9007199254740992) which
  //   stringifies via `%.15g` to `9.00719925474099e+15`.
  // Oracle (2026-05-20) confirms BARE `9.00719925474099e+15` (NV
  // scientific). Post-fix: the integer-detection path fires ONLY when
  // `exp == 0` (the only case where `2**exp = 1` and Perl preserves
  // UV); for any `exp != 0`, route through f64/NV. Pinned by this
  // adversarial input where the int_or_str path WOULD have fit i64 but
  // Perl's NV typing means the output must be scientific.
  check(
    "AIFF_r10_exp53_fits_i64.aif",
    "AIFF_r10_exp53_fits_i64.aif.json",
    true,
  );
  check(
    "AIFF_r10_exp53_fits_i64.aif",
    "AIFF_r10_exp53_fits_i64.aif.n.json",
    false,
  );
}

#[test]
fn aiff_first_overflow_zero_significand_conformance() {
  // Codex R9 recommendation: pin the "first-overflow zero significand"
  // boundary — SampleRate extended `443e0000000000000000` (biased =
  // 0x443E = 17470, exp = 17470-16383-63 = 1024, sig = 0). Even though
  // sig=0, `2^1024` overflows f64 to Inf at the f64::MAX_EXP boundary,
  // so `0 * 2^1024 = 0 * Inf = NaN`. Oracle (2026-05-20) emits
  // `"AIFF:SampleRate": "NaN"` and `"Composite:Duration": "NaN"` —
  // pinning the gate `2f64.powi(exp).is_finite()` for the sig==0
  // short-circuit (the prior `biased != 0x7FFF` test was too lax: any
  // `exp >= 1024` overflows even though `biased < 0x7FFF`).
  check(
    "AIFF_first_overflow_zero_sig.aif",
    "AIFF_first_overflow_zero_sig.aif.json",
    true,
  );
  check(
    "AIFF_first_overflow_zero_sig.aif",
    "AIFF_first_overflow_zero_sig.aif.n.json",
    false,
  );
}

#[test]
fn aiff_first_nv_exponent_conformance() {
  // Codex R9 recommendation: pin the "first NV exponent" boundary —
  // SampleRate extended `40738000000000000000` (biased=0x4073=16499,
  // exp=16499-16383-63=53, sig=2^63). Pure-integer value: 2^63 * 2^53
  // = 2^116. u128 holds this (sig_bits=64, shift=53, total=117 <= 128),
  // so `int_or_str(false, 2^116)` ⇒ magnitude > u64::MAX ⇒ Perl forces
  // NV ⇒ `TagValue::F64(2^116 as f64)`. The serializer's `format_g(_,
  // 15)` then produces `8.30767497365572e+34` — byte-exact to Perl's
  // `%.15g` of 2^116 (oracle 2026-05-20). Pins the int_or_str
  // `mag > u64::MAX ⇒ F64` branch as the "first NV exponent" boundary.
  check("AIFF_first_nv_exp.aif", "AIFF_first_nv_exp.aif.json", true);
  check(
    "AIFF_first_nv_exp.aif",
    "AIFF_first_nv_exp.aif.n.json",
    false,
  );
}

#[test]
fn aiff_huge_positive_exponent_overflow_conformance() {
  // Codex R9 regression: SampleRate extended `407f8000000000000000` —
  // biased exp 0x407F = 16511, exp = 16511 - 16383 - 63 = 65, sig =
  // 0x8000000000000000 (= 2^63). Pure-integer value: 2^63 * 2^65 = 2^128.
  // u128 cannot exactly hold 2^128, so the `exp >= 0` integer-detection
  // branch MUST detect this overflow and fall through to the f64/NV path.
  //
  // The prior `(sig as u128).checked_shl(shift)` ONLY checked the shift
  // amount (< 128), NOT the value-overflow: `(2^63_u128) << 65` returned
  // `Some(0)` because the high bit was silently dropped, then
  // `int_or_str(false, 0)` emitted `I64(0)`, diverging from Perl's
  // `3.40282366920938e+38` (= 2^128 as NV, byte-exact `%.15g`).
  //
  // Post-fix uses the precise bit-count gate `64 - sig.leading_zeros() +
  // shift <= 128`; here `64 - 1 + 65 = 128` ≤ 128, so the path COULD
  // proceed — but the result `2^128` overflows u128 to 0 anyway. Actually
  // the correct gate is STRICT `< 128` for sig with high bit set when
  // the shift would push it past u128. Bundled oracle (2026-05-20):
  // `AIFF:SampleRate = 3.40282366920938e+38` (bare NV) and
  // `Composite:Duration = "0.00 s"` (1000/2^128 ≈ 2.94e-36, <30s ⇒
  // `%.2f s` ⇒ "0.00 s").
  check("AIFF_huge_pos_exp.aif", "AIFF_huge_pos_exp.aif.json", true);
  check(
    "AIFF_huge_pos_exp.aif",
    "AIFF_huge_pos_exp.aif.n.json",
    false,
  );
}

#[test]
fn aifc_conformance() {
  // Synthesized AIFC: FORM <sz> AIFC + FVER + COMM (with CompressionType
  // + CompressorName pstring) + NAME. Exercises the AIFC magic path
  // (SetFileType("AIFC")), the FVER FormatVersionTime branch, and the
  // CompressionType PrintConv hash + pstring decode in COMM.
  check("AIFC.aifc", "AIFC.aifc.json", true);
  check("AIFC.aifc", "AIFC.aifc.n.json", false);
}

#[test]
fn aifc_macroman_high_byte_compressor_name_conformance() {
  // Codex R1 regression: AIFC `CompressorName` pstring carrying MacRoman
  // high bytes 0x80 ("Ä") and 0x81 ("Å"). A prior
  // `from_utf8(...).unwrap_or_default()` in the binary engine would have
  // corrupted 0x80 (invalid UTF-8 start) to the empty string and lost the
  // tag; the post-fix path emits raw `TagValue::Bytes` that the MacRoman
  // ValueConv decodes faithfully. Oracle (bundled `perl exiftool`, captured
  // 2026-05-20): `AIFF:CompressorName = "Ä Å"` (U+00C4 U+0020 U+00C5).
  check("AIFC_macroman.aifc", "AIFC_macroman.aifc.json", true);
  check("AIFC_macroman.aifc", "AIFC_macroman.aifc.n.json", false);
}

#[test]
fn aifc_highbyte_compressiontype_conformance() {
  // Codex R3 regression: AIFC `CompressionType` (a no-ValueConv string[4]
  // with a hash PrintConv) carrying the invalid-UTF-8 lead byte 0x80
  // followed by ASCII "ABC". Perl's hash PrintConv lookup misses (no key
  // matches the raw 4 bytes), so the fallback path is `"Unknown ($val)"`,
  // where `$val` flows through `EscapeJSON` → `FixUTF8` (XMP.pm:2943):
  // invalid bytes are replaced with `?`. Bundled `perl exiftool` (oracle
  // captured 2026-05-20) emits `"Unknown (?ABC)"` under default PrintConv
  // and `"?ABC"` under `-n`. The earlier Latin-1 1:1 mapping in
  // `convert::exiftool_val_string` + the no-ValueConv `Bytes → Str` arms
  // in `processbinarydata.rs:323-326` and `formats/aiff.rs::APPL` would
  // have emitted `"\u{0080}ABC"` instead. This fixture pins the FixUTF8
  // path end-to-end on both the PrintConv (hash-key fallback) and `-n`
  // (raw byte-string serialize) branches.
  check(
    "AIFC_highbyte_comp.aifc",
    "AIFC_highbyte_comp.aifc.json",
    true,
  );
  check(
    "AIFC_highbyte_comp.aifc",
    "AIFC_highbyte_comp.aifc.n.json",
    false,
  );
}

#[test]
fn aifc_pre1970_format_version_time_conformance() {
  // Codex R4 regression: AIFC `FormatVersionTime` with raw u32 = 0 ⇒
  // pre-Unix-epoch timestamp `-2_082_844_800` after the AIFF.pm:26
  // `$val - ((66 * 365 + 17) * 24 * 3600)` subtraction. Perl runs
  // `gmtime` on the signed difference; `datetime::convert_unix_time`
  // here likewise decodes negative input via the proleptic Gregorian
  // Hinnant algorithm. Oracle (bundled `perl exiftool`, captured
  // 2026-05-20): `"1904:01:01 00:00:00"` — the Mac/AIFF epoch itself.
  // Codex R4 raised a `saturating_sub` concern as the source of a
  // potential zero-date sentinel; empirical refutation: the input is an
  // `i64` carrying a `u32`, so `0_i64.saturating_sub(2_082_844_800) =
  // -2_082_844_800` (identical to signed subtraction — `i64` saturates
  // at `i64::MIN`, not at 0). The code now uses plain `-` for clarity
  // and this fixture pins the negative-result path so any future
  // refactor toward `u64` / wrapping math is caught immediately.
  check("AIFC_pre1970.aifc", "AIFC_pre1970.aifc.json", true);
  check("AIFC_pre1970.aifc", "AIFC_pre1970.aifc.n.json", false);
}

#[test]
fn aifc_truncated_comm_conformance() {
  // Codex R3 regression: a truncated AIFC COMM chunk that provides only 1
  // byte of `CompressionType` (declared `string[4]`). ExifTool's `ReadValue`
  // (ExifTool.pm:6290-6293) shortens the count to the remaining bytes
  // (`int(size/len)`) and still emits a value when `count >= 1`; only when
  // zero bytes are available does it return `undef`. A prior
  // `if more < n { None }` bailout in `processbinarydata::StringFixed`
  // silently dropped truncated fields. Oracle (bundled `perl exiftool`,
  // captured 2026-05-20): `CompressionType = "Unknown (N)"` under default
  // PrintConv and `"N"` under `-n`; `CompressorName` is absent (no body
  // bytes for the pstring length byte after the clamped CompressionType).
  check(
    "AIFC_truncated_comm.aifc",
    "AIFC_truncated_comm.aifc.json",
    true,
  );
  check(
    "AIFC_truncated_comm.aifc",
    "AIFC_truncated_comm.aifc.n.json",
    false,
  );
}

#[test]
fn aiff_short_header_error_conformance() {
  // Adversarial: 11-byte FORM header (`FORM\0\0\0\x10AIF`) — too short for
  // the 12-byte magic verify (AIFF.pm:191). Reject before SetFileType
  // ⇒ no AIFF parser finalizes ⇒ the post-loop ExifTool:Error block fires
  // (ExifTool.pm:3080-3128). With the .aif extension a known type was
  // detected ⇒ 'File format error' (ExifTool.pm:3093).
  check("AIFF_short.aif", "AIFF_short.aif.json", true);
  check("AIFF_short.aif", "AIFF_short.aif.n.json", false);
}

#[test]
fn aiff_large_chunk_warn_conformance() {
  // Adversarial: valid AIFF header + COMM chunk with len=0xFFFFFFFF
  // (`len2 = len + (len & 1) > 100 MB`). Default `LargeFileSupport` is
  // truthy (`1`, ExifTool.pm:1167), so the AIFF.pm:230-235 inner
  // branches all fall through; the AIFF.pm:237-240 "known tagInfo" arm
  // fires ⇒ `Warn("Skipping large Common chunk (> 100 MB)")` + `undef
  // $tagInfo` ⇒ chunk body skipped. The oracle (bundled `perl exiftool`,
  // captured 2026-05-20) emits exactly this warning, then File:* tags.
  check("AIFF_huge.aif", "AIFF_huge.aif.json", true);
  check("AIFF_huge.aif", "AIFF_huge.aif.n.json", false);
}

#[test]
fn ape_id3_prefixed_conformance() {
  // Codex R2-F1 cross-format regression pin: APE.pm:122-127 embedded
  // ID3 dispatch. Fixture is a hand-crafted `.ape` whose first bytes
  // are an ID3v2.3 header (TIT2="TestTitle") followed by a 32-byte
  // MAC header (OldHeader, vers=3970) and an APEv2 trailer (Artist=
  // Tester). Bundled `perl exiftool` (verified 2026-05-20 against
  // 13.58):
  //   - ProcessAPE → ProcessID3 finds ID3 (DoneID3=1, $rtnVal=1).
  //   - ProcessID3's audio-loop (ID3.pm:1582-1601) recursively
  //     ProcessAPE → SetFileType(APE), MAC tags, APE trailer tag.
  //   - ID3.pm:1604 SetFileType('MP3') no-op (first-wins).
  //   - ID3.pm:1606-1611 emit File:ID3Size + ID3v2_3:Title.
  // Faithful Rust port flattens the audio-loop recursion: a single
  // ProcessApe::process runs both ID3 extraction AND the MAC/APE-trailer
  // work. Pinned: File:FileType=APE (not MP3), ID3v2_3:Title=TestTitle,
  // MAC:APEVersion=3.97, APE:Artist=Tester all present.
  check("ape_id3_prefixed.ape", "ape_id3_prefixed.ape.json", true);
  check("ape_id3_prefixed.ape", "ape_id3_prefixed.ape.n.json", false);
}

#[test]
fn mp3_with_apev2_trailer_conformance() {
  // Codex R2-F2 cross-format regression pin: ID3.pm:1722-1727 MP3 →
  // APE trailer fallback. Fixture is a hand-crafted `.mp3` with an
  // ID3v2.3 header (TIT2="TestMp3"), MPEG-1 Layer-III sync frame,
  // and APEv2 trailer (Artist=ApeTester). Bundled flow:
  //   - ProcessMP3 calls ProcessID3 → ID3 detected ($rtnVal=1).
  //   - audio loop's recursive ProcessMP3 invokes ParseMPEGAudio →
  //     MPEG:* tags emitted.
  //   - ProcessID3 emits File:ID3Size + ID3v2_3:Title.
  //   - ID3.pm:1722-1727 `if ($rtnVal and not $$et{DoneAPE}) {
  //     ProcessAPE(...) }` fires; ProcessAPE (chained, FileType set)
  //     finds the APEv2 footer → APE:Artist tag emitted.
  // Faithful port: ProcessMp3::process invokes process_id3_inner +
  // mpeg::ProcessMp3, then if rtn_val && !DoneAPE calls
  // ProcessApe::process_trailer_only — exactly mirroring the bundled
  // ordering.
  check(
    "mp3_with_apev2_trailer.mp3",
    "mp3_with_apev2_trailer.mp3.json",
    true,
  );
  check(
    "mp3_with_apev2_trailer.mp3",
    "mp3_with_apev2_trailer.mp3.n.json",
    false,
  );
}

#[test]
fn dsf_with_id3v2_trailer_conformance() {
  // Codex R2-F3 cross-format regression pin: DSF.pm:88-97 ID3v2
  // trailer at `metaPos`. Fixture is a hand-crafted `.dsf` with
  // valid DSD/fmt/data chunks and an ID3v2.3 trailer pointed-at by
  // `metaPos` (offset 28 of the DSD header). The ID3v2 trailer
  // contains TIT2="DsfTitle". Bundled flow:
  //   - DSF.pm:64 SetFileType (DSF), reads fmt chunk, emits
  //     `File:*` triplet + DSF binary-data tags.
  //   - DSF.pm:88-97 `if ($metaPos and $metaLen > 0 and $metaLen <
  //     20_000_000 and Seek+Read)` ⇒ ProcessDirectory(ID3::Main)
  //     over the trailer slice. PROCESS_PROC = ProcessID3Dir →
  //     ProcessID3 finds ID3 at slice offset 0, emits
  //     File:ID3Size + ID3v2_3:Title.
  // Faithful port: ProcessDsf::process reads metaPos from fmt chunk
  // header, slices `data[metaPos..metaPos+metaLen]`, and dispatches
  // process_id3_v2_slice over it.
  check(
    "dsf_with_id3v2_trailer.dsf",
    "dsf_with_id3v2_trailer.dsf.json",
    true,
  );
  check(
    "dsf_with_id3v2_trailer.dsf",
    "dsf_with_id3v2_trailer.dsf.n.json",
    false,
  );
}

#[test]
fn ape_id3v24_footer_then_mac_conformance() {
  // Codex R3 F1 regression pin: ID3.pm:1443 `$hdrEnd = 0`, :1486
  // `Seek(10, 1)` when `flags & 0x10` (v2.4 footer flag), :1504
  // `$hdrEnd = $raf->Tell()`. Without the +10 advance the chained
  // ProcessAPE re-reads from the wrong offset and sees `3DI` (the
  // footer magic) instead of `MAC ` — bundled finds the MAC body, our
  // pre-fix peek did not.
  //
  // Fixture layout (138 bytes):
  //   * 10-byte ID3v2.4 main header (vers=4.0, flags=0x10 [footer-flag],
  //     syncsafe size=24)
  //   * 24-byte body: TIT2 frame "TestV24Footer" (Title)
  //   * 10-byte FOOTER: `3DI` + vers + flags + size mirror of header
  //   * 32-byte MAC OldHeader (vers=3970, sample rate=44100, etc.)
  //   * 56-byte APEv2 trailer carrying APE:Artist="V24FooterTester"
  //     (32-byte footer + 24-byte tag-entry body)
  //
  // Pre-fix behavior: hdr_end = 10 + 24 = 34, slicing skipped the
  // 10-byte footer — `MAC ` magic was at offset 44 but APE saw the
  // footer bytes at offset 34 (`3DI\x04\x00\x10\x00\x00\x00\x18MAC `),
  // failed the magic check, fell through to the `id3_found` branch and
  // returned silently with NO `MAC:*`/`APE:*` tags.
  //
  // Post-fix behavior (matches bundled `perl exiftool 13.58`):
  // hdr_end = 10 + 24 + 10 = 44 → ape_slice begins at offset 44 with
  // `MAC ...` → full MAC header + APE trailer scan succeeds.
  check(
    "ape_id3v24_footer_then_mac.ape",
    "ape_id3v24_footer_then_mac.ape.json",
    true,
  );
  check(
    "ape_id3v24_footer_then_mac.ape",
    "ape_id3v24_footer_then_mac.ape.n.json",
    false,
  );
}

#[test]
fn mp3_with_apev2_and_id3v1_trailer_conformance() {
  // Codex R3 F2 regression pin: APE.pm:169 `$footPos -= $$et{DoneID3}
  // if $$et{DoneID3} > 1` — when ID3.pm:1527 stores 128 (ID3v1 trailer
  // size) in `$$et{DoneID3}`, the APETAGEX 32-byte trailer header sits
  // at `EOF - 32 - 128`, not `EOF - 32`. Pre-fix our APE scan used
  // `data.len() - 32` unconditionally, landing INSIDE the ID3v1 `TAG`
  // block and silently missing the APE trailer.
  //
  // Fixture layout (252 bytes):
  //   * ID3v2.3 (TIT2="TestMp3Id3v1") — 34 bytes total
  //   * MPEG-1 Layer-III sync frame + padding (32 bytes)
  //   * APEv2 trailer carrying APE:Artist="Mp3ApeArtist" (58 bytes
  //     trailer body + 32-byte footer)
  //   * ID3v1 TAG block (128 bytes) at EOF
  //
  // Post-fix behavior (matches bundled): the APE trailer is found at
  // `EOF - 32 - 128 = 92`, APE:Artist is emitted, AND the ID3v1 trailer
  // tags fire from the standalone ProcessID3 invocation. Bundled also
  // emits Composite:Duration via DoneID3-aware scanning; that composite
  // is the documented ACCEPTED-DEFERRAL hand-trim (Composite engine,
  // Phase 3+ — see docs/tracking.md) so the committed goldens omit it.
  check(
    "mp3_with_apev2_and_id3v1_trailer.mp3",
    "mp3_with_apev2_and_id3v1_trailer.mp3.json",
    true,
  );
  check(
    "mp3_with_apev2_and_id3v1_trailer.mp3",
    "mp3_with_apev2_and_id3v1_trailer.mp3.n.json",
    false,
  );
}

#[test]
fn ape_with_id3v1_trailer_conformance() {
  // Codex R3 F2 second regression pin: same DoneID3-shift logic in the
  // MAIN `plan_ape_inner` footer path (not just `plan_apetagex_trailer_
  // only`). A pure `.ape` file (no ID3v2 prefix) with both an APE
  // trailer AND an ID3v1 trailer was missing the APE:* tags pre-fix
  // because the footer scan at `data.len() - 32` lands inside the
  // 128-byte ID3v1 `TAG` block.
  //
  // Fixture layout (248 bytes):
  //   * 32-byte MAC OldHeader (vers=3970)
  //   * APEv2 trailer carrying APE:Artist="ApeId3v1Artist" + APE:Title=
  //     "ApeId3v1Title" (88 bytes: 56-byte tag-entry body + 32-byte footer)
  //   * ID3v1 TAG block (128 bytes) at EOF
  //
  // Post-fix behavior (matches bundled): ProcessID3 (called from
  // APE.pm:124-127) finds the ID3v1 trailer, sets DoneID3 = 128;
  // ProcessAPE's footer scan now uses `EOF - 32 - 128 = 88` and finds
  // the APETAGEX magic. Bundled also emits `Composite:DateTimeOriginal`
  // (from the engine composite system) which is the documented
  // ACCEPTED-DEFERRAL hand-trim (Composite engine, Phase 3+ — see
  // docs/tracking.md) so the committed golden omits it.
  check(
    "ape_with_id3v1_trailer.ape",
    "ape_with_id3v1_trailer.ape.json",
    true,
  );
  check(
    "ape_with_id3v1_trailer.ape",
    "ape_with_id3v1_trailer.ape.n.json",
    false,
  );
}

#[test]
fn ape_with_enhancedtag_and_id3v1_conformance() {
  // Codex R4 F2 regression pin: ID3.pm:1521-1525 — when a standard
  // ID3v1 TAG block is detected at `EOF - 128`, bundled ALSO probes
  // 227 bytes BEFORE it for an Enhanced TAG (matching `/^TAG+/`):
  //   my $eSize = 227;
  //   if ($raf->Seek(-$trailSize - $eSize, 2)
  //       and $raf->Read($eBuff, $eSize) == $eSize
  //       and $eBuff =~ /^TAG+/) {
  //       $id3Trailer{EnhancedTAG} = \$eBuff;
  //       $trailSize += $eSize;
  //   }
  //   $$et{DoneID3} = $trailSize;   # ID3.pm:1527
  //
  // The `^TAG+/` regex is `^TA` followed by `G+` (one or more G's) —
  // confirmed via `perl -e 'print "match" if "TAG" =~ /^TAG+/'`.
  // "TAG+rest" matches via the initial `TAG`. The fixture's Enhanced
  // TAG block begins with the literal bytes `TAG+` (the spec magic);
  // the bundled regex matches because `TAG` ⊂ `TAG+rest`.
  //
  // With Enhanced TAG present, bundled stores `DoneID3 = 128 + 227 =
  // 355` and APE.pm:169 `$footPos -= $$et{DoneID3}` walks BEFORE the
  // Enhanced TAG block when scanning for the APETAGEX footer. Our
  // pre-fix code hardcoded `128`, so the APE footer scan landed
  // INSIDE the Enhanced TAG block → APETAGEX magic missed → SILENT
  // miss of the APE:Artist tag.
  //
  // Fixture layout (454 bytes):
  //   * 32-byte MAC OldHeader (vers=3970)
  //   * APEv2 trailer (67 bytes: 35-byte body + 32-byte footer)
  //     carrying APE:Artist="ApeEnhancedTAGArtist"
  //   * 227-byte Enhanced TAG block (magic `TAG+`)
  //   * 128-byte standard ID3v1 TAG block at EOF
  //
  // F4 fix (Codex adversarial): the 7 `ID3v1_Enh:*` fields are now
  // emitted by `id3::v1_enh::process_id3v1_enh`, faithful to
  // `%Image::ExifTool::ID3::v1_Enh` (ID3.pm:380-425). The committed
  // golden retains all 7 — no longer hand-trimmed.
  //
  // ACCEPTED-DEFERRAL HAND-TRIM (a single line):
  // `Composite:DateTimeOriginal: 2024` is present in bundled output
  // and is the only Composite tag for this fixture. The Composite
  // metadata engine is the documented Phase-3+ accepted-deferral
  // (Composite:Duration / Composite:DateTimeOriginal etc., see
  // docs/tracking.md → "Accepted deferrals"). Hand-trim of ONLY this
  // one line is acceptable per the deferral contract; when the
  // Composite engine lands, re-capture via `tools/gen_golden.sh`.
  check(
    "ape_with_enhancedtag_and_id3v1.ape",
    "ape_with_enhancedtag_and_id3v1.ape.json",
    true,
  );
  check(
    "ape_with_enhancedtag_and_id3v1.ape",
    "ape_with_enhancedtag_and_id3v1.ape.n.json",
    false,
  );
}

#[test]
fn id3v24_footer_truncated_then_nothing_conformance() {
  // Codex R4 F1 regression pin: slice panic on truncated v2.4 footer.
  // ID3.pm:1484-1486 — `if ($flags & 0x10) { $raf->Seek(10, 1); }` —
  // the footer-flag seek is UNCONDITIONAL: filesystems allow seeking
  // past EOF, so `$raf->Tell()` at :1504 yields `10 + size + 10` even
  // when the 10 footer bytes were never written to the file. Bundled's
  // audio-loop then reads ZERO bytes past the EOF (no crash).
  //
  // Our pre-fix code computed `hdr_end = 10 + 24 + 10 = 44` and then
  // sliced `ctx.data()[44..]` over a 34-byte buffer → PANIC. The fix
  // at the consumer side (`ctx.data().get(hdr_end..).unwrap_or(&[])`
  // in `formats/ape.rs`) routes the same hdr_end through a saturating-
  // empty slice, byte-exactly matching bundled's "seek past EOF then
  // read nothing" behavior.
  //
  // Fixture layout (34 bytes):
  //   * 10-byte ID3v2.4 main header (vers=4.0, flags=0x10 [footer-flag],
  //     syncsafe size=24)
  //   * 24-byte body: TIT2 frame "TestV24TrFt0!" (13-byte text)
  //   * NO footer bytes (file truncated AT body end)
  //
  // Bundled golden: FileType=MP3 (extension fallback, no MPEG-audio
  // magic detected), ID3Size=34 (10 header + 24 body, faithful to
  // ID3.pm:1496 `$id3Len += length($hBuff) + 10` — bundled counts the
  // BODY-bytes-actually-read, not the would-have-been-skipped 10 footer
  // bytes), ID3v2_4:Title="TestV24TrFt0!".
  check(
    "id3v24_footer_truncated_then_nothing.mp3",
    "id3v24_footer_truncated_then_nothing.mp3.json",
    true,
  );
  check(
    "id3v24_footer_truncated_then_nothing.mp3",
    "id3v24_footer_truncated_then_nothing.mp3.n.json",
    false,
  );
}

#[test]
fn moi_conformance() {
  // FORMATS.md row 12a: Image::ExifTool::MOI. Bundled fixture
  // `tests/fixtures/MOI.moi` is the real `t/images/MOI.moi` (320 bytes,
  // V6 sidecar with DateTime / Duration / AspectRatio / AudioCodec /
  // AudioBitrate / VideoBitrate). Goldens captured from bundled
  // `perl exiftool` (`-j -G1 -struct` and `-n`).
  //
  // Exercises:
  //   - V6 magic + embedded BE u32 filesize gate (MOI.pm:110-114)
  //   - SetByteOrder('MM') for int16u/int32u walks (MOI.pm:116)
  //   - DateTimeOriginal `undef[8]` + sprintf('%06.3f',…) format
  //   - Duration `int32u/1000` + ConvertDuration sub-30s path
  //   - AspectRatio nibble decode (lo<2 + hi=5 ⇒ "4:3 PAL")
  //   - AudioCodec PrintHex + direct hash hit (0xC1 ⇒ AC3)
  //   - AudioBitrate `*16000+48000` + ConvertBitrate (kbps)
  //   - VideoBitrate hash ValueConv + ConvertBitrate (Mbps)
  check("MOI.moi", "MOI.moi.json", true);
  check("MOI.moi", "MOI.moi.n.json", false);
}

// Add one `#[test]` per ported format here, in FORMATS.md order, each
// asserting both snapshots: check("X.ext","X.ext.json",true) and
// check("X.ext","X.ext.n.json",false).
