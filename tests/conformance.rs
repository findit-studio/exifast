//! §4 conformance: `exifast::extract_info` output must be jsondiff-equivalent
//! to the bundled-ExifTool golden for every ported fixture, for both the
//! default (`-j -G1 -struct`) and `-n` snapshots. One case per ported
//! format — add a `#[test]` per format as it lands (FORMATS.md order).
use exifast::{jsondiff::json_equivalent, parser::extract_info, serialize::to_exiftool_json};

/// Assert exifast's output for `fixture` is equivalent to the committed
/// bundled-ExifTool golden `golden` via `json_equivalent` (object key
/// order insensitive; arrays order-significant; every scalar compared
/// token/lexeme-exact). `print_on` = ExifTool PrintConv (`false` ⇒ `-n`).
fn check(fixture: &str, golden: &str, print_on: bool) {
  let root = env!("CARGO_MANIFEST_DIR");
  let data = std::fs::read(format!("{root}/tests/fixtures/{fixture}"))
    .unwrap_or_else(|e| panic!("read fixture {fixture}: {e}"));
  let want = std::fs::read_to_string(format!("{root}/tests/golden/{golden}"))
    .unwrap_or_else(|e| panic!("read golden {golden}: {e}"));
  let got = to_exiftool_json(&extract_info(fixture, &data, print_on));
  json_equivalent(&got, &want).unwrap_or_else(|e| panic!("{fixture} vs {golden}: {}", e.message()));
}

#[test]
fn aac_conformance() {
  check("AAC.aac", "AAC.aac.json", true);
  check("AAC.aac", "AAC.aac.n.json", false);
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

// Add one `#[test]` per ported format here, in FORMATS.md order, each
// asserting both snapshots: check("X.ext","X.ext.json",true) and
// check("X.ext","X.ext.n.json",false).
