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
fn ogg_conformance() {
  // FORMATS.md row 9 (Ogg + Vorbis-comments): a real Ogg-Vorbis fixture
  // from the bundled-ExifTool corpus. The committed golden is bundled
  // `perl exiftool -j -G1 -struct ... -x Composite:all -x
  // Vorbis:{VorbisVersion,AudioChannels,SampleRate,NominalBitrate,
  // MaximumBitrate,MinimumBitrate}`: `Composite:Duration` is deferred (no
  // Composite engine yet) and the Vorbis identification-binary fields
  // are deferred (R1 F2 scope tightening — see `src/formats/ogg.rs`
  // module docs). Every emitted tag is byte-exact with bundled Perl,
  // both with PrintConv on (default) and `-n`.
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
  // `perl exiftool`): NO `ExifTool:Warning` is emitted — only `Vorbis:Vendor`.
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
  // Composite:Duration and the Vorbis identification-binary fields
  // (VorbisVersion/AudioChannels/SampleRate/NominalBitrate/...) are
  // deferred (R1 F2 scope tightening) so the golden excludes them via
  // `-x Composite:all -x Vorbis:{VorbisVersion,AudioChannels,...}`.
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
fn ogg_opus_synthetic_conformance() {
  // A synthetic minimal Ogg-Opus stream (BOS page wrapping `OpusHead` +
  // EOS page wrapping `OpusTags` with vendor + 2 KEY=VALUE comments —
  // built in `examples/gen_synthetic_opus.rs`). Avoids the real
  // `Opus.opus` corpus fixture's `METADATA_BLOCK_PICTURE` which
  // SubDirectory-hops into `FLAC::Picture` (DEFERRED — see Picture
  // forward-items entry). Exercises `OverrideFileType('OPUS')`
  // (Ogg.pm:50) firing on the `OpusHead` packet, AND the `OpusTags`
  // Vorbis-comments delegation (Opus.pm:32) — the `Opus::Header`
  // binary table (Opus.pm:36-51) is deferred (R1 F2 scope tightening),
  // so `Opus:OpusVersion`/`AudioChannels`/`SampleRate`/`OutputGain` are
  // excluded from the golden via `-x`.
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

// Add one `#[test]` per ported format here, in FORMATS.md order, each
// asserting both snapshots: check("X.ext","X.ext.json",true) and
// check("X.ext","X.ext.n.json",false).
