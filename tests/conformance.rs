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
