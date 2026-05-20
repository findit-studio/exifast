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

// Add one `#[test]` per ported format here, in FORMATS.md order, each
// asserting both snapshots: check("X.ext","X.ext.json",true) and
// check("X.ext","X.ext.n.json",false).
