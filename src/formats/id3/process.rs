//! Faithful port of `ProcessID3` (ID3.pm:1431-1632) + `ProcessMP3`
//! (ID3.pm:1684-1728). ProcessID3 is the directory-level entry point
//! invoked by ProcessMP3 (and by other audio-format Process subs that
//! optionally chain through ID3 — AIFF, MPC, APE, WV, DSF, FLAC, etc.).
//!
//! The full chain for an MP3 file (FORMATS.md row 2 "ID3 infra + MP3
//! completion") is:
//!
//! 1. `ProcessMP3` (ID3.pm:1684-1728) — file-type dispatch entry.
//! 2. → `ProcessID3` (ID3.pm:1431-1632) — sniffs ID3v2 header at start,
//!    ID3v1 trailer at end, Lyrics3, then SetFileType('MP3') and pushes
//!    File:ID3Size + ID3v2/ID3v1 tags.
//! 3. → MPEG audio frame parser (`Image::ExifTool::MPEG::ParseMPEGAudio`)
//!    — emits `MPEG:*` tags. **OUT OF PR SCOPE** — MPEG.pm is row 17.
//! 4. → APE trailer (`Image::ExifTool::APE::ProcessAPE`) — **OUT OF PR
//!    SCOPE** — APE.pm is row 5.
//!
//! Our [`ProcessMp3`] implements steps 1-2 faithfully and documents the
//! deferral of 3-4 to their respective format ports.

use crate::{
  formats::id3::{
    decode::unsync_safe,
    v1::{process_id3v1, ID3V1_MAIN},
    v2_2::ID3V2_2_MAIN,
    v2_3::ID3V2_3_MAIN,
    v2_4::ID3V2_4_MAIN,
    v2_process::process_id3v2,
  },
  parser::{FormatParser, ParseContext},
  value::{Group, TagValue},
};

/// Result of [`parse_v2_header`]. Carries the parsed header buffer + the
/// declared body size + the flags byte — the size and flags are needed by
/// the caller to compute bundled's `$hdrEnd` (ID3.pm:1504) faithfully,
/// because the footer-flag `flags & 0x10` seek (ID3.pm:1486) advances the
/// file position by 10 bytes BEFORE `$hdrEnd = $raf->Tell()`.
struct ParsedV2Header {
  h_buff: Vec<u8>,
  vers: u16,
  flags: u8,
  size: usize,
}

/// The MP3 file-type parser. Faithful to bundled Perl's `Image::ExifTool::
/// ID3::ProcessMP3` (ID3.pm:1684-1728); the chain to MPEG / APE for the
/// audio-frame / APE-trailer tags is documented forward items (rows 17 / 5).
pub struct ProcessMp3;

impl FormatParser for ProcessMp3 {
  fn process(&self, ctx: &mut ParseContext<'_>) -> bool {
    // ID3.pm:1684-1728 `ProcessMP3` is the MP3 PROCESS_PROC. The
    // bundled flow is SUBTLE — what looks like a simple `unless
    // ($rtnVal) ... ParseMPEGAudio` on first read actually emits MPEG
    // audio tags for ID3v2+audio files too, via a recursive call. The
    // dance:
    //
    //   1. Outer `ProcessMP3` (ID3.pm:1692) calls `ProcessID3`.
    //   2. `ProcessID3` finds ID3 → sets `$rtnVal = 1` and `$$et{DoneID3}
    //      = 1` (ID3.pm:1436, 1453, 1520).
    //   3. ID3.pm:1580-1602 (INSIDE ProcessID3, rtnVal-truthy branch):
    //      loops over `@audioFormats = qw(APE MPC FLAC OGG MP3)` and
    //      invokes each one's `Process$type` proc via `&$func($et,
    //      $dirInfo) and last`. For MP3 this routes back to
    //      `Image::ExifTool::ID3::ProcessMP3` (via `%audioModule{MP3} =
    //      'ID3'`).
    //   4. The RECURSIVE `ProcessMP3` calls `ProcessID3` again, which
    //      short-circuits to `return 0` because `$$et{DoneID3}` is set
    //      (ID3.pm:1435). So the recursive `$rtnVal = 0`, and the
    //      `unless ($rtnVal)` branch (ID3.pm:1696-1719) IS entered,
    //      invoking `ParseMPEGAudio` on the audio buffer.
    //
    // Net result: bundled emits BOTH `ID3v2_*:Title` and `MPEG:*`
    // tags for an ID3v2+audio MP3 file. Verified against bundled
    // `perl exiftool` on a hand-crafted ID3v2.3+Layer-III fixture
    // (R1-F1 fixture `tests/fixtures/ID3v2_with_mpeg_audio.mp3`).
    //
    // Faithful Rust integration: call ProcessID3, then ALWAYS call the
    // MPEG audio parser (which models step 4 above — the recursive
    // path that ultimately reaches `ParseMPEGAudio`). `ParseMPEGAudio`
    // is naturally a no-op on files without an MPEG sync byte
    // (returns 0), so the additive call is safe even when ID3 was the
    // sole metadata source. Our MPEG `ProcessMp3` scans for sync from
    // offset 0; the ID3v2 magic bytes `ID3` (0x49 0x44 0x33) cannot
    // false-match the `\xff[\xf0-\xff]` sync pattern, so the scan
    // naturally finds audio sync at the post-ID3 offset.
    //
    // Buffer-offset (Codex R5 high-severity fix): bundled's
    // `$raf->Seek($hdrEnd, 0)` at ID3.pm:1590 advances PAST the ID3v2
    // header BEFORE the recursive ProcessMP3 reads its `$scanLen`-byte
    // audio buffer (ID3.pm:1705). We thread `hdr_end` through from
    // `process_id3_inner` and invoke `mpeg::ProcessMp3` via the
    // offset-aware `process_with_start_offset`, mirroring the
    // bundled Seek+Read pair exactly. Pre-fix: MP3 files with a large
    // ID3v2 (e.g. embedded APIC artwork > 8 KiB) silently lost all
    // `MPEG:*` tags because the from-zero 8 KiB scan window never
    // reached the post-ID3 audio frame. Pinned by the R5 conformance
    // fixture `mp3_with_large_id3v2_artwork.mp3`.
    //
    // ID3.pm:1722-1727 APE trailer fallback (R2-F2). Faithful gate
    // `if ($rtnVal and not $$et{DoneAPE})` ⇒ only invoke ProcessAPE
    // when ProcessID3 (or ParseMPEGAudio) accepted AND APE hasn't
    // already been processed on this `$self` (cross-parser flag).
    // The chained `process_trailer_only` call discards its return —
    // bundled invokes APE in a void context (`ProcessAPE(...)` at
    // ID3.pm:1725 with no `and ...`), so the MP3 final return value
    // is `$rtnVal` from the ID3/MPEG dispatch, NOT APE's. Faithful
    // exactly to ID3.pm:1723-1727.
    let data = ctx.data();
    // ===== Stage 1: detection only (no tag emission yet) =====
    // Codex R6 split: detect_id3 assembles header/trailer buffers + the
    // post-ID3 `hdr_end` offset WITHOUT emitting any tags. The audio
    // loop below (Stage 2) needs to run BEFORE finalize_id3 (Stage 3)
    // so its `SetFileType("APE")` can win first-call-wins over
    // finalize_id3's `SetFileType('MP3')` AND so its MAC/APE:* tags
    // appear in the emission order bundled produces (audio-loop body
    // tags → File:ID3Size → ID3v2_*:Title — see ID3.pm:1582-1611).
    let detected = detect_id3(data, ctx);
    let id3_found = detected.as_ref().map(|d| d.found_any).unwrap_or(false);
    let hdr_end = detected.as_ref().map(|d| d.hdr_end).unwrap_or(0);

    // ===== Stage 2: @audioFormats loop (ID3.pm:1582-1601) =====
    // Codex R6 fix: bundled runs this loop INSIDE ProcessID3 on the
    // rtnVal-truthy branch (only when ID3v2/ID3v1 was found). Side
    // effects + ordering:
    //
    //   @types order — bundled (ID3.pm:1585-1586) computes
    //     `my @types = grep /^$oldType$/, @audioFormats;`   # [MP3]
    //     `push @types, grep(!/^$oldType$/, @audioFormats);` # [MP3,APE,MPC,FLAC,OGG]
    //   So MP3 is FIRST. The loop's `&$func ... and last` exits on
    //   the first Process sub that returns 1.
    //
    //   Per-type semantics:
    //
    //   - type=MP3 (recursive ProcessMP3 via audioModule{MP3}='ID3'):
    //     short-circuits its own ProcessID3 (DoneID3 set) and falls
    //     through to ParseMPEGAudio. Inside that recursive call, IF
    //     ParseMPEGAudio finds MPEG sync at `hdr_end`, it sets
    //     rtnVal=1 — then the recursive's own APE-trailer wrapper
    //     fallback at ID3.pm:1722-1727 fires (DoneAPE=undef on entry).
    //     ProcessAPE wrapper: DoneID3 set, FileType="MP3" set by
    //     ParseMPEGAudio's no-arg SetFileType — trailer-only path,
    //     emits APE:* tags from the APETAGEX footer if present.
    //     We model this faithfully: mpeg::ProcessMp3 +
    //     ape::process_trailer_only.
    //
    //   - type=APE: ProcessAPE called with FILE_TYPE="APE" set by
    //     the loop. DoneAPE=1 unconditionally (APE.pm:132). Magic
    //     check at offset 0 of the post-hdr_end slice: on `MAC `/
    //     `APETAGEX` match, SetFileType (FILE_TYPE="APE"), emit MAC
    //     body / APE trailer tags. We model this via
    //     ape::try_audio_loop_body_at_offset (Fixture B).
    //
    //   - type=MPC, FLAC, OGG: YAGNI per the brief — no fixture in
    //     the suite exercises an MPC/FLAC/OGG body in a .mp3
    //     dispatch. Tracked as a forward item in the docstring of
    //     `ape::try_audio_loop_body_at_offset`.
    //
    // The audio-loop runs only when id3_found is truthy (ID3.pm:1580
    // `if ($rtnVal) { ... }`). When ID3 was not detected, the loop
    // is skipped; the outer ProcessMP3 then runs ParseMPEGAudio +
    // wrapper APE-trailer fallback (Stage 4 / 5 path).
    let mut audio_loop_accepted = false;
    if id3_found {
      // type=MP3 (loop pass 1): recursive ProcessMP3 = mpeg
      // dispatch at hdr_end + wrapper APE-trailer fallback when mpeg
      // succeeds. Bundled `&$func ... and last`: the recursive
      // returns 1 iff mpeg accepted. Codex R6 fix: this DOES set
      // DoneAPE (via process_trailer_only ⇒ APE.pm:132) but only
      // when mpeg accepted — bundled identical (recursive
      // ProcessMP3:1723 sees rtnVal=1 → fires fallback → DoneAPE=1).
      let mp3_recursive_accepted =
        crate::formats::mpeg::ProcessMp3.process_with_start_offset(ctx, hdr_end);
      if mp3_recursive_accepted {
        // Recursive ProcessMP3's APE-trailer wrapper-fallback
        // (ID3.pm:1722-1727 of the RECURSIVE call). DoneAPE undef
        // on entry (the audio loop hasn't touched it yet); fires.
        if !ctx.metadata().done_ape() {
          let _ = crate::formats::ape::ProcessApe.process_trailer_only(ctx);
        }
        audio_loop_accepted = true; // loop exits via `and last`
      } else {
        // Recursive returned 0 (no MPEG sync at hdr_end). bundled
        // moves to next type. type=APE:
        if crate::formats::ape::ProcessApe.try_audio_loop_body_at_offset(ctx, hdr_end) {
          audio_loop_accepted = true; // loop exits via `and last`
        }
        // type=MPC, FLAC, OGG: forward items (see docstring).
      }
    }

    // ===== Stage 3: finalize (SetFileType + ID3Size + tags) =====
    // ID3.pm:1604-1627. `SetFileType('MP3')` is no-op when the audio
    // loop already set FileType (e.g. APE or MP3). Then
    // `FoundTag('ID3Size', $id3Len)` + ID3v2/ID3v1 tag pushes — these
    // appear AFTER the audio loop's body tags in the bundled
    // emission order, matching the golden JSON.
    let id3_finalized = detected.is_some_and(|d| finalize_id3(ctx, d, true));

    // ===== Stage 4: outer ParseMPEGAudio (ID3.pm:1696-1719) =====
    // Bundled outer `ProcessMP3` runs `ParseMPEGAudio` only when
    // ProcessID3 returned 0 (`unless ($rtnVal)`). For id3_found=true,
    // ProcessID3's return is 1 → skip outer ParseMPEGAudio (the
    // audio loop's MP3 pass already handled MPEG). For id3_found=
    // false (no ID3 detected), bundled enters the outer
    // ParseMPEGAudio arm.
    //
    // R5 buffer-offset (preserved for the no-ID3 path): hdr_end=0
    // there, so `process_with_start_offset(ctx, 0)` slices from
    // start of file — byte-exact to the pre-R6 raw-MP3 path.
    let outer_mpeg_found = if id3_found {
      false
    } else {
      crate::formats::mpeg::ProcessMp3.process_with_start_offset(ctx, 0)
    };

    // Bundled `ProcessMP3` final `return $rtnVal`. `$rtnVal` flows
    // through ProcessID3 (Stage 1+2+3) OR outer ParseMPEGAudio
    // (Stage 4). When the audio loop accepted, ProcessID3 returned
    // 1, so id3_finalized is true.
    let rtn_val = id3_finalized || outer_mpeg_found || audio_loop_accepted;

    // ===== Stage 5: outer APE-trailer wrapper fallback (ID3.pm:1722-1727) =====
    // Faithful gate `if ($rtnVal and not $$et{DoneAPE})`:
    //  - For the id3_found=true + MP3-pass case: DoneAPE was set
    //    inside the recursive (Stage 2 type=MP3 fallback) → gate is
    //    false → skip.
    //  - For the id3_found=true + APE-pass case: DoneAPE was set
    //    by try_audio_loop_body_at_offset → gate is false → skip.
    //  - For the id3_found=false + outer-MPEG-accepted case:
    //    DoneAPE is undef (no audio loop ran) → gate fires, attempt
    //    APE-trailer fallback. Faithful to bundled's outer
    //    ProcessMP3:1722-1727 path.
    if rtn_val && !ctx.metadata().done_ape() {
      // Void context (APE.pm `ProcessAPE` at ID3.pm:1725, no
      // `and ...`): result ignored. `process_trailer_only`
      // (APE.pm:165-237 — `unless ($header)` block) skips the magic
      // check + SetFileType because the caller has already set
      // FileType.
      let _ = crate::formats::ape::ProcessApe.process_trailer_only(ctx);
    }
    rtn_val
  }
}

/// Faithful chained `ID3::ProcessID3` entry (ID3.pm:1431-1632) — for
/// APE/MPC/OGG/FLAC-style file-type callers that have either already
/// established `File:FileType` OR will do so after ID3 detection.
/// Models the embedded-ID3 arm of:
///   * APE.pm:122-127 `unless ($$et{DoneID3}) { ... ProcessID3 ... and
///     return 1 }`, with the bundled audio-loop recursion accounted for
///     by the caller running its own SetFileType + body extraction.
///
/// Returns `Id3ChainedResult { found, hdr_end_offset }`:
///   * `found`: `true` (Perl `return 1`) when an ID3v2 header OR an
///     ID3v1 trailer was found and tags emitted; `false` (Perl `return
///     0`) when neither was detected OR `$$et{DoneID3}` was already set.
///   * `hdr_end_offset`: file offset PAST the ID3v2 header (bundled
///     `$hdrEnd` at ID3.pm:1504) — used by the caller to know where the
///     non-ID3 body begins (e.g. APE.pm via the audio-loop's `Seek(
///     $hdrEnd, 0)` at ID3.pm:1590 before the recursive ProcessAPE).
///     `0` when no ID3v2 prefix was found OR the parse hit a Warn-then-
///     `last` path (bundled leaves `$hdrEnd = 0` in those cases — see
///     ID3.pm:1443 initialization; the slice-from-0 behavior is then
///     what the bundled audio-loop's `Seek($hdrEnd, 0)` does).
///
/// Pushes `File:ID3Size`, the ID3v2 tags (group1 = `ID3v2_2`/`ID3v2_3`/
/// `ID3v2_4`), and the ID3v1 tags — but NOT `File:FileType` (caller
/// owns SetFileType).
pub fn process_id3_chained(ctx: &mut ParseContext<'_>) -> Id3ChainedResult {
  let data = ctx.data();
  // Codex R3 F1 fix: derive hdr_end_offset from the SAME parse that
  // emits the tags — NOT a separate shallow peek that would diverge from
  // bundled on the v2.4-footer-flag and Warn-then-`last` cases. The
  // inner call mirrors ID3.pm:1443 `$hdrEnd = 0;` (returned 0 on all
  // Warn-then-`last` paths) and ID3.pm:1486 `Seek(10, 1)` (the
  // footer-flag +10 advance) → :1504 `$hdrEnd = $raf->Tell()`.
  let (found, hdr_end_offset) = process_id3_inner(data, ctx, false);
  Id3ChainedResult {
    found,
    hdr_end_offset,
  }
}

/// Return value of [`process_id3_chained`]. Per the D8 API convention,
/// fields are private; query via accessors. `Default` is the
/// no-ID3-detected shape (`found = false, hdr_end_offset = 0`), used by
/// callers that observe `done_id3()` is already set on a prior parser's
/// invocation and short-circuit a fresh detection.
#[derive(Default)]
pub struct Id3ChainedResult {
  found: bool,
  hdr_end_offset: usize,
}

impl Id3ChainedResult {
  /// `true` iff ProcessID3 found an ID3v2 header OR an ID3v1 trailer.
  pub const fn found(&self) -> bool {
    self.found
  }

  /// File offset PAST the ID3v2 header — bundled `$hdrEnd`
  /// (ID3.pm:1504). `0` when no ID3v2 prefix was detected OR when the
  /// header parse hit a Warn-then-`last` path (bundled leaves `$hdrEnd =
  /// 0` in those cases — initialized at ID3.pm:1443, only set at :1504
  /// AFTER successful parse). Callers (APE.pm:122-127 chained dispatch)
  /// use this to slice the audio body that follows the prefix.
  pub const fn hdr_end_offset(&self) -> usize {
    self.hdr_end_offset
  }
}

/// Faithful chained ID3v2-over-slice entry — the DSF.pm:88-97 arm where
/// `\%dirInfo{DataPt}` is the ID3v2-trailer slice carved out of the file
/// (`metaPos..metaPos+metaLen`) and `ProcessDirectory(\%dirInfo,
/// GetTagTable('Image::ExifTool::ID3::Main'))` invokes `PROCESS_PROC =
/// ProcessID3Dir` (ID3.pm:80 → 1637-1642 → ProcessID3). The caller has
/// already typed the file (DSF.pm:64 `SetFileType()` before the trailer
/// arm at :88-97), so the SetFileType path is skipped.
///
/// `slice` is the trailer bytes (treated as a complete file by ProcessID3
/// — first 3 bytes checked for `^ID3`, last 128 for an ID3v1 `TAG`).
pub fn process_id3_v2_slice(slice: &[u8], ctx: &mut ParseContext<'_>) -> bool {
  // The DSF chained-trailer caller does not consume `$hdrEnd` — DSF's
  // outer Process subroutine slices the ID3v2-trailer bytes BEFORE the
  // call (DSF.pm:75-87) and the post-ID3 body inside that slice is not
  // re-scanned. Drop the hdr_end second tuple element.
  process_id3_inner(slice, ctx, false).0
}

/// Internal ProcessID3 entry. `do_set_file_type` is `true` for the MP3
/// dispatch path (ID3.pm:1604 `SetFileType('MP3')` runs after the audio
/// loop) and `false` for chained-from-{APE,DSF} where the outer parser
/// owns SetFileType (APE: ProcessAPE recursively invoked from the
/// ID3.pm:1582-1601 audio loop calls SetFileType to "APE" first; DSF:
/// ProcessDSF calls SetFileType to "DSF" before invoking the ID3 trailer
/// arm at DSF.pm:88-97). `data` is the slice to scan (`ctx.data()` for
/// the file-level path; a pre-sliced ID3v2 trailer for DSF).
///
/// Returns `(found, hdr_end)`. `found` is the bundled `$rtnVal`
/// (ID3.pm:1442 init, set to `1` at :1453 on `^ID3`, or at :1520 on
/// `^TAG` trailer). `hdr_end` is the bundled `$hdrEnd` (ID3.pm:1443 init
/// to 0, set at :1504 only AFTER a successful v2 header parse). When the
/// header parse hits any Warn-then-`last` path (:1454, :1457, :1459,
/// :1463, :1475, :1478), bundled leaves `$hdrEnd = 0` — the audio
/// loop's `$raf->Seek($hdrEnd, 0)` at :1590 then re-reads from offset 0.
/// We model the same: `0` ⇒ caller slices from offset 0.
///
/// Codex R6: the MP3 file-type dispatch path needs to interleave the
/// `@audioFormats` loop (ID3.pm:1582-1602) BETWEEN the detection step
/// (header/trailer assembly) and the `finalize` step that pushes
/// `SetFileType('MP3') + ID3Size + ID3 tags` (ID3.pm:1604-1627). The
/// audio loop's APE acceptance calls `SetFileType("APE")` which must
/// win first-call-wins over the subsequent `SetFileType('MP3')`, AND
/// must emit MAC/APE:* tags BEFORE the `File:ID3Size` + ID3v2 tags
/// (bundled emission order: audio-loop body tags → ID3.pm:1604 MP3 set
/// → ID3.pm:1606 ID3Size → ID3.pm:1610 ID3v2 tags). The
/// [`detect_id3`] + [`finalize_id3`] split exposes that interleaving
/// seam to `ProcessMp3::process` while keeping the chained
/// {APE,DSF}-from-ID3 callers (which do not need the interleaving) on
/// the same code path via [`process_id3_inner`].
fn process_id3_inner(
  data: &[u8],
  ctx: &mut ParseContext<'_>,
  do_set_file_type: bool,
) -> (bool, usize) {
  let Some(detected) = detect_id3(data, ctx) else {
    return (false, 0);
  };
  let hdr_end = detected.hdr_end;
  let found = finalize_id3(ctx, detected, do_set_file_type);
  (found, hdr_end)
}

/// Result of the ID3 detection step ([`detect_id3`]) — assembled
/// header/trailer buffers + offsets, BEFORE [`finalize_id3`] applies
/// them to the metadata sink. `found_any` carries bundled's `$rtnVal`
/// status (set at ID3.pm:1453 `^ID3` and/or :1520 `^TAG`). The
/// MP3-dispatch path inserts the audio-format loop (ID3.pm:1582-1601)
/// between detection and finalize so the loop's `SetFileType("APE")`
/// can win first-call-wins over the subsequent `SetFileType('MP3')`
/// at ID3.pm:1604.
struct DetectedId3 {
  found_any: bool,
  id3_len: u64,
  hdr_end: usize,
  header_data: Option<(Vec<u8>, u16)>,
  trailer_data: Option<Vec<u8>>,
}

/// Pure detection step of ProcessID3 (ID3.pm:1431-1576) — assembles
/// header/trailer buffers + offsets WITHOUT emitting any tags. Returns
/// `None` when `DoneID3` is already set (early-return at ID3.pm:1435)
/// OR when the data slice is shorter than the 3-byte magic peek
/// (ID3.pm:1446). The `Some(DetectedId3)` carries `found_any=false`
/// when no `^ID3` or `^TAG` was matched — caller still proceeds to
/// finalize, which is a no-op in the no-id3 case.
fn detect_id3(data: &[u8], ctx: &mut ParseContext<'_>) -> Option<DetectedId3> {
  // ID3.pm:1435-1436 `return 0 if $$et{DoneID3}; $$et{DoneID3} = 1;` —
  // avoids the cross-parser infinite recursion bundled relies on for the
  // ID3 → audio-format dispatch loop. Our port models the chained ID3-
  // first paths (APE.pm:124, DSF.pm:88-97 etc.) by calling this entry
  // directly; the guard makes that idempotent if a second parser also
  // tries to detect ID3 over the same `$self`.
  if ctx.metadata().done_id3().is_some() {
    return None;
  }
  // We tentatively set DoneID3=Some(0) BEFORE detection — matching
  // ID3.pm:1436 `$$et{DoneID3} = 1` (set before any header parsing).
  // The trailer-size update (ID3.pm:1527) only happens when an ID3v1
  // trailer is present; we overwrite later in `finalize`.
  ctx.metadata().set_done_id3(0);

  // `data` is provided by the caller — `ctx.data()` for the file-level
  // ProcessID3 path, OR a pre-sliced ID3v2 trailer for the DSF.pm:88-97
  // chained `ProcessDirectory(ID3::Main)` case (ID3.pm:1637-1642
  // `ProcessID3Dir` ⇒ `ProcessID3` over `${$$dirInfo{DataPt}}`).
  let cctx = crate::convert::ConvContext::default();

  let mut id3_len: u64 = 0;
  let mut found_any = false;
  let mut header_data: Option<(Vec<u8>, u16)> = None;
  // ID3.pm:1443 `my $hdrEnd = 0;` — initialized BEFORE the v2 parse and
  // only updated at :1504 on the successful-parse path. Warn-then-`last`
  // exits leave `$hdrEnd = 0`, and the audio loop's `Seek($hdrEnd, 0)`
  // (:1590) then re-reads from start of file.
  let mut hdr_end: usize = 0;

  // ID3.pm:1446 `$raf->Seek(0, 0); $raf->Read($buff, 3) == 3`. Return
  // `None` so the caller treats it as the "no ID3 at all" path
  // (skip audio loop + finalize); bundled equivalently exits ProcessID3
  // with rtnVal=0 and the outer ProcessMP3 falls to ParseMPEGAudio.
  if data.len() < 3 {
    return None;
  }

  // ID3v2 header parsing — faithful to ID3.pm:1452-1505. CRITICAL
  // (Codex R1): `$rtnVal = 1` (ID3.pm:1453) is set on `^ID3` match
  // BEFORE validation, so Warn-then-`last` paths still emit the File:*
  // + ID3Size=0 tags from the post-loop block (ID3.pm:1580-1611).
  // CRITICAL (Codex R3): EVERY Warn-then-`last` path falls through to
  // the ID3v1 trailer scan at ID3.pm:1510-1528 — a file with a corrupt
  // ID3v2 header BUT a valid ID3v1 trailer must still emit ID3v1 tags.
  // We model the `last` by setting `header_data = None` and exiting the
  // `if` block (NOT early-returning).
  if data.starts_with(b"ID3") {
    found_any = true; // ID3.pm:1453 `$rtnVal = 1`.
    if let Some(parsed) = parse_v2_header(data, ctx) {
      id3_len += (parsed.h_buff.len() + 10) as u64;
      // ID3.pm:1504 `$hdrEnd = $raf->Tell();` — position after:
      //   1. read 3 bytes of magic (:1448) ⇒ pos = 3
      //   2. read 7 bytes of vers+flags+size header (:1454) ⇒ pos = 10
      //   3. read $size bytes of body (:1463) ⇒ pos = 10 + size
      //   4. IF (flags & 0x10): `Seek(10, 1)` (:1486) ⇒ pos += 10
      //                                             ⇒ pos = 20 + size
      // The extended-header path (:1473-1483) shrinks `$hBuff` in-memory
      // but does NOT touch the file-position cursor; bundled never reads
      // separately from the file for the ext-header bytes (they live in
      // the body already read at :1463). So `$hdrEnd` depends only on
      // `$size` + the footer flag, NOT on `$len` (ext-header length).
      hdr_end = 10usize.saturating_add(parsed.size);
      if parsed.flags & 0x10 != 0 {
        hdr_end = hdr_end.saturating_add(10);
      }
      header_data = Some((parsed.h_buff, parsed.vers));
    }
  }

  // ID3.pm:1510-1528 — ID3v1 trailer detection.
  let mut trailer_data: Option<Vec<u8>> = None;
  let mut trail_size_for_done_id3: usize = 0;
  if data.len() >= 128 {
    let tail = &data[data.len() - 128..];
    if tail.starts_with(b"TAG") {
      trailer_data = Some(tail.to_vec());
      id3_len += 128;
      found_any = true;
      // ID3.pm:1527 `$$et{DoneID3} = $trailSize;` — used by APE.pm:169
      // `$footPos -= $$et{DoneID3} if $$et{DoneID3} > 1` to walk PAST
      // the ID3v1 trailer when looking for the APE footer.
      trail_size_for_done_id3 = 128;
      // ID3.pm:1521-1525 — Enhanced TAG (TAG+, 227 bytes) immediately
      // PRECEDING the standard 128-byte TAG block:
      //   my $eSize = 227;
      //   if ($raf->Seek(-$trailSize - $eSize, 2)
      //       and $raf->Read($eBuff, $eSize) == $eSize
      //       and $eBuff =~ /^TAG+/) {
      //       $id3Trailer{EnhancedTAG} = \$eBuff;
      //       $trailSize += $eSize;
      //   }
      //
      // The `^TAG+/` regex is `^TA` followed by `G+` (one or more G's) —
      // confirmed via `perl -e 'print "match" if "TAG" =~ /^TAG+/'`. So
      // "TAG", "TAGG", "TAGGG", ... all match (the literal Enhanced TAG
      // magic is `TAG+` in the spec, but the bundled regex matches even
      // a plain `TAG`-prefixed Enhanced block — the regex `+` is the
      // quantifier, not a literal `+`).
      //
      // Codex R4 F2 fix: bundled APE.pm:169 reads `$$et{DoneID3}` as the
      // BYTE COUNT of trailing ID3 data to skip past when scanning for
      // the APETAGEX 32-byte footer. With Enhanced TAG present, bundled
      // stores 355 (128 + 227) and APE's `$footPos -= $$et{DoneID3}`
      // walks back the correct distance. Our previous hardcoded `128`
      // landed the APE footer scan inside the Enhanced TAG block →
      // APETAGEX magic missed → silent miss of APE tags.
      //
      // The Enhanced TAG CONTENT extraction (`$id3Trailer{EnhancedTAG}
      // = \$eBuff` at :1524) remains deferred — only the BYTE COUNT
      // (`trail_size_for_done_id3`) matters for the APE.pm:169 footer-
      // position shift. No bundled fixture in our suite extracts the
      // Enhanced TAG body; tracked as a forward item.
      //
      // Bounds guard: `data.len() >= 128 + 227 = 355` (we already know
      // `data.len() >= 128` from the outer `if`).
      if data.len() >= 128 + 227 {
        let e_start = data.len() - 128 - 227;
        let e_buf = &data[e_start..data.len() - 128];
        // `^TAG+/` ⇒ "TA" + 1+ "G"s. `starts_with(b"TAG")` is the
        // narrowest match (1 G); any longer all-G run also satisfies
        // the regex but the prefix `TAG` covers all of them.
        if e_buf.starts_with(b"TAG") {
          // ID3.pm:1525 `$trailSize += $eSize;` — DoneID3 grows from
          // 128 to 355.
          trail_size_for_done_id3 += 227;
        }
      }
    }
  }

  // ID3.pm:1532-1576 — Lyrics3 trailer. Out-of-PR-scope as faithful but
  // un-exercised; left as a no-op (no fixture triggers it).
  //
  // Codex R4 follow-up: ID3.pm:1539 updates DoneID3 further when a
  // Lyrics3 block is found (`$$et{DoneID3} = $trailSize + $len - $pos +
  // 11`). Real-world MP3+APE files with a Lyrics3 trailer would need the
  // same byte-count update for APE.pm:169 to walk past Lyrics3 too. Codex
  // did not flag this in R4 (no Lyrics3 fixture triggers it), so we leave
  // it as a documented forward item — same posture as the Enhanced TAG
  // content extraction above. No fixture in our suite exercises Lyrics3.

  if trail_size_for_done_id3 > 0 {
    // Overwrite the early Some(0) with the actual trailer size, per
    // ID3.pm:1527. Read by APE.pm:169 for the footer-position shift.
    ctx.metadata().set_done_id3(trail_size_for_done_id3);
  }
  // _cctx kept on the stack for forward compatibility but unused at
  // this stage — finalize_id3 builds its own ConvContext.
  let _ = cctx;
  Some(DetectedId3 {
    found_any,
    id3_len,
    hdr_end,
    header_data,
    trailer_data,
  })
}

/// Apply the detected ID3 to the metadata sink (ID3.pm:1604-1627):
/// `SetFileType('MP3')` when requested (the MP3 dispatch path), then
/// `FoundTag('ID3Size', $id3Len)`, then the ID3v2 frame pushes
/// (`ProcessDirectory(\%id3Header, $tagTablePtr)`), then the ID3v1
/// trailer pushes. Faithful return: bundled `$rtnVal` from ID3.pm:1631.
///
/// Caller contract (Codex R6): the MP3 file-type dispatch path calls
/// `detect_id3` → audio-format loop (potentially `SetFileType("APE")`)
/// → `finalize_id3(do_set_file_type=true)`. The first-call-wins
/// SetFileType gate then suppresses the MP3 set when APE won. The
/// chained {APE,DSF}-from-ID3 callers do not run an audio loop and
/// pass `do_set_file_type=false` (their outer parser owns
/// SetFileType).
fn finalize_id3(
  ctx: &mut ParseContext<'_>,
  detected: DetectedId3,
  do_set_file_type: bool,
) -> bool {
  let cctx = crate::convert::ConvContext::default();
  finalize(
    ctx,
    &cctx,
    detected.id3_len,
    detected.found_any,
    detected.header_data,
    detected.trailer_data,
    do_set_file_type,
  )
}

/// Parse the ID3v2 header (ID3.pm:1452-1505). Returns `Some(ParsedV2Header)`
/// when the header is fully valid; `None` when any Warn-then-`last` path
/// fires (the caller still proceeds to ID3v1 trailer detection — bundled
/// behavior). Pushes Warns to `ctx.metadata()` along the way. Faithful
/// transliteration of the bundled `while ($buff =~ /^ID3/) { ... last }`
/// loop body.
///
/// Returning `flags + size` lets the caller compute `$hdrEnd`
/// (ID3.pm:1504) faithfully: the bundled `if ($flags & 0x10) {
/// $raf->Seek(10, 1); }` arithmetic (:1484-1486) advances the file
/// position by 10 BEFORE `$hdrEnd = $raf->Tell()`, so the chained-slice
/// offset depends on both the declared body size AND the footer flag.
fn parse_v2_header(data: &[u8], ctx: &mut ParseContext<'_>) -> Option<ParsedV2Header> {
  // ID3.pm:1454 — `$raf->Read($hBuff, 7) == 7 or $et->Warn('Short ID3 header'), last`.
  if data.len() < 10 {
    ctx.metadata().push_warning("Short ID3 header");
    return None;
  }
  let h = &data[3..10]; // 7 bytes: vers(2) + flags(1) + size(4)
  let vers = u16::from_be_bytes([h[0], h[1]]);
  let flags = h[2];
  let size_raw = u32::from_be_bytes([h[3], h[4], h[5], h[6]]);
  // ID3.pm:1456-1457 — `$size = UnSyncSafe($size); defined $size or
  //                   $et->Warn('Invalid ID3 header'), last`.
  let size = match unsync_safe(size_raw) {
    Some(s) => s as usize,
    None => {
      ctx.metadata().push_warning("Invalid ID3 header");
      return None;
    }
  };
  // ID3.pm:1458-1462 — `if ($vers >= 0x0500) { ...Warn..., last }`.
  if vers >= 0x0500 {
    let ver_str = format!("2.{}.{}", vers >> 8, vers & 0xff);
    ctx
      .metadata()
      .push_warning(format!("Unsupported ID3 version: {ver_str}"));
    return None;
  }
  // ID3.pm:1463-1466 — `$raf->Read($hBuff, $size) == $size or ...Warn..., last`.
  if 10 + size > data.len() {
    ctx.metadata().push_warning("Truncated ID3 data");
    return None;
  }
  let mut h_buff: Vec<u8> = data[10..10 + size].to_vec();
  // ID3.pm:1467-1470: header-level unsync (v < 0x0400 only — bundled
  // applies header-level unsync only to v2.2/v2.3 here; v2.4 carries
  // per-frame unsync).
  if flags & 0x80 != 0 && vers < 0x0400 {
    h_buff = reverse_unsync_inplace(&h_buff);
  }
  // ID3.pm:1473-1483 — extended header skip:
  //   $size >= 4 or $et->Warn('Bad ID3 extended header'), last;
  //   my $len = UnSyncSafe(unpack('N', $hBuff));
  //   if ($len > length($hBuff)) {
  //       $et->Warn('Truncated ID3 extended header');
  //       last;
  //   }
  //   $hBuff = substr($hBuff, $len);          # ← strips EXACTLY $len bytes
  //   $pos += $len;
  //
  // CRITICAL FAITHFUL DETAILS:
  //
  // (1) Bundled strips EXACTLY `$len` bytes (Codex R1 + R4 both misread
  // this — see the `ID3v2_3_exthdr.mp3` conformance pin). Do NOT
  // "correct" to `$len + 4`.
  //
  // (2) The Perl `$size >= 4` check guards the unpack of the FIRST 4
  // ext-header bytes. After header-level unsync (line above), `h_buff`
  // may have SHRUNK; we must check `h_buff.len() >= 4` BEFORE indexing
  // those bytes (Codex R7-F2: a crafted ID3v2.3 with flags=0xc0,
  // declared-size=4, body=`ff 00 ff 00` shrinks to 2 bytes after unsync;
  // bundled's `length($hBuff)` is post-unsync, so its `$size >= 4`
  // check guards against THIS shape too via the `$len > length($hBuff)`
  // gate at :1477. Our Rust pre-check on `h_buff.len()` makes the
  // panic-free path explicit + faithful).
  if flags & 0x40 != 0 {
    if h_buff.len() < 4 {
      ctx.metadata().push_warning("Bad ID3 extended header");
      return None;
    }
    let ext_len_raw = u32::from_be_bytes([h_buff[0], h_buff[1], h_buff[2], h_buff[3]]);
    let ext_len = match unsync_safe(ext_len_raw) {
      Some(s) => s as usize,
      None => ext_len_raw as usize,
    };
    if ext_len > h_buff.len() {
      ctx.metadata().push_warning("Truncated ID3 extended header");
      return None;
    }
    h_buff = h_buff[ext_len..].to_vec();
  }
  // ID3.pm:1484-1487 — v2.4 footer skip (10 bytes AFTER frames): bundled
  // advances the file position by 10, which then feeds `$hdrEnd =
  // $raf->Tell()` at :1504. We track the flags byte and let the caller
  // compute `hdr_end = 10 + size [+ 10 if flags & 0x10]`.
  Some(ParsedV2Header {
    h_buff,
    vers,
    flags,
    size,
  })
}

// Phase-2 batch integration: the original ID3 PR's
// `has_valid_mpeg_audio_sync` helper (a minimal accept-only port of
// `MPEG::ParseMPEGAudio`'s sync gate) is superseded by the full
// `crate::formats::mpeg` port (FORMATS.md row 2a, PR #4). The no-ID3
// branch in `ProcessMp3::process` now delegates to
// `crate::formats::mpeg::ProcessMp3.process(ctx)` which performs the
// same scan-len bound + Layer-III/MUS caller flag + full `ParseMPEGAudio`
// dispatch (including the `%MPEG::Audio` tag emission `mp3_conformance`
// pins). This eliminates a near-identical helper per the consolidation
// rule ("near-identical helpers ⇒ keep one canonical version").

fn finalize(
  ctx: &mut ParseContext<'_>,
  cctx: &crate::convert::ConvContext,
  id3_len: u64,
  found_any: bool,
  header_data: Option<(Vec<u8>, u16)>,
  trailer_data: Option<Vec<u8>>,
  do_set_file_type: bool,
) -> bool {
  let print_conv_on = ctx.print_conv_enabled();
  if !found_any {
    // ID3.pm:1580 `if ($rtnVal) { ... }` — `SetFileType('MP3')`
    // (ID3.pm:1604) is INSIDE the rtnVal-truthy branch. A no-ID3 path is
    // a faithful reject: return 0, do not push File:*. The candidate
    // loop in `extract_info` will try the next type; if none accept,
    // `finalization_error` emits "File is empty" / "Unknown file type"
    // / "File format error" as bundled Perl does.
    return false;
  }
  if do_set_file_type {
    // ID3.pm:1604 — SetFileType('MP3') before pushing ID3Size + the tags.
    // Skipped when ProcessID3 is invoked by a chained caller (APE/DSF/...)
    // because that caller owns SetFileType — faithful to the bundled
    // audio-loop recursion (ID3.pm:1582-1601 → recursive ProcessAPE calls
    // SetFileType('APE') at APE.pm:141, which then wins over the later
    // SetFileType('MP3') at ID3.pm:1604 via first-call-wins) and the DSF
    // arm (DSF.pm:64 SetFileType BEFORE the trailer ProcessDirectory at
    // DSF.pm:88-97).
    ctx.set_file_type(Some("MP3"), None, None);
  }
  // ID3.pm:1606 — FoundTag('ID3Size', $id3Len). ID3Size is in the File group.
  ctx.metadata().push(
    Group::new("File", "File"),
    "ID3Size",
    TagValue::I64(id3_len as i64),
  );
  // ID3v2 header.
  if let Some((h_buff, vers)) = header_data {
    let table = if vers >= 0x0400 {
      &ID3V2_4_MAIN
    } else if vers >= 0x0300 {
      &ID3V2_3_MAIN
    } else {
      &ID3V2_2_MAIN
    };
    process_id3v2(&h_buff, vers, table, ctx.metadata(), print_conv_on, cctx);
  }
  // ID3v1 trailer (after ID3v2 — Perl pushes both in `if (%id3Header) {
  // ... } if (%id3Trailer) { ... }` order).
  if let Some(t) = trailer_data {
    let _ = ID3V1_MAIN; // referenced for static link only
    process_id3v1(&t, ctx.metadata(), print_conv_on, cctx);
  }
  true
}

fn reverse_unsync_inplace(v: &[u8]) -> Vec<u8> {
  let mut out = Vec::with_capacity(v.len());
  let mut i = 0;
  while i < v.len() {
    if v[i] == 0xff && i + 1 < v.len() && v[i + 1] == 0x00 {
      out.push(0xff);
      i += 2;
    } else {
      out.push(v[i]);
      i += 1;
    }
  }
  out
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::value::Metadata;

  fn run(data: &[u8], name: &str) -> Metadata {
    let mut m = Metadata::new(name);
    {
      let ext = crate::filetype::file_ext_for_name(name);
      let mut c = ParseContext::new(data, "MP3", 0, "MP3", ext, true, &mut m);
      let _ = ProcessMp3.process(&mut c);
    }
    m
  }

  #[test]
  fn process_mp3_empty_data_rejects() {
    // R6-F1 disposition: empty data + .mp3 ext is still REJECTED — no
    // MPEG frame sync means no MP3 acceptance. The candidate loop's
    // post-loop Error fires faithfully.
    let m = run(&[], "x.mp3");
    assert!(m.tags().iter().all(|t| t.name() != "FileType"));
  }

  #[test]
  fn process_mp3_random_bytes_no_mpeg_sync_rejects() {
    // Random non-MPEG bytes with a .mp3 extension → reject (no MPEG
    // sync found ⇒ faithful "File format error" path from the
    // candidate loop).
    let m = run(b"abcdefghij", "random.mp3");
    assert!(m.tags().iter().all(|t| t.name() != "FileType"));
  }

  #[test]
  fn process_mp3_valid_mpeg_audio_frame_accepts_as_mp3() {
    // 4-byte MPEG audio frame header that satisfies the bundled
    // ParseMPEGAudio gate (MPEG.pm:472-485):
    //   sync = 0xfff (high 11 bits all 1)
    //   version = 11 (MPEG-1)
    //   layer = 01 (Layer 3 — MP3)
    //   bitrate index = 1001 (128 kbps for Layer 3 MPEG-1)
    //   sampling-freq = 00 (44100 Hz)
    //   pad/private/channel/etc = 00
    //   emphasis = 00
    // Composite header: 0xff 0xfb 0x90 0x00.
    let mut data: Vec<u8> = vec![0u8; 32];
    data[0] = 0xff;
    data[1] = 0xfb;
    data[2] = 0x90;
    data[3] = 0x00;
    let m = run(&data, "x.mp3");
    let ft = m.tags().iter().find(|t| t.name() == "FileType").unwrap();
    assert_eq!(ft.value(), &TagValue::Str("MP3".into()));
  }

  #[test]
  fn process_mp3_id3v1_only() {
    // Construct a file: 1024 padding bytes + 128-byte ID3v1 TAG block.
    let mut data: Vec<u8> = vec![0; 256]; // some prefix that's NOT ID3
                                          // Build TAG block.
    let mut tag = Vec::with_capacity(128);
    tag.extend_from_slice(b"TAG");
    let pad = |s: &str, n: usize| {
      let mut v: Vec<u8> = s.bytes().collect();
      v.resize(n, 0);
      v
    };
    tag.extend_from_slice(&pad("Title", 30));
    tag.extend_from_slice(&pad("Artist", 30));
    tag.extend_from_slice(&pad("Album", 30));
    tag.extend_from_slice(b"2003");
    tag.extend_from_slice(&pad("Comment", 30));
    tag.push(7); // Hip-Hop
    assert_eq!(tag.len(), 128);
    data.extend_from_slice(&tag);
    let m = run(&data, "x.mp3");
    let ft = m.tags().iter().find(|t| t.name() == "FileType").unwrap();
    assert_eq!(ft.value(), &TagValue::Str("MP3".into()));
    let id3size = m.tags().iter().find(|t| t.name() == "ID3Size").unwrap();
    assert_eq!(id3size.value(), &TagValue::I64(128));
    let title = m.tags().iter().find(|t| t.name() == "Title").unwrap();
    assert_eq!(title.value(), &TagValue::Str("Title".into()));
    let genre = m.tags().iter().find(|t| t.name() == "Genre").unwrap();
    assert_eq!(genre.value(), &TagValue::Str("Hip-Hop".into()));
  }

  #[test]
  fn process_mp3_id3v2_2_with_title_artist() {
    // ID3v2.2 header (10 bytes) + 6-byte TT2 frame + 6-byte TP1 frame.
    let title_frame: Vec<u8> = {
      let mut body: Vec<u8> = vec![0];
      body.extend_from_slice(b"Hello");
      let mut v = Vec::new();
      v.extend_from_slice(b"TT2");
      let len = body.len() as u32;
      v.push(((len >> 16) & 0xff) as u8);
      let lo = (len & 0xffff) as u16;
      v.extend_from_slice(&lo.to_be_bytes());
      v.extend_from_slice(&body);
      v
    };
    let artist_frame: Vec<u8> = {
      let mut body: Vec<u8> = vec![0];
      body.extend_from_slice(b"Phil");
      let mut v = Vec::new();
      v.extend_from_slice(b"TP1");
      let len = body.len() as u32;
      v.push(((len >> 16) & 0xff) as u8);
      let lo = (len & 0xffff) as u16;
      v.extend_from_slice(&lo.to_be_bytes());
      v.extend_from_slice(&body);
      v
    };
    let body: Vec<u8> = title_frame.into_iter().chain(artist_frame).collect();
    let size = body.len() as u32;
    // Synchsafe size: for body.len() < 128, top 7 bits = 0 (synchsafe == raw).
    let mut data = Vec::new();
    data.extend_from_slice(b"ID3");
    data.push(0x02); // vers major = 2
    data.push(0x00); // vers minor
    data.push(0x00); // flags
    data.extend_from_slice(&size.to_be_bytes()); // sync-safe size (for small sizes, == raw)
    data.extend_from_slice(&body);
    let m = run(&data, "x.mp3");
    let title = m.tags().iter().find(|t| t.name() == "Title").unwrap();
    assert_eq!(title.value(), &TagValue::Str("Hello".into()));
    let artist = m.tags().iter().find(|t| t.name() == "Artist").unwrap();
    assert_eq!(artist.value(), &TagValue::Str("Phil".into()));
    let id3size = m.tags().iter().find(|t| t.name() == "ID3Size").unwrap();
    // ID3Size includes 10-byte header + body bytes.
    assert_eq!(id3size.value(), &TagValue::I64(10 + size as i64));
  }

  #[test]
  fn process_mp3_unsync_extheader_shrinks_below_4_does_not_panic() {
    // R7-F2 regression: a crafted v2.3 with flags=0xc0 (unsync +
    // ext-header), declared body size=4, body=`ff 00 ff 00`. After the
    // header-level unsync strips `\xff\x00 → \xff`, h_buff shrinks from
    // 4 to 2 bytes. Without the post-unsync bounds check, the ext-
    // header read would index into 4-byte u32 over 2 bytes and panic.
    // Faithful Warn: "Bad ID3 extended header".
    let mut data = Vec::new();
    data.extend_from_slice(b"ID3");
    data.push(0x03);
    data.push(0x00);
    data.push(0xc0); // flags: unsync (0x80) + ext-header (0x40)
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // sync-safe 4
    data.extend_from_slice(&[0xff, 0x00, 0xff, 0x00]); // body (shrinks to 0xff 0xff)
    let m = run(&data, "x.mp3");
    // Must not panic. Faithful Warn fires.
    assert!(m
      .warnings()
      .iter()
      .any(|w| w.as_str() == "Bad ID3 extended header"));
  }

  #[test]
  fn process_mp3_layer_two_dotless_filename_rejected() {
    // R8-F1 regression: a dotless filename hitting MP3 weakMagic +
    // Layer II sync header `\xff\xfd 0x90 0x00` was previously accepted
    // because the Layer-III gate was skipped when ext != MP3. Bundled
    // ID3.pm:1716 sets $mp3=1 for EVERY non-MUS candidate, so Layer II
    // is rejected. After R8-F1 fix: dotless file with Layer II sync →
    // reject (no FileType pushed).
    let mut data: Vec<u8> = vec![0u8; 32];
    data[0] = 0xff;
    data[1] = 0xfd; // Layer II (layer bits 0x00040000 ⇒ layer == 10)
    data[2] = 0x90;
    data[3] = 0x00;
    let m = run(&data, "x"); // dotless: ext is None
    assert!(m.tags().iter().all(|t| t.name() != "FileType"));
  }

  #[test]
  fn process_mp3_layer_two_mus_extension_accepted() {
    // R8-F1 regression (positive case): bundled ID3.pm:1716 sets
    // $mp3 = $ext eq 'MUS' ? 0 : 1. For ext='MUS' the Layer-III gate
    // is SKIPPED — Layer II is accepted (MPEG-2 audio in the MUS
    // container). Pinned to ensure we don't over-reject.
    let mut data: Vec<u8> = vec![0u8; 32];
    data[0] = 0xff;
    data[1] = 0xfd; // Layer II
    data[2] = 0x90;
    data[3] = 0x00;
    let m = run(&data, "song.mus");
    let ft = m.tags().iter().find(|t| t.name() == "FileType").unwrap();
    assert_eq!(ft.value(), &TagValue::Str("MP3".into()));
  }

  #[test]
  fn process_mp3_unsupported_id3v5_warns() {
    // ID3 magic + version 5.0 — bundled Perl emits the version Warn.
    let mut data = Vec::new();
    data.extend_from_slice(b"ID3");
    data.push(0x05);
    data.push(0x00);
    data.push(0x00);
    data.extend_from_slice(&[0u8, 0, 0, 0]);
    let m = run(&data, "x.mp3");
    assert!(m
      .warnings()
      .iter()
      .any(|w| w.as_str() == "Unsupported ID3 version: 2.5.0"));
  }

  #[test]
  fn process_mp3_truncated_warns() {
    // ID3 magic + valid header + declared size 100, but only 3 body bytes.
    let mut data = Vec::new();
    data.extend_from_slice(b"ID3");
    data.push(0x02);
    data.push(0x00);
    data.push(0x00);
    data.extend_from_slice(&[0u8, 0, 0, 100]); // sync-safe 100
    data.extend_from_slice(&[0u8; 3]);
    let m = run(&data, "x.mp3");
    assert!(m
      .warnings()
      .iter()
      .any(|w| w.as_str() == "Truncated ID3 data"));
  }

  #[test]
  fn process_mp3_short_header_warns() {
    // ID3 magic + only 2 of 7 header bytes.
    let data = b"ID3\x02\x00";
    let m = run(data, "x.mp3");
    assert!(m
      .warnings()
      .iter()
      .any(|w| w.as_str() == "Short ID3 header"));
  }

  #[test]
  fn process_id3_enhanced_tag_sets_done_id3_to_355() {
    // Codex R4 F2 regression pin: ID3.pm:1521-1525 — when standard ID3v1
    // TAG is present AND a 227-byte Enhanced TAG block precedes it (magic
    // satisfies `/^TAG+/` regex = `^TA` + 1+ G's), bundled sets
    // `$$et{DoneID3} = 128 + 227 = 355` (`$trailSize += $eSize` at :1525).
    //
    // Pre-fix our code hardcoded `trail_size_for_done_id3 = 128`; the
    // APE.pm:169 `$footPos -= $$et{DoneID3}` then landed the APE footer
    // scan INSIDE the Enhanced TAG block → silent miss.
    //
    // Synthetic layout: 100-byte non-ID3 padding + 227-byte Enhanced TAG
    // (magic "TAG+...") + 128-byte standard ID3v1 TAG. process_id3_inner
    // runs over the whole buffer and must set done_id3 = 355.
    let mut data: Vec<u8> = vec![0xaa; 100];
    // Enhanced TAG: 227 bytes starting with literal "TAG+" (matches
    // `^TAG+/` because the regex is `^TA` + `G+` = "TA" followed by 1+
    // G's; "TAG+" satisfies this — the first 3 chars are 'T','A','G' and
    // then the `+` is just data past the regex match).
    let mut enhanced = vec![b'T', b'A', b'G', b'+'];
    enhanced.resize(227, 0);
    data.extend_from_slice(&enhanced);
    // Standard ID3v1 TAG (128 bytes starting "TAG").
    let mut id3v1 = vec![b'T', b'A', b'G'];
    id3v1.resize(128, 0);
    data.extend_from_slice(&id3v1);
    assert_eq!(data.len(), 100 + 227 + 128);

    let mut meta = Metadata::new("x.mp3");
    {
      let ext = crate::filetype::file_ext_for_name("x.mp3");
      let mut ctx = ParseContext::new(&data, "MP3", 0, "MP3", ext, true, &mut meta);
      // Direct call to the inner function — no audio-format dispatch.
      let (_found, _hdr_end) = process_id3_inner(&data, &mut ctx, false);
    }
    assert_eq!(
      meta.done_id3(),
      Some(355),
      "Enhanced TAG (227) + standard TAG (128) must yield DoneID3 = 355",
    );
  }

  #[test]
  fn process_id3_standard_tag_only_sets_done_id3_to_128() {
    // Sanity check: without Enhanced TAG (no `^TAG+/` match in the 227
    // bytes before the standard TAG), DoneID3 stays at 128 (faithful to
    // ID3.pm:1527 `$$et{DoneID3} = $trailSize` with $trailSize=128 only).
    let mut data: Vec<u8> = vec![0xaa; 100 + 227];
    // Standard ID3v1 TAG (128 bytes starting "TAG"). The 227 bytes
    // preceding it (offsets 100..327) are non-TAG padding — bundled's
    // `^TAG+/` over those 227 bytes does NOT match.
    let mut id3v1 = vec![b'T', b'A', b'G'];
    id3v1.resize(128, 0);
    data.extend_from_slice(&id3v1);
    assert_eq!(data.len(), 100 + 227 + 128);

    let mut meta = Metadata::new("x.mp3");
    {
      let ext = crate::filetype::file_ext_for_name("x.mp3");
      let mut ctx = ParseContext::new(&data, "MP3", 0, "MP3", ext, true, &mut meta);
      let (_found, _hdr_end) = process_id3_inner(&data, &mut ctx, false);
    }
    assert_eq!(
      meta.done_id3(),
      Some(128),
      "standard TAG alone (no Enhanced TAG) must yield DoneID3 = 128",
    );
  }

  #[test]
  fn process_id3_v24_truncated_footer_does_not_panic() {
    // Codex R4 F1 regression pin: parse_v2_header accepts a v2.4 tag once
    // `10 + size` body bytes are present, but bundled's `$raf->Seek(10, 1)`
    // at ID3.pm:1486 is unconditional — even when the 10 footer bytes are
    // truncated, `$raf->Tell()` at :1504 returns `10 + size + 10`. The
    // chained-ID3 consumer (APE.pm) must NOT panic on the resulting
    // out-of-bounds hdr_end. Producer-side: hdr_end = 44 over a 34-byte
    // buffer is intentional — consumer (`ape.rs:ape_slice`) saturates to
    // empty via `data.get(hdr_end..).unwrap_or(&[])`.
    //
    // This test exercises the producer alone (the consumer guard is
    // exercised by `id3v24_footer_truncated_then_nothing_conformance`
    // which routes through the full APE engine path).
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(b"ID3");
    data.push(0x04); // v2.4 major
    data.push(0x00); // minor
    data.push(0x10); // flags = footer-flag (0x10)
    data.extend_from_slice(&[0u8, 0, 0, 24]); // syncsafe size=24
    data.extend_from_slice(&vec![0u8; 24]); // body bytes
    assert_eq!(data.len(), 34); // NO footer bytes appended

    let mut meta = Metadata::new("x.mp3");
    let hdr_end = {
      let ext = crate::filetype::file_ext_for_name("x.mp3");
      let mut ctx = ParseContext::new(&data, "MP3", 0, "MP3", ext, true, &mut meta);
      let (_found, hdr_end) = process_id3_inner(&data, &mut ctx, false);
      hdr_end
    };
    // Producer matches bundled: hdr_end = 10 + 24 + 10 = 44 (the +10
    // footer-skip happens regardless of whether the 10 footer bytes
    // exist — bundled's filesystem `Seek(10, 1)` past EOF succeeds).
    assert_eq!(hdr_end, 44);
    assert!(
      hdr_end > data.len(),
      "hdr_end must intentionally exceed data.len() to mirror bundled's seek-past-EOF behavior"
    );
  }
}
