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

/// The MP3 file-type parser. Faithful to bundled Perl's `Image::ExifTool::
/// ID3::ProcessMP3` (ID3.pm:1684-1728); the chain to MPEG / APE for the
/// audio-frame / APE-trailer tags is documented forward items (rows 17 / 5).
pub struct ProcessMp3;

impl FormatParser for ProcessMp3 {
  fn process(&self, ctx: &mut ParseContext<'_>) -> bool {
    // ID3.pm:1684-1728. `ProcessMP3` is the MP3 PROCESS_PROC; it always
    // first calls `ProcessID3` (under `unless ($$et{DoneID3})`).
    let id3_found = process_id3_inner(ctx);

    // ID3.pm:1696-1719: when ProcessID3 didn't accept (no ID3), the
    // bundled parser tries the MPEG audio/video frame parser. **OUT OF
    // PR SCOPE** — MPEG.pm is row 17. For an MP3 candidate without ID3,
    // bundled returns 1 once ParseMPEGAudio accepts.
    //
    // Codex R5-F1 disposition: a `.mp3`-extension file with no ID3 +
    // MPEG audio frames would otherwise fall through to the candidate
    // loop's `File format error` post-loop. We ACCEPT the candidacy
    // ONLY when the file extension is `MP3` (the strong "user said this
    // is an MP3" signal); without the extension hint, the candidate
    // loop's weakMagic-MP3 try is left to fail so subsequent candidates
    // (or the post-loop Error) handle the file. This preserves bundled-
    // matching behavior for non-MP3 candidates that happened to land on
    // the MP3 try, while keeping the value-add for real MP3 files.
    //
    // When MPEG.pm lands (row 17), this branch becomes:
    //   if !id3_found {
    //       return process_mpeg(ctx) || process_ape(ctx);
    //   }
    if !id3_found {
      // R6-F1 + R7-F1 + R8-F1: accept ONLY when the data contains a
      // valid MPEG audio frame sync. Three INDEPENDENT flags:
      //
      //   - `scan_window_is_long`: 8192 vs 256 bytes — ID3.pm:1704
      //     `$scanLen = $$et{FILE_EXT} eq 'MP3' ? 8192 : 256`.
      //   - `require_layer_3`: MPEG.pm:485 + ID3.pm:1716 — bundled sets
      //     `$mp3 = $ext eq 'MUS' ? 0 : 1`, so Layer III is required
      //     for EVERY non-MUS candidate, NOT just `.mp3`.
      //   - `retry_on_bad_frame`: MPEG.pm:487-488 — only the literal
      //     `.mp3` extension retries past a fake sync; other dispatch
      //     paths bail immediately (`return 0 unless $ext eq 'MP3'`).
      //
      // R8-F1 caught my prior conflation (`ext_is_mp3` used for both
      // flags): a dotless filename hitting MP3 weakMagic + a Layer II
      // sync header (`\xff\xfd ...`) would have been accepted because
      // the Layer-III gate was skipped. The faithful gate requires
      // Layer III everywhere except MUS.
      let ext_upper = ctx.ext().map(|e| e.to_ascii_uppercase());
      let ext_is_mp3 = ext_upper.as_deref() == Some("MP3");
      let scan_window_is_long = ext_is_mp3;
      let require_layer_3 = ext_upper.as_deref() != Some("MUS");
      let retry_on_bad_frame = ext_is_mp3;
      if has_valid_mpeg_audio_sync(
        ctx.data(),
        scan_window_is_long,
        require_layer_3,
        retry_on_bad_frame,
      ) {
        ctx.set_file_type(Some("MP3"), None, None);
        return true;
      }
      // No ID3, no MPEG frame sync → faithful reject (candidate loop
      // continues; post-loop emits the appropriate Error).
      return false;
    }

    // ID3.pm:1722-1727: if rtnVal truthy, try APE trailer. **OUT OF PR
    // SCOPE**: APE.pm (row 5) is its own port.

    true
  }
}

fn process_id3_inner(ctx: &mut ParseContext<'_>) -> bool {
  // `ctx.data()` returns `&'a [u8]` (lifetime tied to the context, not to
  // `&self`), so the borrow co-exists with the `&mut ctx`-taking metadata
  // calls inside `parse_v2_header`. Avoids the O(n) `data.to_vec()` clone
  // that was previously needed to free the borrow — Copilot review nit on
  // process.rs:111.
  let data: &[u8] = ctx.data();
  let cctx = crate::convert::ConvContext::default();

  let mut id3_len: u64 = 0;
  let mut found_any = false;
  let mut header_data: Option<(Vec<u8>, u16)> = None;

  // ID3.pm:1446 `$raf->Seek(0, 0); $raf->Read($buff, 3) == 3`.
  if data.len() < 3 {
    return false;
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
    header_data = parse_v2_header(data, ctx);
    if let Some((h_buff, _vers)) = header_data.as_ref() {
      id3_len += (h_buff.len() + 10) as u64;
    }
  }

  // ID3.pm:1510-1528 — ID3v1 trailer detection.
  let mut trailer_data: Option<Vec<u8>> = None;
  if data.len() >= 128 {
    let tail = &data[data.len() - 128..];
    if tail.starts_with(b"TAG") {
      trailer_data = Some(tail.to_vec());
      id3_len += 128;
      found_any = true;
    }
  }
  // Enhanced TAG block (227 bytes BEFORE the standard TAG): ID3.pm:
  // 1521-1525. Faithfully present but presently unexercised — no
  // bundled fixture triggers it; documented forward item.

  // ID3.pm:1532-1576 — Lyrics3 trailer. Out-of-PR-scope as faithful but
  // un-exercised; left as a no-op (no fixture triggers it).

  finalize(ctx, &cctx, id3_len, found_any, header_data, trailer_data)
}

/// Parse the ID3v2 header (ID3.pm:1452-1505). Returns `Some((h_buff, vers))`
/// when the header is fully valid; `None` when any Warn-then-`last` path
/// fires (the caller still proceeds to ID3v1 trailer detection — bundled
/// behavior). Pushes Warns to `ctx.metadata()` along the way. Faithful
/// transliteration of the bundled `while ($buff =~ /^ID3/) { ... last }`
/// loop body.
fn parse_v2_header(data: &[u8], ctx: &mut ParseContext<'_>) -> Option<(Vec<u8>, u16)> {
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
  // ID3.pm:1484-1487 — v2.4 footer skip (10 bytes AFTER frames); not
  // modeled here (we work over a byte slice, not a RAF position).
  Some((h_buff, vers))
}

/// Faithful MINIMAL port of `Image::ExifTool::MPEG::ParseMPEGAudio`
/// (MPEG.pm:464-494) — its accept gate ONLY. Three independent inputs:
///
/// - **`scan_window_is_long`** (ID3.pm:1704): `$scanLen = $$et{
///   FILE_EXT} eq 'MP3' ? 8192 : 256`. Bundled `ProcessMP3` reads
///   only this many bytes for the initial scan; out-of-window syncs
///   are NOT considered.
/// - **`require_layer_3`** (MPEG.pm:485 + ID3.pm:1716): bundled sets
///   `$mp3 = $ext eq 'MUS' ? 0 : 1`, so Layer III is required for
///   EVERY non-MUS candidate. R8-F1 corrected my prior conflation of
///   this gate with the .mp3-ext path.
/// - **`retry_on_bad_frame`** (MPEG.pm:487-488): when a candidate sync
///   fails the validation gate, bundled does
///   `return 0 unless $ext eq 'MP3'` — i.e. only the literal `.mp3`
///   extension retries past a fake sync; other dispatch paths bail
///   immediately. Faithful: callers pass `ext_is_mp3` here.
///
/// Checks:
/// 1. Frame sync `\xff.{3}` with high 11 bits all 1 (MPEG.pm:474).
/// 2. Reserved bits: versionID != 01, layer != 00, bitrate-index !=
///    {0000, 1111}, sampling-freq != 11, emphasis != 10 (MPEG.pm:
///    479-485).
/// 3. When `require_layer_3`: layer bits MUST be `0x020000`. Layer
///    I/II syncs are rejected.
///
/// Returns true iff a valid MPEG audio frame sync is found within
/// the scan window.
fn has_valid_mpeg_audio_sync(
  data: &[u8],
  scan_window_is_long: bool,
  require_layer_3: bool,
  retry_on_bad_frame: bool,
) -> bool {
  let scan_len = if scan_window_is_long { 8192 } else { 256 };
  let scan_end = scan_len.min(data.len());
  let mut i = 0;
  while i + 4 <= scan_end {
    if data[i] != 0xff {
      i += 1;
      continue;
    }
    let word = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
    // MPEG.pm:474-477 — high 11 bits all 1; otherwise rewind 2 bytes
    // (`pos -= 2`) to find next sync. Not a "bad frame", so always retry.
    if word & 0xffe0_0000 != 0xffe0_0000 {
      i += 1;
      continue;
    }
    let bad_version = word & 0x0018_0000 == 0x0008_0000;
    let bad_layer = word & 0x0006_0000 == 0x0000_0000;
    let bad_bitrate = word & 0x0000_f000 == 0x0000_0000 || word & 0x0000_f000 == 0x0000_f000;
    let bad_freq = word & 0x0000_0c00 == 0x0000_0c00;
    let bad_emphasis = word & 0x0000_0003 == 0x0000_0002;
    let bad_for_mp3 = require_layer_3 && (word & 0x0006_0000) != 0x0002_0000;
    if bad_version || bad_layer || bad_bitrate || bad_freq || bad_emphasis || bad_for_mp3 {
      // MPEG.pm:487-490 — `return 0 unless $ext eq 'MP3'; pos -= 1`.
      // Faithful: only the `.mp3`-ext path retries past a fake sync.
      if !retry_on_bad_frame {
        return false;
      }
      i += 1;
      continue;
    }
    return true;
  }
  false
}

fn finalize(
  ctx: &mut ParseContext<'_>,
  cctx: &crate::convert::ConvContext,
  id3_len: u64,
  found_any: bool,
  header_data: Option<(Vec<u8>, u16)>,
  trailer_data: Option<Vec<u8>>,
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
  // ID3.pm:1604 — SetFileType('MP3') before pushing ID3Size + the tags.
  ctx.set_file_type(Some("MP3"), None, None);
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
}
