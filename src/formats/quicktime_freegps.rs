// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "quicktime")]
//! Faithful port of `Image::ExifTool::QuickTime::ProcessFreeGPS` and the
//! brute-force `ScanMediaData` scanner (`lib/Image/ExifTool/QuickTimeStream.pl`)
//! — **QuickTime Sub-Port 3.5: the freeGPS scan + self-contained
//! camera-specific decoders**.
//!
//! ## What freeGPS does
//!
//! Many dashcams / action-cams write per-frame GPS / accelerometer data into
//! `free` / `skip` / padding atoms (and sometimes into `mdat` itself) using a
//! "freeGPS " magic prefix. ExifTool's [`ScanMediaData`](https://exiftool.org)
//! brute-force-scans the media data for the magic (and for GoPro `GP\x06\0\0`
//! records), then dispatches each block to [`ProcessFreeGPS`] — a 850-line
//! function (QuickTimeStream.pl:1637-2484) that fingerprints the block by
//! byte-pattern and dispatches to 20+ camera-specific decoders.
//!
//! ## Faithful port scope
//!
//! This sub-port implements the SELF-CONTAINED variants — every GPSType that
//! decodes inside QuickTimeStream.pl without re-dispatching into a separate
//! ExifTool module. The variants are listed below with their fingerprint and
//! source-line cite:
//!
//! | GPSType | Camera / format                        | Lines       | Status   |
//! |---------|----------------------------------------|-------------|----------|
//! | 1       | Azdome GS63H / EEEkit (XOR 0xAA ASCII) | 1652-1715   | Ported   |
//! | 2       | Nextbase 512GW NMEA                    | 1717-1750   | Ported   |
//! | 3       | ViofoA119v3 (Kenwood/Novatek-like)     | 1752-1804   | Ported   |
//! | 4       | E-ACE B44 (Lucky-encrypted lat/lon)    | 1806-1841   | Partial  |
//! | 5       | LigoGPS                                | 1843-1904   | DEFERRED |
//! | 6       | Akaso dashcam                          | 1906-1938   | Ported   |
//! | 7       | "4W\`b]S<" cipher → \$GPRMC text       | 1940-1959   | Ported   |
//! | 8       | Akaso V1 / Redtiger F7N (encrypted)    | 1961-1996   | Ported   |
//! | 9       | EACHPAI                                | 1998-2019   | DEFERRED |
//! | 10      | Vantrue S1 (horsontech)                | 2021-2045   | Ported   |
//! | 11      | ATC GPS (52-byte encrypted records)    | 2047-2157   | Ported   |
//! | 12      | Type 2 80-byte (double lat/lon)        | 2159-2188   | Ported   |
//! | 13      | INNOVV MP4                             | 2190-2214   | Ported   |
//! | 14      | XBHT motorcycle dashcam Model XB702    | 2216-2238   | Ported   |
//! | 15      | Vantrue N4                             | 2240-2263   | Ported   |
//! | 16      | IQS Novatek variant                    | 2298-2309   | Ported   |
//! | 17      | Viofo A119S (Novatek/Kenwood binary)   | 2265-2352   | Ported   |
//! | 17b     | Rexing V1-4k scaled lat/lon            | 2323-2327   | Ported   |
//! | 17c     | Transcend Drive Body Camera 70         | 2328-2338   | Ported   |
//! | 18      | XGODY 12" 4K (ASCII)                   | 2354-2384   | Ported   |
//! | 19      | 70mai A810                             | 2386-2401   | Ported   |
//! | 20      | Nextbase 512G (32-byte BE records)     | 2403-2451   | Ported   |
//!
//! ## Deferred — vendor-module dispatches
//!
//! These freeGPS-or-scan paths re-dispatch into SEPARATE ExifTool modules; this
//! sub-port stops at the freeGPS-side DETECTION + dispatch arm and leaves the
//! vendor parse as a `// DEFERRED` stub:
//!
//!  - **GoPro GPMF** (`Image::ExifTool::GoPro::ProcessGP6`,
//!    QuickTimeStream.pl:3717-3748) — `GP\x06\0\0` records found by the
//!    brute-force scanner.
//!  - **LigoGPS** (`Image::ExifTool::LigoGPS::ProcessLigoGPS`,
//!    QuickTimeStream.pl:1887) — Type 5 fingerprint.
//!  - **Sony rtmd**, **Canon CTMD**, full Android **camm**, Parrot **mett** —
//!    `ProcessSamples`-side timed-metadata dispatches that re-dispatch into
//!    `Image::ExifTool::Sony`, `…::Canon`, `…::QuickTime::camm*`,
//!    `…::Parrot::mett`. The freeGPS path itself never decodes these — but
//!    the brute-force scanner WOULD encounter them when scanning `mdat`. We
//!    detect their magic and leave the vendor decode as a stub.
//!  - **EACHPAI** (GPSType 9) — bundled ExifTool emits
//!    `Can't yet decrypt EACHPAI timed GPS` and stops; faithful (the
//!    encryption isn't published).
//!
//! ## Type-17b — Rexing V1-4k (now ported, was a cross-module dependency)
//!
//! The Type-17b lat/lon scaling (QuickTimeStream.pl:2323-2327) applies ONLY
//! when `$$et{KodakVersion} eq '3.01.054'`. That global is set EXCLUSIVELY by
//! the `'ver '` tag inside the top-level `frea` atom of Kodak PixPro SP360 /
//! Rexing MP4 videos (`Image::ExifTool::Kodak::frea`, Kodak.pm:2987 `RawConv =>
//! '$$self{KodakVersion} = $val'`; dispatched from `%QuickTime::Main` `frea`,
//! QuickTime.pm:610-613). The port now decodes that `frea` atom in the
//! QuickTime atom walker ([`crate::formats::quicktime`]) — the `frea` atom is
//! parsed in the FIRST top-level pass, BEFORE the `mdat` freeGPS scan, so
//! `KodakVersion` is populated when Type-17 decodes — and threads the decoded
//! `KodakVersion` into [`process_free_gps`] (and the `moov`-level `gps ` box
//! path). A file WITHOUT the Kodak `ver ` tag carries `kodak_version == None`
//! and falls through to the default Type-17 branch, unchanged.
//!
//! Each variant cites QuickTimeStream.pl line numbers at the top of its
//! decoder function. All record offsets/byte layouts are taken verbatim from
//! the Perl source.
//!
//! ## GPS priority chain
//!
//! The samples ProcessFreeGPS appends — including every variant decoded
//! here (Kingslim / Rove / FMAS / Wolfbox) — feed [`QuickTimeStreamMeta`]
//! (the same `Vec<GpsSample>` the bounded SP3 decoders fill). That meta
//! is the **LOWEST tier** of the cross-port GPS priority chain —
//! consulted only when no higher-tier source (GoPro → CAMM → Sony rtmd →
//! Insta360 → Parrot) decoded a coordinate pair. The brute-force scan
//! is intentionally a fallback; it lights up dashcam-only files that
//! have no first-party timed-metadata track.

#![deny(clippy::indexing_slicing)]

extern crate alloc;
use alloc::{
  string::{String, ToString},
  vec::Vec,
};

use smol_str::SmolStr;

use crate::{
  formats::{
    gopro,
    quicktime_stream::{convert_lat_lon, join3, synth_gps_date_time},
  },
  metadata::{GoProMeta, GpsSample, QuickTimeStreamMeta, TextExtras},
};

// ── conversion factors (QuickTimeStream.pl:73-75) ──────────────────────────

/// `$knotsToKph = 1.852` (QuickTimeStream.pl:73).
const KNOTS_TO_KPH: f64 = 1.852;
/// `$mpsToKph = 3.6` (QuickTimeStream.pl:74).
const MPS_TO_KPH: f64 = 3.6;
/// `$mphToKph = 1.60934` (QuickTimeStream.pl:75).
const MPH_TO_KPH: f64 = 1.60934;

/// `$gpsBlockSize = 0x8000` (QuickTimeStream.pl:70) — the brute-force scanner
/// reads media data in 32-KiB chunks.
const GPS_BLOCK_SIZE: usize = 0x8000;

/// `@dateMax = ( 24, 59, 59, 2200, 12, 31 )` (QuickTimeStream.pl:67).
const DATE_MAX: [u32; 6] = [24, 59, 59, 2200, 12, 31];

// ── little-endian readers (most freeGPS records are LE, ExifTool sets
//    SetByteOrder('II') at the top of ProcessFreeGPS, QuickTimeStream.pl:1649)

fn le_u16(b: &[u8], off: usize) -> Option<u16> {
  Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

fn le_u32(b: &[u8], off: usize) -> Option<u32> {
  Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

fn le_i32(b: &[u8], off: usize) -> Option<i32> {
  le_u32(b, off).map(|v| v as i32)
}

fn le_u64(b: &[u8], off: usize) -> Option<u64> {
  Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

fn le_i64(b: &[u8], off: usize) -> Option<i64> {
  le_u64(b, off).map(|v| v as i64)
}

fn le_f32(b: &[u8], off: usize) -> Option<f64> {
  let arr: [u8; 4] = b.get(off..off + 4)?.try_into().ok()?;
  Some(f64::from(f32::from_le_bytes(arr)))
}

fn le_f64(b: &[u8], off: usize) -> Option<f64> {
  Some(f64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

// ── big-endian readers (a couple of variants override the byte order;
//    most prominent is GPSType 20 / Nextbase 512G) ──────────────────────────

fn be_u16(b: &[u8], off: usize) -> Option<u16> {
  Some(u16::from_be_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

fn be_u32(b: &[u8], off: usize) -> Option<u32> {
  Some(u32::from_be_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

// ===========================================================================
// ScanMediaData (QuickTimeStream.pl:3679-3789) — the brute-force scan
// ===========================================================================

/// `ScanMediaData` (QuickTimeStream.pl:3679-3789): brute-force-scan a slice
/// of media data (`mdat`) for `freeGPS `-magic blocks (and GoPro `GP\x06\0\0`
/// records). For each `freeGPS ` block found, dispatch into [`process_free_gps`].
///
/// `data` is the WHOLE file slice and `mdat_offset..mdat_end` the absolute
/// byte range of the `mdat` payload (ExifTool reads media data through `$raf`
/// at `$$et{MediaDataOffset}` for `$$et{MediaDataSize}` bytes,
/// QuickTimeStream.pl:3688/3697).
///
/// ExifTool's `$found` flag short-circuits the scan after the first 20 MB if
/// nothing was located (QuickTimeStream.pl:3714); the port mirrors that.
///
/// `create_date_raw` is the movie `mvhd` CreateDate (raw 1904-epoch seconds)
/// for `GPSDateTime` synthesis (`SetGPSDateTime`).
///
/// `already_found_embedded` mirrors ExifTool's `$$et{FoundEmbedded}` short-
/// circuit (QuickTimeStream.pl:3689): if the timed-metadata path already
/// produced GPS samples, skip the brute-force scan entirely.
///
/// **SP4** — `ligogps_out` is the LigoGPS accumulator threaded into
/// [`process_free_gps`]: a `freeGPS ` block carrying a GPSType-5
/// (`LIGOGPSINFO\0`) fingerprint is dispatched into
/// [`crate::formats::ligogps::process_ligogps_with_scale`]
/// (QuickTimeStream.pl:1843-1888). Most files leave it empty.
#[allow(clippy::too_many_arguments)]
pub fn scan_media_data(
  data: &[u8],
  mdat_offset: u64,
  mdat_size: u64,
  create_date_raw: Option<u64>,
  kodak_version: Option<&str>,
  already_found_embedded: bool,
  out: &mut QuickTimeStreamMeta,
  gopro_out: &mut GoProMeta,
  mut ligogps_out: Option<&mut crate::metadata::LigoGpsMeta>,
) {
  // QuickTimeStream.pl:3689 `return if $$et{FoundEmbedded} or not $dataPos`.
  if already_found_embedded || mdat_offset == 0 {
    return;
  }
  let start = mdat_offset.min(data.len() as u64) as usize;
  // ExifTool scans through `$raf` from `$$et{MediaDataOffset}` for an
  // initially `$$et{MediaDataSize}`-byte window (QuickTimeStream.pl:3688/3697).
  // The port holds the WHOLE file, so the scan base is `data[start..]` (the
  // file tail from the mdat payload) and the window is a MUTABLE `limit` over
  // that base. `limit` starts at `mdat_size` (the declared payload) and, on
  // the FIRST-EVER find that is a GoPro GP6 record, EXPANDS to the end of the
  // file (QuickTimeStream.pl:3732-3736 `unless ($found) { Seek(0,2) and
  // $dataLen = Tell - MediaDataOffset }`) because later GP6 records may live in
  // a trailer AFTER the declared `mdat`. The expansion is GUARDED by `unless
  // ($found)`: the freeGPS path sets `$found = 1` (no expansion), and a GP6
  // sets `$found = 2`, so a GP6 that follows ANY earlier find (freeGPS or GP6)
  // does NOT expand — only a first-ever GP6 grows the window.
  let Some(tail) = data.get(start..) else {
    return;
  };
  let mut limit = (mdat_size.min(tail.len() as u64)) as usize;
  if limit == 0 {
    return;
  }

  // QuickTimeStream.pl:2050 `$$et{FreeGPS2}` — the cross-block ATC ring-buffer
  // state (`Then` + `RecentRecPos`) persists for the whole scan, exactly as
  // ExifTool keeps it on `$$et` across every `ProcessFreeGPS` call.
  let mut state = FreeGpsState::new();
  let mut pos = 0usize;
  let mut found = false;
  // QuickTimeStream.pl:3702 `while ($dataLen)` — read 0x8000-byte chunks.
  while pos < limit {
    let chunk_end = (pos + GPS_BLOCK_SIZE).min(limit);
    // `chunk_end <= limit <= tail.len()` and `pos < limit <= chunk_end`, so
    // this `.get` is always `Some`; the `else` break matches the `while` guard.
    let Some(chunk) = tail.get(pos..chunk_end) else {
      break;
    };
    // QuickTimeStream.pl:3710 `if ($buff !~ /(\0..\0freeGPS |GP\x06\0\0)/sg)`.
    // Search ALL non-overlapping matches in this chunk and dispatch.
    let mut search_off = 0usize;
    // When a dispatched block extends past the current chunk, ExifTool advances
    // `$pos += $len` (QuickTimeStream.pl:3781) so the next iteration re-windows
    // at the byte AFTER the whole block. We mirror that by overriding `pos`.
    let mut pos_override: Option<usize> = None;
    // `search_off` is kept `< chunk.len()` by the guards that set it, so
    // `chunk.get(search_off..)` is `Some`; on the impossible miss `and_then`
    // short-circuits and the loop ends (as if no further magic) — byte-identical.
    while let Some(hit) = chunk.get(search_off..).and_then(find_magic) {
      let abs = search_off + hit.offset;
      match hit.kind {
        MagicKind::FreeGps => {
          // QuickTimeStream.pl:3750 `last if length $buff < $gpsBlockSize` — a
          // freeGPS magic found in a sub-0x8000-byte chunk (only possible in
          // the FINAL partial chunk, since `chunk` already includes the 12-byte
          // cross-chunk carry) is NOT decoded: ExifTool bails the whole scan
          // here, BEFORE reading the block length or dispatching. Mirror that —
          // but only for a partial final chunk; a block straddling two FULL
          // 0x8000 chunks is found in a full chunk (`chunk.len()` == 0x8000) and
          // handled by the buffer-extend path below (R1).
          if chunk.len() < GPS_BLOCK_SIZE {
            return;
          }
          // The match's first byte (the `\0`) is 4 bytes BEFORE the literal
          // "freeGPS " — read the box length from the 4 BE bytes at the
          // match start. QuickTimeStream.pl:3764 `my $len = unpack('N', $buff)`.
          if abs + 12 > chunk.len() {
            // tail underflow — defer to the next chunk.
            break;
          }
          let len = be_u32(chunk, abs).unwrap_or(0) as usize;
          // QuickTimeStream.pl:3765 `$len = 12 if $len < 12`.
          let len = len.max(12);
          // QuickTimeStream.pl:3768-3772 — `$more = $len - length($buff); …
          // $raf->Read($buf2, $more)`: ExifTool EXTENDS the buffer when the
          // declared box overruns the current 0x8000-byte chunk. We hold the
          // whole file in memory, so the faithful equivalent is to slice the
          // block from `tail` using its ABSOLUTE offset (`pos + abs`) rather
          // than from the bounded `chunk` window — slicing `chunk[abs..
          // abs+len]` panics whenever `abs + len` exceeds the window, which is
          // the COMMON case for real 0x8000-byte freeGPS blocks: the 12-byte
          // cross-chunk overlap (the `substr($buff,-12)` carry below) lands the
          // next adjacent 0x8000 block straddling the window boundary.
          let block_abs = pos + abs;
          if block_abs + len > limit {
            // QuickTimeStream.pl:3770 `last unless $raf->Read == $more` — a
            // short final read: the declared box runs past the end of the
            // (current) scan window, so stop scanning entirely.
            return;
          }
          // The guard above proves `block_abs + len <= limit <= tail.len()`,
          // so this `.get` is always `Some`; the `else` return matches that
          // guard's recovery (byte-identical).
          let Some(block) = tail.get(block_abs..block_abs + len) else {
            return;
          };
          // QuickTimeStream.pl:3777 `$dirInfo = { DataPt, DataPos, DirLen }` —
          // the brute-force scan's `$dirInfo` carries NO `SampleTime`, so
          // `sample_time` is `None` here (a Type-19 block found by the scan
          // gets no synthesized GPSDateTime, matching the oracle).
          process_free_gps(
            block,
            create_date_raw,
            None,
            kodak_version,
            &mut state,
            out,
            ligogps_out.as_deref_mut(),
          );
          found = true;
          if block_abs + len > chunk_end {
            // The block ran past the current chunk. ExifTool's `$pos += $len;
            // $buf2 = substr($buff, $len)` discards everything up to the block
            // end and continues from there — it does NOT re-scan inside a
            // consumed block. Re-window at the absolute byte after the block.
            pos_override = Some(block_abs + len);
            break;
          }
          // QuickTimeStream.pl:3781 `$pos += $len` (block fully inside the
          // chunk) — keep scanning the rest of this chunk from after the block.
          search_off = abs + len;
          if search_off >= chunk.len() {
            break;
          }
        }
        MagicKind::GoPro => {
          // QuickTimeStream.pl:3717-3748: a GoPro `GP\x06\0\0` record
          // re-dispatches into Image::ExifTool::GoPro::ProcessGP6 (GoPro.pm:
          // 783-803). exifast's port is in [`crate::formats::gopro`]: the
          // contained record (a GPMF KLV starting `DEVC`) goes through the
          // recursive KLV walker.
          //
          // QuickTimeStream.pl:3731 calls `ProcessGP6($et, { RAF => $raf,
          // DirLen => $maxLen })` with the REST of the media-data slice from
          // this magic onward, and the function returns the byte count it
          // consumed. Mirror that — pass `tail[pos+abs..]` so `process_gp6`
          // can walk consecutive `GP\x06\0\0` records as a sequence. The magic
          // was just located within `tail`, so `pos + abs` is in range; use
          // the checked accessor (file-level `deny(indexing_slicing)`). The
          // `DirLen => $maxLen` cap (QuickTimeStream.pl:3728) is `$dataLen -
          // ($start - MediaDataOffset)`, i.e. from the record to the END of
          // the (possibly trailer-expanded) scan window — bound by `limit`.
          let rec_start = pos + abs;
          let consumed = tail
            .get(rec_start..limit)
            .map_or(0, |rest| gopro::process_gp6(rest, gopro_out));
          if consumed > 0 {
            // QuickTimeStream.pl:3732-3737 — the EOF window expansion is
            // guarded by `unless ($found)`: it fires ONLY when NOTHING was
            // located before this GoPro record. Snapshot `$found` BEFORE
            // setting it for this record, so a prior freeGPS block (which set
            // `$found = 1`, line 3753) or a prior GP6 (which set `$found = 2`)
            // does NOT let a later GP6 expand past the declared `mdat` into the
            // trailer. Only a first-ever find expands.
            if !found {
              // QuickTimeStream.pl:3734 `$raf->Seek(0,2) and $dataLen = Tell -
              // MediaDataOffset` — grow the window to the end of the file.
              limit = tail.len();
            }
            found = true;
            // QuickTimeStream.pl:3739-3741 `Seek($start + $size); $pos = …;
            // $buf2 = ''`: ALWAYS advance to the ABSOLUTE consumed end and
            // CLEAR the 12-byte carry (unconditional in ExifTool). `process_gp6`
            // already walked the whole consecutive `GP\x06` sequence, so there
            // is no remaining GP6 to find inside the consumed span; re-window
            // via `pos_override` (resumes with no carry — exactly `$buf2 = ''`)
            // rather than an in-chunk `search_off`. Doing this unconditionally
            // (not just when the span crosses `chunk_end`) also covers a record
            // ending EXACTLY at the 0x8000 boundary, which the outer loop's
            // 12-byte carry would otherwise re-scan from inside consumed bytes.
            let abs_end = rec_start + consumed;
            pos_override = Some(abs_end);
            break;
          } else {
            // consumed == 0 — the record didn't validate; ExifTool's fallback
            // is to continue with the search (QuickTimeStream.pl:3743-3745
            // `Seek($filePos); $buf2 = substr($buff, $buffPos)`). Advance past
            // the 5-byte magic to avoid an infinite re-match.
            search_off = abs + 5;
          }
          if search_off >= chunk.len() {
            break;
          }
        }
      }
    }
    if let Some(p) = pos_override {
      // A block overran the chunk; resume immediately after it (no 12-byte
      // carry — the block boundary is a hard split, like ExifTool's `$buf2 =
      // substr($buff, $len)`).
      if p <= pos {
        break;
      }
      pos = p;
      continue;
    }
    // QuickTimeStream.pl:3711-3712 — keep the last 12 bytes for cross-chunk
    // magic matches.
    if chunk.len() <= 12 {
      break;
    }
    // QuickTimeStream.pl:3713-3715 `next if $found or $pos < 20e6 or $ee > 1;
    // last`: in all samples the first freeGPS block is within ~2 MB of the start
    // of mdat, so when nothing has been found yet the scan stops once `pos`
    // reaches the first 20 MB. The cutoff is `20e6` (= 20_000_000 decimal), NOT
    // `20 * 1024 * 1024`.
    let next = pos + chunk.len() - 12;
    if !found && next >= 20_000_000 {
      break;
    }
    pos = next;
  }
}

enum MagicKind {
  FreeGps,
  GoPro,
}

struct MagicHit {
  offset: usize,
  kind: MagicKind,
}

/// Search a window for either the `freeGPS ` magic (preceded by `\0xx\0`,
/// QuickTimeStream.pl:3710 `/\0..\0freeGPS /`) or the GoPro `GP\x06\0\0`
/// header. Returns the FIRST match's offset (in `buf`) and kind.
fn find_magic(buf: &[u8]) -> Option<MagicHit> {
  // Faithful: `\0..\0freeGPS ` — a NUL byte, two arbitrary bytes, another NUL,
  // then literal "freeGPS ". This is the 16-byte atom header pattern
  // `[hi:1=0][md:1][lo:1][reserved:1=0][f:1=f][r:1=r][e:1=e][e:1=e]...`.
  let needle = b"freeGPS ";
  let go_pro = b"GP\x06\0\0";
  let mut best: Option<MagicHit> = None;
  // freeGPS scan: find "freeGPS " in buf, then verify the 4-byte length
  // header preceding it has the `\0..\0` shape (the first byte must be 0 —
  // the box size is at most 24-bit, and the 4th byte is also 0 in every
  // real sample).
  let mut start = 0usize;
  // `start` stays `<= buf.len()` (the matched needle always fits), so
  // `buf.get(start..)` is `Some`; an impossible miss ends the loop as if no
  // further match — byte-identical to `memmem(&buf[start..], needle)`.
  while let Some(pos) = buf.get(start..).and_then(|s| memmem(s, needle)) {
    let abs = start + pos;
    if abs >= 4 {
      // The match offset is `abs`, the magic starts here, the 4 BE bytes
      // BEFORE this position are the box length. QuickTimeStream.pl:3710's
      // pattern requires bytes -4 and -1 to be NUL.
      let pre = abs - 4;
      // `abs >= 4` ⇒ `pre >= 0` and (since the needle fits) `pre + 3 < len`,
      // so both `.get`s are `Some` — byte-identical to the raw indexing.
      if buf.get(pre) == Some(&0) && buf.get(pre + 3) == Some(&0) {
        // The MATCH starts at the NUL (i.e. at `abs - 4`).
        let offset = abs - 4;
        best = Some(MagicHit {
          offset,
          kind: MagicKind::FreeGps,
        });
        break;
      }
    }
    start = abs + needle.len();
  }
  // GoPro scan.
  if let Some(p) = memmem(buf, go_pro) {
    let take = match &best {
      Some(b) => p < b.offset,
      None => true,
    };
    if take {
      best = Some(MagicHit {
        offset: p,
        kind: MagicKind::GoPro,
      });
    }
  }
  best
}

/// Plain byte substring search (Boyer-Moore would be overkill — the haystacks
/// here are ≤32 KiB and the needles 5-8 bytes).
fn memmem(hay: &[u8], needle: &[u8]) -> Option<usize> {
  if needle.is_empty() || hay.len() < needle.len() {
    return None;
  }
  let last = hay.len() - needle.len();
  for i in 0..=last {
    // `i <= last = hay.len() - needle.len()`, so `i + needle.len() <=
    // hay.len()` and `.get` is always `Some` — byte-identical to the slice.
    if hay.get(i..i + needle.len()) == Some(needle) {
      return Some(i);
    }
  }
  None
}

// ===========================================================================
// ProcessFreeGPS (QuickTimeStream.pl:1637-2484)
// ===========================================================================

/// Cross-block state that `ProcessFreeGPS` carries on `$$et` between freeGPS
/// blocks. The only consumer is the ATC GPSType-11 decoder
/// (QuickTimeStream.pl:2047-2157): the ATC device rewrites its WHOLE 30-entry
/// GPS ring buffer into every 0x8000-byte block, so without remembering the
/// most-recently-decoded record ExifTool would re-emit the same stale fixes
/// from each block. ExifTool keeps this in `$$et{FreeGPS2}`
/// (QuickTimeStream.pl:2058) and reads/writes it across `ProcessFreeGPS`
/// calls; the port threads it through [`scan_media_data`] (and the `gps `
/// sample-table path) instead.
///
/// All other GPSType decoders are stateless block-by-block (Type-13/14/20 emit
/// every record found in the current block, faithful to their `while (//sg)` /
/// `for` loops which carry no `$$et` state), so the struct is touched only by
/// [`decode_type11_atc`].
#[derive(Debug)]
pub struct FreeGpsState {
  /// `$$et{FreeGPS2}{Then}` (QuickTimeStream.pl:2057) — the `(H-1,M,S,Y,m,d)`
  /// of the most-recent ATC record decoded so far. `None` until the first
  /// valid record is seen (ExifTool initialises it to `[(0) x 6]`).
  atc_then: Option<[u32; 6]>,
  /// `$$et{FreeGPS2}{RecentRecPos}` (QuickTimeStream.pl:2151) — the 52-byte
  /// record offset (within the previous block) of that most-recent record, so
  /// the next block can skip everything older than it.
  atc_recent_rec_pos: Option<usize>,
  /// `$$et{FoundEmbedded}` (QuickTimeStream.pl:1650) — set TRUE the moment
  /// [`process_free_gps`] decodes a `freeGPS ` block (i.e. `ProcessFreeGPS` is
  /// entered on a block long enough to clear the `dirLen < 82` guard). It is
  /// the SOLE gate ExifTool uses to skip the brute-force `mdat` scan
  /// (`ScanMediaData`, QuickTimeStream.pl:3689 `return if $$et{FoundEmbedded}`)
  /// — NOT the per-sample `FoundSomething` output (QuickTimeStream.pl:967-973),
  /// which emits the `gps0`/`gsen`/`GPS `/`3gf`/`mebx` samples WITHOUT touching
  /// `FoundEmbedded`. So a file with such a timed-metadata stream PLUS a
  /// `freeGPS ` block buried in `mdat` still gets the buried block scanned.
  found_embedded: bool,
}

impl FreeGpsState {
  /// Fresh state — no ATC record decoded yet, `FoundEmbedded` clear.
  #[inline]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      atc_then: None,
      atc_recent_rec_pos: None,
      found_embedded: false,
    }
  }

  /// `$$et{FoundEmbedded}` — `true` once a `freeGPS ` block was decoded by
  /// [`process_free_gps`]. The caller threads this into [`scan_media_data`]'s
  /// `already_found_embedded` to mirror QuickTimeStream.pl:3689.
  #[inline]
  #[must_use]
  pub const fn found_embedded(&self) -> bool {
    self.found_embedded
  }
}

impl Default for FreeGpsState {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

/// `ProcessFreeGPS` (QuickTimeStream.pl:1637-2484): decode one `freeGPS `
/// block by fingerprint dispatch.
///
/// `data` is the WHOLE block — including the 16-byte atom header
/// (`[size:4][freeGPS :8][padding:4]`). ExifTool's `$$dataPt` is this same
/// whole-block buffer, so all the byte-offset constants in the variant
/// decoders below are RELATIVE to the block start.
///
/// `state` carries the cross-block ATC ring-buffer bookkeeping (the only
/// stateful GPSType); see [`FreeGpsState`].
///
/// `create_date_raw` / `sample_time` are ExifTool's `$$value{CreateDate}` (raw
/// 1904-epoch seconds) and `$$dirInfo{SampleTime}` (the enclosing sample's
/// decoding time, seconds) — the two inputs `SetGPSDateTime` needs to
/// synthesize a `GPSDateTime` (QuickTimeStream.pl:980-1008). Only the GPSTypes
/// whose blocks carry NO embedded date use them (currently only Type-19, the
/// 70mai A810 — QuickTimeStream.pl:2396 `SetGPSDateTime($et, $tagTbl,
/// $$dirInfo{SampleTime})`); every other variant parses its own date from the
/// block and ignores both.
///
/// In this port BOTH live callers pass `sample_time = None`: the brute-force
/// `ScanMediaData` path carries no `SampleTime` (`$dirInfo` has none,
/// QuickTimeStream.pl:3777), and the `moov`-level `gps ` offset box populates
/// only `$$et{ee}{start}`/`{size}` (no `stts`), so its `$time[$i]` is `undef`
/// (QuickTimeStream.pl:2548-2556 → :1562). A date-less GPSType (Type-19) thus
/// emits no `GPSDateTime` — byte-for-byte matching a real 70mai file ("no
/// timestamps in the samples", QuickTimeStream.pl:2389). The `Some` arm — the
/// faithful 1:1 of the Perl that runs when a `gps `-dispatch sample DOES carry
/// a decoding time (`$$dirInfo{SampleTime} => $time[$i]`, QuickTimeStream.pl:1562)
/// — is exercised by the unit test
/// `decode_type19_70mai_synthesizes_gps_date_time_from_sample_time`.
///
/// QuickTimeStream.pl:1645 `return 0 if $dirLen < 82` — a block too short to
/// carry any fingerprint is silently dropped.
///
/// **SP4** — `ligogps_out` is the LigoGPS accumulator: when a GPSType-5
/// (`LIGOGPSINFO\0`) fingerprint is hit (QuickTimeStream.pl:1843-1888) the
/// block is dispatched to
/// [`crate::formats::ligogps::process_ligogps_with_scale`]. The walk path
/// threads a real accumulator (the `mdat` scan, the `moov` `gps ` box, and
/// the `gpmd` Kingslim re-route all pass `Some(..)`); callers with no LigoGPS
/// accumulator (some unit tests) pass `None`, which silently drops a Type-5
/// fingerprint in that path.
pub fn process_free_gps(
  data: &[u8],
  create_date_raw: Option<u64>,
  sample_time: Option<f64>,
  kodak_version: Option<&str>,
  state: &mut FreeGpsState,
  out: &mut QuickTimeStreamMeta,
  ligogps_out: Option<&mut crate::metadata::LigoGpsMeta>,
) {
  // QuickTimeStream.pl:1645 `return 0 if $dirLen < 82` — too short to carry any
  // fingerprint; bails BEFORE the FoundEmbedded flag is set (:1650), so such a
  // runt does NOT suppress the `mdat` scan.
  if data.len() < 82 {
    return;
  }
  // QuickTimeStream.pl:1650 `$$et{FoundEmbedded} = 1` — set the moment a
  // freeGPS block reaches the decoder (whether or not THIS block yields a
  // sample), exactly where the Perl sets it: after the `< 82` guard, before
  // any variant dispatch. This — not per-sample `FoundSomething` output — is
  // what gates `ScanMediaData` (:3689); see [`FreeGpsState::found_embedded`].
  state.found_embedded = true;
  // QuickTimeStream.pl:1649 SetByteOrder('II') — every variant reads LE
  // unless it explicitly switches.

  // GPSType 1: Azdome GS63H / EEEkit encrypted ASCII GPS
  // (QuickTimeStream.pl:1652-1715). Detected by the 8-byte XOR-0xAA-prefix
  // signature at offset 18.
  if data.get(18..26) == Some([0xaa, 0xaa, 0xf2, 0xe1, 0xf0, 0xee, 0x54, 0x54].as_slice()) {
    decode_type1_azdome(data, out);
    return;
  }

  // GPSType 2: Nextbase 512GW NMEA dashcam
  // (QuickTimeStream.pl:1717-1750). Detected by an ASCII timestamp at offset
  // 52: 14 digits in YYYYMMDDhhmmss.
  if data.get(52..66).is_some_and(|s| is_ascii_digits(s, 14)) {
    decode_type2_nextbase_nmea(data, out);
    return;
  }

  // GPSType 3/4: Kenwood DRV-A510W / ViofoA119v3 / E-ACE B44 variants
  // (QuickTimeStream.pl:1752-1841). Detected by `A[NS][EW]\0` at offset 37
  // OR 85 (the Kenwood DRV-A510W has a 48-byte extra header).
  if let Some(((kw_off, lat_ref, lon_ref), payload)) = detect_type3_4(data) {
    decode_type3_4(payload, kw_off, lat_ref, lon_ref, out);
    return;
  }

  // GPSType 5: LigoGPS embedded-in-freeGPS path.
  // (QuickTimeStream.pl:1843-1888). Detected by `LIGOGPSINFO\0` at offset
  // 16/48/80; dispatch to `Image::ExifTool::LigoGPS::ProcessLigoGPS`.
  // The offset-16 + `\xf0\x03\0\0...{16}\0{4}` fingerprint sets the
  // ABASK A8 4K scale = 3 (QuickTimeStream.pl:1886).
  if let Some(off) = detect_type5_ligogps(data) {
    if let Some(ligo_meta) = ligogps_out {
      // QuickTimeStream.pl:1886 — scale = 3 when offset = 16 AND the
      // `\xf0\x03\0\0`+20-zero-bytes Rexing/ABASK fingerprint matches.
      let scale_id = if off == 16
        && data.get(12..16) == Some(&[0xf0, 0x03, 0x00, 0x00])
        && data.get(32..36) == Some(&[0x00, 0x00, 0x00, 0x00])
      {
        Some(3)
      } else {
        None
      };
      // **Finding 3** — each binary LigoGPS record opens a new GLOBAL `Doc<N>`
      // (`$$et{DOC_NUM} = ++$$et{DOC_COUNT}`, LigoGPS.pm:243). This freeGPS arm
      // is reached at the record's walk position from ALL THREE binary paths
      // (the `moov`-level `gps ` box, the Kingslim `gpmd` sample, and the
      // brute-force `mdat` scan), each of which has the SHARED `out` counter in
      // scope — so watermark-then-stamp here off `out.doc_counter()` continues
      // the same global sequence as the file's other embedded sources.
      let ligo_start = ligo_meta.sample_count();
      // QuickTimeStream.pl:1883 — `DirStart = $pos` (i.e. `off`).
      crate::formats::ligogps::process_ligogps_with_scale(data, off, ligo_meta, false, scale_id);
      let next = ligo_meta.stamp_doc_from(ligo_start, out.doc_counter());
      out.set_doc_counter(next);
    }
    return;
  }

  // GPSType 6: Akaso dashcam (QuickTimeStream.pl:1906-1938).
  // Detected by `A\0\0\0....[NS]\0\0\0....[EW]\0\0\0` at offsets 60..79.
  // Per QuickTimeStream.pl:1906 `^.{60}A\0{3}.{4}([NS])\0{3}.{4}([EW])\0{3}` —
  // the regex references bytes only through offset 79, so 80 bytes is the true
  // minimum (the global `< 82` gate already covers it). The previous explicit
  // `>= 88` gate would mis-route an 80..87-byte Akaso block to a later arm; the
  // bounded `.get()` detection + zero-filling `le_*` decode reads match Perl.
  if data.get(60).copied() == Some(b'A')
    && data.get(61..64) == Some(&[0, 0, 0])
    && matches!(data.get(68), Some(&b'N' | &b'S'))
    && data.get(69..72) == Some(&[0, 0, 0])
    && matches!(data.get(76), Some(&b'E' | &b'W'))
    && data.get(77..80) == Some(&[0, 0, 0])
  {
    decode_type6_akaso(data, out);
    return;
  }

  // GPSType 7: "4W`b]S<" cipher → $GPRMC (QuickTimeStream.pl:1940-1959).
  // Detected by the 7-byte cipher signature at offset 60.
  if data.len() >= 140 && data.get(60..67) == Some(b"4W`b]S<") {
    decode_type7_cipher(data, out);
    return;
  }

  // GPSType 8: Akaso V1 / Redtiger F7N (QuickTimeStream.pl:1961-1996).
  // Encrypted lat/lon (NC); detected by a date+flag pattern at offset 64.
  // Detection is the bundled regex alone (QuickTimeStream.pl:1961, which
  // references bytes through offset 79); the dispatch carries NO extra
  // minimum-length gate — `detect_type8` bounds its own reads, and the
  // decoder's `le_*` reads zero-fill the tail like Perl's `unpack`/`Get*`.
  if detect_type8(data) {
    decode_type8_akaso_v1(data, out);
    return;
  }

  // GPSType 9: EACHPAI — DEFERRED (encryption unknown).
  // Bundled regex `/^.{12}\xac\0\0\0.{44}(.{72})/s` (QuickTimeStream.pl:1998):
  // byte 0x0c == 0xac followed by THREE NUL bytes (a little-endian `ac 00 00
  // 00`). The port previously read `be_u32(0x0c) == 0xac` (= big-endian
  // 0xac000000, always false); compare the raw bytes instead.
  if data.get(0x0c).copied() == Some(0xac) && data.get(0x0d..0x10) == Some(&[0, 0, 0]) {
    // Faithful: `Can't yet decrypt EACHPAI timed GPS` — skip silently.
    return;
  }

  // GPSType 10: Vantrue S1 / horsontech (QuickTimeStream.pl:2021-2045).
  // Bundled regex `/^.{64}A([NS])([EW])\0/s` (QuickTimeStream.pl:2021) — `A`@64,
  // `[NS]`@65, `[EW]`@66, `\0`@67: it references bytes only through offset 67,
  // so 68 bytes is the true minimum (the port previously gated on `>= 0x80`,
  // mis-routing a 68..0x80-byte Vantrue block to the Type-20 catch-all). The
  // decoder's `le_*` reads zero-fill the tail like Perl's `unpack`/`GetFloat`,
  // and its own `mon` 1..12 / `day` 1..31 guard (matching :2035) drops a
  // too-short block before emitting.
  if data.get(64).copied() == Some(b'A')
    && matches!(data.get(65), Some(&b'N' | &b'S'))
    && matches!(data.get(66), Some(&b'E' | &b'W'))
    && data.get(67).copied() == Some(0)
  {
    decode_type10_vantrue_s1(data, out);
    return;
  }

  // GPSType 11: ATC GPS (QuickTimeStream.pl:2047-2157).
  // 52-byte encrypted records; detected by "ATC" at offset 0x45.
  if data.len() >= 0x48 && data.get(0x45..0x48) == Some(b"ATC") {
    decode_type11_atc(data, state, out);
    return;
  }

  // GPSType 12: Type 2 80-byte (double lat/lon) (QuickTimeStream.pl:2159-2188).
  // Bundled regex (QuickTimeStream.pl:2159):
  //   `/^.{60}A\0.{10}([NS])\0.{14}([EW])\0/s and $dirLen >= 0x88`.
  // So: `A`@60, `\0`@61, then 10 filler bytes, `[NS]`@72 (= data-layout
  // `0x48` latitude-ref), `\0`@73, 14 filler bytes, `[EW]`@88 (= `0x58`
  // longitude-ref), `\0`@89.
  if data.len() >= 0x88
    && data.get(60).copied() == Some(b'A')
    && data.get(61).copied() == Some(0)
    && matches!(data.get(72), Some(&b'N' | &b'S'))
    && data.get(73).copied() == Some(0)
    && matches!(data.get(88), Some(&b'E' | &b'W'))
    && data.get(89).copied() == Some(0)
  {
    decode_type12_double(data, out);
    return;
  }

  // GPSType 13: INNOVV MP4 (QuickTimeStream.pl:2190-2214). Detected by
  // `A[NS][EW]\0` at offset 16; a stream of 32-byte records follows.
  if data.len() >= 0x40
    && data.get(16).copied() == Some(b'A')
    && matches!(data.get(17), Some(&b'N' | &b'S'))
    && matches!(data.get(18), Some(&b'E' | &b'W'))
    && data.get(19).copied() == Some(0)
  {
    decode_type13_innovv(data, out);
    return;
  }

  // GPSType 14: XBHT motorcycle dashcam (QuickTimeStream.pl:2216-2238).
  // Detected by date/time bytes + `A[NS][EW]` at offset 20-27.
  if data.len() >= 0x40 && detect_type14(data) {
    decode_type14_xbht(data, out);
    return;
  }

  // GPSType 15: Vantrue N4 (QuickTimeStream.pl:2240-2263).
  // Bundled regex `/^.{28}A.{11}([NS]).{15}([EW])/s` (QuickTimeStream.pl:2240)
  // — `A`@28, `[NS]`@40, `[EW]`@56: it references bytes only through offset 56,
  // so the detection has no `>= 0x60` precondition (the bounded `.get()` reads
  // suffice; the previous `>= 0x60` gate would mis-route a 57..0x60-byte Vantrue
  // N4 block to Type-20). Decode `le_f64`/`le_u32` reads zero-fill the tail.
  if data.get(28).copied() == Some(b'A')
    && matches!(data.get(40), Some(&b'N' | &b'S'))
    && matches!(data.get(56), Some(&b'E' | &b'W'))
  {
    decode_type15_vantrue_n4(data, out);
    return;
  }

  // GPSType 16/17/17b/17c: Viofo A119S / IQS / Rexing / Transcend
  // (QuickTimeStream.pl:2265-2352). Bundled regex `/^.{72}A[NS][EW]\0/s`
  // (QuickTimeStream.pl:2265) — `A`@72, `[NS]`@73, `[EW]`@74, `\0`@75: it
  // references bytes only through offset 75, so 76 (0x4c) is the true minimum
  // (the previous `>= 0x60` gate would mis-route a 76..0x60-byte Viofo/IQS
  // block to Type-20). Decode `le_*` reads zero-fill the tail like Perl.
  if data.get(72).copied() == Some(b'A')
    && matches!(data.get(73), Some(&b'N' | &b'S'))
    && matches!(data.get(74), Some(&b'E' | &b'W'))
    && data.get(75).copied() == Some(0)
  {
    decode_type16_17_viofo(data, kodak_version, out);
    return;
  }

  // GPSType 18: XGODY 12" 4K ASCII (QuickTimeStream.pl:2354-2384).
  // `YYYY/MM/DD HH:MM:SS [NS]:` at offset 23.
  if data.len() >= 64 && detect_type18(data) {
    decode_type18_xgody(data, out);
    return;
  }

  // GPSType 19: 70mai A810 (QuickTimeStream.pl:2386-2401).
  // `A` at offset 30 and `VV` at offset 51.
  if data.len() >= 64 && data.get(30).copied() == Some(b'A') && data.get(51..53) == Some(b"VV") {
    decode_type19_70mai(data, create_date_raw, sample_time, out);
    return;
  }

  // GPSType 20: Nextbase 512G (32-byte BE records, QuickTimeStream.pl:2403-2451).
  // Tried last (the catch-all `else` arm in ExifTool).
  decode_type20_nextbase512(data, out);
}

// ===========================================================================
// Variant decoders
// ===========================================================================

/// `\$buff =~ /\d{N}/` — N ASCII decimal digits starting at `pos`.
fn is_ascii_digits(b: &[u8], n: usize) -> bool {
  // `.get(..n)` is `Some` exactly when `b.len() >= n`, byte-identical to the
  // length guard; then every one of the first `n` bytes must be a digit.
  b.get(..n)
    .is_some_and(|s| s.iter().all(|&c| c.is_ascii_digit()))
}

/// `$sec = '0' . $sec if defined $sec and $sec !~ /^\d{2}/`
/// (QuickTimeStream.pl:2460) — pad the seconds string with a leading `0` when
/// it does NOT begin with two ASCII digits (so `"8.5"` → `"08.5"`, `"5"` →
/// `"05"`, but `"45"`/`"08.5"` are left as-is). NOT a `len < 2` test.
fn pad_seconds(sec: &str) -> String {
  let b = sec.as_bytes();
  // Both `.get`s are `Some` only when `b.len() >= 2`, so this is byte-identical
  // to the original `b.len() >= 2 && b[0]… && b[1]…`.
  let starts_two_digits =
    b.first().is_some_and(|c| c.is_ascii_digit()) && b.get(1).is_some_and(|c| c.is_ascii_digit());
  if starts_two_digits {
    sec.to_string()
  } else {
    alloc::format!("0{sec}")
  }
}

/// Common path used by every variant that gathers `yr/mon/.../lat/lon/...`
/// in the same way the ExifTool tail does (QuickTimeStream.pl:2459-2483).
struct FreeGpsTags {
  yr: Option<i32>,
  mon: Option<u32>,
  day: Option<u32>,
  hr: Option<u32>,
  min: Option<u32>,
  sec: Option<String>,
  lat: Option<f64>,
  lon: Option<f64>,
  lat_ref: Option<char>,
  lon_ref: Option<char>,
  alt: Option<f64>,
  spd: Option<f64>,
  trk: Option<f64>,
  accel: Option<(f64, f64, f64)>,
  /// A pre-joined `Accelerometer` STRING — the Roadhawk 4-value
  /// `"$1 $2 $3 $4"` (QuickTimeStream.pl:1266) the 3-tuple `accel` cannot hold.
  /// Takes precedence over `accel` in [`Self::emit`] when set.
  accel_str: Option<SmolStr>,
  user_label: Option<String>,
  /// `true` ⇒ lat/lon are already in decimal degrees (skip ConvertLatLon).
  ddd: bool,
  /// A `SetGPSDateTime`-synthesized `GPSDateTime` (CreateDate + SampleTime,
  /// QuickTimeStream.pl:980-1008) for the date-less GPSTypes that call
  /// `SetGPSDateTime` instead of parsing a date from the block (Type-19). It is
  /// only consulted when the block carried NO embedded date (`yr`/`hr` unset),
  /// faithfully matching ExifTool: `SetGPSDateTime` runs BEFORE the common tail
  /// (QuickTimeStream.pl:2396) and the tail emits no `GPSDateTime` when `$yr`
  /// is undef, so the synthesized value is the only `GPSDateTime` for Type-19.
  synth_date_time: Option<SmolStr>,
  /// The `Process_text` dashcam extras (`Text`/`GSensor`/`Car`/`Distance`/
  /// `VerticalSpeed`/`FNumber`/`ExposureTime`/`ExposureCompensation`/`ISO`,
  /// QuickTimeStream.pl:1213-1294 + the timed-text `Text` tag). Default-empty;
  /// populated ONLY by the text-fallback branches, then moved onto the emitted
  /// [`GpsSample`] when non-empty.
  text_extras: TextExtras,
}

impl FreeGpsTags {
  fn new() -> Self {
    Self {
      yr: None,
      mon: None,
      day: None,
      hr: None,
      min: None,
      sec: None,
      lat: None,
      lon: None,
      lat_ref: None,
      lon_ref: None,
      alt: None,
      spd: None,
      trk: None,
      accel: None,
      accel_str: None,
      user_label: None,
      ddd: false,
      synth_date_time: None,
      text_extras: TextExtras::default(),
    }
  }
  /// Common-tail emission — QuickTimeStream.pl:2455-2483. Validates month +
  /// day ranges and synthesizes GPSDateTime + applies ConvertLatLon.
  fn emit(self, out: &mut QuickTimeStreamMeta) {
    // QuickTimeStream.pl:2455 `return 0 if defined $yr and ($mon < 1 or $mon >
    // 12)`. In Perl an undef `$mon` numifies to 0 in `$mon < 1`, so when `$yr`
    // is defined but `$mon` is NOT, the `$mon < 1` (0 < 1) is true → bail.
    // Mirror that: `yr = Some` with `mon = None` (treated as 0) also bails.
    if let Some(_yr) = self.yr
      && !self.mon.is_some_and(|m| (1..=12).contains(&m))
    {
      return;
    }
    let mut sample = GpsSample::new();
    let date_time = if let (Some(mut yr), Some(mon), Some(day), Some(hr), Some(min), Some(sec)) = (
      self.yr,
      self.mon,
      self.day,
      self.hr,
      self.min,
      self.sec.as_deref(),
    ) {
      // QuickTimeStream.pl:2462 `$yr += 2000 if $yr < 2000`.
      if yr < 2000 {
        yr += 2000;
      }
      let s = pad_seconds(sec);
      Some(alloc::format!(
        "{yr:04}:{mon:02}:{day:02} {hr:02}:{min:02}:{s}Z"
      ))
    } else if let (Some(hr), Some(min), Some(sec)) = (self.hr, self.min, self.sec.as_deref()) {
      // QuickTimeStream.pl:2465-2467 — time-only GPSTimeStamp.
      let s = pad_seconds(sec);
      Some(alloc::format!("{hr:02}:{min:02}:{s}Z"))
    } else {
      None
    };
    // QuickTimeStream.pl:2396 — when the block carried no embedded date, a
    // `SetGPSDateTime`-synthesized `GPSDateTime` (Type-19) is the value. The
    // parsed date (if any) always wins, mirroring ExifTool's last-`HandleTag`
    // semantics (no GPSType both parses a date AND synthesizes one).
    let date_time = date_time
      .map(SmolStr::from)
      .or_else(|| self.synth_date_time.clone());
    sample.set_date_time(date_time);

    // Lat/lon emission (QuickTimeStream.pl:2469-2474). ConvertLatLon UNLESS
    // ddd is set — many GPSType variants pre-format lat/lon in decimal degrees.
    if let (Some(mut lat), Some(mut lon)) = (self.lat, self.lon) {
      if !self.ddd {
        lat = convert_lat_lon(lat);
        lon = convert_lat_lon(lon);
      }
      if matches!(self.lat_ref, Some('S')) {
        lat = -lat;
      }
      if matches!(self.lon_ref, Some('W')) {
        lon = -lon;
      }
      sample.set_latitude(Some(lat));
      sample.set_longitude(Some(lon));
    }
    if let Some(alt) = self.alt {
      sample.set_altitude_m(Some(alt));
    }
    if let Some(spd) = self.spd {
      sample.set_speed_kph(Some(spd));
    }
    if let Some(trk) = self.trk {
      sample.set_track(Some(trk));
    }
    if let Some(acc) = self.accel_str {
      // The Roadhawk pre-joined 4-value string (QuickTimeStream.pl:1266).
      sample.set_accelerometer(Some(acc));
    } else if let Some((x, y, z)) = self.accel {
      sample.set_accelerometer(Some(SmolStr::from(join3(x, y, z))));
    }
    // The `Process_text` dashcam extras (`Text`/`GSensor`/`Car`/`Distance`/…) —
    // attach the populated sub-struct so the SP3 emitter writes them under the
    // sample's `Doc<N>` (QuickTimeStream.pl:1213-1294 + the wrapper's `Text`).
    if !self.text_extras.is_empty() {
      sample.set_text_extras(Some(self.text_extras));
    }
    // user_label — exiftool emits it as `UserLabel`, not part of the typed
    // GpsSample fields. The sample is recorded; we lose the label string by
    // design (the typed domain doesn't carry it). Acknowledge to satisfy
    // dead-code warnings:
    let _ = self.user_label;
    if !sample.is_empty() {
      out.push_gps_sample(sample);
    }
  }
}

/// Apply `SignedInt32 / 256` to a sequence of u32 (QuickTimeStream.pl:1749).
fn signed_div(raw: &[u32], div: f64) -> Vec<f64> {
  raw.iter().map(|&v| f64::from(v as i32) / div).collect()
}

// ─────────────────────────── GPSType 1: Azdome / EEEkit (XOR 0xAA) ─────────

/// `decode_type1_azdome` (QuickTimeStream.pl:1652-1715). XOR the bytes from
/// offset 18 with `0xaa` (capped at 0x101 bytes), then parse the decrypted
/// ASCII layout.
///
/// Decrypted layout:
/// ```text
///   .{8}\d{14}<lbl:15>[NS]\d{8}[EW]\d{9}\d{8}?
/// ```
/// where `\d{4}` = year, then `\d{2}\d{2}\d{2}\d{2}\d{2}` = mon/day/hr/min/sec.
fn decode_type1_azdome(data: &[u8], out: &mut QuickTimeStreamMeta) {
  let mut t = FreeGpsTags::new();
  // QuickTimeStream.pl:1682 — n = min(dirLen-18, 0x101).
  let n = (data.len() - 18).min(0x101);
  let mut buf2 = Vec::with_capacity(n);
  // `data.iter().skip(18).take(n)` reads exactly `data[18..18 + n]` (the guard
  // `data.len() >= 82` and `n = min(len-18, 0x101)` keep that window in range).
  for &b in data.iter().skip(18).take(n) {
    buf2.push(b ^ 0xaa);
  }

  // Parse: `^.{8}(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2}).(.{15})([NS])(\d{8})([EW])(\d{9})(\d{8})?`.
  if buf2.len() >= 8 + 14 + 1 + 15 + 1 + 8 + 1 + 9 {
    let off = 8;
    if buf2.get(off..).is_some_and(|s| is_ascii_digits(s, 14)) {
      let s = buf2
        .get(off..off + 14)
        .and_then(|s| core::str::from_utf8(s).ok())
        .unwrap_or("");
      t.yr = s[0..4].parse().ok();
      t.mon = s[4..6].parse().ok();
      t.day = s[6..8].parse().ok();
      t.hr = s[8..10].parse().ok();
      t.min = s[10..12].parse().ok();
      t.sec = Some(s[12..14].to_string());
      let lbl_off = off + 14 + 1; // skip the 14 digits + the `.` separator.
      let lbl_end = lbl_off + 15;
      if buf2.len() > lbl_end {
        let lbl = String::from_utf8_lossy(buf2.get(lbl_off..lbl_end).unwrap_or(&[]));
        let lbl = lbl.split('\0').next().unwrap_or("").trim().to_string();
        if !lbl.is_empty() {
          t.user_label = Some(lbl);
        }
        // [NS] at lbl_end.
        let pos_lat_ref = lbl_end;
        let lat_ref = buf2.get(pos_lat_ref).copied();
        if matches!(lat_ref, Some(b'N' | b'S')) {
          t.lat_ref = Some(lat_ref.unwrap() as char);
          let pos_lat = pos_lat_ref + 1;
          if buf2.get(pos_lat..).is_some_and(|s| is_ascii_digits(s, 8)) {
            let lat_s = buf2
              .get(pos_lat..pos_lat + 8)
              .and_then(|s| core::str::from_utf8(s).ok())
              .unwrap_or("0");
            t.lat = lat_s.parse::<f64>().ok().map(|v| v / 1e4);
          }
          let pos_lon_ref = pos_lat + 8;
          let lon_ref = buf2.get(pos_lon_ref).copied();
          if matches!(lon_ref, Some(b'E' | b'W')) {
            t.lon_ref = Some(lon_ref.unwrap() as char);
            let pos_lon = pos_lon_ref + 1;
            if buf2.get(pos_lon..).is_some_and(|s| is_ascii_digits(s, 9)) {
              let lon_s = buf2
                .get(pos_lon..pos_lon + 9)
                .and_then(|s| core::str::from_utf8(s).ok())
                .unwrap_or("0");
              t.lon = lon_s.parse::<f64>().ok().map(|v| v / 1e4);
            }
            let pos_spd = pos_lon + 9;
            if buf2.get(pos_spd..).is_some_and(|s| is_ascii_digits(s, 8)) {
              // Azdome: spd is the optional `(\d{8})?` group at offset 57
              // (QuickTimeStream.pl:1690-1693, `$spd += 0` strips leading 0s).
              let spd_s = buf2
                .get(pos_spd..pos_spd + 8)
                .and_then(|s| core::str::from_utf8(s).ok())
                .unwrap_or("0");
              t.spd = spd_s.parse().ok();
            } else {
              // EEEkit: QuickTimeStream.pl:1694 `/^.{57}([-+]\d{4})(\d{3})/s`
              // → spd = `$2` = the 3 digits at offset 62, only when the
              // preceding `[-+]\d{4}` matches at offset 57.
              t.spd = parse_eeekit_spd(&buf2);
            }
          }
        }
      }
    }
  }

  // Accelerometer (QuickTimeStream.pl:1700-1711). The branch is selected by
  // WHICH regex matches, not by buffer length: the offset-65 form
  // (`^.{65}([-+]\d{3})([-+]\d{3})([-+]\d{3})…`) is tried first; only when it
  // does NOT match does the offset-173 Azdome form
  // (`^.{173}([-+]\d{3})([-+]\d{3})([-+]\d{3})`) apply, and that branch also
  // back-fills date/time/label from offset 8 when no GPS year was found
  // (`if (not defined $yr …)`).
  if let Some(acc) = parse_accel_3(&buf2, 65) {
    t.accel = Some(acc);
  } else if let Some(acc) = parse_accel_3(&buf2, 173) {
    t.accel = Some(acc);
    // QuickTimeStream.pl:1708-1710 — Azdome may carry date/time/label even
    // when GPS is absent. Back-fill only if no year was parsed above.
    if t.yr.is_none()
      && buf2.len() >= 8 + 14 + 1 + 15
      && buf2.get(8..).is_some_and(|s| is_ascii_digits(s, 14))
    {
      let s = buf2
        .get(8..8 + 14)
        .and_then(|s| core::str::from_utf8(s).ok())
        .unwrap_or("");
      t.yr = s[0..4].parse().ok();
      t.mon = s[4..6].parse().ok();
      t.day = s[6..8].parse().ok();
      t.hr = s[8..10].parse().ok();
      t.min = s[10..12].parse().ok();
      t.sec = Some(s[12..14].to_string());
      let lbl_off = 8 + 14 + 1; // skip the 14 digits + the `.` separator.
      let lbl = String::from_utf8_lossy(buf2.get(lbl_off..lbl_off + 15).unwrap_or(&[]));
      let lbl = lbl.split('\0').next().unwrap_or("").trim().to_string();
      if !lbl.is_empty() {
        t.user_label = Some(lbl);
      }
    }
  }

  // GPSType 1 is in DDDMM.MMMM (degrees*100 + minutes-fractional, the same
  // format ConvertLatLon expects). The Perl source uses `$ddd = 0` here.
  t.emit(out);
}

/// Parse `[-+]\d{3}` from a 4-byte ASCII window.
fn parse_signed_3digit(b: &[u8]) -> Option<i32> {
  if b.len() < 4 {
    return None;
  }
  // The `b.len() < 4` guard proves `b.first()` and `b.get(1..4)` are `Some`;
  // the `_`/`?` recovery is the same `return None` as the guard.
  let sign = match b.first() {
    Some(b'+') => 1,
    Some(b'-') => -1,
    _ => return None,
  };
  let digits = b.get(1..4)?;
  if !digits.iter().all(|&c| c.is_ascii_digit()) {
    return None;
  }
  let v = core::str::from_utf8(digits).ok()?.parse::<i32>().ok()?;
  Some(sign * v)
}

/// Parse three consecutive `[-+]\d{3}` groups starting at `off` and scale each
/// by `/100`, matching the freeGPS accelerometer regex. Returns `None` (i.e.
/// the regex does not match) unless all three groups are present and valid.
fn parse_accel_3(buf: &[u8], off: usize) -> Option<(f64, f64, f64)> {
  if buf.len() < off + 12 {
    return None;
  }
  // The `buf.len() < off + 12` guard proves these 4-byte windows are in range;
  // `?` on the impossible miss returns `None`, matching that guard.
  let x = parse_signed_3digit(buf.get(off..off + 4)?)?;
  let y = parse_signed_3digit(buf.get(off + 4..off + 8)?)?;
  let z = parse_signed_3digit(buf.get(off + 8..off + 12)?)?;
  Some((
    f64::from(x) / 100.0,
    f64::from(y) / 100.0,
    f64::from(z) / 100.0,
  ))
}

/// EEEkit speed (QuickTimeStream.pl:1694): `/^.{57}([-+]\d{4})(\d{3})/s` → the
/// 3-digit `$2` at offset 62, gated on a leading `[-+]\d{4}` at offset 57.
fn parse_eeekit_spd(buf: &[u8]) -> Option<f64> {
  if buf.len() < 65 {
    return None;
  }
  // The `buf.len() < 65` guard proves every fixed read below is in range; the
  // `?`/`is_some_and` recovery is the same `return None`/false as the guard.
  // `[-+]` at 57, then `\d{4}` at 58..62 (the gate).
  if !matches!(buf.get(57), Some(b'+' | b'-'))
    || !buf
      .get(58..62)
      .is_some_and(|s| s.iter().all(u8::is_ascii_digit))
  {
    return None;
  }
  // `(\d{3})` at 62..65.
  let spd = buf.get(62..65)?;
  if !spd.iter().all(u8::is_ascii_digit) {
    return None;
  }
  // `$2 + 0` — leading zeros stripped by numeric coercion.
  core::str::from_utf8(spd).ok()?.parse::<f64>().ok()
}

// ─────────────────────────── GPSType 2: Nextbase 512GW NMEA ────────────────

/// `decode_type2_nextbase_nmea` (QuickTimeStream.pl:1717-1750).
fn decode_type2_nextbase_nmea(data: &[u8], out: &mut QuickTimeStreamMeta) {
  let mut t = FreeGpsTags::new();
  // QuickTimeStream.pl:1732 `CameraDateTime` (the YYYYMMDDhhmmss at off 52) is
  // a separate tag the typed `GpsSample` does not carry — skipped, like
  // UserLabel/GPSSatellites/GPSDOP.
  // QuickTimeStream.pl:1733/1740 run the NMEA regexes over the RAW block bytes
  // (`$$dataPt`), NOT a decoded UTF-8 string — a Type-2 block always carries
  // binary fields (box header, accel int32s), so a strict `from_utf8` would
  // blank the whole search. Search the bytes directly and decode only the
  // matched (ASCII) sentence.
  // QuickTimeStream.pl:1733 — `\$[A-Z]{2}RMC,…`: any 2-letter talker.
  if let Some(rmc) = find_nmea_sentence(data, b"RMC") {
    parse_nmea_rmc(rmc, &mut t);
  }
  // QuickTimeStream.pl:1740-1745 — `\$[A-Z]{2}GGA,…`: altitude (+ lat/lon/time
  // when RMC did not provide a year). GPSSatellites/GPSDOP are not GpsSample
  // fields, so only the altitude is carried.
  if let Some(gga) = find_nmea_sentence(data, b"GGA") {
    parse_nmea_gga(gga, &mut t);
  }
  // Accelerometer (QuickTimeStream.pl:1746-1750): if GPS valid, read 3 ×
  // int32s at offset 68 / 256.
  if t.lat.is_some() && data.len() >= 68 + 12 {
    let p = 68;
    let raw: Vec<u32> = (0..3).filter_map(|i| le_u32(data, p + i * 4)).collect();
    if raw.len() == 3 {
      let vs = signed_div(&raw, 256.0);
      // `vs` has exactly 3 elements here (guarded above), so the slice
      // pattern always matches — byte-identical to `vs[0/1/2]`.
      if let [a, b, c] = vs.as_slice() {
        t.accel = Some((*a, *b, *c));
      }
    }
  }
  t.emit(out);
}

/// Find an NMEA sentence `$<2 uppercase letters><type>,` anywhere in the RAW
/// block bytes and return the slice starting at the leading `$` (mirroring the
/// bundled `\$[A-Z]{2}<type>,` match, which runs over `$$dataPt` and accepts
/// any talker prefix). Operating on bytes — not a decoded UTF-8 string — is
/// faithful: the bundled regex never decodes the buffer, so a non-ASCII byte
/// elsewhere in the block must not blank the search (QuickTimeStream.pl:1733,
/// 1740).
fn find_nmea_sentence<'a>(b: &'a [u8], kind: &[u8; 3]) -> Option<&'a [u8]> {
  let mut i = 0usize;
  while i + 7 <= b.len() {
    // The `while` guard proves the 7-byte window exists; matching it as a
    // slice pattern is byte-identical to the per-byte `b[i..i+7]` reads.
    if let Some(&[d, c1, c2, k0, k1, k2, comma]) = b.get(i..i + 7)
      && d == b'$'
      && c1.is_ascii_uppercase()
      && c2.is_ascii_uppercase()
      && [k0, k1, k2] == *kind
      && comma == b','
    {
      return b.get(i..);
    }
    i += 1;
  }
  None
}

/// Split a raw NMEA sentence (`$`…, possibly with a `*CC` checksum tail) into
/// comma-separated byte fields, dropping the checksum tail. Each field is a raw
/// byte slice; the per-field shape gates below decode the ASCII subset.
fn nmea_fields(s: &[u8]) -> Vec<&[u8]> {
  // Drop the `*` checksum tail to simplify field splitting.
  let body = s.split(|&c| c == b'*').next().unwrap_or(s);
  body.split(|&c| c == b',').collect()
}

/// Validate a byte field against the bundled `(\d+\.\d+)` NMEA lat/lon shape
/// (one-or-more digits, a dot, one-or-more digits) and parse it as `f64`. Used
/// for RMC/GGA lat & lon (QuickTimeStream.pl:1733/1740) — the bundled regex
/// rejects an empty or integer-only field, so a bare `.parse::<f64>()` (which
/// accepts `"5"`, `"+1"`, `"inf"`, …) would be too loose.
fn nmea_decimal(field: &[u8]) -> Option<f64> {
  let dot = field.iter().position(|&c| c == b'.')?;
  if dot == 0 || dot + 1 >= field.len() {
    return None; // need ≥1 int digit and ≥1 frac digit
  }
  // `dot < field.len()` (from `position`) and the guard above gives
  // `1 <= dot` and `dot + 1 < field.len()`, so both `.get`s are `Some`;
  // `?` on the impossible miss is byte-identical to `return None`.
  if !field.get(..dot)?.iter().all(u8::is_ascii_digit)
    || !field.get(dot + 1..)?.iter().all(u8::is_ascii_digit)
  {
    return None;
  }
  core::str::from_utf8(field).ok()?.parse::<f64>().ok()
}

/// Validate a byte field against the bundled `(-?\d+\.?\d*)` GGA-altitude shape
/// (optional sign, ≥1 int digit, optional dot, optional frac) and parse it as
/// `f64` (QuickTimeStream.pl:1740, capture `$11`). A bare `.parse::<f64>()`
/// would accept `"+1"`, `".5"`, `"inf"`, `"nan"` — none of which the regex
/// matches.
fn nmea_signed_decimal(field: &[u8]) -> Option<f64> {
  // After a `-` the slice is non-empty, so `.get(1..)` is `Some` (byte-
  // identical to `&field[1..]`).
  let rest = match field.first() {
    Some(b'-') => field.get(1..).unwrap_or_default(),
    _ => field,
  };
  // `\d+\.?\d*`: ≥1 leading digit, then optional `.` + optional digits.
  let int_end = rest.iter().take_while(|&&c| c.is_ascii_digit()).count();
  if int_end == 0 {
    return None;
  }
  // `int_end <= rest.len()`, so `.get(int_end..)` is always `Some`.
  let tail = rest.get(int_end..).unwrap_or_default();
  let ok = match tail.first() {
    None => true, // `\d+`
    // `tail` starts with `.`, so `.get(1..)` is `Some` — `\d+\.\d*`.
    Some(b'.') => tail
      .get(1..)
      .is_some_and(|s| s.iter().all(u8::is_ascii_digit)),
    Some(_) => false,
  };
  if !ok {
    return None;
  }
  core::str::from_utf8(field).ok()?.parse::<f64>().ok()
}

/// Parse a `$XXRMC,…` NMEA sentence (RAW bytes) into the `FreeGpsTags`
/// accumulator. QuickTimeStream.pl:1733 (Type 2) / :1952 (Type 7) pattern. Both
/// bundled regexes share this field layout; their lat/lon captures
/// (`(\d+\.\d+)` vs `(\d*?\d{1,2}\.\d+)`) both accept exactly "digits-dot-
/// digits", and both end with the date `(\d{2})(\d{2})(\d+)` (DD, MM, year of
/// ANY length ≥1 — NOT exactly 6).
fn parse_nmea_rmc(s: &[u8], t: &mut FreeGpsTags) {
  let fields = nmea_fields(s);
  // Fields: 0=$RMC, 1=HHMMSS.sss, 2=A, 3=lat, 4=N/S, 5=lon, 6=E/W,
  //         7=spd(knots), 8=trk, 9=DDMMYY, 10..=A
  if fields.len() < 10 {
    return;
  }
  // QuickTimeStream.pl:1733 / :1952 — the bundled regex gates the RMC status
  // field (field 2) with `,A?,`: it matches ONLY an active-fix `A` or an empty
  // field, so a void-fix `V` (the no-fix sentinel real dashcams emit at
  // startup) makes the whole RMC regex fail → no fields are copied. Mirror that
  // by rejecting any non-empty status other than `A`.
  if let Some(status) = fields.get(2).copied()
    && !status.is_empty()
    && status != b"A"
  {
    return;
  }
  // `(\d{2})(\d{2})(\d+(\.\d*)?)` time — ≥6 leading digits (HH MM), then the
  // seconds (`\d+(\.\d*)?`).
  if let Some(tm) = fields.get(1).copied()
    && tm.len() >= 6
    && tm
      .get(..6)
      .is_some_and(|s| s.iter().all(u8::is_ascii_digit))
  {
    // `tm.len() >= 6` guarantees these windows; `.get(..).unwrap_or_default()`
    // is byte-identical (the empty fallback is unreachable).
    t.hr = ascii_u32(tm.get(0..2).unwrap_or_default());
    t.min = ascii_u32(tm.get(2..4).unwrap_or_default());
    t.sec = tm
      .get(4..)
      .and_then(|s| core::str::from_utf8(s).ok())
      .map(ToString::to_string);
  }
  // `(\d+\.\d+)` lat / lon (QuickTimeStream.pl:1733; Type-7 `(\d*?\d{1,2}\.\d+)`
  // has the same digits-dot-digits acceptance set, :1952).
  if let Some(v) = fields.get(3).copied().and_then(nmea_decimal) {
    t.lat = Some(v);
  }
  if let Some(c) = fields.get(4).and_then(|f| ns_ref(f)) {
    t.lat_ref = Some(c);
  }
  if let Some(v) = fields.get(5).copied().and_then(nmea_decimal) {
    t.lon = Some(v);
  }
  if let Some(c) = fields.get(6).and_then(|f| ew_ref(f)) {
    t.lon_ref = Some(c);
  }
  // `(\d*\.?\d*)` spd / trk — `length $9`/`length $10` gate (only set when the
  // captured field is non-empty, QuickTimeStream.pl:1737-1738).
  if let Some(spd) = fields.get(7).copied()
    && !spd.is_empty()
    && let Some(v) = parse_ascii_f64(spd)
  {
    t.spd = Some(v * KNOTS_TO_KPH);
  }
  if let Some(trk) = fields.get(8).copied()
    && !trk.is_empty()
    && let Some(v) = parse_ascii_f64(trk)
  {
    t.trk = Some(v);
  }
  // `(\d{2})(\d{2})(\d+)` date — DD, MM, then the year (`\d+`, any length ≥1).
  if let Some(date) = fields.get(9).copied()
    && date.len() >= 5
    && date.iter().all(u8::is_ascii_digit)
  {
    // `date.len() >= 5` guarantees these windows; the empty fallback is
    // unreachable (byte-identical to `date[0..2]`/`[2..4]`/`[4..]`).
    t.day = ascii_u32(date.get(0..2).unwrap_or_default());
    t.mon = ascii_u32(date.get(2..4).unwrap_or_default());
    let yr_raw: i32 = ascii_u32(date.get(4..).unwrap_or_default()).unwrap_or(0) as i32;
    // QuickTimeStream.pl:1735 `yr = $13 + ($13 >= 70 ? 1900 : 2000)`.
    t.yr = Some(yr_raw + if yr_raw >= 70 { 1900 } else { 2000 });
  }
}

/// Parse an all-ASCII-digit byte slice as `u32` (NMEA field helper).
fn ascii_u32(b: &[u8]) -> Option<u32> {
  core::str::from_utf8(b).ok()?.parse().ok()
}

/// Parse an ASCII byte slice as `i32` (Type-18 year, QuickTimeStream.pl:2366).
fn ascii_i32(b: &[u8]) -> Option<i32> {
  core::str::from_utf8(b).ok()?.parse().ok()
}

/// Trim trailing NUL bytes (`$$dataPt =~ s/\0+$//`, QuickTimeStream.pl:2367).
fn trim_trailing_nuls(b: &[u8]) -> &[u8] {
  let mut end = b.len();
  // `end > 0` ⇒ `end - 1 < b.len()`, so `.get(end - 1)` is `Some` (byte-
  // identical to `b[end - 1]`).
  while end > 0 && b.get(end - 1) == Some(&0) {
    end -= 1;
  }
  // `end <= b.len()`, so `.get(..end)` is always `Some`.
  b.get(..end).unwrap_or(b)
}

/// Validate a string against `[-+]?\d+(\.\d+)?` (a signed-optional integer or
/// `int.frac` decimal — NOT exponent / `inf` / `nan` / leading-dot) and parse
/// it as `f64`. Used by the Type-18 KV value and as the basis for the bare
/// speed gate (QuickTimeStream.pl:2371/2373).
fn parse_signed_int_or_decimal(s: &str) -> Option<f64> {
  let b = s.as_bytes();
  // After a leading sign the slice is non-empty, so `.get(1..)` is `Some`.
  let rest = match b.first() {
    Some(b'+' | b'-') => b.get(1..).unwrap_or_default(),
    _ => b,
  };
  let int_end = rest.iter().take_while(|&&c| c.is_ascii_digit()).count();
  if int_end == 0 {
    return None; // `\d+` requires ≥1 int digit
  }
  // `int_end <= rest.len()`, so `.get(int_end..)` is always `Some`.
  let tail = rest.get(int_end..).unwrap_or_default();
  let ok = match tail.first() {
    None => true, // `\d+`
    // `tail` starts with `.`, so `.get(1..)` is `Some` — `\.\d+`.
    Some(b'.') => tail
      .get(1..)
      .is_some_and(|f| !f.is_empty() && f.iter().all(u8::is_ascii_digit)),
    Some(_) => false,
  };
  if !ok {
    return None;
  }
  s.parse().ok()
}

/// QuickTimeStream.pl:2371 `^([A-Z]):([-+]?\d+(\.\d+)?)$/i` — a single
/// ASCII-letter key (either case) and a signed-int-or-decimal value. Returns
/// `(value, uppercase_key_char)` or `None` if the token does not match the
/// whole pattern.
fn parse_xgody_kv(tok: &str) -> Option<(f64, char)> {
  let (k, v) = tok.split_once(':')?;
  let mut kc = k.chars();
  let ch = kc.next()?;
  if kc.next().is_some() || !ch.is_ascii_alphabetic() {
    return None; // key must be exactly one ASCII letter
  }
  let num = parse_signed_int_or_decimal(v)?;
  // The Perl dispatch compares `$1` case-sensitively (`eq 'N'`, `eq 'x'`, …)
  // against specific letters; `/i` only governs the regex MATCH, not the later
  // `eq` tests. Preserve the original case so e.g. `n:..` matches none of the
  // `eq 'N'`/`eq 'S'`/… arms (it becomes an Unknown_n tag in bundled).
  Some((num, ch))
}

/// `^\d+\.\d+$` — unsigned digits-dot-digits only (the Type-18 bare-speed gate,
/// QuickTimeStream.pl:2373).
fn parse_plain_decimal(s: &str) -> Option<f64> {
  let (int, frac) = s.split_once('.')?;
  if int.is_empty() || frac.is_empty() {
    return None;
  }
  if !int.bytes().all(|c| c.is_ascii_digit()) || !frac.bytes().all(|c| c.is_ascii_digit()) {
    return None;
  }
  s.parse().ok()
}

/// Parse an ASCII byte slice as `f64` (for `(\d*\.?\d*)` spd/trk fields, where
/// the bundled `length $N` gate already excludes the empty case).
fn parse_ascii_f64(b: &[u8]) -> Option<f64> {
  core::str::from_utf8(b).ok()?.parse().ok()
}

/// `([NS])` — the field's first byte must be `N` or `S`.
fn ns_ref(field: &[u8]) -> Option<char> {
  match field.first() {
    Some(&c @ (b'N' | b'S')) => Some(c as char),
    _ => None,
  }
}

/// `([EW])` — the field's first byte must be `E` or `W`.
fn ew_ref(field: &[u8]) -> Option<char> {
  match field.first() {
    Some(&c @ (b'E' | b'W')) => Some(c as char),
    _ => None,
  }
}

/// Parse a `$XXGGA,…` NMEA sentence (RAW bytes, QuickTimeStream.pl:1740-1745):
/// extract altitude (field 9), and the time/lat/lon (fields 1-5) only when RMC
/// did not already set a year. GPSSatellites/GPSDOP are not GpsSample fields.
fn parse_nmea_gga(s: &[u8], t: &mut FreeGpsTags) {
  let fields = nmea_fields(s);
  // 0=$GGA 1=time 2=lat 3=N/S 4=lon 5=E/W 6=fix 7=numSat 8=HDOP 9=alt 10=units.
  // QuickTimeStream.pl:1740 — the bundled regex ends `…,(-?\d+\.?\d*)?,M?`: the
  // altitude capture is followed by a LITERAL comma then an optional `M`. The
  // regex is NOT anchored at the end, so the comma after the altitude must be
  // present for ANY field to be captured — i.e. the units field (index 10) must
  // EXIST. (A GGA whose altitude field is the last one, with no trailing comma,
  // fails the whole regex → nothing copied; verified vs Perl.) So gate on ≥ 11
  // fields. NOTE: `M?` is zero-width-optional, so the units field's CONTENT is
  // unconstrained — `M`, ``, `F`, `ft` all match (also verified vs Perl); do
  // NOT reject a non-`M` units field.
  if fields.len() < 11 {
    return;
  }
  // QuickTimeStream.pl:1740 — the bundled regex gates the GGA fix-quality
  // field (field 6) with `[1-6]?` immediately followed by a literal comma: a
  // no-fix `0` (or `7`) is not in `[1-6]`, so `[1-6]?` matches zero-width and
  // the following `,` then fails against the digit → the whole GGA regex fails
  // → nothing is copied (not even the altitude). Mirror that by rejecting any
  // non-empty fix quality outside 1..6 (verified vs Perl: fix `0`/`7` → no
  // match, `1`/empty → match).
  if let Some(fix) = fields.get(6).copied()
    && !fix.is_empty()
    && !matches!(fix, b"1" | b"2" | b"3" | b"4" | b"5" | b"6")
  {
    return;
  }
  // `($hr,$min,$sec,$lat,$latRef,$lon,$lonRef) = (…) unless defined $yr`.
  if t.yr.is_none() {
    if let Some(tm) = fields.get(1).copied()
      && tm.len() >= 6
      && tm
        .get(..6)
        .is_some_and(|s| s.iter().all(u8::is_ascii_digit))
    {
      // `tm.len() >= 6` guarantees these windows (empty fallback unreachable).
      t.hr = ascii_u32(tm.get(0..2).unwrap_or_default());
      t.min = ascii_u32(tm.get(2..4).unwrap_or_default());
      t.sec = tm
        .get(4..)
        .and_then(|s| core::str::from_utf8(s).ok())
        .map(ToString::to_string);
    }
    // `(\d+\.\d+)` lat / lon (QuickTimeStream.pl:1740).
    if let Some(v) = fields.get(2).copied().and_then(nmea_decimal) {
      t.lat = Some(v);
    }
    if let Some(c) = fields.get(3).and_then(|f| ns_ref(f)) {
      t.lat_ref = Some(c);
    }
    if let Some(v) = fields.get(4).copied().and_then(nmea_decimal) {
      t.lon = Some(v);
    }
    if let Some(c) = fields.get(5).and_then(|f| ew_ref(f)) {
      t.lon_ref = Some(c);
    }
  }
  // `$alt = $11` (field 9) — the `(-?\d+\.?\d*)` shape (always taken when the
  // regex matched). Note: with field 9 empty the bundled capture is undef, so
  // `$alt` is undef — skip when empty.
  if let Some(v) = fields
    .get(9)
    .copied()
    .filter(|f| !f.is_empty())
    .and_then(nmea_signed_decimal)
  {
    t.alt = Some(v);
  }
}

// ───────────────────── GPSType 3/4: Kenwood / ViofoA119v3 / E-ACE B44 ──────

/// Detection state for GPSType 3/4 — the matched offset (37 or 85) and the
/// two ref-direction chars.
type Type34Match = (usize, char, char);

/// Detect GPSType 3/4 (QuickTimeStream.pl:1752-1841). The pattern is
/// `^(.{37}|.{85})\0\0\0A([NS])([EW])\0` — either offset 37 (regular) or 85
/// (Kenwood DRV-A510W with a 48-byte extra header).
///
/// Returns: `((kw_extra_offset, lat_ref, lon_ref), payload_slice)`.
fn detect_type3_4(data: &[u8]) -> Option<(Type34Match, &[u8])> {
  for &candidate in &[37usize, 85] {
    if data.len() >= candidate + 8
      && data.get(candidate..candidate + 4) == Some(&[0, 0, 0, b'A'])
      && matches!(data.get(candidate + 4), Some(&b'N' | &b'S'))
      && matches!(data.get(candidate + 5), Some(&b'E' | &b'W'))
      && data.get(candidate + 6) == Some(&0)
    {
      // The `matches!` arms above already proved these two bytes exist, so
      // the `unwrap_or(0)` fallback is unreachable (byte-identical).
      let lat_ref = data.get(candidate + 4).copied().unwrap_or(0) as char;
      let lon_ref = data.get(candidate + 5).copied().unwrap_or(0) as char;
      let payload = if candidate == 85 {
        // QuickTimeStream.pl:1764 `$$dataPt = substr($$dataPt, 48)`. The
        // `candidate + 8` length guard (candidate == 85) proves `len > 48`.
        data.get(48..).unwrap_or_default()
      } else {
        data
      };
      return Some(((candidate, lat_ref, lon_ref), payload));
    }
  }
  None
}

/// `^[A-Za-z0-9+\/]{8,20}={0,2}$` over a NUL-trimmed slice
/// (QuickTimeStream.pl:1775) — an 8-to-20-char base64 alphabet prefix (alnum /
/// `+` / `/`, NO `=`) optionally followed by a 0-to-2 char `=` pad SUFFIX. `=`
/// must NOT appear inside the prefix, and the prefix is capped at 20 chars.
fn is_base64_shape(s: &[u8]) -> bool {
  // Strip a 0-2 char trailing `=` pad.
  let pad = s.iter().rev().take_while(|&&c| c == b'=').count();
  if pad > 2 {
    return false;
  }
  // `pad <= s.len()`, so `s.len() - pad <= s.len()` and `.get(..)` is `Some`.
  let prefix = s.get(..s.len() - pad).unwrap_or(s);
  (8..=20).contains(&prefix.len())
    && prefix
      .iter()
      .all(|&c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
}

/// Decode GPSType 3 (ViofoA119v3, QuickTimeStream.pl:1781-1804) and GPSType 4
/// (E-ACE B44, QuickTimeStream.pl:1808-1841). Both share the unpack header
/// (`hr/min/sec/yr/mon/day` at offset 0x10, six int32u).
fn decode_type3_4(
  data: &[u8],
  _kw_off: usize,
  lat_ref: char,
  lon_ref: char,
  out: &mut QuickTimeStreamMeta,
) {
  if data.len() < 0x40 {
    return;
  }
  let mut t = FreeGpsTags::new();
  t.lat_ref = Some(lat_ref);
  t.lon_ref = Some(lon_ref);
  // QuickTimeStream.pl:1767 — unpack('x16V6').
  let hr = le_u32(data, 0x10).unwrap_or(0);
  let min = le_u32(data, 0x14).unwrap_or(0);
  let sec = le_u32(data, 0x18).unwrap_or(0);
  let yr_raw = le_u32(data, 0x1c).unwrap_or(0);
  let mon = le_u32(data, 0x20).unwrap_or(0);
  let day = le_u32(data, 0x24).unwrap_or(0);

  // Distinguish Type 3 (binary) from Type 4 (base64/encrypted).
  // QuickTimeStream.pl:1770-1777 — check the 20-byte windows at 0x2c and 0x40
  // for base64 / `\d+\.\d+` shapes.
  let len_ok = data.len() >= 0x78;
  let mut not_enc = !len_ok;
  let mut not_str = !len_ok;
  let mut lt_window: &[u8] = &[];
  let mut ln_window: &[u8] = &[];
  if len_ok {
    // `len_ok` is `data.len() >= 0x78`, and `0x54 <= 0x78`, so these windows
    // are in range (the empty fallback is unreachable, byte-identical).
    lt_window = data.get(0x2c..0x40).unwrap_or_default();
    ln_window = data.get(0x40..0x54).unwrap_or_default();
    for w in [lt_window, ln_window] {
      let trimmed = w.split(|&b| b == 0).next().unwrap_or(&[]);
      // QuickTimeStream.pl:1775 `/^[A-Za-z0-9+\/]{8,20}={0,2}\0*$/`: an 8-20-char
      // base64 prefix (alnum / `+` / `/` — NO `=`), then a 0-2 char `=` SUFFIX,
      // then trailing NULs. The `=` may NOT appear mid-string, and the prefix is
      // capped at 20 (so the NUL-trimmed slice is 8..=22 chars).
      let is_b64 = is_base64_shape(trimmed);
      if !is_b64 {
        not_enc = true;
      }
      let trimmed_s = core::str::from_utf8(trimmed).unwrap_or("");
      let is_decimal = !trimmed_s.is_empty()
        && trimmed_s.contains('.')
        && trimmed_s.chars().all(|c| c.is_ascii_digit() || c == '.');
      if !is_decimal {
        not_str = true;
      }
    }
  }

  if not_enc && not_str {
    // ── Type 3 ── (binary lat/lon).
    // QuickTimeStream.pl:1786-1795 — when `$yr >= 2000` the Kenwood path
    // converts local time → UTC via Time::Local/gmtime (and warns). Under the
    // gen-golden config (TZ=UTC, QuickTimeUTC=1) that round-trip is an
    // identity, so the stored fields are the raw values either way.
    t.yr = Some(yr_raw as i32);
    t.mon = Some(mon);
    t.day = Some(day);
    t.hr = Some(hr);
    t.min = Some(min);
    t.sec = Some(alloc::format!("{sec:02}"));
    t.lat = le_f32(data, 0x2c);
    t.lon = le_f32(data, 0x30);
    t.spd = le_f32(data, 0x34).map(|v| v * KNOTS_TO_KPH);
    t.trk = le_f32(data, 0x38);
    // Accelerometer (QuickTimeStream.pl:1800-1804) at offset 60 (12 bytes).
    if data.len() >= 72 {
      // `data.len() >= 72` proves `data[60..72]` is in range (byte-identical).
      let tmp = data.get(60..72).unwrap_or_default();
      let all_zero = tmp.iter().all(|&b| b == 0);
      let counter = tmp == [1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0];
      if !all_zero && !counter {
        let raw: Vec<u32> = (0..3).filter_map(|i| le_u32(data, 60 + i * 4)).collect();
        if raw.len() == 3 {
          let vs = signed_div(&raw, 256.0);
          // `vs` has exactly 3 elements here (guarded above), so the slice
          // pattern always matches — byte-identical to `vs[0/1/2]`.
          if let [a, b, c] = vs.as_slice() {
            t.accel = Some((*a, *b, *c));
          }
        }
      }
    }
  } else {
    // ── Type 4 ── (E-ACE B44; lat/lon are base64-encoded & encrypted).
    t.yr = Some(yr_raw as i32);
    t.mon = Some(mon);
    t.day = Some(day);
    t.hr = Some(hr);
    t.min = Some(min);
    t.sec = Some(alloc::format!("{sec:02}"));
    t.spd = le_f32(data, 0x54).map(|v| v * KNOTS_TO_KPH);
    t.trk = le_f32(data, 0x58);
    // accel @ offset 92 — leave as raw (QuickTimeStream.pl:1821-1823).
    if data.len() >= 92 + 12 {
      let raw: Vec<u32> = (0..3).filter_map(|i| le_u32(data, 92 + i * 4)).collect();
      if raw.len() == 3 {
        let acc: Vec<f64> = raw.iter().map(|&v| f64::from(v as i32)).collect();
        // `acc` has exactly 3 elements here (guarded above), so the slice
        // pattern always matches — byte-identical to `acc[0/1/2]`.
        if let [a, b, c] = acc.as_slice() {
          t.accel = Some((*a, *b, *c));
        }
      }
    }
    if not_enc {
      // QuickTimeStream.pl:1824-1826 — unencrypted; lat/lon are decimal strings.
      let lt_trimmed = lt_window.split(|&b| b == 0).next().unwrap_or(&[]);
      let ln_trimmed = ln_window.split(|&b| b == 0).next().unwrap_or(&[]);
      if let Ok(v) = core::str::from_utf8(lt_trimmed)
        .unwrap_or("")
        .parse::<f64>()
      {
        t.lat = Some(v);
      }
      if let Ok(v) = core::str::from_utf8(ln_trimmed)
        .unwrap_or("")
        .parse::<f64>()
      {
        t.lon = Some(v);
      }
    } else {
      // DEFERRED in spirit: the Lucky-key decryption (QuickTimeStream.pl:1828-
      // 1840) goes through Image::ExifTool::XMP::DecodeBase64 → DecryptLucky
      // with 21 candidate keys. That's a self-contained RC4-style decoder; we
      // keep an in-house port below for completeness, then try each key.
      if let (Some(lat), Some(lon)) = lucky_decrypt_pair(lt_window, ln_window) {
        t.lat = Some(lat);
        t.lon = Some(lon);
      }
    }
  }
  t.emit(out);
}

/// `DecryptLucky` (QuickTimeStream.pl:1612-1630). RC4-style decryption used by
/// the E-ACE B44 "luckychip"/"customer #X gps" key family.
fn decrypt_lucky(input: &[u8], key: &[u8]) -> Vec<u8> {
  if key.is_empty() {
    return input.to_vec();
  }
  let mut s: [u32; 256] = core::array::from_fn(|i| i as u32);
  let mut j: u32 = 0;
  // Every index below is `< 256` (`i in 0..256`, `& 0xff` masks, `% key.len()`
  // with a non-empty key), so each `.get(..).copied().unwrap_or(0)` is
  // byte-identical to the raw RC4 indexing — the fallback never fires.
  for i in 0..256u32 {
    let si = s.get(i as usize).copied().unwrap_or(0);
    let ki = key.get((i as usize) % key.len()).copied().unwrap_or(0);
    j = (j + si + u32::from(ki)) & 0xff;
    s.swap(i as usize, j as usize);
  }
  let mut out = Vec::with_capacity(input.len());
  let (mut i, mut j) = (0u32, 0u32);
  for &b in input {
    i = i.wrapping_add(1) & 0xff;
    let si = s.get(i as usize).copied().unwrap_or(0);
    j = (j + si) & 0xff;
    s.swap(i as usize, j as usize);
    let si2 = s.get(i as usize).copied().unwrap_or(0);
    let sj2 = s.get(j as usize).copied().unwrap_or(0);
    let k = s.get(((si2 + sj2) & 0xff) as usize).copied().unwrap_or(0) as u8;
    out.push(b ^ k);
  }
  out
}

/// QuickTimeStream.pl:1611 keys + the 20-key sweep (1832-1838): try
/// `luckychip gps`, then `customer ## gps` with the `#` placeholders replaced
/// by `a..t` (20 candidates). Decode each base64-encoded slot first, then
/// decrypt with the candidate key, then validate the result as a positive
/// decimal lat/lon.
fn lucky_decrypt_pair(lt_b64: &[u8], ln_b64: &[u8]) -> (Option<f64>, Option<f64>) {
  let lt = base64_decode(lt_b64);
  let ln = base64_decode(ln_b64);
  if lt.is_empty() || ln.is_empty() {
    return (None, None);
  }
  let primary = b"luckychip gps";
  let try_key = |key: &[u8]| -> Option<(f64, f64)> {
    let lat_dec = decrypt_lucky(&lt, key);
    let lon_dec = decrypt_lucky(&ln, key);
    let lat_s = core::str::from_utf8(&lat_dec).ok()?;
    let lon_s = core::str::from_utf8(&lon_dec).ok()?;
    let lat = parse_strict_decimal(lat_s, 4)?;
    let lon = parse_strict_decimal(lon_s, 5)?;
    Some((lat, lon))
  };
  if let Some((lat, lon)) = try_key(primary) {
    return (Some(lat), Some(lon));
  }
  for ch in b'a'..=b't' {
    let mut key = b"customer ".to_vec();
    key.push(ch);
    key.push(ch);
    key.extend_from_slice(b" gps");
    if let Some((lat, lon)) = try_key(&key) {
      return (Some(lat), Some(lon));
    }
  }
  (None, None)
}

/// Validate a string as `\d{1,N}\.\d+` and parse it as `f64`.
fn parse_strict_decimal(s: &str, max_int_digits: usize) -> Option<f64> {
  let mut chars = s.chars();
  let first = chars.next()?;
  if !first.is_ascii_digit() {
    return None;
  }
  let mut int_digits = 1usize;
  let mut frac_started = false;
  let mut frac_digits = 0usize;
  for c in chars {
    if c == '.' {
      if frac_started {
        return None;
      }
      frac_started = true;
      continue;
    }
    if !c.is_ascii_digit() {
      return None;
    }
    if frac_started {
      frac_digits += 1;
    } else {
      int_digits += 1;
      if int_digits > max_int_digits {
        return None;
      }
    }
  }
  if !frac_started || frac_digits == 0 {
    return None;
  }
  s.parse().ok()
}

/// Tiny base64 decoder for the Lucky lat/lon slots — accepts A-Z/a-z/0-9/+,/
/// and pad `=`.
fn base64_decode(s: &[u8]) -> Vec<u8> {
  let mut out = Vec::new();
  let mut buf: u32 = 0;
  let mut bits = 0u32;
  for &c in s {
    let v: u32 = match c {
      b'A'..=b'Z' => u32::from(c - b'A'),
      b'a'..=b'z' => u32::from(c - b'a') + 26,
      b'0'..=b'9' => u32::from(c - b'0') + 52,
      b'+' => 62,
      b'/' => 63,
      b'=' => break,
      _ => continue, // skip NUL / whitespace
    };
    buf = (buf << 6) | v;
    bits += 6;
    if bits >= 8 {
      bits -= 8;
      out.push(((buf >> bits) & 0xff) as u8);
    }
  }
  out
}

// ─────────────────────────── GPSType 5: LigoGPS (DEFERRED) ─────────────────

/// Detect the LigoGPSINFO fingerprint at offsets 16/48/80.
/// QuickTimeStream.pl:1843 `/^(.{16}|.{48}|.{80})LIGOGPSINFO\0/s and
/// length($$dataPt) >= length($1) + 0x84`. Returns the matched offset
/// (`Some(16|48|80)`). The `length >= $1 + 0x84` guard is part of the bundled
/// condition: a too-short LIGOGPSINFO block must FALL THROUGH (not shadow the
/// later Type-6+ arms), so it is enforced here.
fn detect_type5_ligogps(data: &[u8]) -> Option<usize> {
  for &off in &[16, 48, 80] {
    let end = off + b"LIGOGPSINFO\0".len();
    // `data.get(off..end)` is `Some` exactly when `data.len() >= end`, so this
    // is byte-identical to the `data.len() >= end && &data[off..end] == …` pair.
    if data.get(off..end) == Some(b"LIGOGPSINFO\0".as_slice()) && data.len() >= off + 0x84 {
      return Some(off);
    }
  }
  None
}

// ─────────────────────────── GPSType 6: Akaso dashcam ──────────────────────

/// `decode_type6_akaso` (QuickTimeStream.pl:1906-1938).
fn decode_type6_akaso(data: &[u8], out: &mut QuickTimeStreamMeta) {
  let mut t = FreeGpsTags::new();
  // QuickTimeStream.pl:1926 — `($latRef, $lonRef) = ($1, $2)`; capture 1 is
  // at BLOCK offset 68, capture 2 at 76.
  t.lat_ref = data.get(68).map(|&b| b as char);
  t.lon_ref = data.get(76).map(|&b| b as char);

  // QuickTimeStream.pl:1927 — unpack 'x48V3x28V6'.
  let mut p = 0x30;
  let hr = le_u32(data, p).unwrap_or(0);
  let min = le_u32(data, p + 4).unwrap_or(0);
  let sec = le_u32(data, p + 8).unwrap_or(0);
  p += 12 + 28;
  let yr = le_u32(data, p).unwrap_or(0);
  let mon = le_u32(data, p + 4).unwrap_or(0);
  let day = le_u32(data, p + 8).unwrap_or(0);
  let acc_raw: Vec<u32> = (0..3)
    .filter_map(|i| le_u32(data, p + 12 + i * 4))
    .collect();

  t.yr = Some(yr as i32);
  t.mon = Some(mon);
  t.day = Some(day);
  t.hr = Some(hr);
  t.min = Some(min);
  t.sec = Some(alloc::format!("{sec:02}"));
  t.lat = le_f32(data, 0x40);
  t.lon = le_f32(data, 0x48);
  t.spd = le_f32(data, 0x50);
  t.trk = le_f32(data, 0x54);

  // QuickTimeStream.pl:1932-1937 — "x.xx" preamble flips track sign + drops accel.
  if data.get(16..20) == Some(b"x.xx") {
    if let Some(trk) = t.trk {
      let mut t2 = trk + 180.0;
      if t2 >= 360.0 {
        t2 -= 360.0;
      }
      t.trk = Some(t2);
    }
    t.accel = None;
  } else if acc_raw.len() == 3 {
    let vs = signed_div(&acc_raw, 1000.0);
    // `vs` has exactly 3 elements here (guarded above), so the slice
    // pattern always matches — byte-identical to `vs[0/1/2]`.
    if let [a, b, c] = vs.as_slice() {
      t.accel = Some((*a, *b, *c));
    }
  }
  t.emit(out);
}

// ───────────────────────── GPSType 7: "4W`b]S<" cipher ─────────────────────

/// `decode_type7_cipher` (QuickTimeStream.pl:1940-1959). Subtract 16 from each
/// byte (where ≥16), then parse as a `$GPRMC` NMEA sentence.
fn decode_type7_cipher(data: &[u8], out: &mut QuickTimeStreamMeta) {
  // QuickTimeStream.pl:1951 — `unpack('x60C80')`, subtract 16.
  if data.len() < 60 + 80 {
    return;
  }
  let mut decoded = Vec::with_capacity(80);
  // `skip(60).take(80)` reads exactly `data[60..60 + 80]` (the `data.len() <
  // 60 + 80` guard keeps that window in range) — byte-identical.
  for &b in data.iter().skip(60).take(80) {
    decoded.push(if b >= 16 { b - 16 } else { b });
  }
  // QuickTimeStream.pl:1952 matches `/[A-Z]{2}RMC,…/` over the DECIPHERED RAW
  // bytes (the `$_` buffer) — the decipher of the `4W`b]S<` signature yields a
  // leading `$GPRMC,` (`0x34-0x10 = '$'` …), so the whole buffer is one RMC
  // sentence. Parse the bytes directly (no UTF-8 round-trip, faithful to the
  // bundled byte-level match) — field 0 is the `$GPRMC` talker, field 1+ the
  // RMC fields.
  let mut t = FreeGpsTags::new();
  parse_nmea_rmc(&decoded, &mut t);
  t.emit(out);
}

// ────────────────── GPSType 8: Akaso V1 / Redtiger F7N (encrypted) ─────────

fn detect_type8(data: &[u8]) -> bool {
  // QuickTimeStream.pl:1961 `^.{64}[\x01-\x0c]\0{3}[\x01-\x1f]\0{3}A[NS][EW]\0{5}`
  // — the regex references bytes through offset 79, so 80 (0x50) bytes is the
  // true minimum. (Decode reads further via zero-filling `le_*`, like Perl.)
  if data.len() < 0x50 {
    return false;
  }
  // The `data.len() < 0x50` guard proves bytes 64..80 exist, so this 16-byte
  // window match is byte-identical to the per-byte `data[64..80]` reads; the
  // `else` returns the same `false` as the guard.
  let Some(
    &[
      m0,
      z0,
      z1,
      z2,
      m1,
      z3,
      z4,
      z5,
      lit_a,
      ns,
      ew,
      n0,
      n1,
      n2,
      n3,
      n4,
    ],
  ) = data.get(64..80)
  else {
    return false;
  };
  (0x01..=0x0c).contains(&m0)
    && [z0, z1, z2] == [0, 0, 0]
    && (0x01..=0x1f).contains(&m1)
    && [z3, z4, z5] == [0, 0, 0]
    && lit_a == b'A'
    && (ns == b'N' || ns == b'S')
    && (ew == b'E' || ew == b'W')
    && [n0, n1, n2, n3, n4] == [0, 0, 0, 0, 0]
}

/// `decode_type8_akaso_v1` (QuickTimeStream.pl:1961-1996).
fn decode_type8_akaso_v1(data: &[u8], out: &mut QuickTimeStreamMeta) {
  let mut t = FreeGpsTags::new();
  // QuickTimeStream.pl:1985 — unpack('x48V6a1a1a1x1').
  let hr = le_u32(data, 0x30).unwrap_or(0);
  let min = le_u32(data, 0x34).unwrap_or(0);
  let sec = le_u32(data, 0x38).unwrap_or(0);
  let yr = le_u32(data, 0x3c).unwrap_or(0);
  let mon = le_u32(data, 0x40).unwrap_or(0);
  let day = le_u32(data, 0x44).unwrap_or(0);
  // _stat = data[0x48] (unused in output)
  t.lat_ref = data.get(0x49).map(|&b| b as char);
  t.lon_ref = data.get(0x4a).map(|&b| b as char);

  t.yr = Some(yr as i32);
  t.mon = Some(mon);
  t.day = Some(day);
  t.hr = Some(hr);
  t.min = Some(min);
  t.sec = Some(alloc::format!("{sec:02}"));

  t.spd = le_f32(data, 0x60);
  // QuickTimeStream.pl:1992 `$trk = GetFloat($dataPt, 0x64) + 180` — a bare
  // `+180` with NO 360-wrap (unlike GPSType 6 at :1933-1934).
  t.trk = le_f32(data, 0x64).map(|v| v + 180.0);
  // QuickTimeStream.pl:1993 — GetDouble at 0x50 / 0x58 (encrypted; NC).
  t.lat = le_f64(data, 0x50);
  t.lon = le_f64(data, 0x58);
  // QuickTimeStream.pl:1995 — `$ddd = 1` (encrypted; don't ConvertLatLon).
  t.ddd = true;
  t.emit(out);
}

// ─────────────────── GPSType 10: Vantrue S1 / horsontech ───────────────────

/// `decode_type10_vantrue_s1` (QuickTimeStream.pl:2021-2045).
fn decode_type10_vantrue_s1(data: &[u8], out: &mut QuickTimeStreamMeta) {
  let mut t = FreeGpsTags::new();
  t.lat_ref = data.get(65).map(|&b| b as char);
  t.lon_ref = data.get(66).map(|&b| b as char);
  // QuickTimeStream.pl:2034 — unpack('x68V6x20V3').
  let yr = le_u32(data, 0x44).unwrap_or(0);
  let mon = le_u32(data, 0x48).unwrap_or(0);
  let day = le_u32(data, 0x4c).unwrap_or(0);
  let hr = le_u32(data, 0x50).unwrap_or(0);
  let min = le_u32(data, 0x54).unwrap_or(0);
  let sec = le_u32(data, 0x58).unwrap_or(0);
  let acc_raw: Vec<u32> = (0..3)
    .filter_map(|i| le_u32(data, 0x5c + 20 + i * 4))
    .collect();
  if (1..=12).contains(&mon) && (1..=31).contains(&day) {
    let vs = signed_div(&acc_raw, 1000.0);
    if vs.len() == 3 {
      // `vs` has exactly 3 elements here (guarded above), so the slice
      // pattern always matches — byte-identical to `vs[0/1/2]`.
      if let [a, b, c] = vs.as_slice() {
        t.accel = Some((*a, *b, *c));
      }
    }
    t.lon = le_f32(data, 0x5c);
    t.lat = le_f32(data, 0x60);
    t.spd = le_f32(data, 0x64).map(|v| v * KNOTS_TO_KPH);
    t.trk = le_f32(data, 0x68);
    t.alt = le_f32(data, 0x6c);
    t.yr = Some(yr as i32);
    t.mon = Some(mon);
    t.day = Some(day);
    t.hr = Some(hr);
    t.min = Some(min);
    t.sec = Some(alloc::format!("{sec:02}"));
  }
  t.emit(out);
}

// ───────────────────────── GPSType 11: ATC GPS ─────────────────────────────

/// `decode_type11_atc` (QuickTimeStream.pl:2047-2157). 52-byte encrypted
/// records starting at offset 0x30. Each record is decrypted in place using
/// two key bytes from within the record, then validated.
///
/// The ATC device rewrites its WHOLE ring buffer (30 records in PH's samples)
/// into every 0x8000-byte block, so emitting every valid record per block
/// would re-emit the same stale fixes repeatedly. ExifTool emits ONLY records
/// strictly newer than the most-recent one seen so far, using
/// `$$et{FreeGPS2}{Then}` (the last-emitted timestamp) and
/// `{RecentRecPos}` (the offset to resume from) carried across blocks
/// (QuickTimeStream.pl:2057-2156). The port mirrors that with [`FreeGpsState`].
fn decode_type11_atc(data: &[u8], state: &mut FreeGpsState, out: &mut QuickTimeStreamMeta) {
  // QuickTimeStream.pl:2057 `$then or $then = [ (0) x 6 ]`.
  let mut then = state.atc_then.unwrap_or([0; 6]);
  // `$foundNew` (QuickTimeStream.pl:2055) — reset per block.
  let mut found_new = false;
  // `$lastRecPos` (QuickTimeStream.pl:2055) — per-block; saved to
  // `RecentRecPos` at the end.
  let mut last_rec_pos: Option<usize> = None;
  // `$$et{FreeGPS2}{RecentRecPos}` from the previous block — used to skip
  // older records (cleared the moment we find a newer record in THIS block).
  let mut recent_rec_pos = state.atc_recent_rec_pos;

  // QuickTimeStream.pl:2071 `ATCRec: for ($recPos=0x30; $recPos+52 < $dirLen;
  // $recPos += 52)` — note the STRICT `<` (the trailing checksum/padding
  // bytes mean a record needs one byte of slack past it).
  let mut rec_pos = 0x30usize;
  while rec_pos + 52 < data.len() {
    let mut a = [0u8; 52];
    // The `while` guard proves `rec_pos + 52 <= data.len()`, so this `.get`
    // is always `Some`; the `else` break matches the guard turning false.
    let Some(rec_src) = data.get(rec_pos..rec_pos + 52) else {
      break;
    };
    a.copy_from_slice(rec_src);
    // QuickTimeStream.pl:2080-2082: two key bytes at 0x14 and 0x1c.
    let key1 = a[0x14];
    let key2 = a[0x1c];
    for b in &mut a[0..=0x14] {
      *b ^= key1;
    }
    for b in &mut a[0x18..=0x1b] {
      *b ^= key1;
    }
    a[0x1c] ^= key2;
    for b in &mut a[0x20..=0x32] {
      *b ^= key2;
    }
    // QuickTimeStream.pl:2085 `unpack 'x13C3x28vC2'` (then "H+1") for validation.
    let hr = u32::from(a[0x0d]).wrapping_add(1) & 0xff;
    let min = u32::from(a[0x0e]);
    let sec = u32::from(a[0x0f]);
    let yr = u32::from_le_bytes([a[0x2c], a[0x2d], 0, 0]);
    let mon = u32::from(a[0x2e]);
    let day = u32::from(a[0x2f]);
    // QuickTimeStream.pl:2086 `@now = unpack(...)`: order is (H,M,S,Y,m,d).
    let now = [hr, min, sec, yr, mon, day];
    // QuickTimeStream.pl:2088-2092 — validate against @dateMax; an invalid
    // record is skipped (`next ATCRec`).
    let mut valid = true;
    for (n, max) in now.iter().zip(DATE_MAX.iter()) {
      if *n > *max {
        valid = false;
        break;
      }
    }
    if !valid {
      rec_pos += 52;
      continue;
    }
    // QuickTimeStream.pl:2094-2098 — "look for next ATC record in temporal
    // sequence": compare (Y,m,d) then (H,M,S). `cmp` is the first non-equal
    // component's ordering of `now` vs `then`.
    let mut newer = false;
    let mut older = false;
    for &i in &[3usize, 4, 5, 0, 1, 2] {
      // `i < 6` and `now`/`then` are `[u32; 6]`, so both `.get`s are `Some`;
      // comparing the `Option`s is byte-identical to comparing `now[i]`/`then[i]`.
      if now.get(i) < then.get(i) {
        // QuickTimeStream.pl:2096-2097 — an OLDER record. If we already
        // emitted a newer record this block, stop the whole loop; otherwise
        // just skip this record.
        older = true;
        break;
      }
      if now.get(i) == then.get(i) {
        continue;
      }
      // QuickTimeStream.pl:2099 — a strictly NEWER record.
      newer = true;
      break;
    }
    if older && found_new {
      // QuickTimeStream.pl:2096 `last ATCRec if $foundNew` — we already
      // emitted a newer record this block and now hit an older one; stop.
      break;
    }
    if older || !newer {
      // Older-without-found-new (`last` the inner foreach) OR all-equal (the
      // `next` falling through the foreach): skip this record. Mirror the
      // bundled tail `$recPos = $recentRecPos if $recentRecPos and $recPos <
      // $recentRecPos;` (QuickTimeStream.pl:2155) followed by the `for`
      // increment `$recPos += 52` (QuickTimeStream.pl:2071).
      rec_pos = recent_rec_pos.filter(|&r| rec_pos < r).unwrap_or(rec_pos) + 52;
      continue;
    }

    // QuickTimeStream.pl:2123-2150 — emit the newer record.
    let mut sample = GpsSample::new();
    let trk_raw = i16::from_le_bytes([a[0x24], a[0x25]]) as i32;
    let mut trk = f64::from(trk_raw) / 100.0;
    if trk < 0.0 {
      trk += 360.0;
    }
    let lat = f64::from(i32::from_le_bytes([a[0x10], a[0x11], a[0x12], a[0x13]])) / 1e7;
    let lon = f64::from(i32::from_le_bytes([a[0x18], a[0x19], a[0x1a], a[0x1b]])) / 1e7;
    let spd_raw = f64::from(i32::from_le_bytes([a[0x20], a[0x21], a[0x22], a[0x23]])) / 100.0;
    let alt = f64::from(i32::from_le_bytes([a[0x28], a[0x29], a[0x2a], a[0x2b]])) / 1000.0;
    sample.set_date_time(Some(SmolStr::from(alloc::format!(
      "{yr:04}:{mon:02}:{day:02} {hr:02}:{min:02}:{sec:02}Z"
    ))));
    sample.set_latitude(Some(lat));
    sample.set_longitude(Some(lon));
    sample.set_speed_kph(Some(spd_raw * MPS_TO_KPH));
    sample.set_track(Some(trk));
    sample.set_altitude_m(Some(alt));
    out.push_gps_sample(sample);
    // QuickTimeStream.pl:2148-2154 — remember this as the most-recent record,
    // clear the resume hint (we found something newer here), and `last` the
    // inner foreach (advance to the next 52-byte record).
    then = now;
    last_rec_pos = Some(rec_pos);
    found_new = true;
    recent_rec_pos = None;
    rec_pos += 52;
  }

  // QuickTimeStream.pl:2156 `$$et{FreeGPS2}{RecentRecPos} = $lastRecPos`. When
  // no newer record was found this block, ExifTool stores `undef`, so the next
  // block starts scanning from the top again (only `Then` gates it).
  state.atc_then = Some(then);
  state.atc_recent_rec_pos = last_rec_pos;
}

// ────────────── GPSType 12: 80-byte double lat/lon variant ─────────────────

/// `decode_type12_double` (QuickTimeStream.pl:2159-2188).
fn decode_type12_double(data: &[u8], out: &mut QuickTimeStreamMeta) {
  if data.len() < 0x88 {
    return;
  }
  let mut t = FreeGpsTags::new();
  // QuickTimeStream.pl:2173/2175 data-layout: `0x48` = int32u latitude-ref
  // ('N'/'S'), `0x58` = int32u longitude-ref ('E'/'W'). The detection regex
  // (:2159) captures the same two bytes (`[NS]`@0x48, `[EW]`@0x58).
  t.lat_ref = data.get(0x48).map(|&b| b as char);
  t.lon_ref = data.get(0x58).map(|&b| b as char);
  // QuickTimeStream.pl:2183 — unpack 'x48V3x52V6'.
  let hr = le_u32(data, 0x30).unwrap_or(0);
  let min = le_u32(data, 0x34).unwrap_or(0);
  let sec = le_u32(data, 0x38).unwrap_or(0);
  let yr = le_u32(data, 0x70).unwrap_or(0);
  let mon = le_u32(data, 0x74).unwrap_or(0);
  let day = le_u32(data, 0x78).unwrap_or(0);
  let acc_raw: Vec<u32> = (0..3).filter_map(|i| le_u32(data, 0x7c + i * 4)).collect();
  let vs = signed_div(&acc_raw, 1000.0);
  if vs.len() == 3 {
    // `vs` has exactly 3 elements here (guarded above), so the slice
    // pattern always matches — byte-identical to `vs[0/1/2]`.
    if let [a, b, c] = vs.as_slice() {
      t.accel = Some((*a, *b, *c));
    }
  }
  t.yr = Some(yr as i32);
  t.mon = Some(mon);
  t.day = Some(day);
  t.hr = Some(hr);
  t.min = Some(min);
  t.sec = Some(alloc::format!("{sec:02}"));
  t.lat = le_f64(data, 0x40);
  t.lon = le_f64(data, 0x50);
  t.spd = le_f64(data, 0x60).map(|v| v * KNOTS_TO_KPH);
  t.trk = le_f64(data, 0x68);
  t.emit(out);
}

// ───────────────────────── GPSType 13: INNOVV MP4 ──────────────────────────

/// `decode_type13_innovv` (QuickTimeStream.pl:2190-2214). Multiple records of
/// `A[NS][EW]\0 .{28}` (32-byte each, lat/lon as little-endian float32).
fn decode_type13_innovv(data: &[u8], out: &mut QuickTimeStreamMeta) {
  let mut pos = 0usize;
  while pos + 32 <= data.len() {
    // The `while` guard proves `pos + 4 <= pos + 32 <= data.len()`, so this
    // 4-byte window always matches; binding it avoids re-reading `data[pos+1]`
    // / `data[pos+2]` below (byte-identical).
    let Some(&[a, ns, ew, z]) = data.get(pos..pos + 4) else {
      break;
    };
    if a == b'A' && (ns == b'N' || ns == b'S') && (ew == b'E' || ew == b'W') && z == 0 {
      let lat = le_f32(data, pos + 4).map(f64::abs).unwrap_or(0.0);
      let lon = le_f32(data, pos + 8).map(f64::abs).unwrap_or(0.0);
      let spd = le_f32(data, pos + 12).unwrap_or(0.0) * KNOTS_TO_KPH;
      let trk = le_f32(data, pos + 16).unwrap_or(0.0);
      let acc_raw: Vec<u32> = (0..3)
        .filter_map(|i| le_u32(data, pos + 20 + i * 4))
        .collect();
      let acc: Vec<f64> = acc_raw.iter().map(|&v| f64::from(v as i32)).collect();
      let lat_c = convert_lat_lon(lat);
      let lon_c = convert_lat_lon(lon);
      let lat_signed = if ns == b'S' { -lat_c } else { lat_c };
      let lon_signed = if ew == b'W' { -lon_c } else { lon_c };
      let mut sample = GpsSample::new();
      sample.set_latitude(Some(lat_signed));
      sample.set_longitude(Some(lon_signed));
      sample.set_speed_kph(Some(spd));
      sample.set_track(Some(trk));
      if acc.len() == 3 {
        if let [a, b, c] = acc.as_slice() {
          sample.set_accelerometer(Some(SmolStr::from(join3(*a, *b, *c))));
        }
      }
      out.push_gps_sample(sample);
      pos += 32;
    } else {
      pos += 1;
    }
  }
}

// ─────────────────── GPSType 14: XBHT motorcycle dashcam ───────────────────

fn detect_type14(data: &[u8]) -> bool {
  // QuickTimeStream.pl:2216 `^.{20}[\0-\x18][\0-\x3b]{2}[\0-\x09]A([NS])([EW])`.
  if data.len() < 27 {
    return false;
  }
  // The `data.len() < 27` guard proves bytes 20..27 exist; matching that
  // 7-byte window is byte-identical to the per-byte `data[20..27]` reads.
  let Some(&[b20, b21, b22, b23, lit_a, ns, ew]) = data.get(20..27) else {
    return false;
  };
  b20 <= 0x18
    && b21 <= 0x3b
    && b22 <= 0x3b
    && b23 <= 0x09
    && lit_a == b'A'
    && (ns == b'N' || ns == b'S')
    && (ew == b'E' || ew == b'W')
}

/// `decode_type14_xbht` (QuickTimeStream.pl:2216-2238). Records match
/// `(.{7}[\0-\x09]A[NS][EW].{25})` = 36 bytes wide (the trailing `.{25}` is
/// part of the record even though the unpack only reads through the speed at
/// offset 28-29).
fn decode_type14_xbht(data: &[u8], out: &mut QuickTimeStreamMeta) {
  const REC_LEN: usize = 36;
  let mut pos = 0usize;
  while pos + REC_LEN <= data.len() {
    // Find the next `.{7}[\0-\x09]A[NS][EW].{25}` record.
    // QuickTimeStream.pl:2225 — `(.{7}[\0-\x09]A[NS][EW].{25})`. The record
    // starts 8 bytes before `A`.
    let rec_start = pos;
    // The `while` guard proves `rec_start + REC_LEN <= data.len()`, so this
    // window is always a full 36-byte array; binding it as `&[u8; 36]` lets the
    // constant indices below stay (in-bounds const array indexing isn't linted).
    let Some(rec) = data
      .get(rec_start..rec_start + REC_LEN)
      .and_then(|s| <&[u8; REC_LEN]>::try_from(s).ok())
    else {
      break;
    };
    if rec[7] <= 0x09
      && rec[8] == b'A'
      && (rec[9] == b'N' || rec[9] == b'S')
      && (rec[10] == b'E' || rec[10] == b'W')
    {
      // QuickTimeStream.pl:2227 `unpack('xC7xCCx5VVx4v', $dat)`:
      // skip 1 byte, then 7 C (yr,mon,day,hr,min,sec,ss),
      // skip 1, then 2 C (lat_ref, lon_ref),
      // skip 5, then 2 V (lat, lon),
      // skip 4, then 1 v (spd).
      let yr_b = rec[1];
      let mon = u32::from(rec[2]);
      let day = u32::from(rec[3]);
      let hr = u32::from(rec[4]);
      let min = u32::from(rec[5]);
      let sec_b = rec[6];
      let ss_b = rec[7];
      let lat_ref = rec[9] as char;
      let lon_ref = rec[10] as char;
      let lat = le_u32(rec, 16).unwrap_or(0);
      let lon = le_u32(rec, 20).unwrap_or(0);
      let spd = le_u16(rec, 28).unwrap_or(0);
      let yr = 2000 + i32::from(yr_b);
      let lat_f = f64::from(lat) / 1e4;
      let lon_f = f64::from(lon) / 1e4;
      let lat_c = convert_lat_lon(lat_f);
      let lon_c = convert_lat_lon(lon_f);
      let lat_signed = if lat_ref == 'S' { -lat_c } else { lat_c };
      let lon_signed = if lon_ref == 'W' { -lon_c } else { lon_c };
      let dt = alloc::format!("{yr:04}:{mon:02}:{day:02} {hr:02}:{min:02}:{sec_b:02}.{ss_b}");
      let mut sample = GpsSample::new();
      sample.set_date_time(Some(SmolStr::from(dt)));
      sample.set_latitude(Some(lat_signed));
      sample.set_longitude(Some(lon_signed));
      sample.set_speed_kph(Some(f64::from(spd)));
      out.push_gps_sample(sample);
      pos += REC_LEN;
    } else {
      pos += 1;
    }
  }
}

// ───────────────────────── GPSType 15: Vantrue N4 ──────────────────────────

/// `decode_type15_vantrue_n4` (QuickTimeStream.pl:2240-2263).
fn decode_type15_vantrue_n4(data: &[u8], out: &mut QuickTimeStreamMeta) {
  let mut t = FreeGpsTags::new();
  t.lat_ref = data.get(40).map(|&b| b as char);
  t.lon_ref = data.get(56).map(|&b| b as char);
  // QuickTimeStream.pl:2257 — unpack 'x16V3x52V3V3' (h/m/s @ off 16, then
  // skip 52, y/m/d, then accel int32s ×3).
  let hr = le_u32(data, 0x10).unwrap_or(0);
  let min = le_u32(data, 0x14).unwrap_or(0);
  let sec = le_u32(data, 0x18).unwrap_or(0);
  let yr = le_u32(data, 0x50).unwrap_or(0);
  let mon = le_u32(data, 0x54).unwrap_or(0);
  let day = le_u32(data, 0x58).unwrap_or(0);
  let acc_raw: Vec<u32> = (0..3).filter_map(|i| le_u32(data, 0x5c + i * 4)).collect();
  let vs = signed_div(&acc_raw, 1000.0);
  if vs.len() == 3 {
    // `vs` has exactly 3 elements here (guarded above), so the slice
    // pattern always matches — byte-identical to `vs[0/1/2]`.
    if let [a, b, c] = vs.as_slice() {
      t.accel = Some((*a, *b, *c));
    }
  }
  t.yr = Some(yr as i32);
  t.mon = Some(mon);
  t.day = Some(day);
  t.hr = Some(hr);
  t.min = Some(min);
  t.sec = Some(alloc::format!("{sec:02}"));
  t.lat = le_f64(data, 32).map(f64::abs);
  t.lon = le_f64(data, 48).map(f64::abs);
  t.spd = le_f64(data, 64).map(|v| v * KNOTS_TO_KPH);
  t.trk = le_f64(data, 72);
  t.emit(out);
}

// ────────────── GPSType 16/17/17b/17c: Viofo A119S binary ──────────────────

/// `decode_type16_17_viofo` (QuickTimeStream.pl:2265-2352).
///
/// `kodak_version` is the cross-module `$$et{KodakVersion}` global set by the
/// top-level Kodak `frea` atom (`'ver '` sub-atom, Kodak.pm:2987 — threaded
/// from [`crate::formats::quicktime`]). It selects the **Type-17b** Rexing
/// V1-4k lat/lon scaling (QuickTimeStream.pl:2323-2327) when it equals
/// `'3.01.054'`.
fn decode_type16_17_viofo(data: &[u8], kodak_version: Option<&str>, out: &mut QuickTimeStreamMeta) {
  let mut t = FreeGpsTags::new();
  // QuickTimeStream.pl:2296 — unpack 'x48V6a1a1a1x1V4'.
  let hr = le_u32(data, 0x30).unwrap_or(0);
  let min = le_u32(data, 0x34).unwrap_or(0);
  let sec = le_u32(data, 0x38).unwrap_or(0);
  let yr = le_u32(data, 0x3c).unwrap_or(0);
  let mon = le_u32(data, 0x40).unwrap_or(0);
  let day = le_u32(data, 0x44).unwrap_or(0);
  // _stat = data[0x48]
  t.lat_ref = data.get(0x49).map(|&b| b as char);
  t.lon_ref = data.get(0x4a).map(|&b| b as char);

  let is_iqs = data.get(16..19) == Some(b"IQS");
  if is_iqs {
    // ── Type 16 (IQS variant, QuickTimeStream.pl:2298-2309) ──
    t.ddd = true;
    t.lat = Some(
      le_u32(data, 0x4c)
        .map(|v| f64::from(v as i32).abs() / 1e7)
        .unwrap_or(0.0),
    );
    t.lon = Some(
      le_u32(data, 0x50)
        .map(|v| f64::from(v as i32).abs() / 1e7)
        .unwrap_or(0.0),
    );
    t.spd = le_i32(data, 0x54).map(|v| f64::from(v) / 100.0 * MPS_TO_KPH);
    t.alt = le_f32(data, 0x58).map(|v| v / 1000.0);
  } else {
    // ── Type 17 (Viofo A119S binary, QuickTimeStream.pl:2311-2342) ──
    let mut lat = le_f32(data, 0x4c).unwrap_or(0.0);
    let mut lon = le_f32(data, 0x50).unwrap_or(0.0);
    let mut spd = le_f32(data, 0x54).unwrap_or(0.0) * KNOTS_TO_KPH;
    let trk = le_f32(data, 0x58).unwrap_or(0.0);
    // The bundled dispatch order is 17b → 17c → default-17
    // (QuickTimeStream.pl:2323-2341).
    if kodak_version == Some("3.01.054") {
      // ── 17b (Rexing V1-4k, QuickTimeStream.pl:2323-2327) ──
      // Recognized by the Kodak `frea`-atom `KodakVersion` global; the dashcam
      // scales the raw lat/lon and the result is already decimal degrees
      // (`$ddd = 1`). The speed is NOT divided by `knotsToKph` here (unlike
      // 17c) — it stays the `GetFloat * knotsToKph` km/h value above.
      lat = (lat - 187.982_162_849_635) / 3.0;
      lon = (lon - 2199.198_737_154_95) / 2.0;
      t.ddd = true;
    } else if le_u32(data, 0) == Some(0x400000) && lat.abs() <= 90.0 && lon.abs() <= 180.0 {
      // ── 17c: Transcend Drive Body Camera 70 (QuickTimeStream.pl:2328-2338).
      // `Get32u($dataPt, 0)` is read little-endian (SetByteOrder('II') is in
      // effect): the dump `00 00 40 00` → LE 0x00400000.
      t.ddd = true;
      spd /= KNOTS_TO_KPH; // already km/h.
    }
    // ELSE: unscaled DDDMM.MMMM in lat/lon (default Type 17).
    t.lat = Some(lat);
    t.lon = Some(lon);
    t.spd = Some(spd);
    t.trk = Some(trk);
  }

  // QuickTimeStream.pl:2343-2351 — Transcend Driver Pro 230 double lat/lon
  // (and altitude at 0xa0).
  if data.len() >= 0xb0
    && let (Some(lat2), Some(lon2)) = (le_f64(data, 0x70), le_f64(data, 0x80))
    && let (Some(lat), Some(lon)) = (t.lat, t.lon)
    && (lat2 - lat).abs() < 0.001
    && (lon2 - lon).abs() < 0.001
  {
    t.lat = Some(lat2);
    t.lon = Some(lon2);
    t.alt = le_f64(data, 0xa0);
  }

  t.yr = Some(yr as i32);
  t.mon = Some(mon);
  t.day = Some(day);
  t.hr = Some(hr);
  t.min = Some(min);
  t.sec = Some(alloc::format!("{sec:02}"));
  t.emit(out);
}

// ─────────────────────── GPSType 18: XGODY 4K ASCII ────────────────────────

fn detect_type18(data: &[u8]) -> bool {
  // QuickTimeStream.pl:2354 — `^.{23}(\d{4})/(\d{2})/(\d{2}) (\d{2}):(\d{2}):(\d{2}) [N|S]`.
  // NOTE: the bundled char-class `[N|S]` is LITERAL — it accepts `N`, `|` AND
  // `S` (the `|` inside a `[...]` is just a member, not alternation), so the
  // 21st byte may be any of those three.
  let needed = 23 + 4 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 1;
  if data.len() < needed {
    return false;
  }
  // `data.get(23..needed)` is `Some` exactly when `data.len() >= needed` (the
  // guard above), byte-identical to `&data[23..23 + needed - 23]`.
  let Some(s) = data.get(23..needed) else {
    return false;
  };
  // Verify shape.
  s.iter().enumerate().all(|(i, &c)| match i {
    0..=3 | 5..=6 | 8..=9 | 11..=12 | 14..=15 | 17..=18 => c.is_ascii_digit(),
    4 | 7 => c == b'/',
    10 => c == b' ',
    13 | 16 => c == b':',
    19 => c == b' ',
    20 => c == b'N' || c == b'|' || c == b'S',
    _ => true,
  })
}

/// `decode_type18_xgody` (QuickTimeStream.pl:2354-2384). Parses the
/// `normal:YYYY/MM/DD HH:MM:SS N:lat W:lon spd_kmh x:.. y:.. z:.. A:trk H:..`
/// ASCII line.
fn decode_type18_xgody(data: &[u8], out: &mut QuickTimeStreamMeta) {
  let mut t = FreeGpsTags::new();
  t.ddd = true;
  // QuickTimeStream.pl:2354/2367/2368 index `$$dataPt` by BYTE offset (the
  // regex `^.{23}…` + `substr($$dataPt,43)`), NOT a decoded string. A real
  // Type-18 block has a non-ASCII box header (`00 00 00 a8 …`, :2358), so a
  // strict `from_utf8` of the whole block would blank the decode. Trim trailing
  // NULs on the bytes (`$$dataPt =~ s/\0+$//`) and index the ASCII regions
  // directly.
  let s = trim_trailing_nuls(data);
  // Date/time at offset 23 (QuickTimeStream.pl:2366 captures `$1..$6`).
  if let Some(dt) = s.get(23..23 + 19) {
    // `dt` is exactly 19 bytes here, so each `.get(..).unwrap_or_default()`
    // window is in range (byte-identical to `dt[0..4]` etc.).
    t.yr = ascii_i32(dt.get(0..4).unwrap_or_default());
    t.mon = ascii_u32(dt.get(5..7).unwrap_or_default());
    t.day = ascii_u32(dt.get(8..10).unwrap_or_default());
    t.hr = ascii_u32(dt.get(11..13).unwrap_or_default());
    t.min = ascii_u32(dt.get(14..16).unwrap_or_default());
    t.sec = dt
      .get(17..19)
      .and_then(|x| core::str::from_utf8(x).ok())
      .map(ToString::to_string);
  }
  // Field stream at offset 43 (`split ' ', substr($$dataPt,43)`).
  if s.len() > 43 {
    let mut acc: [Option<f64>; 3] = [None, None, None];
    let mut acc_idx = 0usize;
    // `s.len() > 43`, so `.get(43..)` is `Some` (byte-identical to `s[43..]`).
    for tok_b in s
      .get(43..)
      .unwrap_or_default()
      .split(|&c| c.is_ascii_whitespace())
      .filter(|t| !t.is_empty())
    {
      let Ok(tok) = core::str::from_utf8(tok_b) else {
        continue;
      };
      // QuickTimeStream.pl:2371 — `^([A-Z]):([-+]?\d+(\.\d+)?)$/i`: the key is a
      // SINGLE ASCII letter (the `/i` lets it be either case) and the value is a
      // signed-optional integer-or-decimal (NOT exponent/inf/nan/leading-dot).
      // A token failing this whole match falls through to the bare-speed gate.
      if let Some((num, ch)) = parse_xgody_kv(tok) {
        match ch {
          'N' | 'S' => {
            t.lat = Some(num);
            t.lat_ref = Some(ch);
          }
          'E' | 'W' => {
            t.lon = Some(num);
            t.lon_ref = Some(ch);
          }
          'x' | 'y' | 'z' if acc_idx < 3 => {
            // The `acc_idx < 3` guard proves the index is in range, so this
            // `.get_mut` is always `Some` (byte-identical to `acc[acc_idx]`).
            if let Some(slot) = acc.get_mut(acc_idx) {
              *slot = Some(num);
            }
            acc_idx += 1;
          }
          'A' => {
            t.trk = Some(num);
          }
          _ => {
            // 'H' / 'Unknown_X' — stored in ExifTool as Unknown_X.
            // Typed domain doesn't carry these; skip silently.
          }
        }
      } else if t.lon.is_some() && t.spd.is_none() {
        // QuickTimeStream.pl:2373 — `defined $lon and not defined $spd and
        // /^\d+\.\d+$/`: spd is the first bare DIGITS.DIGITS number after lon
        // (display km/h but raw knots; an int-only/exponent/sign token must NOT
        // match). Multiply by knotsToKph.
        if let Some(n) = parse_plain_decimal(tok) {
          t.spd = Some(n * KNOTS_TO_KPH);
        }
      }
    }
    if acc.iter().all(Option::is_some) {
      t.accel = Some((acc[0].unwrap(), acc[1].unwrap(), acc[2].unwrap()));
    }
  }
  t.emit(out);
}

// ──────────────────────── GPSType 19: 70mai A810 ───────────────────────────

/// `decode_type19_70mai` (QuickTimeStream.pl:2386-2401). The block carries NO
/// embedded date ("no timestamps in the samples I have", QuickTimeStream.pl:
/// 2389); lat/lon as int32s/1e5 at offsets 31/35.
///
/// QuickTimeStream.pl:2396 calls `SetGPSDateTime($et, $tagTbl,
/// $$dirInfo{SampleTime})` BEFORE reading lat/lon — synthesizing `GPSDateTime`
/// from the enclosing sample's decoding time (`sample_time`) plus the movie
/// `CreateDate` (`create_date_raw`) when BOTH exist (else no `GPSDateTime`).
/// `sample_time` is `Some` only on the `gps `-sample-table path; the
/// brute-force mdat scan passes `None`, so a real 70mai file (mdat-embedded,
/// per the bundled note) emits no `GPSDateTime`, matching ExifTool exactly.
fn decode_type19_70mai(
  data: &[u8],
  create_date_raw: Option<u64>,
  sample_time: Option<f64>,
  out: &mut QuickTimeStreamMeta,
) {
  if data.len() < 47 {
    return;
  }
  let mut t = FreeGpsTags::new();
  // QuickTimeStream.pl:2396 `SetGPSDateTime($et, $tagTbl, $$dirInfo{SampleTime})`.
  t.synth_date_time = synth_gps_date_time(create_date_raw, sample_time).map(SmolStr::from);
  // QuickTimeStream.pl:2386-2401 does NOT set `$ddd`, so the common tail
  // applies ConvertLatLon: the int32s/1e5 values are DDDMM.MMMM, not decimal
  // degrees (e.g. 5116.071 → 51°16.071′ → 51.2679°).
  // The `data.len() < 47` guard proves these reads are in range; the
  // bounds-checking `le_i32` returns `Some` here (`unwrap_or(0)` unreachable).
  let lat = le_i32(data, 31).unwrap_or(0);
  let lon = le_i32(data, 35).unwrap_or(0);
  let spd_raw = le_i32(data, 43).unwrap_or(0);
  t.lat = Some(f64::from(lat) / 1e5);
  t.lon = Some(f64::from(lon) / 1e5);
  t.spd = Some(f64::from(spd_raw)); // QuickTimeStream.pl:2399 — "seems to be km/h but NC".
  t.emit(out);
}

// ────────────── GPSType 20: Nextbase 512G (32-byte BE records) ─────────────

/// `decode_type20_nextbase512` (QuickTimeStream.pl:2403-2451). Big-endian
/// records starting at offset 0x32.
///
/// ExifTool's loop terminator (QuickTimeStream.pl:2449)
/// `last if $pos += 0x20 > length($$dataPt) - 0x1e` is subject to Perl operator
/// precedence: `>` binds tighter than `+=`, so it parses as
/// `last if ($pos += (0x20 > length - 0x1e))`. The boolean (0 or 1) is added to
/// `$pos` (always ≥ 0x32, i.e. truthy), so `last` ALWAYS fires after the first
/// record. We replicate that exactly: at most one record is emitted.
fn decode_type20_nextbase512(data: &[u8], out: &mut QuickTimeStreamMeta) {
  let pos = 0x32usize;
  if pos + 30 > data.len() {
    return;
  }
  let spd = be_u16(data, pos).unwrap_or(0);
  let trk_raw = be_u16(data, pos + 2).unwrap_or(0);
  let yr = u32::from(be_u16(data, pos + 4).unwrap_or(0));
  // `pos + 30 <= data.len()` proves these single-byte reads are in range; the
  // `unwrap_or(0)` fallback mirrors the adjacent `be_*(..).unwrap_or(0)` reads.
  let mon = u32::from(data.get(pos + 6).copied().unwrap_or(0));
  let day = u32::from(data.get(pos + 7).copied().unwrap_or(0));
  let hr = u32::from(data.get(pos + 8).copied().unwrap_or(0));
  let min = u32::from(data.get(pos + 9).copied().unwrap_or(0));
  let sec_raw = be_u16(data, pos + 10).unwrap_or(0);
  let lat_raw = be_u32(data, pos + 13).unwrap_or(0);
  let lon_raw = be_u32(data, pos + 17).unwrap_or(0);

  // QuickTimeStream.pl:2433 — validate by date/time bounds.
  if !(2000..=2200).contains(&yr) || !(1..=12).contains(&mon) || !(1..=31).contains(&day) {
    return;
  }
  if hr > 59 || min > 59 || sec_raw > 600 {
    return;
  }
  let lat = f64::from(lat_raw as i32) / 1e7;
  let lon = f64::from(lon_raw as i32) / 1e7;
  // QuickTimeStream.pl:2439-2441 — signed int16 ⇒ deg.
  let mut trk = f64::from(trk_raw as i16) / 100.0;
  if trk < 0.0 {
    trk += 360.0;
  }
  let sec_f = f64::from(sec_raw) / 10.0;
  let dt = alloc::format!("{yr:04}:{mon:02}:{day:02} {hr:02}:{min:02}:{sec_f:04.1}Z");
  let mut sample = GpsSample::new();
  sample.set_date_time(Some(SmolStr::from(dt)));
  sample.set_latitude(Some(lat));
  sample.set_longitude(Some(lon));
  sample.set_speed_kph(Some(f64::from(spd) / 100.0 * MPS_TO_KPH));
  sample.set_track(Some(trk));
  out.push_gps_sample(sample);
}

// ===========================================================================
// Dashcam-vendor `gpmd` variant handlers (QuickTimeStream.pl:181-212)
// ===========================================================================
//
// The `gpmd` MetaFormat re-dispatches by `Condition` to one of five variant
// process-procs. The Kingslim case routes to `ProcessFreeGPS`, whose
// GPSType-5 arm decodes the `LIGOGPSINFO\0`-at-offset-0x50 LigoGPS block
// (QuickTimeStream.pl:1843-1888) — exifast passes the raw sample to
// [`process_free_gps`] (no synthetic header). The remaining variants — Rove
// (ASCII XOR-text), FMAS (Vantrue N2S binary), Wolfbox (G900 / Redtiger F9 4K
// binary) — have dedicated process-procs in bundled which we port below.
//
// Dispatch site (this module's `dispatch_gpmd`) mirrors the bundled
// `QuickTimeStream.pl:181-212` Condition cascade exactly:
//   * `^.{21}\0\0\0A[NS][EW]` → ProcessFreeGPS (Kingslim D4 dashcam → LigoGPS)
//   * `^\0\0\xf2\xe1\xf0\xeeTT` → Process_text (Rove Stealth 4K encrypted)
//   * `^FMAS\0\0\0\0` → ProcessFMAS (Vantrue N2S)
//   * `^.{136}(0{16}[A-Z]{4}|https:\/\/www.redtiger\0)` → ProcessWolfbox
//   * (else) → GoPro GPMF
//
// All four self-contained branches funnel into the same [`GpsSample`]
// vector via [`FreeGpsTags::emit`]; the GoPro branch routes to the GoPro
// KLV walker.

/// The outcome of [`dispatch_gpmd`] — which arm of the bundled
/// QuickTimeStream.pl:181-212 `gpmd` Condition cascade matched. The walker uses
/// it to decide whether to open the per-sample `Doc<N>` ITSELF: a self-contained
/// variant matches its Condition (so ExifTool's `FoundSomething` opens a `Doc<N>`
/// and emits `SampleTime`/`SampleDuration`) EVEN WHEN the process-proc decodes
/// no fix, whereas Kingslim owns a SEPARATE LigoGPS `Doc<N>` opened lazily at
/// finalization (so the walker must NOT consume a second ordinal for it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpmdDispatch {
  /// No dashcam-variant Condition matched — the caller falls back to the GoPro
  /// GPMF parser (the no-`Condition` `gpmd_GoPro` arm, QuickTimeStream.pl:209).
  NoMatch,
  /// The Kingslim D4 arm (`^.{21}\0\0\0A[NS][EW]` → `ProcessFreeGPS` →
  /// LigoGPS). Its GPS lives in the LigoGPS block, which opens its OWN `Doc<N>`
  /// off the shared counter at finalization, so the walker must add NO `gpmd`
  /// doc/timing here.
  ///
  /// `ligo_emitted` is `true` iff `ProcessLigoGPS` actually decoded ≥1 record
  /// that reached LigoGPS.pm:266 — i.e. emitted a real fix. ExifTool's
  /// `delete $$et{SET_GROUP1}` lives at LigoGPS.pm:266, INSIDE `ParseLigoGPS`,
  /// AFTER the format-error (`:236`) and out-of-range (`:254`) `return`s — so a
  /// Kingslim sample whose Condition matched but whose `ProcessLigoGPS` produced
  /// nothing (every record bailed early) leaves `$$et{SET_GROUP1}` UNTOUCHED.
  /// The walker flips its `set_group1_cleared` flag only when this is `true`, so
  /// a no-output Kingslim match does NOT push the trak's following timing to
  /// `QuickTime` (it stays `Track<N>`).
  Kingslim {
    /// `true` iff `ProcessLigoGPS` decoded ≥1 real fix (reached LigoGPS.pm:266,
    /// the `delete $$et{SET_GROUP1}`); `false` for a Condition-match that
    /// produced no LigoGPS output (so `$$et{SET_GROUP1}` stays active).
    ligo_emitted: bool,
  },
  /// A self-contained dashcam variant — Rove (`Process_text`), FMAS
  /// (`ProcessFMAS`), or Wolfbox (`ProcessWolfbox`). Its Condition matched, so
  /// the walker opens ONE per-sample `Doc<N>` regardless of whether the
  /// process-proc appended a [`GpsSample`]: a produced fix is stamped with that
  /// doc + `Track<N>` + sample timing, and a matched-but-empty sample records a
  /// [`crate::metadata::GpmdTimingOnly`] marker carrying the same doc + timing.
  SelfContained,
}

/// Whether a `gpmd` sample matches the `gpmd_Kingslim` Condition
/// `^.{21}\0\0\0A[NS][EW]` (QuickTimeStream.pl:183) — the SAME leading-byte
/// signature the Kingslim arm of [`dispatch_gpmd`] keys on. The walker peeks
/// this BEFORE calling [`dispatch_gpmd`] so it can open the per-sample
/// `FoundSomething` timing `Doc<N>` AHEAD of the LigoGPS doc that
/// [`process_free_gps`] opens INSIDE the Kingslim arm: ExifTool's
/// `FoundSomething` (`ProcessSamples`:1567-1571) emits this sample's
/// `SampleTime`/`SampleDuration` the moment `GetTagInfo` matches the Condition,
/// BEFORE `ProcessFreeGPS` → `ProcessLigoGPS` runs (LigoGPS.pm:243), so a
/// Kingslim sample consumes TWO docs — the timing doc (lower ordinal) then the
/// LigoGPS doc (next). A const byte test, no decode.
#[inline]
#[must_use]
pub fn is_kingslim_gpmd(data: &[u8]) -> bool {
  data.len() >= 28
    && data.get(21..25) == Some(&[0, 0, 0, b'A'])
    && matches!(data.get(25), Some(&b'N' | &b'S'))
    && matches!(data.get(26), Some(&b'E' | &b'W'))
}

/// Dispatch a `gpmd` sample by the bundled QuickTimeStream.pl:181-212
/// Condition cascade. Returns the matched arm (see [`GpmdDispatch`]); the caller
/// falls back to the GoPro GPMF parser on [`GpmdDispatch::NoMatch`].
///
/// `data` is the raw sample bytes (no `freeGPS ` 16-byte header — these
/// arrive through the `stbl` sample tables, not the brute-force mdat scan).
///
/// `ligogps_out` is the walk-level LigoGPS accumulator: the Kingslim branch
/// routes to the GPSType-5 / `ProcessLigoGPS` arm of [`process_free_gps`]
/// (QuickTimeStream.pl:1843-1888), which writes there.
///
/// `free_gps_state` is the WALK-LEVEL `$$et{FoundEmbedded}` accumulator: the
/// Kingslim branch is the bundled `gpmd_Kingslim` process-proc `ProcessFreeGPS`,
/// which sets `$$et{FoundEmbedded} = 1` (QuickTimeStream.pl:1650) and so
/// SUPPRESSES the later brute-force `ScanMediaData` `mdat` scan
/// (QuickTimeStream.pl:3689). Threading the same state the moov walk later reads
/// (via [`FreeGpsState::found_embedded`]) makes that suppression propagate
/// faithfully — a real Kingslim file plus stray `freeGPS`-looking `mdat` bytes
/// no longer double-emits. The Rove / FMAS / Wolfbox process-procs
/// (`Process_text` / `ProcessFMAS` / `ProcessWolfbox`) do NOT set
/// `FoundEmbedded`, so they leave the state untouched.
pub fn dispatch_gpmd(
  data: &[u8],
  out: &mut QuickTimeStreamMeta,
  ligogps_out: &mut crate::metadata::LigoGpsMeta,
  free_gps_state: &mut FreeGpsState,
) -> GpmdDispatch {
  // gpmd_Kingslim — `^.{21}\0\0\0A[NS][EW]` (QuickTimeStream.pl:183).
  // A real Kingslim D4 `gpmd` sample carries `LIGOGPSINFO\0` at offset 0x50
  // (80) and a `####`/ASCII LigoGPS record at 0x50+0x14 (QuickTimeStream.pl
  // :1874-1888 — the `.{80}LIGOGPSINFO\0` alternative of the GPSType-5
  // regex). `ProcessFreeGPS` is the `gpmd_Kingslim` process-proc; its Type-5
  // arm dispatches `ProcessLigoGPS` at `DirStart=80` with scale 1 (line 1886
  // sets scale=3 only when `pos == 16`). The condition signature bytes
  // (`\0\0\0A[NS][EW]` at 21..27) only IDENTIFY the variant; the actual GPS
  // lives in the LigoGPS block (the `A`-at-offset-24 raw lat/lon is the
  // COMMENTED-OUT secondary, QuickTimeStream.pl:1890-1904). Pass the RAW
  // sample straight to `process_free_gps` so `detect_type5_ligogps` fires at
  // offset 80 and routes to `process_ligogps` via `ligogps_out`.
  if is_kingslim_gpmd(data) {
    // The gpmd Kingslim path carries no Kodak version and no enclosing sample
    // time (`create_date_raw`/`sample_time = None`). `process_free_gps` guards
    // `< 82` internally and sets `state.found_embedded = true`
    // (QuickTimeStream.pl:1650) once the block reaches the decoder. Threading the
    // WALK-LEVEL `free_gps_state` (not a throwaway) makes that `FoundEmbedded`
    // propagate to `extract_stream`, suppressing the brute-force `mdat` scan
    // (QuickTimeStream.pl:3689) — faithful to bundled's `gpmd_Kingslim`.
    //
    // Watermark the SHARED LigoGPS accumulator BEFORE the decode so we can flag
    // EXACTLY the records THIS `gpmd` sample produced as `gpmd`-dispatched (the
    // same accumulator also holds the movie-level `moov`-`gps `-box / `mdat`-scan
    // and the `udta`/trailer LigoGPS records — those must NOT be flagged). The
    // flag lets the QuickTime emitter interleave these records with the other
    // `gpmd`-dispatched sources (the SP3 `GpsOrigin::Gpmd` fixes + the matched-
    // empty `GpmdTimingOnly` markers) in ONE doc-ordered merge at their `Doc<N>`
    // walk position — the structural close of the gpmd-emission-order class — so a
    // mixed `gpmd` track (a Kingslim LigoGPS sample then a matched-empty FMAS
    // sample) emits `Doc1`-LIGO before `Doc2`-timing, not the reverse.
    let ligo_start = ligogps_out.sample_count();
    process_free_gps(
      data,
      None,
      None,
      None,
      free_gps_state,
      out,
      Some(ligogps_out),
    );
    ligogps_out.stamp_gpmd_dispatched_from(ligo_start);
    // ExifTool clears `$$et{SET_GROUP1}` at LigoGPS.pm:266 — INSIDE `ParseLigoGPS`,
    // only AFTER a record passes the format-error (`:236`) and out-of-range
    // (`:254`) guards and emits its fix. So the walker must flip its
    // `set_group1_cleared` flag only when `ProcessLigoGPS` actually produced ≥1
    // real fix (a Condition match with no LigoGPS output keeps `SET_GROUP1`
    // active). `emitted_real_fix_since` ignores the out-of-range suppressed
    // placeholders (which burn a `Doc<N>` but `return` BEFORE the `:266` delete).
    let ligo_emitted = ligogps_out.emitted_real_fix_since(ligo_start);
    return GpmdDispatch::Kingslim { ligo_emitted };
  }
  // gpmd_Rove — `^\0\0\xf2\xe1\xf0\xeeTT` (QuickTimeStream.pl:190).
  if data.get(0..8) == Some(&[0x00, 0x00, 0xf2, 0xe1, 0xf0, 0xee, 0x54, 0x54][..]) {
    // The `gpmd` dispatch is NOT the timed-text wrapper, so no `Text => $buff`.
    process_text(data, None, out);
    return GpmdDispatch::SelfContained;
  }
  // gpmd_FMAS — `^FMAS\0\0\0\0` (QuickTimeStream.pl:197).
  if data.get(0..8) == Some(b"FMAS\0\0\0\0".as_slice()) {
    process_fmas(data, out);
    return GpmdDispatch::SelfContained;
  }
  // gpmd_Wolfbox — `^.{136}(0{16}[A-Z]{4}|https:\/\/www.redtiger\0)`
  // (QuickTimeStream.pl:204).
  if detect_wolfbox(data) {
    process_wolfbox(data, out);
    return GpmdDispatch::SelfContained;
  }
  GpmdDispatch::NoMatch
}

/// Detect the Wolfbox / Redtiger Condition (QuickTimeStream.pl:204):
/// `^.{136}(0{16}[A-Z]{4}|https:\/\/www.redtiger\0)`.
fn detect_wolfbox(data: &[u8]) -> bool {
  let Some(tail) = data.get(136..) else {
    return false;
  };
  // Branch A: `0{16}[A-Z]{4}` — 16 ASCII '0' chars then 4 uppercase letters.
  if tail.get(0..16) == Some(&[b'0'; 16][..])
    && tail
      .get(16..20)
      .is_some_and(|s| s.iter().all(u8::is_ascii_uppercase))
  {
    return true;
  }
  // Branch B: `https://www.redtiger\0` (literal 21 bytes incl. NUL).
  if tail.get(0..21) == Some(b"https://www.redtiger\0".as_slice()) {
    return true;
  }
  false
}

// ─────────────────────────── timed-text wrapper ────────────────────────────

/// The `text` / `sbtl` timed-text sample wrapper (QuickTimeStream.pl:1467-1516):
/// `FoundSomething` (`ProcessSamples`:1473) has already opened the `Doc<N>` AND
/// emitted this sample's `SampleTime`/`SampleDuration` (the caller owns the
/// `open_doc`), UNCONDITIONALLY — BEFORE the `Process_text` decode, for EVERY
/// `text` sample. So this prepares `$buff` + the `Text => $buff` / `$handled`
/// decision and runs [`process_text`], then stamps the produced [`GpsSample`]
/// with the enclosing `Track<N>` origin + sample timing (`stamp_gps_gpmd_from`)
/// when a fix/Text row was emitted; when `Process_text` emitted NOTHING (a binary
/// / `\0[^\0]` sample whose `Text` is gated and which matches no sentence — e.g.
/// the Insta360 `.insv`'s 469 binary text samples), it records a
/// [`crate::metadata::GpmdTimingOnly`] marker carrying the SAME doc + `Track<N>` +
/// timing, so the `SampleTime`/`SampleDuration` `FoundSomething` already emitted
/// still surfaces under its `Doc<N>` at `-G3` (and joins the `-G1` cross-sample
/// min-doc scan). This is the `text`-path analogue of the `gpmd` matched-but-empty
/// marker (`ProcessSamples`:2235-2242).
///
/// Faithful skeleton of the wrapper: skip when the buffer starts `$BEGIN`; strip
/// a trailing `\0\0\0\x0cencd\0\0\x01\0` box; strip a leading 2-byte
/// length-prefix when it equals `size - 2` (the CanonPowerShotN100 / chapter
/// shape) — but `next if $size == 2` (a zero-length prefix) skips the `Text`
/// store + `Process_text` decode entirely; then store `Text => $buff` (and mark
/// handled) UNLESS the buffer holds a `\0[^\0]` byte pair. The E-PRANCE B47FS
/// cipher (`^\0 … \x0a$`) and the Garmin `PNDM` binary path (QuickTimeStream.pl:
/// 1486-1509) are separate camera variants, deferred (they need their own
/// fixtures).
///
/// PER-TEXT-SAMPLE-TIMING GUARANTEE: `FoundSomething` (:1461) opens the `Doc<N>`
/// + emits `SampleTime`/`SampleDuration` for EVERY `text` sample BEFORE any
/// decode, so this function has NO early-return escape hatch — every exit (the
/// size==2 `next`, the `$BEGIN` path, a plain-text store, a binary `\0[^\0]`
/// gate, a matched sentence, an empty `Process_text`) flows through the single
/// timing tail, which emits the sample's timing via either the produced GPS/Text
/// rows or a [`crate::metadata::GpmdTimingOnly`] marker. No `text` sample can
/// consume a `Doc<N>` without surfacing its timing.
pub fn process_timed_text(
  buff: &[u8],
  track_index: u32,
  doc: u32,
  sample_time: Option<f64>,
  sample_duration: Option<f64>,
  out: &mut QuickTimeStreamMeta,
) {
  let gps_start = out.gps_sample_count();
  // `unless ($buff =~ /^\$BEGIN/)` — a `$BEGIN…` sample is handled inside
  // `Process_text`'s `$TAG` loop, not by this wrapper preamble.
  let mut buf = buff;
  let mut wrapper_text: Option<SmolStr> = None;
  // ExifTool's `next if $size == 2` (QuickTimeStream.pl:1474) skips the `Text`
  // store + the whole `Process_text` decode for a zero-length length-prefixed
  // sample — but `FoundSomething` (:1461) ALREADY opened this sample's `Doc<N>`
  // + emitted its `SampleTime`/`SampleDuration` ABOVE the `unless` block, so the
  // `next` is NOT a "produce no timing" exit: the doc + timing survive. exifast
  // emits that timing in the unified tail below (the caller opened `doc`), so a
  // size==2 sample must SKIP the decode yet STILL fall through to the tail. Model
  // the `next` as "skip decode", never as an early return — that is the escape
  // hatch the per-text-sample-timing class fix closes.
  let mut skip_decode = false;
  if !buf.starts_with(b"$BEGIN") {
    // `$buff =~ s/\0\0\0\x0cencd\0\0\x01\0$//` — drop a trailing `encd` box.
    if let Some(stripped) =
      buf.strip_suffix(&[0, 0, 0, 0x0c, b'e', b'n', b'c', b'd', 0, 0, 0x01, 0][..])
    {
      buf = stripped;
    }
    // `if $size >= 2 and unpack('n',$buff) == $size - 2 { $buff = substr($buff,2) }`
    // — a 2-byte big-endian length prefix equal to the remaining length.
    if buf.len() >= 2
      && let (Some(hi), Some(lo)) = (buf.first(), buf.get(1))
    {
      let prefix = (u16::from(*hi) << 8) | u16::from(*lo);
      if usize::from(prefix) == buf.len() - 2 {
        if buf.len() == 2 {
          // `next if $size == 2` — the zero-length prefix. Skip storing `Text`
          // and skip `Process_text`, but fall through to the timing tail (the
          // doc + `SampleTime`/`SampleDuration` were already emitted upstream).
          skip_decode = true;
        } else {
          buf = buf.get(2..).unwrap_or(buf);
        }
      }
    }
    // `unless (defined $val or $buff =~ /\0[^\0]/) { HandleTag Text => $buff;
    // $handled = 1 }` — store the whole buffer as `Text` when it has no
    // NUL-followed-by-non-NUL pair (the E-PRANCE `$val` branch is deferred).
    if !skip_decode
      && !has_nul_then_nonnul(buf)
      && let Ok(text) = core::str::from_utf8(buf)
    {
      wrapper_text = Some(SmolStr::from(text));
    }
  }
  // `Process_text($et, \$buff, $tagTbl, $handled)` runs for every non-size==2
  // sample (the `$BEGIN` path reaches it too). A size==2 `next` bypasses it.
  if !skip_decode {
    process_text(buf, wrapper_text, out);
  }
  // ── Unified timing tail — the per-text-sample-timing guarantee ──────────────
  // EVERY exit of this function (size==2 skip, `$BEGIN`, plain-text stored,
  // binary `\0[^\0]` gated, sentence matched, `Process_text` empty) reaches here
  // with the caller's `doc` already opened. `FoundSomething` (QuickTimeStream.pl:
  // 1461) fires its `SampleTime`/`SampleDuration` for EVERY `text` sample BEFORE
  // any decode, so this sample's timing MUST surface under `doc` regardless of
  // whether a fix decoded. Emit it via EXACTLY ONE of: stamping the GPS/Text rows
  // `Process_text` produced, OR a `GpmdTimingOnly` marker when it produced none.
  // There is NO early return above this point — no text sample can consume a
  // `Doc<N>` without emitting its timing here.
  if out.gps_sample_count() > gps_start {
    // Stamp the enclosing `Track<N>` origin + the sample-table timing onto exactly
    // the fix/Text row this sample produced (`FoundSomething` already opened `doc`).
    // The `text` HandlerType trak runs no `ProcessLigoGPS`, so `$$et{SET_GROUP1} =
    // "Track$num"` is never `delete`d here — the fix always rides `Track<N>`
    // (`set_group1_active = true`).
    out.stamp_gps_gpmd_from(
      gps_start,
      track_index,
      doc,
      sample_time,
      sample_duration,
      true,
    );
  } else {
    // `Process_text` emitted nothing (a binary `\0[^\0]` sample whose `Text` is
    // gated and which matches no sentence). `FoundSomething` (:1473) still emitted
    // this sample's `SampleTime`/`SampleDuration` under `doc`, so record a
    // [`crate::metadata::GpmdTimingOnly`] marker carrying the doc + `Track<N>` +
    // timing — exactly the `gpmd` matched-but-empty path. Without it the consumed
    // `Doc<N>` would carry no `Track<N>` timing row even though the oracle has one
    // (the Insta360 `.insv`'s `Doc1..469:Track3:SampleTime`/`SampleDuration`).
    out.push_gpmd_timing_only(crate::metadata::GpmdTimingOnly::new());
    // The `text` handler path runs no `ProcessLigoGPS`, so `$$et{SET_GROUP1} =
    // "Track$num"` is never `delete`d here — the timing always rides `Track<N>`.
    out.stamp_gpmd_timing_only_last(track_index, doc, sample_time, sample_duration, true);
  }
}

/// `$buff =~ /\0[^\0]/` — true when a NUL byte is immediately followed by a
/// non-NUL byte (the "this is binary, don't store as Text" gate,
/// QuickTimeStream.pl:1510).
fn has_nul_then_nonnul(b: &[u8]) -> bool {
  b.windows(2).any(|w| matches!(w, [0, x] if *x != 0))
}

// ─────────────────────────── Process_text (Rove + general) ─────────────────

/// `Process_text` (QuickTimeStream.pl:1053-1295) — faithful port of the
/// ASCII NMEA / dashcam text-stream parser. Used for:
///   * `gpmd_Rove` — Rove Stealth 4K encrypted ASCII (XOR-0xAA payload at
///     offset 8) (QuickTimeStream.pl:190-194 → 1175-1211),
///   * timed-text samples (`text` / `sbtl` handler, QuickTimeStream.pl:1467-
///     1516),
///   * `camm` GPRMC fallback (QuickTimeStream.pl:1540-1546).
///
/// `data` is the sample bytes; the function inspects them for known
/// markers and emits a [`GpsSample`] via the common [`FreeGpsTags::emit`]
/// path when one or more known sentences match.
///
/// The raw-dispatch callers (Rove `gpmd`, `camm` `^X`) pass `wrapper_text =
/// None`; the timed-text wrapper ([`process_timed_text`]) passes the
/// `Text => $buff` value it already stored on the sample
/// (QuickTimeStream.pl:1512) so it survives even when no sentence matches. The
/// confirmed text-fallback variants (Mini 0806 / Roadhawk / Thinkware / DJI) all
/// carry NO leading-`$` `$TAG` records, so they are decoded by the POST-loop
/// branches below — the `unless $handled` in-loop `$tags{Text}` accumulation
/// (QuickTimeStream.pl:1070/1111) never fires for them and is not ported.
pub fn process_text(data: &[u8], wrapper_text: Option<SmolStr>, out: &mut QuickTimeStreamMeta) {
  let mut t = FreeGpsTags::new();
  if let Some(txt) = wrapper_text {
    t.text_extras.set_text(Some(txt));
  }
  let mut emitted_via_text = false;
  // QuickTimeStream.pl:1066 `while ($$dataPt =~ /\$(\w+)([^\$\0]*)/g)` —
  // scan ASCII `$TAG...` sequences (terminated by next `$` or NUL).
  let s = core::str::from_utf8(data).unwrap_or("");
  for (tag, dat) in DollarRecords::new(s) {
    // QuickTimeStream.pl:1068 — $XXRMC sentence.
    if is_two_upper(tag)
      && tag.ends_with("RMC")
      && let Some(parsed) = parse_text_rmc(dat)
    {
      t.hr = Some(parsed.hr);
      t.min = Some(parsed.min);
      t.sec = Some(parsed.sec);
      t.yr = Some(parsed.yr);
      t.mon = Some(parsed.mon);
      t.day = Some(parsed.day);
      t.lat = Some(parsed.lat);
      t.lon = Some(parsed.lon);
      t.ddd = true; // Process_text computes decimal degrees directly.
      if let Some(spd) = parsed.spd {
        t.spd = Some(spd);
      }
      if let Some(trk) = parsed.trk {
        t.trk = Some(trk);
      }
      emitted_via_text = true;
      continue;
    }
    // QuickTimeStream.pl:1084 — $XXGGA sentence.
    if is_two_upper(tag)
      && tag.ends_with("GGA")
      && let Some(parsed) = parse_text_gga(dat)
    {
      t.hr = Some(parsed.hr);
      t.min = Some(parsed.min);
      t.sec = Some(parsed.sec);
      t.lat = Some(parsed.lat);
      t.lon = Some(parsed.lon);
      t.ddd = true;
      if let Some(alt) = parsed.alt {
        t.alt = Some(alt);
      }
      emitted_via_text = true;
      continue;
    }
    // QuickTimeStream.pl:1094 — `$G:YYYY-MM-DD HH:MM:SS-[NS]LAT-[EW]LON-Sspd`.
    if tag == "G"
      && let Some((dt, lat, lon, spd)) = parse_text_g_sentence(dat)
    {
      t.yr = Some(dt.0);
      t.mon = Some(dt.1);
      t.day = Some(dt.2);
      t.hr = Some(dt.3);
      t.min = Some(dt.4);
      t.sec = Some(dt.5);
      t.lat = Some(lat);
      t.lon = Some(lon);
      t.ddd = true;
      t.spd = Some(spd);
      emitted_via_text = true;
    }
  }
  if emitted_via_text {
    t.emit(out);
    return;
  }
  // QuickTimeStream.pl:1175 — BlueSkySea / Ambarella A12 enciphered binary.
  // `^\0\0(..\xaa\xaa|\xf2\xe1\xf0\xee)` and length ≥ 282.
  if data.len() >= 282
    && data.get(0..2) == Some(&[0, 0][..])
    && (data.get(4..6) == Some(&[0xaa, 0xaa][..])
      || data.get(2..6) == Some(&[0xf2, 0xe1, 0xf0, 0xee][..]))
  {
    if decode_xor_aa_block(data, &mut t) {
      t.ddd = true;
      t.emit(out);
    }
    return;
  }
  // ── The post-loop text-fallback branches (QuickTimeStream.pl:1213-1294) ──
  // Reached only when the `$TAG` loop produced no fix AND the binary block did
  // not match — exactly Perl's flow (the `%tags`/binary `return`s above are the
  // early exits). `t` is otherwise empty here, so a fresh decode starts.

  // DJI telemetry (QuickTimeStream.pl:1213-1230):
  //   "F/3.5, SS 1000, ISO 100, EV 0, GPS (8.6499, 53.1665, 18), D 24.26m,
  //    H 6.00m, H.S 2.10m/s, V.S 0.00m/s"
  // The `GPS (lon, lat[, alt])` pair is `$1`=lon, `$2`=lat (the regex captures
  // lon FIRST), both raw decimal degrees.
  if let Some(dji) = parse_dji_telemetry(data) {
    // `$$et{CreateDateAtEnd} = 1` (QuickTimeStream.pl:1217) is a file-flag for a
    // creation-date-at-EOF hint; exifast's crafted fixture carries no such
    // trailer and ExifTool emits no extra tag from it here — no-op.
    t.lat = Some(dji.lat);
    t.lon = Some(dji.lon);
    t.ddd = true;
    if let Some(alt) = dji.alt {
      t.alt = Some(alt);
    }
    if let Some(spd) = dji.speed_kph {
      t.spd = Some(spd);
    }
    let ex = &mut t.text_extras;
    if let Some(d) = dji.distance {
      ex.set_distance(Some(d));
    }
    if let Some(vs) = dji.vertical_speed {
      ex.set_vertical_speed(Some(vs));
    }
    if let Some(fnum) = dji.fnumber {
      ex.set_fnumber(Some(fnum));
    }
    if let Some(et) = dji.exposure_time_s {
      ex.set_exposure_time_s(Some(et));
    }
    if let Some(ev) = dji.exposure_compensation {
      ex.set_exposure_compensation(Some(ev));
    }
    if let Some(iso) = dji.iso {
      ex.set_iso(Some(iso));
    }
    t.emit(out);
    return;
  }

  // Mini 0806 dashcam GPS (QuickTimeStream.pl:1232-1248):
  //   "A,270519,201555.000,3356.8925,N,08420.2071,W,000.0,331.0M,
  //    +01.84,-09.80,-00.61;"
  if let Some(mini) = parse_mini_0806(data) {
    t.yr = Some(mini.yr);
    t.mon = Some(mini.mon);
    t.day = Some(mini.day);
    t.hr = Some(mini.hr);
    t.min = Some(mini.min);
    t.sec = Some(mini.sec);
    if let Some((lat, lat_ref)) = mini.lat {
      t.lat = Some(lat);
      t.lat_ref = Some(lat_ref);
    }
    if let Some((lon, lon_ref)) = mini.lon {
      t.lon = Some(lon);
      t.lon_ref = Some(lon_ref);
    }
    // Mini lat/lon are computed in decimal degrees with the sign already applied
    // in the parse (`* ($ref eq 'S' ? -1 : 1)`), so ConvertLatLon is skipped and
    // the ref is NOT re-applied — clear the ref after capturing the sign.
    t.lat_ref = None;
    t.lon_ref = None;
    t.ddd = true;
    if let Some(alt) = mini.alt {
      t.alt = Some(alt);
    }
    if let Some(spd) = mini.speed {
      t.spd = Some(spd);
    }
    if let Some(acc) = mini.accel_str {
      t.accel_str = Some(acc);
    }
    t.emit(out);
    return;
  }

  // Roadhawk (QuickTimeStream.pl:1250-1269): the `\*[0-9A-F]{2}~$` fingerprint
  // selects a custom-substitution-encoded buffer that DECODES to an
  // `X..Y..Z..G..$GPRMC,..` string; the decoded `$GPRMC` is then parsed by the
  // NMEA-RMC branch below (Perl replaces `$$dataPt` and falls through).
  let mut nmea_buf: Option<Vec<u8>> = None;
  if let Some(decoded) = decode_roadhawk(data) {
    // `$buff =~ /X(.*?)Y(.*?)Z(.*?)G(.*?)\$/` (QuickTimeStream.pl:1264): the
    // decode "worked out" only when the X/Y/Z/G accelerometer prefix is present;
    // capture the 4-value Accelerometer and adopt the decoded buffer for the
    // NMEA-RMC parse (`$$dataPt = $buff`).
    if let Some(acc) = roadhawk_accel(&decoded) {
      t.accel_str = Some(acc);
      nmea_buf = Some(decoded);
    }
  }
  let nmea_data: &[u8] = nmea_buf.as_deref().unwrap_or(data);

  // Thinkware / general NMEA-RMC (QuickTimeStream.pl:1271-1284):
  //   "gsensori,4,512,-67,-12,100;GNRMC,161313.00,A,4529.87489,N,07337.01215,W,
  //    6.225,35.34,310819,,,A*52;CAR,0,0,0,..."
  // A `[A-Z]{2}RMC,..` (NO leading `$`) anywhere in the buffer, with day/mon/yr
  // sanity checks. Roadhawk's decoded `$GPRMC` matches here too.
  let mut matched = false;
  if let Some(rmc) = parse_thinkware_rmc(nmea_data) {
    t.yr = Some(rmc.yr);
    t.mon = Some(rmc.mon);
    t.day = Some(rmc.day);
    t.hr = Some(rmc.hr);
    t.min = Some(rmc.min);
    t.sec = Some(rmc.sec);
    t.lat = Some(rmc.lat);
    t.lon = Some(rmc.lon);
    t.ddd = true;
    if let Some(spd) = rmc.spd {
      t.spd = Some(spd);
    }
    if let Some(trk) = rmc.trk {
      t.trk = Some(trk);
    }
    matched = true;
  }
  // `gsensori` / `CAR` extraction (QuickTimeStream.pl:1285-1286) — applied to
  // the ORIGINAL buffer regardless of which branch matched.
  if let Some(gs) = extract_after_marker(data, b"gsensori,") {
    t.text_extras.set_gsensor(Some(gs));
    matched = true;
  }
  if let Some(car) = extract_after_marker(data, b"CAR,") {
    t.text_extras.set_car(Some(car));
    matched = true;
  }

  // `if (%tags) HandleTextTags` (QuickTimeStream.pl:1288): emit when any branch
  // populated a tag (the Roadhawk Accelerometer counts, as does a wrapper Text).
  if matched || t.accel_str.is_some() || !t.text_extras.is_empty() {
    t.emit(out);
  }
}

/// Iterate `$TAG..[^$\0]*` records inside an ASCII haystack
/// (QuickTimeStream.pl:1066 `/\$(\w+)([^\$\0]*)/g`). The match consumes
/// non-overlapping records left-to-right.
struct DollarRecords<'a> {
  bytes: &'a [u8],
  pos: usize,
}

impl<'a> DollarRecords<'a> {
  fn new(s: &'a str) -> Self {
    Self {
      bytes: s.as_bytes(),
      pos: 0,
    }
  }
}

impl<'a> Iterator for DollarRecords<'a> {
  type Item = (&'a str, &'a str);
  fn next(&mut self) -> Option<Self::Item> {
    while self.pos < self.bytes.len() {
      // Find next `$`.
      let rel = self
        .bytes
        .get(self.pos..)?
        .iter()
        .position(|&b| b == b'$')?;
      let tag_start = self.pos + rel + 1;
      // Read \w+ (alnum + underscore — bundled `\w` matches [A-Za-z0-9_]).
      let mut tag_end = tag_start;
      while self
        .bytes
        .get(tag_end)
        .is_some_and(|&b| b.is_ascii_alphanumeric() || b == b'_')
      {
        tag_end += 1;
      }
      if tag_end == tag_start {
        // `$` alone — skip past it.
        self.pos = tag_start;
        continue;
      }
      // Read `[^\$\0]*` — anything not `$` or NUL.
      let mut data_end = tag_end;
      while self
        .bytes
        .get(data_end)
        .is_some_and(|&b| b != b'$' && b != 0)
      {
        data_end += 1;
      }
      let tag = match self
        .bytes
        .get(tag_start..tag_end)
        .and_then(|s| core::str::from_utf8(s).ok())
      {
        Some(t) => t,
        None => {
          self.pos = data_end;
          continue;
        }
      };
      let dat = match self
        .bytes
        .get(tag_end..data_end)
        .and_then(|s| core::str::from_utf8(s).ok())
      {
        Some(d) => d,
        None => {
          self.pos = data_end;
          continue;
        }
      };
      self.pos = data_end;
      return Some((tag, dat));
    }
    None
  }
}

/// True for a two-upper-case-letter `\w+` prefix (`GP`, `GN`, `BD`, `GL` …).
fn is_two_upper(tag: &str) -> bool {
  let b = tag.as_bytes();
  b.first().is_some_and(u8::is_ascii_uppercase) && b.get(1).is_some_and(u8::is_ascii_uppercase)
}

/// Parsed XXRMC fields (QuickTimeStream.pl:1069).
struct TextRmc {
  hr: u32,
  min: u32,
  sec: String,
  yr: i32,
  mon: u32,
  day: u32,
  lat: f64,
  lon: f64,
  spd: Option<f64>,
  trk: Option<f64>,
}

/// Parse `,HHMMSS.sss,A?,LLMM.MMMM,N/S,LLLMM.MMMM,E/W,spd,trk,DDMMYY...`
/// matching QuickTimeStream.pl:1069 `^,(\d{2})(\d{2})(\d+(?:\.\d*)),A?,
/// (\d*?)(\d{1,2}\.\d+),([NS]),(\d*?)(\d{1,2}\.\d+),([EW]),(\d*\.?\d*),
/// (\d*\.?\d*),(\d{2})(\d{2})(\d+)`. Returns decimal-degrees lat/lon
/// (`(deg + min/60) * sign`).
fn parse_text_rmc(dat: &str) -> Option<TextRmc> {
  let b = dat.as_bytes();
  if b.first() != Some(&b',') {
    return None;
  }
  let mut p = 1usize;
  // 2-digit hr.
  let hr = parse_uint_fixed(b, &mut p, 2)?;
  let min = parse_uint_fixed(b, &mut p, 2)?;
  // Sec: \d+(\.\d*) — at least one int digit + REQUIRED dot + zero+ frac.
  let sec_start = p;
  while digit_at(b, p) {
    p += 1;
  }
  if p == sec_start || !byte_at_eq(b, p, b'.') {
    return None;
  }
  p += 1; // skip '.'
  while digit_at(b, p) {
    p += 1;
  }
  let sec = core::str::from_utf8(b.get(sec_start..p)?).ok()?.to_string();
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  // Optional 'A,'.
  if byte_at_eq(b, p, b'A') {
    p += 1;
    if !byte_at_eq(b, p, b',') {
      return None;
    }
    p += 1;
  }
  // lat: (\d*?)(\d{1,2}\.\d+) — the lazy prefix captures the degrees,
  // remainder is decimal-minutes.
  let (lat_deg, lat_min) = read_dddmm(b, &mut p)?;
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  // N/S
  let lat_sign = match b.get(p)? {
    b'N' => 1.0,
    b'S' => -1.0,
    _ => return None,
  };
  p += 1;
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  // lon
  let (lon_deg, lon_min) = read_dddmm(b, &mut p)?;
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  let lon_sign = match b.get(p)? {
    b'E' => 1.0,
    b'W' => -1.0,
    _ => return None,
  };
  p += 1;
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  // speed (knots) — \d*\.?\d*  → optional.
  let spd = parse_optional_decimal(b, &mut p)?;
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  let trk = parse_optional_decimal(b, &mut p)?;
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  // date: DDMMYY (the YY group is \d+ — greedy, but only first two are
  // used per QuickTimeStream.pl:1076 `$14 + ($14 >= 70 ? 1900 : 2000)`).
  let day = parse_uint_fixed(b, &mut p, 2)?;
  let mon = parse_uint_fixed(b, &mut p, 2)?;
  // Year: \d+ — read at least 2; the year-window heuristic uses the
  // 2-digit value.
  let yr_start = p;
  while digit_at(b, p) {
    p += 1;
  }
  if p - yr_start < 2 {
    return None;
  }
  let yr_2: i32 = core::str::from_utf8(b.get(yr_start..yr_start + 2)?)
    .ok()?
    .parse()
    .ok()?;
  let yr = yr_2 + if yr_2 >= 70 { 1900 } else { 2000 };
  Some(TextRmc {
    hr,
    min,
    sec,
    yr,
    mon,
    day,
    lat: (lat_deg + lat_min / 60.0) * lat_sign,
    lon: (lon_deg + lon_min / 60.0) * lon_sign,
    spd: spd.map(|v| v * KNOTS_TO_KPH),
    trk,
  })
}

/// Parsed XXGGA fields (QuickTimeStream.pl:1084).
struct TextGga {
  hr: u32,
  min: u32,
  sec: String,
  lat: f64,
  lon: f64,
  alt: Option<f64>,
}

fn parse_text_gga(dat: &str) -> Option<TextGga> {
  let b = dat.as_bytes();
  if b.first() != Some(&b',') {
    return None;
  }
  let mut p = 1usize;
  let hr = parse_uint_fixed(b, &mut p, 2)?;
  let min = parse_uint_fixed(b, &mut p, 2)?;
  // sec: \d+(\.\d*)?  — fractional is OPTIONAL for GGA.
  let sec_start = p;
  while digit_at(b, p) {
    p += 1;
  }
  if p == sec_start {
    return None;
  }
  if byte_at_eq(b, p, b'.') {
    p += 1;
    while digit_at(b, p) {
      p += 1;
    }
  }
  let sec = core::str::from_utf8(b.get(sec_start..p)?).ok()?.to_string();
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  let (lat_deg, lat_min) = read_dddmm(b, &mut p)?;
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  let lat_sign = match b.get(p)? {
    b'N' => 1.0,
    b'S' => -1.0,
    _ => return None,
  };
  p += 1;
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  let (lon_deg, lon_min) = read_dddmm(b, &mut p)?;
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  let lon_sign = match b.get(p)? {
    b'E' => 1.0,
    b'W' => -1.0,
    _ => return None,
  };
  p += 1;
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  // [1-6]?, then comma, then satellites/dop/altitude.
  if matches!(b.get(p), Some(b'1'..=b'6')) {
    p += 1;
  }
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  // satellites (digits, optional).
  while digit_at(b, p) {
    p += 1;
  }
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  // DOP (decimal, optional).
  while digit_at(b, p) || byte_at_eq(b, p, b'.') {
    p += 1;
  }
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  // altitude — `-?\d+(\.\d*)?` optional.
  let alt_start = p;
  if byte_at_eq(b, p, b'-') {
    p += 1;
  }
  let int_start = p;
  while digit_at(b, p) {
    p += 1;
  }
  let alt = if p > int_start {
    if byte_at_eq(b, p, b'.') {
      p += 1;
      while digit_at(b, p) {
        p += 1;
      }
    }
    core::str::from_utf8(b.get(alt_start..p)?)
      .ok()?
      .parse::<f64>()
      .ok()
  } else {
    None
  };
  Some(TextGga {
    hr,
    min,
    sec,
    lat: (lat_deg + lat_min / 60.0) * lat_sign,
    lon: (lon_deg + lon_min / 60.0) * lon_sign,
    alt,
  })
}

/// Parse a `$G:YYYY-MM-DD HH:MM:SS-[NS]LAT-[EW]LON-Sspd` sentence
/// (QuickTimeStream.pl:1094). Returns ((yr,mon,day,hr,min,sec), lat, lon, spd).
#[allow(clippy::type_complexity)]
fn parse_text_g_sentence(dat: &str) -> Option<((i32, u32, u32, u32, u32, String), f64, f64, f64)> {
  let b = dat.as_bytes();
  if b.first() != Some(&b':') {
    return None;
  }
  let mut p = 1usize;
  let yr = parse_uint_fixed(b, &mut p, 4)? as i32;
  if !byte_at_eq(b, p, b'-') {
    return None;
  }
  p += 1;
  let mon = parse_uint_fixed(b, &mut p, 2)?;
  if !byte_at_eq(b, p, b'-') {
    return None;
  }
  p += 1;
  let day = parse_uint_fixed(b, &mut p, 2)?;
  if !byte_at_eq(b, p, b' ') {
    return None;
  }
  p += 1;
  let hr = parse_uint_fixed(b, &mut p, 2)?;
  if !byte_at_eq(b, p, b':') {
    return None;
  }
  p += 1;
  let min = parse_uint_fixed(b, &mut p, 2)?;
  if !byte_at_eq(b, p, b':') {
    return None;
  }
  p += 1;
  let sec_start = p;
  let _ = parse_uint_fixed(b, &mut p, 2)?;
  let sec = core::str::from_utf8(b.get(sec_start..p)?).ok()?.to_string();
  if !byte_at_eq(b, p, b'-') {
    return None;
  }
  p += 1;
  let lat_sign = match b.get(p)? {
    b'N' => 1.0,
    b'S' => -1.0,
    _ => return None,
  };
  p += 1;
  let lat = parse_decimal(b, &mut p)?;
  if !byte_at_eq(b, p, b'-') {
    return None;
  }
  p += 1;
  let lon_sign = match b.get(p)? {
    b'E' => 1.0,
    b'W' => -1.0,
    _ => return None,
  };
  p += 1;
  let lon = parse_decimal(b, &mut p)?;
  if !byte_at_eq(b, p, b'-') {
    return None;
  }
  p += 1;
  if !byte_at_eq(b, p, b'S') {
    return None;
  }
  p += 1;
  // Speed = \d+ per bundled regex `S(\d+)` — integer.
  let spd_start = p;
  while digit_at(b, p) {
    p += 1;
  }
  if p == spd_start {
    return None;
  }
  let spd: f64 = core::str::from_utf8(b.get(spd_start..p)?)
    .ok()?
    .parse()
    .ok()?;
  Some((
    (yr, mon, day, hr, min, sec),
    lat * lat_sign,
    lon * lon_sign,
    spd,
  ))
}

/// Parse `(\d*?)(\d{1,2}\.\d+)` — the lazy-prefix + 1-2-digit degrees +
/// fractional-minutes scheme NMEA uses. Returns `(deg, min)`. The bundled
/// regex's `\d*?` lazy match means we extract the LAST 1-2 digits before the
/// `.` as the integer minutes part, and the remainder is degrees.
fn read_dddmm(b: &[u8], p: &mut usize) -> Option<(f64, f64)> {
  let start = *p;
  while digit_at(b, *p) {
    *p += 1;
  }
  if !byte_at_eq(b, *p, b'.') {
    return None;
  }
  let dot = *p;
  // After the dot, advance over fractional digits.
  *p += 1;
  while digit_at(b, *p) {
    *p += 1;
  }
  // Integer part = `b[start..dot]`; \d{1,2} are the minutes integer.
  let int_part = b.get(start..dot)?;
  if int_part.is_empty() {
    return None;
  }
  // Minutes integer is the LAST 1-2 chars; degrees prefix is the rest.
  // `\d{1,2}` — bundled is greedy here: match as many as possible up to 2.
  let take = int_part.len().min(2);
  let deg_str = int_part.get(..int_part.len() - take)?;
  let min_int = int_part.get(int_part.len() - take..)?;
  let frac = b.get(dot..*p)?; // includes the dot
  let deg = if deg_str.is_empty() {
    0.0
  } else {
    core::str::from_utf8(deg_str).ok()?.parse::<f64>().ok()?
  };
  let mut min_s: String = core::str::from_utf8(min_int).ok()?.into();
  min_s.push_str(core::str::from_utf8(frac).ok()?);
  let min: f64 = min_s.parse().ok()?;
  Some((deg, min))
}

/// `true` when the byte at `p` exists and is an ASCII digit (the checked form
/// of `p < b.len() && b[p].is_ascii_digit()`; the file `deny`s indexing).
fn digit_at(b: &[u8], p: usize) -> bool {
  b.get(p).is_some_and(u8::is_ascii_digit)
}

/// `true` when the byte at `p` exists and equals `c` (the checked form of
/// `p < b.len() && b[p] == c`). Its negation is the `p >= b.len() || b[p] != c`
/// guard the NMEA parsers use to require a literal separator.
fn byte_at_eq(b: &[u8], p: usize, c: u8) -> bool {
  b.get(p) == Some(&c)
}

/// Read a `\d{N}` fixed-width unsigned integer, advancing the cursor.
fn parse_uint_fixed(b: &[u8], p: &mut usize, n: usize) -> Option<u32> {
  let slice = b.get(*p..*p + n)?;
  if !slice.iter().all(u8::is_ascii_digit) {
    return None;
  }
  let v: u32 = core::str::from_utf8(slice).ok()?.parse().ok()?;
  *p += n;
  Some(v)
}

/// Read `\d*\.?\d*` (decimal, possibly empty). Returns `Ok(None)` if the
/// field is empty (matches Perl `length` test before assignment, lines
/// 1082-1083), `Ok(Some(v))` if non-empty. Returns `None` only on parse fail.
fn parse_optional_decimal(b: &[u8], p: &mut usize) -> Option<Option<f64>> {
  let start = *p;
  while digit_at(b, *p) || byte_at_eq(b, *p, b'.') {
    *p += 1;
  }
  if *p == start {
    return Some(None);
  }
  let s = core::str::from_utf8(b.get(start..*p)?).ok()?;
  if s == "." || s.is_empty() {
    return Some(None);
  }
  let v: f64 = s.parse().ok()?;
  Some(Some(v))
}

/// Read a `\d+\.\d+` decimal, advancing the cursor.
fn parse_decimal(b: &[u8], p: &mut usize) -> Option<f64> {
  let start = *p;
  while digit_at(b, *p) {
    *p += 1;
  }
  if *p == start {
    return None;
  }
  if byte_at_eq(b, *p, b'.') {
    *p += 1;
    while digit_at(b, *p) {
      *p += 1;
    }
  }
  core::str::from_utf8(b.get(start..*p)?).ok()?.parse().ok()
}

// ─────────────────── Process_text fallbacks (DJI / Mini / Roadhawk / Thinkware)

/// The DJI telemetry decode (QuickTimeStream.pl:1213-1230). `lat`/`lon` are raw
/// decimal degrees; `speed_kph`/`distance` are already `× $mpsToKph`;
/// `vertical_speed` keeps the RAW captured string.
struct DjiTelemetry {
  lat: f64,
  lon: f64,
  alt: Option<f64>,
  speed_kph: Option<f64>,
  distance: Option<f64>,
  vertical_speed: Option<SmolStr>,
  fnumber: Option<f64>,
  exposure_time_s: Option<f64>,
  exposure_compensation: Option<f64>,
  iso: Option<SmolStr>,
}

/// Parse the DJI telemetry text (QuickTimeStream.pl:1216-1227). The `GPS
/// (lon, lat[, alt])` pair is REQUIRED (`$1`=lon, `$2`=lat); every other field
/// is an independent optional `if $$dataPt =~ /.../` match on the WHOLE buffer.
fn parse_dji_telemetry(data: &[u8]) -> Option<DjiTelemetry> {
  let s = core::str::from_utf8(data).ok()?;
  // `GPS \(([-+]?\d*\.\d+),\s*([-+]?\d*\.\d+)` — lon then lat.
  let gps_at = s.find("GPS (")?;
  let after = s.get(gps_at + 5..)?;
  let (lon, rest) = scan_signed_dotted(after)?;
  let rest = rest.strip_prefix(',')?;
  let rest = rest.trim_start_matches([' ', '\t', '\n', '\r', '\x0c']);
  let (lat, _) = scan_signed_dotted(rest)?;
  Some(DjiTelemetry {
    lat,
    lon,
    // `,\s*H\s+([-+]?\d+\.?\d*)m` — altitude from the H(eight) field.
    alt: find_comma_field(s, b"H", |t| {
      let (v, r) = scan_signed_int_optfrac(t)?;
      r.strip_prefix('m').map(|_| v)
    }),
    // `,\s*H.S\s+([-+]?\d+\.?\d*)` — m/s, scaled to km/h (`.` matches any byte).
    speed_kph: find_comma_field(s, b"H.S", |t| scan_signed_int_optfrac(t).map(|(v, _)| v))
      .map(|v| v * MPS_TO_KPH),
    // `,\s*D\s+(\d+\.?\d*)m` — distance (m/s reading) scaled to km/h.
    distance: find_comma_field(s, b"D", |t| {
      let (v, r) = scan_unsigned_int_optfrac(t)?;
      r.strip_prefix('m').map(|_| v)
    })
    .map(|v| v * MPS_TO_KPH),
    // `,\s*V.S\s+([-+]?\d+\.?\d*)` — the RAW captured string (rendered "$val m/s").
    vertical_speed: find_comma_field(s, b"V.S", |t| {
      scan_signed_int_optfrac_str(t).map(|(tok, _)| SmolStr::from(tok))
    }),
    // `\bF\/(\d+\.?\d*)` — f-number.
    fnumber: find_fnumber_field(s, |t| scan_unsigned_int_optfrac(t).map(|(v, _)| v)),
    // `\bSS\s+(\d+\.?\d*)` — exposure 1/SS.
    exposure_time_s: find_word_field(s, b"SS", |t| scan_unsigned_int_optfrac(t).map(|(v, _)| v))
      .and_then(|ss| (ss != 0.0).then_some(1.0 / ss)),
    // `\bEV\s+([-+]?\d+\.?\d*)(\/\d+)?` — `$1 / ($2 || 1)`.
    exposure_compensation: find_word_field(s, b"EV", |t| {
      let (num, r) = scan_signed_int_optfrac(t)?;
      // Optional `/\d+` denominator.
      let denom = r
        .strip_prefix('/')
        .and_then(|d| scan_unsigned_int(d).map(|(v, _)| v))
        .filter(|&d| d != 0.0)
        .unwrap_or(1.0);
      Some(num / denom)
    }),
    // `\bISO\s+(\d+\.?\d*)` — the RAW captured token.
    iso: find_word_field(s, b"ISO", |t| {
      scan_unsigned_int_optfrac_str(t).map(|(tok, _)| SmolStr::from(tok))
    }),
  })
}

/// The Mini 0806 decode (QuickTimeStream.pl:1232-1248).
struct Mini0806 {
  yr: i32,
  mon: u32,
  day: u32,
  hr: u32,
  min: u32,
  sec: String,
  lat: Option<(f64, char)>,
  lon: Option<(f64, char)>,
  alt: Option<f64>,
  speed: Option<f64>,
  /// The 3-value Accelerometer `"$a[9] $a[10] $a[11]"` — ExifTool joins the RAW
  /// split tokens verbatim (`"+01.84 -09.80 -00.61"`, QuickTimeStream.pl:1245),
  /// so this is a pre-joined string, not parsed floats.
  accel_str: Option<SmolStr>,
}

/// Parse the Mini 0806 dashcam record (QuickTimeStream.pl:1234-1245):
/// `^A,(\d{2})(\d{2})(\d{2}),(\d{2})(\d{2})(\d{2}(\.\d+)?)`, then lat/lon via
/// later anchored sub-matches and alt/speed/accel from the comma split.
fn parse_mini_0806(data: &[u8]) -> Option<Mini0806> {
  let b = data;
  // `^A,` — the fingerprint.
  if b.get(0..2) != Some(b"A,".as_slice()) {
    return None;
  }
  let mut p = 2usize;
  // Date DDMMYY (2+2+2) — the regex is `(\d{2})(\d{2})(\d{2})` ⇒ $1=day, $2=mon,
  // $3=yr; the date string is `"20$3:$2:$1"` (QuickTimeStream.pl:1235).
  let day = parse_uint_fixed(b, &mut p, 2)?;
  let mon = parse_uint_fixed(b, &mut p, 2)?;
  let yr2 = parse_uint_fixed(b, &mut p, 2)?;
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  // Time HHMMSS(.sss) — `(\d{2})(\d{2})(\d{2}(\.\d+)?)`.
  let hr = parse_uint_fixed(b, &mut p, 2)?;
  let min = parse_uint_fixed(b, &mut p, 2)?;
  let sec_start = p;
  let _ = parse_uint_fixed(b, &mut p, 2)?;
  if byte_at_eq(b, p, b'.') {
    p += 1;
    while digit_at(b, p) {
      p += 1;
    }
  }
  let sec = core::str::from_utf8(b.get(sec_start..p)?).ok()?.to_string();

  // The whole-buffer text (the remaining matches are field-position sub-regexes).
  let s = core::str::from_utf8(b).ok()?;
  // Lat: `^A,.*?,.*?,(\d{2})(\d+\.\d+),([NS])` — the 3rd comma-field.
  let lat = mini_field_after_commas(s, 3).and_then(|f| {
    let (deg, min2, lref) = parse_mini_coord(f, 2)?;
    Some((
      (deg + min2 / 60.0) * if lref == 'S' { -1.0 } else { 1.0 },
      lref,
    ))
  });
  // Lon: `^A,.*?,.*?,.*?,.*?,(\d{3})(\d+\.\d+),([EW])` — the 5th comma-field.
  let lon = mini_field_after_commas(s, 5).and_then(|f| {
    let (deg, min2, lref) = parse_mini_coord(f, 3)?;
    Some((
      (deg + min2 / 60.0) * if lref == 'W' { -1.0 } else { 1.0 },
      lref,
    ))
  });
  // `@a = split ',', $$dataPt`; $a[7]=speed, $a[8]=altitude(strip M),
  // $a[9..11]=accel (strip trailing `;`).
  let a: Vec<&str> = s.split(',').collect();
  let alt = a.get(8).and_then(|v| {
    let stripped = v.strip_suffix('M')?;
    stripped.parse::<f64>().ok()
  });
  // `$a[7] if $a[7] =~ /^\d+\.\d+$/`.
  let speed = a
    .get(7)
    .filter(|v| is_plain_decimal(v))
    .and_then(|v| v.parse::<f64>().ok());
  // `Accelerometer = "$a[9] $a[10] $a[11]" if $a[11] and $a[11] =~ s/;\s*$//`
  // (QuickTimeStream.pl:1245). The RAW split tokens are joined verbatim; the
  // `s/;\s*$//` strips the trailing `;` (+ whitespace) from `$a[11]` in place and
  // must SUCCEED. So a3 is the third field with its trailing `;…` removed.
  let accel_str = match (a.get(9), a.get(10), a.get(11)) {
    (Some(&a1), Some(&a2), Some(&a3)) if !a3.is_empty() => {
      // `s/;\s*$//` — strip trailing whitespace then a single `;` then any
      // whitespace BEFORE it (Perl `\s*$` is trailing whitespace, the `;` then
      // precedes it). Require the substitution to match (a `;` present).
      let a3_trimmed = a3.trim_end_matches([' ', '\t', '\n', '\r', '\x0c']);
      let a3_no_semi = a3_trimmed.strip_suffix(';')?;
      Some(SmolStr::from(alloc::format!("{a1} {a2} {a3_no_semi}")))
    }
    _ => None,
  };
  Some(Mini0806 {
    yr: i32::try_from(yr2).ok()? + 2000,
    mon,
    day,
    hr,
    min,
    sec,
    lat,
    lon,
    alt,
    speed,
    accel_str,
  })
}

/// The parsed NMEA-RMC fields (QuickTimeStream.pl:1274-1283), shared by the
/// Thinkware path and the Roadhawk decoded `$GPRMC`. Decimal-degree lat/lon.
struct NmeaRmc {
  yr: i32,
  mon: u32,
  day: u32,
  hr: u32,
  min: u32,
  sec: String,
  lat: f64,
  lon: f64,
  spd: Option<f64>,
  trk: Option<f64>,
}

/// Parse a `[A-Z]{2}RMC,...` sentence ANYWHERE in the buffer (NO leading `$`),
/// with the day≤31 / mon≤12 / yr≤99 sanity checks (QuickTimeStream.pl:1274-1276).
/// This is the Thinkware / general-NMEA-RMC POST-loop branch — distinct from the
/// `$`-anchored [`parse_nmea_rmc`] used by the Type-2/7 freeGPS decoders (that
/// one reads RAW decimal lat/lon; this one is the DDMM→decimal `($deg + $min/60)`
/// conversion, like [`parse_text_rmc`]).
fn parse_thinkware_rmc(data: &[u8]) -> Option<NmeaRmc> {
  let s = core::str::from_utf8(data).ok()?;
  let b = s.as_bytes();
  // Scan for `[A-Z]{2}RMC,` and try to parse from there.
  let mut i = 0usize;
  while i + 6 <= b.len() {
    let win = b.get(i..i + 6)?;
    if win.first().is_some_and(u8::is_ascii_uppercase)
      && win.get(1).is_some_and(u8::is_ascii_uppercase)
      && win.get(2..6) == Some(b"RMC,".as_slice())
      && let Some(rmc) = parse_nmea_rmc_body(b, i + 6)
    {
      return Some(rmc);
    }
    i += 1;
  }
  None
}

/// Parse the RMC body starting right after `XXRMC,` at `p`:
/// `(\d{2})(\d{2})(\d+(\.\d*)?),A?,(\d*?)(\d{1,2}\.\d+),([NS]),(\d*?)
/// (\d{1,2}\.\d+),([EW]),(\d*\.?\d*),(\d*\.?\d*),(\d{2})(\d{2})(\d+)` with the
/// day/mon/yr sanity gate.
fn parse_nmea_rmc_body(b: &[u8], mut p: usize) -> Option<NmeaRmc> {
  let hr = parse_uint_fixed(b, &mut p, 2)?;
  let min = parse_uint_fixed(b, &mut p, 2)?;
  // Sec `\d+(\.\d*)?`. The Thinkware branch builds GPSDateTime via
  // `sprintf('%.2d', $3)` (QuickTimeStream.pl:1279) — an INTEGER seconds (the
  // fractional part of `13.00` is dropped by `%.2d`). Capture the integer-digit
  // run for `sec`, then consume (but discard) any fractional digits so the field
  // cursor advances past the whole `\d+(\.\d*)?` match.
  let sec_start = p;
  while digit_at(b, p) {
    p += 1;
  }
  if p == sec_start {
    return None;
  }
  let sec = core::str::from_utf8(b.get(sec_start..p)?).ok()?.to_string();
  if byte_at_eq(b, p, b'.') {
    p += 1;
    while digit_at(b, p) {
      p += 1;
    }
  }
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  // `A?,`.
  if byte_at_eq(b, p, b'A') {
    p += 1;
  }
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  let (lat_deg, lat_min) = read_dddmm(b, &mut p)?;
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  let lat_sign = match b.get(p)? {
    b'N' => 1.0,
    b'S' => -1.0,
    _ => return None,
  };
  p += 1;
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  let (lon_deg, lon_min) = read_dddmm(b, &mut p)?;
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  let lon_sign = match b.get(p)? {
    b'E' => 1.0,
    b'W' => -1.0,
    _ => return None,
  };
  p += 1;
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  let spd = parse_optional_decimal(b, &mut p)?;
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  let trk = parse_optional_decimal(b, &mut p)?;
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  // Date DDMMYY — `(\d{2})(\d{2})(\d+)` ⇒ $13=day, $14=mon, $15=yr.
  let day = parse_uint_fixed(b, &mut p, 2)?;
  let mon = parse_uint_fixed(b, &mut p, 2)?;
  let yr_start = p;
  while digit_at(b, p) {
    p += 1;
  }
  if p - yr_start < 1 {
    return None;
  }
  let yr2: i32 = core::str::from_utf8(b.get(yr_start..(yr_start + 2).min(p))?)
    .ok()?
    .parse()
    .ok()?;
  // Sanity checks: day≤31, mon≤12, yr2≤99 (QuickTimeStream.pl:1276).
  if day > 31 || mon > 12 || yr2 > 99 {
    return None;
  }
  let yr = yr2 + if yr2 >= 70 { 1900 } else { 2000 };
  Some(NmeaRmc {
    yr,
    mon,
    day,
    hr,
    min,
    sec,
    lat: (lat_deg + lat_min / 60.0) * lat_sign,
    lon: (lon_deg + lon_min / 60.0) * lon_sign,
    spd: spd.map(|v| v * KNOTS_TO_KPH),
    trk,
  })
}

/// The Roadhawk custom-substitution decode table (QuickTimeStream.pl:1257):
/// `'-I8XQWRVNZOYPUTA0B1C2SJ9K.L,M$D3E4F5G6H7'`. Each input byte `c` with
/// `n = c - 43 >= 0` maps to `DECODE[n]` (when in range); other bytes pass
/// through unchanged.
const ROADHAWK_DECODE: &[u8] = b"-I8XQWRVNZOYPUTA0B1C2SJ9K.L,M$D3E4F5G6H7";

/// Decode a Roadhawk buffer (QuickTimeStream.pl:1255-1263): the fingerprint
/// `\*[0-9A-F]{2}~$` (a `*` + 2 hex digits + `~` at the very END), then strip
/// the trailing 4 bytes and run the substitution map. Returns the decoded bytes
/// (or `None` when the fingerprint is absent).
fn decode_roadhawk(data: &[u8]) -> Option<Vec<u8>> {
  // `\*[0-9A-F]{2}~$` — the last 4 bytes are `*`, hex, hex, `~`.
  let n = data.len();
  if n < 4 {
    return None;
  }
  let tail = data.get(n - 4..n)?;
  // `[0-9A-F]` — uppercase hex only (Perl's character class).
  let is_hex_upper = |c: &u8| c.is_ascii_digit() || (b'A'..=b'F').contains(c);
  if tail.first() != Some(&b'*')
    || tail.get(3) != Some(&b'~')
    || !tail.get(1..3)?.iter().all(is_hex_upper)
  {
    return None;
  }
  // `substr($$dataPt, 0, -4)` — everything but the trailing 4 bytes.
  let body = data.get(..n - 4)?;
  let decoded: Vec<u8> = body
    .iter()
    .map(|&c| {
      // `$n = $_ - 43; $_ = $decode[$n] if $n >= 0 and defined $decode[$n]`.
      c.checked_sub(43)
        .and_then(|n| ROADHAWK_DECODE.get(n as usize).copied())
        .unwrap_or(c)
    })
    .collect();
  Some(decoded)
}

/// `$buff =~ /X(.*?)Y(.*?)Z(.*?)G(.*?)\$/` (QuickTimeStream.pl:1264): pull the
/// 4-value Accelerometer `"$1 $2 $3 $4"` from a decoded Roadhawk buffer. The
/// captures are NON-greedy up to the next literal, ending at the `$` (of
/// `$GPRMC`). Returns the space-joined string when the prefix is present.
fn roadhawk_accel(decoded: &[u8]) -> Option<SmolStr> {
  let s = core::str::from_utf8(decoded).ok()?;
  let after_x = s.get(s.find('X')? + 1..)?;
  let (a, after_y) = after_x.split_once('Y')?;
  let (b, after_z) = after_y.split_once('Z')?;
  let (c, after_g) = after_z.split_once('G')?;
  let (d, _) = after_g.split_once('$')?;
  let mut out = String::with_capacity(a.len() + b.len() + c.len() + d.len() + 3);
  out.push_str(a);
  out.push(' ');
  out.push_str(b);
  out.push(' ');
  out.push_str(c);
  out.push(' ');
  out.push_str(d);
  Some(SmolStr::from(out))
}

/// `\bMARKER(.*?)(;|$)` (QuickTimeStream.pl:1285-1286) — the capture between a
/// literal marker and the next `;` (or end of buffer). Used for `gsensori,` →
/// `GSensor` and `CAR,` → `Car`. The marker here INCLUDES the trailing `,` of
/// the Perl literal so the capture starts at the value. Returns `None` when the
/// marker is absent.
fn extract_after_marker(data: &[u8], marker: &[u8]) -> Option<SmolStr> {
  let s = core::str::from_utf8(data).ok()?;
  let m = core::str::from_utf8(marker).ok()?;
  let start = s.find(m)? + m.len();
  let rest = s.get(start..)?;
  let end = rest.find(';').unwrap_or(rest.len());
  Some(SmolStr::from(rest.get(..end)?))
}

// ── small scan helpers for the DJI free-form text ────────────────────────────

/// `[-+]?\d*\.\d+` — an optionally-signed number with a REQUIRED decimal point
/// and ≥1 fractional digit (`8.6499`, `.5`, `-12.0`). Returns `(value, rest)`.
fn scan_signed_dotted(s: &str) -> Option<(f64, &str)> {
  let b = s.as_bytes();
  let mut p = 0usize;
  if matches!(b.first(), Some(b'+' | b'-')) {
    p += 1;
  }
  while b.get(p).is_some_and(u8::is_ascii_digit) {
    p += 1;
  }
  if b.get(p) != Some(&b'.') {
    return None;
  }
  p += 1;
  let frac_start = p;
  while b.get(p).is_some_and(u8::is_ascii_digit) {
    p += 1;
  }
  if p == frac_start {
    return None;
  }
  let v: f64 = s.get(..p)?.parse().ok()?;
  Some((v, s.get(p..)?))
}

/// `[-+]?\d+\.?\d*` — a signed integer with an OPTIONAL fractional part.
/// Returns `(value, rest)`.
fn scan_signed_int_optfrac(s: &str) -> Option<(f64, &str)> {
  let (tok, rest) = scan_signed_int_optfrac_str(s)?;
  Some((tok.parse().ok()?, rest))
}

/// As [`scan_signed_int_optfrac`] but returns the RAW token (for tags whose
/// PrintConv interpolates `"$val"` verbatim — `VerticalSpeed`).
fn scan_signed_int_optfrac_str(s: &str) -> Option<(&str, &str)> {
  let b = s.as_bytes();
  let mut p = 0usize;
  if matches!(b.first(), Some(b'+' | b'-')) {
    p += 1;
  }
  let int_start = p;
  while b.get(p).is_some_and(u8::is_ascii_digit) {
    p += 1;
  }
  if p == int_start {
    return None;
  }
  if b.get(p) == Some(&b'.') {
    p += 1;
    while b.get(p).is_some_and(u8::is_ascii_digit) {
      p += 1;
    }
  }
  Some((s.get(..p)?, s.get(p..)?))
}

/// `\d+\.?\d*` — an UNSIGNED integer with an OPTIONAL fractional part.
fn scan_unsigned_int_optfrac(s: &str) -> Option<(f64, &str)> {
  let (tok, rest) = scan_unsigned_int_optfrac_str(s)?;
  Some((tok.parse().ok()?, rest))
}

/// As [`scan_unsigned_int_optfrac`] but returns the RAW token (`ISO`).
fn scan_unsigned_int_optfrac_str(s: &str) -> Option<(&str, &str)> {
  let b = s.as_bytes();
  let mut p = 0usize;
  let int_start = p;
  while b.get(p).is_some_and(u8::is_ascii_digit) {
    p += 1;
  }
  if p == int_start {
    return None;
  }
  if b.get(p) == Some(&b'.') {
    p += 1;
    while b.get(p).is_some_and(u8::is_ascii_digit) {
      p += 1;
    }
  }
  Some((s.get(..p)?, s.get(p..)?))
}

/// `\d+` — a bare unsigned integer. Returns `(value, rest)`.
fn scan_unsigned_int(s: &str) -> Option<(f64, &str)> {
  let b = s.as_bytes();
  let mut p = 0usize;
  while b.get(p).is_some_and(u8::is_ascii_digit) {
    p += 1;
  }
  if p == 0 {
    return None;
  }
  Some((s.get(..p)?.parse().ok()?, s.get(p..)?))
}

/// `\s` (Perl) — ASCII whitespace `[ \t\n\r\f]`. Rust's [`u8::is_ascii_whitespace`]
/// is the same set (space, tab, LF, FF, CR), matching the DJI regexes' `\s`.
fn is_ws(b: u8) -> bool {
  b.is_ascii_whitespace()
}

/// `\w` (Perl) — `[A-Za-z0-9_]`, used for the `\b` word-boundary in `\bF\/` /
/// `\bSS` / `\bEV` / `\bISO`.
fn is_word(b: u8) -> bool {
  b.is_ascii_alphanumeric() || b == b'_'
}

/// Try to match `marker` at byte offset `p` of `b`, where a `.` byte in `marker`
/// matches ANY single byte (mirroring the regex `.` in `H.S` / `V.S`). Returns
/// the offset just past the marker on success.
fn match_marker(b: &[u8], p: usize, marker: &[u8]) -> Option<usize> {
  let mut i = p;
  for &m in marker {
    let c = *b.get(i)?;
    if m != b'.' && m != c {
      return None;
    }
    i += 1;
  }
  Some(i)
}

/// Mirror `,\s*<marker>\s+` (the DJI `GPSAltitude`/`GPSSpeed`/`Distance`/
/// `VerticalSpeed` field prefixes `,\s*H\s+` / `,\s*H.S\s+` / `,\s*D\s+` /
/// `,\s*V.S\s+`). Scans EVERY `,`, skips `\s*`, matches `<marker>` (with `.` =
/// any byte), then requires `\s+`; on the first full match runs `f` on the text
/// AFTER the whitespace and returns its result. Whitespace-tolerant: handles no
/// space after the comma, multiple spaces, and tabs — unlike the old fixed `", H "`
/// literals (which required exactly one space on each side, silently losing the
/// field on valid non-canonical spacing).
fn find_comma_field<T>(s: &str, marker: &[u8], mut f: impl FnMut(&str) -> Option<T>) -> Option<T> {
  let b = s.as_bytes();
  let mut from = 0usize;
  while let Some(rel) = s.get(from..)?.find(',') {
    let comma = from + rel;
    from = comma + 1;
    // `,` then `\s*`.
    let mut p = comma + 1;
    while b.get(p).copied().is_some_and(is_ws) {
      p += 1;
    }
    // `<marker>` (with `.` = any byte).
    let Some(after_marker) = match_marker(b, p, marker) else {
      continue;
    };
    // `\s+` — at least one whitespace byte.
    let mut q = after_marker;
    while b.get(q).copied().is_some_and(is_ws) {
      q += 1;
    }
    if q == after_marker {
      continue; // `\s+` requires ≥1.
    }
    if let Some(v) = f(s.get(q..)?) {
      return Some(v);
    }
  }
  None
}

/// Mirror `\b<marker>\s+` (the DJI `ExposureTime`/`ExposureCompensation`/`ISO`
/// prefixes `\bSS\s+` / `\bEV\s+` / `\bISO\s+`). Scans for `<marker>` at a `\w`
/// word boundary (the preceding byte is start-of-string or a non-`\w`), requires
/// a trailing `\s+`, then runs `f` on the text after the whitespace. Whitespace-
/// tolerant (multi-space / tab after the marker), unlike the old `"SS "` literals.
fn find_word_field<T>(s: &str, marker: &[u8], mut f: impl FnMut(&str) -> Option<T>) -> Option<T> {
  let b = s.as_bytes();
  let Some(&first) = marker.first() else {
    return None;
  };
  let mut from = 0usize;
  while let Some(rel) = s.get(from..)?.bytes().position(|c| c == first) {
    let at = from + rel;
    from = at + 1;
    // `\b` — the byte before `marker` must be a non-`\w` (or start-of-string).
    if at > 0 && b.get(at - 1).copied().is_some_and(is_word) {
      continue;
    }
    let Some(after_marker) = match_marker(b, at, marker) else {
      continue;
    };
    // `\s+`.
    let mut q = after_marker;
    while b.get(q).copied().is_some_and(is_ws) {
      q += 1;
    }
    if q == after_marker {
      continue;
    }
    if let Some(v) = f(s.get(q..)?) {
      return Some(v);
    }
  }
  None
}

/// Mirror `\bF\/` (the DJI `FNumber` prefix). Scans for `F/` at a `\w` word
/// boundary (the `F` preceded by start-of-string or a non-`\w`); the capture
/// starts immediately after the `/` (NO trailing whitespace in the regex). Runs
/// `f` on the text after `F/`.
fn find_fnumber_field<T>(s: &str, mut f: impl FnMut(&str) -> Option<T>) -> Option<T> {
  let b = s.as_bytes();
  let mut from = 0usize;
  while let Some(rel) = s.get(from..)?.find("F/") {
    let at = from + rel;
    from = at + 1;
    if at > 0 && b.get(at - 1).copied().is_some_and(is_word) {
      continue; // `\b` — `F` must be at a word boundary.
    }
    if let Some(v) = f(s.get(at + 2..)?) {
      return Some(v);
    }
  }
  None
}

/// The `n`-th comma-delimited field of a `^A,...` Mini record (1-based; field 0
/// is `A`). Returns the field text (without the leading comma), or `None` when
/// there are fewer than `n+1` fields. The Perl `.*?` lazy hops are exactly
/// "skip `n` commas then read up to the value".
fn mini_field_after_commas(s: &str, n: usize) -> Option<&str> {
  let mut start = 0usize;
  for _ in 0..n {
    let rel = s.get(start..)?.find(',')?;
    start += rel + 1;
  }
  s.get(start..)
}

/// Parse the Mini lat/lon `(\d{deg})(\d+\.\d+),([NSEW])` head of a field:
/// `deg_digits` fixed integer degrees, then `\d+\.\d+` decimal minutes, then a
/// comma and a hemisphere letter. Returns `(deg, decimal_minutes, ref)`.
fn parse_mini_coord(field: &str, deg_digits: usize) -> Option<(f64, f64, char)> {
  let b = field.as_bytes();
  let mut p = 0usize;
  let deg = parse_uint_fixed(b, &mut p, deg_digits)? as f64;
  // `\d+\.\d+` decimal minutes.
  let min_start = p;
  while digit_at(b, p) {
    p += 1;
  }
  if !byte_at_eq(b, p, b'.') || p == min_start {
    return None;
  }
  p += 1;
  let frac_start = p;
  while digit_at(b, p) {
    p += 1;
  }
  if p == frac_start {
    return None;
  }
  let min: f64 = core::str::from_utf8(b.get(min_start..p)?)
    .ok()?
    .parse()
    .ok()?;
  if !byte_at_eq(b, p, b',') {
    return None;
  }
  p += 1;
  let r = match b.get(p)? {
    b'N' => 'N',
    b'S' => 'S',
    b'E' => 'E',
    b'W' => 'W',
    _ => return None,
  };
  Some((deg, min, r))
}

/// `^\d+\.\d+$` — a whole string that is a plain unsigned decimal (Mini speed
/// gate, QuickTimeStream.pl:1244).
fn is_plain_decimal(s: &str) -> bool {
  let b = s.as_bytes();
  let dot = match s.find('.') {
    Some(d) => d,
    None => return false,
  };
  !b.is_empty()
    && dot > 0
    && dot < b.len() - 1
    && b
      .iter()
      .enumerate()
      .all(|(i, &c)| i == dot || c.is_ascii_digit())
}

/// Decode the BlueSkySea / Ambarella A12 XOR-0xAA enciphered binary block
/// (QuickTimeStream.pl:1175-1211). Returns `true` if `t` was populated.
fn decode_xor_aa_block(data: &[u8], t: &mut FreeGpsTags) -> bool {
  let dec14 = xor_aa_slice(data, 8, 14);
  if dec14.len() != 14 || !dec14.iter().all(|c| c.is_ascii_digit()) {
    return false;
  }
  let s = core::str::from_utf8(&dec14).unwrap_or("");
  if s.len() != 14 {
    return false;
  }
  t.yr = s.get(0..4).and_then(|x| x.parse().ok());
  t.mon = s.get(4..6).and_then(|x| x.parse().ok());
  t.day = s.get(6..8).and_then(|x| x.parse().ok());
  t.hr = s.get(8..10).and_then(|x| x.parse().ok());
  t.min = s.get(10..12).and_then(|x| x.parse().ok());
  t.sec = s.get(12..14).map(str::to_string);
  // Latitude — 9 XOR'd bytes at offset 38, pattern `[NS]\d{2}\d+`.
  let lat_bytes = xor_aa_slice(data, 38, 9);
  if lat_bytes.len() == 9 {
    let lat_s = core::str::from_utf8(&lat_bytes).unwrap_or("");
    if let Some(c) = lat_s.chars().next()
      && (c == 'N' || c == 'S')
      && let Some(deg_s) = lat_s.get(1..3)
      && let Some(frac_s) = lat_s.get(3..)
      && let (Ok(deg), Ok(frac)) = (deg_s.parse::<f64>(), frac_s.parse::<f64>())
    {
      let mut lat = deg + frac / 600000.0;
      if c == 'S' {
        lat = -lat;
      }
      t.lat = Some(lat);
      t.lat_ref = None;
    }
  }
  // Longitude — 10 XOR'd bytes at offset 47, pattern `[EW]\d{3}\d+`.
  let lon_bytes = xor_aa_slice(data, 47, 10);
  if lon_bytes.len() == 10 {
    let lon_s = core::str::from_utf8(&lon_bytes).unwrap_or("");
    if let Some(c) = lon_s.chars().next()
      && (c == 'E' || c == 'W')
      && let Some(deg_s) = lon_s.get(1..4)
      && let Some(frac_s) = lon_s.get(4..)
      && let (Ok(deg), Ok(frac)) = (deg_s.parse::<f64>(), frac_s.parse::<f64>())
    {
      let mut lon = deg + frac / 600000.0;
      if c == 'W' {
        lon = -lon;
      }
      t.lon = Some(lon);
      t.lon_ref = None;
    }
  }
  // Altitude — 5 bytes at 0x39, `[-+]\d+`.
  let alt_b = xor_aa_slice(data, 0x39, 5);
  if let Ok(alt_s) = core::str::from_utf8(&alt_b)
    && (alt_s.starts_with('+') || alt_s.starts_with('-'))
    && alt_s
      .get(1..)
      .is_some_and(|d| d.bytes().all(|c| c.is_ascii_digit()))
    && let Ok(v) = alt_s.parse::<f64>()
  {
    t.alt = Some(v);
  }
  // Speed — 3 bytes at 0x3e, `\d+`.
  let spd_b = xor_aa_slice(data, 0x3e, 3);
  if let Ok(spd_s) = core::str::from_utf8(&spd_b)
    && spd_s.chars().all(|c| c.is_ascii_digit())
    && let Ok(v) = spd_s.parse::<f64>()
  {
    t.spd = Some(v);
  }
  // Accelerometer — BlueSkySea (data[4..6] == 0xaaaa): 12 bytes at 0xad,
  // ASCII `[-+]\d{3}` × 3.
  if data.get(4..6) == Some(&[0xaa, 0xaa][..]) && data.len() >= 0xad + 12 {
    let acc_b = xor_aa_slice(data, 0xad, 12);
    if let Ok(acc_s) = core::str::from_utf8(&acc_b)
      && acc_s.len() == 12
    {
      let x = acc_s.get(0..4).and_then(|v| v.parse::<f64>().ok());
      let y = acc_s.get(4..8).and_then(|v| v.parse::<f64>().ok());
      let z = acc_s.get(8..12).and_then(|v| v.parse::<f64>().ok());
      if let (Some(x), Some(y), Some(z)) = (x, y, z) {
        t.accel = Some((x, y, z));
      }
    }
  }
  true
}

/// XOR `len` bytes from `data[off..off+len]` with 0xaa, returning the
/// decrypted Vec. Returns empty Vec if out of range.
fn xor_aa_slice(data: &[u8], off: usize, len: usize) -> Vec<u8> {
  match data.get(off..off + len) {
    Some(slice) => slice.iter().map(|b| b ^ 0xaa).collect(),
    None => Vec::new(),
  }
}

// ─────────────────────────── ProcessFMAS (Vantrue N2S) ─────────────────────

/// `ProcessFMAS` (QuickTimeStream.pl:3580-3609) — Vantrue N2S dashcam binary
/// GPS record. Fixed 160-byte (+) layout with a 36-byte FMAS prelude and an
/// 8-byte INFO/SAMM marker pair at offset 64.
///
/// Layout (bundled QuickTimeStream.pl:3586-3596):
///   off 0x00-0x07 = "FMAS\0\0\0\0"
///   off 0x40-0x47 = "OFNIMMAS" (reversed "INFO"+"SAMM")
///   off 0x48-0x4b = "SAMM"
///   off 0x60-0x6b = yr (LE u16) + mon u8 + day u8 + hr u8 + min u8 + sec u8 …
///   off 0x6c-0x77 = 3× LE f32 acceleration (X/Y/Z — Z first per ExifTool
///                   comment "looks like Z comes first in my sample")
///   off 0x78-0x80 = `AWNQ` markers (E/W + lon deg + min hi + 0 + lat ref + lat deg + min hi)
///   …
///
/// `unpack('x96vCCCCCCx16AAACCCvCCvvv', $dataPt)` decodes (offset 0x60):
///   $a[0] = yr (u16), $a[1..5] = mon/day/hr/min/sec (u8), then x16 skip,
///   $a[6..8] = 3 chars (FMAS layout's "AWNQ" markers), $a[9..10] = lon-ref +
///   lat-ref, $a[10..13] = lon (u8, u8, u16), $a[14..16] = lat (u8, u8, u16),
///   $a[17..19] = spd, dir (u16 each), plus extras.
///
/// Bundled formula:
///   lon = $a[10] + ($a[11] + $a[13]/6000) / 60
///   lat = $a[14] + ($a[15] + $a[16]/6000) / 60
pub fn process_fmas(data: &[u8], out: &mut QuickTimeStreamMeta) {
  if let Some(sample) = decode_fmas(data) {
    out.push_gps_sample(sample);
  }
}

fn decode_fmas(data: &[u8]) -> Option<GpsSample> {
  // QuickTimeStream.pl:3584 — strict sig + length guard.
  if data.len() < 160 {
    return None;
  }
  if data.get(0..8) != Some(b"FMAS\0\0\0\0") {
    return None;
  }
  // Strict bundled regex: `/^FMAS\0\0\0\0.{72}SAMM.{36}A/s`. That is:
  //   FMAS-marker (8) + 72 bytes + "SAMM" (4) + 36 bytes + "A".
  // Offset of "SAMM" = 80, offset of the trailing "A" = 120.
  if data.get(80..84) != Some(b"SAMM") {
    return None;
  }
  if data.get(120) != Some(&b'A') {
    return None;
  }
  // unpack offsets — `x96` puts the cursor at 0x60. The fields are:
  //   $a[0]=yr (v=u16 LE at 0x60), $a[1..5]=mon/day/hr/min/sec (5×u8 at 0x62-0x66),
  //   `x16` skip to 0x77, $a[6..8] = 3 chars (A/W/N/E/S markers), $a[9]=lon-ref,
  //   `$a[10]=lon-deg u8`, $a[11]=lon-min u8, $a[12]=0-pad u8, $a[13]=lon-min-frac u16,
  //   $a[14]=lat-deg u8, $a[15]=lat-min u8, $a[16]=lat-min-frac u16,
  //   $a[17]=spd u16, $a[18]=dir u16.
  // Per bundled comments: $a[8] = E/W ref, $a[9] = N/S ref (the `A` flag is at 120).
  // The `unpack('x96vCCCCCCx16AAACCCvCCvvv')` template breakdown:
  //   x96 → seek to 96(0x60)
  //   v   → $a[0] = u16 LE  (yr)
  //   C×6 → $a[1..6] (mon, day, hr, min, sec, +1 more byte at 0x69)
  //   x16 → skip 16 bytes (now at 0x77 + 16 = 0x77; cursor was at 0x67 after 5
  //         × C, so really 0x66 + 5 + 16 = 0x77; ExifTool unpack consumed 6 C's
  //         (0x62-0x67) then x16 → 0x77).
  //
  // Re-checking ExifTool's template `x96vCCCCCCx16AAACCCvCCvvv`:
  //   x96  → pos = 96 (0x60)
  //   v    → u16 LE → pos += 2  → 0x62
  //   C×6  → 6 bytes → pos += 6 → 0x68
  //   x16  → skip 16 → pos      → 0x78
  //   A×3  → 3 chars → pos += 3 → 0x7b
  //   C×3  → 3 bytes → pos += 3 → 0x7e
  //   v    → u16 LE → pos += 2  → 0x80
  //   C×2  → 2 bytes → pos += 2 → 0x82
  //   v×3  → 3 × u16 → pos += 6 → 0x88
  //
  // So:
  //   $a[0]    = u16 at 0x60 (yr)
  //   $a[1..6] = u8  at 0x62..0x67 (mon, day, hr, min, sec, +1 extra)
  //   $a[7..9] = 3 chars at 0x78..0x7a — "AWN" / "AWS" / "AEN" / etc. markers
  //              ($a[7] = 'A' fix-valid flag, $a[8] = E/W ref, $a[9] = N/S ref)
  //   $a[10]   = u8 at 0x7b (lon deg)
  //   $a[11]   = u8 at 0x7c (lon min int)
  //   $a[12]   = u8 at 0x7d (always 0 — the "why zero byte at $a[12]?")
  //   $a[13]   = u16 at 0x7e (lon min frac × 6000)
  //   $a[14]   = u8 at 0x80 (lat deg)
  //   $a[15]   = u8 at 0x81 (lat min int)
  //   $a[16]   = u16 at 0x82 (lat min frac × 6000)
  //   $a[17]   = u16 at 0x84 (spd)
  //   $a[18]   = u16 at 0x86 (dir)
  let yr = le_u16(data, 0x60)? as i32;
  let mon = *data.get(0x62)? as u32;
  let day = *data.get(0x63)? as u32;
  let hr = *data.get(0x64)? as u32;
  let min = *data.get(0x65)? as u32;
  let sec = *data.get(0x66)? as u32;
  let ew_ref = *data.get(0x79)? as char; // E or W
  let ns_ref = *data.get(0x7a)? as char; // N or S
  let lon_deg = *data.get(0x7b)? as f64;
  let lon_min = *data.get(0x7c)? as f64;
  let lon_frac = le_u16(data, 0x7e)? as f64;
  let lat_deg = *data.get(0x80)? as f64;
  let lat_min = *data.get(0x81)? as f64;
  let lat_frac = le_u16(data, 0x82)? as f64;
  let spd_raw = le_u16(data, 0x84)? as f64;
  let dir = le_u16(data, 0x86)? as f64;
  // Acceleration — 3 × LE f32 at 0x6c (QuickTimeStream.pl:3598 "Z first").
  let ax = le_f32(data, 0x6c);
  let ay = le_f32(data, 0x70);
  let az = le_f32(data, 0x74);

  let mut lon = lon_deg + (lon_min + lon_frac / 6000.0) / 60.0;
  let mut lat = lat_deg + (lat_min + lat_frac / 6000.0) / 60.0;
  if ns_ref == 'S' {
    lat = -lat;
  }
  if ew_ref == 'W' {
    lon = -lon;
  }
  let mut sample = GpsSample::new();
  sample.set_date_time(Some(SmolStr::from(alloc::format!(
    "{yr:04}:{mon:02}:{day:02} {hr:02}:{min:02}:{sec:02}"
  ))));
  sample.set_latitude(Some(lat));
  sample.set_longitude(Some(lon));
  sample.set_speed_kph(Some(spd_raw * MPH_TO_KPH));
  sample.set_track(Some(dir));
  if let (Some(x), Some(y), Some(z)) = (ax, ay, az) {
    sample.set_accelerometer(Some(SmolStr::from(join3(x, y, z))));
  }
  if sample.is_empty() {
    return None;
  }
  Some(sample)
}

// ─────────────────────────── ProcessWolfbox (G900 / Redtiger F9 4K) ────────

/// `ProcessWolfbox` (QuickTimeStream.pl:3615-3676) — Wolfbox G900 and
/// Redtiger F9 4K Mini Dash Cam binary GPS record.
///
/// Layout (bundled QuickTimeStream.pl:3621-3657):
///   Date/time: 3 × u32 LE at 0x68 (`d, mo, yr`), then 3 × u32 LE at 0xa0
///   (`h, m, s`). Bundled `unpack('x104V3x44V3')`:
///     x104 → 0x68, V3 → day/mon/yr (0x68/0x6c/0x70, end at 0x74),
///     x44  → 0xa0, V3 → hr/min/sec (0xa0/0xa4/0xa8).
///   Numerator/divisor `i64/i64` pairs at:
///     0x48 = speed value, 0x50 = speed divisor
///     0x58 = track value, 0x60 = track divisor
///     0xb0 = lat value, 0xb8 = lat divisor
///     0xc0 = lon value, 0xc8 = lon divisor
///     0xe8 = alt value, 0xf0 = alt divisor
///   Then `ConvertLatLon` runs on lat/lon (DDDMM.MMMM → decimal degrees).
///   Speed value is in knots; multiply by `$knotsToKph`.
///
/// Bundled requires ≥0xf8 bytes; we mirror.
pub fn process_wolfbox(data: &[u8], out: &mut QuickTimeStreamMeta) {
  // QuickTimeStream.pl:3619.
  if data.len() < 0xf8 {
    return;
  }
  // x104 V3 x44 V3 — date at 0x68 (d,mo,yr), time at 0xa0 (h,m,s).
  let Some(day) = le_u32(data, 0x68) else {
    return;
  };
  let Some(mon) = le_u32(data, 0x6c) else {
    return;
  };
  let Some(yr) = le_u32(data, 0x70) else { return };
  let Some(hr) = le_u32(data, 0xa0) else { return };
  let Some(min) = le_u32(data, 0xa4) else {
    return;
  };
  let Some(sec) = le_u32(data, 0xa8) else {
    return;
  };
  // Value/divisor pairs (i64 each).
  let div_pair = |p: usize| -> Option<f64> {
    let v = le_i64(data, p)?;
    let scl = le_i64(data, p + 8)?;
    let denom = if scl == 0 { 1.0 } else { scl as f64 };
    Some(v as f64 / denom)
  };
  let Some(spd) = div_pair(0x48) else { return };
  let Some(trk) = div_pair(0x58) else { return };
  let Some(mut lat) = div_pair(0xb0) else {
    return;
  };
  let Some(mut lon) = div_pair(0xc0) else {
    return;
  };
  let Some(alt) = div_pair(0xe8) else { return };
  // ConvertLatLon (QuickTimeStream.pl:3668): DDDMM.MMMM → decimal degrees.
  lat = convert_lat_lon(lat);
  lon = convert_lat_lon(lon);
  let mut sample = GpsSample::new();
  sample.set_date_time(Some(SmolStr::from(alloc::format!(
    "{yr:04}:{mon:02}:{day:02} {hr:02}:{min:02}:{sec:02}Z"
  ))));
  sample.set_latitude(Some(lat));
  sample.set_longitude(Some(lon));
  sample.set_altitude_m(Some(alt));
  sample.set_speed_kph(Some(spd * KNOTS_TO_KPH));
  sample.set_track(Some(trk));
  if !sample.is_empty() {
    out.push_gps_sample(sample);
  }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  /// Decode one freeGPS block with fresh cross-block state — the single-block
  /// test shape (`ProcessFreeGPS` with a clean `$$et{FreeGPS2}`). No CreateDate
  /// / SampleTime (the brute-force-scan shape).
  fn decode_block(block: &[u8], out: &mut QuickTimeStreamMeta) {
    let mut state = FreeGpsState::new();
    process_free_gps(block, None, None, None, &mut state, out, None);
  }

  /// Decode one freeGPS block with a `CreateDate` + `SampleTime` in effect —
  /// the `gps `-sample-table shape that feeds `SetGPSDateTime`
  /// (QuickTimeStream.pl:1562, 2396).
  fn decode_block_with_time(
    block: &[u8],
    create_date_raw: u64,
    sample_time: f64,
    out: &mut QuickTimeStreamMeta,
  ) {
    let mut state = FreeGpsState::new();
    process_free_gps(
      block,
      Some(create_date_raw),
      Some(sample_time),
      None,
      &mut state,
      out,
      None,
    );
  }

  /// Decode one freeGPS block with a `KodakVersion` global in effect — the
  /// Rexing Type-17b test shape.
  fn decode_block_kodak(block: &[u8], kodak_version: &str, out: &mut QuickTimeStreamMeta) {
    let mut state = FreeGpsState::new();
    process_free_gps(
      block,
      None,
      None,
      Some(kodak_version),
      &mut state,
      out,
      None,
    );
  }

  /// Build a freeGPS block from a `inner` mut buffer that is treated as the
  /// payload at BLOCK offset 12. Returns the assembled BLOCK.
  fn make_block(payload_size: usize) -> (Vec<u8>, usize) {
    // BLOCK = 12-byte header + payload_size payload bytes.
    let mut v = vec![0u8; 12 + payload_size];
    let total = v.len() as u32;
    wr(&mut v, 0, &total.to_be_bytes());
    wr(&mut v, 4, b"freeGPS ");
    (v, 12)
  }

  /// Write `src` at `off` (the test-fixture builders' `buf[off..off+N] =`
  /// shape) without raw slice-indexing; panics on an out-of-range fixture,
  /// matching the previous `[..]` write.
  fn wr(buf: &mut [u8], off: usize, src: &[u8]) {
    buf
      .get_mut(off..off + src.len())
      .unwrap()
      .copy_from_slice(src);
  }

  /// Write a single byte at `i` (the `buf[i] = b` fixture shape).
  fn wb(buf: &mut [u8], i: usize, b: u8) {
    *buf.get_mut(i).unwrap() = b;
  }

  #[test]
  fn convert_lat_lon_dddmm_via_pub_helper() {
    let v = convert_lat_lon(4737.7053);
    assert!((v - 47.628_421_666_666_67).abs() < 1e-9);
  }

  #[test]
  fn find_magic_locates_freegps_with_correct_prefix() {
    // 4 BE bytes (size 0x00 0x00 0x80 0x00) then `freeGPS `.
    let mut buf = vec![0x55u8; 10]; // padding
    buf.extend_from_slice(&[0, 0, 0x80, 0]);
    buf.extend_from_slice(b"freeGPS ");
    buf.extend_from_slice(&[0u8; 4]);
    let hit = find_magic(&buf).expect("hit");
    assert!(matches!(hit.kind, MagicKind::FreeGps));
    assert_eq!(hit.offset, 10);
  }

  #[test]
  fn find_magic_rejects_freegps_without_le_size_prefix() {
    // Prefix has the wrong byte pattern (the first byte is not 0).
    let mut buf = vec![0u8; 10];
    buf.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
    buf.extend_from_slice(b"freeGPS ");
    assert!(find_magic(&buf).is_none());
  }

  #[test]
  fn process_free_gps_too_short_is_silent() {
    let mut out = QuickTimeStreamMeta::new();
    decode_block(&[0u8; 50], &mut out);
    assert!(out.is_empty());
  }

  #[test]
  fn decode_type1_azdome_decrypts_and_extracts() {
    // Type 1: detection is the 8-byte signature at BLOCK offset 18.
    // The XOR-0xaa decryption starts at BLOCK offset 18; the first 8
    // decrypted bytes are buf2[0..8] (the signature bytes pre-decryption),
    // then digits/label start at buf2[8]. We build the "decrypted" buffer
    // first, then XOR-0xaa it into the block at offset 18.
    let (mut block, _) = make_block(0x200);
    // The DECRYPTED buf2 layout (block start = block[18] after XOR-0xaa):
    //   buf2[0..8]   8-byte preamble (matches the pre-XOR signature bytes)
    //   buf2[8..22]  14 digits YYYYMMDDhhmmss
    //   buf2[22]     '.' separator
    //   buf2[23..38] 15-byte label
    //   buf2[38]     N/S
    //   buf2[39..47] 8 digits lat (DDMM.MMMM scaled by 1e4)
    //   buf2[47]     E/W
    //   buf2[48..57] 9 digits lon
    //   buf2[57..65] 8 digits speed
    // For 4746.2813 latitude: encode as "47462813" (lat * 1e4).
    let mut decrypted = Vec::new();
    decrypted.extend_from_slice(b"\x00\x00XKZD\xfe\xfe");
    decrypted.extend_from_slice(b"20240107111914");
    decrypted.push(b'.');
    decrypted.extend_from_slice(b"PADLABELXXX0000"); // 15-byte label
    decrypted.push(b'N');
    decrypted.extend_from_slice(b"47462813"); // lat
    decrypted.push(b'W');
    decrypted.extend_from_slice(b"122165017"); // lon (9 digits)
    decrypted.extend_from_slice(b"00000050"); // speed = 50.
    while decrypted.len() < 0x101 {
      decrypted.push(0);
    }
    // XOR with 0xaa and write at block offset 18.
    for (i, &b) in decrypted.iter().enumerate() {
      if 18 + i < block.len() {
        wb(&mut block, 18 + i, b ^ 0xaa);
      }
    }
    let mut out = QuickTimeStreamMeta::new();
    decode_block(&block, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = out.gps_samples().first().unwrap();
    assert_eq!(s.date_time(), Some("2024:01:07 11:19:14Z"));
    // lat 4746.2813 ⇒ ConvertLatLon ⇒ 47 + 46.2813/60 ≈ 47.7713555 ⇒ N positive.
    let lat = s.latitude().expect("lat");
    assert!((lat - 47.77_134_72).abs() < 1e-3, "lat={lat}");
    let lon = s.longitude().expect("lon");
    assert!(lon < -120.0, "lon={lon}");
    assert_eq!(s.speed_kph(), Some(50.0));
  }

  #[test]
  fn decode_type6_akaso_extracts_lat_lon() {
    // Type 6: A at BLOCK offset 60, NS at 68, EW at 76; time/lat/lon at 0x30/0x40.
    // QuickTimeStream.pl byte offsets are block-absolute (include 12-byte header).
    let (mut block, _) = make_block(0x100);
    wb(&mut block, 60, b'A');
    wb(&mut block, 68, b'N');
    wb(&mut block, 76, b'W');
    // hr/min/sec at 0x30..0x3c (3×u32 LE).
    wr(&mut block, 0x30, &14u32.to_le_bytes());
    wr(&mut block, 0x34, &30u32.to_le_bytes());
    wr(&mut block, 0x38, &45u32.to_le_bytes());
    // yr/mon/day at 0x30+12+28 = 0x58..0x64 (3×u32 LE).
    wr(&mut block, 0x58, &2024u32.to_le_bytes());
    wr(&mut block, 0x5c, &7u32.to_le_bytes());
    wr(&mut block, 0x60, &15u32.to_le_bytes());
    // accel: 3×u32 LE at 0x64.
    wr(&mut block, 0x64, &1000u32.to_le_bytes());
    wr(&mut block, 0x68, &2000u32.to_le_bytes());
    wr(&mut block, 0x6c, &3000u32.to_le_bytes());
    // lat/lon/spd/trk floats at 0x40..0x58.
    wr(&mut block, 0x40, &4737.7053f32.to_le_bytes());
    wr(&mut block, 0x48, &12209.901f32.to_le_bytes());
    wr(&mut block, 0x50, &60.0f32.to_le_bytes());
    wr(&mut block, 0x54, &90.0f32.to_le_bytes());
    let mut out = QuickTimeStreamMeta::new();
    decode_block(&block, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = out.gps_samples().first().unwrap();
    assert!((s.latitude().unwrap() - 47.628_421).abs() < 1e-3);
    assert!(s.longitude().unwrap() < -120.0);
    assert_eq!(s.date_time(), Some("2024:07:15 14:30:45Z"));
  }

  #[test]
  fn decrypt_lucky_rc4_roundtrip() {
    // RC4 is symmetric — decrypting the output yields the input.
    let key = b"luckychip gps";
    let plain = b"4737.7053";
    let enc = decrypt_lucky(plain, key);
    let dec = decrypt_lucky(&enc, key);
    assert_eq!(dec, plain);
  }

  #[test]
  fn parse_strict_decimal_rejects_garbage() {
    assert!(parse_strict_decimal("1234.5", 5).is_some());
    assert!(parse_strict_decimal("0.1", 1).is_some());
    assert!(parse_strict_decimal("12.", 5).is_none()); // empty fraction
    assert!(parse_strict_decimal(".5", 5).is_none()); // leading dot
    assert!(parse_strict_decimal("12345.6", 4).is_none()); // too many int digits
    assert!(parse_strict_decimal("abc", 5).is_none());
  }

  #[test]
  fn type11_atc_decrypts_and_emits() {
    // Build one valid ATC 52-byte record (the simplest path: zero-key plaintext).
    // Detected by "ATC" at BLOCK offset 0x45. ExifTool reads the 52-byte
    // record at BLOCK offset 0x30 (skipping the 0x10..0x30 header bytes).
    let (mut block, _) = make_block(0x100);
    // Place "ATC" at offset 0x45 (the detection marker is BLOCK offset 0x45-0x48).
    wr(&mut block, 0x45, b"ATC");
    let rec_off = 0x30usize;
    // Record-local offsets:
    //   0x0d hour-1, 0x0e min, 0x0f sec
    //   0x10..0x13 int32s latitude*1e7, 0x14 = key1
    //   0x15..0x17 "ATC" (this is the detection trigger when at rec+0x15)
    //   0x18..0x1b int32s longitude*1e7, 0x1c key2
    //   0x20..0x23 int32s speed*100, 0x24..0x25 int16s heading*100
    //   0x28..0x2b int32s altitude*1000, 0x2c..0x2d int16u year
    //   0x2e mon, 0x2f day
    wb(&mut block, rec_off + 0x0d, 13); // hr+1 ⇒ hr=14
    wb(&mut block, rec_off + 0x0e, 30); // min
    wb(&mut block, rec_off + 0x0f, 45); // sec
    wr(&mut block, rec_off + 0x10, &476_284_215i32.to_le_bytes());
    wr(&mut block, rec_off + 0x15, b"ATC");
    wr(
      &mut block,
      rec_off + 0x18,
      &(-1_221_650_167i32).to_le_bytes(),
    );
    wr(&mut block, rec_off + 0x20, &2000i32.to_le_bytes());
    wr(&mut block, rec_off + 0x24, &18000i16.to_le_bytes());
    wr(&mut block, rec_off + 0x28, &100_000i32.to_le_bytes());
    wr(&mut block, rec_off + 0x2c, &2024u16.to_le_bytes());
    wb(&mut block, rec_off + 0x2e, 7);
    wb(&mut block, rec_off + 0x2f, 15);
    // Keys 0x14/0x1c are both already 0 ⇒ XOR is identity.
    let mut out = QuickTimeStreamMeta::new();
    decode_block(&block, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = out.gps_samples().first().unwrap();
    assert!((s.latitude().unwrap() - 47.6_284_215).abs() < 1e-6);
    assert!((s.longitude().unwrap() + 122.1_650_167).abs() < 1e-6);
    assert_eq!(s.date_time(), Some("2024:07:15 14:30:45Z"));
    assert!(s.altitude_m().is_some());
  }

  /// GPSType 12 — 80-byte double-lat/lon dashcam (QuickTimeStream.pl:2159-2188).
  /// The bundled regex `/^.{60}A\0.{10}([NS])\0.{14}([EW])\0/s` puts the
  /// latitude-ref at offset 72 (data-layout `0x48`) and the longitude-ref at
  /// offset 88 (`0x58`); the decoder reads those same offsets. Oracle-verified
  /// against bundled ExifTool 13.59 (`-ee -api QuickTimeUTC=1`):
  ///   GPSDateTime 2024:07:15 14:30:45Z, GPSLatitude 47.6284216666667,
  ///   GPSLongitude 122.165016666667, GPSSpeed 18.52 (10 knots × 1.852),
  ///   GPSTrack 90, Accelerometer "1 2 -3".
  /// (The old port checked refs at 71/86 — off by 1/2 — so a real Type-12 block
  /// failed detection and fell through to the Type-20 catch-all.)
  #[test]
  fn type12_double_lat_lon_ref_offsets_0x48_0x58() {
    let (mut block, _) = make_block(0x100);
    // A@60, [NS]@72 (0x48), [EW]@88 (0x58); the intervening bytes stay NUL.
    wb(&mut block, 60, b'A');
    wb(&mut block, 72, b'N');
    wb(&mut block, 88, b'E');
    // hr/min/sec (V) @ 0x30/0x34/0x38.
    wr(&mut block, 0x30, &14u32.to_le_bytes());
    wr(&mut block, 0x34, &30u32.to_le_bytes());
    wr(&mut block, 0x38, &45u32.to_le_bytes());
    // lat double @0x40 (DDMM.MMMM 4737.7053 → 47°37.7053′), lon @0x50 (12209.901).
    wr(&mut block, 0x40, &4737.7053f64.to_le_bytes());
    wr(&mut block, 0x50, &12209.901f64.to_le_bytes());
    // spd double @0x60 (10 knots), trk @0x68 (90°).
    wr(&mut block, 0x60, &10.0f64.to_le_bytes());
    wr(&mut block, 0x68, &90.0f64.to_le_bytes());
    // yr-2000/mon/day (V) @ 0x70/0x74/0x78.
    wr(&mut block, 0x70, &24u32.to_le_bytes());
    wr(&mut block, 0x74, &7u32.to_le_bytes());
    wr(&mut block, 0x78, &15u32.to_le_bytes());
    // accel int32s/1000 @ 0x7c (1.0, 2.0, -3.0).
    wr(&mut block, 0x7c, &1000i32.to_le_bytes());
    wr(&mut block, 0x80, &2000i32.to_le_bytes());
    wr(&mut block, 0x84, &(-3000i32).to_le_bytes());

    let mut out = QuickTimeStreamMeta::new();
    decode_block(&block, &mut out);
    assert_eq!(out.gps_samples().len(), 1, "one Type-12 sample");
    let s = out.gps_samples().first().unwrap();
    assert_eq!(s.date_time(), Some("2024:07:15 14:30:45Z"));
    let lat = s.latitude().expect("lat");
    assert!(
      (lat - 47.628_421_666_666_67).abs() < 1e-9,
      "lat {lat} (want 47.6284216666667, N positive)"
    );
    let lon = s.longitude().expect("lon");
    assert!(
      (lon - 122.165_016_666_667).abs() < 1e-9,
      "lon {lon} (want 122.165016666667, E positive)"
    );
    assert!(
      (s.speed_kph().expect("spd") - 18.52).abs() < 1e-9,
      "spd {:?} (want 18.52 = 10 knots × 1.852)",
      s.speed_kph()
    );
    assert_eq!(s.track(), Some(90.0));
    assert_eq!(s.accelerometer(), Some("1 2 -3"));
  }

  /// GPSType 12 detection is ALSO reachable through the brute-force scanner —
  /// the same oracle-verified block, found in a full 0x8000 chunk, decodes to
  /// the identical sample (the scan path passes no SampleTime, but Type-12
  /// carries its own embedded date).
  #[test]
  fn type12_via_scan_media_data() {
    let mut block = vec![0u8; 0x100];
    wr(&mut block, 0, &0x0100u32.to_be_bytes());
    wr(&mut block, 4, b"freeGPS ");
    wb(&mut block, 60, b'A');
    wb(&mut block, 72, b'N');
    wb(&mut block, 88, b'E');
    wr(&mut block, 0x30, &14u32.to_le_bytes());
    wr(&mut block, 0x34, &30u32.to_le_bytes());
    wr(&mut block, 0x38, &45u32.to_le_bytes());
    wr(&mut block, 0x40, &4737.7053f64.to_le_bytes());
    wr(&mut block, 0x50, &12209.901f64.to_le_bytes());
    wr(&mut block, 0x60, &10.0f64.to_le_bytes());
    wr(&mut block, 0x68, &90.0f64.to_le_bytes());
    wr(&mut block, 0x70, &24u32.to_le_bytes());
    wr(&mut block, 0x74, &7u32.to_le_bytes());
    wr(&mut block, 0x78, &15u32.to_le_bytes());
    wr(&mut block, 0x7c, &1000i32.to_le_bytes());
    wr(&mut block, 0x80, &2000i32.to_le_bytes());
    wr(&mut block, 0x84, &(-3000i32).to_le_bytes());
    let mut file = vec![0u8; 64];
    let mdat_offset = file.len() as u64;
    file.extend_from_slice(&block);
    file.extend_from_slice(&vec![0u8; 0x9000]); // full-chunk padding
    let mdat_size = file.len() as u64 - mdat_offset;
    let mut out = QuickTimeStreamMeta::new();
    let mut gp = GoProMeta::new();
    scan_media_data(
      &file,
      mdat_offset,
      mdat_size,
      None,
      None,
      false,
      &mut out,
      &mut gp,
      None,
    );
    assert_eq!(out.gps_samples().len(), 1);
    assert_eq!(
      out.gps_samples().first().unwrap().date_time(),
      Some("2024:07:15 14:30:45Z")
    );
  }

  #[test]
  fn type20_nextbase_be_decodes_one_record() {
    // Type 20 is the catch-all: an `mdat` block that doesn't match any other
    // fingerprint. The 32-byte BE record starts at BLOCK offset 0x32.
    let (mut block, _) = make_block(0x100);
    let rec_off = 0x32usize;
    wr(&mut block, rec_off, &1000u16.to_be_bytes());
    wr(&mut block, rec_off + 2, &12000u16.to_be_bytes());
    wr(&mut block, rec_off + 4, &2024u16.to_be_bytes());
    wb(&mut block, rec_off + 6, 7);
    wb(&mut block, rec_off + 7, 15);
    wb(&mut block, rec_off + 8, 14);
    wb(&mut block, rec_off + 9, 30);
    wr(&mut block, rec_off + 10, &455u16.to_be_bytes());
    wr(&mut block, rec_off + 13, &476_284_215i32.to_be_bytes());
    wr(&mut block, rec_off + 17, &(-1_221_650_167i32).to_be_bytes());
    let mut out = QuickTimeStreamMeta::new();
    decode_block(&block, &mut out);
    assert!(!out.gps_samples().is_empty());
    let s = out.gps_samples().first().unwrap();
    assert!((s.latitude().unwrap() - 47.6_284_215).abs() < 1e-6);
    assert!((s.longitude().unwrap() + 122.1_650_167).abs() < 1e-6);
    assert!(s.date_time().is_some());
  }

  /// GPSType 7 — the `4W`b]S<` cipher deciphers (subtract 16) to a `$GPRMC`
  /// sentence parsed over RAW bytes (QuickTimeStream.pl:1940-1959). The decode
  /// runs on the deciphered `&[u8]` (NOT a UTF-8 string); the cipher signature
  /// `4W`b]S<` itself is the `+16` encoding of `$GPRMC,`.
  #[test]
  fn type7_cipher_decodes_gprmc_over_bytes() {
    // Encode a plaintext RMC by adding 16 to each byte (inverse of the decode).
    let plain = b"$GPRMC,132230.00,A,4721.35,N,00830.80,E,22.5,199.8,141222,,,A";
    let mut enc = [0u8; 80];
    for (i, slot) in enc.iter_mut().enumerate() {
      *slot = plain.get(i).map_or(0u8, |&c| c.wrapping_add(16));
    }
    // 60-byte pad/header + the 80-byte ciphered region (= 140 bytes total).
    let mut block = vec![0u8; 60];
    block.extend_from_slice(&enc);
    // The detection signature `4W`b]S<` must be the first 7 ciphered bytes.
    assert_eq!(block.get(60..67).unwrap(), b"4W\x60b]S<");
    let mut out = QuickTimeStreamMeta::new();
    decode_block(&block, &mut out);
    assert_eq!(out.gps_samples().len(), 1, "one Type-7 sample");
    let s = out.gps_samples().first().unwrap();
    assert_eq!(s.date_time(), Some("2022:12:14 13:22:30.00Z"));
    // 4721.35 DDMM.MMMM ⇒ ConvertLatLon ⇒ 47 + 21.35/60 ≈ 47.3558°, N positive.
    let lat = s.latitude().expect("lat");
    assert!((lat - 47.355_833).abs() < 1e-4, "lat={lat}");
    // 00830.80 ⇒ 8 + 30.80/60 ≈ 8.5133°, E positive.
    let lon = s.longitude().expect("lon");
    assert!((lon - 8.513_333).abs() < 1e-4, "lon={lon}");
    assert!((s.speed_kph().expect("spd") - 22.5 * 1.852).abs() < 1e-6);
  }

  /// GPSType 18 — XGODY 4K ASCII (QuickTimeStream.pl:2354-2384). The decode
  /// indexes `$$dataPt` by BYTE offset, NOT a decoded string: a real Type-18
  /// block has a non-ASCII box header (`00 00 00 a8 …`, :2358) so a strict
  /// `from_utf8` of the whole block would blank it. Oracle-verified vs bundled
  /// ExifTool 13.59: GPSDateTime 2024:05:22 02:54:29Z, GPSLatitude 42.38247,
  /// GPSLongitude -83.38957, GPSSpeed 99.2672 (53.6 knots × 1.852), GPSTrack
  /// 269.2. (Bundled's Accelerometer is the raw captured strings "-0.02 0.99
  /// 0.10"; the typed `GpsSample` stores 3 f64s rendered via `%.15g`, so the
  /// trailing-zero `0.10` → `0.1` — a pre-existing typed-domain rounding shared
  /// by every accel-emitting GPSType, not affected by this change.)
  #[test]
  fn type18_xgody_decodes_over_bytes_with_nonascii_header() {
    let text = b"normal:2024/05/22 02:54:29 N:42.382470 W:83.389570 53.6 km/h x:-0.02 y:0.99 z:0.10 A:269.2 H:245.5";
    let mut block = vec![0u8; 0x100];
    // A non-ASCII box header (byte 3 = 0xa8) — like a real XGODY block (:2358).
    wr(&mut block, 0, &[0x00, 0x00, 0x00, 0xa8]);
    wr(&mut block, 4, b"freeGPS ");
    wr(&mut block, 16, text);
    let mut out = QuickTimeStreamMeta::new();
    decode_block(&block, &mut out);
    assert_eq!(out.gps_samples().len(), 1, "one Type-18 sample");
    let s = out.gps_samples().first().unwrap();
    assert_eq!(s.date_time(), Some("2024:05:22 02:54:29Z"));
    assert!((s.latitude().expect("lat") - 42.382_47).abs() < 1e-6);
    assert!((s.longitude().expect("lon") - -83.389_57).abs() < 1e-6);
    assert!(
      (s.speed_kph().expect("spd") - 53.6 * 1.852).abs() < 1e-4,
      "spd {:?}",
      s.speed_kph()
    );
    assert_eq!(s.track(), Some(269.2));
    assert_eq!(s.accelerometer(), Some("-0.02 0.99 0.1"));
  }

  /// GPSType 18 bare-speed gate `/^\d+\.\d+$/` (QuickTimeStream.pl:2373): only a
  /// DIGITS.DIGITS bare token after lon is taken as speed (int-only / signed /
  /// exponent tokens do NOT match), and the KV value matches
  /// `([-+]?\d+(\.\d+)?)` with a single-ASCII-letter key.
  #[test]
  fn type18_bare_speed_and_kv_shape_gates() {
    // An int-only bare token `53` (no dot) must NOT be taken as speed; the
    // following `53.6` (digits.digits) is.
    let text = b"normal:2024/05/22 02:54:29 N:42.382470 W:83.389570 53 53.6 km/h";
    let mut block = vec![0u8; 0x100];
    wr(&mut block, 0, &0x0100u32.to_be_bytes());
    wr(&mut block, 4, b"freeGPS ");
    wr(&mut block, 16, text);
    let mut out = QuickTimeStreamMeta::new();
    decode_block(&block, &mut out);
    let s = out.gps_samples().first().unwrap();
    assert!(
      (s.speed_kph().expect("spd") - 53.6 * 1.852).abs() < 1e-4,
      "bare int `53` skipped; `53.6` taken: {:?}",
      s.speed_kph()
    );
  }

  /// GPSType 18 — the `[N|S]` detection char-class is LITERAL: the 21st byte of
  /// the date/time region (`^.{23}…/…/… …:…:… [N|S]`) accepts `N`, `|` OR `S`
  /// (QuickTimeStream.pl:2354). A `|` there still matches the detector.
  #[test]
  fn type18_detection_accepts_pipe_in_char_class() {
    // After the date/time, byte 43 is `|` (the literal `[N|S]` member).
    let text = b"normal:2024/05/22 02:54:29 |:00.000000 N:42.382470 W:83.389570";
    let mut block = vec![0u8; 0x100];
    wr(&mut block, 0, &0x0100u32.to_be_bytes());
    wr(&mut block, 4, b"freeGPS ");
    wr(&mut block, 16, text);
    assert!(detect_type18(block.as_slice()), "`|` at offset 43 detects");
  }

  #[test]
  fn scan_media_data_finds_block_in_mdat() {
    // Build a Type-6 freeGPS block (block-absolute offsets), put it inside an
    // `mdat` payload, then scan. ExifTool's scanner regex
    // (`\0..\0freeGPS `, QuickTimeStream.pl:3710) requires bytes 0 and 3 of
    // the 4-byte BE size header to be NUL — so the block size must be ≤
    // 0xffff00 AND a multiple of 256. We size to exactly 0x0100 here.
    // The block must also be found in a FULL 0x8000-byte chunk: ExifTool bails
    // a sub-0x8000 final chunk WITHOUT decoding (`last if length $buff <
    // $gpsBlockSize`, :3750), so the `mdat` here is padded past 0x8000 (this
    // matches a real dashcam file, whose first freeGPS block sits in an early
    // full chunk — oracle-verified: a sub-0x8000 mdat yields NO GPS).
    let mut block = vec![0u8; 0x100];
    wr(&mut block, 0, &0x0100u32.to_be_bytes());
    wr(&mut block, 4, b"freeGPS ");
    wb(&mut block, 60, b'A');
    wb(&mut block, 68, b'N');
    wb(&mut block, 76, b'W');
    wr(&mut block, 0x30, &14u32.to_le_bytes());
    wr(&mut block, 0x34, &30u32.to_le_bytes());
    wr(&mut block, 0x38, &45u32.to_le_bytes());
    wr(&mut block, 0x58, &2024u32.to_le_bytes());
    wr(&mut block, 0x5c, &7u32.to_le_bytes());
    wr(&mut block, 0x60, &15u32.to_le_bytes());
    wr(&mut block, 0x40, &4737.7053f32.to_le_bytes());
    wr(&mut block, 0x48, &12209.901f32.to_le_bytes());
    // Place inside a synthetic file: 100 bytes header + block + padding so the
    // total `mdat` exceeds 0x8000 (the block is then found in a full chunk).
    let mut file = vec![0u8; 100];
    let mdat_offset = file.len() as u64;
    file.extend_from_slice(&block);
    file.extend_from_slice(&vec![0u8; 0x9000]);
    let mdat_size = file.len() as u64 - mdat_offset;

    let mut out = QuickTimeStreamMeta::new();
    let mut gp = GoProMeta::new();
    scan_media_data(
      &file,
      mdat_offset,
      mdat_size,
      None,
      None,
      false,
      &mut out,
      &mut gp,
      None,
    );
    assert_eq!(out.gps_samples().len(), 1);
    assert!(gp.is_empty());
  }

  /// QuickTimeStream.pl:3750 `last if length $buff < $gpsBlockSize` — a freeGPS
  /// block whose magic is first seen inside the FINAL sub-0x8000 chunk is NOT
  /// decoded (the scan bails). A whole `mdat` smaller than 0x8000 therefore
  /// yields NO samples even though the block is structurally valid (oracle-
  /// verified: a 256-byte `mdat` with one freeGPS block produces no GPS).
  #[test]
  fn scan_media_data_bails_on_sub_0x8000_final_chunk() {
    let block = make_type6_block(0x100);
    let mut file = vec![0u8; 100];
    let mdat_offset = file.len() as u64;
    file.extend_from_slice(&block);
    let mdat_size = file.len() as u64 - mdat_offset; // < 0x8000
    let mut out = QuickTimeStreamMeta::new();
    let mut gp = GoProMeta::new();
    scan_media_data(
      &file,
      mdat_offset,
      mdat_size,
      None,
      None,
      false,
      &mut out,
      &mut gp,
      None,
    );
    assert!(
      out.gps_samples().is_empty(),
      "a freeGPS block in a sub-0x8000 mdat must not be decoded"
    );
  }

  #[test]
  fn scan_media_data_short_circuits_when_embedded_found() {
    let mut out = QuickTimeStreamMeta::new();
    let mut gp = GoProMeta::new();
    let file = vec![0u8; 0x10000];
    scan_media_data(
      &file,
      0,
      file.len() as u64,
      None,
      None,
      true,
      &mut out,
      &mut gp,
      None,
    );
    assert!(out.is_empty());
    assert!(gp.is_empty());
  }

  #[test]
  fn base64_decode_roundtrip() {
    let raw = b"\x01\x02\x03\x04";
    // base64("\x01\x02\x03\x04") = "AQIDBA=="
    let b64 = b"AQIDBA==";
    let out = base64_decode(b64);
    assert_eq!(out, raw);
  }

  #[test]
  fn parse_nmea_rmc_full_sentence() {
    let s = b"$GPRMC,132230.000,A,4721.35197,N,00830.80859,E,22.519,199.88,141222,,,A";
    let mut t = FreeGpsTags::new();
    parse_nmea_rmc(s, &mut t);
    assert_eq!(t.hr, Some(13));
    assert_eq!(t.min, Some(22));
    assert_eq!(t.sec.as_deref(), Some("30.000"));
    assert_eq!(t.day, Some(14));
    assert_eq!(t.mon, Some(12));
    assert_eq!(t.yr, Some(2022));
    assert_eq!(t.lat_ref, Some('N'));
    assert_eq!(t.lon_ref, Some('E'));
    assert!(t.lat.unwrap() > 4721.0);
    assert!(t.lon.unwrap() > 830.0);
    assert!(t.spd.unwrap() > 41.0 && t.spd.unwrap() < 42.0); // 22.519 * 1.852
    assert_eq!(t.trk, Some(199.88));
  }

  /// Bundled RMC accepts any `[A-Z]{2}` talker, not just GP/GN (e.g. `$GA`).
  /// `find_nmea_sentence` runs over RAW bytes (QuickTimeStream.pl:1733).
  #[test]
  fn find_nmea_sentence_accepts_any_talker() {
    let s = b"junk$GARMC,010203.0,A,1.0,N,2.0,E,,,010100,,,A more junk";
    let rmc = find_nmea_sentence(s, b"RMC").expect("any talker matches");
    assert!(rmc.starts_with(b"$GARMC,"));
    // A `GGA` request must not match the `RMC` sentence.
    assert!(find_nmea_sentence(s, b"GGA").is_none());
  }

  /// A non-UTF-8 byte BEFORE the NMEA sentence must NOT blank the search —
  /// the bundled regex runs over raw `$$dataPt` bytes (QuickTimeStream.pl:1733),
  /// so `find_nmea_sentence` + `parse_nmea_rmc` operate on `&[u8]`. (A real
  /// Type-2 block carries binary fields — box header, accel int32s — so a
  /// strict `from_utf8` would have failed.)
  #[test]
  fn parse_nmea_rmc_over_raw_bytes_with_binary_prefix() {
    let mut buf = vec![0x00u8, 0x80, 0xff, 0xfe]; // non-UTF-8 binary prefix
    buf.extend_from_slice(
      b"$GPRMC,132230.000,A,4721.35197,N,00830.80859,E,22.519,199.88,141222,,,A",
    );
    let rmc = find_nmea_sentence(&buf, b"RMC").expect("found over raw bytes");
    let mut t = FreeGpsTags::new();
    parse_nmea_rmc(rmc, &mut t);
    assert_eq!(t.yr, Some(2022));
    assert!(t.lat.unwrap() > 4721.0);
  }

  /// GPSType 2: the `$xxGGA` sentence supplies the altitude that RMC lacks.
  #[test]
  fn parse_nmea_gga_supplies_altitude() {
    let mut t = FreeGpsTags::new();
    t.yr = Some(2022); // pretend RMC already set the date.
    parse_nmea_gga(
      b"$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,,,,",
      &mut t,
    );
    assert_eq!(t.alt, Some(545.4));
    // Because a year is set, GGA must NOT overwrite lat/lon/time.
    assert_eq!(t.lat, None);
    assert_eq!(t.hr, None);
  }

  /// GPSType 1 EEEkit: speed is the 3-digit `$2` at offset 62, gated on a
  /// leading `[-+]\d{4}` at offset 57 (QuickTimeStream.pl:1694) — NOT a 4-byte
  /// window at offset 60.
  #[test]
  fn decode_type1_eeekit_speed_offset_62() {
    let (mut block, _) = make_block(0x200);
    let mut decrypted = Vec::new();
    decrypted.extend_from_slice(b"\x00\x00XKZD\xfe\xfe"); // preamble (offs 0-7)
    decrypted.extend_from_slice(b"20200519162335"); // 14 digits (offs 8-21)
    decrypted.push(b'.'); // separator (off 22)
    decrypted.extend_from_slice(b"00200519162336\x03"); // 15-byte label (offs 23-37)
    decrypted.push(b'N'); // off 38
    decrypted.extend_from_slice(b"37452416"); // lat 8 digits (offs 39-46)
    decrypted.push(b'W'); // off 47
    decrypted.extend_from_slice(b"122255009"); // lon 9 digits (offs 48-56)
    // Offset 57 onward: `+0175` (the `[-+]\d{4}` gate) then `011…` — the
    // optional `(\d{8})?` Azdome speed fails (`+`), so the EEEkit branch reads
    // `$2 = "011"` (= 11) at offset 62.
    decrypted.extend_from_slice(b"+0175011+014+002+026+01");
    while decrypted.len() < 0x101 {
      decrypted.push(0);
    }
    for (i, &b) in decrypted.iter().enumerate() {
      if 18 + i < block.len() {
        wb(&mut block, 18 + i, b ^ 0xaa);
      }
    }
    let mut out = QuickTimeStreamMeta::new();
    decode_block(&block, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = out.gps_samples().first().unwrap();
    assert_eq!(
      s.speed_kph(),
      Some(11.0),
      "EEEkit spd = digits at offset 62"
    );
  }

  /// GPSType 1 Azdome accel-only block: when offset 65 has no `[-+]\d{3}`
  /// triple, the offset-173 branch fires AND back-fills date/time from offset
  /// 8 (QuickTimeStream.pl:1705-1710). Selection is by marker, not length.
  #[test]
  fn decode_type1_azdome_accel_offset_173_backfill() {
    let (mut block, _) = make_block(0x200);
    let mut decrypted = vec![0u8; 0x101];
    // The 8-byte detection preamble (XOR-0xaa of the GPSType-1 signature).
    wr(&mut decrypted, 0, b"\x00\x00XKZD\xfe\xfe");
    // No GPS coordinates (offset 38 stays NUL), but a valid date/time at
    // offset 8 + label.
    wr(&mut decrypted, 8, b"20180924224928");
    wb(&mut decrypted, 22, b'.');
    wr(&mut decrypted, 23, b"5567GP000000000");
    // Offset 65 is left as NULs (no `[-+]\d{3}` triple ⇒ branch A fails).
    // Offset 173: three signed-3-digit accel groups.
    wr(&mut decrypted, 173, b"+012-034+056");
    for (i, &b) in decrypted.iter().enumerate() {
      if 18 + i < block.len() {
        wb(&mut block, 18 + i, b ^ 0xaa);
      }
    }
    let mut out = QuickTimeStreamMeta::new();
    decode_block(&block, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = out.gps_samples().first().unwrap();
    // Date/time back-filled from offset 8 even though GPS is absent.
    assert_eq!(s.date_time(), Some("2018:09:24 22:49:28Z"));
    // Accelerometer from offset 173 (0.12 -0.34 0.56).
    assert_eq!(s.accelerometer(), Some("0.12 -0.34 0.56"));
  }

  /// GPSType 8 track is `GetFloat(0x64) + 180` with NO 360-wrap
  /// (QuickTimeStream.pl:1992), unlike GPSType 6 which does wrap.
  #[test]
  fn decode_type8_track_plus_180_no_wrap() {
    let (mut block, _) = make_block(0x100);
    // Detection: [\x01-\x0c] at 64, [\x01-\x1f] at 68, A NS EW at 72-74.
    wb(&mut block, 64, 0x05);
    wb(&mut block, 68, 0x10);
    wb(&mut block, 72, b'A');
    wb(&mut block, 73, b'N');
    wb(&mut block, 74, b'E');
    // date at 0x3c..0x48 (yr,mon,day) and hr/min/sec at 0x30.
    wr(&mut block, 0x30, &14u32.to_le_bytes());
    wr(&mut block, 0x34, &30u32.to_le_bytes());
    wr(&mut block, 0x38, &45u32.to_le_bytes());
    wr(&mut block, 0x3c, &2024u32.to_le_bytes());
    wr(&mut block, 0x40, &7u32.to_le_bytes());
    wr(&mut block, 0x44, &15u32.to_le_bytes());
    // track raw = 200.0 ⇒ +180 = 380.0 (must NOT wrap to 20.0).
    wr(&mut block, 0x64, &200.0f32.to_le_bytes());
    let mut out = QuickTimeStreamMeta::new();
    decode_block(&block, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    assert_eq!(out.gps_samples().first().unwrap().track(), Some(380.0));
  }

  /// GPSType 19 (70mai) does NOT set `$ddd`, so ConvertLatLon IS applied: the
  /// int32s/1e5 DDDMM.MMMM value 5116.071 becomes 51.2679° (not 51.16).
  #[test]
  fn decode_type19_70mai_applies_convert_lat_lon() {
    let (mut block, _) = make_block(0x100);
    wb(&mut block, 30, b'A');
    wb(&mut block, 51, b'V');
    wb(&mut block, 52, b'V');
    // lat int32s at 31 = 511_607_100 ⇒ /1e5 = 5116.071 (DDDMM.MMMM) ⇒
    // ConvertLatLon ⇒ 51 + 16.071/60 = 51.2679°.
    wr(&mut block, 31, &511_607_100i32.to_le_bytes());
    wr(&mut block, 35, &83_080_900i32.to_le_bytes()); // lon 830.809 ⇒ 8°30.8'
    wr(&mut block, 43, &42i32.to_le_bytes());
    let mut out = QuickTimeStreamMeta::new();
    decode_block(&block, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let lat = out.gps_samples().first().unwrap().latitude().expect("lat");
    assert!((lat - 51.267_85).abs() < 1e-3, "lat={lat}");
    // The brute-force-scan shape (no SampleTime) emits NO GPSDateTime
    // (QuickTimeStream.pl:2396 `SetGPSDateTime($et, $tagTbl, undef)` is a
    // no-op), matching a real mdat-embedded 70mai file.
    assert_eq!(out.gps_samples().first().unwrap().date_time(), None);
  }

  /// GPSType 19 (70mai) threads a per-sample decoding time through
  /// `SetGPSDateTime` (QuickTimeStream.pl:2396): with a CreateDate + SampleTime
  /// BOTH present, `GPSDateTime` = CreateDate + SampleTime
  /// (QuickTimeStream.pl:984-1006); with no CreateDate it stays empty (the `if
  /// defined $sampleTime and $$value{CreateDate}` guard). This pins the
  /// `process_free_gps` `sample_time` MECHANISM directly — the faithful 1:1 of
  /// the Perl that runs when a `gps `-dispatch sample carries a `$time[$i]`.
  /// (No live caller supplies a `Some` SampleTime today: the brute-force scan
  /// has none, and the `moov`-level `gps ` box carries no `stts`.)
  #[test]
  fn decode_type19_70mai_synthesizes_gps_date_time_from_sample_time() {
    let mut block = make_block(0x100).0;
    wb(&mut block, 30, b'A');
    wb(&mut block, 51, b'V');
    wb(&mut block, 52, b'V');
    wr(&mut block, 31, &511_607_100i32.to_le_bytes());
    wr(&mut block, 35, &83_080_900i32.to_le_bytes());
    wr(&mut block, 43, &42i32.to_le_bytes());

    // CreateDate raw 1904-epoch = 3_791_457_280 (= unix 1_708_612_480 =
    // 2024:02:22 14:34:40.000Z); SampleTime 2.0s ⇒ GPSDateTime 14:34:42.000Z.
    // `SetGPSDateTime` (QuickTimeStream.pl:1006) formats via
    // `ConvertUnixTime($sampleTime, 0, 3)` — the positive `$dec = 3` renders a
    // FIXED three-digit fractional second (`.000` for a whole second, no trim).
    let mut out = QuickTimeStreamMeta::new();
    decode_block_with_time(&block, 3_791_457_280, 2.0, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    assert_eq!(
      out.gps_samples().first().unwrap().date_time(),
      Some("2024:02:22 14:34:42.000Z"),
      "GPSDateTime = CreateDate + SampleTime"
    );
    // lat/lon still decode (ConvertLatLon applied).
    let lat = out.gps_samples().first().unwrap().latitude().expect("lat");
    assert!((lat - 51.267_85).abs() < 1e-3, "lat={lat}");

    // No CreateDate ⇒ no GPSDateTime even with a SampleTime.
    let mut out2 = QuickTimeStreamMeta::new();
    let mut state = FreeGpsState::new();
    process_free_gps(&block, None, Some(2.0), None, &mut state, &mut out2, None);
    assert_eq!(out2.gps_samples().first().unwrap().date_time(), None);
  }

  /// GPSType 14 (XBHT) records are 36 bytes wide, so two consecutive records
  /// must both decode (the old 33-byte stride mis-tracked the stream).
  #[test]
  fn decode_type14_xbht_two_records_36_byte_stride() {
    let (mut block, _) = make_block(0x100);
    let write_rec = |b: &mut [u8], start: usize, day: u8| {
      // rec[1..7] = yr,mon,day,hr,min,sec ; rec[7]=ss(<=9) ; rec[8]='A'.
      wb(b, start + 1, 24); // yr ⇒ 2024
      wb(b, start + 2, 7);
      wb(b, start + 3, day);
      wb(b, start + 4, 12);
      wb(b, start + 5, 30);
      wb(b, start + 6, 45);
      wb(b, start + 7, 0);
      wb(b, start + 8, b'A');
      wb(b, start + 9, b'N');
      wb(b, start + 10, b'E');
      wr(b, start + 16, &476_284u32.to_le_bytes()); // lat*1e4
      wr(b, start + 20, &83_080u32.to_le_bytes()); // lon*1e4
      wr(b, start + 28, &55u16.to_le_bytes()); // spd
    };
    // Detection marker for dispatch: hr/min/sec/A at 20-24 (first record at
    // rec_start=16 ⇒ A at 24).
    write_rec(&mut block, 16, 15);
    write_rec(&mut block, 16 + 36, 16);
    let mut out = QuickTimeStreamMeta::new();
    decode_block(&block, &mut out);
    assert_eq!(
      out.gps_samples().len(),
      2,
      "two 36-byte XBHT records must both decode"
    );
    assert_eq!(
      out.gps_samples().first().unwrap().date_time(),
      Some("2024:07:15 12:30:45.0")
    );
    assert_eq!(
      out.gps_samples().get(1).unwrap().date_time(),
      Some("2024:07:16 12:30:45.0")
    );
  }

  /// Build a self-contained Type-6 (Akaso) `freeGPS ` block of exactly
  /// `size` bytes (the scanner regex needs the 4-byte BE size header to have
  /// byte 0 and byte 3 NUL — so `size` must be ≤ 0xffff00 and a multiple of
  /// 256). Each block decodes to one GPS sample.
  fn make_type6_block(size: usize) -> Vec<u8> {
    assert!(size >= 0x80 && size % 256 == 0 && size <= 0xff_ff00);
    let mut block = vec![0u8; size];
    wr(&mut block, 0, &(size as u32).to_be_bytes());
    wr(&mut block, 4, b"freeGPS ");
    // Type-6 markers (QuickTimeStream.pl:1906): A@60, [NS]@68, [EW]@76.
    wb(&mut block, 60, b'A');
    wb(&mut block, 68, b'N');
    wb(&mut block, 76, b'W');
    // hr/min/sec @ 0x30, yr/mon/day @ 0x58, lat/lon floats @ 0x40/0x48.
    wr(&mut block, 0x30, &14u32.to_le_bytes());
    wr(&mut block, 0x34, &30u32.to_le_bytes());
    wr(&mut block, 0x38, &45u32.to_le_bytes());
    wr(&mut block, 0x58, &2024u32.to_le_bytes());
    wr(&mut block, 0x5c, &7u32.to_le_bytes());
    wr(&mut block, 0x60, &15u32.to_le_bytes());
    wr(&mut block, 0x40, &4737.7053f32.to_le_bytes());
    wr(&mut block, 0x48, &12209.901f32.to_le_bytes());
    block
  }

  /// FINDING 1 regression — two ADJACENT 0x8000 `freeGPS ` blocks must both
  /// decode without panicking. ExifTool reads media data in 0x8000-byte chunks
  /// keeping a 12-byte cross-chunk overlap (`substr($buff,-12)`,
  /// QuickTimeStream.pl:3711), so the second 0x8000 block starts ~12 bytes into
  /// the next window and `abs + len` overruns the 0x8000-byte window — the old
  /// `chunk[abs..abs+len]` slice panicked here. Bundled extends the buffer
  /// (`$more = $len - length($buff)`, :3768-3772); the port slices the block
  /// from the full `mdat` at its absolute offset.
  #[test]
  fn scan_media_data_two_adjacent_0x8000_blocks_no_panic() {
    let mut mdat = make_type6_block(GPS_BLOCK_SIZE); // block A: mdat[0..0x8000]
    mdat.extend_from_slice(&make_type6_block(GPS_BLOCK_SIZE)); // block B straddles boundary
    assert_eq!(mdat.len(), 2 * GPS_BLOCK_SIZE);
    // Wrap in a synthetic file so the absolute mdat offset is non-zero.
    let mut file = vec![0u8; 64];
    let mdat_offset = file.len() as u64;
    file.extend_from_slice(&mdat);
    let mut out = QuickTimeStreamMeta::new();
    let mut gp = GoProMeta::new();
    scan_media_data(
      &file,
      mdat_offset,
      mdat.len() as u64,
      None,
      None,
      false,
      &mut out,
      &mut gp,
      None,
    );
    assert_eq!(
      out.gps_samples().len(),
      2,
      "both adjacent 0x8000 freeGPS blocks must decode"
    );
  }

  // ── GoPro GP6 scan regressions (findings #2 + #3) ──────────────────────

  /// Build one 8-byte GPMF KLV record (4-byte tag + fmt + sample_size +
  /// 2-byte BE count), payload, then 4-byte NUL pad.
  fn gp_klv(tag: &[u8; 4], fmt: u8, sample_size: u8, count: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(tag);
    v.push(fmt);
    v.push(sample_size);
    v.extend_from_slice(&count.to_be_bytes());
    v.extend_from_slice(payload);
    while v.len() % 4 != 0 {
      v.push(0);
    }
    v
  }

  /// Build a complete GoPro `GP\x06\0\0` record carrying a DEVC→STRM→{SCAL,
  /// GPS5} with a single fix at `lat_deg` degrees (so one sample per record).
  /// The STRM carries the canonical SCAL vector ahead of GPS5 (GPS5 stays the
  /// LAST record so the GoPro.pm:884 last-in-container guard fires), matching
  /// real GoPro data where every GPS STRM begins with SCAL. The 16-byte GP6
  /// header is `GP\x06\0` + BE size + 8 reserved bytes (GoPro.pm:783-803).
  fn gp6_record_with_gps5(lat_deg: f64) -> Vec<u8> {
    // One GPS5 row: lat encoded as lat_deg * 10_000_000 (the SCAL[0] below
    // divides it back to `lat_deg`), the rest zero.
    let lat_e7 = (lat_deg * 10_000_000.0) as i32;
    let mut row = Vec::new();
    row.extend_from_slice(&lat_e7.to_be_bytes());
    row.extend_from_slice(&0i32.to_be_bytes());
    row.extend_from_slice(&0i32.to_be_bytes());
    row.extend_from_slice(&0i32.to_be_bytes());
    row.extend_from_slice(&0i32.to_be_bytes());
    let scal_payload: Vec<u8> = [10_000_000u32, 10_000_000, 1_000, 1_000, 100]
      .iter()
      .flat_map(|v| v.to_be_bytes())
      .collect();
    let scal = gp_klv(b"SCAL", 0x4c, 4, 5, &scal_payload);
    let gps5 = gp_klv(b"GPS5", 0x6c, 20, 1, &row);
    let mut strm_body = Vec::new();
    strm_body.extend_from_slice(&scal);
    strm_body.extend_from_slice(&gps5);
    let strm = gp_klv(b"STRM", 0, 1, strm_body.len() as u16, &strm_body);
    let devc = gp_klv(b"DEVC", 0, 1, strm.len() as u16, &strm);
    let mut rec = Vec::with_capacity(16 + devc.len());
    rec.extend_from_slice(b"GP\x06\0"); // 4-byte tag (GP, 0x06, NUL)
    rec.extend_from_slice(&(devc.len() as u32).to_be_bytes()); // size BE (hi byte 0)
    rec.extend_from_slice(&[0u8; 8]); // 8 reserved header bytes
    rec.extend_from_slice(&devc);
    rec
  }

  /// FINDING #2 regression — a GoPro GP6 record in a TRAILER (past the declared
  /// `mdat` payload) must still be scanned. QuickTimeStream.pl:3733-3736
  /// expands the scan window to EOF on the first valid GP6 record (`Seek(0,2)
  /// and $dataLen = Tell - MediaDataOffset`) because later records may live in
  /// a trailer. The pre-fix port clamped the scan to `mdat_offset + mdat_size`
  /// and dropped the trailer record.
  #[test]
  fn scan_media_data_gp6_trailer_record_is_scanned() {
    let rec_a = gp6_record_with_gps5(4.2); // inside the declared mdat
    let rec_b = gp6_record_with_gps5(8.4); // in the trailer (past mdat_size)
    let mut file = vec![0u8; 32];
    let mdat_offset = file.len() as u64;
    file.extend_from_slice(&rec_a);
    // mdat_size covers ONLY rec_a; rec_b sits AFTER the declared payload.
    let mdat_size = rec_a.len() as u64;
    file.extend_from_slice(&rec_b);
    let mut out = QuickTimeStreamMeta::new();
    let mut gp = GoProMeta::new();
    scan_media_data(
      &file,
      mdat_offset,
      mdat_size,
      None,
      None,
      false,
      &mut out,
      &mut gp,
      None,
    );
    // BOTH records must be scanned ⇒ 2 GPS samples (one per record). The
    // pre-fix code produced only 1 (the trailer record was never reached).
    assert_eq!(
      gp.gps_samples().len(),
      2,
      "the trailer GP6 record must be scanned after the first valid GP6 expands the window to EOF"
    );
  }

  /// FINDING A regression (R3) — the EOF window expansion is guarded by
  /// `unless ($found)` (QuickTimeStream.pl:3732-3737). When a freeGPS block is
  /// found FIRST it sets `$found = 1` (QuickTimeStream.pl:3753) WITHOUT
  /// expanding the window; a GP6 record that follows then sees `$found` already
  /// truthy, so it must NOT expand the scan past the declared `mdat` into a
  /// trailer. Layout: a full-0x8000 freeGPS block + an in-`mdat` GP6 record,
  /// with a SECOND GP6 record sitting in a trailer PAST `mdat_size`. The
  /// trailer record must NOT be scanned (the window stays clamped to `mdat`).
  /// The pre-fix port expanded unconditionally on any GP6 with `consumed > 0`,
  /// so it wrongly reached the trailer.
  #[test]
  fn scan_media_data_freegps_then_gp6_does_not_expand_to_trailer() {
    // Block 0: a full 0x8000-byte freeGPS block (found in chunk 0; sets
    // `found`, NO expansion — the freeGPS path is `$found = 1`).
    let free = make_type6_block(GPS_BLOCK_SIZE);
    // An in-`mdat` GP6 record immediately after the freeGPS block (at absolute
    // 0x8000); reached via the 12-byte cross-chunk carry. With `found` already
    // set, this GP6 must NOT expand the window.
    let gp6_in = gp6_record_with_gps5(4.2);
    // A trailer GP6 record PAST the declared `mdat` — must stay unscanned.
    let gp6_trailer = gp6_record_with_gps5(8.4);

    let mut mdat = Vec::new();
    mdat.extend_from_slice(&free);
    mdat.extend_from_slice(&gp6_in);
    let mut file = vec![0u8; 32];
    let mdat_offset = file.len() as u64;
    // `mdat_size` covers ONLY the freeGPS block + the in-mdat GP6 record.
    let mdat_size = mdat.len() as u64;
    file.extend_from_slice(&mdat);
    file.extend_from_slice(&gp6_trailer); // trailer, past the declared mdat

    let mut out = QuickTimeStreamMeta::new();
    let mut gp = GoProMeta::new();
    scan_media_data(
      &file,
      mdat_offset,
      mdat_size,
      None,
      None,
      false,
      &mut out,
      &mut gp,
      None,
    );
    // The freeGPS block yields exactly one QuickTime-stream GPS sample.
    assert_eq!(
      out.gps_samples().len(),
      1,
      "the leading freeGPS block must produce one sample"
    );
    // Exactly ONE GoPro sample — from the in-`mdat` GP6 only. The trailer GP6
    // must NOT be scanned because the freeGPS find already set `found`, so the
    // GP6 does not expand the window to EOF. (Pre-fix: 2 GoPro samples.)
    assert_eq!(
      gp.gps_samples().len(),
      1,
      "the trailer GP6 record must NOT be scanned: a prior freeGPS find blocks the EOF expansion (QuickTimeStream.pl:3732 `unless ($found)`)"
    );
    // The single GoPro sample is the in-mdat record (lat 4.2), not the trailer.
    let lat = gp.gps_samples().first().unwrap().latitude().expect("lat");
    assert!(
      (lat - 4.2).abs() < 1e-6,
      "the scanned GoPro sample is the in-mdat record (4.2), not the trailer (8.4): {lat}"
    );
  }

  /// FINDING #3 regression — a GoPro GP6 record whose consumed span crosses a
  /// 0x8000 scanner-chunk boundary must NOT be re-scanned, and the next record
  /// after the span must be found exactly once. QuickTimeStream.pl:3739-3741
  /// seeks to the ABSOLUTE consumed end (`Seek($start+$size); $pos = …; $buf2
  /// = ''`). The pre-fix port advanced only inside the current chunk, so the
  /// loop tail (`pos += chunk.len() - 12`) re-windowed INSIDE the consumed
  /// span and could duplicate the records that followed it.
  #[test]
  fn scan_media_data_gp6_span_crossing_chunk_boundary_no_duplicate() {
    // Pad rec_a so its consumed span ends a few bytes PAST the first 0x8000
    // chunk boundary. The GP6 record's body size is bounded (`<= 0xFFFF`), so
    // we lead with NUL filler inside `mdat` to push the magic close to the
    // boundary, with the record body straddling it.
    let rec_a = gp6_record_with_gps5(4.2);
    let rec_b = gp6_record_with_gps5(8.4);
    // Place rec_a's magic so the 16-byte header + body end ~8 bytes past
    // GPS_BLOCK_SIZE (0x8000). The scanner finds the magic in the first full
    // chunk (the chunk includes the 12-byte cross-window carry, so the magic
    // is visible) and `process_gp6` consumes the whole record from `tail`.
    let lead = GPS_BLOCK_SIZE - rec_a.len() + 8;
    let mut mdat = vec![0u8; lead];
    mdat.extend_from_slice(&rec_a); // ends at lead + rec_a.len() = 0x8000 + 8
    mdat.extend_from_slice(&rec_b); // immediately after the consumed span
    let mut file = vec![0u8; 16];
    let mdat_offset = file.len() as u64;
    let mdat_size = mdat.len() as u64;
    file.extend_from_slice(&mdat);
    let mut out = QuickTimeStreamMeta::new();
    let mut gp = GoProMeta::new();
    scan_media_data(
      &file,
      mdat_offset,
      mdat_size,
      None,
      None,
      false,
      &mut out,
      &mut gp,
      None,
    );
    // Exactly 2 samples — one per record, no duplication from re-scanning the
    // cross-boundary consumed span.
    assert_eq!(
      gp.gps_samples().len(),
      2,
      "a GP6 record spanning the 0x8000 boundary plus the following record must each be scanned exactly once"
    );
    // The two distinct latitudes confirm both records (not one record twice).
    let lats: Vec<i64> = gp
      .gps_samples()
      .iter()
      .filter_map(|s| s.latitude().map(|v| (v * 10.0).round() as i64))
      .collect();
    assert!(
      lats.contains(&42) && lats.contains(&84),
      "both records' fixes present: {lats:?}"
    );
  }

  /// R2 finding regression — a GP6 consumed span ending EXACTLY at the 0x8000
  /// chunk boundary (`abs_end == chunk_end`) must also re-window to the
  /// absolute end and clear the carry. The R1 fix only re-windowed on `abs_end
  /// > chunk_end`, so the exact-boundary case fell through to the in-chunk
  /// `search_off` and the outer 12-byte carry could re-scan the consumed span.
  /// QuickTimeStream.pl:3739-3741 seeks unconditionally; the fixed port mirrors
  /// that. Each record must be scanned exactly once.
  #[test]
  fn scan_media_data_gp6_span_ending_exactly_at_chunk_boundary() {
    let rec_a = gp6_record_with_gps5(4.2);
    let rec_b = gp6_record_with_gps5(8.4);
    // `process_gp6` walks the consecutive rec_a+rec_b sequence, so the consumed
    // span is both records. Place the magic so the span ends EXACTLY at the
    // first 0x8000 boundary: lead = GPS_BLOCK_SIZE - (rec_a + rec_b).
    let lead = GPS_BLOCK_SIZE - rec_a.len() - rec_b.len();
    let mut mdat = vec![0u8; lead];
    mdat.extend_from_slice(&rec_a);
    mdat.extend_from_slice(&rec_b); // consumed span ends at exactly GPS_BLOCK_SIZE
    let mut file = vec![0u8; 16];
    let mdat_offset = file.len() as u64;
    let mdat_size = mdat.len() as u64;
    file.extend_from_slice(&mdat);
    let mut out = QuickTimeStreamMeta::new();
    let mut gp = GoProMeta::new();
    scan_media_data(
      &file,
      mdat_offset,
      mdat_size,
      None,
      None,
      false,
      &mut out,
      &mut gp,
      None,
    );
    assert_eq!(
      gp.gps_samples().len(),
      2,
      "a GP6 span ending exactly at the 0x8000 boundary must not be re-scanned"
    );
    let lats: Vec<i64> = gp
      .gps_samples()
      .iter()
      .filter_map(|s| s.latitude().map(|v| (v * 10.0).round() as i64))
      .collect();
    assert!(
      lats.contains(&42) && lats.contains(&84),
      "both records present exactly once: {lats:?}"
    );
  }

  /// FINDING 1 corollary — a block whose declared length runs PAST the end of
  /// `mdat` must stop the scan cleanly (no panic, no out-of-bounds), mirroring
  /// the bundled short-read bail `last unless $raf->Read == $more`
  /// (QuickTimeStream.pl:3770).
  #[test]
  fn scan_media_data_block_overrunning_mdat_is_safe() {
    let mut block = make_type6_block(0x200);
    // Lie about the size: claim 0x10000 bytes but the buffer is only 0x200.
    wr(&mut block, 0, &0x0001_0000u32.to_be_bytes());
    let mut file = vec![0u8; 32];
    let mdat_offset = file.len() as u64;
    file.extend_from_slice(&block);
    let mut out = QuickTimeStreamMeta::new();
    let mut gp = GoProMeta::new();
    // Must not panic; the over-long block is not dispatched.
    scan_media_data(
      &file,
      mdat_offset,
      block.len() as u64,
      None,
      None,
      false,
      &mut out,
      &mut gp,
      None,
    );
    assert!(out.gps_samples().is_empty());
  }

  /// Build one ATC 52-byte record into `block` at `rec_off` with the given
  /// date/time (zero decryption keys ⇒ plaintext) and a distinct latitude.
  fn write_atc_record(
    block: &mut [u8],
    rec_off: usize,
    ymd: (u16, u8, u8),
    hms: (u8, u8, u8),
    lat_e7: i32,
  ) {
    wb(block, rec_off + 0x0d, hms.0.wrapping_sub(1)); // stored hour is H-1
    wb(block, rec_off + 0x0e, hms.1);
    wb(block, rec_off + 0x0f, hms.2);
    wr(block, rec_off + 0x10, &lat_e7.to_le_bytes());
    wr(block, rec_off + 0x15, b"ATC");
    wr(block, rec_off + 0x18, &(-1_221_650_167i32).to_le_bytes());
    wr(block, rec_off + 0x20, &2000i32.to_le_bytes());
    wr(block, rec_off + 0x24, &0i16.to_le_bytes());
    wr(block, rec_off + 0x28, &100_000i32.to_le_bytes());
    wr(block, rec_off + 0x2c, &ymd.0.to_le_bytes());
    wb(block, rec_off + 0x2e, ymd.1);
    wb(block, rec_off + 0x2f, ymd.2);
  }

  /// FINDING 4 regression — the ATC ring buffer is rewritten WHOLE into every
  /// block, so a second block that repeats the same records plus one newer one
  /// must emit ONLY the newer record (bundled keeps `$$et{FreeGPS2}{Then}`
  /// across blocks and emits records strictly newer than it,
  /// QuickTimeStream.pl:2057-2156). Without cross-block state the stale
  /// coordinates would be re-emitted and `first_fix()` could pick an old one.
  #[test]
  fn type11_atc_cross_block_suppresses_stale_records() {
    // Block 1: two records at 14:30:45 and 14:30:46 (both new on first sight).
    let mut block1 = make_block(0x100).0;
    wr(&mut block1, 0x45, b"ATC");
    write_atc_record(&mut block1, 0x30, (2024, 7, 15), (14, 30, 45), 476_284_215);
    write_atc_record(
      &mut block1,
      0x30 + 52,
      (2024, 7, 15),
      (14, 30, 46),
      476_284_300,
    );
    // Block 2: REPEATS both old records, then adds a NEWER one at 14:30:47.
    let mut block2 = make_block(0x100).0;
    wr(&mut block2, 0x45, b"ATC");
    write_atc_record(&mut block2, 0x30, (2024, 7, 15), (14, 30, 45), 476_284_215);
    write_atc_record(
      &mut block2,
      0x30 + 52,
      (2024, 7, 15),
      (14, 30, 46),
      476_284_300,
    );
    write_atc_record(
      &mut block2,
      0x30 + 104,
      (2024, 7, 15),
      (14, 30, 47),
      476_284_999,
    );

    let mut state = FreeGpsState::new();
    let mut out = QuickTimeStreamMeta::new();
    process_free_gps(&block1, None, None, None, &mut state, &mut out, None);
    assert_eq!(out.gps_samples().len(), 2, "block 1 emits both new records");
    process_free_gps(&block2, None, None, None, &mut state, &mut out, None);
    assert_eq!(
      out.gps_samples().len(),
      3,
      "block 2 must emit ONLY the one newer record, not the two repeats"
    );
    assert_eq!(
      out.gps_samples().get(2).unwrap().date_time(),
      Some("2024:07:15 14:30:47Z"),
      "the third sample is the new 14:30:47 record"
    );
  }

  /// FINDING 5 regression — a void-fix `V` RMC sentence (the no-fix sentinel
  /// dashcams emit at startup) must yield NO sample. Bundled gates the RMC
  /// status with `,A?,` (QuickTimeStream.pl:1733), so a `V` makes the whole
  /// regex fail and no fields are copied.
  #[test]
  fn type2_nmea_rmc_void_status_yields_no_sample() {
    // A Type-2 block: 14 ASCII digits at offset 52, then an RMC with status V.
    let mut block = make_block(0x100).0;
    wr(&mut block, 52, b"20180919100959");
    let rmc = b"$GPRMC,080951.000,V,,,,,000.0,,190918,,,N";
    wr(&mut block, 0x50, rmc);
    let mut out = QuickTimeStreamMeta::new();
    decode_block(&block, &mut out);
    assert!(
      out.gps_samples().is_empty(),
      "a void (V) RMC must not produce a GPS sample"
    );
  }

  /// FINDING 5 regression — a `0` GGA fix-quality must yield NO sample (no
  /// lat/lon, no altitude). Bundled gates GGA with `[1-6]?`
  /// (QuickTimeStream.pl:1740), so fix `0` fails the whole regex.
  #[test]
  fn type2_nmea_gga_zero_fix_yields_no_sample() {
    let mut block = make_block(0x100).0;
    wr(&mut block, 52, b"20180919100959");
    // Only a GGA (no RMC) with fix quality 0 — must copy nothing.
    let gga = b"$GPGGA,123519,4807.038,N,01131.000,E,0,08,0.9,545.4,M,,,";
    wr(&mut block, 0x50, gga);
    let mut out = QuickTimeStreamMeta::new();
    decode_block(&block, &mut out);
    assert!(
      out.gps_samples().is_empty(),
      "a no-fix (0) GGA must not produce a GPS sample"
    );
  }

  /// FINDING 5 positive control — a `V`-status RMC is rejected but a sibling
  /// valid `A` GGA in the same block still supplies a fix (the gates are
  /// per-sentence, mirroring the two independent bundled regexes).
  #[test]
  fn type2_nmea_active_gga_still_decodes_when_rmc_void() {
    let mut block = make_block(0x100).0;
    wr(&mut block, 52, b"20180919100959");
    let payload = b"$GPRMC,080951.000,V,,,,,,,190918,,,N\r\n$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,,,";
    wr(&mut block, 0x50, payload);
    let mut out = QuickTimeStreamMeta::new();
    decode_block(&block, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = out.gps_samples().first().unwrap();
    assert!(s.has_coordinates(), "the active GGA supplies a coordinate");
    assert_eq!(s.altitude_m(), Some(545.4));
  }

  /// `parse_nmea_rmc` accepts an empty status field (the `A?` matches empty),
  /// but rejects `V`.
  #[test]
  fn parse_nmea_rmc_status_gate() {
    let mut t = FreeGpsTags::new();
    parse_nmea_rmc(
      b"$GPRMC,132230.000,,4721.35197,N,00830.80859,E,22.5,199.8,141222,,,A",
      &mut t,
    );
    assert!(t.lat.is_some(), "empty status (A?) is accepted");

    let mut tv = FreeGpsTags::new();
    parse_nmea_rmc(
      b"$GPRMC,132230.000,V,4721.35197,N,00830.80859,E,22.5,199.8,141222,,,A",
      &mut tv,
    );
    assert!(tv.lat.is_none(), "V status copies nothing");
    assert!(tv.yr.is_none());
  }

  /// RMC lat/lon must match `(\d+\.\d+)` (digits-dot-digits) —
  /// QuickTimeStream.pl:1733. An integer-only or empty lat field is rejected by
  /// the bundled regex (the whole RMC match fails → nothing copied).
  #[test]
  fn parse_nmea_rmc_lat_lon_shape_gate() {
    // Integer-only lat field `4721` (no dot) — the regex would not match.
    let mut t = FreeGpsTags::new();
    parse_nmea_rmc(
      b"$GPRMC,132230.000,A,4721,N,00830.80859,E,22.5,199.8,141222,,,A",
      &mut t,
    );
    assert!(t.lat.is_none(), "integer-only lat must be rejected");
  }

  /// GGA altitude `(-?\d+\.?\d*)?` is followed by `,M?` (QuickTimeStream.pl:1740):
  /// the comma after the altitude MUST be present (field 10 must exist), but the
  /// units field's CONTENT is unconstrained because `M?` is zero-width-optional.
  /// Verified vs Perl: `M`/``/`F`/`ft` all match; a GGA whose altitude is the
  /// last field (no trailing comma) does NOT match.
  #[test]
  fn parse_nmea_gga_unit_field_gate() {
    // Units field `F` (feet) is ACCEPTED — `M?` does not constrain it.
    let mut t = FreeGpsTags::new();
    parse_nmea_gga(
      b"$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,F,,,,",
      &mut t,
    );
    assert_eq!(t.alt, Some(545.4), "non-M units field is still accepted");

    // Empty units field (trailing comma present) is accepted.
    let mut t2 = FreeGpsTags::new();
    parse_nmea_gga(
      b"$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,,,,,",
      &mut t2,
    );
    assert_eq!(t2.alt, Some(545.4), "empty units field is accepted");

    // NO comma after the altitude (altitude is the last field) ⇒ the whole GGA
    // regex fails ⇒ nothing copied (the `,M?` comma is mandatory).
    let mut t3 = FreeGpsTags::new();
    parse_nmea_gga(
      b"$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4",
      &mut t3,
    );
    assert_eq!(t3.alt, None, "altitude with no trailing comma is rejected");
  }

  /// Build a Type-17 (Viofo A119S binary) freeGPS block matching the bundled
  /// Rexing dump (QuickTimeStream.pl:2317-2322): `A`/`N`/`W` at offset 72, the
  /// `x48V6` date/time, and the lat/lon floats `e9 7e 90 43` / `48 76 17 45`
  /// (≈ 288.99 / 2423.39). `word0` (offset 0) is NOT `0x00400000`, so the 17c
  /// branch never fires — only the KodakVersion gate selects 17b.
  fn make_type17_rexing_block() -> Vec<u8> {
    let mut b = vec![0u8; 0x100];
    wr(&mut b, 0, &0x0100u32.to_be_bytes()); // box length (BE), LE != 0x400000
    wr(&mut b, 4, b"freeGPS ");
    wb(&mut b, 0x48, b'A');
    wb(&mut b, 0x49, b'N');
    wb(&mut b, 0x4a, b'W');
    wb(&mut b, 0x4b, 0);
    wr(&mut b, 0x30, &14u32.to_le_bytes()); // hr
    wr(&mut b, 0x34, &34u32.to_le_bytes()); // min
    wr(&mut b, 0x38, &40u32.to_le_bytes()); // sec
    wr(&mut b, 0x3c, &2024u32.to_le_bytes()); // yr
    wr(&mut b, 0x40, &2u32.to_le_bytes()); // mon
    wr(&mut b, 0x44, &22u32.to_le_bytes()); // day
    wr(&mut b, 0x4c, &[0xe9, 0x7e, 0x90, 0x43]); // lat float 288.99
    wr(&mut b, 0x50, &[0x48, 0x76, 0x17, 0x45]); // lon float 2423.39
    wr(&mut b, 0x54, &50.0f32.to_le_bytes()); // spd (knots)
    wr(&mut b, 0x58, &90.0f32.to_le_bytes()); // trk
    b
  }

  /// GPSType 17b (Rexing V1-4k) — when `KodakVersion == "3.01.054"`, the raw
  /// lat/lon floats are scaled `(lat-187.982162849635)/3` /
  /// `(lon-2199.19873715495)/2` and treated as decimal degrees
  /// (QuickTimeStream.pl:2323-2327). Oracle-verified vs bundled ExifTool 13.59
  /// (`GPSLatitude 33.6697742486894`, `GPSLongitude -112.096920485025`).
  #[test]
  fn type17b_rexing_kodak_version_scales_lat_lon() {
    let block = make_type17_rexing_block();
    let mut out = QuickTimeStreamMeta::new();
    decode_block_kodak(&block, "3.01.054", &mut out);
    assert_eq!(out.gps_samples().len(), 1, "one 17b sample");
    let s = out.gps_samples().first().unwrap();
    let lat = s.latitude().expect("lat");
    let lon = s.longitude().expect("lon");
    // 17b is `$ddd = 1` ⇒ NO ConvertLatLon; `W` ref negates the longitude.
    assert!(
      (lat - 33.669_774_248_689_4).abs() < 1e-9,
      "17b lat {lat} (want 33.6697742486894)"
    );
    assert!(
      (lon - -112.096_920_485_025).abs() < 1e-9,
      "17b lon {lon} (want -112.096920485025)"
    );
    // 17b does NOT divide speed by knotsToKph (unlike 17c): 50 knots * 1.852.
    assert!(
      (s.speed_kph().expect("spd") - 92.6).abs() < 1e-4,
      "spd 92.6"
    );
    assert_eq!(s.track(), Some(90.0));
    assert_eq!(s.date_time(), Some("2024:02:22 14:34:40Z"));
  }

  /// Control — the SAME Type-17 block WITHOUT a `KodakVersion` (or a
  /// non-matching one) must take the DEFAULT Type-17 branch: lat/lon are raw
  /// DDDMM.MMMM fed to ConvertLatLon, NOT the 17b scaling. Oracle-verified vs
  /// bundled (`GPSLatitude 3.48319142659505`, `GPSLongitude -24.3898763020833`).
  #[test]
  fn type17_default_without_kodak_version_uses_convertlatlon() {
    let block = make_type17_rexing_block();
    // No KodakVersion ⇒ default-17.
    let mut out = QuickTimeStreamMeta::new();
    decode_block(&block, &mut out);
    let s = out.gps_samples().first().unwrap();
    let lat = s.latitude().expect("lat");
    let lon = s.longitude().expect("lon");
    assert!(
      (lat - 3.483_191_426_595_05).abs() < 1e-9,
      "default-17 lat {lat} (want 3.48319142659505)"
    );
    assert!(
      (lon - -24.389_876_302_083_3).abs() < 1e-9,
      "default-17 lon {lon} (want -24.3898763020833)"
    );

    // A NON-matching KodakVersion is also default-17 (only "3.01.054" gates 17b).
    let mut out2 = QuickTimeStreamMeta::new();
    decode_block_kodak(&block, "9.99.999", &mut out2);
    let s2 = out2.gps_samples().first().unwrap();
    assert!(
      (s2.latitude().expect("lat") - 3.483_191_426_595_05).abs() < 1e-9,
      "non-matching KodakVersion stays default-17"
    );
  }

  // ─── Process_text (Rove/Kingslim/general) ─────────────────────────────

  #[test]
  fn process_text_rmc_decimal_degrees_emitted() {
    // QuickTimeStream.pl:1066-1083 — `$GPRMC` ASCII sentence in raw text.
    // Sample: "$GPRMC,082138,A,5330.6683,N,00641.9749,W,012.5,87.86,050213,002.1,A"
    // Lat = (53 + 30.6683/60) = 53.5111... ; Lon = -(6 + 41.9749/60) = -6.69958...
    let raw = b"$GPRMC,082138.0,A,5330.6683,N,00641.9749,W,012.5,87.86,050213,002.1,A";
    let mut out = QuickTimeStreamMeta::new();
    process_text(raw, None, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = &out.gps_samples()[0];
    assert!((s.latitude().unwrap() - 53.51113).abs() < 1e-4);
    assert!((s.longitude().unwrap() + 6.69958).abs() < 1e-4);
    assert!(s.date_time().unwrap().starts_with("2013:02:05 08:21:38"));
    // 12.5 knots * 1.852 = 23.15 kph
    assert!((s.speed_kph().unwrap() - 23.15).abs() < 0.1);
    assert!((s.track().unwrap() - 87.86).abs() < 0.01);
  }

  #[test]
  fn process_text_gga_altitude_decoded() {
    // QuickTimeStream.pl:1084-1092 — GPGGA sentence with altitude.
    let raw = b"$GPGGA,123456.0,4721.35197,N,00830.80859,E,1,08,1.2,123.4,M,0.0,M,,";
    let mut out = QuickTimeStreamMeta::new();
    process_text(raw, None, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = &out.gps_samples()[0];
    assert!((s.altitude_m().unwrap() - 123.4).abs() < 1e-4);
    assert!((s.latitude().unwrap() - (47.0 + 21.35197 / 60.0)).abs() < 1e-4);
    assert!((s.longitude().unwrap() - (8.0 + 30.80859 / 60.0)).abs() < 1e-4);
  }

  #[test]
  fn process_text_g_sentence_decoded() {
    // QuickTimeStream.pl:1094-1098 — `$G:2025-01-15 12:34:56-N47.628-W008.514-S25`.
    let raw = b"$G:2025-01-15 12:34:56-N47.628421-W008.513889-S25";
    let mut out = QuickTimeStreamMeta::new();
    process_text(raw, None, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = &out.gps_samples()[0];
    assert!((s.latitude().unwrap() - 47.628421).abs() < 1e-5);
    assert!((s.longitude().unwrap() + 8.513889).abs() < 1e-5);
    assert!(s.date_time().unwrap().contains("2025:01:15 12:34:56"));
    assert_eq!(s.speed_kph(), Some(25.0));
  }

  #[test]
  fn process_text_truncated_rmc_does_not_emit_sample() {
    // Truncated mid-sentence — must not produce a GPS fix.
    let raw = b"$GPRMC,082138.0,A,5330.6683,N";
    let mut out = QuickTimeStreamMeta::new();
    process_text(raw, None, &mut out);
    assert!(out.gps_samples().is_empty());
  }

  #[test]
  fn process_text_corrupt_rmc_does_not_panic() {
    // Garbage data — must not panic; ideally produces no sample.
    let raw = b"$GPRMC,XXXX,YYY,ZZZZ";
    let mut out = QuickTimeStreamMeta::new();
    process_text(raw, None, &mut out);
    // (the fixed-width hr/min parse will fail on `XXXX`; nothing emitted.)
    assert!(out.gps_samples().is_empty());
  }

  #[test]
  fn process_text_rove_xor_aa_binary_block_decoded() {
    // QuickTimeStream.pl:1175 — the BlueSkySea `\0\0..\xaa\xaa` cipher.
    // Build a 282-byte buffer whose offset 8 starts with the XOR'd date
    // "20190820" (0x32 ^ 0xaa = 0x98 etc.). We construct the plaintext and
    // XOR it back to ciphertext.
    let mut data = vec![0u8; 282];
    // BlueSkySea sig: leading `\0\0..\xaa\xaa` at offset 4..6.
    data[4] = 0xaa;
    data[5] = 0xaa;
    // Encrypted date+time `20190820075157` at offset 8.
    for (i, &c) in b"20190820075157".iter().enumerate() {
      data[8 + i] = c ^ 0xaa;
    }
    // Latitude `N48515873` at offset 38 (9 bytes).
    for (i, &c) in b"N48515873".iter().enumerate() {
      data[38 + i] = c ^ 0xaa;
    }
    // Longitude `E002197769` at offset 47 (10 bytes).
    for (i, &c) in b"E002197769".iter().enumerate() {
      data[47 + i] = c ^ 0xaa;
    }
    // Altitude `+0031` at offset 0x39 (5 bytes).
    for (i, &c) in b"+0031".iter().enumerate() {
      data[0x39 + i] = c ^ 0xaa;
    }
    // Speed `045` at offset 0x3e (3 bytes).
    for (i, &c) in b"045".iter().enumerate() {
      data[0x3e + i] = c ^ 0xaa;
    }
    let mut out = QuickTimeStreamMeta::new();
    process_text(&data, None, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = &out.gps_samples()[0];
    assert!(s.date_time().unwrap().contains("2019:08:20 07:51:57"));
    assert!((s.latitude().unwrap() - (48.0 + 515873.0 / 600000.0)).abs() < 1e-4);
    assert!((s.longitude().unwrap() - (2.0 + 197769.0 / 600000.0)).abs() < 1e-4);
    assert_eq!(s.altitude_m(), Some(31.0));
    assert_eq!(s.speed_kph(), Some(45.0));
  }

  // ─── Process_text fallbacks (Mini / Roadhawk / Thinkware / DJI) ────────

  #[test]
  fn process_text_mini_0806_decoded() {
    // QuickTimeStream.pl:1232-1248. `A,DDMMYY,HHMMSS.sss,DDMM.MMMM,N,DDDMM.MMMM,
    // W,speed,altM,accX,accY,accZ;`.
    let raw = b"A,270519,201555.000,3356.8925,N,08420.2071,W,000.0,331.0M,+01.84,-09.80,-00.61;\n";
    let mut out = QuickTimeStreamMeta::new();
    process_text(raw, None, &mut out);
    assert_eq!(out.gps_samples().len(), 1, "one Mini fix");
    let s = &out.gps_samples()[0];
    // (33 + 56.8925/60) N, -(84 + 20.2071/60) W.
    assert!((s.latitude().unwrap() - (33.0 + 56.8925 / 60.0)).abs() < 1e-6);
    assert!((s.longitude().unwrap() + (84.0 + 20.2071 / 60.0)).abs() < 1e-6);
    assert_eq!(s.date_time().as_deref(), Some("2019:05:27 20:15:55.000Z"));
    assert_eq!(s.altitude_m(), Some(331.0));
    assert_eq!(s.speed_kph(), Some(0.0));
    // Accelerometer keeps the RAW split tokens (NOT parsed floats).
    assert_eq!(s.accelerometer(), Some("+01.84 -09.80 -00.61"));
  }

  #[test]
  fn process_text_roadhawk_decoded() {
    // QuickTimeStream.pl:1250-1269 — the substitution-encoded buffer (the
    // verbatim bundled example) decodes to `X..Y..Z..G..$GPRMC,..`.
    let raw = b".;;;;D?JL;6+;;;D;R?;4;;;;DBB;;O;;;=D;L;;HO71G>F;-?=J-F:FNJJ;\
DPP-JF3F;;PL=DBRLBF0F;=?DNF-RD-PF;N;?=JF;;?D=F:*6F~";
    let mut out = QuickTimeStreamMeta::new();
    process_text(raw, None, &mut out);
    assert_eq!(out.gps_samples().len(), 1, "one Roadhawk fix");
    let s = &out.gps_samples()[0];
    // Decoded `$GPRMC,082138,A,5330.6683,N,00641.9749,W,012.5,87.86,050213,..`.
    assert!((s.latitude().unwrap() - (53.0 + 30.6683 / 60.0)).abs() < 1e-5);
    assert!((s.longitude().unwrap() + (6.0 + 41.9749 / 60.0)).abs() < 1e-5);
    assert_eq!(s.date_time().as_deref(), Some("2013:02:05 08:21:38Z"));
    assert!((s.speed_kph().unwrap() - 23.15).abs() < 1e-4);
    assert_eq!(s.track(), Some(87.86));
    assert_eq!(
      s.accelerometer(),
      Some("0000.2340 -000.0720 0000.9900 0001.0400")
    );
  }

  #[test]
  fn process_text_thinkware_decoded() {
    // QuickTimeStream.pl:1271-1286 — `gsensori,..;GNRMC,..;CAR,..` (no leading
    // `$`). GPSDateTime seconds are INTEGER (`%.2d` drops the `.00`).
    let raw = b"gsensori,4,512,-67,-12,100;GNRMC,161313.00,A,4529.87489,N,07337.01215,W,\
6.225,35.34,310819,,,A*52;CAR,0,0,0,0.0,0,0,0,0,0,0,0,0";
    let mut out = QuickTimeStreamMeta::new();
    process_text(raw, None, &mut out);
    assert_eq!(out.gps_samples().len(), 1, "one Thinkware fix");
    let s = &out.gps_samples()[0];
    assert!((s.latitude().unwrap() - (45.0 + 29.87489 / 60.0)).abs() < 1e-6);
    assert!((s.longitude().unwrap() + (73.0 + 37.01215 / 60.0)).abs() < 1e-6);
    assert_eq!(s.date_time().as_deref(), Some("2019:08:31 16:13:13Z"));
    // 6.225 knots * 1.852 = 11.5287.
    assert!((s.speed_kph().unwrap() - 11.5287).abs() < 1e-4);
    assert_eq!(s.track(), Some(35.34));
    let ex = s.text_extras().expect("text extras");
    assert_eq!(ex.gsensor(), Some("4,512,-67,-12,100"));
    assert_eq!(ex.car(), Some("0,0,0,0.0,0,0,0,0,0,0,0,0"));
  }

  #[test]
  fn process_text_dji_telemetry_decoded() {
    // QuickTimeStream.pl:1213-1230 — `GPS (lon, lat, alt)` is lon-then-lat;
    // altitude from H, speed from H.S, distance from D.
    let raw = b"F/3.5, SS 1000, ISO 100, EV 0, GPS (8.6499, 53.1665, 18), \
D 24.26m, H 6.00m, H.S 2.10m/s, V.S 0.00m/s \n";
    let mut out = QuickTimeStreamMeta::new();
    process_text(raw, None, &mut out);
    assert_eq!(out.gps_samples().len(), 1, "one DJI fix");
    let s = &out.gps_samples()[0];
    // lat = $2 = 53.1665, lon = $1 = 8.6499 (decimal degrees, no ConvertLatLon).
    assert!((s.latitude().unwrap() - 53.1665).abs() < 1e-6);
    assert!((s.longitude().unwrap() - 8.6499).abs() < 1e-6);
    assert_eq!(s.altitude_m(), Some(6.0)); // H 6.00m
    // 2.10 m/s * 3.6 = 7.56 km/h.
    assert!((s.speed_kph().unwrap() - 7.56).abs() < 1e-6);
    let ex = s.text_extras().expect("text extras");
    // Distance 24.26 m/s * 3.6 = 87.336 (km/h, ExifTool's mis-named field).
    assert!((ex.distance().unwrap() - 87.336).abs() < 1e-6);
    assert_eq!(ex.vertical_speed(), Some("0.00")); // raw, rendered "$val m/s"
    assert_eq!(ex.fnumber(), Some(3.5));
    assert_eq!(ex.exposure_time_s(), Some(1.0 / 1000.0));
    assert_eq!(ex.exposure_compensation(), Some(0.0));
    assert_eq!(ex.iso(), Some("100"));
  }

  #[test]
  fn process_timed_text_stores_text_and_stamps_track() {
    // The timed-text wrapper stores `Text => $buff` (a plain-ASCII sample with no
    // `\0[^\0]`) and stamps the produced fix with the enclosing `Track<N>`.
    let raw = b"A,270519,201555.000,3356.8925,N,08420.2071,W,000.0,331.0M,+01.84,-09.80,-00.61;\n";
    let mut out = QuickTimeStreamMeta::new();
    let doc = out.open_doc();
    process_timed_text(raw, 1, doc, Some(0.0), Some(1.0), &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = &out.gps_samples()[0];
    assert_eq!(
      s.text_extras().and_then(|e| e.text()),
      Some(core::str::from_utf8(raw).unwrap())
    );
    assert_eq!(s.sample_time(), Some(0.0));
    assert_eq!(s.sample_duration(), Some(1.0));
    assert_eq!(s.doc(), Some(doc));
  }

  // ─── ProcessFMAS (Vantrue N2S) ────────────────────────────────────────

  #[test]
  fn process_fmas_decodes_synthetic_record() {
    // QuickTimeStream.pl:3580-3609. Build a 160-byte sample matching the
    // bundled `^FMAS\0{4}.{72}SAMM.{36}A/s` regex with placed fields.
    let mut d = vec![0u8; 160];
    d[0..8].copy_from_slice(b"FMAS\0\0\0\0");
    d[80..84].copy_from_slice(b"SAMM");
    d[120] = b'A';
    // Date/time block at 0x60: yr=2025 LE u16, mon=6, day=15, hr=14, min=30, sec=45.
    d[0x60..0x62].copy_from_slice(&2025u16.to_le_bytes());
    d[0x62] = 6;
    d[0x63] = 15;
    d[0x64] = 14;
    d[0x65] = 30;
    d[0x66] = 45;
    // Markers at 0x78..0x7a (AWN): A E N => longitude E, latitude N
    d[0x78] = b'A';
    d[0x79] = b'E'; // E/W
    d[0x7a] = b'N'; // N/S
    // Longitude: deg=8, min=30, frac=600 → 30.1 minutes
    d[0x7b] = 8;
    d[0x7c] = 30;
    d[0x7d] = 0; // padding zero byte
    d[0x7e..0x80].copy_from_slice(&600u16.to_le_bytes());
    // Latitude: deg=47, min=37, frac=4200 → 37.7 minutes
    d[0x80] = 47;
    d[0x81] = 37;
    d[0x82..0x84].copy_from_slice(&4200u16.to_le_bytes());
    // Speed=50 mph, track=180
    d[0x84..0x86].copy_from_slice(&50u16.to_le_bytes());
    d[0x86..0x88].copy_from_slice(&180u16.to_le_bytes());
    // Acceleration X/Y/Z f32 at 0x6c
    d[0x6c..0x70].copy_from_slice(&0.1f32.to_le_bytes());
    d[0x70..0x74].copy_from_slice(&0.2f32.to_le_bytes());
    d[0x74..0x78].copy_from_slice(&0.3f32.to_le_bytes());
    let mut out = QuickTimeStreamMeta::new();
    process_fmas(&d, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = &out.gps_samples()[0];
    // Lat = 47 + (37 + 4200/6000)/60 ≈ 47.628333
    let want_lat = 47.0 + (37.0 + 4200.0 / 6000.0) / 60.0;
    assert!((s.latitude().unwrap() - want_lat).abs() < 1e-6);
    // Lon = 8 + (30 + 600/6000)/60
    let want_lon = 8.0 + (30.0 + 600.0 / 6000.0) / 60.0;
    assert!((s.longitude().unwrap() - want_lon).abs() < 1e-6);
    assert!(s.date_time().unwrap().contains("2025:06:15 14:30:45"));
    // 50 mph * 1.60934 = 80.467 kph
    assert!((s.speed_kph().unwrap() - 80.467).abs() < 0.01);
    assert_eq!(s.track(), Some(180.0));
    assert!(s.accelerometer().is_some());
  }

  #[test]
  fn process_fmas_short_or_invalid_signature_emits_nothing() {
    let mut out = QuickTimeStreamMeta::new();
    process_fmas(&[0u8; 100], &mut out); // too short
    assert!(out.gps_samples().is_empty());
    let mut d = vec![0u8; 160];
    d[0..4].copy_from_slice(b"FFFF"); // wrong sig
    process_fmas(&d, &mut out);
    assert!(out.gps_samples().is_empty());
  }

  // ─── ProcessWolfbox (G900 / Redtiger F9 4K) ───────────────────────────

  #[test]
  fn process_wolfbox_decodes_synthetic_record() {
    // QuickTimeStream.pl:3615-3676. 0xf8-byte minimum.
    let mut d = vec![0u8; 0x100];
    // Date u32 LE at 0x68/0x6c/0x70 = day=15, mon=6, yr=2025.
    d[0x68..0x6c].copy_from_slice(&15u32.to_le_bytes());
    d[0x6c..0x70].copy_from_slice(&6u32.to_le_bytes());
    d[0x70..0x74].copy_from_slice(&2025u32.to_le_bytes());
    // Time u32 LE at 0xa0/0xa4/0xa8 = hr=14, min=30, sec=45.
    d[0xa0..0xa4].copy_from_slice(&14u32.to_le_bytes());
    d[0xa4..0xa8].copy_from_slice(&30u32.to_le_bytes());
    d[0xa8..0xac].copy_from_slice(&45u32.to_le_bytes());
    // Speed value/div (knots * 1000): 25.5 → val 25500, div 1000
    d[0x48..0x50].copy_from_slice(&25500i64.to_le_bytes());
    d[0x50..0x58].copy_from_slice(&1000i64.to_le_bytes());
    // Track val/div: 90.0 → 9000 / 100
    d[0x58..0x60].copy_from_slice(&9000i64.to_le_bytes());
    d[0x60..0x68].copy_from_slice(&100i64.to_le_bytes());
    // Lat val/div: 4737.7053 in DDDMM.MMMM scaled by 1e4 → 47377053 / 10000
    d[0xb0..0xb8].copy_from_slice(&47377053i64.to_le_bytes());
    d[0xb8..0xc0].copy_from_slice(&10000i64.to_le_bytes());
    // Lon val/div: 822.5076 (DDDMM.MMMM for 8°22.5076') → 8225076 / 10000
    d[0xc0..0xc8].copy_from_slice(&8225076i64.to_le_bytes());
    d[0xc8..0xd0].copy_from_slice(&10000i64.to_le_bytes());
    // Alt val/div: 412.5 → 4125 / 10
    d[0xe8..0xf0].copy_from_slice(&4125i64.to_le_bytes());
    d[0xf0..0xf8].copy_from_slice(&10i64.to_le_bytes());
    let mut out = QuickTimeStreamMeta::new();
    process_wolfbox(&d, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = &out.gps_samples()[0];
    // ConvertLatLon(4737.7053) = 47 + 37.7053/60 ≈ 47.628421
    assert!((s.latitude().unwrap() - 47.628421).abs() < 1e-4);
    // ConvertLatLon(822.5076) = 8 + 22.5076/60 ≈ 8.375127
    assert!((s.longitude().unwrap() - (8.0 + 22.5076 / 60.0)).abs() < 1e-4);
    assert_eq!(s.altitude_m(), Some(412.5));
    // 25.5 knots * 1.852 = 47.226
    assert!((s.speed_kph().unwrap() - 47.226).abs() < 0.01);
    assert_eq!(s.track(), Some(90.0));
    assert!(s.date_time().unwrap().contains("2025:06:15 14:30:45"));
  }

  #[test]
  fn process_wolfbox_too_short_emits_nothing() {
    let mut out = QuickTimeStreamMeta::new();
    process_wolfbox(&[0u8; 100], &mut out);
    assert!(out.gps_samples().is_empty());
  }

  // ─── detect_wolfbox (Condition cascade) ───────────────────────────────

  #[test]
  fn detect_wolfbox_matches_hyth_marker() {
    // Bundled regex branch A: 16 ASCII '0' + 4 uppercase chars.
    let mut d = vec![0u8; 200];
    for i in 0..16 {
      d[136 + i] = b'0';
    }
    d[152..156].copy_from_slice(b"HYTH");
    assert!(detect_wolfbox(&d));
  }

  #[test]
  fn detect_wolfbox_matches_redtiger_marker() {
    // Branch B: literal `https://www.redtiger\0`.
    let mut d = vec![0u8; 200];
    d[136..157].copy_from_slice(b"https://www.redtiger\0");
    assert!(detect_wolfbox(&d));
  }

  #[test]
  fn detect_wolfbox_rejects_wrong_marker() {
    let d = vec![0u8; 200];
    assert!(!detect_wolfbox(&d));
  }

  // ─── dispatch_gpmd (Condition cascade) ────────────────────────────────

  #[test]
  fn dispatch_gpmd_routes_kingslim_to_ligogps() {
    // A faithful Kingslim D4 `gpmd` sample (QuickTimeStream.pl:1874-1888):
    //   * Condition signature `^.{21}\0\0\0A[NS][EW]` — `\0\0\0` at 21..24,
    //     `A` at 24, `N` at 25, `W` at 26 (the variant IDENTIFIER only).
    //   * `LIGOGPSINFO\0` at offset 0x50 (80) — the GPSType-5 fingerprint
    //     (`.{80}LIGOGPSINFO\0` alternative), routing to `ProcessLigoGPS`.
    //   * a plain-ASCII LigoGPS record at 0x50+0x14 (100) — `####`-free path
    //     (LigoGPS.pm:303-307, `^.{4}\d{4}/\d{2}/\d{2} `), flags 0x03 so no
    //     decryption / no fuzz. The `A`-at-24 raw lat/lon is the
    //     COMMENTED-OUT secondary (lines 1890-1904) — NOT decoded.
    // Length must be >= 0x50 + 0x84 = 212 for the Type-5 detector AND
    // >= 100 + 0x84 = 232 for the record walk; use 240.
    let mut d = vec![0u8; 240];
    d[24] = b'A';
    d[25] = b'N';
    d[26] = b'W';
    d[80..92].copy_from_slice(b"LIGOGPSINFO\0");
    // Plain-ASCII record at offset 100: 4-byte counter + `YYYY/MM/DD ...`.
    let mut rec = Vec::new();
    rec.extend_from_slice(&[0, 0, 0, 0]); // counter (consumed by `.{4}`)
    rec.extend_from_slice(b"2024/01/15 10:00:00 N:45.5 E:170.5 30.0");
    d.get_mut(100..100 + rec.len())
      .expect("fixture room for record")
      .copy_from_slice(&rec);

    let mut out = QuickTimeStreamMeta::new();
    let mut lg = crate::metadata::LigoGpsMeta::new();
    let mut state = FreeGpsState::new();
    let matched = dispatch_gpmd(&d, &mut out, &mut lg, &mut state);
    assert_eq!(
      matched,
      // This record decodes a valid fix (45.5 N below), so `ProcessLigoGPS`
      // reached LigoGPS.pm:266 ⇒ `ligo_emitted == true` (the SET_GROUP1 delete
      // ran).
      GpmdDispatch::Kingslim { ligo_emitted: true },
      "Kingslim Condition should match (LigoGPS arm; own deferred Doc; emitted a fix)"
    );
    // Route reached the GPSType-5 / LigoGPS arm AND decoded the record into
    // the LigoGPS accumulator (NOT GPSType-14/XBHT, NOT the Type-3/4 freeGPS
    // arm — those would leave `lg` empty / push to `out`).
    let s = lg
      .samples()
      .first()
      .expect("Kingslim must decode via GPSType-5 LigoGPS");
    // N: / E: with magnitudes < 100 ⇒ no DDMM conversion, positive refs.
    assert_eq!(s.latitude(), Some(45.5));
    assert_eq!(s.longitude(), Some(170.5));
    assert_eq!(s.date_time(), Some("2024:01:15 10:00:00"));
    // The Kingslim `ProcessFreeGPS` sets `$$et{FoundEmbedded}`
    // (QuickTimeStream.pl:1650) on the WALK-LEVEL state, suppressing the later
    // brute-force `mdat` scan.
    assert!(
      state.found_embedded(),
      "Kingslim must set FoundEmbedded on the threaded walk state"
    );
  }

  #[test]
  fn process_free_gps_ligogps_arm_is_binary_only() {
    // The freeGPS GPSType-5 arm is `LIGOGPSINFO\0` (binary) ONLY
    // (QuickTimeStream.pl:1843 `/^(.{16}|.{48}|.{80})LIGOGPSINFO\0/`). ExifTool
    // routes the JSON `LIGOGPSINFO {` form solely through the `udta` `LigoJSON`
    // Condition (QuickTime.pm:835), NEVER through this freeGPS arm. A JSON
    // `LIGOGPSINFO {` placed at a freeGPS offset must therefore decode NOTHING
    // here (the 12th byte is a space, not `\0`, so `detect_type5_ligogps` fails).
    let json = br#"LIGOGPSINFO {"status": "A", "NS": "N", "EW": "W", "Latitude": "12.5", "Longitude": "34.5"}"#;
    let mut block = vec![0u8; 16];
    block[4..12].copy_from_slice(b"freeGPS ");
    block.extend_from_slice(json);
    block.resize(block.len().max(96), 0);

    let mut out = QuickTimeStreamMeta::new();
    let mut lg = crate::metadata::LigoGpsMeta::new();
    let mut state = FreeGpsState::new();
    process_free_gps(
      &block,
      None,
      None,
      None,
      &mut state,
      &mut out,
      Some(&mut lg),
    );

    assert!(
      lg.samples().is_empty(),
      "JSON LIGOGPSINFO must NOT decode via the binary freeGPS arm"
    );
  }

  #[test]
  fn dispatch_gpmd_routes_rove_to_process_text() {
    let mut d = vec![0u8; 300];
    d[0..8].copy_from_slice(&[0x00, 0x00, 0xf2, 0xe1, 0xf0, 0xee, 0x54, 0x54]);
    let mut out = QuickTimeStreamMeta::new();
    let mut lg = crate::metadata::LigoGpsMeta::new();
    let mut state = FreeGpsState::new();
    assert_eq!(
      dispatch_gpmd(&d, &mut out, &mut lg, &mut state),
      GpmdDispatch::SelfContained
    );
    // `Process_text` does NOT set `$$et{FoundEmbedded}` — leave it clear.
    assert!(!state.found_embedded());
  }

  #[test]
  fn dispatch_gpmd_routes_fmas() {
    let mut d = vec![0u8; 160];
    d[0..8].copy_from_slice(b"FMAS\0\0\0\0");
    d[80..84].copy_from_slice(b"SAMM");
    d[120] = b'A';
    let mut out = QuickTimeStreamMeta::new();
    let mut lg = crate::metadata::LigoGpsMeta::new();
    let mut state = FreeGpsState::new();
    assert_eq!(
      dispatch_gpmd(&d, &mut out, &mut lg, &mut state),
      GpmdDispatch::SelfContained
    );
    // `ProcessFMAS` does NOT set `$$et{FoundEmbedded}` — leave it clear.
    assert!(!state.found_embedded());
  }

  #[test]
  fn dispatch_gpmd_routes_wolfbox() {
    let mut d = vec![0u8; 0x100];
    for i in 0..16 {
      d[136 + i] = b'0';
    }
    d[152..156].copy_from_slice(b"HYTH");
    // Provide valid date/time so the parse doesn't bail.
    d[0x68..0x6c].copy_from_slice(&15u32.to_le_bytes());
    d[0x6c..0x70].copy_from_slice(&6u32.to_le_bytes());
    d[0x70..0x74].copy_from_slice(&2025u32.to_le_bytes());
    d[0xa0..0xa4].copy_from_slice(&14u32.to_le_bytes());
    d[0xa4..0xa8].copy_from_slice(&30u32.to_le_bytes());
    d[0xa8..0xac].copy_from_slice(&45u32.to_le_bytes());
    // Lat val=0 / div=1 → ConvertLatLon(0)=0; OK for routing test.
    d[0xb8..0xc0].copy_from_slice(&1i64.to_le_bytes());
    d[0xc8..0xd0].copy_from_slice(&1i64.to_le_bytes());
    d[0x50..0x58].copy_from_slice(&1i64.to_le_bytes());
    d[0x60..0x68].copy_from_slice(&1i64.to_le_bytes());
    d[0xf0..0xf8].copy_from_slice(&1i64.to_le_bytes());
    let mut out = QuickTimeStreamMeta::new();
    let mut lg = crate::metadata::LigoGpsMeta::new();
    let mut state = FreeGpsState::new();
    assert_eq!(
      dispatch_gpmd(&d, &mut out, &mut lg, &mut state),
      GpmdDispatch::SelfContained
    );
    // `ProcessWolfbox` does NOT set `$$et{FoundEmbedded}` — leave it clear.
    assert!(!state.found_embedded());
  }

  #[test]
  fn dispatch_gpmd_returns_nomatch_for_gopro_fallback() {
    // No marker matches → caller routes to GoPro KLV walker.
    let d = vec![0u8; 256];
    let mut out = QuickTimeStreamMeta::new();
    let mut lg = crate::metadata::LigoGpsMeta::new();
    let mut state = FreeGpsState::new();
    assert_eq!(
      dispatch_gpmd(&d, &mut out, &mut lg, &mut state),
      GpmdDispatch::NoMatch
    );
    assert!(!state.found_embedded());
  }

  // ─── NMEA helpers ─────────────────────────────────────────────────────

  #[test]
  fn read_dddmm_splits_degrees_and_minutes() {
    // "4721.35197" — degrees=47, minutes=21.35197
    let s = b"4721.35197";
    let mut p = 0;
    let (d, m) = read_dddmm(s, &mut p).expect("parse ok");
    assert_eq!(d, 47.0);
    assert!((m - 21.35197).abs() < 1e-6);
    assert_eq!(p, 10);
  }

  #[test]
  fn read_dddmm_handles_three_digit_degrees() {
    let s = b"12009.901";
    let mut p = 0;
    let (d, m) = read_dddmm(s, &mut p).expect("parse ok");
    assert_eq!(d, 120.0);
    assert!((m - 9.901).abs() < 1e-6);
  }

  #[test]
  fn read_dddmm_handles_one_digit_minutes_prefix() {
    let s = b"08.5";
    let mut p = 0;
    let (d, m) = read_dddmm(s, &mut p).expect("parse ok");
    assert_eq!(d, 0.0);
    assert!((m - 8.5).abs() < 1e-6);
  }

  #[test]
  fn dollar_records_iterates_multiple_sentences() {
    let s = "$GPRMC,1,A,2,N,3,E,4,5,210625\n$GPGGA,1,2,N,3,E,1";
    let recs: Vec<_> = DollarRecords::new(s).collect();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0].0, "GPRMC");
    assert_eq!(recs[1].0, "GPGGA");
  }

  #[test]
  fn dollar_records_skips_garbage_dollar_sign() {
    let s = "$$$$$GPRMC,1";
    let recs: Vec<_> = DollarRecords::new(s).collect();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].0, "GPRMC");
  }

  /// Assert every DJI telemetry field decoded from `buf` matches the canonical
  /// `QuickTime_text_dji_telemetry.mov` values (GPS 8.6499/53.1665, alt 6,
  /// speed 2.10 m/s → 7.56 km/h, distance 24.26 m/s → 87.336 km/h, V.S "0.00",
  /// F/3.5, SS 1000 → 1/1000 s, EV 0, ISO "100"). Shared by the canonical and
  /// the non-canonical-spacing cases so a spacing variant must produce the SAME
  /// fields — never silently drop one (the #104 finding-3 class).
  fn assert_dji_canonical_fields(buf: &str) {
    let dji = parse_dji_telemetry(buf.as_bytes()).expect("DJI telemetry parses");
    assert!((dji.lon - 8.6499).abs() < 1e-9, "lon");
    assert!((dji.lat - 53.1665).abs() < 1e-9, "lat");
    assert!((dji.alt.expect("alt") - 6.0).abs() < 1e-9, "alt");
    assert!(
      (dji.speed_kph.expect("speed") - 2.10 * MPS_TO_KPH).abs() < 1e-9,
      "speed"
    );
    assert!(
      (dji.distance.expect("distance") - 24.26 * MPS_TO_KPH).abs() < 1e-9,
      "distance"
    );
    assert_eq!(
      dji.vertical_speed.as_deref(),
      Some("0.00"),
      "vertical_speed"
    );
    assert!(
      (dji.fnumber.expect("fnumber") - 3.5).abs() < 1e-9,
      "fnumber"
    );
    assert!(
      (dji.exposure_time_s.expect("exposure_time") - 1.0 / 1000.0).abs() < 1e-12,
      "exposure_time"
    );
    assert!(
      (dji.exposure_compensation.expect("ev") - 0.0).abs() < 1e-12,
      "exposure_compensation"
    );
    assert_eq!(dji.iso.as_deref(), Some("100"), "iso");
  }

  #[test]
  fn parse_dji_telemetry_canonical_spacing() {
    // The exact `QuickTime_text_dji_telemetry.mov` Text payload (one space after
    // each comma / field letter).
    assert_dji_canonical_fields(
      "F/3.5, SS 1000, ISO 100, EV 0, GPS (8.6499, 53.1665, 18), D 24.26m, \
       H 6.00m, H.S 2.10m/s, V.S 0.00m/s \n",
    );
  }

  /// #104 finding-3: ExifTool's DJI regexes use `,\s*` / `\s+`, so valid
  /// telemetry with NO space after a comma, MULTIPLE spaces, or TABs must still
  /// extract every field. The old fixed-literal scans (`", H "`, `"SS "`, …)
  /// required exactly one space and SILENTLY dropped altitude/speed/distance/
  /// camera settings on this input.
  #[test]
  fn parse_dji_telemetry_non_canonical_spacing() {
    // No space after the comma before H/H.S/D/V.S; a TAB after SS; DOUBLE spaces
    // after F/-less markers (ISO/EV) and after the field letters; a tab inside
    // the lon/lat `\s*`. Every field must still decode to the canonical values.
    assert_dji_canonical_fields(
      "F/3.5,SS\t1000, ISO  100, EV  0, GPS (8.6499,\t53.1665, 18),D 24.26m,\
       H  6.00m,H.S\t2.10m/s,V.S  0.00m/s \n",
    );
  }

  /// `\s+` is REQUIRED after the comma-field marker (`,\s*H\s+`): `,H6.00m` with
  /// NO whitespace between `H` and the digits must NOT match (faithful to the
  /// regex), so altitude is absent — while the GPS fix still decodes.
  #[test]
  fn parse_dji_telemetry_requires_whitespace_after_marker() {
    let dji = parse_dji_telemetry(b"GPS (8.6499, 53.1665, 18),H6.00m, H.S 2.10m/s")
      .expect("GPS fix still parses");
    assert!(dji.alt.is_none(), "no \\s+ after H ⇒ altitude not captured");
    // The well-formed `H.S 2.10` still decodes (the scanner is per-field).
    assert!(
      (dji.speed_kph.expect("speed") - 2.10 * MPS_TO_KPH).abs() < 1e-9,
      "speed still captured"
    );
  }

  /// The `\b` word boundary on `\bSS` / `\bISO`: a marker embedded INSIDE a word
  /// (`xSS`, `xISO`) must NOT match (no boundary), so the field is absent.
  #[test]
  fn parse_dji_telemetry_word_boundary_blocks_embedded_marker() {
    let dji = parse_dji_telemetry(b"GPS (8.6499, 53.1665, 18), xSS 1000, fooISO 100")
      .expect("GPS fix parses");
    assert!(
      dji.exposure_time_s.is_none(),
      "`xSS` is not at a word boundary ⇒ no ExposureTime"
    );
    assert!(
      dji.iso.is_none(),
      "`fooISO` is not at a word boundary ⇒ no ISO"
    );
  }
}
