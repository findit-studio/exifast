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
//! The samples ProcessFreeGPS appends feed [`QuickTimeStreamMeta`] (the
//! same `Vec<GpsSample>` the bounded SP3 decoders fill). That meta is the
//! **LOWEST tier** of the cross-port GPS priority chain — consulted only
//! when no higher-tier source (GoPro → CAMM → Sony rtmd → Insta360 →
//! Parrot) decoded a coordinate pair. The brute-force scan is intentionally
//! a fallback; it lights up dashcam-only files that have no first-party
//! timed-metadata track.

#![deny(clippy::indexing_slicing)]

extern crate alloc;
use alloc::{
  string::{String, ToString},
  vec::Vec,
};

use smol_str::SmolStr;

use crate::{
  formats::quicktime_stream::{convert_lat_lon, join3, synth_gps_date_time},
  metadata::{GpsSample, QuickTimeStreamMeta},
};

// ── conversion factors (QuickTimeStream.pl:73-75) ──────────────────────────

/// `$knotsToKph = 1.852` (QuickTimeStream.pl:73).
const KNOTS_TO_KPH: f64 = 1.852;
/// `$mpsToKph = 3.6` (QuickTimeStream.pl:74).
const MPS_TO_KPH: f64 = 3.6;

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
pub fn scan_media_data(
  data: &[u8],
  mdat_offset: u64,
  mdat_size: u64,
  create_date_raw: Option<u64>,
  kodak_version: Option<&str>,
  already_found_embedded: bool,
  out: &mut QuickTimeStreamMeta,
) {
  // QuickTimeStream.pl:3689 `return if $$et{FoundEmbedded} or not $dataPos`.
  if already_found_embedded || mdat_offset == 0 {
    return;
  }
  let start = mdat_offset.min(data.len() as u64) as usize;
  let end = mdat_offset.saturating_add(mdat_size).min(data.len() as u64) as usize;
  if end <= start {
    return;
  }
  // `start`/`end` are both clamped to `data.len()` and `end > start`, so this
  // `.get` is always `Some`; the `else` return is unreachable and matches the
  // `end <= start` guard's recovery (byte-identical).
  let Some(mdat) = data.get(start..end) else {
    return;
  };

  // QuickTimeStream.pl:2050 `$$et{FreeGPS2}` — the cross-block ATC ring-buffer
  // state (`Then` + `RecentRecPos`) persists for the whole scan, exactly as
  // ExifTool keeps it on `$$et` across every `ProcessFreeGPS` call.
  let mut state = FreeGpsState::new();
  let mut pos = 0usize;
  let mut found = false;
  // QuickTimeStream.pl:3702 `while ($dataLen)` — read 0x8000-byte chunks.
  while pos < mdat.len() {
    let chunk_end = (pos + GPS_BLOCK_SIZE).min(mdat.len());
    // `chunk_end <= mdat.len()` and `pos < mdat.len() <= chunk_end`, so this
    // `.get` is always `Some`; the `else` break matches the `while` guard.
    let Some(chunk) = mdat.get(pos..chunk_end) else {
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
          // whole `mdat` in memory, so the faithful equivalent is to slice the
          // block from `mdat` using its ABSOLUTE offset (`pos + abs`) rather
          // than from the bounded `chunk` window — slicing `chunk[abs..
          // abs+len]` panics whenever `abs + len` exceeds the window, which is
          // the COMMON case for real 0x8000-byte freeGPS blocks: the 12-byte
          // cross-chunk overlap (the `substr($buff,-12)` carry below) lands the
          // next adjacent 0x8000 block straddling the window boundary.
          let block_abs = pos + abs;
          if block_abs + len > mdat.len() {
            // QuickTimeStream.pl:3770 `last unless $raf->Read == $more` — a
            // short final read: the declared box runs past the end of media
            // data, so stop scanning entirely.
            return;
          }
          // The guard above proves `block_abs + len <= mdat.len()`, so this
          // `.get` is always `Some`; the `else` return matches that guard's
          // recovery (byte-identical).
          let Some(block) = mdat.get(block_abs..block_abs + len) else {
            return;
          };
          // QuickTimeStream.pl:3777 `$dirInfo = { DataPt, DataPos, DirLen }` —
          // the brute-force scan's `$dirInfo` carries NO `SampleTime`, so
          // `sample_time` is `None` here (a Type-19 block found by the scan
          // gets no synthesized GPSDateTime, matching the oracle).
          process_free_gps(block, create_date_raw, None, kodak_version, &mut state, out);
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
          // re-dispatches into Image::ExifTool::GoPro::ProcessGP6.
          // DEFERRED: port the GoPro GPMF module separately.
          // We must still advance past this byte to avoid an infinite
          // re-match.
          search_off = abs + 5;
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
pub fn process_free_gps(
  data: &[u8],
  create_date_raw: Option<u64>,
  sample_time: Option<f64>,
  kodak_version: Option<&str>,
  state: &mut FreeGpsState,
  out: &mut QuickTimeStreamMeta,
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

  // GPSType 5: LigoGPS — DEFERRED.
  // (QuickTimeStream.pl:1843-1904). Detected by `LIGOGPSINFO\0` at offset
  // 16/48/80. We DETECT the fingerprint here to match the dispatch, but the
  // actual parse needs `Image::ExifTool::LigoGPS::ProcessLigoGPS`.
  if detect_type5_ligogps(data).is_some() {
    // DEFERRED: port the LigoGPS module separately.
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
      user_label: None,
      ddd: false,
      synth_date_time: None,
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
    if let Some((x, y, z)) = self.accel {
      sample.set_accelerometer(Some(SmolStr::from(join3(x, y, z))));
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
    process_free_gps(block, None, None, None, &mut state, out);
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
    );
  }

  /// Decode one freeGPS block with a `KodakVersion` global in effect — the
  /// Rexing Type-17b test shape.
  fn decode_block_kodak(block: &[u8], kodak_version: &str, out: &mut QuickTimeStreamMeta) {
    let mut state = FreeGpsState::new();
    process_free_gps(block, None, None, Some(kodak_version), &mut state, out);
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
    scan_media_data(&file, mdat_offset, mdat_size, None, None, false, &mut out);
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
    scan_media_data(&file, mdat_offset, mdat_size, None, None, false, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
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
    scan_media_data(&file, mdat_offset, mdat_size, None, None, false, &mut out);
    assert!(
      out.gps_samples().is_empty(),
      "a freeGPS block in a sub-0x8000 mdat must not be decoded"
    );
  }

  #[test]
  fn scan_media_data_short_circuits_when_embedded_found() {
    let mut out = QuickTimeStreamMeta::new();
    let file = vec![0u8; 0x10000];
    scan_media_data(&file, 0, file.len() as u64, None, None, true, &mut out);
    assert!(out.is_empty());
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
    // 2024:02:22 14:34:40Z); SampleTime 2.0s ⇒ GPSDateTime 14:34:42Z.
    let mut out = QuickTimeStreamMeta::new();
    decode_block_with_time(&block, 3_791_457_280, 2.0, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    assert_eq!(
      out.gps_samples().first().unwrap().date_time(),
      Some("2024:02:22 14:34:42Z"),
      "GPSDateTime = CreateDate + SampleTime"
    );
    // lat/lon still decode (ConvertLatLon applied).
    let lat = out.gps_samples().first().unwrap().latitude().expect("lat");
    assert!((lat - 51.267_85).abs() < 1e-3, "lat={lat}");

    // No CreateDate ⇒ no GPSDateTime even with a SampleTime.
    let mut out2 = QuickTimeStreamMeta::new();
    let mut state = FreeGpsState::new();
    process_free_gps(&block, None, Some(2.0), None, &mut state, &mut out2);
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
    scan_media_data(
      &file,
      mdat_offset,
      mdat.len() as u64,
      None,
      None,
      false,
      &mut out,
    );
    assert_eq!(
      out.gps_samples().len(),
      2,
      "both adjacent 0x8000 freeGPS blocks must decode"
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
    // Must not panic; the over-long block is not dispatched.
    scan_media_data(
      &file,
      mdat_offset,
      block.len() as u64,
      None,
      None,
      false,
      &mut out,
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
    process_free_gps(&block1, None, None, None, &mut state, &mut out);
    assert_eq!(out.gps_samples().len(), 2, "block 1 emits both new records");
    process_free_gps(&block2, None, None, None, &mut state, &mut out);
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
}
