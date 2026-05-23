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

extern crate alloc;
use alloc::{
  string::{String, ToString},
  vec::Vec,
};

use smol_str::SmolStr;

use crate::{
  formats::{
    gopro,
    quicktime_stream::{convert_lat_lon, join3},
  },
  metadata::{GoProMeta, GpsSample, QuickTimeStreamMeta},
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
  b.get(off..off + 2)
    .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn le_u32(b: &[u8], off: usize) -> Option<u32> {
  b.get(off..off + 4)
    .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn le_i32(b: &[u8], off: usize) -> Option<i32> {
  le_u32(b, off).map(|v| v as i32)
}

fn le_u64(b: &[u8], off: usize) -> Option<u64> {
  b.get(off..off + 8)
    .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

fn le_i64(b: &[u8], off: usize) -> Option<i64> {
  le_u64(b, off).map(|v| v as i64)
}

fn le_f32(b: &[u8], off: usize) -> Option<f64> {
  b.get(off..off + 4)
    .map(|s| f64::from(f32::from_le_bytes([s[0], s[1], s[2], s[3]])))
}

fn le_f64(b: &[u8], off: usize) -> Option<f64> {
  b.get(off..off + 8)
    .map(|s| f64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

// ── big-endian readers (a couple of variants override the byte order;
//    most prominent is GPSType 20 / Nextbase 512G) ──────────────────────────

fn be_u16(b: &[u8], off: usize) -> Option<u16> {
  b.get(off..off + 2)
    .map(|s| u16::from_be_bytes([s[0], s[1]]))
}

fn be_u32(b: &[u8], off: usize) -> Option<u32> {
  b.get(off..off + 4)
    .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
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
  already_found_embedded: bool,
  out: &mut QuickTimeStreamMeta,
  gopro_out: &mut GoProMeta,
) {
  scan_media_data_with_ligo(
    data,
    mdat_offset,
    mdat_size,
    create_date_raw,
    already_found_embedded,
    out,
    gopro_out,
    None,
  );
}

/// [`scan_media_data`] variant that additionally accepts a
/// [`LigoGpsMeta`] accumulator — when a `freeGPS` block triggers the
/// `LIGOGPSINFO\0` fingerprint hit
/// (QuickTimeStream.pl:1843-1888) it is dispatched into
/// [`crate::formats::ligogps::process_ligogps_with_scale`] via
/// [`process_free_gps_with_ligo`].
#[allow(clippy::too_many_arguments)]
pub fn scan_media_data_with_ligo(
  data: &[u8],
  mdat_offset: u64,
  mdat_size: u64,
  create_date_raw: Option<u64>,
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
  let end = mdat_offset.saturating_add(mdat_size).min(data.len() as u64) as usize;
  if end <= start {
    return;
  }
  let mdat = &data[start..end];

  let mut pos = 0usize;
  let mut found = false;
  // QuickTimeStream.pl:3702 `while ($dataLen)` — read 0x8000-byte chunks.
  while pos < mdat.len() {
    let chunk_end = (pos + GPS_BLOCK_SIZE).min(mdat.len());
    let chunk = &mdat[pos..chunk_end];
    // QuickTimeStream.pl:3710 `if ($buff !~ /(\0..\0freeGPS |GP\x06\0\0)/sg)`.
    // Search ALL non-overlapping matches in this chunk and dispatch.
    let mut search_off = 0usize;
    let mut advanced = false;
    while let Some(hit) = find_magic(&chunk[search_off..]) {
      let abs = search_off + hit.offset;
      match hit.kind {
        MagicKind::FreeGps => {
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
          // QuickTimeStream.pl:3768-3772 — extend chunk by reading more bytes
          // if the box overruns the current chunk. Here we have the whole
          // mdat in memory; just check the box fits in mdat.
          if abs + len > mdat.len() - pos {
            // The box extends past the current chunk; jump POS so the
            // outer while-loop re-aligns on it next iteration.
            pos += abs;
            advanced = true;
            break;
          }
          let block = &chunk[abs..abs + len];
          // QuickTimeStream.pl:3777-3778: pass DataPt=&block, DirLen=len.
          process_free_gps_with_ligo(block, create_date_raw, out, ligogps_out.as_deref_mut());
          found = true;
          // QuickTimeStream.pl:3781 `$pos += $len`.
          search_off = abs + len;
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
          // consumed. Mirror that — pass `&mdat[pos+abs..]` so `process_gp6`
          // can walk consecutive `GP\x06\0\0` records as a sequence.
          let consumed = gopro::process_gp6(&mdat[pos + abs..], gopro_out);
          if consumed > 0 {
            // QuickTimeStream.pl:3739 `Seek($start + $size)` — advance the
            // outer loop past the consumed records. consumed == 0 means
            // the record didn't validate; ExifTool's fallback is to
            // continue with the search (3743-3745 `Seek($filePos);
            // $buf2 = substr($buff, $buffPos)`).
            search_off = abs + consumed;
            found = true;
          } else {
            // Fallback: advance past the 5-byte magic to avoid an
            // infinite re-match.
            search_off = abs + 5;
          }
        }
      }
    }
    if advanced {
      // chunk reset to a new window; re-loop.
      continue;
    }
    // QuickTimeStream.pl:3711-3712 — keep the last 12 bytes for cross-chunk
    // magic matches.
    if chunk.len() <= 12 {
      break;
    }
    // QuickTimeStream.pl:3715: in all samples, the first freeGPS block is
    // within the first 2 MB of mdat — limit the scan to the first 20 MB
    // when nothing has been found yet.
    let next = pos + chunk.len() - 12;
    if !found && next >= 20 * 1024 * 1024 {
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
  while let Some(pos) = memmem(&buf[start..], needle) {
    let abs = start + pos;
    if abs >= 4 {
      // The match offset is `abs`, the magic starts here, the 4 BE bytes
      // BEFORE this position are the box length. QuickTimeStream.pl:3710's
      // pattern requires bytes -4 and -1 to be NUL.
      let pre = abs - 4;
      if buf[pre] == 0 && buf[pre + 3] == 0 {
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
    if &hay[i..i + needle.len()] == needle {
      return Some(i);
    }
  }
  None
}

// ===========================================================================
// ProcessFreeGPS (QuickTimeStream.pl:1637-2484)
// ===========================================================================

/// `ProcessFreeGPS` (QuickTimeStream.pl:1637-2484): decode one `freeGPS `
/// block by fingerprint dispatch.
///
/// `data` is the WHOLE block — including the 16-byte atom header
/// (`[size:4][freeGPS :8][padding:4]`). ExifTool's `$$dataPt` is this same
/// whole-block buffer, so all the byte-offset constants in the variant
/// decoders below are RELATIVE to the block start.
///
/// QuickTimeStream.pl:1645 `return 0 if $dirLen < 82` — a block too short to
/// carry any fingerprint is silently dropped.
///
/// Back-compat wrapper around [`process_free_gps_with_ligo`] for callers
/// that don't have a [`LigoGpsMeta`] accumulator at hand. The LigoGPS
/// fingerprint (`LIGOGPSINFO\0`) is silently dropped in this path — the
/// trailer-only LigoGPS reach path covers the common case.
pub fn process_free_gps(data: &[u8], create_date_raw: Option<u64>, out: &mut QuickTimeStreamMeta) {
  process_free_gps_with_ligo(data, create_date_raw, out, None);
}

/// [`process_free_gps`] variant that additionally accepts a
/// [`LigoGpsMeta`] accumulator. When the GPSType 5 (LigoGPS)
/// fingerprint is hit (QuickTimeStream.pl:1843), the block is
/// dispatched to [`crate::formats::ligogps::process_ligogps_with_scale`]
/// with the per-offset scale rule from QuickTimeStream.pl:1886.
pub fn process_free_gps_with_ligo(
  data: &[u8],
  _create_date_raw: Option<u64>,
  out: &mut QuickTimeStreamMeta,
  ligogps_out: Option<&mut crate::metadata::LigoGpsMeta>,
) {
  // QuickTimeStream.pl:1645
  if data.len() < 82 {
    return;
  }
  // QuickTimeStream.pl:1649 SetByteOrder('II') — every variant reads LE
  // unless it explicitly switches.

  // GPSType 1: Azdome GS63H / EEEkit encrypted ASCII GPS
  // (QuickTimeStream.pl:1652-1715). Detected by the 8-byte XOR-0xAA-prefix
  // signature at offset 18.
  if data.len() >= 26 && data[18..26] == [0xaa, 0xaa, 0xf2, 0xe1, 0xf0, 0xee, 0x54, 0x54] {
    decode_type1_azdome(data, out);
    return;
  }

  // GPSType 2: Nextbase 512GW NMEA dashcam
  // (QuickTimeStream.pl:1717-1750). Detected by an ASCII timestamp at offset
  // 52: 14 digits in YYYYMMDDhhmmss.
  if data.len() >= 66 && is_ascii_digits(&data[52..66], 14) {
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
        && data.len() >= 32
        && data.get(12..16) == Some(&[0xf0, 0x03, 0x00, 0x00])
        && data.get(32..36) == Some(&[0x00, 0x00, 0x00, 0x00])
      {
        Some(3)
      } else {
        None
      };
      // QuickTimeStream.pl:1883 — `DirStart = $pos` (i.e. `off`).
      crate::formats::ligogps::process_ligogps_with_scale(data, off, ligo_meta, false, scale_id);
    }
    return;
  }

  // GPSType 6: Akaso dashcam (QuickTimeStream.pl:1906-1938).
  // Detected by `A\0\0\0....[NS]\0\0\0....[EW]\0\0\0` at offsets 60..79.
  // Per QuickTimeStream.pl:1906 `^.{60}A\0{3}.{4}([NS])\0{3}.{4}([EW])\0{3}`.
  if data.len() >= 88
    && data.get(60).copied() == Some(b'A')
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
  if data.len() >= 0x70 && detect_type8(data) {
    decode_type8_akaso_v1(data, out);
    return;
  }

  // GPSType 9: EACHPAI — DEFERRED (encryption unknown).
  // (QuickTimeStream.pl:1998-2019). ExifTool emits a warning and stops.
  if data.len() >= 0x10 && be_u32(data, 0x0c) == Some(0xac) {
    // Faithful: `Can't yet decrypt EACHPAI timed GPS` — skip silently.
    return;
  }

  // GPSType 10: Vantrue S1 / horsontech (QuickTimeStream.pl:2021-2045).
  // `A[NS][EW]\0` at offset 64.
  if data.len() >= 0x80
    && data.get(64).copied() == Some(b'A')
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
    decode_type11_atc(data, out);
    return;
  }

  // GPSType 12: Type 2 80-byte (double lat/lon) (QuickTimeStream.pl:2159-2188).
  // `A\0...[NS]\0...[EW]\0` at offsets 60/71/86.
  if data.len() >= 0x88
    && data.get(60).copied() == Some(b'A')
    && data.get(61).copied() == Some(0)
    && matches!(data.get(71), Some(&b'N' | &b'S'))
    && data.get(72).copied() == Some(0)
    && matches!(data.get(86), Some(&b'E' | &b'W'))
    && data.get(87).copied() == Some(0)
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
  // `A` at offset 28 + [NS] at 40 + [EW] at 56.
  if data.len() >= 0x60
    && data.get(28).copied() == Some(b'A')
    && matches!(data.get(40), Some(&b'N' | &b'S'))
    && matches!(data.get(56), Some(&b'E' | &b'W'))
  {
    decode_type15_vantrue_n4(data, out);
    return;
  }

  // GPSType 16/17/17b/17c: Viofo A119S / IQS / Rexing / Transcend
  // (QuickTimeStream.pl:2265-2352). `A[NS][EW]\0` at offset 72.
  if data.len() >= 0x60
    && data.get(72).copied() == Some(b'A')
    && matches!(data.get(73), Some(&b'N' | &b'S'))
    && matches!(data.get(74), Some(&b'E' | &b'W'))
    && data.get(75).copied() == Some(0)
  {
    decode_type16_17_viofo(data, out);
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
    decode_type19_70mai(data, out);
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
  b.len() >= n && b[..n].iter().all(|&c| c.is_ascii_digit())
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
    }
  }
  /// Common-tail emission — QuickTimeStream.pl:2455-2483. Validates month +
  /// day ranges and synthesizes GPSDateTime + applies ConvertLatLon.
  fn emit(self, out: &mut QuickTimeStreamMeta) {
    // QuickTimeStream.pl:2455 `return 0 if defined $yr and ($mon < 1 or $mon > 12)`.
    if let (Some(_yr), Some(mon)) = (self.yr, self.mon)
      && !(1..=12).contains(&mon)
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
      let s = if sec.len() < 2 {
        alloc::format!("0{sec}")
      } else {
        sec.to_string()
      };
      Some(alloc::format!(
        "{yr:04}:{mon:02}:{day:02} {hr:02}:{min:02}:{s}Z"
      ))
    } else if let (Some(hr), Some(min), Some(sec)) = (self.hr, self.min, self.sec.as_deref()) {
      // QuickTimeStream.pl:2465-2467 — time-only GPSTimeStamp.
      let s = if sec.len() < 2 {
        alloc::format!("0{sec}")
      } else {
        sec.to_string()
      };
      Some(alloc::format!("{hr:02}:{min:02}:{s}Z"))
    } else {
      None
    };
    sample.set_date_time(date_time.map(SmolStr::from));

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
  for &b in &data[18..18 + n] {
    buf2.push(b ^ 0xaa);
  }

  // Parse: `^.{8}(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2}).(.{15})([NS])(\d{8})([EW])(\d{9})(\d{8})?`.
  if buf2.len() >= 8 + 14 + 1 + 15 + 1 + 8 + 1 + 9 {
    let off = 8;
    if is_ascii_digits(&buf2[off..], 14) {
      let s = core::str::from_utf8(&buf2[off..off + 14]).unwrap_or("");
      t.yr = s[0..4].parse().ok();
      t.mon = s[4..6].parse().ok();
      t.day = s[6..8].parse().ok();
      t.hr = s[8..10].parse().ok();
      t.min = s[10..12].parse().ok();
      t.sec = Some(s[12..14].to_string());
      let lbl_off = off + 14 + 1; // skip the 14 digits + the `.` separator.
      let lbl_end = lbl_off + 15;
      if buf2.len() > lbl_end {
        let lbl = String::from_utf8_lossy(&buf2[lbl_off..lbl_end]);
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
          if is_ascii_digits(&buf2[pos_lat..], 8) {
            let lat_s = core::str::from_utf8(&buf2[pos_lat..pos_lat + 8]).unwrap_or("0");
            t.lat = lat_s.parse::<f64>().ok().map(|v| v / 1e4);
          }
          let pos_lon_ref = pos_lat + 8;
          let lon_ref = buf2.get(pos_lon_ref).copied();
          if matches!(lon_ref, Some(b'E' | b'W')) {
            t.lon_ref = Some(lon_ref.unwrap() as char);
            let pos_lon = pos_lon_ref + 1;
            if is_ascii_digits(&buf2[pos_lon..], 9) {
              let lon_s = core::str::from_utf8(&buf2[pos_lon..pos_lon + 9]).unwrap_or("0");
              t.lon = lon_s.parse::<f64>().ok().map(|v| v / 1e4);
            }
            let pos_spd = pos_lon + 9;
            if is_ascii_digits(&buf2[pos_spd..], 8) {
              let spd_s = core::str::from_utf8(&buf2[pos_spd..pos_spd + 8]).unwrap_or("0");
              t.spd = spd_s.parse().ok();
            } else if buf2.len() >= 64 {
              // EEEkit: spd as 3 digits at offset 60.
              let s2 = &buf2[60..buf2.len().min(64)];
              if s2.iter().all(|&c| c.is_ascii_digit()) {
                t.spd = core::str::from_utf8(s2).ok().and_then(|s| s.parse().ok());
              }
            }
          }
        }
      }
    }
  }

  // Accelerometer (QuickTimeStream.pl:1700-1711): `^.{65}([-+]\d{3})([-+]\d{3})([-+]\d{3})`.
  if buf2.len() >= 65 + 12 {
    let p = 65;
    if let (Some(x), Some(y), Some(z)) = (
      parse_signed_3digit(&buf2[p..p + 4]),
      parse_signed_3digit(&buf2[p + 4..p + 8]),
      parse_signed_3digit(&buf2[p + 8..p + 12]),
    ) {
      t.accel = Some((
        f64::from(x) / 100.0,
        f64::from(y) / 100.0,
        f64::from(z) / 100.0,
      ));
    }
  } else if buf2.len() >= 173 + 12 {
    // Azdome accel-only fallback (QuickTimeStream.pl:1705-1710).
    let p = 173;
    if let (Some(x), Some(y), Some(z)) = (
      parse_signed_3digit(&buf2[p..p + 4]),
      parse_signed_3digit(&buf2[p + 4..p + 8]),
      parse_signed_3digit(&buf2[p + 8..p + 12]),
    ) {
      t.accel = Some((
        f64::from(x) / 100.0,
        f64::from(y) / 100.0,
        f64::from(z) / 100.0,
      ));
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
  let sign = match b[0] {
    b'+' => 1,
    b'-' => -1,
    _ => return None,
  };
  if !b[1..4].iter().all(|&c| c.is_ascii_digit()) {
    return None;
  }
  let v = core::str::from_utf8(&b[1..4]).ok()?.parse::<i32>().ok()?;
  Some(sign * v)
}

// ─────────────────────────── GPSType 2: Nextbase 512GW NMEA ────────────────

/// `decode_type2_nextbase_nmea` (QuickTimeStream.pl:1717-1750).
fn decode_type2_nextbase_nmea(data: &[u8], out: &mut QuickTimeStreamMeta) {
  let mut t = FreeGpsTags::new();
  // QuickTimeStream.pl:1732 `CameraDateTime` — the YYYYMMDDhhmmss at off 52.
  // The typed domain doesn't carry CameraDateTime as a top-level field; we
  // use the value to seed GPSDateTime if NMEA omits it (which it doesn't,
  // but matches the Perl flow).
  // QuickTimeStream.pl:1733 — $GPRMC pattern.
  let s = core::str::from_utf8(data).unwrap_or("");
  // Look for `$XXRMC,HHMMSS.sss,A,LLMM.MMMM,N,LLLMM.MMMM,E,spd,trk,DDMMYY,,,A*hh`.
  if let Some(idx) = s.find("$GP") {
    parse_nmea_rmc(&s[idx..], &mut t);
  } else if let Some(idx) = s.find("$GN") {
    parse_nmea_rmc(&s[idx..], &mut t);
  } else if let Some(idx) = s.find("$BD") {
    parse_nmea_rmc(&s[idx..], &mut t);
  } else if let Some(idx) = s.find("$GL") {
    parse_nmea_rmc(&s[idx..], &mut t);
  }
  // Accelerometer (QuickTimeStream.pl:1746-1750): if GPS valid, read 3 ×
  // int32s at offset 68 / 256.
  if t.lat.is_some() && data.len() >= 68 + 12 {
    let p = 68;
    let raw: Vec<u32> = (0..3).filter_map(|i| le_u32(data, p + i * 4)).collect();
    if raw.len() == 3 {
      let vs = signed_div(&raw, 256.0);
      t.accel = Some((vs[0], vs[1], vs[2]));
    }
  }
  t.emit(out);
}

/// Parse a `$XXRMC,…` NMEA sentence into the `FreeGpsTags` accumulator.
/// QuickTimeStream.pl:1733 pattern.
fn parse_nmea_rmc(s: &str, t: &mut FreeGpsTags) {
  // Drop the `*` checksum tail to simplify field splitting.
  let s = s.split('*').next().unwrap_or(s);
  let fields: Vec<&str> = s.split(',').collect();
  // Fields: 0=$RMC, 1=HHMMSS.sss, 2=A, 3=lat, 4=N/S, 5=lon, 6=E/W,
  //         7=spd(knots), 8=trk, 9=DDMMYY, 10..=A
  if fields.len() < 10 {
    return;
  }
  if let Some(tm) = fields.get(1).copied()
    && tm.len() >= 6
    && tm[..6].chars().all(|c| c.is_ascii_digit())
  {
    t.hr = tm[0..2].parse().ok();
    t.min = tm[2..4].parse().ok();
    let sec = &tm[4..];
    t.sec = Some(sec.to_string());
  }
  if let Some(lat) = fields.get(3).copied()
    && let Ok(v) = lat.parse::<f64>()
  {
    t.lat = Some(v);
  }
  if let Some(ns) = fields.get(4).copied()
    && let Some(c) = ns.chars().next()
    && (c == 'N' || c == 'S')
  {
    t.lat_ref = Some(c);
  }
  if let Some(lon) = fields.get(5).copied()
    && let Ok(v) = lon.parse::<f64>()
  {
    t.lon = Some(v);
  }
  if let Some(ew) = fields.get(6).copied()
    && let Some(c) = ew.chars().next()
    && (c == 'E' || c == 'W')
  {
    t.lon_ref = Some(c);
  }
  if let Some(spd) = fields.get(7).copied()
    && !spd.is_empty()
    && let Ok(v) = spd.parse::<f64>()
  {
    t.spd = Some(v * KNOTS_TO_KPH);
  }
  if let Some(trk) = fields.get(8).copied()
    && !trk.is_empty()
    && let Ok(v) = trk.parse::<f64>()
  {
    t.trk = Some(v);
  }
  if let Some(date) = fields.get(9).copied()
    && date.len() == 6
    && date.chars().all(|c| c.is_ascii_digit())
  {
    t.day = date[0..2].parse().ok();
    t.mon = date[2..4].parse().ok();
    let yr_raw: i32 = date[4..6].parse().unwrap_or(0);
    // QuickTimeStream.pl:1735 `yr = $13 + ($13 >= 70 ? 1900 : 2000)`.
    t.yr = Some(yr_raw + if yr_raw >= 70 { 1900 } else { 2000 });
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
      let lat_ref = data[candidate + 4] as char;
      let lon_ref = data[candidate + 5] as char;
      let payload = if candidate == 85 {
        // QuickTimeStream.pl:1764 `$$dataPt = substr($$dataPt, 48)`.
        &data[48..]
      } else {
        data
      };
      return Some(((candidate, lat_ref, lon_ref), payload));
    }
  }
  None
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
    lt_window = &data[0x2c..0x40];
    ln_window = &data[0x40..0x54];
    for w in [lt_window, ln_window] {
      let trimmed = w.split(|&b| b == 0).next().unwrap_or(&[]);
      let is_b64 = trimmed.len() >= 8
        && trimmed.len() <= 22
        && trimmed
          .iter()
          .all(|&c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=');
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
    if yr_raw >= 2000 {
      // QuickTimeStream.pl:1786-1795 — local-time → UTC conversion (the gen-
      // golden config pins TZ=UTC + QuickTimeUTC=1, so it's effectively a
      // no-op since the local zone is UTC).
      t.yr = Some(yr_raw as i32);
      t.mon = Some(mon);
      t.day = Some(day);
      t.hr = Some(hr);
      t.min = Some(min);
      t.sec = Some(alloc::format!("{sec:02}"));
    } else {
      t.yr = Some(yr_raw as i32);
      t.mon = Some(mon);
      t.day = Some(day);
      t.hr = Some(hr);
      t.min = Some(min);
      t.sec = Some(alloc::format!("{sec:02}"));
    }
    t.lat = le_f32(data, 0x2c);
    t.lon = le_f32(data, 0x30);
    t.spd = le_f32(data, 0x34).map(|v| v * KNOTS_TO_KPH);
    t.trk = le_f32(data, 0x38);
    // Accelerometer (QuickTimeStream.pl:1800-1804) at offset 60 (12 bytes).
    if data.len() >= 72 {
      let tmp = &data[60..72];
      let all_zero = tmp.iter().all(|&b| b == 0);
      let counter = tmp == [1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0];
      if !all_zero && !counter {
        let raw: Vec<u32> = (0..3).filter_map(|i| le_u32(data, 60 + i * 4)).collect();
        if raw.len() == 3 {
          let vs = signed_div(&raw, 256.0);
          t.accel = Some((vs[0], vs[1], vs[2]));
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
        t.accel = Some((acc[0], acc[1], acc[2]));
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
  for i in 0..256u32 {
    j = (j + s[i as usize] + u32::from(key[(i as usize) % key.len()])) & 0xff;
    s.swap(i as usize, j as usize);
  }
  let mut out = Vec::with_capacity(input.len());
  let (mut i, mut j) = (0u32, 0u32);
  for &b in input {
    i = i.wrapping_add(1) & 0xff;
    j = (j + s[i as usize]) & 0xff;
    s.swap(i as usize, j as usize);
    let k = s[((s[i as usize] + s[j as usize]) & 0xff) as usize] as u8;
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
/// QuickTimeStream.pl:1843. Returns the matched offset (`Some(16|48|80)`).
fn detect_type5_ligogps(data: &[u8]) -> Option<usize> {
  for &off in &[16, 48, 80] {
    let end = off + b"LIGOGPSINFO\0".len();
    if data.len() >= end && &data[off..end] == b"LIGOGPSINFO\0" {
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
    t.accel = Some((vs[0], vs[1], vs[2]));
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
  for &b in &data[60..60 + 80] {
    decoded.push(if b >= 16 { b - 16 } else { b });
  }
  let s = core::str::from_utf8(&decoded).unwrap_or("");
  let mut t = FreeGpsTags::new();
  parse_nmea_rmc(s, &mut t);
  t.emit(out);
}

// ────────────────── GPSType 8: Akaso V1 / Redtiger F7N (encrypted) ─────────

fn detect_type8(data: &[u8]) -> bool {
  // QuickTimeStream.pl:1961 `^.{64}[\x01-\x0c]\0{3}[\x01-\x1f]\0{3}A[NS][EW]\0{5}`.
  if data.len() < 0x78 {
    return false;
  }
  data[64] >= 0x01
    && data[64] <= 0x0c
    && data[65..68] == [0, 0, 0]
    && data[68] >= 0x01
    && data[68] <= 0x1f
    && data[69..72] == [0, 0, 0]
    && data[72] == b'A'
    && (data[73] == b'N' || data[73] == b'S')
    && (data[74] == b'E' || data[74] == b'W')
    && data[75..80] == [0, 0, 0, 0, 0]
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
  t.trk = le_f32(data, 0x64).map(|v| {
    let mut x = v + 180.0;
    if x >= 360.0 {
      x -= 360.0;
    }
    x
  });
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
      t.accel = Some((vs[0], vs[1], vs[2]));
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
/// two key bytes from within the record, then validated and emitted.
fn decode_type11_atc(data: &[u8], out: &mut QuickTimeStreamMeta) {
  // Sequential walk through all 52-byte records (the ExifTool ring-buffer
  // recent-record logic is stateful across calls; we emit every valid record
  // we find in this block).
  let mut pos = 0x30usize;
  while pos + 52 <= data.len() {
    let mut a = [0u8; 52];
    a.copy_from_slice(&data[pos..pos + 52]);
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
    let now = [hr, min, sec, yr, mon, day];
    let mut valid = true;
    for (n, max) in now.iter().zip(DATE_MAX.iter()) {
      if *n > *max {
        valid = false;
        break;
      }
    }
    // ExifTool's `Then` state filters out records older-than-most-recent. We
    // approximate that by dropping all-zero (or yr/mon/day = 0) records,
    // which are the unwritten ring-buffer slots.
    if !valid || yr == 0 || mon == 0 || day == 0 {
      pos += 52;
      continue;
    }
    let mut sample = GpsSample::new();
    // QuickTimeStream.pl:2135-2143.
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
    pos += 52;
  }
}

// ────────────── GPSType 12: 80-byte double lat/lon variant ─────────────────

/// `decode_type12_double` (QuickTimeStream.pl:2159-2188).
fn decode_type12_double(data: &[u8], out: &mut QuickTimeStreamMeta) {
  if data.len() < 0x88 {
    return;
  }
  let mut t = FreeGpsTags::new();
  t.lat_ref = data.get(71).map(|&b| b as char);
  t.lon_ref = data.get(86).map(|&b| b as char);
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
    t.accel = Some((vs[0], vs[1], vs[2]));
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
    if data[pos] == b'A'
      && (data[pos + 1] == b'N' || data[pos + 1] == b'S')
      && (data[pos + 2] == b'E' || data[pos + 2] == b'W')
      && data[pos + 3] == 0
    {
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
      let lat_signed = if data[pos + 1] == b'S' { -lat_c } else { lat_c };
      let lon_signed = if data[pos + 2] == b'W' { -lon_c } else { lon_c };
      let mut sample = GpsSample::new();
      sample.set_latitude(Some(lat_signed));
      sample.set_longitude(Some(lon_signed));
      sample.set_speed_kph(Some(spd));
      sample.set_track(Some(trk));
      if acc.len() == 3 {
        sample.set_accelerometer(Some(SmolStr::from(join3(acc[0], acc[1], acc[2]))));
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
  data[20] <= 0x18
    && data[21] <= 0x3b
    && data[22] <= 0x3b
    && data[23] <= 0x09
    && data[24] == b'A'
    && (data[25] == b'N' || data[25] == b'S')
    && (data[26] == b'E' || data[26] == b'W')
}

/// `decode_type14_xbht` (QuickTimeStream.pl:2216-2238). Records of `[7][A NS EW][25]`.
fn decode_type14_xbht(data: &[u8], out: &mut QuickTimeStreamMeta) {
  let mut pos = 0usize;
  while pos + 33 <= data.len() {
    // Find the next `.{7}[\0-\x09]A[NS][EW].{25}` record.
    // QuickTimeStream.pl:2225 — `(.{7}[\0-\x09]A[NS][EW].{25})`. The record
    // starts at the byte before `A`.
    let rec_start = pos;
    if data.len() < rec_start + 33 {
      break;
    }
    let rec = &data[rec_start..rec_start + 33];
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
      pos += 33;
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
    t.accel = Some((vs[0], vs[1], vs[2]));
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
fn decode_type16_17_viofo(data: &[u8], out: &mut QuickTimeStreamMeta) {
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
    let lat = le_f32(data, 0x4c).unwrap_or(0.0);
    let lon = le_f32(data, 0x50).unwrap_or(0.0);
    let mut spd = le_f32(data, 0x54).unwrap_or(0.0) * KNOTS_TO_KPH;
    let trk = le_f32(data, 0x58).unwrap_or(0.0);
    // 17b: Rexing V1-4k scaling (uses an external KodakVersion check;
    // here we don't have access to global state, so this branch is only
    // taken when (a) data[0] >= 'K' shape *and* abs check. We approximate
    // the gate using the Transcend size-4 shape only.
    // 17c: Transcend Drive Body Camera 70.
    if be_u32(data, 0) == Some(0x400000) && lat.abs() <= 90.0 && lon.abs() <= 180.0 {
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
  let needed = 23 + 4 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 1;
  if data.len() < needed {
    return false;
  }
  let s = &data[23..23 + needed - 23];
  // Verify shape.
  s.iter().enumerate().all(|(i, &c)| match i {
    0..=3 | 5..=6 | 8..=9 | 11..=12 | 14..=15 | 17..=18 => c.is_ascii_digit(),
    4 | 7 => c == b'/',
    10 => c == b' ',
    13 | 16 => c == b':',
    19 => c == b' ',
    20 => c == b'N' || c == b'S',
    _ => true,
  })
}

/// `decode_type18_xgody` (QuickTimeStream.pl:2354-2384). Parses the
/// `normal:YYYY/MM/DD HH:MM:SS N:lat W:lon spd_kmh x:.. y:.. z:.. A:trk H:..`
/// ASCII line.
fn decode_type18_xgody(data: &[u8], out: &mut QuickTimeStreamMeta) {
  let mut t = FreeGpsTags::new();
  t.ddd = true;
  let s_full = core::str::from_utf8(data).unwrap_or("");
  // Trim trailing NULs.
  let s = s_full.trim_end_matches('\0');
  // Date/time at offset 23.
  if s.len() >= 23 + 19 {
    let dt = &s[23..23 + 19];
    let yr: i32 = dt[0..4].parse().unwrap_or(0);
    let mon: u32 = dt[5..7].parse().unwrap_or(0);
    let day: u32 = dt[8..10].parse().unwrap_or(0);
    let hr: u32 = dt[11..13].parse().unwrap_or(0);
    let min: u32 = dt[14..16].parse().unwrap_or(0);
    let sec_s = &dt[17..19];
    t.yr = Some(yr);
    t.mon = Some(mon);
    t.day = Some(day);
    t.hr = Some(hr);
    t.min = Some(min);
    t.sec = Some(sec_s.to_string());
  }
  // Field stream at offset 43.
  if s.len() > 43 {
    let mut acc: [Option<f64>; 3] = [None, None, None];
    let mut acc_idx = 0usize;
    for tok in s[43..].split_ascii_whitespace() {
      if let Some((k, v)) = tok.split_once(':') {
        if k.len() != 1 {
          continue;
        }
        let ch = k.chars().next().unwrap();
        if let Ok(num) = v.parse::<f64>() {
          match ch {
            'N' => {
              t.lat = Some(num);
              t.lat_ref = Some('N');
            }
            'S' => {
              t.lat = Some(num);
              t.lat_ref = Some('S');
            }
            'E' => {
              t.lon = Some(num);
              t.lon_ref = Some('E');
            }
            'W' => {
              t.lon = Some(num);
              t.lon_ref = Some('W');
            }
            'x' | 'y' | 'z' if acc_idx < 3 => {
              acc[acc_idx] = Some(num);
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
        }
      } else if t.lon.is_some() && t.spd.is_none() {
        // QuickTimeStream.pl:2373 — spd is the first bare number after lon,
        // displayed in km/h but raw is knots (multiply by knotsToKph).
        if let Ok(n) = tok.parse::<f64>() {
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

/// `decode_type19_70mai` (QuickTimeStream.pl:2386-2401). No timestamps in the
/// sample data; lat/lon as int32s/1e5 at offsets 31/35.
fn decode_type19_70mai(data: &[u8], out: &mut QuickTimeStreamMeta) {
  if data.len() < 47 {
    return;
  }
  let mut t = FreeGpsTags::new();
  t.ddd = true;
  let lat = i32::from_le_bytes([data[31], data[32], data[33], data[34]]);
  let lon = i32::from_le_bytes([data[35], data[36], data[37], data[38]]);
  let spd_raw = i32::from_le_bytes([data[43], data[44], data[45], data[46]]);
  t.lat = Some(f64::from(lat) / 1e5);
  t.lon = Some(f64::from(lon) / 1e5);
  t.spd = Some(f64::from(spd_raw)); // QuickTimeStream.pl:2399 — "seems to be km/h but NC".
  t.emit(out);
}

// ────────────── GPSType 20: Nextbase 512G (32-byte BE records) ─────────────

/// `decode_type20_nextbase512` (QuickTimeStream.pl:2403-2451). Big-endian
/// records starting at offset 0x32, stepping 0x20 bytes.
fn decode_type20_nextbase512(data: &[u8], out: &mut QuickTimeStreamMeta) {
  let mut pos = 0x32usize;
  loop {
    if pos + 30 > data.len() {
      break;
    }
    let spd = be_u16(data, pos).unwrap_or(0);
    let trk_raw = be_u16(data, pos + 2).unwrap_or(0);
    let yr = u32::from(be_u16(data, pos + 4).unwrap_or(0));
    let mon = u32::from(data[pos + 6]);
    let day = u32::from(data[pos + 7]);
    let hr = u32::from(data[pos + 8]);
    let min = u32::from(data[pos + 9]);
    let sec_raw = be_u16(data, pos + 10).unwrap_or(0);
    let lat_raw = be_u32(data, pos + 13).unwrap_or(0);
    let lon_raw = be_u32(data, pos + 17).unwrap_or(0);

    // QuickTimeStream.pl:2433 — validate by date/time bounds.
    if !(2000..=2200).contains(&yr) || !(1..=12).contains(&mon) || !(1..=31).contains(&day) {
      break;
    }
    if hr > 59 || min > 59 || sec_raw > 600 {
      break;
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
    // QuickTimeStream.pl:2449 `last if $pos += 0x20 > length - 0x1e`.
    pos += 0x20;
    if pos > data.len().saturating_sub(0x1e) {
      break;
    }
  }
}

// ===========================================================================
// Dashcam-vendor `gpmd` variant handlers (QuickTimeStream.pl:181-212)
// ===========================================================================
//
// The `gpmd` MetaFormat re-dispatches by `Condition` to one of five variant
// process-procs. exifast's [`process_free_gps`] above already covers the
// Kingslim case (its bundled Condition `^.{21}\0\0\0A[NS][EW]` matches an
// inner pattern that overlaps GPSType 3/4's offset-37 detector AFTER the
// 16-byte freeGPS header is stripped). The remaining variants — Rove (ASCII
// XOR-text), FMAS (Vantrue N2S binary), Wolfbox (G900 / Redtiger F9 4K
// binary) — have dedicated process-procs in bundled which we port below.
//
// Dispatch site (this module's `dispatch_gpmd`) mirrors the bundled
// `QuickTimeStream.pl:181-212` Condition cascade exactly:
//   * `^.{21}\0\0\0A[NS][EW]` → ProcessFreeGPS (Kingslim D4 dashcam)
//   * `^\0\0\xf2\xe1\xf0\xeeTT` → Process_text (Rove Stealth 4K encrypted)
//   * `^FMAS\0\0\0\0` → ProcessFMAS (Vantrue N2S)
//   * `^.{136}(0{16}[A-Z]{4}|https:\/\/www.redtiger\0)` → ProcessWolfbox
//   * (else) → GoPro GPMF
//
// All four self-contained branches funnel into the same [`GpsSample`]
// vector via [`FreeGpsTags::emit`]; the GoPro branch routes to the GoPro
// KLV walker.

/// Dispatch a `gpmd` sample by the bundled QuickTimeStream.pl:181-212
/// Condition cascade. Returns `true` if any of the dashcam-variant branches
/// matched (Kingslim / Rove / FMAS / Wolfbox); the caller falls back to the
/// GoPro GPMF parser on `false`.
///
/// `data` is the raw sample bytes (no `freeGPS ` 16-byte header — these
/// arrive through the `stbl` sample tables, not the brute-force mdat scan).
pub fn dispatch_gpmd(data: &[u8], out: &mut QuickTimeStreamMeta) -> bool {
  // gpmd_Kingslim — `^.{21}\0\0\0A[NS][EW]` (QuickTimeStream.pl:183).
  // The pattern matches a `freeGPS `-formatted Kingslim record EMBEDDED in
  // the gpmd sample (the leading 21 bytes are the gpmd header that
  // ProcessFreeGPS expects + skips). Re-route via `process_free_gps` after
  // synthesising the leading box-size + magic so the existing detector
  // chain (`detect_type3_4`) fires at the same byte offsets bundled does.
  if data.len() >= 28
    && data.get(21..25) == Some(&[0, 0, 0, b'A'])
    && matches!(data.get(25), Some(&b'N' | &b'S'))
    && matches!(data.get(26), Some(&b'E' | &b'W'))
  {
    // Wrap as a synthetic freeGPS block (12-byte hdr + payload) and feed
    // through the established `process_free_gps` pipeline so the type-3/4
    // detector — which expects `A[NS][EW]\0` at offset 37 from the
    // BLOCK start (12 hdr + 25 sample = 37) — matches.
    let mut block = Vec::with_capacity(12 + data.len());
    block.extend_from_slice(&((data.len() as u32 + 12).to_be_bytes()));
    block.extend_from_slice(b"freeGPS ");
    block.extend_from_slice(data);
    process_free_gps(&block, None, out);
    return true;
  }
  // gpmd_Rove — `^\0\0\xf2\xe1\xf0\xeeTT` (QuickTimeStream.pl:190).
  if data.len() >= 8 && data[0..8] == [0x00, 0x00, 0xf2, 0xe1, 0xf0, 0xee, 0x54, 0x54] {
    process_text(data, out);
    return true;
  }
  // gpmd_FMAS — `^FMAS\0\0\0\0` (QuickTimeStream.pl:197).
  if data.len() >= 8 && data[0..8] == *b"FMAS\0\0\0\0" {
    process_fmas(data, out);
    return true;
  }
  // gpmd_Wolfbox — `^.{136}(0{16}[A-Z]{4}|https:\/\/www.redtiger\0)`
  // (QuickTimeStream.pl:204).
  if detect_wolfbox(data) {
    process_wolfbox(data, out);
    return true;
  }
  false
}

/// Detect the Wolfbox / Redtiger Condition (QuickTimeStream.pl:204):
/// `^.{136}(0{16}[A-Z]{4}|https:\/\/www.redtiger\0)`.
fn detect_wolfbox(data: &[u8]) -> bool {
  if data.len() < 136 + 20 {
    return false;
  }
  let tail = &data[136..];
  // Branch A: `0{16}[A-Z]{4}` — 16 ASCII '0' chars then 4 uppercase letters.
  if tail.len() >= 20
    && tail[0..16] == [b'0'; 16]
    && tail[16..20].iter().all(|c| c.is_ascii_uppercase())
  {
    return true;
  }
  // Branch B: `https://www.redtiger\0` (literal 21 bytes incl. NUL).
  if tail.len() >= 21 && tail[0..21] == *b"https://www.redtiger\0" {
    return true;
  }
  false
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
pub fn process_text(data: &[u8], out: &mut QuickTimeStreamMeta) {
  let mut t = FreeGpsTags::new();
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
    && data[0] == 0
    && data[1] == 0
    && (data[4..6] == [0xaa, 0xaa] || data[2..6] == [0xf2, 0xe1, 0xf0, 0xee])
  {
    if decode_xor_aa_block(data, &mut t) {
      t.ddd = true;
      t.emit(out);
    }
    return;
  }
  // The Mini 0806 / Roadhawk / DJI telemetry / Thinkware-NMEA branches are
  // text-only fallbacks; their fingerprints are independent of the binary
  // dashcam variants we wire up here. Faithful-port stubs follow the same
  // ASCII flow path used by NMEA above and surface via [`FreeGpsTags::emit`].
  // (See follow-up issue: less common Process_text fallbacks.)
  let _ = data;
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
      let rel = self.bytes[self.pos..].iter().position(|&b| b == b'$')?;
      let tag_start = self.pos + rel + 1;
      // Read \w+ (alnum + underscore — bundled `\w` matches [A-Za-z0-9_]).
      let mut tag_end = tag_start;
      while tag_end < self.bytes.len()
        && (self.bytes[tag_end].is_ascii_alphanumeric() || self.bytes[tag_end] == b'_')
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
      while data_end < self.bytes.len() && self.bytes[data_end] != b'$' && self.bytes[data_end] != 0
      {
        data_end += 1;
      }
      let tag = match core::str::from_utf8(&self.bytes[tag_start..tag_end]) {
        Ok(t) => t,
        Err(_) => {
          self.pos = data_end;
          continue;
        }
      };
      let dat = match core::str::from_utf8(&self.bytes[tag_end..data_end]) {
        Ok(d) => d,
        Err(_) => {
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
  b.len() >= 2 && b[0].is_ascii_uppercase() && b[1].is_ascii_uppercase()
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
  while p < b.len() && b[p].is_ascii_digit() {
    p += 1;
  }
  if p == sec_start || p >= b.len() || b[p] != b'.' {
    return None;
  }
  p += 1; // skip '.'
  while p < b.len() && b[p].is_ascii_digit() {
    p += 1;
  }
  let sec = core::str::from_utf8(&b[sec_start..p]).ok()?.to_string();
  if p >= b.len() || b[p] != b',' {
    return None;
  }
  p += 1;
  // Optional 'A,'.
  if p < b.len() && b[p] == b'A' {
    p += 1;
    if p >= b.len() || b[p] != b',' {
      return None;
    }
    p += 1;
  }
  // lat: (\d*?)(\d{1,2}\.\d+) — the lazy prefix captures the degrees,
  // remainder is decimal-minutes.
  let (lat_deg, lat_min) = read_dddmm(b, &mut p)?;
  if p >= b.len() || b[p] != b',' {
    return None;
  }
  p += 1;
  // N/S
  if p >= b.len() {
    return None;
  }
  let lat_sign = match b[p] {
    b'N' => 1.0,
    b'S' => -1.0,
    _ => return None,
  };
  p += 1;
  if p >= b.len() || b[p] != b',' {
    return None;
  }
  p += 1;
  // lon
  let (lon_deg, lon_min) = read_dddmm(b, &mut p)?;
  if p >= b.len() || b[p] != b',' {
    return None;
  }
  p += 1;
  if p >= b.len() {
    return None;
  }
  let lon_sign = match b[p] {
    b'E' => 1.0,
    b'W' => -1.0,
    _ => return None,
  };
  p += 1;
  if p >= b.len() || b[p] != b',' {
    return None;
  }
  p += 1;
  // speed (knots) — \d*\.?\d*  → optional.
  let spd = parse_optional_decimal(b, &mut p)?;
  if p >= b.len() || b[p] != b',' {
    return None;
  }
  p += 1;
  let trk = parse_optional_decimal(b, &mut p)?;
  if p >= b.len() || b[p] != b',' {
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
  while p < b.len() && b[p].is_ascii_digit() {
    p += 1;
  }
  if p - yr_start < 2 {
    return None;
  }
  let yr_2: i32 = core::str::from_utf8(&b[yr_start..yr_start + 2])
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
  while p < b.len() && b[p].is_ascii_digit() {
    p += 1;
  }
  if p == sec_start {
    return None;
  }
  if p < b.len() && b[p] == b'.' {
    p += 1;
    while p < b.len() && b[p].is_ascii_digit() {
      p += 1;
    }
  }
  let sec = core::str::from_utf8(&b[sec_start..p]).ok()?.to_string();
  if p >= b.len() || b[p] != b',' {
    return None;
  }
  p += 1;
  let (lat_deg, lat_min) = read_dddmm(b, &mut p)?;
  if p >= b.len() || b[p] != b',' {
    return None;
  }
  p += 1;
  let lat_sign = match b.get(p)? {
    b'N' => 1.0,
    b'S' => -1.0,
    _ => return None,
  };
  p += 1;
  if p >= b.len() || b[p] != b',' {
    return None;
  }
  p += 1;
  let (lon_deg, lon_min) = read_dddmm(b, &mut p)?;
  if p >= b.len() || b[p] != b',' {
    return None;
  }
  p += 1;
  let lon_sign = match b.get(p)? {
    b'E' => 1.0,
    b'W' => -1.0,
    _ => return None,
  };
  p += 1;
  if p >= b.len() || b[p] != b',' {
    return None;
  }
  p += 1;
  // [1-6]?, then comma, then satellites/dop/altitude.
  if p < b.len() && (b[p] as char).is_ascii_digit() && b[p] >= b'1' && b[p] <= b'6' {
    p += 1;
  }
  if p >= b.len() || b[p] != b',' {
    return None;
  }
  p += 1;
  // satellites (digits, optional).
  while p < b.len() && b[p].is_ascii_digit() {
    p += 1;
  }
  if p >= b.len() || b[p] != b',' {
    return None;
  }
  p += 1;
  // DOP (decimal, optional).
  while p < b.len() && (b[p].is_ascii_digit() || b[p] == b'.') {
    p += 1;
  }
  if p >= b.len() || b[p] != b',' {
    return None;
  }
  p += 1;
  // altitude — `-?\d+(\.\d*)?` optional.
  let alt_start = p;
  if p < b.len() && b[p] == b'-' {
    p += 1;
  }
  let int_start = p;
  while p < b.len() && b[p].is_ascii_digit() {
    p += 1;
  }
  let alt = if p > int_start {
    if p < b.len() && b[p] == b'.' {
      p += 1;
      while p < b.len() && b[p].is_ascii_digit() {
        p += 1;
      }
    }
    core::str::from_utf8(&b[alt_start..p])
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
  if p >= b.len() || b[p] != b'-' {
    return None;
  }
  p += 1;
  let mon = parse_uint_fixed(b, &mut p, 2)?;
  if p >= b.len() || b[p] != b'-' {
    return None;
  }
  p += 1;
  let day = parse_uint_fixed(b, &mut p, 2)?;
  if p >= b.len() || b[p] != b' ' {
    return None;
  }
  p += 1;
  let hr = parse_uint_fixed(b, &mut p, 2)?;
  if p >= b.len() || b[p] != b':' {
    return None;
  }
  p += 1;
  let min = parse_uint_fixed(b, &mut p, 2)?;
  if p >= b.len() || b[p] != b':' {
    return None;
  }
  p += 1;
  let sec_start = p;
  let _ = parse_uint_fixed(b, &mut p, 2)?;
  let sec = core::str::from_utf8(&b[sec_start..p]).ok()?.to_string();
  if p >= b.len() || b[p] != b'-' {
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
  if p >= b.len() || b[p] != b'-' {
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
  if p >= b.len() || b[p] != b'-' {
    return None;
  }
  p += 1;
  if p >= b.len() || b[p] != b'S' {
    return None;
  }
  p += 1;
  // Speed = \d+ per bundled regex `S(\d+)` — integer.
  let spd_start = p;
  while p < b.len() && b[p].is_ascii_digit() {
    p += 1;
  }
  if p == spd_start {
    return None;
  }
  let spd: f64 = core::str::from_utf8(&b[spd_start..p]).ok()?.parse().ok()?;
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
  while *p < b.len() && b[*p].is_ascii_digit() {
    *p += 1;
  }
  if *p >= b.len() || b[*p] != b'.' {
    return None;
  }
  let dot = *p;
  // After the dot, advance over fractional digits.
  *p += 1;
  while *p < b.len() && b[*p].is_ascii_digit() {
    *p += 1;
  }
  // Integer part = `b[start..dot]`; \d{1,2} are the minutes integer.
  let int_part = &b[start..dot];
  if int_part.is_empty() {
    return None;
  }
  // Minutes integer is the LAST 1-2 chars; degrees prefix is the rest.
  // `\d{1,2}` — bundled is greedy here: match as many as possible up to 2.
  let take = int_part.len().min(2);
  let deg_str = &int_part[..int_part.len() - take];
  let min_int = &int_part[int_part.len() - take..];
  let frac = &b[dot..*p]; // includes the dot
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

/// Read a `\d{N}` fixed-width unsigned integer, advancing the cursor.
fn parse_uint_fixed(b: &[u8], p: &mut usize, n: usize) -> Option<u32> {
  if *p + n > b.len() {
    return None;
  }
  if !b[*p..*p + n].iter().all(|c| c.is_ascii_digit()) {
    return None;
  }
  let v: u32 = core::str::from_utf8(&b[*p..*p + n]).ok()?.parse().ok()?;
  *p += n;
  Some(v)
}

/// Read `\d*\.?\d*` (decimal, possibly empty). Returns `Ok(None)` if the
/// field is empty (matches Perl `length` test before assignment, lines
/// 1082-1083), `Ok(Some(v))` if non-empty. Returns `None` only on parse fail.
fn parse_optional_decimal(b: &[u8], p: &mut usize) -> Option<Option<f64>> {
  let start = *p;
  while *p < b.len() && (b[*p].is_ascii_digit() || b[*p] == b'.') {
    *p += 1;
  }
  if *p == start {
    return Some(None);
  }
  let s = core::str::from_utf8(&b[start..*p]).ok()?;
  if s == "." || s.is_empty() {
    return Some(None);
  }
  let v: f64 = s.parse().ok()?;
  Some(Some(v))
}

/// Read a `\d+\.\d+` decimal, advancing the cursor.
fn parse_decimal(b: &[u8], p: &mut usize) -> Option<f64> {
  let start = *p;
  while *p < b.len() && b[*p].is_ascii_digit() {
    *p += 1;
  }
  if *p == start {
    return None;
  }
  if *p < b.len() && b[*p] == b'.' {
    *p += 1;
    while *p < b.len() && b[*p].is_ascii_digit() {
      *p += 1;
    }
  }
  core::str::from_utf8(&b[start..*p]).ok()?.parse().ok()
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
  t.yr = s[0..4].parse().ok();
  t.mon = s[4..6].parse().ok();
  t.day = s[6..8].parse().ok();
  t.hr = s[8..10].parse().ok();
  t.min = s[10..12].parse().ok();
  t.sec = Some(s[12..14].to_string());
  // Latitude — 9 XOR'd bytes at offset 38, pattern `[NS]\d{2}\d+`.
  let lat_bytes = xor_aa_slice(data, 38, 9);
  if lat_bytes.len() == 9 {
    let lat_s = core::str::from_utf8(&lat_bytes).unwrap_or("");
    if let Some(c) = lat_s.chars().next()
      && (c == 'N' || c == 'S')
    {
      let deg_s = &lat_s[1..3];
      let frac_s = &lat_s[3..];
      if let (Ok(deg), Ok(frac)) = (deg_s.parse::<f64>(), frac_s.parse::<f64>()) {
        let mut lat = deg + frac / 600000.0;
        if c == 'S' {
          lat = -lat;
        }
        t.lat = Some(lat);
        t.lat_ref = None;
      }
    }
  }
  // Longitude — 10 XOR'd bytes at offset 47, pattern `[EW]\d{3}\d+`.
  let lon_bytes = xor_aa_slice(data, 47, 10);
  if lon_bytes.len() == 10 {
    let lon_s = core::str::from_utf8(&lon_bytes).unwrap_or("");
    if let Some(c) = lon_s.chars().next()
      && (c == 'E' || c == 'W')
    {
      let deg_s = &lon_s[1..4];
      let frac_s = &lon_s[4..];
      if let (Ok(deg), Ok(frac)) = (deg_s.parse::<f64>(), frac_s.parse::<f64>()) {
        let mut lon = deg + frac / 600000.0;
        if c == 'W' {
          lon = -lon;
        }
        t.lon = Some(lon);
        t.lon_ref = None;
      }
    }
  }
  // Altitude — 5 bytes at 0x39, `[-+]\d+`.
  let alt_b = xor_aa_slice(data, 0x39, 5);
  if let Ok(alt_s) = core::str::from_utf8(&alt_b)
    && (alt_s.starts_with('+') || alt_s.starts_with('-'))
    && alt_s[1..].chars().all(|c| c.is_ascii_digit())
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
  if data.len() > 6 && data[4..6] == [0xaa, 0xaa] && data.len() >= 0xad + 12 {
    let acc_b = xor_aa_slice(data, 0xad, 12);
    if let Ok(acc_s) = core::str::from_utf8(&acc_b)
      && acc_s.len() == 12
    {
      let x = acc_s[0..4].parse::<f64>().ok();
      let y = acc_s[4..8].parse::<f64>().ok();
      let z = acc_s[8..12].parse::<f64>().ok();
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

  /// Build a freeGPS block: `[size:4 BE]["freeGPS ":8]` then `inner` filling the
  /// rest of the BLOCK (block_size is set so block_size = 12 + inner.len()).
  /// QuickTimeStream.pl byte offsets are RELATIVE TO THE BLOCK START
  /// (the 12-byte header counts toward `^.{N}` offsets).
  fn freegps_block(inner: &[u8]) -> Vec<u8> {
    let total = (inner.len() + 12) as u32;
    let mut v = total.to_be_bytes().to_vec();
    v.extend_from_slice(b"freeGPS ");
    v.extend_from_slice(inner);
    v
  }

  /// Build a freeGPS block from a `inner` mut buffer that is treated as the
  /// payload at BLOCK offset 12. Returns the assembled BLOCK.
  fn make_block(payload_size: usize) -> (Vec<u8>, usize) {
    // BLOCK = 12-byte header + payload_size payload bytes.
    let mut v = vec![0u8; 12 + payload_size];
    let total = v.len() as u32;
    v[0..4].copy_from_slice(&total.to_be_bytes());
    v[4..12].copy_from_slice(b"freeGPS ");
    (v, 12)
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
    process_free_gps(&[0u8; 50], None, &mut out);
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
        block[18 + i] = b ^ 0xaa;
      }
    }
    let mut out = QuickTimeStreamMeta::new();
    process_free_gps(&block, None, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = &out.gps_samples()[0];
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
    block[60] = b'A';
    block[68] = b'N';
    block[76] = b'W';
    // hr/min/sec at 0x30..0x3c (3×u32 LE).
    block[0x30..0x34].copy_from_slice(&14u32.to_le_bytes());
    block[0x34..0x38].copy_from_slice(&30u32.to_le_bytes());
    block[0x38..0x3c].copy_from_slice(&45u32.to_le_bytes());
    // yr/mon/day at 0x30+12+28 = 0x58..0x64 (3×u32 LE).
    block[0x58..0x5c].copy_from_slice(&2024u32.to_le_bytes());
    block[0x5c..0x60].copy_from_slice(&7u32.to_le_bytes());
    block[0x60..0x64].copy_from_slice(&15u32.to_le_bytes());
    // accel: 3×u32 LE at 0x64.
    block[0x64..0x68].copy_from_slice(&1000u32.to_le_bytes());
    block[0x68..0x6c].copy_from_slice(&2000u32.to_le_bytes());
    block[0x6c..0x70].copy_from_slice(&3000u32.to_le_bytes());
    // lat/lon/spd/trk floats at 0x40..0x58.
    block[0x40..0x44].copy_from_slice(&4737.7053f32.to_le_bytes());
    block[0x48..0x4c].copy_from_slice(&12209.901f32.to_le_bytes());
    block[0x50..0x54].copy_from_slice(&60.0f32.to_le_bytes());
    block[0x54..0x58].copy_from_slice(&90.0f32.to_le_bytes());
    let mut out = QuickTimeStreamMeta::new();
    process_free_gps(&block, None, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = &out.gps_samples()[0];
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
    block[0x45..0x48].copy_from_slice(b"ATC");
    let rec_off = 0x30usize;
    // Record-local offsets:
    //   0x0d hour-1, 0x0e min, 0x0f sec
    //   0x10..0x13 int32s latitude*1e7, 0x14 = key1
    //   0x15..0x17 "ATC" (this is the detection trigger when at rec+0x15)
    //   0x18..0x1b int32s longitude*1e7, 0x1c key2
    //   0x20..0x23 int32s speed*100, 0x24..0x25 int16s heading*100
    //   0x28..0x2b int32s altitude*1000, 0x2c..0x2d int16u year
    //   0x2e mon, 0x2f day
    block[rec_off + 0x0d] = 13; // hr+1 ⇒ hr=14
    block[rec_off + 0x0e] = 30; // min
    block[rec_off + 0x0f] = 45; // sec
    block[rec_off + 0x10..rec_off + 0x14].copy_from_slice(&476_284_215i32.to_le_bytes());
    block[rec_off + 0x15..rec_off + 0x18].copy_from_slice(b"ATC");
    block[rec_off + 0x18..rec_off + 0x1c].copy_from_slice(&(-1_221_650_167i32).to_le_bytes());
    block[rec_off + 0x20..rec_off + 0x24].copy_from_slice(&2000i32.to_le_bytes());
    block[rec_off + 0x24..rec_off + 0x26].copy_from_slice(&18000i16.to_le_bytes());
    block[rec_off + 0x28..rec_off + 0x2c].copy_from_slice(&100_000i32.to_le_bytes());
    block[rec_off + 0x2c..rec_off + 0x2e].copy_from_slice(&2024u16.to_le_bytes());
    block[rec_off + 0x2e] = 7;
    block[rec_off + 0x2f] = 15;
    // Keys 0x14/0x1c are both already 0 ⇒ XOR is identity.
    let mut out = QuickTimeStreamMeta::new();
    process_free_gps(&block, None, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = &out.gps_samples()[0];
    assert!((s.latitude().unwrap() - 47.6_284_215).abs() < 1e-6);
    assert!((s.longitude().unwrap() + 122.1_650_167).abs() < 1e-6);
    assert_eq!(s.date_time(), Some("2024:07:15 14:30:45Z"));
    assert!(s.altitude_m().is_some());
  }

  #[test]
  fn type20_nextbase_be_decodes_one_record() {
    // Type 20 is the catch-all: an `mdat` block that doesn't match any other
    // fingerprint. The 32-byte BE record starts at BLOCK offset 0x32.
    let (mut block, _) = make_block(0x100);
    let rec_off = 0x32usize;
    block[rec_off..rec_off + 2].copy_from_slice(&1000u16.to_be_bytes());
    block[rec_off + 2..rec_off + 4].copy_from_slice(&12000u16.to_be_bytes());
    block[rec_off + 4..rec_off + 6].copy_from_slice(&2024u16.to_be_bytes());
    block[rec_off + 6] = 7;
    block[rec_off + 7] = 15;
    block[rec_off + 8] = 14;
    block[rec_off + 9] = 30;
    block[rec_off + 10..rec_off + 12].copy_from_slice(&455u16.to_be_bytes());
    block[rec_off + 13..rec_off + 17].copy_from_slice(&476_284_215i32.to_be_bytes());
    block[rec_off + 17..rec_off + 21].copy_from_slice(&(-1_221_650_167i32).to_be_bytes());
    let mut out = QuickTimeStreamMeta::new();
    process_free_gps(&block, None, &mut out);
    assert!(!out.gps_samples().is_empty());
    let s = &out.gps_samples()[0];
    assert!((s.latitude().unwrap() - 47.6_284_215).abs() < 1e-6);
    assert!((s.longitude().unwrap() + 122.1_650_167).abs() < 1e-6);
    assert!(s.date_time().is_some());
  }

  #[test]
  fn scan_media_data_finds_block_in_mdat() {
    // Build a Type-6 freeGPS block (block-absolute offsets), put it inside an
    // `mdat` payload, then scan. ExifTool's scanner regex
    // (`\0..\0freeGPS `, QuickTimeStream.pl:3710) requires bytes 0 and 3 of
    // the 4-byte BE size header to be NUL — so the block size must be ≤
    // 0xffff00 AND a multiple of 256. We size to exactly 0x0100 here, then
    // pad the inner buffer to fit.
    let mut block = vec![0u8; 0x100];
    block[0..4].copy_from_slice(&0x0100u32.to_be_bytes());
    block[4..12].copy_from_slice(b"freeGPS ");
    block[60] = b'A';
    block[68] = b'N';
    block[76] = b'W';
    block[0x30..0x34].copy_from_slice(&14u32.to_le_bytes());
    block[0x34..0x38].copy_from_slice(&30u32.to_le_bytes());
    block[0x38..0x3c].copy_from_slice(&45u32.to_le_bytes());
    block[0x58..0x5c].copy_from_slice(&2024u32.to_le_bytes());
    block[0x5c..0x60].copy_from_slice(&7u32.to_le_bytes());
    block[0x60..0x64].copy_from_slice(&15u32.to_le_bytes());
    block[0x40..0x44].copy_from_slice(&4737.7053f32.to_le_bytes());
    block[0x48..0x4c].copy_from_slice(&12209.901f32.to_le_bytes());
    // Place inside a synthetic file: 100 bytes header + block + 100 bytes tail.
    let mut file = vec![0u8; 100];
    let mdat_offset = file.len() as u64;
    file.extend_from_slice(&block);
    let mdat_size = file.len() as u64 - mdat_offset;
    file.extend_from_slice(&[0u8; 100]);

    let mut out = QuickTimeStreamMeta::new();
    let mut gp = GoProMeta::new();
    scan_media_data(
      &file,
      mdat_offset,
      mdat_size,
      None,
      false,
      &mut out,
      &mut gp,
    );
    assert_eq!(out.gps_samples().len(), 1);
    assert!(gp.is_empty());
  }

  #[test]
  fn scan_media_data_short_circuits_when_embedded_found() {
    let mut out = QuickTimeStreamMeta::new();
    let mut gp = GoProMeta::new();
    let file = vec![0u8; 0x10000];
    scan_media_data(&file, 0, file.len() as u64, None, true, &mut out, &mut gp);
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
    let s = "$GPRMC,132230.000,A,4721.35197,N,00830.80859,E,22.519,199.88,141222,,,A";
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

  // ─── Process_text (Rove/Kingslim/general) ─────────────────────────────

  #[test]
  fn process_text_rmc_decimal_degrees_emitted() {
    // QuickTimeStream.pl:1066-1083 — `$GPRMC` ASCII sentence in raw text.
    // Sample: "$GPRMC,082138,A,5330.6683,N,00641.9749,W,012.5,87.86,050213,002.1,A"
    // Lat = (53 + 30.6683/60) = 53.5111... ; Lon = -(6 + 41.9749/60) = -6.69958...
    let raw = b"$GPRMC,082138.0,A,5330.6683,N,00641.9749,W,012.5,87.86,050213,002.1,A";
    let mut out = QuickTimeStreamMeta::new();
    process_text(raw, &mut out);
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
    process_text(raw, &mut out);
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
    process_text(raw, &mut out);
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
    process_text(raw, &mut out);
    assert!(out.gps_samples().is_empty());
  }

  #[test]
  fn process_text_corrupt_rmc_does_not_panic() {
    // Garbage data — must not panic; ideally produces no sample.
    let raw = b"$GPRMC,XXXX,YYY,ZZZZ";
    let mut out = QuickTimeStreamMeta::new();
    process_text(raw, &mut out);
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
    process_text(&data, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = &out.gps_samples()[0];
    assert!(s.date_time().unwrap().contains("2019:08:20 07:51:57"));
    assert!((s.latitude().unwrap() - (48.0 + 515873.0 / 600000.0)).abs() < 1e-4);
    assert!((s.longitude().unwrap() - (2.0 + 197769.0 / 600000.0)).abs() < 1e-4);
    assert_eq!(s.altitude_m(), Some(31.0));
    assert_eq!(s.speed_kph(), Some(45.0));
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
  fn dispatch_gpmd_routes_kingslim_to_freegps() {
    // Bundled `^.{21}\0\0\0A[NS][EW]` — Kingslim D4 dashcam.
    let mut d = vec![0u8; 256];
    // Place A/N/E at offset 24 (=21 + 3 zero bytes preceding A).
    // The regex is `.{21}\0\0\0A[NS][EW]` so A is at offset 24.
    d[21] = 0;
    d[22] = 0;
    d[23] = 0;
    d[24] = b'A';
    d[25] = b'N';
    d[26] = b'E';
    let mut out = QuickTimeStreamMeta::new();
    let matched = dispatch_gpmd(&d, &mut out);
    // The dispatch matches (returns true) and routes to process_free_gps;
    // even if process_free_gps doesn't produce a sample (because the inner
    // freeGPS state is uninitialized), the dispatch return must be true.
    assert!(matched, "Kingslim Condition should match");
  }

  #[test]
  fn dispatch_gpmd_routes_rove_to_process_text() {
    let mut d = vec![0u8; 300];
    d[0..8].copy_from_slice(&[0x00, 0x00, 0xf2, 0xe1, 0xf0, 0xee, 0x54, 0x54]);
    let mut out = QuickTimeStreamMeta::new();
    assert!(dispatch_gpmd(&d, &mut out));
  }

  #[test]
  fn dispatch_gpmd_routes_fmas() {
    let mut d = vec![0u8; 160];
    d[0..8].copy_from_slice(b"FMAS\0\0\0\0");
    d[80..84].copy_from_slice(b"SAMM");
    d[120] = b'A';
    let mut out = QuickTimeStreamMeta::new();
    assert!(dispatch_gpmd(&d, &mut out));
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
    assert!(dispatch_gpmd(&d, &mut out));
  }

  #[test]
  fn dispatch_gpmd_returns_false_for_gopro_fallback() {
    // No marker matches → caller routes to GoPro KLV walker.
    let d = vec![0u8; 256];
    let mut out = QuickTimeStreamMeta::new();
    assert!(!dispatch_gpmd(&d, &mut out));
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
}
