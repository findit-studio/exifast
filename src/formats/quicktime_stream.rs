// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "quicktime")]
//! Faithful port of `Image::ExifTool::QuickTime::ProcessSamples` and the
//! self-contained timed-metadata decoders (`lib/Image/ExifTool/
//! QuickTimeStream.pl`) — **QuickTime Sub-Port 3: embedded timed GPS
//! metadata**.
//!
//! ## What QuickTimeStream does
//!
//! A QuickTime / MP4 video can carry *timed metadata* tracks: a `trak` whose
//! `hdlr` HandlerType is `meta` / `data` / `sbtl` (or a magic `gps `/`GPS `
//! box at `moov`/file level) holding per-frame GPS coordinates, accelerometer
//! readings, timecodes, … written by dashcams, action cams and drones.
//!
//! ExifTool extracts these in two stages (QuickTimeStream.pl):
//!
//!  1. **`ParseTag`** (QuickTimeStream.pl:2489-2581) — while `ProcessMOV`
//!     walks the `stbl` box it hands every `stco`/`co64`/`stsz`/`stz2`/
//!     `stsc`/`stts` atom to `ParseTag`, which decodes them into the
//!     `$$et{ee}` accumulator (chunk offsets, sample sizes, sample-to-chunk
//!     map, time-to-sample map). The magic `gps `/`GPS ` boxes are processed
//!     by `ParseTag` directly.
//!  2. **`ProcessSamples`** (QuickTimeStream.pl:1304-1592) — invoked when the
//!     `stbl` box closes; it turns the chunk-offset + sample-to-chunk tables
//!     into a flat list of `(sample offset, sample size, sample time, sample
//!     duration)`, then for each sample reads the bytes and dispatches by
//!     `MetaFormat` / `HandlerType` to a per-camera decoder.
//!
//! ## SP3 scope (this module)
//!
//! Ported faithfully:
//!  - the sample-table decoders ([`parse_stsz`], [`parse_stco`],
//!    [`parse_stsc`], [`parse_stts`]) — QuickTimeStream.pl:2495-2538;
//!  - [`process_samples`] — the chunk→sample offset/time machinery
//!    (QuickTimeStream.pl:1339-1392) plus the sample dispatch loop;
//!  - [`process_mebx`] + [`save_meta_keys`] — Apple `mebx` timed metadata
//!    (QuickTimeStream.pl:876-962, 2644-2680);
//!  - the bounded binary GPS records: Novatek `gps `/Kenwood `GPS `
//!    ([`parse_gps_box`], [`parse_kenwood_gps`], QuickTimeStream.pl:2544-2580),
//!    `gps0` ([`process_gps0`]), `3gf` ([`process_3gf`]), `gsen`
//!    ([`process_gsen`]).
//!
//! **Deferred** (documented in `docs/tracking.md`):
//!  - `ProcessFreeGPS` (QuickTimeStream.pl:1637-2488) — the brute-force
//!    `freeGPS ` scanner, 40+ per-camera binary variants, ~850 lines;
//!  - decoders that re-dispatch into *other* ExifTool modules — GoPro `GPMF`,
//!    Sony `rtmd`, Canon `CTMD`, the full `camm` tables, Parrot `mett`;
//!  - the embedded Exif/TIFF hop (`uuid`/`Exif` atoms → `Exif::ProcessExif`)
//!    — awaits the merge of the Exif+GPS port (PR #36 / `lib/exif-gps`).
//!
//! The whole movie is big-endian (QuickTime.pm:10014 `SetByteOrder('MM')`);
//! the few little-endian records (`gps0`, `GPS `) are noted at each site.
//!
//! ## GPS priority chain
//!
//! [`QuickTimeStreamMeta`] is the **LOWEST tier** of the cross-port GPS
//! priority chain that [`crate::metadata::MediaMetadata`] projects from a
//! QuickTime file: GoPro GPMF → Android CAMM → Sony rtmd → Insta360
//! trailer → Parrot mett → SP3 stream. Its `first_fix()` is consulted only
//! when no higher-tier source decoded a coordinate pair. The chain ordering
//! reflects on-device-GPS-hardware fidelity (the action/drone cameras carry
//! their own GNSS) above phone-paired / dashcam-NMEA sources.

#![deny(clippy::indexing_slicing)]

extern crate alloc;
use alloc::{
  string::{String, ToString},
  vec::Vec,
};

use crate::{
  datetime::{convert_datetime, convert_unix_time},
  formats::quicktime_freegps::{self, FreeGpsState},
  metadata::{GpsSample, MebxSample, QuickTimeStreamMeta},
};

/// QuickTime epoch offset: seconds between 1904-01-01 and 1970-01-01.
/// `(66 * 365 + 17) * 24 * 3600` — QuickTime.pm:1361, QuickTimeStream.pl:3520.
const QT_EPOCH_OFFSET: i64 = (66 * 365 + 17) * 24 * 3600;

// (QuickTimeStream.pl:73-75 also defines `$knotsToKph` / `$mpsToKph` /
// `$mphToKph` speed-unit factors; SP3's bounded decoders carry GPSSpeed
// already in km/h or raw counts, so those factors land with the deferred
// freeGPS / Garmin decoders, not here.)

// ── big-endian / little-endian field readers ────────────────────────────

fn be_u16(b: &[u8], off: usize) -> Option<u16> {
  Some(u16::from_be_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

fn be_u32(b: &[u8], off: usize) -> Option<u32> {
  Some(u32::from_be_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

fn be_u64(b: &[u8], off: usize) -> Option<u64> {
  Some(u64::from_be_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

fn be_i16(b: &[u8], off: usize) -> Option<i16> {
  be_u16(b, off).map(|v| v as i16)
}

fn be_i32(b: &[u8], off: usize) -> Option<i32> {
  be_u32(b, off).map(|v| v as i32)
}

fn le_u16(b: &[u8], off: usize) -> Option<u16> {
  Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

fn le_u32(b: &[u8], off: usize) -> Option<u32> {
  Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

fn le_i32(b: &[u8], off: usize) -> Option<i32> {
  le_u32(b, off).map(|v| v as i32)
}

/// Read a big-endian IEEE-754 `double` (used by `gps0` lat/lon, which is a
/// little-endian record — see [`process_gps0`]).
fn le_f64(b: &[u8], off: usize) -> Option<f64> {
  Some(f64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

// ===========================================================================
// ConvertLatLon (QuickTimeStream.pl:1599-1605)
// ===========================================================================

/// `ConvertLatLon` (QuickTimeStream.pl:1599-1605): convert a coordinate from
/// `DDDMM.MMMM` (degrees*100 + decimal minutes) to decimal degrees. Works for
/// negative coordinates (`int()` truncates toward zero, matching Perl `int`).
pub(crate) fn convert_lat_lon(v: f64) -> f64 {
  // Perl `int($v / 100)` truncates toward zero.
  let deg = (v / 100.0) as i64 as f64;
  deg + (v - deg * 100.0) / 60.0
}

// ===========================================================================
// GPSDateTime synthesis (QuickTimeStream.pl SetGPSDateTime:980-1009)
// ===========================================================================

/// `SetGPSDateTime` (QuickTimeStream.pl:980-1009) — approximate a
/// `GPSDateTime` from a sample time and the movie `CreateDate`.
///
/// ExifTool: `$sampleTime += $$value{CreateDate}` (the create-date is the raw
/// 1904-epoch seconds), then — under `QuickTimeUTC` — emits
/// `ConvertUnixTime($sampleTime, 0, 3) . 'Z'`. The gen-golden config pins
/// `QuickTimeUTC=1` + `TZ=UTC`, so the local-time `$tzOff` branch
/// (QuickTimeStream.pl:995-1004) is dead and the result is the UTC string with
/// a `Z` suffix.
///
/// `create_date_raw` is the `mvhd` CreateDate as raw 1904-epoch seconds;
/// `sample_time` is the sample decoding time in seconds. Returns the displayed
/// `YYYY:MM:DD HH:MM:SS[.sss]Z` string, or `None` when there is no
/// CreateDate to anchor against (QuickTimeStream.pl:984 `if defined
/// $sampleTime and $$value{CreateDate}`).
pub(crate) fn synth_gps_date_time(
  create_date_raw: Option<u64>,
  sample_time: Option<f64>,
) -> Option<String> {
  // QuickTimeStream.pl:984 `if defined $sampleTime and $$value{CreateDate}` —
  // `$$value{CreateDate}` is truthiness-checked, so a raw CreateDate of 0 (the
  // QuickTime 1904-epoch zero-date sentinel) is FALSY and yields NO synthesized
  // GPSDateTime. Treat `Some(0)` like the missing case.
  let create = create_date_raw.filter(|&c| c != 0)?;
  let st = sample_time?;
  // $sampleTime += CreateDate (1904-epoch seconds), then to Unix epoch.
  let unix = create as f64 - QT_EPOCH_OFFSET as f64 + st;
  // ConvertUnixTime($sampleTime, 0, 3): integer-seconds resolution here
  // (the bounded decoders never carry sub-second sample times). 'Z' suffix.
  let mut s = convert_datetime(&convert_unix_time(unix as i64));
  s.push('Z');
  Some(s)
}

// ===========================================================================
// Sample-table decoders — ParseTag (QuickTimeStream.pl:2489-2581)
// ===========================================================================

/// Decoded `$$et{ee}` accumulator — the per-`stbl` timed-metadata sample
/// tables ExifTool collects in `ParseTag` before `ProcessSamples` runs
/// (QuickTimeStream.pl:2495-2538).
#[derive(Debug, Default, Clone)]
pub(crate) struct EeData {
  /// `stsz`/`stz2` sample sizes — one per sample (QuickTimeStream.pl:2495).
  size: Vec<u32>,
  /// `stco`/`co64` chunk offsets — absolute file offsets
  /// (QuickTimeStream.pl:2517).
  stco: Vec<u64>,
  /// `stsc` sample-to-chunk entries: `(first_chunk, samples_per_chunk,
  /// desc_index)` (QuickTimeStream.pl:2522).
  stsc: Vec<(u32, u32, u32)>,
  /// `stts` time-to-sample entries: flattened `(count, delta)` pairs
  /// (QuickTimeStream.pl:2533).
  stts: Vec<u32>,
}

/// `ParseTag` `stsz` / `stz2` (QuickTimeStream.pl:2495-2516): decode the
/// sample-size table into `ee.size`.
///
/// `stsz`: `[version+flags:4][sample-size:4][count:4]` then, when the fixed
/// `sample-size` is 0, `count` × `int32u`. `stz2`: the low byte of the
/// `sample-size` word is the bit-width (4 / 8 / 16); a width-4 table packs two
/// nibbles per byte.
fn parse_stsz(tag: &[u8; 4], data: &[u8], ee: &mut EeData) {
  // QuickTimeStream.pl:2495 `length > 12`.
  if data.len() <= 12 {
    return;
  }
  let Some(sz) = be_u32(data, 4) else { return };
  let Some(num) = be_u32(data, 8) else { return };
  let num = num as usize;
  let mut out = Vec::new();
  if tag == b"stsz" {
    if sz == 0 {
      // count × int32u, bounded by the available bytes.
      for i in 0..num {
        match be_u32(data, 12 + i * 4) {
          Some(v) => out.push(v),
          None => break,
        }
      }
    } else {
      // QuickTimeStream.pl:2503 `@$size = ($sz) x $num` — a uniform size.
      out = alloc::vec![sz; num];
    }
  } else {
    // stz2: bit-width is the low byte of the size word.
    let width = sz & 0xff;
    if width == 4 {
      // QuickTimeStream.pl:2508-2512 — two 4-bit sizes per byte
      // (`push @$size, $_ >> 4; push @$size, $_ & 0xff`). Note ExifTool's
      // low-nibble mask is `& 0xff`, NOT `& 0x0f` — a no-op on a byte, so
      // the "low" entry is faithfully the WHOLE byte value.
      let bytes = num.div_ceil(2);
      for i in 0..bytes {
        match data.get(12 + i) {
          Some(&b) => {
            out.push(u32::from(b >> 4));
            out.push(u32::from(b)); // Perl `$_ & 0xff` ≡ `$_` for a byte.
          }
          None => break,
        }
      }
    } else if width == 8 {
      for i in 0..num {
        match data.get(12 + i) {
          Some(&b) => out.push(u32::from(b)),
          None => break,
        }
      }
    } else if width == 16 {
      for i in 0..num {
        match be_u16(data, 12 + i * 2) {
          Some(v) => out.push(u32::from(v)),
          None => break,
        }
      }
    }
  }
  ee.size = out;
}

/// `ParseTag` `stco` / `co64` (QuickTimeStream.pl:2517-2521): decode the
/// chunk-offset table into `ee.stco`. `stco` entries are `int32u`, `co64`
/// entries `int64u`.
fn parse_stco(tag: &[u8; 4], data: &[u8], ee: &mut EeData) {
  if data.len() <= 8 {
    return;
  }
  let Some(num) = be_u32(data, 4) else { return };
  let num = num as usize;
  let mut out = Vec::new();
  for i in 0..num {
    let v = if tag == b"stco" {
      be_u32(data, 8 + i * 4).map(u64::from)
    } else {
      be_u64(data, 8 + i * 8)
    };
    match v {
      Some(v) => out.push(v),
      None => break,
    }
  }
  ee.stco = out;
}

/// `ParseTag` `stsc` (QuickTimeStream.pl:2522-2532): decode the
/// sample-to-chunk table into `ee.stsc`. Each entry is three `int32u`:
/// `(first-chunk, samples-per-chunk, sample-description-index)`. ExifTool
/// requires the WHOLE table to fit (`$dataLen >= 8 + $num * 12`) before
/// recording it.
fn parse_stsc(data: &[u8], ee: &mut EeData) {
  if data.len() <= 8 {
    return;
  }
  let Some(num) = be_u32(data, 4) else { return };
  let num = num as usize;
  // QuickTimeStream.pl:2525 `if $dataLen >= 8 + $num * 12`.
  if data.len() < 8 + num.saturating_mul(12) {
    return;
  }
  let mut out = Vec::with_capacity(num);
  for i in 0..num {
    let base = 8 + i * 12;
    let (Some(a), Some(b), Some(c)) = (
      be_u32(data, base),
      be_u32(data, base + 4),
      be_u32(data, base + 8),
    ) else {
      return;
    };
    out.push((a, b, c));
  }
  ee.stsc = out;
}

/// `ParseTag` `stts` (QuickTimeStream.pl:2533-2538): decode the
/// time-to-sample table into `ee.stts` (flattened `(count, delta)` pairs).
/// ExifTool requires the whole table to fit before recording it.
fn parse_stts(data: &[u8], ee: &mut EeData) {
  if data.len() <= 8 {
    return;
  }
  let Some(num) = be_u32(data, 4) else { return };
  let num = num as usize;
  // QuickTimeStream.pl:2536 `if $dataLen >= 8 + $num * 8`.
  if data.len() < 8 + num.saturating_mul(8) {
    return;
  }
  let mut out = Vec::with_capacity(num * 2);
  for i in 0..num {
    let base = 8 + i * 8;
    let (Some(count), Some(delta)) = (be_u32(data, base), be_u32(data, base + 4)) else {
      return;
    };
    out.push(count);
    out.push(delta);
  }
  ee.stts = out;
}

/// `ParseTag` `GPS ` (QuickTimeStream.pl:2557-2580): decode the Kenwood-style
/// `GPS ` box — a sequence of 36-byte LITTLE-ENDIAN records — directly into
/// GPS samples (this box is self-contained: it carries the data inline, not
/// offsets into `mdat`).
///
/// Record layout (`unpack 'VVVVaVaV'`): `[?:4][?:4][secs:4][speed*1e3:4]`
/// `[N/S:1][lat*1e3:4][E/W:1][lon*1e3:4]`. Lat/lon are `DDDMM.MMMM*1e3`.
fn parse_kenwood_gps(data: &[u8], create_date_raw: Option<u64>, out: &mut QuickTimeStreamMeta) {
  let mut pos = 0usize;
  // QuickTimeStream.pl:2561 `while ($pos + 36 < $dataLen)`.
  while pos + 36 < data.len() {
    // The `while` guard proves `pos + 36 <= data.len()`, so this `.get`
    // is always `Some`; the `else` is unreachable and lands on the same
    // loop-exit as the guard turning false.
    let Some(rec) = data.get(pos..pos + 36) else {
      break;
    };
    // QuickTimeStream.pl:2563 `last if $dat eq "\x0" x 36`.
    if rec.iter().all(|&b| b == 0) {
      break;
    }
    // 'VVVVaVaV' — little-endian: a[0..4) = int32u, a[4]=char, a[5]=int32u,
    // a[6]=char, a[7]=int32u.
    let secs = le_u32(rec, 8).unwrap_or(0);
    let speed = le_u32(rec, 12).unwrap_or(0);
    // `rec` is exactly 36 bytes, so indices 16/21 are always in range;
    // the `unwrap_or(0)` mirrors the adjacent `le_u32(..).unwrap_or(0)`
    // misses (a `0` byte is "not S/W" ⇒ no sign flip — the benign default).
    let ns = rec.get(16).copied().unwrap_or(0);
    let lat_raw = le_u32(rec, 17).unwrap_or(0);
    let ew = rec.get(21).copied().unwrap_or(0);
    let lon_raw = le_u32(rec, 22).unwrap_or(0);

    let mut lat = convert_lat_lon(f64::from(lat_raw) / 1e3);
    let mut lon = convert_lat_lon(f64::from(lon_raw) / 1e3);
    // QuickTimeStream.pl:2571-2572 `$lat = -abs($lat) if $a[4] eq 'S'`.
    if ns == b'S' {
      lat = -lat.abs();
    }
    if ew == b'W' {
      lon = -lon.abs();
    }
    let mut sample = GpsSample::new();
    // SetGPSDateTime($et, $tagTbl, $a[2]) — secs is the sample time.
    sample.set_date_time(
      synth_gps_date_time(create_date_raw, Some(f64::from(secs))).map(smol_str::SmolStr::from),
    );
    sample.set_latitude(Some(lat));
    sample.set_longitude(Some(lon));
    sample.set_speed_kph(Some(f64::from(speed) / 1e3));
    if !sample.is_empty() {
      out.push_gps_sample(sample);
    }
    pos += 36;
  }
}

// ===========================================================================
// ProcessSamples — chunk→sample machinery (QuickTimeStream.pl:1304-1592)
// ===========================================================================

/// One flattened timed sample — `(file offset, byte size, sample time,
/// sample duration)` — the output of the chunk→sample expansion
/// (QuickTimeStream.pl:1339-1392).
struct Sample {
  /// Absolute file offset of the sample bytes.
  start: u64,
  /// Sample byte size.
  size: u32,
  /// Sample decoding time in seconds (`@time`), if the `stts` table was
  /// usable.
  time: Option<f64>,
  /// Sample duration in seconds (`@dur`).
  dur: Option<f64>,
}

/// Expand the `stco`/`stsc`/`stsz`/`stts` tables into a flat sample list —
/// faithful port of QuickTimeStream.pl:1339-1392.
///
/// ExifTool walks the chunk-offset table; for each chunk it consults the
/// sample-to-chunk table to learn how many samples that chunk holds, then
/// lays the samples out back-to-back from the chunk offset using the
/// sample-size table. The time-to-sample table is consumed in lockstep to
/// assign `@time` / `@dur`.
///
/// `media_ts` is the per-track `MediaTimeScale` (`$$et{MediaTS}`,
/// QuickTimeStream.pl:1351 — defaults to 1 when absent/zero).
fn expand_samples(ee: &EeData, media_ts: u32) -> Option<Vec<Sample>> {
  if ee.stco.is_empty() || ee.stsc.is_empty() || ee.size.is_empty() {
    return None;
  }
  let ts = if media_ts == 0 {
    1.0
  } else {
    f64::from(media_ts)
  };

  // The `@$stts` queue is consumed front-to-back; mirror with an index.
  // QuickTimeStream.pl:1346 `if ($stts and @$stts > 1)`.
  let mut stts_idx = 0usize;
  let mut time: Option<u64> = None;
  let mut time_count: u32 = 0;
  let mut time_delta: u32 = 0;
  // `[c, d, ..]` matches exactly when `stts.len() > 1` (the bundled guard),
  // binding `stts[0]`/`stts[1]` without raw indexing — byte-identical.
  if let [c, d, ..] = *ee.stts.as_slice() {
    time = Some(0);
    time_count = c;
    time_delta = d;
    stts_idx = 2;
  }

  // The `@$stsc` queue (front-to-back). Each chunk consults it.
  let mut stsc_idx = 0usize;
  let mut next_chunk: u32 = 0;
  let mut samples_per_chunk: u32 = 0;

  // Each `Sample` carries its own `time`/`dur` (ExifTool's parallel
  // `@time`/`@dur` arrays are folded into the sample record here).
  let mut samples: Vec<Sample> = Vec::new();

  // QuickTimeStream.pl:1353 `foreach $chunkStart (@$stco)`. ExifTool's
  // `$iChunk` is the 1-based chunk ordinal — here `chunk_idx + 1`.
  for (chunk_idx, &chunk_start) in ee.stco.iter().enumerate() {
    let i_chunk = (chunk_idx + 1) as u32;
    // QuickTimeStream.pl:1354 — advance the stsc entry when we reach a new
    // first-chunk boundary.
    if i_chunk >= next_chunk
      && let Some(&(_first, spc, _desc)) = ee.stsc.get(stsc_idx)
    {
      samples_per_chunk = spc;
      stsc_idx += 1;
      next_chunk = ee.stsc.get(stsc_idx).map_or(0, |e| e.0);
    }
    // QuickTimeStream.pl:1358 `@$size < @$start + $samplesPerChunk` — a
    // sample-size shortfall stops the expansion ('Sample size error').
    if (ee.size.len() as u64) < samples.len() as u64 + u64::from(samples_per_chunk) {
      break;
    }
    let mut sample_start = chunk_start;
    // QuickTimeStream.pl:1362 `Sample: for ($i=0; ; )`.
    let mut i: u32 = 0;
    loop {
      let idx = samples.len();
      let size = *ee.size.get(idx)?;
      // QuickTimeStream.pl:1364-1377 — assign @time/@dur from the stts queue.
      let (mut s_time, mut s_dur) = (None, None);
      if let Some(t) = time {
        // QuickTimeStream.pl:1365 `until ($timeCount)` — refill from stts.
        let mut cur_time = t;
        let mut stopped = false;
        while time_count == 0 {
          // `.get(stts_idx..stts_idx + 2)` is `None` exactly when
          // `stts.len() < stts_idx + 2` — the same guard — and the
          // `else` runs the identical `undef $time; last Sample` recovery.
          let Some(&[c, d]) = ee.stts.get(stts_idx..stts_idx + 2) else {
            // QuickTimeStream.pl:1367-1369 `undef $time; last Sample`.
            time = None;
            stopped = true;
            break;
          };
          time_count = c;
          time_delta = d;
          stts_idx += 2;
        }
        if stopped {
          // `last Sample`: still push this sample's offset (the push at
          // QuickTimeStream.pl:1363 happened BEFORE the time block), then
          // leave the chunk loop.
          samples.push(Sample {
            start: sample_start,
            size,
            time: None,
            dur: None,
          });
          break;
        }
        s_time = Some(cur_time as f64 / ts);
        s_dur = Some(f64::from(time_delta) / ts);
        cur_time += u64::from(time_delta);
        time = Some(cur_time);
        time_count -= 1;
      }
      samples.push(Sample {
        start: sample_start,
        size,
        time: s_time,
        dur: s_dur,
      });
      // QuickTimeStream.pl:1380 `last if ++$i >= $samplesPerChunk`.
      i += 1;
      if i >= samples_per_chunk {
        break;
      }
      // QuickTimeStream.pl:1381 `$sampleStart += $$size[$#$start]`.
      sample_start += u64::from(size);
    }
  }
  // QuickTimeStream.pl:1386 `@$start == @$size or ... return` — a mismatch
  // is fatal ('Incorrect sample start/size count').
  if samples.len() != ee.size.len() {
    return None;
  }
  Some(samples)
}

/// `Process_mebx` keys-table entry — a local-ID → `(TagID, format)` mapping
/// recovered from the `OtherSampleDesc` `keys` box (QuickTimeStream.pl
/// `SaveMetaKeys`:876-962).
#[derive(Debug, Clone)]
struct MetaKey {
  /// The raw `keyd` TagID — the `keyd` value with the `(mdta|fiel)com.apple.
  /// quicktime.` namespace prefix stripped (QuickTimeStream.pl:915-916). This
  /// is ExifTool's `$$info{TagID}`; the *displayed* tag name is derived from it
  /// at emit time by [`resolve_mebx_tag`] (the `%QuickTime::Keys` lookup +
  /// camel-case fallback of `Process_mebx`, QuickTimeStream.pl:2657-2666).
  tag_id: String,
  /// The `qtFmt`-resolved value format (`int32u`, `float`, …).
  format: MetaFormat,
}

/// The `%qtFmt` value formats relevant to `mebx` decoding
/// (QuickTimeStream.pl:36-64). Only the codes a `dtyp` namespace-0 entry can
/// name are represented; an unknown code maps to [`MetaFormat::Undef`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetaFormat {
  /// `undef` — opaque bytes (the default; `qtFmt` 0 / unmapped).
  Undef,
  /// `string` — UTF-8 text (`qtFmt` 1).
  Str,
  /// `float` — 32-bit IEEE-754 (`qtFmt` 23, 70-72, 79, 80).
  Float,
  /// `double` — 64-bit IEEE-754 (`qtFmt` 24).
  Double,
  /// `int8s` (`qtFmt` 65).
  Int8s,
  /// `int16s` (`qtFmt` 66).
  Int16s,
  /// `int32s` (`qtFmt` 67).
  Int32s,
  /// `int64s` (`qtFmt` 74).
  Int64s,
  /// `int8u` (`qtFmt` 75).
  Int8u,
  /// `int16u` (`qtFmt` 76).
  Int16u,
  /// `int32u` (`qtFmt` 77).
  Int32u,
  /// `int64u` (`qtFmt` 78).
  Int64u,
}

impl MetaFormat {
  /// `%qtFmt` lookup (QuickTimeStream.pl:36-64). An unmapped code ⇒
  /// `undef` (QuickTimeStream.pl:925 `$qtFmt{$str} || 'undef'`).
  const fn from_qt_fmt(code: u32) -> Self {
    match code {
      1 => Self::Str,
      23 | 70 | 71 | 72 | 79 | 80 => Self::Float,
      24 => Self::Double,
      65 => Self::Int8s,
      66 => Self::Int16s,
      67 => Self::Int32s,
      74 => Self::Int64s,
      75 => Self::Int8u,
      76 => Self::Int16u,
      77 => Self::Int32u,
      78 => Self::Int64u,
      _ => Self::Undef,
    }
  }
}

/// `SaveMetaKeys` (QuickTimeStream.pl:876-962): walk the `OtherSampleDesc`
/// metadata-key table and recover the local-ID → `(TagID, format)` map for
/// `mebx` decoding.
///
/// The table is a sequence of `[size:4][local-id:4]` entries; each entry then
/// holds a sequence of inner `[len:4][tag:4][value]` records — `keyd` carries
/// the tag namespace+name, `dtyp` the value type.
///
/// `base` is the file offset of the `keys` box payload (only used for the
/// verbose dump in ExifTool; here it is unused but kept for parity of intent).
fn save_meta_keys(data: &[u8]) -> Vec<(u32, MetaKey)> {
  let mut keys: Vec<(u32, MetaKey)> = Vec::new();
  // QuickTimeStream.pl:882 `return 0 unless $dirLen > 8`.
  if data.len() <= 8 {
    return keys;
  }
  let mut pos = 0usize;
  // QuickTimeStream.pl:892 `while ($pos + 8 < $dirLen)`.
  while pos + 8 < data.len() {
    let Some(size) = be_u32(data, pos) else { break };
    let Some(local_id) = be_u32(data, pos + 4) else {
      break;
    };
    // QuickTimeStream.pl:895-896 — clamp the entry end to the buffer.
    let mut end = pos.saturating_add(size as usize);
    if end > data.len() {
      end = data.len();
    }
    pos += 8;
    let mut tag_id: Option<String> = None;
    let mut format: Option<MetaFormat> = None;
    // QuickTimeStream.pl:905 `while ($pos + 4 < $end)`.
    while pos + 4 < end {
      let Some(len) = be_u32(data, pos) else { break };
      let len = len as usize;
      // QuickTimeStream.pl:907 `last if $len < 8 or $pos + $len > $end`.
      if len < 8 || pos + len > end {
        break;
      }
      // The guards above prove `pos + 8 <= pos + len <= end <= data.len()`,
      // so both `.get`s always succeed; the `else` breaks the loop just as
      // the `pos + len > end` guard would — byte-identical.
      let (Some(tag), Some(val)) = (data.get(pos + 4..pos + 8), data.get(pos + 8..pos + len))
      else {
        break;
      };
      pos += len;
      if tag == b"keyd" {
        // QuickTimeStream.pl:915 `s/^(mdta|fiel)com\.apple\.quicktime\.//`.
        tag_id = Some(decode_keyd(val));
      } else if tag == b"dtyp" {
        // QuickTimeStream.pl:918-932.
        if val.len() < 4 {
          continue;
        }
        let ns = be_u32(val, 0).unwrap_or(0);
        if ns == 0 {
          // QuickTimeStream.pl:923 `length $val >= 8 or ... next`.
          if val.len() < 8 {
            continue;
          }
          let code = be_u32(val, 4).unwrap_or(0);
          format = Some(MetaFormat::from_qt_fmt(code));
        } else {
          // ns == 1 or other ⇒ 'undef' (QuickTimeStream.pl:926-931).
          format = Some(MetaFormat::Undef);
        }
      }
      // Any other inner tag is a plain HandleTag in ExifTool — not needed
      // for the `mebx` key map.
    }
    pos = end.max(pos);
    // QuickTimeStream.pl:952 `if defined $tagID and defined $format`.
    if let (Some(tag_id), Some(format)) = (tag_id, format) {
      keys.push((local_id, MetaKey { tag_id, format }));
    }
  }
  keys
}

/// `keyd` value → tag ID (QuickTimeStream.pl:915-916). Strip an `mdta` /
/// `fiel` prefix immediately followed by `com.apple.quicktime.`; if nothing
/// is left, fall back to `Tag_<raw>`.
fn decode_keyd(val: &[u8]) -> String {
  let s = String::from_utf8_lossy(val);
  for prefix in ["mdtacom.apple.quicktime.", "fielcom.apple.quicktime."] {
    if let Some(rest) = s.strip_prefix(prefix) {
      if rest.is_empty() {
        // QuickTimeStream.pl:916 `$tagID = "Tag_$val" unless $tagID`.
        return alloc::format!("Tag_{s}");
      }
      return rest.to_string();
    }
  }
  if s.is_empty() {
    return "Tag_".to_string();
  }
  s.into_owned()
}

/// A `mebx` per-key value conversion — the value-tier `ValueConv` ExifTool's
/// `HandleTag` applies after `ReadValue` (QuickTimeStream.pl:2669) for a known
/// `%QuickTime::Keys` tag (QuickTime.pm:6651-...). Only the value-tier convs of
/// keys that occur in `mebx` timed metadata are modelled; the (display-tier)
/// `PrintConv` of those tags is NOT applied here — exifast's typed
/// [`MebxSample`] keeps post-`ValueConv` values (the same convention the GPS
/// samples follow: decimal degrees, not the DMS `PrintConv`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyValueConv {
  /// No `ValueConv` — the `ReadValue` output is the value (most keys).
  None,
  /// `location.ISO6709` ⇒ `ConvertISO6709` (QuickTime.pm:8884-8908): an ISO
  /// 6709 coordinate string → space-joined decimal `lat lon [alt]`.
  Iso6709,
  /// `scene-illuminance` ⇒ `unpack("N",$val)` (QuickTime.pm:6843): a
  /// big-endian `int32u` decoded from the raw (undef-format) bytes.
  SceneIlluminanceN,
  /// `live-photo-info` ⇒ `join " ",unpack "VfVVf6c4lCCcclf4Vvv", $val`
  /// (QuickTime.pm:6789-6791): a fixed 80-byte LITTLE-ENDIAN blob unpacked
  /// into 27 scalars and space-joined. See [`unpack_live_photo_info`].
  LivePhotoInfo,
  /// `detected-face.bounds` ⇒ the round-to-6-dp `PrintConv`
  /// `my @a=split " ",$val;$_=int($_*1e6+.5)/1e6 foreach @a;join " ",@a`
  /// (QuickTime.pm:6816-6822). This is the ONE modelled `mebx` key whose stored
  /// value is its (display-tier) `PrintConv` output rather than its bare
  /// `ValueConv`/`ReadValue` string: the `detected-face` leaves are reached only
  /// through the nested `FaceInfo`→`FaceRec`→`cits` walk (see
  /// [`process_face_info`]), and the `.ee.json` golden the SP3 harness compares
  /// against carries the `PrintConv`-rounded coordinates (`0.123457`), NOT the
  /// raw `%.15g` float (`0.123456791…`). The round is `int($_*1e6+.5)/1e6` —
  /// Perl `int` truncates toward zero AFTER the `+.5`, so it is round-half-up
  /// toward +infinity (`-3` ⇒ `-2.999999`). See [`round_face_bounds`].
  DetectedFaceBounds,
}

/// Resolve a raw `mebx` TagID to the displayed `(Name, ValueConv)` exactly as
/// `Process_mebx` does (QuickTimeStream.pl:2657-2666): the tag table is
/// `%QuickTime::Keys` (QuickTimeStream.pl:177), so a TagID that is a key there
/// keeps that entry's `Name` (and `ValueConv`); any *other* TagID is added
/// dynamically with `Name => ucfirst($name)` where `$name` is the TagID with
/// each `-`/`.` separator folded into the following char's upper-case
/// (`s/[-.](.)/\U$1/g`).
///
/// Returns `None` for a TagID that fails ExifTool's reasonable-id guard
/// (`next unless $tag =~ /^[-\w.]+$/`, QuickTimeStream.pl:2660) — such a sample
/// is silently skipped (no tag emitted). The guard is applied ONLY on the
/// dynamic-add path; a known `%QuickTime::Keys` TagID is always emitted.
fn resolve_mebx_tag(tag_id: &str) -> Option<(smol_str::SmolStr, KeyValueConv)> {
  // The subset of `%QuickTime::Keys` (QuickTime.pm:6651-...) whose TagIDs are
  // documented as appearing in `mebx` timed metadata (the "seen in timed
  // metadata (mebx)" block) plus `location.ISO6709` (the canonical Apple GPS
  // key) and the reverse-DNS keys whose `Name` differs from the camel-cased
  // TagID. Entries whose `Name` already equals the camel-case fallback AND
  // carry no value-tier `ValueConv` are intentionally omitted: the fallback
  // below reproduces them byte-for-byte. The (display-tier) `PrintConv` of
  // these tags is not modelled here (see [`KeyValueConv`]).
  let known: Option<(&str, KeyValueConv)> = match tag_id {
    // GPS — ValueConv ConvertISO6709 (QuickTime.pm:6701-6711).
    "location.ISO6709" => Some(("GPSCoordinates", KeyValueConv::Iso6709)),
    // milli-lux — ValueConv unpack("N",$val) (QuickTime.pm:6840-6845).
    "scene-illuminance" => Some(("SceneIlluminance", KeyValueConv::SceneIlluminanceN)),
    // reverse-DNS keys whose Name ≠ camel-case (QuickTime.pm:6712-6735, 6808).
    "location.accuracy.horizontal" => Some(("LocationAccuracyHorizontal", KeyValueConv::None)),
    "direction.facing" => Some(("CameraDirection", KeyValueConv::None)),
    "direction.motion" => Some(("CameraMotion", KeyValueConv::None)),
    "rating.user" => Some(("UserRating", KeyValueConv::None)),
    "collection.user" => Some(("UserCollection", KeyValueConv::None)),
    "content.identifier" => Some(("ContentIdentifier", KeyValueConv::None)),
    // `detected-face` (QuickTime.pm:6808-6811) is NOT a scalar — it is a
    // `SubDirectory` whose value is a nested `FaceInfo`→`FaceRec`→`cits` MOV
    // atom tree (see [`is_subdir_key`] / [`process_face_info`]). It is handled
    // before this resolver runs, so it never reaches the scalar path. The leaf
    // keys below ARE scalar `%QuickTime::Keys` entries — they are emitted by
    // the nested `cits` `Process_mebx` call (QuickTime.pm:6816-6828).
    "detected-face.bounds" => {
      // The round-to-6-dp display `PrintConv` (QuickTime.pm:6820); see
      // `KeyValueConv::DetectedFaceBounds`.
      Some(("DetectedFaceBounds", KeyValueConv::DetectedFaceBounds))
    }
    "detected-face.face-id" => Some(("DetectedFaceID", KeyValueConv::None)),
    "detected-face.roll-angle" => Some(("DetectedFaceRollAngle", KeyValueConv::None)),
    "detected-face.yaw-angle" => Some(("DetectedFaceYawAngle", KeyValueConv::None)),
    // live-photo-info — ValueConv `join " ",unpack "VfVVf6c4lCCcclf4Vvv",$val`
    // (QuickTime.pm:6789-6791): the raw 80-byte (undef-format) blob is unpacked
    // little-endian into 27 scalars and space-joined. (The Name happens to
    // equal the camel-case fallback `LivePhotoInfo`, but the explicit entry is
    // required to attach the value-tier unpack ValueConv.) The
    // `video-orientation`/`detected-face.bounds` etc. PrintConvs are display
    // tier, not applied to the stored value.
    "live-photo-info" => Some(("LivePhotoInfo", KeyValueConv::LivePhotoInfo)),
    _ => None,
  };
  if let Some((name, conv)) = known {
    return Some((smol_str::SmolStr::from(name), conv));
  }
  // QuickTimeStream.pl:2660 `next unless $tag =~ /^[-\w.]+$/` — only the
  // dynamic-add path is gated; a non-empty run of `[-A-Za-z0-9_.]`.
  if tag_id.is_empty()
    || !tag_id
      .bytes()
      .all(|b| b == b'-' || b == b'.' || b == b'_' || b.is_ascii_alphanumeric())
  {
    return None;
  }
  Some((camel_case_ucfirst(tag_id), KeyValueConv::None))
}

/// `Process_mebx`'s dynamic-tag name (QuickTimeStream.pl:2663-2664):
/// `$name =~ s/[-.](.)/\U$1/g` then `ucfirst($name)` — fold each `-`/`.`
/// separator into the following char's ASCII upper-case, then upper-case the
/// first char. (The TagIDs are reverse-DNS ASCII; Perl `\U`/`ucfirst` match
/// `to_ascii_uppercase` over this domain. `_` is a `\w` char, NOT a separator,
/// so it is preserved verbatim — e.g. `Encoded_With` stays `Encoded_With`.)
fn camel_case_ucfirst(tag_id: &str) -> smol_str::SmolStr {
  let bytes = tag_id.as_bytes();
  let mut out = String::with_capacity(bytes.len());
  let mut i = 0usize;
  while i < bytes.len() {
    // The `while` guard proves `i < bytes.len()`, so this `.get` is always
    // `Some`; the `else` break matches the guard turning false.
    let Some(&b) = bytes.get(i) else { break };
    if b == b'-' || b == b'.' {
      // `s/[-.](.)/\U$1/`: drop the separator, upper-case the next char.
      if let Some(&next) = bytes.get(i + 1) {
        out.push(next.to_ascii_uppercase() as char);
        i += 2;
        continue;
      }
      // A trailing separator with no following char is unmatched by the regex
      // and kept verbatim.
      out.push(b as char);
      i += 1;
    } else {
      out.push(b as char);
      i += 1;
    }
  }
  // ExifTool `ucfirst` upper-cases only the first character.
  if let Some(first) = out.get_mut(0..1) {
    first.make_ascii_uppercase();
  }
  smol_str::SmolStr::from(out)
}

/// Apply a `mebx` key's value-tier [`KeyValueConv`] to the `ReadValue` output
/// (QuickTimeStream.pl:2669 `HandleTag` → the tag's `ValueConv`). `raw_bytes`
/// is the value slice (needed by the byte-oriented `unpack` convs); `read_val`
/// is the already-`ReadValue`-rendered string.
fn apply_key_value_conv(conv: KeyValueConv, raw_bytes: &[u8], read_val: String) -> String {
  match conv {
    KeyValueConv::None => read_val,
    // QuickTime.pm:6843 `unpack("N",$val)` — big-endian int32u over the raw
    // (undef-format) bytes. Perl `unpack 'N'` on < 4 bytes zero-pads on the
    // right; ExifTool only emits this for the 4-byte payload it documents.
    KeyValueConv::SceneIlluminanceN => match be_u32(raw_bytes, 0) {
      Some(v) => v.to_string(),
      None => read_val,
    },
    // QuickTime.pm:6707 `ConvertISO6709` over the (undef-format) string value.
    KeyValueConv::Iso6709 => convert_iso6709(&read_val),
    // QuickTime.pm:6791 `join " ",unpack "VfVVf6c4lCCcclf4Vvv",$val` over the
    // raw (undef-format) bytes. A short value that the `unpack` cannot fully
    // consume falls back to the `ReadValue` string (Perl's `unpack` would
    // yield `undef`s / a warning; ExifTool only emits this for the documented
    // 80-byte payload).
    KeyValueConv::LivePhotoInfo => unpack_live_photo_info(raw_bytes).unwrap_or(read_val),
    // QuickTime.pm:6820 `my @a=split " ",$val;$_=int($_*1e6+.5)/1e6 foreach
    // @a;join " ",@a` — round each space-separated coordinate to 6 dp. Operates
    // on the `ReadValue` string (the `float[8]` rendered `%.15g` and joined by
    // [`read_meta_value`]); `raw_bytes` is unused for this display-tier conv.
    KeyValueConv::DetectedFaceBounds => round_face_bounds(&read_val),
  }
}

/// `detected-face.bounds` `PrintConv` (QuickTime.pm:6820):
/// `my @a=split " ",$val;$_=int($_*1e6+.5)/1e6 foreach @a;join " ",@a` — round
/// each whitespace-separated number in `$val` to 6 decimal places and re-join
/// with single spaces.
///
/// The round is `int($_*1e6+.5)/1e6`. Perl `int` truncates toward zero, but the
/// `+.5` is added BEFORE the truncation, so the result is round-half-up toward
/// +infinity, NOT round-half-away-from-zero: `0.123456789` ⇒ `0.123457`,
/// `-3` ⇒ `int(-2999999.5)/1e6` ⇒ `-2.999999`. Each rounded value is rendered
/// with Perl's default number stringification — `%.15g` via
/// [`format_g`](crate::value::format_g) — which prints the (now ≤6-dp) value
/// without trailing-zero noise (`0.11`, `2`, `-2.999999`).
///
/// `split " ",$val` (a single-space pattern in Perl) splits on runs of
/// whitespace AND skips a leading empty field; `str::split_whitespace`
/// reproduces both. A token that does not parse as a number is passed through
/// verbatim (Perl's numeric coercion of a non-number yields `0` with a warning,
/// but the only producer here is the `%.15g`-rendered `float[8]`, so every
/// token parses).
fn round_face_bounds(val: &str) -> String {
  let mut out = String::with_capacity(val.len());
  for tok in val.split_whitespace() {
    if !out.is_empty() {
      out.push(' ');
    }
    match tok.parse::<f64>() {
      Ok(x) => {
        // `int($_*1e6+.5)` — Perl `int` truncates toward zero (`f64::trunc`).
        let rounded = (x * 1e6 + 0.5).trunc() / 1e6;
        out.push_str(&crate::value::format_g(rounded, 15));
      }
      Err(_) => out.push_str(tok),
    }
  }
  out
}

/// `live-photo-info` ValueConv (QuickTime.pm:6791): `join " ",unpack
/// "VfVVf6c4lCCcclf4Vvv",$val`. The 80-byte value is decoded LITTLE-ENDIAN
/// (the bundled comment concedes the `f`/`l` codes are native-endian and the
/// goldens are generated on a little-endian machine) into 27 scalars —
/// `V`=u32, `f`=f32, `V`=u32, `V`=u32, `f`×6=f32, `c`×4=i8, `l`=i32, `C`=u8,
/// `C`=u8, `c`=i8, `c`=i8, `l`=i32, `f`×4=f32, `V`=u32, `v`=u16, `v`=u16 — then
/// space-joined with each scalar rendered via Perl's default number
/// stringification (`%.15g` for the floats via [`format_g`](crate::value::format_g),
/// plain decimal for the integers — the same join the GPS/accelerometer
/// decoders use). Returns `None` when the value is shorter than the 80 bytes
/// the template consumes (`unpack` cannot fill every field).
fn unpack_live_photo_info(bytes: &[u8]) -> Option<String> {
  // The template consumes exactly 80 bytes (4+4+4+4 + 6*4 + 4*1 + 4 + 4*1 +
  // 4 + 4*4 + 4 + 2 + 2). A shorter value cannot satisfy the unpack.
  if bytes.len() < 80 {
    return None;
  }
  // The `bytes.len() < 80` guard above proves every fixed offset below is in
  // range, so these `.get`s never miss; the `unwrap_or` defaults mirror the
  // `le_u32(..).unwrap_or(0)` reads in the same function and are unreachable.
  let f32_at = |o: usize| {
    bytes
      .get(o..o + 4)
      .and_then(|s| <[u8; 4]>::try_from(s).ok())
      .map(f32::from_le_bytes)
      .unwrap_or(0.0)
  };
  let g = |x: f64| crate::value::format_g(x, 15);
  let mut out = String::new();
  // Push one rendered scalar, space-separated.
  let push = |s: &str, out: &mut String| {
    if !out.is_empty() {
      out.push(' ');
    }
    out.push_str(s);
  };
  let mut o = 0usize;
  // V f V V
  push(&le_u32(bytes, o).unwrap_or(0).to_string(), &mut out);
  o += 4;
  push(&g(f64::from(f32_at(o))), &mut out);
  o += 4;
  push(&le_u32(bytes, o).unwrap_or(0).to_string(), &mut out);
  o += 4;
  push(&le_u32(bytes, o).unwrap_or(0).to_string(), &mut out);
  o += 4;
  // f6
  for _ in 0..6 {
    push(&g(f64::from(f32_at(o))), &mut out);
    o += 4;
  }
  // c4 (signed i8)
  for _ in 0..4 {
    push(
      &(bytes.get(o).copied().unwrap_or(0) as i8).to_string(),
      &mut out,
    );
    o += 1;
  }
  // l (i32)
  push(&le_i32(bytes, o).unwrap_or(0).to_string(), &mut out);
  o += 4;
  // C C (u8)
  push(&bytes.get(o).copied().unwrap_or(0).to_string(), &mut out);
  o += 1;
  push(&bytes.get(o).copied().unwrap_or(0).to_string(), &mut out);
  o += 1;
  // c c (i8)
  push(
    &(bytes.get(o).copied().unwrap_or(0) as i8).to_string(),
    &mut out,
  );
  o += 1;
  push(
    &(bytes.get(o).copied().unwrap_or(0) as i8).to_string(),
    &mut out,
  );
  o += 1;
  // l (i32)
  push(&le_i32(bytes, o).unwrap_or(0).to_string(), &mut out);
  o += 4;
  // f4
  for _ in 0..4 {
    push(&g(f64::from(f32_at(o))), &mut out);
    o += 4;
  }
  // V v v
  push(&le_u32(bytes, o).unwrap_or(0).to_string(), &mut out);
  o += 4;
  push(&le_u16(bytes, o).unwrap_or(0).to_string(), &mut out);
  o += 2;
  push(&le_u16(bytes, o).unwrap_or(0).to_string(), &mut out);
  Some(out)
}

/// `ConvertISO6709` (QuickTime.pm:8884-8908): parse an ISO 6709 coordinate
/// string into a space-joined decimal `lat lon [alt]`, trying ExifTool's three
/// shapes in order — (1) `±DD.D±DDD.D[±AA.A]` decimal degrees, (2)
/// `±DDMM.M±DDDMM.M[±AA.A]` degrees + decimal minutes, (3)
/// `±DDMMSS.S±DDDMMSS.S[±AA.A]` degrees + minutes + decimal seconds.
///
/// An unrecognised string is returned unchanged (QuickTime.pm:8907). Numbers
/// stringify via Perl `$x + 0` ≈ `%.15g` ([`format_g`](crate::value::format_g)).
fn convert_iso6709(val: &str) -> String {
  let b = val.as_bytes();
  let (lat, lon, alt) = match parse_iso_decimal(b)
    .or_else(|| parse_iso_dm(b))
    .or_else(|| parse_iso_dms(b))
  {
    Some(v) => v,
    // QuickTime.pm:8907 `return $val` — unrecognised string unchanged.
    None => return val.to_string(),
  };
  // Perl interpolates `"$lat $lon"` (+ optional alt) with default %.15g.
  let g = |x: f64| crate::value::format_g(x, 15);
  let mut s = alloc::format!("{} {}", g(lat), g(lon));
  if let Some(a) = alt {
    s.push(' ');
    s.push_str(&g(a));
  }
  s
}

/// Read a `[-+]` sign at `b[i]` → `(is_negative, next_index)`.
fn iso_sign(b: &[u8], i: usize) -> Option<(bool, usize)> {
  match b.get(i) {
    Some(b'+') => Some((false, i + 1)),
    Some(b'-') => Some((true, i + 1)),
    _ => None,
  }
}

/// Read exactly `n` ASCII digits at `b[i..]` → `(value, next_index)`.
fn iso_digits_n(b: &[u8], i: usize, n: usize) -> Option<(f64, usize)> {
  let slice = b.get(i..i + n)?;
  if !slice.iter().all(u8::is_ascii_digit) {
    return None;
  }
  let v = slice
    .iter()
    .fold(0f64, |a, &d| a * 10.0 + f64::from(d - b'0'));
  Some((v, i + n))
}

/// Read an optional fractional tail `(?:\.\d*)?` at `b[i..]` (zero or more
/// digits after a `.`) → `(fraction_added, next_index)`; `(0.0, i)` if there is
/// no `.`.
fn iso_frac(b: &[u8], i: usize) -> (f64, usize) {
  if b.get(i) != Some(&b'.') {
    return (0.0, i);
  }
  let mut j = i + 1;
  let mut frac = 0.0f64;
  let mut scale = 0.1f64;
  while let Some(&d) = b.get(j) {
    if !d.is_ascii_digit() {
      break;
    }
    frac += f64::from(d - b'0') * scale;
    scale *= 0.1;
    j += 1;
  }
  (frac, j)
}

/// Optional altitude `[-+]\d+(?:\.\d*)?` at `b[i..]` (≥1 integer digit) → the
/// signed altitude, or `None` when absent / malformed.
fn iso_altitude(b: &[u8], i: usize) -> Option<f64> {
  let (neg, mut j) = iso_sign(b, i)?;
  let start = j;
  let mut v = 0f64;
  while let Some(&d) = b.get(j) {
    if !d.is_ascii_digit() {
      break;
    }
    v = v * 10.0 + f64::from(d - b'0');
    j += 1;
  }
  if j == start {
    return None; // need ≥1 integer digit
  }
  let (frac, _) = iso_frac(b, j);
  Some(if neg { -(v + frac) } else { v + frac })
}

/// Shape 1 — `([-+]\d{1,2}(?:\.\d*)?)([-+]\d{1,3}(?:\.\d*)?)([-+]\d+...)?`:
/// decimal degrees. `(lat, lon, alt?)` or `None`.
fn parse_iso_decimal(b: &[u8]) -> Option<(f64, f64, Option<f64>)> {
  // `[-+]` then 1..=max_int integer digits + optional `.frac`.
  fn signed(b: &[u8], i: usize, max_int: usize) -> Option<(f64, usize)> {
    let (neg, mut j) = iso_sign(b, i)?;
    let start = j;
    let mut v = 0f64;
    while j - start < max_int {
      match b.get(j) {
        Some(&d) if d.is_ascii_digit() => {
          v = v * 10.0 + f64::from(d - b'0');
          j += 1;
        }
        _ => break,
      }
    }
    if j == start {
      return None; // need ≥1 integer digit
    }
    let (frac, j) = iso_frac(b, j);
    Some((if neg { -(v + frac) } else { v + frac }, j))
  }
  let (lat, j) = signed(b, 0, 2)?;
  let (lon, j) = signed(b, j, 3)?;
  let alt = match b.get(j) {
    Some(b'+') | Some(b'-') => signed(b, j, usize::MAX).map(|(a, _)| a),
    _ => None,
  };
  Some((lat, lon, alt))
}

/// Shape 2 — `([-+])(\d{2})(\d{2}(?:\.\d*)?)([-+])(\d{3})(\d{2}(?:\.\d*)?)`
/// `([-+]\d+...)?`: degrees + decimal minutes. `(lat, lon, alt?)` or `None`.
fn parse_iso_dm(b: &[u8]) -> Option<(f64, f64, Option<f64>)> {
  let (neg_lat, j) = iso_sign(b, 0)?;
  let (deg_lat, j) = iso_digits_n(b, j, 2)?;
  let (min_lat, j) = iso_digits_n(b, j, 2)?;
  let (min_lat_frac, j) = iso_frac(b, j);
  let (neg_lon, j) = iso_sign(b, j)?;
  let (deg_lon, j) = iso_digits_n(b, j, 3)?;
  let (min_lon, j) = iso_digits_n(b, j, 2)?;
  let (min_lon_frac, j) = iso_frac(b, j);
  let lat = deg_lat + (min_lat + min_lat_frac) / 60.0;
  let lon = deg_lon + (min_lon + min_lon_frac) / 60.0;
  Some((
    if neg_lat { -lat } else { lat },
    if neg_lon { -lon } else { lon },
    iso_altitude(b, j),
  ))
}

/// Shape 3 — `([-+])(\d{2})(\d{2})(\d{2}(?:\.\d*)?)([-+])(\d{3})(\d{2})`
/// `(\d{2}(?:\.\d*)?)([-+]\d+...)?`: degrees + minutes + decimal seconds.
/// `(lat, lon, alt?)` or `None`.
fn parse_iso_dms(b: &[u8]) -> Option<(f64, f64, Option<f64>)> {
  let (neg_lat, j) = iso_sign(b, 0)?;
  let (deg_lat, j) = iso_digits_n(b, j, 2)?;
  let (min_lat, j) = iso_digits_n(b, j, 2)?;
  let (sec_lat, j) = iso_digits_n(b, j, 2)?;
  let (sec_lat_frac, j) = iso_frac(b, j);
  let (neg_lon, j) = iso_sign(b, j)?;
  let (deg_lon, j) = iso_digits_n(b, j, 3)?;
  let (min_lon, j) = iso_digits_n(b, j, 2)?;
  let (sec_lon, j) = iso_digits_n(b, j, 2)?;
  let (sec_lon_frac, j) = iso_frac(b, j);
  let lat = deg_lat + min_lat / 60.0 + (sec_lat + sec_lat_frac) / 3600.0;
  let lon = deg_lon + min_lon / 60.0 + (sec_lon + sec_lon_frac) / 3600.0;
  Some((
    if neg_lat { -lat } else { lat },
    if neg_lon { -lon } else { lon },
    iso_altitude(b, j),
  ))
}

/// `Process_mebx` (QuickTimeStream.pl:2644-2680): decode one `mebx` timed
/// sample — a sequence of `[size:4][local-id:4][value]` records — using the
/// `keys` map from [`save_meta_keys`].
///
/// `sample_time` / `sample_duration` are threaded onto each decoded pair so
/// the typed layer can reproduce ExifTool's per-`Doc<N>` `SampleTime` /
/// `SampleDuration` (QuickTimeStream.pl `FoundSomething`).
fn process_mebx(
  data: &[u8],
  keys: &[(u32, MetaKey)],
  sample_time: Option<f64>,
  sample_duration: Option<f64>,
  out: &mut QuickTimeStreamMeta,
) {
  let mut pos = 0usize;
  // QuickTimeStream.pl:2654 `for ($pos=0; $pos+8<length($$dataPt); $pos+=$len)`.
  while pos + 8 < data.len() {
    let Some(len) = be_u32(data, pos) else { break };
    let len = len as usize;
    // QuickTimeStream.pl:2656 `last if $len < 8 or $pos + $len > length`.
    if len < 8 || pos + len > data.len() {
      break;
    }
    let id = be_u32(data, pos + 4).unwrap_or(0);
    // The guards prove `pos + 8 <= pos + len <= data.len()`, so this `.get`
    // is always `Some`; the `&&`-bound chain keeps the body byte-identical
    // (an impossible miss simply skips to `pos += len`, as a non-matching
    // key would).
    if let Some((_, info)) = keys.iter().find(|(k, _)| *k == id)
      && let Some(value_bytes) = data.get(pos + 8..pos + len)
    {
      // QuickTimeStream.pl:2668-2674 `HandleTag(..., $val, DataPt=>..., Start=>
      // $pos+8, Size=>$len-8)`. A `%QuickTime::Keys` entry that is a
      // `SubDirectory` makes `HandleTag` recurse into the sub-processor over
      // `[Start, Start+Size]` instead of storing the scalar `$val`. Two such
      // keys reach `mebx` timed metadata:
      //   * `smartstyle-info` (QuickTime.pm:6847-6852 → `PLIST::Main` /
      //     `PLIST::ProcessBinaryPLIST`): the value bytes are a binary plist.
      //   * `detected-face` (QuickTime.pm:6808-6811 → `QuickTime::FaceInfo`,
      //     `PROCESS_PROC => ProcessMOV`): the value bytes are a NESTED MOV
      //     atom tree (`crec`→`FaceRec`→`cits`), re-entered through the box
      //     walker; the `cits` content is itself `Process_mebx`-decoded against
      //     `%QuickTime::Keys` (the SAME `keys` map) and yields the
      //     `DetectedFace*` leaf samples (QuickTime.pm:6626-6648, 6816-6828).
      if info.tag_id == "detected-face" {
        process_face_info(value_bytes, keys, sample_time, sample_duration, out);
      } else if is_subdir_key(&info.tag_id) {
        process_mebx_subdir(&info.tag_id, value_bytes, out);
      } else if let Some((name, conv)) = resolve_mebx_tag(&info.tag_id) {
        // QuickTimeStream.pl:2657-2666 — resolve the TagID through the
        // `%QuickTime::Keys` table (the `mebx` SubDirectory's TagTable,
        // QuickTimeStream.pl:177) to its displayed Name + value-tier ValueConv,
        // skipping a TagID that fails the reasonable-id guard.
        //
        // QuickTimeStream.pl:2668 `ReadValue($dataPt, $pos+8, $format, undef,
        // $len-8)`. A `mebx` record is ≥8 bytes; the value slice is `$len-8`
        // bytes (possibly empty). ReadValue returns an empty STRING — never
        // undef — for the empty/short case (ExifTool.pm:6298-6299), so the tag
        // is ALWAYS emitted once the key resolves (it is never dropped here).
        let read_val = read_meta_value(value_bytes, info.format);
        let value = apply_key_value_conv(conv, value_bytes, read_val);
        out.push_mebx_sample(MebxSample::new(name, value, sample_time, sample_duration));
      }
    }
    pos += len;
  }
}

/// Process a `detected-face` `mebx` `SubDirectory` value — a nested MOV atom
/// tree — by re-entering the box walker and re-running `Process_mebx` on its
/// leaf `cits` content.
///
/// `detected-face` (QuickTime.pm:6808-6811) names `QuickTime::FaceInfo`, whose
/// `PROCESS_PROC` is `ProcessMOV`. The value bytes are therefore a sequence of
/// `crec` atoms (QuickTime.pm:6626-6635, `%QuickTime::FaceInfo`); each `crec`
/// names `QuickTime::FaceRec` (also `ProcessMOV`, QuickTime.pm:6638-6648),
/// whose single `cits` atom names `%QuickTime::Keys` with
/// `ProcessProc => Process_mebx`. So a `cits` body is itself a `mebx` record
/// stream, decoded against the SAME `keys` map (`Process_mebx` reads the shared
/// `$$et{ee}{keys}`), resolving the `detected-face.bounds` / `.face-id` /
/// `.roll-angle` / `.yaw-angle` leaf keys (QuickTime.pm:6816-6828).
///
/// The port's [`for_each_atom`] walks any `[size:4][type:4][payload]` atom
/// sequence over a borrowed buffer (it is NOT bound to the file's top-level
/// tree), so re-entering on the in-memory `value` slice scoped to the
/// `FaceInfo`/`FaceRec` tables is a localized re-use of the existing walker —
/// no structural change. `sample_time` / `sample_duration` thread through to
/// the leaf [`MebxSample`]s exactly as the outer sample's would.
fn process_face_info(
  value: &[u8],
  keys: &[(u32, MetaKey)],
  sample_time: Option<f64>,
  sample_duration: Option<f64>,
  out: &mut QuickTimeStreamMeta,
) {
  // FaceInfo (ProcessMOV): walk the `crec` children. `for_each_atom` accepts a
  // `(start, end)` byte range over `value`; the closure receives each atom's
  // payload sub-slice, which is itself walkable with `for_each_atom(.., 0,
  // len, ..)`.
  for_each_atom(value, 0, value.len(), |t, crec_body| {
    if t != b"crec" {
      return;
    }
    // FaceRec (ProcessMOV): the single `cits` child.
    for_each_atom(crec_body, 0, crec_body.len(), |t2, cits_body| {
      if t2 != b"cits" {
        return;
      }
      // cits → %QuickTime::Keys with Process_mebx (the SAME keys map).
      process_mebx(cits_body, keys, sample_time, sample_duration, out);
    });
  });
}

/// `true` when a `mebx` TagID resolves (through `%QuickTime::Keys`) to a
/// `SubDirectory` entry whose value must be re-processed by ANOTHER module
/// (vs. the nested-MOV `detected-face`, handled by [`process_face_info`]),
/// rather than stored as a scalar. Currently the only such key is
/// `smartstyle-info` (QuickTime.pm:6847-6852 → `PLIST::Main` /
/// `PLIST::ProcessBinaryPLIST`). The other `%QuickTime::Keys` `SubDirectory`
/// entries (e.g. `binary-plist`, the CMTime sub-structs) are not seen in
/// SP3-decoded `mebx` timed metadata, so they are not modelled here.
const fn is_subdir_key(tag_id: &str) -> bool {
  matches!(tag_id.as_bytes(), b"smartstyle-info")
}

/// Process a `mebx` `SubDirectory` key's value through the nested module its
/// `%QuickTime::Keys` entry names. `smartstyle-info` (QuickTime.pm:6847-6852)
/// dispatches to `Image::ExifTool::PLIST::Main` via
/// `PLIST::ProcessBinaryPLIST`: the value bytes ARE a binary plist, decoded
/// into the PLIST tags ExifTool would emit. The decoded tags carry the PLIST
/// table's family-0 group (`PLIST`) and the camel-cased PLIST key name
/// (verified against the bundled `-ee -G1:0` oracle, which scopes them under
/// `Track1:PLIST`); exifast stores them verbatim as rendered [`Tag`]s.
///
/// The `PlistMeta` returned by [`crate::formats::plist::parse_borrowed`] OWNS
/// all its strings (its `'a` lifetime is a phantom), so its `Taggable` stream
/// is collected into owned [`Tag`]s immediately and the borrow of `value` does
/// not escape. A value that is not a recognized plist (or an empty/short
/// value) yields no tags — faithful to `ProcessBinaryPLIST` returning without
/// emitting (PLIST.pm:453-502 `return 0`).
#[cfg(feature = "plist")]
fn process_mebx_subdir(tag_id: &str, value: &[u8], out: &mut QuickTimeStreamMeta) {
  // Only `smartstyle-info` reaches here (see `is_subdir_key`); its SubDirectory
  // is `PLIST::Main` + `ProcessBinaryPLIST`.
  debug_assert_eq!(tag_id, "smartstyle-info");
  let _ = tag_id;
  // PLIST.pm `ProcessBinaryPLIST` over the value bytes. The smartstyle PLIST
  // keys never hit a mode-sensitive `%PLIST::Main` static `PrintConv`
  // (Duration / GPSLatitude / GPSLongitude are keyed on full reverse-DNS
  // paths), so the `PrintConv` render equals the `-n` render — collect once in
  // the default print mode (the `-ee`/`-j` golden mode).
  if let Some(meta) = crate::formats::plist::parse_borrowed(value) {
    for emitted in crate::emit::Taggable::tags(
      &meta,
      crate::emit::EmitOptions::g1(crate::emit::ConvMode::PrintConv, false),
    ) {
      // `Unknown => 1` tags are dropped from default output (every PLIST tag is
      // always-emitted, so this is a no-op in practice — kept for parity with
      // the engine's `run_emission` gate).
      if emitted.unknown() {
        continue;
      }
      out.push_plist_subdir_tag(emitted.into_tag());
    }
  }
}

/// Defensive stub for a hypothetical `quicktime`-without-`plist` build. The
/// `quicktime` feature now chains `plist` (see `Cargo.toml`), so within any
/// build where this module compiles `plist` is enabled and the
/// `#[cfg(feature = "plist")]` definition above is the one selected — this arm
/// is therefore unreachable in practice. It is retained only so the
/// `smartstyle-info` dispatch site type-checks if the feature edge is ever
/// manually severed; when active it drops the `SubDirectory` value (the only
/// such key, `smartstyle-info`, has no scalar form).
#[cfg(not(feature = "plist"))]
fn process_mebx_subdir(_tag_id: &str, _value: &[u8], _out: &mut QuickTimeStreamMeta) {}

/// `ReadValue` for a `mebx` value (QuickTimeStream.pl:2668 — `ReadValue(.., $
/// format, undef, $len-8)`) — render the `qtFmt`-typed bytes to the displayed
/// string. `mebx` values are big-endian (the movie byte order).
///
/// **`count == undef` ⇒ read ALL elements that fit** (ExifTool.pm:6296-6331):
/// with a defined `$size` (`$len-8`) but an undefined `$count`, `ReadValue`
/// first short-circuits — `return '' if defined $count or $size < $len` — so
/// when the available size is SMALLER than one format unit (a short / empty
/// value) it returns an **empty STRING**, NOT undef. Otherwise it sets
/// `$count = int($size / $formatSize{$format})` and loops, pushing one value
/// per element, then `return join(' ', @vals) if @vals > 1`. So a `float[2]` /
/// `float[4]` / `float[9]` matrix, a `double[3]` coordinate, an `int16s[3]`
/// accelerometer triple, etc. are decoded in FULL and space-joined — NOT just
/// the first element. Each element renders exactly as the single-element case
/// did (numeric `$proc` → Perl default stringification: `%.15g` for
/// float/double via [`format_g`](crate::value::format_g), plain decimal for
/// ints). The `string`/`undef` formats (`$formatSize == 1`) have no
/// `$readValueProc`, so ExifTool reads ONE value spanning all `$count*$len`
/// bytes (ExifTool.pm:6307-6311) — kept as the single NUL-trimmed string (and
/// the empty string for an empty value, since `$size < 1` ⇒ `''`).
///
/// Returns a `String` (never an `Option`): for the `undef`-count call
/// `ReadValue` cannot reach its `$count < 1 ⇒ return undef` branch (that branch
/// is guarded by an initially-truthy `$count`), so the result is always a
/// string — the empty string in the short/empty case.
fn read_meta_value(bytes: &[u8], format: MetaFormat) -> String {
  match format {
    // No `$readValueProc` (ExifTool.pm:6307): one value = the whole byte span.
    // `$formatSize == 1` ⇒ the `$size < $len` short-circuit (→ `''`) only fires
    // for an empty value, which naturally yields the empty string here.
    //
    // `string` truncates at the FIRST NUL — `s/\0.*//s` drops the NUL and
    // everything after it (ExifTool.pm:6311) — whereas `undef` keeps the raw
    // byte span verbatim (the `s/\0.*//s` is gated `if $format eq 'string'`).
    MetaFormat::Str => {
      let s = String::from_utf8_lossy(bytes);
      match s.find('\0') {
        Some(nul) => s[..nul].to_string(),
        None => s.into_owned(),
      }
    }
    MetaFormat::Undef => String::from_utf8_lossy(bytes).into_owned(),
    // Numeric formats: a `$readValueProc` exists, so loop `int($size/$len)`
    // elements and space-join (ExifTool.pm:6322-6330). `read_numeric_array`
    // returns the EMPTY STRING when not even one element fits (`$size < $len`
    // ⇒ ExifTool's `return ''`, ExifTool.pm:6299) — NOT undef.
    MetaFormat::Int8u => {
      read_numeric_array(bytes, 1, |b, o| Some(u64::from(*b.get(o)?).to_string()))
    }
    MetaFormat::Int8s => read_numeric_array(bytes, 1, |b, o| Some((*b.get(o)? as i8).to_string())),
    MetaFormat::Int16u => read_numeric_array(bytes, 2, |b, o| be_u16(b, o).map(|v| v.to_string())),
    MetaFormat::Int16s => read_numeric_array(bytes, 2, |b, o| be_i16(b, o).map(|v| v.to_string())),
    MetaFormat::Int32u => read_numeric_array(bytes, 4, |b, o| be_u32(b, o).map(|v| v.to_string())),
    MetaFormat::Int32s => read_numeric_array(bytes, 4, |b, o| be_i32(b, o).map(|v| v.to_string())),
    MetaFormat::Int64u => read_numeric_array(bytes, 8, |b, o| be_u64(b, o).map(|v| v.to_string())),
    MetaFormat::Int64s => read_numeric_array(bytes, 8, |b, o| {
      be_u64(b, o).map(|v| (v as i64).to_string())
    }),
    MetaFormat::Float => read_numeric_array(bytes, 4, |b, o| {
      let arr: [u8; 4] = b.get(o..o + 4)?.try_into().ok()?;
      let f = f32::from_be_bytes(arr);
      Some(crate::value::format_g(f64::from(f), 15))
    }),
    MetaFormat::Double => read_numeric_array(bytes, 8, |b, o| {
      let arr: [u8; 8] = b.get(o..o + 8)?.try_into().ok()?;
      let f = f64::from_be_bytes(arr);
      Some(crate::value::format_g(f, 15))
    }),
  }
}

/// Read `int(bytes.len() / elem_size)` big-endian elements of a fixed-width
/// numeric format and space-join their rendered strings — the multi-element
/// arm of ExifTool's `ReadValue` with `count == undef` (ExifTool.pm:6296-6330).
///
/// `render(bytes, offset)` decodes + stringifies ONE element at `offset` (a
/// byte-bounded reader, so a partial trailing element yields `None` and stops
/// the loop, matching the `int($size/$len)` count truncation). Returns the
/// EMPTY STRING when not a single whole element fits (ExifTool's
/// `return '' if ... $size < $len`, ExifTool.pm:6299 — the `count == undef`
/// call never reaches the later `$count < 1 ⇒ return undef`); a single element
/// returns its bare string (no separator), `@vals > 1` returns the space-joined
/// list.
fn read_numeric_array(
  bytes: &[u8],
  elem_size: usize,
  render: impl Fn(&[u8], usize) -> Option<String>,
) -> String {
  // ExifTool.pm:6298 `$count = int($size / $len)`; a `$size < $len` short
  // value short-circuits to `''` at ExifTool.pm:6299.
  let count = bytes.len() / elem_size;
  if count == 0 {
    // ExifTool.pm:6299 `return '' if ... $size < $len`.
    return String::new();
  }
  let mut out = String::new();
  for i in 0..count {
    let Some(elem) = render(bytes, i * elem_size) else {
      break;
    };
    if !out.is_empty() {
      // ExifTool.pm:6330 `join(' ', @vals)`.
      out.push(' ');
    }
    out.push_str(&elem);
  }
  // `count >= 1` and every element is in-bounds (`count = int(size/elem_size)`
  // already bounds the loop), so `out` is the space-joined value here.
  out
}

// ===========================================================================
// Bounded binary GPS decoders (QuickTimeStream.pl:2686-2789)
// ===========================================================================

/// `Process_3gf` (QuickTimeStream.pl:2686-2708) — Pittasoft BlackVue dashcam
/// `3gf` timed accelerometer. 10-byte records: `[timecode:int32u]`
/// `[x:int16s][y:int16s][z:int16s]`, x/y/z scaled by 1/10. A timecode of
/// `0xffffffff` terminates.
fn process_3gf(data: &[u8], out: &mut QuickTimeStreamMeta) {
  const REC: usize = 10;
  let mut pos = 0usize;
  while pos + REC <= data.len() {
    let tc = be_u32(data, pos).unwrap_or(0);
    // QuickTimeStream.pl:2701 `last if $tc == 0xffffffff`.
    if tc == 0xffff_ffff {
      break;
    }
    let x = f64::from(be_i16(data, pos + 4).unwrap_or(0)) / 10.0;
    let y = f64::from(be_i16(data, pos + 6).unwrap_or(0)) / 10.0;
    let z = f64::from(be_i16(data, pos + 8).unwrap_or(0)) / 10.0;
    let mut sample = GpsSample::new();
    // QuickTimeStream.pl:2703 `TimeCode => $tc / 1000`.
    sample.set_time_code(Some(f64::from(tc) / 1000.0));
    sample.set_accelerometer(Some(smol_str::SmolStr::from(join3(x, y, z))));
    out.push_gps_sample(sample);
    pos += REC;
  }
}

/// `Process_gps0` (QuickTimeStream.pl:2715-2763) — DuDuBell M1 / VSYS M6L
/// `gps0` timed GPS, the 32-byte LITTLE-ENDIAN binary record variant (the
/// encrypted-text Lamax variant is deferred — it routes through
/// `Process_text`, QuickTimeStream.pl:2724-2735).
///
/// Record (`SetByteOrder('II')`): `[lat:double][lon:double]` (DDDMM.MMMM),
/// `[altitude:int32s @0x10][speed:int16u @0x14]`, `[date/time:int8u[6] @0x16]`,
/// `[track/2:int8u @0x1c]`.
fn process_gps0(data: &[u8], out: &mut QuickTimeStreamMeta) {
  // QuickTimeStream.pl:2724 — the encrypted Lamax variant is detected by a
  // signature and deferred (it needs the `Process_text` NMEA decoder).
  if data.get(2..8) == Some(b"\xf2\xe1\xf0\xeeTT".as_slice()) {
    return; // DEFERRED: Lamax encrypted-text gps0 (Process_text NMEA path).
  }
  const REC: usize = 32;
  let mut pos = 0usize;
  while pos + REC <= data.len() {
    let lat_raw = le_f64(data, pos).unwrap_or(0.0);
    let lon_raw = le_f64(data, pos + 8).unwrap_or(0.0);
    // QuickTimeStream.pl:2747 `next if abs($lat) > 9000 or abs($lon) > 18000`.
    if lat_raw.abs() > 9000.0 || lon_raw.abs() > 18000.0 {
      pos += REC;
      continue;
    }
    let lat = convert_lat_lon(lat_raw);
    let lon = convert_lat_lon(lon_raw);
    // date/time: int8u[6] at 0x16 = year-2000, month, day, hour, min, sec.
    // `0x1c - 0x16 == 6`, so `first_chunk::<6>` always matches the slice and
    // destructures it without raw indexing — byte-identical to `d[0..6]`.
    let dt = data.get(pos + 0x16..pos + 0x1c);
    let date_time = dt
      .and_then(|d| d.first_chunk::<6>())
      .map(|&[d0, d1, d2, d3, d4, d5]| {
        alloc::format!(
          "{:04}:{:02}:{:02} {:02}:{:02}:{:02}Z",
          u32::from(d0) + 2000,
          d1,
          d2,
          d3,
          d4,
          d5
        )
      });
    let mut sample = GpsSample::new();
    sample.set_date_time(date_time.map(smol_str::SmolStr::from));
    sample.set_latitude(Some(lat));
    sample.set_longitude(Some(lon));
    sample.set_speed_kph(le_u16(data, pos + 0x14).map(f64::from));
    // QuickTimeStream.pl:2755 `GPSTrack => Get8u(.., 0x1c) * 2`.
    sample.set_track(data.get(pos + 0x1c).map(|&b| f64::from(b) * 2.0));
    sample.set_altitude_m(le_i32(data, pos + 0x10).map(f64::from));
    out.push_gps_sample(sample);
    pos += REC;
  }
}

/// `Process_gsen` (QuickTimeStream.pl:2769-2789) — DuDuBell M1 / VSYS M6L
/// `gsen` timed accelerometer. 3-byte records of `int8s` triples, each
/// scaled by 1/16.
fn process_gsen(data: &[u8], out: &mut QuickTimeStreamMeta) {
  const REC: usize = 3;
  let mut pos = 0usize;
  while pos + REC <= data.len() {
    // The `while` guard proves `pos + 3 <= data.len()`, so this `.get`
    // always yields a 3-slice; the `else` break matches the guard failing.
    let Some(&[rx, ry, rz]) = data.get(pos..pos + REC) else {
      break;
    };
    let x = f64::from(rx as i8) / 16.0;
    let y = f64::from(ry as i8) / 16.0;
    let z = f64::from(rz as i8) / 16.0;
    let mut sample = GpsSample::new();
    sample.set_accelerometer(Some(smol_str::SmolStr::from(join3(x, y, z))));
    out.push_gps_sample(sample);
    pos += REC;
  }
}

/// Join a 3-axis reading the way ExifTool's `"$x $y $z"` interpolation does —
/// each component via Perl's default `%.15g` numeric stringification.
pub(crate) fn join3(x: f64, y: f64, z: f64) -> String {
  let mut s = crate::value::format_g(x, 15);
  s.push(' ');
  s.push_str(&crate::value::format_g(y, 15));
  s.push(' ');
  s.push_str(&crate::value::format_g(z, 15));
  s
}

// ===========================================================================
// process_samples — the SP3 sample dispatch loop
// ===========================================================================

/// One metadata `trak` discovered during the SP3 walk — its `HandlerType`,
/// `MetaFormat`, `MediaTimeScale`, decoded sample tables and `mebx` key map.
#[derive(Debug, Default)]
struct StreamTrack {
  /// `hdlr` HandlerType (QuickTime.pm:8403-8416).
  handler: [u8; 4],
  /// `stsd` MetaFormat — the sample-description format code
  /// (QuickTime.pm:7765-7768).
  meta_format: [u8; 4],
  /// `mdhd` MediaTimeScale.
  media_ts: u32,
  /// The `stbl` sample tables.
  ee: EeData,
  /// The `mebx` `keys`-table map (empty for non-`mebx` tracks).
  meta_keys: Vec<(u32, MetaKey)>,
}

/// `ProcessSamples` (QuickTimeStream.pl:1304-1592) — the per-`stbl` sample
/// dispatch. Given the decoded `track` (sample tables + `HandlerType` /
/// `MetaFormat` / `MediaTimeScale`), expand the sample list and decode each
/// sample by format.
///
/// `data` is the WHOLE file slice (sample offsets are absolute file offsets).
///
/// Only the self-contained sample formats are decoded here (the Apple `mebx`
/// timed-metadata format and the GoPro `gpmd` GPMF format); an unrecognized
/// or deferred `MetaFormat` simply yields no samples (faithful: ExifTool
/// `VPrint`s "Unknown $type format" and moves on, QuickTimeStream.pl:1547).
///
/// Returns `true` iff any sample ENTERED the GoPro GPMF processor — i.e. any
/// non-deferred `gpmd` sample (ExifTool's `$$et{FoundEmbedded}`, set on
/// `ProcessGoPro` entry, GoPro.pm:822), regardless of whether the KLV parse
/// extracted anything.
///
/// `track_index` is the 1-based moov track number of this `trak` (ExifTool's
/// `SET_GROUP1 = "Track$num"`, QuickTime.pm:10353-10354); it is stamped onto
/// every track-scoped timed sample (`mebx` / `camm` GPS) so a later emission
/// task can group them under `Track<N>:` (the oracle group).
#[must_use]
fn process_samples(
  data: &[u8],
  track: &StreamTrack,
  track_index: u32,
  create_date_raw: Option<u64>,
  out: &mut QuickTimeStreamMeta,
  gopro_out: &mut crate::metadata::GoProMeta,
  camm_out: &mut crate::metadata::CammMeta,
) -> bool {
  let samples = match expand_samples(&track.ee, track.media_ts) {
    Some(s) => s,
    None => return false,
  };
  let mut found_embedded = false;
  // QuickTimeStream.pl:1418 `for ($i=0; $i<@$start and $i<@$size; ++$i)`.
  for sample in &samples {
    let start = sample.start as usize;
    let size = sample.size as usize;
    let Some(buff) = data.get(start..start.saturating_add(size)) else {
      // QuickTimeStream.pl:1436-1443 — a seek/read past EOF warns + `next`s.
      continue;
    };
    // R12-B: do NOT skip a size-0 sample. ExifTool reads a 0-byte sample
    // (`$raf->Read($buff, 0) == 0 == $size`, QuickTimeStream.pl:1438-1443, no
    // warn) and STILL dispatches it: for a `gpmd` track the no-`Condition`
    // `gpmd_GoPro` SubDirectory resolves (QuickTimeStream.pl:1518-1529) and
    // `ProcessGoPro` sets `$$et{FoundEmbedded} = 1` on ENTRY (GoPro.pm:822) —
    // BEFORE its record loop — so an EMPTY non-deferred `gpmd` sample marks the
    // file embedded and suppresses the brute-force `mdat` scan. The pre-fix
    // skip left `FoundEmbedded` false on an empty-then-buried-GP6 file, so the
    // scan ran and emitted GP6/freeGPS tags ExifTool suppresses. The `gpmd` arm
    // of `decode_one_sample` returns `true` unconditionally (even for an empty
    // buffer); `process_mebx`, the `camm` arm and the other arms are no-ops on
    // empty bytes (their `pos + N < len` loop never runs), so removing the skip
    // is faithful across formats.
    //
    // `FoundEmbedded` is sticky — once any GoPro sample is recognized it
    // stays set (ExifTool only ever assigns `= 1`, GoPro.pm:822).
    found_embedded |= decode_one_sample(
      buff,
      track,
      track_index,
      sample,
      create_date_raw,
      out,
      gopro_out,
      camm_out,
    );
  }
  found_embedded
}

/// Decode a single timed sample's bytes by `HandlerType` / `MetaFormat` —
/// the dispatch arms of QuickTimeStream.pl:1467-1578.
///
/// Returns `true` iff the sample ENTERED the GoPro GPMF processor — i.e. a
/// non-deferred `gpmd` sample — mirroring ExifTool's `$$et{FoundEmbedded} = 1`
/// set on `ProcessGoPro` entry (GoPro.pm:822), which fires before the KLV loop
/// and so is independent of extraction success. A deferred `gpmd` variant
/// (Kingslim/Rove/FMAS/Wolfbox) and the `mebx`/other paths set no
/// `FoundEmbedded`.
#[must_use]
/// The non-GoPro `gpmd` MetaFormat variants (QuickTimeStream.pl:181-208):
/// Kingslim / Rove / FMAS / Wolfbox. Each matches a leading-byte `Condition`
/// and routes to a processor this port DEFERS (the brute-force `mdat` scan
/// recovers them instead), so a matching `gpmd` sample must not be dispatched
/// to the GoPro KLV walker nor set `FoundEmbedded`. Byte-checks use the
/// checked `.get` form (file-level `deny(indexing_slicing)`).
fn is_deferred_gpmd_variant(buff: &[u8]) -> bool {
  // gpmd_Kingslim: `/^.{21}\0\0\0A[NS][EW]/s` (QuickTimeStream.pl:182-184).
  let kingslim = buff.get(21..24) == Some(&[0, 0, 0][..])
    && buff.get(24) == Some(&b'A')
    && matches!(buff.get(25), Some(b'N' | b'S'))
    && matches!(buff.get(26), Some(b'E' | b'W'));
  // gpmd_Rove: `/^\0\0\xf2\xe1\xf0\xeeTT/` (QuickTimeStream.pl:189-191).
  let rove = buff.get(0..8) == Some(&[0x00, 0x00, 0xf2, 0xe1, 0xf0, 0xee, b'T', b'T'][..]);
  // gpmd_FMAS: `/^FMAS\0\0\0\0/` (QuickTimeStream.pl:196-198).
  let fmas = buff.get(0..8) == Some(b"FMAS\0\0\0\0".as_slice());
  // gpmd_Wolfbox: `/^.{136}(0{16}[A-Z]{4}|https:\/\/www.redtiger\0)/s`
  // (QuickTimeStream.pl:203-205).
  let wolfbox = (buff
    .get(136..152)
    .is_some_and(|s| s.iter().all(|&b| b == b'0'))
    && buff
      .get(152..156)
      .is_some_and(|s| s.iter().all(|&b| b.is_ascii_uppercase())))
    || buff.get(136..157) == Some(b"https://www.redtiger\0".as_slice());
  kingslim || rove || fmas || wolfbox
}

fn decode_one_sample(
  buff: &[u8],
  track: &StreamTrack,
  track_index: u32,
  sample: &Sample,
  create_date_raw: Option<u64>,
  out: &mut QuickTimeStreamMeta,
  gopro_out: &mut crate::metadata::GoProMeta,
  camm_out: &mut crate::metadata::CammMeta,
) -> bool {
  // The `mebx` MetaFormat (QuickTimeStream.pl:174-180) — Apple timed
  // metadata via the `keys` table. `FoundSomething` records the per-`Doc<N>`
  // SampleTime/SampleDuration; the decoded `mebx` pairs carry both.
  if &track.meta_format == b"mebx" {
    // Stamp the `Track<N>` index onto exactly the `mebx` samples this sample's
    // decode produces (including any nested `detected-face` leaves), faithful
    // to ExifTool scoping `SET_GROUP1 = "Track$num"` per-`trak`. The watermark
    // is taken before the (recursive) `process_mebx` call so a file-scoped
    // meta accumulating multiple metadata `trak`s stamps each `trak`'s samples
    // with its own index.
    let mebx_start = out.mebx_sample_count();
    process_mebx(buff, &track.meta_keys, sample.time, sample.dur, out);
    out.stamp_mebx_track_index_from(mebx_start, track_index);
    return false;
  }
  // The `gpmd` MetaFormat (QuickTimeStream.pl:181-212) — five condition-
  // dispatched variants. The fallback (no other Condition matches) is
  // `gpmd_GoPro`, whose SubDirectory routes the sample bytes into
  // `Image::ExifTool::GoPro::GPMF`. exifast's GoPro KLV parser is
  // [`crate::formats::gopro::process_gopro`]. The Kingslim / Rove / FMAS /
  // Wolfbox variants re-dispatch into ProcessFreeGPS / Process_text /
  // ProcessFMAS / ProcessWolfbox — DEFERRED at the `gpmd` dispatch level
  // (the brute-force `mdat` scan already locates Kingslim/Rove/FMAS records
  // when they're stored in `free`/`mdat` rather than as `gpmd` samples).
  if &track.meta_format == b"gpmd" {
    // QuickTimeStream.pl:181-212 is an ORDERED `Condition` list: Kingslim /
    // Rove / FMAS / Wolfbox each match a leading-byte signature and route to a
    // deferred non-GoPro processor (ProcessFreeGPS / Process_text / ProcessFMAS
    // / ProcessWolfbox); only the no-`Condition` `gpmd_GoPro` fallback reaches
    // `GoPro::GPMF`. A deferred variant must NOT be parsed as GoPro and must
    // NOT set `FoundEmbedded` — otherwise its printable FourCC (e.g. `FMAS`)
    // would be mistaken for a GoPro record and suppress the brute-force `mdat`
    // scan that actually recovers these records. Mirror the ordered dispatch:
    // skip a deferred signature, fall through to GoPro only otherwise.
    if is_deferred_gpmd_variant(buff) {
      return false;
    }
    // The `gpmd_GoPro` fallback — the KLV walker. Run it for EXTRACTION, but
    // the `FoundEmbedded` side-effect is decoupled from extraction success:
    // ExifTool sets `$$et{FoundEmbedded} = 1` on ENTRY to `ProcessGoPro`
    // (GoPro.pm:822), BEFORE the KLV record loop (:831), so it fires for EVERY
    // non-deferred `gpmd` sample — even one whose payload is zero-filled,
    // truncated, or otherwise extracts nothing. Because `gpmd_GoPro` is the
    // no-`Condition` fallback (QuickTimeStream.pl:209-212), a non-deferred
    // `gpmd` sample ALWAYS enters `ProcessGoPro`, so `FoundEmbedded` is always
    // set ⇒ `ScanMediaData` returns early (QuickTimeStream.pl:3689). Returning
    // the walker's recognition bool instead would let a corrupt-but-
    // non-deferred `gpmd` sample leave `FoundEmbedded` unset, and the later
    // brute-force `mdat` scan would emit extra GP6/freeGPS tags ExifTool skips.
    // So: extract via the walker, but report `true` UNCONDITIONALLY.
    let _extracted = crate::formats::gopro::process_gopro(buff, gopro_out);
    return true;
  }
  // The `camm` MetaFormat (QuickTimeStream.pl:251-309) — Google's Camera
  // Motion Metadata. Bundled dispatches by the int16u-LE packet-type at
  // sample-bytes +2 to one of seven `%QuickTime::camm<N>` tag tables
  // (camm0..camm7, QuickTimeStream.pl:405-572). Our `process_camm`
  // (faithful port of `ProcessCAMM`:3481-3506) walks the sample as a
  // multi-packet stream and dispatches by type internally.
  //
  // `create_date_raw` is the raw 1904-epoch `mvhd` CreateDate; we route it to
  // camm6's GPS-vs-Unix-epoch heuristic (QuickTimeStream.pl:519) after a
  // 1904→1970 epoch shift via `android_camm::create_date_to_unix`.
  //
  // Returns `false`: `ProcessCAMM` does NOT set `$$et{FoundEmbedded}` (only
  // `ProcessGoPro` (GoPro.pm:822) and a `moov`-level `gps `-box freeGPS decode
  // do), so a `camm` track must NOT suppress the brute-force `mdat` scan.
  if &track.meta_format == b"camm" {
    let create_date_unix = create_date_raw.map(crate::formats::android_camm::create_date_to_unix);
    // Stamp the `Track<N>` index onto exactly the camm GPS samples this
    // sample's decode produces, faithful to ExifTool scoping `SET_GROUP1 =
    // "Track$num"` per-`trak`. Watermark before the (multi-packet) call so a
    // file-scoped meta accumulating multiple `camm` `trak`s stamps each
    // `trak`'s samples with its own index.
    let gps_start = camm_out.gps_sample_count();
    crate::formats::android_camm::process_camm(buff, create_date_unix, camm_out);
    camm_out.stamp_gps_track_index_from(gps_start, track_index);
    return false;
  }
  // NOTE: a real `gps `-HandlerType track is NOT dispatched here — it never
  // reaches `process_samples` ([`is_meta_handler`] excludes `gps `, faithful
  // to ExifTool having no `$eeBox{'gps '}`). The Novatek `gps ` source is the
  // EMPTY-HandlerType `moov`-level box ([`process_moov_gps_box`]), not a track.
  //
  // Sony `rtmd` / Canon `CTMD` / `tx3g` / …:
  // DEFERRED — these re-dispatch into other ExifTool modules (Sony.pm,
  // Canon.pm) or the 850-line ProcessFreeGPS. See module docs +
  // docs/tracking.md. An unrecognized MetaFormat yields no samples, exactly
  // as ExifTool's "Unknown $type format" branch (QuickTimeStream.pl:1547).
  let _ = (buff, &track.handler);
  false
}

// ===========================================================================
// extract_stream — the SP3 entry point
// ===========================================================================

/// Read an atom header at `pos` within `data`; returns `(type, payload
/// range, next sibling)` or `None` on a truncated / invalid header. This is a
/// trimmed re-implementation of the SP1 walker's header read, scoped to the
/// contained-directory walk SP3 needs (sample tables never use the size-0 /
/// 64-bit special cases at the depths SP3 traverses, but 64-bit `co64`-style
/// containers are still handled defensively).
fn atom_at(data: &[u8], pos: usize) -> Option<([u8; 4], usize, usize, usize)> {
  if pos + 8 > data.len() {
    return None;
  }
  // The guard proves `pos + 8 <= data.len()`, so these reads always succeed
  // (the bounds-checking `be_*` helpers return `Some` here); `?` on the
  // impossible miss returns `None`, the same as the `pos + 8 > len` guard.
  let size32 = be_u32(data, pos)?;
  let t: [u8; 4] = data.get(pos + 4..pos + 8)?.try_into().ok()?;
  let (start, end, next) = if size32 == 1 {
    if pos + 16 > data.len() {
      return None;
    }
    // Likewise the `pos + 16 > len` guard proves this 8-byte read is in range.
    let ext = be_u64(data, pos + 8)?;
    let payload = usize::try_from(ext.checked_sub(16)?).ok()?;
    let start = pos + 16;
    let end = start.checked_add(payload)?.min(data.len());
    (start, end, start + payload)
  } else if size32 == 0 {
    // size-0: extends to EOF (contained terminator in SP1's model — here
    // treat the rest of the buffer as the payload and stop the sibling walk).
    (pos + 8, data.len(), data.len())
  } else if size32 < 8 {
    return None;
  } else {
    let payload = size32 as usize - 8;
    let start = pos + 8;
    let end = start.checked_add(payload)?.min(data.len());
    (start, end, start + payload)
  };
  Some((t, start, end, next))
}

/// Iterate the contained sibling atoms in `data[start..end]`, invoking `f`
/// for each `(type, payload)`.
fn for_each_atom(data: &[u8], start: usize, end: usize, mut f: impl FnMut(&[u8; 4], &[u8])) {
  let mut pos = start;
  while pos < end {
    let Some((t, ps, pe, next)) = atom_at(data, pos) else {
      break;
    };
    let pe = pe.min(end);
    // `atom_at` clamps `pe <= data.len()`, and the `ps <= pe` guard makes
    // `.get(ps..pe)` always `Some` here — byte-identical to `data[ps..pe]`.
    if ps <= pe
      && let Some(payload) = data.get(ps..pe)
    {
      f(&t, payload);
    }
    if next <= pos {
      break;
    }
    pos = next;
  }
}

/// Walk one `stbl` box, filling `track.ee` (sample tables) and — for an
/// `OtherSampleDesc`/`MetaSampleDesc` `stsd` — `track.meta_format` /
/// `track.meta_keys`.
fn walk_stbl(data: &[u8], start: usize, end: usize, track: &mut StreamTrack) {
  for_each_atom(data, start, end, |t, body| match t {
    b"stsz" | b"stz2" => parse_stsz(t, body, &mut track.ee),
    b"stco" | b"co64" => parse_stco(t, body, &mut track.ee),
    b"stsc" => parse_stsc(body, &mut track.ee),
    b"stts" => parse_stts(body, &mut track.ee),
    b"stsd" => walk_stsd(body, track),
    _ => {}
  });
}

/// Decode the `stsd` (Sample Description) box for a metadata track —
/// QuickTime.pm:7761-7800 (`MetaSampleDesc` / `OtherSampleDesc`).
///
/// Layout: `[version+flags:4][entry-count:4]` then each entry is
/// `[size:4][format:4][reserved:6][data-ref-index:2]` followed by child
/// atoms. The 4-byte `format` is the `MetaFormat`; for a `mebx` format the
/// `keys` child atom holds the metadata-key table.
fn walk_stsd(data: &[u8], track: &mut StreamTrack) {
  // The 8-byte version/flags + entry-count header, then the FIRST
  // sample-description entry (timed-metadata tracks carry exactly one;
  // ExifTool's `MetaFormat` is last-wins, but a single entry is the
  // universal real-world shape).
  let pos = 8usize;
  if pos + 8 > data.len() {
    return;
  }
  let size = be_u32(data, pos).unwrap_or(0) as usize;
  if size < 16 || pos + size > data.len() {
    return;
  }
  // bytes 4..8 of the entry = the 4-byte format code.
  // The `pos + 8 > len` guard proves this 4-byte read is in range; the
  // `else` return is unreachable and matches that guard's recovery.
  let Some(fmt): Option<[u8; 4]> = data.get(pos + 4..pos + 8).and_then(|s| s.try_into().ok())
  else {
    return;
  };
  track.meta_format = fmt;
  // Child atoms follow the 16-byte SampleDescription header. Scan for
  // `keys` (the `mebx` metadata-key table).
  let entry_end = pos + size;
  for_each_atom(data, pos + 16, entry_end, |t, body| {
    if t == b"keys" {
      // The `keys` box body is itself `[version+flags:4][count:4]` then the
      // key-entry table — `SaveMetaKeys` skips the 8-byte header.
      if body.len() > 8
        && let Some(rest) = body.get(8..)
      {
        track.meta_keys = save_meta_keys(rest);
      }
    }
  });
}

/// Walk one `trak`, collecting its `HandlerType`, `MediaTimeScale` and (when
/// it is a metadata handler) the `stbl` sample tables. Returns the populated
/// [`StreamTrack`].
fn walk_trak(data: &[u8], tr_start: usize, tr_end: usize) -> StreamTrack {
  let mut track = StreamTrack::default();
  for_each_atom(data, tr_start, tr_end, |t, body| {
    if t == b"mdia" {
      // `mdia` holds `mdhd` (timescale) + `hdlr` (handler) + `minf`→`stbl`.
      // body is a sub-slice; recurse using offsets relative to `data`.
      let base = body.as_ptr() as usize - data.as_ptr() as usize;
      for_each_atom(data, base, base + body.len(), |t2, b2| match t2 {
        b"mdhd" => {
          // mdhd MediaTimeScale: version 0 ⇒ int32u at byte 12; version != 0
          // ⇒ int32u at byte 20 (the 64-bit-widened layout).
          if let Some(&v) = b2.first() {
            let off = if v == 0 { 12 } else { 20 };
            if let Some(ts) = be_u32(b2, off) {
              track.media_ts = ts;
            }
          }
        }
        b"hdlr" => {
          // HandlerType is the 4-byte code at byte offset 8.
          if let Some(h) = b2.get(8..12) {
            track.handler.copy_from_slice(h);
          }
        }
        b"minf" => {
          let mb = b2.as_ptr() as usize - data.as_ptr() as usize;
          for_each_atom(data, mb, mb + b2.len(), |t3, b3| {
            if t3 == b"stbl" {
              let sb = b3.as_ptr() as usize - data.as_ptr() as usize;
              walk_stbl(data, sb, sb + b3.len(), &mut track);
            }
          });
        }
        _ => {}
      });
    }
  });
  track
}

/// SP3 entry point — extract QuickTimeStream timed metadata from a whole
/// QuickTime file slice.
///
/// For EVERY top-level `moov`, walks its DIRECT children in file order via
/// [`walk_moov`], processing each GoPro / GPS source at its atom position:
/// each metadata `trak`'s timed samples (`gpmd` GoPro → `gopro_out`), each
/// `moov/udta/GPMF` atom (GoPro → `gopro_out`), and the magic `moov`-level
/// Novatek `gps ` offset box (`ParseTag`, the no-handler `''` entry of
/// `%eeBox`). The `gps0`/`gsen`/`GPS `/`3gf` magic boxes are TOP-LEVEL
/// siblings handled here directly. Because `gpmd` samples and `udta/GPMF`
/// atoms both accumulate into the ONE `gopro_out` (scalar tags last-wins, GPS
/// rows append), interleaving them by atom position — rather than draining
/// all `gpmd` then all `udta/GPMF` — is what makes the final last-wins scalar
/// + GPS-sample order match ExifTool when a `moov` carries both (R9).
///
/// `create_date_raw` is the `mvhd` CreateDate as raw 1904-epoch seconds
/// (needed for `GPSDateTime` synthesis); `None` when no `mvhd` carried one.
///
/// `kodak_version` is the cross-module `$$et{KodakVersion}` global (the Kodak
/// `frea`-atom `'ver '` value, decoded BEFORE this call); it selects the
/// freeGPS Type-17b Rexing scaling in [`quicktime_freegps::process_free_gps`]
/// for the `moov`-level `gps ` offset-box path.
///
/// Returns the decoded [`QuickTimeStreamMeta`] (empty for the common case of a
/// video with no timed metadata) plus the `FoundEmbedded` flag. `FoundEmbedded`
/// is `true` iff EITHER a `moov`-level `gps ` offset box dispatched a `freeGPS `
/// block into [`quicktime_freegps::process_free_gps`] (ExifTool's
/// `$$et{FoundEmbedded}`, QuickTimeStream.pl:1650) OR a GoPro source entered
/// `ProcessGoPro` — a `gpmd` GoPro timed-metadata sample OR a `moov/udta/GPMF`
/// atom (GoPro.pm:822 sets `$$et{FoundEmbedded} = 1` on entry, for both paths).
/// The caller threads that flag into [`quicktime_freegps::scan_media_data`] so
/// the brute-force `mdat` scan is suppressed by a real freeGPS decode or a
/// dispatched GoPro source — NOT by a bare `gps0`/`gsen`/`GPS `/`3gf`/`mebx`
/// timed-metadata sample (those set no `FoundEmbedded`, so a file carrying one
/// of them PLUS a buried `freeGPS ` block is still scanned;
/// QuickTimeStream.pl:967-973 vs :3689).
#[must_use]
pub(crate) fn extract_stream(
  data: &[u8],
  create_date_raw: Option<u64>,
  kodak_version: Option<&str>,
  gopro_out: &mut crate::metadata::GoProMeta,
  camm_out: &mut crate::metadata::CammMeta,
) -> (QuickTimeStreamMeta, bool) {
  let mut out = QuickTimeStreamMeta::new();
  // The freeGPS `$$et{FreeGPS2}` cross-block ring-buffer state shared by the
  // `moov`-level `gps ` offset box (QuickTimeStream.pl:2058). It ALSO carries
  // `$$et{FoundEmbedded}` (QuickTimeStream.pl:1650), set iff a `gps `-box block
  // is decoded — the gate returned to the caller for the `mdat` scan. The
  // brute-force `ScanMediaData` keeps its own instance (its
  // `process_free_gps` calls flip that throwaway flag inertly).
  let mut free_gps_state = FreeGpsState::new();
  // Walk the TOP-LEVEL atoms. `moov` carries the metadata `trak`s + the
  // `moov`-level `gps ` box; the `gps0`/`gsen`/`GPS ` magic boxes are
  // TOP-LEVEL siblings (`%QuickTime::Main` table / `%eeBox` `'GPS ' =>
  // 'main'`, QuickTime.pm:524-533, 932-943).
  // ExifTool's `$$et{FoundEmbedded}` for the GoPro `gpmd` timed-metadata path
  // (GoPro.pm:822) — distinct from the `moov`-level `gps `-box `FoundEmbedded`
  // tracked in `free_gps_state`. OR'd into the gate returned to the caller.
  let mut gopro_found_embedded = false;
  let mut pos = 0usize;
  while pos < data.len() {
    let Some((t, ps, pe, next)) = atom_at(data, pos) else {
      break;
    };
    let body_end = pe.min(data.len());
    match &t {
      b"moov" => {
        gopro_found_embedded |= walk_moov(
          data,
          ps,
          body_end,
          create_date_raw,
          kodak_version,
          &mut free_gps_state,
          &mut out,
          gopro_out,
          camm_out,
        );
      }
      // Top-level DuDuBell / VSYS `gps0` (32-byte LE binary GPS records).
      // `atom_at` guarantees `ps <= body_end <= data.len()`, so `.get` is
      // always `Some`; `unwrap_or_default()` (an empty slice) is unreachable.
      b"gps0" => process_gps0(data.get(ps..body_end).unwrap_or_default(), &mut out),
      // Top-level DuDuBell / VSYS `gsen` (3-byte accelerometer triples).
      b"gsen" => process_gsen(data.get(ps..body_end).unwrap_or_default(), &mut out),
      // Top-level Kenwood `GPS ` (36-byte LE inline GPS records).
      b"GPS " => parse_kenwood_gps(
        data.get(ps..body_end).unwrap_or_default(),
        create_date_raw,
        &mut out,
      ),
      // Pittasoft BlackVue `3gf ` accelerometer (QuickTimeStream.pl
      // `Process_3gf`:2686-2708). ExifTool routes this via the
      // `%QuickTime::Pittasoft` parent table (an SP4 brand-variant); SP3
      // decodes a `3gf ` box wherever it appears in the atoms it walks.
      b"3gf " => process_3gf(data.get(ps..body_end).unwrap_or_default(), &mut out),
      _ => {}
    }
    if next <= pos {
      break;
    }
    pos = next;
  }
  // `$$et{FoundEmbedded}` after the moov walk — set by EITHER a `moov`-level
  // `gps `-box block reaching `process_free_gps` (`free_gps_state`) OR a
  // dispatched GoPro source (`gopro_found_embedded`, GoPro.pm:822): a `gpmd`
  // timed-metadata sample in a `trak` OR a `moov/udta/GPMF` atom — both run
  // through [`walk_moov`], so its returned flag already folds in the
  // `udta/GPMF` path (no separate post-pass). This — not `out.is_empty()` —
  // gates the brute-force `mdat` scan (QuickTimeStream.pl:3689). A GoPro file
  // that also carries unreferenced GP6 trailer records is correctly NOT
  // re-scanned (already extracted via the sample / `udta/GPMF` path),
  // matching ExifTool.
  let found_embedded = free_gps_state.found_embedded() || gopro_found_embedded;
  (out, found_embedded)
}

/// Decode the `moov`-level Novatek `gps ` box — the offset TABLE that
/// `ParseTag` parses at QuickTimeStream.pl:2544-2557 (the `$tag eq 'gps '`
/// arm).
///
/// `payload` is the box VALUE (the bytes AFTER the 8-byte atom header — what
/// ExifTool passes to `ParseTag` as `$$dataPt`, QuickTime.pm:10282). The
/// table layout (read big-endian, the QuickTime `'MM'` order ExifTool sets in
/// `ProcessMOV`, QuickTime.pm:10014):
///   `[reserved:4][count:4]` then `count` × `[start:4][size:4]`
/// where each `(start, size)` is an ABSOLUTE file offset/length of a sample
/// block (NOT relative to `mdat` — the XGODY 12" 4K Dashcam stores its
/// `freeGPS ` blocks OUTSIDE `mdat`, QuickTimeStream.pl:1555-1556). `data` is
/// the WHOLE file slice, so the blocks are read directly from it.
///
/// For each block that begins with `....freeGPS ` (a 4-byte size word + the
/// magic, QuickTimeStream.pl:1553) we call [`quicktime_freegps::process_free_gps`].
/// ExifTool fakes `HandlerType='gps '` and runs `ProcessSamples`
/// (QuickTimeStream.pl:2555-2556) which, for THIS box, sets only
/// `$$et{ee}{start}`/`{size}` (no `stts`), so `$time[$i]` is `undef` and the
/// dispatch passes `SampleTime => undef` (QuickTimeStream.pl:1562) — hence the
/// `None` sample time here. (A date-less GPSType such as Type-19 therefore
/// synthesizes NO `GPSDateTime` from this source, exactly as
/// `SetGPSDateTime(..., undef)` is a no-op, QuickTimeStream.pl:984.)
///
/// `kodak_version` is the cross-module `$$et{KodakVersion}` global (selects the
/// freeGPS Type-17b Rexing scaling); `create_date_raw` is the movie
/// `mvhd` CreateDate (raw 1904-epoch seconds) — both forwarded unchanged.
fn process_moov_gps_box(
  data: &[u8],
  payload: &[u8],
  create_date_raw: Option<u64>,
  kodak_version: Option<&str>,
  free_gps_state: &mut FreeGpsState,
  out: &mut QuickTimeStreamMeta,
) {
  // QuickTimeStream.pl:2544 `elsif ($tag eq 'gps ' and $dataLen > 8)`.
  if payload.len() <= 8 {
    return;
  }
  // QuickTimeStream.pl:2546 `my $num = Get32u($dataPt, 4)`. The 4 bytes at
  // payload offset 0 are reserved/version (ExifTool reads the count at 4).
  let Some(mut num) = be_u32(payload, 4).map(|n| n as usize) else {
    return;
  };
  // QuickTimeStream.pl:2547 `$num = int(($dataLen - 8) / 8) if $num*8+8 > $dataLen`.
  // (`num * 8 + 8` is computed in usize; saturate to avoid overflow on a
  // hostile count.)
  if num.saturating_mul(8).saturating_add(8) > payload.len() {
    num = (payload.len() - 8) / 8;
  }
  // QuickTimeStream.pl:2550-2553 — read the `(start, size)` pairs, then
  // QuickTimeStream.pl:2555-2556 `ProcessSamples` reads each block. Because
  // these blocks may be ANYWHERE in the file (not just `mdat`), the per-sample
  // `start`/`size` are absolute file offsets into `data`.
  for i in 0..num {
    let Some(start) = be_u32(payload, 8 + i * 8).map(|v| v as usize) else {
      break;
    };
    let Some(size) = be_u32(payload, 12 + i * 8).map(|v| v as usize) else {
      break;
    };
    // QuickTimeStream.pl:1435-1442 — a seek/read past EOF warns + `next`s.
    let Some(buff) = data.get(start..start.saturating_add(size)) else {
      continue;
    };
    // QuickTimeStream.pl:1553 `if ($buff =~ /^....freeGPS /s)` — 4 arbitrary
    // bytes (the inner box size) then the literal magic.
    if buff.get(4..12) == Some(b"freeGPS ".as_slice()) {
      // QuickTimeStream.pl:1559-1564 — `ProcessFreeGPS` with `SampleTime =>
      // $time[$i]`, which is `undef` for this box (no `stts`); see fn docs.
      quicktime_freegps::process_free_gps(
        buff,
        create_date_raw,
        None,
        kodak_version,
        free_gps_state,
        out,
      );
    }
  }
}

/// Walk one `moov`'s DIRECT children in file (atom-list) order, processing
/// each GoPro / GPS source AT its child position — exactly as ExifTool's
/// `ProcessMOV` `for(;;)` loop (QuickTime.pm:10032) reaches them:
///
///   - `trak` — the timed-metadata samples (a `gpmd` GoPro track dispatches
///     into [`crate::formats::gopro::process_gopro`]). ExifTool runs
///     `ProcessSamples` when the track's `stbl` box EXITS (QuickTime.pm:10369-
///     10371), i.e. at that `trak`'s position in the walk.
///   - `udta/GPMF` — the GoPro GPMF atom (QuickTime.pm:2132-2135). ExifTool
///     dispatches it via `$et->ProcessDirectory` (QuickTime.pm:10359) the
///     instant the walk descends the `udta` child, i.e. at that `udta`'s
///     position. `GPMF` is reached ONLY through the `udta`/UserData table
///     (`%QuickTime::UserData`, QuickTime.pm:1214-1217); a *direct* `moov/GPMF`
///     child is NOT an ExifTool dispatch target (the Movie table has no `GPMF`
///     entry) and is deliberately ignored here (R8 — oracle-verified vs
///     ExifTool 13.59: a `moov` carrying both a `udta/GPMF` and a direct
///     `moov/GPMF` reports only the `udta` device-name regardless of order).
///   - the magic `moov`-level Novatek `gps ` offset box (`ParseTag` →
///     `ProcessSamples`, QuickTime.pm:10282 / QuickTimeStream.pl:2544), at its
///     own child position (its freeGPS rows land in the SEPARATE `out`
///     accumulator, so they never interleave with GoPro's `gopro_out`).
///
/// Processing each source AT its atom position (rather than draining all
/// `gpmd` samples then all `udta/GPMF` in a fixed post-pass) makes the
/// accumulation into the single flat `gopro_out` follow ExifTool's `for(;;)`
/// walk ORDER — so GoPro scalar tags (last-wins `set_*`) and GPS rows (append
/// `push_*`) land in walk order. This holds across EVERY top-level `moov`
/// (the caller invokes `walk_moov` per `moov` in file order, R7 multi-moov).
///
/// NOTE (oracle-verified, ExifTool 13.59): a file carrying BOTH a `gpmd` trak
/// AND a `udta/GPMF` is NOT a clean last-wins collision in ExifTool — the
/// `gpmd` GoPro tags inherit the track's `SET_GROUP1 = Track<N>` group
/// (GoPro.pm:826 leaves `SET_GROUP0` alone when `SET_GROUP1` is set) while the
/// `udta/GPMF` tags emit at the moov level (`GoPro:`/`QuickTime:`), so the two
/// sources occupy DIFFERENT groups and BOTH survive regardless of sibling
/// order. exifast's flat [`crate::metadata::GoProMeta`] cannot represent that
/// per-track grouping, so it collapses both into one `GoPro:` namespace; this
/// ordered walk only controls WHICH source wins that single flat slot. The
/// group-faithful behaviour (per-track GoPro tags) is a separate, larger
/// change tracked outside this walk — see the module-level note.
///
/// Returns `true` iff ANY GoPro source was DISPATCHED — a `gpmd` GoPro sample
/// in a `trak` OR a `udta/GPMF` atom — mirroring ExifTool's
/// `$$et{FoundEmbedded} = 1` set on ENTRY to `ProcessGoPro` (GoPro.pm:822),
/// the gate for the brute-force `mdat` scan (QuickTimeStream.pl:3689). The
/// `moov`-level `gps ` box's own `FoundEmbedded` is tracked separately via
/// `free_gps_state`.
#[must_use]
fn walk_moov(
  data: &[u8],
  start: usize,
  end: usize,
  create_date_raw: Option<u64>,
  kodak_version: Option<&str>,
  free_gps_state: &mut FreeGpsState,
  out: &mut QuickTimeStreamMeta,
  gopro_out: &mut crate::metadata::GoProMeta,
  camm_out: &mut crate::metadata::CammMeta,
) -> bool {
  let mut gopro_found_embedded = false;
  // ExifTool's `$track` (QuickTime.pm:10353-10354): incremented for EVERY
  // `trak` SubDirectory as `ProcessMOV` descends it, then used as
  // `SET_GROUP1 = "Track$track"`. It counts ALL `trak`s in moov order (video /
  // audio / metadata alike), 1-based — NOT the `tkhd` TrackID (the camm
  // fixture has TrackID 0 yet emits `Track1`). We mirror that by incrementing
  // on every `trak` atom BEFORE the metadata-handler test, so a metadata
  // `trak` preceded by a `vide`/`soun` `trak` gets the correct higher index.
  let mut track_index: u32 = 0;
  for_each_atom(data, start, end, |t, body| {
    let base = body.as_ptr() as usize - data.as_ptr() as usize;
    match t {
      b"trak" => {
        track_index += 1;
        let track = walk_trak(data, base, base + body.len());
        // Only metadata-bearing handlers feed `ProcessSamples`
        // (QuickTimeStream.pl:1315-1331 — `vide`/`soun` are hash-only). A
        // real `gps `-HandlerType track is NOT one of them: ExifTool has no
        // `$eeBox{'gps '}` (only `$eeBox{''}{'gps '}`, the no-handler box at
        // the `moov` level — QuickTime.pm:523-533), so a `trak` whose `hdlr`
        // HandlerType is `gps ` is ignored for embedded extraction. See
        // [`is_meta_handler`].
        if is_meta_handler(&track.handler) {
          gopro_found_embedded |= process_samples(
            data,
            &track,
            track_index,
            create_date_raw,
            out,
            gopro_out,
            camm_out,
          );
        }
      }
      // The `moov`-level Novatek `gps ` box — a DIRECT child atom of `moov`
      // named `gps ` (NOT a `trak`) with the EMPTY HandlerType: `%eeBox`
      // `'' => { 'gps ' => 'moov' }` gated by `$eeBox{$handlerType}{$tag} eq
      // $dirID` with `$dirID eq 'moov'` (QuickTime.pm:523-533, 10110-10114).
      // It is an offset TABLE pointing at `freeGPS ` blocks that may live
      // ANYWHERE in the file (the XGODY 12" 4K Dashcam stores them OUTSIDE
      // `mdat`), decoded by `ParseTag`'s `gps ` arm (QuickTimeStream.pl:2544).
      // `body` here is the box VALUE (payload after the atom header).
      b"gps " => {
        process_moov_gps_box(
          data,
          body,
          create_date_raw,
          kodak_version,
          free_gps_state,
          out,
        );
      }
      // The GoPro `moov/udta/GPMF` atom (QuickTime.pm:2132-2135). ExifTool
      // dispatches it via `$et->ProcessDirectory` (QuickTime.pm:10359) the
      // instant the `for(;;)` walk descends this `udta` child — i.e. at THIS
      // child's atom position, INTERLEAVED with the `trak`/`gpmd` samples
      // (processed at the `trak` position) and the `gps ` box above. Running
      // it here (rather than in a fixed post-pass after every `trak`) makes
      // the accumulation into the flat `gopro_out` follow ExifTool's walk
      // ORDER. (See the fn doc: in ExifTool the two sources land in different
      // GROUPS — `Track<N>:` vs `GoPro:` — so this ordering only decides which
      // wins exifast's single flat slot; full group fidelity is a separate
      // change.)
      //
      // `GPMF` lives ONLY in the `udta`/UserData table, so it is reached as a
      // DIRECT child of `udta`; a direct `moov/GPMF` child is NOT an ExifTool
      // dispatch target and is intentionally not visited (R8). `process_gopro`
      // sets ExifTool's `$$et{FoundEmbedded} = 1` on ENTRY (GoPro.pm:822), so
      // the mere PRESENCE of a dispatched `udta/GPMF` suppresses the
      // brute-force `mdat` scan — independent of whether the body parsed any
      // record. Mirror that: flip `gopro_found_embedded` for every `GPMF`
      // atom visited, consistent with the `gpmd`-sample side-effect.
      b"udta" => {
        for_each_atom(data, base, base + body.len(), |t2, gpmf_body| {
          if t2 == b"GPMF" {
            gopro_found_embedded = true;
            let _extracted = crate::formats::gopro::process_gopro(gpmf_body, gopro_out);
          }
        });
      }
      _ => {}
    }
  });
  gopro_found_embedded
}

/// `true` when a `hdlr` HandlerType feeds the timed-metadata path — `meta`
/// / `data` / `sbtl` / `text` / `camm` / `ctbx` (the `%eeBox` keys with a
/// `%eeStd` directory, QuickTime.pm:524-532). `vide` / `soun` are excluded
/// (those are the hash-only path, QuickTimeStream.pl:1316-1331).
///
/// `gps ` is deliberately NOT here: ExifTool has no `$eeBox{'gps '}` entry —
/// only `$eeBox{''}{'gps '} = 'moov'` (the EMPTY-HandlerType `moov`-level box,
/// handled in [`process_moov_gps_box`]). A real `trak` whose `hdlr`
/// HandlerType is `gps ` is therefore IGNORED for embedded GPS extraction
/// (which also keeps the brute-force `mdat` scan un-suppressed, since such a
/// track populates no samples — QuickTimeStream.pl:3689).
fn is_meta_handler(h: &[u8; 4]) -> bool {
  matches!(h, b"meta" | b"data" | b"sbtl" | b"text" | b"camm" | b"ctbx")
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  /// R2 finding regression — the deferred non-GoPro `gpmd` variants
  /// (QuickTimeStream.pl:181-208) must be recognized so they are NOT
  /// dispatched to the GoPro KLV walker (and so they do not set
  /// `FoundEmbedded`, which would suppress the brute-force `mdat` scan that
  /// recovers them). The GoPro fallback (no signature match) must NOT be
  /// classified as deferred.
  #[test]
  fn deferred_gpmd_variants_are_classified() {
    // gpmd_FMAS: `/^FMAS\0\0\0\0/` (Vantrue N2S). A printable FourCC the
    // GoPro KLV walker would otherwise mistake for a record.
    assert!(is_deferred_gpmd_variant(b"FMAS\0\0\0\0\xde\xad\xbe\xef"));
    // gpmd_Rove: `/^\0\0\xf2\xe1\xf0\xeeTT/`.
    assert!(is_deferred_gpmd_variant(&[
      0x00, 0x00, 0xf2, 0xe1, 0xf0, 0xee, b'T', b'T', 0x01, 0x02
    ]));
    // gpmd_Kingslim: `/^.{21}\0\0\0A[NS][EW]/s`.
    let mut kingslim = vec![0xaau8; 21];
    kingslim.extend_from_slice(&[0, 0, 0, b'A', b'N', b'E']);
    assert!(is_deferred_gpmd_variant(&kingslim));
    // gpmd_Wolfbox: `/^.{136}(0{16}[A-Z]{4}|...)/s`.
    let mut wolfbox = vec![0x11u8; 136];
    wolfbox.extend_from_slice(b"0000000000000000ABCD");
    assert!(is_deferred_gpmd_variant(&wolfbox));
    // gpmd_GoPro fallback — a real GoPro `DEVC` sample is NOT deferred.
    assert!(!is_deferred_gpmd_variant(
      b"DEVC\0\x01\x00\x01\x00\x00\x00\x00"
    ));
    // Too-short buffers never match (no panic — checked `.get`).
    assert!(!is_deferred_gpmd_variant(b"FMA"));
    assert!(!is_deferred_gpmd_variant(&[]));
  }

  /// **R8-B** — `decode_one_sample` sets `FoundEmbedded` (returns `true`) for
  /// ANY non-deferred `gpmd` sample, regardless of whether the GoPro KLV parse
  /// extracted a record. ExifTool sets `$$et{FoundEmbedded} = 1` on ENTRY to
  /// `ProcessGoPro` (GoPro.pm:822), BEFORE the KLV loop, and `gpmd_GoPro` is
  /// the no-`Condition` fallback (QuickTimeStream.pl:209-212) — so every
  /// non-deferred `gpmd` sample enters `ProcessGoPro` ⇒ `FoundEmbedded` ⇒
  /// `ScanMediaData` returns early. A corrupt/zero-filled `gpmd` must therefore
  /// NOT fall through to the brute-force `mdat` scan. The deferred variants
  /// (R2/R6) must still return `false` (NOT GoPro, no `FoundEmbedded`).
  #[test]
  fn gpmd_sets_found_embedded_on_entry_even_when_parse_finds_nothing() {
    let gpmd_track = StreamTrack {
      meta_format: *b"gpmd",
      ..StreamTrack::default()
    };
    let sample = Sample {
      start: 0,
      size: 0,
      time: None,
      dur: None,
    };
    let mut out = QuickTimeStreamMeta::default();
    let mut gopro = crate::metadata::GoProMeta::new();
    let mut camm = crate::metadata::CammMeta::new();

    // A zero-filled `gpmd` sample: `process_gopro` extracts nothing (the KLV
    // walker bails on the four-NUL tag, GoPro.pm:844) — but it is NOT a
    // deferred variant, so it IS the `gpmd_GoPro` fallback and `FoundEmbedded`
    // is set on entry. Pre-fix this returned the walker's `false`; now `true`.
    let zero = [0u8; 64];
    assert!(
      decode_one_sample(
        &zero,
        &gpmd_track,
        1,
        &sample,
        None,
        &mut out,
        &mut gopro,
        &mut camm
      ),
      "zero-filled non-deferred gpmd still sets FoundEmbedded (ProcessGoPro entry)"
    );

    // A `gpmd` sample whose leading tag bytes are non-printable: the walker
    // bails on the tag-char guard (GoPro.pm:833), extracting nothing — but it
    // is still the non-deferred `gpmd_GoPro` fallback, so `FoundEmbedded` is
    // set. (All-`\xff` matches none of Kingslim/Rove/FMAS/Wolfbox: Wolfbox
    // needs `0` bytes at offsets 136-151, which `\xff` fails.)
    let nonprintable = vec![0xffu8; 64];
    assert!(
      !is_deferred_gpmd_variant(&nonprintable),
      "the non-printable sample is NOT a deferred variant"
    );
    assert!(
      decode_one_sample(
        &nonprintable,
        &gpmd_track,
        1,
        &sample,
        None,
        &mut out,
        &mut gopro,
        &mut camm
      ),
      "non-printable non-deferred gpmd still sets FoundEmbedded"
    );

    // No-regression: a DEFERRED variant (FMAS) returns false (NOT GoPro, must
    // not set FoundEmbedded — preserves the R2/R6 fix).
    let fmas = b"FMAS\0\0\0\0\xde\xad\xbe\xef";
    assert!(is_deferred_gpmd_variant(fmas));
    assert!(
      !decode_one_sample(
        fmas,
        &gpmd_track,
        1,
        &sample,
        None,
        &mut out,
        &mut gopro,
        &mut camm
      ),
      "deferred FMAS gpmd does NOT set FoundEmbedded (no regression)"
    );

    // And a real GoPro `DEVC` sample (valid record) of course returns true.
    let devc = b"DEVC\0\x01\x00\x01\x00\x00\x00\x00";
    assert!(
      decode_one_sample(
        devc,
        &gpmd_track,
        1,
        &sample,
        None,
        &mut out,
        &mut gopro,
        &mut camm
      ),
      "a valid GoPro DEVC sample sets FoundEmbedded"
    );

    // A non-`gpmd`, non-`mebx`, non-`camm` track sets nothing (the default,
    // deferred arm — e.g. Sony `rtmd`).
    let other_track = StreamTrack {
      meta_format: *b"rtmd",
      handler: *b"meta",
      ..StreamTrack::default()
    };
    assert!(
      !decode_one_sample(
        &zero,
        &other_track,
        1,
        &sample,
        None,
        &mut out,
        &mut gopro,
        &mut camm
      ),
      "a non-gpmd/non-mebx/non-camm track sets no FoundEmbedded"
    );
    // A `camm` track also sets no FoundEmbedded (ProcessCAMM never sets it),
    // even though it now dispatches into the CAMM decoder.
    let camm_track = StreamTrack {
      meta_format: *b"camm",
      handler: *b"camm",
      ..StreamTrack::default()
    };
    assert!(
      !decode_one_sample(
        &zero,
        &camm_track,
        1,
        &sample,
        None,
        &mut out,
        &mut gopro,
        &mut camm
      ),
      "a camm track does not set FoundEmbedded"
    );
  }

  fn atom(t: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut v = ((body.len() + 8) as u32).to_be_bytes().to_vec();
    v.extend_from_slice(t);
    v.extend_from_slice(body);
    v
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
  fn convert_lat_lon_dddmm() {
    // 4737.7053 (DDDMM.MMMM) = 47 deg + 37.7053 min = 47.628421667 deg.
    let v = convert_lat_lon(4737.7053);
    assert!((v - 47.628_421_666_666_67).abs() < 1e-9, "got {v}");
    // negative coordinate works (Perl int truncates toward zero).
    let n = convert_lat_lon(-4737.7053);
    assert!((n + 47.628_421_666_666_67).abs() < 1e-9, "got {n}");
  }

  #[test]
  fn live_photo_info_unpacks_le_template() {
    // QuickTime.pm:6791 `join " ",unpack "VfVVf6c4lCCcclf4Vvv",$val` over a
    // crafted 80-byte LE value. Mirrors the `QuickTime_mebx_livephoto.mov`
    // fixture; the expected join matches the bundled `-ee` oracle exactly.
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(&1u32.to_le_bytes()); // V
    v.extend_from_slice(&1.5f32.to_le_bytes()); // f
    v.extend_from_slice(&2u32.to_le_bytes()); // V
    v.extend_from_slice(&3u32.to_le_bytes()); // V
    for x in [0.25f32, 0.5, 0.75, 1.0, 1.25, 1.5] {
      v.extend_from_slice(&x.to_le_bytes()); // f6
    }
    for c in [1i8, -2, 3, -4] {
      v.push(c as u8); // c4
    }
    v.extend_from_slice(&(-1000i32).to_le_bytes()); // l
    v.push(200); // C
    v.push(250); // C
    v.push((-5i8) as u8); // c
    v.push(7u8); // c
    v.extend_from_slice(&123_456i32.to_le_bytes()); // l
    for x in [2.5f32, -3.5, 4.0, 0.125] {
      v.extend_from_slice(&x.to_le_bytes()); // f4
    }
    v.extend_from_slice(&99u32.to_le_bytes()); // V
    v.extend_from_slice(&1000u16.to_le_bytes()); // v
    v.extend_from_slice(&65535u16.to_le_bytes()); // v
    assert_eq!(v.len(), 80, "template consumes exactly 80 bytes");
    assert_eq!(
      unpack_live_photo_info(&v).as_deref(),
      Some(
        "1 1.5 2 3 0.25 0.5 0.75 1 1.25 1.5 1 -2 3 -4 -1000 200 250 -5 7 123456 2.5 -3.5 4 0.125 99 1000 65535"
      )
    );
    // A value shorter than 80 bytes cannot satisfy the unpack ⇒ None (the
    // caller falls back to the raw `ReadValue` string).
    assert_eq!(unpack_live_photo_info(v.get(..79).unwrap()), None);
    assert_eq!(unpack_live_photo_info(&[]), None);
  }

  #[test]
  fn stsz_uniform_and_explicit() {
    // explicit (sz==0): version/flags + sz=0 + count=2 + two int32u sizes.
    let mut d = alloc::vec![0u8; 12];
    wr(&mut d, 8, &2u32.to_be_bytes());
    d.extend_from_slice(&100u32.to_be_bytes());
    d.extend_from_slice(&200u32.to_be_bytes());
    let mut ee = EeData::default();
    parse_stsz(b"stsz", &d, &mut ee);
    assert_eq!(ee.size, alloc::vec![100, 200]);
    // uniform (sz!=0): sz=64, count=3 ⇒ [64,64,64].
    let mut u = alloc::vec![0u8; 12];
    wr(&mut u, 4, &64u32.to_be_bytes());
    wr(&mut u, 8, &3u32.to_be_bytes());
    u.push(0); // need length > 12
    let mut ee2 = EeData::default();
    parse_stsz(b"stsz", &u, &mut ee2);
    assert_eq!(ee2.size, alloc::vec![64, 64, 64]);
  }

  #[test]
  fn stsc_requires_full_table() {
    // count=1 but no entry bytes ⇒ rejected (faithful: 8 + num*12 check).
    let mut short = alloc::vec![0u8; 8];
    wr(&mut short, 4, &1u32.to_be_bytes());
    short.push(0); // length > 8
    let mut ee = EeData::default();
    parse_stsc(&short, &mut ee);
    assert!(ee.stsc.is_empty());
    // a complete entry decodes.
    let mut full = alloc::vec![0u8; 8];
    wr(&mut full, 4, &1u32.to_be_bytes());
    full.extend_from_slice(&1u32.to_be_bytes()); // first chunk
    full.extend_from_slice(&5u32.to_be_bytes()); // samples per chunk
    full.extend_from_slice(&1u32.to_be_bytes()); // desc index
    let mut ee2 = EeData::default();
    parse_stsc(&full, &mut ee2);
    assert_eq!(ee2.stsc, alloc::vec![(1, 5, 1)]);
  }

  #[test]
  fn expand_one_chunk_one_sample() {
    let ee = EeData {
      stco: alloc::vec![1000],
      stsc: alloc::vec![(1, 1, 1)],
      size: alloc::vec![42],
      stts: alloc::vec![1, 600], // 1 sample, delta 600
    };
    let samples = expand_samples(&ee, 600).expect("samples");
    assert_eq!(samples.len(), 1);
    assert_eq!(samples.first().unwrap().start, 1000);
    assert_eq!(samples.first().unwrap().size, 42);
    // time 0, dur 600/600 = 1.0s.
    assert_eq!(samples.first().unwrap().time, Some(0.0));
    assert_eq!(samples.first().unwrap().dur, Some(1.0));
  }

  #[test]
  fn process_3gf_decodes_accelerometer_and_terminates() {
    let mut body = Vec::new();
    // record 1: tc=1000, x=10 y=-20 z=30 (raw /10 ⇒ 1, -2, 3).
    body.extend_from_slice(&1000u32.to_be_bytes());
    body.extend_from_slice(&10i16.to_be_bytes());
    body.extend_from_slice(&(-20i16).to_be_bytes());
    body.extend_from_slice(&30i16.to_be_bytes());
    // terminator record.
    body.extend_from_slice(&0xffff_ffffu32.to_be_bytes());
    body.extend_from_slice(&[0u8; 6]);
    let mut out = QuickTimeStreamMeta::new();
    process_3gf(&body, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = out.gps_samples().first().unwrap();
    assert_eq!(s.time_code(), Some(1.0));
    assert_eq!(s.accelerometer(), Some("1 -2 3"));
  }

  #[test]
  fn process_gsen_decodes_triples() {
    // two 3-byte records.
    let body = [16i8 as u8, (-32i8) as u8, 48i8 as u8, 8u8, 0u8, 0u8];
    let mut out = QuickTimeStreamMeta::new();
    process_gsen(&body, &mut out);
    assert_eq!(out.gps_samples().len(), 2);
    // 16/16=1, -32/16=-2, 48/16=3.
    assert_eq!(
      out.gps_samples().first().unwrap().accelerometer(),
      Some("1 -2 3")
    );
    assert_eq!(
      out.gps_samples().get(1).unwrap().accelerometer(),
      Some("0.5 0 0")
    );
  }

  #[test]
  fn synth_gps_date_time_needs_create_date() {
    assert_eq!(synth_gps_date_time(None, Some(1.0)), None);
    assert_eq!(synth_gps_date_time(Some(123), None), None);
    // QuickTimeStream.pl:984 — a raw CreateDate of 0 is FALSY ⇒ no synth (even
    // with a sample time present).
    assert_eq!(synth_gps_date_time(Some(0), Some(1.0)), None);
    // create_date = QT_EPOCH_OFFSET + 1s ⇒ unix 1 ⇒ 1970-01-01 00:00:01
    // (unix 0 hits ExifTool's `0000:00:00 00:00:00` zero sentinel,
    // ExifTool.pm:6776 — so anchor 1s past the epoch).
    let s = synth_gps_date_time(Some(QT_EPOCH_OFFSET as u64 + 1), Some(0.0)).expect("dt");
    assert_eq!(s, "1970:01:01 00:00:01Z");
    // adding the sample time shifts the result forward.
    let s2 = synth_gps_date_time(Some(QT_EPOCH_OFFSET as u64), Some(61.0)).expect("dt");
    assert_eq!(s2, "1970:01:01 00:01:01Z");
  }

  #[test]
  fn save_meta_keys_recovers_keyd_and_dtyp() {
    // one key entry: local-id 1, keyd 'mdtacom.apple.quicktime.Foo', dtyp int32u.
    let keyd_val = b"mdtacom.apple.quicktime.Foo";
    let keyd = {
      let mut v = ((8 + keyd_val.len()) as u32).to_be_bytes().to_vec();
      v.extend_from_slice(b"keyd");
      v.extend_from_slice(keyd_val);
      v
    };
    let dtyp = {
      let mut v = 16u32.to_be_bytes().to_vec();
      v.extend_from_slice(b"dtyp");
      v.extend_from_slice(&0u32.to_be_bytes()); // ns=0
      v.extend_from_slice(&77u32.to_be_bytes()); // int32u
      v
    };
    let mut entry = ((8 + keyd.len() + dtyp.len()) as u32)
      .to_be_bytes()
      .to_vec();
    entry.extend_from_slice(&1u32.to_be_bytes()); // local id
    entry.extend_from_slice(&keyd);
    entry.extend_from_slice(&dtyp);
    let keys = save_meta_keys(&entry);
    assert_eq!(keys.len(), 1);
    assert_eq!(keys.first().unwrap().0, 1);
    assert_eq!(keys.first().unwrap().1.tag_id, "Foo");
    assert_eq!(keys.first().unwrap().1.format, MetaFormat::Int32u);
  }

  #[test]
  fn process_mebx_decodes_int_value() {
    let keys = alloc::vec![(
      1u32,
      MetaKey {
        // Not a `%QuickTime::Keys` TagID ⇒ dynamic-add: camel-case of
        // `GPSCoordinates` (no separators) is itself.
        tag_id: "GPSCoordinates".into(),
        format: MetaFormat::Int32s,
      },
    )];
    // mebx record: [len=12][local-id=1][int32s value=123456].
    let mut rec = 12u32.to_be_bytes().to_vec();
    rec.extend_from_slice(&1u32.to_be_bytes());
    rec.extend_from_slice(&123456i32.to_be_bytes());
    let mut out = QuickTimeStreamMeta::new();
    process_mebx(&rec, &keys, Some(0.5), Some(1.0), &mut out);
    assert_eq!(out.mebx_samples().len(), 1);
    assert_eq!(out.mebx_samples().first().unwrap().name(), "GPSCoordinates");
    assert_eq!(out.mebx_samples().first().unwrap().value(), "123456");
    assert_eq!(
      out.mebx_samples().first().unwrap().sample_duration(),
      Some(1.0)
    );
    assert_eq!(out.mebx_samples().first().unwrap().sample_time(), Some(0.5));
  }

  #[test]
  fn camel_case_ucfirst_matches_perl() {
    // QuickTimeStream.pl:2663-2664 `s/[-.](.)/\U$1/g` + `ucfirst`.
    assert_eq!(camel_case_ucfirst("test.foo-bar"), "TestFooBar");
    assert_eq!(camel_case_ucfirst("video-orientation"), "VideoOrientation");
    assert_eq!(camel_case_ucfirst("still-image-time"), "StillImageTime");
    // `_` is a `\w` char, NOT a separator — preserved verbatim.
    assert_eq!(camel_case_ucfirst("Encoded_With"), "Encoded_With");
    // a trailing separator with no following char is unmatched (kept).
    assert_eq!(camel_case_ucfirst("a."), "A.");
    // ucfirst upper-cases only the first char.
    assert_eq!(camel_case_ucfirst("foo"), "Foo");
  }

  #[test]
  fn resolve_mebx_tag_keys_lookup_and_fallback() {
    // `%QuickTime::Keys` lookup: Name ≠ camel-case (QuickTime.pm:6701).
    let (name, conv) = resolve_mebx_tag("location.ISO6709").expect("known");
    assert_eq!(name, "GPSCoordinates");
    assert_eq!(conv, KeyValueConv::Iso6709);
    // scene-illuminance ⇒ unpack("N",$val).
    let (name, conv) = resolve_mebx_tag("scene-illuminance").expect("known");
    assert_eq!(name, "SceneIlluminance");
    assert_eq!(conv, KeyValueConv::SceneIlluminanceN);
    // detected-face.face-id ⇒ Keys Name DetectedFaceID (≠ camel-case).
    let (name, _) = resolve_mebx_tag("detected-face.face-id").expect("known");
    assert_eq!(name, "DetectedFaceID");
    // detected-face.bounds ⇒ DetectedFaceBounds with the round-to-6dp PrintConv.
    let (name, conv) = resolve_mebx_tag("detected-face.bounds").expect("known");
    assert_eq!(name, "DetectedFaceBounds");
    assert_eq!(conv, KeyValueConv::DetectedFaceBounds);
    // unknown reverse-DNS ⇒ camel-case fallback, no ValueConv.
    let (name, conv) = resolve_mebx_tag("test.foo-bar").expect("valid id");
    assert_eq!(name, "TestFooBar");
    assert_eq!(conv, KeyValueConv::None);
    // QuickTimeStream.pl:2660 `next unless $tag =~ /^[-\w.]+$/`: a TagID with
    // a disallowed char (space) is SKIPPED (no tag).
    assert!(resolve_mebx_tag("bad id").is_none());
    assert!(resolve_mebx_tag("").is_none());
  }

  #[test]
  fn read_meta_value_empty_and_short_yield_empty_string() {
    // ReadValue's `return '' if ... $size < $len` (ExifTool.pm:6299): an empty
    // value or a value shorter than one format unit yields "" — NOT dropped.
    assert_eq!(read_meta_value(&[], MetaFormat::Int32u), "");
    assert_eq!(read_meta_value(&[0x00, 0x01], MetaFormat::Int32u), ""); // 2 < 4
    assert_eq!(read_meta_value(&[], MetaFormat::Str), "");
    assert_eq!(read_meta_value(&[], MetaFormat::Undef), "");
    // a full element still decodes.
    assert_eq!(read_meta_value(&[0, 0, 0, 5], MetaFormat::Int32u), "5");
    // `string` truncates at the first NUL (`s/\0.*//s`, ExifTool.pm:6311):
    // the NUL and everything after it is dropped.
    assert_eq!(read_meta_value(b"hi\0junk", MetaFormat::Str), "hi");
    // `undef` keeps the raw byte span (no NUL handling).
    assert_eq!(read_meta_value(b"ab", MetaFormat::Undef), "ab");
  }

  #[test]
  fn process_mebx_empty_value_emits_empty_string_tag() {
    // An 8-byte record ($len-8 == 0) ⇒ ReadValue returns '' and the tag is
    // STILL emitted (not dropped). Key resolves via camel-case.
    let keys = alloc::vec![(
      7u32,
      MetaKey {
        tag_id: "still-image-time".into(),
        format: MetaFormat::Int8s,
      },
    )];
    let mut rec = 8u32.to_be_bytes().to_vec(); // len=8, no value bytes
    rec.extend_from_slice(&7u32.to_be_bytes());
    rec.extend_from_slice(&[0xFFu8; 4]); // trailing so pos+8 < len
    let mut out = QuickTimeStreamMeta::new();
    process_mebx(&rec, &keys, None, None, &mut out);
    assert_eq!(out.mebx_samples().len(), 1, "empty value still emits a tag");
    assert_eq!(out.mebx_samples().first().unwrap().name(), "StillImageTime");
    assert_eq!(out.mebx_samples().first().unwrap().value(), "");
  }

  #[test]
  fn round_face_bounds_matches_perl_printconv() {
    // QuickTime.pm:6820 `int($_*1e6+.5)/1e6` per element. Perl `int` truncates
    // toward zero AFTER the `+.5`, so it is round-half-up toward +infinity, NOT
    // round-half-away-from-zero. The strings are the `%.15g` renders the
    // `float[8]` decode produces (f32 round-trip), verified byte-identical
    // against the bundled `exiftool` for the same inputs.
    assert_eq!(
      round_face_bounds("0.1 0.2 0.3 0.4 0.123456791043282 0.5 0.6 0.7"),
      "0.1 0.2 0.3 0.4 0.123457 0.5 0.6 0.7"
    );
    // Negative round direction: toward +infinity (NOT away from zero).
    assert_eq!(round_face_bounds("-3"), "-2.999999");
    assert_eq!(round_face_bounds("-7.25"), "-7.249999");
    assert_eq!(round_face_bounds("-2.34567856788635"), "-2.345678");
    assert_eq!(round_face_bounds("-0.123456500470638"), "-0.123456");
    // Rounds UP to an integer; trailing zeros stripped by `%g`.
    assert_eq!(round_face_bounds("1.99999952316284"), "2");
    assert_eq!(round_face_bounds("0.109999999403954"), "0.11");
    // A tiny negative rounds to "0" (Perl `int(-0.4999)` is 0).
    assert_eq!(round_face_bounds("-4.99999998737621e-07"), "0");
    // Already short / exact values pass through unchanged.
    assert_eq!(round_face_bounds("12.5"), "12.5");
    assert_eq!(round_face_bounds(""), "");
  }

  #[test]
  fn process_face_info_walks_nested_crec_cits_tree() {
    // `detected-face` value = FaceInfo MOV tree: crec -> cits -> mebx records
    // for the leaf keys, decoded against the SAME keys map. Two faces here.
    fn atom(typ: &[u8; 4], payload: &[u8]) -> alloc::vec::Vec<u8> {
      let mut v = ((8 + payload.len()) as u32).to_be_bytes().to_vec();
      v.extend_from_slice(typ);
      v.extend_from_slice(payload);
      v
    }
    fn rec(id: u32, val: &[u8]) -> alloc::vec::Vec<u8> {
      let mut v = ((8 + val.len()) as u32).to_be_bytes().to_vec();
      v.extend_from_slice(&id.to_be_bytes());
      v.extend_from_slice(val);
      v
    }
    let keys = alloc::vec![
      (
        2u32,
        MetaKey {
          tag_id: "detected-face.bounds".into(),
          format: MetaFormat::Float
        }
      ),
      (
        3u32,
        MetaKey {
          tag_id: "detected-face.face-id".into(),
          format: MetaFormat::Int32u
        }
      ),
      (
        4u32,
        MetaKey {
          tag_id: "detected-face.roll-angle".into(),
          format: MetaFormat::Float
        }
      ),
    ];
    // Build one face's cits content (bounds float[2] for brevity, face-id, roll).
    // `0.123_456_79` is the f32-representable value (the same bits the on-wire
    // `float[2]` carries); it still `%.15g`-renders to `0.123456791043282` and
    // rounds to `0.123457` (see `round_face_bounds_matches_perl_printconv`).
    let mut bounds = alloc::vec::Vec::new();
    bounds.extend_from_slice(&0.123_456_79_f32.to_be_bytes());
    bounds.extend_from_slice(&(-3.0_f32).to_be_bytes());
    let mut cits_content = rec(2, &bounds);
    cits_content.extend(rec(3, &1001u32.to_be_bytes()));
    cits_content.extend(rec(4, &12.5_f32.to_be_bytes()));
    let crec = atom(b"crec", &atom(b"cits", &cits_content));
    let value = crec; // single face

    let mut out = QuickTimeStreamMeta::new();
    process_face_info(&value, &keys, Some(0.0), Some(1.0), &mut out);
    let p = out.mebx_samples();
    assert_eq!(p.len(), 3, "three leaf keys for the one face");
    assert_eq!(p.first().unwrap().name(), "DetectedFaceBounds");
    // bounds: 0.123456789 rounds to 0.123457; -3 (float[2]) rounds to -2.999999.
    assert_eq!(p.first().unwrap().value(), "0.123457 -2.999999");
    assert_eq!(p.get(1).unwrap().name(), "DetectedFaceID");
    assert_eq!(p.get(1).unwrap().value(), "1001");
    assert_eq!(p.get(2).unwrap().name(), "DetectedFaceRollAngle");
    assert_eq!(p.get(2).unwrap().value(), "12.5"); // roll has no PrintConv
  }

  #[test]
  fn process_mebx_intercepts_detected_face_parent_as_subdir() {
    // A `detected-face` parent record (the nested FaceInfo tree) is routed
    // through `process_face_info`, NOT stored as a scalar `MebxSample`. The
    // outer key resolves to `detected-face`; its value is the crec/cits tree.
    fn atom(typ: &[u8; 4], payload: &[u8]) -> alloc::vec::Vec<u8> {
      let mut v = ((8 + payload.len()) as u32).to_be_bytes().to_vec();
      v.extend_from_slice(typ);
      v.extend_from_slice(payload);
      v
    }
    fn rec(id: u32, val: &[u8]) -> alloc::vec::Vec<u8> {
      let mut v = ((8 + val.len()) as u32).to_be_bytes().to_vec();
      v.extend_from_slice(&id.to_be_bytes());
      v.extend_from_slice(val);
      v
    }
    let keys = alloc::vec![
      (
        1u32,
        MetaKey {
          tag_id: "detected-face".into(),
          format: MetaFormat::Undef
        }
      ),
      (
        3u32,
        MetaKey {
          tag_id: "detected-face.face-id".into(),
          format: MetaFormat::Int32u
        }
      ),
    ];
    let cits_content = rec(3, &7u32.to_be_bytes());
    let face_tree = atom(b"crec", &atom(b"cits", &cits_content));
    // Outer mebx record: [len][local-id=1][face_tree].
    let outer = rec(1, &face_tree);
    let mut out = QuickTimeStreamMeta::new();
    process_mebx(&outer, &keys, Some(0.0), Some(1.0), &mut out);
    let p = out.mebx_samples();
    // ONLY the leaf is emitted — no `DetectedFace`/`FaceInfo` scalar for the
    // parent (the pre-fix branch wrongly emitted the raw tree bytes as a scalar).
    assert_eq!(p.len(), 1, "only the nested leaf, not the parent scalar");
    assert_eq!(p.first().unwrap().name(), "DetectedFaceID");
    assert_eq!(p.first().unwrap().value(), "7");
    assert!(
      p.iter()
        .all(|s| s.name() != "FaceInfo" && s.name() != "DetectedFace"),
      "the detected-face parent must not surface as a scalar"
    );
  }

  #[test]
  fn process_mebx_scene_illuminance_applies_unpack_n() {
    // scene-illuminance ⇒ ValueConv unpack("N",$val) over the raw undef bytes.
    let keys = alloc::vec![(
      1u32,
      MetaKey {
        tag_id: "scene-illuminance".into(),
        format: MetaFormat::Undef, // dtyp ns=1 ⇒ undef format
      },
    )];
    // [len=12][local-id=1][00 00 04 D2] = 1234.
    let mut rec = 12u32.to_be_bytes().to_vec();
    rec.extend_from_slice(&1u32.to_be_bytes());
    rec.extend_from_slice(&[0x00, 0x00, 0x04, 0xD2]);
    let mut out = QuickTimeStreamMeta::new();
    process_mebx(&rec, &keys, None, None, &mut out);
    assert_eq!(out.mebx_samples().len(), 1);
    assert_eq!(
      out.mebx_samples().first().unwrap().name(),
      "SceneIlluminance"
    );
    assert_eq!(out.mebx_samples().first().unwrap().value(), "1234");
  }

  #[test]
  fn convert_iso6709_shapes() {
    // QuickTime.pm:8884-8908 ConvertISO6709.
    // decimal degrees +DD.D+DDD.D[+AA.A].
    assert_eq!(convert_iso6709("+47.6284+122.1650"), "47.6284 122.165");
    assert_eq!(convert_iso6709("+47.6+122.2+10.5"), "47.6 122.2 10.5");
    // negative lat/lon.
    assert_eq!(convert_iso6709("-12.34-098.76"), "-12.34 -98.76");
    // degrees+minutes +DDMM.M+DDDMM.M (Perl %.15g).
    assert_eq!(
      convert_iso6709("+4737.7+12209.9"),
      "47.6283333333333 122.165"
    );
    // degrees+minutes+seconds +DDMMSS.S+DDDMMSS.S (Perl %.15g).
    assert_eq!(
      convert_iso6709("+473742.3+1220954.1"),
      "47.6284166666667 122.165027777778"
    );
    // unrecognised ⇒ unchanged.
    assert_eq!(convert_iso6709("not-a-coord"), "not-a-coord");
    // negative DM with altitude; the `0` zero case (all verified vs perl).
    assert_eq!(convert_iso6709("+0.0+0.0"), "0 0");
    assert_eq!(
      convert_iso6709("-4737.7-12209.9-50.5"),
      "-47.6283333333333 -122.165 -50.5"
    );
    // DMS without a fractional second (shape-3 path, no `.`).
    assert_eq!(
      convert_iso6709("+473742-1220954"),
      "47.6283333333333 -122.165"
    );
    // a value that matches no shape (lat run too long) ⇒ unchanged.
    assert_eq!(convert_iso6709("+90123456"), "+90123456");
  }

  #[test]
  fn kenwood_gps_decodes_le_record() {
    // one 36-byte LE record + a sibling so `pos + 36 < len`.
    let mut rec = Vec::new();
    rec.extend_from_slice(&1u32.to_le_bytes()); // a0
    rec.extend_from_slice(&1u32.to_le_bytes()); // a1
    rec.extend_from_slice(&100u32.to_le_bytes()); // secs
    rec.extend_from_slice(&5000u32.to_le_bytes()); // speed*1e3
    rec.push(b'N'); // ns
    rec.extend_from_slice(&4737705u32.to_le_bytes()); // lat*1e3 (4737.705)
    rec.push(b'W'); // ew
    rec.extend_from_slice(&12209901u32.to_le_bytes()); // lon*1e3 (12209.901)
    // 'VVVVaVaV' consumes 26 bytes; the record is a 36-byte slot ⇒ 10 pad.
    rec.extend_from_slice(&[0u8; 10]);
    assert_eq!(rec.len(), 36);
    let mut data = rec.clone();
    data.extend_from_slice(&[0xFFu8; 8]); // trailing bytes so pos+36 < len
    let mut out = QuickTimeStreamMeta::new();
    parse_kenwood_gps(&data, Some(QT_EPOCH_OFFSET as u64), &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = out.gps_samples().first().unwrap();
    // lat 4737.705 ⇒ 47.628..., positive (N).
    assert!(s.latitude().expect("lat") > 47.0 && s.latitude().expect("lat") < 48.0);
    // lon 12209.901 ⇒ 122.165..., negative (W).
    assert!(s.longitude().expect("lon") < -122.0);
    assert_eq!(s.speed_kph(), Some(5.0));
  }

  #[test]
  fn extract_stream_empty_for_plain_file() {
    // ftyp + moov(mvhd) — no metadata track ⇒ empty stream meta.
    let ftyp = atom(b"ftyp", b"qt  \0\0\0\0");
    let mvhd = atom(b"mvhd", &alloc::vec![0u8; 100]);
    let moov = atom(b"moov", &mvhd);
    let mut data = ftyp;
    data.extend_from_slice(&moov);
    let mut gp = crate::metadata::GoProMeta::new();
    let mut cm = crate::metadata::CammMeta::new();
    let (meta, found_embedded) = extract_stream(&data, None, None, &mut gp, &mut cm);
    assert!(meta.is_empty());
    // No `gps ` box ⇒ ProcessFreeGPS never ran ⇒ FoundEmbedded stays false.
    assert!(!found_embedded);
    assert!(gp.is_empty());
    assert!(cm.is_empty());
  }

  /// Codex R3 — the `moov`-level Novatek `gps ` box (the EMPTY-HandlerType box
  /// keyed by `%eeBox{''}{'gps '} = 'moov'`, QuickTime.pm:523-533, parsed by
  /// `ParseTag` at QuickTimeStream.pl:2544) is an OFFSET TABLE whose
  /// `(start, size)` pairs point at `freeGPS ` blocks ANYWHERE in the file.
  /// This exercises the XGODY 12" 4K Dashcam shape: the block lives OUTSIDE
  /// `mdat` (here there is no `mdat` at all — the block sits between `ftyp` and
  /// `moov`) and is reachable ONLY via the offset table. The block must decode.
  #[test]
  fn moov_gps_box_decodes_freegps_block_outside_mdat() {
    // A self-contained Type-6 (Akaso) freeGPS block (block-relative offsets).
    let mut blk = alloc::vec![0u8; 0x100];
    wr(&mut blk, 0, &0x0100u32.to_be_bytes());
    wr(&mut blk, 4, b"freeGPS ");
    wb(&mut blk, 60, b'A');
    wb(&mut blk, 68, b'N');
    wb(&mut blk, 76, b'W');
    wr(&mut blk, 0x30, &14u32.to_le_bytes());
    wr(&mut blk, 0x34, &30u32.to_le_bytes());
    wr(&mut blk, 0x38, &45u32.to_le_bytes());
    wr(&mut blk, 0x58, &2024u32.to_le_bytes());
    wr(&mut blk, 0x5c, &7u32.to_le_bytes());
    wr(&mut blk, 0x60, &15u32.to_le_bytes());
    wr(&mut blk, 0x40, &4737.7053f32.to_le_bytes());
    wr(&mut blk, 0x48, &12209.901f32.to_le_bytes());

    // Layout = ftyp || freeGPS-block || moov, so the block's ABSOLUTE file
    // offset is simply ftyp.len() — the offset-table `start` must point there.
    let ftyp = atom(b"ftyp", b"qt  \0\0\0\0");
    let block_offset = ftyp.len() as u32;

    // The `gps ` box PAYLOAD: [reserved:4=0][count:4=1] then one
    // (start, size) pair, all big-endian (QuickTime `'MM'` order).
    let mut gps_body = alloc::vec![0u8; 8];
    wr(&mut gps_body, 4, &1u32.to_be_bytes()); // count = 1
    gps_body.extend_from_slice(&block_offset.to_be_bytes()); // absolute start
    gps_body.extend_from_slice(&(blk.len() as u32).to_be_bytes()); // size
    let gps_box = atom(b"gps ", &gps_body);

    // moov = mvhd + the DIRECT-child `gps ` box (NOT inside a trak).
    let mvhd = atom(b"mvhd", &alloc::vec![0u8; 100]);
    let mut moov_body = mvhd;
    moov_body.extend_from_slice(&gps_box);
    let moov = atom(b"moov", &moov_body);

    let mut data = ftyp;
    data.extend_from_slice(&blk); // freeGPS block at offset = block_offset
    data.extend_from_slice(&moov);

    let mut gp = crate::metadata::GoProMeta::new();
    let mut cm = crate::metadata::CammMeta::new();
    let (meta, found_embedded) = extract_stream(&data, None, None, &mut gp, &mut cm);
    assert_eq!(
      meta.gps_samples().len(),
      1,
      "the moov-level gps ' offset table must decode the out-of-mdat block"
    );
    // The `gps `-box decode dispatched a freeGPS block ⇒ FoundEmbedded set
    // (this is exactly the signal that suppresses a redundant `mdat` scan).
    assert!(found_embedded);
    let s = meta.gps_samples().first().unwrap();
    assert!(s.has_coordinates());
    assert_eq!(s.date_time(), Some("2024:07:15 14:30:45Z"));
  }

  /// Codex R3 (negative) — a real `trak` whose `hdlr` HandlerType is `gps `
  /// is IGNORED for embedded GPS: ExifTool has no `$eeBox{'gps '}` entry (only
  /// the EMPTY-HandlerType `moov`-level box, QuickTime.pm:523-533). Even with a
  /// fully-formed `gps `-handler sample table pointing at a real `freeGPS `
  /// block, `extract_stream` must produce NO samples (the block is reached
  /// only by the brute-force `mdat` scan, which runs separately — see the
  /// pipeline-level test in `quicktime.rs`).
  #[test]
  fn gps_handler_track_is_ignored() {
    let mut blk = alloc::vec![0u8; 0x100];
    wr(&mut blk, 0, &0x0100u32.to_be_bytes());
    wr(&mut blk, 4, b"freeGPS ");
    wb(&mut blk, 60, b'A');
    wb(&mut blk, 68, b'N');
    wb(&mut blk, 76, b'W');
    wr(&mut blk, 0x40, &4737.7053f32.to_le_bytes());
    wr(&mut blk, 0x48, &12209.901f32.to_le_bytes());

    let ftyp = atom(b"ftyp", b"qt  \0\0\0\0");
    let block_offset = ftyp.len() as u32;

    // hdlr: [version+flags:4][component-type:4][handler-subtype:4='gps ']…
    let mut hdlr_body = alloc::vec![0u8; 24];
    wr(&mut hdlr_body, 8, b"gps ");
    let hdlr = atom(b"hdlr", &hdlr_body);

    let mut mdhd_body = alloc::vec![0u8; 24];
    wr(&mut mdhd_body, 12, &1000u32.to_be_bytes());
    let mdhd = atom(b"mdhd", &mdhd_body);

    let mut stsd_body = alloc::vec![0u8; 8];
    wr(&mut stsd_body, 4, &1u32.to_be_bytes());
    let mut entry = alloc::vec![0u8; 16];
    wr(&mut entry, 0, &16u32.to_be_bytes());
    wr(&mut entry, 4, b"gps ");
    stsd_body.extend_from_slice(&entry);
    let stsd = atom(b"stsd", &stsd_body);

    let mut stco_body = alloc::vec![0u8; 8];
    wr(&mut stco_body, 4, &1u32.to_be_bytes());
    stco_body.extend_from_slice(&block_offset.to_be_bytes());
    let stco = atom(b"stco", &stco_body);

    let mut stsc_body = alloc::vec![0u8; 8];
    wr(&mut stsc_body, 4, &1u32.to_be_bytes());
    stsc_body.extend_from_slice(&1u32.to_be_bytes());
    stsc_body.extend_from_slice(&1u32.to_be_bytes());
    stsc_body.extend_from_slice(&1u32.to_be_bytes());
    let stsc = atom(b"stsc", &stsc_body);

    let mut stsz_body = alloc::vec![0u8; 8];
    wr(&mut stsz_body, 4, &0u32.to_be_bytes());
    stsz_body.extend_from_slice(&1u32.to_be_bytes());
    stsz_body.extend_from_slice(&(blk.len() as u32).to_be_bytes());
    let stsz = atom(b"stsz", &stsz_body);

    let mut stbl_body = stsd;
    stbl_body.extend_from_slice(&stco);
    stbl_body.extend_from_slice(&stsc);
    stbl_body.extend_from_slice(&stsz);
    let stbl = atom(b"stbl", &stbl_body);
    let minf = atom(b"minf", &stbl);
    let mut mdia_body = mdhd;
    mdia_body.extend_from_slice(&hdlr);
    mdia_body.extend_from_slice(&minf);
    let mdia = atom(b"mdia", &mdia_body);
    let trak = atom(b"trak", &mdia);
    let mvhd = atom(b"mvhd", &alloc::vec![0u8; 100]);
    let mut moov_body = mvhd;
    moov_body.extend_from_slice(&trak);
    let moov = atom(b"moov", &moov_body);

    let mut data = ftyp;
    data.extend_from_slice(&blk);
    data.extend_from_slice(&moov);

    let mut gp = crate::metadata::GoProMeta::new();
    let mut cm = crate::metadata::CammMeta::new();
    let (meta, found_embedded) = extract_stream(&data, None, None, &mut gp, &mut cm);
    assert!(
      meta.is_empty(),
      "a gps '-HandlerType trak must yield no embedded GPS (ExifTool ignores it)"
    );
    // The track is ignored ⇒ ProcessFreeGPS never ran ⇒ FoundEmbedded stays
    // false ⇒ the brute-force `mdat` scan is NOT suppressed (it runs at the
    // pipeline level — see `gps_handler_track_does_not_suppress_mdat_scan`).
    assert!(!found_embedded);
  }

  // NOTE: the Type-19 (70mai A810) SampleTime → `GPSDateTime` threading is
  // unit-tested directly against `process_free_gps` in
  // `quicktime_freegps::tests::decode_type19_70mai_synthesizes_gps_date_time_from_sample_time`.
  // It is NOT reachable via a `moov`-level `gps ` box (that box carries no
  // `stts`, so its `SampleTime` is `None` — see `process_moov_gps_box`) nor via
  // a `gps `-HandlerType track (which ExifTool ignores — see
  // `gps_handler_track_is_ignored`).

  #[test]
  fn process_gps0_skips_out_of_range_and_decodes() {
    // one valid 32-byte LE record.
    let mut rec = alloc::vec![0u8; 32];
    wr(&mut rec, 0, &4737.7053f64.to_le_bytes()); // lat DDDMM.MMMM
    wr(&mut rec, 8, &12209.901f64.to_le_bytes()); // lon
    wr(&mut rec, 0x10, &123i32.to_le_bytes()); // altitude
    wr(&mut rec, 0x14, &60u16.to_le_bytes()); // speed
    wr(&mut rec, 0x16, &[24, 1, 7, 11, 19, 14]); // y m d H M S
    wb(&mut rec, 0x1c, 30); // track/2
    let mut out = QuickTimeStreamMeta::new();
    process_gps0(&rec, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = out.gps_samples().first().unwrap();
    assert_eq!(s.altitude_m(), Some(123.0));
    assert_eq!(s.speed_kph(), Some(60.0));
    assert_eq!(s.track(), Some(60.0)); // 30 * 2
    assert_eq!(s.date_time(), Some("2024:01:07 11:19:14Z"));
  }
}
