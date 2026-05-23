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

extern crate alloc;
use alloc::{
  string::{String, ToString},
  vec::Vec,
};

use crate::{
  datetime::{convert_datetime, convert_unix_time},
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
  b.get(off..off + 2)
    .map(|s| u16::from_be_bytes([s[0], s[1]]))
}

fn be_u32(b: &[u8], off: usize) -> Option<u32> {
  b.get(off..off + 4)
    .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn be_u64(b: &[u8], off: usize) -> Option<u64> {
  b.get(off..off + 8)
    .map(|s| u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

fn be_i16(b: &[u8], off: usize) -> Option<i16> {
  be_u16(b, off).map(|v| v as i16)
}

fn be_i32(b: &[u8], off: usize) -> Option<i32> {
  be_u32(b, off).map(|v| v as i32)
}

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

/// Read a big-endian IEEE-754 `double` (used by `gps0` lat/lon, which is a
/// little-endian record — see [`process_gps0`]).
fn le_f64(b: &[u8], off: usize) -> Option<f64> {
  b.get(off..off + 8)
    .map(|s| f64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
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
  let create = create_date_raw?;
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
    let rec = &data[pos..pos + 36];
    // QuickTimeStream.pl:2563 `last if $dat eq "\x0" x 36`.
    if rec.iter().all(|&b| b == 0) {
      break;
    }
    // 'VVVVaVaV' — little-endian: a[0..4) = int32u, a[4]=char, a[5]=int32u,
    // a[6]=char, a[7]=int32u.
    let secs = le_u32(rec, 8).unwrap_or(0);
    let speed = le_u32(rec, 12).unwrap_or(0);
    let ns = rec[16];
    let lat_raw = le_u32(rec, 17).unwrap_or(0);
    let ew = rec[21];
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
  if ee.stts.len() > 1 {
    time = Some(0);
    time_count = ee.stts[0];
    time_delta = ee.stts[1];
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
    if i_chunk >= next_chunk && stsc_idx < ee.stsc.len() {
      let (_first, spc, _desc) = ee.stsc[stsc_idx];
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
          if ee.stts.len() < stts_idx + 2 {
            // QuickTimeStream.pl:1367-1369 `undef $time; last Sample`.
            time = None;
            stopped = true;
            break;
          }
          time_count = ee.stts[stts_idx];
          time_delta = ee.stts[stts_idx + 1];
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
  /// The resolved tag NAME (`keyd` value, namespace-stripped + camel-cased).
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
      let tag = &data[pos + 4..pos + 8];
      let val = &data[pos + 8..pos + len];
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
    if let Some((_, info)) = keys.iter().find(|(k, _)| *k == id) {
      // QuickTimeStream.pl:2668 `ReadValue($dataPt, $pos+8, $format, .., $len-8)`.
      let value_bytes = &data[pos + 8..pos + len];
      if let Some(value) = read_meta_value(value_bytes, info.format) {
        out.push_mebx_sample(MebxSample::new(
          info.tag_id.clone(),
          value,
          sample_time,
          sample_duration,
        ));
      }
    }
    pos += len;
  }
}

/// `ReadValue` for a `mebx` value (QuickTimeStream.pl:2668) — render the
/// `qtFmt`-typed bytes to the displayed string. `mebx` values are big-endian
/// (the movie byte order). Multi-element values join with a space, matching
/// ExifTool's list rendering.
fn read_meta_value(bytes: &[u8], format: MetaFormat) -> Option<String> {
  if bytes.is_empty() {
    return None;
  }
  match format {
    MetaFormat::Str => Some(
      // Trim the trailing NUL ExifTool's string ReadValue drops.
      String::from_utf8_lossy(bytes)
        .trim_end_matches('\0')
        .to_string(),
    ),
    MetaFormat::Undef => {
      // ExifTool renders an `undef` ReadValue as the raw byte string; for a
      // printable run keep it, else hex — but `mebx` `undef` values are rare
      // and not GPS-bearing, so the lossless UTF-8-lossy rendering suffices.
      Some(
        String::from_utf8_lossy(bytes)
          .trim_end_matches('\0')
          .to_string(),
      )
    }
    MetaFormat::Int8u => Some(bytes[0].to_string()),
    MetaFormat::Int8s => Some((bytes[0] as i8).to_string()),
    MetaFormat::Int16u => be_u16(bytes, 0).map(|v| v.to_string()),
    MetaFormat::Int16s => be_i16(bytes, 0).map(|v| v.to_string()),
    MetaFormat::Int32u => be_u32(bytes, 0).map(|v| v.to_string()),
    MetaFormat::Int32s => be_i32(bytes, 0).map(|v| v.to_string()),
    MetaFormat::Int64u => be_u64(bytes, 0).map(|v| v.to_string()),
    MetaFormat::Int64s => be_u64(bytes, 0).map(|v| (v as i64).to_string()),
    MetaFormat::Float => bytes.get(0..4).map(|s| {
      let f = f32::from_be_bytes([s[0], s[1], s[2], s[3]]);
      crate::value::format_g(f64::from(f), 15)
    }),
    MetaFormat::Double => bytes.get(0..8).map(|s| {
      let f = f64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]);
      crate::value::format_g(f, 15)
    }),
  }
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
  if data.len() >= 8 && &data[2..8] == b"\xf2\xe1\xf0\xeeTT" {
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
    let dt = data.get(pos + 0x16..pos + 0x1c);
    let date_time = dt.map(|d| {
      alloc::format!(
        "{:04}:{:02}:{:02} {:02}:{:02}:{:02}Z",
        u32::from(d[0]) + 2000,
        d[1],
        d[2],
        d[3],
        d[4],
        d[5]
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
    let x = f64::from(data[pos] as i8) / 16.0;
    let y = f64::from(data[pos + 1] as i8) / 16.0;
    let z = f64::from(data[pos + 2] as i8) / 16.0;
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
/// `data` is the WHOLE file slice (sample offsets are absolute file offsets);
/// `create_date_raw` is the movie `mvhd` CreateDate (raw 1904-epoch seconds)
/// for `GPSDateTime` synthesis.
///
/// Only the self-contained sample formats are decoded here; an unrecognized
/// or deferred `MetaFormat` simply yields no samples (faithful: ExifTool
/// `VPrint`s "Unknown $type format" and moves on, QuickTimeStream.pl:1547).
fn process_samples(
  data: &[u8],
  track: &StreamTrack,
  create_date_raw: Option<u64>,
  out: &mut QuickTimeStreamMeta,
) {
  let samples = match expand_samples(&track.ee, track.media_ts) {
    Some(s) => s,
    None => return,
  };
  // QuickTimeStream.pl:1418 `for ($i=0; $i<@$start and $i<@$size; ++$i)`.
  for sample in &samples {
    let start = sample.start as usize;
    let size = sample.size as usize;
    let Some(buff) = data.get(start..start.saturating_add(size)) else {
      // QuickTimeStream.pl:1436-1443 — a seek/read past EOF warns + `next`s.
      continue;
    };
    if buff.is_empty() {
      continue;
    }
    decode_one_sample(buff, track, sample, create_date_raw, out);
  }
}

/// Decode a single timed sample's bytes by `HandlerType` / `MetaFormat` —
/// the dispatch arms of QuickTimeStream.pl:1467-1578.
fn decode_one_sample(
  buff: &[u8],
  track: &StreamTrack,
  sample: &Sample,
  create_date_raw: Option<u64>,
  out: &mut QuickTimeStreamMeta,
) {
  // The `mebx` MetaFormat (QuickTimeStream.pl:174-180) — Apple timed
  // metadata via the `keys` table. `FoundSomething` records the per-`Doc<N>`
  // SampleTime/SampleDuration; the decoded `mebx` pairs carry both.
  if &track.meta_format == b"mebx" {
    process_mebx(buff, &track.meta_keys, sample.time, sample.dur, out);
    return;
  }
  // `gpmd` GoPro / Sony `rtmd` / Canon `CTMD` / full `camm` / `tx3g` / …:
  // DEFERRED — these re-dispatch into other ExifTool modules (GoPro.pm,
  // Sony.pm, Canon.pm) or the 850-line ProcessFreeGPS. See module docs +
  // docs/tracking.md. An unrecognized MetaFormat yields no samples, exactly
  // as ExifTool's "Unknown $type format" branch (QuickTimeStream.pl:1547).
  let _ = (buff, create_date_raw, &track.handler);
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
  let size32 = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
  let mut t = [0u8; 4];
  t.copy_from_slice(&data[pos + 4..pos + 8]);
  let (start, end, next) = if size32 == 1 {
    if pos + 16 > data.len() {
      return None;
    }
    let ext = u64::from_be_bytes([
      data[pos + 8],
      data[pos + 9],
      data[pos + 10],
      data[pos + 11],
      data[pos + 12],
      data[pos + 13],
      data[pos + 14],
      data[pos + 15],
    ]);
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
    if ps <= pe {
      f(&t, &data[ps..pe]);
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
  let mut fmt = [0u8; 4];
  fmt.copy_from_slice(&data[pos + 4..pos + 8]);
  track.meta_format = fmt;
  // Child atoms follow the 16-byte SampleDescription header. Scan for
  // `keys` (the `mebx` metadata-key table).
  let entry_end = pos + size;
  for_each_atom(data, pos + 16, entry_end, |t, body| {
    if t == b"keys" {
      // The `keys` box body is itself `[version+flags:4][count:4]` then the
      // key-entry table — `SaveMetaKeys` skips the 8-byte header.
      if body.len() > 8 {
        track.meta_keys = save_meta_keys(&body[8..]);
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
/// Walks `moov`→`trak` collecting each metadata track's sample tables, then
/// runs [`process_samples`] per track. Also handles the magic `moov`-level
/// `gps `/`GPS ` boxes (QuickTimeStream.pl `ParseTag`, the
/// no-handler `''` entry of `%eeBox`).
///
/// `create_date_raw` is the `mvhd` CreateDate as raw 1904-epoch seconds
/// (needed for `GPSDateTime` synthesis); `None` when no `mvhd` carried one.
///
/// Returns an empty [`QuickTimeStreamMeta`] for the common case of a video
/// with no timed metadata (or only deferred-format metadata).
#[must_use]
pub(crate) fn extract_stream(data: &[u8], create_date_raw: Option<u64>) -> QuickTimeStreamMeta {
  let mut out = QuickTimeStreamMeta::new();
  // Walk the TOP-LEVEL atoms. `moov` carries the metadata `trak`s + the
  // `moov`-level `gps ` box; the `gps0`/`gsen`/`GPS ` magic boxes are
  // TOP-LEVEL siblings (`%QuickTime::Main` table / `%eeBox` `'GPS ' =>
  // 'main'`, QuickTime.pm:524-533, 932-943).
  let mut pos = 0usize;
  while pos < data.len() {
    let Some((t, ps, pe, next)) = atom_at(data, pos) else {
      break;
    };
    let body_end = pe.min(data.len());
    match &t {
      b"moov" => walk_moov(data, ps, body_end, create_date_raw, &mut out),
      // Top-level DuDuBell / VSYS `gps0` (32-byte LE binary GPS records).
      b"gps0" => process_gps0(&data[ps..body_end], &mut out),
      // Top-level DuDuBell / VSYS `gsen` (3-byte accelerometer triples).
      b"gsen" => process_gsen(&data[ps..body_end], &mut out),
      // Top-level Kenwood `GPS ` (36-byte LE inline GPS records).
      b"GPS " => parse_kenwood_gps(&data[ps..body_end], create_date_raw, &mut out),
      // Pittasoft BlackVue `3gf ` accelerometer (QuickTimeStream.pl
      // `Process_3gf`:2686-2708). ExifTool routes this via the
      // `%QuickTime::Pittasoft` parent table (an SP4 brand-variant); SP3
      // decodes a `3gf ` box wherever it appears in the atoms it walks.
      b"3gf " => process_3gf(&data[ps..body_end], &mut out),
      _ => {}
    }
    if next <= pos {
      break;
    }
    pos = next;
  }
  out
}

/// Walk one `moov`: process each `trak`'s timed metadata and the magic
/// `moov`-level `gps `/`GPS ` boxes.
fn walk_moov(
  data: &[u8],
  start: usize,
  end: usize,
  create_date_raw: Option<u64>,
  out: &mut QuickTimeStreamMeta,
) {
  for_each_atom(data, start, end, |t, body| {
    let base = body.as_ptr() as usize - data.as_ptr() as usize;
    match t {
      b"trak" => {
        let track = walk_trak(data, base, base + body.len());
        // Only metadata-bearing handlers feed `ProcessSamples`
        // (QuickTimeStream.pl:1315-1331 — `vide`/`soun` are hash-only).
        if is_meta_handler(&track.handler) {
          process_samples(data, &track, create_date_raw, out);
        }
      }
      // The `moov`-level Novatek `gps ` box (`%eeBox` `'gps ' => 'moov'`,
      // QuickTime.pm:533) is a directory table of offsets into `mdat`
      // pointing at `freeGPS ` blocks. DEFERRED: decoding those blocks needs
      // `ProcessFreeGPS` (QuickTimeStream.pl:1637-2488, ~850 lines, 40+
      // camera variants) — see the module docs + docs/tracking.md. The
      // `GPS ` box is a TOP-LEVEL `main` sibling and IS decoded (it carries
      // its records inline) — handled by [`extract_stream`].
      b"gps " => {
        let _ = create_date_raw; // DEFERRED: freeGPS sample decode.
      }
      _ => {}
    }
  });
}

/// `true` when a `hdlr` HandlerType feeds the timed-metadata path — `meta`
/// / `data` / `sbtl` (QuickTimeStream.pl `%processByMetaFormat`:78-83 and the
/// `%eeBox` handler keys:524-533). `vide` / `soun` are excluded (those are
/// the hash-only path, QuickTimeStream.pl:1316-1331).
fn is_meta_handler(h: &[u8; 4]) -> bool {
  matches!(h, b"meta" | b"data" | b"sbtl" | b"text" | b"camm" | b"ctbx")
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  fn atom(t: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut v = ((body.len() + 8) as u32).to_be_bytes().to_vec();
    v.extend_from_slice(t);
    v.extend_from_slice(body);
    v
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
  fn stsz_uniform_and_explicit() {
    // explicit (sz==0): version/flags + sz=0 + count=2 + two int32u sizes.
    let mut d = alloc::vec![0u8; 12];
    d[8..12].copy_from_slice(&2u32.to_be_bytes());
    d.extend_from_slice(&100u32.to_be_bytes());
    d.extend_from_slice(&200u32.to_be_bytes());
    let mut ee = EeData::default();
    parse_stsz(b"stsz", &d, &mut ee);
    assert_eq!(ee.size, alloc::vec![100, 200]);
    // uniform (sz!=0): sz=64, count=3 ⇒ [64,64,64].
    let mut u = alloc::vec![0u8; 12];
    u[4..8].copy_from_slice(&64u32.to_be_bytes());
    u[8..12].copy_from_slice(&3u32.to_be_bytes());
    u.push(0); // need length > 12
    let mut ee2 = EeData::default();
    parse_stsz(b"stsz", &u, &mut ee2);
    assert_eq!(ee2.size, alloc::vec![64, 64, 64]);
  }

  #[test]
  fn stsc_requires_full_table() {
    // count=1 but no entry bytes ⇒ rejected (faithful: 8 + num*12 check).
    let mut short = alloc::vec![0u8; 8];
    short[4..8].copy_from_slice(&1u32.to_be_bytes());
    short.push(0); // length > 8
    let mut ee = EeData::default();
    parse_stsc(&short, &mut ee);
    assert!(ee.stsc.is_empty());
    // a complete entry decodes.
    let mut full = alloc::vec![0u8; 8];
    full[4..8].copy_from_slice(&1u32.to_be_bytes());
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
    assert_eq!(samples[0].start, 1000);
    assert_eq!(samples[0].size, 42);
    // time 0, dur 600/600 = 1.0s.
    assert_eq!(samples[0].time, Some(0.0));
    assert_eq!(samples[0].dur, Some(1.0));
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
    let s = &out.gps_samples()[0];
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
    assert_eq!(out.gps_samples()[0].accelerometer(), Some("1 -2 3"));
    assert_eq!(out.gps_samples()[1].accelerometer(), Some("0.5 0 0"));
  }

  #[test]
  fn synth_gps_date_time_needs_create_date() {
    assert_eq!(synth_gps_date_time(None, Some(1.0)), None);
    assert_eq!(synth_gps_date_time(Some(123), None), None);
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
    assert_eq!(keys[0].0, 1);
    assert_eq!(keys[0].1.tag_id, "Foo");
    assert_eq!(keys[0].1.format, MetaFormat::Int32u);
  }

  #[test]
  fn process_mebx_decodes_int_value() {
    let keys = alloc::vec![(
      1u32,
      MetaKey {
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
    assert_eq!(out.mebx_samples()[0].name(), "GPSCoordinates");
    assert_eq!(out.mebx_samples()[0].value(), "123456");
    assert_eq!(out.mebx_samples()[0].sample_duration(), Some(1.0));
    assert_eq!(out.mebx_samples()[0].sample_time(), Some(0.5));
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
    let s = &out.gps_samples()[0];
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
    let meta = extract_stream(&data, None);
    assert!(meta.is_empty());
  }

  #[test]
  fn process_gps0_skips_out_of_range_and_decodes() {
    // one valid 32-byte LE record.
    let mut rec = alloc::vec![0u8; 32];
    rec[0..8].copy_from_slice(&4737.7053f64.to_le_bytes()); // lat DDDMM.MMMM
    rec[8..16].copy_from_slice(&12209.901f64.to_le_bytes()); // lon
    rec[0x10..0x14].copy_from_slice(&123i32.to_le_bytes()); // altitude
    rec[0x14..0x16].copy_from_slice(&60u16.to_le_bytes()); // speed
    rec[0x16..0x1c].copy_from_slice(&[24, 1, 7, 11, 19, 14]); // y m d H M S
    rec[0x1c] = 30; // track/2
    let mut out = QuickTimeStreamMeta::new();
    process_gps0(&rec, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = &out.gps_samples()[0];
    assert_eq!(s.altitude_m(), Some(123.0));
    assert_eq!(s.speed_kph(), Some(60.0));
    assert_eq!(s.track(), Some(60.0)); // 30 * 2
    assert_eq!(s.date_time(), Some("2024:01:07 11:19:14Z"));
  }
}
