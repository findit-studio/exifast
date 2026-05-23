// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "quicktime")]
//! Faithful port of `Image::ExifTool::QuickTimeStream::ProcessInsta360`
//! (QuickTimeStream.pl:3252-3478) — the Insta360 trailer walker. Backed
//! by the `%insvDataLen` record-length catalogue (QuickTimeStream.pl:85-
//! 99), the `INSV_MakerNotes` identity table (QuickTimeStream.pl:696-707),
//! and the `QuickTime::Stream` GPS/Exposure tags (QuickTimeStream.pl
//! :107-169).
//!
//! ## Trailer locator
//!
//! The trailer is identified by `IdentifyTrailers` in QuickTime.pm:9897-
//! 9926: read 40 bytes from `EOF - 40`, the last 32 bytes must be the
//! ASCII string `"8db42d694ccc418790edff439fe026bf"` (Insta360's signature
//! UUID); the first 4 bytes are the LE u32 trailer length. (Multiple
//! trailers can chain — this walker only handles one.)
//!
//! `ProcessInsta360` then re-reads 78 bytes from `EOF - 78` and walks
//! backwards from the LAST record to the FIRST, using the 6-byte
//! `[id:u16-LE][len:u32-LE]` footer of each record to step. If a
//! directory-table record (id `0x000`) is encountered, the walker
//! switches to forward-by-index dispatch (QuickTimeStream.pl:3437-3469).
//!
//! ## Per-record-type dispatch
//!
//! `%insvDataLen` (QuickTimeStream.pl:85-99) keys length-per-row to
//! record id; QuickTimeStream.pl:3326-3346 expands the zero-length
//! placeholders. The decoders ported here are the camera-indexing
//! priorities:
//!
//!  - **`0x101` Identity** (QuickTimeStream.pl:3427-3436). NOT in
//!    `%insvDataLen` — the walker reaches it via the `} elsif ($id ==
//!    0x101)` fork. The record body is a sequence of `[tag:u8]
//!    [len:u8][value:len bytes]` items; the first 4 items are surfaced
//!    via the `INSV_MakerNotes` table (`0x0a SerialNumber`, `0x12 Model`,
//!    `0x1a Firmware`, `0x2a Parameters`).
//!  - **`0x700` GPS** (QuickTimeStream.pl:3397-3425). 53-byte rows;
//!    each `status == 'A'` row yields one [`Insta360GpsSample`].
//!  - **`0x400` Exposure** (QuickTimeStream.pl:3386-3391). 16-byte rows;
//!    each row yields one [`Insta360ExposureSample`].
//!
//! Other record types are walked (so the loop-shape is faithful) but
//! their values are discarded — see the metadata module's preamble for
//! the FOLLOW-UP list.
//!
//! ## Endianness
//!
//! `ProcessInsta360` opens with `SetByteOrder('II')` (QuickTimeStream.pl
//! :3308) — every multi-byte int in the trailer is little-endian.
//!
//! ## GPS priority chain
//!
//! Insta360 trailer GPS feeds the **FOURTH tier** of the cross-port GPS
//! priority chain that [`crate::metadata::MediaMetadata`] projects from a
//! QuickTime file: GoPro GPMF → Android CAMM → Sony rtmd → Insta360
//! trailer → Parrot mett → SP3 stream. Insta360 GPS is phone-paired via
//! the Insta360 Studio app — same fidelity tier as Sony rtmd; ordered
//! after Sony because Sony's `GPSStatus 'A'/'V'` flag is explicit while
//! Insta360 only ever surfaces `'A'` (active fix) rows.

extern crate alloc;
use alloc::vec::Vec;

use smol_str::SmolStr;

use crate::metadata::{Insta360ExposureSample, Insta360GpsSample, Insta360Identity, Insta360Meta};

// ===========================================================================
// Trailer signature (QuickTime.pm:9904)
// ===========================================================================

/// The 32-byte ASCII hex string that identifies an Insta360 trailer
/// (QuickTime.pm:9904 + QuickTimeStream.pl:3271). It's a `&str` because
/// the bundled `eq` compares the bytes as a textual hex string, NOT
/// the underlying 16 raw UUID bytes.
pub(crate) const MAGIC: &[u8; 32] = b"8db42d694ccc418790edff439fe026bf";

/// Trailer total-length offset within the 78-byte footer
/// (QuickTimeStream.pl:3276 `unpack('x38V', $buff)`).
const TRAILER_LEN_OFFSET: usize = 38;

/// Total footer size read by `ProcessInsta360`
/// (QuickTimeStream.pl:3270 `$raf->Read($buff, 78)`).
const FOOTER_SIZE: usize = 78;

/// Per-record 6-byte footer = `[id:u16-LE][len:u32-LE]`
/// (QuickTimeStream.pl:3311 `unpack('vV', $buff)`).
const RECORD_FOOTER_SIZE: usize = 6;

// ===========================================================================
// Record IDs (QuickTimeStream.pl:85-99 + 3326-3453)
// ===========================================================================

const ID_DIRECTORY_TABLE: u16 = 0x000;
const ID_IDENTITY: u16 = 0x101;
/// PreviewImage / PreviewTIFF (QuickTimeStream.pl:3358-3371). Walked
/// but not surfaced — heavy + low indexing value (FOLLOW-UP).
#[allow(dead_code)]
const ID_PREVIEW_IMAGE: u16 = 0x200;
const ID_ACCELEROMETER: u16 = 0x300;
const ID_EXPOSURE: u16 = 0x400;
/// VideoTimeStamp (QuickTimeStream.pl:3392-3396). Walked but not
/// surfaced — telemetry-only (FOLLOW-UP, mirrors GoPro #58).
#[allow(dead_code)]
const ID_VIDEO_TIMESTAMP: u16 = 0x600;
const ID_GPS: u16 = 0x700;

// ===========================================================================
// INSV_MakerNotes identity tags (QuickTimeStream.pl:696-707)
// ===========================================================================

const TAG_SERIAL_NUMBER: u8 = 0x0a;
const TAG_MODEL: u8 = 0x12;
const TAG_FIRMWARE: u8 = 0x1a;
const TAG_PARAMETERS: u8 = 0x2a;

// ===========================================================================
// `%insvLimit` defaults — `0x300` accelerometer cap
// (QuickTimeStream.pl:103-105: cap of 20000 records)
// ===========================================================================

/// Maximum 0x300 records we walk before truncating — matches bundled's
/// `%insvLimit` (QuickTimeStream.pl:103-105).
const INSV_LIMIT_0X300: u64 = 20000;

// ===========================================================================
// Little-endian readers
// ===========================================================================

#[inline]
fn le_u16(b: &[u8], off: usize) -> Option<u16> {
  b.get(off..off + 2)
    .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

#[inline]
fn le_u32(b: &[u8], off: usize) -> Option<u32> {
  b.get(off..off + 4)
    .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[inline]
fn le_u64(b: &[u8], off: usize) -> Option<u64> {
  b.get(off..off + 8)
    .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

#[inline]
fn le_f64(b: &[u8], off: usize) -> Option<f64> {
  le_u64(b, off).map(f64::from_bits)
}

// ===========================================================================
// Trailer signature detection
// ===========================================================================

/// `true` when `data` ends with an Insta360 trailer (last 32 bytes match
/// the magic ASCII hex). Faithful per `IdentifyTrailers`
/// (QuickTime.pm:9903-9905) — bundled reads 40 bytes from `EOF-40`, but
/// the actual signature check `eq` is on the LAST 32 bytes of that
/// buffer (`substr($buff, 8) eq '...'`); equivalent to "the file's last
/// 32 bytes are the magic".
#[must_use]
pub fn has_trailer(data: &[u8]) -> bool {
  if data.len() < MAGIC.len() {
    return false;
  }
  &data[data.len() - MAGIC.len()..] == MAGIC.as_slice()
}

/// Parse the trailer-length field from the 78-byte footer. Returns
/// `Some(trailer_len)` when the signature matches and the field
/// decodes. Faithful per QuickTimeStream.pl:3270-3276.
fn read_trailer_len(data: &[u8]) -> Option<u32> {
  if data.len() < FOOTER_SIZE {
    return None;
  }
  let footer_start = data.len() - FOOTER_SIZE;
  let footer = &data[footer_start..];
  // QuickTimeStream.pl:3271 `substr($buff,-32) eq '...'`.
  if &footer[footer.len() - MAGIC.len()..] != MAGIC.as_slice() {
    return None;
  }
  // QuickTimeStream.pl:3276 `unpack('x38V', $buff)`.
  le_u32(footer, TRAILER_LEN_OFFSET)
}

// ===========================================================================
// Per-record decoders
// ===========================================================================

/// Decode one 0x101 INSV_MakerNotes identity record
/// (QuickTimeStream.pl:3427-3436). The record body is a sequence of
/// `[tag:u8][len:u8][value:len bytes]` items; the bundled loop walks at
/// most 4 items.
fn decode_identity(buff: &[u8]) -> Insta360Identity {
  let mut out = Insta360Identity::new();
  let mut p = 0usize;
  // Bundled: `for ($i=0, $p=0; $i<4; ++$i) { ... }`. Walk up to 4 items.
  for _ in 0..4 {
    if p + 2 > buff.len() {
      break;
    }
    let t = buff[p];
    let n = buff[p + 1] as usize;
    if p + 2 + n > buff.len() {
      break;
    }
    let val = &buff[p + 2..p + 2 + n];
    // QuickTimeStream.pl:3434 `$et->HandleTag($tagTablePtr, $t, $val)`.
    match t {
      TAG_SERIAL_NUMBER => {
        out.set_serial_number(Some(SmolStr::new(core::str::from_utf8(val).unwrap_or(""))));
      }
      TAG_MODEL => {
        out.set_model(Some(SmolStr::new(core::str::from_utf8(val).unwrap_or(""))));
      }
      TAG_FIRMWARE => {
        out.set_firmware(Some(SmolStr::new(core::str::from_utf8(val).unwrap_or(""))));
      }
      TAG_PARAMETERS => {
        // QuickTimeStream.pl:705 `ValueConv => '$val =~ tr/_/ /; $val'`.
        let s = core::str::from_utf8(val).unwrap_or("");
        out.set_parameters(Some(SmolStr::new(s.replace('_', " "))));
      }
      _ => {} // Unknown tag; bundled HandleTag with no-table-entry is a no-op.
    }
    p += 2 + n;
  }
  out
}

/// Decode one 0x400 exposure record row (QuickTimeStream.pl:3386-3391).
/// Each row is 16 bytes `[timestamp_ms:u64-LE][exposure_time_s:double-LE]`.
fn decode_exposure_row(row: &[u8]) -> Option<Insta360ExposureSample> {
  if row.len() < 16 {
    return None;
  }
  let mut s = Insta360ExposureSample::new();
  if let Some(ts) = le_u64(row, 0) {
    s.set_timestamp_ms(Some(ts));
  }
  if let Some(et) = le_f64(row, 8) {
    s.set_exposure_time_s(Some(et));
  }
  Some(s)
}

/// Decode one 0x700 GPS record row (QuickTimeStream.pl:3397-3425).
/// Returns `None` for void fixes (status `'V'`) or unrecognized NS/EW
/// chars (the latter is the bundled `Unrecognized INSV GPS format`
/// warning — return that to the caller).
fn decode_gps_row(row: &[u8]) -> Result<Option<Insta360GpsSample>, &'static str> {
  // unpack('VVvaa8aa8aa8a8a8', $tmp) ⇒ 4+4+2+1+8+1+8+1+8+8+8 = 53 bytes.
  if row.len() < 53 {
    return Ok(None);
  }
  // $a[0] u32 = unixtime, $a[1] u32 = unknown, $a[2] u16 = ms,
  // $a[3] = status char, $a[4] lat_bytes (8), $a[5] = NS char,
  // $a[6] lon_bytes (8), $a[7] = EW char,
  // $a[8] speed_bytes (8), $a[9] track_bytes (8), $a[10] alt_bytes (8).
  let unixtime = le_u32(row, 0).ok_or("short row")?;
  // $a[1] @ offset 4 is unused (the bundled `Unknown02` debug tag).
  let ms = le_u16(row, 8).ok_or("short row")?;
  let status = row[10];
  let lat_raw = le_f64(row, 11).ok_or("short row")?;
  let ns = row[19];
  let lon_raw = le_f64(row, 20).ok_or("short row")?;
  let ew = row[28];
  let speed = le_f64(row, 29).ok_or("short row")?;
  let track = le_f64(row, 37).ok_or("short row")?;
  let alt = le_f64(row, 45).ok_or("short row")?;

  // QuickTimeStream.pl:3401-3409: validate NS/EW chars first.
  let ns_ok = ns == b'N' || ns == b'S';
  // `'O'` is the French "Ouest" variant some firmware emits
  // (QuickTimeStream.pl:3403-3405).
  let ew_ok = ew == b'E' || ew == b'W' || ew == b'O';
  if !(ns_ok && ew_ok) {
    // QuickTimeStream.pl:3407 `next if $a[3] eq 'V'` — void fixes don't
    // have valid N/S E/W; skip silently. Otherwise raise the bundled
    // 'Unrecognized INSV GPS format' warning.
    if status == b'V' {
      return Ok(None);
    }
    return Err("Unrecognized INSV GPS format");
  }
  // QuickTimeStream.pl:3411 `next unless $a[3] eq 'A'` — ignore void fixes.
  if status != b'A' {
    return Ok(None);
  }

  // QuickTimeStream.pl:3414 `$a[4] = -abs($a[4]) if $a[5] eq 'S'`.
  let lat = if ns == b'S' { -lat_raw.abs() } else { lat_raw };
  // QuickTimeStream.pl:3415 `$a[6] = -abs($a[6]) if $a[7] ne 'E'`
  // (both 'W' and 'O' flip the sign).
  let lon = if ew != b'E' { -lon_raw.abs() } else { lon_raw };

  // QuickTimeStream.pl:3416-3418 — render GPSDateTime as
  // `ConvertUnixTime($a[0]) . $ms . 'Z'`, where `$ms` is
  // `sprintf('.%.3d', $a[2])` with trailing zeros stripped, and is
  // empty when `$a[2]` is 0.
  let datetime_base = crate::datetime::convert_unix_time(unixtime as i64);
  let ms_suffix = if ms == 0 {
    SmolStr::new("")
  } else {
    // `sprintf('.%.3d', $a[2])` then `s/0+$//`.
    let raw = alloc::format!(".{:03}", ms);
    let trimmed = raw.trim_end_matches('0');
    // After the regex, if everything after the dot trimmed away, bundled
    // keeps the bare dot. Match that.
    SmolStr::new(trimmed)
  };
  let date_time = SmolStr::new(alloc::format!("{datetime_base}{ms_suffix}Z"));

  // QuickTimeStream.pl:74 `my $mpsToKph = 3.6` then :3421
  // `$et->HandleTag($tagTbl, GPSSpeed => $a[8] * $mpsToKph)`.
  let speed_kph = speed * 3.6;

  let mut out = Insta360GpsSample::new();
  out
    .set_date_time(Some(date_time))
    .set_latitude(Some(lat))
    .set_longitude(Some(lon))
    .set_speed_kph(Some(speed_kph))
    .set_track_deg(Some(track))
    .set_altitude_m(Some(alt));
  Ok(Some(out))
}

// ===========================================================================
// Record-type dispatch
// ===========================================================================

/// Dispatch one record by id. `body` is the record's value-bytes
/// (`$len` bytes long, EXCLUDING the 6-byte footer). The walker has
/// already validated lengths; this just classifies and decodes.
fn dispatch_record(id: u16, body: &[u8], out: &mut Insta360Meta) {
  match id {
    ID_IDENTITY => {
      let id_dec = decode_identity(body);
      if !id_dec.is_empty() {
        out.set_identity(id_dec);
      }
    }
    ID_EXPOSURE => {
      // QuickTimeStream.pl:3386-3391 — stride is the entry in `%insvDataLen`
      // (16 bytes).
      let dlen = 16usize;
      let mut p = 0usize;
      while p + dlen <= body.len() {
        if let Some(s) = decode_exposure_row(&body[p..p + dlen]) {
          out.push_exposure_sample(s);
        }
        p += dlen;
      }
    }
    ID_GPS => {
      // QuickTimeStream.pl:3397-3425 — stride is 53 bytes;
      // bundled tolerates non-multiple lengths (the `if ($len % $dlen and
      // $id != 0x700)` guard explicitly exempts 0x700).
      let dlen = 53usize;
      let mut p = 0usize;
      while p + dlen <= body.len() {
        match decode_gps_row(&body[p..p + dlen]) {
          Ok(Some(s)) => {
            out.push_gps_sample(s);
          }
          Ok(None) => {} // void fix or NS/EW indicated 'V' status
          Err(w) => {
            out.set_warning(SmolStr::new(w));
            // QuickTimeStream.pl:3409 `last;` — stop walking this record's
            // remaining rows on a format-warning. The outer record-loop
            // continues with the next record.
            break;
          }
        }
        p += dlen;
      }
    }
    // 0x000 directory-table is handled at the walker level (we don't
    // dispatch into here for it — see scan_trailer).
    // 0x200, 0x300, 0x600 — walked but not surfaced (see metadata module).
    _ => {}
  }
}

// ===========================================================================
// Scan-trailer (the per-file entry point)
// ===========================================================================

/// `Image::ExifTool::QuickTimeStream::ProcessInsta360` (QuickTimeStream.pl
/// :3252-3478) — locate the Insta360 trailer at file EOF and walk every
/// record into the typed [`Insta360Meta`]. If no Insta360 trailer is
/// present in `data`, the function returns the input `out` unchanged
/// (`is_empty()` stays `true`).
///
/// Faithful behaviour notes:
///
/// - QuickTimeStream.pl:3270-3271: read the last 78 bytes; verify the
///   last 32 bytes are the magic ASCII hex string.
/// - QuickTimeStream.pl:3276: trailer length is at offset 38 within the
///   footer (LE u32).
/// - QuickTimeStream.pl:3277: `trailerLen > $trailEnd` ⇒
///   `Bad Insta360 trailer size` warning + return (we accept this as a
///   soft-fail; the typed layer reports the warning + leaves the rest
///   empty).
/// - QuickTimeStream.pl:3308: `SetByteOrder('II')` — all multi-byte ints
///   in the trailer body are LE.
/// - QuickTimeStream.pl:3310-3470: walk LAST-to-FIRST starting from
///   `$epos = -78` (footer offset). On each iteration:
///    - Read `[id:u16-LE][len:u32-LE]` from the current 6-byte footer.
///    - `epos -= len; epos + trailerLen < 0 ⇒ stop` (we've passed the
///      trailer's start).
///    - Seek to `epos` and read `len` bytes (the record body).
///    - Dispatch by id. Special-case 0x300 (accelerometer): bundled
///      checks `len % 20 / len % 56` to pick the per-row stride.
///    - Special-case 0x000 (directory table): switch to forward-by-index
///      dispatch (QuickTimeStream.pl:3437-3469).
///    - Step back 6 more bytes to the previous record's footer; read it.
///
/// **Edge cases.**
/// - A file shorter than 78 bytes → `is_empty()` (no trailer).
/// - A file without the magic UUID → `is_empty()`.
/// - A trailer claiming `trailerLen > file size` → `Bad Insta360 trailer
///   size` warning, no records decoded.
/// - A record `len` overflow / position past start-of-trailer → stop the
///   walk cleanly (per the bundled guards).
pub fn scan_trailer(data: &[u8], out: &mut Insta360Meta) {
  // QuickTimeStream.pl:3270-3271 — locate footer + verify magic.
  let Some(trailer_len_raw) = read_trailer_len(data) else {
    return; // no Insta360 trailer
  };
  let trailer_len = trailer_len_raw as u64;
  let file_size = data.len() as u64;
  // `$raf->Tell()` after the read is at EOF; `$trailEnd = $raf->Tell()`
  // is the file size.
  let trail_end = file_size;
  // QuickTimeStream.pl:3277 `$trailerLen > $trailEnd and $et->Warn(...)`.
  if trailer_len > trail_end {
    out.set_warning(SmolStr::new("Bad Insta360 trailer size"));
    return;
  }
  // Trailer spans `[trail_end - trailer_len, trail_end)` in file bytes.
  // Bundled tracks position as a NEGATIVE offset from `trail_end`:
  //   $epos = -78  ⇒ footer start
  //   $epos -= $len after parsing each record body
  // The loop terminates when `$epos + $trailerLen < 0` (we've gone past
  // the trailer's start). Translate to positive file offsets:
  //   abs_pos = trail_end + epos   (since epos < 0)
  // The trailer's start in file coords is `trail_end - trailer_len`.

  // Read the initial 78-byte footer into `cur` and seed the walker
  // state with the LAST record's (id, len).
  if (data.len() as u64) < FOOTER_SIZE as u64 {
    return;
  }
  // `epos` is the (negative) offset-from-EOF of the CURRENT 6-byte footer.
  let mut epos: i64 = -(FOOTER_SIZE as i64);

  // QuickTimeStream.pl:3311 `unpack('vV', $buff)` — the FIRST 6 bytes of
  // the 78-byte footer ARE the last record's footer.
  let footer_buf = &data[(trail_end as usize) - FOOTER_SIZE..];
  let mut cur_id = match le_u16(footer_buf, 0) {
    Some(v) => v,
    None => return,
  };
  let mut cur_len = match le_u32(footer_buf, 2) {
    Some(v) => v,
    None => return,
  };

  // Directory table state (QuickTimeStream.pl:3449-3466).
  // When a `0x000` record is encountered, we LATCH the dir-table payload
  // and switch to forward-by-index dispatch. `dir_table_pos` advances by
  // 10 bytes per entry (`[id:u16-LE][siz:u32-LE][off:u32-LE]`).
  let mut dir_table: Option<Vec<u8>> = None;
  let mut dir_table_pos = 0usize;

  // Per-record counter cap — bundle's `%insvLimit` (0x300 only — see
  // QuickTimeStream.pl:3347-3352).
  let mut insv_limit_remaining: Option<u64> = None;

  // Hard guard on the number of records we walk (defensive against a
  // malformed dir table or len that would infinite-loop).
  // 2_000_000 is well above any real-world Insta360 trailer's record count.
  let mut hard_guard: u32 = 2_000_000;

  loop {
    if hard_guard == 0 {
      break;
    }
    hard_guard -= 1;

    let id = cur_id;
    let len = cur_len;

    // QuickTimeStream.pl:3312 `($epos -= $len) + $trailerLen < 0 and last`.
    epos = epos.saturating_sub(len as i64);
    if (epos + trailer_len as i64) < 0 {
      break;
    }

    // QuickTimeStream.pl:3313 `$raf->Seek($epos-$offset, 2) or last` —
    // seek to the record body start.
    let body_abs = (trail_end as i64) + epos;
    if body_abs < 0 || (body_abs as u64) + (len as u64) > file_size {
      break;
    }
    let body_start = body_abs as usize;
    let body_end = body_start + len as usize;

    // QuickTimeStream.pl:3326-3346 — `%insvDataLen` + 0x300 stride probe.
    // We don't need bundled's stride probing for the records we surface;
    // dispatch_record runs row-walks internally with the catalogue stride.

    // QuickTimeStream.pl:3347-3352 — `%insvLimit` cap (only 0x300).
    let effective_len = if id == ID_ACCELEROMETER {
      // Bundled trims `$len` to `$insvLimit{$id}[1] * $dlen` when
      // `$len > $insvLimit{$id}[1] * $dlen`. `$dlen` for 0x300 is 20 or
      // 56 depending on the per-row probe. We don't surface 0x300, but
      // we still honour the cap to avoid pathological allocations on a
      // crafted trailer. Pick the safer (larger) stride (56) for the
      // cap — matches the 20000-row * 56-byte hard cap.
      let cap = INSV_LIMIT_0X300.saturating_mul(56);
      if (len as u64) > cap {
        // Bundled emits the `Insta360 ... data is huge` warning here.
        if insv_limit_remaining.is_none() {
          out.set_warning(SmolStr::new(
            "Insta360 accelerometer data is huge. Processing only the first 20000 records",
          ));
        }
        insv_limit_remaining = Some(cap);
        cap as u32
      } else {
        len
      }
    } else {
      len
    };

    let body = &data[body_start..body_start + effective_len as usize];

    // QuickTimeStream.pl:3437 `} elsif ($id == 0x0) { ... }` — directory
    // table latch (QuickTimeStream.pl:3437-3453).
    if id == ID_DIRECTORY_TABLE {
      // `last if not $len` — bundled stops the LAST-to-FIRST walk if
      // the directory table is empty.
      if len == 0 {
        break;
      }
      // Latch the directory table contents (only the FIRST one seen).
      if dir_table.is_none() {
        dir_table = Some(body.to_vec());
        dir_table_pos = 0;
      }
    } else {
      // Dispatch every other record. (Note: bundled has a specific
      // `if ($dlen) { ... } elsif ($id == 0x101)` structure — the
      // 0x101 path is NOT inside `%insvDataLen` so it falls into the
      // `elsif`. Our dispatch_record handles 0x101 by id.)
      dispatch_record(id, body, out);
      // Don't advance `body_end` past `body_start + effective_len`
      // semantically; the underlying seek/step uses the ORIGINAL len.
      let _ = body_end; // suppress unused (kept for explicit-len readers)
    }

    // QuickTimeStream.pl:3455-3469: if a dir-table was latched, jump to
    // the next record by index; otherwise step back 6 bytes for the
    // previous record's footer.
    if let Some(ref dt) = dir_table {
      // Walk dir-table entries until we find a usable one.
      let mut found_next = false;
      loop {
        if dir_table_pos + 10 > dt.len() {
          break;
        }
        let next_id = match le_u16(dt, dir_table_pos) {
          Some(v) => v,
          None => break,
        };
        let next_siz = match le_u32(dt, dir_table_pos + 2) {
          Some(v) => v,
          None => break,
        };
        let next_off = match le_u32(dt, dir_table_pos + 6) {
          Some(v) => v,
          None => break,
        };
        dir_table_pos += 10;
        // QuickTimeStream.pl:3461 `if ($id and $siz and $off + $siz <
        // $trailerLen)`.
        if next_id != 0 && next_siz != 0 && (next_off as u64) + (next_siz as u64) < trailer_len {
          // QuickTimeStream.pl:3462 `$epos = $off + $siz - $trailerLen`
          // — the next record's footer offset (NEGATIVE).
          epos = (next_off as i64) + (next_siz as i64) - (trailer_len as i64);
          cur_id = next_id;
          cur_len = next_siz;
          found_next = true;
          break;
        }
      }
      if !found_next {
        // QuickTimeStream.pl:3466 `last unless defined $epos` — dir
        // table is exhausted or yielded no usable entry.
        break;
      }
      // For dir-table mode bundled does NOT advance epos -= len at the
      // top of the loop the same way — instead it uses the `$off + $siz`
      // delta as the new epos. The loop will read the footer at `epos`
      // (the next record's footer), so the `epos -= $len` at the top
      // re-uses the cur_len we just set above. We've already populated
      // cur_id/cur_len, so we skip the explicit footer-read below.
      continue;
    }

    // QuickTimeStream.pl:3468 `($epos -= 6) + $trailerLen < 0 and last`.
    epos = epos.saturating_sub(RECORD_FOOTER_SIZE as i64);
    if (epos + trailer_len as i64) < 0 {
      break;
    }
    // QuickTimeStream.pl:3470 `$raf->Seek($epos-$offset, 2) or last`.
    let next_footer_abs = (trail_end as i64) + epos;
    if next_footer_abs < 0 || (next_footer_abs as u64) + (RECORD_FOOTER_SIZE as u64) > file_size {
      break;
    }
    let next_footer_buf =
      &data[next_footer_abs as usize..next_footer_abs as usize + RECORD_FOOTER_SIZE];
    cur_id = match le_u16(next_footer_buf, 0) {
      Some(v) => v,
      None => break,
    };
    cur_len = match le_u32(next_footer_buf, 2) {
      Some(v) => v,
      None => break,
    };
  }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  // ----- helpers --------------------------------------------------------

  /// Build the 78-byte Insta360 footer: `[last_id:u16][last_len:u32]
  /// [32 opaque][trailer_len:u32][4 opaque][32-byte ASCII magic]`.
  fn footer(last_id: u16, last_len: u32, trailer_len: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(FOOTER_SIZE);
    out.extend_from_slice(&last_id.to_le_bytes());
    out.extend_from_slice(&last_len.to_le_bytes());
    out.resize(out.len() + 32, 0); // opaque
    out.extend_from_slice(&trailer_len.to_le_bytes());
    out.resize(out.len() + 4, 0); // opaque
    out.extend_from_slice(MAGIC);
    assert_eq!(out.len(), FOOTER_SIZE);
    out
  }

  /// One 6-byte record footer.
  fn record_footer(id: u16, len: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(6);
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out
  }

  /// Build an identity body: `[tag:u8][len:u8][value]` items.
  fn identity_body(items: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (t, v) in items {
      out.push(*t);
      out.push(v.len() as u8);
      out.extend_from_slice(v);
    }
    out
  }

  /// Build one 53-byte GPS row.
  #[allow(clippy::too_many_arguments)]
  fn gps_row(
    unixtime: u32,
    ms: u16,
    status: u8,
    lat: f64,
    ns: u8,
    lon: f64,
    ew: u8,
    speed_mps: f64,
    track_deg: f64,
    altitude_m: f64,
  ) -> Vec<u8> {
    let mut out = Vec::with_capacity(53);
    out.extend_from_slice(&unixtime.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // unknown
    out.extend_from_slice(&ms.to_le_bytes());
    out.push(status);
    out.extend_from_slice(&lat.to_le_bytes());
    out.push(ns);
    out.extend_from_slice(&lon.to_le_bytes());
    out.push(ew);
    out.extend_from_slice(&speed_mps.to_le_bytes());
    out.extend_from_slice(&track_deg.to_le_bytes());
    out.extend_from_slice(&altitude_m.to_le_bytes());
    assert_eq!(out.len(), 53);
    out
  }

  /// Build one 16-byte exposure row.
  fn exposure_row(timestamp_ms: u64, exposure_s: f64) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&timestamp_ms.to_le_bytes());
    out.extend_from_slice(&exposure_s.to_le_bytes());
    out
  }

  /// Build a trailer with the supplied (id, body) records in FILE
  /// ORDER (i.e. first-to-last); a 6-byte footer is appended after
  /// each record body, and the final 78-byte trailer footer ties it
  /// off. Returns a Vec representing the full file.
  ///
  /// File layout:
  ///   [non-trailer prefix bytes][record0_body][record0_footer]
  ///   [record1_body][record1_footer] ... [78-byte trailer footer]
  fn build_file(prefix: &[u8], records: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut file = Vec::new();
    file.extend_from_slice(prefix);
    // Records in file order: each body, then its 6-byte footer.
    for (id, body) in records {
      file.extend_from_slice(body);
      file.extend_from_slice(&record_footer(*id, body.len() as u32));
    }
    // The trailer's 78-byte footer encodes:
    //   - first 6 bytes = LAST record's (id, len) — same as the LAST
    //     record's footer (the 6 bytes immediately before the trailer
    //     footer ARE this same 6 bytes — bundled treats them as the
    //     same thing; the `Read 78` includes those 6 bytes).
    // Actually rereading the bundled code: `Seek -78, Read 78` and then
    // `unpack('vV', $buff)` reads from offset 0 of the 78-byte buffer.
    // That offset 0 IS the last record's footer (we just wrote
    // `record_footer` as the LAST 6 bytes before "where the trailer
    // footer starts"). So: the LAST record's 6-byte footer IS the first
    // 6 bytes of the 78-byte trailer footer. We need to TRIM the last
    // 6 bytes we added (the LAST record_footer) and replace them with
    // the 78-byte trailer footer (whose first 6 bytes = the same).
    let (last_id, last_len) = if let Some((id, body)) = records.last() {
      (*id, body.len() as u32)
    } else {
      (0u16, 0u32)
    };
    // Strip the trailing 6-byte footer (it's redundant with the 78-byte
    // footer's first 6 bytes).
    let last6_start = file.len() - 6;
    file.truncate(last6_start);

    // Compute trailer_len: total bytes of (every record body + every
    // record's 6-byte footer). The LAST record's footer is INSIDE the
    // 78-byte trailer footer, so it counts.
    let trailer_start = prefix.len();
    let trailer_len = (file.len() - trailer_start) as u32 + FOOTER_SIZE as u32;
    let trailer_footer = footer(last_id, last_len, trailer_len);
    file.extend_from_slice(&trailer_footer);
    file
  }

  // ----- has_trailer / read_trailer_len --------------------------------

  #[test]
  fn has_trailer_false_for_short_input() {
    assert!(!has_trailer(&[]));
    assert!(!has_trailer(&[0u8; 10]));
    assert!(!has_trailer(&[0u8; 31]));
  }

  #[test]
  fn has_trailer_true_when_magic_at_eof() {
    let mut buf = vec![0u8; 100];
    buf.extend_from_slice(MAGIC);
    assert!(has_trailer(&buf));
  }

  #[test]
  fn has_trailer_false_when_magic_present_but_not_at_eof() {
    let mut buf = vec![0u8; 50];
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&[0u8; 10]); // append 10 extra bytes after magic
    assert!(!has_trailer(&buf));
  }

  #[test]
  fn read_trailer_len_returns_value_at_offset_38() {
    // Build a 78-byte buffer; trailer_len = 0xdeadbeef at offset 38.
    let mut buf = vec![0u8; 100]; // pad
    let ft = footer(0x101, 16, 0xdeadbeef);
    buf.extend_from_slice(&ft);
    assert_eq!(read_trailer_len(&buf), Some(0xdeadbeef));
  }

  #[test]
  fn read_trailer_len_none_without_magic() {
    let buf = vec![0u8; 200];
    assert!(read_trailer_len(&buf).is_none());
  }

  // ----- per-record-type decoders --------------------------------------

  #[test]
  fn decode_identity_decodes_all_four_tags() {
    let body = identity_body(&[
      (TAG_SERIAL_NUMBER, b"IXX00123"),
      (TAG_MODEL, b"Insta360 X3"),
      (TAG_FIRMWARE, b"1.0.07"),
      (TAG_PARAMETERS, b"2_6_4032_3024"),
    ]);
    let id = decode_identity(&body);
    assert_eq!(id.serial_number(), Some("IXX00123"));
    assert_eq!(id.model(), Some("Insta360 X3"));
    assert_eq!(id.firmware(), Some("1.0.07"));
    // tr/_/ / underscore substitution (QuickTimeStream.pl:705).
    assert_eq!(id.parameters(), Some("2 6 4032 3024"));
  }

  #[test]
  fn decode_identity_truncated_stops_cleanly() {
    let mut body = identity_body(&[(TAG_MODEL, b"Insta360 X3")]);
    body.push(TAG_FIRMWARE);
    body.push(50); // claims 50 bytes but none follow
    let id = decode_identity(&body);
    assert_eq!(id.model(), Some("Insta360 X3"));
    assert_eq!(id.firmware(), None);
  }

  #[test]
  fn decode_identity_caps_at_four_items() {
    // Five items; the 5th must NOT decode (bundled `for ($i=0; $i<4; ++$i)`).
    let body = identity_body(&[
      (TAG_SERIAL_NUMBER, b"S"),
      (TAG_MODEL, b"M"),
      (TAG_FIRMWARE, b"F"),
      (TAG_PARAMETERS, b"P"),
      (0xff, b"extra"),
    ]);
    let id = decode_identity(&body);
    assert_eq!(id.serial_number(), Some("S"));
    assert_eq!(id.parameters(), Some("P"));
    // The 5th tag (0xff) was outside the cap; nothing extra to verify.
  }

  #[test]
  fn decode_exposure_row_extracts_timestamp_and_exposure() {
    let row = exposure_row(123456789, 0.00125);
    let s = decode_exposure_row(&row).expect("decoded");
    assert_eq!(s.timestamp_ms(), Some(123456789));
    assert!((s.exposure_time_s().unwrap() - 0.00125).abs() < 1e-12);
  }

  #[test]
  fn decode_exposure_row_short_returns_none() {
    let row = vec![0u8; 8];
    assert!(decode_exposure_row(&row).is_none());
  }

  #[test]
  fn decode_gps_row_basic_north_east_fix() {
    let row = gps_row(
      1717250400, // 2024:06:01 14:00:00 UTC
      0, b'A', 37.7749, b'N', -122.4194, b'W', // value is "-122.4194" raw
      10.0, 180.0, 15.5,
    );
    // For W: bundled does `-abs(lon_raw)` ⇒ -abs(-122.4194) = -122.4194.
    let s = decode_gps_row(&row).expect("ok").expect("present");
    assert!((s.latitude().unwrap() - 37.7749).abs() < 1e-9);
    assert!((s.longitude().unwrap() - -122.4194).abs() < 1e-9);
    assert!((s.altitude_m().unwrap() - 15.5).abs() < 1e-9);
    assert!((s.speed_kph().unwrap() - 36.0).abs() < 1e-9); // 10 m/s * 3.6
    assert!((s.track_deg().unwrap() - 180.0).abs() < 1e-9);
    assert_eq!(s.date_time(), Some("2024:06:01 14:00:00Z"));
  }

  #[test]
  fn decode_gps_row_south_flips_lat_sign() {
    let row = gps_row(1717250400, 0, b'A', 12.345, b'S', 0.0, b'E', 0.0, 0.0, 0.0);
    let s = decode_gps_row(&row).expect("ok").expect("present");
    assert!((s.latitude().unwrap() - -12.345).abs() < 1e-9);
  }

  #[test]
  fn decode_gps_row_french_o_treated_as_west() {
    let row = gps_row(1717250400, 0, b'A', 0.0, b'N', 5.0, b'O', 0.0, 0.0, 0.0);
    let s = decode_gps_row(&row).expect("ok").expect("present");
    assert!((s.longitude().unwrap() - -5.0).abs() < 1e-9);
  }

  #[test]
  fn decode_gps_row_void_status_returns_none() {
    let row = gps_row(0, 0, b'V', 0.0, b'N', 0.0, b'E', 0.0, 0.0, 0.0);
    let s = decode_gps_row(&row).expect("ok");
    assert!(s.is_none());
  }

  #[test]
  fn decode_gps_row_invalid_ns_with_valid_status_returns_warning() {
    let row = gps_row(0, 0, b'A', 0.0, b'X', 0.0, b'E', 0.0, 0.0, 0.0);
    assert!(decode_gps_row(&row).is_err());
  }

  #[test]
  fn decode_gps_row_void_status_with_invalid_ns_returns_none() {
    // QuickTimeStream.pl:3407 — void fixes skipped even if NS/EW is invalid.
    let row = gps_row(0, 0, b'V', 0.0, b'X', 0.0, b'Y', 0.0, 0.0, 0.0);
    let s = decode_gps_row(&row).expect("ok");
    assert!(s.is_none());
  }

  #[test]
  fn decode_gps_row_ms_field_renders_as_dot_fraction() {
    let row = gps_row(1717250400, 100, b'A', 0.0, b'N', 0.0, b'E', 0.0, 0.0, 0.0);
    // .100 ⇒ trim trailing zeros ⇒ `.1`. Then `Z` suffix.
    let s = decode_gps_row(&row).expect("ok").expect("present");
    assert_eq!(s.date_time(), Some("2024:06:01 14:00:00.1Z"));
  }

  // ----- scan_trailer / walker -----------------------------------------

  #[test]
  fn scan_trailer_no_signature_leaves_out_empty() {
    let data = vec![0u8; 200];
    let mut out = Insta360Meta::new();
    scan_trailer(&data, &mut out);
    assert!(out.is_empty());
    assert!(out.warning().is_none());
  }

  #[test]
  fn scan_trailer_short_file_leaves_out_empty() {
    let data = vec![0u8; 50];
    let mut out = Insta360Meta::new();
    scan_trailer(&data, &mut out);
    assert!(out.is_empty());
  }

  #[test]
  fn scan_trailer_identity_only_single_record() {
    // Build a trailer with one 0x101 identity record.
    let id_body = identity_body(&[
      (TAG_SERIAL_NUMBER, b"IXX00123"),
      (TAG_MODEL, b"Insta360 X3"),
      (TAG_FIRMWARE, b"1.0.07"),
      (TAG_PARAMETERS, b"2_6_4032_3024"),
    ]);
    let file = build_file(b"prefix-bytes-here-1234", &[(ID_IDENTITY, id_body)]);
    let mut out = Insta360Meta::new();
    scan_trailer(&file, &mut out);
    assert!(out.warning().is_none(), "no warnings on clean trailer");
    let id = out.identity().expect("identity decoded");
    assert_eq!(id.serial_number(), Some("IXX00123"));
    assert_eq!(id.model(), Some("Insta360 X3"));
    assert_eq!(id.firmware(), Some("1.0.07"));
    assert_eq!(id.parameters(), Some("2 6 4032 3024"));
  }

  #[test]
  fn scan_trailer_gps_record_single_row() {
    let mut gps_body = Vec::new();
    gps_body.extend_from_slice(&gps_row(
      1717250400, 0, b'A', 45.0, b'N', 8.0, b'E', 10.0, 90.0, 200.0,
    ));
    let file = build_file(b"prefix", &[(ID_GPS, gps_body)]);
    let mut out = Insta360Meta::new();
    scan_trailer(&file, &mut out);
    assert!(out.warning().is_none());
    let fix = out.first_fix().expect("fix");
    assert!((fix.latitude().unwrap() - 45.0).abs() < 1e-9);
    assert!((fix.longitude().unwrap() - 8.0).abs() < 1e-9);
    assert!((fix.altitude_m().unwrap() - 200.0).abs() < 1e-9);
    assert!((fix.speed_kph().unwrap() - 36.0).abs() < 1e-9);
  }

  #[test]
  fn scan_trailer_identity_and_gps_records() {
    let id_body = identity_body(&[(TAG_MODEL, b"Insta360 ONE RS"), (TAG_FIRMWARE, b"1.0.01")]);
    let mut gps_body = Vec::new();
    gps_body.extend_from_slice(&gps_row(
      1717250400, 0, b'A', 45.0, b'N', 8.0, b'E', 0.0, 0.0, 0.0,
    ));
    let file = build_file(
      b"prefix-bytes-",
      &[(ID_IDENTITY, id_body), (ID_GPS, gps_body)],
    );
    let mut out = Insta360Meta::new();
    scan_trailer(&file, &mut out);
    let id = out.identity().expect("identity");
    assert_eq!(id.model(), Some("Insta360 ONE RS"));
    let fix = out.first_fix().expect("fix");
    assert!((fix.latitude().unwrap() - 45.0).abs() < 1e-9);
  }

  #[test]
  fn scan_trailer_exposure_record_extracts_rows() {
    let mut body = Vec::new();
    body.extend_from_slice(&exposure_row(1000, 0.008));
    body.extend_from_slice(&exposure_row(2000, 0.016));
    let file = build_file(b"prefix", &[(ID_EXPOSURE, body)]);
    let mut out = Insta360Meta::new();
    scan_trailer(&file, &mut out);
    let samples = out.exposure_samples();
    assert_eq!(samples.len(), 2);
    assert_eq!(samples[0].timestamp_ms(), Some(1000));
    assert!((samples[0].exposure_time_s().unwrap() - 0.008).abs() < 1e-12);
    assert_eq!(samples[1].timestamp_ms(), Some(2000));
  }

  #[test]
  fn scan_trailer_bad_trailer_size_warns_and_stops() {
    // Build a trailer footer that claims trailer_len > file size.
    let mut buf = vec![0u8; 100];
    let big_trailer_len = 1_000_000u32; // way bigger than 178
    let ft = footer(0x101, 16, big_trailer_len);
    buf.extend_from_slice(&ft);
    let mut out = Insta360Meta::new();
    scan_trailer(&buf, &mut out);
    assert_eq!(out.warning(), Some("Bad Insta360 trailer size"));
    assert!(out.identity().is_none());
  }
}
