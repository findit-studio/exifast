// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "quicktime")]
//! Faithful port of `Image::ExifTool::Sony::Process_rtmd`
//! (Sony.pm:11566-11602) — the Sony "Real-Time MetaData" walker shared by
//! the Alpha A7 / A9 / FX / RX / Cinema-line MP4 / MOV recorders. Backed by
//! the `Image::ExifTool::Sony::rtmd` tag table (Sony.pm:10686-10850).
//!
//! ## Container
//!
//! Each rtmd sample begins with a 2-byte big-endian header length
//! (`Get16u($dataPt, 0)`, Sony.pm:11581). Bundled hard-codes the assumption
//! that the value is `0x1c` (28); we honour the value as-stored so a future
//! firmware that emits a different header still parses.
//!
//! After the header, records follow the shape `[tag:int16u-BE][len:int16u-BE]
//! [value:len bytes]`. Two special cases (Sony.pm:11586-11591):
//!
//!  - **`tag == 0x060e`** — the length field is REPLACED with a fixed `0x10`
//!    (16 bytes), AND `$pos` is NOT advanced past the 4-byte header. The
//!    walker reads 16 bytes STARTING at `$pos` (so the tag + len bytes are
//!    INCLUDED in those 16). Bundled comments say `# 0x060e - 16 bytes
//!    starting with 0x060e2b340253 (fake tag ID - comes before 0x8300
//!    container)`. This is the SMPTE Universal Label that introduces the
//!    container.
//!  - **`tag == 0x8300`** — the 4-byte header IS skipped (`$pos += 4`),
//!    `len` is the body length, but the loop continues with `next` and the
//!    increment `$pos += $len` is SKIPPED. The next iteration thus reads
//!    the FIRST record inside the container as if it were a sibling — a
//!    flat-recursion (inline descend) into the container's children.
//!
//! ## Loop termination
//!
//! Bundled (Sony.pm:11582-11600):
//!  - `while ($pos + 4 < $end)` — strict-less, identical to camm / mebx
//!    bounds handling; a trailing 4-byte remainder is dropped without
//!    decode.
//!  - `last if $tag == 0` — a zero-tag stops the walk (padding / EOM).
//!  - `last if $pos + $len > $end` — a truncated value stops the walk.
//!
//! ## What this module emits
//!
//! For each decoded record, [`process_rtmd`] accumulates one
//! [`SonyRtmdCameraSnapshot`] + (when any `0x85xx` GPS tag is present)
//! ONE [`SonyRtmdGpsSample`] per sample. The aggregation is per-CALL — one
//! call = one sample; the QuickTimeStream dispatcher loops over samples
//! and the per-sample results are pushed onto [`SonyRtmdMeta`] in source
//! order.
//!
//! ## Endianness
//!
//! `Image::ExifTool::Sony` sets `BIG_ENDIAN` as the default byte order
//! (Sony.pm:55 `SetByteOrder('MM')` is the bundled `%Image::ExifTool::Sony`
//! initializer behaviour for rtmd records; `Get16u`/`Get32u` in the walker
//! inherit it).
//!
//! ## GPS priority chain
//!
//! Sony rtmd feeds the **THIRD-HIGHEST tier** of the cross-port GPS
//! priority chain that [`crate::metadata::MediaMetadata`] projects from a
//! QuickTime file: GoPro GPMF → Android CAMM → Sony rtmd → Insta360
//! trailer → Parrot mett → SP3 stream. Sony rtmd GPS is phone-paired
//! (Imaging Edge Mobile pairs the body to a phone whose GNSS feeds the
//! samples) so it ranks below GoPro / CAMM on-device-hardware GPS but
//! above Insta360 / SP3 (both also phone-paired or scan-based).

extern crate alloc;

use smol_str::SmolStr;

use crate::metadata::{SonyRtmdCameraSnapshot, SonyRtmdGpsSample, SonyRtmdMeta};

// ===========================================================================
// Big-endian readers (Sony rtmd is big-endian)
// ===========================================================================

fn be_u16(b: &[u8], off: usize) -> Option<u16> {
  b.get(off..off + 2)
    .map(|s| u16::from_be_bytes([s[0], s[1]]))
}

fn be_u32(b: &[u8], off: usize) -> Option<u32> {
  b.get(off..off + 4)
    .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

// ===========================================================================
// Tag IDs (Sony.pm:10686-10850)
// ===========================================================================

const TAG_SMPTE_LABEL: u16 = 0x060e; // 16-byte fixed Universal Label
const TAG_CONTAINER: u16 = 0x8300; // recurse into contents (no len skip)

// Camera / capture (Sony.pm:10700-10735)
const TAG_FNUMBER: u16 = 0x8000;
const TAG_FRAME_RATE: u16 = 0x8106;
const TAG_EXPOSURE_TIME: u16 = 0x8109;
const TAG_MASTER_GAIN: u16 = 0x810a;
const TAG_ISO: u16 = 0x810b;
const TAG_SERIAL_NUMBER: u16 = 0x8114;

// GPS (Sony.pm:10738-10811)
const TAG_GPS_VERSION_ID: u16 = 0x8500;
const TAG_GPS_LATITUDE_REF: u16 = 0x8501;
const TAG_GPS_LATITUDE: u16 = 0x8502;
const TAG_GPS_LONGITUDE_REF: u16 = 0x8503;
const TAG_GPS_LONGITUDE: u16 = 0x8504;
const TAG_GPS_TIME_STAMP: u16 = 0x8507;
const TAG_GPS_STATUS: u16 = 0x8509;
const TAG_GPS_MEASURE_MODE: u16 = 0x850a;
const TAG_GPS_MAP_DATUM: u16 = 0x8512;
const TAG_GPS_DATE_STAMP: u16 = 0x851d;

// Time / WB (Sony.pm:10817-10833)
const TAG_WHITE_BALANCE: u16 = 0xe303;
const TAG_DATE_TIME: u16 = 0xe304;

// Alternate ISO seen on FX-line firmware (`0xe301`, int32u; Sony.pm:10814).
// Bundled marks it `%hidUnk` and notes "seen: 100, 1600, 12800 - ISO". We
// fold it into the typed `iso` slot when the canonical `0x810b` was absent.
const TAG_ISO_ALT: u16 = 0xe301;

// ===========================================================================
// Per-record decoders
// ===========================================================================

/// `Image::ExifTool::Exif::PrintFNumber` (Exif.pm:5715-5723) — the
/// PrintConv used by `0x8000 FNumber` (Sony.pm:10700-10705). Bundled rounds
/// `< 1.0` to 2 decimals, otherwise to 1. exifast keeps the unrounded
/// `f64` in the typed snapshot; the rounded form is a presentation concern
/// (and would lose precision relative to the bundled `Value` channel under
/// `-n`).
///
/// The `ValueConv = 2^(8-val/8192)` (Sony.pm:10703) IS applied here.
fn decode_fnumber(value: &[u8]) -> Option<f64> {
  // Bundled format is `int16u` (Sony.pm:10702) — read 2 BE bytes.
  let raw = be_u16(value, 0)? as f64;
  // `2 ** (8 - raw/8192)`.
  Some(f64::powf(2.0, 8.0 - raw / 8192.0))
}

/// `0x8106 FrameRate` (Sony.pm:10716) — rational64u, displayed via
/// `sprintf("%.2f", $val)` but stored as the raw quotient.
///
/// `rational64u` = `Get32u(num) / Get32u(denom)`. Bundled
/// `Image::ExifTool::ValueConv` treats a zero-denominator as `inf` (Perl
/// `0/0` → `nan`, `n/0` → `inf` after the float coercion); the typed
/// layer mirrors that — a zero denominator with non-zero numerator
/// returns `f64::INFINITY`, and `0/0` returns `f64::NAN`. The `value::
/// perl_nonfinite_str` lowering then renders them `inf`/`NaN`.
fn decode_rational64u(value: &[u8]) -> Option<f64> {
  let num = be_u32(value, 0)? as f64;
  let denom = be_u32(value, 4)? as f64;
  Some(num / denom)
}

/// `0x8109 ExposureTime` (Sony.pm:10717-10721) — rational64u seconds.
fn decode_exposure_time(value: &[u8]) -> Option<f64> {
  decode_rational64u(value)
}

/// `0x810b ISO` (Sony.pm:10728) — `int16u` raw.
fn decode_iso_u16(value: &[u8]) -> Option<u32> {
  be_u16(value, 0).map(u32::from)
}

/// `0xe301` alt-ISO (Sony.pm:10814) — `int32u` raw.
fn decode_iso_u32(value: &[u8]) -> Option<u32> {
  be_u32(value, 0)
}

/// `0x810a MasterGainAdjustment` (Sony.pm:10722-10727) — `int16u / 100` dB.
fn decode_master_gain_db(value: &[u8]) -> Option<f64> {
  let raw = be_u16(value, 0)? as f64;
  Some(raw / 100.0)
}

/// `0x8114 SerialNumber` (Sony.pm:10734) — `Format => 'string'`. Bundled
/// trims a trailing NUL via `ReadValue`; we mirror that.
fn decode_string(value: &[u8]) -> Option<SmolStr> {
  // Bundled `ReadValue` for `string` format `s/\0+$//` — strip any number
  // of NUL terminators. Non-ASCII bytes are passed through as-is (Sony
  // serial strings are ASCII).
  let trimmed_end = value.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
  let s = core::str::from_utf8(&value[..trimmed_end]).ok()?;
  let s = s.trim();
  if s.is_empty() {
    return None;
  }
  Some(SmolStr::new(s))
}

/// `0xe304 DateTime` (Sony.pm:10828-10834) — 8-byte BCD-packed record.
/// `ValueConv => 'my @a=unpack("x1H4H2H2H2H2H2",$val); "$a[0]:$a[1]:$a[2]
/// $a[3]:$a[4]:$a[5]"'`:
///   - skip byte 0 (`x1`);
///   - 2-byte year as a 4-digit hex string (`H4`, e.g. `0x20 0x24 → "2024"`);
///   - 1-byte month, day, hour, minute, second each as 2-digit hex (`H2`).
///
/// Each byte is rendered as a HEX-DIGITS string, NOT decimal — so a
/// `month` byte `0x05` becomes `"05"`, `0x12` becomes `"12"` (which on a
/// BCD-packed source IS the decimal 12). Bundled then joins them with
/// the formatting `"$y:$mo:$d $h:$mi:$s"`.
fn decode_date_time(value: &[u8]) -> Option<SmolStr> {
  if value.len() < 8 {
    return None;
  }
  // Read bytes 1..8.
  let y0 = value[1];
  let y1 = value[2];
  let mo = value[3];
  let d = value[4];
  let h = value[5];
  let mi = value[6];
  let s = value[7];

  // `H4` on a 2-byte buffer is the 4 hex nibbles, MSB-first: high-nibble
  // of byte 0, low-nibble of byte 0, high-nibble of byte 1, low-nibble of
  // byte 1. For a BCD-packed year `0x20 0x24`, that's "2024".
  let mut out = alloc::string::String::with_capacity(19);
  use core::fmt::Write;
  let _ = write!(
    out,
    "{:02x}{:02x}:{:02x}:{:02x} {:02x}:{:02x}:{:02x}",
    y0, y1, mo, d, h, mi, s
  );
  // `:02x` is lowercase hex; for BCD the result is digits-only so the
  // case doesn't matter, but bundled `H` is lowercase too.
  Some(SmolStr::new(out))
}

/// `0xe303 WhiteBalance` (Sony.pm:10816-10827) — `int8u` raw.
fn decode_u8(value: &[u8]) -> Option<u8> {
  value.first().copied()
}

/// `0x8500 GPSVersionID` (Sony.pm:10738-10743) — `int8u` value with
/// `PrintConv => '$val =~ tr/ /./; $val'`. Bundled `ReadValue` for `int8u`
/// with `Count != 1` joins the values with spaces; the PrintConv then
/// rewrites spaces to dots. We mirror the final form.
fn decode_gps_version_id(value: &[u8]) -> Option<SmolStr> {
  if value.is_empty() {
    return None;
  }
  let mut out = alloc::string::String::with_capacity(value.len() * 4);
  use core::fmt::Write;
  for (i, b) in value.iter().enumerate() {
    if i > 0 {
      out.push('.');
    }
    let _ = write!(out, "{b}");
  }
  Some(SmolStr::new(out))
}

/// `0x8502 GPSLatitude` / `0x8504 GPSLongitude` — three `rational64u`
/// triplets (degrees, minutes, seconds). `ValueConv` calls
/// `GPS::ToDegrees($val)` on the joined string. For three rationals
/// pre-formatted as `"D M S"`, `ToDegrees` returns `D + M/60 + S/3600`
/// (GPS.pm:582-600). The exifast typed layer composes the float directly.
fn decode_gps_coordinate(value: &[u8]) -> Option<f64> {
  // 3 × rational64u = 24 bytes.
  if value.len() < 24 {
    return None;
  }
  let d = decode_rational64u(&value[0..8])?;
  let m = decode_rational64u(&value[8..16])?;
  let s = decode_rational64u(&value[16..24])?;
  Some(d + m / 60.0 + s / 3600.0)
}

/// `0x8507 GPSTimeStamp` (Sony.pm:10776-10781) — three rational64u in
/// `"H M S"` form, then `GPS::ConvertTimeStamp` reformats to
/// `"HH:MM:SS[.s+]"` (GPS.pm:459-474). The typed layer stores the
/// post-`ConvertTimeStamp` string.
fn decode_gps_time_stamp(value: &[u8]) -> Option<SmolStr> {
  if value.len() < 24 {
    return None;
  }
  let h = decode_rational64u(&value[0..8])?;
  let m = decode_rational64u(&value[8..16])?;
  let s = decode_rational64u(&value[16..24])?;
  Some(SmolStr::new(format_gps_time_stamp(h, m, s)))
}

/// `Image::ExifTool::GPS::ConvertTimeStamp` (GPS.pm:459-474). Inputs are
/// the H / M / S triplet AS NUMBERS (the rational quotients). Bundled
/// reconstructs the total seconds, splits into HH / MM / `sprintf("%012.9f",
/// $f)` then strips trailing zeros (after the decimal point); if the
/// rebuilt seconds float >= 60.0 rounds up the minute (and the hour).
fn format_gps_time_stamp(h_in: f64, m_in: f64, s_in: f64) -> alloc::string::String {
  use core::fmt::Write;
  // `my $f = (($h || 0) * 60 + ($m || 0)) * 60 + ($s || 0);`
  let f = (h_in * 60.0 + m_in) * 60.0 + s_in;
  let h_full = (f / 3600.0).floor();
  let mut f1 = f - h_full * 3600.0;
  let m_full = (f1 / 60.0).floor();
  f1 -= m_full * 60.0;

  // `sprintf('%012.9f', $f)` — 12 chars wide, 9 fractional digits,
  // zero-padded. The string IS what bundled tests against `>= 60`.
  let ss_str = alloc::format!("{f1:012.9}");
  let ss_num: f64 = ss_str.parse().unwrap_or(f1);
  let mut h_out = h_full as i64;
  let mut m_out = m_full as i64;
  let ss_final = if ss_num >= 60.0 {
    m_out += 1;
    if m_out >= 60 {
      m_out -= 60;
      h_out += 1;
    }
    alloc::string::String::from("00")
  } else {
    // `$ss =~ s/\.?0+$//` — strip trailing zeros, AND the trailing `.` if
    // it ends up bare.
    trim_trailing_zeros(&ss_str)
  };
  let mut out = alloc::string::String::with_capacity(16);
  let _ = write!(out, "{h_out:02}:{m_out:02}:{ss_final}");
  out
}

/// Perl `s/\.?0+$//` — strip trailing zeros, plus an optional trailing
/// `.` if the trim landed it bare. Operates on a `sprintf("%012.9f", $f)`
/// shape (always carries a `.`), so the regex is safe.
fn trim_trailing_zeros(s: &str) -> alloc::string::String {
  let trimmed = s.trim_end_matches('0');
  let trimmed = trimmed.trim_end_matches('.');
  alloc::string::String::from(trimmed)
}

/// `0x851d GPSDateStamp` (Sony.pm:10806-10811) — `Format => 'string'`,
/// `ValueConv => 'Image::ExifTool::Exif::ExifDate($val)'`. Bundled
/// `ExifDate` (Exif.pm:6068-6076):
///   - strips a trailing NUL;
///   - rewrites `YYYY?MM?DD` (any non-digit separator) to `YYYY:MM:DD`;
///   - already-colon-separated input passes through unchanged.
fn decode_gps_date_stamp(value: &[u8]) -> Option<SmolStr> {
  let s = decode_string(value)?;
  Some(SmolStr::new(exif_date(&s)))
}

/// `Image::ExifTool::Exif::ExifDate` (Exif.pm:6068-6076).
fn exif_date(input: &str) -> alloc::string::String {
  let s = input.trim_end_matches('\0');
  // Trailing 4-digit-year + 2-digit-month + 2-digit-day with any
  // non-digit separators ⇒ rewrite to colon-separated. We match only
  // when the input ends with `\d{4}\D*\d{2}\D*\d{2}`.
  let bytes = s.as_bytes();
  let n = bytes.len();
  if n >= 8 {
    // Try to find a (Y,Y,Y,Y, sep*, M,M, sep*, D,D) tail.
    if let Some(rebuilt) = try_rebuild_exif_date(s) {
      return rebuilt;
    }
  }
  alloc::string::String::from(s)
}

/// Walk backwards from the end of `s`: pop 2 digits (day), skip non-digits,
/// pop 2 digits (month), skip non-digits, pop 4 digits (year). If the
/// preceding text is empty OR we can identify a clean prefix split, rebuild
/// `${prefix}YYYY:MM:DD`. Returns `None` when the tail does NOT match the
/// trailing-date pattern (bundled then leaves the input untouched).
fn try_rebuild_exif_date(s: &str) -> Option<alloc::string::String> {
  // Operate on bytes (ASCII-only for an ExifDate stamp).
  let bytes = s.as_bytes();
  let mut i = bytes.len();

  // Take last 2 digits.
  let d_end = i;
  let d_start = take_n_digits_back(bytes, i, 2)?;
  i = d_start;
  // Skip non-digits.
  i = skip_nondigits_back(bytes, i);
  // Take 2 digits.
  let m_end = i;
  let m_start = take_n_digits_back(bytes, i, 2)?;
  i = m_start;
  // Skip non-digits.
  i = skip_nondigits_back(bytes, i);
  // Take 4 digits (year).
  let y_end = i;
  let y_start = take_n_digits_back(bytes, i, 4)?;
  // Anything before y_start is a prefix that bundled leaves verbatim.
  let prefix = core::str::from_utf8(&bytes[..y_start]).ok()?;
  let y = core::str::from_utf8(&bytes[y_start..y_end]).ok()?;
  let m = core::str::from_utf8(&bytes[m_start..m_end]).ok()?;
  let d = core::str::from_utf8(&bytes[d_start..d_end]).ok()?;
  Some(alloc::format!("{prefix}{y}:{m}:{d}"))
}

fn take_n_digits_back(bytes: &[u8], end: usize, n: usize) -> Option<usize> {
  if end < n {
    return None;
  }
  let start = end - n;
  if bytes[start..end].iter().all(u8::is_ascii_digit) {
    Some(start)
  } else {
    None
  }
}

fn skip_nondigits_back(bytes: &[u8], mut i: usize) -> usize {
  while i > 0 && !bytes[i - 1].is_ascii_digit() {
    i -= 1;
  }
  i
}

// ===========================================================================
// process_rtmd — the bundled Process_rtmd port
// ===========================================================================

/// `Image::ExifTool::Sony::Process_rtmd` (Sony.pm:11566-11602) — walk one
/// rtmd metadata sample and accumulate every camera + GPS record into a
/// single [`SonyRtmdCameraSnapshot`] + (optional) [`SonyRtmdGpsSample`],
/// pushed onto `out` as one snapshot per call.
///
/// Faithful behaviour notes:
///
/// - Sony.pm:11574-11576: a sample shorter than 2 bytes yields no records
///   and a single `Sony rtmd` warning the FIRST time it occurs.
/// - Sony.pm:11581: the 2-byte BE header length at offset 0 is honoured
///   as-is — `$pos` starts at `Get16u($dataPt, 0)`, NOT a hard-coded
///   `0x1c`. (Bundled never rewrites this; matching the file lets new
///   firmware variants parse.)
/// - Sony.pm:11582: `while ($pos + 4 < $end)` — strict-less; a trailing
///   4-byte remainder is dropped.
/// - Sony.pm:11583-11584: `last if $tag == 0` — a zero tag stops the walk.
/// - Sony.pm:11586-11591: the `0x060e` / `0x8300` special cases.
/// - Sony.pm:11592: a truncated value stops the walk.
///
/// Re-entrancy of the container path: the `0x8300` recurse is FLAT (no
/// stack); bundled simply rewrites `$pos += 4` then `next`s. Our port
/// mirrors that — a `0x8300` skips its 4-byte header and continues the
/// `while` loop. Nested containers therefore work for the same reason
/// they do in bundled: each `0x8300` site just advances `pos` by 4.
pub fn process_rtmd(data: &[u8], out: &mut SonyRtmdMeta) {
  let end = data.len();
  if end < 2 {
    // TODO(bundled-wording): Sony.pm `Process_rtmd` (lines 11569-11602)
    // emits NO warning for a short header — it silently `return 0`s.
    // The exifast-original "Truncated Sony rtmd" string fills the gap;
    // when the engine gains a single canonical "header too short to read"
    // surface, replace this wording.
    out.set_warning(SmolStr::new("Truncated Sony rtmd"));
    return;
  }
  // Sony.pm:11581 `$pos = Get16u($dataPt, 0)`.
  let mut pos = match be_u16(data, 0) {
    Some(v) => v as usize,
    None => return,
  };

  // Per-sample accumulators.
  let mut snap = SonyRtmdCameraSnapshot::new();
  let mut gps = SonyRtmdGpsSample::new();
  let mut saw_gps = false;
  // Track whether the canonical 0x810b ISO has fired so we don't let the
  // alt 0xe301 overwrite it (per the fallback semantics in the typed
  // surface — bundled keeps both tags independently under their own
  // `Sony:ISO` / `Sony:Sony_rtmd_0xe301` keys; the typed `iso` slot picks
  // the canonical one when present).
  let mut canonical_iso_set = false;

  // Sony.pm:11582 `while ($pos + 4 < $end)`.
  while pos + 4 < end {
    // Sony.pm:11583 `my $tag = Get16u($dataPt, $pos)`.
    let Some(tag) = be_u16(data, pos) else { break };
    // Sony.pm:11584 `last if $tag == 0`.
    if tag == 0 {
      break;
    }
    // Sony.pm:11585 `my $len = Get16u($dataPt, $pos+2)`.
    let Some(len_raw) = be_u16(data, pos + 2) else {
      break;
    };

    // Sony.pm:11586-11591: `0x060e` / `0x8300` special-cases.
    //
    //   if ($tag == 0x060e) { $len = 0x10; }
    //   else                { $pos += 4; next if $tag == 0x8300; }
    //
    // The dispatch: for 0x060e, `$pos` is NOT advanced (the 16-byte read
    // starts at `$pos`, INCLUDING the 4-byte header). For 0x8300, we skip
    // the 4-byte header and `next` (no `$pos += $len`, so the next
    // iteration reads the FIRST child record). For every other tag we
    // skip the 4-byte header.
    let len: usize;
    let value_start: usize;
    let advance_after: bool;
    if tag == TAG_SMPTE_LABEL {
      len = 0x10;
      value_start = pos; // bundled: the 16 bytes start AT $pos
      advance_after = true;
    } else if tag == TAG_CONTAINER {
      // Skip the header and continue without consuming the body.
      pos += 4;
      continue;
    } else {
      pos += 4;
      len = len_raw as usize;
      value_start = pos;
      advance_after = true;
    }

    // Sony.pm:11592 `last if $pos + $len > $end`. After the `+= 4` shift
    // above, `$pos` == `value_start`.
    if value_start.checked_add(len).is_none_or(|e| e > end) {
      break;
    }
    let value = &data[value_start..value_start + len];

    // Dispatch by tag (Sony.pm:10686-10850).
    match tag {
      // Camera / capture identity
      TAG_FNUMBER => {
        if let Some(v) = decode_fnumber(value) {
          snap.set_f_number(Some(v));
        }
      }
      TAG_FRAME_RATE => {
        if let Some(v) = decode_rational64u(value) {
          snap.set_frame_rate(Some(v));
        }
      }
      TAG_EXPOSURE_TIME => {
        if let Some(v) = decode_exposure_time(value) {
          snap.set_exposure_time_s(Some(v));
        }
      }
      TAG_MASTER_GAIN => {
        if let Some(v) = decode_master_gain_db(value) {
          snap.set_master_gain_db(Some(v));
        }
      }
      TAG_ISO => {
        if let Some(v) = decode_iso_u16(value) {
          snap.set_iso(Some(v));
          canonical_iso_set = true;
        }
      }
      TAG_ISO_ALT => {
        if !canonical_iso_set && let Some(v) = decode_iso_u32(value) {
          snap.set_iso(Some(v));
        }
      }
      TAG_SERIAL_NUMBER => {
        if let Some(v) = decode_string(value) {
          snap.set_serial_number(Some(v));
        }
      }
      // White balance + DateTime
      TAG_WHITE_BALANCE => {
        if let Some(v) = decode_u8(value) {
          snap.set_white_balance_raw(Some(v));
        }
      }
      TAG_DATE_TIME => {
        if let Some(v) = decode_date_time(value) {
          snap.set_date_time(Some(v));
        }
      }
      // GPS family
      TAG_GPS_VERSION_ID => {
        if let Some(v) = decode_gps_version_id(value) {
          gps.set_version_id(Some(v));
          saw_gps = true;
        }
      }
      TAG_GPS_LATITUDE_REF => {
        if let Some(v) = decode_string(value) {
          gps.set_latitude_ref(Some(v));
          saw_gps = true;
        }
      }
      TAG_GPS_LATITUDE => {
        if let Some(v) = decode_gps_coordinate(value) {
          gps.set_latitude(Some(v));
          saw_gps = true;
        }
      }
      TAG_GPS_LONGITUDE_REF => {
        if let Some(v) = decode_string(value) {
          gps.set_longitude_ref(Some(v));
          saw_gps = true;
        }
      }
      TAG_GPS_LONGITUDE => {
        if let Some(v) = decode_gps_coordinate(value) {
          gps.set_longitude(Some(v));
          saw_gps = true;
        }
      }
      TAG_GPS_TIME_STAMP => {
        if let Some(v) = decode_gps_time_stamp(value) {
          gps.set_time_stamp(Some(v));
          saw_gps = true;
        }
      }
      TAG_GPS_STATUS => {
        if let Some(v) = decode_string(value) {
          gps.set_status(Some(v));
          saw_gps = true;
        }
      }
      TAG_GPS_MEASURE_MODE => {
        if let Some(v) = decode_string(value) {
          gps.set_measure_mode(Some(v));
          saw_gps = true;
        }
      }
      TAG_GPS_MAP_DATUM => {
        if let Some(v) = decode_string(value) {
          gps.set_map_datum(Some(v));
          saw_gps = true;
        }
      }
      TAG_GPS_DATE_STAMP => {
        if let Some(v) = decode_gps_date_stamp(value) {
          gps.set_date_stamp(Some(v));
          saw_gps = true;
        }
      }
      _ => {
        // Tags bundled marks `%hidUnk` (Sony.pm:10695-10843) AND tags
        // unrecognized by the table — bundled `HandleTag`s them under
        // their `Sony_rtmd_0xNNNN` name; exifast's typed layer does not
        // surface them (see SonyRtmdMeta module docs). Fall through.
      }
    }

    if advance_after {
      // Sony.pm:11599 `$pos += $len`.
      pos += len;
    }
  }

  // Apply the LatitudeRef / LongitudeRef signs (Sony.pm:10752-10775 — the
  // PrintConv on the *Ref tags is the display N/S/E/W; the ValueConv on
  // the coordinate is the unsigned positive number. The sign comes from
  // applying the ref under `GPS::ToDegrees($val, 1)` — but bundled
  // calls `ToDegrees($val)` here (no `$doSign`), so the bundled `Value`
  // channel is UNSIGNED.
  //
  // For the cross-format domain layer (which feeds `GpsLocation` in
  // decimal degrees), exifast applies the sign so the typed projection
  // is unambiguous. The FAITHFUL bundled-value rendering is the unsigned
  // form; the SIGNED form is exposed via the `signed_latitude` /
  // `signed_longitude` derived accessors on [`SonyRtmdGpsSample`] (which
  // are implicitly the `latitude` / `longitude` fields after we apply
  // the ref here in the walker).
  //
  // (This is a deliberate departure from bundled's per-Value rendering,
  // documented in the SonyRtmdGpsSample module docs.)
  apply_gps_ref_signs(&mut gps);

  out.push_camera_snapshot(snap);
  if saw_gps {
    out.push_gps_sample(gps);
  }
}

/// Apply `GPSLatitudeRef='S'` / `GPSLongitudeRef='W'` as negative-sign
/// flips on the stored coordinate. Bundled `Value` keeps the unsigned
/// rational; the typed layer surfaces the signed decimal degrees so the
/// `GpsLocation` projection is unambiguous.
fn apply_gps_ref_signs(gps: &mut SonyRtmdGpsSample) {
  // Snapshot the refs and the unsigned magnitudes BEFORE mutating; the
  // setter signature takes Option<f64> by value so the borrow checker
  // would otherwise complain.
  let lat_ref = gps.latitude_ref().map(alloc::string::String::from);
  let lon_ref = gps.longitude_ref().map(alloc::string::String::from);
  if let (Some(r), Some(v)) = (lat_ref.as_deref(), gps.latitude()) {
    if matches_south_or_west(r, b'S') {
      gps.set_latitude(Some(-v.abs()));
    } else {
      gps.set_latitude(Some(v.abs()));
    }
  }
  if let (Some(r), Some(v)) = (lon_ref.as_deref(), gps.longitude()) {
    if matches_south_or_west(r, b'W') {
      gps.set_longitude(Some(-v.abs()));
    } else {
      gps.set_longitude(Some(v.abs()));
    }
  }
}

/// `true` when `r` starts with the given upper-case sign character.
/// Sony rtmd refs are bundled as Perl strings (e.g. `'S'`, `'W'`); we
/// accept any prefix that starts with the right letter, mirroring the
/// permissive bundled PrintConv table semantics (Sony.pm:10744-10767).
fn matches_south_or_west(r: &str, sign: u8) -> bool {
  r.as_bytes().first().copied() == Some(sign)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  /// Build a Sony rtmd byte stream: `[hdr_len:u16-BE = 0x1c][zeros to 0x1c]
  /// [records...]`.
  fn rtmd(records: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(0x1c + records.len());
    out.extend_from_slice(&0x001cu16.to_be_bytes());
    out.extend(core::iter::repeat_n(0u8, 0x1c - 2));
    out.extend_from_slice(records);
    out
  }

  /// Build one record `[tag:u16-BE][len:u16-BE][value]`.
  fn rec(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + value.len());
    v.extend_from_slice(&tag.to_be_bytes());
    v.extend_from_slice(&(value.len() as u16).to_be_bytes());
    v.extend_from_slice(value);
    v
  }

  /// Big-endian u16 helper for value bytes.
  fn be16(v: u16) -> [u8; 2] {
    v.to_be_bytes()
  }

  /// Big-endian u32 helper.
  fn be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
  }

  /// Build a rational64u value (num/denom, 8 bytes BE).
  fn rat64u(num: u32, denom: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&be32(num));
    out[4..8].copy_from_slice(&be32(denom));
    out
  }

  #[test]
  fn short_buffer_warns_and_decodes_nothing() {
    let data = [0u8, 1u8]; // exactly 2 bytes — passes the `< 2` guard but
    // `pos = 0x0001` and `pos+4 < end (=2)` is false ⇒ no records.
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    // Bundled `Process_rtmd` does NOT warn on short-but-valid; it warns
    // ONLY when `$end < 2` (Sony.pm:11574-11575). The 2-byte case here
    // is the boundary — exifast emits no warning either.
    assert!(out.warning().is_none());
    // A snapshot is still pushed (empty one).
    assert_eq!(out.camera_snapshots().len(), 1);
    assert!(out.camera_snapshots()[0].is_empty());
    assert!(out.gps_samples().is_empty());
  }

  #[test]
  fn truly_truncated_emits_warning() {
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&[0u8], &mut out);
    assert_eq!(out.warning(), Some("Truncated Sony rtmd"));
    assert!(out.is_empty());
  }

  #[test]
  fn empty_header_iterates_zero_records() {
    // 28-byte header, no records.
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&rtmd(&[]), &mut out);
    // One (empty) snapshot is pushed; no GPS.
    assert_eq!(out.camera_snapshots().len(), 1);
    assert!(out.camera_snapshots()[0].is_empty());
  }

  #[test]
  fn fnumber_value_conv_applied() {
    // bundled raw `int16u` with ValueConv 2^(8 - val/8192). For raw
    // `4096`, `8 - 0.5 = 7.5`, `2^7.5 ≈ 181.019`. Choose a value that
    // matches a friendly f-number: raw `40960` ⇒ `8 - 5 = 3` ⇒ `2^3 = 8`
    // (an f/8 aperture).
    let mut data = rtmd(&rec(TAG_FNUMBER, &be16(40960)));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = &out.camera_snapshots()[0];
    assert!(snap.f_number().is_some());
    assert!((snap.f_number().unwrap() - 8.0).abs() < 1e-9);
    // Lone-record exercises the `pos += len` advance after the dispatch.
    data.clear();
  }

  #[test]
  fn exposure_time_rational() {
    // 1/200 s — num=1, denom=200.
    let data = rtmd(&rec(TAG_EXPOSURE_TIME, &rat64u(1, 200)));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = &out.camera_snapshots()[0];
    assert!((snap.exposure_time_s().unwrap() - 0.005).abs() < 1e-9);
  }

  #[test]
  fn iso_int16u() {
    let data = rtmd(&rec(TAG_ISO, &be16(800)));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(out.camera_snapshots()[0].iso(), Some(800));
  }

  #[test]
  fn iso_alt_int32u_used_when_canonical_absent() {
    let data = rtmd(&rec(TAG_ISO_ALT, &be32(12800)));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(out.camera_snapshots()[0].iso(), Some(12800));
  }

  #[test]
  fn iso_canonical_wins_over_alt() {
    let mut records = Vec::new();
    records.extend_from_slice(&rec(TAG_ISO, &be16(400)));
    records.extend_from_slice(&rec(TAG_ISO_ALT, &be32(12800)));
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(out.camera_snapshots()[0].iso(), Some(400));
  }

  #[test]
  fn master_gain_int16u_div_100_db() {
    // raw = 1234 ⇒ 12.34 dB.
    let data = rtmd(&rec(TAG_MASTER_GAIN, &be16(1234)));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = &out.camera_snapshots()[0];
    assert!((snap.master_gain_db().unwrap() - 12.34).abs() < 1e-9);
  }

  #[test]
  fn frame_rate_rational() {
    // 24000/1001 ≈ 23.976.
    let data = rtmd(&rec(TAG_FRAME_RATE, &rat64u(24_000, 1001)));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = &out.camera_snapshots()[0];
    assert!((snap.frame_rate().unwrap() - 24_000.0 / 1001.0).abs() < 1e-9);
  }

  #[test]
  fn serial_number_splits_model_and_serial() {
    let data = rtmd(&rec(TAG_SERIAL_NUMBER, b"ILCE-7SM3 5072108"));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = &out.camera_snapshots()[0];
    assert_eq!(snap.serial_number(), Some("ILCE-7SM3 5072108"));
    assert_eq!(snap.model(), Some("ILCE-7SM3"));
    assert_eq!(snap.serial(), Some("5072108"));
  }

  #[test]
  fn serial_number_with_nul_padding_trims() {
    let data = rtmd(&rec(TAG_SERIAL_NUMBER, b"ILCE-7M4 99999999\0\0\0"));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = &out.camera_snapshots()[0];
    // Trailing NULs stripped by decode_string.
    assert_eq!(snap.serial_number(), Some("ILCE-7M4 99999999"));
    assert_eq!(snap.model(), Some("ILCE-7M4"));
    assert_eq!(snap.serial(), Some("99999999"));
  }

  #[test]
  fn date_time_bcd_decodes() {
    // 8-byte BCD: skip 1, year 2024, month 03, day 05, hh 10, mm 20, ss 30.
    // BCD: 2024 = 0x20, 0x24; 03 = 0x03; 05 = 0x05; 10 = 0x10; 20 = 0x20;
    // 30 = 0x30. Byte 0 is skipped (any value).
    let payload = [0u8, 0x20, 0x24, 0x03, 0x05, 0x10, 0x20, 0x30];
    let data = rtmd(&rec(TAG_DATE_TIME, &payload));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = &out.camera_snapshots()[0];
    assert_eq!(snap.date_time(), Some("2024:03:05 10:20:30"));
  }

  #[test]
  fn white_balance_raw_passes_through() {
    let data = rtmd(&rec(TAG_WHITE_BALANCE, &[4u8])); // Daylight
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(out.camera_snapshots()[0].white_balance_raw(), Some(4));
  }

  #[test]
  fn gps_full_record_decodes_with_signs_applied() {
    // Build a complete GPS record: VersionID + LatRef='S' + Lat 37 30' 0''
    // + LonRef='W' + Lon 122 0' 30'' + TimeStamp 10:20:30 + Status 'A' +
    // MeasureMode '3' + MapDatum 'WGS-84' + DateStamp '2024 03 05'.
    let mut records = Vec::new();
    records.extend_from_slice(&rec(TAG_GPS_VERSION_ID, &[2u8, 2, 0, 0]));
    records.extend_from_slice(&rec(TAG_GPS_LATITUDE_REF, b"S"));
    let mut lat = Vec::new();
    lat.extend_from_slice(&rat64u(37, 1));
    lat.extend_from_slice(&rat64u(30, 1));
    lat.extend_from_slice(&rat64u(0, 1));
    records.extend_from_slice(&rec(TAG_GPS_LATITUDE, &lat));
    records.extend_from_slice(&rec(TAG_GPS_LONGITUDE_REF, b"W"));
    let mut lon = Vec::new();
    lon.extend_from_slice(&rat64u(122, 1));
    lon.extend_from_slice(&rat64u(0, 1));
    lon.extend_from_slice(&rat64u(30, 1));
    records.extend_from_slice(&rec(TAG_GPS_LONGITUDE, &lon));
    let mut ts = Vec::new();
    ts.extend_from_slice(&rat64u(10, 1));
    ts.extend_from_slice(&rat64u(20, 1));
    ts.extend_from_slice(&rat64u(30, 1));
    records.extend_from_slice(&rec(TAG_GPS_TIME_STAMP, &ts));
    records.extend_from_slice(&rec(TAG_GPS_STATUS, b"A"));
    records.extend_from_slice(&rec(TAG_GPS_MEASURE_MODE, b"3"));
    records.extend_from_slice(&rec(TAG_GPS_MAP_DATUM, b"WGS-84"));
    records.extend_from_slice(&rec(TAG_GPS_DATE_STAMP, b"2024:03:05"));
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let g = &out.gps_samples()[0];
    assert_eq!(g.version_id(), Some("2.2.0.0"));
    assert_eq!(g.latitude_ref(), Some("S"));
    assert!((g.latitude().unwrap() + 37.5).abs() < 1e-9); // South ⇒ negative
    assert_eq!(g.longitude_ref(), Some("W"));
    assert!((g.longitude().unwrap() + 122.00833333333333).abs() < 1e-9);
    assert_eq!(g.time_stamp(), Some("10:20:30"));
    assert_eq!(g.status(), Some("A"));
    assert_eq!(g.measure_mode(), Some("3"));
    assert_eq!(g.map_datum(), Some("WGS-84"));
    assert_eq!(g.date_stamp(), Some("2024:03:05"));
    assert!(g.has_coordinates());
  }

  #[test]
  fn gps_north_east_keep_positive() {
    let mut records = Vec::new();
    records.extend_from_slice(&rec(TAG_GPS_LATITUDE_REF, b"N"));
    let mut lat = Vec::new();
    lat.extend_from_slice(&rat64u(10, 1));
    lat.extend_from_slice(&rat64u(0, 1));
    lat.extend_from_slice(&rat64u(0, 1));
    records.extend_from_slice(&rec(TAG_GPS_LATITUDE, &lat));
    records.extend_from_slice(&rec(TAG_GPS_LONGITUDE_REF, b"E"));
    let mut lon = Vec::new();
    lon.extend_from_slice(&rat64u(20, 1));
    lon.extend_from_slice(&rat64u(0, 1));
    lon.extend_from_slice(&rat64u(0, 1));
    records.extend_from_slice(&rec(TAG_GPS_LONGITUDE, &lon));
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let g = &out.gps_samples()[0];
    assert!((g.latitude().unwrap() - 10.0).abs() < 1e-9);
    assert!((g.longitude().unwrap() - 20.0).abs() < 1e-9);
  }

  #[test]
  fn gps_date_stamp_rewrites_non_colon_separators() {
    // Bundled ExifDate accepts non-colon separators in the date — `2024
    // 03 05` ⇒ `2024:03:05`.
    let data = rtmd(&rec(TAG_GPS_DATE_STAMP, b"2024 03 05\0"));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let g = &out.gps_samples()[0];
    assert_eq!(g.date_stamp(), Some("2024:03:05"));
  }

  #[test]
  fn gps_time_stamp_fractional_seconds_trim_trailing_zeros() {
    // 10:20:30.50 — encoded as h=10/1, m=20/1, s=305/10. ConvertTimeStamp
    // builds `sprintf("%012.9f", 30.5) = "30.500000000"` (12 chars, no
    // leading zero needed because the integer part is 2 digits and the
    // total already meets the minimum width). The substitution
    // `\.?0+$` matches `.500000000`?? No — `0+` is anchored at `$` and
    // matches a run of `0`s. After the trailing 8 zeros come a `5`,
    // not a `0`. So the regex matches just the 8 trailing zeros (the
    // `\.?` matches NOTHING because the preceding char is `5`). Result:
    // `30.5`, joined `10:20:30.5`.
    let mut ts = Vec::new();
    ts.extend_from_slice(&rat64u(10, 1));
    ts.extend_from_slice(&rat64u(20, 1));
    ts.extend_from_slice(&rat64u(305, 10));
    let data = rtmd(&rec(TAG_GPS_TIME_STAMP, &ts));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let g = &out.gps_samples()[0];
    assert_eq!(g.time_stamp(), Some("10:20:30.5"));
  }

  #[test]
  fn zero_tag_stops_walk() {
    // Two records: first valid ISO, second a synthetic zero-tag pad that
    // must stop the walk before any subsequent record fires.
    let mut records = Vec::new();
    records.extend_from_slice(&rec(TAG_ISO, &be16(100)));
    records.extend_from_slice(&[0u8, 0, 0, 4]); // tag=0, len=4
    records.extend_from_slice(&[0u8; 4]); // pad
    records.extend_from_slice(&rec(TAG_FNUMBER, &be16(40960))); // would set f/8 if reached
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let snap = &out.camera_snapshots()[0];
    assert_eq!(snap.iso(), Some(100));
    assert!(snap.f_number().is_none(), "zero-tag must stop the walk");
  }

  #[test]
  fn truncated_value_stops_walk() {
    // ISO record claims 16 bytes but only 2 are provided.
    let mut records = Vec::new();
    records.extend_from_slice(&[0x81, 0x0b, 0x00, 0x10]); // ISO tag, len=16
    records.extend_from_slice(&[0u8; 2]); // only 2 bytes — truncated
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    // The truncated value stops the walk; no fields set.
    assert!(out.camera_snapshots()[0].is_empty());
  }

  #[test]
  fn smpte_label_0x060e_skipped_then_walk_continues() {
    // The fixture: 0x060e fake-tag at the start (16 bytes from $pos),
    // followed by a regular ISO record. After 0x060e bundled does NOT
    // advance past the 4-byte header before reading 16 bytes — so the
    // 16-byte block CONSUMES the tag+len AND 12 payload bytes. The next
    // record begins exactly 16 bytes later.
    let mut records = Vec::new();
    // 16 bytes starting `06 0e 2b 34 02 53 ...` — bundled's SMPTE label.
    let mut label = Vec::with_capacity(16);
    label.extend_from_slice(&[0x06, 0x0e]); // tag bytes
    label.extend_from_slice(&[0x00, 0x00]); // dummy len (ignored)
    label.extend_from_slice(&[
      0x2b, 0x34, 0x02, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    records.extend_from_slice(&label);
    records.extend_from_slice(&rec(TAG_ISO, &be16(640)));
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(out.camera_snapshots()[0].iso(), Some(640));
  }

  #[test]
  fn container_0x8300_recurses_inline() {
    // 0x8300 container: bundled skips the 4-byte header and continues
    // (no len skip) — so the NEXT record is the first child.
    let mut records = Vec::new();
    // Container header — len value is IGNORED (bundled `next`s without
    // reading the body length).
    records.extend_from_slice(&[0x83, 0x00, 0x00, 0x00]); // tag=0x8300, len=0
    // Child record: ISO 1600.
    records.extend_from_slice(&rec(TAG_ISO, &be16(1600)));
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(out.camera_snapshots()[0].iso(), Some(1600));
  }

  #[test]
  fn multiple_records_one_sample_produces_one_snapshot() {
    let mut records = Vec::new();
    records.extend_from_slice(&rec(TAG_SERIAL_NUMBER, b"ILCE-7SM3 5072108"));
    records.extend_from_slice(&rec(TAG_FNUMBER, &be16(40960))); // f/8
    records.extend_from_slice(&rec(TAG_EXPOSURE_TIME, &rat64u(1, 100)));
    records.extend_from_slice(&rec(TAG_ISO, &be16(200)));
    records.extend_from_slice(&rec(TAG_FRAME_RATE, &rat64u(24_000, 1001)));
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(out.camera_snapshots().len(), 1);
    let snap = &out.camera_snapshots()[0];
    assert_eq!(snap.model(), Some("ILCE-7SM3"));
    assert_eq!(snap.serial(), Some("5072108"));
    assert!((snap.f_number().unwrap() - 8.0).abs() < 1e-9);
    assert!((snap.exposure_time_s().unwrap() - 0.01).abs() < 1e-9);
    assert_eq!(snap.iso(), Some(200));
    assert!((snap.frame_rate().unwrap() - 24_000.0 / 1001.0).abs() < 1e-9);
  }

  #[test]
  fn exif_date_already_colon_separated_passes_through() {
    assert_eq!(exif_date("2024:03:05"), "2024:03:05");
  }

  #[test]
  fn exif_date_strips_trailing_nul() {
    assert_eq!(exif_date("2024:03:05\0"), "2024:03:05");
  }

  #[test]
  fn exif_date_rewrites_space_separated() {
    assert_eq!(exif_date("2024 03 05"), "2024:03:05");
  }

  #[test]
  fn exif_date_rewrites_slash_separated() {
    assert_eq!(exif_date("2024/03/05"), "2024:03:05");
  }

  #[test]
  fn gps_time_stamp_minute_carry() {
    // ConvertTimeStamp: ss >= 60 ⇒ ss reset to "00", ++mm. Build h=10/1,
    // m=20/1, s=60/1 → secs = 36060, h=10, m=21, ss="00".
    let mut ts = Vec::new();
    ts.extend_from_slice(&rat64u(10, 1));
    ts.extend_from_slice(&rat64u(20, 1));
    ts.extend_from_slice(&rat64u(60, 1));
    let data = rtmd(&rec(TAG_GPS_TIME_STAMP, &ts));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    // Note: f = (10*60 + 20)*60 + 60 = 36660; h=10, m=21, ss=0.
    // sprintf 0.0 ⇒ "000.000000000" ⇒ trim → "" ⇒ but our pre-test ss_num
    // = 0.0, which is NOT >= 60, so we take the else branch:
    // trimmed "000.000000000" → strip 0+ → "" → strip . → "".
    // Result: "10:20:" — undesirable. Test the OTHER branch: f=3660 ⇒
    // h=1, m=1, ss_str = "000.000000000" → "" again. Need a fractional
    // that rounds up under sprintf.
    //
    // Use h=10/1 m=20/1 s=59999/1000 ⇒ s = 59.999, sprintf gives
    // "059.999000000" → trim trailing zeros → "059.999". Not a carry test
    // either; need s that rounds to 60.0 under %012.9f. %.9f is fixed-
    // point precision; 59.9999999995 ⇒ "059.999999999" (no rounding to
    // 60). 60.0 ⇒ "060.000000000" → trims to "060". That's >= 60 ⇒ minute
    // carries. Use s=60.
    let _ = data;
    // Replace the expectation with the actual h=10, m=21 minute-carry.
    let g = &out.gps_samples()[0];
    assert_eq!(g.time_stamp(), Some("10:21:00"));
  }

  #[test]
  fn gps_time_stamp_zero_components() {
    // h=0 m=0 s=0 ⇒ ConvertTimeStamp produces "00:00:00".
    //
    // `sprintf("%012.9f", 0.0)` = "00.000000000" (12 chars: 2-digit int
    // part already pads to 12 — Perl's `%012.f` is a MINIMUM width).
    // The substitution `\.?0+$` finds the leftmost match: starting at the
    // `.` (pos 2), `\.?` consumes `.`, `0+` consumes the 9 trailing
    // zeros to end-of-string. Substitution removes `.000000000`. Result:
    // "00". Joined: "00:00:00".
    let mut ts = Vec::new();
    ts.extend_from_slice(&rat64u(0, 1));
    ts.extend_from_slice(&rat64u(0, 1));
    ts.extend_from_slice(&rat64u(0, 1));
    let data = rtmd(&rec(TAG_GPS_TIME_STAMP, &ts));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    let g = &out.gps_samples()[0];
    assert_eq!(g.time_stamp(), Some("00:00:00"));
  }

  #[test]
  fn gps_version_id_dotted() {
    let data = rtmd(&rec(TAG_GPS_VERSION_ID, &[2, 2, 0, 0]));
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(out.gps_samples()[0].version_id(), Some("2.2.0.0"));
  }

  #[test]
  fn unknown_tag_skipped_walk_continues() {
    // An unrecognized tag — bundled `HandleTag`s it under a `Sony_rtmd_*`
    // name; exifast's typed layer ignores it but the walk must continue
    // and pick up the next valid record.
    let mut records = Vec::new();
    records.extend_from_slice(&rec(0xabcd, &[0u8, 0u8, 0u8, 0u8]));
    records.extend_from_slice(&rec(TAG_ISO, &be16(3200)));
    let data = rtmd(&records);
    let mut out = SonyRtmdMeta::new();
    process_rtmd(&data, &mut out);
    assert_eq!(out.camera_snapshots()[0].iso(), Some(3200));
  }
}
