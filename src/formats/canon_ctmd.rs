// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "quicktime")]
//! Faithful port of `Image::ExifTool::Canon::ProcessCTMD`
//! (Canon.pm:10758-10804) — the Canon "Timed MetaData" walker shared by
//! the EOS R-line / EOS C-line (Cinema) bodies that write CTMD records into
//! CR3 / CRM / MP4 / MOV containers. Backed by the
//! `Image::ExifTool::Canon::CTMD` / `FocalInfo` / `ExposureInfo` tag tables
//! (Canon.pm:9790-9887).
//!
//! ## Record layout
//!
//! Each CTMD sample is a sequence of records of the shape
//!
//! ```text
//! [size:int32u-LE][type:int16u-LE][header:6 bytes][payload]
//! ```
//!
//! where `size` covers the whole record (including the 4-byte size field),
//! and `payload` is `size - 12` bytes long. ExifTool enters with
//! `SetByteOrder('II')` (Canon.pm:10765) — every multi-byte int is LE.
//!
//! Termination cases:
//!  - **`pos + 6 < dirLen`** is the loop guard (Canon.pm:10766); a record
//!    needs at least 6 readable bytes (size + type) before it can be
//!    classified.
//!  - **`size < 12`** ⇒ `Short CTMD record` warning, stop the walk
//!    (Canon.pm:10781).
//!  - **`pos + size > dirLen`** ⇒ `Truncated CTMD record` warning, stop
//!    the walk (Canon.pm:10782).
//!  - Trailing-byte residue (`pos != dirLen` after the loop) ⇒
//!    `Error parsing Canon CTMD data` warning, but the walker has already
//!    accumulated everything it could (Canon.pm:10802 — emitted at log
//!    level 1, AFTER `return 1`).
//!
//! ## Type dispatch
//!
//! Per `Canon.pm:9790-9830` the indexing-relevant record types are:
//!
//!  - **Type 1 — `TimeStamp`** (Canon.pm:9798-9806). The payload is
//!    `[skip:2][year:int16u-LE][month:u8][day:u8][hour:u8][min:u8][sec:u8]
//!    [centisec:u8]`. Bundled's `RawConv` (Canon.pm:9801-9804):
//!
//!    ```perl
//!    my $fmt = GetByteOrder() eq 'MM' ? 'x2nCCCCCC' : 'x2vCCCCCC';
//!    sprintf('%.4d:%.2d:%.2d %.2d:%.2d:%.2d.%.2d', unpack($fmt, $val));
//!    ```
//!
//!    `ProcessCTMD` sets `'II'`, so the year is the LE variant.
//!  - **Type 4 — `FocalInfo`** (Canon.pm:9853-9864). A binary table of
//!    one `rational32u` entry: `FocalLength` (`Get16u(num) /
//!    Get16u(denom)`).
//!  - **Type 5 — `ExposureInfo`** (Canon.pm:9866-9887). Binary table:
//!    - `FNumber` rational32u @ offset 0 (4 bytes total);
//!    - `ExposureTime` rational32u @ offset 4 (parent stride is `int32u`
//!      = 4 bytes; rational32u itself is 4 bytes);
//!    - `ISO` int32u @ offset 8 with `ValueConv => '$val & 0x7fffffff'`.
//!
//! Other types (3 / 10 / 11) are declared in the table but carry no `Tag`
//! entry; bundled `HandleTag`s only when `$$tagTablePtr{$type}` exists
//! (Canon.pm:10790). Types 7 / 8 / 9 (`ExifInfo*`) re-dispatch into the
//! TIFF walker — **DEFERRED** in this port (lives on the Exif chain).
//!
//! ## Re-entrancy
//!
//! `ProcessCTMD` is per-sample, single-pass; no recursion is involved at
//! the walker level. Each call yields ONE [`CanonCtmdSample`].
//!
//! ## GPS priority chain
//!
//! Canon CTMD does NOT currently surface GPS — Canon writes GPS via the
//! embedded Exif TIFF blocks (`ExifInfo7/8/9` → `GPSInfoIFD`), not CTMD
//! records directly. That decode is deferred to the Exif chain (#82).
//! When it lands, the Canon-CTMD GPS would slot at the same tier as Sony
//! rtmd in the cross-port priority chain (Canon body, phone-paired GPS
//! similar to Sony's Imaging Edge Mobile model). Today's CTMD projection
//! only surfaces CameraInfo (Make=Canon), CaptureSettings (FNumber /
//! ExposureTime / ISO) and LensInfo (FocalLength).

extern crate alloc;

use smol_str::SmolStr;

use crate::metadata::{CanonCtmdExposure, CanonCtmdFocal, CanonCtmdMeta, CanonCtmdSample};

// ===========================================================================
// Little-endian readers (Canon CTMD is `SetByteOrder('II')`, Canon.pm:10765)
// ===========================================================================

fn le_u16(b: &[u8], off: usize) -> Option<u16> {
  b.get(off..off + 2)
    .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn le_u32(b: &[u8], off: usize) -> Option<u32> {
  b.get(off..off + 4)
    .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

// ===========================================================================
// Record types (Canon.pm:9790-9830)
// ===========================================================================

const TYPE_TIMESTAMP: u16 = 1;
const TYPE_FOCAL_INFO: u16 = 4;
const TYPE_EXPOSURE_INFO: u16 = 5;
// 7 / 8 / 9 are ExifInfo* — DEFERRED (TIFF re-dispatch on the Exif chain).
// 3, 10, 11 are declared placeholders without a Tag entry — bundled skips
// them via `if ($$tagTablePtr{$type})` (Canon.pm:10790).

// ===========================================================================
// Per-record decoders
// ===========================================================================

/// Decode the type-1 `TimeStamp` payload (Canon.pm:9798-9806).
///
/// Payload is `[skip:2][year:int16u-LE][month:u8][day:u8][hour:u8]
/// [min:u8][sec:u8][centisec:u8]` — 10 bytes minimum. Returns the
/// pre-`ConvertDateTime` `"YYYY:MM:DD HH:MM:SS.cc"` string.
///
/// We honour Canon.pm:9803 `sprintf('%.4d:%.2d:%.2d %.2d:%.2d:%.2d.%.2d',
/// ...)`. Note: `%.4d` in Perl is "minimum width 4, integer formatting" —
/// equivalent to Rust's `{:04}` (zero-padded to 4 digits) for non-negative
/// inputs. The seven decimal-second `%.2d` ones are likewise `{:02}`.
fn decode_time_stamp(value: &[u8]) -> Option<SmolStr> {
  if value.len() < 10 {
    return None;
  }
  // x2: skip the first 2 bytes of the payload.
  let year = le_u16(value, 2)? as u32;
  let mo = value[4] as u32;
  let d = value[5] as u32;
  let h = value[6] as u32;
  let mi = value[7] as u32;
  let s = value[8] as u32;
  let cs = value[9] as u32;
  let mut out = alloc::string::String::with_capacity(22);
  use core::fmt::Write;
  // Bundled `%.4d` is "minimum width 4, integer" — Perl pads with zeros
  // when a precision specifier is given on an integer. `{:04}` matches.
  let _ = write!(
    out,
    "{year:04}:{mo:02}:{d:02} {h:02}:{mi:02}:{s:02}.{cs:02}"
  );
  Some(SmolStr::new(out))
}

/// Decode `Get16u(num) / Get16u(denom)` (Canon.pm:6089-6094) — the
/// `rational32u` format used inside the Canon CTMD binary subtables.
/// Zero denominator with non-zero numerator returns `inf` (bundled's
/// `return $ratNumer ? 'inf' : 'undef'`), surfaced as `f64::INFINITY`;
/// `0/0` returns `f64::NAN` (the canonical "undef" lowering used elsewhere
/// in the typed layer).
fn decode_rational32u(value: &[u8], off: usize) -> Option<f64> {
  let num = le_u16(value, off)? as f64;
  let denom = le_u16(value, off + 2)? as f64;
  if denom == 0.0 {
    return Some(if num == 0.0 { f64::NAN } else { f64::INFINITY });
  }
  Some(num / denom)
}

/// Decode the type-4 `FocalInfo` payload (Canon.pm:9853-9864).
///
/// Binary table with `FORMAT => 'int32u'` (4-byte stride) and one entry at
/// index 0: `FocalLength` `rational32u` (4 bytes total). Returns `None`
/// when the payload is too short to fit the rational.
fn decode_focal_info(value: &[u8]) -> Option<CanonCtmdFocal> {
  let focal_length = decode_rational32u(value, 0)?;
  let mut out = CanonCtmdFocal::new();
  out.set_focal_length_mm(Some(focal_length));
  Some(out)
}

/// Decode the type-5 `ExposureInfo` payload (Canon.pm:9866-9887).
///
/// Binary table with `FORMAT => 'int32u'` (4-byte stride):
///  - index 0: `FNumber` rational32u at offset 0;
///  - index 1: `ExposureTime` rational32u at offset 4 (stride 4 × 1 = 4);
///  - index 2: `ISO` int32u at offset 8 with `ValueConv =>
///    '$val & 0x7fffffff'` (Canon.pm:9885).
///
/// Returns an empty record (`is_empty()`) when the payload is shorter
/// than 4 bytes — matching bundled's ProcessBinaryData early-out
/// (`last if $more <= 0`, ExifTool.pm:9953). A partial payload (4 ≤ len <
/// 12) yields a partially-populated record (the early fields decode, the
/// later ones stay `None`).
fn decode_exposure_info(value: &[u8]) -> Option<CanonCtmdExposure> {
  let mut out = CanonCtmdExposure::new();
  let mut any = false;
  if value.len() >= 4
    && let Some(v) = decode_rational32u(value, 0)
  {
    out.set_f_number(Some(v));
    any = true;
  }
  if value.len() >= 8
    && let Some(v) = decode_rational32u(value, 4)
  {
    out.set_exposure_time_s(Some(v));
    any = true;
  }
  if value.len() >= 12
    && let Some(raw) = le_u32(value, 8)
  {
    // Canon.pm:9885 `ValueConv => '$val & 0x7fffffff'`.
    out.set_iso(Some(raw & 0x7fff_ffff));
    any = true;
  }
  if any { Some(out) } else { None }
}

// ===========================================================================
// process_ctmd — the bundled ProcessCTMD port
// ===========================================================================

/// `Image::ExifTool::Canon::ProcessCTMD` (Canon.pm:10758-10804) — walk one
/// CTMD timed-metadata sample and accumulate every camera-indexing-relevant
/// record into a single [`CanonCtmdSample`], pushed onto `out` as one
/// sample per call.
///
/// Faithful behaviour notes:
///
/// - Canon.pm:10765 `SetByteOrder('II')` — every multi-byte int is LE.
/// - Canon.pm:10766 `while ($pos + 6 < $dirLen)` — strict-less; a record
///   needs at least the 4-byte size + 2-byte type readable past `$pos`.
/// - Canon.pm:10767 `$size = Get32u($dataPt, $pos)`.
/// - Canon.pm:10768 `$type = Get16u($dataPt, $pos + 4)`.
/// - Canon.pm:10781 `$size < 12` ⇒ `Short CTMD record` warning + stop.
/// - Canon.pm:10782 `$pos + $size > $dirLen` ⇒ `Truncated CTMD record`
///   warning + stop.
/// - Canon.pm:10790-10796 `HandleTag(..., Start => $pos + 12, Size => $size
///   - 12, ...)` — the value payload starts AFTER the 12-byte (size + type
///   + opaque 6-byte) prefix.
/// - Canon.pm:10800 `$pos += $size` — record-by-record advance.
/// - Canon.pm:10802 `$et->Warn('Error parsing Canon CTMD data', 1) if $pos
///   != $dirLen` — a trailing-byte residue is reported, but is non-fatal
///   (bundled returns 1 either way).
///
/// Re-entrancy: per-sample, single-pass; the walker yields exactly ONE
/// [`CanonCtmdSample`] (which itself may carry a TimeStamp + FocalInfo +
/// ExposureInfo all decoded from this call).
pub fn process_ctmd(data: &[u8], out: &mut CanonCtmdMeta) {
  let dir_len = data.len();
  let mut pos = 0usize;

  let mut sample = CanonCtmdSample::new();

  // Canon.pm:10766 `while ($pos + 6 < $dirLen)`.
  while pos + 6 < dir_len {
    // Canon.pm:10767-10768 `$size = Get32u($dataPt, $pos); $type = Get16u
    // ($dataPt, $pos + 4);`.
    let Some(size) = le_u32(data, pos) else { break };
    let Some(type_) = le_u16(data, pos + 4) else {
      break;
    };
    let size = size as usize;

    // Canon.pm:10781 `$size < 12 and $et->Warn('Short CTMD record'), last`.
    if size < 12 {
      out.set_warning(SmolStr::new("Short CTMD record"));
      break;
    }
    // Canon.pm:10782 `$pos + $size > $dirLen and $et->Warn('Truncated CTMD
    // record'), last`.
    if pos.checked_add(size).is_none_or(|e| e > dir_len) {
      out.set_warning(SmolStr::new("Truncated CTMD record"));
      break;
    }

    // Canon.pm:10790-10796 — value payload starts at `pos + 12`, size
    // `size - 12`.
    let value_start = pos + 12;
    let value_end = pos + size;
    let value = &data[value_start..value_end];

    // Canon.pm:10790 `if ($$tagTablePtr{$type})` — bundled only HandleTags
    // for types declared in the table. Types 3 / 10 / 11 carry comments
    // but NO `Tag` entry; they're skipped silently here.
    match type_ {
      TYPE_TIMESTAMP => {
        if let Some(ts) = decode_time_stamp(value) {
          sample.set_time_stamp(Some(ts));
        }
      }
      TYPE_FOCAL_INFO => {
        if let Some(f) = decode_focal_info(value) {
          sample.set_focal(Some(f));
        }
      }
      TYPE_EXPOSURE_INFO => {
        if let Some(e) = decode_exposure_info(value) {
          sample.set_exposure(Some(e));
        }
      }
      // 7 / 8 / 9: ExifInfo* — DEFERRED (TIFF re-dispatch, Exif chain).
      // 3 / 10 / 11 / unknown: bundled has no Tag → no decode.
      _ => {}
    }

    // Canon.pm:10800 `$pos += $size`.
    pos += size;
  }

  // Canon.pm:10802 `$et->Warn('Error parsing Canon CTMD data', 1) if $pos
  // != $dirLen` — the `1` is the bundled log level; we surface the
  // warning regardless (the typed layer keeps only the first warning).
  if pos != dir_len {
    out.set_warning(SmolStr::new("Error parsing Canon CTMD data"));
  }

  out.push_sample(sample);
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  // ---------- record builders ----------

  /// Build one CTMD record `[size:u32-LE][type:u16-LE][6 opaque header
  /// bytes][payload]`.
  fn ctmd_record(type_: u16, header: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let size = 12 + payload.len();
    let mut v = Vec::with_capacity(size);
    v.extend_from_slice(&(size as u32).to_le_bytes());
    v.extend_from_slice(&type_.to_le_bytes());
    v.extend_from_slice(&header);
    v.extend_from_slice(payload);
    v
  }

  fn opaque_header() -> [u8; 6] {
    [0, 0, 0, 1, 0xff, 0xff]
  }

  // ---------- decoder unit tests ----------

  #[test]
  fn decode_time_stamp_matches_perl_fixture() {
    // From the CanonRaw.cr3 fixture (perl exiftool -v3 dump):
    //   payload bytes: `00 00 e2 07 02 15 0c 08 38 15 00 00`
    //   ⇒ skip 2, year=0x07e2 LE = 2018, month=2, day=21, hour=12 (0x0c),
    //     min=8, sec=56 (0x38), centisec=21 (0x15).
    //   ⇒ "2018:02:21 12:08:56.21".
    let payload = [
      0x00, 0x00, 0xe2, 0x07, 0x02, 0x15, 0x0c, 0x08, 0x38, 0x15, 0x00, 0x00,
    ];
    let ts = decode_time_stamp(&payload).expect("decoded");
    assert_eq!(ts.as_str(), "2018:02:21 12:08:56.21");
  }

  #[test]
  fn decode_time_stamp_too_short_returns_none() {
    let payload = [0u8; 9];
    assert!(decode_time_stamp(&payload).is_none());
  }

  #[test]
  fn decode_time_stamp_pads_year_and_centisec() {
    // year=99 (0x63 00), month=1, day=1, hour=0, min=0, sec=0, cs=1.
    let payload = [
      0x00, 0x00, 0x63, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    ];
    let ts = decode_time_stamp(&payload).expect("decoded");
    assert_eq!(ts.as_str(), "0099:01:01 00:00:00.01");
  }

  #[test]
  fn decode_focal_info_matches_perl_fixture() {
    // Real CR3 bytes: `0f 00 01 00 ff ff ff ff ff ff ff ff` ⇒ FocalLength
    // rational32u = (15, 1) = 15.0mm.
    let payload = [
      0x0f, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    let f = decode_focal_info(&payload).expect("decoded");
    assert!((f.focal_length_mm().unwrap() - 15.0).abs() < 1e-9);
  }

  #[test]
  fn decode_focal_info_too_short_returns_none() {
    let payload = [0x0fu8, 0x00];
    assert!(decode_focal_info(&payload).is_none());
  }

  #[test]
  fn decode_exposure_info_matches_perl_fixture() {
    // Real CR3 bytes (28 bytes payload):
    //   `23 00 0a 00 01 00 50 00 00 32 00 00 01 00 00 00 ff ff ff ff
    //    00 00 00 00 ff ff ff ff`
    //  - FNumber = rational32u(0x0023, 0x000a) = 35 / 10 = 3.5.
    //  - ExposureTime = rational32u(0x0001, 0x0050) = 1 / 80 = 0.0125.
    //  - ISO = int32u(0x00003200) & 0x7fffffff = 12800.
    let payload = [
      0x23, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x50, 0x00, 0x00, 0x32, 0x00, 0x00, 0x01, 0x00, 0x00,
      0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    ];
    let e = decode_exposure_info(&payload).expect("decoded");
    assert!((e.f_number().unwrap() - 3.5).abs() < 1e-9);
    assert!((e.exposure_time_s().unwrap() - 1.0 / 80.0).abs() < 1e-9);
    assert_eq!(e.iso(), Some(12800));
  }

  #[test]
  fn decode_exposure_info_iso_high_bit_masked() {
    // ISO = 0x80003200 ⇒ post-mask = 0x00003200 = 12800.
    let payload = [
      0x23, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x50, 0x00, 0x00, 0x32, 0x00, 0x80,
    ];
    let e = decode_exposure_info(&payload).expect("decoded");
    assert_eq!(e.iso(), Some(12800));
  }

  #[test]
  fn decode_exposure_info_partial_payload_decodes_prefix_only() {
    // Only 4 bytes ⇒ FNumber only.
    let payload = [0x23, 0x00, 0x0a, 0x00];
    let e = decode_exposure_info(&payload).expect("decoded");
    assert!((e.f_number().unwrap() - 3.5).abs() < 1e-9);
    assert!(e.exposure_time_s().is_none());
    assert!(e.iso().is_none());
  }

  #[test]
  fn decode_rational32u_zero_denominator_with_nonzero_num_is_inf() {
    let bytes = [0x01, 0x00, 0x00, 0x00];
    let v = decode_rational32u(&bytes, 0).unwrap();
    assert!(v.is_infinite());
  }

  #[test]
  fn decode_rational32u_zero_over_zero_is_nan() {
    let bytes = [0x00u8; 4];
    let v = decode_rational32u(&bytes, 0).unwrap();
    assert!(v.is_nan());
  }

  // ---------- walker tests ----------

  #[test]
  fn process_ctmd_decodes_real_fixture_record_sequence() {
    // Mirror the real CR3 fixture (CanonRaw.cr3): TimeStamp + Focal +
    // Exposure (the type-3 / type-7 placeholders are walked but not
    // decoded).
    let ts_payload = [
      0x00, 0x00, 0xe2, 0x07, 0x02, 0x15, 0x0c, 0x08, 0x38, 0x15, 0x00, 0x00,
    ];
    let focal_payload = [
      0x0f, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    let exp_payload = [
      0x23, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x50, 0x00, 0x00, 0x32, 0x00, 0x00, 0x01, 0x00, 0x00,
      0x00,
    ];
    let mut data = Vec::new();
    data.extend_from_slice(&ctmd_record(1, opaque_header(), &ts_payload));
    data.extend_from_slice(&ctmd_record(4, opaque_header(), &focal_payload));
    data.extend_from_slice(&ctmd_record(5, opaque_header(), &exp_payload));
    let mut out = CanonCtmdMeta::new();
    process_ctmd(&data, &mut out);
    assert!(out.warning().is_none(), "no warnings on clean fixture");
    assert_eq!(out.samples().len(), 1);
    let s = &out.samples()[0];
    assert_eq!(s.time_stamp(), Some("2018:02:21 12:08:56.21"));
    let f = s.focal().expect("focal");
    assert!((f.focal_length_mm().unwrap() - 15.0).abs() < 1e-9);
    let e = s.exposure().expect("exposure");
    assert!((e.f_number().unwrap() - 3.5).abs() < 1e-9);
    assert!((e.exposure_time_s().unwrap() - 1.0 / 80.0).abs() < 1e-9);
    assert_eq!(e.iso(), Some(12800));
  }

  #[test]
  fn process_ctmd_short_record_warns_and_stops() {
    // size = 10 < 12 ⇒ `Short CTMD record` warning + stop. We need a
    // record where the size field claims < 12; the loop guard `pos + 6 <
    // dirLen` permits the read (4-byte size + 2-byte type are readable).
    let mut data = Vec::with_capacity(8);
    data.extend_from_slice(&10u32.to_le_bytes()); // size = 10
    data.extend_from_slice(&1u16.to_le_bytes()); // type = 1
    // Pad so the `pos+6<dirLen` guard isn't the early-out.
    data.extend_from_slice(&[0u8; 4]);
    let mut out = CanonCtmdMeta::new();
    process_ctmd(&data, &mut out);
    assert_eq!(out.warning(), Some("Short CTMD record"));
    // The sample is still pushed (empty).
    assert_eq!(out.samples().len(), 1);
    assert!(out.samples()[0].is_empty());
  }

  #[test]
  fn process_ctmd_truncated_record_warns_and_stops() {
    // size = 100, but only ~20 bytes available ⇒ truncated.
    let mut data = Vec::with_capacity(20);
    data.extend_from_slice(&100u32.to_le_bytes()); // size = 100
    data.extend_from_slice(&1u16.to_le_bytes()); // type = 1
    data.extend_from_slice(&[0u8; 14]); // 14 more bytes, total = 20
    let mut out = CanonCtmdMeta::new();
    process_ctmd(&data, &mut out);
    assert_eq!(out.warning(), Some("Truncated CTMD record"));
    assert_eq!(out.samples().len(), 1);
    assert!(out.samples()[0].is_empty());
  }

  #[test]
  fn process_ctmd_unknown_type_skipped_walk_continues() {
    // Build a sequence: type=99 (no decoder) + type=1 (TimeStamp). The
    // walker must advance past type 99 and decode type 1.
    let ts_payload = [
      0x00, 0x00, 0xe2, 0x07, 0x02, 0x15, 0x0c, 0x08, 0x38, 0x15, 0x00, 0x00,
    ];
    let unknown_payload = [0u8; 8];
    let mut data = Vec::new();
    data.extend_from_slice(&ctmd_record(99, opaque_header(), &unknown_payload));
    data.extend_from_slice(&ctmd_record(1, opaque_header(), &ts_payload));
    let mut out = CanonCtmdMeta::new();
    process_ctmd(&data, &mut out);
    assert!(out.warning().is_none());
    assert_eq!(
      out.samples()[0].time_stamp(),
      Some("2018:02:21 12:08:56.21")
    );
  }

  #[test]
  fn process_ctmd_type3_placeholder_walked_silently() {
    // Type 3 IS commented in bundled (Canon.pm:9807) but has NO Tag entry;
    // the walker advances past it without decoding anything and without
    // a warning. Pair with a type-1 to verify the walker survives.
    let placeholder_payload = [0xff, 0xff, 0xff, 0xff]; // 4 bytes, real-world shape
    let ts_payload = [
      0x00, 0x00, 0xe2, 0x07, 0x02, 0x15, 0x0c, 0x08, 0x38, 0x15, 0x00, 0x00,
    ];
    let mut data = Vec::new();
    data.extend_from_slice(&ctmd_record(3, opaque_header(), &placeholder_payload));
    data.extend_from_slice(&ctmd_record(1, opaque_header(), &ts_payload));
    let mut out = CanonCtmdMeta::new();
    process_ctmd(&data, &mut out);
    assert!(out.warning().is_none());
    assert_eq!(
      out.samples()[0].time_stamp(),
      Some("2018:02:21 12:08:56.21")
    );
  }

  #[test]
  fn process_ctmd_trailing_byte_residue_warns_after_decode() {
    // A full record + 5 trailing bytes (< 6, so the loop exits the
    // `pos + 6 < dirLen` guard without consuming them). Bundled emits
    // `Error parsing Canon CTMD data` (Canon.pm:10802) since `pos !=
    // dirLen` after the walk.
    let ts_payload = [
      0x00, 0x00, 0xe2, 0x07, 0x02, 0x15, 0x0c, 0x08, 0x38, 0x15, 0x00, 0x00,
    ];
    let mut data = ctmd_record(1, opaque_header(), &ts_payload);
    data.extend_from_slice(&[0u8; 5]);
    let mut out = CanonCtmdMeta::new();
    process_ctmd(&data, &mut out);
    // The decode happens first, then the trailing-residue warning fires
    // (but only because no earlier warning was set).
    assert_eq!(out.warning(), Some("Error parsing Canon CTMD data"));
    assert_eq!(
      out.samples()[0].time_stamp(),
      Some("2018:02:21 12:08:56.21")
    );
  }

  #[test]
  fn process_ctmd_empty_buffer_pushes_empty_sample_no_warning() {
    let mut out = CanonCtmdMeta::new();
    process_ctmd(&[], &mut out);
    assert!(out.warning().is_none());
    // One (empty) sample is always pushed per call.
    assert_eq!(out.samples().len(), 1);
    assert!(out.samples()[0].is_empty());
  }

  #[test]
  fn process_ctmd_buffer_smaller_than_6_bytes_warns_trailing_residue() {
    // 5 bytes — the loop guard (`pos + 6 < dirLen`) fails on first iter
    // so no record is walked. After the loop, `pos (0) != dirLen (5)`
    // ⇒ Canon.pm:10802 `Error parsing Canon CTMD data` warning fires
    // (bundled has no separate guard for "dirLen too small for any
    // record"; the trailing-residue check is the only post-loop warning).
    let mut out = CanonCtmdMeta::new();
    process_ctmd(&[0u8; 5], &mut out);
    assert_eq!(out.warning(), Some("Error parsing Canon CTMD data"));
    assert_eq!(out.samples().len(), 1);
    assert!(out.samples()[0].is_empty());
  }
}
