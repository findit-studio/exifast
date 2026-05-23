// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "quicktime")]
//! Faithful port of `Image::ExifTool::QuickTime::ProcessCAMM`
//! (`QuickTimeStream.pl:3481-3506`) — the Google Camera Motion Metadata
//! (CAMM) parser shared by the seven `%QuickTime::camm0..camm7` tag tables
//! (QuickTimeStream.pl:405-572).
//!
//! ## Packet layout
//!
//! A CAMM record is `[reserved:2][type:int16u-le:2][payload]` (the spec
//! reserves the first 2 bytes; bundled accepts non-zero leading bytes since
//! the dispatch `Condition` in `%processByMetaFormat` uses `/^..\xNN\0/s`
//! at QuickTimeStream.pl:255-308). All multi-byte fields BEYOND the header
//! are LITTLE-ENDIAN (the SubDirectory entries declare
//! `ByteOrder => 'Little-Endian'`, QuickTimeStream.pl:258, 265, ...).
//!
//! ## Size table (QuickTimeStream.pl:3491)
//!
//! Bundled stores HEADER-INCLUDED packet sizes:
//!
//! ```text
//!   %size = ( 1 => 12, 2 => 16, 3 => 16, 4 => 16,
//!             5 => 28, 6 => 60, 7 => 16 );
//! ```
//!
//! **Type 0 is NOT in the table.** Bundled's loop (line 3494-3495) thus
//! ABORTS the whole sample with `"Unknown camm record type 0"` on the
//! first type-0 packet. exifast preserves that behaviour for parity —
//! see [`process_camm`].
//!
//! ## What this module emits
//!
//! For each well-typed packet, [`process_camm`] pushes one typed value
//! onto the corresponding `Vec` in [`crate::metadata::CammMeta`]:
//!
//! | type | shape                                  | dest field         |
//! | ---- | -------------------------------------- | ------------------ |
//! |  1   | `i32 ns + i32 ns` (exposure / skew)    | `exposure`         |
//! |  2   | `f32[3]` (AngularVelocity, rad/s)      | `angular_velocity` |
//! |  3   | `f32[3]` (Acceleration, m/s²)          | `acceleration`     |
//! |  4   | `f32[3]` (Position)                    | `position`         |
//! |  5   | `f64 lat + f64 lon + f64 alt`          | `gps_samples` (pt=5)|
//! |  6   | `f64 dt + u32 mm + 2×f64 + 7×f32`      | `gps_samples` (pt=6)|
//! |  7   | `f32[3]` (MagneticField, µT)           | `magnetic_field`   |
//!
//! ## GPSDateTime (type-6) epoch correction
//!
//! Bundled `camm6.GPSDateTime` (QuickTimeStream.pl:508-526) reads the
//! `double` as either GPS-epoch (Jan 6 1980) or Unix-epoch seconds. The
//! heuristic: if `$$self{CreateDate} - $val > 24*3600*365*5` (the CreateDate
//! is far ahead of the timestamp), the value is a GPS-epoch number — add
//! `315964800` to get Unix seconds. Otherwise leave it alone (Unix-epoch
//! input). Then format via `ConvertUnixTime($val, 0, -6) . 'Z'`. exifast
//! mirrors that heuristic in [`format_camm6_gps_datetime`].
//!
//! ## Entry point
//!
//! [`process_camm`] takes a single timed-metadata sample's bytes and emits
//! into a [`crate::metadata::CammMeta`]. The caller dispatches each sample
//! via the QuickTime walker (see `quicktime_stream.rs::decode_one_sample`).
//!
//! ## GPS priority chain
//!
//! Android CAMM feeds the **SECOND-HIGHEST tier** of the cross-port GPS
//! priority chain that [`crate::metadata::MediaMetadata`] projects from a
//! QuickTime file: GoPro GPMF → Android CAMM → Sony rtmd → Insta360
//! trailer → Parrot mett → SP3 stream. CAMM ranks below GoPro (an Android
//! recording that also carries a GoPro track is rare; GoPro stays
//! authoritative) and above Sony rtmd / Insta360 / SP3 because CAMM is
//! the on-device-hardware tier — the camm5/camm6 records come from the
//! Android device's own GNSS.

extern crate alloc;
use alloc::string::String;

use crate::{
  datetime::{convert_datetime, convert_unix_time},
  metadata::{CammExposure, CammGpsSample, CammMeta, CammVector3},
  value::perl_nonfinite_str,
};

// ===========================================================================
// QuickTime ↔ Unix epoch offsets
// ===========================================================================

/// Seconds between the GPS epoch (Jan 6, 1980) and the Unix epoch
/// (Jan 1, 1970). QuickTimeStream.pl:518 `my $offset = 315964800;`.
const GPS_TO_UNIX_OFFSET_S: f64 = 315_964_800.0;

/// Five-year-in-seconds threshold for the GPS-vs-Unix-epoch heuristic
/// (QuickTimeStream.pl:519 `24 * 3600 * 365 * 5`).
const FIVE_YEARS_S: f64 = 24.0 * 3600.0 * 365.0 * 5.0;

/// QuickTime epoch offset: seconds between 1904-01-01 and 1970-01-01.
/// `(66 * 365 + 17) * 24 * 3600` — QuickTime.pm:1361. Used to convert a
/// `mvhd` raw CreateDate (1904-epoch) to Unix seconds for the camm6
/// GPS-epoch heuristic.
const QT_EPOCH_OFFSET_S: f64 = ((66 * 365 + 17) * 24 * 3600) as f64;

// ===========================================================================
// Little-endian readers (camm is declared LE throughout)
// ===========================================================================

// `get(..)` yields an exactly-N-byte slice; `try_into` to a fixed-size array
// keeps each read free of raw indexing (the `formats` file-level
// `#![deny(clippy::indexing_slicing)]`).
fn le_u16(b: &[u8], off: usize) -> Option<u16> {
  b.get(off..off + 2)?.try_into().ok().map(u16::from_le_bytes)
}

fn le_u32(b: &[u8], off: usize) -> Option<u32> {
  b.get(off..off + 4)?.try_into().ok().map(u32::from_le_bytes)
}

fn le_i32(b: &[u8], off: usize) -> Option<i32> {
  le_u32(b, off).map(|v| v as i32)
}

fn le_f32(b: &[u8], off: usize) -> Option<f32> {
  b.get(off..off + 4)?.try_into().ok().map(f32::from_le_bytes)
}

fn le_f64(b: &[u8], off: usize) -> Option<f64> {
  b.get(off..off + 8)?.try_into().ok().map(f64::from_le_bytes)
}

// ===========================================================================
// Per-type decoders
// ===========================================================================

/// Decode a CAMM type-1 exposure record from a 12-byte packet (header
/// included).
///
/// Layout: `[reserved:2][type=1:2][i32 pixel_exposure_ns:4][i32 skew_ns:4]`.
/// Bundled: `%camm1` fields at offsets 4 + 8 with `Format => 'int32s'` and
/// `ValueConv => $val * 1e-9` (QuickTimeStream.pl:428-439). The
/// `ValueConv` is applied inside [`CammExposure::from_raw_ns`].
fn decode_camm1(packet: &[u8]) -> Option<CammExposure> {
  let pixel_ns = le_i32(packet, 4)?;
  let skew_ns = le_i32(packet, 8)?;
  Some(CammExposure::from_raw_ns(pixel_ns, skew_ns))
}

/// Decode a 3-float CAMM vector at offset 4 (the shape shared by camm2 /
/// camm3 / camm4 / camm7). Bundled: `Format => 'float[3]'` at offset 4
/// (QuickTimeStream.pl:450, 462, 474, 569).
fn decode_camm_vec3(packet: &[u8]) -> Option<CammVector3> {
  let x = le_f32(packet, 4)?;
  let y = le_f32(packet, 8)?;
  let z = le_f32(packet, 12)?;
  Some(CammVector3::new(x, y, z))
}

/// Decode a CAMM type-5 GPS record from a 28-byte packet (header included).
///
/// Layout: `[reserved:2][type=5:2][f64 lat:8][f64 lon:8][f64 alt:8]`.
/// Bundled: `%camm5` (QuickTimeStream.pl:478-501).
///
/// `ValueConv = GPS::ToDegrees($val, 1)` is a no-op for a numeric scalar
/// (bundled GPS::ToDegrees strips `N`/`S`/`E`/`W` suffixes from string
/// inputs; on a plain number it returns the number unchanged).
fn decode_camm5(packet: &[u8]) -> Option<CammGpsSample> {
  let lat = le_f64(packet, 4)?;
  let lon = le_f64(packet, 12)?;
  let alt = le_f64(packet, 20)?;
  let mut s = CammGpsSample::new(5);
  s.set_latitude(Some(lat))
    .set_longitude(Some(lon))
    .set_altitude_m(Some(alt));
  Some(s)
}

/// Decode a CAMM type-6 GPS record from a 60-byte packet (header
/// included).
///
/// Layout (QuickTimeStream.pl:503-560, all offsets header-relative):
/// ```text
///   0x04  f64  GPSDateTime  (GPS or Unix epoch; see heuristic)
///   0x0c  u32  GPSMeasureMode (LE)
///   0x10  f64  GPSLatitude
///   0x18  f64  GPSLongitude
///   0x20  f32  GPSAltitude
///   0x24  f32  GPSHorizontalAccuracy
///   0x28  f32  GPSVerticalAccuracy
///   0x2c  f32  GPSVelocityEast
///   0x30  f32  GPSVelocityNorth
///   0x34  f32  GPSVelocityUp
///   0x38  f32  GPSSpeedAccuracy
/// ```
///
/// `create_date_unix_s` is the optional `mvhd` CreateDate expressed in
/// UNIX seconds — used by the GPS-vs-Unix-epoch heuristic
/// (QuickTimeStream.pl:517-524).
fn decode_camm6(packet: &[u8], create_date_unix_s: Option<f64>) -> Option<CammGpsSample> {
  let gps_dt_raw = le_f64(packet, 0x04)?;
  let measure = le_u32(packet, 0x0c)?;
  let lat = le_f64(packet, 0x10)?;
  let lon = le_f64(packet, 0x18)?;
  let alt = le_f32(packet, 0x20)?;
  let h_acc = le_f32(packet, 0x24)?;
  let v_acc = le_f32(packet, 0x28)?;
  let v_e = le_f32(packet, 0x2c)?;
  let v_n = le_f32(packet, 0x30)?;
  let v_u = le_f32(packet, 0x34)?;
  let spd_acc = le_f32(packet, 0x38)?;

  let dt = format_camm6_gps_datetime(gps_dt_raw, create_date_unix_s);

  let mut s = CammGpsSample::new(6);
  s.set_date_time(Some(smol_str::SmolStr::from(dt)))
    .set_measure_mode(Some(measure))
    .set_latitude(Some(lat))
    .set_longitude(Some(lon))
    .set_altitude_m(Some(f64::from(alt)))
    .set_horizontal_accuracy_m(Some(h_acc))
    .set_vertical_accuracy_m(Some(v_acc))
    .set_velocity_east_mps(Some(v_e))
    .set_velocity_north_mps(Some(v_n))
    .set_velocity_up_mps(Some(v_u))
    .set_speed_accuracy_mps(Some(spd_acc));
  Some(s)
}

/// `camm6.GPSDateTime.ValueConv` (QuickTimeStream.pl:517-524) — pick the
/// GPS-vs-Unix-epoch interpretation, then format via
/// `ConvertUnixTime($val, 0, -6) . 'Z'`. Returns the displayed
/// `YYYY:MM:DD HH:MM:SS[.sssZ]` string.
///
/// `create_date_unix_s` is the `mvhd` CreateDate in UNIX seconds; when
/// it's >5 years AHEAD of the raw timestamp, bundled treats the raw value
/// as GPS-epoch and shifts by `+315964800` to land in Unix time.
///
/// Non-finite (NaN / Inf) input is preserved via
/// [`perl_nonfinite_str`] — matches the bundled string rendering of
/// Perl float exceptions (the `Image::ExifTool::ConvertUnixTime` /
/// `sprintf` chain would emit `NaN` / `Inf` strings).
fn format_camm6_gps_datetime(raw: f64, create_date_unix_s: Option<f64>) -> String {
  // Non-finite ⇒ Perl-cased string token. ExifTool would not normally
  // reach this branch on a real-world packet but defending it cheaply
  // keeps the typed projection well-defined.
  if let Some(tok) = perl_nonfinite_str(raw) {
    let mut s = String::with_capacity(tok.len() + 1);
    s.push_str(tok);
    s.push('Z');
    return s;
  }

  // GPS-epoch heuristic: only shift when the create date is far AHEAD of
  // the raw timestamp (bundled QuickTimeStream.pl:519).
  let shifted = match create_date_unix_s {
    Some(cd) if cd - raw > FIVE_YEARS_S => raw + GPS_TO_UNIX_OFFSET_S,
    _ => raw,
  };
  // `ConvertUnixTime($val, 0, -6)`. Truncate to integer seconds for the
  // displayed string (bundled's `-6` flag opts out of fractional rendering
  // on the integer-rounded path).
  let mut s = convert_datetime(&convert_unix_time(shifted as i64));
  s.push('Z');
  s
}

// ===========================================================================
// process_camm — the bundled ProcessCAMM port
// ===========================================================================

/// `ProcessCAMM` (`QuickTimeStream.pl:3481-3506`) — walk a single timed
/// metadata sample as a sequence of CAMM packets, dispatching each by
/// `int16u-LE` type to the matching `%QuickTime::camm<N>` decoder.
///
/// Faithful behaviour notes:
///
///  - Loop condition `while ($pos + 4 < $end)`
///    (QuickTimeStream.pl:3493) — strictly less, NOT `<=`. A trailing 4
///    bytes is NEVER processed.
///  - `$size = $size{$type} or warn + last`
///    (QuickTimeStream.pl:3495) — UNKNOWN packet type (including type 0,
///    which is absent from the `%size` table) STOPS the whole walk for
///    this sample. exifast mirrors this (no per-packet continue).
///  - `$pos + $size > $end and warn + last`
///    (QuickTimeStream.pl:3496) — a TRUNCATED packet also stops the walk.
///  - The packet `$size` INCLUDES the 4-byte header.
///
/// `create_date_unix_s` is the `mvhd` CreateDate as UNIX seconds (or
/// `None`); routed onto camm6 GPS records only (QuickTimeStream.pl:519).
///
/// Pushes each decoded record into `out`.
pub fn process_camm(data: &[u8], create_date_unix_s: Option<f64>, out: &mut CammMeta) {
  let mut pos = 0usize;
  let end = data.len();
  // QuickTimeStream.pl:3493 `while ($pos + 4 < $end)`.
  while pos + 4 < end {
    // QuickTimeStream.pl:3494 `Get16u($dataPt, $pos + 2)` — packet type is
    // the int16u-LE at byte offset +2 (skipping the 2 reserved bytes).
    let Some(t) = le_u16(data, pos + 2) else {
      break;
    };
    // QuickTimeStream.pl:3495 `$size{$type} or warn + last`.
    let Some(size) = camm_packet_size(t) else {
      break;
    };
    let size = size as usize;
    // QuickTimeStream.pl:3496 `$pos + $size > $end and warn + last`. The
    // checked slice doubles as the bounds guard (avoids raw indexing under the
    // `formats` file-level `#![deny(clippy::indexing_slicing)]`); a `None`
    // means the packet overruns the sample ⇒ `last`.
    let Some(packet) = pos.checked_add(size).and_then(|e| data.get(pos..e)) else {
      break;
    };
    // Dispatch by type — `ProcessBinaryData($dirInfo, $tagTbl)` in bundled
    // is type-specialized through the `%camm<N>` tag table choice.
    match t {
      1 => {
        if let Some(e) = decode_camm1(packet) {
          out.push_exposure(e);
        }
      }
      2 => {
        if let Some(v) = decode_camm_vec3(packet) {
          out.push_angular_velocity(v);
        }
      }
      3 => {
        if let Some(v) = decode_camm_vec3(packet) {
          out.push_acceleration(v);
        }
      }
      4 => {
        if let Some(v) = decode_camm_vec3(packet) {
          out.push_position(v);
        }
      }
      5 => {
        if let Some(g) = decode_camm5(packet) {
          out.push_gps_sample(g);
        }
      }
      6 => {
        if let Some(g) = decode_camm6(packet, create_date_unix_s) {
          out.push_gps_sample(g);
        }
      }
      7 => {
        if let Some(v) = decode_camm_vec3(packet) {
          out.push_magnetic_field(v);
        }
      }
      _ => {
        // Unreachable — `camm_packet_size` returned Some for an unknown
        // type, which it cannot. Kept for defensive future-proofing.
      }
    }
    // QuickTimeStream.pl:3503 `$pos += $size`.
    pos += size;
  }
}

/// `%size` (QuickTimeStream.pl:3491) — HEADER-INCLUDED packet size per
/// CAMM type. Returns `None` for types absent from the bundled hash
/// (including type 0); the caller treats a `None` as "unknown — bail".
const fn camm_packet_size(t: u16) -> Option<u16> {
  match t {
    1 => Some(12),
    2 => Some(16),
    3 => Some(16),
    4 => Some(16),
    5 => Some(28),
    6 => Some(60),
    7 => Some(16),
    _ => None,
  }
}

// ===========================================================================
// QuickTime ↔ Unix epoch glue (used by callers passing raw 1904 seconds)
// ===========================================================================

/// Convert a `mvhd` raw 1904-epoch create-date (seconds) to UNIX seconds.
/// Bundled QuickTimeStream.pl:519 reads `$$self{CreateDate}` AFTER the
/// `RawConv` epoch-subtraction (QuickTime.pm:1355-1374). exifast carries
/// the raw count through the SP3 walker; convert here so callers can pass
/// the raw value straight through.
#[inline]
#[must_use]
pub fn create_date_to_unix(raw_1904_s: u64) -> f64 {
  raw_1904_s as f64 - QT_EPOCH_OFFSET_S
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
// Tests build hand-crafted packets and index the decoded sample vectors with
// known-good literals; raw indexing keeps the assertions terse and a panic is
// the desired failure mode, so the `formats` file-level deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;
  use alloc::vec::Vec;

  /// Build a CAMM packet: `[reserved:2 (=0)][type:int16u-le][payload]`.
  fn pkt(t: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + payload.len());
    v.extend_from_slice(&[0u8, 0u8]); // reserved
    v.extend_from_slice(&t.to_le_bytes());
    v.extend_from_slice(payload);
    v
  }

  #[test]
  fn camm1_decodes_exposure_and_skew() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&1_000_000_000i32.to_le_bytes());
    payload.extend_from_slice(&(-500_000_000i32).to_le_bytes());
    let p = pkt(1, &payload);
    assert_eq!(p.len(), 12);
    let mut out = CammMeta::new();
    process_camm(&p, None, &mut out);
    assert_eq!(out.exposure().len(), 1);
    let e = &out.exposure()[0];
    assert!((e.pixel_exposure_time_s() - 1.0).abs() < 1e-12);
    assert!((e.rolling_shutter_skew_time_s() + 0.5).abs() < 1e-12);
  }

  #[test]
  fn camm2_decodes_angular_velocity() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&1.0f32.to_le_bytes());
    payload.extend_from_slice(&(-2.0f32).to_le_bytes());
    payload.extend_from_slice(&3.5f32.to_le_bytes());
    let p = pkt(2, &payload);
    assert_eq!(p.len(), 16);
    let mut out = CammMeta::new();
    process_camm(&p, None, &mut out);
    assert_eq!(out.angular_velocity().len(), 1);
    let v = &out.angular_velocity()[0];
    assert_eq!(v.x(), 1.0);
    assert_eq!(v.y(), -2.0);
    assert_eq!(v.z(), 3.5);
  }

  #[test]
  fn camm3_decodes_acceleration() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&0.1f32.to_le_bytes());
    payload.extend_from_slice(&0.2f32.to_le_bytes());
    payload.extend_from_slice(&9.8f32.to_le_bytes());
    let p = pkt(3, &payload);
    let mut out = CammMeta::new();
    process_camm(&p, None, &mut out);
    assert_eq!(out.acceleration().len(), 1);
    assert!((out.acceleration()[0].z() - 9.8).abs() < 1e-6);
  }

  #[test]
  fn camm4_decodes_position() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&10.0f32.to_le_bytes());
    payload.extend_from_slice(&20.0f32.to_le_bytes());
    payload.extend_from_slice(&30.0f32.to_le_bytes());
    let p = pkt(4, &payload);
    let mut out = CammMeta::new();
    process_camm(&p, None, &mut out);
    assert_eq!(out.position().len(), 1);
    assert_eq!(out.position()[0].x(), 10.0);
    assert_eq!(out.position()[0].y(), 20.0);
    assert_eq!(out.position()[0].z(), 30.0);
  }

  #[test]
  fn camm5_decodes_minimal_gps() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&37.5f64.to_le_bytes());
    payload.extend_from_slice(&(-122.0f64).to_le_bytes());
    payload.extend_from_slice(&50.0f64.to_le_bytes());
    let p = pkt(5, &payload);
    assert_eq!(p.len(), 28);
    let mut out = CammMeta::new();
    process_camm(&p, None, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = &out.gps_samples()[0];
    assert_eq!(s.packet_type(), 5);
    assert_eq!(s.latitude(), Some(37.5));
    assert_eq!(s.longitude(), Some(-122.0));
    assert_eq!(s.altitude_m(), Some(50.0));
    assert!(s.has_coordinates());
    // camm5 fields beyond the basic triplet stay None.
    assert!(s.date_time().is_none());
    assert!(s.measure_mode().is_none());
  }

  #[test]
  fn camm6_decodes_full_gps_with_unix_epoch_timestamp() {
    // Build a camm6 packet with a Unix-epoch GPSDateTime (Jan 1, 2024 00:00 UTC).
    let unix_ts_2024_jan_1 = 1_704_067_200.0f64;
    let mut payload = Vec::new();
    payload.extend_from_slice(&unix_ts_2024_jan_1.to_le_bytes()); // GPSDateTime
    payload.extend_from_slice(&3u32.to_le_bytes()); // GPSMeasureMode = 3 (3D)
    payload.extend_from_slice(&37.5f64.to_le_bytes()); // Lat
    payload.extend_from_slice(&(-122.0f64).to_le_bytes()); // Lon
    payload.extend_from_slice(&100.0f32.to_le_bytes()); // Alt
    payload.extend_from_slice(&5.0f32.to_le_bytes()); // HAcc
    payload.extend_from_slice(&10.0f32.to_le_bytes()); // VAcc
    payload.extend_from_slice(&1.0f32.to_le_bytes()); // VelE
    payload.extend_from_slice(&2.0f32.to_le_bytes()); // VelN
    payload.extend_from_slice(&0.5f32.to_le_bytes()); // VelU
    payload.extend_from_slice(&0.1f32.to_le_bytes()); // SpdAcc
    let p = pkt(6, &payload);
    assert_eq!(p.len(), 60);
    let mut out = CammMeta::new();
    // No create date ⇒ heuristic does NOT shift; raw Unix passes through.
    process_camm(&p, None, &mut out);
    assert_eq!(out.gps_samples().len(), 1);
    let s = &out.gps_samples()[0];
    assert_eq!(s.packet_type(), 6);
    assert_eq!(s.latitude(), Some(37.5));
    assert_eq!(s.longitude(), Some(-122.0));
    assert!((s.altitude_m().unwrap() - 100.0).abs() < 1e-6);
    assert_eq!(s.measure_mode(), Some(3));
    assert_eq!(s.horizontal_accuracy_m(), Some(5.0));
    assert_eq!(s.vertical_accuracy_m(), Some(10.0));
    assert_eq!(s.velocity_east_mps(), Some(1.0));
    assert_eq!(s.velocity_north_mps(), Some(2.0));
    assert_eq!(s.velocity_up_mps(), Some(0.5));
    assert_eq!(s.speed_accuracy_mps(), Some(0.1));
    // Date format: 2024:01:01 00:00:00Z
    assert_eq!(s.date_time(), Some("2024:01:01 00:00:00Z"));
  }

  #[test]
  fn camm6_gps_epoch_heuristic_shifts_when_create_date_far_ahead() {
    // A GPS-epoch timestamp ≈ 1_388_534_400 ≈ Jan 1 2024 in GPS-epoch ⇒
    // bundled treats it as GPS-epoch if `create_date - raw > 5y`.
    let gps_dt_raw = 1_388_534_400.0f64; // GPS-epoch seconds (≈ Jan 1 2024)
    // create_date in UNIX seconds far ahead (10 years ahead of raw).
    let create_date_unix_s = gps_dt_raw + GPS_TO_UNIX_OFFSET_S + (10.0 * 365.0 * 24.0 * 3600.0);
    let mut payload = Vec::new();
    payload.extend_from_slice(&gps_dt_raw.to_le_bytes());
    payload.extend_from_slice(&3u32.to_le_bytes());
    payload.extend_from_slice(&0.0f64.to_le_bytes());
    payload.extend_from_slice(&0.0f64.to_le_bytes());
    payload.extend_from_slice(&[0u8; 4 * 7]);
    let p = pkt(6, &payload);
    let mut out = CammMeta::new();
    process_camm(&p, Some(create_date_unix_s), &mut out);
    let s = &out.gps_samples()[0];
    // After GPS→Unix shift: raw + 315964800 ≈ Mar 9 2014 (the GPS-epoch of
    // 1_388_534_400 + offset). Bundled would render the post-shift Unix time.
    let want_unix = gps_dt_raw + GPS_TO_UNIX_OFFSET_S;
    let want = format!(
      "{}Z",
      convert_datetime(&convert_unix_time(want_unix as i64))
    );
    assert_eq!(s.date_time(), Some(want.as_str()));
  }

  #[test]
  fn camm6_gps_epoch_heuristic_passes_unix_through_when_create_date_close() {
    // create_date is the same as raw (Unix-epoch timestamp). Bundled does
    // NOT shift; the value passes through unmodified.
    let unix_ts = 1_704_067_200.0f64; // 2024-01-01 00:00 UTC
    let mut payload = Vec::new();
    payload.extend_from_slice(&unix_ts.to_le_bytes());
    payload.extend_from_slice(&2u32.to_le_bytes());
    payload.extend_from_slice(&0.0f64.to_le_bytes());
    payload.extend_from_slice(&0.0f64.to_le_bytes());
    payload.extend_from_slice(&[0u8; 4 * 7]);
    let p = pkt(6, &payload);
    let mut out = CammMeta::new();
    process_camm(&p, Some(unix_ts), &mut out);
    assert_eq!(
      out.gps_samples()[0].date_time(),
      Some("2024:01:01 00:00:00Z")
    );
  }

  #[test]
  fn camm7_decodes_magnetic_field() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&30.0f32.to_le_bytes());
    payload.extend_from_slice(&(-15.0f32).to_le_bytes());
    payload.extend_from_slice(&45.0f32.to_le_bytes());
    let p = pkt(7, &payload);
    let mut out = CammMeta::new();
    process_camm(&p, None, &mut out);
    assert_eq!(out.magnetic_field().len(), 1);
    let v = &out.magnetic_field()[0];
    assert_eq!(v.x(), 30.0);
    assert_eq!(v.y(), -15.0);
    assert_eq!(v.z(), 45.0);
  }

  #[test]
  fn type_0_aborts_walk_faithfully() {
    // QuickTimeStream.pl:3495 — type 0 is NOT in %size; the loop warns and
    // `last`s. A type-2 packet AFTER a type-0 must NOT be processed.
    let mut stream = Vec::new();
    // Type-0 packet: header only (any payload would be unread).
    stream.extend_from_slice(&[0u8, 0u8, 0u8, 0u8]); // reserved + type=0
    // Type-2 packet that SHOULD be skipped.
    let mut vec3 = Vec::new();
    vec3.extend_from_slice(&1.0f32.to_le_bytes());
    vec3.extend_from_slice(&2.0f32.to_le_bytes());
    vec3.extend_from_slice(&3.0f32.to_le_bytes());
    stream.extend_from_slice(&pkt(2, &vec3));
    let mut out = CammMeta::new();
    process_camm(&stream, None, &mut out);
    assert_eq!(
      out.angular_velocity().len(),
      0,
      "bundled `last`s on type 0; nothing after must be decoded"
    );
  }

  #[test]
  fn unknown_type_aborts_walk_faithfully() {
    // Unknown type 99 ⇒ bundled `last`s. The following well-typed packet
    // must NOT be decoded.
    let mut stream = Vec::new();
    // Type=99 header.
    stream.extend_from_slice(&[0u8, 0u8]);
    stream.extend_from_slice(&99u16.to_le_bytes());
    // Type-7 packet that should be SKIPPED.
    let mut vec3 = Vec::new();
    vec3.extend_from_slice(&1.0f32.to_le_bytes());
    vec3.extend_from_slice(&2.0f32.to_le_bytes());
    vec3.extend_from_slice(&3.0f32.to_le_bytes());
    stream.extend_from_slice(&pkt(7, &vec3));
    let mut out = CammMeta::new();
    process_camm(&stream, None, &mut out);
    assert!(out.is_empty());
  }

  #[test]
  fn truncated_packet_aborts_walk_faithfully() {
    // QuickTimeStream.pl:3496 — `$pos + $size > $end and last`. A camm5
    // declares 28 bytes but only 20 are provided ⇒ the FIRST packet is
    // dropped and the walk stops.
    let mut stream = Vec::new();
    stream.extend_from_slice(&[0u8, 0u8]);
    stream.extend_from_slice(&5u16.to_le_bytes()); // type=5
    stream.extend_from_slice(&[0u8; 16]); // 20 bytes total, need 28
    let mut out = CammMeta::new();
    process_camm(&stream, None, &mut out);
    assert!(out.is_empty());
  }

  #[test]
  fn loop_strict_less_skips_4_trailing_bytes() {
    // QuickTimeStream.pl:3493 — strictly `<`, NOT `<=`. A 4-byte trailing
    // remainder is dropped without dispatch (no spurious type-0 warning,
    // no decode).
    let mut stream = Vec::new();
    // Full camm2 (16 bytes).
    let mut vec3 = Vec::new();
    vec3.extend_from_slice(&1.0f32.to_le_bytes());
    vec3.extend_from_slice(&2.0f32.to_le_bytes());
    vec3.extend_from_slice(&3.0f32.to_le_bytes());
    stream.extend_from_slice(&pkt(2, &vec3));
    // Trailing 4 bytes that LOOK like a header (type=0) — must be IGNORED
    // because `$pos + 4 < $end` is FALSE when pos+4 == end.
    stream.extend_from_slice(&[0u8, 0u8, 0u8, 0u8]);
    let mut out = CammMeta::new();
    process_camm(&stream, None, &mut out);
    assert_eq!(out.angular_velocity().len(), 1);
  }

  #[test]
  fn multiple_packets_in_single_sample() {
    // QuickTimeStream.pl:3501-3503 — the loop continues after each packet,
    // so multiple records in one sample DO accumulate.
    let mut stream = Vec::new();
    // Three camm3 (acceleration) packets.
    let triples: [(f32, f32, f32); 3] = [(0.1, 0.2, 9.8), (0.0, 0.0, 9.81), (-0.1, 0.0, 9.79)];
    for v in triples {
      let mut payload = Vec::new();
      payload.extend_from_slice(&v.0.to_le_bytes());
      payload.extend_from_slice(&v.1.to_le_bytes());
      payload.extend_from_slice(&v.2.to_le_bytes());
      stream.extend_from_slice(&pkt(3, &payload));
    }
    let mut out = CammMeta::new();
    process_camm(&stream, None, &mut out);
    assert_eq!(out.acceleration().len(), 3);
  }

  #[test]
  fn empty_input_decodes_nothing() {
    let mut out = CammMeta::new();
    process_camm(&[], None, &mut out);
    assert!(out.is_empty());
  }

  #[test]
  fn create_date_to_unix_round_trip() {
    // 1904 epoch = -2082844800 unix.
    assert!((create_date_to_unix(0) + 2_082_844_800.0).abs() < 1e-3);
  }
}
