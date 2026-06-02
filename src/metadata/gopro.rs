//! Typed mirror of `Image::ExifTool::GoPro::GPMF` — the
//! GoPro Metadata Format (GPMF) extracted from `gpmd` timed-metadata samples,
//! GoPro `GP\x06\0\0` records in `mdat`, the `moov`-level `GPMF` atom, and
//! the JPEG APP6 `GoPro` segment.
//!
//! ## What GPMF carries
//!
//! GPMF is a recursive Key-Length-Value (KLV) container; each record carries
//! an 8-byte header (4-byte FourCC tag + 1-byte format code + 1-byte
//! sample-size + 2-byte BE sample-count) plus a payload of
//! `sample_size * sample_count` bytes, padded to a 4-byte boundary
//! (GoPro.pm:831-844). Containers (`fmt=0`) recursively hold child KLV
//! records — the top level is `DEVC` (`DeviceContainer`); inside `DEVC` lives
//! per-stream `STRM` (`NestedSignalStream`), and inside `STRM` live the
//! per-tag GPS / sensor records.
//!
//! Three sibling records modify how a following tag is decoded:
//!  - `TYPE` — a packed format string for a `?` (complex-struct) tag
//!    (GoPro.pm:848-862);
//!  - `SCAL` — per-sample scaling factors applied to the LAST tag of a
//!    container (GoPro.pm:884);
//!  - `UNIT` / `SIUN` — per-element unit strings (currently informational).
//!
//! ## Scope (this sub-port)
//!
//! Ported faithfully — the [`GoPro.pm`](../../../../exiftool/lib/Image/ExifTool/GoPro.pm)
//! recursive KLV parser plus the GPS family that this product targets:
//!
//!  - `GPS5` — per-sample lat / lon / alt / 2D-speed / 3D-speed
//!    (GoPro.pm:487-514, Hero5+);
//!  - `GPS9` — newer per-sample lat / lon / alt / 2D-speed / 3D-speed /
//!    GPS-days / GPS-seconds / DOP / fix (GoPro.pm:516-563, Hero13);
//!  - `GPSU` — UTC date/time string for the FIRST sample (GoPro.pm:242-248);
//!  - `GPSP` — horizontal positioning error in cm → m (GoPro.pm:237-241);
//!  - `GPSF` — GPS fix status / measure mode (GoPro.pm:230-236);
//!  - `GPSA` — GPS altitude system (eg `MSLV`, GoPro.pm:472);
//!  - the camera-identification tags exfiltrated incidentally — `CASN`
//!    (CameraSerialNumber), `MINF` (Model), `FMWR` (FirmwareVersion),
//!    `DVNM` (DeviceName).
//!
//! Other GoPro tag families (ACCL / GYRO / MAGN / ISO / SHUT / sensor
//! telemetry / Karma drone / Max calibrations) are NOT decoded into typed
//! samples in this sub-port — the KLV walker still visits them (so the
//! container nesting is honoured) but their values are discarded. They can
//! be added later by extending the visitor's tag-dispatch; the parse layer
//! is structured to make that an additive change.
//!
//! ## Mapping to ExifTool's `Doc<N>` model
//!
//! ExifTool's `ProcessString` (GoPro.pm:749-777) splits a multi-sample
//! string-of-numbers tag like `GPS5` into one `Doc<N>` per sample. exifast
//! mirrors that with a `Vec<GoProGpsSample>` — one entry per row in the
//! source `GPS5` / `GPS9` payload. The faithful `ScaleValues` post-step
//! (GoPro.pm:705-721) is applied during parse, so the stored values are
//! already in their final units (degrees / metres / m/s).

extern crate alloc;
use alloc::{string::ToString, vec::Vec};

use smol_str::SmolStr;

use crate::metadata::{CameraInfo, GpsLocation, MediaMetadata};

/// One per-sample GPS fix decoded from a `GPS5` or `GPS9` GPMF record. The
/// shape is the union of both records — `GPS9`-only fields default to
/// `None` for a `GPS5` source row.
///
/// Faithful mirror of the per-`Doc<N>` tag group ExifTool's `ProcessString`
/// emits for each row of a `GPS5` / `GPS9` payload
/// (GoPro.pm:749-777, GoPro.pm:487-563).
#[derive(Debug, Clone, PartialEq)]
pub struct GoProGpsSample {
  /// `GPSLatitude` in decimal degrees, positive = north (GoPro.pm:492-495).
  latitude: Option<f64>,
  /// `GPSLongitude` in decimal degrees, positive = east (GoPro.pm:496-499).
  longitude: Option<f64>,
  /// `GPSAltitude` in metres (GoPro.pm:500-503).
  altitude_m: Option<f64>,
  /// `GPSSpeed` 2-D speed in m/s — the raw post-`SCAL` value. ExifTool's
  /// `ValueConv` multiplies by 3.6 to km/h (GoPro.pm:504-508); this typed
  /// layer stores the raw m/s, and the `*3.6` km/h conversion is applied at
  /// the `Taggable` emission (the emitted `GPSSpeed` tag is km/h, matching
  /// `exiftool -ee`).
  speed_2d_mps: Option<f64>,
  /// `GPSSpeed3D` 3-D speed in m/s (GoPro.pm:509-513).
  speed_3d_mps: Option<f64>,
  /// `GPSDateTime` — `GPS9` only, derived from the per-sample
  /// `GPS-days + GPS-seconds` columns 5+6 (GoPro.pm:543-554). Format:
  /// `YYYY:MM:DD HH:MM:SS.sss` (no timezone suffix, matching
  /// `ConvertUnixTime(..., undef, 3)`). Stored as [`SmolStr`] (≤30-char string).
  date_time: Option<SmolStr>,
  /// `GPSDOP` — `GPS9` only, GPS dilution-of-precision (GoPro.pm:555).
  dop: Option<f64>,
  /// `GPSMeasureMode` — `GPS9` only, the raw fix-dimension code:
  /// `2` = 2-D, `3` = 3-D (GoPro.pm:556-562). Stored numeric for the typed
  /// layer; the engine renders the PrintConv text.
  measure_mode: Option<u32>,
}

impl GoProGpsSample {
  /// An empty sample (every field `None`).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      latitude: None,
      longitude: None,
      altitude_m: None,
      speed_2d_mps: None,
      speed_3d_mps: None,
      date_time: None,
      dop: None,
      measure_mode: None,
    }
  }

  /// `GPSLatitude` in decimal degrees.
  #[inline(always)]
  #[must_use]
  pub const fn latitude(&self) -> Option<f64> {
    self.latitude
  }

  /// `GPSLongitude` in decimal degrees.
  #[inline(always)]
  #[must_use]
  pub const fn longitude(&self) -> Option<f64> {
    self.longitude
  }

  /// `GPSAltitude` in metres (per GoPro.pm:500-503).
  #[inline(always)]
  #[must_use]
  pub const fn altitude_m(&self) -> Option<f64> {
    self.altitude_m
  }

  /// `GPSSpeed` 2-D in m/s.
  #[inline(always)]
  #[must_use]
  pub const fn speed_2d_mps(&self) -> Option<f64> {
    self.speed_2d_mps
  }

  /// `GPSSpeed3D` 3-D in m/s.
  #[inline(always)]
  #[must_use]
  pub const fn speed_3d_mps(&self) -> Option<f64> {
    self.speed_3d_mps
  }

  /// `GPSDateTime` displayed string (GPS9 only).
  #[inline(always)]
  #[must_use]
  pub fn date_time(&self) -> Option<&str> {
    self.date_time.as_deref()
  }

  /// `GPSDOP` (GPS9 only).
  #[inline(always)]
  #[must_use]
  pub const fn dop(&self) -> Option<f64> {
    self.dop
  }

  /// `GPSMeasureMode` numeric code (GPS9 only).
  #[inline(always)]
  #[must_use]
  pub const fn measure_mode(&self) -> Option<u32> {
    self.measure_mode
  }

  /// `true` when no field is populated.
  #[inline(always)]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.latitude.is_none()
      && self.longitude.is_none()
      && self.altitude_m.is_none()
      && self.speed_2d_mps.is_none()
      && self.speed_3d_mps.is_none()
      && self.date_time.is_none()
      && self.dop.is_none()
      && self.measure_mode.is_none()
  }

  /// `true` when the sample carries a GPS coordinate pair.
  #[inline(always)]
  #[must_use]
  pub const fn has_coordinates(&self) -> bool {
    self.latitude.is_some() && self.longitude.is_some()
  }

  /// Assign `GPSLatitude`.
  #[inline(always)]
  pub const fn set_latitude(&mut self, v: Option<f64>) -> &mut Self {
    self.latitude = v;
    self
  }

  /// Assign `GPSLongitude`.
  #[inline(always)]
  pub const fn set_longitude(&mut self, v: Option<f64>) -> &mut Self {
    self.longitude = v;
    self
  }

  /// Assign `GPSAltitude` (metres).
  #[inline(always)]
  pub const fn set_altitude_m(&mut self, v: Option<f64>) -> &mut Self {
    self.altitude_m = v;
    self
  }

  /// Assign `GPSSpeed` 2-D.
  #[inline(always)]
  pub const fn set_speed_2d_mps(&mut self, v: Option<f64>) -> &mut Self {
    self.speed_2d_mps = v;
    self
  }

  /// Assign `GPSSpeed3D`.
  #[inline(always)]
  pub const fn set_speed_3d_mps(&mut self, v: Option<f64>) -> &mut Self {
    self.speed_3d_mps = v;
    self
  }

  /// Assign `GPSDateTime` (GPS9).
  #[inline(always)]
  pub fn set_date_time(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.date_time = v;
    self
  }

  /// Assign `GPSDOP` (GPS9).
  #[inline(always)]
  pub const fn set_dop(&mut self, v: Option<f64>) -> &mut Self {
    self.dop = v;
    self
  }

  /// Assign `GPSMeasureMode` (GPS9).
  #[inline(always)]
  pub const fn set_measure_mode(&mut self, v: Option<u32>) -> &mut Self {
    self.measure_mode = v;
    self
  }
}

impl Default for GoProGpsSample {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

/// One per-sample Karma-drone GPS-position fix decoded from a `GLPI` GPMF
/// record (`Name => 'GPSPos'`, GoPro.pm:197-204). The complex `?` record's
/// per-row column layout is `TYPE=LllllsssS` with
/// `SCAL=1000 10000000 10000000 1000 1000 100 100 100 100`; the resolved
/// columns map by POSITION to the `%GoPro::GLPI` table (GoPro.pm:598-626):
/// 0 `GPSDateTime`, 1 `GPSLatitude`, 2 `GPSLongitude`, 3 `GPSAltitude`,
/// 4 `GLPI_Unknown4` (`Unknown`/`Hidden` — never emitted, not stored here),
/// 5 `GPSSpeedX`, 6 `GPSSpeedY`, 7 `GPSSpeedZ`, 8 `GPSTrack`.
///
/// Faithful mirror of the per-`Doc<N>` tag group ExifTool's `ProcessString`
/// (GoPro.pm:749-777) emits for each row of a `GLPI` payload. The
/// `ScaleValues` post-step (GoPro.pm:705-721) is applied during parse, so the
/// stored numeric values are already in their final units
/// (degrees / metres / m/s). NOTE: unlike `GPS5`/`GPS9`, the GLPI speed
/// columns carry NO `*3.6` km/h `ValueConv` (the `%GoPro::GLPI` table has only
/// a `"$val m/s"` PrintConv, GoPro.pm:622-624) — `GPSSpeedX/Y/Z` are stored
/// and emitted in raw m/s.
#[derive(Debug, Clone, PartialEq)]
pub struct GoProGlpiSample {
  /// `GPSDateTime` (col 0, GoPro.pm:602-607) — derived from the raw column-0
  /// "system time" value via ExifTool's `ConvertSystemTime` (GoPro.pm:677-702):
  /// a binary-search interpolation against the file's `SYST` calibration list.
  /// Format `YYYY:MM:DD HH:MM:SS[.fff]` (no timezone), or the literal
  /// `<uncalibrated>` when no `SYST` calibration preceded the fix, or
  /// `0000:00:00 00:00:00` when the interpolated epoch is a whole number (the
  /// faithful `^(\d+)(\.\d+)` regex quirk; see
  /// [`crate::formats::gopro`]). Stored as [`SmolStr`] (≤30-char string).
  date_time: Option<SmolStr>,
  /// `GPSLatitude` in decimal degrees, positive = north (col 1,
  /// GoPro.pm:608-611).
  latitude: Option<f64>,
  /// `GPSLongitude` in decimal degrees, positive = east (col 2,
  /// GoPro.pm:612-615).
  longitude: Option<f64>,
  /// `GPSAltitude` in metres (col 3, GoPro.pm:616-619).
  altitude_m: Option<f64>,
  /// `GPSSpeedX` in m/s (col 5, GoPro.pm:622). Raw m/s — no km/h conversion.
  speed_x_mps: Option<f64>,
  /// `GPSSpeedY` in m/s (col 6, GoPro.pm:623).
  speed_y_mps: Option<f64>,
  /// `GPSSpeedZ` in m/s (col 7, GoPro.pm:624).
  speed_z_mps: Option<f64>,
  /// `GPSTrack` in degrees (col 8, GoPro.pm:625). No `ValueConv`/`PrintConv`.
  track_deg: Option<f64>,
}

impl GoProGlpiSample {
  /// An empty sample (every field `None`).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      date_time: None,
      latitude: None,
      longitude: None,
      altitude_m: None,
      speed_x_mps: None,
      speed_y_mps: None,
      speed_z_mps: None,
      track_deg: None,
    }
  }

  /// `GPSDateTime` displayed string (col 0).
  #[inline(always)]
  #[must_use]
  pub fn date_time(&self) -> Option<&str> {
    self.date_time.as_deref()
  }

  /// `GPSLatitude` in decimal degrees (col 1).
  #[inline(always)]
  #[must_use]
  pub const fn latitude(&self) -> Option<f64> {
    self.latitude
  }

  /// `GPSLongitude` in decimal degrees (col 2).
  #[inline(always)]
  #[must_use]
  pub const fn longitude(&self) -> Option<f64> {
    self.longitude
  }

  /// `GPSAltitude` in metres (col 3).
  #[inline(always)]
  #[must_use]
  pub const fn altitude_m(&self) -> Option<f64> {
    self.altitude_m
  }

  /// `GPSSpeedX` in m/s (col 5).
  #[inline(always)]
  #[must_use]
  pub const fn speed_x_mps(&self) -> Option<f64> {
    self.speed_x_mps
  }

  /// `GPSSpeedY` in m/s (col 6).
  #[inline(always)]
  #[must_use]
  pub const fn speed_y_mps(&self) -> Option<f64> {
    self.speed_y_mps
  }

  /// `GPSSpeedZ` in m/s (col 7).
  #[inline(always)]
  #[must_use]
  pub const fn speed_z_mps(&self) -> Option<f64> {
    self.speed_z_mps
  }

  /// `GPSTrack` in degrees (col 8).
  #[inline(always)]
  #[must_use]
  pub const fn track_deg(&self) -> Option<f64> {
    self.track_deg
  }

  /// `true` when no field is populated.
  #[inline(always)]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.date_time.is_none()
      && self.latitude.is_none()
      && self.longitude.is_none()
      && self.altitude_m.is_none()
      && self.speed_x_mps.is_none()
      && self.speed_y_mps.is_none()
      && self.speed_z_mps.is_none()
      && self.track_deg.is_none()
  }

  /// `true` when the sample carries a GPS coordinate pair.
  #[inline(always)]
  #[must_use]
  pub const fn has_coordinates(&self) -> bool {
    self.latitude.is_some() && self.longitude.is_some()
  }

  /// Assign `GPSDateTime` (col 0).
  #[inline(always)]
  pub fn set_date_time(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.date_time = v;
    self
  }

  /// Assign `GPSLatitude` (col 1).
  #[inline(always)]
  pub const fn set_latitude(&mut self, v: Option<f64>) -> &mut Self {
    self.latitude = v;
    self
  }

  /// Assign `GPSLongitude` (col 2).
  #[inline(always)]
  pub const fn set_longitude(&mut self, v: Option<f64>) -> &mut Self {
    self.longitude = v;
    self
  }

  /// Assign `GPSAltitude` (col 3).
  #[inline(always)]
  pub const fn set_altitude_m(&mut self, v: Option<f64>) -> &mut Self {
    self.altitude_m = v;
    self
  }

  /// Assign `GPSSpeedX` (col 5).
  #[inline(always)]
  pub const fn set_speed_x_mps(&mut self, v: Option<f64>) -> &mut Self {
    self.speed_x_mps = v;
    self
  }

  /// Assign `GPSSpeedY` (col 6).
  #[inline(always)]
  pub const fn set_speed_y_mps(&mut self, v: Option<f64>) -> &mut Self {
    self.speed_y_mps = v;
    self
  }

  /// Assign `GPSSpeedZ` (col 7).
  #[inline(always)]
  pub const fn set_speed_z_mps(&mut self, v: Option<f64>) -> &mut Self {
    self.speed_z_mps = v;
    self
  }

  /// Assign `GPSTrack` (col 8).
  #[inline(always)]
  pub const fn set_track_deg(&mut self, v: Option<f64>) -> &mut Self {
    self.track_deg = v;
    self
  }
}

impl Default for GoProGlpiSample {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

/// One Karma-drone battery-status record decoded from a `KBAT` GPMF record
/// (`Name => 'BatteryStatus'`, GoPro.pm:264-270). The complex `?` record's
/// per-row column layout is `TYPE=lLlsSSSSSSSBBBb` with `SCAL=1000,1000,`
/// `0.00999999977648258,100,1000,1000,1000,1000,0.0166666675359011,1,1,1,1,1,1`;
/// the resolved columns map by POSITION to the `%GoPro::KBAT` table
/// (GoPro.pm:628-649). Only the NAMED columns are stored — the
/// `Unknown`/`Hidden` slots (col 2 `J`, col 9 `%`, cols 10-13) are never
/// emitted by bundled `exiftool -ee` and are not retained here.
///
/// `ScaleValues` (GoPro.pm:705-721) is applied during parse, so the stored
/// values are in their final units (A / Ah / degC / V / seconds / %).
/// `BatteryTime` (col 8) keeps the raw scaled SECONDS (the `ConvertDuration`
/// PrintConv, GoPro.pm:642, is a display-only transform that the emission
/// layer defers, consistent with the other GoPro unit-suffix PrintConvs).
#[derive(Debug, Clone, PartialEq)]
pub struct GoProKbat {
  /// `BatteryCurrent` in amperes (col 0, GoPro.pm:634).
  current_a: Option<f64>,
  /// `BatteryCapacity` in amp-hours (col 1, GoPro.pm:635).
  capacity_ah: Option<f64>,
  /// `BatteryTemperature` in degrees Celsius (col 3, GoPro.pm:637).
  temperature_c: Option<f64>,
  /// `BatteryVoltage1` in volts (col 4, GoPro.pm:638).
  voltage1_v: Option<f64>,
  /// `BatteryVoltage2` in volts (col 5, GoPro.pm:639).
  voltage2_v: Option<f64>,
  /// `BatteryVoltage3` in volts (col 6, GoPro.pm:640).
  voltage3_v: Option<f64>,
  /// `BatteryVoltage4` in volts (col 7, GoPro.pm:641).
  voltage4_v: Option<f64>,
  /// `BatteryTime` in seconds (col 8, GoPro.pm:642). Raw scaled seconds; the
  /// `ConvertDuration(int($val + 0.5))` PrintConv is deferred at emission.
  time_s: Option<f64>,
  /// `BatteryLevel` percentage (col 14, GoPro.pm:648).
  level_pct: Option<f64>,
}

impl GoProKbat {
  /// An empty record (every field `None`).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      current_a: None,
      capacity_ah: None,
      temperature_c: None,
      voltage1_v: None,
      voltage2_v: None,
      voltage3_v: None,
      voltage4_v: None,
      time_s: None,
      level_pct: None,
    }
  }

  /// `BatteryCurrent` in amperes (col 0).
  #[inline(always)]
  #[must_use]
  pub const fn current_a(&self) -> Option<f64> {
    self.current_a
  }

  /// `BatteryCapacity` in amp-hours (col 1).
  #[inline(always)]
  #[must_use]
  pub const fn capacity_ah(&self) -> Option<f64> {
    self.capacity_ah
  }

  /// `BatteryTemperature` in degrees Celsius (col 3).
  #[inline(always)]
  #[must_use]
  pub const fn temperature_c(&self) -> Option<f64> {
    self.temperature_c
  }

  /// `BatteryVoltage1` in volts (col 4).
  #[inline(always)]
  #[must_use]
  pub const fn voltage1_v(&self) -> Option<f64> {
    self.voltage1_v
  }

  /// `BatteryVoltage2` in volts (col 5).
  #[inline(always)]
  #[must_use]
  pub const fn voltage2_v(&self) -> Option<f64> {
    self.voltage2_v
  }

  /// `BatteryVoltage3` in volts (col 6).
  #[inline(always)]
  #[must_use]
  pub const fn voltage3_v(&self) -> Option<f64> {
    self.voltage3_v
  }

  /// `BatteryVoltage4` in volts (col 7).
  #[inline(always)]
  #[must_use]
  pub const fn voltage4_v(&self) -> Option<f64> {
    self.voltage4_v
  }

  /// `BatteryTime` in seconds (col 8). Raw scaled seconds.
  #[inline(always)]
  #[must_use]
  pub const fn time_s(&self) -> Option<f64> {
    self.time_s
  }

  /// `BatteryLevel` percentage (col 14).
  #[inline(always)]
  #[must_use]
  pub const fn level_pct(&self) -> Option<f64> {
    self.level_pct
  }

  /// `true` when no field is populated.
  #[inline(always)]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.current_a.is_none()
      && self.capacity_ah.is_none()
      && self.temperature_c.is_none()
      && self.voltage1_v.is_none()
      && self.voltage2_v.is_none()
      && self.voltage3_v.is_none()
      && self.voltage4_v.is_none()
      && self.time_s.is_none()
      && self.level_pct.is_none()
  }

  /// Assign `BatteryCurrent` (col 0).
  #[inline(always)]
  pub const fn set_current_a(&mut self, v: Option<f64>) -> &mut Self {
    self.current_a = v;
    self
  }

  /// Assign `BatteryCapacity` (col 1).
  #[inline(always)]
  pub const fn set_capacity_ah(&mut self, v: Option<f64>) -> &mut Self {
    self.capacity_ah = v;
    self
  }

  /// Assign `BatteryTemperature` (col 3).
  #[inline(always)]
  pub const fn set_temperature_c(&mut self, v: Option<f64>) -> &mut Self {
    self.temperature_c = v;
    self
  }

  /// Assign `BatteryVoltage1` (col 4).
  #[inline(always)]
  pub const fn set_voltage1_v(&mut self, v: Option<f64>) -> &mut Self {
    self.voltage1_v = v;
    self
  }

  /// Assign `BatteryVoltage2` (col 5).
  #[inline(always)]
  pub const fn set_voltage2_v(&mut self, v: Option<f64>) -> &mut Self {
    self.voltage2_v = v;
    self
  }

  /// Assign `BatteryVoltage3` (col 6).
  #[inline(always)]
  pub const fn set_voltage3_v(&mut self, v: Option<f64>) -> &mut Self {
    self.voltage3_v = v;
    self
  }

  /// Assign `BatteryVoltage4` (col 7).
  #[inline(always)]
  pub const fn set_voltage4_v(&mut self, v: Option<f64>) -> &mut Self {
    self.voltage4_v = v;
    self
  }

  /// Assign `BatteryTime` seconds (col 8).
  #[inline(always)]
  pub const fn set_time_s(&mut self, v: Option<f64>) -> &mut Self {
    self.time_s = v;
    self
  }

  /// Assign `BatteryLevel` percentage (col 14).
  #[inline(always)]
  pub const fn set_level_pct(&mut self, v: Option<f64>) -> &mut Self {
    self.level_pct = v;
    self
  }
}

impl Default for GoProKbat {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

/// The decoded value of a generic (table-driven) `%GoPro::GPMF` tag — the
/// `ReadValue($dataPt, $pos, $format, undef, $size)` result ExifTool's
/// `ProcessGoPro` produces for a non-typed tag (GoPro.pm:864-870), held in
/// its native shape so the emission layer can render BOTH the `-n` (ValueConv)
/// and `-j` (PrintConv) forms.
///
/// The shape mirrors ExifTool's `$val` exactly:
///  - a `string` (`c`) format, or any tag whose `ValueConv`/`RawConv` already
///    produced a string (GPSU date, RMRK Latin text), is [`Self::Str`];
///  - a single numeric scalar is [`Self::Num`] (already post-`ScaleValues`);
///  - a flat run of numerics (a plain multi-value tag like `MAGN`, decoded as
///    one space-joined list across ALL rows — GoPro.pm:869 `ReadValue` returns
///    a flat list) is [`Self::NumList`];
///  - a complex `?` record (GoPro.pm:848-863) is [`Self::Rows`] — one
///    space-joined post-`ScaleValues` string per row (`$val = @v > 1 ? \@v :
///    $v[0]`): a single row renders as a scalar string, multiple rows as a
///    JSON array.
#[derive(Debug, Clone, PartialEq)]
pub enum GoProTagValue {
  /// A string value (a `c`-format tag, or one whose `ValueConv` produced text).
  Str(SmolStr),
  /// A single numeric scalar (post-`ScaleValues`).
  Num(f64),
  /// A flat list of numerics joined with single spaces (a plain multi-value
  /// tag; ExifTool's `ReadValue` returns the whole record as one flat list).
  NumList(Vec<f64>),
  /// A complex `?` record's per-row space-joined scaled strings (GoPro.pm:863).
  Rows(Vec<SmolStr>),
}

impl GoProTagValue {
  /// `true` when this value carries no usable data (empty list / empty rows).
  /// A genuinely empty record never reaches here (`ProcessGoPro` skips
  /// `size == 0`), so this only guards a decode that resolved zero elements.
  #[inline]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    match self {
      Self::Str(s) => s.is_empty(),
      Self::Num(_) => false,
      Self::NumList(v) => v.is_empty(),
      Self::Rows(r) => r.is_empty(),
    }
  }
}

/// The conversion family for a generic (table-driven) `%GoPro::GPMF` tag — the
/// per-tag `PrintConv` / `ValueConv` ExifTool applies (GoPro.pm tag table).
/// The DECODE is format-driven (the KLV header's `fmt` byte); only the CONV is
/// tag-driven, so this enum is the conv half of the static FourCC→(Name, conv)
/// table in [`crate::formats::gopro`]. A `ValueConv`/`RawConv` (e.g. `STMP
/// $val/1e6`, `CDAT ConvertUnixTime`, `GPSU` regex) is applied at DECODE time
/// and lands as a [`GoProTagValue::Str`]/[`GoProTagValue::Num`], so it needs no
/// variant here; this enum carries only the conversions whose `-j` form
/// differs from `-n` (a `PrintConv`) plus the value-affecting `Binary`/
/// `AddUnits` shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoProConv {
  /// No PrintConv — emit the value verbatim in both modes (e.g. `AALP`,
  /// `MTRX`, `ColorTemperatures`, `SceneClassification`). A `ValueConv`-only
  /// tag (`STMP`/`CDAT`/`GPSU`) also uses this — its conversion is folded in
  /// at decode.
  Plain,
  /// `Binary => 1` (GoPro.pm e.g. ACCL/GYRO/CORI/GRAV/IORI/ISOG): ExifTool's
  /// ValueConv is `'\$val'` (a scalar reference), so the value renders as
  /// `"(Binary data N bytes, use -b option to extract)"` in BOTH `-j` and `-n`,
  /// where `N = length` of the post-`ScaleValues` space-joined value STRING
  /// (exiftool:3987 `length($$obj)`).
  Binary,
  /// `%noYes` PrintConv (`N => 'No'`, `Y => 'Yes'`): `-j` maps the raw `N`/`Y`
  /// token, `-n` emits the raw token (GoPro.pm:63).
  NoYes,
  /// `OREN` `AutoRotation` PrintConv (`U => 'Up'`, `D => 'Down'`,
  /// `A => 'Auto'`, GoPro.pm:297-304).
  AutoRotation,
  /// `PRTN` `Protune` PrintConv (`N => 'Off'`, `Y => 'On'`, GoPro.pm:317-323).
  Protune,
  /// `VFOV` `FieldOfView` PrintConv (`W => 'Wide'`, `S => 'Super View'`,
  /// `L => 'Linear'`, GoPro.pm:428-435).
  FieldOfView,
  /// `VERS` `MetadataVersion` PrintConv (`$val =~ tr/ /./` — spaces → dots,
  /// GoPro.pm:424-427).
  Version,
  /// `VFPS` `VideoFrameRate` PrintConv (`$val =~ s( )(/)` — the FIRST space →
  /// `/`, GoPro.pm:437).
  FrameRate,
  /// `VRES` `VideoFrameSize` PrintConv (`$val =~ s/ /x/` — the FIRST space →
  /// `x`, GoPro.pm:445).
  FrameSize,
  /// `TMPC` `CameraTemperature` PrintConv (`"$val C"` — append `" C"`,
  /// GoPro.pm:407-410).
  TempC,
  /// `TZON` `TimeZone` PrintConv (`TimeZoneString($val)` — minutes → `±HH:MM`,
  /// GoPro.pm:415-418).
  TimeZone,
  /// `SHUT` `ExposureTimes` PrintConv — `PrintExposureTime` per element
  /// (GoPro.pm:354-361). `-n` emits the raw float list.
  ExposureTimes,
  /// `%addUnits` PrintConv (`SCPR`/`SIMU`): interleave each value with its
  /// `UNIT`/`SIUN` element (`"5 s 10000 Pa ..."`, GoPro.pm:58-61, 727-743),
  /// but ONLY when the unit count equals the value count. `-n` emits the bare
  /// scaled list. The captured units ride in the [`GoProTag`].
  AddUnits,
}

/// One generic (table-driven) `%GoPro::GPMF` tag decoded by the KLV walker — a
/// default-visible tag OUTSIDE the typed GPS5/GPS9/GLPI/KBAT/SYST/camera-id
/// surface. ExifTool's `ProcessGoPro` `HandleTag`s every known tag
/// (GoPro.pm:885); these are the ones whose meaning is a faithful pass-through
/// (sensor streams, Protune/codec settings, calibrations) rather than a domain
/// field. Stored in walk order on [`GoProMeta::generic_tags`]; rendered to the
/// `-n`/`-j` [`crate::value::TagValue`] at emission (the layer that owns the
/// conv rendering), parallel to the typed GLPI/KBAT path.
#[derive(Debug, Clone, PartialEq)]
pub struct GoProTag {
  /// The ExifTool tag `Name` (e.g. `"Accelerometer"`, `"CameraTemperature"`).
  name: SmolStr,
  /// The decoded value in its native shape (post-`ScaleValues` / post-
  /// `ValueConv`).
  value: GoProTagValue,
  /// The `-j` PrintConv family (`-n` is the verbatim value for most).
  conv: GoProConv,
  /// The captured `UNIT`/`SIUN` elements for an [`GoProConv::AddUnits`] tag
  /// (empty otherwise) — the per-element unit strings the `%addUnits` PrintConv
  /// appends (GoPro.pm:727-743).
  units: Vec<SmolStr>,
}

impl GoProTag {
  /// Build a generic tag with no AddUnits units.
  #[inline]
  #[must_use]
  pub fn new(name: SmolStr, value: GoProTagValue, conv: GoProConv) -> Self {
    Self {
      name,
      value,
      conv,
      units: Vec::new(),
    }
  }

  /// Build an [`GoProConv::AddUnits`] tag carrying its per-element units.
  #[inline]
  #[must_use]
  pub fn with_units(name: SmolStr, value: GoProTagValue, units: Vec<SmolStr>) -> Self {
    Self {
      name,
      value,
      conv: GoProConv::AddUnits,
      units,
    }
  }

  /// The ExifTool tag `Name`.
  #[inline]
  #[must_use]
  pub fn name(&self) -> &str {
    self.name.as_str()
  }

  /// The decoded value.
  #[inline]
  #[must_use]
  pub const fn value(&self) -> &GoProTagValue {
    &self.value
  }

  /// The `-j` PrintConv family.
  #[inline]
  #[must_use]
  pub const fn conv(&self) -> GoProConv {
    self.conv
  }

  /// The captured AddUnits per-element units (empty for non-AddUnits tags).
  #[inline]
  #[must_use]
  pub fn units(&self) -> &[SmolStr] {
    self.units.as_slice()
  }
}

/// The typed result of GoPro GPMF metadata extraction — the per-format
/// mirror of every `%GoPro::GPMF` tag this sub-port decodes.
///
/// One [`GoProMeta`] aggregates ALL GPMF records the source carries: a
/// `gpmd` timed-metadata track typically emits one DEVC container per
/// sample, each containing one or more `STRM` streams; the parser flattens
/// all the per-sample `GPS5` / `GPS9` rows into [`Self::gps_samples`] in
/// the order they appear. Camera identification (model, serial, firmware)
/// is taken from the FIRST sample's `DEVC.STRM*` since these are constant
/// across the file.
///
/// Empty (`is_empty()`) when GoPro GPMF data was sought but none was
/// recognised (or when the source contained only deferred tag families).
#[derive(Debug, Clone, PartialEq)]
pub struct GoProMeta {
  /// `DeviceName` (`DVNM`, GoPro.pm:170-172). Typically the camera model
  /// name displayed string (e.g. `"Hero6 Black"`, `"Camera"`).
  device_name: Option<SmolStr>,
  /// `Model` (`MINF`, GoPro.pm:286-290). The displayed camera model name.
  model: Option<SmolStr>,
  /// `CameraSerialNumber` (`CASN`, GoPro.pm:121).
  camera_serial_number: Option<SmolStr>,
  /// `FirmwareVersion` (`FMWR`, GoPro.pm:195). Format: `HD6.01.01.51.00`.
  firmware_version: Option<SmolStr>,
  /// `MediaUniqueID` (`MUID`, GoPro.pm:456-462). Stored as the **raw**
  /// ExifTool ValueConv — the space-joined `count` × `u32` list (e.g.
  /// `"491b313c 2837…"`), NOT the PrintConv hex string. The hex rendering
  /// (`sprintf('%.8x',$_) foreach @a; join('')`, GoPro.pm:458-461) is applied
  /// at emission time in PrintConv (`-j`) mode; `-n` (ValueConv) emits this
  /// raw space-joined value, matching bundled ExifTool. Stored as [`SmolStr`]
  /// (cheap to clone since `MUID` is short and constant per file).
  media_uid: Option<SmolStr>,
  /// `GPSDateTime` (`GPSU`, GoPro.pm:242-248). The block-level UTC fix the
  /// `GPS5` family is anchored to; `GPS9` carries per-sample timestamps in
  /// the samples themselves.
  gps_date_time: Option<SmolStr>,
  /// `GPSMeasureMode` (`GPSF`, GoPro.pm:230-236). Raw numeric `2` / `3`.
  gps_measure_mode: Option<u32>,
  /// `GPSHPositioningError` (`GPSP`, GoPro.pm:237-241) — already converted
  /// from cm to m by `ValueConv`.
  gps_h_positioning_error_m: Option<f64>,
  /// `GPSAltitudeSystem` (`GPSA`, GoPro.pm:472) — typically `MSLV`.
  gps_altitude_system: Option<SmolStr>,
  /// One [`GoProGpsSample`] per row in a `GPS5` / `GPS9` payload, in source
  /// order (across all samples in the file). The faithful `ScaleValues`
  /// post-step (GoPro.pm:705-721) has already been applied.
  gps_samples: Vec<GoProGpsSample>,
  /// One [`GoProGlpiSample`] per row in a Karma `GLPI` payload
  /// (`GPSPos`, GoPro.pm:197-204), in source order across the file.
  glpi_samples: Vec<GoProGlpiSample>,
  /// One [`GoProKbat`] per row in a Karma `KBAT` payload
  /// (`BatteryStatus`, GoPro.pm:264-270), in source order across the file.
  kbat_records: Vec<GoProKbat>,
  /// The file-global `SYST` (`SystemTime`, GoPro.pm:390-405) calibration list
  /// — `(system_time_seconds, unix_time_seconds)` pairs accumulated from every
  /// two-column `SYST` record (post-`SCAL`). ExifTool stores this on the
  /// ExifTool object (`$$self{SystemTimeList}`) so it persists across all
  /// `DEVC`/`STRM` recursions and gpmd samples; the typed equivalent lives
  /// here, on the one [`GoProMeta`] threaded through the whole walk. Consumed
  /// by [`crate::formats::gopro`]'s `ConvertSystemTime` to resolve a `GLPI`
  /// column-0 `GPSDateTime`. A calibration pair is pushed ONLY for a `SYST`
  /// record that decodes to a SINGLE row of EXACTLY two values, mirroring the
  /// RawConv `my @v = split ' ', $val; if (@v == 2)` gate (GoPro.pm:396-404):
  /// a `count > 1` record decodes to an ARRAYREF (GoPro.pm:863
  /// `$val = @v > 1 ? \@v : $v[0]`) which does not split into two tokens, so it
  /// is NOT calibration.
  system_time_list: Vec<(f64, f64)>,
  /// `SystemTime` (`SYST`, GoPro.pm:390-405) — the DISPLAYED value of the FIRST
  /// `SYST` record, stored as the post-`SCAL` space-joined column string
  /// ExifTool's `HandleTag` receives (e.g. `"5 1551484800"`; a multi-row record
  /// joins its rows with `", "`). `SystemTime` is a DEFAULT tag (no
  /// `Unknown`/`Hidden` flag) so bundled `exiftool -ee` emits it in addition to
  /// the calibration side-effect; the typed surface summarizes the first record
  /// (the per-sample multiset is an `-ee` `Doc<N>` shape this flat layer cannot
  /// reproduce, the same limitation as the GPS/GLPI/KBAT first-fix summaries).
  system_time: Option<SmolStr>,
  /// Every OTHER default-visible `%GoPro::GPMF` tag (GoPro.pm:78-485) the KLV
  /// walker decodes — the sensor streams (`ACCL`/`GYRO`/`CORI`/`GRAV`/…),
  /// Protune/codec settings (`PRTN`/`PTWB`/`VFPS`/…), and calibrations
  /// (`MTRX`/`SCPR`/`SIMU`/…) — held as table-driven [`GoProTag`]s in walk
  /// order. Faithful to ExifTool's `ProcessGoPro` `HandleTag`-every-known-tag
  /// (GoPro.pm:885): a tag is captured iff it is in the default-visible table
  /// (no `Unknown`/`Hidden`), exactly the `-ee` default-mode set. The typed
  /// GPS5/GPS9/GLPI/KBAT/SYST/camera-id tags above are NOT duplicated here;
  /// this is purely the additive remainder. Like the GPS first-fix summaries,
  /// each multi-sample tag is captured once per record in walk order (one
  /// `GoProTag` per `gpmd` sample / `STRM` occurrence), not collapsed.
  generic_tags: Vec<GoProTag>,
}

impl GoProMeta {
  /// An empty result (no GPMF metadata decoded).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      device_name: None,
      model: None,
      camera_serial_number: None,
      firmware_version: None,
      media_uid: None,
      gps_date_time: None,
      gps_measure_mode: None,
      gps_h_positioning_error_m: None,
      gps_altitude_system: None,
      gps_samples: Vec::new(),
      glpi_samples: Vec::new(),
      kbat_records: Vec::new(),
      system_time_list: Vec::new(),
      system_time: None,
      generic_tags: Vec::new(),
    }
  }

  /// `DeviceName` (DVNM).
  #[inline(always)]
  #[must_use]
  pub fn device_name(&self) -> Option<&str> {
    self.device_name.as_deref()
  }

  /// `Model` (MINF).
  #[inline(always)]
  #[must_use]
  pub fn model(&self) -> Option<&str> {
    self.model.as_deref()
  }

  /// `CameraSerialNumber` (CASN).
  #[inline(always)]
  #[must_use]
  pub fn camera_serial_number(&self) -> Option<&str> {
    self.camera_serial_number.as_deref()
  }

  /// `FirmwareVersion` (FMWR).
  #[inline(always)]
  #[must_use]
  pub fn firmware_version(&self) -> Option<&str> {
    self.firmware_version.as_deref()
  }

  /// `MediaUniqueID` (MUID), as the raw space-joined `u32` list (ExifTool's
  /// ValueConv / `-n` value). PrintConv (`-j`) hex-renders this at emission.
  #[inline(always)]
  #[must_use]
  pub fn media_uid(&self) -> Option<&str> {
    self.media_uid.as_deref()
  }

  /// Block-level `GPSDateTime` (GPSU).
  #[inline(always)]
  #[must_use]
  pub fn gps_date_time(&self) -> Option<&str> {
    self.gps_date_time.as_deref()
  }

  /// Block-level `GPSMeasureMode` numeric code (GPSF).
  #[inline(always)]
  #[must_use]
  pub const fn gps_measure_mode(&self) -> Option<u32> {
    self.gps_measure_mode
  }

  /// `GPSHPositioningError` in metres (GPSP, already cm→m converted).
  #[inline(always)]
  #[must_use]
  pub const fn gps_h_positioning_error_m(&self) -> Option<f64> {
    self.gps_h_positioning_error_m
  }

  /// `GPSAltitudeSystem` (GPSA).
  #[inline(always)]
  #[must_use]
  pub fn gps_altitude_system(&self) -> Option<&str> {
    self.gps_altitude_system.as_deref()
  }

  /// One sample per row in `GPS5` / `GPS9`, in source order.
  #[inline(always)]
  #[must_use]
  pub fn gps_samples(&self) -> &[GoProGpsSample] {
    self.gps_samples.as_slice()
  }

  /// One sample per row in the Karma `GLPI` (`GPSPos`) records, in source
  /// order across the file (GoPro.pm:197-204).
  #[inline(always)]
  #[must_use]
  pub fn glpi_samples(&self) -> &[GoProGlpiSample] {
    self.glpi_samples.as_slice()
  }

  /// One record per row in the Karma `KBAT` (`BatteryStatus`) records, in
  /// source order across the file (GoPro.pm:264-270).
  #[inline(always)]
  #[must_use]
  pub fn kbat_records(&self) -> &[GoProKbat] {
    self.kbat_records.as_slice()
  }

  /// `true` when no GPMF tag was decoded.
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.device_name.is_none()
      && self.model.is_none()
      && self.camera_serial_number.is_none()
      && self.firmware_version.is_none()
      && self.media_uid.is_none()
      && self.gps_date_time.is_none()
      && self.gps_measure_mode.is_none()
      && self.gps_h_positioning_error_m.is_none()
      && self.gps_altitude_system.is_none()
      && self.gps_samples.is_empty()
      && self.glpi_samples.is_empty()
      && self.kbat_records.is_empty()
      && self.system_time.is_none()
      && self.generic_tags.is_empty()
  }

  /// The FIRST Karma `GLPI` sample carrying a GPS coordinate pair.
  #[inline(always)]
  #[must_use]
  pub fn first_glpi_fix(&self) -> Option<&GoProGlpiSample> {
    self.glpi_samples.iter().find(|s| s.has_coordinates())
  }

  /// The FIRST sample carrying a GPS coordinate pair — used by the
  /// [`crate::metadata::MediaMetadata`] projection to fill
  /// [`crate::metadata::GpsLocation`].
  #[inline(always)]
  #[must_use]
  pub fn first_fix(&self) -> Option<&GoProGpsSample> {
    self.gps_samples.iter().find(|s| s.has_coordinates())
  }

  /// Assign `DeviceName`.
  #[inline(always)]
  pub fn set_device_name(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.device_name = v;
    self
  }

  /// Assign `Model`.
  #[inline(always)]
  pub fn set_model(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.model = v;
    self
  }

  /// Assign `CameraSerialNumber`.
  #[inline(always)]
  pub fn set_camera_serial_number(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.camera_serial_number = v;
    self
  }

  /// Assign `FirmwareVersion`.
  #[inline(always)]
  pub fn set_firmware_version(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.firmware_version = v;
    self
  }

  /// Assign `MediaUniqueID`.
  #[inline(always)]
  pub fn set_media_uid(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.media_uid = v;
    self
  }

  /// Assign block-level `GPSDateTime`.
  #[inline(always)]
  pub fn set_gps_date_time(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.gps_date_time = v;
    self
  }

  /// Assign block-level `GPSMeasureMode`.
  #[inline(always)]
  pub const fn set_gps_measure_mode(&mut self, v: Option<u32>) -> &mut Self {
    self.gps_measure_mode = v;
    self
  }

  /// Assign `GPSHPositioningError` (metres, post cm→m).
  #[inline(always)]
  pub const fn set_gps_h_positioning_error_m(&mut self, v: Option<f64>) -> &mut Self {
    self.gps_h_positioning_error_m = v;
    self
  }

  /// Assign `GPSAltitudeSystem`.
  #[inline(always)]
  pub fn set_gps_altitude_system(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.gps_altitude_system = v;
    self
  }

  /// Append a per-sample GPS fix.
  #[inline(always)]
  pub fn push_gps_sample(&mut self, sample: GoProGpsSample) -> &mut Self {
    self.gps_samples.push(sample);
    self
  }

  /// Append a Karma `GLPI` (`GPSPos`) sample.
  #[inline(always)]
  pub fn push_glpi_sample(&mut self, sample: GoProGlpiSample) -> &mut Self {
    self.glpi_samples.push(sample);
    self
  }

  /// Append a Karma `KBAT` (`BatteryStatus`) record.
  #[inline(always)]
  pub fn push_kbat_record(&mut self, record: GoProKbat) -> &mut Self {
    self.kbat_records.push(record);
    self
  }

  /// Append one `(system_time_seconds, unix_time_seconds)` calibration pair to
  /// the file-global `SYST` list (GoPro.pm:396-404 `push @$s, \@v`). Used by
  /// the `GLPI` `GPSDateTime` `ConvertSystemTime` resolution.
  #[inline(always)]
  pub fn push_system_time(&mut self, system_s: f64, unix_s: f64) -> &mut Self {
    self.system_time_list.push((system_s, unix_s));
    self
  }

  /// The accumulated `SYST` calibration pairs (in walk order; the consumer
  /// sorts a copy, mirroring ExifTool's lazy sort).
  #[inline(always)]
  #[must_use]
  pub fn system_time_list(&self) -> &[(f64, f64)] {
    self.system_time_list.as_slice()
  }

  /// `SystemTime` (SYST) displayed value of the FIRST `SYST` record — the
  /// post-`SCAL` space-joined column string (GoPro.pm:390-405). A default tag,
  /// emitted by `exiftool -ee`.
  #[inline(always)]
  #[must_use]
  pub fn system_time(&self) -> Option<&str> {
    self.system_time.as_deref()
  }

  /// Record the displayed `SystemTime` value of the FIRST `SYST` record (later
  /// records are summarized by the first, like the GPS/GLPI/KBAT fixes). A
  /// no-op once set, so the first record in walk order wins.
  #[inline(always)]
  pub fn set_system_time(&mut self, v: SmolStr) -> &mut Self {
    if self.system_time.is_none() {
      self.system_time = Some(v);
    }
    self
  }

  /// Every table-driven default-visible `%GoPro::GPMF` tag decoded by the KLV
  /// walker, in walk order. See [`GoProTag`].
  #[inline(always)]
  #[must_use]
  pub fn generic_tags(&self) -> &[GoProTag] {
    self.generic_tags.as_slice()
  }

  /// Append a table-driven generic tag (GoPro.pm default-visible, non-typed).
  #[inline(always)]
  pub fn push_generic_tag(&mut self, tag: GoProTag) -> &mut Self {
    self.generic_tags.push(tag);
    self
  }
}

impl Default for GoProMeta {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// GoPro projection into MediaMetadata (golden L2)
// ===========================================================================

impl GoProMeta {
  /// Project GoPro GPMF metadata into [`MediaMetadata`].
  ///
  /// **CameraInfo:** GoPro is the manufacturer when any GoPro field is set.
  /// `Model` is `MINF` (or `DVNM` when `MINF` is absent); `Serial` is `CASN`;
  /// `Software` is `FMWR`. The projection skips silently when GoPro already
  /// surfaced no camera identity (`is_empty()`), or when a higher-priority
  /// source has already set `md.camera()` (priority-chain semantics).
  ///
  /// **GpsLocation:** GoPro is the **HIGHEST tier** of the GPS priority
  /// chain — GoPro hardware GNSS is the most authoritative source for a
  /// GoPro file. The FIRST `GPS5`/`GPS9` sample carrying a coordinate pair
  /// populates `GpsLocation` (`first_fix()`); timestamp falls back to the
  /// block-level `GPSDateTime` (`GPSU`) when the per-sample `GPS9` value
  /// is absent. When NO `GPS5`/`GPS9` fix exists but a Karma `GLPI`
  /// (`GPSPos`) fix does (a Karma-drone file), the first `GLPI` coordinate is
  /// used as a fallback GPS source — this never regresses the primary
  /// `GPS5`/`GPS9` projection (it only fires when `first_fix()` is `None`).
  ///
  /// An inherent helper (not the golden [`Project`](crate::metadata::Project)
  /// trait): GoPro has no standalone file type — it is reached only through
  /// the QuickTime container, whose [`Project`](crate::metadata::Project) impl
  /// (via [`crate::formats::quicktime::Meta::media_metadata`]) calls this to
  /// fold the on-device GNSS contribution into the QuickTime projection at the
  /// HIGHEST GPS priority tier.
  pub(crate) fn project_into(&self, md: &mut MediaMetadata) {
    if self.is_empty() {
      return;
    }
    // ── CameraInfo ─────────────────────────────────────────────────────
    if md.camera().is_none() {
      let mut cam = CameraInfo::new();
      cam
        .update_make(Some("GoPro".into()))
        .update_model(
          self
            .model()
            .or_else(|| self.device_name())
            .map(str::to_string),
        )
        .update_serial(self.camera_serial_number().map(str::to_string))
        .update_software(self.firmware_version().map(str::to_string));
      if !cam.is_empty() {
        md.set_camera(cam);
      }
    }
    // ── GpsLocation (HIGHEST tier of the GPS priority chain) ───────────
    if md.gps().is_none() {
      if let Some(f) = self.first_fix() {
        // Primary: GPS5/GPS9 hardware GNSS.
        let mut gps = GpsLocation::new();
        gps
          .update_latitude(f.latitude())
          .update_longitude(f.longitude())
          .update_altitude_m(f.altitude_m())
          .update_timestamp(
            f.date_time()
              .map(str::to_string)
              .or_else(|| self.gps_date_time().map(str::to_string)),
          );
        md.set_gps(gps);
      } else if let Some(g) = self.first_glpi_fix() {
        // Fallback: a Karma-drone `GLPI` (`GPSPos`) fix when no GPS5/GPS9
        // sample carried coordinates. `date_time` is the `ConvertSystemTime`
        // value (may be `<uncalibrated>` / `0000:00:00 00:00:00` — only set as
        // the GPS timestamp when it looks like a real date, i.e. not the
        // uncalibrated sentinel).
        let mut gps = GpsLocation::new();
        gps
          .update_latitude(g.latitude())
          .update_longitude(g.longitude())
          .update_altitude_m(g.altitude_m())
          .update_timestamp(
            g.date_time()
              .filter(|s| usable_glpi_time(s))
              .map(str::to_string),
          );
        md.set_gps(gps);
      }
    }
  }
}

/// `true` when a `GLPI` `ConvertSystemTime` result is a usable timestamp for
/// the [`MediaMetadata`] GPS projection — i.e. NOT the `<uncalibrated>`
/// sentinel (no `SYST` calibration) nor the all-zero `0000:00:00 00:00:00`
/// whole-second-epoch quirk. The tag itself still emits these literal values
/// faithfully; this guard only governs the domain projection.
#[inline]
fn usable_glpi_time(s: &str) -> bool {
  !s.is_empty() && !s.starts_with('<') && !s.starts_with("0000:")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn gps_sample_emptiness_and_coordinates() {
    let mut s = GoProGpsSample::new();
    assert!(s.is_empty());
    assert!(!s.has_coordinates());
    s.set_latitude(Some(40.0));
    assert!(!s.is_empty());
    assert!(!s.has_coordinates());
    s.set_longitude(Some(-105.0));
    assert!(s.has_coordinates());
  }

  #[test]
  fn meta_emptiness_and_first_fix() {
    let mut m = GoProMeta::new();
    assert!(m.is_empty());
    let mut sa = GoProGpsSample::new();
    sa.set_altitude_m(Some(100.0)); // no coords
    m.push_gps_sample(sa);
    let mut sb = GoProGpsSample::new();
    sb.set_latitude(Some(1.0)).set_longitude(Some(2.0));
    m.push_gps_sample(sb);
    assert!(!m.is_empty());
    assert_eq!(m.first_fix().expect("fix").latitude(), Some(1.0));
  }

  #[test]
  fn meta_setters_round_trip() {
    let mut m = GoProMeta::new();
    m.set_device_name(Some("Hero6 Black".into()))
      .set_model(Some("HERO6 Black".into()))
      .set_camera_serial_number(Some("C3221324657219".into()))
      .set_firmware_version(Some("HD6.01.01.51.00".into()));
    assert_eq!(m.device_name(), Some("Hero6 Black"));
    assert_eq!(m.model(), Some("HERO6 Black"));
    assert_eq!(m.camera_serial_number(), Some("C3221324657219"));
    assert_eq!(m.firmware_version(), Some("HD6.01.01.51.00"));
    assert!(!m.is_empty());
  }

  // P3-B unit-test backfill — typed-surface accessors round-trip with-some
  // and with-none, and the GPS extras (date_time, gps_altitude_system,
  // gps_h_positioning_error_m, gps_measure_mode, media_uid).

  #[test]
  fn gps_sample_setters_each_field_round_trip() {
    let mut s = GoProGpsSample::new();
    s.set_latitude(Some(40.0))
      .set_longitude(Some(-105.0))
      .set_altitude_m(Some(1500.0))
      .set_speed_2d_mps(Some(15.0))
      .set_speed_3d_mps(Some(16.0))
      .set_date_time(Some("2024:02:03 04:05:06Z".into()))
      .set_dop(Some(1.25))
      .set_measure_mode(Some(3));
    assert_eq!(s.latitude(), Some(40.0));
    assert_eq!(s.longitude(), Some(-105.0));
    assert_eq!(s.altitude_m(), Some(1500.0));
    assert_eq!(s.speed_2d_mps(), Some(15.0));
    assert_eq!(s.speed_3d_mps(), Some(16.0));
    assert_eq!(s.date_time(), Some("2024:02:03 04:05:06Z"));
    assert_eq!(s.dop(), Some(1.25));
    assert_eq!(s.measure_mode(), Some(3));
  }

  #[test]
  fn gps_sample_setters_with_none_keeps_field_empty() {
    let s = GoProGpsSample::new();
    assert_eq!(s.latitude(), None);
    assert_eq!(s.altitude_m(), None);
    assert_eq!(s.dop(), None);
    assert_eq!(s.date_time(), None);
    assert_eq!(s.measure_mode(), None);
  }

  #[test]
  fn meta_gps_extras_accessors() {
    let mut m = GoProMeta::new();
    m.set_gps_date_time(Some("2024:02:03 04:05:06Z".into()))
      .set_gps_altitude_system(Some("MSLV".into()))
      .set_gps_h_positioning_error_m(Some(1.5))
      .set_gps_measure_mode(Some(3))
      .set_media_uid(Some("0123456789abcdef".into()));
    assert_eq!(m.gps_date_time(), Some("2024:02:03 04:05:06Z"));
    assert_eq!(m.gps_altitude_system(), Some("MSLV"));
    assert_eq!(m.gps_h_positioning_error_m(), Some(1.5));
    assert_eq!(m.gps_measure_mode(), Some(3));
    assert_eq!(m.media_uid(), Some("0123456789abcdef"));
  }

  // P3-D project_into round-trip — verify the trait impl writes through to
  // MediaMetadata correctly.

  #[test]
  fn project_into_empty_meta_writes_nothing() {
    let m = GoProMeta::new();
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert!(md.camera().is_none());
    assert!(md.gps().is_none());
  }

  #[test]
  fn project_into_populates_camera_and_gps_from_first_fix() {
    let mut m = GoProMeta::new();
    m.set_model(Some("HERO6 Black".into()))
      .set_camera_serial_number(Some("C322".into()))
      .set_firmware_version(Some("HD6.01".into()))
      .set_gps_date_time(Some("2024:02:03 04:05:06Z".into()));
    let mut s = GoProGpsSample::new();
    s.set_latitude(Some(40.0))
      .set_longitude(Some(-105.0))
      .set_altitude_m(Some(1500.0));
    m.push_gps_sample(s);

    let mut md = MediaMetadata::new();
    m.project_into(&mut md);

    let cam = md.camera().expect("camera populated");
    assert_eq!(cam.make(), Some("GoPro"));
    assert_eq!(cam.model(), Some("HERO6 Black"));
    assert_eq!(cam.serial(), Some("C322"));
    assert_eq!(cam.software(), Some("HD6.01"));

    let gps = md.gps().expect("gps populated");
    assert_eq!(gps.latitude(), Some(40.0));
    assert_eq!(gps.longitude(), Some(-105.0));
    assert_eq!(gps.altitude_m(), Some(1500.0));
    // GPS9 per-sample date_time is None; falls back to block-level GPSU.
    assert_eq!(gps.timestamp(), Some("2024:02:03 04:05:06Z"));
  }

  #[test]
  fn project_into_skips_camera_when_higher_priority_already_set() {
    let mut m = GoProMeta::new();
    m.set_model(Some("HERO6 Black".into()));
    let mut md = MediaMetadata::new();
    let mut existing = CameraInfo::new();
    existing.update_make(Some("Sony".into()));
    md.set_camera(existing);
    m.project_into(&mut md);
    // The higher-priority Sony Make wins — GoPro doesn't overwrite it.
    assert_eq!(md.camera().expect("camera").make(), Some("Sony"));
  }
}
