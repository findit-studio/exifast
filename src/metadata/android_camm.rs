//! Typed mirror of `Image::ExifTool::QuickTime::camm0..camm7` — the
//! Google Camera Motion Metadata (CAMM) records carried in a video's `camm`
//! metadata track. Faithful port of `QuickTimeStream.pl:405-572` (the
//! seven `%QuickTime::camm<N>` tag tables) and `ProcessCAMM`
//! (`QuickTimeStream.pl:3481-3506`).
//!
//! ## Spec
//!
//! Each CAMM packet is a `[reserved:2][type:int16u-le:2][payload]` record.
//! `ProcessCAMM` (QuickTimeStream.pl:3491) sizes each packet (HEADER
//! INCLUDED) as:
//!
//! ```text
//!   type 0:  N/A (NOT in %size — bundled aborts with `Unknown camm record
//!                  type 0` on a real-world stream; see `process_camm`)
//!   type 1:  12 bytes — int32s pixel-exposure-time + int32s
//!                       rolling-shutter-skew-time (nanoseconds)
//!   type 2:  16 bytes — float[3] AngularVelocity (rad/s)
//!   type 3:  16 bytes — float[3] Acceleration (m/s²)
//!   type 4:  16 bytes — float[3] Position
//!   type 5:  28 bytes — double Latitude, double Longitude, double Altitude
//!   type 6:  60 bytes — double GPSDateTime, int32u MeasureMode,
//!                       double Lat, double Lon,
//!                       float Alt, float HAcc, float VAcc,
//!                       float VelE, float VelN, float VelU, float SpdAcc
//!   type 7:  16 bytes — float[3] MagneticField (microtesla)
//! ```
//!
//! ## What this sub-port surfaces
//!
//! Every packet `ProcessCAMM` would emit lands in [`CammMeta`] as one of
//! the typed sample vectors. The motion / sensor families (types 1-4 and 7)
//! are surfaced for completeness — the cross-format product targets
//! camera identity + GPS but the camm motion samples are cheap to keep and
//! useful for downstream callers.
//!
//! GPS packets (types 5 and 6) feed [`CammGpsSample`]; the FIRST one with
//! a coordinate pair is projected into [`crate::metadata::GpsLocation`].
//!
//! All numbers are stored AFTER ExifTool's `ValueConv` — exposure / skew
//! times are in seconds (ns / 1e9, QuickTimeStream.pl:431 / 438), GPS
//! coordinates in decimal degrees (the `ToDegrees($val, 1)` for a `double`
//! input is a NO-OP — bundled `GPS.pm` `ToDegrees` only rewrites the
//! `DDD MM SS.SSS` string form, leaving a plain numeric scalar untouched).

extern crate alloc;
use alloc::{string::ToString, vec::Vec};

use smol_str::SmolStr;

use crate::metadata::{GpsLocation, MediaMetadata};

// ===========================================================================
// CammAngleAxis — type 0 (QuickTimeStream.pl camm0:405-421)
// ===========================================================================

/// One CAMM type-0 angle-axis orientation record.
///
/// Faithful port of `%QuickTime::camm0`'s `AngleAxis = float[3]`
/// (QuickTimeStream.pl:416-420): the rotation angles in radians around the
/// X/Y/Z axes in the camera's local coordinate system.
///
/// **Faithfulness note.** Bundled `ProcessCAMM`'s `%size` hash
/// (QuickTimeStream.pl:3491) does NOT carry `0 => N` — type-0 packets cause
/// the loop to bail with `"Unknown camm record type 0"` and `last` (line
/// 3495). [`CammAngleAxis`] is therefore defined for completeness (and so
/// a future expansion can wire it up trivially) but `process_camm`
/// emits NONE for real-world bundled-parity.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CammAngleAxis {
  /// `AngleAxis[0]` — rotation about the X axis (radians).
  x: f32,
  /// `AngleAxis[1]` — rotation about the Y axis (radians).
  y: f32,
  /// `AngleAxis[2]` — rotation about the Z axis (radians).
  z: f32,
}

impl CammAngleAxis {
  /// Construct from raw X/Y/Z float components.
  #[inline(always)]
  #[must_use]
  pub const fn new(x: f32, y: f32, z: f32) -> Self {
    Self { x, y, z }
  }
  /// `AngleAxis[0]`.
  #[inline(always)]
  #[must_use]
  pub const fn x(&self) -> f32 {
    self.x
  }
  /// `AngleAxis[1]`.
  #[inline(always)]
  #[must_use]
  pub const fn y(&self) -> f32 {
    self.y
  }
  /// `AngleAxis[2]`.
  #[inline(always)]
  #[must_use]
  pub const fn z(&self) -> f32 {
    self.z
  }
}

// ===========================================================================
// CammExposure — type 1 (QuickTimeStream.pl camm1:423-440)
// ===========================================================================

/// One CAMM type-1 exposure record (QuickTimeStream.pl:423-440). Both
/// fields are stored in SECONDS — ExifTool's `ValueConv = $val * 1e-9`
/// (QuickTimeStream.pl:431, 438) on the raw `int32s` nanosecond value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CammExposure {
  /// `PixelExposureTime` in seconds (QuickTimeStream.pl:429-433).
  pixel_exposure_time_s: f64,
  /// `RollingShutterSkewTime` in seconds (QuickTimeStream.pl:434-439).
  rolling_shutter_skew_time_s: f64,
}

impl CammExposure {
  /// Construct from raw nanosecond fields. `ValueConv` is applied here.
  #[inline(always)]
  #[must_use]
  pub const fn from_raw_ns(pixel_ns: i32, skew_ns: i32) -> Self {
    Self {
      pixel_exposure_time_s: pixel_ns as f64 * 1e-9,
      rolling_shutter_skew_time_s: skew_ns as f64 * 1e-9,
    }
  }

  /// `PixelExposureTime` in seconds.
  #[inline(always)]
  #[must_use]
  pub const fn pixel_exposure_time_s(&self) -> f64 {
    self.pixel_exposure_time_s
  }

  /// `RollingShutterSkewTime` in seconds.
  #[inline(always)]
  #[must_use]
  pub const fn rolling_shutter_skew_time_s(&self) -> f64 {
    self.rolling_shutter_skew_time_s
  }
}

// ===========================================================================
// CammVector3 — a shared 3-float record (types 2, 3, 4, 7)
// ===========================================================================

/// One CAMM 3-axis float vector — the shape shared by types 2, 3, 4 and 7
/// (`AngularVelocity`, `Acceleration`, `Position`, `MagneticField`).
///
/// Faithful port of the bundled `Format => 'float[3]'` schema
/// (QuickTimeStream.pl:450, 462, 474, 569). The axis order is X/Y/Z, the
/// units differ by source packet type (`rad/s`, `m/s²`, source-frame units,
/// or microtesla — see [`CammMeta`]).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CammVector3 {
  /// X component.
  x: f32,
  /// Y component.
  y: f32,
  /// Z component.
  z: f32,
}

impl CammVector3 {
  /// Construct from raw X/Y/Z components.
  #[inline(always)]
  #[must_use]
  pub const fn new(x: f32, y: f32, z: f32) -> Self {
    Self { x, y, z }
  }
  /// X component.
  #[inline(always)]
  #[must_use]
  pub const fn x(&self) -> f32 {
    self.x
  }
  /// Y component.
  #[inline(always)]
  #[must_use]
  pub const fn y(&self) -> f32 {
    self.y
  }
  /// Z component.
  #[inline(always)]
  #[must_use]
  pub const fn z(&self) -> f32 {
    self.z
  }
}

// ===========================================================================
// CammGpsSample — types 5 and 6 (QuickTimeStream.pl camm5:478-501, camm6:503-560)
// ===========================================================================

/// One CAMM GPS sample — the union of the type-5 (minimal, double
/// lat/lon/alt) and type-6 (full, with measure-mode, accuracy, velocity)
/// payload shapes.
///
/// Faithful merge of `%QuickTime::camm5` (QuickTimeStream.pl:478-501) and
/// `%QuickTime::camm6` (QuickTimeStream.pl:503-560). A type-5 source row
/// leaves every `..._6_only` field `None`. The numeric scalars are stored
/// AFTER `ValueConv` (a no-op for `GPS.pm::ToDegrees($val, 1)` on a numeric
/// double; see module docs).
#[derive(Debug, Clone, PartialEq)]
pub struct CammGpsSample {
  /// CAMM packet type — `5` (minimal) or `6` (full). Used by downstream
  /// projections to distinguish provenance.
  packet_type: u8,
  /// `GPSLatitude` in decimal degrees (positive = North). camm5 byte 4
  /// (double, QuickTimeStream.pl:484), camm6 byte 0x10
  /// (QuickTimeStream.pl:537).
  latitude: Option<f64>,
  /// `GPSLongitude` in decimal degrees (positive = East). camm5 byte 12
  /// (QuickTimeStream.pl:491), camm6 byte 0x18 (QuickTimeStream.pl:544).
  longitude: Option<f64>,
  /// `GPSAltitude` in metres. camm5 byte 20 stores a `double`
  /// (QuickTimeStream.pl:496-500); camm6 byte 0x20 stores a `float`
  /// (QuickTimeStream.pl:550-553).
  altitude_m: Option<f64>,
  /// **camm6 only.** `GPSDateTime` — bundled stores the displayed
  /// `YYYY:MM:DD HH:MM:SS[.sssZ]` string after the heuristic GPS-vs-Unix
  /// epoch correction (QuickTimeStream.pl:509-525). Stored as [`SmolStr`].
  date_time: Option<SmolStr>,
  /// **camm6 only.** `GPSMeasureMode` raw numeric code — `0`, `2`, or `3`
  /// (QuickTimeStream.pl:528-534). The PrintConv text is generated on the
  /// engine side.
  measure_mode: Option<u32>,
  /// **camm6 only.** `GPSHorizontalAccuracy` in metres
  /// (QuickTimeStream.pl:554).
  horizontal_accuracy_m: Option<f32>,
  /// **camm6 only.** `GPSVerticalAccuracy` in metres
  /// (QuickTimeStream.pl:555).
  vertical_accuracy_m: Option<f32>,
  /// **camm6 only.** `GPSVelocityEast` in m/s (QuickTimeStream.pl:556).
  velocity_east_mps: Option<f32>,
  /// **camm6 only.** `GPSVelocityNorth` in m/s (QuickTimeStream.pl:557).
  velocity_north_mps: Option<f32>,
  /// **camm6 only.** `GPSVelocityUp` in m/s (QuickTimeStream.pl:558).
  velocity_up_mps: Option<f32>,
  /// **camm6 only.** `GPSSpeedAccuracy` in m/s (QuickTimeStream.pl:559).
  speed_accuracy_mps: Option<f32>,
  /// 1-based moov track number of the `camm` `trak` this sample was decoded
  /// from — ExifTool's `SET_GROUP1 = "Track$num"` (`++$track` over EVERY
  /// `trak` SubDirectory, QuickTime.pm:10353-10354), the family-1 group under
  /// which a camm GPS sample is emitted (oracle: `Track1:GPSLatitude`). `None`
  /// until the stream walker stamps it. Stored per-sample (not per-meta)
  /// because the enclosing [`CammMeta`] is file-scoped and could accumulate
  /// samples from more than one `camm` `trak`.
  track_index: Option<u32>,
}

impl CammGpsSample {
  /// An empty sample marked with the given packet type.
  #[inline(always)]
  #[must_use]
  pub const fn new(packet_type: u8) -> Self {
    Self {
      packet_type,
      latitude: None,
      longitude: None,
      altitude_m: None,
      date_time: None,
      measure_mode: None,
      horizontal_accuracy_m: None,
      vertical_accuracy_m: None,
      velocity_east_mps: None,
      velocity_north_mps: None,
      velocity_up_mps: None,
      speed_accuracy_mps: None,
      track_index: None,
    }
  }

  /// CAMM packet type (`5` or `6`).
  #[inline(always)]
  #[must_use]
  pub const fn packet_type(&self) -> u8 {
    self.packet_type
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

  /// `GPSAltitude` in metres (per QuickTimeStream.pl:496-500 for camm5,
  /// :550-553 for camm6).
  #[inline(always)]
  #[must_use]
  pub const fn altitude_m(&self) -> Option<f64> {
    self.altitude_m
  }

  /// `GPSDateTime` displayed string (camm6 only).
  #[inline(always)]
  #[must_use]
  pub fn date_time(&self) -> Option<&str> {
    self.date_time.as_deref()
  }

  /// `GPSMeasureMode` raw numeric code (camm6 only).
  #[inline(always)]
  #[must_use]
  pub const fn measure_mode(&self) -> Option<u32> {
    self.measure_mode
  }

  /// `GPSHorizontalAccuracy` in metres (camm6 only).
  #[inline(always)]
  #[must_use]
  pub const fn horizontal_accuracy_m(&self) -> Option<f32> {
    self.horizontal_accuracy_m
  }

  /// `GPSVerticalAccuracy` in metres (camm6 only).
  #[inline(always)]
  #[must_use]
  pub const fn vertical_accuracy_m(&self) -> Option<f32> {
    self.vertical_accuracy_m
  }

  /// `GPSVelocityEast` in m/s (camm6 only).
  #[inline(always)]
  #[must_use]
  pub const fn velocity_east_mps(&self) -> Option<f32> {
    self.velocity_east_mps
  }

  /// `GPSVelocityNorth` in m/s (camm6 only).
  #[inline(always)]
  #[must_use]
  pub const fn velocity_north_mps(&self) -> Option<f32> {
    self.velocity_north_mps
  }

  /// `GPSVelocityUp` in m/s (camm6 only).
  #[inline(always)]
  #[must_use]
  pub const fn velocity_up_mps(&self) -> Option<f32> {
    self.velocity_up_mps
  }

  /// `GPSSpeedAccuracy` in m/s (camm6 only).
  #[inline(always)]
  #[must_use]
  pub const fn speed_accuracy_mps(&self) -> Option<f32> {
    self.speed_accuracy_mps
  }

  /// 1-based moov track number of the originating `camm` `trak` — the
  /// family-1 `Track<N>` group ExifTool emits this sample under (oracle:
  /// `Track1:GPSLatitude`). `None` until the stream walker stamps it.
  #[inline(always)]
  #[must_use]
  pub const fn track_index(&self) -> Option<u32> {
    self.track_index
  }

  /// Stamp the 1-based moov track number of the originating `trak`.
  #[inline(always)]
  pub const fn set_track_index(&mut self, v: Option<u32>) -> &mut Self {
    self.track_index = v;
    self
  }

  /// `true` when the sample carries a non-zero coordinate pair.
  #[inline(always)]
  #[must_use]
  pub const fn has_coordinates(&self) -> bool {
    self.latitude.is_some() && self.longitude.is_some()
  }

  /// `true` when every field beyond `packet_type` is `None`.
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.latitude.is_none()
      && self.longitude.is_none()
      && self.altitude_m.is_none()
      && self.date_time.is_none()
      && self.measure_mode.is_none()
      && self.horizontal_accuracy_m.is_none()
      && self.vertical_accuracy_m.is_none()
      && self.velocity_east_mps.is_none()
      && self.velocity_north_mps.is_none()
      && self.velocity_up_mps.is_none()
      && self.speed_accuracy_mps.is_none()
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

  /// Assign `GPSAltitude`.
  #[inline(always)]
  pub const fn set_altitude_m(&mut self, v: Option<f64>) -> &mut Self {
    self.altitude_m = v;
    self
  }

  /// Assign `GPSDateTime`.
  #[inline(always)]
  pub fn set_date_time(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.date_time = v;
    self
  }

  /// Assign `GPSMeasureMode`.
  #[inline(always)]
  pub const fn set_measure_mode(&mut self, v: Option<u32>) -> &mut Self {
    self.measure_mode = v;
    self
  }

  /// Assign `GPSHorizontalAccuracy`.
  #[inline(always)]
  pub const fn set_horizontal_accuracy_m(&mut self, v: Option<f32>) -> &mut Self {
    self.horizontal_accuracy_m = v;
    self
  }

  /// Assign `GPSVerticalAccuracy`.
  #[inline(always)]
  pub const fn set_vertical_accuracy_m(&mut self, v: Option<f32>) -> &mut Self {
    self.vertical_accuracy_m = v;
    self
  }

  /// Assign `GPSVelocityEast`.
  #[inline(always)]
  pub const fn set_velocity_east_mps(&mut self, v: Option<f32>) -> &mut Self {
    self.velocity_east_mps = v;
    self
  }

  /// Assign `GPSVelocityNorth`.
  #[inline(always)]
  pub const fn set_velocity_north_mps(&mut self, v: Option<f32>) -> &mut Self {
    self.velocity_north_mps = v;
    self
  }

  /// Assign `GPSVelocityUp`.
  #[inline(always)]
  pub const fn set_velocity_up_mps(&mut self, v: Option<f32>) -> &mut Self {
    self.velocity_up_mps = v;
    self
  }

  /// Assign `GPSSpeedAccuracy`.
  #[inline(always)]
  pub const fn set_speed_accuracy_mps(&mut self, v: Option<f32>) -> &mut Self {
    self.speed_accuracy_mps = v;
    self
  }
}

// ===========================================================================
// CammMeta — the aggregate per-track result
// ===========================================================================

/// The typed result of Android CAMM (Google Camera Motion Metadata)
/// extraction — the per-format mirror of every record `ProcessCAMM`
/// (QuickTimeStream.pl:3481-3506) would emit for a video's `camm` metadata
/// track.
///
/// Empty (`is_empty()`) when CAMM data was sought but none was decoded
/// (the common case for a video without an Android-style camm track).
///
/// **D8 compliance.** All fields are private; access goes through the
/// accessors / setters below.
#[derive(Debug, Clone, PartialEq)]
pub struct CammMeta {
  /// Type-0 `AngleAxis` samples in source order. **Always empty** in
  /// bundled-parity (see [`CammAngleAxis`]); kept so future port expansions
  /// can fill it without an API break.
  angle_axis: Vec<CammAngleAxis>,
  /// Type-1 `PixelExposureTime` / `RollingShutterSkewTime` samples
  /// (QuickTimeStream.pl camm1:423-440).
  exposure: Vec<CammExposure>,
  /// Type-2 `AngularVelocity` samples in rad/s
  /// (QuickTimeStream.pl camm2:442-452).
  angular_velocity: Vec<CammVector3>,
  /// Type-3 `Acceleration` samples in m/s² (QuickTimeStream.pl camm3:454-464).
  acceleration: Vec<CammVector3>,
  /// Type-4 `Position` samples (QuickTimeStream.pl camm4:466-476).
  position: Vec<CammVector3>,
  /// Type-5 + type-6 GPS samples in source order. The `packet_type` field on
  /// each sample preserves provenance (5 = minimal, 6 = full).
  gps_samples: Vec<CammGpsSample>,
  /// Type-7 `MagneticField` samples in microtesla
  /// (QuickTimeStream.pl camm7:562-572).
  magnetic_field: Vec<CammVector3>,
}

impl CammMeta {
  /// An empty result (no CAMM metadata decoded).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      angle_axis: Vec::new(),
      exposure: Vec::new(),
      angular_velocity: Vec::new(),
      acceleration: Vec::new(),
      position: Vec::new(),
      gps_samples: Vec::new(),
      magnetic_field: Vec::new(),
    }
  }

  /// Type-0 `AngleAxis` samples (orientation, radians, X/Y/Z).
  #[inline(always)]
  #[must_use]
  pub fn angle_axis(&self) -> &[CammAngleAxis] {
    self.angle_axis.as_slice()
  }

  /// Type-1 exposure / rolling-shutter samples (seconds).
  #[inline(always)]
  #[must_use]
  pub fn exposure(&self) -> &[CammExposure] {
    self.exposure.as_slice()
  }

  /// Type-2 `AngularVelocity` samples (rad/s).
  #[inline(always)]
  #[must_use]
  pub fn angular_velocity(&self) -> &[CammVector3] {
    self.angular_velocity.as_slice()
  }

  /// Type-3 `Acceleration` samples (m/s²).
  #[inline(always)]
  #[must_use]
  pub fn acceleration(&self) -> &[CammVector3] {
    self.acceleration.as_slice()
  }

  /// Type-4 `Position` samples (local-coordinate units).
  #[inline(always)]
  #[must_use]
  pub fn position(&self) -> &[CammVector3] {
    self.position.as_slice()
  }

  /// Type-5 + type-6 GPS samples in source order.
  #[inline(always)]
  #[must_use]
  pub fn gps_samples(&self) -> &[CammGpsSample] {
    self.gps_samples.as_slice()
  }

  /// Type-7 `MagneticField` samples (microtesla).
  #[inline(always)]
  #[must_use]
  pub fn magnetic_field(&self) -> &[CammVector3] {
    self.magnetic_field.as_slice()
  }

  /// `true` when no record was decoded.
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.angle_axis.is_empty()
      && self.exposure.is_empty()
      && self.angular_velocity.is_empty()
      && self.acceleration.is_empty()
      && self.position.is_empty()
      && self.gps_samples.is_empty()
      && self.magnetic_field.is_empty()
  }

  /// The FIRST GPS sample carrying a coordinate pair — used by the
  /// [`crate::metadata::MediaMetadata`] projection to fill
  /// [`crate::metadata::GpsLocation`].
  #[inline(always)]
  #[must_use]
  pub fn first_fix(&self) -> Option<&CammGpsSample> {
    self.gps_samples.iter().find(|s| s.has_coordinates())
  }

  /// Append a decoded `AngleAxis` (type-0) sample.
  #[inline(always)]
  pub fn push_angle_axis(&mut self, sample: CammAngleAxis) -> &mut Self {
    self.angle_axis.push(sample);
    self
  }

  /// Append a decoded exposure (type-1) sample.
  #[inline(always)]
  pub fn push_exposure(&mut self, sample: CammExposure) -> &mut Self {
    self.exposure.push(sample);
    self
  }

  /// Append a decoded `AngularVelocity` (type-2) sample.
  #[inline(always)]
  pub fn push_angular_velocity(&mut self, sample: CammVector3) -> &mut Self {
    self.angular_velocity.push(sample);
    self
  }

  /// Append a decoded `Acceleration` (type-3) sample.
  #[inline(always)]
  pub fn push_acceleration(&mut self, sample: CammVector3) -> &mut Self {
    self.acceleration.push(sample);
    self
  }

  /// Append a decoded `Position` (type-4) sample.
  #[inline(always)]
  pub fn push_position(&mut self, sample: CammVector3) -> &mut Self {
    self.position.push(sample);
    self
  }

  /// Append a decoded GPS (type-5 or type-6) sample.
  #[inline(always)]
  pub fn push_gps_sample(&mut self, sample: CammGpsSample) -> &mut Self {
    self.gps_samples.push(sample);
    self
  }

  /// The number of GPS samples decoded so far — a watermark the stream walker
  /// takes BEFORE decoding one `camm` `trak`'s samples so it can stamp the
  /// `Track<N>` index onto exactly the samples that `trak` produced (see
  /// [`Self::stamp_gps_track_index_from`]).
  #[inline(always)]
  #[must_use]
  pub(crate) fn gps_sample_count(&self) -> usize {
    self.gps_samples.len()
  }

  /// Stamp the 1-based moov `track_index` onto every GPS sample at or after
  /// `start` — the samples decoded from a single `camm` `trak` since the
  /// walker took its [`Self::gps_sample_count`] watermark. Faithful to
  /// ExifTool scoping `SET_GROUP1 = "Track$num"` per-`trak`
  /// (QuickTime.pm:10353-10354): each sample carries the group of the `trak`
  /// it actually came from, even when this file-scoped meta accumulates more
  /// than one `camm` `trak`.
  pub(crate) fn stamp_gps_track_index_from(&mut self, start: usize, track: u32) {
    if let Some(slice) = self.gps_samples.get_mut(start..) {
      for s in slice {
        s.set_track_index(Some(track));
      }
    }
  }

  /// Append a decoded `MagneticField` (type-7) sample.
  #[inline(always)]
  pub fn push_magnetic_field(&mut self, sample: CammVector3) -> &mut Self {
    self.magnetic_field.push(sample);
    self
  }
}

impl Default for CammMeta {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// Android CAMM projection into MediaMetadata (golden L2)
// ===========================================================================

impl CammMeta {
  /// Project Android CAMM metadata into [`MediaMetadata`].
  ///
  /// **GpsLocation:** Android CAMM (camm5/camm6) sits BELOW GoPro GPMF on
  /// device-GNSS authority but ABOVE the generic SP3 timed-metadata scan in
  /// the cross-port GPS priority chain. The FIRST sample carrying a
  /// coordinate pair populates `GpsLocation` (`first_fix()`); only camm6
  /// carries `GPSDateTime` per-sample (camm5's timestamp lives at the
  /// sample-table level and is left to the engine to surface).
  ///
  /// CAMM does NOT carry a camera-identity record (per QuickTimeStream.pl —
  /// the CAMM tables hold only motion / GPS / sensor data); the Camera
  /// domain stays under the existing higher-priority source.
  ///
  /// An inherent helper (not the golden [`Project`](crate::metadata::Project)
  /// trait): CAMM has no standalone file type — it is reached only through
  /// the QuickTime container, whose projection
  /// ([`crate::formats::quicktime::Meta::media_metadata`]) calls this to fold
  /// the on-device GNSS contribution into the QuickTime projection at the
  /// CAMM GPS priority tier (mirroring the GoPro GPMF projection).
  pub(crate) fn project_into(&self, md: &mut MediaMetadata) {
    if md.gps().is_none()
      && let Some(c) = self.first_fix()
    {
      let mut gps = GpsLocation::new();
      gps
        .update_latitude(c.latitude())
        .update_longitude(c.longitude())
        .update_altitude_m(c.altitude_m())
        .update_timestamp(c.date_time().map(str::to_string));
      md.set_gps(gps);
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn vector3_accessors() {
    let v = CammVector3::new(1.0, -2.0, 3.5);
    assert_eq!(v.x(), 1.0);
    assert_eq!(v.y(), -2.0);
    assert_eq!(v.z(), 3.5);
  }

  #[test]
  fn exposure_value_conv_seconds() {
    // 1_000_000_000 ns ⇒ 1 s; -500_000_000 ns ⇒ -0.5 s
    let e = CammExposure::from_raw_ns(1_000_000_000, -500_000_000);
    assert!((e.pixel_exposure_time_s() - 1.0).abs() < 1e-12);
    assert!((e.rolling_shutter_skew_time_s() + 0.5).abs() < 1e-12);
  }

  #[test]
  fn gps_sample_packet_type_and_emptiness() {
    let s5 = CammGpsSample::new(5);
    assert_eq!(s5.packet_type(), 5);
    assert!(s5.is_empty());
    assert!(!s5.has_coordinates());
    let mut s6 = CammGpsSample::new(6);
    s6.set_latitude(Some(37.5)).set_longitude(Some(-122.0));
    assert!(s6.has_coordinates());
    assert!(!s6.is_empty());
  }

  #[test]
  fn meta_first_fix_skips_no_coord_samples() {
    let mut m = CammMeta::new();
    assert!(m.is_empty());
    let mut s = CammGpsSample::new(6);
    s.set_altitude_m(Some(100.0));
    m.push_gps_sample(s);
    let mut t = CammGpsSample::new(5);
    t.set_latitude(Some(1.0)).set_longitude(Some(2.0));
    m.push_gps_sample(t);
    assert!(!m.is_empty());
    assert_eq!(m.first_fix().expect("fix").latitude(), Some(1.0));
  }

  #[test]
  fn angle_axis_x_y_z() {
    let a = CammAngleAxis::new(0.1, 0.2, 0.3);
    assert_eq!(a.x(), 0.1);
    assert_eq!(a.y(), 0.2);
    assert_eq!(a.z(), 0.3);
  }

  // P3-D project_into round-trip.

  #[test]
  fn project_into_empty_meta_writes_nothing() {
    let m = CammMeta::new();
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert!(md.gps().is_none());
  }

  #[test]
  fn project_into_populates_gps_from_first_camm5_fix() {
    let mut m = CammMeta::new();
    let mut s = CammGpsSample::new(5);
    s.set_latitude(Some(37.77))
      .set_longitude(Some(-122.42))
      .set_altitude_m(Some(50.0));
    m.push_gps_sample(s);
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    let gps = md.gps().expect("gps populated");
    assert_eq!(gps.latitude(), Some(37.77));
    assert_eq!(gps.altitude_m(), Some(50.0));
  }

  #[test]
  fn project_into_skips_gps_when_higher_priority_set() {
    let mut m = CammMeta::new();
    let mut s = CammGpsSample::new(5);
    s.set_latitude(Some(1.0)).set_longitude(Some(2.0));
    m.push_gps_sample(s);
    let mut md = MediaMetadata::new();
    let mut existing = GpsLocation::new();
    existing
      .update_latitude(Some(99.0))
      .update_longitude(Some(99.0));
    md.set_gps(existing);
    m.project_into(&mut md);
    // Higher-priority source's latitude wins.
    assert_eq!(md.gps().expect("gps").latitude(), Some(99.0));
  }

  #[test]
  fn project_into_camm6_carries_date_time_into_timestamp() {
    let mut m = CammMeta::new();
    let mut s = CammGpsSample::new(6);
    s.set_latitude(Some(40.0))
      .set_longitude(Some(-105.0))
      .set_altitude_m(Some(1500.0))
      .set_date_time(Some("2024:02:03 04:05:06.789Z".into()));
    m.push_gps_sample(s);
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    let gps = md.gps().expect("gps populated");
    assert_eq!(gps.timestamp(), Some("2024:02:03 04:05:06.789Z"));
  }
}
