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
  /// 1-based moov `Track<N>` group of the originating `camm` `trak` — see the
  /// like-named [`CammGpsSample`] field. `None` until the walker stamps it.
  track_index: Option<u32>,
  /// 1-based GLOBAL `Doc<N>` ordinal of the camm SAMPLE this record came from —
  /// see the like-named [`CammGpsSample`] field. Stamped off the shared
  /// [`crate::metadata::QuickTimeStreamMeta`] doc counter at extraction.
  doc: Option<u32>,
  /// `SampleTime` — the sample-table decode time in seconds of the camm SAMPLE
  /// this record came from. See the like-named [`CammGpsSample`] field. `None`
  /// until the walker stamps it.
  sample_time: Option<f64>,
  /// `SampleDuration` — the sample-table duration in seconds of the camm SAMPLE
  /// this record came from. See the like-named [`CammGpsSample`] field. `None`
  /// until the walker stamps it.
  sample_duration: Option<f64>,
}

impl CammExposure {
  /// Construct from raw nanosecond fields. `ValueConv` is applied here.
  #[inline(always)]
  #[must_use]
  pub const fn from_raw_ns(pixel_ns: i32, skew_ns: i32) -> Self {
    Self {
      pixel_exposure_time_s: pixel_ns as f64 * 1e-9,
      rolling_shutter_skew_time_s: skew_ns as f64 * 1e-9,
      track_index: None,
      doc: None,
      sample_time: None,
      sample_duration: None,
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

  /// 1-based moov `Track<N>` index of the originating `camm` `trak`, or `None`
  /// until the stream walker stamps it.
  #[inline(always)]
  #[must_use]
  pub const fn track_index(&self) -> Option<u32> {
    self.track_index
  }

  /// 1-based GLOBAL `Doc<N>` ordinal of this record's camm sample, or `None`
  /// until the walker stamps it.
  #[inline(always)]
  #[must_use]
  pub const fn doc(&self) -> Option<u32> {
    self.doc
  }

  /// Stamp the 1-based moov `Track<N>` index.
  #[inline(always)]
  pub const fn set_track_index(&mut self, v: Option<u32>) -> &mut Self {
    self.track_index = v;
    self
  }

  /// Stamp the GLOBAL `Doc<N>` ordinal of this record's camm sample.
  #[inline(always)]
  pub const fn set_doc(&mut self, v: Option<u32>) -> &mut Self {
    self.doc = v;
    self
  }

  /// `SampleTime` of this record's camm sample (seconds), or `None` until the
  /// walker stamps it.
  #[inline(always)]
  #[must_use]
  pub const fn sample_time(&self) -> Option<f64> {
    self.sample_time
  }

  /// `SampleDuration` of this record's camm sample (seconds), or `None` until
  /// the walker stamps it.
  #[inline(always)]
  #[must_use]
  pub const fn sample_duration(&self) -> Option<f64> {
    self.sample_duration
  }

  /// Stamp the sample-table `SampleTime` / `SampleDuration` (seconds) of this
  /// record's camm sample.
  #[inline(always)]
  pub const fn set_sample_timing(&mut self, time: Option<f64>, duration: Option<f64>) -> &mut Self {
    self.sample_time = time;
    self.sample_duration = duration;
    self
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
  /// 1-based moov `Track<N>` group of the originating `camm` `trak` — see the
  /// like-named [`CammGpsSample`] field. `None` until the walker stamps it.
  track_index: Option<u32>,
  /// 1-based GLOBAL `Doc<N>` ordinal of the camm SAMPLE this record came from —
  /// see the like-named [`CammGpsSample`] field. Stamped off the shared
  /// [`crate::metadata::QuickTimeStreamMeta`] doc counter at extraction.
  doc: Option<u32>,
  /// `SampleTime` — the sample-table decode time in seconds of the camm SAMPLE
  /// this record came from. See the like-named [`CammGpsSample`] field. `None`
  /// until the walker stamps it.
  sample_time: Option<f64>,
  /// `SampleDuration` — the sample-table duration in seconds of the camm SAMPLE
  /// this record came from. See the like-named [`CammGpsSample`] field. `None`
  /// until the walker stamps it.
  sample_duration: Option<f64>,
}

impl CammVector3 {
  /// Construct from raw X/Y/Z components.
  #[inline(always)]
  #[must_use]
  pub const fn new(x: f32, y: f32, z: f32) -> Self {
    Self {
      x,
      y,
      z,
      track_index: None,
      doc: None,
      sample_time: None,
      sample_duration: None,
    }
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

  /// 1-based moov `Track<N>` index of the originating `camm` `trak`, or `None`
  /// until the stream walker stamps it.
  #[inline(always)]
  #[must_use]
  pub const fn track_index(&self) -> Option<u32> {
    self.track_index
  }

  /// 1-based GLOBAL `Doc<N>` ordinal of this record's camm sample, or `None`
  /// until the walker stamps it.
  #[inline(always)]
  #[must_use]
  pub const fn doc(&self) -> Option<u32> {
    self.doc
  }

  /// Stamp the 1-based moov `Track<N>` index.
  #[inline(always)]
  pub const fn set_track_index(&mut self, v: Option<u32>) -> &mut Self {
    self.track_index = v;
    self
  }

  /// Stamp the GLOBAL `Doc<N>` ordinal of this record's camm sample.
  #[inline(always)]
  pub const fn set_doc(&mut self, v: Option<u32>) -> &mut Self {
    self.doc = v;
    self
  }

  /// `SampleTime` of this record's camm sample (seconds), or `None` until the
  /// walker stamps it.
  #[inline(always)]
  #[must_use]
  pub const fn sample_time(&self) -> Option<f64> {
    self.sample_time
  }

  /// `SampleDuration` of this record's camm sample (seconds), or `None` until
  /// the walker stamps it.
  #[inline(always)]
  #[must_use]
  pub const fn sample_duration(&self) -> Option<f64> {
    self.sample_duration
  }

  /// Stamp the sample-table `SampleTime` / `SampleDuration` (seconds) of this
  /// record's camm sample.
  #[inline(always)]
  pub const fn set_sample_timing(&mut self, time: Option<f64>, duration: Option<f64>) -> &mut Self {
    self.sample_time = time;
    self.sample_duration = duration;
    self
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
  /// 1-based GLOBAL document ordinal (`$$et{DOC_NUM} = ++$$et{DOC_COUNT}`) of
  /// the camm SAMPLE this fix was decoded from — the `Doc<N>` the `-ee -G3`
  /// emitter writes. ExifTool's `ProcessSamples` runs `FoundSomething`
  /// (`++DOC_COUNT`) ONCE per camm sample BEFORE dispatching `ProcessCAMM`
  /// (QuickTimeStream.pl:1523), then `ProcessCAMM` `HandleTag`s EVERY packet of
  /// that sample under the SAME `DOC_NUM` (it never bumps the doc itself,
  /// QuickTimeStream.pl:3493-3504) — so all fixes from one camm sample share one
  /// `Doc<N>`. Stamped at extraction from the SHARED
  /// [`crate::metadata::QuickTimeStreamMeta`] doc counter (camm lives in a
  /// SEPARATE struct from the `mebx`/SP3 sources, yet ExifTool numbers every
  /// embedded sample off ONE `$$et{DOC_COUNT}`), so it is GLOBAL across the
  /// file's other timed sources in walk order (e.g. a camm `trak` following a
  /// `mebx` `trak` continues the ordinal — `mebx` Doc1, camm Doc2..). `None`
  /// until the walker stamps it (and for unit-built samples), in which case the
  /// emitter falls back to its running per-source ordinal.
  doc: Option<u32>,
  /// `SampleTime` — the sample-table decode time in seconds of the camm SAMPLE
  /// this fix was decoded from (ExifTool's `ProcessSamples` emits it ahead of the
  /// decoded payload, QuickTimeStream.pl:1520; PrintConv `ConvertDuration`). All
  /// packets of one camm sample share one sample-table entry, so they share this
  /// value. `None` until the stream walker stamps it (and for unit-built
  /// samples), in which case the emitter omits it.
  sample_time: Option<f64>,
  /// `SampleDuration` — the sample-table duration in seconds of the camm SAMPLE
  /// this fix was decoded from (paired with [`Self::sample_time`]). `None` until
  /// the walker stamps it.
  sample_duration: Option<f64>,
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
      doc: None,
      sample_time: None,
      sample_duration: None,
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

  /// The 1-based GLOBAL document ordinal (`Doc<N>`) of this fix's camm sample
  /// (see the `doc` field docs), or `None` until the walker stamps it.
  #[inline(always)]
  #[must_use]
  pub const fn doc(&self) -> Option<u32> {
    self.doc
  }

  /// Stamp the GLOBAL document ordinal — the shared `++DOC_COUNT` of the camm
  /// sample this fix came from (see the `doc` field docs).
  #[inline(always)]
  pub const fn set_doc(&mut self, v: Option<u32>) -> &mut Self {
    self.doc = v;
    self
  }

  /// `SampleTime` (seconds) of this fix's camm sample — the sample-table decode
  /// time ExifTool emits ahead of the payload — or `None` until the walker stamps
  /// it. All packets of one camm sample share it.
  #[inline(always)]
  #[must_use]
  pub const fn sample_time(&self) -> Option<f64> {
    self.sample_time
  }

  /// `SampleDuration` (seconds) of this fix's camm sample, or `None` until the
  /// walker stamps it.
  #[inline(always)]
  #[must_use]
  pub const fn sample_duration(&self) -> Option<f64> {
    self.sample_duration
  }

  /// Stamp the sample-table `SampleTime` / `SampleDuration` (seconds) of this
  /// fix's camm sample.
  #[inline(always)]
  pub const fn set_sample_timing(&mut self, time: Option<f64>, duration: Option<f64>) -> &mut Self {
    self.sample_time = time;
    self.sample_duration = duration;
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
// CammWarning — a per-call ProcessCAMM warning (Unknown / Truncated record)
// ===========================================================================

/// One `ProcessCAMM` walk-abort warning (`QuickTimeStream.pl:3495-3496`).
///
/// `ProcessCAMM` `$et->Warn`s then `last`s on (a) an UNKNOWN packet type —
/// `"Unknown camm record type $type"` (`:3495`, fired for type 0 and any type
/// absent from `%size`) — or (b) a TRUNCATED packet — `"Truncated camm record
/// $type"` (`:3496`). Both are plain `$et->Warn(msg)` calls with NO `ignorable`
/// argument, so — unlike the `[minor]` `ExtractEmbedded` warning (`Warn(msg,
/// 3)`) — they carry NO `[minor]` prefix (`ExifTool.pm:5616-5642`).
///
/// The warning is surfaced as a `Track<N>:Warning` scoped to the camm `trak`
/// it occurred in (the same in-stream priority-0 first-wins `Warning` channel
/// the eeBox EEWarn uses), under the `Doc<N>` of the camm SAMPLE that raised
/// it — `ProcessSamples` opens one `Doc<N>` per timed sample (`FoundSomething`,
/// QuickTimeStream.pl:1523) BEFORE `ProcessCAMM` runs, and `$et->Warn`
/// `FoundTag`s the `Warning` under that current `DOC_NUM` (oracle:
/// `Doc2:Track1:Warning` for a camm0 sample following a GPS-fix sample). The
/// walker stamps `track_index` + `doc` after the (multi-packet) `process_camm`
/// call, mirroring the GPS-sample stamps.
///
/// **D8 compliance.** Fields are private; access via the accessors below.
#[derive(Debug, Clone, PartialEq)]
pub struct CammWarning {
  /// The verbatim warning string (NO `[minor]` prefix — a plain `$et->Warn`).
  message: SmolStr,
  /// The 1-based moov `Track<N>` index the warning is scoped to (`None` until
  /// the walker stamps it; defaults to `Track1` at emit time).
  track_index: Option<u32>,
  /// The GLOBAL `Doc<N>` ordinal of the camm sample that raised the warning
  /// (`None` until the walker stamps it). Surfaced as the `Doc<N>:` family-3
  /// prefix at `-G3:1`; collapsed away at `-G1`.
  doc: Option<u32>,
  /// `SampleTime` (seconds) of the camm sample that raised the warning — emitted
  /// ahead of the `Warning` under that sample's `Doc<N>` (oracle camm0:
  /// `Doc1:Track1:SampleTime`, then `SampleDuration`, then `Warning`). `None`
  /// until the walker stamps it.
  sample_time: Option<f64>,
  /// `SampleDuration` (seconds) of the camm sample that raised the warning
  /// (paired with [`Self::sample_time`]). `None` until the walker stamps it.
  sample_duration: Option<f64>,
}

impl CammWarning {
  /// Build a warning carrying `message` (no track/doc index yet — the walker
  /// stamps them after the `process_camm` call).
  #[inline(always)]
  #[must_use]
  pub(crate) fn new(message: SmolStr) -> Self {
    Self {
      message,
      track_index: None,
      doc: None,
      sample_time: None,
      sample_duration: None,
    }
  }

  /// The verbatim warning string (NO `[minor]` prefix).
  #[inline(always)]
  #[must_use]
  pub fn message(&self) -> &str {
    self.message.as_str()
  }

  /// The 1-based moov `Track<N>` index this warning is scoped to.
  #[inline(always)]
  #[must_use]
  pub const fn track_index(&self) -> Option<u32> {
    self.track_index
  }

  /// The GLOBAL `Doc<N>` ordinal of the camm sample that raised this warning.
  #[inline(always)]
  #[must_use]
  pub const fn doc(&self) -> Option<u32> {
    self.doc
  }

  /// Stamp the 1-based moov `Track<N>` index (walker-only).
  #[inline(always)]
  pub(crate) const fn set_track_index(&mut self, v: Option<u32>) -> &mut Self {
    self.track_index = v;
    self
  }

  /// Stamp the GLOBAL `Doc<N>` ordinal (walker-only).
  #[inline(always)]
  pub(crate) const fn set_doc(&mut self, v: Option<u32>) -> &mut Self {
    self.doc = v;
    self
  }

  /// `SampleTime` (seconds) of the camm sample that raised this warning, or
  /// `None` until the walker stamps it.
  #[inline(always)]
  #[must_use]
  pub const fn sample_time(&self) -> Option<f64> {
    self.sample_time
  }

  /// `SampleDuration` (seconds) of the camm sample that raised this warning, or
  /// `None` until the walker stamps it.
  #[inline(always)]
  #[must_use]
  pub const fn sample_duration(&self) -> Option<f64> {
    self.sample_duration
  }

  /// Stamp the sample-table `SampleTime` / `SampleDuration` (seconds) of the camm
  /// sample that raised this warning (walker-only).
  #[inline(always)]
  pub(crate) const fn set_sample_timing(
    &mut self,
    time: Option<f64>,
    duration: Option<f64>,
  ) -> &mut Self {
    self.sample_time = time;
    self.sample_duration = duration;
    self
  }
}

// ===========================================================================
// CammTimingOnly — a recognized camm sample that decoded to NO stored record
// ===========================================================================

/// A per-sample TIMING-ONLY marker for a recognized camm sample (its FIRST
/// packet matched a `camm0..camm7` SubDirectory `Condition`, so ExifTool's
/// `GetTagInfo` returned a tagInfo) whose `ProcessCAMM` walk produced NO stored
/// record — no GPS / motion / exposure fix AND no `Unknown`/`Truncated` warning.
///
/// **Why this exists.** ExifTool fires `FoundSomething`
/// (`$$et{DOC_NUM} = ++$$et{DOC_COUNT}` + `HandleTag SampleTime`/`SampleDuration`,
/// QuickTimeStream.pl:967-972) the moment a first-packet `Condition` matches
/// (`ProcessSamples`:1523), BEFORE — and INDEPENDENTLY of — what `ProcessCAMM`
/// then decodes. So a recognized sample that yields no packet (e.g. a 4-byte-only
/// header: `ProcessCAMM`'s `while ($pos + 4 < $end)` never iterates) STILL emits
/// `Doc<N>:Track<N>:SampleTime`/`SampleDuration` (oracle
/// `QuickTime_camm_emptypayload.mov`). Without a stored marker that timing has no
/// record to ride on, so it would be dropped from the `-G1` cross-kind min-doc
/// scan ([`crate::metadata::CammMeta`] feeds [`CammGpsSample`] / [`CammVector3`] /
/// [`CammExposure`] / [`CammWarning`] into it) and from the `-G3` per-`Doc<N>`
/// emission. This marker carries exactly that sample's `Doc<N>` / `Track<N>` /
/// `SampleTime` / `SampleDuration` so both paths see it.
///
/// **D8 compliance.** Fields are private; access via the accessors below.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CammTimingOnly {
  /// The 1-based moov `Track<N>` index of the camm `trak` the sample belongs to
  /// (`None` until the walker stamps it; defaults to `Track1` at emit time).
  track_index: Option<u32>,
  /// The GLOBAL `Doc<N>` ordinal (`$$et{DOC_NUM} = ++$$et{DOC_COUNT}`) of this
  /// camm sample — the same shared-counter `Doc<N>` the sample's `open_doc` got.
  /// `None` until the walker stamps it.
  doc: Option<u32>,
  /// `SampleTime` (seconds) of this camm sample — the sample-table decode time
  /// `FoundSomething` emits. `None` until the walker stamps it.
  sample_time: Option<f64>,
  /// `SampleDuration` (seconds) of this camm sample (paired with
  /// [`Self::sample_time`]). `None` until the walker stamps it.
  sample_duration: Option<f64>,
}

impl CammTimingOnly {
  /// An unstamped marker (the walker stamps track/doc/timing after the
  /// `process_camm` call, like the GPS/motion/warning records).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn new() -> Self {
    Self {
      track_index: None,
      doc: None,
      sample_time: None,
      sample_duration: None,
    }
  }

  /// The 1-based moov `Track<N>` index of this sample's camm `trak`.
  #[inline(always)]
  #[must_use]
  pub const fn track_index(&self) -> Option<u32> {
    self.track_index
  }

  /// The GLOBAL `Doc<N>` ordinal of this camm sample.
  #[inline(always)]
  #[must_use]
  pub const fn doc(&self) -> Option<u32> {
    self.doc
  }

  /// `SampleTime` (seconds) of this camm sample, or `None` until the walker
  /// stamps it.
  #[inline(always)]
  #[must_use]
  pub const fn sample_time(&self) -> Option<f64> {
    self.sample_time
  }

  /// `SampleDuration` (seconds) of this camm sample, or `None` until the walker
  /// stamps it.
  #[inline(always)]
  #[must_use]
  pub const fn sample_duration(&self) -> Option<f64> {
    self.sample_duration
  }

  /// Stamp the `Track<N>` index, GLOBAL `Doc<N>` ordinal, and sample-table
  /// `SampleTime` / `SampleDuration` (walker-only).
  #[inline(always)]
  pub(crate) const fn set_stamp(
    &mut self,
    track: u32,
    doc: u32,
    time: Option<f64>,
    duration: Option<f64>,
  ) -> &mut Self {
    self.track_index = Some(track);
    self.doc = Some(doc);
    self.sample_time = time;
    self.sample_duration = duration;
    self
  }
}

// ===========================================================================
// CammMotionWatermark — per-type motion-vector lengths (a stamping cursor)
// ===========================================================================

/// A snapshot of [`CammMeta`]'s per-type MOTION sample-vector lengths, taken by
/// the stream walker BEFORE one `process_camm` invocation. Paired with
/// [`CammMeta::stamp_motion_from`] to stamp the `Track<N>` + `Doc<N>` of exactly
/// the camm sample that produced the records appended since. Fields are
/// crate-private; build it only via [`CammMeta::motion_sample_counts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CammMotionWatermark {
  exposure: usize,
  angular_velocity: usize,
  acceleration: usize,
  position: usize,
  magnetic_field: usize,
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
  /// `ProcessCAMM` walk-abort warnings (`Unknown camm record type N` /
  /// `Truncated camm record N`, QuickTimeStream.pl:3495-3496) in source order,
  /// each stamped with the camm `trak`'s `Track<N>` index. Surfaced as
  /// `Track<N>:Warning` ONLY under `-ee` (the camm samples are decoded only
  /// under `ExtractEmbedded`); a no-`ee` parse shows the `[minor]` EEWarn
  /// instead (see [`crate::formats::quicktime::Meta`]'s emitter).
  warnings: Vec<CammWarning>,
  /// TIMING-ONLY markers — one per recognized camm sample (first packet matched
  /// a `Condition`) whose `ProcessCAMM` walk produced NO stored record (no GPS /
  /// motion / exposure fix AND no warning), e.g. a 4-byte-only header sample.
  /// ExifTool's `FoundSomething` emits that sample's `SampleTime`/`SampleDuration`
  /// regardless (QuickTimeStream.pl:1523), so the marker carries the timing into
  /// the `-G1` cross-kind min-doc scan and the `-G3` per-`Doc<N>` emission. See
  /// [`CammTimingOnly`].
  timing_only: Vec<CammTimingOnly>,
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
      warnings: Vec::new(),
      timing_only: Vec::new(),
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

  /// `ProcessCAMM` walk-abort warnings (`Unknown camm record type N` /
  /// `Truncated camm record N`) in source order, each carrying the `Track<N>`
  /// index of the camm `trak` it occurred in.
  #[inline(always)]
  #[must_use]
  pub fn warnings(&self) -> &[CammWarning] {
    self.warnings.as_slice()
  }

  /// TIMING-ONLY markers — recognized camm samples that decoded to NO stored
  /// record (no GPS / motion / warning), each carrying its `Doc<N>` / `Track<N>`
  /// / `SampleTime` / `SampleDuration`. See [`CammTimingOnly`].
  #[inline(always)]
  #[must_use]
  pub fn timing_only(&self) -> &[CammTimingOnly] {
    self.timing_only.as_slice()
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

  /// Append a `ProcessCAMM` walk-abort warning (the `last`-after-`Warn` path,
  /// QuickTimeStream.pl:3495-3496). The walker stamps its `Track<N>` index
  /// after the `process_camm` call (see [`Self::stamp_warning_track_index_from`]).
  #[inline(always)]
  pub fn push_warning(&mut self, warning: CammWarning) -> &mut Self {
    self.warnings.push(warning);
    self
  }

  /// The number of warnings recorded so far — a watermark the stream walker
  /// takes BEFORE one `process_camm` call so it can stamp the `Track<N>` index
  /// onto exactly the warning that call raised (mirrors
  /// [`Self::gps_sample_count`]).
  #[inline(always)]
  #[must_use]
  pub(crate) fn warning_count(&self) -> usize {
    self.warnings.len()
  }

  /// Stamp the 1-based moov `track` index AND the GLOBAL `doc` ordinal onto
  /// every warning at or after `start` — the warning the just-completed
  /// `process_camm` call raised (at most one per call, since `ProcessCAMM`
  /// `last`s after `Warn`). The `doc` is the SAME ordinal the sample opened
  /// (`open_doc`, bumped once per camm sample even when it yields no fix), so
  /// the warning rides that sample's `Doc<N>` (oracle `Doc2:Track1:Warning`
  /// for a camm0 sample after a GPS-fix sample). Mirrors the GPS/motion stamps
  /// so a file-scoped meta accumulating multiple camm `trak`s scopes each
  /// warning to its own track + doc. `time` / `duration` are the camm sample's
  /// sample-table `SampleTime` / `SampleDuration` (seconds), emitted ahead of the
  /// `Warning` under that sample's `Doc<N>` (oracle camm0: `Doc1:Track1:SampleTime`
  /// then `SampleDuration` then `Warning`).
  pub(crate) fn stamp_warning_from(
    &mut self,
    start: usize,
    track: u32,
    doc: u32,
    time: Option<f64>,
    duration: Option<f64>,
  ) {
    if let Some(slice) = self.warnings.get_mut(start..) {
      for w in slice {
        w.set_track_index(Some(track))
          .set_doc(Some(doc))
          .set_sample_timing(time, duration);
      }
    }
  }

  /// Append a TIMING-ONLY marker for a recognized camm sample that decoded to
  /// NO stored record (see [`CammTimingOnly`]). The walker pushes it (and stamps
  /// it via [`Self::stamp_timing_only_last`]) only after confirming `process_camm`
  /// appended no GPS / motion / warning record for the sample.
  #[inline(always)]
  pub(crate) fn push_timing_only(&mut self, marker: CammTimingOnly) -> &mut Self {
    self.timing_only.push(marker);
    self
  }

  /// Stamp the LAST-pushed timing-only marker with its camm sample's `track` /
  /// `doc` / `time` / `duration`. A no-op when none was pushed (the common case —
  /// the sample produced a record), so the walker can call it unconditionally
  /// after [`Self::push_timing_only`].
  pub(crate) fn stamp_timing_only_last(
    &mut self,
    track: u32,
    doc: u32,
    time: Option<f64>,
    duration: Option<f64>,
  ) {
    if let Some(m) = self.timing_only.last_mut() {
      m.set_stamp(track, doc, time, duration);
    }
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

  /// Stamp the GLOBAL document ordinal `doc` onto every GPS sample at or after
  /// `start` — the fixes decoded by ONE `ProcessCAMM` invocation (ONE camm
  /// sample) since the walker took its [`Self::gps_sample_count`] watermark.
  /// Faithful to ExifTool calling `FoundSomething` (`++DOC_COUNT`) ONCE per camm
  /// sample then `HandleTag`ing ALL of that sample's packets under the SAME
  /// `$$et{DOC_NUM}` (`ProcessCAMM` never bumps the doc, QuickTimeStream.pl:3493-
  /// 3504) — so a multi-packet camm sample's fixes share one `Doc<N>`. The `doc`
  /// comes from the SHARED [`crate::metadata::QuickTimeStreamMeta`] counter
  /// (`open_doc`), keeping the ordinal GLOBAL across the file's `mebx`/SP3
  /// sources. Mirrors [`crate::metadata::QuickTimeStreamMeta::stamp_mebx_doc_from`].
  /// `time` / `duration` are the sample-table `SampleTime` / `SampleDuration`
  /// (seconds) of that one camm sample — all its fixes share the one sample-table
  /// entry, so they share the timing (emitted ahead of the GPS payload, like the
  /// `mebx` path).
  pub(crate) fn stamp_gps_doc_from(
    &mut self,
    start: usize,
    doc: u32,
    time: Option<f64>,
    duration: Option<f64>,
  ) {
    if let Some(slice) = self.gps_samples.get_mut(start..) {
      for s in slice {
        s.set_doc(Some(doc)).set_sample_timing(time, duration);
      }
    }
  }

  /// A watermark of the per-type MOTION sample counts (exposure / angular
  /// velocity / acceleration / position / magnetic field) taken BEFORE one
  /// `process_camm` invocation — the typed-MOTION counterpart of
  /// [`Self::gps_sample_count`]. The stream walker pairs it with
  /// [`Self::stamp_motion_from`] so exactly the motion records that ONE camm
  /// sample produced are stamped with that sample's `Track<N>` + `Doc<N>`.
  #[inline(always)]
  #[must_use]
  pub(crate) fn motion_sample_counts(&self) -> CammMotionWatermark {
    CammMotionWatermark {
      exposure: self.exposure.len(),
      angular_velocity: self.angular_velocity.len(),
      acceleration: self.acceleration.len(),
      position: self.position.len(),
      magnetic_field: self.magnetic_field.len(),
    }
  }

  /// Stamp the 1-based moov `track` index AND the GLOBAL `doc` ordinal onto every
  /// MOTION record (camm1-4/7) appended since the `watermark` — the records ONE
  /// `process_camm` invocation (ONE camm sample) produced. Faithful to ExifTool
  /// firing `FoundSomething` (`++DOC_COUNT`) ONCE per camm sample then
  /// `HandleTag`ing EVERY packet of that sample (GPS or motion) under the SAME
  /// `$$et{DOC_NUM}` and `SET_GROUP1 = "Track$num"` (QuickTimeStream.pl:1523/3493-
  /// 3504, QuickTime.pm:10353): all of one sample's records — GPS via
  /// [`Self::stamp_gps_track_index_from`]/[`Self::stamp_gps_doc_from`] and motion
  /// here — share one `Track<N>` + one `Doc<N>`. The `doc` is the same value the
  /// GPS records of this sample got (from the shared `QuickTimeStreamMeta`
  /// counter), so a sample carrying BOTH a GPS and a motion packet keeps them on
  /// one `Doc<N>`. `time` / `duration` are that sample's sample-table `SampleTime`
  /// / `SampleDuration` (seconds), shared by all its packets.
  pub(crate) fn stamp_motion_from(
    &mut self,
    watermark: CammMotionWatermark,
    track: u32,
    doc: u32,
    time: Option<f64>,
    duration: Option<f64>,
  ) {
    let stamp_vec3 = |slice: Option<&mut [CammVector3]>| {
      if let Some(s) = slice {
        for v in s {
          v.set_track_index(Some(track))
            .set_doc(Some(doc))
            .set_sample_timing(time, duration);
        }
      }
    };
    if let Some(slice) = self.exposure.get_mut(watermark.exposure..) {
      for e in slice {
        e.set_track_index(Some(track))
          .set_doc(Some(doc))
          .set_sample_timing(time, duration);
      }
    }
    stamp_vec3(self.angular_velocity.get_mut(watermark.angular_velocity..));
    stamp_vec3(self.acceleration.get_mut(watermark.acceleration..));
    stamp_vec3(self.position.get_mut(watermark.position..));
    stamp_vec3(self.magnetic_field.get_mut(watermark.magnetic_field..));
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
  fn vector3_track_doc_roundtrip_default_none() {
    let mut v = CammVector3::new(1.0, 2.0, 3.0);
    assert_eq!(v.track_index(), None);
    assert_eq!(v.doc(), None);
    v.set_track_index(Some(2)).set_doc(Some(7));
    assert_eq!(v.track_index(), Some(2));
    assert_eq!(v.doc(), Some(7));
  }

  #[test]
  fn exposure_track_doc_roundtrip_default_none() {
    let mut e = CammExposure::from_raw_ns(8_000_000, 1_500_000);
    assert_eq!(e.track_index(), None);
    assert_eq!(e.doc(), None);
    e.set_track_index(Some(1)).set_doc(Some(4));
    assert_eq!(e.track_index(), Some(1));
    assert_eq!(e.doc(), Some(4));
  }

  /// `stamp_motion_from` stamps EXACTLY the motion records appended since the
  /// watermark with ONE camm sample's `Track<N>` + `Doc<N>` (all packet types of
  /// that sample share the same doc), leaving earlier records untouched —
  /// mirroring ExifTool's per-sample `FoundSomething` + per-`trak` `SET_GROUP1`.
  #[test]
  fn stamp_motion_from_watermark_scopes_to_one_sample() {
    let mut m = CammMeta::new();
    // Sample 1 (doc 1, track 1, t=0/dur=1): one acceleration packet.
    let wm1 = m.motion_sample_counts();
    m.push_acceleration(CammVector3::new(1.0, 1.0, 1.0));
    m.stamp_motion_from(wm1, 1, 1, Some(0.0), Some(1.0));
    // Sample 2 (doc 2, track 1, t=1/dur=1): an angular-velocity + a
    // magnetic-field packet.
    let wm2 = m.motion_sample_counts();
    m.push_angular_velocity(CammVector3::new(2.0, 2.0, 2.0));
    m.push_magnetic_field(CammVector3::new(3.0, 3.0, 3.0));
    m.stamp_motion_from(wm2, 1, 2, Some(1.0), Some(1.0));

    assert_eq!(m.acceleration()[0].doc(), Some(1));
    assert_eq!(m.acceleration()[0].track_index(), Some(1));
    // The sample-table timing is threaded onto every motion packet of the sample.
    assert_eq!(m.acceleration()[0].sample_time(), Some(0.0));
    assert_eq!(m.acceleration()[0].sample_duration(), Some(1.0));
    // Sample 2's two packets share doc 2 (one FoundSomething per sample) and its
    // sample-table timing.
    assert_eq!(m.angular_velocity()[0].doc(), Some(2));
    assert_eq!(m.magnetic_field()[0].doc(), Some(2));
    assert_eq!(m.angular_velocity()[0].sample_time(), Some(1.0));
    assert_eq!(m.magnetic_field()[0].sample_time(), Some(1.0));
    // Re-stamping sample 2 must not have touched sample 1's acceleration.
    assert_eq!(m.acceleration()[0].doc(), Some(1));
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
