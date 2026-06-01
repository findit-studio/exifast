//! Typed mirror of `Image::ExifTool::QuickTime::Stream` — the timed-metadata
//! (GPS / sensor) telemetry QuickTimeStream.pl extracts from QuickTime video
//! samples.
//!
//! QuickTimeStream.pl walks a video file's metadata-track sample tables
//! (`stsd`/`stco`/`stsc`/`stsz`/`stts`, parsed by `ParseTag`,
//! QuickTimeStream.pl:2489-2581), then for each timed sample dispatches by
//! `MetaFormat` / `HandlerType` to a per-camera decoder (`ProcessSamples`,
//! QuickTimeStream.pl:1304-1592). The decoded GPS / accelerometer / time tags
//! all land in the single `%Image::ExifTool::QuickTime::Stream` table
//! (QuickTimeStream.pl:108-169).
//!
//! ExifTool emits one `Doc<N>` (sub-document) per timed sample
//! (`$$et{DOC_NUM} = ++$$et{DOC_COUNT}`, `FoundSomething`,
//! QuickTimeStream.pl:967-973). exifast mirrors that with a `Vec` of
//! [`GpsSample`] — one entry per `FoundSomething` call — plus the `mebx`
//! Apple-timed-metadata key/value pairs in [`MebxSample`].
//!
//! **SP3 scope.** This sub-port ports the *self-contained* timed-metadata
//! decoders: the sample-table machinery, `Process_mebx`, and the bounded
//! binary GPS records (`gps `/`GPS `, `gps0`, `3gf`, `gsen`). The brute-force
//! `ProcessFreeGPS` (40+ camera variants, QuickTimeStream.pl:1637-2488) and
//! the decoders that re-dispatch into *other* ExifTool modules (GoPro GPMF,
//! Sony `rtmd`, Canon `CTMD`, the full `camm` tables) are deferred — see
//! `docs/tracking.md`.

extern crate alloc;
use alloc::{string::String, vec::Vec};

use smol_str::SmolStr;

/// One timed GPS / sensor fix decoded from a video metadata sample — the
/// typed mirror of the per-`Doc<N>` tag group ExifTool's `FoundSomething`
/// opens for each sample (QuickTimeStream.pl:967-973). Every field is
/// optional: a given camera format fills only the fields it carries.
#[derive(Debug, Clone, PartialEq)]
pub struct GpsSample {
  /// `SampleTime` — sample decoding time in seconds (QuickTimeStream.pl:161,
  /// from the `stts` time-to-sample table).
  sample_time: Option<f64>,
  /// `SampleDuration` — sample duration in seconds (QuickTimeStream.pl:162).
  sample_duration: Option<f64>,
  /// `GPSLatitude` in decimal degrees, positive = north
  /// (QuickTimeStream.pl:116).
  latitude: Option<f64>,
  /// `GPSLongitude` in decimal degrees, positive = east
  /// (QuickTimeStream.pl:117).
  longitude: Option<f64>,
  /// `GPSAltitude` in metres (QuickTimeStream.pl:120).
  altitude_m: Option<f64>,
  /// `GPSSpeed` (QuickTimeStream.pl:121) — km/h unless [`Self::speed_ref`]
  /// says otherwise (the PrintConv `Notes` on QuickTimeStream.pl:121
  /// declares the default unit).
  speed_kph: Option<f64>,
  /// `GPSSpeedRef` — `K`(km/h) / `M`(mph) / `N`(knots), QuickTimeStream.pl:122.
  speed_ref: Option<char>,
  /// `GPSTrack` — heading, relative to true north unless
  /// [`Self::track_ref`] says otherwise (QuickTimeStream.pl:123).
  track: Option<f64>,
  /// `GPSTrackRef` — `M`(magnetic) / `T`(true), QuickTimeStream.pl:124.
  track_ref: Option<char>,
  /// `GPSDateTime` — the displayed `YYYY:MM:DD HH:MM:SS[.sss]Z` string
  /// (QuickTimeStream.pl:125-130). Stored as [`SmolStr`] — every faithful
  /// decoder emits a ≤30-char timestamp.
  date_time: Option<SmolStr>,
  /// `Accelerometer` — the space-joined 3-axis string (QuickTimeStream.pl:149).
  /// Stored as [`SmolStr`] — bundled emits ≤24 chars (three signed floats
  /// joined by spaces).
  accelerometer: Option<SmolStr>,
  /// `TimeCode` — video timecode in seconds (QuickTimeStream.pl:159).
  time_code: Option<f64>,
}

impl GpsSample {
  /// An empty sample (every field `None`).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      sample_time: None,
      sample_duration: None,
      latitude: None,
      longitude: None,
      altitude_m: None,
      speed_kph: None,
      speed_ref: None,
      track: None,
      track_ref: None,
      date_time: None,
      accelerometer: None,
      time_code: None,
    }
  }

  /// `SampleTime` in seconds.
  #[inline(always)]
  #[must_use]
  pub const fn sample_time(&self) -> Option<f64> {
    self.sample_time
  }

  /// `SampleDuration` in seconds.
  #[inline(always)]
  #[must_use]
  pub const fn sample_duration(&self) -> Option<f64> {
    self.sample_duration
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

  /// `GPSAltitude` in metres (per QuickTimeStream.pl:120, the bundled
  /// PrintConv emits `"$val m"`).
  #[inline(always)]
  #[must_use]
  pub const fn altitude_m(&self) -> Option<f64> {
    self.altitude_m
  }

  /// `GPSSpeed` in km/h — the bundled default unit per QuickTimeStream.pl:121
  /// (`Notes => 'in km/h unless GPSSpeedRef says otherwise'`). When
  /// [`Self::speed_ref`] is set, callers must convert from the indicated
  /// unit (`M`=mph, `N`=knots) before using this value as km/h.
  #[inline(always)]
  #[must_use]
  pub const fn speed_kph(&self) -> Option<f64> {
    self.speed_kph
  }

  /// `GPSSpeedRef` (`K` / `M` / `N`).
  #[inline(always)]
  #[must_use]
  pub const fn speed_ref(&self) -> Option<char> {
    self.speed_ref
  }

  /// `GPSTrack` heading.
  #[inline(always)]
  #[must_use]
  pub const fn track(&self) -> Option<f64> {
    self.track
  }

  /// `GPSTrackRef` (`M` / `T`).
  #[inline(always)]
  #[must_use]
  pub const fn track_ref(&self) -> Option<char> {
    self.track_ref
  }

  /// `GPSDateTime` displayed string.
  #[inline(always)]
  #[must_use]
  pub fn date_time(&self) -> Option<&str> {
    self.date_time.as_deref()
  }

  /// `Accelerometer` 3-axis string.
  #[inline(always)]
  #[must_use]
  pub fn accelerometer(&self) -> Option<&str> {
    self.accelerometer.as_deref()
  }

  /// `TimeCode` in seconds.
  #[inline(always)]
  #[must_use]
  pub const fn time_code(&self) -> Option<f64> {
    self.time_code
  }

  /// `true` when no field is populated (a sample worth dropping).
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.sample_time.is_none()
      && self.sample_duration.is_none()
      && self.latitude.is_none()
      && self.longitude.is_none()
      && self.altitude_m.is_none()
      && self.speed_kph.is_none()
      && self.speed_ref.is_none()
      && self.track.is_none()
      && self.track_ref.is_none()
      && self.date_time.is_none()
      && self.accelerometer.is_none()
      && self.time_code.is_none()
  }

  /// `true` when the sample carries a GPS coordinate pair.
  #[inline(always)]
  #[must_use]
  pub const fn has_coordinates(&self) -> bool {
    self.latitude.is_some() && self.longitude.is_some()
  }

  /// Assign `SampleTime`.
  #[inline(always)]
  pub const fn set_sample_time(&mut self, v: Option<f64>) -> &mut Self {
    self.sample_time = v;
    self
  }

  /// Assign `SampleDuration`.
  #[inline(always)]
  pub const fn set_sample_duration(&mut self, v: Option<f64>) -> &mut Self {
    self.sample_duration = v;
    self
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

  /// Assign `GPSSpeed` (km/h by default, per QuickTimeStream.pl:121).
  #[inline(always)]
  pub const fn set_speed_kph(&mut self, v: Option<f64>) -> &mut Self {
    self.speed_kph = v;
    self
  }

  /// Assign `GPSSpeedRef`.
  #[inline(always)]
  pub const fn set_speed_ref(&mut self, v: Option<char>) -> &mut Self {
    self.speed_ref = v;
    self
  }

  /// Assign `GPSTrack`.
  #[inline(always)]
  pub const fn set_track(&mut self, v: Option<f64>) -> &mut Self {
    self.track = v;
    self
  }

  /// Assign `GPSTrackRef`.
  #[inline(always)]
  pub const fn set_track_ref(&mut self, v: Option<char>) -> &mut Self {
    self.track_ref = v;
    self
  }

  /// Assign `GPSDateTime`.
  #[inline(always)]
  pub fn set_date_time(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.date_time = v;
    self
  }

  /// Assign `Accelerometer`.
  #[inline(always)]
  pub fn set_accelerometer(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.accelerometer = v;
    self
  }

  /// Assign `TimeCode`.
  #[inline(always)]
  pub const fn set_time_code(&mut self, v: Option<f64>) -> &mut Self {
    self.time_code = v;
    self
  }
}

impl Default for GpsSample {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

/// One Apple `mebx` timed-metadata key/value pair (QuickTimeStream.pl
/// `Process_mebx`:2644-2680). `mebx` samples carry generic
/// `[size][local-id][value]` records; the local-id is resolved through the
/// `keys` table saved by `SaveMetaKeys` (QuickTimeStream.pl:876-962) to a
/// tag NAME and a value. exifast keeps the name + the displayed value verbatim
/// (no per-key PrintConv beyond the `qtFmt`-typed `ReadValue`).
#[derive(Debug, Clone, PartialEq)]
pub struct MebxSample {
  /// The resolved tag name — the `keys`-table `TagID` with the
  /// `com.apple.quicktime.` namespace stripped and `-`/`.` segments
  /// camel-cased (QuickTimeStream.pl:915, 2665).
  name: String,
  /// The decoded value, stringified via the `qtFmt`-typed `ReadValue`
  /// (QuickTimeStream.pl:2668).
  value: String,
  /// `SampleTime` in seconds for the timed sample this pair came from
  /// (QuickTimeStream.pl `FoundSomething`:967-973).
  sample_time: Option<f64>,
  /// `SampleDuration` in seconds for the timed sample
  /// (QuickTimeStream.pl:162, 972).
  sample_duration: Option<f64>,
}

impl MebxSample {
  /// Build a `mebx` key/value pair.
  #[inline(always)]
  #[must_use]
  pub fn new(
    name: impl Into<String>,
    value: impl Into<String>,
    sample_time: Option<f64>,
    sample_duration: Option<f64>,
  ) -> Self {
    Self {
      name: name.into(),
      value: value.into(),
      sample_time,
      sample_duration,
    }
  }

  /// The resolved tag name.
  #[inline(always)]
  #[must_use]
  pub fn name(&self) -> &str {
    &self.name
  }

  /// The decoded, stringified value.
  #[inline(always)]
  #[must_use]
  pub fn value(&self) -> &str {
    &self.value
  }

  /// `SampleTime` in seconds.
  #[inline(always)]
  #[must_use]
  pub const fn sample_time(&self) -> Option<f64> {
    self.sample_time
  }

  /// `SampleDuration` in seconds.
  #[inline(always)]
  #[must_use]
  pub const fn sample_duration(&self) -> Option<f64> {
    self.sample_duration
  }
}

/// The typed result of QuickTimeStream timed-metadata extraction — the SP3
/// mirror of every `%QuickTime::Stream` tag `ProcessSamples` /
/// `Process_mebx` would emit for a video's metadata tracks.
///
/// Empty (`is_empty()`) for the common case of a video with no timed
/// metadata (or whose timed metadata uses a deferred decoder). ExifTool only
/// surfaces these tags under the `ExtractEmbedded` option; exifast always
/// decodes them when the self-contained atoms are present (the camera-metadata
/// product goal — see `docs/tracking.md`).
#[derive(Debug, Clone, PartialEq)]
pub struct QuickTimeStreamMeta {
  /// One [`GpsSample`] per timed sample that produced any `%QuickTime::Stream`
  /// tag (QuickTimeStream.pl `FoundSomething`), in sample order.
  gps_samples: Vec<GpsSample>,
  /// Apple `mebx` key/value pairs, in decode order (QuickTimeStream.pl
  /// `Process_mebx`).
  mebx_samples: Vec<MebxSample>,
}

impl QuickTimeStreamMeta {
  /// An empty result (no timed metadata decoded).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      gps_samples: Vec::new(),
      mebx_samples: Vec::new(),
    }
  }

  /// The decoded GPS / sensor samples, in sample order.
  #[inline(always)]
  #[must_use]
  pub fn gps_samples(&self) -> &[GpsSample] {
    self.gps_samples.as_slice()
  }

  /// The decoded Apple `mebx` key/value pairs, in decode order.
  #[inline(always)]
  #[must_use]
  pub fn mebx_samples(&self) -> &[MebxSample] {
    self.mebx_samples.as_slice()
  }

  /// `true` when no timed metadata was decoded.
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.gps_samples.is_empty() && self.mebx_samples.is_empty()
  }

  /// Append a decoded GPS / sensor sample.
  #[inline(always)]
  pub fn push_gps_sample(&mut self, sample: GpsSample) -> &mut Self {
    self.gps_samples.push(sample);
    self
  }

  /// Append a decoded `mebx` key/value pair.
  #[inline(always)]
  pub fn push_mebx_sample(&mut self, sample: MebxSample) -> &mut Self {
    self.mebx_samples.push(sample);
    self
  }

  /// The FIRST sample carrying a GPS coordinate pair — used by the
  /// [`crate::metadata::MediaMetadata`] projection to fill
  /// [`crate::metadata::GpsLocation`].
  #[inline(always)]
  #[must_use]
  pub fn first_fix(&self) -> Option<&GpsSample> {
    self.gps_samples.iter().find(|s| s.has_coordinates())
  }
}

impl Default for QuickTimeStreamMeta {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn gps_sample_emptiness_and_coordinates() {
    let mut s = GpsSample::new();
    assert!(s.is_empty());
    assert!(!s.has_coordinates());
    s.set_latitude(Some(40.0));
    assert!(!s.is_empty());
    assert!(!s.has_coordinates()); // longitude still missing
    s.set_longitude(Some(-105.0));
    assert!(s.has_coordinates());
  }

  #[test]
  fn stream_meta_first_fix_skips_non_coordinate_samples() {
    let mut m = QuickTimeStreamMeta::new();
    assert!(m.is_empty());
    let mut accel_only = GpsSample::new();
    accel_only.set_accelerometer(Some(SmolStr::new("1 2 3")));
    m.push_gps_sample(accel_only);
    let mut fix = GpsSample::new();
    fix.set_latitude(Some(1.0)).set_longitude(Some(2.0));
    m.push_gps_sample(fix);
    assert!(!m.is_empty());
    // first_fix skips the accelerometer-only sample.
    assert_eq!(m.first_fix().expect("fix").latitude(), Some(1.0));
  }

  #[test]
  fn mebx_sample_roundtrip() {
    let s = MebxSample::new("GPSCoordinates", "123456", Some(0.5), Some(1.0));
    assert_eq!(s.name(), "GPSCoordinates");
    assert_eq!(s.value(), "123456");
    assert_eq!(s.sample_time(), Some(0.5));
    assert_eq!(s.sample_duration(), Some(1.0));
  }
}
