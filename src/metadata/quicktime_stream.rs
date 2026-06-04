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

use crate::value::Tag;

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
/// `keys` table saved by `SaveMetaKeys` (QuickTimeStream.pl:876-962) to a raw
/// `TagID`, which `Process_mebx` then maps to a tag NAME via the
/// `%QuickTime::Keys` table (the `mebx` SubDirectory's TagTable,
/// QuickTimeStream.pl:177): a known TagID keeps that entry's `Name` (and
/// value-tier `ValueConv`); any other reasonable TagID is camel-cased
/// (`s/[-.](.)/\U$1/g` + `ucfirst`, QuickTimeStream.pl:2663-2664). exifast
/// keeps the name + the post-`ValueConv` value (the display-tier `PrintConv` of
/// a `%QuickTime::Keys` tag is not applied — the same convention the GPS
/// samples follow).
#[derive(Debug, Clone, PartialEq)]
pub struct MebxSample {
  /// The resolved tag name — the `%QuickTime::Keys` `Name` for a known TagID,
  /// else the camel-cased TagID (QuickTimeStream.pl:2657-2666).
  name: String,
  /// The decoded value: the `qtFmt`-typed `ReadValue` output
  /// (QuickTimeStream.pl:2668) after the key's value-tier `ValueConv`. The
  /// empty string for an empty/short value (ExifTool.pm:6299).
  value: String,
  /// `SampleTime` in seconds for the timed sample this pair came from
  /// (QuickTimeStream.pl `FoundSomething`:967-973).
  sample_time: Option<f64>,
  /// `SampleDuration` in seconds for the timed sample
  /// (QuickTimeStream.pl:162, 972).
  sample_duration: Option<f64>,
  /// 1-based moov track number of the `trak` this sample was decoded from —
  /// ExifTool's `SET_GROUP1 = "Track$num"` (`++$track` over EVERY `trak`
  /// SubDirectory, QuickTime.pm:10353-10354), the family-1 group under which a
  /// `mebx` sample is emitted (oracle: `Track1:GPSCoordinates`). `None` until
  /// the stream walker stamps it. Stored per-sample (not per-meta) because the
  /// enclosing [`QuickTimeStreamMeta`] is file-scoped and could accumulate
  /// samples from more than one metadata `trak`.
  track_index: Option<u32>,
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
      track_index: None,
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

  /// 1-based moov track number of the originating `trak` — the family-1
  /// `Track<N>` group ExifTool emits this `mebx` sample under (oracle:
  /// `Track1:GPSCoordinates`). `None` until the stream walker stamps it.
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
  /// Tags produced by a `mebx` key whose `%QuickTime::Keys` entry is a
  /// `SubDirectory` dispatched to another module — currently only
  /// `smartstyle-info` (QuickTime.pm:6847-6852), whose value is a binary PLIST
  /// processed through `Image::ExifTool::PLIST::Main` /
  /// `PLIST::ProcessBinaryPLIST`. The nested PLIST tags carry the PLIST table's
  /// family-0 group (`PLIST`) and the PLIST tag name (camel-cased key); ExifTool
  /// re-scopes their family-1 group to the enclosing `mebx` Track (verified via
  /// `-G1:0` ⇒ `Track1:PLIST`). exifast stores them as fully-rendered [`Tag`]s
  /// (the nested-module dispatch already converted each value through the PLIST
  /// `Taggable` stream; the smartstyle keys never hit a mode-sensitive
  /// `%PLIST::Main` static `PrintConv`, so the rendering is mode-invariant —
  /// see `quicktime_stream::process_mebx`).
  plist_subdir_tags: Vec<Tag>,
}

impl QuickTimeStreamMeta {
  /// An empty result (no timed metadata decoded).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      gps_samples: Vec::new(),
      mebx_samples: Vec::new(),
      plist_subdir_tags: Vec::new(),
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

  /// The fully-rendered tags from a `mebx` `SubDirectory` key (currently only
  /// `smartstyle-info`'s embedded binary PLIST — QuickTime.pm:6847-6852), in
  /// decode order. Each [`Tag`] keeps the nested module's family-0 group
  /// (`PLIST`) and tag name; see [`QuickTimeStreamMeta`]'s field docs.
  #[inline(always)]
  #[must_use]
  pub fn plist_subdir_tags(&self) -> &[Tag] {
    self.plist_subdir_tags.as_slice()
  }

  /// `true` when no timed metadata was decoded.
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.gps_samples.is_empty() && self.mebx_samples.is_empty() && self.plist_subdir_tags.is_empty()
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

  /// The number of `mebx` samples decoded so far — a watermark the stream
  /// walker takes BEFORE decoding one `trak`'s samples so it can stamp the
  /// `Track<N>` index onto exactly the samples that `trak` produced (see
  /// [`Self::stamp_mebx_track_index_from`]).
  #[inline(always)]
  #[must_use]
  pub(crate) fn mebx_sample_count(&self) -> usize {
    self.mebx_samples.len()
  }

  /// Stamp the 1-based moov `track_index` onto every `mebx` sample at or after
  /// `start` — the samples decoded from a single `trak` since the walker took
  /// its [`Self::mebx_sample_count`] watermark. Faithful to ExifTool scoping
  /// `SET_GROUP1 = "Track$num"` per-`trak` (QuickTime.pm:10353-10354): each
  /// sample carries the group of the `trak` it actually came from, even when
  /// this file-scoped meta accumulates more than one metadata `trak`.
  pub(crate) fn stamp_mebx_track_index_from(&mut self, start: usize, track: u32) {
    if let Some(slice) = self.mebx_samples.get_mut(start..) {
      for s in slice {
        s.set_track_index(Some(track));
      }
    }
  }

  /// Append a fully-rendered tag from a `mebx` `SubDirectory` key (the
  /// `smartstyle-info` embedded-PLIST path).
  #[inline(always)]
  pub fn push_plist_subdir_tag(&mut self, tag: Tag) -> &mut Self {
    self.plist_subdir_tags.push(tag);
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
