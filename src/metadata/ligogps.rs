// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Typed mirror of `Image::ExifTool::LigoGPS` (LigoGPS.pm) — the dashcam
//! vendor GPS records that some bodies (iiway s1, XGODY 12" 4K, ABASK A8 4K,
//! Rexing V1GW-4K, Kingslim D4, BlueSkySea DV688, Redtiger F9 4K, Yada
//! RoadCam Pro 4K BT58189, …) write either as a `freeGPS`/`LIGOGPSINFO`
//! embedded sample stream OR as a `&&&& `-prefixed trailer at file end.
//!
//! ## Provenance
//!
//! Faithful port of:
//!  - `Image::ExifTool::LigoGPS::ProcessLigoGPS` (LigoGPS.pm:289-320) — the
//!    fixed-stride 0x84-byte record walker;
//!  - `Image::ExifTool::LigoGPS::DecryptLigoGPS` (LigoGPS.pm:50-99) —
//!    the per-record byte-cipher with 4 sub-modes driven by the upper 3
//!    bits of each input byte;
//!  - `Image::ExifTool::LigoGPS::ParseLigoGPS` (LigoGPS.pm:229-267) — the
//!    human-readable record parser (`####...DATE TIME N:lat W:lon spd km/h
//!    A:track H:alt M:magvar x:ax y:ay z:az`);
//!  - `Image::ExifTool::LigoGPS::UnfuzzLigoGPS` (LigoGPS.pm:38-44) — the
//!    lat/lon defuzz function;
//!  - `Image::ExifTool::LigoGPS::ProcessLigoJSON` (LigoGPS.pm:334-398) —
//!    the JSON-format variant (Yada RoadCam Pro 4K BT58189).
//!
//! ## What this sub-port surfaces
//!
//! Per LigoGPS.pm:256-265 (binary text records):
//!  - **`GPSDateTime`** — UTC date+time (`YYYY:MM:DD HH:MM:SS`); the bundled
//!    `tr/\//:/` normalises the date separators. Stored as
//!    [`SmolStr`].
//!  - **`GPSLatitude`** — decimal degrees, signed (post bundled
//!    `* (($latNeg or $latRef eq 'S') ? -1 : 1)`).
//!  - **`GPSLongitude`** — decimal degrees, signed (post bundled `* (... eq
//!    'W')` flip).
//!  - **`GPSSpeed`** — km/h (post-`* $spdScl` conversion; the scale factor
//!    is mode-dependent — see [`LigoGpsSample::speed_kph`]).
//!  - **`GPSTrack`** — bearing degrees (`A:` field, LigoGPS.pm:261).
//!  - **`GPSAltitude`** — metres (`H:` field, LigoGPS.pm:262).
//!  - **`MagneticVariation`** — degrees (`M:` field, LigoGPS.pm:263).
//!  - **`Accelerometer`** — space-joined 3-axis string (`x:` `y:` `z:`
//!    fields, LigoGPS.pm:265).
//!
//! For ProcessLigoJSON (LigoGPS.pm:355-396) the same surface PLUS:
//!  - **`DateTimeOriginal`** — the dashcam local-time clock (the bundled
//!    `MYear`/`MMonth`/`MDay`/`MHour`/`MMinute`/`MSecond` fields). Stored
//!    in addition to `GPSDateTime` (which is the UTC GPS time).
//!
//! ## What this sub-port deliberately does NOT decode
//!
//! Faithful-walked but unsurfaced:
//!  - **`OLatitude`/`OLongitude` (ProcessLigoJSON)** — bundled emits them
//!    as `GPSLatitude2`/`GPSLongitude2` (LigoGPS.pm:387-388). These appear
//!    to be the original un-defuzzed lat/lon; the typed surface picks the
//!    main (defuzzed) values only. FOLLOW-UP if dual-readout fidelity is
//!    needed.
//!  - **DecipherLigoGPS cipher discovery (LigoGPS.pm:143-221)** — the
//!    fallback when `DecryptLigoGPS` cannot decode the encrypted prefix.
//!    Cipher discovery requires accumulating ≥10 unique seconds-digit
//!    transitions across multiple records before the cipher table is
//!    known. Real-world dashcam files always satisfy `DecryptLigoGPS` on
//!    the first record, so the deciphered fallback is exotic. FOLLOW-UP
//!    (tracked as a per-port issue).
//!  - **GKU dashcam JSON trailer (LigoGPS.pm:273-281)** — `ProcessGKU` is
//!    a thin wrapper around `ProcessLigoJSON` that skips a 4-byte
//!    leading offset. Not seen in the wild as a QuickTime trailer; the
//!    LIGOGPS JSON path is reached via the embedded `LIGOGPSINFO {`
//!    fingerprint detection. FOLLOW-UP.
//!  - **Sanity-check warnings on out-of-range coordinates (LigoGPS.pm:254)**
//!    — the bundled emits `LIGOGPSINFO coordinates out of range` and
//!    drops the sample; we propagate this through the walker's warning
//!    channel.
//!
//! ## D8 compliance
//!
//! Every field is private; access through accessors. Setters return
//! `&mut Self` for chaining. `const fn` where types permit. No public
//! struct fields; enums newtype/unit-only.

extern crate alloc;
use alloc::{string::String, vec::Vec};

use smol_str::SmolStr;

use crate::metadata::{CaptureSettings, GpsLocation, MediaMetadata, MetaProjectInto};

// ===========================================================================
// LigoGpsSample — one decoded record from `ProcessLigoGPS` / `ProcessLigoJSON`
// ===========================================================================

/// One LigoGPS record decoded from a `####`-prefixed encrypted record
/// (LigoGPS.pm:229-267 `ParseLigoGPS`) or one element of a JSON record
/// stream (LigoGPS.pm:334-398 `ProcessLigoJSON`).
///
/// Bundled-derived field semantics:
///  - `date_time` — `tr|/|:|`-normalised `YYYY:MM:DD HH:MM:SS` (UTC); the
///    JSON variant produces the same shape with a `Z` UTC suffix when
///    decoded from the GPS-time fields (LigoGPS.pm:359). The textual
///    binary variant has no suffix (LigoGPS.pm:244).
///  - `latitude` — signed decimal degrees post `* (($latNeg or $latRef eq
///    'S') ? -1 : 1)` (LigoGPS.pm:258).
///  - `longitude` — signed decimal degrees post `* (($lonNeg or $lonRef eq
///    'W') ? -1 : 1)` (LigoGPS.pm:259).
///  - `speed_kph` — km/h post `* $spdScl` (LigoGPS.pm:260). `$spdScl` is
///    `1` (`flags & 0x02` — non-fuzzed text decoded with kph speed),
///    `1.852` (`flags & 0x01` — non-fuzzed knots → kph), or `1.85407333`
///    (default — the LigoGPS encryption's odd internal unit). For the
///    JSON variant `speed_kph = $info{Speed} * $knotsToKph` (LigoGPS.pm:370).
///  - `track_deg` — bearing degrees (LigoGPS.pm:261).
///  - `altitude_m` — metres (LigoGPS.pm:262).
///  - `magnetic_variation` — degrees (LigoGPS.pm:263).
///  - `accelerometer` — space-joined "ax ay az" (LigoGPS.pm:265 / 373).
///  - `date_time_local` — only set by `ProcessLigoJSON` from the `M*`
///    fields (LigoGPS.pm:379) when all six are present.
#[derive(Debug, Clone, PartialEq)]
pub struct LigoGpsSample {
  /// `GPSDateTime` UTC (LigoGPS.pm:256 / 359-360).
  date_time: Option<SmolStr>,
  /// `DateTimeOriginal` — dashcam local clock (JSON-only, LigoGPS.pm:379).
  date_time_local: Option<SmolStr>,
  /// `GPSLatitude` decimal degrees, signed.
  latitude: Option<f64>,
  /// `GPSLongitude` decimal degrees, signed.
  longitude: Option<f64>,
  /// `GPSSpeed` km/h post-scale.
  speed_kph: Option<f64>,
  /// `GPSTrack` bearing degrees.
  track_deg: Option<f64>,
  /// `GPSAltitude` metres.
  altitude_m: Option<f64>,
  /// `MagneticVariation` degrees.
  magnetic_variation: Option<f64>,
  /// `Accelerometer` space-joined "ax ay az".
  accelerometer: Option<SmolStr>,
}

impl LigoGpsSample {
  /// An empty sample (every field `None`).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      date_time: None,
      date_time_local: None,
      latitude: None,
      longitude: None,
      speed_kph: None,
      track_deg: None,
      altitude_m: None,
      magnetic_variation: None,
      accelerometer: None,
    }
  }

  /// `GPSDateTime` UTC.
  #[inline(always)]
  #[must_use]
  pub fn date_time(&self) -> Option<&str> {
    self.date_time.as_deref()
  }

  /// `DateTimeOriginal` — dashcam local clock (JSON-only).
  #[inline(always)]
  #[must_use]
  pub fn date_time_local(&self) -> Option<&str> {
    self.date_time_local.as_deref()
  }

  /// `GPSLatitude` decimal degrees.
  #[inline(always)]
  #[must_use]
  pub const fn latitude(&self) -> Option<f64> {
    self.latitude
  }

  /// `GPSLongitude` decimal degrees.
  #[inline(always)]
  #[must_use]
  pub const fn longitude(&self) -> Option<f64> {
    self.longitude
  }

  /// `GPSSpeed` km/h.
  #[inline(always)]
  #[must_use]
  pub const fn speed_kph(&self) -> Option<f64> {
    self.speed_kph
  }

  /// `GPSTrack` bearing degrees.
  #[inline(always)]
  #[must_use]
  pub const fn track_deg(&self) -> Option<f64> {
    self.track_deg
  }

  /// `GPSAltitude` metres.
  #[inline(always)]
  #[must_use]
  pub const fn altitude_m(&self) -> Option<f64> {
    self.altitude_m
  }

  /// `MagneticVariation` degrees.
  #[inline(always)]
  #[must_use]
  pub const fn magnetic_variation(&self) -> Option<f64> {
    self.magnetic_variation
  }

  /// `Accelerometer` space-joined "ax ay az".
  #[inline(always)]
  #[must_use]
  pub fn accelerometer(&self) -> Option<&str> {
    self.accelerometer.as_deref()
  }

  /// `true` when no field is populated.
  #[inline(always)]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.date_time.is_none()
      && self.date_time_local.is_none()
      && self.latitude.is_none()
      && self.longitude.is_none()
      && self.speed_kph.is_none()
      && self.track_deg.is_none()
      && self.altitude_m.is_none()
      && self.magnetic_variation.is_none()
      && self.accelerometer.is_none()
  }

  // ── Setters ───────────────────────────────────────────────────────────────

  /// Assign `GPSDateTime`.
  #[inline(always)]
  pub fn set_date_time(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.date_time = v;
    self
  }

  /// Assign `DateTimeOriginal` (JSON-only).
  #[inline(always)]
  pub fn set_date_time_local(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.date_time_local = v;
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

  /// Assign `GPSSpeed` in km/h.
  #[inline(always)]
  pub const fn set_speed_kph(&mut self, v: Option<f64>) -> &mut Self {
    self.speed_kph = v;
    self
  }

  /// Assign `GPSTrack` bearing degrees.
  #[inline(always)]
  pub const fn set_track_deg(&mut self, v: Option<f64>) -> &mut Self {
    self.track_deg = v;
    self
  }

  /// Assign `GPSAltitude` metres.
  #[inline(always)]
  pub const fn set_altitude_m(&mut self, v: Option<f64>) -> &mut Self {
    self.altitude_m = v;
    self
  }

  /// Assign `MagneticVariation` degrees.
  #[inline(always)]
  pub const fn set_magnetic_variation(&mut self, v: Option<f64>) -> &mut Self {
    self.magnetic_variation = v;
    self
  }

  /// Assign `Accelerometer`.
  #[inline(always)]
  pub fn set_accelerometer(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.accelerometer = v;
    self
  }
}

impl Default for LigoGpsSample {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// LigoGpsMeta — the host metadata holder for ProcessLigoGPS output
// ===========================================================================

/// Decoded LigoGPS records — every `####`-prefixed encrypted record that
/// successfully decrypted (LigoGPS.pm:289-320 `ProcessLigoGPS`) plus every
/// JSON record decoded from a `LIGOGPSINFO {` JSON variant (LigoGPS.pm:334-
/// 398 `ProcessLigoJSON`).
///
/// `is_empty()` for a non-LigoGPS file (no encrypted records / no JSON
/// signature at file end).
#[derive(Debug, Clone, PartialEq)]
pub struct LigoGpsMeta {
  /// Decoded GPS samples — one per successfully-parsed record. Order is
  /// file-order (record walker order).
  samples: Vec<LigoGpsSample>,
  /// First warning surfaced by the walker (truncated trailer, decrypt
  /// failure, coordinate out-of-range, …). Bundled emits multiple
  /// `$et->Warn(...)` calls; the camera-indexing surface keeps the first.
  warning: Option<SmolStr>,
}

impl LigoGpsMeta {
  /// An empty LigoGPS holder (no samples, no warning).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      samples: Vec::new(),
      warning: None,
    }
  }

  /// Decoded GPS samples — file-order.
  #[inline(always)]
  #[must_use]
  pub fn samples(&self) -> &[LigoGpsSample] {
    &self.samples
  }

  /// First decoded sample whose `latitude` AND `longitude` are populated.
  /// Used by the [`MetaProjectInto`] adaptor to populate
  /// [`MediaMetadata::gps()`] without scanning all samples at projection
  /// time.
  #[inline(always)]
  #[must_use]
  pub fn first_fix(&self) -> Option<&LigoGpsSample> {
    self
      .samples
      .iter()
      .find(|s| s.latitude.is_some() && s.longitude.is_some())
  }

  /// The first walker warning.
  #[inline(always)]
  #[must_use]
  pub fn warning(&self) -> Option<&str> {
    self.warning.as_deref()
  }

  /// `true` when no samples AND no warning were recorded.
  #[inline(always)]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.samples.is_empty() && self.warning.is_none()
  }

  /// Append a decoded sample. Used by [`crate::formats::ligogps`] only.
  #[inline(always)]
  pub fn push_sample(&mut self, s: LigoGpsSample) -> &mut Self {
    self.samples.push(s);
    self
  }

  /// Set the first warning. Faithful to bundled emitting `$et->Warn`
  /// possibly multiple times — the camera-indexing surface keeps the
  /// first (last-wins would suppress earlier diagnostics).
  #[inline(always)]
  pub fn set_warning(&mut self, w: SmolStr) -> &mut Self {
    if self.warning.is_none() {
      self.warning = Some(w);
    }
    self
  }
}

impl Default for LigoGpsMeta {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// MetaProjectInto — LigoGPS projection into MediaMetadata
// ===========================================================================

impl MetaProjectInto for LigoGpsMeta {
  /// Project LigoGPS records into [`MediaMetadata`].
  ///
  /// **CameraInfo:** LigoGPS records carry no Make/Model/Serial/Firmware
  /// — the format is just GPS telemetry. Bundled (LigoGPS.pm) decodes
  /// only the GPS/accelerometer fields; the camera identity for a dashcam
  /// that writes LigoGPS lives in the QuickTime `udta`/Keys path (SP1+SP2
  /// atoms parsed at the QuickTime SP1 layer). So this projection sets
  /// no `CameraInfo`.
  ///
  /// **CaptureSettings:** not produced — LigoGPS does not carry
  /// exposure/ISO/aperture (those would live in the parent QuickTime
  /// container's makernotes).
  ///
  /// **GpsLocation:** the FIRST sample with a coordinate pair populates
  /// `md.gps()`. LigoGPS is **lowest-tier** in the priority chain —
  /// dashcam vendor GPS shares the same fidelity tier as the
  /// freeGPS-variants and SP3-stream sources (all are "best-effort
  /// brute-force-scan dashcam GPS", not on-device hardware GNSS the way
  /// GoPro/CAMM/Parrot are). The order encoded in
  /// `quicktime::Meta::media_metadata` reflects this: LigoGPS projects
  /// AFTER all the higher-priority sources so an LigoGPS-only file
  /// still gets GPS, but a file with GoPro+LigoGPS prefers GoPro.
  ///
  /// **Warnings:** the walker's `warning()` channel (`Bad LigoGPS
  /// trailer size` / `LIGOGPSINFO coordinates out of range` / …)
  /// propagates into `md.warnings()` with the `"[LigoGPS] "` prefix.
  fn project_into(&self, md: &mut MediaMetadata) {
    // ── GpsLocation ──────────────────────────────────────────────────────
    if md.gps().is_none()
      && let Some(s) = self.first_fix()
    {
      let mut gps = GpsLocation::new();
      gps
        .update_latitude(s.latitude())
        .update_longitude(s.longitude())
        .update_altitude_m(s.altitude_m())
        .update_timestamp(s.date_time().map(String::from));
      md.set_gps(gps);
    }
    // ── Warnings ────────────────────────────────────────────────────────
    if let Some(w) = self.warning() {
      let mut msg = String::with_capacity(10 + w.len());
      msg.push_str("[LigoGPS] ");
      msg.push_str(w);
      md.push_warning(msg);
    }
    // CaptureSettings deliberately unused; LigoGPS doesn't carry capture.
    let _ = CaptureSettings::new();
  }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn ligogps_sample_default_is_empty() {
    let s = LigoGpsSample::default();
    assert!(s.is_empty());
    assert!(s.latitude().is_none());
    assert!(s.longitude().is_none());
    assert!(s.date_time().is_none());
  }

  #[test]
  fn ligogps_sample_setters_round_trip() {
    let mut s = LigoGpsSample::new();
    s.set_latitude(Some(31.285065))
      .set_longitude(Some(-124.759483))
      .set_altitude_m(Some(46.0))
      .set_speed_kph(Some(46.93))
      .set_track_deg(Some(180.0))
      .set_magnetic_variation(Some(12.5))
      .set_date_time(Some(SmolStr::new("2022:09:19 12:45:24")))
      .set_accelerometer(Some(SmolStr::new("-0.000 -0.000 -0.000")));
    assert!(!s.is_empty());
    assert_eq!(s.latitude(), Some(31.285065));
    assert_eq!(s.longitude(), Some(-124.759483));
    assert_eq!(s.altitude_m(), Some(46.0));
    assert_eq!(s.speed_kph(), Some(46.93));
    assert_eq!(s.track_deg(), Some(180.0));
    assert_eq!(s.magnetic_variation(), Some(12.5));
    assert_eq!(s.date_time(), Some("2022:09:19 12:45:24"));
    assert_eq!(s.accelerometer(), Some("-0.000 -0.000 -0.000"));
  }

  #[test]
  fn ligogps_meta_empty_by_default() {
    let m = LigoGpsMeta::default();
    assert!(m.is_empty());
    assert!(m.samples().is_empty());
    assert!(m.first_fix().is_none());
    assert!(m.warning().is_none());
  }

  #[test]
  fn ligogps_meta_first_fix_skips_partial_samples() {
    let mut m = LigoGpsMeta::new();
    // First sample has only latitude — should be skipped by `first_fix`.
    let mut s1 = LigoGpsSample::new();
    s1.set_latitude(Some(10.0));
    m.push_sample(s1);
    // Second sample has BOTH lat/lon — should be the returned fix.
    let mut s2 = LigoGpsSample::new();
    s2.set_latitude(Some(20.0)).set_longitude(Some(30.0));
    m.push_sample(s2);
    let fix = m.first_fix().expect("first_fix");
    assert_eq!(fix.latitude(), Some(20.0));
    assert_eq!(fix.longitude(), Some(30.0));
  }

  #[test]
  fn ligogps_meta_warning_first_wins() {
    let mut m = LigoGpsMeta::new();
    m.set_warning(SmolStr::new("first"));
    m.set_warning(SmolStr::new("second"));
    assert_eq!(m.warning(), Some("first"));
  }

  #[test]
  fn project_into_populates_gps_when_first_fix_present() {
    let mut m = LigoGpsMeta::new();
    let mut s = LigoGpsSample::new();
    s.set_latitude(Some(-45.5))
      .set_longitude(Some(170.5))
      .set_altitude_m(Some(123.0))
      .set_date_time(Some(SmolStr::new("2024:01:15 10:00:00")));
    m.push_sample(s);

    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    let gps = md.gps().expect("gps populated");
    assert_eq!(gps.latitude(), Some(-45.5));
    assert_eq!(gps.longitude(), Some(170.5));
    assert_eq!(gps.altitude_m(), Some(123.0));
    assert_eq!(gps.timestamp(), Some("2024:01:15 10:00:00"));
  }

  #[test]
  fn project_into_skips_when_gps_already_set() {
    let mut m = LigoGpsMeta::new();
    let mut s = LigoGpsSample::new();
    s.set_latitude(Some(10.0)).set_longitude(Some(20.0));
    m.push_sample(s);

    let mut md = MediaMetadata::new();
    // Pre-populate with a higher-priority source.
    let mut prior = GpsLocation::new();
    prior
      .update_latitude(Some(99.0))
      .update_longitude(Some(88.0));
    md.set_gps(prior);
    m.project_into(&mut md);
    let gps = md.gps().expect("gps still populated");
    assert_eq!(gps.latitude(), Some(99.0));
    assert_eq!(gps.longitude(), Some(88.0));
  }

  #[test]
  fn project_into_pushes_prefixed_warning() {
    let mut m = LigoGpsMeta::new();
    m.set_warning(SmolStr::new("Bad LigoGPS trailer size"));
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    let ws = md.warnings();
    assert_eq!(ws.len(), 1);
    assert!(ws[0].starts_with("[LigoGPS] "));
    assert!(ws[0].contains("Bad LigoGPS trailer size"));
  }
}
