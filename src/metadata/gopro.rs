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

use crate::metadata::{CameraInfo, GpsLocation, MediaMetadata, MetaProjectInto};

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
  /// `ValueConv` multiplies by 3.6 to km/h (GoPro.pm:504-508); exifast keeps
  /// m/s as the typed-layer storage (the projection to km/h happens at the
  /// `MediaMetadata::GpsLocation` layer where the engine renders speed).
  speed_2d_mps: Option<f64>,
  /// `GPSSpeed3D` 3-D speed in m/s (GoPro.pm:509-513).
  speed_3d_mps: Option<f64>,
  /// `GPSDateTime` — `GPS9` only, derived from the per-sample
  /// `GPS-days + GPS-seconds` columns 5+6 (GoPro.pm:543-554). Format:
  /// `YYYY:MM:DD HH:MM:SS[.fff]Z`. Stored as [`SmolStr`] (≤30-char string).
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
  /// `MediaUniqueID` (`MUID`, GoPro.pm:456-462). Hex-rendered 32-char ID.
  /// Stored as [`SmolStr`] (heap-allocates above the 23-byte inline budget
  /// but stays cheap to clone since `MUID` is short and constant per file).
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

  /// `MediaUniqueID` (MUID).
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
}

impl Default for GoProMeta {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// MetaProjectInto — GoPro projection into MediaMetadata
// ===========================================================================

impl MetaProjectInto for GoProMeta {
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
  /// GoPro file. The FIRST sample carrying a coordinate pair populates
  /// `GpsLocation` (`first_fix()`); timestamp falls back to the
  /// block-level `GPSDateTime` (`GPSU`) when the per-sample `GPS9` value
  /// is absent.
  fn project_into(&self, md: &mut MediaMetadata) {
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
    if md.gps().is_none()
      && let Some(f) = self.first_fix()
    {
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
    }
  }
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
    assert!(md.warnings().is_empty());
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
