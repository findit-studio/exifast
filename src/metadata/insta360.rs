//! Typed mirror of `Image::ExifTool::QuickTime::INSV_MakerNotes` +
//! `QuickTime::Stream` (the GPS / Exposure / Accelerometer rows it
//! receives from the Insta360 trailer walker). Faithful port of
//! `Image::ExifTool::QuickTimeStream::ProcessInsta360`
//! (QuickTimeStream.pl:3252-3478) plus the per-record-type decoders
//! the same routine drives (QuickTimeStream.pl:3326-3453) and the
//! `INSV_MakerNotes` identity table (QuickTimeStream.pl:696-707).
//!
//! ## Trailer architecture
//!
//! The Insta360 trailer lives at the END of an INSV / INSP / MP4 file
//! and is identified by a 32-byte ASCII hex string
//! `"8db42d694ccc418790edff439fe026bf"` immediately preceding EOF.
//! The 78-byte footer just before EOF (QuickTimeStream.pl:3270-3276) is:
//!
//! ```text
//! [last-record-id:u16-LE][last-record-len:u32-LE][32 opaque bytes]
//! [trailer-length:u32-LE][4 opaque bytes][32-byte ASCII magic UUID]
//! ```
//!
//! The walker steps backwards from the magic (loops from last record to
//! first using the 6-byte `[id:u16-LE][len:u32-LE]` footer chained between
//! records). If a directory-table record (id `0x000`) is encountered, the
//! walker switches to forward-by-index dispatch instead
//! (QuickTimeStream.pl:3437-3469).
//!
//! ## What this sub-port surfaces (camera-indexing-relevant tags)
//!
//! Per QuickTimeStream.pl:3326-3453 plus the `Stream` table at
//! QuickTimeStream.pl:107-169 (`ExposureTime`, `GPSLatitude` etc.):
//!
//!  - **Identity (record `0x101`, INSV_MakerNotes)** — bundled at
//!    QuickTimeStream.pl:696-707:
//!     - `0x0a SerialNumber` (string, often the body serial);
//!     - `0x12 Model` (e.g. `"Insta360 X3"`, `"Insta360 ONE RS"`,
//!       `"Insta360 Ace Pro"`);
//!     - `0x1a Firmware` (string, e.g. `"1.0.07"`);
//!     - `0x2a Parameters` (the lens/raw-resolution string; only the
//!       presence is surfaced — exposed as a SmolStr after the bundled
//!       `$val =~ tr/_/ /` substitution).
//!  - **GPS (record `0x700`)** — 53-byte rows decoded in
//!    QuickTimeStream.pl:3397-3425. Each row is `[unixtime:u32-LE]
//!    [unknown:u32-LE][ms:u16-LE][status:1][lat:double-LE][NS:1]
//!    [lon:double-LE][EW:1][speed:double-LE][track:double-LE]
//!    [alt:double-LE]`. Only `status == 'A'` rows are surfaced.
//!  - **Exposure (record `0x400`)** — 16-byte rows: `[timestamp:u64-LE]
//!    [exposure_time:double-LE]`. `timestamp` is rendered as
//!    `"%.3f"` (milliseconds → seconds).
//!  - **Recording mode** — the GO 2 / ONE RS / X3 firmware doesn't write
//!    a dedicated mode record; the closest bundled has is the
//!    `Parameters` SmolStr in `0x2a`. This sub-port surfaces it under
//!    [`Insta360Identity::parameters`].
//!
//! ## What this sub-port deliberately does NOT decode
//!
//!  - **Accelerometer (record `0x300`)** — telemetry-only,
//!    QuickTimeStream.pl:3372-3385. Each row carries 6 doubles
//!    (`Accelerometer` 3-axis + `AngularVelocity` 3-axis) or 6 int16s
//!    `(val - 0x8000) / 1000`. The walker VISITS the record (so the
//!    walk-shape is faithful) but discards the value rows — same
//!    rationale as GoPro (#58): telemetry adds vector-of-vectors data
//!    that the camera-indexing product doesn't need.
//!  - **Preview images (record `0x200`)** — bundled emits PreviewImage
//!    or PreviewTIFF (QuickTimeStream.pl:3358-3371). Heavy + low
//!    indexing value (the JPEG/TIFF preview duplicates APP2 data already
//!    handled elsewhere). FOLLOW-UP.
//!  - **VideoTimeStamp (record `0x600`)** — `[timestamp:u64-LE]`,
//!    QuickTimeStream.pl:3392-3396. Same telemetry rationale.
//!  - **360° spherical / equirectangular metadata** — not a single
//!    record type but a cross-record concern; the `Parameters` string
//!    in `0x101[0x2a]` contains lens-orientation data the lens-warping
//!    side cares about. FOLLOW-UP.
//!  - **INSP photo trailer (vs INSV video trailer)** — bundled drives
//!    BOTH through the same `ProcessInsta360`, but the `0x200`
//!    record-type fork (JPEG/TIFF preview) is the only INSP-only path.
//!    Since both video + photo INSV/INSP use the SAME 78-byte footer
//!    and the SAME record-type catalogue, the trailer walker decodes
//!    both transparently. FOLLOW-UP only for the preview surfacing.

extern crate alloc;
use alloc::{string::String, vec::Vec};

use smol_str::SmolStr;

use crate::metadata::{CameraInfo, CaptureSettings, GpsLocation, MediaMetadata, MetaProjectInto};

// ===========================================================================
// Insta360Identity — the `0x101` (INSV_MakerNotes) decoded fields
// ===========================================================================

/// Identity decoded from one `0x101` Insta360 record — the camera body's
/// SerialNumber / Model / Firmware / Parameters string carried via the
/// `INSV_MakerNotes` tag table (QuickTimeStream.pl:696-707).
///
/// Every field is optional; a real-world INSV trailer always carries at
/// least Model + Firmware. SerialNumber is missing on some firmware
/// (GO 2 early builds).
#[derive(Debug, Clone, PartialEq)]
pub struct Insta360Identity {
  /// `0x0a SerialNumber` (QuickTimeStream.pl:698).
  serial_number: Option<SmolStr>,
  /// `0x12 Model` (QuickTimeStream.pl:699) — e.g. `"Insta360 X3"`,
  /// `"Insta360 ONE RS"`, `"Insta360 Ace Pro"`.
  model: Option<SmolStr>,
  /// `0x1a Firmware` (QuickTimeStream.pl:700).
  firmware: Option<SmolStr>,
  /// `0x2a Parameters` (QuickTimeStream.pl:701-706) after the bundled
  /// `$val =~ tr/_/ /` substitution. The string encodes the
  /// "number of lenses, 6-axis orientation of each lens, raw resolution"
  /// (bundled note).
  parameters: Option<SmolStr>,
}

impl Insta360Identity {
  /// An empty identity (every field `None`).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      serial_number: None,
      model: None,
      firmware: None,
      parameters: None,
    }
  }

  /// `SerialNumber` (QuickTimeStream.pl:698).
  #[inline(always)]
  #[must_use]
  pub fn serial_number(&self) -> Option<&str> {
    self.serial_number.as_deref()
  }

  /// `Model` (QuickTimeStream.pl:699).
  #[inline(always)]
  #[must_use]
  pub fn model(&self) -> Option<&str> {
    self.model.as_deref()
  }

  /// `Firmware` (QuickTimeStream.pl:700).
  #[inline(always)]
  #[must_use]
  pub fn firmware(&self) -> Option<&str> {
    self.firmware.as_deref()
  }

  /// `Parameters` (QuickTimeStream.pl:701-706).
  #[inline(always)]
  #[must_use]
  pub fn parameters(&self) -> Option<&str> {
    self.parameters.as_deref()
  }

  /// `true` when no field is populated.
  #[inline(always)]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.serial_number.is_none()
      && self.model.is_none()
      && self.firmware.is_none()
      && self.parameters.is_none()
  }

  /// Assign `SerialNumber`.
  #[inline(always)]
  pub fn set_serial_number(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.serial_number = v;
    self
  }

  /// Assign `Model`.
  #[inline(always)]
  pub fn set_model(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.model = v;
    self
  }

  /// Assign `Firmware`.
  #[inline(always)]
  pub fn set_firmware(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.firmware = v;
    self
  }

  /// Assign `Parameters`.
  #[inline(always)]
  pub fn set_parameters(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.parameters = v;
    self
  }
}

impl Default for Insta360Identity {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// Insta360GpsSample — one row from a `0x700` GPS record
// ===========================================================================

/// One GPS fix decoded from an Insta360 `0x700` record. Faithful per
/// QuickTimeStream.pl:3397-3425: each row is 53 bytes,
/// `[unixtime:u32-LE][unknown:u32-LE][ms:u16-LE][status:1][lat:double-LE]
/// [NS:1][lon:double-LE][EW:1][speed:double-LE][track:double-LE]
/// [alt:double-LE]`. Only rows with `status == 'A'` (active fix) are
/// surfaced.
///
/// Bundled-derived field semantics:
///  - `latitude` post-`abs` + sign flipped for `'S'` (QuickTimeStream.pl
///    :3414). Decimal degrees.
///  - `longitude` post-`abs` + sign flipped when ref is NOT `'E'`
///    (QuickTimeStream.pl:3415) — so both `'W'` and `'O'` (French
///    "Ouest") become negative.
///  - `gps_date_time` from `ConvertUnixTime($a[0])` plus the `ms` field
///    as `.NNN` fractional-second suffix, `Z` UTC suffix
///    (QuickTimeStream.pl:3416-3418).
///  - `speed_kph` = bundled `speed_mps * 3.6` (i.e. `* $mpsToKph`,
///    QuickTimeStream.pl:3421 + :74). Stored already-converted.
///  - `track` raw bearing degrees (QuickTimeStream.pl:3422).
///  - `altitude_m` raw metres (QuickTimeStream.pl:3423).
#[derive(Debug, Clone, PartialEq)]
pub struct Insta360GpsSample {
  /// `GPSDateTime` UTC including ms fractional second, `Z`-suffixed.
  date_time: Option<SmolStr>,
  /// `GPSLatitude` in decimal degrees.
  latitude: Option<f64>,
  /// `GPSLongitude` in decimal degrees.
  longitude: Option<f64>,
  /// `GPSSpeed` in km/h (post-`* 3.6` conversion).
  speed_kph: Option<f64>,
  /// `GPSTrack` bearing degrees.
  track_deg: Option<f64>,
  /// `GPSAltitude` in metres.
  altitude_m: Option<f64>,
}

impl Insta360GpsSample {
  /// An empty fix (every field `None`).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      date_time: None,
      latitude: None,
      longitude: None,
      speed_kph: None,
      track_deg: None,
      altitude_m: None,
    }
  }

  /// `GPSDateTime` UTC.
  #[inline(always)]
  #[must_use]
  pub fn date_time(&self) -> Option<&str> {
    self.date_time.as_deref()
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

  /// `GPSSpeed` in km/h.
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

  /// `true` when no field is populated.
  #[inline(always)]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.date_time.is_none()
      && self.latitude.is_none()
      && self.longitude.is_none()
      && self.speed_kph.is_none()
      && self.track_deg.is_none()
      && self.altitude_m.is_none()
  }

  /// Assign `GPSDateTime`.
  #[inline(always)]
  pub fn set_date_time(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.date_time = v;
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
}

impl Default for Insta360GpsSample {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// Insta360ExposureSample — one row from a `0x400` Exposure record
// ===========================================================================

/// One exposure-time sample decoded from an Insta360 `0x400` record
/// (QuickTimeStream.pl:3386-3391). Each row is 16 bytes:
/// `[timestamp_ms:u64-LE][exposure_time_s:double-LE]`.
///
/// Bundled's `TimeCode` field is rendered as `sprintf('%.3f', $val / 1000)`
/// (millis → seconds, 3-decimal text). The typed layer keeps the raw
/// `timestamp_ms` as `u64` and the f64 `exposure_time_s` — the engine
/// formatter renders the bundled-compatible string when needed.
#[derive(Debug, Clone, PartialEq)]
pub struct Insta360ExposureSample {
  /// `TimeCode` raw millisecond counter (the per-stream offset).
  timestamp_ms: Option<u64>,
  /// `ExposureTime` seconds (QuickTimeStream.pl:3390).
  exposure_time_s: Option<f64>,
}

impl Insta360ExposureSample {
  /// An empty exposure sample.
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      timestamp_ms: None,
      exposure_time_s: None,
    }
  }

  /// `TimeCode` raw ms counter.
  #[inline(always)]
  #[must_use]
  pub const fn timestamp_ms(&self) -> Option<u64> {
    self.timestamp_ms
  }

  /// `ExposureTime` seconds.
  #[inline(always)]
  #[must_use]
  pub const fn exposure_time_s(&self) -> Option<f64> {
    self.exposure_time_s
  }

  /// `true` when no field is populated.
  #[inline(always)]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.timestamp_ms.is_none() && self.exposure_time_s.is_none()
  }

  /// Assign `TimeCode` raw ms.
  #[inline(always)]
  pub const fn set_timestamp_ms(&mut self, v: Option<u64>) -> &mut Self {
    self.timestamp_ms = v;
    self
  }

  /// Assign `ExposureTime` seconds.
  #[inline(always)]
  pub const fn set_exposure_time_s(&mut self, v: Option<f64>) -> &mut Self {
    self.exposure_time_s = v;
    self
  }
}

impl Default for Insta360ExposureSample {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// Insta360Meta — the aggregate per-file result
// ===========================================================================

/// The typed result of Insta360 trailer extraction — the per-format
/// mirror of what `ProcessInsta360` (QuickTimeStream.pl:3258-3478) emits
/// over every record-type the walker visits. The walker is per-file,
/// not per-sample (the trailer is a single block at file end); one call
/// yields one `Insta360Meta`.
///
/// Empty (`is_empty()`) when no Insta360 trailer is present in the file
/// or every record-type fork failed to decode.
///
/// **D8 compliance.** Every field is private; access goes through the
/// accessors below.
#[derive(Debug, Clone, PartialEq)]
pub struct Insta360Meta {
  /// `0x101` INSV_MakerNotes identity record. At most one per trailer.
  identity: Option<Insta360Identity>,
  /// `0x700` GPS samples in source order (last record visited first,
  /// since the walker steps backwards). Each `status == 'A'` row appears
  /// here.
  gps_samples: Vec<Insta360GpsSample>,
  /// `0x400` exposure-time samples in source order.
  exposure_samples: Vec<Insta360ExposureSample>,
  /// `ProcessInsta360`-level warnings (QuickTimeStream.pl:3277, 3357,
  /// 3408). Only the FIRST warning is retained, matching bundled
  /// `-j` rendering.
  warning: Option<SmolStr>,
}

impl Insta360Meta {
  /// An empty result (no Insta360 trailer decoded).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      identity: None,
      gps_samples: Vec::new(),
      exposure_samples: Vec::new(),
      warning: None,
    }
  }

  /// `0x101` identity record decode.
  #[inline(always)]
  #[must_use]
  pub const fn identity(&self) -> Option<&Insta360Identity> {
    self.identity.as_ref()
  }

  /// `0x700` GPS samples in source order.
  #[inline(always)]
  #[must_use]
  pub fn gps_samples(&self) -> &[Insta360GpsSample] {
    self.gps_samples.as_slice()
  }

  /// `0x400` exposure-time samples in source order.
  #[inline(always)]
  #[must_use]
  pub fn exposure_samples(&self) -> &[Insta360ExposureSample] {
    self.exposure_samples.as_slice()
  }

  /// The first decoded warning (e.g. `Bad Insta360 trailer size`).
  #[inline(always)]
  #[must_use]
  pub fn warning(&self) -> Option<&str> {
    self.warning.as_deref()
  }

  /// `true` when no record decoded successfully.
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.identity.is_none() && self.gps_samples.is_empty() && self.exposure_samples.is_empty()
  }

  /// The FIRST GPS sample whose `latitude` AND `longitude` are populated —
  /// feeds the [`crate::metadata::GpsLocation`] projection.
  #[inline]
  #[must_use]
  pub fn first_fix(&self) -> Option<&Insta360GpsSample> {
    self
      .gps_samples
      .iter()
      .find(|s| s.latitude.is_some() && s.longitude.is_some())
  }

  /// Set the identity record (subsequent calls are ignored — bundled
  /// emits at most one `0x101` record per trailer).
  #[inline]
  pub fn set_identity(&mut self, v: Insta360Identity) -> &mut Self {
    if self.identity.is_none() {
      self.identity = Some(v);
    }
    self
  }

  /// Append a GPS sample.
  #[inline(always)]
  pub fn push_gps_sample(&mut self, v: Insta360GpsSample) -> &mut Self {
    self.gps_samples.push(v);
    self
  }

  /// Append an exposure-time sample.
  #[inline(always)]
  pub fn push_exposure_sample(&mut self, v: Insta360ExposureSample) -> &mut Self {
    self.exposure_samples.push(v);
    self
  }

  /// Set the first `ProcessInsta360` warning (subsequent calls are ignored).
  #[inline]
  pub fn set_warning(&mut self, msg: SmolStr) -> &mut Self {
    if self.warning.is_none() {
      self.warning = Some(msg);
    }
    self
  }
}

// ===========================================================================
// MetaProjectInto — Insta360 projection into MediaMetadata
// ===========================================================================

impl MetaProjectInto for Insta360Meta {
  /// Project Insta360 INSV/INSP trailer metadata into [`MediaMetadata`].
  ///
  /// **CameraInfo:** Make = `"Insta360"` (every body that writes an
  /// Insta360 trailer is from Arashi Vision Inc.); Model / Serial /
  /// Software come from the `0x101` identity record. Skipped when a
  /// higher-priority source (GoPro / Sony rtmd / Canon CTMD) already
  /// populated Camera identity.
  ///
  /// **CaptureSettings:** the FIRST `0x400` exposure sample with a
  /// non-empty `exposure_time_s()` populates `md.capture()` (Insta360
  /// action-cams have a fixed aperture; only ExposureTime is surfaced).
  ///
  /// **GpsLocation:** Insta360 GPS feeds the **FOURTH tier** of the
  /// priority chain (below GoPro / CAMM / Sony rtmd, above SP3-stream).
  /// Phone-paired GPS via the Insta360 Studio app — same fidelity tier
  /// as Sony rtmd; ordered after Sony because Sony's `GPSStatus 'A'/'V'`
  /// flag is explicit while Insta360 only surfaces `'A'` (active) rows.
  ///
  /// **Warnings:** any ProcessInsta360 `warning()` (`Bad Insta360 trailer
  /// size` etc.) propagates into `md.warnings()` with `"[Insta360] "` prefix.
  fn project_into(&self, md: &mut MediaMetadata) {
    // ── CameraInfo ─────────────────────────────────────────────────────
    if md.camera().is_none()
      && let Some(id) = self.identity()
      && !id.is_empty()
    {
      let mut cam = CameraInfo::new();
      cam.update_make(Some("Insta360".into()));
      cam.update_model(id.model().map(str::to_string));
      cam.update_serial(id.serial_number().map(str::to_string));
      cam.update_software(id.firmware().map(str::to_string));
      if !cam.is_empty() {
        md.set_camera(cam);
      }
    }
    // ── CaptureSettings ────────────────────────────────────────────────
    if md.capture().is_none()
      && let Some(s) = self.exposure_samples().first()
      && let Some(et) = s.exposure_time_s()
    {
      let mut cap = CaptureSettings::new();
      cap.update_exposure_time_s(Some(et));
      if !cap.is_empty() {
        md.set_capture(cap);
      }
    }
    // ── GpsLocation ────────────────────────────────────────────────────
    if md.gps().is_none()
      && let Some(s) = self.first_fix()
    {
      let mut gps = GpsLocation::new();
      gps
        .update_latitude(s.latitude())
        .update_longitude(s.longitude())
        .update_altitude_m(s.altitude_m())
        .update_timestamp(s.date_time().map(str::to_string));
      md.set_gps(gps);
    }
    // ── Warnings ───────────────────────────────────────────────────────
    if let Some(w) = self.warning() {
      let mut msg = String::with_capacity(11 + w.len());
      msg.push_str("[Insta360] ");
      msg.push_str(w);
      md.push_warning(msg);
    }
  }
}

impl Default for Insta360Meta {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn empty_meta_is_empty() {
    let m = Insta360Meta::new();
    assert!(m.is_empty());
    assert!(m.identity().is_none());
    assert!(m.gps_samples().is_empty());
    assert!(m.exposure_samples().is_empty());
    assert!(m.warning().is_none());
    assert!(m.first_fix().is_none());
  }

  #[test]
  fn identity_get_set_roundtrip() {
    let mut id = Insta360Identity::new();
    assert!(id.is_empty());
    id.set_model(Some(SmolStr::new("Insta360 X3")));
    id.set_firmware(Some(SmolStr::new("1.0.07")));
    id.set_serial_number(Some(SmolStr::new("IXX00123")));
    id.set_parameters(Some(SmolStr::new("2 6 4032 3024")));
    assert_eq!(id.model(), Some("Insta360 X3"));
    assert_eq!(id.firmware(), Some("1.0.07"));
    assert_eq!(id.serial_number(), Some("IXX00123"));
    assert_eq!(id.parameters(), Some("2 6 4032 3024"));
    assert!(!id.is_empty());
  }

  #[test]
  fn gps_sample_get_set_roundtrip() {
    let mut g = Insta360GpsSample::new();
    assert!(g.is_empty());
    g.set_latitude(Some(37.7749));
    g.set_longitude(Some(-122.4194));
    g.set_altitude_m(Some(15.5));
    g.set_speed_kph(Some(36.0));
    g.set_track_deg(Some(180.0));
    g.set_date_time(Some(SmolStr::new("2024:06:01 14:00:00Z")));
    assert_eq!(g.latitude(), Some(37.7749));
    assert_eq!(g.longitude(), Some(-122.4194));
    assert_eq!(g.altitude_m(), Some(15.5));
    assert_eq!(g.speed_kph(), Some(36.0));
    assert_eq!(g.track_deg(), Some(180.0));
    assert_eq!(g.date_time(), Some("2024:06:01 14:00:00Z"));
    assert!(!g.is_empty());
  }

  #[test]
  fn exposure_sample_get_set_roundtrip() {
    let mut e = Insta360ExposureSample::new();
    assert!(e.is_empty());
    e.set_timestamp_ms(Some(1000));
    e.set_exposure_time_s(Some(0.008));
    assert_eq!(e.timestamp_ms(), Some(1000));
    assert_eq!(e.exposure_time_s(), Some(0.008));
    assert!(!e.is_empty());
  }

  #[test]
  fn set_identity_only_first_wins() {
    let mut m = Insta360Meta::new();
    let mut a = Insta360Identity::new();
    a.set_model(Some(SmolStr::new("A")));
    m.set_identity(a);
    let mut b = Insta360Identity::new();
    b.set_model(Some(SmolStr::new("B")));
    m.set_identity(b);
    assert_eq!(m.identity().unwrap().model(), Some("A"));
  }

  #[test]
  fn set_warning_only_first_wins() {
    let mut m = Insta360Meta::new();
    m.set_warning(SmolStr::new("first"));
    m.set_warning(SmolStr::new("second"));
    assert_eq!(m.warning(), Some("first"));
  }

  #[test]
  fn first_fix_picks_first_with_lat_and_lon() {
    let mut m = Insta360Meta::new();
    // Sample 0: only altitude set (no lat/lon)
    let mut s0 = Insta360GpsSample::new();
    s0.set_altitude_m(Some(10.0));
    m.push_gps_sample(s0);
    // Sample 1: full fix
    let mut s1 = Insta360GpsSample::new();
    s1.set_latitude(Some(45.0));
    s1.set_longitude(Some(8.0));
    m.push_gps_sample(s1);
    // Sample 2: also full
    let mut s2 = Insta360GpsSample::new();
    s2.set_latitude(Some(46.0));
    s2.set_longitude(Some(9.0));
    m.push_gps_sample(s2);
    let f = m.first_fix().expect("fix");
    assert_eq!(f.latitude(), Some(45.0));
    assert_eq!(f.longitude(), Some(8.0));
  }
}
