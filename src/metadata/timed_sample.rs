// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! The unifying view over the per-format timed-metadata GPS sample structs
//! (`GpsSample`, `GoProGpsSample`, `GoProGlpiSample`, `CammGpsSample`) for the
//! shared `-ee` emitter. Common fields only; per-source speed/extra columns are
//! rendered by the emitter's caller closure (they need the quicktime PrintConv
//! helpers). Values are post-ValueConv (decimal degrees, metres).

use crate::metadata::android_camm::CammGpsSample;
use crate::metadata::gopro::{GoProGlpiSample, GoProGpsSample};
use crate::metadata::quicktime_stream::GpsSample;

/// A pure-data view of the COMMON timed-GPS columns the shared `-ee` emitter
/// (`crate::formats::quicktime::emit_timed_samples`) writes for every sample.
/// Each of the four per-format sample structs implements it in its home module;
/// the divergent per-source speed / extra columns are left to the emitter's
/// `emit_extra` closure (which has the quicktime PrintConv helpers).
///
/// All numeric values are post-`ValueConv` — decimal degrees for lat/lon, metres
/// for altitude, degrees for track, the raw numeric code for measure-mode.
pub(crate) trait TimedSample {
  /// `GPSLatitude` in decimal degrees (positive = north), if the sample carries
  /// one.
  fn latitude(&self) -> Option<f64>;
  /// `GPSLongitude` in decimal degrees (positive = east), if present.
  fn longitude(&self) -> Option<f64>;
  /// `GPSAltitude` in metres, if present.
  fn altitude_m(&self) -> Option<f64> {
    None
  }
  /// `GPSDateTime` displayed string, if present.
  fn date_time(&self) -> Option<&str> {
    None
  }
  /// `GPSTrack` heading in degrees, if present.
  fn track_deg(&self) -> Option<f64> {
    None
  }
  /// `GPSDOP` dilution of precision, if present.
  fn dop(&self) -> Option<f64> {
    None
  }
  /// `GPSMeasureMode` raw numeric code, if present (the emitter applies the
  /// per-source PrintConv).
  fn measure_mode(&self) -> Option<u32> {
    None
  }
  /// `true` when the sample carries a coordinate pair (the `++DOC_COUNT`
  /// gate — ExifTool only opens a `Doc<N>` for a fix with coordinates).
  fn has_coordinates(&self) -> bool {
    self.latitude().is_some() && self.longitude().is_some()
  }
}

// ── GpsSample (QuickTimeStream SP3) ──────────────────────────────────────────
// lat/lon/alt/date_time map directly; `track_deg` is the `GPSTrack` heading
// (`GpsSample::track`). No DOP / measure-mode column.
impl TimedSample for GpsSample {
  #[inline(always)]
  fn latitude(&self) -> Option<f64> {
    self.latitude()
  }
  #[inline(always)]
  fn longitude(&self) -> Option<f64> {
    self.longitude()
  }
  #[inline(always)]
  fn altitude_m(&self) -> Option<f64> {
    self.altitude_m()
  }
  #[inline(always)]
  fn date_time(&self) -> Option<&str> {
    self.date_time()
  }
  #[inline(always)]
  fn track_deg(&self) -> Option<f64> {
    self.track()
  }
}

// ── GoProGpsSample (GPS5 / GPS9) ─────────────────────────────────────────────
// lat/lon/alt/date_time/dop/measure_mode map directly. No `GPSTrack` column
// (GPS5/GPS9 carry no heading); the per-source 2D/3D speeds are emitted by the
// caller closure (they apply the `*3.6` km/h ValueConv).
impl TimedSample for GoProGpsSample {
  #[inline(always)]
  fn latitude(&self) -> Option<f64> {
    self.latitude()
  }
  #[inline(always)]
  fn longitude(&self) -> Option<f64> {
    self.longitude()
  }
  #[inline(always)]
  fn altitude_m(&self) -> Option<f64> {
    self.altitude_m()
  }
  #[inline(always)]
  fn date_time(&self) -> Option<&str> {
    self.date_time()
  }
  #[inline(always)]
  fn dop(&self) -> Option<f64> {
    self.dop()
  }
  #[inline(always)]
  fn measure_mode(&self) -> Option<u32> {
    self.measure_mode()
  }
}

// ── GoProGlpiSample (Karma GLPI `GPSPos`) ────────────────────────────────────
// lat/lon/alt/date_time map directly; `track_deg` is the GLPI heading column
// (`GoProGlpiSample::track_deg`). The per-source X/Y/Z speeds (with the
// `" m/s"` suffix PrintConv) are emitted by the caller closure. No DOP /
// measure-mode column.
impl TimedSample for GoProGlpiSample {
  #[inline(always)]
  fn latitude(&self) -> Option<f64> {
    self.latitude()
  }
  #[inline(always)]
  fn longitude(&self) -> Option<f64> {
    self.longitude()
  }
  #[inline(always)]
  fn altitude_m(&self) -> Option<f64> {
    self.altitude_m()
  }
  #[inline(always)]
  fn date_time(&self) -> Option<&str> {
    self.date_time()
  }
  #[inline(always)]
  fn track_deg(&self) -> Option<f64> {
    self.track_deg()
  }
}

// ── CammGpsSample (Android camm5 / camm6) ────────────────────────────────────
// lat/lon/alt/date_time/measure_mode map directly. No `GPSTrack` / DOP column;
// the camm6 velocity/accuracy columns are emitted by the caller closure.
impl TimedSample for CammGpsSample {
  #[inline(always)]
  fn latitude(&self) -> Option<f64> {
    self.latitude()
  }
  #[inline(always)]
  fn longitude(&self) -> Option<f64> {
    self.longitude()
  }
  #[inline(always)]
  fn altitude_m(&self) -> Option<f64> {
    self.altitude_m()
  }
  #[inline(always)]
  fn date_time(&self) -> Option<&str> {
    self.date_time()
  }
  #[inline(always)]
  fn measure_mode(&self) -> Option<u32> {
    self.measure_mode()
  }
}
