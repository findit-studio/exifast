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
  /// `true` when the sample carries a coordinate pair.
  fn has_coordinates(&self) -> bool {
    self.latitude().is_some() && self.longitude().is_some()
  }

  /// `true` when ExifTool would open a `Doc<N>` (`++DOC_COUNT`) and `HandleTag`
  /// at least one `%QuickTime::Stream` tag for this record — the per-sample
  /// emission gate. The DEFAULT is [`Self::has_coordinates`]: every
  /// `ProcessSamples`/`ScanMediaData` GPS source (GoPro / camm / moov-`gps `-box
  /// / Kenwood / freeGPS-scan) emits ONLY for a coordinate-bearing fix, so for
  /// them `has_emittable_data == has_coordinates` and the Doc numbering + output
  /// stay byte-identical. Only the SP3 [`crate::metadata::GpsSample`] overrides
  /// this — its `gsen` / `3gf` records are accelerometer/timecode-ONLY (no
  /// lat/lon), yet `Process_gsen`/`Process_3gf` (QuickTimeStream.pl:2769/2686)
  /// bump `DOC_NUM` and `HandleTag` `Accelerometer`/`TimeCode` per record
  /// regardless of coordinates, so those sensor-only samples must still emit.
  fn has_emittable_data(&self) -> bool {
    self.has_coordinates()
  }

  /// `true` when this sample's box-of-origin is processed by ExifTool WITHOUT
  /// `-ee` (the top-level `gps0` / `gsen` / `3gf` magic boxes), so its FIRST
  /// fix surfaces + a file-level `ExtractEmbedded` warning fires even at no-`ee`
  /// (see [`crate::metadata::GpsOrigin`]). The default is `false`: every
  /// `ProcessSamples`/`ScanMediaData` source (GoPro / camm / the moov-`gps `-box
  /// / Kenwood / freeGPS-scan) is fully `-ee` gated. Only the SP3
  /// [`crate::metadata::GpsSample`] — which carries the walker-stamped origin —
  /// overrides this.
  fn emits_without_ee(&self) -> bool {
    false
  }

  /// The 0-based PHYSICAL record index within a top-level magic box
  /// (`gps0`/`gsen`/`3gf`), or `None` for every other source. Only meaningful
  /// when [`Self::emits_without_ee`] is `true`: the emitter uses it to reproduce
  /// ExifTool's `Process_gps0`/`Process_gsen`/`Process_3gf` PHYSICAL-record
  /// semantics — at no-`ee` ONLY physical record 0 surfaces (truncate-to-first),
  /// and at `-ee -G3` the `Doc<N>` number is `index + 1` (a record after a
  /// `next`-skipped one keeps its true physical index, faithful to
  /// `++DOC_COUNT`-before-skip, QuickTimeStream.pl:2743/2747). The default is
  /// `None`: the `-ee`-only sources number their docs by the running
  /// emitted-sample ordinal, unaffected by this.
  fn magic_box_record_index(&self) -> Option<u32> {
    None
  }

  /// The sample-table `(SampleTime, SampleDuration)` in seconds that ExifTool's
  /// `ProcessSamples` emits AHEAD of the decoded payload (QuickTimeStream.pl:1520,
  /// PrintConv `ConvertDuration`), or `None` for a source that has NO sample-table
  /// timing. Only the SAMPLE-TABLE TRACK sources carry it: the default is `None`
  /// (the magic-box / stream-GPS sources — `gps0`/`gsen`/`3gf`/Kenwood/moov-`gps `
  /// /freeGPS — emit NO `SampleTime`/`SampleDuration`, faithful to their goldens),
  /// and only [`CammGpsSample`] overrides it (the `mebx` path emits its timing
  /// outside this trait). When `Some`,
  /// [`crate::formats::quicktime::emit_timed_samples`] emits `SampleTime` then
  /// `SampleDuration` ahead of the GPS columns, under the sample's `Doc<N>`.
  fn sample_timing(&self) -> Option<(Option<f64>, Option<f64>)> {
    None
  }

  /// The 1-based GLOBAL document ordinal (`Doc<N>`) stamped on this sample at
  /// EXTRACTION (the typed mirror of `$$et{DOC_NUM} = ++$$et{DOC_COUNT}`), or
  /// `None` when the source is not folded into the global counter. When `Some`,
  /// [`crate::formats::quicktime::emit_timed_samples`] uses it VERBATIM for the
  /// `-ee -G3` `Doc<N>` number — superseding the running emitted-sample ordinal
  /// AND the `magic_box_record_index + 1` formula (the stamp already accounts for
  /// `++DOC_COUNT`-before-skip). Overridden by [`crate::metadata::GpsSample`] (ALL
  /// SP3 sources: the `gps0`/`gsen`/`3gf` magic boxes stamped in-decoder, plus the
  /// `-ee`-only Kenwood / `moov`-`gps `-box / freeGPS-scan stamped post-decode) and
  /// by [`CammGpsSample`] (one doc per camm sample, off the SAME shared counter,
  /// so a camm `trak` after a `mebx` `trak` continues the ordinal — #214). The
  /// default `None` remains for the GoPro sample types, which do NOT participate
  /// in the `Doc<N>` emitter (the flat `GoProMeta` summarizes only the first fix —
  /// an accepted SP4 limitation, see `quicktime::Meta::collect_emitted`), and for
  /// unit-built samples.
  fn doc(&self) -> Option<u32> {
    None
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
  // `gsen`/`3gf` records carry an `Accelerometer` / `TimeCode` but NO
  // coordinate pair; `Process_gsen`/`Process_3gf` still `++DOC_COUNT` +
  // `HandleTag` them, so a sensor-only `GpsSample` is emittable.
  #[inline(always)]
  fn has_emittable_data(&self) -> bool {
    self.has_coordinates() || self.accelerometer().is_some() || self.time_code().is_some()
  }
  #[inline(always)]
  fn emits_without_ee(&self) -> bool {
    self.origin().is_some_and(|o| o.emits_without_ee())
  }
  #[inline(always)]
  fn magic_box_record_index(&self) -> Option<u32> {
    self.magic_box_record_index()
  }
  #[inline(always)]
  fn doc(&self) -> Option<u32> {
    self.doc()
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
  // The sample-table `SampleTime`/`SampleDuration` (seconds) the walker stamped
  // onto this fix — ExifTool's `ProcessSamples` emits them ahead of the GPS
  // payload (the stream-GPS / magic-box sources keep the trait default `None`, so
  // ONLY camm + mebx surface them).
  #[inline(always)]
  fn sample_timing(&self) -> Option<(Option<f64>, Option<f64>)> {
    Some((self.sample_time(), self.sample_duration()))
  }
  // The GLOBAL `Doc<N>` ordinal stamped at extraction from the SHARED
  // `QuickTimeStreamMeta` doc counter (camm lives in `CammMeta`, a separate
  // struct, yet shares ExifTool's single `$$et{DOC_COUNT}`). When present the
  // emitter uses it VERBATIM for `-ee -G3`, so a camm `trak` following a `mebx`
  // `trak` continues the global ordinal (mebx Doc1, camm Doc2..) instead of
  // restarting at the emitter's per-source Doc1.
  #[inline(always)]
  fn doc(&self) -> Option<u32> {
    self.doc()
  }
}

#[cfg(test)]
mod tests {
  use super::TimedSample;
  use crate::metadata::android_camm::CammGpsSample;
  use crate::metadata::quicktime_stream::GpsSample;

  /// The SP3 `GpsSample` override: a sensor-only record (`gsen` accelerometer /
  /// `3gf` accelerometer+timecode, no lat/lon) is EMITTABLE even though it has no
  /// coordinates — `Process_gsen`/`Process_3gf` `++DOC_COUNT` + `HandleTag` it.
  #[test]
  fn gps_sample_has_emittable_data_covers_sensor_only() {
    // A coordinate fix: emittable (and has coordinates).
    let mut coords = GpsSample::new();
    coords.set_latitude(Some(1.0)).set_longitude(Some(2.0));
    assert!(coords.has_coordinates());
    assert!(TimedSample::has_emittable_data(&coords));

    // `gsen`-style accelerometer-only: NO coordinates, still emittable.
    let mut accel = GpsSample::new();
    accel.set_accelerometer(Some("1 -2 3".into()));
    assert!(!accel.has_coordinates());
    assert!(TimedSample::has_emittable_data(&accel));

    // `3gf`-style timecode-only: NO coordinates, still emittable.
    let mut tc = GpsSample::new();
    tc.set_time_code(Some(1.0));
    assert!(!tc.has_coordinates());
    assert!(TimedSample::has_emittable_data(&tc));

    // A truly empty sample is neither.
    let empty = GpsSample::new();
    assert!(!TimedSample::has_emittable_data(&empty));
  }

  /// The GPS sources keep the DEFAULT `has_emittable_data == has_coordinates`, so
  /// the shared emitter's doc numbering + output stay byte-identical for them.
  #[test]
  fn gps_source_has_emittable_data_equals_has_coordinates() {
    let no_fix = CammGpsSample::new(5);
    assert!(!no_fix.has_coordinates());
    assert!(!TimedSample::has_emittable_data(&no_fix));

    let mut fix = CammGpsSample::new(5);
    fix.set_latitude(Some(37.5)).set_longitude(Some(-122.0));
    assert!(fix.has_coordinates());
    assert!(TimedSample::has_emittable_data(&fix));
  }
}
