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

/// The WALKER PATH (box of origin) that reached a [`GpsSample`] — NOT the decode
/// type. ExifTool processes the top-level magic boxes (`gps0` / `gsen` / `3gf`)
/// during `ProcessMOV` REGARDLESS of `-ee` (they are `%QuickTime::Main`
/// SubDirectories, not `ScanMediaData`/`ProcessSamples` sources), so when one of
/// them holds more than one record ExifTool emits the FIRST fix + raises a
/// DOCUMENT-level `[minor] ExtractEmbedded` warning even WITHOUT `-ee`. The other
/// three sources — the `moov`-level Novatek `gps ` offset box, the Kenwood `GPS `
/// box, and the brute-force `mdat` freeGPS scan — run only inside
/// `ProcessSamples`/`ScanMediaData`, so they stay fully `-ee` gated (no no-`ee`
/// fix, no warning). The marker lets [`crate::formats::quicktime`]'s emitter gate
/// per-sample (`extract_embedded || origin.emits_without_ee()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GpsOrigin {
  /// Top-level DuDuBell / VSYS `gps0` box (`Process_gps0`) — processed without
  /// `-ee`.
  Gps0,
  /// Top-level DuDuBell / VSYS `gsen` accelerometer box (`Process_gsen`) —
  /// processed without `-ee`.
  Gsen,
  /// Top-level Pittasoft BlackVue `3gf ` accelerometer box (`Process_3gf`) —
  /// processed without `-ee`.
  ThreeGf,
  /// The `moov`-level Novatek `gps ` offset box → freeGPS dispatch — `-ee` only.
  MoovGpsBox,
  /// The top-level Kenwood `GPS ` inline box (`parse_kenwood_gps`) — `-ee` only.
  Kenwood,
  /// The brute-force `mdat` `freeGPS ` scan (`ScanMediaData`) — `-ee` only.
  FreeGpsScan,
  /// A `gpmd` MetaFormat sample track whose `Condition` matched a self-contained
  /// dashcam variant — Kingslim / Rove / FMAS / Wolfbox (QuickTimeStream.pl:181-
  /// 212). UNLIKE the other freeGPS origins (the `moov`-`gps `-box and the
  /// brute-force `mdat` scan, both movie-level), these are dispatched by
  /// `ProcessSamples` per timed sample, so ExifTool scopes them to the enclosing
  /// `trak`'s `SET_GROUP1 = "Track$num"` (QuickTime.pm:10353-10354) and emits the
  /// sample-table `SampleTime`/`SampleDuration` (QuickTimeStream.pl:161-162) ahead
  /// of the fix — exactly the GoPro `gpmd` / `mebx` / `camm` shape. `track` is
  /// that 1-based moov track number. `-ee` only.
  ///
  /// `set_group1_active` is the `$$et{SET_GROUP1}` state captured at THIS sample's
  /// `FoundSomething` time: `true` ⇒ the key is still `"Track$num"` ⇒ the fix +
  /// its `SampleTime`/`SampleDuration` ride the `Track<N>` group; `false` ⇒ a
  /// PRECEDING Kingslim `ProcessLigoGPS` in this same `trak` already
  /// `delete`d the key (LigoGPS.pm:266) WITHOUT restoring `Track$num` ⇒ the fix
  /// rides the DEFAULT `QuickTime` group. Mirrors the
  /// [`GpmdTimingOnly::set_group1_active`] flag on the matched-but-empty markers,
  /// extended to the DECODED fixes so a `[Kingslim-LIGO, valid-FMAS]` walk stamps
  /// the FMAS fix's GPS + timing `QuickTime` (ground-truth `-ee -G3:1`:
  /// `Doc3:QuickTime:GPSLatitude` / `Doc3:QuickTime:SampleTime`), not `Track<N>`.
  Gpmd { track: u32, set_group1_active: bool },
}

impl GpsOrigin {
  /// `true` for the top-level magic boxes ExifTool processes WITHOUT `-ee`
  /// (`gps0` / `gsen` / `3gf`): a fix from one of these surfaces its FIRST record
  /// + a file-level `ExtractEmbedded` warning even at no-`ee`. The remaining
  /// origins are `ScanMediaData`/`ProcessSamples`-only ⇒ fully `-ee` gated.
  #[inline(always)]
  #[must_use]
  pub(crate) const fn emits_without_ee(&self) -> bool {
    matches!(self, Self::Gps0 | Self::Gsen | Self::ThreeGf)
  }
}

/// The non-GPS-fix tags a `Process_text` dashcam variant (Mini 0806 / Roadhawk
/// / Thinkware / DJI telemetry — QuickTimeStream.pl:1213-1294) `HandleTag`s
/// alongside the GPS columns, plus the timed-text `Text` tag the wrapper stores
/// (QuickTimeStream.pl:1512). These ride the same per-sample `Doc<N>` as the
/// fix; carried in a boxed sub-struct so the common [`GpsSample`] stays lean
/// (only the text path ever allocates one).
///
/// Each value is post-ValueConv: `distance_m` is already `× $mpsToKph` (km/h —
/// ExifTool's `Distance` is mis-named, the value is the m/s reading scaled by
/// 3.6, QuickTimeStream.pl:1222); `fnumber` / `exposure_time_s` /
/// `exposure_compensation` are the raw numeric inputs the Exif PrintConvs
/// format; `iso` / `vertical_speed` keep ExifTool's RAW captured token (the
/// table entries are bare / `"$val m/s"`).
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct TextExtras {
  /// `Text` (QuickTimeStream.pl:1512) — the raw sample buffer the timed-text
  /// wrapper stores verbatim.
  text: Option<SmolStr>,
  /// `GSensor` (QuickTimeStream.pl:1285) — the raw `gsensori,...` capture.
  gsensor: Option<SmolStr>,
  /// `Car` (QuickTimeStream.pl:1286) — the raw `CAR,...` capture.
  car: Option<SmolStr>,
  /// `Distance` (QuickTimeStream.pl:1222) — the m/s reading `× $mpsToKph`,
  /// rendered `"$val m"`.
  distance: Option<f64>,
  /// `VerticalSpeed` (QuickTimeStream.pl:1223) — ExifTool's RAW captured string
  /// (no arithmetic), rendered `"$val m/s"`.
  vertical_speed: Option<SmolStr>,
  /// `FNumber` (QuickTimeStream.pl:1224) — `PrintFNumber($val)` at `-j`.
  fnumber: Option<f64>,
  /// `ExposureTime` (QuickTimeStream.pl:1225) — `1 / SS`, `PrintExposureTime`.
  exposure_time_s: Option<f64>,
  /// `ExposureCompensation` (QuickTimeStream.pl:1226) — `EV / (denom||1)`,
  /// `PrintFraction`.
  exposure_compensation: Option<f64>,
  /// `ISO` (QuickTimeStream.pl:1227) — the RAW captured token (bare table
  /// entry).
  iso: Option<SmolStr>,
}

impl TextExtras {
  /// `true` when no extra is populated (so the emitter can drop the boxed
  /// sub-struct entirely rather than attach an all-`None` one).
  #[inline(always)]
  #[must_use]
  pub(crate) fn is_empty(&self) -> bool {
    self.text.is_none()
      && self.gsensor.is_none()
      && self.car.is_none()
      && self.distance.is_none()
      && self.vertical_speed.is_none()
      && self.fnumber.is_none()
      && self.exposure_time_s.is_none()
      && self.exposure_compensation.is_none()
      && self.iso.is_none()
  }

  /// `Text` — the raw sample buffer.
  #[inline(always)]
  #[must_use]
  pub(crate) fn text(&self) -> Option<&str> {
    self.text.as_deref()
  }
  /// `GSensor` — the raw `gsensori,...` capture.
  #[inline(always)]
  #[must_use]
  pub(crate) fn gsensor(&self) -> Option<&str> {
    self.gsensor.as_deref()
  }
  /// `Car` — the raw `CAR,...` capture.
  #[inline(always)]
  #[must_use]
  pub(crate) fn car(&self) -> Option<&str> {
    self.car.as_deref()
  }
  /// `Distance` (km/h-scaled metres, rendered `"$val m"`).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn distance(&self) -> Option<f64> {
    self.distance
  }
  /// `VerticalSpeed` — the raw captured string (rendered `"$val m/s"`).
  #[inline(always)]
  #[must_use]
  pub(crate) fn vertical_speed(&self) -> Option<&str> {
    self.vertical_speed.as_deref()
  }
  /// `FNumber` raw numeric input.
  #[inline(always)]
  #[must_use]
  pub(crate) const fn fnumber(&self) -> Option<f64> {
    self.fnumber
  }
  /// `ExposureTime` seconds (`1 / SS`).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn exposure_time_s(&self) -> Option<f64> {
    self.exposure_time_s
  }
  /// `ExposureCompensation` raw numeric input.
  #[inline(always)]
  #[must_use]
  pub(crate) const fn exposure_compensation(&self) -> Option<f64> {
    self.exposure_compensation
  }
  /// `ISO` — the raw captured token.
  #[inline(always)]
  #[must_use]
  pub(crate) fn iso(&self) -> Option<&str> {
    self.iso.as_deref()
  }

  /// Assign `Text`.
  #[inline(always)]
  pub(crate) fn set_text(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.text = v;
    self
  }
  /// Assign `GSensor`.
  #[inline(always)]
  pub(crate) fn set_gsensor(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.gsensor = v;
    self
  }
  /// Assign `Car`.
  #[inline(always)]
  pub(crate) fn set_car(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.car = v;
    self
  }
  /// Assign `Distance` (km/h-scaled metres).
  #[inline(always)]
  pub(crate) const fn set_distance(&mut self, v: Option<f64>) -> &mut Self {
    self.distance = v;
    self
  }
  /// Assign `VerticalSpeed` (raw captured string).
  #[inline(always)]
  pub(crate) fn set_vertical_speed(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.vertical_speed = v;
    self
  }
  /// Assign `FNumber`.
  #[inline(always)]
  pub(crate) const fn set_fnumber(&mut self, v: Option<f64>) -> &mut Self {
    self.fnumber = v;
    self
  }
  /// Assign `ExposureTime` (seconds).
  #[inline(always)]
  pub(crate) const fn set_exposure_time_s(&mut self, v: Option<f64>) -> &mut Self {
    self.exposure_time_s = v;
    self
  }
  /// Assign `ExposureCompensation`.
  #[inline(always)]
  pub(crate) const fn set_exposure_compensation(&mut self, v: Option<f64>) -> &mut Self {
    self.exposure_compensation = v;
    self
  }
  /// Assign `ISO` (raw captured token).
  #[inline(always)]
  pub(crate) fn set_iso(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.iso = v;
    self
  }
}

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
  /// The WALKER PATH (box of origin) that produced this sample — stamped by the
  /// stream walker at the dispatch point, not by the per-format decoder. Drives
  /// the no-`ee` emission gate ([`GpsOrigin::emits_without_ee`]): a `gps0` /
  /// `gsen` / `3gf` fix surfaces (first-only) + raises a file-level
  /// `ExtractEmbedded` warning even without `-ee`; the `moov`-`gps `-box /
  /// Kenwood / freeGPS-scan origins stay `-ee` gated. `None` for samples built
  /// directly in unit tests (treated as `-ee`-only — no no-`ee` leak).
  origin: Option<GpsOrigin>,
  /// The 0-based PHYSICAL record index within a top-level magic box
  /// (`gps0`/`gsen`/`3gf`), stamped by the decoder for EVERY physical record
  /// BEFORE the validity skip — the typed mirror of ExifTool's
  /// `$$et{DOC_NUM} = ++$$et{DOC_COUNT}` at the top of the `Process_gps0`/
  /// `Process_gsen`/`Process_3gf` loop (QuickTimeStream.pl:2743/2783/2700), which
  /// counts a record EVEN IF it is then `next`-skipped (an out-of-range gps0
  /// fix). The emitter ([`crate::formats::quicktime::emit_timed_samples`]) reads
  /// it for the no-`ee` magic-box path: at no-`ee` only physical record 0
  /// surfaces (truncate-to-first), and at `-ee -G3` the `Doc<N>` number is
  /// `index + 1` (so a valid record after a skipped one is `Doc<index+1>`, not the
  /// next sequential emitted-sample ordinal). `None` for the `-ee`-only sources
  /// (their Doc numbering is the running emitted-sample ordinal) and for
  /// unit-built samples.
  magic_box_record_index: Option<u32>,
  /// 1-based global document ordinal (`$$et{DOC_NUM} = ++$$et{DOC_COUNT}`) of
  /// this sample's record — the `Doc<N>` the `-ee -G3` emitter writes. Stamped at
  /// extraction from the shared [`QuickTimeStreamMeta`] doc counter for ALL of
  /// this struct's sources: the top-level magic boxes (`gps0`/`gsen`/`3gf`) stamp
  /// it IN-DECODER per PHYSICAL record at the TOP of the loop
  /// (QuickTimeStream.pl:2743/2783/2700), so a SKIPPED out-of-range record still
  /// consumes a global ordinal — the next valid record's stamp accounts for it;
  /// the `-ee`-only Kenwood `GPS ` box / `moov`-`gps `-box freeGPS blocks /
  /// brute-force freeGPS-scan stamp it POST-decode per appended fix
  /// ([`QuickTimeStreamMeta::stamp_gps_doc_from`]). Because it comes from the
  /// meta-wide counter it is a true GLOBAL ordinal across the other timed sources
  /// in the same file (including camm, in a separate struct off the same
  /// counter). When `Some` the emitter uses it VERBATIM for `-ee -G3` (no
  /// `magic_box_record_index + 1` arithmetic); `None` only for unit-built samples
  /// (the emitter then keeps its running per-call ordinal). `magic_box_record_index`
  /// is retained SEPARATELY: it is the PHYSICAL index (0-based) that selects
  /// record 0 for the no-`ee` truncate-to-first decision — distinct from this
  /// global `Doc<N>` number.
  doc: Option<u32>,
  /// The `Process_text` dashcam extras (`Text`/`GSensor`/`Car`/`Distance`/
  /// `VerticalSpeed`/`FNumber`/`ExposureTime`/`ExposureCompensation`/`ISO`) the
  /// Mini 0806 / Roadhawk / Thinkware / DJI-telemetry branches emit alongside
  /// the GPS columns (QuickTimeStream.pl:1213-1294). `None` for every other
  /// source — boxed so a non-text sample carries only a null pointer.
  text_extras: Option<alloc::boxed::Box<TextExtras>>,
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
      origin: None,
      magic_box_record_index: None,
      doc: None,
      text_extras: None,
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

  /// The WALKER PATH (box of origin) that produced this sample, or `None` until
  /// the stream walker stamps it (see [`GpsOrigin`]).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn origin(&self) -> Option<GpsOrigin> {
    self.origin
  }

  /// The 0-based PHYSICAL record index this magic-box (`gps0`/`gsen`/`3gf`)
  /// sample came from, or `None` for non-magic-box / unit-built samples (see
  /// the `magic_box_record_index` field docs).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn magic_box_record_index(&self) -> Option<u32> {
    self.magic_box_record_index
  }

  /// The 1-based global document ordinal (`Doc<N>`) stamped on this sample, or
  /// `None` for the `-ee`-only sources / unit-built samples (see the `doc` field
  /// docs). When `Some`, the emitter uses it verbatim for `-ee -G3`.
  #[inline(always)]
  #[must_use]
  pub(crate) const fn doc(&self) -> Option<u32> {
    self.doc
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
      && self.text_extras.is_none()
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

  /// Stamp the WALKER PATH (box of origin) — set by the stream walker at the
  /// dispatch point that reached this sample (see [`GpsOrigin`]).
  #[inline(always)]
  pub(crate) const fn set_origin(&mut self, v: Option<GpsOrigin>) -> &mut Self {
    self.origin = v;
    self
  }

  /// Stamp the 0-based PHYSICAL record index — set by the magic-box decoder
  /// (`process_gps0`/`process_gsen`/`process_3gf`) for EVERY physical record
  /// BEFORE the validity skip (see the `magic_box_record_index` field docs).
  #[inline(always)]
  pub(crate) const fn set_magic_box_record_index(&mut self, v: Option<u32>) -> &mut Self {
    self.magic_box_record_index = v;
    self
  }

  /// Stamp the 1-based global document ordinal — set by the magic-box decoder
  /// from the shared [`QuickTimeStreamMeta`] doc counter, per PHYSICAL record
  /// (see the `doc` field docs).
  #[inline(always)]
  pub(crate) const fn set_doc(&mut self, v: Option<u32>) -> &mut Self {
    self.doc = v;
    self
  }

  /// The `Process_text` dashcam extras, or `None` for every non-text source.
  #[inline(always)]
  #[must_use]
  pub(crate) fn text_extras(&self) -> Option<&TextExtras> {
    self.text_extras.as_deref()
  }

  /// Attach the `Process_text` extras (boxing the populated sub-struct), or
  /// clear them when `None`.
  #[inline(always)]
  pub(crate) fn set_text_extras(&mut self, v: Option<TextExtras>) -> &mut Self {
    self.text_extras = v.map(alloc::boxed::Box::new);
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
  /// 1-based global document ordinal (`$$et{DOC_NUM} = ++$$et{DOC_COUNT}`) of
  /// the TIMED SAMPLE this record came from — the `Doc<N>` number the `-ee -G3`
  /// emitter writes. ExifTool sets `DOC_NUM` ONCE per timed sample via
  /// `FoundSomething` (ProcessSamples:1517) before dispatching `Process_mebx`,
  /// which `HandleTag`s ALL records of that sample under the SAME `DOC_NUM`
  /// (`Process_mebx` never bumps the doc itself, QuickTimeStream.pl:2644). So
  /// every record decoded by one `process_mebx` invocation — including the
  /// nested `detected-face` leaves — shares ONE ordinal. Stamped by the stream
  /// walker (see [`QuickTimeStreamMeta::stamp_mebx_doc_from`]) from the shared
  /// [`QuickTimeStreamMeta`] doc counter, so it is a true GLOBAL ordinal across
  /// the other timed sources in the same file (e.g. a `gps0` box after a `mebx`
  /// track). `None` until stamped.
  doc: Option<u32>,
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
      doc: None,
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

  /// The 1-based global document ordinal (`Doc<N>`) of the timed sample this
  /// record came from — all records of one timed sample share it (see the
  /// `doc` field docs). `None` until the stream walker stamps it.
  #[inline(always)]
  #[must_use]
  pub const fn doc(&self) -> Option<u32> {
    self.doc
  }

  /// Stamp the 1-based global document ordinal of the originating timed sample.
  #[inline(always)]
  pub const fn set_doc(&mut self, v: Option<u32>) -> &mut Self {
    self.doc = v;
    self
  }
}

/// A per-sample TIMING-ONLY marker for a `gpmd` MetaFormat sample whose
/// self-contained dashcam variant MATCHED its `Condition` (FMAS / Wolfbox / Rove
/// `Process_text`) but whose process-proc decoded NO fix (a too-short or
/// otherwise malformed sample).
///
/// **Why this exists.** The `gpmd` Condition cascade (QuickTimeStream.pl:181-212)
/// keys each self-contained variant on a SHORT leading-byte signature — FMAS on
/// `^FMAS\0\0\0\0` (8 bytes), Wolfbox on `^.{136}(0{16}[A-Z]{4}|…redtiger\0)` —
/// while the SubDirectory process-proc (`ProcessFMAS` / `ProcessWolfbox`) does a
/// STRICTER full-record validation. So a sample that matches the signature but
/// fails the stricter decode emits nothing. ExifTool nonetheless fires
/// `FoundSomething` (`$$et{DOC_NUM} = ++$$et{DOC_COUNT}` + `HandleTag
/// SampleTime`/`SampleDuration`, QuickTimeStream.pl:967-972) the moment
/// `GetTagInfo` matches the Condition (`ProcessSamples`:1567-1571), BEFORE — and
/// INDEPENDENTLY of — what the process-proc decodes. So a matched-but-empty
/// sample STILL opens a `Doc<N>` and emits its `Doc<N>:Track<N>:SampleTime`/
/// `SampleDuration` (ground-truth `-ee -G3:1`: a truncated `FMAS\0\0\0\0`
/// followed by a valid FMAS sample yields `Doc1:Track1:SampleTime` for the empty
/// one and the GPS at `Doc2`, and `-G1` keeps the FIRST sample's `0 s` timing).
/// Without a stored marker that timing has no record to ride on, so the valid
/// sample would be misnumbered `Doc1` and `-G1` would keep its timing instead of
/// the first sample's. This marker carries exactly the empty sample's `Doc<N>` /
/// `Track<N>` / `SampleTime` / `SampleDuration` so both the `-G1` min-doc scan
/// and the `-G3` per-`Doc<N>` emission see it (the `gpmd` analogue of
/// [`crate::metadata::CammTimingOnly`]).
///
/// **D8 compliance.** Fields are private; access via the accessors below.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GpmdTimingOnly {
  /// The 1-based moov `Track<N>` index of the `gpmd` `trak` the sample belongs
  /// to (`None` until the walker stamps it; defaults to `Track1` at emit time).
  track_index: Option<u32>,
  /// The GLOBAL `Doc<N>` ordinal (`$$et{DOC_NUM} = ++$$et{DOC_COUNT}`) this
  /// matched-but-empty `gpmd` sample consumed — the same shared-counter `Doc<N>`
  /// the sample's `open_doc` got. `None` until the walker stamps it.
  doc: Option<u32>,
  /// `SampleTime` (seconds) of this `gpmd` sample — the sample-table decode time
  /// `FoundSomething` emits. `None` until the walker stamps it.
  sample_time: Option<f64>,
  /// `SampleDuration` (seconds) of this `gpmd` sample (paired with
  /// [`Self::sample_time`]). `None` until the walker stamps it.
  sample_duration: Option<f64>,
  /// Whether ExifTool's `$$et{SET_GROUP1} = "Track$num"` was still active when
  /// `FoundSomething` emitted this sample's timing — i.e. the timing rides the
  /// `trak`'s `Track<N>` family-1 group (`true`) or the DEFAULT `QuickTime` group
  /// (`false`). `ProcessLigoGPS` does `SET_GROUP1 = 'LIGO'` then `delete
  /// $$et{SET_GROUP1}` (LigoGPS.pm:255/266) — the `delete` DROPS the key rather
  /// than restoring the `trak`'s `Track$num`, so a Kingslim `gpmd` sample whose
  /// timing is emitted AFTER a PRECEDING Kingslim `ProcessLigoGPS` in the SAME
  /// `ProcessSamples` walk lands under `QuickTime`, not `Track<N>` (ground-truth
  /// `-ee -G3:1`: `[kingslim, fmas-empty, kingslim]` ⇒ `Doc1:Track1` timing,
  /// `Doc2:LIGO`, `Doc3:QuickTime` timing, `Doc4:QuickTime` timing, `Doc5:LIGO`).
  /// Defaults to `true` (the FMAS / Wolfbox / Rove / `text` markers never follow
  /// a LigoGPS `delete`, so they always keep `Track<N>`).
  set_group1_active: bool,
}

impl GpmdTimingOnly {
  /// An unstamped marker (the walker stamps track/doc/timing after confirming a
  /// self-contained `gpmd` variant matched but produced no fix).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn new() -> Self {
    Self {
      track_index: None,
      doc: None,
      sample_time: None,
      sample_duration: None,
      set_group1_active: true,
    }
  }

  /// The 1-based moov `Track<N>` index of this sample's `gpmd` `trak`.
  #[inline(always)]
  #[must_use]
  pub const fn track_index(&self) -> Option<u32> {
    self.track_index
  }

  /// The GLOBAL `Doc<N>` ordinal this matched-but-empty `gpmd` sample consumed.
  #[inline(always)]
  #[must_use]
  pub const fn doc(&self) -> Option<u32> {
    self.doc
  }

  /// `SampleTime` (seconds) of this `gpmd` sample, or `None` until the walker
  /// stamps it.
  #[inline(always)]
  #[must_use]
  pub const fn sample_time(&self) -> Option<f64> {
    self.sample_time
  }

  /// `SampleDuration` (seconds) of this `gpmd` sample, or `None` until the walker
  /// stamps it.
  #[inline(always)]
  #[must_use]
  pub const fn sample_duration(&self) -> Option<f64> {
    self.sample_duration
  }

  /// Whether this marker's timing rides the `trak`'s `Track<N>` family-1 group
  /// (`true`) or the DEFAULT `QuickTime` group (`false`) — the `$$et{SET_GROUP1}`
  /// state at `FoundSomething` time (see the `set_group1_active` field docs).
  #[inline(always)]
  #[must_use]
  pub const fn set_group1_active(&self) -> bool {
    self.set_group1_active
  }

  /// Stamp the `Track<N>` index, GLOBAL `Doc<N>` ordinal, sample-table
  /// `SampleTime` / `SampleDuration`, and the `$$et{SET_GROUP1}`-active flag
  /// (`true` ⇒ `Track<N>` group, `false` ⇒ `QuickTime` group) (walker-only).
  #[inline(always)]
  pub(crate) const fn set_stamp(
    &mut self,
    track: u32,
    doc: u32,
    time: Option<f64>,
    duration: Option<f64>,
    set_group1_active: bool,
  ) -> &mut Self {
    self.track_index = Some(track);
    self.doc = Some(doc);
    self.sample_time = time;
    self.sample_duration = duration;
    self.set_group1_active = set_group1_active;
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
  /// `true` when a top-level magic box (`gps0` / `gsen` / `3gf`) carried MORE
  /// than one record (`$dirLen > $recLen`) — the exact condition under which
  /// ExifTool TRUNCATES that box to its first record and raises the
  /// document-level `[minor] The ExtractEmbedded option may find more tags in
  /// the media data` warning WITHOUT `-ee` (`EEWarn`, QuickTimeStream.pl:2693/
  /// 2738/2776, QuickTime.pm:9545-9549). Set by the decoders ([`process_gps0`]
  /// etc.) at the byte-length check, BEFORE any per-record decode, so it is
  /// faithful to the raw record count (independent of how many records survive
  /// the out-of-range skip). The emitter consults it (only at no-`ee`) to raise
  /// the file-level `ExifTool:Warning`. The `-ee`-only sources (moov-`gps `-box /
  /// Kenwood / freeGPS-scan) never set it — they raise different warnings the
  /// oracle shows ABSENT at no-`ee`.
  magic_box_truncated_no_ee: bool,
  /// The running global document counter — the typed mirror of ExifTool's
  /// `$$et{DOC_COUNT}`. Bumped in EXTRACTION (walk) order at each point ExifTool
  /// runs `$$et{DOC_NUM} = ++$$et{DOC_COUNT}`: ONCE per `mebx` timed sample
  /// ([`decode_one_sample`] via [`Self::open_doc`] +
  /// [`Self::stamp_mebx_doc_from`]); once per PHYSICAL `gps0`/`gsen`/`3gf` record
  /// ([`process_gps0`]/[`process_gsen`]/[`process_3gf`], INCLUDING a skipped
  /// out-of-range record); and once per fix appended by the `-ee`-only
  /// `ProcessSamples`/`ScanMediaData` sources — the Kenwood `GPS ` box, the
  /// `moov`-level `gps `-box freeGPS blocks, and the brute-force `mdat`
  /// freeGPS-scan ([`Self::stamp_gps_doc_from`] at each source's walk position).
  /// It is ALSO shared with the camm decoder, which bumps it once per camm sample
  /// off the SAME counter (`decode_one_sample` camm arm → [`Self::open_doc`] →
  /// [`crate::metadata::CammMeta::stamp_gps_doc_from`]) even though camm fixes
  /// live in a SEPARATE struct. Because the SAME counter spans every embedded
  /// source in the file, the stamped `Doc<N>` ordinals are GLOBAL across them
  /// (e.g. a `camm` `trak` following a `mebx` `trak` continues the ordinal —
  /// `mebx` Doc1, camm Doc2.. — not a colliding `Doc1`; #214). For a SINGLE-source
  /// file the ordinal equals the old per-source numbering, so the byte-exact
  /// goldens are unchanged.
  doc_counter: u32,
  /// TIMING-ONLY markers — one per timed sample that consumed a `Doc<N>` but
  /// produced no stored row, so its `SampleTime`/`SampleDuration` would otherwise
  /// have no record to ride on. Two producers, both `FoundSomething`-driven:
  ///   * a `gpmd` sample whose self-contained dashcam variant (FMAS / Wolfbox /
  ///     Rove `Process_text`) MATCHED its `Condition` but whose process-proc
  ///     decoded NO fix (a too-short / malformed sample, QuickTimeStream.pl:
  ///     1567-1571);
  ///   * a `text` sample whose `Process_text` emitted NOTHING — a binary
  ///     `\0[^\0]` sample whose `Text` is gated and which matches no sentence
  ///     (e.g. the Insta360 `.insv`'s 469 binary `Track3` text samples). ExifTool
  ///     runs `FoundSomething` for EVERY `text` sample BEFORE `Process_text`
  ///     (QuickTimeStream.pl:1473), so the timing is emitted regardless.
  /// In both cases `FoundSomething` opens the `Doc<N>` + emits that sample's
  /// `SampleTime`/`SampleDuration`, so the marker carries the timing into the
  /// `-G1` cross-sample min-doc scan
  /// ([`crate::formats::quicktime::gpmd_gps_min_doc_timing`]) and the `-G3`
  /// per-`Doc<N>` emission, and consumes the doc ordinal so a following VALID
  /// sample is renumbered to the next `Doc<N>`. See [`GpmdTimingOnly`].
  gpmd_timing_only: Vec<GpmdTimingOnly>,
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
      magic_box_truncated_no_ee: false,
      doc_counter: 0,
      gpmd_timing_only: Vec::new(),
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

  /// Bump the global document counter and return the new 1-based ordinal — the
  /// typed mirror of `$$et{DOC_NUM} = ++$$et{DOC_COUNT}` (see the `doc_counter`
  /// field docs). Called ONCE per `mebx` timed sample (before
  /// [`Self::stamp_mebx_doc_from`]) and once per PHYSICAL `gps0`/`gsen`/`3gf`
  /// record. Saturating, so a hostile record count cannot wrap.
  #[inline(always)]
  pub(crate) const fn open_doc(&mut self) -> u32 {
    self.doc_counter = self.doc_counter.saturating_add(1);
    self.doc_counter
  }

  /// The CURRENT value of the global document counter (`$$et{DOC_COUNT}`) —
  /// read by the LigoGPS sources (a SEPARATE [`crate::metadata::LigoGpsMeta`]
  /// struct that does not own this counter) so they can continue the SAME
  /// global `Doc<N>` sequence as the in-struct sources. Paired with
  /// [`Self::set_doc_counter`] after the LigoGPS source bumps it once per record
  /// (`LigoGpsMeta::stamp_doc_from`), mirroring the snapshot-bump-write-back the
  /// in-struct [`Self::stamp_gps_doc_from`] does internally.
  #[inline(always)]
  #[must_use]
  pub(crate) const fn doc_counter(&self) -> u32 {
    self.doc_counter
  }

  /// Write back the global document counter after a LigoGPS source bumped it
  /// once per record (see [`Self::doc_counter`]).
  #[inline(always)]
  pub(crate) const fn set_doc_counter(&mut self, counter: u32) -> &mut Self {
    self.doc_counter = counter;
    self
  }

  /// Stamp the global document ordinal `doc` onto every `mebx` sample at or
  /// after `start` — the records decoded by ONE `process_mebx` invocation (one
  /// timed sample) since the walker took its [`Self::mebx_sample_count`]
  /// watermark. Faithful to ExifTool calling `FoundSomething` ONCE per timed
  /// sample (ProcessSamples:1517) then `HandleTag`ing ALL of that sample's
  /// records — including the nested `detected-face` leaves — under the SAME
  /// `$$et{DOC_NUM}` (`Process_mebx` never bumps the doc, QuickTimeStream.pl:2644).
  pub(crate) fn stamp_mebx_doc_from(&mut self, start: usize, doc: u32) {
    if let Some(slice) = self.mebx_samples.get_mut(start..) {
      for s in slice {
        s.set_doc(Some(doc));
      }
    }
  }

  /// The number of GPS / sensor samples decoded so far — a watermark the stream
  /// walker takes BEFORE decoding one box's records so it can stamp the
  /// [`GpsOrigin`] onto exactly the samples that box produced (see
  /// [`Self::stamp_gps_origin_from`]). Mirrors [`Self::mebx_sample_count`].
  #[inline(always)]
  #[must_use]
  pub(crate) fn gps_sample_count(&self) -> usize {
    self.gps_samples.len()
  }

  /// Stamp `origin` onto every GPS sample at or after `start` — the samples
  /// decoded since the walker took its [`Self::gps_sample_count`] watermark. The
  /// origin is the WALKER PATH (box of origin) that reached those samples, NOT
  /// the decode type; it gates the no-`ee` emission (see [`GpsOrigin`]). Mirrors
  /// [`Self::stamp_mebx_track_index_from`].
  pub(crate) fn stamp_gps_origin_from(&mut self, start: usize, origin: GpsOrigin) {
    if let Some(slice) = self.gps_samples.get_mut(start..) {
      for s in slice {
        s.set_origin(Some(origin));
      }
    }
  }

  /// Assign the running GLOBAL document ordinal (`++DOC_COUNT`) to each GPS
  /// sample at or after `start` that does not already carry one — the
  /// `-ee`-only `ProcessSamples`/`ScanMediaData` sources (Kenwood `GPS ` box,
  /// the `moov`-level `gps `-box freeGPS blocks, the brute-force `mdat`
  /// freeGPS-scan), each of which bumps `$$et{DOC_NUM} = ++$$et{DOC_COUNT}` once
  /// per fix it appends (QuickTimeStream.pl:2565 Kenwood, the per-record /
  /// per-block `FoundSomething` of `ProcessFreeGPS`). Called AFTER the source's
  /// decode (watermark-then-stamp, mirroring [`Self::stamp_gps_origin_from`]),
  /// so the bumps land in the source's append order. Because the counter is the
  /// SAME `doc_counter` the `mebx`/`gps0`/`gsen`/`3gf` decoders already bump (via
  /// [`Self::open_doc`]), the stamped `Doc<N>` ordinals are GLOBAL across every
  /// source in WALK order (e.g. a Kenwood box after a `mebx` track continues the
  /// ordinal). Samples already stamped in-decoder (`gps0`/`gsen`/`3gf`, which
  /// `++DOC_COUNT` per PHYSICAL record incl. a skipped one) are LEFT UNTOUCHED —
  /// the `doc().is_none()` guard preserves their physical-record numbering. The
  /// emitter then reads each sample's [`GpsSample::doc`] VERBATIM for `-ee -G3`.
  pub(crate) fn stamp_gps_doc_from(&mut self, start: usize) {
    // Snapshot the counter, bump it locally per unstamped sample, then write it
    // back — avoids aliasing `self.open_doc()` with the `gps_samples` slice
    // borrow while preserving `open_doc`'s saturating semantics.
    let mut counter = self.doc_counter;
    if let Some(slice) = self.gps_samples.get_mut(start..) {
      for s in slice {
        if s.doc().is_none() {
          counter = counter.saturating_add(1);
          s.set_doc(Some(counter));
        }
      }
    }
    self.doc_counter = counter;
  }

  /// Stamp a `gpmd` MetaFormat sample track's just-decoded fixes (those at or
  /// after `start`) with the per-sample document, `Track<N>` origin, and sample-
  /// table timing — the `ProcessSamples` shape for the self-contained dashcam
  /// variants (FMAS / Wolfbox / Rove `Process_text`). Each such `freeGPS`
  /// process-proc appends ONE fix per timed sample, and ExifTool's
  /// `FoundSomething` (ProcessSamples:1517) opens ONE `Doc<N>` for that sample
  /// and emits its `SampleTime`/`SampleDuration` ahead of the fix, scoped to the
  /// enclosing `trak`'s `SET_GROUP1 = "Track$num"`. Open the GLOBAL doc once
  /// (caller passed it, continuing the shared counter), and write the doc +
  /// [`GpsOrigin::Gpmd`] + sample timing onto every fix this call produced
  /// (watermark-then-stamp, like [`Self::stamp_mebx_doc_from`]). Samples already
  /// stamped (none in this path — `dispatch_gpmd` pushes bare fixes) are left
  /// alone. The `doc` is shared across the (usually single) fixes of one sample,
  /// matching `FoundSomething`'s one-doc-per-sample.
  ///
  /// `set_group1_active` is the `$$et{SET_GROUP1}`-active state captured at this
  /// sample's `FoundSomething` time (BEFORE any of this `trak`'s own LigoGPS
  /// ran) — carried onto the [`GpsOrigin::Gpmd`] origin so the emitter groups
  /// the fix `Track<N>` (`true`) or the DEFAULT `QuickTime` (`false`, a preceding
  /// Kingslim `ProcessLigoGPS` already `delete`d the key). See
  /// [`GpsOrigin::Gpmd`].
  pub(crate) fn stamp_gps_gpmd_from(
    &mut self,
    start: usize,
    track: u32,
    doc: u32,
    sample_time: Option<f64>,
    sample_duration: Option<f64>,
    set_group1_active: bool,
  ) {
    if let Some(slice) = self.gps_samples.get_mut(start..) {
      for s in slice {
        s.set_origin(Some(GpsOrigin::Gpmd {
          track,
          set_group1_active,
        }));
        if s.doc().is_none() {
          s.set_doc(Some(doc));
        }
        if s.sample_time().is_none() {
          s.set_sample_time(sample_time);
        }
        if s.sample_duration().is_none() {
          s.set_sample_duration(sample_duration);
        }
      }
    }
  }

  /// The TIMING-ONLY markers — one per matched-but-empty self-contained `gpmd`
  /// sample (FMAS / Wolfbox / Rove). See [`GpmdTimingOnly`].
  #[inline(always)]
  #[must_use]
  pub fn gpmd_timing_only(&self) -> &[GpmdTimingOnly] {
    self.gpmd_timing_only.as_slice()
  }

  /// Push a TIMING-ONLY marker (an unstamped [`GpmdTimingOnly`]). The walker
  /// calls this when a timed sample consumed a `Doc<N>` but appended no
  /// `GpsSample` / `Text` row, then stamps it via
  /// [`Self::stamp_gpmd_timing_only_last`]. Two callers: a self-contained `gpmd`
  /// variant whose `Condition` matched (`dispatch_gpmd` returned
  /// [`crate::formats::quicktime_freegps::GpmdDispatch::SelfContained`]) yet
  /// decoded nothing, and a `text` sample whose `Process_text` emitted nothing
  /// (the binary-text path, [`crate::formats::quicktime_freegps::
  /// process_timed_text`]). Mirrors the camm
  /// [`crate::metadata::CammMeta::push_timing_only`] precedent.
  pub(crate) fn push_gpmd_timing_only(&mut self, marker: GpmdTimingOnly) -> &mut Self {
    self.gpmd_timing_only.push(marker);
    self
  }

  /// Stamp the most-recently-pushed `gpmd` TIMING-ONLY marker with its sample's
  /// `Track<N>` index, GLOBAL `Doc<N>` ordinal, sample-table timing, and the
  /// `$$et{SET_GROUP1}`-active flag (`true` ⇒ the `Track<N>` group, `false` ⇒ the
  /// DEFAULT `QuickTime` group after a preceding Kingslim `ProcessLigoGPS`
  /// `delete`d the key — see [`GpmdTimingOnly::set_group1_active`]) — called
  /// immediately after [`Self::push_gpmd_timing_only`].
  pub(crate) fn stamp_gpmd_timing_only_last(
    &mut self,
    track: u32,
    doc: u32,
    sample_time: Option<f64>,
    sample_duration: Option<f64>,
    set_group1_active: bool,
  ) -> &mut Self {
    if let Some(m) = self.gpmd_timing_only.last_mut() {
      m.set_stamp(track, doc, sample_time, sample_duration, set_group1_active);
    }
    self
  }

  /// `true` when a top-level magic box (`gps0`/`gsen`/`3gf`) carried more than
  /// one record — ExifTool's `$dirLen > $recLen` truncation + `EEWarn` trigger
  /// (see the `magic_box_truncated_no_ee` field docs). Consulted by the emitter
  /// (only at no-`ee`) to raise the file-level `ExifTool:Warning`.
  #[inline(always)]
  #[must_use]
  pub(crate) fn magic_box_truncated_no_ee(&self) -> bool {
    self.magic_box_truncated_no_ee
  }

  /// Record that a top-level magic box carried more than one record — call at
  /// the decoder's `$dirLen > $recLen` byte-length check, BEFORE the per-record
  /// loop, so it is faithful to the raw record count (see the field docs).
  #[inline(always)]
  pub(crate) fn note_magic_box_truncated(&mut self) {
    self.magic_box_truncated_no_ee = true;
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

  /// Only the top-level magic boxes (`gps0`/`gsen`/`3gf`) are processed without
  /// `-ee`; the `ProcessSamples`/`ScanMediaData` origins stay `-ee`-gated.
  #[test]
  fn gps_origin_emits_without_ee_only_for_magic_boxes() {
    for o in [GpsOrigin::Gps0, GpsOrigin::Gsen, GpsOrigin::ThreeGf] {
      assert!(o.emits_without_ee(), "{o:?} is a no-ee top-level magic box");
    }
    for o in [
      GpsOrigin::MoovGpsBox,
      GpsOrigin::Kenwood,
      GpsOrigin::FreeGpsScan,
    ] {
      assert!(!o.emits_without_ee(), "{o:?} is -ee-only");
    }
  }

  /// `origin` defaults to `None` and the accessor round-trips the setter; the
  /// origin marker does NOT make an otherwise-empty sample non-empty (it is
  /// provenance, not data).
  #[test]
  fn gps_sample_origin_roundtrip_and_emptiness() {
    let mut s = GpsSample::new();
    assert_eq!(s.origin(), None);
    s.set_origin(Some(GpsOrigin::Gps0));
    assert_eq!(s.origin(), Some(GpsOrigin::Gps0));
    // An origin-only sample is still empty (no data field set).
    assert!(s.is_empty());
  }

  /// `stamp_gps_origin_from` stamps EXACTLY the samples appended since the
  /// watermark — earlier samples keep their prior origin (the per-box
  /// watermark-then-stamp the walker uses to attribute each box's records).
  #[test]
  fn stamp_gps_origin_from_only_touches_samples_after_watermark() {
    let mut m = QuickTimeStreamMeta::new();
    // A pre-existing sample from an earlier box (e.g. a Kenwood `GPS ` fix).
    let mut earlier = GpsSample::new();
    earlier
      .set_latitude(Some(1.0))
      .set_longitude(Some(2.0))
      .set_origin(Some(GpsOrigin::Kenwood));
    m.push_gps_sample(earlier);
    // Watermark, then decode a `gps0` box (two fixes).
    let start = m.gps_sample_count();
    for (lat, lon) in [(3.0, 4.0), (5.0, 6.0)] {
      let mut s = GpsSample::new();
      s.set_latitude(Some(lat)).set_longitude(Some(lon));
      m.push_gps_sample(s);
    }
    m.stamp_gps_origin_from(start, GpsOrigin::Gps0);
    let origins: Vec<Option<GpsOrigin>> = m.gps_samples().iter().map(GpsSample::origin).collect();
    assert_eq!(
      origins,
      [
        Some(GpsOrigin::Kenwood), // earlier sample untouched
        Some(GpsOrigin::Gps0),
        Some(GpsOrigin::Gps0),
      ]
    );
  }

  /// The truncation/`EEWarn` flag defaults off and latches once noted.
  #[test]
  fn magic_box_truncation_flag_latches() {
    let mut m = QuickTimeStreamMeta::new();
    assert!(!m.magic_box_truncated_no_ee());
    m.note_magic_box_truncated();
    assert!(m.magic_box_truncated_no_ee());
  }
}
