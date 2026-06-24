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

use smol_str::SmolStr;

use crate::convert::EscapedJson;

use crate::metadata::{CameraInfo, CaptureSettings, GpsLocation, MediaMetadata};

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
#[derive(Debug, Clone)]
pub struct Insta360Identity {
  /// `0x0a SerialNumber` (QuickTimeStream.pl:698). Stored as the FULL
  /// `EscapeJSON` verdict ([`EscapedJson`]): the content plus whether the
  /// ORIGINAL raw-byte value classified as a BARE JSON token or a QUOTED
  /// string. A plainly-set value (the `set_*` API) is a quoted string; the
  /// decode path (`*_json` setters) carries the classify decision so a
  /// NUL-split numeric/boolean serial renders quoted, not bare (#53).
  serial_number: Option<EscapedJson>,
  /// `0x12 Model` (QuickTimeStream.pl:699) — e.g. `"Insta360 X3"`,
  /// `"Insta360 ONE RS"`, `"Insta360 Ace Pro"`.
  model: Option<EscapedJson>,
  /// `0x1a Firmware` (QuickTimeStream.pl:700).
  firmware: Option<EscapedJson>,
  /// `0x2a Parameters` (QuickTimeStream.pl:701-706) after the bundled
  /// `$val =~ tr/_/ /` substitution. The string encodes the
  /// "number of lenses, 6-axis orientation of each lens, raw resolution"
  /// (bundled note).
  parameters: Option<EscapedJson>,
  /// The STICKY `DOC_NUM` the `0x101` record inherits. `ProcessInsta360`
  /// walks the identity record LAST (it is first in file, walked last) and
  /// does NOT `++$$et{DOC_NUM}` for it — so its tags ride whatever the last
  /// surfaced timed row left `DOC_NUM` at (QuickTimeStream.pl:3427-3436 has
  /// no `FoundSomething` call). `None` / `0` ⇒ the flat (Main) document
  /// (no timed rows were walked before the identity).
  doc: Option<u32>,
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
      doc: None,
    }
  }

  /// `SerialNumber` (QuickTimeStream.pl:698) — the rendered text content.
  #[inline(always)]
  #[must_use]
  pub fn serial_number(&self) -> Option<&str> {
    self.serial_number.as_ref().map(EscapedJson::as_str)
  }

  /// `Model` (QuickTimeStream.pl:699) — the rendered text content.
  #[inline(always)]
  #[must_use]
  pub fn model(&self) -> Option<&str> {
    self.model.as_ref().map(EscapedJson::as_str)
  }

  /// `Firmware` (QuickTimeStream.pl:700) — the rendered text content.
  #[inline(always)]
  #[must_use]
  pub fn firmware(&self) -> Option<&str> {
    self.firmware.as_ref().map(EscapedJson::as_str)
  }

  /// `Parameters` (QuickTimeStream.pl:701-706) — the rendered text content.
  #[inline(always)]
  #[must_use]
  pub fn parameters(&self) -> Option<&str> {
    self.parameters.as_ref().map(EscapedJson::as_str)
  }

  /// `SerialNumber` with its [`EscapedJson`] classify verdict — the emit path
  /// maps `Bare`→[`crate::value::TagValue::Str`] (gate renders it bare) and
  /// `Quoted`→[`crate::value::TagValue::JsonStr`] (forced-quoted, #53).
  #[inline(always)]
  #[must_use]
  pub(crate) fn serial_number_json(&self) -> Option<&EscapedJson> {
    self.serial_number.as_ref()
  }

  /// `Model` with its [`EscapedJson`] classify verdict (see
  /// [`Self::serial_number_json`]).
  #[inline(always)]
  #[must_use]
  pub(crate) fn model_json(&self) -> Option<&EscapedJson> {
    self.model.as_ref()
  }

  /// `Firmware` with its [`EscapedJson`] classify verdict (see
  /// [`Self::serial_number_json`]).
  #[inline(always)]
  #[must_use]
  pub(crate) fn firmware_json(&self) -> Option<&EscapedJson> {
    self.firmware.as_ref()
  }

  /// `Parameters` with its [`EscapedJson`] classify verdict (see
  /// [`Self::serial_number_json`]).
  #[inline(always)]
  #[must_use]
  pub(crate) fn parameters_json(&self) -> Option<&EscapedJson> {
    self.parameters.as_ref()
  }

  /// The sticky `DOC_NUM` this identity record inherits (see field doc).
  #[inline(always)]
  #[must_use]
  pub const fn doc(&self) -> Option<u32> {
    self.doc
  }

  /// `true` when no VALUE field is populated. The sticky [`Self::doc`] is a
  /// walk-position stamp, not content, so it does not affect emptiness.
  #[inline(always)]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.serial_number.is_none()
      && self.model.is_none()
      && self.firmware.is_none()
      && self.parameters.is_none()
  }

  /// Assign `SerialNumber` from plain text. A plainly-set value is a QUOTED
  /// JSON string (`EscapeJSON` would never coerce a typed-in value to a bare
  /// token without re-running its gate); the decode path uses
  /// [`Self::set_serial_number_json`] to carry the classify verdict instead.
  #[inline(always)]
  pub fn set_serial_number(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.serial_number = v.map(EscapedJson::Quoted);
    self
  }

  /// Assign `Model` from plain text (QUOTED; see [`Self::set_serial_number`]).
  #[inline(always)]
  pub fn set_model(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.model = v.map(EscapedJson::Quoted);
    self
  }

  /// Assign `Firmware` from plain text (QUOTED; see [`Self::set_serial_number`]).
  #[inline(always)]
  pub fn set_firmware(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.firmware = v.map(EscapedJson::Quoted);
    self
  }

  /// Assign `Parameters` from plain text (QUOTED; see
  /// [`Self::set_serial_number`]).
  #[inline(always)]
  pub fn set_parameters(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.parameters = v.map(EscapedJson::Quoted);
    self
  }

  /// Assign `SerialNumber` with its [`EscapedJson`] classify verdict (the
  /// decode path — `escape_json_raw_bytes_classified`).
  #[inline(always)]
  pub(crate) fn set_serial_number_json(&mut self, v: Option<EscapedJson>) -> &mut Self {
    self.serial_number = v;
    self
  }

  /// Assign `Model` with its [`EscapedJson`] classify verdict.
  #[inline(always)]
  pub(crate) fn set_model_json(&mut self, v: Option<EscapedJson>) -> &mut Self {
    self.model = v;
    self
  }

  /// Assign `Firmware` with its [`EscapedJson`] classify verdict.
  #[inline(always)]
  pub(crate) fn set_firmware_json(&mut self, v: Option<EscapedJson>) -> &mut Self {
    self.firmware = v;
    self
  }

  /// Assign `Parameters` with its [`EscapedJson`] classify verdict.
  #[inline(always)]
  pub(crate) fn set_parameters_json(&mut self, v: Option<EscapedJson>) -> &mut Self {
    self.parameters = v;
    self
  }

  /// Assign the sticky `DOC_NUM` (see [`Self::doc`]).
  #[inline(always)]
  pub const fn set_doc(&mut self, v: Option<u32>) -> &mut Self {
    self.doc = v;
    self
  }
}

impl Default for Insta360Identity {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

/// Value equality on each field's OBSERVABLE/CANONICAL form, never its raw
/// private representation. Every field of [`Insta360Identity`] is compared this
/// way, so no construction-path bookkeeping can leak into equality (#53):
///
///  - the four identity fields (`serial_number` / `model` / `firmware` /
///    `parameters`, each [`EscapedJson`]) carry a private `Bare`/`Quoted`
///    JSON-rendering verdict that is serialization bookkeeping, NOT identity — a
///    clean numeric serial the decode path stores as `Bare("1234")` is the SAME
///    identity as one a `set_serial_number(Some("1234"))` caller stores as
///    `Quoted("1234")` (external callers cannot construct `Bare`). Each is
///    compared via its `*()` accessor (the inner `&str`), so the derived
///    [`EscapedJson`] `PartialEq` (which also discriminates the variant) is
///    deliberately NOT used.
///  - [`Self::doc`] is the sticky `DOC_NUM` walk stamp, compared via its emit
///    canonical form `doc.unwrap_or(0)`: `None` and `Some(0)` both denote the
///    flat (Main) document — emit collapses them with `id.doc().unwrap_or(0)`
///    (`quicktime.rs` `Group::with_doc(.., id.doc().unwrap_or(0))`), so a record
///    the decode path stamps `Some(0)` and the same content left `None` by
///    public construction are observably identical. `Some(nonzero)` stays a
///    distinct `Doc<N>`.
///
/// With all five fields observable-compared, the equality-leak class is closed:
/// no field carries a raw representation into `eq`. `Eq`/`Hash` are not derived,
/// so there is no consistency obligation to uphold.
impl PartialEq for Insta360Identity {
  #[inline]
  fn eq(&self, other: &Self) -> bool {
    self.serial_number() == other.serial_number()
      && self.model() == other.model()
      && self.firmware() == other.firmware()
      && self.parameters() == other.parameters()
      && self.doc.unwrap_or(0) == other.doc.unwrap_or(0)
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
  /// The GLOBAL `DOC_NUM` `ProcessInsta360` stamped this surfaced fix with
  /// (`++$$et{DOC_NUM}` per surfaced timed row, QuickTimeStream.pl:3416-3424
  /// via `FoundSomething`). `None` ⇒ flat/unstamped (a unit-built sample).
  doc: Option<u32>,
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
      doc: None,
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

  /// The GLOBAL `DOC_NUM` stamp (see field doc).
  #[inline(always)]
  #[must_use]
  pub const fn doc(&self) -> Option<u32> {
    self.doc
  }

  /// `true` when no VALUE field is populated. The [`Self::doc`] walk stamp is
  /// not content.
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

  /// Assign the GLOBAL `DOC_NUM` stamp (see [`Self::doc`]).
  #[inline(always)]
  pub const fn set_doc(&mut self, v: Option<u32>) -> &mut Self {
    self.doc = v;
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
  /// The GLOBAL `DOC_NUM` `ProcessInsta360` stamped this surfaced exposure
  /// row with (`++$$et{DOC_NUM}` per surfaced timed row, via `FoundSomething`
  /// — QuickTimeStream.pl:3386-3391). `None` ⇒ flat/unstamped.
  doc: Option<u32>,
}

impl Insta360ExposureSample {
  /// An empty exposure sample.
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      timestamp_ms: None,
      exposure_time_s: None,
      doc: None,
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

  /// The GLOBAL `DOC_NUM` stamp (see field doc).
  #[inline(always)]
  #[must_use]
  pub const fn doc(&self) -> Option<u32> {
    self.doc
  }

  /// `true` when no VALUE field is populated. The [`Self::doc`] walk stamp is
  /// not content.
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

  /// Assign the GLOBAL `DOC_NUM` stamp (see [`Self::doc`]).
  #[inline(always)]
  pub const fn set_doc(&mut self, v: Option<u32>) -> &mut Self {
    self.doc = v;
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
// Insta360AccelSample — one row from a `0x300` Accelerometer record
// ===========================================================================

/// One accelerometer / angular-velocity sample decoded from an Insta360
/// `0x300` record (QuickTimeStream.pl:3326-3346 stride probe + 3372-3385).
/// Each row is either 56 bytes `[TimeCode:u64][6×double-LE]` or 20 bytes
/// `[TimeCode:u64][6×u16-LE]` (each u16 decoded `(v - 0x8000) / 1000`); the
/// first 3 components are `Accelerometer`, the last 3 `AngularVelocity`
/// (QuickTimeStream.pl:3377-3384). The vec3 tags carry NO PrintConv — they
/// are the three f64 space-joined via Perl's `%.15g` (`"@a"`), mode-invariant.
#[derive(Debug, Clone, PartialEq)]
pub struct Insta360AccelSample {
  /// The GLOBAL `DOC_NUM` stamp (`++$$et{DOC_NUM}` per surfaced row).
  doc: Option<u32>,
  /// `TimeCode` raw millisecond counter.
  timecode_ms: Option<u64>,
  /// `Accelerometer` 3-axis (the first 3 components).
  accelerometer: Option<[f64; 3]>,
  /// `AngularVelocity` 3-axis (the last 3 components).
  angular_velocity: Option<[f64; 3]>,
}

impl Insta360AccelSample {
  /// An empty accelerometer sample.
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      doc: None,
      timecode_ms: None,
      accelerometer: None,
      angular_velocity: None,
    }
  }

  /// The GLOBAL `DOC_NUM` stamp.
  #[inline(always)]
  #[must_use]
  pub const fn doc(&self) -> Option<u32> {
    self.doc
  }

  /// `TimeCode` raw ms counter.
  #[inline(always)]
  #[must_use]
  pub const fn timecode_ms(&self) -> Option<u64> {
    self.timecode_ms
  }

  /// `Accelerometer` 3-axis.
  #[inline(always)]
  #[must_use]
  pub const fn accelerometer(&self) -> Option<[f64; 3]> {
    self.accelerometer
  }

  /// `AngularVelocity` 3-axis.
  #[inline(always)]
  #[must_use]
  pub const fn angular_velocity(&self) -> Option<[f64; 3]> {
    self.angular_velocity
  }

  /// `true` when no VALUE field is populated. The [`Self::doc`] walk stamp is
  /// not content.
  #[inline(always)]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.timecode_ms.is_none() && self.accelerometer.is_none() && self.angular_velocity.is_none()
  }

  /// Assign the GLOBAL `DOC_NUM` stamp.
  #[inline(always)]
  pub const fn set_doc(&mut self, v: Option<u32>) -> &mut Self {
    self.doc = v;
    self
  }

  /// Assign `TimeCode` raw ms.
  #[inline(always)]
  pub const fn set_timecode_ms(&mut self, v: Option<u64>) -> &mut Self {
    self.timecode_ms = v;
    self
  }

  /// Assign `Accelerometer` 3-axis.
  #[inline(always)]
  pub const fn set_accelerometer(&mut self, v: Option<[f64; 3]>) -> &mut Self {
    self.accelerometer = v;
    self
  }

  /// Assign `AngularVelocity` 3-axis.
  #[inline(always)]
  pub const fn set_angular_velocity(&mut self, v: Option<[f64; 3]>) -> &mut Self {
    self.angular_velocity = v;
    self
  }
}

impl Default for Insta360AccelSample {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// Insta360VideoTimeSample — one row from a `0x600` VideoTimeStamp record
// ===========================================================================

/// One video-timestamp sample decoded from an Insta360 `0x600` record
/// (QuickTimeStream.pl:3392-3396). Each row is 8 bytes
/// `[VideoTimeStamp:u64-LE]`. `VideoTimeStamp` is rendered as
/// `sprintf('%.3f', $val / 1000)` (millis → seconds, 3-decimal text), the
/// same as the `TimeCode` columns; mode-invariant (no PrintConv).
#[derive(Debug, Clone, PartialEq)]
pub struct Insta360VideoTimeSample {
  /// The GLOBAL `DOC_NUM` stamp (`++$$et{DOC_NUM}` per surfaced row).
  doc: Option<u32>,
  /// `VideoTimeStamp` raw millisecond counter.
  timecode_ms: Option<u64>,
}

impl Insta360VideoTimeSample {
  /// An empty video-timestamp sample.
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      doc: None,
      timecode_ms: None,
    }
  }

  /// The GLOBAL `DOC_NUM` stamp.
  #[inline(always)]
  #[must_use]
  pub const fn doc(&self) -> Option<u32> {
    self.doc
  }

  /// `VideoTimeStamp` raw ms counter.
  #[inline(always)]
  #[must_use]
  pub const fn timecode_ms(&self) -> Option<u64> {
    self.timecode_ms
  }

  /// `true` when no VALUE field is populated. The [`Self::doc`] walk stamp is
  /// not content.
  #[inline(always)]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.timecode_ms.is_none()
  }

  /// Assign the GLOBAL `DOC_NUM` stamp.
  #[inline(always)]
  pub const fn set_doc(&mut self, v: Option<u32>) -> &mut Self {
    self.doc = v;
    self
  }

  /// Assign `VideoTimeStamp` raw ms.
  #[inline(always)]
  pub const fn set_timecode_ms(&mut self, v: Option<u64>) -> &mut Self {
    self.timecode_ms = v;
    self
  }
}

impl Default for Insta360VideoTimeSample {
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
/// **Lazy-decode discipline.** `ProcessInsta360` decodes the timed records
/// (GPS / exposure / videotime / accelerometer) ONLY under `-ee`
/// (QuickTimeStream.pl:3296-3300 returns early without `ExtractEmbedded`),
/// and a crafted trailer can carry millions of rows (esp. 0x600
/// VideoTimeStamp at 8 bytes/row). To avoid eagerly allocating those Vecs
/// during the opts-agnostic parse, this struct holds only a BOUNDED domain
/// summary plus a borrow of the input bytes (`raw`). The full row decode is
/// deferred to emit time (`-ee`) via `decode_all_records(self.raw(),
/// self.trail_end())` in [`crate::formats::insta360`]. The summary (identity /
/// first GPS fix /
/// first exposure) is all [`Self::project_into`] — the always-on domain
/// path — needs.
///
/// Empty (`is_empty()`) when no Insta360 trailer with a decodable summary
/// is present (the `raw`/`trailer` borrow is still set for a signature-only
/// trailer so the positional warning + `-ee` decode still fire).
///
/// **D8 compliance.** Every field is private; access goes through the
/// accessors below.
#[derive(Debug, Clone, PartialEq)]
pub struct Insta360Meta<'a> {
  /// `0x101` INSV_MakerNotes identity record (WITH its sticky `DOC_NUM`),
  /// decoded cheaply during the light parse walk. At most one per trailer.
  identity: Option<Insta360Identity>,
  /// The FIRST valid `0x700` GPS `'A'` fix (lat+lon populated), decoded
  /// cheaply during the light parse walk — all [`Self::project_into`]'s
  /// `GpsLocation` tier needs. NOT doc-stamped (the light walk skips the
  /// global counter). The full per-row GPS Vec is produced lazily by
  /// `decode_all_records` at `-ee` emit time.
  first_gps: Option<Insta360GpsSample>,
  /// The FIRST `0x400` exposure row, decoded cheaply during the light parse
  /// walk — all [`Self::project_into`]'s `CaptureSettings` tier needs.
  first_exposure: Option<Insta360ExposureSample>,
  /// The detected trailer's `(file_offset, byte_size)` — set when an Insta360
  /// signature + length is identified. Drives the ALWAYS-ON
  /// `[minor] <name> trailer at offset 0x%x (%d bytes)` warning ExifTool's
  /// `ProcessMOV` raises whenever its walk reaches a trailer
  /// (QuickTime.pm:10600), present in EVERY mode (incl. no-`-ee`). `None`
  /// when no Insta360 trailer is present. On a bad-size trailer (`trailerLen >
  /// file size`) this is still set, with the WRAPPED (negative→unsigned)
  /// offset, matching bundled (which emits the positional warning then
  /// suppresses "Bad trailer size" via priority-0 first-wins).
  trailer: Option<(u64, u32)>,
  /// The HEAD (EARLIEST, closest-to-BOF) trailer of `IdentifyTrailers`'
  /// linked-list walk (QuickTime.pm:9897-9926), as `(kind name, start, len)` —
  /// drives the positional `[minor] <name> trailer at offset 0x%x (%d bytes)`
  /// warning `ProcessMOV` raises for the trailer hierarchy head
  /// (QuickTime.pm:10600). USUALLY the Insta360 trailer itself (then equal to
  /// the [`Self::trailer`] span with name `"Insta360"`), but when the Insta360
  /// trailer is followed by a LigoGPS/MIE trailer the head is whichever is
  /// closest to BOF — still the Insta360 trailer, since trailers are contiguous
  /// to EOF and the Insta360 one precedes the later block. For a file with ONLY
  /// a LigoGPS/MIE trailer (no Insta360) the head carries that kind's name and
  /// span (and [`Self::trailer`] is `None`). `None` when no trailer at all.
  head_trailer: Option<(&'static str, u64, u64)>,
  /// The full input file bytes, borrowed for the DEFERRED `-ee` row decode
  /// (`decode_all_records(raw, trail_end)` in [`crate::formats::insta360`]).
  /// `Some` whenever an Insta360 trailer signature + length was identified
  /// (incl. a bad-size trailer, whose decode simply yields nothing); `None` for
  /// a file with no Insta360 trailer.
  raw: Option<&'a [u8]>,
  /// File offset one-past the LAST byte of the Insta360 trailer — the anchor
  /// the deferred `-ee` decode walks backward from (`decode_all_records(raw,
  /// trail_end)`). Equals `raw.len()` for a standalone trailer at EOF, or
  /// `entry.start + entry.len` when `IdentifyTrailers` found the Insta360
  /// trailer behind a later LigoGPS/MIE trailer. `0` (unused) when no Insta360
  /// trailer is present; read only alongside [`Self::raw`].
  trail_end: usize,
  /// The value of the SHARED global document counter (`$$et{DOC_COUNT}`) at the
  /// moment `ProcessInsta360` begins in `ProcessMOV`'s trailer loop
  /// (QuickTime.pm:10654-10677) — i.e. AFTER every moov-timed + `udta`-LigoGPS +
  /// earlier-chain trailer source has bumped it. The deferred `-ee` row decode
  /// (`decode_all_records`) seeds its running counter from this base, so each
  /// surfaced Insta360 row gets `Doc<doc_base + N>` (`$$et{DOC_NUM} =
  /// ++$$et{DOC_COUNT}`, QuickTimeStream.pl:3374/3388/3394/3412) — continuing the
  /// ONE global sequence instead of restarting at 1. `0` for an Insta360-only
  /// file (the common case; byte-identical to the pre-unification local 0-based
  /// counter). The `0x101` identity still inherits the STICKY current doc (Main
  /// when no timed row preceded it), NOT this base.
  doc_base: u32,
}

impl<'a> Insta360Meta<'a> {
  /// An empty result (no Insta360 trailer decoded).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      identity: None,
      first_gps: None,
      first_exposure: None,
      trailer: None,
      head_trailer: None,
      raw: None,
      trail_end: 0,
      doc_base: 0,
    }
  }

  /// `0x101` identity record decode (with its sticky `DOC_NUM`).
  #[inline(always)]
  #[must_use]
  pub const fn identity(&self) -> Option<&Insta360Identity> {
    self.identity.as_ref()
  }

  /// The FIRST valid `0x700` GPS `'A'` fix (the domain-summary GPS), if any
  /// — feeds the [`crate::metadata::GpsLocation`] projection. The full
  /// per-row GPS Vec is produced lazily by `decode_all_records` at `-ee`
  /// emit time.
  #[inline(always)]
  #[must_use]
  pub const fn first_gps(&self) -> Option<&Insta360GpsSample> {
    self.first_gps.as_ref()
  }

  /// The FIRST `0x400` exposure row (the domain-summary exposure), if any —
  /// feeds the [`crate::metadata::CaptureSettings`] projection.
  #[inline(always)]
  #[must_use]
  pub const fn first_exposure(&self) -> Option<&Insta360ExposureSample> {
    self.first_exposure.as_ref()
  }

  /// The detected Insta360 trailer's `(file_offset, byte_size)`, if any (see
  /// field doc). Present iff an Insta360 trailer was identified; the positional
  /// trailer warning is driven off [`Self::head_trailer`] (the linked-list
  /// head, which may be a different trailer kind), NOT this.
  #[inline(always)]
  #[must_use]
  pub const fn trailer(&self) -> Option<(u64, u32)> {
    self.trailer
  }

  /// The HEAD (earliest) trailer `(kind name, start, len)` — drives the
  /// always-on `[minor] <name> trailer at offset 0x%x (%d bytes)` warning. See
  /// the field doc; `None` when no trailer at all was found.
  #[inline(always)]
  #[must_use]
  pub const fn head_trailer(&self) -> Option<(&'static str, u64, u64)> {
    self.head_trailer
  }

  /// The full input bytes borrowed for the DEFERRED `-ee` row decode
  /// (`decode_all_records(raw, trail_end)`); `None` when no Insta360 trailer
  /// was identified.
  #[inline(always)]
  #[must_use]
  pub const fn raw(&self) -> Option<&'a [u8]> {
    self.raw
  }

  /// File offset one-past the Insta360 trailer's LAST byte — the deferred
  /// `-ee` decode's backward anchor (`decode_all_records(raw, trail_end)`). See
  /// the field doc; meaningful only when [`Self::raw`] is `Some`.
  #[inline(always)]
  #[must_use]
  pub const fn trail_end(&self) -> usize {
    self.trail_end
  }

  /// The SHARED global document counter (`$$et{DOC_COUNT}`) value at the moment
  /// `ProcessInsta360` runs in the trailer phase — the base the deferred `-ee`
  /// row decode adds its per-row ordinals to (see the field doc). `0` for an
  /// Insta360-only file.
  #[inline(always)]
  #[must_use]
  pub const fn doc_base(&self) -> u32 {
    self.doc_base
  }

  /// `true` when no domain-summary content decoded. The [`Self::trailer`]
  /// detection flag is intentionally NOT consulted: a trailer that yielded
  /// no summary is still "empty" for projection purposes (the always-on
  /// trailer warning is driven off [`Self::trailer`] directly, in the
  /// QuickTime emitter, not off this predicate). The timed-row Vecs are
  /// decoded lazily at `-ee` time and so do not participate here either.
  #[inline(always)]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.identity.is_none() && self.first_gps.is_none() && self.first_exposure.is_none()
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

  /// Set the domain-summary first GPS fix (subsequent calls are ignored —
  /// the FIRST valid `'A'` fix wins).
  #[inline]
  pub fn set_first_gps(&mut self, v: Insta360GpsSample) -> &mut Self {
    if self.first_gps.is_none() {
      self.first_gps = Some(v);
    }
    self
  }

  /// Set the domain-summary first exposure row (subsequent calls are
  /// ignored — the FIRST row wins).
  #[inline]
  pub fn set_first_exposure(&mut self, v: Insta360ExposureSample) -> &mut Self {
    if self.first_exposure.is_none() {
      self.first_exposure = Some(v);
    }
    self
  }

  /// Record the detected trailer's `(file_offset, byte_size)` (subsequent
  /// calls are ignored — one trailer per file walk).
  #[inline]
  pub fn set_trailer(&mut self, offset: u64, size: u32) -> &mut Self {
    if self.trailer.is_none() {
      self.trailer = Some((offset, size));
    }
    self
  }

  /// Record the HEAD (earliest) trailer `(kind name, start, len)` that drives
  /// the positional warning (subsequent calls are ignored — one head per walk).
  #[inline]
  pub fn set_head_trailer(&mut self, name: &'static str, start: u64, len: u64) -> &mut Self {
    if self.head_trailer.is_none() {
      self.head_trailer = Some((name, start, len));
    }
    self
  }

  /// Borrow the full input bytes for the DEFERRED `-ee` row decode
  /// (subsequent calls are ignored).
  #[inline]
  pub fn set_raw(&mut self, data: &'a [u8]) -> &mut Self {
    if self.raw.is_none() {
      self.raw = Some(data);
    }
    self
  }

  /// Set the deferred `-ee` decode's backward anchor (the Insta360 trailer's
  /// end offset). Paired with [`Self::set_raw`].
  #[inline]
  pub const fn set_trail_end(&mut self, trail_end: usize) -> &mut Self {
    self.trail_end = trail_end;
    self
  }

  /// Record the SHARED global document-counter base (`$$et{DOC_COUNT}` when
  /// `ProcessInsta360` begins in the trailer phase) — seeds the deferred `-ee`
  /// row decode's running counter so each row gets `Doc<doc_base + N>`. See the
  /// field doc.
  #[inline]
  pub const fn set_doc_base(&mut self, doc_base: u32) -> &mut Self {
    self.doc_base = doc_base;
    self
  }

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
  pub(crate) fn project_into(&self, md: &mut MediaMetadata) {
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
      && let Some(s) = self.first_exposure()
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
      && let Some(s) = self.first_gps()
    {
      let mut gps = GpsLocation::new();
      gps
        .update_latitude(s.latitude())
        .update_longitude(s.longitude())
        .update_altitude_m(s.altitude_m())
        .update_timestamp(s.date_time().map(str::to_string));
      md.set_gps(gps);
    }
  }
}

impl Default for Insta360Meta<'_> {
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
    assert!(m.first_gps().is_none());
    assert!(m.first_exposure().is_none());
    assert!(m.raw().is_none());
    assert!(m.trailer().is_none());
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
  fn identity_eq_compares_content_not_json_verdict() {
    // #53: the decode path can store a clean numeric ORIGINAL as the bare JSON
    // verdict (`escape_json_raw_bytes_classified("1234")` → `Bare("1234")`),
    // while the public `set_*` API stores the SAME visible text as `Quoted`.
    // The classify verdict is JSON-rendering bookkeeping, not identity, so the
    // two must compare EQUAL on their public content.
    let mut decoded = Insta360Identity::new();
    decoded.set_serial_number_json(Some(EscapedJson::Bare(SmolStr::new("1234"))));
    assert_eq!(decoded.serial_number(), Some("1234"));

    let mut via_setter = Insta360Identity::new();
    via_setter.set_serial_number(Some(SmolStr::new("1234")));
    // Confirm the setter took the quoted verdict (the private leak the bug is
    // about) — yet equality ignores it.
    assert!(matches!(
      via_setter.serial_number_json(),
      Some(EscapedJson::Quoted(_))
    ));

    assert_eq!(
      decoded, via_setter,
      "Bare(\"1234\") and Quoted(\"1234\") must be equal (same content)"
    );

    // Sanity: genuinely different content is still NOT equal.
    let mut other = Insta360Identity::new();
    other.set_serial_number(Some(SmolStr::new("5678")));
    assert_ne!(decoded, other);

    // #53 R5: the `doc` walk stamp is compared by its emit canonical form
    // `doc.unwrap_or(0)`. `None` and `Some(0)` both denote the flat (Main)
    // document (emit collapses them via `id.doc().unwrap_or(0)`), so identical
    // content under either must compare EQUAL — the construction path must not
    // leak through `doc`.
    let mut doc_none = Insta360Identity::new();
    doc_none.set_serial_number(Some(SmolStr::new("1234")));
    assert_eq!(doc_none.doc(), None);
    let mut doc_zero = doc_none.clone();
    doc_zero.set_doc(Some(0));
    assert_eq!(doc_zero.doc(), Some(0));
    assert_eq!(
      doc_none, doc_zero,
      "doc None and Some(0) are the SAME Main-doc state (unwrap_or(0))"
    );

    // A nonzero `Doc<N>` stays distinct from the Main document (and from a
    // different nonzero doc): same content, different sticky doc ⇒ NOT equal.
    let mut doc_one = doc_none.clone();
    doc_one.set_doc(Some(1));
    assert_ne!(
      doc_zero, doc_one,
      "Some(0) (Main) and Some(1) (Doc1) are distinct documents"
    );
    assert_ne!(doc_none, doc_one);
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
    e.set_doc(Some(3));
    assert_eq!(e.timestamp_ms(), Some(1000));
    assert_eq!(e.exposure_time_s(), Some(0.008));
    assert_eq!(e.doc(), Some(3));
    assert!(!e.is_empty());
  }

  #[test]
  fn identity_doc_is_not_content() {
    // The sticky DOC_NUM stamp must not make an otherwise-empty identity
    // non-empty (it is a walk position, not a value).
    let mut id = Insta360Identity::new();
    id.set_doc(Some(8));
    assert_eq!(id.doc(), Some(8));
    assert!(id.is_empty());
  }

  #[test]
  fn gps_sample_doc_roundtrip_and_not_content() {
    let mut g = Insta360GpsSample::new();
    g.set_doc(Some(1));
    assert_eq!(g.doc(), Some(1));
    // doc alone is not content.
    assert!(g.is_empty());
    g.set_latitude(Some(45.0));
    assert!(!g.is_empty());
  }

  #[test]
  fn accel_sample_get_set_roundtrip() {
    let mut a = Insta360AccelSample::new();
    assert!(a.is_empty());
    a.set_timecode_ms(Some(1000));
    a.set_accelerometer(Some([0.1, 0.2, 9.8]));
    a.set_angular_velocity(Some([0.01, -0.02, 0.03]));
    a.set_doc(Some(8));
    assert_eq!(a.timecode_ms(), Some(1000));
    assert_eq!(a.accelerometer(), Some([0.1, 0.2, 9.8]));
    assert_eq!(a.angular_velocity(), Some([0.01, -0.02, 0.03]));
    assert_eq!(a.doc(), Some(8));
    assert!(!a.is_empty());
  }

  #[test]
  fn accel_sample_doc_is_not_content() {
    let mut a = Insta360AccelSample::new();
    a.set_doc(Some(7));
    assert!(a.is_empty());
  }

  #[test]
  fn video_time_sample_get_set_roundtrip() {
    let mut v = Insta360VideoTimeSample::new();
    assert!(v.is_empty());
    v.set_timecode_ms(Some(2000));
    v.set_doc(Some(6));
    assert_eq!(v.timecode_ms(), Some(2000));
    assert_eq!(v.doc(), Some(6));
    assert!(!v.is_empty());
  }

  #[test]
  fn video_time_sample_doc_is_not_content() {
    let mut v = Insta360VideoTimeSample::new();
    v.set_doc(Some(5));
    assert!(v.is_empty());
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
  fn first_exposure_summary_only_first_wins() {
    let mut m = Insta360Meta::new();
    assert!(m.first_exposure().is_none());
    let mut e0 = Insta360ExposureSample::new();
    e0.set_timestamp_ms(Some(1000))
      .set_exposure_time_s(Some(0.008));
    m.set_first_exposure(e0);
    let mut e1 = Insta360ExposureSample::new();
    e1.set_timestamp_ms(Some(2000));
    m.set_first_exposure(e1);
    let s = m.first_exposure().expect("exposure summary");
    assert_eq!(s.timestamp_ms(), Some(1000));
    assert!((s.exposure_time_s().unwrap() - 0.008).abs() < 1e-12);
    // The exposure summary counts toward non-emptiness.
    assert!(!m.is_empty());
  }

  #[test]
  fn set_raw_only_first_wins() {
    let a = [1u8, 2, 3];
    let b = [9u8, 9];
    let mut m = Insta360Meta::new();
    assert!(m.raw().is_none());
    m.set_raw(&a);
    m.set_raw(&b);
    assert_eq!(m.raw(), Some(a.as_slice()));
    // The raw borrow is not domain content.
    assert!(m.is_empty());
  }

  #[test]
  fn set_trailer_only_first_wins() {
    let mut m = Insta360Meta::new();
    assert_eq!(m.trailer(), None);
    m.set_trailer(140, 442);
    m.set_trailer(999, 1);
    assert_eq!(m.trailer(), Some((140, 442)));
    // The trailer flag does NOT make a record-less meta non-empty.
    assert!(m.is_empty());
  }

  #[test]
  fn first_gps_summary_only_first_wins() {
    let mut m = Insta360Meta::new();
    assert!(m.first_gps().is_none());
    let mut s1 = Insta360GpsSample::new();
    s1.set_latitude(Some(45.0));
    s1.set_longitude(Some(8.0));
    m.set_first_gps(s1);
    // A later fix must NOT override the first.
    let mut s2 = Insta360GpsSample::new();
    s2.set_latitude(Some(46.0));
    s2.set_longitude(Some(9.0));
    m.set_first_gps(s2);
    let f = m.first_gps().expect("fix");
    assert_eq!(f.latitude(), Some(45.0));
    assert_eq!(f.longitude(), Some(8.0));
    assert!(!m.is_empty());
  }
}
