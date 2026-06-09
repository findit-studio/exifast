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
//!  - **`GPSLatitude2`/`GPSLongitude2`** — the bundled `OLatitude`/
//!    `OLongitude` fields (LigoGPS.pm:387-388), hemisphere-signed by the
//!    same `NS`/`EW` refs as the primary lat/lon.
//!
//! ## What this sub-port deliberately does NOT decode
//!
//! Faithful-walked but unsurfaced:
//!  - **DecipherLigoGPS cipher discovery (LigoGPS.pm:143-221)** — the
//!    fallback when `DecryptLigoGPS` cannot decode the encrypted prefix.
//!    Cipher discovery requires accumulating ≥10 unique seconds-digit
//!    transitions across multiple records before the cipher table is
//!    known. Real-world dashcam files always satisfy `DecryptLigoGPS` on
//!    the first record, so the deciphered fallback is exotic. FOLLOW-UP
//!    (tracked as a per-port issue).
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

use crate::metadata::{GpsLocation, MediaMetadata};

// ===========================================================================
// LigoSource — which ExifTool dispatch path decoded a record
// ===========================================================================

/// The ExifTool dispatch path that produced a [`LigoGpsSample`]. The `-ee`
/// gating differs between the two families (LigoGPS.pm):
///  - [`LigoSource::UdtaJson`] — the `udta` `LigoJSON` / `GKUData` Conditions
///    (QuickTime.pm:834-846) routed to `ProcessLigoJSON` (LigoGPS.pm:334-398).
///    ExifTool processes the FIRST active record EVEN WITHOUT `-ee`, then
///    `Warn`s + `last`s (LigoGPS.pm:390-393); only `-ee` extracts the rest.
///  - [`LigoSource::Binary`] — `ProcessLigoGPS` (LigoGPS.pm:289-320), reached
///    via the file-end `&&&& ` trailer (QuickTime.pm:10658-10668) or a
///    `freeGPS`-embedded `LIGOGPSINFO\0` sample (QuickTimeStream.pl:1843-1888).
///    These entry points run ONLY inside the `-ee` trailer / scan pass, so the
///    binary family is fully `-ee`-gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LigoSource {
  /// A `udta` `LigoJSON` / `GKUData` record (`ProcessLigoJSON`). The FIRST
  /// active such record emits without `-ee`.
  UdtaJson,
  /// A binary `ProcessLigoGPS` record (trailer or freeGPS-embedded). Fully
  /// `-ee`-gated.
  Binary,
}

impl LigoSource {
  /// `true` for the `udta`-JSON / GKU family — the one whose FIRST active
  /// record emits without `-ee` (LigoGPS.pm:390-393).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn is_udta_json(self) -> bool {
    matches!(self, Self::UdtaJson)
  }
}

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
  /// `GPSLatitude2` decimal degrees, signed — the JSON `OLatitude` field
  /// (JSON-only, LigoGPS.pm:387). The bundled documents it as "? same
  /// values as Latitude/Longitude" (the un-defuzzed original).
  latitude2: Option<f64>,
  /// `GPSLongitude2` decimal degrees, signed — the JSON `OLongitude`
  /// field (JSON-only, LigoGPS.pm:388).
  longitude2: Option<f64>,
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
  /// Which ExifTool dispatch path produced this record — gates the no-`ee`
  /// FIRST-record emission (LigoGPS.pm:390-393, [`LigoSource`]). Defaults to
  /// [`LigoSource::Binary`] (the fully-`-ee`-gated family).
  source: LigoSource,
  /// The 1-based GLOBAL document ordinal (`Doc<N>`) stamped on this record —
  /// the typed mirror of `$$et{DOC_NUM} = ++$$et{DOC_COUNT}` (LigoGPS.pm:243 /
  /// :354). Allocated from the SAME shared `QuickTimeStreamMeta` counter as the
  /// other timed decoders, at the point the record is processed in walk order
  /// (see [`LigoGpsMeta::stamp_doc_from`]). `None` for unit-built samples; the
  /// emitter falls back to a per-record running ordinal then.
  doc: Option<u32>,
  /// A DOC-BURNING placeholder: a binary record that `ParseLigoGPS` accepted far
  /// enough to bump `$$et{DOC_NUM} = ++$$et{DOC_COUNT}` (LigoGPS.pm:243) but then
  /// rejected at the out-of-range sanity check (LigoGPS.pm:254 `($lat > 90 or
  /// $lon > 180) and ..., return`), so it consumes a global `Doc<N>` yet emits NO
  /// GPS tags. The emitter [`crate::formats::quicktime`] still advances its
  /// per-record doc ordinal for it (so the NEXT record's `Doc<N>` is the burned
  /// slot's successor) but skips all tag emission. `false` for a real sample.
  suppressed: bool,
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
      latitude2: None,
      longitude2: None,
      speed_kph: None,
      track_deg: None,
      altitude_m: None,
      magnetic_variation: None,
      accelerometer: None,
      source: LigoSource::Binary,
      doc: None,
      suppressed: false,
    }
  }

  /// A DOC-BURNING placeholder for an out-of-range binary record (LigoGPS.pm:243
  /// bumps `++DOC_COUNT` BEFORE the :254 range-check `return`): it carries no GPS
  /// fields, only the [`Self::suppressed`] flag, so it consumes one global
  /// `Doc<N>` ordinal yet emits nothing. `source` stays [`LigoSource::Binary`]
  /// (the fully-`-ee`-gated family — a binary record is never the no-`ee`
  /// first-record), so at no-`ee` it is skipped entirely like every other binary
  /// record.
  #[inline(always)]
  #[must_use]
  pub(crate) const fn new_suppressed() -> Self {
    let mut s = Self::new();
    s.suppressed = true;
    s
  }

  /// `true` when this is a doc-burning placeholder (out-of-range binary record)
  /// — the emitter consumes its `Doc<N>` but emits no tags. See
  /// [`Self::new_suppressed`].
  #[inline(always)]
  #[must_use]
  pub(crate) const fn is_suppressed(&self) -> bool {
    self.suppressed
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

  /// `GPSLatitude2` decimal degrees (JSON `OLatitude`).
  #[inline(always)]
  #[must_use]
  pub const fn latitude2(&self) -> Option<f64> {
    self.latitude2
  }

  /// `GPSLongitude2` decimal degrees (JSON `OLongitude`).
  #[inline(always)]
  #[must_use]
  pub const fn longitude2(&self) -> Option<f64> {
    self.longitude2
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

  /// Which ExifTool dispatch path produced this record ([`LigoSource`]).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn source(&self) -> LigoSource {
    self.source
  }

  /// The 1-based GLOBAL `Doc<N>` ordinal stamped on this record, or `None` for
  /// an unstamped (unit-built) sample.
  #[inline(always)]
  #[must_use]
  pub(crate) const fn doc(&self) -> Option<u32> {
    self.doc
  }

  /// `true` when no field is populated.
  #[inline(always)]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.date_time.is_none()
      && self.date_time_local.is_none()
      && self.latitude.is_none()
      && self.longitude.is_none()
      && self.latitude2.is_none()
      && self.longitude2.is_none()
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

  /// Assign `GPSLatitude2` (JSON `OLatitude`).
  #[inline(always)]
  pub const fn set_latitude2(&mut self, v: Option<f64>) -> &mut Self {
    self.latitude2 = v;
    self
  }

  /// Assign `GPSLongitude2` (JSON `OLongitude`).
  #[inline(always)]
  pub const fn set_longitude2(&mut self, v: Option<f64>) -> &mut Self {
    self.longitude2 = v;
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

  /// Assign the dispatch [`LigoSource`] (gates the no-`ee` first-record path).
  #[inline(always)]
  pub(crate) const fn set_source(&mut self, v: LigoSource) -> &mut Self {
    self.source = v;
    self
  }

  /// Assign the GLOBAL `Doc<N>` ordinal. Used by [`LigoGpsMeta::stamp_doc_from`].
  #[inline(always)]
  pub(crate) const fn set_doc(&mut self, v: Option<u32>) -> &mut Self {
    self.doc = v;
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

  /// The number of samples decoded so far — a watermark the QuickTime walker
  /// takes BEFORE decoding one LigoGPS source so it can stamp the GLOBAL
  /// `Doc<N>` onto exactly the records that source produced (see
  /// [`Self::stamp_doc_from`]). Mirrors
  /// [`crate::metadata::QuickTimeStreamMeta::gps_sample_count`].
  #[inline(always)]
  #[must_use]
  pub(crate) fn sample_count(&self) -> usize {
    self.samples.len()
  }

  /// Stamp the GLOBAL document ordinal onto each sample at or after `start` —
  /// the records decoded since the walker took its [`Self::sample_count`]
  /// watermark. `counter` is the CURRENT value of the shared
  /// `QuickTimeStreamMeta` doc counter (`$$et{DOC_COUNT}`); this bumps it once
  /// per record (`$$et{DOC_NUM} = ++$$et{DOC_COUNT}`, LigoGPS.pm:243 / :354) in
  /// the records' append (walk) order and returns the NEW counter value for the
  /// caller to write back, so LigoGPS docs continue the SAME global sequence as
  /// every `mebx`/`camm`/`gps0`/freeGPS source in the file (no collision /
  /// restart). Mirrors
  /// [`crate::metadata::QuickTimeStreamMeta::stamp_gps_doc_from`]'s
  /// snapshot-bump-write-back discipline, but takes the counter by value because
  /// the counter is owned by the stream meta, not here.
  #[must_use]
  pub(crate) fn stamp_doc_from(&mut self, start: usize, mut counter: u32) -> u32 {
    if let Some(slice) = self.samples.get_mut(start..) {
      for s in slice {
        counter = counter.saturating_add(1);
        s.set_doc(Some(counter));
      }
    }
    counter
  }

  /// Move every sample of `other` to the END of this holder (preserving its
  /// internal order), keeping THIS holder's warning if set else adopting
  /// `other`'s (first-wins, matching [`Self::set_warning`]).
  ///
  /// Used by the QuickTime walker to land the DEFERRED top-level `udta`-LigoGPS
  /// records AFTER the moov-timed sources in the shared sample Vec: ExifTool's
  /// single `ProcessMOV` walk emits the moov-timed metadata BEFORE a top-level
  /// `udta` that follows it in file order, so the udta records take the HIGHER
  /// `Doc<N>` ordinals AND appear later in output. Decoding them into a temp
  /// holder during the Pass-1 atom walk and appending here (after `extract_stream`
  /// + its inline doc stamp) keeps BOTH the append order and the global doc
  /// sequence faithful. (See the `parse_inner` phase-order note for the
  /// documented udta-before-moov limitation.)
  #[inline]
  pub(crate) fn append(&mut self, other: Self) -> &mut Self {
    let Self { samples, warning } = other;
    self.samples.extend(samples);
    if self.warning.is_none() {
      self.warning = warning;
    }
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
// project_into — LigoGPS projection into MediaMetadata
// ===========================================================================

impl LigoGpsMeta {
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
  /// **Warnings:** the walker's `warning()` channel (`Unrecognized data in
  /// LigoGPS trailer` / `LIGOGPSINFO format error` / `LIGOGPSINFO coordinates
  /// out of range` / …) is NOT pushed into `MediaMetadata` — it carries no
  /// warnings channel (the original `md.push_warning` path was written against
  /// an older surface, the same drift the #126 Parrot port hit). The warning
  /// stays on the typed [`LigoGpsMeta::warning`] surface and IS surfaced in the
  /// rendered output through the QuickTime per-format diagnostics path
  /// ([`crate::formats::quicktime::Meta`]'s [`crate::diagnostics::Diagnose`]
  /// impl) as a DOCUMENT-level `ExifTool:Warning` — faithful, because ExifTool
  /// raises these LigoGPS warnings with no `SET_GROUP1='LIGO'` in effect (the
  /// `ParseLigoGPS` warnings precede the LigoGPS.pm:255 `SET_GROUP1`; the
  /// trailer warning is in the `ProcessMOV` loop), so they are NOT `LIGO`-scoped.
  pub(crate) fn project_into(&self, md: &mut MediaMetadata) {
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
  fn warning_is_retained_on_the_typed_surface() {
    // Warnings do not propagate into `MediaMetadata` (it carries no warnings
    // channel — the original `md.push_warning` path was written against an older
    // surface, the same drift #126 Parrot hit). The rendered output surfaces
    // `warning()` through the QuickTime per-format diagnostics path (a
    // document-level `ExifTool:Warning`; see `quicktime::Meta`'s `Diagnose`).
    // Assert here the warning is STORED on the typed surface and that
    // `project_into` is a safe no-op for it.
    let mut m = LigoGpsMeta::new();
    m.set_warning(SmolStr::new("Unrecognized data in LigoGPS trailer"));
    assert_eq!(m.warning(), Some("Unrecognized data in LigoGPS trailer"));
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert!(md.gps().is_none());
    assert!(md.capture().is_none());
  }
}
