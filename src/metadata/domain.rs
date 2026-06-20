//! The normalized typed-metadata domain layer.
//!
//! [`MediaMetadata`] is a format-agnostic PROJECTION over a file's parsed
//! metadata: well-structured Rust structs grouped by domain (media,
//! camera, lens, GPS, capture) rather than a flat tag map. The per-format
//! `XxxMeta` (e.g. [`crate::metadata::QuickTimeMeta`]) stays the faithful
//! parse layer; this module builds the projection FROM it.
//!
//! ## SP1 scope (QuickTime port)
//!
//! [`MediaMetadata::from_quicktime`] populates only the [`MediaInfo`]
//! basics QuickTime SP1 can decode from the core structural atoms
//! (duration, dimensions, created time, track kinds). The
//! [`CameraInfo`] / [`LensInfo`] / [`GpsLocation`] / [`CaptureSettings`]
//! domains are left `None` — QuickTime SP2+ (the camera atoms,
//! embedded Exif, GPS) and other format ports fill them. The layer is
//! deliberately extensible: a new `from_*` projection entry point per
//! format, each writing only the domains it can decode.

use core::time::Duration;

use crate::metadata::{HandlerKind, QuickTimeMeta};

// ===========================================================================
// CameraInfo
// ===========================================================================

/// Camera-identity domain: who/what recorded the file. Every field is
/// optional — a format/sub-port that cannot decode a field leaves it `None`.
///
/// SP1 of the QuickTime port does not populate this struct (the camera
/// atoms `©mak`/`©mod`/serial live in `udta`/Keys/ItemList, deferred to
/// SP2). It exists now so the [`MediaMetadata`] aggregate is shape-stable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CameraInfo {
  /// Camera manufacturer (e.g. `"Apple"`, `"Canon"`).
  make: Option<String>,
  /// Camera model (e.g. `"iPhone 15 Pro"`).
  model: Option<String>,
  /// Camera body serial number.
  serial: Option<String>,
  /// Recording software / firmware string.
  software: Option<String>,
}

impl CameraInfo {
  /// An empty `CameraInfo` (every field `None`).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      make: None,
      model: None,
      serial: None,
      software: None,
    }
  }

  /// Camera manufacturer.
  #[inline(always)]
  #[must_use]
  pub fn make(&self) -> Option<&str> {
    self.make.as_deref()
  }

  /// Camera model.
  #[inline(always)]
  #[must_use]
  pub fn model(&self) -> Option<&str> {
    self.model.as_deref()
  }

  /// Camera body serial number.
  #[inline(always)]
  #[must_use]
  pub fn serial(&self) -> Option<&str> {
    self.serial.as_deref()
  }

  /// Recording software / firmware string.
  #[inline(always)]
  #[must_use]
  pub fn software(&self) -> Option<&str> {
    self.software.as_deref()
  }

  /// `true` when no field is populated — the projection produced nothing.
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.make.is_none() && self.model.is_none() && self.serial.is_none() && self.software.is_none()
  }

  /// Assign the raw camera-make wrapper.
  #[inline(always)]
  pub fn update_make(&mut self, v: Option<String>) -> &mut Self {
    self.make = v;
    self
  }

  /// Assign the raw camera-model wrapper.
  #[inline(always)]
  pub fn update_model(&mut self, v: Option<String>) -> &mut Self {
    self.model = v;
    self
  }

  /// Assign the raw serial-number wrapper.
  #[inline(always)]
  pub fn update_serial(&mut self, v: Option<String>) -> &mut Self {
    self.serial = v;
    self
  }

  /// Assign the raw software wrapper.
  #[inline(always)]
  pub fn update_software(&mut self, v: Option<String>) -> &mut Self {
    self.software = v;
    self
  }

  /// Field-by-field merge: `self`'s `Some` wins; each `None` field is
  /// filled from `other`. The precedence the [`MediaMetadata::merge`]
  /// aggregate relies on — a higher-priority source (`self`) overrides a
  /// lower-priority one (`other`) per field, never wholesale.
  #[must_use]
  pub fn merge(mut self, other: Self) -> Self {
    self.make = self.make.or(other.make);
    self.model = self.model.or(other.model);
    self.serial = self.serial.or(other.serial);
    self.software = self.software.or(other.software);
    self
  }
}

impl Default for CameraInfo {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// LensInfo
// ===========================================================================

/// Lens-identity domain. Every field optional; QuickTime SP1 does not
/// populate it (lens atoms are SP2+).
#[derive(Debug, Clone, PartialEq)]
pub struct LensInfo {
  /// Lens manufacturer.
  make: Option<String>,
  /// Lens model.
  model: Option<String>,
  /// Focal length in millimetres.
  focal_length_mm: Option<f64>,
  /// Maximum aperture (f-number) of the lens.
  aperture: Option<f64>,
}

impl LensInfo {
  /// An empty `LensInfo` (every field `None`).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      make: None,
      model: None,
      focal_length_mm: None,
      aperture: None,
    }
  }

  /// Lens manufacturer.
  #[inline(always)]
  #[must_use]
  pub fn make(&self) -> Option<&str> {
    self.make.as_deref()
  }

  /// Lens model.
  #[inline(always)]
  #[must_use]
  pub fn model(&self) -> Option<&str> {
    self.model.as_deref()
  }

  /// Focal length in millimetres.
  #[inline(always)]
  #[must_use]
  pub const fn focal_length_mm(&self) -> Option<f64> {
    self.focal_length_mm
  }

  /// Maximum aperture (f-number).
  #[inline(always)]
  #[must_use]
  pub const fn aperture(&self) -> Option<f64> {
    self.aperture
  }

  /// `true` when no field is populated.
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.make.is_none()
      && self.model.is_none()
      && self.focal_length_mm.is_none()
      && self.aperture.is_none()
  }

  /// Assign the raw lens-make wrapper.
  #[inline(always)]
  pub fn update_make(&mut self, v: Option<String>) -> &mut Self {
    self.make = v;
    self
  }

  /// Assign the raw lens-model wrapper.
  #[inline(always)]
  pub fn update_model(&mut self, v: Option<String>) -> &mut Self {
    self.model = v;
    self
  }

  /// Assign the raw focal-length wrapper.
  #[inline(always)]
  pub const fn update_focal_length_mm(&mut self, v: Option<f64>) -> &mut Self {
    self.focal_length_mm = v;
    self
  }

  /// Assign the raw aperture wrapper.
  #[inline(always)]
  pub const fn update_aperture(&mut self, v: Option<f64>) -> &mut Self {
    self.aperture = v;
    self
  }

  /// Field-by-field merge: `self`'s `Some` wins; each `None` field is
  /// filled from `other`. See [`MediaMetadata::merge`] for the precedence
  /// contract.
  #[must_use]
  pub fn merge(mut self, other: Self) -> Self {
    self.make = self.make.or(other.make);
    self.model = self.model.or(other.model);
    self.focal_length_mm = self.focal_length_mm.or(other.focal_length_mm);
    self.aperture = self.aperture.or(other.aperture);
    self
  }
}

impl Default for LensInfo {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// GpsLocation
// ===========================================================================

/// GPS-location domain. Every field optional; QuickTime SP1 does not
/// populate it (the `©xyz` / GPS track atoms are SP2/SP3).
#[derive(Debug, Clone, PartialEq)]
pub struct GpsLocation {
  /// Latitude in decimal degrees (positive = north).
  latitude: Option<f64>,
  /// Longitude in decimal degrees (positive = east).
  longitude: Option<f64>,
  /// Altitude in metres above sea level.
  altitude_m: Option<f64>,
  /// GPS fix timestamp, as the displayed `YYYY:MM:DD HH:MM:SS` string.
  timestamp: Option<String>,
}

impl GpsLocation {
  /// An empty `GpsLocation` (every field `None`).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      latitude: None,
      longitude: None,
      altitude_m: None,
      timestamp: None,
    }
  }

  /// Latitude in decimal degrees.
  #[inline(always)]
  #[must_use]
  pub const fn latitude(&self) -> Option<f64> {
    self.latitude
  }

  /// Longitude in decimal degrees.
  #[inline(always)]
  #[must_use]
  pub const fn longitude(&self) -> Option<f64> {
    self.longitude
  }

  /// Altitude in metres.
  #[inline(always)]
  #[must_use]
  pub const fn altitude_m(&self) -> Option<f64> {
    self.altitude_m
  }

  /// GPS fix timestamp string.
  #[inline(always)]
  #[must_use]
  pub fn timestamp(&self) -> Option<&str> {
    self.timestamp.as_deref()
  }

  /// `true` when no field is populated.
  #[inline(always)]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.latitude.is_none()
      && self.longitude.is_none()
      && self.altitude_m.is_none()
      && self.timestamp.is_none()
  }

  /// Assign the raw latitude wrapper.
  #[inline(always)]
  pub const fn update_latitude(&mut self, v: Option<f64>) -> &mut Self {
    self.latitude = v;
    self
  }

  /// Assign the raw longitude wrapper.
  #[inline(always)]
  pub const fn update_longitude(&mut self, v: Option<f64>) -> &mut Self {
    self.longitude = v;
    self
  }

  /// Assign the raw altitude wrapper.
  #[inline(always)]
  pub const fn update_altitude_m(&mut self, v: Option<f64>) -> &mut Self {
    self.altitude_m = v;
    self
  }

  /// Assign the raw timestamp wrapper.
  #[inline(always)]
  pub fn update_timestamp(&mut self, v: Option<String>) -> &mut Self {
    self.timestamp = v;
    self
  }

  /// Field-by-field merge: `self`'s `Some` wins; each `None` field is
  /// filled from `other`. See [`MediaMetadata::merge`] for the precedence
  /// contract.
  #[must_use]
  pub fn merge(mut self, other: Self) -> Self {
    self.latitude = self.latitude.or(other.latitude);
    self.longitude = self.longitude.or(other.longitude);
    self.altitude_m = self.altitude_m.or(other.altitude_m);
    self.timestamp = self.timestamp.or(other.timestamp);
    self
  }
}

impl Default for GpsLocation {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// CaptureSettings
// ===========================================================================

/// Capture-settings domain (exposure / ISO / aperture at capture time).
/// Every field optional; QuickTime SP1 does not populate it (these come
/// from embedded Exif, SP3).
#[derive(Debug, Clone, PartialEq)]
pub struct CaptureSettings {
  /// Exposure (shutter) time in seconds.
  exposure_time_s: Option<f64>,
  /// ISO sensitivity.
  iso: Option<u32>,
  /// Aperture (f-number) at capture time.
  f_number: Option<f64>,
}

impl CaptureSettings {
  /// An empty `CaptureSettings` (every field `None`).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      exposure_time_s: None,
      iso: None,
      f_number: None,
    }
  }

  /// Exposure (shutter) time in seconds.
  #[inline(always)]
  #[must_use]
  pub const fn exposure_time_s(&self) -> Option<f64> {
    self.exposure_time_s
  }

  /// ISO sensitivity.
  #[inline(always)]
  #[must_use]
  pub const fn iso(&self) -> Option<u32> {
    self.iso
  }

  /// Aperture (f-number).
  #[inline(always)]
  #[must_use]
  pub const fn f_number(&self) -> Option<f64> {
    self.f_number
  }

  /// `true` when no field is populated.
  #[inline(always)]
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.exposure_time_s.is_none() && self.iso.is_none() && self.f_number.is_none()
  }

  /// Assign the raw exposure-time wrapper.
  #[inline(always)]
  pub const fn update_exposure_time_s(&mut self, v: Option<f64>) -> &mut Self {
    self.exposure_time_s = v;
    self
  }

  /// Assign the raw ISO wrapper.
  #[inline(always)]
  pub const fn update_iso(&mut self, v: Option<u32>) -> &mut Self {
    self.iso = v;
    self
  }

  /// Assign the raw f-number wrapper.
  #[inline(always)]
  pub const fn update_f_number(&mut self, v: Option<f64>) -> &mut Self {
    self.f_number = v;
    self
  }

  /// Field-by-field merge: `self`'s `Some` wins; each `None` field is
  /// filled from `other`. See [`MediaMetadata::merge`] for the precedence
  /// contract.
  #[must_use]
  pub const fn merge(mut self, other: Self) -> Self {
    // `Option::or` is not yet `const`; expand it by hand so this stays a
    // `const fn` (every field here is `Copy`).
    if self.exposure_time_s.is_none() {
      self.exposure_time_s = other.exposure_time_s;
    }
    if self.iso.is_none() {
      self.iso = other.iso;
    }
    if self.f_number.is_none() {
      self.f_number = other.f_number;
    }
    self
  }
}

impl Default for CaptureSettings {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// Orientation
// ===========================================================================

/// The display orientation of a file's primary visual content, expressed as
/// the EXIF `Orientation` model (`0x0112`): a value `1`–`8` encoding a
/// rotation plus an optional mirror flip.
///
/// This is the single normalized orientation a consumer reads to orient a
/// decoded-frame thumbnail without parsing tags. It unifies the two source
/// encodings:
///
/// * **Stills** — the EXIF `Orientation` tag directly (its `1`–`8`).
/// * **Video** — the QuickTime/RIFF display-matrix rotation (`0`/`90`/`180`/
///   `270` clockwise), which has no mirror component, mapped into the
///   rotation-only subset of the EXIF model (`0→1`, `90→6`, `180→3`,
///   `270→8`).
///
/// # Operation-order contract — MIRROR FIRST
///
/// The two accessors decompose the orientation under one fixed order: a
/// consumer applies the horizontal mirror ([`Self::mirrored`]) FIRST, THEN
/// rotates clockwise by [`Self::rotation_degrees`]:
///
/// ```text
/// if o.mirrored() { flip_horizontal(); }
/// rotate_clockwise(o.rotation_degrees());
/// ```
///
/// This matches the wording of ExifTool's reflected labels — "Mirror
/// horizontal AND rotate N CW" — literally: the `(degrees, mirrored)` pair is
/// the (rotate-after-mirror, mirror) factorization of the label, so the net
/// pixel transform equals the label. The EXIF `1`–`8` ⇄ (clockwise degrees,
/// mirrored) mapping under this contract is the standard one (TIFF 6.0 / EXIF
/// 2.3); the `degrees CW` / `mirrored` columns are what the two accessors
/// return and the rightmost column is ExifTool's `Orientation` PrintConv
/// label (the canonical truth):
///
/// | EXIF | degrees CW | mirrored | ExifTool label | net transform |
/// |---|---|---|---|---|
/// | 1 | 0 | no | Horizontal (normal) | identity |
/// | 2 | 0 | yes | Mirror horizontal | mirror horizontal |
/// | 3 | 180 | no | Rotate 180 | rotate 180 |
/// | 4 | 180 | yes | Mirror vertical | mirror vertical (mirror-h then 180) |
/// | 5 | 270 | yes | Mirror horizontal and rotate 270 CW | transpose (main diagonal) |
/// | 6 | 90 | no | Rotate 90 CW | rotate 90 CW |
/// | 7 | 90 | yes | Mirror horizontal and rotate 90 CW | transverse (anti-diagonal) |
/// | 8 | 270 | no | Rotate 270 CW | rotate 270 CW |
///
/// Note `5` and `7` are NOT interchangeable: `5` rotates `270` CW after the
/// mirror (≡ transpose) and `7` rotates `90` CW (≡ transverse), tracking the
/// "rotate 270/90 CW" wording of their respective labels. The reflected `2`/
/// `4`/`5`/`7` are the [`Self::mirrored`] set; `4` ("Mirror vertical") is
/// `mirror-h` then `180` CW, which equals a vertical mirror under this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Orientation(u8);

impl Orientation {
  /// Build from a raw EXIF `Orientation` value. Returns `None` for any value
  /// outside the defined `1`–`8` range (`0` and out-of-range encodings are
  /// not a valid orientation).
  #[inline]
  #[must_use]
  pub const fn from_exif_value(value: u8) -> Option<Self> {
    if value >= 1 && value <= 8 {
      Some(Self(value))
    } else {
      None
    }
  }

  /// Build from a video display-matrix rotation in clockwise degrees. Only
  /// the four right-angle rotations a display matrix encodes are accepted
  /// (`0`/`90`/`180`/`270`); they map to the un-mirrored EXIF subset
  /// (`1`/`6`/`3`/`8`). Any other angle yields `None`.
  #[inline]
  #[must_use]
  pub const fn from_video_degrees(degrees: u16) -> Option<Self> {
    match degrees {
      0 => Some(Self(1)),
      90 => Some(Self(6)),
      180 => Some(Self(3)),
      270 => Some(Self(8)),
      _ => None,
    }
  }

  /// The raw EXIF `Orientation` value (`1`–`8`).
  #[inline(always)]
  #[must_use]
  pub const fn exif_value(self) -> u8 {
    self.0
  }

  /// The clockwise rotation to apply, in degrees (`0`/`90`/`180`/`270`),
  /// under the type's **mirror-first** contract: a consumer applies the
  /// horizontal mirror ([`Self::mirrored`]) FIRST, THEN rotates by this many
  /// degrees clockwise. The pair is chosen so that net transform reproduces
  /// ExifTool's `Orientation` label exactly (see the type-level table) — e.g.
  /// `5` = `mirror-h` then `270` CW (≡ transpose) and `7` = `mirror-h` then
  /// `90` CW (≡ transverse); the two are NOT interchangeable.
  #[inline]
  #[must_use]
  pub const fn rotation_degrees(self) -> u16 {
    match self.0 {
      3 | 4 => 180,
      // `6` = "Rotate 90 CW"; `7` = "Mirror horizontal and rotate 90 CW"
      // (mirror-first ⇒ transverse). Both rotate 90 CW.
      6 | 7 => 90,
      // `8` = "Rotate 270 CW"; `5` = "Mirror horizontal and rotate 270 CW"
      // (mirror-first ⇒ transpose). Both rotate 270 CW.
      5 | 8 => 270,
      // 1 | 2 (and, defensively, any unconstructible value) — no rotation.
      _ => 0,
    }
  }

  /// `true` if the orientation includes a horizontal mirror flip (the
  /// reflected EXIF values `2`/`4`/`5`/`7`). Under the type's **mirror-first**
  /// contract this flip is applied BEFORE [`Self::rotation_degrees`]: a
  /// consumer does `if mirrored() { flip_horizontal(); } rotate_cw(degrees)`.
  /// (`4` = `mirror-h` then `180` CW ≡ mirror vertical; `5` ≡ transpose; `7`
  /// ≡ transverse — all reproduce the ExifTool label under this order.)
  #[inline]
  #[must_use]
  pub const fn mirrored(self) -> bool {
    matches!(self.0, 2 | 4 | 5 | 7)
  }
}

// ===========================================================================
// MediaInfo
// ===========================================================================

/// Media-container domain: the basic structural facts of the file —
/// duration, pixel dimensions, creation time, and which track kinds it
/// carries. This is the domain QuickTime SP1 populates.
#[derive(Debug, Clone, PartialEq)]
pub struct MediaInfo {
  /// Total media duration.
  duration: Option<Duration>,
  /// Pixel width of the primary video track.
  width: Option<u32>,
  /// Pixel height of the primary video track.
  height: Option<u32>,
  /// Creation timestamp, as the displayed `YYYY:MM:DD HH:MM:SS` string.
  created: Option<String>,
  /// The kinds of track the container holds (video / audio / …), in file
  /// order. Used by callers to answer "is this a video or an audio file?".
  track_kinds: Vec<TrackKind>,
  /// Display orientation of the primary visual content (EXIF `Orientation`
  /// for stills; the display-matrix rotation for video). `None` when the
  /// source carries no orientation (or the default `1` was never written).
  orientation: Option<Orientation>,
}

impl MediaInfo {
  /// An empty `MediaInfo` (every field `None` / empty).
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      duration: None,
      width: None,
      height: None,
      created: None,
      track_kinds: Vec::new(),
      orientation: None,
    }
  }

  /// Total media duration.
  #[inline(always)]
  #[must_use]
  pub const fn duration(&self) -> Option<Duration> {
    self.duration
  }

  /// Pixel width of the primary video track.
  #[inline(always)]
  #[must_use]
  pub const fn width(&self) -> Option<u32> {
    self.width
  }

  /// Pixel height of the primary video track.
  #[inline(always)]
  #[must_use]
  pub const fn height(&self) -> Option<u32> {
    self.height
  }

  /// Creation timestamp string.
  #[inline(always)]
  #[must_use]
  pub fn created(&self) -> Option<&str> {
    self.created.as_deref()
  }

  /// The kinds of track the container holds, in file order.
  #[inline(always)]
  #[must_use]
  pub fn track_kinds(&self) -> &[TrackKind] {
    self.track_kinds.as_slice()
  }

  /// Display orientation of the primary visual content — the EXIF
  /// `Orientation` for stills, the display-matrix rotation for video. A
  /// consumer reads this to orient a decoded-frame thumbnail without parsing
  /// tags. `None` when the source carries no orientation.
  #[inline(always)]
  #[must_use]
  pub const fn orientation(&self) -> Option<Orientation> {
    self.orientation
  }

  /// `true` if the container carries at least one video track.
  #[inline(always)]
  #[must_use]
  pub fn has_video(&self) -> bool {
    self.track_kinds.iter().any(TrackKind::is_video)
  }

  /// `true` if the container carries at least one audio track.
  #[inline(always)]
  #[must_use]
  pub fn has_audio(&self) -> bool {
    self.track_kinds.iter().any(TrackKind::is_audio)
  }

  /// Assign the raw duration wrapper.
  #[inline(always)]
  pub const fn update_duration(&mut self, v: Option<Duration>) -> &mut Self {
    self.duration = v;
    self
  }

  /// Assign the raw width wrapper.
  #[inline(always)]
  pub const fn update_width(&mut self, v: Option<u32>) -> &mut Self {
    self.width = v;
    self
  }

  /// Assign the raw height wrapper.
  #[inline(always)]
  pub const fn update_height(&mut self, v: Option<u32>) -> &mut Self {
    self.height = v;
    self
  }

  /// Assign the raw created-timestamp wrapper.
  #[inline(always)]
  pub fn update_created(&mut self, v: Option<String>) -> &mut Self {
    self.created = v;
    self
  }

  /// Assign the display orientation.
  #[inline(always)]
  pub const fn update_orientation(&mut self, v: Option<Orientation>) -> &mut Self {
    self.orientation = v;
    self
  }

  /// Mutable access to the track-kind list (grow / shrink).
  #[inline(always)]
  pub const fn track_kinds_mut(&mut self) -> &mut Vec<TrackKind> {
    &mut self.track_kinds
  }

  /// Field-by-field merge: `self`'s `Some` (and non-empty `track_kinds`)
  /// wins; each gap is filled from `other`. See [`MediaMetadata::merge`]
  /// for the precedence contract.
  #[must_use]
  pub fn merge(mut self, other: Self) -> Self {
    self.duration = self.duration.or(other.duration);
    self.width = self.width.or(other.width);
    self.height = self.height.or(other.height);
    self.created = self.created.or(other.created);
    self.orientation = self.orientation.or(other.orientation);
    if self.track_kinds.is_empty() {
      self.track_kinds = other.track_kinds;
    }
    self
  }
}

impl Default for MediaInfo {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

/// The kind of a media track in the normalized projection. An open
/// vocabulary — containers keep adding handler kinds — with a lossless
/// [`TrackKind::Other`] escape carrying the raw 4-character code.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TrackKind {
  /// A video track.
  Video,
  /// An audio track.
  Audio,
  /// A subtitle / text / closed-caption track.
  Subtitle,
  /// A timecode track.
  TimeCode,
  /// A metadata track.
  Metadata,
  /// Any track kind not covered above — the raw handler code, preserved
  /// verbatim.
  Other(String),
}

impl TrackKind {
  /// Project a faithful-parse [`HandlerKind`] onto the normalized
  /// [`TrackKind`]. Total — every handler kind maps to exactly one variant.
  #[inline(always)]
  #[must_use]
  pub fn from_handler(handler: &HandlerKind) -> Self {
    match handler {
      HandlerKind::Video => Self::Video,
      HandlerKind::Audio => Self::Audio,
      HandlerKind::Text | HandlerKind::Subtitle => Self::Subtitle,
      HandlerKind::TimeCode => Self::TimeCode,
      HandlerKind::Metadata => Self::Metadata,
      HandlerKind::Hint => Self::Other("hint".to_string()),
      HandlerKind::Other(code) => Self::Other(code.clone()),
    }
  }

  /// `true` for a video track.
  #[inline(always)]
  #[must_use]
  pub const fn is_video(&self) -> bool {
    matches!(self, Self::Video)
  }

  /// `true` for an audio track.
  #[inline(always)]
  #[must_use]
  pub const fn is_audio(&self) -> bool {
    matches!(self, Self::Audio)
  }

  /// `true` for a subtitle / text track.
  #[inline(always)]
  #[must_use]
  pub const fn is_subtitle(&self) -> bool {
    matches!(self, Self::Subtitle)
  }

  /// `true` for a timecode track.
  #[inline(always)]
  #[must_use]
  pub const fn is_time_code(&self) -> bool {
    matches!(self, Self::TimeCode)
  }

  /// `true` for a metadata track.
  #[inline(always)]
  #[must_use]
  pub const fn is_metadata(&self) -> bool {
    matches!(self, Self::Metadata)
  }

  /// `true` for an unrecognized track kind.
  #[inline(always)]
  #[must_use]
  pub const fn is_other(&self) -> bool {
    matches!(self, Self::Other(_))
  }
}

// ===========================================================================
// MediaMetadata — the aggregate projection
// ===========================================================================

/// The normalized typed-metadata aggregate: a format-agnostic, well-
/// structured view of a media file's metadata, grouped by domain.
///
/// This is a PROJECTION built from a format's faithful-parse layer (e.g.
/// [`QuickTimeMeta`]) — NOT a flat tag map. A caller indexes a media
/// library by reading [`Self::media`] for structural facts and
/// [`Self::camera`] / [`Self::lens`] / [`Self::gps`] / [`Self::capture`]
/// for the camera-metadata domains.
///
/// [`Self::media`] is always present (every file has a container);
/// the other four domains are `Option` — `None` when the source format /
/// sub-port could not decode that domain.
#[derive(Debug, Clone, PartialEq)]
pub struct MediaMetadata {
  /// Structural container facts (always present).
  media: MediaInfo,
  /// Camera-identity domain, or `None` if undecoded.
  camera: Option<CameraInfo>,
  /// Lens-identity domain, or `None` if undecoded.
  lens: Option<LensInfo>,
  /// GPS-location domain, or `None` if undecoded.
  gps: Option<GpsLocation>,
  /// Capture-settings domain, or `None` if undecoded.
  capture: Option<CaptureSettings>,
}

impl MediaMetadata {
  /// An empty aggregate — an empty [`MediaInfo`] and all camera domains
  /// `None`. The starting point a `from_*` projection fills.
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      media: MediaInfo::new(),
      camera: None,
      lens: None,
      gps: None,
      capture: None,
    }
  }

  /// Build the projection from a QuickTime faithful-parse layer.
  ///
  /// **SP1 scope:** fills only [`MediaInfo`] — the movie duration, the
  /// primary video track's pixel dimensions, the creation timestamp, and
  /// the per-track [`TrackKind`] list. The camera / lens / GPS / capture
  /// domains stay `None`: their QuickTime atoms (`udta` camera tags,
  /// embedded Exif, GPS tracks) are SP2-SP4 work. As those sub-ports land,
  /// THIS function grows to populate the extra domains — the projection
  /// entry point is the single extensible seam.
  #[must_use]
  pub fn from_quicktime(qt: &QuickTimeMeta) -> Self {
    let mut media = MediaInfo::new();

    // Movie duration (mvhd Duration, seconds → Duration).
    if let Some(secs) = qt.duration_seconds() {
      media.update_duration(duration_from_secs(secs));
    }
    // Creation timestamp (mvhd CreateDate).
    media.update_created(qt.create_date().map(str::to_string));

    // Primary video track's pixel dimensions + the per-track kind list.
    for track in qt.tracks() {
      if let Some(handler) = track.handler() {
        media
          .track_kinds_mut()
          .push(TrackKind::from_handler(handler));
      }
      // The first track that carries non-zero tkhd dimensions is taken as
      // the primary video track (faithful to ExifTool's ImageWidth /
      // ImageHeight surfacing the video track's tkhd values).
      if let (None, Some(w), Some(h)) = (media.width(), track.image_width(), track.image_height()) {
        media.update_width(Some(w));
        media.update_height(Some(h));
      }
    }

    // Display orientation from the primary VIDEO track's tkhd
    // `MatrixStructure`. Mirrors ExifTool's `CalcRotation` (QuickTime.pm:8797):
    // the first `vide`-handler track, its matrix angle via `GetRotationAngle`,
    // mapped into the rotation-only EXIF subset (video matrices carry no
    // mirror). `None` when there is no video track, no matrix, a degenerate
    // matrix, or a non-right-angle rotation.
    media.update_orientation(video_matrix_orientation(qt));

    Self {
      media,
      // SP2-SP4 / other formats fill these.
      camera: None,
      lens: None,
      gps: None,
      capture: None,
    }
  }

  /// The structural container facts (always present).
  #[inline(always)]
  #[must_use]
  pub const fn media(&self) -> &MediaInfo {
    &self.media
  }

  /// The camera-identity domain, or `None` if undecoded.
  #[inline(always)]
  #[must_use]
  pub const fn camera(&self) -> Option<&CameraInfo> {
    self.camera.as_ref()
  }

  /// The lens-identity domain, or `None` if undecoded.
  #[inline(always)]
  #[must_use]
  pub const fn lens(&self) -> Option<&LensInfo> {
    self.lens.as_ref()
  }

  /// The GPS-location domain, or `None` if undecoded.
  #[inline(always)]
  #[must_use]
  pub const fn gps(&self) -> Option<&GpsLocation> {
    self.gps.as_ref()
  }

  /// The capture-settings domain, or `None` if undecoded.
  #[inline(always)]
  #[must_use]
  pub const fn capture(&self) -> Option<&CaptureSettings> {
    self.capture.as_ref()
  }

  /// Mutable access to the structural container facts — the seam a future
  /// `from_*` projection / sub-port writes through.
  #[inline(always)]
  pub const fn media_mut(&mut self) -> &mut MediaInfo {
    &mut self.media
  }

  /// Mutable access to the camera-identity domain.
  #[inline(always)]
  pub const fn camera_mut(&mut self) -> Option<&mut CameraInfo> {
    self.camera.as_mut()
  }

  /// Mutable access to the lens-identity domain.
  #[inline(always)]
  pub const fn lens_mut(&mut self) -> Option<&mut LensInfo> {
    self.lens.as_mut()
  }

  /// Mutable access to the GPS-location domain.
  #[inline(always)]
  pub const fn gps_mut(&mut self) -> Option<&mut GpsLocation> {
    self.gps.as_mut()
  }

  /// Mutable access to the capture-settings domain.
  #[inline(always)]
  pub const fn capture_mut(&mut self) -> Option<&mut CaptureSettings> {
    self.capture.as_mut()
  }

  /// Set the camera-identity domain to the present value.
  #[inline(always)]
  pub fn set_camera(&mut self, camera: CameraInfo) -> &mut Self {
    self.camera = Some(camera);
    self
  }

  /// Set the lens-identity domain to the present value.
  #[inline(always)]
  pub fn set_lens(&mut self, lens: LensInfo) -> &mut Self {
    self.lens = Some(lens);
    self
  }

  /// Set the GPS-location domain to the present value.
  #[inline(always)]
  pub fn set_gps(&mut self, gps: GpsLocation) -> &mut Self {
    self.gps = Some(gps);
    self
  }

  /// Set the capture-settings domain to the present value.
  #[inline(always)]
  pub fn set_capture(&mut self, capture: CaptureSettings) -> &mut Self {
    self.capture = Some(capture);
    self
  }

  /// Combine two projections into one, with `self` taking precedence.
  ///
  /// The merge is **field-by-field, not domain-by-domain**: for every leaf
  /// field, `self`'s `Some` value wins and `other` only fills the gaps
  /// where `self` is `None`. The always-present [`MediaInfo`] merges the
  /// same way ([`MediaInfo::merge`]); each optional domain
  /// ([`CameraInfo`] / [`LensInfo`] / [`GpsLocation`] / [`CaptureSettings`])
  /// is combined per-field when both sides carry it, or taken wholesale
  /// when only one does.
  ///
  /// This is the seam that lets a base projection (e.g. EXIF IFD0/ExifIFD)
  /// be enriched by a secondary, more-specific source (e.g. the vendor
  /// MakerNote) without either clobbering the other: the caller puts the
  /// higher-priority source on the left (`self`) and the fallback on the
  /// right (`other`).
  #[must_use]
  pub fn merge(self, other: Self) -> Self {
    Self {
      media: self.media.merge(other.media),
      camera: merge_opt(self.camera, other.camera, CameraInfo::merge),
      lens: merge_opt(self.lens, other.lens, LensInfo::merge),
      gps: merge_opt(self.gps, other.gps, GpsLocation::merge),
      capture: merge_opt(self.capture, other.capture, CaptureSettings::merge),
    }
  }
}

/// Combine two optional domains: when both are present, `merge` them
/// (`self`-field-wins, per the domain's own `merge`); when only one is
/// present, take it; when neither, `None`. The single helper every
/// optional [`MediaMetadata`] domain routes through so the
/// field-by-field precedence is uniform.
#[inline]
fn merge_opt<T>(lhs: Option<T>, rhs: Option<T>, merge: impl FnOnce(T, T) -> T) -> Option<T> {
  match (lhs, rhs) {
    (Some(a), Some(b)) => Some(merge(a, b)),
    (Some(a), None) => Some(a),
    (None, Some(b)) => Some(b),
    (None, None) => None,
  }
}

impl Default for MediaMetadata {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

/// Convert a duration in (possibly fractional) seconds to a
/// [`core::time::Duration`]. Non-finite or negative inputs (which only a
/// hostile/malformed file produces) yield `None` — `Duration` cannot
/// represent them.
fn duration_from_secs(secs: f64) -> Option<Duration> {
  if !secs.is_finite() || secs < 0.0 {
    return None;
  }
  Some(Duration::from_secs_f64(secs))
}

/// The display [`Orientation`] from the primary video track's tkhd
/// `MatrixStructure`, mirroring ExifTool's `CalcRotation` (QuickTime.pm:8797):
/// the FIRST `vide`-handler track, its matrix rotation via
/// [`get_rotation_angle`](crate::composite::convs::video::get_rotation_angle),
/// snapped to the nearest right angle and mapped into the rotation-only EXIF
/// subset. `None` when there is no video track, no/degenerate matrix, or the
/// angle is not (within rounding) one of `0`/`90`/`180`/`270`.
#[cfg(feature = "alloc")]
fn video_matrix_orientation(qt: &QuickTimeMeta) -> Option<Orientation> {
  let track = qt
    .tracks()
    .iter()
    .find(|t| t.handler().is_some_and(HandlerKind::is_video))?;
  let angle = crate::composite::convs::video::get_rotation_angle(track.matrix_structure()?)?;
  // `get_rotation_angle` already rounds to 3 decimals in [0, 360) and the
  // cardinal rotations land EXACTLY (0/90/180/270 — the rounding absorbs the
  // truncated-pi error; see its tests). Round to the nearest whole degree and
  // accept ONLY a cardinal right angle (a skewed / non-90° matrix ⇒ `None`).
  let degrees = (angle.round() as i64).rem_euclid(360);
  Orientation::from_video_degrees(u16::try_from(degrees).ok()?)
}

/// Without `alloc`, [`get_rotation_angle`] (which parses the matrix string) is
/// unavailable; a no-`alloc` build carries no orientation. (`from_quicktime`
/// itself is only reachable with `alloc` — `QuickTimeMeta` is alloc-backed —
/// so this arm exists purely to keep the module compiling under every feature
/// permutation.)
#[cfg(not(feature = "alloc"))]
fn video_matrix_orientation(_qt: &QuickTimeMeta) -> Option<Orientation> {
  None
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::metadata::MediaTrack;

  #[test]
  fn track_kind_projection_from_handler() {
    assert!(TrackKind::from_handler(&HandlerKind::Video).is_video());
    assert!(TrackKind::from_handler(&HandlerKind::Audio).is_audio());
    assert!(TrackKind::from_handler(&HandlerKind::Text).is_subtitle());
    assert!(TrackKind::from_handler(&HandlerKind::Metadata).is_metadata());
    let other = TrackKind::from_handler(&HandlerKind::from_code("camm"));
    assert!(other.is_other());
  }

  #[test]
  fn empty_aggregate_has_only_media() {
    let m = MediaMetadata::new();
    assert!(m.camera().is_none());
    assert!(m.lens().is_none());
    assert!(m.gps().is_none());
    assert!(m.capture().is_none());
    assert!(m.media().duration().is_none());
  }

  #[test]
  fn from_quicktime_populates_media_info_only() {
    let mut qt = QuickTimeMeta::new();
    qt.set_time_scale(Some(600));
    // R6/F1: mvhd Duration is stored as a RAW timescale-count; the
    // durationInfo divide (7500 / 600 = 12.5 s) is applied by
    // `duration_seconds()` against the final TimeScale.
    qt.set_duration_count(Some(7500));
    qt.set_create_date(Some("2024:01:02 03:04:05".to_string()));
    // A video track with dimensions.
    let mut video = MediaTrack::new();
    video.set_handler(HandlerKind::Video);
    video.set_image_width(Some(1920));
    video.set_image_height(Some(1080));
    qt.push_track(video);
    // An audio track (no dimensions).
    let mut audio = MediaTrack::new();
    audio.set_handler(HandlerKind::Audio);
    qt.push_track(audio);

    let projected = MediaMetadata::from_quicktime(&qt);
    let media = projected.media();
    assert_eq!(media.duration(), Some(Duration::from_secs_f64(12.5)));
    assert_eq!(media.width(), Some(1920));
    assert_eq!(media.height(), Some(1080));
    assert_eq!(media.created(), Some("2024:01:02 03:04:05"));
    assert!(media.has_video());
    assert!(media.has_audio());
    assert_eq!(media.track_kinds().len(), 2);
    // SP1: camera / lens / gps / capture stay None.
    assert!(projected.camera().is_none());
    assert!(projected.lens().is_none());
    assert!(projected.gps().is_none());
    assert!(projected.capture().is_none());
  }

  #[test]
  fn duration_from_secs_rejects_non_finite() {
    assert!(duration_from_secs(f64::NAN).is_none());
    assert!(duration_from_secs(-1.0).is_none());
    assert_eq!(duration_from_secs(0.0), Some(Duration::ZERO));
  }

  #[test]
  fn camera_lens_capture_setters_chain() {
    let mut m = MediaMetadata::new();
    let mut cam = CameraInfo::new();
    cam
      .update_make(Some("Apple".into()))
      .update_model(Some("iPhone".into()));
    m.set_camera(cam);
    assert_eq!(m.camera().expect("camera").make(), Some("Apple"));
    assert!(!m.camera().expect("camera").is_empty());
  }

  #[test]
  fn merge_self_some_wins_other_fills_gaps() {
    // `self`: make + model set, serial absent.
    let mut base_cam = CameraInfo::new();
    base_cam
      .update_make(Some("Canon".into()))
      .update_model(Some("EOS".into()));
    let mut base = MediaMetadata::new();
    base.set_camera(base_cam);

    // `other`: make DIFFERENT (must NOT win), serial present (fills the gap).
    let mut over_cam = CameraInfo::new();
    over_cam
      .update_make(Some("Nikon".into()))
      .update_serial(Some("SN-123".into()));
    let mut over = MediaMetadata::new();
    over.set_camera(over_cam);

    let merged = base.merge(over);
    let cam = merged.camera().expect("camera present");
    // self's Some wins on a conflicting field…
    assert_eq!(cam.make(), Some("Canon"));
    assert_eq!(cam.model(), Some("EOS"));
    // …and other fills the field self left None.
    assert_eq!(cam.serial(), Some("SN-123"));
  }

  #[test]
  fn merge_takes_domain_present_on_only_one_side() {
    // `self` carries only lens; `other` carries only gps. Neither is lost.
    let mut lens = LensInfo::new();
    lens.update_model(Some("EF 50mm".into()));
    let mut base = MediaMetadata::new();
    base.set_lens(lens);

    let mut gps = GpsLocation::new();
    gps.update_latitude(Some(48.5));
    let mut other = MediaMetadata::new();
    other.set_gps(gps);

    let merged = base.merge(other);
    assert_eq!(merged.lens().expect("lens").model(), Some("EF 50mm"));
    assert_eq!(merged.gps().expect("gps").latitude(), Some(48.5));
    // A domain absent on both stays absent.
    assert!(merged.capture().is_none());
  }

  #[test]
  fn merge_media_info_is_field_wise() {
    // self: width set, height absent; other: both set (height fills, width
    // does NOT overwrite).
    let mut base = MediaMetadata::new();
    base.media_mut().update_width(Some(1920));
    let mut other = MediaMetadata::new();
    other
      .media_mut()
      .update_width(Some(640))
      .update_height(Some(480));

    let merged = base.merge(other);
    assert_eq!(merged.media().width(), Some(1920)); // self wins
    assert_eq!(merged.media().height(), Some(480)); // other fills the gap
  }

  #[test]
  fn orientation_exif_value_to_degrees_and_mirror() {
    // The full EXIF 1-8 model → (clockwise degrees, mirrored) under the
    // MIRROR-FIRST contract (mirror, THEN rotate CW), the standard mapping
    // (TIFF 6.0 / EXIF 2.3) whose net transform reproduces ExifTool's
    // `Orientation` PrintConv label. NOTE 5 = (270, mirrored) and
    // 7 = (90, mirrored): the "rotate 270/90 CW" of their labels — NOT
    // swapped (the regression this guards).
    let cases = [
      (1, 0, false),   // Horizontal (normal)
      (2, 0, true),    // Mirror horizontal
      (3, 180, false), // Rotate 180
      (4, 180, true),  // Mirror vertical (mirror-h then 180)
      (5, 270, true),  // Mirror horizontal and rotate 270 CW (transpose)
      (6, 90, false),  // Rotate 90 CW
      (7, 90, true),   // Mirror horizontal and rotate 90 CW (transverse)
      (8, 270, false), // Rotate 270 CW
    ];
    for (exif, degrees, mirrored) in cases {
      let o = Orientation::from_exif_value(exif).expect("1-8 is a valid orientation");
      assert_eq!(o.exif_value(), exif);
      assert_eq!(o.rotation_degrees(), degrees, "degrees for EXIF {exif}");
      assert_eq!(o.mirrored(), mirrored, "mirrored for EXIF {exif}");
    }
  }

  /// Transform-composition proof: applying `mirrored()` + `rotation_degrees()`
  /// under the documented MIRROR-FIRST contract produces, for EACH reflected
  /// value (2/4/5/7), the SAME net pixel transform the ExifTool label names.
  /// In particular it pins 5 (transpose) ≠ 7 (transverse) — the swap finding.
  #[test]
  fn orientation_mirror_variants_compose_to_their_label() {
    // A corner-tracking model on a wider-than-tall image (W=4, H=2): map the
    // four stored corners through `flip_h` (mirror-first) then `rotate N CW`,
    // and compare against the corner map each label describes directly. We
    // tag corners TL/TR/BL/BR so a swap of 5↔7 is detectable (they send TL to
    // different places).
    const W: i32 = 4;
    const H: i32 = 2;
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct P {
      x: i32,
      y: i32,
    }
    /// A net pixel transform expressed as a corner map (a label's ground truth).
    type LabelFn = fn(P) -> P;
    let corners = [
      P { x: 0, y: 0 },         // TL
      P { x: W - 1, y: 0 },     // TR
      P { x: 0, y: H - 1 },     // BL
      P { x: W - 1, y: H - 1 }, // BR
    ];

    // The contract: mirror-h first (on the W×H stored image), then rotate CW.
    // `flip_h`: x -> W-1-x. `rot90cw` on a w×h image: (x,y) -> (h-1-y, x).
    // `rot180`: (x,y) -> (w-1-x, h-1-y). `rot270cw`: (x,y) -> (y, w-1-x).
    fn apply(p: P, mirrored: bool, degrees: u16) -> P {
      let P { mut x, y } = p;
      // After an optional horizontal mirror the working width stays W, height H.
      if mirrored {
        x = W - 1 - x;
      }
      let (w, h) = (W, H);
      match degrees {
        0 => P { x, y },
        90 => P { x: h - 1 - y, y: x },
        180 => P {
          x: w - 1 - x,
          y: h - 1 - y,
        },
        270 => P { x: y, y: w - 1 - x },
        d => panic!("unexpected rotation {d}"),
      }
    }

    // Ground-truth net transforms named by the label, expressed directly.
    fn mirror_h(p: P) -> P {
      P {
        x: W - 1 - p.x,
        y: p.y,
      }
    }
    fn mirror_v(p: P) -> P {
      P {
        x: p.x,
        y: H - 1 - p.y,
      }
    }
    fn transpose(p: P) -> P {
      P { x: p.y, y: p.x } // reflect across the main diagonal
    }
    fn transverse(p: P) -> P {
      // reflect across the anti-diagonal (on the W×H image)
      P {
        x: H - 1 - p.y,
        y: W - 1 - p.x,
      }
    }

    // (exif, label-transform) for every REFLECTED orientation.
    let label: [(u8, LabelFn); 4] = [
      (2, mirror_h),
      (4, mirror_v),
      (5, transpose),
      (7, transverse),
    ];
    for (exif, label_fn) in label {
      let o = Orientation::from_exif_value(exif).unwrap();
      for &c in &corners {
        assert_eq!(
          apply(c, o.mirrored(), o.rotation_degrees()),
          label_fn(c),
          "EXIF {exif}: mirror-first composition must equal its label transform at {c:?}"
        );
      }
    }

    // Explicitly assert 5 and 7 are NOT swapped: they send the same corner to
    // DIFFERENT places (transpose vs transverse), so a swap would be caught.
    let o5 = Orientation::from_exif_value(5).unwrap();
    let o7 = Orientation::from_exif_value(7).unwrap();
    assert_eq!(o5.rotation_degrees(), 270, "5 rotates 270 CW (transpose)");
    assert_eq!(o7.rotation_degrees(), 90, "7 rotates 90 CW (transverse)");
    let tl = corners[0];
    assert_ne!(
      apply(tl, o5.mirrored(), o5.rotation_degrees()),
      apply(tl, o7.mirrored(), o7.rotation_degrees()),
      "5 (transpose) and 7 (transverse) must NOT map TL identically"
    );
  }

  #[test]
  fn orientation_from_exif_value_rejects_out_of_range() {
    assert!(Orientation::from_exif_value(0).is_none());
    assert!(Orientation::from_exif_value(9).is_none());
    assert!(Orientation::from_exif_value(u8::MAX).is_none());
  }

  #[test]
  fn orientation_from_video_degrees_maps_rotation_subset() {
    // The four cardinal video matrix rotations → the un-mirrored EXIF subset.
    assert_eq!(
      Orientation::from_video_degrees(0).map(|o| o.exif_value()),
      Some(1)
    );
    assert_eq!(
      Orientation::from_video_degrees(90).map(|o| o.exif_value()),
      Some(6)
    );
    assert_eq!(
      Orientation::from_video_degrees(180).map(|o| o.exif_value()),
      Some(3)
    );
    assert_eq!(
      Orientation::from_video_degrees(270).map(|o| o.exif_value()),
      Some(8)
    );
    // A video rotation is never mirrored.
    for deg in [0, 90, 180, 270] {
      assert!(!Orientation::from_video_degrees(deg).unwrap().mirrored());
    }
    // A non-cardinal angle has no orientation.
    assert!(Orientation::from_video_degrees(45).is_none());
    assert!(Orientation::from_video_degrees(360).is_none());
  }

  #[test]
  fn from_quicktime_projects_video_matrix_orientation() {
    let mut qt = QuickTimeMeta::new();
    // A video track with a 90° CW display matrix (`[0 1; -1 0]` ⇒ atan2(1,0)).
    let mut video = MediaTrack::new();
    video.set_handler(HandlerKind::Video);
    video.set_image_width(Some(1920));
    video.set_image_height(Some(1080));
    video.set_matrix_structure(Some("0 1 0 -1 0 0 0 0 1".to_string()));
    qt.push_track(video);

    let projected = MediaMetadata::from_quicktime(&qt);
    let o = projected
      .media()
      .orientation()
      .expect("the video matrix encodes a 90° rotation");
    assert_eq!(o.rotation_degrees(), 90);
    assert_eq!(o.exif_value(), 6); // Rotate 90 CW
    assert!(!o.mirrored());
  }

  #[test]
  fn from_quicktime_no_matrix_is_no_orientation() {
    // A video track with no MatrixStructure ⇒ no orientation (not the
    // default 1). A degenerate all-zero matrix is likewise `None`.
    let mut qt = QuickTimeMeta::new();
    let mut video = MediaTrack::new();
    video.set_handler(HandlerKind::Video);
    qt.push_track(video);
    assert!(
      MediaMetadata::from_quicktime(&qt)
        .media()
        .orientation()
        .is_none()
    );

    let mut qt2 = QuickTimeMeta::new();
    let mut v2 = MediaTrack::new();
    v2.set_handler(HandlerKind::Video);
    v2.set_matrix_structure(Some("0 0 0 0 0 0 0 0 0".to_string()));
    qt2.push_track(v2);
    assert!(
      MediaMetadata::from_quicktime(&qt2)
        .media()
        .orientation()
        .is_none()
    );
  }

  #[test]
  fn from_quicktime_identity_matrix_is_orientation_1() {
    // The identity matrix ⇒ 0° ⇒ EXIF 1 (Horizontal/normal), NOT `None`.
    let mut qt = QuickTimeMeta::new();
    let mut video = MediaTrack::new();
    video.set_handler(HandlerKind::Video);
    video.set_matrix_structure(Some("1 0 0 0 1 0 0 0 1".to_string()));
    qt.push_track(video);
    let o = MediaMetadata::from_quicktime(&qt)
      .media()
      .orientation()
      .expect("identity ⇒ orientation 1");
    assert_eq!(o.exif_value(), 1);
    assert_eq!(o.rotation_degrees(), 0);
  }

  #[test]
  fn media_info_orientation_merge_self_wins_other_fills() {
    // self has orientation, other a different one ⇒ self wins.
    let mut base = MediaInfo::new();
    base.update_orientation(Orientation::from_exif_value(6));
    let mut other = MediaInfo::new();
    other.update_orientation(Orientation::from_exif_value(3));
    let merged = base.merge(other);
    assert_eq!(merged.orientation().map(|o| o.exif_value()), Some(6));

    // self None, other Some ⇒ other fills the gap.
    let base2 = MediaInfo::new();
    let mut other2 = MediaInfo::new();
    other2.update_orientation(Orientation::from_exif_value(8));
    assert_eq!(
      base2.merge(other2).orientation().map(|o| o.exif_value()),
      Some(8)
    );
  }
}
