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

use smol_str::SmolStr;

use crate::metadata::{HandlerKind, QuickTimeMeta};

extern crate alloc;
use alloc::vec::Vec;

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
}

impl Default for CaptureSettings {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
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

  /// Mutable access to the track-kind list (grow / shrink).
  #[inline(always)]
  pub const fn track_kinds_mut(&mut self) -> &mut Vec<TrackKind> {
    &mut self.track_kinds
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
  /// Per-port warnings surfaced during projection — each entry is prefixed
  /// by the originating port (e.g. `"[Sony rtmd] Truncated Sony rtmd"`).
  /// Mirrors bundled ExifTool's single `Warning` channel; the [`MetaProjectInto`]
  /// trait is the seam each port writes through.
  warnings: Vec<SmolStr>,
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
      warnings: Vec::new(),
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

    Self {
      media,
      // SP2-SP4 / other formats fill these.
      camera: None,
      lens: None,
      gps: None,
      capture: None,
      warnings: Vec::new(),
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

  /// Per-port warnings surfaced during projection.
  ///
  /// Each entry is a port-prefixed string like
  /// `"[Sony rtmd] Truncated Sony rtmd"`, mirroring bundled ExifTool's
  /// single `Warning` channel. A port's [`MetaProjectInto`] impl appends
  /// its own warnings here.
  #[inline(always)]
  #[must_use]
  pub fn warnings(&self) -> &[SmolStr] {
    &self.warnings
  }

  /// Append a port-prefixed warning. Callers (port-specific
  /// [`MetaProjectInto`] impls) prefix the message with `"[<port>] "`.
  #[inline(always)]
  pub fn push_warning(&mut self, w: impl Into<SmolStr>) -> &mut Self {
    self.warnings.push(w.into());
    self
  }
}

impl Default for MediaMetadata {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

// ===========================================================================
// MetaProjectInto — the per-port projection seam
// ===========================================================================

/// The seam each per-format `XxxMeta` implements to project into the
/// aggregate [`MediaMetadata`].
///
/// Splits the format-specific projection logic out of the host parser's
/// `media_metadata()` constructor: each port owns its own `project_into`
/// impl beside its `XxxMeta` struct, and the host calls them in priority
/// order. The order encodes the cross-format GPS / camera-identity /
/// capture-settings priority chain — earlier ports win when a later port
/// would fill an already-set domain (each impl is expected to no-op when
/// the domain it would write is already populated).
///
/// This is a Rust-side organizational seam — there is no Perl equivalent
/// (ExifTool flattens every decoder into a shared tag soup). Each format
/// port wires its impl up at the branch where the port lands.
pub trait MetaProjectInto {
  /// Project this format-specific metadata into `md`. Each impl is
  /// expected to:
  ///
  ///  - skip a domain (Camera/Lens/GPS/Capture) when `md` already has it
  ///    set (priority-chain semantics);
  ///  - prefix any pushed warning with `"[<port>] "`.
  fn project_into(&self, md: &mut MediaMetadata);
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
  fn warnings_channel_starts_empty_and_appends_in_order() {
    let mut m = MediaMetadata::new();
    assert!(m.warnings().is_empty());
    m.push_warning("[Sony rtmd] Truncated Sony rtmd");
    m.push_warning("[Canon CTMD] Short CTMD record");
    assert_eq!(m.warnings().len(), 2);
    assert_eq!(m.warnings()[0], "[Sony rtmd] Truncated Sony rtmd");
    assert_eq!(m.warnings()[1], "[Canon CTMD] Short CTMD record");
  }

  #[test]
  fn project_into_seam_is_a_trait_with_one_required_method() {
    // Anchor test: every per-port `XxxMeta` impl must populate `md` via
    // this single seam. Branches above SP3 wire their concrete impls.
    struct Noop;
    impl MetaProjectInto for Noop {
      fn project_into(&self, _md: &mut MediaMetadata) {}
    }
    let mut m = MediaMetadata::new();
    Noop.project_into(&mut m);
    assert!(m.warnings().is_empty());
  }
}
