//! Typed metadata layer.
//!
//! Two tiers live here:
//!
//! 1. **Faithful per-format parse structs** — e.g. [`QuickTimeMeta`]: a 1:1
//!    typed mirror of what a format parser decodes from the file. These
//!    follow the exact field shape of the source format (ExifTool's atom
//!    tables, in QuickTime's case).
//!
//! 2. **The normalized domain layer** — [`MediaMetadata`] and its component
//!    domains ([`CameraInfo`], [`LensInfo`], [`GpsLocation`],
//!    [`CaptureSettings`], [`MediaInfo`]). This is a PROJECTION: a
//!    well-structured, format-agnostic view callers consume regardless of
//!    which container the file used. The per-format `XxxMeta` stays the
//!    faithful parse layer; [`MediaMetadata::from_quicktime`] (and future
//!    `from_*` entry points) build the projection.
//!
//! SP1 of the QuickTime port populates only the [`MediaInfo`] basics it can
//! decode from the core structural atoms (duration, dimensions, created
//! time, track kinds). The camera / lens / GPS / capture domains are left
//! `None` for later sub-ports and other formats to fill — the layer is
//! deliberately extensible.

mod android_camm;
mod domain;
mod gopro;
mod quicktime;
mod quicktime_stream;
mod sony_rtmd;

pub use android_camm::{CammAngleAxis, CammExposure, CammGpsSample, CammMeta, CammVector3};
pub use domain::{
  CameraInfo, CaptureSettings, GpsLocation, LensInfo, MediaInfo, MediaMetadata, MetaProjectInto,
};
pub use gopro::{GoProGpsSample, GoProMeta};
pub use quicktime::{HandlerKind, MediaTrack, QuickTimeMeta};
pub use quicktime_stream::{GpsSample, MebxSample, QuickTimeStreamMeta};
pub use sony_rtmd::{SonyRtmdCameraSnapshot, SonyRtmdGpsSample, SonyRtmdMeta};
