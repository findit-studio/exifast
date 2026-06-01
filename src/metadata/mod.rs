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

#[cfg(feature = "crw")]
pub(crate) mod crw;
mod domain;
#[cfg(feature = "png")]
pub(crate) mod png;
pub mod project;
mod quicktime;

#[cfg(feature = "crw")]
pub use crw::{
  CrwDecoderTable, CrwImageInfo, CrwMeta, CrwRawJpgInfo, CrwSubTable, CrwSubTableBlock,
  CrwTimeStamp,
};
pub use domain::{
  CameraInfo, CaptureSettings, GpsLocation, LensInfo, MediaInfo, MediaMetadata, TrackKind,
};
#[cfg(feature = "png")]
pub use png::{
  PngColorType, PngDynamicProfileTag, PngExifEvent, PngMeta, PngTextKind, PngTextRecord,
};
pub use project::Project;
pub use quicktime::{HandlerKind, MediaTrack, QuickTimeMeta};
