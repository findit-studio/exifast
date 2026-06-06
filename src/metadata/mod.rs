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
mod canon_ctmd;
#[cfg(feature = "crw")]
pub(crate) mod crw;
mod domain;
mod gopro;
#[cfg(feature = "png")]
pub(crate) mod png;
pub mod project;
mod quicktime;
mod quicktime_stream;
mod sony_rtmd;
mod timed_sample;
// RIFF / AVI domain projection (`impl Project for RiffMeta`). Gated on the
// `riff` feature; the module holds only the trait impl (no public items to
// re-export).
#[cfg(feature = "riff")]
pub(crate) mod riff;

pub use android_camm::{
  CammAngleAxis, CammExposure, CammGpsSample, CammMeta, CammTimingOnly, CammVector3, CammWarning,
};
pub use canon_ctmd::{
  CanonCtmdExposure, CanonCtmdFocal, CanonCtmdMeta, CanonCtmdSample, CanonCtmdWarning,
  CtmdExifInfo, CtmdExifTag,
};
#[cfg(feature = "crw")]
pub use crw::{
  CrwDecoderTable, CrwExposureInfo, CrwFlashInfo, CrwImageInfo, CrwMeta, CrwRawArray,
  CrwRawJpgInfo, CrwSubTable, CrwSubTableBlock, CrwTimeStamp, CrwWhiteSample,
};
pub use domain::{
  CameraInfo, CaptureSettings, GpsLocation, LensInfo, MediaInfo, MediaMetadata, TrackKind,
};
pub use gopro::{
  GoProConv, GoProGlpiSample, GoProGpsSample, GoProKbat, GoProMeta, GoProTag, GoProTagValue,
};
#[cfg(feature = "png")]
pub use png::{
  PngColorType, PngDynamicProfileTag, PngExifEvent, PngMeta, PngTextKind, PngTextRecord,
};
pub use project::Project;
pub use quicktime::{
  HandlerKind, KodakFrea, MediaTrack, QuickTimeGps, QuickTimeKeys, QuickTimeMeta, QuickTimeUserData,
};
pub(crate) use quicktime_stream::GpsOrigin;
pub use quicktime_stream::{GpsSample, MebxSample, QuickTimeStreamMeta};
pub use sony_rtmd::{
  NumericRead, SonyRtmdCameraSnapshot, SonyRtmdCoord, SonyRtmdGpsSample, SonyRtmdMeta,
  SonyRtmdSample,
};
pub(crate) use timed_sample::TimedSample;
