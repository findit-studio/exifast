//! Per-format parser modules. Each `pub mod <fmt>;` is gated on its Cargo
//! feature (spec §4). The runtime ExifTool-file-type → parser registry is
//! [`crate::format_parser::any_parser_for`] (returning a closed-set
//! [`crate::format_parser::AnyParser`]); the engine entry
//! [`crate::parser::extract_info`] dispatches through it. When a format
//! feature is disabled, its file-type string returns `None` (faithful to
//! ExifTool's "Process<Type> not loaded → `next` in candidate loop" —
//! ExifTool.pm:3060-3077).

#[cfg(feature = "aac")]
pub mod aac;
#[cfg(feature = "aiff")]
pub mod aiff;
#[cfg(feature = "ape")]
pub mod ape;
#[cfg(feature = "audible")]
pub mod audible;
#[cfg(feature = "dsf")]
pub mod dsf;
#[cfg(feature = "dv")]
pub mod dv;
#[cfg(feature = "flac")]
pub mod flac;
#[cfg(feature = "id3")]
pub mod id3;
#[cfg(feature = "matroska")]
pub mod matroska;
#[cfg(feature = "moi")]
pub mod moi;
#[cfg(feature = "mpc")]
pub mod mpc;
// MPEG audio frame parser is the internal `mpeg-audio` feature (gates
// `mp3` and is reused by other audio chained formats). Phase D may split
// `mpeg::audio` from a future `mpeg::video` submodule; today the file
// holds only the audio half (the video side is a Phase-2 forward item).
#[cfg(feature = "mpeg-audio")]
pub mod mpeg;
#[cfg(feature = "ogg")]
pub mod ogg;
#[cfg(feature = "real")]
pub mod real;
#[cfg(feature = "red")]
pub mod red;
#[cfg(feature = "wavpack")]
pub mod wavpack;
#[cfg(feature = "xmp")]
pub mod xmp;
