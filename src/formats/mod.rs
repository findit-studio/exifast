//! Per-format parser modules. Each `pub mod <fmt>;` is gated on its Cargo
//! feature (spec §4). The runtime ExifTool-file-type → parser registry is
//! [`crate::format_parser::any_parser_for`] (returning a closed-set
//! [`crate::format_parser::AnyParser`]); the engine entry
//! [`crate::parser::extract_info`] dispatches through it. When a format
//! feature is disabled, its file-type string returns `None` (faithful to
//! ExifTool's "Process<Type> not loaded → `next` in candidate loop" —
//! ExifTool.pm:3060-3077).

// Golden-v2 Contract 3c (Phase C): parser-panic-safety by construction. This
// inner attribute CASCADES into every `pub mod <fmt>;` submodule below, so a
// newly added parser is checked even if it forgets its own file-level deny —
// it cannot silently ship raw `buf[i]` indexing on input bytes. Per-file
// `#![deny(...)]` stays on each leaf for local visibility; test modules opt
// out locally with `#[allow(clippy::indexing_slicing)]`.
#![deny(clippy::indexing_slicing)]

#[cfg(feature = "aac")]
pub mod aac;
#[cfg(feature = "aiff")]
pub mod aiff;
#[cfg(feature = "ape")]
pub mod ape;
#[cfg(feature = "audible")]
pub mod audible;
#[cfg(feature = "crw")]
pub mod crw;
#[cfg(feature = "dsf")]
pub mod dsf;
#[cfg(feature = "dv")]
pub mod dv;
#[cfg(feature = "flac")]
pub mod flac;
#[cfg(feature = "flash")]
pub mod flash;
// H264 is engine-only (FORMATS.md row 16 — no `H264` file type); the
// typed parser is consumed by a future M2TS / MPEG port.
#[cfg(feature = "h264")]
pub mod h264;
#[cfg(feature = "id3")]
pub mod id3;
// M2TS (MPEG-2 Transport Stream / AVCHD camcorder container, FORMATS.md
// row 25 / 26). Depends on `h264` for the PES-payload H.264 demux that
// AVCHD-encoded video carries (`H264::ParseH264Video`, M2TS.pm:343-345).
#[cfg(feature = "m2ts")]
pub mod m2ts;
#[cfg(feature = "matroska")]
pub mod matroska;
#[cfg(feature = "moi")]
pub mod moi;
#[cfg(feature = "mpc")]
pub mod mpc;
#[cfg(feature = "mxf")]
pub mod mxf;
// MPEG audio frame parser is the internal `mpeg-audio` feature (gates
// `mp3` and is reused by other audio chained formats). Phase D may split
// `mpeg::audio` from a future `mpeg::video` submodule; today the file
// holds only the audio half (the video side is a Phase-2 forward item).
#[cfg(feature = "mpeg-audio")]
pub mod mpeg;
#[cfg(feature = "ogg")]
pub mod ogg;
// PLIST — engine-only per FORMATS.md row 12b. Leaf format (no cross-format
// chains); ports both the binary (`bplist0…`) and XML plist encodings.
#[cfg(feature = "plist")]
pub mod plist;
#[cfg(feature = "png")]
pub mod png;
#[cfg(feature = "quicktime")]
pub mod quicktime;
// QuickTime SP3 — embedded timed GPS metadata (QuickTimeStream.pl). A
// sub-module of the QuickTime port; gated on the same `quicktime` feature.
#[cfg(feature = "quicktime")]
pub mod quicktime_stream;
// QuickTime SP3.5 — ProcessFreeGPS + brute-force scan (QuickTimeStream.pl
// :1637-2484, :3679-3789). Self-contained camera-variant decoders; vendor-
// module dispatches (Sony rtmd, Canon CTMD, LigoGPS, full camm) are
// stubbed; GoPro GPMF wires through to [`gopro`] (SP4).
#[cfg(feature = "quicktime")]
pub mod quicktime_freegps;
// GoPro SP4 — GPMF KLV parser + the GPS family of GoPro.pm tag tables.
// Reached either via the QuickTime ProcessFreeGPS brute-force scan (GoPro
// `GP\x06\0\0` records in `mdat`) or via the `gpmd` timed-metadata sample
// dispatch (`Image::ExifTool::GoPro::GPMF` SubDirectory). Gated on the
// `quicktime` feature — there is no separate GoPro file type, GoPro
// metadata is always reached through a QuickTime container.
#[cfg(feature = "quicktime")]
pub mod gopro;
// Android CAMM — Google Camera Motion Metadata. Faithful port of
// `Image::ExifTool::QuickTime::ProcessCAMM` (QuickTimeStream.pl:3481-3506) +
// the seven `%QuickTime::camm0..camm7` tag tables (QuickTimeStream.pl:405-
// 572). Reached through the `camm` MetaFormat dispatch in
// [`quicktime_stream`]. Gated on the `quicktime` feature.
#[cfg(feature = "quicktime")]
pub mod android_camm;
#[cfg(feature = "real")]
pub mod real;
#[cfg(feature = "red")]
pub mod red;
#[cfg(feature = "riff")]
pub mod riff;
#[cfg(feature = "quicktime")]
pub mod sony_rtmd;
#[cfg(feature = "wavpack")]
pub mod wavpack;
#[cfg(feature = "xmp")]
pub mod xmp;
