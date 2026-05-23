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
#[cfg(feature = "flash")]
pub mod flash;
// H264 is engine-only (FORMATS.md row 16 — no `H264` file type); the
// typed parser is consumed by a future M2TS / MPEG port.
#[cfg(feature = "h264")]
pub mod h264;
#[cfg(feature = "id3")]
pub mod id3;
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
// Canon CTMD — Canon Timed MetaData timed records in Canon EOS R-line /
// Cinema-line CR3 / CRM / MP4 / MOV containers. Faithful port of
// `Image::ExifTool::Canon::ProcessCTMD` (Canon.pm:10758-10804) + the
// `Image::ExifTool::Canon::CTMD` / `FocalInfo` / `ExposureInfo` tag tables
// (Canon.pm:9790-9887). Reached through the `CTMD` MetaFormat dispatch in
// [`quicktime_stream`]. Gated on the `quicktime` feature.
#[cfg(feature = "quicktime")]
pub mod canon_ctmd;
// Insta360 — INSV/INSP trailer walker. Faithful port of
// `Image::ExifTool::QuickTimeStream::ProcessInsta360`
// (QuickTimeStream.pl:3252-3478) + the `%insvDataLen` length catalogue
// (QuickTimeStream.pl:85-99) and the `INSV_MakerNotes` identity table
// (QuickTimeStream.pl:696-707). Located at file EOF by the magic ASCII
// hex string `8db42d694ccc418790edff439fe026bf`. Reached via a direct
// file-end pass in `quicktime::parse_inner` (no metadata-track dispatch
// — Insta360 is a trailer, not a `gpmd`/`camm`/`CTMD`-style track).
// Gated on the `quicktime` feature.
#[cfg(feature = "quicktime")]
pub mod insta360;
// Sony rtmd — Real-Time MetaData timed records in Sony Alpha A7/A9/FX/
// RX/Cinema-line MP4/MOV recorders. Faithful port of
// `Image::ExifTool::Sony::Process_rtmd` (Sony.pm:11566-11602) + the
// `Image::ExifTool::Sony::rtmd` tag table (Sony.pm:10686-10850). Reached
// through the `rtmd` MetaFormat dispatch in [`quicktime_stream`]. Gated
// on the `quicktime` feature.
#[cfg(feature = "real")]
pub mod real;
#[cfg(feature = "red")]
pub mod red;
#[cfg(feature = "quicktime")]
pub mod sony_rtmd;
#[cfg(feature = "wavpack")]
pub mod wavpack;
