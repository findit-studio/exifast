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
// MISB (STANAG-4609 KLV) timed metadata in M2TS `0x15` packetized-metadata
// streams; a sub-module of the M2TS port (MISB.pm → M2TS.pm:355-364).
#[cfg(feature = "matroska")]
pub mod matroska;
#[cfg(feature = "m2ts")]
pub mod misb;
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
// OLE compound-document (Windows Compound Binary File) decoder for the PNG
// `cpIp` chunk → FlashPix `ProcessFPX` (#142). Gated with `png` (its sole user).
#[cfg(feature = "png")]
pub mod ole;
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
// QuickTime SP4 — brand-variant container dispatch (HEIC/AVIF/CR3/JP2/
// iso5/hvc1). Faithful port of:
//  - %ftypLookup brand table (QuickTime.pm:130-237) + %mimeLookup
//    (QuickTime.pm:103-126).
//  - HEIF/HEIC/AVIF `meta` box walker — iinf/iloc/ipma/ipco/iref/pitm
//    (QuickTime.pm:2834-2916 + 9131-9523).
//  - CR3 / CRM Canon UUID atom dispatch (QuickTime.pm:1236-1242 +
//    Canon.pm:9657-9738) — CNCV CompressorVersion override + CMT1-4
//    location records.
//  - JP2 / JPX / JPM box walker (Jpeg2000.pm:1538-1597 + UUID-Exif/XMP
//    at :279-352).
//
// Each variant produces a typed `HeifMeta` / `Cr3Meta` / `Jp2Meta`
// (in [`crate::metadata`]) that the QuickTime walker carries through
// to the per-variant `MetaProjectInto` projection. Gated on the same
// `quicktime` feature.
#[cfg(feature = "quicktime")]
pub mod quicktime_brands;
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
// DJI Protobuf — `djmd` / `dbgi` timed-metadata walker. Faithful port of
// `Image::ExifTool::Protobuf::ProcessProtobuf` (Protobuf.pm:128-300) driven
// by the `%Image::ExifTool::DJI::Protobuf` tag table (DJI.pm:235-859) and its
// nested message tables (DJI::FrameInfo / GPSInfo / DroneInfo / GimbalInfo,
// DJI.pm:867-921). Reached through the `djmd` + `dbgi` MetaFormat dispatch in
// [`quicktime_stream`] (QuickTimeStream.pl:349-358 routes both SubDirectories
// into `Image::ExifTool::DJI::Protobuf`). Surfaces drone / handheld-cam GNSS
// + camera settings + orientation for Mavic 3/3 Pro/4 Pro, Air 3/3s, Mini 4
// Pro/5 Pro, Avata 2, Neo, Matrice 30/4E, Osmo Action 4/5/6, Pocket 3, Osmo
// 360. Gated on the `quicktime` feature.
#[cfg(feature = "quicktime")]
pub mod dji_protobuf;
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
// LigoGPS — dashcam vendor GPS module. Faithful port of
// `Image::ExifTool::LigoGPS` (LigoGPS.pm:1-431). Reached via TWO paths:
//   (a) the `&&&& `-prefixed trailer at file EOF (QuickTime.pm:9906-9907
//       + 10658-10668) — `IdentifyTrailers` matches `/\&\&\&\&(.{4})$/`
//       at EOF-40, the trailer body begins `[size:u32-BE][skip]
//       [LIGOGPSINFO\0...]`.
//   (b) the freeGPS-embedded sample dispatch (QuickTimeStream.pl
//       :1843-1888) — `LIGOGPSINFO\0` at offset 16/48/80 inside a
//       freeGPS block. Wired through `quicktime_freegps::process_free_gps`.
// Records are fixed-stride 0x84 bytes, either `####`-prefixed encrypted
// (LigoGPS.pm:50-99 DecryptLigoGPS) or plain-ASCII (Redtiger F9 4K).
// JSON variant (LigoGPS.pm:334-398 ProcessLigoJSON) handles Yada
// RoadCam Pro 4K BT58189. Gated on the `quicktime` feature.
#[cfg(feature = "quicktime")]
pub mod ligogps;
// Parrot mett — drone timed-metadata walker. Faithful port of
// `Image::ExifTool::Parrot::Process_mett` (Parrot.pm:791-854) +
// the per-version binary tables `Image::ExifTool::Parrot::V1`/`V2`/
// `V3`/`TimeStamp`/`FollowMe`/`Automation` (Parrot.pm:86-660).
// Reached through the `mett` MetaFormat dispatch in [`quicktime_stream`]
// (QuickTimeStream.pl:312-315 routes `mett` SubDirectory → Parrot::mett).
// Surfaces drone GPS + flight telemetry for Anafi / Anafi USA / Anafi
// Ai / Anafi Thermal / Bebop / Bebop 2 / Disco bodies. Gated on the
// `quicktime` feature.
#[cfg(feature = "quicktime")]
pub mod parrot;
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
