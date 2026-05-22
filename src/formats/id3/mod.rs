// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "id3")]
//! Faithful port of `Image::ExifTool::ID3` (lib/Image/ExifTool/ID3.pm).
//!
//! Implements ID3v1, ID3v2.2/2.3/2.4 plus the MP3 wrapper (`ProcessMP3` at
//! ID3.pm:1684-1728) via the typed [`Id3Meta<'a>`] / [`Mp3Meta<'a>`]
//! published through the [`crate::format_parser::FormatParser`] trait. The MP3
//! engine entry ([`ProcessMp3::process`]) drives
//! the typed `serialize_tags` path into the engine
//! `tagmap::TagMap` so the serialized JSON stays
//! byte-exact for all 60+ ID3/MP3 conformance fixtures.
//!
//! Per FORMATS.md row 2 (ID3 infra + MP3 completion) this module
//! implements:
//! - ID3v1 (ID3.pm:335-378) — full %v1 binary table + ProcessID3v1.
//! - ID3v2.2/.3/.4 (ID3.pm:428-718) + %id3v2_common — all common
//!   frame types in ProcessID3v2 (ID3.pm:1111-1423).
//! - ProcessID3 (ID3.pm:1431-1632) — directory entry; ID3v2 header
//!   detection at start, ID3v1 trailer detection at end.
//! - ProcessMP3 dispatch (ID3.pm:1684-1728) + minimal MPEG audio
//!   sync gate for file-type acceptance (MPEG:* extraction defers to
//!   MPEG.pm row 17).
//!
//! **F4 (Codex adversarial — implemented):**
//! - ID3v1 "Enhanced TAG" 227-byte trailer (ID3.pm:1521-1525, processed
//!   per ID3.pm:1618-1626). The 7 `ID3v1_Enh:*` fields are now extracted
//!   via [`v1_enh::process_id3v1_enh`] and staged alongside the standard
//!   v1 fields, mirroring bundled.
//!
//! **Out-of-PR-scope (Codex R9-F1 — faithful forward items):**
//! - Lyrics3 v1/v2 trailer (ID3.pm:1532-1576). NO fixture in scope;
//!   processing deferred.
//! - The ID3.pm:1582-1601 audio-format loop (ID3-prefixed APE/MPC/FLAC/
//!   OGG body in an .mp3 dispatch). Per Codex R6 finding tracked in
//!   `docs/tracking.md` — keep the deferral; vanishingly rare in the
//!   wild, Case A "ID3+no-MPEG+APE-trailer" is path-equivalent via the
//!   `ProcessMp3` wrapper APE fallback (ID3.pm:1722-1727), Case B
//!   "ID3+APE-body-in-.mp3" not exercised by any known fixture.
//! - MPEG audio-frame parsing (`ParseMPEGAudio`, MPEG.pm:464-494) —
//!   FORMATS.md row 17. ProcessMP3 ports ONLY the sync gate; MPEG:*
//!   tag extraction defers to that PR.
//! - APE trailer (`ProcessAPE`, ID3.pm:1722-1727) — FORMATS.md row 5.
//! - SubDirectory frames `GEOB`/`SYLT` (ID3.pm:547-571) — faithful
//!   "Don't know how to handle" Warn until `ProcessGEOB` /
//!   `ProcessSynText` land. `PRIV` is handled inline (owner-id-derived
//!   tag name + raw bytes).
//!
//! Internal layout:
//! - [`genre`] — `%genre` (ID3.pm:131-332).
//! - [`picture_type`] — `%pictureType` (ID3.pm:42-64).
//! - [`text`] — text-handling helpers (`ConvertID3v1Text`, `PrintGenre`,
//!   POP/POPM PrintConv, `MakeTagName`, TLEN ValueConv/PrintConv).
//! - [`decode`] — `DecodeString` (ID3.pm:1054-1092) + `UnSyncSafe`
//!   (ID3.pm:1098-1106).
//! - [`v1`] — `%Image::ExifTool::ID3::v1` (ID3.pm:335-378) + ProcessID3v1.
//! - [`v1_enh`] — `%Image::ExifTool::ID3::v1_Enh` (ID3.pm:380-425) +
//!   ProcessID3v1Enh (the 227-byte "Enhanced TAG" trailer, F4 fix).
//! - [`v2_2`] / [`v2_3`] / [`v2_4`] — version-specific tag tables.
//! - [`v2_process`] — `ProcessID3v2` (ID3.pm:1111-1423).
//! - [`process`] — `ProcessID3` (ID3.pm:1431-1632) + `ProcessMp3`
//!   (ID3.pm:1684-1728) + the typed [`Id3Meta`]/[`Mp3Meta`] types and
//!   their [`crate::format_parser::FormatParser`] / `serialize_tags`
//!   impls.

pub mod decode;
pub mod genre;
pub mod picture_type;
pub mod process;
pub mod text;
pub mod v1;
pub mod v1_enh;
pub mod v2_2;
pub mod v2_3;
pub mod v2_4;
pub mod v2_common;
pub mod v2_process;

pub use process::{
  Id3Context, Id3Error, Id3Meta, Id3Picture, Id3v1Meta, Id3v2Frame, Id3v2Version, ProcessId3,
  parse_id3_borrowed, parse_id3v1_from_block,
};

// MP3 wrapper re-exports (Codex A-R2-1) — gated behind `mp3`, which pulls
// `mpeg-audio` + `ape`. The plain `id3` feature (pulled by flac/aiff/dsf/ape
// for the ID3-prefix chain) does NOT compile these.
#[cfg(feature = "mp3")]
pub use process::{Mp3Context, Mp3Error, Mp3Meta, ProcessMp3, parse_mp3_borrowed};
