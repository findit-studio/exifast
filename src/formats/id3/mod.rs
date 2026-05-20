//! Faithful port of `Image::ExifTool::ID3` (lib/Image/ExifTool/ID3.pm).
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
//! **Out-of-PR-scope (Codex R9-F1 — faithful forward items):**
//! - ID3v1 "Enhanced TAG" 227-byte trailer (ID3.pm:1521-1525). NO
//!   fixture in scope; processing deferred until a real bundled-oracle
//!   sample is captured.
//! - Lyrics3 v1/v2 trailer (ID3.pm:1532-1576). Same: NO fixture in
//!   scope; processing deferred.
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
//! - [`v2_2`] / [`v2_3`] / [`v2_4`] — version-specific tag tables.
//! - [`v2_process`] — `ProcessID3v2` (ID3.pm:1111-1423).
//! - [`process`] — `ProcessID3` (ID3.pm:1431-1632) + `ProcessMp3`
//!   (ID3.pm:1684-1728) + `FormatParser` impls.

pub mod decode;
pub mod genre;
pub mod picture_type;
pub mod process;
pub mod text;
pub mod v1;
pub mod v2_2;
pub mod v2_3;
pub mod v2_4;
pub mod v2_common;
pub mod v2_process;

pub use process::ProcessMp3;
