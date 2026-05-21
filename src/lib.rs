// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.
//! `exifast`: a faithful Rust port of ExifTool's metadata reader.
//!
//! Stage 1 scope: video/audio formats, read-only. Per-format port status
//! is tracked in `FORMATS.md` at the repository root.
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

// Alias `alloc as std` on no_std + alloc builds so code can use
// `std::vec::Vec` etc. uniformly across feature combos. When the
// `std` feature is on, the real `std` crate is already in scope via
// the prelude. The `unused_extern_crates` allow silences a
// rust-2018-idioms false positive — the alias is needed at use-time
// even though rustc can't see that statically.
#[cfg(all(not(feature = "std"), feature = "alloc"))]
#[allow(unused_extern_crates)]
extern crate alloc as std;

#[cfg(feature = "std")]
#[allow(unused_extern_crates)]
extern crate std;

pub mod bitstream;
pub mod charset;
pub mod convert;
pub mod datetime;
pub mod error;
pub mod filetype;
pub mod formats;
// `jsondiff` and `serialize` are the JSON emitter + golden-diff oracle: they
// unconditionally depend on `serde_json` (and `serde`). They are gated on
// the `json` feature (spec §4: `json = ["alloc", "dep:serde_json", "dep:serde", ...]`).
// Library callers without `json` get the typed-Meta API path only; CLI
// JSON emission requires the feature.
// `json_scalar` builds the per-scalar JSON lexemes by hand (no `serde_json`),
// so it needs only `alloc` (String/format!), NOT the serde-pulling `json`
// feature. Gated on `alloc` because [`json_writer`] — the engine's mandatory
// `$$et` value sink after task #124 — depends on it, and the engine
// (parser + format modules) is always compiled.
#[cfg(feature = "alloc")]
pub mod json_scalar;
// The direct typed-Meta → JSON `TagWriter` and the engine's `$$et` value sink
// (task #124). Reuses the byte-exact scalar encoders in [`json_scalar`] so it
// is byte-identical to the `Metadata`→JSON `serialize` path. Builds its JSON
// string directly (no `serde_json`), so it is gated on `alloc` rather than the
// serde-pulling `json` feature: the always-compiled parser/format engine now
// emits through it, so it must be available in every engine build.
#[cfg(feature = "alloc")]
pub mod json_writer;
#[cfg(feature = "json")]
pub mod jsondiff;
pub mod parser;
// Phase D — new lib-first `FormatParser` trait scaffold, lands alongside the
// legacy `parser::FormatParser` (re-exported there as `OldFormatParser`). Per
// the spec at `docs/superpowers/specs/2026-05-21-lib-first-formatparser-design.md`:
// `parser_new` holds the new `FormatParser` / `MetaSinker` / `TagWriter` /
// `SharedFlags` traits + `AnyParser` / `AnyMeta` enum dispatch skeletons; `sink`
// holds the reference `TagWriter` implementor used by Phase D unit tests.
// Format arms are added in Phase E (MOI) and Phase F (everything else).
pub mod parser_new;
pub mod processbinarydata;
pub mod reader;
#[cfg(feature = "json")]
pub mod serialize;
pub mod sink;
pub mod tagtable;
pub mod value;

pub use error::{Error, OutOfBounds, Result, UnexpectedEof};
pub use value::{Group, Metadata, Rational, Tag, TagValue};

// Closed-set dispatch + sink scaffold re-exports (the public `AnyError`
// wrapper + the `parse_bytes` / `parse_<fmt>` entry points land in Phase G).
pub use parser_new::{AnyMeta, AnyParser, MetaSinker, SharedFlags, TagWriter};

// Per-format public typed re-exports. Each module's `XxxMeta<'a>` + accessor
// methods are the lib-first surface; the `ProcessXxx` unit-struct is the
// parser handle (carried in `AnyParser`); `XxxError` is the fatal-error
// variant.
#[cfg(feature = "aac")]
pub use formats::aac::{AacError, AacMeta, ProcessAac};
#[cfg(feature = "aiff")]
pub use formats::aiff::{AiffError, AiffMeta, ProcessAiff};
#[cfg(feature = "ape")]
pub use formats::ape::{ApeContext, ApeError, ApeMeta, ProcessApe};
#[cfg(feature = "audible")]
pub use formats::audible::{AaMeta, AudibleError, ProcessAa};
#[cfg(feature = "dsf")]
pub use formats::dsf::{DsfContext, DsfError, DsfMeta, ProcessDsf};
#[cfg(feature = "dv")]
pub use formats::dv::{DvError, DvMeta, DvParseOutcome, ProcessDv};
#[cfg(feature = "flac")]
pub use formats::flac::{FlacContext, FlacError, FlacMeta, ProcessFlac};
#[cfg(feature = "id3")]
pub use formats::id3::{
  Id3Context, Id3Error, Id3Meta, Id3Picture, Id3v1Meta, Id3v2Frame, Id3v2Version, ProcessId3,
};
// MP3 wrapper (Codex A-R2-1) — `mp3` feature pulls `mpeg-audio` + `ape`.
#[cfg(feature = "mp3")]
pub use formats::id3::{Mp3Context, Mp3Error, Mp3Meta, ProcessMp3};
#[cfg(feature = "moi")]
pub use formats::moi::{MoiError, MoiMeta, ProcessMoi};
#[cfg(feature = "mpc")]
pub use formats::mpc::{MpcContext, MpcError, MpcMeta, ProcessMpc};
#[cfg(feature = "mpeg-audio")]
pub use formats::mpeg::{MpegAudioContext, MpegAudioError, MpegAudioMeta, ProcessMpegAudio};
#[cfg(feature = "ogg")]
pub use formats::ogg::{OggError, OggMeta, ProcessOgg};
#[cfg(feature = "red")]
pub use formats::red::{ProcessR3D, R3dError, R3dMeta};
#[cfg(feature = "wavpack")]
pub use formats::wavpack::{ProcessWv, WvContext, WvError, WvMeta};
