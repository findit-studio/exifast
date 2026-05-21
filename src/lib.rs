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
