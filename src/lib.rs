// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.
//! `exifast`: a faithful Rust port of ExifTool's metadata reader.
//!
//! Stage 1 scope: video/audio formats, read-only. Per-format port status
//! is tracked in `FORMATS.md` at the repository root.
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod bitstream;
pub mod convert;
pub mod error;
pub mod filetype;
pub mod formats;
pub mod jsondiff;
pub mod parser;
pub mod reader;
pub mod serialize;
pub mod tagtable;
pub mod value;

pub use error::{Error, OutOfBounds, Result, UnexpectedEof};
pub use value::{Group, Metadata, Rational, Tag, TagValue};
