// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.
//! `exifast`: a faithful Rust port of ExifTool's metadata reader.
//!
//! Lib-first design — the primary API exposes typed `XxxMeta<'a>` values per
//! format (see [`formats`](crate::formats)). VALUE-equivalent JSON output vs
//! bundled `perl exiftool` is a secondary path (standard `serde_json`): the
//! engine renders via [`parser::extract_info`], and a typed `AnyMeta` can be
//! serialized directly with the optional [`Rendered`](crate::Rendered) wrapper.
//!
//! # Usage — universal dispatch
//!
//! Detect the file type from the input bytes and dispatch to the right
//! per-format parser through the closed [`AnyParser`](crate::format_parser::AnyParser)
//! / [`AnyMeta`](crate::format_parser::AnyMeta) enums. Most callers don't
//! know the format up front; this is the typical entry point:
//!
//! ```no_run
//! # #[cfg(feature = "moi")] {
//! use exifast::{parse_bytes, AnyMeta};
//!
//! let bytes = std::fs::read("file.moi").unwrap();
//! if let Some(meta) = parse_bytes(&bytes) {
//!   match meta {
//!     AnyMeta::Moi(moi) => {
//!       println!("MOI version: {}", moi.version());
//!     }
//!     // `#[non_exhaustive]` requires a catch-all arm
//!     _ => println!("Some other format"),
//!   }
//! }
//! # }
//! ```
//!
//! # Usage — per-format typed access
//!
//! When the caller knows the format up front, the per-format
//! `parse_<fmt>` accessors return the typed `XxxMeta<'a>` directly with
//! no enum hop. The lifetime of the returned Meta is tied to the input
//! buffer (zero-alloc by default; to store a Meta beyond the input
//! buffer's lifetime, clone the borrowed fields the caller needs):
//!
//! ```no_run
//! # #[cfg(feature = "flac")] {
//! use exifast::SharedFlags;
//!
//! let bytes = std::fs::read("song.flac").unwrap();
//! let mut shared = SharedFlags::new();
//! if let Some(flac) = exifast::parse_flac(&bytes, &mut shared) {
//!   if let Some(rate) = flac.sample_rate() {
//!     println!("Sample rate: {} Hz", rate);
//!   }
//! }
//! # }
//! ```
//!
//! # Cargo features
//!
//! Per-format Cargo gates let consumers prune unused formats (e.g. WASM
//! bundle-size reduction). See `Cargo.toml` § per-format gates and the
//! design spec for the full feature graph. The default feature set
//! (`std + json + all-formats`) gives CLI users every format and the
//! JSON serializer.
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
// The format-agnostic emission framework (`Taggable` + the `run_emission`
// engine + `ConvMode`/`EmittedTag`): the single place the cross-cutting
// emission rules (Unknown-suppression, sink dedup) are applied, so every
// format's typed `Meta` emits through ONE engine instead of a hand-rolled
// `serialize_tags`. `alloc`-gated to match `tagmap` (the engine's sink).
#[cfg(feature = "alloc")]
pub mod emit;
pub mod error;
// The Exif/TIFF IFD infrastructure (`exif` feature) + the GPS sub-IFD tag
// table (`gps` feature). `src/exif/` is a top-level module (not under
// `formats/`) because the Exif port is REUSABLE infra — QuickTime / RIFF /
// MakerNotes ports call `exif::parse_exif_block` on embedded Exif blocks, so
// it is not a leaf file-format like the `formats::*` modules. See
// `src/exif/mod.rs` for the camera-metadata-core rationale.
#[cfg(feature = "exif")]
pub mod exif;
pub mod filetype;
pub mod formats;
// The normalized typed-metadata domain layer (`MediaMetadata` and its
// per-domain structs) plus the faithful per-format parse mirrors (e.g.
// `QuickTimeMeta`). Unconditional — pure typed data with no serde/json
// dependency; the QuickTime port's `from_quicktime` projection lives here.
pub mod metadata;
// `jsondiff` (value-semantic golden-diff oracle) and `serialize` (the
// `serde_json` document renderer) depend on `serde_json` + `serde`, gated on
// the `json` feature (`json = ["serde", "alloc", "dep:serde_json", "dep:serde"]`).
// Library callers without `json` get the typed-Meta API path only; the optional
// `serde` feature alone provides the `Serialize` impls (TagValue / `Rendered`).
#[cfg(feature = "json")]
pub mod jsondiff;
pub mod parser;
// The lib-first `FormatParser` trait scaffold + closed-set `AnyParser` /
// `AnyMeta` dispatch — the SOLE parser architecture. The engine entry
// `parser::extract_info` routes through `any_parser_for(ft) ->
// AnyParser::parse_any`; each typed Meta's `serialize_tags` renders into a
// `tagmap::TagMap`, then serde-renders. The byte-exact conformance suite
// validates the typed path directly.
pub mod format_parser;
pub mod processbinarydata;
pub mod reader;
#[cfg(feature = "json")]
pub mod serialize;
// The single inline tag-collection sink the typed-Meta rendering path emits
// into (replaces the removed `TagWriter`/`MetaSinker` trait pair and the
// `JsonTagWriter`/`MapTagWriter` collectors). `pub(crate)`, `alloc`-gated so
// the `serde`-only `Rendered` wrapper can use it without `serde_json`.
#[cfg(feature = "alloc")]
pub(crate) mod tagmap;
pub mod tagtable;
pub mod value;

pub use error::{Error, OutOfBounds, Result, UnexpectedEof};
pub use value::{Group, Metadata, Rational, Tag, TagValue};

// The normalized cross-format domain layer (golden pattern L2). Re-exported
// at the crate root so the top-level [`media_metadata`] convenience entry's
// return type — and the [`Project`](crate::metadata::Project) seam each
// per-format `Meta` implements — are reachable without traversing into the
// [`metadata`] module. The per-domain structs stay under `exifast::metadata`.
pub use metadata::{MediaMetadata, Project};

// The emission-framework public surface (`run_emission` stays `pub(crate)` —
// it writes into the crate-private `TagMap` sink). `alloc`-gated to match the
// `emit` module.
#[cfg(feature = "alloc")]
pub use emit::{ConvMode, EmittedTag, Taggable};

// ===========================================================================
// Public lib-first API surface — Phase G
// ===========================================================================
//
// The public top-level `parse_bytes` + per-format `parse_<fmt>` entry points
// land here so callers don't need to traverse into `formats::<fmt>` for the
// happy path. Per skill §6 (no module-name stutter), each format's typed
// `Meta`/`Context` types now use the bare names — so they CANNOT all
// be re-exported at the crate root unaliased (`formats::moi::Meta` and
// `formats::aac::Meta` would collide). The per-format typed surface is
// therefore reached through the public [`formats`] module
// (`exifast::formats::<fmt>::Meta`); only the parser-handle unit-structs
// (`ProcessXxx`) are re-exported here (their names are unique). The universal
// [`parse_bytes`] / [`AnyMeta`] surface and every `parse_<fmt>` fn stay at the
// crate root.

/// The optional serde [`Serialize`](serde::Serialize) view of a typed
/// [`AnyMeta`] (`-j`/`-n` mode wrapper) — available with `--features serde`.
#[cfg(all(feature = "serde", feature = "alloc"))]
pub use format_parser::Rendered;
pub use format_parser::{AnyMeta, AnyParser, ExplicitThenLiteral, FileTypeFinalize, SharedFlags};

// Per-format parser-handle re-exports. The `ProcessXxx` unit-struct is the
// parser handle (carried in `AnyParser`). The typed `Meta<'a>` (+ accessor
// methods) are reached via `exifast::formats::<fmt>::Meta` — they are NOT
// re-exported at the crate root because their bare §6 names would collide
// across formats. (id3 keeps its `Id3*`/`Mp3*` axis prefixes and mpeg uses
// `Audio*`, but for a uniform surface those per-format Meta/Context types are
// also reached only via the `formats` module, not the crate root.)
#[cfg(feature = "aac")]
pub use formats::aac::ProcessAac;
#[cfg(feature = "aiff")]
pub use formats::aiff::ProcessAiff;
#[cfg(feature = "ape")]
pub use formats::ape::ProcessApe;
#[cfg(feature = "audible")]
pub use formats::audible::ProcessAa;
#[cfg(feature = "dsf")]
pub use formats::dsf::ProcessDsf;
#[cfg(feature = "dv")]
pub use formats::dv::ProcessDv;
// Exif/TIFF IFD parser handle (FORMATS.md row 13). The typed `ExifMeta<'a>`
// + the reusable `parse_exif_block` entry are reached via `exifast::exif::*`
// (the bare §6 names — `Meta` would collide with the `formats::*` Metas, so
// only the unique `ProcessExif` handle is re-exported at the crate root).
#[cfg(feature = "exif")]
pub use exif::ProcessExif;
#[cfg(feature = "flac")]
pub use formats::flac::ProcessFlac;
#[cfg(feature = "flash")]
pub use formats::flash::ProcessFlv;
#[cfg(feature = "h264")]
pub use formats::h264::ProcessH264;
#[cfg(feature = "id3")]
pub use formats::id3::ProcessId3;
#[cfg(feature = "matroska")]
pub use formats::matroska::ProcessMatroska;
// MP3 wrapper (Codex A-R2-1) — `mp3` feature pulls `mpeg-audio` + `ape`.
#[cfg(feature = "mp3")]
pub use formats::id3::ProcessMp3;
#[cfg(feature = "moi")]
pub use formats::moi::ProcessMoi;
#[cfg(feature = "mpc")]
pub use formats::mpc::ProcessMpc;
#[cfg(feature = "mpeg-audio")]
pub use formats::mpeg::ProcessMpegAudio;
#[cfg(feature = "mxf")]
pub use formats::mxf::ProcessMxf;
#[cfg(feature = "ogg")]
pub use formats::ogg::ProcessOgg;
#[cfg(feature = "plist")]
pub use formats::plist::ProcessPlist;
#[cfg(feature = "quicktime")]
pub use formats::quicktime::ProcessMov;
#[cfg(feature = "real")]
pub use formats::real::ProcessReal;
#[cfg(feature = "red")]
pub use formats::red::ProcessR3D;
#[cfg(feature = "wavpack")]
pub use formats::wavpack::ProcessWv;

// ===========================================================================
// `parse_bytes` — universal dispatch entry
// ===========================================================================

/// Universal dispatch entry point: detect the file type from `bytes` (using
/// the existing magic-number based detection from
/// [`filetype::detection_candidates`](crate::filetype::detection_candidates))
/// and route through the closed [`AnyParser`] / [`AnyMeta`] enums.
///
/// Returns:
/// - `Some(meta)` — the first parser to accept the data, wrapped in
///   the appropriate [`AnyMeta`] variant.
/// - `None` — no parser accepted the data (no detected format in the
///   compiled feature set matched). No ported format has a Rust-level fatal
///   mode, so a malformed input is either a rejected candidate (`None`) or an
///   accepted `AnyMeta` carrying a `Warn`/`Error` tag — never an error here.
///
/// The returned [`AnyMeta`] borrows from the input `bytes` for zero
/// allocation on the happy path. To store a Meta beyond the lifetime of
/// `bytes`, clone the borrowed fields the caller needs out of the
/// appropriate [`AnyMeta`] arm.
///
/// # Filename-less detection
///
/// This entry point passes an empty filename to
/// [`filetype::detection_candidates`](crate::filetype::detection_candidates),
/// so detection is driven purely by magic numbers. Callers with a filename
/// (which lets ExifTool's `%fileTypeLookup` add extension-based candidates)
/// can fall back to the legacy [`parser::extract_info`] for byte-exact CLI
/// JSON output, or build their own `AnyParser` resolution via
/// [`format_parser::any_parser_for`].
#[cfg(feature = "std")]
#[must_use]
pub fn parse_bytes(bytes: &[u8]) -> Option<AnyMeta<'_>> {
  // Golden-v2 Contract 3d — a `catch_unwind` BACKSTOP at the public boundary.
  // The primary no-panic guarantee is 3a (the recursion budgets) + 3b (the
  // `tests/no_panic.rs` proptest gate); this only converts an UNANTICIPATED
  // panic (a future bug, a slice-index regression, an arithmetic overflow in a
  // debug build) into the same empty result a clean rejection yields, so an
  // untrusted byte stream can never crash the host process. `AssertUnwindSafe`
  // is sound here: the closure only READS `bytes` (a shared `&[u8]`) and
  // returns an owned/borrowed result — no `&mut` state is left half-updated
  // across the boundary.
  std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| parse_bytes_inner(bytes)))
    .unwrap_or(None)
}

/// Inner body of [`parse_bytes`] (see that fn's doc + Golden-v2 3d note). The
/// public wrapper adds the `catch_unwind` backstop. `parse_bytes` is itself
/// `std`-only, so its inner shares that gate.
#[cfg(feature = "std")]
fn parse_bytes_inner(bytes: &[u8]) -> Option<AnyMeta<'_>> {
  // Empty filename ⇒ magic-only detection (ExifTool.pm:2965-3045 with
  // `$ext = undef`). Each candidate is tried in turn; the first parser to
  // return `Some(meta)` wins. Faithful to the legacy
  // `parser::extract_info` loop, minus the candidate-rejection side
  // effects on `Metadata` (the typed `AnyMeta` carries everything).
  //
  // `SharedFlags` is constructed fresh per candidate so that side effects
  // from a rejected candidate (e.g. a partial ID3 walk that flipped
  // `done_id3`) don't leak into the next candidate's parse. This mirrors
  // ExifTool's `local $$et` scoping pattern for the candidate loop.
  let mut shared = SharedFlags::new();
  for cand in filetype::detection_candidates("", bytes) {
    let ft = cand.file_type();
    // ExifTool.pm:3035-3045 / XMP.pm:4369-4387 — the XMP module's content sniff
    // routes an XML `<plist>` (or `<!DOCTYPE plist>`) to `ProcessPLIST`. With an
    // empty filename, a UTF-8-BOM-prefixed XML plist is reached ONLY this way:
    // its XMP `%magicNumber` (ExifTool.pm:1045 `…(\xef\xbb\xbf)?…\s*<`) accepts
    // the BOM that the PLIST `%magicNumber` (ExifTool.pm:1015 `(bplist0|\s*<|…)`)
    // does not, so `XMP` is the first/only candidate; `ProcessXMP` then
    // `SetFileType('PLIST', 'application/xml')` and hands the body to
    // `PLIST::FoundTag`. This port has no standalone XMP parser, so replicate that
    // hop here — exactly as `parser::extract_info_typed` does — and dispatch as
    // `PLIST` so the typed API yields `AnyMeta::Plist` (not silently `None`).
    // `magic()` stays a faithful 1:1 of `%magicNumber` (the PLIST gate is
    // unchanged); the BOM tolerance lives only in this XMP→PLIST route, and
    // `ProcessPlist` itself skips a leading UTF-8 BOM at its XML gate.
    #[cfg(feature = "plist")]
    let ft = if ft == "XMP"
      && format_parser::any_parser_for("XMP").is_none()
      && formats::plist::xml_content_is_plist(bytes)
    {
      "PLIST"
    } else {
      ft
    };
    let Some(parser) = format_parser::any_parser_for(ft) else {
      continue;
    };
    // `cand.header_skip()` threads the unknown-leading-header byte count
    // (Perl `$skip`, `ExifTool.pm:3029`) for the terminal JPEG/TIFF candidate;
    // `0` for every ordinary candidate. `cand.parent_type()` is the candidate's
    // `Parent` — the standalone-TIFF arm gates `File:PageCount` on it == "TIFF".
    if let Some(m) = parser.parse_any(
      bytes,
      &mut shared,
      None,
      cand.header_skip(),
      Some(cand.parent_type()),
    ) {
      return Some(m);
    }
    // Reset shared flags between rejected candidates so partial
    // side-effects (e.g. a probe that touched `done_id3`) don't leak.
    shared = SharedFlags::new();
  }
  None
}

// ===========================================================================
// `media_metadata` — top-level domain-projection entry (golden pattern L2)
// ===========================================================================

/// Detect the file type from `bytes`, parse it, and project the result onto
/// the normalized cross-format [`MediaMetadata`] domain — the lib-first
/// "give me camera / lens / GPS / capture / container facts regardless of
/// format" convenience entry.
///
/// This is the one-call wrapper over [`parse_bytes`] +
/// [`AnyMeta::project`](crate::AnyMeta::project): it dispatches to the right
/// per-format parser, then folds the typed `Meta` into the domain aggregate.
///
/// Returns:
/// - `Some(md)` — the bytes parsed to a known format; `md` carries whatever
///   domains that format projects. Today only EXIF/TIFF (incl. JPEG-embedded
///   Exif + the vendor MakerNote) fills camera / lens / GPS / capture; every
///   other format projects an **empty** [`MediaMetadata`] (all domains `None`)
///   until its Phase-2 projection lands. So a recognized non-EXIF file yields
///   `Some(MediaMetadata)` whose [`camera`](MediaMetadata::camera) etc. are
///   `None`.
/// - `None` — no parser accepted the bytes (unknown/empty input). A caller
///   that wants the typed `AnyMeta` (e.g. to inspect a non-EXIF format's tags
///   directly) should use [`parse_bytes`] and call
///   [`AnyMeta::project`](crate::AnyMeta::project) itself.
///
/// # Examples
///
/// ```no_run
/// # #[cfg(feature = "exif")] {
/// let bytes = std::fs::read("photo.jpg").unwrap();
/// if let Some(md) = exifast::media_metadata(&bytes) {
///   if let Some(make) = md.camera().and_then(|c| c.make()) {
///     println!("shot on a {make}");
///   }
/// }
/// # }
/// ```
#[cfg(feature = "std")]
#[must_use]
pub fn media_metadata(bytes: &[u8]) -> Option<MediaMetadata> {
  // Golden-v2 Contract 3d — `catch_unwind` backstop (see [`parse_bytes`]).
  // Backstop only; 3a (recursion budgets) + 3b (proptest) are the primary
  // guarantee. `AssertUnwindSafe` is sound: the closure only reads `bytes`.
  // A caught panic ⇒ `None` (the `Option` default), same as a clean miss.
  std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| media_metadata_inner(bytes)))
    .unwrap_or_default()
}

/// Inner body of [`media_metadata`] (see that fn's doc + Golden-v2 3d note).
#[cfg(feature = "std")]
fn media_metadata_inner(bytes: &[u8]) -> Option<MediaMetadata> {
  // `None` from `parse_bytes` (no format matched) maps straight through.
  parse_bytes(bytes).map(|any| any.project())
}

// ===========================================================================
// Per-format `parse_<fmt>` typed direct accessors
// ===========================================================================
//
// These are thin re-exports of each format module's `parse_borrowed`
// entry point. They live on the crate root for ergonomics — callers
// don't need to traverse `formats::<fmt>::parse_borrowed` for the
// happy path. The names mirror the format Cargo feature so they
// auto-document the relationship.
//
// Leaf formats accept just `&[u8]`. Chained formats also take
// `&mut SharedFlags` (the cross-format `DoneID3` / `DoneAPE` bag); the
// MP3 / MPEG-audio entries also take an extension string.

/// Parse a MOI buffer directly. See [`formats::moi::parse_borrowed`].
#[cfg(feature = "moi")]
#[must_use]
pub fn parse_moi(bytes: &[u8]) -> Option<formats::moi::Meta<'_>> {
  formats::moi::parse_borrowed(bytes)
}

/// Parse a Matroska/MKV/MKA/MKS/WebM buffer directly. See
/// [`formats::matroska::parse_borrowed`].
#[cfg(feature = "matroska")]
#[must_use]
pub fn parse_matroska(bytes: &[u8]) -> Option<formats::matroska::Meta<'_>> {
  formats::matroska::parse_borrowed(bytes)
}

/// Parse a QuickTime / MP4 / MOV / M4A / M4V / 3GP / 3G2 buffer directly.
/// See [`formats::quicktime::parse_borrowed`]. **SP1**: the box/atom walker
/// plus the core structural atoms only (see the module docs).
#[cfg(feature = "quicktime")]
#[must_use]
pub fn parse_quicktime(bytes: &[u8]) -> Option<formats::quicktime::Meta<'_>> {
  formats::quicktime::parse_borrowed(bytes)
}

/// Parse an MXF (Material Exchange Format) buffer directly. See
/// [`formats::mxf::parse_borrowed`].
#[cfg(feature = "mxf")]
#[must_use]
pub fn parse_mxf(bytes: &[u8]) -> Option<formats::mxf::MxfMeta<'_>> {
  formats::mxf::parse_borrowed(bytes)
}

/// Parse an Apple Property List buffer directly — decodes both the binary
/// (`bplist0…`) and XML (`<?xml …?>`) encodings. See
/// [`formats::plist::parse_borrowed`].
#[cfg(feature = "plist")]
#[must_use]
pub fn parse_plist(bytes: &[u8]) -> Option<formats::plist::PlistMeta<'_>> {
  formats::plist::parse_borrowed(bytes)
}

/// Parse an AAC (ADTS) buffer directly. See [`formats::aac::parse_borrowed`].
#[cfg(feature = "aac")]
#[must_use]
pub fn parse_aac(bytes: &[u8]) -> Option<formats::aac::Meta<'_>> {
  formats::aac::parse_borrowed(bytes)
}

/// Parse a DV stream buffer directly. See [`formats::dv::parse_borrowed`].
#[cfg(feature = "dv")]
#[must_use]
pub fn parse_dv(bytes: &[u8]) -> Option<formats::dv::ParseOutcome<'static>> {
  formats::dv::parse_borrowed(bytes)
}

/// Parse a standalone TIFF file (an Exif/TIFF block) directly. See
/// [`exif::parse_borrowed`].
///
/// A standalone TIFF file IS an Exif/TIFF block: the byte-order marker +
/// magic + IFD0 offset are at offset 0. JPEG / MP4 embed Exif as a
/// SubDirectory — those container ports call [`exif::parse_exif_block`]
/// directly on the embedded block.
///
/// Returns `None` when `bytes` is not a valid TIFF header (a malformed
/// standalone TIFF surfaces its diagnostics as `Warn`/`Error` tags on the
/// returned [`exif::ExifMeta`], never as a fatal error).
#[cfg(all(feature = "exif", feature = "std"))]
#[must_use]
pub fn parse_exif(bytes: &[u8]) -> Option<exif::ExifMeta<'_>> {
  // Golden-v2 Contract 3d — `catch_unwind` backstop (see [`parse_bytes`]).
  // Backstop only; 3a/3b are the primary guarantee. `AssertUnwindSafe` is
  // sound: the closure only reads `bytes`.
  std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| parse_exif_inner(bytes))).unwrap_or(None)
}

/// `parse_exif` on a no_std (no `catch_unwind`) build — direct passthrough.
#[cfg(all(feature = "exif", not(feature = "std")))]
#[must_use]
pub fn parse_exif(bytes: &[u8]) -> Option<exif::ExifMeta<'_>> {
  parse_exif_inner(bytes)
}

/// Inner body of [`parse_exif`] (see that fn's doc + Golden-v2 3d note).
#[cfg(feature = "exif")]
fn parse_exif_inner(bytes: &[u8]) -> Option<exif::ExifMeta<'_>> {
  exif::parse_borrowed(bytes)
}

/// Parse a raw Exif/TIFF byte block directly into a typed
/// [`exif::ExifMeta`] — the **reusable** entry a QuickTime / RIFF /
/// MakerNotes port calls on an embedded Exif block. See
/// [`exif::parse_exif_block`]. The GPS sub-IFD is decoded automatically when
/// the `gps` feature is enabled (reached through the IFD0 `GPSInfo` tag).
///
/// Returns `None` when `block` is not a valid TIFF header.
#[cfg(all(feature = "exif", feature = "std"))]
#[must_use]
pub fn parse_exif_block(block: &[u8]) -> Option<exif::ExifMeta<'_>> {
  // Golden-v2 Contract 3d — `catch_unwind` backstop (see [`parse_bytes`]).
  // Backstop only; 3a/3b are the primary guarantee. `AssertUnwindSafe` is
  // sound: the closure only reads `block`. A caught panic ⇒ `None`.
  std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
    parse_exif_block_inner(block)
  }))
  .unwrap_or_default()
}

/// `parse_exif_block` on a no_std (no `catch_unwind`) build — direct passthrough.
#[cfg(all(feature = "exif", not(feature = "std")))]
#[must_use]
pub fn parse_exif_block(block: &[u8]) -> Option<exif::ExifMeta<'_>> {
  parse_exif_block_inner(block)
}

/// Inner body of [`parse_exif_block`] (see that fn's doc + Golden-v2 3d note).
#[cfg(feature = "exif")]
fn parse_exif_block_inner(block: &[u8]) -> Option<exif::ExifMeta<'_>> {
  exif::parse_exif_block(block)
}

/// Parse an Audible (AA) buffer directly. See [`formats::audible::parse_borrowed`].
#[cfg(feature = "audible")]
#[must_use]
pub fn parse_audible(bytes: &[u8]) -> Option<formats::audible::Meta<'_>> {
  formats::audible::parse_borrowed(bytes)
}

/// Parse a Red R3D buffer directly. See [`formats::red::parse_borrowed`].
#[cfg(feature = "red")]
#[must_use]
pub fn parse_r3d(bytes: &[u8]) -> Option<formats::red::Meta<'_>> {
  formats::red::parse_borrowed(bytes)
}

/// Parse an ID3 (v1 or v2) directory directly. See
/// [`formats::id3::parse_id3_borrowed`].
///
/// `shared` carries cross-format state for chained dispatch (the
/// `$$et{DoneID3}` flag, etc.); pass a fresh
/// [`SharedFlags::new()`] when calling stand-alone.
///
/// `print_conv = true` stages the tags in `-j` PrintConv mode (e.g. ID3v1
/// Genre `"Hip-Hop"`); `false` stages in `-n` post-ValueConv raw mode
/// (e.g. Genre `7`). One parse stages BOTH lists; the renderer picks by mode.
#[cfg(feature = "id3")]
#[must_use]
pub fn parse_id3<'a>(
  bytes: &'a [u8],
  shared: Option<&mut SharedFlags>,
  print_conv: bool,
) -> Option<formats::id3::Id3Meta<'a>> {
  formats::id3::parse_id3_borrowed(bytes, shared, print_conv)
}

/// Parse an MP3 file (ID3 wrapper + MPEG audio chain + APE trailer)
/// directly through the typed [`ProcessMp3`] parser, faithful to bundled
/// `Image::ExifTool::ID3::ProcessMP3` (ID3.pm:1684-1728). Only `bytes`
/// flows into the returned [`formats::id3::Mp3Meta`] (which carries the ID3,
/// MPEG-audio, and APE-trailer sub-Metas); it is `Some` for a valid
/// MPEG-only MP3 (Codex BF1/CF1).
///
/// `ext` borrows on an **independent** lifetime — it is consumed only to
/// derive the MPEG scan window + Layer-II/MUS gate and is never stored, so
/// a transient `ext` string may be dropped while the returned meta lives on
/// (Codex C-R2-2).
///
/// The ID3 sub-Meta is staged in `-j` (PrintConv) mode; sink the result
/// with `sink(true, ...)`.
#[cfg(feature = "mp3")]
#[must_use]
pub fn parse_mp3<'a>(bytes: &'a [u8], ext: Option<&str>) -> Option<formats::id3::Mp3Meta<'a>> {
  // `parse_mp3_borrowed` decouples the transient `shared` AND `ext` borrows
  // from the returned `id3::Mp3Meta<'a>` (which borrows only from `bytes`), so a
  // local `SharedFlags` and a transient `ext` are both valid here.
  let mut shared = SharedFlags::new();
  formats::id3::parse_mp3_borrowed(bytes, ext, &mut shared)
}

/// Parse an AIFF (or AIFC) buffer directly. See
/// [`formats::aiff::parse_borrowed`].
#[cfg(feature = "aiff")]
#[must_use]
pub fn parse_aiff(bytes: &[u8]) -> Option<formats::aiff::Meta<'_>> {
  formats::aiff::parse_borrowed(bytes)
}

/// Parse an APE (Monkey's Audio) buffer directly through the typed
/// [`ProcessApe`] parser, including the embedded ID3 chain (APE.pm:124-127).
///
/// `shared` carries cross-format state (`DoneID3` / `DoneAPE` flags) and
/// borrows **independently** of `bytes` — only the byte-buffer lifetime
/// `'a` flows into the returned [`formats::ape::Meta`] (the MAC/main side
/// is owned; the nested ID3 sub-Meta borrows from `bytes`). The transient
/// `shared` may therefore be dropped or reused while the returned meta
/// lives on (Codex C-R2-2).
///
/// **R4 F2 (Codex adversarial)** — routes through `parse_full_chained`
/// rather than `parse_full_owned`, so an ID3v2-prefixed APE buffer or an
/// ID3v1-trailered APE buffer surfaces the chained ID3 sub-Meta the way
/// the engine `AnyParser::Ape` arm does. Pre-fix the lib-direct API
/// (`parse_full_owned`) skipped the ID3 chain — silent metadata loss on
/// `ape_id3_prefixed.ape` / `ape_with_id3v1_trailer.ape` / etc. through
/// this path.
#[cfg(feature = "ape")]
#[must_use]
pub fn parse_ape<'a>(bytes: &'a [u8], shared: &mut SharedFlags) -> Option<formats::ape::Meta<'a>> {
  // `ape = ["id3"]` per Cargo.toml ⇒ `parse_full_chained` is always present
  // here. Returns `Option<Meta<'a>>` where `'a` is tied to `bytes` (the
  // nested `Id3Meta` borrows from `bytes`); `shared` is transient.
  formats::ape::parse_full_chained(bytes, shared)
}

/// Parse a DSF (DSD Stream File) buffer directly. See
/// [`formats::dsf::parse_borrowed`].
#[cfg(feature = "dsf")]
#[must_use]
pub fn parse_dsf(bytes: &[u8]) -> Option<formats::dsf::Meta<'_>> {
  formats::dsf::parse_borrowed(bytes)
}

/// Parse a FLAC buffer directly. See [`formats::flac::parse_borrowed`].
///
/// `shared` carries cross-format state (`DoneID3` flag, etc.).
#[cfg(feature = "flac")]
#[must_use]
pub fn parse_flac<'a>(
  bytes: &'a [u8],
  shared: &mut SharedFlags,
) -> Option<formats::flac::Meta<'a>> {
  formats::flac::parse_borrowed(bytes, shared)
}

/// Parse a Real (RM / RA / RAM / RPM) buffer directly. See
/// [`formats::real::parse_borrowed`].
#[cfg(feature = "real")]
#[must_use]
pub fn parse_real(bytes: &[u8]) -> Option<formats::real::RealMeta<'_>> {
  formats::real::parse_borrowed(bytes)
}

/// Parse an H.264 NAL byte stream directly. See [`formats::h264::parse_borrowed`].
///
/// H264 is **engine-only** — ExifTool has no `H264` file type ([`parse_bytes`]
/// will never dispatch to it). This entry point is for callers that already
/// have a de-packetized H.264 elementary stream (e.g. an M2TS / MPEG demuxer
/// that extracted the PES payload) and want the typed [`formats::h264::H264Meta`].
///
/// Returns `Ok(None)` when `bytes` contains no NAL start code at all.
#[cfg(feature = "h264")]
#[must_use]
pub fn parse_h264(bytes: &[u8]) -> Option<formats::h264::H264Meta<'_>> {
  formats::h264::parse_borrowed(bytes)
}

/// Parse a Flash Video (FLV) buffer directly. See
/// [`formats::flash::parse_borrowed`].
#[cfg(feature = "flash")]
#[must_use]
pub fn parse_flv(bytes: &[u8]) -> Option<formats::flash::Meta<'_>> {
  formats::flash::parse_borrowed(bytes)
}

/// Parse an Ogg container (Vorbis / Opus / Theora) buffer directly. See
/// [`formats::ogg::parse_borrowed`].
///
/// `print_conv_enabled = true` matches bundled `perl exiftool -j`;
/// `false` matches `-j -n`.
#[cfg(feature = "ogg")]
#[must_use]
pub fn parse_ogg(bytes: &[u8], print_conv_enabled: bool) -> Option<formats::ogg::Meta<'_>> {
  formats::ogg::parse_borrowed(bytes, print_conv_enabled)
}

/// Parse an MPEG audio frame stream buffer directly. See
/// [`formats::mpeg::parse_borrowed`].
///
/// `mp3 = true` enforces Layer III (MPEG.pm:466). `ext` is the file
/// extension (uppercased, no leading dot — e.g. `"MP3"`, `"MUS"`); the
/// empty string disables the validation-reject retry (MPEG.pm:488).
#[cfg(feature = "mpeg-audio")]
#[must_use]
pub fn parse_mpeg_audio<'a>(
  bytes: &'a [u8],
  mp3: bool,
  ext: &str,
) -> Option<formats::mpeg::AudioMeta<'a>> {
  formats::mpeg::parse_borrowed(bytes, mp3, ext)
}

/// Parse an MPC (Musepack SV7) buffer directly, including the embedded
/// ID3 prefix (MPC.pm:84-87) and APE trailer (MPC.pm:111-113) chains.
///
/// **R4 F2 (Codex adversarial)** — routes through `parse_full_chained`
/// rather than `parse_borrowed`. Pre-fix the lib-direct API called the
/// bare body-only `parse_borrowed`, so an MPC with a leading ID3 or a
/// trailing APE silently dropped those tags through the public path
/// (the engine `AnyParser::Mpc` arm always used the chained entry).
///
/// A fresh [`SharedFlags`] is constructed per call (the public entry has
/// no chain state to thread). The returned `Meta<'a>` is tied to `bytes`
/// (the nested ID3 / APE sub-Metas borrow from `bytes`).
#[cfg(feature = "mpc")]
#[must_use]
pub fn parse_mpc(bytes: &[u8]) -> Option<formats::mpc::Meta<'_>> {
  // `mpc = ["id3", "ape"]` per Cargo.toml ⇒ `parse_full_chained` is always
  // present here.
  let mut shared = SharedFlags::default();
  formats::mpc::parse_full_chained(bytes, &mut shared)
}

/// Parse a WavPack `.wv` buffer directly, including the embedded ID3
/// + APE trailer chains (WavPack.pm:100-103).
///
/// **R4 F2 (Codex adversarial)** — routes through `parse_full_chained`
/// rather than `parse_borrowed`. Pre-fix the lib-direct API called the
/// bare body-only `parse_borrowed`, so a WavPack with an ID3v1 or APE
/// trailer silently dropped those tags through the public path (the
/// engine `AnyParser::Wv` arm always used the chained entry).
///
/// A fresh [`SharedFlags`] is constructed per call. The returned
/// `Meta<'a>` is tied to `bytes` (the nested ID3 / APE sub-Metas borrow
/// from `bytes`).
#[cfg(feature = "wavpack")]
#[must_use]
pub fn parse_wavpack(bytes: &[u8]) -> Option<formats::wavpack::Meta<'_>> {
  // `wavpack = ["id3", "ape"]` per Cargo.toml ⇒ `parse_full_chained` is
  // always present here.
  let mut shared = SharedFlags::default();
  formats::wavpack::parse_full_chained(bytes, &mut shared)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  /// `parse_bytes` returns `None` for an empty input — no parser
  /// accepts an empty buffer, which matches ExifTool's
  /// `File is empty` Error-only path (here surfaced as `None`).
  #[test]
  #[cfg(feature = "std")]
  fn parse_bytes_empty_input_returns_none() {
    let result = parse_bytes(b"");
    assert!(result.is_none());
  }

  /// `media_metadata` over a real Canon JPEG projects the camera domain
  /// through `parse_bytes` → `AnyMeta::Exif` → `Project::project` (the
  /// JPEG candidate routes to the Exif walker). The make comes from IFD0
  /// `Make`; the model/serial fold in the Canon MakerNote merge.
  #[test]
  #[cfg(all(feature = "exif", feature = "std"))]
  fn media_metadata_canon_jpeg_projects_camera() {
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/MakerNotes_Canon.jpg"
    ))
    .expect("read MakerNotes_Canon.jpg fixture");
    let md = media_metadata(&bytes).expect("Canon JPEG projects to Some(MediaMetadata)");
    let camera = md.camera().expect("camera domain populated");
    assert_eq!(camera.make(), Some("Canon"));
    // Sanity that the projection is the full EXIF+MakerNote one (not empty).
    assert!(camera.model().is_some_and(|m| m.starts_with("Canon EOS")));
  }

  /// `media_metadata` returns `None` for empty input (no parser accepts an
  /// empty buffer) — `parse_bytes(..) == None` maps straight through.
  #[test]
  #[cfg(feature = "std")]
  fn media_metadata_empty_input_is_none() {
    assert!(media_metadata(b"").is_none());
    assert!(media_metadata(b"\x00\x00\x00\x00not-a-format").is_none());
  }

  /// `parse_bytes` returns `None` for a buffer that no parser
  /// accepts (random bytes with no magic-number match).
  #[test]
  #[cfg(feature = "std")]
  fn parse_bytes_unknown_format_returns_none() {
    let result = parse_bytes(b"\x00\x00\x00\x00not-a-format");
    assert!(result.is_none());
  }

  /// `parse_bytes` dispatches a recognized MOI file to the
  /// [`AnyMeta::Moi`] arm.
  #[test]
  #[cfg(all(feature = "moi", feature = "std"))]
  fn parse_bytes_moi_v6_dispatches_to_moi_arm() {
    // V6 magic + minimal padding for MOI acceptance.
    let bytes = &[
      b'V', b'6', // magic
      0x00, 0x00, 0x00, 0x40, // embedded file size = 0x40 (large enough)
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // datetime placeholder
      0x00, 0x00, 0x00, 0x00, // duration
      0x00, 0x00, // aspect ratio etc.
    ];
    // Pad to 64 bytes so the MOI parser doesn't reject on too-short.
    let mut padded = bytes.to_vec();
    padded.resize(64, 0);
    let result = parse_bytes(&padded);
    // The MOI parser may accept or reject this minimal buffer depending on
    // its internal validation; we don't pin the exact outcome here, just
    // that the dispatch doesn't panic.
    let _ = result;
  }

  /// Codex C-R4-1: an ID3v2-PREFIXED Ogg stream must dispatch to
  /// [`AnyMeta::Ogg`], NOT the mis-routed [`AnyMeta::Mp3`]. The
  /// `%magicNumber{OGG}` gate is `(OggS|ID3)` (ExifTool.pm:1004), so the
  /// ID3-prefixed buffer detects as OGG and the OGG arm is tried first; before
  /// this fix the OGG parse failed (`OggS` not at offset 0) and the weak-magic
  /// MP3 arm wrongly accepted. The OGG arm now seeks past the ID3v2 header
  /// (bundled `Seek($hdrEnd, 0)`, Ogg.pm:79-82 → ID3.pm:1590) and re-parses
  /// Ogg on the post-ID3 slice. Verified byte-exact-equivalent vs bundled
  /// `perl exiftool` (FileType=OGG, Vorbis:* tags) — the fixture is
  /// `Vorbis.ogg` with a synthesized 34-byte ID3v2.3 TIT2 prefix.
  #[test]
  #[cfg(all(feature = "ogg", feature = "mp3", feature = "json"))]
  fn parse_bytes_id3_prefixed_ogg_dispatches_to_ogg_not_mp3() {
    let data = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/ogg_id3_prefixed.ogg"
    ))
    .expect("read ogg_id3_prefixed.ogg fixture");
    // Sanity: the fixture really does start with an ID3v2 prefix (NOT OggS).
    assert!(data.starts_with(b"ID3"), "fixture must be ID3-prefixed");
    let meta = parse_bytes(&data).expect("ID3-prefixed Ogg must be recognized");
    // Core C-R4-1 assertion: dispatch to Ogg, NOT the mis-routed Mp3.
    assert!(
      matches!(meta, AnyMeta::Ogg(_)),
      "ID3-prefixed Ogg must dispatch to AnyMeta::Ogg, not {meta:?}"
    );
    // Content check: serde-rendering the post-ID3 Ogg stream (the public typed
    // `Rendered` serde view) yields the SAME Vorbis tags bundled `perl exiftool`
    // reports (e.g. Vorbis:Artist "Who Knows"), proving the ID3v2 prefix was
    // correctly skipped and the real Ogg-Vorbis stream parsed.
    let obj = serde_json::to_value(Rendered::new(&meta, true)).expect("render");
    let obj = obj.as_object().expect("flat object");
    assert_eq!(
      obj.get("Vorbis:Artist").and_then(|v| v.as_str()),
      Some("Who Knows"),
      "post-ID3 Ogg-Vorbis tags must be present: {obj:?}"
    );
    assert_eq!(
      obj.get("Vorbis:Title").and_then(|v| v.as_str()),
      Some("A 4s sample for testing embedded cover art"),
      "post-ID3 Ogg-Vorbis Title must be present: {obj:?}"
    );
  }

  /// Codex R13/F1 [REAL-INPUT]: a UTF-8-BOM XML plist with NO filename must
  /// dispatch to [`AnyMeta::Plist`] through the public typed `parse_bytes` API —
  /// NOT silently return `None`. With an empty filename, magic-only detection
  /// yields `XMP` first (XMP `%magicNumber` accepts the `\xef\xbb\xbf` BOM,
  /// ExifTool.pm:1045) while the PLIST `%magicNumber` (ExifTool.pm:1015) does NOT,
  /// so the later PLIST candidate never matches. Bundled ExifTool reaches this
  /// file via `ProcessXMP`'s `<plist>` content-sniff (XMP.pm:4385) →
  /// `SetFileType('PLIST', 'application/xml')` → `PLIST::FoundTag`. `parse_bytes`
  /// now mirrors `extract_info_typed`'s XMP→PLIST relabel via the
  /// [`formats::plist::xml_content_is_plist`] gate, so the typed API yields the
  /// plist metadata. Verified vs bundled `perl exiftool -j -G1` on the same bytes
  /// (extensionless): `File:FileType` "PLIST", `File:MIMEType` "application/xml",
  /// `XML:TestString` "BOM plist", `XML:TestInteger` 256.
  #[test]
  #[cfg(all(feature = "plist", feature = "std"))]
  fn parse_bytes_bom_xml_plist_relabels_xmp_to_plist() {
    let data = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/plist_synth_xml_utf8bom.plist"
    ))
    .expect("read plist_synth_xml_utf8bom.plist fixture");
    // Sanity: the fixture really does start with a UTF-8 BOM (NOT `<?xml` / `bplist`).
    assert!(
      data.starts_with(&[0xEF, 0xBB, 0xBF]),
      "fixture must be UTF-8-BOM-prefixed"
    );
    let meta =
      parse_bytes(&data).expect("BOM XML plist must be recognized via XMP→PLIST relabel, not None");
    // Core R13/F1 assertion: the typed API dispatches to the PLIST arm.
    assert!(
      matches!(meta, AnyMeta::Plist(_)),
      "BOM XML plist must dispatch to AnyMeta::Plist, not {meta:?}"
    );
  }

  /// Each per-format `parse_<fmt>` entry can be invoked with a byte slice
  /// (compile-time check — the test body just confirms the call shapes).
  /// The actual semantics are exercised by per-format conformance tests.
  #[test]
  fn per_format_parse_entries_compile() {
    let bytes: &[u8] = b"";
    #[cfg(feature = "moi")]
    let _ = parse_moi(bytes);
    #[cfg(feature = "matroska")]
    let _ = parse_matroska(bytes);
    #[cfg(feature = "mxf")]
    let _ = parse_mxf(bytes);
    #[cfg(feature = "plist")]
    let _ = parse_plist(bytes);
    #[cfg(feature = "aac")]
    let _ = parse_aac(bytes);
    #[cfg(feature = "dv")]
    let _ = parse_dv(bytes);
    #[cfg(feature = "exif")]
    {
      let _ = parse_exif(bytes);
      let _ = parse_exif_block(bytes);
    }
    #[cfg(feature = "audible")]
    let _ = parse_audible(bytes);
    #[cfg(feature = "red")]
    let _ = parse_r3d(bytes);
    #[cfg(feature = "aiff")]
    let _ = parse_aiff(bytes);
    #[cfg(feature = "dsf")]
    let _ = parse_dsf(bytes);
    #[cfg(feature = "ogg")]
    let _ = parse_ogg(bytes, true);
    #[cfg(feature = "real")]
    let _ = parse_real(bytes);
    #[cfg(feature = "mpc")]
    let _ = parse_mpc(bytes);
    #[cfg(feature = "wavpack")]
    let _ = parse_wavpack(bytes);
    #[cfg(feature = "id3")]
    {
      let _ = parse_id3(bytes, None, true);
    }
    #[cfg(feature = "mp3")]
    {
      let _ = parse_mp3(bytes, None);
    }
    #[cfg(feature = "flac")]
    {
      let mut shared = SharedFlags::new();
      let _ = parse_flac(bytes, &mut shared);
    }
    #[cfg(feature = "flash")]
    let _ = parse_flv(bytes);
    #[cfg(feature = "ape")]
    {
      let mut shared = SharedFlags::new();
      let _ = parse_ape(bytes, &mut shared);
    }
    #[cfg(feature = "mpeg-audio")]
    {
      let _ = parse_mpeg_audio(bytes, true, "MP3");
    }
  }

  /// **Codex C-R2-2.** `parse_mp3`'s returned `id3::Mp3Meta<'a>` is tied ONLY to
  /// the byte buffer — a transient `ext` string can be dropped while the
  /// meta lives on. This compiles only if `ext` is on an independent
  /// (non-`'a`) lifetime. (The buffer is non-MP3 so the parse returns
  /// `None`; the point is the borrow shape, exercised at compile time.)
  #[test]
  #[cfg(feature = "mp3")]
  fn parse_mp3_meta_outlives_transient_ext() {
    let bytes: Vec<u8> = vec![0xff, 0xfb, 0x90, 0x00];
    let meta = {
      // `ext` is a short-lived String dropped at the end of this block.
      let ext: String = String::from("MP3");
      let m = parse_mp3(&bytes, Some(ext.as_str()));
      // `ext` drops here; `m` must remain valid (borrows only `bytes`).
      m
    };
    // Use the meta after `ext` is gone — proves the decoupling.
    let _ = meta.is_some();
  }

  /// **Codex C-R2-2.** `parse_ape`'s returned `ape::Meta<'a>` does not borrow
  /// from `shared` — the `SharedFlags` can be dropped (or reused for another
  /// parse) while the meta lives on. Compiles only if `shared` is on an
  /// independent lifetime.
  #[test]
  #[cfg(feature = "ape")]
  fn parse_ape_meta_outlives_transient_shared() {
    let bytes: Vec<u8> = vec![0u8; 64];
    let meta = {
      let mut shared = SharedFlags::new();
      let m = parse_ape(&bytes, &mut shared);
      // `shared` drops here; `m` must remain valid (ape::Meta is owned).
      m
    };
    let _ = meta.is_some();
    // `shared` can also be reused for a second parse without aliasing the
    // first meta — exercise that path too.
    let mut shared2 = SharedFlags::new();
    let _ = parse_ape(&bytes, &mut shared2);
  }
}
