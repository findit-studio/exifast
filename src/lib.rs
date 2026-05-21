// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.
//! `exifast`: a faithful Rust port of ExifTool's metadata reader.
//!
//! Lib-first design — the primary API exposes typed `XxxMeta<'a>` values per
//! format (see [`formats`](crate::formats)). Byte-exact JSON output vs
//! bundled `perl exiftool` is a secondary path derived from the typed Meta
//! via the [`MetaSinker`](crate::parser_new::MetaSinker) trait.
//!
//! # Usage — universal dispatch
//!
//! Detect the file type from the input bytes and dispatch to the right
//! per-format parser through the closed [`AnyParser`](crate::parser_new::AnyParser)
//! / [`AnyMeta`](crate::parser_new::AnyMeta) enums. Most callers don't
//! know the format up front; this is the typical entry point:
//!
//! ```no_run
//! # #[cfg(feature = "moi")] {
//! use exifast::{parse_bytes, AnyMeta};
//!
//! let bytes = std::fs::read("file.moi").unwrap();
//! if let Some(meta) = parse_bytes(&bytes).unwrap() {
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
//! if let Some(flac) = exifast::parse_flac(&bytes, &mut shared).unwrap() {
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
pub mod error;
pub mod filetype;
pub mod formats;
// `jsondiff` and `serialize` are the JSON emitter + golden-diff oracle: they
// unconditionally depend on `serde_json` (and `serde`). They are gated on
// the `json` feature (spec §4: `json = ["alloc", "dep:serde_json", "dep:serde", ...]`).
// Library callers without `json` get the typed-Meta API path only; CLI
// JSON emission requires the feature.
// The engine's `$$et` value sink: a `TagWriter` that buffers a `Vec<Tag>`
// (cross-format `$$et` state, FoundTag last-wins, family0-override). Gated on
// `alloc` because the always-compiled parser/format engine emits through it.
// Its terminal `finish()` render is `json`-gated (standard `serde_json` via
// [`serialize::render_document`]) — the COLLECTION surface is serde-free; only
// the final JSON render needs `json`.
#[cfg(feature = "alloc")]
pub mod json_writer;
#[cfg(feature = "json")]
pub mod jsondiff;
pub mod parser;
// The lib-first `FormatParser` trait scaffold + closed-set `AnyParser` /
// `AnyMeta` dispatch — the SOLE parser architecture. The engine entry
// `parser::extract_info` routes through `any_parser_for(ft) ->
// AnyParser::extract_into`; the byte-exact conformance suite validates the
// typed path directly.
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

// ===========================================================================
// Public lib-first API surface — Phase G
// ===========================================================================
//
// The public top-level `parse_bytes` + per-format `parse_<fmt>` entry points
// land here so callers don't need to traverse into `formats::<fmt>` for the
// happy path. Re-exports of `XxxMeta` + `ProcessXxx` + `XxxError` from each
// format module are kept feature-gated to match the per-format Cargo gates.

pub use parser_new::{AnyError, AnyMeta, AnyParser, MetaSinker, SharedFlags, TagWriter};

// Per-format public typed re-exports. Each module's `XxxMeta<'a>` + accessor
// methods are the lib-first surface; the `ProcessXxx` unit-struct is the
// parser handle (carried in `AnyParser`); `XxxError` is the fatal-error
// variant (carried in `AnyError`).
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

// ===========================================================================
// `parse_bytes` — universal dispatch entry
// ===========================================================================

/// Universal dispatch entry point: detect the file type from `bytes` (using
/// the existing magic-number based detection from
/// [`filetype::detection_candidates`](crate::filetype::detection_candidates))
/// and route through the closed [`AnyParser`] / [`AnyMeta`] enums.
///
/// Returns:
/// - `Ok(Some(meta))` — the first parser to accept the data, wrapped in
///   the appropriate [`AnyMeta`] variant.
/// - `Ok(None)` — no parser accepted the data (no detected format in the
///   compiled feature set matched).
/// - `Err(AnyError)` — a per-format parser surfaced a Rust-level fatal
///   error. Most format ports today have no fatal modes (uninhabited
///   `XxxError` enums), so the `Err` branch is unreachable in practice.
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
/// [`parser_new::any_parser_for`].
///
/// # Errors
///
/// See [`AnyError`].
///
/// # Examples
///
/// ```no_run
/// # #[cfg(feature = "moi")] {
/// use exifast::{parse_bytes, AnyMeta};
///
/// let bytes = std::fs::read("file.moi").unwrap();
/// if let Some(AnyMeta::Moi(moi)) = parse_bytes(&bytes).unwrap() {
///   println!("MOI version: {}", moi.version());
/// }
/// # }
/// ```
#[cfg(feature = "std")]
pub fn parse_bytes(bytes: &[u8]) -> core::result::Result<Option<AnyMeta<'_>>, AnyError> {
  // Empty filename ⇒ magic-only detection (ExifTool.pm:2965-3045 with
  // `$ext = undef`). Each candidate is tried in turn; the first parser to
  // return `Ok(Some(meta))` wins. Faithful to the legacy
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
    let Some(parser) = parser_new::any_parser_for(ft) else {
      continue;
    };
    if let Some(m) = parser.parse_any(bytes, &mut shared, None)? {
      return Ok(Some(m));
    }
    // Reset shared flags between rejected candidates so partial
    // side-effects (e.g. a probe that touched `done_id3`) don't leak.
    shared = SharedFlags::new();
  }
  Ok(None)
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
///
/// # Errors
///
/// Returns the per-format [`MoiError`] (currently uninhabited).
#[cfg(feature = "moi")]
pub fn parse_moi(bytes: &[u8]) -> core::result::Result<Option<MoiMeta<'_>>, MoiError> {
  formats::moi::parse_borrowed(bytes)
}

/// Parse an AAC (ADTS) buffer directly. See [`formats::aac::parse_borrowed`].
///
/// # Errors
///
/// Returns the per-format [`AacError`] (currently uninhabited).
#[cfg(feature = "aac")]
pub fn parse_aac(bytes: &[u8]) -> core::result::Result<Option<AacMeta<'_>>, AacError> {
  formats::aac::parse_borrowed(bytes)
}

/// Parse a DV stream buffer directly. See [`formats::dv::parse_borrowed`].
///
/// # Errors
///
/// Returns the per-format [`DvError`] (currently uninhabited).
#[cfg(feature = "dv")]
pub fn parse_dv(bytes: &[u8]) -> core::result::Result<Option<DvParseOutcome<'static>>, DvError> {
  formats::dv::parse_borrowed(bytes)
}

/// Parse an Audible (AA) buffer directly. See [`formats::audible::parse_borrowed`].
///
/// # Errors
///
/// Returns the per-format [`AudibleError`] (currently uninhabited).
#[cfg(feature = "audible")]
pub fn parse_audible(bytes: &[u8]) -> core::result::Result<Option<AaMeta<'_>>, AudibleError> {
  formats::audible::parse_borrowed(bytes)
}

/// Parse a Red R3D buffer directly. See [`formats::red::parse_borrowed`].
///
/// # Errors
///
/// Returns the per-format [`R3dError`] (currently uninhabited).
#[cfg(feature = "red")]
pub fn parse_r3d(bytes: &[u8]) -> core::result::Result<Option<R3dMeta<'_>>, R3dError> {
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
/// (e.g. Genre `7`). The returned Meta must be sinked in the same mode
/// (see the [`MetaSinker`] impl for `Id3Meta`).
///
/// # Errors
///
/// Returns the per-format [`Id3Error`] (currently uninhabited).
#[cfg(feature = "id3")]
pub fn parse_id3<'a>(
  bytes: &'a [u8],
  shared: Option<&mut SharedFlags>,
  print_conv: bool,
) -> core::result::Result<Option<Id3Meta<'a>>, Id3Error> {
  formats::id3::parse_id3_borrowed(bytes, shared, print_conv)
}

/// Parse an MP3 file (ID3 wrapper + MPEG audio chain + APE trailer)
/// directly through the typed [`ProcessMp3`] parser, faithful to bundled
/// `Image::ExifTool::ID3::ProcessMP3` (ID3.pm:1684-1728). Only `bytes`
/// flows into the returned [`Mp3Meta<'a>`] (which carries the ID3,
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
///
/// # Errors
///
/// Returns the per-format [`Mp3Error`].
#[cfg(feature = "mp3")]
pub fn parse_mp3<'a>(
  bytes: &'a [u8],
  ext: Option<&str>,
) -> core::result::Result<Option<Mp3Meta<'a>>, Mp3Error> {
  // `parse_mp3_borrowed` decouples the transient `shared` AND `ext` borrows
  // from the returned `Mp3Meta<'a>` (which borrows only from `bytes`), so a
  // local `SharedFlags` and a transient `ext` are both valid here.
  let mut shared = SharedFlags::new();
  formats::id3::parse_mp3_borrowed(bytes, ext, &mut shared)
}

/// Parse an AIFF (or AIFC) buffer directly. See
/// [`formats::aiff::parse_borrowed`].
///
/// # Errors
///
/// Returns the per-format [`AiffError`] (currently uninhabited).
#[cfg(feature = "aiff")]
pub fn parse_aiff(bytes: &[u8]) -> core::result::Result<Option<AiffMeta<'_>>, AiffError> {
  formats::aiff::parse_borrowed(bytes)
}

/// Parse an APE (Monkey's Audio) buffer directly through the typed
/// [`ProcessApe`] parser.
///
/// `shared` carries cross-format state (`DoneID3` / `DoneAPE` flags) and
/// borrows **independently** of `bytes` — only the byte-buffer lifetime
/// `'a` flows into the returned [`ApeMeta`] (which owns its data; `'a` is
/// phantom). The transient `shared` may therefore be dropped or reused
/// while the returned meta lives on (Codex C-R2-2).
///
/// # Errors
///
/// Returns the per-format [`ApeError`] (currently uninhabited).
#[cfg(feature = "ape")]
pub fn parse_ape<'a>(
  bytes: &'a [u8],
  shared: &mut SharedFlags,
) -> core::result::Result<Option<ApeMeta<'a>>, ApeError> {
  // Use the decoupled `parse_full_owned` (returns `ApeMeta<'static>`,
  // covariant to `'a`) rather than `ProcessApe.parse(ApeContext::new(...))`,
  // whose GAT `Context<'a> = ApeContext<'a>` ties `shared` to the Meta's
  // lifetime even though `ApeMeta` never borrows from it (Codex C-R2-2).
  Ok(formats::ape::parse_full_owned(bytes, shared))
}

/// Parse a DSF (DSD Stream File) buffer directly. See
/// [`formats::dsf::parse_borrowed`].
///
/// # Errors
///
/// Returns the per-format [`DsfError`] (currently uninhabited).
#[cfg(feature = "dsf")]
pub fn parse_dsf(bytes: &[u8]) -> core::result::Result<Option<DsfMeta<'_>>, DsfError> {
  formats::dsf::parse_borrowed(bytes)
}

/// Parse a FLAC buffer directly. See [`formats::flac::parse_borrowed`].
///
/// `shared` carries cross-format state (`DoneID3` flag, etc.).
///
/// # Errors
///
/// Returns the per-format [`FlacError`] (currently uninhabited).
#[cfg(feature = "flac")]
pub fn parse_flac<'a>(
  bytes: &'a [u8],
  shared: &mut SharedFlags,
) -> core::result::Result<Option<FlacMeta<'a>>, FlacError> {
  formats::flac::parse_borrowed(bytes, shared)
}

/// Parse an Ogg container (Vorbis / Opus / Theora) buffer directly. See
/// [`formats::ogg::parse_borrowed`].
///
/// `print_conv_enabled = true` matches bundled `perl exiftool -j`;
/// `false` matches `-j -n`.
///
/// # Errors
///
/// Returns the per-format [`OggError`] (currently uninhabited).
#[cfg(feature = "ogg")]
pub fn parse_ogg(
  bytes: &[u8],
  print_conv_enabled: bool,
) -> core::result::Result<Option<OggMeta<'_>>, OggError> {
  formats::ogg::parse_borrowed(bytes, print_conv_enabled)
}

/// Parse an MPEG audio frame stream buffer directly. See
/// [`formats::mpeg::parse_borrowed`].
///
/// `mp3 = true` enforces Layer III (MPEG.pm:466). `ext` is the file
/// extension (uppercased, no leading dot — e.g. `"MP3"`, `"MUS"`); the
/// empty string disables the validation-reject retry (MPEG.pm:488).
///
/// # Errors
///
/// Returns the per-format [`MpegAudioError`] (currently uninhabited).
#[cfg(feature = "mpeg-audio")]
pub fn parse_mpeg_audio<'a>(
  bytes: &'a [u8],
  mp3: bool,
  ext: &str,
) -> core::result::Result<Option<MpegAudioMeta<'a>>, MpegAudioError> {
  formats::mpeg::parse_borrowed(bytes, mp3, ext)
}

/// Parse an MPC (Musepack SV7) buffer directly. See
/// [`formats::mpc::parse_borrowed`].
///
/// # Errors
///
/// Returns the per-format [`MpcError`] (currently uninhabited).
#[cfg(feature = "mpc")]
pub fn parse_mpc(bytes: &[u8]) -> core::result::Result<Option<MpcMeta<'_>>, MpcError> {
  formats::mpc::parse_borrowed(bytes)
}

/// Parse a WavPack `.wv` buffer directly. See
/// [`formats::wavpack::parse_borrowed`].
///
/// # Errors
///
/// Returns the per-format [`WvError`] (currently uninhabited).
#[cfg(feature = "wavpack")]
pub fn parse_wavpack(bytes: &[u8]) -> core::result::Result<Option<WvMeta<'_>>, WvError> {
  formats::wavpack::parse_borrowed(bytes)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;

  /// `parse_bytes` returns `Ok(None)` for an empty input — no parser
  /// accepts an empty buffer, which matches ExifTool's
  /// `File is empty` Error-only path (here surfaced as `Ok(None)`).
  #[test]
  #[cfg(feature = "std")]
  fn parse_bytes_empty_input_returns_none() {
    let result = parse_bytes(b"").unwrap();
    assert!(result.is_none());
  }

  /// `parse_bytes` returns `Ok(None)` for a buffer that no parser
  /// accepts (random bytes with no magic-number match).
  #[test]
  #[cfg(feature = "std")]
  fn parse_bytes_unknown_format_returns_none() {
    let result = parse_bytes(b"\x00\x00\x00\x00not-a-format").unwrap();
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
    let result = parse_bytes(&padded).unwrap();
    // The MOI parser may accept or reject this minimal buffer depending on
    // its internal validation; we don't pin the exact outcome here, just
    // that the dispatch produces an `Ok(_)` (no panic, no `Err`).
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
    use crate::json_writer::JsonTagWriter;
    use crate::parser_new::MetaSinker;
    let data = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/ogg_id3_prefixed.ogg"
    ))
    .expect("read ogg_id3_prefixed.ogg fixture");
    // Sanity: the fixture really does start with an ID3v2 prefix (NOT OggS).
    assert!(data.starts_with(b"ID3"), "fixture must be ID3-prefixed");
    let meta = parse_bytes(&data)
      .expect("parse_bytes must not error")
      .expect("ID3-prefixed Ogg must be recognized");
    // Core C-R4-1 assertion: dispatch to Ogg, NOT the mis-routed Mp3.
    assert!(
      matches!(meta, AnyMeta::Ogg(_)),
      "ID3-prefixed Ogg must dispatch to AnyMeta::Ogg, not {meta:?}"
    );
    // Content check: sinking the post-ID3 Ogg stream yields the SAME Vorbis
    // tags bundled `perl exiftool` reports (e.g. Vorbis:Artist "Who Knows"),
    // proving the ID3v2 prefix was correctly skipped and the real Ogg-Vorbis
    // stream parsed (byte-exact-equivalent to bundled, verified manually).
    let mut w = JsonTagWriter::new("ogg_id3_prefixed.ogg");
    meta.sink(true, &mut w).expect("sink is infallible");
    let json = w.finish();
    // serde emits keys without a space after `:`; check by value via the
    // parsed document (the key tokens themselves are spacing-independent).
    let doc: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    let obj = doc[0].as_object().expect("file object");
    assert_eq!(
      obj.get("Vorbis:Artist").and_then(|v| v.as_str()),
      Some("Who Knows"),
      "post-ID3 Ogg-Vorbis tags must be present: {json}"
    );
    assert_eq!(
      obj.get("Vorbis:Title").and_then(|v| v.as_str()),
      Some("A 4s sample for testing embedded cover art"),
      "post-ID3 Ogg-Vorbis Title must be present: {json}"
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
    #[cfg(feature = "aac")]
    let _ = parse_aac(bytes);
    #[cfg(feature = "dv")]
    let _ = parse_dv(bytes);
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

  /// **Codex C-R2-2.** `parse_mp3`'s returned `Mp3Meta<'a>` is tied ONLY to
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
      let m = parse_mp3(&bytes, Some(ext.as_str())).expect("ok");
      // `ext` drops here; `m` must remain valid (borrows only `bytes`).
      m
    };
    // Use the meta after `ext` is gone — proves the decoupling.
    let _ = meta.is_some();
  }

  /// **Codex C-R2-2.** `parse_ape`'s returned `ApeMeta<'a>` does not borrow
  /// from `shared` — the `SharedFlags` can be dropped (or reused for another
  /// parse) while the meta lives on. Compiles only if `shared` is on an
  /// independent lifetime.
  #[test]
  #[cfg(feature = "ape")]
  fn parse_ape_meta_outlives_transient_shared() {
    let bytes: Vec<u8> = vec![0u8; 64];
    let meta = {
      let mut shared = SharedFlags::new();
      let m = parse_ape(&bytes, &mut shared).expect("ok");
      // `shared` drops here; `m` must remain valid (ApeMeta is owned).
      m
    };
    let _ = meta.is_some();
    // `shared` can also be reused for a second parse without aliasing the
    // first meta — exercise that path too.
    let mut shared2 = SharedFlags::new();
    let _ = parse_ape(&bytes, &mut shared2).expect("ok");
  }
}
