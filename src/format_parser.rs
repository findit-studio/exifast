// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! Lib-first `FormatParser` trait + closed-set [`AnyParser`] / [`AnyMeta`]
//! dispatch — the sole parser architecture. The engine entry
//! [`crate::parser::extract_info`] routes through [`any_parser_for`] →
//! `AnyParser::extract_into`. Design spec at
//! `docs/superpowers/specs/2026-05-21-lib-first-formatparser-design.md`.
//!
//! The central pieces, per spec §6:
//!
//! - [`FormatParser`] — the central parser trait with associated `Meta`,
//!   `Context<'a>`, and `Error` types. Sealed via [`parser_sealed::Sealed`]
//!   so downstream crates cannot add format arms.
//! - Each `Meta` type's inherent `serialize_tags(print_conv, &mut
//!   crate::tagmap::TagMap)` method — the typed-Meta rendering seam that emits
//!   the format's `(Group1, Name, value)` tags into the inline
//!   [`crate::tagmap::TagMap`] sink (which applies the faithful first-wins
//!   dedup). [`AnyMeta::serialize_tags`] dispatches across the closed set and
//!   flattens chained sub-Metas. The optional [`Rendered`] wrapper drives it
//!   for the `-j`/`-n` serde view.
//! - [`SharedFlags`] — cross-format shared state (DoneID3 / DoneAPE / file-type
//!   stack) threaded through chained parsers.
//!
//! The closed-set enums [`AnyParser`] and [`AnyMeta`] dispatch over the
//! runtime-keyed parser registry. Each format adds an arm in Phase E (MOI)
//! / Phase F (everything else). Both are `#[non_exhaustive]` so new format
//! arms are additive.

pub(crate) mod parser_sealed {
  /// Sealed marker for the new [`super::FormatParser`] trait. Downstream
  /// crates cannot implement the trait because they cannot name this
  /// type (the `parser_sealed` module is `pub(crate)`, accessible only
  /// to in-crate format modules that implement [`super::FormatParser`]).
  pub trait Sealed {}
}

/// One ported format parser. Each format owns its `Meta` (typed output),
/// `Context<'a>` (per-format input view — leaves take `&'a [u8]`, chained
/// formats take a richer struct with shared mutable state), and `Error`.
///
/// `parse` returns:
/// - `Ok(Some(meta))` — this is the format; here are the tags. (Perl `return 1`)
/// - `Ok(None)`       — not this format, try the next detection candidate.
///   (Perl `return 0`)
/// - `Err(e)`         — Rust-level fatal (not Perl-modeled — Perl uses
///   `$et->Warn`/`$et->Error` which are recorded as tags in `Meta` regardless
///   of return).
///
/// IMPORTANT: side effects on the shared [`SharedFlags`] (held inside the
/// per-format `Context`) PERSIST regardless of return value, faithful to
/// ExifTool's `$self` model. Preserved from the old `FormatParser` trait
/// (see `[[exifast-phase2-forward-items]]`).
///
/// The trait is **sealed** (cannot be implemented by downstream crates). The
/// closed-set discipline is required by the [`AnyParser`] / [`AnyMeta`] enum
/// dispatch model (associated types are not dyn-compatible, so dispatch
/// happens via a match on a closed enum). New formats are added inside the
/// crate by:
///
/// 1. Implementing [`parser_sealed::Sealed`] on the new parser type;
/// 2. Implementing this `FormatParser` trait on it;
/// 3. Adding a `#[cfg(feature = "<fmt>")]`-gated arm to [`AnyParser`],
///    [`AnyMeta`], and [`AnyMeta`]'s `serialize_tags` impl.
pub trait FormatParser: parser_sealed::Sealed {
  /// The typed metadata structure this parser produces on a successful
  /// parse, as a **generic associated type** parameterized by the input
  /// borrow lifetime `'a`. Meta types borrow from the input bytes
  /// (`Meta<'a> = XxxMeta<'a>`), holding `&'a str` / primitive integers /
  /// `core::time::Duration` / `jiff::civil::DateTime` for no-alloc
  /// compatibility.
  ///
  /// The GAT threads the input lifetime through [`Self::parse`] so the
  /// returned Meta borrows directly from the `Context<'a>` it was parsed
  /// from — no `'static` upgrade, no `Box::leak`. Library callers consuming
  /// `parse_bytes` get a zero-allocation `AnyMeta<'a>` tied to their input
  /// buffer (Codex AF2).
  type Meta<'a>
  where
    Self: 'a;
  /// Per-format input view. Leaf formats (MOI, AAC, DV, Audible) use
  /// `&'a [u8]`; chained formats (ID3, APE, MP3, …) use a struct
  /// wrapping `&'a [u8]` + `&'a mut SharedFlags`.
  type Context<'a>
  where
    Self: 'a;
  /// Rust-level fatal error (distinct from Perl `Warn`/`Error` tags, which
  /// belong to `Meta` and surface through the typed `serialize_tags` emission
  /// into [`crate::tagmap::TagMap`]).
  type Error;

  /// Run the parser on a per-format `Context`. The returned `Meta<'a>`
  /// borrows from the same `'a` as the input `Context`. See trait docs for
  /// return value semantics.
  fn parse<'a>(&self, ctx: Self::Context<'a>) -> Result<Option<Self::Meta<'a>>, Self::Error>;
}

/// Cross-format shared state. Threaded through chained parsers
/// (ID3 → APE, APE → ID3, DSF → ID3, etc.). Holds the flags that
/// bundled ExifTool keeps in `$$et` for cross-recursion gating.
///
/// **Storage choice for `file_type_stack`:** per spec §11 open question 3,
/// the file-type stack depth observed in bundled ExifTool is ≤ 2
/// (ID3 → APE chain). This struct uses `[Option<&'static str>; 4]` —
/// fixed inline storage, zero dependencies, no_std-clean. The size bound
/// of 4 leaves headroom over the observed depth. If a future chain
/// exceeds 4 it will panic in [`Self::push_file_type`]; we'll grow the
/// constant if/when that ever happens.
///
/// D8 convention: no public fields; accessors only.
#[derive(Debug, Default, Clone)]
pub struct SharedFlags {
  /// `$$et{DoneID3}` — `None` until `ProcessID3` runs (`unless ($$et{DoneID3})`
  /// recursion guard, ID3.pm:1435); `Some(n)` once run, with `n` the ID3v1
  /// trailer size in bytes (128 + 227 if Enhanced TAG, etc.; `0` when ID3v2
  /// was found but no v1 trailer — ID3.pm:1436 sets `1` as a truthy "ran"
  /// marker, which the APE shift's `> 1` guard treats identically to `0`).
  /// Read by `APE.pm:169` (`$footPos -= $$et{DoneID3} if $$et{DoneID3} > 1`)
  /// for the footer-position shift. Mirrors the legacy
  /// [`crate::value::Metadata::done_id3`] `Option<usize>` shape so the bridge
  /// and the typed chained dispatch agree on the not-run vs ran-no-trailer
  /// distinction (Codex AF1/BF3).
  done_id3: Option<usize>,
  /// The post-ID3v2-header file position (bundled `$hdrEnd`) recorded when
  /// the typed `ProcessID3` pass runs. The bundled audio-format loop seeks
  /// to this offset (`$raf->Seek($hdrEnd, 0)`, ID3.pm:1590) before the
  /// recursive `ProcessMP3`, so the DoneID3-skip path of `ProcessMP3` scans
  /// MPEG from `$hdrEnd`, NOT from offset 0. Carry it here so a chained
  /// typed caller that pre-ran ID3 over the FULL buffer still scans the
  /// POST-ID3 region for an MPEG frame (Codex B-R3-1). `None` until a typed
  /// ID3 pass has run.
  id3_hdr_end: Option<usize>,
  /// `$$et{DoneAPE}` — set by APE after running, read by `ID3.pm:1723`
  /// to gate the wrapper APE-trailer fallback.
  done_ape: bool,
  /// `$$et{FILE_TYPE}` — file-type stack for the audio-format loop
  /// (`ID3.pm:1582-1601`). Read by chained parsers to know who dispatched
  /// them. Fixed-capacity `[Option<&'static str>; 4]` per the storage
  /// note on this struct.
  file_type_stack: [Option<&'static str>; 4],
  /// Number of occupied slots in `file_type_stack` (the stack "len").
  file_type_stack_len: usize,
}

impl SharedFlags {
  /// Construct empty shared flags (alias of [`Default::default`]).
  #[must_use]
  #[inline(always)]
  pub fn new() -> Self {
    Self::default()
  }

  /// `$$et{DoneID3}` — `None` until `ProcessID3` runs; `Some(n)` once run,
  /// with `n` the ID3v1-trailer size in bytes (`Some(0)` ⇒ ran but no v1
  /// trailer). The `unless ($$et{DoneID3})` recursion guard (ID3.pm:1435,
  /// APE.pm:124) maps to `is_none()`; the APE.pm:169 footer shift maps to
  /// `done_id3().is_some_and(|n| n > 1)`. Mirrors
  /// [`crate::value::Metadata::done_id3`] (Codex AF1/BF3).
  #[must_use]
  #[inline(always)]
  pub const fn done_id3(&self) -> Option<usize> {
    self.done_id3
  }

  /// Set `$$et{DoneID3} = trailer_size`. Called by the ID3 parser after a
  /// v1 trailer is consumed (pass `0` for the "ID3v2 found, no v1 trailer"
  /// case — ID3.pm:1436 sets the truthy `1` marker; the APE `> 1` arithmetic
  /// guard treats `0` and `1` identically, so we normalize to `0`). Returns
  /// `&mut Self` to chain (§3).
  #[inline(always)]
  pub const fn set_done_id3(&mut self, trailer_size: usize) -> &mut Self {
    self.done_id3 = Some(trailer_size);
    self
  }

  /// The post-ID3v2-header file position (bundled `$hdrEnd`) recorded by the
  /// typed `ProcessID3` pass. `None` until a typed ID3 pass has run. The
  /// DoneID3-skip path of the typed `ProcessMP3` reads this to scan MPEG
  /// from `$hdrEnd` instead of offset 0, faithful to the audio-format loop's
  /// `$raf->Seek($hdrEnd, 0)` (ID3.pm:1590) before recursive `ProcessMP3`
  /// (Codex B-R3-1).
  #[must_use]
  #[inline(always)]
  pub const fn id3_hdr_end(&self) -> Option<usize> {
    self.id3_hdr_end
  }

  /// Record the post-ID3v2-header file position (bundled `$hdrEnd`). Called
  /// by the typed ID3 pass after it determines the header end so a later
  /// chained `ProcessMP3` skip path can scan MPEG from there (Codex B-R3-1).
  /// Returns `&mut Self` to chain (§3).
  #[inline(always)]
  pub const fn set_id3_hdr_end(&mut self, hdr_end: usize) -> &mut Self {
    self.id3_hdr_end = Some(hdr_end);
    self
  }

  /// `$$et{DoneAPE}` — APE-trailer-already-handled flag, gates the
  /// wrapper fallback in `ID3.pm:1723-1726`.
  #[must_use]
  #[inline(always)]
  pub const fn done_ape(&self) -> bool {
    self.done_ape
  }

  /// Set `$$et{DoneAPE}`. Called by the APE parser after running. Returns
  /// `&mut Self` to chain (§3).
  #[inline(always)]
  pub const fn set_done_ape(&mut self, value: bool) -> &mut Self {
    self.done_ape = value;
    self
  }

  /// View the current file-type stack as a slice (in push order). `_slice`
  /// projection of the fixed-capacity backing array (§3).
  #[must_use]
  #[inline(always)]
  pub const fn file_type_stack_slice(&self) -> &[Option<&'static str>] {
    self.file_type_stack.split_at(self.file_type_stack_len).0
  }

  /// Push a file-type tag onto the stack. Panics if the stack is full
  /// (current cap = 4; see the struct doc). Returns `&mut Self` to chain (§3).
  #[inline(always)]
  pub const fn push_file_type(&mut self, file_type: &'static str) -> &mut Self {
    assert!(
      self.file_type_stack_len < self.file_type_stack.len(),
      "SharedFlags::push_file_type: stack overflow (cap=4, observed depth in bundled ExifTool is ≤ 2)",
    );
    self.file_type_stack[self.file_type_stack_len] = Some(file_type);
    self.file_type_stack_len += 1;
    self
  }

  /// Pop the most recent file-type tag, returning it if the stack was
  /// non-empty.
  #[inline(always)]
  pub const fn pop_file_type(&mut self) -> Option<&'static str> {
    if self.file_type_stack_len == 0 {
      return None;
    }
    self.file_type_stack_len -= 1;
    self.file_type_stack[self.file_type_stack_len].take()
  }

  /// Peek the most recent file-type tag without popping it.
  #[must_use]
  #[inline(always)]
  pub const fn current_file_type(&self) -> Option<&'static str> {
    if self.file_type_stack_len == 0 {
      None
    } else {
      self.file_type_stack[self.file_type_stack_len - 1]
    }
  }
}

/// Closed-set enum dispatch over the runtime-keyed parser registry.
/// Each format adds an arm in Phase E (MOI) / Phase F (all others).
///
/// `#[non_exhaustive]` ensures consumers cannot exhaustively match on
/// the enum across crate-feature combinations — new format arms are
/// additive within the crate, but no caller can rely on a fixed set.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub enum AnyParser {
  /// MOI (Phase E pilot — camcorder MOD info sidecar).
  #[cfg(feature = "moi")]
  Moi(crate::formats::moi::ProcessMoi),
  /// AAC (Phase F1 — ADTS audio).
  #[cfg(feature = "aac")]
  Aac(crate::formats::aac::ProcessAac),
  /// DV (Phase F1 — DV video stream).
  #[cfg(feature = "dv")]
  Dv(crate::formats::dv::ProcessDv),
  /// Audible (AA) (Phase F1 — DRM'd audiobook).
  #[cfg(feature = "audible")]
  Aa(crate::formats::audible::ProcessAa),
  /// Canon CRW (CIFF) raw container.
  #[cfg(feature = "crw")]
  Crw(crate::formats::crw::ProcessCrw),
  /// Red R3D (Phase F1 — Redcode video).
  #[cfg(feature = "red")]
  R3D(crate::formats::red::ProcessR3D),
  /// ID3 directory parser (Phase F2 — ID3v1 + ID3v2 unified).
  #[cfg(feature = "id3")]
  Id3(crate::formats::id3::ProcessId3),
  /// MP3 wrapper parser (Phase F2 — ID3 + audio-frame chain).
  #[cfg(feature = "mp3")]
  Mp3(crate::formats::id3::ProcessMp3),
  /// AIFF (Phase F3 — Audio Interchange File Format / AIFC / DjVu).
  #[cfg(feature = "aiff")]
  Aiff(crate::formats::aiff::ProcessAiff),
  /// APE (Phase F3 — Monkey's Audio, chains ID3v1/v2).
  #[cfg(feature = "ape")]
  Ape(crate::formats::ape::ProcessApe),
  /// DSF (Phase F3 — DSD Stream File, chains ID3v2 trailer).
  #[cfg(feature = "dsf")]
  Dsf(crate::formats::dsf::ProcessDsf),
  /// FLAC (Phase F3 — Free Lossless Audio Codec).
  #[cfg(feature = "flac")]
  Flac(crate::formats::flac::ProcessFlac),
  /// H264 (FORMATS.md row 16 — H.264 NAL stream; engine-only, no file type).
  #[cfg(feature = "h264")]
  H264(crate::formats::h264::ProcessH264),
  /// Flash FLV (Phase F-wave-a — Flash Video).
  #[cfg(feature = "flash")]
  Flv(crate::formats::flash::ProcessFlv),
  /// Ogg (Phase F4 — Ogg container + Vorbis comments + Opus + Theora delegation).
  #[cfg(feature = "ogg")]
  Ogg(crate::formats::ogg::ProcessOgg),
  /// PNG (FORMATS.md row 11 — Portable Network Graphics container + eXIf).
  #[cfg(feature = "png")]
  Png(crate::formats::png::ProcessPng),
  /// Real (RM/RV/RMVB/RA/RAM/RPM — RealMedia + RealAudio container + Metafile).
  #[cfg(feature = "real")]
  Real(crate::formats::real::ProcessReal),
  /// MPEG audio (Phase F4 — MP3 / MP2 / MUS frame parser + Xing/LAME tail).
  #[cfg(feature = "mpeg-audio")]
  MpegAudio(crate::formats::mpeg::ProcessMpegAudio),
  /// MPC (Phase F5 — Musepack SV7/SV8 audio, chains ID3 + APE).
  #[cfg(feature = "mpc")]
  Mpc(crate::formats::mpc::ProcessMpc),
  /// WavPack (Phase F5 — `.wv` / `.wvp` hybrid-lossless audio, chains ID3 + APE).
  #[cfg(feature = "wavpack")]
  Wv(crate::formats::wavpack::ProcessWv),
  /// Matroska (FORMATS.md row 23 — MKV/MKA/MKS/WebM EBML container).
  #[cfg(feature = "matroska")]
  Matroska(crate::formats::matroska::ProcessMatroska),
  /// QuickTime (MOV/MP4/M4A/M4V/3GP/3G2 — ISO-BMFF box container).
  #[cfg(feature = "quicktime")]
  QuickTime(crate::formats::quicktime::ProcessMov),
  /// MXF (FORMATS.md row 24 — Material Exchange Format KLV container).
  #[cfg(feature = "mxf")]
  Mxf(crate::formats::mxf::ProcessMxf),
  /// Exif/TIFF (FORMATS.md row 13 — a standalone TIFF file IS an Exif/TIFF
  /// block; GPS row 14 is its sub-IFD, decoded through the same walker).
  #[cfg(feature = "exif")]
  Exif(crate::exif::ProcessExif),
}

/// Closed-set enum of every format's `Meta` output. Mirrors [`AnyParser`].
///
/// `#[non_exhaustive]` ensures consumers cannot exhaustively match on the
/// enum across crate-feature combinations — new format arms are additive
/// within the crate, but no caller can rely on a fixed set.
///
/// The lifetime `'a` is anchored by the real format arms (which all carry
/// `XxxMeta<'a>`). When NO format feature is enabled, every arm is
/// `cfg`'d out and `'a` would be unused (a hard `E0392` error), so the
/// [`AnyMeta::_Phantom`] variant — present ONLY in a no-format build —
/// anchors `'a`. Under the `all-formats` default the phantom is `cfg`'d
/// OUT (Codex CF3).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum AnyMeta<'a> {
  /// MOI (Phase E pilot).
  #[cfg(feature = "moi")]
  Moi(crate::formats::moi::Meta<'a>),
  /// AAC (Phase F1).
  #[cfg(feature = "aac")]
  Aac(crate::formats::aac::Meta<'a>),
  /// DV (Phase F1). Carries the [`crate::formats::dv::ParseOutcome`]
  /// because DV has TWO accept paths (unrecognized-profile warn vs.
  /// full data); the closed-enum carry must distinguish them so the
  /// sink can warn on the former without emitting DV:* tags.
  #[cfg(feature = "dv")]
  Dv(crate::formats::dv::ParseOutcome<'a>),
  /// Audible (AA) (Phase F1).
  #[cfg(feature = "audible")]
  Aa(crate::formats::audible::Meta<'a>),
  /// Canon CRW (CIFF) raw container. The typed [`crate::metadata::CrwMeta`]
  /// carries the `%CanonRaw::Main` scalar records + the raw blocks of the
  /// records dispatched to the ported `Canon::*` MakerNote sub-tables (decoded
  /// to `Canon:*` tags at serialize time). `'a` is a phantom (`CrwMeta` owns
  /// its data — every value is transformed during the CIFF walk).
  #[cfg(feature = "crw")]
  Crw(crate::metadata::CrwMeta<'a>),
  /// Red R3D (Phase F1).
  #[cfg(feature = "red")]
  R3d(crate::formats::red::Meta<'a>),
  /// ID3 directory metadata (Phase F2). The [`crate::formats::id3::ProcessId3`]
  /// `FormatParser` impl produces a borrowed `Id3Meta<'a>` via the
  /// [`FormatParser::Meta`] GAT (Codex AF2; `'a` is phantom there since
  /// `Id3Meta` owns its strings).
  #[cfg(feature = "id3")]
  Id3(crate::formats::id3::Id3Meta<'a>),
  /// MP3 wrapper metadata (Phase F2). Wraps [`crate::formats::id3::Id3Meta`]
  /// plus the typed MPEG-audio + APE-trailer sub-Metas (Codex BF1/CF1);
  /// the MPEG-audio sub-Meta borrows its `encoder` field from the input.
  #[cfg(feature = "mp3")]
  Mp3(crate::formats::id3::Mp3Meta<'a>),
  /// AIFF (Phase F3).
  #[cfg(feature = "aiff")]
  Aiff(crate::formats::aiff::Meta<'a>),
  /// APE (Phase F3).
  #[cfg(feature = "ape")]
  Ape(crate::formats::ape::Meta<'a>),
  /// DSF (Phase F3).
  #[cfg(feature = "dsf")]
  Dsf(crate::formats::dsf::Meta<'a>),
  /// FLAC (Phase F3).
  #[cfg(feature = "flac")]
  Flac(crate::formats::flac::Meta<'a>),
  /// H264 (FORMATS.md row 16 — H.264 NAL stream). Engine-only: there is no
  /// `H264` file type, so this variant is never produced by
  /// [`crate::parser::extract_info`]; it exists for a future M2TS / MPEG
  /// port to carry an H.264 sub-Meta through the closed dispatch.
  #[cfg(feature = "h264")]
  H264(crate::formats::h264::H264Meta<'a>),
  /// Flash FLV (Phase F-wave-a).
  #[cfg(feature = "flash")]
  Flv(crate::formats::flash::Meta<'a>),
  /// Ogg (Phase F4 — Ogg container + Vorbis comments). The
  /// [`crate::formats::ogg::ProcessOgg`] `FormatParser` impl produces a
  /// borrowed `ogg::Meta<'a>` via the [`FormatParser::Meta`] GAT (Codex
  /// AF2; `'a` is phantom there since `ogg::Meta` owns its data).
  #[cfg(feature = "ogg")]
  Ogg(crate::formats::ogg::Meta<'a>),
  /// PNG (FORMATS.md row 11 — Portable Network Graphics with embedded
  /// `eXIf` chunk). The typed [`crate::metadata::PngMeta`] carries the
  /// IHDR/pHYs/iCCP-name/text-record state directly; the captured
  /// `eXIf` TIFF block is dispatched to [`crate::exif::parse_exif_block`]
  /// at serialize time.
  #[cfg(feature = "png")]
  Png(crate::metadata::PngMeta<'a>),
  /// Real (RM/RV/RMVB/RA/RAM/RPM). The typed
  /// [`crate::formats::real::ProcessReal`] handles both the RealMedia
  /// chunked container AND the RealAudio fixed-layout header, including
  /// the embedded RJMD metadata + ID3v1 trailer on RM files.
  #[cfg(feature = "real")]
  Real(crate::formats::real::RealMeta<'a>),
  /// MPEG audio (Phase F4 — frame parser, Xing/LAME tail). Produced as
  /// `mpeg::AudioMeta<'static>` by [`crate::formats::mpeg::ProcessMpegAudio`].
  #[cfg(feature = "mpeg-audio")]
  MpegAudio(crate::formats::mpeg::AudioMeta<'a>),
  /// MPC (Phase F5 — Musepack SV7/SV8 audio).
  #[cfg(feature = "mpc")]
  Mpc(crate::formats::mpc::Meta<'a>),
  /// WavPack (Phase F5 — `.wv` / `.wvp` hybrid-lossless audio).
  #[cfg(feature = "wavpack")]
  Wv(crate::formats::wavpack::Meta<'a>),
  /// Matroska (FORMATS.md row 23).
  #[cfg(feature = "matroska")]
  Matroska(crate::formats::matroska::Meta<'a>),
  /// QuickTime (MOV/MP4/M4A/M4V/3GP/3G2 — SP1 core structural atoms).
  #[cfg(feature = "quicktime")]
  QuickTime(crate::formats::quicktime::Meta<'a>),
  /// MXF (FORMATS.md row 24 — Material Exchange Format). `MxfMeta` owns its
  /// data (every value is transformed during the KLV walk); `'a` is a
  /// phantom there, kept for GAT uniformity.
  #[cfg(feature = "mxf")]
  Mxf(crate::formats::mxf::MxfMeta<'a>),
  /// Exif/TIFF (FORMATS.md row 13 — typed `ExifMeta<'a>` carrying the IFD
  /// chain's tags + the captured-but-deferred MakerNote blob). GPS sub-IFD
  /// tags (row 14) are inside this same Meta.
  #[cfg(feature = "exif")]
  Exif(crate::exif::ExifMeta<'a>),
  /// Lifetime anchor for a no-format build (Codex CF3). When at least one
  /// format feature is enabled this variant is `cfg`'d OUT (the real arms
  /// anchor `'a`); it exists only so a `--features std` build with no
  /// format gate still type-checks `AnyMeta<'a>` instead of failing with
  /// `E0392` (unused lifetime parameter). It is uninhabitable from safe
  /// code (`PhantomData` payload, `#[doc(hidden)]`).
  #[cfg(not(any(
    feature = "moi",
    feature = "aac",
    feature = "dv",
    feature = "audible",
    feature = "crw",
    feature = "red",
    feature = "id3",
    feature = "mp3",
    feature = "aiff",
    feature = "ape",
    feature = "dsf",
    feature = "flac",
    feature = "h264",
    feature = "flash",
    feature = "ogg",
    feature = "png",
    feature = "real",
    feature = "mpeg-audio",
    feature = "mpc",
    feature = "wavpack",
    feature = "matroska",
    feature = "quicktime",
    feature = "mxf",
    feature = "exif",
  )))]
  #[doc(hidden)]
  _Phantom(core::marker::PhantomData<&'a ()>),
}

#[cfg(feature = "alloc")]
impl AnyMeta<'_> {
  /// Collect this typed Meta's FORMAT [`EmittedTag`](crate::emit::EmittedTag)
  /// stream — the SINGLE source of the tag dispatch shared by
  /// [`serialize_tags`](Self::serialize_tags) (the `-j`/`-n` JSON path) and
  /// [`iter_tags`](Self::iter_tags) (the public generic-extraction path).
  ///
  /// Each arm is exactly `m.tags(mode).collect()` — the format's
  /// [`Taggable`](crate::emit::Taggable) stream, already rendered for `mode`
  /// (PrintConv vs ValueConv), with each sub-Meta's tags spliced in the
  /// faithful `FoundTag` order inside its own `tags()`. NO warning/error
  /// logic here (tags only); the diagnostics live in
  /// [`drain_diagnostics`](Self::drain_diagnostics).
  ///
  /// `#[non_exhaustive]` on `AnyMeta` plus per-format `cfg(feature)` gates
  /// makes a `_`-less match exhaustive when ≥1 format feature is on (the real
  /// arms), and when NO format feature is on (only the `_Phantom` arm, Codex
  /// CF3). The `all-formats` default takes the former path; the phantom arm
  /// keeps the no-format build type-checking.
  fn collect_emitted(&self, mode: crate::emit::ConvMode) -> std::vec::Vec<crate::emit::EmittedTag> {
    use crate::emit::Taggable as _;
    match self {
      #[cfg(feature = "moi")]
      AnyMeta::Moi(m) => m.tags(mode).collect(),
      #[cfg(feature = "aac")]
      AnyMeta::Aac(m) => m.tags(mode).collect(),
      // DV: only the `Meta` variant yields tags; `UnrecognizedProfile`
      // (DV.pm:188 — Warn + return 1 without DV:* tags) yields NONE — its
      // warning is drained by `drain_diagnostics`.
      #[cfg(feature = "dv")]
      AnyMeta::Dv(o) => match o {
        crate::formats::dv::ParseOutcome::UnrecognizedProfile => std::vec::Vec::new(),
        crate::formats::dv::ParseOutcome::Meta(m) => m.tags(mode).collect(),
      },
      #[cfg(feature = "audible")]
      AnyMeta::Aa(m) => m.tags(mode).collect(),
      #[cfg(feature = "crw")]
      AnyMeta::Crw(m) => m.tags(mode).collect(),
      #[cfg(feature = "red")]
      AnyMeta::R3d(m) => m.tags(mode).collect(),
      #[cfg(feature = "id3")]
      AnyMeta::Id3(m) => m.tags(mode).collect(),
      #[cfg(feature = "mp3")]
      AnyMeta::Mp3(m) => m.tags(mode).collect(),
      #[cfg(feature = "aiff")]
      AnyMeta::Aiff(m) => m.tags(mode).collect(),
      #[cfg(feature = "ape")]
      AnyMeta::Ape(m) => m.tags(mode).collect(),
      #[cfg(feature = "dsf")]
      AnyMeta::Dsf(m) => m.tags(mode).collect(),
      #[cfg(feature = "flac")]
      AnyMeta::Flac(m) => m.tags(mode).collect(),
      #[cfg(feature = "h264")]
      AnyMeta::H264(m) => m.tags(mode).collect(),
      #[cfg(feature = "flash")]
      AnyMeta::Flv(m) => m.tags(mode).collect(),
      #[cfg(feature = "ogg")]
      AnyMeta::Ogg(m) => m.tags(mode).collect(),
      #[cfg(feature = "png")]
      AnyMeta::Png(m) => m.tags(mode).collect(),
      #[cfg(feature = "real")]
      AnyMeta::Real(m) => m.tags(mode).collect(),
      #[cfg(feature = "mpeg-audio")]
      AnyMeta::MpegAudio(m) => m.tags(mode).collect(),
      #[cfg(feature = "mpc")]
      AnyMeta::Mpc(m) => m.tags(mode).collect(),
      #[cfg(feature = "wavpack")]
      AnyMeta::Wv(m) => m.tags(mode).collect(),
      #[cfg(feature = "matroska")]
      AnyMeta::Matroska(m) => m.tags(mode).collect(),
      #[cfg(feature = "quicktime")]
      AnyMeta::QuickTime(m) => m.tags(mode).collect(),
      #[cfg(feature = "mxf")]
      AnyMeta::Mxf(m) => m.tags(mode).collect(),
      // EXIF's `tags()` yields `File:ExifByteOrder` first (when a TIFF block
      // was processed), then the IFD-walk entries, then the MakerNote vendor
      // emissions — uniform with every other format.
      #[cfg(feature = "exif")]
      AnyMeta::Exif(m) => m.tags(mode).collect(),
      // No-format build: the only variant is the uninhabitable phantom
      // (Codex CF3). `PhantomData` carries no data; the arm exists purely
      // for exhaustiveness and yields no tags.
      #[cfg(not(any(
        feature = "moi",
        feature = "aac",
        feature = "dv",
        feature = "audible",
        feature = "crw",
        feature = "red",
        feature = "id3",
        feature = "mp3",
        feature = "aiff",
        feature = "ape",
        feature = "dsf",
        feature = "flac",
        feature = "h264",
        feature = "flash",
        feature = "ogg",
        feature = "png",
        feature = "real",
        feature = "mpeg-audio",
        feature = "mpc",
        feature = "wavpack",
        feature = "matroska",
        feature = "quicktime",
        feature = "mxf",
        feature = "exif",
      )))]
      AnyMeta::_Phantom(_) => {
        let _ = mode;
        std::vec::Vec::new()
      }
    }
  }

  /// The format tag stream as [`value::Tag`](crate::value::Tag)s
  /// (golden-pattern **L4**) — the public, no-JSON generic-extraction API.
  /// Yields the Unknown-gated, de-duplicated tag set carrying the full
  /// [`Group`](crate::value::Group) (family-0 + family-1). Diagnostics
  /// (`ExifTool:Warning` / `ExifTool:Error`) are NOT included — they are a
  /// separate channel surfaced by the JSON path (and the engine-orchestration
  /// tags `SourceFile` / `File:FileType` / version are added by
  /// [`crate::parser::extract_info`], not here).
  ///
  /// This yields the same tag set the JSON path produces (same keys, same
  /// values, same dedup) MINUS those diagnostics + orchestration tags, but it
  /// carries family-0 too (which the `-G1` JSON key drops). `mode` selects
  /// PrintConv (`-j`) vs ValueConv (`-n`) values.
  #[must_use = "iter_tags yields the tag stream lazily; consume the iterator"]
  pub fn iter_tags(
    &self,
    mode: crate::emit::ConvMode,
  ) -> impl Iterator<Item = crate::value::Tag> + '_ {
    let mut out: std::vec::Vec<crate::value::Tag> = std::vec::Vec::new();
    for e in self.collect_emitted(mode) {
      // Unknown-suppression — ExifTool's default output omits `Unknown=>1`
      // tags (`ExifTool.pm:9179`); identical to `run_emission`'s gate.
      if e.unknown() {
        continue;
      }
      let tag = e.into_tag();
      // Faithful last-wins-IN-PLACE dedup on the (family1, name) key — the
      // same identity the `TagMap` sink dedups on (keeps first-occurrence
      // POSITION, latest value wins). Linear scan (no_std + alloc clean; tag
      // counts are small).
      if let Some(slot) = out
        .iter_mut()
        .find(|t| t.group_ref().family1() == tag.group_ref().family1() && t.name() == tag.name())
      {
        *slot = tag;
      } else {
        out.push(tag);
      }
    }
    out.into_iter()
  }

  /// Serialize this typed Meta's FORMAT tags into the inline tag-collection
  /// sink [`crate::tagmap::TagMap`], then drain its diagnostics. Single-sources
  /// the tag path through [`collect_emitted`](Self::collect_emitted) (which
  /// dispatches to each format's [`Taggable`](crate::emit::Taggable) stream,
  /// flattening nested sub-Metas — Mp3 → ID3/MPEG/APE, Dsf/Ape → ID3, …), then
  /// drains the per-format `$et->Warn`/`$et->Error` channel via
  /// [`drain_diagnostics`](Self::drain_diagnostics).
  ///
  /// `print_conv = true` emits PrintConv strings (`-j`); `false` emits
  /// post-ValueConv raw scalars (`-n`). Infallible.
  ///
  /// The tag write is driven by the canonical engine
  /// [`run_emission`](crate::emit::run_emission) over this `AnyMeta`'s
  /// [`Taggable`](crate::emit::Taggable) stream (the `collect_emitted`
  /// dispatch), so the Unknown-suppression + `write_value(family1, name,
  /// value)` + last-wins dedup are EXACTLY the engine's — then the per-format
  /// diagnostics are drained. Because an `AnyMeta` is a SINGLE Meta (exactly
  /// one arm fires), "all tags then all diagnostics" is identical to the prior
  /// per-arm "run_emission then drain" — byte-identical JSON.
  pub(crate) fn serialize_tags(
    &self,
    print_conv: bool,
    out: &mut crate::tagmap::TagMap,
  ) -> Result<(), core::convert::Infallible> {
    let mode = crate::emit::ConvMode::from_print_conv(print_conv);
    crate::emit::run_emission(self, mode, out);
    self.drain_diagnostics(out)
  }

  /// Drain this typed Meta's per-format diagnostic channel (the `$et->Warn` /
  /// `$et->Error` accumulators) into the [`TagMap`](crate::tagmap::TagMap)
  /// sink, in the exact order each format's retired inherent `serialize_tags`
  /// emitted them. The TAG emission is done separately (via
  /// [`collect_emitted`](Self::collect_emitted) / [`run_emission`]); this is
  /// the diagnostics-only second half of [`serialize_tags`](Self::serialize_tags).
  ///
  /// `run_emission` has no warning/error channel, so the warnings/errors that
  /// used to be drained after the per-arm `run_emission` call are relocated
  /// here VERBATIM (same accessors, same order, same conditions). The net
  /// `TagMap` (and `first_warning`/`first_error`) stays byte-identical.
  fn drain_diagnostics(
    &self,
    out: &mut crate::tagmap::TagMap,
  ) -> Result<(), core::convert::Infallible> {
    match self {
      #[cfg(feature = "moi")]
      AnyMeta::Moi(_) => Ok(()),
      #[cfg(feature = "aac")]
      AnyMeta::Aac(_) => Ok(()),
      #[cfg(feature = "dv")]
      AnyMeta::Dv(o) => match o {
        // DV.pm:188 — Warn + return 1 without DV:* tags. The typed path emits
        // the warning and no tags (the document builder surfaces it as the
        // ExifTool:Warning).
        crate::formats::dv::ParseOutcome::UnrecognizedProfile => {
          out.write_warning("Unrecognized DV profile")
        }
        crate::formats::dv::ParseOutcome::Meta(_) => Ok(()),
      },
      #[cfg(feature = "audible")]
      AnyMeta::Aa(m) => {
        // Warnings/errors stay outside the `Taggable` stream (`run_emission`
        // has no warning/error channel — Audible.pm `$et->Warn`/`$et->Error`
        // accumulators surface through `TagMap::first_warning`/`first_error`).
        for w in m.warnings() {
          out.write_warning(w.as_str())?;
        }
        for e in m.errors() {
          out.write_error(e.as_str())?;
        }
        Ok(())
      }
      #[cfg(feature = "crw")]
      AnyMeta::Crw(_) => {
        // CRW emits NO `$et->Warn`/`$et->Error` for the ported records: the
        // two `ProcessCanonRaw` warnings (`Bad CRW directory entry`
        // `CanonRaw.pm:652`, `Not processing double-referenced … directory`
        // `CanonRaw.pm:636`) are stop-the-walk events that never fire on a
        // real/crafted CRW (no `tagInfo`-less or self-referential directory),
        // and the embedded Canon sub-table decoders raise none. The
        // `CRW file format error` warning (`CanonRaw.pm:842`) is unreachable
        // here too — a header/signature mismatch returns `Ok(None)` (the
        // engine then emits its own `ExifTool:Error`), and a valid header with
        // an unreadable root directory still produces `Some(meta)` with no
        // records (bundled's `ProcessCanonRaw` `return 0` warns, but no real
        // CRW reaches it). So nothing to drain.
        Ok(())
      }
      #[cfg(feature = "red")]
      AnyMeta::R3d(m) => {
        // Red.pm `$et->Warn` accumulators surface through `TagMap::first_warning`.
        for w in m.warnings() {
          out.write_warning(w)?;
        }
        Ok(())
      }
      #[cfg(feature = "id3")]
      AnyMeta::Id3(m) => {
        // The kept inherent `Id3Meta::serialize_tags` appended these after the
        // tags; ID3 is a directory parser, never dispatched standalone, so this
        // arm is inert today — kept consistent with the migration.
        for w in m.warnings_slice() {
          out.write_warning(w.as_str())?;
        }
        for e in m.errors_slice() {
          out.write_error(e.as_str())?;
        }
        Ok(())
      }
      #[cfg(feature = "mp3")]
      AnyMeta::Mp3(m) => {
        // Bundled `ProcessMP3` order (ID3.pm:1684-1728): (a) the ID3 sub-Meta's
        // own warnings then errors; (b) MPEG-audio emits none; (c) the APE
        // sub-Meta's own — APE first emits its nested ID3v1-trailer sub-Meta's
        // warnings then errors, then the APE.pm:238 `Warn('Bad APE trailer')`.
        if let Some(id3) = m.id3() {
          for w in id3.warnings_slice() {
            out.write_warning(w.as_str())?;
          }
          for e in id3.errors_slice() {
            out.write_error(e.as_str())?;
          }
        }
        #[cfg(feature = "ape")]
        if let Some(ape) = m.ape() {
          if let Some(id3) = ape.id3_ref() {
            for w in id3.warnings_slice() {
              out.write_warning(w.as_str())?;
            }
            for e in id3.errors_slice() {
              out.write_error(e.as_str())?;
            }
          }
          if ape.warn_bad_trailer() {
            out.write_warning("Bad APE trailer")?;
          }
        }
        Ok(())
      }
      #[cfg(feature = "aiff")]
      AnyMeta::Aiff(m) => {
        // AIFF.pm's `$et->Warn("Skipping large ... chunk")` surfaces through
        // `TagMap::first_warning`. AIFF emits no `$et->Error` (the short-header
        // reject returns `Ok(None)` ⇒ the engine's post-loop `ExifTool:Error`
        // block fires instead).
        for w in m.warnings() {
          out.write_warning(w)?;
        }
        Ok(())
      }
      #[cfg(feature = "ape")]
      AnyMeta::Ape(m) => {
        // The KEPT inherent `ape::Meta::serialize_tags` emitted these in order:
        // (a) the chained ID3 sub-Meta's own warnings then errors (BEFORE the
        // MAC/main body); (b) the APE.pm:238 `Warn('Bad APE trailer')` (AFTER
        // the main stream).
        #[cfg(feature = "id3")]
        if let Some(id3) = m.id3_ref() {
          for w in id3.warnings_slice() {
            out.write_warning(w.as_str())?;
          }
          for e in id3.errors_slice() {
            out.write_error(e.as_str())?;
          }
        }
        if m.warn_bad_trailer() {
          out.write_warning("Bad APE trailer")?;
        }
        Ok(())
      }
      #[cfg(feature = "dsf")]
      AnyMeta::Dsf(m) => {
        // The retired `dsf::Meta::serialize_tags` emitted the DSF.pm:71
        // fmt-read warning BEFORE the tags, then `id3.serialize_tags` appended
        // the ID3 sub-Meta's own warnings/errors AFTER its tags. Draining in
        // that order (fmt warning, then ID3 warnings, then ID3 errors) keeps
        // the net `TagMap` byte-identical.
        if let Some(w) = m.fmt_warning() {
          out.write_warning(w)?;
        }
        #[cfg(feature = "id3")]
        if let Some(id3) = m.id3_ref() {
          for w in id3.warnings_slice() {
            out.write_warning(w.as_str())?;
          }
          for e in id3.errors_slice() {
            out.write_error(e.as_str())?;
          }
        }
        Ok(())
      }
      #[cfg(feature = "flac")]
      AnyMeta::Flac(m) => {
        // The retired `flac::Meta::serialize_tags` emitted these in order:
        // (a) the chained ID3 sub-Meta's own warnings then errors (BEFORE the
        // FLAC body); (b) the FLAC.pm:278 "Format error in FLAC file" warning;
        // (c) one "Picture pointer references previous VorbisComment directory"
        // warning per METADATA_BLOCK_PICTURE Vorbis item (Vorbis.pm:122-135).
        #[cfg(feature = "id3")]
        if let Some(id3) = m.id3_ref() {
          for w in id3.warnings_slice() {
            out.write_warning(w.as_str())?;
          }
          for e in id3.errors_slice() {
            out.write_error(e.as_str())?;
          }
        }
        if m.has_format_error() {
          out.write_warning("Format error in FLAC file")?;
        }
        for item in m.vorbis_items() {
          if item.is_picture_recursion_warning() {
            out.write_warning("Picture pointer references previous VorbisComment directory")?;
          }
        }
        Ok(())
      }
      #[cfg(feature = "h264")]
      AnyMeta::H264(m) => {
        // The `Warn('Entries in MDPM directory are out of sequence')` /
        // forbidden-bit warnings (H264.pm:989/1058) surface through
        // `TagMap::first_warning`.
        for w in m.warnings() {
          out.write_warning(w.as_str())?;
        }
        Ok(())
      }
      #[cfg(feature = "flash")]
      AnyMeta::Flv(m) => {
        // The FLV `$et->Warn` accumulators (Flash.pm:353/437/456/504/511)
        // surface through `TagMap::first_warning`.
        for w in m.warnings() {
          out.write_warning(w.as_str())?;
        }
        Ok(())
      }
      #[cfg(feature = "ogg")]
      AnyMeta::Ogg(m) => {
        // The retired `ogg::Meta::serialize_tags` emitted these in order:
        // (a) the chained ID3 sub-Meta's own warnings then errors (BEFORE the
        // OGG body); (b) OGG's own accumulated warnings (`Lost synchronization`
        // Ogg.pm:97, `Missing page(s) in Ogg file` Ogg.pm:158, `Format error in
        // Vorbis comments` Vorbis.pm:208) in occurrence order.
        #[cfg(feature = "id3")]
        if let Some(id3) = m.id3_ref() {
          for w in id3.warnings_slice() {
            out.write_warning(w.as_str())?;
          }
          for e in id3.errors_slice() {
            out.write_error(e.as_str())?;
          }
        }
        for w in m.warnings() {
          out.write_warning(w.as_str())?;
        }
        Ok(())
      }
      #[cfg(feature = "png")]
      AnyMeta::Png(m) => {
        // The retired `png::PngMeta::serialize_tags` emitted these in order:
        // (a) the PNG walker's own accumulated warnings (`Truncated PNG image`
        // PNG.pm:1486, `Text/EXIF chunk(s) found after PNG <chunk> …`
        // PNG.pm:1598, the zlib inflate-error warnings `Error inflating
        // <chunk>` PNG.pm:942 / `Unknown compression method <n> for <chunk>`
        // PNG.pm:951, the `Invalid eXIf chunk` / `Improper "Exif00" header …`
        // PNG.pm:1369-1384, …) BEFORE the eXIf dispatch; (b) the embedded eXIf
        // Exif block's own
        // `$et->Warn` warnings (drained INSIDE the retired
        // `exif_meta.serialize_tags` call AFTER its tags). The PNG-level
        // warnings always precede the Exif ones (PNG walks first), so the
        // document-level `first_warning` (= `ExifTool:Warning`) is unchanged;
        // we preserve the full order for completeness.
        for w in m.warnings() {
          out.write_warning(w)?;
        }
        // The eXIf / Raw-profile EXIF sub-Metas' diagnostics, IN CHUNK ORDER via
        // the SAME shared-`$$et{PROCESSED}` event replay `tags()` / `project()`
        // use (`replay_exif_events`, `ExifTool.pm:9061-9072` + `PNG.pm:1193`).
        // For each EXIF event, in chunk order:
        //   * its own EXIF `$et->Warn` corpus (Bad-directory, suspicious-offset,
        //     …) via `ExifMeta::warnings()` (a blocked event skipped IFD0 so it
        //     has none; a reset-only profile yields no `meta`);
        //   * the cross-source cycle-guard warning(s) the walk raised
        //     (`ExifTool.pm:9068`, "$dirName pointer references previous $prev
        //     directory") — these are EMPTY unless the event's IFD0 `$addr`
        //     collided with an already-processed directory (IFD0 OR a trailing
        //     IFD; the `$prev` is the recorded name, e.g. `IFD1` for a
        //     cross-source trailing-IFD collision).
        // Draining in chunk order keeps the warning sequence faithful (the
        // cycle-guard warning lands where bundled raises it, between the
        // surrounding events' warnings).
        //
        // NOTE (documented, not chased): 3+ events sharing one `$addr` drive
        // bundled into emergent C-buffer/offset GARBAGE values (e.g. `IFD0:Make
        // = "\x1a"`) alongside the cycle-guard warning(s). That is beyond the
        // DOCUMENTED cycle-guard (which just warns + skips); this port emits
        // clean tags for the processed directories + one cycle-guard warning per
        // blocked directory, matching `ExifTool.pm:9066-9072` rather than the
        // garbage. See `replay_exif_events`.
        #[cfg(feature = "exif")]
        for replay in crate::formats::png::replay_exif_events(m.exif_events()) {
          if let Some(exif_meta) = replay.meta() {
            for w in exif_meta.warnings() {
              out.write_warning(w)?;
            }
          }
          for w in replay.cycle_guard_warnings() {
            out.write_warning(w)?;
          }
        }
        Ok(())
      }
      #[cfg(feature = "real")]
      AnyMeta::Real(_) => {
        // Real emits NO warnings/errors (Real.pm `return 0` on bad input; the
        // "Unsupported RealAudio version" `Warn` produces no tags AND no tagmap
        // warning), and the chained `Id3v1Meta` likewise carries none.
        Ok(())
      }
      #[cfg(feature = "mpeg-audio")]
      AnyMeta::MpegAudio(_) => Ok(()),
      #[cfg(feature = "mpc")]
      AnyMeta::Mpc(m) => {
        // The retired `mpc::Meta::serialize_tags` emitted these in order:
        // (a) the ID3 sub-Meta's own warnings then errors (BEFORE the MPC
        // body); (b) the MPC.pm:107-109 non-SV7 warning; (c) the APE sub-Meta's
        // own — APE first emits its nested ID3v1-trailer sub-Meta's warnings
        // then errors, then the APE.pm:238 `Warn('Bad APE trailer')`.
        #[cfg(feature = "id3")]
        if let Some(id3) = m.id3_ref() {
          for w in id3.warnings_slice() {
            out.write_warning(w.as_str())?;
          }
          for e in id3.errors_slice() {
            out.write_error(e.as_str())?;
          }
        }
        if m.warn_unsupported_version() {
          out.write_warning("Audio info currently not extracted from this version MPC file")?;
        }
        #[cfg(feature = "ape")]
        if let Some(ape) = m.ape_ref() {
          #[cfg(feature = "id3")]
          if let Some(id3) = ape.id3_ref() {
            for w in id3.warnings_slice() {
              out.write_warning(w.as_str())?;
            }
            for e in id3.errors_slice() {
              out.write_error(e.as_str())?;
            }
          }
          if ape.warn_bad_trailer() {
            out.write_warning("Bad APE trailer")?;
          }
        }
        Ok(())
      }
      #[cfg(feature = "wavpack")]
      AnyMeta::Wv(m) => {
        // The retired `wavpack::Meta::serialize_tags` emitted these in order:
        // (a) the chained ID3 sub-Meta's own warnings then errors (AFTER the WV
        // header tags); (b) the chained APE sub-Meta's own warnings/errors —
        // APE first emits its nested ID3v1-trailer sub-Meta's warnings then
        // errors, then the APE.pm:238 `Warn('Bad APE trailer')`.
        #[cfg(feature = "id3")]
        if let Some(id3) = m.id3_ref() {
          for w in id3.warnings_slice() {
            out.write_warning(w.as_str())?;
          }
          for e in id3.errors_slice() {
            out.write_error(e.as_str())?;
          }
        }
        #[cfg(feature = "ape")]
        if let Some(ape) = m.ape_ref() {
          #[cfg(feature = "id3")]
          if let Some(id3) = ape.id3_ref() {
            for w in id3.warnings_slice() {
              out.write_warning(w.as_str())?;
            }
            for e in id3.errors_slice() {
              out.write_error(e.as_str())?;
            }
          }
          if ape.warn_bad_trailer() {
            out.write_warning("Bad APE trailer")?;
          }
        }
        Ok(())
      }
      #[cfg(feature = "matroska")]
      AnyMeta::Matroska(_) => Ok(()),
      #[cfg(feature = "quicktime")]
      AnyMeta::QuickTime(m) => {
        // The FIRST `ProcessMOV` warning (`Truncated '...' data` / `Invalid
        // atom size`) stays OUTSIDE the `Taggable` stream — QuickTime.pm:
        // 10242/10590 surfaces it as the document-level `ExifTool:Warning` via
        // `TagMap::first_warning`. R6/F2: the per-track truncation warnings are
        // emitted IN the tag stream under their `Track<N>:Warning` key, not here.
        if let Some(w) = m.warning() {
          out.write_warning(w)?;
        }
        Ok(())
      }
      #[cfg(feature = "mxf")]
      AnyMeta::Mxf(_) => Ok(()),
      #[cfg(feature = "exif")]
      AnyMeta::Exif(m) => {
        // EXIF's `$et->Warn(...)` (IFD-bounds checks, `Malformed APP1 EXIF
        // segment`, …) → `ExifTool:Warning`. `File:ExifByteOrder` is a real
        // tag now emitted by `tags()` (via `collect_emitted`), NOT a
        // diagnostic — so only the warnings are drained here, matching the
        // warning loop the inherent `ExifMeta::serialize_tags` runs after its
        // `run_emission`.
        for w in m.warnings() {
          out.write_warning(w)?;
        }
        Ok(())
      }
      // No-format build: the only variant is the uninhabitable phantom
      // (Codex CF3). `PhantomData` carries no data; the arm exists purely
      // for exhaustiveness and drains nothing.
      #[cfg(not(any(
        feature = "moi",
        feature = "aac",
        feature = "dv",
        feature = "audible",
        feature = "crw",
        feature = "red",
        feature = "id3",
        feature = "mp3",
        feature = "aiff",
        feature = "ape",
        feature = "dsf",
        feature = "flac",
        feature = "h264",
        feature = "flash",
        feature = "ogg",
        feature = "real",
        feature = "mpeg-audio",
        feature = "mpc",
        feature = "wavpack",
        feature = "matroska",
        feature = "quicktime",
        feature = "mxf",
        feature = "exif",
      )))]
      AnyMeta::_Phantom(_) => {
        let _ = out;
        Ok(())
      }
    }
  }
}

#[cfg(feature = "alloc")]
impl crate::emit::Taggable for AnyMeta<'_> {
  /// The closed-set FORMAT tag stream — every format arm's
  /// [`Taggable`](crate::emit::Taggable) emission, dispatched through
  /// [`collect_emitted`](AnyMeta::collect_emitted) and flattened over chained
  /// sub-Metas. This is what lets the document path drive the whole `AnyMeta`
  /// through the canonical [`run_emission`](crate::emit::run_emission) engine
  /// (see [`serialize_tags`](AnyMeta::serialize_tags)) instead of re-deriving
  /// the Unknown-gate + `write_value` + dedup per arm. Diagnostics
  /// (`$et->Warn`/`$et->Error`) are NOT part of this stream — they are drained
  /// separately by [`drain_diagnostics`](AnyMeta::drain_diagnostics).
  fn tags(
    &self,
    mode: crate::emit::ConvMode,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    self.collect_emitted(mode).into_iter()
  }
}

/// Payload for [`FileTypeFinalize::ExplicitThenLiteral`]: a `SetFileType($set)`
/// followed by a raw replacement of the `File:FileType` value with `$literal`
/// (AIFF DjVu multi-page, AIFF.pm:206). Extracted into a named struct so the
/// enum stays unit-or-newtype only (§2 — no struct-style variants); the
/// `FileTypeExtension` / `MIMEType` are derived from `set`, NOT `literal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExplicitThenLiteral {
  set: &'static str,
  literal: &'static str,
}

impl ExplicitThenLiteral {
  /// Construct from the `SetFileType` argument and the literal that replaces
  /// the `File:FileType` value in place.
  #[must_use]
  #[inline(always)]
  pub const fn new(set: &'static str, literal: &'static str) -> Self {
    Self { set, literal }
  }

  /// The type passed to `SetFileType` (drives `FileTypeExtension`/`MIMEType`).
  #[must_use]
  #[inline(always)]
  pub const fn set(&self) -> &'static str {
    self.set
  }

  /// The literal that replaces the `File:FileType` value in place.
  #[must_use]
  #[inline(always)]
  pub const fn literal(&self) -> &'static str {
    self.literal
  }
}

/// Payload for [`FileTypeFinalize::ExplicitWithMime`]: a
/// `SetFileType($set, $mime)` where the parser supplies BOTH the explicit
/// file type AND its MIME (QuickTime.pm:10008 `SetFileType($fileType,
/// $mimeLookup{$fileType} || 'video/mp4')` — the M4A/M4V/M4B MIMEs are NOT in
/// the generic `%mimeType` table, so they must be carried through). Extracted
/// into a named struct so the enum stays unit-or-newtype only (§2). The
/// `FileTypeExtension` is still derived from `set`; only the `MIMEType` comes
/// from `mime`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExplicitWithMime {
  set: &'static str,
  mime: &'static str,
}

impl ExplicitWithMime {
  /// Construct from the `SetFileType` type argument and its explicit MIME.
  #[must_use]
  #[inline(always)]
  pub const fn new(set: &'static str, mime: &'static str) -> Self {
    Self { set, mime }
  }

  /// The type passed to `SetFileType` (drives `FileType`/`FileTypeExtension`).
  #[must_use]
  #[inline(always)]
  pub const fn set(&self) -> &'static str {
    self.set
  }

  /// The explicit `File:MIMEType` the parser supplies (the second
  /// `SetFileType` argument).
  #[must_use]
  #[inline(always)]
  pub const fn mime(&self) -> &'static str {
    self.mime
  }
}

/// How the engine ([`crate::parser::extract_info`]) should finalize the
/// `File:*` triplet for an accepted typed [`AnyMeta`] — the typed-path
/// counterpart of the `SetFileType` / `OverrideFileType` calls each format's
/// (now-removed) `process` entry used to make. The format chooses the variant;
/// the engine applies it against its file-type-resolution helpers.
///
/// `#[non_exhaustive]` like the sibling closed-set enums: variants are
/// additive within the crate. Variants are unit or newtype only (§2): the
/// two-field finalize case lives in the [`ExplicitThenLiteral`] named struct.
#[non_exhaustive]
#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  derive_more::IsVariant,
  derive_more::Unwrap,
  derive_more::TryUnwrap,
)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
pub enum FileTypeFinalize {
  /// `SetFileType()` with no argument — finalize to the DETECTED candidate
  /// type (ExifTool.pm:9684). The MOI/AAC/DV/Audible/Red/APE/DSF/FLAC/MPC/WV
  /// `Process<Type>` entries all do this (`AAC.pm:107` etc.).
  Detected,
  /// `SetFileType($explicit)` — finalize to an EXPLICIT type the parser
  /// derived from the file body (AIFF: `AIFF`/`AIFC`/`DJVU` from the FORM
  /// magic, AIFF.pm:202/210).
  Explicit(&'static str),
  /// `SetFileType()` then `OverrideFileType($target)` — finalize to the
  /// detected type, then in-place override (OGG → `OGV`/`OPUS`, Ogg.pm:49-50).
  DetectedThenOverride(&'static str),
  /// `SetFileType($set)` then raw-replace the `File:FileType` VALUE with
  /// `$literal` (AIFF DjVu multi-page: `SetFileType('DJVU')` then
  /// `$$self{VALUE}{FileType} = 'DJVU (multi-page)'`, AIFF.pm:206). The
  /// payload (see [`ExplicitThenLiteral`]) carries the `set` + `literal`.
  ExplicitThenLiteral(ExplicitThenLiteral),
  /// `SetFileType($set, $mime)` — finalize to an EXPLICIT type WITH an
  /// explicit MIME the parser derived from the body, bypassing the generic
  /// `%mimeType` table lookup (QuickTime: M4A→`audio/mp4`, M4V→`video/x-m4v`,
  /// which are absent from `%mimeType`, QuickTime.pm:10008). The payload (see
  /// [`ExplicitWithMime`]) carries the `set` + `mime`.
  ExplicitWithMime(ExplicitWithMime),
}

impl AnyMeta<'_> {
  /// Project this typed Meta onto the normalized cross-format
  /// [`MediaMetadata`](crate::metadata::MediaMetadata) domain — the
  /// closed-dispatch entry to the golden-pattern **L2** layer, mirroring the
  /// [`serialize_tags`](Self::serialize_tags) dispatch shape.
  ///
  /// Today only the `Exif` arm carries a domain projection (it routes through
  /// [`Project::project`](crate::metadata::Project) on its
  /// [`ExifMeta`](crate::exif::ExifMeta), folding the EXIF IFDs + the vendor
  /// MakerNote into camera / lens / GPS / capture). **Every other arm — and
  /// the no-format `_Phantom` arm — returns an empty
  /// [`MediaMetadata`](crate::metadata::MediaMetadata)** (all domains `None`):
  /// those formats do not yet implement
  /// [`Project`](crate::metadata::Project). As each per-format projection
  /// lands (Phase 2), its arm switches from the empty default to
  /// `m.project()` — purely additive, no emission/output change.
  #[must_use]
  pub fn project(&self) -> crate::metadata::MediaMetadata {
    match self {
      // The only arm with a domain projection today: EXIF/TIFF (incl. the
      // vendor MakerNote merge) via the `Project` trait. Phase 2 switches the
      // arms below from the empty default to their own `m.project()`.
      #[cfg(feature = "exif")]
      AnyMeta::Exif(m) => crate::metadata::Project::project(m),
      #[cfg(feature = "moi")]
      AnyMeta::Moi(m) => crate::metadata::Project::project(m),
      #[cfg(feature = "aac")]
      AnyMeta::Aac(m) => crate::metadata::Project::project(m),
      #[cfg(feature = "dv")]
      AnyMeta::Dv(o) => match o {
        crate::formats::dv::ParseOutcome::UnrecognizedProfile => {
          crate::metadata::MediaMetadata::new()
        }
        crate::formats::dv::ParseOutcome::Meta(m) => crate::metadata::Project::project(m),
      },
      #[cfg(feature = "audible")]
      AnyMeta::Aa(m) => crate::metadata::Project::project(m),
      #[cfg(feature = "crw")]
      AnyMeta::Crw(m) => crate::metadata::Project::project(m),
      #[cfg(feature = "red")]
      AnyMeta::R3d(m) => crate::metadata::Project::project(m),
      #[cfg(feature = "id3")]
      AnyMeta::Id3(m) => crate::metadata::Project::project(m),
      #[cfg(feature = "mp3")]
      AnyMeta::Mp3(m) => crate::metadata::Project::project(m),
      #[cfg(feature = "aiff")]
      AnyMeta::Aiff(m) => crate::metadata::Project::project(m),
      #[cfg(feature = "ape")]
      AnyMeta::Ape(m) => crate::metadata::Project::project(m),
      #[cfg(feature = "dsf")]
      AnyMeta::Dsf(m) => crate::metadata::Project::project(m),
      #[cfg(feature = "flac")]
      AnyMeta::Flac(m) => crate::metadata::Project::project(m),
      #[cfg(feature = "h264")]
      AnyMeta::H264(m) => crate::metadata::Project::project(m),
      #[cfg(feature = "flash")]
      AnyMeta::Flv(m) => crate::metadata::Project::project(m),
      #[cfg(feature = "ogg")]
      AnyMeta::Ogg(m) => crate::metadata::Project::project(m),
      #[cfg(feature = "png")]
      AnyMeta::Png(m) => crate::metadata::Project::project(m),
      #[cfg(feature = "real")]
      AnyMeta::Real(m) => crate::metadata::Project::project(m),
      #[cfg(feature = "mpeg-audio")]
      AnyMeta::MpegAudio(m) => crate::metadata::Project::project(m),
      #[cfg(feature = "mpc")]
      AnyMeta::Mpc(m) => crate::metadata::Project::project(m),
      #[cfg(feature = "wavpack")]
      AnyMeta::Wv(m) => crate::metadata::Project::project(m),
      #[cfg(feature = "matroska")]
      AnyMeta::Matroska(m) => crate::metadata::Project::project(m),
      #[cfg(feature = "quicktime")]
      AnyMeta::QuickTime(m) => crate::metadata::Project::project(m),
      #[cfg(feature = "mxf")]
      AnyMeta::Mxf(m) => crate::metadata::Project::project(m),
      // No-format build: the only variant is the uninhabitable phantom
      // (Codex CF3); it projects to the empty aggregate for exhaustiveness.
      #[cfg(not(any(
        feature = "moi",
        feature = "aac",
        feature = "dv",
        feature = "audible",
        feature = "crw",
        feature = "red",
        feature = "id3",
        feature = "mp3",
        feature = "aiff",
        feature = "ape",
        feature = "dsf",
        feature = "flac",
        feature = "h264",
        feature = "flash",
        feature = "ogg",
        feature = "real",
        feature = "mpeg-audio",
        feature = "mpc",
        feature = "wavpack",
        feature = "matroska",
        feature = "quicktime",
        feature = "mxf",
        feature = "exif",
      )))]
      AnyMeta::_Phantom(_) => crate::metadata::MediaMetadata::new(),
    }
  }

  /// How the engine should finalize the `File:*` triplet for this accepted
  /// Meta (the typed-path replacement for the per-format `SetFileType` /
  /// `OverrideFileType` calls). See [`FileTypeFinalize`].
  #[must_use]
  pub fn finalize_file_type(&self) -> FileTypeFinalize {
    match self {
      // Leaf + chained formats that finalize to the detected candidate type.
      #[cfg(feature = "moi")]
      AnyMeta::Moi(_) => FileTypeFinalize::Detected,
      #[cfg(feature = "aac")]
      AnyMeta::Aac(_) => FileTypeFinalize::Detected,
      #[cfg(feature = "dv")]
      AnyMeta::Dv(_) => FileTypeFinalize::Detected,
      #[cfg(feature = "audible")]
      AnyMeta::Aa(_) => FileTypeFinalize::Detected,
      // CRW: `ProcessCRW` calls `$et->SetFileType()` with no argument
      // (`CanonRaw.pm:825`) ⇒ finalize to the DETECTED candidate type ("CRW").
      #[cfg(feature = "crw")]
      AnyMeta::Crw(_) => FileTypeFinalize::Detected,
      #[cfg(feature = "red")]
      AnyMeta::R3d(_) => FileTypeFinalize::Detected,
      // ID3 is a directory parser (no top-level file type); it has no engine
      // entry. Treat as detected for completeness (unreachable from
      // `extract_info`, which never dispatches ID3 as a file type).
      #[cfg(feature = "id3")]
      AnyMeta::Id3(_) => FileTypeFinalize::Detected,
      #[cfg(feature = "mp3")]
      AnyMeta::Mp3(_) => FileTypeFinalize::Detected,
      // AIFF: explicit magic-derived type, with the DjVu multi-page literal.
      #[cfg(feature = "aiff")]
      AnyMeta::Aiff(m) => {
        let ft = m.magic().as_file_type();
        if m.djvu_multi_page() {
          FileTypeFinalize::ExplicitThenLiteral(ExplicitThenLiteral::new(ft, "DJVU (multi-page)"))
        } else {
          FileTypeFinalize::Explicit(ft)
        }
      }
      #[cfg(feature = "ape")]
      AnyMeta::Ape(_) => FileTypeFinalize::Detected,
      #[cfg(feature = "dsf")]
      AnyMeta::Dsf(_) => FileTypeFinalize::Detected,
      #[cfg(feature = "flac")]
      AnyMeta::Flac(_) => FileTypeFinalize::Detected,
      // H264: engine-only — `any_parser_for` never resolves an `H264` file
      // type, so this arm is unreachable from `extract_info`. `Detected` is
      // the inert default for the closed-set exhaustiveness.
      #[cfg(feature = "h264")]
      AnyMeta::H264(_) => FileTypeFinalize::Detected,
      #[cfg(feature = "flash")]
      AnyMeta::Flv(_) => FileTypeFinalize::Detected,
      // OGG: detected ("OGG"), then optional content override (OGV/OPUS).
      #[cfg(feature = "ogg")]
      AnyMeta::Ogg(m) => match m.file_type_override() {
        Some(target) => FileTypeFinalize::DetectedThenOverride(target),
        None => FileTypeFinalize::Detected,
      },
      // PNG: `ProcessPNG` calls `$et->SetFileType($fileType)` with
      // `$fileType` from `%pngLookup` (PNG.pm:1439-1440). For the PNG
      // signature this is `"PNG"` — the detected candidate. Bundled does
      // NOT apply post-walk overrides for PNG/MNG/JNG.
      #[cfg(feature = "png")]
      AnyMeta::Png(_) => FileTypeFinalize::Detected,
      // Real: SetFileType($type) where $type = 'RM' / 'RA' / 'RAM' / 'RPM'
      // (Real.pm:528-558). The candidate detected as "Real" is finalized
      // to whichever sub-type the magic prefix selected.
      #[cfg(feature = "real")]
      AnyMeta::Real(m) => FileTypeFinalize::Explicit(m.kind().file_type()),
      #[cfg(feature = "mpeg-audio")]
      AnyMeta::MpegAudio(_) => FileTypeFinalize::Detected,
      #[cfg(feature = "mpc")]
      AnyMeta::Mpc(_) => FileTypeFinalize::Detected,
      #[cfg(feature = "wavpack")]
      AnyMeta::Wv(_) => FileTypeFinalize::Detected,
      // Matroska: SetFileType is detected ("MKV"); a `DocType => "webm"`
      // body invokes `OverrideFileType("WEBM")` (Matroska.pm:72) on the
      // typed Meta. Other MKA/MKS overrides happen at end-of-walk based on
      // track types (Matroska.pm:1240-1245) — Phase-2 forward item.
      #[cfg(feature = "matroska")]
      AnyMeta::Matroska(m) => {
        if m.is_webm() {
          FileTypeFinalize::DetectedThenOverride("WEBM")
        } else {
          FileTypeFinalize::Detected
        }
      }
      // QuickTime: `SetFileType($fileType, $mimeLookup{$fileType} ||
      // 'video/mp4')` where `$fileType`/MIME are derived from the `ftyp`
      // major/compatible brands (QuickTime.pm:9986-10008); a non-`ftyp` first
      // atom finalizes to MOV/`video/quicktime` (QuickTime.pm:10012). The
      // parser supplies BOTH — the M4A/M4V/M4B MIMEs are absent from the
      // generic `%mimeType` table, so the engine must NOT recompute them (F2).
      #[cfg(feature = "quicktime")]
      AnyMeta::QuickTime(m) => {
        FileTypeFinalize::ExplicitWithMime(ExplicitWithMime::new(m.file_type(), m.mime()))
      }
      // MXF: `ProcessMXF` calls `SetFileType()` with no argument
      // (MXF.pm:2820) ⇒ finalize to the detected candidate type.
      #[cfg(feature = "mxf")]
      AnyMeta::Mxf(_) => FileTypeFinalize::Detected,
      // Exif/TIFF: `DoProcessTIFF` calls `SetFileType($t)` (ExifTool.pm:
      // 8683) — finalize to the DETECTED candidate type ("TIFF" for a
      // standalone `.tif`). DNG/NEF/RAW overrides (ExifTool.pm:8754-8765)
      // depend on MakerNote/DNGVersion tags — deferred to the MakerNotes
      // wave; the camera-metadata-core TIFF fixtures finalize as TIFF.
      #[cfg(feature = "exif")]
      AnyMeta::Exif(_) => FileTypeFinalize::Detected,
      #[cfg(not(any(
        feature = "moi",
        feature = "aac",
        feature = "dv",
        feature = "audible",
        feature = "crw",
        feature = "red",
        feature = "id3",
        feature = "mp3",
        feature = "aiff",
        feature = "ape",
        feature = "dsf",
        feature = "flac",
        feature = "h264",
        feature = "flash",
        feature = "ogg",
        feature = "png",
        feature = "real",
        feature = "mpeg-audio",
        feature = "mpc",
        feature = "wavpack",
        feature = "matroska",
        feature = "quicktime",
        feature = "mxf",
        feature = "exif",
      )))]
      AnyMeta::_Phantom(_) => FileTypeFinalize::Detected,
    }
  }
}

/// A mode-carrying [`Serialize`](serde::Serialize) view of a typed
/// [`AnyMeta`]: the `-j` (PrintConv) vs `-n` (raw ValueConv) toggle that the
/// CLI applies, packaged so a caller can render the typed parse result to JSON
/// with `serde_json` directly — `serde_json::to_string(&Rendered::new(&meta,
/// true))`.
///
/// It serializes the Meta's FORMAT tags as a flat JSON object of
/// `"<Group1>:<Name>": value` entries (standard `serde_json` scalars; the
/// value-semantic [`crate::jsondiff`] comparator treats token style as
/// irrelevant). This is the typed-library counterpart of the engine's
/// [`crate::parser::extract_info`] — it does NOT add the orchestration tags
/// (`SourceFile`, the `File:*` triplet, `ExifTool:ExifToolVersion`); those are
/// the engine's responsibility (`extract_info` emits them around the format
/// tags). Chained Metas (Mp3 wrapping ID3/MPEG/APE, etc.) flatten all their
/// sub-Metas' tags into the one object via the `serialize_tags` chain.
///
/// `#[non_exhaustive]`-free (a plain value wrapper); construct via
/// [`Rendered::new`]. D8 convention: no public fields.
#[cfg(all(feature = "serde", feature = "alloc"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "serde", feature = "alloc"))))]
#[derive(Debug, Clone, Copy)]
pub struct Rendered<'a, 'm> {
  meta: &'a AnyMeta<'m>,
  print_conv: bool,
}

#[cfg(all(feature = "serde", feature = "alloc"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "serde", feature = "alloc"))))]
impl<'a, 'm> Rendered<'a, 'm> {
  /// Wrap `meta` for serialization in the given mode (`print_conv = true` ⇒
  /// `-j` PrintConv strings; `false` ⇒ `-n` raw post-ValueConv scalars).
  #[must_use]
  #[inline(always)]
  pub const fn new(meta: &'a AnyMeta<'m>, print_conv: bool) -> Self {
    Self { meta, print_conv }
  }

  /// The wrapped Meta.
  #[must_use]
  #[inline(always)]
  pub const fn meta(&self) -> &AnyMeta<'m> {
    self.meta
  }

  /// The render mode (`true` = `-j` PrintConv, `false` = `-n` raw).
  #[must_use]
  #[inline(always)]
  pub const fn print_conv(&self) -> bool {
    self.print_conv
  }
}

// Optional serde `Serialize` for `Rendered` (skill §8: one anonymous gated
// const block). It drives the typed Meta's inherent `serialize_tags` to collect
// the format tags into a `TagMap` (the same emission the engine uses, with the
// -j/-n choice + chain flattening in ONE place), then serializes them as a flat
// `"<Group1>:<Name>": value` object via `TagValue`'s own `Serialize`. The
// `TagMap` already applied `%noDups` first-wins on the `"<Group1>:<Name>"` key.
#[cfg(all(feature = "serde", feature = "alloc"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "serde", feature = "alloc"))))]
const _: () = {
  use crate::tagmap::TagMap;
  use serde::ser::{Serialize, SerializeMap, Serializer};

  impl Serialize for Rendered<'_, '_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
      // Collect the Meta's FORMAT tags via the inherent `serialize_tags` (the
      // typed-path tag emission). `Rendered` emits only the format tags, not
      // the orchestration triplet. `serialize_tags` is infallible.
      let mut tm = TagMap::new();
      let _ = self.meta.serialize_tags(self.print_conv, &mut tm);
      let entries = tm.entries();
      // The FIRST `$et->Warn` surfaces as `ExifTool:Warning`, faithful to
      // the full document serializer (`serialize.rs:134-138`). `Rendered`
      // is the warning-bearing path for engine-only formats with no file
      // type (H264 — H264.pm:989 MDPM out-of-sequence).
      let warning = tm.first_warning();
      let extra = usize::from(warning.is_some());
      let mut map = s.serialize_map(Some(entries.len() + extra))?;
      for (key, value) in entries {
        map.serialize_entry(key.as_str(), value)?;
      }
      if let Some(w) = warning {
        map.serialize_entry("ExifTool:Warning", w)?;
      }
      map.end()
    }
  }
};

// ===========================================================================
// AnyError — closed-set error from `AnyParser::parse_any` + `parse_bytes`
// ===========================================================================

/// Aggregate Rust-level fatal error from the closed [`AnyParser`] dispatch.
///
/// One variant wraps each format's [`FormatParser::Error`]; conversions
/// from the per-format `XxxError` types are provided via `From` impls so
/// the per-arm dispatch in [`AnyParser::parse_any`] can write
/// `.map_err(Into::into)`.
///
/// Most format errors today are uninhabited (no variants — see e.g.
/// [`crate::formats::moi::Error`]); the `From` impls for those formats
/// translate into unreachable matches that `rustc` constant-folds out at
/// monomorphization. The structure exists so future I/O-fallible parsers
/// can add fatal modes without changing the public `AnyError` shape.
///
/// `#[non_exhaustive]` matches [`AnyParser`] / [`AnyMeta`]: consumers
/// cannot exhaustively match on this enum across crate-feature combos —
/// new format arms (or new variants on existing errors) are additive
/// within the crate, but no caller can rely on a fixed set.
///
/// §5: derived via `thiserror` (`Display` + `core::error::Error`, no-std
/// clean — was a `std`-only hand-written `impl std::error::Error`). Each
/// wrapped source is `#[from]` (which implies `#[source]`): thiserror
/// generates the per-arm `From<XxxError>` conversion AND threads the wrapped
/// error through `source()`, so the dispatch in [`AnyParser::parse_any`] can
/// write `.map_err(Into::into)` for free. This was a Wave-1 forward item: it
/// became possible once the Wave-2 sweep gave every format error a
/// `#[derive(thiserror::Error)]` `core::error::Error` impl in all feature
/// tiers (the `#[from]`-implied `XxxError: core::error::Error` bound is now
/// satisfied unconditionally, not just under `std`). `#[from]` works even on
/// the uninhabited (empty-enum) format errors — thiserror emits a
/// `From<Empty>` whose body is type-correct but never callable, which `rustc`
/// constant-folds out at monomorphization.
#[non_exhaustive]
#[derive(Debug, Clone, thiserror::Error)]
pub enum AnyError {
  /// MOI fatal-error wrapper.
  #[cfg(feature = "moi")]
  #[error("MOI: {0}")]
  Moi(#[from] crate::formats::moi::Error),
  /// AAC fatal-error wrapper.
  #[cfg(feature = "aac")]
  #[error("AAC: {0}")]
  Aac(#[from] crate::formats::aac::Error),
  /// DV fatal-error wrapper.
  #[cfg(feature = "dv")]
  #[error("DV: {0}")]
  Dv(#[from] crate::formats::dv::Error),
  /// Audible (AA) fatal-error wrapper.
  #[cfg(feature = "audible")]
  #[error("AA: {0}")]
  Aa(#[from] crate::formats::audible::Error),
  /// Canon CRW fatal-error wrapper.
  #[cfg(feature = "crw")]
  #[error("CRW: {0}")]
  Crw(#[from] crate::formats::crw::Error),
  /// Red R3D fatal-error wrapper.
  #[cfg(feature = "red")]
  #[error("R3D: {0}")]
  R3d(#[from] crate::formats::red::Error),
  /// ID3 fatal-error wrapper.
  #[cfg(feature = "id3")]
  #[error("ID3: {0}")]
  Id3(#[from] crate::formats::id3::Id3Error),
  /// MP3 fatal-error wrapper.
  #[cfg(feature = "mp3")]
  #[error("MP3: {0}")]
  Mp3(#[from] crate::formats::id3::Mp3Error),
  /// AIFF fatal-error wrapper.
  #[cfg(feature = "aiff")]
  #[error("AIFF: {0}")]
  Aiff(#[from] crate::formats::aiff::Error),
  /// APE fatal-error wrapper.
  #[cfg(feature = "ape")]
  #[error("APE: {0}")]
  Ape(#[from] crate::formats::ape::Error),
  /// DSF fatal-error wrapper.
  #[cfg(feature = "dsf")]
  #[error("DSF: {0}")]
  Dsf(#[from] crate::formats::dsf::Error),
  /// FLAC fatal-error wrapper.
  #[cfg(feature = "flac")]
  #[error("FLAC: {0}")]
  Flac(#[from] crate::formats::flac::Error),
  /// H264 fatal-error wrapper.
  #[cfg(feature = "h264")]
  #[error("H264: {0}")]
  H264(#[from] crate::formats::h264::H264Error),
  /// Flash FLV fatal-error wrapper.
  #[cfg(feature = "flash")]
  #[error("FLV: {0}")]
  Flv(#[from] crate::formats::flash::Error),
  /// Ogg fatal-error wrapper.
  #[cfg(feature = "ogg")]
  #[error("OGG: {0}")]
  Ogg(#[from] crate::formats::ogg::Error),
  /// PNG fatal-error wrapper.
  #[cfg(feature = "png")]
  #[error("PNG: {0}")]
  Png(#[from] crate::formats::png::Error),
  /// Real (RM/RA/RAM/RPM) fatal-error wrapper.
  #[cfg(feature = "real")]
  #[error("Real: {0}")]
  Real(#[from] crate::formats::real::RealError),
  /// MPEG audio fatal-error wrapper.
  #[cfg(feature = "mpeg-audio")]
  #[error("MPEG-audio: {0}")]
  MpegAudio(#[from] crate::formats::mpeg::AudioError),
  /// MPC fatal-error wrapper.
  #[cfg(feature = "mpc")]
  #[error("MPC: {0}")]
  Mpc(#[from] crate::formats::mpc::Error),
  /// WavPack fatal-error wrapper.
  #[cfg(feature = "wavpack")]
  #[error("WV: {0}")]
  Wv(#[from] crate::formats::wavpack::Error),
  /// Matroska fatal-error wrapper.
  #[cfg(feature = "matroska")]
  #[error("Matroska: {0}")]
  Matroska(#[from] crate::formats::matroska::Error),
  /// QuickTime fatal-error wrapper.
  #[cfg(feature = "quicktime")]
  #[error("QuickTime: {0}")]
  QuickTime(#[from] crate::formats::quicktime::Error),
  /// MXF fatal-error wrapper.
  #[cfg(feature = "mxf")]
  #[error("MXF: {0}")]
  Mxf(#[from] crate::formats::mxf::MxfError),
  /// Exif/TIFF fatal-error wrapper.
  #[cfg(feature = "exif")]
  #[error("Exif: {0}")]
  Exif(#[from] crate::exif::Error),
}

// R3 F1: the bespoke `id3v2_prefix_end` helper has been removed. The
// previous dispatch arm computed an ID3v2-header offset, skipped past the
// prefix, and reparsed the OGG body — but never emitted the ID3 directory
// (silent metadata loss). The fix is `ogg::parse_full_chained`, which
// invokes the typed `parse_id3_with_hdr_end` and nests an `Id3Meta` into
// `ogg::Meta`, faithful to bundled Ogg.pm:79-83.

// ===========================================================================
// AnyParser::parse_any — the closed-dispatch entry point
// ===========================================================================

impl AnyParser {
  /// Closed-dispatch entry point: invokes the wrapped [`FormatParser`] with
  /// a per-format `Context` constructed from `bytes` + `shared`, then wraps
  /// the typed `Meta` in [`AnyMeta`].
  ///
  /// Leaf formats (MOI, AAC, DV, Audible, Red, OGG) ignore `shared`. Chained
  /// formats (ID3, MP3, AIFF, APE, DSF, FLAC, MPC, WavPack, MPEG-audio) read
  /// and/or mutate `shared` per ExifTool's `$$et{DoneID3}` / `$$et{DoneAPE}`
  /// flags (spec §6.4).
  ///
  /// `ext` is the file extension (uppercased, no leading dot) — used by
  /// the MP3 / MPEG-audio parsers for the layer-II / `.MUS` gate. Pass
  /// `None` when the extension is unknown (the parsers fall through their
  /// extension-dependent retry branches).
  ///
  /// `header_skip` is the byte count of an unknown leading header that the
  /// file-type detector scanned past for the terminal JPEG/TIFF candidate
  /// ([`crate::filetype::DetectionCandidate::header_skip`], Perl `$skip` at
  /// `ExifTool.pm:3029`); `0` for every ordinary candidate. The `JPEG`/`TIFF`
  /// arms slice `bytes` at that offset before dispatch and rebase the embedded
  /// Exif `Base` by it, so an `IsOffset` tag stays a TRUE absolute file offset.
  ///
  /// `tiff_parent_type` is the candidate's `Parent`
  /// ([`crate::filetype::DetectionCandidate::parent_type`], `$$dirInfo{Parent}`)
  /// — `"TIFF"` for a plain `.tif`/dotless/full-scan TIFF, the SUBTYPE
  /// (`DNG`/`NEF`/`CR2`/…) for a TIFF-rooted RAW. The standalone-TIFF arm gates
  /// the `File:PageCount` synthesis on `tiff_parent_type == Some("TIFF")`
  /// (bundled's `TIFF_TYPE eq 'TIFF'`, `ExifTool.pm:8715`/`:8767`); every other
  /// arm ignores it. `None` ⇒ gate off (no synthesized PageCount).
  ///
  /// # Errors
  ///
  /// Returns [`AnyError`] when the dispatched per-format parser raises a
  /// Rust-level fatal. Most ported formats today have no fatal modes
  /// (uninhabited `XxxError` enums), so the `Err` branch is unreachable
  /// in practice; the structure is in place for future I/O-fallible
  /// parsers.
  ///
  /// `ext` borrows on an INDEPENDENT (elided) lifetime — distinct from
  /// `bytes`. Only `bytes` drives the returned `AnyMeta<'a>`; no dispatch arm
  /// stores `ext` into the Meta (the MP3 / MPEG-audio arms thread it into
  /// helpers that consume it for the layer-II / `.MUS` gate but never retain
  /// it). So a caller may pass a transient `ext` string, drop it, and keep
  /// the returned Meta (Codex C-R3-1; C-R2-2 fixed the direct `parse_<fmt>`
  /// accessors but missed this closed-dispatch path).
  pub fn parse_any<'a>(
    self,
    bytes: &'a [u8],
    shared: &mut SharedFlags,
    ext: Option<&str>,
    header_skip: usize,
    tiff_parent_type: Option<&str>,
  ) -> Result<Option<AnyMeta<'a>>, AnyError> {
    // No-format build (Codex CF3): `AnyParser` has no variants, so the
    // `match` below is empty and the parameters are unused. Discard them
    // to keep the no-format tier warning-clean.
    #[cfg(not(any(
      feature = "moi",
      feature = "aac",
      feature = "dv",
      feature = "audible",
      feature = "crw",
      feature = "red",
      feature = "id3",
      feature = "mp3",
      feature = "aiff",
      feature = "ape",
      feature = "dsf",
      feature = "flac",
      feature = "h264",
      feature = "flash",
      feature = "ogg",
      feature = "png",
      feature = "real",
      feature = "mpeg-audio",
      feature = "mpc",
      feature = "wavpack",
      feature = "matroska",
      feature = "quicktime",
      feature = "mxf",
      feature = "exif",
    )))]
    let _ = (bytes, shared, ext, header_skip, tiff_parent_type);
    // `header_skip` and `tiff_parent_type` are consumed ONLY by the `JPEG`/`TIFF`
    // (`AnyParser::Exif`) arm; every other format starts at file offset 0 and is
    // not a TIFF subtype. Discard them here so a single-format build whose one
    // arm is not `Exif` stays warning-clean (the `Exif` arm's later use of the
    // `Copy` `usize` / `Option<&str>` is unaffected).
    let _ = (header_skip, tiff_parent_type);
    match self {
      #[cfg(feature = "moi")]
      AnyParser::Moi(p) => {
        let _ = (shared, ext);
        p.parse(bytes)
          .map(|o| o.map(AnyMeta::Moi))
          .map_err(Into::into)
      }
      #[cfg(feature = "aac")]
      AnyParser::Aac(p) => {
        let _ = (shared, ext);
        p.parse(bytes)
          .map(|o| o.map(AnyMeta::Aac))
          .map_err(Into::into)
      }
      #[cfg(feature = "dv")]
      AnyParser::Dv(p) => {
        let _ = (shared, ext);
        p.parse(bytes)
          .map(|o| o.map(AnyMeta::Dv))
          .map_err(Into::into)
      }
      #[cfg(feature = "audible")]
      AnyParser::Aa(p) => {
        let _ = (shared, ext);
        p.parse(bytes)
          .map(|o| o.map(AnyMeta::Aa))
          .map_err(Into::into)
      }
      #[cfg(feature = "crw")]
      AnyParser::Crw(p) => {
        // CRW is a leaf format (no cross-format chain): `shared` and `ext` are
        // unused. The CIFF walker decodes the whole HEAP tree from the byte
        // slice; the records dispatched to the ported Canon MakerNote
        // sub-tables are re-decoded to `Canon:*` tags at `serialize_tags` time
        // (faithful to `ProcessCanonRaw` dispatching `CanonRaw::Main`
        // SubDirectory records into `Image::ExifTool::Canon`).
        let _ = (shared, ext);
        p.parse(bytes)
          .map(|o| o.map(AnyMeta::Crw))
          .map_err(Into::into)
      }
      #[cfg(feature = "red")]
      AnyParser::R3D(p) => {
        let _ = (shared, ext);
        p.parse(bytes)
          .map(|o| o.map(AnyMeta::R3d))
          .map_err(Into::into)
      }
      // Chained formats dispatch via their **decoupled** `*_borrowed` /
      // `*_owned` entries: `shared` borrows independently of `bytes`, so the
      // returned `AnyMeta<'a>` borrows only from `bytes` and `shared` (a
      // transient scratch bag) does not pin the result lifetime. Going
      // through the per-format `Context<'a>` here would tie `shared` to `'a`
      // via the GAT and break the `parse_bytes` candidate loop (Codex AF2).
      #[cfg(feature = "id3")]
      AnyParser::Id3(p) => {
        let _ = (p, ext);
        // ID3 typed Meta is mode-locked; the closed dispatch stages `-j`.
        crate::formats::id3::parse_id3_borrowed(bytes, Some(shared), /* print_conv */ true)
          .map(|o| o.map(AnyMeta::Id3))
          .map_err(Into::into)
      }
      #[cfg(feature = "mp3")]
      AnyParser::Mp3(p) => {
        let _ = p;
        crate::formats::id3::parse_mp3_borrowed(bytes, ext, shared)
          .map(|o| o.map(AnyMeta::Mp3))
          .map_err(Into::into)
      }
      #[cfg(feature = "aiff")]
      AnyParser::Aiff(p) => {
        let _ = (shared, ext);
        p.parse(bytes)
          .map(|o| o.map(AnyMeta::Aiff))
          .map_err(Into::into)
      }
      #[cfg(feature = "ape")]
      AnyParser::Ape(p) => {
        let _ = (p, ext);
        // `parse_full_chained` runs the embedded ID3 chain (prefix v2 /
        // trailer v1, APE.pm:124-127) and nests the typed `Id3Meta` into the
        // returned `ape::Meta`, so the typed `parse_any` path emits the complete
        // `File:ID3Size` + `ID3v2_*`/`ID3v1` + `MAC:*` + `APE:*` tag set —
        // matching the engine `ProcessApe::process`. (`ape` pulls `id3`.)
        Ok(crate::formats::ape::parse_full_chained(bytes, shared).map(AnyMeta::Ape))
      }
      #[cfg(feature = "dsf")]
      AnyParser::Dsf(p) => {
        let _ = (p, ext, &mut *shared);
        // DSF's typed parse uses only `data`; the ID3v2 trailer scan range
        // is exposed on the Meta for the caller to dispatch.
        crate::formats::dsf::parse_borrowed(bytes)
          .map(|o| o.map(AnyMeta::Dsf))
          .map_err(Into::into)
      }
      #[cfg(feature = "flac")]
      AnyParser::Flac(p) => {
        let _ = (p, ext);
        crate::formats::flac::parse_borrowed(bytes, shared)
          .map(|o| o.map(AnyMeta::Flac))
          .map_err(Into::into)
      }
      #[cfg(feature = "h264")]
      AnyParser::H264(p) => {
        // Engine-only — `any_parser_for` never returns this arm, so the
        // dispatch is unreachable in practice. It is wired for a future
        // M2TS / MPEG port that resolves an `AnyParser::H264` directly.
        let _ = (shared, ext);
        p.parse(bytes)
          .map(|o| o.map(AnyMeta::H264))
          .map_err(Into::into)
      }
      #[cfg(feature = "flash")]
      AnyParser::Flv(p) => {
        let _ = (p, shared, ext);
        // FLV is a leaf format (no cross-format chain): ignore `shared`
        // and `ext`. The typed `parse_borrowed` accepts only a byte slice.
        crate::formats::flash::parse_borrowed(bytes)
          .map(|o| o.map(AnyMeta::Flv))
          .map_err(Into::into)
      }
      #[cfg(feature = "ogg")]
      AnyParser::Ogg(p) => {
        let _ = (p, ext);
        // R3 F1 (Codex adversarial): the OGG path now uses
        // `parse_full_chained`, which runs `unless ($$et{DoneID3}) {
        // ID3::ProcessID3 }` (Ogg.pm:79-83) BEFORE the container walk and
        // nests the typed `Id3Meta` into `ogg::Meta::id3`. Pre-fix the
        // dispatch stripped the ID3v2 prefix to reparse `bytes[hdr_end..]`
        // but never emitted the ID3 directory — silent metadata loss caught
        // by Codex round 3. The typed `serialize_tags` sink (ogg.rs)
        // emits the ID3 sub-Meta's `File:ID3Size` + `ID3v2_*:*` frame
        // tags, restoring value-equivalence with bundled.
        //
        // `success()` filtering still applies: an ID3-prefixed file whose
        // post-ID3 body is NOT a valid OGG stream (e.g. an ID3-prefixed
        // MP3) returns `success() == false` and the candidate loop
        // continues to the next file-type (MP3 will then dispatch with
        // the same `SharedFlags`'s `DoneID3` already set, mirroring
        // bundled `unless ($$et{DoneID3})` recursion guard).
        // (`ogg` requires `id3` in Cargo.toml.)
        let chained =
          crate::formats::ogg::parse_full_chained(bytes, shared, /* print_conv */ true)?
            .filter(|m| m.success());
        if let Some(m) = chained {
          return Ok(Some(AnyMeta::Ogg(m)));
        }
        Ok(None)
      }
      #[cfg(feature = "png")]
      AnyParser::Png(p) => {
        // PNG is a leaf format with no cross-format chain state — `shared`
        // and `ext` are unused. The chunk walker captures every ported
        // chunk and an optional `eXIf` TIFF block; the embedded Exif IFD
        // chain is decoded at `serialize_tags` time via the Exif sub-
        // walker (sharing the same TagMap sink, faithful to bundled's
        // `ProcessPNG → ProcessTIFF → ProcessExif` dispatch chain at
        // PNG.pm:1391).
        let _ = (shared, ext);
        p.parse(bytes)
          .map(|o| o.map(AnyMeta::Png))
          .map_err(Into::into)
      }
      #[cfg(feature = "real")]
      AnyParser::Real(p) => {
        // Real has its own internal ID3v1 trailer scan (Real.pm:678-687)
        // for the RM family. The typed parser handles that inline via
        // `formats::id3::parse_id3v1_from_block`, so no `SharedFlags`
        // threading is needed here — `done_id3` would not be set by the
        // inline path since the engine never recurses into ID3 dispatch
        // under the Real candidate.
        //
        // `ext` IS threaded: `ProcessReal` reads `$$et{FILE_EXT}`
        // (Real.pm:535) to distinguish a RAM Metafile (default) from an
        // RPM Plug-in Metafile (`.rpm` extension). The leaf
        // `FormatParser::parse` has no extension channel, so the dispatch
        // uses the extension-aware `parse_with_ext` entry instead.
        let _ = (p, shared);
        crate::formats::real::parse_with_ext(bytes, ext)
          .map(|o| o.map(AnyMeta::Real))
          .map_err(Into::into)
      }
      #[cfg(feature = "mpeg-audio")]
      AnyParser::MpegAudio(p) => {
        // The MPEG-audio parser is normally invoked internally by MP3 — it
        // is never a top-level file-type in `any_parser_for`. The closed
        // dispatch arm is provided so external callers that construct an
        // `AnyParser::MpegAudio` directly (e.g. unit tests, or future
        // crates that want raw MPEG-audio access) can still route through
        // the same closed-set machinery. The `mp3` flag and the extension
        // are derived from `ext` exactly as `ID3::ProcessMP3` does
        // (ID3.pm:1715-1717: `$ext eq 'MUS' ? 0 : 1`).
        let _ = (p, &mut *shared);
        let ext = ext.unwrap_or("");
        let mp3 = !ext.eq_ignore_ascii_case("MUS");
        crate::formats::mpeg::parse_borrowed(bytes, mp3, ext)
          .map(|o| o.map(AnyMeta::MpegAudio))
          .map_err(Into::into)
      }
      #[cfg(feature = "mpc")]
      AnyParser::Mpc(p) => {
        let _ = (p, ext);
        // F2 (Codex adversarial): `parse_full_chained` runs the embedded
        // ID3 prefix (MPC.pm:84-87) and APE trailer (MPC.pm:111-113)
        // chains and nests their typed sub-Metas — the pre-fix arm called
        // `parse_borrowed` which dropped both chains.
        // (`mpc` requires `id3` + `ape` in Cargo.toml so this `cfg(all)`
        // arm is the only one — the bare `parse_borrowed` is gone.)
        Ok(crate::formats::mpc::parse_full_chained(bytes, shared).map(AnyMeta::Mpc))
      }
      #[cfg(feature = "wavpack")]
      AnyParser::Wv(p) => {
        let _ = (p, ext);
        // F2 (Codex adversarial): `parse_full_chained` runs the APE
        // trailer chain (WavPack.pm:100-103 `APE::ProcessAPE`). The
        // pre-fix arm called `parse_borrowed` which dropped the chain.
        // (`wavpack` requires `id3` + `ape` in Cargo.toml.)
        Ok(crate::formats::wavpack::parse_full_chained(bytes, shared).map(AnyMeta::Wv))
      }
      #[cfg(feature = "matroska")]
      AnyParser::Matroska(p) => {
        let _ = (shared, ext);
        p.parse(bytes)
          .map(|o| o.map(AnyMeta::Matroska))
          .map_err(Into::into)
      }
      #[cfg(feature = "quicktime")]
      AnyParser::QuickTime(p) => {
        // QuickTime SP1 is a leaf format with no shared chain state, but it
        // DOES read `$$et{FILE_EXT}` for the `%useExt` rule (QuickTime.pm:240,
        // 10006-10007: `.glv` + MP4-compatible ftyp ⇒ `File:FileType=GLV`).
        // The leaf `FormatParser::parse` has no extension channel, so the
        // dispatch uses the extension-aware `parse_with_ext` entry instead.
        let _ = (p, shared);
        crate::formats::quicktime::parse_with_ext(bytes, ext)
          .map(|o| o.map(AnyMeta::QuickTime))
          .map_err(Into::into)
      }
      #[cfg(feature = "mxf")]
      AnyParser::Mxf(p) => {
        // MXF is a leaf format (Engine-only, no chained state): `shared`
        // and `ext` are unused.
        let _ = (shared, ext);
        p.parse(bytes)
          .map(|o| o.map(AnyMeta::Mxf))
          .map_err(Into::into)
      }
      #[cfg(feature = "exif")]
      AnyParser::Exif(p) => {
        // Exif/TIFF is a leaf format — `shared` (cross-format chain state)
        // and `ext` are unused. The IFD walker decodes the whole chain
        // (IFD0 → IFD1 → ExifIFD → GPS → InteropIFD) from the byte block.
        //
        // Container branch (faithful to ExifTool dispatching the right
        // `Process<Type>` by file magic): a camera JPEG starts with the SOI
        // marker `\xff\xd8`. For that we walk the JPEG markers and decode the
        // embedded `APP1` `Exif\0\0` block(s) (ExifTool.pm:7736-7783 — the
        // Exif arm of `ProcessJPEG`); otherwise the bytes are a standalone
        // TIFF and go straight to the IFD walker (`p.parse`). Both produce an
        // `ExifMeta`. A real TIFF never begins `\xff\xd8`, so the branch is
        // unambiguous, and the direct standalone-TIFF API
        // (`ProcessExif::parse` / `parse_exif_block`) is unaffected — only
        // this engine dispatch adds the JPEG hop.
        //
        // JPEG-container acceptance is SPLIT from Exif extraction (faithful to
        // bundled `SetFileType` at ExifTool.pm:7304, run before — and
        // independent of — the `APP1` Exif arm): `parse_jpeg_exif` returns
        // `None` ONLY for a non-JPEG, so once the SOI magic matched here the
        // result is always `Ok(Some(..))` and the JPEG candidate is ALWAYS
        // accepted — finalizing `File:FileType = JPEG` even for a stripped /
        // editor JPEG with no usable `APP1` Exif (its `ExifMeta` then carries
        // no entries, just a `Malformed APP1 EXIF segment` warning where
        // bundled warns). Engine `Ok(None)` candidate-rejection can no longer
        // mis-reject a valid JPEG into a finalization error.
        //
        // Unknown-leading-header (Codex R18 F2): the file-type detector's
        // terminal candidate (`ExifTool.pm:3026-3034`) scans PAST `header_skip`
        // junk bytes to find a JPEG `SOI` (`\xff\xd8\xff`) or a TIFF magic.
        // When `header_skip > 0` the JPEG/TIFF body therefore starts at
        // `bytes[header_skip..]`, and the embedded Exif `Base` must be rebased
        // by `header_skip` (Perl `$dirInfo{Base} = $pos + $skip` —
        // `ExifTool.pm:3030` — flows into the TIFF block's `Base`, keeping
        // `IsOffset` tags absolute). Pre-fix this arm only matched a `SOI` at
        // byte 0, so a recoverable/edited JPEG with a small unknown header was
        // detected then mis-rejected into a `File format error`.
        // Exif/TIFF is a leaf format — `shared` is unused, and the `p` unit
        // dispatcher is bypassed for the base-aware entry below. `ext` IS used
        // by the standalone-TIFF arm: it feeds the finalized-`FILE_TYPE`
        // computation (the sub-type-by-ext promotion).
        let _ = (p, shared);
        let body = bytes.get(header_skip..).unwrap_or(&[]);
        if body.len() >= 2 && body[0] == 0xff && body[1] == 0xd8 {
          return Ok(
            crate::exif::jpeg::parse_jpeg_exif_with_base(body, header_skip).map(AnyMeta::Exif),
          );
        }
        // A standalone TIFF — at byte 0 normally, or at `bytes[header_skip..]`
        // for the detector's terminal TIFF-after-unknown-header candidate.
        // `base == header_skip` rebases its `IsOffset` tags to absolute file
        // offsets. The `File:PageCount` gate follows bundled's
        // `$$self{TIFF_TYPE} eq 'TIFF'` (`ExifTool.pm:8715`/`:8767`): ON for a
        // plain `TIFF` candidate Parent, OFF for a TIFF-rooted SUBTYPE
        // (`DNG`/`NEF`/`CR2`/…), which reaches this arm via its `TIFF` candidate
        // (`file_type() == "TIFF"`) but carries the subtype as its `parent_type`
        // — so a multi-page RAW does NOT gain a non-bundled `File:PageCount`.
        let base = u32::try_from(header_skip).unwrap_or(u32::MAX);
        let tiff_type_is_tiff = tiff_parent_type == Some("TIFF");
        // Thread the FINALIZED `$$self{FILE_TYPE}` — the SAME string the engine
        // emits as `File:FileType` — as the container file type, so the
        // `Canon::ShotInfo` pos-22 CRW-allows-0 RawConv (`Canon.pm:2977`/
        // `:2990`, which keys on `$$self{FILE_TYPE} eq "CRW"`) checks the RIGHT
        // variable. It is the candidate `Parent` run through `DoProcessTIFF`'s
        // `$t`/`SetFileType` rule (ExifTool.pm:8685-8694) + the sub-type-by-ext
        // promotion — NOT the bare `Parent` (`tiff_parent_type`). The two
        // diverge for a `.crw`-named TIFF-magic file: its `Parent` is `"CRW"`
        // (the uppercased ext) but its finalized `FILE_TYPE` is `"TIFF"` (CRW's
        // base module is `CanonRaw`, not TIFF, and `"CRW"` lacks a `RAW`
        // substring, so `$t` is undef ⇒ stays `"TIFF"`). The standalone-TIFF
        // base type is always `"TIFF"` (the only candidate `file_type()` that
        // maps to `AnyParser::Exif`). The result is provably never `"CRW"` (no
        // CIFF/CRW front-end; `CRW` is never a TIFF-base/RAW promotion), so the
        // CRW branch stays correctly dead — but the gate now checks the right
        // value, and the `.crw`-named-TIFF case matches bundled.
        // `$$dirInfo{Parent} || ''` (ExifTool.pm:8685) — a missing candidate
        // Parent (dotless / embedded TIFF) is the empty string ⇒ `$t` undef ⇒
        // the finalized name stays the detected `"TIFF"`.
        let file_type =
          crate::parser::finalized_tiff_file_type("TIFF", tiff_parent_type.unwrap_or(""), ext);
        Ok(
          crate::exif::parse_standalone_tiff_with_base(
            body,
            base,
            tiff_type_is_tiff,
            Some(&file_type),
          )
          .map(AnyMeta::Exif),
        )
      }
    }
  }
}

/// Map a finalized ExifTool file-type string to its [`AnyParser`] arm, or
/// `None` if the format has no ported parser yet OR its Cargo feature is
/// disabled. This is the runtime parser registry the engine entry
/// [`crate::parser::extract_info`] dispatches through; it returns `None` for
/// feature-pruned formats, faithful to ExifTool's "module not loaded ⇒
/// `next` in candidate loop" (ExifTool.pm:3060-3077).
#[must_use]
pub fn any_parser_for(file_type: &str) -> Option<AnyParser> {
  match file_type {
    #[cfg(feature = "audible")]
    "AA" => Some(AnyParser::Aa(crate::formats::audible::ProcessAa)),
    #[cfg(feature = "aac")]
    "AAC" => Some(AnyParser::Aac(crate::formats::aac::ProcessAac)),
    #[cfg(feature = "aiff")]
    "AIFF" => Some(AnyParser::Aiff(crate::formats::aiff::ProcessAiff)),
    #[cfg(feature = "ape")]
    "APE" => Some(AnyParser::Ape(crate::formats::ape::ProcessApe)),
    // Canon CRW (CIFF) raw container. `%fileTypeLookup{CRW}` resolves the
    // `.crw` extension + the `HEAP(CCDR|JPGM)` CIFF signature to file type
    // "CRW" (base module `CanonRaw`, MIME `image/x-canon-crw`); bundled
    // `ProcessCRW` (CanonRaw.pm:812) validates the header + walks the HEAP
    // tree. (NOTE: a TIFF-magic file merely NAMED `.crw` is detected as TIFF,
    // not CRW — handled by the standalone-TIFF `AnyParser::Exif` arm; this arm
    // is only reached for a genuine CIFF-signature CRW.)
    #[cfg(feature = "crw")]
    "CRW" => Some(AnyParser::Crw(crate::formats::crw::ProcessCrw)),
    #[cfg(feature = "dsf")]
    "DSF" => Some(AnyParser::Dsf(crate::formats::dsf::ProcessDsf)),
    #[cfg(feature = "dv")]
    "DV" => Some(AnyParser::Dv(crate::formats::dv::ProcessDv)),
    #[cfg(feature = "flac")]
    "FLAC" => Some(AnyParser::Flac(crate::formats::flac::ProcessFlac)),
    // A camera JPEG (`File:FileType == "JPEG"`) is the primary camera-photo
    // format. Bundled `ProcessJPEG` (ExifTool.pm:7260-7821) walks the JPEG
    // markers and dispatches the `APP1` `Exif\0\0` segment to ProcessTIFF →
    // ProcessExif (ExifTool.pm:7736-7783). We route JPEG to the SAME
    // `AnyParser::Exif` arm: the dispatch in `parse_any` branches on the JPEG
    // SOI magic (`\xff\xd8`) to run the marker walk
    // ([`crate::exif::jpeg::parse_jpeg_exif`]) before falling through to the
    // standalone-TIFF path. Both yield an `ExifMeta` (the GPS sub-IFD, row 14,
    // is decoded through it). The non-Exif JPEG segments (APP0/APP13/SOF/…)
    // and multi-segment APP1 XMP are a deferred JPEG-container follow-up
    // (`docs/tracking.md`).
    #[cfg(feature = "exif")]
    "JPEG" => Some(AnyParser::Exif(crate::exif::ProcessExif)),
    #[cfg(feature = "matroska")]
    "MKV" => Some(AnyParser::Matroska(
      crate::formats::matroska::ProcessMatroska,
    )),
    #[cfg(feature = "flash")]
    "FLV" => Some(AnyParser::Flv(crate::formats::flash::ProcessFlv)),
    #[cfg(feature = "mp3")]
    "MP3" => Some(AnyParser::Mp3(crate::formats::id3::ProcessMp3)),
    #[cfg(feature = "moi")]
    "MOI" => Some(AnyParser::Moi(crate::formats::moi::ProcessMoi)),
    // ExifTool maps every QuickTime extension (MOV / MP4 / M4A / M4V /
    // M4B / M4P / 3GP / 3G2 / …) to base type `"MOV"` via the
    // `%fileTypeLookup` table; `detection_candidates` yields `"MOV"` as
    // the candidate file_type. The parser differentiates MP4/M4A/… from
    // the `ftyp` brands and drives the right `SetFileType` (via
    // `FileTypeFinalize::Explicit`).
    #[cfg(feature = "quicktime")]
    "MOV" => Some(AnyParser::QuickTime(crate::formats::quicktime::ProcessMov)),
    #[cfg(feature = "mpc")]
    "MPC" => Some(AnyParser::Mpc(crate::formats::mpc::ProcessMpc)),
    #[cfg(feature = "mxf")]
    "MXF" => Some(AnyParser::Mxf(crate::formats::mxf::ProcessMxf)),
    #[cfg(feature = "ogg")]
    "OGG" => Some(AnyParser::Ogg(crate::formats::ogg::ProcessOgg)),
    // PNG (FORMATS.md row 11) — `%fileTypeLookup{PNG}` resolves the
    // `.png`/`.apng`/`.mng`/`.jng` extension and the 8-byte signature to
    // file type "PNG"; bundled `ProcessPNG` (PNG.pm:1410) dispatches the
    // chunk walker. The eXIf chunk's TIFF block is handed to the Exif
    // walker at serialize time (PNG.pm:1391 `$et->ProcessTIFF($dirInfo)`).
    #[cfg(feature = "png")]
    "PNG" => Some(AnyParser::Png(crate::formats::png::ProcessPng)),
    // ExifTool maps RM / RA / RMVB / RV / RAM / RPM extensions to base type
    // `"Real"` via the `%fileTypeLookup` aliases; detection_candidates
    // yields `"Real"` as the candidate file_type.
    #[cfg(feature = "real")]
    "Real" => Some(AnyParser::Real(crate::formats::real::ProcessReal)),
    #[cfg(feature = "red")]
    "R3D" => Some(AnyParser::R3D(crate::formats::red::ProcessR3D)),
    // A standalone TIFF file IS an Exif/TIFF block (FORMATS.md row 13):
    // `%fileTypeLookup{TIFF}` resolves the `.tif`/`.tiff` extension and the
    // `II*\0`/`MM\0*` magic to file type "TIFF", dispatched here. The Exif
    // IFD walker decodes IFD0 → IFD1 → ExifIFD → GPS → InteropIFD; the GPS
    // sub-IFD (row 14) is reached through it. RAW formats whose base type is
    // "TIFF" (CR2/NEF/DNG/ARW/…) also resolve to file type "TIFF" — they
    // dispatch here too, decoding their standard Exif IFDs (vendor MakerNote
    // parsing is the deferred MakerNotes wave).
    #[cfg(feature = "exif")]
    "TIFF" => Some(AnyParser::Exif(crate::exif::ProcessExif)),
    #[cfg(feature = "wavpack")]
    "WV" => Some(AnyParser::Wv(crate::formats::wavpack::ProcessWv)),
    _ => None,
  }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn shared_flags_round_trip() {
    let mut sf = SharedFlags::new();
    assert_eq!(sf.done_id3(), None);
    assert!(!sf.done_ape());
    assert!(sf.file_type_stack_slice().is_empty());
    assert_eq!(sf.current_file_type(), None);

    sf.set_done_id3(128);
    sf.set_done_ape(true);
    sf.push_file_type("MP3");
    sf.push_file_type("ID3");
    assert_eq!(sf.done_id3(), Some(128));
    assert!(sf.done_ape());
    assert_eq!(sf.current_file_type(), Some("ID3"));
    assert_eq!(sf.file_type_stack_slice(), &[Some("MP3"), Some("ID3")]);

    assert_eq!(sf.pop_file_type(), Some("ID3"));
    assert_eq!(sf.pop_file_type(), Some("MP3"));
    assert_eq!(sf.pop_file_type(), None);
    assert!(sf.file_type_stack_slice().is_empty());
  }

  /// `any_parser_for` resolves every ported format that has its feature
  /// enabled, and returns `None` for unported / video-side / empty
  /// file-type strings (the candidate-loop fall-through cases).
  #[test]
  fn any_parser_for_resolves_ported_formats() {
    #[cfg(feature = "audible")]
    assert!(any_parser_for("AA").is_some());
    #[cfg(feature = "aac")]
    assert!(any_parser_for("AAC").is_some());
    #[cfg(feature = "aiff")]
    assert!(any_parser_for("AIFF").is_some());
    #[cfg(feature = "ape")]
    assert!(any_parser_for("APE").is_some());
    #[cfg(feature = "dsf")]
    assert!(any_parser_for("DSF").is_some());
    #[cfg(feature = "dv")]
    assert!(any_parser_for("DV").is_some());
    #[cfg(feature = "flac")]
    assert!(any_parser_for("FLAC").is_some());
    #[cfg(feature = "flash")]
    assert!(any_parser_for("FLV").is_some());
    #[cfg(feature = "moi")]
    assert!(any_parser_for("MOI").is_some());
    #[cfg(feature = "mp3")]
    assert!(any_parser_for("MP3").is_some());
    #[cfg(feature = "mpc")]
    assert!(any_parser_for("MPC").is_some());
    #[cfg(feature = "ogg")]
    assert!(any_parser_for("OGG").is_some());
    #[cfg(feature = "real")]
    assert!(any_parser_for("Real").is_some());
    #[cfg(feature = "red")]
    assert!(any_parser_for("R3D").is_some());
    #[cfg(feature = "wavpack")]
    assert!(any_parser_for("WV").is_some());
    // Exif/TIFF: a standalone TIFF AND a camera JPEG both route to the Exif
    // walker (the JPEG dispatch branches on SOI magic in `parse_any`). Codex
    // R16/F1: the JPEG arm is the core product capability — without it a
    // camera photo's Make/Model/DateTime/GPS were never extracted.
    #[cfg(feature = "exif")]
    {
      assert!(any_parser_for("TIFF").is_some());
      assert!(any_parser_for("JPEG").is_some());
    }
    assert!(any_parser_for("MPEG").is_none()); // video side deferred
    assert!(any_parser_for("").is_none());
    assert!(any_parser_for("AIFC").is_none()); // resolves to AIFF via lookup, not directly
  }

  /// `parse_any` dispatches through `AnyParser::Moi` and returns a
  /// `AnyMeta::Moi` arm for a valid MOI file. Verifies that the closed-set
  /// dispatch produces the same shape as the direct typed entry.
  #[cfg(feature = "moi")]
  #[test]
  fn parse_any_moi_via_closed_dispatch() {
    // Minimal MOI v6 file: V6 magic + 16 bytes of header (the parser will
    // accept the magic and produce a partial Meta or `None`; we only verify
    // the dispatch shape compiles and routes through the AnyMeta::Moi arm).
    let bytes = b"V6\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let parser = any_parser_for("MOI").expect("MOI feature enabled");
    let mut shared = SharedFlags::new();
    // `header_skip == 0`: an ordinary (non-header-skip) candidate.
    let result = parser.parse_any(bytes, &mut shared, None, 0, None);
    // The exact `Some`/`None` outcome depends on the MOI parser's
    // acceptance rules for a 16-byte buffer; this test just verifies the
    // dispatch doesn't panic and produces an `Ok(_)` result.
    assert!(result.is_ok());
  }

  /// Codex C-R3-1: `parse_any` decouples the transient `ext` borrow from the
  /// returned `AnyMeta<'a>` (only `bytes` flows into the Meta). The MP3 arm
  /// threads `ext` into `parse_mp3_borrowed` for the layer-II / `.MUS` gate
  /// but never stores it, so a short-lived `ext` string may be dropped while
  /// the returned Meta lives on. This compiles ONLY if `ext` is on an
  /// independent lifetime; it is the closed-dispatch analogue of
  /// `lib::parse_mp3_meta_outlives_transient_ext` (which covered the direct
  /// accessor under C-R2-2). The byte buffer is a minimal MPEG-audio sync
  /// frame so the MP3 arm produces `Some`.
  #[cfg(feature = "mp3")]
  #[test]
  fn parse_any_meta_outlives_transient_ext() {
    let bytes: Vec<u8> = vec![0xff, 0xfb, 0x90, 0x00];
    let parser = any_parser_for("MP3").expect("MP3 feature enabled");
    let mut shared = SharedFlags::new();
    let meta = {
      // `ext` is a short-lived String dropped at the end of this block.
      let ext: String = String::from("MP3");
      let m = parser
        .parse_any(&bytes, &mut shared, Some(ext.as_str()), 0, None)
        .expect("ok");
      // `ext` drops here; `m` must remain valid (it borrows only `bytes`).
      m
    };
    // Use the meta after `ext` is gone — proves the decoupling.
    let _ = meta.is_some();
  }

  /// `AnyError` formats nicely via `Display`. Most format errors are
  /// uninhabited, so the variant constructors aren't constructible — but
  /// the `Display` impl compiles, which is what matters.
  #[test]
  fn any_error_implements_display() {
    fn _accepts_display<E: core::fmt::Display>(_: &E) {}
    fn _check_any_error(e: &AnyError) {
      _accepts_display(e);
    }
  }

  /// `Rendered` serializes a typed `AnyMeta`'s FORMAT tags to a flat
  /// `"<Group1>:<Name>": value` JSON object via `serde_json`, honouring the
  /// `-j`/`-n` mode, with NO orchestration triplet (SourceFile/File:*/version).
  /// Driven through a real AAC fixture so the chain (sink → records → serde)
  /// is exercised end to end.
  #[cfg(all(feature = "json", feature = "aac"))]
  #[test]
  fn rendered_serializes_meta_format_tags_both_modes() {
    use crate::{format_parser::Rendered, jsondiff::json_equivalent};
    let data = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/tests/fixtures/AAC.aac"
    ))
    .expect("read AAC.aac fixture");
    let parser = any_parser_for("AAC").expect("AAC feature enabled");
    let mut shared = SharedFlags::new();
    let meta = parser
      .parse_any(&data, &mut shared, Some("AAC"), 0, None)
      .expect("parse ok")
      .expect("AAC recognized");

    // -j (PrintConv): a flat object of AAC:* tags; no SourceFile / File:* /
    // ExifTool:* orchestration (those are the engine's job, not `Rendered`'s).
    let j = serde_json::to_string(&Rendered::new(&meta, true)).expect("serialize -j");
    assert!(j.starts_with('{') && j.ends_with('}'), "flat object: {j}");
    assert!(!j.contains("SourceFile"), "no orchestration tags: {j}");
    let v: serde_json::Value = serde_json::from_str(&j).expect("valid JSON");
    let obj = v.as_object().expect("object");
    assert!(
      obj.keys().all(|k| k.starts_with("AAC:")),
      "only AAC:* format tags: {j}"
    );
    // The flat object is value-equivalent to the AAC:* slice of the engine's
    // full document (a strict subset check via a hand-picked known tag).
    assert!(
      obj.contains_key("AAC:SampleRate"),
      "AAC:SampleRate present: {j}"
    );

    // -n (raw): same key set, values are the raw post-ValueConv scalars.
    let n = serde_json::to_string(&Rendered::new(&meta, false)).expect("serialize -n");
    let vn: serde_json::Value = serde_json::from_str(&n).expect("valid JSON");
    assert_eq!(
      v.as_object().unwrap().len(),
      vn.as_object().unwrap().len(),
      "-j and -n carry the same tag set"
    );
    // `Rendered` is value-stable: serializing twice yields equivalent JSON.
    let j2 = serde_json::to_string(&Rendered::new(&meta, true)).expect("serialize again");
    json_equivalent(&j, &j2).expect("Rendered is deterministic");
  }
}

/// The [`parser_sealed::Sealed`] super-trait is private, so downstream
/// crates cannot implement [`FormatParser`] for foreign types. This
/// `compile_fail` doc-test demonstrates: trying to implement
/// [`FormatParser`] without sealing the type produces an E0405
/// (trait not satisfied) compilation error.
///
/// ```compile_fail
/// use exifast::format_parser::FormatParser;
///
/// struct ForeignParser;
///
/// impl FormatParser for ForeignParser {
///   type Meta = ();
///   type Context<'a> = &'a [u8];
///   type Error = ();
///   fn parse<'a>(&self, _ctx: &'a [u8]) -> Result<Option<()>, ()> {
///     Ok(None)
///   }
/// }
/// ```
#[cfg(doctest)]
#[allow(dead_code)]
struct SealedTraitDocTestAnchor;
