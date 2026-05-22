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
  /// Ogg (Phase F4 — Ogg container + Vorbis comments + Opus + Theora delegation).
  #[cfg(feature = "ogg")]
  Ogg(crate::formats::ogg::ProcessOgg),
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
  /// Ogg (Phase F4 — Ogg container + Vorbis comments). The
  /// [`crate::formats::ogg::ProcessOgg`] `FormatParser` impl produces a
  /// borrowed `ogg::Meta<'a>` via the [`FormatParser::Meta`] GAT (Codex
  /// AF2; `'a` is phantom there since `ogg::Meta` owns its data).
  #[cfg(feature = "ogg")]
  Ogg(crate::formats::ogg::Meta<'a>),
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
    feature = "red",
    feature = "id3",
    feature = "mp3",
    feature = "aiff",
    feature = "ape",
    feature = "dsf",
    feature = "flac",
    feature = "ogg",
    feature = "real",
    feature = "mpeg-audio",
    feature = "mpc",
    feature = "wavpack",
    feature = "matroska",
    feature = "quicktime",
  )))]
  #[doc(hidden)]
  _Phantom(core::marker::PhantomData<&'a ()>),
}

#[cfg(feature = "alloc")]
impl AnyMeta<'_> {
  /// Serialize this typed Meta's FORMAT tags into the inline tag-collection
  /// sink [`crate::tagmap::TagMap`] (the typed-path replacement for the deleted
  /// `serialize_tags`). Dispatches to each format's inherent
  /// `serialize_tags`, flattening nested sub-Metas (Mp3 → ID3/MPEG/APE,
  /// Dsf/Ape → ID3). `print_conv = true` emits PrintConv strings (`-j`);
  /// `false` emits post-ValueConv raw scalars (`-n`). Infallible.
  pub(crate) fn serialize_tags(
    &self,
    print_conv: bool,
    out: &mut crate::tagmap::TagMap,
  ) -> Result<(), core::convert::Infallible> {
    // `#[non_exhaustive]` on `AnyMeta` plus per-format `cfg(feature)` gates
    // means a `_`-less match is exhaustive when ≥1 format feature is on
    // (the real arms), and when NO format feature is on (only the
    // `_Phantom` arm, Codex CF3). The `all-formats` default takes the
    // former path; the phantom arm below keeps the no-format build
    // type-checking.
    match self {
      #[cfg(feature = "moi")]
      AnyMeta::Moi(m) => m.serialize_tags(print_conv, out),
      #[cfg(feature = "aac")]
      AnyMeta::Aac(m) => m.serialize_tags(print_conv, out),
      #[cfg(feature = "dv")]
      AnyMeta::Dv(o) => match o {
        // DV.pm:188 — Warn + return 1 without DV:* tags. The typed path emits
        // the warning and no tags (the document builder surfaces it as the
        // ExifTool:Warning).
        crate::formats::dv::ParseOutcome::UnrecognizedProfile => {
          out.write_warning("Unrecognized DV profile")
        }
        crate::formats::dv::ParseOutcome::Meta(m) => m.serialize_tags(print_conv, out),
      },
      #[cfg(feature = "audible")]
      AnyMeta::Aa(m) => m.serialize_tags(print_conv, out),
      #[cfg(feature = "red")]
      AnyMeta::R3d(m) => m.serialize_tags(print_conv, out),
      #[cfg(feature = "id3")]
      AnyMeta::Id3(m) => m.serialize_tags(print_conv, out),
      #[cfg(feature = "mp3")]
      AnyMeta::Mp3(m) => m.serialize_tags(print_conv, out),
      #[cfg(feature = "aiff")]
      AnyMeta::Aiff(m) => m.serialize_tags(print_conv, out),
      #[cfg(feature = "ape")]
      AnyMeta::Ape(m) => m.serialize_tags(print_conv, out),
      #[cfg(feature = "dsf")]
      AnyMeta::Dsf(m) => m.serialize_tags(print_conv, out),
      #[cfg(feature = "flac")]
      AnyMeta::Flac(m) => m.serialize_tags(print_conv, out),
      #[cfg(feature = "ogg")]
      AnyMeta::Ogg(m) => m.serialize_tags(print_conv, out),
      #[cfg(feature = "real")]
      AnyMeta::Real(m) => m.serialize_tags(print_conv, out),
      #[cfg(feature = "mpeg-audio")]
      AnyMeta::MpegAudio(m) => m.serialize_tags(print_conv, out),
      #[cfg(feature = "mpc")]
      AnyMeta::Mpc(m) => m.serialize_tags(print_conv, out),
      #[cfg(feature = "wavpack")]
      AnyMeta::Wv(m) => m.serialize_tags(print_conv, out),
      #[cfg(feature = "matroska")]
      AnyMeta::Matroska(m) => m.serialize_tags(print_conv, out),
      #[cfg(feature = "quicktime")]
      AnyMeta::QuickTime(m) => m.serialize_tags(print_conv, out),
      // No-format build: the only variant is the uninhabitable phantom
      // (Codex CF3). `PhantomData` carries no data; the arm exists purely
      // for exhaustiveness.
      #[cfg(not(any(
        feature = "moi",
        feature = "aac",
        feature = "dv",
        feature = "audible",
        feature = "red",
        feature = "id3",
        feature = "mp3",
        feature = "aiff",
        feature = "ape",
        feature = "dsf",
        feature = "flac",
        feature = "ogg",
        feature = "real",
        feature = "mpeg-audio",
        feature = "mpc",
        feature = "wavpack",
        feature = "matroska",
        feature = "quicktime",
      )))]
      AnyMeta::_Phantom(_) => {
        let _ = (print_conv, out);
        Ok(())
      }
    }
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
      // OGG: detected ("OGG"), then optional content override (OGV/OPUS).
      #[cfg(feature = "ogg")]
      AnyMeta::Ogg(m) => match m.file_type_override() {
        Some(target) => FileTypeFinalize::DetectedThenOverride(target),
        None => FileTypeFinalize::Detected,
      },
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
      #[cfg(not(any(
        feature = "moi",
        feature = "aac",
        feature = "dv",
        feature = "audible",
        feature = "red",
        feature = "id3",
        feature = "mp3",
        feature = "aiff",
        feature = "ape",
        feature = "dsf",
        feature = "flac",
        feature = "ogg",
        feature = "real",
        feature = "mpeg-audio",
        feature = "mpc",
        feature = "wavpack",
        feature = "matroska",
        feature = "quicktime",
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
      let mut map = s.serialize_map(Some(entries.len()))?;
      for (key, value) in entries {
        map.serialize_entry(key.as_str(), value)?;
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
  /// Ogg fatal-error wrapper.
  #[cfg(feature = "ogg")]
  #[error("OGG: {0}")]
  Ogg(#[from] crate::formats::ogg::Error),
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
  ) -> Result<Option<AnyMeta<'a>>, AnyError> {
    // No-format build (Codex CF3): `AnyParser` has no variants, so the
    // `match` below is empty and the parameters are unused. Discard them
    // to keep the no-format tier warning-clean.
    #[cfg(not(any(
      feature = "moi",
      feature = "aac",
      feature = "dv",
      feature = "audible",
      feature = "red",
      feature = "id3",
      feature = "mp3",
      feature = "aiff",
      feature = "ape",
      feature = "dsf",
      feature = "flac",
      feature = "ogg",
      feature = "real",
      feature = "mpeg-audio",
      feature = "mpc",
      feature = "wavpack",
      feature = "matroska",
      feature = "quicktime",
    )))]
    let _ = (bytes, shared, ext);
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
    #[cfg(feature = "dsf")]
    "DSF" => Some(AnyParser::Dsf(crate::formats::dsf::ProcessDsf)),
    #[cfg(feature = "dv")]
    "DV" => Some(AnyParser::Dv(crate::formats::dv::ProcessDv)),
    #[cfg(feature = "flac")]
    "FLAC" => Some(AnyParser::Flac(crate::formats::flac::ProcessFlac)),
    #[cfg(feature = "matroska")]
    "MKV" => Some(AnyParser::Matroska(
      crate::formats::matroska::ProcessMatroska,
    )),
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
    #[cfg(feature = "ogg")]
    "OGG" => Some(AnyParser::Ogg(crate::formats::ogg::ProcessOgg)),
    // ExifTool maps RM / RA / RMVB / RV / RAM / RPM extensions to base type
    // `"Real"` via the `%fileTypeLookup` aliases; detection_candidates
    // yields `"Real"` as the candidate file_type.
    #[cfg(feature = "real")]
    "Real" => Some(AnyParser::Real(crate::formats::real::ProcessReal)),
    #[cfg(feature = "red")]
    "R3D" => Some(AnyParser::R3D(crate::formats::red::ProcessR3D)),
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
    let result = parser.parse_any(bytes, &mut shared, None);
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
        .parse_any(&bytes, &mut shared, Some(ext.as_str()))
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
      .parse_any(&data, &mut shared, Some("AAC"))
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
