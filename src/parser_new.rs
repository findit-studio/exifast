// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! New lib-first `FormatParser` trait scaffold. Lands alongside the existing
//! [`crate::parser::OldFormatParser`] (aliased from the legacy
//! [`crate::parser::FormatParser`]); each format migrates from old to new in
//! Phases E–F per the design spec at
//! `docs/superpowers/specs/2026-05-21-lib-first-formatparser-design.md`.
//!
//! The four central pieces, per spec §6:
//!
//! - [`FormatParser`] — the central parser trait with associated `Meta`,
//!   `Context<'a>`, and `Error` types. Sealed via [`parser_sealed::Sealed`]
//!   so downstream crates cannot add format arms.
//! - [`TagWriter`] — fallible sink receiving tag emissions. Mirrors
//!   `mediaframe::PixelSink`. Implementors that cannot fail use
//!   [`core::convert::Infallible`] as `Error`.
//! - [`MetaSinker`] — implemented by `Meta` types; emits the format's tags
//!   into a `TagWriter`.
//! - [`SharedFlags`] — cross-format shared state (DoneID3 / DoneAPE / file-type
//!   stack) threaded through chained parsers.
//!
//! The closed-set enums [`AnyParser`] and [`AnyMeta`] dispatch over the
//! runtime-keyed parser registry. Each format adds an arm in Phase E (MOI)
//! / Phase F (everything else). Both are `#[non_exhaustive]` so new format
//! arms are additive.

use core::fmt;

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
///    [`AnyMeta`], and [`AnyMeta`]'s [`MetaSinker`] impl.
pub trait FormatParser: parser_sealed::Sealed {
  /// The typed metadata structure this parser produces on a successful
  /// parse. Should typically borrow from the input bytes (`Meta<'a>`),
  /// holding `&'a str` / primitive integers / `core::time::Duration` /
  /// `jiff::civil::DateTime` for no-alloc compatibility.
  type Meta;
  /// Per-format input view. Leaf formats (MOI, AAC, DV, Audible) use
  /// `&'a [u8]`; chained formats (ID3, APE, MP3, …) use a struct
  /// wrapping `&'a [u8]` + `&'a mut SharedFlags`.
  type Context<'a>
  where
    Self: 'a;
  /// Rust-level fatal error (distinct from Perl `Warn`/`Error` tags, which
  /// belong to `Meta` and propagate via [`TagWriter::write_warning`] /
  /// [`TagWriter::write_error`]).
  type Error;

  /// Run the parser on a per-format `Context`. See trait docs for return
  /// value semantics.
  fn parse(&self, ctx: Self::Context<'_>) -> Result<Option<Self::Meta>, Self::Error>;
}

/// Receivers of tag emissions. Implemented by JSON writers, in-memory
/// `BTreeMap` collectors, validation harnesses, etc.
///
/// Sinks that cannot fail use [`core::convert::Infallible`] as `Error` —
/// the compiler eliminates the `Result` branching at every call site.
/// Same pattern as `mediaframe::PixelSink::Error`.
///
/// Methods take primitive types directly rather than a `TagValue` enum:
/// this lets implementors write specialized output paths (e.g., JSON
/// numeric-vs-string emission for `u64` vs `&str`) without an intermediate
/// boxed/enum allocation. The [`Self::write_fmt`] entry is the no-alloc
/// workhorse: `PrintConv` strings format directly into the writer's sink,
/// never materializing as a `String`.
pub trait TagWriter {
  /// Sink-level error type. Implementors that cannot fail set this to
  /// [`core::convert::Infallible`].
  type Error;

  /// Emit a `&str` value (e.g., `File:FileType=MOI`).
  fn write_str(&mut self, group: &str, name: &str, value: &str) -> Result<(), Self::Error>;
  /// Emit a `u64` value (e.g., `File:FileSize=12345`).
  fn write_u64(&mut self, group: &str, name: &str, value: u64) -> Result<(), Self::Error>;
  /// Emit an `i64` value (e.g., a signed integer tag).
  fn write_i64(&mut self, group: &str, name: &str, value: i64) -> Result<(), Self::Error>;
  /// Emit an `f64` value (e.g., a rational converted to floating point).
  fn write_f64(&mut self, group: &str, name: &str, value: f64) -> Result<(), Self::Error>;
  /// Emit raw bytes (e.g., a cover-art payload).
  fn write_bytes(&mut self, group: &str, name: &str, value: &[u8]) -> Result<(), Self::Error>;
  /// Format directly into the writer's `core::fmt::Write` sink — no
  /// intermediate `String` allocation. Used by `PrintConv` emissions
  /// (e.g., `ConvertDuration` → `"0:05:00.300"`).
  fn write_fmt(
    &mut self,
    group: &str,
    name: &str,
    f: impl FnOnce(&mut dyn fmt::Write) -> fmt::Result,
  ) -> Result<(), Self::Error>;
  /// Emit a `Warning` tag (Perl `$et->Warn`).
  fn write_warning(&mut self, text: &str) -> Result<(), Self::Error>;
  /// Emit an `Error` tag (Perl `$et->Error`).
  fn write_error(&mut self, text: &str) -> Result<(), Self::Error>;
  /// Emit a list of `&str` values for a single (group, name) key — the
  /// list-coalesce primitive used by Vorbis ARTIST=Alice/Bob style tag
  /// repeats and APE's `Track-tag/Tag2-trailing-list` walker.
  ///
  /// The default implementation calls [`Self::write_str`] for each
  /// element in order. Writers that DO want list-aware semantics (e.g.
  /// `MetadataTagWriter` → `Metadata::push_listable`) override this method
  /// to coalesce into a single first-occurrence-position list value.
  /// Stateless writers (`MapTagWriter`, future JSON-array sinks) keep the
  /// default and either see last-write-wins (map storage) or emit each
  /// element as a separate JSON value (array sinks).
  ///
  /// Added in Phase G to let OGG/FLAC bridges use the generic
  /// [`MetaSinker`] path instead of calling `Metadata::push_listable`
  /// directly (per F3-FLAC / F4-OGG integration notes).
  fn write_str_list(
    &mut self,
    group: &str,
    name: &str,
    values: &[&str],
  ) -> Result<(), Self::Error> {
    for v in values {
      self.write_str(group, name, v)?;
    }
    Ok(())
  }
}

/// Implemented by `Meta` types: emits the format's tags into a [`TagWriter`].
/// "One who sinks metadata into a destination."
///
/// Errors propagate from the writer (the Meta itself has no error states —
/// fallibility belongs to the destination).
///
/// **Phase E discovery — `print_conv` parameter.** Spec §6.3 originally
/// shaped this as `sink<W>(&self, out: &mut W)` with no mode flag. The MOI
/// pilot (Phase E) surfaced that byte-exact reproduction of the bundled
/// `perl exiftool -j` / `-n` JSON pair requires the Meta to know whether
/// PrintConv strings (e.g. `ConvertDuration("8.16 s")`) or post-ValueConv
/// raw values (e.g. `8.16` as `f64`) should be emitted. This mirrors
/// ExifTool's `$$self{OPTIONS}{PrintConv}` flag (ExifTool.pm:5710): the
/// PrintConv toggle is a global engine option, not a writer/sink choice.
///
/// Library callers consuming typed accessors on the Meta directly never
/// touch this trait; only the CLI JSON path (`MetaSinker` → `TagWriter`)
/// needs the toggle.
pub trait MetaSinker {
  /// Emit this Meta's tags into `out`. Emission order should mirror the
  /// bundled-Perl iteration order of the format's tag table.
  ///
  /// `print_conv = true` emits PrintConv strings (faithful to
  /// `perl exiftool -j`); `print_conv = false` emits post-ValueConv raw
  /// scalars (faithful to `perl exiftool -j -n`).
  fn sink<W: TagWriter>(&self, print_conv: bool, out: &mut W) -> Result<(), W::Error>;
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
  pub fn done_id3(&self) -> Option<usize> {
    self.done_id3
  }

  /// Set `$$et{DoneID3} = trailer_size`. Called by the ID3 parser after a
  /// v1 trailer is consumed (pass `0` for the "ID3v2 found, no v1 trailer"
  /// case — ID3.pm:1436 sets the truthy `1` marker; the APE `> 1` arithmetic
  /// guard treats `0` and `1` identically, so we normalize to `0`).
  pub fn set_done_id3(&mut self, trailer_size: usize) {
    self.done_id3 = Some(trailer_size);
  }

  /// `$$et{DoneAPE}` — APE-trailer-already-handled flag, gates the
  /// wrapper fallback in `ID3.pm:1723-1726`.
  #[must_use]
  pub fn done_ape(&self) -> bool {
    self.done_ape
  }

  /// Set `$$et{DoneAPE}`. Called by the APE parser after running.
  pub fn set_done_ape(&mut self, value: bool) {
    self.done_ape = value;
  }

  /// View the current file-type stack as a slice (in push order).
  #[must_use]
  pub fn file_type_stack(&self) -> &[Option<&'static str>] {
    &self.file_type_stack[..self.file_type_stack_len]
  }

  /// Push a file-type tag onto the stack. Panics if the stack is full
  /// (current cap = 4; see the struct doc).
  pub fn push_file_type(&mut self, file_type: &'static str) {
    assert!(
      self.file_type_stack_len < self.file_type_stack.len(),
      "SharedFlags::push_file_type: stack overflow (cap={}, observed depth in bundled ExifTool is ≤ 2)",
      self.file_type_stack.len(),
    );
    self.file_type_stack[self.file_type_stack_len] = Some(file_type);
    self.file_type_stack_len += 1;
  }

  /// Pop the most recent file-type tag, returning it if the stack was
  /// non-empty.
  pub fn pop_file_type(&mut self) -> Option<&'static str> {
    if self.file_type_stack_len == 0 {
      return None;
    }
    self.file_type_stack_len -= 1;
    self.file_type_stack[self.file_type_stack_len].take()
  }

  /// Peek the most recent file-type tag without popping it.
  #[must_use]
  pub fn current_file_type(&self) -> Option<&'static str> {
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
  /// MPEG audio (Phase F4 — MP3 / MP2 / MUS frame parser + Xing/LAME tail).
  #[cfg(feature = "mpeg-audio")]
  MpegAudio(crate::formats::mpeg::ProcessMpegAudio),
  /// MPC (Phase F5 — Musepack SV7/SV8 audio, chains ID3 + APE).
  #[cfg(feature = "mpc")]
  Mpc(crate::formats::mpc::ProcessMpc),
  /// WavPack (Phase F5 — `.wv` / `.wvp` hybrid-lossless audio, chains ID3 + APE).
  #[cfg(feature = "wavpack")]
  Wv(crate::formats::wavpack::ProcessWv),
}

/// Closed-set enum of every format's `Meta` output. Mirrors [`AnyParser`].
///
/// `#[non_exhaustive]` ensures consumers cannot exhaustively match on the
/// enum across crate-feature combinations — new format arms are additive
/// within the crate, but no caller can rely on a fixed set. (Phase D
/// originally added a `_Phantom(PhantomData<&'a ()>)` variant as a
/// no-format-feature placeholder; Phase G retired it now that all 13
/// formats have a real arm.)
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum AnyMeta<'a> {
  /// MOI (Phase E pilot).
  #[cfg(feature = "moi")]
  Moi(crate::formats::moi::MoiMeta<'a>),
  /// AAC (Phase F1).
  #[cfg(feature = "aac")]
  Aac(crate::formats::aac::AacMeta<'a>),
  /// DV (Phase F1). Carries the [`crate::formats::dv::DvParseOutcome`]
  /// because DV has TWO accept paths (unrecognized-profile warn vs.
  /// full data); the closed-enum carry must distinguish them so the
  /// sink can warn on the former without emitting DV:* tags.
  #[cfg(feature = "dv")]
  Dv(crate::formats::dv::DvParseOutcome<'a>),
  /// Audible (AA) (Phase F1).
  #[cfg(feature = "audible")]
  Aa(crate::formats::audible::AaMeta<'a>),
  /// Red R3D (Phase F1).
  #[cfg(feature = "red")]
  R3d(crate::formats::red::R3dMeta<'a>),
  /// ID3 directory metadata (Phase F2). The [`crate::formats::id3::ProcessId3`]
  /// `FormatParser` impl produces `Id3Meta<'static>` (Phase E
  /// `into_static` pragma); this arm carries the `<'a>` projection so the
  /// closed enum compiles at any caller lifetime.
  #[cfg(feature = "id3")]
  Id3(crate::formats::id3::Id3Meta<'a>),
  /// MP3 wrapper metadata (Phase F2). Wraps [`crate::formats::id3::Id3Meta`]
  /// plus borrowed MPEG-audio / APE-trailer passthrough slices; the typed
  /// MPEG-audio / APE arms land in Phase F3/F4 (per
  /// `docs/tracking.md` F2 ID3 integration notes).
  #[cfg(feature = "mp3")]
  Mp3(crate::formats::id3::Mp3Meta<'a>),
  /// AIFF (Phase F3).
  #[cfg(feature = "aiff")]
  Aiff(crate::formats::aiff::AiffMeta<'a>),
  /// APE (Phase F3).
  #[cfg(feature = "ape")]
  Ape(crate::formats::ape::ApeMeta<'a>),
  /// DSF (Phase F3).
  #[cfg(feature = "dsf")]
  Dsf(crate::formats::dsf::DsfMeta<'a>),
  /// FLAC (Phase F3).
  #[cfg(feature = "flac")]
  Flac(crate::formats::flac::FlacMeta<'a>),
  /// Ogg (Phase F4 — Ogg container + Vorbis comments). The
  /// [`crate::formats::ogg::ProcessOgg`] `FormatParser` impl produces
  /// `OggMeta<'static>` (Phase E `into_static` pragma); this arm carries
  /// the `<'a>` projection so the closed enum compiles at any caller
  /// lifetime.
  #[cfg(feature = "ogg")]
  Ogg(crate::formats::ogg::OggMeta<'a>),
  /// MPEG audio (Phase F4 — frame parser, Xing/LAME tail). Produced as
  /// `MpegAudioMeta<'static>` by [`crate::formats::mpeg::ProcessMpegAudio`].
  #[cfg(feature = "mpeg-audio")]
  MpegAudio(crate::formats::mpeg::MpegAudioMeta<'a>),
  /// MPC (Phase F5 — Musepack SV7/SV8 audio).
  #[cfg(feature = "mpc")]
  Mpc(crate::formats::mpc::MpcMeta<'a>),
  /// WavPack (Phase F5 — `.wv` / `.wvp` hybrid-lossless audio).
  #[cfg(feature = "wavpack")]
  Wv(crate::formats::wavpack::WvMeta<'a>),
}

impl MetaSinker for AnyMeta<'_> {
  fn sink<W: TagWriter>(&self, print_conv: bool, out: &mut W) -> Result<(), W::Error> {
    // Note: `#[non_exhaustive]` on `AnyMeta` plus per-format `cfg(feature)`
    // gates means a match without `_` is only exhaustive when at least one
    // format feature is on. The `all-formats` default and the `any(...)`
    // gating on this `impl` block ensure that's always the case for any
    // build that has an `AnyMeta` value to sink (a no-format build has no
    // variants and the enum cannot be constructed).
    match self {
      #[cfg(feature = "moi")]
      AnyMeta::Moi(m) => m.sink(print_conv, out),
      #[cfg(feature = "aac")]
      AnyMeta::Aac(m) => m.sink(print_conv, out),
      #[cfg(feature = "dv")]
      AnyMeta::Dv(o) => match o {
        // DV.pm:188 — Warn + return 1 without DV:* tags. The bridge
        // emits the warning at the legacy `OldFormatParser::process`
        // entry; the sink path emits no tags for this variant.
        crate::formats::dv::DvParseOutcome::UnrecognizedProfile => {
          out.write_warning("Unrecognized DV profile")
        }
        crate::formats::dv::DvParseOutcome::Meta(m) => m.sink(print_conv, out),
      },
      #[cfg(feature = "audible")]
      AnyMeta::Aa(m) => m.sink(print_conv, out),
      #[cfg(feature = "red")]
      AnyMeta::R3d(m) => m.sink(print_conv, out),
      #[cfg(feature = "id3")]
      AnyMeta::Id3(m) => m.sink(print_conv, out),
      #[cfg(feature = "mp3")]
      AnyMeta::Mp3(m) => m.sink(print_conv, out),
      #[cfg(feature = "aiff")]
      AnyMeta::Aiff(m) => m.sink(print_conv, out),
      #[cfg(feature = "ape")]
      AnyMeta::Ape(m) => m.sink(print_conv, out),
      #[cfg(feature = "dsf")]
      AnyMeta::Dsf(m) => m.sink(print_conv, out),
      #[cfg(feature = "flac")]
      AnyMeta::Flac(m) => m.sink(print_conv, out),
      #[cfg(feature = "ogg")]
      AnyMeta::Ogg(m) => m.sink(print_conv, out),
      #[cfg(feature = "mpeg-audio")]
      AnyMeta::MpegAudio(m) => m.sink(print_conv, out),
      #[cfg(feature = "mpc")]
      AnyMeta::Mpc(m) => m.sink(print_conv, out),
      #[cfg(feature = "wavpack")]
      AnyMeta::Wv(m) => m.sink(print_conv, out),
    }
  }
}

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
/// [`crate::formats::moi::MoiError`]); the `From` impls for those formats
/// translate into unreachable matches that `rustc` constant-folds out at
/// monomorphization. The structure exists so future I/O-fallible parsers
/// can add fatal modes without changing the public `AnyError` shape.
///
/// `#[non_exhaustive]` matches [`AnyParser`] / [`AnyMeta`]: consumers
/// cannot exhaustively match on this enum across crate-feature combos —
/// new format arms (or new variants on existing errors) are additive
/// within the crate, but no caller can rely on a fixed set.
#[non_exhaustive]
#[derive(Debug, Clone, derive_more::Display)]
pub enum AnyError {
  /// MOI fatal-error wrapper.
  #[cfg(feature = "moi")]
  #[display("MOI: {_0}")]
  Moi(crate::formats::moi::MoiError),
  /// AAC fatal-error wrapper.
  #[cfg(feature = "aac")]
  #[display("AAC: {_0}")]
  Aac(crate::formats::aac::AacError),
  /// DV fatal-error wrapper.
  #[cfg(feature = "dv")]
  #[display("DV: {_0}")]
  Dv(crate::formats::dv::DvError),
  /// Audible (AA) fatal-error wrapper.
  #[cfg(feature = "audible")]
  #[display("AA: {_0}")]
  Aa(crate::formats::audible::AudibleError),
  /// Red R3D fatal-error wrapper.
  #[cfg(feature = "red")]
  #[display("R3D: {_0}")]
  R3d(crate::formats::red::R3dError),
  /// ID3 fatal-error wrapper.
  #[cfg(feature = "id3")]
  #[display("ID3: {_0}")]
  Id3(crate::formats::id3::Id3Error),
  /// MP3 fatal-error wrapper.
  #[cfg(feature = "mp3")]
  #[display("MP3: {_0}")]
  Mp3(crate::formats::id3::Mp3Error),
  /// AIFF fatal-error wrapper.
  #[cfg(feature = "aiff")]
  #[display("AIFF: {_0}")]
  Aiff(crate::formats::aiff::AiffError),
  /// APE fatal-error wrapper.
  #[cfg(feature = "ape")]
  #[display("APE: {_0}")]
  Ape(crate::formats::ape::ApeError),
  /// DSF fatal-error wrapper.
  #[cfg(feature = "dsf")]
  #[display("DSF: {_0}")]
  Dsf(crate::formats::dsf::DsfError),
  /// FLAC fatal-error wrapper.
  #[cfg(feature = "flac")]
  #[display("FLAC: {_0}")]
  Flac(crate::formats::flac::FlacError),
  /// Ogg fatal-error wrapper.
  #[cfg(feature = "ogg")]
  #[display("OGG: {_0}")]
  Ogg(crate::formats::ogg::OggError),
  /// MPEG audio fatal-error wrapper.
  #[cfg(feature = "mpeg-audio")]
  #[display("MPEG-audio: {_0}")]
  MpegAudio(crate::formats::mpeg::MpegAudioError),
  /// MPC fatal-error wrapper.
  #[cfg(feature = "mpc")]
  #[display("MPC: {_0}")]
  Mpc(crate::formats::mpc::MpcError),
  /// WavPack fatal-error wrapper.
  #[cfg(feature = "wavpack")]
  #[display("WV: {_0}")]
  Wv(crate::formats::wavpack::WvError),
}

#[cfg(feature = "std")]
impl std::error::Error for AnyError {}

#[cfg(feature = "moi")]
impl From<crate::formats::moi::MoiError> for AnyError {
  fn from(e: crate::formats::moi::MoiError) -> Self {
    AnyError::Moi(e)
  }
}
#[cfg(feature = "aac")]
impl From<crate::formats::aac::AacError> for AnyError {
  fn from(e: crate::formats::aac::AacError) -> Self {
    AnyError::Aac(e)
  }
}
#[cfg(feature = "dv")]
impl From<crate::formats::dv::DvError> for AnyError {
  fn from(e: crate::formats::dv::DvError) -> Self {
    AnyError::Dv(e)
  }
}
#[cfg(feature = "audible")]
impl From<crate::formats::audible::AudibleError> for AnyError {
  fn from(e: crate::formats::audible::AudibleError) -> Self {
    AnyError::Aa(e)
  }
}
#[cfg(feature = "red")]
impl From<crate::formats::red::R3dError> for AnyError {
  fn from(e: crate::formats::red::R3dError) -> Self {
    AnyError::R3d(e)
  }
}
#[cfg(feature = "id3")]
impl From<crate::formats::id3::Id3Error> for AnyError {
  fn from(e: crate::formats::id3::Id3Error) -> Self {
    AnyError::Id3(e)
  }
}
#[cfg(feature = "mp3")]
impl From<crate::formats::id3::Mp3Error> for AnyError {
  fn from(e: crate::formats::id3::Mp3Error) -> Self {
    AnyError::Mp3(e)
  }
}
#[cfg(feature = "aiff")]
impl From<crate::formats::aiff::AiffError> for AnyError {
  fn from(e: crate::formats::aiff::AiffError) -> Self {
    AnyError::Aiff(e)
  }
}
#[cfg(feature = "ape")]
impl From<crate::formats::ape::ApeError> for AnyError {
  fn from(e: crate::formats::ape::ApeError) -> Self {
    AnyError::Ape(e)
  }
}
#[cfg(feature = "dsf")]
impl From<crate::formats::dsf::DsfError> for AnyError {
  fn from(e: crate::formats::dsf::DsfError) -> Self {
    AnyError::Dsf(e)
  }
}
#[cfg(feature = "flac")]
impl From<crate::formats::flac::FlacError> for AnyError {
  fn from(e: crate::formats::flac::FlacError) -> Self {
    AnyError::Flac(e)
  }
}
#[cfg(feature = "ogg")]
impl From<crate::formats::ogg::OggError> for AnyError {
  fn from(e: crate::formats::ogg::OggError) -> Self {
    AnyError::Ogg(e)
  }
}
#[cfg(feature = "mpeg-audio")]
impl From<crate::formats::mpeg::MpegAudioError> for AnyError {
  fn from(e: crate::formats::mpeg::MpegAudioError) -> Self {
    AnyError::MpegAudio(e)
  }
}
#[cfg(feature = "mpc")]
impl From<crate::formats::mpc::MpcError> for AnyError {
  fn from(e: crate::formats::mpc::MpcError) -> Self {
    AnyError::Mpc(e)
  }
}
#[cfg(feature = "wavpack")]
impl From<crate::formats::wavpack::WvError> for AnyError {
  fn from(e: crate::formats::wavpack::WvError) -> Self {
    AnyError::Wv(e)
  }
}

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
  pub fn parse_any<'a>(
    self,
    bytes: &'a [u8],
    shared: &mut SharedFlags,
    ext: Option<&'a str>,
  ) -> Result<Option<AnyMeta<'a>>, AnyError> {
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
      #[cfg(feature = "id3")]
      AnyParser::Id3(p) => {
        let _ = ext;
        let ctx = crate::formats::id3::Id3Context::new(bytes, shared);
        p.parse(ctx)
          .map(|o| o.map(AnyMeta::Id3))
          .map_err(Into::into)
      }
      #[cfg(feature = "mp3")]
      AnyParser::Mp3(p) => {
        let ctx = crate::formats::id3::Mp3Context::new(bytes, shared, ext);
        p.parse(ctx)
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
        let _ = ext;
        let ctx = crate::formats::ape::ApeContext::new(bytes, shared);
        p.parse(ctx)
          .map(|o| o.map(AnyMeta::Ape))
          .map_err(Into::into)
      }
      #[cfg(feature = "dsf")]
      AnyParser::Dsf(p) => {
        let _ = ext;
        let ctx = crate::formats::dsf::DsfContext::new(bytes, shared);
        p.parse(ctx)
          .map(|o| o.map(AnyMeta::Dsf))
          .map_err(Into::into)
      }
      #[cfg(feature = "flac")]
      AnyParser::Flac(p) => {
        let _ = ext;
        let ctx = crate::formats::flac::FlacContext::new(bytes, shared);
        p.parse(ctx)
          .map(|o| o.map(AnyMeta::Flac))
          .map_err(Into::into)
      }
      #[cfg(feature = "ogg")]
      AnyParser::Ogg(p) => {
        let _ = (shared, ext);
        p.parse(bytes)
          .map(|o| o.map(AnyMeta::Ogg))
          .map_err(Into::into)
      }
      #[cfg(feature = "mpeg-audio")]
      AnyParser::MpegAudio(p) => {
        // The MPEG-audio parser is normally invoked internally by MP3 — it
        // is never a top-level file-type in `parser_for`. The closed
        // dispatch arm is provided so external callers that construct an
        // `AnyParser::MpegAudio` directly (e.g. unit tests, or future
        // crates that want raw MPEG-audio access) can still route through
        // the same closed-set machinery. The `mp3` flag and the extension
        // are derived from `ext` exactly as `ID3::ProcessMP3` does
        // (ID3.pm:1715-1717: `$ext eq 'MUS' ? 0 : 1`).
        let ext = ext.unwrap_or("");
        let mp3 = !ext.eq_ignore_ascii_case("MUS");
        let ctx = crate::formats::mpeg::MpegAudioContext::new(bytes, ext, mp3, shared);
        p.parse(ctx)
          .map(|o| o.map(AnyMeta::MpegAudio))
          .map_err(Into::into)
      }
      #[cfg(feature = "mpc")]
      AnyParser::Mpc(p) => {
        let _ = ext;
        let ctx = crate::formats::mpc::MpcContext::new(bytes, shared);
        p.parse(ctx)
          .map(|o| o.map(AnyMeta::Mpc))
          .map_err(Into::into)
      }
      #[cfg(feature = "wavpack")]
      AnyParser::Wv(p) => {
        let _ = ext;
        let ctx = crate::formats::wavpack::WvContext::new(bytes, shared);
        p.parse(ctx).map(|o| o.map(AnyMeta::Wv)).map_err(Into::into)
      }
    }
  }
}

/// Map a finalized ExifTool file-type string to its [`AnyParser`] arm, or
/// `None` if the format has no ported parser yet OR its Cargo feature is
/// disabled. Mirrors [`crate::formats::parser_for`] (the legacy registry)
/// shape-for-shape — both return `None` for feature-pruned formats, faithful
/// to ExifTool's "module not loaded ⇒ `next` in candidate loop"
/// (ExifTool.pm:3060-3077).
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
    #[cfg(feature = "mp3")]
    "MP3" => Some(AnyParser::Mp3(crate::formats::id3::ProcessMp3)),
    #[cfg(feature = "moi")]
    "MOI" => Some(AnyParser::Moi(crate::formats::moi::ProcessMoi)),
    #[cfg(feature = "mpc")]
    "MPC" => Some(AnyParser::Mpc(crate::formats::mpc::ProcessMpc)),
    #[cfg(feature = "ogg")]
    "OGG" => Some(AnyParser::Ogg(crate::formats::ogg::ProcessOgg)),
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
  use crate::sink::{MapTagWriter, MapValue};
  use core::convert::Infallible;
  use std::string::ToString;

  /// Smoke test: `MapTagWriter` actually implements [`TagWriter`] and the
  /// trait methods are callable without going through any other type.
  #[test]
  fn map_tag_writer_implements_tag_writer() {
    let mut w = MapTagWriter::new();
    w.write_str("Group", "Name", "value").unwrap();
    w.write_u64("Group", "U64", 42).unwrap();
    w.write_i64("Group", "I64", -7).unwrap();
    w.write_f64("Group", "F64", 3.5).unwrap();
    w.write_bytes("Group", "Bytes", &[1, 2, 3]).unwrap();
    w.write_fmt("Group", "Fmt", |f| write!(f, "0:05:00.300"))
      .unwrap();
    w.write_warning("warn-text").unwrap();
    w.write_error("err-text").unwrap();

    // 6 keyed entries + 1 warning + 1 error = 8 total entries in the map.
    assert_eq!(w.len(), 8);
    assert_eq!(
      w.get("Group", "Name").map(MapValue::as_str),
      Some("value".to_string())
    );
    assert_eq!(
      w.get("Group", "U64").map(MapValue::as_str),
      Some("42".to_string())
    );
    assert_eq!(
      w.get("Group", "I64").map(MapValue::as_str),
      Some("-7".to_string())
    );
    assert_eq!(
      w.get("Group", "F64").map(MapValue::as_str),
      Some("3.5".to_string())
    );
    assert_eq!(
      w.get("Group", "Fmt").map(MapValue::as_str),
      Some("0:05:00.300".to_string())
    );
    assert!(w.warnings().iter().any(|s| s == "warn-text"));
    assert!(w.errors().iter().any(|s| s == "err-text"));
  }

  /// A toy Meta + MetaSinker impl proves the dataflow Meta → TagWriter
  /// compiles end-to-end (associated `Error` type plumbing, lifetime
  /// bounds on the writer, etc.).
  #[derive(Debug, Clone, Copy)]
  struct DummyMeta<'a> {
    name: &'a str,
    size: u64,
  }

  impl MetaSinker for DummyMeta<'_> {
    fn sink<W: TagWriter>(&self, print_conv: bool, out: &mut W) -> Result<(), W::Error> {
      out.write_str("Dummy", "Name", self.name)?;
      if print_conv {
        // Faithful to the PrintConv toggle: emit a formatted text view
        // when print_conv is on; the raw numeric otherwise.
        out.write_fmt("Dummy", "Size", |w| write!(w, "{} bytes", self.size))?;
      } else {
        out.write_u64("Dummy", "Size", self.size)?;
      }
      Ok(())
    }
  }

  #[test]
  fn meta_sinker_emits_into_map_tag_writer() {
    let meta = DummyMeta {
      name: "moi-fake",
      size: 1234,
    };
    // -j (PrintConv on) — formatted bytes-string.
    let mut w = MapTagWriter::new();
    meta.sink(true, &mut w).unwrap();
    assert_eq!(
      w.get("Dummy", "Name").map(MapValue::as_str),
      Some("moi-fake".to_string())
    );
    assert_eq!(
      w.get("Dummy", "Size").map(MapValue::as_str),
      Some("1234 bytes".to_string())
    );
    // -n (PrintConv off) — raw u64.
    let mut w = MapTagWriter::new();
    meta.sink(false, &mut w).unwrap();
    assert_eq!(
      w.get("Dummy", "Size").map(MapValue::as_str),
      Some("1234".to_string())
    );
  }

  /// Demonstrates that an `Infallible`-erroring sink compiles cleanly —
  /// the Result path is collapsed at type-check time, so a
  /// `?`-propagating sink chain never needs runtime branching on the
  /// no-fail leg.
  struct InfallibleSink;

  impl TagWriter for InfallibleSink {
    type Error = Infallible;
    fn write_str(&mut self, _g: &str, _n: &str, _v: &str) -> Result<(), Infallible> {
      Ok(())
    }
    fn write_u64(&mut self, _g: &str, _n: &str, _v: u64) -> Result<(), Infallible> {
      Ok(())
    }
    fn write_i64(&mut self, _g: &str, _n: &str, _v: i64) -> Result<(), Infallible> {
      Ok(())
    }
    fn write_f64(&mut self, _g: &str, _n: &str, _v: f64) -> Result<(), Infallible> {
      Ok(())
    }
    fn write_bytes(&mut self, _g: &str, _n: &str, _v: &[u8]) -> Result<(), Infallible> {
      Ok(())
    }
    fn write_fmt(
      &mut self,
      _g: &str,
      _n: &str,
      _f: impl FnOnce(&mut dyn fmt::Write) -> fmt::Result,
    ) -> Result<(), Infallible> {
      Ok(())
    }
    fn write_warning(&mut self, _t: &str) -> Result<(), Infallible> {
      Ok(())
    }
    fn write_error(&mut self, _t: &str) -> Result<(), Infallible> {
      Ok(())
    }
  }

  #[test]
  fn infallible_sink_compiles_cleanly() {
    let meta = DummyMeta { name: "x", size: 0 };
    let mut sink = InfallibleSink;
    // The `unwrap()` on an `Infallible` result is what the doc claims is
    // collapsed at type-check; here we just ensure the dataflow compiles.
    let result: Result<(), Infallible> = meta.sink(true, &mut sink);
    let () = result.unwrap();
  }

  #[test]
  fn shared_flags_round_trip() {
    let mut sf = SharedFlags::new();
    assert_eq!(sf.done_id3(), None);
    assert!(!sf.done_ape());
    assert!(sf.file_type_stack().is_empty());
    assert_eq!(sf.current_file_type(), None);

    sf.set_done_id3(128);
    sf.set_done_ape(true);
    sf.push_file_type("MP3");
    sf.push_file_type("ID3");
    assert_eq!(sf.done_id3(), Some(128));
    assert!(sf.done_ape());
    assert_eq!(sf.current_file_type(), Some("ID3"));
    assert_eq!(sf.file_type_stack(), &[Some("MP3"), Some("ID3")]);

    assert_eq!(sf.pop_file_type(), Some("ID3"));
    assert_eq!(sf.pop_file_type(), Some("MP3"));
    assert_eq!(sf.pop_file_type(), None);
    assert!(sf.file_type_stack().is_empty());
  }

  /// `any_parser_for` resolves every ported format that has its feature
  /// enabled. Mirrors the same coverage as [`crate::formats::parser_for`]
  /// (the legacy registry); the two registries are designed to be
  /// shape-for-shape identical (same file-type strings ⇒ same `Some`/
  /// `None` decisions).
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
}

/// The [`parser_sealed::Sealed`] super-trait is private, so downstream
/// crates cannot implement [`FormatParser`] for foreign types. This
/// `compile_fail` doc-test demonstrates: trying to implement
/// [`FormatParser`] without sealing the type produces an E0405
/// (trait not satisfied) compilation error.
///
/// ```compile_fail
/// use exifast::parser_new::FormatParser;
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
