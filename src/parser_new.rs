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
use core::marker::PhantomData;

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
  /// `$$et{DoneID3}` — set by ID3 to the size of the ID3v1 trailer
  /// (128 + 227 if Enhanced TAG, etc.). Read by `APE.pm:169` for the
  /// footer-position shift.
  done_id3: usize,
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

  /// `$$et{DoneID3}` — bytes consumed by an ID3v1 trailer (128 + 227 if
  /// Enhanced TAG, etc.). Zero means "not yet processed".
  #[must_use]
  pub fn done_id3(&self) -> usize {
    self.done_id3
  }

  /// Set `$$et{DoneID3}`. Called by the ID3 parser after the v1 trailer
  /// is consumed.
  pub fn set_done_id3(&mut self, value: usize) {
    self.done_id3 = value;
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
  // Phase F4 adds: Ogg, MpegAudio.
  // Phase F5 adds: Mpc, WavPack.
}

/// Closed-set enum of every format's `Meta` output. Mirrors [`AnyParser`].
///
/// The `_Phantom` variant exists so the enum compiles even when no format
/// feature is enabled (e.g. `--no-default-features` builds). It is
/// removed in Phase G (last) once every format has a real arm AND the
/// public-API contract pins at least one format always being present.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum AnyMeta<'a> {
  /// Placeholder so the enum compiles when no format feature is enabled.
  /// Removed in Phase G.
  #[doc(hidden)]
  _Phantom(PhantomData<&'a ()>),
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
}

impl MetaSinker for AnyMeta<'_> {
  fn sink<W: TagWriter>(&self, print_conv: bool, out: &mut W) -> Result<(), W::Error> {
    match self {
      AnyMeta::_Phantom(_) => {
        // Phantom variant emits no tags; exists only as a type-system
        // placeholder for the no-format-feature build.
        let _ = (out, print_conv);
        Ok(())
      }
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
    }
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
    assert_eq!(sf.done_id3(), 0);
    assert!(!sf.done_ape());
    assert!(sf.file_type_stack().is_empty());
    assert_eq!(sf.current_file_type(), None);

    sf.set_done_id3(128);
    sf.set_done_ape(true);
    sf.push_file_type("MP3");
    sf.push_file_type("ID3");
    assert_eq!(sf.done_id3(), 128);
    assert!(sf.done_ape());
    assert_eq!(sf.current_file_type(), Some("ID3"));
    assert_eq!(sf.file_type_stack(), &[Some("MP3"), Some("ID3")]);

    assert_eq!(sf.pop_file_type(), Some("ID3"));
    assert_eq!(sf.pop_file_type(), Some("MP3"));
    assert_eq!(sf.pop_file_type(), None);
    assert!(sf.file_type_stack().is_empty());
  }

  /// The `_Phantom` arm of [`AnyMeta`] sinks nothing. Verifies the
  /// MetaSinker impl is reachable for the type-level placeholder.
  #[test]
  fn any_meta_phantom_sinks_nothing() {
    let any: AnyMeta<'_> = AnyMeta::_Phantom(PhantomData);
    let mut w = MapTagWriter::new();
    any.sink(true, &mut w).unwrap();
    assert_eq!(w.len(), 0);
    let mut w = MapTagWriter::new();
    any.sink(false, &mut w).unwrap();
    assert_eq!(w.len(), 0);
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
