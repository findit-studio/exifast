// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "wavpack")]
//! Faithful port of `Image::ExifTool::WavPack` (lib/Image/ExifTool/WavPack.pm).
//! WavPack.pm is 144 lines: one tag table + one `Process<Type>` sub.
//!
//! A typed [`Meta<'a>`] is produced by the
//! [`crate::parser_new::FormatParser`] trait; the engine entry `process`
//! drives the typed `serialize_tags` path into the engine
//! `tagmap::TagMap` and the chained ID3/APE trailers so
//! the serialized JSON stays byte-exact with bundled `perl exiftool`.
//!
//! ## What WavPack is
//!
//! WavPack (`.wv` and `.wvp`) is a hybrid-lossless audio codec. Files
//! start with a 32-byte block header beginning with the ASCII magic
//! `wvpk` (WavPack.pm:88). All five exposed tags are sub-fields of the
//! big-endian `int32u` flags word at byte offset 24 — extracted by mask
//! + bit-shift (`%WavPack::Main`, WavPack.pm:21-74).
//!
//! PROCESS_PROC is `ExifTool::ProcessBinaryData` (WavPack.pm:22) running
//! over the 32-byte header. With `FORMAT => 'int32u'` (WavPack.pm:24)
//! and ALL five tag IDs sharing the integer part `6` (`6.1`..`6.5`,
//! WavPack.pm:31-73), every tag reads the SAME `int32u` at offset
//! `6 * 4 = 24` and applies its own `Mask` (ExifTool.pm:10067-10068
//! `val = (val & mask) >> BitShift`, `BitShift` auto-derived from the
//! trailing zero bits of `Mask`, ExifTool.pm:5905-5910). So a faithful
//! Rust transliteration reads the single `int32u` once (big-endian,
//! ExifTool global default 'MM', ExifTool.pm:5981 — `WavPack.pm` never
//! calls `SetByteOrder`) and emits the 5 tags in numeric order (the Perl
//! `sort` at ExifTool.pm:9907).
//!
//! Byte-order verified against the bundled `perl exiftool` oracle: an
//! on-disk LE flags value `0x0480008d` produces BytesPerSample=1,
//! AudioType=Mono, Compression=Lossless, DataFormat=Integer,
//! SampleRate=48000 — exactly what `u32::from_be_bytes(...)` + the
//! `%WavPack::Main` masks compute.
//!
//! ## Chained ID3 + APE (WavPack.pm:97-103)
//!
//! `ProcessWV` (WavPack.pm:80-105) also calls `RIFF::ProcessRIFF` and
//! `APE::ProcessAPE` AFTER its own `ProcessBinaryData`, to extract any
//! RIFF wrapper / ID3 / APE-trailer metadata. The bundled `ProcessAPE`
//! ALSO calls `ProcessID3` internally (APE.pm:122-127) — so the WavPack
//! chain effectively runs RIFF → ID3 → APE.
//!
//! **Scope.** The typed parser ([`ProcessWv::parse`]) produces a
//! [`Meta`] that ONLY carries the WavPack-header tags AND
//! borrow-from-input `Option<&'a [u8]>` placeholders denoting the byte
//! ranges where ID3 / APE trailers may live (the whole input buffer,
//! since both legacy formats scan the entire file). Actually parsing
//! those trailers is delegated to the engine entry `process`,
//! which calls the existing chained entries
//! `crate::formats::id3::process::process_id3_chained` +
//! `crate::formats::ape::ProcessApe::process_trailer_only` (the same
//! APIs APE.pm uses internally). The bundled `perl
//! exiftool` oracle on the committed WavPack fixtures (`WavPack.wv` /
//! `WavPack_adversarial.wv` — native `wvpk....` 32-byte header, no
//! RIFF wrapper, no ID3, no APE trailer) emits exactly the File:* +
//! 5 WavPack-header tags; the RIFF / ID3 / APE delegations observably
//! emit nothing for these fixtures, but the bridge still drives them
//! for correctness on chained fixtures.
//!
//! **RIFF deferral.** The RIFF wrapper detection (WavPack.pm:97-99)
//! remains a Phase-2 forward item — `RIFF::ProcessRIFF` is not ported
//! yet; FORMATS.md row 22 will wire it. On the committed fixtures the
//! deferral is observably no-op (no RIFF wrapper present).

use crate::parser_new::{FormatParser, SharedFlags, parser_sealed};

// ===========================================================================
// Mask + BitShift constants
// ===========================================================================

/// BitShift derivation. Faithful to ExifTool.pm:5905-5910:
///   `++$bitShift until $mask & (1 << $bitShift);`
/// i.e. `BitShift = number of trailing zero bits of Mask`. `trailing_zeros`
/// is `const fn` on u32 and total — no runtime cost, no panic surface —
/// so the `*_SHIFT` constants are derived from their `*_MASK` constants.
/// This makes the mask/shift invariant enforced by construction (a mask
/// change automatically updates the shift). The Perl loop algorithm and
/// the resulting shifts are byte-identical.
const fn bit_shift(mask: u32) -> u32 {
  mask.trailing_zeros()
}

/// WavPack.pm:33 `Mask => 0x03` (BytesPerSample).
const BYTES_PER_SAMPLE_MASK: u32 = 0x0000_0003;
const BYTES_PER_SAMPLE_SHIFT: u32 = bit_shift(BYTES_PER_SAMPLE_MASK); // 0
/// WavPack.pm:38 `Mask => 0x04` (AudioType).
const AUDIO_TYPE_MASK: u32 = 0x0000_0004;
const AUDIO_TYPE_SHIFT: u32 = bit_shift(AUDIO_TYPE_MASK); // 2
/// WavPack.pm:43 `Mask => 0x08` (Compression).
const COMPRESSION_MASK: u32 = 0x0000_0008;
const COMPRESSION_SHIFT: u32 = bit_shift(COMPRESSION_MASK); // 3
/// WavPack.pm:48 `Mask => 0x80` (DataFormat).
const DATA_FORMAT_MASK: u32 = 0x0000_0080;
const DATA_FORMAT_SHIFT: u32 = bit_shift(DATA_FORMAT_MASK); // 7
/// WavPack.pm:53 `Mask => 0x07800000` (SampleRate).
const SAMPLE_RATE_MASK: u32 = 0x0780_0000;
const SAMPLE_RATE_SHIFT: u32 = bit_shift(SAMPLE_RATE_MASK); // 23

/// WavPack.pm:55-72 `SampleRate` PrintConv hash — indices 0..=14 are
/// known integer rates; index 15 is the string `"Custom"`. Looked up at
/// emit time (PrintConv-on) and via the typed accessor
/// [`Meta::sample_rate_hz`].
///
/// Returns `None` only for indices ≥ 16 which are unreachable from a
/// 4-bit mask (`0x07800000 >> 23 = 0..=15`). Kept as `None` for total
/// safety rather than asserting.
#[must_use]
const fn sample_rate_lookup(index: u8) -> Option<SampleRate> {
  match index {
    0 => Some(SampleRate::Hz(6000)),
    1 => Some(SampleRate::Hz(8000)),
    2 => Some(SampleRate::Hz(9600)),
    3 => Some(SampleRate::Hz(11025)),
    4 => Some(SampleRate::Hz(12000)),
    5 => Some(SampleRate::Hz(16000)),
    6 => Some(SampleRate::Hz(22050)),
    7 => Some(SampleRate::Hz(24000)),
    8 => Some(SampleRate::Hz(32000)),
    9 => Some(SampleRate::Hz(44100)),
    10 => Some(SampleRate::Hz(48000)),
    11 => Some(SampleRate::Hz(64000)),
    12 => Some(SampleRate::Hz(88200)),
    13 => Some(SampleRate::Hz(96000)),
    14 => Some(SampleRate::Hz(192000)),
    15 => Some(SampleRate::Custom),
    _ => None,
  }
}

// ===========================================================================
// Typed enums
// ===========================================================================

/// `AudioType` PrintConv (WavPack.pm:39): 0 ⇒ "Stereo", 1 ⇒ "Mono".
///
/// §2: unit-only variant enum. The on-disk source is a single `Mask => 0x04`
/// bit (WavPack.pm:38), so the vocabulary is **closed and total** — every
/// raw value (0 or 1) maps to a variant and `from_raw`/`raw` round-trip for
/// both, so no lossless `Unknown` escape is needed. `#[non_exhaustive]`
/// guards future additions (the `AudioType` axis could grow if a later
/// WavPack revision widened the field). Predicates (`is_*`) and `Display`
/// route through [`AudioType::as_str`] (single source of truth).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::IsVariant)]
pub enum AudioType {
  /// WavPack.pm:39 — raw 0 ⇒ "Stereo".
  Stereo,
  /// WavPack.pm:39 — raw 1 ⇒ "Mono".
  Mono,
}

impl AudioType {
  /// Decode the raw bit (already mask + shift extracted) — 0 or 1.
  #[must_use]
  #[inline(always)]
  pub const fn from_raw(b: u8) -> AudioType {
    if b == 0 {
      AudioType::Stereo
    } else {
      AudioType::Mono
    }
  }

  /// The on-disk raw bit (0 = Stereo, 1 = Mono). Used by the `-n` raw
  /// emission path. Round-trips with [`Self::from_raw`] for every value.
  #[must_use]
  #[inline(always)]
  pub const fn raw(self) -> u8 {
    match self {
      AudioType::Stereo => 0,
      AudioType::Mono => 1,
    }
  }

  /// WavPack.pm:39 PrintConv string. Single source of truth for both the
  /// PrintConv emission and [`Display`](core::fmt::Display).
  #[must_use]
  #[inline(always)]
  pub const fn as_str(self) -> &'static str {
    match self {
      AudioType::Stereo => "Stereo",
      AudioType::Mono => "Mono",
    }
  }
}

impl core::fmt::Display for AudioType {
  #[inline(always)]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

/// `Compression` PrintConv (WavPack.pm:44): 0 ⇒ "Lossless", 1 ⇒ "Hybrid".
///
/// §2: unit-only variant enum, closed-and-total over the single
/// `Mask => 0x08` bit (WavPack.pm:43) — `from_raw`/`raw` round-trip for both
/// values, so no `Unknown` escape is needed. `#[non_exhaustive]` +
/// predicates + `Display` via [`Compression::as_str`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::IsVariant)]
pub enum Compression {
  /// WavPack.pm:44 — raw 0 ⇒ "Lossless".
  Lossless,
  /// WavPack.pm:44 — raw 1 ⇒ "Hybrid".
  Hybrid,
}

impl Compression {
  /// Decode the raw bit (already mask + shift extracted) — 0 or 1.
  #[must_use]
  #[inline(always)]
  pub const fn from_raw(b: u8) -> Compression {
    if b == 0 {
      Compression::Lossless
    } else {
      Compression::Hybrid
    }
  }

  /// The on-disk raw bit (0 = Lossless, 1 = Hybrid). Round-trips with
  /// [`Self::from_raw`] for every value.
  #[must_use]
  #[inline(always)]
  pub const fn raw(self) -> u8 {
    match self {
      Compression::Lossless => 0,
      Compression::Hybrid => 1,
    }
  }

  /// WavPack.pm:44 PrintConv string. Single source of truth for both the
  /// PrintConv emission and [`Display`](core::fmt::Display).
  #[must_use]
  #[inline(always)]
  pub const fn as_str(self) -> &'static str {
    match self {
      Compression::Lossless => "Lossless",
      Compression::Hybrid => "Hybrid",
    }
  }
}

impl core::fmt::Display for Compression {
  #[inline(always)]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

/// `DataFormat` PrintConv (WavPack.pm:49): 0 ⇒ "Integer", 1 ⇒ "Floating Point".
///
/// §2: unit-only variant enum, closed-and-total over the single
/// `Mask => 0x80` bit (WavPack.pm:48) — `from_raw`/`raw` round-trip for both
/// values, so no `Unknown` escape is needed. `#[non_exhaustive]` +
/// predicates + `Display` via [`DataFormat::as_str`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::IsVariant)]
pub enum DataFormat {
  /// WavPack.pm:49 — raw 0 ⇒ "Integer".
  Integer,
  /// WavPack.pm:49 — raw 1 ⇒ "Floating Point".
  FloatingPoint,
}

impl DataFormat {
  /// Decode the raw bit (already mask + shift extracted) — 0 or 1.
  #[must_use]
  #[inline(always)]
  pub const fn from_raw(b: u8) -> DataFormat {
    if b == 0 {
      DataFormat::Integer
    } else {
      DataFormat::FloatingPoint
    }
  }

  /// The on-disk raw bit (0 = Integer, 1 = FloatingPoint). Round-trips with
  /// [`Self::from_raw`] for every value.
  #[must_use]
  #[inline(always)]
  pub const fn raw(self) -> u8 {
    match self {
      DataFormat::Integer => 0,
      DataFormat::FloatingPoint => 1,
    }
  }

  /// WavPack.pm:49 PrintConv string. Single source of truth for both the
  /// PrintConv emission and [`Display`](core::fmt::Display).
  #[must_use]
  #[inline(always)]
  pub const fn as_str(self) -> &'static str {
    match self {
      DataFormat::Integer => "Integer",
      DataFormat::FloatingPoint => "Floating Point",
    }
  }
}

impl core::fmt::Display for DataFormat {
  #[inline(always)]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

/// `SampleRate` PrintConv decoded shape (WavPack.pm:55-72). Indices
/// 0..=14 map to known integer rates; index 15 is the `"Custom"` string.
///
/// §2: unit-or-newtype variants only — `Hz(u32)` (newtype) carries the
/// post-PrintConv numeric rate, NOT the raw 4-bit index (the raw index is
/// preserved separately on [`Meta::sample_rate_raw_index`] for `-n`
/// emission and provides the lossless on-disk round-trip). The
/// externally-numbered 4-bit index is **total** over [0, 15] via
/// [`sample_rate_lookup`], so this decoded form needs no `Unknown` escape.
/// `#[non_exhaustive]` guards future rate additions. Data-carrying, so it
/// gets `is_*` predicates plus `unwrap_hz`/`try_unwrap_hz` accessors
/// (derive_more) and a `Display` routed through the same numeric/`"Custom"`
/// rendering the serializer uses. The `Hz` payload is `Copy` (`u32`), so the
/// by-value `unwrap_hz()`/`try_unwrap_hz()` accessors are the ergonomic form
/// (no `ref` variants needed).
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
pub enum SampleRate {
  /// WavPack.pm:55-71 — known sample rate in Hz (e.g. `48000`).
  Hz(u32),
  /// WavPack.pm:72 — index 15 ⇒ `"Custom"` (sample rate not encoded in
  /// the header; the rate is "custom" / out-of-table).
  Custom,
}

impl core::fmt::Display for SampleRate {
  /// Single source of truth for `SampleRate`'s textual rendering — matches
  /// the `serialize_tags` PrintConv emission (`Hz(n)` ⇒ the bare number,
  /// `Custom` ⇒ `"Custom"`).
  #[inline(always)]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      SampleRate::Hz(n) => write!(f, "{n}"),
      SampleRate::Custom => f.write_str("Custom"),
    }
  }
}

// ===========================================================================
// Typed Meta — `Meta<'a>`
// ===========================================================================

/// Typed WavPack metadata — the lib-first output of [`ProcessWv`].
///
/// Carries the five `%WavPack::Main` header tags (post-mask, post-shift,
/// post-ValueConv) and two borrow-from-input `Option<&'a [u8]>` placeholders
/// for ID3 / APE trailers. The placeholders denote the byte ranges where
/// the legacy chained parsers can scan; actually invoking them lives in
/// the engine entry `process` for byte-exact conformance during
/// Phase F5–G.
///
/// **D8 — no public fields, accessors only.** Construct only via
/// [`ProcessWv::parse`].
///
/// **Lifetimes.** `'a` is held for the ID3 / APE byte-range slices. The
/// WavPack-header fields are owned primitives (no allocation). On the
/// no-chained-trailer case (the committed fixtures) both byte-range
/// fields are `None`-tied to the input but contain the unsliced buffer
/// so a future lib-first ID3 / APE typed parser can scan them.
///
/// ## Library usage
///
/// ```ignore
/// use exifast::parser_new::{FormatParser, SharedFlags};
/// use exifast::formats::wavpack::{ProcessWv, Context};
///
/// let bytes = std::fs::read("file.wv")?;
/// let mut shared = SharedFlags::new();
/// let ctx = Context::new(&bytes, &mut shared);
/// if let Some(wv) = ProcessWv.parse(ctx)? {
///   println!("BytesPerSample: {}", wv.bytes_per_sample());
///   println!("AudioType: {}", wv.audio_type().print_conv());
///   if let Some(rate) = wv.sample_rate_hz() {
///     println!("SampleRate: {rate} Hz");
///   } else {
///     println!("SampleRate: Custom");
///   }
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct Meta<'a> {
  /// WavPack.pm:31-35 BytesPerSample — `Mask => 0x03; ValueConv => '$val + 1'`.
  /// Raw 2-bit field ∈ [0, 3] ⇒ post-ValueConv [1, 4] bytes per sample
  /// (1 = 8-bit, 2 = 16-bit, 3 = 24-bit, 4 = 32-bit). PrintConv is None,
  /// so the post-ValueConv integer is emitted directly under both `-j`
  /// and `-n`.
  bytes_per_sample: u8,
  /// WavPack.pm:36-40 AudioType — `Mask => 0x04`. Raw bit ∈ [0, 1];
  /// PrintConv hash 0 ⇒ "Stereo", 1 ⇒ "Mono".
  audio_type: AudioType,
  /// WavPack.pm:41-45 Compression — `Mask => 0x08`. Raw bit ∈ [0, 1];
  /// PrintConv hash 0 ⇒ "Lossless", 1 ⇒ "Hybrid".
  compression: Compression,
  /// WavPack.pm:46-50 DataFormat — `Mask => 0x80`. Raw bit ∈ [0, 1];
  /// PrintConv hash 0 ⇒ "Integer", 1 ⇒ "Floating Point".
  data_format: DataFormat,
  /// WavPack.pm:51-73 SampleRate — `Mask => 0x07800000`. Raw 4-bit index
  /// ∈ [0, 15]; PrintConv hash 0..=14 = numeric rates, 15 = "Custom".
  /// Preserved typed via [`SampleRate`] (decoded form for ergonomic
  /// access; the original raw index is stored alongside for `-n` byte-
  /// exact emission).
  sample_rate: SampleRate,
  /// Raw 4-bit `SampleRate` index ∈ [0, 15] preserved alongside the
  /// decoded [`SampleRate`] for `-n` raw emission. (WavPack.pm:53 mask =
  /// 0x07800000, shift = 23 ⇒ raw value is the bundled `int($val)` that
  /// `perl exiftool -n` emits as a bare JSON number.)
  sample_rate_raw_index: u8,
  /// Byte range for the legacy `RIFF::ProcessRIFF` / `ID3::ProcessID3` /
  /// `APE::ProcessAPE` chained scan (WavPack.pm:96-103). Carries
  /// `Some(&data)` — the full input buffer — on the typed parse so a
  /// future lib-first ID3 typed parser can pick up the range without a
  /// re-read; `None` is reserved for a future "stop-after-header" mode.
  /// Today the engine entry `process` does the actual chained parsing.
  id3_apetrailer_scan: Option<&'a [u8]>,
}

impl<'a> Meta<'a> {
  /// WavPack.pm:31-35 — `BytesPerSample` post-ValueConv (1..=4). Copy ⇒
  /// returned by value under the bare name (§3).
  #[must_use]
  #[inline(always)]
  pub const fn bytes_per_sample(&self) -> u8 {
    self.bytes_per_sample
  }

  /// WavPack.pm:36-40 — `AudioType` decoded enum. Copy ⇒ by value (§3).
  #[must_use]
  #[inline(always)]
  pub const fn audio_type(&self) -> AudioType {
    self.audio_type
  }

  /// WavPack.pm:41-45 — `Compression` decoded enum. Copy ⇒ by value (§3).
  #[must_use]
  #[inline(always)]
  pub const fn compression(&self) -> Compression {
    self.compression
  }

  /// WavPack.pm:46-50 — `DataFormat` decoded enum. Copy ⇒ by value (§3).
  #[must_use]
  #[inline(always)]
  pub const fn data_format(&self) -> DataFormat {
    self.data_format
  }

  /// WavPack.pm:51-73 — `SampleRate` typed decoded form (`Hz(u32)` or
  /// `Custom`). Copy ⇒ by value (§3).
  #[must_use]
  #[inline(always)]
  pub const fn sample_rate(&self) -> SampleRate {
    self.sample_rate
  }

  /// `SampleRate` as `u32` Hz when known; `None` for the `"Custom"`
  /// index 15. Convenience accessor for callers that want a numeric
  /// rate or nothing.
  #[must_use]
  #[inline(always)]
  pub const fn sample_rate_hz(&self) -> Option<u32> {
    match self.sample_rate {
      SampleRate::Hz(n) => Some(n),
      SampleRate::Custom => None,
    }
  }

  /// Raw 4-bit `SampleRate` index ∈ [0, 15]. Equivalent to the bundled
  /// `perl exiftool -n` numeric output for `File:SampleRate` (which
  /// emits the pre-PrintConv raw mask value). Copy ⇒ by value (§3).
  #[must_use]
  #[inline(always)]
  pub const fn sample_rate_raw_index(&self) -> u8 {
    self.sample_rate_raw_index
  }

  /// Byte range where the chained ID3 / APE-trailer scan runs. `Some`
  /// borrows from the input buffer; today's lib-first parse always sets
  /// this to the full buffer. The engine entry `process` consumes it
  /// through the existing chained entries
  /// `crate::formats::id3::process::process_id3_chained` +
  /// `crate::formats::ape::ProcessApe::process_trailer_only`. §3 slice
  /// projection: returns `Option<&[u8]>`, never `&Option<&[u8]>`.
  #[must_use]
  #[inline(always)]
  pub const fn id3_ape_scan_range(&self) -> Option<&'a [u8]> {
    self.id3_apetrailer_scan
  }
}

// ===========================================================================
// `Context<'a>` — per-format input view
// ===========================================================================

/// Per-format input view for [`ProcessWv`]. Wraps the input bytes plus
/// a `&mut SharedFlags` for the cross-format chain (ID3 → APE flags).
/// Spec §6.4 — chained-format `Context<'a>` is a struct, not a bare
/// `&'a [u8]`.
///
/// The shared flags are reserved for the lib-first typed ID3 / APE
/// parsers (Phase F2 / F3 work in parallel agents). Today the
/// engine entry `process` still drives ID3 / APE via the
/// `Metadata` flags ([`crate::value::Metadata::set_done_id3`] /
/// [`crate::value::Metadata::set_done_ape`]); when the typed-ID3 /
/// typed-APE typed parsers land they'll read/write
/// [`SharedFlags::done_id3`] / [`SharedFlags::done_ape`] instead. The
/// `&mut SharedFlags` carry is the seam.
///
/// D8: no public fields; constructor + accessors only.
pub struct Context<'a> {
  /// The full WavPack file bytes — typically the entire input buffer.
  data: &'a [u8],
  /// Mutable cross-format flags. Reserved for the typed ID3 / APE
  /// parsers (Phase F2 / F3) — today's lib-first WavPack parse does
  /// not flip these; the legacy bridge uses the [`crate::value::Metadata`]
  /// counterparts instead.
  shared: &'a mut SharedFlags,
}

impl<'a> Context<'a> {
  /// Build a context wrapping `data` and a borrowed `shared` flags
  /// table. The flags are not mutated by the lib-first parse today;
  /// see the type-level docs for the Phase F2 / F3 plan.
  #[must_use]
  #[inline(always)]
  pub const fn new(data: &'a [u8], shared: &'a mut SharedFlags) -> Self {
    Self { data, shared }
  }

  /// View the input bytes. §3 slice projection — returns `&[u8]`.
  #[must_use]
  #[inline(always)]
  pub const fn data(&self) -> &'a [u8] {
    self.data
  }

  /// Read-only view of the shared flags. The mutable borrow is exposed
  /// via [`Self::shared_mut`] for the typed ID3 / APE parsers (Phase F2 /
  /// F3) once they migrate. (The `shared`/`shared_mut` pairing mirrors the
  /// established cross-format `SharedFlags` accessor convention —
  /// `ape.rs`, `id3/process.rs` — rather than the generic `_ref`/`_mut`
  /// pair, kept identical for chained-dispatch call-site uniformity.)
  #[must_use]
  #[inline(always)]
  pub const fn shared(&self) -> &SharedFlags {
    self.shared
  }

  /// Mutable view of the shared flags (reserved for typed chained
  /// parsers; today's WavPack parse leaves them untouched).
  #[inline(always)]
  pub const fn shared_mut(&mut self) -> &mut SharedFlags {
    self.shared
  }
}

// ===========================================================================
// `ProcessWv` — the lib-first parser
// ===========================================================================

/// WavPack parser — faithful port of `Image::ExifTool::WavPack::ProcessWV`
/// (WavPack.pm:80-105).
#[derive(Debug, Clone, Copy)]
pub struct ProcessWv;

impl parser_sealed::Sealed for ProcessWv {}

impl FormatParser for ProcessWv {
  /// GAT: the Meta borrows from the input `'a` (Codex AF2).
  type Meta<'a> = Meta<'a>;
  /// Spec §6.4 — chained-format context is a struct wrapping `&[u8]` +
  /// `&mut SharedFlags`.
  type Context<'a> = Context<'a>;
  /// Rust-level fatal error (none today; WavPack parsing has no I/O modes).
  type Error = Error;

  /// Parse a WavPack file's bytes into a typed [`Meta`], or `None` if
  /// the buffer is not a valid WavPack file (short read, bad magic, or
  /// version-byte mismatch — WavPack.pm:87-88).
  ///
  /// Returns `Err` only for Rust-level fatal modes; the current port
  /// has none (every bad input is `Ok(None)` per Perl's `return 0`).
  fn parse<'a>(&self, ctx: Self::Context<'a>) -> Result<Option<Self::Meta<'a>>, Error> {
    Ok(parse_inner(ctx.data))
  }
}

/// Lib-first direct entry. Same as [`FormatParser::parse`] now that the
/// [`FormatParser::Meta`] GAT threads the input borrow lifetime through —
/// returns a [`Meta`] borrowing from the input buffer (zero allocation,
/// including the chained ID3/APE trailer scan range; Codex AF2).
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today; reserved for
/// future I/O wrappers).
pub fn parse_borrowed(data: &[u8]) -> Result<Option<Meta<'_>>, Error> {
  Ok(parse_inner(data))
}

/// Inner parser — produces a borrow-from-input [`Meta`]. The
/// [`FormatParser::Meta`] GAT (`type Meta<'a> = Meta<'a>`) returns this
/// borrowed form directly into the closed [`crate::parser_new::AnyMeta`]
/// enum, keeping the live trailer-scan slice (Codex AF2).
fn parse_inner(data: &[u8]) -> Option<Meta<'_>> {
  // WavPack.pm:87 `return 0 unless $raf->Read($buff, 32) == 32`.
  if data.len() < 32 {
    return None;
  }
  // WavPack.pm:88 `return 0 unless $buff =~ /^wvpk.{4}[\x02\x10]\x04/s`.
  //   bytes 0..4 == "wvpk"
  //   bytes 4..8 = ckSize  (any value, `.{4}` consumes them)
  //   byte 8 ∈ {0x02, 0x10}
  //   byte 9 == 0x04
  if &data[..4] != b"wvpk" {
    return None;
  }
  if data[8] != 0x02 && data[8] != 0x10 {
    return None;
  }
  if data[9] != 0x04 {
    return None;
  }

  // WavPack.pm:91-95 `$et->ProcessBinaryData(\%dirInfo, GetTagTable(
  // 'Image::ExifTool::WavPack::Main'))`. With `FORMAT=>'int32u'` and all
  // five tag IDs sharing `int(index) = 6`, every tag's entry offset is
  // `6 * 4 = 24` (ExifTool.pm:9946 `$entry = int($index) * $increment +
  // $varSize`, $varSize stays 0 across the integer-keyed loop). The
  // shared `int32u` is read with the current byte order (ExifTool.pm:
  // 6239 `int32u => \&Get32u`); WavPack.pm never calls `SetByteOrder`,
  // so the global default 'MM' (ExifTool.pm:5981) applies — big-endian.
  //
  // ExifTool byte-order-state quirk (verified against bundled
  // `perl exiftool` 2026-05-20): `$currentByteOrder` is process-wide
  // and `ExifTool::Init` (ExifTool.pm:4316-4365) does NOT reset it
  // between files in a batch invocation. Other audio modules
  // (FLAC.pm:256, APE.pm:140/173, MPC.pm:98) explicitly call
  // `SetByteOrder('MM'|'II')`; WavPack.pm does not, so e.g.
  // `perl exiftool le.tiff WavPack.wv` reads these flags as `II`
  // (because the TIFF read flipped the global). Our port is faithful
  // to the FRESH-PROCESS state — global default 'MM' — which is the
  // §4 conformance bar (tools/gen_golden.sh invokes Perl once per
  // file). exifast's library API is per-file (`extract_info` builds a
  // fresh `Metadata` per call); no shared parser state exists across
  // calls, so the Perl batch-mode leak is structurally invisible
  // here. Threading byte-order state through `ParseContext` would be
  // dead code today and is intentionally not done.
  let flags = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);

  // Mask + shift, faithful to ExifTool.pm:10067-10068
  // `val = (val & mask) >> shift`.
  let bps_raw = ((flags & BYTES_PER_SAMPLE_MASK) >> BYTES_PER_SAMPLE_SHIFT) as u8;
  // ValueConv `$val + 1` (WavPack.pm:34) ⇒ post-ValueConv ∈ [1, 4].
  let bytes_per_sample = bps_raw + 1;

  let at_raw = ((flags & AUDIO_TYPE_MASK) >> AUDIO_TYPE_SHIFT) as u8;
  let audio_type = AudioType::from_raw(at_raw);

  let comp_raw = ((flags & COMPRESSION_MASK) >> COMPRESSION_SHIFT) as u8;
  let compression = Compression::from_raw(comp_raw);

  let df_raw = ((flags & DATA_FORMAT_MASK) >> DATA_FORMAT_SHIFT) as u8;
  let data_format = DataFormat::from_raw(df_raw);

  let sr_raw = ((flags & SAMPLE_RATE_MASK) >> SAMPLE_RATE_SHIFT) as u8;
  // sr_raw ∈ [0, 15] by construction (4-bit mask). The `expect` is
  // defensive: `sample_rate_lookup` is total over [0, 15].
  let sample_rate = sample_rate_lookup(sr_raw)
    .expect("4-bit SampleRate index always resolves via sample_rate_lookup");

  // Carry the full input as the chained-trailer scan range. WavPack.pm:
  // 97-102 scans the WHOLE file (the Perl `$raf` is reset to offset 0
  // by `Seek(0, 0)`) for RIFF wrapper / ID3 / APE trailers. The typed
  // parse exposes the range; the legacy bridge invokes the chained
  // parsers.
  Some(Meta {
    bytes_per_sample,
    audio_type,
    compression,
    data_format,
    sample_rate,
    sample_rate_raw_index: sr_raw,
    id3_apetrailer_scan: Some(data),
  })
}

// ===========================================================================
// `serialize_tags` — typed Meta → TagMap
// ===========================================================================

#[cfg(feature = "alloc")]
impl Meta<'_> {
  /// Emit WavPack tags into the writer in ExifTool numeric sort order
  /// (WavPack.pm:31-73 → ExifTool.pm:9907 sorted-key walk): 6.1
  /// BytesPerSample, 6.2 AudioType, 6.3 Compression, 6.4 DataFormat, 6.5
  /// SampleRate. The family-0/-1 group is `"File"` (WavPack.pm:23
  /// `GROUPS => { 0 => 'File', 1 => 'File', 2 => 'Audio' }`; `-G1` ⇒
  /// `"File:"` prefix; the family-2 `'Audio'` is not emitted under `-G1`).
  ///
  /// `print_conv=true` ⇒ PrintConv strings (`-j` mode, e.g.
  /// `"Mono"`/`"Lossless"`/`"Custom"`); `print_conv=false` ⇒ post-ValueConv
  /// raw scalars (`-n` mode, e.g. `1`/`0`/`15`).
  pub(crate) fn serialize_tags(
    &self,
    print_conv: bool,
    out: &mut crate::tagmap::TagMap,
  ) -> Result<(), core::convert::Infallible> {
    const GROUP: &str = "File";

    // 6.1 BytesPerSample — post-ValueConv `+1` already applied at parse
    // time. PrintConv is None, so the post-ValueConv integer is emitted
    // directly under both -j and -n.
    out.write_u64(GROUP, "BytesPerSample", u64::from(self.bytes_per_sample))?;

    // 6.2 AudioType — -j: PrintConv string; -n: raw u8.
    if print_conv {
      out.write_str(GROUP, "AudioType", self.audio_type.as_str())?;
    } else {
      out.write_u64(GROUP, "AudioType", u64::from(self.audio_type.raw()))?;
    }

    // 6.3 Compression — -j: PrintConv string; -n: raw u8.
    if print_conv {
      out.write_str(GROUP, "Compression", self.compression.as_str())?;
    } else {
      out.write_u64(GROUP, "Compression", u64::from(self.compression.raw()))?;
    }

    // 6.4 DataFormat — -j: PrintConv string; -n: raw u8.
    if print_conv {
      out.write_str(GROUP, "DataFormat", self.data_format.as_str())?;
    } else {
      out.write_u64(GROUP, "DataFormat", u64::from(self.data_format.raw()))?;
    }

    // 6.5 SampleRate — -j: PrintConv hash. Hash returns I64 for known
    // rates (0..=14) ⇒ bare JSON number; Str("Custom") for index 15 ⇒
    // quoted JSON string. -n: raw 4-bit index 0..=15 (bare number).
    if print_conv {
      match self.sample_rate {
        SampleRate::Hz(n) => out.write_u64(GROUP, "SampleRate", u64::from(n))?,
        SampleRate::Custom => out.write_str(GROUP, "SampleRate", "Custom")?,
      }
    } else {
      out.write_u64(GROUP, "SampleRate", u64::from(self.sample_rate_raw_index))?;
    }

    Ok(())
  }
}

// ===========================================================================
// `Error` — Rust-level fatal modes (currently none)
// ===========================================================================

/// Rust-level fatal modes for WavPack parsing. Currently empty — every
/// bad input produces `Ok(None)` (Perl `return 0`). Reserved for future
/// I/O wrappers if streaming readers are added.
///
/// §5: `Display` + `core::error::Error` derived via `thiserror` (v2,
/// `default-features = false` ⇒ `core::error::Error` in every feature
/// tier, not just `std`). `#[non_exhaustive]` lets I/O variants land
/// without a breaking change.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {}

// ===========================================================================
// Engine entry — typed parse + File:* + sink into `Metadata`
// ===========================================================================

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;
  use crate::tagmap::TagMap;

  // -------------------------------------------------------------------------
  // Mask + shift derivation
  // -------------------------------------------------------------------------

  #[test]
  fn bit_shifts_pin_to_perl_table() {
    // ExifTool.pm:5905-5910: BitShift = trailing zeros of Mask.
    assert_eq!(BYTES_PER_SAMPLE_MASK, 0x0000_0003);
    assert_eq!(AUDIO_TYPE_MASK, 0x0000_0004);
    assert_eq!(COMPRESSION_MASK, 0x0000_0008);
    assert_eq!(DATA_FORMAT_MASK, 0x0000_0080);
    assert_eq!(SAMPLE_RATE_MASK, 0x0780_0000);
    assert_eq!(BYTES_PER_SAMPLE_SHIFT, 0);
    assert_eq!(AUDIO_TYPE_SHIFT, 2);
    assert_eq!(COMPRESSION_SHIFT, 3);
    assert_eq!(DATA_FORMAT_SHIFT, 7);
    assert_eq!(SAMPLE_RATE_SHIFT, 23);
  }

  #[test]
  fn sample_rate_lookup_table_is_faithful() {
    // WavPack.pm:55-72 — 0..=14 known rates, 15 = Custom.
    assert_eq!(sample_rate_lookup(0), Some(SampleRate::Hz(6000)));
    assert_eq!(sample_rate_lookup(9), Some(SampleRate::Hz(44100)));
    assert_eq!(sample_rate_lookup(10), Some(SampleRate::Hz(48000)));
    assert_eq!(sample_rate_lookup(14), Some(SampleRate::Hz(192000)));
    assert_eq!(sample_rate_lookup(15), Some(SampleRate::Custom));
    // Unreachable from a 4-bit mask, but kept total for safety.
    assert_eq!(sample_rate_lookup(16), None);
  }

  #[test]
  fn sample_rate_variant_accessors() {
    // §2 predicates + unwrap accessors (derive_more) + Display single source.
    let hz = SampleRate::Hz(48000);
    assert!(hz.is_hz());
    assert!(!hz.is_custom());
    assert_eq!(hz.unwrap_hz(), 48000u32);
    assert_eq!(hz.try_unwrap_hz().ok(), Some(48000u32));
    assert_eq!(hz.to_string(), "48000");
    let custom = SampleRate::Custom;
    assert!(custom.is_custom());
    assert!(!custom.is_hz());
    assert!(custom.try_unwrap_hz().is_err());
    assert_eq!(custom.to_string(), "Custom");
  }

  // -------------------------------------------------------------------------
  // Typed enums
  // -------------------------------------------------------------------------

  #[test]
  fn audio_type_round_trip() {
    assert_eq!(AudioType::from_raw(0), AudioType::Stereo);
    assert_eq!(AudioType::from_raw(1), AudioType::Mono);
    assert_eq!(AudioType::Stereo.raw(), 0);
    assert_eq!(AudioType::Mono.raw(), 1);
    assert_eq!(AudioType::Stereo.as_str(), "Stereo");
    assert_eq!(AudioType::Mono.as_str(), "Mono");
    // §2 Display routes through as_str (single source of truth).
    assert_eq!(AudioType::Stereo.to_string(), "Stereo");
    // §2 predicates (derive_more::IsVariant).
    assert!(AudioType::Stereo.is_stereo());
    assert!(!AudioType::Stereo.is_mono());
  }

  #[test]
  fn compression_round_trip() {
    assert_eq!(Compression::from_raw(0), Compression::Lossless);
    assert_eq!(Compression::from_raw(1), Compression::Hybrid);
    assert_eq!(Compression::Lossless.raw(), 0);
    assert_eq!(Compression::Hybrid.raw(), 1);
    assert_eq!(Compression::Lossless.as_str(), "Lossless");
    assert_eq!(Compression::Hybrid.as_str(), "Hybrid");
    assert_eq!(Compression::Hybrid.to_string(), "Hybrid");
    assert!(Compression::Lossless.is_lossless());
    assert!(Compression::Hybrid.is_hybrid());
  }

  #[test]
  fn data_format_round_trip() {
    assert_eq!(DataFormat::from_raw(0), DataFormat::Integer);
    assert_eq!(DataFormat::from_raw(1), DataFormat::FloatingPoint);
    assert_eq!(DataFormat::Integer.raw(), 0);
    assert_eq!(DataFormat::FloatingPoint.raw(), 1);
    assert_eq!(DataFormat::Integer.as_str(), "Integer");
    assert_eq!(DataFormat::FloatingPoint.as_str(), "Floating Point");
    assert_eq!(DataFormat::FloatingPoint.to_string(), "Floating Point");
    assert!(DataFormat::Integer.is_integer());
    assert!(DataFormat::FloatingPoint.is_floating_point());
  }

  // -------------------------------------------------------------------------
  // `parse_borrowed` — lib-first direct entry
  // -------------------------------------------------------------------------

  /// Build a 32-byte wvpk header with the given LE flags word. All
  /// other fields use deterministic values; only the flags drive
  /// WavPack's tags.
  fn header_with_flags(flags_le: u32) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0..4].copy_from_slice(b"wvpk");
    h[4..8].copy_from_slice(&100u32.to_le_bytes()); // ckSize
    h[8] = 0x10; // version low
    h[9] = 0x04; // version high (0x0410)
    // [10] block_index_u8 = 0
    // [11] total_samples_u8 = 0
    h[12..16].copy_from_slice(&1000u32.to_le_bytes()); // total_samples
    // [16..20] block_index = 0
    h[20..24].copy_from_slice(&500u32.to_le_bytes()); // block_samples
    h[24..28].copy_from_slice(&flags_le.to_le_bytes()); // flags (LE on disk)
    // [28..32] crc = 0
    h
  }

  #[test]
  fn parse_borrowed_extracts_fixture_flags() {
    // Oracle pattern: on-disk LE flags `0x0480008d`. BE read of bytes
    // 24..27 = 0x8d008004 ⇒
    //   BytesPerSample raw=0 +1 = 1
    //   AudioType raw=1 → Mono
    //   Compression raw=0 → Lossless
    //   DataFormat raw=0 → Integer
    //   SampleRate raw=10 → Hz(48000)
    let data = header_with_flags(0x0480_008d);
    let meta = parse_borrowed(&data).expect("ok").expect("parsed");
    assert_eq!(meta.bytes_per_sample(), 1);
    assert_eq!(meta.audio_type(), AudioType::Mono);
    assert_eq!(meta.compression(), Compression::Lossless);
    assert_eq!(meta.data_format(), DataFormat::Integer);
    assert_eq!(meta.sample_rate(), SampleRate::Hz(48000));
    assert_eq!(meta.sample_rate_hz(), Some(48000));
    assert_eq!(meta.sample_rate_raw_index(), 10);
    // The chained scan range is the FULL input buffer.
    assert_eq!(meta.id3_ape_scan_range(), Some(data.as_slice()));
  }

  #[test]
  fn parse_borrowed_adversarial_all_bits_set() {
    // flags = 0xFFFFFFFF: every mask saturates.
    //   BytesPerSample raw=3 → +1 = 4
    //   AudioType raw=1 → Mono
    //   Compression raw=1 → Hybrid
    //   DataFormat raw=1 → FloatingPoint
    //   SampleRate raw=15 → Custom
    let data = header_with_flags(0xFFFF_FFFF);
    let meta = parse_borrowed(&data).expect("ok").expect("parsed");
    assert_eq!(meta.bytes_per_sample(), 4);
    assert_eq!(meta.audio_type(), AudioType::Mono);
    assert_eq!(meta.compression(), Compression::Hybrid);
    assert_eq!(meta.data_format(), DataFormat::FloatingPoint);
    assert_eq!(meta.sample_rate(), SampleRate::Custom);
    assert_eq!(meta.sample_rate_hz(), None);
    assert_eq!(meta.sample_rate_raw_index(), 15);
  }

  #[test]
  fn parse_borrowed_rejects_short() {
    assert!(parse_borrowed(&[]).unwrap().is_none());
    assert!(parse_borrowed(&[0u8; 16]).unwrap().is_none());
    assert!(parse_borrowed(&[0u8; 31]).unwrap().is_none());
  }

  #[test]
  fn parse_borrowed_rejects_bad_magic() {
    let mut data = vec![0u8; 32];
    data[..4].copy_from_slice(b"WVPK");
    assert!(parse_borrowed(&data).unwrap().is_none());
  }

  #[test]
  fn parse_borrowed_rejects_bad_version_byte_8() {
    let mut data = vec![0u8; 32];
    data[..4].copy_from_slice(b"wvpk");
    data[8] = 0x05; // out of {0x02, 0x10}
    data[9] = 0x04;
    assert!(parse_borrowed(&data).unwrap().is_none());
  }

  #[test]
  fn parse_borrowed_rejects_bad_version_byte_9() {
    let mut data = vec![0u8; 32];
    data[..4].copy_from_slice(b"wvpk");
    data[8] = 0x10;
    data[9] = 0x05; // not 0x04
    assert!(parse_borrowed(&data).unwrap().is_none());
  }

  #[test]
  fn parse_borrowed_accepts_version_byte_02() {
    // Byte 8 == 0x02 is the other allowed version (WavPack.pm:88).
    let mut data = header_with_flags(0);
    data[8] = 0x02; // 0x0402
    let meta = parse_borrowed(&data).expect("ok").expect("parsed");
    assert_eq!(meta.bytes_per_sample(), 1); // raw=0 +1
  }

  // -------------------------------------------------------------------------
  // `FormatParser` trait + `Context`
  // -------------------------------------------------------------------------

  #[test]
  fn format_parser_trait_returns_borrowed_meta() {
    let data = header_with_flags(0x0480_008d);
    let mut shared = SharedFlags::new();
    let ctx = Context::new(&data, &mut shared);
    let meta = <ProcessWv as FormatParser>::parse(&ProcessWv, ctx)
      .expect("ok")
      .expect("parsed");
    // Identical extraction to `parse_borrowed`: the GAT path now threads
    // the input borrow through, so the chained-trailer scan range survives
    // (previously dropped by the removed `into_static`; Codex AF2).
    assert_eq!(meta.bytes_per_sample(), 1);
    assert_eq!(meta.audio_type(), AudioType::Mono);
    assert_eq!(meta.sample_rate(), SampleRate::Hz(48000));
    assert_eq!(meta.sample_rate_raw_index(), 10);
    // The borrowed scan range is preserved on the trait path now.
    assert!(meta.id3_ape_scan_range().is_some());
  }

  #[test]
  fn format_parser_trait_rejects_bad_magic() {
    let mut data = vec![0u8; 32];
    data[..4].copy_from_slice(b"WVPK");
    let mut shared = SharedFlags::new();
    let ctx = Context::new(&data, &mut shared);
    let result = <ProcessWv as FormatParser>::parse(&ProcessWv, ctx).unwrap();
    assert!(result.is_none());
  }

  #[test]
  fn wv_context_exposes_shared_mut_for_chained_parsers() {
    // Reserved-for-Phase-F2/F3 wiring smoke test — the lib-first parse
    // does not actually flip shared flags today.
    let data = header_with_flags(0);
    let mut shared = SharedFlags::new();
    {
      let mut ctx = Context::new(&data, &mut shared);
      assert_eq!(ctx.shared().done_id3(), None);
      ctx.shared_mut().set_done_id3(128);
    }
    assert_eq!(shared.done_id3(), Some(128));
  }

  // -------------------------------------------------------------------------
  // `serialize_tags` — typed Meta → TagMap (PrintConv on / off)
  // -------------------------------------------------------------------------

  fn collect(flags_le: u32, print_conv: bool) -> TagMap {
    let data = header_with_flags(flags_le);
    let mut shared = SharedFlags::new();
    let ctx = Context::new(&data, &mut shared);
    let meta = <ProcessWv as FormatParser>::parse(&ProcessWv, ctx)
      .unwrap()
      .unwrap();
    let mut w = TagMap::new();
    meta.serialize_tags(print_conv, &mut w).unwrap();
    w
  }

  #[test]
  fn sink_print_on_emits_fixture_strings() {
    let w = collect(0x0480_008d, true);
    let g = |n: &str| w.get_str("File", n);
    assert_eq!(g("BytesPerSample"), Some("1".into()));
    assert_eq!(g("AudioType"), Some("Mono".into()));
    assert_eq!(g("Compression"), Some("Lossless".into()));
    assert_eq!(g("DataFormat"), Some("Integer".into()));
    assert_eq!(g("SampleRate"), Some("48000".into()));
  }

  #[test]
  fn sink_print_on_emits_adversarial_strings() {
    let w = collect(0xFFFF_FFFF, true);
    let g = |n: &str| w.get_str("File", n);
    assert_eq!(g("BytesPerSample"), Some("4".into()));
    assert_eq!(g("AudioType"), Some("Mono".into()));
    assert_eq!(g("Compression"), Some("Hybrid".into()));
    assert_eq!(g("DataFormat"), Some("Floating Point".into()));
    assert_eq!(g("SampleRate"), Some("Custom".into()));
  }

  #[test]
  fn sink_print_off_emits_fixture_raw() {
    let w = collect(0x0480_008d, false);
    let g = |n: &str| w.get_str("File", n);
    assert_eq!(g("BytesPerSample"), Some("1".into())); // +1 applied
    assert_eq!(g("AudioType"), Some("1".into()));
    assert_eq!(g("Compression"), Some("0".into()));
    assert_eq!(g("DataFormat"), Some("0".into()));
    // SampleRate -n: raw 4-bit index (10), not the post-PrintConv 48000.
    assert_eq!(g("SampleRate"), Some("10".into()));
  }

  #[test]
  fn sink_print_off_emits_adversarial_raw() {
    let w = collect(0xFFFF_FFFF, false);
    let g = |n: &str| w.get_str("File", n);
    assert_eq!(g("BytesPerSample"), Some("4".into())); // raw=3 +1
    assert_eq!(g("AudioType"), Some("1".into()));
    assert_eq!(g("Compression"), Some("1".into()));
    assert_eq!(g("DataFormat"), Some("1".into()));
    assert_eq!(g("SampleRate"), Some("15".into())); // raw index 15
  }

  // -------------------------------------------------------------------------
  // Engine entry — typed parse + File:* + sink into `TagMap`
  // -------------------------------------------------------------------------

  // The engine path is now `crate::parser::extract_info`. These run it and
  // assert on the parsed JSON object (replacing the retired `ProcessWv::process`
  // + `TagMap` tests).
  fn engine_obj(data: &[u8], print_on: bool) -> serde_json::Map<String, serde_json::Value> {
    let json = crate::parser::extract_info("WavPack.wv", data, print_on);
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    v.as_array().unwrap()[0].as_object().unwrap().clone()
  }
  fn is_wv(obj: &serde_json::Map<String, serde_json::Value>) -> bool {
    obj.get("File:FileType").and_then(|v| v.as_str()) == Some("WV")
  }

  #[test]
  fn bridge_fixture_round_trip_print_on() {
    let obj = engine_obj(&header_with_flags(0x0480_008d), true);
    let s = |k: &str| obj.get(k).and_then(|v| v.as_str());
    assert_eq!(s("File:FileType"), Some("WV"));
    assert_eq!(
      obj.get("File:BytesPerSample").and_then(|v| v.as_u64()),
      Some(1)
    );
    assert_eq!(s("File:AudioType"), Some("Mono"));
    assert_eq!(s("File:Compression"), Some("Lossless"));
    assert_eq!(s("File:DataFormat"), Some("Integer"));
    assert_eq!(
      obj.get("File:SampleRate").and_then(|v| v.as_u64()),
      Some(48000)
    );
  }

  #[test]
  fn bridge_fixture_round_trip_print_off() {
    let obj = engine_obj(&header_with_flags(0x0480_008d), false);
    let u = |k: &str| obj.get(k).and_then(|v| v.as_u64());
    assert_eq!(u("File:BytesPerSample"), Some(1));
    assert_eq!(u("File:AudioType"), Some(1));
    assert_eq!(u("File:Compression"), Some(0));
    assert_eq!(u("File:DataFormat"), Some(0));
    assert_eq!(u("File:SampleRate"), Some(10));
  }

  #[test]
  fn bridge_adversarial_round_trip_print_on() {
    let obj = engine_obj(&header_with_flags(0xFFFF_FFFF), true);
    let s = |k: &str| obj.get(k).and_then(|v| v.as_str());
    assert_eq!(
      obj.get("File:BytesPerSample").and_then(|v| v.as_u64()),
      Some(4)
    );
    assert_eq!(s("File:AudioType"), Some("Mono"));
    assert_eq!(s("File:Compression"), Some("Hybrid"));
    assert_eq!(s("File:DataFormat"), Some("Floating Point"));
    assert_eq!(s("File:SampleRate"), Some("Custom"));
  }

  #[test]
  fn bridge_rejects_short() {
    assert!(!is_wv(&engine_obj(&vec![0u8; 16], true)));
  }

  #[test]
  fn bridge_rejects_bad_magic() {
    let mut data = vec![0u8; 32];
    data[..4].copy_from_slice(b"WVPK");
    assert!(!is_wv(&engine_obj(&data, true)));
  }

  #[test]
  fn bridge_rejects_bad_version_byte_8() {
    let mut data = vec![0u8; 32];
    data[..4].copy_from_slice(b"wvpk");
    data[8] = 0x05;
    data[9] = 0x04;
    assert!(!is_wv(&engine_obj(&data, true)));
  }

  #[test]
  fn bridge_rejects_bad_version_byte_9() {
    let mut data = vec![0u8; 32];
    data[..4].copy_from_slice(b"wvpk");
    data[8] = 0x10;
    data[9] = 0x05;
    assert!(!is_wv(&engine_obj(&data, true)));
  }

  #[test]
  fn bridge_accepts_version_byte_02() {
    let mut data = header_with_flags(0);
    data[8] = 0x02;
    let obj = engine_obj(&data, true);
    assert!(is_wv(&obj));
    assert!(obj.contains_key("File:BytesPerSample"));
  }

  #[test]
  fn bridge_emits_tags_in_expected_order() {
    // ExifTool.pm:9907 numeric sort ⇒ 6.1..6.5. Order is preserved by the
    // typed `serialize_tags` -> `TagMap` entries (the JSON object loses it).
    let data = header_with_flags(0x0480_008d);
    let meta = parse_borrowed(&data).unwrap().unwrap();
    let mut tm = TagMap::new();
    meta.serialize_tags(true, &mut tm).unwrap();
    // WavPack tags use family-1 group "File" (WavPack.pm GROUPS{1}); the
    // typed sink emits ONLY these 5 (the File:* triplet is engine-added).
    let names: std::vec::Vec<&str> = tm
      .entries()
      .iter()
      .filter_map(|(k, _)| k.strip_prefix("File:"))
      .collect();
    assert_eq!(
      names,
      vec![
        "BytesPerSample",
        "AudioType",
        "Compression",
        "DataFormat",
        "SampleRate",
      ]
    );
  }

  #[test]
  fn bridge_accepts_wavpack_fixture() {
    // The WavPack chain runs ID3 + APE-trailer dispatch internally
    // (SharedFlags DoneAPE); the observable effect is acceptance as WV.
    let obj = engine_obj(&header_with_flags(0x0480_008d), true);
    assert!(is_wv(&obj));
  }
}
