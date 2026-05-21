// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "wavpack")]
//! Faithful port of `Image::ExifTool::WavPack` (lib/Image/ExifTool/WavPack.pm).
//! WavPack.pm is 144 lines: one tag table + one `Process<Type>` sub.
//!
//! **Phase F5 — lib-first migration.** Follows the MOI pilot (Phase E) +
//! AAC / DV leaves (Phase F1) pattern: a typed [`WvMeta<'a>`] is produced
//! by the new [`crate::parser_new::FormatParser`] trait; the legacy
//! [`crate::parser::OldFormatParser`] entry point bridges through
//! [`crate::sink::MetadataTagWriter`] so CLI JSON output stays byte-exact
//! during the per-format crawl. The bridge is retired in Phase G.
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
//! [`WvMeta`] that ONLY carries the WavPack-header tags AND
//! borrow-from-input `Option<&'a [u8]>` placeholders denoting the byte
//! ranges where ID3 / APE trailers may live (the whole input buffer,
//! since both legacy formats scan the entire file). Actually parsing
//! those trailers is delegated to the legacy `OldFormatParser` bridge,
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

use core::convert::Infallible;

use crate::{
  parser::ParseContext,
  parser_new::{FormatParser, MetaSinker, SharedFlags, TagWriter, parser_sealed},
  sink::MetadataTagWriter,
};

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
/// [`WvMeta::sample_rate_hz`].
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
/// D8: newtype-style enum — no fields on variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioType {
  /// WavPack.pm:39 — raw 0 ⇒ "Stereo".
  Stereo,
  /// WavPack.pm:39 — raw 1 ⇒ "Mono".
  Mono,
}

impl AudioType {
  /// Decode the raw bit (already mask + shift extracted) — 0 or 1.
  #[must_use]
  pub const fn from_raw(b: u8) -> AudioType {
    if b == 0 {
      AudioType::Stereo
    } else {
      AudioType::Mono
    }
  }

  /// The on-disk raw bit (0 = Stereo, 1 = Mono). Used by the `-n` raw
  /// emission path.
  #[must_use]
  pub const fn raw(self) -> u8 {
    match self {
      AudioType::Stereo => 0,
      AudioType::Mono => 1,
    }
  }

  /// WavPack.pm:39 PrintConv string.
  #[must_use]
  pub const fn print_conv(self) -> &'static str {
    match self {
      AudioType::Stereo => "Stereo",
      AudioType::Mono => "Mono",
    }
  }
}

/// `Compression` PrintConv (WavPack.pm:44): 0 ⇒ "Lossless", 1 ⇒ "Hybrid".
///
/// D8: newtype-style enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
  /// WavPack.pm:44 — raw 0 ⇒ "Lossless".
  Lossless,
  /// WavPack.pm:44 — raw 1 ⇒ "Hybrid".
  Hybrid,
}

impl Compression {
  /// Decode the raw bit (already mask + shift extracted) — 0 or 1.
  #[must_use]
  pub const fn from_raw(b: u8) -> Compression {
    if b == 0 {
      Compression::Lossless
    } else {
      Compression::Hybrid
    }
  }

  /// The on-disk raw bit (0 = Lossless, 1 = Hybrid).
  #[must_use]
  pub const fn raw(self) -> u8 {
    match self {
      Compression::Lossless => 0,
      Compression::Hybrid => 1,
    }
  }

  /// WavPack.pm:44 PrintConv string.
  #[must_use]
  pub const fn print_conv(self) -> &'static str {
    match self {
      Compression::Lossless => "Lossless",
      Compression::Hybrid => "Hybrid",
    }
  }
}

/// `DataFormat` PrintConv (WavPack.pm:49): 0 ⇒ "Integer", 1 ⇒ "Floating Point".
///
/// D8: newtype-style enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataFormat {
  /// WavPack.pm:49 — raw 0 ⇒ "Integer".
  Integer,
  /// WavPack.pm:49 — raw 1 ⇒ "Floating Point".
  FloatingPoint,
}

impl DataFormat {
  /// Decode the raw bit (already mask + shift extracted) — 0 or 1.
  #[must_use]
  pub const fn from_raw(b: u8) -> DataFormat {
    if b == 0 {
      DataFormat::Integer
    } else {
      DataFormat::FloatingPoint
    }
  }

  /// The on-disk raw bit (0 = Integer, 1 = FloatingPoint).
  #[must_use]
  pub const fn raw(self) -> u8 {
    match self {
      DataFormat::Integer => 0,
      DataFormat::FloatingPoint => 1,
    }
  }

  /// WavPack.pm:49 PrintConv string.
  #[must_use]
  pub const fn print_conv(self) -> &'static str {
    match self {
      DataFormat::Integer => "Integer",
      DataFormat::FloatingPoint => "Floating Point",
    }
  }
}

/// `SampleRate` PrintConv decoded shape (WavPack.pm:55-72). Indices
/// 0..=14 map to known integer rates; index 15 is the `"Custom"` string.
///
/// D8: newtype-style enum — the `Hz` variant payload is the post-PrintConv
/// numeric rate, NOT the raw 4-bit index (`raw_index` is preserved
/// separately on [`WvMeta`] for `-n` emission).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleRate {
  /// WavPack.pm:55-71 — known sample rate in Hz (e.g. `48000`).
  Hz(u32),
  /// WavPack.pm:72 — index 15 ⇒ `"Custom"` (sample rate not encoded in
  /// the header; the rate is "custom" / out-of-table).
  Custom,
}

// ===========================================================================
// Typed Meta — `WvMeta<'a>`
// ===========================================================================

/// Typed WavPack metadata — the lib-first output of [`ProcessWv`].
///
/// Carries the five `%WavPack::Main` header tags (post-mask, post-shift,
/// post-ValueConv) and two borrow-from-input `Option<&'a [u8]>` placeholders
/// for ID3 / APE trailers. The placeholders denote the byte ranges where
/// the legacy chained parsers can scan; actually invoking them lives in
/// the [`OldFormatParser`] bridge for byte-exact CLI conformance during
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
/// use exifast::formats::wavpack::{ProcessWv, WvContext};
///
/// let bytes = std::fs::read("file.wv")?;
/// let mut shared = SharedFlags::new();
/// let ctx = WvContext::new(&bytes, &mut shared);
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
pub struct WvMeta<'a> {
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
  /// Today the `OldFormatParser` bridge does the actual chained parsing.
  id3_apetrailer_scan: Option<&'a [u8]>,
}

impl<'a> WvMeta<'a> {
  /// WavPack.pm:31-35 — `BytesPerSample` post-ValueConv (1..=4).
  #[must_use]
  pub fn bytes_per_sample(&self) -> u8 {
    self.bytes_per_sample
  }

  /// WavPack.pm:36-40 — `AudioType` decoded enum.
  #[must_use]
  pub fn audio_type(&self) -> AudioType {
    self.audio_type
  }

  /// WavPack.pm:41-45 — `Compression` decoded enum.
  #[must_use]
  pub fn compression(&self) -> Compression {
    self.compression
  }

  /// WavPack.pm:46-50 — `DataFormat` decoded enum.
  #[must_use]
  pub fn data_format(&self) -> DataFormat {
    self.data_format
  }

  /// WavPack.pm:51-73 — `SampleRate` typed decoded form (`Hz(u32)` or
  /// `Custom`).
  #[must_use]
  pub fn sample_rate(&self) -> SampleRate {
    self.sample_rate
  }

  /// `SampleRate` as `u32` Hz when known; `None` for the `"Custom"`
  /// index 15. Convenience accessor for callers that want a numeric
  /// rate or nothing.
  #[must_use]
  pub fn sample_rate_hz(&self) -> Option<u32> {
    match self.sample_rate {
      SampleRate::Hz(n) => Some(n),
      SampleRate::Custom => None,
    }
  }

  /// Raw 4-bit `SampleRate` index ∈ [0, 15]. Equivalent to the bundled
  /// `perl exiftool -n` numeric output for `File:SampleRate` (which
  /// emits the pre-PrintConv raw mask value).
  #[must_use]
  pub fn sample_rate_raw_index(&self) -> u8 {
    self.sample_rate_raw_index
  }

  /// Byte range where the chained ID3 / APE-trailer scan runs. `Some`
  /// borrows from the input buffer; today's lib-first parse always sets
  /// this to the full buffer. The `OldFormatParser` bridge consumes it
  /// through the existing chained entries
  /// `crate::formats::id3::process::process_id3_chained` +
  /// `crate::formats::ape::ProcessApe::process_trailer_only`.
  #[must_use]
  pub fn id3_ape_scan_range(&self) -> Option<&'a [u8]> {
    self.id3_apetrailer_scan
  }
}

// ===========================================================================
// `WvContext<'a>` — per-format input view
// ===========================================================================

/// Per-format input view for [`ProcessWv`]. Wraps the input bytes plus
/// a `&mut SharedFlags` for the cross-format chain (ID3 → APE flags).
/// Spec §6.4 — chained-format `Context<'a>` is a struct, not a bare
/// `&'a [u8]`.
///
/// The shared flags are reserved for the lib-first typed ID3 / APE
/// parsers (Phase F2 / F3 work in parallel agents). Today the
/// [`OldFormatParser`] bridge still drives ID3 / APE via the legacy
/// `Metadata` flags ([`crate::value::Metadata::set_done_id3`] /
/// [`crate::value::Metadata::set_done_ape`]); when the typed-ID3 /
/// typed-APE typed parsers land they'll read/write
/// [`SharedFlags::done_id3`] / [`SharedFlags::done_ape`] instead. The
/// `&mut SharedFlags` carry is the seam.
///
/// D8: no public fields; constructor + accessors only.
pub struct WvContext<'a> {
  /// The full WavPack file bytes — typically the entire input buffer.
  data: &'a [u8],
  /// Mutable cross-format flags. Reserved for the typed ID3 / APE
  /// parsers (Phase F2 / F3) — today's lib-first WavPack parse does
  /// not flip these; the legacy bridge uses the [`crate::value::Metadata`]
  /// counterparts instead.
  shared: &'a mut SharedFlags,
}

impl<'a> WvContext<'a> {
  /// Build a context wrapping `data` and a borrowed `shared` flags
  /// table. The flags are not mutated by the lib-first parse today;
  /// see the type-level docs for the Phase F2 / F3 plan.
  pub fn new(data: &'a [u8], shared: &'a mut SharedFlags) -> Self {
    Self { data, shared }
  }

  /// View the input bytes.
  #[must_use]
  pub fn data(&self) -> &'a [u8] {
    self.data
  }

  /// Read-only view of the shared flags. The mutable borrow is exposed
  /// via [`Self::shared_mut`] for the typed ID3 / APE parsers (Phase F2 /
  /// F3) once they migrate.
  #[must_use]
  pub fn shared(&self) -> &SharedFlags {
    self.shared
  }

  /// Mutable view of the shared flags (reserved for typed chained
  /// parsers; today's WavPack parse leaves them untouched).
  pub fn shared_mut(&mut self) -> &mut SharedFlags {
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
  type Meta<'a> = WvMeta<'a>;
  /// Spec §6.4 — chained-format context is a struct wrapping `&[u8]` +
  /// `&mut SharedFlags`.
  type Context<'a> = WvContext<'a>;
  /// Rust-level fatal error (none today; WavPack parsing has no I/O modes).
  type Error = WvError;

  /// Parse a WavPack file's bytes into a typed [`WvMeta`], or `None` if
  /// the buffer is not a valid WavPack file (short read, bad magic, or
  /// version-byte mismatch — WavPack.pm:87-88).
  ///
  /// Returns `Err` only for Rust-level fatal modes; the current port
  /// has none (every bad input is `Ok(None)` per Perl's `return 0`).
  fn parse<'a>(&self, ctx: Self::Context<'a>) -> Result<Option<Self::Meta<'a>>, WvError> {
    Ok(parse_inner(ctx.data))
  }
}

/// Lib-first direct entry. Same as [`FormatParser::parse`] now that the
/// [`FormatParser::Meta`] GAT threads the input borrow lifetime through —
/// returns a [`WvMeta`] borrowing from the input buffer (zero allocation,
/// including the chained ID3/APE trailer scan range; Codex AF2).
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today; reserved for
/// future I/O wrappers).
pub fn parse_borrowed(data: &[u8]) -> Result<Option<WvMeta<'_>>, WvError> {
  Ok(parse_inner(data))
}

/// Inner parser — produces a borrow-from-input [`WvMeta`]. The
/// [`FormatParser::Meta`] GAT (`type Meta<'a> = WvMeta<'a>`) returns this
/// borrowed form directly into the closed [`crate::parser_new::AnyMeta`]
/// enum, keeping the live trailer-scan slice (Codex AF2).
fn parse_inner(data: &[u8]) -> Option<WvMeta<'_>> {
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
  Some(WvMeta {
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
// `MetaSinker` — typed Meta → TagWriter
// ===========================================================================

impl MetaSinker for WvMeta<'_> {
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
  fn sink<W: TagWriter>(&self, print_conv: bool, out: &mut W) -> Result<(), W::Error> {
    const GROUP: &str = "File";

    // 6.1 BytesPerSample — post-ValueConv `+1` already applied at parse
    // time. PrintConv is None, so the post-ValueConv integer is emitted
    // directly under both -j and -n.
    out.write_u64(GROUP, "BytesPerSample", u64::from(self.bytes_per_sample))?;

    // 6.2 AudioType — -j: PrintConv string; -n: raw u8.
    if print_conv {
      out.write_str(GROUP, "AudioType", self.audio_type.print_conv())?;
    } else {
      out.write_u64(GROUP, "AudioType", u64::from(self.audio_type.raw()))?;
    }

    // 6.3 Compression — -j: PrintConv string; -n: raw u8.
    if print_conv {
      out.write_str(GROUP, "Compression", self.compression.print_conv())?;
    } else {
      out.write_u64(GROUP, "Compression", u64::from(self.compression.raw()))?;
    }

    // 6.4 DataFormat — -j: PrintConv string; -n: raw u8.
    if print_conv {
      out.write_str(GROUP, "DataFormat", self.data_format.print_conv())?;
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
// `WvError` — Rust-level fatal modes (currently none)
// ===========================================================================

/// Rust-level fatal modes for WavPack parsing. Currently empty — every
/// bad input produces `Ok(None)` (Perl `return 0`). Reserved for future
/// I/O wrappers if streaming readers are added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WvError {}

impl core::fmt::Display for WvError {
  fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match *self {}
  }
}

#[cfg(feature = "std")]
impl std::error::Error for WvError {}

// ===========================================================================
// Legacy `OldFormatParser` bridge — preserves CLI byte-exact JSON
// ===========================================================================

impl ProcessWv {
  /// Engine entry used by the closed [`crate::parser_new::AnyParser`]
  /// dispatch (`crate::parser::extract_info`). Runs the typed
  /// [`FormatParser::parse`] and drives [`MetaSinker::sink`] through a
  /// [`MetadataTagWriter`] so the serialized JSON stays byte-exact with
  /// bundled `perl exiftool`.
  ///
  /// Faithful order (WavPack.pm:87-104):
  /// 1. Magic + version-byte gate (`return 0` on reject) — WavPack.pm:87-88.
  /// 2. `SetFileType` — WavPack.pm:89.
  /// 3. ProcessBinaryData over the WavPack::Main table — WavPack.pm:91-95.
  ///    The five header tags emit in numeric-key sort order
  ///    (ExifTool.pm:9907).
  /// 4. `Seek(0, 0)` + `RIFF::ProcessRIFF` — WavPack.pm:97-99
  ///    (Phase-2 forward item; RIFF parser not ported yet — observably
  ///    no-op on the committed fixtures).
  /// 5. APE-trailer chain: `APE::ProcessAPE` — WavPack.pm:100-102.
  ///    Routes through `crate::formats::ape::ProcessApe::process_trailer_only`
  ///    (the same entry the bundled audio loop uses recursively).
  ///    `ProcessApe::process_trailer_only` ALSO sets `done_ape`
  ///    (APE.pm:131); this matches the bundled flag-setting order. On
  ///    the committed fixtures (no APE trailer present) this is
  ///    observably no-op.
  pub(crate) fn process(&self, ctx: &mut ParseContext<'_>) -> bool {
    // Phase F5 bridge: extract the typed Meta from a fresh shared-flags
    // workspace, then sink it back into the legacy `Metadata` plumbing.
    // The lib-first `SharedFlags` is NOT the same store as the legacy
    // `Metadata::done_id3` / `Metadata::done_ape`; the legacy chained
    // parsers below read the latter, so we don't need to thread the
    // former through here.
    let meta_opt = {
      let data = ctx.data();
      parse_inner(data)
    };
    let Some(meta) = meta_opt else {
      return false; // WavPack.pm:87-88 reject — `return 0`.
    };

    // WavPack.pm:89 `$et->SetFileType()` — no-arg ⇒ detected file type ("WV").
    ctx.set_file_type(None, None, None);
    let print_conv = ctx.print_conv_enabled();

    // WavPack.pm:91-95 — sink the 5 header tags through the typed Meta.
    // Faithful to the ProcessBinaryData iteration order (numeric-key
    // sort) and the PrintConv / ValueConv toggle.
    {
      let mut bridge = MetadataTagWriter::new(ctx.metadata());
      let _: Result<(), Infallible> = meta.sink(print_conv, &mut bridge);
    }

    // WavPack.pm:96-103: `RIFF::ProcessRIFF` + `APE::ProcessAPE` trailers.
    // ----------------------------------------------------------------
    // WavPack.pm:97-99 `Seek(0, 0)` + `RIFF::ProcessRIFF` — RIFF parser
    // not ported yet (FORMATS.md row 22 forward item). On the committed
    // fixtures (no RIFF wrapper) this is observably no-op.
    //
    // WavPack.pm:100-103 `$$et{PATH}[-1] = 'APE'` then
    // `APE::ProcessAPE($et, $dirInfo)`. The bundled `ProcessAPE` itself
    // dispatches to `ProcessID3` first (APE.pm:122-127 — the embedded
    // ID3 arm). We invoke
    // [`crate::formats::ape::ProcessApe::process_trailer_only`], which
    // is the same entry the bundled audio loop uses recursively for
    // the "wrapper has already set FileType, just scan for trailer"
    // case. That entry:
    //   * does NOT re-run the embedded-ID3 dispatch (APE.pm:122-127);
    //     the bundled WavPack.pm DOES (the WavPack-level ProcessAPE
    //     call goes through APE.pm:119 which checks `unless ($$et{
    //     DoneID3})`). We need to drive the ID3 detection separately
    //     before the APE trailer.
    //   * DOES set `done_ape` (APE.pm:131) and scan for the APE-tag
    //     trailer at EOF / ID3v1-adjusted position.
    //
    // ID3 dispatch — bundled APE.pm:122-127 `unless ($$et{DoneID3}) {
    // require Image::ExifTool::ID3; Image::ExifTool::ID3::ProcessID3(
    // $et, $dirInfo) and return 1; }`. The `and return 1` only fires
    // when ProcessID3 succeeds AND we're in APE's own entry; in the
    // WavPack chain, after the WavPack header tags are already pushed,
    // hitting `return 1` from inside the APE call just means APE bails
    // out of its own MAC body scan — the WavPack-level `return 1`
    // (WavPack.pm:104) is unaffected. We model this faithfully via the
    // chained `process_id3_chained` entry.
    if ctx.metadata().done_id3().is_none() {
      let _ = crate::formats::id3::process::process_id3_chained(ctx);
    }
    let _ = crate::formats::ape::ProcessApe.process_trailer_only(ctx);

    true // WavPack.pm:104 `return 1`.
  }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{
    sink::{MapTagWriter, MapValue},
    value::{Metadata, TagValue},
  };

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

  // -------------------------------------------------------------------------
  // Typed enums
  // -------------------------------------------------------------------------

  #[test]
  fn audio_type_round_trip() {
    assert_eq!(AudioType::from_raw(0), AudioType::Stereo);
    assert_eq!(AudioType::from_raw(1), AudioType::Mono);
    assert_eq!(AudioType::Stereo.raw(), 0);
    assert_eq!(AudioType::Mono.raw(), 1);
    assert_eq!(AudioType::Stereo.print_conv(), "Stereo");
    assert_eq!(AudioType::Mono.print_conv(), "Mono");
  }

  #[test]
  fn compression_round_trip() {
    assert_eq!(Compression::from_raw(0), Compression::Lossless);
    assert_eq!(Compression::from_raw(1), Compression::Hybrid);
    assert_eq!(Compression::Lossless.raw(), 0);
    assert_eq!(Compression::Hybrid.raw(), 1);
    assert_eq!(Compression::Lossless.print_conv(), "Lossless");
    assert_eq!(Compression::Hybrid.print_conv(), "Hybrid");
  }

  #[test]
  fn data_format_round_trip() {
    assert_eq!(DataFormat::from_raw(0), DataFormat::Integer);
    assert_eq!(DataFormat::from_raw(1), DataFormat::FloatingPoint);
    assert_eq!(DataFormat::Integer.raw(), 0);
    assert_eq!(DataFormat::FloatingPoint.raw(), 1);
    assert_eq!(DataFormat::Integer.print_conv(), "Integer");
    assert_eq!(DataFormat::FloatingPoint.print_conv(), "Floating Point");
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
  // `FormatParser` trait + `WvContext`
  // -------------------------------------------------------------------------

  #[test]
  fn format_parser_trait_returns_borrowed_meta() {
    let data = header_with_flags(0x0480_008d);
    let mut shared = SharedFlags::new();
    let ctx = WvContext::new(&data, &mut shared);
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
    let ctx = WvContext::new(&data, &mut shared);
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
      let mut ctx = WvContext::new(&data, &mut shared);
      assert_eq!(ctx.shared().done_id3(), None);
      ctx.shared_mut().set_done_id3(128);
    }
    assert_eq!(shared.done_id3(), Some(128));
  }

  // -------------------------------------------------------------------------
  // `MetaSinker` — typed Meta → TagWriter (PrintConv on / off)
  // -------------------------------------------------------------------------

  fn collect(flags_le: u32, print_conv: bool) -> MapTagWriter {
    let data = header_with_flags(flags_le);
    let mut shared = SharedFlags::new();
    let ctx = WvContext::new(&data, &mut shared);
    let meta = <ProcessWv as FormatParser>::parse(&ProcessWv, ctx)
      .unwrap()
      .unwrap();
    let mut w = MapTagWriter::new();
    meta.sink(print_conv, &mut w).unwrap();
    w
  }

  #[test]
  fn sink_print_on_emits_fixture_strings() {
    let w = collect(0x0480_008d, true);
    let g = |n: &str| w.get("File", n).map(MapValue::as_str);
    assert_eq!(g("BytesPerSample"), Some("1".into()));
    assert_eq!(g("AudioType"), Some("Mono".into()));
    assert_eq!(g("Compression"), Some("Lossless".into()));
    assert_eq!(g("DataFormat"), Some("Integer".into()));
    assert_eq!(g("SampleRate"), Some("48000".into()));
  }

  #[test]
  fn sink_print_on_emits_adversarial_strings() {
    let w = collect(0xFFFF_FFFF, true);
    let g = |n: &str| w.get("File", n).map(MapValue::as_str);
    assert_eq!(g("BytesPerSample"), Some("4".into()));
    assert_eq!(g("AudioType"), Some("Mono".into()));
    assert_eq!(g("Compression"), Some("Hybrid".into()));
    assert_eq!(g("DataFormat"), Some("Floating Point".into()));
    assert_eq!(g("SampleRate"), Some("Custom".into()));
  }

  #[test]
  fn sink_print_off_emits_fixture_raw() {
    let w = collect(0x0480_008d, false);
    let g = |n: &str| w.get("File", n).map(MapValue::as_str);
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
    let g = |n: &str| w.get("File", n).map(MapValue::as_str);
    assert_eq!(g("BytesPerSample"), Some("4".into())); // raw=3 +1
    assert_eq!(g("AudioType"), Some("1".into()));
    assert_eq!(g("Compression"), Some("1".into()));
    assert_eq!(g("DataFormat"), Some("1".into()));
    assert_eq!(g("SampleRate"), Some("15".into())); // raw index 15
  }

  // -------------------------------------------------------------------------
  // Legacy `OldFormatParser` bridge — preserves CLI byte-exact JSON
  // -------------------------------------------------------------------------

  fn run_bridge(data: &[u8], print_on: bool) -> Metadata {
    let mut m = Metadata::new("WavPack.wv");
    let mut c = ParseContext::new(data, "WV", 0, "WV", None, print_on, &mut m);
    ProcessWv.process(&mut c);
    m
  }

  #[test]
  fn bridge_fixture_round_trip_print_on() {
    let data = header_with_flags(0x0480_008d);
    let m = run_bridge(&data, true);
    let by_name = |n: &str| {
      m.tags()
        .iter()
        .find(|t| t.name() == n)
        .map(|t| t.value().clone())
    };
    assert_eq!(by_name("FileType"), Some(TagValue::Str("WV".into())));
    assert_eq!(by_name("BytesPerSample"), Some(TagValue::I64(1)));
    assert_eq!(by_name("AudioType"), Some(TagValue::Str("Mono".into())));
    assert_eq!(
      by_name("Compression"),
      Some(TagValue::Str("Lossless".into()))
    );
    assert_eq!(by_name("DataFormat"), Some(TagValue::Str("Integer".into())));
    assert_eq!(by_name("SampleRate"), Some(TagValue::I64(48000)));
  }

  #[test]
  fn bridge_fixture_round_trip_print_off() {
    let data = header_with_flags(0x0480_008d);
    let m = run_bridge(&data, false);
    let by_name = |n: &str| {
      m.tags()
        .iter()
        .find(|t| t.name() == n)
        .map(|t| t.value().clone())
    };
    assert_eq!(by_name("BytesPerSample"), Some(TagValue::I64(1)));
    assert_eq!(by_name("AudioType"), Some(TagValue::I64(1)));
    assert_eq!(by_name("Compression"), Some(TagValue::I64(0)));
    assert_eq!(by_name("DataFormat"), Some(TagValue::I64(0)));
    assert_eq!(by_name("SampleRate"), Some(TagValue::I64(10)));
  }

  #[test]
  fn bridge_adversarial_round_trip_print_on() {
    let data = header_with_flags(0xFFFF_FFFF);
    let m = run_bridge(&data, true);
    let by_name = |n: &str| {
      m.tags()
        .iter()
        .find(|t| t.name() == n)
        .map(|t| t.value().clone())
    };
    assert_eq!(by_name("BytesPerSample"), Some(TagValue::I64(4)));
    assert_eq!(by_name("AudioType"), Some(TagValue::Str("Mono".into())));
    assert_eq!(by_name("Compression"), Some(TagValue::Str("Hybrid".into())));
    assert_eq!(
      by_name("DataFormat"),
      Some(TagValue::Str("Floating Point".into()))
    );
    assert_eq!(by_name("SampleRate"), Some(TagValue::Str("Custom".into())));
  }

  #[test]
  fn bridge_rejects_short() {
    let mut m = Metadata::new("WavPack.wv");
    let data = vec![0u8; 16];
    let mut c = ParseContext::new(&data, "WV", 0, "WV", None, true, &mut m);
    assert!(!ProcessWv.process(&mut c));
    assert!(m.tags().is_empty()); // no SetFileType run
  }

  #[test]
  fn bridge_rejects_bad_magic() {
    let mut m = Metadata::new("WavPack.wv");
    let mut data = vec![0u8; 32];
    data[..4].copy_from_slice(b"WVPK");
    let mut c = ParseContext::new(&data, "WV", 0, "WV", None, true, &mut m);
    assert!(!ProcessWv.process(&mut c));
    assert!(m.tags().is_empty());
  }

  #[test]
  fn bridge_rejects_bad_version_byte_8() {
    let mut m = Metadata::new("WavPack.wv");
    let mut data = vec![0u8; 32];
    data[..4].copy_from_slice(b"wvpk");
    data[8] = 0x05;
    data[9] = 0x04;
    let mut c = ParseContext::new(&data, "WV", 0, "WV", None, true, &mut m);
    assert!(!ProcessWv.process(&mut c));
    assert!(m.tags().is_empty());
  }

  #[test]
  fn bridge_rejects_bad_version_byte_9() {
    let mut m = Metadata::new("WavPack.wv");
    let mut data = vec![0u8; 32];
    data[..4].copy_from_slice(b"wvpk");
    data[8] = 0x10;
    data[9] = 0x05;
    let mut c = ParseContext::new(&data, "WV", 0, "WV", None, true, &mut m);
    assert!(!ProcessWv.process(&mut c));
    assert!(m.tags().is_empty());
  }

  #[test]
  fn bridge_accepts_version_byte_02() {
    let mut data = header_with_flags(0);
    data[8] = 0x02;
    let m = run_bridge(&data, true);
    assert!(m.tags().iter().any(|t| t.name() == "FileType"));
    assert!(m.tags().iter().any(|t| t.name() == "BytesPerSample"));
  }

  #[test]
  fn bridge_emits_tags_in_expected_order() {
    // ExifTool.pm:9907 numeric sort ⇒ 6.1, 6.2, 6.3, 6.4, 6.5. After
    // SetFileType pushes the File:* triplet, the bridge sinks the 5
    // WavPack tags in that order. The chained ID3 + APE trailer
    // entries emit nothing on the fixture (no ID3 / no APE trailer).
    let data = header_with_flags(0x0480_008d);
    let m = run_bridge(&data, true);
    let names: std::vec::Vec<&str> = m.tags().iter().map(|t| t.name()).collect();
    assert_eq!(
      names,
      vec![
        "FileType",
        "FileTypeExtension",
        "MIMEType",
        "BytesPerSample",
        "AudioType",
        "Compression",
        "DataFormat",
        "SampleRate",
      ]
    );
  }

  #[test]
  fn bridge_marks_done_ape_after_running() {
    // APE.pm:131 `$$et{DoneAPE} = 1` runs INSIDE `process_trailer_only`,
    // regardless of whether an APE trailer is actually present. Pin
    // that the WavPack chain drives the flag.
    let data = header_with_flags(0x0480_008d);
    let m = run_bridge(&data, true);
    assert!(m.done_ape());
  }
}
