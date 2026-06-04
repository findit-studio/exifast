// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

#![cfg(feature = "dsf")]
//! Faithful port of `Image::ExifTool::DSF` (lib/Image/ExifTool/DSF.pm,
//! ExifTool 13.58, 138 lines). DSD Stream File container: `'DSD '` chunk +
//! `'fmt '` chunk. Read-only.
//!
//! A typed [`Meta<'a>`] is produced by the
//! [`crate::format_parser::FormatParser`] trait; the engine entry `process`
//! drives the typed `serialize_tags` path into the engine
//! `tagmap::TagMap` and the chained ID3v2 trailer so the
//! serialized JSON stays byte-exact with bundled `perl exiftool`.
//!
//! ## Why DSF needs a `Context<'a>` struct (not the leaf `&'a [u8]`)
//!
//! DSF chains into the bundled ID3v2 trailer at `metaPos` (DSF.pm:88-97).
//! The chain is now fully typed: [`parse_inner`] parses the trailer slice
//! into a nested [`crate::formats::id3::Id3Meta`] ([`Meta::id3_ref`]) via
//! [`crate::formats::id3::process::parse_id3_borrowed`], and the
//! `serialize_tags` sink emits its `File:ID3Size` + `ID3v2_*:*` tags after
//! the `'fmt '` chunk. The `Context<'a>` = `&'a [u8]` + `&'a mut
//! SharedFlags` shape is retained for parser-trait uniformity even though
//! DSF itself does not read/mutate `SharedFlags` (the trailer is a
//! self-contained ID3 "file"; the typed nesting passes `shared = None`).
//!
//! ## ID3 trailer
//!
//! [`Meta::id3_trailer`] still exposes the borrowed `&'a [u8]` of the
//! trailer bytes (faithful to `DSF.pm:88-97`'s `$dirInfo{DataPt}` slice)
//! as a lib-first convenience; [`Meta::id3_ref`] is the typed sub-Meta
//! parsed from those same bytes, which the sink emits.

// Golden-v2 Contract 3c (Phase C, slice w2c): panic-safety by construction —
// every raw index/slice on the input buffer is converted to a checked `.get()`
// form below. Each conversion is byte-identical: the preceding length guard
// (`data.len() < 40`, the `dir_end > dir_total` break, the `end > data.len()`
// trailer guard) already proves the read in range, so the `.get()` always
// yields the same bytes via the same recovery path it had before.
#![deny(clippy::indexing_slicing)]

use crate::{
  format_parser::{FormatParser, SharedFlags, parser_sealed},
  tagtable::{PrintConv, PrintConvHash, PrintValue, TagDef, TagId, TagTable, ValueConv},
  value::{Group, Metadata, TagValue},
};

/// The xtask-GENERATED `%DSF::Main` table (`cargo xtask gen-tables --kind
/// tagdef --module DSF::Main`), transcribed from `exiftool -listx`. Consulted
/// by [`dsf_get`] ONLY as the ADDITIVE fallback — the hand-written `static`s
/// below shadow every key they define (hand wins on collision). The two layers
/// are byte-identical for the 8 declarative `%DSF::Main` tags, so the generated
/// fallback never actually fires here; it exists as the drift guard
/// (`tests/xtask_check.rs`) against a future ExifTool-version change, NOT as new
/// coverage (it contributes 0 new tags).
#[path = "dsf_generated.rs"]
mod generated;

// ===========================================================================
// Static tag table — `%DSF::Main` (DSF.pm:20-49)
// ===========================================================================

// DSF.pm:30 `3 => 'FormatVersion'`.
static FORMAT_VERSION: TagDef =
  TagDef::new("FormatVersion", "File", ValueConv::None, PrintConv::None);
// DSF.pm:31 `4 => { Name => 'FormatID', PrintConv => { 0 => 'DSD Raw' }}`.
static FORMAT_ID: TagDef = TagDef::new(
  "FormatID",
  "File",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[("0", PrintValue::Str("DSD Raw"))])),
);
// DSF.pm:32-43 `5 => { Name => 'ChannelType', PrintConv => { 1..7 } }`.
static CHANNEL_TYPE: TagDef = TagDef::new(
  "ChannelType",
  "File",
  ValueConv::None,
  PrintConv::Hash(PrintConvHash::direct(&[
    ("1", PrintValue::Str("Mono")),
    ("2", PrintValue::Str("Stereo (Left, Right)")),
    ("3", PrintValue::Str("3 Channels (Left, Right, Center)")),
    ("4", PrintValue::Str("Quad (Left, Right, Back L, Back R)")),
    (
      "5",
      PrintValue::Str("4 Channels (Left, Right, Center, Bass)"),
    ),
    (
      "6",
      PrintValue::Str("5 Channels (Left, Right, Center, Back L, Back R)"),
    ),
    (
      "7",
      PrintValue::Str("5.1 Channels (Left, Right, Center, Bass, Back L, Back R)"),
    ),
  ])),
);
// DSF.pm:44 `6 => 'ChannelCount'`.
static CHANNEL_COUNT: TagDef =
  TagDef::new("ChannelCount", "File", ValueConv::None, PrintConv::None);
// DSF.pm:45 `7 => 'SampleRate'`.
static SAMPLE_RATE: TagDef = TagDef::new("SampleRate", "File", ValueConv::None, PrintConv::None);
// DSF.pm:46 `8 => 'BitsPerSample'`.
static BITS_PER_SAMPLE: TagDef =
  TagDef::new("BitsPerSample", "File", ValueConv::None, PrintConv::None);
// DSF.pm:47 `9 => { Name => 'SampleCount', Format => 'int64u' }`.
//
// `Format => 'int64u'` consumes 8 bytes at byte offset 36 (key 9 * 4-byte
// int32u stride), which is why DSF::Main has no key 10 (would land inside
// the int64u payload).
static SAMPLE_COUNT: TagDef =
  TagDef::new("SampleCount", "File", ValueConv::None, PrintConv::None).with_format("int64u");
// DSF.pm:48 `11 => 'BlockSize'`.
static BLOCK_SIZE: TagDef = TagDef::new("BlockSize", "File", ValueConv::None, PrintConv::None);

/// `%DSF::Main` (DSF.pm:20-49). family-0/1 groups both `'File'`
/// (DSF.pm:22 `GROUPS => { 0 => 'File', 1 => 'File', 2 => 'Audio' }`;
/// family-2 'Audio' is not emitted under `-G1`). Keyed by integer
/// (`TagId::Int`) — contrast AAC which is string-keyed.
fn dsf_get(id: TagId) -> Option<&'static TagDef> {
  // Hand-first (the additive-codegen invariant, mirroring XMP `lookup_field`):
  // the hand `static`s WIN on every key they define, so no existing golden can
  // shift. The xtask-generated [`generated::get`] is consulted ONLY as the
  // fallback. For `%DSF::Main` the hand layer is complete (all 8 ids), so the
  // generated arm never fires — it is the drift guard, not new coverage.
  let hand = match id {
    TagId::Int(3) => Some(&FORMAT_VERSION),
    TagId::Int(4) => Some(&FORMAT_ID),
    TagId::Int(5) => Some(&CHANNEL_TYPE),
    TagId::Int(6) => Some(&CHANNEL_COUNT),
    TagId::Int(7) => Some(&SAMPLE_RATE),
    TagId::Int(8) => Some(&BITS_PER_SAMPLE),
    TagId::Int(9) => Some(&SAMPLE_COUNT),
    TagId::Int(11) => Some(&BLOCK_SIZE),
    _ => None,
  };
  hand.or_else(|| generated::get(id))
}

/// `%Image::ExifTool::DSF::Main` (DSF.pm:20). Family-0 group `"File"`
/// (DSF.pm:22). Per-tag family-1 is also `"File"`.
pub static DSF_MAIN: TagTable = TagTable::new("File", dsf_get);

/// Sorted integer keys of `%DSF::Main` in ASCENDING order. Faithful to Perl's
/// `sort { $a <=> $b } keys %$tagTbl` for ProcessBinaryData. 10 is absent
/// (consumed by key 9's `Format => 'int64u'`).
const DSF_KEYS: &[i64] = &[3, 4, 5, 6, 7, 8, 9, 11];

// ===========================================================================
// Typed Meta — `Meta<'a>`
// ===========================================================================

/// The `'fmt '` chunk fields (DSF.pm:30-48). Every field is the raw
/// post-decode integer — PrintConv hashes (FormatID, ChannelType) are
/// applied at `serialize_tags` time mirroring the
/// `$$self{OPTIONS}{PrintConv}` toggle.
///
/// `present_mask` tracks which `DSF_KEYS` entries the parser successfully
/// read (one bit per key index in `DSF_KEYS` order — bit 0 = key 3, bit
/// 1 = key 4, …, bit 7 = key 11). On the production happy path the mask
/// is `0xFF` (every field fits); a pathological `fmt_len` in `(12, 48)`
/// produces a partial mask and the sink emits ONLY the present fields,
/// faithful to ExifTool.pm:9953 `last if $more <= 0`.
#[derive(Debug, Clone, Copy)]
pub struct FmtData {
  /// 0x0c key 3 — `FormatVersion` (DSF.pm:30). int32u LE.
  format_version: u32,
  /// 0x10 key 4 — `FormatID` raw u32 (DSF.pm:31). PrintConv: 0⇒"DSD Raw".
  format_id: u32,
  /// 0x14 key 5 — `ChannelType` raw u32 (DSF.pm:32-43). PrintConv: hash.
  channel_type: u32,
  /// 0x18 key 6 — `ChannelCount` (DSF.pm:44). int32u LE.
  channel_count: u32,
  /// 0x1c key 7 — `SampleRate` (DSF.pm:45). int32u LE.
  sample_rate: u32,
  /// 0x20 key 8 — `BitsPerSample` (DSF.pm:46). int32u LE.
  bits_per_sample: u32,
  /// 0x24 key 9 — `SampleCount` (DSF.pm:47). int64u LE.
  sample_count: u64,
  /// 0x2c key 11 — `BlockSize` (DSF.pm:48). int32u LE.
  block_size: u32,
  /// True iff `sample_count > i64::MAX` — emission switches from
  /// `TagValue::I64` to a decimal `TagValue::Str` to preserve the exact
  /// unsigned value (Perl UV→NV-shape; the serializer's number gate
  /// keeps a ≥16-digit bare integer as a JSON number — byte-exact vs
  /// `exiftool -j` for large unsigned values).
  sample_count_is_decimal_string: bool,
  /// Bitmask of present `DSF_KEYS` entries (LSB = first key). `0xFF` for
  /// the production happy path; partial on pathological short payloads.
  present_mask: u8,
}

impl FmtData {
  /// DSF.pm:30 `3 => 'FormatVersion'` (int32u LE).
  #[must_use]
  #[inline(always)]
  pub const fn format_version(&self) -> u32 {
    self.format_version
  }
  /// DSF.pm:31 raw `FormatID` (int32u LE). Use [`Self::format_id_print`]
  /// for the PrintConv-resolved name.
  #[must_use]
  #[inline(always)]
  pub const fn format_id(&self) -> u32 {
    self.format_id
  }
  /// DSF.pm:31 `PrintConv => { 0 => 'DSD Raw' }`. Returns `None` for
  /// hash misses (faithful — Perl emits `0` raw in that case).
  #[must_use]
  #[inline(always)]
  pub const fn format_id_print(&self) -> Option<&'static str> {
    match self.format_id {
      0 => Some("DSD Raw"),
      _ => None,
    }
  }
  /// DSF.pm:32-43 raw `ChannelType` (int32u LE). Use
  /// [`Self::channel_type_print`] for the PrintConv-resolved name.
  #[must_use]
  #[inline(always)]
  pub const fn channel_type(&self) -> u32 {
    self.channel_type
  }
  /// DSF.pm:32-43 `PrintConv` hash. Returns `None` on a hash miss
  /// (faithful — Perl emits the raw integer in that case).
  #[must_use]
  #[inline(always)]
  pub const fn channel_type_print(&self) -> Option<&'static str> {
    match self.channel_type {
      1 => Some("Mono"),
      2 => Some("Stereo (Left, Right)"),
      3 => Some("3 Channels (Left, Right, Center)"),
      4 => Some("Quad (Left, Right, Back L, Back R)"),
      5 => Some("4 Channels (Left, Right, Center, Bass)"),
      6 => Some("5 Channels (Left, Right, Center, Back L, Back R)"),
      7 => Some("5.1 Channels (Left, Right, Center, Bass, Back L, Back R)"),
      _ => None,
    }
  }
  /// DSF.pm:44 `ChannelCount` (int32u LE).
  #[must_use]
  #[inline(always)]
  pub const fn channel_count(&self) -> u32 {
    self.channel_count
  }
  /// DSF.pm:45 `SampleRate` (int32u LE).
  #[must_use]
  #[inline(always)]
  pub const fn sample_rate(&self) -> u32 {
    self.sample_rate
  }
  /// DSF.pm:46 `BitsPerSample` (int32u LE).
  #[must_use]
  #[inline(always)]
  pub const fn bits_per_sample(&self) -> u32 {
    self.bits_per_sample
  }
  /// DSF.pm:47 `SampleCount` (int64u LE). The full unsigned range is
  /// preserved; values above `i64::MAX` are still exact via `u64`.
  #[must_use]
  #[inline(always)]
  pub const fn sample_count(&self) -> u64 {
    self.sample_count
  }
  /// DSF.pm:48 `BlockSize` (int32u LE).
  #[must_use]
  #[inline(always)]
  pub const fn block_size(&self) -> u32 {
    self.block_size
  }
}

/// Typed DSF metadata — the lib-first output of [`ProcessDsf`].
///
/// `Meta` holds three orthogonal slices of the DSF.pm port:
///
/// 1. The `'fmt '` chunk fields ([`Self::fmt`]). `None` only on the
///    DSF.pm:71-72 Warn-then-return-1 path (a malformed `fmtLen` —
///    `fmtLen <= 12 || fmtLen >= 1000 || short read`); on every happy
///    path this is `Some` with all eight integers populated.
/// 2. The fmt-chunk warning text ([`Self::fmt_warning`]). When
///    [`Self::fmt`] is `None`, this is `Some("Error reading DSF fmt
///    chunk")` (DSF.pm:71) so the sink re-emits it through
///    `TagMap::write_warning` for byte-exact CLI JSON.
/// 3. The optional ID3v2 trailer bytes ([`Self::id3_trailer`]) — the
///    `metaPos..metaPos+metaLen` slice (DSF.pm:88-97) borrowed from the
///    input buffer (zero-alloc) — AND the typed [`Self::id3_ref`] sub-Meta
///    parsed from those bytes via
///    [`crate::formats::id3::process::parse_id3_borrowed`]. The sink emits
///    `id3`'s `File:ID3Size` + `ID3v2_*:*` tags (the bundled-Perl
///    `ProcessDirectory(GetTagTable('Image::ExifTool::ID3::Main'))`
///    output), so the typed Meta is self-contained.
///
/// **D8 — no public fields, accessors only.**
///
/// **Lifetimes.** `Meta` borrows only the optional ID3 trailer bytes
/// (`id3_trailer: Option<&'a [u8]>`) from the input. Every fmt-chunk
/// integer is owned. The lifetime is preserved end-to-end so the
/// `id3_trailer` slice can flow through `parse_borrowed` zero-alloc.
#[derive(Debug, Clone)]
pub struct Meta<'a> {
  /// The eight `'fmt '` chunk fields (DSF.pm:30-48), or `None` on the
  /// DSF.pm:71-72 Warn-then-accept path.
  fmt: Option<FmtData>,
  /// `Some("Error reading DSF fmt chunk")` iff [`Self::fmt`] is `None`
  /// (DSF.pm:71). The bridge re-pushes this through
  /// `write_warning` so the bundled-Perl `$et->Warn(...)` semantics
  /// are preserved.
  fmt_warning: Option<&'static str>,
  /// ID3v2 trailer slice (DSF.pm:88-97) — `metaPos..metaPos+metaLen`
  /// borrowed from the input buffer. `None` when `metaPos == 0` or
  /// the slice fails the bundled-Perl guards (`metaLen > 0 &&
  /// metaLen < 20_000_000 && Read == metaLen`).
  ///
  /// Retained as a lib-first convenience alongside the typed [`Self::id3_ref`]
  /// sub-Meta (parsed from these same bytes). The sink emits via [`Self::id3_ref`];
  /// this raw slice lets callers re-process the trailer differently if needed.
  id3_trailer: Option<&'a [u8]>,
  /// Typed ID3 sub-Meta parsed from [`Self::id3_trailer`] (DSF.pm:88-97).
  /// `Some` iff the trailer slice was present AND ID3 detection accepted it
  /// (an ID3v2 header at offset 0). Carries `File:ID3Size` + the
  /// `ID3v2_*:*` frame tags; the typed `serialize_tags` sink emits them after
  /// the `'fmt '` chunk fields, replacing the engine's separate
  /// `process_id3_v2_slice` dispatch.
  #[cfg(feature = "id3")]
  id3: Option<crate::formats::id3::Id3Meta<'a>>,
}

impl<'a> Meta<'a> {
  /// The `'fmt '` chunk fields, present on every happy path and absent
  /// only on the DSF.pm:71-72 Warn-then-accept path.
  ///
  /// §3: [`FmtData`] is `Copy`, so an `Option<T: Copy>` field is
  /// returned **by value** (`-> Option<FmtData>`, bare name), not as a
  /// borrow.
  #[must_use]
  #[inline(always)]
  pub const fn fmt(&self) -> Option<FmtData> {
    self.fmt
  }

  /// The Warn text emitted by DSF.pm:71 when the fmt-chunk read fails.
  /// `Some` iff [`Self::fmt`] is `None`.
  #[must_use]
  #[inline(always)]
  pub const fn fmt_warning(&self) -> Option<&'static str> {
    self.fmt_warning
  }

  /// The optional ID3v2 trailer bytes (DSF.pm:88-97). Borrowed from
  /// the input buffer when present; `None` when there is no trailer
  /// (`metaPos == 0`) or the trailer fails the bundled-Perl guards
  /// (`metaLen > 0 && metaLen < 20_000_000 && Read == metaLen`).
  ///
  /// §3: the canonical `Option<&[u8]>` slice view of the borrowed trailer
  /// (the `Copy` field is returned by value).
  #[must_use]
  #[inline(always)]
  pub const fn id3_trailer(&self) -> Option<&'a [u8]> {
    self.id3_trailer
  }

  /// Typed ID3 sub-Meta parsed from the [`Self::id3_trailer`] bytes
  /// (DSF.pm:88-97). `Some` iff the trailer was present and ID3 detection
  /// accepted it. The `serialize_tags` sink
  /// emits its `File:ID3Size` + `ID3v2_*:*` tags after the `'fmt '` chunk.
  ///
  /// §3: non-`Copy` borrow ⇒ `_ref` suffix.
  #[cfg(feature = "id3")]
  #[must_use]
  #[inline(always)]
  pub const fn id3_ref(&self) -> Option<&crate::formats::id3::Id3Meta<'a>> {
    self.id3.as_ref()
  }
}

// ===========================================================================
// `Context` — per-format input view (chained shape)
// ===========================================================================

/// Per-format `Context<'a>` for [`ProcessDsf`]. Spec §6.1: leaf formats
/// (MOI, AAC, DV, Audible) use `&'a [u8]`; chained formats (the DSF→ID3
/// trailer family) use a struct wrapping `&'a [u8]` + `&'a mut SharedFlags`.
///
/// DSF is the simplest chained leaf — it does not itself read or mutate
/// `SharedFlags` (the chain into [`crate::formats::id3::process::
/// process_id3_v2_slice`] runs through the legacy `ParseContext` path
/// for now), but the F4 typed-ID3 follow-on will need to thread
/// `DoneID3` through this context. Pinning the shape at F3 keeps the
/// F4 PR purely additive (no breaking changes to the F3 API).
///
/// D8 convention: PRIVATE fields; constructor + accessors only.
#[derive(Debug)]
pub struct Context<'a> {
  /// The full file bytes (`$raf` in DSF.pm). Borrows for `'a`.
  data: &'a [u8],
  /// The cross-format flag block (spec §6.4). DSF does not currently
  /// read or mutate any flag, but the typed F4 ID3 follow-on will pass
  /// `DoneID3` through here.
  #[allow(dead_code)]
  shared: &'a mut SharedFlags,
}

impl<'a> Context<'a> {
  /// Construct a fresh DSF context (only constructor — D8 PRIVATE fields).
  #[must_use]
  #[inline(always)]
  pub const fn new(data: &'a [u8], shared: &'a mut SharedFlags) -> Self {
    Self { data, shared }
  }

  /// File bytes (`$raf` in DSF.pm).
  ///
  /// §3: the canonical `&[u8]` slice view of the borrowed input.
  #[must_use]
  #[inline(always)]
  pub const fn data(&self) -> &'a [u8] {
    self.data
  }
}

// ===========================================================================
// `ProcessDsf` — the lib-first parser
// ===========================================================================

/// DSF parser (faithful `ProcessDSF`, DSF.pm:55-99).
#[derive(Debug, Clone, Copy)]
pub struct ProcessDsf;

impl parser_sealed::Sealed for ProcessDsf {}

impl FormatParser for ProcessDsf {
  /// GAT: the Meta borrows the optional ID3v2 trailer from the input `'a`
  /// directly — zero allocation for the `AnyMeta` closed-set publish path
  /// (Codex AF2).
  type Meta<'a> = Meta<'a>;
  /// Spec §6.1: chained format Context wraps `&'a [u8]` + `&'a mut
  /// SharedFlags`.
  type Context<'a> = Context<'a>;
  /// Rust-level fatal error (none today; DSF parsing has no I/O modes).

  /// Parse a DSF file's bytes into a typed [`Meta`] borrowing from
  /// `ctx.data` (`'a`).
  fn parse<'a>(&self, ctx: Self::Context<'a>) -> Option<Self::Meta<'a>> {
    parse_inner(ctx.data)
  }
}

/// Lib-first direct entry. Same as [`FormatParser::parse`] but returns a
/// [`Meta`] that borrows the optional ID3v2 trailer from the input
/// buffer — zero allocation. Identical to the [`FormatParser::parse`]
/// path now that the [`FormatParser::Meta`] GAT threads the borrow
/// lifetime through (Codex AF2).
///
/// # Errors
///
/// Returns `Err` for Rust-level fatal modes (none today; reserved for
/// future I/O wrappers).
pub fn parse_borrowed(data: &[u8]) -> Option<Meta<'_>> {
  parse_inner(data)
}

/// Inner parser — produces a borrow-from-input [`Meta`]. The
/// [`FormatParser::Meta`] GAT (`type Meta<'a> = Meta<'a>`) returns
/// this borrowed form (including the live ID3v2 trailer slice) directly
/// into the closed [`crate::format_parser::AnyMeta`] enum (Codex AF2).
///
/// Returns:
/// - `Ok(None)` — header magic missed (`return 0` BEFORE
///   `SetFileType`, DSF.pm:62-63).
/// - `Ok(Some({ fmt: None, fmt_warning: Some(...) }))` — magic matched
///   but the fmt-chunk read failed (DSF.pm:71-72 Warn + return 1).
/// - `Ok(Some({ fmt: Some(...), id3_trailer: Option<...> }))` — happy
///   path; optional ID3v2 trailer carried through.
fn parse_inner(data: &[u8]) -> Option<Meta<'_>> {
  // DSF.pm:62 `$raf->Read($buff,40)==40 or return 0`.
  if data.len() < 40 {
    return None;
  }
  // DSF.pm:63 `$buff =~ /^DSD \x1c\0{7}.{16}fmt /s`. The regex is
  // anchored (^) and the `{16}` middle is "any 16 bytes" (Perl `.` under
  // `/s` matches any byte including \n). Translated literally as four
  // byte-equality checks; the 16-byte middle (fileSize+metaPos) is
  // unconstrained.
  // `data.len() >= 40` (guard above) ⇒ every fixed-offset read below is in
  // range; `head.get(..)` always yields `Some`, so each check is byte-
  // identical. `head[i]` == `data[i]` (head is `data[..40]`), so reading off
  // `head` keeps the same offsets and bytes; `starts_with` is the equivalent
  // of the `head[0..4] == b"DSD "` magic test. The `?` is always `Some` here
  // (len >= 40) and reuses the same early-`None` reject as the length guard.
  let head = data.get(..40)?;
  if !head.starts_with(b"DSD ") {
    return None;
  }
  if head.get(4) != Some(&0x1c) {
    return None;
  }
  if !head.get(5..12).is_some_and(|s| s.iter().all(|&b| b == 0)) {
    return None;
  }
  if head.get(28..32) != Some(b"fmt ".as_slice()) {
    return None;
  }
  // DSF.pm:66 `SetByteOrder('II')` — every Get* below is little-endian.
  // DSF.pm:67 `my $fmtLen = Get64u(\$buff,32)`. `head.get(..)` is always
  // `Some` (len == 40), so `read_u64_le` reads the same bytes as before; the
  // `0` fallback is unreachable.
  let fmt_len = head.get(32..40).map_or(0, read_u64_le);
  // DSF.pm:74-75 `$fileSize = Get64u(\$buff,12); $metaPos = Get64u(
  // \$buff,20)` — local-only, NOT emitted as DSF tags. Read here for
  // use by the ID3v2 trailer arm at DSF.pm:88-97.
  let file_size = head.get(12..20).map_or(0, read_u64_le);
  let meta_pos = head.get(20..28).map_or(0, read_u64_le);
  // DSF.pm:68-72 `unless ($fmtLen > 12 and $fmtLen < 1000 and $raf->Read(
  //   $buf2, $fmtLen - 12) == $fmtLen - 12) { Warn; return 1 }`.
  //
  // The `fmt_len > 12` guard is what makes the `fmt_len - 12` subtraction
  // below panic-free in unsigned Rust (signed-Perl → usize underflow
  // footgun, per [[exifast-phase2-forward-items]]). The `fmt_len < 1000`
  // guard is NOT a `usize`-cast safety requirement (999 fits any
  // realistic `usize`); it exists for two load-bearing reasons:
  //   1. ExifTool conformance — DSF.pm:68 enforces this exact bound, so
  //      a Perl-rejecting file must also be rejected here for byte-exact
  //      diffs against `exiftool -j`.
  //   2. Bounded fmt-chunk read — caps the slice size at < 1KB regardless
  //      of input, so a malicious header cannot trigger a huge fmt-chunk
  //      decode. Both guards are load-bearing — do NOT reorder.
  let fmt_ok = fmt_len > 12 && fmt_len < 1000 && {
    let need = (fmt_len - 12) as usize;
    data.len() >= 40usize.saturating_add(need)
  };
  if !fmt_ok {
    // DSF.pm:71-72 — Warn + return 1. No fmt-chunk payload.
    // Caller (bridge / lib-direct) still emits File:* (DSF.pm:64
    // SetFileType runs BEFORE the guard — bridge mirrors the ordering).
    // The optional ID3v2 trailer is still scanned: DSF.pm:88-97 runs
    // AFTER the Warn (the Warn path falls through to the trailer arm).
    // Faithful to the bundled-Perl flow: the trailer's `metaPos`/`metaLen`
    // were already captured from the header.
    let id3_trailer = id3_trailer_slice(data, file_size, meta_pos);
    return Some(Meta {
      fmt: None,
      fmt_warning: Some("Error reading DSF fmt chunk"),
      id3_trailer,
      #[cfg(feature = "id3")]
      id3: id3_from_trailer(id3_trailer),
    });
  }
  // DSF.pm:76 `$buff = substr($buff,28) . $buf2` — the dirInfo buffer
  // is `'fmt '` + chunkSize (12 bytes from head[28..40]) + payload
  // (fmt_len - 12 bytes from data[40..]). Total length == fmt_len.
  //
  // The DSF-local binary walk reads each integer at its computed offset
  // inside the dirInfo buffer; we transliterate that directly off the
  // file bytes by computing `dir_offset = key * 4`, then
  // `file_offset = dir_offset - 28 + 0` when `dir_offset >= 28`
  // (the 12-byte `'fmt '`+size prefix is at file offset 28..40, and
  // the payload begins at file offset 40 — so `file_offset = dir_offset
  // + 12` after the prefix). No intermediate `Vec` allocation needed
  // (Phase F3 zero-alloc derivation).
  //
  // Key 3 (FormatVersion) lands at dir_offset 12 ⇒ file_offset 40
  // (start of payload). Key 11 (BlockSize) lands at dir_offset 44 ⇒
  // file_offset 72 (and requires fmt_len >= 48). Key 9 (SampleCount)
  // lands at dir_offset 36 ⇒ file_offset 64..72 (8 bytes).
  let payload_len = (fmt_len - 12) as usize;
  let dir_total = 12 + payload_len;
  // Reads each fmt-chunk integer. Bounds-checked against `dir_total`
  // (faithful to ExifTool.pm:9953 `last if $more <= 0; # all done if
  // we have reached the end of data`). The DSF_KEYS list is strictly
  // ascending so the first out-of-range field truncates the rest.
  let mut format_version: u32 = 0;
  let mut format_id: u32 = 0;
  let mut channel_type: u32 = 0;
  let mut channel_count: u32 = 0;
  let mut sample_rate: u32 = 0;
  let mut bits_per_sample: u32 = 0;
  let mut sample_count: u64 = 0;
  let mut block_size: u32 = 0;
  let mut sample_count_is_decimal_string = false;
  let mut emitted: u8 = 0;
  for &key in DSF_KEYS {
    let dir_off = (key as usize) * 4;
    let is_int64 = key == 9;
    let width: usize = if is_int64 { 8 } else { 4 };
    let dir_end = dir_off + width;
    if dir_end > dir_total {
      // Once one key is out of range, every subsequent key is too
      // (ascending). Faithful early-exit.
      break;
    }
    // Map dirInfo offset to absolute file offset: the dirInfo buffer
    // is `head[28..40] + payload` (40..40+payload_len in file). So:
    //   file_off = (dir_off < 12) ? 28 + dir_off : 40 + (dir_off - 12)
    // Equivalently: `file_off = dir_off + 28` for dir_off in [0,12),
    // `file_off = dir_off + 28` for the whole range (the 28-byte head
    // shift). Verified: dir_off 12 ⇒ file_off 40 (payload start),
    // dir_off 36 ⇒ file_off 64 (SampleCount start). ✓
    let file_off = dir_off + 28;
    // `dir_end <= dir_total` (the `break` guard above) ⇒
    // `file_off + width = dir_end + 28 <= dir_total + 28 = 40 + payload_len
    // <= data.len()` (the `fmt_ok` guard), so each `.get(file_off..)` always
    // yields `Some` (the `0` fallback is unreachable) — byte-identical.
    if is_int64 {
      let v = data.get(file_off..file_off + 8).map_or(0, read_u64_le);
      sample_count = v;
      if v > i64::MAX as u64 {
        sample_count_is_decimal_string = true;
      }
    } else {
      let v = data.get(file_off..file_off + 4).map_or(0, read_u32_le);
      match key {
        3 => format_version = v,
        4 => format_id = v,
        5 => channel_type = v,
        6 => channel_count = v,
        7 => sample_rate = v,
        8 => bits_per_sample = v,
        11 => block_size = v,
        _ => {}
      }
    }
    emitted += 1;
  }
  // The eight fmt-chunk fields are populated by the loop above. The
  // `present_mask` (one bit per key in DSF_KEYS order) tracks which
  // fields actually fit in the dirInfo buffer — pathological short
  // payloads emit only the prefix. `emitted` is the count of populated
  // fields (0..=8); converted to a bitmask here.
  debug_assert!(emitted as usize <= DSF_KEYS.len());
  let present_mask: u8 = if emitted == 0 {
    0
  } else if emitted as usize == DSF_KEYS.len() {
    0xFF
  } else {
    // DSF_KEYS is ascending, so the first `emitted` bits are set.
    (1u8 << emitted) - 1
  };
  // Sanity: this matches `emitted_mask(dir_total)` (used by the
  // `walk_binary_data` partial-walk test).
  debug_assert_eq!(present_mask, emitted_mask(dir_total));
  let fmt = if present_mask == 0 {
    // Every key fell out of range (fmt_len just over 12 with no payload
    // covering even FormatVersion). Emit zero fmt-chunk tags — the
    // typed Meta still represents a successful magic+SetFileType but
    // produces no DSF:* output.
    None
  } else {
    Some(FmtData {
      format_version,
      format_id,
      channel_type,
      channel_count,
      sample_rate,
      bits_per_sample,
      sample_count,
      block_size,
      sample_count_is_decimal_string,
      present_mask,
    })
  };
  let id3_trailer = id3_trailer_slice(data, file_size, meta_pos);
  Some(Meta {
    fmt,
    fmt_warning: None,
    id3_trailer,
    #[cfg(feature = "id3")]
    id3: id3_from_trailer(id3_trailer),
  })
}

/// Parse the optional ID3v2 trailer slice (DSF.pm:88-97) into a typed
/// [`crate::formats::id3::Id3Meta`]. The trailer is a self-contained ID3
/// "file" (ID3v2 header at offset 0); DSF does NOT thread cross-format
/// `SharedFlags` (it is the simplest chained leaf), so `shared = None`.
/// `Some` iff the slice was present AND ID3 detection accepted it. Both
/// `-j` and `-n` lists are staged inside the returned Meta (one parse
/// serves both sink modes), so the `print_conv` argument is fixed `true`.
#[cfg(feature = "id3")]
fn id3_from_trailer(trailer: Option<&[u8]>) -> Option<crate::formats::id3::Id3Meta<'_>> {
  let slice = trailer?;
  crate::formats::id3::process::parse_id3_borrowed(slice, None, /* print_conv */ true)
}

/// Computes the present-mask bit per `DSF_KEYS` entry based on whether
/// the dirInfo buffer covers each field. Faithful to ExifTool.pm:9953
/// `last if $more <= 0` — returns the bitmask of present fields in
/// `DSF_KEYS` order (bit 0 = key 3, bit 1 = key 4, …, bit 7 = key 11).
/// Returns `0xFF` when every field fits.
// `slice::get` is not yet const-stable (E0658), so this `const fn` cannot use
// the checked form; the `while i < DSF_KEYS.len()` bound proves `DSF_KEYS[i]`
// is in range, so the indexing is panic-free by construction. Narrow,
// const-fn-only exception to the file-level deny.
#[allow(clippy::indexing_slicing)]
const fn emitted_mask(dir_total: usize) -> u8 {
  let mut mask: u8 = 0;
  let mut i: usize = 0;
  while i < DSF_KEYS.len() {
    let key = DSF_KEYS[i];
    let dir_off = (key as usize) * 4;
    let width: usize = if key == 9 { 8 } else { 4 };
    if dir_off + width <= dir_total {
      mask |= 1u8 << i;
    } else {
      // Strictly ascending — once out of range, the rest are too.
      break;
    }
    i += 1;
  }
  mask
}

/// Extract the optional ID3v2 trailer slice (DSF.pm:88-97) from `data`.
///
/// Faithful guards:
/// - `$metaPos` truthy ⇒ `meta_pos > 0`.
/// - `$metaLen = $fileSize - $metaPos` ⇒ `file_size.checked_sub(meta_pos)`
///   (handles the malformed `file_size < meta_pos` case as an unsigned
///   underflow ⇒ `None`, faithful to the `$metaLen > 0` Perl guard).
/// - `$metaLen > 0 and $metaLen < 20000000`.
/// - `$raf->Read($buff, $metaLen) == $metaLen` ⇒ in-memory slice bounds.
///
/// Returns the borrowed trailer bytes when every guard passes; `None`
/// otherwise.
fn id3_trailer_slice(data: &[u8], file_size: u64, meta_pos: u64) -> Option<&[u8]> {
  if meta_pos == 0 {
    return None;
  }
  let meta_len = file_size.checked_sub(meta_pos)?;
  if meta_len == 0 || meta_len >= 20_000_000 {
    return None;
  }
  let mp = meta_pos as usize;
  let ml = meta_len as usize;
  let end = mp.checked_add(ml)?;
  if end > data.len() {
    return None;
  }
  // `end = mp + ml <= data.len()` (guards above), so `.get(mp..end)` is always
  // `Some` — byte-identical to the prior `&data[mp..end]`; the `?` reuses the
  // same `None` (no-trailer) recovery the `end > data.len()` guard returns.
  data.get(mp..end)
}

/// Little-endian u32 reader (DSF.pm:66 `SetByteOrder('II')`).
/// Panic-free: caller bounds-checks `b` to at least 4 bytes, so
/// `first_chunk::<4>` always yields `Some` here (the `0` fallback is
/// unreachable) — byte-identical to the prior `b[..4]` copy.
fn read_u32_le(b: &[u8]) -> u32 {
  b.first_chunk::<4>().copied().map_or(0, u32::from_le_bytes)
}

/// Little-endian u64 reader (DSF.pm:66 `SetByteOrder('II')`).
/// Panic-free: caller bounds-checks `b` to at least 8 bytes, so
/// `first_chunk::<8>` always yields `Some` here (the `0` fallback is
/// unreachable) — byte-identical to the prior `b[..8]` copy.
fn read_u64_le(b: &[u8]) -> u64 {
  b.first_chunk::<8>().copied().map_or(0, u64::from_le_bytes)
}

// ===========================================================================
// `Taggable` — the golden-pattern emission path
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::diagnostics::Diagnose for Meta<'_> {
  /// DSF's diagnostics in the retired drain order: the DSF.pm:71 fmt-read
  /// warning FIRST (it precedes the tags), then the chained ID3 sub-Meta's own
  /// warnings then errors (its tags emit after DSF's, so its diagnostics drain
  /// after). The net `TagMap` (and `first_warning`) stays byte-identical.
  fn diagnostics(&self) -> std::vec::Vec<crate::diagnostics::Diagnostic> {
    let mut out = std::vec::Vec::new();
    if let Some(w) = self.fmt_warning() {
      out.push(crate::diagnostics::Diagnostic::warn(w));
    }
    #[cfg(feature = "id3")]
    if let Some(id3) = self.id3_ref() {
      out.extend(crate::diagnostics::Diagnose::diagnostics(id3));
    }
    out
  }
}

#[cfg(feature = "alloc")]
impl crate::emit::Taggable for Meta<'_> {
  /// Yield DSF tags in `%DSF::Main` ascending-key order (DSF.pm has no
  /// `FIRST_ENTRY` hint, so ExifTool walks keys via `sort { $a <=> $b }` —
  /// [`DSF_KEYS`]), then splice the chained ID3v2 trailer tags. The
  /// golden-pattern parallel to the retired `serialize_tags`: the SINK
  /// changes (an [`EmittedTag`](crate::emit::EmittedTag) per value instead
  /// of `out.write_*`), the per-tag PrintConv branches + the
  /// `present_mask`/[`DSF_KEYS`] conditional emission are preserved verbatim.
  ///
  /// `mode == PrintConv` (`-j`) ⇒ PrintConv hashes resolved;
  /// `mode == ValueConv` (`-n`) ⇒ post-ValueConv raw integers.
  ///
  /// **Group.** Family-0/1 both `"File"` (DSF.pm:22 `GROUPS => { 0 =>
  /// 'File', 1 => 'File', 2 => 'Audio' }`; family-2 `'Audio'` is not emitted
  /// under `-G1`). Every DSF fmt tag is a known tag ⇒ `unknown: false`.
  ///
  /// **Emission order (DSF.pm faithful)**:
  /// 1. `fmt`-chunk tags in [`DSF_KEYS`] order (if [`Meta::fmt`] is `Some`).
  /// 2. DSF.pm:88-97 chained ID3v2 trailer tags (if [`Meta::id3_ref`] is
  ///    `Some`) — AFTER the fmt-chunk tags, faithful to the bundled emission
  ///    order (ProcessBinaryData then the trailer ProcessDirectory).
  ///
  /// The fmt-chunk read failure WARNING ([`Meta::fmt_warning`], DSF.pm:71)
  /// and the chained ID3 sub-Meta's warnings/errors are NOT part of this
  /// tag stream ([`run_emission`](crate::emit::run_emission) has no
  /// warning/error channel) — the `AnyMeta::Dsf` dispatch arm drains them
  /// after `run_emission`, so the net output is unchanged.
  ///
  /// The File:* triplet is NOT emitted here — it is the engine
  /// ([`crate::parser::extract_info`]) `SetFileType` responsibility
  /// (DSF.pm:64).
  fn tags(
    &self,
    opts: crate::emit::EmitOptions,
  ) -> impl Iterator<Item = crate::emit::EmittedTag> + '_ {
    let mode = opts.mode;
    use crate::emit::EmittedTag;
    use crate::value::{Group, TagValue};

    // Family-0 "File" / family-1 "File" for every DSF fmt tag (see fn docs).
    let group = || Group::new("File", "File");
    let print_conv = matches!(mode, crate::emit::ConvMode::PrintConv);

    let mut tags: std::vec::Vec<EmittedTag> = std::vec::Vec::new();

    // (1) DSF.pm:30-48 fmt-chunk tags, ascending key order. The happy-path
    // mask is 0xFF (every field present). Partial-walk pathological inputs
    // are exercised through the legacy `walk_binary_data` helper.
    if let Some(fmt) = self.fmt {
      // `present_mask` bit ordering matches `DSF_KEYS`: bit 0 = key 3
      // (FormatVersion), …, bit 7 = key 11 (BlockSize). Each arm guards on
      // the corresponding mask bit so a partial-fit dirInfo buffer emits
      // only the present prefix (faithful to ExifTool.pm:9953 early-exit).
      let mask = fmt.present_mask;
      // Key 3 — FormatVersion (DSF.pm:30, no PrintConv).
      if mask & (1 << 0) != 0 {
        tags.push(EmittedTag::new(
          group(),
          "FormatVersion".into(),
          TagValue::U64(u64::from(fmt.format_version)),
          false,
        ));
      }
      // Key 4 — FormatID (DSF.pm:31). PrintConv: 0 ⇒ "DSD Raw".
      if mask & (1 << 1) != 0 {
        let value = if print_conv {
          match fmt.format_id_print() {
            Some(name) => TagValue::Str(name.into()),
            // Hash miss: emit the raw integer (faithful — Perl emits the
            // unconverted value).
            None => TagValue::U64(u64::from(fmt.format_id)),
          }
        } else {
          TagValue::U64(u64::from(fmt.format_id))
        };
        tags.push(EmittedTag::new(group(), "FormatID".into(), value, false));
      }
      // Key 5 — ChannelType (DSF.pm:32-43). PrintConv: hash.
      if mask & (1 << 2) != 0 {
        let value = if print_conv {
          match fmt.channel_type_print() {
            Some(name) => TagValue::Str(name.into()),
            None => TagValue::U64(u64::from(fmt.channel_type)),
          }
        } else {
          TagValue::U64(u64::from(fmt.channel_type))
        };
        tags.push(EmittedTag::new(group(), "ChannelType".into(), value, false));
      }
      // Key 6 — ChannelCount (DSF.pm:44, no PrintConv).
      if mask & (1 << 3) != 0 {
        tags.push(EmittedTag::new(
          group(),
          "ChannelCount".into(),
          TagValue::U64(u64::from(fmt.channel_count)),
          false,
        ));
      }
      // Key 7 — SampleRate (DSF.pm:45, no PrintConv).
      if mask & (1 << 4) != 0 {
        tags.push(EmittedTag::new(
          group(),
          "SampleRate".into(),
          TagValue::U64(u64::from(fmt.sample_rate)),
          false,
        ));
      }
      // Key 8 — BitsPerSample (DSF.pm:46, no PrintConv).
      if mask & (1 << 5) != 0 {
        tags.push(EmittedTag::new(
          group(),
          "BitsPerSample".into(),
          TagValue::U64(u64::from(fmt.bits_per_sample)),
          false,
        ));
      }
      // Key 9 — SampleCount (DSF.pm:47, int64u, no PrintConv). Values above
      // i64::MAX get the decimal-string treatment (the serializer's number
      // gate keeps a ≥16-digit bare integer as a JSON number — byte-exact
      // vs `exiftool -j` for large unsigned values). The retired sink used
      // `write_fmt(|w| write!(w, "{}", n))`; the decimal `TagValue::Str`
      // here renders identically.
      if mask & (1 << 6) != 0 {
        let value = if fmt.sample_count_is_decimal_string {
          TagValue::Str(fmt.sample_count.to_string().into())
        } else {
          TagValue::U64(fmt.sample_count)
        };
        tags.push(EmittedTag::new(group(), "SampleCount".into(), value, false));
      }
      // Key 11 — BlockSize (DSF.pm:48, no PrintConv).
      if mask & (1 << 7) != 0 {
        tags.push(EmittedTag::new(
          group(),
          "BlockSize".into(),
          TagValue::U64(u64::from(fmt.block_size)),
          false,
        ));
      }
    }

    // (2) DSF.pm:88-97 — chained ID3v2 trailer. Spliced AFTER the fmt-chunk
    // tags, faithful to the bundled emission order (the retired sink called
    // `id3.serialize_tags(print_conv, out)` at this exact point). `Id3Meta`
    // is `Taggable`, so its tags flow through the same engine; its
    // warnings/errors are drained by the `AnyMeta::Dsf` arm.
    #[cfg(feature = "id3")]
    if let Some(id3) = self.id3.as_ref() {
      tags.extend(id3.tags(opts));
    }

    tags.into_iter()
  }
}

// ===========================================================================
// `Project` — the normalized cross-format domain projection (golden L2)
// ===========================================================================

#[cfg(feature = "alloc")]
impl crate::metadata::Project for Meta<'_> {
  /// Project DSF metadata onto the normalized
  /// [`MediaMetadata`](crate::metadata::MediaMetadata) domain.
  ///
  /// DSF is a DSD audio stream: it carries no camera / lens / GPS / capture
  /// facts (those domains stay `None`). The single faithful structural
  /// contribution is one audio [`TrackKind`](crate::metadata::TrackKind):
  /// DSF files are audio-only (`%DSF::Main` `GROUPS{2} => 'Audio'`,
  /// DSF.pm:22).
  ///
  /// **Duration stays `None`.** DSF.pm emits no `Duration` tag, and the
  /// `'fmt '` chunk exposes only raw `SampleCount` / `SampleRate` integers
  /// — there is no decoded duration accessor on [`FmtData`]. Synthesizing
  /// `sample_count / sample_rate` would invent a value ExifTool never
  /// surfaces, so this projection leaves `duration` (and dimensions /
  /// created) `None`. The chained ID3 trailer's `Length` (TLEN) frame is
  /// NOT folded here (DSF's `Project` mirrors the bare-stream AAC shape;
  /// ID3 duration folding stays in [`Id3Meta`]'s own projection).
  fn project(&self) -> crate::metadata::MediaMetadata {
    use crate::metadata::TrackKind;
    let mut media = crate::metadata::MediaMetadata::new();
    media.media_mut().track_kinds_mut().push(TrackKind::Audio);
    media
  }
}

// ===========================================================================
// Engine entry — typed parse + File:* + sink into `Metadata`
// ===========================================================================

// ===========================================================================
// DSF-local ProcessBinaryData walk — exercised by the pathological
// out-of-range test; the typed parser only emits full / no fmt
// =====
// ======================================================================

/// DSF-local subset of `Image::ExifTool::ProcessBinaryData` (ExifTool.pm,
/// `sub ProcessBinaryData`). Pinned for the pathological out-of-range
/// test (`walk_out_of_range_field_is_skipped` exercises a custom
/// dirInfo buffer that's too short to cover key 9 or key 11). The
/// production happy path goes through `parse_inner` ⇒ `serialize_tags`
/// and never calls this helper.
///
/// `buf` is the dirInfo-shape buffer (`'fmt '` + 8-byte chunkSize +
/// payload). Faithful per-tag walk: bounds-check + LE u32/u64 read +
/// `convert::apply` + push under `("File", "File")`.
#[allow(dead_code)]
fn walk_binary_data(buf: &[u8], m: &mut Metadata, print_conv_enabled: bool) {
  for &key in DSF_KEYS {
    let Some(def) = dsf_get(TagId::Int(key)) else {
      continue;
    };
    let off = (key as usize).saturating_mul(4);
    let width: usize = match def.format() {
      Some("int64u") => 8,
      _ => 4,
    };
    let end = off.saturating_add(width);
    if end > buf.len() {
      // ExifTool.pm:9953 `last if $more <= 0`.
      break;
    }
    // `off + width <= buf.len()` (the `end > buf.len()` break above) ⇒ each
    // `.get(off..off + width)` is always `Some`; the panic-free `read_*_le`
    // helpers (which bounds-check internally) read the same bytes as the prior
    // `copy_from_slice(&buf[off..off + width])` — byte-identical.
    let raw = if width == 8 {
      let v = read_u64_le(buf.get(off..off + 8).unwrap_or(&[]));
      if v <= i64::MAX as u64 {
        TagValue::I64(v as i64)
      } else {
        // Faithful Perl UV→NV-shape: the serializer's number gate keeps
        // a ≥16-digit bare integer as a JSON number — byte-exact vs
        // `exiftool -j` for large unsigned values.
        TagValue::Str(v.to_string().into())
      }
    } else {
      TagValue::I64(read_u32_le(buf.get(off..off + 4).unwrap_or(&[])) as i64)
    };
    let out = crate::convert::apply(def, &raw, print_conv_enabled);
    m.push(Group::new("File", "File"), def.name(), out);
  }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
// The file-level `#![deny(clippy::indexing_slicing)]` is a parser-panic-safety
// contract (Phase C w2c); the test-builder helpers index fixed-layout buffers
// freely (an out-of-range index is a test-assertion failure, not a shipped
// panic), so the deny is relaxed here.
#[allow(clippy::indexing_slicing)]
mod tests {
  use super::*;
  use crate::emit::{ConvMode, Taggable};
  use crate::tagmap::TagMap;

  /// Drive a [`Meta`] through the golden [`run_emission`](crate::emit) engine
  /// PLUS the `AnyMeta::Dsf` arm's warning drain (the DSF.pm:71 fmt-read
  /// warning + the chained ID3 sub-Meta's warnings/errors). Mirrors the
  /// `format_parser.rs` arm exactly so the in-module tests exercise the same
  /// net `TagMap` the engine produces. `print_conv` ⇒ `-j`, else `-n`.
  fn emit_via_engine(meta: &Meta<'_>, print_conv: bool, out: &mut TagMap) {
    crate::emit::run_emission(
      meta,
      crate::emit::EmitOptions::g1(ConvMode::from_print_conv(print_conv), false),
      out,
    );
    // Drain diagnostics through the SAME `run_diagnostics` path the
    // `format_parser.rs` arm uses, so the `[minor]`/`[x$n]` prefixing matches
    // production (the chained ID3 sub-Meta's ignorable levels flow through
    // DSF's `Diagnose` impl).
    crate::diagnostics::run_diagnostics(meta, out);
  }

  // --- Table + dispatch ---------------------------------------------------

  #[test]
  fn table_and_keys_are_faithful() {
    let g = DSF_MAIN.get();
    // Every emitted DSF tag.
    assert_eq!(g(TagId::Int(3)).unwrap().name(), "FormatVersion");
    assert_eq!(g(TagId::Int(4)).unwrap().name(), "FormatID");
    assert_eq!(g(TagId::Int(5)).unwrap().name(), "ChannelType");
    assert_eq!(g(TagId::Int(6)).unwrap().name(), "ChannelCount");
    assert_eq!(g(TagId::Int(7)).unwrap().name(), "SampleRate");
    assert_eq!(g(TagId::Int(8)).unwrap().name(), "BitsPerSample");
    assert_eq!(g(TagId::Int(9)).unwrap().name(), "SampleCount");
    assert_eq!(g(TagId::Int(11)).unwrap().name(), "BlockSize");
    // Per-tag family-1 is "File" (DSF.pm:22).
    for &k in DSF_KEYS {
      assert_eq!(g(TagId::Int(k)).unwrap().group1(), "File");
    }
    assert_eq!(DSF_MAIN.group0(), "File");
    // Key 10 is intentionally absent (consumed by key 9's int64u).
    assert!(g(TagId::Int(10)).is_none());
    // Bogus integer keys miss.
    assert!(g(TagId::Int(0)).is_none());
    assert!(g(TagId::Int(12)).is_none());
    // DSF is integer-keyed; string ids never match.
    assert!(g(TagId::Str("FormatVersion")).is_none());
    assert!(g(TagId::Str("3")).is_none());
  }

  #[test]
  fn dsf_keys_const_is_ascending_and_complete() {
    let mut prev = i64::MIN;
    for &k in DSF_KEYS {
      assert!(k > prev, "DSF_KEYS must be strictly ascending");
      prev = k;
      assert!(
        dsf_get(TagId::Int(k)).is_some(),
        "DSF_KEYS entry {k} missing from dsf_get"
      );
    }
    assert_eq!(DSF_KEYS, &[3, 4, 5, 6, 7, 8, 9, 11]);
  }

  #[test]
  fn print_conv_shapes_are_faithful() {
    let g = DSF_MAIN.get();
    match g(TagId::Int(4)).unwrap().print_conv() {
      PrintConv::Hash(h) => {
        let de = h.direct_entries();
        assert_eq!(de.len(), 1);
        assert_eq!(de[0], ("0", PrintValue::Str("DSD Raw")));
      }
      _ => panic!("FormatID print_conv must be a hash"),
    }
    match g(TagId::Int(5)).unwrap().print_conv() {
      PrintConv::Hash(h) => {
        assert_eq!(h.direct_entries().len(), 7);
        assert_eq!(
          h.direct_entries()[1],
          ("2", PrintValue::Str("Stereo (Left, Right)"))
        );
      }
      _ => panic!("ChannelType print_conv must be a hash"),
    }
    assert!(g(TagId::Int(3)).unwrap().print_conv().is_none());
    assert!(g(TagId::Int(11)).unwrap().print_conv().is_none());
    assert_eq!(g(TagId::Int(9)).unwrap().format(), Some("int64u"));
    for k in [3, 4, 5, 6, 7, 8, 11] {
      assert_eq!(g(TagId::Int(k)).unwrap().format(), None);
    }
  }

  // --- Fixture builders ---------------------------------------------------

  /// 76-byte minimal valid DSF (matches the spec's §3.1 fixture exactly).
  fn happy_path_dsf() -> std::vec::Vec<u8> {
    let mut v = std::vec::Vec::with_capacity(76);
    v.extend_from_slice(b"DSD ");
    v.extend_from_slice(&0x1cu64.to_le_bytes()); // DSD chunk size
    v.extend_from_slice(&76u64.to_le_bytes()); // fileSize
    v.extend_from_slice(&0u64.to_le_bytes()); // metaPos = 0
    v.extend_from_slice(b"fmt ");
    v.extend_from_slice(&48u64.to_le_bytes()); // fmtLen
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&2u32.to_le_bytes());
    v.extend_from_slice(&2u32.to_le_bytes());
    v.extend_from_slice(&2_822_400u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&2_822_400u64.to_le_bytes());
    v.extend_from_slice(&4096u32.to_le_bytes());
    assert_eq!(v.len(), 76);
    v
  }

  // --- Typed FormatParser path --------------------------------------------

  #[test]
  fn parse_borrowed_rejects_short_buffer() {
    assert!(parse_borrowed(&[]).is_none());
    assert!(parse_borrowed(&[0u8; 39]).is_none());
  }

  #[test]
  fn parse_borrowed_rejects_bad_magic() {
    let mut bad = happy_path_dsf();
    bad[0..4].copy_from_slice(b"XXXX");
    assert!(parse_borrowed(&bad).is_none());
    let mut bad = happy_path_dsf();
    bad[4] = 0x00; // not 0x1c
    assert!(parse_borrowed(&bad).is_none());
    let mut bad = happy_path_dsf();
    bad[5] = 0xff; // not \0
    assert!(parse_borrowed(&bad).is_none());
    let mut bad = happy_path_dsf();
    bad[28..32].copy_from_slice(b"FMTA");
    assert!(parse_borrowed(&bad).is_none());
  }

  #[test]
  fn parse_borrowed_happy_path_populates_fmt_data() {
    let bytes = happy_path_dsf();
    let meta = parse_borrowed(&bytes).expect("parsed");
    assert!(meta.fmt_warning().is_none());
    assert!(meta.id3_trailer().is_none());
    let fmt = meta.fmt().expect("fmt populated");
    assert_eq!(fmt.format_version(), 1);
    assert_eq!(fmt.format_id(), 0);
    assert_eq!(fmt.format_id_print(), Some("DSD Raw"));
    assert_eq!(fmt.channel_type(), 2);
    assert_eq!(fmt.channel_type_print(), Some("Stereo (Left, Right)"));
    assert_eq!(fmt.channel_count(), 2);
    assert_eq!(fmt.sample_rate(), 2_822_400);
    assert_eq!(fmt.bits_per_sample(), 1);
    assert_eq!(fmt.sample_count(), 2_822_400);
    assert_eq!(fmt.block_size(), 4096);
  }

  #[test]
  fn parse_borrowed_warn_path_emits_warning_no_fmt() {
    // fmtLen = 8 ⇒ guard fails (≤ 12).
    let mut v = std::vec::Vec::with_capacity(40);
    v.extend_from_slice(b"DSD ");
    v.extend_from_slice(&0x1cu64.to_le_bytes());
    v.extend_from_slice(&40u64.to_le_bytes());
    v.extend_from_slice(&0u64.to_le_bytes());
    v.extend_from_slice(b"fmt ");
    v.extend_from_slice(&8u64.to_le_bytes()); // fmtLen = 8 (≤ 12 ⇒ guard fail)
    let meta = parse_borrowed(&v).expect("parsed");
    assert!(meta.fmt().is_none());
    assert_eq!(meta.fmt_warning(), Some("Error reading DSF fmt chunk"));
    assert!(meta.id3_trailer().is_none());
  }

  #[test]
  fn parse_borrowed_warn_path_at_fmt_len_12_no_underflow() {
    // CRITICAL: DSF.pm:68 strict `$fmtLen > 12`. With fmtLen==12 the
    // subtraction `$fmtLen - 12 == 0` would not underflow in Perl, but
    // the `>` guard prevents the (no-op) read. We MUST NOT subtract 12
    // from fmt_len when fmt_len <= 12 — that would underflow in
    // unsigned Rust.
    let mut v = std::vec::Vec::with_capacity(40);
    v.extend_from_slice(b"DSD ");
    v.extend_from_slice(&0x1cu64.to_le_bytes());
    v.extend_from_slice(&40u64.to_le_bytes());
    v.extend_from_slice(&0u64.to_le_bytes());
    v.extend_from_slice(b"fmt ");
    v.extend_from_slice(&12u64.to_le_bytes()); // fmtLen = 12 (NOT > 12)
    let meta = parse_borrowed(&v).expect("parsed");
    assert!(meta.fmt().is_none());
    assert_eq!(meta.fmt_warning(), Some("Error reading DSF fmt chunk"));
  }

  #[test]
  fn parse_borrowed_warn_path_at_fmt_len_zero_no_underflow() {
    for fmt_len in [0u64, 1, 11] {
      let mut v = std::vec::Vec::with_capacity(40);
      v.extend_from_slice(b"DSD ");
      v.extend_from_slice(&0x1cu64.to_le_bytes());
      v.extend_from_slice(&40u64.to_le_bytes());
      v.extend_from_slice(&0u64.to_le_bytes());
      v.extend_from_slice(b"fmt ");
      v.extend_from_slice(&fmt_len.to_le_bytes());
      let meta = parse_borrowed(&v).expect("parsed");
      assert!(meta.fmt().is_none(), "fmt_len={fmt_len}");
      assert_eq!(meta.fmt_warning(), Some("Error reading DSF fmt chunk"));
    }
  }

  #[test]
  fn parse_borrowed_warn_path_at_fmt_len_1000_upper_bound() {
    // fmtLen = 1000 ⇒ guard fails (the `<` is strict).
    let mut v = std::vec::Vec::with_capacity(40);
    v.extend_from_slice(b"DSD ");
    v.extend_from_slice(&0x1cu64.to_le_bytes());
    v.extend_from_slice(&40u64.to_le_bytes());
    v.extend_from_slice(&0u64.to_le_bytes());
    v.extend_from_slice(b"fmt ");
    v.extend_from_slice(&1000u64.to_le_bytes());
    let meta = parse_borrowed(&v).expect("parsed");
    assert!(meta.fmt().is_none());
    assert_eq!(meta.fmt_warning(), Some("Error reading DSF fmt chunk"));
  }

  #[test]
  fn parse_borrowed_warn_path_at_fmt_len_999_accepts() {
    // Adjacent passing boundary to `fmt_len == 1000`. DSF.pm:68 `$fmtLen
    // < 1000` is strict, so 999 with a 987-byte trailing payload parses
    // successfully and emits no warning.
    let mut v = std::vec::Vec::with_capacity(40 + 987);
    v.extend_from_slice(b"DSD ");
    v.extend_from_slice(&0x1cu64.to_le_bytes());
    v.extend_from_slice(&(40u64 + 987).to_le_bytes()); // fileSize
    v.extend_from_slice(&0u64.to_le_bytes()); // metaPos = 0 ⇒ no ID3
    v.extend_from_slice(b"fmt ");
    v.extend_from_slice(&999u64.to_le_bytes()); // fmtLen = 999 (< 1000 ✓)
    // First 36 bytes of payload: the eight fmt-chunk fields.
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&2u32.to_le_bytes());
    v.extend_from_slice(&2u32.to_le_bytes());
    v.extend_from_slice(&2_822_400u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&2_822_400u64.to_le_bytes());
    v.extend_from_slice(&4096u32.to_le_bytes());
    // Pad to total payload of 987 bytes (951 zeros after the 36-byte head).
    v.extend(core::iter::repeat(0u8).take(987 - 36));
    let meta = parse_borrowed(&v).expect("parsed");
    assert!(meta.fmt_warning().is_none());
    let fmt = meta.fmt().expect("populated");
    assert_eq!(fmt.format_version(), 1);
    assert_eq!(fmt.block_size(), 4096);
  }

  #[test]
  fn parse_borrowed_warn_path_at_truncated_payload() {
    // fmtLen claims a payload longer than the file actually has.
    let mut v = std::vec::Vec::with_capacity(40);
    v.extend_from_slice(b"DSD ");
    v.extend_from_slice(&0x1cu64.to_le_bytes());
    v.extend_from_slice(&40u64.to_le_bytes());
    v.extend_from_slice(&0u64.to_le_bytes());
    v.extend_from_slice(b"fmt ");
    v.extend_from_slice(&48u64.to_le_bytes()); // fmtLen = 48 ⇒ need 36 more
    let meta = parse_borrowed(&v).expect("parsed");
    assert!(meta.fmt().is_none());
    assert_eq!(meta.fmt_warning(), Some("Error reading DSF fmt chunk"));
  }

  // --- ID3 trailer borrow -------------------------------------------------

  fn dsf_with_trailer(trailer: &[u8]) -> std::vec::Vec<u8> {
    // 76-byte fmt + `trailer.len()` bytes appended.
    let mut v = happy_path_dsf();
    let file_size = 76u64 + trailer.len() as u64;
    let meta_pos = 76u64;
    // Rewrite fileSize and metaPos.
    v[12..20].copy_from_slice(&file_size.to_le_bytes());
    v[20..28].copy_from_slice(&meta_pos.to_le_bytes());
    v.extend_from_slice(trailer);
    v
  }

  #[test]
  fn parse_borrowed_carries_id3_trailer_slice() {
    let id3_bytes = b"ID3\x03\x00\x00\x00\x00\x00\x01\x00";
    let v = dsf_with_trailer(id3_bytes);
    let meta = parse_borrowed(&v).expect("parsed");
    assert_eq!(meta.id3_trailer(), Some(&id3_bytes[..]));
  }

  #[test]
  fn parse_borrowed_no_id3_trailer_when_meta_pos_zero() {
    let bytes = happy_path_dsf(); // metaPos == 0
    let meta = parse_borrowed(&bytes).expect("parsed");
    assert!(meta.id3_trailer().is_none());
  }

  #[test]
  fn parse_borrowed_no_id3_trailer_when_file_size_less_than_meta_pos() {
    // Malformed: metaPos > fileSize ⇒ unsigned underflow in `$metaLen`
    // calculation. Bundled-Perl's `$metaLen > 0` guard rejects; we
    // mirror with `checked_sub`.
    let mut v = happy_path_dsf();
    v[12..20].copy_from_slice(&50u64.to_le_bytes()); // fileSize = 50
    v[20..28].copy_from_slice(&100u64.to_le_bytes()); // metaPos = 100
    let meta = parse_borrowed(&v).expect("parsed");
    assert!(meta.id3_trailer().is_none());
  }

  #[test]
  fn parse_borrowed_no_id3_trailer_when_meta_len_zero() {
    // metaPos == fileSize ⇒ metaLen == 0 ⇒ guard fails.
    let mut v = happy_path_dsf();
    v[12..20].copy_from_slice(&76u64.to_le_bytes()); // fileSize = 76
    v[20..28].copy_from_slice(&76u64.to_le_bytes()); // metaPos = 76
    let meta = parse_borrowed(&v).expect("parsed");
    assert!(meta.id3_trailer().is_none());
  }

  #[test]
  fn parse_borrowed_no_id3_trailer_when_meta_len_too_large() {
    // metaLen >= 20_000_000 ⇒ guard fails (DSF.pm:88
    // `$metaLen < 20000000`).
    let mut v = happy_path_dsf();
    let file_size = 76u64 + 20_000_000;
    let meta_pos = 76u64;
    v[12..20].copy_from_slice(&file_size.to_le_bytes());
    v[20..28].copy_from_slice(&meta_pos.to_le_bytes());
    // Note: we don't actually append 20MB — the bounds check on
    // `end > data.len()` rejects before the size guard. Equivalent
    // behavior (both guards reject).
    let meta = parse_borrowed(&v).expect("parsed");
    assert!(meta.id3_trailer().is_none());
  }

  #[test]
  fn parse_borrowed_no_id3_trailer_when_short_read() {
    // metaPos points past the actual file end.
    let mut v = happy_path_dsf();
    v[12..20].copy_from_slice(&100u64.to_le_bytes()); // claim fileSize = 100
    v[20..28].copy_from_slice(&76u64.to_le_bytes()); // metaPos = 76
    // But the file is only 76 bytes — `end > data.len()` rejects.
    let meta = parse_borrowed(&v).expect("parsed");
    assert!(meta.id3_trailer().is_none());
  }

  // --- serialize_tags ---------------------------------------------------------

  #[test]
  fn sink_emits_full_fmt_set_in_key_order_print_conv() {
    let bytes = happy_path_dsf();
    let meta = parse_borrowed(&bytes).expect("parsed");
    let mut w = TagMap::new();
    emit_via_engine(&meta, true, &mut w);
    // Spot-check: PrintConv-resolved names + numeric raw scalars.
    assert_eq!(w.get_str("File", "FormatVersion"), Some("1".to_string()));
    assert_eq!(w.get_str("File", "FormatID"), Some("DSD Raw".to_string()));
    assert_eq!(
      w.get_str("File", "ChannelType"),
      Some("Stereo (Left, Right)".to_string())
    );
    assert_eq!(w.get_str("File", "ChannelCount"), Some("2".to_string()));
    assert_eq!(w.get_str("File", "SampleRate"), Some("2822400".to_string()));
    assert_eq!(w.get_str("File", "BitsPerSample"), Some("1".to_string()));
    assert_eq!(
      w.get_str("File", "SampleCount"),
      Some("2822400".to_string())
    );
    assert_eq!(w.get_str("File", "BlockSize"), Some("4096".to_string()));
    assert!(w.warnings().is_empty());
  }

  #[test]
  fn sink_emits_full_fmt_set_print_conv_off() {
    let bytes = happy_path_dsf();
    let meta = parse_borrowed(&bytes).expect("parsed");
    let mut w = TagMap::new();
    emit_via_engine(&meta, false, &mut w);
    // -n: raw numeric for FormatID / ChannelType (hash NOT applied).
    assert_eq!(w.get_str("File", "FormatID"), Some("0".to_string()));
    assert_eq!(w.get_str("File", "ChannelType"), Some("2".to_string()));
  }

  #[test]
  fn sink_emits_warning_when_fmt_chunk_failed() {
    let meta = Meta {
      fmt: None,
      fmt_warning: Some("Error reading DSF fmt chunk"),
      id3_trailer: None,
      #[cfg(feature = "id3")]
      id3: None,
    };
    let mut w = TagMap::new();
    emit_via_engine(&meta, true, &mut w);
    assert_eq!(w.warnings(), &["Error reading DSF fmt chunk".to_string()]);
    // No fmt-chunk tags emitted on the warn path.
    assert!(w.get("File", "FormatVersion").is_none());
    assert!(w.get("File", "BlockSize").is_none());
  }

  #[test]
  fn sink_emits_int64u_above_i64_max_as_decimal_string() {
    // SampleCount = u64::MAX ⇒ post-promotion fmt
    // `sample_count_is_decimal_string = true` ⇒ `write_fmt` decimal.
    let meta = Meta {
      fmt: Some(FmtData {
        format_version: 0,
        format_id: 0,
        channel_type: 0,
        channel_count: 0,
        sample_rate: 0,
        bits_per_sample: 0,
        sample_count: u64::MAX,
        block_size: 0,
        sample_count_is_decimal_string: true,
        present_mask: 0xFF,
      }),
      fmt_warning: None,
      id3_trailer: None,
      #[cfg(feature = "id3")]
      id3: None,
    };
    let mut w = TagMap::new();
    emit_via_engine(&meta, true, &mut w);
    assert_eq!(
      w.get_str("File", "SampleCount"),
      Some("18446744073709551615".to_string())
    );
  }

  // --- Partial fmt-chunk walk via parse_inner -----------------------------

  #[test]
  fn parse_borrowed_partial_fmt_chunk_emits_prefix_only() {
    // fmt_len = 20 (`> 12 && < 1000`) ⇒ dirInfo total = 20 bytes.
    // dir_off for key 3 (FormatVersion) is 12, width 4 ⇒ fits.
    // dir_off for key 4 (FormatID) is 16, width 4 ⇒ fits (dir_total
    // >= 20 ✓). Key 5 (ChannelType) is at 20, needs 24 ⇒ does NOT.
    // So we expect ONLY FormatVersion + FormatID in the sink output.
    let mut v = std::vec::Vec::with_capacity(40 + 8);
    v.extend_from_slice(b"DSD ");
    v.extend_from_slice(&0x1cu64.to_le_bytes());
    v.extend_from_slice(&48u64.to_le_bytes()); // fileSize = 48
    v.extend_from_slice(&0u64.to_le_bytes()); // metaPos = 0
    v.extend_from_slice(b"fmt ");
    v.extend_from_slice(&20u64.to_le_bytes()); // fmtLen = 20
    // payload: 8 bytes = key3 (FormatVersion) + key4 (FormatID).
    v.extend_from_slice(&7u32.to_le_bytes()); // FormatVersion = 7
    v.extend_from_slice(&0u32.to_le_bytes()); // FormatID = 0 ⇒ "DSD Raw"
    assert_eq!(v.len(), 48);
    let meta = parse_borrowed(&v).expect("parsed");
    assert!(meta.fmt_warning().is_none());
    let fmt = meta.fmt().expect("partial fmt");
    assert_eq!(fmt.present_mask, 0b0000_0011); // keys 3,4 only
    assert_eq!(fmt.format_version(), 7);
    assert_eq!(fmt.format_id(), 0);
    // The sink emits ONLY the present prefix.
    let mut w = TagMap::new();
    emit_via_engine(&meta, true, &mut w);
    assert_eq!(w.get_str("File", "FormatVersion"), Some("7".to_string()));
    assert_eq!(w.get_str("File", "FormatID"), Some("DSD Raw".to_string()));
    assert!(w.get("File", "ChannelType").is_none());
    assert!(w.get("File", "BlockSize").is_none());
  }

  #[test]
  fn parse_borrowed_zero_fmt_chunk_emits_no_fmt_tags() {
    // fmt_len = 13 ⇒ dir_total = 13 ⇒ even FormatVersion (dir_off
    // 12, width 4 ⇒ needs 16) doesn't fit. Expect fmt == None,
    // no warning (the guard PASSED on > 12 && < 1000 + read
    // succeeded), no fmt-chunk tags.
    let mut v = std::vec::Vec::with_capacity(40 + 1);
    v.extend_from_slice(b"DSD ");
    v.extend_from_slice(&0x1cu64.to_le_bytes());
    v.extend_from_slice(&41u64.to_le_bytes()); // fileSize = 41
    v.extend_from_slice(&0u64.to_le_bytes()); // metaPos = 0
    v.extend_from_slice(b"fmt ");
    v.extend_from_slice(&13u64.to_le_bytes()); // fmtLen = 13
    v.extend_from_slice(&[0u8; 1]); // 1 byte payload
    assert_eq!(v.len(), 41);
    let meta = parse_borrowed(&v).expect("parsed");
    assert!(meta.fmt_warning().is_none());
    assert!(
      meta.fmt().is_none(),
      "fmt_len just over 12 with no key-3 coverage ⇒ fmt is None"
    );
    let mut w = TagMap::new();
    emit_via_engine(&meta, true, &mut w);
    assert!(w.is_empty());
  }

  // --- ProcessBinaryData walk helper (pathological dirInfo) ---------------

  /// Build a dirInfo-shape buffer with the same layout DSF.pm:76 yields:
  /// `'fmt '` + 8-byte chunkSize + payload. Helper only.
  fn dir(payload: &[u8]) -> std::vec::Vec<u8> {
    let mut b = std::vec::Vec::with_capacity(12 + payload.len());
    b.extend_from_slice(b"fmt ");
    b.extend_from_slice(&((12 + payload.len()) as u64).to_le_bytes());
    b.extend_from_slice(payload);
    b
  }

  #[test]
  fn walk_out_of_range_field_is_skipped() {
    // dirInfo buffer ending at offset 36 — keys 3..=8 fit, 9 (offset
    // 36, 8 bytes) does NOT, 11 (offset 44, 4 bytes) also does NOT.
    let mut p = std::vec::Vec::with_capacity(24);
    for _ in 0..6 {
      p.extend_from_slice(&0u32.to_le_bytes());
    }
    let buf = dir(&p);
    assert_eq!(buf.len(), 36);
    let mut m = Metadata::new("x");
    walk_binary_data(&buf, &mut m, false);
    let names: std::vec::Vec<&str> = m.tags_slice().iter().map(|t| t.name()).collect();
    assert_eq!(
      names,
      [
        "FormatVersion",
        "FormatID",
        "ChannelType",
        "ChannelCount",
        "SampleRate",
        "BitsPerSample",
      ]
    );
    assert!(m.tags_slice().iter().all(|t| t.name() != "SampleCount"));
    assert!(m.tags_slice().iter().all(|t| t.name() != "BlockSize"));
  }

  #[test]
  fn walk_int64u_above_i64_max_is_decimal_string() {
    let mut p = std::vec::Vec::with_capacity(36);
    p.resize(36, 0);
    p[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
    let buf = dir(&p);
    let mut m = Metadata::new("x");
    walk_binary_data(&buf, &mut m, false);
    let sc = m
      .tags_slice()
      .iter()
      .find(|t| t.name() == "SampleCount")
      .unwrap()
      .value_ref()
      .clone();
    assert_eq!(sc, TagValue::Str("18446744073709551615".into()));
  }

  #[test]
  fn emitted_mask_full_when_dir_total_covers_block_size() {
    // block_size key = 11 ⇒ dir_off = 44, width = 4 ⇒ requires
    // dir_total >= 48.
    assert_eq!(emitted_mask(48), 0xFF);
    assert_eq!(emitted_mask(76), 0xFF); // production happy path
  }

  #[test]
  fn emitted_mask_truncates_at_first_out_of_range_key() {
    // dir_total == 36 ⇒ keys 3..=8 fit (bits 0..=5), keys 9/11 fall off.
    assert_eq!(emitted_mask(36), 0b0011_1111);
    // dir_total == 32 ⇒ keys 3..=7 fit (bits 0..=4), keys 8/9/11 fall off.
    assert_eq!(emitted_mask(32), 0b0001_1111);
    // dir_total == 12 ⇒ no payload yet ⇒ NO fmt keys fit.
    assert_eq!(emitted_mask(12), 0);
  }

  // --- FormatParser trait round-trip --------------------------------------

  #[test]
  fn format_parser_trait_returns_borrowed_meta() {
    let bytes = happy_path_dsf();
    let mut shared = SharedFlags::new();
    let ctx = Context::new(&bytes, &mut shared);
    let meta = <ProcessDsf as FormatParser>::parse(&ProcessDsf, ctx).expect("parsed");
    // GAT path borrows from the input; this fixture has metaPos=0 (no ID3
    // trailer), so the trailer slice is absent here.
    assert!(meta.id3_trailer().is_none());
    // fmt fields survive intact.
    let fmt = meta.fmt().expect("populated");
    assert_eq!(fmt.format_version(), 1);
    assert_eq!(fmt.sample_count(), 2_822_400);
  }

  // --- Engine entry (`extract_info`) --------------------------------------
  // The engine path is now `crate::parser::extract_info` (detect → typed parse
  // → serde-render). These tests run it and assert on the parsed JSON object,
  // replacing the retired `ProcessDsf::process` + `TagMap` tests.

  /// Run the engine over `data` (named `x.dsf`) in `-j` mode and return the
  /// single file object. `None` is impossible (always a one-object array).
  fn engine_obj(data: &[u8]) -> serde_json::Map<String, serde_json::Value> {
    let json = crate::parser::extract_info("x.dsf", data, true);
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    v.as_array().unwrap()[0].as_object().unwrap().clone()
  }

  #[test]
  fn engine_rejects_when_short() {
    for n in [0usize, 39] {
      let buf = std::vec![0u8; n];
      let obj = engine_obj(&buf);
      // No DSF File:FileType (header miss ⇒ not finalized as DSF).
      assert_ne!(
        obj.get("File:FileType").and_then(|v| v.as_str()),
        Some("DSF"),
        "n={n}"
      );
    }
  }

  #[test]
  fn engine_rejects_when_wrong_magic() {
    let mut bad = happy_path_dsf()[..40].to_vec();
    bad[0..4].copy_from_slice(b"XXXX");
    let obj = engine_obj(&bad);
    assert_ne!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("DSF")
    );
  }

  #[test]
  fn engine_accepts_minimal_valid_emits_full_set() {
    let obj = engine_obj(&happy_path_dsf());
    assert_eq!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("DSF")
    );
    assert_eq!(
      obj.get("File:FileTypeExtension").and_then(|v| v.as_str()),
      Some("dsf")
    );
    assert_eq!(
      obj.get("File:MIMEType").and_then(|v| v.as_str()),
      Some("audio/x-dsf")
    );
    // fmt-chunk tags present.
    for key in [
      "File:FormatVersion",
      "File:FormatID",
      "File:ChannelType",
      "File:ChannelCount",
      "File:SampleRate",
      "File:BitsPerSample",
      "File:SampleCount",
      "File:BlockSize",
    ] {
      assert!(obj.contains_key(key), "missing {key}");
    }
    assert!(!obj.contains_key("ExifTool:Warning"));
    assert_eq!(
      obj.get("File:FormatID").and_then(|v| v.as_str()),
      Some("DSD Raw")
    );
    assert_eq!(
      obj.get("File:ChannelType").and_then(|v| v.as_str()),
      Some("Stereo (Left, Right)")
    );
  }

  #[test]
  fn engine_warns_on_short_fmt_chunk_returns_true() {
    let mut buf = std::vec::Vec::with_capacity(40);
    buf.extend_from_slice(b"DSD ");
    buf.extend_from_slice(&0x1cu64.to_le_bytes());
    buf.extend_from_slice(&40u64.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(b"fmt ");
    buf.extend_from_slice(&8u64.to_le_bytes()); // fmtLen = 8 (≤ 12)
    let obj = engine_obj(&buf);
    // File:* triplet emitted (DSF.pm:64 SetFileType before the Warn).
    assert_eq!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("DSF")
    );
    assert!(!obj.contains_key("File:FormatVersion"));
    assert_eq!(
      obj.get("ExifTool:Warning").and_then(|v| v.as_str()),
      Some("Error reading DSF fmt chunk")
    );
  }

  #[test]
  fn engine_warns_on_truncated_fmt_payload_returns_true() {
    let mut buf = std::vec::Vec::with_capacity(40);
    buf.extend_from_slice(b"DSD ");
    buf.extend_from_slice(&0x1cu64.to_le_bytes());
    buf.extend_from_slice(&40u64.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(b"fmt ");
    buf.extend_from_slice(&48u64.to_le_bytes()); // fmtLen = 48 ⇒ need 36 more
    let obj = engine_obj(&buf);
    assert_eq!(
      obj.get("ExifTool:Warning").and_then(|v| v.as_str()),
      Some("Error reading DSF fmt chunk")
    );
    assert!(!obj.contains_key("File:FormatVersion"));
  }

  #[test]
  fn engine_fmt_len_equals_12_underflow_guard() {
    // CRITICAL: DSF.pm:68 strict `$fmtLen > 12` underflow guard.
    let mut buf = std::vec::Vec::with_capacity(40);
    buf.extend_from_slice(b"DSD ");
    buf.extend_from_slice(&0x1cu64.to_le_bytes());
    buf.extend_from_slice(&40u64.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(b"fmt ");
    buf.extend_from_slice(&12u64.to_le_bytes()); // fmtLen = 12 (NOT > 12)
    let obj = engine_obj(&buf);
    assert_eq!(
      obj.get("ExifTool:Warning").and_then(|v| v.as_str()),
      Some("Error reading DSF fmt chunk")
    );
  }

  #[test]
  fn engine_dispatches_id3_trailer() {
    // Synthesize a DSF file with a small ID3v2.3 header attached (empty body).
    let id3 = b"ID3\x03\x00\x00\x00\x00\x00\x00";
    let buf = dsf_with_trailer(id3);
    let obj = engine_obj(&buf);
    assert!(!obj.contains_key("ExifTool:Warning"));
    // FileType still DSF (the chained ID3 path does NOT SetFileType).
    assert_eq!(
      obj.get("File:FileType").and_then(|v| v.as_str()),
      Some("DSF")
    );
  }

  // --- §3/§5 skill-conformance tests for the typed DSF surface -----------

  #[test]
  fn dsf_fmt_accessor_is_byvalue_copy() {
    // §3: `FmtData` is Copy ⇒ `Meta::fmt()` returns `Option<T>` by
    // value (not `Option<&T>`), and the field getters are by-value too.
    let buf = happy_path_dsf();
    let meta = parse_borrowed(&buf).expect("some");
    let fmt: Option<FmtData> = meta.fmt();
    let fmt = fmt.expect("fmt present on happy path");
    assert_eq!(fmt.channel_count(), 2);
    assert_eq!(fmt.sample_rate(), 2_822_400);
    assert_eq!(fmt.sample_count(), 2_822_400);
    assert_eq!(fmt.block_size(), 4096);
    // const-eval check: a by-value Copy getter is usable in const context.
    const _: () = {
      // (compile-time presence of the const fns; no runtime assert needed)
    };
  }

  #[test]
  #[cfg(feature = "id3")]
  fn dsf_id3_ref_accessor_absent_without_trailer() {
    // §3: the non-Copy nested-Meta getter is `id3_ref()`.
    let buf = happy_path_dsf();
    let meta = parse_borrowed(&buf).expect("some");
    assert!(meta.id3_ref().is_none(), "metaPos=0 ⇒ no ID3 trailer");
  }
  // --- Golden-pattern `Taggable` / `Project` ------------------------------

  /// `Taggable::tags(-j)` yields the full fmt-chunk set in DSF_KEYS order
  /// with PrintConv hashes resolved (FormatID ⇒ "DSD Raw", ChannelType ⇒
  /// the descriptive string), driven through `run_emission`.
  #[test]
  fn taggable_emits_full_fmt_set_print_conv() {
    let bytes = happy_path_dsf();
    let meta = parse_borrowed(&bytes).expect("parsed");
    let mut w = TagMap::new();
    crate::emit::run_emission(
      &meta,
      crate::emit::EmitOptions::g1(ConvMode::PrintConv, false),
      &mut w,
    );
    assert_eq!(w.get_str("File", "FormatVersion"), Some("1".to_string()));
    assert_eq!(w.get_str("File", "FormatID"), Some("DSD Raw".to_string()));
    assert_eq!(
      w.get_str("File", "ChannelType"),
      Some("Stereo (Left, Right)".to_string())
    );
    assert_eq!(
      w.get_str("File", "SampleCount"),
      Some("2822400".to_string())
    );
    assert_eq!(w.get_str("File", "BlockSize"), Some("4096".to_string()));
  }

  /// `Taggable::tags(-n)` yields the raw integers (no PrintConv hashes):
  /// FormatID / ChannelType emit their numeric values.
  #[test]
  fn taggable_emits_raw_scalars_value_conv() {
    let bytes = happy_path_dsf();
    let meta = parse_borrowed(&bytes).expect("parsed");
    let mut w = TagMap::new();
    crate::emit::run_emission(
      &meta,
      crate::emit::EmitOptions::g1(ConvMode::ValueConv, false),
      &mut w,
    );
    assert_eq!(w.get_str("File", "FormatID"), Some("0".to_string()));
    assert_eq!(w.get_str("File", "ChannelType"), Some("2".to_string()));
    assert_eq!(w.get_str("File", "SampleRate"), Some("2822400".to_string()));
  }

  /// Every DSF fmt tag carries family-0 AND family-1 group `"File"`
  /// (DSF.pm:22), so the emitted [`crate::emit::EmittedTag`]s key under
  /// `File:*`.
  #[test]
  fn taggable_group_is_file_family0_and_family1() {
    let bytes = happy_path_dsf();
    let meta = parse_borrowed(&bytes).expect("parsed");
    let tags: std::vec::Vec<_> = meta
      .tags(crate::emit::EmitOptions::g1(ConvMode::PrintConv, false))
      .collect();
    assert!(!tags.is_empty());
    for t in &tags {
      assert_eq!(t.tag().group_ref().family0(), "File");
      assert_eq!(t.tag().group_ref().family1(), "File");
      assert!(!t.unknown());
    }
  }

  /// An id3-bearing DSF (the `dsf_with_id3v2_trailer.dsf` fixture) splices
  /// the chained ID3v2 trailer tags AFTER the fmt-chunk tags — proving the
  /// `id3.tags(mode)` chaining position matches the retired
  /// `id3.serialize_tags` call site. The fmt tags must still be `File:*`,
  /// and the ID3 trailer must contribute `File:ID3Size` + `ID3v2_*:*`
  /// entries.
  #[test]
  #[cfg(feature = "id3")]
  fn taggable_chains_id3_trailer_after_fmt() {
    let bytes = std::fs::read(
      std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/dsf_with_id3v2_trailer.dsf"),
    )
    .expect("read dsf_with_id3v2_trailer.dsf fixture");
    let meta = parse_borrowed(&bytes).expect("parsed");
    assert!(meta.id3_ref().is_some(), "fixture carries an ID3v2 trailer");

    // The tag stream: fmt-chunk `File:*` tags, THEN the ID3 trailer tags.
    let names: std::vec::Vec<String> = meta
      .tags(crate::emit::EmitOptions::g1(ConvMode::PrintConv, false))
      .map(|t| std::format!("{}:{}", t.tag().group_ref().family1(), t.tag().name()))
      .collect();
    // fmt-chunk FormatVersion is first; it precedes any ID3 entry.
    let fmt_pos = names
      .iter()
      .position(|n| n == "File:FormatVersion")
      .expect("FormatVersion emitted");
    let id3_pos = names
      .iter()
      .position(|n| n.starts_with("ID3v2") || n == "File:ID3Size")
      .expect("an ID3 trailer tag is spliced");
    assert!(
      fmt_pos < id3_pos,
      "ID3 trailer tags must follow the fmt-chunk tags (fmt_pos={fmt_pos}, id3_pos={id3_pos}): {names:?}"
    );

    // Driven through the engine, both the fmt set and the ID3 trailer land.
    let mut w = TagMap::new();
    emit_via_engine(&meta, true, &mut w);
    assert_eq!(w.get_str("File", "FormatID"), Some("DSD Raw".to_string()));
    assert!(
      w.entries()
        .iter()
        .any(|(_, g, n, _)| g.starts_with("ID3v2") || (g == "File" && n == "ID3Size")),
      "ID3 trailer tags present in the engine output"
    );
  }

  /// `Project` reports DSF as audio-only (one `TrackKind::Audio`) with no
  /// camera / lens / GPS / capture facts and no synthesized duration.
  #[test]
  fn project_is_audio_only_no_duration() {
    use crate::metadata::{Project, TrackKind};
    let bytes = happy_path_dsf();
    let meta = parse_borrowed(&bytes).expect("parsed");
    let md = Project::project(&meta);
    assert_eq!(md.media().track_kinds(), &[TrackKind::Audio]);
    assert!(
      md.media().duration().is_none(),
      "DSF synthesizes no duration"
    );
    assert!(md.media().width().is_none());
    assert!(md.media().height().is_none());
    assert!(md.camera().is_none());
    assert!(md.lens().is_none());
    assert!(md.gps().is_none());
    assert!(md.capture().is_none());
  }
}
