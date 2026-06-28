// SPDX-License-Identifier: GPL-3.0-or-later
// exifast — a 1:1 Rust port of ExifTool (Phil Harvey). See THIRD_PARTY.md.

//! The faithful PNG parse layer: a typed mirror of the chunks decoded by
//! [`crate::formats::png::ProcessPng`].
//!
//! These structs follow the source-format shape (`PNG.pm` chunk tables —
//! `IHDR`, `pHYs`, `iCCP`, `tEXt`/`zTXt`/`iTXt`, `eXIf`). The normalized
//! [`crate::metadata::MediaMetadata`] projection is built FROM this layer
//! via [`crate::metadata::MediaMetadata::from_png`].
//!
//! D8: no public struct fields anywhere; accessors only. Enums are
//! newtype/unit-only.

#![cfg(feature = "png")]

use smol_str::SmolStr;
use std::{string::String, vec::Vec};

// ===========================================================================
// PngColorType — IHDR byte 9 (PNG.pm:400-410)
// ===========================================================================

/// The PNG color type from `IHDR` byte 9 (`PNG.pm:400-410`).
///
/// `PrintConv => {0=>'Grayscale', 2=>'RGB', 3=>'Palette', 4=>'Grayscale with
/// Alpha', 6=>'RGB with Alpha'}` — every other byte value falls through to
/// [`PngColorType::Other`] (preserved verbatim, as bundled emits the raw
/// numeric value when the PrintConv has no entry).
///
/// D8: enum newtype-only; predicates `is_*` for each variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PngColorType {
  /// `0` — Grayscale.
  Grayscale,
  /// `2` — RGB.
  Rgb,
  /// `3` — Palette indexed.
  Palette,
  /// `4` — Grayscale with Alpha.
  GrayscaleAlpha,
  /// `6` — RGB with Alpha.
  RgbAlpha,
  /// Any other byte value — preserved verbatim.
  Other(u8),
}

impl PngColorType {
  /// Classify the raw `IHDR` byte 9 (`PNG.pm:400-410`). Total — every byte
  /// value resolves (unknowns to [`PngColorType::Other`]).
  #[inline(always)]
  #[must_use]
  pub const fn from_byte(byte: u8) -> Self {
    match byte {
      0 => Self::Grayscale,
      2 => Self::Rgb,
      3 => Self::Palette,
      4 => Self::GrayscaleAlpha,
      6 => Self::RgbAlpha,
      n => Self::Other(n),
    }
  }

  /// The raw `IHDR` byte 9 this color type corresponds to.
  #[inline(always)]
  #[must_use]
  pub const fn as_byte(&self) -> u8 {
    match self {
      Self::Grayscale => 0,
      Self::Rgb => 2,
      Self::Palette => 3,
      Self::GrayscaleAlpha => 4,
      Self::RgbAlpha => 6,
      Self::Other(n) => *n,
    }
  }

  /// The bundled `PrintConv` label for this color type, or `None` if not in
  /// `PNG.pm:400-410`'s table.
  #[inline(always)]
  #[must_use]
  pub const fn print_conv(&self) -> Option<&'static str> {
    match self {
      Self::Grayscale => Some("Grayscale"),
      Self::Rgb => Some("RGB"),
      Self::Palette => Some("Palette"),
      Self::GrayscaleAlpha => Some("Grayscale with Alpha"),
      Self::RgbAlpha => Some("RGB with Alpha"),
      Self::Other(_) => None,
    }
  }

  /// `true` for [`PngColorType::Grayscale`] (raw byte 0).
  #[inline(always)]
  #[must_use]
  pub const fn is_grayscale(&self) -> bool {
    matches!(self, Self::Grayscale)
  }

  /// `true` for [`PngColorType::Rgb`] (raw byte 2).
  #[inline(always)]
  #[must_use]
  pub const fn is_rgb(&self) -> bool {
    matches!(self, Self::Rgb)
  }

  /// `true` for [`PngColorType::Palette`] (raw byte 3).
  #[inline(always)]
  #[must_use]
  pub const fn is_palette(&self) -> bool {
    matches!(self, Self::Palette)
  }

  /// `true` for [`PngColorType::GrayscaleAlpha`] (raw byte 4).
  #[inline(always)]
  #[must_use]
  pub const fn is_grayscale_alpha(&self) -> bool {
    matches!(self, Self::GrayscaleAlpha)
  }

  /// `true` for [`PngColorType::RgbAlpha`] (raw byte 6).
  #[inline(always)]
  #[must_use]
  pub const fn is_rgb_alpha(&self) -> bool {
    matches!(self, Self::RgbAlpha)
  }

  /// `true` for [`PngColorType::Other`] (any byte value not in the table).
  #[inline(always)]
  #[must_use]
  pub const fn is_other(&self) -> bool {
    matches!(self, Self::Other(_))
  }
}

// ===========================================================================
// PngTextKind — provenance of a [`PngTextRecord`]
// ===========================================================================

/// The chunk type that produced a [`PngTextRecord`]. `PNG.pm:258-300`:
/// `tEXt` is the plain Latin-1 keyword/value chunk, `zTXt` is the
/// zlib-compressed Latin-1 variant (now INFLATED at parse time — a clean
/// `zTXt` is stored as a `tEXt`-kind record carrying the decompressed value;
/// see [`PngTextRecord::is_compressed`]), and `iTXt` is the UTF-8 variant with
/// an optional language tag + translated keyword.
///
/// D8: enum unit-variant only; predicates `is_*` for each variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PngTextKind {
  /// `tEXt` (`PNG.pm:258-261`) — plain Latin-1.
  TEXt,
  /// `zTXt` (`PNG.pm:294-300`) — zlib-compressed Latin-1.
  ZTXt,
  /// `iTXt` (`PNG.pm:197-203`) — UTF-8 with optional language tag.
  ITXt,
}

impl PngTextKind {
  /// The 4-character PNG chunk type (e.g. `"tEXt"`).
  #[inline(always)]
  #[must_use]
  pub const fn as_chunk_type(&self) -> &'static str {
    match self {
      Self::TEXt => "tEXt",
      Self::ZTXt => "zTXt",
      Self::ITXt => "iTXt",
    }
  }

  /// `true` for the `tEXt` chunk type.
  #[inline(always)]
  #[must_use]
  pub const fn is_text(&self) -> bool {
    matches!(self, Self::TEXt)
  }

  /// `true` for the `zTXt` chunk type.
  #[inline(always)]
  #[must_use]
  pub const fn is_ztxt(&self) -> bool {
    matches!(self, Self::ZTXt)
  }

  /// `true` for the `iTXt` chunk type.
  #[inline(always)]
  #[must_use]
  pub const fn is_itxt(&self) -> bool {
    matches!(self, Self::ITXt)
  }
}

// ===========================================================================
// PngTextRecord — one decoded text chunk
// ===========================================================================

// ===========================================================================
// IhdrFields — chunk-walker hand-off type for the IHDR setter
// ===========================================================================

/// The 7 IHDR fields the chunk walker passes to [`PngMeta::set_ihdr`]
/// (`PNG.pm:387-423` — width, height, bit-depth, color-type, compression,
/// filter, interlace). Bundled the values come straight off
/// `ProcessBinaryData`; this struct is the in-Rust analogue, kept
/// `pub(crate)` since the walker is the only constructor.
///
/// D8: no public fields; the chunk walker constructs via the public
/// associated `new` constructor and the setter consumes the whole struct.
#[derive(Debug, Clone, Copy)]
pub(crate) struct IhdrFields {
  pub(crate) width: u32,
  pub(crate) height: u32,
  pub(crate) bit_depth: u8,
  pub(crate) color_type: u8,
  pub(crate) compression: u8,
  pub(crate) filter: u8,
  pub(crate) interlace: u8,
}

/// One decoded PNG text chunk (`tEXt` / `zTXt` / `iTXt`).
///
/// Faithful to `PNG.pm`'s `ProcessPNG_tEXt` (`:1325-1332`) / `ProcessPNG_iTXt`
/// (`:1339-1351`) / `ProcessPNG_Compressed` (`:1288-1318`) split: each chunk
/// type is parsed into a `keyword`, a `value`, and (for `iTXt`) an
/// optional language tag + translated keyword.
///
/// **`zTXt` / compressed-`iTXt` are now zlib-INFLATED at parse time**
/// (`PNG.pm:929-948 FoundPNG`). On a clean inflate the decompressed value is
/// decoded (Latin-1 for `zTXt`, UTF-8 for `iTXt`) and the record is stored as
/// if it had been an uncompressed `tEXt` / `iTXt` — [`Self::is_compressed`] is
/// `false` and [`Self::value`] carries the text. A corrupt zlib stream leaves
/// the value empty and records the bundled `Error inflating <keyword>` warning
/// (`PNG.pm:942`); a non-zero compression method records `Unknown compression
/// method <n> for <keyword>` (`PNG.pm:951`). In those warning cases the record
/// stays flagged compressed. The keyword is always decoded (it lives BEFORE
/// the compression flag).
///
/// D8: no public fields; accessors only. Bounded-short strings
/// (`keyword`, `language`, `translated_keyword`) are [`SmolStr`]
/// per `[[exifast-smolstr-rule]]`; the unbounded value is [`String`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PngTextRecord {
  /// Provenance: `tEXt` / `zTXt` / `iTXt`.
  kind: PngTextKind,
  /// The keyword (`tEXt`/`zTXt`: 1-79 Latin-1 chars; `iTXt`: 1-79 Latin-1).
  keyword: SmolStr,
  /// The decoded text value. For a `zTXt` / compressed `iTXt` whose zlib
  /// stream FAILED to inflate (or used an unknown compression method), this is
  /// empty (a warning was recorded instead — see the type-level docs); a clean
  /// inflate populates it with the decompressed text.
  value: String,
  /// `iTXt` RFC-3066 language tag (`PNG.pm:1345`). Empty `""` is preserved
  /// verbatim (bundled normalizes case via `StandardLangCase`); not present
  /// on `tEXt` / `zTXt`.
  language: Option<SmolStr>,
  /// `iTXt` translated keyword (`PNG.pm:1345`); not present on `tEXt` /
  /// `zTXt`.
  translated_keyword: Option<SmolStr>,
  /// Whether this record's compressed payload was NOT decoded — `true` only
  /// for a `zTXt` / compressed `iTXt` whose zlib stream failed to inflate or
  /// used an unknown compression method. When `true`, [`Self::value`] is empty
  /// and the parser's `warnings` list carries the `Error inflating <keyword>`
  /// (`PNG.pm:942`) or `Unknown compression method <n> for <keyword>`
  /// (`PNG.pm:951`) message. A cleanly inflated `zTXt`/`iTXt` is stored with
  /// `is_compressed == false` (it is indistinguishable from an uncompressed
  /// chunk at emission time).
  is_compressed: bool,
}

impl PngTextRecord {
  /// Construct a plain `tEXt` record (Latin-1 → UTF-8 decoded).
  #[inline(always)]
  #[must_use]
  pub fn new_text(keyword: SmolStr, value: String) -> Self {
    Self {
      kind: PngTextKind::TEXt,
      keyword,
      value,
      language: None,
      translated_keyword: None,
      is_compressed: false,
    }
  }

  /// Construct a `zTXt` record whose compressed payload was NOT decoded —
  /// used only when the zlib stream fails to inflate or uses an unknown
  /// compression method (the parser records the matching warning). On a clean
  /// inflate the parser instead stores a `tEXt`-kind record via
  /// [`Self::new_text`] carrying the decompressed value. The keyword IS
  /// preserved either way (it lives BEFORE the compression-method byte).
  #[inline(always)]
  #[must_use]
  pub fn new_ztxt_deferred(keyword: SmolStr) -> Self {
    Self {
      kind: PngTextKind::ZTXt,
      keyword,
      value: String::new(),
      language: None,
      translated_keyword: None,
      is_compressed: true,
    }
  }

  /// Construct an `iTXt` record. `language` and `translated_keyword` may
  /// be empty `""` (bundled preserves both). `compressed` mirrors the
  /// compression-flag byte; when `true`, `value` should be empty (the
  /// payload is dropped — zlib inflate is deferred).
  #[inline(always)]
  #[must_use]
  pub fn new_itxt(
    keyword: SmolStr,
    value: String,
    language: SmolStr,
    translated_keyword: SmolStr,
    compressed: bool,
  ) -> Self {
    Self {
      kind: PngTextKind::ITXt,
      keyword,
      value,
      language: Some(language),
      translated_keyword: Some(translated_keyword),
      is_compressed: compressed,
    }
  }

  /// The chunk type that produced this record.
  #[inline(always)]
  #[must_use]
  pub const fn kind(&self) -> PngTextKind {
    self.kind
  }

  /// The keyword (`PNG.pm:1328` / `1342`).
  #[inline(always)]
  #[must_use]
  pub fn keyword(&self) -> &str {
    self.keyword.as_str()
  }

  /// The decoded text value (empty for a deferred compressed record).
  #[inline(always)]
  #[must_use]
  pub fn value(&self) -> &str {
    self.value.as_str()
  }

  /// The `iTXt` language tag, if any (RFC 3066, `PNG.pm:1345`).
  #[inline(always)]
  #[must_use]
  pub fn language(&self) -> Option<&str> {
    self.language.as_deref()
  }

  /// The `iTXt` translated keyword, if any.
  #[inline(always)]
  #[must_use]
  pub fn translated_keyword(&self) -> Option<&str> {
    self.translated_keyword.as_deref()
  }

  /// `true` only for a `zTXt` / compressed `iTXt` whose zlib stream could NOT
  /// be inflated (corrupt stream or unknown compression method) — the value
  /// bytes were dropped and a warning recorded. A cleanly inflated compressed
  /// chunk returns `false` (it is stored like an uncompressed record).
  #[inline(always)]
  #[must_use]
  pub const fn is_compressed(&self) -> bool {
    self.is_compressed
  }
}

// ===========================================================================
// PngDynamicProfileTag — a `FoundPNG` dynamically-added tag (PNG.pm:1116-1124)
// ===========================================================================

/// A tag bundled's `FoundPNG` (`PNG.pm:1116-1124`) creates dynamically — the
/// `else` branch reached when NO `tagInfo` resolves for the keyword. Two
/// chunk-walk situations land here, BOTH oracle-confirmed against
/// `perl exiftool -j -G1` 13.59:
///
/// 1. **A registered `Raw profile type {exif,APP1,icc,icm,iptc,8bim,xmp}`
///    SubDirectory keyword carried in an `iTXt` with a NON-EMPTY language.**
///    `GetLangInfo` (`PNG.pm:890-898`) returns `undef` for any `SubDirectory`
///    tag (`PNG.pm:895`), so the `not $tagInfo and $lang` fallback
///    (`PNG.pm:923-926`) cannot recover a localized tagInfo and the keyword is
///    NOT routed to `ProcessProfile`. (`tEXt`/`zTXt` have no language field, so
///    a registered keyword there ALWAYS routes to the SubDirectory —
///    [`PngExifEvent`] — never here.)
/// 2. **Any UNREGISTERED `Raw profile type *` keyword** (e.g.
///    `Raw profile type generic`), in `tEXt` / `zTXt` / `iTXt` regardless of
///    language — there is no table entry at all.
///
/// In the `else` branch bundled builds `$tagInfo = { Name => $name }` where
/// `($name = $tag) =~ s/\s+(.)/\u$1/g` collapses whitespace runs and
/// uppercases the following char ([`png_dynamic_tag_name`] also applies the
/// `tr/-_a-zA-Z0-9//dc` illegal-char strip + first-letter `ucfirst` that
/// `GetTagInfoList` (`ExifTool.pm:9256-9257`) imposes on EVERY added tag). It
/// then sets `$$tagInfo{Binary} = 1 if $tag =~ /^Raw profile type /`
/// (`PNG.pm:1122`) — keyed on the ORIGINAL keyword `$tag`, case-sensitive, with
/// literal single spaces. `FoundTag($tagInfo, $val)` stores `$val` — the
/// chunk's value AFTER `$et->Decode($val, $enc)` (`PNG.pm:964-966`, which runs
/// here because `$tagInfo` was still `undef` at that point) — so the stored
/// bytes are the DECODED value (Latin-1→UTF-8 for `tEXt`/`zTXt`, UTF-8 for
/// `iTXt`), exactly what `-b` re-emits.
///
/// `binary == true` (the `/^Raw profile type /` match) renders as the universal
/// `(Binary data N bytes, use -b option to extract)` placeholder at ANY size
/// (oracle: even 0- and 1-byte values render as the placeholder, NO size
/// threshold). `binary == false` (a keyword whose original form does NOT match
/// the regex — e.g. lowercase `raw profile type …` or a double-space variant)
/// emits the decoded value as plain text. Crucially this path NEVER touches
/// `$$et{PROCESSED}` (it bypasses `ProcessProfile`), so it emits NO
/// [`PngExifEvent`] and performs NO cross-source reset.
///
/// D8: no public fields; accessors only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PngDynamicProfileTag {
  /// The normalized tag name (`PNG.pm:1118` + `ExifTool.pm:9256-9257`), e.g.
  /// `RawProfileTypeExif`. Emitted under the `PNG` family-1 group.
  name: SmolStr,
  /// The DECODED value bytes (`$val` after `PNG.pm:964` `Decode`). Rendered as
  /// the `(Binary data N bytes, …)` placeholder when [`Self::is_binary`].
  value: Vec<u8>,
  /// `true` when the ORIGINAL keyword matched `/^Raw profile type /`
  /// (`PNG.pm:1122` `$$tagInfo{Binary} = 1`) — render as the binary-data
  /// placeholder; `false` ⇒ render the decoded value as plain text.
  binary: bool,
}

impl PngDynamicProfileTag {
  /// Construct a dynamic profile tag from its normalized `name`, decoded
  /// `value` bytes, and `binary` flag.
  #[inline(always)]
  #[must_use]
  pub fn new(name: SmolStr, value: Vec<u8>, binary: bool) -> Self {
    Self {
      name,
      value,
      binary,
    }
  }

  /// The normalized tag name (e.g. `RawProfileTypeExif`).
  #[inline(always)]
  #[must_use]
  pub fn name(&self) -> &str {
    self.name.as_str()
  }

  /// The decoded value bytes (`-b` output).
  #[inline(always)]
  #[must_use]
  pub fn value(&self) -> &[u8] {
    &self.value
  }

  /// Whether bundled flagged this `Binary => 1` (`PNG.pm:1122`) — emit the
  /// `(Binary data N bytes, …)` placeholder rather than the value as text.
  #[inline(always)]
  #[must_use]
  pub const fn is_binary(&self) -> bool {
    self.binary
  }
}

// ===========================================================================
// PngExifEvent — one EXIF-relevant event in the PNG chunk-walk event stream
// ===========================================================================

/// One EXIF-relevant event emitted by the PNG chunk walk, in chunk (walk)
/// order. A PNG's EXIF-bearing chunks form an ORDERED event stream that bundled
/// replays through ONE shared `$$et{PROCESSED}` map
/// (`ExifTool.pm:9061-9072` + `PNG.pm:1193`); this enum is the faithful typed
/// mirror of bundled's object-level `ProcessTIFF` / `ProcessProfile` sequence.
///
/// **Why an event stream (not a `(bool, block)` source).** Bundled's
/// per-directory cycle-guard is keyed on each chain directory's `$addr`
/// (`ExifTool.pm:9066`) over a SINGLE `$$et{PROCESSED}` set spanning the whole
/// file. `ProcessProfile` (`PNG.pm:1193`) CLEARS that set BEFORE dispatching the
/// decoded profile — and crucially it does so for EVERY well-formed raw profile,
/// whether or not the profile carries EXIF (oracle-verified against
/// `perl exiftool -j -G1` 13.59: an `icc`/`iptc`/`8bim`/`xmp` profile, AND an
/// `exif`/`APP1` profile whose decoded content is XMP or unrecognized, ALL reset
/// the set between two `eXIf` sources, un-blocking the second). A MALFORMED raw
/// profile (whose `^\n(.*?)\n\s*(\d+)\n(.*)` framing fails, `PNG.pm:1166`) makes
/// `ProcessProfile` `return 0` BEFORE the reset, so it neither resets nor
/// processes — it emits NO event at all. The native `eXIf`/`zxIf` chunks
/// (`PNG.pm:309-330`) feed `ProcessTIFF` with NO reset. Three distinct
/// behaviours ⇒ three variants; the boolean `is_profile` flag could not
/// distinguish the reset-only profiles (which carry no EXIF) from a no-op.
///
/// The replay ([`crate::formats::png::replay_exif_events`]) walks this stream
/// once for tag emission ([`crate::formats::png::ProcessPng`]'s `tags()`), the
/// domain projection, and the warning drain, so all three agree on exactly which
/// directories win and which warn.
///
/// D8: enum with no public fields; accessors only. The owned blocks are small
/// `Vec`s (even a phone screenshot's EXIF block is < 10 KB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PngExifEvent {
  /// A native `eXIf` / `zxIf` chunk (`PNG.pm:309-330`, incl. a `%stdCase`
  /// case-variant), or the inflated TIFF of a `zxIf` — dispatched to
  /// `ProcessTIFF` with NO `$$et{PROCESSED}` reset. The payload is the raw
  /// `II`/`MM`-led TIFF block, stored as a `Box<[u8]>` so its allocation is
  /// EXACTLY its length by construction (no excess capacity): a retained inflated
  /// `zxIf` TIFF is charged by its byte length to the file-wide zXIf budget, and a
  /// `Box<[u8]>` makes that charge equal the retained allocation at the type level
  /// (not allocator-dependent — see [`crate::formats::png`]'s zXIf inflate path).
  NativeTiff(Box<[u8]>),
  /// An ImageMagick `Raw profile type exif` / `Raw profile type APP1` chunk
  /// (`PNG.pm:710`/`:689`) whose well-formed body decoded to a TIFF block
  /// (an `Exif\0\0`-prefixed or bare `II`/`MM` TIFF, `PNG.pm:1216-1265`) —
  /// `ProcessProfile` RESETS `$$et{PROCESSED}` (`PNG.pm:1193`) and then
  /// dispatches the TIFF to `ProcessTIFF`. The payload is the (marker-stripped)
  /// TIFF block.
  ExifProfile(Vec<u8>),
  /// A well-formed raw profile that does NOT yield an EXIF TIFF, yet still runs
  /// through `ProcessProfile` and so RESETS `$$et{PROCESSED}` (`PNG.pm:1193`)
  /// with no EXIF tags. This covers the non-EXIF profile kinds — `icc`/`icm`
  /// (`PNG.pm:719`/`:727`), `iptc` (`:735`), `8bim` (`:755`), `xmp` (`:746`) —
  /// AND the `exif`/`APP1` profiles whose decoded content is XMP
  /// (`PNG.pm:1236`) or unrecognized (`PNG.pm:1266`). exifast has no ported ICC
  /// / IPTC / Photoshop module, so their tags are deferred (none emitted), but
  /// the cross-source `$$et{PROCESSED}` reset is the load-bearing effect and IS
  /// modeled. For the XMP kinds (`xmp` and the XMP-content `exif`/`APP1` arm)
  /// the reset event is pushed ALONGSIDE the decoded packet in
  /// [`PngMeta::xmp_profiles`] (#179) — the ported XMP module emits the `XMP-*`
  /// tags while this event still performs the reset. Carries no payload (no EXIF
  /// block to walk).
  ResetOnlyProfile,
}

impl PngExifEvent {
  /// `true` for a native `eXIf` / `zxIf` chunk ([`Self::NativeTiff`]).
  #[inline(always)]
  #[must_use]
  pub const fn is_native(&self) -> bool {
    matches!(self, Self::NativeTiff(_))
  }

  /// `true` for a raw-profile EXIF TIFF ([`Self::ExifProfile`]) — the
  /// `ProcessProfile` reset-then-`ProcessTIFF` path.
  #[inline(always)]
  #[must_use]
  pub const fn is_exif_profile(&self) -> bool {
    matches!(self, Self::ExifProfile(_))
  }

  /// `true` for a well-formed non-EXIF raw profile ([`Self::ResetOnlyProfile`])
  /// — the `ProcessProfile` reset-only path (no EXIF tags).
  #[inline(always)]
  #[must_use]
  pub const fn is_reset_only(&self) -> bool {
    matches!(self, Self::ResetOnlyProfile)
  }

  /// The raw `II`/`MM`-led TIFF block for the EXIF-bearing variants
  /// ([`Self::NativeTiff`] / [`Self::ExifProfile`]); `None` for
  /// [`Self::ResetOnlyProfile`] (it has no EXIF block). Pass `Some` to
  /// [`crate::exif::parse_exif_block`] to walk the embedded IFD chain.
  #[inline(always)]
  #[must_use]
  pub fn block(&self) -> Option<&[u8]> {
    match self {
      Self::NativeTiff(b) => Some(b),
      Self::ExifProfile(b) => Some(b),
      Self::ResetOnlyProfile => None,
    }
  }
}

// ===========================================================================
// PngContainer — which PNG-sibling container the signature selected
// ===========================================================================

/// Which of the three PNG-sibling containers the 8-byte signature selected
/// (`%pngLookup`, `PNG.pm:61-65`). Drives the resolved `File:FileType` (via
/// [`crate::formats::png::ProcessPng`]'s finalize arm) and — for MNG/JNG — the
/// `%MNG::Main` chunk-table FALLBACK (`PNG.pm:1444-1446`). The signature is
/// authoritative (`SetFileType($fileType)`, `PNG.pm:1439`), independent of the
/// filename extension.
///
/// D8: enum unit-variant only; predicates + `as_file_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PngContainer {
  /// `\x89PNG\r\n\x1a\n` → PNG (hdr `IHDR`, end `IEND`).
  #[default]
  Png,
  /// `\x8aMNG\r\n\x1a\n` → MNG (hdr `MHDR`, end `MEND`).
  Mng,
  /// `\x8bJNG\r\n\x1a\n` → JNG (hdr `JHDR`, end `IEND`).
  Jng,
}

impl PngContainer {
  /// The base `File:FileType` NAME this container finalizes to (`PNG.pm:61-65`'s
  /// first column). An animated PNG further overrides `PNG` → `APNG` later.
  #[inline]
  #[must_use]
  pub const fn as_file_type(self) -> &'static str {
    match self {
      Self::Png => "PNG",
      Self::Mng => "MNG",
      Self::Jng => "JNG",
    }
  }

  /// `true` for an MNG or JNG container — the two that engage the `%MNG::Main`
  /// chunk-table fallback (`PNG.pm:1444` `$fileType ne 'PNG'`).
  #[inline]
  #[must_use]
  pub const fn is_mng_family(self) -> bool {
    matches!(self, Self::Mng | Self::Jng)
  }

  /// `true` for the plain PNG container.
  #[inline]
  #[must_use]
  pub const fn is_png(self) -> bool {
    matches!(self, Self::Png)
  }
}

// ===========================================================================
// PngMeta — the faithful PNG parse layer
// ===========================================================================

/// The faithful PNG parse layer — a typed mirror of the chunks decoded by
/// [`crate::formats::png::ProcessPng`].
///
/// **Field shape follows `PNG.pm`'s chunk tables exactly.** Every chunk is
/// optional (a stripped PNG can omit any of them); the chunk-walk order is
/// the file order (which we preserve in [`Self::text_records`]).
///
/// **MakerNote-bearing eXIf chunks.** A real-camera PNG screenshot
/// (iPhone screenshot, Android share-sheet PNG) carries Exif via the
/// `eXIf` chunk (`PNG.pm:309-317`, dispatching to `Image::ExifTool::Exif`'s
/// `Main` table via `ProcessTIFF`). The captured Exif IFD chain is
/// produced through [`crate::exif::parse_exif_block`] and EMITTED inline
/// at serialize time — only the OWNED PNG-level facts (`PngMeta` proper)
/// land here. The lifetime `'a` is carried for future Exif sub-Meta
/// embedding (currently a phantom).
///
/// D8: no public fields; accessors only.
#[derive(Debug, Clone, PartialEq)]
pub struct PngMeta<'a> {
  // ----- IHDR (PNG.pm:193-196, sub-table PNG.pm:387-423) ----------------
  /// `IHDR.ImageWidth` (`PNG.pm:391-394`).
  width: Option<u32>,
  /// `IHDR.ImageHeight` (`PNG.pm:395-398`).
  height: Option<u32>,
  /// `IHDR.BitDepth` (`PNG.pm:399`).
  bit_depth: Option<u8>,
  /// `IHDR.ColorType` (`PNG.pm:400-410`).
  color_type: Option<PngColorType>,
  /// `IHDR.Compression` (`PNG.pm:411-414`). Only `0` is defined.
  compression: Option<u8>,
  /// `IHDR.Filter` (`PNG.pm:415-418`). Only `0` is defined.
  filter: Option<u8>,
  /// `IHDR.Interlace` (`PNG.pm:419-422`). `0` = Noninterlaced, `1` = Adam7.
  interlace: Option<u8>,
  // ----- acTL (animated PNG, PNG.pm:302-307 + sub-table PNG.pm:766-782) --
  /// `acTL.AnimationFrames` (`AnimationControl` tag 0, `int32u`,
  /// `PNG.pm:774-777`) — the APNG `num_frames`. Its RawConv
  /// (`$self->OverrideFileType("APNG", undef, "PNG"); $val`) emits the value
  /// UNCHANGED but, as a side effect, promotes `File:FileType` to `APNG`
  /// (driven by [`Self::is_apng`]). PER-GROUP ([`ActlValues`]): a pre-`IEND`
  /// `acTL` (→ `PNG:AnimationFrames`) and a post-`IEND` trailer `acTL`
  /// (→ `Trailer:AnimationFrames`, `PNG.pm:1484`) are kept SEPARATELY so a
  /// trailer-only frame count does not re-group the main one (and vice-versa);
  /// each occurrence emits under its OWN family-1 group (oracle-verified vs
  /// 13.59). All-`None` when no `acTL` chunk was seen.
  animation_frames: ActlValues,
  /// `acTL.AnimationPlays` (`AnimationControl` tag 1, `int32u`,
  /// `PNG.pm:778-781`) — the APNG `num_plays`. The raw value is stored; the
  /// PrintConv `$val || "inf"` (`0` ⇒ `"inf"`) is applied at emission. PER-GROUP
  /// ([`ActlValues`]): kept SEPARATELY from `AnimationFrames`'s provenance — a
  /// 4-to-7-byte trailer `acTL` carries only `AnimationFrames` (bytes `4..8`
  /// absent), so its `trailer` slot stays `None` and the main
  /// `PNG:AnimationPlays` is NOT re-grouped to `Trailer`. All-`None` when no
  /// `acTL` chunk supplied bytes `4..8`.
  animation_plays: ActlValues,
  // ----- iDOT (PNG.pm:331-342) -----------------------------------------
  /// `iDOT.AppleDataOffsets` — Apple's private "data offsets" chunk
  /// (`Name => 'AppleDataOffsets', Binary => 1`, NO SubDirectory). Only the
  /// payload LENGTH is retained: the tag is `Binary => 1` and renders as the
  /// universal `(Binary data N bytes, …)` placeholder (`-j`), which derives
  /// from the byte count alone — bundled `-b` extracts the raw bytes, but the
  /// JSON path never touches them. Storing the length (not the payload) keeps
  /// a crafted large-but-present `iDOT` chunk from forcing a payload-sized
  /// allocation. PER-GROUP ([`BinaryChunkLengths`]): a PNG can carry `iDOT`
  /// BOTH before `IEND` (→ `PNG:AppleDataOffsets`) AND after it
  /// (→ `Trailer:AppleDataOffsets`); bundled emits BOTH under their distinct
  /// family-1 groups (oracle-verified vs 13.59), so the main and the
  /// post-`IEND` trailer lengths are kept SEPARATELY (each region last-wins).
  /// All-`None` when no `iDOT` chunk was seen.
  apple_data_offsets: BinaryChunkLengths,
  // ----- gdAT (PNG.pm:374-378) -----------------------------------------
  /// `gdAT.GainMapImage` — the gain-map preview image chunk (`Name =>
  /// 'GainMapImage', Groups => { 2 => 'Preview' }, Binary => 1`, NO
  /// SubDirectory — the same shape as `iDOT`). Only the payload LENGTH is
  /// retained: like `iDOT` it renders as the `(Binary data N bytes, …)`
  /// placeholder (`-j`) from the byte count alone (`-b` extracts the raw
  /// bytes), so the embedded image is never cloned. PER-GROUP
  /// ([`BinaryChunkLengths`]): a pre-`IEND` `gdAT` (→ `PNG:GainMapImage`) and a
  /// post-`IEND` trailer `gdAT` (→ `Trailer:GainMapImage`) BOTH emit under
  /// their distinct family-1 groups (oracle-verified vs 13.59), so their
  /// lengths are kept separately (each region last-wins). All-`None` when no
  /// `gdAT` chunk was seen.
  gain_map_image: BinaryChunkLengths,
  // ----- pHYs (PNG.pm:216-222, sub-table PNG.pm:441-468) ----------------
  /// `pHYs.PixelsPerUnitX` (`PNG.pm:453-457`).
  pixels_per_unit_x: Option<u32>,
  /// `pHYs.PixelsPerUnitY` (`PNG.pm:458-462`).
  pixels_per_unit_y: Option<u32>,
  /// `pHYs.PixelUnits` (`PNG.pm:463-467`). `0` = unknown, `1` = meters.
  pixel_units: Option<u8>,
  // ----- cICP (PNG.pm:348-353, sub-table PNG.pm:471-541) ----------------
  /// `cICP.ColorPrimaries` (`CICodePoints` tag 0, `int8u`, `PNG.pm:479-495`).
  /// The HDR color-primaries code point; its PrintConv (`PNG.pm:481-494`)
  /// renders the named primaries (`9` → `BT.2020, BT.2100`), falling through
  /// to the raw number for an unmapped code. Each cICP field is INDEPENDENTLY
  /// available (`ProcessBinaryData` per-offset), so a runt 1-to-3-byte cICP
  /// supplies only the leading fields. PER-GROUP ([`RegionValue`]): a pre-`IEND`
  /// `cICP` (→ `PNG-cICP:ColorPrimaries`) and a post-`IEND` trailer `cICP`
  /// (→ `Trailer:ColorPrimaries`, `PNG.pm:1484`) are kept SEPARATELY so a
  /// trailer chunk does not overwrite the main fields nor re-group them; both
  /// emit under their OWN family-1 group (oracle-verified vs 13.59). A TRUNCATED
  /// later same-region chunk that omits this field leaves the earlier value
  /// intact (present-only update). All-`None` when no `cICP` supplied byte 0.
  color_primaries: RegionValue<u8>,
  /// `cICP.TransferCharacteristics` (`CICodePoints` tag 1, `int8u`,
  /// `PNG.pm:496-519`). PrintConv renders the named transfer function (`16` →
  /// `SMPTE ST 2084, ITU BT.2100 PQ`), raw number otherwise. Needs byte 1.
  /// PER-GROUP ([`RegionValue`]): independent main/trailer slots, present-only.
  transfer_characteristics: RegionValue<u8>,
  /// `cICP.MatrixCoefficients` (`CICodePoints` tag 2, `int8u`,
  /// `PNG.pm:520-539`). PrintConv renders the named matrix (`9` → `BT.2020
  /// non-constant luminance, BT.2100 YCbCr`), raw number otherwise. Needs
  /// byte 2. PER-GROUP ([`RegionValue`]): independent main/trailer slots,
  /// present-only — a 2-byte later `cICP` that omits byte 2 keeps this value.
  matrix_coefficients: RegionValue<u8>,
  /// `cICP.VideoFullRangeFlag` (`CICodePoints` tag 3, `int8u`, `PNG.pm:540`).
  /// No PrintConv — the raw flag (`0`/`1`). Needs byte 3. PER-GROUP
  /// ([`RegionValue`]): independent main/trailer slots, present-only.
  video_full_range_flag: RegionValue<u8>,
  // ----- vpAg (PNG.pm:290-293, sub-table PNG.pm:561-573) ----------------
  /// `vpAg.VirtualImageWidth` (`VirtualPage` tag 0, `int32u`, `PNG.pm:566`) —
  /// ImageMagick's private virtual-page chunk. Raw number (no conv). Needs
  /// bytes `0..4`. PER-GROUP ([`RegionValue`]): a pre-`IEND` `vpAg`
  /// (→ `PNG:VirtualImageWidth`) and a post-`IEND` trailer `vpAg`
  /// (→ `Trailer:VirtualImageWidth`, `PNG.pm:1484`) kept SEPARATELY; both emit;
  /// a truncated later same-region chunk omitting this leaves it intact.
  virtual_image_width: RegionValue<u32>,
  /// `vpAg.VirtualImageHeight` (`VirtualPage` tag 1, `int32u`, `PNG.pm:567`).
  /// Raw number. Needs bytes `4..8` (INDEPENDENT of the width — an 8-byte
  /// vpAg supplies width+height but not the units byte). PER-GROUP
  /// ([`RegionValue`]): independent main/trailer slots, present-only.
  virtual_image_height: RegionValue<u32>,
  /// `vpAg.VirtualPageUnits` (`VirtualPage` tag 2, `int8u`, `PNG.pm:568-572`).
  /// Raw number (the table notes "what is the conversion for this?" — none).
  /// Needs byte 8. PER-GROUP ([`RegionValue`]): independent main/trailer slots,
  /// present-only — a 5-or-8-byte later `vpAg` omitting byte 8 keeps this value.
  virtual_page_units: RegionValue<u8>,
  // ----- iCCP (PNG.pm:171-181) -----------------------------------------
  /// `iCCP-name` — the ICC profile NAME (`PNG.pm:182-190` + 1304). The
  /// profile body bytes are NOT parsed (Phase-2 sub-port deferred).
  icc_profile_name: Option<SmolStr>,
  // ----- bKGD (PNG.pm:128-131) ----------------------------------------
  /// `bKGD.BackgroundColor` rendered as the bundled value string (`join
  /// " " unpack(length($val) < 2 ? "C" : "n*", $val)`, `PNG.pm:128-131`).
  background_color: Option<String>,
  // ----- tIME (PNG.pm:262-275) ----------------------------------------
  /// `tIME.ModifyDate` rendered as the bundled `sprintf` string
  /// (`PNG.pm:267`).
  modify_date: Option<String>,
  // ----- text chunks (tEXt / zTXt / iTXt) ----------------------------
  /// Every decoded text record in chunk-walk (file) order.
  text_records: Vec<PngTextRecord>,
  // ----- dynamically-added profile tags (PNG.pm:1116-1124) ------------
  /// Tags bundled's `FoundPNG` creates dynamically when NO `tagInfo` resolves
  /// for the keyword ([`PngDynamicProfileTag`]) — a registered raw-profile
  /// SubDirectory keyword in an `iTXt` WITH a language (`GetLangInfo` → `undef`,
  /// `PNG.pm:895`), or any unregistered `Raw profile type *` keyword. Kept in
  /// chunk-walk order; emitted after the text records. These NEVER touch
  /// `$$et{PROCESSED}` (no [`PngExifEvent`], no reset).
  dynamic_profile_tags: Vec<PngDynamicProfileTag>,
  // ----- EXIF event stream: eXIf/zxIf chunks + "Raw profile type X" -------
  /// The ordered EXIF-relevant event stream captured during the chunk walk, in
  /// WALK (chunk) ORDER ([`PngExifEvent`]). A native `eXIf`/`zxIf` chunk
  /// (`PNG.pm:309-330`) pushes [`PngExifEvent::NativeTiff`]; an ImageMagick
  /// `Raw profile type {exif,APP1}` chunk carrying a TIFF (`PNG.pm:1216-1265`)
  /// pushes [`PngExifEvent::ExifProfile`]; any OTHER well-formed raw profile
  /// (`icc`/`iptc`/`8bim`/`xmp`, or `exif`/`APP1` with XMP/unrecognized content)
  /// pushes [`PngExifEvent::ResetOnlyProfile`]. The stream is replayed through
  /// ONE shared `$$et{PROCESSED}` set (`ExifTool.pm:9061-9072` + `PNG.pm:1193`)
  /// by [`crate::formats::png::ProcessPng`]'s `tags()` / `project()` /
  /// warning-drain, so chunk order, the per-event kind, AND each TIFF's IFD0
  /// offset jointly decide which directories contribute and which warn (verified
  /// against `perl exiftool -j -G1`). Empty when the PNG carries no EXIF event.
  exif_events: Vec<PngExifEvent>,
  // ----- XMP raw profiles (PNG.pm:746 / :1216-1248) ----------------------
  /// The hex-decoded XMP packets captured from `Raw profile type xmp` chunks
  /// (`PNG.pm:746` → `ProcessProfile` → `ProcessDirectory(XMP::Main)`) and from
  /// the XMP-content arm of `Raw profile type {exif,APP1}` (`PNG.pm:1236`, after
  /// the `$xmpAPP1hdr` strip), in WALK (chunk) ORDER. Each entry is the raw XMP
  /// packet bytes bundled feeds to `ProcessXMP`; they are decoded into
  /// `XMP-*:*` tags by [`crate::formats::png::ProcessPng`]'s `tags()` /
  /// `project()` / warning-drain via [`crate::formats::xmp::parse_borrowed`]
  /// when the `xmp` feature is built. The `ResetOnlyProfile` event the same
  /// chunk pushes models the `$$et{PROCESSED}` reset (`PNG.pm:1193`); this field
  /// carries the decodable CONTENT. Gated on the `xmp` feature because the PNG
  /// port does not depend on the XMP module (`png = ["exif", …]`) — without it
  /// the packet is still captured by the chunk walk but no XMP tags are emitted
  /// (faithful to "no ported XMP module").
  #[cfg(feature = "xmp")]
  xmp_profiles: Vec<Vec<u8>>,
  // ----- trailer (post-IEND) bookkeeping (PNG.pm:1479-1484) --------------
  /// `true` once the chunk walker has crossed the `IEND` end chunk with
  /// unconsumed trailer bytes remaining and re-entered the chunk loop in
  /// TRAILER mode (`PNG.pm:1479-1484` sets `$$et{SET_GROUP1} = 'Trailer'`).
  /// While set, every chunk parsed is a TRAILER chunk: its PNG-level tags
  /// (and the GPS sub-IFD, but NOT the `Exif::Main`-table IFDs) carry the
  /// family-1 `Trailer` group override ([`crate::value::Group`]), faithfully
  /// to bundled's live `SET_GROUP1` global resolved in `GetGroup`
  /// (`ExifTool.pm:3860`) — see [`crate::formats::png::ProcessPng`]'s `tags`.
  in_trailer: bool,
  /// Index into [`Self::text_records`] at which the TRAILER text records
  /// begin (records `>= this` were parsed AFTER `IEND`). `usize::MAX` until
  /// the trailer is entered (no trailer ⇒ every record is pre-`IEND`).
  trailer_text_start: usize,
  /// Index into [`Self::dynamic_profile_tags`] at which the TRAILER dynamic
  /// tags begin. `usize::MAX` until the trailer is entered.
  trailer_dynamic_start: usize,
  /// Index into [`Self::exif_events`] at which the TRAILER EXIF events begin.
  /// `usize::MAX` until the trailer is entered.
  trailer_event_start: usize,
  /// Index into [`Self::xmp_profiles`] at which the TRAILER XMP profiles begin.
  /// `usize::MAX` until the trailer is entered.
  #[cfg(feature = "xmp")]
  trailer_xmp_start: usize,
  /// Index into [`Self::warnings`] at which the post-`IEND` TRAILER warnings
  /// begin (warnings `>= this` were raised while bundled's
  /// `$$et{SET_GROUP1} = 'Trailer'` (`PNG.pm:1484`) was active, so they surface
  /// as the family-1 `Trailer:Warning` TAG rather than the document-level
  /// `ExifTool:Warning`). `usize::MAX` until the trailer is entered. NOTE the
  /// `Trailer data after PNG IEND chunk` entry warning itself (`PNG.pm:1481`) is
  /// pushed by the walker BEFORE [`Self::begin_trailer`] sets `SET_GROUP1`, so
  /// its index is `< this` and it stays document-level (oracle-confirmed).
  trailer_warning_start: usize,
  /// Set when a structural single-value chunk (`IHDR` / `pHYs` / `bKGD` /
  /// `tIME` / `iCCP-name`) was last written from a TRAILER chunk — so its
  /// emitted PNG-level tags carry the `Trailer` family-1 override. (A trailing
  /// duplicate of a structural chunk is not a real-camera scenario but bundled
  /// still group-shifts it; last-wins, matching the singleton fields.)
  structural_trailing: StructuralTrailing,
  // ----- structural warnings --------------------------------------------
  /// Warnings raised during the chunk walk (`Bad CRC`, `Truncated PNG`,
  /// `Text/EXIF chunk(s) found after PNG IDAT (may be ignored by some
  /// readers)`, the post-`IEND` `Trailer data after PNG IEND chunk`
  /// `PNG.pm:1481`, …). The ENGINE surfaces the FIRST as
  /// `ExifTool:Warning` (`ExifTool.pm:1288-1297`).
  warnings: Vec<String>,
  /// The WALK-ORDER interleaving of the three document-diagnostic sources —
  /// the PNG-level [`Self::warnings`], the embedded-EXIF [`Self::exif_events`]
  /// (whose replay surfaces the embedded `$et->Warn` corpus + the cross-source
  /// cycle-guard), and the raw-profile [`Self::xmp_profiles`] (whose
  /// `ProcessXMP` records at most one first-occurrence `$et->Warn`, e.g. `XMP is
  /// double UTF-encoded`). Each push to one of those three streams appends one
  /// [`PngDiagStep`] here, so the warning drain
  /// ([`crate::diagnostics::Diagnose`]) can replay every document warning at its
  /// CHUNK-WALK position — the order ExifTool's serial chunk walk
  /// (`PNG.pm:1410-1685`) emits them in, which is load-bearing for the
  /// document-level FIRST-`ExifTool:Warning` surface (`Warning` is `Priority=0`
  /// first-wins, `ExifTool.pm:5404-5417`). Without it a raw-profile-XMP decode
  /// warning would drain AFTER an unrelated later chunk's warning and hide it
  /// (#205, a malformed-input ordering bug).
  diag_order: Vec<PngDiagStep>,
  /// FILE-WIDE running total of zXIf-inflated bytes (`PNG.pm:1386-1389`). Every
  /// `zxIf`/`eXIf` chunk's nested-inflate chain charges its decompressed output
  /// here so the whole PNG's inflated-then-RETAINED EXIF memory
  /// ([`PngExifEvent::NativeTiff`], cloned out of the inflated buffer) is bounded
  /// across ALL chunks, not per chunk — a small PNG can carry MANY independent
  /// `zxIf` chunks, each inflating to a near-cap valid TIFF that is retained, so
  /// a per-call budget would let retained memory grow as O(chunks × cap). The
  /// chunk walker reads the REMAINING budget off this and stops a chain (the
  /// aborted-inflate `Error inflating <tag>` warning, `PNG.pm:943`) once the
  /// cumulative file-wide total would exceed the cap
  /// ([`crate::formats::png::process_exif_block`]). Untouched by an uncompressed
  /// `eXIf` (no inflation — its retained bytes are already bounded by the on-disk
  /// chunk length), so a real PNG (≤ 1 small uncompressed `eXIf`) never charges
  /// it and is byte-identical.
  zxif_inflated_total: usize,
  // ----- container (signature-derived, PNG.pm:61-65) ---------------------
  /// Which PNG-sibling container the 8-byte signature selected (`PNG`/`MNG`/
  /// `JNG`, `%pngLookup`). Drives the resolved `File:FileType` and the
  /// `%MNG::Main` fallback. Defaults to [`PngContainer::Png`].
  container: PngContainer,
  // ----- MNG/JNG chunk sub-tables (MNG.pm) -------------------------------
  /// The decoded MNG/JNG-specific chunk metadata (`MNG.pm`'s 17
  /// `ProcessBinaryData` sub-tables + inline-`ValueConv` / `Binary => 1`
  /// chunks), produced as the chunk walker reaches each MNG-specific chunk when
  /// the resolved file type is MNG/JNG (`PNG.pm:1444-1446`/`:1653-1657`'s
  /// `%MNG::Main` fallback). `None` for an ordinary PNG (and for an MNG/JNG that
  /// carried no MNG-specific chunk). Emitted via its
  /// [`Taggable`](crate::emit::Taggable) impl under group `MNG`, appended AFTER
  /// the PNG-level tags in [`crate::formats::png::ProcessPng`]'s `tags()`; its
  /// diagnostics drain alongside the PNG warnings. The same "sub-Meta hangs off
  /// the parent Meta" shape as `GeoTiffMeta` on `ExifMeta`.
  mng: Option<crate::exif::mng::MngMeta>,
  // ----- JUMBF / C2PA caBX box subsystem (Jpeg2000.pm) -------------------
  /// The decoded JUMBF / C2PA metadata of a PNG `caBX` chunk
  /// (`PNG.pm:343-346` → `Jpeg2000::Main`), produced by
  /// [`crate::exif::jumbf::process`] when the chunk walker reaches a `caBX`
  /// chunk. `None` for a PNG with no `caBX` (and for a `caBX` whose box stream
  /// recognized nothing). Emitted via its
  /// [`Taggable`](crate::emit::Taggable) impl under groups `JUMBF` (the `jumd`
  /// description tags) + `Jpeg2000` (the `bfdb`/`bidb`/`c2sh` content tags) on
  /// the `Doc<N>` axis, appended AFTER the PNG-level tags; its diagnostics drain
  /// alongside the PNG warnings. The same "sub-Meta hangs off the parent Meta"
  /// shape as `GeoTiffMeta`/`MngMeta`.
  jumbf: Option<crate::exif::jumbf::JumbfMeta>,
  /// The JUMBF walker warnings of EACH dispatched `caBX` chunk, one inner `Vec`
  /// per `caBX` (in chunk-walk order). [`PngDiagStep::Jumbf`] carries the index
  /// into this list, so each `caBX`'s warnings drain at ITS walk position — the
  /// per-OCCURRENCE diagnostic axis, decoupled from the last-wins [`Self::jumbf`]
  /// TAG meta. A PNG legally carries one `caBX` (so this holds one entry), but a
  /// crafted PNG can carry several; the `caBX` TAGS last-wins-replace into
  /// [`Self::jumbf`] while the DIAGNOSTICS stay per-occurrence, so a malformed
  /// LATER `caBX`'s warning does not steal the priority-0 first-wins
  /// `ExifTool:Warning` slot from an intervening earlier-walked warning
  /// ([[exifast-warning-priority0-firstwins]]). Only a NON-empty decode pushes an
  /// entry (an empty `caBX` is dropped whole, see [`Self::set_jumbf`]).
  jumbf_diags: Vec<Vec<crate::exif::jumbf::JumbfWarning>>,
  /// Phantom carry of `'a` for future zero-alloc evolution / sub-Meta
  /// embedding.
  _lifetime: core::marker::PhantomData<&'a ()>,
}

/// One step in [`PngMeta::diag_order`] — which document-diagnostic SOURCE the
/// chunk walk reached next, recorded in walk order. The warning drain consumes
/// the three source streams ([`PngMeta::warnings`], [`PngMeta::exif_events`],
/// [`PngMeta::xmp_profiles`]) in lockstep with this sequence, so each source's
/// own walk order is preserved AND the sources interleave at their true chunk
/// positions (#205).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PngDiagStep {
  /// The next [`PngMeta::warnings`] entry — a PNG-level walker warning.
  Warning,
  /// The next [`PngMeta::exif_events`] entry — an embedded-EXIF event whose
  /// replay yields its EXIF warnings + cross-source cycle-guard warning(s).
  ExifEvent,
  /// The next [`PngMeta::xmp_profiles`] entry — a raw-profile XMP packet whose
  /// `ProcessXMP` decode yields at most one first-occurrence warning.
  #[cfg(feature = "xmp")]
  Xmp,
  /// A `caBX` chunk's JUMBF sub-Meta — its `Jpeg2000.pm` walker warnings
  /// (`Truncated JUMD directory`, the depth-budget `JUMBF box nesting too deep`,
  /// …) drain at the `caBX` chunk-walk position. Carries the index into
  /// [`PngMeta::jumbf_diags`] of THAT `caBX`'s warnings: each non-empty `caBX`
  /// pushes its OWN step (a PNG legally carries one, but a crafted PNG can carry
  /// several), so the warnings stay PER occurrence and drain at the right walk
  /// position. Decoupled from the last-wins [`PngMeta::jumbf`] TAG meta —
  /// recorded so a malformed `caBX` BEFORE a later PNG warning wins the
  /// document-level priority-0 first-wins `ExifTool:Warning` slot, while a
  /// malformed LATER `caBX` does NOT steal that slot from an earlier-walked
  /// warning, matching ExifTool's walk-position emission.
  Jumbf(usize),
}

/// The payload LENGTHS of a `Binary => 1` PNG vendor chunk (`iDOT` /
/// `gdAT`) split BY FAMILY-1 GROUP — a pre-`IEND` occurrence (`main`, emitted
/// under the `PNG` group) and a post-`IEND` TRAILER occurrence (`trailer`,
/// emitted under the `Trailer` group, `PNG.pm:1484`). A single PNG can carry
/// the chunk in BOTH regions and bundled emits BOTH placeholders under their
/// distinct groups (oracle-verified vs ExifTool 13.59), so a single
/// `Option<usize>` would lose one; this pair preserves both. STILL
/// length-only — never the payload bytes (the `Binary => 1` placeholder is
/// rendered from the byte count alone). Each slot is last-wins (a repeated
/// chunk within the same region overwrites, matching the singleton TagMap
/// key). `main == trailer == None` when the chunk was absent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct BinaryChunkLengths {
  /// Length of the pre-`IEND` occurrence — emitted under the `PNG` family-1
  /// group. Last-wins on a repeated pre-`IEND` chunk.
  main: Option<usize>,
  /// Length of the post-`IEND` TRAILER occurrence — emitted under the
  /// `Trailer` family-1 group (`PNG.pm:1484`). Last-wins on a repeated
  /// post-`IEND` chunk.
  trailer: Option<usize>,
}

impl BinaryChunkLengths {
  /// An empty pair — neither a pre- nor a post-`IEND` occurrence seen.
  #[inline(always)]
  #[must_use]
  const fn new() -> Self {
    Self {
      main: None,
      trailer: None,
    }
  }

  /// Record one occurrence's `len`, routed to the `trailer` slot when the
  /// chunk was parsed in post-`IEND` TRAILER mode (`trailing == true`,
  /// `PNG.pm:1484`) and the `main` slot otherwise. Last-wins within the slot.
  #[inline(always)]
  fn set(&mut self, len: usize, trailing: bool) {
    if trailing {
      self.trailer = Some(len);
    } else {
      self.main = Some(len);
    }
  }

  /// The pre-`IEND` (`PNG:`-group) occurrence length, if any.
  #[inline(always)]
  #[must_use]
  const fn main(&self) -> Option<usize> {
    self.main
  }

  /// The post-`IEND` (`Trailer:`-group) occurrence length, if any.
  #[inline(always)]
  #[must_use]
  const fn trailer(&self) -> Option<usize> {
    self.trailer
  }
}

/// One `acTL` sub-table field's value (`AnimationFrames` OR `AnimationPlays`)
/// split BY FAMILY-1 GROUP — a pre-`IEND` occurrence (`main`, emitted under the
/// `PNG` group) and a post-`IEND` TRAILER occurrence (`trailer`, emitted under
/// the `Trailer` group, `PNG.pm:1484`). The SAME per-field-provenance shape as
/// [`BinaryChunkLengths`] (iDOT/gdAT), applied PER acTL FIELD because the two
/// fields are extracted INDEPENDENTLY by `ProcessBinaryData` (each iff its
/// `offset+size` is within the chunk length): a 4-to-7-byte trailer `acTL`
/// supplies `AnimationFrames` (bytes `0..4`) but NOT `AnimationPlays` (bytes
/// `4..8`), so `AnimationFrames.trailer` is `Some` while `AnimationPlays.trailer`
/// stays `None`. A single shared trailing flag would have re-grouped the main
/// `AnimationPlays` to `Trailer` and fabricated a `Trailer:AnimationPlays` that
/// did not exist in the trailer chunk; separate slots keep each field's group
/// faithful (oracle-verified vs ExifTool 13.59). Each slot is last-wins (a
/// repeated `acTL` within the same region overwrites, matching the singleton
/// TagMap key). `main == trailer == None` when the field was never extracted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ActlValues {
  /// Value of the pre-`IEND` occurrence — emitted under the `PNG` family-1
  /// group. Last-wins on a repeated pre-`IEND` `acTL`.
  main: Option<u32>,
  /// Value of the post-`IEND` TRAILER occurrence — emitted under the `Trailer`
  /// family-1 group (`PNG.pm:1484`). Last-wins on a repeated post-`IEND` `acTL`.
  trailer: Option<u32>,
}

impl ActlValues {
  /// An empty pair — neither a pre- nor a post-`IEND` occurrence of this acTL
  /// field seen.
  #[inline(always)]
  #[must_use]
  const fn new() -> Self {
    Self {
      main: None,
      trailer: None,
    }
  }

  /// Record one occurrence's `value`, routed to the `trailer` slot when the
  /// `acTL` chunk was parsed in post-`IEND` TRAILER mode (`trailing == true`,
  /// `PNG.pm:1484`) and the `main` slot otherwise. Last-wins within the slot.
  #[inline(always)]
  fn set(&mut self, value: u32, trailing: bool) {
    if trailing {
      self.trailer = Some(value);
    } else {
      self.main = Some(value);
    }
  }

  /// The pre-`IEND` (`PNG:`-group) occurrence value, if any.
  #[inline(always)]
  #[must_use]
  const fn main(&self) -> Option<u32> {
    self.main
  }

  /// The post-`IEND` (`Trailer:`-group) occurrence value, if any.
  #[inline(always)]
  #[must_use]
  const fn trailer(&self) -> Option<u32> {
    self.trailer
  }
}

/// One `ProcessBinaryData` sub-table FIELD split BY FAMILY-1 GROUP — a pre-`IEND`
/// occurrence (`main`) and a post-`IEND` TRAILER occurrence (`trailer`,
/// `PNG.pm:1484` `SET_GROUP1 = 'Trailer'`). The SAME per-field-provenance shape
/// as [`ActlValues`] (acTL) and [`BinaryChunkLengths`] (iDOT/gdAT), generalised
/// over the field's value type so it serves the `cICP` `CICodePoints`
/// (`int8u`) and `vpAg` `VirtualPage` (`int32u` / `int8u`) sub-tables.
///
/// `ProcessBinaryData` extracts EACH field of a chunk INDEPENDENTLY (a field
/// emits iff its `offset + size` is within the chunk length) and NEVER clears a
/// previously-emitted tag (`ExifTool.pm` writes each into the tag hash as it is
/// read). So the per-field slot is the faithful storage: a TRUNCATED later
/// chunk that omits a field passes `None` for it ([`Self::set`] is simply not
/// called), leaving the earlier value intact; a field the later chunk DOES carry
/// overwrites the slot (last-wins WITHIN the region — oracle-verified vs ExifTool
/// 13.59: a full `cICP` then a 2-byte `cICP` keeps the earlier
/// MatrixCoefficients/VideoFullRangeFlag and updates the present
/// ColorPrimaries/TransferCharacteristics). Splitting main from trailer keeps a
/// post-`IEND` chunk from clobbering the pre-`IEND` values AND from re-grouping
/// the surviving main tags to `Trailer`: bundled emits the main fields under
/// `PNG-cICP`/`PNG` and the post-`IEND` fields under `Trailer`, BOTH at once.
/// `main == trailer == None` when the field was never extracted in that region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RegionValue<T: Copy> {
  /// Value of the pre-`IEND` occurrence — emitted under the chunk's default
  /// family-1 group (`PNG-cICP` for cICP, `PNG` for vpAg). Last-wins on a
  /// repeated pre-`IEND` chunk.
  main: Option<T>,
  /// Value of the post-`IEND` TRAILER occurrence — emitted under the `Trailer`
  /// family-1 group (`PNG.pm:1484`). Last-wins on a repeated post-`IEND` chunk.
  trailer: Option<T>,
}

impl<T: Copy> RegionValue<T> {
  /// An empty pair — neither a pre- nor a post-`IEND` occurrence of this field
  /// seen.
  #[inline(always)]
  #[must_use]
  const fn new() -> Self {
    Self {
      main: None,
      trailer: None,
    }
  }

  /// Record one occurrence's `value`, routed to the `trailer` slot when the
  /// chunk was parsed in post-`IEND` TRAILER mode (`trailing == true`,
  /// `PNG.pm:1484`) and the `main` slot otherwise. Last-wins within the slot. A
  /// field the chunk does NOT carry is never passed here, so its slot keeps any
  /// earlier value (present-only update).
  #[inline(always)]
  fn set(&mut self, value: T, trailing: bool) {
    if trailing {
      self.trailer = Some(value);
    } else {
      self.main = Some(value);
    }
  }

  /// The pre-`IEND` occurrence value, if any.
  #[inline(always)]
  #[must_use]
  const fn main(&self) -> Option<T>
  where
    T: Copy,
  {
    self.main
  }

  /// The post-`IEND` (`Trailer:`-group) occurrence value, if any.
  #[inline(always)]
  #[must_use]
  const fn trailer(&self) -> Option<T>
  where
    T: Copy,
  {
    self.trailer
  }
}

impl<T: Copy> Default for RegionValue<T> {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

/// Which structural single-value PNG chunks (the [`PngMeta`] singleton fields)
/// were last set from a post-`IEND` TRAILER chunk and so carry the `Trailer`
/// family-1 group override. All-`false` for a standard (IEND-last) PNG.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct StructuralTrailing {
  /// `IHDR` sub-table (ImageWidth/Height/BitDepth/ColorType/Compression/
  /// Filter/Interlace) came from a trailer chunk.
  ihdr: bool,
  /// `pHYs` sub-table (PixelsPerUnitX/Y, PixelUnits) came from a trailer chunk.
  phys: bool,
  /// `iCCP-name` (ProfileName) came from a trailer chunk.
  iccp: bool,
  /// `bKGD` (BackgroundColor) came from a trailer chunk.
  bkgd: bool,
  /// `tIME` (ModifyDate) came from a trailer chunk.
  time: bool,
}

impl Default for PngMeta<'_> {
  #[inline(always)]
  fn default() -> Self {
    Self::new()
  }
}

impl PngMeta<'_> {
  /// An empty `PngMeta` — every chunk field `None`, no text records, no
  /// warnings. The starting point the chunk walker fills.
  #[inline(always)]
  #[must_use]
  pub const fn new() -> Self {
    Self {
      width: None,
      height: None,
      bit_depth: None,
      color_type: None,
      compression: None,
      filter: None,
      interlace: None,
      animation_frames: ActlValues::new(),
      animation_plays: ActlValues::new(),
      apple_data_offsets: BinaryChunkLengths::new(),
      gain_map_image: BinaryChunkLengths::new(),
      pixels_per_unit_x: None,
      pixels_per_unit_y: None,
      pixel_units: None,
      color_primaries: RegionValue::new(),
      transfer_characteristics: RegionValue::new(),
      matrix_coefficients: RegionValue::new(),
      video_full_range_flag: RegionValue::new(),
      virtual_image_width: RegionValue::new(),
      virtual_image_height: RegionValue::new(),
      virtual_page_units: RegionValue::new(),
      icc_profile_name: None,
      background_color: None,
      modify_date: None,
      text_records: Vec::new(),
      dynamic_profile_tags: Vec::new(),
      exif_events: Vec::new(),
      #[cfg(feature = "xmp")]
      xmp_profiles: Vec::new(),
      in_trailer: false,
      trailer_text_start: usize::MAX,
      trailer_dynamic_start: usize::MAX,
      trailer_event_start: usize::MAX,
      #[cfg(feature = "xmp")]
      trailer_xmp_start: usize::MAX,
      trailer_warning_start: usize::MAX,
      structural_trailing: StructuralTrailing {
        ihdr: false,
        phys: false,
        iccp: false,
        bkgd: false,
        time: false,
      },
      warnings: Vec::new(),
      diag_order: Vec::new(),
      zxif_inflated_total: 0,
      container: PngContainer::Png,
      mng: None,
      jumbf: None,
      jumbf_diags: Vec::new(),
      _lifetime: core::marker::PhantomData,
    }
  }

  // ===== IHDR accessors =================================================

  /// The `IHDR.ImageWidth` (`PNG.pm:391-394`), `None` when no IHDR was
  /// decoded (a stripped PNG).
  #[inline(always)]
  #[must_use]
  pub const fn width(&self) -> Option<u32> {
    self.width
  }

  /// The `IHDR.ImageHeight` (`PNG.pm:395-398`).
  #[inline(always)]
  #[must_use]
  pub const fn height(&self) -> Option<u32> {
    self.height
  }

  /// Both image dimensions as `(width, height)` when BOTH are present.
  #[inline(always)]
  #[must_use]
  pub const fn dimensions(&self) -> Option<(u32, u32)> {
    match (self.width, self.height) {
      (Some(w), Some(h)) => Some((w, h)),
      _ => None,
    }
  }

  /// The `IHDR.BitDepth` (`PNG.pm:399`).
  #[inline(always)]
  #[must_use]
  pub const fn bit_depth(&self) -> Option<u8> {
    self.bit_depth
  }

  /// The `IHDR.ColorType` (`PNG.pm:400-410`).
  #[inline(always)]
  #[must_use]
  pub const fn color_type(&self) -> Option<PngColorType> {
    self.color_type
  }

  /// The `IHDR.Compression` (`PNG.pm:411-414`).
  #[inline(always)]
  #[must_use]
  pub const fn compression(&self) -> Option<u8> {
    self.compression
  }

  /// The `IHDR.Filter` (`PNG.pm:415-418`).
  #[inline(always)]
  #[must_use]
  pub const fn filter(&self) -> Option<u8> {
    self.filter
  }

  /// The `IHDR.Interlace` (`PNG.pm:419-422`).
  #[inline(always)]
  #[must_use]
  pub const fn interlace(&self) -> Option<u8> {
    self.interlace
  }

  // ===== acTL accessors =================================================

  /// `acTL.AnimationFrames` from the MAIN (pre-`IEND`) `acTL` chunk
  /// (`PNG:AnimationFrames`, `AnimationControl` tag 0, `PNG.pm:774-777`).
  /// `None` when no pre-`IEND` `acTL` supplied bytes `0..4`.
  #[inline(always)]
  #[must_use]
  pub const fn animation_frames_main(&self) -> Option<u32> {
    self.animation_frames.main()
  }

  /// `acTL.AnimationFrames` from the post-`IEND` TRAILER `acTL` chunk
  /// (`Trailer:AnimationFrames`, parsed while `SET_GROUP1 = 'Trailer'`,
  /// `PNG.pm:1484`). `None` when no post-`IEND` `acTL` supplied bytes `0..4`.
  #[inline(always)]
  #[must_use]
  pub const fn animation_frames_trailer(&self) -> Option<u32> {
    self.animation_frames.trailer()
  }

  /// `acTL.AnimationPlays` from the MAIN (pre-`IEND`) `acTL` chunk
  /// (`PNG:AnimationPlays`, `AnimationControl` tag 1, `PNG.pm:778-781`), the
  /// RAW value (`0` ⇒ infinite). The `$val || "inf"` PrintConv is applied at
  /// emission. `None` when no pre-`IEND` `acTL` supplied bytes `4..8`.
  #[inline(always)]
  #[must_use]
  pub const fn animation_plays_main(&self) -> Option<u32> {
    self.animation_plays.main()
  }

  /// `acTL.AnimationPlays` from the post-`IEND` TRAILER `acTL` chunk
  /// (`Trailer:AnimationPlays`, parsed while `SET_GROUP1 = 'Trailer'`,
  /// `PNG.pm:1484`), the RAW value. `None` when no post-`IEND` `acTL` supplied
  /// bytes `4..8` — e.g. a runt 4-to-7-byte trailer `acTL` leaves this `None`
  /// so the main `PNG:AnimationPlays` is NOT re-grouped to `Trailer`.
  #[inline(always)]
  #[must_use]
  pub const fn animation_plays_trailer(&self) -> Option<u32> {
    self.animation_plays.trailer()
  }

  /// Whether this PNG is an ANIMATED PNG — i.e. carried an `acTL` chunk (so
  /// `AnimationFrames` was decoded in EITHER region). Drives the `File:FileType`
  /// promotion to `APNG`: bundled's `AnimationFrames` RawConv calls
  /// `$self->OverrideFileType("APNG", undef, "PNG")` (`PNG.pm:776`), so the
  /// override fires whenever the `acTL` chunk is present, regardless of the
  /// frame count's value. Keyed on `AnimationFrames` (tag 0) because that is
  /// the tag whose RawConv runs the override; either a pre-`IEND` or a
  /// post-`IEND` `acTL` arms it.
  #[inline(always)]
  #[must_use]
  pub const fn is_apng(&self) -> bool {
    self.animation_frames.main().is_some() || self.animation_frames.trailer().is_some()
  }

  // ===== pHYs accessors =================================================

  /// `pHYs.PixelsPerUnitX` (`PNG.pm:453-457`).
  #[inline(always)]
  #[must_use]
  pub const fn pixels_per_unit_x(&self) -> Option<u32> {
    self.pixels_per_unit_x
  }

  /// `pHYs.PixelsPerUnitY` (`PNG.pm:458-462`).
  #[inline(always)]
  #[must_use]
  pub const fn pixels_per_unit_y(&self) -> Option<u32> {
    self.pixels_per_unit_y
  }

  /// `pHYs.PixelUnits` (`PNG.pm:463-467`). `0` = unknown, `1` = meters.
  #[inline(always)]
  #[must_use]
  pub const fn pixel_units(&self) -> Option<u8> {
    self.pixel_units
  }

  // ===== cICP accessors =================================================

  /// `cICP.ColorPrimaries` from the MAIN (pre-`IEND`) `cICP` chunk
  /// (`PNG-cICP:ColorPrimaries`, `PNG.pm:479-495`). `None` when no pre-`IEND`
  /// `cICP` supplied byte 0.
  #[inline(always)]
  #[must_use]
  pub const fn color_primaries_main(&self) -> Option<u8> {
    self.color_primaries.main()
  }

  /// `cICP.ColorPrimaries` from the post-`IEND` TRAILER `cICP` chunk
  /// (`Trailer:ColorPrimaries`, parsed while `SET_GROUP1 = 'Trailer'`,
  /// `PNG.pm:1484`). `None` when no post-`IEND` `cICP` supplied byte 0.
  #[inline(always)]
  #[must_use]
  pub const fn color_primaries_trailer(&self) -> Option<u8> {
    self.color_primaries.trailer()
  }

  /// `cICP.TransferCharacteristics` from the MAIN (pre-`IEND`) `cICP` chunk
  /// (`PNG.pm:496-519`). `None` when no pre-`IEND` `cICP` supplied byte 1.
  #[inline(always)]
  #[must_use]
  pub const fn transfer_characteristics_main(&self) -> Option<u8> {
    self.transfer_characteristics.main()
  }

  /// `cICP.TransferCharacteristics` from the post-`IEND` TRAILER `cICP` chunk
  /// (`PNG.pm:1484`). `None` when no post-`IEND` `cICP` supplied byte 1.
  #[inline(always)]
  #[must_use]
  pub const fn transfer_characteristics_trailer(&self) -> Option<u8> {
    self.transfer_characteristics.trailer()
  }

  /// `cICP.MatrixCoefficients` from the MAIN (pre-`IEND`) `cICP` chunk
  /// (`PNG.pm:520-539`). `None` when no pre-`IEND` `cICP` supplied byte 2.
  #[inline(always)]
  #[must_use]
  pub const fn matrix_coefficients_main(&self) -> Option<u8> {
    self.matrix_coefficients.main()
  }

  /// `cICP.MatrixCoefficients` from the post-`IEND` TRAILER `cICP` chunk
  /// (`PNG.pm:1484`). `None` when no post-`IEND` `cICP` supplied byte 2.
  #[inline(always)]
  #[must_use]
  pub const fn matrix_coefficients_trailer(&self) -> Option<u8> {
    self.matrix_coefficients.trailer()
  }

  /// `cICP.VideoFullRangeFlag` from the MAIN (pre-`IEND`) `cICP` chunk
  /// (`PNG.pm:540`). `None` when no pre-`IEND` `cICP` supplied byte 3.
  #[inline(always)]
  #[must_use]
  pub const fn video_full_range_flag_main(&self) -> Option<u8> {
    self.video_full_range_flag.main()
  }

  /// `cICP.VideoFullRangeFlag` from the post-`IEND` TRAILER `cICP` chunk
  /// (`PNG.pm:1484`). `None` when no post-`IEND` `cICP` supplied byte 3.
  #[inline(always)]
  #[must_use]
  pub const fn video_full_range_flag_trailer(&self) -> Option<u8> {
    self.video_full_range_flag.trailer()
  }

  // ===== vpAg accessors =================================================

  /// `vpAg.VirtualImageWidth` from the MAIN (pre-`IEND`) `vpAg` chunk
  /// (`PNG:VirtualImageWidth`, `PNG.pm:566`). `None` when no pre-`IEND` `vpAg`
  /// supplied bytes `0..4`.
  #[inline(always)]
  #[must_use]
  pub const fn virtual_image_width_main(&self) -> Option<u32> {
    self.virtual_image_width.main()
  }

  /// `vpAg.VirtualImageWidth` from the post-`IEND` TRAILER `vpAg` chunk
  /// (`Trailer:VirtualImageWidth`, `PNG.pm:1484`). `None` when no post-`IEND`
  /// `vpAg` supplied bytes `0..4`.
  #[inline(always)]
  #[must_use]
  pub const fn virtual_image_width_trailer(&self) -> Option<u32> {
    self.virtual_image_width.trailer()
  }

  /// `vpAg.VirtualImageHeight` from the MAIN (pre-`IEND`) `vpAg` chunk
  /// (`PNG.pm:567`). `None` when no pre-`IEND` `vpAg` supplied bytes `4..8`.
  #[inline(always)]
  #[must_use]
  pub const fn virtual_image_height_main(&self) -> Option<u32> {
    self.virtual_image_height.main()
  }

  /// `vpAg.VirtualImageHeight` from the post-`IEND` TRAILER `vpAg` chunk
  /// (`PNG.pm:1484`). `None` when no post-`IEND` `vpAg` supplied bytes `4..8`.
  #[inline(always)]
  #[must_use]
  pub const fn virtual_image_height_trailer(&self) -> Option<u32> {
    self.virtual_image_height.trailer()
  }

  /// `vpAg.VirtualPageUnits` from the MAIN (pre-`IEND`) `vpAg` chunk
  /// (`PNG.pm:568-572`). `None` when no pre-`IEND` `vpAg` supplied byte 8.
  #[inline(always)]
  #[must_use]
  pub const fn virtual_page_units_main(&self) -> Option<u8> {
    self.virtual_page_units.main()
  }

  /// `vpAg.VirtualPageUnits` from the post-`IEND` TRAILER `vpAg` chunk
  /// (`PNG.pm:1484`). `None` when no post-`IEND` `vpAg` supplied byte 8.
  #[inline(always)]
  #[must_use]
  pub const fn virtual_page_units_trailer(&self) -> Option<u8> {
    self.virtual_page_units.trailer()
  }

  /// Helper: DPI as `(x, y)` derived from `pHYs`. PNG stores pixels per
  /// METER (`PixelUnits == 1`); 1 inch = 0.0254 m, so DPI = ppm × 0.0254.
  /// Returns `None` when `PixelUnits != 1` or either ppm component is
  /// missing/zero.
  #[must_use]
  pub fn dpi(&self) -> Option<(f64, f64)> {
    if self.pixel_units != Some(1) {
      return None;
    }
    let x = self.pixels_per_unit_x?;
    let y = self.pixels_per_unit_y?;
    if x == 0 || y == 0 {
      return None;
    }
    Some((f64::from(x) * 0.0254, f64::from(y) * 0.0254))
  }

  // ===== iDOT accessors =================================================

  /// The payload LENGTH of the MAIN (pre-`IEND`) Apple `iDOT` chunk
  /// (`PNG:AppleDataOffsets`, `PNG.pm:331-342`), used to render the
  /// `(Binary data N bytes, …)` placeholder. The raw bytes are never retained.
  /// `None` when no pre-`IEND` `iDOT` chunk was seen.
  #[inline(always)]
  #[must_use]
  pub const fn apple_data_offsets_main_len(&self) -> Option<usize> {
    self.apple_data_offsets.main()
  }

  /// The payload LENGTH of the post-`IEND` TRAILER Apple `iDOT` chunk
  /// (`Trailer:AppleDataOffsets`, `PNG.pm:331-342` parsed while
  /// `SET_GROUP1 = 'Trailer'`, `PNG.pm:1484`). `None` when no post-`IEND`
  /// `iDOT` chunk was seen.
  #[inline(always)]
  #[must_use]
  pub const fn apple_data_offsets_trailer_len(&self) -> Option<usize> {
    self.apple_data_offsets.trailer()
  }

  // ===== gdAT accessors =================================================

  /// The payload LENGTH of the MAIN (pre-`IEND`) `gdAT` chunk
  /// (`PNG:GainMapImage`, `PNG.pm:374-378`), used to render the
  /// `(Binary data N bytes, …)` placeholder. The raw bytes are never retained.
  /// `None` when no pre-`IEND` `gdAT` chunk was seen.
  #[inline(always)]
  #[must_use]
  pub const fn gain_map_image_main_len(&self) -> Option<usize> {
    self.gain_map_image.main()
  }

  /// The payload LENGTH of the post-`IEND` TRAILER `gdAT` chunk
  /// (`Trailer:GainMapImage`, `PNG.pm:374-378` parsed while
  /// `SET_GROUP1 = 'Trailer'`, `PNG.pm:1484`). `None` when no post-`IEND`
  /// `gdAT` chunk was seen.
  #[inline(always)]
  #[must_use]
  pub const fn gain_map_image_trailer_len(&self) -> Option<usize> {
    self.gain_map_image.trailer()
  }

  // ===== iCCP accessors =================================================

  /// The `iCCP-name` — the ICC profile NAME (`PNG.pm:182-190`). The
  /// profile body bytes are NOT parsed (Phase-2 sub-port deferred).
  #[inline(always)]
  #[must_use]
  pub fn icc_profile_name(&self) -> Option<&str> {
    self.icc_profile_name.as_deref()
  }

  // ===== bKGD / tIME accessors =========================================

  /// The `bKGD.BackgroundColor` value string (already rendered as
  /// bundled's `join " " unpack(...)`).
  #[inline(always)]
  #[must_use]
  pub fn background_color(&self) -> Option<&str> {
    self.background_color.as_deref()
  }

  /// The `tIME.ModifyDate` value string (already rendered as bundled's
  /// `sprintf("%.4d:%.2d:%.2d %.2d:%.2d:%.2d", unpack("nC5", $val))`,
  /// `PNG.pm:267`).
  #[inline(always)]
  #[must_use]
  pub fn modify_date(&self) -> Option<&str> {
    self.modify_date.as_deref()
  }

  // ===== text records ===================================================

  /// All text records (`tEXt` / `zTXt` / `iTXt`) in chunk-walk (file)
  /// order.
  #[inline(always)]
  #[must_use]
  pub fn text_records(&self) -> &[PngTextRecord] {
    &self.text_records
  }

  // ===== dynamically-added profile tags ===============================

  /// The tags `FoundPNG` added dynamically ([`PngDynamicProfileTag`]) — a
  /// registered raw-profile keyword in a language-tagged `iTXt`, or any
  /// unregistered `Raw profile type *` keyword — in chunk-walk order.
  #[inline(always)]
  #[must_use]
  pub fn dynamic_profile_tags(&self) -> &[PngDynamicProfileTag] {
    &self.dynamic_profile_tags
  }

  // ===== EXIF event stream =============================================

  /// The captured EXIF-relevant event stream ([`PngExifEvent`]) in WALK (chunk)
  /// ORDER — native `eXIf`/`zxIf` chunks, EXIF raw profiles, and reset-only raw
  /// profiles interleaved exactly as they appeared in the file. Empty when the
  /// PNG carries no EXIF event.
  ///
  /// Consumers MUST replay these through ONE shared `$$et{PROCESSED}` map with
  /// bundled's reset semantics (`PNG.pm:1193`) rather than treating any single
  /// one as authoritative: a [`PngExifEvent::ResetOnlyProfile`] or
  /// [`PngExifEvent::ExifProfile`] first CLEARS the set; a directory whose
  /// `$addr` was already processed is then BLOCKED.
  /// [`crate::formats::png::replay_exif_events`] implements that replay for tag
  /// emission, the domain projection, and the warning drain.
  #[inline(always)]
  #[must_use]
  pub fn exif_events(&self) -> &[PngExifEvent] {
    &self.exif_events
  }

  // ===== XMP raw profiles ==============================================

  /// The hex-decoded XMP packets captured from `Raw profile type xmp` chunks
  /// (and the XMP-content arm of `Raw profile type {exif,APP1}`) in WALK
  /// ORDER. Each is the raw XMP packet bundled feeds to `ProcessXMP`
  /// (`PNG.pm:746`/`:1236`); decode via
  /// [`crate::formats::xmp::parse_borrowed`]. Empty when the PNG carries no XMP
  /// raw profile. Present only when the `xmp` feature is built (the PNG port
  /// does not otherwise depend on the XMP module).
  #[cfg(feature = "xmp")]
  #[inline(always)]
  #[must_use]
  pub fn xmp_profiles(&self) -> &[Vec<u8>] {
    &self.xmp_profiles
  }

  // ===== warnings =======================================================

  /// Warnings raised during the chunk walk.
  #[inline(always)]
  #[must_use]
  pub fn warnings(&self) -> &[String] {
    &self.warnings
  }

  // ===== setters (crate-private, used by the chunk walker) =============

  /// Set the IHDR `(width, height, bit_depth, color_type, compression,
  /// filter, interlace)` tuple — the chunk-walker hook. `pub(crate)`. When the
  /// walker is in TRAILER mode (`PNG.pm:1484`) the IHDR tags carry the
  /// `Trailer` family-1 override.
  pub(crate) fn set_ihdr(&mut self, ihdr: IhdrFields) {
    self.width = Some(ihdr.width);
    self.height = Some(ihdr.height);
    self.bit_depth = Some(ihdr.bit_depth);
    self.color_type = Some(PngColorType::from_byte(ihdr.color_type));
    self.compression = Some(ihdr.compression);
    self.filter = Some(ihdr.filter);
    self.interlace = Some(ihdr.interlace);
    self.structural_trailing.ihdr = self.in_trailer;
  }

  /// Set the pHYs `(ppu_x, ppu_y, units)` triple.
  pub(crate) fn set_phys(&mut self, ppu_x: u32, ppu_y: u32, units: u8) {
    self.pixels_per_unit_x = Some(ppu_x);
    self.pixels_per_unit_y = Some(ppu_y);
    self.pixel_units = Some(units);
    self.structural_trailing.phys = self.in_trailer;
  }

  /// Record the `cICP` HDR code-point fields (`CICodePoints`, `PNG.pm:471-541`)
  /// per-field AND per-region. Each argument is `Some` IFF the chunk held that
  /// field's int8u byte (`ProcessBinaryData` per-offset availability,
  /// `PNG.pm:472`), so a runt cICP supplies only the leading fields. Each
  /// PRESENT field is routed to the pre-`IEND` (`PNG-cICP:`) or post-`IEND`
  /// (`Trailer:`) slot per the current [`Self::begin_trailer`] state
  /// (`PNG.pm:1484`); an ABSENT field's `None` is NOT stored, so an earlier
  /// same-region value SURVIVES (`ProcessBinaryData` never clears a previously
  /// emitted tag). A post-`IEND` `cICP` therefore neither overwrites the main
  /// fields nor re-groups them — both regions emit under their own family-1
  /// group (oracle-verified vs ExifTool 13.59). Last-wins WITHIN each region.
  pub(crate) fn set_cicp(
    &mut self,
    color_primaries: Option<u8>,
    transfer_characteristics: Option<u8>,
    matrix_coefficients: Option<u8>,
    video_full_range_flag: Option<u8>,
  ) {
    if let Some(v) = color_primaries {
      self.color_primaries.set(v, self.in_trailer);
    }
    if let Some(v) = transfer_characteristics {
      self.transfer_characteristics.set(v, self.in_trailer);
    }
    if let Some(v) = matrix_coefficients {
      self.matrix_coefficients.set(v, self.in_trailer);
    }
    if let Some(v) = video_full_range_flag {
      self.video_full_range_flag.set(v, self.in_trailer);
    }
  }

  /// Record the `vpAg` ImageMagick virtual-page fields (`VirtualPage`,
  /// `PNG.pm:561-573`) per-field AND per-region. `width`/`height` are `Some` IFF
  /// their `int32u` bytes (`0..4` / `4..8`) were present; `units` IFF byte 8 was
  /// present — each INDEPENDENT (`ProcessBinaryData` per-offset). Each PRESENT
  /// field is routed to the pre-`IEND` (`PNG:`) or post-`IEND` (`Trailer:`) slot
  /// per the current [`Self::begin_trailer`] state (`PNG.pm:1484`); an ABSENT
  /// field's `None` is NOT stored, so an earlier same-region value SURVIVES.
  /// A post-`IEND` `vpAg` neither overwrites the main fields nor re-groups them.
  /// Last-wins WITHIN each region.
  pub(crate) fn set_vpag(&mut self, width: Option<u32>, height: Option<u32>, units: Option<u8>) {
    if let Some(v) = width {
      self.virtual_image_width.set(v, self.in_trailer);
    }
    if let Some(v) = height {
      self.virtual_image_height.set(v, self.in_trailer);
    }
    if let Some(v) = units {
      self.virtual_page_units.set(v, self.in_trailer);
    }
  }

  /// Set the acTL `AnimationFrames` value — `AnimationControl` tag 0
  /// (`int32u` at offset 0, `PNG.pm:774-777`). `ProcessBinaryData` extracts
  /// this independently of `AnimationPlays` (each field emits IFF its
  /// `offset+size` is within the chunk length), so a runt 4-to-7-byte acTL
  /// still produces `AnimationFrames`. It triggers the `File:FileType` → `APNG`
  /// promotion ([`Self::is_apng`]) via its RawConv side effect. Routed to the
  /// pre-`IEND` (`PNG:`) or post-`IEND` (`Trailer:`) slot per the current
  /// [`Self::begin_trailer`] state (`PNG.pm:1484`) — kept SEPARATELY from
  /// `AnimationPlays` so a trailer-only `acTL` does not re-group the main play
  /// count; last-wins WITHIN each region.
  pub(crate) fn set_animation_frames(&mut self, num_frames: u32) {
    self.animation_frames.set(num_frames, self.in_trailer);
  }

  /// Set the acTL `AnimationPlays` value — `AnimationControl` tag 1 (`int32u`
  /// at offset 4, `PNG.pm:778-781`), extracted by `ProcessBinaryData` only when
  /// the chunk holds the full bytes `4..8`. Stored raw; the PrintConv
  /// `$val || "inf"` (`0` ⇒ `"inf"`) is applied at emission. Routed to the
  /// pre-`IEND` (`PNG:`) or post-`IEND` (`Trailer:`) slot per the current
  /// [`Self::begin_trailer`] state (`PNG.pm:1484`), independently of
  /// `AnimationFrames`'s provenance; last-wins WITHIN each region.
  pub(crate) fn set_animation_plays(&mut self, num_plays: u32) {
    self.animation_plays.set(num_plays, self.in_trailer);
  }

  /// Record the Apple `iDOT` chunk's payload LENGTH (`AppleDataOffsets`,
  /// `PNG.pm:331-342`). The bytes themselves are never retained — the
  /// `Binary => 1` placeholder is rendered from the length. Routed to the
  /// pre-`IEND` (`PNG:`) or post-`IEND` (`Trailer:`) slot per the current
  /// [`Self::begin_trailer`] state, so a PNG carrying `iDOT` in BOTH regions
  /// keeps both lengths; last-wins WITHIN each region.
  pub(crate) fn set_apple_data_offsets(&mut self, len: usize) {
    self.apple_data_offsets.set(len, self.in_trailer);
  }

  /// Record the `gdAT` chunk's payload LENGTH (`GainMapImage`,
  /// `PNG.pm:374-378`). Like `iDOT` the bytes are never retained — the
  /// `Binary => 1` placeholder is rendered from the length. Routed to the
  /// pre-`IEND` (`PNG:`) or post-`IEND` (`Trailer:`) slot per the current
  /// [`Self::begin_trailer`] state; last-wins WITHIN each region.
  pub(crate) fn set_gain_map_image(&mut self, len: usize) {
    self.gain_map_image.set(len, self.in_trailer);
  }

  /// Set the iCCP profile NAME.
  pub(crate) fn set_icc_profile_name(&mut self, name: SmolStr) {
    self.icc_profile_name = Some(name);
    self.structural_trailing.iccp = self.in_trailer;
  }

  /// Set the bKGD value string.
  pub(crate) fn set_background_color(&mut self, value: String) {
    self.background_color = Some(value);
    self.structural_trailing.bkgd = self.in_trailer;
  }

  /// Set the tIME value string.
  pub(crate) fn set_modify_date(&mut self, value: String) {
    self.modify_date = Some(value);
    self.structural_trailing.time = self.in_trailer;
  }

  /// Append one EXIF-relevant event to the stream, in WALK ORDER. The chunk
  /// walker calls this at chunk-encounter time so [`Self::exif_events`]
  /// preserves file order — which, with the per-event kind, drives the replay's
  /// reset / blocking decision (`PNG.pm:1193`, `ExifTool.pm:9061-9072`).
  pub(crate) fn push_exif_event(&mut self, event: PngExifEvent) {
    self.diag_order.push(PngDiagStep::ExifEvent);
    self.exif_events.push(event);
  }

  /// FILE-WIDE total of zXIf-inflated bytes so far (`PNG.pm:1386-1389`). The
  /// chunk walker subtracts this from the cap to size each chain's inflate so
  /// the cumulative inflated-and-retained EXIF memory across ALL `zxIf`/`eXIf`
  /// chunks is bounded — not reset per chunk.
  #[inline(always)]
  #[must_use]
  pub(crate) fn zxif_inflated_total(&self) -> usize {
    self.zxif_inflated_total
  }

  /// Charge `n` zXIf-inflated bytes to the file-wide running total
  /// ([`Self::zxif_inflated_total`]). Saturating so the counter never wraps even
  /// under a crafted chain (it is only ever compared against the cap).
  #[inline(always)]
  pub(crate) fn add_zxif_inflated(&mut self, n: usize) {
    self.zxif_inflated_total = self.zxif_inflated_total.saturating_add(n);
  }

  /// Append a hex-decoded XMP packet captured from a `Raw profile type xmp`
  /// chunk (or the XMP-content arm of `Raw profile type {exif,APP1}`), in WALK
  /// ORDER (`PNG.pm:746`/`:1236`). Decoded into `XMP-*` tags at emission time.
  #[cfg(feature = "xmp")]
  pub(crate) fn push_xmp_profile(&mut self, packet: Vec<u8>) {
    self.diag_order.push(PngDiagStep::Xmp);
    self.xmp_profiles.push(packet);
  }

  /// Append a text record.
  pub(crate) fn push_text_record(&mut self, record: PngTextRecord) {
    self.text_records.push(record);
  }

  /// Append a dynamically-added profile tag ([`PngDynamicProfileTag`]) — the
  /// `FoundPNG` `else`-branch hook (`PNG.pm:1116-1124`).
  pub(crate) fn push_dynamic_profile_tag(&mut self, tag: PngDynamicProfileTag) {
    self.dynamic_profile_tags.push(tag);
  }

  /// Append a structural warning.
  pub(crate) fn push_warning(&mut self, warning: String) {
    self.diag_order.push(PngDiagStep::Warning);
    self.warnings.push(warning);
  }

  // ===== container =====================================================

  /// Which PNG-sibling container the signature selected (`PNG`/`MNG`/`JNG`).
  #[inline]
  #[must_use]
  pub const fn container(&self) -> PngContainer {
    self.container
  }

  /// Record the signature-derived container — the chunk-walker hook called once
  /// right after the signature gate (`PNG.pm:1438`).
  #[inline]
  pub(crate) fn set_container(&mut self, container: PngContainer) {
    self.container = container;
  }

  // ===== MNG/JNG sub-Meta ===============================================

  /// The decoded MNG/JNG-specific chunk metadata, if any was captured (an
  /// MNG/JNG file that carried at least one MNG-specific chunk). `None` for an
  /// ordinary PNG.
  #[inline]
  #[must_use]
  pub(crate) fn mng(&self) -> Option<&crate::exif::mng::MngMeta> {
    self.mng.as_ref()
  }

  /// Get the MNG sub-Meta, lazily creating an empty one — the chunk-walker hook
  /// called for each MNG-specific chunk when the resolved file type is MNG/JNG.
  /// The walker appends the decoded leaves via the returned `&mut MngMeta`.
  #[inline]
  pub(crate) fn mng_mut(&mut self) -> &mut crate::exif::mng::MngMeta {
    self.mng.get_or_insert_with(crate::exif::mng::MngMeta::new)
  }

  /// The decoded JUMBF / C2PA metadata of a `caBX` chunk, if any. `None` for a
  /// PNG with no `caBX` (and for a `caBX` whose box stream recognized nothing).
  #[inline]
  #[must_use]
  pub(crate) fn jumbf(&self) -> Option<&crate::exif::jumbf::JumbfMeta> {
    self.jumbf.as_ref()
  }

  /// Record the decoded JUMBF metadata of a `caBX` chunk — the chunk-walker hook
  /// called once per `caBX` chunk (`PNG.pm:343-346`). A non-empty decode REPLACES
  /// any prior for the TAG output (a PNG may legally carry a single `caBX`;
  /// last-wins matches the `%PNG::Main` `caBX` non-List default); an empty decode
  /// (`JumbfMeta::is_empty`) is dropped whole so the PNG output stays
  /// byte-identical.
  ///
  /// EACH non-empty `caBX` appends one [`PngDiagStep::Jumbf`] to
  /// [`Self::diag_order`] at ITS chunk-walk position, carrying the index of THAT
  /// `caBX`'s warnings stored in [`Self::jumbf_diags`] — so the JUMBF walker's
  /// warnings drain at the `caBX` chunk position rather than after the whole walk,
  /// PER occurrence. Load-bearing for the document-level priority-0 first-wins
  /// `ExifTool:Warning` (a malformed `caBX` before a later PNG warning must win):
  /// the diagnostics are decoupled from the last-wins TAG meta, so a malformed
  /// LATER `caBX` does NOT steal the slot from an earlier-walked warning. The TAG
  /// output ([`Self::jumbf`]) still last-wins-replaces (a 2nd `caBX`'s tags
  /// overwrite), matching the `%PNG::Main` singleton key.
  #[inline]
  pub(crate) fn set_jumbf(&mut self, jumbf: crate::exif::jumbf::JumbfMeta) {
    if !jumbf.is_empty() {
      self
        .diag_order
        .push(PngDiagStep::Jumbf(self.jumbf_diags.len()));
      self.jumbf_diags.push(jumbf.warnings().to_vec());
      self.jumbf = Some(jumbf);
    }
  }

  /// The JUMBF walker warnings recorded for the `caBX` occurrence at `index` (the
  /// index a [`PngDiagStep::Jumbf`] carries) — the per-occurrence diagnostic
  /// drain reads them at the `caBX` walk position. `None` for an out-of-range
  /// index (defensive; the drain only replays recorded steps).
  #[inline]
  #[must_use]
  pub(crate) fn jumbf_diag(&self, index: usize) -> Option<&[crate::exif::jumbf::JumbfWarning]> {
    self.jumbf_diags.get(index).map(Vec::as_slice)
  }

  /// The WALK-ORDER interleaving of the three document-diagnostic sources (one
  /// [`PngDiagStep`] per push to [`Self::warnings`] / [`Self::exif_events`] /
  /// [`Self::xmp_profiles`]). The warning drain
  /// ([`crate::diagnostics::Diagnose`]) replays it with three cursors so every
  /// document warning surfaces at its chunk-walk position (#205).
  #[inline]
  #[must_use]
  pub(crate) fn diag_order(&self) -> &[PngDiagStep] {
    &self.diag_order
  }

  // ===== trailer (post-IEND) bookkeeping ================================

  /// Enter TRAILER mode — the chunk-walker hook called ONCE when it crosses the
  /// `IEND` end chunk with unconsumed trailer bytes remaining
  /// (`PNG.pm:1479-1484`, where bundled sets `$$et{SET_GROUP1} = 'Trailer'`).
  /// Captures the current list lengths as the trailer watermarks: every text
  /// record / dynamic tag / EXIF event pushed AFTER this is a TRAILER chunk and
  /// its PNG-level tags carry the `Trailer` family-1 override. Idempotent (the
  /// watermarks are only captured on the first call; a malformed trailer that
  /// stops immediately still records the boundary).
  pub(crate) fn begin_trailer(&mut self) {
    if !self.in_trailer {
      self.in_trailer = true;
      self.trailer_text_start = self.text_records.len();
      self.trailer_dynamic_start = self.dynamic_profile_tags.len();
      self.trailer_event_start = self.exif_events.len();
      #[cfg(feature = "xmp")]
      {
        self.trailer_xmp_start = self.xmp_profiles.len();
      }
      // `PNG.pm:1481-1484`: the `Trailer data after PNG IEND chunk` entry
      // warning is raised (and pushed) by the walker BEFORE this call, so it
      // sits below the watermark and stays document-level; every warning raised
      // while parsing a trailer chunk lands at/after the watermark and so
      // surfaces as `Trailer:Warning` (`SET_GROUP1 = 'Trailer'`).
      self.trailer_warning_start = self.warnings.len();
    }
  }

  /// The current post-`MEND`/`IEND` trailer state (`PNG.pm:1484`
  /// `$$et{SET_GROUP1} = 'Trailer'`). The MNG-specific chunk dispatch
  /// ([`crate::formats::png::ProcessPng`]) reads it to stamp each MNG leaf's
  /// trailer provenance at decode time (the per-leaf analogue of the watermark
  /// indices the list-stored PNG tags use, since the MNG leaves live in a
  /// sub-Meta the watermark-by-index scheme cannot reach).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn in_trailer(&self) -> bool {
    self.in_trailer
  }

  /// Whether the text record at index `i` was parsed from a post-`IEND`
  /// TRAILER chunk (so its tag carries the `Trailer` family-1 override).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn text_record_is_trailing(&self, i: usize) -> bool {
    i >= self.trailer_text_start
  }

  /// Whether the dynamic profile tag at index `i` came from a TRAILER chunk.
  #[inline(always)]
  #[must_use]
  pub(crate) const fn dynamic_tag_is_trailing(&self, i: usize) -> bool {
    i >= self.trailer_dynamic_start
  }

  /// Whether the EXIF event at index `i` came from a TRAILER chunk (so its
  /// PNG-level `ExifByteOrder` + the GPS sub-IFD carry the `Trailer` override;
  /// the `Exif::Main`-table IFDs keep their `IFD0`/`ExifIFD`/… group).
  #[inline(always)]
  #[must_use]
  pub(crate) const fn event_is_trailing(&self, i: usize) -> bool {
    i >= self.trailer_event_start
  }

  /// Whether the XMP raw profile at index `i` came from a post-`IEND` TRAILER
  /// chunk (so its decoded `XMP-*` tags carry the `Trailer` family-1 override,
  /// `PNG.pm:1484`).
  #[cfg(feature = "xmp")]
  #[inline(always)]
  #[must_use]
  pub(crate) const fn xmp_is_trailing(&self, i: usize) -> bool {
    i >= self.trailer_xmp_start
  }

  /// Whether the warning at index `i` in [`Self::warnings`] was raised while the
  /// chunk walker was in post-`IEND` TRAILER mode (`PNG.pm:1484`
  /// `$$et{SET_GROUP1} = 'Trailer'`), so it surfaces as the family-1
  /// `Trailer:Warning` TAG rather than the document-level `ExifTool:Warning`.
  /// `false` for every warning of a standard (IEND-last) PNG.
  #[inline(always)]
  #[must_use]
  pub(crate) const fn warning_is_trailing(&self, i: usize) -> bool {
    i >= self.trailer_warning_start
  }

  /// Whether the `IHDR` sub-table tags came from a TRAILER chunk.
  #[inline(always)]
  #[must_use]
  pub(crate) const fn ihdr_is_trailing(&self) -> bool {
    self.structural_trailing.ihdr
  }

  /// Whether the `pHYs` sub-table tags came from a TRAILER chunk.
  #[inline(always)]
  #[must_use]
  pub(crate) const fn phys_is_trailing(&self) -> bool {
    self.structural_trailing.phys
  }

  /// Whether the `iCCP-name` (ProfileName) tag came from a TRAILER chunk.
  #[inline(always)]
  #[must_use]
  pub(crate) const fn iccp_is_trailing(&self) -> bool {
    self.structural_trailing.iccp
  }

  /// Whether the `bKGD` (BackgroundColor) tag came from a TRAILER chunk.
  #[inline(always)]
  #[must_use]
  pub(crate) const fn bkgd_is_trailing(&self) -> bool {
    self.structural_trailing.bkgd
  }

  /// Whether the `tIME` (ModifyDate) tag came from a TRAILER chunk.
  #[inline(always)]
  #[must_use]
  pub(crate) const fn time_is_trailing(&self) -> bool {
    self.structural_trailing.time
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn empty_meta_has_no_chunks() {
    let m = PngMeta::new();
    assert!(m.width().is_none());
    assert!(m.height().is_none());
    assert!(m.dimensions().is_none());
    assert!(m.bit_depth().is_none());
    assert!(m.color_type().is_none());
    assert!(m.icc_profile_name().is_none());
    assert!(m.background_color().is_none());
    assert!(m.modify_date().is_none());
    assert!(m.text_records().is_empty());
    assert!(m.exif_events().is_empty());
    assert!(m.warnings().is_empty());
    assert!(m.dpi().is_none());
  }

  #[test]
  fn ihdr_setters_populate_dimensions_and_color_type() {
    let mut m = PngMeta::new();
    m.set_ihdr(IhdrFields {
      width: 16,
      height: 16,
      bit_depth: 1,
      color_type: 0,
      compression: 0,
      filter: 0,
      interlace: 0,
    });
    assert_eq!(m.width(), Some(16));
    assert_eq!(m.height(), Some(16));
    assert_eq!(m.dimensions(), Some((16, 16)));
    assert_eq!(m.bit_depth(), Some(1));
    assert!(m.color_type().expect("set").is_grayscale());
    assert_eq!(m.color_type().expect("set").print_conv(), Some("Grayscale"));
  }

  #[test]
  fn color_type_classifies_every_table_byte() {
    assert!(PngColorType::from_byte(0).is_grayscale());
    assert!(PngColorType::from_byte(2).is_rgb());
    assert!(PngColorType::from_byte(3).is_palette());
    assert!(PngColorType::from_byte(4).is_grayscale_alpha());
    assert!(PngColorType::from_byte(6).is_rgb_alpha());
    assert!(PngColorType::from_byte(99).is_other());
    assert_eq!(PngColorType::from_byte(99).as_byte(), 99);
    assert!(PngColorType::from_byte(99).print_conv().is_none());
  }

  #[test]
  fn phys_dpi_converts_pixels_per_meter() {
    let mut m = PngMeta::new();
    // 2834 ppm ≈ 71.98 dpi — bundled's pHYs default.
    m.set_phys(2834, 2834, 1);
    let (dx, dy) = m.dpi().expect("dpi computed");
    // 2834 * 0.0254 = 71.9836
    assert!((dx - 71.9836).abs() < 1e-9, "dx = {dx}");
    assert!((dy - 71.9836).abs() < 1e-9, "dy = {dy}");
  }

  #[test]
  fn phys_dpi_returns_none_for_unknown_units() {
    let mut m = PngMeta::new();
    m.set_phys(2834, 2834, 0);
    assert!(m.dpi().is_none());
  }

  #[test]
  fn text_record_text_chunk_round_trip() {
    let r = PngTextRecord::new_text("Comment".into(), "test comment".to_string());
    assert!(r.kind().is_text());
    assert_eq!(r.keyword(), "Comment");
    assert_eq!(r.value(), "test comment");
    assert!(r.language().is_none());
    assert!(r.translated_keyword().is_none());
    assert!(!r.is_compressed());
  }

  #[test]
  fn text_record_itxt_carries_language() {
    let r = PngTextRecord::new_itxt(
      "Title".into(),
      "Hello".to_string(),
      "en".into(),
      "Greeting".into(),
      false,
    );
    assert!(r.kind().is_itxt());
    assert_eq!(r.language(), Some("en"));
    assert_eq!(r.translated_keyword(), Some("Greeting"));
    assert!(!r.is_compressed());
  }

  #[test]
  fn text_record_ztxt_deferred_carries_empty_value() {
    let r = PngTextRecord::new_ztxt_deferred("Description".into());
    assert!(r.kind().is_ztxt());
    assert_eq!(r.keyword(), "Description");
    assert!(r.value().is_empty());
    assert!(r.is_compressed());
  }

  #[test]
  fn exif_event_round_trip_preserves_order_and_kind() {
    let mut m = PngMeta::new();
    // A native eXIf chunk, then a reset-only profile, then an EXIF raw-profile.
    m.push_exif_event(PngExifEvent::NativeTiff(
      (*b"MM\x00\x2a\x00\x00\x00\x08").into(),
    ));
    m.push_exif_event(PngExifEvent::ResetOnlyProfile);
    m.push_exif_event(PngExifEvent::ExifProfile(
      b"II\x2a\x00\x08\x00\x00\x00".to_vec(),
    ));
    let evs = m.exif_events();
    assert_eq!(evs.len(), 3);
    // Walk order is preserved, each variant classified + block exposed.
    assert!(evs[0].is_native());
    assert_eq!(
      evs[0].block(),
      Some(b"MM\x00\x2a\x00\x00\x00\x08".as_slice())
    );
    assert!(evs[1].is_reset_only());
    assert_eq!(evs[1].block(), None);
    assert!(evs[2].is_exif_profile());
    assert_eq!(
      evs[2].block(),
      Some(b"II\x2a\x00\x08\x00\x00\x00".as_slice())
    );
  }

  #[test]
  fn warnings_push() {
    let mut m = PngMeta::new();
    m.push_warning("Bad CRC for IHDR chunk".to_string());
    assert_eq!(m.warnings().len(), 1);
    assert_eq!(m.warnings()[0], "Bad CRC for IHDR chunk");
  }
}
