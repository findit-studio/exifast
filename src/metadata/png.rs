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
  /// `II`/`MM`-led TIFF block.
  NativeTiff(Vec<u8>),
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
      Self::NativeTiff(b) | Self::ExifProfile(b) => Some(b),
      Self::ResetOnlyProfile => None,
    }
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
  // ----- pHYs (PNG.pm:216-222, sub-table PNG.pm:441-468) ----------------
  /// `pHYs.PixelsPerUnitX` (`PNG.pm:453-457`).
  pixels_per_unit_x: Option<u32>,
  /// `pHYs.PixelsPerUnitY` (`PNG.pm:458-462`).
  pixels_per_unit_y: Option<u32>,
  /// `pHYs.PixelUnits` (`PNG.pm:463-467`). `0` = unknown, `1` = meters.
  pixel_units: Option<u8>,
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
      pixels_per_unit_x: None,
      pixels_per_unit_y: None,
      pixel_units: None,
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
      structural_trailing: StructuralTrailing {
        ihdr: false,
        phys: false,
        iccp: false,
        bkgd: false,
        time: false,
      },
      warnings: Vec::new(),
      diag_order: Vec::new(),
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
    }
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
      b"MM\x00\x2a\x00\x00\x00\x08".to_vec(),
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
