//! Typed brand-variant metadata for the QuickTime/ISO-BMFF container —
//! the `ftyp` brand-dispatch layer. SP4 wires HEIC/AVIF/CR3/JP2 into the
//! QuickTime walker; this module holds the typed sub-metas each variant
//! produces.
//!
//! Three faithful sub-metas live here:
//!
//!  - [`HeifMeta`] — items extracted from a HEIF/HEIC/AVIF `meta` box
//!    via the iinf/iloc/ipma/ipco/iref walker (QuickTime.pm:2834-2916,
//!    9131-9523). Surfaces the PrimaryItem id, per-item Type/Name/
//!    ContentType, and Extent (offset+length) information that
//!    [`crate::formats::quicktime_brands`] uses to locate embedded
//!    Exif/XMP item data.
//!
//!  - [`Cr3Meta`] — Canon CR3 / CRM (`crx ` brand) container identity.
//!    Records the CompressorVersion string (CNCV) that drives the
//!    CR3-vs-CRM override (Canon.pm:9664-9668 `OverrideFileType($1)`),
//!    plus presence/offset of the per-block Canon CMT1/CMT2/CMT3/CMT4
//!    payloads (Canon.pm:9684-9726). The CMT bodies are TIFF/Exif blocks
//!    that the Exif IFD parser (PR #36) would decode; SP4 only records
//!    their location + size + flagged-for-deferral fact.
//!
//!  - [`Jp2Meta`] — JPEG 2000 (`JP2`/`jpx`/`jpm`/`mj2` brands) container
//!    identity. Records the detected sub-type (JP2/JPX/JPM/JXL/JPH) and
//!    presence/location of the JP2 UUID-Exif / UUID-XMP boxes
//!    (Jpeg2000.pm:279-352). Like CR3, the embedded Exif body parse is
//!    deferred to PR #36.
//!
//! Every typed value here flows into [`crate::metadata::MediaMetadata`]
//! via the per-variant [`crate::metadata::MetaProjectInto`] impl in
//! [`crate::formats::quicktime`].
//!
//! ## D8 + SmolStr policy
//!
//! All fields are PRIVATE; access is through accessors only (D8 mandate).
//! STORED string data uses `SmolStr` (most brand/type strings are 4 ASCII
//! bytes — well within the SmolStr inline budget); TRANSIENT builders
//! during decode use plain `String`. Numeric fields use the native
//! width the source ISO-BMFF spec defines (u64 for offsets, u32 for
//! sizes/version counts, u16 for item ids ≤v1 / u32 for item ids ≥v2).

use core::default::Default;

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use smol_str::SmolStr;

use crate::metadata::MediaMetadata;

// ===========================================================================
// HEIF item extent (iloc) — offset+length pair into the file
// ===========================================================================

/// One extent in an ISO-BMFF `iloc` (Item Location) record. Bundled
/// stores these as `[$extent_index, $extent_offset, $extent_length, ...]`
/// (QuickTime.pm:9189). exifast keeps only the offset+length the consumer
/// needs to read the item body — `$extent_index` is only meaningful for
/// item-construction-method == 2 (offset INSIDE another item) which is
/// rare and DEFERRED.
///
/// All offsets are absolute file positions (after `BaseOffset` is added
/// — see `HandleItemInfo` at QuickTime.pm:9397).
#[derive(Debug, Clone, Default)]
pub struct HeifExtent {
  offset: u64,
  length: u64,
}

impl HeifExtent {
  /// Construct an empty extent (zero offset / length).
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {
      offset: 0,
      length: 0,
    }
  }

  /// The absolute file offset of the extent's first byte.
  #[must_use]
  #[inline(always)]
  pub const fn offset(&self) -> u64 {
    self.offset
  }

  /// The extent's length in bytes.
  #[must_use]
  #[inline(always)]
  pub const fn length(&self) -> u64 {
    self.length
  }

  /// Setter (offset).
  #[inline(always)]
  pub const fn set_offset(&mut self, v: u64) -> &mut Self {
    self.offset = v;
    self
  }

  /// Setter (length).
  #[inline(always)]
  pub const fn set_length(&mut self, v: u64) -> &mut Self {
    self.length = v;
    self
  }
}

// ===========================================================================
// HEIF item — one infe / iloc / ipma row
// ===========================================================================

/// One HEIF / HEIC / AVIF item — the union of the `infe` (Item Info
/// Entry) and `iloc` (Item Location) rows that share an item id.
///
/// Bundled stores this as `$$items{$id}{Type} / {Name} / {ContentType} /
/// {Extents} / {BaseOffset}` (QuickTime.pm:9244-9272 + 9173-9192).
/// exifast surfaces the fields that drive [`HandleItemInfo`]
/// (QuickTime.pm:9343-9526): `Type` (`Exif`/`xml1`/`mime`/`uri `/`hvc1`/
/// `av01`/`grid`/`iovl`/`tmap`), `Name`, `ContentType`, and the
/// per-extent file location.
#[derive(Debug, Clone, Default)]
pub struct HeifItem {
  id: u32,
  item_type: Option<SmolStr>,
  name: Option<SmolStr>,
  content_type: Option<SmolStr>,
  extents: Vec<HeifExtent>,
  base_offset: u64,
  construction_method: u16,
  // Per-field "was this infe version-branch the one that assigned it?"
  // flags — they record WHICH slot fields a single `infe` entry actually
  // wrote, so the keyed `iinf` merge can faithfully distinguish "this
  // entry assigned the field (overwrite, possibly to `None`)" from "this
  // entry's version branch never touched the field (keep the prior
  // value)". ExifTool's `ParseItemInfoEntry` (QuickTime.pm:9228-9281)
  // assigns `Type` ONLY in the v2/3/4+ else-branch (:9258) and
  // `ContentType` ONLY in v0/1 (:9245) or the v2/3/4+ `mime` arm (:9262);
  // a plain `Some`/`None` on the value cannot tell "untouched" from
  // "assigned to a non-UTF-8 → `None`". (Name is assigned by EVERY
  // version, so it needs no flag — the merge always overwrites it.) These
  // flags are merge-time bookkeeping only; they never participate in
  // identity/emptiness.
  type_assigned: bool,
  content_type_assigned: bool,
}

impl HeifItem {
  /// Construct an empty `HeifItem` (zero id, no fields).
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {
      id: 0,
      item_type: None,
      name: None,
      content_type: None,
      extents: Vec::new(),
      base_offset: 0,
      construction_method: 0,
      type_assigned: false,
      content_type_assigned: false,
    }
  }

  /// The 1-based ISO-BMFF item id (QuickTime.pm:9241-9253).
  #[must_use]
  #[inline(always)]
  pub const fn id(&self) -> u32 {
    self.id
  }

  /// The 4-byte item type — `Exif`, `xml1`, `mime`, `uri `, `hvc1`,
  /// `av01`, `grid`, `iovl`, `tmap` …  (QuickTime.pm:3415 comment).
  /// `None` for `infe` version 0/1 entries (which carry a Name only,
  /// QuickTime.pm:9240-9246).
  #[must_use]
  #[inline(always)]
  pub fn item_type(&self) -> Option<&str> {
    self.item_type.as_deref()
  }

  /// The item's UTF-8 name (a free-form string, often empty).
  #[must_use]
  #[inline(always)]
  pub fn name(&self) -> Option<&str> {
    self.name.as_deref()
  }

  /// The MIME content type — populated only for `type=='mime'` items
  /// (QuickTime.pm:9261-9263). For Exif/XMP items this is `None`;
  /// `HandleItemInfo` later maps `application/rdf+xml` → XMP.
  #[must_use]
  #[inline(always)]
  pub fn content_type(&self) -> Option<&str> {
    self.content_type.as_deref()
  }

  /// `true` when the `infe` entry that produced this item ASSIGNED `Type`
  /// — i.e. it took the v2/3/4+ else-branch (QuickTime.pm:9258, where
  /// `$$items{$id}{Type}` is set from the raw 4 bytes). v0/1 entries
  /// never assign `Type`, so this stays `false` for them. The keyed
  /// `iinf` merge overwrites the slot's `item_type` ONLY when this is set
  /// (so a v0 entry never nulls a Type set by an earlier v2 entry, while
  /// a v2 entry with a non-UTF-8 type — `item_type() == None` but
  /// `type_assigned() == true` — DOES clear the prior Type).
  #[must_use]
  #[inline(always)]
  pub const fn type_assigned(&self) -> bool {
    self.type_assigned
  }

  /// `true` when the `infe` entry that produced this item ASSIGNED
  /// `ContentType` — v0/1 always (QuickTime.pm:9245), and the v2/3/4+
  /// `mime` arm (:9262). A v2/3/4+ entry whose type is NOT `mime`
  /// (`Exif`/`uri `/…) assigns NEITHER ContentType nor URI, so this stays
  /// `false` and the merge KEEPS any prior ContentType. The merge
  /// overwrites the slot's `content_type` ONLY when this is set.
  #[must_use]
  #[inline(always)]
  pub const fn content_type_assigned(&self) -> bool {
    self.content_type_assigned
  }

  /// The list of extents (offset+length pairs) for this item. Most
  /// HEIF items have exactly ONE extent; multi-extent items appear for
  /// derived / grid / overlay images (DEFERRED). All offsets are
  /// file-absolute (`BaseOffset` is folded in by the walker).
  #[must_use]
  #[inline(always)]
  pub fn extents(&self) -> &[HeifExtent] {
    &self.extents
  }

  /// `BaseOffset` from the `iloc` row — bundled adds this to every
  /// extent offset (QuickTime.pm:9173). Stored for completeness; the
  /// walker SHOULD have already folded it into `extents()`.
  #[must_use]
  #[inline(always)]
  pub const fn base_offset(&self) -> u64 {
    self.base_offset
  }

  /// `ConstructionMethod` (QuickTime.pm:9167): 0 = file offset,
  /// 1 = idat-relative, 2 = item-relative. Only 0 and (with `idat`
  /// captured) 1 are supported; 2 is DEFERRED.
  #[must_use]
  #[inline(always)]
  pub const fn construction_method(&self) -> u16 {
    self.construction_method
  }

  /// Setter (id).
  #[inline(always)]
  pub const fn set_id(&mut self, v: u32) -> &mut Self {
    self.id = v;
    self
  }

  /// Setter (item type).
  #[inline(always)]
  pub fn set_item_type(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.item_type = v;
    self
  }

  /// Setter (name).
  #[inline(always)]
  pub fn set_name(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.name = v;
    self
  }

  /// Setter (content type).
  #[inline(always)]
  pub fn set_content_type(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.content_type = v;
    self
  }

  /// Setter (Type-assigned flag — see [`Self::type_assigned`]).
  #[inline(always)]
  pub const fn set_type_assigned(&mut self, v: bool) -> &mut Self {
    self.type_assigned = v;
    self
  }

  /// Setter (ContentType-assigned flag — see
  /// [`Self::content_type_assigned`]).
  #[inline(always)]
  pub const fn set_content_type_assigned(&mut self, v: bool) -> &mut Self {
    self.content_type_assigned = v;
    self
  }

  /// Setter (push one extent).
  #[inline(always)]
  pub fn push_extent(&mut self, e: HeifExtent) -> &mut Self {
    self.extents.push(e);
    self
  }

  /// Setter (REPLACE the whole extent vector). Mirrors the `iloc` parse's
  /// `$$items{$id}{Extents} = \@extents` (QuickTime.pm:9192) — a fresh
  /// `iloc` row for an item id assigns (overwrites) its extents, it does
  /// not append to a prior row's.
  #[inline(always)]
  pub fn set_extents(&mut self, v: Vec<HeifExtent>) -> &mut Self {
    self.extents = v;
    self
  }

  /// Setter (base offset).
  #[inline(always)]
  pub const fn set_base_offset(&mut self, v: u64) -> &mut Self {
    self.base_offset = v;
    self
  }

  /// Setter (construction method).
  #[inline(always)]
  pub const fn set_construction_method(&mut self, v: u16) -> &mut Self {
    self.construction_method = v;
    self
  }
}

// ===========================================================================
// Av1Config — the `av1C` AV1 Codec Configuration record
// ===========================================================================

/// The decoded `av1C` box (AV1 Codec Configuration Record), faithful to the
/// `%Image::ExifTool::QuickTime::AV1Config` `ProcessBinaryData` table
/// (QuickTime.pm:3308-3367). The box is an `ipco` item property whose body is
/// the raw `AV1CodecConfigurationRecord` (no version/flags fullbox prefix —
/// `FIRST_ENTRY => 0`, format `int8u`).
///
/// SP4 surfaces only the three NON-`Unknown` tags ExifTool emits by default:
/// `AV1ConfigurationVersion` (byte 0, `Mask 0x7f`), `ChromaFormat` (byte 2,
/// `Mask 0x1c`), and `ChromaSamplePosition` (byte 2, `Mask 0x03`). The
/// `Unknown => 1` fields (`SeqProfile`/`SeqLevelIdx0`/`SeqTier0`/`HighBitDepth`/
/// `TwelveBit`/`InitialDelaySamples`) are not extracted unless `-U`/`Unknown`
/// is set, which exifast does not surface — so they are not stored. The stored
/// values are the MASKED-and-BITSHIFTED ints (`($byte & Mask) >> BitShift`,
/// ExifTool.pm:5916-5921 + :10079), i.e. the keys into the PrintConv maps.
///
/// Each field is an [`Option`] tracking PER-FIELD PRESENCE — `ProcessBinaryData`
/// emits a tag IFF its byte offset is within the data length (ExifTool.pm:
/// 9963-9964: `my $more = $size - $entry; last if $more <= 0`). So a truncated
/// `av1C` whose body stops short of byte 2 emits only `AV1ConfigurationVersion`
/// (byte 0), leaving `chroma_format`/`chroma_sample_position` `None`. A real
/// record is ≥ 4 bytes and populates all three; the `Option`s only diverge for a
/// crafted/truncated box. Duplicate `av1C` boxes merge PER TAG via [`Self::merge`]
/// — a later truncated box overwrites only the fields it contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Av1Config {
  version: Option<u8>,
  chroma_format: Option<u8>,
  chroma_sample_position: Option<u8>,
}

impl Av1Config {
  /// Construct an `Av1Config` from the per-field masked/bitshifted values, each
  /// `Some` only when its source byte was present in the `av1C` body.
  #[must_use]
  #[inline(always)]
  pub const fn new(
    version: Option<u8>,
    chroma_format: Option<u8>,
    chroma_sample_position: Option<u8>,
  ) -> Self {
    Self {
      version,
      chroma_format,
      chroma_sample_position,
    }
  }

  /// `AV1ConfigurationVersion` — byte 0 `& 0x7f` (QuickTime.pm:3312-3315). No
  /// PrintConv ⇒ a bare int in both modes. `None` when byte 0 was absent (an
  /// empty `av1C` body).
  #[must_use]
  #[inline(always)]
  pub const fn version(&self) -> Option<u8> {
    self.version
  }

  /// `ChromaFormat` — `(byte 2 & 0x1c) >> 2` (QuickTime.pm:3341-3351); the
  /// PrintConv key (`0`/`2`/`3`/`7` ⇒ the YUV / Monochrome label). `None` when
  /// the body stopped short of byte 2 (a 1- or 2-byte truncated `av1C`).
  #[must_use]
  #[inline(always)]
  pub const fn chroma_format(&self) -> Option<u8> {
    self.chroma_format
  }

  /// `ChromaSamplePosition` — byte 2 `& 0x03` (QuickTime.pm:3352-3361); the
  /// PrintConv key (`0`/`1`/`2`/`3` ⇒ Unknown / Vertical / Colocated /
  /// (reserved)). `None` when the body stopped short of byte 2.
  #[must_use]
  #[inline(always)]
  pub const fn chroma_sample_position(&self) -> Option<u8> {
    self.chroma_sample_position
  }

  /// Merge a later `av1C`'s fields into this one with PER-TAG last-wins, matching
  /// `ProcessBinaryData`: re-running the `AV1Config` table on a second `av1C`
  /// FoundTag-overwrites each tag the second box CONTAINS, but a tag the second
  /// box lacks (truncated past its byte offset) keeps the earlier value. So a
  /// later 1-byte `av1C` overwrites `AV1ConfigurationVersion` only, leaving an
  /// earlier `ChromaFormat`/`ChromaSamplePosition` intact (oracle: full 4-byte
  /// then 1-byte `av1C` → `ChromaFormat` from the first, `AV1ConfigurationVersion`
  /// from the second). Each present (`Some`) field of `next` replaces this
  /// field's value; an absent (`None`) field of `next` leaves this one unchanged.
  #[inline]
  pub const fn merge(&mut self, next: Self) {
    if next.version.is_some() {
      self.version = next.version;
    }
    if next.chroma_format.is_some() {
      self.chroma_format = next.chroma_format;
    }
    if next.chroma_sample_position.is_some() {
      self.chroma_sample_position = next.chroma_sample_position;
    }
  }
}

// ===========================================================================
// HeifMeta — the full HEIF meta-box parse
// ===========================================================================

/// Typed mirror of the HEIF / HEIC / AVIF `meta` box parse — the union
/// of the iinf, iloc, ipma, ipco, iref, pitm rows that drive
/// `HandleItemInfo` at QuickTime.pm:9343-9526.
///
/// Bundled scatters the data across `$$et{ItemInfo}`, `$$et{PrimaryItem}`,
/// `$$et{ItemPropertyContainer}`, `$$et{MediaDataInfo}` — exifast
/// gathers them all into this single typed surface. The faithful
/// post-`meta`-walk routine in [`crate::formats::quicktime_brands`]
/// populates this struct; downstream code reads it via the accessors.
///
/// **What this surfaces (camera-indexing scope):**
///  - The PrimaryItem id (`pitm`) — the image's "main" item.
///  - Per-item Type / Name / ContentType / Extents — so an Exif item's
///    bytes can be located.
///  - The `idat` payload (offset + length) when a HEIC carries one —
///    needed for construction-method == 1 extents.
///
/// **What is DEFERRED:**
///  - `ipco`/`ipma` property dispatch (ImageSpatialExtent / Rotation /
///    Mirroring / ColorSpec) — present in the parse but not surfaced as
///    typed fields (would need the per-property tables QuickTime.pm:
///    2986-3411).
///  - `iref` deep relationships (`dimg`/`thmb`/`auxl`/`base`) — only
///    `cdsc` (ContentDescribes) is decoded; full thumbnail-graph walk
///    is a P3 follow-up.
///  - Derived images (`grid`/`iovl`/`iden`) — these compose multiple
///    extents into a single rendered image; SP4 records their items
///    but does NOT execute the composition (P3 follow-up).
#[derive(Debug, Clone, Default)]
pub struct HeifMeta {
  primary_item: Option<u32>,
  items: Vec<HeifItem>,
  idat_offset: Option<u64>,
  idat_length: Option<u64>,
  /// `File:ImageWidth` from a main-document `ispe` (ImageSpatialExtent)
  /// property in `ipco` (QuickTime.pm:3034-3047). The last main-document
  /// `ispe` in `ipco` order wins (last-FoundTag-wins); a main-document `ispe`
  /// is one no item associates, or one the primary item associates. `None`
  /// when no main-document `ispe` was decoded (e.g. a non-HEIF `meta` box). #146.
  image_width: Option<u32>,
  /// `File:ImageHeight` from the same main-document `ispe` (#146).
  image_height: Option<u32>,
  /// The decoded `av1C` (AV1 Codec Configuration) box from `ipco`
  /// (QuickTime.pm:3079-3082 → the `AV1Config` table). `None` for a non-AVIF
  /// `meta` box (or one without an `av1C` property). Duplicate `av1C` boxes
  /// resolve PER TAG — ExifTool walks every `ipco` child positionally and
  /// re-runs the `AV1Config` ProcessBinaryData per `av1C` box, each FoundTag
  /// overwriting only the tags THAT box contains (last-wins per tag, see
  /// [`Av1Config::merge`]). A real AVIF carries exactly one. #149.
  av1_config: Option<Av1Config>,
  warning: Option<String>,
  /// The absolute file offset of the `meta` box whose walk produced
  /// [`Self::warning`] — recorded first-wins alongside the warning so the
  /// document-level diagnostics drain can order this walk warning against the
  /// `ProcessMOV` atom warning BY FILE POSITION (ExifTool emits `Warning` tags
  /// priority-0 first-wins, the earliest by walk order; QuickTime's `meta` box
  /// is walked at its atom position, so a `ParseItemInfoEntry` /
  /// `ParseItemPropAssoc` warning must outrank a LATER malformed top-level
  /// atom's warning). `None` when no warning was recorded. #159.
  warning_offset: Option<u64>,
}

impl HeifMeta {
  /// Construct an empty `HeifMeta`.
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {
      primary_item: None,
      items: Vec::new(),
      idat_offset: None,
      idat_length: None,
      image_width: None,
      image_height: None,
      av1_config: None,
      warning: None,
      warning_offset: None,
    }
  }

  /// The `pitm` PrimaryItem reference id — the "main" image. `None`
  /// when no `pitm` box was seen (or the meta-box version was malformed).
  /// Faithful to QuickTime.pm:2883-2892 `$$self{PrimaryItem}`.
  #[must_use]
  #[inline(always)]
  pub const fn primary_item(&self) -> Option<u32> {
    self.primary_item
  }

  /// The list of decoded items (one per `infe` / `iloc` pair). Sorted
  /// by item id (the `HandleItemInfo` invariant at QuickTime.pm:9358
  /// `sort { $a <=> $b } keys %$items`).
  #[must_use]
  #[inline(always)]
  pub fn items(&self) -> &[HeifItem] {
    &self.items
  }

  /// The `idat` payload offset (file-absolute). Used for items with
  /// `construction_method == 1` (HEIC default for the primary item).
  #[must_use]
  #[inline(always)]
  pub const fn idat_offset(&self) -> Option<u64> {
    self.idat_offset
  }

  /// The `idat` payload length in bytes.
  #[must_use]
  #[inline(always)]
  pub const fn idat_length(&self) -> Option<u64> {
    self.idat_length
  }

  /// `File:ImageWidth` — the last main-document `ispe` width (#146). `None`
  /// when no main-document `ispe` was decoded.
  #[must_use]
  #[inline(always)]
  pub const fn image_width(&self) -> Option<u32> {
    self.image_width
  }

  /// `File:ImageHeight` — the last main-document `ispe` height (#146).
  #[must_use]
  #[inline(always)]
  pub const fn image_height(&self) -> Option<u32> {
    self.image_height
  }

  /// The decoded `av1C` AV1 Codec Configuration (#149). `None` for a non-AVIF
  /// `meta` box (no `av1C` property).
  #[must_use]
  #[inline(always)]
  pub const fn av1_config(&self) -> Option<Av1Config> {
    self.av1_config
  }

  /// First non-fatal warning surfaced during the meta-box walk
  /// (truncated iloc/iinf/ipma, item-info entries out of order, …).
  /// `None` for a clean parse.
  #[must_use]
  #[inline(always)]
  pub fn warning(&self) -> Option<&str> {
    self.warning.as_deref()
  }

  /// The absolute file offset of the `meta` box that produced
  /// [`Self::warning`] (recorded first-wins by [`Self::set_warning_at`]).
  /// Consumed by the QuickTime document-level diagnostics drain to order this
  /// walk warning against the `ProcessMOV` atom warning by file position. #159.
  #[must_use]
  #[inline(always)]
  pub const fn warning_offset(&self) -> Option<u64> {
    self.warning_offset
  }

  /// `true` when no `meta` box was decoded (no items, no pitm, no
  /// warning). Used by the projection layer to skip a non-HEIF file.
  #[must_use]
  #[inline(always)]
  pub fn is_empty(&self) -> bool {
    self.primary_item.is_none() && self.items.is_empty() && self.warning.is_none()
  }

  /// Look up an item by id (linear scan — most HEIF files have only a
  /// handful of items so a HashMap would be overkill).
  #[must_use]
  #[inline(always)]
  pub fn item_by_id(&self, id: u32) -> Option<&HeifItem> {
    self.items.iter().find(|i| i.id() == id)
  }

  /// Locate the FIRST item whose `Type` is `Exif` — the canonical Exif
  /// item in HEIC/AVIF (QuickTime.pm:9371 `Exif => 'EXIF'`).
  //
  // TODO(#36): this matches on `Type == Exif` alone. ExifTool's
  // `HandleItemInfo` classifies each item by its Perl-truthy EFFECTIVE
  // type `$$item{ContentType} || $$item{Type} || next`
  // (QuickTime.pm:9360), so a NON-EMPTY `ContentType` DOMINATES a later
  // `Type` for the same id. When #36 ports the embedded-Exif/XMP
  // EXTRACTION path it must use that precedence, not bare `Type`: a
  // crafted duplicate id carrying both a `mime` ContentType and a later
  // `Type == Exif` resolves XMP-only (ContentType wins), so the Exif
  // branch must NOT also claim it. (No production consumer today — this
  // accessor is test-only — so the deferral is safe.)
  #[must_use]
  #[inline(always)]
  pub fn exif_item(&self) -> Option<&HeifItem> {
    self
      .items
      .iter()
      .find(|i| i.item_type().is_some_and(|t| t == "Exif"))
  }

  /// Locate the FIRST item whose `ContentType` is `application/rdf+xml`
  /// — the XMP item (QuickTime.pm:9371 `'application/rdf+xml' => 'XMP'`).
  //
  // TODO(#36): this matches on `ContentType` alone. ExifTool's
  // `HandleItemInfo` classifies each item by its Perl-truthy EFFECTIVE
  // type `$$item{ContentType} || $$item{Type} || next`
  // (QuickTime.pm:9360), where a NON-EMPTY `ContentType` DOMINATES `Type`
  // for the same id. When #36 ports the embedded-Exif/XMP EXTRACTION path
  // it must use that precedence: a crafted duplicate id carrying both a
  // `mime`/`application/rdf+xml` ContentType and a later `Type == Exif`
  // resolves XMP-only here (ContentType wins over the later Type), so the
  // mime-then-Exif duplicate case is XMP. (No production consumer today —
  // this accessor is test-only — so the deferral is safe.)
  #[must_use]
  #[inline(always)]
  pub fn xmp_item(&self) -> Option<&HeifItem> {
    self
      .items
      .iter()
      .find(|i| i.content_type().is_some_and(|t| t == "application/rdf+xml"))
  }

  /// Setter (primary item id).
  #[inline(always)]
  pub const fn set_primary_item(&mut self, v: Option<u32>) -> &mut Self {
    self.primary_item = v;
    self
  }

  /// Setter (push one item).
  #[inline(always)]
  pub fn push_item(&mut self, item: HeifItem) -> &mut Self {
    self.items.push(item);
    self
  }

  /// Mutable view of the item list — lets the `iloc`/`infe` merge update
  /// an existing entry in place (keyed by item id) instead of cloning and
  /// rebuilding the whole list each iteration. Mirrors ExifTool keying its
  /// `$$items{$id}` hash directly (QuickTime.pm:9192).
  #[must_use]
  #[inline(always)]
  pub fn items_mut(&mut self) -> &mut [HeifItem] {
    &mut self.items
  }

  /// Setter (idat offset).
  #[inline(always)]
  pub const fn set_idat_offset(&mut self, v: Option<u64>) -> &mut Self {
    self.idat_offset = v;
    self
  }

  /// Setter (idat length).
  #[inline(always)]
  pub const fn set_idat_length(&mut self, v: Option<u64>) -> &mut Self {
    self.idat_length = v;
    self
  }

  /// Setter (`File:ImageWidth` — main-document `ispe` width).
  #[inline(always)]
  pub const fn set_image_width(&mut self, v: Option<u32>) -> &mut Self {
    self.image_width = v;
    self
  }

  /// Setter (`File:ImageHeight` — main-document `ispe` height).
  #[inline(always)]
  pub const fn set_image_height(&mut self, v: Option<u32>) -> &mut Self {
    self.image_height = v;
    self
  }

  /// Setter (`av1C` AV1 Codec Configuration — last-wins per `ipco` walk order,
  /// #149).
  #[inline(always)]
  pub const fn set_av1_config(&mut self, v: Option<Av1Config>) -> &mut Self {
    self.av1_config = v;
    self
  }

  /// Setter (warning — first-wins, mirroring the SP1 convention). Leaves
  /// [`Self::warning_offset`] untouched (no position recorded); the production
  /// meta-box walk uses [`Self::set_warning_at`] so the document-level
  /// diagnostics drain can order the warning by file position.
  #[inline(always)]
  pub fn set_warning(&mut self, v: Option<String>) -> &mut Self {
    if self.warning.is_none() {
      self.warning = v;
    }
    self
  }

  /// Setter recording the warning AND the absolute file offset of the `meta`
  /// box that produced it (both first-wins, in lockstep — the offset is only
  /// stored when this call actually records the warning). The meta-box walk
  /// passes its `meta_abs_offset` so the QuickTime diagnostics drain can rank
  /// this walk warning against the `ProcessMOV` atom warning by file position
  /// (priority-0 first-wins ⇒ earliest walk position wins). #159.
  #[inline(always)]
  pub fn set_warning_at(&mut self, v: Option<String>, offset: u64) -> &mut Self {
    if self.warning.is_none() {
      if v.is_some() {
        self.warning_offset = Some(offset);
      }
      self.warning = v;
    }
    self
  }
}

// ===========================================================================
// HeifMeta — projection
// ===========================================================================

impl HeifMeta {
  /// Project HEIF/AVIF meta-box facts into [`MediaMetadata`].
  ///
  /// SP4 surfaces ONLY warnings here — the camera identity in a HEIF
  /// file lives inside an `Exif` item whose body is a TIFF block, and
  /// the Exif IFD parser (PR #36 `lib/exif-gps`) is on a sibling
  /// branch. Once it lands, `HandleItemInfo` will read the Exif
  /// extent's bytes and parse them into [`crate::metadata::CameraInfo`]
  /// — that wire-up is the SP4→#36 join point.
  ///
  /// `MediaInfo` dimensions could come from an `ispe` (ImageSpatialExtent)
  /// property in `ipco` (QuickTime.pm:3034-3047), but that requires the
  /// full ipma→ipco property dispatch which is DEFERRED.
  pub(crate) fn project_into(&self, _md: &mut MediaMetadata) {
    // TODO(#159 audit): the meta-box walker's `warning()` channel is NOT
    // propagated here — `MediaMetadata` has no warnings channel in the
    // current architecture (this code was written against an older
    // `MediaMetadata::push_warning`). The other ports surface their
    // per-format warnings through the diagnostics path at emission time;
    // the SP4 faithful-emission audit wires `HeifMeta::warning()` the same
    // way. The warning is still STORED on the typed surface
    // (`self.warning()`).
  }
}

// ===========================================================================
// Cr3Meta — Canon CR3 / CRM identity
// ===========================================================================

/// Which Canon `uuid` CMT block a [`Cr3Block`] location is, used to drive the
/// re-dispatch table (`Image::ExifTool::Canon::uuid`, Canon.pm:9684-9726):
/// `Cmt1` → IFD0 (`Exif::Main`), `Cmt2` → ExifIFD (`Exif::Main`), `Cmt3` →
/// MakerNoteCanon (`Canon::Main` via `ProcessCMT3`), `Cmt4` → GPS (`GPS::Main`).
/// The Canon-`uuid` walk uses it to dispatch each box's eager parse and to
/// record the box LOCATION in the matching [`Cr3Meta`] slot
/// ([`Cr3Meta::record_cmt_location`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cr3CmtKind {
  /// `CMT1` — IFD0 (`Exif::Main`); its IFD0 `Model` seeds `$$self{Model}`.
  Cmt1,
  /// `CMT2` — ExifIFD (`Exif::Main`).
  Cmt2,
  /// `CMT3` — MakerNoteCanon (`Canon::Main` via `ProcessCMT3`).
  Cmt3,
  /// `CMT4` — GPS (`GPS::Main`).
  Cmt4,
}

impl Cr3CmtKind {
  /// The block's 4CC tag as a string (`"CMT1"`..`"CMT4"`).
  #[must_use]
  #[inline(always)]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Cmt1 => "CMT1",
      Self::Cmt2 => "CMT2",
      Self::Cmt3 => "CMT3",
      Self::Cmt4 => "CMT4",
    }
  }

  /// True iff this is [`Self::Cmt1`].
  #[must_use]
  #[inline(always)]
  pub const fn is_cmt1(&self) -> bool {
    matches!(self, Self::Cmt1)
  }

  /// True iff this is [`Self::Cmt2`].
  #[must_use]
  #[inline(always)]
  pub const fn is_cmt2(&self) -> bool {
    matches!(self, Self::Cmt2)
  }

  /// True iff this is [`Self::Cmt3`].
  #[must_use]
  #[inline(always)]
  pub const fn is_cmt3(&self) -> bool {
    matches!(self, Self::Cmt3)
  }

  /// True iff this is [`Self::Cmt4`].
  #[must_use]
  #[inline(always)]
  pub const fn is_cmt4(&self) -> bool {
    matches!(self, Self::Cmt4)
  }
}

/// Typed mirror of the Canon CR3 / CRM (`crx ` brand) container identity
/// — the `Image::ExifTool::Canon::uuid` atom set (Canon.pm:9657-9738)
/// reached via the QuickTime UUID-Canon dispatch (QuickTime.pm:1236-1242).
///
/// **What this surfaces:**
///  - `CompressorVersion` (CNCV) — the string `"CanonCR3 0.x.xx"` or
///    `"CanonCRM 0.x.xx"`. Bundled extracts a 3-char ID via the
///    `OverrideFileType($1) if $val =~ /^Canon(\w{3})/i` regex
///    (Canon.pm:9667) — so `CanonCR3 0.1.00` → file type `CR3` and
///    `CanonCRM 0.1.00` → file type `CRM`.
///  - Per-block presence + file-absolute offset + length for CMT1
///    (IFD0/Exif), CMT2 (ExifIFD), CMT3 (Canon MakerNotes), CMT4 (GPS),
///    plus CNTH (CanonCNTH preview) and THMB (ThumbnailImage).
///
/// **What is DEFERRED to PR #36 (`lib/exif-gps`) and the Canon
/// makernote port:**
///  - The TIFF/Exif body parse of CMT1/CMT2/CMT4 (each is a TIFF block
///    that `Image::ExifTool::ProcessTIFF` decodes — Canon.pm:9689 / :9698
///    / :9722).
///  - The CMT3 Canon-MakerNote parse (Canon.pm:9713 `ProcessCMT3`).
///  - CMT3 is the source of the body Model/Serial — its parse is the
///    direct join to [`crate::metadata::CameraInfo::model`].
#[derive(Debug, Clone, Default)]
pub struct Cr3Meta {
  /// `CompressorVersion` value — the `CanonCR3 0.x.xx` / `CanonCRM
  /// 0.x.xx` string. SmolStr — typically ≤ 32 chars.
  compressor_version: Option<SmolStr>,
  /// 3-char file-type override extracted from `compressor_version`:
  /// `Canon(\w{3})` → `CR3` or `CRM` (Canon.pm:9667).
  override_file_type: Option<SmolStr>,
  /// Location (file-absolute offset + length) of the LAST CMT1 box seen
  /// (Exif IFD0). Last-wins per kind, mirroring ExifTool's `FoundTag`
  /// last-wins-in-place: a duplicate `CMT1` overwrites this slot. This is a
  /// FIXED slot, NOT a per-box list — a crafted CR3 with millions of CMT
  /// boxes cannot grow it (the COUNT-amplification surface is gone).
  cmt1: Option<Cr3Block>,
  /// Location of the last CMT2 box (ExifIFD) — see [`Self::cmt1`].
  cmt2: Option<Cr3Block>,
  /// Location of the last CMT3 box (Canon MakerNotes) — see [`Self::cmt1`].
  cmt3: Option<Cr3Block>,
  /// Location of the last CMT4 box (GPS) — see [`Self::cmt1`].
  cmt4: Option<Cr3Block>,
  /// The CMT1-4 tags RENDERED for `-j` (PrintConv), in file-walk order. The
  /// CMT box bodies are TIFF/Canon-MakerNote sub-slices of the input buffer
  /// that ExifTool re-dispatches through `ProcessTIFF` / `ProcessCMT3`
  /// (Canon.pm:9686-9726); they are parsed EAGERLY during the Canon-`uuid`
  /// walk (where the input buffer is in scope) and the resulting OWNED
  /// [`EmittedTag`]s stored here — the raw bodies are NEVER retained. This
  /// bounds CMT storage to the parsed TAG count (the Exif walker already caps
  /// IFD entries), proportional to input size, with NO per-box and NO
  /// per-`uuid`-atom amplification.
  cmt_print: Vec<crate::emit::EmittedTag>,
  /// The CMT1-4 tags rendered for `-n` (ValueConv), in file-walk order — the
  /// `-n` counterpart of [`Self::cmt_print`] (the same blocks, rendered in the
  /// other [`ConvMode`](crate::emit::ConvMode); emission is mode-dependent, so
  /// both renderings are produced once at walk time).
  cmt_value: Vec<crate::emit::EmittedTag>,
  /// Offset / length of CNTH (CanonCNTH preview) — Canon.pm:9670-9673.
  cnth: Option<Cr3Block>,
  /// Offset / length of THMB (ThumbnailImage) — Canon.pm:9727-9733.
  thmb: Option<Cr3Block>,
}

/// One Canon CR3 CMT-family block LOCATION: an absolute file offset + length.
/// Faithful to the Canon::uuid SubDirectory pattern (Canon.pm:9687-9691).
///
/// This records ONLY where a CMT1-4 / CNTH / THMB box sits — it carries NO box
/// body. The CMT1-4 TIFF/Canon-MakerNote bodies are parsed EAGERLY during the
/// Canon-`uuid` walk and their decoded tags stored on
/// [`Cr3Meta::cmt_print`](Cr3Meta) / [`Cr3Meta::cmt_value`](Cr3Meta); keeping
/// no raw bytes here is what makes a file-controlled wholesale-clone of a
/// crafted multi-MB CMT box STRUCTURALLY impossible (there is no field to copy
/// it into).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cr3Block {
  offset: u64,
  length: u64,
}

impl Cr3Block {
  /// Construct an empty block.
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {
      offset: 0,
      length: 0,
    }
  }

  /// A block at `offset` of `length` bytes (the common ctor — the walk records
  /// each box's location in one call).
  #[must_use]
  #[inline(always)]
  pub const fn at(offset: u64, length: u64) -> Self {
    Self { offset, length }
  }

  /// The block's absolute file offset.
  #[must_use]
  #[inline(always)]
  pub const fn offset(&self) -> u64 {
    self.offset
  }

  /// The block's length in bytes.
  #[must_use]
  #[inline(always)]
  pub const fn length(&self) -> u64 {
    self.length
  }

  /// Setter (offset).
  #[inline(always)]
  pub const fn set_offset(&mut self, v: u64) -> &mut Self {
    self.offset = v;
    self
  }

  /// Setter (length).
  #[inline(always)]
  pub const fn set_length(&mut self, v: u64) -> &mut Self {
    self.length = v;
    self
  }
}

impl Cr3Meta {
  /// Construct an empty `Cr3Meta`.
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {
      compressor_version: None,
      override_file_type: None,
      cmt1: None,
      cmt2: None,
      cmt3: None,
      cmt4: None,
      cmt_print: Vec::new(),
      cmt_value: Vec::new(),
      cnth: None,
      thmb: None,
    }
  }

  /// The CNCV `CompressorVersion` string (e.g. `"CanonCR3 0.1.00"`).
  #[must_use]
  #[inline(always)]
  pub fn compressor_version(&self) -> Option<&str> {
    self.compressor_version.as_deref()
  }

  /// The 3-char file-type override (Canon.pm:9667):
  /// `CR3` for `CanonCR3...`, `CRM` for `CanonCRM...`. `None` when CNCV
  /// is absent / unparseable.
  #[must_use]
  #[inline(always)]
  pub fn override_file_type(&self) -> Option<&str> {
    self.override_file_type.as_deref()
  }

  /// The CMT1 block location (Exif IFD0 — Canon.pm:9684-9692). `None` when no
  /// CMT1 child was present. Last-wins on a duplicate (the LAST CMT1's
  /// location).
  #[must_use]
  #[inline(always)]
  pub const fn cmt1(&self) -> Option<&Cr3Block> {
    self.cmt1.as_ref()
  }

  /// The CMT2 block location (ExifIFD — Canon.pm:9693-9701; last-wins).
  #[must_use]
  #[inline(always)]
  pub const fn cmt2(&self) -> Option<&Cr3Block> {
    self.cmt2.as_ref()
  }

  /// The CMT3 block location (Canon MakerNotes — Canon.pm:9702-9716; last-wins).
  #[must_use]
  #[inline(always)]
  pub const fn cmt3(&self) -> Option<&Cr3Block> {
    self.cmt3.as_ref()
  }

  /// The CMT4 block location (GPS — Canon.pm:9717-9726; last-wins).
  #[must_use]
  #[inline(always)]
  pub const fn cmt4(&self) -> Option<&Cr3Block> {
    self.cmt4.as_ref()
  }

  /// The CMT1-4 tags decoded during the Canon-`uuid` walk, rendered for the
  /// requested [`ConvMode`](crate::emit::ConvMode) (`print_conv` ⇒ `-j`
  /// PrintConv, else `-n` ValueConv), in file-walk order. The emission path
  /// pushes these verbatim (the parse already happened at walk time).
  #[must_use]
  #[inline(always)]
  pub fn cmt_tags(&self, print_conv: bool) -> &[crate::emit::EmittedTag] {
    if print_conv {
      self.cmt_print.as_slice()
    } else {
      self.cmt_value.as_slice()
    }
  }

  /// The CNTH block (CanonCNTH preview — Canon.pm:9670-9673).
  #[must_use]
  #[inline(always)]
  pub const fn cnth(&self) -> Option<&Cr3Block> {
    self.cnth.as_ref()
  }

  /// The THMB block (ThumbnailImage — Canon.pm:9727-9733).
  #[must_use]
  #[inline(always)]
  pub const fn thmb(&self) -> Option<&Cr3Block> {
    self.thmb.as_ref()
  }

  /// `true` when no Canon UUID atom (`85 c0 b6 87 82 0f 11 e0 81 11
  /// f4 ce 46 2b 6a 48`) was found in the file's moov tree.
  #[must_use]
  #[inline(always)]
  pub fn is_empty(&self) -> bool {
    self.compressor_version.is_none()
      && self.cmt1.is_none()
      && self.cmt2.is_none()
      && self.cmt3.is_none()
      && self.cmt4.is_none()
      && self.cmt_print.is_empty()
      && self.cmt_value.is_empty()
      && self.cnth.is_none()
      && self.thmb.is_none()
  }

  /// Setter (compressor version).
  #[inline(always)]
  pub fn set_compressor_version(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.compressor_version = v;
    self
  }

  /// Setter (override file type).
  #[inline(always)]
  pub fn set_override_file_type(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.override_file_type = v;
    self
  }

  /// Record the LOCATION of a CMT1-4 box (last-wins per kind — a duplicate
  /// overwrites the slot, mirroring ExifTool's `FoundTag` last-wins-in-place).
  /// Stores no body; the decoded tags are added separately via
  /// [`Self::push_cmt_tags`].
  #[inline(always)]
  pub fn record_cmt_location(&mut self, kind: Cr3CmtKind, block: Cr3Block) -> &mut Self {
    match kind {
      Cr3CmtKind::Cmt1 => self.cmt1 = Some(block),
      Cr3CmtKind::Cmt2 => self.cmt2 = Some(block),
      Cr3CmtKind::Cmt3 => self.cmt3 = Some(block),
      Cr3CmtKind::Cmt4 => self.cmt4 = Some(block),
    }
    self
  }

  /// Append one CMT block's decoded tags for BOTH conv modes (`-j` PrintConv
  /// in `print`, `-n` ValueConv in `value`), in file-walk order. Called once
  /// per CMT box from the Canon-`uuid` walk after the body is parsed; an empty
  /// box (no parseable TIFF / no tags) appends nothing, so the buffers grow
  /// with the parsed TAG count, never the box count.
  #[inline(always)]
  pub fn push_cmt_tags(
    &mut self,
    print: Vec<crate::emit::EmittedTag>,
    value: Vec<crate::emit::EmittedTag>,
  ) -> &mut Self {
    self.cmt_print.extend(print);
    self.cmt_value.extend(value);
    self
  }

  /// Setter (CNTH).
  #[inline(always)]
  pub fn set_cnth(&mut self, v: Option<Cr3Block>) -> &mut Self {
    self.cnth = v;
    self
  }

  /// Setter (THMB).
  #[inline(always)]
  pub fn set_thmb(&mut self, v: Option<Cr3Block>) -> &mut Self {
    self.thmb = v;
    self
  }
}

// ===========================================================================
// Cr3Meta — Canon CR3 / CRM identity projection
// ===========================================================================

impl Cr3Meta {
  /// Project CR3 / CRM facts into [`MediaMetadata`].
  ///
  /// **CameraInfo.make:** `"Canon"` — bundled stamps this through the
  /// Canon makernote-derived `MakerNotes:Canon::Main` group, but the
  /// presence of a Canon UUID atom in a CR3 file is itself a faithful
  /// signal of the manufacturer. The model/serial come from CMT3
  /// (Canon MakerNotes) which is DEFERRED to the Canon makernote port.
  ///
  /// **Warnings:** propagate any iloc/iinf walk warnings under the
  /// `"[CR3] "` prefix.
  pub(crate) fn project_into(&self, md: &mut MediaMetadata) {
    use crate::metadata::CameraInfo;
    // Set Canon brand when we've decoded ANY Canon UUID child — a
    // bare Canon UUID with no CMT1-4 still tells us "Canon body".
    if !self.is_empty() && md.camera().is_none_or(|c| c.make().is_none()) {
      let mut cam = md.camera().cloned().unwrap_or_else(CameraInfo::new);
      cam.update_make(Some(String::from("Canon")));
      md.set_camera(cam);
    }
    // TODO(#159 audit): the UUID-walker `warning()` channel is NOT
    // propagated here — `MediaMetadata` has no warnings channel in the
    // current architecture (this code was written against an older
    // `MediaMetadata::push_warning`). The warning is still STORED on the
    // typed surface (`self.warning()`); the SP4 faithful-emission audit
    // wires it through the diagnostics path at emission time.
  }
}

// ===========================================================================
// Jp2Meta — JPEG 2000 container identity
// ===========================================================================

/// Typed mirror of the JPEG 2000 (`JP2`/`JPX`/`JPM`/`MJ2`) container —
/// a thin record of the detected sub-type plus the presence/location of
/// JP2 UUID-Exif / UUID-XMP boxes (Jpeg2000.pm:279-352).
///
/// **What this surfaces:**
///  - Sub-type (`JP2`, `JPX`, `JPM`, `JXL`, `JPH`) — derived from the
///    inner `ftyp` brand following the 12-byte JP2 signature
///    (Jpeg2000.pm:1580-1587).
///  - Offset / length of the FIRST `uuid`-Exif box body — the Exif/TIFF
///    payload starts at `body[16..]` (Jpeg2000.pm:289-290 `Start =>
///    '$valuePtr + 16'`). DEFERRED to PR #36 for the actual TIFF parse.
///  - Offset / length of the FIRST `uuid`-XMP box (Jpeg2000.pm:335-341).
///  - Offset / length of an `ihdr` (Image Header) box — gives image
///    dimensions (Jpeg2000.pm:168-173).
///
/// **What is DEFERRED:**
///  - JP2 codestream (`jp2c`) decoding — Phase-3 image-data path.
///  - JPM compound-image walk (Jpeg2000.pm:200-242).
///  - MJ2 motion sequence decode.
///  - JUMBF C2PA box walk (Jpeg2000.pm:803-840).
#[derive(Debug, Clone, Default)]
pub struct Jp2Meta {
  /// The detected sub-type (`JP2`, `JPX`, `JPM`, `JXL`, `JPH`, …)
  /// from the inner `ftyp` brand. `None` when no `ftyp` box was found
  /// (legacy JP2 with only the 12-byte signature).
  sub_type: Option<SmolStr>,
  /// Offset / length of the first UUID-Exif body. `None` when no such
  /// UUID is present (most JP2 files outside of Photoshop/Digikam).
  uuid_exif: Option<Jp2Block>,
  /// Offset / length of the first UUID-XMP body.
  uuid_xmp: Option<Jp2Block>,
  /// Offset / length of the `ihdr` Image Header box (14-byte body).
  ihdr: Option<Jp2Block>,
  /// `ftyp` MajorBrand — the RAW 4-byte brand from the `ftyp` box body
  /// (`%Image::ExifTool::Jpeg2000::FileType` offset 0, Jpeg2000.pm:558).
  /// The PrintConv (`jp2 `→"JPEG 2000 Image (.JP2)", …) is applied at
  /// emission. `None` when no `ftyp` box was decoded.
  major_brand: Option<SmolStr>,
  /// `ftyp` MinorVersion — the `sprintf("%x.%x.%x", unpack("nCC", $val))`
  /// rendering of body bytes 4..8 (Jpeg2000.pm:569-573). Stored
  /// post-ValueConv (mode-invariant, no PrintConv).
  minor_version: Option<SmolStr>,
  /// `ftyp` CompatibleBrands — body bytes 8.. split into 4-byte chunks
  /// with any NUL-containing chunk dropped (Jpeg2000.pm:574-581
  /// `ValueConv => 'my @a=($val=~/.{4}/sg); @a=grep(!/\0/,@a); \@a'`).
  /// Emitted as a List. Empty when no `ftyp` / no surviving chunks.
  compatible_brands: Vec<SmolStr>,
  /// `ihdr` ImageHeight — `int32u` at body offset 0 (Jpeg2000.pm:516-519).
  ihdr_height: Option<u32>,
  /// `ihdr` ImageWidth — `int32u` at body offset 4 (Jpeg2000.pm:520-523).
  ihdr_width: Option<u32>,
  /// `ihdr` NumberOfComponents — `int16u` at body offset 8
  /// (Jpeg2000.pm:524-527).
  ihdr_components: Option<u16>,
  /// `ihdr` BitsPerComponent — the RAW byte at body offset 10; the
  /// `Variable`/`N Bits, Signed|Unsigned` PrintConv (Jpeg2000.pm:528-537)
  /// is applied at emission.
  ihdr_bits_per_component: Option<u8>,
  /// `ihdr` Compression — the RAW byte at body offset 11; the enum
  /// PrintConv (Jpeg2000.pm:538-550) is applied at emission.
  ihdr_compression: Option<u8>,
  /// `colr` ColorSpecMethod — the SIGNED byte at colr offset 0 (`int8s`,
  /// the `%ColorSpec` table-level `FORMAT => 'int8s'`, Jpeg2000.pm:636);
  /// the enum PrintConv (Jpeg2000.pm:653-668) is applied at emission.
  /// Drives whether `color_space` is present (method 1 ⇒ enumerated
  /// ColorSpace).
  color_spec_method: Option<i8>,
  /// `colr` ColorSpecPrecedence — the SIGNED byte at colr offset 1
  /// (`int8s`, Jpeg2000.pm:669-672). Emitted as a bare signed int.
  color_spec_precedence: Option<i8>,
  /// `colr` ColorSpecApproximation — the SIGNED byte at colr offset 2
  /// (`int8s`, Jpeg2000.pm:636/673-684); the enum PrintConv is applied at
  /// emission.
  color_spec_approximation: Option<i8>,
  /// `colr` ColorSpace — `int32u` at colr offset 3, present ONLY when
  /// `color_spec_method == 1` (Jpeg2000.pm:698-728). When method ∈ {2,3}
  /// the bytes are an ICC profile (DEFERRED, `TODO(ICC)`); method 4 is
  /// vendor ColorSpecData (DEFERRED). The enum PrintConv is applied at
  /// emission.
  color_space: Option<u32>,
  /// `true` when this container is a JPEG XL (`ProcessJXL`, Jpeg2000.pm:
  /// 1603-1653) rather than a plain JPEG 2000 — set for BOTH the boxed
  /// (`\0\0\0\x0cJXL \x0d\x0a\x87\x0a`, :1611) and the raw-codestream
  /// (`^\xff\x0a`, :1614) forms. Drives the `JXL`-vs-`JXL Codestream`
  /// FileType finalize.
  is_jxl: bool,
  /// `true` for the RAW JXL codestream form (`^\xff\x0a`, Jpeg2000.pm:1614)
  /// — `SetFileType('JXL Codestream', 'image/jxl', 'jxl')` (:1628) — as
  /// opposed to the boxed JXL form (`is_jxl && !jxl_raw_codestream`),
  /// which keeps `File:FileType = JXL`.
  jxl_raw_codestream: bool,
  /// JXL `ImageWidth` decoded from the first codestream (`ProcessJXLCodestream`,
  /// Jpeg2000.pm:1469-1510). `None` when no codestream was decoded (a boxed
  /// JXL with no `jxlc`/`jxlp`, or a non-JXL JP2).
  image_width: Option<u32>,
  /// JXL `ImageHeight` decoded from the first codestream.
  image_height: Option<u32>,
  /// Once-guard mirroring `$$et{ProcessedJXLCodestream}` (Jpeg2000.pm:1475):
  /// only the FIRST codestream is decoded, so a boxed JXL with several
  /// partial-codestream `jxlp` boxes takes its dimensions from the first.
  processed_codestream: bool,
  warning: Option<String>,
}

/// One JP2 sub-box block: absolute file offset + length.
#[derive(Debug, Clone, Default)]
pub struct Jp2Block {
  offset: u64,
  length: u64,
}

impl Jp2Block {
  /// Construct an empty block.
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {
      offset: 0,
      length: 0,
    }
  }

  /// The block's absolute file offset.
  #[must_use]
  #[inline(always)]
  pub const fn offset(&self) -> u64 {
    self.offset
  }

  /// The block's length in bytes.
  #[must_use]
  #[inline(always)]
  pub const fn length(&self) -> u64 {
    self.length
  }

  /// Setter (offset).
  #[inline(always)]
  pub const fn set_offset(&mut self, v: u64) -> &mut Self {
    self.offset = v;
    self
  }

  /// Setter (length).
  #[inline(always)]
  pub const fn set_length(&mut self, v: u64) -> &mut Self {
    self.length = v;
    self
  }
}

impl Jp2Meta {
  /// Construct an empty `Jp2Meta`.
  #[must_use]
  #[inline(always)]
  pub const fn new() -> Self {
    Self {
      sub_type: None,
      uuid_exif: None,
      uuid_xmp: None,
      ihdr: None,
      major_brand: None,
      minor_version: None,
      compatible_brands: Vec::new(),
      ihdr_height: None,
      ihdr_width: None,
      ihdr_components: None,
      ihdr_bits_per_component: None,
      ihdr_compression: None,
      color_spec_method: None,
      color_spec_precedence: None,
      color_spec_approximation: None,
      color_space: None,
      is_jxl: false,
      jxl_raw_codestream: false,
      image_width: None,
      image_height: None,
      processed_codestream: false,
      warning: None,
    }
  }

  /// The detected sub-type (`JP2`, `JPX`, …).
  #[must_use]
  #[inline(always)]
  pub fn sub_type(&self) -> Option<&str> {
    self.sub_type.as_deref()
  }

  /// The UUID-Exif body block.
  #[must_use]
  #[inline(always)]
  pub const fn uuid_exif(&self) -> Option<&Jp2Block> {
    self.uuid_exif.as_ref()
  }

  /// The UUID-XMP body block.
  #[must_use]
  #[inline(always)]
  pub const fn uuid_xmp(&self) -> Option<&Jp2Block> {
    self.uuid_xmp.as_ref()
  }

  /// The `ihdr` Image Header block.
  #[must_use]
  #[inline(always)]
  pub const fn ihdr(&self) -> Option<&Jp2Block> {
    self.ihdr.as_ref()
  }

  /// The RAW `ftyp` MajorBrand 4-char string (PrintConv applied at emit).
  #[must_use]
  #[inline(always)]
  pub fn major_brand(&self) -> Option<&str> {
    self.major_brand.as_deref()
  }

  /// The `ftyp` MinorVersion (`%x.%x.%x` rendering, post-ValueConv).
  #[must_use]
  #[inline(always)]
  pub fn minor_version(&self) -> Option<&str> {
    self.minor_version.as_deref()
  }

  /// The `ftyp` CompatibleBrands (NUL-containing chunks already dropped).
  #[must_use]
  #[inline(always)]
  pub fn compatible_brands(&self) -> &[SmolStr] {
    &self.compatible_brands
  }

  /// The `ihdr` ImageHeight (`int32u`).
  #[must_use]
  #[inline(always)]
  pub const fn ihdr_height(&self) -> Option<u32> {
    self.ihdr_height
  }

  /// The `ihdr` ImageWidth (`int32u`).
  #[must_use]
  #[inline(always)]
  pub const fn ihdr_width(&self) -> Option<u32> {
    self.ihdr_width
  }

  /// The `ihdr` NumberOfComponents (`int16u`).
  #[must_use]
  #[inline(always)]
  pub const fn ihdr_components(&self) -> Option<u16> {
    self.ihdr_components
  }

  /// The RAW `ihdr` BitsPerComponent byte (PrintConv applied at emit).
  #[must_use]
  #[inline(always)]
  pub const fn ihdr_bits_per_component(&self) -> Option<u8> {
    self.ihdr_bits_per_component
  }

  /// The RAW `ihdr` Compression byte (PrintConv applied at emit).
  #[must_use]
  #[inline(always)]
  pub const fn ihdr_compression(&self) -> Option<u8> {
    self.ihdr_compression
  }

  /// The signed `colr` ColorSpecMethod byte (`int8s`; PrintConv at emit).
  #[must_use]
  #[inline(always)]
  pub const fn color_spec_method(&self) -> Option<i8> {
    self.color_spec_method
  }

  /// The `colr` ColorSpecPrecedence signed byte (`int8s`).
  #[must_use]
  #[inline(always)]
  pub const fn color_spec_precedence(&self) -> Option<i8> {
    self.color_spec_precedence
  }

  /// The signed `colr` ColorSpecApproximation byte (`int8s`; PrintConv at
  /// emit).
  #[must_use]
  #[inline(always)]
  pub const fn color_spec_approximation(&self) -> Option<i8> {
    self.color_spec_approximation
  }

  /// The `colr` ColorSpace (`int32u`, method-1 only; PrintConv at emit).
  #[must_use]
  #[inline(always)]
  pub const fn color_space(&self) -> Option<u32> {
    self.color_space
  }

  /// `true` when this container is a JPEG XL (boxed OR raw codestream) —
  /// `ProcessJXL` (Jpeg2000.pm:1603-1653).
  #[must_use]
  #[inline(always)]
  pub const fn is_jxl(&self) -> bool {
    self.is_jxl
  }

  /// `true` for the RAW JXL codestream form (`^\xff\x0a`, Jpeg2000.pm:1614)
  /// — `File:FileType = JXL Codestream`. `false` for boxed JXL / non-JXL.
  #[must_use]
  #[inline(always)]
  pub const fn jxl_raw_codestream(&self) -> bool {
    self.jxl_raw_codestream
  }

  /// The JXL `ImageWidth` decoded from the first codestream (`ProcessJXLCodestream`).
  #[must_use]
  #[inline(always)]
  pub const fn image_width(&self) -> Option<u32> {
    self.image_width
  }

  /// The JXL `ImageHeight` decoded from the first codestream.
  #[must_use]
  #[inline(always)]
  pub const fn image_height(&self) -> Option<u32> {
    self.image_height
  }

  /// `true` once a codestream has been decoded — the once-guard mirroring
  /// `$$et{ProcessedJXLCodestream}` (Jpeg2000.pm:1475).
  #[must_use]
  #[inline(always)]
  pub const fn processed_codestream(&self) -> bool {
    self.processed_codestream
  }

  /// First non-fatal warning surfaced during the JP2 box walk.
  #[must_use]
  #[inline(always)]
  pub fn warning(&self) -> Option<&str> {
    self.warning.as_deref()
  }

  /// `true` when no JP2 / JXL signature was found.
  #[must_use]
  #[inline(always)]
  pub fn is_empty(&self) -> bool {
    self.sub_type.is_none()
      && self.uuid_exif.is_none()
      && self.uuid_xmp.is_none()
      && self.ihdr.is_none()
      && self.major_brand.is_none()
      && self.ihdr_height.is_none()
      && self.ihdr_width.is_none()
      && self.color_spec_method.is_none()
      && !self.is_jxl
      && self.image_width.is_none()
      && self.image_height.is_none()
      && self.warning.is_none()
  }

  /// Setter (sub_type).
  #[inline(always)]
  pub fn set_sub_type(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.sub_type = v;
    self
  }

  /// Setter (uuid_exif).
  #[inline(always)]
  pub fn set_uuid_exif(&mut self, v: Option<Jp2Block>) -> &mut Self {
    self.uuid_exif = v;
    self
  }

  /// Setter (uuid_xmp).
  #[inline(always)]
  pub fn set_uuid_xmp(&mut self, v: Option<Jp2Block>) -> &mut Self {
    self.uuid_xmp = v;
    self
  }

  /// Setter (ihdr).
  #[inline(always)]
  pub fn set_ihdr(&mut self, v: Option<Jp2Block>) -> &mut Self {
    self.ihdr = v;
    self
  }

  /// Setter (`ftyp` MajorBrand).
  #[inline(always)]
  pub fn set_major_brand(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.major_brand = v;
    self
  }

  /// Setter (`ftyp` MinorVersion).
  #[inline(always)]
  pub fn set_minor_version(&mut self, v: Option<SmolStr>) -> &mut Self {
    self.minor_version = v;
    self
  }

  /// Setter (REPLACE the whole CompatibleBrands list).
  #[inline(always)]
  pub fn set_compatible_brands(&mut self, v: Vec<SmolStr>) -> &mut Self {
    self.compatible_brands = v;
    self
  }

  /// Setter (`ihdr` ImageHeight).
  #[inline(always)]
  pub const fn set_ihdr_height(&mut self, v: Option<u32>) -> &mut Self {
    self.ihdr_height = v;
    self
  }

  /// Setter (`ihdr` ImageWidth).
  #[inline(always)]
  pub const fn set_ihdr_width(&mut self, v: Option<u32>) -> &mut Self {
    self.ihdr_width = v;
    self
  }

  /// Setter (`ihdr` NumberOfComponents).
  #[inline(always)]
  pub const fn set_ihdr_components(&mut self, v: Option<u16>) -> &mut Self {
    self.ihdr_components = v;
    self
  }

  /// Setter (`ihdr` BitsPerComponent raw byte).
  #[inline(always)]
  pub const fn set_ihdr_bits_per_component(&mut self, v: Option<u8>) -> &mut Self {
    self.ihdr_bits_per_component = v;
    self
  }

  /// Setter (`ihdr` Compression raw byte).
  #[inline(always)]
  pub const fn set_ihdr_compression(&mut self, v: Option<u8>) -> &mut Self {
    self.ihdr_compression = v;
    self
  }

  /// Setter (`colr` ColorSpecMethod signed byte).
  #[inline(always)]
  pub const fn set_color_spec_method(&mut self, v: Option<i8>) -> &mut Self {
    self.color_spec_method = v;
    self
  }

  /// Setter (`colr` ColorSpecPrecedence signed byte).
  #[inline(always)]
  pub const fn set_color_spec_precedence(&mut self, v: Option<i8>) -> &mut Self {
    self.color_spec_precedence = v;
    self
  }

  /// Setter (`colr` ColorSpecApproximation signed byte).
  #[inline(always)]
  pub const fn set_color_spec_approximation(&mut self, v: Option<i8>) -> &mut Self {
    self.color_spec_approximation = v;
    self
  }

  /// Setter (`colr` ColorSpace `int32u`, method-1 only).
  #[inline(always)]
  pub const fn set_color_space(&mut self, v: Option<u32>) -> &mut Self {
    self.color_space = v;
    self
  }

  /// Setter (`is_jxl`).
  #[inline(always)]
  pub const fn set_is_jxl(&mut self, v: bool) -> &mut Self {
    self.is_jxl = v;
    self
  }

  /// Setter (`jxl_raw_codestream`).
  #[inline(always)]
  pub const fn set_jxl_raw_codestream(&mut self, v: bool) -> &mut Self {
    self.jxl_raw_codestream = v;
    self
  }

  /// Setter (image width).
  #[inline(always)]
  pub const fn set_image_width(&mut self, v: Option<u32>) -> &mut Self {
    self.image_width = v;
    self
  }

  /// Setter (image height).
  #[inline(always)]
  pub const fn set_image_height(&mut self, v: Option<u32>) -> &mut Self {
    self.image_height = v;
    self
  }

  /// Setter (`processed_codestream` once-guard).
  #[inline(always)]
  pub const fn set_processed_codestream(&mut self, v: bool) -> &mut Self {
    self.processed_codestream = v;
    self
  }

  /// Setter (warning).
  #[inline(always)]
  pub fn set_warning(&mut self, v: Option<String>) -> &mut Self {
    if self.warning.is_none() {
      self.warning = v;
    }
    self
  }
}

// ===========================================================================
// Jp2Meta — projection
// ===========================================================================

impl Jp2Meta {
  /// Project JP2 / JXL facts into [`MediaMetadata`].
  ///
  /// The camera identity in a JP2/JXL lives inside the UUID-Exif body
  /// whose TIFF parse is deferred to PR #36, so the only DOMAIN facts SP4
  /// surfaces are the JXL codestream dimensions (`ProcessJXLCodestream`,
  /// Jpeg2000.pm:1469-1510) — the image's true pixel size — into
  /// [`MediaInfo`]. Plain JP2 has no codestream-decoded dimensions here
  /// (the `ihdr` decode is a deferred follow-up), so its projection stays
  /// a no-op.
  pub(crate) fn project_into(&self, md: &mut MediaMetadata) {
    if self.image_width.is_some() || self.image_height.is_some() {
      let media = md.media_mut();
      if let Some(w) = self.image_width {
        media.update_width(Some(w));
      }
      if let Some(h) = self.image_height {
        media.update_height(Some(h));
      }
    }
    // The JP2 box-walker `warning()` is now surfaced at EMISSION time via
    // `impl Diagnose for Jp2Meta` (the standalone JP2 entry point wired in
    // the #159 audit), so it reaches the output `ExifTool:Warning` stream.
    // It is still NOT propagated into the `MediaMetadata` PROJECTION here —
    // `MediaMetadata` has no warnings channel in the current architecture
    // (this code was written against an older `MediaMetadata::push_warning`).
    // TODO(#159 audit): fold the JP2 warning into the domain projection if
    // `MediaMetadata` ever grows a diagnostics channel.
  }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
  use super::*;
  use crate::metadata::CameraInfo;

  #[test]
  fn heif_extent_default_zero() {
    let e = HeifExtent::default();
    assert_eq!(e.offset(), 0);
    assert_eq!(e.length(), 0);
  }

  #[test]
  fn heif_extent_setters_round_trip() {
    let mut e = HeifExtent::new();
    e.set_offset(0x1234).set_length(0x5678);
    assert_eq!(e.offset(), 0x1234);
    assert_eq!(e.length(), 0x5678);
  }

  #[test]
  fn heif_item_setters_round_trip() {
    let mut it = HeifItem::new();
    it.set_id(7)
      .set_item_type(Some(SmolStr::new_static("Exif")))
      .set_name(Some(SmolStr::new_static("")))
      .set_content_type(Some(SmolStr::new_static("application/rdf+xml")))
      .set_base_offset(100)
      .set_construction_method(0);
    let mut e = HeifExtent::new();
    e.set_offset(0x1000).set_length(64);
    it.push_extent(e);
    assert_eq!(it.id(), 7);
    assert_eq!(it.item_type(), Some("Exif"));
    assert_eq!(it.content_type(), Some("application/rdf+xml"));
    assert_eq!(it.base_offset(), 100);
    assert_eq!(it.extents().len(), 1);
    assert_eq!(it.extents()[0].offset(), 0x1000);
    assert_eq!(it.construction_method(), 0);
  }

  #[test]
  fn heif_meta_empty_by_default() {
    let m = HeifMeta::default();
    assert!(m.is_empty());
    assert!(m.primary_item().is_none());
    assert!(m.items().is_empty());
    assert!(m.exif_item().is_none());
    assert!(m.xmp_item().is_none());
  }

  #[test]
  fn heif_meta_exif_xmp_lookups() {
    let mut m = HeifMeta::new();
    let mut a = HeifItem::new();
    a.set_id(1).set_item_type(Some(SmolStr::new_static("hvc1")));
    m.push_item(a);
    let mut b = HeifItem::new();
    b.set_id(2).set_item_type(Some(SmolStr::new_static("Exif")));
    m.push_item(b);
    let mut c = HeifItem::new();
    c.set_id(3)
      .set_item_type(Some(SmolStr::new_static("mime")))
      .set_content_type(Some(SmolStr::new_static("application/rdf+xml")));
    m.push_item(c);
    assert_eq!(m.exif_item().unwrap().id(), 2);
    assert_eq!(m.xmp_item().unwrap().id(), 3);
    assert_eq!(m.item_by_id(2).unwrap().item_type(), Some("Exif"));
    assert!(m.item_by_id(99).is_none());
  }

  #[test]
  fn heif_meta_set_warning_first_wins() {
    let mut m = HeifMeta::new();
    m.set_warning(Some(String::from("first")));
    m.set_warning(Some(String::from("second")));
    assert_eq!(m.warning(), Some("first"));
  }

  #[test]
  fn heif_meta_set_primary_idat() {
    let mut m = HeifMeta::new();
    m.set_primary_item(Some(1))
      .set_idat_offset(Some(0x4000))
      .set_idat_length(Some(0x800));
    assert_eq!(m.primary_item(), Some(1));
    assert_eq!(m.idat_offset(), Some(0x4000));
    assert_eq!(m.idat_length(), Some(0x800));
    assert!(!m.is_empty());
  }

  #[test]
  fn cr3_block_setters() {
    let mut b = Cr3Block::new();
    b.set_offset(0x100).set_length(0x40);
    assert_eq!(b.offset(), 0x100);
    assert_eq!(b.length(), 0x40);
  }

  #[test]
  fn cr3_meta_empty_by_default() {
    let m = Cr3Meta::default();
    assert!(m.is_empty());
    assert!(m.cmt1().is_none());
    assert!(m.cmt2().is_none());
    assert!(m.cmt3().is_none());
    assert!(m.cmt4().is_none());
    assert!(m.compressor_version().is_none());
    assert!(m.override_file_type().is_none());
  }

  #[test]
  fn cr3_meta_setters_round_trip() {
    let mut m = Cr3Meta::new();
    m.set_compressor_version(Some(SmolStr::new_static("CanonCR3 0.1.00")))
      .set_override_file_type(Some(SmolStr::new_static("CR3")));
    // CMT box LOCATIONS go in fixed per-kind slots (last-wins); the eager
    // walk records them with `record_cmt_location`.
    m.record_cmt_location(Cr3CmtKind::Cmt1, Cr3Block::at(0x100, 0x40));
    assert!(!m.is_empty());
    assert_eq!(m.compressor_version(), Some("CanonCR3 0.1.00"));
    assert_eq!(m.override_file_type(), Some("CR3"));
    assert_eq!(m.cmt1().unwrap().offset(), 0x100);
    assert_eq!(m.cmt1().unwrap().length(), 0x40);
  }

  #[test]
  fn cr3_meta_project_into_sets_canon_make() {
    let mut m = Cr3Meta::new();
    m.set_compressor_version(Some(SmolStr::new_static("CanonCR3 0.1.00")))
      .set_override_file_type(Some(SmolStr::new_static("CR3")));
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert_eq!(md.camera().and_then(CameraInfo::make), Some("Canon"));
  }

  #[test]
  fn cr3_meta_project_into_skips_when_empty() {
    let m = Cr3Meta::new();
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert!(md.camera().is_none());
  }

  #[test]
  fn jp2_meta_empty_by_default() {
    let m = Jp2Meta::default();
    assert!(m.is_empty());
    assert!(m.sub_type().is_none());
    assert!(m.uuid_exif().is_none());
    assert!(m.uuid_xmp().is_none());
    assert!(m.ihdr().is_none());
  }

  #[test]
  fn jp2_meta_setters_round_trip() {
    let mut m = Jp2Meta::new();
    m.set_sub_type(Some(SmolStr::new_static("JP2")));
    let mut b = Jp2Block::new();
    b.set_offset(0x200).set_length(0x80);
    m.set_uuid_exif(Some(b));
    assert!(!m.is_empty());
    assert_eq!(m.sub_type(), Some("JP2"));
    assert_eq!(m.uuid_exif().unwrap().offset(), 0x200);
  }

  #[test]
  fn jp2_meta_warning_stored_on_typed_surface() {
    // `MediaMetadata` has no warnings channel in the current architecture,
    // so `project_into` of a warning-only JP2 is a domain no-op; the
    // walker warning is STORED on the typed surface for the SP4
    // faithful-emission audit to wire through the diagnostics path.
    let mut m = Jp2Meta::new();
    m.set_warning(Some(String::from("boom")));
    assert_eq!(m.warning(), Some("boom"));
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert!(md.camera().is_none());
    assert!(md.gps().is_none());
  }

  #[test]
  fn jxl_meta_fields_round_trip() {
    let mut m = Jp2Meta::new();
    m.set_is_jxl(true)
      .set_jxl_raw_codestream(true)
      .set_image_width(Some(200))
      .set_image_height(Some(130))
      .set_processed_codestream(true);
    assert!(m.is_jxl());
    assert!(m.jxl_raw_codestream());
    assert_eq!(m.image_width(), Some(200));
    assert_eq!(m.image_height(), Some(130));
    assert!(m.processed_codestream());
    assert!(!m.is_empty());
  }

  #[test]
  fn jxl_meta_projects_codestream_dimensions_into_media() {
    // The decoded JXL ImageWidth/ImageHeight (ProcessJXLCodestream,
    // Jpeg2000.pm:1507-1508) are the image's true pixel size and project
    // into MediaInfo.
    let mut m = Jp2Meta::new();
    m.set_is_jxl(true)
      .set_image_width(Some(200))
      .set_image_height(Some(130));
    let mut md = MediaMetadata::new();
    m.project_into(&mut md);
    assert_eq!(md.media().width(), Some(200));
    assert_eq!(md.media().height(), Some(130));
  }
}
